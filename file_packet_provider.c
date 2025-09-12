/* file_packet_provider_data.c
 * Routines for a packet_provider_data for packets from a file.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <stdint.h>
#include <glib.h>
#include "cfile.h"
#include "wiretap/wtap.h"
#include "wiretap/wtap_opttypes.h"

const nstime_t *
cap_file_provider_get_frame_ts(struct packet_provider_data *prov, uint32_t frame_num)
{
    const frame_data *fd = NULL;

    if (prov->ref && prov->ref->num == frame_num) {
        fd = prov->ref;
    } else if (prov->prev_dis && prov->prev_dis->num == frame_num) {
        fd = prov->prev_dis;
    } else if (prov->prev_cap && prov->prev_cap->num == frame_num) {
        fd = prov->prev_cap;
    } else if (prov->frames) {
        fd = frame_data_sequence_find(prov->frames, frame_num);
    }

    return (fd && fd->has_ts) ? &fd->abs_ts : NULL;
}

const nstime_t *
cap_file_provider_get_start_ts(struct packet_provider_data *prov)
{
    return prov->wth ? wtap_file_start_ts(prov->wth) : NULL;
}

static int
frame_cmp(const void *a, const void *b, void *user_data _U_)
{
  const frame_data *fdata1 = (const frame_data *) a;
  const frame_data *fdata2 = (const frame_data *) b;

  return (fdata1->num < fdata2->num) ? -1 :
    (fdata1->num > fdata2->num) ? 1 :
    0;
}

const char *
cap_file_provider_get_interface_name(struct packet_provider_data *prov, uint32_t interface_id, unsigned section_number)
{
  wtapng_iface_descriptions_t *idb_info;
  wtap_block_t wtapng_if_descr = NULL;
  char* interface_name;

  idb_info = wtap_file_get_idb_info(prov->wth);

  unsigned gbl_iface_id = wtap_file_get_shb_global_interface_id(prov->wth, section_number, interface_id);

  if (gbl_iface_id < idb_info->interface_data->len)
    wtapng_if_descr = g_array_index(idb_info->interface_data, wtap_block_t, gbl_iface_id);

  g_free(idb_info);

  if (wtapng_if_descr) {
    if (wtap_block_get_string_option_value(wtapng_if_descr, OPT_IDB_NAME, &interface_name) == WTAP_OPTTYPE_SUCCESS)
      return interface_name;
    if (wtap_block_get_string_option_value(wtapng_if_descr, OPT_IDB_DESCRIPTION, &interface_name) == WTAP_OPTTYPE_SUCCESS)
      return interface_name;
    if (wtap_block_get_string_option_value(wtapng_if_descr, OPT_IDB_HARDWARE, &interface_name) == WTAP_OPTTYPE_SUCCESS)
      return interface_name;
  }
  return "unknown";
}

const char *
cap_file_provider_get_interface_description(struct packet_provider_data *prov, uint32_t interface_id, unsigned section_number)
{
  wtapng_iface_descriptions_t *idb_info;
  wtap_block_t wtapng_if_descr = NULL;
  char* interface_name;

  idb_info = wtap_file_get_idb_info(prov->wth);

  interface_id = wtap_file_get_shb_global_interface_id(prov->wth, section_number, interface_id);

  if (interface_id < idb_info->interface_data->len)
    wtapng_if_descr = g_array_index(idb_info->interface_data, wtap_block_t, interface_id);

  g_free(idb_info);

  if (wtapng_if_descr) {
    if (wtap_block_get_string_option_value(wtapng_if_descr, OPT_IDB_DESCRIPTION, &interface_name) == WTAP_OPTTYPE_SUCCESS)
      return interface_name;
  }
  return NULL;
}

static bool
cap_file_provider_get_dpib(struct packet_provider_data *prov, uint32_t dpib_id, unsigned section_number _U_, wtap_block_t *dpib)
{
  wtapng_dpib_lookup_info_t *info = wtap_file_get_dpib_lookup_info(prov->wth);
  wtap_block_t res = NULL;
  bool rv = false;

  if (info == NULL) {
    ws_warning("Could not find dpib lookup info for wtap %p", prov->wth);
    goto out;
  }

  if (info->dpibs == NULL) {
    ws_warning("Found dpib lookup info for wtap %p, but no dpibs are available", prov->wth);
    goto out;
  }

  if (info->dpibs->len <= dpib_id) {
    ws_warning("Found dpib_id %u not present in wtap (size %u)", dpib_id, info->dpibs->len);
    goto out;
  }

  res = g_array_index(info->dpibs, wtap_block_t, dpib_id);
  if (res == NULL) {
    ws_warning("Could not find dpib with id=%d", dpib_id);
    goto out;
  }

  *dpib = res;
  rv = true;

out:
  if (info != NULL)
    g_free(info);

  return rv;
}

static bool
cap_get_darwin_process_id(struct packet_provider_data *prov, uint32_t dpib_id, unsigned section_number, int32_t *pid)
{
    wtapng_ft_specific_mandatory_t *dpib_mand  = NULL;
    wtap_block_t                   dpib       = NULL;

    if (!cap_file_provider_get_dpib(prov, dpib_id, section_number, &dpib))
        return false;

    /* The process id is represented as `record_type` of the mandatory data
     * of the file-type specific information block.
     */
    dpib_mand = (wtapng_ft_specific_mandatory_t*)wtap_block_get_mandatory_data(dpib);
    if (!dpib_mand)
        return false;

    *pid = dpib_mand->record_type;
    return true;
}

static bool
cap_get_darwin_process_name(struct packet_provider_data *prov, uint32_t dpib_id, unsigned section_number, char **pname)
{
    wtap_block_t dpib;

    /* If we can not find DPIB block that is being referenced by a packet block,
     * we emit a warning message.
     */
    if (!cap_file_provider_get_dpib(prov, dpib_id, section_number, &dpib)) {
        ws_warning("Failed to get dpib with id=%u", dpib_id);
        return false;
    }

    /* Note: Darwin kernel is providing the process name as a best effort,
     * leading to the possibility of the process name being empty.
     * This is not a bug in the dissector, but a limitation of the Darwin kernel.
     *
     * Because of that, we emit a `noisy` message, but not a warning.
     */
    if (wtap_block_get_string_option_value(dpib, OPT_DPIB_NAME, pname) != WTAP_OPTTYPE_SUCCESS) {
        ws_noisy("Failed to get process name from dpib %p id=%u", dpib, dpib_id);
        return false;
    }

    return true;
}

static bool
cap_get_darwin_process_uuid(struct packet_provider_data *prov, uint32_t dpib_id, unsigned section_number, const uint8_t **uuid, size_t *uuid_len)
{
    wtap_block_t    dpib              = NULL;
    GBytes          *uuid_data        = NULL;
    gsize           uuid_data_size    = 0;

    if (!cap_file_provider_get_dpib(prov, dpib_id, section_number, &dpib))
        return false;

    if (wtap_block_get_bytes_option_value(dpib, OPT_DPIB_UUID, &uuid_data) != WTAP_OPTTYPE_SUCCESS) {
        ws_warning("Failed to get process uuid from dpib %p id=%u", dpib, dpib_id);
        return false;
    }

    if (uuid_data == NULL) {
        ws_warning("Null uuid found in dpib %p id=%u", dpib, dpib_id);
        return false;
    }

    *uuid = g_bytes_get_data(uuid_data, &uuid_data_size);
    if (uuid_len)
        *uuid_len = (*uuid == NULL) ? 0 : uuid_data_size;

    return true;
}

int32_t
cap_file_provider_get_process_id(struct packet_provider_data *prov, uint32_t process_info_id, unsigned section_number)
{
  int32_t process_id;

  if (!cap_get_darwin_process_id(prov, process_info_id, section_number, &process_id))
    return -1;

  return process_id;
}

const char *
cap_file_provider_get_process_name(struct packet_provider_data *prov, uint32_t process_info_id, unsigned section_number _U_)
{
  char *process_name = NULL;

  if (!cap_get_darwin_process_name(prov, process_info_id, section_number, &process_name))
    return NULL;

  return process_name;
}

const uint8_t *
cap_file_provider_get_process_uuid(struct packet_provider_data *prov, uint32_t process_info_id, unsigned section_number _U_,  size_t *uuid_size)
{
    const uint8_t *uuid;

    if (!cap_get_darwin_process_uuid(prov, process_info_id, section_number, &uuid, uuid_size))
        return NULL;

    return uuid;
}

wtap_block_t
cap_file_provider_get_modified_block(struct packet_provider_data *prov, const frame_data *fd)
{
  if (prov->frames_modified_blocks)
     return (wtap_block_t)g_tree_lookup(prov->frames_modified_blocks, fd);

  /* ws_warning? */
  return NULL;
}

void
cap_file_provider_set_modified_block(struct packet_provider_data *prov, frame_data *fd, const wtap_block_t new_block)
{
  if (!prov->frames_modified_blocks)
    prov->frames_modified_blocks = g_tree_new_full(frame_cmp, NULL, NULL, (GDestroyNotify)wtap_block_unref);

  /* insert new packet block */
  g_tree_replace(prov->frames_modified_blocks, fd, (void *)new_block);

  fd->has_modified_block = 1;
}
