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
#include <epan/cfile.h>
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

const nstime_t *
cap_file_provider_get_end_ts(struct packet_provider_data *prov)
{
    return prov->wth ? wtap_file_end_ts(prov->wth) : NULL;
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

static wtap_block_t
cap_file_provider_get_pib(struct packet_provider_data *prov, uint32_t process_info_id, unsigned section_number _U_)
{
  wtap_block_t pib = wtap_file_get_pib(prov->wth, process_info_id);

  /* If we can not find the process information block that is being
   * referenced by a packet block, we emit a warning message.
   */
  if (pib == NULL)
    ws_warning("Process information block %u not present in wtap %p (%u blocks)",
               process_info_id, prov->wth, wtap_file_get_num_pibs(prov->wth));

  return pib;
}

int32_t
cap_file_provider_get_process_id(struct packet_provider_data *prov, uint32_t process_info_id, unsigned section_number)
{
  wtap_block_t pib = cap_file_provider_get_pib(prov, process_info_id, section_number);
  wtapng_process_info_mandatory_t *pib_mand;

  if (pib == NULL)
    return -1;

  pib_mand = (wtapng_process_info_mandatory_t *)wtap_block_get_mandatory_data(pib);
  return (int32_t)pib_mand->process_id;
}

const char *
cap_file_provider_get_process_name(struct packet_provider_data *prov, uint32_t process_info_id, unsigned section_number)
{
  wtap_block_t pib = cap_file_provider_get_pib(prov, process_info_id, section_number);
  char *process_name;

  if (pib == NULL)
    return NULL;

  /* Note: the name is optional, and, for example, the Darwin kernel
   * provides it as a best effort, so a missing name is not a bug in
   * the dissector but a limitation of the source.
   *
   * Because of that, we emit a `noisy` message, but not a warning.
   */
  if (wtap_block_get_string_option_value(pib, OPT_PIB_NAME, &process_name) != WTAP_OPTTYPE_SUCCESS) {
    ws_noisy("No process name in process information block %u", process_info_id);
    return NULL;
  }

  return process_name;
}

const uint8_t *
cap_file_provider_get_process_uuid(struct packet_provider_data *prov, uint32_t process_info_id, unsigned section_number, size_t *uuid_size)
{
  wtap_block_t pib = cap_file_provider_get_pib(prov, process_info_id, section_number);
  GBytes *uuid_data;
  const uint8_t *uuid;
  size_t uuid_data_size = 0;

  if (pib == NULL)
    return NULL;

  /* The UUID is optional as well. */
  if (wtap_block_get_bytes_option_value(pib, OPT_PIB_UUID, &uuid_data) != WTAP_OPTTYPE_SUCCESS ||
      uuid_data == NULL) {
    ws_noisy("No process UUID in process information block %u", process_info_id);
    return NULL;
  }

  uuid = g_bytes_get_data(uuid_data, &uuid_data_size);
  if (uuid_size)
    *uuid_size = (uuid == NULL) ? 0 : uuid_data_size;

  return uuid;
}

const char *
cap_file_provider_get_process_path(struct packet_provider_data *prov, uint32_t process_info_id, unsigned section_number)
{
  wtap_block_t pib = cap_file_provider_get_pib(prov, process_info_id, section_number);
  char *path;

  if (pib == NULL ||
      wtap_block_get_string_option_value(pib, OPT_PIB_PATH, &path) != WTAP_OPTTYPE_SUCCESS)
    return NULL;

  return path;
}

const uint8_t *
cap_file_provider_get_process_cmdline(struct packet_provider_data *prov, uint32_t process_info_id, unsigned section_number, size_t *cmdline_size)
{
  wtap_block_t pib = cap_file_provider_get_pib(prov, process_info_id, section_number);
  GBytes *cmdline_data;
  const uint8_t *cmdline;
  size_t cmdline_data_size = 0;

  if (pib == NULL ||
      wtap_block_get_bytes_option_value(pib, OPT_PIB_CMDLINE, &cmdline_data) != WTAP_OPTTYPE_SUCCESS ||
      cmdline_data == NULL)
    return NULL;

  cmdline = g_bytes_get_data(cmdline_data, &cmdline_data_size);
  if (cmdline_size)
    *cmdline_size = (cmdline == NULL) ? 0 : cmdline_data_size;

  return cmdline;
}

bool
cap_file_provider_get_process_parent_id(struct packet_provider_data *prov, uint32_t process_info_id, unsigned section_number, uint32_t *parent_process_id)
{
  wtap_block_t pib = cap_file_provider_get_pib(prov, process_info_id, section_number);

  return pib != NULL &&
         wtap_block_get_uint32_option_value(pib, OPT_PIB_PPID, parent_process_id) == WTAP_OPTTYPE_SUCCESS;
}

bool
cap_file_provider_get_process_user_id(struct packet_provider_data *prov, uint32_t process_info_id, unsigned section_number, uint32_t *user_id)
{
  wtap_block_t pib = cap_file_provider_get_pib(prov, process_info_id, section_number);

  return pib != NULL &&
         wtap_block_get_uint32_option_value(pib, OPT_PIB_UID, user_id) == WTAP_OPTTYPE_SUCCESS;
}

const char *
cap_file_provider_get_process_user_name(struct packet_provider_data *prov, uint32_t process_info_id, unsigned section_number)
{
  wtap_block_t pib = cap_file_provider_get_pib(prov, process_info_id, section_number);
  char *user_name;

  if (pib == NULL ||
      wtap_block_get_string_option_value(pib, OPT_PIB_USER, &user_name) != WTAP_OPTTYPE_SUCCESS)
    return NULL;

  return user_name;
}

bool
cap_file_provider_get_process_start_time(struct packet_provider_data *prov, uint32_t process_info_id, unsigned section_number, nstime_t *start_time)
{
  wtap_block_t pib = cap_file_provider_get_pib(prov, process_info_id, section_number);
  uint64_t start_time_ns;

  if (pib == NULL ||
      wtap_block_get_uint64_option_value(pib, OPT_PIB_STARTTIME, &start_time_ns) != WTAP_OPTTYPE_SUCCESS)
    return false;

  /* The option is in nanoseconds since the Epoch. */
  start_time->secs = (time_t)(start_time_ns / 1000000000U);
  start_time->nsecs = (int)(start_time_ns % 1000000000U);
  return true;
}

bool
cap_file_provider_find_process_info(struct packet_provider_data *prov, uint32_t process_id, unsigned section_number _U_, const nstime_t *ts, uint32_t *process_info_id)
{
  unsigned pib_num;

  if (!wtap_file_find_pib(prov->wth, process_id, ts, &pib_num))
    return false;

  *process_info_id = pib_num;
  return true;
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
