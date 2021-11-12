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

#include <glib.h>

#include "cfile.h"

static int
frame_cmp(gconstpointer a, gconstpointer b, gpointer user_data _U_)
{
  const frame_data *fdata1 = (const frame_data *) a;
  const frame_data *fdata2 = (const frame_data *) b;

  return (fdata1->num < fdata2->num) ? -1 :
    (fdata1->num > fdata2->num) ? 1 :
    0;
}

const char *
cap_file_provider_get_interface_name(struct packet_provider_data *prov, guint32 interface_id)
{
  wtapng_iface_descriptions_t *idb_info;
  wtap_block_t wtapng_if_descr = NULL;
  char* interface_name;

  idb_info = wtap_file_get_idb_info(prov->wth);

  if (interface_id < idb_info->interface_data->len)
    wtapng_if_descr = g_array_index(idb_info->interface_data, wtap_block_t, interface_id);

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
cap_file_provider_get_interface_description(struct packet_provider_data *prov, guint32 interface_id)
{
  wtapng_iface_descriptions_t *idb_info;
  wtap_block_t wtapng_if_descr = NULL;
  char* interface_name;

  idb_info = wtap_file_get_idb_info(prov->wth);

  if (interface_id < idb_info->interface_data->len)
    wtapng_if_descr = g_array_index(idb_info->interface_data, wtap_block_t, interface_id);

  g_free(idb_info);

  if (wtapng_if_descr) {
    if (wtap_block_get_string_option_value(wtapng_if_descr, OPT_IDB_DESCRIPTION, &interface_name) == WTAP_OPTTYPE_SUCCESS)
      return interface_name;
  }
  return NULL;
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
  g_tree_replace(prov->frames_modified_blocks, fd, (gpointer)new_block);

  fd->has_modified_block = TRUE;
}
