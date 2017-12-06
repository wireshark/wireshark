/* frame_set.c
 * fdfdkfslf;ajkdf
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <glib.h>

#include <epan/frame_set.h>

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
frame_set_get_interface_name(frame_set *fs, guint32 interface_id)
{
  wtapng_iface_descriptions_t *idb_info;
  wtap_block_t wtapng_if_descr = NULL;
  char* interface_name;

  idb_info = wtap_file_get_idb_info(fs->wth);

  if (interface_id < idb_info->interface_data->len)
    wtapng_if_descr = g_array_index(idb_info->interface_data, wtap_block_t, interface_id);

  g_free(idb_info);

  if (wtapng_if_descr) {
    if (wtap_block_get_string_option_value(wtapng_if_descr, OPT_IDB_NAME, &interface_name) == WTAP_OPTTYPE_SUCCESS)
      return interface_name;
    if (wtap_block_get_string_option_value(wtapng_if_descr, OPT_IDB_DESCR, &interface_name) == WTAP_OPTTYPE_SUCCESS)
      return interface_name;
  }
  return "unknown";
}

const char *
frame_set_get_interface_description(frame_set *fs, guint32 interface_id)
{
  wtapng_iface_descriptions_t *idb_info;
  wtap_block_t wtapng_if_descr = NULL;
  char* interface_name;

  idb_info = wtap_file_get_idb_info(fs->wth);

  if (interface_id < idb_info->interface_data->len)
    wtapng_if_descr = g_array_index(idb_info->interface_data, wtap_block_t, interface_id);

  g_free(idb_info);

  if (wtapng_if_descr) {
    if (wtap_block_get_string_option_value(wtapng_if_descr, OPT_IDB_DESCR, &interface_name) == WTAP_OPTTYPE_SUCCESS)
      return interface_name;
  }
  return NULL;
}

const char *
frame_set_get_user_comment(frame_set *fs, const frame_data *fd)
{
  if (fs->frames_user_comments)
     return (const char *)g_tree_lookup(fs->frames_user_comments, fd);

  /* g_warning? */
  return NULL;
}

void
frame_set_set_user_comment(frame_set *fs, frame_data *fd, const char *new_comment)
{
  if (!fs->frames_user_comments)
    fs->frames_user_comments = g_tree_new_full(frame_cmp, NULL, NULL, g_free);

  /* insert new packet comment */
  g_tree_replace(fs->frames_user_comments, fd, g_strdup(new_comment));

  fd->flags.has_user_comment = TRUE;
}
