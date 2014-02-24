/* cfile.c
 * capture_file GUI-independent manipulation
 * Vassilii Khachaturov <vassilii@tarunz.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>

#include "cfile.h"

static const wtapng_if_descr_t *
cap_file_get_interface_desc(void *data, guint32 interface_id)
{
  capture_file *cf = (capture_file *) data;
  wtapng_iface_descriptions_t *idb_info;
  const wtapng_if_descr_t *wtapng_if_descr = NULL;

  idb_info = wtap_file_get_idb_info(cf->wth);

  if (interface_id < idb_info->number_of_interfaces)
    wtapng_if_descr = &g_array_index(idb_info->interface_data, wtapng_if_descr_t, interface_id);

  g_free(idb_info);
  return wtapng_if_descr;
}

const char *
cap_file_get_interface_name(void *data, guint32 interface_id)
{
  const wtapng_if_descr_t *wtapng_if_descr = cap_file_get_interface_desc(data, interface_id);

  if (wtapng_if_descr) {
    if (wtapng_if_descr->if_name)
      return wtapng_if_descr->if_name;
    else if (wtapng_if_descr->if_description)
      return wtapng_if_descr->if_description;
  }
  return "unknown";
}

const GArray *
cap_file_get_interface_option(void *data, guint32 interface_id, guint16 option_code)
{
  const wtapng_if_descr_t *wtapng_if_descr = cap_file_get_interface_desc(data, interface_id);

  if (wtapng_if_descr && wtapng_if_descr->if_options) {
    gint code = (gint) option_code;
    return (const GArray *) g_hash_table_lookup(wtapng_if_descr->if_options, &code);
  }
  return NULL;
}

void
cap_file_init(capture_file *cf)
{
  /* Initialize the capture file struct */
  memset(cf, 0, sizeof(capture_file));
  cf->snap            = WTAP_MAX_PACKET_SIZE;
}
