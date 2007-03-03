/* export_object_http.c
 * Routines for tracking & saving objects found in HTTP streams
 * See also: export_object.c / export_object.h for common code
 * Copyright 2007, Stephen Fisher <stephentfisher@yahoo.com>
 *
 * $Id$
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <gtk/gtk.h>

/* This feature has not been ported to GTK1 */
#if GTK_MAJOR_VERSION >= 2

#include <epan/dissectors/packet-http.h>

#include <epan/emem.h>
#include <epan/tap.h>

#include "export_object.h"

static int
eo_http_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_,
	       const void *data)
{
	export_object_list_t *object_list = tapdata;
	const http_info_value_t *stat_info = data;
	export_object_entry_t *entry;

	if(stat_info->content_type) { /* We have new data waiting */
		entry = g_malloc(sizeof(export_object_entry_t));

		entry->pkt_num = pinfo->fd->num;
		entry->hostname = stat_info->http_host;
		entry->content_type = stat_info->content_type;
		entry->filename = g_path_get_basename(stat_info->request_uri);
		entry->payload_len = stat_info->payload_len;
		entry->payload_data = stat_info->payload_data;

		object_list->entries =
			g_slist_append(object_list->entries, entry);
		return 1; /* State changed - window should be redrawn */
	} else {
		return 0; /* State unchanged - no window updates needed */
	}
}

void
eo_http_cb(GtkWidget *widget _U_, gpointer data _U_)
{
	export_object_window("http", eo_http_packet);
}

#endif /* GTK_MAJOR_VERSION >= 2 */
