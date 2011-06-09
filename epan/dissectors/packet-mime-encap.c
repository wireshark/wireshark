/* packet-mime-encap.c
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include <epan/emem.h>

static int proto_mime_encap = -1;

static heur_dissector_list_t heur_subdissector_list;
static dissector_handle_t data_handle;

/* XXX, orginal version was using composite tvb, sorry I can't force it to work */
static GString *whole_file;

static void
mime_encap_init(void)
{
	if (whole_file) {
		g_string_free(whole_file, TRUE);
		whole_file = NULL;
	}
}

static void
dissect_mime_encap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item* item;
	guint len;

	/* XXX, COL_INFO */

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MIME_FILE");
	item = proto_tree_add_item(tree, proto_mime_encap, tvb, 0, -1, FALSE);

	/* frames with nsec >= 1000000000 means errors :) */
	if (pinfo->fd->abs_ts.nsecs >= 1000000000) {
		proto_item_append_text(item, " (Error)");
		/* return; */ /* dissect what we have */
	}

	if (!whole_file)
		whole_file = g_string_new("");

	/* eof? */
	if (!(len = tvb_length(tvb))) {
		tvbuff_t *comp_tvb;

		proto_item_append_text(item, " (Final)");

		comp_tvb = tvb_new_child_real_data(tvb, whole_file->str, (guint) whole_file->len, (gint) whole_file->len);
		add_new_data_source(pinfo, comp_tvb, "Whole file");

		if (!dissector_try_heuristic(heur_subdissector_list, comp_tvb, pinfo, tree)) {
			proto_item_append_text(item, " (Unhandled)");
			call_dissector(data_handle, comp_tvb, pinfo, tree);
		}
	} else {
		if (!pinfo->fd->flags.visited) {
			g_string_set_size(whole_file, pinfo->fd->file_off + len);
			tvb_memcpy(tvb, whole_file->str + pinfo->fd->file_off, 0, len);
		}
	}
}

void
proto_register_mime_encap(void)
{
	proto_mime_encap = proto_register_protocol("MIME file", "MIME_FILE", "mime_dlt");

	register_dissector("mime_dlt", dissect_mime_encap, proto_mime_encap);
	register_init_routine(mime_encap_init);
	register_heur_dissector_list("wtap_file", &heur_subdissector_list);
}

void
proto_reg_handoff_mime_encap(void)
{
	dissector_handle_t mime_encap_handle;

	data_handle = find_dissector("data");
	mime_encap_handle = find_dissector("mime_dlt");
	dissector_add_uint("wtap_encap", WTAP_ENCAP_MIME, mime_encap_handle);
}
