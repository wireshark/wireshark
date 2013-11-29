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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <wiretap/wtap.h>

#include "tvbuff-int.h"

static int proto_mime_encap = -1;

static heur_dissector_list_t heur_subdissector_list;
static dissector_handle_t data_handle;

static tvbuff_t *file_tvbs;
static tvbuff_t *whole_tvb;

static void
mime_encap_init(void)
{
	if (file_tvbs) {
		tvb_free_chain(file_tvbs);
		file_tvbs = NULL;
		whole_tvb = NULL;
	}
}

static void
dissect_mime_encap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item* item;
	guint len;

	/* XXX, COL_INFO */

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MIME_FILE");
	item = proto_tree_add_item(tree, proto_mime_encap, tvb, 0, -1, ENC_NA);

	/* frames with nsec >= 1000000000 means errors :) */
	if (pinfo->fd->abs_ts.nsecs >= 1000000000) {
		proto_item_append_text(item, " (Error)");
		/* return; */ /* dissect what we have */
	}

	len = tvb_length(tvb);
	if (!pinfo->fd->flags.visited) {
		if (len) {
			tvbuff_t *cloned_tvb = tvb_clone(tvb);

			if (!file_tvbs) {
				file_tvbs = cloned_tvb;
				whole_tvb = tvb_new_composite();
			} else
				tvb_add_to_chain(file_tvbs, cloned_tvb);

			tvb_composite_append(whole_tvb, cloned_tvb);
		} else
			tvb_composite_finalize(whole_tvb);
	}

	/* End of file? */
	if (!len && whole_tvb) {
		/*
		 * Here we're doing some trick.
		 *
		 * We don't want to call dissectors with composite tvb, cause dissectors can create subsets or real data child
		 * on it, which would append to whole_tvb chain and would be freed only in mime_encap_init.
		 *
		 * So we create some tvb which pass all calls to whole_tvb, but chain with tvb (which is freed in dissection cleanup)
		 */
		tvbuff_t *tmp_tvb = tvb_new_chain(tvb, whole_tvb);

		proto_item_append_text(item, " (Final)");

		add_new_data_source(pinfo, tmp_tvb, "Whole file");

		if (!dissector_try_heuristic(heur_subdissector_list, tmp_tvb, pinfo, tree, NULL)) {
			proto_item_append_text(item, " (Unhandled)");
			call_dissector(data_handle, tmp_tvb, pinfo, tree);
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
