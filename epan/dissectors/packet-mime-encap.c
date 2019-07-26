/* packet-mime-encap.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

#include <wiretap/wtap.h>

void proto_register_mime_encap(void);
void proto_reg_handoff_mime_encap(void);

static int proto_mime_encap = -1;

static dissector_handle_t mime_encap_handle;

static heur_dissector_list_t heur_subdissector_list;

static int
dissect_mime_encap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item* item;
	heur_dtbl_entry_t *hdtbl_entry;

	/* XXX, COL_INFO */

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MIME_FILE");
	item = proto_tree_add_item(tree, proto_mime_encap, tvb, 0, -1, ENC_NA);

	if (!dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, tree, &hdtbl_entry, NULL)) {
		proto_item_append_text(item, " (Unhandled)");
		call_data_dissector(tvb, pinfo, tree);
	}
	return tvb_captured_length(tvb);
}

void
proto_register_mime_encap(void)
{
	proto_mime_encap = proto_register_protocol("MIME file", "MIME_FILE", "mime_dlt");

	mime_encap_handle = register_dissector("mime_dlt", dissect_mime_encap, proto_mime_encap);
	heur_subdissector_list = register_heur_dissector_list("wtap_file", proto_mime_encap);
}

void
proto_reg_handoff_mime_encap(void)
{
	dissector_add_uint("wtap_encap", WTAP_ENCAP_MIME, mime_encap_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
