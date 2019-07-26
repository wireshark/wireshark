/* packet-newmail.c
 * Routines for Exchange New Mail Notification dissection
 * Copyright 2006, Stephen Fisher (see AUTHORS file)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_newmail(void);
void proto_reg_handoff_newmail(void);

/* Initialize the protocol and registered fields */
static int proto_newmail = -1;
static int hf_newmail_payload = -1;

/* Initialize the subtree pointers */
static gint ett_newmail = -1;

static dissector_handle_t newmail_handle;

/* Code to actually dissect the packets */
static int
dissect_newmail(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *newmail_tree;

	/* Make entries in Protocol column and Info column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NEWMAIL");

	col_set_str(pinfo->cinfo, COL_INFO, "Microsoft Exchange new mail notification");

	if (tree) {
		ti = proto_tree_add_item(tree, proto_newmail, tvb, 0, -1, ENC_NA);

		newmail_tree = proto_item_add_subtree(ti, ett_newmail);

		proto_tree_add_item(newmail_tree, hf_newmail_payload, tvb, 0, 8, ENC_NA);
	}

	return tvb_captured_length(tvb);
}


/* Register the protocol with Wireshark */
void
proto_register_newmail(void)
{

	/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_newmail_payload,
		  { "Notification payload", "newmail.notification_payload",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Payload requested by client in the MAPI register push notification packet", HFILL }
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_newmail,
	};

	proto_newmail = proto_register_protocol("Microsoft Exchange New Mail Notification", "NEWMAIL", "newmail");

	proto_register_field_array(proto_newmail, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	newmail_handle = register_dissector("newmail", dissect_newmail, proto_newmail);
}

void
proto_reg_handoff_newmail(void)
{
	dissector_add_for_decode_as_with_preference("udp.port", newmail_handle);
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
