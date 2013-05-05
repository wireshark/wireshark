/* packet-exported_pdu.c
 * Routines for exported_pdu dissection
 * Copyright 2013, Anders Broman <anders-broman@ericsson.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/tap.h>
#include <epan/exported_pdu.h>

void proto_reg_handoff_exported_pdu(void);

static gint exported_pdu_tap = -1;

static int proto_exported_pdu = -1;
static int proto_exported_pdu_tag = -1;
static int proto_exported_pdu_tag_len = -1;
static int proto_exported_pdu_prot_name = -1;


/* Initialize the subtree pointers */
static gint ett_exported_pdu = -1;

#define EXPORTED_PDU_NEXT_PROTO_STR  0
static const value_string exported_pdu_tag_vals[] = {
   { EXP_PDU_TAG_END_OF_OPT,       "End-of-options" },
/* 1 - 9 reserved */
   { EXP_PDU_TAG_OPTIONS_LENGTH,   "Total length of the options exluding this TLV" },
   { EXP_PDU_TAG_LINKTYPE,         "Linktype value" },
   { EXP_PDU_TAG_PROTO_NAME,       "PDU content protocol name" },
   /* Add protocol type related tags here */
/* 13 - 19 reserved */
   { EXP_PDU_TAG_IPV4_SRC,         "IPv4 Source Address" },
   { EXP_PDU_TAG_IPV4_DST,         "IPv4 Destination Address" },
   { EXP_PDU_TAG_IPV6_SRC,         "IPv6 Source Address" },
   { EXP_PDU_TAG_IPV6_DST,         "IPv4 Destination Address" },

   { EXP_PDU_TAG_SRC_PORT,         "Source Port" },
   { EXP_PDU_TAG_DST_PORT,         "Destination Port" },

   { EXP_PDU_TAG_SCTP_PPID,        "SCTP ppid" },

   { EXP_PDU_TAG_SS7_OPC,          "SS7 OPC" },
   { EXP_PDU_TAG_SS7_DPC,          "SS7 DPC" },

   { 0,        NULL   }
};

/* Code to actually dissect the packets */
static void
dissect_exported_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *exported_pdu_tree;
	tvbuff_t * payload_tvb = NULL;
    int offset = 0;
    guint16 tag;
    int tag_len;
	int next_proto_type = -1;
	char *proto_name = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Exported PDU");


    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_exported_pdu, tvb, offset, -1, ENC_NA);
    exported_pdu_tree = proto_item_add_subtree(ti, ett_exported_pdu);

    tag = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(exported_pdu_tree, proto_exported_pdu_tag, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;
    proto_tree_add_item(exported_pdu_tree, proto_exported_pdu_tag_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    tag_len = tvb_get_ntohs(tvb, offset);
    offset+=2;
    while(tag != 0){
		switch(tag){
		case EXP_PDU_TAG_PROTO_NAME:
			next_proto_type = EXPORTED_PDU_NEXT_PROTO_STR;
			proto_name = tvb_get_ephemeral_string(tvb, offset, tag_len);
			proto_tree_add_item(exported_pdu_tree, proto_exported_pdu_prot_name, tvb, offset, tag_len, ENC_BIG_ENDIAN);
			break;
		default:
			break;
		};
		offset = offset + tag_len;
        proto_tree_add_item(exported_pdu_tree, proto_exported_pdu_tag, tvb, offset, 2, ENC_BIG_ENDIAN);
        tag = tvb_get_ntohs(tvb, offset);
        offset+=2;
        proto_tree_add_item(exported_pdu_tree, proto_exported_pdu_tag_len, tvb, offset, 2, ENC_BIG_ENDIAN);
        tag_len = tvb_get_ntohs(tvb, offset);
        offset+=2;
    }

	payload_tvb = tvb_new_subset_remaining(tvb, offset);

	switch(next_proto_type){
	case EXPORTED_PDU_NEXT_PROTO_STR:
		call_dissector(find_dissector(proto_name), payload_tvb, pinfo, tree);
		break;
	default:
		break;
	}

	proto_tree_add_text(exported_pdu_tree, payload_tvb, 0, -1,"Exported PDU");
}

/* Register the protocol with Wireshark.
 *
 */
void
proto_register_exported_pdu(void)
{
    /*module_t *exported_pdu_module;*/

    static hf_register_info hf[] = {
        { &proto_exported_pdu_tag,
            { "Tag", "exported_pdu.tag",
               FT_UINT16, BASE_DEC, VALS(exported_pdu_tag_vals), 0,
              NULL, HFILL }
        },
        { &proto_exported_pdu_tag_len,
            { "Length", "exported_pdu.tag_len",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &proto_exported_pdu_prot_name,
            { "Protocol name", "exported_pdu.prot_name",
               FT_STRING, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_exported_pdu
    };

    /* Register the protocol name and description */
    proto_exported_pdu = proto_register_protocol("EXPORTED_PDU",
            "exported_pdu", "exported_pdu");

    register_dissector("exported_pdu", dissect_exported_pdu, proto_exported_pdu);

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_exported_pdu, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

#if 0
    exported_pdu_module = prefs_register_protocol(exported_pdu,
            proto_reg_handoff_exported_pdu);

    prefs_register_bool_preference(exported_pdu_module, "show_hex",
            "Display numbers in Hex",
            "Enable to display numerical values in hexadecimal.",
            &gPREF_HEX);

    * Register an example port preference */
    prefs_register_uint_preference(exported_pdu_module, "tcp.port", "exported_pdu TCP Port",
            " exported_pdu TCP port if other than the default",
            10, &gPORT_PREF);
#endif
    /* Register for tapping 
     * The tap is registered here but it is to be used by dissectors that
     * want to export their PDU:s, see packet-sip.c
     */
    exported_pdu_tap = register_tap("export_pdu");

}

void
proto_reg_handoff_exported_pdu(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t exported_pdu_handle;

    if (!initialized) {
        exported_pdu_handle = find_dissector("exported_pdu");
        initialized = TRUE;

    }
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
