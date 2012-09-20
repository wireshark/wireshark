/* packet-teimanagement.c
 * Routines for LAPD TEI Management frame disassembly
 * Rolf Fiedler <rolf.fiedler@innoventif.com>
 * based on code by Gilbert Ramirez <gram@alumni.rice.edu>
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
#include <epan/lapd_sapi.h>

/* ISDN/LAPD references:
 *
 * http://www.cisco.com/univercd/cc/td/doc/cisintwk/ito_doc/isdn.htm
 * http://www.ece.wpi.edu/courses/ee535/hwk11cd95/agrebe/agrebe.html
 * http://www.acacia-net.com/Clarinet/Protocol/q9213o84.htm
 */

static int proto_tei=-1;

static int lm_entity_id=-1;
static int lm_reference=-1;
static int lm_message=-1;
static int lm_action=-1;
static int lm_extend =-1;
static gint lm_subtree=-1;

#define TEI_ID_REQUEST    0x01
#define TEI_ID_ASSIGNED   0x02
#define TEI_ID_DENIED     0x03
#define TEI_ID_CHECK_REQ  0x04
#define TEI_ID_CHECK_RESP 0x05
#define TEI_ID_REMOVE     0x06
#define TEI_ID_VERIFY     0x07

static const value_string tei_msg_vals[]={
    { TEI_ID_REQUEST,    "Identity Request"},
    { TEI_ID_ASSIGNED,   "Identity Assigned"},
    { TEI_ID_DENIED,     "Identity Denied"},
    { TEI_ID_CHECK_REQ,  "Identity Check Request"},
    { TEI_ID_CHECK_RESP, "Identity Check Response"},
    { TEI_ID_REMOVE,     "Identity Remove"},
    { TEI_ID_VERIFY,     "Identity Verify"},
    { 0, NULL}
};

static void
dissect_teimanagement(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *tei_tree = NULL;
    proto_item *tei_ti;
    guint8 message;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TEI");
    col_clear(pinfo->cinfo, COL_INFO);

    if (tree) {
	tei_ti = proto_tree_add_item(tree, proto_tei, tvb, 0, 5, ENC_NA);
	tei_tree = proto_item_add_subtree(tei_ti, lm_subtree);

	proto_tree_add_item(tei_tree, lm_entity_id, tvb, 0, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tei_tree, lm_reference,  tvb, 1, 2, ENC_BIG_ENDIAN);
    }

    message = tvb_get_guint8(tvb, 3);
    if (check_col(pinfo->cinfo, COL_INFO))
	col_add_str(pinfo->cinfo, COL_INFO,
	    val_to_str(message, tei_msg_vals, "Unknown message type (0x%04x)"));
    if (tree) {
	proto_tree_add_uint(tei_tree, lm_message, tvb, 3, 1, message);
	proto_tree_add_item(tei_tree, lm_action, tvb, 4, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tei_tree, lm_extend, tvb, 4, 1, ENC_BIG_ENDIAN);
    }
}

void
proto_register_teimanagement(void)
{
    static gint *subtree[]={
	&lm_subtree
    };

    static hf_register_info hf[] = {
	{ &lm_entity_id,
	  { "Entity", "tei.entity", FT_UINT8, BASE_HEX, NULL, 0x0,
	  	"Layer Management Entity Identifier", HFILL }},

	{ &lm_reference,
	  { "Reference", "tei.reference", FT_UINT16, BASE_DEC, NULL, 0x0,
	  	"Reference Number", HFILL }},

	{ &lm_message,
	  { "Msg", "tei.msg", FT_UINT8, BASE_DEC, VALS(tei_msg_vals), 0x0,
	  	"Message Type", HFILL }},

	{ &lm_action,
	  { "Action", "tei.action", FT_UINT8, BASE_DEC, NULL, 0xfe,
	  	"Action Indicator", HFILL }},

	{ &lm_extend,
	  { "Extend", "tei.extend", FT_UINT8, BASE_DEC, NULL, 0x01,
	  	"Extension Indicator", HFILL }}
    };

    proto_tei = proto_register_protocol("TEI Management Procedure, Channel D (LAPD)",
					 "TEI_MANAGEMENT", "tei_management");
    proto_register_field_array (proto_tei, hf, array_length(hf));
    proto_register_subtree_array(subtree, array_length(subtree));
}

void
proto_reg_handoff_teimanagement(void)
{
    dissector_handle_t teimanagement_handle;

    teimanagement_handle = create_dissector_handle(dissect_teimanagement,
        proto_tei);
    dissector_add_uint("lapd.sapi", LAPD_SAPI_L2, teimanagement_handle);
}
