/* packet-gprs-ns.c
 * Routines for GPRS Network Service (ETSI GSM 08.16 version 6.3.0)
 * dissection
 * Copyright 2003, Josef Korelus <jkor@quick.cz>
 *
 * $Id: packet-gprs-ns.c,v 1.1 2003/09/03 22:26:38 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <glib.h>
#include <epan/packet.h>

/*ETSI  GSM08.16 Network Service */
#define NS_UNITDATA     0x00
#define NS_RESET        0x02
#define NS_RESET_ACK    0x03
#define NS_BLOCK        0x04
#define NS_BLOCK_ACK    0x05
#define NS_UNBLOCK      0x06
#define NS_UNBLOCK_ACK  0x07
#define NS_STATUS       0x08
#define NS_ALIVE        0x0a
#define NS_ALIVE_ACK    0x0b

/*ETSI  GSM 08.16 IEI coding */
#define Cause           0x00
#define NS_VCI          0x01
#define NS_PDU          0x02
#define BVCI            0x03
#define NSEI            0x04

static gint proto_gprs_ns = -1;
static gint ett_gprs_ns = -1;
static gint hf_gprs_ns_vci = -1;
static gint hf_gprs_ns_pdutype = -1;
static gint hf_gprs_ns_nsei = -1;
static gint hf_gprs_ns_bvci = -1;
static gint hf_gprs_ns_spare = -1;
static gint hf_gprs_ns_cause = -1;
 
static const value_string ns_pdu_type[]= {
        { NS_UNITDATA,    "NS-UNITDATA" },
        { NS_RESET,       "NS-RESET" },
        { NS_RESET_ACK,   "NS-RESET-ACK" },
        { NS_BLOCK,       "NS-BLOCK" },
        { NS_BLOCK_ACK,   "NS-BLOCK-ACK" },
        { NS_UNBLOCK,     "NS-UNBLOCK" },
        { NS_UNBLOCK_ACK, "NS-UNBLOCK-ACK" },
        { NS_STATUS,      "NS-STATUS" },
        { NS_ALIVE,       "NS-ALIVE" },
        { NS_ALIVE_ACK,   "NS-ALIVE-ACK" },
        { 0,               NULL },
};

static const value_string ns_ie_type[]= {
        {  Cause,   "Cause" },
        {  NS_VCI,  "NS-VCI"},  
        {  NS_PDU,  "NS PDU"},  
        {  BVCI,    "BVCI"}, 
        {  NSEI,    "NSEI"},
        {  0,        NULL },
};

static const value_string cause_val[]= {
        { 0x0,    "Transit network failure" },
        { 0x1,    "O&M intervention" },
        { 0x2,    "Equipment failure" },
        { 0x3,    "NS-VC blocked " },
        { 0x4,    "NS-VC unknown" },
        { 0x5,    "NS-VC unknown on that NSE" },
        { 0x8,    "Semantically incorrect PDU" },
        { 0xa,    "PDU not compatible with protocol state" },
        { 0xb,    "Protocol error - unspecified" },
        { 0xc,    "Invalid essential IE" },
        { 0xd,    "Missing essential IE" },
        { 0,      NULL },	
};
 
static dissector_handle_t data_handle;

static void
dissect_gprs_ns(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	proto_item *ti = NULL;
	proto_tree *gprs_ns_tree = NULL;
	guint8 nspdu, cause;
	guint16 nsvc, bvc;
	tvbuff_t *next_tvb;
  
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "GPRS NS");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	nspdu = tvb_get_guint8(tvb,offset);
	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_str(pinfo->cinfo, COL_INFO, match_strval(nspdu, ns_pdu_type));
	if (tree) {
		ti = proto_tree_add_item(tree, proto_gprs_ns, tvb, 0, -1, FALSE);
		gprs_ns_tree = proto_item_add_subtree(ti, ett_gprs_ns);
		proto_tree_add_uint(gprs_ns_tree, hf_gprs_ns_pdutype, tvb, 0, 1, nspdu);
	}
	offset++;

	switch (nspdu) {

	case NS_ALIVE:
	case NS_ALIVE_ACK:
	case NS_UNBLOCK:
	case NS_UNBLOCK_ACK:
		break;

	case NS_BLOCK:
		offset=offset+2;
		cause = tvb_get_guint8(tvb,offset);
		if (tree)
			proto_tree_add_uint(gprs_ns_tree, hf_gprs_ns_cause, tvb, offset, 1, cause);
		offset=offset+3;
		nsvc = tvb_get_ntohs(tvb,offset);
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, " NSVCI: %u Cause: %s", nsvc,
					match_strval(cause,cause_val));
		if (tree)
			proto_tree_add_uint(gprs_ns_tree, hf_gprs_ns_vci, tvb, offset, 2, nsvc);
		offset=offset+2;
		break;

	case NS_BLOCK_ACK:
		offset=offset+3;
		nsvc = tvb_get_ntohs(tvb,offset);
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, " NSVCI: %u", nsvc);
		if (tree)
			proto_tree_add_uint(gprs_ns_tree, hf_gprs_ns_vci, tvb, offset, 2, nsvc);
		offset=offset+2;
		break;

	case NS_RESET:
		offset=offset+2;
		cause = tvb_get_guint8(tvb,offset);
		if (tree)
			proto_tree_add_uint(gprs_ns_tree, hf_gprs_ns_cause, tvb, offset, 1, cause);
		offset=offset+3;
		nsvc = tvb_get_ntohs(tvb,offset);
		if (tree)
			proto_tree_add_uint(gprs_ns_tree, hf_gprs_ns_vci, tvb, offset, 2, nsvc);
		offset=offset+4;
		bvc = tvb_get_ntohs(tvb,offset); 		
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, " NSVCI: %u NSEI: %u Cause: %s",
					nsvc, bvc, match_strval(cause, cause_val));
		if (tree)
			proto_tree_add_uint(gprs_ns_tree, hf_gprs_ns_nsei, tvb, offset, 2, bvc);
		offset=offset+2;
		break;

	case NS_RESET_ACK:
		offset=offset+2;
		nsvc = tvb_get_ntohs(tvb,offset);
		if (tree)
			proto_tree_add_uint(gprs_ns_tree, hf_gprs_ns_vci, tvb, offset, 2, nsvc);
		offset=offset+4;
		bvc = tvb_get_ntohs(tvb,offset); 		
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, " NSVCI: %u NSEI: %u", nsvc, bvc);
		if (tree)
			proto_tree_add_uint(gprs_ns_tree, hf_gprs_ns_nsei, tvb, offset, 2, bvc);
		offset=offset+2;
		break;

	case NS_UNITDATA:
		if (tree)
			proto_tree_add_item(gprs_ns_tree, hf_gprs_ns_spare, tvb, offset, 1, FALSE);
		offset++;
		bvc = tvb_get_ntohs(tvb,offset);
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, " BVCI: %u", bvc);
		if (tree)
			proto_tree_add_uint(gprs_ns_tree, hf_gprs_ns_bvci, tvb, offset, 2, bvc);
		offset=offset+2;
		next_tvb = tvb_new_subset(tvb, offset, -1, -1);
		call_dissector(data_handle, next_tvb, pinfo, tree);
		break;

	case NS_STATUS:
		break;		 

	default:
		break;
	}
}

/* Register the protocol with Ethereal */
void
proto_register_gprs_ns(void)
{
	static hf_register_info hf[] = {
		{ &hf_gprs_ns_pdutype, {
		  "PDU Type", "gprs_ns.pdutype", FT_UINT8, BASE_HEX,
		  VALS(ns_pdu_type), 0x0, "NS Command", HFILL}},
		{ &hf_gprs_ns_cause, {
		  "Cause", "gprs_ns.cause", FT_UINT8, BASE_HEX,
		  VALS(cause_val), 0x0, "Cause", HFILL}},
		{ &hf_gprs_ns_vci, {
		  "NSVCI", "gprs_ns.nsvci", FT_UINT16, BASE_DEC,
		  NULL, 0x0, "Network Service Virtual Connection id", HFILL}},
		{ &hf_gprs_ns_nsei, {
		  "NSEI", "gprs_ns.nsei", FT_UINT16, BASE_DEC,
		  NULL, 0x0, "Network Service Entity Id", HFILL}},
		{ &hf_gprs_ns_bvci, {
		  "BVCI", "gprs_ns.bvci", FT_UINT16, BASE_DEC,
		  NULL, 0x0, "Cell ID", HFILL}},
		{ &hf_gprs_ns_spare, {
		  "Spare octet", "gprs_ns.spare", FT_UINT8, BASE_HEX,
		  NULL, 0x0, "", HFILL}},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		 &ett_gprs_ns,
	};

	proto_gprs_ns = proto_register_protocol("GPRS Network service",
	    "GPRS NS","gprs_ns");
	proto_register_field_array(proto_gprs_ns, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("gprs_ns", dissect_gprs_ns, proto_gprs_ns);
}

void
proto_reg_handoff_gprs_ns(void)
{
        data_handle = find_dissector("data");
}
