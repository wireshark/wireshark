/* packet-gprs-ns.c
 * Routines for GPRS Network Service (ETSI GSM 08.16 version 6.3.0)
 * dissection
 * Copyright 2003, Josef Korelus <jkor@quick.cz>
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

static int proto_gprs_ns = -1;
static gint ett_gprs_ns = -1;
static int hf_gprs_ns_pdutype = -1;
static int hf_gprs_ns_ie_type = -1;
static int hf_gprs_ns_ie_length = -1;
static int hf_gprs_ns_cause = -1;
static int hf_gprs_ns_vci = -1;
static int hf_gprs_ns_nsei = -1;
static int hf_gprs_ns_bvci = -1;
static int hf_gprs_ns_spare = -1;
 
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
 
static dissector_handle_t bssgp_handle;

static void
process_tlvs(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	guint8 type;
	int length_len;
	guint16 length;
	guint8 cause;
	guint16 nsvc, bvc, nsei;

	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		type = tvb_get_guint8(tvb, offset);
		proto_tree_add_uint(tree, hf_gprs_ns_ie_type,
		    tvb, offset, 1, type);
		offset++;

		length_len = 1;
		length = tvb_get_guint8(tvb, offset);
		if (length & 0x80) {
			/*
			 * This is the final octet of the length.
			 */
			length &= 0x7F;
		} else {
			/*
			 * One more octet.
			 */
			length_len++;
			length = (length << 8) | tvb_get_guint8(tvb, offset);
		}
		proto_tree_add_uint(tree, hf_gprs_ns_ie_length,
		    tvb, offset, length_len, length);
		offset += length_len;

		switch (type) {

		case Cause:
			if (length == 1) {
				cause = tvb_get_guint8(tvb, offset);
				if (tree) {
					proto_tree_add_uint(tree,
					    hf_gprs_ns_cause, tvb, offset, 1,
					    cause);
				}
				if (check_col(pinfo->cinfo, COL_INFO)) {
					col_append_fstr(pinfo->cinfo, COL_INFO,
					    "  Cause: %s",
					    val_to_str(cause, cause_val, "Unknown (0x%02x)"));
				}
			} else {
				if (tree) {
					proto_tree_add_text(tree,
					    tvb, offset, length,
					    "Bad cause length %u, should be 1",
					    length);
				}
			}
			break;

		case NS_VCI:
			if (length == 2) {
				nsvc = tvb_get_ntohs(tvb, offset);
				if (tree) {
					proto_tree_add_uint(tree,
					    hf_gprs_ns_vci, tvb, offset, 2,
					    nsvc);
				}
				if (check_col(pinfo->cinfo, COL_INFO)) {
					col_append_fstr(pinfo->cinfo, COL_INFO,
					    " NSVCI: %u", nsvc);
				}
			} else {
				if (tree) {
					proto_tree_add_text(tree,
					    tvb, offset, length,
					    "Bad NS-VCI length %u, should be 2",
					    length);
				}
			}
			break;

		case NS_PDU:
			/*
			 * XXX - dissect as a GPRS NS PDU.
			 * Do the usual "error packet" stuff.
			 */
			if (tree) {
				proto_tree_add_text(tree,
				    tvb, offset, length,
				    "Error PDU");
			}
			break;

		case BVCI:
			if (length == 2) {
				bvc = tvb_get_ntohs(tvb, offset);
				if (tree) {
					proto_tree_add_uint(tree,
					    hf_gprs_ns_bvci, tvb, offset, 2,
					    bvc);
				}
				if (check_col(pinfo->cinfo, COL_INFO)) {
					col_append_fstr(pinfo->cinfo, COL_INFO,
					    " BVCI: %u", bvc);
				}
			} else {
				if (tree) {
					proto_tree_add_text(tree,
					    tvb, offset, length,
					    "Bad BVCI length %u, should be 2",
					    length);
				}
			}
			break;

		case NSEI:
			if (length == 2) {
				nsei = tvb_get_ntohs(tvb, offset);
				if (tree) {
					proto_tree_add_uint(tree,
					    hf_gprs_ns_nsei, tvb, offset, 2,
					    nsei);
				}
				if (check_col(pinfo->cinfo, COL_INFO)) {
					col_append_fstr(pinfo->cinfo, COL_INFO,
					    " NSEI: %u", nsei);
				}
			} else {
				if (tree) {
					proto_tree_add_text(tree,
					    tvb, offset, length,
					    "Bad NSEI length %u, should be 2",
					    length);
				}
			}
			break;

		default:
			if (tree) {
				proto_tree_add_text(tree,
				    tvb, offset, length,
				    "Unknown IE contents");
			}
			break;
		}
		offset += length;	
	}
}

static void
dissect_gprs_ns(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	proto_item *ti = NULL;
	proto_tree *gprs_ns_tree = NULL;
	guint8 nspdu;
	guint16 bvc;
	tvbuff_t *next_tvb;
  
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "GPRS NS");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	nspdu = tvb_get_guint8(tvb,offset);
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_str(pinfo->cinfo, COL_INFO,
		    val_to_str(nspdu, ns_pdu_type, "Unknown PDU type (0x%02x)"));
	}
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
	case NS_BLOCK_ACK:
	case NS_RESET:
	case NS_RESET_ACK:
	case NS_STATUS:
		/*
		 * Process TLVs.
		 */
		process_tlvs(tvb, offset, pinfo, gprs_ns_tree);
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
		call_dissector(bssgp_handle, next_tvb, pinfo, tree);
		break;

	default:
		break;
	}
}

/* Register the protocol with Wireshark */
void
proto_register_gprs_ns(void)
{
	static hf_register_info hf[] = {
		{ &hf_gprs_ns_pdutype, {
		  "PDU Type", "gprs_ns.pdutype", FT_UINT8, BASE_HEX,
		  VALS(ns_pdu_type), 0x0, "NS Command", HFILL}},
		{ &hf_gprs_ns_ie_type, {
		  "IE Type", "gprs_ns.ietype", FT_UINT8, BASE_HEX,
		  VALS(ns_ie_type), 0x0, "IE Type", HFILL}},
		{ &hf_gprs_ns_ie_length, {
		  "IE Length", "gprs_ns.ielength", FT_UINT16, BASE_DEC,
		  NULL, 0x0, "IE Length", HFILL}},
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
        bssgp_handle = find_dissector("bssgp");
}
