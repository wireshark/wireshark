/* packet-nstrace.c
 * Routines for nstrace dissection
 * Copyright 2006, Ravi Kondamuru <Ravi.Kondamuru@citrix.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <wiretap/netscaler.h>

static int proto_nstrace = -1;

static int hf_ns_nicno = -1;
static int hf_ns_dir = -1;
static int hf_ns_pcbdevno = -1;
static int hf_ns_l_pcbdevno = -1;
static int hf_ns_devno = -1;
static int hf_ns_vlantag = -1;
static int hf_ns_coreid = -1;

static gint ett_ns = -1;

static const value_string ns_dir_vals[] = {
	{ NSPR_PDPKTRACEFULLTX_V10, "TX" },
	{ NSPR_PDPKTRACEFULLTX_V20, "TX" },
	{ NSPR_PDPKTRACEFULLTXB_V10, "TXB" },
	{ NSPR_PDPKTRACEFULLTXB_V20, "TXB" },
	{ NSPR_PDPKTRACEFULLRX_V10, "RX" },
	{ NSPR_PDPKTRACEFULLRX_V20, "RX" },
	{ NSPR_PDPKTRACEPARTTX_V10, "TX"  },
	{ NSPR_PDPKTRACEPARTTX_V20, "TX" },
	{ NSPR_PDPKTRACEPARTTXB_V10, "TXB" },
	{ NSPR_PDPKTRACEPARTTXB_V20, "TXB" },
	{ NSPR_PDPKTRACEPARTRX_V10, "RX" },
	{ NSPR_PDPKTRACEPARTRX_V20, "RX" },
	{ NSPR_PDPKTRACEFULLTX_V21, "TX" },
	{ NSPR_PDPKTRACEFULLTXB_V21, "TXB" },
	{ NSPR_PDPKTRACEFULLRX_V21, "RX" },
	{ NSPR_PDPKTRACEPARTTX_V21, "TX" },
	{ NSPR_PDPKTRACEPARTTXB_V21, "TXB" },
	{ NSPR_PDPKTRACEPARTRX_V21, "RX" },
	{ NSPR_PDPKTRACEFULLTX_V22, "TX" },
	{ NSPR_PDPKTRACEFULLTX_V23, "TX" },
	{ NSPR_PDPKTRACEFULLTXB_V22, "TXB" },
	{ NSPR_PDPKTRACEFULLTXB_V23, "TXB" },
	{ NSPR_PDPKTRACEFULLRX_V22, "RX" },
	{ NSPR_PDPKTRACEFULLRX_V23, "RX" },
	{ NSPR_PDPKTRACEPARTTX_V22, "TX" },
	{ NSPR_PDPKTRACEPARTTX_V23, "TX" },
	{ NSPR_PDPKTRACEPARTTXB_V22, "TXB" },
	{ NSPR_PDPKTRACEPARTTXB_V23, "TXB" },
	{ NSPR_PDPKTRACEPARTRX_V22, "RX" },
	{ NSPR_PDPKTRACEPARTRX_V23, "RX" },
	{ 0,              NULL }
};

static dissector_handle_t eth_withoutfcs_handle;


static void
dissect_nstrace(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree   *ns_tree = NULL;
	proto_item   *ti = NULL;
	struct nstr_phdr *pnstr = &(pinfo->pseudo_header->nstr);
	tvbuff_t     *next_tvb_eth_client;
	guint8        offset;


	ti = proto_tree_add_protocol_format(tree, proto_nstrace, tvb, 0, pnstr->eth_offset, "NetScaler Packet Trace");
	ns_tree = proto_item_add_subtree(ti, ett_ns);
  
	proto_tree_add_item(ns_tree, hf_ns_dir, tvb, pnstr->dir_offset, pnstr->dir_len, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ns_tree, hf_ns_nicno, tvb, pnstr->nicno_offset, pnstr->nicno_len, ENC_LITTLE_ENDIAN);

	switch (pnstr->rec_type)
	{
	case NSPR_HEADER_VERSION203:
		proto_tree_add_item(ns_tree, hf_ns_coreid, tvb, pnstr->coreid_offset, 2, ENC_LITTLE_ENDIAN);
		/* fall through to next case */

	case NSPR_HEADER_VERSION202:
		col_add_fstr(pinfo->cinfo, COL_8021Q_VLAN_ID, "%d", tvb_get_letohs(tvb, pnstr->vlantag_offset));
		proto_tree_add_item(ns_tree, hf_ns_vlantag, tvb, pnstr->vlantag_offset, 2, ENC_LITTLE_ENDIAN);
		/* fall through to next case */

	case NSPR_HEADER_VERSION201:
		proto_tree_add_item(ns_tree, hf_ns_pcbdevno, tvb, pnstr->pcb_offset, 4, ENC_LITTLE_ENDIAN);
		ti = proto_tree_add_item(ns_tree, hf_ns_devno, tvb, pnstr->pcb_offset, 4, ENC_LITTLE_ENDIAN);
		PROTO_ITEM_SET_HIDDEN(ti);

		proto_tree_add_item(ns_tree, hf_ns_l_pcbdevno, tvb, pnstr->l_pcb_offset, 4, ENC_LITTLE_ENDIAN);
		ti = proto_tree_add_item(ns_tree, hf_ns_devno, tvb, pnstr->l_pcb_offset, 4, ENC_LITTLE_ENDIAN);
		PROTO_ITEM_SET_HIDDEN(ti);

		break;

	default:
		break;
	}
  
	/* Dissect as Ethernet */
	offset = pnstr->eth_offset;
	next_tvb_eth_client = tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset), tvb_reported_length_remaining(tvb, offset));
	call_dissector(eth_withoutfcs_handle, next_tvb_eth_client, pinfo, tree);  
}

void
proto_register_ns(void)
{
	static hf_register_info hf[] = {

		{ &hf_ns_nicno,
		  { "Nic No",		"nstrace.nicno", FT_UINT8, BASE_DEC,NULL, 0x0,
			NULL, HFILL }},

		{ &hf_ns_coreid,
		  { "Core Id",		"nstrace.coreid", FT_UINT16, BASE_DEC,NULL, 0x0,
			NULL, HFILL }},

		{ &hf_ns_dir,
		  { "Operation",	"nstrace.dir", FT_UINT8, BASE_HEX,  VALS(ns_dir_vals), 0x0,
			NULL, HFILL }},

		{ &hf_ns_pcbdevno,
		  { "PcbDevNo",		"nstrace.pdevno", FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_ns_l_pcbdevno,
		  { "Linked PcbDevNo",	"nstrace.l_pdevno", FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_ns_devno,
		  { "DevNo",		"nstrace.devno", FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_ns_vlantag,
		  { "Vlan",		"nstrace.vlan", FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},	

	};

	static gint *ett[] = {
		&ett_ns,
	};

	proto_nstrace = proto_register_protocol("NetScaler Trace", "NS Trace", "ns");
	proto_register_field_array(proto_nstrace, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}


void proto_reg_handoff_ns(void)
{
	dissector_handle_t nstrace_handle;

	eth_withoutfcs_handle = find_dissector("eth_withoutfcs");

	nstrace_handle = create_dissector_handle(dissect_nstrace, proto_nstrace);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_NSTRACE_1_0, nstrace_handle);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_NSTRACE_2_0, nstrace_handle);
}
