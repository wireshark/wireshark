/* packet-isis-snp.c
 * Routines for decoding isis complete & partial SNP and their payload
 *
 * $Id: packet-isis-snp.c,v 1.10 2001/07/02 00:19:34 guy Exp $
 * Stuart Stanley <stuarts@mxmail.net>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
 *
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include "packet.h"
#include "packet-osi.h"
#include "packet-isis.h"
#include "packet-isis-clv.h"
#include "packet-isis-lsp.h"
#include "packet-isis-snp.h"

/* csnp packets */
static int proto_isis_csnp = -1;
static int hf_isis_csnp_pdu_length = -1;
static gint ett_isis_csnp = -1;
static gint ett_isis_csnp_lsp_entries = -1;
static gint ett_isis_csnp_authentication = -1;
static gint ett_isis_csnp_clv_unknown = -1;

/* psnp packets */
static int proto_isis_psnp = -1;
static int hf_isis_psnp_pdu_length = -1;
static gint ett_isis_psnp = -1;
static gint ett_isis_psnp_lsp_entries = -1;
static gint ett_isis_psnp_authentication = -1;
static gint ett_isis_psnp_clv_unknown = -1;

static void dissect_l1_snp_authentication_clv(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int offset,
	int id_length, int length);
static void dissect_l2_snp_authentication_clv(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int offset,
	int id_length, int length);
static void dissect_snp_lsp_entries(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int offset,
	int id_length, int length);

static const isis_clv_handle_t clv_l1_csnp_opts[] = {
	{
		ISIS_CLV_L1_CSNP_LSP_ENTRIES,
		"LSP entries",
		&ett_isis_csnp_lsp_entries,
		dissect_snp_lsp_entries
	},
	{
		ISIS_CLV_L1_CSNP_AUTHENTICATION_NS,
		"Authentication(non spec)",
		&ett_isis_csnp_authentication,
		dissect_l1_snp_authentication_clv
	},
	{
		ISIS_CLV_L1_CSNP_AUTHENTICATION,
		"Authentication",
		&ett_isis_csnp_authentication,
		dissect_l1_snp_authentication_clv
	},
	{
		0, "", NULL, NULL 
	}
};

static const isis_clv_handle_t clv_l2_csnp_opts[] = {
	{
		ISIS_CLV_L2_CSNP_LSP_ENTRIES,
		"LSP entries",
		&ett_isis_csnp_lsp_entries,
		dissect_snp_lsp_entries
	},
	{
		ISIS_CLV_L2_CSNP_AUTHENTICATION_NS,
		"Authentication(non spec)",
		&ett_isis_csnp_authentication,
		dissect_l2_snp_authentication_clv
	},
	{
		ISIS_CLV_L2_CSNP_AUTHENTICATION,
		"Authentication",
		&ett_isis_csnp_authentication,
		dissect_l2_snp_authentication_clv
	},
	{
		0, "", NULL, NULL 
	}
};

static const isis_clv_handle_t clv_l1_psnp_opts[] = {
	{
		ISIS_CLV_L1_PSNP_LSP_ENTRIES,
		"LSP entries",
		&ett_isis_psnp_lsp_entries,
		dissect_snp_lsp_entries
	},
	{
		ISIS_CLV_L1_PSNP_AUTHENTICATION_NS,
		"Authentication(non spec)",
		&ett_isis_psnp_authentication,
		dissect_l1_snp_authentication_clv
	},
	{
		ISIS_CLV_L1_PSNP_AUTHENTICATION,
		"Authentication",
		&ett_isis_psnp_authentication,
		dissect_l1_snp_authentication_clv
	},
	{
		0, "", NULL, NULL 
	}
};

static const isis_clv_handle_t clv_l2_psnp_opts[] = {
	{
		ISIS_CLV_L2_PSNP_LSP_ENTRIES,
		"LSP entries",
		&ett_isis_psnp_lsp_entries,
		dissect_snp_lsp_entries
	},
	{
		ISIS_CLV_L2_PSNP_AUTHENTICATION,
		"Authentication",
		&ett_isis_psnp_authentication,
		dissect_l2_snp_authentication_clv
	},
	{
		ISIS_CLV_L2_PSNP_AUTHENTICATION_NS,
		"Authentication(non spec)",
		&ett_isis_psnp_authentication,
		dissect_l2_snp_authentication_clv
	},
	{
		0, "", NULL, NULL 
	}
};
/*
 * Name: dissect_snp_lsp_entries()
 *
 * Description:
 *	All the snp packets use a common payload format.  We have up
 *	to n entries (based on length), which are made of:
 *		2 : remaining life time
 *		8 : lsp id
 *		4 : sequence number
 *		2 : checksum
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	packet_info * : info for current packet
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : offset into packet data where we are.
 *	int : length of payload to decode.
 *	int : length of IDs in packet.
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void 
dissect_snp_lsp_entries(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	int offset, int id_length, int length)
{
	while ( length > 0 ) {
		if ( length < 2+id_length+2+4+2 ) {
			isis_dissect_unknown(tvb, pinfo, tree, offset,
				"Short SNP header entry (%d vs %d)", length,
				2+id_length+2+4+2 );
			return;
		}
		
		proto_tree_add_text(tree, tvb, offset, 2, "Remaining life      : %d",
			tvb_get_ntohs(tvb, offset));
		length -= 2;
		offset += 2;

		isis_lsp_decode_lsp_id(tvb, pinfo, tree, offset,
			 "LSP ID              ", id_length);
		length -= id_length + 2;
		offset += id_length + 2;

		proto_tree_add_text(tree, tvb, offset, 4, 
			"LSP Sequence Number : 0x%04x",
			tvb_get_ntohl(tvb, offset));
		length -= 4;
		offset += 4;

		proto_tree_add_text(tree, tvb, offset, 2, 
			"LSP checksum        : 0x%02x",
			tvb_get_ntohs(tvb, offset));
		length -= 2;
		offset += 2;
	}

}

/*
 * Name: isis_dissect_isis_csnp()
 *
 * Description:
 *	Tear apart a L1 or L2 CSNP header and then call into payload dissect
 *	to pull apart the lsp id payload.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	packet_info * : info for current packet
 *	proto_tree * : protocol display tree to add to.  May be NULL.
 *	int offset : our offset into packet data.
 *	int : type (l1 csnp, l2 csnp)
 *	int : header length of packet.
 *	int : length of IDs in packet.
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
void 
isis_dissect_isis_csnp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	int offset, int type, int header_length, int id_length)
{
	proto_item	*ti;
	proto_tree	*csnp_tree = NULL;
	guint16		pdu_length;
	int 		len;

	if (!proto_is_protocol_enabled(proto_isis_csnp)) {
		dissect_data(tvb, offset, pinfo, tree);
		return;
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_isis_csnp, tvb,
			offset, tvb_length_remaining(tvb, offset), FALSE);
		csnp_tree = proto_item_add_subtree(ti, ett_isis_csnp);
	}

	pdu_length = tvb_get_ntohs(tvb, offset);
	if (tree) {
		proto_tree_add_uint(csnp_tree, hf_isis_csnp_pdu_length, tvb,
			offset, 2, pdu_length);
	}
	offset += 2;

	if (tree) {
		proto_tree_add_text(csnp_tree, tvb, offset, id_length + 1, 
			"Source id    : %s",
				print_system_id( tvb_get_ptr(tvb, offset, id_length+1), id_length+1 ) );
	}
	offset += id_length + 1;

	if (tree) {
		isis_lsp_decode_lsp_id(tvb, pinfo, csnp_tree, offset,
			"Start LSP id ", id_length );
	}
	offset += id_length + 2;

	if (tree) {
		isis_lsp_decode_lsp_id(tvb, pinfo, csnp_tree, offset,
			 "End   LSP id ", id_length );
	}
	offset += id_length + 2;

	len = pdu_length - header_length;
	if (len < 0) {
		return;
	}
	/* Call into payload dissector */
	if (type == ISIS_TYPE_L1_CSNP ) {
		isis_dissect_clvs(tvb, pinfo, csnp_tree, offset,
			clv_l1_csnp_opts, len, id_length,
			ett_isis_csnp_clv_unknown );
	} else {
		isis_dissect_clvs(tvb, pinfo, csnp_tree, offset,
			clv_l2_csnp_opts, len, id_length,
			ett_isis_csnp_clv_unknown );
	}
}

/*
 * Name: isis_dissect_isis_psnp()
 *
 * Description:
 *	Tear apart a L1 or L2 PSNP header and then call into payload dissect
 *	to pull apart the lsp id payload.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	packet_info * : info for current packet
 *	proto_tree * : protocol display tree to add to.  May be NULL.
 *	int : our offset into packet data
 *	int : type (l1 psnp, l2 psnp)
 *	int : header length of packet.
 *	int : length of IDs in packet.
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
void 
isis_dissect_isis_psnp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	int offset, int type, int header_length, int id_length)
{
	proto_item	*ti;
	proto_tree	*psnp_tree = NULL;
	guint16		pdu_length;
	int 		len;

	if (!proto_is_protocol_enabled(proto_isis_psnp)) {
		dissect_data(tvb, offset, pinfo, tree);
		return;
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_isis_psnp, tvb,
			offset, tvb_length_remaining(tvb, offset), FALSE);
		psnp_tree = proto_item_add_subtree(ti, ett_isis_psnp);
	}

	pdu_length = tvb_get_ntohs(tvb, offset);
	if (tree) {
		proto_tree_add_uint(psnp_tree, hf_isis_psnp_pdu_length, tvb,
			offset, 2, pdu_length);
	}
	offset += 2;

	if (tree) {
		proto_tree_add_text(psnp_tree, tvb, offset, id_length + 1,
			"Source id: %s",
			print_system_id( tvb_get_ptr(tvb, offset, id_length+1), id_length + 1 ) );
	}
	offset += id_length + 1;

	len = pdu_length - header_length;
	if (len < 0) {
		isis_dissect_unknown(tvb, pinfo, tree, offset,
			"packet header length %d went beyond packet",
			header_length );
		return;
	}
	/* Call into payload dissector */
	if (type == ISIS_TYPE_L1_CSNP ) {
		isis_dissect_clvs(tvb, pinfo, psnp_tree, offset,
			clv_l1_csnp_opts, len, id_length,
			ett_isis_psnp_clv_unknown );
	} else {
		isis_dissect_clvs(tvb, pinfo, psnp_tree, offset,
			clv_l2_csnp_opts, len, id_length,
			ett_isis_psnp_clv_unknown );
	}
}

/*
 * Name: dissect_L1_snp_authentication_clv()
 *
 * Description:
 *	Decode for a lsp packets authenticaion clv.  Calls into the
 *	clv common one.  An auth inside a L1 SNP is a per area password
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	packet_info * : info for current packet
 *	proto_tree * : proto tree to build on (may be null)
 *	int : current offset into packet data
 *	int : length of IDs in packet.
 *	int : length of this clv
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void 
dissect_l1_snp_authentication_clv(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int offset,
	int id_length, int length)
{
	isis_dissect_authentication_clv(tvb, pinfo, tree, offset, length,
		"Per area authentication" );
}

/*
 * Name: dissect_l2_authentication_clv()
 *
 * Description:
 *	Decode for a lsp packets authenticaion clv.  Calls into the
 *	clv common one.  An auth inside a L2 LSP is a per domain password
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	packet_info * : info for current packet
 *	proto_tree * : proto tree to build on (may be null)
 *	int : current offset into packet data
 *	int : length of IDs in packet.
 *	int : length of this clv
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void 
dissect_l2_snp_authentication_clv(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int offset,
	int id_length, int length)
{
	isis_dissect_authentication_clv(tvb, pinfo, tree, offset, length,
		"Per domain authentication" );
}

/*
 * Name: proto_register_isis_csnp()
 *
 * Description: 
 *	Register our protocol sub-sets with protocol manager.
 *	NOTE: this procedure is autolinked by the makefile process that
 *		builds register.c
 *
 */
void 
proto_register_isis_csnp(void) {
	static hf_register_info hf[] = {
		{ &hf_isis_csnp_pdu_length,
		{ "PDU length",		"isis_csnp.pdu_length", FT_UINT16, 
		  BASE_DEC, NULL, 0x0, "", HFILL }},
	};
	static gint *ett[] = {
		&ett_isis_csnp,
		&ett_isis_csnp_lsp_entries,
		&ett_isis_csnp_authentication,
		&ett_isis_csnp_clv_unknown,
	};

	proto_isis_csnp = proto_register_protocol(PROTO_STRING_CSNP,
	    "ISIS CSNP", "isis_csnp");
	proto_register_field_array(proto_isis_csnp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}


/*
 * Name: proto_register_isis_psnp()
 *
 * Description: 
 *	Register our protocol sub-sets with protocol manager.
 *	NOTE: this procedure is autolinked by the makefile process that
 *		builds register.c
 */
void 
proto_register_isis_psnp(void) {
	static hf_register_info hf[] = {
		{ &hf_isis_psnp_pdu_length,
		{ "PDU length",		"isis_psnp.pdu_length", FT_UINT16, 
		  BASE_DEC, NULL, 0x0, "", HFILL }},
	};
	static gint *ett[] = {
		&ett_isis_psnp,
		&ett_isis_psnp_lsp_entries,
		&ett_isis_psnp_authentication,
		&ett_isis_psnp_clv_unknown,
	};

	proto_isis_psnp = proto_register_protocol(PROTO_STRING_PSNP,
	    "ISIS PSNP", "isis_psnp");
	proto_register_field_array(proto_isis_psnp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}
