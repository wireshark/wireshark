/* packet-isis-snp.c
 * Routines for decoding isis complete & partial SNP and their payload
 *
 * $Id: packet-isis-snp.c,v 1.7 2000/08/13 14:08:22 deniel Exp $
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

static void dissect_snp_lsp_entries(const u_char *pd, int offset,
		guint length, int id_length, frame_data *fd, proto_tree *tree );
static void dissect_l1_snp_authentication_clv(const u_char *pd, int offset,
		guint length, int id_length, frame_data *fd, proto_tree *tree );
static void dissect_l2_snp_authentication_clv(const u_char *pd, int offset,
		guint length, int id_length, frame_data *fd, proto_tree *tree );

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
 *	u_char * : packet data
 *	int : offset into packet data where we are.
 *	guint : length of payload to decode.
 *	int : length of IDs in packet.
 *	frame_data * : frame data (complete frame)
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void 
dissect_snp_lsp_entries(const u_char *pd, int offset, guint length, 
		int id_length, frame_data *fd, proto_tree *tree ) {
	while ( length > 0 ) {
		if ( length < 2+id_length+2+4+2 ) {
			isis_dissect_unknown(offset, length, tree, fd,
				"Short SNP header entry (%d vs %d)", length,
				2+id_length+2+4+2 );
			return;
		}
		
		proto_tree_add_text(tree, NullTVB, offset, 2, "Remaining life      : %d",
			pntohs(&pd[offset]));
		length -= 2;
		offset += 2;

		isis_lsp_decode_lsp_id( "LSP ID              ", tree, pd,
			offset, id_length);
		length -= id_length + 2;
		offset += id_length + 2;

		proto_tree_add_text(tree, NullTVB, offset, 4, 
			"LSP Sequence Number : 0x%04x",
			pntohl(&pd[offset]));
		length -= 4;
		offset += 4;

		proto_tree_add_text(tree, NullTVB, offset, 2, 
			"LSP checksum        : 0x%02x",
			pntohs(&pd[offset]));
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
 *	int : type (l1 csnp, l2 csnp)
 *	int : header length of packet.
 *	int : length of IDs in packet.
 *	u_char * : packet data
 *	int offset : our offset into packet data.
 *	frame_data * : frame data
 *	proto_tree * : protocol display tree to add to.  May be NULL.
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
void 
isis_dissect_isis_csnp(int type, int header_length, int id_length,
		const u_char *pd, int offset, frame_data *fd, proto_tree *tree){
	proto_item	*ti;
	proto_tree	*csnp_tree = NULL;
	int		hlen;
	guint16		pdu_length;
	int 		len;

	OLD_CHECK_DISPLAY_AS_DATA(proto_isis_csnp, pd, offset, fd, tree);

	hlen = 2+id_length+1+id_length+2+id_length+2;

	if (!BYTES_ARE_IN_FRAME(offset, hlen)) {
		isis_dissect_unknown(offset, hlen, tree, fd,
			"not enough capture data for header (%d vs %d)",
			 hlen, END_OF_FRAME);
		return;
	}
	
	if (tree) {
		ti = proto_tree_add_item(tree, proto_isis_csnp, NullTVB,
			offset, END_OF_FRAME, FALSE);
		csnp_tree = proto_item_add_subtree(ti, ett_isis_csnp);
	}

	pdu_length = pntohs(&pd[offset]);
	if (tree) {
		proto_tree_add_uint(csnp_tree, hf_isis_csnp_pdu_length, NullTVB,
			offset, 2, pdu_length);
	}
	offset += 2;

	if (tree) {
		proto_tree_add_text(csnp_tree, NullTVB, offset, id_length + 1, 
			"Source id    : %s",
				print_system_id( pd + offset, id_length + 1 ) );
	}
	offset += id_length + 1;

	if (tree) {
		isis_lsp_decode_lsp_id( "Start LSP id ", csnp_tree, pd, offset,
			id_length );
	}
	offset += id_length + 2;

	if (tree) {
		isis_lsp_decode_lsp_id( "End   LSP id ", csnp_tree, pd, offset,
			id_length );
	}
	offset += id_length + 2;

	len = pdu_length - header_length;
	if (len < 0) {
		return;
	}
	/* Call into payload dissector */
	if (type == ISIS_TYPE_L1_CSNP ) {
		isis_dissect_clvs ( clv_l1_csnp_opts, len, id_length, pd,
			offset, fd, csnp_tree, ett_isis_csnp_clv_unknown );
	} else {
		isis_dissect_clvs ( clv_l2_csnp_opts, len, id_length, pd,
			offset, fd, csnp_tree, ett_isis_csnp_clv_unknown );
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
 *	int : type (l1 psnp, l2 psnp)
 *	int : header length of packet.
 *	int : length of IDs in packet.
 *	u_char * : packet data
 *	int offset : our offset into packet data.
 *	frame_data * : frame data
 *	proto_tree * : protocol display tree to add to.  May be NULL.
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
void 
isis_dissect_isis_psnp(int type, int header_length, int id_length,
		const u_char *pd, int offset, frame_data *fd, proto_tree *tree){
	proto_item	*ti;
	proto_tree	*psnp_tree = NULL;
	int		hlen;
	guint16		pdu_length;
	int 		len;

	OLD_CHECK_DISPLAY_AS_DATA(proto_isis_psnp, pd, offset, fd, tree);
    
	hlen = 2+id_length+1;

	if (!BYTES_ARE_IN_FRAME(offset, hlen)) {
		isis_dissect_unknown(offset, hlen, tree, fd,
			"not enough capture data for header (%d vs %d)",
			 hlen, END_OF_FRAME);
		return;
	}
	
	if (tree) {
		ti = proto_tree_add_item(tree, proto_isis_psnp, NullTVB,
			offset, END_OF_FRAME, FALSE);
		psnp_tree = proto_item_add_subtree(ti, ett_isis_psnp);
	}

	pdu_length = pntohs(&pd[offset]);
	if (tree) {
		proto_tree_add_uint(psnp_tree, hf_isis_psnp_pdu_length, NullTVB,
			offset, 2, pdu_length);
	}
	offset += 2;

	if (tree) {
		proto_tree_add_text(psnp_tree, NullTVB, offset, id_length + 1,
			"Source id: %s",
			print_system_id( pd + offset, id_length + 1 ) );
	}
	offset += id_length + 1;

	len = pdu_length - header_length;
	if (len < 0) {
		isis_dissect_unknown(offset, header_length, tree, fd,
			"packet header length %d went beyond packet",
			header_length );
		return;
	}
	/* Call into payload dissector */
	if (type == ISIS_TYPE_L1_CSNP ) {
		isis_dissect_clvs ( clv_l1_csnp_opts, len, id_length, pd,
			offset, fd, psnp_tree, ett_isis_psnp_clv_unknown );
	} else {
		isis_dissect_clvs ( clv_l2_csnp_opts, len, id_length, pd,
			offset, fd, psnp_tree, ett_isis_psnp_clv_unknown );
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
 *	u_char * : packet data
 *	int : current offset into packet data
 *	guint : length of this clv
 *	int : length of IDs in packet.
 *	frame_data * : frame data
 *	proto_tree * : proto tree to build on (may be null)
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void 
dissect_l1_snp_authentication_clv(const u_char *pd, int offset, 
		guint length, int id_length, frame_data *fd, proto_tree *tree) {
	isis_dissect_authentication_clv(pd, offset, length, fd, tree, 
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
 *	u_char * : packet data
 *	int : current offset into packet data
 *	guint : length of this clv
 *	int : length of IDs in packet.
 *	frame_data * : frame data
 *	proto_tree * : proto tree to build on (may be null)
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void 
dissect_l2_snp_authentication_clv(const u_char *pd, int offset, 
		guint length, int id_length, frame_data *fd, proto_tree *tree) {
	isis_dissect_authentication_clv(pd, offset, length, fd, tree, 
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
 * Input:
 *	u_char * : packet data
 *	int : offset into packet data where we are.
 *	guint : length of clv we are decoding
 *	frame_data * : frame data (complete frame)
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
void 
proto_register_isis_csnp(void) {
	static hf_register_info hf[] = {
		{ &hf_isis_csnp_pdu_length,
		{ "PDU length",		"isis_csnp.pdu_length", FT_UINT16, 
		  BASE_DEC, NULL, 0x0, "" }},
	};
	static gint *ett[] = {
		&ett_isis_csnp,
		&ett_isis_csnp_lsp_entries,
		&ett_isis_csnp_authentication,
		&ett_isis_csnp_clv_unknown,
	};

	proto_isis_csnp = proto_register_protocol(PROTO_STRING_CSNP, "isis_csnp");
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
 *
 * Input:
 *	u_char * : packet data
 *	int : offset into packet data where we are.
 *	guint : length of clv we are decoding
 *	frame_data * : frame data (complete frame)
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
void 
proto_register_isis_psnp(void) {
	static hf_register_info hf[] = {
		{ &hf_isis_psnp_pdu_length,
		{ "PDU length",		"isis_psnp.pdu_length", FT_UINT16, 
		  BASE_DEC, NULL, 0x0, "" }},
	};
	static gint *ett[] = {
		&ett_isis_psnp,
		&ett_isis_psnp_lsp_entries,
		&ett_isis_psnp_authentication,
		&ett_isis_psnp_clv_unknown,
	};

	proto_isis_psnp = proto_register_protocol(PROTO_STRING_PSNP, "isis_psnp");
	proto_register_field_array(proto_isis_psnp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}
