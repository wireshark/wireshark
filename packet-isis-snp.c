/* packet-isis-snp.c
 * Routines for decoding isis complete & partial SNP and their payload
 *
 * $Id: packet-isis-snp.c,v 1.1 1999/12/15 04:34:19 guy Exp $
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
		guint length, frame_data *fd, proto_tree *tree );
static void dissect_l1_snp_authentication_clv(const u_char *pd, int offset,
		guint length, frame_data *fd, proto_tree *tree );
static void dissect_l2_snp_authentication_clv(const u_char *pd, int offset,
		guint length, frame_data *fd, proto_tree *tree );

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
 * Name: dissect_snp_payload()
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
 *	int : length of payload to decode.
 *	frame_data * : frame data (complete frame)
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void 
dissect_snp_lsp_entries(const u_char *pd, int offset, guint length, 
		frame_data *fd, proto_tree *tree ) {
	isis_snp_t *ps;

	ps = (isis_snp_t *) &pd[offset];
	while ( length > 0 ) {
		if ( length < sizeof(isis_psnp_t) ) {
			isis_dissect_unknown(offset, length, tree, fd,
				"Short SNP header entry (%d vs %d)", length,
				sizeof(isis_psnp_t) );
			return;
		}
		
		proto_tree_add_text(tree, offset, 2, "Remaining life: %d",
			pntohs(&ps->isis_snp_remaining_lifetime));
		isis_lsp_decode_lsp_id( "LSP ID", tree, offset + 2,
			&ps->isis_snp_lsp_id );
		proto_tree_add_text(tree, offset+10, 4, 
			"LSP Sequence Number: 0x%04x",
			pntohl(&ps->isis_snp_sequence_number));
		proto_tree_add_text(tree, offset+14, 2, 
			"LSP checksum: 0x%02x",
			pntohl(&ps->isis_snp_checksum));
		length -= sizeof ( isis_snp_t );
		offset += sizeof ( isis_snp_t );
		ps++;
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
isis_dissect_isis_csnp(int type, int header_length, const u_char *pd, 
		int offset, frame_data *fd, proto_tree *tree){
	isis_csnp_t	*ilp;
	proto_item	*ti;
	proto_tree	*csnp_tree = NULL;
	int		hlen;
	int 		len;

	hlen = sizeof(*ilp);

	if (fd->cap_len < (offset + hlen)) {
		isis_dissect_unknown(offset, hlen, tree, fd,
			"not enough capture data for header (%d vs %d)",
			 hlen, offset - fd->cap_len);
		return;
	}
	
	ilp = (isis_csnp_t *) &pd[offset];

	if (tree) {
		ti = proto_tree_add_item(tree, proto_isis_csnp,
			offset, fd->cap_len - offset, NULL);
		csnp_tree = proto_item_add_subtree(ti, ett_isis_csnp);
		proto_tree_add_item(csnp_tree, hf_isis_csnp_pdu_length,
			offset, 2, pntohs(&ilp->isis_csnp_pdu_length));
		proto_tree_add_text(csnp_tree, offset + 2, 7, 
			"Source id: %02x%02x.%02x%02x.%02x%02x.%02x",
				ilp->isis_csnp_source_id[0],
				ilp->isis_csnp_source_id[1],
				ilp->isis_csnp_source_id[2],
				ilp->isis_csnp_source_id[3],
				ilp->isis_csnp_source_id[4],
				ilp->isis_csnp_source_id[5],
				ilp->isis_csnp_source_id[6] );
		isis_lsp_decode_lsp_id( "Start LSP id", csnp_tree, offset + 9,
			&ilp->isis_csnp_start_lsp_id );
		isis_lsp_decode_lsp_id( "End LSP id", csnp_tree, offset + 17,
			&ilp->isis_csnp_start_lsp_id );
	}

	offset += hlen;
	len = pntohs(&ilp->isis_csnp_pdu_length);
	len -= header_length;
	if (len < 0) {
		return;
	}
	/* Call into payload dissector */
	if (type == ISIS_TYPE_L1_CSNP ) {
		isis_dissect_clvs ( clv_l1_csnp_opts, len, pd, offset, fd,
			csnp_tree, ett_isis_csnp_clv_unknown );
	} else {
		isis_dissect_clvs ( clv_l2_csnp_opts, len, pd, offset, fd,
			csnp_tree, ett_isis_csnp_clv_unknown );
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
isis_dissect_isis_psnp(int type, int header_length, const u_char *pd, 
		int offset, frame_data *fd, proto_tree *tree){
	isis_psnp_t	*ilp;
	proto_item	*ti;
	proto_tree	*psnp_tree = NULL;
	int		hlen;
	int 		len;

	hlen = sizeof(*ilp);

	if (fd->cap_len < (offset + hlen)) {
		isis_dissect_unknown(offset, hlen, tree, fd,
			"not enough capture data for header (%d vs %d)",
			 hlen, offset - fd->cap_len);
		return;
	}
	
	ilp = (isis_psnp_t *) &pd[offset];

	if (tree) {
		ti = proto_tree_add_item(tree, proto_isis_psnp,
			offset, fd->cap_len - offset, NULL);
		psnp_tree = proto_item_add_subtree(ti, ett_isis_psnp);
		proto_tree_add_item(psnp_tree, hf_isis_psnp_pdu_length,
			offset, 2, pntohs(&ilp->isis_psnp_pdu_length));
		proto_tree_add_text(psnp_tree, offset + 2, 7, 
			"Source id: %02x%02x.%02x%02x.%02x%02x.%02x",
				ilp->isis_psnp_source_id[0],
				ilp->isis_psnp_source_id[1],
				ilp->isis_psnp_source_id[2],
				ilp->isis_psnp_source_id[3],
				ilp->isis_psnp_source_id[4],
				ilp->isis_psnp_source_id[5],
				ilp->isis_psnp_source_id[6] );
	}

	offset += hlen;
	len = pntohs(&ilp->isis_psnp_pdu_length);
	len -= header_length;
	if (len < 0) {
		isis_dissect_unknown(offset, header_length, tree, fd,
			"packet header length %d went beyond packet",
			header_length );
		return;
	}
	/* Call into payload dissector */
	if (type == ISIS_TYPE_L1_CSNP ) {
		isis_dissect_clvs ( clv_l1_csnp_opts, len, pd, offset, fd,
			psnp_tree, ett_isis_psnp_clv_unknown );
	} else {
		isis_dissect_clvs ( clv_l2_csnp_opts, len, pd, offset, fd,
			psnp_tree, ett_isis_psnp_clv_unknown );
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
 *	frame_data * : frame data
 *	proto_tree * : proto tree to build on (may be null)
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void 
dissect_l1_snp_authentication_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree) {
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
 *	frame_data * : frame data
 *	proto_tree * : proto tree to build on (may be null)
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void 
dissect_l2_snp_authentication_clv(const u_char *pd, int offset, 
		guint length, frame_data *fd, proto_tree *tree) {
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

	proto_isis_csnp = proto_register_protocol("ISIS csnp", "ISIS-csnp");
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

	proto_isis_psnp = proto_register_protocol("ISIS psnp", "ISIS-psnp");
	proto_register_field_array(proto_isis_psnp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

