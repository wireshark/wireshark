/* packet-isis-snp.c
 * Routines for decoding isis complete & partial SNP and their payload
 *
 * $Id$
 * Stuart Stanley <stuarts@mxmail.net>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include "packet-osi.h"
#include "packet-isis.h"
#include "packet-isis-clv.h"
#include "packet-isis-lsp.h"
#include "packet-isis-snp.h"

/* csnp packets */
static int hf_isis_csnp_pdu_length = -1;
static gint ett_isis_csnp = -1;
static gint ett_isis_csnp_clv_lsp_entries = -1;
static gint ett_isis_csnp_lsp_entry = -1;
static gint ett_isis_csnp_clv_authentication = -1;
static gint ett_isis_csnp_clv_ip_authentication = -1;
static gint ett_isis_csnp_clv_checksum = -1;
static gint ett_isis_csnp_clv_unknown = -1;

/* psnp packets */
static int hf_isis_psnp_pdu_length = -1;
static gint ett_isis_psnp = -1;
static gint ett_isis_psnp_clv_lsp_entries = -1;
static gint ett_isis_psnp_lsp_entry = -1;
static gint ett_isis_psnp_clv_authentication = -1;
static gint ett_isis_psnp_clv_ip_authentication = -1;
static gint ett_isis_psnp_clv_checksum = -1;
static gint ett_isis_psnp_clv_unknown = -1;

static void dissect_snp_authentication_clv(tvbuff_t *tvb,
	proto_tree *tree, int offset, int id_length, int length);
static void dissect_snp_ip_authentication_clv(tvbuff_t *tvb,
	proto_tree *tree, int offset, int id_length, int length);
static void dissect_snp_checksum_clv(tvbuff_t *tvb,
	proto_tree *tree, int offset, int id_length, int length);
static void dissect_snp_lsp_entries_clv(tvbuff_t *tvb,
	proto_tree *tree, int offset, int id_length, int length);

static const isis_clv_handle_t clv_l1_csnp_opts[] = {
	{
		ISIS_CLV_LSP_ENTRIES,
		"LSP entries",
		&ett_isis_csnp_clv_lsp_entries,
		dissect_snp_lsp_entries_clv
	},
	{
		ISIS_CLV_AUTHENTICATION,
		"Authentication",
		&ett_isis_csnp_clv_authentication,
		dissect_snp_authentication_clv
	},
	{
		ISIS_CLV_IP_AUTHENTICATION,
		"IP Authentication",
		&ett_isis_csnp_clv_ip_authentication,
		dissect_snp_ip_authentication_clv
	},
	{
		ISIS_CLV_CHECKSUM,
		"Checksum",
		&ett_isis_csnp_clv_checksum,
		dissect_snp_checksum_clv
	},
	{
		0, "", NULL, NULL
	}
};

static const isis_clv_handle_t clv_l2_csnp_opts[] = {
	{
		ISIS_CLV_LSP_ENTRIES,
		"LSP entries",
		&ett_isis_csnp_clv_lsp_entries,
		dissect_snp_lsp_entries_clv
	},
	{
		ISIS_CLV_AUTHENTICATION,
		"Authentication",
		&ett_isis_csnp_clv_authentication,
		dissect_snp_authentication_clv
	},
	{
		ISIS_CLV_IP_AUTHENTICATION,
		"IP Authentication",
		&ett_isis_csnp_clv_ip_authentication,
		dissect_snp_ip_authentication_clv
	},
	{
		ISIS_CLV_CHECKSUM,
		"Checksum",
		&ett_isis_csnp_clv_checksum,
		dissect_snp_checksum_clv
	},
	{
		0, "", NULL, NULL
	}
};

static const isis_clv_handle_t clv_l1_psnp_opts[] = {
	{
		ISIS_CLV_LSP_ENTRIES,
		"LSP entries",
		&ett_isis_psnp_clv_lsp_entries,
		dissect_snp_lsp_entries_clv
	},
	{
		ISIS_CLV_AUTHENTICATION,
		"Authentication",
		&ett_isis_psnp_clv_authentication,
		dissect_snp_authentication_clv
	},
	{
		ISIS_CLV_IP_AUTHENTICATION,
		"IP Authentication",
		&ett_isis_psnp_clv_ip_authentication,
		dissect_snp_ip_authentication_clv
	},
	{
		ISIS_CLV_CHECKSUM,
		"Checksum",
		&ett_isis_psnp_clv_checksum,
		dissect_snp_checksum_clv
	},
	{
		0, "", NULL, NULL
	}
};

static const isis_clv_handle_t clv_l2_psnp_opts[] = {
	{
		ISIS_CLV_LSP_ENTRIES,
		"LSP entries",
		&ett_isis_psnp_clv_lsp_entries,
		dissect_snp_lsp_entries_clv
	},
	{
		ISIS_CLV_AUTHENTICATION,
		"Authentication",
		&ett_isis_psnp_clv_authentication,
		dissect_snp_authentication_clv
	},
	{
		ISIS_CLV_IP_AUTHENTICATION,
		"IP Authentication",
		&ett_isis_psnp_clv_ip_authentication,
		dissect_snp_ip_authentication_clv
	},
	{
		ISIS_CLV_CHECKSUM,
		"Checksum",
		&ett_isis_psnp_clv_checksum,
		dissect_snp_checksum_clv
	},
	{
		0, "", NULL, NULL
	}
};

/*
 * Name: dissect_snp_lsp_entries_clv()
 *
 * Description:
 *	All the snp packets use a common payload format.  We have up
 *	to n entries (based on length), which are made of:
 *		2         : remaining life time
 *		id_length : lsp id
 *		4         : sequence number
 *		2         : checksum
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : offset into packet data where we are.
 *	int : length of IDs in packet.
 *	int : length of payload to decode.
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void
dissect_snp_lsp_entries_clv(tvbuff_t *tvb, proto_tree *tree, int offset,
	int id_length, int length)
{
        proto_tree *subtree,*ti;

	while ( length > 0 ) {
		if ( length < 2+id_length+2+4+2 ) {
			isis_dissect_unknown(tvb, tree, offset,
				"Short SNP header entry (%d vs %d)", length,
				2+id_length+2+4+2 );
			return;
		}

	        ti = proto_tree_add_text(tree, tvb, offset, 2+id_length+2+4+2,
                                    "LSP-ID: %s, Sequence: 0x%08x, Lifetime: %5us, Checksum: 0x%04x",
                                           print_system_id( tvb_get_ptr(tvb, offset+2, id_length+2), id_length+2 ),
                                           tvb_get_ntohl(tvb, offset+2+id_length+2),
                                           tvb_get_ntohs(tvb, offset),
                                           tvb_get_ntohs(tvb, offset+2+id_length+2+4));

                subtree = proto_item_add_subtree(ti,ett_isis_csnp_lsp_entry);

		proto_tree_add_text(subtree, tvb, offset+2, 8,
			"LSP-ID:             : %s",
			print_system_id( tvb_get_ptr(tvb, offset+2, id_length+2), id_length+2 ));

		proto_tree_add_text(subtree, tvb, offset+2+id_length+2, 4,
			"LSP Sequence Number : 0x%08x",
			tvb_get_ntohl(tvb, offset+2+id_length+2));

		proto_tree_add_text(subtree, tvb, offset, 2,
			"Remaining Lifetime  : %us",
			tvb_get_ntohs(tvb, offset));

		proto_tree_add_text(subtree, tvb, offset+2+id_length+2+4, 2,
			"LSP checksum        : 0x%04x",
			tvb_get_ntohs(tvb, offset+2+id_length+2+4));

		length -= 2+id_length+2+4+2;
		offset += 2+id_length+2+4+2;
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
isis_dissect_isis_csnp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
	int type, int header_length, int id_length)
{
	proto_item	*ti;
	proto_tree	*csnp_tree = NULL;
	guint16		pdu_length;
	int 		len;

	if (tree) {
		ti = proto_tree_add_text(tree, tvb, offset, -1,
		    PROTO_STRING_CSNP);
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
			"Source-ID:    %s",
				print_system_id( tvb_get_ptr(tvb, offset, id_length+1), id_length+1 ) );
	}
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Source-ID: %s",
			print_system_id( tvb_get_ptr(tvb, offset, id_length+1), id_length+1 ) );
	}
	offset += id_length + 1;

	if (tree) {
		proto_tree_add_text(csnp_tree, tvb, offset, id_length + 2,
			"Start LSP-ID: %s",
                                    print_system_id( tvb_get_ptr(tvb, offset, id_length+2), id_length+2 ) );                
	}
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Start LSP-ID: %s",
			print_system_id( tvb_get_ptr(tvb, offset, id_length+2), id_length+2 ) );
	}
	offset += id_length + 2;

	if (tree) {
		proto_tree_add_text(csnp_tree, tvb, offset, id_length + 2,
			"End LSP-ID: %s",
                                    print_system_id( tvb_get_ptr(tvb, offset, id_length+2), id_length+2 ) );  
	}
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ", End LSP-ID: %s",
			print_system_id( tvb_get_ptr(tvb, offset, id_length+2), id_length+2 ) );
	}
	offset += id_length + 2;

	len = pdu_length - header_length;
	if (len < 0) {
		return;
	}
	/* Call into payload dissector */
	if (type == ISIS_TYPE_L1_CSNP ) {
		isis_dissect_clvs(tvb, csnp_tree, offset,
			clv_l1_csnp_opts, len, id_length,
			ett_isis_csnp_clv_unknown );
	} else {
		isis_dissect_clvs(tvb, csnp_tree, offset,
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
isis_dissect_isis_psnp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
	int type, int header_length, int id_length)
{
	proto_item	*ti;
	proto_tree	*psnp_tree = NULL;
	guint16		pdu_length;
	int 		len;

	if (tree) {
		ti = proto_tree_add_text(tree, tvb, offset, -1,
		    PROTO_STRING_PSNP);
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
			"Source-ID: %s",
			print_system_id( tvb_get_ptr(tvb, offset, id_length+1), id_length + 1 ) );
	}
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Source-ID: %s",
			print_system_id( tvb_get_ptr(tvb, offset, id_length+1), id_length+1 ) );
	}
	offset += id_length + 1;

	len = pdu_length - header_length;
	if (len < 0) {
		isis_dissect_unknown(tvb, tree, offset,
			"packet header length %d went beyond packet",
			header_length );
		return;
	}
	/* Call into payload dissector */
	if (type == ISIS_TYPE_L1_PSNP ) {
		isis_dissect_clvs(tvb, psnp_tree, offset,
			clv_l1_psnp_opts, len, id_length,
			ett_isis_psnp_clv_unknown );
	} else {
		isis_dissect_clvs(tvb, psnp_tree, offset,
			clv_l2_psnp_opts, len, id_length,
			ett_isis_psnp_clv_unknown );
	}
}

/*
 * Name: dissect_snp_authentication_clv()
 *
 * Description:
 *	Decode for a snp packets authenticaion clv.
 *      Calls into the CLV common one.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : proto tree to build on (may be null)
 *	int : current offset into packet data
 *	int : length of IDs in packet.
 *	int : length of this clv
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void
dissect_snp_authentication_clv(tvbuff_t *tvb, proto_tree *tree, int offset,
	int id_length _U_, int length)
{
	isis_dissect_authentication_clv(tvb, tree, offset, length);
}

/*
 * Name: dissect_snp_ip_authentication_clv()
 *
 * Description:
 *	Decode for a snp packets authenticaion clv.
 *      Calls into the CLV common one.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : proto tree to build on (may be null)
 *	int : current offset into packet data
 *	int : length of IDs in packet.
 *	int : length of this clv
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void
dissect_snp_ip_authentication_clv(tvbuff_t *tvb, proto_tree *tree, int offset,
	int id_length _U_, int length)
{
	isis_dissect_ip_authentication_clv(tvb, tree, offset, length);
}

/*
 * Name: dissect_snp_checksum_clv()
 *
 * Description:
 *      dump and verify the optional checksum in TLV 12
 *
 * Input:
 *      tvbuff_t * : tvbuffer for packet data
 *      proto_tree * : protocol display tree to fill out.  May be NULL
 *      int : offset into packet data where we are.
 *      int : length of clv we are decoding
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */

static void
dissect_snp_checksum_clv(tvbuff_t *tvb,
        proto_tree *tree, int offset, int id_length _U_, int length) {

	guint16 pdu_length,checksum, cacl_checksum=0;

	if (tree) {
                if ( length != 2 ) {
                        proto_tree_add_text ( tree, tvb, offset, length,
                                              "incorrect checksum length (%u), should be (2)", length );
                        return;
                }

    		checksum = tvb_get_ntohs(tvb, offset);    		

                /* the check_and_get_checksum() function needs to know how big
                 * the packet is. we can either pass through the pdu-len through several layers
                 * of dissectors and wrappers or extract the PDU length field from the PDU specific header
                 * which is offseted 8 bytes (relative to the beginning of the IS-IS packet) in SNPs */

    		pdu_length = tvb_get_ntohs(tvb, 8);   

                /* unlike the LSP checksum verification which starts at an offset of 12 we start at offset 0*/
		switch (check_and_get_checksum(tvb, 0, pdu_length, checksum, offset, &cacl_checksum))
		{

        		case NO_CKSUM :
                                proto_tree_add_text ( tree, tvb, offset, length,
                                                      "Checksum: 0x%04x [unused]", checksum);
       	 		break;
        		case DATA_MISSING :
          			isis_dissect_unknown(tvb, tree, offset,
                                                     "[packet length %d went beyond packet]",
                                                     tvb_length(tvb));
        		break;
        		case CKSUM_NOT_OK :
                                proto_tree_add_text ( tree, tvb, offset, length,
                                                      "Checksum: 0x%04x [incorrect, should be 0x%04x]",
                                                      checksum,
                                                      cacl_checksum);
        		break;
	        	case CKSUM_OK :
                                proto_tree_add_text ( tree, tvb, offset, length,
                                                      "Checksum: 0x%04x [correct]", checksum);
        		break;
        		default :
          			g_message("'check_and_get_checksum' returned an invalid value");
    		}
	}
}

/*
 * Name: isis_register_csnp()
 *
 * Description:
 *	Register our protocol sub-sets with protocol manager.
 *
 * Input:
 *	int : protocol index for the ISIS protocol
 *
 * Output:
 *	void
 */
void
isis_register_csnp(int proto_isis) {
	static hf_register_info hf[] = {
		{ &hf_isis_csnp_pdu_length,
		{ "PDU length",		"isis.csnp.pdu_length", FT_UINT16,
		  BASE_DEC, NULL, 0x0, NULL, HFILL }},
	};
	static gint *ett[] = {
		&ett_isis_csnp,
		&ett_isis_csnp_clv_lsp_entries,
		&ett_isis_csnp_lsp_entry,
		&ett_isis_csnp_clv_authentication,
		&ett_isis_csnp_clv_ip_authentication,
		&ett_isis_csnp_clv_checksum,
		&ett_isis_csnp_clv_unknown,
	};

	proto_register_field_array(proto_isis, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}


/*
 * Name: isis_register_psnp()
 *
 * Description:
 *	Register our protocol sub-sets with protocol manager.
 *
 * Input:
 *	int : protocol index for the ISIS protocol
 *
 * Output:
 *	void
 */
void
isis_register_psnp(int proto_isis) {
	static hf_register_info hf[] = {
		{ &hf_isis_psnp_pdu_length,
		{ "PDU length",		"isis.psnp.pdu_length", FT_UINT16,
		  BASE_DEC, NULL, 0x0, NULL, HFILL }},
	};
	static gint *ett[] = {
		&ett_isis_psnp,
		&ett_isis_psnp_clv_lsp_entries,
		&ett_isis_psnp_lsp_entry,
		&ett_isis_psnp_clv_authentication,
		&ett_isis_psnp_clv_ip_authentication,
		&ett_isis_psnp_clv_checksum,
		&ett_isis_psnp_clv_unknown,
	};

	proto_register_field_array(proto_isis, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}
