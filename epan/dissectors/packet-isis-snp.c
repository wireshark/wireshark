/* packet-isis-snp.c
 * Routines for decoding isis complete & partial SNP and their payload
 *
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
#include <epan/expert.h>
#include "packet-osi.h"
#include "packet-isis.h"
#include "packet-isis-clv.h"

void proto_register_isis_csnp(void);
void proto_reg_handoff_isis_csnp(void);
void proto_register_isis_psnp(void);
void proto_reg_handoff_isis_psnp(void);
void proto_register_isis_lsp(void);
void proto_reg_handoff_isis_lsp(void);
void proto_register_isis_hello(void);
void proto_reg_handoff_isis_hello(void);

static int proto_isis_csnp = -1;
static int proto_isis_psnp = -1;

/* csnp packets */
static int hf_isis_csnp_pdu_length = -1;
static int hf_isis_csnp_source_id = -1;
static int hf_isis_csnp_start_lsp_id = -1;
static int hf_isis_csnp_end_lsp_id = -1;
static int hf_isis_csnp_lsp_id = -1;
static int hf_isis_csnp_lsp_seq_num = -1;
static int hf_isis_csnp_lsp_remain_life = -1;
static int hf_isis_csnp_lsp_checksum = -1;
static int hf_isis_csnp_checksum = -1;
static gint ett_isis_csnp = -1;
static gint ett_isis_csnp_clv_lsp_entries = -1;
static gint ett_isis_csnp_lsp_entry = -1;
static gint ett_isis_csnp_clv_authentication = -1;
static gint ett_isis_csnp_clv_ip_authentication = -1;
static gint ett_isis_csnp_clv_checksum = -1;
static gint ett_isis_csnp_clv_unknown = -1;

static expert_field ei_isis_csnp_short_packet = EI_INIT;
static expert_field ei_isis_csnp_long_packet = EI_INIT;
static expert_field ei_isis_csnp_authentication = EI_INIT;

/* psnp packets */
static int hf_isis_psnp_pdu_length = -1;
static int hf_isis_psnp_source_id = -1;
static gint ett_isis_psnp = -1;
static gint ett_isis_psnp_clv_lsp_entries = -1;
static gint ett_isis_psnp_lsp_entry = -1;
static gint ett_isis_psnp_clv_authentication = -1;
static gint ett_isis_psnp_clv_ip_authentication = -1;
static gint ett_isis_psnp_clv_checksum = -1;
static gint ett_isis_psnp_clv_unknown = -1;

static expert_field ei_isis_psnp_short_packet = EI_INIT;
static expert_field ei_isis_psnp_long_packet = EI_INIT;

static void
dissect_snp_authentication_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
	int id_length _U_, int length)
{
	isis_dissect_authentication_clv(tree, pinfo, tvb, &ei_isis_csnp_authentication, offset, length);
}

static void
dissect_snp_ip_authentication_clv(tvbuff_t *tvb, packet_info* pinfo _U_, proto_tree *tree, int offset,
	int id_length _U_, int length)
{
	isis_dissect_ip_authentication_clv(tvb, tree, offset, length);
}

/*
 * Name: dissect_snp_checksum_clv()
 *
 * Description:
 *      dump and verify the optional checksum in TLV 12
 */
static void
dissect_snp_checksum_clv(tvbuff_t *tvb, packet_info* pinfo,
        proto_tree *tree, int offset, int id_length _U_, int length) {

    guint16 pdu_length,checksum, cacl_checksum=0;
    proto_item* ti;

    if ( length != 2 ) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_csnp_short_packet, tvb, offset, -1,
            "incorrect checksum length (%u), should be (2)", length );
            return;
    }

    ti = proto_tree_add_item( tree, hf_isis_csnp_checksum, tvb, offset, length, ENC_BIG_ENDIAN);

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
             proto_item_append_text(ti, " [unused]");
       	break;
        case DATA_MISSING :
             expert_add_info_format(pinfo, ti, &ei_isis_csnp_long_packet,
                                        "Packet length %d went beyond packet", tvb_length(tvb));
        break;
        case CKSUM_NOT_OK :
             proto_item_append_text(ti, " [incorrect, should be 0x%04x]", cacl_checksum);
        break;
        case CKSUM_OK :
             proto_item_append_text(ti, " [correct]");
        break;
    }
}

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
 */
static void
dissect_snp_lsp_entries_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
	int id_length, int length)
{
	proto_item *ti;
	proto_tree *subtree;

	while ( length > 0 ) {
		if ( length < 2+id_length+2+4+2 ) {
			proto_tree_add_expert_format(tree, pinfo, &ei_isis_csnp_short_packet, tvb, offset, -1,
				"Short SNP header entry (%d vs %d)", length, 2+id_length+2+4+2 );
			return;
		}

		ti = proto_tree_add_text(tree, tvb, offset, 2+id_length+2+4+2, "LSP Entry");
		subtree = proto_item_add_subtree(ti,ett_isis_csnp_lsp_entry);

		proto_tree_add_item(tree, hf_isis_csnp_lsp_id, tvb, offset+2, id_length+2, ENC_NA);

		proto_tree_add_item(subtree, hf_isis_csnp_lsp_seq_num, tvb, offset+2+id_length+2, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(subtree, hf_isis_csnp_lsp_remain_life, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(subtree, hf_isis_csnp_lsp_checksum, tvb, offset+2+id_length+2+4, 2, ENC_BIG_ENDIAN);

		length -= 2+id_length+2+4+2;
		offset += 2+id_length+2+4+2;
	}

}

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

static void
dissect_isis_csnp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
	const isis_clv_handle_t *opts, int header_length, int id_length)
{
	proto_item	*ti;
	proto_tree	*csnp_tree = NULL;
	guint16		pdu_length;
	int 		len;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISIS CSNP");

	ti = proto_tree_add_item(tree, proto_isis_csnp, tvb, offset, -1, ENC_NA);
	csnp_tree = proto_item_add_subtree(ti, ett_isis_csnp);

	pdu_length = tvb_get_ntohs(tvb, offset);
	proto_tree_add_uint(csnp_tree, hf_isis_csnp_pdu_length, tvb,
			offset, 2, pdu_length);
	offset += 2;

	proto_tree_add_item(csnp_tree, hf_isis_csnp_source_id, tvb, offset, id_length, ENC_NA);
	col_append_fstr(pinfo->cinfo, COL_INFO, ", Source-ID: %s", tvb_print_system_id( tvb, offset, id_length ));
	offset += id_length + 1;

	proto_tree_add_item(csnp_tree, hf_isis_csnp_start_lsp_id, tvb, offset, id_length + 2, ENC_NA);
	col_append_fstr(pinfo->cinfo, COL_INFO, ", Start LSP-ID: %s",
					tvb_print_system_id( tvb, offset, id_length+2 ));
	offset += id_length + 2;

	proto_tree_add_item(csnp_tree, hf_isis_csnp_end_lsp_id, tvb, offset, id_length + 2, ENC_NA);
	col_append_fstr(pinfo->cinfo, COL_INFO, ", End LSP-ID: %s",
					tvb_print_system_id( tvb, offset, id_length+2 ));
	offset += id_length + 2;

	len = pdu_length - header_length;
	if (len < 0) {
		proto_tree_add_expert_format(tree, pinfo, &ei_isis_csnp_short_packet, tvb, offset, -1,
			"packet header length %d went beyond packet", header_length );
		return;
	}

	isis_dissect_clvs(tvb, pinfo, csnp_tree, offset,
			opts, &ei_isis_csnp_short_packet, len, id_length, ett_isis_csnp_clv_unknown );
}


static int
dissect_isis_l1_csnp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	isis_data_t* isis = (isis_data_t*)data;
	dissect_isis_csnp(tvb, pinfo, tree, 0,
		clv_l1_csnp_opts, isis->header_length, isis->system_id_len);
	return tvb_length(tvb);
}

static int
dissect_isis_l2_csnp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	isis_data_t* isis = (isis_data_t*)data;
	dissect_isis_csnp(tvb, pinfo, tree, 0,
		clv_l2_csnp_opts, isis->header_length, isis->system_id_len);
	return tvb_length(tvb);
}

static void
dissect_isis_psnp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
	const isis_clv_handle_t *opts, int header_length, int id_length)
{
	proto_item	*ti;
	proto_tree	*psnp_tree;
	guint16		pdu_length;
	int 		len;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISIS PSNP");

	ti = proto_tree_add_item(tree, proto_isis_psnp, tvb, offset, -1, ENC_NA);
	psnp_tree = proto_item_add_subtree(ti, ett_isis_psnp);

	pdu_length = tvb_get_ntohs(tvb, offset);
	proto_tree_add_uint(psnp_tree, hf_isis_psnp_pdu_length, tvb,
			offset, 2, pdu_length);
	offset += 2;

	proto_tree_add_item(psnp_tree, hf_isis_psnp_source_id, tvb, offset, id_length, ENC_NA);
	col_append_fstr(pinfo->cinfo, COL_INFO, ", Source-ID: %s", tvb_print_system_id( tvb, offset, id_length ));

	offset += id_length + 1;

	len = pdu_length - header_length;
	if (len < 0) {
		proto_tree_add_expert_format(tree, pinfo, &ei_isis_psnp_long_packet, tvb, offset, -1,
			"packet header length %d went beyond packet", header_length );
		return;
	}
	/* Call into payload dissector */
	isis_dissect_clvs(tvb, pinfo, psnp_tree, offset,
			opts, &ei_isis_psnp_short_packet, len, id_length, ett_isis_psnp_clv_unknown );
}

static int
dissect_isis_l1_psnp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	isis_data_t* isis = (isis_data_t*)data;
	dissect_isis_psnp(tvb, pinfo, tree, 0,
		clv_l1_psnp_opts, isis->header_length, isis->system_id_len);
	return tvb_length(tvb);
}

static int
dissect_isis_l2_psnp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	isis_data_t* isis = (isis_data_t*)data;
	dissect_isis_psnp(tvb, pinfo, tree, 0,
		clv_l2_psnp_opts, isis->header_length, isis->system_id_len);
	return tvb_length(tvb);
}

void
proto_register_isis_csnp(void)
{
	static hf_register_info hf[] = {
		{ &hf_isis_csnp_pdu_length,
		{ "PDU length",		"isis.csnp.pdu_length", FT_UINT16,
		  BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_isis_csnp_source_id,
		{ "Source-ID", "isis.csnp.source_id",
			FT_SYSTEM_ID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_isis_csnp_start_lsp_id,
		{ "Start LSP-ID", "isis.csnp.start_lsp_id",
			FT_SYSTEM_ID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_isis_csnp_end_lsp_id,
		{ "End LSP-ID", "isis.csnp.end_lsp_id",
			FT_SYSTEM_ID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_isis_csnp_lsp_id,
		{ "LSP-ID", "isis.csnp.lsp_id",
			FT_SYSTEM_ID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_isis_csnp_lsp_seq_num,
		{ "LSP Sequence Number",		"isis.csnp.lsp_seq_num", FT_UINT32,
		  BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_isis_csnp_lsp_remain_life,
		{ "Remaining Lifetime",		"isis.csnp.lsp_remain_life", FT_UINT16,
		  BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_isis_csnp_lsp_checksum,
		{ "LSP checksum",		"isis.csnp.lsp_checksum", FT_UINT16,
		  BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_isis_csnp_checksum,
		{ "Checksum",		"isis.csnp.checksum", FT_UINT16,
		  BASE_HEX, NULL, 0x0, NULL, HFILL }},
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

	static ei_register_info ei[] = {
		{ &ei_isis_csnp_short_packet, { "isis.csnp.short_packet", PI_MALFORMED, PI_ERROR, "Short packet", EXPFILL }},
		{ &ei_isis_csnp_long_packet, { "isis.csnp.long_packet", PI_MALFORMED, PI_ERROR, "Long packet", EXPFILL }},
		{ &ei_isis_csnp_authentication, { "isis.csnp.authentication.unknown", PI_PROTOCOL, PI_WARN, "Unknown authentication type", EXPFILL }},
	};
	expert_module_t* expert_isis_csnp;

	/* Register the protocol name and description */
	proto_isis_csnp = proto_register_protocol(PROTO_STRING_CSNP, "ISIS CSNP", "isis.csnp");

	proto_register_field_array(proto_isis_csnp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_isis_csnp = expert_register_protocol(proto_isis_csnp);
	expert_register_field_array(expert_isis_csnp, ei, array_length(ei));
}

void
proto_reg_handoff_isis_csnp(void)
{
	dissector_add_uint("isis.type", ISIS_TYPE_L1_CSNP, new_create_dissector_handle(dissect_isis_l1_csnp, proto_isis_csnp));
	dissector_add_uint("isis.type", ISIS_TYPE_L2_CSNP, new_create_dissector_handle(dissect_isis_l2_csnp, proto_isis_csnp));
}

void
proto_register_isis_psnp(void)
{
	static hf_register_info hf[] = {
		{ &hf_isis_psnp_pdu_length,
		{ "PDU length",		"isis.psnp.pdu_length", FT_UINT16,
		  BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_isis_psnp_source_id,
		{ "Source-ID", "isis.psnp.source_id",
			FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
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
	static ei_register_info ei[] = {
		{ &ei_isis_psnp_long_packet, { "isis.psnp.long_packet", PI_MALFORMED, PI_ERROR, "Long packet", EXPFILL }},
		{ &ei_isis_psnp_short_packet, { "isis.psnp.short_packet", PI_MALFORMED, PI_ERROR, "Short packet", EXPFILL }},
	};
	expert_module_t* expert_isis_psnp;

	/* Register the protocol name and description */
	proto_isis_psnp = proto_register_protocol(PROTO_STRING_PSNP, "ISIS PSNP", "isis.psnp");

	proto_register_field_array(proto_isis_psnp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_isis_psnp = expert_register_protocol(proto_isis_psnp);
	expert_register_field_array(expert_isis_psnp, ei, array_length(ei));
}

void
proto_reg_handoff_isis_psnp(void)
{
	dissector_add_uint("isis.type", ISIS_TYPE_L1_PSNP, new_create_dissector_handle(dissect_isis_l1_psnp, proto_isis_psnp));
	dissector_add_uint("isis.type", ISIS_TYPE_L2_PSNP, new_create_dissector_handle(dissect_isis_l2_psnp, proto_isis_psnp));
}
