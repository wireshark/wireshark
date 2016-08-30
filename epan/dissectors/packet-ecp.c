/* packet-ecp.c
 * Routines for Solaris ECP/VDP dissection based on IEEE 802.1Qbg Draft 2.1
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

#include <stdio.h>
#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/to_str.h>
#include <epan/expert.h>
#include <epan/oui.h>

void proto_register_ecp(void);
void proto_register_vdp(void);
void proto_reg_handoff_ecp_21(void);
void proto_reg_handoff_vdp(void);

static int proto_ecp = -1;
static int hf_ecp_version = -1;
static int hf_ecp_op = -1;
static int hf_ecp_subtype = -1;
static int hf_ecp_seqno = -1;

static int proto_vdp = -1;
static int hf_vdp_tlv_type = -1;
static int hf_vdp_tlv_len = -1;
static int hf_vdp_tlv_assoc_reason = -1;
static int hf_vdp_vidstr_ps = -1;
static int hf_vdp_vidstr_pcp = -1;
static int hf_vdp_vidstr_vid = -1;
static int hf_vdp_vsitypeid = -1;
static int hf_vdp_vsiversion = -1;
static int hf_vdp_vsiid_format = -1;
static int hf_vdp_vsiid = -1;
static int hf_vdp_filter_format = -1;
static int hf_vdp_assoc_mac_id = -1;
static int hf_vdp_manager_id = -1;
static int hf_vdp_data = -1;
static int hf_vdp_tlv_org_oui = -1;
static int hf_vdp_tlv_oracle_subtype = -1;
static int hf_vdp_tlv_assoc_flag_mbit = -1;
static int hf_vdp_tlv_assoc_flag_sbit = -1;
static int hf_vdp_tlv_assoc_flag_req_rsp = -1;
static int hf_vdp_tlv_assoc_request_flags = -1;
static int hf_vdp_tlv_assoc_flag_hard_error = -1;
static int hf_vdp_tlv_assoc_flag_keep = -1;
static int hf_vdp_tlv_assoc_error = -1;
static int hf_vdp_tlv_assoc_response_flags = -1;

static int hf_oui_oracle_encoding = -1;

static gint ett_ecp = -1;
static gint ett_vdp_tlv = -1;
static gint ett_vdp_tlv_assoc = -1;
static gint ett_vdp_tlv_org = -1;
static gint ett_vdp_assoc_flags = -1;

static expert_field ei_vdp_tlvlen_bad = EI_INIT;

static dissector_table_t   ecp_subdissector_table;

#define	ECP_OP_REQ		0x0
#define	ECP_OP_ACK		0x1

#define	ECP_SUBTYPE_VDP		0x0001
#define	ECP_SUBTYPE_PECSP	0x0002

#define VDP_TLV_PREASSOC	0x01
#define VDP_TLV_PREASSOCRR	0x02
#define VDP_TLV_ASSOC		0x03
#define VDP_TLV_DEASSOC		0x04
#define VDP_TLV_MGRID		0x05
#define	VDP_TLV_ORG		0x7F

#define	VSI_FMT_IPv4		0x01
#define	VSI_FMT_IPv6		0x02
#define	VSI_FMT_MAC		0x03
#define	VSI_FMT_LOCAL		0x04
#define	VSI_FMT_UUID		0x05

#define	VDP_FILTER_VID		0x01
#define	VDP_FILTER_MACVID	0x02
#define	VDP_FILTER_GRPVID	0x03
#define	VDP_FILTER_GRPMACVID	0x04

/* Masks - from packet-lldp.c */
#define TLV_TYPE_MASK		0xFE00
#define TLV_TYPE(value)		(((value) & TLV_TYPE_MASK) >> 9)
#define TLV_INFO_LEN_MASK	0x01FF
#define TLV_INFO_LEN(value)	((value) & TLV_INFO_LEN_MASK)

#define	ECP_VERSION_MASK	0xF000
#define	ECP_OP_MASK		0x0C00
#define	ECP_SUBTYPE_MASK	0x03FF

#define	ECP_VERSION(value)	(((value) & ECP_VERSION_MASK) >> 12)
#define	ECP_OP(value)		(((value) & ECP_OP_MASK) >> 10)
#define	ECP_SUBTYPE(value)	(((value) & ECP_SUBTYPE_MASK))

#define	OUI_ORACLE_VSIMGR_SUBTYPE	0x01

static const value_string ecp_op_vals[] = {
	{ ECP_OP_REQ,	"ECP request" },
	{ ECP_OP_ACK,	"ECP acknowledgement" },
	{ 0,	NULL }
};

static const value_string ecp_subtype_vals[] = {
	{ ECP_SUBTYPE_VDP,	"VDP" },
	{ 0,			NULL }
};

static const value_string vdp_tlv_type_vals[] = {
	{ VDP_TLV_PREASSOC,		"PreAssociate" },
	{ VDP_TLV_PREASSOCRR,		"PreAssociate with RR" },
	{ VDP_TLV_ASSOC,		"Associate" },
	{ VDP_TLV_DEASSOC,		"DeAssociate" },
	{ VDP_TLV_MGRID,		"VSI Manager ID" },
	{ VDP_TLV_ORG,			"Orgnaizationally defined TLV" },
	{ 0x0,				NULL }
};

static const value_string oui_oracle_subtype_vals[] = {
	{ OUI_ORACLE_VSIMGR_SUBTYPE,		"VSI Manager Subtype" },
	{ 0x0,					NULL }
};

static const value_string oui_oracle_encoding_vals[] = {
	{ 0x1,		"oracle_vsi_v1" },
	{ 0x0,		NULL }
};

static const value_string vdp_response_error_type_vals[] = {
	{ 0x0,	"Success" },
	{ 0x1,	"Invalid Format" },
	{ 0x2,	"Insufficient Resource" },
	{ 0x3,	"Unable to Contact VSI Manager" },
	{ 0x4,	"Other Failure" },
	{ 0x5,	"Invalid VID, GroupID, or Mac address" },
	{ 0x0,	NULL }
};

static const value_string vdp_vsiid_format_vals[] = {
	{ VSI_FMT_IPv4,		"IPv4" },
	{ VSI_FMT_IPv6,		"IPv6" },
	{ VSI_FMT_MAC,		"MAC" },
	{ VSI_FMT_LOCAL,	"Local" },
	{ VSI_FMT_UUID,		"UUID" },
	{ 0x0,	NULL }
};

static const value_string vdp_filter_format_vals[] = {
	{ VDP_FILTER_VID,		"VID" },
	{ VDP_FILTER_MACVID,		"MAC/VID" },
	{ VDP_FILTER_GRPVID,		"GroupID/VID" },
	{ VDP_FILTER_GRPMACVID,		"GroupID/MAC/VID" },
	{ 0x0,				NULL }
};

static void
vdp_add_vidstr(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
	if (tree) {
		proto_tree_add_item(tree, hf_vdp_vidstr_ps, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_vdp_vidstr_pcp, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_vdp_vidstr_vid, tvb, offset, 2, ENC_BIG_ENDIAN);
	}
}

static void
dissect_vdp_tlv_assoc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item* length_item _U_, int offset, guint8 tlvtype, int tlvlen _U_)
{
	proto_tree *vdp_tlv_assoc_tree;
	proto_item *associate_item;
	guint8 reason, filter_format;
	int start_offset = offset;

	if (tlvtype == VDP_TLV_ASSOC)
		vdp_tlv_assoc_tree = proto_tree_add_subtree(tree, tvb, offset, 0,
			ett_vdp_tlv_assoc, &associate_item, "VDP Associate");
	else
		vdp_tlv_assoc_tree = proto_tree_add_subtree(tree, tvb, offset, 0,
			ett_vdp_tlv_assoc, &associate_item, "VDP DeAssociate");

	/* Reason */
	reason = tvb_get_guint8(tvb, offset);
	if (reason & 0x40) {
		static const int * response_flags[] = {
			&hf_vdp_tlv_assoc_flag_hard_error,
			&hf_vdp_tlv_assoc_flag_keep,
			&hf_vdp_tlv_assoc_flag_req_rsp,
			NULL
		};

		proto_tree_add_item(vdp_tlv_assoc_tree, hf_vdp_tlv_assoc_error, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_bitmask(vdp_tlv_assoc_tree, tvb, offset, hf_vdp_tlv_assoc_response_flags, ett_vdp_assoc_flags, response_flags, ENC_BIG_ENDIAN);
	} else {
		static const int * request_flags[] = {
			&hf_vdp_tlv_assoc_flag_mbit,
			&hf_vdp_tlv_assoc_flag_sbit,
			&hf_vdp_tlv_assoc_flag_req_rsp,
			NULL
		};

		proto_tree_add_item(vdp_tlv_assoc_tree, hf_vdp_tlv_assoc_reason, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_bitmask(vdp_tlv_assoc_tree, tvb, offset, hf_vdp_tlv_assoc_request_flags, ett_vdp_assoc_flags, request_flags, ENC_BIG_ENDIAN);
	}
	offset++;

	/* VSITYPEID/VERSION */
	proto_tree_add_item(vdp_tlv_assoc_tree, hf_vdp_vsitypeid, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset += 3;
	proto_tree_add_item(vdp_tlv_assoc_tree, hf_vdp_vsiversion, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	/* VSIID Format */
	proto_tree_add_item(vdp_tlv_assoc_tree, hf_vdp_vsiid_format, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	/* VSIID */
	proto_tree_add_item(vdp_tlv_assoc_tree, hf_vdp_vsiid, tvb, offset, 16, ENC_NA);
	offset += 16;

	/* Filter Format */
	proto_tree_add_item(vdp_tlv_assoc_tree, hf_vdp_filter_format, tvb, offset, 1, ENC_BIG_ENDIAN);
	filter_format = tvb_get_guint8(tvb, offset);
	offset++;

	switch (filter_format) {
	case VDP_FILTER_VID:
		vdp_add_vidstr(tvb, vdp_tlv_assoc_tree, offset);
		offset += 2;
		break;
	case VDP_FILTER_MACVID:
		proto_tree_add_item(vdp_tlv_assoc_tree, hf_vdp_assoc_mac_id, tvb, offset, 6, ENC_NA);
		offset += 6;
		vdp_add_vidstr(tvb, vdp_tlv_assoc_tree, offset);
		offset += 2;
		break;
	}

	proto_item_set_len(associate_item, offset-start_offset);
}

static void
dissect_vdp_tlv_mgrid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item* length_item, int offset, int tlvlen)
{
	if (tlvlen != 16) {
		expert_add_info(pinfo, length_item, &ei_vdp_tlvlen_bad);
	} else {
		proto_tree_add_item(tree, hf_vdp_manager_id, tvb, offset, 16, ENC_NA);
	}
}

static void
dissect_oracle_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset)
{
	proto_tree_add_item(tree, hf_oui_oracle_encoding, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_vdp_tlv_org(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item* length_item, int offset, int tlvlen)
{
	guint32 oui;
	guint8 subtype;

	if (tlvlen < 3) {
		expert_add_info(pinfo, length_item, &ei_vdp_tlvlen_bad);
        return;
	}

	proto_tree_add_item_ret_uint(tree, hf_vdp_tlv_org_oui, tvb, offset, 3, ENC_BIG_ENDIAN, &oui);
	offset += 3;

	/* XXX only support Oracle OUI for now */
	if (oui != OUI_ORACLE)
		return;

	proto_tree_add_item(tree, hf_vdp_tlv_oracle_subtype, tvb, offset, 1, ENC_NA);
	subtype = tvb_get_guint8(tvb, offset);
	offset++;

	switch (subtype) {
	case OUI_ORACLE_VSIMGR_SUBTYPE:
		dissect_oracle_tlv(tvb, pinfo, tree, offset);
		break;
	}
}

static int
dissect_vdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_tree *vdp_tlv_tree;
	proto_item *ti, *length_item;
	int offset = 0;
	guint8	tlvtype;
	guint16 tlvhdr;
	int tlvlen = 0;

	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		tlvhdr = tvb_get_ntohs(tvb, offset);
		tlvtype = TLV_TYPE(tlvhdr);
		tlvlen = TLV_INFO_LEN(tlvhdr);

		if (tlvtype == 0) /* XXX most likely it's padding */
			break;

		vdp_tlv_tree = proto_tree_add_subtree(tree, tvb, offset,
			tlvlen + 2, ett_vdp_tlv, &ti, "VDP TLV");
		proto_tree_add_item(vdp_tlv_tree, hf_vdp_tlv_type, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		length_item = proto_tree_add_item(vdp_tlv_tree, hf_vdp_tlv_len, tvb,
			offset, 2, ENC_BIG_ENDIAN);

		offset += 2;
		switch (tlvtype) {
		case VDP_TLV_PREASSOC:
			break;
		case VDP_TLV_PREASSOCRR:
			break;
		case VDP_TLV_ASSOC:
		case VDP_TLV_DEASSOC:
			dissect_vdp_tlv_assoc(tvb, pinfo, vdp_tlv_tree, length_item, offset, tlvtype, tlvlen);
			break;
		case VDP_TLV_MGRID:
			dissect_vdp_tlv_mgrid(tvb, pinfo, vdp_tlv_tree, length_item, offset, tlvlen);
			break;
		case VDP_TLV_ORG:
			dissect_vdp_tlv_org(tvb, pinfo, vdp_tlv_tree, length_item, offset, tlvlen);
			break;
		default:
			proto_tree_add_item(vdp_tlv_tree, hf_vdp_data, tvb, offset, tlvlen, ENC_NA);
			break;
		}

		offset += tlvlen;
	}

	return offset;
}

static int
dissect_ecp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *ti;
	proto_tree *ecp_tree = NULL;
	int offset = 0;
	tvbuff_t *next_tvb;
	guint16 hdr, ver, op, subtype, seqno;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ECP");
	col_clear(pinfo->cinfo, COL_INFO);

	/* details */
	ti = proto_tree_add_item(tree, proto_ecp, tvb, 0, -1, ENC_NA);
	ecp_tree = proto_item_add_subtree(ti, ett_ecp);

	proto_tree_add_item(ecp_tree, hf_ecp_version, tvb, offset, 2,
		ENC_BIG_ENDIAN);
	proto_tree_add_item(ecp_tree, hf_ecp_op, tvb, offset, 2,
		ENC_BIG_ENDIAN);
	proto_tree_add_item(ecp_tree, hf_ecp_subtype, tvb, offset, 2,
		ENC_BIG_ENDIAN);

	/* Version/OP/Subtype */
	hdr = tvb_get_ntohs(tvb, offset);
	ver = ECP_VERSION(hdr);
	op = ECP_OP(hdr);
	subtype = ECP_SUBTYPE(hdr);
	col_add_fstr(pinfo->cinfo, COL_INFO,
	    "PDU Version = %x OP = %x Subtype = %x", ver, op, subtype);

	offset += 2;

	/* Seqno */
	if (tree) {
		proto_tree_add_item(ecp_tree, hf_ecp_seqno, tvb, offset, 2,
		    ENC_BIG_ENDIAN);
	}
	seqno = tvb_get_ntohs(tvb, offset);
	switch (op) {
	case ECP_OP_REQ:
		col_append_fstr(pinfo->cinfo, COL_INFO,
		    " SEQ = 0x%x", seqno);
		break;
	case ECP_OP_ACK:
		col_append_fstr(pinfo->cinfo, COL_INFO,
		    " ACK = 0x%x", seqno);
		break;
	}
	offset += 2;

	next_tvb = tvb_new_subset_remaining(tvb, offset);
	if (!dissector_try_uint(ecp_subdissector_table, subtype, next_tvb, pinfo, ecp_tree))
	{
		call_data_dissector(next_tvb, pinfo, tree);
	}

	return tvb_captured_length(tvb);
}

void
proto_register_ecp(void)
{
	static hf_register_info hf[] = {
		{ &hf_ecp_version,
		{ "Version",	"ecp.ver", FT_UINT16, BASE_DEC,
		    NULL, ECP_VERSION_MASK, NULL, HFILL }},
		{ &hf_ecp_op,
		{ "Operation", "ecp.op", FT_UINT16, BASE_HEX,
		    VALS(ecp_op_vals), ECP_OP_MASK, NULL, HFILL }},
		{ &hf_ecp_subtype,
		{ "Subtype", "ecp.subtype", FT_UINT16, BASE_HEX,
		    VALS(ecp_subtype_vals), ECP_SUBTYPE_MASK, NULL, HFILL }},
		{ &hf_ecp_seqno,
		{ "Sequence number", "ecp.seqno", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_ecp,
	};

	proto_ecp = proto_register_protocol("Edge Control Protocol", "ECP21", "ecp21");
	proto_register_field_array(proto_ecp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	ecp_subdissector_table = register_dissector_table("ecp.subtype", "ECP Subtypes", proto_ecp, FT_UINT32, BASE_DEC);
}

void
proto_register_vdp(void)
{
	static hf_register_info hf[] = {
		{ &hf_vdp_tlv_type,
		{ "VDP TLV Type", "vdp21.tlvtype", FT_UINT16, BASE_DEC,
			VALS(vdp_tlv_type_vals), TLV_TYPE_MASK, NULL, HFILL }},
		{ &hf_vdp_tlv_len,
		{ "VDP TLV Length", "vdp21.tlvlen", FT_UINT16, BASE_DEC,
			NULL, TLV_INFO_LEN_MASK, NULL, HFILL }},
		{ &hf_vdp_tlv_assoc_reason,
		{ "Reason", "vdp21.assoc.reason", FT_UINT8, BASE_HEX,
			NULL, 0x0F, NULL, HFILL }},
		{ &hf_vdp_tlv_assoc_error,
		{ "Error", "vdp21.assoc.error", FT_UINT8, BASE_HEX,
			VALS(vdp_response_error_type_vals), 0x0F, NULL, HFILL }},
		{ &hf_vdp_tlv_assoc_request_flags,
		{ "Flags", "vdp21.assoc.request_flags", FT_UINT8, BASE_HEX,
			NULL, 0xF0, NULL, HFILL }},
		{ &hf_vdp_tlv_assoc_response_flags,
		{ "Flags", "vdp21.assoc.response_flags", FT_UINT8, BASE_HEX,
			NULL, 0xF0, NULL, HFILL }},
		{ &hf_vdp_tlv_assoc_flag_mbit,
		{ "M-Bit", "vdp21.assoc.flags.mbit", FT_BOOLEAN, 8,
			NULL, 0x10, NULL, HFILL }},
		{ &hf_vdp_tlv_assoc_flag_sbit,
		{ "S-Bit", "vdp21.assoc.flags.sbit", FT_BOOLEAN, 8,
			NULL, 0x20, NULL, HFILL }},
		{ &hf_vdp_tlv_assoc_flag_req_rsp,
		{ "Response", "vdp21.assoc.flags.req_rsp", FT_BOOLEAN, 8,
			TFS(&tfs_true_false), 0x40, NULL, HFILL }},
		{ &hf_vdp_tlv_assoc_flag_hard_error,
		{ "Hard Error", "vdp21.assoc.flags.hard_error", FT_BOOLEAN, 8,
			NULL, 0x10, NULL, HFILL }},
		{ &hf_vdp_tlv_assoc_flag_keep,
		{ "Keep", "vdp21.assoc.flags.keep", FT_BOOLEAN, 8,
			NULL, 0x20, NULL, HFILL }},
		{ &hf_oui_oracle_encoding,
		{ "VSI Manager ID Encoding", "vdp21.oracle.encoding", FT_UINT8,
			BASE_HEX, VALS(oui_oracle_encoding_vals),
			0x0, NULL, HFILL}},
		{ &hf_vdp_vsitypeid,
		{ "VSI Type ID", "vdp21.vsitypeid", FT_UINT24,
			BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{ &hf_vdp_vsiversion,
		{ "VSI Version", "vdp21.vsiversion", FT_UINT8,
			BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{ &hf_vdp_vsiid_format,
		{ "VSIID Format", "vdp21.vsiidformat", FT_UINT8,
			BASE_HEX, VALS(vdp_vsiid_format_vals), 0x0,
			NULL, HFILL}},
		{ &hf_vdp_filter_format,
		{ "VDP Filter Format", "vdp21.filterformat", FT_UINT8,
			BASE_HEX, VALS(vdp_filter_format_vals), 0x0,
			NULL, HFILL}},
		{ &hf_vdp_assoc_mac_id,
		{ "MAC ID", "vdp21.assoc.mac_id", FT_ETHER, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_vdp_vsiid,
		{ "VSIID", "vdp21.VSIID", FT_BYTES, SEP_COLON,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_vdp_vidstr_ps,
		{ "VIDSTR PS", "vdp21.vidstr.ps", FT_UINT16, BASE_HEX,
			NULL, 0x800, NULL, HFILL }},
		{ &hf_vdp_vidstr_pcp,
		{ "VIDSTR PCP", "vdp21.vidstr.pcp", FT_UINT16, BASE_HEX,
			NULL, 0x700, NULL, HFILL }},
		{ &hf_vdp_vidstr_vid,
		{ "VIDSTR VID", "vdp21.vidstr.vid", FT_UINT16, BASE_HEX,
			NULL, 0x0FFF, NULL, HFILL }},
		{ &hf_vdp_manager_id,
		{ "VDP Manager ID", "vdp21.manager_id", FT_IPv6, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_vdp_data,
		{ "Data", "vdp21.data", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_vdp_tlv_org_oui,
		{ "VIDSTR VID", "vdp21.org_oui", FT_UINT24, BASE_HEX,
			VALS(oui_vals), 0x0, NULL, HFILL }},
		{ &hf_vdp_tlv_oracle_subtype,
		{ "Oracle Subtype", "vdp21.org.oracle.subtype", FT_UINT8, BASE_HEX,
			VALS(oui_oracle_subtype_vals), 0x0, NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_vdp_tlv,
		&ett_vdp_tlv_assoc,
		&ett_vdp_tlv_org,
		&ett_vdp_assoc_flags,
	};

	static ei_register_info ei[] = {
		{ &ei_vdp_tlvlen_bad, { "vdp21.tlvlen.bad", PI_MALFORMED, PI_ERROR, "VDP TLV Invalid Length", EXPFILL }},
	};

	expert_module_t* expert_vdp;

	proto_vdp = proto_register_protocol("VSI protocol", "VDP21", "vdp21");
	proto_register_field_array(proto_vdp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_vdp = expert_register_protocol(proto_vdp);
	expert_register_field_array(expert_vdp, ei, array_length(ei));

}

void
proto_reg_handoff_ecp_21(void)
{
	dissector_handle_t ecp_handle;

	ecp_handle = create_dissector_handle(dissect_ecp, proto_ecp);
	dissector_add_uint("ethertype", ETHERTYPE_ECP, ecp_handle);
}

void
proto_reg_handoff_vdp(void)
{
	dissector_handle_t vdp_handle;

	vdp_handle = create_dissector_handle(dissect_vdp, proto_vdp);
	dissector_add_uint("ecp.subtype", ECP_SUBTYPE_VDP, vdp_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=true:
 */
