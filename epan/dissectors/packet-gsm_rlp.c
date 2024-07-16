/* packet-gsm_rlp.c
 * Routines for GSM RLP (3GPP TS 24.022) frame dissection
 * (C) 2023 Harald Welte <laforge@osmocom.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <epan/conversation.h>

void proto_register_gsmrlp(void);

static int proto_gsmrlp;

static int hf_gsmrlp_cr;
static int hf_gsmrlp_pf;
static int hf_gsmrlp_n_r;
static int hf_gsmrlp_n_s;
static int hf_gsmrlp_ftype;
static int hf_gsmrlp_s_ftype;
static int hf_gsmrlp_u_ftype;
static int hf_gsmrlp_fcs;
static int hf_gsmrlp_fcs_status;

static int hf_gsmrlp_xid_p_type;
static int hf_gsmrlp_xid_p_len;
static int hf_gsmrlp_xid_p_val;

static int ett_gsmrlp;
static int ett_gsmrlp_xid;

static expert_field ei_gsmrlp_fcs_bad;

static dissector_handle_t l2rcop_handle;
static bool decode_as_l2rcop = true;

/* 3GPP TS 24.002 Section 5.2.1 */
enum rlp_ftype {
	RLP_FT_U,
	RLP_FT_S,
	RLP_FT_IS,
};

static const value_string rlp_ftype_vals[] = {
	{ RLP_FT_U,	"U" },
	{ RLP_FT_S,	"S" },
	{ RLP_FT_IS,	"IS" },
	{ 0, NULL }
};

/* 3GPP TS 24.002 Section 5.2.1 */
enum rlp_u_ftype {
	RLP_U_FT_SABM	= 0x07,
	RLP_U_FT_UA	= 0x0c,
	RLP_U_FT_DISC	= 0x08,
	RLP_U_FT_DM	= 0x03,
	RLP_U_FT_NULL	= 0x0f,
	RLP_U_FT_UI	= 0x00,
	RLP_U_FT_XID	= 0x17,
	RLP_U_FT_TEST	= 0x1c,
	RLP_U_FT_REMAP	= 0x11,
};
static const value_string rlp_ftype_u_vals[] = {
	{ RLP_U_FT_SABM,	"SABM" },
	{ RLP_U_FT_UA,		"UA" },
	{ RLP_U_FT_DISC,	"DISC" },
	{ RLP_U_FT_DM,		"DM" },
	{ RLP_U_FT_NULL,	"NULL" },
	{ RLP_U_FT_UI,		"UI" },
	{ RLP_U_FT_XID,		"XID" },
	{ RLP_U_FT_TEST,	"TEST" },
	{ RLP_U_FT_REMAP,	"REMAP" },
	{ 0, NULL }
};

/* 3GPP TS 24.002 Section 5.2.1 */
enum rlp_s_ftype {
	RLP_S_FT_RR	= 0,
	RLP_S_FT_REJ	= 2,
	RLP_S_FT_RNR	= 1,
	RLP_S_FT_SREJ	= 3,
};
static const value_string rlp_ftype_s_vals[] = {
	{ RLP_S_FT_RR,		"RR" },
	{ RLP_S_FT_REJ,		"REJ" },
	{ RLP_S_FT_RNR,		"RNR" },
	{ RLP_S_FT_SREJ,	"SREJ" },
	{ 0, NULL }
};

/* 3GPP TS 24.002 Section 5.2.2.6 */
enum rlp_xid_param_type {
	XID_P_DELIMITER			= 0,
	XID_P_RLP_VERSION		= 1,
	XID_P_IWF_TO_UE_WIN_SIZE	= 2,
	XID_P_UE_TO_IWF_WIN_SIZE	= 3,
	XID_P_ACK_TIMER_T1		= 4,
	XID_P_RETRANS_ATTEMPTS_N2	= 5,
	XID_P_REPLY_DELAY_T2		= 6,
	XID_P_COMPRESSION_PT		= 7,
	XID_P_RESEQUENCING_T4		= 8,
	XID_P_OPTIONAL_FEATURES		= 9,
};

static const value_string rlp_xid_param_vals[] = {
	{ XID_P_DELIMITER,		"Delimiter (end of parameters)" },
	{ XID_P_RLP_VERSION, 		"RLP version number" },
	{ XID_P_IWF_TO_UE_WIN_SIZE,	"IWF to UE window size" },
	{ XID_P_UE_TO_IWF_WIN_SIZE,	"UE to IWF window size" },
	{ XID_P_ACK_TIMER_T1,		"Acknowledgement Timer (T1)" },
	{ XID_P_RETRANS_ATTEMPTS_N2,	"Retransmission attempts (N2)" },
	{ XID_P_REPLY_DELAY_T2,		"Reply delay (T2)" },
	{ XID_P_COMPRESSION_PT,		"Compression PT" },
	{ XID_P_RESEQUENCING_T4,	"Re-sequencing timer (T4)" },
	{ XID_P_OPTIONAL_FEATURES,	"Optional Features" },
	{ 0, NULL }
};

static const uint32_t rlp_fcs_table[256] = {
	0x00B29D2D, 0x00643A5B, 0x0044D87A, 0x00927F0C, 0x00051C38, 0x00D3BB4E, 0x00F3596F, 0x0025FE19,
	0x008694BC, 0x005033CA, 0x0070D1EB, 0x00A6769D, 0x003115A9, 0x00E7B2DF, 0x00C750FE, 0x0011F788,
	0x00DA8E0F, 0x000C2979, 0x002CCB58, 0x00FA6C2E, 0x006D0F1A, 0x00BBA86C, 0x009B4A4D, 0x004DED3B,
	0x00EE879E, 0x003820E8, 0x0018C2C9, 0x00CE65BF, 0x0059068B, 0x008FA1FD, 0x00AF43DC, 0x0079E4AA,
	0x0062BB69, 0x00B41C1F, 0x0094FE3E, 0x00425948, 0x00D53A7C, 0x00039D0A, 0x00237F2B, 0x00F5D85D,
	0x0056B2F8, 0x0080158E, 0x00A0F7AF, 0x007650D9, 0x00E133ED, 0x0037949B, 0x001776BA, 0x00C1D1CC,
	0x000AA84B, 0x00DC0F3D, 0x00FCED1C, 0x002A4A6A, 0x00BD295E, 0x006B8E28, 0x004B6C09, 0x009DCB7F,
	0x003EA1DA, 0x00E806AC, 0x00C8E48D, 0x001E43FB, 0x008920CF, 0x005F87B9, 0x007F6598, 0x00A9C2EE,
	0x0049DA1E, 0x009F7D68, 0x00BF9F49, 0x0069383F, 0x00FE5B0B, 0x0028FC7D, 0x00081E5C, 0x00DEB92A,
	0x007DD38F, 0x00AB74F9, 0x008B96D8, 0x005D31AE, 0x00CA529A, 0x001CF5EC, 0x003C17CD, 0x00EAB0BB,
	0x0021C93C, 0x00F76E4A, 0x00D78C6B, 0x00012B1D, 0x00964829, 0x0040EF5F, 0x00600D7E, 0x00B6AA08,
	0x0015C0AD, 0x00C367DB, 0x00E385FA, 0x0035228C, 0x00A241B8, 0x0074E6CE, 0x005404EF, 0x0082A399,
	0x0099FC5A, 0x004F5B2C, 0x006FB90D, 0x00B91E7B, 0x002E7D4F, 0x00F8DA39, 0x00D83818, 0x000E9F6E,
	0x00ADF5CB, 0x007B52BD, 0x005BB09C, 0x008D17EA, 0x001A74DE, 0x00CCD3A8, 0x00EC3189, 0x003A96FF,
	0x00F1EF78, 0x0027480E, 0x0007AA2F, 0x00D10D59, 0x00466E6D, 0x0090C91B, 0x00B02B3A, 0x00668C4C,
	0x00C5E6E9, 0x0013419F, 0x0033A3BE, 0x00E504C8, 0x007267FC, 0x00A4C08A, 0x008422AB, 0x005285DD,
	0x001F18F0, 0x00C9BF86, 0x00E95DA7, 0x003FFAD1, 0x00A899E5, 0x007E3E93, 0x005EDCB2, 0x00887BC4,
	0x002B1161, 0x00FDB617, 0x00DD5436, 0x000BF340, 0x009C9074, 0x004A3702, 0x006AD523, 0x00BC7255,
	0x00770BD2, 0x00A1ACA4, 0x00814E85, 0x0057E9F3, 0x00C08AC7, 0x00162DB1, 0x0036CF90, 0x00E068E6,
	0x00430243, 0x0095A535, 0x00B54714, 0x0063E062, 0x00F48356, 0x00222420, 0x0002C601, 0x00D46177,
	0x00CF3EB4, 0x001999C2, 0x00397BE3, 0x00EFDC95, 0x0078BFA1, 0x00AE18D7, 0x008EFAF6, 0x00585D80,
	0x00FB3725, 0x002D9053, 0x000D7272, 0x00DBD504, 0x004CB630, 0x009A1146, 0x00BAF367, 0x006C5411,
	0x00A72D96, 0x00718AE0, 0x005168C1, 0x0087CFB7, 0x0010AC83, 0x00C60BF5, 0x00E6E9D4, 0x00304EA2,
	0x00932407, 0x00458371, 0x00656150, 0x00B3C626, 0x0024A512, 0x00F20264, 0x00D2E045, 0x00044733,
	0x00E45FC3, 0x0032F8B5, 0x00121A94, 0x00C4BDE2, 0x0053DED6, 0x008579A0, 0x00A59B81, 0x00733CF7,
	0x00D05652, 0x0006F124, 0x00261305, 0x00F0B473, 0x0067D747, 0x00B17031, 0x00919210, 0x00473566,
	0x008C4CE1, 0x005AEB97, 0x007A09B6, 0x00ACAEC0, 0x003BCDF4, 0x00ED6A82, 0x00CD88A3, 0x001B2FD5,
	0x00B84570, 0x006EE206, 0x004E0027, 0x0098A751, 0x000FC465, 0x00D96313, 0x00F98132, 0x002F2644,
	0x00347987, 0x00E2DEF1, 0x00C23CD0, 0x00149BA6, 0x0083F892, 0x00555FE4, 0x0075BDC5, 0x00A31AB3,
	0x00007016, 0x00D6D760, 0x00F63541, 0x00209237, 0x00B7F103, 0x00615675, 0x0041B454, 0x00971322,
	0x005C6AA5, 0x008ACDD3, 0x00AA2FF2, 0x007C8884, 0x00EBEBB0, 0x003D4CC6, 0x001DAEE7, 0x00CB0991,
	0x00686334, 0x00BEC442, 0x009E2663, 0x00488115, 0x00DFE221, 0x00094557, 0x0029A776, 0x00FF0000
};

/*! compute RLP FCS according to 3GPP TS 24.022 Section 4.4 */
static uint32_t rlp_fcs_compute(const unsigned char *in, size_t in_len)
{
	uint32_t divider = 0;
	size_t i;

	for (i = 0; i < in_len; i++) {
		unsigned char input = in[i] ^ (divider & 0xff);
		divider = (divider >> 8) ^ rlp_fcs_table[input];
	}

	return ((divider & 0xff) << 16) | (divider & 0xff00) | ((divider & 0xff0000) >> 16);
}

static int
dissect_gsmrlp_xid(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	int cur;

	for (cur = offset; cur < (int) tvb_reported_length(tvb);) {
		uint8_t len = tvb_get_guint8(tvb, cur) & 0x0f;
		uint8_t type = tvb_get_guint8(tvb, cur) >> 4;
		proto_tree *xid_tree;

		proto_tree_add_subtree_format(tree, tvb, cur, 1 + len, ett_gsmrlp_xid, &xid_tree, "XID Parameter: %s",
		                        val_to_str_const(type, rlp_xid_param_vals, "Unknown"));
		proto_tree_add_item(xid_tree, hf_gsmrlp_xid_p_type, tvb, cur, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(xid_tree, hf_gsmrlp_xid_p_len, tvb, cur, 1, ENC_BIG_ENDIAN);
		if (len)
			proto_tree_add_item(xid_tree, hf_gsmrlp_xid_p_val, tvb, cur + 1, len, ENC_BIG_ENDIAN);
		cur += 1 + len;
		if (type == XID_P_DELIMITER)
			break;
	}

	return cur - offset;
}


/* Dissect a RLP v0/v1 message as described in TS 24.022 section 5.2 */
static int
dissect_gsmrlp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	int reported_len = tvb_reported_length(tvb);
	proto_tree *rlp_tree;
	proto_item *ti;
	uint8_t n_s, n_r;

	/* we currently support the 16bit header of RLP v0 + v1 */

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "GSM-RLP");

	n_s = (tvb_get_guint8(tvb, 0)) >> 3 | ((tvb_get_guint8(tvb, 1) & 1) << 5);
	n_r = (tvb_get_guint8(tvb, 1) >> 2);

	ti = proto_tree_add_protocol_format(tree, proto_gsmrlp, tvb, 0, reported_len,
					    "GSM RLP");
	rlp_tree = proto_item_add_subtree(ti, ett_gsmrlp);

	proto_tree_add_item(rlp_tree, hf_gsmrlp_cr, tvb, 0, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(rlp_tree, hf_gsmrlp_pf, tvb, 1, 1, ENC_BIG_ENDIAN);
	if (n_s == 0x3f) { /* U frame */
		unsigned u_ftype;
		proto_tree_add_uint(rlp_tree, hf_gsmrlp_ftype, tvb, 0, 1, RLP_FT_U);
		proto_tree_add_item_ret_uint(rlp_tree, hf_gsmrlp_u_ftype, tvb, 1, 1, ENC_BIG_ENDIAN, &u_ftype);
		if ((n_r & 0x1f) == RLP_U_FT_XID)
			dissect_gsmrlp_xid(tvb, 2, pinfo, rlp_tree);
		proto_item_append_text(ti, " U-Frame: %s", val_to_str(u_ftype, rlp_ftype_u_vals, "Unknown 0x%02x"));
	} else if (n_s == 0x3e) { /* S Frame */
		unsigned s_ftype;
		proto_tree_add_uint(rlp_tree, hf_gsmrlp_ftype, tvb, 0, 1, RLP_FT_S);
		proto_tree_add_item_ret_uint(rlp_tree, hf_gsmrlp_s_ftype, tvb, 0, 1, ENC_BIG_ENDIAN, &s_ftype);
		proto_tree_add_uint(rlp_tree, hf_gsmrlp_n_r, tvb, 1, 1, n_r);
		proto_item_append_text(ti, " S-Frame: %s, N(S): %u, N(R): %u",
				       val_to_str(s_ftype, rlp_ftype_s_vals, "Unknown 0x%02x"), n_s, n_r);
	} else { /* IS Frame */
		tvbuff_t *next_tvb;
		unsigned s_ftype;
		int data_len;

		proto_tree_add_uint(rlp_tree, hf_gsmrlp_ftype, tvb, 0, 1, RLP_FT_IS);
		proto_tree_add_item_ret_uint(rlp_tree, hf_gsmrlp_s_ftype, tvb, 0, 1, ENC_BIG_ENDIAN, &s_ftype);
		proto_tree_add_uint(rlp_tree, hf_gsmrlp_n_s, tvb, 0, 2, n_s);
		proto_tree_add_uint(rlp_tree, hf_gsmrlp_n_r, tvb, 1, 1, n_r);
		proto_item_append_text(ti, " IS-Frame: %s, N(S): %u, N(R): %u",
				       val_to_str(s_ftype, rlp_ftype_s_vals, "Unknown 0x%02x"), n_s, n_r);

		/* dispatch user data */
		data_len = reported_len - 2 /* header */ - 3 /* FCS */;
		next_tvb = tvb_new_subset_length(tvb, 2, data_len);
		if (decode_as_l2rcop && l2rcop_handle)
			call_dissector(l2rcop_handle, next_tvb, pinfo, rlp_tree);
		else
			call_data_dissector(next_tvb, pinfo, rlp_tree);
	}

	/* FCS is always the last 3 bytes of the message */
	tvb_ensure_bytes_exist(tvb, 0, reported_len - 3);
	uint32_t fcs_computed = rlp_fcs_compute(tvb_get_ptr(tvb, 0, reported_len - 3), reported_len - 3);
	proto_tree_add_checksum(rlp_tree, tvb, reported_len - 3, hf_gsmrlp_fcs, hf_gsmrlp_fcs_status,
				&ei_gsmrlp_fcs_bad, pinfo, fcs_computed, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);

	return tvb_reported_length(tvb);
}

void
proto_register_gsmrlp(void)
{
	static hf_register_info hf[] = {
	    { &hf_gsmrlp_cr,
	      { "C/R", "gsm_rlp.cr", FT_UINT8, BASE_DEC, NULL, 0x01,
		"Command/Response bit", HFILL }},
	    { &hf_gsmrlp_pf,
	      { "P/F", "gsm_rlp.pf", FT_UINT8, BASE_DEC, NULL, 0x02,
		"Poll/Final bit", HFILL }},
	    { &hf_gsmrlp_n_r,
	      { "N(R)", "gsm_rlp.n_r", FT_UINT8, BASE_DEC, NULL, 0,
		"Receive Sequence Number", HFILL }},
	    { &hf_gsmrlp_n_s,
	      { "N(S)", "gsm_rlp.n_s", FT_UINT8, BASE_DEC, NULL, 0,
		"Send Sequence Number", HFILL }},
	    { &hf_gsmrlp_ftype,
	      { "Frame type", "gsm_rlp.ftype", FT_UINT8, BASE_HEX,
		VALS(rlp_ftype_vals), 0, NULL, HFILL }},
	    { &hf_gsmrlp_u_ftype,
	      { "U Frame type", "gsm_rlp.u_ftype", FT_UINT8, BASE_HEX,
		VALS(rlp_ftype_u_vals), 0x7c, NULL, HFILL }},
	    { &hf_gsmrlp_s_ftype,
	      { "S frame type", "gsm_rlp.s_ftype", FT_UINT8, BASE_HEX,
		VALS(rlp_ftype_s_vals), 0x06, NULL, HFILL }},
	    { &hf_gsmrlp_fcs,
	      { "Frame Check Sequence", "gsm_rlp.fcs", FT_UINT24, BASE_HEX,
		NULL, 0, NULL, HFILL }},
	    { &hf_gsmrlp_fcs_status,
	      { "FCS Status", "gsm_rlp.fcs.status", FT_UINT8, BASE_NONE,
		VALS(proto_checksum_vals), 0, NULL, HFILL }},

	    { &hf_gsmrlp_xid_p_type,
	      { "XID Parameter Type", "gsm_rlp.xid.param_type", FT_UINT8, BASE_HEX,
		VALS(rlp_xid_param_vals), 0xf0, NULL, HFILL }},
	    { &hf_gsmrlp_xid_p_len,
	      { "XID Parameter Length", "gsm_rlp.xid.param_len", FT_UINT8, BASE_DEC,
		NULL, 0x0f, NULL, HFILL }},
	    { &hf_gsmrlp_xid_p_val,
	      { "XID Parameter Value", "gsm_rlp.xid.param_value", FT_UINT8, BASE_DEC,
		NULL, 0, NULL, HFILL }},
	};
	static int *ett[] = {
		&ett_gsmrlp,
		&ett_gsmrlp_xid,
	};
	static ei_register_info ei[] = {
		{ &ei_gsmrlp_fcs_bad, { "gsm_rlp.fcs_bad", PI_CHECKSUM, PI_ERROR, "Bad checksum" , EXPFILL }},
	};
	module_t *rlp_module;
	expert_module_t *expert_gsmrlp;

	proto_gsmrlp = proto_register_protocol("GSM Radio Link Protocol (RLP)", "GSM-RLP", "gsm_rlp");
	proto_register_field_array(proto_gsmrlp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_gsmrlp = expert_register_protocol(proto_gsmrlp);
	expert_register_field_array(expert_gsmrlp, ei, array_length(ei));

	register_dissector("gsm_rlp", dissect_gsmrlp, proto_gsmrlp);

	rlp_module = prefs_register_protocol(proto_gsmrlp, NULL);
	prefs_register_bool_preference(rlp_module, "decode_as_l2rcop", "Decode payload as L2RCOP",
				       NULL, &decode_as_l2rcop);
}
void
proto_reg_handoff_gsmrlp(void)
{
	l2rcop_handle = find_dissector_add_dependency("gsm_l2rcop", proto_gsmrlp);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
