/* packet-gsm_a_rp.c
 * Routines for GSM A Interface RP dissection - SMS GSM layer 3
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * Title		3GPP			Other
 *
 *   Reference [5]
 *   Point-to-Point (PP) Short Message Service (SMS)
 *   support on mobile radio interface
 *   (3GPP TS 24.011 version 4.1.1 Release 4)
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

#include <epan/packet.h>
#include <epan/expert.h>

#include "packet-gsm_a_common.h"

void proto_register_gsm_a_rp(void);
void proto_reg_handoff_gsm_a_rp(void);

/* PROTOTYPES/FORWARDS */

static const value_string gsm_rp_msg_strings[] = {
	{ 0x00,	"RP-DATA (MS to Network)" },
	{ 0x01,	"RP-DATA (Network to MS)" },
	{ 0x02,	"RP-ACK (MS to Network)" },
	{ 0x03,	"RP-ACK (Network to MS)" },
	{ 0x04,	"RP-ERROR (MS to Network)" },
	{ 0x05,	"RP-ERROR (Network to MS)" },
	{ 0x06,	"RP-SMMA (MS to Network)" },
	{ 0, NULL }
};

typedef enum
{
	/* Short Message Service Information Elements [5] 8.2 */
	DE_RP_MESSAGE_REF,				/* RP-Message Reference */
	DE_RP_ORIG_ADDR,				/* RP-Originator Address */
	DE_RP_DEST_ADDR,				/* RP-Destination Address */
	DE_RP_USER_DATA,				/* RP-User Data */
	DE_RP_CAUSE,					/* RP-Cause */
	DE_RP_NONE							/* NONE */
}
rp_elem_idx_t;

static const value_string gsm_rp_elem_strings[] = {
	/* Short Message Service RP Information Elements [5] 8.2 */
	{ DE_RP_MESSAGE_REF, "RP-Message Reference" },
	{ DE_RP_ORIG_ADDR,   "RP-Originator Address" },
	{ DE_RP_DEST_ADDR,   "RP-Destination Address" },
	{ DE_RP_USER_DATA,   "RP-User Data" },
	{ DE_RP_CAUSE,	     "RP-Cause" },
	{ 0, NULL }
};
value_string_ext gsm_rp_elem_strings_ext = VALUE_STRING_EXT_INIT(gsm_rp_elem_strings);

/* Initialize the protocol and registered fields */
static int proto_a_rp = -1;

static int hf_gsm_a_rp_msg_type = -1;
int hf_gsm_a_rp_elem_id = -1;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_gsm_a_rp_tpdu = -1;
static int hf_gsm_a_rp_extension = -1;
static int hf_gsm_a_rp_diagnostic_field = -1;
static int hf_gsm_a_rp_cause = -1;
static int hf_gsm_a_rp_message_elements = -1;
static int hf_gsm_a_rp_rp_message_reference = -1;

/* Initialize the subtree pointers */
static gint ett_rp_msg = -1;

static expert_field ei_gsm_a_rp_extraneous_data = EI_INIT;

static dissector_handle_t gsm_sms_handle;	/* SMS TPDU */

static proto_tree *g_tree;

#define	NUM_GSM_RP_ELEM (sizeof(gsm_rp_elem_strings)/sizeof(value_string))
gint ett_gsm_rp_elem[NUM_GSM_RP_ELEM];

/*
 * [5] 8.2.3
 */
static guint16
de_rp_message_ref(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_rp_rp_message_reference, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [5] 8.2.5.1
 */
static guint16
de_rp_orig_addr(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string, int string_len)
{
	return(de_cld_party_bcd_num(tvb, tree, pinfo, offset, len, add_string, string_len));
}

/*
 * [5] 8.2.5.2
 */
static guint16
de_rp_dest_addr(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string, int string_len)
{
	return(de_cld_party_bcd_num(tvb, tree, pinfo, offset, len, add_string, string_len));
}

/*
 * [5] 8.2.5.3
 */
static guint16
de_rp_user_data(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	  curr_offset;
	tvbuff_t *tpdu_tvb;

	curr_offset = offset;

	proto_tree_add_bytes_format(tree, hf_gsm_a_rp_tpdu, tvb, curr_offset, len, NULL, "TPDU (not displayed)");

	/*
	 * dissect the embedded TPDU message
	 */
	tpdu_tvb = tvb_new_subset_length(tvb, curr_offset, len);

	call_dissector_only(gsm_sms_handle, tpdu_tvb, pinfo, g_tree, NULL);

	curr_offset += len;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_rp_extraneous_data);

	return(curr_offset - offset);
}

/*
 * [5] 8.2.5.4
 */
static const value_string gsm_rp_cause_vals[] = {
	{ 1,    "Unassigned (unallocated) number" },
	{ 8,    "Operator determined barring" },
	{ 10,   "Call barred" },
	{ 11,   "Reserved" },
	{ 21,	"Short message transfer rejected" },
	{ 22,   "Memory capacity exceeded" },
	{ 27,   "Destination out of order" },
	{ 28,   "Unidentified subscriber" },
	{ 29,   "Facility rejected" },
	{ 30,   "Unknown subscriber" },
	{ 38,   "Network out of order" },
	{ 41,   "Temporary failure" },
	{ 42,   "Congestion" },
	{ 47,   "Resources unavailable, unspecified" },
	{ 50,   "Requested facility not subscribed" },
	{ 69,   "Requested facility not implemented" },
	{ 81,   "Invalid short message transfer reference value" },
	{ 95,   "Semantically incorrect message" },
	{ 96,   "Invalid mandatory information" },
	{ 97,   "Message type non-existent or not implemented" },
	{ 98,   "Message not compatible with short message protocol state" },
	{ 99,   "Information element non-existent or not implemented" },
	{ 111,  "Protocol error, unspecified" },
	{ 127,  "Interworking, unspecified" },
	{ 0, NULL }
};

value_string_ext gsm_rp_cause_vals_ext = VALUE_STRING_EXT_INIT(gsm_rp_cause_vals);

static const true_false_string tfs_extended_no_extension = { "Extended", "No extension"};

static guint16
de_rp_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string, int string_len)
{
	guint8	oct;
	guint32	curr_offset;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	proto_tree_add_item(tree, hf_gsm_a_rp_extension, tvb, curr_offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_gsm_a_rp_cause, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	curr_offset++;

	if (add_string)
		g_snprintf(add_string, string_len, " - (%u) %s", oct & 0x7f, val_to_str_ext_const(oct & 0x7f, &gsm_rp_cause_vals_ext, "Reserved"));

	NO_MORE_DATA_CHECK(len);

	proto_tree_add_item(tree, hf_gsm_a_rp_diagnostic_field, tvb, curr_offset, len - (curr_offset - offset), ENC_NA);

	curr_offset += len - (curr_offset - offset);

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_rp_extraneous_data);

	return(curr_offset - offset);
}

guint16 (*rp_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string, int string_len) = {
	/* Short Message Service Information Elements [5] 8.2 */
	de_rp_message_ref, /* RP-Message Reference */
	de_rp_orig_addr,   /* RP-Originator Address */
	de_rp_dest_addr,   /* RP-Destination Address */
	de_rp_user_data,   /* RP-User Data */
	de_rp_cause,	   /* RP-Cause */
	NULL,	/* NONE */
};

/* MESSAGE FUNCTIONS */

/*
 * [5] 7.3.1.1
 */
void
rp_data_n_ms(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V(GSM_A_PDU_TYPE_RP, DE_RP_MESSAGE_REF, NULL);

	ELEM_MAND_LV(GSM_A_PDU_TYPE_RP, DE_RP_ORIG_ADDR, NULL);

	ELEM_MAND_LV(GSM_A_PDU_TYPE_RP, DE_RP_DEST_ADDR, NULL);

	ELEM_MAND_LV(GSM_A_PDU_TYPE_RP, DE_RP_USER_DATA, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_rp_extraneous_data);
}

/*
 * [5] 7.3.1.2
 */
static void
rp_data_ms_n(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_RECV;

	ELEM_MAND_V(GSM_A_PDU_TYPE_RP, DE_RP_MESSAGE_REF, NULL);

	ELEM_MAND_LV(GSM_A_PDU_TYPE_RP, DE_RP_ORIG_ADDR, NULL);

	ELEM_MAND_LV(GSM_A_PDU_TYPE_RP, DE_RP_DEST_ADDR, NULL);

	ELEM_MAND_LV(GSM_A_PDU_TYPE_RP, DE_RP_USER_DATA, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_rp_extraneous_data);
}

/*
 * [5] 7.3.2
 */
static void
rp_smma(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	ELEM_MAND_V(GSM_A_PDU_TYPE_RP, DE_RP_MESSAGE_REF, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_rp_extraneous_data);
}

/*
 * [5] 7.3.3
 */
static void
rp_ack_n_ms(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V(GSM_A_PDU_TYPE_RP, DE_RP_MESSAGE_REF, NULL);

	ELEM_OPT_TLV(0x41, GSM_A_PDU_TYPE_RP, DE_RP_USER_DATA, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_rp_extraneous_data);
}

/*
 * [5] 7.3.3
 */
static void
rp_ack_ms_n(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_RECV;

	ELEM_MAND_V(GSM_A_PDU_TYPE_RP, DE_RP_MESSAGE_REF, NULL);

	ELEM_OPT_TLV(0x41, GSM_A_PDU_TYPE_RP, DE_RP_USER_DATA, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_rp_extraneous_data);
}

/*
 * [5] 7.3.4
 */
static void
rp_error_n_ms(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V(GSM_A_PDU_TYPE_RP, DE_RP_MESSAGE_REF, NULL);

	ELEM_MAND_LV(GSM_A_PDU_TYPE_RP, DE_RP_CAUSE, NULL);

	ELEM_OPT_TLV(0x41, GSM_A_PDU_TYPE_RP, DE_RP_USER_DATA, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_rp_extraneous_data);
}

/*
 * [5] 7.3.4
 */
static void
rp_error_ms_n(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_RECV;

	ELEM_MAND_V(GSM_A_PDU_TYPE_RP, DE_RP_MESSAGE_REF, NULL);

	ELEM_MAND_LV(GSM_A_PDU_TYPE_RP, DE_RP_CAUSE, NULL);

	ELEM_OPT_TLV(0x41, GSM_A_PDU_TYPE_RP, DE_RP_USER_DATA, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_rp_extraneous_data);
}

#define	NUM_GSM_RP_MSG (sizeof(gsm_rp_msg_strings)/sizeof(value_string))
static gint ett_gsm_rp_msg[NUM_GSM_RP_MSG];
static void (*rp_msg_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len) = {
	rp_data_ms_n,	/* RP-DATA (MS to Network) */
	rp_data_n_ms,	/* RP-DATA (Network to MS) */
	rp_ack_ms_n,	/* RP-ACK (MS to Network) */
	rp_ack_n_ms,	/* RP-ACK (Network to MS) */
	rp_error_ms_n,	/* RP-ERROR (MS to Network) */
	rp_error_n_ms,	/* RP-ERROR (Network to MS) */
	rp_smma,	/* RP-SMMA (MS to Network) */
	NULL,	/* NONE */
};

/* GENERIC DISSECTOR FUNCTIONS */

static int
dissect_rp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	guint8	     oct;
	guint32	     offset, saved_offset;
	guint32	     len;
	gint	     idx;
	proto_item  *rp_item = NULL;
	proto_tree  *rp_tree = NULL;
	const gchar *str;

	col_append_str(pinfo->cinfo, COL_INFO, "(RP) ");

	offset = 0;
	saved_offset = offset;

	g_tree = tree;

	len = tvb_reported_length(tvb);

	/*
	 * add RP message name
	 */
	oct = tvb_get_guint8(tvb, offset++);

	str = try_val_to_str_idx((guint32) oct, gsm_rp_msg_strings, &idx);

	/*
	 * create the protocol tree
	 */
	if (str == NULL)
	{
		rp_item =
			proto_tree_add_protocol_format(tree, proto_a_rp, tvb, 0, len,
				"GSM A-I/F RP - Unknown RP Message Type (0x%02x)",
				oct);

		rp_tree = proto_item_add_subtree(rp_item, ett_rp_msg);
	}
	else
	{
		rp_item =
			proto_tree_add_protocol_format(tree, proto_a_rp, tvb, 0, -1,
				"GSM A-I/F RP - %s",
				str);

		rp_tree = proto_item_add_subtree(rp_item, ett_gsm_rp_msg[idx]);

		col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", str);
	}

	/*
	 * add RP message name
	 */
	proto_tree_add_uint_format(rp_tree, hf_gsm_a_rp_msg_type,
		tvb, saved_offset, 1, oct, "Message Type %s", str ? str : "(Unknown)");

	if (str == NULL) return offset;

	if (offset >=len) return offset;

	/*
	 * decode elements
	 */
	if (rp_msg_fcn[idx] == NULL)
	{
		proto_tree_add_item(rp_tree, hf_gsm_a_rp_message_elements, tvb, offset, len - offset, ENC_NA);
	}
	else
	{
		(*rp_msg_fcn[idx])(tvb, rp_tree, pinfo, offset, len - offset);
	}
	return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */
void
proto_register_gsm_a_rp(void)
{
	guint i;
	guint last_offset;

	/* Setup list of header fields */

	static hf_register_info hf[] = {
		{ &hf_gsm_a_rp_msg_type,
		  { "RP Message Type",	"gsm_a.rp.msg_type",
		    FT_UINT8, BASE_HEX, VALS(gsm_rp_msg_strings), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_rp_elem_id,
		  { "Element ID",	"gsm_a.rp.elem_id",
		    FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},

      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_gsm_a_rp_rp_message_reference, { "RP-Message Reference", "gsm_a.rp.rp_message_reference", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_a_rp_tpdu, { "TPDU", "gsm_a.rp.tpdu", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_a_rp_extension, { "Extension", "gsm_a.rp.extension", FT_BOOLEAN, 8, TFS(&tfs_extended_no_extension), 0x80, NULL, HFILL }},
      { &hf_gsm_a_rp_cause, { "Cause", "gsm_a.rp.cause", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gsm_rp_cause_vals_ext, 0x7F, NULL, HFILL }},
      { &hf_gsm_a_rp_diagnostic_field, { "Diagnostic field", "gsm_a.rp.diagnostic_field", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gsm_a_rp_message_elements, { "Message Elements", "gsm_a.rp.message_elements", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	};

	static ei_register_info ei[] = {
		{ &ei_gsm_a_rp_extraneous_data, { "gsm_a.rp.extraneous_data", PI_PROTOCOL, PI_NOTE, "Extraneous Data, dissector bug or later version spec(report to wireshark.org)", EXPFILL }},
	};

	expert_module_t* expert_gsm_a_rp;

	/* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_ELEMS	1
	gint *ett[NUM_INDIVIDUAL_ELEMS +
		  NUM_GSM_RP_MSG +
		  NUM_GSM_RP_ELEM];

	ett[0] = &ett_rp_msg;

	last_offset = NUM_INDIVIDUAL_ELEMS;

	for (i=0; i < NUM_GSM_RP_MSG; i++, last_offset++)
	{
		ett_gsm_rp_msg[i] = -1;
		ett[last_offset] = &ett_gsm_rp_msg[i];
	}

	for (i=0; i < NUM_GSM_RP_ELEM; i++, last_offset++)
	{
		ett_gsm_rp_elem[i] = -1;
		ett[last_offset] = &ett_gsm_rp_elem[i];
	}

	/* Register the protocol name and description */

	proto_a_rp = proto_register_protocol("GSM A-I/F RP", "GSM RP", "gsm_a.rp");

	proto_register_field_array(proto_a_rp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_gsm_a_rp = expert_register_protocol(proto_a_rp);
	expert_register_field_array(expert_gsm_a_rp, ei, array_length(ei));

	register_dissector("gsm_a_rp", dissect_rp, proto_a_rp);
}

void
proto_reg_handoff_gsm_a_rp(void)
{
	dissector_handle_t	gsm_a_rp_handle;

	gsm_a_rp_handle = create_dissector_handle(dissect_rp, proto_a_rp);
	/* Dissect messages embedded in SIP */
	dissector_add_string("media_type","application/vnd.3gpp.sms", gsm_a_rp_handle);
	gsm_sms_handle = find_dissector_add_dependency("gsm_sms", proto_a_rp);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
