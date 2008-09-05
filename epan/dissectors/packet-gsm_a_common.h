/* packet-gsm_a_common.h
 *
 * $Id$
 *
 *   Reference [3]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 4.7.0 Release 4)
 *   (ETSI TS 124 008 V6.8.0 (2005-03))
 *
 *   Reference [5]
 *   Point-to-Point (PP) Short Message Service (SMS)
 *   support on mobile radio interface
 *   (3GPP TS 24.011 version 4.1.1 Release 4)
 *
 *   Reference [7]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 5.9.0 Release 5)
 *
 *   Reference [8]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 6.7.0 Release 6)
 *	 (3GPP TS 24.008 version 6.8.0 Release 6)
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>,
 * In association with Telos Technology Inc.
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
#ifndef __PACKET_GSM_A_COMMON_H__
#define __PACKET_GSM_A_COMMON_H__

#include "packet-sccp.h"

/* PROTOTYPES/FORWARDS */
typedef guint8 (*elem_fcn)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
typedef void (*msg_fcn)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len);

typedef struct dgt_set_t
{
	unsigned char out[15];
}
dgt_set_t;

int my_dgt_tbcd_unpack( 
	char	*out,		/* ASCII pattern out */
	guchar	*in,		/* packed pattern in */
	int		num_octs,	/* Number of octets to unpack */
	dgt_set_t	*dgt		/* Digit definitions */
	);

/* globals needed as a result of spltting the packet-gsm_a.c into several files
 * until further restructuring can take place to make them more modular
 */

/* common PD values */
extern const value_string protocol_discriminator_vals[];
extern const value_string gsm_a_pd_short_str_vals[];

extern guint8 de_cld_party_bcd_num(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

/* Needed to share the packet-gsm_a_common.c functions */
extern const value_string gsm_bssmap_elem_strings[];
extern gint ett_gsm_bssmap_elem[];
extern elem_fcn bssmap_elem_fcn[];
extern int hf_gsm_a_bssmap_elem_id;

extern const value_string gsm_dtap_elem_strings[];
extern gint ett_gsm_dtap_elem[];
extern elem_fcn dtap_elem_fcn[];
extern int hf_gsm_a_dtap_elem_id;

extern const value_string gsm_rp_elem_strings[];
extern gint ett_gsm_rp_elem[];
extern elem_fcn rp_elem_fcn[];
extern int hf_gsm_a_rp_elem_id;

extern const value_string gsm_rr_elem_strings[];
extern gint ett_gsm_rr_elem[];
extern elem_fcn rr_elem_fcn[];
extern int hf_gsm_a_rr_elem_id;
extern void get_rr_msg_params(guint8 oct, const gchar **msg_str, int *ett_tree, int *hf_idx, msg_fcn *msg_fcn);

extern const value_string gsm_common_elem_strings[];
extern gint ett_gsm_common_elem[];
extern elem_fcn common_elem_fcn[];
extern int hf_gsm_a_common_elem_id;

extern const value_string gsm_gm_elem_strings[];
extern gint ett_gsm_gm_elem[];
extern elem_fcn gm_elem_fcn[];
extern int hf_gsm_a_gm_elem_id;
extern void get_gmm_msg_params(guint8 oct, const gchar **msg_str, int *ett_tree, int *hf_idx, msg_fcn *msg_fcn);
extern void get_sm_msg_params(guint8 oct, const gchar **msg_str, int *ett_tree, int *hf_idx, msg_fcn *msg_fcn);

extern sccp_msg_info_t* sccp_msg;
extern sccp_assoc_info_t* sccp_assoc;

extern int gsm_a_tap;
extern gboolean lower_nibble;
extern packet_info *gsm_a_dtap_pinfo;

/* common field values */
extern int hf_gsm_a_length;
extern int hf_gsm_a_extension;
extern int hf_gsm_a_tmsi;
extern int hf_gsm_a_L3_protocol_discriminator;
extern int hf_gsm_a_b8spare;
extern int hf_gsm_a_skip_ind;
extern int hf_gsm_a_rr_chnl_needed_ch1;

/* for the nasty hack below */
#define GSM_BSSMAP_APDU_IE	0x49

/* flags for the packet-gsm_a_common routines */
#define GSM_A_PDU_TYPE_BSSMAP	BSSAP_PDU_TYPE_BSSMAP /* i.e. 0 - until split complete at least! */
#define GSM_A_PDU_TYPE_DTAP		BSSAP_PDU_TYPE_DTAP   /* i.e. 1 - until split complete at least! */
#define GSM_A_PDU_TYPE_RP		2
#define GSM_A_PDU_TYPE_RR		3
#define GSM_A_PDU_TYPE_COMMON	4
#define GSM_A_PDU_TYPE_GM		5

extern const char* get_gsm_a_msg_string(int pdu_type, int idx);

/*
 * this should be set on a per message basis, if possible
 */
#define	IS_UPLINK_FALSE		0
#define	IS_UPLINK_TRUE		1
#define	IS_UPLINK_UNKNOWN	2

/* Defines and nasty static for handling half octet mandatory V IEs 
 * TODO: Note origimally UPPER_NIBBLE was -2 and LOWER_NIBBLE was -1
 * changed here to unsigned integer as it wouldn't compile (Warnings on Ubuntu)
 * uggly hack...
 */
#define UPPER_NIBBLE	(2)
#define LOWER_NIBBLE	(1)

/* FUNCTIONS */

/* ELEMENT FUNCTIONS */

#define	EXTRANEOUS_DATA_CHECK(edc_len, edc_max_len) \
	if (((edc_len) > (edc_max_len))||lower_nibble) \
	{ \
		proto_tree_add_text(tree, tvb, \
			curr_offset, (edc_len) - (edc_max_len), "Extraneous Data"); \
		curr_offset += ((edc_len) - (edc_max_len)); \
	}

#define	SHORT_DATA_CHECK(sdc_len, sdc_min_len) \
	if ((sdc_len) < (sdc_min_len)) \
	{ \
		proto_tree_add_text(tree, tvb, \
			curr_offset, (sdc_len), "Short Data (?)"); \
		curr_offset += (sdc_len); \
		return(curr_offset - offset); \
	}

#define	EXACT_DATA_CHECK(edc_len, edc_eq_len) \
	if ((edc_len) != (edc_eq_len)) \
	{ \
		proto_tree_add_text(tree, tvb, \
			curr_offset, (edc_len), "Unexpected Data Length"); \
		curr_offset += (edc_len); \
		return(curr_offset - offset); \
	}

#define	NO_MORE_DATA_CHECK(nmdc_len) \
	if ((nmdc_len) == (curr_offset - offset)) return(nmdc_len);

#define	SET_ELEM_VARS(SEV_pdu_type, SEV_elem_names, SEV_elem_ett, SEV_elem_funcs) \
	switch (SEV_pdu_type) \
	{ \
	case GSM_A_PDU_TYPE_BSSMAP: \
		SEV_elem_names = gsm_bssmap_elem_strings; \
		SEV_elem_ett = ett_gsm_bssmap_elem; \
		SEV_elem_funcs = bssmap_elem_fcn; \
		break; \
	case GSM_A_PDU_TYPE_DTAP: \
		SEV_elem_names = gsm_dtap_elem_strings; \
		SEV_elem_ett = ett_gsm_dtap_elem; \
		SEV_elem_funcs = dtap_elem_fcn; \
		break; \
	case GSM_A_PDU_TYPE_RP: \
		SEV_elem_names = gsm_rp_elem_strings; \
		SEV_elem_ett = ett_gsm_rp_elem; \
		SEV_elem_funcs = rp_elem_fcn; \
		break; \
	case GSM_A_PDU_TYPE_RR: \
		SEV_elem_names = gsm_rr_elem_strings; \
		SEV_elem_ett = ett_gsm_rr_elem; \
		SEV_elem_funcs = rr_elem_fcn; \
		break; \
	case GSM_A_PDU_TYPE_COMMON: \
		SEV_elem_names = gsm_common_elem_strings; \
		SEV_elem_ett = ett_gsm_common_elem; \
		SEV_elem_funcs = common_elem_fcn; \
		break; \
	case GSM_A_PDU_TYPE_GM: \
		SEV_elem_names = gsm_gm_elem_strings; \
		SEV_elem_ett = ett_gsm_gm_elem; \
		SEV_elem_funcs = gm_elem_fcn; \
		break; \
	default: \
		proto_tree_add_text(tree, \
			tvb, curr_offset, -1, \
			"Unknown PDU type (%u)", SEV_pdu_type); \
		return(consumed); \
	}

/*
 * Type Length Value (TLV) element dissector
 */
extern guint8 elem_tlv(tvbuff_t *tvb, proto_tree *tree, guint8 iei, gint pdu_type, int idx, guint32 offset, guint len, const gchar *name_add);

/*
 * Type Value (TV) element dissector
 *
 * Length cannot be used in these functions, big problem if a element dissector
 * is not defined for these.
 */
extern guint8 elem_tv(tvbuff_t *tvb, proto_tree *tree, guint8 iei, gint pdu_type, int idx, guint32 offset, const gchar *name_add);

/*
 * Type Value (TV) element dissector
 * Where top half nibble is IEI and bottom half nibble is value.
 *
 * Length cannot be used in these functions, big problem if a element dissector
 * is not defined for these.
 */
extern guint8 elem_tv_short(tvbuff_t *tvb, proto_tree *tree, guint8 iei, gint pdu_type, int idx, guint32 offset, const gchar *name_add);

/*
 * Type (T) element dissector
 */
extern guint8 elem_t(tvbuff_t *tvb, proto_tree *tree, guint8 iei, gint pdu_type, int idx, guint32 offset, const gchar *name_add);

/*
 * Length Value (LV) element dissector
 */
extern guint8 elem_lv(tvbuff_t *tvb, proto_tree *tree, gint pdu_type, int idx, guint32 offset, guint len, const gchar *name_add);

/*
 * Value (V) element dissector
 *
 * Length cannot be used in these functions, big problem if a element dissector
 * is not defined for these.
 */
extern guint8 elem_v(tvbuff_t *tvb, proto_tree *tree, gint pdu_type, int idx, guint32 offset);

/*
 * Short Value (V_SHORT) element dissector
 *
 * Length is (ab)used in these functions to indicate upper nibble of the octet (-2) or lower nibble (-1)
 * noting that the tv_short dissector always sets the length to -1, as the upper nibble is the IEI.
 * This is expected to be used upper nibble first, as the tables of 24.008.
 */

extern guint8 elem_v_short(tvbuff_t *tvb, proto_tree *tree, gint pdu_type, int idx, guint32 offset);


#define ELEM_MAND_TLV(EMT_iei, EMT_pdu_type, EMT_elem_idx, EMT_elem_name_addition) \
{\
	if ((consumed = elem_tlv(tvb, tree, (guint8) EMT_iei, EMT_pdu_type, EMT_elem_idx, curr_offset, curr_len, EMT_elem_name_addition)) > 0) \
	{ \
		curr_offset += consumed; \
		curr_len -= consumed; \
	} \
	else \
	{ \
		proto_tree_add_text(tree, \
			tvb, curr_offset, 0, \
			"Missing Mandatory element (0x%02x) %s%s, rest of dissection is suspect", \
			EMT_iei, \
			get_gsm_a_msg_string(EMT_pdu_type, EMT_elem_idx), \
			(EMT_elem_name_addition == NULL) || (EMT_elem_name_addition[0] == '\0') ? "" : EMT_elem_name_addition \
			); \
	} \
	if (curr_len <= 0) return; \
}

#define ELEM_OPT_TLV(EOT_iei, EOT_pdu_type, EOT_elem_idx, EOT_elem_name_addition) \
{\
	if ((consumed = elem_tlv(tvb, tree, (guint8) EOT_iei, EOT_pdu_type, EOT_elem_idx, curr_offset, curr_len, EOT_elem_name_addition)) > 0) \
	{ \
		curr_offset += consumed; \
		curr_len -= consumed; \
	} \
	if (curr_len <= 0) return; \
}

#define ELEM_MAND_TV(EMT_iei, EMT_pdu_type, EMT_elem_idx, EMT_elem_name_addition) \
{\
	if ((consumed = elem_tv(tvb, tree, (guint8) EMT_iei, EMT_pdu_type, EMT_elem_idx, curr_offset, EMT_elem_name_addition)) > 0) \
	{ \
		curr_offset += consumed; \
		curr_len -= consumed; \
	} \
	else \
	{ \
		proto_tree_add_text(tree, \
			tvb, curr_offset, 0, \
			"Missing Mandatory element (0x%02x) %s%s, rest of dissection is suspect", \
			EMT_iei, \
			get_gsm_a_msg_string(EMT_pdu_type, EMT_elem_idx), \
			(EMT_elem_name_addition == NULL) || (EMT_elem_name_addition[0] == '\0') ? "" : EMT_elem_name_addition \
		); \
	} \
	if (curr_len <= 0) return; \
}

#define ELEM_OPT_TV(EOT_iei, EOT_pdu_type, EOT_elem_idx, EOT_elem_name_addition) \
{\
	if ((consumed = elem_tv(tvb, tree, (guint8) EOT_iei, EOT_pdu_type, EOT_elem_idx, curr_offset, EOT_elem_name_addition)) > 0) \
	{ \
		curr_offset += consumed; \
		curr_len -= consumed; \
	} \
	if (curr_len <= 0) return; \
}

#define ELEM_OPT_TV_SHORT(EOT_iei, EOT_pdu_type, EOT_elem_idx, EOT_elem_name_addition) \
{\
	if ((consumed = elem_tv_short(tvb, tree, EOT_iei, EOT_pdu_type, EOT_elem_idx, curr_offset, EOT_elem_name_addition)) > 0) \
	{ \
		curr_offset += consumed; \
		curr_len -= consumed; \
	} \
	if (curr_len <= 0) return; \
}

#define ELEM_OPT_T(EOT_iei, EOT_pdu_type, EOT_elem_idx, EOT_elem_name_addition) \
{\
	if ((consumed = elem_t(tvb, tree, (guint8) EOT_iei, EOT_pdu_type, EOT_elem_idx, curr_offset, EOT_elem_name_addition)) > 0) \
	{ \
		curr_offset += consumed; \
		curr_len -= consumed; \
	} \
	if (curr_len <= 0) return; \
}

#define ELEM_MAND_LV(EML_pdu_type, EML_elem_idx, EML_elem_name_addition) \
{\
	if ((consumed = elem_lv(tvb, tree, EML_pdu_type, EML_elem_idx, curr_offset, curr_len, EML_elem_name_addition)) > 0) \
	{ \
		curr_offset += consumed; \
		curr_len -= consumed; \
	} \
	else \
	{ \
		/* Mandatory, but nothing we can do */ \
	} \
	if (curr_len <= 0) return; \
}

#define ELEM_MAND_V(EMV_pdu_type, EMV_elem_idx) \
{\
	if ((consumed = elem_v(tvb, tree, EMV_pdu_type, EMV_elem_idx, curr_offset)) > 0) \
	{ \
		curr_offset += consumed; \
		curr_len -= consumed; \
	} \
	else \
	{ \
		/* Mandatory, but nothing we can do */ \
	} \
	if (curr_len <= 0) return; \
}

#define ELEM_MAND_V_SHORT(EMV_pdu_type, EMV_elem_idx) \
{\
	if ((consumed = elem_v_short(tvb, tree, EMV_pdu_type, EMV_elem_idx, curr_offset)) > 0) \
	{ \
		curr_offset += consumed; \
		curr_len -= consumed; \
	} \
	else \
	{ \
		/* Mandatory, but nothing we can do */ \
	} \
	if (curr_len <= 0) return; \
}

/*
 * this enum must be kept in-sync with 'gsm_a_pd_str'
 * it is used as an index into the array
 */
typedef enum
{
	PD_GCC = 0,
	PD_BCC,
	PD_RSVD_1,
	PD_CC,
	PD_GTTP,
	PD_MM,
	PD_RR,
	PD_UNK_1,
	PD_GMM,
	PD_SMS,
	PD_SM,
	PD_SS,
	PD_LCS,
	PD_UNK_2,
	PD_RSVD_EXT,
	PD_RSVD_TEST
}
gsm_a_pd_str_e;

typedef struct _gsm_a_tap_rec_t {
	/*
	 * value from packet-bssap.h
	 */
	guint8		pdu_type;
	guint8		message_type;
	gsm_a_pd_str_e	protocol_disc;
} gsm_a_tap_rec_t;

void dissect_bssmap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

void dtap_mm_mm_info(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len);

guint8 be_cell_id_aux(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len, guint8 disc);
guint8 be_cell_id_list(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
guint8 be_chan_type(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

guint8 de_lai(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
guint8 de_mid(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
guint8 de_cell_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

guint8 de_ms_cm_1(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_);
guint8 de_ms_cm_2(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

guint8 de_sm_apn(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
guint8 de_sm_qos(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
guint8 de_sm_pflow_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

guint8 de_gmm_drx_param(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
guint8 de_gmm_ms_net_cap(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
guint8 de_gmm_rai(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
guint8 de_gmm_ms_radio_acc_cap(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

guint8 de_rr_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
guint8 de_rr_cell_dsc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
guint8 de_rr_ch_dsc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_);
guint8 de_rr_ch_mode(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
guint8 de_rr_chnl_needed(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_);
guint8 de_rr_cip_mode_set(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
guint8 de_rr_cm_enq_mask(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
guint8 de_rr_meas_res(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_);
guint8 de_rr_multirate_conf(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_);
guint8 de_rr_sus_cau(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
guint8 de_rr_tlli(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

guint8 de_rej_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_);
guint8 de_d_gb_call_ref(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_);

void dtap_rr_ho_cmd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len);

/*
 * the following allows TAP code access to the messages
 * without having to duplicate it. With MSVC and a 
 * libwireshark.dll, we need a special declaration.
 */
WS_VAR_IMPORT const value_string gsm_a_bssmap_msg_strings[];
WS_VAR_IMPORT const value_string gsm_a_dtap_msg_mm_strings[];
WS_VAR_IMPORT const value_string gsm_a_dtap_msg_rr_strings[];
WS_VAR_IMPORT const value_string gsm_a_dtap_msg_cc_strings[];
WS_VAR_IMPORT const value_string gsm_a_dtap_msg_gmm_strings[];
WS_VAR_IMPORT const value_string gsm_a_dtap_msg_sms_strings[];
WS_VAR_IMPORT const value_string gsm_a_dtap_msg_sm_strings[];
WS_VAR_IMPORT const value_string gsm_a_dtap_msg_ss_strings[];
WS_VAR_IMPORT const gchar *gsm_a_pd_str[];

extern const value_string gsm_a_qos_del_of_err_sdu_vals[];
extern const value_string gsm_a_qos_del_order_vals[];
extern const value_string gsm_a_qos_traffic_cls_vals[];
extern const value_string gsm_a_qos_ber_vals[];
extern const value_string gsm_a_qos_sdu_err_rat_vals[];
extern const value_string gsm_a_qos_traff_hdl_pri_vals[];

extern const value_string gsm_a_type_of_number_values[];
extern const value_string gsm_a_numbering_plan_id_values[]; 

typedef enum
{
	/* Common Information Elements [3] 10.5.1 */
	DE_CELL_ID,				/* Cell Identity */
	DE_CIPH_KEY_SEQ_NUM,	/* Ciphering Key Sequence Number */
	DE_LAI,					/* Location Area Identification */
	DE_MID,					/* Mobile Identity */
	DE_MS_CM_1,				/* Mobile Station Classmark 1 */
	DE_MS_CM_2,				/* Mobile Station Classmark 2 */
	DE_MS_CM_3,				/* Mobile Station Classmark 3 */
	DE_SPARE_NIBBLE,			/* Spare Half Octet */
	DE_D_GB_CALL_REF,		/* Descriptive group or broadcast call reference */
	DE_G_CIPH_KEY_NUM,		/* Group Cipher Key Number */
	DE_PD_SAPI,				/* PD and SAPI $(CCBS)$ */
	DE_PRIO,				/* Priority Level */
	DE_PLMN_LIST,			/* PLMN List */

	DE_COMMON_NONE							/* NONE */
}
common_elem_idx_t;

typedef enum
{
	/* Mobility Management Information Elements [3] 10.5.3 */
	DE_AUTH_PARAM_RAND,				/* Authentication Parameter RAND */
	DE_AUTH_PARAM_AUTN,				/* Authentication Parameter AUTN (UMTS authentication challenge only) */
	DE_AUTH_RESP_PARAM,				/* Authentication Response Parameter */
	DE_AUTH_RESP_PARAM_EXT,			/* Authentication Response Parameter (extension) (UMTS authentication challenge only) */
	DE_AUTH_FAIL_PARAM,				/* Authentication Failure Parameter (UMTS authentication challenge only) */
	DE_CM_SRVC_TYPE,				/* CM Service Type */
	DE_ID_TYPE,						/* Identity Type */
	DE_LOC_UPD_TYPE,				/* Location Updating Type */
	DE_NETWORK_NAME,				/* Network Name */
	DE_REJ_CAUSE,					/* Reject Cause */
	DE_FOP,							/* Follow-on Proceed */
	DE_TIME_ZONE,					/* Time Zone */
	DE_TIME_ZONE_TIME,				/* Time Zone and Time */
	DE_CTS_PERM,					/* CTS Permission */
	DE_LSA_ID,						/* LSA Identifier */
	DE_DAY_SAVING_TIME,				/* Daylight Saving Time */
	DE_EMERGENCY_NUM_LIST,			/* Emergency Number List */
	/* Call Control Information Elements 10.5.4 */
	DE_AUX_STATES,					/* Auxiliary States */
	DE_BEARER_CAP,					/* Bearer Capability */
	DE_CC_CAP,						/* Call Control Capabilities */
	DE_CALL_STATE,					/* Call State */
	DE_CLD_PARTY_BCD_NUM,			/* Called Party BCD Number */
	DE_CLD_PARTY_SUB_ADDR,			/* Called Party Subaddress */
	DE_CLG_PARTY_BCD_NUM,			/* Calling Party BCD Number */
	DE_CLG_PARTY_SUB_ADDR,			/* Calling Party Subaddress */
	DE_CAUSE,						/* Cause */
	DE_CLIR_SUP,					/* CLIR Suppression */
	DE_CLIR_INV,					/* CLIR Invocation */
	DE_CONGESTION,					/* Congestion Level */
	DE_CONN_NUM,					/* Connected Number */
	DE_CONN_SUB_ADDR,				/* Connected Subaddress */
	DE_FACILITY,					/* Facility */
	DE_HLC,							/* High Layer Compatibility */
	DE_KEYPAD_FACILITY,				/* Keypad Facility */
	DE_LLC,							/* Low Layer Compatibility */
	DE_MORE_DATA,					/* More Data */
	DE_NOT_IND,						/* Notification Indicator */
	DE_PROG_IND,					/* Progress Indicator */
	DE_RECALL_TYPE,					/* Recall type $(CCBS)$ */
	DE_RED_PARTY_BCD_NUM,			/* Redirecting Party BCD Number */
	DE_RED_PARTY_SUB_ADDR,			/* Redirecting Party Subaddress */
	DE_REPEAT_IND,					/* Repeat Indicator */
	DE_REV_CALL_SETUP_DIR,			/* Reverse Call Setup Direction */
	DE_SETUP_CONTAINER,				/* SETUP Container $(CCBS)$ */
	DE_SIGNAL,						/* Signal */
	DE_SS_VER_IND,					/* SS Version Indicator */
	DE_USER_USER,					/* User-user */
	DE_ALERT_PATTERN,				/* Alerting Pattern $(NIA)$ */
	DE_ALLOWED_ACTIONS,				/* Allowed Actions $(CCBS)$ */
	DE_SI,							/* Stream Identifier */
	DE_NET_CC_CAP,					/* Network Call Control Capabilities */
	DE_CAUSE_NO_CLI,				/* Cause of No CLI */
	DE_IMM_MOD_IND,					/* Immediate Modification Indicator */
	DE_SUP_CODEC_LIST,				/* Supported Codec List */
	DE_SRVC_CAT,					/* Service Category */
	/* Short Message Service Information Elements [5] 8.1.4 */
	DE_CP_USER_DATA,				/* CP-User Data */
	DE_CP_CAUSE,					/* CP-Cause */
	/* Tests procedures information elements 3GPP TS 44.014 6.4.0 and 3GPP TS 34.109 6.4.0 */
	DE_TP_SUB_CHANNEL,			/* Close TCH Loop Cmd Sub-channel */
	DE_TP_ACK,			/* Open Loop Cmd Ack */
	DE_TP_LOOP_TYPE,			/* Close Multi-slot Loop Cmd Loop type*/
	DE_TP_LOOP_ACK,			/* Close Multi-slot Loop Ack Result */
	DE_TP_TESTED_DEVICE,			/* Test Interface Tested device */
	DE_TP_PDU_DESCRIPTION,			/* GPRS Test Mode Cmd PDU description */
	DE_TP_MODE_FLAG,			/* GPRS Test Mode Cmd Mode flag */
	DE_TP_EGPRS_MODE_FLAG,			/* EGPRS Start Radio Block Loopback Cmd Mode flag */
	DE_TP_UE_TEST_LOOP_MODE,			/* Close UE Test Loop Mode */
	DE_TP_UE_POSITIONING_TECHNOLOGY,			/* UE Positioning Technology */
	DE_TP_RLC_SDU_COUNTER_VALUE,			/* RLC SDU Counter Value */
	DE_NONE							/* NONE */
}
dtap_elem_idx_t;

typedef enum
{
	/* GPRS Mobility Management Information Elements [3] 10.5.5 */
	DE_ATTACH_RES,					/* [7] 10.5.1 Attach Result*/
	DE_ATTACH_TYPE,					/* [7] 10.5.2 Attach Type */
	DE_CIPH_ALG,					/* [7] 10.5.3 Cipher Algorithm */
	DE_TMSI_STAT,					/* [7] 10.5.4 TMSI Status */
	DE_DETACH_TYPE,					/* [7] 10.5.5 Detach Type */
	DE_DRX_PARAM,					/* [7] 10.5.6 DRX Parameter */
	DE_FORCE_TO_STAND,				/* [7] 10.5.7 Force to Standby */
	DE_FORCE_TO_STAND_H,			/* [7] 10.5.8 Force to Standby - Info is in the high nibble */
	DE_P_TMSI_SIG,					/* [7] 10.5.9 P-TMSI Signature */
	DE_P_TMSI_SIG_2,				/* [7] 10.5.10 P-TMSI Signature 2 */
	DE_ID_TYPE_2,					/* [7] 10.5.11 Identity Type 2 */
	DE_IMEISV_REQ,					/* [7] 10.5.12 IMEISV Request */
	DE_REC_N_PDU_NUM_LIST,			/* [7] 10.5.13 Receive N-PDU Numbers List */
	DE_MS_NET_CAP,					/* [7] 10.5.14 MS Network Capability */
	DE_MS_RAD_ACC_CAP,				/* [7] 10.5.15 MS Radio Access Capability */
	DE_GMM_CAUSE,					/* [7] 10.5.16 GMM Cause */
	DE_RAI,							/* [7] 10.5.17 Routing Area Identification */
	DE_UPD_RES,						/* [7] 10.5.18 Update Result */
	DE_UPD_TYPE,					/* [7] 10.5.19 Update Type */
	DE_AC_REF_NUM,					/* [7] 10.5.20 A&C Reference Number */
	DE_AC_REF_NUM_H,				/* A&C Reference Number - Info is in the high nibble */
	DE_SRVC_TYPE,					/* [7] 10.5.20 Service Type */
	DE_CELL_NOT,					/* [7] 10.5.21 Cell Notification */
	DE_PS_LCS_CAP,					/* [7] 10.5.22 PS LCS Capability */
	DE_NET_FEAT_SUP,				/* [7] 10.5.23 Network Feature Support */
	DE_RAT_INFO_CONTAINER,			/* [7] 10.5.24 Inter RAT information container */
	/* [7] 10.5.25 Requested MS information */
	/* Session Management Information Elements [3] 10.5.6 */
	DE_ACC_POINT_NAME,				/* Access Point Name */
	DE_NET_SAPI,					/* Network Service Access Point Identifier */
	DE_PRO_CONF_OPT,				/* Protocol Configuration Options */
	DE_PD_PRO_ADDR,					/* Packet Data Protocol Address */
	DE_QOS,							/* Quality Of Service */
	DE_SM_CAUSE,					/* SM Cause */
	DE_LINKED_TI,					/* Linked TI */
	DE_LLC_SAPI,					/* LLC Service Access Point Identifier */
	DE_TEAR_DOWN_IND,				/* Tear Down Indicator */
	DE_PACKET_FLOW_ID,				/* Packet Flow Identifier */
	DE_TRAFFIC_FLOW_TEMPLATE,		/* Traffic Flow Template */
	/* GPRS Common Information Elements [8] 10.5.7 */
	DE_PDP_CONTEXT_STAT,			/* [8] 10.5.7.1		PDP Context Status */
	DE_RAD_PRIO,					/* [8] 10.5.7.2		Radio Priority */
	DE_GPRS_TIMER,					/* [8] 10.5.7.3		GPRS Timer */
	DE_GPRS_TIMER_2,				/* [8] 10.5.7.4		GPRS Timer 2 */
	DE_RAD_PRIO_2,					/* [8] 10.5.7.5		Radio Priority 2 */
	DE_MBMS_CTX_STATUS,				/* [8] 10.5.7.6		MBMS context status */
	DE_GM_NONE							/* NONE */
}
gm_elem_idx_t;

#endif /* __PACKET_GSM_A_COMMON_H__ */
