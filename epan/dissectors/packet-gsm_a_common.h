/* packet-gsm_a_common.h
 *
 * $Id$
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


/* PROTOTYPES/FORWARDS */
typedef guint8 (*elem_fcn)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
typedef void (*msg_fcn)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len);

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

extern gboolean lower_nibble;

/* common field values */
extern int hf_gsm_a_length;
extern int hf_gsm_a_extension;
extern int hf_gsm_a_tmsi;
extern int hf_gsm_a_L3_protocol_discriminator;
extern int hf_gsm_a_b8spare;

/* for the nasty hack below */
#define GSM_BSSMAP_APDU_IE	0x49

/* flags for the packet-gsm_a_common routines */
#define GSM_A_PDU_TYPE_BSSMAP	BSSAP_PDU_TYPE_BSSMAP /* i.e. 0 - until split complete at least! */
#define GSM_A_PDU_TYPE_DTAP		BSSAP_PDU_TYPE_DTAP   /* i.e. 1 - until split complete at least! */
#define GSM_A_PDU_TYPE_RP		2

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
#define UPPER_NIBBLE    (2)
#define LOWER_NIBBLE    (1)

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
    case BSSAP_PDU_TYPE_BSSMAP: \
	SEV_elem_names = gsm_bssmap_elem_strings; \
	SEV_elem_ett = ett_gsm_bssmap_elem; \
	SEV_elem_funcs = bssmap_elem_fcn; \
	break; \
    case BSSAP_PDU_TYPE_DTAP: \
	SEV_elem_names = gsm_dtap_elem_strings; \
	SEV_elem_ett = ett_gsm_dtap_elem; \
	SEV_elem_funcs = dtap_elem_fcn; \
	break; \
    case GSM_A_PDU_TYPE_RP: \
	SEV_elem_names = gsm_rp_elem_strings; \
	SEV_elem_ett = ett_gsm_rp_elem; \
	SEV_elem_funcs = rp_elem_fcn; \
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
		(EMT_pdu_type == BSSAP_PDU_TYPE_BSSMAP) ? \
		    gsm_bssmap_elem_strings[EMT_elem_idx].strptr : gsm_dtap_elem_strings[EMT_elem_idx].strptr, \
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
		(EMT_pdu_type == BSSAP_PDU_TYPE_BSSMAP) ? \
		    gsm_bssmap_elem_strings[EMT_elem_idx].strptr : gsm_dtap_elem_strings[EMT_elem_idx].strptr, \
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

#endif /* __PACKET_GSM_A_COMMON_H__ */
