/* packet-nas_5gs.c
* Routines for Non-Access-Stratum (NAS) protocol for Evolved Packet System (EPS) dissection
*
* Copyright 2018, Anders Broman <anders.broman@ericsson.com>
*
* Wireshark - Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998 Gerald Combs
*
* SPDX-License-Identifier: GPL-2.0-or-later
*
* References: 3GPP TS 24.501 0.4.0
*/

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

#include <wsutil/pow2.h>

#include "packet-gsm_a_common.h"

void proto_register_nas_5gs(void);
void proto_reg_handoff_nas_5gs(void);

static dissector_handle_t eap_handle = NULL;
static dissector_handle_t nas_eps_handle = NULL;
static dissector_handle_t nas_eps_plain_handle = NULL;

#define PNAME  "Non-Access-Stratum 5GS (NAS)PDU"
#define PSNAME "NAS-5GS"
#define PFNAME "nas-5gs"

static int proto_nas_5gs = -1;

int hf_nas_5gs_common_elem_id = -1;
int hf_nas_5gs_mm_elem_id = -1;
int hf_nas_5gs_sm_elem_id = -1;

static int hf_nas_5gs_epd = -1;
static int hf_nas_5gs_spare_b7 = -1;
static int hf_nas_5gs_spare_b6 = -1;
static int hf_nas_5gs_spare_b5 = -1;
static int hf_nas_5gs_spare_b4 = -1;
static int hf_nas_5gs_spare_b3 = -1;
static int hf_nas_5gs_spare_b2 = -1;
static int hf_nas_5gs_spare_b1 = -1;
static int hf_nas_5gs_security_header_type = -1;
static int hf_nas_5gs_mm_msg_type = -1;
static int hf_nas_5gs_sm_msg_type = -1;
static int hf_nas_5gs_proc_trans_id = -1;
static int hf_nas_5gs_spare_half_octet = -1;
static int hf_nas_5gs_pdu_session_id = -1;
static int hf_nas_5gs_msg_elems = -1;
static int hf_nas_5gs_mm_for = -1;
static int hf_nas_5gs_mm_5gs_reg_type = -1;
static int hf_nas_5gs_mm_tsc = -1;
static int hf_nas_5gs_mm_nas_key_set_id = -1;
static int hf_nas_5gs_mm_5gmm_cause = -1;
static int hf_nas_5gs_mm_pld_cont_type = -1;
static int hf_nas_5gs_mm_sst = -1;
static int hf_nas_5gs_mm_sd = -1;
static int hf_nas_5gs_mm_mapped_conf_sst = -1;
static int hf_nas_5gs_mm_mapped_conf_ssd = -1;
static int hf_nas_5gs_mm_switch_off = -1;
static int hf_nas_5gs_mm_re_reg_req = -1;
static int hf_nas_5gs_mm_acc_type = -1;
static int hf_nas_5gs_mm_dnn = -1;
static int hf_nas_5gs_mm_hash_amf = -1;
static int hf_nas_5gs_mm_raai_b0 = -1;
static int hf_nas_5gs_mm_conf_upd_ind_ack_b0 = -1;
static int hf_nas_5gs_mm_conf_upd_ind_red_b1 = -1;
static int hf_nas_5gs_mm_nas_sec_algo_enc = -1;
static int hf_nas_5gs_mm_nas_sec_algo_ip = -1;
static int hf_nas_5gs_mm_nonceamf = -1;
static int hf_nas_5gs_mm_s1_mode_b0 = -1;
static int hf_nas_5gs_mm_type_id = -1;
static int hf_nas_5gs_mm_odd_even = -1;
static int hf_nas_5gs_mm_length = -1;
static int hf_nas_5gs_mm_pdu_ses_id = -1;
static int hf_nas_5gs_mm_old_pdu_ses_id = -1;
static int hf_nas_5gs_mm_pld_cont = -1;
static int hf_nas_5gs_mm_all_acc_b1b0 = -1;
static int hf_nas_5gs_mm_sup_acc_b1b0 = -1;
static int hf_nas_5gs_mm_req_type = -1;
static int hf_nas_5gs_mm_serv_type = -1;
static int hf_nas_5gs_mm_5g_ea0 = -1;
static int hf_nas_5gs_mm_128_5g_ea1 = -1;
static int hf_nas_5gs_mm_128_5g_ea2 = -1;
static int hf_nas_5gs_mm_128_5g_ea3 = -1;
static int hf_nas_5gs_mm_5g_ea4 = -1;
static int hf_nas_5gs_mm_5g_ea5 = -1;
static int hf_nas_5gs_mm_5g_ea6 = -1;
static int hf_nas_5gs_mm_5g_ea7 = -1;
static int hf_nas_5gs_mm_5g_ia0 = -1;
static int hf_nas_5gs_mm_5g_128_ia1 = -1;
static int hf_nas_5gs_mm_5g_128_ia2 = -1;
static int hf_nas_5gs_mm_5g_128_ia3 = -1;
static int hf_nas_5gs_mm_5g_ia4 = -1;
static int hf_nas_5gs_mm_5g_ia5 = -1;
static int hf_nas_5gs_mm_5g_ia6 = -1;
static int hf_nas_5gs_mm_5g_ia7 = -1;
static int hf_nas_5gs_mm_eea0 = -1;
static int hf_nas_5gs_mm_128eea1 = -1;
static int hf_nas_5gs_mm_128eea2 = -1;
static int hf_nas_5gs_mm_eea3 = -1;
static int hf_nas_5gs_mm_eea4 = -1;
static int hf_nas_5gs_mm_eea5 = -1;
static int hf_nas_5gs_mm_eea6 = -1;
static int hf_nas_5gs_mm_eea7 = -1;
static int hf_nas_5gs_mm_eia0 = -1;
static int hf_nas_5gs_mm_128eia1 = -1;
static int hf_nas_5gs_mm_128eia2 = -1;
static int hf_nas_5gs_mm_eia3 = -1;
static int hf_nas_5gs_mm_eia4 = -1;
static int hf_nas_5gs_mm_eia5 = -1;
static int hf_nas_5gs_mm_eia6 = -1;
static int hf_nas_5gs_mm_eia7 = -1;
static int hf_nas_5gs_mm_s1_mode_reg_b0 = -1;

static int hf_nas_5gs_pdu_ses_sts_psi_7_b7 = -1;
static int hf_nas_5gs_pdu_ses_sts_psi_6_b6 = -1;
static int hf_nas_5gs_pdu_ses_sts_psi_5_b5 = -1;
static int hf_nas_5gs_pdu_ses_sts_psi_4_b4 = -1;
static int hf_nas_5gs_pdu_ses_sts_psi_3_b3 = -1;
static int hf_nas_5gs_pdu_ses_sts_psi_2_b2 = -1;
static int hf_nas_5gs_pdu_ses_sts_psi_1_b1 = -1;
static int hf_nas_5gs_pdu_ses_sts_psi_0_b0 = -1;

static int hf_nas_5gs_pdu_ses_sts_psi_15_b7 = -1;
static int hf_nas_5gs_pdu_ses_sts_psi_14_b6 = -1;
static int hf_nas_5gs_pdu_ses_sts_psi_13_b5 = -1;
static int hf_nas_5gs_pdu_ses_sts_psi_12_b4 = -1;
static int hf_nas_5gs_pdu_ses_sts_psi_11_b3 = -1;
static int hf_nas_5gs_pdu_ses_sts_psi_10_b2 = -1;
static int hf_nas_5gs_pdu_ses_sts_psi_9_b1 = -1;
static int hf_nas_5gs_pdu_ses_sts_psi_8_b0 = -1;

static int hf_nas_5gs_ul_data_sts_psi_7_b7 = -1;
static int hf_nas_5gs_ul_data_sts_psi_6_b6 = -1;
static int hf_nas_5gs_ul_data_sts_psi_5_b5 = -1;
static int hf_nas_5gs_ul_data_sts_psi_4_b4 = -1;
static int hf_nas_5gs_ul_data_sts_psi_3_b3 = -1;
static int hf_nas_5gs_ul_data_sts_psi_2_b2 = -1;
static int hf_nas_5gs_ul_data_sts_psi_1_b1 = -1;
static int hf_nas_5gs_ul_data_sts_psi_0_b0 = -1;

static int hf_nas_5gs_ul_data_sts_psi_15_b7 = -1;
static int hf_nas_5gs_ul_data_sts_psi_14_b6 = -1;
static int hf_nas_5gs_ul_data_sts_psi_13_b5 = -1;
static int hf_nas_5gs_ul_data_sts_psi_12_b4 = -1;
static int hf_nas_5gs_ul_data_sts_psi_11_b3 = -1;
static int hf_nas_5gs_ul_data_sts_psi_10_b2 = -1;
static int hf_nas_5gs_ul_data_sts_psi_9_b1 = -1;
static int hf_nas_5gs_ul_data_sts_psi_8_b0 = -1;

static int hf_nas_5gs_sm_pdu_session_type = -1;
static int hf_nas_5gs_sm_sc_mode = -1;
static int hf_nas_5gs_sm_rqos_b0 = -1;
static int hf_nas_5gs_sm_5gsm_cause = -1;
static int hf_nas_5gs_sm_pdu_ses_type = -1;
static int hf_nas_5gs_sm_pdu_addr_inf_ipv4 = -1;
static int hf_nas_5gs_sm_pdu_addr_inf_ipv6 = -1;
static int hf_nas_5gs_sm_qos_rule_id = -1;
static int hf_nas_5gs_sm_length = -1;
static int hf_nas_5gs_sm_rop = -1;
static int hf_nas_5gs_sm_dqr = -1;
static int hf_nas_5gs_sm_nof_pkt_filters = -1;
static int hf_nas_5gs_sm_pkt_flt_id = -1;
static int hf_nas_5gs_sm_pkt_flt_dir = -1;
static int hf_nas_5gs_sm_pf_len = -1;
static int hf_nas_5gs_sm_pf_type = -1;

static int nas_5gs_sm_unit_for_session_ambr_dl = -1;
static int hf_nas_5gs_sm_session_ambr_dl = -1;
static int nas_5gs_sm_unit_for_session_ambr_ul = -1;
static int hf_nas_5gs_sm_session_ambr_ul = -1;

static int ett_nas_5gs = -1;
static int ett_nas_5gs_mm_nssai = -1;
static int ett_nas_5gs_mm_pdu_ses_id = -1;
static int ett_nas_5gs_sm_qos_rules = -1;

static expert_field ei_nas_5gs_extraneous_data = EI_INIT;
static expert_field ei_nas_5gs_unknown_pd = EI_INIT;
static expert_field ei_nas_5gs_mm_unknown_msg_type = EI_INIT;
static expert_field ei_nas_5gs_sm_unknown_msg_type = EI_INIT;
static expert_field ei_nas_5gs_msg_not_dis = EI_INIT;
static expert_field ei_nas_5gs_ie_not_dis = EI_INIT;
static expert_field ei_nas_5gs_missing_mandatory_elemen = EI_INIT;
static expert_field ei_nas_5gs_dnn_too_long = EI_INIT;
static expert_field ei_nas_5gs_unknown_value = EI_INIT;
static expert_field ei_nas_5gs_num_pkt_flt = EI_INIT;
static expert_field ei_nas_5gs_not_diss = EI_INIT;


static guint16 de_nas_5gs_mm_s_nssai(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_);

static const value_string nas_5gs_security_header_type_vals[] = {
    { 0,    "Plain NAS message, not security protected"},
    { 1,    "Integrity protected"},
    { 2,    "Integrity protected and ciphered"},
    { 3,    "Integrity protected with new 5GS security context"},
    { 4,    "Integrity protected and ciphered with new 5GS security context"},
    { 0,    NULL }
};


#define TGPP_PD_5GMM 0x7e
#define TGPP_PD_5GSM 0x2e

static const value_string nas_5gs_epd_vals[] = {
    { 0x00,              "Group call control" },
    { 0x01,              "Broadcast call control" },
    { 0x02,              "EPS session management messages" },
    { 0x03,              "Call Control; call related SS messages" },
    { 0x04,              "GPRS Transparent Transport Protocol (GTTP)" },
    { 0x05,              "Mobility Management messages" },
    { 0x06,              "Radio Resources Management messages" },
    { 0x07,              "EPS mobility management messages" },
    { 0x08,              "GPRS mobility management messages" },
    { 0x09,              "SMS messages" },
    { 0x0a,              "GPRS session management messages" },
    { 0x0b,              "Non call related SS messages" },
    { 0x0c,              "Location services specified in 3GPP TS 44.071" },
    { 0x0d,              "Unknown" },
    /*{0x0e,            "Reserved for extension of the PD to one octet length "},*/
    { 0x0f,              "Tests procedures described in 3GPP TS 44.014, 3GPP TS 34.109 and 3GPP TS 36.509" },
    { TGPP_PD_5GSM,      "5G session management messages" },
    { TGPP_PD_5GMM,      "5G mobility management messages" },
    { 0,    NULL }
};


/*
 * 9.8.2    Common information elements
 */
 /*
  * 9.8.2.1    Additional information
  */
static guint16
de_nas_5gs_cmn_add_inf(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 * 9.8.2.2    PDU session status
 */

static true_false_string tfs_nas_5gs_pdu_ses_sts_psi = {
    "Not PDU SESSION INACTIVE",
    "PDU SESSION INACTIVE"
};



static guint16
de_nas_5gs_pdu_ses_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    int curr_offset;

    static const int * psi_0_7_flags[] = {
        &hf_nas_5gs_pdu_ses_sts_psi_7_b7,
        &hf_nas_5gs_pdu_ses_sts_psi_6_b6,
        &hf_nas_5gs_pdu_ses_sts_psi_5_b5,
        &hf_nas_5gs_pdu_ses_sts_psi_4_b4,
        &hf_nas_5gs_pdu_ses_sts_psi_3_b3,
        &hf_nas_5gs_pdu_ses_sts_psi_2_b2,
        &hf_nas_5gs_pdu_ses_sts_psi_1_b1,
        &hf_nas_5gs_pdu_ses_sts_psi_0_b0,
        NULL
    };

    static const int * psi_8_15_flags[] = {
        &hf_nas_5gs_pdu_ses_sts_psi_15_b7,
        &hf_nas_5gs_pdu_ses_sts_psi_14_b6,
        &hf_nas_5gs_pdu_ses_sts_psi_13_b5,
        &hf_nas_5gs_pdu_ses_sts_psi_12_b4,
        &hf_nas_5gs_pdu_ses_sts_psi_11_b3,
        &hf_nas_5gs_pdu_ses_sts_psi_10_b2,
        &hf_nas_5gs_pdu_ses_sts_psi_9_b1,
        &hf_nas_5gs_pdu_ses_sts_psi_8_b0,
        NULL
    };

    curr_offset = offset;
    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, psi_0_7_flags, ENC_BIG_ENDIAN);
    curr_offset++;

    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, psi_8_15_flags, ENC_BIG_ENDIAN);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_nas_5gs_extraneous_data);

    return (curr_offset - offset);

}

/*
 * 9.8.2.3    Uplink data status
 */
static true_false_string tfs_nas_5gs_ul_data_sts_psi = {
    "uplink data are pending ",
    "no uplink data are pending"
};

static guint16
de_nas_5gs_ul_data_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    int curr_offset;

    static const int * psi_0_7_flags[] = {
        &hf_nas_5gs_ul_data_sts_psi_7_b7,
        &hf_nas_5gs_ul_data_sts_psi_6_b6,
        &hf_nas_5gs_ul_data_sts_psi_5_b5,
        &hf_nas_5gs_ul_data_sts_psi_4_b4,
        &hf_nas_5gs_ul_data_sts_psi_3_b3,
        &hf_nas_5gs_ul_data_sts_psi_2_b2,
        &hf_nas_5gs_ul_data_sts_psi_1_b1,
        &hf_nas_5gs_ul_data_sts_psi_0_b0,
        NULL
    };

    static const int * psi_8_15_flags[] = {
        &hf_nas_5gs_ul_data_sts_psi_15_b7,
        &hf_nas_5gs_ul_data_sts_psi_14_b6,
        &hf_nas_5gs_ul_data_sts_psi_13_b5,
        &hf_nas_5gs_ul_data_sts_psi_12_b4,
        &hf_nas_5gs_ul_data_sts_psi_11_b3,
        &hf_nas_5gs_ul_data_sts_psi_10_b2,
        &hf_nas_5gs_ul_data_sts_psi_9_b1,
        &hf_nas_5gs_ul_data_sts_psi_8_b0,
        NULL
    };

    curr_offset = offset;
    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, psi_0_7_flags, ENC_BIG_ENDIAN);
    curr_offset++;

    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, psi_8_15_flags, ENC_BIG_ENDIAN);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_nas_5gs_extraneous_data);

    return (curr_offset - offset);

    return len;
}


/*
 * 9.8.3    5GS mobility management (5GMM) information elements
 */

 /*
  * 9.8.3.1    5GMM capability
  */
static guint16
de_nas_5gs_mm_5gmm_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    guint32 offset, guint len _U_,
    gchar *add_string _U_, int string_len _U_)
{
    static const int * flags[] = {
        &hf_nas_5gs_spare_b7,
        &hf_nas_5gs_spare_b6,
        &hf_nas_5gs_spare_b5,
        &hf_nas_5gs_spare_b4,
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_spare_b1,
        &hf_nas_5gs_mm_s1_mode_b0,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return 1;
}

/*
 * 9.8.3.2    5GMM cause
 */

static const value_string nas_5gs_mm_cause_vals[] = {
    { 0x03, "Illegal UE" },
    { 0x05, "PEI not accepted" },
    { 0x06, "Illegal ME" },
    { 0x07, "5GS services not allowed" },
    { 0x0a, "Implicitly deregistered" },
    { 0x0b, "PLMN not allowed" },
    { 0x0c, "Tracking area not allowed" },
    { 0x0e, "Roaming not allowed in this tracking area" },
    { 0x15, "Synch failure" },
    { 0x1b, "N1 mode not allowed" },
    { 0x5f, "Semantically incorrect message" },
    { 0x60, "Invalid mandatory information" },
    { 0x61, "Message type non-existent or not implemented" },
    { 0x62, "Message type not compatible with the protocol state" },
    { 0x63, "Information element non-existent or not implemented" },
    { 0x64, "Conditional IE error" },
    { 0x65, "Message not compatible with the protocol state" },
    { 0x6f, "Protocol error, unspecified" },
    { 0,    NULL }
};

static guint16
de_nas_5gs_mm_5gmm_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len _U_,
    gchar *add_string _U_, int string_len _U_)
{
    guint32 cause;

    proto_tree_add_item_ret_uint(tree, hf_nas_5gs_mm_5gmm_cause, tvb, offset, 1, ENC_BIG_ENDIAN, &cause);

    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
        val_to_str_const(cause, nas_5gs_mm_cause_vals, "Unknown"));


    return 1;
}

/*
 * 9.8.3.3    5GS mobile identity
 */
static const value_string nas_5gs_mm_type_id_vals[] = {
    { 0x1, "SUCI" },
    { 0x3, "IMEI" },
    { 0x4, "5G-TMSI" },
    { 0x6, "5G-GUTI" },
    { 0, NULL }
 };

static true_false_string nas_5gs_odd_even_tfs = {
    "Odd number of identity digits",
    "Even number of identity digits"
};

static guint16
de_nas_5gs_mm_5gs_mobile_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    /*guint32 type_id;*/

    /*proto_tree_add_item_ret_uint(tree, hf_nas_5gs_mm_type_id, tvb, offset, 1, ENC_BIG_ENDIAN, &type_id);*/
    proto_tree_add_item(tree, hf_nas_5gs_mm_type_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_5gs_mm_odd_even, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len -1);

    return len;
}

/*
 * 9.8.3.4    5GS network feature support
 */
static guint16
de_nas_5gs_mm_5gs_nw_feat_sup(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    /* The definition of 5GS network feature support is FFS, but should include a dual-registration supported indication.*/
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 * 9.8.3.5    5GS registration result
 */
static guint16
de_nas_5gs_mm_5gs_reg_res(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len _U_,
    gchar *add_string _U_, int string_len _U_)
{
    /* The definition of 5GS registration result is FFS. Use lemgth = 1*/
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, 1);

    return 1;
}

/*
 * 9.8.3.6    5GS registration type
 */

static const value_string nas_5gs_registration_type_values[] = {
    { 0x1, "initial registration" },
    { 0x2, "mobility registration updating" },
    { 0x3, "periodic registration updating" },
    { 0x4, "unused(initial registration)" },
    { 0x5, "unused(initial registration)" },
    { 0x6, "5GS emergency registration" },
    { 0x7, "reserved" },
    { 0, NULL }
 };

static true_false_string nas_5gs_for_tfs = {
    "Follow-on request pending",
    "No follow-on request pending"
};

static guint16
de_nas_5gs_mm_5gs_reg_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    guint32 offset, guint len _U_,
    gchar *add_string _U_, int string_len _U_)
{

    proto_tree_add_item(tree, hf_nas_5gs_mm_for, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_5gs_mm_5gs_reg_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 1;
}

/*
 *  9.8.3.7    Allowed PDU session status
 */
static guint16
de_nas_5gs_mm_allow_pdu_ses_sts(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 *  9.8.3.8    Authentication parameter AUTN
 */
/* See subclause 10.5.3.1 in 3GPP TS 24.008 [8].*/

/*
 *   9.8.3.9    Authentication parameter RAND
 */

/* See subclause 10.5.3.1 in 3GPP TS 24.008 [8]. */

/*
 *   9.8.3.10    Configuration update indication
 */
static guint16
de_nas_5gs_mm_conf_upd_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    guint32 offset, guint len _U_,
    gchar *add_string _U_, int string_len _U_)
{

    static const int * flags[] = {
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_mm_conf_upd_ind_red_b1,
        &hf_nas_5gs_mm_conf_upd_ind_ack_b0,
        NULL
    };


    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return 1;
}

/*
 *   9.8.3.11    Daylight saving time
 */
/* See subclause 10.5.3.12 in 3GPP TS 24.008 */

/*
 *   9.8.3.12    De-registration type
 */
static const true_false_string nas_5gs_mm_switch_off_tfs = {
    "Switch off",
    "Normal detach"
};

static const true_false_string nas_5gs_mm_re_reg_req_tfs = {
    "re-registration required",
    "re-registration not required"
};

static const value_string nas_5gs_mm_acc_type_vals[] = {
    { 0x1, "3GPP access"},
    { 0x2, "Non-3GPP access"},
    { 0x3, "3GPP access and non-3GPP access"},
    {   0, NULL }
};

static guint16
de_nas_5gs_mm_de_reg_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len _U_,
    gchar *add_string _U_, int string_len _U_)
{
    /* Switch off   Re-registration required    Access type */
    proto_tree_add_item(tree, hf_nas_5gs_mm_switch_off, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_5gs_mm_re_reg_req, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_5gs_mm_acc_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, 1);

    return 1;
}

/*
 *   9.8.3.13    DNN
 */
static guint16
de_nas_5gs_mm_dnn(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    guint32     curr_offset;
    guint       curr_len;
    guint8     *str;
    proto_item *pi;

    curr_offset = offset;
    /* A DNN value field contains an APN as defined in 3GPP TS 23.003 */

    str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, len, ENC_ASCII | ENC_NA);

    curr_len = 0;
    while (curr_len < len)
    {
        guint step = str[curr_len];
        str[curr_len] = '.';
        curr_len += step + 1;
    }

    /* Highlight bytes including the first length byte */
    pi = proto_tree_add_string(tree, hf_nas_5gs_mm_dnn, tvb, curr_offset, len, str + 1);
    if (len > 100) {
        expert_add_info(pinfo, pi, &ei_nas_5gs_dnn_too_long);
    }
    curr_offset += len;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_nas_5gs_extraneous_data);

    return (curr_offset - offset);

}

/*
 *   9.8.3.14    EAP message
 */
static guint16
de_nas_5gs_mm_eap_msg(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    /* EAP message as specified in IETF RFC 3748 */
    if (eap_handle) {
        col_append_str(pinfo->cinfo, COL_PROTOCOL, "/");
        col_set_fence(pinfo->cinfo, COL_PROTOCOL);
        call_dissector(eap_handle, tvb_new_subset_length(tvb, offset, len), pinfo, tree);
    }

    return len;
}

/*
 *   9.8.3.15    EPS NAS message container
 */
static guint16
de_nas_5gs_mm_eps_nas_msg_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    /* an EPS NAS message as specified in 3GPP TS 24.301 */
    if (nas_eps_handle) {
        col_append_str(pinfo->cinfo, COL_PROTOCOL, "/");
        col_set_fence(pinfo->cinfo, COL_PROTOCOL);
        call_dissector(eap_handle, tvb_new_subset_length(tvb, offset, len), pinfo, tree);
    }

    return len;
}

/*
 *   9.8.3.16    GPRS timer 2
 */
/* See subclause 10.5.7.4 in 3GPP TS 24.008 */

/*
 *   9.8.3.17    HashAMF
 */
static guint16
de_nas_5gs_mm_hashamf(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    guint32     curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_nas_5gs_mm_hash_amf, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    curr_offset += len;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_nas_5gs_extraneous_data);

    return len;
}

/*
 *   9.8.3.18    IMEISV request
 */
/* See subclause 10.5.5.10 in 3GPP TS 24.008 */

/*
 *   9.8.3.19    LADN information
 */

static guint16
de_nas_5gs_mm_ladn_inf(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 *   9.8.3.20    Message authentication code
 */
static guint16
de_nas_5gs_mm_msg_auth_code(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 *   9.8.3.21    MICO indication
 */
static const true_false_string tfs_nas_5gs_raai = {
    "all PLMN registration area allocated",
    "all PLMN registration area not allocated"
};


static guint16
de_nas_5gs_mm_mico_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    guint32 offset, guint len _U_,
    gchar *add_string _U_, int string_len _U_)
{
    static const int * flags[] = {
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_spare_b1,
        &hf_nas_5gs_mm_raai_b0,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return 1;
}

static const true_false_string nas_5gs_mm_tsc_tfs = {
    "Mapped security context (for KSIASME)",
    "Native security context (for KSIAMF)"
};

/*
 *   9.8.3.22    NAS key set identifier
 */
static guint16
de_nas_5gs_mm_nas_key_set_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    guint32 offset, guint len _U_,
    gchar *add_string _U_, int string_len _U_)
{

    /* NAS key set identifier IEI   TSC     NAS key set identifier */
    proto_tree_add_item(tree, hf_nas_5gs_mm_tsc, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_5gs_mm_nas_key_set_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 1;
}

/*
 *   9.8.3.23    NAS message container
 */
static guint16
de_nas_5gs_mm_nas_msg_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    /* a NAS message without NAS security heade */
    if (nas_eps_plain_handle) {
        col_append_str(pinfo->cinfo, COL_PROTOCOL, "/");
        col_set_fence(pinfo->cinfo, COL_PROTOCOL);
        call_dissector(nas_eps_plain_handle, tvb_new_subset_length(tvb, offset, len), pinfo, tree);
    }

    return len;
}

/*
 *   9.8.3.24    NAS security algorithms
 */

static const value_string nas_5gs_mm_type_of_ip_algo_vals[] = {
    { 0x0, "5G-IA0 (null integrity protection algorithm)"},
    { 0x1, "128-5G-IA1"},
    { 0x2, "128-5G-IA2"},
    { 0x3, "128-5G-IA3"},
    { 0x4, "5G-IA4"},
    { 0x5, "5G-IA5"},
    { 0x6, "5G-IA6"},
    { 0x7, "5G-IA7"},
    {   0, NULL }
};

static const value_string nas_5gs_mm_type_of_enc_algo_vals[] = {
    { 0x0, "5G-EA0 (null ciphering algorithm)"},
    { 0x1, "128-5G-EA1"},
    { 0x2, "128-5G-EA2"},
    { 0x3, "128-5G-EA3"},
    { 0x4, "5G-EA4"},
    { 0x5, "5G-EA5"},
    { 0x6, "5G-EA6"},
    { 0x7, "5G-EA7"},
    {   0, NULL }
};

static guint16
de_nas_5gs_mm_nas_sec_algo(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    guint32 offset, guint len _U_,
    gchar *add_string _U_, int string_len _U_)
{

    proto_tree_add_item(tree, hf_nas_5gs_mm_nas_sec_algo_enc, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_5gs_mm_nas_sec_algo_ip, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 1;
}

/*
 *   9.8.3.25    NAS security parameters to NG-RAN
 */
static guint16
de_nas_5gs_mm_nas_sec_par_ng_ran(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;
    /* NonceAMF value (octet 2 to 5)
    * This field is coded as the nonce value in the Nonce information element (see subclause 9.8.3.27).
    */
    proto_tree_add_item(tree, hf_nas_5gs_mm_nonceamf, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* Type of ciphering algorithm    Type of integrity protection algorithm*/
    proto_tree_add_item(tree, hf_nas_5gs_mm_nas_sec_algo_enc, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_5gs_mm_nas_sec_algo_ip, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* 0    0    0    0    TSC    NAS key set identifier */
    proto_tree_add_item(tree, hf_nas_5gs_mm_tsc, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_5gs_mm_nas_key_set_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    curr_offset += len;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_nas_5gs_extraneous_data);

    return len;
}

/*
 *   9.8.3.26    Network name
 */
/* See subclause 10.5.3.5a in 3GPP TS 24.008 */

/*
 *   9.8.3.27    Nonce
 */
/* See subclause 9.9.3.25 in 3GPP TS 24.301 [10].*/

/*
 *   9.8.3.28    NSSAI
 */
static guint16
de_nas_5gs_mm_nssai(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree *sub_tree;
    proto_item *item;
    int i = 1;
    gint32 length;
    guint32 curr_offset;

    curr_offset = offset;

    while ((curr_offset - offset) < len) {

        sub_tree = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nas_5gs_mm_nssai, &item, "S-NSSAI %u", i);

        proto_tree_add_item_ret_int(sub_tree, hf_nas_5gs_mm_length, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &length);

        curr_offset += de_nas_5gs_mm_s_nssai(tvb, sub_tree, pinfo, curr_offset, length, NULL, 0);
        proto_item_set_len(item, length + 1);
        i++;

    }

    return len;
}

/*
 *   9.8.3.29    NSSAI info for PDU sessions
 */
static guint16
de_nas_5gs_mm_nssai_inf_for_pdu_ses(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree *sub_tree, *sub_tree2;
    proto_item *item;
    int i = 1;
    gint32 length;
    guint32 curr_offset;

    curr_offset = offset;

    while ((curr_offset - offset) < len) {

        sub_tree2 = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nas_5gs_mm_pdu_ses_id, NULL, "PDU session identity %u", i);
        proto_tree_add_item(sub_tree2, hf_nas_5gs_mm_pdu_ses_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset++;

        sub_tree = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nas_5gs_mm_nssai, &item, "S-NSSAI %u", i);

        proto_tree_add_item_ret_int(sub_tree, hf_nas_5gs_mm_length, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &length);

        curr_offset += de_nas_5gs_mm_s_nssai(tvb, sub_tree, pinfo, curr_offset, length, NULL, 0);
        proto_item_set_len(item, length + 1);
        i++;

    }

    return len;
}

/*
 *   9.8.3.30    Payload container
 */
static guint16
de_nas_5gs_mm_pld_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_item(tree, hf_nas_5gs_mm_pld_cont, tvb, offset, len, ENC_NA);

    return len;
}

/*
 *   9.8.3.31    Payload container type
 */
static const value_string nas_5gs_mm_pld_cont_type_vals[] = {
    { 0x01, "N1 SM information" },
    { 0x02, "SMS" },
    { 0x03, "LTE Positioning Protocol (LPP) message container" },
    {    0, NULL } };

static guint16
de_nas_5gs_mm_pld_cont_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    guint32 offset, guint len _U_,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_item(tree, hf_nas_5gs_mm_pld_cont_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 1;
}

/*
 *   9.8.3.32    PDU session reactivation result
 */
static guint16
de_nas_5gs_mm_pdu_ses_react_res(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 *   9.8.3.33    PLMN list
 */
/* See subclause 10.5.1.13 in 3GPP TS 24.008 */

/*
 *   9.8.3.34    Old PDU session identity
 */
static guint16
de_nas_5gs_mm_old_pdu_ses_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    guint32 offset, guint len _U_,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_item(tree, hf_nas_5gs_mm_old_pdu_ses_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 1;
}

/*
 *   9.8.3.35    Rejected NSSAI
 */
static guint16
de_nas_5gs_mm_rej_nssai(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 *    9.8.3.36    S1 UE network capability
 */
/* See subclause 9.9.3.34 in 3GPP TS 24.301 */

/*
 *    9.8.3.37    S-NSSAI
 */
static guint16
de_nas_5gs_mm_s_nssai(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    /* SST    octet 3
     * This field contains the 8 bit SST value. The coding of the SST value part is defined in 3GPP TS 23.003
     */
    proto_tree_add_item(tree, hf_nas_5gs_mm_sst, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (len == 1) {
        return len;
    }
    offset += 1;
    /* SD    octet 4 - octet 6* */
    proto_tree_add_item(tree, hf_nas_5gs_mm_sd, tvb, offset, 3, ENC_BIG_ENDIAN);
    if (len == 4) {
        return len;
    }
    offset += 3;
    /* Mapped configured SST    octet 7* */
    proto_tree_add_item(tree, hf_nas_5gs_mm_mapped_conf_sst, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (len == 5) {
        return len;
    }
    offset += 1;
    /* Mapped configured SD    octet 8 - octet 10* */
    proto_tree_add_item(tree, hf_nas_5gs_mm_mapped_conf_ssd, tvb, offset, 3, ENC_BIG_ENDIAN);

    return len;
}

/*
 *    9.8.3.38    Sequence number
 */

static guint16
de_nas_5gs_mm_seq_no(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 *     9.8.3.39    Service area list
 */

static guint16
de_nas_5gs_mm_sal(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 *     9.8.3.40    SMS allowed
 */

static const value_string nas_5gs_mm_all_acc_vals[] = {
    { 0x00, "SMS over NAS not allowed" },
    { 0x01, "SMS over NAS allowed via 3GPP access only" },
    { 0x02, "SMS over NAS allowed via both 3GPP access and non-3GPP access" },
    { 0x03, "reserved" },
    {    0, NULL } };

static guint16
de_nas_5gs_mm_sms_all(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    guint32 offset, guint len _U_,
    gchar *add_string _U_, int string_len _U_)
{

    static const int * flags[] = {
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_mm_all_acc_b1b0,
        NULL
    };


    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return 1;
}

/*
 *     9.8.3.41    SMS requested
 */

static const value_string nas_5gs_mm_sup_acc_vals[] = {
    { 0x00, "SMS over NAS not supported" },
    { 0x01, "SMS over NAS supported via 3GPP access only" },
    { 0x02, "SMS over NAS supported via both 3GPP access and non-3GPP access" },
    { 0x03, "Reserved" },
    {    0, NULL } };

static guint16
de_nas_5gs_mm_sms_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    guint32 offset, guint len _U_,
    gchar *add_string _U_, int string_len _U_)
{

    static const int * flags[] = {
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_mm_sup_acc_b1b0,
        NULL
    };


    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return 1;
}


/*
 *     9.8.3.42    Request type
 */
static const value_string nas_5gs_mm_req_type_vals[] = {
    { 0x01, "Initial request" },
    { 0x02, "Existing PDU session" },
    { 0x03, "Initial emergency request" },
    { 0x04, "Existing emergency PDU session" },
    {    0, NULL } };

static guint16
de_nas_5gs_mm_req_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    guint32 offset, guint len _U_,
    gchar *add_string _U_, int string_len _U_)
{

    proto_tree_add_item(tree, hf_nas_5gs_mm_req_type, tvb, offset, 3, ENC_BIG_ENDIAN);

    return 1;
}

/*
 *     9.8.3.43    Service type
 */

static const value_string nas_5gs_mm_serv_type_vals[] = {
    { 0x00, "Signalling" },
    { 0x01, "Data" },
    { 0x02, "Paging response" },
    { 0x03, "Reserved" },
    { 0x04, "Emergency services fallback" },
    {    0, NULL } };

static guint16
de_nas_5gs_mm_serv_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    guint32 offset, guint len _U_,
    gchar *add_string _U_, int string_len _U_)
{
    static const int * flags[] = {
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_mm_serv_type,
        NULL
    };


    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return 1;
}

/*
 *     9.8.3.44    Tracking area identity
 */
/* See subclause 9.9.3.32 in 3GPP TS 24.301 */

/*
 *     9.8.3.45    Tracking area identity list
 */
/* See subclause 9.9.3.33 in 3GPP TS 24.301 */

/*
 *     9.8.3.46    Time zone
 */
/* See subclause 10.5.3.8 in 3GPP TS 24.008 */

/*
 *     9.8.3.47    Time zone and time
 */
/* See subclause 10.5.3.9 in 3GPP TS 24.00*/

/*
 *     9.8.3.48    UE security capability
 */

static guint16
de_nas_5gs_mm_ue_sec_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    static const int * oct3_flags[] = {
        &hf_nas_5gs_mm_5g_ea0,
        &hf_nas_5gs_mm_128_5g_ea1,
        &hf_nas_5gs_mm_128_5g_ea2,
        &hf_nas_5gs_mm_128_5g_ea3,
        &hf_nas_5gs_mm_5g_ea4,
        &hf_nas_5gs_mm_5g_ea5,
        &hf_nas_5gs_mm_5g_ea6,
        &hf_nas_5gs_mm_5g_ea7,
        NULL
    };

    static const int * oct4_flags[] = {
        &hf_nas_5gs_mm_5g_ia0,
        &hf_nas_5gs_mm_5g_128_ia1,
        &hf_nas_5gs_mm_5g_128_ia2,
        &hf_nas_5gs_mm_5g_128_ia3,
        &hf_nas_5gs_mm_5g_ia4,
        &hf_nas_5gs_mm_5g_ia5,
        &hf_nas_5gs_mm_5g_ia6,
        &hf_nas_5gs_mm_5g_ia7,
        NULL
    };

    static const int * oct5_flags[] = {
        &hf_nas_5gs_mm_eea0,
        &hf_nas_5gs_mm_128eea1,
        &hf_nas_5gs_mm_128eea2,
        &hf_nas_5gs_mm_eea3,
        &hf_nas_5gs_mm_eea4,
        &hf_nas_5gs_mm_eea5,
        &hf_nas_5gs_mm_eea6,
        &hf_nas_5gs_mm_eea7,
        NULL
    };

    static const int * oct6_flags[] = {
        &hf_nas_5gs_mm_eia0,
        &hf_nas_5gs_mm_128eia1,
        &hf_nas_5gs_mm_128eia2,
        &hf_nas_5gs_mm_eia3,
        &hf_nas_5gs_mm_eia4,
        &hf_nas_5gs_mm_eia5,
        &hf_nas_5gs_mm_eia6,
        &hf_nas_5gs_mm_eia7,
        NULL
    };

    curr_offset = offset;


    /* 5G-EA0    128-5G-EA1    128-5G-EA2    128-5G-EA3    5G-EA4    5G-EA5    5G-EA6    5G-EA7    octet 3 */
    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, oct3_flags, ENC_NA);
    curr_offset++;

    /* 5G-IA0    128-5G-IA1    128-5G-IA2    128-5G-IA3    5G-IA4    5G-IA5    5G-IA6    5G-IA7 octet 4 */
    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, oct4_flags, ENC_NA);
    curr_offset++;

    if (len == 4) {
        return len;
    }

    /* EEA0    128-EEA1    128-EEA2    128-EEA3    EEA4    EEA5    EEA6    EEA7 octet 5 */
    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, oct5_flags, ENC_NA);
    curr_offset++;

    /* EIA0    128-EIA1    128-EIA2    128-EIA3    EIA4    EIA5    EIA6    EIA7 octet 6 */
    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, oct6_flags, ENC_NA);


    return len;
}

/*
 *     9.8.3.49    UE status
 */

static true_false_string tfs_nas_5gs_mm_s1_mod = {
    "UE is in EMM-REGISTERED state",
    "UE is not in EMM-REGISTERED state"
};



static guint16
de_nas_5gs_mm_ue_sts(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    guint32 offset, guint len _U_,
    gchar *add_string _U_, int string_len _U_)
{
    static const int * flags[] = {
        &hf_nas_5gs_spare_b7,
        &hf_nas_5gs_spare_b6,
        &hf_nas_5gs_spare_b5,
        &hf_nas_5gs_spare_b4,
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_spare_b1,
        &hf_nas_5gs_mm_s1_mode_reg_b0,
        NULL
    };

    /* 0 Spare    0 Spare    0 Spare    0 Spare    0 Spare    0 Spare    0 Spare    S1 mode reg
*/
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return 1;
}

/*
 * 9.8.4    5GS session management (5GSM) information elements
 */

/*
 *     9.8.4.1    5GSM cause
 */

static const value_string nas_5gs_sm_cause_vals[] = {
    { 0x1d, "User authentication failed" },
    { 0x1f, "Request rejected, unspecified" },
    { 0x22, "Service option temporarily out of order" },
    { 0x24, "Regular deactivation" },
    { 0x27, "Reactivation requested" },
    { 0x32, "PDU session type Ipv4 only allowed" },
    { 0x33, "PDU session type Ipv6 only allowed" },
    { 0x5f, "Semantically incorrect message" },
    { 0x60, "Invalid mandatory information" },
    { 0x61, "Message type non - existent or not implemented" },
    { 0x62, "Message type not compatible with the protocol state" },
    { 0x63, "Information element non - existent or not implemented" },
    { 0x64, "Conditional IE error" },
    { 0x65, "Message not compatible with the protocol state" },
    { 0x6f, "Protocol error, unspecified" },
    { 0,    NULL }
};

static guint16
de_nas_5gs_sm_5gsm_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len _U_,
    gchar *add_string _U_, int string_len _U_)
{
    guint32 cause;

    proto_tree_add_item_ret_uint(tree, hf_nas_5gs_sm_5gsm_cause, tvb, offset, 1, ENC_BIG_ENDIAN, &cause);

    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
        val_to_str_const(cause, nas_5gs_sm_cause_vals, "Unknown"));


    return 1;
}

/*
 *     9.8.4.2    Extended protocol configuration options
 */
/* See subclause 10.5.6.3A in 3GPP TS 24.008 */


/*
 *     9.8.4.3    GPRS timer
 */

/* See subclause 10.5.7.3 in 3GPP TS 24.008 */

/*
 *     9.8.4.4    PDU address
 */

static const value_string nas_5gs_sm_pdu_ses_type_vals[] = {
    { 0x2, "IPv4" },
    { 0x3, "IPv6" },
    { 0,    NULL }
};


static guint16
de_nas_5gs_sm_pdu_address(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_item *ti;
    guint32 value;

    /* 0 Spare    0 Spare    0 Spare    0 Spare    PDU session type value */
    ti = proto_tree_add_item_ret_uint(tree, hf_nas_5gs_sm_pdu_ses_type, tvb, offset, 1, ENC_BIG_ENDIAN, &value);
    offset++;

    /* PDU address information */
    switch (value) {
    case 2:
        /* IPv4 */
        proto_tree_add_item(tree, hf_nas_5gs_sm_pdu_addr_inf_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        break;
    case 3:
        /* IPv6 */
        proto_tree_add_item(tree, hf_nas_5gs_sm_pdu_addr_inf_ipv6, tvb, offset, 16, ENC_NA);
        break;
    default:
        expert_add_info(pinfo, ti, &ei_nas_5gs_unknown_value);
        break;
    }
    return len;
}

/*
 *     9.8.4.5    PDU session type
 */
static const value_string nas_5gs_pdu_session_type_values[] = {
    { 0x1, "IP" },
    { 0x2, "Ipv4" },
    { 0x3, "Ipv6" },
    { 0x4, "Unstructured" },
    { 0x5, "Ethernet" },
    { 0, NULL }
 };


static guint16
de_nas_5gs_sm_pdu_session_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    guint32 offset, guint len _U_,
    gchar *add_string _U_, int string_len _U_)
{

    proto_tree_add_item(tree, hf_nas_5gs_sm_pdu_session_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 1;
}


/*
 *     9.8.4.6    QoS rules
 */

static true_false_string tfs_nas_5gs_sm_dqr = {
    "The QoS rule is the default QoS rule",
    "The QoS rule is not the default QoS rule"
};

static const value_string nas_5gs_rule_operation_code_values[] = {
    { 0x0, "Reserved" },
    { 0x1, "Create new QoS rule" },
    { 0x2, "Delete existing QoS rule" },
    { 0x3, "Modify existing QoS rule and add packet filters" },
    { 0x4, "Modify existing QoS rule and replace packet filters" },
    { 0x5, "Modify existing QoS rule and delete packet filters" },
    { 0x6, "Modify existing QoS rule without modifying packet filters" },
    { 0x7, "Reserved" },
    { 0, NULL }
 };

static const value_string nas_5gs_sm_pf_type_values[] = {
    { 0x10, "IPv4 remote address type" },
    { 0x11, "IPv4 local address type" },
    { 0x21, "IPv6 remote address/prefix length type" },
    { 0x23, "IPv6 local address/prefix length type" },
    { 0x30, "Protocol identifier/Next header type" },
    { 0x40, "Single local port type" },
    { 0x41, "Local port range type" },
    { 0x50, "Single remote port type" },
    { 0x51, "Remote port range type" },
    { 0x60, "Security parameter index type" },
    { 0x70, "Type of service/Traffic class type" },
    { 0x80, "Flow label type" },
    { 0x81, "Destination MAC address type" },
    { 0x82, "Source MAC address type" },
    { 0x83, "802.1Q C-TAG VID type" },
    { 0x84, "802.1Q S-TAG VID type" },
    { 0x85, "802.1Q C-TAG PCP/DEI type" },
    { 0x86, "802.1Q S-TAG PCP/DEI type" },
    { 0x87, "Ethertype type" },
    { 0, NULL }
 };


static guint16
de_nas_5gs_sm_qos_rules(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{

    proto_tree *sub_tree, *sub_tree2;
    proto_item *item;
    int i = 1, j = 1;
    gint32 length, pf_len, pf_type;
    guint32 curr_offset, start_offset, rule_start_offset;
    guint8 num_pkt_flt, rop;

    static const int * flags[] = {
        &hf_nas_5gs_sm_rop,
        &hf_nas_5gs_sm_dqr,
        &hf_nas_5gs_sm_nof_pkt_filters,
        NULL
    };

    curr_offset = offset;

    while ((curr_offset - offset) < len) {

        /* QoS Rule */
        rule_start_offset = curr_offset;
        sub_tree = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nas_5gs_sm_qos_rules, &item, "QoS rule %u", i);

        /* QoS rule identifier */
        proto_tree_add_item(sub_tree, hf_nas_5gs_sm_qos_rule_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset += 1;
        /* Length of QoS rule */
        proto_tree_add_item_ret_int(sub_tree, hf_nas_5gs_sm_length, tvb, curr_offset, 2, ENC_BIG_ENDIAN, &length);
        curr_offset += 2;

        proto_item_set_len(item, length + 3);

        /* Rule operation code    DQR bit    Number of packet filters */
        num_pkt_flt = tvb_get_guint8(tvb, curr_offset);
        rop = num_pkt_flt >> 5;
        num_pkt_flt = num_pkt_flt & 0x0f;
        proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);
        curr_offset++;

        /* For the "delete existing QoS rule" operation and for the "modify existing QoS rule without modifying packet filters"
         * operation, the number of packet filters shall be coded as 0.
         */
        if ((rop == 0) || (rop == 7)) {
            /* Reserved */
            proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_unknown_value, tvb, curr_offset, length - 1);
            i++;
            curr_offset += (length - 1);
            continue;
        }
        if ((rop == 2) || (rop == 6)) {
            if (rop != 0) {
                proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_num_pkt_flt, tvb, curr_offset, length - 1);
                i++;
                curr_offset += (length - 1);
                continue;
            }
        }

        while (num_pkt_flt > 0) {
            /* Packet filter list */
            sub_tree2 = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nas_5gs_sm_qos_rules, &item, "Packet filter %u", j);
            start_offset = curr_offset;
            if (rop == 5) {
                /* modify existing QoS rule and delete packet filters */
                /* 0    0    0    0    Packet filter identifier x*/
                proto_tree_add_item(sub_tree2, hf_nas_5gs_sm_pkt_flt_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                curr_offset++;
            } else {
                /* "create new QoS rule", or "modify existing QoS rule and add packet filters"
                 * or "modify existing QoS rule and replace packet filters"
                 */
                /* 0    0    Packet filter direction 1    Packet filter identifier 1*/
                proto_tree_add_item(sub_tree2, hf_nas_5gs_sm_pkt_flt_dir, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(sub_tree2, hf_nas_5gs_sm_pkt_flt_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                curr_offset++;
                /* Length of packet filter contents */
                proto_tree_add_item_ret_int(sub_tree2, hf_nas_5gs_sm_pf_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &pf_len);
                curr_offset++;
                /* Packet filter contents */
                /* Each packet filter component shall be encoded as a sequence of a one octet packet filter component type identifier
                 * and a fixed length packet filter component value field.
                 * The packet filter component type identifier shall be transmitted first.
                 */
                proto_tree_add_item_ret_int(sub_tree2, hf_nas_5gs_sm_pf_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &pf_type);
                curr_offset++;
                switch (pf_type) {
                default:
                    proto_tree_add_expert(sub_tree2, pinfo, &ei_nas_5gs_not_diss, tvb, curr_offset, pf_len - 1);
                    break;
                }
                curr_offset += (pf_len - 1);
            }
            num_pkt_flt--;
            j++;
            proto_item_set_len(item, curr_offset - start_offset);

        }
        /* 0 Spare    E    Number of parameters */
        i++;
        curr_offset = rule_start_offset + length + 3;
    }


    return len;
}

/*
 *      9.8.4.7    Session-AMBR
 */

static const value_string nas_5gs_sm_unit_for_session_ambr_values[] = {
    { 0x00, "value is not used" },
    { 0x01, "value is incremented in multiples of 1 Kbps" },
    { 0x02, "value is incremented in multiples of 4 Kbps" },
    { 0x03, "value is incremented in multiples of 16 Kbps" },
    { 0x04, "value is incremented in multiples of 64 Kbps" },
    { 0x05, "value is incremented in multiples of 256 kbps" },
    { 0x06, "value is incremented in multiples of 1 Mbps" },
    { 0x07, "value is incremented in multiples of 4 Mbps" },
    { 0x08, "value is incremented in multiples of 16 Mbps" },
    { 0x09, "value is incremented in multiples of 64 Mbps" },
    { 0x0a, "value is incremented in multiples of 256 Mbps" },
    { 0x0b, "value is incremented in multiples of 1 Gbps" },
    { 0x0c, "value is incremented in multiples of 4 Gbps" },
    { 0x0d, "value is incremented in multiples of 16 Gbps" },
    { 0x0e, "value is incremented in multiples of 64 Gbps" },
    { 0x0f, "value is incremented in multiples of 256 Gbps" },
    { 0x10, "value is incremented in multiples of 1 Tbps" },
    { 0x11, "value is incremented in multiples of 4 Tbps" },
    { 0x12, "value is incremented in multiples of 16 Tbps" },
    { 0x13, "value is incremented in multiples of 64 Tbps" },
    { 0x14, "value is incremented in multiples of 256 Tbps" },
    { 0x15, "value is incremented in multiples of 1 Pbps" },
    { 0x16, "value is incremented in multiples of 4 Pbps" },
    { 0x17, "value is incremented in multiples of 16 Pbps" },
    { 0x18, "value is incremented in multiples of 64 Pbps" },
    { 0x19, "value is incremented in multiples of 256 Pbps" },
    { 0, NULL }
};

static guint32
get_ext_ambr_unit(guint32 unit, const char **unit_str)
{
    guint32 mult;

    if (unit <= 0x05) {
        mult = pow4(guint32, unit);
        *unit_str = "Kbps";
    }
    else if (unit <= 0x0a) {
        mult = pow4(guint32, unit - 0x05);
        *unit_str = "Mbps";
    }
    else if (unit <= 0x0e) {
        mult = pow4(guint32, unit - 0x07);
        *unit_str = "Gbps";
    }
    else if (unit <= 0x14) {
        mult = pow4(guint32, unit - 0x0c);
        *unit_str = "Tbps";
    }
    else if (unit <= 0x19) {
        mult = pow4(guint32, unit - 0x11);
        *unit_str = "Pbps";
    }
    else {
        mult = 256;
        *unit_str = "Pbps";
    }
    return mult;
}
static guint16
de_nas_5gs_sm_session_ambr(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    guint32 unit, mult, ambr_val;
    const char *unit_str;

    /* Unit for Session-AMBR for downlink */
    proto_tree_add_item_ret_uint(tree, nas_5gs_sm_unit_for_session_ambr_dl, tvb, offset, 1, ENC_BIG_ENDIAN, &unit);

    /* Session-AMBR for downlink (octets 4 and 5) */
    mult = get_ext_ambr_unit(unit, &unit_str);
    ambr_val = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint_format_value(tree, hf_nas_5gs_sm_session_ambr_dl, tvb, offset, 2,
        ambr_val, "%u %s (%u)", ambr_val * mult, unit_str, ambr_val);
    offset += 2;

    proto_tree_add_item_ret_uint(tree, nas_5gs_sm_unit_for_session_ambr_ul, tvb, offset, 1, ENC_NA, &unit);
    offset++;
    mult = get_ext_ambr_unit(unit, &unit_str);
    ambr_val = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint_format_value(tree, hf_nas_5gs_sm_session_ambr_ul, tvb, offset, 2,
        ambr_val, "%u %s (%u)", ambr_val * mult, unit_str, ambr_val);

    return len;
}

/*
 *      9.8.4.8    SM PDU DN request container
 */
/* The SM PDU DN request container contains a DN-specific identity of the UE in the network access identifier (NAI) format */
static guint16
de_nas_5gs_sm_pdu_dn_req_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 *      9.8.4.9    SSC mode
 */

static const value_string nas_5gs_sc_mode_values[] = {
    { 0x1, "SSC mode 1" },
    { 0x2, "SSC mode 2" },
    { 0x3, "SSC mode 3" },
    { 0, NULL }
 };


static guint16
de_nas_5gs_sm_ssc_mode(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    guint32 offset, guint len _U_,
    gchar *add_string _U_, int string_len _U_)
{

    proto_tree_add_item(tree, hf_nas_5gs_sm_sc_mode, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 1;
}


/*
 *       9.8.4.10    5GSM capability
 */

static guint16
de_nas_5gs_sm_5gsm_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    guint32 offset, guint len _U_,
    gchar *add_string _U_, int string_len _U_)
{

    static const int * flags[] = {
        &hf_nas_5gs_spare_b7,
        &hf_nas_5gs_spare_b6,
        &hf_nas_5gs_spare_b5,
        &hf_nas_5gs_spare_b4,
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_spare_b1,
        &hf_nas_5gs_sm_rqos_b0,
        NULL
    };


    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return 1;
}


/*
 *   9.8.2    Common information elements
 */

/* 9.8.2.1    Additional information*/

/*
 * Note this enum must be of the same size as the element decoding list
 */
typedef enum
{
    DE_NAS_5GS_CMN_ADD_INF,       /*9.8.2.1    Additional information*/
    DE_NAS_5GS_PDU_SES_STATUS,    /*9.8.2.2    PDU session status*/
    DE_NAS_5GS_UL_DATA_STATUS,    /*9.8.2.3    Uplink data status*/
    DE_NAS_5GS_COMMON_NONE        /* NONE */
}
nas_5gs_common_elem_idx_t;

static const value_string nas_5gs_common_elem_strings[] = {
    { DE_NAS_5GS_CMN_ADD_INF, "Additional information" },                    /* 9.8.2.1    Additional information*/
    { DE_NAS_5GS_PDU_SES_STATUS, "PDU session status" },                     /* 9.8.2.2    PDU session status*/
    { DE_NAS_5GS_UL_DATA_STATUS, "Uplink data status" },                     /* 9.8.2.3    Uplink data status*/
    { 0, NULL }
};
value_string_ext nas_5gs_common_elem_strings_ext = VALUE_STRING_EXT_INIT(nas_5gs_common_elem_strings);

#define NUM_NAS_5GS_COMMON_ELEM (sizeof(nas_5gs_common_elem_strings)/sizeof(value_string))
gint ett_nas_5gs_common_elem[NUM_NAS_5GS_COMMON_ELEM];


guint16(*nas_5gs_common_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string, int string_len) = {
        /*  9.8.2    Common information elements */
        de_nas_5gs_cmn_add_inf,       /*9.8.2.1    Additional information*/
        de_nas_5gs_pdu_ses_status,    /*9.8.2.2    PDU session status*/
        de_nas_5gs_ul_data_status,    /*9.8.2.3    Uplink data status*/
        NULL,   /* NONE */
};



/*
 * 9.8.3    5GS mobility management (5GMM) information elements
 */
typedef enum
{
    DE_NAS_5GS_MM_5GMM_CAP,                  /* 9.8.3.1     5GMM capability*/
    DE_NAS_5GS_MM_5GMM_CAUSE,                /* 9.8.3.2     5GMM cause*/
    DE_NAS_5GS_MM_5GS_MOBILE_ID,             /* 9.8.3.3     5GS mobile identity*/
    DE_NAS_5GS_MM_5GS_NW_FEAT_SUP,           /* 9.8.3.4     5GS network feature support*/
    DE_NAS_5GS_MM_5GS_REG_RES,               /* 9.8.3.5     5GS registration result*/
    DE_NAS_5GS_MM_5GS_REG_TYPE,              /* 9.8.3.6     5GS registration type*/
    DE_NAS_5GS_MM_ALLOW_PDU_SES_STS,         /* 9.8.3.7     Allowed PDU session status*/
    DE_NAS_5GS_MM_AUT_PAR_AUTN,              /* 9.8.3.8     Authentication parameter AUTN*/
    DE_NAS_5GS_MM_AUT_PAR_RAND,              /* 9.8.3.9     Authentication parameter RAND*/
    DE_NAS_5GS_MM_CONF_UPD_IND,              /* 9.8.3.10    Configuration update indication*/
    DE_NAS_5GS_MM_DLGT_SAVING_TIME,          /* 9.8.3.11    Daylight saving time*/
    DE_NAS_5GS_MM_DE_REG_TYPE,               /* 9.8.3.12    De-registration type*/
    DE_NAS_5GS_MM_DNN,                       /* 9.8.3.13    DNN*/
    DE_NAS_5GS_MM_EAP_MSG,                   /* 9.8.3.14    EAP message*/
    DE_NAS_5GS_MM_EPS_NAS_MSG_CONT,          /* 9.8.3.15    EPS NAS message container*/
    DE_NAS_5GS_MM_GPRS_TIMER_2,              /* 9.8.3.16    GPRS timer 2*/
    DE_NAS_5GS_MM_HASHAMF,                   /* 9.8.3.17    HashAMF*/
    DE_NAS_5GS_MM_IMEISV_REQ,                /* 9.8.3.18    IMEISV request*/
    DE_NAS_5GS_MM_LADN_INF,                  /* 9.8.3.19    LADN information*/
    DE_NAS_5GS_MM_MSG_AUTH_CODE,             /* 9.8.3.20    Message authentication code*/
    DE_NAS_5GS_MM_MICO_IND,                  /* 9.8.3.21    MICO indication*/
    DE_NAS_5GS_MM_NAS_KEY_SET_ID,            /* 9.8.3.22    NAS key set identifier*/
    DE_NAS_5GS_MM_NAS_MSG_CONT,              /* 9.8.3.23    NAS message container*/
    DE_NAS_5GS_MM_NAS_SEC_ALGO,              /* 9.8.3.24    NAS security algorithms*/
    DE_NAS_5GS_MM_NAS_SEC_PAR_NG_RAN,        /* 9.8.3.25    NAS security parameters to NG-RAN*/
    DE_NAS_5GS_MM_NW_NAME,                   /* 9.8.3.26    Network name*/
    DE_NAS_5GS_MM_NONCE,                     /* 9.8.3.27    Nonce*/
    DE_NAS_5GS_MM_NSSAI,                     /* 9.8.3.28    NSSAI*/
    DE_NAS_5GS_MM_NSSAI_INF_FOR_PDU_SES,     /* 9.8.3.29    NSSAI info for PDU sessions*/
    DE_NAS_5GS_MM_PLD_CONT,                  /* 9.8.3.30    Payload container*/
    DE_NAS_5GS_MM_PLD_CONT_TYPE,             /* 9.8.3.31    Payload container type*/
    DE_NAS_5GS_MM_PDU_SES_REACT_RES,         /* 9.8.3.32    PDU session reactivation result*/
    DE_NAS_5GS_MM_PLMN_LIST,                 /* 9.8.3.33    PLMN list*/
    DE_NAS_5GS_MM_OLD_PDU_SES_ID,            /* 9.8.3.34    Old PDU session identity*/
    DE_NAS_5GS_MM_REJ_NSSAI,                 /* 9.8.3.35    Rejected NSSAI*/
    DE_NAS_5GS_MM_S1_UE_NW_CAP,              /* 9.8.3.36    S1 UE network capability*/
    DE_NAS_5GS_MM_S_NSSAI,                   /* 9.8.3.37    S-NSSAI*/
    DE_NAS_5GS_MM_SEQ_NO,                    /* 9.8.3.38    Sequence number*/
    DE_NAS_5GS_MM_SAL,                       /* 9.8.3.39    Service area list*/
    DE_NAS_5GS_MM_SMS_ALL,                   /* 9.8.3.40    SMS allowed*/
    DE_NAS_5GS_MM_SMS_REQ,                   /* 9.8.3.41    SMS requested*/
    DE_NAS_5GS_MM_REQ_TYPE,                  /* 9.8.3.42    Request type*/
    DE_NAS_5GS_MM_SERV_TYPE,                 /* 9.8.3.43    Service type*/
    DE_NAS_5GS_MM_TAI_ID,                    /* 9.8.3.44    Tracking area identity*/
    DE_NAS_5GS_MM_TAI_ID_LIST,               /* 9.8.3.45    Tracking area identity list*/
    DE_NAS_5GS_MM_TZ,                        /* 9.8.3.46    Time zone*/
    DE_NAS_5GS_MM_TZ_AND_T,                  /* 9.8.3.47    Time zone and time*/
    DE_NAS_5GS_MM_UE_SEC_CAP,                /* 9.8.3.48    UE security capability*/
    DE_NAS_5GS_MM_UE_STS,                    /* 9.8.3.49    UE status*/
    DE_NAS_5GS_MM_NONE        /* NONE */
}
nas_5gs_mm_elem_idx_t;

static const value_string nas_5gs_mm_elem_strings[] = {
    { DE_NAS_5GS_MM_5GMM_CAP,                   "5GMM capability" },                    /* 9.8.3.1    5GMM capability*/
    { DE_NAS_5GS_MM_5GMM_CAUSE,                 "5GMM cause" },                         /* 9.8.3.2    5GMM cause*/
    { DE_NAS_5GS_MM_5GS_MOBILE_ID,              "5GS mobile identity" },                /* 9.8.3.3    5GS mobile identity*/
    { DE_NAS_5GS_MM_5GS_NW_FEAT_SUP,            "5GS network feature support" },        /* 9.8.3.4    5GS network feature support*/
    { DE_NAS_5GS_MM_5GS_REG_RES,                "5GS registration resul" },             /* 9.8.3.5    5GS registration result*/
    { DE_NAS_5GS_MM_5GS_REG_TYPE,               "5GS registration type" },              /* 9.8.3.6    5GS registration type*/
    { DE_NAS_5GS_MM_ALLOW_PDU_SES_STS,          "Allowed PDU session status" },         /* 9.8.3.7    Allowed PDU session status*/
    { DE_NAS_5GS_MM_AUT_PAR_AUTN,               "Authentication parameter AUTN" },      /* 9.8.3.8    Authentication parameter AUTN*/
    { DE_NAS_5GS_MM_AUT_PAR_RAND,               "Authentication parameter RAND" },      /* 9.8.3.9    Authentication parameter RAND*/
    { DE_NAS_5GS_MM_CONF_UPD_IND,               "Configuration update indication" },    /* 9.8.3.10    Configuration update indication*/
    { DE_NAS_5GS_MM_DLGT_SAVING_TIME,           "Daylight saving time" },               /* 9.8.3.11    Daylight saving time*/
    { DE_NAS_5GS_MM_DE_REG_TYPE,                "De-registration type" },               /* 9.8.3.12    De-registration type*/
    { DE_NAS_5GS_MM_DNN,                        "DNN" },                                /* 9.8.3.13    DNN*/
    { DE_NAS_5GS_MM_EAP_MSG,                    "EAP message" },                        /* 9.8.3.14    EAP message*/
    { DE_NAS_5GS_MM_EPS_NAS_MSG_CONT,           "EPS NAS message container" },          /* 9.8.3.15    EPS NAS message container*/
    { DE_NAS_5GS_MM_GPRS_TIMER_2,               "GPRS timer 2" },                       /* 9.8.3.16    GPRS timer 2*/
    { DE_NAS_5GS_MM_HASHAMF,                    "HashAMF" },                            /* 9.8.3.17    HashAMF*/
    { DE_NAS_5GS_MM_IMEISV_REQ,                 "IMEISV request" },                     /* 9.8.3.18    IMEISV request*/
    { DE_NAS_5GS_MM_LADN_INF,                   "LADN information" },                   /* 9.8.3.19    LADN information*/
    { DE_NAS_5GS_MM_MSG_AUTH_CODE,              "Message authentication code" },        /* 9.8.3.20    Message authentication code*/
    { DE_NAS_5GS_MM_MICO_IND,                   "MICO indication" },                    /* 9.8.3.21    MICO indication*/
    { DE_NAS_5GS_MM_NAS_KEY_SET_ID,             "NAS key set identifier" },             /* 9.8.3.22    NAS key set identifier*/
    { DE_NAS_5GS_MM_NAS_MSG_CONT,               "NAS message container" },              /* 9.8.3.23    NAS message container*/
    { DE_NAS_5GS_MM_NAS_SEC_ALGO,               "NAS security algorithms" },            /* 9.8.3.24    NAS security algorithms*/
    { DE_NAS_5GS_MM_NAS_SEC_PAR_NG_RAN,         "NAS security parameters to NG-RAN" },  /* 9.8.3.25    NAS security parameters to NG-RAN*/
    { DE_NAS_5GS_MM_NW_NAME,                    "Network name" },                       /* 9.8.3.26    Network name*/
    { DE_NAS_5GS_MM_NONCE,                      "Nonce" },                              /* 9.8.3.27    Nonce*/
    { DE_NAS_5GS_MM_NSSAI,                      "NSSAI" },                              /* 9.8.3.28    NSSAI*/
    { DE_NAS_5GS_MM_NSSAI_INF_FOR_PDU_SES,      "NSSAI info for PDU sessions" },        /* 9.8.3.29    NSSAI info for PDU sessions*/
    { DE_NAS_5GS_MM_PLD_CONT,                   "Payload container" },                  /* 9.8.3.30    Payload container*/
    { DE_NAS_5GS_MM_PLD_CONT_TYPE,              "Payload container type" },             /* 9.8.3.31    Payload container type*/
    { DE_NAS_5GS_MM_PDU_SES_REACT_RES,          "PDU session reactivation result" },    /* 9.8.3.32    PDU session reactivation result*/
    { DE_NAS_5GS_MM_PLMN_LIST,                  "PLMN list" },                          /* 9.8.3.33    PLMN list*/
    { DE_NAS_5GS_MM_OLD_PDU_SES_ID,             "Old PDU session identity" },           /* 9.8.3.34    Old PDU session identity*/
    { DE_NAS_5GS_MM_REJ_NSSAI,                  "Rejected NSSAI" },                     /* 9.8.3.35    Rejected NSSAI*/
    { DE_NAS_5GS_MM_S1_UE_NW_CAP,               "S1 UE network capability" },           /* 9.8.3.36    S1 UE network capability*/
    { DE_NAS_5GS_MM_S_NSSAI,                    "S-NSSAI" },                            /* 9.8.3.37    S-NSSAI*/
    { DE_NAS_5GS_MM_SEQ_NO,                     "Sequence number" },                    /* 9.8.3.38    Sequence number*/
    { DE_NAS_5GS_MM_SAL,                        "Service area list" },                  /* 9.8.3.39    Service area list*/
    { DE_NAS_5GS_MM_SMS_ALL,                    "SMS allowed" },                        /* 9.8.3.40    SMS allowed*/
    { DE_NAS_5GS_MM_SMS_REQ,                    "SMS requested" },                      /* 9.8.3.41    SMS requested*/
    { DE_NAS_5GS_MM_REQ_TYPE,                   "Request type" },                       /* 9.8.3.42    Request type*/
    { DE_NAS_5GS_MM_SERV_TYPE,                  "Service type" },                       /* 9.8.3.43    Service type*/
    { DE_NAS_5GS_MM_TAI_ID,                     "Tracking area identity" },             /* 9.8.3.44    Tracking area identity*/
    { DE_NAS_5GS_MM_TAI_ID_LIST,                "Tracking area identity list" },        /* 9.8.3.45    Tracking area identity list*/
    { DE_NAS_5GS_MM_TZ,                         "Time zone" },                          /* 9.8.3.46    Time zone*/
    { DE_NAS_5GS_MM_TZ_AND_T,                   "Time zone and time" },                 /* 9.8.3.47    Time zone and time*/
    { DE_NAS_5GS_MM_UE_SEC_CAP,                 "UE security capability" },             /* 9.8.3.48    UE security capability*/
    { DE_NAS_5GS_MM_UE_STS,                     "UE status" },                          /* 9.8.3.49    UE status*/
    { 0, NULL }
};
value_string_ext nas_5gs_mm_elem_strings_ext = VALUE_STRING_EXT_INIT(nas_5gs_mm_elem_strings);

#define NUM_NAS_5GS_MM_ELEM (sizeof(nas_5gs_mm_elem_strings)/sizeof(value_string))
gint ett_nas_5gs_mm_elem[NUM_NAS_5GS_MM_ELEM];

guint16(*nas_5gs_mm_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string, int string_len) = {
        /*  9.8.3    5GS mobility management (5GMM) information elements */
        de_nas_5gs_mm_5gmm_cap,                  /* 9.8.3.1    5GMM capability*/
        de_nas_5gs_mm_5gmm_cause,                /* 9.8.3.2    5GMM cause*/
        de_nas_5gs_mm_5gs_mobile_id,             /* 9.8.3.3    5GS mobile identity*/
        de_nas_5gs_mm_5gs_nw_feat_sup,           /* 9.8.3.4    5GS network feature support*/
        de_nas_5gs_mm_5gs_reg_res,               /* 9.8.3.5    5GS registration result*/
        de_nas_5gs_mm_5gs_reg_type,              /* 9.8.3.6    5GS registration type*/
        de_nas_5gs_mm_allow_pdu_ses_sts,         /* 9.8.3.7    Allowed PDU session status*/
        NULL,                                    /* 9.8.3.8    Authentication parameter AUTN*/
        NULL,                                    /* 9.8.3.9    Authentication parameter RAND*/
        de_nas_5gs_mm_conf_upd_ind,              /* 9.8.3.10    Configuration update indication*/
        NULL,                                    /* 9.8.3.11    Daylight saving time*/
        de_nas_5gs_mm_de_reg_type,               /* 9.8.3.12    De-registration type*/
        de_nas_5gs_mm_dnn,                       /* 9.8.3.13    DNN*/
        de_nas_5gs_mm_eap_msg,                   /* 9.8.3.14    EAP message*/
        de_nas_5gs_mm_eps_nas_msg_cont,          /* 9.8.3.15    EPS NAS message container*/
        NULL,                                    /* 9.8.3.16    GPRS timer 2*/
        de_nas_5gs_mm_hashamf,                   /* 9.8.3.17    HashAMF*/
        NULL,                                    /* 9.8.3.18    IMEISV request*/
        de_nas_5gs_mm_ladn_inf,                  /* 9.8.3.19    LADN information*/
        de_nas_5gs_mm_msg_auth_code,             /* 9.8.3.20    Message authentication code*/
        de_nas_5gs_mm_mico_ind,                  /* 9.8.3.21    MICO indication*/
        de_nas_5gs_mm_nas_key_set_id,            /* 9.8.3.22    NAS key set identifier*/
        de_nas_5gs_mm_nas_msg_cont,              /* 9.8.3.23    NAS message container*/
        de_nas_5gs_mm_nas_sec_algo,              /* 9.8.3.24    NAS security algorithms*/
        de_nas_5gs_mm_nas_sec_par_ng_ran,        /* 9.8.3.25    NAS security parameters to NG-RAN*/
        NULL,                                    /* 9.8.3.26    Network name*/
        NULL,                                    /* 9.8.3.27    Nonce*/
        de_nas_5gs_mm_nssai,                     /* 9.8.3.28    NSSAI*/
        de_nas_5gs_mm_nssai_inf_for_pdu_ses,     /* 9.8.3.29    NSSAI info for PDU sessions*/
        de_nas_5gs_mm_pld_cont,                  /* 9.8.3.30    Payload container*/
        de_nas_5gs_mm_pld_cont_type,             /* 9.8.3.31    Payload container type*/
        de_nas_5gs_mm_pdu_ses_react_res,         /* 9.8.3.32    PDU session reactivation result*/
        NULL,                                    /* 9.8.3.33    PLMN list*/
        de_nas_5gs_mm_old_pdu_ses_id,            /* 9.8.3.34    Old PDU session identity*/
        de_nas_5gs_mm_rej_nssai,                 /* 9.8.3.35    Rejected NSSAI*/
        NULL,                                    /* 9.8.3.36    S1 UE network capability*/
        de_nas_5gs_mm_s_nssai,                   /* 9.8.3.37    S-NSSAI*/
        de_nas_5gs_mm_seq_no,                    /* 9.8.3.38    Sequence number*/
        de_nas_5gs_mm_sal,                       /* 9.8.3.39    Service area list*/
        de_nas_5gs_mm_sms_all,                   /* 9.8.3.40    SMS allowed*/
        de_nas_5gs_mm_sms_req,                   /* 9.8.3.41    SMS requested*/
        de_nas_5gs_mm_req_type,                  /* 9.8.3.42    Request type*/
        de_nas_5gs_mm_serv_type,                 /* 9.8.3.43    Service type*/
        NULL,                                    /* 9.8.3.44    Tracking area identity*/
        NULL,                                    /* 9.8.3.45    Tracking area identity list*/
        NULL,                                    /* 9.8.3.46    Time zone*/
        NULL,                                    /* 9.8.3.47    Time zone and time*/
        de_nas_5gs_mm_ue_sec_cap,                /* 9.8.3.48    UE security capability*/
        de_nas_5gs_mm_ue_sts,                    /* 9.8.3.49    UE status*/
        NULL,   /* NONE */
};


/*
 * 9.8.4    5GS session management (5GSM) information elements
 */

typedef enum
{

    DE_NAS_5GS_SM_5GSM_CAUSE,           /* 9.8.4.1    5GSM cause */
    DE_NAS_5GS_SM_EXT_PROT_CONF_OPT,    /* 9.8.4.2    Extended protocol configuration options */
    DE_NAS_5GS_SM_GPRS_TIMER,           /* 9.8.4.3    GPRS timer */
    DE_NAS_5GS_SM_PDU_ADDRESS,          /* 9.8.4.4    PDU address */
    DE_NAS_5GS_SM_PDU_SESSION_TYPE,     /* 9.8.4.5    PDU session type */
    DE_NAS_5GS_SM_QOS_RULES,            /* 9.8.4.6    QoS rules */
    DE_NAS_5GS_SM_SESSION_AMBR,         /* 9.8.4.7    Session-AMBR */
    DE_NAS_5GS_SM_PDU_DN_REQ_CONT,      /* 9.8.4.8    SM PDU DN request container */
    DE_NAS_5GS_SM_SSC_MODE,             /* 9.8.4.9    SSC mode */
    DE_NAS_5GS_SM_5GSM_CAP,            /*  9.8.4.10   5GSM capability */
    DE_NAS_5GS_SM_NONE        /* NONE */
}
nas_5gs_sm_elem_idx_t;


static const value_string nas_5gs_sm_elem_strings[] = {
    { DE_NAS_5GS_SM_5GSM_CAUSE, "5GSM cause" },                                         /* 9.8.4.1    5GSM cause */
    { DE_NAS_5GS_SM_EXT_PROT_CONF_OPT, "Extended protocol configuration options" },     /* 9.8.4.2    Extended protocol configuration options */
    { DE_NAS_5GS_SM_GPRS_TIMER, " GPRS timer" },                                        /* 9.8.4.3    GPRS timer */
    { DE_NAS_5GS_SM_PDU_ADDRESS, "PDU address" },                                       /* 9.8.4.4    PDU address */
    { DE_NAS_5GS_SM_PDU_SESSION_TYPE, "PDU session type" },                             /* 9.8.4.5    PDU session type */
    { DE_NAS_5GS_SM_QOS_RULES, "QoS rules" },                                           /* 9.8.4.6    QoS rules */
    { DE_NAS_5GS_SM_SESSION_AMBR, "Session-AMBR" },                                     /* 9.8.4.7    Session-AMBR */
    { DE_NAS_5GS_SM_PDU_DN_REQ_CONT, "SM PDU DN request container" },                   /* 9.8.4.8    SM PDU DN request container */
    { DE_NAS_5GS_SM_SSC_MODE, "SSC mode" },                                             /* 9.8.4.9    SSC mode */
    { DE_NAS_5GS_SM_5GSM_CAP, "5GSM capability" },                                      /* 9.8.4.10   5GSM capability */

    { 0, NULL }
};
value_string_ext nas_5gs_sm_elem_strings_ext = VALUE_STRING_EXT_INIT(nas_5gs_sm_elem_strings);

#define NUM_NAS_5GS_SM_ELEM (sizeof(nas_5gs_sm_elem_strings)/sizeof(value_string))
gint ett_nas_5gs_sm_elem[NUM_NAS_5GS_SM_ELEM];

guint16(*nas_5gs_sm_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string, int string_len) = {
        /*  5GS session management (5GSM) information elements */
        de_nas_5gs_sm_5gsm_cause,           /* 9.8.4.1    5GSM cause */
        NULL,                               /* 9.8.4.2    Extended protocol configuration options */
        NULL,                               /* 9.8.4.3    GPRS timer */
        de_nas_5gs_sm_pdu_address,          /* 9.8.4.4    PDU address */
        de_nas_5gs_sm_pdu_session_type,     /* 9.8.4.5    PDU session type */
        de_nas_5gs_sm_qos_rules,            /* 9.8.4.6    QoS rules */
        de_nas_5gs_sm_session_ambr,         /* 9.8.4.7    Session-AMBR */
        de_nas_5gs_sm_pdu_dn_req_cont,      /* 9.8.4.8    SM PDU DN request container */
        de_nas_5gs_sm_ssc_mode,             /* 9.8.4.9    SSC mode */
        de_nas_5gs_sm_5gsm_cap,            /*  9.8.4.10    5GSM capability */
        NULL,   /* NONE */
};

/* Gap fill msg decoding*/
static void
nas_5gs_exp_not_dissected_yet(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{

    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_msg_not_dis, tvb, offset, len);
}

/*
 * 8.2.1    Authentication request
 */
static void
nas_5gs_mm_authentication_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* ngKSI    NAS key set identifier     9.8.3.22    M    V    1/2 */
    /* Spare half octet    Spare half octet     9.5    M    V    1/2 */
    proto_tree_add_item(tree, hf_nas_5gs_spare_half_octet, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NAS_KEY_SET_ID, " - ngKSI", ei_nas_5gs_missing_mandatory_elemen);

    /*21    Authentication parameter RAND (5G authentication challenge)    Authentication parameter RAND     9.8.3.9    O    TV    17*/
    ELEM_MAND_TV(0x21, GSM_A_PDU_TYPE_DTAP, DE_AUTH_PARAM_RAND, " - 5G authentication challenge", ei_nas_5gs_missing_mandatory_elemen);
    /*20    Authentication parameter AUTN (5G authentication challenge)    Authentication parameter AUTN     9.8.3.8    O    TLV    18*/
    ELEM_MAND_TLV(0x20, GSM_A_PDU_TYPE_DTAP, DE_AUTH_PARAM_AUTN, " - 5G authentication challeng", ei_nas_5gs_missing_mandatory_elemen);
    /*78    EAP message    EAP message     9.8.3.14    O    TLV-E    7-1503*/
    ELEM_OPT_TLV_E(0x78, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_EAP_MSG, NULL);


    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}
/*
 *8.2.2    Authentication response
 */
static void
nas_5gs_mm_authentication_resp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* EAP message    EAP message     9.8.3.14    O    TLV-E    7-1503 */
    ELEM_OPT_TLV_E(0x78, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_EAP_MSG, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.3 Authentication result
 */

/*
ngKSI    NAS key set identifier 9.8.3.27    M    V    1/2
Spare half octet    Spare half octet 9.5    M    V    1/2
EAP message    EAP message 9.8.3.16    M    LV-E    6-1502

*/
/*
 * 8.2.4 Authentication failure
 */
static void
nas_5gs_mm_authentication_failure(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* 5GMM cause   5GMM cause     9.8.3.2  M   V   1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GMM_CAUSE, NULL, ei_nas_5gs_missing_mandatory_elemen);


    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}
/*
 * 8.2.5 Authentication reject
 */
static void
nas_5gs_mm_authentication_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    /*guint32 consumed;*/
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.6 Registration request
 */
static void
nas_5gs_mm_registration_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*    5GS registration type    5GS registration type 9.8.3.6    M    V    1*/
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_REG_TYPE, NULL, ei_nas_5gs_missing_mandatory_elemen);

    /*    ngKSI    NAS key set identifier 9.8.3.22    M    V    1*/
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NAS_KEY_SET_ID, " - ngKSI", ei_nas_5gs_missing_mandatory_elemen);

    /*    Mobile identity    5GS mobile identity 9.8.3.3    M    LV    TBD*/
    ELEM_MAND_LV(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_MOBILE_ID, NULL, ei_nas_5gs_missing_mandatory_elemen);

    /*55    NonceUE    Nonce 9.8.3.27    O    TV    5*/
    ELEM_OPT_TV(0x55, NAS_PDU_TYPE_EMM, DE_EMM_NONCE, " - NonceUE");

    /*10    5GMM capability    5GMM capability 9.8.3.1    O    TLV    4-15*/
    ELEM_OPT_TLV(0x10, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GMM_CAP, NULL);

    /*2E    UE security capability    UE security capability 9.8.3.48    O    TLV    4-6*/
    ELEM_OPT_TLV(0x2e, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_UE_SEC_CAP, NULL);

    /*2F    Requested NSSAI    NSSAI 9.8.3.28    O    TLV    4-74*/
    ELEM_OPT_TLV(0x2f, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NSSAI, " - Requested NSSAI");

    /*52    Last visited registered TAI    Tracking area identity 9.8.3.44    O    TV    6*/
    ELEM_OPT_TV(0x52, NAS_PDU_TYPE_EMM, DE_EMM_TRAC_AREA_ID, " - Last visited registered TAI");

    /*30    S1 UE network capability    S1 UE network capability 9.8.3.36    O    TV    6-13*/
    ELEM_OPT_TLV(0x30, NAS_PDU_TYPE_EMM, DE_EMM_UE_NET_CAP, NULL);

    /*40    Uplink data status    Uplink data status 9.8.2.3    O    TLV    4*/
    ELEM_OPT_TLV(0x40, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_UL_DATA_STATUS, NULL);

    /*50    PDU session status    PDU session status 9.8.2.2    O    TLV    4*/
    ELEM_OPT_TLV(0x50, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_PDU_SES_STATUS, NULL);

    /*B-    MICO indication    MICO indication 9.8.3.21    O    TV    1*/
    ELEM_OPT_TV_SHORT(0xb0, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_MICO_IND, NULL);

    /*2B    UE status    UE status 9.8.3.49    O    TLV    3*/
    ELEM_OPT_TLV(0x2b, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_UE_STS, NULL);

    /*2C    Additional GUTI    5GS mobile identity 9.8.3.3    O    TLV    TBD*/
    ELEM_OPT_TLV(0x2c, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_MOBILE_ID, " -  Additional GUTI");

    /*2D    NSSAI info for PDU sessions    NSSAI info for PDU sessions 9.8.3.29    O    TLV    6-90*/
    ELEM_OPT_TLV(0x2d, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NSSAI_INF_FOR_PDU_SES, NULL);

    /*C-    SMS requested    SMS requested 9.8.3.41    O    TV    1*/
    ELEM_OPT_TV_SHORT(0xc0, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_SMS_REQ, NULL);

    /*7C    EPS NAS message container    EPS NAS message container 9.8.3.15    O    TLV-E    TBD*/
    ELEM_OPT_TLV_E(0x7c, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_EPS_NAS_MSG_CONT, NULL);
    /*
    25    Allowed PDU session status    Allowed PDU session status     9.8.3.9    O    TLV    4-34
    TBD    Policy section identifier list    Policy section identifier list     9.8.3.40    O    TBD    TBD
    60    UE's usage setting    UE's usage setting     9.8.3.56    O    TLV    3

    */

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.7    Registration accept
 */

static void
nas_5gs_mm_registration_accept(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*      5GS registration result    5GS registration result     9.8.3.5    M    V    TBD*/
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_REG_RES, NULL, ei_nas_5gs_missing_mandatory_elemen);

    /*2C    5G-GUTI    5GS mobile identity     9.8.3.3    O    TLV    TBD*/
    ELEM_OPT_TLV(0x2c, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_MOBILE_ID, " - 5G-GUTI");

    /*4A    Equivalent PLMNs    PLMN list     9.8.3.33    O    TLV    5-47*/
    ELEM_OPT_TLV(0x4a, GSM_A_PDU_TYPE_COMMON, DE_PLMN_LIST, " - Equivalent PLMNs");
    /*54    TAI list    Tracking area identity list     9.8.3.45    O    TLV    8-98*/
    ELEM_OPT_TLV(0x54, NAS_PDU_TYPE_EMM, DE_EMM_TRAC_AREA_ID_LST, NULL);
    /*70    Allowed NSSAI    NSSAI     9.8.3.28    O    TLV    4-74*/
    ELEM_OPT_TLV(0x70, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NSSAI, " - Allowed NSSAI");
    /*11    Rejected NSSAI    Rejected NSSAI     9.8.3.35    O    TLV    4-42*/
    ELEM_OPT_TLV(0x11, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_REJ_NSSAI, NULL);
    /*wx    5GS network feature support    5GS network feature support     9.8.3.4    O    TBD    TBD*/

    /*50    PDU session status    PDU session status     9.8.2.2    O    TLV    4*/
    ELEM_OPT_TLV(0x50, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_PDU_SES_STATUS, NULL);
    /*26    PDU session reactivation result    PDU session reactivation result     9.8.3.32    O    TLV    4-32*/
    ELEM_OPT_TLV(0x26, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PDU_SES_REACT_RES, NULL);
    /*79    LADN information    LADN information     9.8.3.19    O    TLV-E    11-1579*/
    ELEM_OPT_TLV(0x79, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_LADN_INF, NULL);
    /*B-    MICO indication    MICO indication     9.8.3.21    O    TV    1*/
    ELEM_OPT_TV_SHORT(0xb0, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_MICO_IND, NULL);
    /*D-    SMS allowed    SMS allowed     9.8.3.40    O    TV    1*/
    ELEM_OPT_TV_SHORT(0xd0, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_SMS_ALL, NULL);
    /*
    27    Service area list    Service area list     9.8.3.47    O    TLV    6-194
    5E    T3512 value    GPRS timer 3     9.8.3.21    O    TLV    3
    5D    Non-3GPP de-registration timer value    GPRS timer 2     9.8.3.20    O    TLV    3
    34    Emergency number list    Emergency number list     9.8.3.17    O    TLV    5-50
    TBD    Extended emergency number list    Extended emergency number list     9.8.3.19    O    TLV    TBD

    */

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.8 Registration complete
 */
static void
nas_5gs_mm_registration_complete(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}
/*
* 8.2.9 Registration reject
*/
static void
nas_5gs_mm_registration_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* 5GMM cause   5GMM cause     9.8.3.2  M   V   1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GMM_CAUSE, NULL, ei_nas_5gs_missing_mandatory_elemen);

    /* 5F  T3346 value GPRS timer 2     9.8.3.16   O   TLV 3 */
    ELEM_OPT_TLV(0x5F, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3346 value");

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.10    UL NAS transport
 */
static void
nas_5gs_mm_ul_nas_transp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*Payload container type    Payload container type     9.8.3.31    M    V    1/2 */
    /*Spare half octet    Spare half octet    9.5    M    V    1/2*/
    proto_tree_add_item(tree, hf_nas_5gs_spare_half_octet, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PLD_CONT_TYPE, NULL, ei_nas_5gs_missing_mandatory_elemen);


    /*Payload container    Payload container    9.8.3.30    M    LV-E    3-65537*/
    /*PDU session ID    PDU session identity    9.4    C    V    1*/
    /*70    Old PDU session ID    Old PDU session identity    9.8.3.34    O    TV    2*/
    /*8-    Request type    Request type    9.8.3.42    O    TV    1*/
    /*22    S-NSSAI    S-NSSAI    9.8.3.37    O    TLV    3-10*/
    /*25    DNN    DNN    9.8.3.13    O    TLV    3-102*/
    /*24    Additional information    Additional information    9.8.2.1    O    TLV    3-n*/


    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
* 8.2.11 DL NAS transport
*/
static void
nas_5gs_mm_dl_nas_transp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*Payload container type    Payload container type     9.8.3.31    M    V    1/2 */
    /*Spare half octet    Spare half octet    9.5    M    V    1/2*/
    proto_tree_add_item(tree, hf_nas_5gs_spare_half_octet, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PLD_CONT_TYPE, NULL, ei_nas_5gs_missing_mandatory_elemen);


    /*Payload container    Payload container    9.8.3.30    M    LV-E    3-65537*/
    /*PDU session ID    PDU session identity    9.4    C    V    1*/
    /*24    Additional information    Additional information    9.8.2.1    O    TLV    3-n*/
    /*72    5GMM cause    5GMM cause 9.8.3.2    O    TV    2
*/


    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.12 De-registration request (UE originating de-registration)
 */
static void
nas_5gs_mm_de_reg_req_ue_orig(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* De-registration type    De-registration type     9.8.3.12   M   V   1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_DE_REG_TYPE, NULL, ei_nas_5gs_missing_mandatory_elemen);

    /*5GS mobile identity    5GS mobile identity     9.8.3.3  M   TLV TBD*/
    ELEM_MAND_LV(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_MOBILE_ID, NULL, ei_nas_5gs_missing_mandatory_elemen);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.13 De-registration accept (UE originating de-registration)
 */
/* No data */

/*
 * 8.2.14 De-registration request (UE terminated de-registration)
 */
static void
nas_5gs_mm_de_registration_req_ue_term(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* De-registration type    De-registration type 9.8.3.12   M   V   1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_DE_REG_TYPE, NULL, ei_nas_5gs_missing_mandatory_elemen);

    /* 72 5GMM cause   5GMM cause     9.8.3.2  M   V   2 */
    ELEM_OPT_TV(0x72, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GMM_CAUSE, NULL);

    /* 5F  T3346 value GPRS timer 2     9.8.3.16   O   TLV 3 */
    ELEM_OPT_TLV(0x5F, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3346 value");

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.15 De-registration accept (UE terminated de-registration)
 */
 /* No data */


/*
 * 8.2.16 Service request
 */
static void
nas_5gs_mm_service_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    /*guint32 consumed;*/
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NAS_KEY_SET_ID, " - ngKSI", ei_nas_5gs_missing_mandatory_elemen);

    Spare half octet    Spare half octet     9.4    M    V    1/2
    Uplink data status    Uplink data status     9.8.2.3    O    TLV    4
    PDU session status    PDU session status     9.8.2.2    O    TLV    4
    Allowed PDU session status    Allowed PDU session status     9.8.3.7    O    TLV    4-34


    */

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
  * 8.2.17 Service accept
 */
static void
nas_5gs_mm_service_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*50    PDU session status    PDU session status     9.8.2.2    O    TLV    4*/
    ELEM_OPT_TLV(0x50, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_PDU_SES_STATUS, NULL);

    /*
    26    PDU session reactivation result    PDU session reactivation result 9.8.3.37    O    TLV    4-32
    7E    PDU session reactivation result error cause    PDU session reactivation result error cause 9.8.3.38    O    TLV-E    5-515

    */

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);
}

/*
 * 8.2.18 Service reject
 */
static void
nas_5gs_mm_service_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* 5GMM cause   5GMM cause     9.8.3.2  M   V   1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GMM_CAUSE, NULL, ei_nas_5gs_missing_mandatory_elemen);

    /*50    PDU session status    PDU session status 9.8.2.2    O    TLV    4*/
    ELEM_OPT_TLV(0x50, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_PDU_SES_STATUS, NULL);

    /* 5F  T3346 value GPRS timer 2     9.8.3.16   O   TLV 3 */
    ELEM_OPT_TLV(0x5F, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3346 value");

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.19 Configuration update command
 */
static void
nas_5gs_mm_conf_upd_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*Configuration update indication    Configuration update indication     9.8.3.10    M    V    1/2*/
    /*Spare half octet    Spare half octet     9.5    M    V    1/2*/
    proto_tree_add_item(tree, hf_nas_5gs_spare_half_octet, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_CONF_UPD_IND, NULL, ei_nas_5gs_missing_mandatory_elemen);

    /*2C    5G-GUTI    5GS mobile identity     9.8.3.3    O    TLV    TBD*/
    ELEM_MAND_LV(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_MOBILE_ID, NULL, ei_nas_5gs_missing_mandatory_elemen);

    /*54    TAI list    Tracking area identity list     9.8.3.45    O    TLV    8-98*/
    ELEM_OPT_TLV(0x54, NAS_PDU_TYPE_EMM, DE_EMM_TRAC_AREA_ID_LST, NULL);

    /*70    Allowed NSSAI    NSSAI     9.8.3.28    O    TLV    4-74*/
    ELEM_OPT_TLV(0x70, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NSSAI, " - Allowed NSSAI");

    /*27    Service area list    Service area list     9.8.3.39    O    TLV    6-194 */
    ELEM_OPT_TLV(0x70, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_SAL, NULL);

    /*43    Full name for network    Network name     9.8.3.26    O    TLV    3-n*/
    ELEM_OPT_TLV(0x43, GSM_A_PDU_TYPE_DTAP, DE_NETWORK_NAME, " - Full name for network");

    /*45    Short name for network    Network name     9.8.3.26    O    TLV    3-n*/
    ELEM_OPT_TLV(0x45, GSM_A_PDU_TYPE_DTAP, DE_NETWORK_NAME, " - Short Name");

    /*46    Local time zone    Time zone     9.8.3.46    O    TV    2*/
    ELEM_OPT_TV(0x46, GSM_A_PDU_TYPE_DTAP, DE_TIME_ZONE, " - Local");

    /*47    Universal time and local time zone    Time zone and time     9.8.3.47    O    TV    8*/
    ELEM_OPT_TV(0x47, GSM_A_PDU_TYPE_DTAP, DE_TIME_ZONE_TIME, " - Universal Time and Local Time Zone");

    /*49    Network daylight saving time    Daylight saving time     9.8.3.11    O    TLV    3*/
    ELEM_OPT_TLV(0x49, GSM_A_PDU_TYPE_DTAP, DE_DAY_SAVING_TIME, NULL);

    /*79    LADN information    LADN information     9.8.3.19    O    TLV-E    11-1579*/
    ELEM_OPT_TLV(0x79, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_LADN_INF, NULL);

    /*B-    MICO indication    MICO indication     9.8.3.21    O    TV    1*/
    ELEM_OPT_TV_SHORT(0xb0, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_MICO_IND, NULL);

    /*31    Configured NSSAI    NSSAI     9.8.3.28    O    TLV    4-74*/
    ELEM_OPT_TLV(0x31, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NSSAI, " - Configured NSSAI");

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.20 Configuration update complete
 */

/*
 * 8.2.21 Identity request
 */
static void
nas_5gs_mm_id_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
   /* guint32 consumed;*/
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*
    Identity type    Identity type     FFS    M    V    1/2
    Spare half octet    Spare half octet     9.5    M    V    1/2

    */

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.22 Identity response
 */
static void
nas_5gs_mm_id_resp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Mobile identity  5GS mobile identity 9.8.3.3 M   LV  TBD */
    ELEM_MAND_LV(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_MOBILE_ID, NULL, ei_nas_5gs_missing_mandatory_elemen);


    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.23 Notification
 */
static void
nas_5gs_mm_notification(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    /*guint32 consumed;*/
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* F-    Access type    Access type 9.8.3.8    O    TV    1 */

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.24 Notification response
 */

/*
 * 8.2.25 Security mode command
 */
static void
nas_5gs_mm_sec_mode_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*Selected NAS security algorithms    NAS security algorithms     9.8.3.24    M    V    1  */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NAS_SEC_ALGO, NULL, ei_nas_5gs_missing_mandatory_elemen);

    /*NAS key set identifier    NAS key set identifier     9.8.3.22    M    V    1*/
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NAS_KEY_SET_ID, NULL, ei_nas_5gs_missing_mandatory_elemen);

    /*Replayed UE security capabilities    UE security capability     9.8.3.48    M    LV    3-5*/
    ELEM_MAND_LV(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_UE_SEC_CAP, " - Replayed UE security capabilities", ei_nas_5gs_missing_mandatory_elemen);
    /*Xa    Allowed NSSAI    NSSAI     9.8.3.28    O    TBD    TBD*/
    /*ELEM_OPT_TLV(0x70, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NSSAI, " - Allowed NSSAI");*/

    /*E-    IMEISV request    IMEISV request     9.8.3.18    O    TV    1*/
    ELEM_OPT_TV_SHORT(0xE0, NAS_PDU_TYPE_EMM, DE_EMM_IMEISV_REQ, NULL);
    /*55    Replayed nonceUE    Nonce     9.8.3.27    O    TV    5*/
    /*56    NonceAMF    Nonce     9.8.3.27    O    TV    5*/
    /*4F    HashAMF    HashAMF     9.8.3.17    O    TV    9*/
    /*78    EAP message    EAP message     9.8.3.14    O    TLV-E    7*/
    ELEM_OPT_TLV_E(0x78, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_EAP_MSG, NULL);


    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.26 Security mode complete
 */
static void
nas_5gs_mm_sec_mode_comp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    /*guint32 consumed;*/
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*
    Allowed NSSAI    NSSAI     9.8.3.28    M    TBD    TBD
    IMEISV    5G mobile identity     9.8.3.3    O    TLV    TBD
    NAS message container    NAS message container     9.8.3.23    O    TLV-E    3-n

    */

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.27 Security mode reject
 */

static void
nas_5gs_mm_sec_mode_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* EMM cause    5GMM cause 9.8.3.2    M    V    1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GMM_CAUSE, " - EMM cause", ei_nas_5gs_missing_mandatory_elemen);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.28 5GMM status
 */

static void
nas_5gs_mm_5gmm_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* EMM cause    5GMM cause 9.8.3.2    M    V    1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GMM_CAUSE, " - EMM cause", ei_nas_5gs_missing_mandatory_elemen);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/* 8.3 5GS session management messages */

/*
 * 8.3.1 PDU session establishment request
 */
static void
nas_5gs_sm_pdu_ses_est_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*9-    PDU session type    PDU session type     9.8.4.5    O    TV    1*/
    ELEM_OPT_TV_SHORT(0x90, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_PDU_SESSION_TYPE, NULL);

    /*A-    SSC mode    SSC mode     9.8.4.9    O    TV    1*/
    ELEM_OPT_TV_SHORT(0xa0, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_SSC_MODE, NULL);

    /*28    5GSM capability    5GSM capability     9.8.4.10    O    TLV    3-15 */
    ELEM_OPT_TLV(0x28, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CAP, NULL);

    /*yz    SM PDU DN request container    SM PDU DN request container     9.8.4.8    O    TBD    TBD*/

    /*7B    Extended protocol configuration options    Extended protocol configuration options     9.8.4.2    O    TLV-E    4-65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);



    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.3.2 PDU session establishment accept
 */
static void
nas_5gs_sm_pdu_ses_est_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*Selected PDU session type    PDU session type 9.8.4.5    M    V    1/2*/
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_PDU_SESSION_TYPE, " - Selected PDU session type", ei_nas_5gs_missing_mandatory_elemen);
    /*Selected SSC mode    SSC mode 9.8.4.9    M    V    1/2*/

    /* DNN    DNN 9.8.3.13    M    LV    2-TBD*/
    /*Authorized QoS rules    QoS rules 9.8.4.6    M    LV-E    2-65537*/
    /*Session AMBR    Session-AMBR 9.8.4.7    M    LV    TBD*/
    /*73    5GSM cause    5GSM cause 9.8.4.1    O    TV    2*/
    ELEM_OPT_TV(0x73, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CAUSE, NULL);

    /*29    PDU address    PDU address 9.8.4.4    O    TLV    7*/
    /*78    EAP message    EAP message 9.8.3.14    O    TLV-E    7-1503*/
    /*74    RQ timer value    GPRS timer 9.8.4.3    O    TV    2*/
    /*7B    Extended protocol configuration options    Extended protocol configuration options 9.8.4.2    O    TLV-E    4-65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    /*22    S-NSSAI    S-NSSAI 9.8.3.37    O    TLV    3-6*/

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.3.3 PDU session establishment reject
 */

static void
nas_5gs_sm_pdu_ses_est_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* EMM cause    5GMM cause 9.8.3.2    M    V    1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GMM_CAUSE, " - EMM cause", ei_nas_5gs_missing_mandatory_elemen);

    /*78    EAP message    EAP message 9.8.3.14    O    TLV - E    7 - 1503*/
    ELEM_OPT_TLV_E(0x78, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_EAP_MSG, NULL);

    /*7B    Extended protocol configuration options    Extended protocol configuration options    9.8.4.2    O    TLV - E    4 - 65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);


    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.3.4 PDU session authentication command
 */

static void
nas_5gs_sm_pdu_ses_auth_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*78    EAP message    EAP message 9.8.3.14    O    TLV - E    7 - 1503*/
    ELEM_OPT_TLV_E(0x78, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_EAP_MSG, NULL);

    /*7B    Extended protocol configuration options    Extended protocol configuration options    9.8.4.2    O    TLV - E    4 - 65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);


    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}
/*
 * 8.3.5 PDU session authentication complete
 */

static void
nas_5gs_sm_pdu_ses_auth_comp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*78    EAP message    EAP message 9.8.3.14    O    TLV - E    7 - 1503*/
    ELEM_OPT_TLV_E(0x78, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_EAP_MSG, NULL);

    /*7B    Extended protocol configuration options    Extended protocol configuration options    9.8.4.2    O    TLV - E    4 - 65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);


    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 *8.3.6 PDU session modification request
 */

static void
nas_5gs_sm_pdu_ses_mod_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*7B    Extended protocol configuration options    Extended protocol configuration options    9.8.4.2    O    TLV - E    4 - 65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    /*7A    Requested QoS rules    QoS rules 9.8.4.6    O    TLV-E    3-65538 */

    /* 28    5GSM capability    5GSM capability 9.8.4.10    O    TLV    3-15 */

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.3.7    PDU session modification reject
 */

static void
nas_5gs_sm_pdu_ses_mod_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* 5GSM cause    5GSM cause 9.8.4.1    M    V    1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CAUSE, NULL, ei_nas_5gs_missing_mandatory_elemen);

    /*78    EAP message    EAP message 9.8.3.14    O    TLV - E    7 - 1503*/
    ELEM_OPT_TLV_E(0x78, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_EAP_MSG, NULL);

    /*7B    Extended protocol configuration options    Extended protocol configuration options    9.8.4.2    O    TLV - E    4 - 65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
* 8.3.8 PDU session modification command
*/

static void
nas_5gs_sm_pdu_ses_mod_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* 5GSM cause    5GSM cause 9.8.4.1    M    V    1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CAUSE, NULL, ei_nas_5gs_missing_mandatory_elemen);

    /*7B    Authorized QoS rules    QoS rules     9.8.4.6    O    TLV-E    3-65538*/
    /*2A    Session AMBR    Session-AMBR     9.8.4.7    O    TLV    8*/
    /*75    PDU session release time    GPRS timer     9.8.4.3    O    TV    2*/
    /*7B    Extended protocol configuration options    Extended protocol configuration options     9.8.4.2    O    TLV-E    4-65538*/

    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);


    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.3.9 PDU session modification complete
 */

static void
nas_5gs_sm_pdu_ses_mod_comp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*7B    Extended protocol configuration options    Extended protocol configuration options    9.8.4.2    O    TLV - E    4 - 65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.3.10 PDU session modification command reject
 */

static void
nas_5gs_sm_pdu_ses_mod_com_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* 5GSM cause    5GSM cause 9.8.4.1    M    V    1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CAUSE, NULL, ei_nas_5gs_missing_mandatory_elemen);

    /*7B    Extended protocol configuration options    Extended protocol configuration options    9.8.4.2    O    TLV - E    4 - 65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.3.11 PDU session release request
 */

static void
nas_5gs_sm_pdu_ses_rel_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* 5GSM cause    5GSM cause 9.8.4.1    M    V    1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CAUSE, NULL, ei_nas_5gs_missing_mandatory_elemen);

    /*7B    Extended protocol configuration options    Extended protocol configuration options    9.8.4.2    O    TLV - E    4 - 65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.3.12 PDU session release reject
 */

static void
nas_5gs_sm_pdu_ses_rel_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* 5GSM cause    5GSM cause 9.8.4.1    M    V    1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CAUSE, NULL, ei_nas_5gs_missing_mandatory_elemen);

    /*7B    Extended protocol configuration options    Extended protocol configuration options    9.8.4.2    O    TLV - E    4 - 65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.3.13 PDU session release command
 */

static void
nas_5gs_sm_pdu_ses_rel_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* 5GSM cause    5GSM cause 9.8.4.1    M    V    1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CAUSE, NULL, ei_nas_5gs_missing_mandatory_elemen);

    /* 37    Back-off timer value    GPRS timer 3 9.8.3.21    O    TLV    3 */
    /*7B    Extended protocol configuration options    Extended protocol configuration options    9.8.4.2    O    TLV - E    4 - 65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
* 8.3.14 PDU session release complete
*/

static void
nas_5gs_sm_pdu_ses_rel_comp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*7B    Extended protocol configuration options    Extended protocol configuration options    9.8.4.2    O    TLV - E    4 - 65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.3.15 5GSM status
 */

static void
nas_5gs_sm_5gsm_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* 5GSM cause    5GSM cause 9.8.4.1    M    V    1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CAUSE, NULL, ei_nas_5gs_missing_mandatory_elemen);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}


/* 9.7  Message type */

/* 5GS mobility management messages */
static const value_string nas_5gs_mm_message_type_vals[] = {
    { 0x41,    "Registration request"},
    { 0x42,    "Registration accept"},
    { 0x43,    "Registration complete"},
    { 0x44,    "Registration reject"},
    { 0x45,    "Deregistration request (UE originating)"},
    { 0x46,    "Deregistration accept (UE originating)"},
    { 0x47,    "Deregistration request (UE terminated)"},
    { 0x48,    "Deregistration accept (UE terminated)"},

    { 0x49,    "Not used in v 0.4.0"},
    { 0x4a,    "Not used in v 0.4.0" },
    { 0x4b,    "Not used in v 0.4.0" },

    { 0x4c,    "Service request"},
    { 0x4d,    "Service reject"},
    { 0x4e,    "Service accept"},

    { 0x4f,    "Not used in v 0.4.0" },
    { 0x50,    "Not used in v 0.4.0" },
    { 0x51,    "Not used in v 0.4.0" },
    { 0x52,    "Not used in v 0.4.0" },
    { 0x53,    "Not used in v 0.4.0" },

    { 0x54,    "Configuration update command"},
    { 0x55,    "Configuration update complete"},
    { 0x56,    "Authentication request"},
    { 0x57,    "Authentication response"},
    { 0x58,    "Authentication reject"},
    { 0x59,    "Authentication failure"},
    { 0x5a,    "Identity request"},
    { 0x5b,    "Identity response"},
    { 0x5c,    "Security mode command"},
    { 0x5d,    "Security mode complete"},
    { 0x5e,    "Security mode reject"},

    { 0x5f,    "Not used in v 0.4.0" },
    { 0x60,    "Not used in v 0.4.0" },
    { 0x61,    "Not used in v 0.4.0" },
    { 0x62,    "Not used in v 0.4.0" },
    { 0x63,    "Not used in v 0.4.0" },

    { 0x64,    "5GMM status"},
    { 0x65,    "Notification"},
    { 0x66,    "DL NAS transport"},
    { 0x67,    "UL NAS transport"},
    { 0,    NULL }
};

static value_string_ext nas_5gs_mm_msg_strings_ext = VALUE_STRING_EXT_INIT(nas_5gs_mm_message_type_vals);

#define NUM_NAS_5GS_MM_MSG (sizeof(nas_5gs_mm_message_type_vals)/sizeof(value_string))
static gint ett_nas_5gs_mm_msg[NUM_NAS_5GS_MM_MSG];
static void(*nas_5gs_mm_msg_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len) = {
    nas_5gs_mm_registration_req,                /* 0x41    Registration request */
    nas_5gs_mm_registration_accept,             /* 0x42    Registration accept */
    nas_5gs_mm_registration_complete,           /* 0x43    Registration complete */
    nas_5gs_mm_registration_rej,                /* 0x44    Registration reject */
    nas_5gs_mm_de_reg_req_ue_orig,              /* 0x45    Deregistration request (UE originating) */
    nas_5gs_exp_not_dissected_yet,              /* 0x46    Deregistration accept (UE originating) */
    nas_5gs_mm_de_registration_req_ue_term,     /* 0x47    Deregistration request (UE terminated) */
    nas_5gs_exp_not_dissected_yet,              /* 0x48    Deregistration accept (UE terminated) */

    nas_5gs_exp_not_dissected_yet,              /* 0x49    Not used in v 0.4.0 */
    nas_5gs_exp_not_dissected_yet,              /* 0x4a    Not used in v 0.4.0 */
    nas_5gs_exp_not_dissected_yet,              /* 0x4b    Not used in v 0.4.0 */

    nas_5gs_mm_service_req,                     /* 0x4c    Service request */
    nas_5gs_mm_service_rej,                     /* 0x4d    Service reject */
    nas_5gs_mm_service_acc,                     /* 0x4e    Service accept */

    nas_5gs_exp_not_dissected_yet,              /* 0x4f    Not used in v 0.4.0 */
    nas_5gs_exp_not_dissected_yet,              /* 0x50    Not used in v 0.4.0 */
    nas_5gs_exp_not_dissected_yet,              /* 0x51    Not used in v 0.4.0 */
    nas_5gs_exp_not_dissected_yet,              /* 0x52    Not used in v 0.4.0 */
    nas_5gs_exp_not_dissected_yet,              /* 0x53    Not used in v 0.4.0 */

    nas_5gs_mm_conf_upd_cmd,                    /* 0x54    Configuration update command */
    nas_5gs_exp_not_dissected_yet,              /* 0x55    Configuration update complete */
    nas_5gs_mm_authentication_req,              /* 0x56    Authentication request */
    nas_5gs_mm_authentication_resp,             /* 0x57    Authentication response */
    nas_5gs_mm_authentication_rej,              /* 0x58    Authentication reject */
    nas_5gs_mm_authentication_failure,          /* 0x59    Authentication failure */
    nas_5gs_mm_id_req,                          /* 0x5a    Identity request */
    nas_5gs_mm_id_resp,                         /* 0x5b    Identity response */
    nas_5gs_mm_sec_mode_cmd,                    /* 0x5c    Security mode command */
    nas_5gs_mm_sec_mode_comp,                   /* 0x5d    Security mode complete */
    nas_5gs_mm_sec_mode_rej,                    /* 0x5e    Security mode reject */

    nas_5gs_exp_not_dissected_yet,              /* 0x5f    Not used in v 0.4.0 */
    nas_5gs_exp_not_dissected_yet,              /* 0x60    Not used in v 0.4.0 */
    nas_5gs_exp_not_dissected_yet,              /* 0x61    Not used in v 0.4.0 */
    nas_5gs_exp_not_dissected_yet,              /* 0x62    Not used in v 0.4.0 */
    nas_5gs_exp_not_dissected_yet,              /* 0x63    Not used in v 0.4.0 */

    nas_5gs_mm_5gmm_status,                     /* 0x64    5GMM status */
    nas_5gs_mm_notification,                    /* 0x65    Notification */
    nas_5gs_mm_dl_nas_transp,                   /* 0x66    DL NAS transport */
    nas_5gs_mm_ul_nas_transp,                   /* 0x67    UL NAS transport */

    NULL,   /* NONE */

};


    /* 5GS session management messages */
    static const value_string nas_5gs_sm_message_type_vals[] = {

    { 0xc1,    "PDU session establishment request"},
    { 0xc2,    "PDU session establishment accept"},
    { 0xc3,    "PDU session establishment reject"},

    { 0xc4,    "Not used in v 0.4.0"},
    { 0xc5,    "PDU session authentication command"},

    { 0xc6,    "PDU session authentication complete" },
    { 0xc7,    "Not used in v 0.4.0" },
    { 0xc8,    "Not used in v 0.4.0" },

    { 0xc9,    "PDU session modification request"},
    { 0xca,    "PDU session modification reject"},
    { 0xcb,    "PDU session modification command"},

    { 0xcc,    "Not used in v 0.4.0" },

    { 0xcd,    "PDU session modification complete"},
    { 0xce,    "PDU session modification command reject"},

    { 0xcf,    "Not used in v 0.4.0" },
    { 0xd0,    "Not used in v 0.4.0" },

    { 0xd1,    "PDU session release request"},
    { 0xd2,    "PDU session release reject"},
    { 0xd3,    "PDU session release command"},
    { 0xd4,    "PDU session release complete"},

    { 0xd5,    "Not used in v 0.4.0" },

    { 0xd6,    "5GSM status"},
    { 0,    NULL }
};
static value_string_ext nas_5gs_sm_msg_strings_ext = VALUE_STRING_EXT_INIT(nas_5gs_sm_message_type_vals);

#define NUM_NAS_5GS_SM_MSG (sizeof(nas_5gs_sm_message_type_vals)/sizeof(value_string))
static gint ett_nas_5gs_sm_msg[NUM_NAS_5GS_SM_MSG];

static void(*nas_5gs_sm_msg_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len) = {
    nas_5gs_sm_pdu_ses_est_req,            /* 0xc1     PDU session establishment request */
    nas_5gs_sm_pdu_ses_est_acc,            /* 0xc2     PDU session establishment accept */
    nas_5gs_sm_pdu_ses_est_rej,            /* 0xc3     PDU session establishment reject */

    nas_5gs_exp_not_dissected_yet,         /* 0xc4     Not used in v 0.4.0 */
    nas_5gs_sm_pdu_ses_auth_cmd,           /* 0xc5     PDU session authentication command */

    nas_5gs_sm_pdu_ses_auth_comp,          /* 0xc6     PDU session authentication complete */
    nas_5gs_exp_not_dissected_yet,         /* 0xc7     Not used in v 0.4.0 */
    nas_5gs_exp_not_dissected_yet,         /* 0xc8     Not used in v 0.4.0 */

    nas_5gs_sm_pdu_ses_mod_req,            /* 0xc9     PDU session modification request */
    nas_5gs_sm_pdu_ses_mod_rej,            /* 0xca     PDU session modification reject */
    nas_5gs_sm_pdu_ses_mod_cmd,            /* 0xcb     PDU session modification command */

    nas_5gs_exp_not_dissected_yet,         /* 0xcc     Not used in v 0.4.0 */

    nas_5gs_sm_pdu_ses_mod_comp,           /* 0xcd     PDU session modification complete */
    nas_5gs_sm_pdu_ses_mod_com_rej,        /* 0xce     PDU session modification command reject */

    nas_5gs_exp_not_dissected_yet,         /* 0xcf     Not used in v 0.4.0 */
    nas_5gs_exp_not_dissected_yet,         /* 0xd0     Not used in v 0.4.0 */

    nas_5gs_sm_pdu_ses_rel_req,            /* 0xd1     PDU session release request */
    nas_5gs_sm_pdu_ses_rel_rej,            /* 0xd2     PDU session release reject */
    nas_5gs_sm_pdu_ses_rel_cmd,            /* 0xd3     PDU session release command */
    nas_5gs_sm_pdu_ses_rel_comp,           /* 0xd4     PDU session release complete */

    nas_5gs_exp_not_dissected_yet,         /* 0xd5     Not used in v 0.4.0 */

    nas_5gs_sm_5gsm_status,                /* 0xd6     5GSM status */

    NULL,   /* NONE */

};



static void
get_nas_5gsmm_msg_params(guint8 oct, const gchar **msg_str, int *ett_tree, int *hf_idx, msg_fcn *msg_fcn_p)
{
    gint            idx;

    *msg_str = try_val_to_str_idx_ext((guint32)(oct & 0xff), &nas_5gs_mm_msg_strings_ext, &idx);
    *hf_idx = hf_nas_5gs_mm_msg_type;
    if (*msg_str != NULL) {
        *ett_tree = ett_nas_5gs_mm_msg[idx];
        *msg_fcn_p = nas_5gs_mm_msg_fcn[idx];
    }

    return;
}

static void
get_nas_5gssm_msg_params(guint8 oct, const gchar **msg_str, int *ett_tree, int *hf_idx, msg_fcn *msg_fcn_p)
{
    gint            idx;

    *msg_str = try_val_to_str_idx_ext((guint32)(oct & 0xff), &nas_5gs_sm_msg_strings_ext, &idx);
    *hf_idx = hf_nas_5gs_sm_msg_type;
    if (*msg_str != NULL) {
        *ett_tree = ett_nas_5gs_sm_msg[idx];
        *msg_fcn_p = nas_5gs_sm_msg_fcn[idx];
    }

    return;
}
static void
dissect_nas_5gs_sm_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    const gchar *msg_str;
    guint32      len;
    gint         ett_tree;
    int          hf_idx;
    void(*msg_fcn_p)(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len);
    guint8       oct;

    len = tvb_reported_length(tvb);

    /* Message type IE*/
    oct = tvb_get_guint8(tvb, offset);
    msg_fcn_p = NULL;
    ett_tree = -1;
    hf_idx = -1;
    msg_str = NULL;

    get_nas_5gssm_msg_params(oct, &msg_str, &ett_tree, &hf_idx, &msg_fcn_p);

    if (msg_str) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, msg_str);
    }
    else {
        proto_tree_add_expert_format(tree, pinfo, &ei_nas_5gs_sm_unknown_msg_type, tvb, offset, 1, "Unknown Message Type 0x%02x", oct);
        return;
    }

    /*
    * Add NAS message name
    */
    proto_tree_add_item(tree, hf_idx, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /*
    * decode elements
    */
    if (msg_fcn_p == NULL)
    {
        if (tvb_reported_length_remaining(tvb, offset)) {
            proto_tree_add_item(tree, hf_nas_5gs_msg_elems, tvb, offset, len - offset, ENC_NA);
        }
    }
    else
    {
        (*msg_fcn_p)(tvb, tree, pinfo, offset, len - offset);
    }

}

static void
disect_nas_5gs_mm_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{

    const gchar *msg_str;
    guint32      len;
    gint         ett_tree;
    int          hf_idx;
    void(*msg_fcn_p)(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len);
    guint8       oct;

    len = tvb_reported_length(tvb);

    /* Message type IE*/
    oct = tvb_get_guint8(tvb, offset);
    msg_fcn_p = NULL;
    ett_tree = -1;
    hf_idx = -1;
    msg_str = NULL;

    get_nas_5gsmm_msg_params(oct, &msg_str, &ett_tree, &hf_idx, &msg_fcn_p);

    if (msg_str) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, msg_str);
    }
    else {
        proto_tree_add_expert_format(tree, pinfo, &ei_nas_5gs_mm_unknown_msg_type, tvb, offset, 1, "Unknown Message Type 0x%02x", oct);
        return;
    }

    /*
    * Add NAS message name
    */
    proto_tree_add_item(tree, hf_idx, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /*
    * decode elements
    */
    if (msg_fcn_p == NULL)
    {
        if (tvb_reported_length_remaining(tvb, offset)) {
            proto_tree_add_item(tree, hf_nas_5gs_msg_elems, tvb, offset, len - offset, ENC_NA);
        }
    }
    else
    {
        (*msg_fcn_p)(tvb, tree, pinfo, offset, len - offset);
    }

}


static int
dissect_nas_5gs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{

    proto_item *item;
    proto_tree *nas_5gs_tree;
    int offset = 0;
    guint32 epd;

    /* make entry in the Protocol column on summary display */
    col_append_sep_str(pinfo->cinfo, COL_PROTOCOL, "/", "NAS-5GS");

    item = proto_tree_add_item(tree, proto_nas_5gs, tvb, 0, -1, ENC_NA);
    nas_5gs_tree = proto_item_add_subtree(item, ett_nas_5gs);

    /* Extended protocol discriminator  octet 1 */
    proto_tree_add_item_ret_uint(nas_5gs_tree, hf_nas_5gs_epd, tvb, offset, 1, ENC_BIG_ENDIAN, &epd);
    offset++;
    /* Security header type associated with a spare half octet; or
     * PDU session identity octet 2
     */
    switch (epd) {
    case TGPP_PD_5GMM:
        /* 9.5  Spare half octet
        * Bits 5 to 8 of the second octet of every 5GMM message contains the spare half octet
        * which is filled with spare bits set to zero.
        */
        proto_tree_add_item(nas_5gs_tree, hf_nas_5gs_spare_half_octet, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(nas_5gs_tree, hf_nas_5gs_security_header_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    case TGPP_PD_5GSM:
        /* 9.4  PDU session identity
        * Bits 1 to 8 of the second octet of every 5GSM message contain the PDU session identity IE.
        * The PDU session identity and its use to identify a message flow are defined in 3GPP TS 24.007
        */
        proto_tree_add_item(nas_5gs_tree, hf_nas_5gs_pdu_session_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    default:
        proto_tree_add_expert_format(nas_5gs_tree, pinfo, &ei_nas_5gs_unknown_pd, tvb, offset, -1, "Not a NAS 5GS PD %u (%s)",
            epd, val_to_str_const(epd, nas_5gs_epd_vals, "Unknown"));
        break;

    }
    offset++;

    /* 9.6  Procedure transaction identity
     * Bits 1 to 8 of the third octet of every 5GSM message contain the procedure transaction identity.
     * The procedure transaction identity and its use are defined in 3GPP TS 24.007
     * XXX Only 5GSM ?
     */
    proto_tree_add_item(nas_5gs_tree, hf_nas_5gs_proc_trans_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    switch (epd) {
    case TGPP_PD_5GMM:
        /* 5GS mobility management messages */
        disect_nas_5gs_mm_msg(tvb, pinfo, nas_5gs_tree, offset);
        break;
    case TGPP_PD_5GSM:
        /* 5GS session management messages. */
        dissect_nas_5gs_sm_msg(tvb, pinfo, nas_5gs_tree, offset);
        break;
    default:
        DISSECTOR_ASSERT_NOT_REACHED();
        break;
    }

    return tvb_reported_length(tvb);
}

void
proto_register_nas_5gs(void)
{

    /* List of fields */

    static hf_register_info hf[] = {
        { &hf_nas_5gs_epd,
        { "Extended protocol discriminator",   "nas_5gs.epd",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_epd_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_spare_b7,
        { "Spare",   "nas_5gs.spare_b7",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_spare_b6,
        { "Spare",   "nas_5gs.spare_b6",
            FT_UINT8, BASE_DEC, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_spare_b5,
        { "Spare",   "nas_5gs.spare_b5",
            FT_UINT8, BASE_DEC, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_spare_b4,
        { "Spare",   "nas_5gs.spare_b4",
            FT_UINT8, BASE_DEC, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_spare_b3,
        { "Spare",   "nas_5gs.spare_b3",
            FT_UINT8, BASE_DEC, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_spare_b2,
        { "Spare",   "nas_5gs.spare_b2",
            FT_UINT8, BASE_DEC, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_spare_b1,
        { "Spare",   "nas_5gs.spare_b1",
            FT_UINT8, BASE_DEC, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_security_header_type,
        { "Security header type",   "nas_5gs.security_header_type",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_security_header_type_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_msg_type,
        { "Message type",   "nas_5gs.mm.message_type",
        FT_UINT8, BASE_HEX | BASE_EXT_STRING, &nas_5gs_mm_msg_strings_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_msg_type,
        { "Message type",   "nas_5gs.sm.message_type",
        FT_UINT8, BASE_HEX | BASE_EXT_STRING, &nas_5gs_sm_msg_strings_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_common_elem_id,
            { "Element ID", "nas_5gs.common.elem_id",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_elem_id,
            { "Element ID", "nas_5gs.mm.elem_id",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_elem_id,
            { "Element ID", "nas_5gs.sm.elem_id",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_proc_trans_id,
        { "Procedure transaction identity",   "nas_5gs.proc_trans_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_spare_half_octet,
        { "Spare Half Octet",   "nas_5gs.spare_half_octet",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_session_id,
        { "PDU session identity",   "nas_5gs.pdu_session_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_msg_elems,
        { "Message Elements", "nas_5gs.message_elements",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_for,
        { "Follow-On Request bit (FOR)",   "nas_5gs.mm.for",
            FT_BOOLEAN, 8, TFS(&nas_5gs_for_tfs), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5gs_reg_type,
        { "5GS registration type",   "nas_5gs.mm.5gs_reg_type",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_registration_type_values), 0x07,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_tsc,
        { "Type of security context flag (TSC)",   "nas_5gs.mm.tsc",
            FT_BOOLEAN, 8, TFS(&nas_5gs_mm_tsc_tfs), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_nas_key_set_id,
        { "NAS key set identifier",   "nas_5gs.mm.nas_key_set_id",
            FT_UINT8, BASE_DEC, NULL, 0x03,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5gmm_cause,
        { "5GMM cause",   "nas_5gs.mm.5gmm_cause",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_cause_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_pld_cont_type,
        { "5GMM cause",   "nas_5gs.mm.pld_cont_type",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_pld_cont_type_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_sst,
        { "Slice/service type (SST)",   "nas_5gs.mm.sst",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_sd,
        { "Slice differentiator (SD)",   "nas_5gs.mm.mm_sd",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_mapped_conf_sst,
        { "Mapped configured SST",   "nas_5gs.mm.mapped_conf_sst",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_mapped_conf_ssd,
        { "Mapped configured SD",   "nas_5gs.mm.mapped_conf_ssd",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_switch_off,
        { "Switch off",   "nas_5gs.mm.switch_off",
            FT_BOOLEAN, 8, TFS(&nas_5gs_mm_switch_off_tfs), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_re_reg_req,
        { "Re-registration required",   "nas_5gs.mm.re_reg_req",
            FT_BOOLEAN, 8, TFS(&nas_5gs_mm_re_reg_req_tfs), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_acc_type,
        { "Access type",   "nas_5gs.mm.acc_type",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_acc_type_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_dnn,
        { "DNN", "nas_5gs.mm.dnn",
            FT_STRING, BASE_NONE, NULL,0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_hash_amf,
        { "HashAMF",   "nas_5gs.mm.hash_amf",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_raai_b0,
        { "Registration Area Allocation Indication (RAAI)",   "nas_5gs.mm.raai_b0",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_raai), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_conf_upd_ind_ack_b0,
        { "Acknowledgement",   "nas_5gs.mm.conf_upd_ind.ack",
            FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_conf_upd_ind_red_b1,
        { "Registration",   "nas_5gs.mm.conf_upd_ind.red",
            FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_nas_sec_algo_enc,
        { "Type of ciphering algorithm",   "nas_5gs.mm.nas_sec_algo_enc",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_type_of_enc_algo_vals), 0xf0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_nas_sec_algo_ip,
        { "Type of integrity protection algorithm",   "nas_5gs.mm.nas_sec_algo_ip",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_type_of_ip_algo_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_nonceamf,
        { "NonceAMF",   "nas_5gs.mm.nonceamf",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_s1_mode_b0,
        { "S1 mode",   "nas_5gs.mm.s1_mode_b0",
            FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_type_id,
        { "Type of identity",   "nas_5gs.mm.type_id",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_type_id_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_odd_even,
        { "Odd/even indication","nas_5gs.mm.odd_even",
            FT_BOOLEAN, 8, TFS(&nas_5gs_odd_even_tfs), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_length,
        { "Length",   "nas_5gs.mm.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_pdu_ses_id,
        { "PDU session identity",   "nas_5gs.mm.pdu_ses_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_old_pdu_ses_id,
        { "Old PDU session identity",   "nas_5gs.mm.old_pdu_ses_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_pld_cont,
        { "Payload container",   "nas_5gs.mm.pld_cont",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_all_acc_b1b0,
        { "Allowed accesses",   "nas_5gs.mm.all_acc_b1b0",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_all_acc_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_sup_acc_b1b0,
        { "Supported accesses",   "nas_5gs.mm.sup_acc_b1b0",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_sup_acc_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_req_type,
        { "Request type",   "nas_5gs.mm.req_typ",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_req_type_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_serv_type,
        { "Service type",   "nas_5gs.mm.serv_type",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_serv_type_vals), 0x07,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_ea0,
        { "5G-EA0","nas_5gs.mm.5g_ea0",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_128_5g_ea1,
        { "128-5G-EA1","nas_5gs.mm.128_5g_ea1",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_128_5g_ea2,
        { "128-5G-EA2","nas_5gs.mm.128_5g_ea2",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_128_5g_ea3,
        { "128-5G-EA3","nas_5gs.mm.128_5g_ea3",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_ea4,
        { "5G-EA4","nas_5gs.mm.5g_ea4",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_ea5,
        { "5G-EA5","nas_5gs.mm.5g_ea5",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_ea6,
        { "5G-EA6","nas_5gs.mm.5g_ea6",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_ea7,
        { "5G-EA7","nas_5gs.mm.5g_ea7",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_ia0,
        { "EIA0","nas_5gs.mm.ia0",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_128_ia1,
        { "128-EIA1","nas_5gs.mm.5g_128_ia1",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_128_ia2,
        { "128-EIA2","nas_5gs.mm.5g_128_ia2",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_128_ia3,
        { "128-EIA3","nas_5gs.mm.5g_128_ia4",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_ia4,
        { "EIA4","nas_5gs.mm.5g_128_ia4",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_ia5,
        { "EIA5","nas_5gs.mm.5g_ia5",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_ia6,
        { "EIA6","nas_5gs.mm.5g_ia6",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_ia7,
        { "EIA7","nas_5gs.mm.5g_ia7",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_eea0,
        { "EEA0","nas_5gs.mm.eea0",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_128eea1,
        { "128-EEA1","nas_5gs.mm.128eea1",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_128eea2,
        { "128-EEA2","nas_5gs.mm.128eea2",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_eea3,
        { "128-EEA3","nas_5gs.mm.eea3",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_eea4,
        { "EEA4","nas_5gs.mm.eea4",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_eea5,
        { "EEA5","nas_5gs.mm.eea5",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_eea6,
        { "EEA6","nas_5gs.mm.eea6",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_eea7,
        { "EEA7","nas_5gs.mm.eea7",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_eia0,
        { "EIA0","nas_5gs.mm.eia0",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_128eia1,
        { "128-EIA1","nas_5gs.mm.128eia1",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_128eia2,
        { "128-EIA2","nas_5gs.mm.128eia2",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_eia3,
        { "128-EIA3","nas_5gs.mm.eia3",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_eia4,
        { "EIA4","nas_5gs.mm.eia4",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_eia5,
        { "EIA5","nas_5gs.mm.eia5",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_eia6,
        { "EIA6","nas_5gs.mm.eia6",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_eia7,
        { "EIA7","nas_5gs.mm.eia7",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_s1_mode_reg_b0,
        { "S1 mode reg","nas_5gs.mm.s1_mode_reg_b0",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_mm_s1_mod), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_pdu_session_type,
        { "PDU session type",   "nas_5gs.sm.pdu_session_type",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_pdu_session_type_values), 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_0_b0,
        { "Spare","nas_5gs.pdu_ses_sts_psi_0_b0",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_1_b1,
        { "Spare","nas_5gs.pdu_ses_sts_psi_1_b1",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_2_b2,
        { "Spare","nas_5gs.pdu_ses_sts_psi_2_b2",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_3_b3,
        { "PSI(3)","nas_5gs.pdu_ses_sts_psi_3_b3",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_sts_psi), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_4_b4,
        { "PSI(4)","nas_5gs.pdu_ses_sts_psi_4_b4",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_sts_psi), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_5_b5,
        { "PSI(5)","nas_5gs.pdu_ses_sts_psi_5_b5",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_sts_psi), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_6_b6,
        { "PSI(6)","nas_5gs.pdu_ses_sts_psi_6_b6",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_sts_psi), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_7_b7,
        { "PSI(7)","nas_5gs.pdu_ses_sts_psi_7_b7",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_sts_psi), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_8_b0,
        { "PSI(8)","nas_5gs.pdu_ses_sts_psi_8_b0",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_sts_psi), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_9_b1,
        { "PSI(9)","nas_5gs.pdu_ses_sts_psi_9_b1",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_sts_psi), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_10_b2,
        { "PSI(10)","nas_5gs.pdu_ses_sts_psi_10_b2",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_sts_psi), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_11_b3,
        { "PSI(11)","nas_5gs.pdu_ses_sts_psi_11_b3",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_sts_psi), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_12_b4,
        { "PSI(12)","nas_5gs.pdu_ses_sts_psi_12_b4",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_sts_psi), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_13_b5,
        { "PSI(13)","nas_5gs.pdu_ses_sts_psi_13_b5",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_sts_psi), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_14_b6,
        { "PSI(14)","nas_5gs.pdu_ses_sts_psi_14_b6",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_sts_psi), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_15_b7,
        { "PSI(15)","nas_5gs.pdu_ses_sts_psi_15_b7",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_sts_psi), 0x80,
            NULL, HFILL }
        },

        { &hf_nas_5gs_ul_data_sts_psi_0_b0,
        { "Spare","nas_5gs.ul_data_sts_psi_0_b0",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_1_b1,
        { "Spare","nas_5gs.ul_data_sts_psi_1_b1",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_2_b2,
        { "Spare","nas_5gs.ul_data_sts_psi_2_b2",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_3_b3,
        { "PSI(3)","nas_5gs.ul_data_sts_psi_3_b3",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_ul_data_sts_psi), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_4_b4,
        { "PSI(4)","nas_5gs.ul_data_sts_psi_4_b4",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_ul_data_sts_psi), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_5_b5,
        { "PSI(5)","nas_5gs.ul_data_sts_psi_5_b5",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_ul_data_sts_psi), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_6_b6,
        { "PSI(6)","nas_5gs.ul_data_sts_psi_6_b6",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_ul_data_sts_psi), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_7_b7,
        { "PSI(7)","nas_5gs.ul_data_sts_psi_7_b7",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_ul_data_sts_psi), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_8_b0,
        { "PSI(8)","nas_5gs.ul_data_sts_psi_8_b0",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_ul_data_sts_psi), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_9_b1,
        { "PSI(9)","nas_5gs.ul_data_sts_psi_9_b1",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_ul_data_sts_psi), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_10_b2,
        { "PSI(10)","nas_5gs.ul_data_sts_psi_10_b2",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_ul_data_sts_psi), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_11_b3,
        { "PSI(11)","nas_5gs.ul_data_sts_psi_11_b3",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_ul_data_sts_psi), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_12_b4,
        { "PSI(12)","nas_5gs.ul_data_sts_psi_12_b4",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_ul_data_sts_psi), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_13_b5,
        { "PSI(13)","nas_5gs.ul_data_sts_psi_13_b5",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_ul_data_sts_psi), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_14_b6,
        { "PSI(14)","nas_5gs.ul_data_sts_psi_14_b6",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_ul_data_sts_psi), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_15_b7,
        { "PSI(15)","nas_5gs.ul_data_sts_psi_15_b7",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_ul_data_sts_psi), 0x80,
            NULL, HFILL }
        },

        { &hf_nas_5gs_sm_sc_mode,
        { "SSC mode",   "nas_5gs.sm.sc_mode",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_sc_mode_values), 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_rqos_b0,
        { "Reflective QoS(RqoS)",   "nas_5gs.sm.rqos",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_5gsm_cause,
        { "5GSM cause",   "nas_5gs.sm.5gsm_cause",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_sm_cause_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_pdu_ses_type,
        { "PDU session type",   "nas_5gs.sm.pdu_ses_type",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_sm_pdu_ses_type_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_pdu_addr_inf_ipv4,
        { "PDU address information", "nas_5gs.sm.pdu_addr_inf_ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_pdu_addr_inf_ipv6,
        { "PDU address information", "nas_5gs.sm.pdu_addr_inf_ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_qos_rule_id,
        { "QoS rule identifier",   "nas_5gs.sm.qos_rule_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_length,
        { "Length",   "nas_5gs.sm.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_rop,
        { "Rule operation code",   "nas_5gs.sm.rop",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_rule_operation_code_values), 0xe0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_dqr,
        { "DQR",   "nas_5gs.sm.dqr",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_sm_dqr), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_nof_pkt_filters,
        { "Number of packet filters",   "nas_5gs.sm.nof_pkt_filters",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_pkt_flt_dir,
        { "Packet filter direction",   "nas_5gs.sm.pkt_flt_dir",
            FT_UINT8, BASE_DEC, NULL, 0x30,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_pkt_flt_id,
        { "Packet filter identifier",   "nas_5gs.sm.pkt_flt_id",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_pf_len,
        { "Length",   "nas_5gs.sm.pf_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_pf_type,
        { "Packet filter component type",   "nas_5gs.sm.pf_type",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_sm_pf_type_values), 0x0,
            NULL, HFILL }
        },
        { &nas_5gs_sm_unit_for_session_ambr_dl,
        { "Unit for Session-AMBR for downlink",   "nas_5gs.sm.unit_for_session_ambr_dl",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_sm_unit_for_session_ambr_values), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_session_ambr_dl,
        { "Session-AMBR for downlink",   "nas_5gs.sm.session_ambr_dl",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &nas_5gs_sm_unit_for_session_ambr_ul,
        { "Unit for Session-AMBR for uplink",   "nas_5gs.sm.unit_for_session_ambr_ul",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_sm_unit_for_session_ambr_values), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_session_ambr_ul,
        { "Session-AMBR for uplink",   "nas_5gs.sm.session_ambr_ul",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
    };

    guint     i;
    guint     last_offset;

    /* Setup protocol subtree array */
#define NUM_INDIVIDUAL_ELEMS    4
    gint *ett[NUM_INDIVIDUAL_ELEMS +
        NUM_NAS_5GS_COMMON_ELEM +
        NUM_NAS_5GS_MM_MSG + NUM_NAS_5GS_MM_ELEM +
        NUM_NAS_5GS_SM_MSG + NUM_NAS_5GS_SM_ELEM
    ];

    ett[0] = &ett_nas_5gs;
    ett[1] = &ett_nas_5gs_mm_nssai;
    ett[2] = &ett_nas_5gs_mm_pdu_ses_id;
    ett[3] = &ett_nas_5gs_sm_qos_rules;

    last_offset = NUM_INDIVIDUAL_ELEMS;

    for (i = 0; i < NUM_NAS_5GS_COMMON_ELEM; i++, last_offset++)
    {
        ett_nas_5gs_common_elem[i] = -1;
        ett[last_offset] = &ett_nas_5gs_common_elem[i];
    }

    /* MM */
    for (i = 0; i < NUM_NAS_5GS_MM_MSG; i++, last_offset++)
    {
        ett_nas_5gs_mm_msg[i] = -1;
        ett[last_offset] = &ett_nas_5gs_mm_msg[i];
    }

    for (i = 0; i < NUM_NAS_5GS_MM_ELEM; i++, last_offset++)
    {
        ett_nas_5gs_mm_elem[i] = -1;
        ett[last_offset] = &ett_nas_5gs_mm_elem[i];
    }

    for (i = 0; i < NUM_NAS_5GS_SM_MSG; i++, last_offset++)
    {
        ett_nas_5gs_sm_msg[i] = -1;
        ett[last_offset] = &ett_nas_5gs_sm_msg[i];
    }

    for (i = 0; i < NUM_NAS_5GS_SM_ELEM; i++, last_offset++)
    {
        ett_nas_5gs_sm_elem[i] = -1;
        ett[last_offset] = &ett_nas_5gs_sm_elem[i];
    }

    static ei_register_info ei[] = {
    { &ei_nas_5gs_extraneous_data, { "nas_5gs.extraneous_data", PI_PROTOCOL, PI_NOTE, "Extraneous Data, dissector bug or later version spec(report to wireshark.org)", EXPFILL }},
    { &ei_nas_5gs_unknown_pd,{ "nas_5gs.unknown_pd", PI_PROTOCOL, PI_ERROR, "Unknown protocol discriminator", EXPFILL } },
    { &ei_nas_5gs_mm_unknown_msg_type,{ "nas_5gs.mm.unknown_msg_type", PI_PROTOCOL, PI_WARN, "Unknown Message Type", EXPFILL } },
    { &ei_nas_5gs_sm_unknown_msg_type,{ "nas_5gs.sm.unknown_msg_type", PI_PROTOCOL, PI_WARN, "Unknown Message Type", EXPFILL } },
    { &ei_nas_5gs_msg_not_dis,{ "nas_5gs.msg_not_dis", PI_PROTOCOL, PI_WARN, "MSG IEs not dissected yet", EXPFILL } },
    { &ei_nas_5gs_ie_not_dis,{ "nas_5gs.ie_not_dis", PI_PROTOCOL, PI_WARN, "IE not dissected yet", EXPFILL } },
    { &ei_nas_5gs_missing_mandatory_elemen,{ "nas_5gs.missing_mandatory_element", PI_PROTOCOL, PI_ERROR, "Missing Mandatory element, rest of dissection is suspect", EXPFILL } },
    { &ei_nas_5gs_dnn_too_long,{ "nas_5gs.dnn_to_long", PI_PROTOCOL, PI_ERROR, "DNN encoding has more than 100 octets", EXPFILL } },
    { &ei_nas_5gs_unknown_value,{ "nas_5gs.unknown_value", PI_PROTOCOL, PI_ERROR, "Value not according to (decoded)specification", EXPFILL } },
    { &ei_nas_5gs_num_pkt_flt,{ "nas_5gs.num_pkt_flt", PI_PROTOCOL, PI_ERROR, "num_pkt_flt != 0", EXPFILL } },
    { &ei_nas_5gs_not_diss,{ "nas_5gs.not_diss", PI_PROTOCOL, PI_NOTE, "Not dissected yet", EXPFILL } },
    };

    expert_module_t* expert_nas_5gs;

    /* Register protocol */
    proto_nas_5gs = proto_register_protocol(PNAME, PSNAME, PFNAME);
    /* Register fields and subtrees */
    proto_register_field_array(proto_nas_5gs, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_nas_5gs = expert_register_protocol(proto_nas_5gs);
    expert_register_field_array(expert_nas_5gs, ei, array_length(ei));

    /* Register dissector */
    register_dissector(PFNAME, dissect_nas_5gs, proto_nas_5gs);

}

void
proto_reg_handoff_nas_5gs(void)
{
    eap_handle = find_dissector("eap");
    nas_eps_handle = find_dissector("nas-eps");
    nas_eps_plain_handle = find_dissector("nas-eps_plain");

}

/*
* Editor modelines
*
* Local Variables:
* c-basic-offset: 4
* tab-width: 8
* indent-tabs-mode: nil
* End:
*
* ex: set shiftwidth=4 tabstop=8 expandtab:
* :indentSize=4:tabSize=8:noTabs=true:
*/
