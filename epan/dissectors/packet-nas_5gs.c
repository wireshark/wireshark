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
* References: 3GPP TS 24.501 0.3.1 2018-02-09
*/

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

#include "packet-gsm_a_common.h"

void proto_register_nas_5gs(void);
void proto_reg_handoff_nas_5gs(void);

#define PNAME  "Non-Access-Stratum 5GS (NAS)PDU"
#define PSNAME "NAS-5GS"
#define PFNAME "nas-5gs"

static int proto_nas_5gs = -1;

int hf_nas_5gs_common_elem_id = -1;
int hf_nas_5gs_mm_elem_id = -1;
int hf_nas_5gs_sm_elem_id = -1;

static int hf_nas_5gs_epd = -1;
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
static int hf_nas_5gs_mm_switch_off = -1;
static int hf_nas_5gs_mm_re_reg_req = -1;
static int hf_nas_5gs_mm_acc_type = -1;


static int ett_nas_5gs = -1;

static expert_field ei_nas_5gs_extraneous_data = EI_INIT;
static expert_field ei_nas_5gs_unknown_pd = EI_INIT;
static expert_field ei_nas_5gs_mm_unknown_msg_type = EI_INIT;
static expert_field ei_nas_5gs_sm_unknown_msg_type = EI_INIT;
static expert_field ei_nas_5gs_msg_not_dis = EI_INIT;
static expert_field ei_nas_5gs_ie_not_dis = EI_INIT;
static expert_field ei_nas_eps_missing_mandatory_elemen = EI_INIT;

/*
static const value_string nas_5gs_security_header_type_vals[] = {
    { 0,    "Plain NAS message, not security protected"},
    { 1,    "Integrity protected"},
    { 2,    "Integrity protected and ciphered"},
    { 3,    "Integrity protected with new 5GS security context"},
    { 4,    "Integrity protected and ciphered with new 5GS security context"},
    { 0,    NULL }
};
*/

#define TGPP_PD_5GMM 0x0e
#define TGPP_PD_5GSM 0x1e

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
    { TGPP_PD_5GMM,     "5G mobility management messages" },
    { TGPP_PD_5GSM,     "5G session management messages" },
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
static guint16
de_nas_5gs_pdu_ses_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 * 9.8.2.3    Uplink data status
 */
static guint16
de_nas_5gs_ul_data_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}


/*
 * 9.8.3    5GS mobility management (5GMM) information elements
 */

 /*
  * 9.8.3.1    5GMM capability
  */
static guint16
de_nas_5gs_mm_5gmm_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
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
static guint16
de_nas_5gs_mm_5gs_mobile_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    /* Length of 5GS mobile identity contents   octet 2 */
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

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
/*
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
 */

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
de_nas_5gs_mm_conf_upd_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 *   9.8.3.11    Daylight saving time
 */
static guint16
de_nas_5gs_mm_dlgt_saving_time(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

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
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 *   9.8.3.14    EAP message
 */
static guint16
de_nas_5gs_mm_eap_msg(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

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
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

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
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 *   9.8.3.18    IMEISV request
 */
static guint16
de_nas_5gs_mm_imeisv_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

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
static guint16
de_nas_5gs_mm_mico_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
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
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 *   9.8.3.24    NAS security algorithms
 */
static guint16
de_nas_5gs_mm_nas_sec_algo(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 *   9.8.3.25    NAS security parameters to NG-RAN
 */
static guint16
de_nas_5gs_mm_nas_sec_par_ng_ran(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 *   9.8.3.26    Network name
 */
static guint16
de_nas_5gs_mm_nw_name(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

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
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

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
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 *   9.8.3.30    Payload container
 */
static guint16
de_nas_5gs_mm_pld_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

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
de_nas_5gs_mm_old_pdu_ses_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
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
de_nas_5gs_mm_s_nssai(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

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

static guint16
de_nas_5gs_mm_sms_all(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len _U_,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, 1);

    return 1;
}

/*
 *     9.8.3.41    SMS requested
 */

static guint16
de_nas_5gs_mm_sms_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 *     9.8.3.42    Request type
 */

static guint16
de_nas_5gs_mm_req_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 *     9.8.3.43    Service type
 */

static guint16
de_nas_5gs_mm_serv_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
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
de_nas_5gs_mm_ue_sec_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 *     9.8.3.49    UE status
 */

static guint16
de_nas_5gs_mm_ue_sts(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 * 9.8.4    5GS session management (5GSM) information elements
 */

/*
 *     9.8.4.1    5GSM cause
 */

static guint16
de_nas_5gs_sm_5gsm_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 *     9.8.4.2    Extended protocol configuration options
 */

static guint16
de_nas_5gs_sm_ext_prot_conf_opt(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 *     9.8.4.3    GPRS timer
 */

static guint16
de_nas_5gs_sm_gprs_timer(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 *     9.8.4.4    PDU address
 */

static guint16
de_nas_5gs_sm_pdu_address(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 *     9.8.4.5    PDU session type
 */

static guint16
de_nas_5gs_sm_pdu_session_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 *     9.8.4.6    QoS rules
 */

static guint16
de_nas_5gs_sm_qos_rules(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 *      9.8.4.7    Session-AMBR
 */

static guint16
de_nas_5gs_sm_session_ambr(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 *      9.8.4.8    SM PDU DN request container
 */

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

static guint16
de_nas_5gs_sm_ssc_mode(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 *       9.8.4.10    5GSM capability
 */

static guint16
de_nas_5gs_sm_5gsm_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    guint32 offset, guint len,
    gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
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
    DE_NAS_5GS_MM_5GMM_CAP,                  /* 9.8.3.1    5GMM capability*/
    DE_NAS_5GS_MM_5GMM_CAUSE,                /* 9.8.3.2    5GMM cause*/
    DE_NAS_5GS_MM_5GS_MOBILE_ID,             /* 9.8.3.3    5GS mobile identity*/
    DE_NAS_5GS_MM_5GS_NW_FEAT_SUP,           /* 9.8.3.4    5GS network feature support*/
    DE_NAS_5GS_MM_5GS_REG_RES,               /* 9.8.3.5    5GS registration result*/
    DE_NAS_5GS_MM_5GS_REG_TYPE,              /* 9.8.3.6    5GS registration type*/
    DE_NAS_5GS_MM_ALLOW_PDU_SES_STS,         /* 9.8.3.7    Allowed PDU session status*/
    DE_NAS_5GS_MM_AUT_PAR_AUTN,              /* 9.8.3.8    Authentication parameter AUTN*/
    DE_NAS_5GS_MM_AUT_PAR_RAND,              /* 9.8.3.9    Authentication parameter RAND*/
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
        de_nas_5gs_mm_dlgt_saving_time,          /* 9.8.3.11    Daylight saving time*/
        de_nas_5gs_mm_de_reg_type,               /* 9.8.3.12    De-registration type*/
        de_nas_5gs_mm_dnn,                       /* 9.8.3.13    DNN*/
        de_nas_5gs_mm_eap_msg,                   /* 9.8.3.14    EAP message*/
        de_nas_5gs_mm_eps_nas_msg_cont,          /* 9.8.3.15    EPS NAS message container*/
        NULL,                                    /* 9.8.3.16    GPRS timer 2*/
        de_nas_5gs_mm_hashamf,                   /* 9.8.3.17    HashAMF*/
        de_nas_5gs_mm_imeisv_req,                /* 9.8.3.18    IMEISV request*/
        de_nas_5gs_mm_ladn_inf,                  /* 9.8.3.19    LADN information*/
        de_nas_5gs_mm_msg_auth_code,             /* 9.8.3.20    Message authentication code*/
        de_nas_5gs_mm_mico_ind,                  /* 9.8.3.21    MICO indication*/
        de_nas_5gs_mm_nas_key_set_id,            /* 9.8.3.22    NAS key set identifier*/
        de_nas_5gs_mm_nas_msg_cont,              /* 9.8.3.23    NAS message container*/
        de_nas_5gs_mm_nas_sec_algo,              /* 9.8.3.24    NAS security algorithms*/
        de_nas_5gs_mm_nas_sec_par_ng_ran,        /* 9.8.3.25    NAS security parameters to NG-RAN*/
        de_nas_5gs_mm_nw_name,                   /* 9.8.3.26    Network name*/
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
    DE_NAS_5GS_SM_5GSM_CAP,            /*  9.8.4.10    5GSM capability */
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
    { DE_NAS_5GS_SM_5GSM_CAP, "5GSM capability" },                                      /* 9.8.4.10    5GSM capability */

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
        de_nas_5gs_sm_ext_prot_conf_opt,    /* 9.8.4.2    Extended protocol configuration options */
        de_nas_5gs_sm_gprs_timer,           /* 9.8.4.3    GPRS timer */
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
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NAS_KEY_SET_ID, " - ngKSI", ei_nas_eps_missing_mandatory_elemen);

    /*21    Authentication parameter RAND (5G authentication challenge)    Authentication parameter RAND     9.8.3.9    O    TV    17*/
    ELEM_MAND_TV(0x21, GSM_A_PDU_TYPE_DTAP, DE_AUTH_PARAM_RAND, " - 5G authentication challenge", ei_nas_eps_missing_mandatory_elemen);
    /*20    Authentication parameter AUTN (5G authentication challenge)    Authentication parameter AUTN     9.8.3.8    O    TLV    18*/
    ELEM_MAND_TLV(0x20, GSM_A_PDU_TYPE_DTAP, DE_AUTH_PARAM_AUTN, " - 5G authentication challeng", ei_nas_eps_missing_mandatory_elemen);
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

    /*
    EAP message    EAP message     9.8.3.14    O    TLV-E    7-1503

    */
    ELEM_OPT_TLV_E(0x78, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_EAP_MSG, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.3    Authentication failure
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
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GMM_CAUSE, NULL, ei_nas_eps_missing_mandatory_elemen);


    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}
/*
 * 8.2.4    Authentication reject
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
 * 8.2.5 Registration request
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
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_REG_TYPE, NULL, ei_nas_eps_missing_mandatory_elemen);

    /*    ngKSI    NAS key set identifier 9.8.3.22    M    V    1*/
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NAS_KEY_SET_ID, " - ngKSI", ei_nas_eps_missing_mandatory_elemen);

    /*    Mobile identity    5GS mobile identity 9.8.3.3    M    LV    TBD*/
    ELEM_MAND_LV(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_MOBILE_ID, NULL, ei_nas_eps_missing_mandatory_elemen);

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

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.6    Registration accept
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
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_REG_RES, NULL, ei_nas_eps_missing_mandatory_elemen);

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


    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.7    Registration complete
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
* 8.2.8 Registration reject
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
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GMM_CAUSE, NULL, ei_nas_eps_missing_mandatory_elemen);

    /* 5F  T3346 value GPRS timer 2     9.8.3.16   O   TLV 3 */
    ELEM_OPT_TLV(0x5F, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3346 value");

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.9    UL NAS transport
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
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PLD_CONT_TYPE, NULL, ei_nas_eps_missing_mandatory_elemen);


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
* 8.2.10    DL NAS transport
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
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PLD_CONT_TYPE, NULL, ei_nas_eps_missing_mandatory_elemen);


    /*Payload container    Payload container    9.8.3.30    M    LV-E    3-65537*/
    /*PDU session ID    PDU session identity    9.4    C    V    1*/
    /*24    Additional information    Additional information    9.8.2.1    O    TLV    3-n*/


    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.11 De-registration request (UE originating de-registration)
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
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_DE_REG_TYPE, NULL, ei_nas_eps_missing_mandatory_elemen);

    /*5GS mobile identity    5GS mobile identity     9.8.3.3  M   TLV TBD*/

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

#if 0
Template:
/*
 * 8.2.2    Authentication response
 */
static void
nas_5gs_mm_authentication_resp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*

    */

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}
#endif


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

    { 0x49,    "Nout used in v 0.3.1"},
    { 0x4a,    "Nout used in v 0.3.1" },
    { 0x4b,    "Nout used in v 0.3.1" },

    { 0x4c,    "Service request"},
    { 0x4d,    "Service reject"},
    { 0x4e,    "Service accept"},

    { 0x4f,    "Nout used in v 0.3.1" },
    { 0x50,    "Nout used in v 0.3.1" },
    { 0x51,    "Nout used in v 0.3.1" },
    { 0x52,    "Nout used in v 0.3.1" },
    { 0x53,    "Nout used in v 0.3.1" },

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

    { 0x5f,    "Nout used in v 0.3.1" },
    { 0x60,    "Nout used in v 0.3.1" },
    { 0x61,    "Nout used in v 0.3.1" },
    { 0x62,    "Nout used in v 0.3.1" },
    { 0x63,    "Nout used in v 0.3.1" },

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
    nas_5gs_mm_registration_req,        /* 0x41    Registration request */
    nas_5gs_mm_registration_accept,     /* 0x42    Registration accept */
    nas_5gs_mm_registration_complete,   /* 0x43    Registration complete */
    nas_5gs_mm_registration_rej,        /* 0x44    Registration reject */
    nas_5gs_mm_de_reg_req_ue_orig,      /* 0x45    Deregistration request (UE originating) */
    nas_5gs_exp_not_dissected_yet,      /* 0x46    Deregistration accept (UE originating) */
    nas_5gs_exp_not_dissected_yet,      /* 0x47    Deregistration request (UE terminated) */
    nas_5gs_exp_not_dissected_yet,      /* 0x48    Deregistration accept (UE terminated) */

    nas_5gs_exp_not_dissected_yet,      /* 0x49    Nout used in v 0.3.1 */
    nas_5gs_exp_not_dissected_yet,      /* 0x4a    Nout used in v 0.3.1 */
    nas_5gs_exp_not_dissected_yet,      /* 0x4b    Nout used in v 0.3.1 */

    nas_5gs_exp_not_dissected_yet,      /* 0x4c    Service request */
    nas_5gs_exp_not_dissected_yet,      /* 0x4d    Service reject */
    nas_5gs_exp_not_dissected_yet,      /* 0x4e    Service accept */

    nas_5gs_exp_not_dissected_yet,      /* 0x4f    Nout used in v 0.3.1 */
    nas_5gs_exp_not_dissected_yet,      /* 0x50    Nout used in v 0.3.1 */
    nas_5gs_exp_not_dissected_yet,      /* 0x51    Nout used in v 0.3.1 */
    nas_5gs_exp_not_dissected_yet,      /* 0x52    Nout used in v 0.3.1 */
    nas_5gs_exp_not_dissected_yet,      /* 0x53    Nout used in v 0.3.1 */

    nas_5gs_exp_not_dissected_yet,      /* 0x54    Configuration update command */
    nas_5gs_exp_not_dissected_yet,      /* 0x55    Configuration update complete */
    nas_5gs_mm_authentication_req,      /* 0x56    Authentication request */
    nas_5gs_mm_authentication_resp,     /* 0x57    Authentication response */
    nas_5gs_mm_authentication_rej,      /* 0x58    Authentication reject */
    nas_5gs_mm_authentication_failure,  /* 0x59    Authentication failure */
    nas_5gs_exp_not_dissected_yet,      /* 0x5a    Identity request */
    nas_5gs_exp_not_dissected_yet,      /* 0x5b    Identity response */
    nas_5gs_exp_not_dissected_yet,      /* 0x5c    Security mode command */
    nas_5gs_exp_not_dissected_yet,      /* 0x5d    Security mode complete */
    nas_5gs_exp_not_dissected_yet,      /* 0x5e    Security mode reject */

    nas_5gs_exp_not_dissected_yet,      /* 0x5f    Nout used in v 0.3.1 */
    nas_5gs_exp_not_dissected_yet,      /* 0x60    Nout used in v 0.3.1 */
    nas_5gs_exp_not_dissected_yet,      /* 0x61    Nout used in v 0.3.1 */
    nas_5gs_exp_not_dissected_yet,      /* 0x62    Nout used in v 0.3.1 */
    nas_5gs_exp_not_dissected_yet,      /* 0x63    Nout used in v 0.3.1 */

    nas_5gs_exp_not_dissected_yet,      /* 0x64    5GMM status */
    nas_5gs_exp_not_dissected_yet,      /* 0x65    Notification */
    nas_5gs_mm_dl_nas_transp,           /* 0x66    DL NAS transport */
    nas_5gs_mm_ul_nas_transp,           /* 0x67    UL NAS transport */

    NULL,   /* NONE */

};


    /* 5GS session management messages */
    static const value_string nas_5gs_sm_message_type_vals[] = {

    { 0xc1,    "PDU session establishment request"},
    { 0xc2,    "PDU session establishment accept"},
    { 0xc3,    "PDU session establishment reject"},

    { 0xc4,    "PDU session authentication request"},
    { 0xc5,    "PDU session authentication accept"},

    { 0xc6,    "Nout used in v 0.3.1" },
    { 0xc7,    "Nout used in v 0.3.1" },
    { 0xc8,    "Nout used in v 0.3.1" },

    { 0xc9,    "PDU session modification request"},
    { 0xca,    "PDU session modification reject"},
    { 0xcb,    "PDU session modification command"},

    { 0xcc,    "Nout used in v 0.3.1" },

    { 0xcd,    "PDU session modification complete"},
    { 0xce,    "PDU session modification command reject"},

    { 0xcf,    "Nout used in v 0.3.1" },
    { 0xd0,    "Nout used in v 0.3.1" },

    { 0xd1,    "PDU session release request"},
    { 0xd2,    "PDU session release reject"},
    { 0xd3,    "PDU session release command"},
    { 0xd4,    "PDU session release complete"},

    { 0xd5,    "Nout used in v 0.3.1" },

    { 0xd6,    "5GSM status"},
    { 0,    NULL }
};
static value_string_ext nas_5gs_sm_msg_strings_ext = VALUE_STRING_EXT_INIT(nas_5gs_sm_message_type_vals);

#define NUM_NAS_5GS_SM_MSG (sizeof(nas_5gs_sm_message_type_vals)/sizeof(value_string))
static gint ett_nas_5gs_sm_msg[NUM_NAS_5GS_SM_MSG];

static void(*nas_5gs_sm_msg_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len) = {
    nas_5gs_exp_not_dissected_yet,         /* 0xc1     PDU session establishment request */
    nas_5gs_exp_not_dissected_yet,         /* 0xc2     PDU session establishment accept */
    nas_5gs_exp_not_dissected_yet,         /* 0xc3     PDU session establishment reject */

    nas_5gs_exp_not_dissected_yet,         /* 0xc4     PDU session authentication request */
    nas_5gs_exp_not_dissected_yet,         /* 0xc5     PDU session authentication accept */

    nas_5gs_exp_not_dissected_yet,         /* 0xc6     Nout used in v 0.3.1 */
    nas_5gs_exp_not_dissected_yet,         /* 0xc7     Nout used in v 0.3.1 */
    nas_5gs_exp_not_dissected_yet,         /* 0xc8     Nout used in v 0.3.1 */

    nas_5gs_exp_not_dissected_yet,         /* 0xc9     PDU session modification request */
    nas_5gs_exp_not_dissected_yet,         /* 0xca     PDU session modification reject */
    nas_5gs_exp_not_dissected_yet,         /* 0xcb     PDU session modification command */

    nas_5gs_exp_not_dissected_yet,         /* 0xcc     Nout used in v 0.3.1 */

    nas_5gs_exp_not_dissected_yet,         /* 0xcd     PDU session modification complete */
    nas_5gs_exp_not_dissected_yet,         /* 0xce     PDU session modification command reject */

    nas_5gs_exp_not_dissected_yet,         /* 0xcf     Nout used in v 0.3.1 */
    nas_5gs_exp_not_dissected_yet,         /* 0xd0     Nout used in v 0.3.1 */

    nas_5gs_exp_not_dissected_yet,         /* 0xd1     PDU session release request */
    nas_5gs_exp_not_dissected_yet,         /* 0xd2     PDU session release reject */
    nas_5gs_exp_not_dissected_yet,         /* 0xd3     PDU session release command */
    nas_5gs_exp_not_dissected_yet,         /* 0xd4     PDU session release complete */

    nas_5gs_exp_not_dissected_yet,         /* 0xd5     Nout used in v 0.3.1 */

    nas_5gs_exp_not_dissected_yet,         /* 0xd6     5GSM status */

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
        { &hf_nas_5gs_security_header_type,
        { "Security header type",   "nas_5gs.security_header_type",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
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
            FT_BOOLEAN, 8, TFS(&nas_5gs_for_tfs), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5gs_reg_type,
        { "5GS registration type",   "nas_5gs.mm.5gs_reg_type",
            FT_UINT8, BASE_DEC, NULL, 0x0,
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
    };

    guint     i;
    guint     last_offset;

    /* Setup protocol subtree array */
#define NUM_INDIVIDUAL_ELEMS    1
    gint *ett[NUM_INDIVIDUAL_ELEMS +
        NUM_NAS_5GS_COMMON_ELEM +
        NUM_NAS_5GS_MM_MSG + NUM_NAS_5GS_MM_ELEM +
        NUM_NAS_5GS_SM_MSG + NUM_NAS_5GS_SM_ELEM
    ];

    ett[0] = &ett_nas_5gs;

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
    { &ei_nas_eps_missing_mandatory_elemen,{ "nas_5gs.missing_mandatory_element", PI_PROTOCOL, PI_ERROR, "Missing Mandatory element, rest of dissection is suspect", EXPFILL } },
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
