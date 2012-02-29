/* packet-nas_eps.c
 * Routines for Non-Access-Stratum (NAS) protocol for Evolved Packet System (EPS) dissection
 *
 * Copyright 2008 - 2010, Anders Broman <anders.broman@ericsson.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * References: 3GPP TS 24.301 V9.6.0 (2011-03)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/asn1.h>

#include "packet-gsm_map.h"
#include "packet-gsm_a_common.h"
#include "packet-e212.h"
#include "packet-lcsap.h"

#define PNAME  "Non-Access-Stratum (NAS)PDU"
#define PSNAME "NAS-EPS"
#define PFNAME "nas-eps"

/* Initialize the protocol and registered fields */
static int proto_nas_eps = -1;

/* Dissector handles */
static dissector_handle_t gsm_a_dtap_handle;
static dissector_handle_t lpp_handle;

/* Forward declaration */
static void disect_nas_eps_esm_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);

static int hf_nas_eps_msg_emm_type = -1;
int hf_nas_eps_common_elem_id = -1;
int hf_nas_eps_emm_elem_id = -1;
static int hf_nas_eps_bearer_id = -1;
static int hf_nas_eps_spare_bits = -1;
static int hf_nas_eps_security_header_type = -1;
static int hf_nas_eps_msg_auth_code = -1;
static int hf_nas_eps_seq_no = -1;
static int hf_nas_eps_seq_no_short = -1;
static int hf_nas_eps_emm_ebi0 = -1;
static int hf_nas_eps_emm_ebi1 = -1;
static int hf_nas_eps_emm_ebi2 = -1;
static int hf_nas_eps_emm_ebi3 = -1;
static int hf_nas_eps_emm_ebi4 = -1;
static int hf_nas_eps_emm_ebi5 = -1;
static int hf_nas_eps_emm_ebi6 = -1;
static int hf_nas_eps_emm_ebi7 = -1;
static int hf_nas_eps_emm_ebi8 = -1;
static int hf_nas_eps_emm_ebi9 = -1;
static int hf_nas_eps_emm_ebi10 = -1;
static int hf_nas_eps_emm_ebi11 = -1;
static int hf_nas_eps_emm_ebi12 = -1;
static int hf_nas_eps_emm_ebi13 = -1;
static int hf_nas_eps_emm_ebi14 = -1;
static int hf_nas_eps_emm_ebi15 = -1;
static int hf_nas_eps_emm_dl_nas_cnt = -1;
static int hf_nas_eps_emm_nonce_mme = -1;
static int hf_nas_eps_emm_nonce = -1;
static int hf_nas_eps_emm_paging_id = -1;
static int hf_nas_eps_emm_eps_att_type = -1;
static int hf_nas_eps_emm_cs_lcs_type = -1;
static int hf_nas_eps_emm_epc_lcs_type = -1;
static int hf_nas_eps_emm_emc_bs_type = -1;
static int hf_nas_eps_emm_ims_vops_type = -1;
static int hf_nas_eps_emm_nas_key_set_id = -1;
static int hf_nas_eps_tsc = -1;
static int hf_nas_eps_emm_odd_even = -1;
static int hf_nas_eps_emm_type_of_id = -1;
static int hf_nas_eps_emm_mme_grp_id = -1;
static int hf_nas_eps_emm_imsi = -1;
static int hf_nas_eps_emm_imei = -1;
static int hf_nas_eps_emm_mme_code = -1;
static int hf_nas_eps_emm_m_tmsi = -1;
static int hf_nas_eps_esm_msg_cont = -1;
static int hf_nas_eps_esm_imeisv_req = -1;
static int hf_nas_eps_emm_toi = -1;
static int hf_nas_eps_emm_toc = -1;
static int hf_nas_eps_emm_EPS_attach_result = -1;
static int hf_nas_eps_emm_spare_half_octet = -1;
static int hf_nas_eps_emm_add_upd_res = -1;
static int hf_nas_eps_emm_add_upd_type = -1;
static int hf_nas_eps_emm_res = -1;
static int hf_nas_eps_emm_csfb_resp = -1;
static int hf_nas_eps_emm_cause = -1;
static int hf_nas_eps_emm_id_type2 = -1;
static int hf_nas_eps_emm_short_mac = -1;
static int hf_nas_eps_emm_tai_tol = -1;
static int hf_nas_eps_emm_tai_n_elem = -1;
static int hf_nas_eps_emm_tai_tac = -1;
static int hf_nas_eps_emm_eea0 = -1;
static int hf_nas_eps_emm_128eea1 = -1;
static int hf_nas_eps_emm_128eea2 = -1;
static int hf_nas_eps_emm_eea3 = -1;
static int hf_nas_eps_emm_eea4 = -1;
static int hf_nas_eps_emm_eea5 = -1;
static int hf_nas_eps_emm_eea6 = -1;
static int hf_nas_eps_emm_eea7 = -1;
static int hf_nas_eps_emm_eia0 = -1;
static int hf_nas_eps_emm_128eia1 = -1;
static int hf_nas_eps_emm_128eia2 = -1;
static int hf_nas_eps_emm_eia3 = -1;
static int hf_nas_eps_emm_eia4 = -1;
static int hf_nas_eps_emm_eia5 = -1;
static int hf_nas_eps_emm_eia6 = -1;
static int hf_nas_eps_emm_eia7 = -1;
static int hf_nas_eps_emm_uea0 = -1;
static int hf_nas_eps_emm_uea1 = -1;
static int hf_nas_eps_emm_uea2 = -1;
static int hf_nas_eps_emm_uea3 = -1;
static int hf_nas_eps_emm_uea4 = -1;
static int hf_nas_eps_emm_uea5 = -1;
static int hf_nas_eps_emm_uea6 = -1;
static int hf_nas_eps_emm_uea7 = -1;
static int hf_nas_eps_emm_ucs2_supp = -1;
static int hf_nas_eps_emm_uia1 = -1;
static int hf_nas_eps_emm_uia2 = -1;
static int hf_nas_eps_emm_uia3 = -1;
static int hf_nas_eps_emm_uia4 = -1;
static int hf_nas_eps_emm_uia5 = -1;
static int hf_nas_eps_emm_uia6 = -1;
static int hf_nas_eps_emm_uia7 = -1;
static int hf_nas_eps_emm_gea1 = -1;
static int hf_nas_eps_emm_gea2 = -1;
static int hf_nas_eps_emm_gea3 = -1;
static int hf_nas_eps_emm_gea4 = -1;
static int hf_nas_eps_emm_gea5 = -1;
static int hf_nas_eps_emm_gea6 = -1;
static int hf_nas_eps_emm_gea7 = -1;
static int hf_nas_eps_emm_lpp_cap = -1;
static int hf_nas_eps_emm_lcs_cap = -1;
static int hf_nas_eps_emm_1xsrvcc_cap = -1;
static int hf_nas_eps_emm_nf_cap = -1;
static int hf_nas_eps_emm_ue_ra_cap_inf_upd_need_flg;
static int hf_nas_eps_emm_ss_code = -1;
static int hf_nas_eps_emm_lcs_ind = -1;
static int hf_nas_eps_emm_gen_msg_cont_type = -1;
static int hf_nas_eps_emm_apn_ambr_ul = -1;
static int hf_nas_eps_emm_apn_ambr_dl = -1;
static int hf_nas_eps_emm_apn_ambr_ul_ext = -1;
static int hf_nas_eps_emm_apn_ambr_dl_ext = -1;
static int hf_nas_eps_emm_apn_ambr_ul_ext2 = -1;
static int hf_nas_eps_emm_apn_ambr_dl_ext2 = -1;

static int hf_nas_eps_emm_switch_off = -1;
static int hf_nas_eps_emm_detach_type_UL = -1;
static int hf_nas_eps_emm_detach_type_DL = -1;

static int hf_nas_eps_qci = -1;
static int hf_nas_eps_mbr_ul = -1;
static int hf_nas_eps_mbr_dl = -1;
static int hf_nas_eps_gbr_ul = -1;
static int hf_nas_eps_gbr_dl = -1;
static int hf_nas_eps_embr_ul = -1;
static int hf_nas_eps_embr_dl = -1;
static int hf_nas_eps_egbr_ul = -1;
static int hf_nas_eps_egbr_dl = -1;

static int hf_nas_eps_esm_cause = -1;
static int hf_nas_eps_esm_eit = -1;
static int hf_nas_eps_esm_lnkd_eps_bearer_id = -1;
static int hf_nas_eps_esm_notif_ind = -1;
static int hf_nas_eps_esm_pdn_type = -1;
static int hf_nas_eps_esm_pdn_ipv4 = -1;
static int hf_nas_eps_esm_pdn_ipv6_if_id = -1;

static int hf_nas_eps_esm_linked_bearer_id = -1;

static int hf_nas_eps_active_flg = -1;
static int hf_nas_eps_eps_update_result_value = -1;
static int hf_nas_eps_eps_update_type_value = -1;
static int hf_nas_eps_service_type = -1;

static int hf_nas_eps_nas_msg_cont = -1;
static int hf_nas_eps_gen_msg_cont = -1;

static int hf_nas_eps_cmn_add_info = -1;
static int hf_nas_eps_esm_request_type = -1;

/* ESM */
static int hf_nas_eps_msg_esm_type = -1;
int hf_nas_eps_esm_elem_id = -1;
static int hf_nas_eps_esm_proc_trans_id = -1;

/* Initialize the subtree pointers */
static int ett_nas_eps = -1;
static int ett_nas_eps_esm_msg_cont = -1;
static int ett_nas_eps_nas_msg_cont = -1;
static int ett_nas_eps_gen_msg_cont = -1;
static int ett_nas_eps_cmn_add_info = -1;

/* Global variables */
static packet_info *gpinfo;

guint8 eps_nas_gen_msg_cont_type = 0;

/* Table 9.8.1: Message types for EPS mobility management
 *  0   1   -   -   -   -   -   -       EPS mobility management messages
 */
static const value_string nas_msg_emm_strings[] = {
    { 0x41, "Attach request"},
    { 0x42, "Attach accept"},
    { 0x43, "Attach complete"},
    { 0x44, "Attach reject"},
    { 0x45, "Detach request"},
    { 0x46, "Detach accept"},

    { 0x48, "Tracking area update request"},
    { 0x49, "Tracking area update accept"},
    { 0x4a, "Tracking area update complete"},
    { 0x4b, "Tracking area update reject"},

    { 0x4c, "Extended service request"},
    { 0x4e, "Service reject"},

    { 0x50, "GUTI reallocation command"},
    { 0x51, "GUTI reallocation complete"},
    { 0x52, "Authentication request"},
    { 0x53, "Authentication response"},
    { 0x54, "Authentication reject"},
    { 0x5c, "Authentication failure"},
    { 0x55, "Identity request"},
    { 0x56, "Identity response"},
    { 0x5d, "Security mode command"},
    { 0x5e, "Security mode complete"},
    { 0x5f, "Security mode reject"},

    { 0x60, "EMM status"},
    { 0x61, "EMM information"},
    { 0x62, "Downlink NAS transport"},
    { 0x63, "Uplink NAS transport"},
    { 0x64, "CS Service notification"},
    { 0x68, "Downlink generic NAS transport"},
    { 0x69, "Uplink generic NAS transport"},
    { 0,    NULL }
};

/* Table 9.8.2: Message types for EPS session management */

static const value_string nas_msg_esm_strings[] = {
    { 0xc1, "Activate default EPS bearer context request"},
    { 0xc2, "Activate default EPS bearer context accept"},
    { 0xc3, "Activate default EPS bearer context reject"},
    { 0xc5, "Activate dedicated EPS bearer context request"},
    { 0xc6, "Activate dedicated EPS bearer context accept"},
    { 0xc7, "Activate dedicated EPS bearer context reject"},
    { 0xc9, "Modify EPS bearer context request"},
    { 0xca, "Modify EPS bearer context accept"},
    { 0xcb, "Modify EPS bearer context reject"},
    { 0xcd, "Deactivate EPS bearer context request"},
    { 0xce, "Deactivate EPS bearer context accept"},
    { 0xd0, "PDN connectivity request"},
    { 0xd1, "PDN connectivity reject"},
    { 0xd2, "PDN disconnect request"},
    { 0xd3, "PDN disconnect reject"},
    { 0xd4, "Bearer resource allocation request"},
    { 0xd5, "Bearer resource allocation reject"},
    { 0xd6, "Bearer resource modification request"},
    { 0xd7, "Bearer resource modification reject"},
    { 0xd9, "ESM information request"},
    { 0xda, "ESM information response"},
    { 0xdb, "Notification"},
    { 0xe8, "ESM status"},
    { 0,    NULL }
};

static const value_string security_header_type_vals[] = {
    { 0,    "Plain NAS message, not security protected"},
    { 1,    "Integrity protected"},
    { 2,    "Integrity protected and ciphered"},
    { 3,    "Integrity protected with new EPS security context"},
    { 4,    "Integrity protected and ciphered with new EPS security context"},
    { 5,    "Reserved"},
    { 6,    "Reserved"},
    { 7,    "Reserved"},
    { 8,    "Reserved"},
    { 9,    "Reserved"},
    { 10,   "Reserved"},
    { 11,   "Reserved"},
    { 12,   "Security header for the SERVICE REQUEST message "},
    { 13,   "These values are not used in this version of the protocol. If received they shall be interpreted as \"1100\""},
    { 14,   "These values are not used in this version of the protocol. If received they shall be interpreted as \"1100\""},
    { 15,   "These values are not used in this version of the protocol. If received they shall be interpreted as \"1100\""},
    { 0,    NULL }
};
static value_string_ext security_header_type_vals_ext = VALUE_STRING_EXT_INIT(security_header_type_vals);

const value_string nas_eps_common_elem_strings[] = {
    { 0x00, "Additional information" },                 /* 9.9.2.0  Additional information */
    { 0x00, "EPS bearer context status" },              /* 9.9.2.1  EPS bearer context status */
    { 0x00, "Location area identification" },           /* 9.9.2.2  Location area identification */
    { 0x00, "Mobile identity" },                        /* 9.9.2.3  Mobile identity */
    { 0x00, "Mobile station classmark 2" },             /* 9.9.2.4  Mobile station classmark 2 */
    { 0x00, "Mobile station classmark 3" },             /* 9.9.2.5  Mobile station classmark 3 */
    { 0x00, "NAS security parameters from E-UTRA" },    /* 9.9.2.6  NAS security parameters from E-UTRA */
    { 0x00, "NAS security parameters to E-UTRA" },      /* 9.9.2.7  NAS security parameters to E-UTRA */
    { 0x00, "PLMN list" },                              /* 9.9.2.8  PLMN list   */
                                                        /* 9.9.2.9  Spare half octet */
    { 0x00, "Supported codec list" },                   /* 9.9.2.10 Supported codec list */
    { 0, NULL }
};
/* Utility functions */
static guint16
calc_bitrate(guint8 value){
    guint16 return_value = value;

    if (value > 63 && value <= 127) {
        return_value = 64 + (value - 64) * 8;
    }
    else if (value > 127 && value <= 254) {
        return_value = 576 + (value - 128) * 64;
    }
    else if (value==0xff) {
        return_value = 0;
    }
    return return_value;
}
static guint32
calc_bitrate_ext(guint8 value){
    guint32 return_value = 0;

    if (value > 0 && value <= 0x4a) {
        return_value = 8600 + value * 100;
    }
    else if (value > 0x4a && value <= 0xba) {
        return_value = 16 + (value-0x4a);
    }
    else if (value > 0xba && value <= 0xfa) {
        return_value = 128 + (value-0xba)*2;
    }
    else {
        return_value = 256;
    }

    return return_value;
}

#define NUM_NAS_EPS_COMMON_ELEM (sizeof(nas_eps_common_elem_strings)/sizeof(value_string))
gint ett_nas_eps_common_elem[NUM_NAS_EPS_COMMON_ELEM];

typedef enum
{
    DE_EPS_CMN_ADD_INFO,                        /* 9.9.2.0  Additional information */
    DE_EPS_CMN_EPS_BE_CTX_STATUS,               /* 9.9.2.1  EPS bearer context status */
    DE_EPS_CMN_LOC_AREA_ID,                     /* 9.9.2.2  Location area identification */
    DE_EPS_CMN_MOB_ID,                          /* 9.9.2.3  Mobile identity */
    DE_EPS_MS_CM_2,                             /* 9.9.2.4  Mobile station classmark 2 */
    DE_EPS_MS_CM_3,                             /* 9.9.2.5  Mobile station classmark 3 */
    DE_EPS_NAS_SEC_PAR_FROM_EUTRA,              /* 9.9.2.6  NAS security parameters from E-UTRA */
    DE_EPS_NAS_SEC_PAR_TO_EUTRA,                /* 9.9.2.7  NAS security parameters to E-UTRA */

    DE_EPS_CMN_PLM_LST,                         /* 9.9.2.8  PLMN list */
    DE_EPS_CMN_SUP_CODEC_LST,                   /* 9.9.2.6  9.9.2.10    Supported codec list */
    DE_EPS_COMMON_NONE                          /* NONE */
}
nas_eps_common_elem_idx_t;
/*
 * 9.9.2    Common information elements
 */

/* 9.9.2.0 Additional information */
static guint16
de_eps_cmn_add_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    proto_item *item;
    proto_tree *sub_tree;
    tvbuff_t *new_tvb;

    item = proto_tree_add_item(tree, hf_nas_eps_cmn_add_info, tvb, offset, len, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_nas_eps_cmn_add_info);

    new_tvb = tvb_new_subset(tvb, offset, len, len);

    switch (eps_nas_gen_msg_cont_type) {
    case 1:
        /* LPP */
        dissect_lcsap_Correlation_ID_PDU(new_tvb, pinfo, sub_tree);
        break;
    default:
        break;
    }

    return(len);
}

/*
 * 9.9.2.1  EPS bearer context status
 */
static const true_false_string  nas_eps_emm_ebi_vals = {
    "BEARER CONTEXT-ACTIVE",
    "BEARER CONTEXT-INACTIVE"
};

static guint16
de_eps_cmn_eps_be_ctx_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    /* EBI(7)  EBI(6)  EBI(5)  EBI(4)  EBI(3)  EBI(2)  EBI(1) EBI(0) octet 3 */
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi7, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi6, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi5, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EBI(0) - EBI(4): Bits 0 to 4 of octet 3 are spare and shall be coded as zero. */
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi4, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi3, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;
    /* EBI(15) EBI(14) EBI(13) EBI(12) EBI(11) EBI(10) EBI(9) EBI(8) octet 4 */
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi15, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi14, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi13, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi12, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi11, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi10, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi9, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi8, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    return len;
}
/*
 * 9.9.2.2  Location area identification
 * See subclause 10.5.1.3 in 3GPP TS 24.008 [6].
 */
/*
 * 9.9.2.3  Mobile identity
 * See subclause 10.5.1.4 in 3GPP TS 24.008 [6].
 * exported from gsm_a_common
 */

/*
 * 9.9.2.4  Mobile station classmark 2
 * See subclause 10.5.1.6 in 3GPP TS 24.008 [13].
 */
/*
 * 9.9.2.5  Mobile station classmark 3
 * See subclause 10.5.1.7 in 3GPP TS 24.008 [13].
 */

/*
 * 9.9.2.6  NAS security parameters from E-UTRA
 */
guint16
de_emm_sec_par_from_eutra(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    /* DL NAS COUNT value (short) (octet 2, bit 1 to 4)
     * This field contains the 4 least significant bits of the binary representation of the downlink
     * NAS COUNT value applicable when this information element is sent.
     */
    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, curr_offset<<3, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_dl_nas_cnt, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    return len;
}

/*
 * 9.9.2.7  NAS security parameters to E-UTRA
 */
guint16
de_emm_sec_par_to_eutra(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;
    /* NonceMME value (octet 1 to 5)
     * This field is coded as the nonce value in the Nonce information element (see subclause 9.9.3.25).
     */
    proto_tree_add_item(tree, hf_nas_eps_emm_nonce_mme, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
    curr_offset+=4;
    /* type of ciphering algorithm (octet 6, bit 5 to 7)
     * These fields are coded as the type of integrity protection algorithm and type of ciphering algorithm
     * in the NAS security algorithms information element (see subclause 9.9.3.23).
     * Bit 4 and 8 of octet 6 are spare and shall be coded as zero.
     */
    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, curr_offset<<3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_toc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* Type of integrity protection algorithm (octet 6, bit 1 to 3)*/
    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, (curr_offset<<3)+4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_toi, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;
    /*
     * NAS key set identifier (octet 7, bit 1 to 3) and
     * type of security context flag (TSC) (octet 7, bit 4)
     * These fields are coded as the NAS key set identifier and type of security context flag in the
     * NAS key set identifier information element (see subclause 9.9.3.21).
     * Bit 5 to 8 of octet 7 are spare and shall be coded as zero.
     */
    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, curr_offset<<3, 4, ENC_BIG_ENDIAN);
    /* Type of security context flag (TSC)  V   1/2 */
    proto_tree_add_bits_item(tree, hf_nas_eps_tsc, tvb, (curr_offset<<3)+4, 1, ENC_BIG_ENDIAN);
    /* NAS key set identifier */
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_nas_key_set_id, tvb, (curr_offset<<3)+5, 3, ENC_BIG_ENDIAN);
    curr_offset++;
    return len;
}

/*
 * 9.9.2.8  PLMN list
 * See subclause 10.5.1.13 in 3GPP TS 24.008 [6].
 */
/*
 * 9.9.2.9  Spare half octet
 * This element is used in the description of EMM and ESM messages when an odd number of
 * half octet type 1 information elements are used. This element is filled with spare bits
 * set to zero and is placed in bits 5 to 8 of the octet unless otherwise specified.
 * Coded Inline
 */

/*
 * 9.9.2.10 Supported codec list
 * See subclause 10.5.4.32 in 3GPP TS 24.008 [13].
 * Dissected in packet-gsm_a_dtap.c
 */

guint16 (*nas_eps_common_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string, int string_len) = {
    /* 9.9.2    Common information elements */
    de_eps_cmn_add_info,            /* 9.9.2.0  Additional information */
    de_eps_cmn_eps_be_ctx_status,   /* 9.9.2.1  EPS bearer context status */
    de_lai,                         /* 9.9.2.2  Location area identification */
    de_mid,                         /* 9.9.2.3  Mobile identity See subclause 10.5.1.4 in 3GPP TS 24.008*/
    de_ms_cm_2,                     /* 9.9.2.4  Mobile station classmark 2 */
    de_ms_cm_3,                     /* 9.9.2.5  Mobile station classmark 3 */
    de_emm_sec_par_from_eutra,      /* 9.9.2.6  NAS security parameters from E-UTRA */
    de_emm_sec_par_to_eutra,        /* 9.9.2.7  NAS security parameters to E-UTRA */

    de_plmn_list,                   /* 9.9.2.8  PLMN list */
    NULL,                           /* 9.9.2.10 Supported codec list (packet-gsm_a_dtap.c) */
    NULL,   /* NONE */
};

const value_string nas_emm_elem_strings[] = {
    /* 9.9.3    EPS Mobility Management (EMM) information elements */
    { 0x00, "Additional update result" },           /* 9.9.3.0A Additional update result */
    { 0x00, "Additional update type" },             /* 9.9.3.0B Additional update type */
    { 0x00, "Authentication failure parameter" },   /* 9.9.3.1  Authentication failure parameter */
    { 0x00, "Authentication parameter AUTN" },      /* 9.9.3.2  Authentication parameter AUTN */
    { 0x00, "Authentication parameter RAND" },      /* 9.9.3.3  Authentication parameter RAND */
    { 0x00, "Authentication response parameter" },  /* 9.9.3.4  Authentication response parameter */
    { 0x00, "CSFB response" },                      /* 9.9.3.5  CSFB response */
    { 0x00, "Daylight saving time" },               /* 9.9.3.6  Daylight saving time */
    { 0x00, "Detach type" },                        /* 9.9.3.7  Detach type */
    { 0x00, "DRX parameter" },                      /* 9.9.3.8  DRX parameter */
    { 0x00, "EMM cause" },                          /* 9.9.3.9  EMM cause */
    { 0x00, "EPS attach result" },                  /* 9.9.3.10 EPS attach result */
    { 0x00, "EPS attach type" },                    /* 9.9.3.11 EPS attach type */
    { 0x00, "EPS mobile identity" },                /* 9.9.3.12 EPS mobile identity */
    { 0x00, "EPS network feature support" },        /* 9.9.3.12 EPS mobile identity */
    { 0x00, "EPS update result" },                  /* 9.9.3.13 EPS update result */
    { 0x00, "EPS update type" },                    /* 9.9.3.14 EPS update type */
    { 0x00, "ESM message container" },              /* 9.9.3.15 ESM message conta */
    { 0x00, "GPRS timer" },                         /* 9.9.3.16 GPRS timer ,See subclause 10.5.7.3 in 3GPP TS 24.008 [6]. */
    { 0x00, "Identity type 2" },                    /* 9.9.3.17 Identity type 2 ,See subclause 10.5.5.9 in 3GPP TS 24.008 [6]. */
    { 0x00, "IMEISV request" },                     /* 9.9.3.18 IMEISV request ,See subclause 10.5.5.10 in 3GPP TS 24.008 [6]. */
    { 0x00, "KSI and sequence number" },            /* 9.9.3.19 KSI and sequence number */
    { 0x00, "MS network capability" },              /* 9.9.3.20 MS network capability ,See subclause 10.5.5.12 in 3GPP TS 24.008 [6]. */
    { 0x00, "NAS key set identifier" },             /* 9.9.3.21 NAS key set identifier */
    { 0x00, "NAS message container" },              /* 9.9.3.22 NAS message container */
    { 0x00, "NAS security algorithms" },            /* 9.9.3.23 NAS security algorithms */
    { 0x00, "Network name" },                       /* 9.9.3.24 Network name, See subclause 10.5.3.5a in 3GPP TS 24.008 [6]. */
    { 0x00, "Nonce" },                              /* 9.9.3.25 Nonce */
    { 0x00, "Paging identity" },                    /* 9.9.3.25A Paging identity */
    { 0x00, "P-TMSI signature" },                   /* 9.9.3.26 P-TMSI signature, See subclause 10.5.5.8 in 3GPP TS 24.008 [6]. */
    { 0x00, "Service type" },                       /* 9.9.3.27 Service type ,See subclause 10.5.5.15 in 3GPP TS 24.008 [6]. */
    { 0x00, "Short MAC" },                          /* 9.9.3.28 Short MAC */
    { 0x00, "Time zone" },                          /* 9.9.3.29 Time zone, See subclause 10.5.3.8 in 3GPP TS 24.008 [6]. */
    { 0x00, "Time zone and time" },                 /* 9.9.3.30 Time zone and time, See subclause 10.5.3.9 in 3GPP TS 24.008 [6]. */
    { 0x00, "TMSI status" },                        /* 9.9.3.31 TMSI status, See subclause 10.5.5.4 in 3GPP TS 24.008 [6]. */
    { 0x00, "Tracking area identity" },             /* 9.9.3.32 Tracking area identity */
    { 0x00, "Tracking area identity list" },        /* 9.9.3.33 Tracking area identity list */
    { 0x00, "UE network capability" },              /* 9.9.3.34 UE network capability */
    { 0x00, "UE radio capability information update needed" },  /* 9.9.3.35 UE radio capability information update needed */
    { 0x00, "UE security capability" },             /* 9.9.3.36 UE security capability */
    { 0x00, "Emergency Number List" },              /* 9.9.3.37 Emergency Number List */
    { 0x00, "CLI" },                                /* 9.9.3.38 CLI */
    { 0x00, "SS Code" },                            /* 9.9.3.39 SS Code */
    { 0x00, "LCS indicator" },                      /* 9.9.3.40 LCS indicator */
    { 0x00, "LCS client identity" },                /* 9.9.3.41 LCS client identity */
    { 0x00, "Generic message container type" },     /* 9.9.3.42 Generic message container type */
    { 0x00, "Generic message container" },          /* 9.9.3.43 Generic message container */
    { 0x00, "Voice domain preference and UEs usage setting" }, /* 9.9.3.44 Voice domain preference and UEs usage setting */
    { 0, NULL }
};
#define NUM_NAS_EMM_ELEM (sizeof(nas_emm_elem_strings)/sizeof(value_string))
gint ett_nas_eps_emm_elem[NUM_NAS_EMM_ELEM];

#if 0
This enum has been moved to packet-gsm_a_common to
make it possible to use element dissection from this dissector
in other dissectors.
It is left here as a comment for easier reference.

Note this enum must be of the same size as the element decoding list

typedef enum
{
    /. 9.9.3    EPS Mobility Management (EMM) information elements ./
    DE_EMM_ADD_UPD_RES,         /. 9.9.3.0A Additional update result ./
    DE_EMM_ADD_UPD_TYPE,        /. 9.9.3.0B Additional update type ./
    DE_EMM_AUTH_FAIL_PAR,       /. 9.9.3.1  Authentication failure parameter (dissected in packet-gsm_a_dtap.c)./
    DE_EMM_AUTN,                /. 9.9.3.2  Authentication parameter AUTN ./
    DE_EMM_AUTH_PAR_RAND,       /. 9.9.3.3  Authentication parameter RAND ./
    DE_EMM_AUTH_RESP_PAR,       /. 9.9.3.4  Authentication response parameter ./
    DE_EMM_CSFB_RESP,           /. 9.9.3.5  CSFB response ./
    DE_EMM_DAYL_SAV_T,          /. 9.9.3.6  Daylight saving time ./
    DE_EMM_DET_TYPE,            /. 9.9.3.7  Detach type ./
    DE_EMM_DRX_PAR,             /. 9.9.3.8  DRX parameter (dissected in packet-gsm_a_gm.c)./
    DE_EMM_CAUSE,               /. 9.9.3.9  EMM cause ./
    DE_EMM_ATT_RES,             /. 9.9.3.10 EPS attach result (Coded inline ./
    DE_EMM_ATT_TYPE,            /. 9.9.3.11 EPS attach type (Coded Inline)./
    DE_EMM_EPS_MID,             /. 9.9.3.12 EPS mobile identity ./
    DE_EMM_EPS_NET_FEATURE_SUP, /. 9.9.3.12A EPS network feature support ./
    DE_EMM_EPS_UPD_RES,         /. 9.9.3.13 EPS update result ( Coded inline)./
    DE_EMM_EPS_UPD_TYPE,        /. 9.9.3.14 EPS update type ./
    DE_EMM_ESM_MSG_CONT,        /. 9.9.3.15 ESM message conta ./
    DE_EMM_GPRS_TIMER,          /. 9.9.3.16 GPRS timer ,See subclause 10.5.7.3 in 3GPP TS 24.008 [6]. ./
    DE_EMM_ID_TYPE_2,           /. 9.9.3.17 Identity type 2 ,See subclause 10.5.5.9 in 3GPP TS 24.008 [6]. ./
    DE_EMM_IMEISV_REQ,          /. 9.9.3.18 IMEISV request ,See subclause 10.5.5.10 in 3GPP TS 24.008 [6]. ./
    DE_EMM_KSI_AND_SEQ_NO,      /. 9.9.3.19 KSI and sequence number ./
    DE_EMM_MS_NET_CAP,          /. 9.9.3.20 MS network capability ,See subclause 10.5.5.12 in 3GPP TS 24.008 [6]. ./
    DE_EMM_NAS_KEY_SET_ID,      /. 9.9.3.21 NAS key set identifier (coded inline)./
    DE_EMM_NAS_MSG_CONT,        /. 9.9.3.22 NAS message container ./
    DE_EMM_NAS_SEC_ALGS,        /. 9.9.3.23 NAS security algorithms ./
    DE_EMM_NET_NAME,            /. 9.9.3.24 Network name, See subclause 10.5.3.5a in 3GPP TS 24.008 [6]. ./
    DE_EMM_NONCE,               /. 9.9.3.25 Nonce ./
    DE_EMM_PAGING_ID,           /. 9.9.3.25A Paging identity ./
    DE_EMM_P_TMSI_SIGN,         /. 9.9.3.26 P-TMSI signature, See subclause 10.5.5.8 in 3GPP TS 24.008 [6]. ./
    DE_EMM_SERV_TYPE,           /. 9.9.3.27 Service type ./
    DE_EMM_SHORT_MAC,           /. 9.9.3.28 Short MAC ./
    DE_EMM_TZ,                  /. 9.9.3.29 Time zone, See subclause 10.5.3.8 in 3GPP TS 24.008 [6]. ./
    DE_EMM_TZ_AND_T,            /. 9.9.3.30 Time zone and time, See subclause 10.5.3.9 in 3GPP TS 24.008 [6]. ./
    DE_EMM_TMSI_STAT,           /. 9.9.3.31 TMSI status, See subclause 10.5.5.4 in 3GPP TS 24.008 [6]. ./
    DE_EMM_TRAC_AREA_ID,        /. 9.9.3.32 Tracking area identity ./
    DE_EMM_TRAC_AREA_ID_LST,    /. 9.9.3.33 Tracking area identity list ./
    DE_EMM_UE_NET_CAP,          /. 9.9.3.34 UE network capability ./
    DE_EMM_UE_RA_CAP_INF_UPD_NEED,  /. 9.9.3.35 UE radio capability information update needed ./
    DE_EMM_UE_SEC_CAP,          /. 9.9.3.36 UE security capability ./
    DE_EMM_EMERG_NUM_LST,       /. 9.9.3.37 Emergency Number List ./
    DE_EMM_CLI,                 /. 9.9.3.38 CLI ./
    DE_EMM_SS_CODE,             /. 9.9.3.39 SS Code ./
    DE_EMM_LCS_IND,             /. 9.9.3.40 LCS indicator ./
    DE_EMM_LCS_CLIENT_ID,       /. 9.9.3.41 LCS client identity ./
    DE_EMM_GEN_MSG_CONT_TYPE,   /. 9.9.3.42 Generic message container type ./
    DE_EMM_GEN_MSG_CONT,        /. 9.9.3.43 Generic message container ./
    DE_EMM_VOICE_DMN_PREF,      /. 9.9.3.44 Voice domain preference and UEs usage setting ./
    DE_EMM_NONE                 /. NONE ./

}
nas_emm_elem_idx_t;

#endif
/* TODO: Update to latest spec */
/* 9.9.3    EPS Mobility Management (EMM) information elements
 */
/*
 * 9.9.3.0A  Additional update result
 */
static const value_string nas_eps_emm_add_upd_res_vals[] = {
    { 0x0, "no additional information"},
    { 0x1, "CS Fallback not preferred"},
    { 0x2, "SMS only"},
    { 0x3, "reserved"},
    { 0, NULL }
};
static guint16
de_emm_add_upd_res(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset, bit_offset;

    curr_offset = offset;
    bit_offset = (curr_offset<<3)+4;

    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
    bit_offset += 2;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_add_upd_res, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
    curr_offset++;

    return (curr_offset - offset);
}
/*
 * 9.9.3.0B  Additional update type
 */
static const value_string nas_eps_emm_add_upd_type_vals[] = {
    { 0x0, "no additional information (shall be interpreted as request for combined attach or combined tracking area updating)"},
    { 0x1, "SMS only"},
    { 0, NULL }
};
static guint16
de_emm_add_upd_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset, bit_offset;

    curr_offset = offset;
    bit_offset = (curr_offset<<3)+4;

    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
    bit_offset += 3;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_add_upd_type, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    return (curr_offset - offset);
}
/*
 * 9.9.3.1  Authentication failure parameter
 * See subclause 10.5.3.2.2 in 3GPP TS 24.008 [6].
 * (dissected in packet-gsm_a_dtap.c)
 */
/*
 * 9.9.3.2  Authentication parameter AUTN
 * See subclause 10.5.3.1.1 in 3GPP TS 24.008 [6].
 */
/*
 * 9.9.3.3  Authentication parameter RAND
 * See subclause 10.5.3.1 in 3GPP TS 24.008 [6].
 */
/*
 * 9.9.3.4  Authentication response parameter
 */
static guint16
de_emm_auth_resp_par(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_nas_eps_emm_res, tvb, curr_offset, len, ENC_NA);

    return len;
}
/*
 * 9.9.3.4A Ciphering key sequence number
 * See subclause 9.9.3.19 in 3GPP TS 24.008 [13].
 */

/*
 * 9.9.3.5  CSFB response
 */

/*
 * CSFB response value (octet 1)
 */

static const value_string nas_eps_emm_csfb_resp_vals[] = {
    { 0x0,  "CS fallback rejected by the UE"},
    { 0x1,  "CS fallback accepted by the UE"},
    { 0, NULL }
};

static guint16
de_emm_csfb_resp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset, bit_offset;

    curr_offset = offset;

    /* bit 4 Spare */
    bit_offset = curr_offset<<3;
    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset+4, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(tree, hf_nas_eps_emm_csfb_resp, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    return(curr_offset-offset);
}
/*
 * 9.9.3.6  Daylight saving time
 * See subclause 10.5.3.12 in 3GPP TS 24.008 [6].
 */
/*
 * 9.9.3.7  Detach type
 * Coded inline
 */
static const value_string nas_eps_emm_switch_off_vals[] = {
    { 0x0,  "Normal detach"},
    { 0x1,  "Switch off"},
    { 0x2,  "Reserved"},
    { 0x3,  "Reserved"},
    { 0x4,  "Reserved"},
    { 0x5,  "Reserved"},
    { 0x6,  "Reserved"},
    { 0x7,  "Reserved"},
    { 0, NULL }
};
/* Type of detach (octet 1)
 * In the UE to network direction:
 */
static const value_string nas_eps_emm_type_of_dtatch_UL_vals[] = {
    { 0x1,  "EPS detach"},
    { 0x2,  "IMSI detach"},
    { 0x3,  "Combined EPS/IMSI detach"},
    { 0x4,  "Combined EPS/IMSI detach"}, /* All other values are interpreted as "combined EPS/IMSI detach" in this version of the protocol.*/
    { 0x5,  "Combined EPS/IMSI detach"}, /* -"- */
    { 0x6,  "Reserved"},
    { 0x7,  "Reserved"},
    { 0, NULL }
};

/*
 * In the network to UE direction:
 */

static const value_string nas_eps_emm_type_of_dtatch_DL_vals[] = {
    { 0x1,  "Re-attach required"},
    { 0x2,  "Re-attach not required"},
    { 0x3,  "IMSI detach"},
    { 0x4,  "Re-attach not required"}, /* All other values are interpreted as "re-attach not required" in this version of the protocol.*/
    { 0x5,  "Re-attach not required"}, /* -"- */
    { 0x6,  "Reserved"},
    { 0x7,  "Reserved"},
    { 0, NULL }
};

/*
 * 9.9.3.8  DRX parameter
 * See subclause 10.5.5.6 in 3GPP TS 24.008 [13].
 */
/*
 * 9.9.3.9  EMM cause
 */
static const value_string nas_eps_emm_cause_values[] = {
    { 0x2,  "IMSI unknown in HSS"},
    { 0x3,  "Illegal UE"},
    { 0x5,  "IMEI not accepted"},
    { 0x6,  "Illegal ME"},
    { 0x7,  "EPS services not allowed"},
    { 0x8,  "EPS services and non-EPS services not allowed"},
    { 0x9,  "UE identity cannot be derived by the network"},
    { 0xa,  "Implicitly detached"},
    { 0xb,  "PLMN not allowed"},
    { 0xc,  "Tracking Area not allowed"},
    { 0xd,  "Roaming not allowed in this tracking area"},
    { 0xe,  "EPS services not allowed in this PLMN"},
    { 0xf,  "No Suitable Cells In tracking area"},
    { 0x10, "MSC temporarily not reachable"},
    { 0x11, "Network failure"},
    { 0x12, "CS domain not available"},
    { 0x13, "ESM failure"},
    { 0x14, "MAC failure"},
    { 0x15, "Synch failure"},
    { 0x16, "Congestion"},
    { 0x17, "UE security capabilities mismatch"},
    { 0x18, "Security mode rejected, unspecified"},
    { 0x19, "Not authorized for this CSG"},
    { 0x1a, "Non-EPS authentication unacceptable"},
    { 0x27, "CS domain temporarily not available"},
    { 0x28, "No EPS bearer context activated"},
    { 0x5f, "Semantically incorrect message"},
    { 0x60, "Invalid mandatory information"},
    { 0x61, "Message type non-existent or not implemented"},
    { 0x62, "Message type not compatible with the protocol state"},
    { 0x63, "Information element non-existent or not implemented"},
    { 0x64, "Conditional IE error"},
    { 0x65, "Message not compatible with the protocol state"},
    { 0x6f, "Protocol error, unspecified"},
    { 0, NULL }
};

static guint16
de_emm_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_nas_eps_emm_cause, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    return curr_offset-offset;}
/*
 * 9.9.3.10 EPS attach result
 */

static const value_string nas_eps_emm_EPS_attach_result_values[] = {
    { 0,    "reserved"},
    { 1,    "EPS only"},
    { 2,    "Combined EPS/IMSI attach"},
    { 3,    "reserved"},
    { 4,    "reserved"},
    { 5,    "reserved"},
    { 6,    "reserved"},
    { 7,    "reserved"},
    { 0, NULL }
};
/* Coded inline */

/*
 * 9.9.3.11 EPS attach type
 */

static const value_string nas_eps_emm_eps_att_type_vals[] = {
    { 0,    "EPS attach(unused)"},
    { 1,    "EPS attach"},
    { 2,    "Combined EPS/IMSI attach"},
    { 3,    "EPS attach(unused)"},
    { 4,    "EPS attach(unused)"},
    { 5,    "EPS attach(unused)"},
    { 6,    "EPS emergency attach"},
    { 7,    "Reserved"},
    { 0, NULL }
};
/* Coded inline */

/*
 * 9.9.3.12 EPS mobile identity
 */
static char *
unpack_eps_mid_digits(tvbuff_t *tvb) {

    int length;
    guint8 octet;
    int i=0;
    int offset = 0;
    char *digit_str;

    length = tvb_length(tvb);

    digit_str = ep_alloc(length*2);

    /* Get identity digit 1 */
    octet = tvb_get_guint8(tvb,offset);
    digit_str[i++] = (((octet>>4) & 0x0f) + '0');
    offset++;

    /* Loop on following octets to retrieve other identity digits */
    while ( offset < length ){

        octet = tvb_get_guint8(tvb,offset);
        digit_str[i] = ((octet & 0x0f) + '0');
        i++;

        /*
         * unpack second value in byte
         */
        octet = octet >> 4;

        if (octet == 0x0f)  /* odd number bytes - hit filler */
            break;

        digit_str[i] = ((octet & 0x0f) + '0');
        i++;
        offset++;

    }
    digit_str[i]= '\0';
    return digit_str;
}

static const value_string nas_eps_emm_type_of_id_vals[] = {
    { 0,    "reserved"},
    { 1,    "IMSI"},
    { 2,    "reserved"},
    { 3,    "IMEI"},
    { 4,    "reserved"},
    { 5,    "reserved"},
    { 6,    "GUTI"},
    { 7,    "reserved"},
    { 0, NULL }
};
static guint16
de_emm_eps_mid(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    guint8 octet;
    char    *digit_str;
    tvbuff_t *new_tvb;

    curr_offset = offset;

    octet = tvb_get_guint8(tvb,offset);
    /* Type of identity (octet 3) */
    proto_tree_add_item(tree, hf_nas_eps_emm_odd_even, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_type_of_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    switch (octet&0x7){
        case 1:
            /* IMSI */
            new_tvb = tvb_new_subset(tvb, curr_offset, len, len );
            digit_str = unpack_eps_mid_digits(new_tvb);
            proto_tree_add_string(tree, hf_nas_eps_emm_imsi, new_tvb, 0, -1, digit_str);
            break;
        case 3:
            /* IMEI */
            new_tvb = tvb_new_subset(tvb, curr_offset, len, len );
            digit_str = unpack_eps_mid_digits(new_tvb);
            proto_tree_add_string(tree, hf_nas_eps_emm_imei, new_tvb, 0, -1, digit_str);
            break;
        case 6:
            /* GUTI */
            curr_offset++;
            curr_offset = dissect_e212_mcc_mnc(tvb, gpinfo, tree, curr_offset, TRUE);
            /* MME Group ID octet 7 - 8 */
            proto_tree_add_item(tree, hf_nas_eps_emm_mme_grp_id, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
            curr_offset+=2;
            /* MME Code Octet 9 */
            proto_tree_add_item(tree, hf_nas_eps_emm_mme_code, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            curr_offset++;
            /* M-TMSI Octet 10 - 13 */
            proto_tree_add_item(tree, hf_nas_eps_emm_m_tmsi, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
            curr_offset+=4;
            break;
        default:
            proto_tree_add_text(tree, tvb, curr_offset, len - 1, "Type of identity not known");
            break;
    }

    return(len);
}

/*
 * 9.9.3.12A    EPS network feature support
 */
static const value_string nas_eps_emm_cs_lcs_vals[] = {
    { 0,    "no information about support of location services via CS domain is available"},
    { 1,    "location services via CS domain not supported"},
    { 2,    "location services via CS domain supported"},
    { 3,    "reserved"},
    { 0, NULL }
};
static const true_false_string nas_eps_emm_epc_lcs_value = {
    "location services via EPC supported",
    "location services via EPC not supported"
};
static const true_false_string nas_eps_emm_emc_bs_value = {
    "emergency bearer services in S1 mode supported",
    "emergency bearer services in S1 mode not supported"
};
static const true_false_string nas_eps_emm_ims_vops_value = {
    "IMS voice over PS session in S1 mode supported",
    "IMS voice over PS session in S1 mode not supported"
};

static guint16
de_emm_eps_net_feature_sup(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset, bit_offset;

    curr_offset = offset;
    bit_offset = curr_offset << 3;
    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
    bit_offset += 3;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_cs_lcs_type, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
    bit_offset += 2;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_epc_lcs_type, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset += 1;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_emc_bs_type, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset += 1;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_ims_vops_type, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset += 1;

    return len;
}
/*
 * 9.9.3.13 EPS update result
 */
static const value_string nas_eps_emm_eps_update_result_vals[] = {
    { 0,    "TA updated"},
    { 1,    "Combined TA/LA updated"},
    { 2,    "Reserved"},
    { 3,    "Reserved"},
    { 4,    "TA updated and ISR activated"},
    { 5,    "Combined TA/LA updated and ISR activated"},
    { 6,    "Reserved"},
    { 7,    "Reserved"},
    { 0, NULL }
};

/*
 * 9.9.3.14 EPS update type
 */
static const true_false_string  nas_eps_emm_active_flg_value = {
    "Bearer establishment requested",
    "No bearer establishment requested"
};

static const value_string nas_eps_emm_eps_update_type_vals[] = {
    { 0,    "TA updating"},
    { 1,    "Combined TA/LA updating"},
    { 2,    "Combined TA/LA updating with IMSI attach"},
    { 3,    "Periodic updating"},
    { 4,    "Unused; shall be interpreted as 'TA updating', if received by the network"},
    { 5,    "Unused; shall be interpreted as 'TA updating', if received by the network"},
    { 6,    "Reserved"},
    { 7,    "Reserved"},
    { 0, NULL }
};

/*
 * 9.9.3.15 ESM message container
 */
static guint16
de_emm_esm_msg_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    proto_item *item;
    proto_tree *sub_tree;
    tvbuff_t    *new_tvb;
    guint32 curr_offset;

    curr_offset = offset;


    item = proto_tree_add_item(tree, hf_nas_eps_esm_msg_cont, tvb, curr_offset, len, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_nas_eps_esm_msg_cont);

    /* This IE can contain any ESM PDU as defined in subclause 8.3. */
    new_tvb = tvb_new_subset(tvb, curr_offset, len, len );
    /* Plain NAS message */
    disect_nas_eps_esm_msg(new_tvb, gpinfo, sub_tree, 0/* offset */);

    return(len);
}
/*
 * 9.9.3.16 GPRS timer
 * See subclause 10.5.7.3 in 3GPP TS 24.008 [6].
 * packet-gsm_a_gm.c
 */
/*
 * 9.9.3.17 Identity type 2
 * See subclause 10.5.5.9 in 3GPP TS 24.008 [6].
 */
static const value_string nas_eps_emm_id_type2_vals[] = {
    { 1,    "IMSI"},
    { 2,    "IMEI"},
    { 3,    "IMEISV"},
    { 4,    "TMSI"},
    { 0, NULL }
};

/*
 * 9.9.3.18 IMEISV request
 * See subclause 10.5.5.10 in 3GPP TS 24.008 [6].
 */
/* IMEISV request value (octet 1) */
static const value_string nas_eps_emm_imeisv_req_vals[] = {
    { 0,    "IMEISV not requested"},
    { 1,    "IMEISV requested"},
    { 2,    "IMEISV not requested"},
    { 3,    "IMEISV not requested"},
    { 4,    "IMEISV not requested"},
    { 5,    "IMEISV not requested"},
    { 6,    "IMEISV not requested"},
    { 7,    "IMEISV not requested"},
    { 0, NULL }
};
static guint16
de_emm_nas_imeisv_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    int bit_offset;

    curr_offset = offset;

    bit_offset = curr_offset<<3;
    bit_offset+=4;
    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_esm_imeisv_req, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    return(curr_offset - offset);
}
/*
 * 9.9.3.19 KSI and sequence number
 */
static guint16
de_emm_nas_ksi_and_seq_no(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    int bit_offset;

    curr_offset = offset;
    bit_offset = curr_offset<<3;

    proto_tree_add_bits_item(tree, hf_nas_eps_emm_nas_key_set_id, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
    bit_offset += 3;
    proto_tree_add_bits_item(tree, hf_nas_eps_seq_no_short, tvb, bit_offset, 5, ENC_BIG_ENDIAN);
    curr_offset++;

    return(curr_offset - offset);
}

/*
 * 9.9.3.20 MS network capability
 * See subclause 10.5.5.12 in 3GPP TS 24.008 [6].
 */
/*
 * 9.9.3.21 NAS key set identifier
 */
/*
 * Type of security context flag (TSC) (octet 1)
 */
static const value_string nas_eps_tsc_vals[] = {
    { 0,    "Native security context (for KSIasme)"},
    { 1,    "Mapped security context (for KSIsgsn)"},
    { 0, NULL }
};

/* NAS key set identifier (octet 1) Bits 3  2   1 */

static const value_string nas_eps_emm_NAS_key_set_identifier_vals[] = {
    { 0,    ""},
    { 1,    ""},
    { 2,    ""},
    { 3,    ""},
    { 4,    ""},
    { 5,    ""},
    { 6,    ""},
    { 7,    "No key is available"},
    { 0, NULL }
};

/* Takes bit offset as input and consumes 4 bits */
static void
de_emm_nas_key_set_id_bits(tvbuff_t *tvb, proto_tree *tree, guint32 bit_offset, const gchar *add_string)
{
    proto_item *item;

    /* Type of security context flag (TSC) (octet 1)    V   1/2 */
    proto_tree_add_bits_item(tree, hf_nas_eps_tsc, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    /* NAS key set identifier (octet 1) */
    item = proto_tree_add_bits_item(tree, hf_nas_eps_emm_nas_key_set_id, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
    if(add_string){
        proto_item_append_text(item, "%s", add_string);
    }
    bit_offset+=3;
}
/*
 * Note used for TV Short
 */
static guint16
de_emm_nas_key_set_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset, bit_offset;

    curr_offset = offset;

    /* Get the bit offset of the lover half of the octet bits 4 - 1 */
    bit_offset = curr_offset<<3;
    bit_offset+=4;

    /* Type of security context flag (TSC) (octet 1)    V   1/2 */
    proto_tree_add_bits_item(tree, hf_nas_eps_tsc, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    /* NAS key set identifier (octet 1) */
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_nas_key_set_id, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
    bit_offset+=3;
    curr_offset++;

    return(curr_offset - offset);
}

/*
 * 9.9.3.22 NAS message container
 */
static guint16
de_emm_nas_msg_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    proto_item *item;
    proto_tree *sub_tree;
    tvbuff_t *new_tvb;
    guint32 curr_offset;

    curr_offset = offset;

    /* NAS message container contents (octet 3 to octet n)
     * This IE can contain an SMS message (i.e. CP-DATA, CP-ACK or CP-ERROR)
     * as defined in subclause 7.2 in 3GPP TS 24.011 [13A].
     */

    item = proto_tree_add_item(tree, hf_nas_eps_nas_msg_cont, tvb, curr_offset, len, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_nas_eps_nas_msg_cont);

    new_tvb = tvb_new_subset(tvb, curr_offset, len, len );
    if(gsm_a_dtap_handle)
        call_dissector(gsm_a_dtap_handle, new_tvb, gpinfo, sub_tree);

    return(len);
}
/*
 * 9.9.3.23 NAS security algorithms
 */
/* Type of integrity protection algorithm (octet 2, bit 1 to 3) */
static const value_string nas_eps_emm_toi_vals[] = {
    { 0,    "EPS integrity algorithm EIA0 (null integrity protection algorithm)"},
    { 1,    "EPS integrity algorithm 128-EIA1"},
    { 2,    "EPS integrity algorithm 128-EIA2"},
    { 3,    "EPS integrity algorithm EIA3"},
    { 4,    "EPS integrity algorithm EIA4"},
    { 5,    "EPS integrity algorithm EIA5"},
    { 6,    "EPS integrity algorithm EIA6"},
    { 7,    "EPS integrity algorithm EIA7"},
    { 0, NULL }
};

/* Type of ciphering algorithm (octet 2, bit 5 to 7) */

static const value_string nas_eps_emm_toc_vals[] = {
    { 0,    "EPS encryption algorithm EEA0 (null ciphering algorithm)"},
    { 1,    "EPS encryption algorithm 128-EEA1"},
    { 2,    "EPS encryption algorithm 128-EEA2"},
    { 3,    "EPS encryption algorithm EEA3"},
    { 4,    "EPS encryption algorithm EEA4"},
    { 5,    "EPS encryption algorithm EEA5"},
    { 6,    "EPS encryption algorithm EEA6"},
    { 7,    "EPS encryption algorithm EEA7"},
    { 0, NULL }
};
static guint16
de_emm_nas_sec_alsgs(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    int bit_offset;
    guint32 curr_offset;

    curr_offset = offset;

    bit_offset = offset<<3;
    /* Bit 4 and 8 of octet 2 are spare and shall be coded as zero. */
    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    /* Type of ciphering algorithm (octet 2, bit 5 to 7) */
    proto_tree_add_item(tree, hf_nas_eps_emm_toc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    bit_offset+=4;
    /* Bit 4 and 8 of octet 2 are spare and shall be coded as zero. */
    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    /* Type of integrity protection algorithm (octet 2, bit 1 to 3) */
    proto_tree_add_item(tree, hf_nas_eps_emm_toi, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    return(curr_offset-offset);
}
/*
 * 9.9.3.24 Network name
 * See subclause 10.5.3.5a in 3GPP TS 24.008 [6].
 */
/*
 * 9.9.3.25 Nonce
 */
static guint16
de_emm_nonce(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_nas_eps_emm_nonce, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
    curr_offset+=4;

    return(curr_offset-offset);
}
/*
 * 9.9.3.25A Paging identity
 */
 static const true_false_string nas_eps_emm_paging_id_vals = {
    "TMSI",
    "IMSI"
};

static guint16
de_emm_paging_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, curr_offset<<3, 7, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_paging_id, tvb, (curr_offset<<3)+7, 1, ENC_BIG_ENDIAN);
    curr_offset+=len;

    return(len);
}
/*
 * 9.9.3.26 P-TMSI signature
 * See subclause 10.5.5.8 in 3GPP TS 24.008 [6].
 */
/*
 * 9.9.3.27 Service type
 */
static const value_string nas_eps_service_type_vals[] = {
    { 0,    "Mobile originating CS fallback or 1xCS fallback"},
    { 1,    "Mobile terminating CS fallback or 1xCS fallback"},
    { 2,    "Mobile originating CS fallback emergency call or 1xCS fallback emergency call"},
    { 0, NULL }
};

/*
 * 9.9.3.28 Short MAC
 */
static guint16
de_emm_nas_short_mac(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;


    proto_tree_add_item(tree, hf_nas_eps_emm_short_mac, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
    curr_offset+=2;

    return(curr_offset-offset);
}
/*
 * 9.9.3.29 Time zone
 * See subclause 10.5.3.8 in 3GPP TS 24.008 [6].
 */
/*
 * 9.9.3.30 Time zone and time
 * See subclause 10.5.3.9 in 3GPP TS 24.008 [6].
 */
/*
 * 9.9.3.31 TMSI status
 * See subclause 10.5.5.4 in 3GPP TS 24.008 [6].
 */
/*
 * 9.9.3.32 Tracking area identity
 */

guint16
de_emm_trac_area_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    curr_offset = dissect_e212_mcc_mnc(tvb, gpinfo, tree, curr_offset, TRUE);
    proto_tree_add_item(tree, hf_nas_eps_emm_tai_tac, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
    curr_offset+=2;

    return(curr_offset-offset);
}
/*
 * 9.9.3.33 Tracking area identity list
 */
/* Type of list (octet 1)
 * Bits 7 6
 */
static const value_string nas_eps_emm_tai_tol_vals[] = {
    { 0,    "list of TACs belonging to one PLMN, with non-consecutive TAC values"},
    { 1,    "list of TACs belonging to one PLMN, with consecutive TAC values"},
    { 2,    "list of TAIs belonging to different PLMNs"},
    { 0, NULL }
};

static guint16
de_emm_trac_area_id_lst(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    proto_item *item;
    guint32 curr_offset;
    guint8 octet, tol, n_elem;
    int i;

    curr_offset = offset;

    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, curr_offset<<3, 1, ENC_BIG_ENDIAN);
    /* Type of list (octet 1) Bits 7 6 */
    proto_tree_add_item(tree, hf_nas_eps_emm_tai_tol, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* Number of elements (octet 1) Bits 5 4 3 2 1 */
    octet = tvb_get_guint8(tvb,curr_offset)& 0x7f;
    tol = octet >> 5;
    n_elem = (octet & 0x1f)+1;
    item = proto_tree_add_item(tree, hf_nas_eps_emm_tai_n_elem, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    if(n_elem<16)
        proto_item_append_text(item, " [+1 = %u element(s)]", n_elem);

    curr_offset++;
    if (tol>2){
        proto_tree_add_text(tree, tvb, curr_offset, len-(curr_offset-offset) , "Unknown type of list ( Not in 3GPP TS 24.301 version 8.1.0 Release 8 )");
        return len;
    }

    switch(tol){
        case 0:
            /* MCC digit 2 MCC digit 1 octet 2
             * MNC digit 3 MCC digit 3 octet 3
             * MNC digit 2 MNC digit 1 octet 4
             */
            curr_offset = dissect_e212_mcc_mnc(tvb, gpinfo, tree, curr_offset, TRUE);
            /* type of list = "000" */
            /* TAC 1             octet 5
             * TAC 1 (continued) octet 6
             * ...
             * ...
             * TAC k             octet 2k+3*
             * TAC k (continued) octet 2k+4*
             */
            if (len < (guint)(4+(n_elem*2))){
                proto_tree_add_text(tree, tvb, curr_offset, len-1 , "[Wrong number of elements?]");
                return len;
            }
            for (i=0; i < n_elem; i++, curr_offset+=2)
                proto_tree_add_item(tree, hf_nas_eps_emm_tai_tac, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
            break;
        case 1:

            /* type of list = "010" */
            /* MCC digit 2 MCC digit 1 octet 2
             * MNC digit 3 MCC digit 3 octet 3
             * MNC digit 2 MNC digit 1 octet 4
             */
            curr_offset = dissect_e212_mcc_mnc(tvb, gpinfo, tree, curr_offset, TRUE);
            proto_tree_add_item(tree, hf_nas_eps_emm_tai_tac, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
            curr_offset+=2;
            break;
        case 2:
            if (len< (guint)(1+(n_elem*5))){
                proto_tree_add_text(tree, tvb, curr_offset, len-1 , "[Wrong number of elements?]");
                return len;
            }

            for (i=0; i < n_elem; i++){
                /* type of list = "001" */
                /* MCC digit 2 MCC digit 1 octet 2
                 * MNC digit 3 MCC digit 3 octet 3
                 * MNC digit 2 MNC digit 1 octet 4
                 */
                curr_offset = dissect_e212_mcc_mnc(tvb, gpinfo, tree, curr_offset, TRUE);
                proto_tree_add_item(tree, hf_nas_eps_emm_tai_tac, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
                curr_offset+=2;
            }
            break;
        default:
            /* Unknown ( Not in 3GPP TS 24.301 version 8.1.0 Release 8 ) */
            break;
    }
    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

    return(curr_offset-offset);
}
/*
 * 9.9.3.34 UE network capability
 */

static const true_false_string  nas_eps_emm_supported_flg_value = {
    "Supported",
    "Not Supported"
};
static const true_false_string  nas_eps_emm_ucs2_supp_flg_value = {
    "The UE has no preference between the use of the default alphabet and the use of UCS2",
    "The UE has a preference for the default alphabet"
};
/* LPP capability (octet 7, bit 4) */
static const true_false_string nas_eps_emm_lpp_cap_flg = {
    "LTE Positioning Protocol supported",
    "LTE Positioning Protocol not supported"
};
/* LCS capability (octet 7, bit 3) */
static const true_false_string nas_eps_emm_lcs_cap_flg = {
    "Location services notification mechanisms supported",
    "Location services notification mechanisms not supported"
};
/* 1xSRVCC capability (octet 7, bit 2) */
static const true_false_string  nas_eps_emm_1xsrvcc_cap_flg = {
    "SRVCC from E-UTRAN to cdma2000 1xCS supported",
    "SRVCC from E-UTRAN to cdma2000 1x CS not supported"
};
/* NF capability (octet 7, bit 1) */
static const true_false_string  nas_eps_emm_nf_cap_flg = {
    "Notification procedure supported",
    "Notification procedure not supported"
};

guint16
de_emm_ue_net_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;


    /* EPS encryption algorithms supported (octet 3) */
    /* EPS encryption algorithm EEA0 supported (octet 3, bit 8) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eea0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS encryption algorithm 128-EEA1 supported (octet 3, bit 7) */
    proto_tree_add_item(tree, hf_nas_eps_emm_128eea1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS encryption algorithm 128-EEA2 supported (octet 3, bit 6) */
    proto_tree_add_item(tree, hf_nas_eps_emm_128eea2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS encryption algorithm 128-EEA3 supported (octet 3, bit 5) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eea3, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS encryption algorithm 128-EEA4 supported (octet 3, bit 4) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eea4, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS encryption algorithm 128-EEA5 supported (octet 3, bit 5) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eea5, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS encryption algorithm 128-EEA6 supported (octet 3, bit 6) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eea6, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS encryption algorithm 128-EEA7 supported (octet 3, bit 7) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eea7, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;


    /* EPS integrity algorithms supported (octet 4) */
    /* EPS integrity algorithm EIA0 supported (octet 4, bit 8) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eia0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS integrity algorithm 128-EIA1 supported (octet 4, bit 7) */
    proto_tree_add_item(tree, hf_nas_eps_emm_128eia1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS integrity algorithm 128-EIA2 supported (octet 4, bit 6) */
    proto_tree_add_item(tree, hf_nas_eps_emm_128eia2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS integrity algorithm EIA3 supported (octet 4, bit 5) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eia3, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS integrity algorithm EIA4 supported (octet 4, bit 4) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eia4, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS integrity algorithm EIA5 supported (octet 4, bit 3) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eia5, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS integrity algorithm EIA6 supported (octet 4, bit 2) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eia6, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS integrity algorithm EIA7 supported (octet 4, bit 1) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eia7, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;


    /* Following octets are optional */
    if ((curr_offset - offset) >= len)
        return (len);

    /* UMTS encryption algorithms supported (octet 5)
     * UMTS encryption algorithm UEA0 supported (octet 5, bit 8)
     */
    /* UMTS encryption algorithm 128-UEA0 supported (octet 5, bit 8) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uea0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS encryption algorithm 128-UEA0 supported (octet 5, bit 7) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uea1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS encryption algorithm 128-UEA0 supported (octet 5, bit 6) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uea2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS encryption algorithm 128-UEA0 supported (octet 5, bit 5) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uea3, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS encryption algorithm 128-UEA0 supported (octet 5, bit 4) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uea4, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS encryption algorithm 128-UEA0 supported (octet 5, bit 5) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uea5, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS encryption algorithm 128-UEA0 supported (octet 5, bit 6) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uea6, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS encryption algorithm 128-UEA0 supported (octet 5, bit 7) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uea7, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    if ((curr_offset - offset) >= len)
        return (len);

    /* UCS2 support (UCS2) (octet 6, bit 8)
     * This information field indicates the likely treatment of UCS2 encoded character strings
     * by the UE.
     */
    proto_tree_add_item(tree, hf_nas_eps_emm_ucs2_supp, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS integrity algorithms supported (octet 6) */
    /* UMTS integrity algorithm UIA1 supported (octet 6, bit 7) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uia1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS integrity algorithm UIA1 supported (octet 6, bit 6) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uia2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS integrity algorithm UIA1 supported (octet 6, bit 5) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uia3, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS integrity algorithm UIA1 supported (octet 6, bit 4) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uia4, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS integrity algorithm UIA1 supported (octet 6, bit 3) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uia5, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS integrity algorithm UIA1 supported (octet 6, bit 2) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uia6, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS integrity algorithm UIA1 supported (octet 6, bit 1) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uia7, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    if ((curr_offset - offset) >= len)
        return (len);

    /* Bits 8 to 5 of octet 7 are spare and shall be coded as zero. */
    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, (curr_offset<<3), 4, ENC_BIG_ENDIAN);
    /* LPP capability (octet 7, bit 4) */
    proto_tree_add_item(tree, hf_nas_eps_emm_lpp_cap, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* LCS capability (octet 7, bit 3) */
    proto_tree_add_item(tree, hf_nas_eps_emm_lcs_cap, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* 1xSRVCC capability (octet 7, bit 2) */
    proto_tree_add_item(tree, hf_nas_eps_emm_1xsrvcc_cap, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* NF capability (octet 7, bit 1) */
    proto_tree_add_item(tree, hf_nas_eps_emm_nf_cap, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    return(len);
}
/* UE radio capability information update needed flag (URC upd) (octet 1) */
static const true_false_string  nas_eps_emm_ue_ra_cap_inf_upd_need_flg = {
    "UE radio capability information update needed",
    "UE radio capability information update not needed"
};

/*
 * 9.9.3.35 UE radio capability information update needed
 */

static guint16
de_emm_ue_ra_cap_inf_upd_need(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_nas_eps_emm_ue_ra_cap_inf_upd_need_flg, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    return(len);
}
/*
 * 9.9.3.36 UE security capability
 */

static guint16
de_emm_ue_sec_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    /* EPS encryption algorithms supported (octet 3) */
    /* EPS encryption algorithm EEA0 supported (octet 3, bit 8) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eea0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS encryption algorithm 128-EEA1 supported (octet 3, bit 7) */
    proto_tree_add_item(tree, hf_nas_eps_emm_128eea1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS encryption algorithm 128-EEA2 supported (octet 3, bit 6) */
    proto_tree_add_item(tree, hf_nas_eps_emm_128eea2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS encryption algorithm 128-EEA3 supported (octet 3, bit 5) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eea3, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS encryption algorithm 128-EEA4 supported (octet 3, bit 4) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eea4, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS encryption algorithm 128-EEA5 supported (octet 3, bit 5) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eea5, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS encryption algorithm 128-EEA6 supported (octet 3, bit 6) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eea6, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS encryption algorithm 128-EEA7 supported (octet 3, bit 7) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eea7, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;


    /* EPS integrity algorithms supported (octet 4) */
    /* EPS integrity algorithm EIA0 supported (octet 4, bit 8) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eia0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS integrity algorithm 128-EIA1 supported (octet 4, bit 7) */
    proto_tree_add_item(tree, hf_nas_eps_emm_128eia1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS integrity algorithm 128-EIA2 supported (octet 4, bit 6) */
    proto_tree_add_item(tree, hf_nas_eps_emm_128eia2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS integrity algorithm EIA3 supported (octet 4, bit 5) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eia3, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS integrity algorithm EIA4 supported (octet 4, bit 4) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eia4, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS integrity algorithm EIA5 supported (octet 4, bit 3) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eia5, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS integrity algorithm EIA6 supported (octet 4, bit 2) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eia6, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS integrity algorithm EIA7 supported (octet 4, bit 1) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eia7, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;


    /* Octets 5, 6, and 7 are optional. If octet 5 is included,
     * then also octet 6 shall be included and octet 7 may be included.
     */
    if(len==2)
        return(len);

    /* UMTS encryption algorithms supported (octet 5) */
    /* UMTS encryption algorithm UEA0 supported (octet 5, bit 8) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uea0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS encryption algorithm UEA1 supported (octet 5, bit 7) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uea1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS encryption algorithm UEA2 supported (octet 5, bit 6) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uea2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS encryption algorithm UEA3 supported (octet 5, bit 5) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uea3, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS encryption algorithm UEA4 supported (octet 5, bit 4) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uea4, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS encryption algorithm UEA5 supported (octet 5, bit 5) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uea5, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS encryption algorithm UEA6 supported (octet 5, bit 6) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uea6, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS encryption algorithm UEA7 supported (octet 5, bit 7) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uea7, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    /* UMTS integrity algorithms supported (octet 6) */
    /* Bit 8 of octet 6 is spare and shall be coded as zero. */
    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, (curr_offset<<3), 1, ENC_BIG_ENDIAN);
    /* UMTS integrity algorithm UIA1 supported (octet 6, bit 7) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uia1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS integrity algorithm UIA2 supported (octet 6, bit 6) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uia2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS integrity algorithm UIA3 supported (octet 6, bit 5) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uia3, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS integrity algorithm UIA4 supported (octet 6, bit 4) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uia4, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS integrity algorithm UIA5 supported (octet 6, bit 3) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uia5, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS integrity algorithm UIA6 supported (octet 6, bit 2) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uia6, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS integrity algorithm UIA7 supported (octet 6, bit 1) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uia7, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    if(len==4)
        return(len);

    /* Bit 8 of octet 7 is spare and shall be coded as zero. */
    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, (curr_offset<<3), 1, ENC_BIG_ENDIAN);
    /* GPRS encryption algorithm GEA1 supported (octet 7, bit 7) */
    proto_tree_add_item(tree, hf_nas_eps_emm_gea1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* GPRS encryption algorithm GEA2 supported (octet 7, bit 6) */
    proto_tree_add_item(tree, hf_nas_eps_emm_gea2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* GPRS encryption algorithm GEA3 supported (octet 7, bit 5) */
    proto_tree_add_item(tree, hf_nas_eps_emm_gea3, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* GPRS encryption algorithm GEA4 supported (octet 7, bit 4) */
    proto_tree_add_item(tree, hf_nas_eps_emm_gea4, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* GPRS encryption algorithm GEA5 supported (octet 7, bit 3) */
    proto_tree_add_item(tree, hf_nas_eps_emm_gea5, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* GPRS encryption algorithm GEA6 supported (octet 7, bit 2) */
    proto_tree_add_item(tree, hf_nas_eps_emm_gea6, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* GPRS encryption algorithm GEA7 supported (octet 7, bit 1) */
    proto_tree_add_item(tree, hf_nas_eps_emm_gea7, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    return(len);
}
/*
 * 9.9.3.37 Emergency Number List
 * See subclause 10.5.3.13 in 3GPP TS 24.008 [13].
 * packet-gsm_a_dtap.c
 */

/*
 * 9.9.3.38 CLI
 */

/*
 * The coding of the CLI value part is the same as for octets 3 to 14
 * of the Calling party BCD number information element defined in
 * subclause 10.5.4.9 of 3GPP TS 24.008
 */

/*
 * 9.9.3.39 SS Code
 */
static guint16
de_emm_ss_code(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    /*
     * SS Code value
     * The coding of the SS Code value is given in subclause 17.7.5 of 3GPP TS 29.002 [15B].
     * value string imported from gsm map
     */
    proto_tree_add_item(tree, hf_nas_eps_emm_ss_code, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    return(len);
}

/*
 * 9.9.3.40 LCS indicator
 */
/* LCS indicator value */
static const value_string nas_eps_emm_lcs_ind_vals[] = {
    { 0,    "Normal, unspecified"},
    { 1,    "MT-LR"},
    { 0, NULL }
};


static guint16
de_emm_lcs_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;


    proto_tree_add_item(tree, hf_nas_eps_emm_lcs_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    return(len);
}
/*
 * 9.9.3.41 LCS client identity
 */
static guint16
de_emm_lcs_client_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    tvbuff_t *new_tvb;

    curr_offset = offset;

    /* LCS client identity (value part)
     * The coding of the value part of the LCS client identity is given
     * in subclause 17.7.13 of 3GPP TS 29.002 [15B](GSM MAP).
     */
    new_tvb = tvb_new_subset(tvb, curr_offset, len, len );
    dissect_gsm_map_lcs_LCS_ClientID_PDU( new_tvb, gpinfo, tree );

    return(len);
}

/*
 * 9.9.3.42 Generic message container type
 */
static const value_string nas_eps_emm_gen_msg_cont_type_vals[] = {
    { 0,    "Reserved"},
    { 1,    "LTE Positioning Protocol (LPP) message container"},
    { 2,    "Location services message container "},
    { 0, NULL }
};

static guint16
de_emm_gen_msg_cont_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    eps_nas_gen_msg_cont_type = tvb_get_guint8(tvb, curr_offset);
    proto_tree_add_item(tree, hf_nas_eps_emm_gen_msg_cont_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    return(curr_offset - offset);
}
/*
 * 9.9.3.43 Generic message container
 */
static guint16
de_emm_gen_msg_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    proto_item *item;
    proto_tree *sub_tree;
    tvbuff_t *new_tvb;

    item = proto_tree_add_item(tree, hf_nas_eps_gen_msg_cont, tvb, offset, len, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_nas_eps_gen_msg_cont);

    new_tvb = tvb_new_subset(tvb, offset, len, len);

    switch (eps_nas_gen_msg_cont_type) {
    case 1:
        /* LPP */
        if (lpp_handle) {
            call_dissector(lpp_handle, new_tvb, pinfo, sub_tree);
        }
        break;
    case 2:
        /* Location services */
        if (gsm_a_dtap_handle) {
            call_dissector(gsm_a_dtap_handle, new_tvb, pinfo, sub_tree);
        }
        break;
    default:
        break;
    }

    return(len);
}
/*
 * 9.9.3.44 Voice domain preference and UE's usage setting
 * See subclause 10.5.5.28 in 3GPP TS 24.008 [13].
 * packet-gsm_a_dtap.c
 */

 /*
 * 9.9.4    EPS Session Management (ESM) information elements
 */

/*
 * 9.9.4.1 Access point name
 * See subclause 10.5.6.1 in 3GPP TS 24.008 [6].
 */
/*
 * 9.9.4.2 APN aggregate maximum bit rate
 */

static guint16
de_esm_apn_aggr_max_br(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    guint8 octet;
    guint32 dl_total = 0;
    guint32 ul_total = 0;
    guint32 bitrate = 0;

    curr_offset = offset;
    /* APN-AMBR for downlink    octet 3 */
    octet = tvb_get_guint8(tvb,curr_offset);
    if(octet==0){
        proto_tree_add_uint_format(tree, hf_nas_eps_emm_apn_ambr_dl, tvb, curr_offset, 1, octet,
                       "Reserved");
    }else{
        bitrate = calc_bitrate(octet);
        dl_total += bitrate;
        proto_tree_add_uint_format(tree, hf_nas_eps_emm_apn_ambr_dl, tvb, curr_offset, 1, octet,
                       "APN-AMBR for downlink : %u kbps", bitrate);
    }
    curr_offset++;

    /* APN-AMBR for uplink  octet 4 */
    octet = tvb_get_guint8(tvb,curr_offset);
    if(octet==0){
        proto_tree_add_uint_format(tree, hf_nas_eps_emm_apn_ambr_ul, tvb, curr_offset, 1, octet,
                       "Reserved");
    }else{
        bitrate = calc_bitrate(octet);
        ul_total += bitrate;
        proto_tree_add_uint_format(tree, hf_nas_eps_emm_apn_ambr_ul, tvb, curr_offset, 1, octet,
                       "APN-AMBR for uplink : %u kbps", bitrate);
    }
    curr_offset++;
    if ((curr_offset - offset) >= len)
        return(len);
    /* APN-AMBR for downlink (extended) octet 5 */
    octet = tvb_get_guint8(tvb,curr_offset);
    if(octet==0){
        proto_tree_add_uint_format(tree, hf_nas_eps_emm_apn_ambr_dl_ext, tvb, curr_offset, 1, octet,
                       "Use the value indicated by the APN-AMBR for downlink");
    }else{
        bitrate = calc_bitrate_ext(octet);
        dl_total += (octet > 0x4a) ? bitrate*1000 : bitrate;
        proto_tree_add_uint_format(tree, hf_nas_eps_emm_apn_ambr_dl_ext, tvb, curr_offset, 1, octet,
                       "APN-AMBR for downlink (extended) : %u %s",
                       bitrate,
                       (octet > 0x4a) ? "Mbps" : "kbps");
    }
    if (len < 5) {
        /* APN-AMBR for downlink (extended-2) is not present; display total now */
        if (octet != 0) {
            /* Ignore value indicated by the APN-AMBR for downlink */
            dl_total = (octet > 0x4a) ? bitrate*1000 : bitrate;
        }
        if (dl_total >= 1000) {
            proto_tree_add_text(tree, tvb, curr_offset, 1,"Total APN-AMBR for downlink : %.3f Mbps", (gfloat)dl_total / 1000);
            } else {
            proto_tree_add_text(tree, tvb, curr_offset, 1,"Total APN-AMBR for downlink : %u kbps", dl_total);
        }
    }
    curr_offset++;
    if ((curr_offset - offset) >= len)
        return(len);
    /* APN-AMBR for uplink (extended)   octet 6 */
    octet = tvb_get_guint8(tvb,curr_offset);
    if(octet==0){
        proto_tree_add_uint_format(tree, hf_nas_eps_emm_apn_ambr_ul_ext, tvb, curr_offset, 1, octet,
                       "Use the value indicated by the APN-AMBR for uplink");
    }else{
        bitrate = calc_bitrate_ext(octet);
        ul_total += (octet > 0x4a) ? bitrate*1000 : bitrate;
        proto_tree_add_uint_format(tree, hf_nas_eps_emm_apn_ambr_ul_ext, tvb, curr_offset, 1, octet,
                       "APN-AMBR for uplink (extended) : %u %s",
                       bitrate,
                       (octet > 0x4a) ? "Mbps" : "kbps");
    }
    if (len < 6) {
        /* APN-AMBR for uplink (extended-2) is not present; display total now */
        if (octet != 0) {
            /* Ignore value indicated by the APN-AMBR for uplink */
            ul_total = (octet > 0x4a) ? bitrate*1000 : bitrate;
        }
        if (ul_total >= 1000) {
            proto_tree_add_text(tree, tvb, curr_offset, 1,"Total APN-AMBR for uplink : %.3f Mbps", (gfloat)ul_total / 1000);
            } else {
            proto_tree_add_text(tree, tvb, curr_offset, 1,"Total APN-AMBR for uplink : %u kbps", ul_total);
        }
    }
    curr_offset++;
    if ((curr_offset - offset) >= len)
        return(len);
    /* APN-AMBR for downlink (extended-2)   octet 7 */
    octet = tvb_get_guint8(tvb,curr_offset);
    if((octet==0)||(octet==0xff)){
        proto_tree_add_uint_format(tree, hf_nas_eps_emm_apn_ambr_dl_ext2, tvb, curr_offset, 1, octet,
                       "Use the value indicated by the APN-AMBR for downlink and APN-AMBR for downlink (extended)");
    }else{
        dl_total += octet*256*1000;
        proto_tree_add_uint_format(tree, hf_nas_eps_emm_apn_ambr_dl_ext2, tvb, curr_offset, 1, octet,
                       "APN-AMBR for downlink (extended-2) : %u Mbps",
                       (octet* 256));
    }
    proto_tree_add_text(tree, tvb, curr_offset, 1,"Total APN-AMBR for downlink : %.3f Mbps", (gfloat)dl_total / 1000);
    curr_offset++;
    if ((curr_offset - offset) >= len)
        return(len);
    /* APN-AMBR for uplink (extended-2) octet 8 */
    octet = tvb_get_guint8(tvb,curr_offset);
    if((octet==0)||(octet==0xff)){
        proto_tree_add_uint_format(tree, hf_nas_eps_emm_apn_ambr_ul_ext2, tvb, curr_offset, 1, octet,
                       "Use the value indicated by the APN-AMBR for uplink and APN-AMBR for downlink (extended)");
    }else{
        ul_total += octet*256*1000;
        proto_tree_add_uint_format(tree, hf_nas_eps_emm_apn_ambr_ul_ext2, tvb, curr_offset, 1, octet,
                       "APN-AMBR for uplink (extended-2) : %u Mbps",
                       (octet* 256));
    }
    proto_tree_add_text(tree, tvb, curr_offset, 1,"Total APN-AMBR for uplink : %.3f Mbps", (gfloat)ul_total / 1000);
    curr_offset++;

    return(len);
}
/*
 * 9.9.4.3 EPS quality of service
 */

/* Quality of Service Class Identifier (QCI), octet 3 (see 3GPP TS 23.203 [7]) */
static const range_string nas_eps_qci_vals[] = {
    { 0x00, 0x00, "UE -> NW Network selects the QCI / NW -> UE Reserved"},
    { 0x01, 0x01, "QCI 1"},
    { 0x02, 0x02, "QCI 2"},
    { 0x03, 0x03, "QCI 3"},
    { 0x04, 0x04, "QCI 4"},
    { 0x05, 0x05, "QCI 5"},
    { 0x06, 0x06, "QCI 6"},
    { 0x07, 0x07, "QCI 7"},
    { 0x08, 0x08, "QCI 8"},
    { 0x09, 0x09, "QCI 9"},
    { 0x0A, 0x7F, "Reserved"},
    { 0x80, 0xFE, "Operator-specific QCI"},
    { 0xFF, 0xFF, "Reserved"},
    { 0,    0,    NULL }
};



static guint16
de_esm_qos(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    guint8 octet;

    curr_offset = offset;

    /* QCI octet 3 */
    proto_tree_add_item(tree, hf_nas_eps_qci, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;
    if ((curr_offset - offset) >= len)
        return(len);
    /* Maximum bit rate for uplink octet 4 */
    octet = tvb_get_guint8(tvb,curr_offset);
    if(octet==0){
        proto_tree_add_uint_format(tree, hf_nas_eps_mbr_ul, tvb, curr_offset, 1, octet,
                       "UE->NW Subscribed maximum bit rate for uplink/ NW->UE Reserved");
    }else{
        proto_tree_add_uint_format(tree, hf_nas_eps_mbr_ul, tvb, curr_offset, 1, octet,
                       "Maximum bit rate for uplink : %u kbps", calc_bitrate(octet));
    }
    curr_offset++;
    if ((curr_offset - offset) >= len)
        return(len);
    /* Maximum bit rate for downlink octet 5 */
    octet = tvb_get_guint8(tvb,curr_offset);
    if(octet==0){
        proto_tree_add_uint_format(tree, hf_nas_eps_mbr_dl, tvb, curr_offset, 1, octet,
                       "UE->NW Subscribed maximum bit rate for downlink/ NW->UE Reserved");
    }else{
        proto_tree_add_uint_format(tree, hf_nas_eps_mbr_dl, tvb, curr_offset, 1, octet,
                       "Maximum bit rate for downlink : %u kbps", calc_bitrate(octet));
    }
    curr_offset++;
    if ((curr_offset - offset) >= len)
        return(len);
    /* Guaranteed bit rate for uplink octet 6 */
    octet = tvb_get_guint8(tvb,curr_offset);
    proto_tree_add_uint_format(tree, hf_nas_eps_gbr_ul, tvb, curr_offset, 1, octet,
                   "Guaranteed bit rate for uplink : %u kbps", calc_bitrate(octet));

    curr_offset++;
    if ((curr_offset - offset) >= len)
        return(len);
    /* Guaranteed bit rate for downlink octet 7 */
    octet = tvb_get_guint8(tvb,curr_offset);
    proto_tree_add_uint_format(tree, hf_nas_eps_gbr_ul, tvb, curr_offset, 1, octet,
                   "Guaranteed bit rate for downlink : %u kbps", calc_bitrate(octet));

    curr_offset++;
    if ((curr_offset - offset) >= len)
        return(len);
    /* Maximum bit rate for uplink (extended) octet 8 */
    octet = tvb_get_guint8(tvb,curr_offset);
    if(octet==0){
        proto_tree_add_uint_format(tree, hf_nas_eps_embr_ul, tvb, curr_offset, 1, octet,
                       "Use the value indicated by the maximum bit rate for uplink in octet 4.");
    }else{
        proto_tree_add_uint_format(tree, hf_nas_eps_embr_ul, tvb, curr_offset, 1, octet,
                       "Maximum bit rate for uplink(extended) : %u %s",
                       calc_bitrate_ext(octet),
                       (octet > 0x4a) ? "Mbps" : "kbps");
    }
    curr_offset++;
    if ((curr_offset - offset) >= len)
        return(len);
    /* Maximum bit rate for downlink (extended) octet 9 */
    octet = tvb_get_guint8(tvb,curr_offset);
    if(octet==0){
        proto_tree_add_uint_format(tree, hf_nas_eps_embr_ul, tvb, curr_offset, 1, octet,
                       "Use the value indicated by the maximum bit rate for downlink in octet 5.");
    }else{
        proto_tree_add_uint_format(tree, hf_nas_eps_embr_ul, tvb, curr_offset, 1, octet,
                       "Maximum bit rate for downlink(extended) : %u %s",
                       calc_bitrate_ext(octet),
                       (octet > 0x4a) ? "Mbps" : "kbps");
    }
    curr_offset++;
    if ((curr_offset - offset) >= len)
        return(len);
    /* Guaranteed bit rate for uplink (extended) octet 10 */
    octet = tvb_get_guint8(tvb,curr_offset);
    if(octet==0){
        proto_tree_add_uint_format(tree, hf_nas_eps_embr_ul, tvb, curr_offset, 1, octet,
                       "Use the value indicated by the Guaranteed bit rate for uplink in octet 6.");
    }else{
        proto_tree_add_uint_format(tree, hf_nas_eps_embr_ul, tvb, curr_offset, 1, octet,
                       "Guaranteed bit rate for uplink(extended) : %u %s",
                       calc_bitrate_ext(octet),
                       (octet > 0x4a) ? "Mbps" : "kbps");
    }
    curr_offset++;
    if ((curr_offset - offset) >= len)
        return(len);
    /* Guaranteed bit rate for downlink (extended) octet 11 */
    octet = tvb_get_guint8(tvb,curr_offset);
    if(octet==0){
        proto_tree_add_uint_format(tree, hf_nas_eps_embr_ul, tvb, curr_offset, 1, octet,
                       "Use the value indicated by the Guaranteed bit rate for downlink in octet 7.");
    }else{
        proto_tree_add_uint_format(tree, hf_nas_eps_embr_ul, tvb, curr_offset, 1, octet,
                       "Guaranteed bit rate for downlink(extended) : %u %s",
                       calc_bitrate_ext(octet),
                       (octet > 0x4a) ? "Mbps" : "kbps");
    }
    curr_offset++;

    return(len);
}
/*
 * 9.9.4.4 ESM cause
 */

static const value_string nas_eps_esm_cause_vals[] = {
    { 0x08, "Operator Determined Barring"},
    { 0x1a, "Insufficient resources"},
    { 0x1b, "Unknown or missing APN"},
    { 0x1c, "Unknown PDN type"},
    { 0x1d, "User authentication failed"},
    { 0x1e, "Request rejected by Serving GW or PDN GW"},
    { 0x1f, "Request rejected, unspecified"},
    { 0x20, "Service option not supported"},
    { 0x21, "Requested service option not subscribed"},
    { 0x22, "Service option temporarily out of order"},
    { 0x23, "PTI already in use"},
    { 0x24, "Regular deactivation"},
    { 0x25, "EPS QoS not accepted"},
    { 0x26, "Network failure"},
    { 0x27, "Reactivation requested"},
    { 0x29, "Semantic error in the TFT operation"},
    { 0x2a, "Syntactical error in the TFT operation"},
    { 0x2b, "Invalid EPS bearer identity"},
    { 0x2c, "Semantic errors in packet filter(s)"},
    { 0x2d, "Syntactical errors in packet filter(s)"},
    { 0x2e, "EPS bearer context without TFT already activated"},
    { 0x2f, "PTI mismatch"},
    { 0x31, "Last PDN disconnection not allowed"},
    { 0x32, "PDN type IPv4 only allowed"},
    { 0x33, "PDN type IPv6 only allowed"},
    { 0x34, "Single address bearers only allowed"},
    { 0x35, "ESM information not received"},
    { 0x36, "PDN connection does not exist"},
    { 0x37, "Multiple PDN connections for a given APN not allowed"},
    { 0x38, "Collision with network initiated request"},
    { 0x3b, "Unsupported QCI value"},
    { 0x51, "Invalid PTI value"},
    { 0x5f, "Semantically incorrect message"},
    { 0x60, "Invalid mandatory information"},
    { 0x61, "Message type non-existent or not implemented"},
    { 0x62, "Message type not compatible with the protocol state"},
    { 0x63, "Information element non-existent or not implemented"},
    { 0x64, "Conditional IE error"},
    { 0x65, "Message not compatible with the protocol state"},
    { 0x6f, "Protocol error, unspecified"},
    { 0x70, "APN restriction value incompatible with active EPS bearer context"},
    { 0, NULL }
};

static guint16
de_esm_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_nas_eps_esm_cause, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    return(curr_offset - offset);
}
/*
 * 9.9.4.5 ESM information transfer flag
 */
/* EIT (ESM information transfer) */
static const true_false_string  nas_eps_emm_eit_vals = {
    "Security protected ESM information transfer required",
    "Security protected ESM information transfer not required"
};
static guint16
de_esm_inf_trf_flg(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;


    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, (curr_offset<<3)+4, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_esm_eit, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;
    return(curr_offset-offset);
}
/*
 * 9.9.4.6 Linked EPS bearer identity
 */
/*
 * Linked EPS bearer identity (bits 1-4)
 */

static const value_string nas_eps_esm_linked_bearer_id_vals[] = {
    { 0x0,  "Reserved"},
    { 0x1,  "Reserved"},
    { 0x2,  "Reserved"},
    { 0x3,  "Reserved"},
    { 0x4,  "Reserved"},
    { 0x5,  "EPS bearer identity value 5"},
    { 0x6,  "EPS bearer identity value 6"},
    { 0x7,  "EPS bearer identity value 7"},
    { 0x8,  "EPS bearer identity value 8"},
    { 0x9,  "EPS bearer identity value 9"},
    { 0xa,  "EPS bearer identity value 10"},
    { 0xb,  "EPS bearer identity value 11"},
    { 0xc,  "EPS bearer identity value 12"},
    { 0xd,  "EPS bearer identity value 13"},
    { 0xe,  "EPS bearer identity value 14"},
    { 0xf,  "EPS bearer identity value 15"},
    { 0, NULL }
};



static guint16
de_esm_lnkd_eps_bearer_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_nas_eps_esm_lnkd_eps_bearer_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    return(len);
}

/*
 * 9.9.4.7 LLC service access point identifier
 * See subclause 10.5.6.9 in 3GPP TS 24.008
 */

/*
 * 9.9.4.7a Notification indicator
 */
static const value_string nas_eps_esm_notif_ind_vals[] = {
    { 0x0,  "Reserved"},
    { 0x1,  "SRVCC handover cancelled, IMS session re-establishment required"},
    { 0, NULL }
};

static guint16
de_esm_notif_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_nas_eps_esm_notif_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    return(len);
}

/*
 * 9.9.4.8 Packet flow identifier
 * See subclause 10.5.6.11 in 3GPP TS 24.008
 */
/*
 * 9.9.4.9 PDN address
 */
static guint16
de_esm_pdn_addr(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    guint8 pdn_type;

    curr_offset = offset;


    pdn_type  = tvb_get_guint8(tvb, offset) & 0x7;
    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, curr_offset<<3, 5, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_esm_pdn_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    switch(pdn_type){
        case 1:
            /* IPv4 */
            proto_tree_add_item(tree, hf_nas_eps_esm_pdn_ipv4, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
            curr_offset+=4;
            break;
        case 2:
            /* IPv6 3GPP TS 24.301 version 9.4.0 Release 9
             * If PDN type value indicates IPv6, the PDN address information in octet 4 to octet 11
             * contains an IPv6 interface identifier. Bit 8 of octet 4 represents the most significant bit
             * of the IPv6 interface identifier and bit 1 of octet 11 the least significant bit.
             */
            proto_tree_add_item(tree, hf_nas_eps_esm_pdn_ipv6_if_id, tvb, curr_offset, 8, ENC_NA);
            curr_offset+=8;
            break;
        case 3:
            /* IPv4/IPv6 3GPP TS 24.301 version 9.4.0 Release 9
             * If PDN type value indicates IPv4v6, the PDN address information in octet 4 to octet 15
             * contains an IPv6 interface identifier and an IPv4 address. Bit 8 of octet 4 represents
             * the most significant bit of the IPv6 interface identifier and bit 1 of octet 11 the least
             * significant bit. Bit 8 of octet 12 represents the most significant bit of the IPv4 address
             * and bit 1 of octet 15 the least significant bit.
             */
            proto_tree_add_item(tree, hf_nas_eps_esm_pdn_ipv6_if_id, tvb, curr_offset, 8, ENC_NA);
            curr_offset+=8;
            proto_tree_add_item(tree, hf_nas_eps_esm_pdn_ipv4, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
            curr_offset+=4;
            break;
        default:
            break;
    }

    return(curr_offset-offset);
}

/*
 * 9.9.4.10 PDN type
 * Coded inline 1/2 octet
 */
static const value_string nas_eps_esm_pdn_type_values[] = {
    { 0x1,  "IPv4" },
    { 0x2,  "IPv6" },
    { 0x3,  "IPv4v6" },
    { 0x4,  "Unused; shall be interpreted as IPv6 if received by the network" },
    { 0, NULL }
};

/*
 * 9.9.4.11 Protocol configuration options
 * See subclause 10.5.6.3 in 3GPP TS 24.008
 */
/*
 * 9.9.4.12 Quality of service
 * See subclause 10.5.6.5 in 3GPP TS 24.008
 * Coded inline 1/2 octet
 */
/*
 * 9.9.4.13 Radio priority
 * See subclause 10.5.7.2 in 3GPP TS 24.008
 */
/*
 * 9.9.4.14 Request type
 * See subclause 10.5.6.17 in 3GPP TS 24.008
 */
static const value_string nas_eps_esm_request_type_values[] = {
	{ 0x1,	"initial request" },
	{ 0x2,	"Handover" },
	{ 0x3,	"Unused; shall be interpreted as initial request if received by the network" },
	{ 0x4,	"emergency" },
	{ 0, NULL }
 };

/*
 * 9.9.4.15 Traffic flow aggregate description
 * The Traffic flow aggregate description information element is encoded using the same format as the Traffic flow
 * template information element (see subclause 10.5.6.12 in 3GPP TS 24.008 [13]). When sending this IE, the UE shall
 * assign the packet filter identifier values so that they are unique across all packet filters for the PDN connection.
 */
/*
 * 9.9.4.16 Traffic flow template
 * See subclause 10.5.6.12 in 3GPP TS 24.008
 * packet-gsm_a_gm.c
 */
/*
 * 9.9.4.17 Transaction identifier
 * The Transaction identifier information element is coded as the Linked TI information element in 3GPP TS 24.008 [13],
 * subclause 10.5.6.7.
 * The coding of the TI flag, the TI value and the EXT bit is defined in 3GPP TS 24.007[20].
 */

guint16 (*emm_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string, int string_len) = {
    /* 9.9.3    EPS Mobility Management (EMM) information elements */
    de_emm_add_upd_res,         /* 9.9.3.0A Additional update result */
    de_emm_add_upd_type,        /* 9.9.3.0B Additional update type */
    NULL,                       /* 9.9.3.1  Authentication failure parameter(dissected in packet-gsm_a_dtap.c) */
    NULL,                       /* 9.9.3.2  Authentication parameter AUTN(packet-gsm_a_dtap.c) */
    NULL,                       /* 9.9.3.3  Authentication parameter RAND */
    de_emm_auth_resp_par,       /* 9.9.3.4  Authentication response parameter */
    de_emm_csfb_resp,           /* 9.9.3.5  CSFB response */
    NULL,                       /* 9.9.3.6  Daylight saving time (packet-gsm_a_dtap.c)*/
    NULL,                       /* 9.9.3.7  Detach type */
    NULL,                       /* 9.9.3.8  DRX parameter */
    de_emm_cause,               /* 9.9.3.9  EMM cause */
    NULL,                       /* 9.9.3.10 EPS attach result (coded inline) */
    NULL,                       /* 9.9.3.11 EPS attach type(Coded Inline) */
    de_emm_eps_mid,             /* 9.9.3.12 EPS mobile identity */
    de_emm_eps_net_feature_sup, /* 9.9.3.12A EPS network feature support */
    NULL,                       /* 9.9.3.13 EPS update result (Coded Inline)*/
    NULL,                       /* 9.9.3.14 EPS update type (Inline)*/
    de_emm_esm_msg_cont,        /* 9.9.3.15 ESM message conta */
    NULL,                       /* 9.9.3.16 GPRS timer ,See subclause 10.5.7.3 in 3GPP TS 24.008 [6]. (packet-gsm_a_gm.c)*/
    NULL,                       /* 9.9.3.17 Identity type 2 ,See subclause 10.5.5.9 in 3GPP TS 24.008 [6]. */
    de_emm_nas_imeisv_req,      /* 9.9.3.18 IMEISV request ,See subclause 10.5.5.10 in 3GPP TS 24.008 [6]. */
    de_emm_nas_ksi_and_seq_no,  /* 9.9.3.19 KSI and sequence number */
    NULL,                       /* 9.9.3.20 MS network capability ,See subclause 10.5.5.12 in 3GPP TS 24.008 [6].(packet-gsm_a_gm.c) */
    de_emm_nas_key_set_id,      /* 9.9.3.21 NAS key set identifier (Coded Inline) */
    de_emm_nas_msg_cont,        /* 9.9.3.22 NAS message container */
    de_emm_nas_sec_alsgs,       /* 9.9.3.23 NAS security algorithms */
    NULL,                       /* 9.9.3.24 Network name, See subclause 10.5.3.5a in 3GPP TS 24.008 [6]. (packet-gsm_a_dtap.c)*/
    de_emm_nonce,               /* 9.9.3.25 Nonce */
    de_emm_paging_id,           /* 9.9.3.25A Paging identity */
    NULL,                       /* 9.9.3.26 P-TMSI signature, See subclause 10.5.5.8 in 3GPP TS 24.008 [6]. (packet-gsm_a_gm.c)*/
    NULL,                       /* 9.9.3.27 Service type  */
    de_emm_nas_short_mac,       /* 9.9.3.28 Short MAC */
    NULL,                       /* 9.9.3.29 Time zone, See subclause 10.5.3.8 in 3GPP TS 24.008 [6]. (packet-gsm_a_dtap.c)*/
    NULL,                       /* 9.9.3.30 Time zone and time, See subclause 10.5.3.9 in 3GPP TS 24.008 [6]. (packet-gsm_a_dtap.c)*/
    NULL,                       /* 9.9.3.31 TMSI status, See subclause 10.5.5.4 in 3GPP TS 24.008 [6]. (packet-gsm_a_gm.c)*/
    de_emm_trac_area_id,        /* 9.9.3.32 Tracking area identity */
    de_emm_trac_area_id_lst,    /* 9.9.3.33 Tracking area identity list */
    de_emm_ue_net_cap,          /* 9.9.3.34 UE network capability */
    de_emm_ue_ra_cap_inf_upd_need, /* 9.9.3.35  UE radio capability information update needed */
    de_emm_ue_sec_cap,          /* 9.9.3.36 UE security capability */
    NULL,                       /* 9.9.3.37 Emergency Number List (packet-gsm_A_dtap.c) */
    NULL,                       /* 9.9.3.38 CLI */
    de_emm_ss_code,             /* 9.9.3.39 SS Code */
    de_emm_lcs_ind,             /* 9.9.3.40 LCS indicator */
    de_emm_lcs_client_id,       /* 9.9.3.41 LCS client identity */
    de_emm_gen_msg_cont_type,   /* 9.9.3.42 Generic message container type */
    de_emm_gen_msg_cont,        /* 9.9.3.43 Generic message container */
    NULL,                       /* 9.9.3.44 Voice domain preference and UE's usage setting */
    NULL,   /* NONE */
};

/* 9.9.4 EPS Session Management (ESM) information elements */
const value_string nas_esm_elem_strings[] = {
    { 0x00, "Access point name" },                      /* 9.9.4.1 Access point name */
    { 0x00, "APN aggregate maximum bit rate" },         /* 9.9.4.2 APN aggregate maximum bit rate */
    { 0x00, "EPS quality of service" },                 /* 9.9.4.3 EPS quality of service */
    { 0x00, "ESM cause" },                              /* 9.9.4.4 ESM cause */
    { 0x00, "ESM information transfer flag" },          /* 9.9.4.5 ESM information transfer flag */
    { 0x00, "Linked EPS bearer identity" },             /* 9.9.4.6 Linked EPS bearer identity */
    { 0x00, "LLC service access point identifier" },    /* 9.9.4.7 LLC service access point identifier */
    { 0x00, "Notification indicator" },                 /* 9.9.4.7a Notification indicator */
    { 0x00, "Packet flow identifier" },                 /* 9.9.4.8 Packet flow identifier */
    { 0x00, "PDN address" },                            /* 9.9.4.9 PDN address */
    { 0x00, "PDN type" },                               /* 9.9.4.10 PDN type */
    { 0x00, "Protocol configuration options" },         /* 9.9.4.11 Protocol configuration options */
    { 0x00, "Quality of service" },                     /* 9.9.4.12 Quality of service */
    { 0x00, "Radio priority" },                         /* 9.9.4.13 Radio priority */
    { 0x00, "Request type" },                           /* 9.9.4.14 Request type */
    { 0x00, "Traffic flow aggregate description" },     /* 9.9.4.15 Traffic flow aggregate description */
    { 0x00, "Traffic flow templat" },                   /* 9.9.4.16 Traffic flow template */
    { 0x00, "Transaction identifier" },                 /* 9.9.4.17 Transaction identifier */
    { 0, NULL }
};


#define NUM_NAS_ESM_ELEM (sizeof(nas_esm_elem_strings)/sizeof(value_string))
gint ett_nas_eps_esm_elem[NUM_NAS_ESM_ELEM];

typedef enum
{
    DE_ESM_APN,                     /* 9.9.4.1 Access point name */
    DE_ESM_APN_AGR_MAX_BR,          /* 9.9.4.2 APN aggregate maximum bit rate */
    DE_ESM_EPS_QOS,                 /* 9.9.4.3 EPS quality of service */
    DE_ESM_CAUSE,                   /* 9.9.4.4 ESM cause */
    DE_ESM_INF_TRF_FLG,             /* 9.9.4.5 ESM information transfer flag */
    DE_ESM_LNKED_EPS_B_ID,          /* 9.9.4.6 Linked EPS bearer identity  */
    DE_ESM_LLC_SAPI,                /* 9.9.4.7 LLC service access point identifier */
    DE_ESM_NOTIF_IND,               /* 9.9.4.7a Notification indicator */
    DE_ESM_P_FLW_ID,                /* 9.9.4.8 Packet flow identifier  */
    DE_ESM_PDN_ADDR,                /* 9.9.4.9 PDN address */
    DE_ESM_PDN_TYPE,                /* 9.9.4.10 PDN type */
    DE_ESM_PROT_CONF_OPT,           /* 9.9.4.11 Protocol configuration options */
    DE_ESM_QOS,                     /* 9.9.4.12 Quality of service */
    DE_ESM_RA_PRI,                  /* 9.9.4.13 Radio priority  */
    DE_ESM_REQ_TYPE,                /* 9.9.4.14 Request type */
    DE_ESM_TRAF_FLOW_AGR_DESC,      /* 9.9.4.15 Traffic flow aggregate description */
    DE_ESM_TRAF_FLOW_TEMPL,         /* 9.9.4.16 Traffic flow template */
    DE_ESM_TID,                     /* 9.9.4.17 Transaction identifier  */
    DE_ESM_NONE                     /* NONE */
}

nas_esm_elem_idx_t;

guint16 (*esm_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string, int string_len) = {
    NULL,                           /* 9.9.4.1 Access point name */
    de_esm_apn_aggr_max_br,         /* 9.9.4.2 APN aggregate maximum bit rate */
    de_esm_qos,                     /* 9.9.4.3 EPS quality of service */
    de_esm_cause,                   /* 9.9.4.4 ESM cause */
    de_esm_inf_trf_flg,             /* 9.9.4.5 ESM information transfer flag */
    de_esm_lnkd_eps_bearer_id,      /* 9.9.4.6 Linked EPS bearer identity  */
    NULL,                           /* 9.9.4.7 LLC service access point identifier */
    de_esm_notif_ind,               /* 9.9.4.7a Notification indicator */
    NULL,                           /* 9.9.4.8 Packet flow identifier  */
    de_esm_pdn_addr,                /* 9.9.4.9 PDN address */
    NULL,                           /* 9.9.4.10 PDN type */
    NULL,                           /* 9.9.4.11 Protocol configuration options */
    NULL,                           /* 9.9.4.12 Quality of service */
    NULL,                           /* 9.9.4.13 Radio priority  */
    NULL,                           /* 9.9.4.14 Request type */
    NULL,                           /* 9.9.4.15 Traffic flow aggregate description */
    NULL,                           /* 9.9.4.16 Traffic flow template */
    NULL,                           /* 9.9.4.17 Transaction identifier  */
    NULL,   /* NONE */
};

/* MESSAGE FUNCTIONS */

/*
 * 8.2.1    Attach accept
 */

static void
nas_emm_attach_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset, bit_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*  Spare half octet    Spare half octet 9.9.2.7    M   V   1/2 */
    bit_offset = curr_offset<<3;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_spare_half_octet, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset+=4;
    /*  EPS attach result   EPS attach result 9.9.3.10  M   V   1/2 */
    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_EPS_attach_result, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
    bit_offset+=3;
    /* Fix up the lengths */
    curr_len--;
    curr_offset++;
    /*  T3412 value GPRS timer 9.9.3.16 M   V   1 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER, " - T3412 value");
    /*  Tracking area identity list 9.9.3.33    M   LV  7-97 */
    ELEM_MAND_LV(NAS_PDU_TYPE_EMM, DE_EMM_TRAC_AREA_ID_LST, " - TAI list");
    /*  ESM message container 9.9.3.15  M   LV-E    2-n */
    ELEM_MAND_LV_E(NAS_PDU_TYPE_EMM, DE_EMM_ESM_MSG_CONT, NULL);
    /* 50   GUTI    EPS mobile identity 9.9.3.12    O   TLV 13 */
    ELEM_OPT_TLV(0x50, NAS_PDU_TYPE_EMM, DE_EMM_EPS_MID, " - GUTI");
    /* 13   Location area identification    Location area identification 9.9.2.2    O   TV  6 */
    ELEM_OPT_TV(0x13, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_LOC_AREA_ID, NULL);
    /* 23   MS identity     Mobile identity 9.9.2.3 O   TLV 7-10 */
    ELEM_OPT_TLV(0x23, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_MOB_ID, " - MS identity");
    /* 53   EMM cause   EMM cause 9.9.3.9   O   TV  2 */
    ELEM_OPT_TV(0x53, NAS_PDU_TYPE_EMM, DE_EMM_CAUSE, NULL);
    /* 17   T3402 value GPRS timer 9.9.3.16 O   TV  2 */
    ELEM_OPT_TV(0x17, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER, " - T3402 value");
    /* 59   T3423 value GPRS timer 9.9.3.16 O   TV  2 */
    ELEM_OPT_TV(0x59, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER, " - T3423 value");
    /* 4A   Equivalent PLMNs    PLMN list 9.9.2.8   O   TLV 5-47 */
    ELEM_OPT_TLV(0x4a, GSM_A_PDU_TYPE_COMMON, DE_PLMN_LIST, " - Equivalent PLMNs");
    /* 34   Emergency Number List 9.9.3.37  O   TLV 5-50 */
    ELEM_OPT_TLV(0x34, GSM_A_PDU_TYPE_DTAP, DE_EMERGENCY_NUM_LIST, NULL);
    /* 64   EPS network feature support EPS network feature support 9.9.3.12A   O   TLV 3 */
    ELEM_OPT_TLV(0x64, NAS_PDU_TYPE_EMM, DE_EMM_EPS_NET_FEATURE_SUP, NULL);
    /* F-   Additional update result    Additional update result 9.9.3.0A   O   TV  1 */
    ELEM_OPT_TV_SHORT( 0xF0 , NAS_PDU_TYPE_EMM, DE_EMM_ADD_UPD_RES, NULL );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.2.2    Attach complete
 */
static void
nas_emm_attach_comp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* ESM message container    ESM message container 9.9.3.15  M   LV-E    2-n */
    ELEM_MAND_LV_E(NAS_PDU_TYPE_EMM, DE_EMM_ESM_MSG_CONT, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);

}

/*
 * 8.2.3    Attach reject
 */
static void
nas_emm_attach_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* * EMM cause  EMM cause 9.9.3.9   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_EMM, DE_EMM_CAUSE, NULL);
    /* 78 ESM message container ESM message container 9.9.3.15  O   TLV-E   4-n */
    ELEM_OPT_TLV_E(0x78, NAS_PDU_TYPE_EMM, DE_EMM_ESM_MSG_CONT, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);

}
/*
 * 8.2.4    Attach request
 */
static void
nas_emm_attach_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset, bit_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    bit_offset = curr_offset<<3;

    /* NAS key set identifier   NAS key set identifier 9.9.3.21 M   V   1/2 */
    de_emm_nas_key_set_id_bits(tvb, tree, bit_offset, NULL);
    bit_offset+=4;

    /* EPS attach type  EPS attach type 9.9.3.11    M   V   1/2
     * Inline:
     */
    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_eps_att_type, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
    bit_offset+=3;

    /* Fix the lengths */
    curr_len--;
    curr_offset++;
    /* Old GUTI or IMSI EPS mobile identity 9.9.3.12    M   LV  5-12 */
    ELEM_MAND_LV(NAS_PDU_TYPE_EMM, DE_EMM_EPS_MID, " - Old GUTI or IMSI");
    /* UE network capability    UE network capability 9.9.3.34  M   LV  3-14 */
    ELEM_MAND_LV(NAS_PDU_TYPE_EMM, DE_EMM_UE_NET_CAP, NULL);
    /* ESM message container    ESM message container 9.9.3.15  M   LV-E    2-n */
    ELEM_MAND_LV_E(NAS_PDU_TYPE_EMM, DE_EMM_ESM_MSG_CONT, NULL);
    /* 19   Old P-TMSI signature    P-TMSI signature 10.5.5.8   O   TV  4 */
    ELEM_OPT_TV( 0x19 , GSM_A_PDU_TYPE_GM, DE_P_TMSI_SIG, " - Old P-TMSI Signature");
    /* 50   Additional GUTI EPS mobile identity 9.9.3.12    O   TLV 13 */
    ELEM_OPT_TLV( 0x50 , NAS_PDU_TYPE_EMM, DE_EMM_EPS_MID, " - Additional GUTI");
    /* 52 Last visited registered TAI   Tracking area identity 9.9.3.32 O   TV  6 */
    ELEM_OPT_TV(0x52, NAS_PDU_TYPE_EMM, DE_EMM_TRAC_AREA_ID, " - Last visited registered TAI");
    /* 5c DRX parameter DRX parameter 9.9.3.8   O   TV  3 */
    ELEM_OPT_TV(0x5c, GSM_A_PDU_TYPE_GM, DE_DRX_PARAM, NULL );
    /* 31 MS network capability MS network capability 9.9.3.20  M   LV  3-9 */
    ELEM_OPT_TLV( 0x31, GSM_A_PDU_TYPE_GM, DE_MS_NET_CAP , NULL );
    /* 13 Old location area identification  Location area identification 9.9.2.2    O   TV  6 */
    ELEM_OPT_TV(0x13, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_LOC_AREA_ID, " - Old location area identification");
    /* 9- TMSI status   TMSI status 9.9.3.31    O   TV  1 */
    ELEM_OPT_TV_SHORT( 0x90 , GSM_A_PDU_TYPE_GM, DE_TMSI_STAT , NULL );
    /* 11   Mobile station classmark 2  Mobile station classmark 2 9.9.2.5  O   TLV 5 */
    ELEM_OPT_TLV( 0x11, NAS_PDU_TYPE_COMMON, DE_EPS_MS_CM_2 , NULL );
    /* 20   Mobile station classmark 3  Mobile station classmark 3 9.9.2.5  O   TLV 2-34 */
    ELEM_OPT_TLV( 0x20, NAS_PDU_TYPE_COMMON, DE_EPS_MS_CM_3 , NULL );
    /* 40   Supported Codecs    Supported Codec List 9.9.2.10   O   TLV 5-n */
    ELEM_OPT_TLV(0x40, GSM_A_PDU_TYPE_DTAP, DE_SUP_CODEC_LIST, " - Supported Codecs");
    /* F-   Additional update type  Additional update type 9.9.3.0B O   TV  1 */
    ELEM_OPT_TV_SHORT( 0xF0 , NAS_PDU_TYPE_EMM, DE_EMM_ADD_UPD_TYPE, NULL );
    /* 5D   Voice domain preference and UE's usage setting  Voice domain preference and UE's usage setting 9.9.3.44 O   TLV 3 */
    ELEM_OPT_TLV(0x5D, GSM_A_PDU_TYPE_GM, DE_VOICE_DOMAIN_PREF, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.2.5    Authentication failure
 */
static void
nas_emm_attach_fail(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

     /* EMM cause   EMM cause 9.9.3.9   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_EMM, DE_EMM_CAUSE, NULL);
    /* 30 Authentication failure parameter  Authentication failure parameter 9.9.3.1    O   TLV 1 */
    ELEM_OPT_TLV(0x30, GSM_A_PDU_TYPE_DTAP, DE_AUTH_FAIL_PARAM, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.2.6    Authentication reject
 * No IE:s
 */
/*
 * 8.2.7    Authentication request
 */

static void
nas_emm_auth_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset, bit_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    bit_offset = curr_offset<<3;
    /* H1 */
    /*  Spare half octet    Spare half octet 9.9.2.7    M   V   1/2 */
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_spare_half_octet, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset+=4;
    /* H0 */
    /*
     * NAS key set identifierASME   NAS key set identifier 9.9.3.21 M   V   1/2
     */
    de_emm_nas_key_set_id_bits(tvb, tree, bit_offset, " ASME");
    bit_offset+=4;

    /* Fix the lengths */
    curr_len--;
    curr_offset++;

    /*
     * Authentication parameter RAND (EPS challenge) 9.9.3.3    M   V   16
     */
    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_AUTH_PARAM_RAND, " - EPS challenge");
    /*
     * Authentication parameter AUTN (EPS challenge) 9.9.3.2    M   LV  17
     */
    ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_AUTH_PARAM_AUTN, " - EPS challenge");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);

}
/*
 * 8.2.8    Authentication response
 */
static void
nas_emm_auth_resp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*
     * Authentication response parameter 9.9.3.4    M   LV  5-17
     */
    ELEM_MAND_LV(NAS_PDU_TYPE_EMM, DE_EMM_AUTH_RESP_PAR, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.2.9    CS service notification
 */

static void
nas_emm_cs_serv_not(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    consumed = 0;

    /* Paging identity  Paging identity 9.9.3.25A   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_EMM, DE_EMM_PAGING_ID, NULL);
    /* 60   CLI CLI 9.9.3.38    O   TLV 3-12 */
    ELEM_OPT_TLV(0x60, GSM_A_PDU_TYPE_DTAP, DE_CLD_PARTY_BCD_NUM, " - CLI");
    /* 61   SS Code SS Code 9.9.3.39    O   TV  2 */
    ELEM_OPT_TV(0x61, NAS_PDU_TYPE_EMM, DE_EMM_SS_CODE, NULL);
    /* 62   LCS indicator   LCS indicator 9.9.3.40  O   TV  2 */
    ELEM_OPT_TV(0x62, NAS_PDU_TYPE_EMM, DE_EMM_LCS_IND, NULL);
    /* 63   LCS client identity LCS client identity 9.9.3.41    O   TLV 3-257 */
    ELEM_OPT_TLV(0x63, NAS_PDU_TYPE_EMM, DE_EMM_LCS_CLIENT_ID, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.2.10   Detach accept
 * 8.2.10.1 Detach accept (UE originating detach)
 * No further IE's
 * 8.2.10.2 Detach accept (UE terminated detach)
 * No further IE's
 */
/*
 * 8.2.11   Detach request
 * 8.2.11.1 Detach request (UE originating detach)
 */

static void
nas_emm_detach_req_UL(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset,bit_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    proto_tree_add_text(tree, tvb, curr_offset, len,"Up link");
    /* NAS key set identifier   NAS key set identifier 9.9.3.21 M   V   1/2 */
    bit_offset = curr_offset<<3;
    de_emm_nas_key_set_id_bits(tvb, tree, bit_offset, NULL);
    bit_offset+=4;
    /* Detach type  Detach type 9.9.3.6 M   V   1/2 */
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_switch_off, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_detach_type_UL, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
    bit_offset+=3;

    /* Fix the lengths */
    curr_len--;
    curr_offset++;

    /* GUTI or IMSI EPS mobile identity 9.9.3.12    M   LV  5-12 */
    ELEM_MAND_LV(NAS_PDU_TYPE_EMM, DE_EMM_EPS_MID, " - GUTI or IMSI");

    return;
}
/*
 * 8.2.11.2 Detach request (UE terminated detach)
 */
static void
nas_emm_detach_req_DL(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset, bit_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    proto_tree_add_text(tree, tvb, curr_offset, len,"Down link");
    /* Spare half octet Spare half octet 9.9.2.7    M   V   1/2 */
    bit_offset = curr_offset<<3;
    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset+=4;
    /* Detach type  Detach type 9.9.3.6 M   V   1/2 */
    /* In the network to UE direction bit 4 is spare. The network shall set this bit to zero. */
    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_detach_type_DL, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
    bit_offset+=3;

    /* Fix the lengths */
    curr_len--;
    curr_offset++;

    /* No more mandatory elements */
    if (curr_len==0)
        return;

    /* EMM cause    EMM cause 9.9.3.9   O   TV  2 */
    ELEM_OPT_TV(0x53, NAS_PDU_TYPE_EMM, DE_EMM_CAUSE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);

    return;
}
static void
nas_emm_detach_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    /*guint curr_len;*/

    curr_offset = offset;
    /*curr_len = len;*/

    if (pinfo){
        if(pinfo->link_dir==P2P_DIR_UL){
            nas_emm_detach_req_UL(tvb, tree, pinfo, offset, len);
            return;
        }else if(pinfo->link_dir==P2P_DIR_DL){
            nas_emm_detach_req_DL(tvb, tree, pinfo, offset, len);
            return;
        }
    }
    proto_tree_add_text(tree, tvb, curr_offset, len,"UL/DL not known, can't properly dissect");
    proto_tree_add_text(tree, tvb, curr_offset, len,"Trying to dissect as UE terminated detach");
    nas_emm_detach_req_DL(tvb, tree, pinfo, offset, len);
    proto_tree_add_text(tree, tvb, curr_offset, len,"Trying to dissect as UE originating detach");
    nas_emm_detach_req_UL(tvb, tree, pinfo, offset, len);

    return;

}

/*
 * 8.2.12   Downlink NAS Transport
 */
static void
nas_emm_dl_nas_trans(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    pinfo->link_dir = P2P_DIR_DL;

    /* NAS message container    NAS message container 9.9.3.22  M   LV  3-252 */
    ELEM_MAND_LV(NAS_PDU_TYPE_EMM, DE_EMM_NAS_MSG_CONT, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.2.13   EMM information
 */
static void
nas_emm_emm_inf(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* 43   Full name for network   Network name 9.9.3.24   O   TLV 3-? */
    ELEM_OPT_TLV(0x43, GSM_A_PDU_TYPE_DTAP, DE_NETWORK_NAME, " - Full name for network");
    /* 45   Short name for network  Network name 9.9.3.24   O   TLV 3-? */
    ELEM_OPT_TLV(0x45, GSM_A_PDU_TYPE_DTAP, DE_NETWORK_NAME, " - Short Name");
    /* 46   Local time zone Time zone 9.9.3.29  O   TV  2 */
    ELEM_OPT_TV(0x46, GSM_A_PDU_TYPE_DTAP, DE_TIME_ZONE, " - Local");
    /* 47   Universal time and local time zone  Time zone and time 9.9.3.30 O   TV  8 */
    ELEM_OPT_TV(0x47, GSM_A_PDU_TYPE_DTAP, DE_TIME_ZONE_TIME, " - Universal Time and Local Time Zone");
    /* 49   Network daylight saving time    Daylight saving time 9.9.3.6    O   TLV 3 */
    ELEM_OPT_TLV(0x49, GSM_A_PDU_TYPE_DTAP, DE_DAY_SAVING_TIME, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}


/*
 * 8.2.14   EMM status
 */
static void
nas_emm_emm_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* EMM cause    EMM cause 9.9.3.9   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_EMM, DE_EMM_CAUSE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.2.15   Extended service request
 */
static void
nas_emm_ext_serv_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset,bit_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    bit_offset = curr_offset<<3;

    /* NAS key set identifier   NAS key set identifier 9.9.3.21 M   V   1/2 */
    de_emm_nas_key_set_id_bits(tvb, tree, bit_offset, NULL);
    bit_offset+=4;
    /* Service type Service type 9.9.3.27   M   V   1/2 Service type*/
    proto_tree_add_bits_item(tree, hf_nas_eps_service_type, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset+=4;
    /* Fix up the lengths */
    curr_len--;
    curr_offset++;

    /* M-TMSI   Mobile identity 9.9.2.3 M   LV  6 */
    ELEM_MAND_LV(NAS_PDU_TYPE_COMMON, DE_EPS_CMN_MOB_ID, " - M-TMSI");
    /* B-   CSFB response   CSFB response 9.9.3.5   C   TV  1 */
    ELEM_OPT_TV_SHORT(0xb0, NAS_PDU_TYPE_EMM, DE_EMM_CSFB_RESP, NULL);
    /* 57   EPS bearer context status   EPS bearer context status 9.9.2.1   O   TLV 4 */
    ELEM_OPT_TLV(0x57, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_EPS_BE_CTX_STATUS, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.2.16   GUTI reallocation command
 */
static void
nas_emm_guti_realloc_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* GUTI EPS mobile identity 9.9.3.12    M   LV  12 */
    ELEM_MAND_LV(NAS_PDU_TYPE_EMM, DE_EMM_EPS_MID, " - GUTI");

    /* 54   TAI list    Tracking area identity list 9.9.3.33    O   TLV 8-98 */
    ELEM_OPT_TLV(0x54, NAS_PDU_TYPE_EMM, DE_EMM_TRAC_AREA_ID_LST, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.2.17   GUTI reallocation complete
 * No more IE's
 */
/*
 * 8.2.18   Identity request
 */

static void
nas_emm_id_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset, bit_offset;
    /*guint32   consumed;*/
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;


    bit_offset=curr_offset<<3;

    /* Spare half octet Spare half octet 9.9.2.7    M   V   1/2 */
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_spare_half_octet, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset+=4;

    /* Identity type    Identity type 2 9.9.3.17    M   V   1/2 */
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_id_type2, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset+=4;
    /*consumed = 1;*/


    /* Fix up the lengths */
    curr_len--;
    curr_offset++;

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.2.19   Identity response
 */
static void
nas_emm_id_res(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Mobile identity  Mobile identity 9.9.2.3 M   LV  4-10 */
    ELEM_MAND_LV(NAS_PDU_TYPE_COMMON, DE_EPS_CMN_MOB_ID, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}



/*
 * 8.2.20   Security mode command
 */
static void
nas_emm_sec_mode_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset, bit_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*  Selected NAS security algorithms    NAS security algorithms 9.9.3.23    M   V   1  */
    ELEM_MAND_V(NAS_PDU_TYPE_EMM, DE_EMM_NAS_SEC_ALGS, " - Selected NAS security algorithms");

    bit_offset = curr_offset<<3;
    /* Spare half octet Spare half octet 9.9.2.7    M   V   1/2 */
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_spare_half_octet, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset+=4;
    /*  NAS key set identifierASME  NAS key set identifier 9.9.3.21 M   V   1/2 */
    de_emm_nas_key_set_id_bits(tvb, tree, bit_offset, " ASME");
    bit_offset+=4;

    /* Fix up the lengths */
    curr_len--;
    curr_offset++;

    /*  Replayed UE security capabilities   UE security capability 9.9.3.36 M   LV  3-6 */
    ELEM_MAND_LV(NAS_PDU_TYPE_EMM, DE_EMM_UE_SEC_CAP, " - Replayed UE security capabilities");
    /* C-   IMEISV request  IMEISV request 9.9.3.18 O   TV  1 */
    ELEM_OPT_TV_SHORT( 0xC0 , NAS_PDU_TYPE_EMM, DE_EMM_IMEISV_REQ , NULL );
    /* 55   Replayed NonceUE    Nonce 9.9.3.25  O   TV  5 */
    ELEM_OPT_TV(0x55, NAS_PDU_TYPE_EMM, DE_EMM_NONCE, " - Replayed NonceUE");
    /* 56   NonceMME    Nonce 9.9.3.25  O   TV  5 */
    ELEM_OPT_TV(0x56, NAS_PDU_TYPE_EMM, DE_EMM_NONCE, " - NonceMME");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.2.21   Security mode complete
 */
static void
nas_emm_sec_mode_comp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    if (curr_len == 0)
        return;

    /* 23   IMEISV  Mobile identity 9.9.2.3 O   TLV 11 */
    ELEM_OPT_TLV(0x23, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_MOB_ID, " - IMEISV");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.2.22   Security mode reject
 */
static void
nas_emm_sec_mode_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* EMM cause    EMM cause 9.9.3.9   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_EMM, DE_EMM_CAUSE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.2.23   Security protected NAS message
 */
#if 0
static int
nas_emm_sec_prot_msg(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint   curr_len;
    guint8 security_header_type;

    curr_offset = offset;
    curr_len = len;

    /* Security header type Security header type 9.3.1 M V 1/2 */
    security_header_type = tvb_get_guint8(tvb,offset)>>4;
    proto_tree_add_item(tree, hf_nas_eps_security_header_type, tvb, 0, 1, ENC_BIG_ENDIAN);
    /* Protocol discriminator Protocol discriminator 9.2 M V 1/2 */
    proto_tree_add_item(tree, hf_gsm_a_L3_protocol_discriminator, tvb, 0, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Message authentication code  Message authentication code 9.5 M   V   4 */
    if (security_header_type !=0){
        /* Message authentication code */
        proto_tree_add_item(tree, hf_nas_eps_msg_auth_code, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;
        if ((security_header_type==2)||(security_header_type==4)){
            /* Integrity protected and ciphered = 2, Integrity protected and ciphered with new EPS security context = 4 */
            proto_tree_add_text(tree, tvb, offset, len-5,"Ciphered message");
            return offset;
        }
    }else{
        proto_tree_add_text(tree, tvb, offset, len,"Not a security protected message");
        return offset;
    }
    /* Sequence number  Sequence number 9.6 M   V   1 */
    proto_tree_add_item(tree, hf_nas_eps_seq_no, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* NAS message  NAS message 9.7 M   V   1-n  */
    return offset;
}
#endif
/*
 * 8.2.24   Service reject
 */
static void
nas_emm_serv_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* EMM cause    EMM cause 9.9.3.9   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_EMM, DE_EMM_CAUSE, NULL);

    /* 5B   T3442 value GPRS timer 9.9.3.16 C   TV  2 */
    ELEM_OPT_TV(0x5b, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER, " - T3442 value");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.2.25   Service request
 * This message is sent by the UE to the network to request the establishment
 * of a NAS signalling connection and of the radio and S1 bearers.
 * Its structure does not follow the structure of a standard layer 3 message. See table 8.2.25.1.
 */
/* Table 8.2.25.1
 * Protocol discriminator Protocol discriminator 9.2 M V 1/2
 * Security header type Security header type 9.3.1 M V 1/2
 * KSI and sequence number KSI and sequence number 9.9.3.19 M V 1
 * Message authentication code (short) Short MAC 9.9.3.28 M V 2
 */
static void
nas_emm_service_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* KSI and sequence number 9.9.3.19 M V 1   */
    ELEM_MAND_V(NAS_PDU_TYPE_EMM, DE_EMM_KSI_AND_SEQ_NO, NULL);

    /* Short MAC 9.9.3.28 M V 2 */
    ELEM_MAND_V(NAS_PDU_TYPE_EMM, DE_EMM_SHORT_MAC, " - Message authentication code (short)");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.2.26   Tracking area update accept
 */
static void
nas_emm_trac_area_upd_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset, bit_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*  Spare half octet    Spare half octet 9.9.2.7    M   V   1/2 */
    bit_offset = curr_offset<<3;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_spare_half_octet, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset+=4;
    /*  EPS update result   EPS update result 9.9.3.13  M   V   1/2 */
    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(tree, hf_nas_eps_eps_update_result_value, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
    bit_offset+=3;
    /* Fix up the lengths */
    curr_len--;
    curr_offset++;
    /* No more mandatory elements */
    if (curr_len==0)
        return;
    /* 5A   T3412 value GPRS timer 9.9.3.16 O   TV  2 */
    ELEM_OPT_TV(0x5a, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER, " - T3412 value");
    /* 50   GUTI    EPS mobile identity 9.9.3.12    O   TLV 13 */
    ELEM_OPT_TLV(0x50, NAS_PDU_TYPE_EMM, DE_EMM_EPS_MID, " - GUTI");
    /* 54   TAI list    Tracking area identity list 9.9.3.33    O   TLV 8-98 */
    ELEM_OPT_TLV(0x54, NAS_PDU_TYPE_EMM, DE_EMM_TRAC_AREA_ID_LST, NULL);
    /* 57   EPS bearer context status   EPS bearer context status 9.9.2.1   O   TLV 4 */
    ELEM_OPT_TLV(0x57, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_EPS_BE_CTX_STATUS, NULL);
    /* 13   Location area identification    Location area identification 9.9.2.2    O   TV  6 */
    ELEM_OPT_TV(0x13, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_LOC_AREA_ID, NULL);
    /* 23   MS identity Mobile identity 9.9.2.3 O   TLV 7-10  */
    ELEM_OPT_TLV(0x23, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_MOB_ID, " - MS identity");
    /* 53   EMM cause   EMM cause 9.9.3.9   O   TV  2  */
    ELEM_OPT_TV(0x53, NAS_PDU_TYPE_EMM, DE_EMM_CAUSE, NULL);
    /* 17   T3402 value GPRS timer 9.9.3.16 O   TV  2  */
    ELEM_OPT_TV(0x17, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER, " - T3402 value");
    /* 59   T3423 value GPRS timer 9.9.3.16 O   TV  2 */
    ELEM_OPT_TV(0x59, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER, " - T3423 value");
    /* 4A   Equivalent PLMNs    PLMN list 9.9.2.8   O   TLV 5-47 */
    ELEM_OPT_TLV(0x4a, GSM_A_PDU_TYPE_COMMON, DE_PLMN_LIST, " - PLMN list");
    /* 34   Emergency Number List   Emergency Number List 9.9.3.37  O   TLV 5-50 */
    ELEM_OPT_TLV(0x34, GSM_A_PDU_TYPE_DTAP, DE_EMERGENCY_NUM_LIST, NULL);
    /* 64   EPS network feature support EPS network feature support 9.9.3.12A   O   TLV 3 */
    ELEM_OPT_TLV(0x64, NAS_PDU_TYPE_EMM, DE_EMM_EPS_NET_FEATURE_SUP, NULL);
    /* F-   Additional update result    Additional update result 9.9.3.0A   O   TV  1 */
    ELEM_OPT_TV_SHORT( 0xF0 , NAS_PDU_TYPE_EMM, DE_EMM_ADD_UPD_RES, NULL );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.2.27   Tracking area update complete
 * No more IE's
 */
/*
 * 8.2.28   Tracking area update reject
 */
static void
nas_emm_trac_area_upd_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* EMM cause    EMM cause 9.9.3.9   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_EMM, DE_EMM_CAUSE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.2.29   Tracking area update request
 */
static void
nas_emm_trac_area_upd_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{

    guint32 curr_offset, bit_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    bit_offset = curr_offset<<3;

    /*  NAS key set identifierASME  NAS key set identifier 9.9.3.21 M   V   1/2 */
    de_emm_nas_key_set_id_bits(tvb, tree, bit_offset, " ASME");
    bit_offset+=4;

    /*  EPS update type EPS update type 9.9.3.14    M   V   1/2 */
    proto_tree_add_bits_item(tree, hf_nas_eps_active_flg, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(tree, hf_nas_eps_eps_update_type_value, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
    bit_offset+=3;

    /* Fix the lengths */
    curr_len--;
    curr_offset++;
    /*  Old GUTI    EPS mobile identity 9.9.3.12    M   LV  12 */
    ELEM_MAND_LV(NAS_PDU_TYPE_EMM, DE_EMM_EPS_MID, " - Old GUTI");
    /* No more Mandatory elements */

    /*  B-  NAS key set identifier  Non-current native NAS key set identifier 9.9.3.21  O   TV  1 */
    ELEM_OPT_TV_SHORT( 0xb0 , NAS_PDU_TYPE_EMM, DE_EMM_NAS_KEY_SET_ID , " - Non-current native NAS key set identifier" );
    /* 8-   GPRS ciphering key sequence number  Ciphering key sequence number 9.9.3.4a  O   TV  1  */
    ELEM_OPT_TV_SHORT(0x80, GSM_A_PDU_TYPE_COMMON, DE_CIPH_KEY_SEQ_NUM, " - GPRS ciphering key sequence number");
    /* 19   Old P-TMSI signature    P-TMSI signature 9.9.3.26   O   TV  4 */
    ELEM_OPT_TV( 0x19 , GSM_A_PDU_TYPE_GM, DE_P_TMSI_SIG, " - Old P-TMSI Signature");
    /* 50   Additional GUTI EPS mobile identity 9.9.3.12    O   TLV 13 */
    ELEM_OPT_TLV(0x50, NAS_PDU_TYPE_EMM, DE_EMM_EPS_MID, " - Additional GUTI");
    /* 55   NonceUE Nonce 9.9.3.25  O   TV  5 */
    ELEM_OPT_TV(0x55, NAS_PDU_TYPE_EMM, DE_EMM_NONCE, " - NonceUE");
    /* 58   UE network capability   UE network capability 9.9.3.34  O   TLV 4-15 */
    ELEM_OPT_TLV(0x58, NAS_PDU_TYPE_EMM, DE_EMM_UE_NET_CAP, NULL);
    /* 52   Last visited registered TAI Tracking area identity 9.9.3.32 O   TV  6 */
    ELEM_OPT_TV(0x52, NAS_PDU_TYPE_EMM, DE_EMM_TRAC_AREA_ID, " - Last visited registered TAI");
    /* 5C   DRX parameter   DRX parameter 9.9.3.8   O   TV  3 */
    ELEM_OPT_TV(0x5c, GSM_A_PDU_TYPE_GM, DE_DRX_PARAM, NULL );
    /* A-   UE radio capability information update needed   UE radio capability information update needed 9.9.3.35  O   TV  1 */
    ELEM_OPT_TV_SHORT( 0xA0 , NAS_PDU_TYPE_EMM, DE_EMM_UE_RA_CAP_INF_UPD_NEED , NULL );
    /* 57   EPS bearer context status   EPS bearer context status 9.9.2.1   O   TLV 4 */
    ELEM_OPT_TLV(0x57, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_EPS_BE_CTX_STATUS, NULL);
    /* 31   MS network capability   MS network capability 9.9.3.20  O   TLV 4-10 */
    ELEM_OPT_TLV( 0x31 , GSM_A_PDU_TYPE_GM, DE_MS_NET_CAP , NULL );
    /* 13   Old location area identification    Location area identification 9.9.2.2    O   TV  6 */
    ELEM_OPT_TV(0x13, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_LOC_AREA_ID, " - Old location area identification");
    /* 9-   TMSI status TMSI status 9.9.3.31    O   TV  1  */
    ELEM_OPT_TV_SHORT( 0x90 , GSM_A_PDU_TYPE_GM, DE_TMSI_STAT , NULL );
    /* 11   Mobile station classmark 2  Mobile station classmark 2 9.9.2.5  O   TLV 5 */
    ELEM_OPT_TLV( 0x11, NAS_PDU_TYPE_COMMON, DE_EPS_MS_CM_2 , NULL );
    /* 20   Mobile station classmark 3  Mobile station classmark 3 9.9.2.5  O   TLV 2-34 */
    ELEM_OPT_TLV( 0x20, NAS_PDU_TYPE_COMMON, DE_EPS_MS_CM_3 , NULL );
    /* 40   Supported Codecs    Supported Codec List 9.9.2.10   O   TLV 5-n */
    ELEM_OPT_TLV(0x40, GSM_A_PDU_TYPE_DTAP, DE_SUP_CODEC_LIST, " - Supported Codecs");
    /* F-   Additional update type  Additional update type 9.9.3.0B O   TV  1 */
    ELEM_OPT_TV_SHORT( 0xF0 , NAS_PDU_TYPE_EMM, DE_EMM_ADD_UPD_TYPE, NULL );
    /* 5D   Voice domain preference and UE's usage setting  Voice domain preference and UE's usage setting 9.9.3.44 O   TLV 3 */
    ELEM_OPT_TLV(0x5D, GSM_A_PDU_TYPE_GM, DE_VOICE_DOMAIN_PREF, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.2.30   Uplink NAS Transport
 */
static void
nas_emm_ul_nas_trans(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    pinfo->link_dir = P2P_DIR_UL;

    /* NAS message container    NAS message container 9.9.3.22  M   LV  3-252*/
    ELEM_MAND_LV(NAS_PDU_TYPE_EMM, DE_EMM_NAS_MSG_CONT, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.2.31   Downlink generic NAS transport
 */
static void
nas_emm_dl_gen_nas_trans(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    pinfo->link_dir = P2P_DIR_DL;

    /* Generic message container type Generic message container type 9.9.3.42 M V 1 */
    ELEM_MAND_V(NAS_PDU_TYPE_EMM, DE_EMM_GEN_MSG_CONT_TYPE, NULL);
    /* Generic message container Generic message container 9.9.3.43 M LV-E 3-n */
    ELEM_MAND_LV_E(NAS_PDU_TYPE_EMM, DE_EMM_GEN_MSG_CONT, NULL)
    /* 65 Additional information Additional information 9.9.2.0 O TLV 3-n */
    ELEM_OPT_TLV(0x65, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_ADD_INFO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);

    eps_nas_gen_msg_cont_type = 0;
}

/*
 * 8.2.32   Uplink generic NAS transport
 */
static void
nas_emm_ul_gen_nas_trans(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    pinfo->link_dir = P2P_DIR_UL;

    /* Generic message container type Generic message container type 9.9.3.42 M V 1 */
    ELEM_MAND_V(NAS_PDU_TYPE_EMM, DE_EMM_GEN_MSG_CONT_TYPE, NULL);
    /* Generic message container Generic message container 9.9.3.43 M LV-E 3-n */
    ELEM_MAND_LV_E(NAS_PDU_TYPE_EMM, DE_EMM_GEN_MSG_CONT, NULL)
    /* 65 Additional information Additional information 9.9.2.0 O TLV 3-n */
    ELEM_OPT_TLV(0x65, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_ADD_INFO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);

    eps_nas_gen_msg_cont_type = 0;
}

/*
 * 8.3  EPS session management messages
 */

/*
 * 8.3.1    Activate dedicated EPS bearer context accept
 */
static void
nas_esm_act_ded_eps_bearer_ctx_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    if(len==0)
        return;

    curr_offset = offset;
    curr_len = len;

    /* This message is sent by the UE to the network */
    pinfo->link_dir = P2P_DIR_UL;

    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253 */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.3.2    Activate dedicated EPS bearer context reject
 */
static void
nas_esm_act_ded_eps_bearer_ctx_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* This message is sent by UE to the network to reject activation of a dedicated EPS bearer context */
    pinfo->link_dir = P2P_DIR_UL;

    /* ESM cause    ESM cause 9.9.4.2   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_ESM, DE_ESM_CAUSE, NULL);
    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253 */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.3.3    Activate dedicated EPS bearer context request
 */
static void
nas_esm_act_ded_eps_bearer_ctx_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset, bit_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* This message is sent by the network to the UE to request activation of a dedicated EPS bearer context... */
    pinfo->link_dir = P2P_DIR_DL;


    /* Spare half octet Spare half octet 9.9.2.9    M   V   1/2 */
    bit_offset = curr_offset<<3;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_spare_half_octet, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset+=4;
    /* Linked EPS bearer identity   Linked EPS bearer identity 9.9.4.6  M   V   1/2 */
    proto_tree_add_bits_item(tree, hf_nas_eps_esm_linked_bearer_id, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset+=4;
    /* Fix the lengths */
    curr_len--;
    curr_offset++;

    /* EPS QoS  EPS quality of service 9.9.4.3  M   LV  2-10 */
    ELEM_MAND_LV(NAS_PDU_TYPE_ESM, DE_ESM_EPS_QOS, NULL);
    /* TFT  Traffic flow template 9.9.4.16  M   LV  2-256 */
    ELEM_MAND_LV( GSM_A_PDU_TYPE_GM, DE_TRAFFIC_FLOW_TEMPLATE , NULL );
    /* 5D   Transaction identifier  Transaction identifier 9.9.4.17 O   TLV 3-4 */
    ELEM_OPT_TLV( 0x5d , GSM_A_PDU_TYPE_GM, DE_LINKED_TI , " - Transaction identifier" );
    /* 30   Negotiated QoS  Quality of service 9.9.4.12 O   TLV 14-18 */
    ELEM_OPT_TLV( 0x30 , GSM_A_PDU_TYPE_GM, DE_QOS , " - Negotiated QoS" );
    /* 32   Negotiated LLC SAPI LLC service access point identifier 9.9.4.7 O   TV  2 */
    ELEM_OPT_TV( 0x32 , GSM_A_PDU_TYPE_GM, DE_LLC_SAPI , " - Negotiated LLC SAPI" );
    /* 8-   Radio priority  Radio priority 9.9.4.13 O   TV  1 */
    ELEM_OPT_TV_SHORT ( 0x80 , GSM_A_PDU_TYPE_GM , DE_RAD_PRIO , NULL );
    /* 34   Packet flow Identifier  Packet flow Identifier 9.9.4.8  O   TLV 3 */
    ELEM_OPT_TLV( 0x34 , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL );
    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253 */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.3.4    Activate default EPS bearer context accept
 */
static void
nas_esm_act_def_eps_bearer_ctx_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    if(len==0)
        return;

    /* This message is sent by the UE to the network to acknowledge activation of a default EPS bearer context */
    pinfo->link_dir = P2P_DIR_UL;

    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253  */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.3.5    Activate default EPS bearer context reject
 */
static void
nas_esm_act_def_eps_bearer_ctx_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* This message is sent by UE to the network to reject activation of a default EPS bearer context. */
    pinfo->link_dir = P2P_DIR_UL;

    /*  ESM cause   ESM cause 9.9.4.4   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_ESM, DE_ESM_CAUSE, NULL);
    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253 */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.3.6 Activate default EPS bearer context request
 */
static void
nas_esm_act_def_eps_bearer_ctx_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* This message is sent by the network to the UE to request activation of a default EPS bearer context. */
    pinfo->link_dir = P2P_DIR_DL;

    /*  EPS QoS EPS quality of service 9.9.4.3  M   LV  2-10 */
    ELEM_MAND_LV(NAS_PDU_TYPE_ESM, DE_ESM_EPS_QOS, NULL);
    /*  Access point name   Access point name 9.9.4.1   M   LV  2-101 */
    ELEM_MAND_LV( GSM_A_PDU_TYPE_GM, DE_ACC_POINT_NAME , NULL );
    /*  PDN address PDN address 9.9.4.9 M   LV  6-14 DE_ESM_PDN_ADDR*/
    ELEM_MAND_LV( NAS_PDU_TYPE_ESM, DE_ESM_PDN_ADDR , NULL );
    /* 5D   Transaction identifier  Transaction identifier 9.9.4.17 O   TLV 3-4 */
    ELEM_OPT_TLV( 0x5d , GSM_A_PDU_TYPE_GM, DE_LINKED_TI , " - Transaction identifier" );
    /* 30   Negotiated QoS  Quality of service 9.9.4.12 O   TLV 14-18 */
    ELEM_OPT_TLV( 0x30 , GSM_A_PDU_TYPE_GM, DE_QOS , " - Negotiated QoS" );
    /* 32   Negotiated LLC SAPI LLC service access point identifier 9.9.4.7 O   TV  2 */
    ELEM_OPT_TV( 0x32 , GSM_A_PDU_TYPE_GM, DE_LLC_SAPI , " - Negotiated LLC SAPI" );
    /* 8-   Radio priority  Radio priority 9.9.4.13 O   TV  1 */
    ELEM_OPT_TV_SHORT ( 0x80 , GSM_A_PDU_TYPE_GM , DE_RAD_PRIO , NULL );
    /* 34   Packet flow Identifier  Packet flow Identifier 9.9.4.8  O   TLV 3 */
    ELEM_OPT_TLV( 0x34 , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL );
    /* 5E   APN-AMBR    APN aggregate maximum bit rate 9.9.4.2  O   TLV 4-8 DE_ESM_APN_AGR_MAX_BR*/
    ELEM_OPT_TLV( 0x5e , NAS_PDU_TYPE_ESM, DE_ESM_APN_AGR_MAX_BR , NULL );
    /* 58   ESM cause   ESM cause 9.9.4.4   O   TV  2 */
    ELEM_OPT_TV( 0x58 , NAS_PDU_TYPE_ESM, DE_ESM_CAUSE , NULL );
    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253 */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.3.7    Bearer resource allocation reject
 */
static void
nas_esm_bearer_res_all_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* This message is sent by the network to the UE to reject the allocation of a dedicated bearer resource. */
    pinfo->link_dir = P2P_DIR_DL;

    /*  ESM cause   ESM cause 9.9.4.4   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_ESM, DE_ESM_CAUSE, NULL);
    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253 */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.3.8    Bearer resource allocation request
 */
static void
nas_esm_bearer_res_all_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset, bit_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* This message is sent by the UE to the network to request the allocation of a dedicated bearer resource. */
    pinfo->link_dir = P2P_DIR_UL;

    /*  Spare half octet    Spare half octet 9.9.2.9    M   V   1/2 */
    bit_offset = curr_offset<<3;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_spare_half_octet, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset+=4;
    /*  Linked EPS bearer identity  Linked EPS bearer identity 9.9.4.6  M   V   1/2 */
    proto_tree_add_bits_item(tree, hf_nas_eps_esm_linked_bearer_id, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset+=4;
    /* Fix the lengths */
    curr_len--;
    curr_offset++;

    /*  Traffic flow aggregate  Traffic flow aggregate description 9.9.4.15 M   LV  2-256 */
    ELEM_MAND_LV( GSM_A_PDU_TYPE_GM, DE_TRAFFIC_FLOW_TEMPLATE , " - Traffic flow aggregate" );
    /*  Required traffic flow QoS   EPS quality of service 9.9.4.3  M   LV  2-10 */
    ELEM_MAND_LV(NAS_PDU_TYPE_ESM, DE_ESM_EPS_QOS, " - Required traffic flow QoS");
    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253 */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.3.9    Bearer resource modification reject
 */
static void
nas_esm_bearer_res_mod_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* This message is sent by the network to the UE to reject the modification of a dedicated bearer resource. */
    pinfo->link_dir = P2P_DIR_DL;

    /*  ESM cause   ESM cause 9.9.4.4   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_ESM, DE_ESM_CAUSE, NULL);
    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253 */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.3.10   Bearer resource modification request
 */
static void
nas_esm_bearer_res_mod_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset, bit_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* This message is sent by the UE to the network to request the modification of a dedicated bearer resource. */
    pinfo->link_dir = P2P_DIR_UL;

    /*  Spare half octet    Spare half octet 9.9.2.9    M   V   1/2 */
    bit_offset = curr_offset<<3;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_spare_half_octet, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset+=4;
    /* EPS bearer identity for packet filter    Linked EPS bearer identity 9.9.4.6  M   V   1/2 */
    proto_tree_add_bits_item(tree, hf_nas_eps_esm_linked_bearer_id, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset+=4;
    /* Fix the lengths */
    curr_len--;
    curr_offset++;
    /* Traffic flow aggregate   Traffic flow aggregate description 9.9.4.15 M   LV  2-256 */
    ELEM_MAND_LV( GSM_A_PDU_TYPE_GM, DE_TRAFFIC_FLOW_TEMPLATE , " - Traffic flow aggregate" );
    /* 5B   Required traffic flow QoS   EPS quality of service 9.9.4.3  O   TLV 3-11 */
    ELEM_OPT_TLV( 0x5B , NAS_PDU_TYPE_ESM, DE_ESM_EPS_QOS , " - Required traffic flow QoS" );
    /* 58   ESM cause   ESM cause 9.9.4.4   O   TV  2 */
    ELEM_OPT_TV( 0x58 , NAS_PDU_TYPE_ESM, DE_ESM_CAUSE , NULL );
    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253  */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.3.11 Deactivate EPS bearer context accept
 */
static void
nas_esm_deact_eps_bearer_ctx_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    if(len==0)
        return;

    /* This message is sent by the UE to acknowledge deactivation of the EPS bearer context... */
    pinfo->link_dir = P2P_DIR_UL;

    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.3.12 Deactivate EPS bearer context request
 */
static void
nas_esm_deact_eps_bearer_ctx_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* This message is sent by the network to request deactivation of an active EPS bearer context. */
    pinfo->link_dir = P2P_DIR_DL;

    /*  ESM cause   ESM cause 9.9.4.4   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_ESM, DE_ESM_CAUSE, NULL);
    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.3.13 ESM information request
 * No IE:s
 */
static void
nas_esm_inf_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.3.14 ESM information response
 */
static void
nas_esm_inf_resp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    if(len==0)
        return;

    /* This message is sent by the UE to the network in response to an ESM INFORMATION REQUEST... */
    pinfo->link_dir = P2P_DIR_UL;

    /* 28   Access point name   Access point name 9.9.4.1   O   TLV 3-102 */
    ELEM_OPT_TLV( 0x28 , GSM_A_PDU_TYPE_GM, DE_ACC_POINT_NAME , NULL );
    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253 */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.3.15 ESM status
 */
static void
nas_esm_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* ESM cause    ESM cause 9.9.4.4   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_ESM, DE_ESM_CAUSE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.3.16 Modify EPS bearer context accept
 */
static void
nas_esm_mod_eps_bearer_ctx_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    if(len==0)
        return;

    /* This message is sent by the UE to the network to acknowledge the modification of an active EPS bearer context. */
    pinfo->link_dir = P2P_DIR_UL;

    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253 */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.3.17 Modify EPS bearer context reject
 */
static void
nas_esm_mod_eps_bearer_ctx_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* This message is sent by the UE or the network to reject a modification of an active EPS bearer context. */
    pinfo->link_dir = P2P_DIR_UL;

    /* ESM cause    ESM cause 9.9.4.4   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_ESM, DE_ESM_CAUSE, NULL);
    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253 */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.3.18 Modify EPS bearer context request
 */
static void
nas_esm_mod_eps_bearer_ctx_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    if(len==0)
        return;

    /*This message is sent by the network to inform the UE about events which are relevant for the upper layer... */
    pinfo->link_dir = P2P_DIR_DL;

    /* 5B   New EPS QoS EPS quality of service 9.9.4.3  O   TLV 3-11 */
    ELEM_OPT_TLV( 0x5B , NAS_PDU_TYPE_ESM, DE_ESM_EPS_QOS , " - New EPS QoS" );
    /* 36   TFT Traffic flow template 9.9.4.16  O   TLV 3-257 */
    ELEM_OPT_TLV( 0x36 , GSM_A_PDU_TYPE_GM, DE_TRAFFIC_FLOW_TEMPLATE , NULL );
    /* 30   New QoS Quality of service 9.9.4.12 O   TLV 14-18 */
    ELEM_OPT_TLV( 0x30 , GSM_A_PDU_TYPE_GM, DE_QOS , " - New QoS" );
    /* 32   Negotiated LLC SAPI LLC service access point identifier 9.9.4.7 O   TV  2 */
    ELEM_OPT_TV( 0x32 , GSM_A_PDU_TYPE_GM, DE_LLC_SAPI , " - Negotiated LLC SAPI" );
    /* 8-   Radio priority  Radio priority 9.9.4.13 O   TV  1 */
    ELEM_OPT_TV_SHORT ( 0x80 , GSM_A_PDU_TYPE_GM , DE_RAD_PRIO , NULL );
    /* 34   Packet flow Identifier  Packet flow Identifier 9.9.4.8  O   TLV 3 */
    ELEM_OPT_TLV( 0x34 , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL );
    /* 5E   APN-AMBR    APN aggregate maximum bit rate 9.9.4.2  O   TLV 4-8 */
    ELEM_OPT_TLV( 0x5E , NAS_PDU_TYPE_ESM, DE_ESM_APN_AGR_MAX_BR , NULL );
    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253 */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.3.18A Notification
 */
static void
nas_esm_notification(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Notification indicator Notification indicator 9.9.4.7A M LV 2 */
    ELEM_MAND_LV(NAS_PDU_TYPE_ESM, DE_ESM_NOTIF_IND, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.3.19 PDN connectivity reject
 */
static void
nas_esm_pdn_con_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*This message is sent by the network to the UE to reject establishment of a PDN connection. */
    pinfo->link_dir = P2P_DIR_DL;

    /* ESM cause    ESM cause 9.9.4.4   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_ESM, DE_ESM_CAUSE, NULL);
    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253 */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.3.20 PDN connectivity request
 */
static void
nas_esm_pdn_con_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;
	int     bit_offset;

    curr_offset = offset;
    curr_len = len;

    /*This message is sent by the UE to the network to initiate establishment of a PDN connection. */
    pinfo->link_dir = P2P_DIR_UL;

    /* PDN type PDN type 9.9.4.10 M V 1/2 */
    bit_offset = curr_offset<<3;
    proto_tree_add_bits_item(tree, hf_nas_eps_esm_pdn_type, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset+=4;

    /* Request type 9.9.4.14 M V 1/2 */
    proto_tree_add_bits_item(tree, hf_nas_eps_esm_request_type, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset+=4;
    /* Fix the lengths */
    curr_len--;
    curr_offset++;
    if (curr_len == 0)
        return;

    /* D- ESM information transfer flag 9.9.4.5 O TV 1 */
    ELEM_OPT_TV_SHORT( 0xd0 , NAS_PDU_TYPE_ESM, DE_ESM_INF_TRF_FLG , NULL );
    /* 28 Access point name 9.9.4.1 O TLV 3-102 */
    ELEM_OPT_TLV( 0x28 , GSM_A_PDU_TYPE_GM, DE_ACC_POINT_NAME , NULL );
    /* 27 Protocol configuration options 9.9.4.11 O TLV 3-253 */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.3.20 PDN disconnect reject
 */
static void
nas_esm_pdn_disc_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*This message is sent by the UE to the network to initiate establishment of a PDN connection. */
    pinfo->link_dir = P2P_DIR_UL;

    /* ESM cause    ESM cause 9.9.4.4   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_ESM, DE_ESM_CAUSE, NULL);
    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253 */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.3.21 PDN disconnect request
 */
static void
nas_esm_pdn_disc_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset, bit_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* This message is sent by the network to the UE to reject release of a PDN connection. */
    pinfo->link_dir = P2P_DIR_DL;

    /*  Spare half octet    Spare half octet 9.9.2.9    M   V   1/2 */
    bit_offset = curr_offset<<3;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_spare_half_octet, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset+=4;
    /* Linked EPS bearer identity   Linked EPS bearer identity 9.9.4.6  M   V   1/2 */
    proto_tree_add_bits_item(tree, hf_nas_eps_esm_linked_bearer_id, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset+=4;
    /* Fix the lengths */
    curr_len--;
    curr_offset++;
    if (curr_len == 0)
        return;
    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253 */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}


#define NUM_NAS_MSG_ESM (sizeof(nas_msg_esm_strings)/sizeof(value_string))
static gint ett_nas_msg_esm[NUM_NAS_MSG_ESM];
static void (*nas_msg_esm_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len) = {
    nas_esm_act_def_eps_bearer_ctx_req, /* Activate default EPS bearer context request*/
    nas_esm_act_def_eps_bearer_ctx_acc, /* Activate default EPS bearer context accept*/
    nas_esm_act_def_eps_bearer_ctx_rej, /* Activate default EPS bearer context reject*/
    nas_esm_act_ded_eps_bearer_ctx_req, /* Activate dedicated EPS bearer context request*/
    nas_esm_act_ded_eps_bearer_ctx_acc, /* Activate dedicated EPS bearer context accept*/
    nas_esm_act_ded_eps_bearer_ctx_rej, /* Activate dedicated EPS bearer context reject*/
    nas_esm_mod_eps_bearer_ctx_req,     /* Modify EPS bearer context request*/
    nas_esm_mod_eps_bearer_ctx_acc,     /* Modify EPS bearer context accept*/
    nas_esm_mod_eps_bearer_ctx_rej,     /* Modify EPS bearer context reject*/
    nas_esm_deact_eps_bearer_ctx_req,   /* Deactivate EPS bearer context request*/
    nas_esm_deact_eps_bearer_ctx_acc,   /* Deactivate EPS bearer context accept*/
    nas_esm_pdn_con_req,                /* 8.3.18 PDN connectivity request */
    nas_esm_pdn_con_rej,                /* PDN connectivity reject*/
    nas_esm_pdn_disc_req,               /* PDN disconnect request*/
    nas_esm_pdn_disc_rej,               /* PDN disconnect reject*/
    nas_esm_bearer_res_all_req,         /* Bearer resource allocation request*/
    nas_esm_bearer_res_all_rej,         /* Bearer resource allocation reject*/
    nas_esm_bearer_res_mod_req,         /* Bearer resource modification request*/
    nas_esm_bearer_res_mod_rej,         /* Bearer resource modification reject*/
    nas_esm_inf_req,                    /* ESM information request, No IE:s*/
    nas_esm_inf_resp,                   /* ESM information response*/
    nas_esm_notification,               /* Notification */
    nas_esm_status,                     /* ESM status */

    NULL,   /* NONE */
};

static void
get_nas_esm_msg_params(guint8 oct, const gchar **msg_str, int *ett_tree, int *hf_idx, msg_fcn *msg_fcn_p)
{
    gint            idx;

    *msg_str = match_strval_idx((guint32) (oct & 0xff), nas_msg_esm_strings, &idx);
    *ett_tree = ett_nas_msg_esm[idx];
    *hf_idx = hf_nas_eps_msg_esm_type;
    *msg_fcn_p = nas_msg_esm_fcn[idx];

    return;
}



#define NUM_NAS_MSG_EMM (sizeof(nas_msg_emm_strings)/sizeof(value_string))
static gint ett_nas_msg_emm[NUM_NAS_MSG_EMM];
static void (*nas_msg_emm_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len) = {
    nas_emm_attach_req,         /* Attach request */
    nas_emm_attach_acc,         /* Attach accept */
    nas_emm_attach_comp,        /* Attach complete */
    nas_emm_attach_rej,         /* Attach reject */
    nas_emm_detach_req,         /* Detach request */
    NULL,                       /* 8.2.10   Detach accept */

    nas_emm_trac_area_upd_req,  /* Tracking area update request */
    nas_emm_trac_area_upd_acc,  /* Tracking area update accept */
    NULL,                       /* Tracking area update complete (No IE's)*/
    nas_emm_trac_area_upd_rej,  /* Tracking area update reject */

    nas_emm_ext_serv_req,       /* Extended service request */
    nas_emm_serv_rej,           /* Service reject */

    nas_emm_guti_realloc_cmd,   /* GUTI reallocation command */
    NULL,                       /* GUTI reallocation complete (No IE's) */
    nas_emm_auth_req,           /* Authentication request */
    nas_emm_auth_resp,          /* Authentication response */
    NULL,                       /* Authentication reject (No IE:s)*/
    nas_emm_attach_fail,        /* Authentication failure */
    nas_emm_id_req,             /* Identity request */
    nas_emm_id_res,             /* Identity response */
    nas_emm_sec_mode_cmd,       /* Security mode command */
    nas_emm_sec_mode_comp,      /* Security mode complete */
    nas_emm_sec_mode_rej,       /* Security mode reject */

    nas_emm_emm_status,         /* EMM status */
    nas_emm_emm_inf,            /* EMM information */
    nas_emm_dl_nas_trans,       /* Downlink NAS transport */
    nas_emm_ul_nas_trans,       /* Uplink NAS transport */
    nas_emm_cs_serv_not,        /* 8.2.9    CS service notification */
    nas_emm_dl_gen_nas_trans,   /* Downlink generic NAS transport */
    nas_emm_ul_gen_nas_trans,   /* Uplink generic NAS transport */
    NULL,   /* NONE */

};

static void
get_nas_emm_msg_params(guint8 oct, const gchar **msg_str, int *ett_tree, int *hf_idx, msg_fcn *msg_fcn_p)
{
    gint            idx;

    *msg_str = match_strval_idx((guint32) (oct & 0xff), nas_msg_emm_strings, &idx);
    *ett_tree = ett_nas_msg_emm[idx];
    *hf_idx = hf_nas_eps_msg_emm_type;
    *msg_fcn_p = nas_msg_emm_fcn[idx];

    return;
}

/*
 * EPS session management messages.
 * A plain NAS message is pased to this function
 */
static void
disect_nas_eps_esm_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    const gchar     *msg_str;
    guint32         len;
    gint            ett_tree;
    int             hf_idx;
    void            (*msg_fcn_p)(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len);
    guint8          oct;

    len = tvb_length(tvb);
    /*
     * EPS bearer identity 9.3.2
     */
    proto_tree_add_item(tree, hf_nas_eps_bearer_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* Protocol discriminator 9.2 */
    proto_tree_add_item(tree, hf_gsm_a_L3_protocol_discriminator, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Procedure transaction identity 9.4
     * The procedure transaction identity and its use are defined in 3GPP TS 24.007
     */
    proto_tree_add_item(tree, hf_nas_eps_esm_proc_trans_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /*messge type IE*/
    oct = tvb_get_guint8(tvb,offset);
    msg_fcn_p = NULL;
    ett_tree = -1;
    hf_idx = -1;
    msg_str = NULL;

    get_nas_esm_msg_params(oct, &msg_str, &ett_tree, &hf_idx, &msg_fcn_p);

    if(msg_str){
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, msg_str);
    }else{
        proto_tree_add_text(tree, tvb, offset, 1,"Unknown message 0x%x",oct);
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
        proto_tree_add_text(tree, tvb, offset, len - offset,
            "Message Elements");
    }
    else
    {
        (*msg_fcn_p)(tvb, tree, pinfo, offset, len - offset);
    }

}
/*
 * The "real" security header has been dissected or if dissect_header = TRUE
 */
static void
dissect_nas_eps_emm_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, gboolean second_header)
{
    const gchar     *msg_str;
    guint32         len;
    gint            ett_tree;
    int             hf_idx;
    void            (*msg_fcn_p)(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len);
    guint8          security_header_type, oct;

    len = tvb_length(tvb);

    /* 9.3.1    Security header type */
    if(second_header){
        security_header_type = tvb_get_guint8(tvb,offset)>>4;
        proto_tree_add_item(tree, hf_nas_eps_security_header_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_gsm_a_L3_protocol_discriminator, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        if (security_header_type !=0){
            /* Message authentication code */
            proto_tree_add_item(tree, hf_nas_eps_msg_auth_code, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            /* Sequence number */
            proto_tree_add_item(tree, hf_nas_eps_seq_no, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            if ((security_header_type==2)||(security_header_type==4))
                /* Integrity protected and ciphered = 2, Integrity protected and ciphered with new EPS security context = 4 */
                return;
            proto_tree_add_item(tree, hf_nas_eps_security_header_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_gsm_a_L3_protocol_discriminator, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
        }
    }
    /* Messge type IE*/
    oct = tvb_get_guint8(tvb,offset);
    msg_fcn_p = NULL;
    ett_tree = -1;
    hf_idx = -1;
    msg_str = NULL;

    get_nas_emm_msg_params(oct, &msg_str, &ett_tree, &hf_idx, &msg_fcn_p);

    if(msg_str){
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, msg_str);
    }else{
        proto_tree_add_text(tree, tvb, offset, 1,"Unknown message 0x%x",oct);
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
        proto_tree_add_text(tree, tvb, offset, len - offset,
            "Message Elements");
    }
    else
    {
        (*msg_fcn_p)(tvb, tree, pinfo, offset, len - offset);
    }

}
/* TS 24.301 8.2.1
 * 9    General message format and information elements coding
 * 9.1  Overview
 * Within the protocols defined in the present document, every message, except the SERVICE REQUEST message,
 * is a standard L3 message as defined in 3GPP TS 24.007 [12]. This means that the message consists of the following parts:
 * 1)   if the message is a plain NAS message:
 *  a)  protocol discriminator;
 *  b)  EPS bearer identity or security header type;
 *  c)  procedure transaction identity;
 *  d)  message type;
 *  e)  other information elements, as required.
 * 2)   if the message is a security protected NAS message:
 *  a)  protocol discriminator;
 *  b)  security header type;
 *  c)  message authentication code;
 *  d)  sequence number;
 *  e)  plain NAS message, as defined in item 1.
 *
 * The EPS bearer identity and the procedure transaction identity are only used in messages
 * with protocol discriminator EPS session management. Octet 1a with the procedure transaction
 * identity shall only be included in these messages.
 */

/*
 * All messages recived here will have the security header:
 *  Figure 9.1.2: General message organization example for a security protected NAS message
 *      9.3.1 Bits 5 to 8 of the first octet of every EPS Mobility Management (EMM)
 *            message contain the Security header type IE.
 *      4.4.4.2 All ESM messages are integrity protected.
 */

static void
dissect_nas_eps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *item;
    proto_tree  *nas_eps_tree;
    guint8      pd, security_header_type;
    int     offset = 0;
    guint32     len;
    guint32     msg_auth_code;

    /* Save pinfo */
    gpinfo = pinfo;
    len = tvb_length(tvb);

    /* make entry in the Protocol column on summary display */
    col_append_str(pinfo->cinfo, COL_PROTOCOL, "/NAS-EPS");

    item = proto_tree_add_item(tree, proto_nas_eps, tvb, 0, -1, ENC_NA);
    nas_eps_tree = proto_item_add_subtree(item, ett_nas_eps);

    /* Security header type Security header type 9.3.1 M V 1/2 */
    security_header_type = tvb_get_guint8(tvb,offset)>>4;
    proto_tree_add_item(nas_eps_tree, hf_nas_eps_security_header_type, tvb, 0, 1, ENC_BIG_ENDIAN);
    /* Protocol discriminator Protocol discriminator 9.2 M V 1/2 */
    proto_tree_add_item(nas_eps_tree, hf_gsm_a_L3_protocol_discriminator, tvb, 0, 1, ENC_BIG_ENDIAN);
    pd = tvb_get_guint8(tvb,offset)&0x0f;
    offset++;
    /* Message authentication code  Message authentication code 9.5 M   V   4 */
    if (security_header_type == 0){
        if(pd==7){
            /* Plain EPS mobility management messages. */
            dissect_nas_eps_emm_msg(tvb, pinfo, nas_eps_tree, offset, ENC_BIG_ENDIAN);
            return;
        }else{
            proto_tree_add_text(tree, tvb, offset, len, "All ESM messages should be integrity protected");
            return;
        }
    }else{
        /* SERVICE REQUEST (12)  is not a plain NAS message treat separately */
        if (security_header_type == 12){
            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "SERVICE REQUEST");
            nas_emm_service_req(tvb, nas_eps_tree, pinfo, offset, len-offset);
            return;
        }
        /* Message authentication code */
        proto_tree_add_item(nas_eps_tree, hf_nas_eps_msg_auth_code, tvb, offset, 4, ENC_BIG_ENDIAN);
        msg_auth_code = tvb_get_ntohl(tvb, offset);
        offset+=4;
        if ((security_header_type==2)||(security_header_type==4)){
            /* Possible ciphered message */
            if(msg_auth_code!=0){
                /* Sequence number  Sequence number 9.6 M   V   1 */
                proto_tree_add_item(nas_eps_tree, hf_nas_eps_seq_no, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
                /* Integrity protected and ciphered = 2, Integrity protected and ciphered with new EPS security context = 4 */
				/* Read security_header_type AND pd */
                pd = tvb_get_guint8(tvb,offset);
                /* If pd is in plaintext this message probably isn't ciphered */
                if((pd!=7)&&(pd!=2)&&(pd!=15)){
                    proto_tree_add_text(nas_eps_tree, tvb, offset, len-6,"Ciphered message");
                    return;
                }
            }else{
                /* msg_auth_code == 0, probably not ciphered */
                /* Sequence number  Sequence number 9.6 M   V   1 */
                proto_tree_add_item(nas_eps_tree, hf_nas_eps_seq_no, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
            }
        }else{
            /* Sequence number  Sequence number 9.6 M   V   1 */
            proto_tree_add_item(nas_eps_tree, hf_nas_eps_seq_no, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
        }
    }
    /* NAS message  NAS message 9.7 M   V   1-n  */

    pd = tvb_get_guint8(tvb,offset)&0x0f;
    switch (pd){
        case 2:
            /* EPS session management messages.
             * Ref 3GPP TS 24.007 version 8.0.0 Release 8, Table 11.2: Protocol discriminator values
             */
            disect_nas_eps_esm_msg(tvb, pinfo, nas_eps_tree, offset);
            break;
        case 7:
            /* EPS mobility management messages.
             * Ref 3GPP TS 24.007 version 8.0.0 Release 8, Table 11.2: Protocol discriminator values
             */
            dissect_nas_eps_emm_msg(tvb, pinfo, nas_eps_tree, offset, TRUE);
            break;
        case 15:
            /* Special conformance testing functions for User Equipment messages.
             * Ref 3GPP TS 24.007 version 8.0.0 Release 8, Table 11.2: Protocol discriminator values
             */
            if (gsm_a_dtap_handle){
                tvbuff_t *new_tvb = tvb_new_subset(tvb, offset, -1, -1);
                call_dissector(gsm_a_dtap_handle, new_tvb, pinfo, nas_eps_tree);
                break;
            } /* else fall through default */
        default:
            proto_tree_add_text(nas_eps_tree, tvb, offset, -1, "Not a NAS EPS PD %u(%s)",pd,val_to_str(pd, protocol_discriminator_vals,"unknown"));
            break;
    }

}

static void
dissect_nas_eps_plain(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *item;
    proto_tree  *nas_eps_tree;
    guint8      pd;
    int     offset = 0;

    /* Save pinfo */
    gpinfo = pinfo;

    /* make entry in the Protocol column on summary display */
    col_append_str(pinfo->cinfo, COL_PROTOCOL, "/NAS-EPS");

    item = proto_tree_add_item(tree, proto_nas_eps, tvb, 0, -1, ENC_NA);
    nas_eps_tree = proto_item_add_subtree(item, ett_nas_eps);

    pd = tvb_get_guint8(tvb,offset)&0x0f;
    switch (pd){
        case 2:
            /* EPS session management messages.
             * Ref 3GPP TS 24.007 version 8.0.0 Release 8, Table 11.2: Protocol discriminator values
             */
            disect_nas_eps_esm_msg(tvb, pinfo, nas_eps_tree, offset);
            break;
        case 7:
            /* EPS mobility management messages.
             * Ref 3GPP TS 24.007 version 8.0.0 Release 8, Table 11.2: Protocol discriminator values
             */
            dissect_nas_eps_emm_msg(tvb, pinfo, nas_eps_tree, offset, TRUE);
            break;
        case 15:
            /* Special conformance testing functions for User Equipment messages.
             * Ref 3GPP TS 24.007 version 8.0.0 Release 8, Table 11.2: Protocol discriminator values
             */
            if (gsm_a_dtap_handle){
                tvbuff_t *new_tvb = tvb_new_subset(tvb, offset, -1, -1);
                call_dissector(gsm_a_dtap_handle, new_tvb,pinfo, nas_eps_tree);
                break;
            } /* else fall through default */
        default:
            proto_tree_add_text(nas_eps_tree, tvb, offset, -1, "Not a NAS EPS PD %u(%s)",pd,val_to_str(pd, protocol_discriminator_vals,"unknown"));
            break;
    }

}

void proto_register_nas_eps(void) {
    guint       i;
    guint       last_offset;

    /* List of fields */

  static hf_register_info hf[] = {
    { &hf_nas_eps_msg_emm_type,
        { "NAS EPS Mobility Management Message Type",   "nas_eps.nas_msg_emm_type",
        FT_UINT8, BASE_HEX, VALS(nas_msg_emm_strings), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_common_elem_id,
        { "Element ID", "nas_eps.common.elem_id",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_elem_id,
        { "Element ID", "nas_eps.emm.elem_id",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_nas_eps_bearer_id,
        { "EPS bearer identity",    "nas_eps.bearer_id",
        FT_UINT8, BASE_HEX, NULL, 0xf0,
        NULL, HFILL }
    },
    { &hf_nas_eps_spare_bits,
        { "Spare bit(s)", "nas_eps.spare_bits",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_security_header_type,
        { "Security header type","nas_eps.security_header_type",
        FT_UINT8,BASE_DEC|BASE_EXT_STRING, &security_header_type_vals_ext, 0xf0,
        NULL, HFILL }
    },
    { &hf_nas_eps_msg_auth_code,
        { "Message authentication code","nas_eps.msg_auth_code",
        FT_UINT32,BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_seq_no,
        { "Sequence number","nas_eps.seq_no",
        FT_UINT8,BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_seq_no_short,
        { "Sequence number (short)","nas_eps.seq_no_short",
        FT_UINT8,BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_ebi0,
        { "EBI(0) spare","nas_eps.emm.ebi0",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_ebi1,
        { "EBI(1) spare","nas_eps.emm.ebi1",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_ebi2,
        { "EBI(2) spare","nas_eps.emm.ebi2",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_ebi3,
        { "EBI(3) spare","nas_eps.emm.ebi3",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_ebi4,
        { "EBI(4) spare","nas_eps.emm.ebi4",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_ebi5,
        { "EBI(5)","nas_eps.emm.ebi5",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_ebi_vals), 0x20,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_ebi6,
        { "EBI(6)","nas_eps.emm.ebi6",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_ebi_vals), 0x40,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_ebi7,
        { "EBI(7)","nas_eps.emm.ebi7",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_ebi_vals), 0x80,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_ebi8,
        { "EBI(8)","nas_eps.emm.ebi8",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_ebi_vals), 0x01,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_ebi9,
        { "EBI(9)","nas_eps.emm.ebi9",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_ebi_vals), 0x02,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_ebi10,
        { "EBI(10)","nas_eps.emm.ebi10",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_ebi_vals), 0x04,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_ebi11,
        { "EBI(11)","nas_eps.emm.ebi11",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_ebi_vals), 0x08,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_ebi12,
        { "EBI(12)","nas_eps.emm.ebi12",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_ebi_vals), 0x10,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_ebi13,
        { "EBI(13)","nas_eps.emm.ebi13",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_ebi_vals), 0x20,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_ebi14,
        { "EBI(14)","nas_eps.emm.ebi14",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_ebi_vals), 0x40,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_ebi15,
        { "EBI(15)","nas_eps.emm.ebi15",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_ebi_vals), 0x80,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_dl_nas_cnt,
        { "DL NAS COUNT value","nas_eps.emm.dl_nas_cnt",
        FT_UINT8,BASE_DEC, NULL, 0x0f,
        NULL, HFILL }
    },
    {&hf_nas_eps_emm_nonce_mme,
        { "NonceMME","nas_eps.emm.nonce_mme",
        FT_UINT32,BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    {&hf_nas_eps_emm_nonce,
        { "Nonce","nas_eps.emm.nonce",
        FT_UINT32,BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_paging_id,
        { "Paging identity value","nas_eps.emm.paging_id",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_paging_id_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_eps_att_type,
        { "EPS attach type","nas_eps.emm.eps_att_type",
        FT_UINT8,BASE_DEC, VALS(nas_eps_emm_eps_att_type_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_cs_lcs_type,
        { "CS-LCS","nas_eps.emm.cs_lcs",
        FT_UINT8, BASE_DEC, VALS(nas_eps_emm_cs_lcs_vals), 0x0,
        "Location services indicator in CS", HFILL }
    },
    { &hf_nas_eps_emm_epc_lcs_type,
        { "EPC-LCS","nas_eps.emm.epc_lcs",
        FT_BOOLEAN ,BASE_NONE, TFS(&nas_eps_emm_epc_lcs_value), 0x0,
        "Location services indicator in EPC", HFILL }
    },
    { &hf_nas_eps_emm_emc_bs_type,
        { "EMC BS","nas_eps.emm.emc_bs",
        FT_BOOLEAN, BASE_NONE, TFS(&nas_eps_emm_emc_bs_value), 0x0,
        "Emergency bearer services indicator", HFILL }
    },
    { &hf_nas_eps_emm_ims_vops_type,
        { "IMS VoPS","nas_eps.emm.ims_vops",
        FT_BOOLEAN, BASE_NONE, TFS(&nas_eps_emm_ims_vops_value), 0x0,
        "IMS voice over PS session indicator", HFILL }
    },
    { &hf_nas_eps_tsc,
        { "Type of security context flag (TSC)","nas_eps.emm.tsc",
        FT_UINT8,BASE_DEC, VALS(nas_eps_tsc_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_nas_key_set_id,
        { "NAS key set identifier","nas_eps.emm.nas_key_set_id",
        FT_UINT8,BASE_DEC, VALS(nas_eps_emm_NAS_key_set_identifier_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_odd_even,
        { "odd/even indic","nas_eps.emm.odd_even",
        FT_UINT8,BASE_DEC, NULL, 0x8,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_type_of_id,
        { "Type of identity","nas_eps.emm.type_of_id",
        FT_UINT8,BASE_DEC, VALS(nas_eps_emm_type_of_id_vals), 0x07,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_mme_grp_id,
        { "MME Group ID","nas_eps.emm.mme_grp_id",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_imsi,
        { "IMSI", "nas_eps.emm.imsi",
          FT_STRING, BASE_NONE, NULL, 0,
          NULL, HFILL }
    },
    { &hf_nas_eps_emm_imei,
        { "IMEI", "nas_eps.emm.imei",
          FT_STRING, BASE_NONE, NULL, 0,
          NULL, HFILL }
    },
    { &hf_nas_eps_emm_mme_code,
        { "MME Code","nas_eps.emm.mme_code",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_m_tmsi,
        { "M-TMSI","nas_eps.emm.m_tmsi",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_msg_cont,
        { "ESM message container contents","nas_eps.emm.esm_msg_cont",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_imeisv_req,
        { "IMEISV request","nas_eps.emm.imeisv_req",
        FT_UINT8, BASE_DEC, VALS(nas_eps_emm_imeisv_req_vals), 0x07,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_toi,
        { "Type of integrity protection algorithm","nas_eps.emm.toi",
        FT_UINT8, BASE_DEC, VALS(nas_eps_emm_toi_vals), 0x07,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_toc,
        { "Type of ciphering algorithm","nas_eps.emm.toc",
        FT_UINT8, BASE_DEC, VALS(nas_eps_emm_toc_vals), 0x70,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_EPS_attach_result,
        { "Attach result","nas_eps.emm.EPS_attach_result",
        FT_UINT8,BASE_DEC, VALS(nas_eps_emm_EPS_attach_result_values), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_spare_half_octet,
        { "Spare half octet","nas_eps.emm.spare_half_octet",
        FT_UINT8,BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_add_upd_res,
        { "AURV","nas_eps.emm.add_upd_res",
        FT_UINT8, BASE_DEC, VALS(nas_eps_emm_add_upd_res_vals), 0x0,
        "Additional update result value", HFILL }
    },
    { &hf_nas_eps_emm_add_upd_type,
        { "AUTV","nas_eps.emm.add_upd_type",
        FT_UINT8, BASE_DEC, VALS(nas_eps_emm_add_upd_type_vals), 0x0,
        "Additional update type value", HFILL }
    },
    { &hf_nas_eps_emm_res,
        { "RES","nas_eps.emm.res",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_csfb_resp,
        { "CSFB response","nas_eps.emm.csfb_resp",
        FT_UINT8, BASE_DEC, VALS(nas_eps_emm_csfb_resp_vals), 0x03,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_cause,
        { "Cause","nas_eps.emm.cause",
        FT_UINT8, BASE_DEC, VALS(nas_eps_emm_cause_values), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_id_type2,
        { "Identity type 2","nas_eps.emm.id_type2",
        FT_UINT8, BASE_DEC, VALS(nas_eps_emm_id_type2_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_short_mac,
        { "Message authentication code (short)","nas_eps.emm.short_mac",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_tai_tol,
        { "Type of list","nas_eps.emm.tai_tol",
        FT_UINT8, BASE_DEC, VALS(nas_eps_emm_tai_tol_vals), 0x60,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_tai_n_elem,
        { "Number of elements","nas_eps.emm.tai_n_elem",
        FT_UINT8, BASE_DEC,  NULL, 0x1f,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_tai_tac,
        { "Tracking area code(TAC)","nas_eps.emm.tai_tac",
        FT_UINT16, BASE_HEX,  NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_eea0,
        { "EEA0","nas_eps.emm.eea0",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x80,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_128eea1,
        { "128-EEA1","nas_eps.emm.128eea1",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x40,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_128eea2,
        { "128-EEA2","nas_eps.emm.128eea2",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x20,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_eea3,
        { "EEA3","nas_eps.emm.eea3",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x10,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_eea4,
        { "EEA4","nas_eps.emm.eea4",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x08,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_eea5,
        { "EEA5","nas_eps.emm.eea5",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x04,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_eea6,
        { "EEA6","nas_eps.emm.eea6",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x02,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_eea7,
        { "EEA7","nas_eps.emm.eea7",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x01,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_eia0,
        { "EIA0","nas_eps.emm.eia0",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x80,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_128eia1,
        { "128-EIA1","nas_eps.emm.128eia1",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x40,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_128eia2,
        { "128-EIA2","nas_eps.emm.128eia2",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x20,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_eia3,
        { "EIA3","nas_eps.emm.eia3",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x10,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_eia4,
        { "EIA4","nas_eps.emm.eia4",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x08,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_eia5,
        { "EIA5","nas_eps.emm.eia5",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x04,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_eia6,
        { "EIA6","nas_eps.emm.eia6",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x02,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_eia7,
        { "EIA7","nas_eps.emm.eia7",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x01,
        NULL, HFILL }
    },


    { &hf_nas_eps_emm_uea0,
        { "UEA0","nas_eps.emm.uea0",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x80,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_uea1,
        { "UEA1","nas_eps.emm.uea1",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x40,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_uea2,
        { "UEA2","nas_eps.emm.uea2",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x20,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_uea3,
        { "UEA3","nas_eps.emm.uea3",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x10,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_uea4,
        { "UEA4","nas_eps.emm.uea4",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x08,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_uea5,
        { "UEA5","nas_eps.emm.uea5",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x04,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_uea6,
        { "UEA6","nas_eps.emm.uea6",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x02,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_uea7,
        { "UEA7","nas_eps.emm.uea7",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x01,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_ucs2_supp,
        { "UCS2 support (UCS2)","nas_eps.emm.emm_ucs2_supp",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_ucs2_supp_flg_value), 0x80,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_uia1,
        { "UMTS integrity algorithm UIA1","nas_eps.emm.uia1",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x40,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_uia2,
        { "UMTS integrity algorithm UIA2","nas_eps.emm.uia2",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x20,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_uia3,
        { "UMTS integrity algorithm UIA3","nas_eps.emm.uia3",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x10,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_uia4,
        { "UMTS integrity algorithm UIA4","nas_eps.emm.uia4",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x08,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_uia5,
        { "UMTS integrity algorithm UIA5","nas_eps.emm.uia5",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x04,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_uia6,
        { "UMTS integrity algorithm UIA6","nas_eps.emm.uia6",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x02,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_uia7,
        { "UMTS integrity algorithm UIA7","nas_eps.emm.uia7",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x01,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_gea1,
        { "GPRS encryption algorithm GEA1","nas_eps.emm.gea1",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x40,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_gea2,
        { "GPRS encryption algorithm GEA2","nas_eps.emm.gea2",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x20,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_gea3,
        { "GPRS encryption algorithm GEA3","nas_eps.emm.gea3",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x10,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_gea4,
        { "GPRS encryption algorithm GEA4","nas_eps.emm.gea4",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x08,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_gea5,
        { "GPRS encryption algorithm GEA5","nas_eps.emm.gea5",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x04,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_gea6,
        { "GPRS encryption algorithm GEA6","nas_eps.emm.gea6",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x02,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_gea7,
        { "GPRS encryption algorithm GEA7","nas_eps.emm.gea7",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_supported_flg_value), 0x01,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_lpp_cap,
        { "LPP capability","nas_eps.emm.lpp_cap",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_lpp_cap_flg), 0x08,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_lcs_cap,
        { "LCS capability","nas_eps.emm.lcs_cap",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_lcs_cap_flg), 0x04,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_1xsrvcc_cap,
        { "1xSRVCC capability","nas_eps.emm.1xsrvcc_cap",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_1xsrvcc_cap_flg), 0x02,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_nf_cap,
        { "NF capability","nas_eps.emm.nf_cap",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_nf_cap_flg), 0x01,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_ue_ra_cap_inf_upd_need_flg,
        { "1xSRVCC capability","nas_eps.emm.ue_ra_cap_inf_upd_need_flg",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_ue_ra_cap_inf_upd_need_flg), 0x01,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_ss_code,
        { "SS Code","nas_eps.emm.ss_code",
        FT_UINT8,BASE_DEC, VALS(ssCode_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_lcs_ind,
        { "LCS indicator","nas_eps.emm.emm_lcs_ind",
        FT_UINT8,BASE_DEC, VALS(nas_eps_emm_lcs_ind_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_gen_msg_cont_type,
        { "Container type","nas_eps.emm.gen_msg_cont_type",
        FT_UINT8,BASE_DEC, VALS(nas_eps_emm_gen_msg_cont_type_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_apn_ambr_ul,
        { "APN-AMBR for uplink","nas_eps.emm.apn_ambr_ul",
        FT_UINT8,BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_apn_ambr_dl,
        { "APN-AMBR for downlink","nas_eps.emm.apn_ambr_dl",
        FT_UINT8,BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_apn_ambr_ul_ext,
        { "APN-AMBR for uplink(Extended)","nas_eps.emm.apn_ambr_ul_ext",
        FT_UINT8,BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_apn_ambr_dl_ext,
        { "APN-AMBR for downlink(Extended)","nas_eps.emm.apn_ambr_dl_ext",
        FT_UINT8,BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_apn_ambr_ul_ext2,
        { "APN-AMBR for uplink(Extended-2)","nas_eps.emm.apn_ambr_ul_ext2",
        FT_UINT8,BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_apn_ambr_dl_ext2,
        { "APN-AMBR for downlink(Extended-2)","nas_eps.emm.apn_ambr_dl_ext2",
        FT_UINT8,BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_switch_off,
        { "Switch off","nas_eps.emm.switch_off",
        FT_UINT8,BASE_DEC, VALS(nas_eps_emm_switch_off_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_detach_type_UL,
        { "Detach Type","nas_eps.emm.detach_type_ul",
        FT_UINT8,BASE_DEC, VALS(nas_eps_emm_type_of_dtatch_UL_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_detach_type_DL,
        { "Detach Type","nas_eps.emm.detach_type_dl",
        FT_UINT8,BASE_DEC, VALS(nas_eps_emm_type_of_dtatch_DL_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_qci,
        { "Quality of Service Class Identifier (QCI)","nas_eps.emm.qci",
        FT_UINT8,(BASE_DEC|BASE_RANGE_STRING), RVALS(nas_eps_qci_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_mbr_ul,
        { "Maximum bit rate for uplink","nas_eps.emm.mbr_ul",
        FT_UINT8,BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_mbr_dl,
        { "Maximum bit rate for downlink","nas_eps.emm.mbr_dl",
        FT_UINT8,BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_gbr_ul,
        { "Guaranteed bit rate for uplink","nas_eps.emm.gbr_ul",
        FT_UINT8,BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_gbr_dl,
        { "Guaranteed bit rate for downlink","nas_eps.emm.gbr_dl",
        FT_UINT8,BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_embr_ul,
        { "Maximum bit rate for uplink(ext)","nas_eps.emm.embr_ul",
        FT_UINT8,BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_embr_dl,
        { "Maximum bit rate for downlink(ext)","nas_eps.emm.embr_dl",
        FT_UINT8,BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_egbr_ul,
        { "Guaranteed bit rate for uplink(ext)","nas_eps.emm.egbr_ul",
        FT_UINT8,BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_egbr_dl,
        { "Guaranteed bit rate for downlink(ext)","nas_eps.emm.egbr_dl",
        FT_UINT8,BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_cause,
        { "Cause","nas_eps.esm.cause",
        FT_UINT8,BASE_DEC, VALS(nas_eps_esm_cause_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_eit,
        { "EIT (ESM information transfer)", "nas_eps.emm.eit",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_eit_vals), 0x01,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_lnkd_eps_bearer_id,
        { "Linked EPS bearer identity","nas_eps.esm.lnkd_eps_bearer_id",
        FT_UINT8,BASE_DEC, VALS(nas_eps_esm_linked_bearer_id_vals), 0x0f,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_notif_ind,
        { "Notification indicator value","nas_eps.esm.notif_ind",
        FT_UINT8,BASE_DEC, VALS(nas_eps_esm_notif_ind_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_pdn_ipv4,
        {"PDN IPv4", "nas_eps.esm.pdn_ipv4",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_nas_eps_esm_pdn_ipv6_if_id,
        {"PDN IPv6 if id", "nas_eps.esm.pdn_ipv6_if_id",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_nas_eps_esm_linked_bearer_id,
        { "Linked EPS bearer identity","nas_eps.esm.linked_bearer_id",
        FT_UINT8,BASE_DEC, VALS(nas_eps_esm_linked_bearer_id_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_active_flg,
        { "Active flag", "nas_eps.emm.active_flg",
        FT_BOOLEAN, BASE_NONE, TFS(&nas_eps_emm_active_flg_value), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_eps_update_result_value,
        { "EPS update result value","nas_eps.emm.eps_update_result_value",
        FT_UINT8,BASE_DEC, VALS(nas_eps_emm_eps_update_result_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_eps_update_type_value,
        { "EPS update type value", "nas_eps.emm.update_type_value",
        FT_UINT8,BASE_DEC, VALS(nas_eps_emm_eps_update_type_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_service_type,
        { "Service type", "nas_eps.emm.service_type",
        FT_UINT8,BASE_DEC, VALS(nas_eps_service_type_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_nas_msg_cont,
        { "NAS message container content", "nas_eps.emm.nas_msg_cont",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_gen_msg_cont,
        { "Generic message container content", "nas_eps.emm.gen_msg_cont",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_cmn_add_info,
        { "Additional information content", "nas_eps.cmn.add_info",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* ESM hf cvariables */
    { &hf_nas_eps_msg_esm_type,
        { "NAS EPS session management messages",    "nas_eps.nas_msg_esm_type",
        FT_UINT8, BASE_HEX, VALS(nas_msg_esm_strings), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_elem_id,
        { "Element ID", "nas_eps.esm.elem_id",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_proc_trans_id,
        { "Procedure transaction identity", "nas_eps.esm.proc_trans_id",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_pdn_type,
        { "PDN type",   "nas_eps.nas_eps_esm_pdn_type",
        FT_UINT8, BASE_DEC, VALS(nas_eps_esm_pdn_type_values), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_request_type,
        { "Request type",	"nas_eps.nas_eps_esm_request_type",
        FT_UINT8, BASE_DEC, VALS(nas_eps_esm_request_type_values), 0x0,
        NULL, HFILL }
    },
  };

    /* Setup protocol subtree array */
#define NUM_INDIVIDUAL_ELEMS    5
    gint *ett[NUM_INDIVIDUAL_ELEMS +
          NUM_NAS_EPS_COMMON_ELEM +
          NUM_NAS_MSG_EMM + NUM_NAS_EMM_ELEM+
          NUM_NAS_MSG_ESM + NUM_NAS_ESM_ELEM];

    ett[0] = &ett_nas_eps;
    ett[1] = &ett_nas_eps_esm_msg_cont;
    ett[2] = &ett_nas_eps_nas_msg_cont;
    ett[3] = &ett_nas_eps_gen_msg_cont;
    ett[4] = &ett_nas_eps_cmn_add_info;

    last_offset = NUM_INDIVIDUAL_ELEMS;

    for (i=0; i < NUM_NAS_EPS_COMMON_ELEM; i++, last_offset++)
    {
        ett_nas_eps_common_elem[i] = -1;
        ett[last_offset] = &ett_nas_eps_common_elem[i];
    }

    /* EMM */
    for (i=0; i < NUM_NAS_MSG_EMM; i++, last_offset++)
    {
        ett_nas_msg_emm[i] = -1;
        ett[last_offset] = &ett_nas_msg_emm[i];
    }

    for (i=0; i < NUM_NAS_EMM_ELEM; i++, last_offset++)
    {
        ett_nas_eps_emm_elem[i] = -1;
        ett[last_offset] = &ett_nas_eps_emm_elem[i];
    }
    /* EPS */
    for (i=0; i < NUM_NAS_MSG_ESM; i++, last_offset++)
    {
        ett_nas_msg_esm[i] = -1;
        ett[last_offset] = &ett_nas_msg_esm[i];
    }

    for (i=0; i < NUM_NAS_ESM_ELEM; i++, last_offset++)
    {
        ett_nas_eps_esm_elem[i] = -1;
        ett[last_offset] = &ett_nas_eps_esm_elem[i];
    }

    /* Register protocol */
    proto_nas_eps = proto_register_protocol(PNAME, PSNAME, PFNAME);
    /* Register fields and subtrees */
    proto_register_field_array(proto_nas_eps, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register dissector */
    register_dissector(PFNAME, dissect_nas_eps, proto_nas_eps);

    /* Register dissector */
    register_dissector("nas-eps_plain", dissect_nas_eps_plain, proto_nas_eps);
}

void
proto_reg_handoff_nas_eps(void)
{
    gsm_a_dtap_handle = find_dissector("gsm_a_dtap");
    lpp_handle = find_dissector("lpp");
}
