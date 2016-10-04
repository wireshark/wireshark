/* packet-nas_eps.c
 * Routines for Non-Access-Stratum (NAS) protocol for Evolved Packet System (EPS) dissection
 *
 * Copyright 2008 - 2010, Anders Broman <anders.broman@ericsson.com>
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
 *
 * References: 3GPP TS 24.301 V13.5.0 (2016-03)
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>
#include "packet-gsm_map.h"
#include "packet-gsm_a_common.h"
#include "packet-e212.h"
#include "packet-lcsap.h"

void proto_register_nas_eps(void);
void proto_reg_handoff_nas_eps(void);

#define PNAME  "Non-Access-Stratum (NAS)PDU"
#define PSNAME "NAS-EPS"
#define PFNAME "nas-eps"

/* Initialize the protocol and registered fields */
static int proto_nas_eps = -1;

/* Dissector handles */
static dissector_handle_t gsm_a_dtap_handle;
static dissector_handle_t lpp_handle;
static dissector_handle_t nbifom_handle;

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
static int hf_nas_eps_ciphered_msg = -1;
static int hf_nas_eps_msg_elems = -1;
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
static int hf_nas_eps_emm_ext_emm_cause = -1;
static int hf_nas_eps_emm_eps_att_type = -1;
static int hf_nas_eps_emm_cp_ciot = -1;
static int hf_nas_eps_emm_er_wo_pdn = -1;
static int hf_nas_eps_emm_esr_ps = -1;
static int hf_nas_eps_emm_cs_lcs = -1;
static int hf_nas_eps_emm_epc_lcs = -1;
static int hf_nas_eps_emm_emc_bs = -1;
static int hf_nas_eps_emm_ims_vops = -1;
static int hf_nas_eps_emm_epco = -1;
static int hf_nas_eps_emm_hc_cp_ciot = -1;
static int hf_nas_eps_emm_s1_u_data = -1;
static int hf_nas_eps_emm_up_ciot = -1;
static int hf_nas_eps_emm_nas_key_set_id = -1;
static int hf_nas_eps_tsc = -1;
static int hf_nas_eps_emm_odd_even = -1;
static int hf_nas_eps_emm_type_of_id = -1;
static int hf_nas_eps_emm_mme_grp_id = -1;
static int hf_nas_eps_emm_imei = -1;
static int hf_nas_eps_emm_mme_code = -1;
static int hf_nas_eps_emm_m_tmsi = -1;
static int hf_nas_eps_esm_msg_cont = -1;
static int hf_nas_eps_esm_imeisv_req = -1;
static int hf_nas_eps_emm_toi = -1;
static int hf_nas_eps_emm_toc = -1;
static int hf_nas_eps_emm_EPS_attach_result = -1;
static int hf_nas_eps_emm_spare_half_octet = -1;
static int hf_nas_eps_emm_anb_up_ciot = -1;
static int hf_nas_eps_emm_anb_cp_ciot = -1;
static int hf_nas_eps_emm_add_upd_res = -1;
static int hf_nas_eps_emm_pnb_ciot = -1;
static int hf_nas_eps_emm_saf = -1;
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
static int hf_nas_eps_emm_prose_dd_cap = -1;
static int hf_nas_eps_emm_prose_cap = -1;
static int hf_nas_eps_emm_h245_ash_cap = -1;
static int hf_nas_eps_emm_acc_csfb_cap = -1;
static int hf_nas_eps_emm_lpp_cap = -1;
static int hf_nas_eps_emm_lcs_cap = -1;
static int hf_nas_eps_emm_1xsrvcc_cap = -1;
static int hf_nas_eps_emm_nf_cap = -1;
static int hf_nas_eps_emm_epco_cap = -1;
static int hf_nas_eps_emm_hc_cp_ciot_cap = -1;
static int hf_nas_eps_emm_er_wo_pdn_cap = -1;
static int hf_nas_eps_emm_s1u_data_cap = -1;
static int hf_nas_eps_emm_up_ciot_cap = -1;
static int hf_nas_eps_emm_cp_ciot_cap = -1;
static int hf_nas_eps_emm_prose_relay_cap = -1;
static int hf_nas_eps_emm_prose_dc_cap = -1;
static int hf_nas_eps_emm_ue_ra_cap_inf_upd_need_flg = -1;
static int hf_nas_eps_emm_ss_code = -1;
static int hf_nas_eps_emm_lcs_ind = -1;
static int hf_nas_eps_emm_gen_msg_cont_type = -1;
static int hf_nas_eps_emm_apn_ambr_ul = -1;
static int hf_nas_eps_emm_apn_ambr_dl = -1;
static int hf_nas_eps_emm_apn_ambr_ul_ext = -1;
static int hf_nas_eps_emm_apn_ambr_dl_ext = -1;
static int hf_nas_eps_emm_apn_ambr_ul_ext2 = -1;
static int hf_nas_eps_emm_apn_ambr_dl_ext2 = -1;
static int hf_nas_eps_emm_apn_ambr_ul_total = -1;
static int hf_nas_eps_emm_apn_ambr_dl_total = -1;
static int hf_nas_eps_emm_guti_type = -1;
static int hf_nas_eps_emm_detach_req_UL = -1;
static int hf_nas_eps_emm_detach_req_DL = -1;
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
static int hf_nas_eps_esm_notif_ind = -1;
static int hf_nas_eps_esm_pdn_type = -1;
static int hf_nas_eps_esm_pdn_ipv4 = -1;
static int hf_nas_eps_esm_pdn_ipv6_if_id = -1;
static int hf_nas_eps_esm_eplmnc = -1;
static int hf_nas_eps_esm_ratc = -1;
static int hf_nas_eps_esm_linked_bearer_id = -1;
static int hf_nas_eps_esm_nbifom_cont = -1;
static int hf_nas_eps_esm_remote_ue_context_list_nb_ue_contexts = -1;
static int hf_nas_eps_esm_remote_ue_context_list_ue_context_len = -1;
static int hf_nas_eps_esm_remote_ue_context_list_ue_context_nb_user_id = -1;
static int hf_nas_eps_esm_remote_ue_context_list_ue_context_user_id_len = -1;
static int hf_nas_eps_esm_remote_ue_context_list_ue_context_odd_even_indic = -1;
static int hf_nas_eps_esm_remote_ue_context_list_ue_context_user_id_type = -1;
static int hf_nas_eps_esm_remote_ue_context_list_ue_context_encr_imsi = -1;
static int hf_nas_eps_esm_remote_ue_context_list_ue_context_msisdn = -1;
static int hf_nas_eps_esm_remote_ue_context_list_ue_context_imei = -1;
static int hf_nas_eps_esm_remote_ue_context_list_ue_context_imeisv = -1;
static int hf_nas_eps_esm_remote_ue_context_list_ue_context_address_type = -1;
static int hf_nas_eps_esm_remote_ue_context_list_ue_context_ipv4 = -1;
static int hf_nas_eps_esm_remote_ue_context_list_ue_context_port_number = -1;
static int hf_nas_eps_esm_remote_ue_context_list_ue_context_ipv6_prefix = -1;
static int hf_nas_eps_esm_pkmf_address_type = -1;
static int hf_nas_eps_esm_pkmf_ipv4 = -1;
static int hf_nas_eps_esm_pkmf_ipv6 = -1;
static int hf_nas_eps_esm_spare_bit0x80 = -1;
static int hf_nas_eps_esm_hdr_comp_config_prof_0104 = -1;
static int hf_nas_eps_esm_hdr_comp_config_prof_0103 = -1;
static int hf_nas_eps_esm_hdr_comp_config_prof_0102 = -1;
static int hf_nas_eps_esm_hdr_comp_config_prof_0006 = -1;
static int hf_nas_eps_esm_hdr_comp_config_prof_0004 = -1;
static int hf_nas_eps_esm_hdr_comp_config_prof_0003 = -1;
static int hf_nas_eps_esm_hdr_comp_config_prof_0002 = -1;
static int hf_nas_eps_esm_hdr_compr_config_max_cid = -1;
static int hf_nas_eps_esm_ctrl_plane_only_ind_cpoi = -1;
static int hf_nas_eps_esm_user_data_cont = -1;
static int hf_nas_eps_esm_rel_assist_ind_ddx = -1;
static int hf_nas_eps_esm_hdr_compr_config_status_ebi7 = -1;
static int hf_nas_eps_esm_hdr_compr_config_status_ebi6 = -1;
static int hf_nas_eps_esm_hdr_compr_config_status_ebi5 = -1;
static int hf_nas_eps_esm_spare_bits0x1f00 = -1;
static int hf_nas_eps_esm_hdr_compr_config_status_ebi15 = -1;
static int hf_nas_eps_esm_hdr_compr_config_status_ebi14 = -1;
static int hf_nas_eps_esm_hdr_compr_config_status_ebi13 = -1;
static int hf_nas_eps_esm_hdr_compr_config_status_ebi12 = -1;
static int hf_nas_eps_esm_hdr_compr_config_status_ebi11 = -1;
static int hf_nas_eps_esm_hdr_compr_config_status_ebi10 = -1;
static int hf_nas_eps_esm_hdr_compr_config_status_ebi9 = -1;
static int hf_nas_eps_esm_hdr_compr_config_status_ebi8 = -1;
static int hf_nas_eps_esm_serv_plmn_rate_ctrl_val = -1;

static int hf_nas_eps_active_flg = -1;
static int hf_nas_eps_data_serv_type = -1;
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
static int ett_nas_eps_remote_ue_context = -1;

static expert_field ei_nas_eps_extraneous_data = EI_INIT;
static expert_field ei_nas_eps_unknown_identity = EI_INIT;
static expert_field ei_nas_eps_unknown_type_of_list = EI_INIT;
static expert_field ei_nas_eps_wrong_nb_of_elems = EI_INIT;
static expert_field ei_nas_eps_unknown_msg_type = EI_INIT;
static expert_field ei_nas_eps_unknown_pd = EI_INIT;
static expert_field ei_nas_eps_esm_tp_not_integ_prot = EI_INIT;

/* Global variables */
static gboolean g_nas_eps_dissect_plain = FALSE;
static gboolean g_nas_eps_null_decipher = TRUE;

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
    { 0x4d, "Control plane service request"},
    { 0x4e, "Service reject"},
    { 0x4f, "Service accept"},

    { 0x50, "GUTI reallocation command"},
    { 0x51, "GUTI reallocation complete"},
    { 0x52, "Authentication request"},
    { 0x53, "Authentication response"},
    { 0x54, "Authentication reject"},
    { 0x55, "Identity request"},
    { 0x56, "Identity response"},
    { 0x5c, "Authentication failure"},
    { 0x5d, "Security mode command"},
    { 0x5e, "Security mode complete"},
    { 0x5f, "Security mode reject"},

    { 0x60, "EMM status"},
    { 0x61, "EMM information"},
    { 0x62, "Downlink NAS transport"},
    { 0x63, "Uplink NAS transport"},
    { 0x64, "CS service notification"},
    { 0x68, "Downlink generic NAS transport"},
    { 0x69, "Uplink generic NAS transport"},
    { 0,    NULL }
};
static value_string_ext nas_msg_emm_strings_ext = VALUE_STRING_EXT_INIT(nas_msg_emm_strings);

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
    { 0xdc, "ESM dummy message"},
    { 0xe8, "ESM status"},
    { 0xe9, "Remote UE report"},
    { 0xea, "Remote UE report response"},
    { 0xeb, "ESM data transport"},
    { 0,    NULL }
};
static value_string_ext nas_msg_esm_strings_ext = VALUE_STRING_EXT_INIT(nas_msg_esm_strings);

static const value_string security_header_type_vals[] = {
    { 0,    "Plain NAS message, not security protected"},
    { 1,    "Integrity protected"},
    { 2,    "Integrity protected and ciphered"},
    { 3,    "Integrity protected with new EPS security context"},
    { 4,    "Integrity protected and ciphered with new EPS security context"},
    { 5,    "Integrity protected and partially ciphered NAS message"},
    { 6,    "Reserved"},
    { 7,    "Reserved"},
    { 8,    "Reserved"},
    { 9,    "Reserved"},
    { 10,   "Reserved"},
    { 11,   "Reserved"},
    { 12,   "Security header for the SERVICE REQUEST message"},
    { 13,   "These values are not used in this version of the protocol."
             " If received they shall be interpreted as security header for the SERVICE REQUEST message"},
    { 14,   "These values are not used in this version of the protocol."
             " If received they shall be interpreted as Security header for the SERVICE REQUEST message"},
    { 15,   "These values are not used in this version of the protocol."
             " If received they shall be interpreted as Security header for the SERVICE REQUEST message"},
    { 0,    NULL }
};
static value_string_ext security_header_type_vals_ext = VALUE_STRING_EXT_INIT(security_header_type_vals);

typedef enum
{
    DE_EPS_CMN_ADD_INFO,                        /* 9.9.2.0  Additional information */
    DE_EPS_CMN_DEVICE_PROPERTIES,               /* 9.9.2.0A Device properties */
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

static const value_string nas_eps_common_elem_strings[] = {
    { DE_EPS_CMN_ADD_INFO, "Additional information" },                       /* 9.9.2.0  Additional information */
    { DE_EPS_CMN_DEVICE_PROPERTIES, "Device properties" },                   /* 9.9.2.0A Device properties */
    { DE_EPS_CMN_EPS_BE_CTX_STATUS, "EPS bearer context status" },           /* 9.9.2.1  EPS bearer context status */
    { DE_EPS_CMN_LOC_AREA_ID, "Location area identification" },              /* 9.9.2.2  Location area identification */
    { DE_EPS_CMN_MOB_ID, "Mobile identity" },                                /* 9.9.2.3  Mobile identity */
    { DE_EPS_MS_CM_2, "Mobile station classmark 2" },                        /* 9.9.2.4  Mobile station classmark 2 */
    { DE_EPS_MS_CM_3, "Mobile station classmark 3" },                        /* 9.9.2.5  Mobile station classmark 3 */
    { DE_EPS_NAS_SEC_PAR_FROM_EUTRA, "NAS security parameters from E-UTRA" },/* 9.9.2.6  NAS security parameters from E-UTRA */
    { DE_EPS_NAS_SEC_PAR_TO_EUTRA, "NAS security parameters to E-UTRA" },    /* 9.9.2.7  NAS security parameters to E-UTRA */
    { DE_EPS_CMN_PLM_LST, "PLMN list" },                                     /* 9.9.2.8  PLMN list   */
                                                                             /* 9.9.2.9  Spare half octet */
    { DE_EPS_CMN_SUP_CODEC_LST, "Supported codec list" },                    /* 9.9.2.10 Supported codec list */
    { 0, NULL }
};
value_string_ext nas_eps_common_elem_strings_ext = VALUE_STRING_EXT_INIT(nas_eps_common_elem_strings);

/* Utility functions */
static guint16
calc_bitrate(guint8 value) {
    guint16 return_value = value;

    if ((value > 63) && (value <= 127)) {
        return_value = 64 + (value - 64) * 8;
    }
    else if ((value > 127) && (value <= 254)) {
        return_value = 576 + (value - 128) * 64;
    }
    else if (value == 0xff) {
        return_value = 0;
    }
    return return_value;
}
static guint32
calc_bitrate_ext(guint8 value) {
    guint32 return_value = 0;

    if ((value > 0) && (value <= 0x4a)) {
        return_value = 8600 + value * 100;
    }
    else if ((value > 0x4a) && (value <= 0xba)) {
        return_value = 16 + (value-0x4a);
    }
    else if ((value > 0xba) && (value <= 0xfa)) {
        return_value = 128 + (value-0xba)*2;
    }
    else {
        return_value = 256;
    }

    return return_value;
}
static guint32
calc_bitrate_ext2(guint8 value) {
    guint32 return_value = 0;

    if ((value > 0) && (value <= 0x3d)) {
        return_value = 256 + value * 4;
    }
    else if ((value > 0x3d) && (value <= 0xa1)) {
        return_value = 500 + (value-0x3d) * 10;
    }
    else if ((value > 0xa1) && (value <= 0xf6)) {
        return_value = 1500 + (value-0xa1) * 100;
    }
    else {
        return_value = 10000;
    }

    return return_value;
}

#define NUM_NAS_EPS_COMMON_ELEM (sizeof(nas_eps_common_elem_strings)/sizeof(value_string))
gint ett_nas_eps_common_elem[NUM_NAS_EPS_COMMON_ELEM];

/*
 * 9.9.2    Common information elements
 */

/* 9.9.2.0 Additional information */
static guint16
de_eps_cmn_add_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
                    guint32 offset, guint len,
                    gchar *add_string _U_, int string_len _U_)
{
    proto_item *item;
    proto_tree *sub_tree;
    tvbuff_t   *new_tvb;

    item     = proto_tree_add_item(tree, hf_nas_eps_cmn_add_info, tvb, offset, len, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_nas_eps_cmn_add_info);

    new_tvb = tvb_new_subset_length(tvb, offset, len);

    switch (eps_nas_gen_msg_cont_type) {
        case 1:
            /* LPP */
            dissect_lcsap_Correlation_ID_PDU(new_tvb, pinfo, sub_tree, NULL);
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
de_eps_cmn_eps_be_ctx_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                             guint32 offset, guint len _U_,
                             gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    /* EBI(7)  EBI(6)  EBI(5)  EBI(4)  EBI(3)  EBI(2)  EBI(1) EBI(0) octet 3 */
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi7,  tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi6,  tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi5,  tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EBI(0) - EBI(4): Bits 0 to 4 of octet 3 are spare and shall be coded as zero. */
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi4,  tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi3,  tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi2,  tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi1,  tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi0,  tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;
    /* EBI(15) EBI(14) EBI(13) EBI(12) EBI(11) EBI(10) EBI(9) EBI(8) octet 4 */
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi15, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi14, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi13, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi12, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi11, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi10, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi9,  tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_ebi8,  tvb, curr_offset, 1, ENC_BIG_ENDIAN);

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
de_emm_sec_par_from_eutra(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                          guint32 offset, guint len _U_,
                          gchar *add_string _U_, int string_len _U_)
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
de_emm_sec_par_to_eutra(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                        guint32 offset, guint len _U_,
                        gchar *add_string _U_, int string_len _U_)
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

guint16 (*nas_eps_common_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
                                     guint32 offset, guint len,
                                     gchar *add_string, int string_len) = {
    /* 9.9.2    Common information elements */
    de_eps_cmn_add_info,            /* 9.9.2.0  Additional information */
    NULL,                           /* 9.9.2.0A Device properties */
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

static const value_string nas_emm_elem_strings[] = {
    /* 9.9.3    EPS Mobility Management (EMM) information elements */
    { DE_EMM_ADD_UPD_RES, "Additional update result" },                        /* 9.9.3.0A Additional update result */
    { DE_EMM_ADD_UPD_TYPE, "Additional update type" },                         /* 9.9.3.0B Additional update type */
    { DE_EMM_AUTH_FAIL_PAR, "Authentication failure parameter" },              /* 9.9.3.1  Authentication failure parameter */
    { DE_EMM_AUTN, "Authentication parameter AUTN" },                          /* 9.9.3.2  Authentication parameter AUTN */
    { DE_EMM_AUTH_PAR_RAND, "Authentication parameter RAND" },                 /* 9.9.3.3  Authentication parameter RAND */
    { DE_EMM_AUTH_RESP_PAR, "Authentication response parameter" },             /* 9.9.3.4  Authentication response parameter */
    { DE_EMM_CSFB_RESP, "CSFB response" },                                     /* 9.9.3.5  CSFB response */
    { DE_EMM_DAYL_SAV_T, "Daylight saving time" },                             /* 9.9.3.6  Daylight saving time */
    { DE_EMM_DET_TYPE, "Detach type" },                                        /* 9.9.3.7  Detach type */
    { DE_EMM_DRX_PAR, "DRX parameter" },                                       /* 9.9.3.8  DRX parameter */
    { DE_EMM_CAUSE, "EMM cause" },                                             /* 9.9.3.9  EMM cause */
    { DE_EMM_ATT_RES, "EPS attach result" },                                   /* 9.9.3.10 EPS attach result */
    { DE_EMM_ATT_TYPE, "EPS attach type" },                                    /* 9.9.3.11 EPS attach type */
    { DE_EMM_EPS_MID, "EPS mobile identity" },                                 /* 9.9.3.12 EPS mobile identity */
    { DE_EMM_EPS_NET_FEATURE_SUP, "EPS network feature support" },             /* 9.9.3.12A EPS network feature support */
    { DE_EMM_EPS_UPD_RES, "EPS update result" },                               /* 9.9.3.13 EPS update result */
    { DE_EMM_EPS_UPD_TYPE, "EPS update type" },                                /* 9.9.3.14 EPS update type */
    { DE_EMM_ESM_MSG_CONT, "ESM message container" },                          /* 9.9.3.15 ESM message conta */
    { DE_EMM_GPRS_TIMER, "GPRS timer" },                                       /* 9.9.3.16 GPRS timer ,See subclause 10.5.7.3 in 3GPP TS 24.008 [6]. */
    { DE_EMM_GPRS_TIMER_2, "GPRS timer 2" },                                   /* 9.9.3.16A GPRS timer 2, See subclause 10.5.7.4 in 3GPP TS 24.008. */
    { DE_EMM_GPRS_TIMER_3, "GPRS timer 3" },                                   /* 9.9.3.16B GPRS timer 3, See subclause 10.5.7.4a in 3GPP TS 24.008. */
    { DE_EMM_ID_TYPE_2, "Identity type 2" },                                   /* 9.9.3.17 Identity type 2 ,See subclause 10.5.5.9 in 3GPP TS 24.008 [6]. */
    { DE_EMM_IMEISV_REQ, "IMEISV request" },                                   /* 9.9.3.18 IMEISV request ,See subclause 10.5.5.10 in 3GPP TS 24.008 [6]. */
    { DE_EMM_KSI_AND_SEQ_NO, "KSI and sequence number" },                      /* 9.9.3.19 KSI and sequence number */
    { DE_EMM_MS_NET_CAP, "MS network capability" },                            /* 9.9.3.20 MS network capability ,See subclause 10.5.5.12 in 3GPP TS 24.008 [6]. */
    { DE_EMM_MS_NET_FEAT_SUP, "MS network feature support" },                  /* 9.9.3.20A MS network feature support, See subclause 10.5.1.15 in 3GPP TS 24.008. */
    { DE_EMM_NAS_KEY_SET_ID, "NAS key set identifier" },                       /* 9.9.3.21 NAS key set identifier */
    { DE_EMM_NAS_MSG_CONT, "NAS message container" },                          /* 9.9.3.22 NAS message container */
    { DE_EMM_NAS_SEC_ALGS, "NAS security algorithms" },                        /* 9.9.3.23 NAS security algorithms */
    { DE_EMM_NET_NAME, "Network name" },                                       /* 9.9.3.24 Network name, See subclause 10.5.3.5a in 3GPP TS 24.008 [6]. */
    { DE_EMM_NONCE, "Nonce" },                                                 /* 9.9.3.25 Nonce */
    { DE_EMM_PAGING_ID, "Paging identity" },                                   /* 9.9.3.25A Paging identity */
    { DE_EMM_P_TMSI_SIGN, "P-TMSI signature" },                                /* 9.9.3.26 P-TMSI signature, See subclause 10.5.5.8 in 3GPP TS 24.008 [6]. */
    { DE_EMM_EXT_CAUSE, " Extended EMM cause" },                               /* 9.9.3.26A Extended EMM cause */
    { DE_EMM_SERV_TYPE, "Service type" },                                      /* 9.9.3.27 Service type ,See subclause 10.5.5.15 in 3GPP TS 24.008 [6]. */
    { DE_EMM_SHORT_MAC, "Short MAC" },                                         /* 9.9.3.28 Short MAC */
    { DE_EMM_TZ, "Time zone" },                                                /* 9.9.3.29 Time zone, See subclause 10.5.3.8 in 3GPP TS 24.008 [6]. */
    { DE_EMM_TZ_AND_T, "Time zone and time" },                                 /* 9.9.3.30 Time zone and time, See subclause 10.5.3.9 in 3GPP TS 24.008 [6]. */
    { DE_EMM_TMSI_STAT, "TMSI status" },                                       /* 9.9.3.31 TMSI status, See subclause 10.5.5.4 in 3GPP TS 24.008 [6]. */
    { DE_EMM_TRAC_AREA_ID, "Tracking area identity" },                         /* 9.9.3.32 Tracking area identity */
    { DE_EMM_TRAC_AREA_ID_LST, "Tracking area identity list" },                /* 9.9.3.33 Tracking area identity list */
    { DE_EMM_UE_NET_CAP, "UE network capability" },                            /* 9.9.3.34 UE network capability */
    { DE_EMM_UE_RA_CAP_INF_UPD_NEED, "UE radio capability information update needed" },/* 9.9.3.35 UE radio capability information update needed */
    { DE_EMM_UE_SEC_CAP, "UE security capability" },                           /* 9.9.3.36 UE security capability */
    { DE_EMM_EMERG_NUM_LST, "Emergency Number List" },                         /* 9.9.3.37 Emergency Number List */
    { DE_EMM_CLI, "CLI" },                                                     /* 9.9.3.38 CLI */
    { DE_EMM_SS_CODE, "SS Code" },                                             /* 9.9.3.39 SS Code */
    { DE_EMM_LCS_IND, "LCS indicator" },                                       /* 9.9.3.40 LCS indicator */
    { DE_EMM_LCS_CLIENT_ID, "LCS client identity" },                           /* 9.9.3.41 LCS client identity */
    { DE_EMM_GEN_MSG_CONT_TYPE, "Generic message container type" },            /* 9.9.3.42 Generic message container type */
    { DE_EMM_GEN_MSG_CONT, "Generic message container" },                      /* 9.9.3.43 Generic message container */
    { DE_EMM_VOICE_DMN_PREF, "Voice domain preference and UEs usage setting" },/* 9.9.3.44 Voice domain preference and UEs usage setting */
    { DE_EMM_GUTI_TYPE, "GUTI type" },                                         /* 9.9.3.45 GUTI type */
    { DE_EMM_EXT_DRX_PARAMS, "Extended DRX parameters" },                      /* 9.9.3.46 Extended DRX parameters */
    { DE_EMM_DATA_SERV_TYPE, "Data service type" },                            /* 9.9.3.47 Data service type */
    { 0, NULL }
};
value_string_ext nas_emm_elem_strings_ext = VALUE_STRING_EXT_INIT(nas_emm_elem_strings);

#define NUM_NAS_EMM_ELEM (sizeof(nas_emm_elem_strings)/sizeof(value_string))
gint ett_nas_eps_emm_elem[NUM_NAS_EMM_ELEM];

#if 0
/* This enum has been moved to packet-gsm_a_common to
make it possible to use element dissection from this dissector
in other dissectors.
It is left here as a comment for easier reference.
*/
/*
Note this enum must be of the same size as the element decoding list
*/
typedef enum
{
    /* 9.9.3    EPS Mobility Management (EMM) information elements */
    DE_EMM_ADD_UPD_RES,         /* 9.9.3.0A Additional update result */
    DE_EMM_ADD_UPD_TYPE,        /* 9.9.3.0B Additional update type */
    DE_EMM_AUTH_FAIL_PAR,       /* 9.9.3.1  Authentication failure parameter (dissected in packet-gsm_a_dtap.c)*/
    DE_EMM_AUTN,                /* 9.9.3.2  Authentication parameter AUTN */
    DE_EMM_AUTH_PAR_RAND,       /* 9.9.3.3  Authentication parameter RAND */
    DE_EMM_AUTH_RESP_PAR,       /* 9.9.3.4  Authentication response parameter */
    DE_EMM_CSFB_RESP,           /* 9.9.3.5  CSFB response */
    DE_EMM_DAYL_SAV_T,          /* 9.9.3.6  Daylight saving time */
    DE_EMM_DET_TYPE,            /* 9.9.3.7  Detach type */
    DE_EMM_DRX_PAR,             /* 9.9.3.8  DRX parameter (dissected in packet-gsm_a_gm.c)*/
    DE_EMM_CAUSE,               /* 9.9.3.9  EMM cause */
    DE_EMM_ATT_RES,             /* 9.9.3.10 EPS attach result (Coded inline */
    DE_EMM_ATT_TYPE,            /* 9.9.3.11 EPS attach type (Coded Inline)*/
    DE_EMM_EPS_MID,             /* 9.9.3.12 EPS mobile identity */
    DE_EMM_EPS_NET_FEATURE_SUP, /* 9.9.3.12A EPS network feature support */
    DE_EMM_EPS_UPD_RES,         /* 9.9.3.13 EPS update result ( Coded inline)*/
    DE_EMM_EPS_UPD_TYPE,        /* 9.9.3.14 EPS update type */
    DE_EMM_ESM_MSG_CONT,        /* 9.9.3.15 ESM message conta */
    DE_EMM_GPRS_TIMER,          /* 9.9.3.16 GPRS timer ,See subclause 10.5.7.3 in 3GPP TS 24.008 [6]. */
    DE_EMM_GPRS_TIMER_2,        /* 9.9.3.16A GPRS timer 2, See subclause 10.5.7.4 in 3GPP TS 24.008. */
    DE_EMM_GPRS_TIMER_3,        /* 9.9.3.16B GPRS timer 3, See subclause 10.5.7.4a in 3GPP TS 24.008. */
    DE_EMM_ID_TYPE_2,           /* 9.9.3.17 Identity type 2 ,See subclause 10.5.5.9 in 3GPP TS 24.008 [6]. */
    DE_EMM_IMEISV_REQ,          /* 9.9.3.18 IMEISV request ,See subclause 10.5.5.10 in 3GPP TS 24.008 [6]. */
    DE_EMM_KSI_AND_SEQ_NO,      /* 9.9.3.19 KSI and sequence number */
    DE_EMM_MS_NET_CAP,          /* 9.9.3.20 MS network capability ,See subclause 10.5.5.12 in 3GPP TS 24.008 [6]. */
    DE_EMM_MS_NET_FEAT_SUP,     /* 9.9.3.20A MS network feature support, See subclause 10.5.1.15 in 3GPP TS 24.008. */
    DE_EMM_NAS_KEY_SET_ID,      /* 9.9.3.21 NAS key set identifier (coded inline)*/
    DE_EMM_NAS_MSG_CONT,        /* 9.9.3.22 NAS message container */
    DE_EMM_NAS_SEC_ALGS,        /* 9.9.3.23 NAS security algorithms */
    DE_EMM_NET_NAME,            /* 9.9.3.24 Network name, See subclause 10.5.3.5a in 3GPP TS 24.008 [6]. */
    DE_EMM_NONCE,               /* 9.9.3.25 Nonce */
    DE_EMM_PAGING_ID,           /* 9.9.3.25A Paging identity */
    DE_EMM_P_TMSI_SIGN,         /* 9.9.3.26 P-TMSI signature, See subclause 10.5.5.8 in 3GPP TS 24.008 [6]. */
    DE_EMM_EXT_CAUSE,           /* 9.9.3.26A Extended EMM cause */
    DE_EMM_SERV_TYPE,           /* 9.9.3.27 Service type */
    DE_EMM_SHORT_MAC,           /* 9.9.3.28 Short MAC */
    DE_EMM_TZ,                  /* 9.9.3.29 Time zone, See subclause 10.5.3.8 in 3GPP TS 24.008 [6]. */
    DE_EMM_TZ_AND_T,            /* 9.9.3.30 Time zone and time, See subclause 10.5.3.9 in 3GPP TS 24.008 [6]. */
    DE_EMM_TMSI_STAT,           /* 9.9.3.31 TMSI status, See subclause 10.5.5.4 in 3GPP TS 24.008 [6]. */
    DE_EMM_TRAC_AREA_ID,        /* 9.9.3.32 Tracking area identity */
    DE_EMM_TRAC_AREA_ID_LST,    /* 9.9.3.33 Tracking area identity list */
    DE_EMM_UE_NET_CAP,          /* 9.9.3.34 UE network capability */
    DE_EMM_UE_RA_CAP_INF_UPD_NEED,  /* 9.9.3.35 UE radio capability information update needed */
    DE_EMM_UE_SEC_CAP,          /* 9.9.3.36 UE security capability */
    DE_EMM_EMERG_NUM_LST,       /* 9.9.3.37 Emergency Number List */
    DE_EMM_CLI,                 /* 9.9.3.38 CLI */
    DE_EMM_SS_CODE,             /* 9.9.3.39 SS Code */
    DE_EMM_LCS_IND,             /* 9.9.3.40 LCS indicator */
    DE_EMM_LCS_CLIENT_ID,       /* 9.9.3.41 LCS client identity */
    DE_EMM_GEN_MSG_CONT_TYPE,   /* 9.9.3.42 Generic message container type */
    DE_EMM_GEN_MSG_CONT,        /* 9.9.3.43 Generic message container */
    DE_EMM_VOICE_DMN_PREF,      /* 9.9.3.44 Voice domain preference and UEs usage setting */
    DE_EMM_GUTI_TYPE,           /* 9.9.3.45 GUTI type */
    DE_EMM_EXT_DRX_PARAMS,      /* 9.9.3.46 Extended DRX parameters */
    DE_EMM_DATA_SERV_TYPE,      /* 9.9.3.47 Data service type */
    DE_EMM_NONE                 /* NONE */
}
nas_emm_elem_idx_t;
#endif

/* TODO: Update to latest spec */
/* 9.9.3    EPS Mobility Management (EMM) information elements
 */
/*
 * 9.9.3.0A  Additional update result
 */
static const true_false_string nas_eps_emm_anb_up_ciot_value = {
    "User plane EPS optimization accepted",
    "User plane EPS optimization not accepted"
};
static const true_false_string nas_eps_emm_anb_cp_ciot_value = {
    "Control plane CIoT EPS optimization accepted",
    "Control plane CIoT EPS optimization not accepted"
};
static const value_string nas_eps_emm_add_upd_res_vals[] = {
    { 0x0, "No additional information"},
    { 0x1, "CS Fallback not preferred"},
    { 0x2, "SMS only"},
    { 0x3, "Reserved"},
    { 0, NULL }
};
static guint16
de_emm_add_upd_res(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                   guint32 offset, guint len _U_,
                   gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset, bit_offset;

    curr_offset = offset;
    bit_offset  = (curr_offset<<3)+4;

    proto_tree_add_bits_item(tree, hf_nas_eps_emm_anb_up_ciot, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset ++;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_anb_cp_ciot, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset ++;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_add_upd_res, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
    curr_offset++;

    return (curr_offset - offset);
}
/*
 * 9.9.3.0B  Additional update type
 */
static const value_string nas_eps_emm_pnb_ciot_vals[] = {
    { 0x0, "No additional information"},
    { 0x1, "Control-plane CIoT EPS optimization"},
    { 0x2, "User-plane CIoT EPS optimization"},
    { 0x3, "Reserved"},
    { 0, NULL }
};
static const true_false_string nas_eps_emm_saf_value = {
    "Keeping the NAS signalling connection is required after the completion of the"
        "tracking area updating procedure",
    "Keeping the NAS signalling connection is not required after the completion of the"
        "tracking area updating procedure"
};
static const true_false_string nas_eps_emm_add_upd_type_value = {
    "SMS only",
    "No additional information (shall be interpreted as request for"
        " combined attach or combined tracking area updating)"
};
static guint16
de_emm_add_upd_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                    guint32 offset, guint len _U_,
                    gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset, bit_offset;

    curr_offset = offset;
    bit_offset  = (curr_offset<<3)+4;

    proto_tree_add_bits_item(tree, hf_nas_eps_emm_pnb_ciot, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
    bit_offset += 2;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_saf, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset += 1;
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
de_emm_auth_resp_par(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                     guint32 offset, guint len _U_,
                     gchar *add_string _U_, int string_len _U_)
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
de_emm_csfb_resp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                 guint32 offset, guint len _U_,
                 gchar *add_string _U_, int string_len _U_)
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
static const value_string nas_eps_emm_type_of_detach_UL_vals[] = {
    { 0x1,  "EPS detach"},
    { 0x2,  "IMSI detach"},
    { 0x3,  "Combined EPS/IMSI detach"},
    { 0x4,  "Combined EPS/IMSI detach"}, /* All other values are interpreted as
                                             "combined EPS/IMSI detach" in this version of the protocol.*/
    { 0x5,  "Combined EPS/IMSI detach"}, /* -"- */
    { 0x6,  "Reserved"},
    { 0x7,  "Reserved"},
    { 0, NULL }
};

/*
 * In the network to UE direction:
 */

static const value_string nas_eps_emm_type_of_detach_DL_vals[] = {
    { 0x1,  "Re-attach required"},
    { 0x2,  "Re-attach not required"},
    { 0x3,  "IMSI detach"},
    { 0x4,  "Re-attach not required"}, /* All other values are interpreted as
                                           "re-attach not required" in this version of the protocol.*/
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
const value_string nas_eps_emm_cause_values[] = {
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
    { 0x23, "Requested service option not authorized in this PLMN"},
    { 0x27, "CS service temporarily not available"},
    { 0x28, "No EPS bearer context activated"},
    { 0x2a, "Severe network failure"},
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
value_string_ext nas_eps_emm_cause_values_ext = VALUE_STRING_EXT_INIT(nas_eps_emm_cause_values);

static guint16
de_emm_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
             guint32 offset, guint len _U_,
             gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    guint8 cause;

    curr_offset = offset;

    cause = tvb_get_guint8(tvb, curr_offset);
    proto_tree_add_item(tree, hf_nas_eps_emm_cause, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
                    val_to_str_ext_const(cause, &nas_eps_emm_cause_values_ext, "Unknown"));

    curr_offset++;

    return curr_offset-offset;
}

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

static true_false_string nas_eps_odd_even_value = {
    "Odd number of identity digits",
    "Even number of identity digits"
};
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
de_emm_eps_mid(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
               guint32 offset, guint len _U_,
               gchar *add_string _U_, int string_len _U_)
{
    guint32   curr_offset;
    guint8    octet;
    const char     *digit_str;
    tvbuff_t *new_tvb;

    curr_offset = offset;

    octet = tvb_get_guint8(tvb,offset);
    /* Type of identity (octet 3) */
    proto_tree_add_item(tree, hf_nas_eps_emm_odd_even, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_type_of_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    switch (octet&0x7) {
        case 1:
            /* IMSI */
            new_tvb = tvb_new_subset_length(tvb, curr_offset, len);
            dissect_e212_imsi(new_tvb, pinfo, tree,  0, len, TRUE);
            break;
        case 3:
            /* IMEI */
            new_tvb = tvb_new_subset_length(tvb, curr_offset, len);
            digit_str = tvb_bcd_dig_to_wmem_packet_str(new_tvb, 0, len, NULL, TRUE);
            proto_tree_add_string(tree, hf_nas_eps_emm_imei, new_tvb, 0, -1, digit_str);
            break;
        case 6:
            /* GUTI */
            curr_offset++;
            curr_offset = dissect_e212_mcc_mnc(tvb, pinfo, tree, curr_offset, E212_NONE, TRUE);
            /* MME Group ID octet 7 - 8 */
            proto_tree_add_item(tree, hf_nas_eps_emm_mme_grp_id, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
            curr_offset+=2;
            /* MME Code Octet 9 */
            proto_tree_add_item(tree, hf_nas_eps_emm_mme_code, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            curr_offset++;
            /* M-TMSI Octet 10 - 13 */
            proto_tree_add_item(tree, hf_nas_eps_emm_m_tmsi, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
            /*curr_offset+=4;*/
            break;
        default:
            proto_tree_add_expert(tree, pinfo, &ei_nas_eps_unknown_identity, tvb, curr_offset, len - 1);
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
static guint16
de_emm_eps_net_feature_sup(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                           guint32 offset, guint len _U_,
                           gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset, bit_offset;

    curr_offset = offset;
    bit_offset = curr_offset << 3;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_cp_ciot, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset += 1;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_er_wo_pdn, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset += 1;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_esr_ps, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset += 1;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_cs_lcs, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
    bit_offset += 2;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_epc_lcs, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset += 1;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_emc_bs, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset += 1;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_ims_vops, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset += 1;
    if (len >= 2) {
        proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
        bit_offset += 4;
        proto_tree_add_bits_item(tree, hf_nas_eps_emm_epco, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset += 1;
        proto_tree_add_bits_item(tree, hf_nas_eps_emm_hc_cp_ciot, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset += 1;
        proto_tree_add_bits_item(tree, hf_nas_eps_emm_s1_u_data, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset += 1;
        proto_tree_add_bits_item(tree, hf_nas_eps_emm_up_ciot, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    }

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
de_emm_esm_msg_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
                    guint32 offset, guint len,
                    gchar *add_string _U_, int string_len _U_)
{
    proto_item *item;
    proto_tree *sub_tree;
    tvbuff_t   *new_tvb;
    guint32     curr_offset;
    guint8      init_sec_hdr_type = tvb_get_bits8(tvb, 0, 4);

    curr_offset = offset;


    item = proto_tree_add_item(tree, hf_nas_eps_esm_msg_cont, tvb, curr_offset, len, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_nas_eps_esm_msg_cont);

    /* This IE can contain any ESM PDU as defined in subclause 8.3. */
    new_tvb = tvb_new_subset_length(tvb, curr_offset, len);
    if (init_sec_hdr_type == 5) {
        /* Integrity protected and partially ciphered NAS message */
        guint8 pd = tvb_get_guint8(new_tvb, 0);
        /* If pd is in plaintext this message probably isn't ciphered */
        if (((pd&0x0f) != 2) || (((pd&0x0f) == 2) && ((pd&0xf0) > 0) && ((pd&0xf0) < 0x50))) {
            proto_tree_add_item(sub_tree, hf_nas_eps_ciphered_msg, new_tvb, 0, len, ENC_NA);
        } else {
            TRY {
                /* Potential plain NAS message: let's try to decode it and catch exceptions */
                disect_nas_eps_esm_msg(new_tvb, pinfo, sub_tree, 0/* offset */);
            } CATCH_BOUNDS_ERRORS {
                /* Dissection exception: message was probably ciphered and heuristic was too weak */
                show_exception(new_tvb, pinfo, sub_tree, EXCEPT_CODE, GET_MESSAGE);
            } ENDTRY
        }
    } else {
        /* Plain NAS message */
        disect_nas_eps_esm_msg(new_tvb, pinfo, sub_tree, 0/* offset */);
    }

    return(len);
}
/*
 * 9.9.3.16 GPRS timer
 * See subclause 10.5.7.3 in 3GPP TS 24.008 [6].
 * packet-gsm_a_gm.c
 */
/*
 * 9.9.3.16A GPRS timer 2
 * See subclause 10.5.7.4 in 3GPP TS 24.008.
 * packet-gsm_a_gm.c
 */
/*
 * 9.9.3.16B GPRS timer 3
 * See subclause 10.5.7.4a in 3GPP TS 24.008.
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
de_emm_nas_imeisv_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                      guint32 offset, guint len _U_,
                      gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    int     bit_offset;

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
de_emm_nas_ksi_and_seq_no(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                          guint32 offset, guint len _U_,
                          gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    int     bit_offset;

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
 * packet-gsm_a_gm.c
 */
/*
 * 9.9.3.20A MS network feature support
 * See subclause 10.5.1.15 in 3GPP TS 24.008.
 * packet-gsm_a_gm.c
 */
/*
 * 9.9.3.21 NAS key set identifier
 */
/*
 * Type of security context flag (TSC) (octet 1)
 */
static const true_false_string nas_eps_tsc_value = {
    "Mapped security context (for KSIsgsn)",
    "Native security context (for KSIasme)"
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
    if (add_string) {
        proto_item_append_text(item, "%s", add_string);
    }
    /*bit_offset+=3;*/
}
/*
 * Note used for TV Short
 */
static guint16
de_emm_nas_key_set_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                      guint32 offset, guint len _U_,
                      gchar *add_string _U_, int string_len _U_)
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
    /*bit_offset+=3;*/
    curr_offset++;

    return(curr_offset - offset);
}

/*
 * 9.9.3.22 NAS message container
 */
static guint16
de_emm_nas_msg_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
                    guint32 offset, guint len _U_,
                    gchar *add_string _U_, int string_len _U_)
{
    proto_item *item;
    proto_tree *sub_tree;
    tvbuff_t   *new_tvb;
    guint32     curr_offset;

    curr_offset = offset;

    /* NAS message container contents (octet 3 to octet n)
     * This IE can contain an SMS message (i.e. CP-DATA, CP-ACK or CP-ERROR)
     * as defined in subclause 7.2 in 3GPP TS 24.011 [13A].
     */

    item = proto_tree_add_item(tree, hf_nas_eps_nas_msg_cont, tvb, curr_offset, len, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_nas_eps_nas_msg_cont);

    new_tvb = tvb_new_subset_length(tvb, curr_offset, len);
    if (gsm_a_dtap_handle)
        call_dissector(gsm_a_dtap_handle, new_tvb, pinfo, sub_tree);

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
    { 3,    "EPS integrity algorithm 128-EIA3"},
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
    { 3,    "EPS encryption algorithm 128-EEA3"},
    { 4,    "EPS encryption algorithm EEA4"},
    { 5,    "EPS encryption algorithm EEA5"},
    { 6,    "EPS encryption algorithm EEA6"},
    { 7,    "EPS encryption algorithm EEA7"},
    { 0, NULL }
};
static guint16
de_emm_nas_sec_alsgs(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                     guint32 offset, guint len _U_,
                     gchar *add_string _U_, int string_len _U_)
{
    int     bit_offset;
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
de_emm_nonce(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
             guint32 offset, guint len _U_,
             gchar *add_string _U_, int string_len _U_)
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
de_emm_paging_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                 guint32 offset, guint len _U_,
                 gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, curr_offset<<3, 7, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_paging_id, tvb, (curr_offset<<3)+7, 1, ENC_BIG_ENDIAN);
    /*curr_offset+=1;*/

    return(1);
}
/*
 * 9.9.3.26 P-TMSI signature
 * See subclause 10.5.5.8 in 3GPP TS 24.008 [6].
 */

 /*
 * 9.9.3.26A Extended EMM cause
 */
static const true_false_string nas_eps_ext_emm_cause = {
    "E-UTRAN not allowed",
    "E-UTRAN allowed"
};

static guint16
de_emm_ext_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                 guint32 offset, guint len _U_,
                 gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset, bit_offset;

    curr_offset = offset;
    bit_offset  = (curr_offset<<3)+4;

    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
    bit_offset += 3;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_ext_emm_cause, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    return (curr_offset - offset);
}

 /*
 * 9.9.3.27 Service type
 */
static const range_string nas_eps_service_type_vals[] = {
    { 0,  0, "Mobile originating CS fallback or 1xCS fallback"},
    { 1,  1, "Mobile terminating CS fallback or 1xCS fallback"},
    { 2,  2, "Mobile originating CS fallback emergency call or 1xCS fallback emergency call"},
    { 3,  4, "Mobile originating CS fallback or 1xCS fallback"},
    { 8, 11, "Packet services via S1"},
    { 0, 0, NULL }
};

/*
 * 9.9.3.28 Short MAC
 */
static guint16
de_emm_nas_short_mac(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                     guint32 offset, guint len _U_,
                     gchar *add_string _U_, int string_len _U_)
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
de_emm_trac_area_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
                    guint32 offset, guint len _U_,
                    gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    curr_offset = dissect_e212_mcc_mnc(tvb, pinfo, tree, curr_offset, E212_NONE, TRUE);
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
de_emm_trac_area_id_lst(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
                        guint32 offset, guint len _U_,
                        gchar *add_string _U_, int string_len _U_)
{
    proto_item *item;
    guint32 curr_offset;
    guint8 octet, tol, n_elem;
    int i;

    curr_offset = offset;

    while ((curr_offset - offset) < len) {
        proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, curr_offset<<3, 1, ENC_BIG_ENDIAN);
        /* Type of list (octet 1) Bits 7 6 */
        proto_tree_add_item(tree, hf_nas_eps_emm_tai_tol, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        /* Number of elements (octet 1) Bits 5 4 3 2 1 */
        octet = tvb_get_guint8(tvb,curr_offset)& 0x7f;
        tol = octet >> 5;
        n_elem = (octet & 0x1f)+1;
        item = proto_tree_add_item(tree, hf_nas_eps_emm_tai_n_elem, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        if (n_elem<16)
            proto_item_append_text(item, " [+1 = %u element(s)]", n_elem);

        curr_offset++;
        if (tol>2) {
            proto_tree_add_expert(tree, pinfo, &ei_nas_eps_unknown_type_of_list, tvb, curr_offset, len-(curr_offset-offset));
            return len;
        }

        switch (tol) {
            case 0:
                /* MCC digit 2 MCC digit 1 octet 2
                * MNC digit 3 MCC digit 3 octet 3
                * MNC digit 2 MNC digit 1 octet 4
                */
                curr_offset = dissect_e212_mcc_mnc(tvb, pinfo, tree, curr_offset, E212_NONE, TRUE);
                /* type of list = "000" */
                /* TAC 1             octet 5
                * TAC 1 (continued) octet 6
                * ...
                * ...
                * TAC k             octet 2k+3*
                * TAC k (continued) octet 2k+4*
                */
                if (len < (guint)(4+(n_elem*2))) {
                    proto_tree_add_expert(tree, pinfo, &ei_nas_eps_wrong_nb_of_elems, tvb, curr_offset, len-(curr_offset-offset));
                    return len;
                }
                for (i=0; i < n_elem; i++, curr_offset+=2)
                    proto_tree_add_item(tree, hf_nas_eps_emm_tai_tac, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
                break;
            case 1:
                /* type of list = "001" */
                /* MCC digit 2 MCC digit 1 octet 2
                * MNC digit 3 MCC digit 3 octet 3
                * MNC digit 2 MNC digit 1 octet 4
                */
                curr_offset = dissect_e212_mcc_mnc(tvb, pinfo, tree, curr_offset, E212_NONE, TRUE);
                proto_tree_add_item(tree, hf_nas_eps_emm_tai_tac, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
                curr_offset+=2;
                break;
            case 2:
                if (len< (guint)(1+(n_elem*5))) {
                    proto_tree_add_expert(tree, pinfo, &ei_nas_eps_wrong_nb_of_elems, tvb, curr_offset, len-(curr_offset-offset));
                    return len;
                }
                for (i=0; i < n_elem; i++) {
                    /* type of list = "010" */
                    /* MCC digit 2 MCC digit 1 octet 2
                    * MNC digit 3 MCC digit 3 octet 3
                    * MNC digit 2 MNC digit 1 octet 4
                    */
                    curr_offset = dissect_e212_mcc_mnc(tvb, pinfo, tree, curr_offset, E212_NONE, TRUE);
                    proto_tree_add_item(tree, hf_nas_eps_emm_tai_tac, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
                    curr_offset+=2;
                }
                break;
            default:
                /* Unknown ( Not in 3GPP TS 24.301 version 8.1.0 Release 8 ) */
                EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_nas_eps_extraneous_data);
                curr_offset = offset + len;
                break;
        }
    }

    return(curr_offset-offset);
}
/*
 * 9.9.3.34 UE network capability
 */

static const true_false_string  nas_eps_emm_ucs2_supp_flg_value = {
    "The UE has no preference between the use of the default alphabet and the use of UCS2",
    "The UE has a preference for the default alphabet"
};
guint16
de_emm_ue_net_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                  guint32 offset, guint len,
                  gchar *add_string _U_, int string_len _U_)
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
    /* EPS encryption algorithm EEA4 supported (octet 3, bit 4) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eea4, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS encryption algorithm EEA5 supported (octet 3, bit 3) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eea5, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS encryption algorithm EEA6 supported (octet 3, bit 2) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eea6, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS encryption algorithm EEA7 supported (octet 3, bit 1) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eea7, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;


    /* EPS integrity algorithms supported (octet 4) */
    /* EPS integrity algorithm EIA0 supported (octet 4, bit 8) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eia0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS integrity algorithm 128-EIA1 supported (octet 4, bit 7) */
    proto_tree_add_item(tree, hf_nas_eps_emm_128eia1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS integrity algorithm 128-EIA2 supported (octet 4, bit 6) */
    proto_tree_add_item(tree, hf_nas_eps_emm_128eia2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS integrity algorithm 128-EIA3 supported (octet 4, bit 5) */
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
    /* UMTS encryption algorithm 128-UEA1 supported (octet 5, bit 7) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uea1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS encryption algorithm 128-UEA2 supported (octet 5, bit 6) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uea2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS encryption algorithm 128-UEA3 supported (octet 5, bit 5) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uea3, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS encryption algorithm 128-UEA4 supported (octet 5, bit 4) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uea4, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS encryption algorithm 128-UEA5 supported (octet 5, bit 3) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uea5, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS encryption algorithm 128-UEA6 supported (octet 5, bit 2) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uea6, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS encryption algorithm 128-UEA7 supported (octet 5, bit 1) */
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

    if ((curr_offset - offset) >= len)
        return (len);

    /* ProSe-dd capability (octet 7, bit 8) */
    proto_tree_add_item(tree, hf_nas_eps_emm_prose_dd_cap, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* ProSe capability (octet 7, bit 7) */
    proto_tree_add_item(tree, hf_nas_eps_emm_prose_cap, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* H.245-ASH capability (octet 7, bit 6) */
    proto_tree_add_item(tree, hf_nas_eps_emm_h245_ash_cap, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* ACC-CSFB capability (octet 7, bit 5) */
    proto_tree_add_item(tree, hf_nas_eps_emm_acc_csfb_cap, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* LPP capability (octet 7, bit 4) */
    proto_tree_add_item(tree, hf_nas_eps_emm_lpp_cap, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* LCS capability (octet 7, bit 3) */
    proto_tree_add_item(tree, hf_nas_eps_emm_lcs_cap, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* 1xSRVCC capability (octet 7, bit 2) */
    proto_tree_add_item(tree, hf_nas_eps_emm_1xsrvcc_cap, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* NF capability (octet 7, bit 1) */
    proto_tree_add_item(tree, hf_nas_eps_emm_nf_cap, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    if ((curr_offset - offset) >= len)
        return (len);

    /* ePCO capability (octet 8, bit 8) */
    proto_tree_add_item(tree, hf_nas_eps_emm_epco_cap, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* HC-CP CIoT capability (octet 8, bit 7) */
    proto_tree_add_item(tree, hf_nas_eps_emm_hc_cp_ciot_cap, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* ERw/oPDN capability (octet 8, bit 6) */
    proto_tree_add_item(tree, hf_nas_eps_emm_er_wo_pdn_cap, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* S1-U data capability (octet 8, bit 5) */
    proto_tree_add_item(tree, hf_nas_eps_emm_s1u_data_cap, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UP CIoT capability (octet 8, bit 4) */
    proto_tree_add_item(tree, hf_nas_eps_emm_up_ciot_cap, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* CP CIoT capability (octet 8, bit 3) */
    proto_tree_add_item(tree, hf_nas_eps_emm_cp_ciot_cap, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* ProSe-relay capability (octet 8, bit 2) */
    proto_tree_add_item(tree, hf_nas_eps_emm_prose_relay_cap, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* ProSe-dc capability (octet 8, bit 1) */
    proto_tree_add_item(tree, hf_nas_eps_emm_prose_dc_cap, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    while ((curr_offset - offset) < len) {
        proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, (curr_offset<<3), 8, ENC_BIG_ENDIAN);
        curr_offset++;
    }

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
de_emm_ue_ra_cap_inf_upd_need(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                              guint32 offset, guint len _U_,
                              gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, (curr_offset<<3)+4, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_emm_ue_ra_cap_inf_upd_need_flg, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    return(len);
}
/*
 * 9.9.3.36 UE security capability
 */

static guint16
de_emm_ue_sec_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                  guint32 offset, guint len _U_,
                  gchar *add_string _U_, int string_len _U_)
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
    /* EPS encryption algorithm EEA4 supported (octet 3, bit 4) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eea4, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS encryption algorithm EEA5 supported (octet 3, bit 3) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eea5, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS encryption algorithm EEA6 supported (octet 3, bit 2) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eea6, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS encryption algorithm EEA7 supported (octet 3, bit 1) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eea7, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;


    /* EPS integrity algorithms supported (octet 4) */
    /* EPS integrity algorithm EIA0 supported (octet 4, bit 8) */
    proto_tree_add_item(tree, hf_nas_eps_emm_eia0, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS integrity algorithm 128-EIA1 supported (octet 4, bit 7) */
    proto_tree_add_item(tree, hf_nas_eps_emm_128eia1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS integrity algorithm 128-EIA2 supported (octet 4, bit 6) */
    proto_tree_add_item(tree, hf_nas_eps_emm_128eia2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* EPS integrity algorithm 128-EIA3 supported (octet 4, bit 5) */
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
    if (len == 2)
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
    /* UMTS encryption algorithm UEA4 supported (octet 5, bit 4) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uea4, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS encryption algorithm UEA5 supported (octet 5, bit 3) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uea5, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS encryption algorithm UEA6 supported (octet 5, bit 2) */
    proto_tree_add_item(tree, hf_nas_eps_emm_uea6, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UMTS encryption algorithm UEA7 supported (octet 5, bit 1) */
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

    if (len == 4)
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
de_emm_ss_code(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
               guint32 offset, guint len _U_,
               gchar *add_string _U_, int string_len _U_)
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
de_emm_lcs_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
               guint32 offset, guint len _U_,
               gchar *add_string _U_, int string_len _U_)
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
de_emm_lcs_client_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
                     guint32 offset, guint len _U_,
                     gchar *add_string _U_, int string_len _U_)
{
    guint32   curr_offset;
    tvbuff_t *new_tvb;

    curr_offset = offset;

    /* LCS client identity (value part)
     * The coding of the value part of the LCS client identity is given
     * in subclause 17.7.13 of 3GPP TS 29.002 [15B](GSM MAP).
     */
    new_tvb = tvb_new_subset_length(tvb, curr_offset, len);
    dissect_gsm_map_lcs_LCS_ClientID_PDU( new_tvb, pinfo, tree, NULL );

    return(len);
}

/*
 * 9.9.3.42 Generic message container type
 */
static const range_string nas_eps_emm_gen_msg_cont_type_vals[] = {
    {   0,   0, "Reserved"},
    {   1,   1, "LTE Positioning Protocol (LPP) message container"},
    {   2,   2, "Location services message container"},
    {   3, 127, "Unused"},
    { 128, 255, "Reserved"},
    { 0, 0, NULL }
};

static guint16
de_emm_gen_msg_cont_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                         guint32 offset, guint len _U_,
                         gchar *add_string _U_, int string_len _U_)
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
de_emm_gen_msg_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
                    guint32 offset, guint len,
                    gchar *add_string _U_, int string_len _U_)
{
    proto_item *item;
    proto_tree *sub_tree;
    tvbuff_t   *new_tvb;

    item = proto_tree_add_item(tree, hf_nas_eps_gen_msg_cont, tvb, offset, len, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_nas_eps_gen_msg_cont);

    new_tvb = tvb_new_subset_length(tvb, offset, len);

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
 * 9.9.3.45 GUTI type
 */
static const true_false_string nas_eps_emm_guti_type_value = {
    "Mapped GUTI",
    "Native GUTI"
};

static guint16
de_emm_guti_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                 guint32 offset, guint len _U_,
                 gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset, bit_offset;

    curr_offset = offset;
    bit_offset  = (curr_offset<<3)+4;

    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
    bit_offset += 3;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_guti_type, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    return (curr_offset - offset);
}

/*
 * 9.9.3.46 Extended DRX parameters
 * See subclause 10.5.5.32 in 3GPP TS 24.008
 */

/*
 * 9.9.3.47 Data service type
 * Coded inline 1/2 octet
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
de_esm_apn_aggr_max_br(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                       guint32 offset, guint len _U_,
                       gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    guint8  octet;
    guint32 dl_total = 0;
    guint32 ul_total = 0;
    guint32 bitrate  = 0;

    curr_offset = offset;
    /* APN-AMBR for downlink    octet 3 */
    octet = tvb_get_guint8(tvb,curr_offset);
    if (octet == 0) {
        proto_tree_add_uint_format(tree, hf_nas_eps_emm_apn_ambr_dl, tvb, curr_offset, 1, octet,
                       "Reserved");
    } else {
        bitrate = calc_bitrate(octet);
        dl_total = bitrate;
        proto_tree_add_uint_format_value(tree, hf_nas_eps_emm_apn_ambr_dl, tvb, curr_offset, 1, octet,
                       "%u kbps", bitrate);
    }
    curr_offset++;

    /* APN-AMBR for uplink  octet 4 */
    octet = tvb_get_guint8(tvb,curr_offset);
    if (octet == 0) {
        proto_tree_add_uint_format(tree, hf_nas_eps_emm_apn_ambr_ul, tvb, curr_offset, 1, octet,
                       "Reserved");
    } else {
        bitrate = calc_bitrate(octet);
        ul_total = bitrate;
        proto_tree_add_uint_format_value(tree, hf_nas_eps_emm_apn_ambr_ul, tvb, curr_offset, 1, octet,
                       "%u kbps", bitrate);
    }
    curr_offset++;
    if ((curr_offset - offset) >= len)
        return(len);
    /* APN-AMBR for downlink (extended) octet 5 */
    octet = tvb_get_guint8(tvb,curr_offset);
    if (octet == 0) {
        proto_tree_add_uint_format(tree, hf_nas_eps_emm_apn_ambr_dl_ext, tvb, curr_offset, 1, octet,
                       "Use the value indicated by the APN-AMBR for downlink");
    } else {
        bitrate = calc_bitrate_ext(octet);
        dl_total = (octet > 0x4a) ? bitrate*1000 : bitrate;
        proto_tree_add_uint_format_value(tree, hf_nas_eps_emm_apn_ambr_dl_ext, tvb, curr_offset, 1, octet,
                       "%u %s", bitrate, (octet > 0x4a) ? "Mbps" : "kbps");
    }
    if (len < 5) {
        /* APN-AMBR for downlink (extended-2) is not present; display total now */
        if (dl_total >= 1000) {
            proto_tree_add_uint_format_value(tree, hf_nas_eps_emm_apn_ambr_dl_total, tvb, curr_offset, 1, dl_total, "%.3f Mbps", (gfloat)dl_total / 1000);
        } else {
            proto_tree_add_uint_format_value(tree, hf_nas_eps_emm_apn_ambr_dl_total, tvb, curr_offset, 1, dl_total, "%u kbps", dl_total);
        }
    }
    curr_offset++;
    if ((curr_offset - offset) >= len)
        return(len);
    /* APN-AMBR for uplink (extended)   octet 6 */
    octet = tvb_get_guint8(tvb,curr_offset);
    if (octet == 0) {
        proto_tree_add_uint_format(tree, hf_nas_eps_emm_apn_ambr_ul_ext, tvb, curr_offset, 1, octet,
                       "Use the value indicated by the APN-AMBR for uplink");
    } else {
        bitrate = calc_bitrate_ext(octet);
        ul_total = (octet > 0x4a) ? bitrate*1000 : bitrate;
        proto_tree_add_uint_format_value(tree, hf_nas_eps_emm_apn_ambr_ul_ext, tvb, curr_offset, 1, octet,
                       "%u %s", bitrate, (octet > 0x4a) ? "Mbps" : "kbps");
    }
    if (len < 6) {
        /* APN-AMBR for uplink (extended-2) is not present; display total now */
        if (ul_total >= 1000) {
            proto_tree_add_uint_format_value(tree, hf_nas_eps_emm_apn_ambr_ul_total, tvb, curr_offset, 1, ul_total, "%.3f Mbps", (gfloat)ul_total / 1000);
        } else {
            proto_tree_add_uint_format_value(tree, hf_nas_eps_emm_apn_ambr_ul_total, tvb, curr_offset, 1, ul_total, "%u kbps", ul_total);
        }
    }
    curr_offset++;
    if ((curr_offset - offset) >= len)
        return(len);
    /* APN-AMBR for downlink (extended-2)   octet 7 */
    octet = tvb_get_guint8(tvb,curr_offset);
    if ((octet == 0)||(octet == 0xff)) {
        proto_tree_add_uint_format(tree, hf_nas_eps_emm_apn_ambr_dl_ext2, tvb, curr_offset, 1, octet,
                       "Use the value indicated by the APN-AMBR for downlink and APN-AMBR for downlink (extended)");
    } else {
        dl_total += octet*256*1000;
        proto_tree_add_uint_format_value(tree, hf_nas_eps_emm_apn_ambr_dl_ext2, tvb, curr_offset, 1, octet,
                       "%u Mbps", (octet* 256));
    }
    proto_tree_add_uint_format_value(tree, hf_nas_eps_emm_apn_ambr_dl_total, tvb, curr_offset, 1, dl_total, "%.3f Mbps", (gfloat)dl_total / 1000);
    curr_offset++;
    if ((curr_offset - offset) >= len)
        return(len);
    /* APN-AMBR for uplink (extended-2) octet 8 */
    octet = tvb_get_guint8(tvb,curr_offset);
    if ((octet == 0)||(octet == 0xff)) {
        proto_tree_add_uint_format(tree, hf_nas_eps_emm_apn_ambr_ul_ext2, tvb, curr_offset, 1, octet,
                       "Use the value indicated by the APN-AMBR for uplink and APN-AMBR for uplink (extended)");
    } else {
        ul_total += octet*256*1000;
        proto_tree_add_uint_format_value(tree, hf_nas_eps_emm_apn_ambr_ul_ext2, tvb, curr_offset, 1, octet,
                       "%u Mbps", (octet* 256));
    }
    proto_tree_add_uint_format_value(tree, hf_nas_eps_emm_apn_ambr_ul_total, tvb, curr_offset, 1, ul_total, "%.3f Mbps", (gfloat)ul_total / 1000);
    curr_offset++;

    return(len);
}
/*
 * 9.9.4.2A Connectivity type
 * See subclause 10.5.6.19 in 3GPP TS 24.008.
 * packet-gsm_a_gm.c
 */
/*
 * 9.9.4.3 EPS quality of service
 */

/* Quality of Service Class Identifier (QCI), octet 3 (see 3GPP TS 23.203 [7]) */
static const range_string nas_eps_qci_vals[] = {
    { 0x00, 0x00, "Reserved"},
    { 0x01, 0x01, "QCI 1"},
    { 0x02, 0x02, "QCI 2"},
    { 0x03, 0x03, "QCI 3"},
    { 0x04, 0x04, "QCI 4"},
    { 0x05, 0x05, "QCI 5"},
    { 0x06, 0x06, "QCI 6"},
    { 0x07, 0x07, "QCI 7"},
    { 0x08, 0x08, "QCI 8"},
    { 0x09, 0x09, "QCI 9"},
    { 0x0A, 0x40, "Spare"},
    { 0x41, 0x41, "QCI 65"},
    { 0x42, 0x42, "QCI 66"},
    { 0x43, 0x44, "Spare"},
    { 0x45, 0x45, "QCI 69"},
    { 0x46, 0x46, "QCI 70"},
    { 0x47, 0x7F, "Spare"},
    { 0x80, 0xFE, "Operator-specific QCI"},
    { 0xFF, 0xFF, "Reserved"},
    { 0,    0,    NULL }
};



guint16
de_esm_qos(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
           guint32 offset, guint len,
           gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    guint8  octet;

    curr_offset = offset;

    /* QCI octet 3 */
    proto_tree_add_item(tree, hf_nas_eps_qci, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;
    if ((curr_offset - offset) >= len)
        return(len);
    /* Maximum bit rate for uplink octet 4 */
    octet = tvb_get_guint8(tvb,curr_offset);
    if (octet == 0) {
        proto_tree_add_uint_format(tree, hf_nas_eps_mbr_ul, tvb, curr_offset, 1, octet,
                       "UE->NW Subscribed maximum bit rate for uplink/ NW->UE Reserved");
    } else {
        proto_tree_add_uint_format_value(tree, hf_nas_eps_mbr_ul, tvb, curr_offset, 1, octet,
                       "%u kbps", calc_bitrate(octet));
    }
    curr_offset++;
    if ((curr_offset - offset) >= len)
        return(len);
    /* Maximum bit rate for downlink octet 5 */
    octet = tvb_get_guint8(tvb,curr_offset);
    if (octet == 0) {
        proto_tree_add_uint_format(tree, hf_nas_eps_mbr_dl, tvb, curr_offset, 1, octet,
                       "UE->NW Subscribed maximum bit rate for downlink/ NW->UE Reserved");
    } else {
        proto_tree_add_uint_format_value(tree, hf_nas_eps_mbr_dl, tvb, curr_offset, 1, octet,
                       "%u kbps", calc_bitrate(octet));
    }
    curr_offset++;
    if ((curr_offset - offset) >= len)
        return(len);
    /* Guaranteed bit rate for uplink octet 6 */
    octet = tvb_get_guint8(tvb,curr_offset);
    proto_tree_add_uint_format_value(tree, hf_nas_eps_gbr_ul, tvb, curr_offset, 1, octet,
                   "%u kbps", calc_bitrate(octet));

    curr_offset++;
    if ((curr_offset - offset) >= len)
        return(len);
    /* Guaranteed bit rate for downlink octet 7 */
    octet = tvb_get_guint8(tvb,curr_offset);
    proto_tree_add_uint_format_value(tree, hf_nas_eps_gbr_dl, tvb, curr_offset, 1, octet,
                   "%u kbps", calc_bitrate(octet));

    curr_offset++;
    if ((curr_offset - offset) >= len)
        return(len);
    /* Maximum bit rate for uplink (extended) octet 8 */
    octet = tvb_get_guint8(tvb,curr_offset);
    if (octet == 0) {
        proto_tree_add_uint_format(tree, hf_nas_eps_embr_ul, tvb, curr_offset, 1, octet,
                       "Use the value indicated by the maximum bit rate for uplink in octet 4");
    } else {
        proto_tree_add_uint_format(tree, hf_nas_eps_embr_ul, tvb, curr_offset, 1, octet,
                       "Maximum bit rate for uplink (extended) : %u %s",
                       calc_bitrate_ext(octet),
                       (octet > 0x4a) ? "Mbps" : "kbps");
    }
    curr_offset++;
    if ((curr_offset - offset) >= len)
        return(len);
    /* Maximum bit rate for downlink (extended) octet 9 */
    octet = tvb_get_guint8(tvb,curr_offset);
    if (octet == 0) {
        proto_tree_add_uint_format(tree, hf_nas_eps_embr_dl, tvb, curr_offset, 1, octet,
                       "Use the value indicated by the maximum bit rate for downlink in octet 5");
    } else {
        proto_tree_add_uint_format(tree, hf_nas_eps_embr_dl, tvb, curr_offset, 1, octet,
                       "Maximum bit rate for downlink (extended) : %u %s",
                       calc_bitrate_ext(octet),
                       (octet > 0x4a) ? "Mbps" : "kbps");
    }
    curr_offset++;
    if ((curr_offset - offset) >= len)
        return(len);
    /* Guaranteed bit rate for uplink (extended) octet 10 */
    octet = tvb_get_guint8(tvb,curr_offset);
    if (octet == 0) {
        proto_tree_add_uint_format(tree, hf_nas_eps_egbr_ul, tvb, curr_offset, 1, octet,
                       "Use the value indicated by the guaranteed bit rate for uplink in octet 6");
    } else {
        proto_tree_add_uint_format(tree, hf_nas_eps_egbr_ul, tvb, curr_offset, 1, octet,
                       "Guaranteed bit rate for uplink (extended) : %u %s",
                       calc_bitrate_ext(octet),
                       (octet > 0x4a) ? "Mbps" : "kbps");
    }
    curr_offset++;
    if ((curr_offset - offset) >= len)
        return(len);
    /* Guaranteed bit rate for downlink (extended) octet 11 */
    octet = tvb_get_guint8(tvb,curr_offset);
    if (octet == 0) {
        proto_tree_add_uint_format(tree, hf_nas_eps_egbr_dl, tvb, curr_offset, 1, octet,
                       "Use the value indicated by the guaranteed bit rate for downlink in octet 7");
    } else {
        proto_tree_add_uint_format(tree, hf_nas_eps_egbr_dl, tvb, curr_offset, 1, octet,
                       "Guaranteed bit rate for downlink (extended) : %u %s",
                       calc_bitrate_ext(octet),
                       (octet > 0x4a) ? "Mbps" : "kbps");
    }
    curr_offset++;
    if ((curr_offset - offset) >= len)
        return(len);
    /* Maximum bit rate for uplink (extended-2) octet 12 */
    octet = tvb_get_guint8(tvb,curr_offset);
    if (octet == 0) {
        proto_tree_add_uint_format(tree, hf_nas_eps_embr_ul, tvb, curr_offset, 1, octet,
                       "Use the value indicated by the maximum bit rate for uplink in octet 4 and octet 8");
    } else {
        proto_tree_add_uint_format(tree, hf_nas_eps_embr_ul, tvb, curr_offset, 1, octet,
                       "Maximum bit rate for uplink (extended-2) : %u Mbps",
                       calc_bitrate_ext2(octet));
    }
    curr_offset++;
    /* Maximum bit rate for downlink (extended-2) octet 13 */
    octet = tvb_get_guint8(tvb,curr_offset);
    if (octet == 0) {
        proto_tree_add_uint_format(tree, hf_nas_eps_embr_dl, tvb, curr_offset, 1, octet,
                       "Use the value indicated by the maximum bit rate for downlink in octet 5 and octet 9");
    } else {
        proto_tree_add_uint_format(tree, hf_nas_eps_embr_dl, tvb, curr_offset, 1, octet,
                       "Maximum bit rate for downlink (extended-2) : %u Mbps",
                       calc_bitrate_ext2(octet));
    }
    curr_offset++;
    /* Guaranteed bit rate for uplink (extended-2) octet 14 */
    octet = tvb_get_guint8(tvb,curr_offset);
    if (octet == 0) {
        proto_tree_add_uint_format(tree, hf_nas_eps_egbr_ul, tvb, curr_offset, 1, octet,
                       "Use the value indicated by the guaranteed bit rate for uplink in octet 6 and octet 10");
    } else {
        proto_tree_add_uint_format(tree, hf_nas_eps_egbr_ul, tvb, curr_offset, 1, octet,
                       "Guaranteed bit rate for uplink (extended-2) : %u Mbps",
                       calc_bitrate_ext2(octet));
    }
    curr_offset++;
    /* Guaranteed bit rate for downlink (extended-2) octet 15 */
    octet = tvb_get_guint8(tvb,curr_offset);
    if (octet == 0) {
        proto_tree_add_uint_format(tree, hf_nas_eps_egbr_dl, tvb, curr_offset, 1, octet,
                       "Use the value indicated by the guaranteed bit rate for downlink in octet 7 and octet 11");
    } else {
        proto_tree_add_uint_format(tree, hf_nas_eps_egbr_dl, tvb, curr_offset, 1, octet,
                       "Guaranteed bit rate for downlink (extended-2) : %u Mbps",
                       calc_bitrate_ext2(octet));
    }

    return(len);
}
/*
 * 9.9.4.4 ESM cause
 */

static const value_string nas_eps_esm_cause_vals[] = {
    { 0x08, "Operator Determined Barring"},
    { 0x1a, "Insufficient resources"},
    { 0x1b, "Missing or unknown APN"},
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
    { 0x2e, "Unused"},
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
    { 0x3c, "Bearer handling not supported"},
    { 0x41, "Maximum number of EPS bearers reached"},
    { 0x42, "Requested APN not supported in current RAT and PLMN combination"},
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
    { 0x71, "Multiple accesses to a PDN connection not allowed"},
    { 0, NULL }
};
static value_string_ext nas_eps_esm_cause_vals_ext = VALUE_STRING_EXT_INIT(nas_eps_esm_cause_vals);

static guint16
de_esm_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
             guint32 offset, guint len _U_,
             gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    guint8 cause;

    curr_offset = offset;

    cause = tvb_get_guint8(tvb, curr_offset);
    proto_tree_add_item(tree, hf_nas_eps_esm_cause, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
                    val_to_str_ext_const(cause, &nas_eps_esm_cause_vals_ext, "Unknown"));

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
de_esm_inf_trf_flg(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                   guint32 offset, guint len _U_,
                   gchar *add_string _U_, int string_len _U_)
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
de_esm_notif_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                 guint32 offset, guint len _U_,
                 gchar *add_string _U_, int string_len _U_)
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
de_esm_pdn_addr(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                guint32 offset, guint len _U_,
                gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    guint8  pdn_type;

    curr_offset = offset;


    pdn_type  = tvb_get_guint8(tvb, offset) & 0x7;
    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, curr_offset<<3, 5, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_esm_pdn_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    switch (pdn_type) {
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
    { 0x5,  "Non IP" },
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
 * 9.9.4.13a Re-attempt indicator
 */
const true_false_string nas_eps_esm_eplmnc_value = {
    "UE is not allowed to re-attempt the procedure in an equivalent PLMN",
    "UE is allowed to re-attempt the procedure in an equivalent PLMN"
};

const true_false_string nas_eps_esm_ratc_value = {
    "UE is not allowed to re-attempt the procedure in A/Gb mode or Iu mode",
    "UE is allowed to re-attempt the procedure in A/Gb mode or Iu mode"
};

static guint16
de_esm_re_attempt_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset,
                       guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, offset << 3, 6, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_esm_eplmnc, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_eps_esm_ratc, tvb, offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_nas_eps_extraneous_data);

    return len;
}

/*
 * 9.9.4.14 Request type
 * See subclause 10.5.6.17 in 3GPP TS 24.008
 */
static const value_string nas_eps_esm_request_type_values[] = {
    { 0x1,      "Initial request" },
    { 0x2,      "Handover" },
    { 0x3,      "Unused; shall be interpreted as initial request if received by the network" },
    { 0x4,      "Emergency" },
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
/*
 * 9.9.4.18 WLAN offload acceptability
 * See subclause 10.5.6.20 in 3GPP TS 24.008
 * packet-gsm_a_gm.c
 */
/*
 * 9.9.4.19 NBIFOM container
 */
static guint16
de_esm_nbifom_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    if (nbifom_handle) {
        tvbuff_t *nbifom_tvb = tvb_new_subset_length(tvb, offset, len);

        call_dissector(nbifom_handle, nbifom_tvb, pinfo, tree);
    } else {
        proto_tree_add_item(tree, hf_nas_eps_esm_nbifom_cont, tvb, offset, len, ENC_NA);
    }

    return len;
}

/*
 * 9.9.4.20 Remote UE context list
 */
static const value_string nas_eps_esm_user_info_type_values[] = {
    { 0x1, "Encrypted IMSI" },
    { 0x2, "IMSI" },
    { 0x3, "MSISDN" },
    { 0x4, "IMEI" },
    { 0x5, "IMEISV" },
    { 0, NULL }
 };
static const value_string nas_eps_esm_address_type_values[] = {
    { 0x0, "No IP Info" },
    { 0x1, "IPv4" },
    { 0x2, "IPv6" },
    { 0, NULL }
 };
static guint16
de_esm_remote_ue_context_list(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
                              guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset = offset;
    guint32 nb_ue_contexts, ue_context_len, nb_user_id, user_id_len, user_id_type, remote_address_type, i, j;
    proto_tree *subtree;
    proto_item *subtree_item;

    proto_tree_add_item_ret_uint(tree, hf_nas_eps_esm_remote_ue_context_list_nb_ue_contexts, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &nb_ue_contexts);
    curr_offset ++;
    for (i = 1; i <= nb_ue_contexts; i++) {
        subtree = proto_tree_add_subtree_format(tree, tvb, curr_offset, len - (curr_offset - offset), ett_nas_eps_remote_ue_context,
                                                &subtree_item, "Remote UE context %u", i);
        proto_tree_add_item_ret_uint(subtree, hf_nas_eps_esm_remote_ue_context_list_ue_context_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &ue_context_len);
        proto_item_set_len(subtree_item, ue_context_len+1);
        curr_offset ++;
        proto_tree_add_item_ret_uint(subtree, hf_nas_eps_esm_remote_ue_context_list_ue_context_nb_user_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &nb_user_id);
        curr_offset ++;
        for (j = 0; j < nb_user_id; j++) {
            proto_tree_add_item_ret_uint(subtree, hf_nas_eps_esm_remote_ue_context_list_ue_context_user_id_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &user_id_len);
            curr_offset ++;
            proto_tree_add_item(subtree, hf_nas_eps_esm_remote_ue_context_list_ue_context_odd_even_indic, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item_ret_uint(subtree, hf_nas_eps_esm_remote_ue_context_list_ue_context_user_id_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &user_id_type);
            switch (user_id_type & 0x07) {
                case 1:
                    proto_tree_add_bits_item(subtree, hf_nas_eps_spare_bits, tvb, curr_offset<<3, 4, ENC_BIG_ENDIAN);
                    curr_offset++;
                    proto_tree_add_item(subtree, hf_nas_eps_esm_remote_ue_context_list_ue_context_encr_imsi, tvb, curr_offset, 16, ENC_NA);
                    curr_offset += 16;
                    break;
                case 2:
                    dissect_e212_imsi(tvb, pinfo, subtree, curr_offset, user_id_len, TRUE);
                    curr_offset += user_id_len;
                    break;
                case 3:
                    {
                        const gchar *msisdn_str = tvb_bcd_dig_to_wmem_packet_str(tvb, curr_offset, user_id_len, NULL, TRUE);
                        proto_tree_add_string(subtree, hf_nas_eps_esm_remote_ue_context_list_ue_context_msisdn, tvb, curr_offset, user_id_len, msisdn_str);
                        curr_offset += user_id_len;
                    }
                    break;
                case 4:
                    {
                        const gchar *imei_str = tvb_bcd_dig_to_wmem_packet_str(tvb, curr_offset, user_id_len, NULL, TRUE);
                        proto_tree_add_string(subtree, hf_nas_eps_esm_remote_ue_context_list_ue_context_imei, tvb, curr_offset, user_id_len, imei_str);
                        curr_offset += user_id_len;
                    }
                    break;
                case 5:
                    {
                        const gchar *imeisv_str = tvb_bcd_dig_to_wmem_packet_str(tvb, curr_offset, user_id_len, NULL, TRUE);
                        proto_tree_add_string(subtree, hf_nas_eps_esm_remote_ue_context_list_ue_context_imeisv, tvb, curr_offset, user_id_len, imeisv_str);
                        curr_offset += user_id_len;
                    }
                    break;
                default:
                    curr_offset += user_id_len;
                    break;
            }
        }
        proto_tree_add_bits_item(subtree, hf_nas_eps_spare_bits, tvb, curr_offset<<3, 5, ENC_BIG_ENDIAN);
        proto_tree_add_item_ret_uint(subtree, hf_nas_eps_esm_remote_ue_context_list_ue_context_address_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &remote_address_type);
        curr_offset++;
        switch (remote_address_type & 0x07) {
            case 1:
                proto_tree_add_item(subtree, hf_nas_eps_esm_remote_ue_context_list_ue_context_ipv4, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
                curr_offset += 4;
                proto_tree_add_item(subtree, hf_nas_eps_esm_remote_ue_context_list_ue_context_port_number, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
                curr_offset += 2;
                break;
            case 2:
                proto_tree_add_item(subtree, hf_nas_eps_esm_remote_ue_context_list_ue_context_ipv6_prefix, tvb, curr_offset, 8, ENC_NA);
                curr_offset += 8;
                break;
            case 0:
            default:
                break;
        }
    }

    return len;
}

/*
 * 9.9.4.21 PKMF address
 */
static const value_string nas_eps_esm_pkmf_address_type_values[] = {
    { 0x1, "IPv4" },
    { 0x2, "IPv6" },
    { 0, NULL }
 };
static guint16
de_esm_pkmf_address(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                    guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset = offset;
    guint32 pkmf_address_type;

    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, curr_offset<<3, 5, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(tree, hf_nas_eps_esm_pkmf_address_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &pkmf_address_type);
    curr_offset++;
    switch (pkmf_address_type & 0x07) {
        case 1:
            proto_tree_add_item(tree, hf_nas_eps_esm_pkmf_ipv4, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
            break;
        case 2:
            proto_tree_add_item(tree, hf_nas_eps_esm_pkmf_ipv6, tvb, curr_offset, 16, ENC_NA);
            break;
        default:
            break;
    }

    return len;
}

/*
 * 9.9.4.22 Header compression configuration
 */
static guint16
de_esm_hdr_compr_config(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                        guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset = offset;

    static const int * flags[] = {
        &hf_nas_eps_esm_spare_bit0x80,
        &hf_nas_eps_esm_hdr_comp_config_prof_0104,
        &hf_nas_eps_esm_hdr_comp_config_prof_0103,
        &hf_nas_eps_esm_hdr_comp_config_prof_0102,
        &hf_nas_eps_esm_hdr_comp_config_prof_0006,
        &hf_nas_eps_esm_hdr_comp_config_prof_0004,
        &hf_nas_eps_esm_hdr_comp_config_prof_0003,
        &hf_nas_eps_esm_hdr_comp_config_prof_0002,
        NULL
    };
    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, flags, ENC_NA);
    curr_offset++;
    proto_tree_add_item(tree, hf_nas_eps_esm_hdr_compr_config_max_cid, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

    return len;
}

/*
 * 9.9.4.23 Control plane only indication
 */
static true_false_string nas_eps_ctrl_plane_only_ind_cpoi_value = {
    "PDN connection can be used for control plane CIoT EPS optimization only",
    "PDN connection can be used with user plane radio bearer(s)"
};
static guint16
de_esm_ctrl_plane_only_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                           guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, (offset<<3)+4, 3, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(tree, hf_nas_eps_esm_ctrl_plane_only_ind_cpoi, tvb, (offset<<3)+7, 1, ENC_BIG_ENDIAN);

    return 1;
}

/*
 * 9.9.4.24 User data container
 */
static guint16
de_esm_user_data_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                      guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_item(tree, hf_nas_eps_esm_user_data_cont, tvb, offset, len, ENC_NA);

    return len;
}

/*
 * 9.9.4.25 Release assistance indication
 */
static const value_string nas_eps_esm_rel_assist_ind_ddx_vals[] = {
    { 0x00, "No information available" },
    { 0x01, "Downlink data transmission subsequent to the uplink data transmission is not expected" },
    { 0x02, "Downlink data transmission subsequent to the uplink data transmission is expected" },
    { 0x03, "Reserved" },
    { 0, NULL}
};
static guint16
de_esm_rel_assist_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                      guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, (offset<<3)+4, 2, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(tree, hf_nas_eps_esm_rel_assist_ind_ddx, tvb, (offset<<3)+6, 2, ENC_BIG_ENDIAN);

    return 1;
}

/*
 * 9.9.4.26 Extended protocol configuration options
 */
static guint16
de_esm_ext_pco(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
               guint32 offset, guint len, gchar *add_string, int string_len)
{
    return de_sm_pco(tvb, tree, pinfo, offset, len, add_string, string_len);
}

/*
 * 9.9.4.27 Header compression configuration status
 */
static true_false_string nas_eps_esm_hdr_compr_config_status_ebi_value = {
    "Header compression configuration is not used",
    "Header compression configuration is used"
};
static guint16
de_esm_hdr_compr_config_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                               guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    static const int * flags[] = {
        &hf_nas_eps_esm_hdr_compr_config_status_ebi7,
        &hf_nas_eps_esm_hdr_compr_config_status_ebi6,
        &hf_nas_eps_esm_hdr_compr_config_status_ebi5,
        &hf_nas_eps_esm_spare_bits0x1f00,
        &hf_nas_eps_esm_hdr_compr_config_status_ebi15,
        &hf_nas_eps_esm_hdr_compr_config_status_ebi14,
        &hf_nas_eps_esm_hdr_compr_config_status_ebi13,
        &hf_nas_eps_esm_hdr_compr_config_status_ebi12,
        &hf_nas_eps_esm_hdr_compr_config_status_ebi11,
        &hf_nas_eps_esm_hdr_compr_config_status_ebi10,
        &hf_nas_eps_esm_hdr_compr_config_status_ebi9,
        &hf_nas_eps_esm_hdr_compr_config_status_ebi8,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 2, flags, ENC_BIG_ENDIAN);

    return len;
}

/*
 * 9.9.4.28 Serving PLMN rate control
 */
static guint16
de_esm_serv_plmn_rate_ctrl(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
                           guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    proto_item *pi;

    pi = proto_tree_add_item(tree, hf_nas_eps_esm_serv_plmn_rate_ctrl_val, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_item_append_text(pi, " message(s)");

    return len;
}

guint16 (*emm_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string, int string_len) = {
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
    NULL,                       /* 9.9.3.16A GPRS timer 2, See subclause 10.5.7.4 in 3GPP TS 24.008. (packet-gsm_a_gm.c)*/
    NULL,                       /* 9.9.3.16B GPRS timer 3, See subclause 10.5.7.4a in 3GPP TS 24.008. (packet-gsm_a_gm.c)*/
    NULL,                       /* 9.9.3.17 Identity type 2 ,See subclause 10.5.5.9 in 3GPP TS 24.008 [6]. */
    de_emm_nas_imeisv_req,      /* 9.9.3.18 IMEISV request ,See subclause 10.5.5.10 in 3GPP TS 24.008 [6]. */
    de_emm_nas_ksi_and_seq_no,  /* 9.9.3.19 KSI and sequence number */
    NULL,                       /* 9.9.3.20 MS network capability ,See subclause 10.5.5.12 in 3GPP TS 24.008 [6].(packet-gsm_a_gm.c) */
    NULL,                       /* 9.9.3.20A MS network feature support, See subclause 10.5.1.15 in 3GPP TS 24.008.(packet-gsm_a_gm.c) */
    de_emm_nas_key_set_id,      /* 9.9.3.21 NAS key set identifier (Coded Inline) */
    de_emm_nas_msg_cont,        /* 9.9.3.22 NAS message container */
    de_emm_nas_sec_alsgs,       /* 9.9.3.23 NAS security algorithms */
    NULL,                       /* 9.9.3.24 Network name, See subclause 10.5.3.5a in 3GPP TS 24.008 [6]. (packet-gsm_a_dtap.c)*/
    de_emm_nonce,               /* 9.9.3.25 Nonce */
    de_emm_paging_id,           /* 9.9.3.25A Paging identity */
    NULL,                       /* 9.9.3.26 P-TMSI signature, See subclause 10.5.5.8 in 3GPP TS 24.008 [6]. (packet-gsm_a_gm.c)*/
    de_emm_ext_cause,           /* 9.9.3.26A Extended EMM cause */
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
    NULL,                       /* 9.9.3.37 Emergency Number List (packet-gsm_a_dtap.c) */
    NULL,                       /* 9.9.3.38 CLI */
    de_emm_ss_code,             /* 9.9.3.39 SS Code */
    de_emm_lcs_ind,             /* 9.9.3.40 LCS indicator */
    de_emm_lcs_client_id,       /* 9.9.3.41 LCS client identity */
    de_emm_gen_msg_cont_type,   /* 9.9.3.42 Generic message container type */
    de_emm_gen_msg_cont,        /* 9.9.3.43 Generic message container */
    NULL,                       /* 9.9.3.44 Voice domain preference and UE's usage setting */
    de_emm_guti_type,           /* 9.9.3.45 GUTI type */
    NULL,                       /* 9.9.3.46 Extended DRX parameters */
    NULL,                       /* 9.9.3.47 Data service type */
    NULL,   /* NONE */
};

/* 9.9.4 EPS Session Management (ESM) information elements */
typedef enum
{
    DE_ESM_APN,                     /* 9.9.4.1 Access point name */
    DE_ESM_APN_AGR_MAX_BR,          /* 9.9.4.2 APN aggregate maximum bit rate */
    DE_ESM_CONNECTIVITY_TYPE,       /* 9.9.4.2A Connectivity type */
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
    DE_ESM_RE_ATTEMPT_IND,          /* 9.9.4.13a Re-attempt indicator */
    DE_ESM_REQ_TYPE,                /* 9.9.4.14 Request type */
    DE_ESM_TRAF_FLOW_AGR_DESC,      /* 9.9.4.15 Traffic flow aggregate description */
    DE_ESM_TRAF_FLOW_TEMPL,         /* 9.9.4.16 Traffic flow template */
    DE_ESM_TID,                     /* 9.9.4.17 Transaction identifier */
    DE_ESM_WLAN_OFFLOAD_ACCEPT,     /* 9.9.4.18 WLAN offload acceptability */
    DE_ESM_NBIFOM_CONT,             /* 9.9.4.19 NBIFOM container */
    DE_ESM_REMOTE_UE_CONTEXT_LIST,  /* 9.9.4.20 Remote UE context list */
    DE_ESM_PKMF_ADDRESS,            /* 9.9.4.21 PKMF address */
    DE_ESM_HDR_COMPR_CONFIG,        /* 9.9.4.22 Header compression configuration */
    DE_ESM_CTRL_PLANE_ONLY_IND,     /* 9.9.4.23 Control plane only indication */
    DE_ESM_USER_DATA_CONT,          /* 9.9.4.24 User data container */
    DE_ESM_REL_ASSIST_IND,          /* 9.9.4.25 Release assistance indication */
    DE_ESM_EXT_PCO,                 /* 9.9.4.26 Extended protocol configuration options */
    DE_ESM_HDR_COMPR_CONFIG_STATUS, /* 9.9.4.27 Header compression configuration status */
    DE_ESM_SERV_PLMN_RATE_CTRL,     /* 9.9.4.28 Serving PLMN rate control */
    DE_ESM_NONE                     /* NONE */
}
nas_esm_elem_idx_t;

static const value_string nas_esm_elem_strings[] = {
    { DE_ESM_APN, "Access point name" },                                          /* 9.9.4.1 Access point name */
    { DE_ESM_APN_AGR_MAX_BR, "APN aggregate maximum bit rate" },                  /* 9.9.4.2 APN aggregate maximum bit rate */
    { DE_ESM_CONNECTIVITY_TYPE, "Connectivity type" },                            /* 9.9.4.2A Connectivity type */
    { DE_ESM_EPS_QOS, "EPS quality of service" },                                 /* 9.9.4.3 EPS quality of service */
    { DE_ESM_CAUSE, "ESM cause" },                                                /* 9.9.4.4 ESM cause */
    { DE_ESM_INF_TRF_FLG, "ESM information transfer flag" },                      /* 9.9.4.5 ESM information transfer flag */
    { DE_ESM_LNKED_EPS_B_ID, "Linked EPS bearer identity" },                      /* 9.9.4.6 Linked EPS bearer identity */
    { DE_ESM_LLC_SAPI, "LLC service access point identifier" },                   /* 9.9.4.7 LLC service access point identifier */
    { DE_ESM_NOTIF_IND, "Notification indicator" },                               /* 9.9.4.7a Notification indicator */
    { DE_ESM_P_FLW_ID, "Packet flow identifier" },                                /* 9.9.4.8 Packet flow identifier */
    { DE_ESM_PDN_ADDR, "PDN address" },                                           /* 9.9.4.9 PDN address */
    { DE_ESM_PDN_TYPE, "PDN type" },                                              /* 9.9.4.10 PDN type */
    { DE_ESM_PROT_CONF_OPT, "Protocol configuration options" },                   /* 9.9.4.11 Protocol configuration options */
    { DE_ESM_QOS, "Quality of service" },                                         /* 9.9.4.12 Quality of service */
    { DE_ESM_RA_PRI, "Radio priority" },                                          /* 9.9.4.13 Radio priority */
    { DE_ESM_RE_ATTEMPT_IND, "Re-attempt indicator" },                            /* 9.9.4.13a Re-attempt indicator */
    { DE_ESM_REQ_TYPE, "Request type" },                                          /* 9.9.4.14 Request type */
    { DE_ESM_TRAF_FLOW_AGR_DESC, "Traffic flow aggregate description" },          /* 9.9.4.15 Traffic flow aggregate description */
    { DE_ESM_TRAF_FLOW_TEMPL, "Traffic flow template" },                          /* 9.9.4.16 Traffic flow template */
    { DE_ESM_TID, "Transaction identifier" },                                     /* 9.9.4.17 Transaction identifier */
    { DE_ESM_WLAN_OFFLOAD_ACCEPT, "WLAN offload acceptability" },                 /* 9.9.4.18 WLAN offload acceptability */
    { DE_ESM_NBIFOM_CONT, "NBIFOM container" },                                   /* 9.9.4.19 NBIFOM container */
    { DE_ESM_REMOTE_UE_CONTEXT_LIST, "Remote UE context list" },                  /* 9.9.4.20 Remote UE context list */
    { DE_ESM_PKMF_ADDRESS, "PKMF address" },                                      /* 9.9.4.21 PKMF address */
    { DE_ESM_HDR_COMPR_CONFIG, "Header compression configuration" },              /* 9.9.4.22 Header compression configuration */
    { DE_ESM_CTRL_PLANE_ONLY_IND, "Control plane only indication" },              /* 9.9.4.23 Control plane only indication */
    { DE_ESM_USER_DATA_CONT, "User data container" },                             /* 9.9.4.24 User data container */
    { DE_ESM_REL_ASSIST_IND, "Release assistance indication" },                   /* 9.9.4.25 Release assistance indication */
    { DE_ESM_EXT_PCO, "Extended protocol configuration options" },                /* 9.9.4.26 Extended protocol configuration options */
    { DE_ESM_HDR_COMPR_CONFIG_STATUS, "Header compression configuration status" },/* 9.9.4.27 Header compression configuration status */
    { DE_ESM_SERV_PLMN_RATE_CTRL, "Serving PLMN rate control" },                  /* 9.9.4.28 Serving PLMN rate control */
    { 0, NULL }
};
value_string_ext nas_esm_elem_strings_ext = VALUE_STRING_EXT_INIT(nas_esm_elem_strings);

#define NUM_NAS_ESM_ELEM (sizeof(nas_esm_elem_strings)/sizeof(value_string))
gint ett_nas_eps_esm_elem[NUM_NAS_ESM_ELEM];

guint16 (*esm_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string, int string_len) = {
    NULL,                           /* 9.9.4.1 Access point name */
    de_esm_apn_aggr_max_br,         /* 9.9.4.2 APN aggregate maximum bit rate */
    NULL,                           /* 9.9.4.2A Connectivity type */
    de_esm_qos,                     /* 9.9.4.3 EPS quality of service */
    de_esm_cause,                   /* 9.9.4.4 ESM cause */
    de_esm_inf_trf_flg,             /* 9.9.4.5 ESM information transfer flag */
    NULL,                           /* 9.9.4.6 Linked EPS bearer identity  */
    NULL,                           /* 9.9.4.7 LLC service access point identifier */
    de_esm_notif_ind,               /* 9.9.4.7a Notification indicator */
    NULL,                           /* 9.9.4.8 Packet flow identifier  */
    de_esm_pdn_addr,                /* 9.9.4.9 PDN address */
    NULL,                           /* 9.9.4.10 PDN type */
    NULL,                           /* 9.9.4.11 Protocol configuration options */
    NULL,                           /* 9.9.4.12 Quality of service */
    NULL,                           /* 9.9.4.13 Radio priority  */
    de_esm_re_attempt_ind,          /* 9.9.4.13a Re-attempt indicator */
    NULL,                           /* 9.9.4.14 Request type */
    NULL,                           /* 9.9.4.15 Traffic flow aggregate description */
    NULL,                           /* 9.9.4.16 Traffic flow template */
    NULL,                           /* 9.9.4.17 Transaction identifier */
    NULL,                           /* 9.9.4.18 WLAN offload acceptability */
    de_esm_nbifom_cont,             /* 9.9.4.19 NBIFOM container */
    de_esm_remote_ue_context_list,  /* 9.9.4.20 Remote UE context list */
    de_esm_pkmf_address,            /* 9.9.4.21 PKMF address */
    de_esm_hdr_compr_config,        /* 9.9.4.22 Header compression configuration */
    de_esm_ctrl_plane_only_ind,     /* 9.9.4.23 Control plane only indication */
    de_esm_user_data_cont,          /* 9.9.4.24 User data container */
    de_esm_rel_assist_ind,          /* 9.9.4.25 Release assistance indication */
    de_esm_ext_pco,                 /* 9.9.4.26 Extended protocol configuration options */
    de_esm_hdr_compr_config_status, /* 9.9.4.27 Header compression configuration status */
    de_esm_serv_plmn_rate_ctrl,     /* 9.9.4.28 Serving PLMN rate control */
    NULL,   /* NONE */
};

/* MESSAGE FUNCTIONS */

/*
 * 8.2.1    Attach accept
 */

static void
nas_emm_attach_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset, bit_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    pinfo->link_dir = P2P_DIR_DL;

    /*  Spare half octet    Spare half octet 9.9.2.7    M   V   1/2 */
    bit_offset = curr_offset<<3;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_spare_half_octet, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset+=4;
    /*  EPS attach result   EPS attach result 9.9.3.10  M   V   1/2 */
    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_EPS_attach_result, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
    /*bit_offset+=3;*/
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
    /* 5E   T3412 extended value GPRS timer 3 9.9.3.16B O   TLV  3 */
    ELEM_OPT_TLV(0x5E, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - T3412 extended value");
    /* 6A   T3324 value GPRS timer 2 9.9.3.16A O   TLV  3 */
    ELEM_OPT_TLV(0x6A, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3324");
    /* 6E   Extended DRX parameters Extended DRX parameters 9.9.3.46 O   TLV  3 */
    ELEM_OPT_TLV(0x6E, GSM_A_PDU_TYPE_GM, DE_EXT_DRX_PARAMS, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}
/*
 * 8.2.2    Attach complete
 */
static void
nas_emm_attach_comp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    pinfo->link_dir = P2P_DIR_UL;

    /* ESM message container    ESM message container 9.9.3.15  M   LV-E    2-n */
    ELEM_MAND_LV_E(NAS_PDU_TYPE_EMM, DE_EMM_ESM_MSG_CONT, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);

}

/*
 * 8.2.3    Attach reject
 */
static void
nas_emm_attach_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    pinfo->link_dir = P2P_DIR_DL;

    /* * EMM cause  EMM cause 9.9.3.9   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_EMM, DE_EMM_CAUSE, NULL);
    /* 78 ESM message container ESM message container 9.9.3.15  O   TLV-E   4-n */
    ELEM_OPT_TLV_E(0x78, NAS_PDU_TYPE_EMM, DE_EMM_ESM_MSG_CONT, NULL);
    /* 5F   T3346 value GPRS timer 2 9.9.3.16A O   TLV  3 */
    ELEM_OPT_TLV(0x5F, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3346 value");
    /* 16   T3402 value GPRS timer 2 9.9.3.16A O   TLV  3 */
    ELEM_OPT_TLV(0x16, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3402 value");
    /* A-   Extended EMM cause   Extended EMM cause 9.9.3.26A  O   TV  1 */
    ELEM_OPT_TV_SHORT( 0xA0, NAS_PDU_TYPE_EMM, DE_EMM_EXT_CAUSE, NULL );

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);

}
/*
 * 8.2.4    Attach request
 */
static void
nas_emm_attach_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset, bit_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    bit_offset = curr_offset<<3;

    pinfo->link_dir = P2P_DIR_UL;

    /* NAS key set identifier   NAS key set identifier 9.9.3.21 M   V   1/2 */
    de_emm_nas_key_set_id_bits(tvb, tree, bit_offset, NULL);
    bit_offset+=4;

    /* EPS attach type  EPS attach type 9.9.3.11    M   V   1/2
     * Inline:
     */
    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_eps_att_type, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
    /*bit_offset+=3;*/

    /* Fix the lengths */
    curr_len--;
    curr_offset++;
    /* Old GUTI or IMSI EPS mobile identity 9.9.3.12    M   LV  5-12 */
    ELEM_MAND_LV(NAS_PDU_TYPE_EMM, DE_EMM_EPS_MID, NULL);
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
    /* D-   Device properties  Device properties 9.9.2.0A O   TV  1 */
    ELEM_OPT_TV_SHORT(0xD0 , GSM_A_PDU_TYPE_GM, DE_DEVICE_PROPERTIES, NULL);
    /* E-   Old GUTI type  GUTI type 9.9.3.45 O   TV  1 */
    ELEM_OPT_TV_SHORT(0xE0 , NAS_PDU_TYPE_EMM, DE_EMM_GUTI_TYPE, " - Old GUTI type");
    /* C-   MS network feature support  MS network feature support 9.9.3.20A O  TV 1 */
    ELEM_OPT_TV_SHORT(0xC0 , GSM_A_PDU_TYPE_COMMON, DE_MS_NET_FEAT_SUP, NULL);
    /* 10   TMSI based NRI container  Network resource identifier container 9.9.3.24A O  TLV 4 */
    ELEM_OPT_TLV(0x10, GSM_A_PDU_TYPE_GM, DE_NET_RES_ID_CONT, " - TMSI based NRI container");
    /* 6A   T3324 value  GPRS timer 2 9.9.3.16A O  TLV 3 */
    ELEM_OPT_TLV(0x6A, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3324 value");
    /* 5E   T3412 extended value  GPRS timer 3 9.9.3.16B O  TLV 3 */
    ELEM_OPT_TLV(0x5E, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - T3412 extended value");
    /* 6E   Extended DRX parameters Extended DRX parameters 9.9.3.46 O   TLV  3 */
    ELEM_OPT_TLV(0x6E, GSM_A_PDU_TYPE_GM, DE_EXT_DRX_PARAMS, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}
/*
 * 8.2.5    Authentication failure
 */
static void
nas_emm_auth_fail(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    pinfo->link_dir = P2P_DIR_UL;

    /* EMM cause   EMM cause 9.9.3.9   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_EMM, DE_EMM_CAUSE, NULL);
    /* 30 Authentication failure parameter  Authentication failure parameter 9.9.3.1    O   TLV 1 */
    ELEM_OPT_TLV(0x30, GSM_A_PDU_TYPE_DTAP, DE_AUTH_FAIL_PARAM, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}
/*
 * 8.2.6    Authentication reject
 * No IE:s
 */
/*
 * 8.2.7    Authentication request
 */

static void
nas_emm_auth_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset, bit_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    pinfo->link_dir = P2P_DIR_DL;

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
    /*bit_offset+=4;*/

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

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);

}
/*
 * 8.2.8    Authentication response
 */
static void
nas_emm_auth_resp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    pinfo->link_dir = P2P_DIR_UL;

    /*
     * Authentication response parameter 9.9.3.4    M   LV  5-17
     */
    ELEM_MAND_LV(NAS_PDU_TYPE_EMM, DE_EMM_AUTH_RESP_PAR, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}

/*
 * 8.2.9    CS service notification
 */

static void
nas_emm_cs_serv_not(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    pinfo->link_dir = P2P_DIR_DL;

    /* Paging identity  Paging identity 9.9.3.25A   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_EMM, DE_EMM_PAGING_ID, NULL);
    /* 60   CLI CLI 9.9.3.38    O   TLV 3-12 */
    ELEM_OPT_TLV(0x60, GSM_A_PDU_TYPE_DTAP, DE_CLG_PARTY_BCD_NUM, " - CLI");
    /* 61   SS Code SS Code 9.9.3.39    O   TV  2 */
    ELEM_OPT_TV(0x61, NAS_PDU_TYPE_EMM, DE_EMM_SS_CODE, NULL);
    /* 62   LCS indicator   LCS indicator 9.9.3.40  O   TV  2 */
    ELEM_OPT_TV(0x62, NAS_PDU_TYPE_EMM, DE_EMM_LCS_IND, NULL);
    /* 63   LCS client identity LCS client identity 9.9.3.41    O   TLV 3-257 */
    ELEM_OPT_TLV(0x63, NAS_PDU_TYPE_EMM, DE_EMM_LCS_CLIENT_ID, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
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
nas_emm_detach_req_UL(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset,bit_offset;
    guint32 consumed;
    guint   curr_len;
    guint64 switch_off;
    guint64 detach_type;

    curr_offset = offset;
    curr_len    = len;

    proto_tree_add_item(tree, hf_nas_eps_emm_detach_req_UL, tvb, curr_offset, len, ENC_NA);
    /* NAS key set identifier   NAS key set identifier 9.9.3.21 M   V   1/2 */
    bit_offset = curr_offset<<3;
    de_emm_nas_key_set_id_bits(tvb, tree, bit_offset, NULL);
    bit_offset+=4;
    /* Detach type  Detach type 9.9.3.6 M   V   1/2 */
    proto_tree_add_bits_ret_val(tree, hf_nas_eps_emm_switch_off, tvb, bit_offset, 1, &switch_off, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_ret_val(tree, hf_nas_eps_emm_detach_type_UL, tvb, bit_offset, 3, &detach_type, ENC_BIG_ENDIAN);
   /* bit_offset+=3;*/
    /* Show detach reason in Info column.  TODO: expert info ? */
    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s%s)",
                    val_to_str_const((guint32)detach_type, nas_eps_emm_type_of_detach_UL_vals, "Unknown"),
                    (switch_off==0) ? "" : " / switch-off");

    /* Fix the lengths */
    curr_len--;
    curr_offset++;

    /* GUTI or IMSI EPS mobile identity 9.9.3.12    M   LV  5-12 */
    ELEM_MAND_LV(NAS_PDU_TYPE_EMM, DE_EMM_EPS_MID, NULL);
}
/*
 * 8.2.11.2 Detach request (UE terminated detach)
 */
static void
nas_emm_detach_req_DL(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset, bit_offset;
    guint32 consumed;
    guint   curr_len;
    guint64 detach_type;

    curr_offset = offset;
    curr_len    = len;

    proto_tree_add_item(tree, hf_nas_eps_emm_detach_req_DL, tvb, curr_offset, len, ENC_NA);
    /* Spare half octet Spare half octet 9.9.2.7    M   V   1/2 */
    bit_offset = curr_offset<<3;
    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset+=4;
    /* Detach type  Detach type 9.9.3.6 M   V   1/2 */
    /* In the network to UE direction bit 4 is spare. The network shall set this bit to zero. */
    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_ret_val(tree, hf_nas_eps_emm_detach_type_DL, tvb, bit_offset, 3, &detach_type, ENC_BIG_ENDIAN);
    /*bit_offset+=3;*/
    /* Show detach reason in Info column.  TODO: expert info ? */
    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
                    val_to_str_const((guint32)detach_type, nas_eps_emm_type_of_detach_DL_vals, "Unknown"));

    /* Fix the lengths */
    curr_len--;
    curr_offset++;

    /* No more mandatory elements */
    if (curr_len == 0)
        return;

    /* EMM cause    EMM cause 9.9.3.9   O   TV  2 */
    ELEM_OPT_TV(0x53, NAS_PDU_TYPE_EMM, DE_EMM_CAUSE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}
static void
nas_emm_detach_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    if (pinfo->link_dir == P2P_DIR_UL) {
        nas_emm_detach_req_UL(tvb, tree, pinfo, offset, len);
        return;
    }else if (pinfo->link_dir == P2P_DIR_DL) {
        nas_emm_detach_req_DL(tvb, tree, pinfo, offset, len);
        return;
    }

    if (len >= 8) {
        nas_emm_detach_req_UL(tvb, tree, pinfo, offset, len);
    } else {
        nas_emm_detach_req_DL(tvb, tree, pinfo, offset, len);
    }
}

/*
 * 8.2.12   Downlink NAS Transport
 */
static void
nas_emm_dl_nas_trans(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    pinfo->link_dir = P2P_DIR_DL;

    /* NAS message container    NAS message container 9.9.3.22  M   LV  3-252 */
    ELEM_MAND_LV(NAS_PDU_TYPE_EMM, DE_EMM_NAS_MSG_CONT, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}
/*
 * 8.2.13   EMM information
 */
static void
nas_emm_emm_inf(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    pinfo->link_dir = P2P_DIR_DL;

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

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}


/*
 * 8.2.14   EMM status
 */
static void
nas_emm_emm_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    /* EMM cause    EMM cause 9.9.3.9   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_EMM, DE_EMM_CAUSE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}

/*
 * 8.2.15   Extended service request
 */
static void
nas_emm_ext_serv_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset,bit_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    bit_offset = curr_offset<<3;

    pinfo->link_dir = P2P_DIR_UL;

    /* NAS key set identifier   NAS key set identifier 9.9.3.21 M   V   1/2 */
    de_emm_nas_key_set_id_bits(tvb, tree, bit_offset, NULL);
    bit_offset+=4;
    /* Service type Service type 9.9.3.27   M   V   1/2 Service type*/
    proto_tree_add_bits_item(tree, hf_nas_eps_service_type, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    /*bit_offset+=4;*/
    /* Fix up the lengths */
    curr_len--;
    curr_offset++;

    /* M-TMSI   Mobile identity 9.9.2.3 M   LV  6 */
    ELEM_MAND_LV(NAS_PDU_TYPE_COMMON, DE_EPS_CMN_MOB_ID, " - M-TMSI");
    /* B-   CSFB response   CSFB response 9.9.3.5   C   TV  1 */
    ELEM_OPT_TV_SHORT(0xb0, NAS_PDU_TYPE_EMM, DE_EMM_CSFB_RESP, NULL);
    /* 57   EPS bearer context status   EPS bearer context status 9.9.2.1   O   TLV 4 */
    ELEM_OPT_TLV(0x57, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_EPS_BE_CTX_STATUS, NULL);
    /* D-   Device properties  Device properties 9.9.2.0A O   TV  1 */
    ELEM_OPT_TV_SHORT(0xD0 , GSM_A_PDU_TYPE_GM, DE_DEVICE_PROPERTIES, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}
/*
 * 8.2.16   GUTI reallocation command
 */
static void
nas_emm_guti_realloc_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    pinfo->link_dir = P2P_DIR_DL;

    /* GUTI EPS mobile identity 9.9.3.12    M   LV  12 */
    ELEM_MAND_LV(NAS_PDU_TYPE_EMM, DE_EMM_EPS_MID, " - GUTI");

    /* 54   TAI list    Tracking area identity list 9.9.3.33    O   TLV 8-98 */
    ELEM_OPT_TLV(0x54, NAS_PDU_TYPE_EMM, DE_EMM_TRAC_AREA_ID_LST, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
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
    curr_len    = len;

    pinfo->link_dir = P2P_DIR_DL;

    bit_offset=curr_offset<<3;

    /* Spare half octet Spare half octet 9.9.2.7    M   V   1/2 */
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_spare_half_octet, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset+=4;

    /* Identity type    Identity type 2 9.9.3.17    M   V   1/2 */
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_id_type2, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    /*bit_offset+=4;*/
    /*consumed = 1;*/


    /* Fix up the lengths */
    curr_len--;
    curr_offset++;

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}
/*
 * 8.2.19   Identity response
 */
static void
nas_emm_id_res(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    pinfo->link_dir = P2P_DIR_UL;

    /* Mobile identity  Mobile identity 9.9.2.3 M   LV  4-10 */
    ELEM_MAND_LV(NAS_PDU_TYPE_COMMON, DE_EPS_CMN_MOB_ID, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}



/*
 * 8.2.20   Security mode command
 */
static void
nas_emm_sec_mode_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset, bit_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    pinfo->link_dir = P2P_DIR_DL;

    /*  Selected NAS security algorithms    NAS security algorithms 9.9.3.23    M   V   1  */
    ELEM_MAND_V(NAS_PDU_TYPE_EMM, DE_EMM_NAS_SEC_ALGS, " - Selected NAS security algorithms");

    bit_offset = curr_offset<<3;
    /* Spare half octet Spare half octet 9.9.2.7    M   V   1/2 */
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_spare_half_octet, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset+=4;
    /*  NAS key set identifierASME  NAS key set identifier 9.9.3.21 M   V   1/2 */
    de_emm_nas_key_set_id_bits(tvb, tree, bit_offset, " ASME");
    /*bit_offset+=4;*/

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

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}
/*
 * 8.2.21   Security mode complete
 */
static void
nas_emm_sec_mode_comp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    pinfo->link_dir = P2P_DIR_UL;

    if (curr_len == 0)
        return;

    /* 23   IMEISV  Mobile identity 9.9.2.3 O   TLV 11 */
    ELEM_OPT_TLV(0x23, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_MOB_ID, " - IMEISV");

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}
/*
 * 8.2.22   Security mode reject
 */
static void
nas_emm_sec_mode_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    pinfo->link_dir = P2P_DIR_UL;

    /* EMM cause    EMM cause 9.9.3.9   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_EMM, DE_EMM_CAUSE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}
/*
 * 8.2.24   Service reject
 */
static void
nas_emm_serv_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    pinfo->link_dir = P2P_DIR_DL;

    /* EMM cause    EMM cause 9.9.3.9   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_EMM, DE_EMM_CAUSE, NULL);
    /* 5B   T3442 value GPRS timer 9.9.3.16 C   TV  2 */
    ELEM_OPT_TV(0x5b, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER, " - T3442 value");
    /* 5F   T3346 value GPRS timer 2 9.9.3.16A O   TLV  3 */
    ELEM_OPT_TLV(0x5F, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3346 value");

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
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
nas_emm_service_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    pinfo->link_dir = P2P_DIR_UL;

    /* KSI and sequence number 9.9.3.19 M V 1   */
    ELEM_MAND_V(NAS_PDU_TYPE_EMM, DE_EMM_KSI_AND_SEQ_NO, NULL);

    /* Short MAC 9.9.3.28 M V 2 */
    ELEM_MAND_V(NAS_PDU_TYPE_EMM, DE_EMM_SHORT_MAC, " - Message authentication code (short)");

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}

/*
 * 8.2.26   Tracking area update accept
 */
static void
nas_emm_trac_area_upd_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset, bit_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    pinfo->link_dir = P2P_DIR_DL;

    /*  Spare half octet    Spare half octet 9.9.2.7    M   V   1/2 */
    bit_offset = curr_offset<<3;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_spare_half_octet, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset+=4;
    /*  EPS update result   EPS update result 9.9.3.13  M   V   1/2 */
    proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(tree, hf_nas_eps_eps_update_result_value, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
    /*bit_offset+=3;*/
    /* Fix up the lengths */
    curr_len--;
    curr_offset++;
    /* No more mandatory elements */
    if (curr_len == 0)
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
    /* 5E   T3412 extended value GPRS timer 3 9.9.3.16B O   TLV  3 */
    ELEM_OPT_TLV(0x5E, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - T3412 extended value");
    /* 6A   T3324 value GPRS timer 2 9.9.3.16A O   TLV  3 */
    ELEM_OPT_TLV(0x6A, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3324");
    /* 6E   Extended DRX parameters Extended DRX parameters 9.9.3.46 O   TLV  3 */
    ELEM_OPT_TLV(0x6E, GSM_A_PDU_TYPE_GM, DE_EXT_DRX_PARAMS, NULL);
    /* 68   Header compression configuration status Header compression configuration status 9.9.4.27 O  TLV  4 */
    ELEM_OPT_TLV(0x68, NAS_PDU_TYPE_ESM, DE_ESM_HDR_COMPR_CONFIG_STATUS, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}
/*
 * 8.2.27   Tracking area update complete
 * No more IE's
 */
/*
 * 8.2.28   Tracking area update reject
 */
static void
nas_emm_trac_area_upd_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    pinfo->link_dir = P2P_DIR_DL;

    /* EMM cause    EMM cause 9.9.3.9   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_EMM, DE_EMM_CAUSE, NULL);
    /* 5F   T3346 value GPRS timer 2 9.9.3.16A O   TLV  3 */
    ELEM_OPT_TLV(0x5F, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3346 value");
    /* A-   Extended EMM cause   Extended EMM cause 9.9.3.26A  O   TV  1 */
    ELEM_OPT_TV_SHORT( 0xA0, NAS_PDU_TYPE_EMM, DE_EMM_EXT_CAUSE, NULL );

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}
/*
 * 8.2.29   Tracking area update request
 */
static void
nas_emm_trac_area_upd_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{

    guint32 curr_offset, bit_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    bit_offset = curr_offset<<3;

    pinfo->link_dir = P2P_DIR_UL;

    /*  NAS key set identifierASME  NAS key set identifier 9.9.3.21 M   V   1/2 */
    de_emm_nas_key_set_id_bits(tvb, tree, bit_offset, " ASME");
    bit_offset+=4;

    /*  EPS update type EPS update type 9.9.3.14    M   V   1/2 */
    proto_tree_add_bits_item(tree, hf_nas_eps_active_flg, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(tree, hf_nas_eps_eps_update_type_value, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
    /*bit_offset+=3;*/

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
    ELEM_OPT_TV_SHORT( 0xA0, NAS_PDU_TYPE_EMM, DE_EMM_UE_RA_CAP_INF_UPD_NEED, NULL );
    /* 57   EPS bearer context status   EPS bearer context status 9.9.2.1   O   TLV 4 */
    ELEM_OPT_TLV(0x57, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_EPS_BE_CTX_STATUS, NULL);
    /* 31   MS network capability   MS network capability 9.9.3.20  O   TLV 4-10 */
    ELEM_OPT_TLV( 0x31, GSM_A_PDU_TYPE_GM, DE_MS_NET_CAP, NULL );
    /* 13   Old location area identification    Location area identification 9.9.2.2    O   TV  6 */
    ELEM_OPT_TV(0x13, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_LOC_AREA_ID, " - Old location area identification");
    /* 9-   TMSI status TMSI status 9.9.3.31    O   TV  1  */
    ELEM_OPT_TV_SHORT( 0x90, GSM_A_PDU_TYPE_GM, DE_TMSI_STAT, NULL );
    /* 11   Mobile station classmark 2  Mobile station classmark 2 9.9.2.5  O   TLV 5 */
    ELEM_OPT_TLV( 0x11, NAS_PDU_TYPE_COMMON, DE_EPS_MS_CM_2 , NULL );
    /* 20   Mobile station classmark 3  Mobile station classmark 3 9.9.2.5  O   TLV 2-34 */
    ELEM_OPT_TLV( 0x20, NAS_PDU_TYPE_COMMON, DE_EPS_MS_CM_3 , NULL );
    /* 40   Supported Codecs    Supported Codec List 9.9.2.10   O   TLV 5-n */
    ELEM_OPT_TLV(0x40, GSM_A_PDU_TYPE_DTAP, DE_SUP_CODEC_LIST, " - Supported Codecs");
    /* F-   Additional update type  Additional update type 9.9.3.0B O   TV  1 */
    ELEM_OPT_TV_SHORT( 0xF0, NAS_PDU_TYPE_EMM, DE_EMM_ADD_UPD_TYPE, NULL );
    /* 5D   Voice domain preference and UE's usage setting  Voice domain preference and UE's usage setting 9.9.3.44 O   TLV 3 */
    ELEM_OPT_TLV(0x5D, GSM_A_PDU_TYPE_GM, DE_VOICE_DOMAIN_PREF, NULL);
    /* E-   Old GUTI type  GUTI type 9.9.3.45 O   TV  1 */
    ELEM_OPT_TV_SHORT(0xE0, NAS_PDU_TYPE_EMM, DE_EMM_GUTI_TYPE, " - Old GUTI type");
    /* D-   Device properties  Device properties 9.9.2.0A O   TV  1 */
    ELEM_OPT_TV_SHORT(0xD0, GSM_A_PDU_TYPE_GM, DE_DEVICE_PROPERTIES, NULL);
    /* C-   MS network feature support  MS network feature support 9.9.3.20A 0  TV 1 */
    ELEM_OPT_TV_SHORT(0xC0, GSM_A_PDU_TYPE_COMMON, DE_MS_NET_FEAT_SUP, NULL);
    /* 10   TMSI based NRI container  Network resource identifier container 9.9.3.24A 0  TLV 4 */
    ELEM_OPT_TLV(0x10, GSM_A_PDU_TYPE_GM, DE_NET_RES_ID_CONT, " - TMSI based NRI container");
    /* 6A   T3324 value  GPRS timer 2 9.9.3.16A O  TLV 3 */
    ELEM_OPT_TLV(0x6A, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3324 value");
    /* 5E   T3412 extended value  GPRS timer 3 9.9.3.16B O  TLV 3 */
    ELEM_OPT_TLV(0x5E, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - T3412 extended value");
    /* 6E   Extended DRX parameters Extended DRX parameters 9.9.3.46 O   TLV  3 */
    ELEM_OPT_TLV(0x6E, GSM_A_PDU_TYPE_GM, DE_EXT_DRX_PARAMS, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}

/*
 * 8.2.30   Uplink NAS Transport
 */
static void
nas_emm_ul_nas_trans(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    pinfo->link_dir = P2P_DIR_UL;

    /* NAS message container    NAS message container 9.9.3.22  M   LV  3-252*/
    ELEM_MAND_LV(NAS_PDU_TYPE_EMM, DE_EMM_NAS_MSG_CONT, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}

/*
 * 8.2.31   Downlink generic NAS transport
 */
static void
nas_emm_dl_gen_nas_trans(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    pinfo->link_dir = P2P_DIR_DL;

    /* Generic message container type Generic message container type 9.9.3.42 M V 1 */
    ELEM_MAND_V(NAS_PDU_TYPE_EMM, DE_EMM_GEN_MSG_CONT_TYPE, NULL);
    /* Generic message container Generic message container 9.9.3.43 M LV-E 3-n */
    ELEM_MAND_LV_E(NAS_PDU_TYPE_EMM, DE_EMM_GEN_MSG_CONT, NULL)
    /* 65 Additional information Additional information 9.9.2.0 O TLV 3-n */
    ELEM_OPT_TLV(0x65, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_ADD_INFO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);

    eps_nas_gen_msg_cont_type = 0;
}

/*
 * 8.2.32   Uplink generic NAS transport
 */
static void
nas_emm_ul_gen_nas_trans(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    pinfo->link_dir = P2P_DIR_UL;

    /* Generic message container type Generic message container type 9.9.3.42 M V 1 */
    ELEM_MAND_V(NAS_PDU_TYPE_EMM, DE_EMM_GEN_MSG_CONT_TYPE, NULL);
    /* Generic message container Generic message container 9.9.3.43 M LV-E 3-n */
    ELEM_MAND_LV_E(NAS_PDU_TYPE_EMM, DE_EMM_GEN_MSG_CONT, NULL)
    /* 65 Additional information Additional information 9.9.2.0 O TLV 3-n */
    ELEM_OPT_TLV(0x65, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_ADD_INFO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);

    eps_nas_gen_msg_cont_type = 0;
}

/*
 * 8.2.33   Control plane service request
 */
static const value_string nas_eps_emm_data_serv_type_vals[] = {
    { 0x0, "Mobile originating request" },
    { 0x1, "Mobile terminating request" },
    { 0, NULL }
};

static void
nas_emm_ctrl_plane_serv_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset, bit_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;
    bit_offset  = curr_offset<<3;

    pinfo->link_dir = P2P_DIR_UL;

    /* NAS key set identifier  NAS key set identifier 9.9.3.21 M V 1/2 */
    de_emm_nas_key_set_id_bits(tvb, tree, bit_offset, NULL);
    bit_offset+=4;
    /* Data service type  Data service type 9.9.3.47 M V 1/2 */
    proto_tree_add_bits_item(tree, hf_nas_eps_active_flg, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset += 1;
    proto_tree_add_bits_item(tree, hf_nas_eps_data_serv_type, tvb, bit_offset, 3, ENC_BIG_ENDIAN);

    /* Fix the lengths */
    curr_len--;
    curr_offset++;
    if (curr_len == 0)
        return;

    /* 78  ESM message container  ESM message container 9.9.3.15 O  TLV-E  3-n */
    ELEM_OPT_TLV_E(0x78, NAS_PDU_TYPE_EMM, DE_EMM_ESM_MSG_CONT, NULL);
    /* 67  NAS message container  NAS message container 9.9.3.22 O  TLV  4-253 */
    ELEM_OPT_TLV(0x67, NAS_PDU_TYPE_EMM, DE_EMM_NAS_MSG_CONT, NULL);
    /* 57  EPS bearer context status  EPS bearer context status 9.9.2.1 O  TLV  4 */
    ELEM_OPT_TLV(0x57, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_EPS_BE_CTX_STATUS, NULL);
    /* D-  Device properties  Device properties 9.9.2.0A O  TV  1 */
    ELEM_OPT_TV_SHORT(0xD0, GSM_A_PDU_TYPE_GM, DE_DEVICE_PROPERTIES, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}

/*
 * 8.2.34   Service accept
 */
static void
nas_emm_serv_accept(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    pinfo->link_dir = P2P_DIR_DL;

    if (curr_len == 0)
        return;

    /* 57  EPS bearer context status  EPS bearer context status 9.9.2.1 O  TLV  4 */
    ELEM_OPT_TLV(0x57, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_EPS_BE_CTX_STATUS, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
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

    if (len == 0)
        return;

    curr_offset = offset;
    curr_len = len;

    /* This message is sent by the UE to the network */
    pinfo->link_dir = P2P_DIR_UL;

    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253 */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );
    /* 33   NBIFOM container  NBIFOM container 9.9.4.19 O   TLV 3-257 */
    ELEM_OPT_TLV(0x33, NAS_PDU_TYPE_ESM, DE_ESM_NBIFOM_CONT, NULL);
    /* 7B   Extended protocol configuration options Extended protocol configuration options 9.9.4.26 O  TLV-E  4-65538 */
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
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
    curr_len    = len;

    /* This message is sent by UE to the network to reject activation of a dedicated EPS bearer context */
    pinfo->link_dir = P2P_DIR_UL;

    /* ESM cause    ESM cause 9.9.4.2   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_ESM, DE_ESM_CAUSE, NULL);
    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253 */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );
    /* 33   NBIFOM container  NBIFOM container 9.9.4.19 O   TLV 3-257 */
    ELEM_OPT_TLV(0x33, NAS_PDU_TYPE_ESM, DE_ESM_NBIFOM_CONT, NULL);
    /* 7B   Extended protocol configuration options Extended protocol configuration options 9.9.4.26 O  TLV-E  4-65538 */
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
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
    curr_len    = len;

    /* This message is sent by the network to the UE to request activation of a dedicated EPS bearer context... */
    pinfo->link_dir = P2P_DIR_DL;


    /* Spare half octet Spare half octet 9.9.2.9    M   V   1/2 */
    bit_offset = curr_offset<<3;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_spare_half_octet, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset+=4;
    /* Linked EPS bearer identity   Linked EPS bearer identity 9.9.4.6  M   V   1/2 */
    proto_tree_add_bits_item(tree, hf_nas_eps_esm_linked_bearer_id, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    /*bit_offset+=4;*/
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
    /* C-   WLAN offload indication  WLAN offload indication 9.9.4.18 O  TV 1 */
    ELEM_OPT_TV_SHORT(0xC0 , GSM_A_PDU_TYPE_GM, DE_SM_WLAN_OFFLOAD_ACCEPT, " - WLAN offload indication");
    /* 33   NBIFOM container  NBIFOM container 9.9.4.19 O   TLV 3-257 */
    ELEM_OPT_TLV(0x33, NAS_PDU_TYPE_ESM, DE_ESM_NBIFOM_CONT, NULL);
    /* 7B   Extended protocol configuration options Extended protocol configuration options 9.9.4.26 O  TLV-E  4-65538 */
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
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
    curr_len    = len;

    if (len == 0)
        return;

    /* This message is sent by the UE to the network to acknowledge activation of a default EPS bearer context */
    pinfo->link_dir = P2P_DIR_UL;

    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253  */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );
    /* 7B   Extended protocol configuration options Extended protocol configuration options 9.9.4.26 O  TLV-E  4-65538 */
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
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
    curr_len    = len;

    /* This message is sent by UE to the network to reject activation of a default EPS bearer context. */
    pinfo->link_dir = P2P_DIR_UL;

    /*  ESM cause   ESM cause 9.9.4.4   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_ESM, DE_ESM_CAUSE, NULL);
    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253 */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );
    /* 7B   Extended protocol configuration options Extended protocol configuration options 9.9.4.26 O  TLV-E  4-65538 */
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
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
    curr_len    = len;

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
    /* B-   Connectivity type  Connectivity type 9.9.4.2A O  TV 1 */
    ELEM_OPT_TV_SHORT(0xB0 , GSM_A_PDU_TYPE_GM, DE_SM_CONNECTIVITY_TYPE, NULL);
    /* C-   WLAN offload indication  WLAN offload indication 9.9.4.18 O  TV 1 */
    ELEM_OPT_TV_SHORT(0xC0 , GSM_A_PDU_TYPE_GM, DE_SM_WLAN_OFFLOAD_ACCEPT, " - WLAN offload indication");
    /* 33   NBIFOM container  NBIFOM container 9.9.4.19 O   TLV 3-257 */
    ELEM_OPT_TLV(0x33, NAS_PDU_TYPE_ESM, DE_ESM_NBIFOM_CONT, NULL);
    /* 66   Header compression configuration  Header compression configuration 9.9.4.22 O   TLV 3-TBD */
    ELEM_OPT_TLV(0x66, NAS_PDU_TYPE_ESM, DE_ESM_HDR_COMPR_CONFIG, NULL);
    /* 9-   Control plane only indication  Control plane only indication 9.9.4.23 O   TV 1 */
    ELEM_OPT_TV_SHORT(0x90, NAS_PDU_TYPE_ESM, DE_ESM_CTRL_PLANE_ONLY_IND, NULL);
    /* 7B   Extended protocol configuration options Extended protocol configuration options 9.9.4.26 O  TLV-E  4-65538 */
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);
    /* 6E   Serving PLMN rate control  Serving PLMN rate control 9.9.4.28 O  TLV  4 */
    ELEM_OPT_TLV(0x6E, NAS_PDU_TYPE_ESM, DE_ESM_SERV_PLMN_RATE_CTRL, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
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
    curr_len    = len;

    /* This message is sent by the network to the UE to reject the allocation of a dedicated bearer resource. */
    pinfo->link_dir = P2P_DIR_DL;

    /*  ESM cause   ESM cause 9.9.4.4   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_ESM, DE_ESM_CAUSE, NULL);
    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253 */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );
    /* 37   Back-off timer value GPRS timer 3 9.9.3.16B O   TLV  3 */
    ELEM_OPT_TLV(0x37, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - Back-off timer value");
    /* 6B   Re-attempt indicator Re-attempt indicator 9.9.4.13A O TLV 3 */
    ELEM_OPT_TLV(0x6B, NAS_PDU_TYPE_ESM, DE_ESM_RE_ATTEMPT_IND, NULL);
    /* 33   NBIFOM container  NBIFOM container 9.9.4.19 O   TLV 3-257 */
    ELEM_OPT_TLV(0x33, NAS_PDU_TYPE_ESM, DE_ESM_NBIFOM_CONT, NULL);
    /* 7B   Extended protocol configuration options Extended protocol configuration options 9.9.4.26 O  TLV-E  4-65538 */
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
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
    curr_len    = len;

    /* This message is sent by the UE to the network to request the allocation of a dedicated bearer resource. */
    pinfo->link_dir = P2P_DIR_UL;

    /*  Spare half octet    Spare half octet 9.9.2.9    M   V   1/2 */
    bit_offset = curr_offset<<3;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_spare_half_octet, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset+=4;
    /*  Linked EPS bearer identity  Linked EPS bearer identity 9.9.4.6  M   V   1/2 */
    proto_tree_add_bits_item(tree, hf_nas_eps_esm_linked_bearer_id, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    /*bit_offset+=4;*/
    /* Fix the lengths */
    curr_len--;
    curr_offset++;

    /*  Traffic flow aggregate  Traffic flow aggregate description 9.9.4.15 M   LV  2-256 */
    ELEM_MAND_LV( GSM_A_PDU_TYPE_GM, DE_TRAFFIC_FLOW_TEMPLATE , " - Traffic flow aggregate" );
    /*  Required traffic flow QoS   EPS quality of service 9.9.4.3  M   LV  2-10 */
    ELEM_MAND_LV(NAS_PDU_TYPE_ESM, DE_ESM_EPS_QOS, " - Required traffic flow QoS");
    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253 */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );
    /* C-   Device properties  Device properties 9.9.2.0A O   TV  1 */
    ELEM_OPT_TV_SHORT(0xC0 , GSM_A_PDU_TYPE_GM, DE_DEVICE_PROPERTIES, NULL);
    /* 33   NBIFOM container  NBIFOM container 9.9.4.19 O   TLV 3-257 */
    ELEM_OPT_TLV(0x33, NAS_PDU_TYPE_ESM, DE_ESM_NBIFOM_CONT, NULL);
    /* 7B   Extended protocol configuration options Extended protocol configuration options 9.9.4.26 O  TLV-E  4-65538 */
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
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
    curr_len    = len;

    /* This message is sent by the network to the UE to reject the modification of a dedicated bearer resource. */
    pinfo->link_dir = P2P_DIR_DL;

    /*  ESM cause   ESM cause 9.9.4.4   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_ESM, DE_ESM_CAUSE, NULL);
    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253 */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );
    /* 37   Back-off timer value GPRS timer 3 9.9.3.16B O   TLV  3 */
    ELEM_OPT_TLV(0x37, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - Back-off timer value");
    /* 6B   Re-attempt indicator Re-attempt indicator 9.9.4.13A O TLV 3 */
    ELEM_OPT_TLV(0x6B, NAS_PDU_TYPE_ESM, DE_ESM_RE_ATTEMPT_IND, NULL);
    /* 33   NBIFOM container  NBIFOM container 9.9.4.19 O   TLV 3-257 */
    ELEM_OPT_TLV(0x33, NAS_PDU_TYPE_ESM, DE_ESM_NBIFOM_CONT, NULL);
    /* 7B   Extended protocol configuration options Extended protocol configuration options 9.9.4.26 O  TLV-E  4-65538 */
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
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
    curr_len    = len;

    /* This message is sent by the UE to the network to request the modification of a dedicated bearer resource. */
    pinfo->link_dir = P2P_DIR_UL;

    /*  Spare half octet    Spare half octet 9.9.2.9    M   V   1/2 */
    bit_offset = curr_offset<<3;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_spare_half_octet, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset+=4;
    /* EPS bearer identity for packet filter    Linked EPS bearer identity 9.9.4.6  M   V   1/2 */
    proto_tree_add_bits_item(tree, hf_nas_eps_esm_linked_bearer_id, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    /*bit_offset+=4;*/
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
    /* C-   Device properties  Device properties 9.9.2.0A O   TV  1 */
    ELEM_OPT_TV_SHORT(0xC0 , GSM_A_PDU_TYPE_GM, DE_DEVICE_PROPERTIES, NULL);
    /* 33   NBIFOM container  NBIFOM container 9.9.4.19 O   TLV 3-257 */
    ELEM_OPT_TLV(0x33, NAS_PDU_TYPE_ESM, DE_ESM_NBIFOM_CONT, NULL);
    /* 66   Header compression configuration  Header compression configuration 9.9.4.22 O   TLV 3-TBD */
    ELEM_OPT_TLV(0x66, NAS_PDU_TYPE_ESM, DE_ESM_HDR_COMPR_CONFIG, NULL);
    /* 7B   Extended protocol configuration options Extended protocol configuration options 9.9.4.26 O  TLV-E  4-65538 */
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
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
    curr_len    = len;

    if (len == 0)
        return;

    /* This message is sent by the UE to acknowledge deactivation of the EPS bearer context... */
    pinfo->link_dir = P2P_DIR_UL;

    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );
    /* 7B   Extended protocol configuration options Extended protocol configuration options 9.9.4.26 O  TLV-E  4-65538 */
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
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
    curr_len    = len;

    /* This message is sent by the network to request deactivation of an active EPS bearer context. */
    pinfo->link_dir = P2P_DIR_DL;

    /*  ESM cause   ESM cause 9.9.4.4   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_ESM, DE_ESM_CAUSE, NULL);
    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );
    /* 37   T3396 value GPRS timer 3 9.9.3.16B O   TLV  3 */
    ELEM_OPT_TLV(0x37, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - T3396 value");
    /* C-   WLAN offload indication  WLAN offload indication 9.9.4.18 O  TV 1 */
    ELEM_OPT_TV_SHORT(0xC0 , GSM_A_PDU_TYPE_GM, DE_SM_WLAN_OFFLOAD_ACCEPT, " - WLAN offload indication");
    /* 33   NBIFOM container  NBIFOM container 9.9.4.19 O   TLV 3-257 */
    ELEM_OPT_TLV(0x33, NAS_PDU_TYPE_ESM, DE_ESM_NBIFOM_CONT, NULL);
    /* 7B   Extended protocol configuration options Extended protocol configuration options 9.9.4.26 O  TLV-E  4-65538 */
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}

/*
 * 8.3.12A ESM dummy message
 * No IE:s
 */
static void
nas_esm_dummy_msg(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
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
    curr_len    = len;

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
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
    curr_len    = len;

    if (len == 0)
        return;

    /* This message is sent by the UE to the network in response to an ESM INFORMATION REQUEST... */
    pinfo->link_dir = P2P_DIR_UL;

    /* 28   Access point name   Access point name 9.9.4.1   O   TLV 3-102 */
    ELEM_OPT_TLV( 0x28 , GSM_A_PDU_TYPE_GM, DE_ACC_POINT_NAME , NULL );
    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253 */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );
    /* 7B   Extended protocol configuration options Extended protocol configuration options 9.9.4.26 O  TLV-E  4-65538 */
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}
/*
 * 8.3.15 ESM status
 */
static void
nas_esm_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    /* ESM cause    ESM cause 9.9.4.4   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_ESM, DE_ESM_CAUSE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
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
    curr_len    = len;

    if (len == 0)
        return;

    /* This message is sent by the UE to the network to acknowledge the modification of an active EPS bearer context. */
    pinfo->link_dir = P2P_DIR_UL;

    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253 */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );
    /* 33   NBIFOM container  NBIFOM container 9.9.4.19 O   TLV 3-257 */
    ELEM_OPT_TLV(0x33, NAS_PDU_TYPE_ESM, DE_ESM_NBIFOM_CONT, NULL);
    /* 7B   Extended protocol configuration options Extended protocol configuration options 9.9.4.26 O  TLV-E  4-65538 */
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
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
    curr_len    = len;

    /* This message is sent by the UE or the network to reject a modification of an active EPS bearer context. */
    pinfo->link_dir = P2P_DIR_UL;

    /* ESM cause    ESM cause 9.9.4.4   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_ESM, DE_ESM_CAUSE, NULL);
    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253 */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );
    /* 33   NBIFOM container  NBIFOM container 9.9.4.19 O   TLV 3-257 */
    ELEM_OPT_TLV(0x33, NAS_PDU_TYPE_ESM, DE_ESM_NBIFOM_CONT, NULL);
    /* 7B   Extended protocol configuration options Extended protocol configuration options 9.9.4.26 O  TLV-E  4-65538 */
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
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
    curr_len    = len;

    if (len == 0)
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
    /* C-   WLAN offload indication  WLAN offload indication 9.9.4.18 O  TV 1 */
    ELEM_OPT_TV_SHORT(0xC0 , GSM_A_PDU_TYPE_GM, DE_SM_WLAN_OFFLOAD_ACCEPT, " - WLAN offload indication");
    /* 33   NBIFOM container  NBIFOM container 9.9.4.19 O   TLV 3-257 */
    ELEM_OPT_TLV(0x33, NAS_PDU_TYPE_ESM, DE_ESM_NBIFOM_CONT, NULL);
    /* 66   Header compression configuration  Header compression configuration 9.9.4.22 O   TLV 3-TBD */
    ELEM_OPT_TLV(0x66, NAS_PDU_TYPE_ESM, DE_ESM_HDR_COMPR_CONFIG, NULL);
    /* 7B   Extended protocol configuration options Extended protocol configuration options 9.9.4.26 O  TLV-E  4-65538 */
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}
/*
 * 8.3.18A Notification
 */
static void
nas_esm_notification(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    pinfo->link_dir = P2P_DIR_DL;

    /* Notification indicator Notification indicator 9.9.4.7A M LV 2 */
    ELEM_MAND_LV(NAS_PDU_TYPE_ESM, DE_ESM_NOTIF_IND, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
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
    curr_len    = len;

    /*This message is sent by the network to the UE to reject establishment of a PDN connection. */
    pinfo->link_dir = P2P_DIR_DL;

    /* ESM cause    ESM cause 9.9.4.4   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_ESM, DE_ESM_CAUSE, NULL);
    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253 */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );
    /* 37   Back-off timer value GPRS timer 3 9.9.3.16B O   TLV  3 */
    ELEM_OPT_TLV(0x37, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - Back-off timer value");
    /* 6B   Re-attempt indicator Re-attempt indicator 9.9.4.13A O TLV 3 */
    ELEM_OPT_TLV(0x6B, NAS_PDU_TYPE_ESM, DE_ESM_RE_ATTEMPT_IND, NULL);
    /* 33   NBIFOM container  NBIFOM container 9.9.4.19 O   TLV 3-257 */
    ELEM_OPT_TLV(0x33, NAS_PDU_TYPE_ESM, DE_ESM_NBIFOM_CONT, NULL);
    /* 7B   Extended protocol configuration options Extended protocol configuration options 9.9.4.26 O  TLV-E  4-65538 */
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}

/*
 * 8.3.20 PDN connectivity request
 */
void
nas_esm_pdn_con_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;
    int     bit_offset;

    curr_offset = offset;
    curr_len    = len;

    /*This message is sent by the UE to the network to initiate establishment of a PDN connection. */
    pinfo->link_dir = P2P_DIR_UL;

    /* PDN type PDN type 9.9.4.10 M V 1/2 */
    bit_offset = curr_offset<<3;
    proto_tree_add_bits_item(tree, hf_nas_eps_esm_pdn_type, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset+=4;

    /* Request type 9.9.4.14 M V 1/2 */
    proto_tree_add_bits_item(tree, hf_nas_eps_esm_request_type, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    /*bit_offset+=4;*/
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
    /* C-   Device properties  Device properties 9.9.2.0A O   TV  1 */
    ELEM_OPT_TV_SHORT(0xC0 , GSM_A_PDU_TYPE_GM, DE_DEVICE_PROPERTIES, NULL);
    /* 33   NBIFOM container  NBIFOM container 9.9.4.19 O   TLV 3-257 */
    ELEM_OPT_TLV(0x33, NAS_PDU_TYPE_ESM, DE_ESM_NBIFOM_CONT, NULL);
    /* 66   Header compression configuration  Header compression configuration 9.9.4.22 O   TLV 3-TBD */
    ELEM_OPT_TLV(0x66, NAS_PDU_TYPE_ESM, DE_ESM_HDR_COMPR_CONFIG, NULL);
    /* 7B   Extended protocol configuration options Extended protocol configuration options 9.9.4.26 O  TLV-E  4-65538 */
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}
/*
 * 8.3.21 PDN disconnect reject
 */
static void
nas_esm_pdn_disc_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    /* This message is sent by the network to the UE to reject release of a PDN connection. */
    pinfo->link_dir = P2P_DIR_DL;

    /* ESM cause    ESM cause 9.9.4.4   M   V   1 */
    ELEM_MAND_V(NAS_PDU_TYPE_ESM, DE_ESM_CAUSE, NULL);
    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253 */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );
    /* 7B   Extended protocol configuration options Extended protocol configuration options 9.9.4.26 O  TLV-E  4-65538 */
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}
/*
 * 8.3.22 PDN disconnect request
 */
static void
nas_esm_pdn_disc_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset, bit_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    /*This message is sent by the UE to the network to initiate release of a PDN connection. */
    pinfo->link_dir = P2P_DIR_UL;

    /*  Spare half octet    Spare half octet 9.9.2.9    M   V   1/2 */
    bit_offset = curr_offset<<3;
    proto_tree_add_bits_item(tree, hf_nas_eps_emm_spare_half_octet, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset+=4;
    /* Linked EPS bearer identity   Linked EPS bearer identity 9.9.4.6  M   V   1/2 */
    proto_tree_add_bits_item(tree, hf_nas_eps_esm_linked_bearer_id, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    /*bit_offset+=4;*/
    /* Fix the lengths */
    curr_len--;
    curr_offset++;
    if (curr_len == 0)
        return;
    /* 27   Protocol configuration options  Protocol configuration options 9.9.4.11 O   TLV 3-253 */
    ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL );
    /* 7B   Extended protocol configuration options Extended protocol configuration options 9.9.4.26 O  TLV-E  4-65538 */
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}
/*
 * 8.3.23 Remote UE report
 */
static void
nas_esm_remote_ue_report(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    if (len == 0)
        return;

    pinfo->link_dir = P2P_DIR_UL;

    /* 79   Remote UE Context Connected  Remote UE context list 9.9.4.20 O   TLV-E 3-65538 */
    ELEM_OPT_TLV_E(0x79, NAS_PDU_TYPE_ESM, DE_ESM_REMOTE_UE_CONTEXT_LIST, " - Remote UE Context Connected");
    /* 7A   Remote UE Context Disconnected  Remote UE context list 9.9.4.20 O   TLV-E 3-65538 */
    ELEM_OPT_TLV_E(0x7A, NAS_PDU_TYPE_ESM, DE_ESM_REMOTE_UE_CONTEXT_LIST, " - Remote UE Context Disconnected");
    /* 6F   ProSe Key Management Function address  PKMF address 9.9.4.21 O   TLV 3-19 */
    ELEM_OPT_TLV(0x6F, NAS_PDU_TYPE_ESM, DE_ESM_PKMF_ADDRESS, " - ProSe Key Management Function address");

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}
/*
 * 8.3.24 Remote UE report response
 */
static void
nas_esm_remote_ue_report_resp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    /*guint32 consumed;*/
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    pinfo->link_dir = P2P_DIR_DL;

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}
/*
 * 8.3.25 ESM data transport
 */
static void
nas_esm_data_transport(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    /* User data container  User data container 9.9.4.24 M  LV-E  2-n */
    ELEM_MAND_LV_E(NAS_PDU_TYPE_ESM, DE_ESM_USER_DATA_CONT, NULL);
    /* F-  Release assistance indication  Release assistance indication 9.9.4.25 O  TV  1 */
    ELEM_OPT_TV_SHORT(0xF0, NAS_PDU_TYPE_ESM, DE_ESM_REL_ASSIST_IND, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_eps_extraneous_data);
}

#define NUM_NAS_MSG_ESM (sizeof(nas_msg_esm_strings)/sizeof(value_string))
static gint ett_nas_msg_esm[NUM_NAS_MSG_ESM];
static void (*nas_msg_esm_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len) = {
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
    nas_esm_dummy_msg,                  /* ESM dummy message */
    nas_esm_status,                     /* ESM status */
    nas_esm_remote_ue_report,           /* Remote UE report */
    nas_esm_remote_ue_report_resp,      /* Remote UE report response */
    nas_esm_data_transport,             /* ESM data transport */

    NULL,   /* NONE */
};

static void
get_nas_esm_msg_params(guint8 oct, const gchar **msg_str, int *ett_tree, int *hf_idx, msg_fcn *msg_fcn_p)
{
    gint            idx;

    *msg_str   = try_val_to_str_idx_ext((guint32) (oct & 0xff), &nas_msg_esm_strings_ext, &idx);
    *hf_idx    = hf_nas_eps_msg_esm_type;
    if (*msg_str != NULL) {
        *ett_tree  = ett_nas_msg_esm[idx];
        *msg_fcn_p = nas_msg_esm_fcn[idx];
    }

    return;
}



#define NUM_NAS_MSG_EMM (sizeof(nas_msg_emm_strings)/sizeof(value_string))
static gint ett_nas_msg_emm[NUM_NAS_MSG_EMM];
static void (*nas_msg_emm_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len) = {
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
    nas_emm_ctrl_plane_serv_req,/* Control plane servire request */
    nas_emm_serv_rej,           /* Service reject */
    nas_emm_serv_accept,        /* Service accept */

    nas_emm_guti_realloc_cmd,   /* GUTI reallocation command */
    NULL,                       /* GUTI reallocation complete (No IE's) */
    nas_emm_auth_req,           /* Authentication request */
    nas_emm_auth_resp,          /* Authentication response */
    NULL,                       /* Authentication reject (No IE:s)*/
    nas_emm_id_req,             /* Identity request */
    nas_emm_id_res,             /* Identity response */
    nas_emm_auth_fail,          /* Authentication failure */
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

    *msg_str   = try_val_to_str_idx_ext((guint32) (oct & 0xff), &nas_msg_emm_strings_ext, &idx);
    *hf_idx    = hf_nas_eps_msg_emm_type;
    if (*msg_str != NULL) {
        *ett_tree  = ett_nas_msg_emm[idx];
        *msg_fcn_p = nas_msg_emm_fcn[idx];
    }

    return;
}

static const value_string nas_eps_esm_bearer_id_vals[] = {
    { 0x0,  "No EPS bearer identity assigned"},
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

/*
 * EPS session management messages.
 * A plain NAS message is pased to this function
 */
static void
disect_nas_eps_esm_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    const gchar *msg_str;
    guint32      len;
    gint         ett_tree;
    int          hf_idx;
    void       (*msg_fcn_p)(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len);
    guint8       oct;

    len = tvb_reported_length(tvb);
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

    /*message type IE*/
    oct = tvb_get_guint8(tvb,offset);
    msg_fcn_p = NULL;
    ett_tree = -1;
    hf_idx = -1;
    msg_str = NULL;

    get_nas_esm_msg_params(oct, &msg_str, &ett_tree, &hf_idx, &msg_fcn_p);

    if (msg_str) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, msg_str);
    } else {
        proto_tree_add_expert_format(tree, pinfo, &ei_nas_eps_unknown_msg_type, tvb, offset, 1, "Unknown Message Type 0x%02x", oct);
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
            proto_tree_add_item(tree, hf_nas_eps_msg_elems, tvb, offset, len - offset, ENC_NA);
        }
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
    const gchar *msg_str;
    guint32      len;
    gint         ett_tree;
    int          hf_idx;
    void       (*msg_fcn_p)(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len);
    guint8       security_header_type, oct;

    len = tvb_reported_length(tvb);

    /* 9.3.1    Security header type */
    if (second_header) {
        security_header_type = tvb_get_guint8(tvb,offset)>>4;
        proto_tree_add_item(tree, hf_nas_eps_security_header_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_gsm_a_L3_protocol_discriminator, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        if (security_header_type != 0) {
            /* Message authentication code */
            proto_tree_add_item(tree, hf_nas_eps_msg_auth_code, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            /* Sequence number */
            proto_tree_add_item(tree, hf_nas_eps_seq_no, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            if ((security_header_type == 2)||(security_header_type == 4))
                /* Integrity protected and ciphered = 2, Integrity protected and ciphered with new EPS security context = 4 */
                return;
            proto_tree_add_item(tree, hf_nas_eps_security_header_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_gsm_a_L3_protocol_discriminator, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
        }
    }
    /* Message type IE*/
    oct = tvb_get_guint8(tvb,offset);
    msg_fcn_p = NULL;
    ett_tree = -1;
    hf_idx = -1;
    msg_str = NULL;

    get_nas_emm_msg_params(oct, &msg_str, &ett_tree, &hf_idx, &msg_fcn_p);

    if (msg_str) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, msg_str);
    } else {
        proto_tree_add_expert_format(tree, pinfo, &ei_nas_eps_unknown_msg_type, tvb, offset, 1, "Unknown Message Type 0x%02x", oct);
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
            proto_tree_add_item(tree, hf_nas_eps_msg_elems, tvb, offset, len - offset, ENC_NA);
        }
    }
    else
    {
        (*msg_fcn_p)(tvb, tree, pinfo, offset, len - offset);
    }

}

static int
dissect_nas_eps_plain(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *item;
    proto_tree *nas_eps_tree;
    guint8      pd;
    int         offset = 0;

    /* make entry in the Protocol column on summary display */
    col_append_sep_str(pinfo->cinfo, COL_PROTOCOL, "/", "NAS-EPS");

    item = proto_tree_add_item(tree, proto_nas_eps, tvb, 0, -1, ENC_NA);
    nas_eps_tree = proto_item_add_subtree(item, ett_nas_eps);

    /* SERVICE REQUEST (security header type equal to 12 or greater) is not a plain NAS message */
    pd = tvb_get_guint8(tvb,offset);
    if (((pd&0x0f) == 0x07) && ((pd&0xf0) >= 0xc0)) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Service request");
        /* Security header type Security header type 9.3.1 M V 1/2 */
        proto_tree_add_item(nas_eps_tree, hf_nas_eps_security_header_type, tvb, 0, 1, ENC_BIG_ENDIAN);
        /* Protocol discriminator Protocol discriminator 9.2 M V 1/2 */
        proto_tree_add_item(nas_eps_tree, hf_gsm_a_L3_protocol_discriminator, tvb, 0, 1, ENC_BIG_ENDIAN);
        offset++;
        nas_emm_service_req(tvb, nas_eps_tree, pinfo, offset, tvb_reported_length(tvb)-offset);
        return tvb_captured_length(tvb);
    }

    pd &= 0x0f;
    switch (pd) {
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
            if (gsm_a_dtap_handle) {
                tvbuff_t *new_tvb = tvb_new_subset_remaining(tvb, offset);
                call_dissector(gsm_a_dtap_handle, new_tvb,pinfo, nas_eps_tree);
                break;
            } /* else fall through default */
        default:
            proto_tree_add_expert_format(nas_eps_tree, pinfo, &ei_nas_eps_unknown_pd, tvb, offset, -1, "Not a NAS EPS PD %u (%s)",
                                         pd, val_to_str_const(pd, protocol_discriminator_vals, "Unknown"));
            break;
    }

    return tvb_captured_length(tvb);
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
 * All messages received here will have the security header:
 *  Figure 9.1.2: General message organization example for a security protected NAS message
 *      9.3.1 Bits 5 to 8 of the first octet of every EPS Mobility Management (EMM)
 *            message contain the Security header type IE.
 *      4.4.4.2 All ESM messages are integrity protected.
 */

static int
dissect_nas_eps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *item;
    proto_tree *nas_eps_tree;
    guint8      pd, security_header_type;
    int         offset = 0;
    guint32     len;
    guint32     msg_auth_code;

    len = tvb_reported_length(tvb);
    /* The protected NAS message header is 6 octets long, and the NAS message header is at least 2 octets long. */
    /* If the length of the tvbuffer is less than 8 octets, we can safely conclude the message is not protected. */
    if (len < 8) {
        dissect_nas_eps_plain(tvb, pinfo, tree, data);
        return tvb_captured_length(tvb);
    }

    if (g_nas_eps_dissect_plain) {
        dissect_nas_eps_plain(tvb, pinfo, tree, data);
        return tvb_captured_length(tvb);
    }

    /* make entry in the Protocol column on summary display */
    col_append_sep_str(pinfo->cinfo, COL_PROTOCOL, "/", "NAS-EPS");

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
    if (security_header_type == 0) {
        if (pd == 7) {
            /* Plain EPS mobility management messages. */
            dissect_nas_eps_emm_msg(tvb, pinfo, nas_eps_tree, offset, FALSE);
            return tvb_captured_length(tvb);
        } else {
            proto_tree_add_expert(nas_eps_tree, pinfo, &ei_nas_eps_esm_tp_not_integ_prot, tvb, offset, len);
            return tvb_captured_length(tvb);
        }
    } else {
        /* SERVICE REQUEST (12 or greater) is not a plain NAS message treat separately */
        if (security_header_type >= 12) {
            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Service request");
            nas_emm_service_req(tvb, nas_eps_tree, pinfo, offset, len-offset);
            return tvb_captured_length(tvb);
        }
        /* Message authentication code */
        proto_tree_add_item(nas_eps_tree, hf_nas_eps_msg_auth_code, tvb, offset, 4, ENC_BIG_ENDIAN);
        msg_auth_code = tvb_get_ntohl(tvb, offset);
        offset+=4;
        if ((security_header_type == 2)||(security_header_type == 4)) {
            /* Possible ciphered message */
            if (msg_auth_code != 0) {
                /* Sequence number  Sequence number 9.6 M   V   1 */
                proto_tree_add_item(nas_eps_tree, hf_nas_eps_seq_no, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
                /* Integrity protected and ciphered = 2, Integrity protected and ciphered with new EPS security context = 4 */
                /* Read security_header_type / EPS bearer id AND pd */
                pd = tvb_get_guint8(tvb,offset);
                /* If pd is in plaintext this message probably isn't ciphered */
                /* Use preferences settings to override this behavior */
                if (!g_nas_eps_null_decipher ||
                    ((pd != 7) && (pd != 15) &&
                    (((pd&0x0f) != 2) || (((pd&0x0f) == 2) && ((pd&0xf0) > 0) && ((pd&0xf0) < 0x50))))) {
                    proto_tree_add_item(nas_eps_tree, hf_nas_eps_ciphered_msg, tvb, offset, len-6, ENC_NA);
                    return tvb_captured_length(tvb);
                }
            } else {
                /* msg_auth_code == 0, probably not ciphered */
                /* Sequence number  Sequence number 9.6 M   V   1 */
                proto_tree_add_item(nas_eps_tree, hf_nas_eps_seq_no, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
            }
        } else {
            /* Sequence number  Sequence number 9.6 M   V   1 */
            proto_tree_add_item(nas_eps_tree, hf_nas_eps_seq_no, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
        }
    }
    /* NAS message  NAS message 9.7 M   V   1-n  */

    pd = tvb_get_guint8(tvb,offset)&0x0f;
    switch (pd) {
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
            if (gsm_a_dtap_handle) {
                tvbuff_t *new_tvb = tvb_new_subset_remaining(tvb, offset);
                call_dissector(gsm_a_dtap_handle, new_tvb, pinfo, nas_eps_tree);
                break;
            } /* else fall through default */
        default:
            proto_tree_add_expert_format(nas_eps_tree, pinfo, &ei_nas_eps_unknown_pd, tvb, offset, -1, "Not a NAS EPS PD %u (%s)",
                             pd, val_to_str_const(pd, protocol_discriminator_vals, "Unknown"));
            break;
    }

    return tvb_captured_length(tvb);
}

void
proto_register_nas_eps(void)
{
    guint     i;
    guint     last_offset;
    module_t *nas_eps_module;

    /* List of fields */

  static hf_register_info hf[] = {
    { &hf_nas_eps_msg_emm_type,
        { "NAS EPS Mobility Management Message Type",   "nas_eps.nas_msg_emm_type",
        FT_UINT8, BASE_HEX|BASE_EXT_STRING, &nas_msg_emm_strings_ext, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_common_elem_id,
        { "Element ID", "nas_eps.common.elem_id",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_elem_id,
        { "Element ID", "nas_eps.emm.elem_id",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
    { &hf_nas_eps_bearer_id,
        { "EPS bearer identity",    "nas_eps.bearer_id",
        FT_UINT8, BASE_DEC, VALS(nas_eps_esm_bearer_id_vals), 0xf0,
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
    { &hf_nas_eps_ciphered_msg,
        { "Ciphered message","nas_eps.ciphered_msg",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_msg_elems,
        { "Message Elements", "nas_eps.message_elements",
        FT_BYTES, BASE_NONE, NULL, 0x0,
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
        FT_BOOLEAN, BASE_NONE, TFS(&nas_eps_emm_paging_id_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_ext_emm_cause,
        { "Extended EMM cause","nas_eps.emm.ext_emm_cause",
        FT_BOOLEAN, BASE_NONE, TFS(&nas_eps_ext_emm_cause), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_eps_att_type,
        { "EPS attach type","nas_eps.emm.eps_att_type",
        FT_UINT8,BASE_DEC, VALS(nas_eps_emm_eps_att_type_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_cp_ciot,
        { "Control plane CIoT EPS optimization","nas_eps.emm.cp_ciot",
        FT_BOOLEAN ,BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_er_wo_pdn,
        { "EMM-REGISTERED w/o PDN connectivity","nas_eps.emm.er_wo_pdn",
        FT_BOOLEAN ,BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_esr_ps,
        { "Support of EXTENDED SERVICE REQUEST for packet services","nas_eps.emm.esr_ps",
        FT_BOOLEAN ,BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_cs_lcs,
        { "CS-LCS","nas_eps.emm.cs_lcs",
        FT_UINT8, BASE_DEC, VALS(nas_eps_emm_cs_lcs_vals), 0x0,
        "Location services indicator in CS", HFILL }
    },
    { &hf_nas_eps_emm_epc_lcs,
        { "Location services via EPC","nas_eps.emm.epc_lcs",
        FT_BOOLEAN ,BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_emc_bs,
        { "Emergency bearer services in S1 mode","nas_eps.emm.emc_bs",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_ims_vops,
        { "IMS voice over PS session in S1 mode","nas_eps.emm.ims_vops",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_epco,
        { "Extended protocol configuration options IE","nas_eps.emm.epco",
        FT_BOOLEAN ,BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_hc_cp_ciot,
        { "Header compression for control plane CIoT EPS optimization","nas_eps.emm.hc_cp_ciot",
        FT_BOOLEAN ,BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_s1_u_data,
        { "S1-u data transfer","nas_eps.emm.s1_u_data",
        FT_BOOLEAN ,BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_up_ciot,
        { "User plane CIoT EPS optimization","nas_eps.emm.up_ciot",
        FT_BOOLEAN ,BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_tsc,
        { "Type of security context flag (TSC)","nas_eps.emm.tsc",
        FT_BOOLEAN,BASE_DEC, TFS(&nas_eps_tsc_value), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_nas_key_set_id,
        { "NAS key set identifier","nas_eps.emm.nas_key_set_id",
        FT_UINT8,BASE_DEC, VALS(nas_eps_emm_NAS_key_set_identifier_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_odd_even,
        { "Odd/even indication","nas_eps.emm.odd_even",
        FT_BOOLEAN, 8, TFS(&nas_eps_odd_even_value), 0x8,
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
    { &hf_nas_eps_emm_anb_up_ciot,
        { "Accepted Network Behavior UP CIoT","nas_eps.emm.anb_up_ciot",
        FT_BOOLEAN, BASE_NONE, TFS(&nas_eps_emm_anb_up_ciot_value), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_anb_cp_ciot,
        { "Accepted Network Behavior CP CIoT","nas_eps.emm.anb_cp_ciot",
        FT_BOOLEAN, BASE_NONE, TFS(&nas_eps_emm_anb_cp_ciot_value), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_add_upd_res,
        { "AURV","nas_eps.emm.add_upd_res",
        FT_UINT8, BASE_DEC, VALS(nas_eps_emm_add_upd_res_vals), 0x0,
        "Additional update result value", HFILL }
    },
    { &hf_nas_eps_emm_pnb_ciot,
        { "Preferred CIoT network behaviour","nas_eps.emm.pnb_ciot",
        FT_UINT8, BASE_DEC, VALS(nas_eps_emm_pnb_ciot_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_saf,
        { "SAF","nas_eps.emm.saf",
        FT_BOOLEAN, BASE_NONE, TFS(&nas_eps_emm_saf_value), 0x0,
        "Signalling active flag", HFILL }
    },
    { &hf_nas_eps_emm_add_upd_type,
        { "AUTV","nas_eps.emm.add_upd_type",
        FT_BOOLEAN, BASE_NONE, TFS(&nas_eps_emm_add_upd_type_value), 0x0,
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
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &nas_eps_emm_cause_values_ext, 0x0,
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
        FT_UINT16, BASE_DEC,  NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_eea0,
        { "EEA0","nas_eps.emm.eea0",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_128eea1,
        { "128-EEA1","nas_eps.emm.128eea1",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_128eea2,
        { "128-EEA2","nas_eps.emm.128eea2",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_eea3,
        { "128-EEA3","nas_eps.emm.eea3",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_eea4,
        { "EEA4","nas_eps.emm.eea4",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_eea5,
        { "EEA5","nas_eps.emm.eea5",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_eea6,
        { "EEA6","nas_eps.emm.eea6",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_eea7,
        { "EEA7","nas_eps.emm.eea7",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_eia0,
        { "EIA0","nas_eps.emm.eia0",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_128eia1,
        { "128-EIA1","nas_eps.emm.128eia1",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_128eia2,
        { "128-EIA2","nas_eps.emm.128eia2",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_eia3,
        { "128-EIA3","nas_eps.emm.eia3",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_eia4,
        { "EIA4","nas_eps.emm.eia4",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_eia5,
        { "EIA5","nas_eps.emm.eia5",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_eia6,
        { "EIA6","nas_eps.emm.eia6",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_eia7,
        { "EIA7","nas_eps.emm.eia7",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
        NULL, HFILL }
    },


    { &hf_nas_eps_emm_uea0,
        { "UEA0","nas_eps.emm.uea0",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_uea1,
        { "UEA1","nas_eps.emm.uea1",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_uea2,
        { "UEA2","nas_eps.emm.uea2",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_uea3,
        { "UEA3","nas_eps.emm.uea3",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_uea4,
        { "UEA4","nas_eps.emm.uea4",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_uea5,
        { "UEA5","nas_eps.emm.uea5",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_uea6,
        { "UEA6","nas_eps.emm.uea6",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_uea7,
        { "UEA7","nas_eps.emm.uea7",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_ucs2_supp,
        { "UCS2 support (UCS2)","nas_eps.emm.emm_ucs2_supp",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_ucs2_supp_flg_value), 0x80,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_uia1,
        { "UMTS integrity algorithm UIA1","nas_eps.emm.uia1",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_uia2,
        { "UMTS integrity algorithm UIA2","nas_eps.emm.uia2",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_uia3,
        { "UMTS integrity algorithm UIA3","nas_eps.emm.uia3",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_uia4,
        { "UMTS integrity algorithm UIA4","nas_eps.emm.uia4",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_uia5,
        { "UMTS integrity algorithm UIA5","nas_eps.emm.uia5",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_uia6,
        { "UMTS integrity algorithm UIA6","nas_eps.emm.uia6",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_uia7,
        { "UMTS integrity algorithm UIA7","nas_eps.emm.uia7",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_gea1,
        { "GPRS encryption algorithm GEA1","nas_eps.emm.gea1",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_gea2,
        { "GPRS encryption algorithm GEA2","nas_eps.emm.gea2",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_gea3,
        { "GPRS encryption algorithm GEA3","nas_eps.emm.gea3",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_gea4,
        { "GPRS encryption algorithm GEA4","nas_eps.emm.gea4",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_gea5,
        { "GPRS encryption algorithm GEA5","nas_eps.emm.gea5",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_gea6,
        { "GPRS encryption algorithm GEA6","nas_eps.emm.gea6",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_gea7,
        { "GPRS encryption algorithm GEA7","nas_eps.emm.gea7",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_prose_dd_cap,
        { "ProSe direct discovery","nas_eps.emm.prose_dd_cap",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_prose_cap,
        { "ProSe","nas_eps.emm.prose_cap",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_h245_ash_cap,
        { "H.245 After SRVCC Handover","nas_eps.emm.h245_ash_cap",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_acc_csfb_cap,
        { "Access class control for CSFB","nas_eps.emm.acc_csfb_cap",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_lpp_cap,
        { "LTE Positioning Protocol","nas_eps.emm.lpp_cap",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_lcs_cap,
        { "Location services (LCS) notification mechanisms","nas_eps.emm.lcs_cap",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_1xsrvcc_cap,
        { "SRVCC from E-UTRAN to cdma2000 1xCS","nas_eps.emm.1xsrvcc_cap",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_nf_cap,
        { "Notification procedure","nas_eps.emm.nf_cap",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_epco_cap,
        { "Extended protocol configuration options","nas_eps.emm.epco_cap",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_hc_cp_ciot_cap,
        { "Header compression for control plane CIoT EPS optimization","nas_eps.emm.hc_cp_ciot_cap",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_er_wo_pdn_cap,
        { "EMM-REGISTERED w/o PDN connectivity","nas_eps.emm.er_wo_pdn_cap",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_s1u_data_cap,
        { "S1-U data transfer","nas_eps.emm.s1u_data_cap",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_up_ciot_cap,
        { "User plane CIoT EPS optimization","nas_eps.emm.up_ciot_cap",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_cp_ciot_cap,
        { "Control plane CIoT EPS optimization","nas_eps.emm.cp_ciot_cap",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_prose_relay_cap,
        { "ProSe UE-to-network relay","nas_eps.emm.prose_relay_cap",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_prose_dc_cap,
        { "ProSe direct communication","nas_eps.emm.prose_dc_cap",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_ue_ra_cap_inf_upd_need_flg,
        { "URC upd","nas_eps.emm.ue_ra_cap_inf_upd_need_flg",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_ue_ra_cap_inf_upd_need_flg), 0x01,
        "UE radio capability information update needed flag", HFILL }
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
        FT_UINT8,BASE_DEC|BASE_RANGE_STRING, RVALS(nas_eps_emm_gen_msg_cont_type_vals), 0x0,
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
        { "APN-AMBR for uplink (extended)","nas_eps.emm.apn_ambr_ul_ext",
        FT_UINT8,BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_apn_ambr_dl_ext,
        { "APN-AMBR for downlink (extended)","nas_eps.emm.apn_ambr_dl_ext",
        FT_UINT8,BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_apn_ambr_ul_ext2,
        { "APN-AMBR for uplink (extended-2)","nas_eps.emm.apn_ambr_ul_ext2",
        FT_UINT8,BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_apn_ambr_dl_ext2,
        { "APN-AMBR for downlink (extended-2)","nas_eps.emm.apn_ambr_dl_ext2",
        FT_UINT8,BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_apn_ambr_ul_total,
        { "Total APN-AMBR for uplink","nas_eps.emm.apn_ambr_ul_total",
        FT_UINT8,BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_apn_ambr_dl_total,
        { "Total APN-AMBR for downlink","nas_eps.emm.apn_ambr_dl_total",
        FT_UINT8,BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_guti_type,
        { "GUTI type", "nas_eps.emm.guti_type",
        FT_BOOLEAN, BASE_NONE, TFS(&nas_eps_emm_guti_type_value), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_detach_req_UL,
        { "Uplink","nas_eps.emm.detach_req_ul",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_detach_req_DL,
        { "Downlink","nas_eps.emm.detach_req_dl",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_switch_off,
        { "Switch off","nas_eps.emm.switch_off",
        FT_UINT8,BASE_DEC, VALS(nas_eps_emm_switch_off_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_detach_type_UL,
        { "Detach Type","nas_eps.emm.detach_type_ul",
        FT_UINT8,BASE_DEC, VALS(nas_eps_emm_type_of_detach_UL_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_emm_detach_type_DL,
        { "Detach Type","nas_eps.emm.detach_type_dl",
        FT_UINT8,BASE_DEC, VALS(nas_eps_emm_type_of_detach_DL_vals), 0x0,
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
        FT_UINT8,BASE_DEC|BASE_EXT_STRING, &nas_eps_esm_cause_vals_ext, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_eit,
        { "EIT (ESM information transfer)", "nas_eps.emm.eit",
        FT_BOOLEAN, 8, TFS(&nas_eps_emm_eit_vals), 0x01,
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
    { &hf_nas_eps_esm_eplmnc,
        { "EPLMNC", "nas_eps.esm.eplmnc",
        FT_BOOLEAN, 8, TFS(&nas_eps_esm_eplmnc_value), 0x02,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_ratc,
        { "RATC", "nas_eps.esm.ratc",
        FT_BOOLEAN, 8, TFS(&nas_eps_esm_ratc_value), 0x01,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_linked_bearer_id,
        { "Linked EPS bearer identity","nas_eps.esm.linked_bearer_id",
        FT_UINT8,BASE_DEC, VALS(nas_eps_esm_linked_bearer_id_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_nbifom_cont,
        { "NBIFOM container content","nas_eps.esm.nbifom_cont",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_remote_ue_context_list_nb_ue_contexts,
        { "Number of remote UE contexts","nas_eps.esm.remote_ue_context_list.nb_ue_contexts",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_remote_ue_context_list_ue_context_len,
        { "Length of remote UE context","nas_eps.esm.remote_ue_context_list.ue_context.len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_remote_ue_context_list_ue_context_nb_user_id,
        { "Number of user identities","nas_eps.esm.remote_ue_context_list.ue_context.nb_user_id",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_remote_ue_context_list_ue_context_user_id_len,
        { "Length of user identity","nas_eps.esm.remote_ue_context_list.ue_context.user_id_len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_remote_ue_context_list_ue_context_odd_even_indic,
        { "Odd/even indication","nas_eps.esm.remote_ue_context_list.ue_context.odd_even_indic",
        FT_BOOLEAN, 8, TFS(&nas_eps_odd_even_value), 0x08,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_remote_ue_context_list_ue_context_user_id_type,
        { "Type of user identity","nas_eps.esm.remote_ue_context_list.ue_context.user_id_type",
        FT_UINT8, BASE_DEC, VALS(nas_eps_esm_user_info_type_values), 0x07,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_remote_ue_context_list_ue_context_encr_imsi,
        { "Encrypted IMSI", "nas_eps.esm.remote_ue_context_list.ue_context.encr_imsi",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_remote_ue_context_list_ue_context_msisdn,
        { "MSISDN", "nas_eps.esm.remote_ue_context_list.ue_context.msisdn",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_remote_ue_context_list_ue_context_imei,
        { "IMEI", "nas_eps.esm.remote_ue_context_list.ue_context.imei",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_remote_ue_context_list_ue_context_imeisv,
        { "IMEISV", "nas_eps.esm.remote_ue_context_list.ue_context.imeisv",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_remote_ue_context_list_ue_context_address_type,
        { "Address type","nas_eps.esm.remote_ue_context_list.ue_context.address_type",
        FT_UINT8, BASE_DEC, VALS(nas_eps_esm_address_type_values), 0x07,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_remote_ue_context_list_ue_context_ipv4,
        { "IPv4 address","nas_eps.esm.remote_ue_context_list.ue_context.ipv4",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_remote_ue_context_list_ue_context_port_number,
        { "Port number","nas_eps.esm.remote_ue_context_list.ue_context.port_number",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_remote_ue_context_list_ue_context_ipv6_prefix,
        { "IPv6 prefix","nas_eps.esm.remote_ue_context_list.ue_context.ipv6_prefix",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_pkmf_address_type,
        { "Address type","nas_eps.esm.pkmf.address_type",
        FT_UINT8, BASE_DEC, VALS(nas_eps_esm_pkmf_address_type_values), 0x07,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_pkmf_ipv4,
        { "IPv4 address","nas_eps.esm.pkmf.ipv4",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_pkmf_ipv6,
        { "IPv6 address","nas_eps.esm.pkmf.ipv6",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_spare_bit0x80,
        { "Spare bit(s)", "nas_eps.spare_bits",
        FT_UINT8, BASE_HEX, NULL, 0x80,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_hdr_comp_config_prof_0104,
        { "RoHC profile 0x0104 (IP)", "nas_eps.esm.hdr_comp_config.prof_0104",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_hdr_comp_config_prof_0103,
        { "RoHC profile 0x0103 (ESP/IP)", "nas_eps.esm.hdr_comp_config.prof_0103",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_hdr_comp_config_prof_0102,
        { "RoHC profile 0x0102 (UDP/IP)", "nas_eps.esm.hdr_comp_config.prof_0102",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_hdr_comp_config_prof_0006,
        { "RoHC profile 0x0006 (TCP/IP)", "nas_eps.esm.hdr_comp_config.prof_0006",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_hdr_comp_config_prof_0004,
        { "RoHC profile 0x0004 (IP)", "nas_eps.esm.hdr_comp_config.prof_0004",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_hdr_comp_config_prof_0003,
        { "RoHC profile 0x0003 (ESP/IP)", "nas_eps.esm.hdr_comp_config.prof_0003",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_hdr_comp_config_prof_0002,
        { "RoHC profile 0x0002 (UDP/IP)", "nas_eps.esm.hdr_comp_config.prof_0002",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_hdr_compr_config_max_cid,
        { "MAX_CID", "nas_eps.esm.hdr_comp_config.max_cid",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_ctrl_plane_only_ind_cpoi,
        { "CPOI", "nas_eps.esm.ctrl_plane_only_ind.cpoi",
        FT_BOOLEAN, BASE_NONE, TFS(&nas_eps_ctrl_plane_only_ind_cpoi_value), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_user_data_cont,
        { "User data contents", "nas_eps.esm.user_data_cont",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_rel_assist_ind_ddx,
        { "Downlink data expected","nas_eps.esm.rel_assist_ind.ddx",
        FT_UINT8, BASE_DEC, VALS(nas_eps_esm_rel_assist_ind_ddx_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_hdr_compr_config_status_ebi7,
        { "EBI(7)", "nas_eps.esm.hdr_compr_config_status.ebi7",
        FT_BOOLEAN, 16, TFS(&nas_eps_esm_hdr_compr_config_status_ebi_value), 0x8000,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_hdr_compr_config_status_ebi6,
        { "EBI(6)", "nas_eps.esm.hdr_compr_config_status.ebi6",
        FT_BOOLEAN, 16, TFS(&nas_eps_esm_hdr_compr_config_status_ebi_value), 0x4000,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_hdr_compr_config_status_ebi5,
        { "EBI(5)", "nas_eps.esm.hdr_compr_config_status.ebi5",
        FT_BOOLEAN, 16, TFS(&nas_eps_esm_hdr_compr_config_status_ebi_value), 0x2000,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_spare_bits0x1f00,
        { "Spare bit(s)", "nas_eps.spare_bits",
        FT_UINT16, BASE_HEX, NULL, 0x1f00,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_hdr_compr_config_status_ebi15,
        { "EBI(15)", "nas_eps.esm.hdr_compr_config_status.ebi15",
        FT_BOOLEAN, 16, TFS(&nas_eps_esm_hdr_compr_config_status_ebi_value), 0x0080,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_hdr_compr_config_status_ebi14,
        { "EBI(14)", "nas_eps.esm.hdr_compr_config_status.ebi14",
        FT_BOOLEAN, 16, TFS(&nas_eps_esm_hdr_compr_config_status_ebi_value), 0x0040,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_hdr_compr_config_status_ebi13,
        { "EBI(13)", "nas_eps.esm.hdr_compr_config_status.ebi13",
        FT_BOOLEAN, 16, TFS(&nas_eps_esm_hdr_compr_config_status_ebi_value), 0x0020,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_hdr_compr_config_status_ebi12,
        { "EBI(12)", "nas_eps.esm.hdr_compr_config_status.ebi12",
        FT_BOOLEAN, 16, TFS(&nas_eps_esm_hdr_compr_config_status_ebi_value), 0x0010,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_hdr_compr_config_status_ebi11,
        { "EBI(11)", "nas_eps.esm.hdr_compr_config_status.ebi11",
        FT_BOOLEAN, 16, TFS(&nas_eps_esm_hdr_compr_config_status_ebi_value), 0x0008,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_hdr_compr_config_status_ebi10,
        { "EBI(10)", "nas_eps.esm.hdr_compr_config_status.ebi10",
        FT_BOOLEAN, 16, TFS(&nas_eps_esm_hdr_compr_config_status_ebi_value), 0x0004,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_hdr_compr_config_status_ebi9,
        { "EBI(9)", "nas_eps.esm.hdr_compr_config_status.ebi9",
        FT_BOOLEAN, 16, TFS(&nas_eps_esm_hdr_compr_config_status_ebi_value), 0x0002,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_hdr_compr_config_status_ebi8,
        { "EBI(8)", "nas_eps.esm.hdr_compr_config_status.ebi8",
        FT_BOOLEAN, 16, TFS(&nas_eps_esm_hdr_compr_config_status_ebi_value), 0x0001,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_serv_plmn_rate_ctrl_val,
        { "Serving PLMN rate control value", "nas_eps.esm.serv_plmn_rate_ctrl_val",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_active_flg,
        { "Active flag", "nas_eps.emm.active_flg",
        FT_BOOLEAN, BASE_NONE, TFS(&nas_eps_emm_active_flg_value), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_data_serv_type,
        { "Data service type", "nas_eps.emm.data_serv_type",
        FT_UINT8, BASE_DEC, VALS(nas_eps_emm_data_serv_type_vals), 0x0,
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
        FT_UINT8,BASE_DEC|BASE_RANGE_STRING, RVALS(nas_eps_service_type_vals), 0x0,
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
        FT_UINT8, BASE_HEX|BASE_EXT_STRING, &nas_msg_esm_strings_ext, 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_elem_id,
        { "Element ID", "nas_eps.esm.elem_id",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_proc_trans_id,
        { "Procedure transaction identity", "nas_eps.esm.proc_trans_id",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_pdn_type,
        { "PDN type",   "nas_eps.esm_pdn_type",
        FT_UINT8, BASE_DEC, VALS(nas_eps_esm_pdn_type_values), 0x0,
        NULL, HFILL }
    },
    { &hf_nas_eps_esm_request_type,
        { "Request type", "nas_eps.esm_request_type",
        FT_UINT8, BASE_DEC, VALS(nas_eps_esm_request_type_values), 0x0,
        NULL, HFILL }
    },
  };

    static ei_register_info ei[] = {
        { &ei_nas_eps_extraneous_data, { "nas_eps.extraneous_data", PI_PROTOCOL, PI_NOTE, "Extraneous Data, dissector bug or later version spec(report to wireshark.org)", EXPFILL }},
        { &ei_nas_eps_unknown_identity, { "nas_eps.emm.unknown_identity", PI_PROTOCOL, PI_WARN, "Type of identity not known", EXPFILL }},
        { &ei_nas_eps_unknown_type_of_list, { "nas_eps.emm.tai_unknown_list_type", PI_PROTOCOL, PI_WARN, "Unknown type of list", EXPFILL }},
        { &ei_nas_eps_wrong_nb_of_elems, { "nas_eps.emm.tai_wrong_number_of_elems", PI_PROTOCOL, PI_ERROR, "[Wrong number of elements?]", EXPFILL }},
        { &ei_nas_eps_unknown_msg_type, { "nas_eps.unknown_msg_type", PI_PROTOCOL, PI_WARN, "Unknown Message Type", EXPFILL }},
        { &ei_nas_eps_unknown_pd, { "nas_eps.unknown_pd", PI_PROTOCOL, PI_ERROR, "Unknown protocol discriminator", EXPFILL }},
        { &ei_nas_eps_esm_tp_not_integ_prot, { "nas_eps.esm_tp_not_integrity_protected", PI_PROTOCOL, PI_ERROR, "All ESM / Test Procedures messages should be integrity protected", EXPFILL }}
    };

    expert_module_t* expert_nas_eps;

    /* Setup protocol subtree array */
#define NUM_INDIVIDUAL_ELEMS    6
    gint *ett[NUM_INDIVIDUAL_ELEMS +
          NUM_NAS_EPS_COMMON_ELEM +
          NUM_NAS_MSG_EMM + NUM_NAS_EMM_ELEM+
          NUM_NAS_MSG_ESM + NUM_NAS_ESM_ELEM];

    ett[0] = &ett_nas_eps;
    ett[1] = &ett_nas_eps_esm_msg_cont;
    ett[2] = &ett_nas_eps_nas_msg_cont;
    ett[3] = &ett_nas_eps_gen_msg_cont;
    ett[4] = &ett_nas_eps_cmn_add_info;
    ett[5] = &ett_nas_eps_remote_ue_context;

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
    expert_nas_eps = expert_register_protocol(proto_nas_eps);
    expert_register_field_array(expert_nas_eps, ei, array_length(ei));

    /* Register dissector */
    register_dissector(PFNAME, dissect_nas_eps, proto_nas_eps);

    /* Register dissector */
    register_dissector("nas-eps_plain", dissect_nas_eps_plain, proto_nas_eps);

    /* Register configuration options to always dissect as plain messages */
    nas_eps_module = prefs_register_protocol(proto_nas_eps, NULL);

    prefs_register_bool_preference(nas_eps_module,
                                   "dissect_plain",
                                   "Force dissect as plain NAS EPS",
                                   "Always dissect NAS EPS messages as plain",
                                   &g_nas_eps_dissect_plain);

    prefs_register_bool_preference(nas_eps_module,
                                   "null_decipher",
                                   "Try to detect and decode EEA0 ciphered messages",
                                   "This should work when the NAS security algorithm is NULL (128-EEA0).",
                                   &g_nas_eps_null_decipher);
}

void
proto_reg_handoff_nas_eps(void)
{
    gsm_a_dtap_handle = find_dissector_add_dependency("gsm_a_dtap", proto_nas_eps);
    lpp_handle = find_dissector_add_dependency("lpp", proto_nas_eps);
    nbifom_handle = find_dissector_add_dependency("nbifom", proto_nas_eps);
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
