/* packet-gtp.c
 *
 * $Id$
 *
 * Routines for GTP dissection
 * Copyright 2001, Michal Melerowicz <michal.melerowicz@nokia.com>
 *                 Nicolas Balkota <balkota@mac.com>
 *
 * Updates and corrections:
 * Copyright 2006 - 2009, Anders Broman <anders.broman@ericsson.com>
 *
 * Added Bearer control mode dissection:
 * Copyright 2011, Grzegorz Szczytowski <grzegorz.szczytowski@gmail.com>
 *
 * Updates and corrections:
 * Copyright 2011, Anders Broman <anders.broman@ericsson.com>
 *
 * PDCP PDU number extension header support added by Martin Isaksson <martin.isaksson@ericsson.com>
 *
 * Control Plane Request-Response tracking code Largely based on similar routines in
 * packet-ldap.c by Ronnie Sahlberg
 * Added by Kari Tiirikainen <kari.tiirikainen@nsn.com>
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
 * Ref: 3GPP TS 29.060
 * http://www.3gpp.org/ftp/Specs/html-info/29060.htm
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/sminmpec.h>
#include <epan/asn1.h>
#include <epan/tap.h>
#include "packet-ppp.h"
#include "packet-radius.h"
#include "packet-bssap.h"
#include "packet-gsm_a_common.h"
#include "packet-gsm_map.h"
#include "packet-gprscdr.h"
#include "packet-per.h"
#include "packet-ranap.h"
#include "packet-bssgp.h"
#include "packet-e212.h"
#include "packet-gtp.h"

static dissector_table_t ppp_subdissector_table;
static dissector_table_t gtp_priv_ext_dissector_table;
static dissector_table_t gtp_cdr_fmt_dissector_table;

#define GTPv0_PORT  3386
#define GTPv1C_PORT 2123    /* 3G Control PDU */
#define GTPv1U_PORT 2152    /* 3G T-PDU */

#define GTPv0_HDR_LENGTH     20
#define GTPv1_HDR_LENGTH     12
#define GTP_PRIME_HDR_LENGTH  6

/* to check compliance with ETSI  */
#define GTP_MANDATORY   1
#define GTP_OPTIONAL    2
#define GTP_CONDITIONAL 4

static gboolean g_gtp_over_tcp = TRUE;
static guint g_gtpv0_port  = GTPv0_PORT;
static guint g_gtpv1c_port = GTPv1C_PORT;
static guint g_gtpv1u_port = GTPv1U_PORT;

void proto_reg_handoff_gtp(void);

static int proto_gtp = -1;

/*KTi*/
static int hf_gtp_response_in = -1;
static int hf_gtp_response_to = -1;
static int hf_gtp_time = -1;
static int hf_gtp_apn = -1;
static int hf_gtp_cause = -1;
static int hf_gtp_chrg_char = -1;
static int hf_gtp_chrg_char_s = -1;
static int hf_gtp_chrg_char_n = -1;
static int hf_gtp_chrg_char_p = -1;
static int hf_gtp_chrg_char_f = -1;
static int hf_gtp_chrg_char_h = -1;
static int hf_gtp_chrg_char_r = -1;
static int hf_gtp_chrg_id = -1;
static int hf_gtp_chrg_ipv4 = -1;
static int hf_gtp_chrg_ipv6 = -1;
static int hf_gtp_ext_flow_label = -1;
static int hf_gtp_ext_id = -1;
static int hf_gtp_ext_val = -1;
static int hf_gtp_ext_hdr = -1;
static int hf_gtp_ext_hdr_next = -1;
static int hf_gtp_ext_hdr_length = -1;
static int hf_gtp_ext_hdr_pdcpsn = -1;
static int hf_gtp_flags = -1;
static int hf_gtp_flags_ver = -1;
static int hf_gtp_prime_flags_ver = -1;
static int hf_gtp_flags_pt = -1;
static int hf_gtp_flags_spare1 = -1;
static int hf_gtp_flags_snn = -1;
static int hf_gtp_flags_spare2 = -1;
static int hf_gtp_flags_e = -1;
static int hf_gtp_flags_s = -1;
static int hf_gtp_flags_pn = -1;
static int hf_gtp_flow_ii = -1;
static int hf_gtp_flow_label = -1;
static int hf_gtp_flow_sig = -1;
static int hf_gtp_gsn_addr_len = -1;
static int hf_gtp_gsn_addr_type = -1;
static int hf_gtp_gsn_ipv4 = -1;
static int hf_gtp_gsn_ipv6 = -1;
static int hf_gtp_imsi = -1;
static int hf_gtp_length = -1;
static int hf_gtp_map_cause = -1;
static int hf_gtp_message_type = -1;
static int hf_gtp_ms_reason = -1;
static int hf_gtp_ms_valid = -1;
static int hf_gtp_msisdn = -1;
static int hf_gtp_next = -1;
static int hf_gtp_npdu_number = -1;
static int hf_gtp_node_ipv4 = -1;
static int hf_gtp_node_ipv6 = -1;
static int hf_gtp_nsapi = -1;
static int hf_gtp_ptmsi = -1;
static int hf_gtp_ptmsi_sig = -1;
static int hf_gtp_qos_version = -1;
static int hf_gtp_qos_spare1 = -1;
static int hf_gtp_qos_delay = -1;
static int hf_gtp_qos_mean = -1;
static int hf_gtp_qos_peak = -1;
static int hf_gtp_qos_spare2 = -1;
static int hf_gtp_qos_precedence = -1;
static int hf_gtp_qos_spare3 = -1;
static int hf_gtp_qos_reliability = -1;
static int hf_gtp_qos_al_ret_priority = -1;
static int hf_gtp_qos_traf_class = -1;
static int hf_gtp_qos_del_order = -1;
static int hf_gtp_qos_del_err_sdu = -1;
static int hf_gtp_qos_max_sdu_size = -1;
static int hf_gtp_qos_max_ul = -1;
static int hf_gtp_qos_max_dl = -1;
static int hf_gtp_qos_res_ber = -1;
static int hf_gtp_qos_sdu_err_ratio = -1;
static int hf_gtp_qos_trans_delay = -1;
static int hf_gtp_qos_traf_handl_prio = -1;
static int hf_gtp_qos_guar_ul = -1;
static int hf_gtp_qos_guar_dl = -1;
static int hf_gtp_qos_src_stat_desc = -1;
static int hf_gtp_qos_sig_ind = -1;
static int hf_gtp_pkt_flow_id = -1;
static int hf_gtp_rab_gtpu_dn = -1;
static int hf_gtp_rab_gtpu_up = -1;
static int hf_gtp_rab_pdu_dn = -1;
static int hf_gtp_rab_pdu_up = -1;
static int hf_gtp_rai_rac = -1;
static int hf_gtp_rai_lac = -1;
static int hf_gtp_ranap_cause = -1;
static int hf_gtp_recovery = -1;
static int hf_gtp_reorder = -1;
static int hf_gtp_rnc_ipv4 = -1;
static int hf_gtp_rnc_ipv6 = -1;
static int hf_gtp_rp = -1;
static int hf_gtp_rp_nsapi = -1;
static int hf_gtp_rp_sms = -1;
static int hf_gtp_rp_spare = -1;
static int hf_gtp_sel_mode = -1;
static int hf_gtp_seq_number = -1;
static int hf_gtp_sndcp_number = -1;
static int hf_gtp_tear_ind = -1;
static int hf_gtp_teid = -1;
static int hf_gtp_teid_cp = -1;
static int hf_gtp_ulink_teid_cp = -1;
static int hf_gtp_teid_data = -1;
static int hf_gtp_ulink_teid_data = -1;
static int hf_gtp_teid_ii = -1;
static int hf_gtp_tft_code = -1;
static int hf_gtp_tft_spare = -1;
static int hf_gtp_tft_number = -1;
static int hf_gtp_tft_eval = -1;
static int hf_gtp_tid = -1;
static int hf_gtp_tlli = -1;
static int hf_gtp_tr_comm = -1;
static int hf_gtp_trace_ref = -1;
static int hf_gtp_trace_type = -1;
static int hf_gtp_unknown = -1;
static int hf_gtp_user_addr_pdp_org = -1;
static int hf_gtp_user_addr_pdp_type = -1;
static int hf_gtp_user_ipv4 = -1;
static int hf_gtp_user_ipv6 = -1;
static int hf_gtp_security_mode = -1;
static int hf_gtp_no_of_vectors = -1;
static int hf_gtp_cipher_algorithm = -1;
static int hf_gtp_cksn_ksi = -1;
static int hf_gtp_cksn = -1;
static int hf_gtp_ksi = -1;
static int hf_gtp_ext_length = -1;
static int hf_gtp_ext_apn_res = -1;
static int hf_gtp_ext_rat_type = -1;
static int hf_gtp_ext_geo_loc_type = -1;
static int hf_gtp_ext_sac = -1;
static int hf_gtp_ext_imeisv = -1;
static int hf_gtp_targetRNC_ID = -1;
static int hf_gtp_bssgp_cause = -1;
static int hf_gtp_bssgp_ra_discriminator = -1;
static int hf_gtp_sapi = -1;
static int hf_gtp_xid_par_len = -1;
static int hf_gtp_earp_pvi = -1;
static int hf_gtp_earp_pl = -1;
static int hf_gtp_earp_pci = -1;
static int hf_gtp_cdr_app = -1;
static int hf_gtp_cdr_rel = -1;
static int hf_gtp_cdr_ver = -1;
static int hf_gtp_spare = -1;
static int hf_gtp_cmn_flg_ppc = -1;
static int hf_gtp_cmn_flg_mbs_srv_type = -1;
static int hf_gtp_cmn_flg_mbs_ran_pcd_rdy = -1;
static int hf_gtp_cmn_flg_mbs_cnt_inf = -1;
static int hf_gtp_cmn_flg_nrsn = -1;
static int hf_gtp_cmn_flg_no_qos_neg = -1;
static int hf_gtp_cmn_flg_upgrd_qos_sup = -1;
static int hf_gtp_tmgi = -1;
static int hf_gtp_mbms_ses_dur_days = -1;
static int hf_gtp_mbms_ses_dur_s = -1;
static int hf_gtp_no_of_mbms_sa_codes = -1;
static int hf_gtp_mbms_sa_code = -1;
static int hf_gtp_mbs_2g_3g_ind = -1;
static int hf_gtp_time_2_dta_tr = -1;
static int hf_gtp_ext_ei = -1;
static int hf_gtp_ext_gcsi = -1;
static int hf_gtp_ext_dti = -1;
static int hf_gtp_ra_prio_lcs = -1;
static int hf_gtp_bcm = -1;
static int hf_gtp_rim_routing_addr = -1;

/* Initialize the subtree pointers */
static gint ett_gtp = -1;
static gint ett_gtp_flags = -1;
static gint ett_gtp_ext = -1;
static gint ett_gtp_ext_hdr = -1;
static gint ett_gtp_rai = -1;
static gint ett_gtp_qos = -1;
static gint ett_gtp_auth_tri = -1;
static gint ett_gtp_flow_ii = -1;
static gint ett_gtp_rab_cntxt = -1;
static gint ett_gtp_rp = -1;
static gint ett_gtp_pkt_flow_id = -1;
static gint ett_gtp_chrg_char = -1;
static gint ett_gtp_user = -1;
static gint ett_gtp_mm = -1;
static gint ett_gtp_trip = -1;
static gint ett_gtp_quint = -1;
static gint ett_gtp_pdp = -1;
static gint ett_gtp_apn = -1;
static gint ett_gtp_proto = -1;
static gint ett_gtp_gsn_addr = -1;
static gint ett_gtp_tft = -1;
static gint ett_gtp_tft_pf = -1;
static gint ett_gtp_tft_flags = -1;
static gint ett_gtp_rab_setup = -1;
static gint ett_gtp_hdr_list = -1;
static gint ett_gtp_chrg_addr = -1;
static gint ett_gtp_node_addr = -1;
static gint ett_gtp_rel_pack = -1;
static gint ett_gtp_can_pack = -1;
static gint ett_gtp_data_resp = -1;
static gint ett_gtp_priv_ext = -1;
static gint ett_gtp_net_cap = -1;
static gint ett_gtp_ext_tree_apn_res = -1;
static gint ett_gtp_ext_rat_type = -1;
static gint ett_gtp_ext_imeisv = -1;
static gint ett_gtp_ext_ran_tr_cont = -1;
static gint ett_gtp_ext_pdp_cont_prio = -1;
static gint ett_gtp_ext_ssgn_no = -1;
static gint ett_gtp_ext_rab_setup_inf = -1;
static gint ett_gtp_ext_common_flgs = -1;
static gint ett_gtp_ext_usr_loc_inf = -1;
static gint ett_gtp_ext_ms_time_zone = -1;
static gint ett_gtp_ext_camel_chg_inf_con = -1;
static gint ett_GTP_EXT_MBMS_UE_CTX = -1;
static gint ett_gtp_ext_tmgi = -1;
static gint ett_gtp_tmgi = -1;
static gint ett_gtp_ext_rim_ra = -1;
static gint ett_gtp_ext_mbms_prot_conf_opt = -1;
static gint ett_gtp_ext_mbms_sa = -1;
static gint ett_gtp_ext_bms_ses_dur = -1;
static gint ett_gtp_ext_src_rnc_pdp_ctx_inf = -1;
static gint ett_gtp_ext_add_trs_inf = -1;
static gint ett_gtp_ext_hop_count = -1;
static gint ett_gtp_ext_sel_plmn_id = -1;
static gint ett_gtp_ext_mbms_ses_id = -1;
static gint ett_gtp_ext_mbms_2g_3g_ind = -1;
static gint ett_gtp_ext_enh_nsapi = -1;
static gint ett_gtp_ext_ad_mbms_trs_inf = -1;
static gint ett_gtp_ext_mbms_ses_id_rep_no = -1;
static gint ett_gtp_ext_mbms_time_to_data_tr = -1;
static gint ett_gtp_ext_ps_ho_req_ctx = -1;
static gint ett_gtp_ext_bss_cont = -1;
static gint ett_gtp_ext_cell_id = -1;
static gint ett_gtp_ext_pdu_no = -1;
static gint ett_gtp_ext_bssgp_cause = -1;
static gint ett_gtp_ext_ra_prio_lcs = -1;
static gint ett_gtp_ext_ps_handover_xid = -1;
static gint ett_gtp_target_id = -1;
static gint ett_gtp_utran_cont = -1;
static gint ett_gtp_bcm = -1;
static gint ett_gtp_cdr_ver = -1;
static gint ett_gtp_cdr_dr = -1;
static gint ett_gtp_uli_rai = -1;

static gboolean g_gtp_tpdu = TRUE;
static gboolean g_gtp_etsi_order = FALSE;

static int gtp_tap = -1;

/* Definition of flags masks */
#define GTP_VER_MASK 0xE0

static const value_string ver_types[] = {
    {0, "GTP release 97/98 version"},
    {1, "GTP release 99 version"},
    {2, "GTPv2-C"},
    {3, "None"},
    {4, "None"},
    {5, "None"},
    {6, "None"},
    {7, "None"},
    {0, NULL}
};

static const value_string pt_types[] = {
    {0, "GTP'"},
    {1, "GTP"},
    {0, NULL}
};

#define GTP_PT_MASK         0x10
#define GTP_SPARE1_MASK     0x0E
#define GTP_SPARE2_MASK     0x08
#define GTP_E_MASK          0x04
#define GTP_S_MASK          0x02
#define GTP_SNN_MASK        0x01
#define GTP_PN_MASK         0x01

#define GTP_EXT_HDR_PDCP_SN 0xC0

static const value_string next_extension_header_fieldvals[] = {
    {   0, "No more extension headers"},
    {   1, "MBMS support indication"},
    {   2, "MS Info Change Reporting support indication"},
    {GTP_EXT_HDR_PDCP_SN, "PDCP PDU number"},
    {0xc1, "Suspend Request"},
    {0xc2, "Suspend Response"},
    {0, NULL}
};

/* Definition of 3G charging characteristics masks */
#define GTP_MASK_CHRG_CHAR_S    0xF000
#define GTP_MASK_CHRG_CHAR_N    0x0800
#define GTP_MASK_CHRG_CHAR_P    0x0400
#define GTP_MASK_CHRG_CHAR_F    0x0200
#define GTP_MASK_CHRG_CHAR_H    0x0100
#define GTP_MASK_CHRG_CHAR_R    0x00FF

/* Traffic Flow Templates  mask */
#define GTPv1_TFT_CODE_MASK 0xE0
#define GTPv1_TFT_SPARE_MASK    0x10
#define GTPv1_TFT_NUMBER_MASK   0x0F

/* Definition of GSN Address masks */
#define GTP_EXT_GSN_ADDR_TYPE_MASK      0xC0
#define GTP_EXT_GSN_ADDR_LEN_MASK       0x3F

/* Definition of QoS masks */
#define GTP_EXT_QOS_SPARE1_MASK                 0xC0
#define GTP_EXT_QOS_DELAY_MASK                  0x38
#define GTP_EXT_QOS_RELIABILITY_MASK            0x07
#define GTP_EXT_QOS_PEAK_MASK                   0xF0
#define GTP_EXT_QOS_SPARE2_MASK                 0x08
#define GTP_EXT_QOS_PRECEDENCE_MASK             0x07
#define GTP_EXT_QOS_SPARE3_MASK                 0xE0
#define GTP_EXT_QOS_MEAN_MASK                   0x1F
#define GTP_EXT_QOS_TRAF_CLASS_MASK             0xE0
#define GTP_EXT_QOS_DEL_ORDER_MASK              0x18
#define GTP_EXT_QOS_DEL_ERR_SDU_MASK            0x07
#define GTP_EXT_QOS_RES_BER_MASK                0xF0
#define GTP_EXT_QOS_SDU_ERR_RATIO_MASK          0x0F
#define GTP_EXT_QOS_TRANS_DELAY_MASK            0xFC
#define GTP_EXT_QOS_TRAF_HANDL_PRIORITY_MASK    0x03
#define GTP_EXT_QOS_SRC_STAT_DESC_MASK          0x0F
#define GTP_EXT_QOS_SIG_IND_MASK                0x10

/* Definition of Radio Priority's masks */
#define GTPv1_EXT_RP_NSAPI_MASK         0xF0
#define GTPv1_EXT_RP_SPARE_MASK         0x08
#define GTPv1_EXT_RP_MASK               0x07

static const value_string gtp_message_type[] = {
    {GTP_MSG_UNKNOWN,             "For future use"},
    {GTP_MSG_ECHO_REQ,            "Echo request"},
    {GTP_MSG_ECHO_RESP,           "Echo response"},
    {GTP_MSG_VER_NOT_SUPP,        "Version not supported"},
    {GTP_MSG_NODE_ALIVE_REQ,      "Node alive request"},
    {GTP_MSG_NODE_ALIVE_RESP,     "Node alive response"},
    {GTP_MSG_REDIR_REQ,           "Redirection request"},
    {GTP_MSG_REDIR_RESP,          "Redirection response"},
    /*
     * 8-15 For future use. Shall not be sent. If received,
     * shall be treated as an Unknown message.
     */
#if 0
    {   8,                        "Unknown message(For future use)"},
    {   9,                        "Unknown message(For future use)"},
    {  10,                        "Unknown message(For future use)"},
    {  11,                        "Unknown message(For future use)"},
    {  12,                        "Unknown message(For future use)"},
    {  13,                        "Unknown message(For future use)"},
    {  14,                        "Unknown message(For future use)"},
    {  15,                        "Unknown message(For future use)"},
#endif
    {GTP_MSG_CREATE_PDP_REQ,      "Create PDP context request"},
    {GTP_MSG_CREATE_PDP_RESP,     "Create PDP context response"},
    {GTP_MSG_UPDATE_PDP_REQ,      "Update PDP context request"},
    {GTP_MSG_UPDATE_PDP_RESP,     "Update PDP context response"},
    {GTP_MSG_DELETE_PDP_REQ,      "Delete PDP context request"},
    {GTP_MSG_DELETE_PDP_RESP,     "Delete PDP context response"},
    {GTP_MSG_INIT_PDP_CONTEXT_ACT_REQ,   "Initiate PDP Context Activation Request"},
    {GTP_MSG_INIT_PDP_CONTEXT_ACT_RESP,  "Initiate PDP Context Activation Response"},
/*
 * 24-25 For future use. Shall not be sent. If received,
 * shall be treated as an Unknown message.
 */
    {GTP_MSG_DELETE_AA_PDP_REQ,   "Delete AA PDP Context Request"},
    {GTP_MSG_DELETE_AA_PDP_RESP,  "Delete AA PDP Context Response"},
    {GTP_MSG_ERR_IND,             "Error indication"},
    {GTP_MSG_PDU_NOTIFY_REQ,      "PDU notification request"},
    {GTP_MSG_PDU_NOTIFY_RESP,     "PDU notification response"},
    {GTP_MSG_PDU_NOTIFY_REJ_REQ,  "PDU notification reject request"},
    {GTP_MSG_PDU_NOTIFY_REJ_RESP, "PDU notification reject response"},
    {GTP_MSG_SUPP_EXT_HDR,        "Supported extension header notification"},
    {GTP_MSG_SEND_ROUT_INFO_REQ,  "Send routing information for GPRS request"},
    {GTP_MSG_SEND_ROUT_INFO_RESP, "Send routing information for GPRS response"},
    {GTP_MSG_FAIL_REP_REQ,        "Failure report request"},
    {GTP_MSG_FAIL_REP_RESP,       "Failure report response"},
    {GTP_MSG_MS_PRESENT_REQ,      "Note MS GPRS present request"},
    {GTP_MSG_MS_PRESENT_RESP,     "Note MS GPRS present response"},
    /* 38-47 For future use. Shall not be sent. If received,
     * shall be treated as an Unknown message.
     */
#if 0
    {  38,                        "Unknown message(For future use)"},
    {  39,                        "Unknown message(For future use)"},
    {  40,                        "Unknown message(For future use)"},
    {  41,                        "Unknown message(For future use)"},
    {  42,                        "Unknown message(For future use)"},
    {  43,                        "Unknown message(For future use)"},
    {  44,                        "Unknown message(For future use)"},
    {  45,                        "Unknown message(For future use)"},
    {  46,                        "Unknown message(For future use)"},
    {  47,                        "Unknown message(For future use)"},
#endif
    {GTP_MSG_IDENT_REQ,           "Identification request"},
    {GTP_MSG_IDENT_RESP,          "Identification response"},
    {GTP_MSG_SGSN_CNTXT_REQ,      "SGSN context request"},
    {GTP_MSG_SGSN_CNTXT_RESP,     "SGSN context response"},
    {GTP_MSG_SGSN_CNTXT_ACK,      "SGSN context acknowledgement"},
    {GTP_MSG_FORW_RELOC_REQ,      "Forward relocation request"},
    {GTP_MSG_FORW_RELOC_RESP,     "Forward relocation response"},
    {GTP_MSG_FORW_RELOC_COMP,     "Forward relocation complete"},
    {GTP_MSG_RELOC_CANCEL_REQ,    "Relocation cancel request"},
    {GTP_MSG_RELOC_CANCEL_RESP,   "Relocation cancel response"},
    {GTP_MSG_FORW_SRNS_CNTXT,     "Forward SRNS context"},
    {GTP_MSG_FORW_RELOC_ACK,      "Forward relocation complete acknowledge"},
    {GTP_MSG_FORW_SRNS_CNTXT_ACK, "Forward SRNS context acknowledge"},
    /* 61-69 For future use. Shall not be sent. If received,
     * shall be treated as an Unknown message.
     */
#if 0
    {  61,                        "Unknown message(For future use)"},
    {  62,                        "Unknown message(For future use)"},
    {  63,                        "Unknown message(For future use)"},
    {  64,                        "Unknown message(For future use)"},
    {  65,                        "Unknown message(For future use)"},
    {  66,                        "Unknown message(For future use)"},
    {  67,                        "Unknown message(For future use)"},
    {  68,                        "Unknown message(For future use)"},
    {  69,                        "Unknown message(For future use)"},
#endif
    {GTP_MSG_RAN_INFO_RELAY,      "RAN Information Relay"},
    /* 71-95 For future use. Shall not be sent. If received,
     * shall be treated as an Unknown message.
     */
#if 0
    {  71,                        "Unknown message(For future use)"},
    {  72,                        "Unknown message(For future use)"},
    {  73,                        "Unknown message(For future use)"},
    {  74,                        "Unknown message(For future use)"},
    {  75,                        "Unknown message(For future use)"},
    {  76,                        "Unknown message(For future use)"},
    {  77,                        "Unknown message(For future use)"},
    {  78,                        "Unknown message(For future use)"},
    {  79,                        "Unknown message(For future use)"},
    {  80,                        "Unknown message(For future use)"},
    {  81,                        "Unknown message(For future use)"},
    {  82,                        "Unknown message(For future use)"},
    {  83,                        "Unknown message(For future use)"},
    {  84,                        "Unknown message(For future use)"},
    {  85,                        "Unknown message(For future use)"},
    {  86,                        "Unknown message(For future use)"},
    {  87,                        "Unknown message(For future use)"},
    {  88,                        "Unknown message(For future use)"},
    {  89,                        "Unknown message(For future use)"},
    {  90,                        "Unknown message(For future use)"},
    {  91,                        "Unknown message(For future use)"},
    {  92,                        "Unknown message(For future use)"},
    {  93,                        "Unknown message(For future use)"},
    {  94,                        "Unknown message(For future use)"},
    {  95,                        "Unknown message(For future use)"},
#endif
    {GTP_MBMS_NOTIFY_REQ,         "MBMS Notification Request"},
    {GTP_MBMS_NOTIFY_RES,         "MBMS Notification Response"},
    {GTP_MBMS_NOTIFY_REJ_REQ,     "MBMS Notification Reject Request"},
    {GTP_MBMS_NOTIFY_REJ_RES,     "MBMS Notification Reject Response"},
    {GTP_CREATE_MBMS_CNTXT_REQ,   "Create MBMS Context Request"},
    {GTP_CREATE_MBMS_CNTXT_RES,   "Create MBMS Context Response"},
    {GTP_UPD_MBMS_CNTXT_REQ,      "Update MBMS Context Request"},
    {GTP_UPD_MBMS_CNTXT_RES,      "Update MBMS Context Response"},
    {GTP_DEL_MBMS_CNTXT_REQ,      "Delete MBMS Context Request"},
    {GTP_DEL_MBMS_CNTXT_RES,      "Delete MBMS Context Response"},
    /* 106 - 111 For future use. Shall not be sent. If received,
     * shall be treated as an Unknown message.
     */
#if 0
    {  106,                       "Unknown message(For future use)"},
    {  107,                       "Unknown message(For future use)"},
    {  108,                       "Unknown message(For future use)"},
    {  109,                       "Unknown message(For future use)"},
    {  110,                       "Unknown message(For future use)"},
    {  111,                       "Unknown message(For future use)"},
#endif
    {GTP_MBMS_REG_REQ,            "MBMS Registration Request"},
    {GTP_MBMS_REG_RES,            "MBMS Registration Response"},
    {GTP_MBMS_DE_REG_REQ,         "MBMS De-Registration Request"},
    {GTP_MBMS_DE_REG_RES,         "MBMS De-Registration Response"},
    {GTP_MBMS_SES_START_REQ,      "MBMS Session Start Request"},
    {GTP_MBMS_SES_START_RES,      "MBMS Session Start Response"},
    {GTP_MBMS_SES_STOP_REQ,       "MBMS Session Stop Request"},
    {GTP_MBMS_SES_STOP_RES,       "MBMS Session Stop Response"},
    {GTP_MBMS_SES_UPD_REQ,        "MBMS Session Update Request"},
    {GTP_MBMS_SES_UPD_RES,        "MBMS Session Update Response"},
    /* 122-127 For future use. Shall not be sent.
     * If received, shall be treated as an Unknown message.
     */
#if 0
    {  122,                       "Unknown message(For future use)"},
    {  123,                       "Unknown message(For future use)"},
    {  124,                       "Unknown message(For future use)"},
    {  125,                       "Unknown message(For future use)"},
    {  126,                       "Unknown message(For future use)"},
    {  127,                       "Unknown message(For future use)"},
#endif
	{GTP_MS_INFO_CNG_NOT_REQ,     "MS Info Change Notification Request"},
    {GTP_MS_INFO_CNG_NOT_RES,     "MS Info Change Notification Response"},
    /* 130-239 For future use. Shall not be sent. If received,
     * shall be treated as an Unknown message.
     */
#if 0
    {  130,                       "Unknown message(For future use)"},
    {  131,                       "Unknown message(For future use)"},
    {  132,                       "Unknown message(For future use)"},
    {  133,                       "Unknown message(For future use)"},
    {  134,                       "Unknown message(For future use)"},
    {  135,                       "Unknown message(For future use)"},
    {  136,                       "Unknown message(For future use)"},
    {  137,                       "Unknown message(For future use)"},
    {  138,                       "Unknown message(For future use)"},
    {  139,                       "Unknown message(For future use)"},
    {  140,                       "Unknown message(For future use)"},
    {  141,                       "Unknown message(For future use)"},
    {  142,                       "Unknown message(For future use)"},
    {  143,                       "Unknown message(For future use)"},
    {  144,                       "Unknown message(For future use)"},
    {  145,                       "Unknown message(For future use)"},
    {  146,                       "Unknown message(For future use)"},
    {  147,                       "Unknown message(For future use)"},
    {  148,                       "Unknown message(For future use)"},
    {  149,                       "Unknown message(For future use)"},
    {  150,                       "Unknown message(For future use)"},
    {  151,                       "Unknown message(For future use)"},
    {  152,                       "Unknown message(For future use)"},
    {  153,                       "Unknown message(For future use)"},
    {  154,                       "Unknown message(For future use)"},
    {  155,                       "Unknown message(For future use)"},
    {  156,                       "Unknown message(For future use)"},
    {  157,                       "Unknown message(For future use)"},
    {  158,                       "Unknown message(For future use)"},
    {  159,                       "Unknown message(For future use)"},
#endif
    {GTP_MSG_DATA_TRANSF_REQ,     "Data record transfer request"},
    {GTP_MSG_DATA_TRANSF_RESP,    "Data record transfer response"},
    /* 242-253 For future use. Shall not be sent. If received,
     * shall be treated as an Unknown message.
     */
#if 0
    {  242,                       "Unknown message(For future use)"},
    {  243,                       "Unknown message(For future use)"},
    {  244,                       "Unknown message(For future use)"},
    {  245,                       "Unknown message(For future use)"},
    {  246,                       "Unknown message(For future use)"},
    {  247,                       "Unknown message(For future use)"},
    {  248,                       "Unknown message(For future use)"},
    {  249,                       "Unknown message(For future use)"},
    {  250,                       "Unknown message(For future use)"},
    {  251,                       "Unknown message(For future use)"},
    {  252,                       "Unknown message(For future use)"},
    {  253,                       "Unknown message(For future use)"},
#endif
    {GTP_MSG_END_MARKER,          "End Marker"},
    {GTP_MSG_TPDU,                "T-PDU"},
    {0, NULL}
};
static value_string_ext gtp_message_type_ext = VALUE_STRING_EXT_INIT(gtp_message_type);

/* definitions of fields in extension header */
#define GTP_EXT_CAUSE                 0x01
#define GTP_EXT_IMSI                  0x02
#define GTP_EXT_RAI                   0x03
#define GTP_EXT_TLLI                  0x04
#define GTP_EXT_PTMSI                 0x05
#define GTP_EXT_QOS_GPRS              0x06
#define GTP_EXT_REORDER               0x08
#define GTP_EXT_AUTH_TRI              0x09
#define GTP_EXT_MAP_CAUSE             0x0B
#define GTP_EXT_PTMSI_SIG             0x0C
#define GTP_EXT_MS_VALID              0x0D
#define GTP_EXT_RECOVER               0x0E
#define GTP_EXT_SEL_MODE              0x0F

#define GTP_EXT_16                    0x10
#define GTP_EXT_FLOW_LABEL            0x10
#define GTP_EXT_TEID                  0x10    /* 0xFF10 3G */

#define GTP_EXT_17                    0x11
#define GTP_EXT_FLOW_SIG              0x11
#define GTP_EXT_TEID_CP               0x11    /* 0xFF11 3G */

#define GTP_EXT_18                    0x12
#define GTP_EXT_FLOW_II               0x12
#define GTP_EXT_TEID_II               0x12    /* 0xFF12 3G */

#define GTP_EXT_19                    0x13    /* 19 TV Teardown Ind 7.7.16 */
#define GTP_EXT_MS_REASON             0x13    /* same as 0x1D GTPv1_EXT_MS_REASON */
#define GTP_EXT_TEAR_IND              0x13    /* 0xFF13 3G */

#define GTP_EXT_NSAPI                 0x14    /* 3G */
#define GTP_EXT_RANAP_CAUSE           0x15    /* 3G */
#define GTP_EXT_RAB_CNTXT             0x16    /* 3G */
#define GTP_EXT_RP_SMS                0x17    /* 3G */
#define GTP_EXT_RP                    0x18    /* 3G */
#define GTP_EXT_PKT_FLOW_ID           0x19    /* 3G */
#define GTP_EXT_CHRG_CHAR             0x1A    /* 3G */
#define GTP_EXT_TRACE_REF             0x1B    /* 3G */
#define GTP_EXT_TRACE_TYPE            0x1C    /* 3G */
#define GTPv1_EXT_MS_REASON           0x1D    /* 3G 29 TV MS Not Reachable Reason 7.7.25A */
/* 117-126 Reserved for the GPRS charging protocol (see GTP' in 3GPP TS 32.295 [33]) */
#define GTP_EXT_TR_COMM               0x7E    /* charging */
#define GTP_EXT_CHRG_ID               0x7F    /* 127 TV Charging ID 7.7.26 */
#define GTP_EXT_USER_ADDR             0x80
#define GTP_EXT_MM_CNTXT              0x81
#define GTP_EXT_PDP_CNTXT             0x82
#define GTP_EXT_APN                   0x83
#define GTP_EXT_PROTO_CONF            0x84
#define GTP_EXT_GSN_ADDR              0x85
#define GTP_EXT_MSISDN                0x86
#define GTP_EXT_QOS_UMTS              0x87    /* 3G */
#define GTP_EXT_AUTH_QUI              0x88    /* 3G */
#define GTP_EXT_TFT                   0x89    /* 3G */
#define GTP_EXT_TARGET_ID             0x8A    /* 3G */
#define GTP_EXT_UTRAN_CONT            0x8B    /* 3G */
#define GTP_EXT_RAB_SETUP             0x8C    /* 3G */
#define GTP_EXT_HDR_LIST              0x8D    /* 3G */
#define GTP_EXT_TRIGGER_ID            0x8E    /* 3G   142 7.7.41 */
#define GTP_EXT_OMC_ID                0x8F    /* 3G   143 TLV OMC Identity 7.7.42 */
#define GTP_EXT_RAN_TR_CONT           0x90    /* 3G   144 TLV RAN Transparent Container 7.7.43 */
#define GTP_EXT_PDP_CONT_PRIO         0x91    /* 3G   145 TLV PDP Context Prioritization 7.7.45 */
#define GTP_EXT_ADD_RAB_SETUP_INF     0x92    /* 3G   146 TLV Additional RAB Setup Information 7.7.45A */
#define GTP_EXT_SSGN_NO               0x93    /* 3G   147 TLV SGSN Number 7.7.47 */
#define GTP_EXT_COMMON_FLGS           0x94    /* 3G   148 TLV Common Flags 7.7.48 */
#define GTP_EXT_APN_RES               0x95    /* 3G   149 */
#define GTP_EXT_RA_PRIO_LCS           0x96    /* 3G   150 TLV Radio Priority LCS 7.7.25B */
#define GTP_EXT_RAT_TYPE              0x97    /* 3G   151 TLV RAT Type 7.7.50 */
#define GTP_EXT_USR_LOC_INF           0x98    /* 3G   152 TLV User Location Information 7.7.51 */
#define GTP_EXT_MS_TIME_ZONE          0x99    /* 3G   153 TLV MS Time Zone 7.7.52 */
#define GTP_EXT_IMEISV                0x9A    /* 3G   154 TLV IMEI(SV) 7.7.53 */
#define GTP_EXT_CAMEL_CHG_INF_CON     0x9B    /* 3G   155 TLV CAMEL Charging Information Container 7.7.54 */
#define GTP_EXT_MBMS_UE_CTX           0x9C    /* 3G   156 TLV MBMS UE Context 7.7.55 */
#define GTP_EXT_TMGI                  0x9D    /* 3G   157 TLV Temporary Mobile Group Identity (TMGI) 7.7.56 */
#define GTP_EXT_RIM_RA                0x9E    /* 3G   158 TLV RIM Routing Address 7.7.57 */
#define GTP_EXT_MBMS_PROT_CONF_OPT    0x9F    /* 3G   159 TLV MBMS Protocol Configuration Options 7.7.58 */
#define GTP_EXT_MBMS_SA               0xA0    /* 3G   160 TLV MBMS Service Area 7.7.60 */
#define GTP_EXT_SRC_RNC_PDP_CTX_INF   0xA1    /* 3G   161 TLV Source RNC PDCP context info 7.7.61 */
#define GTP_EXT_ADD_TRS_INF           0xA2    /* 3G   162 TLV Additional Trace Info 7.7.62 */
#define GTP_EXT_HOP_COUNT             0xA3    /* 3G   163 TLV Hop Counter 7.7.63 */
#define GTP_EXT_SEL_PLMN_ID           0xA4    /* 3G   164 TLV Selected PLMN ID 7.7.64 */
#define GTP_EXT_MBMS_SES_ID           0xA5    /* 3G   165 TLV MBMS Session Identifier 7.7.65 */
#define GTP_EXT_MBMS_2G_3G_IND        0xA6    /* 3G   166 TLV MBMS 2G/3G Indicator 7.7.66 */
#define GTP_EXT_ENH_NSAPI             0xA7    /* 3G   167 TLV Enhanced NSAPI 7.7.67 */
#define GTP_EXT_MBMS_SES_DUR          0xA8    /* 3G   168 TLV MBMS Session Duration 7.7.59 */
#define GTP_EXT_ADD_MBMS_TRS_INF      0xA9    /* 3G   169 TLV Additional MBMS Trace Info 7.7.68 */
#define GTP_EXT_MBMS_SES_ID_REP_NO    0xAA    /* 3G   170 TLV MBMS Session Identity Repetition Number 7.7.69 */
#define GTP_EXT_MBMS_TIME_TO_DATA_TR  0xAB    /* 3G   171 TLV MBMS Time To Data Transfer 7.7.70 */
#define GTP_EXT_PS_HO_REQ_CTX         0xAC    /* 3G   172 TLV PS Handover Request Context 7.7.71 */
#define GTP_EXT_BSS_CONT              0xAD    /* 3G   173 TLV BSS Container 7.7.72 */
#define GTP_EXT_CELL_ID               0xAE    /* 3G   174 TLV Cell Identification 7.7.73 */
#define GTP_EXT_PDU_NO                0xAF    /* 3G   175 TLV PDU Numbers 7.7.74 */
#define GTP_EXT_BSSGP_CAUSE           0xB0    /* 3G   176 TLV BSSGP Cause 7.7.75 */
#define GTP_EXT_REQ_MBMS_BEARER_CAP   0xB1    /* 3G   177 TLV Required MBMS bearer capabilities       7.7.76 */
#define GTP_EXT_RIM_ROUTING_ADDR_DISC 0xB2    /* 3G   178 TLV RIM Routing Address Discriminator       7.7.77 */
#define GTP_EXT_LIST_OF_SETUP_PFCS    0xB3    /* 3G   179 TLV List of set-up PFCs     7.7.78 */
#define GTP_EXT_PS_HANDOVER_XIP_PAR   0xB4    /* 3G   180 TLV PS Handover XID Parameters      7.7.79 */
#define GTP_EXT_MS_INF_CHG_REP_ACT    0xB5    /* 3G   181 TLV MS Info Change Reporting Action 7.7.80 */
#define GTP_EXT_DIRECT_TUNNEL_FLGS    0xB6    /* 3G   182 TLV Direct Tunnel Flags     7.7.81 */
#define GTP_EXT_CORRELATION_ID        0xB7    /* 3G   183 TLV Correlation-ID  7.7.82 */
#define GTP_EXT_BEARER_CONTROL_MODE   0xB8    /* 3G   184 TLV Bearer Control Mode     7.7.83 */
                                              /* 3G   185 TLV MBMS Flow Identifier    7.7.84 */
                                              /* 3G   186 TLV MBMS IP Multicast Distribution    7.7.85 */
                                              /* 3G   187 TLV MBMS Distribution Acknowledgement 7.7.86 */
                                              /* 3G   188 TLV Reliable INTER RAT HANDOVER INFO  7.7.87 */
                                              /* 3G   189 TLV RFSP Index        7.7.88 */
                                              /* 3G   190 TLV Fully Qualified Domain Name (FQDN)        7.7.90 */
#define GTP_EXT_EVO_ALLO_RETE_P1      0xBF    /* 3G   191 TLV Evolved Allocation/Retention Priority I   7.7.91 */
                                              /* 3G   192 TLV Evolved Allocation/Retention Priority II  7.7.92 */
                                              /* 3G   193 TLV Extended Common Flags     7.7.93 */
                                              /* 3G   194 TLV User CSG Information (UCI)        7.7.94 */
                                              /* 3G   195 TLV CSG Information Reporting Action  7.7.95 */
                                              /* 3G   196 TLV CSG ID    7.7.96 */
                                              /* 3G   197 TLV CSG Membership Indication (CMI)   7.7.97 */
                                              /* 3G   198 TLV Aggregate Maximum Bit Rate (AMBR) 7.7.98 */
                                              /* 3G   199 TLV UE Network Capability     7.7.99 */
                                              /* 3G   200 TLV UE-AMBR   7.7.100 */
                                              /* 3G   201 TLV APN-AMBR with NSAPI       7.7.101 */
                                              /* 3G   202 TLV GGSN Back-Off Time 7.7.102 */
                                              /* 3G   203 TLV Signalling Priority Indication 7.7.103 */
                                              /* 3G   204 TLV Signalling Priority Indication with NSAPI 7.7.104 */
                                              /* 3G   205 TLV Higher bitrates than 16 Mbps flag 7.7.105 */
                                              /* 3G   206 TLV Max MBR/APN-AMBR 7.7.106 */
                                              /* 3G   207 TLV Additional MM context for SRVCC 7.7.107 */
                                              /* 3G   208 TLV Additional flags for SRVCC 7.7.108  */
                                              /* 3G   209 TLV STN-SR 7.7.109  */
                                              /* 3G   210 TLV C-MSISDN 7.7.110  */
                                              /* 3G   211 TLV Extended RANAP Cause 7.7.111  */
                                              /*  212-238 TLV Spare. For future use.     */

/* 239-250  Reserved for the GPRS charging protocol (see GTP' in 3GPP TS 32.295 [33])*/

#define GTP_EXT_C1                    0xC1
#define GTP_EXT_C2                    0xC2
#define GTP_EXT_REL_PACK              0xF9    /* charging */
#define GTP_EXT_CAN_PACK              0xFA    /* charging */
#define GTP_EXT_CHRG_ADDR             0xFB    /* 3G   251     TLV     Charging Gateway Address        7.7.44 */
/* 252-254  Reserved for the GPRS charging protocol (see GTP' in 3GPP TS 32.295 [33])*/
#define GTP_EXT_DATA_REQ              0xFC    /* charging */
#define GTP_EXT_DATA_RESP             0xFD    /* charging */
#define GTP_EXT_NODE_ADDR             0xFE    /* charging */
#define GTP_EXT_PRIV_EXT              0xFF

static const value_string gtp_val[] = {
    {GTP_EXT_CAUSE, "Cause of operation"},
    {GTP_EXT_IMSI, "IMSI"},
    {GTP_EXT_RAI, "Routing Area Identity"},
    {GTP_EXT_TLLI, "Temporary Logical Link Identity"},
    {GTP_EXT_PTMSI, "Packet TMSI"},
/*   6 */  {GTP_EXT_QOS_GPRS, "Quality of Service"},
    /* 6-7 Spare */
/*   8 */  {GTP_EXT_REORDER, "Reorder required"},
/*   9 */  {GTP_EXT_AUTH_TRI, "Authentication triplets"},
	/* 10 Spare */
/*  11 */  {GTP_EXT_MAP_CAUSE, "MAP cause"},
/*  12 */  {GTP_EXT_PTMSI_SIG, "P-TMSI signature"},
/*  13 */  {GTP_EXT_MS_VALID, "MS validated"},
/*  14 */  {GTP_EXT_RECOVER, "Recovery"},
/*  15 */  {GTP_EXT_SEL_MODE, "Selection mode"},

/*  16 */  {GTP_EXT_16, "Flow label data I"},
/*  16 */  {GTP_EXT_FLOW_LABEL, "Flow label data I"},
/*  16 */  {GTP_EXT_TEID, "Tunnel Endpoint Identifier Data I"},    /* 3G */

    {GTP_EXT_17, "Flow label signalling"},
    {GTP_EXT_FLOW_SIG, "Flow label signalling"},
    {GTP_EXT_TEID_CP, "Tunnel Endpoint Identifier Data Control Plane"}, /* 3G */

    {GTP_EXT_18, "Flow label data II"},
    {GTP_EXT_FLOW_II, "Flow label data II"},
    {GTP_EXT_TEID_II, "Tunnel Endpoint Identifier Data II"},    /* 3G */

    {GTP_EXT_19, "MS not reachable reason"},
    {GTP_EXT_MS_REASON, "MS not reachable reason"},
    {GTP_EXT_TEAR_IND, "Teardown ID"},  /* 3G */

    {GTP_EXT_NSAPI, "NSAPI"},   /* 3G */
    {GTP_EXT_RANAP_CAUSE, "RANAP cause"},   /* 3G */
    {GTP_EXT_RAB_CNTXT, "RAB context"}, /* 3G */
    {GTP_EXT_RP_SMS, "Radio Priority for MO SMS"},  /* 3G */
    {GTP_EXT_RP, "Radio Priority"}, /* 3G */
    {GTP_EXT_PKT_FLOW_ID, "Packet Flow ID"},    /* 3G */
    {GTP_EXT_CHRG_CHAR, "Charging characteristics"},    /* 3G */
    {GTP_EXT_TRACE_REF, "Trace references"},    /* 3G */
    {GTP_EXT_TRACE_TYPE, "Trace type"}, /* 3G */
/*  29 */  {GTPv1_EXT_MS_REASON, "MS not reachable reason"},   /* 3G */
    /* 117-126 Reserved for the GPRS charging protocol (see GTP' in 3GPP TS 32.295 [33]) */
/* 126 */  {GTP_EXT_TR_COMM, "Packet transfer command"},   /* charging */
/* 127 */  {GTP_EXT_CHRG_ID, "Charging ID"},
    {GTP_EXT_USER_ADDR, "End user address"},
    {GTP_EXT_MM_CNTXT, "MM context"},
    {GTP_EXT_PDP_CNTXT, "PDP context"},
    {GTP_EXT_APN, "Access Point Name"},
    {GTP_EXT_PROTO_CONF, "Protocol configuration options"},
    {GTP_EXT_GSN_ADDR, "GSN address"},
    {GTP_EXT_MSISDN, "MS international PSTN/ISDN number"},
    {GTP_EXT_QOS_UMTS, "Quality of service (UMTS)"},    /* 3G */
    {GTP_EXT_AUTH_QUI, "Authentication quintuplets"},   /* 3G */
    {GTP_EXT_TFT, "Traffic Flow Template (TFT)"},   /* 3G */
    {GTP_EXT_TARGET_ID, "Target (RNC) identification"}, /* 3G */
    {GTP_EXT_UTRAN_CONT, "UTRAN transparent field"},    /* 3G */
    {GTP_EXT_RAB_SETUP, "RAB setup information"},   /* 3G */
    {GTP_EXT_HDR_LIST, "Extension Header Types List"},  /* 3G */
    {GTP_EXT_TRIGGER_ID, "Trigger Id"}, /* 3G */
    {GTP_EXT_OMC_ID, "OMC Identity"},   /* 3G */

    {GTP_EXT_RAN_TR_CONT, "RAN Transparent Container"}, /* 7.7.43 */
    {GTP_EXT_PDP_CONT_PRIO, "PDP Context Prioritization"},  /* 7.7.45 */
    {GTP_EXT_ADD_RAB_SETUP_INF, "Additional RAB Setup Information"},    /* 7.7.45A */
    {GTP_EXT_SSGN_NO, "SGSN Number"},   /* 7.7.47 */
    {GTP_EXT_COMMON_FLGS, "Common Flags"},  /* 7.7.48 */
    {GTP_EXT_APN_RES, "APN Restriction"},   /* 3G */
    {GTP_EXT_RA_PRIO_LCS, "Radio Priority LCS"},    /* 7.7.25B */
    {GTP_EXT_RAT_TYPE, "RAT Type"}, /* 3G */
    {GTP_EXT_USR_LOC_INF, "User Location Information"}, /* 7.7.51 */
    {GTP_EXT_MS_TIME_ZONE, "MS Time Zone"}, /* 7.7.52 */

    {GTP_EXT_IMEISV, "IMEI(SV)"},   /* 3G */
    {GTP_EXT_CAMEL_CHG_INF_CON, "CAMEL Charging Information Container"},    /* 7.7.54 */
    {GTP_EXT_MBMS_UE_CTX, "MBMS UE Context"},   /* 7.7.55 */
    {GTP_EXT_TMGI, "Temporary Mobile Group Identity (TMGI)"},   /* 7.7.56 */
    {GTP_EXT_RIM_RA, "RIM Routing Address"},    /* 7.7.57 */
    {GTP_EXT_MBMS_PROT_CONF_OPT, "MBMS Protocol Configuration Options"},    /* 7.7.58 */
    {GTP_EXT_MBMS_SA, "MBMS Service Area"}, /* 7.7.60 */
    {GTP_EXT_SRC_RNC_PDP_CTX_INF, "Source RNC PDCP context info"},  /* 7.7.61 */
    {GTP_EXT_ADD_TRS_INF, "Additional Trace Info"}, /* 7.7.62 */
    {GTP_EXT_HOP_COUNT, "Hop Counter"}, /* 7.7.63 */
    {GTP_EXT_SEL_PLMN_ID, "Selected PLMN ID"},  /* 7.7.64 */
    {GTP_EXT_MBMS_SES_ID, "MBMS Session Identifier"},   /* 7.7.65 */
    {GTP_EXT_MBMS_2G_3G_IND, "MBMS 2G/3G Indicator"},   /* 7.7.66 */
    {GTP_EXT_ENH_NSAPI, "Enhanced NSAPI"},  /* 7.7.67 */
    {GTP_EXT_MBMS_SES_DUR, "MBMS Session Duration"},    /* 7.7.59 */
    {GTP_EXT_ADD_MBMS_TRS_INF, "Additional MBMS Trace Info"},   /* 7.7.68 */
    {GTP_EXT_MBMS_SES_ID_REP_NO, "MBMS Session Identity Repetition Number"},    /* 7.7.69 */
    {GTP_EXT_MBMS_TIME_TO_DATA_TR, "MBMS Time To Data Transfer"},   /* 7.7.70 */
    {GTP_EXT_PS_HO_REQ_CTX, "PS Handover Request Context"}, /* 7.7.71 */
    {GTP_EXT_BSS_CONT, "BSS Container"},    /* 7.7.72 */
    {GTP_EXT_CELL_ID, "Cell Identification"},   /* 7.7.73 */
    {GTP_EXT_PDU_NO, "PDU Numbers"},    /* 7.7.74 */
    {GTP_EXT_BSSGP_CAUSE, "BSSGP Cause"},   /* 7.7.75 */
    {GTP_EXT_REQ_MBMS_BEARER_CAP, "Required MBMS bearer capabilities"}, /* 7.7.76 */
    {GTP_EXT_RIM_ROUTING_ADDR_DISC, "RIM Routing Address Discriminator"},   /* 7.7.77 */
    {GTP_EXT_LIST_OF_SETUP_PFCS, "List of set-up PFCs"},    /* 7.7.78 */
    {GTP_EXT_PS_HANDOVER_XIP_PAR, "PS Handover XID Parameters"},    /* 7.7.79 */
    {GTP_EXT_MS_INF_CHG_REP_ACT, "MS Info Change Reporting Action"},    /* 7.7.80 */
    {GTP_EXT_DIRECT_TUNNEL_FLGS, "Direct Tunnel Flags"},    /* 7.7.81 */
    {GTP_EXT_CORRELATION_ID, "Correlation-ID"}, /* 7.7.82 */
    {GTP_EXT_BEARER_CONTROL_MODE, "Bearer Control Mode"},   /* 7.7.83 */
    {185, "MBMS Flow Identifier"},   /* 7.7.84 */
    {186, "MBMS IP Multicast Distribution"},   /* 7.7.85 */
    {187, "MBMS Distribution Acknowledgement"},   /* 7.7.86 */
    {188, "Reliable INTER RAT HANDOVER INFO"},   /* 7.7.87 */
    {189, "RFSP Index"},   /* 7.7.88 */
    {190, "Fully Qualified Domain Name (FQDN)"},   /* 7.7.90 */
    {GTP_EXT_EVO_ALLO_RETE_P1, "Evolved Allocation/Retention Priority I"},   /* 7.7.91 */
    {192, "Evolved Allocation/Retention Priority II"},   /* 7.7.92 */
    {193, "Extended Common Flags"},   /* 7.7.93 */
    {194, "User CSG Information (UCI)"},   /* 7.7.94 */
    {195, "CSG Information Reporting Action"},   /* 7.7.95 */
    {196, "CSG ID"},   /* 7.7.96 */
    {197, "CSG Membership Indication (CMI)"},   /* 7.7.97 */
    {198, "Aggregate Maximum Bit Rate (AMBR)"},   /* 7.7.98 */
    {199, "UE Network Capability"},   /* 7.7.99 */
    {200, "UE-AMBR"},   /* 7.7.100 */
    {201, "APN-AMBR with NSAPI"},   /* 7.7.101 */
    {202, "GGSN Back-Off Time"},   /* 7.7.102 */
    {203, "Signalling Priority Indication"},   /* 7.7.103 */
    {204, "Signalling Priority Indication with NSAPI"},   /* 7.7.104 */
    {205, "Higher bitrates than 16 Mbps flag"},   /* 7.7.105  */
    {206, "Max MBR/APN-AMBR"},   /* 7.7.106  */
    {207, "Additional MM context for SRVCC"},   /* 7.7.107  */
    {208, "Additional flags for SRVCC"},   /* 7.7.108  */
    {209, "STN-SR"},   /* 7.7.109  */
    {210, "C-MSISDN"},   /* 7.7.110  */
    {211, "Extended RANAP Cause"},   /* 7.7.111  */
	/* 212-238 TLV Spare. For future use. */
	/* 239-250 Reserved for the GPRS charging protocol (see GTP' in 3GPP TS 32.295 [33]) */
/* 249 */  {GTP_EXT_REL_PACK, "Sequence numbers of released packets IE"},  /* charging */
/* 250 */  {GTP_EXT_CAN_PACK, "Sequence numbers of canceled packets IE"},  /* charging */
/* 251 */  {GTP_EXT_CHRG_ADDR, "Charging Gateway address"}, /* 7.7.44 */
	/* 252-254 Reserved for the GPRS charging protocol (see GTP' in 3GPP TS 32.295 [33]) */
/* 252 */  {GTP_EXT_DATA_REQ, "Data record packet"},   /* charging */
/* 253 */  {GTP_EXT_DATA_RESP, "Requests responded"},  /* charging */
/* 254 */  {GTP_EXT_NODE_ADDR, "Address of recommended node"}, /* charging */
/* 255 */  {GTP_EXT_PRIV_EXT, "Private Extension"},
    {0, NULL}
};
static value_string_ext gtp_val_ext = VALUE_STRING_EXT_INIT(gtp_val);

/* It seems like some IE's are renamed in gtpv1 at least reading
 * 3GPP TS 29.060 version 6.11.0 Release 6
 */
static const value_string gtpv1_val[] = {
/*   1 */  {GTP_EXT_CAUSE, "Cause of operation"},
/*   2 */  {GTP_EXT_IMSI, "IMSI"},
/*   3 */  {GTP_EXT_RAI, "Routing Area Identity"},
/*   4 */  {GTP_EXT_TLLI, "Temporary Logical Link Identity"},
/*   5 */  {GTP_EXT_PTMSI, "Packet TMSI"},
/*   6 */  {GTP_EXT_QOS_GPRS, "Quality of Service"},
    /* 6-7 Spare */
/*   7 */  {7, "Spare"},
/*   8 */  {GTP_EXT_REORDER, "Reorder required"},
/*   9 */  {GTP_EXT_AUTH_TRI, "Authentication triplets"},
	/* 10 Spare */
/*  10 */  {10, "Spare"},
/*  11 */  {GTP_EXT_MAP_CAUSE, "MAP cause"},
/*  12 */  {GTP_EXT_PTMSI_SIG, "P-TMSI signature"},
/*  13 */  {GTP_EXT_MS_VALID, "MS validated"},
/*  14 */  {GTP_EXT_RECOVER, "Recovery"},
/*  15 */  {GTP_EXT_SEL_MODE, "Selection mode"},
/*  16 */  {GTP_EXT_TEID, "Tunnel Endpoint Identifier Data I"},    /* 3G */
/*  17 */  {GTP_EXT_TEID_CP, "Tunnel Endpoint Identifier Data Control Plane"}, /* 3G */
/*  18 */  {GTP_EXT_TEID_II, "Tunnel Endpoint Identifier Data II"},    /* 3G */
/*  19 */  {GTP_EXT_TEAR_IND, "Teardown ID"},  /* 3G */

/*  20 */  {GTP_EXT_NSAPI, "NSAPI"},   /* 3G */
/*  21 */  {GTP_EXT_RANAP_CAUSE, "RANAP cause"},   /* 3G */
/*  22 */  {GTP_EXT_RAB_CNTXT, "RAB context"}, /* 3G */
/*  23 */  {GTP_EXT_RP_SMS, "Radio Priority for MO SMS"},  /* 3G */
/*  24 */  {GTP_EXT_RP, "Radio Priority"}, /* 3G */
/*  25 */  {GTP_EXT_PKT_FLOW_ID, "Packet Flow ID"},    /* 3G */
/*  26 */  {GTP_EXT_CHRG_CHAR, "Charging characteristics"},    /* 3G */
/*  27 */  {GTP_EXT_TRACE_REF, "Trace references"},    /* 3G */
/*  28 */  {GTP_EXT_TRACE_TYPE, "Trace type"}, /* 3G */
/*  29 */  {GTPv1_EXT_MS_REASON, "MS not reachable reason"},   /* 3G */
    /* 117-126 Reserved for the GPRS charging protocol (see GTP' in 3GPP TS 32.295 [33]) */
/* 126 */  {GTP_EXT_TR_COMM, "Packet transfer command"},   /* charging */
/* 127 */  {GTP_EXT_CHRG_ID, "Charging ID"},

/* 128 */  {GTP_EXT_USER_ADDR, "End user address"},
/* 129 */  {GTP_EXT_MM_CNTXT, "MM context"},
/* 130 */  {GTP_EXT_PDP_CNTXT, "PDP context"},
/* 131 */  {GTP_EXT_APN, "Access Point Name"},
/* 132 */  {GTP_EXT_PROTO_CONF, "Protocol configuration options"},
/* 133 */  {GTP_EXT_GSN_ADDR, "GSN address"},
/* 134 */  {GTP_EXT_MSISDN, "MS international PSTN/ISDN number"},
/* 135 */  {GTP_EXT_QOS_UMTS, "Quality of service (UMTS)"},    /* 3G */
/* 136 */  {GTP_EXT_AUTH_QUI, "Authentication quintuplets"},   /* 3G */
/* 137 */  {GTP_EXT_TFT, "Traffic Flow Template (TFT)"},   /* 3G */
/* 138 */  {GTP_EXT_TARGET_ID, "Target (RNC) identification"}, /* 3G */
/* 139 */  {GTP_EXT_UTRAN_CONT, "UTRAN transparent field"},    /* 3G */
/* 140 */  {GTP_EXT_RAB_SETUP, "RAB setup information"},   /* 3G */
/* 141 */  {GTP_EXT_HDR_LIST, "Extension Header Types List"},  /* 3G */
/* 142 */  {GTP_EXT_TRIGGER_ID, "Trigger Id"}, /* 3G */
/* 143 */  {GTP_EXT_OMC_ID, "OMC Identity"},   /* 3G */
/* 144 */  {GTP_EXT_RAN_TR_CONT, "RAN Transparent Container"}, /* 7.7.43 */
/* 145 */  {GTP_EXT_PDP_CONT_PRIO, "PDP Context Prioritization"},  /* 7.7.45 */
/* 146 */  {GTP_EXT_ADD_RAB_SETUP_INF, "Additional RAB Setup Information"},    /* 7.7.45A */
/* 147 */  {GTP_EXT_SSGN_NO, "SGSN Number"},   /* 7.7.47 */
/* 148 */  {GTP_EXT_COMMON_FLGS, "Common Flags"},  /* 7.7.48 */
/* 149 */  {GTP_EXT_APN_RES, "APN Restriction"},   /* 3G */
/* 150 */  {GTP_EXT_RA_PRIO_LCS, "Radio Priority LCS"},    /* 7.7.25B */
/* 151 */  {GTP_EXT_RAT_TYPE, "RAT Type"}, /* 3G */
/* 152 */  {GTP_EXT_USR_LOC_INF, "User Location Information"}, /* 7.7.51 */
/* 153 */  {GTP_EXT_MS_TIME_ZONE, "MS Time Zone"}, /* 7.7.52 */

/* 154 */  {GTP_EXT_IMEISV, "IMEI(SV)"},   /* 3G */
/* 155 */  {GTP_EXT_CAMEL_CHG_INF_CON, "CAMEL Charging Information Container"},    /* 7.7.54 */
/* 156 */  {GTP_EXT_MBMS_UE_CTX, "MBMS UE Context"},   /* 7.7.55 */
/* 157 */  {GTP_EXT_TMGI, "Temporary Mobile Group Identity (TMGI)"},   /* 7.7.56 */
/* 158 */  {GTP_EXT_RIM_RA, "RIM Routing Address"},    /* 7.7.57 */
/* 159 */  {GTP_EXT_MBMS_PROT_CONF_OPT, "MBMS Protocol Configuration Options"},    /* 7.7.58 */
/* 160 */  {GTP_EXT_MBMS_SA, "MBMS Service Area"}, /* 7.7.60 */
/* 161 */  {GTP_EXT_SRC_RNC_PDP_CTX_INF, "Source RNC PDCP context info"},  /* 7.7.61 */
/* 162 */  {GTP_EXT_ADD_TRS_INF, "Additional Trace Info"}, /* 7.7.62 */
/* 163 */  {GTP_EXT_HOP_COUNT, "Hop Counter"}, /* 7.7.63 */
/* 164 */  {GTP_EXT_SEL_PLMN_ID, "Selected PLMN ID"},  /* 7.7.64 */
/* 165 */  {GTP_EXT_MBMS_SES_ID, "MBMS Session Identifier"},   /* 7.7.65 */
/* 166 */  {GTP_EXT_MBMS_2G_3G_IND, "MBMS 2G/3G Indicator"},   /* 7.7.66 */
/* 167 */  {GTP_EXT_ENH_NSAPI, "Enhanced NSAPI"},  /* 7.7.67 */
/* 168 */  {GTP_EXT_MBMS_SES_DUR, "MBMS Session Duration"},    /* 7.7.59 */
/* 169 */  {GTP_EXT_ADD_MBMS_TRS_INF, "Additional MBMS Trace Info"},   /* 7.7.68 */
/* 170 */  {GTP_EXT_MBMS_SES_ID_REP_NO, "MBMS Session Identity Repetition Number"},    /* 7.7.69 */
/* 171 */  {GTP_EXT_MBMS_TIME_TO_DATA_TR, "MBMS Time To Data Transfer"},   /* 7.7.70 */
/* 172 */  {GTP_EXT_PS_HO_REQ_CTX, "PS Handover Request Context"}, /* 7.7.71 */
/* 173 */  {GTP_EXT_BSS_CONT, "BSS Container"},    /* 7.7.72 */
/* 174 */  {GTP_EXT_CELL_ID, "Cell Identification"},   /* 7.7.73 */
/* 175 */  {GTP_EXT_PDU_NO, "PDU Numbers"},    /* 7.7.74 */
/* 176 */  {GTP_EXT_BSSGP_CAUSE, "BSSGP Cause"},   /* 7.7.75 */

/* 177 */  {GTP_EXT_REQ_MBMS_BEARER_CAP, "Required MBMS bearer capabilities"}, /* 7.7.76 */
/* 178 */  {GTP_EXT_RIM_ROUTING_ADDR_DISC, "RIM Routing Address Discriminator"},   /* 7.7.77 */
/* 179 */  {GTP_EXT_LIST_OF_SETUP_PFCS, "List of set-up PFCs"},    /* 7.7.78 */
/* 180 */  {GTP_EXT_PS_HANDOVER_XIP_PAR, "PS Handover XID Parameters"},    /* 7.7.79 */
/* 181 */  {GTP_EXT_MS_INF_CHG_REP_ACT, "MS Info Change Reporting Action"},    /* 7.7.80 */
/* 182 */  {GTP_EXT_DIRECT_TUNNEL_FLGS, "Direct Tunnel Flags"},    /* 7.7.81 */
/* 183 */  {GTP_EXT_CORRELATION_ID, "Correlation-ID"}, /* 7.7.82 */
/* 184 */  {GTP_EXT_BEARER_CONTROL_MODE, "Bearer Control Mode"},   /* 7.7.83 */
    {185, "MBMS Flow Identifier"},   /* 7.7.84 */
    {186, "MBMS IP Multicast Distribution"},   /* 7.7.85 */
    {187, "MBMS Distribution Acknowledgement"},   /* 7.7.86 */
    {188, "Reliable INTER RAT HANDOVER INFO"},   /* 7.7.87 */
    {189, "RFSP Index"},   /* 7.7.88 */
    {190, "Fully Qualified Domain Name (FQDN)"},   /* 7.7.90 */
    {GTP_EXT_EVO_ALLO_RETE_P1, "Evolved Allocation/Retention Priority I"},   /* 7.7.91 */
    {192, "Evolved Allocation/Retention Priority II"},   /* 7.7.92 */
    {193, "Extended Common Flags"},   /* 7.7.93 */
    {194, "User CSG Information (UCI)"},   /* 7.7.94 */
    {195, "CSG Information Reporting Action"},   /* 7.7.95 */
    {196, "CSG ID"},   /* 7.7.96 */
    {197, "CSG Membership Indication (CMI)"},   /* 7.7.97 */
    {198, "Aggregate Maximum Bit Rate (AMBR)"},   /* 7.7.98 */
    {199, "UE Network Capability"},   /* 7.7.99 */
    {200, "UE-AMBR"},   /* 7.7.100 */
    {201, "APN-AMBR with NSAPI"},   /* 7.7.101 */
    {202, "GGSN Back-Off Time"},   /* 7.7.102 */
    {203, "Signalling Priority Indication"},   /* 7.7.103 */
    {204, "Signalling Priority Indication with NSAPI"},   /* 7.7.104 */
    {205, "Higher bitrates than 16 Mbps flag"},   /* 7.7.105  */
    {206, "Max MBR/APN-AMBR"},   /* 7.7.106  */
    {207, "Additional MM context for SRVCC"},   /* 7.7.107  */
    {208, "Additional flags for SRVCC"},   /* 7.7.108  */
    {209, "STN-SR"},   /* 7.7.109  */
    {210, "C-MSISDN"},   /* 7.7.110  */
    {211, "Extended RANAP Cause"},   /* 7.7.111  */
	/* 212-238 TLV Spare. For future use. */
	/* 239-250 Reserved for the GPRS charging protocol (see GTP' in 3GPP TS 32.295 [33]) */
/* 249 */  {GTP_EXT_REL_PACK, "Sequence numbers of released packets IE"},  /* charging */
/* 250 */  {GTP_EXT_CAN_PACK, "Sequence numbers of canceled packets IE"},  /* charging */
/* 251 */  {GTP_EXT_CHRG_ADDR, "Charging Gateway address"}, /* 7.7.44 */
	/* 252-254 Reserved for the GPRS charging protocol (see GTP' in 3GPP TS 32.295 [33]) */
/* 252 */  {GTP_EXT_DATA_REQ, "Data record packet"},   /* charging */
/* 253 */  {GTP_EXT_DATA_RESP, "Requests responded"},  /* charging */
/* 254 */  {GTP_EXT_NODE_ADDR, "Address of recommended node"}, /* charging */
/* 255 */  {GTP_EXT_PRIV_EXT, "Private Extension"},

    {0, NULL}
};
static value_string_ext gtpv1_val_ext = VALUE_STRING_EXT_INIT(gtpv1_val);

/* GPRS:    9.60 v7.6.0, page 37
 * UMTS:    29.060 v4.0, page 45
 * ETSI TS 129 060 V9.4.0 (2010-10) Ch 7.7.1
 */
static const value_string cause_type[] = {
    {  0, "Request IMSI"},
    {  1, "Request IMEI"},
    {  2, "Request IMSI and IMEI"},
    {  3, "No identity needed"},
    {  4, "MS refuses"},
    {  5, "MS is not GPRS responding"},
    /* For future use 6-48 */
    /* Cause values reserved for GPRS charging
     * protocol use (see GTP' in 3GPP TS 32.295 [33])
     * 49-63
     */
    { 59, "System failure"}, /* charging */
    { 60, "The transmit buffers are becoming full"}, /* charging */
    { 61, "The receive buffers are becoming full"},  /* charging */
    { 62, "Another node is about to go down"},       /* charging */
    { 63, "This node is about to go down"},          /* charging */
    /* For future use 64-127 */
    {128, "Request accepted"},
    {129, "New PDP type due to network preference"},
    {130, "New PDP type due to single address bearer only"},
    /* For future use 131-176 */
    /* Cause values reserved for GPRS charging
     * protocol use (see GTP' in 3GPP TS 32.295 [33])
     * 177-191
     */
    {177, "CDR decoding error"},

    {192, "Non-existent"},
    {193, "Invalid message format"},
    {194, "IMSI not known"},
    {195, "MS is GPRS detached"},
    {196, "MS is not GPRS responding"},
    {197, "MS refuses"},
    {198, "Version not supported"},
    {199, "No resource available"},
    {200, "Service not supported"},
    {201, "Mandatory IE incorrect"},
    {202, "Mandatory IE missing"},
    {203, "Optional IE incorrect"},
    {204, "System failure"},
    {205, "Roaming restriction"},
    {206, "P-TMSI signature mismatch"},
    {207, "GPRS connection suspended"},
    {208, "Authentication failure"},
    {209, "User authentication failed"},
    {210, "Context not found"},
    {211, "All PDP dynamic addresses are occupied"},
    {212, "No memory is available"},
    {213, "Relocation failure"},
    {214, "Unknown mandatory extension header"},
    {215, "Semantic error in the TFT operation"},
    {216, "Syntactic error in the TFT operation"},
    {217, "Semantic errors in packet filter(s)"},
    {218, "Syntactic errors in packet filter(s)"},
    {219, "Missing or unknown APN"},
    {220, "Unknown PDP address or PDP type"},
    {221, "PDP context without TFT already activated"},
    {222, "APN access denied - no subscription"},
    {223, "APN Restriction type incompatibility with currently active PDP Contexts"},
    {224, "MS MBMS Capabilities Insufficient"},
    {225, "Invalid Correlation-ID"},
    {226, "MBMS Bearer Context Superseded"},
    {227, "Bearer Control Mode violation"},
    {228, "Collision with network initiated request"},
    /* For future use 229-240 */
    /* Cause values reserved for GPRS charging
     * protocol use (see GTP' in 3GPP TS 32.295 [33])
     * 241-255
     */
    {252, "Request related to possibly duplicated packets already fulfilled"},  /* charging */
    {253, "Request already fulfilled"}, /* charging */
    {254, "Sequence numbers of released/cancelled packets IE incorrect"},   /* charging */
    {255, "Request not fulfilled"}, /* charging */
    {0, NULL}
};
static value_string_ext cause_type_ext = VALUE_STRING_EXT_INIT(cause_type);

/* GPRS:    9.02 v7.7.0
 * UMTS:    29.002 v4.2.1, chapter 17.5, page 268
 * Imported gsm_old_GSMMAPLocalErrorcode_vals from gsm_map from gsm_map
 */

static const value_string gsn_addr_type[] = {
    {0x00, "IPv4"},
    {0x01, "IPv6"},
    {0, NULL},
};

static const value_string pdp_type[] = {
    {0x00, "X.25"},
    {0x01, "PPP"},
    {0x02, "OSP:IHOSS"},
    {0x21, "IPv4"},
    {0x57, "IPv6"},
    {0, NULL}
};

static const value_string pdp_org_type[] = {
    {0, "ETSI"},
    {1, "IETF"},
    {0, NULL}
};

static const value_string qos_delay_type[] = {
    {0x00, "Subscribed delay class (in MS to network direction)"},
    {0x01, "Delay class 1"},
    {0x02, "Delay class 2"},
    {0x03, "Delay class 3"},
    {0x04, "Delay class 4 (best effort)"},
    {0x07, "Reserved"},
    {0, NULL}
};

static const value_string qos_reliability_type[] = {
    {0x00, "Subscribed reliability class (in MS to network direction)"},
    {0x01, "Acknowledged GTP, LLC, and RLC; Protected data"},
    {0x02, "Unacknowledged GTP, Ack LLC/RLC, Protected data"},
    {0x03, "Unacknowledged GTP/LLC, Ack RLC, Protected data"},
    {0x04, "Unacknowledged GTP/LLC/RLC, Protected data"},
    {0x05, "Unacknowledged GTP/LLC/RLC, Unprotected data"},
    {0x07, "Reserved"},
    {0, NULL}
};

static const value_string qos_peak_type[] = {
    {0x00, "Subscribed peak throughput (in MS to network direction)"},
    {0x01, "Up to 1 000 oct/s"},
    {0x02, "Up to 2 000 oct/s"},
    {0x03, "Up to 4 000 oct/s"},
    {0x04, "Up to 8 000 oct/s"},
    {0x05, "Up to 16 000 oct/s"},
    {0x06, "Up to 32 000 oct/s"},
    {0x07, "Up to 64 000 oct/s"},
    {0x08, "Up to 128 000 oct/s"},
    {0x09, "Up to 256 000 oct/s"},
/* QoS Peak throughput classes from 0x0A to 0x0F (from 10 to 15) are subscribed */
    {0x0A, "Reserved"},
    {0x0B, "Reserved"},
    {0x0C, "Reserved"},
    {0x0D, "Reserved"},
    {0x0E, "Reserved"},
    {0x0F, "Reserved"},
    {0, NULL}
};

static const value_string qos_precedence_type[] = {
    {0x00, "Subscribed precedence (in MS to network direction)"},
    {0x01, "High priority"},
    {0x02, "Normal priority"},
    {0x03, "Low priority"},
    {0x07, "Reserved"},
    {0, NULL}
};

static const value_string qos_mean_type[] = {
    {0x00, "Subscribed mean throughput (in MS to network direction)"},
    {0x01, "100 oct/h"},        /* Class 2 */
    {0x02, "200 oct/h"},        /* Class 3 */
    {0x03, "500 oct/h"},        /* Class 4 */
    {0x04, "1 000 oct/h"},      /* Class 5 */
    {0x05, "2 000 oct/h"},      /* Class 6 */
    {0x06, "5 000 oct/h"},      /* Class 7 */
    {0x07, "10 000 oct/h"},     /* Class 8 */
    {0x08, "20 000 oct/h"},     /* Class 9 */
    {0x09, "50 000 oct/h"},     /* Class 10 */
    {0x0A, "100 000 oct/h"},    /* Class 11 */
    {0x0B, "200 000 oct/h"},    /* Class 12 */
    {0x0C, "500 000 oct/h"},    /* Class 13 */
    {0x0D, "1 000 000 oct/h"},  /* Class 14 */
    {0x0E, "2 000 000 oct/h"},  /* Class 15 */
    {0x0F, "5 000 000 oct/h"},  /* Class 16 */
    {0x10, "10 000 000 oct/h"}, /* Class 17 */
    {0x11, "20 000 000 oct/h"}, /* Class 18 */
    {0x12, "50 000 000 oct/h"}, /* Class 19 */
/* QoS Mean throughput classes from 0x13 to 0x1E (from 19 to 30) are subscribed */
    {0x13, "Reserved"},
    {0x14, "Reserved"},
    {0x15, "Reserved"},
    {0x16, "Reserved"},
    {0x17, "Reserved"},
    {0x18, "Reserved"},
    {0x19, "Reserved"},
    {0x1A, "Reserved"},
    {0x1B, "Reserved"},
    {0x1C, "Reserved"},
    {0x1D, "Reserved"},
    {0x1E, "Reserved"},
    {0x1F, "Best effort"},  /* Class 1 */
    {0, NULL}
};
static value_string_ext qos_mean_type_ext = VALUE_STRING_EXT_INIT(qos_mean_type);

static const value_string qos_del_err_sdu[] = {
    {0x00, "Subscribed delivery of erroneous SDUs (in MS to network direction)"},
    {0x01, "No detect ('-')"},
    {0x02, "Erroneous SDUs are delivered ('yes')"},
    {0x03, "Erroneous SDUs are not delivered ('no')"},
    {0x07, "Reserved"},  /* All other values are reserved */
    {0, NULL}
};

static const value_string qos_del_order[] = {
    {0x00, "Subscribed delivery order (in MS to network direction)"},
    {0x01, "With delivery order ('yes')"},
    {0x02, "Without delivery order ('no')"},
    {0x03, "Reserved"},  /* All other values are reserved */
    {0, NULL}
};

static const value_string qos_traf_class[] = {
    {0x00, "Subscribed traffic class (in MS to network direction)"},
    {0x01, "Conversational class"},
    {0x02, "Streaming class"},
    {0x03, "Interactive class"},
    {0x04, "Background class"},
    {0x07, "Reserved"},  /* All other values are reserved */
    {0, NULL}
};

static const value_string qos_max_sdu_size[] = {
    {0x00, "Subscribed maximum SDU size (in MS to network direction"},
    /* For values from 0x01 to 0x96 (from 1 to 150), use a granularity of 10 octets */
    {0x97, "1502 octets"},
    {0x98, "1510 octets"},
    {0x99, "1520 octets"},
    {0, NULL}             /* All other values are reserved */
};

static const value_string qos_max_ul[] = {
    {0x00, "Subscribed maximum bit rate for uplink (in MS to network direction)"},
    /* For values from 0x01 to 0x3F (from 1 to 63), use a granularity of 1 kbps */
    /* For values from 0x40 to 0x7F, value = 64 kbps + (value - 0x40) * 8 kbps */
    /* For values from 0x80 to 0xFE, value = 576 kbps + (value - 0x80) * 64 kbps */
    {0xFF, "0 kbps"},
    {0, NULL}
};

static const value_string qos_max_dl[] = {
    {0x00, "Subscribed maximum bit rate for downlink (in MS to network direction)"},
    /* For values from 0x01 to 0x3F (from 1 to 63), use a granularity of 1 kbps */
    /* For values from 0x40 to 0x7F, value = 64 kbps + (value - 0x40) * 8 kbps */
    /* For values from 0x80 to 0xFE, value = 576 kbps + (value - 0x80) * 64 kbps */
    {0xFF, "0 kbps"},
    {0, NULL}
};

static const value_string qos_res_ber[] = {
    {0x00, "Subscribed residual BER (in MS to network direction)"},
    {0x01, "1/20 = 5x10^-2"},
    {0x02, "1/100 = 1x10^-2"},
    {0x03, "1/200 = 5x10^-3"},
    {0x04, "1/250 = 4x10^-3"},
    {0x05, "1/1 000 = 1x10^-3"},
    {0x06, "1/10 000 = 1x10^-4"},
    {0x07, "1/100 000 = 1x10^-5"},
    {0x08, "1/1 000 000 = 1x10^-6"},
    {0x09, "3/50 000 000 = 6x10^-8"},
    {0x0F, "Reserved"},    /* All other values are reserved */
    {0, NULL}
};

static const value_string qos_sdu_err_ratio[] = {
    {0x00, "Subscribed SDU error ratio (in MS to network direction)"},
    {0x01, "1/100 = 1x10^-2"},
    {0x02, "7/1000 = 7x10^-3"},
    {0x03, "1/1 000 = 1x10^-3"},
    {0x04, "1/10 000 = 1x10^-4"},
    {0x05, "1/100 000 = 1x10^-5"},
    {0x06, "1/1 000 000 = 1x10^-6"},
    {0x07, "1/10 = 1x10^-1"},
    {0x0F, "Reserved"},    /* All other values are reserved */
    {0, NULL}
};

static const value_string qos_traf_handl_prio[] = {
    {0x00, "Subscribed traffic handling priority (in MS to network direction)"},
    {0x01, "Priority level 1"},
    {0x02, "Priority level 2"},
    {0x03, "Priority level 3"},
    {0, NULL}
};

static const value_string qos_trans_delay[] = {
    {0x00, "Subscribed Transfer Delay (in MS to network direction)"},
    {0x01, "10 ms"},        /* Using a granularity of 10 ms */
    {0x02, "20 ms"},
    {0x03, "30 ms"},
    {0x04, "40 ms"},
    {0x05, "50 ms"},
    {0x06, "60 ms"},
    {0x07, "70 ms"},
    {0x08, "80 ms"},
    {0x09, "90 ms"},
    {0x0A, "100 ms"},
    {0x0B, "110 ms"},
    {0x0C, "120 ms"},
    {0x0D, "130 ms"},
    {0x0E, "140 ms"},
    {0x0F, "150 ms"},
    {0x10, "200 ms"},       /* (For values from 0x10 to 0x1F, value = 200 ms + (value - 0x10) * 50 ms */
    {0x11, "250 ms"},
    {0x12, "300 ms"},
    {0x13, "350 ms"},
    {0x14, "400 ms"},
    {0x15, "450 ms"},
    {0x16, "500 ms"},
    {0x17, "550 ms"},
    {0x18, "600 ms"},
    {0x19, "650 ms"},
    {0x1A, "700 ms"},
    {0x1B, "750 ms"},
    {0x1C, "800 ms"},
    {0x1D, "850 ms"},
    {0x1E, "900 ms"},
    {0x1F, "950 ms"},
    {0x20, "1000 ms"},      /* For values from 0x20 to 0x3E, value = 1000 ms + (value - 0x20) * 100 ms */
    {0x21, "1100 ms"},
    {0x22, "1200 ms"},
    {0x23, "1300 ms"},
    {0x24, "1400 ms"},
    {0x25, "1500 ms"},
    {0x26, "1600 ms"},
    {0x27, "1700 ms"},
    {0x28, "1800 ms"},
    {0x29, "1900 ms"},
    {0x2A, "2000 ms"},
    {0x2B, "2100 ms"},
    {0x2C, "2200 ms"},
    {0x2D, "2300 ms"},
    {0x2E, "2400 ms"},
    {0x2F, "2500 ms"},
    {0x30, "2600 ms"},
    {0x31, "2700 ms"},
    {0x32, "2800 ms"},
    {0x33, "2900 ms"},
    {0x34, "3000 ms"},
    {0x35, "3100 ms"},
    {0x36, "3200 ms"},
    {0x37, "3300 ms"},
    {0x38, "3400 ms"},
    {0x39, "3500 ms"},
    {0x3A, "3600 ms"},
    {0x3B, "3700 ms"},
    {0x3C, "3800 ms"},
    {0x3D, "3900 ms"},
    {0x3E, "4000 ms"},
    {0x3F, "Reserved"},
    {0, NULL}
};
static value_string_ext qos_trans_delay_ext = VALUE_STRING_EXT_INIT(qos_trans_delay);

static const value_string qos_guar_ul[] = {
    {0x00, "Subscribed guaranteed bit rate for uplink (in MS to network direction)"},
    /* For values from 0x01 to 0x3F (from 1 to 63), use a granularity of 1 kbps */
    /* For values from 0x40 to 0x7F, value = 64 kbps + (value - 0x40) * 8 kbps */
    /* For values from 0x80 to 0xFE, value = 576 kbps + (value - 0x80) * 64 kbps */
    {0xFF, "0 kbps"},
    {0, NULL}
};

static const value_string src_stat_desc_vals[] = {
    {0x00, "unknown"},
    {0x01, "speech"},
    {0, NULL}
};


static const true_false_string gtp_sig_ind = {
    "Optimised for signalling traffic",
    "Not optimised for signalling traffic"
};

static const value_string qos_guar_dl[] = {
    {0x00, "Subscribed guaranteed bit rate for downlink (in MS to network direction)"},
    /* For values from 0x01 to 0x3F (from 1 to 63), use a granularity of 1 kbps */
    /* For values from 0x40 to 0x7F, value = 64 kbps + (value - 0x40) * 8 kbps */
    /* For values from 0x80 to 0xFE, value = 576 kbps + (value - 0x80) * 64 kbps */
    {0xFF, "0 kbps"},
    {0, NULL}
};

static const value_string sel_mode_type[] = {
    {0, "MS or network provided APN, subscribed verified"},
    {1, "MS provided APN, subscription not verified"},
    {2, "Network provided APN, subscription not verified"},
    {3, "For future use (Network provided APN, subscription not verified"}, /* Shall not be sent. If received, shall be sent as value 2 */
    {0, NULL}
};

static const value_string tr_comm_type[] = {
    {1, "Send data record packet"},
    {2, "Send possibly duplicated data record packet"},
    {3, "Cancel data record packet"},
    {4, "Release data record packet"},
    {0, NULL}
};

/* TODO: CHeck if all ms_reasons are included */
static const value_string ms_not_reachable_type[] = {
    {0, "No paging response via the MSC"},
    {1, "IMSI detached"},
    {2, "Roaming restriction"},
    {3, "Deregistered in the HLR for non GPRS"},
    {4, "MS purge for non GPRS"},
    {5, "No paging response via the SGSN"},
    {6, "GPRS detached"},
    {7, "Deregistered in the HLR for non GPRS"},
    {8, "MS purged for GPRS"},
    {9, "Unidentified subscriber via the MSC"},
    {10, "Unidentified subscriber via the SGSN"},
    {11, "Deregistered in the HSS/HLR for IMS"},
    {12, "No response via the IP-SM-GW"},
    {0, NULL}
};

/* UMTS:   25.413 v3.4.0, chapter 9.2.1.4, page 80
 */
static const value_string ranap_cause_type[] = {
/* Radio Network Layer Cause (1-->64) */
    {1, "RAB preempted"},
    {2, "Trelocoverall Expiry"},
    {3, "Trelocprep Expiry"},
    {4, "Treloccomplete Expiry"},
    {5, "Tqueuing Expiry"},
    {6, "Relocation Triggered"},
    {7, "TRELOCalloc Expiry"},
    {8, "Unable to Establish During Relocation"},
    {9, "Unknown Target RNC"},
    {10, "Relocation Cancelled"},
    {11, "Successful Relocation"},
    {12, "Requested Ciphering and/or Integrity Protection Algorithms not Supported"},
    {13, "Change of Ciphering and/or Integrity Protection is not supported"},
    {14, "Failure in the Radio Interface Procedure"},
    {15, "Release due to UTRAN Generated Reason"},
    {16, "User Inactivity"},
    {17, "Time Critical Relocation"},
    {18, "Requested Traffic Class not Available"},
    {19, "Invalid RAB Parameters Value"},
    {20, "Requested Maximum Bit Rate not Available"},
    {21, "Requested Guaranteed Bit Rate not Available"},
    {22, "Requested Transfer Delay not Achievable"},
    {23, "Invalid RAB Parameters Combination"},
    {24, "Condition Violation for SDU Parameters"},
    {25, "Condition Violation for Traffic Handling Priority"},
    {26, "Condition Violation for Guaranteed Bit Rate"},
    {27, "User Plane Versions not Supported"},
    {28, "Iu UP Failure"},
    {29, "Relocation Failure in Target CN/RNC or Target System"},
    {30, "Invalid RAB ID"},
    {31, "No Remaining RAB"},
    {32, "Interaction with other procedure"},
    {33, "Requested Maximum Bit Rate for DL not Available"},
    {34, "Requested Maximum Bit Rate for UL not Available"},
    {35, "Requested Guaranteed Bit Rate for DL not Available"},
    {36, "Requested Guaranteed Bit Rate for UL not Available"},
    {37, "Repeated Integrity Checking Failure"},
    {38, "Requested Report Type not supported"},
    {39, "Request superseded"},
    {40, "Release due to UE generated signalling connection release"},
    {41, "Resource Optimisation Relocation"},
    {42, "Requested Information Not Available"},
    {43, "Relocation desirable for radio reasons"},
    {44, "Relocation not supported in Target RNC or Target System"},
    {45, "Directed Retry"},
    {46, "Radio Connection With UE Lost"},
    {47, "rNC-unable-to-establish-all-RFCs"},
    {48, "deciphering-keys-not-available"},
    {49, "dedicated-assistance-data-not-available"},
    {50, "relocation-target-not-allowed"},
    {51, "location-reporting-congestion"},
    {52, "reduce-load-in-serving-cell"},
    {53, "no-radio-resources-available-in-target-cell"},
    {54, "gERAN-Iumode-failure"},
    {55, "access-restricted-due-to-shared-networks"},
    {56, "incoming-relocation-not-supported-due-to-PUESBINE-feature"},
    {57, "traffic-load-in-the-target-cell-higher-than-in-the-source-cell"},
    {58, "mBMS-no-multicast-service-for-this-UE"},
    {59, "mBMS-unknown-UE-ID"},
    {60, "successful-MBMS-session-start-no-data-bearer-necessary"},
    {61, "mBMS-superseded-due-to-NNSF"},
    {62, "mBMS-UE-linking-already-done"},
    {63, "mBMS-UE-de-linking-failure-no-existing-UE-linking"},
    {64, "tMGI-unknown"},
/* Transport Layer Cause (65-->80) */
    {65, "Signalling Transport Resource Failure"},
    {66, "Iu Transport Connection Failed to Establish"},
/* NAS Cause (81-->96) */
    {81, "User Restriction Start Indication"},
    {82, "User Restriction End Indication"},
    {83, "Normal Release"},
/* Protocol Cause (97-->112) */
    {97, "Transfer Syntax Error"},
    {98, "Semantic Error"},
    {99, "Message not compatible with receiver state"},
    {100, "Abstract Syntax Error (Reject)"},
    {101, "Abstract Syntax Error (Ignore and Notify)"},
    {102, "Abstract Syntax Error (Falsely Constructed Message"},
/* Miscellaneous Cause (113-->128) */
    {113, "O & M Intervention"},
    {114, "No Resource Available"},
    {115, "Unspecified Failure"},
    {116, "Network Optimisation"},
/* Non-standard Cause (129-->255) */

/* ranap_CauseRadioNetworkExtension ??
    { 257, "iP-multicast-address-and-APN-not-valid" },
    { 258, "mBMS-de-registration-rejected-due-to-implicit-registration" },
    { 259, "mBMS-request-superseded" },
    { 260, "mBMS-de-registration-during-session-not-allowed" },
    { 261, "mBMS-no-data-bearer-necessary" },
  */

    {0, NULL}
};
static value_string_ext ranap_cause_type_ext = VALUE_STRING_EXT_INIT(ranap_cause_type);

static const value_string mm_sec_modep[] = {
    {0, "Used cipher value, UMTS keys and Quintuplets"},
    {1, "GSM key and triplets"},
    {2, "UMTS key and quintuplets"},
    {3, "GSM key and quintuplets"},
    {0, NULL}
};

static const value_string gtp_cipher_algorithm[] = {
    {0, "No ciphering"},
    {1, "GEA/1"},
    {2, "GEA/2"},
    {3, "GEA/3"},
    {4, "GEA/4"},
    {5, "GEA/5"},
    {6, "GEA/6"},
    {7, "GEA/7"},
    {0, NULL}
};
static const value_string gtp_ext_rat_type_vals[] = {
      {0, "Reserved"},
      {1, "UTRAN"},
      {2, "GERAN"},
      {3, "WLAN"},
      {4, "GAN"},
      {5, "HSPA Evolution"},
      {0, NULL}
};

#define MM_PROTO_GROUP_CALL_CONTROL     0x00
#define MM_PROTO_BROADCAST_CALL_CONTROL 0x01
#define MM_PROTO_PDSS1                  0x02
#define MM_PROTO_CALL_CONTROL           0x03
#define MM_PROTO_PDSS2                  0x04
#define MM_PROTO_MM_NON_GPRS            0x05
#define MM_PROTO_RR_MGMT                0x06
#define MM_PROTO_MM_GPRS                0x08
#define MM_PROTO_SMS                    0x09
#define MM_PROTO_SESSION_MGMT           0x0A
#define MM_PROTO_NON_CALL_RELATED       0x0B

static const value_string tft_code_type[] = {
    {0, "Spare"},
    {1, "Create new TFT"},
    {2, "Delete existing TFT"},
    {3, "Add packet filters to existing TFT"},
    {4, "Replace packet filters in existing TFT"},
    {5, "Delete packet filters from existing TFT"},
    {6, "Reserved"},
    {7, "Reserved"},
    {0, NULL}
};


static dissector_handle_t ip_handle;
static dissector_handle_t ipv6_handle;
static dissector_handle_t ppp_handle;
static dissector_handle_t data_handle;
static dissector_handle_t gtpcdr_handle;
static dissector_handle_t sndcpxid_handle;
static dissector_handle_t gtpv2_handle;
static dissector_handle_t bssgp_handle;
static dissector_table_t bssap_pdu_type_table;

static gtp_msg_hash_t *gtp_match_response(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, gint seq_nr, guint msgtype);

static int decode_gtp_cause(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_imsi(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_rai(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_tlli(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_ptmsi(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_qos_gprs(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_reorder(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_auth_tri(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_map_cause(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_ptmsi_sig(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_ms_valid(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_recovery(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_sel_mode(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_16(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_17(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_18(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_19(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_nsapi(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_ranap_cause(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_rab_cntxt(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_rp_sms(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_rp(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_pkt_flow_id(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_chrg_char(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_trace_ref(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_trace_type(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_ms_reason(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_tr_comm(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_chrg_id(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_user_addr(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_mm_cntxt(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_pdp_cntxt(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_apn(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_gsn_addr(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_proto_conf(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_msisdn(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_qos_umts(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_auth_qui(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_tft(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_target_id(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_utran_cont(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_rab_setup(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_hdr_list(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_trigger_id(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_omc_id(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);

static int decode_gtp_ran_tr_cont(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_pdp_cont_prio(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_add_rab_setup_inf(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_ssgn_no(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_common_flgs(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_apn_res(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_ra_prio_lcs(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_rat_type(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_usr_loc_inf(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_ms_time_zone(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_imeisv(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_camel_chg_inf_con(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_mbms_ue_ctx(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_tmgi(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_rim_ra(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_mbms_prot_conf_opt(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_mbms_sa(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_src_rnc_pdp_ctx_inf(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_add_trs_inf(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_hop_count(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_sel_plmn_id(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_mbms_ses_id(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_mbms_2g_3g_ind(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_enh_nsapi(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_mbms_ses_dur(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_add_mbms_trs_inf(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_mbms_ses_id_rep_no(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_mbms_time_to_data_tr(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_ps_ho_req_ctx(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_bss_cont(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_cell_id(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_pdu_no(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_bssgp_cause(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_mbms_bearer_cap(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree);
static int decode_gtp_rim_ra_disc(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree);
static int decode_gtp_lst_set_up_pfc(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_ps_handover_xid(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_direct_tnl_flg(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_ms_inf_chg_rep_act(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_corrl_id(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_evolved_allc_rtn_p1(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_bearer_cntrl_mod(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_chrg_addr(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_rel_pack(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_can_pack(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_data_req(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_data_resp(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_node_addr(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_priv_ext(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);
static int decode_gtp_unknown(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree);

typedef struct _gtp_opt {
    int optcode;
    int (*decode) (tvbuff_t *, int, packet_info *, proto_tree *);
} gtp_opt_t;

static const gtp_opt_t gtpopt[] = {
    {GTP_EXT_CAUSE, decode_gtp_cause},
    {GTP_EXT_IMSI, decode_gtp_imsi},
    {GTP_EXT_RAI, decode_gtp_rai},
    {GTP_EXT_TLLI, decode_gtp_tlli},
    {GTP_EXT_PTMSI, decode_gtp_ptmsi},
    {GTP_EXT_QOS_GPRS, decode_gtp_qos_gprs},
    {GTP_EXT_REORDER, decode_gtp_reorder},
    {GTP_EXT_AUTH_TRI, decode_gtp_auth_tri},
    {GTP_EXT_MAP_CAUSE, decode_gtp_map_cause},
    {GTP_EXT_PTMSI_SIG, decode_gtp_ptmsi_sig},
    {GTP_EXT_MS_VALID, decode_gtp_ms_valid},
    {GTP_EXT_RECOVER, decode_gtp_recovery},
    {GTP_EXT_SEL_MODE, decode_gtp_sel_mode},
    {GTP_EXT_16, decode_gtp_16},
    {GTP_EXT_17, decode_gtp_17},
    {GTP_EXT_18, decode_gtp_18},
    {GTP_EXT_19, decode_gtp_19},
    {GTP_EXT_NSAPI, decode_gtp_nsapi},
    {GTP_EXT_RANAP_CAUSE, decode_gtp_ranap_cause},
    {GTP_EXT_RAB_CNTXT, decode_gtp_rab_cntxt},
    {GTP_EXT_RP_SMS, decode_gtp_rp_sms},
    {GTP_EXT_RP, decode_gtp_rp},
    {GTP_EXT_PKT_FLOW_ID, decode_gtp_pkt_flow_id},
    {GTP_EXT_CHRG_CHAR, decode_gtp_chrg_char},
    {GTP_EXT_TRACE_REF, decode_gtp_trace_ref},
    {GTP_EXT_TRACE_TYPE, decode_gtp_trace_type},
    {GTPv1_EXT_MS_REASON, decode_gtp_ms_reason},
    {GTP_EXT_TR_COMM, decode_gtp_tr_comm},
    {GTP_EXT_CHRG_ID, decode_gtp_chrg_id},
    {GTP_EXT_USER_ADDR, decode_gtp_user_addr},
    {GTP_EXT_MM_CNTXT, decode_gtp_mm_cntxt},
    {GTP_EXT_PDP_CNTXT, decode_gtp_pdp_cntxt},
    {GTP_EXT_APN, decode_gtp_apn},
    {GTP_EXT_PROTO_CONF, decode_gtp_proto_conf},
    {GTP_EXT_GSN_ADDR, decode_gtp_gsn_addr},
    {GTP_EXT_MSISDN, decode_gtp_msisdn},
    {GTP_EXT_QOS_UMTS, decode_gtp_qos_umts},    /* 3G */
    {GTP_EXT_AUTH_QUI, decode_gtp_auth_qui},    /* 3G */
    {GTP_EXT_TFT, decode_gtp_tft},  /* 3G */
    {GTP_EXT_TARGET_ID, decode_gtp_target_id},  /* 3G */
    {GTP_EXT_UTRAN_CONT, decode_gtp_utran_cont},    /* 3G */
    {GTP_EXT_RAB_SETUP, decode_gtp_rab_setup},  /* 3G */
    {GTP_EXT_HDR_LIST, decode_gtp_hdr_list},    /* 3G */
    {GTP_EXT_TRIGGER_ID, decode_gtp_trigger_id},    /* 3G */
    {GTP_EXT_OMC_ID, decode_gtp_omc_id},    /* 3G */
    /* TS 29 060 V6.11.0 */
    {GTP_EXT_RAN_TR_CONT, decode_gtp_ran_tr_cont},  /* 7.7.43 */
    {GTP_EXT_PDP_CONT_PRIO, decode_gtp_pdp_cont_prio},  /* 7.7.45 */
    {GTP_EXT_ADD_RAB_SETUP_INF, decode_gtp_add_rab_setup_inf},  /* 7.7.45A */
    {GTP_EXT_SSGN_NO, decode_gtp_ssgn_no},  /* 7.7.47 */
    {GTP_EXT_COMMON_FLGS, decode_gtp_common_flgs},  /* 7.7.48 */
    {GTP_EXT_APN_RES, decode_gtp_apn_res},  /* 3G */
    {GTP_EXT_RA_PRIO_LCS, decode_gtp_ra_prio_lcs},  /* 7.7.25B */
    {GTP_EXT_RAT_TYPE, decode_gtp_rat_type},    /* 3G */
    {GTP_EXT_USR_LOC_INF, decode_gtp_usr_loc_inf},  /* 7.7.51 */
    {GTP_EXT_MS_TIME_ZONE, decode_gtp_ms_time_zone},    /* 7.7.52 */
    {GTP_EXT_IMEISV, decode_gtp_imeisv},    /* 3G 7.7.53 */
    {GTP_EXT_CAMEL_CHG_INF_CON, decode_gtp_camel_chg_inf_con},  /* 7.7.54 */
    {GTP_EXT_MBMS_UE_CTX, decode_gtp_mbms_ue_ctx},  /* 7.7.55 */
    {GTP_EXT_TMGI, decode_gtp_tmgi},    /* 7.7.56 */
    {GTP_EXT_RIM_RA, decode_gtp_rim_ra},    /* 7.7.57 */
    {GTP_EXT_MBMS_PROT_CONF_OPT, decode_gtp_mbms_prot_conf_opt},    /* 7.7.58 */
    {GTP_EXT_MBMS_SA, decode_gtp_mbms_sa},  /* 7.7.60 */
    {GTP_EXT_SRC_RNC_PDP_CTX_INF, decode_gtp_src_rnc_pdp_ctx_inf},  /* 7.7.61 */
    {GTP_EXT_ADD_TRS_INF, decode_gtp_add_trs_inf},  /* 7.7.62 */
    {GTP_EXT_HOP_COUNT, decode_gtp_hop_count},  /* 7.7.63 */
    {GTP_EXT_SEL_PLMN_ID, decode_gtp_sel_plmn_id},  /* 7.7.64 */
    {GTP_EXT_MBMS_SES_ID, decode_gtp_mbms_ses_id},  /* 7.7.65 */
    {GTP_EXT_MBMS_2G_3G_IND, decode_gtp_mbms_2g_3g_ind},    /* 7.7.66 */
    {GTP_EXT_ENH_NSAPI, decode_gtp_enh_nsapi},  /* 7.7.67 */
    {GTP_EXT_MBMS_SES_DUR, decode_gtp_mbms_ses_dur},    /* 7.7.59 */
    {GTP_EXT_ADD_MBMS_TRS_INF, decode_gtp_add_mbms_trs_inf},    /* 7.7.68 */
    {GTP_EXT_MBMS_SES_ID_REP_NO, decode_gtp_mbms_ses_id_rep_no},    /* 7.7.69 */
    {GTP_EXT_MBMS_TIME_TO_DATA_TR, decode_gtp_mbms_time_to_data_tr},    /* 7.7.70 */
    {GTP_EXT_PS_HO_REQ_CTX, decode_gtp_ps_ho_req_ctx},  /* 7.7.71 */
    {GTP_EXT_BSS_CONT, decode_gtp_bss_cont},    /* 7.7.72 */
    {GTP_EXT_CELL_ID, decode_gtp_cell_id},  /* 7.7.73 */
    {GTP_EXT_PDU_NO, decode_gtp_pdu_no},    /* 7.7.74 */
    {GTP_EXT_BSSGP_CAUSE, decode_gtp_bssgp_cause},  /* 7.7.75 */
    {GTP_EXT_REQ_MBMS_BEARER_CAP, decode_gtp_mbms_bearer_cap},  /* 7.7.76 */
    {GTP_EXT_RIM_ROUTING_ADDR_DISC, decode_gtp_rim_ra_disc},    /* 7.7.77 */
    {GTP_EXT_LIST_OF_SETUP_PFCS, decode_gtp_lst_set_up_pfc},    /* 7.7.78 */
    {GTP_EXT_PS_HANDOVER_XIP_PAR, decode_gtp_ps_handover_xid},  /* 7.7.79 */
    {GTP_EXT_MS_INF_CHG_REP_ACT, decode_gtp_ms_inf_chg_rep_act},    /* 7.7.80 */
    {GTP_EXT_DIRECT_TUNNEL_FLGS, decode_gtp_direct_tnl_flg},    /* 7.7.81 */
    {GTP_EXT_CORRELATION_ID, decode_gtp_corrl_id},  /* 7.7.82 */
    {GTP_EXT_BEARER_CONTROL_MODE, decode_gtp_bearer_cntrl_mod}, /* 7.7.83 */
    {GTP_EXT_EVO_ALLO_RETE_P1, decode_gtp_evolved_allc_rtn_p1}, /* 7.7.91 */
    {GTP_EXT_REL_PACK, decode_gtp_rel_pack},    /* charging */
    {GTP_EXT_CAN_PACK, decode_gtp_can_pack},    /* charging */
    {GTP_EXT_CHRG_ADDR, decode_gtp_chrg_addr},
    {GTP_EXT_DATA_REQ, decode_gtp_data_req},    /* charging */
    {GTP_EXT_DATA_RESP, decode_gtp_data_resp},  /* charging */
    {GTP_EXT_NODE_ADDR, decode_gtp_node_addr},
    {GTP_EXT_PRIV_EXT, decode_gtp_priv_ext},
    {0, decode_gtp_unknown}
};

struct _gtp_hdr {
    guint8 flags;
    guint8 message;
    guint16 length;
};

static guint8 gtp_version = 0;
static const char *yesno[] = { "no", "yes" };

#define BCD2CHAR(d)         ((d) | 0x30)

static gchar *
id_to_str(tvbuff_t *tvb, gint offset)
{
    static gchar str[17] = "                ";
    guint8 bits8to5, bits4to1;
    int i, j;
    guint8 ad;

    for (i = j = 0; i < 8; i++) {
        ad = tvb_get_guint8(tvb, offset + i);
        bits8to5 = hi_nibble(ad);
        bits4to1 = lo_nibble(ad);
        if (bits4to1 <= 9)
            str[j++] = BCD2CHAR(bits4to1);
        else
            j++;
        if (bits8to5 <= 9)
            str[j++] = BCD2CHAR(bits8to5);
        else
            j++;
    }
    str[j] = '\0';
    return str;
}

static gchar *
msisdn_to_str(tvbuff_t *tvb, gint offset, int len)
{
    static gchar str[18] = "+                ";
    guint8 bits8to5, bits4to1;
    int i, j;
    guint ad;

    for (i = j = 1; i < MIN(len, 9); i++) {
        ad = tvb_get_guint8(tvb, offset + i);
        bits8to5 = hi_nibble(ad);
        bits4to1 = lo_nibble(ad);
        if (bits4to1 <= 9)
            str[j++] = BCD2CHAR(bits4to1);
        else
            j++;
        if (bits8to5 <= 9)
            str[j++] = BCD2CHAR(bits8to5);
        else
            j++;
    }
    str[j] = '\0';

    return str;
}

/* Next definitions and function check_field_presence checks if given field
 * in GTP packet is compliant with ETSI
 */
typedef struct _header {
    guint8 code;
    guint8 presence;
} ext_header;

typedef struct _message {
    guint8 code;
    ext_header fields[32];
} _gtp_mess_items;

/* ---------------------
 * GPRS messages
 * ---------------------*/
static _gtp_mess_items gprs_mess_items[] = {

    {
        GTP_MSG_ECHO_REQ, {
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_ECHO_RESP, {
            {GTP_EXT_RECOVER, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_VER_NOT_SUPP, {
            {0, 0}
        }
    },
    {
        GTP_MSG_NODE_ALIVE_REQ, {
            {GTP_EXT_NODE_ADDR, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_NODE_ALIVE_RESP, {
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_REDIR_REQ, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_NODE_ADDR, GTP_OPTIONAL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_REDIR_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_CREATE_PDP_REQ, {
            {GTP_EXT_QOS_GPRS, GTP_MANDATORY},
            {GTP_EXT_RECOVER, GTP_OPTIONAL},
            {GTP_EXT_SEL_MODE, GTP_MANDATORY},
            {GTP_EXT_FLOW_LABEL, GTP_MANDATORY},
            {GTP_EXT_FLOW_SIG, GTP_MANDATORY},
            {GTP_EXT_MSISDN, GTP_MANDATORY},
            {GTP_EXT_USER_ADDR, GTP_MANDATORY},
            {GTP_EXT_APN, GTP_MANDATORY},
            {GTP_EXT_PROTO_CONF, GTP_OPTIONAL},
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY},
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_CREATE_PDP_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_QOS_GPRS, GTP_CONDITIONAL},
            {GTP_EXT_REORDER, GTP_CONDITIONAL},
            {GTP_EXT_RECOVER, GTP_OPTIONAL},
            {GTP_EXT_FLOW_LABEL, GTP_CONDITIONAL},
            {GTP_EXT_FLOW_SIG, GTP_CONDITIONAL},
            {GTP_EXT_CHRG_ID, GTP_CONDITIONAL},
            {GTP_EXT_USER_ADDR, GTP_CONDITIONAL},
            {GTP_EXT_PROTO_CONF, GTP_OPTIONAL},
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL},
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL},
            {GTP_EXT_CHRG_ADDR, GTP_OPTIONAL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_UPDATE_PDP_REQ, {
            {GTP_EXT_QOS_GPRS, GTP_MANDATORY},
            {GTP_EXT_RECOVER, GTP_OPTIONAL},
            {GTP_EXT_FLOW_LABEL, GTP_MANDATORY},
            {GTP_EXT_FLOW_SIG, GTP_MANDATORY},
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY},
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0},
        }
    },
    {
        GTP_MSG_UPDATE_PDP_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_QOS_GPRS, GTP_CONDITIONAL},
            {GTP_EXT_RECOVER, GTP_OPTIONAL},
            {GTP_EXT_FLOW_LABEL, GTP_CONDITIONAL},
            {GTP_EXT_FLOW_SIG, GTP_CONDITIONAL},
            {GTP_EXT_CHRG_ID, GTP_CONDITIONAL},
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL},
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL},
            {GTP_EXT_CHRG_ADDR, GTP_OPTIONAL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_DELETE_PDP_REQ, {
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_DELETE_PDP_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0},
        }
    },
    {
        GTP_MSG_INIT_PDP_CONTEXT_ACT_REQ, {
            {GTP_EXT_QOS_GPRS, GTP_MANDATORY},
            {GTP_EXT_RECOVER, GTP_OPTIONAL},
            {GTP_EXT_SEL_MODE, GTP_MANDATORY},
            {GTP_EXT_FLOW_LABEL, GTP_MANDATORY},
            {GTP_EXT_FLOW_SIG, GTP_MANDATORY},
            {GTP_EXT_USER_ADDR, GTP_MANDATORY},
            {GTP_EXT_APN, GTP_MANDATORY},
            {GTP_EXT_PROTO_CONF, GTP_OPTIONAL},
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY},
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_INIT_PDP_CONTEXT_ACT_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_QOS_GPRS, GTP_CONDITIONAL},
            {GTP_EXT_REORDER, GTP_CONDITIONAL},
            {GTP_EXT_RECOVER, GTP_OPTIONAL},
            {GTP_EXT_FLOW_LABEL, GTP_CONDITIONAL},
            {GTP_EXT_FLOW_SIG, GTP_CONDITIONAL},
            {GTP_EXT_CHRG_ID, GTP_CONDITIONAL},
            {GTP_EXT_USER_ADDR, GTP_CONDITIONAL},
            {GTP_EXT_PROTO_CONF, GTP_OPTIONAL},
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL},
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL},
            {GTP_EXT_CHRG_ADDR, GTP_OPTIONAL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_DELETE_AA_PDP_REQ, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_DELETE_AA_PDP_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_ERR_IND, {
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_PDU_NOTIFY_REQ, {
            {GTP_EXT_USER_ADDR, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_PDU_NOTIFY_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_PDU_NOTIFY_REJ_REQ, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_USER_ADDR, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_PDU_NOTIFY_REJ_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_SEND_ROUT_INFO_REQ, {
            {GTP_EXT_IMSI, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_SEND_ROUT_INFO_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_IMSI, GTP_MANDATORY},
            {GTP_EXT_MAP_CAUSE, GTP_OPTIONAL},
            {GTP_EXT_MS_REASON, GTP_OPTIONAL},
            {GTP_EXT_GSN_ADDR, GTP_OPTIONAL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_FAIL_REP_REQ, {
            {GTP_EXT_IMSI, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_FAIL_REP_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_MAP_CAUSE, GTP_OPTIONAL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_MS_PRESENT_REQ, {
            {GTP_EXT_IMSI, GTP_MANDATORY},
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_MS_PRESENT_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_IDENT_REQ, {
            {GTP_EXT_RAI, GTP_MANDATORY},
            {GTP_EXT_PTMSI, GTP_MANDATORY},
            {GTP_EXT_PTMSI_SIG, GTP_OPTIONAL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_IDENT_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_IMSI, GTP_CONDITIONAL},
            {GTP_EXT_AUTH_TRI, GTP_OPTIONAL},
            {GTP_EXT_AUTH_QUI, GTP_OPTIONAL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_SGSN_CNTXT_REQ, {
            {GTP_EXT_IMSI, GTP_CONDITIONAL},
            {GTP_EXT_RAI, GTP_MANDATORY},
            {GTP_EXT_TLLI, GTP_MANDATORY},
            {GTP_EXT_PTMSI_SIG, GTP_OPTIONAL},
            {GTP_EXT_MS_VALID, GTP_OPTIONAL},
            {GTP_EXT_FLOW_SIG, GTP_MANDATORY},
            {0, 0}
        }
    },
    {
        GTP_MSG_SGSN_CNTXT_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_IMSI, GTP_CONDITIONAL},
            {GTP_EXT_FLOW_SIG, GTP_CONDITIONAL},
            {GTP_EXT_MM_CNTXT, GTP_CONDITIONAL},
            {GTP_EXT_PDP_CNTXT, GTP_CONDITIONAL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_SGSN_CNTXT_ACK, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_FLOW_II, GTP_CONDITIONAL},
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_DATA_TRANSF_REQ, {
            {GTP_EXT_TR_COMM, GTP_MANDATORY},
            {GTP_EXT_DATA_REQ, GTP_CONDITIONAL},
            {GTP_EXT_REL_PACK, GTP_CONDITIONAL},
            {GTP_EXT_CAN_PACK, GTP_CONDITIONAL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_DATA_TRANSF_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_DATA_RESP, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        0, {
            {0, 0}
        }
    }
};

/* -----------------------------
 * UMTS messages
 * -----------------------------*/
static _gtp_mess_items umts_mess_items[] = {
    /* 7.2 Path Management Messages */
    {
        GTP_MSG_ECHO_REQ, {
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_ECHO_RESP, {
            {GTP_EXT_RECOVER, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_VER_NOT_SUPP, {
            {0, 0}
        }
    },
    {
        GTP_MSG_SUPP_EXT_HDR, {
            {GTP_EXT_HDR_LIST, GTP_MANDATORY},
            {0, 0}
        }
    },
    /* ??? */
    {
        GTP_MSG_NODE_ALIVE_REQ, {
            {GTP_EXT_NODE_ADDR, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_NODE_ALIVE_RESP, {
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_REDIR_REQ, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_NODE_ADDR, GTP_OPTIONAL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_REDIR_REQ, {
            {0, 0}
        }
    },
    /* 7.3 Tunnel Management Messages */
    {
        GTP_MSG_CREATE_PDP_REQ, {
            {GTP_EXT_IMSI, GTP_CONDITIONAL},
            /* RAI is in TS 29.060 V6.11.0 */
            {GTP_EXT_RAI, GTP_OPTIONAL},        /* Routeing Area Identity (RAI) Optional 7.7.3 */
            {GTP_EXT_RECOVER, GTP_OPTIONAL},
            {GTP_EXT_SEL_MODE, GTP_CONDITIONAL},
            {GTP_EXT_TEID, GTP_MANDATORY},
            {GTP_EXT_TEID_CP, GTP_CONDITIONAL},
            {GTP_EXT_NSAPI, GTP_MANDATORY},
            {GTP_EXT_NSAPI, GTP_CONDITIONAL},
            {GTP_EXT_CHRG_CHAR, GTP_OPTIONAL},
            {GTP_EXT_TRACE_REF, GTP_OPTIONAL},
            {GTP_EXT_TRACE_TYPE, GTP_OPTIONAL},
            {GTP_EXT_USER_ADDR, GTP_CONDITIONAL},
            {GTP_EXT_APN, GTP_CONDITIONAL},
            {GTP_EXT_PROTO_CONF, GTP_CONDITIONAL},
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY},
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY},
            {GTP_EXT_MSISDN, GTP_CONDITIONAL},
            {GTP_EXT_QOS_UMTS, GTP_MANDATORY},
            {GTP_EXT_TFT, GTP_CONDITIONAL},
            {GTP_EXT_TRIGGER_ID, GTP_OPTIONAL},
            {GTP_EXT_OMC_ID, GTP_OPTIONAL},
            /* TS 29.060 V6.11.0 */
            {GTP_EXT_APN_RES, GTP_OPTIONAL},
            {GTP_EXT_RAT_TYPE, GTP_OPTIONAL},
            {GTP_EXT_USR_LOC_INF, GTP_OPTIONAL},
            {GTP_EXT_MS_TIME_ZONE, GTP_OPTIONAL},
            {GTP_EXT_IMEISV, GTP_OPTIONAL},
            {GTP_EXT_CAMEL_CHG_INF_CON, GTP_OPTIONAL},
            {GTP_EXT_ADD_TRS_INF, GTP_OPTIONAL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_CREATE_PDP_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_REORDER, GTP_CONDITIONAL},
            {GTP_EXT_RECOVER, GTP_OPTIONAL},
            {GTP_EXT_TEID, GTP_CONDITIONAL},
            {GTP_EXT_TEID_CP, GTP_CONDITIONAL},
            {GTP_EXT_NSAPI, GTP_CONDITIONAL},
            {GTP_EXT_CHRG_ID, GTP_CONDITIONAL},
            {GTP_EXT_USER_ADDR, GTP_CONDITIONAL},
            {GTP_EXT_PROTO_CONF, GTP_OPTIONAL},
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL},
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL},
            {GTP_EXT_QOS_UMTS, GTP_CONDITIONAL},
            {GTP_EXT_CHRG_ADDR, GTP_OPTIONAL},
            /* TS 29.060 V6.11.0 */
            {GTP_EXT_CHRG_ADDR, GTP_OPTIONAL},  /* Alternative Charging Gateway Address Optional 7.7.44 */
            {GTP_EXT_COMMON_FLGS, GTP_OPTIONAL},        /* Common Flags Optional 7.7.48 */
            {GTP_EXT_APN_RES, GTP_OPTIONAL},    /* APN Restriction Optional 7.7.49 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {                           /* checked, SGSN -> GGSN */
        GTP_MSG_UPDATE_PDP_REQ, {
            {GTP_EXT_IMSI, GTP_CONDITIONAL},
            {GTP_EXT_RAI, GTP_OPTIONAL},        /* Routeing Area Identity (RAI) Optional 7.7.3 */
            {GTP_EXT_RECOVER, GTP_OPTIONAL},
            {GTP_EXT_TEID, GTP_MANDATORY},
            {GTP_EXT_TEID_CP, GTP_CONDITIONAL},
            {GTP_EXT_NSAPI, GTP_MANDATORY},
            {GTP_EXT_TRACE_REF, GTP_OPTIONAL},
            {GTP_EXT_TRACE_TYPE, GTP_OPTIONAL},
            {GTP_EXT_PROTO_CONF, GTP_OPTIONAL}, /* Protocol Configuration Options Optional 7.7.31 */
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY},  /* SGSN Address for Control Plane Mandatory GSN Address 7.7.32 */
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY},  /* SGSN Address for User Traffic Mandatory GSN Address 7.7.32 */
            {GTP_EXT_GSN_ADDR, GTP_OPTIONAL},   /* Alternative SGSN Address for Control Plane Conditional GSN Address 7.7.32 */
            {GTP_EXT_GSN_ADDR, GTP_OPTIONAL},   /* Alternative SGSN Address for User Traffic Conditional GSN Address 7.7.32 */
            {GTP_EXT_QOS_UMTS, GTP_MANDATORY},
            {GTP_EXT_TFT, GTP_OPTIONAL},
            {GTP_EXT_TRIGGER_ID, GTP_OPTIONAL},
            {GTP_EXT_OMC_ID, GTP_OPTIONAL},
            {GTP_EXT_COMMON_FLGS, GTP_OPTIONAL},                        /* Common Flags Optional 7.7.48 */
            {GTP_EXT_RAT_TYPE, GTP_OPTIONAL},                           /* RAT Type Optional 7.7.50 */
            {GTP_EXT_USR_LOC_INF, GTP_OPTIONAL},                        /* User Location Information Optional 7.7.51 */
            {GTP_EXT_MS_TIME_ZONE, GTP_OPTIONAL},                       /* MS Time Zone Optional 7.7.52 */
            {GTP_EXT_ADD_TRS_INF, GTP_OPTIONAL},                        /* Additonal Trace Info Optional 7.7.62 */
            {GTP_EXT_DIRECT_TUNNEL_FLGS, GTP_OPTIONAL}, /* Direct Tunnel Flags     7.7.81 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {                           /* checked, GGSN -> SGSN */
        GTP_MSG_UPDATE_PDP_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_RECOVER, GTP_OPTIONAL},
            {GTP_EXT_TEID, GTP_CONDITIONAL},
            {GTP_EXT_TEID_CP, GTP_CONDITIONAL},
            {GTP_EXT_CHRG_ID, GTP_CONDITIONAL},
            {GTP_EXT_PROTO_CONF, GTP_OPTIONAL}, /* Protocol Configuration Options Optional 7.7.31 */
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL},
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL},
            {GTP_EXT_GSN_ADDR, GTP_OPTIONAL},   /* Alternative SGSN Address for Control Plane Conditional GSN Address 7.7.32 */
            {GTP_EXT_GSN_ADDR, GTP_OPTIONAL},   /* Alternative SGSN Address for User Traffic Conditional GSN Address 7.7.32 */
            {GTP_EXT_QOS_UMTS, GTP_CONDITIONAL},
            {GTP_EXT_CHRG_ADDR, GTP_OPTIONAL},
            {GTP_EXT_CHRG_ADDR, GTP_OPTIONAL},  /* Alternative Charging Gateway Address Optional 7.7.44 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {GTP_EXT_COMMON_FLGS, GTP_OPTIONAL},        /* Common Flags Optional 7.7.48 */
            {GTP_EXT_APN_RES, GTP_OPTIONAL},    /* APN Restriction Optional 7.7.49 */
            {0, 0}
        }
    },
    {
        GTP_MSG_DELETE_PDP_REQ, {
            {GTP_EXT_TEAR_IND, GTP_CONDITIONAL},
            {GTP_EXT_NSAPI, GTP_MANDATORY},
            {GTP_EXT_PROTO_CONF, GTP_OPTIONAL}, /* Protocol Configuration Options Optional 7.7.31 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_DELETE_PDP_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_PROTO_CONF, GTP_OPTIONAL}, /* Protocol Configuration Options Optional 7.7.31 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_ERR_IND, {
            {GTP_EXT_TEID, GTP_MANDATORY},
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY},  /* GSN Address Mandatory 7.7.32 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_PDU_NOTIFY_REQ, {
            {GTP_EXT_IMSI, GTP_MANDATORY},
            {GTP_EXT_TEID_CP, GTP_MANDATORY},
            {GTP_EXT_USER_ADDR, GTP_MANDATORY},
            {GTP_EXT_APN, GTP_MANDATORY},
            {GTP_EXT_PROTO_CONF, GTP_OPTIONAL}, /* Protocol Configuration Options Optional 7.7.31 */
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_PDU_NOTIFY_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_PDU_NOTIFY_REJ_REQ, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_TEID_CP, GTP_MANDATORY},
            {GTP_EXT_USER_ADDR, GTP_MANDATORY},
            {GTP_EXT_APN, GTP_MANDATORY},
            {GTP_EXT_PROTO_CONF, GTP_OPTIONAL}, /* Protocol Configuration Options Optional 7.7.31 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_PDU_NOTIFY_REJ_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    /* 7.4 Location Management Messages */
    {
        GTP_MSG_SEND_ROUT_INFO_REQ, {
            {GTP_EXT_IMSI, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_SEND_ROUT_INFO_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_IMSI, GTP_MANDATORY},
            {GTP_EXT_MAP_CAUSE, GTP_OPTIONAL},
            {GTPv1_EXT_MS_REASON, GTP_OPTIONAL},
            {GTP_EXT_GSN_ADDR, GTP_OPTIONAL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_FAIL_REP_REQ, {
            {GTP_EXT_IMSI, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_FAIL_REP_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_MAP_CAUSE, GTP_OPTIONAL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_MS_PRESENT_REQ, {
            {GTP_EXT_IMSI, GTP_MANDATORY},
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_MS_PRESENT_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    /* 7.5 Mobility Management Messages */
    {
        GTP_MSG_IDENT_REQ, {
            {GTP_EXT_RAI, GTP_MANDATORY},
            {GTP_EXT_PTMSI, GTP_MANDATORY},
            {GTP_EXT_PTMSI_SIG, GTP_CONDITIONAL},
            {GTP_EXT_GSN_ADDR, GTP_OPTIONAL},   /* SGSN Address for Control Plane Optional 7.7.32 */
            {GTP_EXT_HOP_COUNT, GTP_OPTIONAL},  /* Hop Counter Optional 7.7.63 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_IDENT_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_IMSI, GTP_CONDITIONAL},
            {GTP_EXT_AUTH_TRI, GTP_CONDITIONAL},
            {GTP_EXT_AUTH_QUI, GTP_CONDITIONAL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_SGSN_CNTXT_REQ, {
            {GTP_EXT_IMSI, GTP_CONDITIONAL},
            {GTP_EXT_RAI, GTP_MANDATORY},
            {GTP_EXT_TLLI, GTP_CONDITIONAL},
            {GTP_EXT_PTMSI, GTP_CONDITIONAL},
            {GTP_EXT_PTMSI_SIG, GTP_CONDITIONAL},
            {GTP_EXT_MS_VALID, GTP_OPTIONAL},
            {GTP_EXT_TEID_CP, GTP_MANDATORY},
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY},
            {GTP_EXT_GSN_ADDR, GTP_OPTIONAL},   /* Alternative SGSN Address for Control Plane Optional 7.7.32 */
            {GTP_EXT_SSGN_NO, GTP_OPTIONAL},    /* SGSN Number Optional 7.7.47 */
            {GTP_EXT_HOP_COUNT, GTP_OPTIONAL},  /* Hop Counter Optional 7.7.63 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_SGSN_CNTXT_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_IMSI, GTP_CONDITIONAL},
            {GTP_EXT_TEID_CP, GTP_CONDITIONAL},
            {GTP_EXT_RAB_CNTXT, GTP_CONDITIONAL},       /* RAB Context Conditional 7.7.19 */
            {GTP_EXT_RP_SMS, GTP_OPTIONAL},
            {GTP_EXT_RP, GTP_OPTIONAL},
            {GTP_EXT_PKT_FLOW_ID, GTP_OPTIONAL},
            {GTP_EXT_CHRG_CHAR, GTP_OPTIONAL},  /* CharingCharacteristics Optional 7.7.23 */
            {GTP_EXT_RA_PRIO_LCS, GTP_OPTIONAL},        /* Radio Priority LCS Optional 7.7.25B */
            {GTP_EXT_MM_CNTXT, GTP_CONDITIONAL},
            {GTP_EXT_PDP_CNTXT, GTP_CONDITIONAL},
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL},
            {GTP_EXT_PDP_CONT_PRIO, GTP_OPTIONAL},      /* PDP Context Prioritization Optional 7.7.45 */
            {GTP_EXT_MBMS_UE_CTX, GTP_OPTIONAL},        /* MBMS UE Context Optional 7.7.55 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_SGSN_CNTXT_ACK, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_TEID_II, GTP_CONDITIONAL},
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_FORW_RELOC_REQ, {
            {GTP_EXT_IMSI, GTP_MANDATORY},
            {GTP_EXT_TEID_CP, GTP_MANDATORY},
            {GTP_EXT_RANAP_CAUSE, GTP_MANDATORY},
            {GTP_EXT_CHRG_CHAR, GTP_OPTIONAL},  /* CharingCharacteristics Optional 7.7.23 */
            {GTP_EXT_MM_CNTXT, GTP_MANDATORY},
            {GTP_EXT_PDP_CNTXT, GTP_CONDITIONAL},
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY},
            {GTP_EXT_TARGET_ID, GTP_MANDATORY},
            {GTP_EXT_UTRAN_CONT, GTP_MANDATORY},
            {GTP_EXT_PDP_CONT_PRIO, GTP_OPTIONAL},      /* PDP Context Prioritization Optional 7.7.45 */
            {GTP_EXT_MBMS_UE_CTX, GTP_OPTIONAL},        /* MBMS UE Context Optional 7.7.55 */
            {GTP_EXT_SEL_PLMN_ID, GTP_OPTIONAL},        /* Selected PLMN ID Optional 7.7.64 */
            {GTP_EXT_PS_HO_REQ_CTX, GTP_OPTIONAL},      /* PS Handover Request Context Optional 7.7.71 */
            {GTP_EXT_BSS_CONT, GTP_OPTIONAL},   /* BSS Container Optional 7.7.72 */
            {GTP_EXT_CELL_ID, GTP_OPTIONAL},    /* Cell Identification Optional 7.7.73 */
            {GTP_EXT_BSSGP_CAUSE, GTP_OPTIONAL},        /* BSSGP Cause Optional 7.7.75 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {GTP_EXT_SSGN_NO, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_FORW_RELOC_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_TEID_CP, GTP_CONDITIONAL},
            {GTP_EXT_TEID_II, GTP_CONDITIONAL}, /* Tunnel Endpoint Identifier Data II Optional 7.7.15 */
            {GTP_EXT_RANAP_CAUSE, GTP_CONDITIONAL},
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL},
            {GTP_EXT_UTRAN_CONT, GTP_OPTIONAL},
            {GTP_EXT_RAB_SETUP, GTP_CONDITIONAL},
            {GTP_EXT_ADD_RAB_SETUP_INF, GTP_CONDITIONAL},       /* Additional RAB Setup Information Conditional 7.7.45A */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_FORW_RELOC_COMP, {
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_RELOC_CANCEL_REQ, {
            {GTP_EXT_IMSI, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_RELOC_CANCEL_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_FORW_RELOC_ACK, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_FORW_SRNS_CNTXT_ACK, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MSG_FORW_SRNS_CNTXT, {
            {GTP_EXT_RAB_CNTXT, GTP_MANDATORY},
            {GTP_EXT_SRC_RNC_PDP_CTX_INF, GTP_OPTIONAL},        /* Source RNC PDCP context info Optional 7.7.61 */
            {GTP_EXT_PDU_NO, GTP_OPTIONAL},     /* PDU Numbers Optional 7.7.74 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },

/*      7.5.14 RAN Information Management Messages */
    {
        GTP_MSG_RAN_INFO_RELAY, {
            {GTP_EXT_RAN_TR_CONT, GTP_MANDATORY},       /* RAN Transparent Container Mandatory 7.7.43 */
            {GTP_EXT_RIM_RA, GTP_OPTIONAL},             /* RIM Routing Address Optional 7.7.57 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
/* 7.5A MBMS Messages
 * 7.5A.1 UE Specific MBMS Messages
 */
    {
        GTP_MBMS_NOTIFY_REQ, {
            {GTP_EXT_IMSI, GTP_MANDATORY},      /* IMSI Mandatory 7.7.2 */
            {GTP_EXT_TEID_CP, GTP_MANDATORY},   /* Tunnel Endpoint Identifier Control Plane Mandatory 7.7.14 */
            {GTP_EXT_NSAPI, GTP_MANDATORY},     /* NSAPI Mandatory 7.7.17 */
            {GTP_EXT_USER_ADDR, GTP_MANDATORY}, /* End User Address Mandatory 7.7.27 */
            {GTP_EXT_APN, GTP_MANDATORY},       /* Access Point Name Mandatory 7.7.30 */
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY},  /* GGSN Address for Control Plane Mandatory 7.7.32 */
            {GTP_EXT_MBMS_PROT_CONF_OPT, GTP_OPTIONAL}, /* MBMS Protocol Configuration Options Optional 7.7.58 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},   /* Private Extension Optional 7.7.46 */
            {0, 0}
        }
    },
    {
        GTP_MBMS_NOTIFY_RES, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},     /* Cause Mandatory 7.7.1 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MBMS_NOTIFY_REJ_REQ, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},     /* Cause Mandatory 7.7.1 */
            {GTP_EXT_TEID_CP, GTP_MANDATORY},   /* Tunnel Endpoint Identifier Control Plane Mandatory 7.7.14 */
            {GTP_EXT_NSAPI, GTP_MANDATORY},     /* NSAPI Mandatory 7.7.17 */
            {GTP_EXT_USER_ADDR, GTP_MANDATORY}, /* End User Address Mandatory 7.7.27 */
            {GTP_EXT_APN, GTP_MANDATORY},       /* Access Point Name Mandatory 7.7.30 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MBMS_NOTIFY_REJ_RES, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},     /* Cause Mandatory 7.7.1 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_CREATE_MBMS_CNTXT_REQ, {
            {GTP_EXT_IMSI, GTP_CONDITIONAL},    /* IMSI Conditional 7.7.2 */
            {GTP_EXT_RAI, GTP_MANDATORY},       /* Routeing Area Identity (RAI) Mandatory 7.7.3 */
            {GTP_EXT_RECOVER, GTP_OPTIONAL},    /* Recovery Optional 7.7.11 */
            {GTP_EXT_SEL_MODE, GTP_CONDITIONAL},        /* Selection mode Conditional 7.7.12 */
            {GTP_EXT_TEID_CP, GTP_CONDITIONAL}, /* Tunnel Endpoint Identifier Control Plane Conditional 7.7.14 */
            {GTP_EXT_TRACE_REF, GTP_OPTIONAL},  /* Trace Reference Optional 7.7.24 */
            {GTP_EXT_TRACE_TYPE, GTP_OPTIONAL}, /* Trace Type Optional 7.7.25 */
            {GTP_EXT_USER_ADDR, GTP_MANDATORY}, /* End User Address Mandatory 7.7.27 */
            {GTP_EXT_APN, GTP_MANDATORY},       /* Access Point Name Mandatory 7.7.30 */
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY},  /* SGSN Address for signalling Mandatory GSN Address 7.7.32 */
            {GTP_EXT_MSISDN, GTP_CONDITIONAL},  /* MSISDN Conditional 7.7.33 */
            {GTP_EXT_TRIGGER_ID, GTP_OPTIONAL}, /* Trigger Id Optional 7.7.41 */
            {GTP_EXT_OMC_ID, GTP_OPTIONAL},     /* OMC Identity Optional 7.7.42 */
            {GTP_EXT_RAT_TYPE, GTP_OPTIONAL},   /* RAT Type Optional 7.7.50 */
            {GTP_EXT_USR_LOC_INF, GTP_OPTIONAL},        /* User Location Information Optional 7.7.51 */
            {GTP_EXT_MS_TIME_ZONE, GTP_OPTIONAL},       /* MS Time Zone Optional 7.7.52 */
            {GTP_EXT_IMEISV, GTP_OPTIONAL},     /* IMEI(SV) Optional 7.7.53 */
            {GTP_EXT_MBMS_PROT_CONF_OPT, GTP_OPTIONAL}, /* MBMS Protocol Configuration Options Optional 7.7.58 */
            {GTP_EXT_ADD_TRS_INF, GTP_OPTIONAL},        /* Additonal Trace Info Optional 7.7.62 */
            {GTP_EXT_ENH_NSAPI, GTP_MANDATORY}, /* Enhanced NSAPI Mandatory 7.7.67 */
            {GTP_EXT_ADD_MBMS_TRS_INF, GTP_OPTIONAL},   /* Additional MBMS Trace Info Optional 7.7.68 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_CREATE_MBMS_CNTXT_RES, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},     /* Cause Mandatory 7.7.1 */
            {GTP_EXT_RECOVER, GTP_OPTIONAL},    /* Recovery Optional 7.7.11 */
            {GTP_EXT_TEID_CP, GTP_CONDITIONAL}, /* Tunnel Endpoint Identifier Control Plane Conditional 7.7.14 */
            {GTP_EXT_CHRG_ID, GTP_CONDITIONAL}, /* Charging ID Conditional 7.7.26 */
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL},        /* GGSN Address for Control Plane Conditional GSN Address 7.7.32 */
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL},        /* Alternative GGSN Address for Control Plane Conditional GSN Address 7.7.32 */
            {GTP_EXT_CHRG_ADDR, GTP_OPTIONAL},  /* Charging Gateway Address Optional 7.7.44 */
            {GTP_EXT_CHRG_ADDR, GTP_OPTIONAL},  /* Alternative Charging Gateway Address Optional 7.7.44 */
            {GTP_EXT_MBMS_PROT_CONF_OPT, GTP_OPTIONAL}, /* MBMS Protocol Configuration Options Optional 7.7.58 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_UPD_MBMS_CNTXT_REQ, {
            {GTP_EXT_IMSI, GTP_CONDITIONAL},    /* IMSI Conditional 7.7.2 */
            {GTP_EXT_RAI, GTP_MANDATORY},       /* Routeing Area Identity (RAI) Mandatory 7.7.3 */
            {GTP_EXT_RECOVER, GTP_OPTIONAL},    /* Recovery Optional 7.7.11 */
            {GTP_EXT_TEID_CP, GTP_CONDITIONAL}, /* Tunnel Endpoint Identifier Control Plane Conditional 7.7.14 */
            {GTP_EXT_TRACE_REF, GTP_OPTIONAL},  /* Trace Reference Optional 7.7.24 */
            {GTP_EXT_TRACE_TYPE, GTP_OPTIONAL}, /* Trace Type Optional 7.7.25 */
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY},  /* SGSN Address for Control Plane Mandatory GSN Address 7.7.32 */
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL},        /* Alternative SGSN Address for Control Plane Conditional GSN Address 7.7.32 */
            {GTP_EXT_TRIGGER_ID, GTP_OPTIONAL}, /* Trigger Id Optional 7.7.41 */
            {GTP_EXT_OMC_ID, GTP_OPTIONAL},     /* OMC Identity Optional 7.7.42 */
            {GTP_EXT_RAT_TYPE, GTP_OPTIONAL},   /* RAT Type Optional 7.7.50 */
            {GTP_EXT_USR_LOC_INF, GTP_OPTIONAL},        /* User Location Information Optional 7.7.51 */
            {GTP_EXT_MS_TIME_ZONE, GTP_OPTIONAL},       /* MS Time Zone Optional 7.7.52 */
            {GTP_EXT_ADD_TRS_INF, GTP_OPTIONAL},        /* Additional Trace Info Optional 7.7.62 */
            {GTP_EXT_ENH_NSAPI, GTP_MANDATORY}, /* Enhanced NSAPI Mandatory 7.7.67 */
            {GTP_EXT_ADD_MBMS_TRS_INF, GTP_OPTIONAL},   /* Additional MBMS Trace Info Optional 7.7.68 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_UPD_MBMS_CNTXT_RES, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},     /* Cause Mandatory 7.7.1 */
            {GTP_EXT_RECOVER, GTP_OPTIONAL},    /* Recovery Optional 7.7.11 */
            {GTP_EXT_TEID_CP, GTP_MANDATORY},   /* Tunnel Endpoint Identifier Control Plane Conditional 7.7.14 */
            {GTP_EXT_CHRG_ID, GTP_CONDITIONAL}, /* Charging ID Conditional 7.7.26 */
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL},        /* GGSN Address for Control Plane Conditional GSN Address 7.7.32 */
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL},        /* Alternative GGSN Address for Control Plane Conditional GSN Address 7.7.32 */
            {GTP_EXT_CHRG_ADDR, GTP_OPTIONAL},  /* Charging Gateway Address Optional 7.7.44 */
            {GTP_EXT_CHRG_ADDR, GTP_OPTIONAL},  /* Alternative Charging Gateway Address Optional 7.7.44 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},   /* Private Extension Optional 7.7.46 */
            {0, 0}
        }
    },
    {
        GTP_DEL_MBMS_CNTXT_REQ, {
            {GTP_EXT_IMSI, GTP_CONDITIONAL},    /* IMSI Conditional 7.7.2 */
            {GTP_EXT_TEID_CP, GTP_MANDATORY},   /* Tunnel Endpoint Identifier Control Plane Conditional 7.7.14 */
            {GTP_EXT_USER_ADDR, GTP_CONDITIONAL},       /* End User Address Conditional 7.7.27 */
            {GTP_EXT_APN, GTP_CONDITIONAL},     /* Access Point Name Conditional 7.7.30 */
            {GTP_EXT_MBMS_PROT_CONF_OPT, GTP_OPTIONAL}, /* MBMS Protocol Configuration Options Optional 7.7.58 */
            {GTP_EXT_ENH_NSAPI, GTP_MANDATORY}, /* Enhanced NSAPI Conditional 7.7.67 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},   /* Private Extension Optional 7.7.46 */
            {0, 0}
        }
    },
    {
        GTP_DEL_MBMS_CNTXT_RES, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},     /* Cause Mandatory 7.7.1 */
            {GTP_EXT_MBMS_PROT_CONF_OPT, GTP_OPTIONAL}, /* MBMS Protocol Configuration Options Optional 7.7.58 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},
            {0, 0}
        }
    },
    {
        GTP_MBMS_REG_REQ, {
            {GTP_EXT_USER_ADDR, GTP_MANDATORY}, /* End User Address Mandatory 7.7.27 */
            {GTP_EXT_APN, GTP_MANDATORY},       /* Access Point Name Mandatory 7.7.30 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},   /* Private Extension Optional 7.7.46 */
            {0, 0}
        }
    },
    {
        GTP_MBMS_REG_RES, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},     /* Cause Mandatory 7.7.1 */
            {GTP_EXT_TMGI, GTP_MANDATORY},      /* Temporary Mobile Group Identity (TMGI) Conditional 7.7.56 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},   /* Private Extension Optional 7.7.46 */
            {0, 0}
        }
    },
    {
        GTP_MBMS_DE_REG_REQ, {
            {GTP_EXT_USER_ADDR, GTP_MANDATORY}, /* End User Address Mandatory 7.7.27 */
            {GTP_EXT_APN, GTP_MANDATORY},       /* Access Point Name Mandatory 7.7.30 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},   /* Private Extension Optional 7.7.46 */
            {0, 0}
        }
    },
    {
        GTP_MBMS_DE_REG_RES, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},     /* Cause Mandatory 7.7.1 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},   /* Private Extension Optional 7.7.46 */
            {0, 0}
        }
    },
    {
        GTP_MBMS_SES_START_REQ, {
            {GTP_EXT_RECOVER, GTP_OPTIONAL},    /* Recovery Optional 7.7.11 */
            {GTP_EXT_TEID_CP, GTP_CONDITIONAL}, /* Tunnel Endpoint Identifier Control Plane Conditional 7.7.14 */
            {GTP_EXT_USER_ADDR, GTP_MANDATORY}, /* End User Address Mandatory 7.7.27 */
            {GTP_EXT_APN, GTP_MANDATORY},       /* Access Point Name Mandatory 7.7.30 */
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL},        /* GGSN Address for Control Plane Conditional GSN Address 7.7.32 */
            {GTP_EXT_QOS_UMTS, GTP_MANDATORY},  /* Quality of Service Profile Mandatory 7.7.34 */
            {GTP_EXT_COMMON_FLGS, GTP_OPTIONAL},        /* Common Flags Mandatory 7.7.48 */
            {GTP_EXT_TMGI, GTP_MANDATORY},      /* Temporary Mobile Group Identity (TMGI) Mandatory 7.7.56 */
            {GTP_EXT_MBMS_SES_DUR, GTP_MANDATORY},      /* MBMS Session Duration Mandatory 7.7.59 */
            {GTP_EXT_MBMS_SA, GTP_MANDATORY},   /* MBMS Service Area Mandatory 7.7.60 */
            {GTP_EXT_MBMS_SES_ID, GTP_OPTIONAL},        /* MBMS Session Identifier Optional 7.7.65 */
            {GTP_EXT_MBMS_2G_3G_IND, GTP_MANDATORY},    /* MBMS 2G/3G Indicator Mandatory 7.7.66 */
            {GTP_EXT_MBMS_SES_ID_REP_NO, GTP_OPTIONAL}, /* MBMS Session Identity Repetition Number Optional 7.7.69 */
            {GTP_EXT_MBMS_TIME_TO_DATA_TR, GTP_MANDATORY},      /* MBMS Time To Data Transfer Mandatory 7.7.70 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},   /* Private Extension Optional 7.7.46 */
            {0, 0}
        }
    },
    {
        GTP_MBMS_SES_START_RES, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},     /* Cause Mandatory 7.7.1 */
            {GTP_EXT_RECOVER, GTP_OPTIONAL},    /* Recovery Optional 7.7.11 */
            {GTP_EXT_TEID, GTP_CONDITIONAL},    /* Tunnel Endpoint Identifier Data I Conditional 7.7.13 */
            {GTP_EXT_TEID_CP, GTP_CONDITIONAL}, /* Tunnel Endpoint Identifier Control Plane Conditional 7.7.14 */
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL},        /* SGSN Address for Control Plane Conditional GSN Address 7.7.32 */
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL},        /* SGSN Address for user traffic Conditional GSN Address 7.7.32 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},   /* Private Extension Optional 7.7.46 */
            {0, 0}
        }
    },
    {
        GTP_MBMS_SES_STOP_REQ, {
            {GTP_EXT_USER_ADDR, GTP_MANDATORY}, /* End User Address Mandatory 7.7.27 */
            {GTP_EXT_APN, GTP_MANDATORY},       /* Access Point Name Mandatory 7.7.30 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},   /* Private Extension Optional 7.7.46 */
            {0, 0}
        }
    },
    {
        GTP_MBMS_SES_STOP_RES, {
            {GTP_EXT_CAUSE, GTP_MANDATORY},     /* Cause Mandatory 7.7.1 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL},   /* Private Extension Optional 7.7.46 */
            {0, 0}
        }
    },
    {
        0, {
            {0, 0}
        }
    }
};

/* Data structure attached to a conversation,
        to keep track of request/response-pairs
 */
typedef struct gtp_conv_info_t {
    struct gtp_conv_info_t *next;
    GHashTable *unmatched;
    GHashTable *matched;
} gtp_conv_info_t;

static gtp_conv_info_t *gtp_info_items = NULL;

static guint gtp_sn_hash(gconstpointer k)
{
    const gtp_msg_hash_t *key = (const gtp_msg_hash_t *)k;

    return key->seq_nr;
}

static gint gtp_sn_equal_matched(gconstpointer k1, gconstpointer k2)
{
    const gtp_msg_hash_t *key1 = (const gtp_msg_hash_t *)k1;
    const gtp_msg_hash_t *key2 = (const gtp_msg_hash_t *)k2;

    if ( key1->req_frame && key2->req_frame && (key1->req_frame!=key2->req_frame) ) {
        return 0;
    }

    if ( key1->rep_frame && key2->rep_frame && (key1->rep_frame!=key2->rep_frame) ) {
        return 0;
    }

    return key1->seq_nr == key2->seq_nr;
}

static gint gtp_sn_equal_unmatched(gconstpointer k1, gconstpointer k2)
{
    const gtp_msg_hash_t *key1 = (const gtp_msg_hash_t *)k1;
    const gtp_msg_hash_t *key2 = (const gtp_msg_hash_t *)k2;

    return key1->seq_nr == key2->seq_nr;
}

static gtp_msg_hash_t *gtp_match_response(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, gint seq_nr, guint msgtype)
{
    gtp_msg_hash_t gcr, *gcrp = NULL;
    gtp_conv_info_t *gtp_info = (gtp_conv_info_t *)pinfo->private_data;

    gcr.seq_nr=seq_nr;

    switch (msgtype) {
    case GTP_MSG_ECHO_REQ:
    case GTP_MSG_CREATE_PDP_REQ:
    case GTP_MSG_UPDATE_PDP_REQ:
    case GTP_MSG_DELETE_PDP_REQ:
        gcr.is_request=TRUE;
        gcr.req_frame=pinfo->fd->num;
        gcr.rep_frame=0;
        break;
    case GTP_MSG_ECHO_RESP:
    case GTP_MSG_CREATE_PDP_RESP:
    case GTP_MSG_UPDATE_PDP_RESP:
    case GTP_MSG_DELETE_PDP_RESP:
        gcr.is_request=FALSE;
        gcr.req_frame=0;
        gcr.rep_frame=pinfo->fd->num;
        break;
        default:;
        break;
    }

    gcrp = (gtp_msg_hash_t *)g_hash_table_lookup(gtp_info->matched, &gcr);

    if (gcrp) {

        gcrp->is_request=gcr.is_request;

    } else {

        /*no match, let's try to make one*/
        switch (msgtype) {
        case GTP_MSG_ECHO_REQ:
        case GTP_MSG_CREATE_PDP_REQ:
        case GTP_MSG_UPDATE_PDP_REQ:
        case GTP_MSG_DELETE_PDP_REQ:
            gcr.seq_nr=seq_nr;

            gcrp=(gtp_msg_hash_t *)g_hash_table_lookup(gtp_info->unmatched, &gcr);
            if (gcrp) {
                g_hash_table_remove(gtp_info->unmatched, gcrp);
            }
            /* if we cant reuse the old one, grab a new chunk */
            if (!gcrp) {
                gcrp = se_new(gtp_msg_hash_t);
            }
            gcrp->seq_nr=seq_nr;
            gcrp->req_frame = pinfo->fd->num;
            gcrp->req_time = pinfo->fd->abs_ts;
            gcrp->rep_frame = 0;
            gcrp->msgtype = msgtype;
            gcrp->is_request = TRUE;
            g_hash_table_insert(gtp_info->unmatched, gcrp, gcrp);
            return NULL;
            break;
        case GTP_MSG_ECHO_RESP:
        case GTP_MSG_CREATE_PDP_RESP:
        case GTP_MSG_UPDATE_PDP_RESP:
        case GTP_MSG_DELETE_PDP_RESP:
            gcr.seq_nr=seq_nr;
            gcrp=(gtp_msg_hash_t *)g_hash_table_lookup(gtp_info->unmatched, &gcr);

            if (gcrp) {
                if (!gcrp->rep_frame) {
                    g_hash_table_remove(gtp_info->unmatched, gcrp);
                    gcrp->rep_frame=pinfo->fd->num;
                    gcrp->is_request=FALSE;
                    g_hash_table_insert(gtp_info->matched, gcrp, gcrp);
                }
            }
            break;
        default:;
        break;
        }
    }

    /* we have found a match */
    if (gcrp) {
        proto_item *it;


        if (gcrp->is_request) {
            it = proto_tree_add_uint(tree, hf_gtp_response_in, tvb, 0, 0, gcrp->rep_frame);
            PROTO_ITEM_SET_GENERATED(it);
        } else {
            nstime_t ns;

            it = proto_tree_add_uint(tree, hf_gtp_response_to, tvb, 0, 0, gcrp->req_frame);
            PROTO_ITEM_SET_GENERATED(it);
            nstime_delta(&ns, &pinfo->fd->abs_ts, &gcrp->req_time);
            it = proto_tree_add_time(tree, hf_gtp_time, tvb, 0, 0, &ns);
            PROTO_ITEM_SET_GENERATED(it);
        }
    }
    return gcrp;
}


static int check_field_presence(guint8 message, guint8 field, int *position)
{

    guint i = 0;
    _gtp_mess_items *mess_items;

    switch (gtp_version) {
    case 0:
        mess_items = gprs_mess_items;
        break;
    case 1:
        mess_items = umts_mess_items;
        break;
    default:
        return -2;
    }

    while (mess_items[i].code) {
        if (mess_items[i].code == message) {

            while (mess_items[i].fields[*position].code) {
                if (mess_items[i].fields[*position].code == field) {
                    (*position)++;
                    return 0;
                } else {
                    if (mess_items[i].fields[*position].presence == GTP_MANDATORY) {
                        return mess_items[i].fields[(*position)++].code;
                    } else {
                        (*position)++;
                    }
                }
            }
            return -1;
        }
        i++;
    }

    return -2;
}

/* Decoders of fields in extension headers, each function returns no of bytes from field */

/* GPRS:        9.60 v7.6.0, chapter
 * UMTS:        29.060 v4.0, chapter
 * 7.7.1 Cause
 */
static int decode_gtp_cause(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint8 cause;

    cause = tvb_get_guint8(tvb, offset + 1);

    proto_tree_add_uint(tree, hf_gtp_cause, tvb, offset, 2, cause);

    return 2;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.2
 * UMTS:        29.060 v4.0, chapter 7.7.2
 */
static int decode_gtp_imsi(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    const gchar *imsi_str;

    /* Octets 2 - 9 IMSI */
    imsi_str =  tvb_bcd_dig_to_ep_str( tvb, offset+1, 8, NULL, FALSE);

    proto_tree_add_string(tree, hf_gtp_imsi, tvb, offset+1, 8, imsi_str);

    return 9;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.3
 * UMTS:        29.060 v4.0, chapter 7.7.3 Routeing Area Identity (RAI)
 */
static int decode_gtp_rai(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    proto_tree *ext_tree_rai;
    proto_item *te;

    te = proto_tree_add_text(tree, tvb, offset, 1, "%s", val_to_str_ext_const(GTP_EXT_RAI, &gtp_val_ext, "Unknown message"));
    ext_tree_rai = proto_item_add_subtree(te, ett_gtp_rai);

	dissect_e212_mcc_mnc(tvb, pinfo, ext_tree_rai, offset+1, TRUE);
    proto_tree_add_uint(ext_tree_rai, hf_gtp_rai_lac, tvb, offset + 4, 2, tvb_get_ntohs(tvb, offset + 4));
    proto_tree_add_uint(ext_tree_rai, hf_gtp_rai_rac, tvb, offset + 6, 1, tvb_get_guint8(tvb, offset + 6));

    return 7;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.4, page 39
 * UMTS:        29.060 v4.0, chapter 7.7.4 Temporary Logical Link Identity (TLLI)
 */
static int decode_gtp_tlli(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint32 tlli;

    tlli = tvb_get_ntohl(tvb, offset + 1);
    proto_tree_add_uint(tree, hf_gtp_tlli, tvb, offset, 5, tlli);

    return 5;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.5, page 39
 * UMTS:        29.060 v4.0, chapter 7.7.5 Packet TMSI (P-TMSI)
 */
static int decode_gtp_ptmsi(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint32 ptmsi;

    ptmsi = tvb_get_ntohl(tvb, offset + 1);
    proto_tree_add_uint(tree, hf_gtp_ptmsi, tvb, offset, 5, ptmsi);

    return 5;
}

/* 
 * adjust - how many bytes before offset should be highlighted
 */
static int decode_qos_gprs(tvbuff_t * tvb, int offset, proto_tree * tree, const gchar * qos_str, guint8 adjust)
{

    guint8 spare1, delay, reliability, peak, spare2, precedence, spare3, mean;
    proto_tree *ext_tree_qos;
    proto_item *te;

    spare1 = tvb_get_guint8(tvb, offset) & GTP_EXT_QOS_SPARE1_MASK;
    delay = tvb_get_guint8(tvb, offset) & GTP_EXT_QOS_DELAY_MASK;
    reliability = tvb_get_guint8(tvb, offset) & GTP_EXT_QOS_RELIABILITY_MASK;
    peak = tvb_get_guint8(tvb, offset + 1) & GTP_EXT_QOS_PEAK_MASK;
    spare2 = tvb_get_guint8(tvb, offset + 1) & GTP_EXT_QOS_SPARE2_MASK;
    precedence = tvb_get_guint8(tvb, offset + 1) & GTP_EXT_QOS_PRECEDENCE_MASK;
    spare3 = tvb_get_guint8(tvb, offset + 2) & GTP_EXT_QOS_SPARE3_MASK;
    mean = tvb_get_guint8(tvb, offset + 2) & GTP_EXT_QOS_MEAN_MASK;

    te = proto_tree_add_text(tree, tvb, offset - adjust, 3 + adjust, "%s: delay: %u, reliability: %u, peak: %u, precedence: %u, mean: %u",
                             qos_str, (delay >> 3) & 0x07, reliability, (peak >> 4) & 0x0F, precedence, mean);
    ext_tree_qos = proto_item_add_subtree(te, ett_gtp_qos);

    if (adjust != 0) {
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_spare1, tvb, offset, 1, spare1);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_delay, tvb, offset, 1, delay);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_reliability, tvb, offset, 1, reliability);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_peak, tvb, offset + 1, 1, peak);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_spare2, tvb, offset + 1, 1, spare2);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_precedence, tvb, offset + 1, 1, precedence);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_spare3, tvb, offset + 2, 1, spare3);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_mean, tvb, offset + 2, 1, mean);
    }

    return 3;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.6, page 39
 *              4.08
 *              3.60
 * UMTS:        not present
 * TODO:        check if length is included: ETSI 4.08 vs 9.60
 */
static int decode_gtp_qos_gprs(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    return (1 + decode_qos_gprs(tvb, offset + 1, tree, "Quality of Service", 1));

}

/* GPRS:        9.60 v7.6.0, chapter 7.9.7, page 39
 * UMTS:        29.060 v4.0, chapter 7.7.6 Reordering Required
 */
static int decode_gtp_reorder(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint8 reorder;

    reorder = tvb_get_guint8(tvb, offset + 1) & 0x01;
    proto_tree_add_boolean(tree, hf_gtp_reorder, tvb, offset, 2, reorder);

    return 2;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.8, page 40
 *              4.08 v7.1.2, chapter 10.5.3.1+
 * UMTS:        29.060 v4.0, chapter 7.7.7
 * TODO: Add blurb support by registering items in the protocol registration
 */
static int decode_gtp_auth_tri(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    proto_tree *ext_tree_auth_tri;
    proto_item *te;

    te = proto_tree_add_text(tree, tvb, offset, 29, "%s", val_to_str_ext_const(GTP_EXT_AUTH_TRI, &gtp_val_ext, "Unknown message"));
    ext_tree_auth_tri = proto_item_add_subtree(te, ett_gtp_auth_tri);

    proto_tree_add_text(ext_tree_auth_tri, tvb, offset + 1, 16, "RAND: %s", tvb_bytes_to_str(tvb, offset + 1, 16));
    proto_tree_add_text(ext_tree_auth_tri, tvb, offset + 17, 4, "SRES: %s", tvb_bytes_to_str(tvb, offset + 17, 4));
    proto_tree_add_text(ext_tree_auth_tri, tvb, offset + 21, 8, "Kc: %s", tvb_bytes_to_str(tvb, offset + 21, 8));

    return 1 + 16 + 4 + 8;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.9, page 40
 *              9.02 v7.7.0, page 1090
 * UMTS:        29.060 v4.0, chapter 7.7.8, page 48
 *              29.002 v4.2.1, chapter 17.5, page 268
 */
static int decode_gtp_map_cause(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint8 map_cause;

    map_cause = tvb_get_guint8(tvb, offset + 1);
    proto_tree_add_uint(tree, hf_gtp_map_cause, tvb, offset, 2, map_cause);

    return 2;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.10, page 41
 * UMTS:        29.060 v4.0, chapter 7.7.9, page 48
 */
static int decode_gtp_ptmsi_sig(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint32 ptmsi_sig;

    ptmsi_sig = tvb_get_ntoh24(tvb, offset + 1);
    proto_tree_add_uint(tree, hf_gtp_ptmsi_sig, tvb, offset, 4, ptmsi_sig);

    return 4;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.11, page 41
 * UMTS:        29.060 v4.0, chapter 7.7.10, page 49
 */
static int decode_gtp_ms_valid(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint8 ms_valid;

    ms_valid = tvb_get_guint8(tvb, offset + 1) & 0x01;
    proto_tree_add_boolean(tree, hf_gtp_ms_valid, tvb, offset, 2, ms_valid);

    return 2;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.12, page 41
 * UMTS:        29.060 v4.0, chapter 7.7.11 Recovery
 */
static int decode_gtp_recovery(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint8 recovery;

    recovery = tvb_get_guint8(tvb, offset + 1);
    proto_tree_add_uint(tree, hf_gtp_recovery, tvb, offset, 2, recovery);

    return 2;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.13, page 42
 * UMTS:        29.060 v4.0, chapter 7.7.12 Selection Mode
 */


static const gchar *dissect_radius_selection_mode(proto_tree * tree, tvbuff_t * tvb, packet_info* pinfo _U_)
{
    guint8 sel_mode;

    /* Value in ASCII(UTF-8) */
    sel_mode = tvb_get_guint8(tvb, 0) - 0x30;
    proto_tree_add_uint(tree, hf_gtp_sel_mode, tvb, 0, 1, sel_mode);

    return val_to_str_const(sel_mode, sel_mode_type, "Unknown");
}

static int decode_gtp_sel_mode(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    proto_tree_add_item(tree, hf_gtp_sel_mode, tvb, offset, 2, ENC_BIG_ENDIAN);
    return 2;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.14, page 42
 * UMTS:        29.060 v4.0, chapter 7.7.13, page 50
 */
static int decode_gtp_16(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 ext_flow_label;
    guint32 teid_data;

    switch (gtp_version) {
    case 0:
        ext_flow_label = tvb_get_ntohs(tvb, offset + 1);
        proto_tree_add_uint(tree, hf_gtp_ext_flow_label, tvb, offset, 3, ext_flow_label);

        return 3;
    case 1:
        teid_data = tvb_get_ntohl(tvb, offset + 1);
        proto_tree_add_uint(tree, hf_gtp_teid_data, tvb, offset, 5, teid_data);

        return 5;
    default:
        proto_tree_add_text(tree, tvb, offset, 1, "Flow label/TEID Data I : GTP version not supported");

        return 3;
    }
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.15, page 42
 * UMTS:        29.060 v4.0, chapter 7.7.14, page 42
 */
static int decode_gtp_17(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 flow_sig;
    guint32 teid_cp;

    switch (gtp_version) {
    case 0:
        flow_sig = tvb_get_ntohs(tvb, offset + 1);
        proto_tree_add_uint(tree, hf_gtp_flow_sig, tvb, offset, 3, flow_sig);
        return 3;
    case 1:
        teid_cp = tvb_get_ntohl(tvb, offset + 1);
        proto_tree_add_uint(tree, hf_gtp_teid_cp, tvb, offset, 5, teid_cp);
        return 5;
    default:
        proto_tree_add_text(tree, tvb, offset, 1, "Flow label signalling/TEID control plane : GTP version not supported");
        return 3;
    }
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.16, page 42
 * UMTS:        29.060 v4.0, chapter 7.7.15, page 51
 */
static int decode_gtp_18(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 flow_ii;
    guint32 teid_ii;
    proto_tree *ext_tree_flow_ii;
    proto_item *te;

    switch (gtp_version) {
    case 0:
        te = proto_tree_add_text(tree, tvb, offset, 4, "%s", val_to_str_ext_const(GTP_EXT_FLOW_II, &gtp_val_ext, "Unknown message"));
        ext_tree_flow_ii = proto_item_add_subtree(te, ett_gtp_flow_ii);

        proto_tree_add_uint(ext_tree_flow_ii, hf_gtp_nsapi, tvb, offset + 1, 1, tvb_get_guint8(tvb, offset + 1) & 0x0F);

        flow_ii = tvb_get_ntohs(tvb, offset + 2);
        proto_tree_add_uint(ext_tree_flow_ii, hf_gtp_flow_ii, tvb, offset + 2, 2, flow_ii);

        return 4;
    case 1:
        te = proto_tree_add_text(tree, tvb, offset, 6, "%s", val_to_str_ext_const(GTP_EXT_TEID_II, &gtpv1_val_ext, "Unknown message"));
        ext_tree_flow_ii = proto_item_add_subtree(te, ett_gtp_flow_ii);

        proto_tree_add_uint(ext_tree_flow_ii, hf_gtp_nsapi, tvb, offset + 1, 1, tvb_get_guint8(tvb, offset + 1) & 0x0F);


        teid_ii = tvb_get_ntohl(tvb, offset + 2);
        proto_tree_add_uint(ext_tree_flow_ii, hf_gtp_teid_ii, tvb, offset + 2, 4, teid_ii);

        return 6;
    default:
        proto_tree_add_text(tree, tvb, offset, 1, "Flow data II/TEID Data II : GTP Version not supported");

        return 4;
    }
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.16A, page 43
 * UMTS:        29.060 v4.0, chapter 7.7.16, page 51
 * Check if all ms_reason types are included
 */
static int decode_gtp_19(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint8 field19;

    field19 = tvb_get_guint8(tvb, offset + 1);

    switch (gtp_version) {
    case 0:
        proto_tree_add_uint(tree, hf_gtp_ms_reason, tvb, offset, 2, field19);
        break;
    case 1:
        proto_tree_add_boolean(tree, hf_gtp_tear_ind, tvb, offset, 2, field19 & 0x01);
        break;
    default:
        proto_tree_add_text(tree, tvb, offset, 1, "Information Element Type = 19 : GTP Version not supported");
        break;
    }

    return 2;
}

/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.17, page 51
 */
static int decode_gtp_nsapi(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint8 nsapi;

    nsapi = tvb_get_guint8(tvb, offset + 1) & 0x0F;
    proto_tree_add_uint(tree, hf_gtp_nsapi, tvb, offset, 2, nsapi);

    return 2;
}

/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.18, page 52
 */
static int decode_gtp_ranap_cause(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint8 ranap;

    ranap = tvb_get_guint8(tvb, offset + 1);

    if (ranap > 0 && ranap <= 64)
        proto_tree_add_uint_format(tree, hf_gtp_ranap_cause, tvb, offset, 2,
                                   ranap, "%s (Radio Network Layer Cause) : %s (%u)",
                                   val_to_str_ext_const(GTP_EXT_RANAP_CAUSE, &gtp_val_ext, "Unknown"),
                                   val_to_str_ext_const(ranap, &ranap_cause_type_ext, "Unknown RANAP Cause"), ranap);

    if (ranap > 64 && ranap <= 80)
        proto_tree_add_uint_format(tree, hf_gtp_ranap_cause, tvb, offset, 2,
                                   ranap, "%s (Transport Layer Cause) : %s (%u)",
                                   val_to_str_ext_const(GTP_EXT_RANAP_CAUSE, &gtp_val_ext, "Unknown"),
                                   val_to_str_ext_const(ranap, &ranap_cause_type_ext, "Unknown RANAP Cause"), ranap);

    if (ranap > 80 && ranap <= 96)
        proto_tree_add_uint_format(tree, hf_gtp_ranap_cause, tvb, offset, 2,
                                   ranap, "%s (NAS Cause) : %s (%u)",
                                   val_to_str_ext_const(GTP_EXT_RANAP_CAUSE, &gtp_val_ext, "Unknown"),
                                   val_to_str_ext_const(ranap, &ranap_cause_type_ext, "Unknown RANAP Cause"), ranap);

    if (ranap > 96 && ranap <= 112)
        proto_tree_add_uint_format(tree, hf_gtp_ranap_cause, tvb, offset, 2, ranap,
                                   "%s (Protocol Cause) : %s (%u)",
                                   val_to_str_ext_const(GTP_EXT_RANAP_CAUSE, &gtp_val_ext, "Unknown"),
                                   val_to_str_ext_const(ranap, &ranap_cause_type_ext, "Unknown RANAP Cause"), ranap);

    if (ranap > 112 && ranap <= 128)
        proto_tree_add_uint_format(tree, hf_gtp_ranap_cause, tvb, offset, 2, ranap,
                                   "%s (Miscellaneous Cause) : %s (%u)",
                                   val_to_str_ext_const(GTP_EXT_RANAP_CAUSE, &gtp_val_ext, "Unknown"),
                                   val_to_str_ext_const(ranap, &ranap_cause_type_ext, "Unknown RANAP Cause"), ranap);

    if (ranap > 128 /* && ranap <=255 */ )
        proto_tree_add_uint_format(tree, hf_gtp_ranap_cause, tvb, offset, 2, ranap,
                                   "%s (Non-standard Cause) : %s (%u)",
                                   val_to_str_ext_const(GTP_EXT_RANAP_CAUSE, &gtp_val_ext, "Unknown"),
                                   val_to_str_ext_const(ranap, &ranap_cause_type_ext, "Unknown RANAP Cause"), ranap);

    return 2;
}

/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.19, page 52
 */
static int decode_gtp_rab_cntxt(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint8 nsapi;
    proto_tree *ext_tree_rab_cntxt;
    proto_item *te;

    te = proto_tree_add_text(tree, tvb, offset, 10, "%s", val_to_str_ext_const(GTP_EXT_RAB_CNTXT, &gtp_val_ext, "Unknown message"));
    ext_tree_rab_cntxt = proto_item_add_subtree(te, ett_gtp_rab_cntxt);

    nsapi = tvb_get_guint8(tvb, offset + 1) & 0x0F;

    proto_tree_add_uint(ext_tree_rab_cntxt, hf_gtp_nsapi, tvb, offset + 1, 1, nsapi);
    proto_tree_add_item(ext_tree_rab_cntxt, hf_gtp_rab_gtpu_dn, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree_rab_cntxt, hf_gtp_rab_gtpu_up, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree_rab_cntxt, hf_gtp_rab_pdu_dn, tvb, offset + 6, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree_rab_cntxt, hf_gtp_rab_pdu_up, tvb, offset + 8, 2, ENC_BIG_ENDIAN);

    return 10;
}


/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.20, page 53
 */
static int decode_gtp_rp_sms(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint8 rp_sms;

    rp_sms = tvb_get_guint8(tvb, offset + 1) & 0x07;
    proto_tree_add_uint(tree, hf_gtp_rp_sms, tvb, offset, 2, rp_sms);

    return 2;
}

/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.21, page 53
 */
static int decode_gtp_rp(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    proto_tree *ext_tree_rp;
    proto_item *te;
    guint8 nsapi, rp, spare;

    nsapi = tvb_get_guint8(tvb, offset + 1) & 0xF0;
    spare = tvb_get_guint8(tvb, offset + 1) & 0x08;
    rp = tvb_get_guint8(tvb, offset + 1) & 0x07;

    te = proto_tree_add_uint_format(tree, hf_gtp_rp, tvb, offset, 2, rp, "Radio Priority for NSAPI(%u) : %u", nsapi, rp);
    ext_tree_rp = proto_item_add_subtree(te, ett_gtp_rp);

    proto_tree_add_uint(ext_tree_rp, hf_gtp_rp_nsapi, tvb, offset + 1, 1, nsapi);
    proto_tree_add_uint(ext_tree_rp, hf_gtp_rp_spare, tvb, offset + 1, 1, spare);
    proto_tree_add_uint(ext_tree_rp, hf_gtp_rp, tvb, offset + 1, 1, rp);

    return 2;
}

/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.22, page 53
 */
static int decode_gtp_pkt_flow_id(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    proto_tree *ext_tree_pkt_flow_id;
    proto_item *te;
    guint8 nsapi, pkt_flow_id;

    nsapi = tvb_get_guint8(tvb, offset + 1) & 0x0F;
    pkt_flow_id = tvb_get_guint8(tvb, offset + 2);

    te = proto_tree_add_uint_format(tree, hf_gtp_pkt_flow_id, tvb, offset, 3, pkt_flow_id, "Packet Flow ID for NSAPI(%u) : %u", nsapi, pkt_flow_id);
    ext_tree_pkt_flow_id = proto_item_add_subtree(te, ett_gtp_pkt_flow_id);

    proto_tree_add_uint(ext_tree_pkt_flow_id, hf_gtp_nsapi, tvb, offset + 1, 1, nsapi);
    proto_tree_add_uint_format(ext_tree_pkt_flow_id, hf_gtp_pkt_flow_id, tvb,
                               offset + 2, 1, pkt_flow_id, "%s : %u", val_to_str_ext_const(GTP_EXT_PKT_FLOW_ID, &gtp_val_ext, "Unknown message"), pkt_flow_id);

    return 3;
}

/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.23, page 53
 * TODO: Differenciate these uints?
 */
static int decode_gtp_chrg_char(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 chrg_char;
    proto_item *te;
    proto_tree *ext_tree_chrg_char;

    chrg_char = tvb_get_ntohs(tvb, offset + 1);

    te = proto_tree_add_uint(tree, hf_gtp_chrg_char, tvb, offset, 3, chrg_char);
    /*"%s: %x", val_to_str_ext_const (GTP_EXT_CHRG_CHAR, &gtp_val_ext, "Unknown message"), chrg_char); */
    ext_tree_chrg_char = proto_item_add_subtree(te, ett_gtp_chrg_char);

    proto_tree_add_uint(ext_tree_chrg_char, hf_gtp_chrg_char_s, tvb, offset + 1, 2, chrg_char);
    proto_tree_add_uint(ext_tree_chrg_char, hf_gtp_chrg_char_n, tvb, offset + 1, 2, chrg_char);
    proto_tree_add_uint(ext_tree_chrg_char, hf_gtp_chrg_char_p, tvb, offset + 1, 2, chrg_char);
    proto_tree_add_uint(ext_tree_chrg_char, hf_gtp_chrg_char_f, tvb, offset + 1, 2, chrg_char);
    proto_tree_add_uint(ext_tree_chrg_char, hf_gtp_chrg_char_h, tvb, offset + 1, 2, chrg_char);
    proto_tree_add_uint(ext_tree_chrg_char, hf_gtp_chrg_char_r, tvb, offset + 1, 2, chrg_char);

    return 3;
}

/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.24, page
 */
static int decode_gtp_trace_ref(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 trace_ref;

    trace_ref = tvb_get_ntohs(tvb, offset + 1);

    proto_tree_add_uint(tree, hf_gtp_trace_ref, tvb, offset, 3, trace_ref);

    return 3;
}

/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.25, page
 */
static int decode_gtp_trace_type(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 trace_type;

    trace_type = tvb_get_ntohs(tvb, offset + 1);

    proto_tree_add_uint(tree, hf_gtp_trace_type, tvb, offset, 3, trace_type);

    return 3;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.16A
 * UMTS:        29.060 v4.0, chapter 7.7.25A, page
 */
static int decode_gtp_ms_reason(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint8 reason;

    reason = tvb_get_guint8(tvb, offset + 1);

    /* Reason for Absence is defined in 3GPP TS 23.040  */
    proto_tree_add_uint(tree, hf_gtp_ms_reason, tvb, offset, 2, reason);

    return 2;
}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.25B
 * Radio Priority LCS
 */
static int decode_gtp_ra_prio_lcs(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s : ", val_to_str_ext_const(GTP_EXT_RA_PRIO_LCS, &gtp_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_ra_prio_lcs);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    proto_tree_add_item(ext_tree, hf_gtp_ra_prio_lcs, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 3 + length;

}

/* GPRS:        12.15 v7.6.0, chapter 7.3.3, page 45
 * UMTS:        33.015
 */
static int decode_gtp_tr_comm(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint8 tr_command;

    tr_command = tvb_get_guint8(tvb, offset + 1);

    proto_tree_add_uint(tree, hf_gtp_tr_comm, tvb, offset, 2, tr_command);

    return 2;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.17, page 43
 * UMTS:        29.060 v4.0, chapter 7.7.26, page 55
 */
static int decode_gtp_chrg_id(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint32 chrg_id;

    chrg_id = tvb_get_ntohl(tvb, offset + 1);
    proto_tree_add_uint(tree, hf_gtp_chrg_id, tvb, offset, 5, chrg_id);

    return 5;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.18, page 43
 * UMTS:        29.060 v4.0, chapter 7.7.27, page 55
 */
static int decode_gtp_user_addr(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    guint8 pdp_typ, pdp_org;
    guint32 addr_ipv4;
    struct e_in6_addr addr_ipv6;
    proto_tree *ext_tree_user;
    proto_item *te;


    length = tvb_get_ntohs(tvb, offset + 1);
    pdp_org = tvb_get_guint8(tvb, offset + 3) & 0x0F;
    pdp_typ = tvb_get_guint8(tvb, offset + 4);

    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s (%s/%s)",
                             val_to_str_ext_const(GTP_EXT_USER_ADDR, &gtp_val_ext, "Unknown message"),
                             val_to_str_const(pdp_org, pdp_org_type, "Unknown PDP Organization"),
                             val_to_str_const(pdp_typ, pdp_type, "Unknown PDP Type"));
    ext_tree_user = proto_item_add_subtree(te, ett_gtp_user);

    proto_tree_add_text(ext_tree_user, tvb, offset + 1, 2, "Length : %u", length);
    proto_tree_add_uint(ext_tree_user, hf_gtp_user_addr_pdp_org, tvb, offset + 3, 1, pdp_org);
    proto_tree_add_uint(ext_tree_user, hf_gtp_user_addr_pdp_type, tvb, offset + 4, 1, pdp_typ);

    if (length == 2) {
        if (pdp_org == 0 && pdp_typ == 1)
            proto_item_append_text(te, " (Point to Point Protocol)");
        else if (pdp_typ == 2)
            proto_item_append_text(te, " (Octet Stream Protocol)");
    } else if (length > 2) {
        switch (pdp_typ) {
        case 0x21:
            addr_ipv4 = tvb_get_ipv4(tvb, offset + 5);
            proto_tree_add_ipv4(ext_tree_user, hf_gtp_user_ipv4, tvb, offset + 5, 4, addr_ipv4);
            proto_item_append_text(te, " : %s", ip_to_str((guint8 *) & addr_ipv4));
            break;
        case 0x57:
            tvb_get_ipv6(tvb, offset + 5, &addr_ipv6);
            proto_tree_add_ipv6(ext_tree_user, hf_gtp_user_ipv6, tvb, offset + 5, 16, (guint8 *) & addr_ipv6);
            proto_item_append_text(te, " : %s", ip6_to_str((struct e_in6_addr *) &addr_ipv6));
            break;
        }
    } else
        proto_item_append_text(te, " : empty PDP Address");

    return 3 + length;
}

static int decode_triplet(tvbuff_t * tvb, int offset, proto_tree * tree, guint16 count)
{

    proto_tree *ext_tree_trip;
    proto_item *te_trip;
    guint16 i;

    for (i = 0; i < count; i++) {
        te_trip = proto_tree_add_text(tree, tvb, offset + i * 28, 28, "Triplet no%x", i);
        ext_tree_trip = proto_item_add_subtree(te_trip, ett_gtp_trip);

        proto_tree_add_text(ext_tree_trip, tvb, offset + i * 28, 16, "RAND: %s", tvb_bytes_to_str(tvb, offset + i * 28, 16));
        proto_tree_add_text(ext_tree_trip, tvb, offset + i * 28 + 16, 4, "SRES: %s", tvb_bytes_to_str(tvb, offset + i * 28 + 16, 4));
        proto_tree_add_text(ext_tree_trip, tvb, offset + i * 28 + 20, 8, "Kc: %s", tvb_bytes_to_str(tvb, offset + i * 28 + 20, 8));
    }

    return count * 28;
}

/* adjust - how many bytes before quintuplet should be highlighted
 */
static int decode_quintuplet(tvbuff_t * tvb, int offset, proto_tree * tree, guint16 count)
{

    proto_tree *ext_tree_quint;
    proto_item *te_quint;
    guint16 q_offset, i;
    guint8 xres_len, auth_len;

    q_offset = 0;

    for (i = 0; i < count; i++) {

        te_quint = proto_tree_add_text(tree, tvb, offset, -1, "Quintuplet #%x", i + 1);
        ext_tree_quint = proto_item_add_subtree(te_quint, ett_gtp_quint);


        proto_tree_add_text(ext_tree_quint, tvb, offset + q_offset, 16, "RAND: %s", tvb_bytes_to_str(tvb, offset, 16));
        q_offset = q_offset + 16;
        xres_len = tvb_get_guint8(tvb, offset + q_offset);
        proto_tree_add_text(ext_tree_quint, tvb, offset + q_offset, 1, "XRES length: %u", xres_len);
        q_offset++;
        proto_tree_add_text(ext_tree_quint, tvb, offset + q_offset, xres_len, "XRES: %s", tvb_bytes_to_str(tvb, offset + q_offset, xres_len));
        q_offset = q_offset + xres_len;
        proto_tree_add_text(ext_tree_quint, tvb, offset + q_offset, 16, "Quintuplet Ciphering Key: %s", tvb_bytes_to_str(tvb, offset + q_offset, 16));
        q_offset = q_offset + 16;
        proto_tree_add_text(ext_tree_quint, tvb, offset + q_offset, 16, "Quintuplet Integrity Key: %s", tvb_bytes_to_str(tvb, offset + q_offset, 16));
        q_offset = q_offset + 16;
        auth_len = tvb_get_guint8(tvb, offset + q_offset);
        proto_tree_add_text(ext_tree_quint, tvb, offset + q_offset, 1, "Authentication length: %u", auth_len);
        q_offset++;
        proto_tree_add_text(ext_tree_quint, tvb, offset + q_offset, auth_len, "AUTH: %s", tvb_bytes_to_str(tvb, offset + q_offset, auth_len));

        q_offset = q_offset + auth_len;
        proto_item_set_end(te_quint, tvb, offset + q_offset);

    }

    return q_offset;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.19 page
 * UMTS:        29.060 v4.0, chapter 7.7.28 page 57
 * TODO:        - check if for quintuplets first 2 bytes are length, according to AuthQuint
 *              - finish displaying last 3 parameters
 */
static int decode_gtp_mm_cntxt(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree)
{

    guint16 length, quint_len, con_len;
    guint8 count, sec_mode, len, iei;
    proto_tree *ext_tree_mm;
    proto_item *te;
    proto_item *tf = NULL;
    proto_tree *tf_tree = NULL;

    te = proto_tree_add_text(tree, tvb, offset, 1, "%s", val_to_str_ext_const(GTP_EXT_MM_CNTXT, &gtp_val_ext, "Unknown message"));
    ext_tree_mm = proto_item_add_subtree(te, ett_gtp_mm);

    /* Octet 2 - 3 */
    length = tvb_get_ntohs(tvb, offset + 1);
    if (length < 1)
        return 3;

    /* Octet 4 (cksn)*/

    /* Octet 5 */
    sec_mode = (tvb_get_guint8(tvb, offset + 4) >> 6) & 0x03;
    count = (tvb_get_guint8(tvb, offset + 4) >> 3) & 0x07;

    proto_tree_add_text(ext_tree_mm, tvb, offset + 1, 2, "Length: %x", length);
    if (gtp_version == 0)
        sec_mode = 1;


    switch (sec_mode) {
    case 0:                     /* Used cipher value, UMTS keys and Quintuplets */
        proto_tree_add_item(ext_tree_mm, hf_gtp_cksn_ksi, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ext_tree_mm, hf_gtp_security_mode, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ext_tree_mm, hf_gtp_no_of_vectors, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ext_tree_mm, hf_gtp_cipher_algorithm, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_text(ext_tree_mm, tvb, offset + 5, 16, "Ciphering key CK: %s", tvb_bytes_to_str(tvb, offset + 5, 16));
        proto_tree_add_text(ext_tree_mm, tvb, offset + 21, 16, "Integrity key IK: %s", tvb_bytes_to_str(tvb, offset + 21, 16));
        quint_len = tvb_get_ntohs(tvb, offset + 37);
        proto_tree_add_text(ext_tree_mm, tvb, offset + 37, 2, "Quintuplets length: 0x%x (%u)", quint_len, quint_len);

        offset = offset + decode_quintuplet(tvb, offset + 39, ext_tree_mm, count) + 39;


        break;
    case 1:                     /* GSM key and triplets */
        proto_tree_add_item(ext_tree_mm, hf_gtp_cksn, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
        if (gtp_version != 0)
            proto_tree_add_item(ext_tree_mm, hf_gtp_security_mode, tvb, offset + 4, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(ext_tree_mm, hf_gtp_no_of_vectors, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ext_tree_mm, hf_gtp_cipher_algorithm, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_text(ext_tree_mm, tvb, offset + 5, 8, "Ciphering key Kc: %s", tvb_bytes_to_str(tvb, offset + 5, 8));

        offset = offset + decode_triplet(tvb, offset + 13, ext_tree_mm, count) + 13;

        break;
    case 2:                     /* UMTS key and quintuplets */
        proto_tree_add_item(ext_tree_mm, hf_gtp_ksi, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ext_tree_mm, hf_gtp_security_mode, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ext_tree_mm, hf_gtp_no_of_vectors, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_text(ext_tree_mm, tvb, offset + 5, 16, "Ciphering key CK: %s", tvb_bytes_to_str(tvb, offset + 5, 16));
        proto_tree_add_text(ext_tree_mm, tvb, offset + 21, 16, "Integrity key IK: %s", tvb_bytes_to_str(tvb, offset + 21, 16));
        quint_len = tvb_get_ntohs(tvb, offset + 37);
        proto_tree_add_text(ext_tree_mm, tvb, offset + 37, 2, "Quintuplets length: 0x%x (%u)", quint_len, quint_len);

        offset = offset + decode_quintuplet(tvb, offset + 39, ext_tree_mm, count) + 39;

        break;
    case 3:                     /* GSM key and quintuplets */
        proto_tree_add_item(ext_tree_mm, hf_gtp_cksn, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ext_tree_mm, hf_gtp_security_mode, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ext_tree_mm, hf_gtp_no_of_vectors, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ext_tree_mm, hf_gtp_cipher_algorithm, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_text(ext_tree_mm, tvb, offset + 5, 8, "Ciphering key Kc: %s", tvb_bytes_to_str(tvb, offset + 5, 8));
        quint_len = tvb_get_ntohs(tvb, offset + 13);
        proto_tree_add_text(ext_tree_mm, tvb, offset + 13, 2, "Quintuplets length: 0x%x (%u)", quint_len, quint_len);

        offset = offset + decode_quintuplet(tvb, offset + 15, ext_tree_mm, count) + 15;

        break;
    default:
        break;
    }

/*
 * 3GPP TS 24.008 10.5.5.6 ( see packet-gsm_a.c )
 */
    de_gmm_drx_param(tvb, ext_tree_mm, pinfo, offset, 2, NULL, 0);
    offset = offset + 2;

    len = tvb_get_guint8(tvb, offset);
    tf = proto_tree_add_text(ext_tree_mm, tvb, offset, len + 1, "MS Network Capability");

    tf_tree = proto_item_add_subtree(tf, ett_gtp_net_cap);

    proto_tree_add_text(tf_tree, tvb, offset, 1, "Length of MS network capability contents: %u", len);

    offset++;
/*
 * GPP TS 24.008 10.5.5.12 ( see packet-gsm_a.c )
 */
    de_gmm_ms_net_cap(tvb, tf_tree, pinfo, offset, len, NULL, 0);
    offset = offset + len;

/* 3GPP TS 29.060 version 9.4.0 Release 9
 *  The two octets Container Length holds the length of the Container, excluding the Container Length octets.
 * Container contains one or several optional information elements as described in the clause "Overview", from the clause
 * "General message format and information elements coding" in 3GPP TS 24.008 [5]. For the definition of the IEI see
 * table 47a, "IEIs for information elements used in the container". The IMEISV shall, if available, be included in the
 * Container. The IMEISV is included in the Mobile identity IE. If Container is not included, its Length field value shall
 * be set to 0. If the MS is emergency attached and the MS is UICCless or the IMSI is unauthenticated, the International
 * Mobile Equipment Identity (IMEI) shall be used as the MS identity.
 *
 * Table 47A: IEIs for information elements used in the container
 * IEI            Information element
 * 0x23           Mobile identity
 *
 * NOTE: In 3GPP TS 24.008 [5] the IEI definition is
 * message dependent. The table is added to
 * have a unique definition in the present
 * document for the used IEI in the MMcontext.
 */

    con_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(ext_tree_mm, tvb, offset, 2, "Container length: %u", con_len);
    offset = offset + 2;

    if (con_len > 0) {
        proto_tree_add_text(ext_tree_mm, tvb, offset, con_len, "Container");

        iei = tvb_get_guint8(tvb,offset);
        if (iei == 0x23){
            proto_tree_add_text(ext_tree_mm, tvb, offset, 1, "Mobile identity IEI %u",iei);
            offset++;
            len = tvb_get_guint8(tvb,offset);
            proto_tree_add_text(ext_tree_mm, tvb, offset, 1, "Length %u",len);
            offset++;
            de_mid(tvb, ext_tree_mm, pinfo, offset, len, NULL, 0);
        }else{
            proto_tree_add_text(ext_tree_mm, tvb, offset, 1, "Unknown IEI %u - Later spec than TS 29.060 9.4.0 used?",iei);
        }
    }

    return 3 + length;
}

/* Function to extract the value of an hexadecimal octet. Only the lower
 * nybble will be non-zero in the output.
 * */
static guint8 hex2dec(guint8 x)
{
    if ((x >= 'a') && (x <= 'f'))
        x = x - 'a' + 10;
    else if ((x >= 'A') && (x <= 'F'))
        x = x - 'A' + 10;
    else if ((x >= '0') && (x <= '9'))
        x = x - '0';
    else
        x = 0;
    return x;
}

/* Wrapper function to add UTF-8 decoding for QoS attributes in
 * RADIUS messages.
 * */
static guint8 wrapped_tvb_get_guint8(tvbuff_t * tvb, int offset, int type)
{
    if (type == 2)
        return (hex2dec(tvb_get_guint8(tvb, offset)) << 4 | hex2dec(tvb_get_guint8(tvb, offset + 1)));
    else
        return tvb_get_guint8(tvb, offset);
}

 /* WARNING : actually length is coded on 2 octets for QoS profile but on 1 octet for PDP Context!
  * so type means length of length :-)
  *
  * WARNING :) type does not mean length of length any more... see below for
  * type = 3!
  */
static int decode_qos_umts(tvbuff_t * tvb, int offset, proto_tree * tree, const gchar * qos_str, guint8 type)
{

    guint length;
    guint8 al_ret_priority;
    guint8 delay, reliability, peak, precedence, mean, spare1, spare2, spare3;
    guint8 traf_class, del_order, del_err_sdu;
    guint8 max_sdu_size, max_ul, max_dl, max_ul_ext, max_dl_ext;
    guint8 res_ber, sdu_err_ratio;
    guint8 trans_delay, traf_handl_prio;
    guint8 guar_ul, guar_dl, guar_ul_ext, guar_dl_ext;
    guint8 src_stat_desc, sig_ind;
    proto_tree *ext_tree_qos;
    proto_item *te;
    int mss, mu, md, gu, gd;

    /* Will keep if the input is UTF-8 encoded (as in RADIUS messages).
     * If 1, input is *not* UTF-8 encoded (i.e. each input octet corresponds
     * to one byte to be dissected).
     * If 2, input is UTF-8 encoded (i.e. each *couple* of input octets
     * corresponds to one byte to be dissected)
     * */
    guint8 utf8_type = 1;

    /* In RADIUS messages the QoS has a version field of two octets prepended.
     * As of 29.061 v.3.a.0, there is an hyphen between "Release Indicator" and
     * <release specific QoS IE UTF-8 encoding>. Even if it sounds rather
     * inconsistent and unuseful, I will check hyphen presence here and
     * will signal its presence.
     * */
    guint8 hyphen;

    /* Will keep the value that will be returned
     * */
    int retval = 0;

    switch (type) {
    case 1:
        length = tvb_get_guint8(tvb, offset);
        te = proto_tree_add_text(tree, tvb, offset, length + 1, "%s", qos_str);
        ext_tree_qos = proto_item_add_subtree(te, ett_gtp_qos);
        proto_tree_add_text(ext_tree_qos, tvb, offset, 1, "Length: %u", length);
        offset++;
        retval = length + 1;
        break;
    case 2:
        length = tvb_get_ntohs(tvb, offset + 1);
        te = proto_tree_add_text(tree, tvb, offset, length + 3, "%s", qos_str);
        ext_tree_qos = proto_item_add_subtree(te, ett_gtp_qos);
        proto_tree_add_text(ext_tree_qos, tvb, offset + 1, 2, "Length: %u", length);
        offset += 3;            /* +1 because of first 0x86 byte for UMTS QoS */
        retval = length + 3;
        break;
    case 3:
        /* For QoS inside RADIUS Client messages from GGSN */
        utf8_type = 2;

        /* The field in the RADIUS message is the length of the tvb we were given */
        length = tvb_length(tvb);
        te = proto_tree_add_text(tree, tvb, offset, length, "%s", qos_str);

        ext_tree_qos = proto_item_add_subtree(te, ett_gtp_qos);

        proto_tree_add_item(ext_tree_qos, hf_gtp_qos_version, tvb, offset, 2, ENC_ASCII|ENC_NA);

        /* Hyphen handling */
        hyphen = tvb_get_guint8(tvb, offset + 2);
        if (hyphen == ((guint8) '-')) {
            /* Hyphen is present, put in protocol tree */
            proto_tree_add_text(ext_tree_qos, tvb, offset + 2, 1, "Hyphen separator: -");
            offset++;           /* "Get rid" of hyphen */
        }

        /* Now, we modify offset here and in order to use type later
         * effectively.*/
        offset++;

        length -= offset;
        length /= 2;

        retval = length + 2;    /* Actually, will be ignored. */
        break;
    default:
        /* XXX - what should we do with the length here? */
        length = 0;
        retval = 0;
        ext_tree_qos = NULL;
        break;
    }

    /* In RADIUS messages there is no allocation-retention priority
     * so I don't need to wrap the following call to tvb_get_guint8
     * */
    al_ret_priority = tvb_get_guint8(tvb, offset);

    /* All calls are wrapped to take into account the possibility that the
     * input is UTF-8 encoded. If utf8_type is equal to 1, the final value
     * of the offset will be the same as in the previous version of this
     * dissector, and the wrapped function will serve as a dumb wrapper;
     * otherwise, if utf_8_type is 2, the offset is correctly shifted by
     * two bytes for needed shift, and the wrapped function will unencode
     * two values from the input.
     * */
    spare1 = wrapped_tvb_get_guint8(tvb, offset + (1 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_SPARE1_MASK;
    delay = wrapped_tvb_get_guint8(tvb, offset + (1 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_DELAY_MASK;
    reliability = wrapped_tvb_get_guint8(tvb, offset + (1 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_RELIABILITY_MASK;
    peak = wrapped_tvb_get_guint8(tvb, offset + (2 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_PEAK_MASK;
    spare2 = wrapped_tvb_get_guint8(tvb, offset + (2 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_SPARE2_MASK;
    precedence = wrapped_tvb_get_guint8(tvb, offset + (2 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_PRECEDENCE_MASK;
    spare3 = wrapped_tvb_get_guint8(tvb, offset + (3 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_SPARE3_MASK;
    mean = wrapped_tvb_get_guint8(tvb, offset + (3 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_MEAN_MASK;

    /* In RADIUS messages there is no allocation-retention priority */
    if (type != 3)
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_al_ret_priority, tvb, offset, 1, al_ret_priority);

    /* All additions must take care of the fact that QoS fields in RADIUS
     * messages are UTF-8 encoded, so we have to use the same trick as above.
     * */
    proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_spare1, tvb, offset + (1 - 1) * utf8_type + 1, utf8_type, spare1);
    proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_delay, tvb, offset + (1 - 1) * utf8_type + 1, utf8_type, delay);
    proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_reliability, tvb, offset + (1 - 1) * utf8_type + 1, utf8_type, reliability);
    proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_peak, tvb, offset + (2 - 1) * utf8_type + 1, utf8_type, peak);
    proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_spare2, tvb, offset + (2 - 1) * utf8_type + 1, utf8_type, spare2);
    proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_precedence, tvb, offset + (2 - 1) * utf8_type + 1, utf8_type, precedence);
    proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_spare3, tvb, offset + (3 - 1) * utf8_type + 1, utf8_type, spare3);
    proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_mean, tvb, offset + (3 - 1) * utf8_type + 1, utf8_type, mean);

    /* TS 24.008 V 7.8.0
     * The quality of service is a type 4 information element with a minimum length of 14 octets and a maximum length of 18
     * octets. The QoS requested by the MS shall be encoded both in the QoS attributes specified in octets 3-5 and in the QoS
     * attributes specified in octets 6-14.
     * In the MS to network direction and in the network to MS direction the following applies:
     * - Octets 15-18 are optional. If octet 15 is included, then octet 16 shall also be included, and octets 17 and 18 may
     * be included.
     * - If octet 17 is included, then octet 18 shall also be included.
     * - A QoS IE received without octets 6-18, without octets 14-18, without octets 15-18, or without octets 17-18 shall
     * be accepted by the receiving entity.
     */

    if (length > 4) {

        /* See above for the need of wrapping
         *
         */
        /* Octet 6 */
        traf_class = wrapped_tvb_get_guint8(tvb, offset + (4 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_TRAF_CLASS_MASK;
        del_order = wrapped_tvb_get_guint8(tvb, offset + (4 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_DEL_ORDER_MASK;
        del_err_sdu = wrapped_tvb_get_guint8(tvb, offset + (4 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_DEL_ERR_SDU_MASK;
        max_sdu_size = wrapped_tvb_get_guint8(tvb, offset + (5 - 1) * utf8_type + 1, utf8_type);
        max_ul = wrapped_tvb_get_guint8(tvb, offset + (6 - 1) * utf8_type + 1, utf8_type);
        max_dl = wrapped_tvb_get_guint8(tvb, offset + (7 - 1) * utf8_type + 1, utf8_type);
        res_ber = wrapped_tvb_get_guint8(tvb, offset + (8 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_RES_BER_MASK;
        sdu_err_ratio = wrapped_tvb_get_guint8(tvb, offset + (8 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_SDU_ERR_RATIO_MASK;
        trans_delay = wrapped_tvb_get_guint8(tvb, offset + (9 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_TRANS_DELAY_MASK;
        traf_handl_prio = wrapped_tvb_get_guint8(tvb, offset + (9 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_TRAF_HANDL_PRIORITY_MASK;
        guar_ul = wrapped_tvb_get_guint8(tvb, offset + (10 - 1) * utf8_type + 1, utf8_type);
        /* Octet 13 */
        guar_dl = wrapped_tvb_get_guint8(tvb, offset + (11 - 1) * utf8_type + 1, utf8_type);

        src_stat_desc = 0;
        sig_ind = 0;
        max_dl_ext = 0;
        guar_dl_ext = 0;
        max_ul_ext = 0;
        guar_ul_ext =0;

        if (length > 13) {
            src_stat_desc = wrapped_tvb_get_guint8(tvb, offset + (12 - 1) * utf8_type + 1, utf8_type)& GTP_EXT_QOS_SRC_STAT_DESC_MASK;
            sig_ind = wrapped_tvb_get_guint8(tvb, offset + (12 - 1) * utf8_type + 1, utf8_type)& GTP_EXT_QOS_SIG_IND_MASK;
        }
        if (length > 14) {
            max_dl_ext = wrapped_tvb_get_guint8(tvb, offset + (13 - 1) * utf8_type + 1, utf8_type);
            guar_dl_ext = wrapped_tvb_get_guint8(tvb, offset + (14 - 1) * utf8_type + 1, utf8_type);
        }
        if (length > 17) {
            max_ul_ext = wrapped_tvb_get_guint8(tvb, offset + (15 - 1) * utf8_type + 1, utf8_type);
            guar_ul_ext = wrapped_tvb_get_guint8(tvb, offset + (16 - 1) * utf8_type + 1, utf8_type);
        }

        /* See above comments for the changes
         * */
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_traf_class, tvb, offset + (4 - 1) * utf8_type + 1, utf8_type, traf_class);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_del_order, tvb, offset + (4 - 1) * utf8_type + 1, utf8_type, del_order);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_del_err_sdu, tvb, offset + (4 - 1) * utf8_type + 1, utf8_type, del_err_sdu);
        if (max_sdu_size == 0 || max_sdu_size > 150)
            proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_max_sdu_size, tvb, offset + (5 - 1) * utf8_type + 1, utf8_type, max_sdu_size);
        if (max_sdu_size > 0 && max_sdu_size <= 150) {
            mss = max_sdu_size * 10;
            proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_sdu_size, tvb, offset + (5 - 1) * utf8_type + 1, utf8_type, mss,
                                       "Maximum SDU size: %u octets", mss);
        }

        if (max_ul == 0 || max_ul == 255)
            proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_max_ul, tvb, offset + (6 - 1) * utf8_type + 1, utf8_type, max_ul);
        if (max_ul > 0 && max_ul <= 63)
            proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_ul, tvb, offset + (6 - 1) * utf8_type + 1, utf8_type, max_ul,
                                       "Maximum bit rate for uplink: %u kbps", max_ul);
        if (max_ul > 63 && max_ul <= 127) {
            mu = 64 + (max_ul - 64) * 8;
            proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_ul, tvb, offset + (6 - 1) * utf8_type + 1, utf8_type, mu,
                                       "Maximum bit rate for uplink: %u kbps", mu);
        }

        if (max_ul > 127 && max_ul <= 254) {
            mu = 576 + (max_ul - 128) * 64;
            proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_ul, tvb, offset + (6 - 1) * utf8_type + 1, utf8_type, mu,
                                       "Maximum bit rate for uplink: %u kbps", mu);
        }

        if (max_dl == 0 || max_dl == 255)
            proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_max_dl, tvb, offset + (7 - 1) * utf8_type + 1, utf8_type, max_dl);
        if (max_dl > 0 && max_dl <= 63)
            proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_dl, tvb, offset + (7 - 1) * utf8_type + 1, utf8_type, max_dl,
                                       "Maximum bit rate for downlink: %u kbps", max_dl);
        if (max_dl > 63 && max_dl <= 127) {
            md = 64 + (max_dl - 64) * 8;
            proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_dl, tvb, offset + (7 - 1) * utf8_type + 1, utf8_type, md,
                                       "Maximum bit rate for downlink: %u kbps", md);
        }
        if (max_dl > 127 && max_dl <= 254) {
            md = 576 + (max_dl - 128) * 64;
            proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_dl, tvb, offset + (7 - 1) * utf8_type + 1, utf8_type, md,
                                       "Maximum bit rate for downlink: %u kbps", md);
        }

        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_res_ber, tvb, offset + (8 - 1) * utf8_type + 1, utf8_type, res_ber);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_sdu_err_ratio, tvb, offset + (8 - 1) * utf8_type + 1, utf8_type, sdu_err_ratio);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_trans_delay, tvb, offset + (9 - 1) * utf8_type + 1, utf8_type, trans_delay);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_traf_handl_prio, tvb, offset + (9 - 1) * utf8_type + 1, utf8_type, traf_handl_prio);

        if (guar_ul == 0 || guar_ul == 255)
            proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_guar_ul, tvb, offset + (10 - 1) * utf8_type + 1, utf8_type, guar_ul);
        if (guar_ul > 0 && guar_ul <= 63)
            proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_ul, tvb, offset + (10 - 1) * utf8_type + 1, utf8_type, guar_ul,
                                       "Guaranteed bit rate for uplink: %u kbps", guar_ul);
        if (guar_ul > 63 && guar_ul <= 127) {
            gu = 64 + (guar_ul - 64) * 8;
            proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_ul, tvb, offset + (10 - 1) * utf8_type + 1, utf8_type, gu,
                                       "Guaranteed bit rate for uplink: %u kbps", gu);
        }
        if (guar_ul > 127 && guar_ul <= 254) {
            gu = 576 + (guar_ul - 128) * 64;
            proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_ul, tvb, offset + (10 - 1) * utf8_type + 1, utf8_type, gu,
                                       "Guaranteed bit rate for uplink: %u kbps", gu);
        }

        /* Octet 13 */
        if (guar_dl == 0 || guar_dl == 255)
            proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_guar_dl, tvb, offset + (11 - 1) * utf8_type + 1, utf8_type, guar_dl);
        if (guar_dl > 0 && guar_dl <= 63)
            proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_dl, tvb, offset + (11 - 1) * utf8_type + 1, utf8_type, guar_dl,
                                       "Guaranteed bit rate for downlink: %u kbps", guar_dl);
        if (guar_dl > 63 && guar_dl <= 127) {
            gd = 64 + (guar_dl - 64) * 8;
            proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_dl, tvb, offset + (11 - 1) * utf8_type + 1, utf8_type, gd,
                                       "Guaranteed bit rate for downlink: %u kbps", gd);
        }
        if (guar_dl > 127 && guar_dl <= 254) {
            gd = 576 + (guar_dl - 128) * 64;
            proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_dl, tvb, offset + (11 - 1) * utf8_type + 1, utf8_type, gd,
                                       "Guaranteed bit rate for downlink: %u kbps", gd);
        }

        if(length > 13){
            proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_src_stat_desc, tvb, offset + (12 - 1) * utf8_type + 1, utf8_type, src_stat_desc);
            proto_tree_add_boolean(ext_tree_qos, hf_gtp_qos_sig_ind, tvb, offset + (12 - 1) * utf8_type + 1, utf8_type, sig_ind);
        }
        if(length > 14){
            /* Octet 15 */
            if (max_dl_ext > 0 && max_dl_ext <= 0x4a) {
                md = 8600 + max_dl_ext * 100;
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_dl, tvb, offset + (13 - 1) * utf8_type + 1, utf8_type, md,
                                           "Ext Maximum bit rate for downlink: %u kbps", md);
            }
            if (max_dl_ext > 0x4a && max_dl_ext <= 0xba) {
                md = 16 + (max_dl_ext-0x4a);
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_dl, tvb, offset + (13 - 1) * utf8_type + 1, utf8_type, md,
                                           "Ext Maximum bit rate for downlink: %u Mbps", md);
            }
            if (max_dl_ext > 0xba && max_dl_ext <= 0xfa) {
                md = 128 + (max_dl_ext-0xba)*2;
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_dl, tvb, offset + (13 - 1) * utf8_type + 1, utf8_type, md,
                                           "Ext Maximum bit rate for downlink: %u Mbps", md);
            }
            /* Octet 16 */
            if(guar_dl_ext == 0)
                proto_tree_add_text(ext_tree_qos, tvb, offset + (14 - 1) * utf8_type + 1, utf8_type, "Use the value indicated by the Guaranteed bit rate for downlink in octet 13");
            if (guar_dl_ext > 0 && guar_dl_ext <= 0x4a) {
                gd = 8600 + guar_dl_ext * 100;
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_dl, tvb, offset + (14 - 1) * utf8_type + 1, utf8_type, gd,
                                           "Ext Guaranteed bit rate for downlink: %u kbps", gd);
            }
            if (guar_dl_ext > 0x4a && max_dl_ext <= 0xba) {
                gd = 16 + (guar_dl_ext-0x4a);
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_dl, tvb, offset + (14 - 1) * utf8_type + 1, utf8_type, gd,
                                           "Ext Guaranteed bit rate for downlink: %u Mbps", gd);
            }
            if (guar_dl_ext > 0xba && max_dl_ext <= 0xfa) {
                gd = 128 + (guar_dl_ext-0xba)*2;
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_dl, tvb, offset + (14 - 1) * utf8_type + 1, utf8_type, gd,
                                           "Ext Guaranteed bit rate for downlink: %u Mbps", gd);
            }

        }
        if(length > 16){
            /* Octet 17
             * This field is an extension of the Maximum bit rate for uplink in octet 8. The coding is identical to that of the Maximum bit
             * rate for downlink (extended).
             */
            if (max_ul_ext > 0 && max_ul_ext <= 0x4a) {
                md = 8600 + max_ul_ext * 100;
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_ul, tvb, offset + (15 - 1) * utf8_type + 1, utf8_type, md,
                                           "Ext Maximum bit rate for uplink: %u kbps", md);
            }
            if (max_ul_ext > 0x4a && max_ul_ext <= 0xba) {
                md = 16 + (max_ul_ext-0x4a);
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_ul, tvb, offset + (15 - 1) * utf8_type + 1, utf8_type, md,
                                           "Ext Maximum bit rate for uplink: %u Mbps", md);
            }
            if (max_ul_ext > 0xba && max_ul_ext <= 0xfa) {
                md = 128 + (max_ul_ext-0xba)*2;
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_ul, tvb, offset + (15 - 1) * utf8_type + 1, utf8_type, md,
                                           "Ext Maximum bit rate for uplink: %u Mbps", md);
            }
            /* Octet 18 */
            if (guar_ul_ext == 0)
                proto_tree_add_text(ext_tree_qos, tvb, offset + (16 - 1) * utf8_type + 1, utf8_type, "Use the value indicated by the Guaranteed bit rate for uplink in octet 12");
            if (guar_ul_ext > 0 && guar_ul_ext <= 0x4a) {
                gd = 8600 + guar_ul_ext * 100;
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_ul, tvb, offset + (16 - 1) * utf8_type + 1, utf8_type, gd,
                                           "Ext Guaranteed bit rate for uplink: %u kbps", gd);
            }
            if (guar_ul_ext > 0x4a && max_ul_ext <= 0xba) {
                gd = 16 + (guar_ul_ext-0x4a);
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_ul, tvb, offset + (16 - 1) * utf8_type + 1, utf8_type, gd,
                                           "Ext Guaranteed bit rate for uplink: %u Mbps", gd);
            }
            if (guar_ul_ext > 0xba && max_ul_ext <= 0xfa) {
                gd = 128 + (guar_ul_ext-0xba)*2;
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_ul, tvb, offset + (16 - 1) * utf8_type + 1, utf8_type, gd,
                                           "Ext Guaranteed bit rate for uplink: %u Mbps", gd);
            }
        }

    }

    return retval;
}

/* Diameter 3GPP AVP Code: 5 3GPP-GPRS Negotiated QoS profile */
static int
dissect_diameter_3gpp_qosprofile(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {

    decode_qos_umts(tvb, 0, tree, "UMTS GTP QoS Profile", 3);
    return tvb_length(tvb);
}

static const gchar *dissect_radius_qos_umts(proto_tree * tree, tvbuff_t * tvb, packet_info* pinfo _U_)
{
    decode_qos_umts(tvb, 0, tree, "UMTS GTP QoS Profile", 3);
    return tvb_get_ephemeral_string(tvb, 0, tvb_length(tvb));
}

static void decode_apn(tvbuff_t * tvb, int offset, guint16 length, proto_tree * tree)
{

    guint8 *apn = NULL;
    int name_len, tmp;

    if (length > 0) {
        name_len = tvb_get_guint8(tvb, offset);

        if (name_len < 0x20) {
            apn = tvb_get_ephemeral_string(tvb, offset + 1, length - 1);
            for (;;) {
                if (name_len >= length - 1)
                    break;
                tmp = name_len;
                name_len = name_len + apn[tmp] + 1;
                apn[tmp] = '.';
            }
        } else
            apn = tvb_get_ephemeral_string(tvb, offset, length);

        proto_tree_add_string(tree, hf_gtp_apn, tvb, offset, length, apn);
    }
}

/* 
 * GPRS:        9.60 v7.6.0, chapter 7.9.20
 * UMTS:        29.060 v4.0, chapter 7.7.29 PDP Context
 * TODO:        unify addr functions
 */
static int decode_gtp_pdp_cntxt(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint8 ggsn_addr_len, apn_len, trans_id, vaa, asi, order, nsapi, sapi, pdu_send_no, pdu_rec_no, pdp_cntxt_id, pdp_type_org, pdp_type_num, pdp_addr_len;
    guint16 length, sn_down, sn_up, up_flow;
    guint32 addr_ipv4;
    struct e_in6_addr addr_ipv6;
    proto_tree *ext_tree_pdp;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);

    te = proto_tree_add_text(tree, tvb, offset, length + 3, "%s", val_to_str_ext_const(GTP_EXT_PDP_CNTXT, &gtp_val_ext, "Unknown message"));
    ext_tree_pdp = proto_item_add_subtree(te, ett_gtp_pdp);

    vaa = (tvb_get_guint8(tvb, offset + 3) >> 6) & 0x01;
    asi = (tvb_get_guint8(tvb, offset + 3) >> 5) & 0x01;
    order = (tvb_get_guint8(tvb, offset + 3) >> 4) & 0x01;
    nsapi = tvb_get_guint8(tvb, offset + 3) & 0x0F;
    sapi = tvb_get_guint8(tvb, offset + 4) & 0x0F;

    proto_tree_add_text(ext_tree_pdp, tvb, offset + 3, 1, "VPLMN address allowed: %s", yesno[vaa]);
    proto_tree_add_text(ext_tree_pdp, tvb, offset + 3, 1, "Activity Status Indicator: %s", yesno[asi]);
    proto_tree_add_text(ext_tree_pdp, tvb, offset + 3, 1, "Reordering required: %s", yesno[order]);
    proto_tree_add_text(ext_tree_pdp, tvb, offset + 3, 1, "NSAPI: %u", nsapi);
    proto_tree_add_text(ext_tree_pdp, tvb, offset + 4, 1, "SAPI: %u", sapi);

    switch (gtp_version) {
    case 0:
        decode_qos_gprs(tvb, offset + 5, ext_tree_pdp, "QoS subscribed", 0);
        decode_qos_gprs(tvb, offset + 8, ext_tree_pdp, "QoS requested", 0);
        decode_qos_gprs(tvb, offset + 11, ext_tree_pdp, "QoS negotiated", 0);
        offset = offset + 14;
        break;
    case 1:
        offset = offset + 5;
        offset = offset + decode_qos_umts(tvb, offset, ext_tree_pdp, "QoS subscribed", 1);
        offset = offset + decode_qos_umts(tvb, offset, ext_tree_pdp, "QoS requested", 1);
        offset = offset + decode_qos_umts(tvb, offset, ext_tree_pdp, "QoS negotiated", 1);
        break;
    default:
        break;
    }

    sn_down = tvb_get_ntohs(tvb, offset);
    sn_up = tvb_get_ntohs(tvb, offset + 2);
    pdu_send_no = tvb_get_guint8(tvb, offset + 4);
    pdu_rec_no = tvb_get_guint8(tvb, offset + 5);

    proto_tree_add_text(ext_tree_pdp, tvb, offset, 2, "Sequence number down: %u", sn_down);
    proto_tree_add_text(ext_tree_pdp, tvb, offset + 2, 2, "Sequence number up: %u", sn_up);
    proto_tree_add_text(ext_tree_pdp, tvb, offset + 4, 1, "Send N-PDU number: %u", pdu_send_no);
    proto_tree_add_text(ext_tree_pdp, tvb, offset + 5, 1, "Receive N-PDU number: %u", pdu_rec_no);

    switch (gtp_version) {
    case 0:
        up_flow = tvb_get_ntohs(tvb, offset + 6);
        proto_tree_add_text(ext_tree_pdp, tvb, offset + 6, 2, "Uplink flow label signalling: %u", up_flow);
        offset = offset + 8;
        break;
    case 1:
        pdp_cntxt_id = tvb_get_guint8(tvb, offset + 14);
        proto_tree_add_item(ext_tree_pdp, hf_gtp_ulink_teid_cp, tvb, offset + 6, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ext_tree_pdp, hf_gtp_ulink_teid_data, tvb, offset + 10, 4, ENC_BIG_ENDIAN);
        proto_tree_add_text(ext_tree_pdp, tvb, offset + 14, 1, "PDP context identifier: %u", pdp_cntxt_id);
        offset = offset + 15;
        break;
    default:
        break;
    }

    pdp_type_org = tvb_get_guint8(tvb, offset) & 0x0F;
    pdp_type_num = tvb_get_guint8(tvb, offset + 1);
    pdp_addr_len = tvb_get_guint8(tvb, offset + 2);

    proto_tree_add_text(ext_tree_pdp, tvb, offset, 1, "PDP organization: %s", val_to_str_const(pdp_type_org, pdp_type, "Unknown PDP org"));
    proto_tree_add_text(ext_tree_pdp, tvb, offset + 1, 1, "PDP type: %s", val_to_str_const(pdp_type_num, pdp_type, "Unknown PDP type"));
    proto_tree_add_text(ext_tree_pdp, tvb, offset + 2, 1, "PDP address length: %u", pdp_addr_len);

    if (pdp_addr_len > 0) {
        switch (pdp_type_num) {
        case 0x21:
            addr_ipv4 = tvb_get_ipv4(tvb, offset + 3);
            proto_tree_add_text(ext_tree_pdp, tvb, offset + 3, 4, "PDP address: %s", ip_to_str((guint8 *) & addr_ipv4));
            break;
        case 0x57:
            tvb_get_ipv6(tvb, offset + 3, &addr_ipv6);
            proto_tree_add_text(ext_tree_pdp, tvb, offset + 3, 16, "PDP address: %s", ip6_to_str((struct e_in6_addr *) &addr_ipv6));
            break;
        default:
            break;
        }
    }

    offset = offset + 3 + pdp_addr_len;

    ggsn_addr_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(ext_tree_pdp, tvb, offset, 1, "GGSN address length: %u", ggsn_addr_len);

    switch (ggsn_addr_len) {
    case 4:
        addr_ipv4 = tvb_get_ipv4(tvb, offset + 1);
        proto_tree_add_text(ext_tree_pdp, tvb, offset + 1, 4, "GGSN Address for control plane: %s", ip_to_str((guint8 *) & addr_ipv4));
        break;
    case 16:
        tvb_get_ipv6(tvb, offset + 1, &addr_ipv6);
        proto_tree_add_text(ext_tree_pdp, tvb, offset + 1, 16, "GGSN Address for User Traffic: %s", ip6_to_str((struct e_in6_addr *) &addr_ipv6));
        break;
    default:
        break;
    }

    offset = offset + 1 + ggsn_addr_len;

    if (gtp_version == 1) {

        ggsn_addr_len = tvb_get_guint8(tvb, offset);
        proto_tree_add_text(ext_tree_pdp, tvb, offset, 1, "GGSN 2 address length: %u", ggsn_addr_len);

        switch (ggsn_addr_len) {
        case 4:
            addr_ipv4 = tvb_get_ipv4(tvb, offset + 1);
            proto_tree_add_text(ext_tree_pdp, tvb, offset + 1, 4, "GGSN 2 address: %s", ip_to_str((guint8 *) & addr_ipv4));
            break;
        case 16:
            tvb_get_ipv6(tvb, offset + 1, &addr_ipv6);
            proto_tree_add_text(ext_tree_pdp, tvb, offset + 1, 16, "GGSN 2 address: %s", ip6_to_str((struct e_in6_addr *) &addr_ipv6));
            break;
        default:
            break;
        }
        offset = offset + 1 + ggsn_addr_len;

    }

    apn_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(ext_tree_pdp, tvb, offset, 1, "APN length: %u", apn_len);
    decode_apn(tvb, offset + 1, apn_len, ext_tree_pdp);

    offset = offset + 1 + apn_len;
    /*
     * The Transaction Identifier is the 4 or 12 bit Transaction Identifier used in the 3GPP TS 24.008 [5] Session Management
     * messages which control this PDP Context. If the length of the Transaction Identifier is 4 bit, the second octet shall be
     * set to all zeros. The encoding is defined in 3GPP TS 24.007 [3]. The latest Transaction Identifier sent from SGSN to
     * MS is stored in the PDP context IE.
     * NOTE: Bit 5-8 of the first octet in the encoding defined in 3GPP TS 24.007 [3] is mapped into bit 1-4 of the first
     * octet in this field.
     */
    trans_id = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(ext_tree_pdp, tvb, offset, 2, "Transaction identifier: %u", trans_id);

    return 3 + length;
}

/* GPRS:        9.60, v7.6.0, chapter 7.9.21
 * UMTS:        29.060, v4.0, chapter 7.7.30
 */
static int decode_gtp_apn(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree_apn;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);

    te = proto_tree_add_text(tree, tvb, offset, length + 3, "%s", val_to_str_ext_const(GTP_EXT_APN, &gtp_val_ext, "Unknown field"));
    ext_tree_apn = proto_item_add_subtree(te, ett_gtp_apn);

    proto_tree_add_text(ext_tree_apn, tvb, offset + 1, 2, "APN length : %u", length);
    decode_apn(tvb, offset + 3, length, ext_tree_apn);

    return 3 + length;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.22
 *              4.08 v. 7.1.2, chapter 10.5.6.3 (p.580)
 * UMTS:        29.060 v4.0, chapter 7.7.31 Protocol Configuration Options
 *              24.008, v4.2, chapter 10.5.6.3
 */
int decode_gtp_proto_conf(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree)
{

    guint16 length;
    tvbuff_t *next_tvb;
    proto_tree *ext_tree_proto;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);

    te = proto_tree_add_text(tree, tvb, offset, length + 3, "%s", val_to_str_ext_const(GTP_EXT_PROTO_CONF, &gtp_val_ext, "Unknown message"));
    ext_tree_proto = proto_item_add_subtree(te, ett_gtp_proto);

    proto_tree_add_text(ext_tree_proto, tvb, offset + 1, 2, "Length: %u", length);

    if (length < 1)
        return 3;

	/* The Protocol Configuration Options contains external network protocol options that may be necessary to transfer
	 * between the GGSN and the MS. The content and the coding of the Protocol Configuration are defined in octet 3-z of the
	 * Protocol Configuration Options in3GPP TS 24.008 [5].
	 */
	next_tvb = tvb_new_subset(tvb, offset + 3, length, length);
	pinfo->link_dir = P2P_DIR_UL;
	de_sm_pco(next_tvb, ext_tree_proto, pinfo, 0, length, NULL, 0);

    return 3 + length;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.23
 * UMTS:        29.060 v4.0, chapter 7.7.32
 */
static int decode_gtp_gsn_addr(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint8 addr_type, addr_len;
    guint16 length;
    guint32 addr_ipv4;
    struct e_in6_addr addr_ipv6;
    proto_tree *ext_tree_gsn_addr;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);

    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "GSN address : ");
    ext_tree_gsn_addr = proto_item_add_subtree(te, ett_gtp_gsn_addr);

    switch (length) {
    case 4:
        proto_tree_add_text(ext_tree_gsn_addr, tvb, offset + 1, 2, "GSN address length : %u", length);
        addr_ipv4 = tvb_get_ipv4(tvb, offset + 3);
        proto_item_append_text(te, "%s", ip_to_str((guint8 *) & addr_ipv4));
        proto_tree_add_ipv4(ext_tree_gsn_addr, hf_gtp_gsn_ipv4, tvb, offset + 3, 4, addr_ipv4);
        break;
    case 5:
        proto_tree_add_text(ext_tree_gsn_addr, tvb, offset + 1, 2, "GSN address Information Element length : %u", length);
        addr_type = tvb_get_guint8(tvb, offset + 3) & 0xC0;
        proto_tree_add_uint(ext_tree_gsn_addr, hf_gtp_gsn_addr_type, tvb, offset + 3, 1, addr_type);
        addr_len = tvb_get_guint8(tvb, offset + 3) & 0x3F;
        proto_tree_add_uint(ext_tree_gsn_addr, hf_gtp_gsn_addr_len, tvb, offset + 3, 1, addr_len);
        addr_ipv4 = tvb_get_ipv4(tvb, offset + 4);
        proto_item_append_text(te, "%s", ip_to_str((guint8 *) & addr_ipv4));
        proto_tree_add_ipv4(ext_tree_gsn_addr, hf_gtp_gsn_ipv4, tvb, offset + 4, 4, addr_ipv4);
        break;
    case 16:
        proto_tree_add_text(ext_tree_gsn_addr, tvb, offset + 1, 2, "GSN address length : %u", length);
        tvb_get_ipv6(tvb, offset + 3, &addr_ipv6);
        proto_item_append_text(te, "%s", ip6_to_str((struct e_in6_addr *) &addr_ipv6));
        proto_tree_add_ipv6(ext_tree_gsn_addr, hf_gtp_gsn_ipv6, tvb, offset + 3, 16, (guint8 *) & addr_ipv6);
        break;
    case 17:
        proto_tree_add_text(ext_tree_gsn_addr, tvb, offset + 1, 2, "GSN address Information Element length : %u", length);
        addr_type = tvb_get_guint8(tvb, offset + 3) & 0xC0;
        proto_tree_add_uint(ext_tree_gsn_addr, hf_gtp_gsn_addr_type, tvb, offset + 3, 1, addr_type);
        addr_len = tvb_get_guint8(tvb, offset + 3) & 0x3F;
        proto_tree_add_uint(ext_tree_gsn_addr, hf_gtp_gsn_addr_len, tvb, offset + 3, 1, addr_len);
        tvb_get_ipv6(tvb, offset + 4, &addr_ipv6);
        proto_item_append_text(te, "%s", ip6_to_str((struct e_in6_addr *) &addr_ipv6));
        proto_tree_add_ipv6(ext_tree_gsn_addr, hf_gtp_gsn_ipv6, tvb, offset + 4, 16, (guint8 *) & addr_ipv6);
        break;
    default:
        proto_item_append_text(te, "unknown type or wrong length");
        break;
    }

    return 3 + length;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.24
 * UMTS:        29.060 v4.0, chapter 7.7.33
 */
static int decode_gtp_msisdn(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    gchar *msisdn_str;
    guint16 length;

    length = tvb_get_ntohs(tvb, offset + 1);

    if (length < 1)
        return 3;

    msisdn_str = msisdn_to_str(tvb, offset + 3, length);

    proto_tree_add_string(tree, hf_gtp_msisdn, tvb, offset, 3 + length, msisdn_str);

    return 3 + length;
}

/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.34
 *              24.008 v4.2, chapter 10.5.6.5
 */
static int decode_gtp_qos_umts(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    return decode_qos_umts(tvb, offset, tree, "Quality of Service", 2);
}

/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.35
 */
static int decode_gtp_auth_qui(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    proto_tree *ext_tree;
    proto_item *te_quint;
    guint16 length;
    guint8 xres_len, auth_len;


    length = tvb_get_ntohs(tvb, offset + 1);

    te_quint = proto_tree_add_text(tree, tvb, offset, length + 1, "Quintuplet");
    ext_tree = proto_item_add_subtree(te_quint, ett_gtp_quint);
    offset++;

    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    proto_tree_add_text(ext_tree, tvb, offset, 16, "RAND: %s", tvb_bytes_to_str(tvb, offset, 16));
    offset = offset + 16;
    xres_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(ext_tree, tvb, offset, 1, "XRES length: %u", xres_len);
    offset++;
    proto_tree_add_text(ext_tree, tvb, offset, xres_len, "XRES: %s", tvb_bytes_to_str(tvb, offset, xres_len));
    offset = offset + xres_len;
    proto_tree_add_text(ext_tree, tvb, offset, 16, "Quintuplet Ciphering Key: %s", tvb_bytes_to_str(tvb, offset, 16));
    offset = offset + 16;
    proto_tree_add_text(ext_tree, tvb, offset, 16, "Quintuplet Integrity Key: %s", tvb_bytes_to_str(tvb, offset, 16));
    offset = offset + 16;
    auth_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(ext_tree, tvb, offset, 1, "Authentication length: %u", auth_len);
    offset++;
    proto_tree_add_text(ext_tree, tvb, offset, auth_len, "AUTH: %s", tvb_bytes_to_str(tvb, offset, auth_len));

    return (3 + length);

}

/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.36
 *              24.008 v4.2, chapter 10.5.6.12
 */
static int decode_gtp_tft(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length, port1, port2, tos;
    guint8 tft_flags, tft_code, no_packet_filters, i, pf_id, pf_eval, pf_len, pf_content_id, proto;
    guint pf_offset;
    guint32 mask_ipv4, addr_ipv4, ipsec_id, label;
    struct e_in6_addr addr_ipv6, mask_ipv6;
    proto_tree *ext_tree_tft, *ext_tree_tft_pf, *ext_tree_tft_flags;
    proto_item *te, *tee, *tef;

    length = tvb_get_ntohs(tvb, offset + 1);

    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "Traffic flow template");
    ext_tree_tft = proto_item_add_subtree(te, ett_gtp_tft);

    tft_flags = tvb_get_guint8(tvb, offset + 3);
    tft_code = (tft_flags >> 5) & 0x07;
    no_packet_filters = tft_flags & 0x0F;

    proto_tree_add_text(ext_tree_tft, tvb, offset + 1, 2, "TFT length: %u", length);

    tef = proto_tree_add_text(ext_tree_tft, tvb, offset + 3, 1, "TFT flags");
    ext_tree_tft_flags = proto_item_add_subtree(tef, ett_gtp_tft_flags);
    proto_tree_add_uint(ext_tree_tft_flags, hf_gtp_tft_code, tvb, offset + 3, 1, tft_flags);
    proto_tree_add_uint(ext_tree_tft_flags, hf_gtp_tft_spare, tvb, offset + 3, 1, tft_flags);
    proto_tree_add_uint(ext_tree_tft_flags, hf_gtp_tft_number, tvb, offset + 3, 1, tft_flags);

    offset = offset + 4;

    for (i = 0; i < no_packet_filters; i++) {

        pf_id = tvb_get_guint8(tvb, offset);

        tee = proto_tree_add_text(ext_tree_tft, tvb, offset, 1, "Packet filter id: %u", pf_id);
        ext_tree_tft_pf = proto_item_add_subtree(tee, ett_gtp_tft_pf);
        offset++;

        if (tft_code != 2) {

            pf_eval = tvb_get_guint8(tvb, offset);
            pf_len = tvb_get_guint8(tvb, offset + 1);

            proto_tree_add_uint(ext_tree_tft_pf, hf_gtp_tft_eval, tvb, offset, 1, pf_eval);
            proto_tree_add_text(ext_tree_tft_pf, tvb, offset + 1, 1, "Content length: %u", pf_len);

            offset = offset + 2;
            pf_offset = 0;

            while (pf_offset < pf_len) {

                pf_content_id = tvb_get_guint8(tvb, offset + pf_offset);

                switch (pf_content_id) {
                    /* address IPv4 and mask = 8 bytes */
                case 0x10:
                    addr_ipv4 = tvb_get_ipv4(tvb, offset + pf_offset + 1);
                    mask_ipv4 = tvb_get_ipv4(tvb, offset + pf_offset + 5);
                    proto_tree_add_text(ext_tree_tft_pf, tvb, offset + pf_offset, 9, "ID 0x10: IPv4/mask: %s/%s", ip_to_str((guint8 *) & addr_ipv4),
                                        ip_to_str((guint8 *) & mask_ipv4));
                    pf_offset = pf_offset + 9;
                    break;
                    /* address IPv6 and mask = 32 bytes */
                case 0x20:
                    tvb_get_ipv6(tvb, offset + pf_offset + 1, &addr_ipv6);
                    tvb_get_ipv6(tvb, offset + pf_offset + 17, &mask_ipv6);
                    proto_tree_add_text(ext_tree_tft_pf, tvb, offset + pf_offset, 33, "ID 0x20: IPv6/mask: %s/%s",
                                        ip6_to_str((struct e_in6_addr *) &addr_ipv6), ip6_to_str((struct e_in6_addr *) &mask_ipv6));
                    pf_offset = pf_offset + 33;
                    break;
                    /* protocol identifier/next header type = 1 byte */
                case 0x30:
                    proto = tvb_get_guint8(tvb, offset + pf_offset + 1);
                    proto_tree_add_text(ext_tree_tft_pf, tvb, offset + pf_offset, 2, "ID 0x30: IPv4 protocol identifier/IPv6 next header: %u (%x)",
                                        proto, proto);
                    pf_offset = pf_offset + 2;
                    break;
                    /* single destination port type = 2 bytes */
                case 0x40:
                    port1 = tvb_get_ntohs(tvb, offset + pf_offset + 1);
                    proto_tree_add_text(ext_tree_tft_pf, tvb, offset + pf_offset, 3, "ID 0x40: destination port: %u", port1);
                    pf_offset = pf_offset + 3;
                    break;
                    /* destination port range type = 4 bytes */
                case 0x41:
                    port1 = tvb_get_ntohs(tvb, offset + pf_offset + 1);
                    port2 = tvb_get_ntohs(tvb, offset + pf_offset + 3);
                    proto_tree_add_text(ext_tree_tft_pf, tvb, offset + pf_offset, 5, "ID 0x41: destination port range: %u - %u", port1, port2);
                    pf_offset = pf_offset + 5;
                    break;
                    /* single source port type = 2 bytes */
                case 0x50:
                    port1 = tvb_get_ntohs(tvb, offset + pf_offset + 1);
                    proto_tree_add_text(ext_tree_tft_pf, tvb, offset + pf_offset, 3, "ID 0x50: source port: %u", port1);
                    pf_offset = pf_offset + 3;
                    break;
                    /* source port range type = 4 bytes */
                case 0x51:
                    port1 = tvb_get_ntohs(tvb, offset + pf_offset + 1);
                    port2 = tvb_get_ntohs(tvb, offset + pf_offset + 3);
                    proto_tree_add_text(ext_tree_tft_pf, tvb, offset + pf_offset, 5, "ID 0x51: source port range: %u - %u", port1, port2);
                    pf_offset = pf_offset + 5;
                    break;
                    /* security parameter index type = 4 bytes */
                case 0x60:
                    ipsec_id = tvb_get_ntohl(tvb, offset + pf_offset + 1);
                    proto_tree_add_text(ext_tree_tft_pf, tvb, offset + pf_offset, 5, "ID 0x60: security parameter index: %x", ipsec_id);
                    pf_offset = pf_offset + 5;
                    break;
                    /* type of service/traffic class type = 2 bytes */
                case 0x70:
                    tos = tvb_get_ntohs(tvb, offset + pf_offset + 1);
                    proto_tree_add_text(ext_tree_tft_pf, tvb, offset + pf_offset, 2, "ID 0x70: Type of Service/Traffic Class: %u (%x)", tos, tos);
                    pf_offset = pf_offset + 3;
                    break;
                    /* flow label type = 3 bytes */
                case 0x80:
                    label = tvb_get_ntoh24(tvb, offset + pf_offset + 1) & 0x0FFFFF;
                    proto_tree_add_text(ext_tree_tft_pf, tvb, offset + pf_offset, 4, "ID 0x80: Flow Label: %u (%x)", label, label);
                    pf_offset = pf_offset + 4;
                    break;

                default:
                    proto_tree_add_text(ext_tree_tft_pf, tvb, offset + pf_offset, 1, "Unknown value: %x ", pf_content_id);
                    pf_offset++;        /* to avoid infinite loop */
                    break;
                }
            }

            offset = offset + pf_offset;
        }
    }

    return 3 + length;
}

/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.37
 * Type = 138 (Decimal)
 *              25.413(RANAP) TargetID
 */
static int decode_gtp_target_id(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_item *target_id_item;
    proto_tree *ext_tree;
    tvbuff_t *next_tvb;
    asn1_ctx_t asn1_ctx;
    asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);

    length = tvb_get_ntohs(tvb, offset + 1);

    target_id_item = proto_tree_add_text(tree, tvb, offset, 3 + length, "Target Identification");
    ext_tree = proto_item_add_subtree(target_id_item, ett_gtp_target_id);
    offset = offset + 1;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* The Target Identification information element contains the identification of a target RNC. Octets 4-n shall be encoded
     * as the "Target RNC-ID" part of the "Target ID" parameter in 3GPP TS 25.413 [7]. Therefore, the "Choice Target ID"
     * that indicates "Target RNC-ID" (numerical value of 0x20) shall not be included in the "Target RNC-ID" value in octets
     * 4-n.
     */
    next_tvb = tvb_new_subset(tvb, offset, length, length);
    dissect_ranap_TargetRNC_ID(next_tvb, 0, &asn1_ctx, ext_tree, hf_gtp_targetRNC_ID);

    return 3 + length;
}


/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.38
 */
static int decode_gtp_utran_cont(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_item *utran_cont_item;
    proto_tree *ext_tree;
    tvbuff_t *next_tvb;

    length = tvb_get_ntohs(tvb, offset + 1);

    utran_cont_item = proto_tree_add_text(tree, tvb, offset, 3 + length, "UTRAN transparent field");
    ext_tree = proto_item_add_subtree(utran_cont_item, ett_gtp_utran_cont);
    offset = offset + 1;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    next_tvb = tvb_new_subset(tvb, offset, length, length);
    if (data_handle)
        call_dissector(data_handle, next_tvb, pinfo, ext_tree);

    return 3 + length;

}


/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.39
 */
static int decode_gtp_rab_setup(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint32 teid, addr_ipv4;
    guint16 length;
    guint8 nsapi;
    struct e_in6_addr addr_ipv6;
    proto_tree *ext_tree_rab_setup;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    nsapi = tvb_get_guint8(tvb, offset + 3) & 0x0F;

    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "Radio Access Bearer Setup Information");
    ext_tree_rab_setup = proto_item_add_subtree(te, ett_gtp_rab_setup);

    proto_tree_add_text(ext_tree_rab_setup, tvb, offset + 1, 2, "RAB setup length : %u", length);
    proto_tree_add_uint(ext_tree_rab_setup, hf_gtp_nsapi, tvb, offset + 3, 1, nsapi);

    if (length > 1) {

        teid = tvb_get_ntohl(tvb, offset + 4);

        proto_tree_add_uint(ext_tree_rab_setup, hf_gtp_teid_data, tvb, offset + 4, 4, teid);

        switch (length) {
        case 12:
            addr_ipv4 = tvb_get_ipv4(tvb, offset + 8);
            proto_tree_add_ipv4(ext_tree_rab_setup, hf_gtp_rnc_ipv4, tvb, offset + 8, 4, addr_ipv4);
            break;
        case 24:
            tvb_get_ipv6(tvb, offset + 8, &addr_ipv6);
            proto_tree_add_ipv6(ext_tree_rab_setup, hf_gtp_rnc_ipv6, tvb, offset + 8, 16, (guint8 *) & addr_ipv6);
            break;
        default:
            break;
        }
    }

    return 3 + length;
}


/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.40
 */
static int decode_gtp_hdr_list(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    int i;
    guint8 length, hdr;
    proto_tree *ext_tree_hdr_list;
    proto_item *te;

    length = tvb_get_guint8(tvb, offset + 1);

    te = proto_tree_add_text(tree, tvb, offset, 2 + length, "%s", val_to_str_ext_const(GTP_EXT_HDR_LIST, &gtp_val_ext, "Unknown"));
    ext_tree_hdr_list = proto_item_add_subtree(te, ett_gtp_hdr_list);

    proto_tree_add_text(ext_tree_hdr_list, tvb, offset + 1, 1, "Number of Extension Header Types in list (i.e., length) : %u", length);

    for (i = 0; i < length; i++) {
        hdr = tvb_get_guint8(tvb, offset + 2 + i);

        proto_tree_add_text(ext_tree_hdr_list, tvb, offset + 2 + i, 1, "No. %u --> Extension Header Type value : %s (%u)", i + 1,
                            val_to_str_ext_const(hdr, &gtp_val_ext, "Unknown Extension Header Type"), hdr);
    }

    return 2 + length;
}

/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.41
 * TODO:        find TriggerID description
 */
static int decode_gtp_trigger_id(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;

    length = tvb_get_ntohs(tvb, offset + 1);

    proto_tree_add_text(tree, tvb, offset, 3 + length, "%s length : %u", val_to_str_ext_const(GTP_EXT_TRIGGER_ID, &gtp_val_ext, "Unknown"), length);

    return 3 + length;

}

/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.42
 * TODO:        find OMC-ID description
 */
static int decode_gtp_omc_id(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;

    length = tvb_get_ntohs(tvb, offset + 1);

    proto_tree_add_text(tree, tvb, offset, 3 + length, "%s length : %u", val_to_str_ext_const(GTP_EXT_OMC_ID, &gtp_val_ext, "Unknown"), length);

    return 3 + length;

}

/* GPRS:        9.60 v7.6.0, chapter 7.9.25
 * UMTS:        29.060 v6.11.0, chapter 7.7.44 Charging Gateway Address
 */
static int decode_gtp_chrg_addr(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    guint32 addr_ipv4;
    struct e_in6_addr addr_ipv6;
    proto_tree *ext_tree_chrg_addr;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);

    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s : ", val_to_str_ext_const(GTP_EXT_CHRG_ADDR, &gtp_val_ext, "Unknown"));
    ext_tree_chrg_addr = proto_item_add_subtree(te, ett_gtp_chrg_addr);

    proto_tree_add_text(ext_tree_chrg_addr, tvb, offset + 1, 2, "%s length : %u", val_to_str_ext_const(GTP_EXT_CHRG_ADDR, &gtp_val_ext, "Unknown"), length);

    switch (length) {
    case 4:
        addr_ipv4 = tvb_get_ipv4(tvb, offset + 3);
        proto_item_append_text(te, "%s", ip_to_str((guint8 *) & addr_ipv4));
        proto_tree_add_ipv4(ext_tree_chrg_addr, hf_gtp_chrg_ipv4, tvb, offset + 3, 4, addr_ipv4);
        break;
    case 16:
        tvb_get_ipv6(tvb, offset + 3, &addr_ipv6);
        proto_item_append_text(te, "%s", ip6_to_str((struct e_in6_addr *) &addr_ipv6));
        proto_tree_add_ipv6(ext_tree_chrg_addr, hf_gtp_chrg_ipv6, tvb, offset + 3, 16, (guint8 *) & addr_ipv6);
        break;
    default:
        proto_item_append_text(te, "unknown type or wrong length");
        break;
    }

    return 3 + length;
}

/* GPRS:        ?
 * UMTS:        29.060 V9.4.0, chapter 7.7.43 RAN Transparent Container
 * The information in the value part of the RAN Transparent Container IE contains all information elements (starting with
 * and including the BSSGP "PDU Type") in either of the RAN INFORMATION, RAN INFORMATION REQUEST,
 * RAN INFORMATION ACK or RAN INFORMATION ERROR messages respectively as specified in 3GPP TS 48.018
 */
static int decode_gtp_ran_tr_cont(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;
    tvbuff_t    *next_tvb;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s : ", val_to_str_ext_const(GTP_EXT_RAN_TR_CONT, &gtp_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_ran_tr_cont);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    next_tvb = tvb_new_subset(tvb, offset, length, length);
    if (bssgp_handle){
        col_set_fence(pinfo->cinfo, COL_INFO); 
        call_dissector(bssgp_handle, next_tvb, pinfo, ext_tree);
    }

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.45 PDP Context Prioritization
 */
static int decode_gtp_pdp_cont_prio(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s : ", val_to_str_ext_const(GTP_EXT_PDP_CONT_PRIO, &gtp_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_pdp_cont_prio);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* TODO add decoding of data */
    proto_tree_add_text(ext_tree, tvb, offset, length, "Data not decoded yet");

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.45A Additional RAB Setup Information
 */
static int decode_gtp_add_rab_setup_inf(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s : ", val_to_str_ext_const(GTP_EXT_ADD_RAB_SETUP_INF, &gtp_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_rab_setup_inf);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* TODO add decoding of data */
    proto_tree_add_text(ext_tree, tvb, offset, length, "Data not decoded yet");

    return 3 + length;

}


 /* GPRS:       ?
  * UMTS:       29.060 v6.11.0, chapter 7.7.47 SGSN Number
  */
static int decode_gtp_ssgn_no(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s : ", val_to_str_ext_const(GTP_EXT_SSGN_NO, &gtp_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_ssgn_no);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* TODO add decoding of data */
    proto_tree_add_text(ext_tree, tvb, offset, length, "Data not decoded yet");

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        3GPP TS 29.060 version 7.8.0 Release 7, chapter 7.7.48 Common Flags
 */
static int decode_gtp_common_flgs(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s : ", val_to_str_ext_const(GTP_EXT_COMMON_FLGS, &gtp_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_common_flgs);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* Upgrade QoS Supported */
    proto_tree_add_item(ext_tree, hf_gtp_cmn_flg_upgrd_qos_sup, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* NRSN bit field */
    proto_tree_add_item(ext_tree, hf_gtp_cmn_flg_nrsn, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* No QoS negotiation */
    proto_tree_add_item(ext_tree, hf_gtp_cmn_flg_no_qos_neg, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* MBMS Counting Information bi */
    proto_tree_add_item(ext_tree, hf_gtp_cmn_flg_mbs_cnt_inf, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* RAN Procedures Ready */
    proto_tree_add_item(ext_tree, hf_gtp_cmn_flg_mbs_ran_pcd_rdy, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* MBMS Service Type */
    proto_tree_add_item(ext_tree, hf_gtp_cmn_flg_mbs_srv_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* Prohibit Payload Compression */
    proto_tree_add_item(ext_tree, hf_gtp_cmn_flg_ppc, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.49
 */
static int decode_gtp_apn_res(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree_apn_res;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s : ", val_to_str_ext_const(GTP_EXT_APN_RES, &gtp_val_ext, "Unknown"));
    ext_tree_apn_res = proto_item_add_subtree(te, ett_gtp_ext_tree_apn_res);

    offset++;
    proto_tree_add_item(ext_tree_apn_res, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    /* Restriction Type value */
    if (length != 1) {
        proto_item *expert_item;
        expert_item = proto_tree_add_text(tree, tvb, 0, length, "Wrong length indicated. Expected 1, got %u", length);
        expert_add_info_format(pinfo, expert_item, PI_MALFORMED, PI_ERROR, "Wrong length indicated. Expected 1, got %u", length);
        PROTO_ITEM_SET_GENERATED(expert_item);
        return 3 + length;
    }

    proto_tree_add_item(ext_tree_apn_res, hf_gtp_ext_apn_res, tvb, offset, length, ENC_BIG_ENDIAN);
    return 3 + length;
}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.50 RAT Type
 * RAT Type
 * Type = 151 (Decimal)
 */

static int decode_gtp_rat_type(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree_rat_type;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_RAT_TYPE, &gtp_val_ext, "Unknown"));
    ext_tree_rat_type = proto_item_add_subtree(te, ett_gtp_ext_rat_type);

    offset++;
    proto_tree_add_item(ext_tree_rat_type, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    /* RAT Type value */
    if (length != 1) {
        proto_item *expert_item;
        expert_item = proto_tree_add_text(tree, tvb, 0, length, "Wrong length indicated. Expected 1, got %u", length);
        expert_add_info_format(pinfo, expert_item, PI_MALFORMED, PI_ERROR, "Wrong length indicated. Expected 1, got %u", length);
        PROTO_ITEM_SET_GENERATED(expert_item);
        return 3 + length;
    }

   proto_tree_add_item(ext_tree_rat_type, hf_gtp_ext_rat_type, tvb, offset, length, ENC_BIG_ENDIAN);
   proto_item_append_text(te, ": %s", val_to_str_const(tvb_get_guint8(tvb,offset), gtp_ext_rat_type_vals, "Unknown"));

   return 3 + length;
}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.51
 * User Location Information
 * Type = 152 (Decimal)
 */

static const gchar *dissect_radius_user_loc(proto_tree * tree, tvbuff_t * tvb, packet_info* pinfo)
{

    int offset = 0;
    guint8 geo_loc_type;
    guint16 length = tvb_length(tvb);

    /* Geographic Location Type */
    proto_tree_add_item(tree, hf_gtp_ext_geo_loc_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    geo_loc_type = tvb_get_guint8(tvb, offset);
    offset++;

    if (geo_loc_type == 0)
        /* Use gsm_a's function to dissect Geographic Location by faking disc ( last 0) */
        be_cell_id_aux(tvb, tree, pinfo, offset, length - 1, NULL, 0, 0);
    if (geo_loc_type == 1) {
        /* Use gsm_a's function to dissect Geographic Location by faking disc ( last 4) */
        be_cell_id_aux(tvb, tree, pinfo, offset, length - 1, NULL, 0, 4);
        offset = offset + 5;
        proto_tree_add_item(tree, hf_gtp_ext_sac, tvb, offset, 2, ENC_BIG_ENDIAN);
    }


    return tvb_bytes_to_str(tvb, 0, length);
}

/*
 * 7.7.51 User Location Information
 */

static int decode_gtp_usr_loc_inf(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree, *rai_tree;
    proto_item *te, *fi;
    guint8 geo_loc_type;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_USR_LOC_INF, &gtp_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_usr_loc_inf);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* TODO add decoding of data */
    /* Geographic Location Type */
    proto_tree_add_item(ext_tree, hf_gtp_ext_geo_loc_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    geo_loc_type = tvb_get_guint8(tvb, offset);
    offset++;

	switch(geo_loc_type){
		case 0:
			/* Geographic Location field included and it holds the Cell Global
			 * Identification (CGI) of where the user currently is registered.
			 * CGI is defined in sub-clause 4.3.1 of 3GPP TS 23.003 [2].
			 */
            /* Use gsm_a's function to dissect Geographic Location by faking disc ( last 0) */
            be_cell_id_aux(tvb, ext_tree, pinfo, offset, length - 1, NULL, 0, 0);
			break;
		case 1:
			/* Geographic Location field included and it holds the Service
			 * Area Identity (SAI) of where the user currently is registered.
			 * SAI is defined in sub-clause 9.2.3.9 of 3GPP TS 25.413 [7].
			 */
            /* Use gsm_a's function to dissect Geographic Location by faking disc ( last 4) */
            be_cell_id_aux(tvb, ext_tree, pinfo, offset, length - 1, NULL, 0, 4);
            offset = offset + 5;
            proto_tree_add_item(ext_tree, hf_gtp_ext_sac, tvb, offset, 2, ENC_BIG_ENDIAN);
			break;
		case 2:
			/* Geographic Location field included and it holds the Routing
			 * Area Identification (RAI) of where the user currently is
			 * registered. RAI is defined in sub-clause 4.2 of 3GPP TS 23.003
			 * [2].
			 */
            fi = proto_tree_add_text(ext_tree, tvb, offset + 1, 7, "Routeing Area Identity (RAI)");
            rai_tree = proto_item_add_subtree(fi, ett_gtp_uli_rai);

			dissect_e212_mcc_mnc(tvb, pinfo, rai_tree, offset, TRUE);
            offset+=3;
            proto_tree_add_item(rai_tree, hf_gtp_rai_lac, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(rai_tree, hf_gtp_rai_rac, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset+=4;
			break;
		default:
			proto_tree_add_text(tree, tvb, offset, length - 1, "Unknown Location type data");
			break;
	}

    return 3 + length;

}

static const value_string daylight_saving_time_vals[] = {
    {0, "No adjustment"},
    {1, "+1 hour adjustment for Daylight Saving Time"},
    {2, "+2 hours adjustment for Daylight Saving Time"},
    {3, "Reserved"},
    {0, NULL}
};

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.52
 * MS Time Zone
 * Type = 153 (Decimal)
 * The ' MS Time Zone' IE is used to indicate the offset between universal time and local time
 * in steps of 15 minutes of where the MS currently resides. The 'Time Zone' field uses the same
 * format as the 'Time Zone' IE in 3GPP TS 24.008 (10.5.3.8)
 * its value shall be set as defined in 3GPP TS 22.042
 */
static int decode_gtp_ms_time_zone(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;
    guint8 data;
    char sign;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s: ", val_to_str_ext_const(GTP_EXT_MS_TIME_ZONE, &gtp_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_ms_time_zone);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    /* 3GPP TS 23.040 version 6.6.0 Release 6
     * 9.2.3.11 TP-Service-Centre-Time-Stamp (TP-SCTS)
     * :
     * The Time Zone indicates the difference, expressed in quarters of an hour,
     * between the local time and GMT. In the first of the two semi-octets,
     * the first bit (bit 3 of the seventh octet of the TP-Service-Centre-Time-Stamp field)
     * represents the algebraic sign of this difference (0: positive, 1: negative).
     */

    data = tvb_get_guint8(tvb, offset);
    sign = (data & 0x08) ? '-' : '+';
    data = (data >> 4) + (data & 0x07) * 10;

    proto_tree_add_text(ext_tree, tvb, offset, 1, "Timezone: GMT %c %d hours %d minutes", sign, data / 4, data % 4 * 15);
    proto_item_append_text(te, "GMT %c %d hours %d minutes", sign, data / 4, data % 4 * 15);
    offset++;

    data = tvb_get_guint8(tvb, offset) & 0x3;
    proto_tree_add_text(ext_tree, tvb, offset, 1, "%s", val_to_str_const(data, daylight_saving_time_vals, "Unknown"));

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.53
 * International Mobile Equipment Identity (and Software Version) (IMEI(SV))
 * Type = 154 (Decimal)
 */
static int decode_gtp_imeisv(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_imeisv;
    proto_item *te;
    tvbuff_t *next_tvb;
    const char *digit_str;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_IMEISV, &gtp_val_ext, "Unknown"));
    ext_imeisv = proto_item_add_subtree(te, ett_gtp_ext_imeisv);

    offset++;
    proto_tree_add_item(ext_imeisv, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    /* IMEI(SV)
     * The structure of the IMEI and IMEISV are defined in sub-clause 6.2 of 3GPP TS 23.003 [2].
     * The 'IMEI(SV)' field shall contain the IMEISV if it is available. If only the IMEI is available,
     * then the IMEI shall be placed in the IMEI(SV) field and the last semi-octet of octet 11 shall be
     * set to '1111'. Both IMEI and IMEISV are BCD encoded.
     */
    next_tvb = tvb_new_subset(tvb, offset, length, length);
    digit_str = unpack_digits(next_tvb, 0);
    proto_tree_add_string(ext_imeisv, hf_gtp_ext_imeisv, next_tvb, 0, -1, digit_str);
    proto_item_append_text(te, ": %s", digit_str);

    return 3 + length;
}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.54
 * CAMEL Charging Information Container
 * Type = 155 (Decimal)
 */
static int decode_gtp_camel_chg_inf_con(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_CAMEL_CHG_INF_CON, &gtp_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_camel_chg_inf_con);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* TODO add decoding of data */
    proto_tree_add_text(ext_tree, tvb, offset, length, "Data not decoded yet");

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.55
 * MBMS UE Context
 */
static int decode_gtp_mbms_ue_ctx(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_MBMS_UE_CTX, &gtp_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_GTP_EXT_MBMS_UE_CTX);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* TODO add decoding of data */
    proto_tree_add_text(ext_tree, tvb, offset, length, "Data not decoded yet");

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        3GPP TS 29.060 version 7.8.0 Release 7, chapter 7.7.56
 * Temporary Mobile Group Identity (TMGI)
 * The Temporary Mobile Group Identity (TMGI) information element contains
 * a TMGI allocated by the BM-SC. It is coded as in the value part defined
 * in 3GPP T S 24.008 [5] (i.e. the IEI and octet length indicator are not included).
 */

static int decode_gtp_tmgi(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree, *tmgi_tree;
    proto_item *te, *ti;
    tvbuff_t *next_tvb;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_TMGI, &gtp_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_tmgi);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    ti = proto_tree_add_item(ext_tree, hf_gtp_tmgi, tvb, offset, length, ENC_NA);

    tmgi_tree = proto_item_add_subtree(ti, ett_gtp_tmgi);
    next_tvb = tvb_new_subset(tvb, offset, length, length);
    de_mid(next_tvb, tmgi_tree, pinfo, 0, length, NULL, 0);
    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.57
 * RIM Routing Address
 */
static int decode_gtp_rim_ra(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_RIM_RA, &gtp_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_rim_ra);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* To dissect the Address the Routing Address discriminator must be known */
    /*
     * Octets 4-n are coded according to 3GPP TS 48.018 [20] 11.3.77 RIM Routing Information IE octets 4-n.
     */
	proto_tree_add_item(ext_tree, hf_gtp_rim_routing_addr, tvb, offset, length, ENC_BIG_ENDIAN);

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.58
 * MBMS Protocol Configuration Options
 */
static int decode_gtp_mbms_prot_conf_opt(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_MBMS_PROT_CONF_OPT, &gtp_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_mbms_prot_conf_opt);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* TODO add decoding of data */
    proto_tree_add_text(ext_tree, tvb, offset, length, "Data not decoded yet");

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        3GPP TS 29.060 version 7.8.0 Release 7, chapter 7.7.59
 * MBMS Session Duration
 */
/* Used for Diameter */
static int dissect_gtp_mbms_ses_dur(tvbuff_t * tvb _U_, packet_info * pinfo _U_, proto_tree * tree _U_)
{

    int offset = 0;

    proto_tree_add_item(tree, hf_gtp_mbms_ses_dur_days, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtp_mbms_ses_dur_s, tvb, offset, 3, ENC_BIG_ENDIAN);

    return 3;

}

static int decode_gtp_mbms_ses_dur(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_MBMS_SES_DUR, &gtp_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_bms_ses_dur);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* The MBMS Session Duration is defined in 3GPP TS 23.246 [26].
     * The MBMS Session Duration information element indicates the estimated
     * session duration of the MBMS service data transmission if available.
     * The payload shall be encoded as per the MBMS-Session-Duration AVP defined
     * in 3GPP TS 29.061 [27], excluding the AVP Header fields
     * (as defined in IETF RFC 3588 [36], section 4.1).
     */
    /* The MBMS-Session-Duration AVP (AVP code 904) is of type OctetString
     * with a length of three octets and indicates the estimated session duration
     * (MBMS Service data transmission). Bits 0 to 16 (17 bits) express seconds, for which the
     * maximum allowed value is 86400 seconds. Bits 17 to 23 (7 bits) express days,
     * for which the maximum allowed value is 18 days. For the whole session duration the seconds
     * and days are added together and the maximum session duration is 19 days.
     */
    proto_tree_add_item(ext_tree, hf_gtp_mbms_ses_dur_days, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree, hf_gtp_mbms_ses_dur_s, tvb, offset, 3, ENC_BIG_ENDIAN);

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        3GPP TS 29.060 version 7.8.0 Release 7, chapter 7.7.60
 * MBMS Service Area
 */
static int
dissect_gtp_3gpp_mbms_service_area(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {

    int offset = 0;
    guint8 no_of_mbms_sa_codes;
    int i;

    /* The MBMS Service Area is defined in 3GPP TS 23.246 [26].
     * The MBMS Service Area information element indicates the area over
     * which the Multimedia Broadcast/Multicast Service is to be distributed.
     * The payload shall be encoded as per the MBMS-Service-Area AVP defined
     * in 3GPP TS 29.061 [27], excluding the AVP Header fields (as defined in
     * IETF RFC 3588 [36], section 4.1).
     */
    /* Number N of MBMS service area codes coded as:
     * 1 binary value is '00000000'
     * ... ...
     * 256 binary value is '11111111'
     */
    no_of_mbms_sa_codes = tvb_get_guint8(tvb, offset) + 1;
    proto_tree_add_uint(tree, hf_gtp_no_of_mbms_sa_codes, tvb, offset, 1, no_of_mbms_sa_codes);
    offset++;
    /* A consecutive list of N MBMS service area codes
     * The MBMS Service Area Identity and its semantics are defined in 3GPP TS 23.003
     * The length of an MBMS service area code is 2 octets.
     */
    for (i = 0; i < no_of_mbms_sa_codes; i++) {
        proto_tree_add_item(tree, hf_gtp_mbms_sa_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset = offset + 2;
    }

    return offset;
}

static int decode_gtp_mbms_sa(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    tvbuff_t *next_tvb;
    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_MBMS_SA, &gtp_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_mbms_sa);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    next_tvb = tvb_new_subset(tvb, offset, length-3, length-3);
    dissect_gtp_3gpp_mbms_service_area(next_tvb, pinfo,ext_tree);

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.61
 * Source RNC PDCP context info
 */
static int decode_gtp_src_rnc_pdp_ctx_inf(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_SRC_RNC_PDP_CTX_INF, &gtp_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_src_rnc_pdp_ctx_inf);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* TODO add decoding of data */
    proto_tree_add_text(ext_tree, tvb, offset, length, "Data not decoded yet");

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.62
 * Additional Trace Info
 */
static int decode_gtp_add_trs_inf(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_ADD_TRS_INF, &gtp_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_add_trs_inf);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* TODO add decoding of data */
    proto_tree_add_text(ext_tree, tvb, offset, length, "Data not decoded yet");

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.63
 * Hop Counter
 */
static int decode_gtp_hop_count(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_HOP_COUNT, &gtp_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_hop_count);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* TODO add decoding of data */
    proto_tree_add_text(ext_tree, tvb, offset, length, "Data not decoded yet");

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.64
 * Selected PLMN ID
 */
static int decode_gtp_sel_plmn_id(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_SEL_PLMN_ID, &gtp_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_sel_plmn_id);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* TODO add decoding of data */
    proto_tree_add_text(ext_tree, tvb, offset, length, "Data not decoded yet");

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.65
 * MBMS Session Identifier
 */
static int decode_gtp_mbms_ses_id(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_MBMS_SES_ID, &gtp_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_mbms_ses_id);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* TODO add decoding of data */
    proto_tree_add_text(ext_tree, tvb, offset, length, "Data not decoded yet");

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.66
 * MBMS 2G/3G Indicator
 */
static const value_string gtp_mbs_2g_3g_ind_vals[] = {
    {0, "2G only"},
    {1, "3G only"},
    {2, "Both 2G and 3G"},
    {0, NULL}
};

static int decode_gtp_mbms_2g_3g_ind(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_MBMS_2G_3G_IND, &gtp_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_mbms_2g_3g_ind);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* MBMS 2G/3G Indicator */
    proto_tree_add_item(ext_tree, hf_gtp_mbs_2g_3g_ind, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.67
 * Enhanced NSAPI
 */
static int decode_gtp_enh_nsapi(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_ENH_NSAPI, &gtpv1_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_enh_nsapi);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* TODO add decoding of data */
    proto_tree_add_text(ext_tree, tvb, offset, length, "Data not decoded yet");

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.68
 * Additional MBMS Trace Info
 */
static int decode_gtp_add_mbms_trs_inf(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_ADD_MBMS_TRS_INF, &gtpv1_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_ad_mbms_trs_inf);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* TODO add decoding of data */
    proto_tree_add_text(ext_tree, tvb, offset, length, "Data not decoded yet");

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.69
 * MBMS Session Identity Repetition Number
 */
static int decode_gtp_mbms_ses_id_rep_no(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_MBMS_SES_ID_REP_NO, &gtpv1_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_mbms_ses_id_rep_no);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* TODO add decoding of data */
    proto_tree_add_text(ext_tree, tvb, offset, length, "Data not decoded yet");

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        3GPP TS 29.060 version 7.8.0 Release 7
 * MBMS Time To Data Transfer
 */
/* Used for Diameter */
static int dissect_gtp_mbms_time_to_data_tr(tvbuff_t * tvb _U_, packet_info * pinfo _U_, proto_tree * tree _U_)
{

    int offset = 0;
    guint8 time_2_dta_tr;

    time_2_dta_tr = tvb_get_guint8(tvb, offset) + 1;
    proto_tree_add_uint(tree, hf_gtp_time_2_dta_tr, tvb, offset, 1, time_2_dta_tr);

    return 3;

}

static int decode_gtp_mbms_time_to_data_tr(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;
    guint8 time_2_dta_tr;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_MBMS_TIME_TO_DATA_TR, &gtpv1_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_mbms_time_to_data_tr);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* TODO add decoding of data
     * The MBMS Time To Data Transfer is defined in 3GPP TS 23.246 [26].
     * The MBMS Time To Data Transfer information element contains a
     * MBMS Time To Data Transfer allocated by the BM-SC.
     * The payload shall be encoded as per the MBMS-Time-To-Data-Transfer AVP
     * defined in 3GPP TS 29.061 [27], excluding the AVP Header fields
     * (as defined in IETF RFC 3588 [36], section 4.1).
     */
    /* The coding is specified as per the Time to MBMS Data Transfer Value Part Coding
     * of the Time to MBMS Data Transfer IE in 3GPP TS 48.018
     * Bits
     * 8 7 6 5 4 3 2 1
     * 0 0 0 0 0 0 0 0 1s
     * 0 0 0 0 0 0 0 1 2s
     * 0 0 0 0 0 0 1 0 3s
     * :
     * 1 1 1 1 1 1 1 1 256s
     */
    time_2_dta_tr = tvb_get_guint8(tvb, offset) + 1;
    proto_tree_add_uint(ext_tree, hf_gtp_time_2_dta_tr, tvb, offset, 1, time_2_dta_tr);

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.71
 * PS Handover Request Context
 */
static int
decode_gtp_ps_ho_req_ctx(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_PS_HO_REQ_CTX, &gtpv1_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_ps_ho_req_ctx);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* TODO add decoding of data */
    proto_tree_add_text(ext_tree, tvb, offset, length, "Data not decoded yet");

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.72
 * BSS Container
 */
static int
decode_gtp_bss_cont(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_BSS_CONT, &gtpv1_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_bss_cont);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* TODO add decoding of data */
    proto_tree_add_text(ext_tree, tvb, offset, length, "Data not decoded yet");
    /*
     * The content of this container is defined in 3GPP TS 48.018
     */

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.73
 * Cell Identification
 */
static int
decode_gtp_cell_id(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_CELL_ID, &gtpv1_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_cell_id);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* TODO add decoding of data */
    proto_tree_add_text(ext_tree, tvb, offset, length, "Data not decoded yet");
    /*
     * for PS handover from A/Gb mode, the identification of a target cell (Cell ID 1) and the identification of the
     * source cell (Cell ID 2) as defined in 3GPP TS 48.018 [20].
     *
     * for PS handover from Iu mode, the identification of a target cell (Cell ID 1)) and the identification of the
     * source RNC (RNC-ID) as defined in 3GPP TS 48.018
     */

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.74
 * PDU Numbers
 */
static int
decode_gtp_pdu_no(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_PDU_NO, &gtpv1_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_pdu_no);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* TODO add decoding of data */
    proto_tree_add_text(ext_tree, tvb, offset, length, "Data not decoded yet");

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.75
 * BSSGP Cause
 */
static int
decode_gtp_bssgp_cause(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_BSSGP_CAUSE, &gtpv1_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_bssgp_cause);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    /*
     * The BSSGP Cause information element contains the cause as defined in 3GPP TS 48.018
     */
    proto_tree_add_item(ext_tree, hf_gtp_bssgp_cause, tvb, offset, 2, ENC_BIG_ENDIAN);

    return 3 + length;

}

/*
 * Required MBMS bearer capabilities    7.7.76
 */
static int
decode_gtp_mbms_bearer_cap(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{
    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_BSSGP_CAUSE, &gtpv1_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_bssgp_cause);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
#if 0 /* Fix Dead Store Warning */
    offset = offset + 2;
#endif
    /* The payload shall be encoded as per the
     * Required-MBMS-Bearer-Capabilities AVP defined in 3GPP TS 29.061 [27],
     * excluding the AVP Header fields (as defined in IETF RFC 3588 [36], section 4.1).
     */
    /* TODO Add decoding (call Diameter dissector???) */
        return 3 + length;
}

/*
 * RIM Routing Address Discriminator    7.7.77
 */

static const value_string gtp_bssgp_ra_discriminator_vals[] = {
    { 0, "A Cell Identifier is used to identify a GERAN cell" },
    { 1, "A Global RNC-ID is used to identify a UTRAN RNC" },
    { 2, "An eNB identifier is used to identify an E-UTRAN eNodeB or HeNB" },
    { 0, NULL },
};

static int
decode_gtp_rim_ra_disc(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_RIM_ROUTING_ADDR_DISC, &gtpv1_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_pdu_no);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* Octet 4 bits 4 - 1 is coded according to 3GPP TS 48.018 [20] 
     * RIM Routing Information IE octet 3 bits 4 - 1.
     * Bits 8 - 5 are coded "0000".
     */
    proto_tree_add_item(ext_tree, hf_gtp_bssgp_ra_discriminator, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 3 + length;

}
/*
 * List of set-up PFCs  7.7.78
 */
static int
decode_gtp_lst_set_up_pfc(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_LIST_OF_SETUP_PFCS, &gtpv1_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_pdu_no);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* TODO add decoding of data */
    proto_tree_add_text(ext_tree, tvb, offset, length, "Data not decoded yet");

    return 3 + length;

}
/*
 * PS Handover XID Parameters   7.7.79
 */
static int decode_gtp_ps_handover_xid(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;
    tvbuff_t *next_tvb;
    guint8 sapi;
    guint8 xid_par_len;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_PS_HANDOVER_XIP_PAR, &gtpv1_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_ps_handover_xid);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    sapi = tvb_get_guint8(tvb, offset) & 0x0F;
    proto_tree_add_uint(ext_tree, hf_gtp_sapi, tvb, offset, 1, sapi);
    offset++;

    xid_par_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(ext_tree, hf_gtp_xid_par_len, tvb, offset, 1, xid_par_len);
    offset++;

    if (sndcpxid_handle) {
        next_tvb = tvb_new_subset_remaining(tvb, offset);
        call_dissector(sndcpxid_handle, next_tvb, pinfo, tree);
    } else
        proto_tree_add_text(tree, tvb, offset, 0, "Data");

    return 4 + length;

}

/*
 * MS Info Change Reporting Action      7.7.80
 */
static int decode_gtp_ms_inf_chg_rep_act(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_MS_INF_CHG_REP_ACT, &gtpv1_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_pdu_no);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* TODO add decoding of data */
    proto_tree_add_text(ext_tree, tvb, offset, length, "Data not decoded yet");

    return 3 + length;

}
/*
 * Direct Tunnel Flags  7.7.81
 */
static int decode_gtp_direct_tnl_flg(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_DIRECT_TUNNEL_FLGS, &gtpv1_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_pdu_no);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* TODO add decoding of data */
    proto_tree_add_text(ext_tree, tvb, offset, length, "Data not decoded yet");
    proto_tree_add_item(ext_tree, hf_gtp_ext_ei, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree, hf_gtp_ext_gcsi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree, hf_gtp_ext_dti, tvb, offset, 1, ENC_BIG_ENDIAN);
#if 0 /* Fix Dead Store Warning */
    offset++;
#endif
    return 3 + length;

}
/*
 * Correlation-ID       7.7.82
 */
static int decode_gtp_corrl_id(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_CORRELATION_ID, &gtpv1_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_pdu_no);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* TODO add decoding of data */
    proto_tree_add_text(ext_tree, tvb, offset, length, "Data not decoded yet");

    return 3 + length;

}
/*
 * Bearer Control Mode  7.7.83
 * version 10.0.0
 */
static const value_string gtp_pdp_bcm_type_vals[] = {
    {0, "MS_only"},
    {1, "MS/NW"},
    {0, NULL}
};

static int decode_gtp_bearer_cntrl_mod(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_BEARER_CONTROL_MODE, &gtpv1_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_bcm);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    proto_tree_add_item(ext_tree, hf_gtp_bcm, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 3 + length;

}

/*
 * 7.7.91 Evolved Allocation/Retention Priority I
 */
static int decode_gtp_evolved_allc_rtn_p1(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    proto_tree *ext_tree;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "%s", val_to_str_ext_const(GTP_EXT_EVO_ALLO_RETE_P1, &gtpv1_val_ext, "Unknown"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext_pdu_no);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    proto_tree_add_item(ext_tree, hf_gtp_earp_pvi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree, hf_gtp_earp_pl, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree, hf_gtp_earp_pci, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 3 + length;


}
/* GPRS:        12.15
 * UMTS:        33.015
 */
static int decode_gtp_rel_pack(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length, n, number;
    proto_tree *ext_tree_rel_pack;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);

    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "Sequence numbers of released packets IE");
    ext_tree_rel_pack = proto_item_add_subtree(te, ett_gtp_rel_pack);

    n = 0;

    while (n < length) {

        number = tvb_get_ntohs(tvb, offset + 3 + n);
        proto_tree_add_text(ext_tree_rel_pack, tvb, offset + 3 + n, 2, "%u", number);
        n = n + 2;

    }

    return 3 + length;
}

/* GPRS:        12.15
 * UMTS:        33.015
 */
static int decode_gtp_can_pack(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length, n, number;
    proto_tree *ext_tree_can_pack;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);

    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "Sequence numbers of cancelled  packets IE");
    ext_tree_can_pack = proto_item_add_subtree(te, ett_gtp_can_pack);

    n = 0;

    while (n < length) {

        number = tvb_get_ntohs(tvb, offset + 3 + n);
        proto_tree_add_text(ext_tree_can_pack, tvb, offset + 3 + n, 2, "%u", number);
        n = n + 2;
    }

    return 3 + length;
}

/* CDRs dissector
 * 3GPP TS 32.295 version 9.0.0 Release 9
 */


static const value_string gtp_cdr_fmt_vals[] = {
    {1, "Basic Encoding Rules (BER)"},
    {2, "Unaligned basic Packed Encoding Rules (PER)"},
    {3, "Aligned basic Packed Encoding Rules (PER)"},
    {0, NULL}
};
static int decode_gtp_data_req(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length, cdr_length;
    guint8 no, format, app_id, rel_id, ver_id, i;
    proto_tree *ext_tree, *ver_tree, *cdr_dr_tree;
    proto_item *te, *fmt_item, *ver_item;
    tvbuff_t *next_tvb;

    te = proto_tree_add_text(tree, tvb, offset, 1, "%s", val_to_str_ext_const(GTP_EXT_DATA_REQ, &gtp_val_ext, "Unknown message"));
    ext_tree = proto_item_add_subtree(te, ett_gtp_ext);
    offset++;

    length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(ext_tree, tvb, offset, 2, "Length: %u", length);
    offset+=2;

    /* Octet 4 Number of Data Records */
    no = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(ext_tree, tvb, offset, 1, "Number of data records: %u", no);
    offset++;

    /* Octet 5 Data Record Format */
    format = tvb_get_guint8(tvb, offset);
    fmt_item = proto_tree_add_text(ext_tree, tvb, offset, 1, "Data record format: %u", format);
    offset++;
    /* The value range is 1-255 in decimal. The value '0' should not be used.
     * Only the values 1-10 and 51-255 can be used for standards purposes.
     * Values in the range of 11-50 are to be configured only by operators, and are not subject to standardization.
     */
    if(format<4){
        proto_item_append_text(fmt_item, " %s", val_to_str_const(format, gtp_cdr_fmt_vals, "Unknown"));
        /* Octet 6 -7  Data Record Format Version
         *    8 7 6 5             4 3 2 1
         * 6 Application Identifier Release Identifier
         * 7 Version Identifier
         */
        app_id = tvb_get_guint8(tvb,offset);
        rel_id = app_id & 0x0f;
        app_id = app_id >>4;
        ver_id =tvb_get_guint8(tvb,offset+1);
        /* The second octet (#7 in Data Record Packet IE) identifies the version of the TS used to encode the CDR,
         * i.e. its value corresponds to the second digit of the version number of the document [51]
         * (as shown on the cover sheet), plus '1'.
         * E.g. for version 3.4.0, the Version Identifier would be "5".
         * In circumstances where the second digit is an alphabetical character, (e.g. 3.b.0), the corresponding ASCII value shall
         * be taken, e.g. the Version Identifier would be "66" (ASCII(b)).
         */
        if(ver_id<0x65)
            ver_id = ver_id -1;
        /* XXX We don't handle ASCCI version */

        ver_item = proto_tree_add_text(ext_tree, tvb, offset, 2, "Data record format version: AppId %u Rel %u.%u.0", app_id,rel_id,ver_id);
        ver_tree = proto_item_add_subtree(ver_item, ett_gtp_cdr_ver);
        proto_tree_add_item(ver_tree, hf_gtp_cdr_app, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ver_tree, hf_gtp_cdr_rel, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(ver_tree, hf_gtp_cdr_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        for(i = 0; i < no; ++i) {
            cdr_length = tvb_get_ntohs(tvb, offset);
            te = proto_tree_add_text(ext_tree, tvb, offset, cdr_length+2, "Data record %d", i + 1);
            cdr_dr_tree = proto_item_add_subtree(te, ett_gtp_cdr_dr);
            proto_tree_add_text(cdr_dr_tree, tvb, offset, 2, "Length: %u", cdr_length);
            offset+=2;
            proto_tree_add_text(cdr_dr_tree, tvb, offset, cdr_length, "Content");
            next_tvb = tvb_new_subset_remaining(tvb, offset);

            /* XXX this is for release 6, may not work for higer releases */
            if(format==1){
                dissect_gprscdr_GPRSCallEventRecord_PDU(next_tvb, pinfo, cdr_dr_tree);
            }else{
                /* Do we have a dissector regestering for this data format? */
                dissector_try_uint(gtp_cdr_fmt_dissector_table, format, next_tvb, pinfo, cdr_dr_tree);
            }

            offset = offset + cdr_length;
        }

    }else{
        /* Proprietary CDR format */
        proto_item_append_text(fmt_item, " Proprietary or un documented format");
    }

    if (gtpcdr_handle) {
        next_tvb = tvb_new_subset_remaining(tvb, offset);
        call_dissector(gtpcdr_handle, next_tvb, pinfo, tree);
    }

    return 3 + length;
}

/* GPRS:        12.15
 * UMTS:        33.015
 */
static int decode_gtp_data_resp(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length, n, number;
    proto_tree *ext_tree_data_resp;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);

    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "Requests responded");
    ext_tree_data_resp = proto_item_add_subtree(te, ett_gtp_data_resp);

    n = 0;

    while (n < length) {

        number = tvb_get_ntohs(tvb, offset + 3 + n);
        proto_tree_add_text(ext_tree_data_resp, tvb, offset + 3 + n, 2, "%u", number);
        n = n + 2;

    }

    return 3 + length;

}

/* GPRS:        12.15
 * UMTS:        33.015
 */
static int decode_gtp_node_addr(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length;
    guint32 addr_ipv4;
    struct e_in6_addr addr_ipv6;
    proto_tree *ext_tree_node_addr;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);

    te = proto_tree_add_text(tree, tvb, offset, 3 + length, "Node address: ");
    ext_tree_node_addr = proto_item_add_subtree(te, ett_gtp_node_addr);

    proto_tree_add_text(ext_tree_node_addr, tvb, offset + 1, 2, "Node address length: %u", length);

    switch (length) {
    case 4:
        addr_ipv4 = tvb_get_ipv4(tvb, offset + 3);
        proto_item_append_text(te, "%s", ip_to_str((guint8 *) & addr_ipv4));
        proto_tree_add_ipv4(ext_tree_node_addr, hf_gtp_node_ipv4, tvb, offset + 3, 4, addr_ipv4);
        break;
    case 16:
        tvb_get_ipv6(tvb, offset + 3, &addr_ipv6);
        proto_item_append_text(te, "%s", ip6_to_str((struct e_in6_addr *) &addr_ipv6));
        proto_tree_add_ipv6(ext_tree_node_addr, hf_gtp_node_ipv6, tvb, offset + 3, 16, (guint8 *) & addr_ipv6);
        break;
    default:
        proto_item_append_text(te, "unknown type or wrong length");
        break;
    }

    return 3 + length;

}

/* GPRS:        9.60 v7.6.0, chapter 7.9.26
 * UMTS:        29.060 v4.0, chapter 7.7.46 Private Extension
 *
 */

static int decode_gtp_priv_ext(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    guint16 length, ext_id;
    proto_tree *ext_tree_priv_ext;
    proto_item *te;
    tvbuff_t *next_tvb;

    te = proto_tree_add_text(tree, tvb, offset, 1, "%s", val_to_str_ext_const(GTP_EXT_PRIV_EXT, &gtp_val_ext, "Unknown message"));
    ext_tree_priv_ext = proto_item_add_subtree(te, ett_gtp_ext);

    offset++;
    length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(ext_tree_priv_ext, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    if (length >= 2) {
        ext_id = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint(ext_tree_priv_ext, hf_gtp_ext_id, tvb, offset, 2, ext_id);
        offset = offset + 2;

        /*
         * XXX - is this always a text string?  Or should it be
         * displayed as hex data?
         */
       if (length > 2){
            proto_tree_add_item(ext_tree_priv_ext, hf_gtp_ext_val, tvb, offset, length - 2, ENC_NA);
            next_tvb = tvb_new_subset_remaining(tvb, offset);
            dissector_try_uint(gtp_priv_ext_dissector_table, ext_id, next_tvb, pinfo, ext_tree_priv_ext);
       }
    }

    return 3 + length;
}

static int decode_gtp_unknown(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree)
{

    proto_tree_add_text(tree, tvb, offset, 1, "Unknown extension header");

    return tvb_length_remaining(tvb, offset);
}

static void dissect_gtp_common(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
    struct _gtp_hdr gtp_hdr;
    proto_tree *gtp_tree, *flags_tree, *ext_tree;
    proto_item *ti, *tf, *item;
    int i, offset, length, gtp_prime, checked_field, mandatory;
    int seq_no=0, flow_label=0;
    guint8 pdu_no, next_hdr = 0, ext_hdr_val, noOfExtHdrs = 0, ext_hdr_length;
    gchar *tid_str;
    guint32 teid = 0;
    tvbuff_t *next_tvb;
    guint8 sub_proto, acfield_len = 0, control_field;
    gtp_msg_hash_t *gcrp=NULL;
    conversation_t *conversation=NULL;
    gtp_conv_info_t *gtp_info;
    void* pd_save;


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GTP");
    col_clear(pinfo->cinfo, COL_INFO);

    /*
     * Do we have a conversation for this connection?
     */
    conversation = find_or_create_conversation(pinfo);

    /*
     * Do we already know this conversation?
     */
    gtp_info = conversation_get_proto_data(conversation, proto_gtp);
    if (gtp_info == NULL) {
        /* No.  Attach that information to the conversation, and add
         * it to the list of information structures.
         */
        gtp_info = g_malloc(sizeof(gtp_conv_info_t));
        /*Request/response matching tables*/
        gtp_info->matched = g_hash_table_new(gtp_sn_hash, gtp_sn_equal_matched);
        gtp_info->unmatched = g_hash_table_new(gtp_sn_hash, gtp_sn_equal_unmatched);

        conversation_add_proto_data(conversation, proto_gtp, gtp_info);

        gtp_info->next = gtp_info_items;
        gtp_info_items = gtp_info;
    }
    pd_save = pinfo->private_data;
    pinfo->private_data = gtp_info;

    tvb_memcpy(tvb, (guint8 *) & gtp_hdr, 0, 4);

    if (!(gtp_hdr.flags & 0x10))
                gtp_prime = 1;
    else
                gtp_prime = 0;

    switch ((gtp_hdr.flags >> 5) & 0x07) {
            case 0:
                        gtp_version = 0;
                        break;
            case 1:
                        gtp_version = 1;
                        break;
            default:
                        gtp_version = 1;
                        break;
    }

    col_add_str(pinfo->cinfo, COL_INFO, val_to_str_ext_const(gtp_hdr.message, &gtp_message_type_ext, "Unknown"));

    if (tree) {
        ti = proto_tree_add_item(tree, proto_gtp, tvb, 0, -1, ENC_NA);
        gtp_tree = proto_item_add_subtree(ti, ett_gtp);

        tf = proto_tree_add_uint(gtp_tree, hf_gtp_flags, tvb, 0, 1, gtp_hdr.flags);
        flags_tree = proto_item_add_subtree(tf, ett_gtp_flags);

        if(gtp_prime==0){
            proto_tree_add_uint(flags_tree, hf_gtp_flags_ver, tvb, 0, 1, gtp_hdr.flags);
        }else{
            proto_tree_add_uint(flags_tree, hf_gtp_prime_flags_ver, tvb, 0, 1, gtp_hdr.flags);
        }

        proto_tree_add_uint(flags_tree, hf_gtp_flags_pt, tvb, 0, 1, gtp_hdr.flags);

        if((gtp_prime==1)||(gtp_version==0)){
            proto_tree_add_uint(flags_tree, hf_gtp_flags_spare1, tvb, 0, 1, gtp_hdr.flags);
            proto_tree_add_boolean(flags_tree, hf_gtp_flags_snn, tvb, 0, 1, gtp_hdr.flags);
        }else{
            proto_tree_add_uint(flags_tree, hf_gtp_flags_spare2, tvb, 0, 1, gtp_hdr.flags);
            proto_tree_add_boolean(flags_tree, hf_gtp_flags_e, tvb, 0, 1, gtp_hdr.flags);
            proto_tree_add_boolean(flags_tree, hf_gtp_flags_s, tvb, 0, 1, gtp_hdr.flags);
            proto_tree_add_boolean(flags_tree, hf_gtp_flags_pn, tvb, 0, 1, gtp_hdr.flags);
        }

        proto_tree_add_uint(gtp_tree, hf_gtp_message_type, tvb, 1, 1, gtp_hdr.message);

        gtp_hdr.length = g_ntohs(gtp_hdr.length);
        proto_tree_add_uint(gtp_tree, hf_gtp_length, tvb, 2, 2, gtp_hdr.length);

        offset = 4;

        if (gtp_prime) {
            seq_no = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(gtp_tree, hf_gtp_seq_number, tvb, offset, 2, seq_no);
            offset += 2;
        } else
            switch (gtp_version) {
            case 0:
                seq_no = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(gtp_tree, hf_gtp_seq_number, tvb, offset, 2, seq_no);
                offset += 2;

                flow_label = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(gtp_tree, hf_gtp_flow_label, tvb, offset, 2, flow_label);
                offset += 2;

                pdu_no = tvb_get_guint8(tvb, offset);
                proto_tree_add_uint(gtp_tree, hf_gtp_sndcp_number, tvb, offset, 1, pdu_no);
                offset += 4;

                tid_str = id_to_str(tvb, offset);
                proto_tree_add_string(gtp_tree, hf_gtp_tid, tvb, offset, 8, tid_str);
                offset += 8;
                break;
            case 1:
                teid = tvb_get_ntohl(tvb, offset);
                proto_tree_add_uint(gtp_tree, hf_gtp_teid, tvb, offset, 4, teid);
                offset += 4;

                /* Are sequence number/N-PDU Number/extension header present? */
                if (gtp_hdr.flags & 0x07) {
                    seq_no = tvb_get_ntohs(tvb, offset);
                    proto_tree_add_uint(gtp_tree, hf_gtp_seq_number, tvb, offset, 2, seq_no);
                    offset += 2;

                    pdu_no = tvb_get_guint8(tvb, offset);
                    proto_tree_add_uint(gtp_tree, hf_gtp_npdu_number, tvb, offset, 1, pdu_no);
                    offset++;

                    next_hdr = tvb_get_guint8(tvb, offset);

                    /* Don't add extension header, we'll add a subtree for that */
                    /* proto_tree_add_uint(gtp_tree, hf_gtp_next, tvb, offset, 1, next_hdr); */

                    offset++;

                    /* Change to while? */
                    if (next_hdr) {

                        /* TODO Add support for more than one extension header */

                        noOfExtHdrs++;

                        tf = proto_tree_add_uint(gtp_tree, hf_gtp_ext_hdr, tvb, offset, 4, next_hdr);
                        ext_tree = proto_item_add_subtree(tf, ett_gtp_ext_hdr);

                        /* PDCP PDU
                         * 3GPP 29.281 v9.0.0, 5.2.2.2 PDCP PDU Number
                         *
                         * "This extension header is transmitted, for example in UTRAN, at SRNS relocation time,
                         * to provide the PDCP sequence number of not yet acknowledged N-PDUs. It is 4 octets long,
                         *  and therefore the Length field has value 1.
                         *
                         *  When used between two eNBs at the X2 interface in E-UTRAN, bits 5-8 of octet 2 are spare.
                         *  The meaning of the spare bits shall be set to zero.
                         *
                         * Wireshark Note: TS 29.060 does not define bit 5-6 as spare, so no check is possible unless a preference is used.
                         */
                        if (next_hdr == GTP_EXT_HDR_PDCP_SN) {

                            /* First byte is length (should be 1) */
                            ext_hdr_length = tvb_get_guint8(tvb, offset);
                            if (ext_hdr_length != 1) {
                                expert_add_info_format(pinfo, ext_tree, PI_PROTOCOL, PI_WARN, "The length field for the PDCP SN Extension header should be 1.");
                            }
                            proto_tree_add_item(ext_tree, hf_gtp_ext_hdr_length, tvb, offset,1, ENC_BIG_ENDIAN);
                            offset++;

                            proto_tree_add_item(ext_tree, hf_gtp_ext_hdr_pdcpsn, tvb, offset, 2, ENC_BIG_ENDIAN);
                            offset += 2;

                            /* Last is next_hdr */
                            next_hdr = tvb_get_guint8(tvb, offset);
                            item = proto_tree_add_item(ext_tree, hf_gtp_ext_hdr_next, tvb, offset, 1, ENC_BIG_ENDIAN);

                            if (next_hdr) {
                                expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN, "Can't decode more than one extension header.");
                            }
                            offset++;
                         }
                    }
                }
                break;
            default:
                break;
            }

        if (gtp_hdr.message != GTP_MSG_TPDU) {
            /* TODO: This code should be cleaned up to handle more than one
             * header and possibly display the header content */
            if (next_hdr) {
                offset++;
                switch (next_hdr) {
                case 1:
                    /* MBMS support indication */
                    proto_tree_add_text(gtp_tree, tvb, offset, 4, "[--- MBMS support indication header ---]");
                    offset += 3;
                    break;
                case 2:
                    /* MS Info Change Reporting support indication */
                    proto_tree_add_text(gtp_tree, tvb, offset, 4, "[--- MS Info Change Reporting support indication header ---]");
                    offset += 3;
                    break;
                case 0xc0:
                    /* PDCP PDU number */
                    proto_tree_add_text(gtp_tree, tvb, offset, 4, "[--- PDCP PDU number header ---]");
                    offset += 3;
                    break;
                case 0xc1:
                    /* Suspend Request */
                    proto_tree_add_text(gtp_tree, tvb, offset, 4, "[--- Suspend Request header ---]");
                    offset += 3;
                    break;
                case 0xc2:
                    /* Suspend Response */
                    proto_tree_add_text(gtp_tree, tvb, offset, 4, "[--- Suspend Response header ---]");
                    offset += 3;
                    break;
                default:
                    proto_tree_add_text(gtp_tree, tvb, offset, 4, "[--- Unknown extension header ---]");
                    offset += 3;
                    break;
                }
                next_hdr = tvb_get_guint8(tvb, offset);
                proto_tree_add_uint(gtp_tree, hf_gtp_next, tvb, offset, 1, next_hdr);
                offset++;
            }
           /* proto_tree_add_text(gtp_tree, tvb, 0, 0, "[--- end of GTP header, beginning of extension headers ---]");*/
            length = tvb_length(tvb);
            mandatory = 0;      /* check order of GTP fields against ETSI */
            for (;;) {
                if (offset >= length)
                    break;
                if (next_hdr) {
                    ext_hdr_val = next_hdr;
                    next_hdr = 0;
                } else
                    ext_hdr_val = tvb_get_guint8(tvb, offset);
                if (g_gtp_etsi_order) {
                    checked_field = check_field_presence(gtp_hdr.message, ext_hdr_val, (int *) &mandatory);
                    switch (checked_field) {
                    case -2:
                        proto_tree_add_text(gtp_tree, tvb, 0, 0, "[WARNING] message not found");
                        break;
                    case -1:
                        proto_tree_add_text(gtp_tree, tvb, 0, 0, "[WARNING] field not present");
                        break;
                    case 0:
                        break;
                    default:
                        proto_tree_add_text(gtp_tree, tvb, offset, 1, "[WARNING] wrong next field, should be: %s",
                                            val_to_str_ext_const(checked_field, &gtp_val_ext, "Unknown extension field"));
                        break;
                    }
                }

                i = -1;
                while (gtpopt[++i].optcode)
                    if (gtpopt[i].optcode == ext_hdr_val)
                        break;
                offset = offset + (*gtpopt[i].decode) (tvb, offset, pinfo, gtp_tree);
            }

            /*Use sequence number to track Req/Resp pairs*/
            if (seq_no) {
                gcrp = gtp_match_response(tvb, pinfo, gtp_tree, seq_no, gtp_hdr.message);
                /*pass packet to tap for response time reporting*/
                if (gcrp) {
                    tap_queue_packet(gtp_tap,pinfo,gcrp);
                }
            }
        }
        proto_item_set_len (ti, offset);
    }

    if ((gtp_hdr.message == GTP_MSG_TPDU) && g_gtp_tpdu) {

        if (gtp_prime)
            offset = 6;
        else if (gtp_version == 1) {
            if (gtp_hdr.flags & 0x07) {
                offset = 11;
                if (tvb_get_guint8(tvb, offset) == 0)
                    offset++;
            } else
                offset = 8;
        } else
            offset = 20;

        /* Can only handle one extension header type... */
        if (noOfExtHdrs != 0) offset+= 1 + noOfExtHdrs*4;

        sub_proto = tvb_get_guint8(tvb, offset);

        if ((sub_proto >= 0x45) && (sub_proto <= 0x4e)) {
            /* this is most likely an IPv4 packet
             * we can exclude 0x40 - 0x44 because the minimum header size is 20 octets
             * 0x4f is excluded because PPP protocol type "IPv6 header compression"
             * with protocol field compression is more likely than a plain IPv4 packet with 60 octet header size */

            next_tvb = tvb_new_subset_remaining(tvb, offset);
            call_dissector(ip_handle, next_tvb, pinfo, tree);

        } else if ((sub_proto & 0xf0) == 0x60) {
            /* this is most likely an IPv6 packet */
            next_tvb = tvb_new_subset_remaining(tvb, offset);
            call_dissector(ipv6_handle, next_tvb, pinfo, tree);
        } else {
            /* this seems to be a PPP packet */

            if (sub_proto == 0xff) {
                /* this might be an address field, even it shouldn't be here */
                control_field = tvb_get_guint8(tvb, offset + 1);
                if (control_field == 0x03)
                    /* now we are pretty sure that address and control field are mistakenly inserted -> ignore it for PPP dissection */
                    acfield_len = 2;
            }

            next_tvb = tvb_new_subset_remaining(tvb, offset + acfield_len);
            call_dissector(ppp_handle, next_tvb, pinfo, tree);
        }

        col_prepend_fstr(pinfo->cinfo, COL_PROTOCOL, "GTP <");
        col_append_str(pinfo->cinfo, COL_PROTOCOL, ">");
    }
    pinfo->private_data = pd_save;
}

static void dissect_gtpprim(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{

    dissect_gtp_common(tvb, pinfo, tree);
}

static void dissect_gtp(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
    guint8 version;
    /*
     * If this is GTPv2-C call the gtpv2 dissector if present
     * Should this be moved to after the conversation stuff to retain that functionality for GTPv2 ???
     */
    version = tvb_get_guint8(tvb,0)>>5;
    if (version==2) {
        /* GTPv2-C 3GPP TS 29.274 */
        if (gtpv2_handle) {
            call_dissector(gtpv2_handle, tvb, pinfo, tree);
            return;
        }
    }
    if(version>2){
        proto_tree_add_text(tree, tvb, 0, -1, "No WS dissector for GTP version %u %s", version,
                            val_to_str_const(version, ver_types, "Unknown"));
        return;
    }

    dissect_gtp_common(tvb, pinfo, tree);

}


static const true_false_string yes_no_tfs = {
    "yes",
    "no"
};

static void gtp_reinit(void)
{
    gtp_conv_info_t *gtp_info;

    /* Free up state attached to the gtp_info structures */
    for (gtp_info = gtp_info_items; gtp_info != NULL; ) {
        gtp_conv_info_t *next;

        g_hash_table_destroy(gtp_info->matched);
        gtp_info->matched=NULL;
        g_hash_table_destroy(gtp_info->unmatched);
        gtp_info->unmatched=NULL;

        next = gtp_info->next;
        g_free(gtp_info);
        gtp_info = next;
    }

    gtp_info_items = NULL;
}

void proto_register_gtp(void)
{
    static hf_register_info hf_gtp[] = {

        {&hf_gtp_response_in,
         {"Response In", "gtp.response_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0, "The response to this GTP request is in this frame", HFILL}},
        {&hf_gtp_response_to,
         {"Response To", "gtp.response_to", FT_FRAMENUM, BASE_NONE, NULL, 0x0, "This is a response to the GTP request in this frame", HFILL}},
        {&hf_gtp_time, {"Time", "gtp.time", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, "The time between the Request and the Response", HFILL}},
        {&hf_gtp_apn, {"APN", "gtp.apn", FT_STRING, BASE_NONE, NULL, 0, "Access Point Name", HFILL}},
        {&hf_gtp_cause, {"Cause", "gtp.cause", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &cause_type_ext, 0, "Cause of operation", HFILL}},
        {&hf_gtp_chrg_char, {"Charging characteristics", "gtp.chrg_char", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf_gtp_chrg_char_s, {"Spare", "gtp.chrg_char_s", FT_UINT16, BASE_DEC, NULL, GTP_MASK_CHRG_CHAR_S, NULL, HFILL}},
        {&hf_gtp_chrg_char_n, {"Normal charging", "gtp.chrg_char_n", FT_UINT16, BASE_DEC, NULL, GTP_MASK_CHRG_CHAR_N, NULL, HFILL}},
        {&hf_gtp_chrg_char_p, {"Prepaid charging", "gtp.chrg_char_p", FT_UINT16, BASE_DEC, NULL, GTP_MASK_CHRG_CHAR_P, NULL, HFILL}},
        {&hf_gtp_chrg_char_f,
         {"Flat rate charging", "gtp.chrg_char_f", FT_UINT16, BASE_DEC, NULL, GTP_MASK_CHRG_CHAR_F, NULL, HFILL}},
        {&hf_gtp_chrg_char_h,
         {"Hot billing charging", "gtp.chrg_char_h", FT_UINT16, BASE_DEC, NULL, GTP_MASK_CHRG_CHAR_H, NULL, HFILL}},
        {&hf_gtp_chrg_char_r, {"Reserved", "gtp.chrg_char_r", FT_UINT16, BASE_DEC, NULL, GTP_MASK_CHRG_CHAR_R, NULL, HFILL}},
        {&hf_gtp_chrg_id, {"Charging ID", "gtp.chrg_id", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}},
        {&hf_gtp_chrg_ipv4, {"CG address IPv4", "gtp.chrg_ipv4", FT_IPv4, BASE_NONE, NULL, 0, "Charging Gateway address IPv4", HFILL}},
        {&hf_gtp_chrg_ipv6, {"CG address IPv6", "gtp.chrg_ipv6", FT_IPv6, BASE_NONE, NULL, 0, "Charging Gateway address IPv6", HFILL}},
        {&hf_gtp_ext_flow_label, {"Flow Label Data I", "gtp.ext_flow_label", FT_UINT16, BASE_HEX, NULL, 0, "Flow label data", HFILL}},
        {&hf_gtp_ext_id, {"Extension identifier", "gtp.ext_id", FT_UINT16, BASE_DEC|BASE_EXT_STRING, &sminmpec_values_ext, 0, NULL, HFILL}},
        {&hf_gtp_ext_val, {"Extension value", "gtp.ext_val", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf_gtp_flags, {"Flags", "gtp.flags", FT_UINT8, BASE_HEX, NULL, 0, "Ver/PT/Spare...", HFILL}},
        {&hf_gtp_ext_hdr, {"Extension header", "gtp.ext_hdr", FT_UINT8, BASE_HEX, VALS(next_extension_header_fieldvals), 0, NULL, HFILL}},
        {&hf_gtp_ext_hdr_next, {"Next extension header", "gtp.ext_hdr.next", FT_UINT8, BASE_HEX, VALS(next_extension_header_fieldvals), 0, NULL, HFILL}},
        {&hf_gtp_ext_hdr_pdcpsn, {"PDCP Sequence Number", "gtp.ext_hdr.pdcp_sn", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf_gtp_ext_hdr_length, {"Extension Header Length", "gtp.ext_hdr.length", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf_gtp_flags_ver,
         {"Version", "gtp.flags.version",
          FT_UINT8, BASE_DEC, VALS(ver_types), GTP_VER_MASK,
          "GTP Version", HFILL}
        },
        {&hf_gtp_prime_flags_ver,
         {"Version", "gtp.prim.flags.version",
          FT_UINT8, BASE_DEC,NULL, GTP_VER_MASK,
          "GTP' Version", HFILL}
        },
        {&hf_gtp_flags_pt,
         {"Protocol type", "gtp.flags.payload",
          FT_UINT8, BASE_DEC, VALS(pt_types), GTP_PT_MASK,
          NULL, HFILL}
        },
        {&hf_gtp_flags_spare1,
         {"Reserved", "gtp.flags.reserved",
          FT_UINT8, BASE_DEC, NULL, GTP_SPARE1_MASK,
          "Reserved (shall be sent as '111' )", HFILL}
        },
        {&hf_gtp_flags_snn,
         {"Is SNDCP N-PDU included?", "gtp.flags.snn", FT_BOOLEAN, 8, TFS(&yes_no_tfs), GTP_SNN_MASK,
          "Is SNDCP N-PDU LLC Number included? (1 = yes, 0 = no)", HFILL}},
        {&hf_gtp_flags_spare2,
         {"Reserved", "gtp.flags.reserved", FT_UINT8, BASE_DEC, NULL, GTP_SPARE2_MASK, "Reserved (shall be sent as '1' )", HFILL}},
        {&hf_gtp_flags_e,
         {"Is Next Extension Header present?", "gtp.flags.e", FT_BOOLEAN, 8, TFS(&yes_no_tfs), GTP_E_MASK,
          "Is Next Extension Header present? (1 = yes, 0 = no)", HFILL}},
        {&hf_gtp_flags_s,
         {"Is Sequence Number present?", "gtp.flags.s", FT_BOOLEAN, 8, TFS(&yes_no_tfs), GTP_S_MASK, "Is Sequence Number present? (1 = yes, 0 = no)",
          HFILL}},
        {&hf_gtp_flags_pn,
         {"Is N-PDU number present?", "gtp.flags.pn", FT_BOOLEAN, 8, TFS(&yes_no_tfs), GTP_PN_MASK, "Is N-PDU number present? (1 = yes, 0 = no)",
          HFILL}},
        {&hf_gtp_flow_ii, {"Flow Label Data II", "gtp.flow_ii", FT_UINT16, BASE_DEC, NULL, 0, "Downlink flow label data", HFILL}},
        {&hf_gtp_flow_label, {"Flow label", "gtp.flow_label", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}},
        {&hf_gtp_flow_sig, {"Flow label Signalling", "gtp.flow_sig", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}},
        {&hf_gtp_gsn_addr_len,
         {"GSN Address Length", "gtp.gsn_addr_len", FT_UINT8, BASE_DEC, NULL, GTP_EXT_GSN_ADDR_LEN_MASK, NULL, HFILL}},
        {&hf_gtp_gsn_addr_type,
         {"GSN Address Type", "gtp.gsn_addr_type", FT_UINT8, BASE_DEC, VALS(gsn_addr_type), GTP_EXT_GSN_ADDR_TYPE_MASK, NULL, HFILL}},
        {&hf_gtp_gsn_ipv4, {"GSN address IPv4", "gtp.gsn_ipv4", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf_gtp_gsn_ipv6, {"GSN address IPv6", "gtp.gsn_ipv6", FT_IPv6, BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf_gtp_imsi, {"IMSI", "gtp.imsi", FT_STRING, BASE_NONE, NULL, 0, "International Mobile Subscriber Identity number", HFILL}},
        {&hf_gtp_length, {"Length", "gtp.length", FT_UINT16, BASE_DEC, NULL, 0, "Length (i.e. number of octets after TID or TEID)", HFILL}},
        {&hf_gtp_map_cause, {"MAP cause", "gtp.map_cause", FT_UINT8, BASE_DEC, VALS(gsm_old_GSMMAPLocalErrorcode_vals), 0, NULL, HFILL}},
        {&hf_gtp_message_type, {"Message Type", "gtp.message", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &gtp_message_type_ext, 0x0, "GTP Message Type", HFILL}},
        {&hf_gtp_ms_reason,
         {"MS not reachable reason", "gtp.ms_reason", FT_UINT8, BASE_DEC, VALS(ms_not_reachable_type), 0, NULL, HFILL}},
        {&hf_gtp_ms_valid, {"MS validated", "gtp.ms_valid", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_gtp_msisdn, {"MSISDN", "gtp.msisdn", FT_STRING, BASE_NONE, NULL, 0, "MS international PSTN/ISDN number", HFILL}},
        {&hf_gtp_next,
         {"Next extension header type", "gtp.next", FT_UINT8, BASE_HEX, VALS(next_extension_header_fieldvals), 0, NULL,
          HFILL}},
        {&hf_gtp_node_ipv4, {"Node address IPv4", "gtp.node_ipv4", FT_IPv4, BASE_NONE, NULL, 0, "Recommended node address IPv4", HFILL}},
        {&hf_gtp_node_ipv6, {"Node address IPv6", "gtp.node_ipv6", FT_IPv6, BASE_NONE, NULL, 0, "Recommended node address IPv6", HFILL}},
        {&hf_gtp_npdu_number, {"N-PDU Number", "gtp.npdu_number", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL}},
        {&hf_gtp_nsapi, {"NSAPI", "gtp.nsapi", FT_UINT8, BASE_DEC, NULL, 0, "Network layer Service Access Point Identifier", HFILL}},
        {&hf_gtp_qos_version, {"Version", "gtp.qos_version", FT_STRING, BASE_NONE, NULL, 0, "Version of the QoS Profile", HFILL}},
        {&hf_gtp_qos_spare1, {"Spare", "gtp.qos_spare1", FT_UINT8, BASE_DEC, NULL, GTP_EXT_QOS_SPARE1_MASK, "Spare (shall be sent as '00' )", HFILL}},
        {&hf_gtp_qos_delay,
         {"QoS delay", "gtp.qos_delay", FT_UINT8, BASE_DEC, VALS(qos_delay_type), GTP_EXT_QOS_DELAY_MASK, "Quality of Service Delay Class", HFILL}},
        {&hf_gtp_qos_reliability,
         {"QoS reliability", "gtp.qos_reliability", FT_UINT8, BASE_DEC, VALS(qos_reliability_type), GTP_EXT_QOS_RELIABILITY_MASK,
          "Quality of Service Reliability Class", HFILL}},
        {&hf_gtp_qos_peak,
         {"QoS peak", "gtp.qos_peak", FT_UINT8, BASE_DEC, VALS(qos_peak_type), GTP_EXT_QOS_PEAK_MASK, "Quality of Service Peak Throughput", HFILL}},
        {&hf_gtp_qos_spare2, {"Spare", "gtp.qos_spare2", FT_UINT8, BASE_DEC, NULL, GTP_EXT_QOS_SPARE2_MASK, "Spare (shall be sent as 0)", HFILL}},
        {&hf_gtp_qos_precedence,
         {"QoS precedence", "gtp.qos_precedence", FT_UINT8, BASE_DEC, VALS(qos_precedence_type), GTP_EXT_QOS_PRECEDENCE_MASK,
          "Quality of Service Precedence Class", HFILL}},
        {&hf_gtp_qos_spare3,
         {"Spare", "gtp.qos_spare3", FT_UINT8, BASE_DEC, NULL, GTP_EXT_QOS_SPARE3_MASK, "Spare (shall be sent as '000' )", HFILL}},
        {&hf_gtp_qos_mean,
         {"QoS mean", "gtp.qos_mean", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &qos_mean_type_ext, GTP_EXT_QOS_MEAN_MASK, "Quality of Service Mean Throughput", HFILL}},
        {&hf_gtp_qos_al_ret_priority,
         {"Allocation/Retention priority", "gtp.qos_al_ret_priority", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf_gtp_qos_traf_class,
         {"Traffic class", "gtp.qos_traf_class", FT_UINT8, BASE_DEC, VALS(qos_traf_class), GTP_EXT_QOS_TRAF_CLASS_MASK, NULL, HFILL}},
        {&hf_gtp_qos_del_order,
         {"Delivery order", "gtp.qos_del_order", FT_UINT8, BASE_DEC, VALS(qos_del_order), GTP_EXT_QOS_DEL_ORDER_MASK, NULL, HFILL}},
        {&hf_gtp_qos_del_err_sdu,
         {"Delivery of erroneous SDU", "gtp.qos_del_err_sdu", FT_UINT8, BASE_DEC, VALS(qos_del_err_sdu), GTP_EXT_QOS_DEL_ERR_SDU_MASK,
          NULL, HFILL}},
        {&hf_gtp_qos_max_sdu_size,
         {"Maximum SDU size", "gtp.qos_max_sdu_size", FT_UINT8, BASE_DEC, VALS(qos_max_sdu_size), 0, NULL, HFILL}},
        {&hf_gtp_qos_max_ul,
         {"Maximum bit rate for uplink", "gtp.qos_max_ul", FT_UINT8, BASE_DEC, VALS(qos_max_ul), 0, NULL, HFILL}},
        {&hf_gtp_qos_max_dl,
         {"Maximum bit rate for downlink", "gtp.qos_max_dl", FT_UINT8, BASE_DEC, VALS(qos_max_dl), 0, NULL, HFILL}},
        {&hf_gtp_qos_res_ber,
         {"Residual BER", "gtp.qos_res_ber", FT_UINT8, BASE_DEC, VALS(qos_res_ber), GTP_EXT_QOS_RES_BER_MASK, "Residual Bit Error Rate", HFILL}},
        {&hf_gtp_qos_sdu_err_ratio,
         {"SDU Error ratio", "gtp.qos_sdu_err_ratio", FT_UINT8, BASE_DEC, VALS(qos_sdu_err_ratio), GTP_EXT_QOS_SDU_ERR_RATIO_MASK, NULL,
          HFILL}},
        {&hf_gtp_qos_trans_delay,
         {"Transfer delay", "gtp.qos_trans_delay", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &qos_trans_delay_ext, GTP_EXT_QOS_TRANS_DELAY_MASK, NULL, HFILL}},
        {&hf_gtp_qos_traf_handl_prio,
         {"Traffic handling priority", "gtp.qos_traf_handl_prio", FT_UINT8, BASE_DEC, VALS(qos_traf_handl_prio), GTP_EXT_QOS_TRAF_HANDL_PRIORITY_MASK,
          NULL, HFILL}},
        {&hf_gtp_qos_guar_ul,
         {"Guaranteed bit rate for uplink", "gtp.qos_guar_ul", FT_UINT8, BASE_DEC, VALS(qos_guar_ul), 0, NULL, HFILL}},
        {&hf_gtp_qos_guar_dl,
         {"Guaranteed bit rate for downlink", "gtp.qos_guar_dl", FT_UINT8, BASE_DEC, VALS(qos_guar_dl), 0, NULL,
          HFILL}},
        {&hf_gtp_qos_src_stat_desc,
         {"Source Statistics Descriptor", "gtp.src_stat_desc", FT_UINT8, BASE_DEC, VALS(src_stat_desc_vals), GTP_EXT_QOS_SRC_STAT_DESC_MASK, NULL, HFILL}},
        {&hf_gtp_qos_sig_ind,
         {"Signalling Indication", "gtp.sig_ind", FT_BOOLEAN, 8, TFS(&gtp_sig_ind), GTP_EXT_QOS_SIG_IND_MASK, NULL, HFILL}},
        {&hf_gtp_pkt_flow_id, {"Packet Flow ID", "gtp.pkt_flow_id", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf_gtp_ptmsi, {"P-TMSI", "gtp.ptmsi", FT_UINT32, BASE_HEX, NULL, 0, "Packet-Temporary Mobile Subscriber Identity", HFILL}},
        {&hf_gtp_ptmsi_sig, {"P-TMSI Signature", "gtp.ptmsi_sig", FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL}},
        {&hf_gtp_rab_gtpu_dn, {"Downlink GTP-U seq number", "gtp.rab_gtp_dn", FT_UINT16, BASE_DEC, NULL, 0, "Downlink GTP-U sequence number", HFILL}},
        {&hf_gtp_rab_gtpu_up, {"Uplink GTP-U seq number", "gtp.rab_gtp_up", FT_UINT16, BASE_DEC, NULL, 0, "Uplink GTP-U sequence number", HFILL}},
        {&hf_gtp_rab_pdu_dn,
         {"Downlink next PDCP-PDU seq number", "gtp.rab_pdu_dn", FT_UINT16, BASE_DEC, NULL, 0, "Downlink next PDCP-PDU sequence number", HFILL}},
        {&hf_gtp_rab_pdu_up,
         {"Uplink next PDCP-PDU seq number", "gtp.rab_pdu_up", FT_UINT16, BASE_DEC, NULL, 0, "Uplink next PDCP-PDU sequence number", HFILL}},
        {&hf_gtp_rai_rac, {"RAC", "gtp.rac", FT_UINT8, BASE_DEC, NULL, 0, "Routing Area Code", HFILL}},
        {&hf_gtp_rai_lac, {"LAC", "gtp.lac", FT_UINT16, BASE_DEC, NULL, 0, "Location Area Code", HFILL}},
        {&hf_gtp_ranap_cause, {"RANAP cause", "gtp.ranap_cause", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &ranap_cause_type_ext, 0, NULL, HFILL}},
        {&hf_gtp_recovery, {"Recovery", "gtp.recovery", FT_UINT8, BASE_DEC, NULL, 0, "Restart counter", HFILL}},
        {&hf_gtp_reorder, {"Reordering required", "gtp.reorder", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_gtp_rnc_ipv4, {"RNC address IPv4", "gtp.rnc_ipv4", FT_IPv4, BASE_NONE, NULL, 0, "Radio Network Controller address IPv4", HFILL}},
        {&hf_gtp_rnc_ipv6, {"RNC address IPv6", "gtp.rnc_ipv6", FT_IPv6, BASE_NONE, NULL, 0, "Radio Network Controller address IPv6", HFILL}},
        {&hf_gtp_rp, {"Radio Priority", "gtp.rp", FT_UINT8, BASE_DEC, NULL, GTPv1_EXT_RP_MASK, "Radio Priority for uplink tx", HFILL}},
        {&hf_gtp_rp_nsapi,
         {"NSAPI in Radio Priority", "gtp.rp_nsapi", FT_UINT8, BASE_DEC, NULL, GTPv1_EXT_RP_NSAPI_MASK,
          "Network layer Service Access Point Identifier in Radio Priority", HFILL}},
        {&hf_gtp_rp_sms, {"Radio Priority SMS", "gtp.rp_sms", FT_UINT8, BASE_DEC, NULL, 0, "Radio Priority for MO SMS", HFILL}},
        {&hf_gtp_rp_spare, {"Reserved", "gtp.rp_spare", FT_UINT8, BASE_DEC, NULL, GTPv1_EXT_RP_SPARE_MASK, "Spare bit", HFILL}},
        {&hf_gtp_sel_mode,
         {"Selection mode", "gtp.sel_mode",
          FT_UINT8, BASE_DEC, VALS(sel_mode_type), 0x03,
          NULL, HFILL}
        },
        {&hf_gtp_seq_number, {"Sequence number", "gtp.seq_number", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}},
        {&hf_gtp_sndcp_number, {"SNDCP N-PDU LLC Number", "gtp.sndcp_number", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL}},
        {&hf_gtp_tear_ind, {"Teardown Indicator", "gtp.tear_ind", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_gtp_teid, {"TEID", "gtp.teid", FT_UINT32, BASE_HEX, NULL, 0, "Tunnel Endpoint Identifier", HFILL}},
        {&hf_gtp_teid_cp, {"TEID Control Plane", "gtp.teid_cp", FT_UINT32, BASE_HEX, NULL, 0, "Tunnel Endpoint Identifier Control Plane", HFILL}},
        {&hf_gtp_ulink_teid_cp,
         {"Uplink TEID Control Plane", "gtp.ulink_teid_cp", FT_UINT32, BASE_HEX, NULL, 0, "Uplink Tunnel Endpoint Identifier Control Plane", HFILL}},
        {&hf_gtp_teid_data, {"TEID Data I", "gtp.teid_data", FT_UINT32, BASE_HEX, NULL, 0, "Tunnel Endpoint Identifier Data I", HFILL}},
        {&hf_gtp_ulink_teid_data,
         {"Uplink TEID Data I", "gtp.ulink_teid_data", FT_UINT32, BASE_HEX, NULL, 0, "UplinkTunnel Endpoint Identifier Data I", HFILL}},
        {&hf_gtp_teid_ii, {"TEID Data II", "gtp.teid_ii", FT_UINT32, BASE_HEX, NULL, 0, "Tunnel Endpoint Identifier Data II", HFILL}},
        {&hf_gtp_tft_code,
         {"TFT operation code", "gtp.tft_code", FT_UINT8, BASE_DEC, VALS(tft_code_type), GTPv1_TFT_CODE_MASK, NULL, HFILL}},
        {&hf_gtp_tft_spare, {"TFT spare bit", "gtp.tft_spare", FT_UINT8, BASE_DEC, NULL, GTPv1_TFT_SPARE_MASK, NULL, HFILL}},
        {&hf_gtp_tft_number,
         {"Number of packet filters", "gtp.tft_number", FT_UINT8, BASE_DEC, NULL, GTPv1_TFT_NUMBER_MASK, NULL, HFILL}},
        {&hf_gtp_tft_eval, {"Evaluation precedence", "gtp.tft_eval", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf_gtp_tid, {"TID", "gtp.tid", FT_STRING, BASE_NONE, NULL, 0, "Tunnel Identifier", HFILL}},
        {&hf_gtp_tlli, {"TLLI", "gtp.tlli", FT_UINT32, BASE_HEX, NULL, 0, "Temporary Logical Link Identity", HFILL}},
        {&hf_gtp_tr_comm, {"Packet transfer command", "gtp.tr_comm", FT_UINT8, BASE_DEC, VALS(tr_comm_type), 0, "Packat transfer command", HFILL}},
        {&hf_gtp_trace_ref, {"Trace reference", "gtp.trace_ref", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}},
        {&hf_gtp_trace_type, {"Trace type", "gtp.trace_type", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}},
        {&hf_gtp_unknown, {"Unknown data (length)", "gtp.unknown", FT_UINT16, BASE_DEC, NULL, 0, "Unknown data", HFILL}},
        {&hf_gtp_user_addr_pdp_org,
         {"PDP type organization", "gtp.user_addr_pdp_org", FT_UINT8, BASE_DEC, VALS(pdp_org_type), 0, NULL, HFILL}},
        {&hf_gtp_user_addr_pdp_type, {"PDP type number", "gtp.user_addr_pdp_type", FT_UINT8, BASE_HEX, VALS(pdp_type), 0, "PDP type", HFILL}},
        {&hf_gtp_user_ipv4, {"End user address IPv4", "gtp.user_ipv4", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf_gtp_user_ipv6, {"End user address IPv6", "gtp.user_ipv6", FT_IPv6, BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf_gtp_security_mode,
         {"Security Mode", "gtp.security_mode",
          FT_UINT8, BASE_DEC, VALS(mm_sec_modep), 0xc0,
          NULL, HFILL}
        },
        {&hf_gtp_no_of_vectors,
         {"No of Vectors", "gtp.no_of_vectors",
          FT_UINT8, BASE_DEC, NULL, 0x38,
          NULL, HFILL}
        },
        {&hf_gtp_cipher_algorithm,
         {"Cipher Algorithm", "gtp.no_of_vectors",
          FT_UINT8, BASE_DEC, VALS(gtp_cipher_algorithm), 0x07,
          NULL, HFILL}
        },
        {&hf_gtp_cksn_ksi,
         {"Ciphering Key Sequence Number (CKSN)/Key Set Identifier (KSI)", "gtp.cksn_ksi",
          FT_UINT8, BASE_DEC, NULL, 0x07,
          "CKSN/KSI", HFILL}
        },
        {&hf_gtp_cksn,
         {"Ciphering Key Sequence Number (CKSN)", "gtp.cksn_ksi",
          FT_UINT8, BASE_DEC, NULL, 0x07,
          "CKSN", HFILL}
        },
        {&hf_gtp_ksi,
         {"Key Set Identifier (KSI)", "gtp.cksn_ksi",
          FT_UINT8, BASE_DEC, NULL, 0x07,
          "KSI", HFILL}
        },
        {&hf_gtp_ext_length,
         {"Length", "gtp.ext_length",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "IE Length", HFILL}
        },
        {&hf_gtp_ext_apn_res,
         {"Restriction Type", "gtp.ext_apn_res",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtp_ext_rat_type,
         {"RAT Type", "gtp.ext_rat_type",
          FT_UINT8, BASE_DEC, VALS(gtp_ext_rat_type_vals), 0x0,
          NULL, HFILL}
        },
        {&hf_gtp_ext_geo_loc_type,
         {"Geographic Location Type", "gtp.ext_geo_loc_type",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtp_ext_sac,
         {"SAC", "gtp.ext_sac",
          FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtp_ext_imeisv,
         {"IMEI(SV)", "gtp.ext_imeisv",
          FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        { &hf_gtp_targetRNC_ID,
          { "targetRNC-ID", "gtp.targetRNC_ID",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        {&hf_gtp_bssgp_cause,
         {"BSSGP Cause", "gtp.bssgp_cause",
          FT_UINT8, BASE_DEC|BASE_EXT_STRING, &bssgp_cause_vals_ext, 0,
          NULL, HFILL}},
        { &hf_gtp_bssgp_ra_discriminator,
          { "Routing Address Discriminator", "gtp.bssgp.rad",
            FT_UINT8, BASE_DEC, VALS(gtp_bssgp_ra_discriminator_vals), 0x0f,
            NULL, HFILL }
        },
        {&hf_gtp_sapi,
         {"PS Handover XID SAPI", "gtp.ps_handover_xid_sapi",
          FT_UINT8, BASE_DEC, NULL, 0x0F,
          "SAPI", HFILL}},
        {&hf_gtp_xid_par_len,
         {"PS Handover XID parameter length", "gtp.ps_handover_xid_par_len",
          FT_UINT8, BASE_DEC, NULL, 0xFF,
          "XID parameter length", HFILL}},
        {&hf_gtp_earp_pvi,
         {"PVI Pre-emption Vulnerability", "gtp.EARP_pre_emption_par_vulnerability",
          FT_UINT8, BASE_DEC, NULL, 0x01,
          NULL, HFILL}},
        {&hf_gtp_earp_pl,
         {"PL Priority Level", "gtp.EARP_priority_level",
          FT_UINT8, BASE_DEC, NULL, 0x3C,
          NULL, HFILL}},
        {&hf_gtp_earp_pci,
         {"PCI Pre-emption Capability", "gtp.EARP_pre_emption_Capability",
          FT_UINT8, BASE_DEC, NULL, 0x40,
          NULL, HFILL}},
        {&hf_gtp_cdr_app,
         {"Application Identifier", "gtp.cdr_app",
          FT_UINT8, BASE_DEC, NULL, 0xf0,
          NULL, HFILL}},
        { &hf_gtp_cdr_rel,
         {"Release Identifier", "gtp.cdr_rel",
          FT_UINT8, BASE_DEC, NULL, 0x0f,
          NULL, HFILL}},
        { &hf_gtp_cdr_ver,
         {"Version Identifier", "gtp.cdr_ver",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}},
        {&hf_gtp_spare,
         {"Spare", "gtp.spare",
          FT_UINT8, BASE_DEC, NULL, 0x02,
          NULL, HFILL}},
        {&hf_gtp_cmn_flg_ppc,
         {"Prohibit Payload Compression", "gtp.cmn_flg.ppc",
          FT_BOOLEAN, 8, NULL, 0x01,
          NULL, HFILL}},
        {&hf_gtp_cmn_flg_mbs_srv_type,
         {"MBMS Service Type", "gtp.cmn_flg.mbs_srv_type",
          FT_BOOLEAN, 8, NULL, 0x02,
          NULL, HFILL}},
        {&hf_gtp_cmn_flg_mbs_ran_pcd_rdy,
         {"RAN Procedures Ready", "gtp.cmn_flg.ran_pcd_rd",
          FT_BOOLEAN, 8, NULL, 0x04,
          NULL, HFILL}},
        {&hf_gtp_cmn_flg_mbs_cnt_inf,
         {"MBMS Counting Information", "gtp.cmn_flg.mbs_cnt_inf",
          FT_BOOLEAN, 8, NULL, 0x08,
          NULL, HFILL}},
        {&hf_gtp_cmn_flg_no_qos_neg,
         {"No QoS negotiation", "gtp.cmn_flg.no_qos_neg",
          FT_BOOLEAN, 8, NULL, 0x10,
          NULL, HFILL}},
        {&hf_gtp_cmn_flg_nrsn,
         {"NRSN bit field", "gtp.cmn_flg.nrsn",
          FT_BOOLEAN, 8, NULL, 0x20,
          NULL, HFILL}},
        {&hf_gtp_cmn_flg_upgrd_qos_sup,
         {"Upgrade QoS Supported", "gtp.cmn_flg.ran_pcd_rd",
          FT_BOOLEAN, 8, NULL, 0x40,
          NULL, HFILL}},
        {&hf_gtp_tmgi,
         {"Temporary Mobile Group Identity (TMGI)", "gtp.cmn_flg.ran_pcd_rd",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}},
        {&hf_gtp_no_of_mbms_sa_codes,
         {"Number of MBMS service area codes", "gtp.no_of_mbms_sa_codes",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          "Number N of MBMS service area codes", HFILL}
        },
        {&hf_gtp_mbms_ses_dur_days,
         {"Estimated session duration days", "gtp.mbms_ses_dur_days",
          FT_UINT8, BASE_DEC, NULL, 0xfe,
          NULL, HFILL}
        },
        {&hf_gtp_mbms_ses_dur_s,
         {"Estimated session duration seconds", "gtp.mbms_ses_dur_s",
          FT_UINT24, BASE_DEC, NULL, 0x01ffff,
          NULL, HFILL}
        },
        {&hf_gtp_mbms_sa_code,
         {"MBMS service area code", "gtp.mbms_sa_code",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtp_mbs_2g_3g_ind,
         {"MBMS 2G/3G Indicator", "gtp.mbs_2g_3g_ind",
          FT_UINT8, BASE_DEC, VALS(gtp_mbs_2g_3g_ind_vals), 0x0,
          NULL, HFILL}
        },
        {&hf_gtp_time_2_dta_tr,
         {"Time to MBMS Data Transfer", "gtp.time_2_dta_tr",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        { &hf_gtp_ext_ei,
          {"Error Indication (EI)", "gtp.ei",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           NULL, HFILL}
        },
        {&hf_gtp_ext_gcsi,
         {"GPRS-CSI (GCSI)", "gtp.gcsi",
          FT_UINT8, BASE_DEC, NULL, 0x02,
          NULL, HFILL}
        },
        { &hf_gtp_ext_dti,
          {"Direct Tunnel Indicator (DTI)", "gtp.dti",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           NULL, HFILL}
        },
        { &hf_gtp_ra_prio_lcs,
          {"Radio Priority LCS", "gtp.raplcs",
           FT_UINT8, BASE_DEC, NULL, 0x07,
           NULL, HFILL}
        },
        { &hf_gtp_bcm,
         {"Bearer Control Mode", "gtp.bcm",
          FT_UINT8, BASE_DEC, VALS(gtp_pdp_bcm_type_vals), 0,
          NULL, HFILL}
        },
		{ &hf_gtp_rim_routing_addr,
         {"RIM Routing Address value", "gtp.rim_routing_addr_val",
          FT_BYTES, BASE_NONE, NULL, 0,
          NULL, HFILL}
        },
    };

    static gint *ett_gtp_array[] = {
        &ett_gtp,
        &ett_gtp_flags,
        &ett_gtp_ext,
        &ett_gtp_rai,
        &ett_gtp_qos,
        &ett_gtp_auth_tri,
        &ett_gtp_flow_ii,
        &ett_gtp_rab_cntxt,
        &ett_gtp_rp,
        &ett_gtp_pkt_flow_id,
        &ett_gtp_chrg_char,
        &ett_gtp_user,
        &ett_gtp_mm,
        &ett_gtp_trip,
        &ett_gtp_quint,
        &ett_gtp_pdp,
        &ett_gtp_apn,
        &ett_gtp_proto,
        &ett_gtp_gsn_addr,
        &ett_gtp_tft,
        &ett_gtp_tft_pf,
        &ett_gtp_tft_flags,
        &ett_gtp_rab_setup,
        &ett_gtp_hdr_list,
        &ett_gtp_chrg_addr,
        &ett_gtp_node_addr,
        &ett_gtp_rel_pack,
        &ett_gtp_can_pack,
        &ett_gtp_data_resp,
        &ett_gtp_priv_ext,
        &ett_gtp_net_cap,
        &ett_gtp_ext_tree_apn_res,
        &ett_gtp_ext_rat_type,
        &ett_gtp_ext_imeisv,
        &ett_gtp_ext_ran_tr_cont,
        &ett_gtp_ext_pdp_cont_prio,
        &ett_gtp_ext_ssgn_no,
        &ett_gtp_ext_rab_setup_inf,
        &ett_gtp_ext_common_flgs,
        &ett_gtp_ext_usr_loc_inf,
        &ett_gtp_ext_ms_time_zone,
        &ett_gtp_ext_camel_chg_inf_con,
        &ett_GTP_EXT_MBMS_UE_CTX,
        &ett_gtp_ext_tmgi,
        &ett_gtp_tmgi,
        &ett_gtp_ext_rim_ra,
        &ett_gtp_ext_mbms_prot_conf_opt,
        &ett_gtp_ext_mbms_sa,
        &ett_gtp_ext_bms_ses_dur,
        &ett_gtp_ext_src_rnc_pdp_ctx_inf,
        &ett_gtp_ext_add_trs_inf,
        &ett_gtp_ext_hop_count,
        &ett_gtp_ext_sel_plmn_id,
        &ett_gtp_ext_mbms_ses_id,
        &ett_gtp_ext_mbms_2g_3g_ind,
        &ett_gtp_ext_enh_nsapi,
        &ett_gtp_ext_ad_mbms_trs_inf,
        &ett_gtp_ext_mbms_ses_id_rep_no,
        &ett_gtp_ext_mbms_time_to_data_tr,
        &ett_gtp_ext_ps_ho_req_ctx,
        &ett_gtp_ext_bss_cont,
        &ett_gtp_ext_cell_id,
        &ett_gtp_ext_pdu_no,
        &ett_gtp_ext_bssgp_cause,
        &ett_gtp_ext_ra_prio_lcs,
        &ett_gtp_ext_ps_handover_xid,
        &ett_gtp_target_id,
        &ett_gtp_utran_cont,
        &ett_gtp_bcm,
        &ett_gtp_cdr_ver,
        &ett_gtp_cdr_dr,
        &ett_gtp_ext_hdr,
		&ett_gtp_uli_rai,
    };

    module_t *gtp_module;

    proto_gtp = proto_register_protocol("GPRS Tunneling Protocol", "GTP", "gtp");
    proto_register_field_array(proto_gtp, hf_gtp, array_length(hf_gtp));
    proto_register_subtree_array(ett_gtp_array, array_length(ett_gtp_array));

    gtp_module = prefs_register_protocol(proto_gtp, proto_reg_handoff_gtp);

    prefs_register_uint_preference(gtp_module, "v0_port", "GTPv0 and GTP' port", "GTPv0 and GTP' port (default 3386)", 10, &g_gtpv0_port);
    prefs_register_uint_preference(gtp_module, "v1c_port", "GTPv1 or GTPv2 control plane (GTP-C, GTPv2-C) port", "GTPv1 and GTPv2 control plane port (default 2123)", 10,
                                   &g_gtpv1c_port);
    prefs_register_uint_preference(gtp_module, "v1u_port", "GTPv1 user plane (GTP-U) port", "GTPv1 user plane port (default 2152)", 10,
                                   &g_gtpv1u_port);
    prefs_register_bool_preference(gtp_module, "dissect_tpdu", "Dissect T-PDU", "Dissect T-PDU", &g_gtp_tpdu);

    prefs_register_obsolete_preference(gtp_module, "v0_dissect_cdr_as");
    prefs_register_obsolete_preference(gtp_module, "v0_check_etsi");
    prefs_register_obsolete_preference(gtp_module, "v1_check_etsi");
    prefs_register_bool_preference(gtp_module, "check_etsi", "Compare GTP order with ETSI", "GTP ETSI order", &g_gtp_etsi_order);
    prefs_register_obsolete_preference(gtp_module, "ppp_reorder");

    /* This preference can be used to disable the dissection of GTP over TCP. Most of the Wireless operators uses GTP over UDP.
     * The preference is set to TRUE by default forbackward compatibility
     */
    prefs_register_bool_preference(gtp_module, "dissect_gtp_over_tcp", "Dissect GTP over TCP", "Dissect GTP over TCP", &g_gtp_over_tcp);

    register_dissector("gtp", dissect_gtp, proto_gtp);
    register_dissector("gtpprim", dissect_gtpprim, proto_gtp);

    gtp_priv_ext_dissector_table = register_dissector_table("gtp.priv_ext", "GTP PRIVATE EXT", FT_UINT16, BASE_DEC);
    gtp_cdr_fmt_dissector_table = register_dissector_table("gtp.cdr_fmt", "GTP DATA RECORD TYPE", FT_UINT16, BASE_DEC);

    register_init_routine(gtp_reinit);
    gtp_tap=register_tap("gtp");
}
/* TS 132 295 V9.0.0 (2010-02)
 * 5.1.3 Port usage
 * - The UDP Destination Port may be the server port number 3386 which has been reserved for GTP'.
 * Alternatively another port can be used, which has been configured by O&M, except Port Number 2123
 * which is used by GTPv2-C.
 * :
 * The TCP Destination Port may be the server port number 3386, which has been reserved for G-PDUs. Alternatively,
 * another port may be used as configured by O&M. Extra implementation-specific destination ports are possible but
 * all CGFs shall support the server port number.
 */

void proto_reg_handoff_gtp(void)
{
    static gboolean Initialized = FALSE;
    static dissector_handle_t gtp_handle, gtp_prim_handle;
    static gboolean gtp_over_tcp;
    static guint gtpv0_port;
    static guint gtpv1c_port;
    static guint gtpv1u_port;

    if (!Initialized) {
        gtp_handle = find_dissector("gtp");
        gtp_prim_handle = find_dissector("gtpprim");
        ppp_subdissector_table = find_dissector_table("ppp.protocol");

        radius_register_avp_dissector(VENDOR_THE3GPP, 5, dissect_radius_qos_umts);
        radius_register_avp_dissector(VENDOR_THE3GPP, 12, dissect_radius_selection_mode);
        radius_register_avp_dissector(VENDOR_THE3GPP, 22, dissect_radius_user_loc);



        ip_handle = find_dissector("ip");
        ipv6_handle = find_dissector("ipv6");
        ppp_handle = find_dissector("ppp");
        data_handle = find_dissector("data");
        gtpcdr_handle = find_dissector("gtpcdr");
        sndcpxid_handle = find_dissector("sndcpxid");
        gtpv2_handle = find_dissector("gtpv2");
        bssgp_handle = find_dissector("bssgp");
        bssap_pdu_type_table = find_dissector_table("bssap.pdu_type");
        /* AVP Code: 5 3GPP-GPRS Negotiated QoS profile */
        dissector_add_uint("diameter.3gpp", 5, new_create_dissector_handle(dissect_diameter_3gpp_qosprofile, proto_gtp));
        /* AVP Code: 903 MBMS-Service-Area */
        dissector_add_uint("diameter.3gpp", 903, new_create_dissector_handle(dissect_gtp_3gpp_mbms_service_area, proto_gtp));
        /* AVP Code: 904 MBMS-Session-Duration */
        dissector_add_uint("diameter.3gpp", 904, new_create_dissector_handle(dissect_gtp_mbms_ses_dur, proto_gtp));
        /* AVP Code: 911 MBMS-Time-To-Data-Transfer */
        dissector_add_uint("diameter.3gpp", 911, new_create_dissector_handle(dissect_gtp_mbms_time_to_data_tr, proto_gtp));

        Initialized = TRUE;
    } else {
        dissector_delete_uint("udp.port", gtpv0_port, gtp_prim_handle);
        dissector_delete_uint("udp.port", gtpv1c_port, gtp_handle);
        dissector_delete_uint("udp.port", gtpv1u_port, gtp_handle);

        if (gtp_over_tcp) {
            dissector_delete_uint("tcp.port", gtpv0_port, gtp_prim_handle);
            dissector_delete_uint("tcp.port", gtpv1c_port, gtp_handle);
            dissector_delete_uint("tcp.port", gtpv1u_port, gtp_handle);
        }
    }

    gtp_over_tcp = g_gtp_over_tcp;
    gtpv0_port   = g_gtpv0_port;
    gtpv1c_port  = g_gtpv1c_port;
    gtpv1u_port  = g_gtpv1u_port;

    dissector_add_uint("udp.port", g_gtpv0_port, gtp_prim_handle);
    dissector_add_uint("udp.port", g_gtpv1c_port, gtp_handle);
    dissector_add_uint("udp.port", g_gtpv1u_port, gtp_handle);

    if (g_gtp_over_tcp) {
        dissector_add_uint("tcp.port", g_gtpv0_port, gtp_prim_handle);
        dissector_add_uint("tcp.port", g_gtpv1c_port, gtp_handle);
        dissector_add_uint("tcp.port", g_gtpv1u_port, gtp_handle);
    }
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
