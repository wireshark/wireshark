/* packet-gtp.c
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
 * Copyright 2011-2013, Anders Broman <anders.broman@ericsson.com>
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
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * GTP v0: 3GPP TS 09.60
 *
 *    http://www.3gpp.org/ftp/Specs/html-info/0960.htm
 *
 * GTP v1: 3GPP TS 29.060
 *
 *    http://www.3gpp.org/ftp/Specs/html-info/29060.htm
 *
 * GTP': 3GPP TS 32.295
 *
 *    http://www.3gpp.org/ftp/Specs/html-info/32295.htm
 */

#include "config.h"

#include <math.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/sminmpec.h>
#include <epan/addr_resolv.h>
#include <epan/asn1.h>
#include <epan/tap.h>
#include <epan/srt_table.h>
#include <epan/to_str.h>
#include <epan/uat.h>
#include <epan/proto_data.h>
#include <epan/etypes.h>

#include "packet-ppp.h"
#include "packet-radius.h"
#include "packet-gsm_a_common.h"
#include "packet-gsm_map.h"
#include "packet-gprscdr.h"
#include "packet-bssgp.h"
#include "packet-rrc.h"
#include "packet-e212.h"
#include "packet-e164.h"
#include "packet-gtp.h"
#include "packet-ranap.h"
#include "packet-pdcp-nr.h"
#include "packet-pdcp-lte.h"
#include "packet-rohc.h"

void proto_register_gtp(void);
void proto_reg_handoff_gtp(void);

static dissector_table_t gtp_priv_ext_dissector_table;
static dissector_table_t gtp_cdr_fmt_dissector_table;
static dissector_table_t gtp_hdr_ext_dissector_table;
static dissector_handle_t gtp_handle, gtp_prime_handle;
static dissector_handle_t nrup_handle;

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

#define GTP_TPDU_AS_NONE -1
#define GTP_TPDU_AS_TPDU_HEUR 0
#define GTP_TPDU_AS_PDCP_LTE 1
#define GTP_TPDU_AS_PDCP_NR 2
#define GTP_TPDU_AS_SYNC 3
#define GTP_TPDU_AS_ETHERNET 4
#define GTP_TPDU_AS_CUSTOM 5

static gboolean g_gtp_over_tcp = TRUE;
gboolean g_gtp_session = FALSE;

static guint pref_pair_matching_max_interval_ms = 0; /* Default: disable */

static guint g_gtpv0_port  = GTPv0_PORT;
static guint g_gtpv1c_port = GTPv1C_PORT;
static guint g_gtpv1u_port = GTPv1U_PORT;

static int proto_gtp = -1;
static int proto_gtpprime = -1;

/*KTi*/
static int hf_gtp_ie_id = -1;
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
static int hf_gtp_ext_hdr_ran_cont = -1;
static int hf_gtp_ext_hdr_spare_bits = -1;
static int hf_gtp_ext_hdr_spare_bytes = -1;
static int hf_gtp_ext_hdr_long_pdcp_sn = -1;
static int hf_gtp_ext_hdr_xw_ran_cont = -1;
static int hf_gtp_ext_hdr_pdcpsn = -1;
static int hf_gtp_ext_hdr_udp_port = -1;
static int hf_gtp_flags = -1;
static int hf_gtp_flags_ver = -1;
static int hf_gtp_prime_flags_ver = -1;
static int hf_gtp_flags_pt = -1;
static int hf_gtp_flags_spare1 = -1;
static int hf_gtp_flags_hdr_length = -1;
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
static int hf_gtp_length = -1;
static int hf_gtp_map_cause = -1;
static int hf_gtp_message_type = -1;
static int hf_gtp_ms_reason = -1;
static int hf_gtp_ms_valid = -1;
static int hf_gtp_npdu_number = -1;
static int hf_gtp_node_ipv4 = -1;
static int hf_gtp_node_ipv6 = -1;
static int hf_gtp_node_name = -1;
static int hf_gtp_node_realm = -1;
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
static int hf_gtp_qos_spare4 = -1;
static int hf_gtp_qos_sig_ind = -1;
static int hf_gtp_qos_src_stat_desc = -1;
static int hf_gtp_qos_arp = -1;
static int hf_gtp_qos_arp_pvi = -1;
static int hf_gtp_qos_arp_pl = -1;
static int hf_gtp_qos_arp_pci = -1;
static int hf_gtp_qos_qci = -1;
static int hf_gtp_qos_ul_mbr = -1;
static int hf_gtp_qos_dl_mbr = -1;
static int hf_gtp_qos_ul_gbr = -1;
static int hf_gtp_qos_dl_gbr = -1;
static int hf_gtp_qos_ul_apn_ambr = -1;
static int hf_gtp_qos_dl_apn_ambr = -1;
static int hf_gtp_pkt_flow_id = -1;
static int hf_gtp_rab_gtpu_dn = -1;
static int hf_gtp_rab_gtpu_up = -1;
static int hf_gtp_rab_pdu_dn = -1;
static int hf_gtp_rab_pdu_up = -1;
static int hf_gtp_uli_geo_loc_type = -1;
static int hf_gtp_cgi_ci = -1;
static int hf_gtp_sai_sac = -1;
static int hf_gtp_rai_rac = -1;
static int hf_gtp_lac = -1;
static int hf_gtp_tac = -1;
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
static int hf_gtp_session = -1;
static int hf_gtp_sndcp_number = -1;
static int hf_gtp_tear_ind = -1;
static int hf_gtp_teid = -1;
static int hf_gtp_teid_cp = -1;
static int hf_gtp_uplink_teid_cp = -1;
static int hf_gtp_teid_data = -1;
static int hf_gtp_uplink_teid_data = -1;
static int hf_gtp_teid_ii = -1;
static int hf_gtp_tid = -1;
static int hf_gtp_tlli = -1;
static int hf_gtp_tr_comm = -1;
static int hf_gtp_trace_ref = -1;
static int hf_gtp_trace_type = -1;
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
static int hf_gtp_utran_field = -1;
static int hf_gtp_ext_apn_res = -1;
static int hf_gtp_ext_rat_type = -1;
static int hf_gtp_ext_imeisv = -1;
static int hf_gtp_target_rnc_id = -1;
static int hf_gtp_target_ext_rnc_id = -1;
static int hf_gtp_bssgp_cause = -1;
static int hf_gtp_bssgp_ra_discriminator = -1;
static int hf_gtp_sapi = -1;
static int hf_gtp_xid_par_len = -1;
static int hf_gtp_rep_act_type = -1;
static int hf_gtp_correlation_id = -1;
static int hf_gtp_earp_pci = -1;
static int hf_gtp_earp_pl = -1;
static int hf_gtp_earp_pvi = -1;
static int hf_gtp_ext_comm_flags_uasi = -1;
static int hf_gtp_ext_comm_flags_bdwi = -1;
static int hf_gtp_ext_comm_flags_pcri = -1;
static int hf_gtp_ext_comm_flags_vb = -1;
static int hf_gtp_ext_comm_flags_retloc = -1;
static int hf_gtp_ext_comm_flags_cpsr = -1;
static int hf_gtp_ext_comm_flags_ccrsi = -1;
static int hf_gtp_ext_comm_flags_unauthenticated_imsi = -1;
static int hf_gtp_csg_id = -1;
static int hf_gtp_access_mode = -1;
static int hf_gtp_cmi = -1;
static int hf_gtp_csg_inf_rep_act_ucicsg = -1;
static int hf_gtp_csg_inf_rep_act_ucishc = -1;
static int hf_gtp_csg_inf_rep_act_uciuhc = -1;
static int hf_gtp_ext_comm_flags_II_pnsi = -1;
static int hf_gtp_ext_comm_flags_II_dtci = -1;
static int hf_gtp_ext_comm_flags_II_pmtsmi = -1;
static int hf_gtp_ext_comm_flags_II_spare = -1;
static int hf_gtp_ciot_opt_sup_ind_sgni_pdn = -1;
static int hf_gtp_ciot_opt_sup_ind_scni_pdn = -1;
static int hf_gtp_ciot_opt_sup_ind_spare = -1;
static int hf_gtp_up_fun_sel_ind_flags_dcnr = -1;
static int hf_gtp_up_fun_sel_ind_flags_spare = -1;
static int hf_gtp_cdr_app = -1;
static int hf_gtp_cdr_rel = -1;
static int hf_gtp_cdr_ver = -1;
static int hf_gtp_cdr_rel_ext = -1;
static int hf_gtp_cdr_length = -1;
static int hf_gtp_cdr_context = -1;
static int hf_gtp_cmn_flg_ppc = -1;
static int hf_gtp_cmn_flg_mbs_srv_type = -1;
static int hf_gtp_cmn_flg_mbs_ran_pcd_rdy = -1;
static int hf_gtp_cmn_flg_mbs_cnt_inf = -1;
static int hf_gtp_cmn_flg_nrsn = -1;
static int hf_gtp_cmn_flg_no_qos_neg = -1;
static int hf_gtp_cmn_flg_upgrd_qos_sup = -1;
static int hf_gtp_cmn_flg_dual_addr_bearer_flg = -1;
static int hf_gtp_linked_nsapi = -1;
static int hf_gtp_enh_nsapi = -1;
static int hf_gtp_tmgi = -1;
static int hf_gtp_mbms_ses_dur_days = -1;
static int hf_gtp_mbms_ses_dur_s = -1;
static int hf_gtp_no_of_mbms_sa_codes = -1;
static int hf_gtp_mbms_sa_code = -1;
static int hf_gtp_trace_ref2 = -1;
static int hf_gtp_trace_rec_session_ref = -1;
static int hf_gtp_trace_triggers_ggsn_pdp = -1;
static int hf_gtp_trace_triggers_ggsn_mbms = -1;
static int hf_gtp_trace_triggers_ggsn = -1;
static int hf_gtp_trace_depth = -1;
static int hf_gtp_trace_loi_ggsn_gmb = -1;
static int hf_gtp_trace_loi_ggsn_gi = -1;
static int hf_gtp_trace_loi_ggsn_gn = -1;
static int hf_gtp_trace_loi_ggsn = -1;
static int hf_gtp_trace_activity_control = -1;
static int hf_gtp_hop_count = -1;
static int hf_gtp_mbs_2g_3g_ind = -1;
static int hf_gtp_trace_triggers_bm_sc_mbms = -1;
static int hf_gtp_trace_triggers_bm_sc = -1;
static int hf_gtp_trace_loi_bm_sc_gmb = -1;
static int hf_gtp_trace_loi_bm_sc = -1;
static int hf_gtp_time_2_dta_tr = -1;
static int hf_gtp_target_lac = -1;
static int hf_gtp_target_rac = -1;
static int hf_gtp_target_ci = -1;
static int hf_gtp_source_type = -1;
static int hf_gtp_source_lac = -1;
static int hf_gtp_source_rac = -1;
static int hf_gtp_source_ci = -1;
static int hf_gtp_source_rnc_id = -1;
static int hf_gtp_ext_ei = -1;
static int hf_gtp_ext_gcsi = -1;
static int hf_gtp_ext_dti = -1;
static int hf_gtp_ra_prio_lcs = -1;
static int hf_gtp_bcm = -1;
static int hf_gtp_fqdn = -1;
static int hf_gtp_rim_routing_addr = -1;
static int hf_gtp_mbms_flow_id = -1;
static int hf_gtp_mbms_dist_indic = -1;
static int hf_gtp_ext_apn_ambr_ul = -1;
static int hf_gtp_ext_apn_ambr_dl = -1;
static int hf_gtp_ext_sub_ue_ambr_ul = -1;
static int hf_gtp_ext_sub_ue_ambr_dl = -1;
static int hf_gtp_ext_auth_ue_ambr_ul = -1;
static int hf_gtp_ext_auth_ue_ambr_dl = -1;
static int hf_gtp_ext_auth_apn_ambr_ul = -1;
static int hf_gtp_ext_auth_apn_ambr_dl = -1;
static int hf_gtp_ext_ggsn_back_off_time_units = -1;
static int hf_gtp_ext_ggsn_back_off_timer = -1;
static int hf_gtp_lapi = -1;
static int hf_gtp_higher_br_16mb_flg = -1;
static int hf_gtp_max_mbr_apn_ambr_ul = -1;
static int hf_gtp_max_mbr_apn_ambr_dl = -1;
static int hf_gtp_ext_enb_type = -1;
static int hf_gtp_macro_enodeb_id = -1;
static int hf_gtp_home_enodeb_id = -1;
static int hf_gtp_dummy_octets = -1;

static int hf_pdcp_cont = -1;

static int hf_gtp_ext_hdr_pdu_ses_cont_pdu_type = -1;
static int hf_gtp_ext_hdr_pdu_ses_cont_ppp = -1;
static int hf_gtp_ext_hdr_pdu_ses_cont_rqi = -1;
static int hf_gtp_ext_hdr_pdu_ses_cont_qos_flow_id = -1;
static int hf_gtp_ext_hdr_pdu_ses_cont_ppi = -1;

static int hf_gtp_spare_b4b0 = -1;
static int hf_gtp_spare_b7b6 = -1;
static int hf_gtp_spare_h1 = -1;
static int hf_gtp_rnc_ip_addr_v4 = -1;
static int hf_gtp_rnc_ip_addr_v6 = -1;
static int hf_gtp_ms_cm_2_len = -1;
static int hf_gtp_ms_cm_3_len = -1;
static int hf_gtp_sup_codec_lst_len = -1;
static int hf_gtp_add_flg_for_srvcc_ics = -1;
static int hf_gtp_sel_mode_val = -1;
static int hf_gtp_uli_timestamp = -1;
static int hf_gtp_lhn_id = -1;
static int hf_gtp_sel_entity = -1;
static int hf_gtp_ue_usage_type_value = -1;
static int hf_gtp_scef_id_length = -1;
static int hf_gtp_scef_id = -1;
static int hf_gtp_iov_updates_counter = -1;
static int hf_gtp_mapped_ue_usage_type = -1;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_gtp_rfsp_index = -1;
static int hf_gtp_quintuplet_ciphering_key = -1;
static int hf_gtp_kc = -1;
static int hf_gtp_rand = -1;
static int hf_gtp_pdp_context_identifier = -1;
static int hf_gtp_receive_n_pdu_number = -1;
static int hf_gtp_container_length = -1;
static int hf_gtp_quintuplets_length = -1;
static int hf_gtp_auth = -1;
static int hf_gtp_tft_length = -1;
static int hf_gtp_ggsn_address_for_control_plane_ipv4 = -1;
static int hf_gtp_ggsn_address_for_control_plane_ipv6 = -1;
static int hf_gtp_ggsn_address_for_user_traffic_ipv4 = -1;
static int hf_gtp_ggsn_address_for_user_traffic_ipv6 = -1;
static int hf_gtp_integrity_key_ik = -1;
static int hf_gtp_gsn_address_information_element_length = -1;
static int hf_gtp_reordering_required = -1;
static int hf_gtp_sres = -1;
static int hf_gtp_data_record_format = -1;
static int hf_gtp_timezone = -1;
static int hf_gtp_timezone_dst = -1;
static int hf_gtp_authentication_length = -1;
static int hf_gtp_send_n_pdu_number = -1;
static int hf_gtp_sequence_number_up = -1;
static int hf_gtp_pdp_address_length = -1;
static int hf_gtp_transaction_identifier = -1;
static int hf_gtp_xres_length = -1;
static int hf_gtp_ggsn_address_length = -1;
static int hf_gtp_apn_length = -1;
static int hf_gtp_sequence_number_down = -1;
static int hf_gtp_pdp_address_ipv4 = -1;
static int hf_gtp_activity_status_indicator = -1;
static int hf_gtp_pdp_type = -1;
static int hf_gtp_quintuplet_integrity_key = -1;
static int hf_gtp_pdp_address_ipv6 = -1;
static int hf_gtp_rab_setup_length = -1;
static int hf_gtp_number_of_data_records = -1;
static int hf_gtp_ciphering_key_kc = -1;
static int hf_gtp_pdp_cntxt_sapi = -1;
static int hf_gtp_xres = -1;
static int hf_gtp_pdp_organization = -1;
static int hf_gtp_node_address_length = -1;
static int hf_gtp_gsn_address_length = -1;
static int hf_gtp_vplmn_address_allowed = -1;
static int hf_gtp_uplink_flow_label_signalling = -1;
static int hf_gtp_extended_end_user_address = -1;
static int hf_gtp_ciphering_key_ck = -1;
static int hf_gtp_fqdn_length = -1;
static int hf_gtp_seq_num_released = -1;
static int hf_gtp_seq_num_canceled = -1;
static int hf_gtp_requests_responded = -1;
static int hf_gtp_hyphen_separator = -1;
static int hf_gtp_ms_network_cap_content_len = -1;
static int hf_gtp_iei = -1;
static int hf_gtp_iei_mobile_id_len = -1;
static int hf_gtp_qos_umts_length = -1;
static int hf_gtp_num_ext_hdr_types = -1;
static int hf_gtp_ext_hdr_type = -1;
static int hf_gtp_tpdu_data = -1;

static int hf_gtp_sgsn_address_for_control_plane_ipv4 = -1;
static int hf_gtp_sgsn_address_for_control_plane_ipv6 = -1;
static int hf_gtp_sgsn_address_for_user_traffic_ipv4 = -1;
static int hf_gtp_sgsn_address_for_user_traffic_ipv6 = -1;

/* Initialize the subtree pointers */
static gint ett_gtp = -1;
static gint ett_gtp_flags = -1;
static gint ett_gtp_ext = -1;
static gint ett_gtp_ext_hdr = -1;
static gint ett_gtp_qos = -1;
static gint ett_gtp_qos_arp = -1;
static gint ett_gtp_flow_ii = -1;
static gint ett_gtp_rp = -1;
static gint ett_gtp_pkt_flow_id = -1;
static gint ett_gtp_trip = -1;
static gint ett_gtp_quint = -1;
static gint ett_gtp_proto = -1;
static gint ett_gtp_gsn_addr = -1;
static gint ett_gtp_tft = -1;
static gint ett_gtp_rab_setup = -1;
static gint ett_gtp_hdr_list = -1;
static gint ett_gtp_node_addr = -1;
static gint ett_gtp_rel_pack = -1;
static gint ett_gtp_can_pack = -1;
static gint ett_gtp_data_resp = -1;
static gint ett_gtp_drx = -1;
static gint ett_gtp_net_cap = -1;
static gint ett_gtp_tmgi = -1;
static gint ett_gtp_cdr_ver = -1;
static gint ett_gtp_cdr_dr = -1;
static gint ett_gtp_mm_cntxt = -1;
static gint ett_gtp_utran_cont = -1;
static gint ett_gtp_nr_ran_cont = -1;
static gint ett_gtp_pdcp_no_conf = -1;
static gint ett_pdu_session_cont = -1;
static gint ett_gtp_trace_triggers_ggsn = -1;
static gint ett_gtp_trace_loi_ggsn = -1;
static gint ett_gtp_trace_triggers_bm_sc = -1;
static gint ett_gtp_trace_loi_bm_sc = -1;
static gint ett_gtp_bss_cont = -1;
static gint ett_gtp_lst_set_up_pfc = -1;
static gint ett_gtp_rrc_cont = -1;

static expert_field ei_gtp_ext_hdr_pdcpsn = EI_INIT;
static expert_field ei_gtp_ext_length_mal = EI_INIT;
static expert_field ei_gtp_ext_length_warn = EI_INIT;
static expert_field ei_gtp_undecoded = EI_INIT;
static expert_field ei_gtp_message_not_found = EI_INIT;
static expert_field ei_gtp_field_not_present = EI_INIT;
static expert_field ei_gtp_wrong_next_field = EI_INIT;
static expert_field ei_gtp_field_not_support_in_version = EI_INIT;
static expert_field ei_gtp_guaranteed_bit_rate_value = EI_INIT;
static expert_field ei_gtp_max_bit_rate_value = EI_INIT;
static expert_field ei_gtp_ext_geo_loc_type = EI_INIT;
static expert_field ei_gtp_iei = EI_INIT;
static expert_field ei_gtp_unknown_extension_header = EI_INIT;
static expert_field ei_gtp_unknown_pdu_type = EI_INIT;
static expert_field ei_gtp_source_type_unknown = EI_INIT;
static expert_field ei_gtp_cdr_rel_ext_invalid = EI_INIT;

static const range_string assistance_info_type[] = {
    { 0,   0,   "UNKNOWN" },
    { 1,   1,   "Average CQL" },
    { 2,   2,   "Average HARQ Failure" },
    { 3,   3,   "Average HARQ Retransmissions" },
    { 4,   4,   "DL Radio Quality Index" },
    { 5,   5,   "UL Radio Quality Index" },
    { 6,   6,   "Power Headroom Report" },
    { 7,   228, "reserved for future value extensions" },
    { 229, 255, "reserved for test purposes" },
    { 0,   0,   NULL}
};


/* NRUP - TS 38.425 */
/* NR-U RAN Container */
static int proto_nrup = -1;
static int hf_nrup_pdu_type = -1;
static int hf_nrup_spr_bit_extnd_flag = -1;
static int hf_nrup_dl_discrd_blks = -1;
static int hf_nrup_dl_flush = -1;
static int hf_nrup_rpt_poll = -1;
static int hf_nrup_retransmission_flag = -1;
static int hf_nrup_ass_inf_rep_poll_flag = -1;
static int hf_nrup_spare = -1;
static int hf_nrup_request_out_of_seq_report = -1;
static int hf_nrup_report_delivered = -1;
static int hf_nrup_user_data_existence_flag = -1;
static int hf_nrup_nr_u_seq_num = -1;
static int hf_nrup_dl_disc_nr_pdcp_pdu_sn = -1;
static int hf_nrup_dl_disc_num_blks = -1;
static int hf_nrup_dl_disc_nr_pdcp_pdu_sn_start = -1;
static int hf_nrup_dl_disc_blk_sz = -1;
static int hf_nrup_dl_report_nr_pdcp_pdu_sn = -1;
static int hf_nrup_high_tx_nr_pdcp_sn_ind = -1;
static int hf_nrup_high_delivered_nr_pdcp_sn_ind = -1;
static int hf_nrup_final_frame_ind = -1;
static int hf_nrup_lost_pkt_rpt = -1;
static int hf_nrup_high_retx_nr_pdcp_sn_ind = -1;
static int hf_nrup_high_delivered_retx_nr_pdcp_sn_ind = -1;
static int hf_nrup_cause_rpt = -1;
static int hf_nrup_delivered_nr_pdcp_sn_range_ind = -1;
static int hf_nrup_data_rate_ind = -1;
static int hf_nrup_desrd_buff_sz_data_radio_bearer = -1;
static int hf_nrup_desrd_data_rate = -1;
static int hf_nrup_num_lost_nru_seq_num = -1;
static int hf_nrup_start_lost_nru_seq_num = -1;
static int hf_nrup_end_lost_nru_seq_num = -1;
static int hf_nrup_high_success_delivered_nr_pdcp_sn = -1;
static int hf_nrup_high_tx_nr_pdcp_sn = -1;
static int hf_nrup_cause_val = -1;
static int hf_nrup_high_success_delivered_retx_nr_pdcp_sn = -1;
static int hf_nrup_high_retx_nr_pdcp_sn = -1;
static int hf_nrup_pdcp_duplication_ind = -1;
static int hf_nrup_assistance_information_ind = -1;
static int hf_nrup_ul_delay_ind = -1;
static int hf_nrup_dl_delay_ind = -1;
static int hf_nrup_spare_2 = -1;
static int hf_nrup_pdcp_duplication_activation_suggestion = -1;
static int hf_nrup_num_assistance_info_fields = -1;
static int hf_nrup_assistance_information_type = -1;
static int hf_nrup_num_octets_radio_qa_info = -1;
static int hf_nrup_radio_qa_info = -1;
static int hf_nrup_ul_delay_du_result = -1;
static int hf_nrup_dl_delay_du_result = -1;

static gint ett_nrup = -1;



/* --- PDCP DECODE ADDITIONS --- */
static gboolean
pdcp_uat_fld_ip_chk_cb(void* r _U_, const char* ipaddr, guint len _U_, const void* u1 _U_, const void* u2 _U_, char** err)
{
    ws_in4_addr ip4_addr;
    ws_in6_addr ip6_addr;

    /* Check for a valid IPv4 or IPv6 address */
    if (ipaddr &&
        (ws_inet_pton6(ipaddr, &ip6_addr) ||
         ws_inet_pton4(ipaddr, &ip4_addr))) {
        *err = NULL;
        return TRUE;
    }

    *err = ws_strdup_printf("No valid IP address given");
    return FALSE;
}

#define PDCP_TEID_WILDCARD "*"

static gboolean
pdcp_uat_fld_teid_chk_cb(void* r _U_, const char* teid, guint len _U_, const void* u1 _U_, const void* u2 _U_, char** err)
{
    if (teid) {
        guint32 val;

        /* Check if it is a wildcard TEID */
        if (!strcmp(teid, PDCP_TEID_WILDCARD)) {
            *err = NULL;
            return TRUE;
        }
        /* Check if it is a valid 32bits unsinged integer */
        if (ws_basestrtou32(teid, NULL, &val, 0)) {
            *err = NULL;
            return TRUE;
        }
    }

    *err = ws_strdup_printf("No valid TEID given");
    return FALSE;
}

typedef struct {
    gchar *ip_addr_str;
    address ip_address;
    gchar *teid_str;
    gboolean teid_wildcard;
    guint32 teid;
    guint header_present;
    enum pdcp_plane plane;
    guint lte_sn_length;
    guint rohc_compression;
    //guint rohc_mode;
    guint rohc_profile;
} uat_pdcp_lte_keys_record_t;

/* N.B. this is an array/table of the struct above, where IP address + TEID is the key */
static uat_pdcp_lte_keys_record_t *uat_pdcp_lte_keys_records = NULL;

static gboolean pdcp_lte_update_cb(void *r, char **err)
{
    uat_pdcp_lte_keys_record_t* rec = (uat_pdcp_lte_keys_record_t *)r;
    ws_in4_addr ip4_addr;
    ws_in6_addr ip6_addr;

    if (!strcmp(rec->teid_str, PDCP_TEID_WILDCARD)) {
        rec->teid_wildcard = TRUE;
        rec->teid = 0;
    } else if (ws_basestrtou32(rec->teid_str, NULL, &rec->teid, 0)) {
        rec->teid_wildcard = FALSE;
    } else {
        if (err)
            *err = ws_strdup_printf("No valid TEID given");
        return FALSE;
    }

    free_address_wmem(wmem_epan_scope(), &rec->ip_address);
    if (ws_inet_pton6(rec->ip_addr_str, &ip6_addr)) {
        alloc_address_wmem(wmem_epan_scope(), &rec->ip_address, AT_IPv6, sizeof(ws_in6_addr), &ip6_addr);
    } else if (ws_inet_pton4(rec->ip_addr_str, &ip4_addr)) {
        alloc_address_wmem(wmem_epan_scope(), &rec->ip_address, AT_IPv4, sizeof(ws_in4_addr), &ip4_addr);
    } else {
        if (err)
            *err = ws_strdup_printf("No valid IP address given");
        return FALSE;
    }

    return TRUE;
}

static void *pdcp_lte_copy_cb(void *n, const void *o, size_t len _U_)
{
    uat_pdcp_lte_keys_record_t* new_rec = (uat_pdcp_lte_keys_record_t *)n;
    const uat_pdcp_lte_keys_record_t* old_rec = (const uat_pdcp_lte_keys_record_t *)o;

    /* Copy UAT fields */
    new_rec->ip_addr_str = g_strdup(old_rec->ip_addr_str);
    clear_address(&new_rec->ip_address);
    new_rec->teid_str = g_strdup(old_rec->teid_str);
    new_rec->header_present = old_rec->header_present;
    new_rec->plane = old_rec->plane;
    new_rec->lte_sn_length = old_rec->lte_sn_length;
    new_rec->rohc_compression = old_rec->rohc_compression;
    //new_rec->rohc_mode = old_rec->rohc_mode;
    new_rec->rohc_profile = old_rec->rohc_profile;

    pdcp_lte_update_cb(new_rec, NULL);

    return new_rec;
}

static void pdcp_lte_free_cb(void *r)
{
    uat_pdcp_lte_keys_record_t* rec = (uat_pdcp_lte_keys_record_t *)r;

    g_free(rec->ip_addr_str);
    g_free(rec->teid_str);
    free_address_wmem(wmem_epan_scope(), &rec->ip_address);
}

#define PDCP_SN_LENGTH_12_BITS_STR "12 bits"
static const value_string vs_pdcp_lte_sn_length[] = {
    {PDCP_SN_LENGTH_5_BITS,  "5 bits"},
    {PDCP_SN_LENGTH_7_BITS,  "7 bits"},
    {PDCP_SN_LENGTH_12_BITS, PDCP_SN_LENGTH_12_BITS_STR},
    {PDCP_SN_LENGTH_15_BITS, "15 bits"},
    {PDCP_SN_LENGTH_18_BITS, "18 bits"},
    {0, NULL}
};

/* Struct for saving PDCP-NR information about specific TEID */
typedef struct {
    gchar *ip_addr_str;
    address ip_address;
    gchar *teid_str;
    gboolean teid_wildcard;
    guint32 teid;
    guint direction;
    /* PDCP_NR_(U|D)L_sdap_hdr_PRESENT bitmask */
    guint sdap_header_present;
    guint mac_i_present;
    enum pdcp_nr_plane plane;
    guint pdcp_nr_sn_length;
    guint rohc_compression;
    //guint rohc_mode;
    guint rohc_profile;
} uat_pdcp_nr_keys_record_t;

/* N.B. this is an array/table of the struct above, where IP address + TEID is the key */
static uat_pdcp_nr_keys_record_t *uat_pdcp_nr_keys_records = NULL;

static gboolean pdcp_nr_update_cb(void *r, char **err) {
    uat_pdcp_nr_keys_record_t* rec = (uat_pdcp_nr_keys_record_t *)r;
    ws_in4_addr ip4_addr;
    ws_in6_addr ip6_addr;

    if (!strcmp(rec->teid_str, PDCP_TEID_WILDCARD)) {
        rec->teid_wildcard = TRUE;
        rec->teid = 0;
    } else if (ws_basestrtou32(rec->teid_str, NULL, &rec->teid, 0)) {
        rec->teid_wildcard = FALSE;
    } else {
        if (err)
            *err = ws_strdup_printf("No valid TEID given");
        return FALSE;
    }

    free_address_wmem(wmem_epan_scope(), &rec->ip_address);
    if (ws_inet_pton6(rec->ip_addr_str, &ip6_addr)) {
        alloc_address_wmem(wmem_epan_scope(), &rec->ip_address, AT_IPv6, sizeof(ws_in6_addr), &ip6_addr);
    } else if (ws_inet_pton4(rec->ip_addr_str, &ip4_addr)) {
        alloc_address_wmem(wmem_epan_scope(), &rec->ip_address, AT_IPv4, sizeof(ws_in4_addr), &ip4_addr);
    } else {
        if (err)
            *err = ws_strdup_printf("No valid IP address given");
        return FALSE;
    }

    return TRUE;
}

static void *pdcp_nr_copy_cb(void *n, const void *o, size_t len _U_) {
    uat_pdcp_nr_keys_record_t* new_rec = (uat_pdcp_nr_keys_record_t *)n;
    const uat_pdcp_nr_keys_record_t* old_rec = (const uat_pdcp_nr_keys_record_t *)o;

    /* Copy UAT fields */
    new_rec->ip_addr_str = g_strdup(old_rec->ip_addr_str);
    clear_address(&new_rec->ip_address);
    new_rec->teid_str = g_strdup(old_rec->teid_str);
    new_rec->direction = old_rec->direction;
    new_rec->sdap_header_present = old_rec->sdap_header_present;
    new_rec->mac_i_present = old_rec->mac_i_present;
    new_rec->plane = old_rec->plane;
    new_rec->pdcp_nr_sn_length = old_rec->pdcp_nr_sn_length;
    new_rec->rohc_compression = old_rec->rohc_compression;
    //new_rec->rohc_mode = old_rec->rohc_mode;
    new_rec->rohc_profile = old_rec->rohc_profile;

    pdcp_nr_update_cb(new_rec, NULL);

    return new_rec;
}

static void pdcp_nr_free_cb(void *r)
{
    uat_pdcp_nr_keys_record_t* rec = (uat_pdcp_nr_keys_record_t *)r;

    g_free(rec->ip_addr_str);
    g_free(rec->teid_str);
    free_address_wmem(wmem_epan_scope(), &rec->ip_address);
}

#define PDCP_NR_DIRECTION_UPLINK_STR "UL"
static const value_string vs_direction[] = {
    { PDCP_NR_DIRECTION_UPLINK, PDCP_NR_DIRECTION_UPLINK_STR },
    { PDCP_NR_DIRECTION_DOWNLINK, "DL" },
    { 0, NULL }
};

/* Value sets for each drop-down list in the GUI */
#define PDCP_NR_SDAP_HEADER_NOT_PRESENT_STR "SDAP header NOT present"
#define PDCP_NR_SDAP_HEADER_NOT_PRESENT 0
#define PDCP_NR_SDAP_HEADER_PRESENT 1
static const value_string vs_sdap_header_present[] = {
    { 0, PDCP_NR_SDAP_HEADER_NOT_PRESENT_STR },
    { 1, "SDAP header present" },
    { 0, NULL }
};

#define PDCP_LTE_HEADER_PRESENT_STR "Header present"
#define PDCP_LTE_HEADER_NOT_PRESENT 0
#define PDCP_LTE_HEADER_PRESENT 1

static const value_string vs_header_present[] = {
    { 0, "Header NOT present" },
    { 1, PDCP_LTE_HEADER_PRESENT_STR },
    { 0, NULL }
};


#define MAC_I_PRESENT_FALSE_STR "MAC-I NOT present"
static const value_string vs_mac_i_present[] = {
    { FALSE, MAC_I_PRESENT_FALSE_STR },
    { TRUE, "MAC-I present" },
    { 0, NULL }
};

#define USER_PLANE_STR "User plane"
static const value_string vs_pdcp_plane[] = {
    { NR_SIGNALING_PLANE, "Signaling plane" },
    { NR_USER_PLANE, USER_PLANE_STR },
    { 0, NULL }
};

static const value_string vs_pdcp_nr_sn_length[] = {
    { PDCP_NR_SN_LENGTH_12_BITS, PDCP_SN_LENGTH_12_BITS_STR },
    { PDCP_NR_SN_LENGTH_18_BITS, "18 bits" },
    { 0, NULL }
};

#define ROHC_COMPRESSION_FALSE_STR "RoHC NOT compressed"
static const value_string vs_rohc_compression[] = {
    { FALSE, ROHC_COMPRESSION_FALSE_STR },
    { TRUE, "RoHC compressed" },
    { 0, NULL }
};

//#define ROHC_MODE_NOT_SET_STR "Mode not set"
//static const value_string vs_rohc_mode[] = {
//    { MODE_NOT_SET, ROHC_MODE_NOT_SET_STR },
//    { UNIDIRECTIONAL, "Unidirectional" },
//    { OPTIMISTIC_BIDIRECTIONAL, "Optimistic bidirectional" },
//    { RELIABLE_BIDIRECTIONAL, "Reliable bidirectional" },
//    { 0, NULL }
//};

#define ROHC_PROFILE_RTP_STR "RTP (1)"
#define ROHC_PROFILE_UNCOMPRESSED_STR "Uncompressed (0)"
static const value_string vs_rohc_profile[] = {
    { ROHC_PROFILE_UNCOMPRESSED, ROHC_PROFILE_UNCOMPRESSED_STR },
    { ROHC_PROFILE_RTP, ROHC_PROFILE_RTP_STR },
    { ROHC_PROFILE_UDP, "UDP (2)" },
    { ROHC_PROFILE_IP, "IP (4)" },
    { ROHC_PROFILE_UNKNOWN, "Unknown" },
    { 0, NULL }
};

/* Entries added by UAT */
static uat_t * pdcp_nr_keys_uat = NULL;
static guint num_pdcp_nr_keys_uat = 0;

/* Default values for a TEID entry */
UAT_CSTRING_CB_DEF(pdcp_nr_users, ip_addr_str, uat_pdcp_nr_keys_record_t)
UAT_CSTRING_CB_DEF(pdcp_nr_users, teid_str, uat_pdcp_nr_keys_record_t)
UAT_VS_DEF(pdcp_nr_users, direction, uat_pdcp_nr_keys_record_t, guint, PDCP_NR_DIRECTION_UPLINK, PDCP_NR_DIRECTION_UPLINK_STR)
UAT_VS_DEF(pdcp_nr_users, sdap_header_present, uat_pdcp_nr_keys_record_t, guint, PDCP_NR_SDAP_HEADER_NOT_PRESENT, PDCP_NR_SDAP_HEADER_NOT_PRESENT_STR)
UAT_VS_DEF(pdcp_nr_users, mac_i_present, uat_pdcp_nr_keys_record_t, guint, FALSE, MAC_I_PRESENT_FALSE_STR)
UAT_VS_DEF(pdcp_nr_users, plane, uat_pdcp_nr_keys_record_t, enum pdcp_nr_plane, NR_USER_PLANE, USER_PLANE_STR)
UAT_VS_DEF(pdcp_nr_users, pdcp_nr_sn_length, uat_pdcp_nr_keys_record_t, guint, PDCP_NR_SN_LENGTH_12_BITS, PDCP_SN_LENGTH_12_BITS_STR)
UAT_VS_DEF(pdcp_nr_users, rohc_compression, uat_pdcp_nr_keys_record_t, guint, FALSE, ROHC_COMPRESSION_FALSE_STR)
//UAT_VS_DEF(pdcp_nr_users, rohc_mode, uat_pdcp_nr_keys_record_t, guint, MODE_NOT_SET, ROHC_MODE_NOT_SET_STR)
UAT_VS_DEF(pdcp_nr_users, rohc_profile, uat_pdcp_nr_keys_record_t, guint, ROHC_PROFILE_UNCOMPRESSED, ROHC_PROFILE_UNCOMPRESSED_STR)

static uat_pdcp_nr_keys_record_t* look_up_pdcp_nr_keys_record(packet_info *pinfo, guint32 teidn)
{
    unsigned int record_id;

    /* Look up UAT entries. N.B. linear search... */
    for (record_id = 0; record_id < num_pdcp_nr_keys_uat; record_id++) {
        if (addresses_equal(&uat_pdcp_nr_keys_records[record_id].ip_address, &pinfo->dst) &&
            (uat_pdcp_nr_keys_records[record_id].teid_wildcard ||
             uat_pdcp_nr_keys_records[record_id].teid == teidn)) {
            return &uat_pdcp_nr_keys_records[record_id];
        }
    }

    /* No match at all - return NULL */
    return NULL;
}

/* Entries added by UAT */
static uat_t * pdcp_lte_keys_uat = NULL;
static guint num_pdcp_lte_keys_uat = 0;

/* Default values for a TEID entry */
UAT_CSTRING_CB_DEF(pdcp_lte_users, ip_addr_str, uat_pdcp_lte_keys_record_t)
UAT_CSTRING_CB_DEF(pdcp_lte_users, teid_str, uat_pdcp_lte_keys_record_t)
UAT_VS_DEF(pdcp_lte_users, header_present, uat_pdcp_lte_keys_record_t, guint, PDCP_LTE_HEADER_PRESENT, PDCP_LTE_HEADER_PRESENT_STR)
UAT_VS_DEF(pdcp_lte_users, plane, uat_pdcp_lte_keys_record_t, enum pdcp_plane, USER_PLANE, USER_PLANE_STR)
UAT_VS_DEF(pdcp_lte_users, lte_sn_length, uat_pdcp_lte_keys_record_t, guint, PDCP_NR_SN_LENGTH_12_BITS, PDCP_SN_LENGTH_12_BITS_STR)
UAT_VS_DEF(pdcp_lte_users, rohc_compression, uat_pdcp_lte_keys_record_t, guint, FALSE, ROHC_COMPRESSION_FALSE_STR)
//UAT_VS_DEF(pdcp_lte_users, rohc_mode, uat_pdcp_lte_keys_record_t, guint, MODE_NOT_SET, ROHC_MODE_NOT_SET_STR)
UAT_VS_DEF(pdcp_lte_users, rohc_profile, uat_pdcp_lte_keys_record_t, guint, ROHC_PROFILE_UNCOMPRESSED, ROHC_PROFILE_UNCOMPRESSED_STR)

static uat_pdcp_lte_keys_record_t* look_up_pdcp_lte_keys_record(packet_info *pinfo, guint32 teidn)
{
    unsigned int record_id;

    /* Look up UAT entries. N.B. linear search... */
    for (record_id = 0; record_id < num_pdcp_lte_keys_uat; record_id++) {
        if (addresses_equal(&uat_pdcp_lte_keys_records[record_id].ip_address, &pinfo->dst) &&
            (uat_pdcp_lte_keys_records[record_id].teid_wildcard ||
             uat_pdcp_lte_keys_records[record_id].teid == teidn)) {
            return &uat_pdcp_lte_keys_records[record_id];
        }
    }

    /* No match at all - return NULL */
    return NULL;
}

/* --- END PDCP NR DECODE ADDITIONS --- */

static gboolean g_gtp_etsi_order = FALSE;

static gint dissect_tpdu_as = GTP_TPDU_AS_TPDU_HEUR;
static const enum_val_t gtp_decode_tpdu_as[] = {
    {"none", "None",   GTP_TPDU_AS_NONE},
    {"tpdu heuristic", "TPDU Heuristic",   GTP_TPDU_AS_TPDU_HEUR},
    {"pdcp-lte", "PDCP-LTE",   GTP_TPDU_AS_PDCP_LTE },
    {"pdcp-nr", "PDCP-NR",   GTP_TPDU_AS_PDCP_NR },
    {"sync", "SYNC",   GTP_TPDU_AS_SYNC},
    {"eth", "ETHERNET",   GTP_TPDU_AS_ETHERNET},
    {"custom", "Custom",   GTP_TPDU_AS_CUSTOM},
    {NULL, NULL, 0}
};


static int gtp_tap = -1;
static int gtpv1_tap = -1;

/* Definition of flags masks */
#define GTP_VER_MASK 0xE0

static const true_false_string gtp_hdr_length_vals = {
    "6-Octet Header",
    "20-Octet Header"
};

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

#define GTP_EXT_HDR_NO_MORE_EXT_HDRS         0x00
#define GTP_EXT_HDR_MBMS_SUPPORT_IND         0x01
#define GTP_EXT_HDR_MS_INFO_CHG_REP_SUPP_IND 0x02
#define GTP_EXT_HDR_LONG_PDCP_PDU_NUMBER     0x03 /* TS 29.281 (GTPv1-U)*/
#define GTP_EXT_HDR_SERVICE_CLASS_INDICATOR  0x20 /* TS 29.281 (GTPv1-U)*/
#define GTP_EXT_HDR_UDP_PORT                 0x40
#define GTP_EXT_HDR_RAN_CONT                 0x81
#define GTP_EXT_HDR_LONG_PDCP_PDU            0x82
#define GTP_EXT_HDR_XW_RAN_CONT              0x83
#define GTP_EXT_HDR_NR_RAN_CONT              0x84
#define GTP_EXT_HDR_PDU_SESSION_CONT         0x85
#define GTP_EXT_HDR_PDCP_SN                  0xC0
#define GTP_EXT_HDR_SUSPEND_REQ              0xC1
#define GTP_EXT_HDR_SUSPEND_RESP             0xC2

static const value_string next_extension_header_fieldvals[] = {
    {GTP_EXT_HDR_NO_MORE_EXT_HDRS, "No more extension headers"},
    {GTP_EXT_HDR_MBMS_SUPPORT_IND, "MBMS support indication"},
    {GTP_EXT_HDR_MS_INFO_CHG_REP_SUPP_IND, "MS Info Change Reporting support indication"},
    {GTP_EXT_HDR_LONG_PDCP_PDU_NUMBER, "Long PDCP PDU Number"},
    {GTP_EXT_HDR_SERVICE_CLASS_INDICATOR, "Service Class Indicator"},
    {GTP_EXT_HDR_UDP_PORT, "UDP Port number"},
    {GTP_EXT_HDR_RAN_CONT,"RAN container"},
    {GTP_EXT_HDR_LONG_PDCP_PDU,"Long PDCP PDU number"},
    {GTP_EXT_HDR_XW_RAN_CONT,"Xw RAN container"},
    {GTP_EXT_HDR_NR_RAN_CONT,"NR RAN container"},
    {GTP_EXT_HDR_PDU_SESSION_CONT,"PDU Session container"},
    {GTP_EXT_HDR_PDCP_SN, "PDCP PDU number"},
    {GTP_EXT_HDR_SUSPEND_REQ, "Suspend Request"},
    {GTP_EXT_HDR_SUSPEND_RESP, "Suspend Response"},
    {0, NULL}
};

/* Definition of 3G charging characteristics masks */
#define GTP_MASK_CHRG_CHAR_S    0xF000
#define GTP_MASK_CHRG_CHAR_N    0x0800
#define GTP_MASK_CHRG_CHAR_P    0x0400
#define GTP_MASK_CHRG_CHAR_F    0x0200
#define GTP_MASK_CHRG_CHAR_H    0x0100
#define GTP_MASK_CHRG_CHAR_R    0x00FF

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
#define GTP_EXT_QOS_SPARE4_MASK                 0xE0
#define GTP_EXT_QOS_SIG_IND_MASK                0x10
#define GTP_EXT_QOS_SRC_STAT_DESC_MASK          0x0F

/* Definition of Radio Priority's masks */
#define GTPv1_EXT_RP_NSAPI_MASK         0xF0
#define GTPv1_EXT_RP_SPARE_MASK         0x08
#define GTPv1_EXT_RP_MASK               0x07

#define NR_UP_DL_USER_DATA                0
#define NR_UP_DL_DATA_DELIVERY_STATUS     1
#define NR_UP_ASSISTANCE_INFORMATION_DATA 2

static const value_string nr_pdu_type_cnst[] = {
    {NR_UP_DL_USER_DATA,                "DL User Data"},
    {NR_UP_DL_DATA_DELIVERY_STATUS,     "DL Data Delivery Status"},
    {NR_UP_ASSISTANCE_INFORMATION_DATA, "Assistance Information Data"},
    {0, NULL}
};

static const range_string nr_up_cause_vals[] = {
    {0,   0,     "Unknown"},
    {1,   1,     "Radio Link Outage"},
    {2,   2,     "Radio Link Resume"},
    {3,   3,     "UL Radio Link Outage"},
    {4,   4,     "DL Radio Link Outage"},
    {5,   5,     "UL Radio Link Resume"},
    {6,   6,     "DL Radio Link Resume"},
    {7,   228,   "Reserved for future value extensions"},
    {228, 255,   "Reserved for test purposes"},
    {0,   0,     NULL}
};


static const true_false_string tfs_final_frame_indication = {
    "Frame is final",
    "Frame is not final"
};


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
    {   8,                              "Unknown message(For future use)"},
    {   9,                              "Unknown message(For future use)"},
    {  10,                              "Unknown message(For future use)"},
    {  11,                              "Unknown message(For future use)"},
    {  12,                              "Unknown message(For future use)"},
    {  13,                              "Unknown message(For future use)"},
    {  14,                              "Unknown message(For future use)"},
    {  15,                              "Unknown message(For future use)"},
#endif
    {GTP_MSG_CREATE_PDP_REQ,            "Create PDP context request"},
    {GTP_MSG_CREATE_PDP_RESP,           "Create PDP context response"},
    {GTP_MSG_UPDATE_PDP_REQ,            "Update PDP context request"},
    {GTP_MSG_UPDATE_PDP_RESP,           "Update PDP context response"},
    {GTP_MSG_DELETE_PDP_REQ,            "Delete PDP context request"},
    {GTP_MSG_DELETE_PDP_RESP,           "Delete PDP context response"},
    {GTP_MSG_INIT_PDP_CONTEXT_ACT_REQ,  "Initiate PDP Context Activation Request"},
    {GTP_MSG_INIT_PDP_CONTEXT_ACT_RESP, "Initiate PDP Context Activation Response"},
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
    {GTP_MSG_UE_REG_QUERY_REQ,    "UE Registration Query Request"},
    {GTP_MSG_UE_REG_QUERY_RESP,   "UE Registration Query Response"},
    /* 63-69 For future use. Shall not be sent. If received,
     * shall be treated as an Unknown message.
     */
#if 0
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
#define GTP_EXT_SGSN_NO               0x93    /* 3G   147 TLV SGSN Number 7.7.47 */
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
#define GTP_EXT_PDU_NO                0xAF    /* 3G   175 TLV PDU Numbers                               7.7.74 */
#define GTP_EXT_BSSGP_CAUSE           0xB0    /* 3G   176 TLV BSSGP Cause                               7.7.75 */
#define GTP_EXT_REQ_MBMS_BEARER_CAP   0xB1    /* 3G   177 TLV Required MBMS bearer capabilities         7.7.76 */
#define GTP_EXT_RIM_ROUTING_ADDR_DISC 0xB2    /* 3G   178 TLV RIM Routing Address Discriminator         7.7.77 */
#define GTP_EXT_LIST_OF_SETUP_PFCS    0xB3    /* 3G   179 TLV List of set-up PFCs                       7.7.78 */
#define GTP_EXT_PS_HANDOVER_XIP_PAR   0xB4    /* 3G   180 TLV PS Handover XID Parameters                7.7.79 */
#define GTP_EXT_MS_INF_CHG_REP_ACT    0xB5    /* 3G   181 TLV MS Info Change Reporting Action           7.7.80 */
#define GTP_EXT_DIRECT_TUNNEL_FLGS    0xB6    /* 3G   182 TLV Direct Tunnel Flags                       7.7.81 */
#define GTP_EXT_CORRELATION_ID        0xB7    /* 3G   183 TLV Correlation-ID                            7.7.82 */
#define GTP_EXT_BEARER_CONTROL_MODE   0xB8    /* 3G   184 TLV Bearer Control Mode                       7.7.83 */
#define GTP_EXT_MBMS_FLOW_ID          0xB9    /* 3G   185 TLV MBMS Flow Identifier                      7.7.84 */
#define GTP_EXT_MBMS_IP_MCAST_DIST    0xBA    /* 3G   186 TLV MBMS IP Multicast Distribution            7.7.85 */
#define GTP_EXT_MBMS_DIST_ACK         0xBB    /* 3G   187 TLV MBMS Distribution Acknowledgement         7.7.86 */
#define GTP_EXT_RELIABLE_IRAT_HO_INF  0xBC    /* 3G   188 TLV Reliable INTER RAT HANDOVER INFO          7.7.87 */
#define GTP_EXT_RFSP_INDEX            0xBD    /* 3G   189 TLV RFSP Index                                7.7.88 */
#define GTP_EXT_FQDN                  0xBE    /* 3G   190 TLV Fully Qualified Domain Name (FQDN)        7.7.90 */
#define GTP_EXT_EVO_ALLO_RETE_P1      0xBF    /* 3G   191 TLV Evolved Allocation/Retention Priority I   7.7.91 */
#define GTP_EXT_EVO_ALLO_RETE_P2      0xC0    /* 3G   192 TLV Evolved Allocation/Retention Priority II  7.7.92 */
#define GTP_EXT_EXTENDED_COMMON_FLGS  0xC1    /* 3G   193 TLV Extended Common Flags                     7.7.93 */
#define GTP_EXT_UCI                   0xC2    /* 3G   194 TLV User CSG Information (UCI)                7.7.94 */
#define GTP_EXT_CSG_INF_REP_ACT       0xC3    /* 3G   195 TLV CSG Information Reporting Action          7.7.95 */
#define GTP_EXT_CSG_ID                0xC4    /* 3G   196 TLV CSG ID                                    7.7.96 */
#define GTP_EXT_CMI                   0xC5    /* 3G   197 TLV CSG Membership Indication (CMI)           7.7.97 */
#define GTP_EXT_AMBR                  0xC6    /* 3G   198 TLV Aggregate Maximum Bit Rate (AMBR)         7.7.98 */
#define GTP_EXT_UE_NETWORK_CAP        0xC7    /* 3G   199 TLV UE Network Capability                     7.7.99 */
#define GTP_EXT_UE_AMBR               0xC8    /* 3G   200 TLV UE-AMBR                                   7.7.100 */
#define GTP_EXT_APN_AMBR_WITH_NSAPI   0xC9    /* 3G   201 TLV APN-AMBR with NSAPI                       7.7.101 */
#define GTP_EXT_GGSN_BACK_OFF_TIME    0xCA    /* 3G   202 TLV GGSN Back-Off Time                        7.7.102 */
#define GTP_EXT_SIG_PRI_IND           0xCB    /* 3G   203 TLV Signalling Priority Indication            7.7.103 */
#define GTP_EXT_SIG_PRI_IND_W_NSAPI   0xCC    /* 3G   204 TLV Signalling Priority Indication with NSAPI 7.7.104 */
#define GTP_EXT_HIGHER_BR_16MB_FLG    0xCD    /* 3G   205 TLV Higher bitrates than 16 Mbps flag         7.7.105 */
#define GTP_EXT_MAX_MBR_APN_AMBR      0xCE    /* 3G   206 TLV Max MBR/APN-AMBR                          7.7.106 */
#define GTP_EXT_ADD_MM_CTX_SRVCC      0xCF    /* 3G   207 TLV Additional MM context for SRVCC           7.7.107 */
#define GTP_EXT_ADD_FLGS_SRVCC        0xD0    /* 3G   208 TLV Additional flags for SRVCC                7.7.108 */
#define GTP_EXT_STN_SR                0xD1    /* 3G   209 TLV STN-SR                                    7.7.109 */
#define GTP_EXT_C_MSISDN              0xD2    /* 3G   210 TLV C-MSISDN                                  7.7.110 */
#define GTP_EXT_EXT_RANAP_CAUSE       0xD3    /* 3G   211 TLV Extended RANAP Cause                      7.7.111 */
#define GTP_EXT_ENODEB_ID             0xD4    /* 3G   212 TLV eNodeB ID                                 7.7.112 */
#define GTP_EXT_SEL_MODE_W_NSAPI      0xD5    /* 3G   213 TLV Selection Mode with NSAPI                 7.7.113 */
#define GTP_EXT_ULI_TIMESTAMP         0xD6    /* 3G   214 TLV ULI Timestamp                             7.7.114 */
#define GTP_EXT_LHN_ID_W_SAPI         0xD7    /* 3G   215 TLV Local Home Network ID (LHN-ID) with NSAPI 7.7.115 */
#define GTP_EXT_CN_OP_SEL_ENTITY      0xD8    /* 3G   216 TLV CN Operator Selection Entity              7.7.116 */
#define GTP_EXT_UE_USAGE_TYPE         0xD9    /* 3G   217 TLV UE Usage Type                             7.7.117 */
#define GTP_EXT_EXT_COMMON_FLGS_II    0xDA    /* 3G   218 TLV Extended Common Flags II                  7.7.118 */
#define GTP_EXT_NODE_IDENTIFIER       0xDB    /* 3G   219 TLV Node Identifier                           7.7.119 */
#define GTP_EXT_CIOT_OPT_SUP_IND      0xDC    /* 3G   220 TLV CIoT Optimizations Support Indication     7.7.120 */
#define GTP_EXT_SCEF_PDN_CONNECTION   0xDD    /* 3G   221 TLV SCEF PDN Connection                       7.7.121 */
#define GTP_EXT_IOV_UPDATES_COUNTER   0xDE    /* 3G   222 TLV IOV_updates counter                       7.7.122 */
#define GTP_EXT_MAPPED_UE_USAGE_TYPE  0xDF    /* 3G   223 TLV Mapped UE Usage Type                      7.7.123 */
#define GTP_EXT_UP_FUN_SEL_IND_FLAGS  0xE0    /* 3G   224 TLV UP Function Selection Indication Flags    7.7.124 */


/*  225-238 TLV Spare. For future use.     */

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
    {GTP_EXT_CAUSE,                 "Cause of operation"},
    {GTP_EXT_IMSI,                  "IMSI"},
    {GTP_EXT_RAI,                   "Routing Area Identity"},
    {GTP_EXT_TLLI,                  "Temporary Logical Link Identity"},
    {GTP_EXT_PTMSI,                 "Packet TMSI"},
/*   6 */  {GTP_EXT_QOS_GPRS,       "Quality of Service"},
/* 6-7 Spare */
/*   8 */  {GTP_EXT_REORDER,        "Reorder required"},
/*   9 */  {GTP_EXT_AUTH_TRI,       "Authentication triplets"},
/* 10 Spare */
/*  11 */  {GTP_EXT_MAP_CAUSE,      "MAP cause"},
/*  12 */  {GTP_EXT_PTMSI_SIG,      "P-TMSI signature"},
/*  13 */  {GTP_EXT_MS_VALID,       "MS validated"},
/*  14 */  {GTP_EXT_RECOVER,        "Recovery"},
/*  15 */  {GTP_EXT_SEL_MODE,       "Selection mode"},

/*  16 */  {GTP_EXT_16,             "Flow label data I"},
/*  16 */  /* ??? {GTP_EXT_FLOW_LABEL,     "Flow label data I"}, */
/*  16 */  /* ??? {GTP_EXT_TEID,           "Tunnel Endpoint Identifier Data I"}, */   /* 3G */

    {GTP_EXT_17,                    "Flow label signalling"},
/* ???    {GTP_EXT_FLOW_SIG,              "Flow label signalling"}, */
/* ???    {GTP_EXT_TEID_CP,               "Tunnel Endpoint Identifier Data Control Plane"}, */ /* 3G */

    {GTP_EXT_18,                    "Flow label data II"},
/* ???    {GTP_EXT_FLOW_II,               "Flow label data II"}, */
/* ???    {GTP_EXT_TEID_II,               "Tunnel Endpoint Identifier Data II"}, */   /* 3G */

    {GTP_EXT_19,                    "MS not reachable reason"},
/* ???    {GTP_EXT_MS_REASON,             "MS not reachable reason"}, */
/* ???    {GTP_EXT_TEAR_IND,              "Teardown ID"}, */ /* 3G */

    {GTP_EXT_NSAPI,                 "NSAPI"},   /* 3G */
    {GTP_EXT_RANAP_CAUSE,           "RANAP cause"},   /* 3G */
    {GTP_EXT_RAB_CNTXT,             "RAB context"}, /* 3G */
    {GTP_EXT_RP_SMS,                "Radio Priority for MO SMS"},  /* 3G */
    {GTP_EXT_RP,                    "Radio Priority"}, /* 3G */
    {GTP_EXT_PKT_FLOW_ID,           "Packet Flow ID"},    /* 3G */
    {GTP_EXT_CHRG_CHAR,             "Charging characteristics"},    /* 3G */
    {GTP_EXT_TRACE_REF,             "Trace references"},    /* 3G */
    {GTP_EXT_TRACE_TYPE,            "Trace type"}, /* 3G */
/*  29 */  {GTPv1_EXT_MS_REASON,    "MS not reachable reason"},   /* 3G */
/* 117-126 Reserved for the GPRS charging protocol (see GTP' in 3GPP TS 32.295 [33]) */
/* 126 */  {GTP_EXT_TR_COMM,        "Packet transfer command"},   /* charging */
/* 127 */  {GTP_EXT_CHRG_ID,        "Charging ID"},
    {GTP_EXT_USER_ADDR,             "End user address"},
    {GTP_EXT_MM_CNTXT,              "MM context"},
    {GTP_EXT_PDP_CNTXT,             "PDP context"},
    {GTP_EXT_APN,                   "Access Point Name"},
    {GTP_EXT_PROTO_CONF,            "Protocol configuration options"},
    {GTP_EXT_GSN_ADDR,              "GSN address"},
    {GTP_EXT_MSISDN,                "MS international PSTN/ISDN number"},
    {GTP_EXT_QOS_UMTS,              "Quality of service (UMTS)"},    /* 3G */
    {GTP_EXT_AUTH_QUI,              "Authentication quintuplets"},   /* 3G */
    {GTP_EXT_TFT,                   "Traffic Flow Template (TFT)"},   /* 3G */
    {GTP_EXT_TARGET_ID,             "Target (RNC) identification"}, /* 3G */
    {GTP_EXT_UTRAN_CONT,            "UTRAN transparent field"},    /* 3G */
    {GTP_EXT_RAB_SETUP,             "RAB setup information"},   /* 3G */
    {GTP_EXT_HDR_LIST,              "Extension Header Types List"},  /* 3G */
    {GTP_EXT_TRIGGER_ID,            "Trigger Id"}, /* 3G */
    {GTP_EXT_OMC_ID,                "OMC Identity"},   /* 3G */

    {GTP_EXT_RAN_TR_CONT,           "RAN Transparent Container"}, /* 7.7.43 */
    {GTP_EXT_PDP_CONT_PRIO,         "PDP Context Prioritization"},  /* 7.7.45 */
    {GTP_EXT_ADD_RAB_SETUP_INF,     "Additional RAB Setup Information"},    /* 7.7.45A */
    {GTP_EXT_SGSN_NO,               "SGSN Number"},   /* 7.7.47 */
    {GTP_EXT_COMMON_FLGS,           "Common Flags"},  /* 7.7.48 */
    {GTP_EXT_APN_RES,               "APN Restriction"},   /* 3G */
    {GTP_EXT_RA_PRIO_LCS,           "Radio Priority LCS"},    /* 7.7.25B */
    {GTP_EXT_RAT_TYPE,              "RAT Type"}, /* 3G */
    {GTP_EXT_USR_LOC_INF,           "User Location Information"}, /* 7.7.51 */
    {GTP_EXT_MS_TIME_ZONE,          "MS Time Zone"}, /* 7.7.52 */

    {GTP_EXT_IMEISV,                "IMEI(SV)"},   /* 3G */
    {GTP_EXT_CAMEL_CHG_INF_CON,     "CAMEL Charging Information Container"},    /* 7.7.54 */
    {GTP_EXT_MBMS_UE_CTX,           "MBMS UE Context"},   /* 7.7.55 */
    {GTP_EXT_TMGI,                  "Temporary Mobile Group Identity (TMGI)"},   /* 7.7.56 */
    {GTP_EXT_RIM_RA,                "RIM Routing Address"},    /* 7.7.57 */
    {GTP_EXT_MBMS_PROT_CONF_OPT,    "MBMS Protocol Configuration Options"},    /* 7.7.58 */
    {GTP_EXT_MBMS_SA,               "MBMS Service Area"}, /* 7.7.60 */
    {GTP_EXT_SRC_RNC_PDP_CTX_INF,   "Source RNC PDCP context info"},  /* 7.7.61 */
    {GTP_EXT_ADD_TRS_INF,           "Additional Trace Info"}, /* 7.7.62 */
    {GTP_EXT_HOP_COUNT,             "Hop Counter"}, /* 7.7.63 */
    {GTP_EXT_SEL_PLMN_ID,           "Selected PLMN ID"},  /* 7.7.64 */
    {GTP_EXT_MBMS_SES_ID,           "MBMS Session Identifier"},   /* 7.7.65 */
    {GTP_EXT_MBMS_2G_3G_IND,        "MBMS 2G/3G Indicator"},   /* 7.7.66 */
    {GTP_EXT_ENH_NSAPI,             "Enhanced NSAPI"},  /* 7.7.67 */
    {GTP_EXT_MBMS_SES_DUR,          "MBMS Session Duration"},    /* 7.7.59 */
    {GTP_EXT_ADD_MBMS_TRS_INF,      "Additional MBMS Trace Info"},   /* 7.7.68 */
    {GTP_EXT_MBMS_SES_ID_REP_NO,    "MBMS Session Identity Repetition Number"},    /* 7.7.69 */
    {GTP_EXT_MBMS_TIME_TO_DATA_TR,  "MBMS Time To Data Transfer"},   /* 7.7.70 */
    {GTP_EXT_PS_HO_REQ_CTX,         "PS Handover Request Context"}, /* 7.7.71 */
    {GTP_EXT_BSS_CONT,              "BSS Container"},    /* 7.7.72 */
    {GTP_EXT_CELL_ID,               "Cell Identification"},   /* 7.7.73 */
    {GTP_EXT_PDU_NO,                "PDU Numbers"},    /* 7.7.74 */
    {GTP_EXT_BSSGP_CAUSE,           "BSSGP Cause"},   /* 7.7.75 */
    {GTP_EXT_REQ_MBMS_BEARER_CAP,   "Required MBMS bearer capabilities"}, /* 7.7.76 */
    {GTP_EXT_RIM_ROUTING_ADDR_DISC, "RIM Routing Address Discriminator"},   /* 7.7.77 */
    {GTP_EXT_LIST_OF_SETUP_PFCS,    "List of set-up PFCs"},    /* 7.7.78 */
/* 180 */  {GTP_EXT_PS_HANDOVER_XIP_PAR, "  PS Handover XID Parameters"},                  /* 7.7.79 */
/* 181 */  {GTP_EXT_MS_INF_CHG_REP_ACT,     "MS Info Change Reporting Action"},            /* 7.7.80 */
/* 182 */  {GTP_EXT_DIRECT_TUNNEL_FLGS,     "Direct Tunnel Flags"},                        /* 7.7.81 */
/* 183 */  {GTP_EXT_CORRELATION_ID,         "Correlation-ID"},                             /* 7.7.82 */
/* 184 */  {GTP_EXT_BEARER_CONTROL_MODE,    "Bearer Control Mode"},                        /* 7.7.83 */
/* 185 */  {GTP_EXT_MBMS_FLOW_ID,           "MBMS Flow Identifier"},                       /* 7.7.84 */
/* 186 */  {GTP_EXT_MBMS_IP_MCAST_DIST,     "MBMS IP Multicast Distribution"},             /* 7.7.85 */
/* 187 */  {GTP_EXT_MBMS_DIST_ACK,          "MBMS Distribution Acknowledgement"},          /* 7.7.86 */
/* 188 */  {GTP_EXT_RELIABLE_IRAT_HO_INF,   "Reliable INTER RAT HANDOVER INFO"},           /* 7.7.87 */
/* 189 */  {GTP_EXT_RFSP_INDEX,             "RFSP Index"},                                 /* 7.7.88 */
/* 190 */  {GTP_EXT_FQDN,                   "Fully Qualified Domain Name (FQDN)"},         /* 7.7.90 */
/* 191 */  {GTP_EXT_EVO_ALLO_RETE_P1,       "Evolved Allocation/Retention Priority I"},    /* 7.7.91 */
/* 192 */  {GTP_EXT_EVO_ALLO_RETE_P2,       "Evolved Allocation/Retention Priority II"},   /* 7.7.92 */
/* 193 */  {GTP_EXT_EXTENDED_COMMON_FLGS,   "Extended Common Flags"},                      /* 7.7.93 */
/* 194 */  {GTP_EXT_UCI,                    "User CSG Information (UCI)"},                 /* 7.7.94 */
/* 195 */  {GTP_EXT_CSG_INF_REP_ACT,        "CSG Information Reporting Action"},           /* 7.7.95 */
/* 196 */  {GTP_EXT_CSG_ID,                 "CSG ID"},                                     /* 7.7.96 */
/* 197 */  {GTP_EXT_CMI,                    "CSG Membership Indication (CMI)"},            /* 7.7.97 */
/* 198 */  {GTP_EXT_AMBR,                   "Aggregate Maximum Bit Rate (AMBR)"},          /* 7.7.98 */
/* 199 */  {GTP_EXT_UE_NETWORK_CAP,         "UE Network Capability"},                      /* 7.7.99 */
/* 200 */  {GTP_EXT_UE_AMBR,                "UE-AMBR"},                                    /* 7.7.100 */
/* 201 */  {GTP_EXT_APN_AMBR_WITH_NSAPI,    "APN-AMBR with NSAPI"},                        /* 7.7.101 */
/* 202 */  {GTP_EXT_GGSN_BACK_OFF_TIME,     "GGSN Back-Off Time"},                         /* 7.7.102 */
/* 203 */  {GTP_EXT_SIG_PRI_IND,            "Signalling Priority Indication"},             /* 7.7.103 */
/* 204 */  {GTP_EXT_SIG_PRI_IND_W_NSAPI,    "Signalling Priority Indication with NSAPI"},  /* 7.7.104 */
/* 205 */  {GTP_EXT_HIGHER_BR_16MB_FLG,     "Higher bitrates than 16 Mbps flag"},          /* 7.7.105 */
/* 206 */  {GTP_EXT_MAX_MBR_APN_AMBR,       "Max MBR/APN-AMBR"},                           /* 7.7.106 */
/* 207 */  {GTP_EXT_ADD_MM_CTX_SRVCC,       "Additional MM context for SRVCC"},            /* 7.7.107 */
/* 208 */  {GTP_EXT_ADD_FLGS_SRVCC,         "Additional flags for SRVCC"},                 /* 7.7.108 */
/* 209 */  {GTP_EXT_STN_SR,                 "STN-SR"},                                     /* 7.7.109 */
/* 210 */  {GTP_EXT_C_MSISDN,               "C-MSISDN"},                                   /* 7.7.110 */
/* 211 */  {GTP_EXT_EXT_RANAP_CAUSE,        "Extended RANAP Cause"},                       /* 7.7.111 */
/* 212 */  {GTP_EXT_ENODEB_ID,              "eNodeB ID" },                                 /* 7.7.112 */
/* 213 */  {GTP_EXT_SEL_MODE_W_NSAPI,       "Selection Mode with NSAPI" },                 /* 7.7.113 */
/* 214 */  {GTP_EXT_ULI_TIMESTAMP,          "ULI Timestamp" },                             /* 7.7.114 */
/* 215 */  {GTP_EXT_LHN_ID_W_SAPI,          "Local Home Network ID (LHN-ID) with NSAPI" }, /* 7.7.115 */
/* 216 */  {GTP_EXT_CN_OP_SEL_ENTITY,       "Operator Selection Entity" },                 /* 7.7.116 */
/* 217 */  {GTP_EXT_UE_USAGE_TYPE,          "UE Usage Type" },                             /* 7.7.117 */
/* 218 */  {GTP_EXT_EXT_COMMON_FLGS_II,     "Extended Common Flags II"},                   /* 7.7.118 */
/* 219 */  {GTP_EXT_NODE_IDENTIFIER,        "Node Identifier" },                           /* 7.7.119 */
/* 220 */  {GTP_EXT_CIOT_OPT_SUP_IND,       "CIoT Optimizations Support Indication" },     /* 7.7.120 */
/* 221 */  {GTP_EXT_SCEF_PDN_CONNECTION,    "SCEF PDN Connection" },                       /* 7.7.121 */
/* 222 */  {GTP_EXT_IOV_UPDATES_COUNTER,    "IOV_updates counter" },                       /* 7.7.122 */
/* 223 */  {GTP_EXT_MAPPED_UE_USAGE_TYPE,   "Mapped UE Usage Type" },                      /* 7.7.123 */
/* 224 */  {GTP_EXT_UP_FUN_SEL_IND_FLAGS,   "UP Function Selection Indication Flags" },    /* 7.7.124 */


/* 225-238 TLV Spare. For future use. */
/* 239-250 Reserved for the GPRS charging protocol (see GTP' in 3GPP TS 32.295 [33]) */
/* 249 */  {GTP_EXT_REL_PACK,  "Sequence numbers of released packets IE"},  /* charging */
/* 250 */  {GTP_EXT_CAN_PACK,  "Sequence numbers of canceled packets IE"},  /* charging */
/* 251 */  {GTP_EXT_CHRG_ADDR, "Charging Gateway address"},                 /* 7.7.44 */
/* 252-254 Reserved for the GPRS charging protocol (see GTP' in 3GPP TS 32.295 [33]) */
/* 252 */  {GTP_EXT_DATA_REQ,  "Data record packet"},                       /* charging */
/* 253 */  {GTP_EXT_DATA_RESP, "Requests responded"},                       /* charging */
/* 254 */  {GTP_EXT_NODE_ADDR, "Address of recommended node"},              /* charging */
/* 255 */  {GTP_EXT_PRIV_EXT,  "Private Extension"},
    {0, NULL}
};
static value_string_ext gtp_val_ext = VALUE_STRING_EXT_INIT(gtp_val);

/* It seems like some IE's are renamed in gtpv1 at least reading
 * 3GPP TS 29.060 version 6.11.0 Release 6
 */
static const value_string gtpv1_val[] = {
/*   1 */  {GTP_EXT_CAUSE,                 "Cause of operation"},
/*   2 */  {GTP_EXT_IMSI,                  "IMSI"},
/*   3 */  {GTP_EXT_RAI,                   "Routing Area Identity"},
/*   4 */  {GTP_EXT_TLLI,                  "Temporary Logical Link Identity"},
/*   5 */  {GTP_EXT_PTMSI,                 "Packet TMSI"},
/*   6 */  {GTP_EXT_QOS_GPRS,              "Quality of Service"},
/* 6-7 Spare */
/*   7 */  {7,                             "Spare"},
/*   8 */  {GTP_EXT_REORDER,               "Reorder required"},
/*   9 */  {GTP_EXT_AUTH_TRI,              "Authentication triplets"},
/* 10 Spare */
/*  10 */  {10,                            "Spare"},
/*  11 */  {GTP_EXT_MAP_CAUSE,             "MAP cause"},
/*  12 */  {GTP_EXT_PTMSI_SIG,             "P-TMSI signature"},
/*  13 */  {GTP_EXT_MS_VALID,              "MS validated"},
/*  14 */  {GTP_EXT_RECOVER,               "Recovery"},
/*  15 */  {GTP_EXT_SEL_MODE,              "Selection mode"},
/*  16 */  {GTP_EXT_TEID,                  "Tunnel Endpoint Identifier Data I"},              /* 3G */
/*  17 */  {GTP_EXT_TEID_CP,               "Tunnel Endpoint Identifier Data Control Plane"},  /* 3G */
/*  18 */  {GTP_EXT_TEID_II,               "Tunnel Endpoint Identifier Data II"},             /* 3G */
/*  19 */  {GTP_EXT_TEAR_IND,              "Teardown ID"},                                    /* 3G */

/*  20 */  {GTP_EXT_NSAPI,                 "NSAPI"},                                          /* 3G */
/*  21 */  {GTP_EXT_RANAP_CAUSE,           "RANAP cause"},                                    /* 3G */
/*  22 */  {GTP_EXT_RAB_CNTXT,             "RAB context"},                                    /* 3G */
/*  23 */  {GTP_EXT_RP_SMS,                "Radio Priority for MO SMS"},                      /* 3G */
/*  24 */  {GTP_EXT_RP,                    "Radio Priority"},                                 /* 3G */
/*  25 */  {GTP_EXT_PKT_FLOW_ID,           "Packet Flow ID"},                                 /* 3G */
/*  26 */  {GTP_EXT_CHRG_CHAR,             "Charging characteristics"},                       /* 3G */
/*  27 */  {GTP_EXT_TRACE_REF,             "Trace references"},                               /* 3G */
/*  28 */  {GTP_EXT_TRACE_TYPE,            "Trace type"},                                     /* 3G */
/*  29 */  {GTPv1_EXT_MS_REASON,           "MS not reachable reason"},                        /* 3G */
/* 117-126 Reserved for the GPRS charging protocol (see GTP' in 3GPP TS 32.295 [33]) */
/* 126 */  {GTP_EXT_TR_COMM,               "Packet transfer command"},                        /* charging */
/* 127 */  {GTP_EXT_CHRG_ID,               "Charging ID"},

/* 128 */  {GTP_EXT_USER_ADDR,             "End user address"},
/* 129 */  {GTP_EXT_MM_CNTXT,              "MM context"},
/* 130 */  {GTP_EXT_PDP_CNTXT,             "PDP context"},
/* 131 */  {GTP_EXT_APN,                   "Access Point Name"},
/* 132 */  {GTP_EXT_PROTO_CONF,            "Protocol configuration options"},
/* 133 */  {GTP_EXT_GSN_ADDR,              "GSN address"},
/* 134 */  {GTP_EXT_MSISDN,                "MS international PSTN/ISDN number"},
/* 135 */  {GTP_EXT_QOS_UMTS,              "Quality of service (UMTS)"},                      /* 3G */
/* 136 */  {GTP_EXT_AUTH_QUI,              "Authentication quintuplets"},                     /* 3G */
/* 137 */  {GTP_EXT_TFT,                   "Traffic Flow Template (TFT)"},                    /* 3G */
/* 138 */  {GTP_EXT_TARGET_ID,             "Target (RNC) identification"},                    /* 3G */
/* 139 */  {GTP_EXT_UTRAN_CONT,            "UTRAN transparent field"},                        /* 3G */
/* 140 */  {GTP_EXT_RAB_SETUP,             "RAB setup information"},                          /* 3G */
/* 141 */  {GTP_EXT_HDR_LIST,              "Extension Header Types List"},                    /* 3G */
/* 142 */  {GTP_EXT_TRIGGER_ID,            "Trigger Id"},                                     /* 3G */
/* 143 */  {GTP_EXT_OMC_ID,                "OMC Identity"},                                   /* 3G */
/* 144 */  {GTP_EXT_RAN_TR_CONT,           "RAN Transparent Container"},                      /* 7.7.43 */
/* 145 */  {GTP_EXT_PDP_CONT_PRIO,         "PDP Context Prioritization"},                     /* 7.7.45 */
/* 146 */  {GTP_EXT_ADD_RAB_SETUP_INF,     "Additional RAB Setup Information"},               /* 7.7.45A */
/* 147 */  {GTP_EXT_SGSN_NO,               "SGSN Number"},                                    /* 7.7.47 */
/* 148 */  {GTP_EXT_COMMON_FLGS,           "Common Flags"},                                   /* 7.7.48 */
/* 149 */  {GTP_EXT_APN_RES,               "APN Restriction"},                                /* 3G */
/* 150 */  {GTP_EXT_RA_PRIO_LCS,           "Radio Priority LCS"},                             /* 7.7.25B */
/* 151 */  {GTP_EXT_RAT_TYPE,              "RAT Type"},                                       /* 3G */
/* 152 */  {GTP_EXT_USR_LOC_INF,           "User Location Information"},                      /* 7.7.51 */
/* 153 */  {GTP_EXT_MS_TIME_ZONE,          "MS Time Zone"},                                   /* 7.7.52 */

/* 154 */  {GTP_EXT_IMEISV,                "IMEI(SV)"},                                       /* 3G */
/* 155 */  {GTP_EXT_CAMEL_CHG_INF_CON,     "CAMEL Charging Information Container"},           /* 7.7.54 */
/* 156 */  {GTP_EXT_MBMS_UE_CTX,           "MBMS UE Context"},                                /* 7.7.55 */
/* 157 */  {GTP_EXT_TMGI,                  "Temporary Mobile Group Identity (TMGI)"},         /* 7.7.56 */
/* 158 */  {GTP_EXT_RIM_RA,                "RIM Routing Address"},                            /* 7.7.57 */
/* 159 */  {GTP_EXT_MBMS_PROT_CONF_OPT,    "MBMS Protocol Configuration Options"},            /* 7.7.58 */
/* 160 */  {GTP_EXT_MBMS_SA,               "MBMS Service Area"},                              /* 7.7.60 */
/* 161 */  {GTP_EXT_SRC_RNC_PDP_CTX_INF,   "Source RNC PDCP context info"},                   /* 7.7.61 */
/* 162 */  {GTP_EXT_ADD_TRS_INF,           "Additional Trace Info"},                          /* 7.7.62 */
/* 163 */  {GTP_EXT_HOP_COUNT,             "Hop Counter"},                                    /* 7.7.63 */
/* 164 */  {GTP_EXT_SEL_PLMN_ID,           "Selected PLMN ID"},                               /* 7.7.64 */
/* 165 */  {GTP_EXT_MBMS_SES_ID,           "MBMS Session Identifier"},                        /* 7.7.65 */
/* 166 */  {GTP_EXT_MBMS_2G_3G_IND,        "MBMS 2G/3G Indicator"},                           /* 7.7.66 */
/* 167 */  {GTP_EXT_ENH_NSAPI,             "Enhanced NSAPI"},                                 /* 7.7.67 */
/* 168 */  {GTP_EXT_MBMS_SES_DUR,          "MBMS Session Duration"},                          /* 7.7.59 */
/* 169 */  {GTP_EXT_ADD_MBMS_TRS_INF,      "Additional MBMS Trace Info"},                     /* 7.7.68 */
/* 170 */  {GTP_EXT_MBMS_SES_ID_REP_NO,    "MBMS Session Identity Repetition Number"},        /* 7.7.69 */
/* 171 */  {GTP_EXT_MBMS_TIME_TO_DATA_TR,  "MBMS Time To Data Transfer"},                     /* 7.7.70 */
/* 172 */  {GTP_EXT_PS_HO_REQ_CTX,         "PS Handover Request Context"},                    /* 7.7.71 */
/* 173 */  {GTP_EXT_BSS_CONT,              "BSS Container"},                                  /* 7.7.72 */
/* 174 */  {GTP_EXT_CELL_ID,               "Cell Identification"},                            /* 7.7.73 */
/* 175 */  {GTP_EXT_PDU_NO,                "PDU Numbers"},                                    /* 7.7.74 */
/* 176 */  {GTP_EXT_BSSGP_CAUSE,           "BSSGP Cause"},                                    /* 7.7.75 */

/* 177 */  {GTP_EXT_REQ_MBMS_BEARER_CAP,   "Required MBMS bearer capabilities"},              /* 7.7.76 */
/* 178 */  {GTP_EXT_RIM_ROUTING_ADDR_DISC, "RIM Routing Address Discriminator"},              /* 7.7.77 */
/* 179 */  {GTP_EXT_LIST_OF_SETUP_PFCS,    "List of set-up PFCs"},                            /* 7.7.78 */
/* 180 */  {GTP_EXT_PS_HANDOVER_XIP_PAR,   "PS Handover XID Parameters"},                     /* 7.7.79 */
/* 181 */  {GTP_EXT_MS_INF_CHG_REP_ACT,    "MS Info Change Reporting Action"},                /* 7.7.80 */
/* 182 */  {GTP_EXT_DIRECT_TUNNEL_FLGS,    "Direct Tunnel Flags"},                            /* 7.7.81 */
/* 183 */  {GTP_EXT_CORRELATION_ID,        "Correlation-ID"},                                 /* 7.7.82 */
/* 184 */  {GTP_EXT_BEARER_CONTROL_MODE,   "Bearer Control Mode"},                            /* 7.7.83 */
/* 185 */  {GTP_EXT_MBMS_FLOW_ID,          "MBMS Flow Identifier"},                           /* 7.7.84 */
/* 186 */  {GTP_EXT_MBMS_IP_MCAST_DIST,    "MBMS IP Multicast Distribution"},                 /* 7.7.85 */
/* 187 */  {GTP_EXT_MBMS_DIST_ACK,         "MBMS Distribution Acknowledgement"},              /* 7.7.86 */
/* 188 */  {GTP_EXT_RELIABLE_IRAT_HO_INF,  "Reliable INTER RAT HANDOVER INFO"},               /* 7.7.87 */
/* 190 */  {GTP_EXT_RFSP_INDEX,            "RFSP Index"},                                     /* 7.7.88 */
/* 190 */  {GTP_EXT_FQDN,                  "Fully Qualified Domain Name (FQDN)"},             /* 7.7.90 */
/* 191 */  {GTP_EXT_EVO_ALLO_RETE_P1,      "Evolved Allocation/Retention Priority I"},        /* 7.7.91 */
/* 192 */  {GTP_EXT_EVO_ALLO_RETE_P2,      "Evolved Allocation/Retention Priority II"},       /* 7.7.92 */
/* 193 */  {GTP_EXT_EXTENDED_COMMON_FLGS,  "Extended Common Flags"},                          /* 7.7.93 */
/* 194 */  {GTP_EXT_UCI,                   "User CSG Information (UCI)"},                     /* 7.7.94 */
/* 195 */  {GTP_EXT_CSG_INF_REP_ACT,       "CSG Information Reporting Action"},               /* 7.7.95 */
/* 196 */  {GTP_EXT_CSG_ID,                "CSG ID"},                                         /* 7.7.96 */
/* 197 */  {GTP_EXT_CMI,                   "CSG Membership Indication (CMI)"},                /* 7.7.97 */
/* 198 */  {198,                           "Aggregate Maximum Bit Rate (AMBR)"},              /* 7.7.98 */
/* 199 */  {199,                           "UE Network Capability"},                          /* 7.7.99 */
/* 200 */  {200,                           "UE-AMBR"},                                        /* 7.7.100 */
/* 201 */  {201,                           "APN-AMBR with NSAPI"},                            /* 7.7.101 */
/* 202 */  {202,                           "GGSN Back-Off Time"},                             /* 7.7.102 */
/* 203 */  {203,                           "Signalling Priority Indication"},                 /* 7.7.103 */
/* 204 */  {204,                           "Signalling Priority Indication with NSAPI"},      /* 7.7.104 */
/* 205 */  {205,                           "Higher bitrates than 16 Mbps flag"},              /* 7.7.105 */
/* 206 */  {206,                           "Max MBR/APN-AMBR"},                               /* 7.7.106 */
/* 207 */  {207,                           "Additional MM context for SRVCC"},                /* 7.7.107 */
/* 208 */  {208,                           "Additional flags for SRVCC"},                     /* 7.7.108 */
/* 209 */  {209,                           "STN-SR"},                                         /* 7.7.109 */
/* 210 */  {210,                           "C-MSISDN"},                                       /* 7.7.110 */
/* 211 */  {211,                           "Extended RANAP Cause"},                           /* 7.7.111 */
/* 212 */  {GTP_EXT_ENODEB_ID,             "eNodeB ID" },                                     /* 7.7.112 */
/* 213 */  {GTP_EXT_SEL_MODE_W_NSAPI,      "Selection Mode with NSAPI" },                     /* 7.7.113 */
/* 214 */  {GTP_EXT_ULI_TIMESTAMP,         "ULI Timestamp" },                                 /* 7.7.114 */
/* 215 */  {GTP_EXT_LHN_ID_W_SAPI,         "Local Home Network ID (LHN-ID) with NSAPI" },     /* 7.7.115 */
/* 216 */  {GTP_EXT_CN_OP_SEL_ENTITY,      "Operator Selection Entity" },                     /* 7.7.116 */
/* 217 */  {GTP_EXT_UE_USAGE_TYPE,         "UE Usage Type" },                                 /* 7.7.117 */
/* 218 */  {GTP_EXT_EXT_COMMON_FLGS_II,    "Extended Common Flags II"},                       /* 7.7.118 */
/* 219 */  {GTP_EXT_NODE_IDENTIFIER,       "Node Identifier" },                              /* 7.7.119 */
/* 220 */  {GTP_EXT_CIOT_OPT_SUP_IND,      "CIoT Optimizations Support Indication" },        /* 7.7.120 */
/* 221 */  {GTP_EXT_SCEF_PDN_CONNECTION,   "SCEF PDN Connection" },                          /* 7.7.121 */
/* 222 */  {GTP_EXT_IOV_UPDATES_COUNTER,   "IOV_updates counter" },                          /* 7.7.122 */
/* 223 */  {GTP_EXT_MAPPED_UE_USAGE_TYPE,  "Mapped UE Usage Type" },                         /* 7.7.123 */
/* 224 */  {GTP_EXT_UP_FUN_SEL_IND_FLAGS,  "UP Function Selection Indication Flags" },       /* 7.7.124 */

/* 225-238 TLV Spare. For future use. */
/* 239-250 Reserved for the GPRS charging protocol (see GTP' in 3GPP TS 32.295 [33]) */
/* 249 */  {GTP_EXT_REL_PACK,              "Sequence numbers of released packets IE"},        /* charging */
/* 250 */  {GTP_EXT_CAN_PACK,              "Sequence numbers of canceled packets IE"},        /* charging */
/* 251 */  {GTP_EXT_CHRG_ADDR,             "Charging Gateway address"},                       /* 7.7.44 */
/* 252-254 Reserved for the GPRS charging protocol (see GTP' in 3GPP TS 32.295 [33]) */
/* 252 */  {GTP_EXT_DATA_REQ,              "Data record packet"},                             /* charging */
/* 253 */  {GTP_EXT_DATA_RESP,             "Requests responded"},                             /* charging */
/* 254 */  {GTP_EXT_NODE_ADDR,             "Address of recommended node"},                    /* charging */
/* 255 */  {GTP_EXT_PRIV_EXT,              "Private Extension"},

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
    {  6, "Reactivation Requested"},
    {  7, "PDP address inactivity timer expires"},
    /* For future use 8-48 */
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
    {229, "APN Congestion"},
    {230, "Bearer handling not supported"},
    {231, "Target access restricted for the subscriber" },
    {232, "UE is temporarily not reachable due to power saving" },
    {233, "Relocation failure due to NAS message redirection"},
    /* For future use -240 */
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
value_string_ext cause_type_ext = VALUE_STRING_EXT_INIT(cause_type);

/* GPRS:    9.02 v7.7.0
 * UMTS:    29.002 v4.2.1, chapter 17.5, page 268
 * Imported gsm_old_GSMMAPLocalErrorcode_vals from gsm_map from gsm_map
 */

static const value_string gsn_addr_type[] = {
    {0x00, "IPv4"},
    {0x01, "IPv6"},
    {0, NULL}
};

static const value_string pdp_type[] = {
    {0x00, "X.25"},
    {0x01, "PPP"},
    {0x02, "OSP:IHOSS"},
    {0x21, "IPv4"},
    {0x57, "IPv6"},
    {0x8d, "IPv4v6"},
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

/*
 * UMTS:   23.040 v14.0.0, chapter 3.3.2
 */
static const value_string ms_not_reachable_type[] = {
    { 0, "No paging response via the MSC"},
    { 1, "IMSI detached"},
    { 2, "Roaming restriction"},
    { 3, "Deregistered in the HLR for non GPRS"},
    { 4, "MS purge for non GPRS"},
    { 5, "No paging response via the SGSN"},
    { 6, "GPRS detached"},
    { 7, "Deregistered in the HLR for non GPRS"},
    { 8, "MS purged for GPRS"},
    { 9, "Unidentified subscriber via the MSC"},
    {10, "Unidentified subscriber via the SGSN"},
    {11, "Deregistered in the HSS/HLR for IMS"},
    {12, "No response via the IP-SM-GW"},
    {13, "The MS is temporarily unavailable"},
    {0, NULL}             /* All other values are reserved */
};

/* UMTS:   25.413 v3.4.0, chapter 9.2.1.4, page 80
 */
static const value_string ranap_cause_type[] = {
/* Radio Network Layer Cause (1-->64) */
    {   1, "RAB preempted"},
    {   2, "Trelocoverall Expiry"},
    {   3, "Trelocprep Expiry"},
    {   4, "Treloccomplete Expiry"},
    {   5, "Tqueuing Expiry"},
    {   6, "Relocation Triggered"},
    {   7, "TRELOCalloc Expiry"},
    {   8, "Unable to Establish During Relocation"},
    {   9, "Unknown Target RNC"},
    {  10, "Relocation Cancelled"},
    {  11, "Successful Relocation"},
    {  12, "Requested Ciphering and/or Integrity Protection Algorithms not Supported"},
    {  13, "Change of Ciphering and/or Integrity Protection is not supported"},
    {  14, "Failure in the Radio Interface Procedure"},
    {  15, "Release due to UTRAN Generated Reason"},
    {  16, "User Inactivity"},
    {  17, "Time Critical Relocation"},
    {  18, "Requested Traffic Class not Available"},
    {  19, "Invalid RAB Parameters Value"},
    {  20, "Requested Maximum Bit Rate not Available"},
    {  21, "Requested Guaranteed Bit Rate not Available"},
    {  22, "Requested Transfer Delay not Achievable"},
    {  23, "Invalid RAB Parameters Combination"},
    {  24, "Condition Violation for SDU Parameters"},
    {  25, "Condition Violation for Traffic Handling Priority"},
    {  26, "Condition Violation for Guaranteed Bit Rate"},
    {  27, "User Plane Versions not Supported"},
    {  28, "Iu UP Failure"},
    {  29, "Relocation Failure in Target CN/RNC or Target System"},
    {  30, "Invalid RAB ID"},
    {  31, "No Remaining RAB"},
    {  32, "Interaction with other procedure"},
    {  33, "Requested Maximum Bit Rate for DL not Available"},
    {  34, "Requested Maximum Bit Rate for UL not Available"},
    {  35, "Requested Guaranteed Bit Rate for DL not Available"},
    {  36, "Requested Guaranteed Bit Rate for UL not Available"},
    {  37, "Repeated Integrity Checking Failure"},
    {  38, "Requested Report Type not supported"},
    {  39, "Request superseded"},
    {  40, "Release due to UE generated signalling connection release"},
    {  41, "Resource Optimisation Relocation"},
    {  42, "Requested Information Not Available"},
    {  43, "Relocation desirable for radio reasons"},
    {  44, "Relocation not supported in Target RNC or Target System"},
    {  45, "Directed Retry"},
    {  46, "Radio Connection With UE Lost"},
    {  47, "rNC-unable-to-establish-all-RFCs"},
    {  48, "deciphering-keys-not-available"},
    {  49, "dedicated-assistance-data-not-available"},
    {  50, "relocation-target-not-allowed"},
    {  51, "location-reporting-congestion"},
    {  52, "reduce-load-in-serving-cell"},
    {  53, "no-radio-resources-available-in-target-cell"},
    {  54, "gERAN-Iumode-failure"},
    {  55, "access-restricted-due-to-shared-networks"},
    {  56, "incoming-relocation-not-supported-due-to-PUESBINE-feature"},
    {  57, "traffic-load-in-the-target-cell-higher-than-in-the-source-cell"},
    {  58, "mBMS-no-multicast-service-for-this-UE"},
    {  59, "mBMS-unknown-UE-ID"},
    {  60, "successful-MBMS-session-start-no-data-bearer-necessary"},
    {  61, "mBMS-superseded-due-to-NNSF"},
    {  62, "mBMS-UE-linking-already-done"},
    {  63, "mBMS-UE-de-linking-failure-no-existing-UE-linking"},
    {  64, "tMGI-unknown"},
/* Transport Layer Cause (65-->80) */
    {  65, "Signalling Transport Resource Failure"},
    {  66, "Iu Transport Connection Failed to Establish"},
/* NAS Cause (81-->96) */
    {  81, "User Restriction Start Indication"},
    {  82, "User Restriction End Indication"},
    {  83, "Normal Release"},
/* Protocol Cause (97-->112) */
    {  97, "Transfer Syntax Error"},
    {  98, "Semantic Error"},
    {  99, "Message not compatible with receiver state"},
    { 100, "Abstract Syntax Error (Reject)"},
    { 101, "Abstract Syntax Error (Ignore and Notify)"},
    { 102, "Abstract Syntax Error (Falsely Constructed Message"},
/* Miscellaneous Cause (113-->128) */
    { 113, "O & M Intervention"},
    { 114, "No Resource Available"},
    { 115, "Unspecified Failure"},
    { 116, "Network Optimisation"},
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
    {6, "EUTRAN (WB-E-UTRAN)"},
    {7, "Virtual"},
    {8, "EUTRAN-NB-IoT"},
    {0, NULL}
};
static const value_string chg_rep_act_type_vals[] = {
    {0, "Stop Reporting"},
    {1, "Start Reporting CGI/SAI"},
    {2, "Start Reporting RAI"},
    {0, NULL}
};


static const value_string geographic_location_type[] = {
    {0, "Cell Global Identification (CGI)"},
    {1, "Service Area Identity (SAI)"},
    {2, "Routing Area Identification (RAI)"},
/* reserved for future used (3-->127) */
/* values below used by Radius */
    {128, "TAI"},
    {129, "ECGI"},
    {130, "TAI & ECGI"},
    {131, "eNodeB ID"},
    {132, "TAI and eNodeB ID"},
    {133, "extended eNodeB ID"},
    {134, "TAI and extended eNodeB ID"},
    {135, "NCGI"},
    {136, "5GS TAI"},
    {137, "5GS TAI and NCGI"},
    {138, "NG-RAN Node ID"},
    {139, "5GS TAI and NG-RAN Node ID"},
/* reserved for future used (140-->255) */
    {0, NULL}
};

static const value_string gtp_ext_hdr_pdu_ses_cont_pdu_type_vals[] = {
    {0,  "DL PDU SESSION INFORMATION"},
    {1,  "UL PDU SESSION INFORMATION"},
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

static void
gtpstat_init(struct register_srt* srt _U_, GArray* srt_array)
{
    srt_stat_table *gtp_srt_table;

    gtp_srt_table = init_srt_table("GTP Requests", NULL, srt_array, 4, NULL, NULL, NULL);
    init_srt_table_row(gtp_srt_table, 0, "Echo");
    init_srt_table_row(gtp_srt_table, 1, "Create PDP context");
    init_srt_table_row(gtp_srt_table, 2, "Update PDP context");
    init_srt_table_row(gtp_srt_table, 3, "Delete PDP context");
}

static tap_packet_status
gtpstat_packet(void *pss, packet_info *pinfo, epan_dissect_t *edt _U_, const void *prv, tap_flags_t flags _U_)
{
    guint i = 0;
    srt_stat_table *gtp_srt_table;
    srt_data_t *data = (srt_data_t *)pss;
    const gtp_msg_hash_t *gtp=(const gtp_msg_hash_t *)prv;
    int idx=0;

    /* we are only interested in reply packets */
    if(gtp->is_request){
        return TAP_PACKET_DONT_REDRAW;
    }
    /* if we have not seen the request, just ignore it */
    if(!gtp->req_frame){
        return TAP_PACKET_DONT_REDRAW;
    }

    /* Only use the commands we know how to handle, this is not a comprehensive list */
    /* Redoing the message indexing is bit reduntant,                    */
    /*  but using message type as such would yield a long gtp_srt_table. */
    /*  Only a fraction of the messages are matchable req/resp pairs,    */
    /*  it just doesn't feel feasible.                                   */

    switch(gtp->msgtype){
    case GTP_MSG_ECHO_REQ: idx=0;
        break;
    case GTP_MSG_CREATE_PDP_REQ: idx=1;
        break;
    case GTP_MSG_UPDATE_PDP_REQ: idx=2;
        break;
    case GTP_MSG_DELETE_PDP_REQ: idx=3;
        break;
    default:
        return TAP_PACKET_DONT_REDRAW;
    }

    gtp_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);
    add_srt_table_data(gtp_srt_table, idx, &gtp->req_time, pinfo);

    return TAP_PACKET_REDRAW;
}


static dissector_handle_t eth_handle;
static dissector_handle_t ip_handle;
static dissector_handle_t ipv6_handle;
static dissector_handle_t ppp_handle;
static dissector_handle_t sync_handle;
static dissector_handle_t gtpcdr_handle;
static dissector_handle_t sndcpxid_handle;
static dissector_handle_t gtpv2_handle;
static dissector_handle_t bssgp_handle;
static dissector_handle_t pdcp_nr_handle;
static dissector_handle_t pdcp_lte_handle;
static dissector_handle_t gtp_tpdu_custom_handle;
static dissector_table_t bssap_pdu_type_table;

static int proto_pdcp_lte = -1;

guint32 gtp_session_count;

/* Relation between frame -> session */
GHashTable* session_table;
/* Relation between <teid,ip> -> frame */
wmem_tree_t* frame_tree;

typedef struct {
    guint32 teid;
    guint32 frame;
} gtp_info_t;

/* GTP Session funcs*/
guint32
get_frame(address ip, guint32 teid, guint32 *frame) {
    gboolean found = FALSE;
    wmem_list_frame_t *elem;
    gtp_info_t *info;
    wmem_list_t *info_list;
    gchar *ip_str;

    /* First we get the teid list*/
    ip_str = address_to_str(wmem_packet_scope(), &ip);
    info_list = (wmem_list_t*)wmem_tree_lookup_string(frame_tree, ip_str, 0);
    if (info_list != NULL) {
        elem = wmem_list_head(info_list);
        while (!found && elem) {
            info = (gtp_info_t*)wmem_list_frame_data(elem);
            if (teid == info->teid) {
                *frame = info->frame;
                return 1;
            }
            elem = wmem_list_frame_next(elem);
        }
    }
    return 0;
}

static gboolean
call_foreach_ip(const void *key _U_, void *value, void *data){
    wmem_list_frame_t * elem;
    wmem_list_t *info_list = (wmem_list_t *)value;
    gtp_info_t *info;
    guint32* frame = (guint32*)data;

    /* We loop over the <teid, frame> list */
    elem = wmem_list_head(info_list);
    while (elem) {
        info = (gtp_info_t*)wmem_list_frame_data(elem);
        if (info->frame == *frame) {
            wmem_list_frame_t * del = elem;
            /* proceed to next request */
            elem = wmem_list_frame_next(elem);
            /* If we find the frame we remove its information from the list */
            wmem_list_remove_frame(info_list, del);
            wmem_free(wmem_file_scope(), info);
        }
        else {
            elem = wmem_list_frame_next(elem);
        }
    }

    return FALSE;
}

void
remove_frame_info(guint32 *f) {
    /* For each ip node */
    wmem_tree_foreach(frame_tree, call_foreach_ip, (void *)f);
}

void
add_gtp_session(guint32 frame, guint32 session) {
    guint32 *f, *session_count;

    f = wmem_new0(wmem_file_scope(), guint32);
    session_count = wmem_new0(wmem_file_scope(), guint32);
    *f = frame;
    *session_count = session;
    g_hash_table_insert(session_table, f, session_count);
}

gboolean
teid_exists(guint32 teid, wmem_list_t *teid_list) {
    wmem_list_frame_t *elem;
    guint32 *info;
    gboolean found;
    found = FALSE;
    elem = wmem_list_head(teid_list);
    while (!found && elem) {
        info = (guint32*)wmem_list_frame_data(elem);
        found = *info == teid;
        elem = wmem_list_frame_next(elem);
    }
    return found;
}

gboolean
ip_exists(address ip, wmem_list_t *ip_list) {
    wmem_list_frame_t *elem;
    address *info;
    gboolean found;
    found = FALSE;
    elem = wmem_list_head(ip_list);
    while (!found && elem) {
        info = (address*)wmem_list_frame_data(elem);
        found = addresses_equal(info, &ip);
        elem = wmem_list_frame_next(elem);
    }
    return found;
}

static gboolean
info_exists(gtp_info_t *wanted, wmem_list_t *info_list) {
    wmem_list_frame_t *elem;
    gtp_info_t *info;
    gboolean found;
    found = FALSE;
    elem = wmem_list_head(info_list);
    while (!found && elem) {
        info = (gtp_info_t*)wmem_list_frame_data(elem);
        found = wanted->teid == info->teid;
        elem = wmem_list_frame_next(elem);
    }
    return found;
}

void
fill_map(wmem_list_t *teid_list, wmem_list_t *ip_list, guint32 frame) {
    wmem_list_frame_t *elem_ip, *elem_teid;
    gtp_info_t *gtp_info;
    wmem_list_t * info_list; /* List of <teids,frames>*/
    guint32 *f, *session, *fr, *session_count;
    GHashTableIter iter;
    guint32 teid;
    gchar *ip;

    elem_ip = wmem_list_head(ip_list);
    while (elem_ip) {
        ip = address_to_str(wmem_file_scope(), (address*)wmem_list_frame_data(elem_ip));
        /* We check if a teid list exists for this ip */
        info_list = (wmem_list_t*)wmem_tree_lookup_string(frame_tree, ip, 0);
        if (info_list == NULL) {
            info_list = wmem_list_new(wmem_file_scope());
        }
        /* We loop over the teid list */
        elem_teid = wmem_list_head(teid_list);
        while (elem_teid) {
            teid = *(guint32*)wmem_list_frame_data(elem_teid);
            f = wmem_new0(wmem_file_scope(), guint32);
            *f = frame;
            gtp_info = wmem_new0(wmem_file_scope(), gtp_info_t);
            gtp_info->teid = teid;
            gtp_info->frame = *f;
            if (info_exists(gtp_info, info_list)) {
                /* If the teid and ip already existed, that means that we need to remove old info about that session */
                /* We look for its session ID */
                session = (guint32 *)g_hash_table_lookup(session_table, f);
                if (session) {
                    g_hash_table_iter_init(&iter, session_table);
                    while (g_hash_table_iter_next(&iter, (gpointer*)&fr, (gpointer*)&session_count)) {
                        /* If the msg has the same session ID and it's not the upd req we have to remove its info */
                        if (*session_count == *session) {
                            /* If it's the session we are looking for, we remove all the frame information */
                            remove_frame_info(fr);
                        }
                    }
                }
            }
            wmem_list_prepend(info_list, gtp_info);
            elem_teid = wmem_list_frame_next(elem_teid);
        }
        wmem_tree_insert_string(frame_tree, ip, info_list, 0);
        elem_ip = wmem_list_frame_next(elem_ip);
    }
}

gboolean
is_cause_accepted(guint8 cause, guint32 version) {
    if (version == 1) {
        return cause == 128 || cause == 129 || cause == 130;
    }
    else if (version == 2) {
        return cause == 16 || cause == 17 || cause == 18 || cause == 19;
    }
    return FALSE;
}

static int decode_gtp_cause(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args);
static int decode_gtp_imsi(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_rai(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_tlli(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_ptmsi(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_qos_gprs(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_reorder(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_auth_tri(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_map_cause(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_ptmsi_sig(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_ms_valid(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_recovery(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_sel_mode(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_16(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args);
static int decode_gtp_17(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args);
static int decode_gtp_18(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_19(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_nsapi(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_ranap_cause(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_rab_cntxt(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_rp_sms(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_rp(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_pkt_flow_id(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_chrg_char(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_trace_ref(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_trace_type(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_ms_reason(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_tr_comm(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_chrg_id(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_user_addr(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_mm_cntxt(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_pdp_cntxt(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_apn(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_gsn_addr_common(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args, const char * tree_name, int hf_ipv4, int hf_ipv6);
static int decode_gtp_gsn_addr(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args);
static int decode_gtp_sgsn_addr_for_control_plane(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args);
static int decode_gtp_sgsn_addr_for_user_plane(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args);
static int decode_gtp_ggsn_addr_for_control_plane(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args);
static int decode_gtp_ggsn_addr_for_user_plane(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args);
static int decode_gtp_proto_conf(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_msisdn(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_qos_umts(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_auth_qui(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_tft(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_target_id(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_utran_cont(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_rab_setup(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_hdr_list(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_trigger_id(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_omc_id(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);

static int decode_gtp_ran_tr_cont(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_pdp_cont_prio(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_add_rab_setup_inf(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_sgsn_no(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_common_flgs(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_apn_res(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_ra_prio_lcs(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_rat_type(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_usr_loc_inf(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_ms_time_zone(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_imeisv(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_camel_chg_inf_con(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_mbms_ue_ctx(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_tmgi(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_rim_ra(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_mbms_prot_conf_opt(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_mbms_sa(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_src_rnc_pdp_ctx_inf(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_add_trs_inf(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_hop_count(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_sel_plmn_id(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_mbms_ses_id(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_mbms_2g_3g_ind(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_enh_nsapi(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_mbms_ses_dur(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_add_mbms_trs_inf(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_mbms_ses_id_rep_no(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_mbms_time_to_data_tr(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_ps_ho_req_ctx(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_bss_cont(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_cell_id(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_pdu_no(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_bssgp_cause(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_mbms_bearer_cap(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_rim_ra_disc(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_lst_set_up_pfc(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_ps_handover_xid(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_direct_tnl_flg(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_ms_inf_chg_rep_act(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_corrl_id(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_fqdn(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_evolved_allc_rtn_p1(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_evolved_allc_rtn_p2(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_extended_common_flgs(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_uci(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_csg_inf_rep_act(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_csg_id(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_cmi(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_apn_ambr(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_ue_network_cap(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_ue_ambr(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_apn_ambr_with_nsapi(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_ggsn_back_off_time(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_sig_pri_ind(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_sig_pri_ind_w_nsapi(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_higher_br_16mb_flg(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_max_mbr_apn_ambr(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_add_mm_ctx_srvcc(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_add_flgs_srvcc(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_stn_sr(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_c_msisdn(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_ext_ranap_cause(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_ext_enodeb_id(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_ext_sel_mode_w_nsapi(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_ext_uli_timestamp(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_ext_lhn_id_w_sapi(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_ext_cn_op_sel_entity(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_ue_usage_type(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_extended_common_flgs_II(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_ext_node_id(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_ciot_opt_sup_ind(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_scef_pdn_conn(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_iov_updates_counter(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_mapped_ue_usage_type(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_up_fun_sel_ind_flags(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);

static int decode_gtp_bearer_cntrl_mod(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_mbms_flow_id(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_mbms_ip_mcast_dist(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_mbms_dist_ack(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_reliable_irat_ho_inf(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_rfsp_index(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_);

static int decode_gtp_chrg_addr(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_rel_pack(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_can_pack(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_data_req(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_data_resp(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_node_addr(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_priv_ext(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);
static int decode_gtp_unknown(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);

typedef struct {
    int optcode;
    int (*decode) (tvbuff_t *, int, packet_info *, proto_tree *, session_args_t *);
} gtp_opt_t;

static const gtp_opt_t gtpopt[] = {
/* 0x01 */  {GTP_EXT_CAUSE, decode_gtp_cause},
/* 0x02 */  {GTP_EXT_IMSI, decode_gtp_imsi},
/* 0x03 */  {GTP_EXT_RAI, decode_gtp_rai},
/* 0x04 */  {GTP_EXT_TLLI, decode_gtp_tlli},
/* 0x05 */  {GTP_EXT_PTMSI, decode_gtp_ptmsi},
/* 0x06 */  {GTP_EXT_QOS_GPRS, decode_gtp_qos_gprs},
/* 0x07 */
/* 0x08 */  {GTP_EXT_REORDER, decode_gtp_reorder},
/* 0x09 */  {GTP_EXT_AUTH_TRI, decode_gtp_auth_tri},
/* 0x0a */
/* 0x0b */  {GTP_EXT_MAP_CAUSE, decode_gtp_map_cause},
/* 0x0c */  {GTP_EXT_PTMSI_SIG, decode_gtp_ptmsi_sig},
/* 0x0d */  {GTP_EXT_MS_VALID, decode_gtp_ms_valid},
/* 0x0e */  {GTP_EXT_RECOVER, decode_gtp_recovery},
/* 0x0f */  {GTP_EXT_SEL_MODE, decode_gtp_sel_mode},
/* 0x10 */  {GTP_EXT_16, decode_gtp_16},
/* 0x11 */  {GTP_EXT_17, decode_gtp_17},
/* 0x12 */  {GTP_EXT_18, decode_gtp_18},
/* 0x13 */  {GTP_EXT_19, decode_gtp_19},
/* 0x14 */  {GTP_EXT_NSAPI, decode_gtp_nsapi},
/* 0x15 */  {GTP_EXT_RANAP_CAUSE, decode_gtp_ranap_cause},
/* 0x16 */  {GTP_EXT_RAB_CNTXT, decode_gtp_rab_cntxt},
/* 0x17 */  {GTP_EXT_RP_SMS, decode_gtp_rp_sms},
/* 0x18 */  {GTP_EXT_RP, decode_gtp_rp},
/* 0x19 */  {GTP_EXT_PKT_FLOW_ID, decode_gtp_pkt_flow_id},
/* 0x1a */  {GTP_EXT_CHRG_CHAR, decode_gtp_chrg_char},
/* 0x1b */  {GTP_EXT_TRACE_REF, decode_gtp_trace_ref},
/* 0x1c */  {GTP_EXT_TRACE_TYPE, decode_gtp_trace_type},
/* 0x1d */  {GTPv1_EXT_MS_REASON, decode_gtp_ms_reason},

/* 0x7e */  {GTP_EXT_TR_COMM, decode_gtp_tr_comm},
/* 0x7f */  {GTP_EXT_CHRG_ID, decode_gtp_chrg_id},
/* 0x80 */  {GTP_EXT_USER_ADDR, decode_gtp_user_addr},
/* 0x81 */  {GTP_EXT_MM_CNTXT, decode_gtp_mm_cntxt},
/* 0x82 */  {GTP_EXT_PDP_CNTXT, decode_gtp_pdp_cntxt},
/* 0x83 */  {GTP_EXT_APN, decode_gtp_apn},
/* 0x84 */  {GTP_EXT_PROTO_CONF, decode_gtp_proto_conf},
/* 0x85 */  {GTP_EXT_GSN_ADDR, decode_gtp_gsn_addr},
/* 0x86 */  {GTP_EXT_MSISDN, decode_gtp_msisdn},
/* 0x87 */  {GTP_EXT_QOS_UMTS, decode_gtp_qos_umts},                            /* 3G */
/* 0x88 */  {GTP_EXT_AUTH_QUI, decode_gtp_auth_qui},                            /* 3G */
/* 0x89 */  {GTP_EXT_TFT, decode_gtp_tft},                                      /* 3G */
/* 0x8a */  {GTP_EXT_TARGET_ID, decode_gtp_target_id},                          /* 3G */
/* 0x8b */  {GTP_EXT_UTRAN_CONT, decode_gtp_utran_cont},                        /* 3G */
/* 0x8c */  {GTP_EXT_RAB_SETUP, decode_gtp_rab_setup},                          /* 3G */
/* 0x8d */  {GTP_EXT_HDR_LIST, decode_gtp_hdr_list},                            /* 3G */
/* 0x8e */  {GTP_EXT_TRIGGER_ID, decode_gtp_trigger_id},                        /* 3G */
/* 0x8f */  {GTP_EXT_OMC_ID, decode_gtp_omc_id},                                /* 3G */
    /* TS 29 060 V6.11.0 */
/* 0x90 */  {GTP_EXT_RAN_TR_CONT, decode_gtp_ran_tr_cont},                      /* 7.7.43 */
/* 0x91 */  {GTP_EXT_PDP_CONT_PRIO, decode_gtp_pdp_cont_prio},                  /* 7.7.45 */
/* 0x92 */  {GTP_EXT_ADD_RAB_SETUP_INF, decode_gtp_add_rab_setup_inf},          /* 7.7.45A */
/* 0x93 */  {GTP_EXT_SGSN_NO, decode_gtp_sgsn_no},                              /* 7.7.47 */
/* 0x94 */  {GTP_EXT_COMMON_FLGS, decode_gtp_common_flgs},                      /* 7.7.48 */
/* 0x95 */  {GTP_EXT_APN_RES, decode_gtp_apn_res},                              /* 3G */
/* 0x96 */  {GTP_EXT_RA_PRIO_LCS, decode_gtp_ra_prio_lcs},                      /* 7.7.25B */
/* 0x97 */  {GTP_EXT_RAT_TYPE, decode_gtp_rat_type},                            /* 3G */
/* 0x98 */  {GTP_EXT_USR_LOC_INF, decode_gtp_usr_loc_inf},                      /* 7.7.51 */
/* 0x99 */  {GTP_EXT_MS_TIME_ZONE, decode_gtp_ms_time_zone},                    /* 7.7.52 */
/* 0x9a */  {GTP_EXT_IMEISV, decode_gtp_imeisv},                                /* 3G 7.7.53 */
/* 0x9b */  {GTP_EXT_CAMEL_CHG_INF_CON, decode_gtp_camel_chg_inf_con},          /* 7.7.54 */
/* 0x9c */  {GTP_EXT_MBMS_UE_CTX, decode_gtp_mbms_ue_ctx},                      /* 7.7.55 */
/* 0x9d */  {GTP_EXT_TMGI, decode_gtp_tmgi},                                    /* 7.7.56 */
/* 0x9e */  {GTP_EXT_RIM_RA, decode_gtp_rim_ra},                                /* 7.7.57 */
/* 0x9f */  {GTP_EXT_MBMS_PROT_CONF_OPT, decode_gtp_mbms_prot_conf_opt},        /* 7.7.58 */
/* 0xa0 */  {GTP_EXT_MBMS_SA, decode_gtp_mbms_sa},                              /* 7.7.60 */
/* 0xa1 */  {GTP_EXT_SRC_RNC_PDP_CTX_INF, decode_gtp_src_rnc_pdp_ctx_inf},      /* 7.7.61 */
/* 0xa2 */  {GTP_EXT_ADD_TRS_INF, decode_gtp_add_trs_inf},                      /* 7.7.62 */
/* 0xa3 */  {GTP_EXT_HOP_COUNT, decode_gtp_hop_count},                          /* 7.7.63 */
/* 0xa4 */  {GTP_EXT_SEL_PLMN_ID, decode_gtp_sel_plmn_id},                      /* 7.7.64 */
/* 0xa5 */  {GTP_EXT_MBMS_SES_ID, decode_gtp_mbms_ses_id},                      /* 7.7.65 */
/* 0xa6 */  {GTP_EXT_MBMS_2G_3G_IND, decode_gtp_mbms_2g_3g_ind},                /* 7.7.66 */
/* 0xa7 */  {GTP_EXT_ENH_NSAPI, decode_gtp_enh_nsapi},                          /* 7.7.67 */
/* 0xa8 */  {GTP_EXT_MBMS_SES_DUR, decode_gtp_mbms_ses_dur},                    /* 7.7.59 */
/* 0xa9 */  {GTP_EXT_ADD_MBMS_TRS_INF, decode_gtp_add_mbms_trs_inf},            /* 7.7.68 */
/* 0xaa */  {GTP_EXT_MBMS_SES_ID_REP_NO, decode_gtp_mbms_ses_id_rep_no},        /* 7.7.69 */
/* 0xab */  {GTP_EXT_MBMS_TIME_TO_DATA_TR, decode_gtp_mbms_time_to_data_tr},    /* 7.7.70 */
/* 0xac */  {GTP_EXT_PS_HO_REQ_CTX, decode_gtp_ps_ho_req_ctx},                  /* 7.7.71 */
/* 0xad */  {GTP_EXT_BSS_CONT, decode_gtp_bss_cont},                            /* 7.7.72 */
/* 0xae */  {GTP_EXT_CELL_ID, decode_gtp_cell_id},                              /* 7.7.73 */
/* 0xaf */  {GTP_EXT_PDU_NO, decode_gtp_pdu_no},                                /* 7.7.74 */
/* 0xb0 */  {GTP_EXT_BSSGP_CAUSE, decode_gtp_bssgp_cause},                      /* 7.7.75 */
/* 0xb1 */  {GTP_EXT_REQ_MBMS_BEARER_CAP, decode_gtp_mbms_bearer_cap},          /* 7.7.76 */
/* 0xb2 */  {GTP_EXT_RIM_ROUTING_ADDR_DISC, decode_gtp_rim_ra_disc},            /* 7.7.77 */
/* 0xb3 */  {GTP_EXT_LIST_OF_SETUP_PFCS, decode_gtp_lst_set_up_pfc},            /* 7.7.78 */
/* 0xb4 */  {GTP_EXT_PS_HANDOVER_XIP_PAR, decode_gtp_ps_handover_xid},          /* 7.7.79 */
/* 0xb5 */  {GTP_EXT_MS_INF_CHG_REP_ACT, decode_gtp_ms_inf_chg_rep_act},        /* 7.7.80 */
/* 0xb6 */  {GTP_EXT_DIRECT_TUNNEL_FLGS, decode_gtp_direct_tnl_flg},            /* 7.7.81 */
/* 0xb7 */  {GTP_EXT_CORRELATION_ID, decode_gtp_corrl_id},                      /* 7.7.82 */
/* 0xb8 */  {GTP_EXT_BEARER_CONTROL_MODE, decode_gtp_bearer_cntrl_mod},         /* 7.7.83 */
/* 0xb9 */  {GTP_EXT_MBMS_FLOW_ID, decode_gtp_mbms_flow_id},                    /* 7.7.84 */
/* 0xba */  {GTP_EXT_MBMS_IP_MCAST_DIST, decode_gtp_mbms_ip_mcast_dist},        /* 7.7.85 */
/* 0xba */  {GTP_EXT_MBMS_DIST_ACK, decode_gtp_mbms_dist_ack},                  /* 7.7.86 */
/* 0xbc */  {GTP_EXT_RELIABLE_IRAT_HO_INF, decode_gtp_reliable_irat_ho_inf},    /* 7.7.87 */
/* 0xbd */  {GTP_EXT_RFSP_INDEX, decode_gtp_rfsp_index},                        /* 7.7.88 */

/* 0xbe */  {GTP_EXT_FQDN, decode_gtp_fqdn},                                    /* 7.7.90 */
/* 0xbf */  {GTP_EXT_EVO_ALLO_RETE_P1, decode_gtp_evolved_allc_rtn_p1},         /* 7.7.91 */
/* 0xc0 */  {GTP_EXT_EVO_ALLO_RETE_P2, decode_gtp_evolved_allc_rtn_p2},         /* 7.7.92 */
/* 0xc1 */  {GTP_EXT_EXTENDED_COMMON_FLGS, decode_gtp_extended_common_flgs},    /* 7.7.93 */
/* 0xc2 */  {GTP_EXT_UCI, decode_gtp_uci},                                      /* 7.7.94 */
/* 0xc3 */  {GTP_EXT_CSG_INF_REP_ACT, decode_gtp_csg_inf_rep_act},              /* 7.7.95 */
/* 0xc4 */  {GTP_EXT_CSG_ID, decode_gtp_csg_id},                                /* 7.7.96 */
/* 0xc5 */  {GTP_EXT_CMI, decode_gtp_cmi},                                      /* 7.7.97 */
/* 0xc6 */  {GTP_EXT_AMBR, decode_gtp_apn_ambr},                                /* 7.7.98 */
/* 0xc7 */  {GTP_EXT_UE_NETWORK_CAP, decode_gtp_ue_network_cap},                /* 7.7.99 */
/* 0xc8 */  {GTP_EXT_UE_AMBR, decode_gtp_ue_ambr},                              /* 7.7.100 */
/* 0xc9 */  {GTP_EXT_APN_AMBR_WITH_NSAPI, decode_gtp_apn_ambr_with_nsapi},      /* 7.7.101 */
/* 0xCA */  {GTP_EXT_GGSN_BACK_OFF_TIME, decode_gtp_ggsn_back_off_time},        /* 7.7.102 */
/* 0xCB */  {GTP_EXT_SIG_PRI_IND, decode_gtp_sig_pri_ind},                      /* 7.7.103 */
/* 0xCC */  {GTP_EXT_SIG_PRI_IND_W_NSAPI, decode_gtp_sig_pri_ind_w_nsapi},      /* 7.7.104 */
/* 0xCD */  {GTP_EXT_HIGHER_BR_16MB_FLG, decode_gtp_higher_br_16mb_flg},        /* 7.7.105 */
/* 0xCE */  {GTP_EXT_MAX_MBR_APN_AMBR, decode_gtp_max_mbr_apn_ambr},            /* 7.7.106 */
/* 0xCF */  {GTP_EXT_ADD_MM_CTX_SRVCC, decode_gtp_add_mm_ctx_srvcc},            /* 7.7.107 */
/* 0xD0 */  {GTP_EXT_ADD_FLGS_SRVCC, decode_gtp_add_flgs_srvcc},                /* 7.7.108 */
/* 0xD1 */  {GTP_EXT_STN_SR, decode_gtp_stn_sr},                                /* 7.7.109 */
/* 0xD2 */  {GTP_EXT_C_MSISDN, decode_gtp_c_msisdn},                            /* 7.7.110 */
/* 0xD3 */  {GTP_EXT_EXT_RANAP_CAUSE, decode_gtp_ext_ranap_cause},              /* 7.7.111 */
/* 0xD4 */  {GTP_EXT_ENODEB_ID, decode_gtp_ext_enodeb_id },                     /* 7.7.112 */
/* 0xD5 */  {GTP_EXT_SEL_MODE_W_NSAPI, decode_gtp_ext_sel_mode_w_nsapi },       /* 7.7.113 */
/* 0xD6 */  {GTP_EXT_ULI_TIMESTAMP, decode_gtp_ext_uli_timestamp },             /* 7.7.114 */
/* 0xD7 */  {GTP_EXT_LHN_ID_W_SAPI, decode_gtp_ext_lhn_id_w_sapi },             /* 7.7.115 */
/* 0xD8 */  {GTP_EXT_CN_OP_SEL_ENTITY, decode_gtp_ext_cn_op_sel_entity },       /* 7.7.116 */
/* 0xD9 */  {GTP_EXT_UE_USAGE_TYPE, decode_gtp_ue_usage_type },                 /* 7.7.117 */
/* 0xDA */  {GTP_EXT_EXT_COMMON_FLGS_II, decode_gtp_extended_common_flgs_II },  /* 7.7.118 */
/* 0xDB */  {GTP_EXT_NODE_IDENTIFIER, decode_gtp_ext_node_id },                 /* 7.7.119 */
/* 0xDC */  {GTP_EXT_CIOT_OPT_SUP_IND, decode_gtp_ciot_opt_sup_ind },           /* 7.7.120 */
/* 0xDD */  {GTP_EXT_SCEF_PDN_CONNECTION, decode_gtp_scef_pdn_conn },           /* 7.7.121 */
/* 0xDE */  {GTP_EXT_IOV_UPDATES_COUNTER, decode_gtp_iov_updates_counter },     /* 7.7.122 */
/* 0xDF */  {GTP_EXT_MAPPED_UE_USAGE_TYPE, decode_gtp_mapped_ue_usage_type },   /* 7.7.123 */
/* 0xE0 */  {GTP_EXT_UP_FUN_SEL_IND_FLAGS, decode_gtp_up_fun_sel_ind_flags },   /* 7.7.124 */

/* 0xf9 */  {GTP_EXT_REL_PACK, decode_gtp_rel_pack },                           /* charging */
/* 0xfa */  {GTP_EXT_CAN_PACK, decode_gtp_can_pack},                            /* charging */
/* 0xfb */  {GTP_EXT_CHRG_ADDR, decode_gtp_chrg_addr},

/* 0xfc */  {GTP_EXT_DATA_REQ, decode_gtp_data_req},                           /* charging */
/* 0xfd */  {GTP_EXT_DATA_RESP, decode_gtp_data_resp},                         /* charging */
/* 0xfe */  {GTP_EXT_NODE_ADDR, decode_gtp_node_addr},
/* 0xff */  {GTP_EXT_PRIV_EXT, decode_gtp_priv_ext},
    {0, decode_gtp_unknown}
};

#define NUM_GTP_IES 255
static gint ett_gtp_ies[NUM_GTP_IES];

static guint8 gtp_version = 0;

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
            str[j++] = ' ';
        if (bits8to5 <= 9)
            str[j++] = BCD2CHAR(bits8to5);
        else
            str[j++] = ' ';
    }
    str[j] = '\0';
    return str;
}


/* Next definitions and function check_field_presence_and_decoder checks if given field
 * in GTP packet is compliant with ETSI
 */
typedef int (ie_decoder) (tvbuff_t *, int, packet_info *, proto_tree *, session_args_t *);

typedef struct {
    guint8 code;
    guint8 presence;
    ie_decoder *alt_decoder;
} ext_header;

typedef struct {
    guint8 code;
    ext_header fields[46];
} _gtp_mess_items;

/* ---------------------
 * GPRS messages
 * ---------------------*/
static _gtp_mess_items gprs_mess_items[] = {

    {
        GTP_MSG_ECHO_REQ, {
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_ECHO_RESP, {
            {GTP_EXT_RECOVER, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_VER_NOT_SUPP, {
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_NODE_ALIVE_REQ, {
            {GTP_EXT_NODE_ADDR, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_NODE_ALIVE_RESP, {
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_REDIR_REQ, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_NODE_ADDR, GTP_OPTIONAL, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_REDIR_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_CREATE_PDP_REQ, {
            {GTP_EXT_QOS_GPRS, GTP_MANDATORY, NULL},
            {GTP_EXT_RECOVER, GTP_OPTIONAL, NULL},
            {GTP_EXT_SEL_MODE, GTP_MANDATORY, NULL},
            {GTP_EXT_FLOW_LABEL, GTP_MANDATORY, NULL},
            {GTP_EXT_FLOW_SIG, GTP_MANDATORY, NULL},
            {GTP_EXT_MSISDN, GTP_MANDATORY, NULL},
            {GTP_EXT_USER_ADDR, GTP_MANDATORY, NULL},
            {GTP_EXT_APN, GTP_MANDATORY, NULL},
            {GTP_EXT_PROTO_CONF, GTP_OPTIONAL, NULL},
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY, NULL},
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_CREATE_PDP_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_QOS_GPRS, GTP_CONDITIONAL, NULL},
            {GTP_EXT_REORDER, GTP_CONDITIONAL, NULL},
            {GTP_EXT_RECOVER, GTP_OPTIONAL, NULL},
            {GTP_EXT_FLOW_LABEL, GTP_CONDITIONAL, NULL},
            {GTP_EXT_FLOW_SIG, GTP_CONDITIONAL, NULL},
            {GTP_EXT_CHRG_ID, GTP_CONDITIONAL, NULL},
            {GTP_EXT_USER_ADDR, GTP_CONDITIONAL, NULL},
            {GTP_EXT_PROTO_CONF, GTP_OPTIONAL, NULL},
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL, NULL},
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL, NULL},
            {GTP_EXT_CHRG_ADDR, GTP_OPTIONAL, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_UPDATE_PDP_REQ, {
            {GTP_EXT_QOS_GPRS, GTP_MANDATORY, NULL},
            {GTP_EXT_RECOVER, GTP_OPTIONAL, NULL},
            {GTP_EXT_FLOW_LABEL, GTP_MANDATORY, NULL},
            {GTP_EXT_FLOW_SIG, GTP_MANDATORY, NULL},
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY, NULL},
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL},
        }
    },
    {
        GTP_MSG_UPDATE_PDP_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_QOS_GPRS, GTP_CONDITIONAL, NULL},
            {GTP_EXT_RECOVER, GTP_OPTIONAL, NULL},
            {GTP_EXT_FLOW_LABEL, GTP_CONDITIONAL, NULL},
            {GTP_EXT_FLOW_SIG, GTP_CONDITIONAL, NULL},
            {GTP_EXT_CHRG_ID, GTP_CONDITIONAL, NULL},
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL, NULL},
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL, NULL},
            {GTP_EXT_CHRG_ADDR, GTP_OPTIONAL, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_DELETE_PDP_REQ, {
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_DELETE_PDP_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL},
        }
    },
    {
        GTP_MSG_INIT_PDP_CONTEXT_ACT_REQ, {
            {GTP_EXT_QOS_GPRS, GTP_MANDATORY, NULL},
            {GTP_EXT_RECOVER, GTP_OPTIONAL, NULL},
            {GTP_EXT_SEL_MODE, GTP_MANDATORY, NULL},
            {GTP_EXT_FLOW_LABEL, GTP_MANDATORY, NULL},
            {GTP_EXT_FLOW_SIG, GTP_MANDATORY, NULL},
            {GTP_EXT_USER_ADDR, GTP_MANDATORY, NULL},
            {GTP_EXT_APN, GTP_MANDATORY, NULL},
            {GTP_EXT_PROTO_CONF, GTP_OPTIONAL, NULL},
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY, NULL},
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_INIT_PDP_CONTEXT_ACT_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_QOS_GPRS, GTP_CONDITIONAL, NULL},
            {GTP_EXT_REORDER, GTP_CONDITIONAL, NULL},
            {GTP_EXT_RECOVER, GTP_OPTIONAL, NULL},
            {GTP_EXT_FLOW_LABEL, GTP_CONDITIONAL, NULL},
            {GTP_EXT_FLOW_SIG, GTP_CONDITIONAL, NULL},
            {GTP_EXT_CHRG_ID, GTP_CONDITIONAL, NULL},
            {GTP_EXT_USER_ADDR, GTP_CONDITIONAL, NULL},
            {GTP_EXT_PROTO_CONF, GTP_OPTIONAL, NULL},
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL, NULL},
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL, NULL},
            {GTP_EXT_CHRG_ADDR, GTP_OPTIONAL, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_DELETE_AA_PDP_REQ, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_DELETE_AA_PDP_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_ERR_IND, {
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_PDU_NOTIFY_REQ, {
            {GTP_EXT_USER_ADDR, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_PDU_NOTIFY_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_PDU_NOTIFY_REJ_REQ, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_USER_ADDR, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_PDU_NOTIFY_REJ_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_SEND_ROUT_INFO_REQ, {
            {GTP_EXT_IMSI, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_SEND_ROUT_INFO_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_IMSI, GTP_MANDATORY, NULL},
            {GTP_EXT_MAP_CAUSE, GTP_OPTIONAL, NULL},
            {GTP_EXT_MS_REASON, GTP_OPTIONAL, NULL},
            {GTP_EXT_GSN_ADDR, GTP_OPTIONAL, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_FAIL_REP_REQ, {
            {GTP_EXT_IMSI, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_FAIL_REP_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_MAP_CAUSE, GTP_OPTIONAL, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_MS_PRESENT_REQ, {
            {GTP_EXT_IMSI, GTP_MANDATORY, NULL},
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_MS_PRESENT_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_IDENT_REQ, {
            {GTP_EXT_RAI, GTP_MANDATORY, NULL},
            {GTP_EXT_PTMSI, GTP_MANDATORY, NULL},
            {GTP_EXT_PTMSI_SIG, GTP_OPTIONAL, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_IDENT_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_IMSI, GTP_CONDITIONAL, NULL},
            {GTP_EXT_AUTH_TRI, GTP_OPTIONAL, NULL},
            {GTP_EXT_AUTH_QUI, GTP_OPTIONAL, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_SGSN_CNTXT_REQ, {
            {GTP_EXT_IMSI, GTP_CONDITIONAL, NULL},
            {GTP_EXT_RAI, GTP_MANDATORY, NULL},
            {GTP_EXT_TLLI, GTP_MANDATORY, NULL},
            {GTP_EXT_PTMSI_SIG, GTP_OPTIONAL, NULL},
            {GTP_EXT_MS_VALID, GTP_OPTIONAL, NULL},
            {GTP_EXT_FLOW_SIG, GTP_MANDATORY, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_SGSN_CNTXT_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_IMSI, GTP_CONDITIONAL, NULL},
            {GTP_EXT_FLOW_SIG, GTP_CONDITIONAL, NULL},
            {GTP_EXT_MM_CNTXT, GTP_CONDITIONAL, NULL},
            {GTP_EXT_PDP_CNTXT, GTP_CONDITIONAL, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_SGSN_CNTXT_ACK, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_FLOW_II, GTP_CONDITIONAL, NULL},
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_DATA_TRANSF_REQ, {
            {GTP_EXT_TR_COMM, GTP_MANDATORY, NULL},
            {GTP_EXT_DATA_REQ, GTP_CONDITIONAL, NULL},
            {GTP_EXT_REL_PACK, GTP_CONDITIONAL, NULL},
            {GTP_EXT_CAN_PACK, GTP_CONDITIONAL, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_DATA_TRANSF_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_DATA_RESP, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        0, {
            {0, 0, NULL}
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
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_ECHO_RESP, {
            {GTP_EXT_RECOVER, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_VER_NOT_SUPP, {
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_SUPP_EXT_HDR, {
            {GTP_EXT_HDR_LIST, GTP_MANDATORY, NULL},
            {0, 0, NULL}
        }
    },
    /* ??? */
    {
        GTP_MSG_NODE_ALIVE_REQ, {
            {GTP_EXT_NODE_ADDR, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_NODE_ALIVE_RESP, {
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_REDIR_REQ, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_NODE_ADDR, GTP_OPTIONAL, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_REDIR_REQ, {
            {0, 0, NULL}
        }
    },
    /* 7.3 Tunnel Management Messages */
    {
        GTP_MSG_CREATE_PDP_REQ, {
            {GTP_EXT_IMSI, GTP_CONDITIONAL, NULL},
            /* RAI is in TS 29.060 V6.11.0 */
            {GTP_EXT_RAI, GTP_OPTIONAL, NULL},        /* Routeing Area Identity (RAI) Optional 7.7.3 */
            {GTP_EXT_RECOVER, GTP_OPTIONAL, NULL},
            {GTP_EXT_SEL_MODE, GTP_CONDITIONAL, NULL},
            {GTP_EXT_TEID, GTP_MANDATORY, NULL},
            {GTP_EXT_TEID_CP, GTP_CONDITIONAL, NULL},
            {GTP_EXT_NSAPI, GTP_MANDATORY, NULL},
            {GTP_EXT_NSAPI, GTP_CONDITIONAL, NULL}, /* Linked NSAPI Conditional */
            {GTP_EXT_CHRG_CHAR, GTP_OPTIONAL, NULL},
            {GTP_EXT_TRACE_REF, GTP_OPTIONAL, NULL},
            {GTP_EXT_TRACE_TYPE, GTP_OPTIONAL, NULL},
            {GTP_EXT_USER_ADDR, GTP_CONDITIONAL, NULL},
            {GTP_EXT_APN, GTP_CONDITIONAL, NULL},
            {GTP_EXT_PROTO_CONF, GTP_CONDITIONAL, NULL},
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY, decode_gtp_sgsn_addr_for_control_plane},
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY, decode_gtp_sgsn_addr_for_user_plane},
            {GTP_EXT_MSISDN, GTP_CONDITIONAL, NULL},
            {GTP_EXT_QOS_UMTS, GTP_MANDATORY, NULL},
            {GTP_EXT_TFT, GTP_CONDITIONAL, NULL},
            {GTP_EXT_TRIGGER_ID, GTP_OPTIONAL, NULL},
            {GTP_EXT_OMC_ID, GTP_OPTIONAL, NULL},
            {GTP_EXT_COMMON_FLGS, GTP_OPTIONAL, NULL}, /* Common Flags Optional 7.7.48 */
            {GTP_EXT_APN_RES, GTP_OPTIONAL, NULL},
            {GTP_EXT_RAT_TYPE, GTP_OPTIONAL, NULL},
            {GTP_EXT_USR_LOC_INF, GTP_OPTIONAL, NULL},
            {GTP_EXT_MS_TIME_ZONE, GTP_OPTIONAL, NULL},
            {GTP_EXT_IMEISV, GTP_CONDITIONAL, NULL},
            {GTP_EXT_CAMEL_CHG_INF_CON, GTP_OPTIONAL, NULL},
            {GTP_EXT_ADD_TRS_INF, GTP_OPTIONAL, NULL},
            /* Updated to TS 29.060 V16.0.0 */
            {GTP_EXT_CORRELATION_ID, GTP_OPTIONAL, NULL}, /* 7.7.82 */
            {GTP_EXT_EVO_ALLO_RETE_P1, GTP_OPTIONAL, NULL}, /* 7.7.91 */
            {GTP_EXT_EXTENDED_COMMON_FLGS, GTP_OPTIONAL, NULL}, /* 7.7.93 */
            {GTP_EXT_UCI, GTP_OPTIONAL, NULL}, /* 7.7.94 */
            {GTP_EXT_AMBR, GTP_OPTIONAL, NULL}, /* 7.7.98 */
            {GTP_EXT_SIG_PRI_IND, GTP_OPTIONAL, NULL}, /* 7.7.103 */
            {GTP_EXT_CN_OP_SEL_ENTITY, GTP_OPTIONAL, NULL}, /* 7.7.116 */
            {GTP_EXT_MAPPED_UE_USAGE_TYPE, GTP_OPTIONAL, NULL},  /* 7.7.123 */
            {GTP_EXT_UP_FUN_SEL_IND_FLAGS, GTP_OPTIONAL, NULL},  /* 7.7.124 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_CREATE_PDP_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_REORDER, GTP_CONDITIONAL, NULL},
            {GTP_EXT_RECOVER, GTP_OPTIONAL, NULL},
            {GTP_EXT_TEID, GTP_CONDITIONAL, NULL},
            {GTP_EXT_TEID_CP, GTP_CONDITIONAL, NULL},
            {GTP_EXT_NSAPI, GTP_CONDITIONAL, NULL},
            {GTP_EXT_CHRG_ID, GTP_CONDITIONAL, NULL},
            {GTP_EXT_USER_ADDR, GTP_CONDITIONAL, NULL},
            {GTP_EXT_PROTO_CONF, GTP_OPTIONAL, NULL},
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL, decode_gtp_ggsn_addr_for_control_plane},
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL, decode_gtp_ggsn_addr_for_user_plane},
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL, NULL}, /* Alternative GGSN Addreses for Control Plane 7.7.32 */
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL, NULL}, /* Alternative GGSN Address for user traffic 7.7.32 */
            {GTP_EXT_QOS_UMTS, GTP_CONDITIONAL, NULL},
            {GTP_EXT_CHRG_ADDR, GTP_OPTIONAL, NULL},
            /* TS 29.060 V6.11.0 */
            {GTP_EXT_CHRG_ADDR, GTP_OPTIONAL, NULL},   /* Alternative Charging Gateway Address Optional 7.7.44 */
            {GTP_EXT_COMMON_FLGS, GTP_OPTIONAL, NULL}, /* Common Flags Optional 7.7.48 */
            {GTP_EXT_APN_RES, GTP_OPTIONAL, NULL},     /* APN Restriction Optional 7.7.49 */
            {GTP_EXT_MS_INF_CHG_REP_ACT, GTP_OPTIONAL, NULL}, /* 7.7.80 */
            {GTP_EXT_BEARER_CONTROL_MODE, GTP_OPTIONAL, NULL}, /* 7.7.83 */
            {GTP_EXT_EVO_ALLO_RETE_P1, GTP_OPTIONAL, NULL}, /* 7.7.91 */
            {GTP_EXT_EXTENDED_COMMON_FLGS, GTP_OPTIONAL, NULL}, /* 7.7.93 */
            {GTP_EXT_CSG_INF_REP_ACT, GTP_OPTIONAL, NULL}, /* 7.7.95 */
            {GTP_EXT_AMBR, GTP_OPTIONAL, NULL}, /* 7.7.98 */
            {GTP_EXT_GGSN_BACK_OFF_TIME, GTP_OPTIONAL, NULL}, /* 7.7.102 */
            {GTP_EXT_EXT_COMMON_FLGS_II, GTP_OPTIONAL, NULL}, /* 7.7.118 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {                           /* checked, SGSN -> GGSN */
        GTP_MSG_UPDATE_PDP_REQ, {
            {GTP_EXT_IMSI, GTP_CONDITIONAL, NULL},
            {GTP_EXT_RAI, GTP_OPTIONAL, NULL},         /* Routeing Area Identity (RAI) Optional 7.7.3 */
            {GTP_EXT_RECOVER, GTP_OPTIONAL, NULL},
            {GTP_EXT_TEID, GTP_MANDATORY, NULL},
            {GTP_EXT_TEID_CP, GTP_CONDITIONAL, NULL},
            {GTP_EXT_NSAPI, GTP_MANDATORY, NULL},
            {GTP_EXT_TRACE_REF, GTP_OPTIONAL, NULL},
            {GTP_EXT_TRACE_TYPE, GTP_OPTIONAL, NULL},
            {GTP_EXT_PROTO_CONF, GTP_OPTIONAL, NULL},  /* Protocol Configuration Options Optional 7.7.31 */
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY, decode_gtp_sgsn_addr_for_control_plane},   /* SGSN Address for Control Plane Mandatory GSN Address 7.7.32 */
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY, decode_gtp_sgsn_addr_for_user_plane},      /* SGSN Address for User Traffic Mandatory GSN Address 7.7.32 */
            {GTP_EXT_GSN_ADDR, GTP_OPTIONAL, NULL},    /* Alternative SGSN Address for Control Plane Conditional GSN Address 7.7.32 */
            {GTP_EXT_GSN_ADDR, GTP_OPTIONAL, NULL},    /* Alternative SGSN Address for User Traffic Conditional GSN Address 7.7.32 */
            {GTP_EXT_QOS_UMTS, GTP_MANDATORY, NULL},
            {GTP_EXT_TFT, GTP_OPTIONAL, NULL},
            {GTP_EXT_TRIGGER_ID, GTP_OPTIONAL, NULL},
            {GTP_EXT_OMC_ID, GTP_OPTIONAL, NULL},
            {GTP_EXT_COMMON_FLGS, GTP_OPTIONAL, NULL},        /* Common Flags Optional 7.7.48 */
            {GTP_EXT_RAT_TYPE, GTP_OPTIONAL, NULL},           /* RAT Type Optional 7.7.50 */
            {GTP_EXT_USR_LOC_INF, GTP_OPTIONAL, NULL},        /* User Location Information Optional 7.7.51 */
            {GTP_EXT_MS_TIME_ZONE, GTP_OPTIONAL, NULL},       /* MS Time Zone Optional 7.7.52 */
            {GTP_EXT_ADD_TRS_INF, GTP_OPTIONAL, NULL},        /* Additional Trace Info Optional 7.7.62 */
            {GTP_EXT_DIRECT_TUNNEL_FLGS, GTP_OPTIONAL, NULL}, /* Direct Tunnel Flags     7.7.81 */
            {GTP_EXT_EVO_ALLO_RETE_P1, GTP_OPTIONAL, NULL}, /* 7.7.91 */
            {GTP_EXT_EXTENDED_COMMON_FLGS, GTP_OPTIONAL, NULL}, /* 7.7.93 */
            {GTP_EXT_UCI, GTP_OPTIONAL, NULL}, /* 7.7.94 */
            {GTP_EXT_AMBR, GTP_OPTIONAL, NULL}, /* 7.7.98 */
            {GTP_EXT_SIG_PRI_IND, GTP_OPTIONAL, NULL}, /* 7.7.103 */
            {GTP_EXT_UE_USAGE_TYPE, GTP_OPTIONAL, NULL}, /* 7.7.117 */
            {GTP_EXT_IMEISV, GTP_OPTIONAL, NULL}, /* 7.7.53 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {                           /* checked, GGSN -> SGSN */
        GTP_MSG_UPDATE_PDP_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_RECOVER, GTP_OPTIONAL, NULL},
            {GTP_EXT_TEID, GTP_CONDITIONAL, NULL},
            {GTP_EXT_TEID_CP, GTP_CONDITIONAL, NULL},
            {GTP_EXT_CHRG_ID, GTP_CONDITIONAL, NULL},
            {GTP_EXT_PROTO_CONF, GTP_OPTIONAL, NULL},  /* Protocol Configuration Options Optional 7.7.31 */
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL, decode_gtp_ggsn_addr_for_control_plane},
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL, decode_gtp_ggsn_addr_for_user_plane},
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL, NULL},    /* Alternative GGSN Address for Control Plane Conditional GSN Address 7.7.32 */
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL, NULL},    /* Alternative GGSN Address for User Traffic Conditional GSN Address 7.7.32 */
            {GTP_EXT_QOS_UMTS, GTP_CONDITIONAL, NULL},
            {GTP_EXT_CHRG_ADDR, GTP_OPTIONAL, NULL},
            {GTP_EXT_CHRG_ADDR, GTP_OPTIONAL, NULL},   /* Alternative Charging Gateway Address Optional 7.7.44 */
            {GTP_EXT_COMMON_FLGS, GTP_OPTIONAL, NULL}, /* Common Flags Optional 7.7.48 */
            {GTP_EXT_APN_RES, GTP_OPTIONAL, NULL},     /* APN Restriction Optional 7.7.49 */
            {GTP_EXT_BEARER_CONTROL_MODE, GTP_OPTIONAL, NULL}, /* 7.7.83 */
            {GTP_EXT_MS_INF_CHG_REP_ACT, GTP_OPTIONAL, NULL}, /* 7.7.80 */
            {GTP_EXT_EVO_ALLO_RETE_P1, GTP_OPTIONAL, NULL}, /* 7.7.91 */
            {GTP_EXT_CSG_INF_REP_ACT, GTP_OPTIONAL, NULL}, /* 7.7.95 */
            {GTP_EXT_AMBR, GTP_OPTIONAL, NULL}, /* 7.7.98 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_DELETE_PDP_REQ, {
            {GTP_EXT_CAUSE, GTP_OPTIONAL, NULL},
            {GTP_EXT_TEAR_IND, GTP_CONDITIONAL, NULL},
            {GTP_EXT_NSAPI, GTP_MANDATORY, NULL},
            {GTP_EXT_PROTO_CONF, GTP_OPTIONAL, NULL}, /* Protocol Configuration Options Optional 7.7.31 */
            {GTP_EXT_USR_LOC_INF, GTP_OPTIONAL, NULL}, /* User Location Information Optional 7.7.51 */
            {GTP_EXT_MS_TIME_ZONE, GTP_OPTIONAL, NULL}, /* MS Time Zone Optional 7.7.52 */
            {GTP_EXT_EXTENDED_COMMON_FLGS, GTP_OPTIONAL, NULL}, /* 7.7.93 */
            {GTP_EXT_ULI_TIMESTAMP, GTP_OPTIONAL, NULL}, /* 7.7.114 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_DELETE_PDP_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_PROTO_CONF, GTP_OPTIONAL, NULL}, /* Protocol Configuration Options Optional 7.7.31 */
            {GTP_EXT_USR_LOC_INF, GTP_OPTIONAL, NULL}, /* User Location Information Optional 7.7.51 */
            {GTP_EXT_MS_TIME_ZONE, GTP_OPTIONAL, NULL}, /* MS Time Zone Optional 7.7.52 */
            {GTP_EXT_ULI_TIMESTAMP, GTP_OPTIONAL, NULL}, /* 7.7.114 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_ERR_IND, {
            {GTP_EXT_TEID, GTP_MANDATORY, NULL},
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY, decode_gtp_ggsn_addr_for_control_plane},  /* GSN Address Mandatory 7.7.32 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_PDU_NOTIFY_REQ, {
            {GTP_EXT_IMSI, GTP_MANDATORY, NULL},
            {GTP_EXT_TEID_CP, GTP_MANDATORY, NULL},
            {GTP_EXT_USER_ADDR, GTP_MANDATORY, NULL},
            {GTP_EXT_APN, GTP_MANDATORY, NULL},
            {GTP_EXT_PROTO_CONF, GTP_OPTIONAL, NULL}, /* Protocol Configuration Options Optional 7.7.31 */
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY, decode_gtp_ggsn_addr_for_control_plane},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_PDU_NOTIFY_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_PDU_NOTIFY_REJ_REQ, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_TEID_CP, GTP_MANDATORY, NULL},
            {GTP_EXT_USER_ADDR, GTP_MANDATORY, NULL},
            {GTP_EXT_APN, GTP_MANDATORY, NULL},
            {GTP_EXT_PROTO_CONF, GTP_OPTIONAL, NULL}, /* Protocol Configuration Options Optional 7.7.31 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_PDU_NOTIFY_REJ_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_INIT_PDP_CONTEXT_ACT_REQ, {
            {GTP_EXT_NSAPI, GTP_MANDATORY, NULL},  /* NSAPI Mandatory 7.7.17 */
            {GTP_EXT_PROTO_CONF, GTP_OPTIONAL, NULL}, /* Protocol Configuration Options Optional 7.7.31 */
            {GTP_EXT_QOS_UMTS, GTP_MANDATORY, NULL}, /* Quality of Service Profile Mandatory 7.7.34 */
            {GTP_EXT_TFT, GTP_CONDITIONAL, NULL}, /* TFT Conditional 7.7.36 */
            {GTP_EXT_CORRELATION_ID, GTP_MANDATORY, NULL}, /* 7.7.82 */
            {GTP_EXT_EVO_ALLO_RETE_P1, GTP_OPTIONAL, NULL}, /* 7.7.91 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
        }
    },
    {
        GTP_MSG_INIT_PDP_CONTEXT_ACT_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_PROTO_CONF, GTP_CONDITIONAL, NULL}, /* Protocol Configuration Options Conditional 7.7.31 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
        }
    },
    /* 7.4 Location Management Messages */
    {
        GTP_MSG_SEND_ROUT_INFO_REQ, {
            {GTP_EXT_IMSI, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_SEND_ROUT_INFO_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_IMSI, GTP_MANDATORY, NULL},
            {GTP_EXT_MAP_CAUSE, GTP_OPTIONAL, NULL},
            {GTPv1_EXT_MS_REASON, GTP_OPTIONAL, NULL},
            {GTP_EXT_GSN_ADDR, GTP_OPTIONAL, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_FAIL_REP_REQ, {
            {GTP_EXT_IMSI, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_FAIL_REP_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_MAP_CAUSE, GTP_OPTIONAL, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_MS_PRESENT_REQ, {
            {GTP_EXT_IMSI, GTP_MANDATORY, NULL},
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_MS_PRESENT_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    /* 7.5 Mobility Management Messages */
    {
        GTP_MSG_IDENT_REQ, {
            {GTP_EXT_RAI, GTP_MANDATORY, NULL},
            {GTP_EXT_PTMSI, GTP_MANDATORY, NULL},
            {GTP_EXT_PTMSI_SIG, GTP_CONDITIONAL, NULL},
            {GTP_EXT_GSN_ADDR, GTP_OPTIONAL, decode_gtp_sgsn_addr_for_control_plane},   /* SGSN Address for Control Plane Optional 7.7.32 */
            {GTP_EXT_HOP_COUNT, GTP_OPTIONAL, NULL},  /* Hop Counter Optional 7.7.63 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_IDENT_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_IMSI, GTP_CONDITIONAL, NULL},
            {GTP_EXT_AUTH_TRI, GTP_CONDITIONAL, NULL},
            {GTP_EXT_AUTH_QUI, GTP_CONDITIONAL, NULL},
            {GTP_EXT_UE_USAGE_TYPE, GTP_OPTIONAL, NULL}, /* 7.7.117 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_SGSN_CNTXT_REQ, {
            {GTP_EXT_IMSI, GTP_CONDITIONAL, NULL},
            {GTP_EXT_RAI, GTP_MANDATORY, NULL},
            {GTP_EXT_TLLI, GTP_CONDITIONAL, NULL},
            {GTP_EXT_PTMSI, GTP_CONDITIONAL, NULL},
            {GTP_EXT_PTMSI_SIG, GTP_CONDITIONAL, NULL},
            {GTP_EXT_MS_VALID, GTP_OPTIONAL, NULL},
            {GTP_EXT_TEID_CP, GTP_MANDATORY, NULL},
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY, decode_gtp_sgsn_addr_for_control_plane},
            {GTP_EXT_GSN_ADDR, GTP_OPTIONAL, decode_gtp_sgsn_addr_for_control_plane},   /* Alternative SGSN Address for Control Plane Optional 7.7.32 */
            {GTP_EXT_SGSN_NO, GTP_OPTIONAL, NULL},    /* SGSN Number Optional 7.7.47 */
            {GTP_EXT_RAT_TYPE, GTP_OPTIONAL, NULL},   /* RAT Type Optional 7.7.50 */
            {GTP_EXT_HOP_COUNT, GTP_OPTIONAL, NULL},  /* Hop Counter Optional 7.7.63 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_SGSN_CNTXT_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_IMSI, GTP_CONDITIONAL, NULL},
            {GTP_EXT_TEID_CP, GTP_CONDITIONAL, NULL},
            {GTP_EXT_RAB_CNTXT, GTP_CONDITIONAL, NULL},  /* RAB Context Conditional 7.7.19 */
            {GTP_EXT_RP_SMS, GTP_OPTIONAL, NULL},
            {GTP_EXT_RP, GTP_OPTIONAL, NULL},
            {GTP_EXT_PKT_FLOW_ID, GTP_OPTIONAL, NULL},
            {GTP_EXT_CHRG_CHAR, GTP_OPTIONAL, NULL},     /* CharingCharacteristics Optional 7.7.23 */
            {GTP_EXT_RA_PRIO_LCS, GTP_OPTIONAL, NULL},   /* Radio Priority LCS Optional 7.7.25B */
            {GTP_EXT_MM_CNTXT, GTP_CONDITIONAL, NULL},
            {GTP_EXT_PDP_CNTXT, GTP_CONDITIONAL, NULL},
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL, decode_gtp_sgsn_addr_for_control_plane},
            {GTP_EXT_PDP_CONT_PRIO, GTP_OPTIONAL, NULL}, /* PDP Context Prioritization Optional 7.7.45 */
            {GTP_EXT_MBMS_UE_CTX, GTP_OPTIONAL, NULL},   /* MBMS UE Context Optional 7.7.55 */
            {GTP_EXT_RFSP_INDEX, GTP_OPTIONAL, NULL}, /* Subscribed RFSP Index 7.7.88 */
            {GTP_EXT_RFSP_INDEX, GTP_OPTIONAL, NULL}, /* RFSP Index in use 7.7.88 */
            {GTP_EXT_FQDN, GTP_OPTIONAL, NULL}, /* Co-located GGSN-PGW FQDN 7.7.90 */
            {GTP_EXT_EVO_ALLO_RETE_P2, GTP_OPTIONAL, NULL}, /* 7.7.92 */
            {GTP_EXT_EXTENDED_COMMON_FLGS, GTP_OPTIONAL, NULL}, /* 7.7.93 */
            {GTP_EXT_UE_NETWORK_CAP, GTP_OPTIONAL, NULL}, /* 7.7.99 */
            {GTP_EXT_UE_AMBR, GTP_OPTIONAL, NULL}, /* 7.7.100 */
            {GTP_EXT_APN_AMBR_WITH_NSAPI, GTP_OPTIONAL, NULL}, /* 7.7.101 */
            {GTP_EXT_SIG_PRI_IND_W_NSAPI, GTP_OPTIONAL, NULL}, /* 7.7.104 */
            {GTP_EXT_HIGHER_BR_16MB_FLG, GTP_OPTIONAL, NULL}, /* 7.7.105 */
            {GTP_EXT_SEL_MODE_W_NSAPI, GTP_OPTIONAL, NULL}, /* 7.7.113 */
            {GTP_EXT_LHN_ID_W_SAPI, GTP_OPTIONAL, NULL }, /* 7.7.115 */
            {GTP_EXT_UE_USAGE_TYPE, GTP_OPTIONAL, NULL}, /* 7.7.117 */
            {GTP_EXT_EXT_COMMON_FLGS_II, GTP_OPTIONAL, NULL}, /* 7.7.118 */
            {GTP_EXT_SCEF_PDN_CONNECTION, GTP_OPTIONAL, NULL }, /* 7.7.121 */
            {GTP_EXT_IOV_UPDATES_COUNTER, GTP_OPTIONAL, NULL }, /* 7.7.122 */
            {GTP_EXT_GSN_ADDR, GTP_OPTIONAL, NULL},    /* Alternative GGSN Address for Control Plane 7.7.32 */
            {GTP_EXT_GSN_ADDR, GTP_OPTIONAL, NULL},    /* Alternative GGSN Address for User Traffic 7.7.32 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_SGSN_CNTXT_ACK, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_TEID_II, GTP_CONDITIONAL, NULL},
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL, decode_gtp_sgsn_addr_for_user_plane},
            {GTP_EXT_SGSN_NO, GTP_OPTIONAL, NULL},    /* SGSN Number Optional 7.7.47 */
            {GTP_EXT_NODE_IDENTIFIER, GTP_OPTIONAL, NULL}, /* 7.7.119 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_FORW_RELOC_REQ, {
            {GTP_EXT_IMSI, GTP_CONDITIONAL, NULL}, /* The IMSI shall not be included in the message if the MS is emergency attached and the MS is UICCless */
            {GTP_EXT_TEID_CP, GTP_MANDATORY, NULL},
            {GTP_EXT_RANAP_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_PKT_FLOW_ID, GTP_OPTIONAL, NULL},
            {GTP_EXT_CHRG_CHAR, GTP_OPTIONAL, NULL},     /* CharingCharacteristics Optional 7.7.23 */
            {GTP_EXT_MM_CNTXT, GTP_MANDATORY, NULL},
            {GTP_EXT_PDP_CNTXT, GTP_CONDITIONAL, NULL},
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY, decode_gtp_sgsn_addr_for_control_plane},
            {GTP_EXT_TARGET_ID, GTP_MANDATORY, NULL},
            {GTP_EXT_UTRAN_CONT, GTP_MANDATORY, NULL},
            {GTP_EXT_PDP_CONT_PRIO, GTP_OPTIONAL, NULL}, /* PDP Context Prioritization Optional 7.7.45 */
            {GTP_EXT_MBMS_UE_CTX, GTP_OPTIONAL, NULL},   /* MBMS UE Context Optional 7.7.55 */
            {GTP_EXT_SEL_PLMN_ID, GTP_OPTIONAL, NULL},   /* Selected PLMN ID Optional 7.7.64 */
            {GTP_EXT_PS_HO_REQ_CTX, GTP_OPTIONAL, NULL}, /* PS Handover Request Context Optional 7.7.71 */
            {GTP_EXT_BSS_CONT, GTP_OPTIONAL, NULL},      /* BSS Container Optional 7.7.72 */
            {GTP_EXT_CELL_ID, GTP_OPTIONAL, NULL},       /* Cell Identification Optional 7.7.73 */
            {GTP_EXT_BSSGP_CAUSE, GTP_OPTIONAL, NULL},   /* BSSGP Cause Optional 7.7.75 */
            {GTP_EXT_PS_HANDOVER_XIP_PAR, GTP_OPTIONAL, NULL}, /* 7.7.79 */
            {GTP_EXT_DIRECT_TUNNEL_FLGS, GTP_OPTIONAL, NULL}, /* Direct Tunnel Flags     7.7.81 */
            {GTP_EXT_RELIABLE_IRAT_HO_INF, GTP_OPTIONAL, NULL},    /* 7.7.87 */
            {GTP_EXT_RFSP_INDEX, GTP_OPTIONAL, NULL}, /* Subscribed RFSP Index 7.7.88 */
            {GTP_EXT_RFSP_INDEX, GTP_OPTIONAL, NULL}, /* RFSP Index in use 7.7.88 */
            {GTP_EXT_FQDN, GTP_OPTIONAL, NULL}, /* Co-located GGSN-PGW FQDN 7.7.90 */
            {GTP_EXT_EVO_ALLO_RETE_P2, GTP_OPTIONAL, NULL}, /* 7.7.92 */
            {GTP_EXT_EXTENDED_COMMON_FLGS, GTP_OPTIONAL, NULL}, /* 7.7.93 */
            {GTP_EXT_CSG_ID, GTP_OPTIONAL, NULL}, /* 7.7.96 */
            {GTP_EXT_CMI, GTP_OPTIONAL, NULL}, /* 7.7.97 */
            {GTP_EXT_UE_NETWORK_CAP, GTP_OPTIONAL, NULL}, /* 7.7.99 */
            {GTP_EXT_UE_AMBR, GTP_OPTIONAL, NULL}, /* 7.7.100 */
            {GTP_EXT_APN_AMBR_WITH_NSAPI, GTP_OPTIONAL, NULL}, /* 7.7.101 */
            {GTP_EXT_SIG_PRI_IND_W_NSAPI, GTP_OPTIONAL, NULL}, /* 7.7.104 */
            {GTP_EXT_HIGHER_BR_16MB_FLG, GTP_OPTIONAL, NULL}, /* 7.7.105 */
            {GTP_EXT_ADD_MM_CTX_SRVCC, GTP_OPTIONAL, NULL}, /* 7.7.107 */
            {GTP_EXT_ADD_FLGS_SRVCC, GTP_OPTIONAL, NULL}, /* 7.7.108 */
            {GTP_EXT_STN_SR, GTP_OPTIONAL, NULL}, /* 7.7.109 */
            {GTP_EXT_C_MSISDN, GTP_OPTIONAL, NULL}, /* 7.7.110 */
            {GTP_EXT_EXT_RANAP_CAUSE, GTP_OPTIONAL, NULL}, /* 7.7.111 */
            {GTP_EXT_ENODEB_ID, GTP_OPTIONAL, NULL}, /* 7.7.112 */
            {GTP_EXT_SEL_MODE_W_NSAPI, GTP_OPTIONAL, NULL}, /* 7.7.113 */
            {GTP_EXT_UE_USAGE_TYPE, GTP_OPTIONAL, NULL}, /* 7.7.117 */
            {GTP_EXT_EXT_COMMON_FLGS_II, GTP_OPTIONAL, NULL}, /* 7.7.118 */
            {GTP_EXT_SCEF_PDN_CONNECTION, GTP_OPTIONAL, NULL }, /* 7.7.121 */
            {GTP_EXT_GSN_ADDR, GTP_OPTIONAL, NULL},    /* Alternative GGSN Address for Control Plane 7.7.32 */
            {GTP_EXT_GSN_ADDR, GTP_OPTIONAL, NULL},    /* Alternative GGSN Address for User Traffic 7.7.32 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_FORW_RELOC_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_TEID_CP, GTP_CONDITIONAL, NULL},
            {GTP_EXT_TEID_II, GTP_CONDITIONAL, NULL},           /* Tunnel Endpoint Identifier Data II Optional 7.7.15 */
            {GTP_EXT_RANAP_CAUSE, GTP_CONDITIONAL, NULL},
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL, NULL}, /* SGSN Address for Control plane */
            {GTP_EXT_GSN_ADDR, GTP_OPTIONAL, NULL}, /* SGSN Address for User Traffic - cannot appear without above Address for Control plane */
            {GTP_EXT_UTRAN_CONT, GTP_OPTIONAL, NULL},
            {GTP_EXT_RAB_SETUP, GTP_CONDITIONAL, NULL},
            {GTP_EXT_ADD_RAB_SETUP_INF, GTP_CONDITIONAL, NULL}, /* Additional RAB Setup Information Conditional 7.7.45A */
            {GTP_EXT_SGSN_NO, GTP_OPTIONAL, NULL},    /* SGSN Number Optional 7.7.47 */
            {GTP_EXT_BSS_CONT, GTP_OPTIONAL, NULL},      /* BSS Container Optional 7.7.72 */
            {GTP_EXT_BSSGP_CAUSE, GTP_OPTIONAL, NULL},   /* BSSGP Cause Optional 7.7.75 */
            {GTP_EXT_LIST_OF_SETUP_PFCS, GTP_OPTIONAL, NULL}, /* 7.7.78 */
            {GTP_EXT_EXT_RANAP_CAUSE, GTP_OPTIONAL, NULL}, /* 7.7.111 */
            {GTP_EXT_NODE_IDENTIFIER, GTP_OPTIONAL, NULL}, /* 7.7.119 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_FORW_RELOC_COMP, {
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_RELOC_CANCEL_REQ, {
            {GTP_EXT_IMSI, GTP_CONDITIONAL, NULL}, /* If MS is emergency attached and the MS is UICCless, the IMSI cannot be included. */
            {GTP_EXT_IMEISV, GTP_CONDITIONAL, NULL}, /* 7.7.53 */
            {GTP_EXT_EXTENDED_COMMON_FLGS, GTP_OPTIONAL, NULL}, /* 7.7.93 */
            {GTP_EXT_EXT_RANAP_CAUSE, GTP_OPTIONAL, NULL}, /* 7.7.111 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_RELOC_CANCEL_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_FORW_RELOC_ACK, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_FORW_SRNS_CNTXT_ACK, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MSG_FORW_SRNS_CNTXT, {
            {GTP_EXT_RAB_CNTXT, GTP_MANDATORY, NULL},
            {GTP_EXT_SRC_RNC_PDP_CTX_INF, GTP_OPTIONAL, NULL}, /* Source RNC PDCP context info Optional 7.7.61 */
            {GTP_EXT_PDU_NO, GTP_OPTIONAL, NULL},              /* PDU Numbers Optional 7.7.74 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },

/*      7.5.14 RAN Information Management Messages */
    {
        GTP_MSG_RAN_INFO_RELAY, {
            {GTP_EXT_RAN_TR_CONT, GTP_MANDATORY, NULL},        /* RAN Transparent Container Mandatory 7.7.43 */
            {GTP_EXT_RIM_RA, GTP_OPTIONAL, NULL},              /* RIM Routing Address Optional 7.7.57 */
            {GTP_EXT_RIM_ROUTING_ADDR_DISC, GTP_OPTIONAL, NULL}, /* 7.7.77 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
/*      7.5.15 UE Registration Query Request */
    {
        GTP_MSG_UE_REG_QUERY_REQ, {
            {GTP_EXT_IMSI, GTP_MANDATORY, NULL},
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
/*      7.5.16 UE Registration Query Response */
    {
        GTP_MSG_UE_REG_QUERY_RESP, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},
            {GTP_EXT_IMSI, GTP_MANDATORY, NULL},
            {GTP_EXT_SEL_PLMN_ID, GTP_CONDITIONAL, NULL}, /* Selected PLMN ID 7.7.64 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
/* 7.5A MBMS Messages
 * 7.5A.1 UE Specific MBMS Messages
 */
    {
        GTP_MBMS_NOTIFY_REQ, {
            {GTP_EXT_IMSI, GTP_MANDATORY, NULL},              /* IMSI Mandatory 7.7.2 */
            {GTP_EXT_TEID_CP, GTP_MANDATORY, NULL},           /* Tunnel Endpoint Identifier Control Plane Mandatory 7.7.14 */
            {GTP_EXT_NSAPI, GTP_MANDATORY, NULL},             /* NSAPI Mandatory 7.7.17 */
            {GTP_EXT_USER_ADDR, GTP_MANDATORY, NULL},         /* End User Address Mandatory 7.7.27 */
            {GTP_EXT_APN, GTP_MANDATORY, NULL},               /* Access Point Name Mandatory 7.7.30 */
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY, decode_gtp_ggsn_addr_for_control_plane},          /* GGSN Address for Control Plane Mandatory 7.7.32 */
            {GTP_EXT_MBMS_PROT_CONF_OPT, GTP_OPTIONAL, NULL}, /* MBMS Protocol Configuration Options Optional 7.7.58 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},           /* Private Extension Optional 7.7.46 */
            {0, 0, NULL}
        }
    },
    {
        GTP_MBMS_NOTIFY_RES, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},     /* Cause Mandatory 7.7.1 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MBMS_NOTIFY_REJ_REQ, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},     /* Cause Mandatory 7.7.1 */
            {GTP_EXT_TEID_CP, GTP_MANDATORY, NULL},   /* Tunnel Endpoint Identifier Control Plane Mandatory 7.7.14 */
            {GTP_EXT_NSAPI, GTP_MANDATORY, NULL},     /* NSAPI Mandatory 7.7.17 */
            {GTP_EXT_USER_ADDR, GTP_MANDATORY, NULL}, /* End User Address Mandatory 7.7.27 */
            {GTP_EXT_APN, GTP_MANDATORY, NULL},       /* Access Point Name Mandatory 7.7.30 */
            {GTP_EXT_GSN_ADDR, GTP_OPTIONAL, decode_gtp_sgsn_addr_for_control_plane},          /* SGSN Address for Control Plane Optional 7.7.32 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MBMS_NOTIFY_REJ_RES, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},     /* Cause Mandatory 7.7.1 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_CREATE_MBMS_CNTXT_REQ, {
            {GTP_EXT_IMSI, GTP_CONDITIONAL, NULL},            /* IMSI Conditional 7.7.2 */
            {GTP_EXT_RAI, GTP_MANDATORY, NULL},               /* Routeing Area Identity (RAI) Mandatory 7.7.3 */
            {GTP_EXT_RECOVER, GTP_OPTIONAL, NULL},            /* Recovery Optional 7.7.11 */
            {GTP_EXT_SEL_MODE, GTP_CONDITIONAL, NULL},        /* Selection mode Conditional 7.7.12 */
            {GTP_EXT_TEID_CP, GTP_CONDITIONAL, NULL},         /* Tunnel Endpoint Identifier Control Plane Conditional 7.7.14 */
            {GTP_EXT_TRACE_REF, GTP_OPTIONAL, NULL},          /* Trace Reference Optional 7.7.24 */
            {GTP_EXT_TRACE_TYPE, GTP_OPTIONAL, NULL},         /* Trace Type Optional 7.7.25 */
            {GTP_EXT_USER_ADDR, GTP_MANDATORY, NULL},         /* End User Address Mandatory 7.7.27 */
            {GTP_EXT_APN, GTP_MANDATORY, NULL},               /* Access Point Name Mandatory 7.7.30 */
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY, decode_gtp_sgsn_addr_for_control_plane},          /* SGSN Address for signalling Mandatory GSN Address 7.7.32 */
            {GTP_EXT_MSISDN, GTP_CONDITIONAL, NULL},          /* MSISDN Conditional 7.7.33 */
            {GTP_EXT_TRIGGER_ID, GTP_OPTIONAL, NULL},         /* Trigger Id Optional 7.7.41 */
            {GTP_EXT_OMC_ID, GTP_OPTIONAL, NULL},             /* OMC Identity Optional 7.7.42 */
            {GTP_EXT_RAT_TYPE, GTP_OPTIONAL, NULL},           /* RAT Type Optional 7.7.50 */
            {GTP_EXT_USR_LOC_INF, GTP_OPTIONAL, NULL},        /* User Location Information Optional 7.7.51 */
            {GTP_EXT_MS_TIME_ZONE, GTP_OPTIONAL, NULL},       /* MS Time Zone Optional 7.7.52 */
            {GTP_EXT_IMEISV, GTP_OPTIONAL, NULL},             /* IMEI(SV) Optional 7.7.53 */
            {GTP_EXT_MBMS_PROT_CONF_OPT, GTP_OPTIONAL, NULL}, /* MBMS Protocol Configuration Options Optional 7.7.58 */
            {GTP_EXT_ADD_TRS_INF, GTP_OPTIONAL, NULL},        /* Additional Trace Info Optional 7.7.62 */
            {GTP_EXT_ENH_NSAPI, GTP_MANDATORY, NULL},         /* Enhanced NSAPI Mandatory 7.7.67 */
            {GTP_EXT_ADD_MBMS_TRS_INF, GTP_OPTIONAL, NULL},   /* Additional MBMS Trace Info Optional 7.7.68 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_CREATE_MBMS_CNTXT_RES, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},             /* Cause Mandatory 7.7.1 */
            {GTP_EXT_RECOVER, GTP_OPTIONAL, NULL},            /* Recovery Optional 7.7.11 */
            {GTP_EXT_TEID_CP, GTP_CONDITIONAL, NULL},         /* Tunnel Endpoint Identifier Control Plane Conditional 7.7.14 */
            {GTP_EXT_CHRG_ID, GTP_CONDITIONAL, NULL},         /* Charging ID Conditional 7.7.26 */
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL, NULL},        /* GGSN Address for Control Plane Conditional GSN Address 7.7.32 */
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL, NULL},        /* Alternative GGSN Address for Control Plane Conditional GSN Address 7.7.32 */
            {GTP_EXT_CHRG_ADDR, GTP_OPTIONAL, NULL},          /* Charging Gateway Address Optional 7.7.44 */
            {GTP_EXT_CHRG_ADDR, GTP_OPTIONAL, NULL},          /* Alternative Charging Gateway Address Optional 7.7.44 */
            {GTP_EXT_MBMS_PROT_CONF_OPT, GTP_OPTIONAL, NULL}, /* MBMS Protocol Configuration Options Optional 7.7.58 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_UPD_MBMS_CNTXT_REQ, {
            {GTP_EXT_IMSI, GTP_CONDITIONAL, NULL},          /* IMSI Conditional 7.7.2 */
            {GTP_EXT_RAI, GTP_MANDATORY, NULL},             /* Routeing Area Identity (RAI) Mandatory 7.7.3 */
            {GTP_EXT_RECOVER, GTP_OPTIONAL, NULL},          /* Recovery Optional 7.7.11 */
            {GTP_EXT_TEID_CP, GTP_CONDITIONAL, NULL},       /* Tunnel Endpoint Identifier Control Plane Conditional 7.7.14 */
            {GTP_EXT_TRACE_REF, GTP_OPTIONAL, NULL},        /* Trace Reference Optional 7.7.24 */
            {GTP_EXT_TRACE_TYPE, GTP_OPTIONAL, NULL},       /* Trace Type Optional 7.7.25 */
            {GTP_EXT_GSN_ADDR, GTP_MANDATORY, decode_gtp_sgsn_addr_for_control_plane},        /* SGSN Address for Control Plane Mandatory GSN Address 7.7.32 */
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL, NULL},      /* Alternative SGSN Address for Control Plane Conditional GSN Address 7.7.32 */
            {GTP_EXT_TRIGGER_ID, GTP_OPTIONAL, NULL},       /* Trigger Id Optional 7.7.41 */
            {GTP_EXT_OMC_ID, GTP_OPTIONAL, NULL},           /* OMC Identity Optional 7.7.42 */
            {GTP_EXT_RAT_TYPE, GTP_OPTIONAL, NULL},         /* RAT Type Optional 7.7.50 */
            {GTP_EXT_USR_LOC_INF, GTP_OPTIONAL, NULL},      /* User Location Information Optional 7.7.51 */
            {GTP_EXT_MS_TIME_ZONE, GTP_OPTIONAL, NULL},     /* MS Time Zone Optional 7.7.52 */
            {GTP_EXT_ADD_TRS_INF, GTP_OPTIONAL, NULL},      /* Additional Trace Info Optional 7.7.62 */
            {GTP_EXT_ENH_NSAPI, GTP_MANDATORY, NULL},       /* Enhanced NSAPI Mandatory 7.7.67 */
            {GTP_EXT_ADD_MBMS_TRS_INF, GTP_OPTIONAL, NULL}, /* Additional MBMS Trace Info Optional 7.7.68 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_UPD_MBMS_CNTXT_RES, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},      /* Cause Mandatory 7.7.1 */
            {GTP_EXT_RECOVER, GTP_OPTIONAL, NULL},     /* Recovery Optional 7.7.11 */
            {GTP_EXT_TEID_CP, GTP_MANDATORY, NULL},    /* Tunnel Endpoint Identifier Control Plane Conditional 7.7.14 */
            {GTP_EXT_CHRG_ID, GTP_CONDITIONAL, NULL},  /* Charging ID Conditional 7.7.26 */
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL, NULL}, /* GGSN Address for Control Plane Conditional GSN Address 7.7.32 */
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL, NULL}, /* Alternative GGSN Address for Control Plane Conditional GSN Address 7.7.32 */
            {GTP_EXT_CHRG_ADDR, GTP_OPTIONAL, NULL},   /* Charging Gateway Address Optional 7.7.44 */
            {GTP_EXT_CHRG_ADDR, GTP_OPTIONAL, NULL},   /* Alternative Charging Gateway Address Optional 7.7.44 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},    /* Private Extension Optional 7.7.46 */
            {0, 0, NULL}
        }
    },
    {
        GTP_DEL_MBMS_CNTXT_REQ, {
            {GTP_EXT_IMSI, GTP_CONDITIONAL, NULL},            /* IMSI Conditional 7.7.2 */
            {GTP_EXT_TEID_CP, GTP_MANDATORY, NULL},           /* Tunnel Endpoint Identifier Control Plane Conditional 7.7.14 */
            {GTP_EXT_USER_ADDR, GTP_CONDITIONAL, NULL},       /* End User Address Conditional 7.7.27 */
            {GTP_EXT_APN, GTP_CONDITIONAL, NULL},             /* Access Point Name Conditional 7.7.30 */
            {GTP_EXT_MBMS_PROT_CONF_OPT, GTP_OPTIONAL, NULL}, /* MBMS Protocol Configuration Options Optional 7.7.58 */
            {GTP_EXT_ENH_NSAPI, GTP_MANDATORY, NULL},         /* Enhanced NSAPI Conditional 7.7.67 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},           /* Private Extension Optional 7.7.46 */
            {0, 0, NULL}
        }
    },
    {
        GTP_DEL_MBMS_CNTXT_RES, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},             /* Cause Mandatory 7.7.1 */
            {GTP_EXT_MBMS_PROT_CONF_OPT, GTP_OPTIONAL, NULL}, /* MBMS Protocol Configuration Options Optional 7.7.58 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},
            {0, 0, NULL}
        }
    },
    {
        GTP_MBMS_REG_REQ, {
            {GTP_EXT_TEID_CP, GTP_CONDITIONAL, NULL},           /* Tunnel Endpoint Identifier Control Plane Conditional 7.7.14 */
            {GTP_EXT_USER_ADDR, GTP_MANDATORY, NULL}, /* End User Address Mandatory 7.7.27 */
            {GTP_EXT_APN, GTP_MANDATORY, NULL},       /* Access Point Name Mandatory 7.7.30 */
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL, decode_gtp_sgsn_addr_for_control_plane},        /* SGSN Address for Control Plane GSN Address 7.7.32 */
            {GTP_EXT_GSN_ADDR, GTP_OPTIONAL, NULL},      /* Alternative SGSN Address for Control Plane GSN Address 7.7.32 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},   /* Private Extension Optional 7.7.46 */
            {0, 0, NULL}
        }
    },
    {
        GTP_MBMS_REG_RES, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},     /* Cause Mandatory 7.7.1 */
            {GTP_EXT_TEID_CP, GTP_CONDITIONAL, NULL},           /* Tunnel Endpoint Identifier Control Plane Conditional 7.7.14 */
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL, NULL}, /* GGSN Address for Control Plane Conditional GSN Address 7.7.32 */
            {GTP_EXT_TMGI, GTP_CONDITIONAL, NULL},      /* Temporary Mobile Group Identity (TMGI) Conditional 7.7.56 */
            {GTP_EXT_REQ_MBMS_BEARER_CAP, GTP_CONDITIONAL, NULL}, /* 7.7.76 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},   /* Private Extension Optional 7.7.46 */
            {0, 0, NULL}
        }
    },
    {
        GTP_MBMS_DE_REG_REQ, {
            {GTP_EXT_USER_ADDR, GTP_MANDATORY, NULL}, /* End User Address Mandatory 7.7.27 */
            {GTP_EXT_APN, GTP_MANDATORY, NULL},       /* Access Point Name Mandatory 7.7.30 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},   /* Private Extension Optional 7.7.46 */
            {0, 0, NULL}
        }
    },
    {
        GTP_MBMS_DE_REG_RES, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},     /* Cause Mandatory 7.7.1 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},   /* Private Extension Optional 7.7.46 */
            {0, 0, NULL}
        }
    },
    {
        GTP_MBMS_SES_START_REQ, {
            {GTP_EXT_RECOVER, GTP_OPTIONAL, NULL},               /* Recovery Optional 7.7.11 */
            {GTP_EXT_TEID_CP, GTP_CONDITIONAL, NULL},            /* Tunnel Endpoint Identifier Control Plane Conditional 7.7.14 */
            {GTP_EXT_USER_ADDR, GTP_MANDATORY, NULL},            /* End User Address Mandatory 7.7.27 */
            {GTP_EXT_APN, GTP_MANDATORY, NULL},                  /* Access Point Name Mandatory 7.7.30 */
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL, NULL},           /* GGSN Address for Control Plane Conditional GSN Address 7.7.32 */
            {GTP_EXT_GSN_ADDR, GTP_OPTIONAL, NULL},              /* Alternative GGSN Address for Control Plane GSN Address 7.7.32 */
            {GTP_EXT_QOS_UMTS, GTP_MANDATORY, NULL},             /* Quality of Service Profile Mandatory 7.7.34 */
            {GTP_EXT_COMMON_FLGS, GTP_OPTIONAL, NULL},           /* Common Flags Mandatory 7.7.48 */
            {GTP_EXT_TMGI, GTP_MANDATORY, NULL},                 /* Temporary Mobile Group Identity (TMGI) Mandatory 7.7.56 */
            {GTP_EXT_MBMS_SA, GTP_MANDATORY, NULL},              /* MBMS Service Area Mandatory 7.7.60 */
            {GTP_EXT_MBMS_SES_ID, GTP_OPTIONAL, NULL},           /* MBMS Session Identifier Optional 7.7.65 */
            {GTP_EXT_MBMS_2G_3G_IND, GTP_MANDATORY, NULL},       /* MBMS 2G/3G Indicator Mandatory 7.7.66 */
            {GTP_EXT_MBMS_SES_DUR, GTP_MANDATORY, NULL},         /* MBMS Session Duration Mandatory 7.7.59 */ /* V16.0.0 has it here. */
            {GTP_EXT_MBMS_SES_ID_REP_NO, GTP_OPTIONAL, NULL},    /* MBMS Session Identity Repetition Number Optional 7.7.69 */
            {GTP_EXT_MBMS_TIME_TO_DATA_TR, GTP_MANDATORY, NULL}, /* MBMS Time To Data Transfer Mandatory 7.7.70 */
            {GTP_EXT_MBMS_FLOW_ID, GTP_OPTIONAL, NULL}, /* 7.7.84 */
            {GTP_EXT_MBMS_IP_MCAST_DIST, GTP_OPTIONAL, NULL}, /* 7.7.85 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},              /* Private Extension Optional 7.7.46 */
            {0, 0, NULL}
        }
    },
    {
        GTP_MBMS_SES_START_RES, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},      /* Cause Mandatory 7.7.1 */
            {GTP_EXT_RECOVER, GTP_OPTIONAL, NULL},     /* Recovery Optional 7.7.11 */
            {GTP_EXT_TEID, GTP_CONDITIONAL, NULL},     /* Tunnel Endpoint Identifier Data I Conditional 7.7.13 */
            {GTP_EXT_TEID_CP, GTP_CONDITIONAL, NULL},  /* Tunnel Endpoint Identifier Control Plane Conditional 7.7.14 */
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL, NULL}, /* SGSN Address for Control Plane Conditional GSN Address 7.7.32 */
            {GTP_EXT_GSN_ADDR, GTP_CONDITIONAL, NULL}, /* SGSN Address for user traffic Conditional GSN Address 7.7.32 */
            {GTP_EXT_GSN_ADDR, GTP_OPTIONAL, NULL}, /* Alternative SGSN Address for user traffic GSN Address 7.7.32 */
            {GTP_EXT_MBMS_DIST_ACK, GTP_OPTIONAL, NULL}, /* 7.7.86 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},    /* Private Extension Optional 7.7.46 */
            {0, 0, NULL}
        }
    },
    {
        GTP_MBMS_SES_STOP_REQ, {
            {GTP_EXT_USER_ADDR, GTP_MANDATORY, NULL}, /* End User Address Mandatory 7.7.27 */
            {GTP_EXT_APN, GTP_MANDATORY, NULL},       /* Access Point Name Mandatory 7.7.30 */
            {GTP_EXT_MBMS_FLOW_ID, GTP_OPTIONAL, NULL}, /* 7.7.84 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},   /* Private Extension Optional 7.7.46 */
            {0, 0, NULL}
        }
    },
    {
        GTP_MBMS_SES_STOP_RES, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},     /* Cause Mandatory 7.7.1 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},   /* Private Extension Optional 7.7.46 */
            {0, 0, NULL}
        }
    },
    {
        GTP_MBMS_SES_UPD_REQ, {
            {GTP_EXT_TEID_CP, GTP_OPTIONAL, NULL},  /* Tunnel Endpoint Identifier Control Plane 7.7.14 */
            {GTP_EXT_USER_ADDR, GTP_MANDATORY, NULL}, /* End User Address Mandatory 7.7.27 */
            {GTP_EXT_APN, GTP_MANDATORY, NULL},       /* Access Point Name Mandatory 7.7.30 */
            {GTP_EXT_GSN_ADDR, GTP_OPTIONAL, NULL},           /* GGSN Address for Control Plane GSN Address 7.7.32 */
            {GTP_EXT_TMGI, GTP_MANDATORY, NULL},                 /* Temporary Mobile Group Identity (TMGI) Mandatory 7.7.56 */
            {GTP_EXT_MBMS_SES_DUR, GTP_MANDATORY, NULL},         /* MBMS Session Duration Mandatory 7.7.59 */ /* V16.0.0 has it here. */
            {GTP_EXT_MBMS_SA, GTP_MANDATORY, NULL},              /* MBMS Service Area Mandatory 7.7.60 */
            {GTP_EXT_MBMS_SES_ID, GTP_OPTIONAL, NULL},           /* MBMS Session Identifier Optional 7.7.65 */
            {GTP_EXT_MBMS_SES_ID_REP_NO, GTP_OPTIONAL, NULL},    /* MBMS Session Identity Repetition Number Optional 7.7.69 */
            {GTP_EXT_MBMS_FLOW_ID, GTP_OPTIONAL, NULL}, /* 7.7.84 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},   /* Private Extension Optional 7.7.46 */
            {0, 0, NULL}
        }
    },
    {
        GTP_MBMS_SES_UPD_RES, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},     /* Cause Mandatory 7.7.1 */
            {GTP_EXT_TEID, GTP_OPTIONAL, NULL},     /* Tunnel Endpoint Identifier Data I 7.7.13 */
            {GTP_EXT_TEID_CP, GTP_OPTIONAL, NULL},  /* Tunnel Endpoint Identifier Control Plane 7.7.14 */
            {GTP_EXT_GSN_ADDR, GTP_OPTIONAL, NULL}, /* SGSN Address for Data I GSN Address 7.7.32 */
            {GTP_EXT_GSN_ADDR, GTP_OPTIONAL, NULL}, /* SGSN Address for Control Plane GSN Address 7.7.32 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},   /* Private Extension Optional 7.7.46 */
            {0, 0, NULL}
        }
    },
    {
        GTP_MS_INFO_CNG_NOT_REQ, {
            {GTP_EXT_IMSI, GTP_CONDITIONAL, NULL}, /* IMSI Conditional 7.7.2 */
            {GTP_EXT_NSAPI, GTP_OPTIONAL, NULL}, /* Linked NSAPI Optional 7.7.17 */
            {GTP_EXT_RAT_TYPE, GTP_MANDATORY, NULL}, /* RAT Type 7.7.50 */
            {GTP_EXT_USR_LOC_INF, GTP_CONDITIONAL, NULL},/* User Location Information 7.7.51 */
            {GTP_EXT_IMEISV, GTP_CONDITIONAL, NULL}, /* IMEI(SV) 7.7.53 */
            {GTP_EXT_EXTENDED_COMMON_FLGS, GTP_OPTIONAL, NULL}, /* 7.7.93 */
            {GTP_EXT_UCI, GTP_OPTIONAL, NULL}, /* 7.7.94 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},   /* Private Extension Optional 7.7.46 */
            {0, 0, NULL}
        }
    },
    {
        GTP_MS_INFO_CNG_NOT_RES, {
            {GTP_EXT_CAUSE, GTP_MANDATORY, NULL},  /* Cause Mandatory 7.7.1 */
            {GTP_EXT_IMSI, GTP_CONDITIONAL, NULL}, /* IMSI Conditional 7.7.2 */
            {GTP_EXT_NSAPI, GTP_OPTIONAL, NULL}, /* Linked NSAPI Optional 7.7.17 */
            {GTP_EXT_IMEISV, GTP_CONDITIONAL, NULL}, /* IMEI(SV) 7.7.53 */
            {GTP_EXT_MS_INF_CHG_REP_ACT, GTP_OPTIONAL, NULL}, /* 7.7.80 */
            {GTP_EXT_CSG_INF_REP_ACT, GTP_OPTIONAL, NULL}, /* 7.7.95 */
            {GTP_EXT_PRIV_EXT, GTP_OPTIONAL, NULL},   /* Private Extension Optional 7.7.46 */
            {0, 0, NULL}
        }
    },
    {
        0, {
            {0, 0, NULL}
        }
    }
};

/* Data structure attached to a  conversation,
        to keep track of request/response-pairs
 */
typedef struct gtp_conv_info_t {
    struct gtp_conv_info_t *next;
    GHashTable             *unmatched;
    GHashTable             *matched;
} gtp_conv_info_t;

static gtp_conv_info_t *gtp_info_items = NULL;

static guint
gtp_sn_hash(gconstpointer k)
{
    const gtp_msg_hash_t *key = (const gtp_msg_hash_t *)k;

    return key->seq_nr;
}

static gint
gtp_sn_equal_matched(gconstpointer k1, gconstpointer k2)
{
    const gtp_msg_hash_t *key1 = (const gtp_msg_hash_t *)k1;
    const gtp_msg_hash_t *key2 = (const gtp_msg_hash_t *)k2;
    double diff;
    nstime_t delta;

    if ( key1->req_frame && key2->req_frame && (key1->req_frame != key2->req_frame) ) {
        return 0;
    }

    if ( key1->rep_frame && key2->rep_frame && (key1->rep_frame != key2->rep_frame) ) {
        return 0;
    }

    if (pref_pair_matching_max_interval_ms) {
        nstime_delta(&delta, &key1->req_time, &key2->req_time);
        diff = fabs(nstime_to_msec(&delta));

        return key1->seq_nr == key2->seq_nr && diff < pref_pair_matching_max_interval_ms;
    }

    return key1->seq_nr == key2->seq_nr;
}

static gint
gtp_sn_equal_unmatched(gconstpointer k1, gconstpointer k2)
{
    const gtp_msg_hash_t *key1 = (const gtp_msg_hash_t *)k1;
    const gtp_msg_hash_t *key2 = (const gtp_msg_hash_t *)k2;
    double diff;
    nstime_t delta;

    if (pref_pair_matching_max_interval_ms) {
        nstime_delta(&delta, &key1->req_time, &key2->req_time);
        diff = fabs(nstime_to_msec(&delta));

        return key1->seq_nr == key2->seq_nr && diff < pref_pair_matching_max_interval_ms;
    }

    return key1->seq_nr == key2->seq_nr;
}

static gtp_msg_hash_t *
gtp_match_response(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, gint seq_nr, guint msgtype, gtp_conv_info_t *gtp_info, guint8 last_cause)
{
    gtp_msg_hash_t   gcr, *gcrp = NULL;
    guint32 *session;

    gcr.seq_nr=seq_nr;
    gcr.req_time = pinfo->abs_ts;

    switch (msgtype) {
    case GTP_MSG_ECHO_REQ:
    case GTP_MSG_CREATE_PDP_REQ:
    case GTP_MSG_UPDATE_PDP_REQ:
    case GTP_MSG_DELETE_PDP_REQ:
    case GTP_MSG_FORW_RELOC_REQ:
    case GTP_MSG_DATA_TRANSF_REQ:
    case GTP_MSG_SGSN_CNTXT_REQ:
    case GTP_MS_INFO_CNG_NOT_REQ:
    case GTP_MSG_IDENT_REQ:
        gcr.is_request=TRUE;
        gcr.req_frame=pinfo->num;
        gcr.rep_frame=0;
        break;
    case GTP_MSG_ECHO_RESP:
    case GTP_MSG_CREATE_PDP_RESP:
    case GTP_MSG_UPDATE_PDP_RESP:
    case GTP_MSG_DELETE_PDP_RESP:
    case GTP_MSG_FORW_RELOC_RESP:
    case GTP_MSG_DATA_TRANSF_RESP:
    case GTP_MSG_SGSN_CNTXT_RESP:
    case GTP_MS_INFO_CNG_NOT_RES:
    case GTP_MSG_IDENT_RESP:
        gcr.is_request=FALSE;
        gcr.req_frame=0;
        gcr.rep_frame=pinfo->num;
        break;
    default:
        gcr.is_request=FALSE;
        gcr.req_frame=0;
        gcr.rep_frame=0;
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
        case GTP_MSG_FORW_RELOC_REQ:
        case GTP_MSG_DATA_TRANSF_REQ:
        case GTP_MSG_SGSN_CNTXT_REQ:
        case GTP_MS_INFO_CNG_NOT_REQ:
        case GTP_MSG_IDENT_REQ:
            gcr.seq_nr=seq_nr;

            gcrp=(gtp_msg_hash_t *)g_hash_table_lookup(gtp_info->unmatched, &gcr);
            if (gcrp) {
                g_hash_table_remove(gtp_info->unmatched, gcrp);
            }
            /* if we can't reuse the old one, grab a new chunk */
            if (!gcrp) {
                gcrp = wmem_new(wmem_file_scope(), gtp_msg_hash_t);
            }
            gcrp->seq_nr=seq_nr;
            gcrp->req_frame = pinfo->num;
            gcrp->req_time = pinfo->abs_ts;
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
        case GTP_MSG_FORW_RELOC_RESP:
        case GTP_MSG_DATA_TRANSF_RESP:
        case GTP_MSG_SGSN_CNTXT_RESP:
        case GTP_MS_INFO_CNG_NOT_RES:
        case GTP_MSG_IDENT_RESP:
            gcr.seq_nr=seq_nr;
            gcrp=(gtp_msg_hash_t *)g_hash_table_lookup(gtp_info->unmatched, &gcr);

            if (gcrp) {
                if (!gcrp->rep_frame) {
                    g_hash_table_remove(gtp_info->unmatched, gcrp);
                    gcrp->rep_frame=pinfo->num;
                    gcrp->is_request=FALSE;
                    g_hash_table_insert(gtp_info->matched, gcrp, gcrp);
                }
            }
            break;
        default:
            break;
        }
    }

    /* we have found a match */
    if (gcrp) {
        proto_item *it;


        if (gcrp->is_request) {
            it = proto_tree_add_uint(tree, hf_gtp_response_in, tvb, 0, 0, gcrp->rep_frame);
            proto_item_set_generated(it);
        } else {
            nstime_t ns;

            it = proto_tree_add_uint(tree, hf_gtp_response_to, tvb, 0, 0, gcrp->req_frame);
            proto_item_set_generated(it);
            nstime_delta(&ns, &pinfo->abs_ts, &gcrp->req_time);
            it = proto_tree_add_time(tree, hf_gtp_time, tvb, 0, 0, &ns);
            proto_item_set_generated(it);
            if (g_gtp_session) {
                if (!PINFO_FD_VISITED(pinfo) && gtp_version == 1) {
                    /* GTP session */
                    /* If it does not have any session assigned yet */
                    session = (guint32 *)g_hash_table_lookup(session_table, &pinfo->num);
                    if (!session) {
                        session = (guint32 *)g_hash_table_lookup(session_table, &gcrp->req_frame);
                        if (session != NULL) {
                            add_gtp_session(pinfo->num, *session);
                        }
                    }

                    if (!is_cause_accepted(last_cause, gtp_version)){
                        /* If the cause is not accepted then we have to remove all the session information about its corresponding request */
                        remove_frame_info(&gcrp->req_frame);
                    }
                }
            }
        }
    }
    return gcrp;
}


static int
check_field_presence_and_decoder(guint8 message, guint8 field, int *position, ie_decoder **alt_decoder)
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
                    *alt_decoder = mess_items[i].fields[*position].alt_decoder;
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
static int
decode_gtp_cause(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args)
{

    guint8 cause;

    cause = tvb_get_guint8(tvb, offset + 1);
    if (g_gtp_session) {
        args->last_cause = cause;
    }
    proto_tree_add_uint(tree, hf_gtp_cause, tvb, offset, 2, cause);

    return 2;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.2
 * UMTS:        29.060 v4.0, chapter 7.7.2
 */
static int
decode_gtp_imsi(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_)
{
    /* const gchar *imsi_str; */

    /* Octets 2 - 9 IMSI */
    /* imsi_str = */ dissect_e212_imsi(tvb, pinfo, tree,  offset+1, 8, FALSE);

    return 9;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.3
 * UMTS:        29.060 v4.0, chapter 7.7.3 Routeing Area Identity (RAI)
 */
static int
decode_gtp_rai(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    proto_tree *ext_tree_rai;

    ext_tree_rai = proto_tree_add_subtree(tree, tvb, offset, 1, ett_gtp_ies[GTP_EXT_RAI], NULL,
                            val_to_str_ext_const(GTP_EXT_RAI, &gtp_val_ext, "Unknown message"));

    dissect_e212_mcc_mnc(tvb, pinfo, ext_tree_rai, offset+1, E212_RAI, TRUE);
    proto_tree_add_item(ext_tree_rai, hf_gtp_lac, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree_rai, hf_gtp_rai_rac, tvb, offset + 6, 1, ENC_BIG_ENDIAN);

    return 7;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.4, page 39
 * UMTS:        29.060 v4.0, chapter 7.7.4 Temporary Logical Link Identity (TLLI)
 */
static int
decode_gtp_tlli(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint32 tlli;

    tlli = tvb_get_ntohl(tvb, offset + 1);
    proto_tree_add_uint(tree, hf_gtp_tlli, tvb, offset, 5, tlli);

    return 5;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.5, page 39
 * UMTS:        29.060 v4.0, chapter 7.7.5 Packet TMSI (P-TMSI)
 */
static int
decode_gtp_ptmsi(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    proto_item* ti;

    proto_tree_add_item(tree, hf_gtp_ptmsi, tvb, offset + 1, 4, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(tree, hf_3gpp_tmsi, tvb, offset+1, 4, ENC_BIG_ENDIAN);
    proto_item_set_hidden(ti);

    return 5;
}

/*
 * adjust - how many bytes before offset should be highlighted
 */
static int
decode_qos_gprs(tvbuff_t * tvb, int offset, proto_tree * tree, const gchar * qos_str, guint8 adjust)
{

    guint8      spare1, delay, reliability, peak, spare2, precedence, spare3, mean;
    proto_tree *ext_tree_qos;

    spare1      = tvb_get_guint8(tvb, offset)     & GTP_EXT_QOS_SPARE1_MASK;
    delay       = tvb_get_guint8(tvb, offset)     & GTP_EXT_QOS_DELAY_MASK;
    reliability = tvb_get_guint8(tvb, offset)     & GTP_EXT_QOS_RELIABILITY_MASK;
    peak        = tvb_get_guint8(tvb, offset + 1) & GTP_EXT_QOS_PEAK_MASK;
    spare2      = tvb_get_guint8(tvb, offset + 1) & GTP_EXT_QOS_SPARE2_MASK;
    precedence  = tvb_get_guint8(tvb, offset + 1) & GTP_EXT_QOS_PRECEDENCE_MASK;
    spare3      = tvb_get_guint8(tvb, offset + 2) & GTP_EXT_QOS_SPARE3_MASK;
    mean        = tvb_get_guint8(tvb, offset + 2) & GTP_EXT_QOS_MEAN_MASK;

    ext_tree_qos = proto_tree_add_subtree_format(tree, tvb, offset - adjust, 3 + adjust, ett_gtp_qos, NULL,
                             "%s: delay: %u, reliability: %u, peak: %u, precedence: %u, mean: %u",
                             qos_str, (delay >> 3) & 0x07, reliability, (peak >> 4) & 0x0F, precedence, mean);

    if (adjust != 0) {
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_spare1,      tvb, offset,     1, spare1);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_delay,       tvb, offset,     1, delay);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_reliability, tvb, offset,     1, reliability);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_peak,        tvb, offset + 1, 1, peak);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_spare2,      tvb, offset + 1, 1, spare2);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_precedence,  tvb, offset + 1, 1, precedence);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_spare3,      tvb, offset + 2, 1, spare3);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_mean,        tvb, offset + 2, 1, mean);
    }

    return 3;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.6, page 39
 *              4.08
 *              3.60
 * UMTS:        not present
 * TODO:        check if length is included: ETSI 4.08 vs 9.60
 */
static int
decode_gtp_qos_gprs(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    return (1 + decode_qos_gprs(tvb, offset + 1, tree, "Quality of Service", 1));

}

/* GPRS:        9.60 v7.6.0, chapter 7.9.7, page 39
 * UMTS:        29.060 v4.0, chapter 7.7.6 Reordering Required
 */
static int
decode_gtp_reorder(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
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
static int
decode_gtp_auth_tri(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    proto_tree *ext_tree_auth_tri;

    ext_tree_auth_tri = proto_tree_add_subtree(tree, tvb, offset, 29, ett_gtp_ies[GTP_EXT_AUTH_TRI], NULL,
                            val_to_str_ext_const(GTP_EXT_AUTH_TRI, &gtp_val_ext, "Unknown message"));

    proto_tree_add_item(ext_tree_auth_tri, hf_gtp_rand, tvb, offset + 1, 16, ENC_NA);
    proto_tree_add_item(ext_tree_auth_tri, hf_gtp_sres, tvb, offset + 17, 4, ENC_NA);
    proto_tree_add_item(ext_tree_auth_tri, hf_gtp_kc, tvb, offset + 21, 8, ENC_NA);

    return 1 + 16 + 4 + 8;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.9, page 40
 *              9.02 v7.7.0, page 1090
 * UMTS:        29.060 v4.0, chapter 7.7.8, page 48
 *              29.002 v4.2.1, chapter 17.5, page 268
 */
static int
decode_gtp_map_cause(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint8 map_cause;

    map_cause = tvb_get_guint8(tvb, offset + 1);
    proto_tree_add_uint(tree, hf_gtp_map_cause, tvb, offset, 2, map_cause);

    return 2;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.10, page 41
 * UMTS:        29.060 v4.0, chapter 7.7.9, page 48
 */
static int
decode_gtp_ptmsi_sig(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint32 ptmsi_sig;

    ptmsi_sig = tvb_get_ntoh24(tvb, offset + 1);
    proto_tree_add_uint(tree, hf_gtp_ptmsi_sig, tvb, offset, 4, ptmsi_sig);

    return 4;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.11, page 41
 * UMTS:        29.060 v4.0, chapter 7.7.10, page 49
 */
static int
decode_gtp_ms_valid(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint8 ms_valid;

    ms_valid = tvb_get_guint8(tvb, offset + 1) & 0x01;
    proto_tree_add_boolean(tree, hf_gtp_ms_valid, tvb, offset, 2, ms_valid);

    return 2;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.12, page 41
 * UMTS:        29.060 v4.0, chapter 7.7.11 Recovery
 */
static int
decode_gtp_recovery(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint8 recovery;

    recovery = tvb_get_guint8(tvb, offset + 1);
    proto_tree_add_uint(tree, hf_gtp_recovery, tvb, offset, 2, recovery);

    return 2;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.13, page 42
 * UMTS:        29.060 v4.0, chapter 7.7.12 Selection Mode
 */


static const gchar *
dissect_radius_selection_mode(proto_tree * tree, tvbuff_t * tvb, packet_info* pinfo _U_)
{
    guint8 sel_mode;

    /* Value in ASCII(UTF-8) */
    sel_mode = tvb_get_guint8(tvb, 0) - 0x30;
    proto_tree_add_uint(tree, hf_gtp_sel_mode, tvb, 0, 1, sel_mode);

    return val_to_str_const(sel_mode, sel_mode_type, "Unknown");
}

static int
decode_gtp_sel_mode(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    proto_tree *ext_tree;
    proto_item *te;
    guint8 sel_mode;

    sel_mode = tvb_get_guint8(tvb, offset + 1) & 0x03;

    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_gtp_ies[GTP_EXT_SEL_MODE], &te,
                            val_to_str_ext_const(GTP_EXT_SEL_MODE, &gtp_val_ext, "Unknown message"));
    proto_item_append_text(te, ": %s", val_to_str_const(sel_mode, sel_mode_type, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_sel_mode, tvb, offset+1, 1, ENC_BIG_ENDIAN);

    return 2;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.14, page 42
 * UMTS:        29.060 v4.0, chapter 7.7.13, page 50
 */
static int
decode_gtp_16(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args)
{

    guint16 ext_flow_label;
    guint32 teid_data, *teid;

    switch (gtp_version) {
    case 0:
        ext_flow_label = tvb_get_ntohs(tvb, offset + 1);
        proto_tree_add_uint(tree, hf_gtp_ext_flow_label, tvb, offset, 3, ext_flow_label);

        return 3;
    case 1:
        teid_data = tvb_get_ntohl(tvb, offset + 1);
        /* We save the teid_data so that we could assignate its corresponding session ID later */
        if (g_gtp_session && !PINFO_FD_VISITED(pinfo)) {
            args->last_teid = teid_data; /* We save it to track the error indication */
            if (!teid_exists(teid_data, args->teid_list)) {
                teid = wmem_new(wmem_packet_scope(), guint32);
                *teid = teid_data;
                wmem_list_prepend(args->teid_list, teid);
            }
        }
        proto_tree_add_uint(tree, hf_gtp_teid_data, tvb, offset+1, 4, teid_data);

        return 5;
    default:
        proto_tree_add_expert_format(tree, pinfo, &ei_gtp_field_not_support_in_version,
                    tvb, offset, 1, "Flow label/TEID Data I : GTP version not supported");

        return 3;
    }
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.15, page 42
 * UMTS:        29.060 v4.0, chapter 7.7.14, page 42
 */
static int
decode_gtp_17(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args)
{

    guint32 teid_cp;
    guint32 *teid;

    switch (gtp_version) {
    case 0:
        proto_tree_add_item(tree, hf_gtp_flow_sig, tvb, offset+1, 2, ENC_BIG_ENDIAN);
        return 3;
    case 1:
        proto_tree_add_item_ret_uint(tree, hf_gtp_teid_cp, tvb, offset+1 , 4, ENC_BIG_ENDIAN, &teid_cp);
        /* We save the teid_cp so that we could assignate its corresponding session ID later */
        if (g_gtp_session && !PINFO_FD_VISITED(pinfo)) {
            if (!teid_exists(teid_cp, args->teid_list)) {
                teid = wmem_new(wmem_packet_scope(), guint32);
                *teid = teid_cp;
                wmem_list_prepend(args->teid_list, teid);
            }
        }
        return 5;
    default:
        proto_tree_add_expert_format(tree, pinfo, &ei_gtp_field_not_support_in_version,
            tvb, offset, 1, "Flow label signalling/TEID control plane : GTP version not supported");
        return 3;
    }
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.16, page 42
 * UMTS:        29.060 v4.0, chapter 7.7.15, page 51
 */
static int
decode_gtp_18(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_)
{

    guint16     flow_ii;
    guint32     teid_ii;
    proto_tree *ext_tree_flow_ii;

    switch (gtp_version) {
    case 0:
        ext_tree_flow_ii = proto_tree_add_subtree(tree, tvb, offset, 4, ett_gtp_ies[GTP_EXT_FLOW_II], NULL,
                        val_to_str_ext_const(GTP_EXT_FLOW_II, &gtp_val_ext, "Unknown message"));

        proto_tree_add_item(ext_tree_flow_ii, hf_gtp_nsapi, tvb, offset + 1, 1, ENC_BIG_ENDIAN);

        flow_ii = tvb_get_ntohs(tvb, offset + 2);
        proto_tree_add_uint(ext_tree_flow_ii, hf_gtp_flow_ii, tvb, offset + 2, 2, flow_ii);

        return 4;
    case 1:
        ext_tree_flow_ii = proto_tree_add_subtree(tree, tvb, offset, 6, ett_gtp_flow_ii, NULL,
                val_to_str_ext_const(GTP_EXT_TEID_II, &gtpv1_val_ext, "Unknown message"));

        proto_tree_add_item(ext_tree_flow_ii, hf_gtp_nsapi, tvb, offset + 1, 1, ENC_BIG_ENDIAN);

        teid_ii = tvb_get_ntohl(tvb, offset + 2);
        proto_tree_add_uint(ext_tree_flow_ii, hf_gtp_teid_ii, tvb, offset + 2, 4, teid_ii);

        return 6;
    default:
        proto_tree_add_expert_format(tree, pinfo, &ei_gtp_field_not_support_in_version,
            tvb, offset, 1, "Flow data II/TEID Data II : GTP Version not supported");

        return 4;
    }
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.16A, page 43
 * UMTS:        29.060 v4.0, chapter 7.7.16, page 51
 * Check if all ms_reason types are included
 */
static int
decode_gtp_19(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_)
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
        proto_tree_add_expert_format(tree, pinfo, &ei_gtp_field_not_support_in_version,
            tvb, offset, 1, "Information Element Type = 19 : GTP Version not supported");
        break;
    }

    return 2;
}

/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.17, page 51
 */
static int
decode_gtp_nsapi(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint8      nsapi;
    proto_tree *ext_tree;
    proto_item *te;

    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 2, ett_gtp_ies[GTP_EXT_NSAPI], &te,
                            val_to_str_ext_const(GTP_EXT_NSAPI, &gtp_val_ext, "Unknown message"));

    nsapi = tvb_get_guint8(tvb, offset + 1) & 0x0F;
    proto_tree_add_item(ext_tree, hf_gtp_nsapi, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(te, ": %u",nsapi);

    return 2;
}

/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.18, page 52
 */
static int
decode_gtp_ranap_cause(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint8 ranap;

    ranap = tvb_get_guint8(tvb, offset + 1);

    if ((ranap > 0) && (ranap <= 64))
        proto_tree_add_uint_format(tree, hf_gtp_ranap_cause, tvb, offset, 2,
                                   ranap, "%s (Radio Network Layer Cause) : %s (%u)",
                                   val_to_str_ext_const(GTP_EXT_RANAP_CAUSE, &gtp_val_ext, "Unknown"),
                                   val_to_str_ext_const(ranap, &ranap_cause_type_ext, "Unknown RANAP Cause"), ranap);

    if ((ranap > 64) && (ranap <= 80))
        proto_tree_add_uint_format(tree, hf_gtp_ranap_cause, tvb, offset, 2,
                                   ranap, "%s (Transport Layer Cause) : %s (%u)",
                                   val_to_str_ext_const(GTP_EXT_RANAP_CAUSE, &gtp_val_ext, "Unknown"),
                                   val_to_str_ext_const(ranap, &ranap_cause_type_ext, "Unknown RANAP Cause"), ranap);

    if ((ranap > 80) && (ranap <= 96))
        proto_tree_add_uint_format(tree, hf_gtp_ranap_cause, tvb, offset, 2,
                                   ranap, "%s (NAS Cause) : %s (%u)",
                                   val_to_str_ext_const(GTP_EXT_RANAP_CAUSE, &gtp_val_ext, "Unknown"),
                                   val_to_str_ext_const(ranap, &ranap_cause_type_ext, "Unknown RANAP Cause"), ranap);

    if ((ranap > 96) && (ranap <= 112))
        proto_tree_add_uint_format(tree, hf_gtp_ranap_cause, tvb, offset, 2, ranap,
                                   "%s (Protocol Cause) : %s (%u)",
                                   val_to_str_ext_const(GTP_EXT_RANAP_CAUSE, &gtp_val_ext, "Unknown"),
                                   val_to_str_ext_const(ranap, &ranap_cause_type_ext, "Unknown RANAP Cause"), ranap);

    if ((ranap > 112) && (ranap <= 128))
        proto_tree_add_uint_format(tree, hf_gtp_ranap_cause, tvb, offset, 2, ranap,
                                   "%s (Miscellaneous Cause) : %s (%u)",
                                   val_to_str_ext_const(GTP_EXT_RANAP_CAUSE, &gtp_val_ext, "Unknown"),
                                   val_to_str_ext_const(ranap, &ranap_cause_type_ext, "Unknown RANAP Cause"), ranap);

    if ((ranap > 128) /* && (ranap <= 255) */ )
        proto_tree_add_uint_format(tree, hf_gtp_ranap_cause, tvb, offset, 2, ranap,
                                   "%s (Non-standard Cause) : %s (%u)",
                                   val_to_str_ext_const(GTP_EXT_RANAP_CAUSE, &gtp_val_ext, "Unknown"),
                                   val_to_str_ext_const(ranap, &ranap_cause_type_ext, "Unknown RANAP Cause"), ranap);

    return 2;
}

/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.19, page 52
 */
static int
decode_gtp_rab_cntxt(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    proto_tree *ext_tree_rab_cntxt;

    ext_tree_rab_cntxt = proto_tree_add_subtree(tree, tvb, offset, 10, ett_gtp_ies[GTP_EXT_RAB_CNTXT], NULL,
                        val_to_str_ext_const(GTP_EXT_RAB_CNTXT, &gtp_val_ext, "Unknown message"));

    proto_tree_add_item(ext_tree_rab_cntxt, hf_gtp_nsapi,       tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree_rab_cntxt, hf_gtp_rab_gtpu_dn, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree_rab_cntxt, hf_gtp_rab_gtpu_up, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree_rab_cntxt, hf_gtp_rab_pdu_dn,  tvb, offset + 6, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree_rab_cntxt, hf_gtp_rab_pdu_up,  tvb, offset + 8, 2, ENC_BIG_ENDIAN);

    return 10;
}


/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.20, page 53
 */
static int
decode_gtp_rp_sms(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint8 rp_sms;

    rp_sms = tvb_get_guint8(tvb, offset + 1) & 0x07;
    proto_tree_add_uint(tree, hf_gtp_rp_sms, tvb, offset, 2, rp_sms);

    return 2;
}

/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.21, page 53
 */
static int
decode_gtp_rp(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    proto_tree *ext_tree_rp;
    proto_item *te;
    guint8      nsapi, rp, spare;

    nsapi = tvb_get_guint8(tvb, offset + 1) & 0xF0;
    spare = tvb_get_guint8(tvb, offset + 1) & 0x08;
    rp = tvb_get_guint8(tvb, offset + 1) & 0x07;

    te = proto_tree_add_uint_format(tree, hf_gtp_rp, tvb, offset, 2, rp, "Radio Priority for NSAPI(%u) : %u", nsapi, rp);
    ext_tree_rp = proto_item_add_subtree(te, ett_gtp_rp);

    proto_tree_add_uint(ext_tree_rp, hf_gtp_rp_nsapi, tvb, offset + 1, 1, nsapi);
    proto_tree_add_uint(ext_tree_rp, hf_gtp_rp_spare, tvb, offset + 1, 1, spare);
    proto_tree_add_uint(ext_tree_rp, hf_gtp_rp,       tvb, offset + 1, 1, rp);

    return 2;
}

/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.22, page 53
 */
static int
decode_gtp_pkt_flow_id(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    proto_tree *ext_tree_pkt_flow_id;
    proto_item *te;
    guint8      nsapi, pkt_flow_id;

    nsapi = tvb_get_guint8(tvb, offset + 1) & 0x0F;
    pkt_flow_id = tvb_get_guint8(tvb, offset + 2);

    te = proto_tree_add_uint_format(tree, hf_gtp_pkt_flow_id, tvb, offset, 3, pkt_flow_id, "Packet Flow ID for NSAPI(%u) : %u", nsapi, pkt_flow_id);
    ext_tree_pkt_flow_id = proto_item_add_subtree(te, ett_gtp_pkt_flow_id);

    proto_tree_add_item(ext_tree_pkt_flow_id, hf_gtp_nsapi, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_uint_format(ext_tree_pkt_flow_id, hf_gtp_pkt_flow_id, tvb,
                               offset + 2, 1, pkt_flow_id, "%s : %u", val_to_str_ext_const(GTP_EXT_PKT_FLOW_ID, &gtp_val_ext, "Unknown message"), pkt_flow_id);

    return 3;
}

/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.23, page 53
 * TODO: Differenciate these uints?
 */
static int
decode_gtp_chrg_char(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     chrg_char;
    proto_item *te;
    proto_tree *ext_tree_chrg_char;

    chrg_char = tvb_get_ntohs(tvb, offset + 1);

    te = proto_tree_add_uint(tree, hf_gtp_chrg_char, tvb, offset, 3, chrg_char);
    /*"%s: %x", val_to_str_ext_const (GTP_EXT_CHRG_CHAR, &gtp_val_ext, "Unknown message"), chrg_char); */
    ext_tree_chrg_char = proto_item_add_subtree(te, ett_gtp_ies[GTP_EXT_CHRG_CHAR]);

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
static int
decode_gtp_trace_ref(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16 trace_ref;

    trace_ref = tvb_get_ntohs(tvb, offset + 1);

    proto_tree_add_uint(tree, hf_gtp_trace_ref, tvb, offset, 3, trace_ref);

    return 3;
}

/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.25, page
 */
static int
decode_gtp_trace_type(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16 trace_type;

    trace_type = tvb_get_ntohs(tvb, offset + 1);

    proto_tree_add_uint(tree, hf_gtp_trace_type, tvb, offset, 3, trace_type);

    return 3;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.16A
 * UMTS:        29.060 v4.0, chapter 7.7.25A, page
 */
static int
decode_gtp_ms_reason(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
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
static int
decode_gtp_ra_prio_lcs(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree_format(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_RA_PRIO_LCS], NULL,
                    "%s : ", val_to_str_ext_const(GTP_EXT_RA_PRIO_LCS, &gtp_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    proto_tree_add_item(ext_tree, hf_gtp_ra_prio_lcs, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 3 + length;

}

/* GPRS:        12.15 v7.6.0, chapter 7.3.3, page 45
 * UMTS:        33.015
 */
static int
decode_gtp_tr_comm(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint8 tr_command;

    tr_command = tvb_get_guint8(tvb, offset + 1);

    proto_tree_add_uint(tree, hf_gtp_tr_comm, tvb, offset, 2, tr_command);

    return 2;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.17, page 43
 * UMTS:        29.060 v4.0, chapter 7.7.26, page 55
 */
static int
decode_gtp_chrg_id(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint32 chrg_id;

    chrg_id = tvb_get_ntohl(tvb, offset + 1);
    proto_tree_add_uint(tree, hf_gtp_chrg_id, tvb, offset, 5, chrg_id);

    return 5;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.18, page 43
 * UMTS:        29.060 v4.0, chapter 7.7.27, page 55
 */
static int
decode_gtp_user_addr(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16            length;
    guint8             pdp_typ, pdp_org;
    proto_tree        *ext_tree_user;
    proto_item        *te;


    length = tvb_get_ntohs(tvb, offset + 1);
    pdp_org = tvb_get_guint8(tvb, offset + 3) & 0x0F;
    pdp_typ = tvb_get_guint8(tvb, offset + 4);

    ext_tree_user = proto_tree_add_subtree_format(tree, tvb, offset, 3 + length,
                             ett_gtp_ies[GTP_EXT_USER_ADDR], &te, "%s (%s/%s)",
                             val_to_str_ext_const(GTP_EXT_USER_ADDR, &gtp_val_ext, "Unknown message"),
                             val_to_str_const(pdp_org, pdp_org_type, "Unknown PDP Organization"),
                             val_to_str_const(pdp_typ, pdp_type, "Unknown PDP Type"));

    proto_tree_add_item(ext_tree_user, hf_gtp_length, tvb, offset + 1, 2, ENC_BIG_ENDIAN);
    proto_tree_add_uint(ext_tree_user, hf_gtp_user_addr_pdp_org,  tvb, offset + 3, 1, pdp_org);
    proto_tree_add_uint(ext_tree_user, hf_gtp_user_addr_pdp_type, tvb, offset + 4, 1, pdp_typ);

    if (length == 2) {
        if ((pdp_org == 0) && (pdp_typ == 1))
            proto_item_append_text(te, " (Point to Point Protocol)");
        else if (pdp_typ == 2)
            proto_item_append_text(te, " (Octet Stream Protocol)");
    } else if (length > 2) {
        switch (pdp_typ) {
        case 0x21:
            proto_tree_add_item(ext_tree_user, hf_gtp_user_ipv4, tvb, offset + 5, 4, ENC_BIG_ENDIAN);
            proto_item_append_text(te, " : %s", tvb_ip_to_str(pinfo->pool, tvb, offset + 5));
            break;
        case 0x57:
            proto_tree_add_item(ext_tree_user, hf_gtp_user_ipv6, tvb, offset + 5, 16, ENC_NA);
            proto_item_append_text(te, " : %s", tvb_ip6_to_str(pinfo->pool, tvb, offset + 5));
            break;
        case 0x8d:
            if (length == 6) {
                ws_in6_addr ipv6;
                memset(&ipv6, 0, sizeof(ws_in6_addr));
                proto_tree_add_item(ext_tree_user, hf_gtp_user_ipv4, tvb, offset + 5, 4, ENC_BIG_ENDIAN);
                proto_tree_add_ipv6_format_value(ext_tree_user, hf_gtp_user_ipv6, tvb, offset + 9, 0, &ipv6, "dynamic");
                proto_item_append_text(te, " : %s / dynamic", tvb_ip_to_str(pinfo->pool, tvb, offset + 5));
            } else if (length == 18) {
                proto_tree_add_ipv4_format_value(ext_tree_user, hf_gtp_user_ipv6, tvb, offset + 5, 0, 0, "dynamic");
                proto_tree_add_item(ext_tree_user, hf_gtp_user_ipv6, tvb, offset + 5, 16, ENC_NA);
                proto_item_append_text(te, " : dynamic / %s", tvb_ip6_to_str(pinfo->pool, tvb, offset + 5));
            } else if (length == 22) {
                proto_tree_add_item(ext_tree_user, hf_gtp_user_ipv4, tvb, offset + 5, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(ext_tree_user, hf_gtp_user_ipv6, tvb, offset + 9, 16, ENC_NA);
                proto_item_append_text(te, " : %s / %s", tvb_ip_to_str(pinfo->pool, tvb, offset + 5),
                                       tvb_ip6_to_str(pinfo->pool, tvb, offset + 9));
            } else {
                proto_tree_add_expert_format(ext_tree_user, pinfo, &ei_gtp_ext_length_mal, tvb, offset + 3, length, "Wrong length indicated. Expected 6, 18 or 22, got %u", length);
            }
            break;
        }
    } else
        proto_item_append_text(te, " : empty PDP Address");

    return 3 + length;
}

static int
decode_triplet(tvbuff_t * tvb, int offset, proto_tree * tree, guint16 count)
{

    proto_tree *ext_tree_trip;
    guint16     i;

    for (i = 0; i < count; i++) {
        ext_tree_trip = proto_tree_add_subtree_format(tree, tvb, offset + i * 28, 28, ett_gtp_trip, NULL, "Triplet no%x", i);

        proto_tree_add_item(ext_tree_trip, hf_gtp_rand, tvb, offset + i * 28, 16, ENC_NA);
        proto_tree_add_item(ext_tree_trip, hf_gtp_sres, tvb, offset + i * 28 + 16, 4, ENC_NA);
        proto_tree_add_item(ext_tree_trip, hf_gtp_kc, tvb, offset + i * 28 + 20, 8, ENC_NA);
    }

    return count * 28;
}

/* adjust - how many bytes before quintuplet should be highlighted
 */
static int
decode_quintuplet(tvbuff_t * tvb, int offset, proto_tree * tree, guint16 count)
{

    proto_tree *ext_tree_quint;
    proto_item *te_quint;
    guint16     q_offset, i;
    guint8      xres_len, auth_len;

    q_offset = 0;

    for (i = 0; i < count; i++) {

        ext_tree_quint = proto_tree_add_subtree_format(tree, tvb, offset, -1,
                                ett_gtp_quint, &te_quint, "Quintuplet #%x", i + 1);

        proto_tree_add_item(ext_tree_quint, hf_gtp_rand, tvb, offset + q_offset, 16, ENC_NA);
        q_offset = q_offset + 16;
        xres_len = tvb_get_guint8(tvb, offset + q_offset);
        proto_tree_add_item(ext_tree_quint, hf_gtp_xres_length, tvb, offset + q_offset, 1, ENC_BIG_ENDIAN);
        q_offset++;
        proto_tree_add_item(ext_tree_quint, hf_gtp_xres, tvb, offset + q_offset, xres_len, ENC_NA);
        q_offset = q_offset + xres_len;
        proto_tree_add_item(ext_tree_quint, hf_gtp_quintuplet_ciphering_key, tvb, offset + q_offset, 16, ENC_NA);
        q_offset = q_offset + 16;
        proto_tree_add_item(ext_tree_quint, hf_gtp_quintuplet_integrity_key, tvb, offset + q_offset, 16, ENC_NA);
        q_offset = q_offset + 16;
        auth_len = tvb_get_guint8(tvb, offset + q_offset);
        proto_tree_add_item(ext_tree_quint, hf_gtp_authentication_length, tvb, offset + q_offset, 1, ENC_BIG_ENDIAN);
        q_offset++;
        proto_tree_add_item(ext_tree_quint, hf_gtp_auth, tvb, offset + q_offset, auth_len, ENC_NA);

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
static int
decode_gtp_mm_cntxt(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length, con_len;
    guint8      count, sec_mode, len, iei;
    proto_tree *ext_tree_mm;
    proto_tree *tf_tree = NULL, *con_tree;

    ext_tree_mm = proto_tree_add_subtree(tree, tvb, offset, 1, ett_gtp_ies[GTP_EXT_MM_CNTXT], NULL,
                        val_to_str_ext_const(GTP_EXT_MM_CNTXT, &gtp_val_ext, "Unknown message"));

    /* Octet 2 - 3 */
    length = tvb_get_ntohs(tvb, offset + 1);
    if (length < 1)
        return 3;

    /* Octet 4 (cksn)*/

    /* Octet 5 */
    sec_mode = (tvb_get_guint8(tvb, offset + 4) >> 6) & 0x03;
    count = (tvb_get_guint8(tvb, offset + 4) >> 3) & 0x07;

    proto_tree_add_item(ext_tree_mm, hf_gtp_length, tvb, offset + 1, 2, ENC_BIG_ENDIAN);
    if (gtp_version == 0)
        sec_mode = 1;


    switch (sec_mode) {
    case 0:                     /* Used cipher value, UMTS keys and Quintuplets */
        proto_tree_add_item(ext_tree_mm, hf_gtp_cksn_ksi,         tvb, offset + 3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ext_tree_mm, hf_gtp_security_mode,    tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ext_tree_mm, hf_gtp_no_of_vectors,    tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ext_tree_mm, hf_gtp_cipher_algorithm, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ext_tree_mm, hf_gtp_ciphering_key_ck, tvb, offset + 5, 16, ENC_NA);
        proto_tree_add_item(ext_tree_mm, hf_gtp_integrity_key_ik, tvb, offset + 21, 16, ENC_NA);
        proto_tree_add_item(ext_tree_mm, hf_gtp_quintuplets_length, tvb, offset + 37, 2, ENC_BIG_ENDIAN);

        offset = offset + decode_quintuplet(tvb, offset + 39, ext_tree_mm, count) + 39;


        break;
    case 1:                     /* GSM key and triplets */
        proto_tree_add_item(ext_tree_mm, hf_gtp_cksn, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
        if (gtp_version != 0)
            proto_tree_add_item(ext_tree_mm, hf_gtp_security_mode, tvb, offset + 4, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(ext_tree_mm, hf_gtp_no_of_vectors,    tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ext_tree_mm, hf_gtp_cipher_algorithm, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ext_tree_mm, hf_gtp_ciphering_key_kc, tvb, offset + 5, 8, ENC_NA);

        offset = offset + decode_triplet(tvb, offset + 13, ext_tree_mm, count) + 13;

        break;
    case 2:                     /* UMTS key and quintuplets */
        proto_tree_add_item(ext_tree_mm, hf_gtp_ksi, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ext_tree_mm, hf_gtp_security_mode, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ext_tree_mm, hf_gtp_no_of_vectors, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ext_tree_mm, hf_gtp_ciphering_key_ck, tvb, offset + 5, 16, ENC_NA);
        proto_tree_add_item(ext_tree_mm, hf_gtp_integrity_key_ik, tvb, offset + 21, 16, ENC_NA);
       proto_tree_add_item(ext_tree_mm, hf_gtp_quintuplets_length, tvb, offset + 37, 2, ENC_BIG_ENDIAN);

        offset = offset + decode_quintuplet(tvb, offset + 39, ext_tree_mm, count) + 39;

        break;
    case 3:                     /* GSM key and quintuplets */
        proto_tree_add_item(ext_tree_mm, hf_gtp_cksn,             tvb, offset + 3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ext_tree_mm, hf_gtp_security_mode,    tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ext_tree_mm, hf_gtp_no_of_vectors,    tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ext_tree_mm, hf_gtp_cipher_algorithm, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ext_tree_mm, hf_gtp_ciphering_key_kc, tvb, offset + 5, 8, ENC_NA);
        proto_tree_add_item(ext_tree_mm, hf_gtp_quintuplets_length, tvb, offset + 13, 2, ENC_BIG_ENDIAN);

        offset = offset + decode_quintuplet(tvb, offset + 15, ext_tree_mm, count) + 15;

        break;
    default:
        break;
    }

/*
 * 3GPP TS 24.008 10.5.5.6 ( see packet-gsm_a.c )
 */
    tf_tree = proto_tree_add_subtree(ext_tree_mm, tvb, offset, 2, ett_gtp_drx, NULL, "DRX Parameter");
    de_gmm_drx_param(tvb, tf_tree, pinfo, offset, 2, NULL, 0);
    offset = offset + 2;

    len = tvb_get_guint8(tvb, offset);
    tf_tree = proto_tree_add_subtree(ext_tree_mm, tvb, offset, len + 1, ett_gtp_net_cap, NULL, "MS Network Capability");

    proto_tree_add_uint(tf_tree, hf_gtp_ms_network_cap_content_len, tvb, offset, 1, len);

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
    proto_tree_add_item(ext_tree_mm, hf_gtp_container_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    if (con_len > 0) {
        proto_item* ti;

        con_tree = proto_tree_add_subtree(ext_tree_mm, tvb, offset, con_len, ett_gtp_mm_cntxt, NULL, "Container");

        iei = tvb_get_guint8(tvb,offset);
        ti = proto_tree_add_uint(con_tree, hf_gtp_iei, tvb, offset, 1, iei);
        if (iei == 0x23) {
            proto_item_append_text(ti, " (Mobile identity)");
            offset++;
            len = tvb_get_guint8(tvb,offset);
            proto_tree_add_uint(con_tree, hf_gtp_iei_mobile_id_len, tvb, offset, 1, len);
            offset++;
            de_mid(tvb, con_tree, pinfo, offset, len, NULL, 0);
        } else {
            expert_add_info(pinfo, ti, &ei_gtp_iei);
        }
    }

    return 3 + length;
}

/* Function to extract the value of an hexadecimal octet. Only the lower
 * nybble will be non-zero in the output.
 * */
static guint8
hex2dec(guint8 x)
{
    /* XXX, ws_xton() */
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
static guint8
wrapped_tvb_get_guint8(tvbuff_t * tvb, int offset, int type)
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
int
decode_qos_umts(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, const gchar * qos_str, guint8 type)
{

    guint       length;
    guint8      al_ret_priority;
    guint8      delay, reliability, peak, precedence, mean, spare1, spare2, spare3;
    guint8      traf_class, del_order, del_err_sdu;
    guint8      max_sdu_size, max_ul, max_dl, max_ul_ext, max_dl_ext, max_ul_ext2 = 0, max_dl_ext2 = 0;
    guint8      res_ber, sdu_err_ratio;
    guint8      trans_delay, traf_handl_prio;
    guint8      guar_ul, guar_dl, guar_ul_ext, guar_dl_ext, guar_ul_ext2 = 0, guar_dl_ext2 = 0;
    guint8      src_stat_desc, sig_ind, spare4;
    proto_tree *ext_tree_qos;
    int         mss, mu, md, gu, gd;
    guint8      arp, qci;
    guint32     apn_ambr;
    guint64     br;

    /* Will keep if the input is UTF-8 encoded (as in RADIUS messages).
     * If 1, input is *not* UTF-8 encoded (i.e. each input octet corresponds
     * to one byte to be dissected).
     * If 2, input is UTF-8 encoded (i.e. each *couple* of input octets
     * corresponds to one byte to be dissected)
     * */
    guint8 utf8_type = 1;

    /* Will keep the release indicator as indicated in the RADIUS message */
    guint8 rel_ind = 0;

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
    case 0:
        /* For QoS inside GPRS-CDR messages from GGSN/P-GW */
        length = tvb_reported_length(tvb);
        ext_tree_qos = proto_tree_add_subtree(tree, tvb, offset, length, ett_gtp_qos, NULL, qos_str);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_umts_length, tvb, offset, 1, length);
        /* QoS inside GPRS-CDR has no length octet, so no extra offset needed */
        retval = length;
        break;
    case 1:
        length = tvb_get_guint8(tvb, offset);
        ext_tree_qos = proto_tree_add_subtree(tree, tvb, offset, length + 1, ett_gtp_qos, NULL, qos_str);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_umts_length, tvb, offset, 1, length);
        offset++;
        retval = length + 1;
        break;
    case 2:
        length = tvb_get_ntohs(tvb, offset + 1);
        ext_tree_qos = proto_tree_add_subtree(tree, tvb, offset, length + 3, ett_gtp_qos, NULL, qos_str);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_umts_length, tvb, offset + 1, 2, length);
        offset += 3;            /* +1 because of first 0x86 byte for UMTS QoS */
        retval = length + 3;
        break;
    case 3:
        /* For QoS inside RADIUS Client messages from GGSN/P-GW */
        utf8_type = 2;

        /* The field in the RADIUS message is the length of the tvb we were given */
        length = tvb_reported_length(tvb);
        ext_tree_qos = proto_tree_add_subtree(tree, tvb, offset, length, ett_gtp_qos, NULL, qos_str);

        rel_ind = wrapped_tvb_get_guint8(tvb, offset, 2);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_version, tvb, offset, 2, rel_ind);

        /* Hyphen handling */
        hyphen = tvb_get_guint8(tvb, offset + 2);
        if (hyphen == ((guint8) '-')) {
            /* Hyphen is present, put in protocol tree */
            proto_tree_add_item(ext_tree_qos, hf_gtp_hyphen_separator, tvb, offset + 2, 1, ENC_NA);
            offset++;           /* "Get rid" of hyphen */
        }

        /* Now, we modify offset here and in order to use type later
         * effectively.*/
        offset++;

        length -= offset;
        length /= 2;

        /* Fake the length of the IE including the IE id and length octets
         * we are actually using it to determine precense of Octet n as counted in
         * TS 24.008
         */
        length = retval = length + 2;    /* Actually, will be ignored. */
        break;
    default:
        /* XXX - what should we do with the length here? */
        length = 0;
        retval = 0;
        ext_tree_qos = NULL;
        break;
    }

    if ((type == 3) && (rel_ind >= 8)) {
        /* Release 8 or higher P-GW QoS profile */
        static int * const arp_flags[] = {
            &hf_gtp_qos_arp_pci,
            &hf_gtp_qos_arp_pl,
            &hf_gtp_qos_arp_pvi,
            NULL
        };

        offset++;
        arp = wrapped_tvb_get_guint8(tvb, offset, 2);
        proto_tree_add_bitmask_value_with_flags(ext_tree_qos, tvb, offset, hf_gtp_qos_arp,
                    ett_gtp_qos_arp, arp_flags, arp, BMT_NO_APPEND);
        offset += 2;

        qci = wrapped_tvb_get_guint8(tvb, offset, 2);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_qci, tvb, offset, 2, qci);
        offset += 2;
        if (qci <= 4) {
            /* GBR QCI */
            br = ((guint64)wrapped_tvb_get_guint8(tvb, offset  , 2) << 32) |
                 ((guint64)wrapped_tvb_get_guint8(tvb, offset+2, 2) << 24) |
                 ((guint64)wrapped_tvb_get_guint8(tvb, offset+4, 2) << 16) |
                 ((guint64)wrapped_tvb_get_guint8(tvb, offset+6, 2) <<  8) |
                  (guint64)wrapped_tvb_get_guint8(tvb, offset+8, 2);
            proto_tree_add_uint64(ext_tree_qos, hf_gtp_qos_ul_mbr, tvb, offset, 10, br);
            offset += 10;
            br = ((guint64)wrapped_tvb_get_guint8(tvb, offset  , 2) << 32) |
                 ((guint64)wrapped_tvb_get_guint8(tvb, offset+2, 2) << 24) |
                 ((guint64)wrapped_tvb_get_guint8(tvb, offset+4, 2) << 16) |
                 ((guint64)wrapped_tvb_get_guint8(tvb, offset+6, 2) <<  8) |
                  (guint64)wrapped_tvb_get_guint8(tvb, offset+8, 2);
            proto_tree_add_uint64(ext_tree_qos, hf_gtp_qos_dl_mbr, tvb, offset, 10, br);
            offset += 10;
            br = ((guint64)wrapped_tvb_get_guint8(tvb, offset  , 2) << 32) |
                 ((guint64)wrapped_tvb_get_guint8(tvb, offset+2, 2) << 24) |
                 ((guint64)wrapped_tvb_get_guint8(tvb, offset+4, 2) << 16) |
                 ((guint64)wrapped_tvb_get_guint8(tvb, offset+6, 2) <<  8) |
                  (guint64)wrapped_tvb_get_guint8(tvb, offset+8, 2);
            proto_tree_add_uint64(ext_tree_qos, hf_gtp_qos_ul_gbr, tvb, offset, 10, br);
            offset += 10;
            br = ((guint64)wrapped_tvb_get_guint8(tvb, offset  , 2) << 32) |
                 ((guint64)wrapped_tvb_get_guint8(tvb, offset+2, 2) << 24) |
                 ((guint64)wrapped_tvb_get_guint8(tvb, offset+4, 2) << 16) |
                 ((guint64)wrapped_tvb_get_guint8(tvb, offset+6, 2) <<  8) |
                  (guint64)wrapped_tvb_get_guint8(tvb, offset+8, 2);
            proto_tree_add_uint64(ext_tree_qos, hf_gtp_qos_dl_gbr, tvb, offset, 10, br);
        } else {
            /* non GBR QCI */
            apn_ambr = (wrapped_tvb_get_guint8(tvb, offset  , 2) << 24) |
                       (wrapped_tvb_get_guint8(tvb, offset+2, 2) << 16) |
                       (wrapped_tvb_get_guint8(tvb, offset+4, 2) <<  8) |
                        wrapped_tvb_get_guint8(tvb, offset+6, 2);
            proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_ul_apn_ambr, tvb, offset, 8, apn_ambr);
            offset += 8;
            apn_ambr = (wrapped_tvb_get_guint8(tvb, offset  , 2) << 24) |
                       (wrapped_tvb_get_guint8(tvb, offset+2, 2) << 16) |
                       (wrapped_tvb_get_guint8(tvb, offset+4, 2) <<  8) |
                        wrapped_tvb_get_guint8(tvb, offset+6, 2);
            proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_dl_apn_ambr, tvb, offset, 8, apn_ambr);
        }
        return retval;
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
    spare1      = wrapped_tvb_get_guint8(tvb, offset + (1 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_SPARE1_MASK;
    delay       = wrapped_tvb_get_guint8(tvb, offset + (1 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_DELAY_MASK;
    reliability = wrapped_tvb_get_guint8(tvb, offset + (1 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_RELIABILITY_MASK;
    peak        = wrapped_tvb_get_guint8(tvb, offset + (2 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_PEAK_MASK;
    spare2      = wrapped_tvb_get_guint8(tvb, offset + (2 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_SPARE2_MASK;
    precedence  = wrapped_tvb_get_guint8(tvb, offset + (2 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_PRECEDENCE_MASK;
    spare3      = wrapped_tvb_get_guint8(tvb, offset + (3 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_SPARE3_MASK;
    mean        = wrapped_tvb_get_guint8(tvb, offset + (3 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_MEAN_MASK;

    /* In RADIUS messages there is no allocation-retention priority */
    if (type != 3)
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_al_ret_priority, tvb, offset, 1, al_ret_priority);

    /* All additions must take care of the fact that QoS fields in RADIUS
     * messages are UTF-8 encoded, so we have to use the same trick as above.
     * */
    proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_spare1,      tvb, offset + (1 - 1) * utf8_type + 1, utf8_type, spare1);
    proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_delay,       tvb, offset + (1 - 1) * utf8_type + 1, utf8_type, delay);
    proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_reliability, tvb, offset + (1 - 1) * utf8_type + 1, utf8_type, reliability);
    proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_peak,        tvb, offset + (2 - 1) * utf8_type + 1, utf8_type, peak);
    proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_spare2,      tvb, offset + (2 - 1) * utf8_type + 1, utf8_type, spare2);
    proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_precedence,  tvb, offset + (2 - 1) * utf8_type + 1, utf8_type, precedence);
    proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_spare3,      tvb, offset + (3 - 1) * utf8_type + 1, utf8_type, spare3);
    proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_mean,        tvb, offset + (3 - 1) * utf8_type + 1, utf8_type, mean);

    /* TS 24.008 V 7.8.0 10.5.6.5 Quality of service
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
        traf_class      = wrapped_tvb_get_guint8(tvb, offset + (4 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_TRAF_CLASS_MASK;
        del_order       = wrapped_tvb_get_guint8(tvb, offset + (4 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_DEL_ORDER_MASK;
        del_err_sdu     = wrapped_tvb_get_guint8(tvb, offset + (4 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_DEL_ERR_SDU_MASK;
        max_sdu_size    = wrapped_tvb_get_guint8(tvb, offset + (5 - 1) * utf8_type + 1, utf8_type);
        max_ul          = wrapped_tvb_get_guint8(tvb, offset + (6 - 1) * utf8_type + 1, utf8_type);
        max_dl          = wrapped_tvb_get_guint8(tvb, offset + (7 - 1) * utf8_type + 1, utf8_type);
        res_ber         = wrapped_tvb_get_guint8(tvb, offset + (8 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_RES_BER_MASK;
        sdu_err_ratio   = wrapped_tvb_get_guint8(tvb, offset + (8 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_SDU_ERR_RATIO_MASK;
        trans_delay     = wrapped_tvb_get_guint8(tvb, offset + (9 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_TRANS_DELAY_MASK;
        traf_handl_prio = wrapped_tvb_get_guint8(tvb, offset + (9 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_TRAF_HANDL_PRIORITY_MASK;
        guar_ul         = wrapped_tvb_get_guint8(tvb, offset + (10 - 1) * utf8_type + 1, utf8_type);
        /* Octet 13 */
        guar_dl         = wrapped_tvb_get_guint8(tvb, offset + (11 - 1) * utf8_type + 1, utf8_type);

        spare4        = 0;
        sig_ind       = 0;
        src_stat_desc = 0;
        max_dl_ext    = 0;
        guar_dl_ext   = 0;
        max_ul_ext    = 0;
        guar_ul_ext   = 0;

        if (length > 13 ||((type == 2) && (length == 13))) {
            spare4        = wrapped_tvb_get_guint8(tvb, offset + (12 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_SPARE4_MASK;
            sig_ind       = wrapped_tvb_get_guint8(tvb, offset + (12 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_SIG_IND_MASK;
            src_stat_desc = wrapped_tvb_get_guint8(tvb, offset + (12 - 1) * utf8_type + 1, utf8_type) & GTP_EXT_QOS_SRC_STAT_DESC_MASK;
        }
        if (length > 14) {
            max_dl_ext  = wrapped_tvb_get_guint8(tvb, offset + (13 - 1) * utf8_type + 1, utf8_type);
            guar_dl_ext = wrapped_tvb_get_guint8(tvb, offset + (14 - 1) * utf8_type + 1, utf8_type);
        }
        if (length > 16) {
            max_ul_ext = wrapped_tvb_get_guint8(tvb, offset + (15 - 1) * utf8_type + 1, utf8_type);
            guar_ul_ext = wrapped_tvb_get_guint8(tvb, offset + (16 - 1) * utf8_type + 1, utf8_type);
        }
        if (length > 18) {
            max_dl_ext2 = wrapped_tvb_get_guint8(tvb, offset + (17 - 1) * utf8_type + 1, utf8_type);
            guar_dl_ext2 = wrapped_tvb_get_guint8(tvb, offset + (18 - 1) * utf8_type + 1, utf8_type);
        }
        if (length > 20) {
            max_ul_ext2 = wrapped_tvb_get_guint8(tvb, offset + (19 - 1) * utf8_type + 1, utf8_type);
            guar_ul_ext2 = wrapped_tvb_get_guint8(tvb, offset + (20 - 1) * utf8_type + 1, utf8_type);
        }

        /*
         * See above comments for the changes
         */
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_traf_class,  tvb, offset + (4 - 1) * utf8_type + 1, utf8_type, traf_class);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_del_order,   tvb, offset + (4 - 1) * utf8_type + 1, utf8_type, del_order);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_del_err_sdu, tvb, offset + (4 - 1) * utf8_type + 1, utf8_type, del_err_sdu);
        if (max_sdu_size == 0 || max_sdu_size > 150)
            proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_max_sdu_size, tvb, offset + (5 - 1) * utf8_type + 1, utf8_type, max_sdu_size);
        if ((max_sdu_size > 0) && (max_sdu_size <= 150)) {
            mss = max_sdu_size * 10;
            proto_tree_add_uint_format_value(ext_tree_qos, hf_gtp_qos_max_sdu_size, tvb, offset + (5 - 1) * utf8_type + 1, utf8_type, mss,
                                       "%u octets", mss);
        }

        if (max_ul == 0 || max_ul == 255)
            proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_max_ul, tvb, offset + (6 - 1) * utf8_type + 1, utf8_type, max_ul);
        if ((max_ul > 0) && (max_ul <= 63))
            proto_tree_add_uint_format_value(ext_tree_qos, hf_gtp_qos_max_ul, tvb, offset + (6 - 1) * utf8_type + 1, utf8_type, max_ul,
                                       "%u kbps", max_ul);
        if ((max_ul > 63) && (max_ul <= 127)) {
            mu = 64 + (max_ul - 64) * 8;
            proto_tree_add_uint_format_value(ext_tree_qos, hf_gtp_qos_max_ul, tvb, offset + (6 - 1) * utf8_type + 1, utf8_type, mu,
                                       "%u kbps", mu);
        }

        if ((max_ul > 127) && (max_ul <= 254)) {
            mu = 576 + (max_ul - 128) * 64;
            proto_tree_add_uint_format_value(ext_tree_qos, hf_gtp_qos_max_ul, tvb, offset + (6 - 1) * utf8_type + 1, utf8_type, mu,
                                       "%u kbps", mu);
        }

        if (max_dl == 0 || max_dl == 255)
            proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_max_dl, tvb, offset + (7 - 1) * utf8_type + 1, utf8_type, max_dl);
        if ((max_dl > 0) && (max_dl <= 63))
            proto_tree_add_uint_format_value(ext_tree_qos, hf_gtp_qos_max_dl, tvb, offset + (7 - 1) * utf8_type + 1, utf8_type, max_dl,
                                       "%u kbps", max_dl);
        if ((max_dl > 63) && (max_dl <= 127)) {
            md = 64 + (max_dl - 64) * 8;
            proto_tree_add_uint_format_value(ext_tree_qos, hf_gtp_qos_max_dl, tvb, offset + (7 - 1) * utf8_type + 1, utf8_type, md,
                                       "%u kbps", md);
        }
        if ((max_dl > 127) && (max_dl <= 254)) {
            md = 576 + (max_dl - 128) * 64;
            proto_tree_add_uint_format_value(ext_tree_qos, hf_gtp_qos_max_dl, tvb, offset + (7 - 1) * utf8_type + 1, utf8_type, md,
                                       "%u kbps", md);
        }

        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_res_ber,         tvb, offset + (8 - 1) * utf8_type + 1, utf8_type, res_ber);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_sdu_err_ratio,   tvb, offset + (8 - 1) * utf8_type + 1, utf8_type, sdu_err_ratio);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_trans_delay,     tvb, offset + (9 - 1) * utf8_type + 1, utf8_type, trans_delay);
        proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_traf_handl_prio, tvb, offset + (9 - 1) * utf8_type + 1, utf8_type, traf_handl_prio);

        if (guar_ul == 0 || guar_ul == 255)
            proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_guar_ul, tvb, offset + (10 - 1) * utf8_type + 1, utf8_type, guar_ul);
        if ((guar_ul > 0) && (guar_ul <= 63))
            proto_tree_add_uint_format_value(ext_tree_qos, hf_gtp_qos_guar_ul, tvb, offset + (10 - 1) * utf8_type + 1, utf8_type, guar_ul,
                                       "%u kbps", guar_ul);
        if ((guar_ul > 63) && (guar_ul <= 127)) {
            gu = 64 + (guar_ul - 64) * 8;
            proto_tree_add_uint_format_value(ext_tree_qos, hf_gtp_qos_guar_ul, tvb, offset + (10 - 1) * utf8_type + 1, utf8_type, gu,
                                       "%u kbps", gu);
        }
        if ((guar_ul > 127) && (guar_ul <= 254)) {
            gu = 576 + (guar_ul - 128) * 64;
            proto_tree_add_uint_format_value(ext_tree_qos, hf_gtp_qos_guar_ul, tvb, offset + (10 - 1) * utf8_type + 1, utf8_type, gu,
                                       "%u kbps", gu);
        }

        /* Octet 13 */
        if (guar_dl == 0 || guar_dl == 255)
            proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_guar_dl, tvb, offset + (11 - 1) * utf8_type + 1, utf8_type, guar_dl);
        if ((guar_dl > 0) && (guar_dl <= 63))
            proto_tree_add_uint_format_value(ext_tree_qos, hf_gtp_qos_guar_dl, tvb, offset + (11 - 1) * utf8_type + 1, utf8_type, guar_dl,
                                       "%u kbps", guar_dl);
        if ((guar_dl > 63) && (guar_dl <= 127)) {
            gd = 64 + (guar_dl - 64) * 8;
            proto_tree_add_uint_format_value(ext_tree_qos, hf_gtp_qos_guar_dl, tvb, offset + (11 - 1) * utf8_type + 1, utf8_type, gd,
                                       "%u kbps", gd);
        }
        if ((guar_dl > 127) && (guar_dl <= 254)) {
            gd = 576 + (guar_dl - 128) * 64;
            proto_tree_add_uint_format_value(ext_tree_qos, hf_gtp_qos_guar_dl, tvb, offset + (11 - 1) * utf8_type + 1, utf8_type, gd,
                                       "%u kbps", gd);
        }

        if(length > 13 ||((type == 2) && (length == 13))) {
            proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_spare4, tvb, offset + (12 - 1) * utf8_type + 1, utf8_type, spare4);
            proto_tree_add_boolean(ext_tree_qos, hf_gtp_qos_sig_ind, tvb, offset + (12 - 1) * utf8_type + 1, utf8_type, sig_ind);
            proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_src_stat_desc, tvb, offset + (12 - 1) * utf8_type + 1, utf8_type, src_stat_desc);
        }


        if(length > 14) {
            /* Octet 15 */
            if(max_dl_ext == 0)
                proto_tree_add_expert_format(ext_tree_qos, pinfo, &ei_gtp_max_bit_rate_value, tvb, offset + (13 - 1) * utf8_type + 1, utf8_type,
                                           "Ext Maximum bit rate for downlink: Use the value in octet 9");
            if ((max_dl_ext > 0) && (max_dl_ext <= 0x4a)) {
                md = 8600 + max_dl_ext * 100;
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_dl, tvb, offset + (13 - 1) * utf8_type + 1, utf8_type, md,
                                           "Ext Maximum bit rate for downlink: %u kbps", md);
            }
            if ((max_dl_ext > 0x4a) && (max_dl_ext <= 0xba)) {
                md = 16 + (max_dl_ext-0x4a);
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_dl, tvb, offset + (13 - 1) * utf8_type + 1, utf8_type, md,
                                           "Ext Maximum bit rate for downlink: %u Mbps", md);
            }
            if ((max_dl_ext > 0xba) && (max_dl_ext <= 0xfa)) {
                md = 128 + (max_dl_ext-0xba)*2;
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_dl, tvb, offset + (13 - 1) * utf8_type + 1, utf8_type, md,
                                           "Ext Maximum bit rate for downlink: %u Mbps", md);
            }
            /* Octet 16 */
            if(guar_dl_ext == 0)
                proto_tree_add_expert_format(ext_tree_qos, pinfo, &ei_gtp_guaranteed_bit_rate_value, tvb, offset + (14 - 1) * utf8_type + 1, utf8_type,
                                           "Ext Guaranteed bit rate for downlink: Use the value in octet 13");
            if ((guar_dl_ext > 0) && (guar_dl_ext <= 0x4a)) {
                gd = 8600 + guar_dl_ext * 100;
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_dl, tvb, offset + (14 - 1) * utf8_type + 1, utf8_type, gd,
                                           "Ext Guaranteed bit rate for downlink: %u kbps", gd);
            }
            if ((guar_dl_ext > 0x4a) && (guar_dl_ext <= 0xba)) {
                gd = 16 + (guar_dl_ext-0x4a);
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_dl, tvb, offset + (14 - 1) * utf8_type + 1, utf8_type, gd,
                                           "Ext Guaranteed bit rate for downlink: %u Mbps", gd);
            }
            if ((guar_dl_ext > 0xba) && (guar_dl_ext <= 0xfa)) {
                gd = 128 + (guar_dl_ext-0xba)*2;
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_dl, tvb, offset + (14 - 1) * utf8_type + 1, utf8_type, gd,
                                           "Ext Guaranteed bit rate for downlink: %u Mbps", gd);
            }

        }
        if(length > 16) {
            /* Octet 17
             * This field is an extension of the Maximum bit rate for uplink in octet 8. The coding is identical to that of the Maximum bit
             * rate for downlink (extended).
             */
            if (max_ul_ext == 0)
                proto_tree_add_expert_format(ext_tree_qos, pinfo, &ei_gtp_max_bit_rate_value, tvb, offset + (15 - 1) * utf8_type + 1, utf8_type,
                                             "Ext Maximum bit rate for uplink: Use the value indicated in octet 8");
            if ((max_ul_ext > 0) && (max_ul_ext <= 0x4a)) {
                md = 8600 + max_ul_ext * 100;
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_ul, tvb, offset + (15 - 1) * utf8_type + 1, utf8_type, md,
                                           "Ext Maximum bit rate for uplink: %u kbps", md);
            }
            if ((max_ul_ext > 0x4a) && (max_ul_ext <= 0xba)) {
                md = 16 + (max_ul_ext-0x4a);
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_ul, tvb, offset + (15 - 1) * utf8_type + 1, utf8_type, md,
                                           "Ext Maximum bit rate for uplink: %u Mbps", md);
            }
            if ((max_ul_ext > 0xba) && (max_ul_ext <= 0xfa)) {
                md = 128 + (max_ul_ext-0xba)*2;
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_ul, tvb, offset + (15 - 1) * utf8_type + 1, utf8_type, md,
                                           "Ext Maximum bit rate for uplink: %u Mbps", md);
            }
            /* Octet 18 */
            if (guar_ul_ext == 0)
                proto_tree_add_expert_format(ext_tree_qos, pinfo, &ei_gtp_guaranteed_bit_rate_value, tvb, offset + (16 - 1) * utf8_type + 1, utf8_type,
                                           "Ext Guaranteed bit rate for uplink: Use the value indicated in octet 12");
            if ((guar_ul_ext > 0) && (guar_ul_ext <= 0x4a)) {
                gd = 8600 + guar_ul_ext * 100;
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_ul, tvb, offset + (16 - 1) * utf8_type + 1, utf8_type, gd,
                                           "Ext Guaranteed bit rate for uplink: %u kbps", gd);
            }
            if ((guar_ul_ext > 0x4a) && (guar_ul_ext <= 0xba)) {
                gd = 16 + (guar_ul_ext-0x4a);
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_ul, tvb, offset + (16 - 1) * utf8_type + 1, utf8_type, gd,
                                           "Ext Guaranteed bit rate for uplink: %u Mbps", gd);
            }
            if ((guar_ul_ext > 0xba) && (guar_ul_ext <= 0xfa)) {
                gd = 128 + (guar_ul_ext-0xba)*2;
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_ul, tvb, offset + (16 - 1) * utf8_type + 1, utf8_type, gd,
                                           "Ext Guaranteed bit rate for uplink: %u Mbps", gd);
            }
        }

        if(length > 18) {
            /* Octet 19 Maximum bit rate for downlink (extended-2)
             * This field is an extension of the Maximum bit rate for uplink in octet 8. The coding is identical to that of the Maximum bit
             * rate for downlink (extended).
             */
            if (max_dl_ext2 == 0)
                proto_tree_add_expert_format(ext_tree_qos, pinfo, &ei_gtp_max_bit_rate_value, tvb, offset + (17 - 1) * utf8_type + 1, utf8_type,
                                           "Ext2 Maximum bit rate for downlink: Use the value in octet 9 and octet 15.");

            if ((max_dl_ext2 > 0) && (max_dl_ext2 <= 0x3d)) {
                md = 256 + max_dl_ext2 * 4;
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_ul, tvb, offset + (15 - 1) * utf8_type + 1, utf8_type, md,
                                           "Ext2 Maximum bit rate for downlink: %u Mbps", md);
            }
            if ((max_dl_ext2 > 0x3d) && (max_dl_ext2 <= 0xa1)) {
                md = 500 + (max_dl_ext2-0x3d) * 10;
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_ul, tvb, offset + (15 - 1) * utf8_type + 1, utf8_type, md,
                                           "Ext2 Maximum bit rate for downlink: %u Mbps", md);
            }
            if ((max_dl_ext2 > 0xa1) && (max_dl_ext2 <= 0xf6)) {
                md = 1500 + (max_dl_ext2-0xa1)*10;
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_ul, tvb, offset + (15 - 1) * utf8_type + 1, utf8_type, md,
                                           "Ext2 Maximum bit rate for downlink: %u Mbps", md);
            }
            /* Octet 20 Guaranteed bit rate for downlink (extended-2) */
            if (guar_dl_ext2 == 0)
                proto_tree_add_expert_format(ext_tree_qos, pinfo, &ei_gtp_max_bit_rate_value, tvb, offset + (16 - 1) * utf8_type + 1, utf8_type,
                                           "Ext2 Guaranteed bit rate for downlink: Use the value in octet 13 and octet 16.");
            if ((guar_dl_ext2 > 0) && (guar_dl_ext2 <= 0x3d)) {
                gd = 256 + guar_dl_ext2 * 4;
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_ul, tvb, offset + (16 - 1) * utf8_type + 1, utf8_type, gd,
                                           "Ext2 Guaranteed bit rate for downlink: %u Mbps", gd);
            }
            if ((guar_dl_ext2 > 0x3d) && (guar_dl_ext2 <= 0xa1)) {
                gd = 500 + (guar_dl_ext2-0x3d) * 10;
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_ul, tvb, offset + (16 - 1) * utf8_type + 1, utf8_type, gd,
                                           "Ext2 Guaranteed bit rate for downlink: %u Mbps", gd);
            }
            if ((guar_dl_ext2 > 0xba) && (guar_dl_ext2 <= 0xfa)) {
                gd = 1500 + (guar_dl_ext2-0xa1) * 10;
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_ul, tvb, offset + (16 - 1) * utf8_type + 1, utf8_type, gd,
                                           "Ext2 Guaranteed bit rate for uplink: %u Mbps", gd);
            }
        }

        if(length > 20) {
            /* Maximum bit rate for uplink (extended-2), octet 21
             * This field is an extension of the Maximum bit rate for uplink in octet 8. The coding is identical to that of the Maximum bit
             * rate for downlink (extended).
             */
            if (max_ul_ext2 == 0)
                proto_tree_add_expert_format(ext_tree_qos, pinfo, &ei_gtp_max_bit_rate_value, tvb, offset + (17 - 1) * utf8_type + 1, utf8_type,
                                           "Ext2 Maximum bit rate for uplink: Use the value in octet 8 and octet 17.");

            if ((max_ul_ext2 > 0) && (max_ul_ext2 <= 0x3d)) {
                md = 256 + max_ul_ext2 * 4;
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_ul, tvb, offset + (15 - 1) * utf8_type + 1, utf8_type, md,
                                           "Ext2 Maximum bit rate for uplink: %u Mbps", md);
            }
            if ((max_ul_ext2 > 0x3d) && (max_ul_ext2 <= 0xa1)) {
                md = 500 + (max_ul_ext2-0x3d) * 10;
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_ul, tvb, offset + (15 - 1) * utf8_type + 1, utf8_type, md,
                                           "Ext2 Maximum bit rate for uplink: %u Mbps", md);
            }
            if ((max_ul_ext2 > 0xa1) && (max_ul_ext2 <= 0xf6)) {
                md = 1500 + (max_ul_ext2-0xa1)*10;
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_ul, tvb, offset + (15 - 1) * utf8_type + 1, utf8_type, md,
                                           "Ext2 Maximum bit rate for uplink: %u Mbps", md);
            }
            /* Guaranteed bit rate for uplink (extended-2), octet 22 */
            if (guar_ul_ext2 == 0)
                proto_tree_add_expert_format(ext_tree_qos, pinfo, &ei_gtp_max_bit_rate_value, tvb, offset + (16 - 1) * utf8_type + 1, utf8_type,
                                           "Ext2 Guaranteed bit rate for uplink: Use the value in octet 13 and octet 16.");
            if ((guar_ul_ext2 > 0) && (guar_ul_ext2 <= 0x3d)) {
                gd = 256 + guar_ul_ext2 * 4;
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_ul, tvb, offset + (16 - 1) * utf8_type + 1, utf8_type, gd,
                                           "Ext2 Guaranteed bit rate for uplink: %u Mbps", gd);
            }
            if ((guar_ul_ext2 > 0x3d) && (guar_ul_ext2 <= 0xa1)) {
                gd = 500 + (max_ul_ext2-0x3d) * 10;
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_ul, tvb, offset + (16 - 1) * utf8_type + 1, utf8_type, gd,
                                           "Ext2 Guaranteed bit rate for uplink: %u Mbps", gd);
            }
            if ((guar_ul_ext2 > 0xba) && (guar_ul_ext2 <= 0xfa)) {
                gd = 1500 + (guar_ul_ext2-0xa1) * 10;
                proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_ul, tvb, offset + (16 - 1) * utf8_type + 1, utf8_type, gd,
                                           "Ext2 Guaranteed bit rate for uplink: %u Mbps", gd);
            }
        }
    }

    return retval;
}

/* Diameter 3GPP AVP Code: 5 3GPP-GPRS Negotiated QoS profile */
static int
dissect_diameter_3gpp_qosprofile(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {

    decode_qos_umts(tvb, 0, pinfo, tree, "UMTS GTP QoS Profile", 3);
    return tvb_reported_length(tvb);
}

static const gchar *
dissect_radius_qos_umts(proto_tree * tree, tvbuff_t * tvb, packet_info* pinfo)
{
    decode_qos_umts(tvb, 0, pinfo, tree, "UMTS GTP QoS Profile", 3);
    return tvb_get_string_enc(wmem_packet_scope(), tvb, 0, tvb_reported_length(tvb), ENC_UTF_8|ENC_NA);
}

#define MAX_APN_LENGTH          100

static void
decode_apn(tvbuff_t * tvb, int offset, guint16 length, proto_tree * tree, proto_item *item)
{
    guint8   str[MAX_APN_LENGTH+1];
    guint    curr_len;

    /*
     * This is "a domain name represented as a sequence of labels, where
     * each label consists of a length octet followed by that number of
     * octets.", DNS-style.
     *
     * XXX - does it involve compression?
     */

    /* init buffer and copy it */
    memset(str, 0, MAX_APN_LENGTH+1);
    tvb_memcpy(tvb, str, offset, length<MAX_APN_LENGTH?length:MAX_APN_LENGTH);

    curr_len = 0;
    while ((curr_len < length) && (curr_len < MAX_APN_LENGTH))
    {
        guint step    = str[curr_len];
        str[curr_len] = '.';
        curr_len     += step+1;
    }

    /* Highlight bytes including the first length byte */
    proto_tree_add_string(tree, hf_gtp_apn, tvb, offset, length, str+1);
    if(item){
        proto_item_append_text(item, ": %s", str+1);
    }

}

static void
decode_fqdn(tvbuff_t * tvb, int offset, guint16 length, proto_tree * tree, session_args_t * args _U_)
{
    guint8 *fqdn = NULL;
    int     name_len, tmp;

    if (length > 0) {
        name_len = tvb_get_guint8(tvb, offset);

        if (name_len < 0x20) {
            fqdn = tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 1, length - 1, ENC_ASCII);
            for (;;) {
                if (name_len >= length - 1)
                    break;
                tmp = name_len;
                name_len = name_len + fqdn[tmp] + 1;
                fqdn[tmp] = '.';
            }
        } else
            fqdn = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_ASCII);

        proto_tree_add_string(tree, hf_gtp_fqdn, tvb, offset, length, fqdn);
    }
}

/*
 * GPRS:        9.60 v7.6.0, chapter 7.9.20
 * UMTS:        29.060 v4.0, chapter 7.7.29 PDP Context
 * TODO:        unify addr functions
 */
static int
decode_gtp_pdp_cntxt(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint8             ggsn_addr_len, apn_len, trans_id, ea;
    guint8             pdp_type_num, pdp_addr_len;
    guint16            length;
    proto_tree        *ext_tree_pdp;

    length = tvb_get_ntohs(tvb, offset + 1);

    ext_tree_pdp = proto_tree_add_subtree(tree, tvb, offset, length + 3, ett_gtp_ies[GTP_EXT_PDP_CNTXT], NULL,
                    val_to_str_ext_const(GTP_EXT_PDP_CNTXT, &gtp_val_ext, "Unknown message"));

    ea = (tvb_get_guint8(tvb, offset + 3) >> 7) & 0x01;

    proto_tree_add_item(ext_tree_pdp, hf_gtp_extended_end_user_address, tvb, offset + 3, 1, ENC_NA);
    proto_tree_add_item(ext_tree_pdp, hf_gtp_vplmn_address_allowed, tvb, offset + 3, 1, ENC_NA);
    proto_tree_add_item(ext_tree_pdp, hf_gtp_activity_status_indicator, tvb, offset + 3, 1, ENC_NA);
    proto_tree_add_item(ext_tree_pdp, hf_gtp_reordering_required, tvb, offset + 3, 1, ENC_NA);
    proto_tree_add_item(ext_tree_pdp, hf_gtp_nsapi, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree_pdp, hf_gtp_pdp_cntxt_sapi, tvb, offset + 4, 1, ENC_BIG_ENDIAN);

    switch (gtp_version) {
    case 0:
        decode_qos_gprs(tvb, offset + 5, ext_tree_pdp, "QoS subscribed", 0);
        decode_qos_gprs(tvb, offset + 8, ext_tree_pdp, "QoS requested", 0);
        decode_qos_gprs(tvb, offset + 11, ext_tree_pdp, "QoS negotiated", 0);
        offset = offset + 14;
        break;
    case 1:
        offset = offset + 5;
        offset = offset + decode_qos_umts(tvb, offset, pinfo, ext_tree_pdp, "QoS subscribed", 1);
        offset = offset + decode_qos_umts(tvb, offset, pinfo, ext_tree_pdp, "QoS requested", 1);
        offset = offset + decode_qos_umts(tvb, offset, pinfo, ext_tree_pdp, "QoS negotiated", 1);
        break;
    default:
        break;
    }

    proto_tree_add_item(ext_tree_pdp, hf_gtp_sequence_number_down, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree_pdp, hf_gtp_sequence_number_up, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree_pdp, hf_gtp_send_n_pdu_number, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree_pdp, hf_gtp_receive_n_pdu_number, tvb, offset + 5, 1, ENC_BIG_ENDIAN);

    switch (gtp_version) {
    case 0:
        proto_tree_add_item(ext_tree_pdp, hf_gtp_uplink_flow_label_signalling, tvb, offset + 6, 2, ENC_BIG_ENDIAN);
        offset = offset + 8;
        break;
    case 1:
        proto_tree_add_item(ext_tree_pdp, hf_gtp_uplink_teid_cp,   tvb, offset + 6, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ext_tree_pdp, hf_gtp_uplink_teid_data, tvb, offset + 10, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ext_tree_pdp, hf_gtp_pdp_context_identifier, tvb, offset + 14, 1, ENC_BIG_ENDIAN);
        offset = offset + 15;
        break;
    default:
        break;
    }

    pdp_type_num = tvb_get_guint8(tvb, offset + 1);
    pdp_addr_len = tvb_get_guint8(tvb, offset + 2);

    proto_tree_add_item(ext_tree_pdp, hf_gtp_pdp_organization, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree_pdp, hf_gtp_pdp_type, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree_pdp, hf_gtp_pdp_address_length, tvb, offset + 2, 1, ENC_BIG_ENDIAN);

    if (pdp_addr_len > 0) {
        switch (pdp_type_num) {
        case 0x21:
            proto_tree_add_item(ext_tree_pdp, hf_gtp_pdp_address_ipv4, tvb, offset + 3, 4, ENC_BIG_ENDIAN);
            break;
        case 0x57:
            proto_tree_add_item(ext_tree_pdp, hf_gtp_pdp_address_ipv6, tvb, offset + 3, 16, ENC_NA);
            break;
        default:
            break;
        }
    }

    offset = offset + 3 + pdp_addr_len;

    ggsn_addr_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(ext_tree_pdp, hf_gtp_ggsn_address_length, tvb, offset, 1, ENC_BIG_ENDIAN);

    switch (ggsn_addr_len) {
    case 4:
        proto_tree_add_item(ext_tree_pdp, hf_gtp_ggsn_address_for_control_plane_ipv4, tvb, offset + 1, 4, ENC_BIG_ENDIAN);
        break;
    case 16:
        proto_tree_add_item(ext_tree_pdp, hf_gtp_ggsn_address_for_control_plane_ipv6, tvb, offset + 1, 16, ENC_NA);
        break;
    default:
        break;
    }

    offset = offset + 1 + ggsn_addr_len;

    if (gtp_version == 1) {

        ggsn_addr_len = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(ext_tree_pdp, hf_gtp_ggsn_address_length, tvb, offset, 1, ENC_BIG_ENDIAN);

        switch (ggsn_addr_len) {
        case 4:
            proto_tree_add_item(ext_tree_pdp, hf_gtp_ggsn_address_for_user_traffic_ipv4, tvb, offset + 1, 4, ENC_BIG_ENDIAN);
            break;
        case 16:
            proto_tree_add_item(ext_tree_pdp, hf_gtp_ggsn_address_for_user_traffic_ipv6, tvb, offset + 1, 16, ENC_NA);
            break;
        default:
            break;
        }
        offset = offset + 1 + ggsn_addr_len;

    }

    apn_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(ext_tree_pdp, hf_gtp_apn_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    decode_apn(tvb, offset + 1, apn_len, ext_tree_pdp, NULL);

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
    proto_tree_add_uint(ext_tree_pdp, hf_gtp_transaction_identifier, tvb, offset, 2, trans_id);
    offset += 2;

    if (ea) {
        pdp_type_num = tvb_get_guint8(tvb, offset);
        pdp_addr_len = tvb_get_guint8(tvb, offset + 1);

        proto_tree_add_item(ext_tree_pdp, hf_gtp_pdp_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ext_tree_pdp, hf_gtp_pdp_address_length, tvb, offset + 1, 1, ENC_BIG_ENDIAN);

        if (pdp_addr_len > 0) {
            switch (pdp_type_num) {
            case 0x21:
                proto_tree_add_item(ext_tree_pdp, hf_gtp_pdp_address_ipv4, tvb, offset + 2, 4, ENC_NA);
                break;
            case 0x57:
                proto_tree_add_item(ext_tree_pdp, hf_gtp_pdp_address_ipv6, tvb, offset + 2, 16, ENC_NA);
                break;
            default:
                break;
            }
        }
    }

    return 3 + length;
}

/* GPRS:        9.60, v7.6.0, chapter 7.9.21
 * UMTS:        29.060, v4.0, chapter 7.7.30
 */
static int
decode_gtp_apn(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree_apn;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);

    ext_tree_apn = proto_tree_add_subtree(tree, tvb, offset, length + 3, ett_gtp_ies[GTP_EXT_APN], &te,
                                val_to_str_ext_const(GTP_EXT_APN, &gtp_val_ext, "Unknown field"));

    proto_tree_add_item(ext_tree_apn, hf_gtp_apn_length, tvb, offset + 1, 2, ENC_BIG_ENDIAN);
    decode_apn(tvb, offset + 3, length, ext_tree_apn, te);

    return 3 + length;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.22
 *              4.08 v. 7.1.2, chapter 10.5.6.3 (p.580)
 * UMTS:        29.060 v4.0, chapter 7.7.31 Protocol Configuration Options
 *              24.008, v4.2, chapter 10.5.6.3
 */
int
decode_gtp_proto_conf(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    tvbuff_t   *next_tvb;
    proto_tree *ext_tree_proto;

    length = tvb_get_ntohs(tvb, offset + 1);

    ext_tree_proto = proto_tree_add_subtree(tree, tvb, offset, length + 3,
                ett_gtp_proto, NULL, val_to_str_ext_const(GTP_EXT_PROTO_CONF, &gtp_val_ext, "Unknown message"));

    proto_tree_add_uint(ext_tree_proto, hf_gtp_length, tvb, offset + 1, 2, length);

    if (length < 1)
        return 3;

    /* The Protocol Configuration Options contains external network protocol options that may be necessary to transfer
     * between the GGSN and the MS. The content and the coding of the Protocol Configuration are defined in octet 3-z of the
     * Protocol Configuration Options in3GPP TS 24.008 [5].
     */
    next_tvb = tvb_new_subset_length(tvb, offset + 3, length);
    de_sm_pco(next_tvb, ext_tree_proto, pinfo, 0, length, NULL, 0);

    return 3 + length;
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.23
 * UMTS:        29.060 v4.0, chapter 7.7.32
 */
static int
decode_gtp_gsn_addr_common(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args, const char * tree_name, int hf_ipv4, int hf_ipv6)
{

    guint8             addr_type, addr_len;
    guint16            length;
    proto_tree        *ext_tree_gsn_addr;
    proto_item        *te;
    address           *gsn_address;

    length = tvb_get_ntohs(tvb, offset + 1);

    ext_tree_gsn_addr = proto_tree_add_subtree_format(tree, tvb, offset, 3 + length, ett_gtp_gsn_addr, &te, "%s : ", tree_name);
    gsn_address = wmem_new0(wmem_packet_scope(), address);
    switch (length) {
    case 4:
        proto_tree_add_item(ext_tree_gsn_addr, hf_gtp_gsn_address_length, tvb, offset + 1, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(ext_tree_gsn_addr, hf_ipv4, tvb, offset + 3, 4, ENC_BIG_ENDIAN);
        if (hf_ipv4 != hf_gtp_gsn_ipv4)
            proto_item_set_hidden(proto_tree_add_item(ext_tree_gsn_addr, hf_gtp_gsn_ipv4, tvb, offset + 3, 4, ENC_BIG_ENDIAN));
        proto_item_append_text(te, "%s", tvb_ip_to_str(pinfo->pool, tvb, offset + 3));
        set_address_tvb(gsn_address, AT_IPv4, 4, tvb, offset + 3);
        break;
    case 5:
        proto_tree_add_item(ext_tree_gsn_addr, hf_gtp_gsn_address_information_element_length, tvb, offset + 1, 2, ENC_BIG_ENDIAN);
        addr_type = tvb_get_guint8(tvb, offset + 3) & 0xC0;
        proto_tree_add_uint(ext_tree_gsn_addr, hf_gtp_gsn_addr_type, tvb, offset + 3, 1, addr_type);
        addr_len = tvb_get_guint8(tvb, offset + 3) & 0x3F;
        proto_tree_add_uint(ext_tree_gsn_addr, hf_gtp_gsn_addr_len, tvb, offset + 3, 1, addr_len);
        proto_tree_add_item(ext_tree_gsn_addr, hf_ipv4, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
        if (hf_ipv4 != hf_gtp_gsn_ipv4)
            proto_item_set_hidden(proto_tree_add_item(ext_tree_gsn_addr, hf_gtp_gsn_ipv4, tvb, offset + 4, 4, ENC_BIG_ENDIAN));
        proto_item_append_text(te, "%s", tvb_ip_to_str(pinfo->pool, tvb, offset + 4));
        set_address_tvb(gsn_address, AT_IPv6, 16, tvb, offset + 4);
        break;
    case 16:
        proto_tree_add_item(ext_tree_gsn_addr, hf_gtp_gsn_address_length, tvb, offset + 1, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(ext_tree_gsn_addr, hf_ipv6, tvb, offset + 3, 16, ENC_NA);
        if (hf_ipv6 != hf_gtp_gsn_ipv6)
            proto_item_set_hidden(proto_tree_add_item(ext_tree_gsn_addr, hf_gtp_gsn_ipv6, tvb, offset + 3, 16, ENC_NA));
        proto_item_append_text(te, "%s", tvb_ip6_to_str(pinfo->pool, tvb, offset + 3));
        set_address_tvb(gsn_address, AT_IPv4, 4, tvb, offset + 3);
        break;
    case 17:
        proto_tree_add_item(ext_tree_gsn_addr, hf_gtp_gsn_address_information_element_length, tvb, offset + 1, 2, ENC_BIG_ENDIAN);
        addr_type = tvb_get_guint8(tvb, offset + 3) & 0xC0;
        proto_tree_add_uint(ext_tree_gsn_addr, hf_gtp_gsn_addr_type, tvb, offset + 3, 1, addr_type);
        addr_len = tvb_get_guint8(tvb, offset + 3) & 0x3F;
        proto_tree_add_uint(ext_tree_gsn_addr, hf_gtp_gsn_addr_len, tvb, offset + 3, 1, addr_len);
        proto_item_append_text(te, "%s", tvb_ip6_to_str(pinfo->pool, tvb, offset + 4));
        proto_tree_add_item(ext_tree_gsn_addr, hf_ipv6, tvb, offset + 4, 16, ENC_NA);
        if (hf_ipv6 != hf_gtp_gsn_ipv6)
            proto_item_set_hidden(proto_tree_add_item(ext_tree_gsn_addr, hf_gtp_gsn_ipv6, tvb, offset + 4, 16, ENC_NA));
        set_address_tvb(gsn_address, AT_IPv6, 16, tvb, offset + 4);
        break;
    default:
        proto_item_append_text(te, "unknown type or wrong length");
        break;
    }

    if (g_gtp_session && gtp_version == 1 && !PINFO_FD_VISITED(pinfo)) {
        if (!ip_exists(*gsn_address, args->ip_list)) {
            copy_address_wmem(wmem_packet_scope(), &args->last_ip, gsn_address);
            wmem_list_prepend(args->ip_list, gsn_address);
        }
    }
    return 3 + length;
}

static int
decode_gtp_gsn_addr(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args) {
    return decode_gtp_gsn_addr_common(tvb, offset, pinfo, tree, args, "GSN address", hf_gtp_gsn_ipv4, hf_gtp_gsn_ipv6);
}

static int
decode_gtp_sgsn_addr_for_control_plane(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args)
{
    return decode_gtp_gsn_addr_common(tvb, offset, pinfo, tree, args,
        "SGSN Address for control plane", hf_gtp_sgsn_address_for_control_plane_ipv4, hf_gtp_sgsn_address_for_control_plane_ipv6);
}

static int
decode_gtp_sgsn_addr_for_user_plane(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args)
{
    return decode_gtp_gsn_addr_common(tvb, offset, pinfo, tree, args,
        "SGSN Address for user traffic", hf_gtp_sgsn_address_for_user_traffic_ipv4, hf_gtp_sgsn_address_for_user_traffic_ipv6);
}

static int
decode_gtp_ggsn_addr_for_control_plane(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args)
{
    return decode_gtp_gsn_addr_common(tvb, offset, pinfo, tree, args,
        "GGSN Address for control plane", hf_gtp_ggsn_address_for_control_plane_ipv4, hf_gtp_ggsn_address_for_control_plane_ipv6);
}

static int
decode_gtp_ggsn_addr_for_user_plane(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args)
{
    return decode_gtp_gsn_addr_common(tvb, offset, pinfo, tree, args,
        "GGSN Address for user traffic", hf_gtp_ggsn_address_for_user_traffic_ipv4, hf_gtp_ggsn_address_for_user_traffic_ipv6);
}

/* GPRS:        9.60 v7.6.0, chapter 7.9.24
 * UMTS:        29.060 v4.0, chapter 7.7.33
 */
static int
decode_gtp_msisdn(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    tvbuff_t   *next_tvb;
    proto_tree *ext_tree_proto;

    length = tvb_get_ntohs(tvb, offset + 1);

    ext_tree_proto = proto_tree_add_subtree(tree, tvb, offset, length + 3, ett_gtp_proto, NULL,
                            val_to_str_ext_const(GTP_EXT_MSISDN, &gtp_val_ext, "Unknown message"));

    proto_tree_add_uint(ext_tree_proto, hf_gtp_length, tvb, offset + 1, 2, length);

    length = tvb_get_ntohs(tvb, offset + 1);

    if (length < 1)
        return 3;

    next_tvb = tvb_new_subset_length(tvb, offset+3, length);
    dissect_gsm_map_msisdn(next_tvb, pinfo, ext_tree_proto);

    return 3 + length;
}

/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.34
 *              24.008 v4.2, chapter 10.5.6.5
 */
static int
decode_gtp_qos_umts(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_)
{

    return decode_qos_umts(tvb, offset, pinfo, tree, "Quality of Service", 2);
}

/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.35
 */
static int
decode_gtp_auth_qui(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    proto_tree *ext_tree;
    guint16     length;
    guint8      xres_len, auth_len;


    length = tvb_get_ntohs(tvb, offset + 1);

    ext_tree = proto_tree_add_subtree(tree, tvb, offset, length + 1, ett_gtp_quint, NULL, "Quintuplet");
    offset++;

    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    proto_tree_add_item(ext_tree, hf_gtp_rand, tvb, offset, 16, ENC_NA);
    offset = offset + 16;
    xres_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(ext_tree, hf_gtp_xres_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_xres, tvb, offset, xres_len, ENC_NA);
    offset = offset + xres_len;
    proto_tree_add_item(ext_tree, hf_gtp_quintuplet_ciphering_key, tvb, offset, 16, ENC_NA);
    offset = offset + 16;
    proto_tree_add_item(ext_tree, hf_gtp_quintuplet_integrity_key, tvb, offset, 16, ENC_NA);
    offset = offset + 16;
    auth_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(ext_tree, hf_gtp_authentication_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_auth, tvb, offset, auth_len, ENC_NA);

    return (3 + length);

}

/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.36
 *              24.008 v4.2, chapter 10.5.6.12
 */
static int
decode_gtp_tft(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    proto_tree     *ext_tree_tft;
    guint          length;

    length = tvb_get_ntohs(tvb, offset + 1);

    ext_tree_tft = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_tft, NULL, "Traffic flow template");
    proto_tree_add_item(ext_tree_tft, hf_gtp_tft_length, tvb, offset + 1, 2, ENC_BIG_ENDIAN);

    /* The detailed coding of Traffic Flow Template
    * Description is specified in 3GPP TS 24.008 [5] ,
    * clause 10.5.6.12, beginning with octet 3..
    * Use the decoding in packet-gsm_a_gm.c
    */
    de_sm_tflow_temp(tvb, ext_tree_tft, pinfo, offset + 3, length, NULL, 0);

    return 3 + length;
}

/* GPRS:        not present
 * UMTS:        3GPP TS 29.060 version 10.4.0 Release 10, chapter 7.7.37
 * Type = 138 (Decimal)
 *              25.413(RANAP) TargetID
 * There are several CRs to this IE make sure to check with a recent spec if dissection is questioned.
 */
static int
decode_gtp_target_id(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_)
{

    guint16         length;
    proto_tree      *ext_tree;


    length = tvb_get_ntohs(tvb, offset + 1);

    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_TARGET_ID], NULL, "Target Identification");
    offset = offset + 1;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    if (length == 0){
        return 3 + length;
    }

    /* Quote from specification:
     * The Target Identification information element contains the identification of a target RNC. Octets 4-n shall contain a
     * non-transparent copy of the corresponding IEs (see subclause 7.7.2) and be encoded as specified in Figure 51 below.
     * The "Target RNC-ID" part of the "Target ID" parameter is specified in 3GPP TS 25.413 [7].
     * NOTE 1: The ASN.1 parameter "Target ID" is forwarded non-transparently in order to maintain backward compatibility.
     * NOTE 2: The preamble of the "Target RNC-ID" (numerical value of e.g. 0x20) however shall not be included in
     *         octets 4-n. Also the optional "iE-Extensions" parameter shall not be included into the GTP IE.
     */
    /* Octet 4-6 MCC + MNC */
    if (length == 9) {
        /* Patch for systems still not following NOTE 2 */
        proto_tree_add_expert_format(ext_tree, pinfo, &ei_gtp_undecoded, tvb, offset, 1, "Not Compliant with 3GPP TS 29.060 7.7.37: The preamble of the \"Target RNC-ID\" (numerical value of e.g. 0x20) however shall not be included in octets 4-n.");
        offset+=1;
        dissect_e212_mcc_mnc(tvb, pinfo, ext_tree, offset, E212_NONE, FALSE);
    } else {
        /* Following Standards */
        dissect_e212_mcc_mnc(tvb, pinfo, ext_tree, offset, E212_NONE, TRUE);
    }
    offset+=3;

    /* Octet 7-8 LAC */
    proto_tree_add_item(ext_tree, hf_gtp_lac, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;
    /* Octet 9 RAC */
    proto_tree_add_item(ext_tree, hf_gtp_rai_rac, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Octet 10-11 RNC-ID*/
    proto_tree_add_item(ext_tree, hf_gtp_target_rnc_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;
    /* If the optional Extended RNC-ID is not included, then the length variable 'n' = 8 and the overall length of the IE is 11
     * octets. Otherwise, 'n' = 10 and the overall length of the IE is 13 octets
     */
    if(length == 10){
        proto_tree_add_item(ext_tree, hf_gtp_target_ext_rnc_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    }

    return 3 + length;
}


/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.38
 */
static int
decode_gtp_utran_cont(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;
    tvbuff_t   *new_tvb;
    proto_tree *sub_tree;

    length = tvb_get_ntohs(tvb, offset + 1);

    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_UTRAN_CONT], NULL, "UTRAN transparent Container");

    offset = offset + 1;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    proto_tree_add_item(ext_tree, hf_gtp_utran_field, tvb, offset, length, ENC_NA);

    switch (pinfo->link_dir) {
    case P2P_DIR_UL:
        sub_tree = proto_tree_add_subtree(ext_tree, tvb, offset, length, ett_gtp_utran_cont, NULL, "Source RNC to Target RNC Transparent Container");
        new_tvb = tvb_new_subset_remaining(tvb, offset);
        dissect_ranap_SourceRNC_ToTargetRNC_TransparentContainer_PDU(new_tvb, pinfo, sub_tree, NULL);
        break;
    case P2P_DIR_DL:
        sub_tree = proto_tree_add_subtree(ext_tree, tvb, offset, length, ett_gtp_utran_cont, NULL, "Target RNC to Source RNC Transparent Container");
        new_tvb = tvb_new_subset_remaining(tvb, offset);
        dissect_ranap_TargetRNC_ToSourceRNC_TransparentContainer_PDU(new_tvb, pinfo, sub_tree, NULL);
        break;
    default:
        break;
    }

    return 3 + length;

}


/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.39
 */
static int
decode_gtp_rab_setup(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint32            teid;
    guint16            length;
    proto_tree        *ext_tree_rab_setup;

    length = tvb_get_ntohs(tvb, offset + 1);

    ext_tree_rab_setup = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_rab_setup, NULL, "Radio Access Bearer Setup Information");

    proto_tree_add_item(ext_tree_rab_setup, hf_gtp_rab_setup_length, tvb, offset + 1, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree_rab_setup, hf_gtp_nsapi, tvb, offset + 3, 1, ENC_BIG_ENDIAN);

    if (length > 1) {

        teid = tvb_get_ntohl(tvb, offset + 4);

        proto_tree_add_uint(ext_tree_rab_setup, hf_gtp_teid_data, tvb, offset + 4, 4, teid);

        switch (length) {
        case 9:
            proto_tree_add_item(ext_tree_rab_setup, hf_gtp_rnc_ipv4, tvb, offset + 8, 4, ENC_BIG_ENDIAN);
            break;
        case 21:
            proto_tree_add_item(ext_tree_rab_setup, hf_gtp_rnc_ipv6, tvb, offset + 8, 16, ENC_NA);
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
static int
decode_gtp_hdr_list(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    int         i;
    guint8      length, hdr;
    proto_tree *ext_tree_hdr_list;

    length = tvb_get_guint8(tvb, offset + 1);

    ext_tree_hdr_list = proto_tree_add_subtree(tree, tvb, offset, 2 + length, ett_gtp_hdr_list, NULL,
                            val_to_str_ext_const(GTP_EXT_HDR_LIST, &gtp_val_ext, "Unknown"));

    proto_tree_add_item(ext_tree_hdr_list, hf_gtp_num_ext_hdr_types, tvb, offset + 1, 1, ENC_NA);

    for (i = 0; i < length; i++) {
        hdr = tvb_get_guint8(tvb, offset + 2 + i);

        proto_tree_add_uint_format(ext_tree_hdr_list, hf_gtp_ext_hdr_type, tvb, offset + 2 + i, 1, hdr, "No. %u --> Extension Header Type value : %s (0x%02x)", i + 1,
                            val_to_str_const(hdr, next_extension_header_fieldvals, "Unknown Extension Header Type"), hdr);
    }

    return 2 + length;
}

/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.41
 * TODO:        find TriggerID description
 */
static int
decode_gtp_trigger_id(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16 length;
    proto_item* ti;

    length = tvb_get_ntohs(tvb, offset + 1);

    ti = proto_tree_add_uint_format(tree, hf_gtp_ext_length, tvb, offset, 2, length, "%s length : %u",
                                  val_to_str_ext_const(GTP_EXT_TRIGGER_ID, &gtp_val_ext, "Unknown"), length);
    proto_item_set_len(ti, 3 + length);

    return 3 + length;

}

/* GPRS:        not present
 * UMTS:        29.060 v4.0, chapter 7.7.42
 * TODO:        find OMC-ID description
 */
static int
decode_gtp_omc_id(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16 length;
    proto_item* ti;

    length = tvb_get_ntohs(tvb, offset + 1);

    ti = proto_tree_add_uint_format(tree, hf_gtp_ext_length, tvb, offset, 2, length, "%s length : %u",
                                  val_to_str_ext_const(GTP_EXT_OMC_ID, &gtp_val_ext, "Unknown"), length);
    proto_item_set_len(ti, 3 + length);

    return 3 + length;

}

/* GPRS:        9.60 v7.6.0, chapter 7.9.25
 * UMTS:        29.060 v6.11.0, chapter 7.7.44 Charging Gateway Address
 */
static int
decode_gtp_chrg_addr(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16            length;
    proto_tree        *ext_tree_chrg_addr;
    proto_item        *te;

    length = tvb_get_ntohs(tvb, offset + 1);

    ext_tree_chrg_addr = proto_tree_add_subtree_format(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_CHRG_ADDR], &te,
                                    "%s : ", val_to_str_ext_const(GTP_EXT_CHRG_ADDR, &gtp_val_ext, "Unknown"));

    proto_tree_add_uint_format(ext_tree_chrg_addr, hf_gtp_ext_length, tvb, offset + 1, 2, length,
                                    "%s length : %u", val_to_str_ext_const(GTP_EXT_CHRG_ADDR, &gtp_val_ext, "Unknown"), length);

    switch (length) {
    case 4:
        proto_tree_add_item(ext_tree_chrg_addr, hf_gtp_chrg_ipv4, tvb, offset + 3, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(te, "%s", tvb_ip_to_str(pinfo->pool, tvb, offset + 3));
        break;
    case 16:
        proto_tree_add_item(ext_tree_chrg_addr, hf_gtp_chrg_ipv6, tvb, offset + 3, 16, ENC_NA);
        proto_item_append_text(te, "%s", tvb_ip6_to_str(pinfo->pool, tvb, offset + 3));
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
static int
decode_gtp_ran_tr_cont(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;
    tvbuff_t   *next_tvb;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree_format(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_RAN_TR_CONT], NULL,
                        "%s : ", val_to_str_ext_const(GTP_EXT_RAN_TR_CONT, &gtp_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    next_tvb = tvb_new_subset_length(tvb, offset, length);
    if (bssgp_handle) {
#if 0
        col_set_fence(pinfo->cinfo, COL_INFO);
#endif
        call_dissector(bssgp_handle, next_tvb, pinfo, ext_tree);
    }

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.45 PDP Context Prioritization
 */
static int
decode_gtp_pdp_cont_prio(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree_format(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_PDP_CONT_PRIO], NULL,
                        "%s : ", val_to_str_ext_const(GTP_EXT_PDP_CONT_PRIO, &gtp_val_ext, "Unknown"));

    if (length == 0) {
        return 3;
    }

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* TODO add decoding of data */
    proto_tree_add_expert(ext_tree, pinfo, &ei_gtp_undecoded, tvb, offset, length);

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.45A Additional RAB Setup Information
 */
static int
decode_gtp_add_rab_setup_inf(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree_format(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_ADD_RAB_SETUP_INF], NULL,
                    "%s : ", val_to_str_ext_const(GTP_EXT_ADD_RAB_SETUP_INF, &gtp_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    proto_tree_add_item(ext_tree, hf_gtp_nsapi, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (length == 1)
        return 3 + length;

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_teid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (length == 9) {
        /* RNC IP address IPv4*/
        proto_tree_add_item(ext_tree, hf_gtp_rnc_ip_addr_v4, tvb, offset, 4, ENC_BIG_ENDIAN);
    } else {
        /* RNC IP address IPv6*/
        proto_tree_add_item(ext_tree, hf_gtp_rnc_ip_addr_v6, tvb, offset, 16, ENC_NA);
    }


    return 3 + length;

}


 /* GPRS:       ?
  * UMTS:       29.060 v6.11.0, chapter 7.7.47 SGSN Number
  */
static int
decode_gtp_sgsn_no(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;
    tvbuff_t   *new_tvb;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree_format(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_SGSN_NO], NULL,
                    "%s", val_to_str_ext_const(GTP_EXT_SGSN_NO, &gtp_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    new_tvb = tvb_new_subset_length(tvb, offset, length);
    dissect_gsm_map_msisdn(new_tvb, pinfo, ext_tree);

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        3GPP TS 29.060 version 7.8.0 Release 7, chapter 7.7.48 Common Flags
 */
static int
decode_gtp_common_flgs(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree_format(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_COMMON_FLGS], NULL,
                "%s : ", val_to_str_ext_const(GTP_EXT_COMMON_FLGS, &gtp_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length,                   tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* Dual Address Bearer Flag */
    proto_tree_add_item(ext_tree, hf_gtp_cmn_flg_dual_addr_bearer_flg, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* Upgrade QoS Supported */
    proto_tree_add_item(ext_tree, hf_gtp_cmn_flg_upgrd_qos_sup,        tvb, offset, 1, ENC_BIG_ENDIAN);
    /* NRSN bit field */
    proto_tree_add_item(ext_tree, hf_gtp_cmn_flg_nrsn,                 tvb, offset, 1, ENC_BIG_ENDIAN);
    /* No QoS negotiation */
    proto_tree_add_item(ext_tree, hf_gtp_cmn_flg_no_qos_neg,           tvb, offset, 1, ENC_BIG_ENDIAN);
    /* MBMS Counting Information bi */
    proto_tree_add_item(ext_tree, hf_gtp_cmn_flg_mbs_cnt_inf,          tvb, offset, 1, ENC_BIG_ENDIAN);
    /* RAN Procedures Ready */
    proto_tree_add_item(ext_tree, hf_gtp_cmn_flg_mbs_ran_pcd_rdy,      tvb, offset, 1, ENC_BIG_ENDIAN);
    /* MBMS Service Type */
    proto_tree_add_item(ext_tree, hf_gtp_cmn_flg_mbs_srv_type,         tvb, offset, 1, ENC_BIG_ENDIAN);
    /* Prohibit Payload Compression */
    proto_tree_add_item(ext_tree, hf_gtp_cmn_flg_ppc,                  tvb, offset, 1, ENC_BIG_ENDIAN);

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.49
 */
static int
decode_gtp_apn_res(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree_apn_res;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree_apn_res = proto_tree_add_subtree_format(tree, tvb, offset, 3 + length,  ett_gtp_ies[GTP_EXT_APN_RES], NULL,
                "%s : ", val_to_str_ext_const(GTP_EXT_APN_RES, &gtp_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree_apn_res, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    /* Restriction Type value */
    if (length != 1) {
        proto_tree_add_expert_format(tree, pinfo, &ei_gtp_ext_length_mal, tvb, 0, length, "Wrong length indicated. Expected 1, got %u", length);
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

static int
decode_gtp_rat_type(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree_rat_type;
    proto_item *te;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree_rat_type = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_RAT_TYPE], &te,
                        val_to_str_ext_const(GTP_EXT_RAT_TYPE, &gtp_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree_rat_type, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    /* RAT Type value */
    if (length != 1) {
        proto_tree_add_expert_format(tree, pinfo, &ei_gtp_ext_length_mal, tvb, 0, length, "Wrong length indicated. Expected 1, got %u", length);
        return 3 + length;
    }

   proto_tree_add_item(ext_tree_rat_type, hf_gtp_ext_rat_type, tvb, offset, length, ENC_BIG_ENDIAN);
   proto_item_append_text(te, ": %s", val_to_str_const(tvb_get_guint8(tvb,offset), gtp_ext_rat_type_vals, "Unknown"));

   return 3 + length;
}

/*
 * 7.7.51 User Location Information
 */

void
dissect_gtp_uli(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_)
{
    guint8      geo_loc_type;
    proto_item* ti;

    /* Geographic Location Type */
    geo_loc_type = tvb_get_guint8(tvb, offset);
    ti = proto_tree_add_uint(tree, hf_gtp_uli_geo_loc_type, tvb, offset, 1, geo_loc_type);

    offset++;

    switch(geo_loc_type) {
        case 0:
            /* Geographic Location field included and it holds the Cell Global
             * Identification (CGI) of where the user currently is registered.
             * CGI is defined in sub-clause 4.3.1 of 3GPP TS 23.003 [2].
             */
            dissect_e212_mcc_mnc(tvb, pinfo, tree, offset, E212_CGI, TRUE);
            offset+=3;
            proto_tree_add_item(tree, hf_gtp_lac, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset+=2;
            /* The CI is of fixed length with 2 octets and it can be coded using a full hexadecimal representation */
            proto_tree_add_item(tree, hf_gtp_cgi_ci, tvb, offset, 2, ENC_BIG_ENDIAN);
            break;
        case 1:
            /* Geographic Location field included and it holds the Service
             * Area Identity (SAI) of where the user currently is registered.
             * SAI is defined in sub-clause 9.2.3.9 of 3GPP TS 25.413 [7].
             */
            dissect_e212_mcc_mnc(tvb, pinfo, tree, offset, E212_SAI, TRUE);
            offset+=3;
            proto_tree_add_item(tree, hf_gtp_lac, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_gtp_sai_sac, tvb, offset, 2, ENC_BIG_ENDIAN);
            break;
        case 2:
            /* Geographic Location field included and it holds the Routing
             * Area Identification (RAI) of where the user currently is
             * registered. RAI is defined in sub-clause 4.2 of 3GPP TS 23.003
             * [2].
             *
             * The routing area code consists of 2 octets and is found in octet
             * 10 and octet 11. Only the first octet (10) contains the RAC and
             * the second octet (11) is coded as "11111111".
             */
            dissect_e212_mcc_mnc(tvb, pinfo, tree, offset, E212_RAI, TRUE);
            offset+=3;
            proto_tree_add_item(tree, hf_gtp_lac, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset+=2;
            proto_tree_add_item(tree, hf_gtp_rai_rac, tvb, offset, 1, ENC_BIG_ENDIAN);
            break;
        default:
            expert_add_info(pinfo, ti, &ei_gtp_ext_geo_loc_type);
            break;
    }
}

static int
decode_gtp_usr_loc_inf(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_USR_LOC_INF], NULL,
                val_to_str_ext_const(GTP_EXT_USR_LOC_INF, &gtp_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    dissect_gtp_uli(tvb, offset, pinfo, ext_tree, args);

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
static int
decode_gtp_ms_time_zone(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;
    proto_item *te;
    guint8      data;
    char        sign;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree_format(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_MS_TIME_ZONE], &te,
                    "%s: ", val_to_str_ext_const(GTP_EXT_MS_TIME_ZONE, &gtp_val_ext, "Unknown"));

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

    proto_tree_add_uint_format_value(ext_tree, hf_gtp_timezone, tvb, offset, 1, data, "GMT %c %d hours %d minutes", sign, data / 4, data % 4 * 15);
    proto_item_append_text(te, "GMT %c %d hours %d minutes", sign, data / 4, data % 4 * 15);
    offset++;

    proto_tree_add_item(ext_tree, hf_gtp_timezone_dst, tvb, offset, 1, ENC_NA);

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.53
 * International Mobile Equipment Identity (and Software Version) (IMEI(SV))
 * Type = 154 (Decimal)
 */
static int
decode_gtp_imeisv(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_imeisv;
    proto_item *te;
    tvbuff_t   *next_tvb;
    char       *digit_str;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_imeisv = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_IMEISV], &te,
                        val_to_str_ext_const(GTP_EXT_IMEISV, &gtp_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_imeisv, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    /* IMEI(SV)
     * The structure of the IMEI and IMEISV are defined in sub-clause 6.2 of 3GPP TS 23.003 [2].
     * The 'IMEI(SV)' field shall contain the IMEISV if it is available. If only the IMEI is available,
     * then the IMEI shall be placed in the IMEI(SV) field and the last semi-octet of octet 11 shall be
     * set to '1111'. Both IMEI and IMEISV are BCD encoded.
     */
    next_tvb = tvb_new_subset_length(tvb, offset, length);
    proto_tree_add_item_ret_display_string(ext_imeisv, hf_gtp_ext_imeisv, next_tvb, 0, -1, ENC_BCD_DIGITS_0_9, wmem_packet_scope(), &digit_str);
    proto_item_append_text(te, ": %s", digit_str);

    return 3 + length;
}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.54
 * CAMEL Charging Information Container
 * Type = 155 (Decimal)
 */
static int
decode_gtp_camel_chg_inf_con(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_CAMEL_CHG_INF_CON], NULL,
                    val_to_str_ext_const(GTP_EXT_CAMEL_CHG_INF_CON, &gtp_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    dissect_gprscdr_CAMELInformationPDP_PDU(tvb_new_subset_length(tvb, offset, length), pinfo, ext_tree, NULL);

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.55
 * MBMS UE Context
 */
static int
decode_gtp_mbms_ue_ctx(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;
    guint8      enh_nsapi, trans_id;
    guint32     pdp_type_num, pdp_addr_len, ggsn_addr_len, apn_len;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_MBMS_UE_CTX], NULL,
                val_to_str_ext_const(GTP_EXT_MBMS_UE_CTX, &gtp_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    proto_tree_add_item(ext_tree, hf_gtp_linked_nsapi, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_uplink_teid_cp, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    enh_nsapi = tvb_get_guint8(tvb, offset);
    if (enh_nsapi < 128) {
        proto_tree_add_uint_format_value(ext_tree, hf_gtp_enh_nsapi, tvb, offset, 1, enh_nsapi, "Reserved");
    } else {
        proto_tree_add_item(ext_tree, hf_gtp_enh_nsapi, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_pdp_organization, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item_ret_uint(ext_tree, hf_gtp_pdp_type, tvb, offset, 1, ENC_BIG_ENDIAN, &pdp_type_num);
    offset++;
    proto_tree_add_item_ret_uint(ext_tree, hf_gtp_pdp_address_length, tvb, offset, 1, ENC_BIG_ENDIAN, &pdp_addr_len);
    offset++;
    if (pdp_addr_len > 0) {
        switch (pdp_type_num) {
        case 0x21:
            proto_tree_add_item(ext_tree, hf_gtp_pdp_address_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
            break;
        case 0x57:
            proto_tree_add_item(ext_tree, hf_gtp_pdp_address_ipv6, tvb, offset, 16, ENC_NA);
            break;
        default:
            break;
        }
        offset += pdp_addr_len;
    }
    proto_tree_add_item_ret_uint(ext_tree, hf_gtp_ggsn_address_length, tvb, offset, 1, ENC_BIG_ENDIAN, &ggsn_addr_len);
    offset++;

    switch (ggsn_addr_len) {
    case 4:
        proto_tree_add_item(ext_tree, hf_gtp_ggsn_address_for_control_plane_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        break;
    case 16:
        proto_tree_add_item(ext_tree, hf_gtp_ggsn_address_for_control_plane_ipv6, tvb, offset, 16, ENC_NA);
        break;
    default:
        /* XXX: Expert info? */
        break;
    }
    offset += ggsn_addr_len;

    proto_tree_add_item_ret_uint(ext_tree, hf_gtp_apn_length, tvb, offset, 1, ENC_BIG_ENDIAN, &apn_len);
    offset++;
    decode_apn(tvb, offset, apn_len, ext_tree, NULL);
    offset += apn_len;
    /*
     * The Transaction Identifier is the 4 or 12 bit Transaction Identifier used in the 3GPP TS 24.008 [5] Session Management
     * messages which control this PDP Context. If the length of the Transaction Identifier is 4 bit, the second octet shall be
     * set to all zeros. The encoding is defined in 3GPP TS 24.007 [3]. The latest Transaction Identifier sent from SGSN to
     * MS is stored in the MBMS context IE.
     * NOTE: Bit 5-8 of the first octet in the encoding defined in 3GPP TS 24.007 [3] is mapped into bit 1-4 of the first
     * octet in this field.
     */
    trans_id = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(ext_tree, hf_gtp_transaction_identifier, tvb, offset, 2, trans_id);

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        3GPP TS 29.060 version 7.8.0 Release 7, chapter 7.7.56
 * Temporary Mobile Group Identity (TMGI)
 * The Temporary Mobile Group Identity (TMGI) information element contains
 * a TMGI allocated by the BM-SC. It is coded as in the value part defined
 * in 3GPP T S 24.008 [5] (i.e. the IEI and octet length indicator are not included).
 */

static int
decode_gtp_tmgi(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree, *tmgi_tree;
    proto_item *ti;
    tvbuff_t   *next_tvb;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_TMGI], NULL,
                val_to_str_ext_const(GTP_EXT_TMGI, &gtp_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    ti = proto_tree_add_item(ext_tree, hf_gtp_tmgi, tvb, offset, length, ENC_NA);

    tmgi_tree = proto_item_add_subtree(ti, ett_gtp_tmgi);
    next_tvb = tvb_new_subset_length(tvb, offset, length);
    de_mid(next_tvb, tmgi_tree, pinfo, 0, length, NULL, 0);
    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.57
 * RIM Routing Address
 */
static int
decode_gtp_rim_ra(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_RIM_RA], NULL,
                            val_to_str_ext_const(GTP_EXT_RIM_RA, &gtp_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* To dissect the Address the Routing Address discriminator must be known */
    /*
     * Octets 4-n are coded according to 3GPP TS 48.018 [20] 11.3.77 RIM Routing Information IE octets 4-n.
     */
    proto_tree_add_item(ext_tree, hf_gtp_rim_routing_addr, tvb, offset, length, ENC_NA);

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.58
 * MBMS Protocol Configuration Options
 */
static int
decode_gtp_mbms_prot_conf_opt(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;
    tvbuff_t   *next_tvb;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_MBMS_PROT_CONF_OPT], NULL,
                    val_to_str_ext_const(GTP_EXT_MBMS_PROT_CONF_OPT, &gtp_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* The MBMS Protocol Configuration Options contains protocol options
     * associated with an MBMS context, that may be necessary to transfer
     * between the GGSN and the MS. The content and the coding of the MBMS
     * Protocol Configuration Options are defined in octets 3-z of the MBMS
     * Protocol Configuration Options in 3GPP TS 24.008 [5].
     */
    next_tvb = tvb_new_subset_length(tvb, offset, length);
    de_sm_mbms_prot_conf_opt(next_tvb, ext_tree, pinfo, 0, length, NULL, 0);

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        3GPP TS 29.060 version 7.8.0 Release 7, chapter 7.7.59
 * MBMS Session Duration
 */
/* Used for Diameter */
static int
dissect_gtp_mbms_ses_dur(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree, void *data _U_)
{

    int offset = 0;

    proto_tree_add_item(tree, hf_gtp_mbms_ses_dur_days, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gtp_mbms_ses_dur_s,    tvb, offset, 3, ENC_BIG_ENDIAN);

    return 3;

}

static int
decode_gtp_mbms_ses_dur(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_MBMS_SES_DUR], NULL,
                val_to_str_ext_const(GTP_EXT_MBMS_SES_DUR, &gtp_val_ext, "Unknown"));

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
    proto_tree_add_item(ext_tree, hf_gtp_mbms_ses_dur_days, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree, hf_gtp_mbms_ses_dur_s, tvb, offset, 3, ENC_BIG_ENDIAN);

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        3GPP TS 29.060 version 7.8.0 Release 7, chapter 7.7.60
 * MBMS Service Area
 */
static int
dissect_gtp_3gpp_mbms_service_area(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_) {

    int    offset = 0;
    guint8 no_of_mbms_sa_codes;
    int    i;

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

static int
decode_gtp_mbms_sa(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_)
{

    tvbuff_t   *next_tvb;
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_MBMS_SA], NULL,
                val_to_str_ext_const(GTP_EXT_MBMS_SA, &gtp_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    next_tvb = tvb_new_subset_length(tvb, offset, length-3);
    dissect_gtp_3gpp_mbms_service_area(next_tvb, pinfo, ext_tree, NULL);

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.61
 * Source RNC PDCP context info
 */
static int
decode_gtp_src_rnc_pdp_ctx_inf(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree, *sub_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_SRC_RNC_PDP_CTX_INF], NULL,
                    val_to_str_ext_const(GTP_EXT_SRC_RNC_PDP_CTX_INF, &gtp_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    sub_tree = proto_tree_add_subtree(ext_tree, tvb, offset, length, ett_gtp_rrc_cont, NULL, "Source RNC to Target RNC Transparent Container");
    dissect_rrc_ToTargetRNC_Container_PDU(tvb, pinfo, sub_tree, NULL);

    return 3 + length;
}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.62
 * Additional Trace Info
 */
static const true_false_string gtp_trace_tfs = {
  "Should be traced",
  "Should not be traced",
};

static const value_string gtp_trace_depth_vals[] = {
  { 0, "minimum" },
  { 1, "medium" },
  { 2, "maximum" },
  { 3, "minimumWithoutVendorSpecificExtension" },
  { 4, "mediumWithoutVendorSpecificExtension" },
  { 5, "maximumWithoutVendorSpecificExtension" },
  { 0, NULL }
};

static const value_string gtp_trace_activity_control_vals[] = {
  { 0, "Trace Deactivation"},
  { 1, "Trace Activation"},
  { 0, NULL}
};

static int
decode_gtp_add_trs_inf(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;

    static int * const trigger_flags[] = {
        &hf_gtp_trace_triggers_ggsn_mbms,
        &hf_gtp_trace_triggers_ggsn_pdp,
        NULL
    };

    static int * const loi_flags[] = {
        &hf_gtp_trace_loi_ggsn_gmb,
        &hf_gtp_trace_loi_ggsn_gi,
        &hf_gtp_trace_loi_ggsn_gn,
        NULL
    };

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_ADD_TRS_INF], NULL,
                    val_to_str_ext_const(GTP_EXT_ADD_TRS_INF, &gtp_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    proto_tree_add_item(ext_tree, hf_gtp_trace_ref2, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;
    proto_tree_add_item(ext_tree, hf_gtp_trace_rec_session_ref, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask(ext_tree, tvb, offset, hf_gtp_trace_triggers_ggsn, ett_gtp_trace_triggers_ggsn, trigger_flags, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_trace_depth, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_bitmask(ext_tree, tvb, offset, hf_gtp_trace_loi_ggsn, ett_gtp_trace_loi_ggsn, loi_flags, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_trace_activity_control, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.63
 * Hop Counter
 */
static int
decode_gtp_hop_count(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_HOP_COUNT], NULL,
                val_to_str_ext_const(GTP_EXT_HOP_COUNT, &gtp_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    proto_tree_add_item(ext_tree, hf_gtp_hop_count, tvb, offset, 1, ENC_NA);

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.64
 * Selected PLMN ID
 */
static int
decode_gtp_sel_plmn_id(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_MBMS_SES_ID], NULL,
                                val_to_str_ext_const(GTP_EXT_SEL_PLMN_ID, &gtp_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    dissect_e212_mcc_mnc(tvb, pinfo, ext_tree, offset, E212_NONE, FALSE);
    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.65
 * MBMS Session Identifier
 */
static int
decode_gtp_mbms_ses_id(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_MBMS_SES_ID], NULL, val_to_str_ext_const(GTP_EXT_MBMS_SES_ID, &gtp_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* TODO add decoding of data */
    proto_tree_add_expert(ext_tree, pinfo, &ei_gtp_undecoded, tvb, offset, length);

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

static int
decode_gtp_mbms_2g_3g_ind(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_MBMS_2G_3G_IND], NULL,
                val_to_str_ext_const(GTP_EXT_MBMS_2G_3G_IND, &gtp_val_ext, "Unknown"));

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
static int
decode_gtp_enh_nsapi(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;
    guint8      enh_nsapi;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_ENH_NSAPI], NULL, val_to_str_ext_const(GTP_EXT_ENH_NSAPI, &gtpv1_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    enh_nsapi = tvb_get_guint8(tvb, offset);
    if (enh_nsapi < 128) {
        proto_tree_add_uint_format_value(ext_tree, hf_gtp_enh_nsapi, tvb, offset, 1, enh_nsapi, "Reserved");
    } else {
        proto_tree_add_item(ext_tree, hf_gtp_enh_nsapi, tvb, offset, 1, ENC_BIG_ENDIAN);
    }

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.68
 * Additional MBMS Trace Info
 */
static int
decode_gtp_add_mbms_trs_inf(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;

    static int * const trigger_flags[] = {
        &hf_gtp_trace_triggers_bm_sc_mbms,
        NULL
    };

    static int * const loi_flags[] = {
        &hf_gtp_trace_loi_bm_sc_gmb,
        NULL
    };

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_ADD_MBMS_TRS_INF], NULL,
                            val_to_str_ext_const(GTP_EXT_ADD_MBMS_TRS_INF, &gtpv1_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* XXX: There is clearly an error in TS 29.060 V17.1.0 and earlier.
     * In Figure 7.7.68.1 the octet column has a gap and is not aligned,
     * octets 7-8 should be for the Trace Recording Session Reference, other
     * values should be moved up a row, and there should be a value for
     * the Trace Activity Control as octet 12, making the IE length 9,
     * as with 7.7.62 Additional Trace Info.
     * Unfortunately the mistake is carried over into the the length field
     * elsewhere in the spec, such as in Table 37.
     */
    proto_tree_add_item(ext_tree, hf_gtp_trace_ref2, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;
    proto_tree_add_item(ext_tree, hf_gtp_trace_rec_session_ref, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_bitmask(ext_tree, tvb, offset, hf_gtp_trace_triggers_bm_sc, ett_gtp_trace_triggers_bm_sc, trigger_flags, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_trace_depth, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_bitmask(ext_tree, tvb, offset, hf_gtp_trace_loi_bm_sc, ett_gtp_trace_loi_bm_sc, loi_flags, ENC_BIG_ENDIAN);
    if(length > 8){
        offset++;
        proto_tree_add_item(ext_tree, hf_gtp_trace_activity_control, tvb, offset, 1, ENC_BIG_ENDIAN);
    }

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.69
 * MBMS Session Identity Repetition Number
 */
static int
decode_gtp_mbms_ses_id_rep_no(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_MBMS_SES_ID_REP_NO], NULL,
                                        val_to_str_ext_const(GTP_EXT_MBMS_SES_ID_REP_NO, &gtpv1_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* TODO add decoding of data */
    proto_tree_add_expert(ext_tree, pinfo, &ei_gtp_undecoded, tvb, offset, length);

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        3GPP TS 29.060 version 7.8.0 Release 7
 * MBMS Time To Data Transfer
 */
/* Used for Diameter */
static int
dissect_gtp_mbms_time_to_data_tr(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree, void *data _U_)
{

    int    offset = 0;
    guint8 time_2_dta_tr;

    time_2_dta_tr = tvb_get_guint8(tvb, offset) + 1;
    proto_tree_add_uint(tree, hf_gtp_time_2_dta_tr, tvb, offset, 1, time_2_dta_tr);

    return 3;

}

static int
decode_gtp_mbms_time_to_data_tr(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;
    guint8      time_2_dta_tr;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_MBMS_TIME_TO_DATA_TR], NULL,
                        val_to_str_ext_const(GTP_EXT_MBMS_TIME_TO_DATA_TR, &gtpv1_val_ext, "Unknown"));

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
decode_gtp_ps_ho_req_ctx(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_PS_HO_REQ_CTX], NULL,
                val_to_str_ext_const(GTP_EXT_PS_HO_REQ_CTX, &gtpv1_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;
    /* TODO add decoding of data */
    proto_tree_add_expert(ext_tree, pinfo, &ei_gtp_undecoded, tvb, offset, length);

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.72
 * BSS Container
 */
static int
decode_gtp_bss_cont(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree, *sub_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_BSS_CONT], NULL,
                    val_to_str_ext_const(GTP_EXT_BSS_CONT, &gtpv1_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    switch (pinfo->link_dir) {
    case P2P_DIR_UL:
        sub_tree = proto_tree_add_subtree(ext_tree, tvb, offset, length, ett_gtp_bss_cont, NULL, "Source BSS to Target BSS Transparent Container");
        de_bssgp_source_BSS_to_target_BSS_transp_cont(tvb, sub_tree, pinfo, offset, length, NULL, 0);
        break;
    case P2P_DIR_DL:
        sub_tree = proto_tree_add_subtree(ext_tree, tvb, offset, length, ett_gtp_bss_cont, NULL, "Target BSS to Source BSS Transparent Container");
        de_bssgp_target_BSS_to_source_BSS_transp_cont(tvb, sub_tree, pinfo, offset, length, NULL, 0);
        break;
    default:
        break;
    }
    /*
     * The content of this container is defined in 3GPP TS 48.018
     */

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.73
 * Cell Identification
 */
static const value_string gtp_source_type_vals[] = {
    { 0, "Source Cell ID"},
    { 1, "Source RNC-ID" },
    { 0, NULL            }
};

static int
decode_gtp_cell_id(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    guint32     source_type;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_CELL_ID], NULL,
                                val_to_str_ext_const(GTP_EXT_CELL_ID, &gtpv1_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    /*
     * for PS handover from A/Gb mode, the identification of a target cell (Cell ID 1) and the identification of the
     * source cell (Cell ID 2) as defined in 3GPP TS 48.018 [20].
     *
     * for PS handover from Iu mode, the identification of a target cell (Cell ID 1)) and the identification of the
     * source RNC (RNC-ID) as defined in 3GPP TS 48.018
     *
     * for PS handover from S1 mode, the identification of a target cell (Target Cell ID) as defined in 3GPP TS 48.018.
     * Octet 12 shall be set to "Source Cell ID" and octets 13-20 shall be encoded as all zero.
     *
     * 3GPP TS 48.018 defines Target and Source Cell ID to use the Cell
     * Identifier IE, encoded as 6 octets of the value part of the RAI IE
     * followed by 2 octets of the value of the Cell Identity IE, both defined
     * in 3GPP TS 24.008. The 3GPP TS 48.018 RNC-ID IE is similar, with the 6
     * octet RAI as in 3GPP TS 24.008 followed by two octets of the RNC-ID.
     * (Or Extended RNC-ID, but the RNC-ID is presented in network byte order
     * with the most significant bits of octet 9 set to "0000", so there is
     * no need to distinguish be RNC-ID and Extended RNC-ID.)
     */
    dissect_e212_mcc_mnc(tvb, pinfo, ext_tree, offset, E212_NONE, TRUE);
    offset += 3;
    proto_tree_add_item(ext_tree, hf_gtp_target_lac, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ext_tree, hf_gtp_target_rac, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ext_tree, hf_gtp_target_ci, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item_ret_uint(ext_tree, hf_gtp_source_type, tvb, offset, 1, ENC_NA, &source_type);
    offset++;
    switch (source_type) {
    case 0:
        dissect_e212_mcc_mnc(tvb, pinfo, ext_tree, offset, E212_NONE, TRUE);
        offset += 3;
        proto_tree_add_item(ext_tree, hf_gtp_source_lac, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(ext_tree, hf_gtp_source_rac, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(ext_tree, hf_gtp_source_ci, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 1:
        dissect_e212_mcc_mnc(tvb, pinfo, ext_tree, offset, E212_NONE, TRUE);
        offset += 3;
        proto_tree_add_item(ext_tree, hf_gtp_source_lac, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(ext_tree, hf_gtp_source_rac, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(ext_tree, hf_gtp_source_rnc_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    default:
        proto_tree_add_expert(ext_tree, pinfo, &ei_gtp_source_type_unknown, tvb, offset-1, 1);
        break;
    }

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.74
 * PDU Numbers
 */
static int
decode_gtp_pdu_no(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_PDU_NO], NULL,
                                            val_to_str_ext_const(GTP_EXT_PDU_NO, &gtpv1_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    proto_tree_add_item(ext_tree, hf_gtp_nsapi, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(ext_tree, hf_gtp_sequence_number_down, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ext_tree, hf_gtp_sequence_number_up, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    /* The Send N-PDU Number is used only when acknowledged peer-to-peer LLC
     * operation is used for the PDP context.  Send N-PDU Number is the N-PDU
     * number to be assigned by SNDCP to the next down link N-PDU received from
     * the GGSN.
     *
     * The Receive N-PDU Number is used only when acknowledged peer-to-peer LLC
     * operation is used for the PDP context.  The Receive N-PDU Number is the
     * N-PDU number expected by SNDCP from the next up link N-PDU to be
     * received from the MS.
     *
     * XXX: For some reason, 2 octets are reserved for each the Send and
     * Receive N-PDU numbers, even though an N-PDU number in acknowledged
     * mode only has values 0-255 (see 3GPP TS 44.065) and is in a one
     * octet field in the PDP Context IE (7.7.29). Assume, in the lack
     * of other guidance, that the first octet will be zero and the value
     * will be in the second octet.
     * Cf. 7.7.51 ULI, where there is an explicit note in TS 29.060 that only
     * the first octet contains the RAC and the second octet is filler.
     */
    proto_tree_add_item(ext_tree, hf_gtp_send_n_pdu_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ext_tree, hf_gtp_receive_n_pdu_number, tvb, offset, 2, ENC_BIG_ENDIAN);

    return 3 + length;

}

/* GPRS:        ?
 * UMTS:        29.060 v6.11.0, chapter 7.7.75
 * BSSGP Cause
 */
static int
decode_gtp_bssgp_cause(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_BSSGP_CAUSE], NULL,
                                        val_to_str_ext_const(GTP_EXT_BSSGP_CAUSE, &gtpv1_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    /*
     * The BSSGP Cause information element contains the cause as defined in 3GPP TS 48.018
     */
    proto_tree_add_item(ext_tree, hf_gtp_bssgp_cause, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 3 + length;

}

/*
 * Required MBMS bearer capabilities    7.7.76
 */
static int
decode_gtp_mbms_bearer_cap(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_REQ_MBMS_BEARER_CAP], NULL,
                                    val_to_str_ext_const(GTP_EXT_REQ_MBMS_BEARER_CAP, &gtpv1_val_ext, "Unknown"));

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
    { 0, NULL }
};

static int
decode_gtp_rim_ra_disc(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_RIM_ROUTING_ADDR_DISC], NULL,
                                val_to_str_ext_const(GTP_EXT_RIM_ROUTING_ADDR_DISC, &gtpv1_val_ext, "Unknown"));

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
decode_gtp_lst_set_up_pfc(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree, *sub_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_LIST_OF_SETUP_PFCS], NULL,
                                        val_to_str_ext_const(GTP_EXT_LIST_OF_SETUP_PFCS, &gtpv1_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    sub_tree = proto_tree_add_subtree(ext_tree, tvb, offset, length, ett_gtp_lst_set_up_pfc, NULL, "List of set-up PFCs");
    de_bssgp_list_of_setup_pfcs(tvb, sub_tree, pinfo, offset, length, NULL, 0);

    return 3 + length;

}
/*
 * PS Handover XID Parameters   7.7.79
 */
static int
decode_gtp_ps_handover_xid(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;
    tvbuff_t   *next_tvb;
    guint8      sapi;
    guint8      xid_par_len;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_PS_HANDOVER_XIP_PAR], NULL,
                                        val_to_str_ext_const(GTP_EXT_PS_HANDOVER_XIP_PAR, &gtpv1_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    sapi = tvb_get_guint8(tvb, offset) & 0x0F;
    proto_tree_add_uint(ext_tree, hf_gtp_sapi, tvb, offset, 1, sapi);
    offset++;

    xid_par_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(ext_tree, hf_gtp_xid_par_len, tvb, offset, 1, xid_par_len);
    offset++;

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    if (sndcpxid_handle)
        call_dissector(sndcpxid_handle, next_tvb, pinfo, tree);
    else
        call_data_dissector(next_tvb, pinfo, tree);

    return 4 + length;

}

/*
 * MS Info Change Reporting Action      7.7.80
 */
static int
decode_gtp_ms_inf_chg_rep_act(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_MS_INF_CHG_REP_ACT], NULL,
                                        val_to_str_ext_const(GTP_EXT_MS_INF_CHG_REP_ACT, &gtpv1_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    proto_tree_add_item(ext_tree, hf_gtp_rep_act_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 3 + length;

}
/*
 * Direct Tunnel Flags  7.7.81
 */
static int
decode_gtp_direct_tnl_flg(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_DIRECT_TUNNEL_FLGS], NULL,
                                        val_to_str_ext_const(GTP_EXT_DIRECT_TUNNEL_FLGS, &gtpv1_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(ext_tree, hf_gtp_ext_ei,   tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree, hf_gtp_ext_gcsi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree, hf_gtp_ext_dti,  tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if (length == 1) {
        return 3 + length;
    }
    proto_tree_add_expert(ext_tree, pinfo, &ei_gtp_undecoded, tvb, offset, length);

    return 3 + length;

}
/*
 * Correlation-ID       7.7.82
 */
static int
decode_gtp_corrl_id(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_CORRELATION_ID], NULL,
                    val_to_str_ext_const(GTP_EXT_CORRELATION_ID, &gtpv1_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    proto_tree_add_item(ext_tree, hf_gtp_correlation_id,  tvb, offset, 1, ENC_BIG_ENDIAN);

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

static int
decode_gtp_bearer_cntrl_mod(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length,  ett_gtp_ies[GTP_EXT_BEARER_CONTROL_MODE], NULL,
                                        val_to_str_ext_const(GTP_EXT_BEARER_CONTROL_MODE, &gtpv1_val_ext, "Unknown"));

    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    proto_tree_add_item(ext_tree, hf_gtp_bcm, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 3 + length;

}

/*
 * 7.7.84 MBMS Flow Identifier
 */
static int
decode_gtp_mbms_flow_id(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_MBMS_FLOW_ID], NULL,
                                        val_to_str_ext_const(GTP_EXT_MBMS_FLOW_ID, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    /* 4-n MBMS Flow Identifier */
    proto_tree_add_item(ext_tree, hf_gtp_mbms_flow_id, tvb, offset, length, ENC_NA);


    return 3 + length;
}

/*
 * 7.7.85 MBMS IP Multicast Distribution
 */

static int
decode_gtp_mbms_ip_mcast_dist(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_MBMS_IP_MCAST_DIST], NULL,
                                    val_to_str_ext_const(GTP_EXT_MBMS_IP_MCAST_DIST, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    proto_tree_add_expert(ext_tree, pinfo, &ei_gtp_undecoded, tvb, offset, length);

    return 3 + length;
}

/*
 * 7.7.86 MBMS Distribution Acknowledgement
 */
/* Table 7.7.86.1: Distribution Indication values */
static const value_string gtp_mbms_dist_indic_vals[] = {
    {0, "No RNCs have accepted IP multicast distribution"},
    {1, "All RNCs have accepted IP multicast distribution"},
    {2, "Some RNCs have accepted IP multicast distribution"},
    {3, "Spare. For future use."},
    {0, NULL}
};
static int
decode_gtp_mbms_dist_ack(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_MBMS_DIST_ACK], NULL,
                                    val_to_str_ext_const(GTP_EXT_MBMS_DIST_ACK, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    /* Distribution Indication values */
    proto_tree_add_item(ext_tree, hf_gtp_mbms_dist_indic, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 3 + length;
}

/*
 * 7.7.87 Reliable INTER RAT HANDOVER INFO
 */
static int
decode_gtp_reliable_irat_ho_inf(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_RELIABLE_IRAT_HO_INF], NULL,
                                        val_to_str_ext_const(GTP_EXT_RELIABLE_IRAT_HO_INF, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    proto_tree_add_expert(ext_tree, pinfo, &ei_gtp_undecoded, tvb, offset, length);

    return 3 + length;
}

/*
 * 7.7.88 RFSP Index
 */
static int
decode_gtp_rfsp_index(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length, rfsp;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_RFSP_INDEX], NULL,
                                        val_to_str_ext_const(GTP_EXT_RFSP_INDEX, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    rfsp = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(ext_tree, hf_gtp_rfsp_index, tvb, offset, length, rfsp+1);

    return 3 + length;
}
/*
 * 7.7.89 PDP Type
 */
/*
 * 7.7.90 Fully Qualified Domain Name (FQDN)
 */
static int
decode_gtp_fqdn(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);

    ext_tree = proto_tree_add_subtree(tree, tvb, offset, length + 3, ett_gtp_ies[GTP_EXT_FQDN], NULL,
                                    val_to_str_ext_const(GTP_EXT_FQDN, &gtp_val_ext, "Unknown field"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(ext_tree, hf_gtp_fqdn_length, tvb, offset + 1, 2, ENC_BIG_ENDIAN);
    decode_fqdn(tvb, offset + 3, length, ext_tree, NULL);

    return 3 + length;
}

/*
 * 7.7.91 Evolved Allocation/Retention Priority I
 */
static int
decode_gtp_evolved_allc_rtn_p1(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_EVO_ALLO_RETE_P1], NULL,
                                        val_to_str_ext_const(GTP_EXT_EVO_ALLO_RETE_P1, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id,      tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(ext_tree, hf_gtp_earp_pci,   tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree, hf_gtp_earp_pl,    tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree, hf_gtp_earp_pvi,   tvb, offset, 1, ENC_BIG_ENDIAN);

    return 3 + length;


}

/*
 * 7.7.92 Evolved Allocation/Retention Priority II
 */
static int
decode_gtp_evolved_allc_rtn_p2(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_EVO_ALLO_RETE_P2], NULL,
                                        val_to_str_ext_const(GTP_EXT_EVO_ALLO_RETE_P2, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    proto_tree_add_item(ext_tree, hf_gtp_nsapi, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(ext_tree, hf_gtp_earp_pci, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree, hf_gtp_earp_pl,  tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree, hf_gtp_earp_pvi, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 3 + length;


}

/*
 * 7.7.93 Extended Common Flags
 */
static int
decode_gtp_extended_common_flgs(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_EXTENDED_COMMON_FLGS], NULL,
                                        val_to_str_ext_const(GTP_EXT_EXTENDED_COMMON_FLGS, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    proto_tree_add_item(ext_tree, hf_gtp_ext_comm_flags_uasi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree, hf_gtp_ext_comm_flags_bdwi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree, hf_gtp_ext_comm_flags_pcri, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree, hf_gtp_ext_comm_flags_vb, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree, hf_gtp_ext_comm_flags_retloc, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree, hf_gtp_ext_comm_flags_cpsr, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree, hf_gtp_ext_comm_flags_ccrsi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree, hf_gtp_ext_comm_flags_unauthenticated_imsi, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if(length > 1){
        proto_tree_add_expert(ext_tree, pinfo, &ei_gtp_undecoded, tvb, offset, length-1);
    }

    return 3 + length;
}

/*
 * 7.7.94 User CSG Information (UCI)
 */

static const value_string gtp_access_mode_vals[] = {
   { 0, "Closed Mode" },
   { 1, "Hybrid Mode" },
   { 2, "Reserved" },
   { 3, "Reserved" },
   { 0, NULL }
};

static int
decode_gtp_uci(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_UCI], NULL,
                                        val_to_str_ext_const(GTP_EXT_UCI, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    dissect_e212_mcc_mnc(tvb, pinfo, ext_tree, offset, E212_NONE, TRUE);
    offset += 3;
    proto_tree_add_item(ext_tree, hf_gtp_csg_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(ext_tree, hf_gtp_access_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* Due to a specification oversight, the CMI values ... are reversed from
     * the values of the CSG-Membership-Indication AVP in 3GPP TS 32.299 [56].
     * Therefore, when CMI values are sent over the charging interface, the
     * values are encoded as specified in 3GPP TS 32.299 [56]. Furthermore,
     * the encoding is different between GTPv1 and GTPv2.
     */
    proto_tree_add_item(ext_tree, hf_gtp_cmi, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 3 + length;
}

/*
 * 7.7.95 CSG Information Reporting Action
 */

static int
decode_gtp_csg_inf_rep_act(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    static int * const flags[] = {
        &hf_gtp_csg_inf_rep_act_uciuhc,
        &hf_gtp_csg_inf_rep_act_ucishc,
        &hf_gtp_csg_inf_rep_act_ucicsg,
        NULL
    };

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_CSG_INF_REP_ACT], NULL,
                                            val_to_str_ext_const(GTP_EXT_CSG_INF_REP_ACT, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id,      tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    proto_tree_add_bitmask_list(ext_tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return 3 + length;
}
/*
 * 7.7.96 CSG ID
 */

static int
decode_gtp_csg_id(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_CSG_ID], NULL,
                                            val_to_str_ext_const(GTP_EXT_CSG_ID, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    proto_tree_add_expert(ext_tree, pinfo, &ei_gtp_undecoded, tvb, offset, length);

    return 3 + length;
}
/*
 * 7.7.97 CSG Membership Indication (CMI)
 */
static int
decode_gtp_cmi(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_CMI], NULL,
                                        val_to_str_ext_const(GTP_EXT_CMI, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    /* Due to a specification oversight, the CMI values ... are reversed from
     * the values of the CSG-Membership-Indication AVP in 3GPP TS 32.299 [56].
     * Therefore, when CMI values are sent over the charging interface, the
     * values are encoded as specified in 3GPP TS 32.299 [56].
     */
    proto_tree_add_item(ext_tree, hf_gtp_cmi, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 3 + length;
}
/*
 * 7.7.98 APN Aggregate Maximum Bit Rate (APN-AMBR)
 */
static int
decode_gtp_apn_ambr(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_RELIABLE_IRAT_HO_INF], NULL,
                                        val_to_str_ext_const(GTP_EXT_AMBR, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    /* APN Aggregate Maximum Bit Rate (APN-AMBR) is defined in clause 9.9.4.2 of 3GPP TS 24.301 [42], but shall be
     * formatted as shown in Figure 7.7.98-1 as Unsigned32 binary integer values in kbps (1000 bits per second).
     */
    /* 4 to 7 APN-AMBR for Uplink */
    proto_tree_add_item(ext_tree, hf_gtp_ext_apn_ambr_ul, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;
    /* 8 to 11 APN-AMBR for Downlink */
    proto_tree_add_item(ext_tree, hf_gtp_ext_apn_ambr_dl, tvb, offset, 4, ENC_BIG_ENDIAN);

    return 3 + length;
}
/*
 * 7.7.99 UE Network Capability
 */
static int
decode_gtp_ue_network_cap(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_UE_NETWORK_CAP], NULL,
                                        val_to_str_ext_const(GTP_EXT_UE_NETWORK_CAP, &gtpv1_val_ext, "Unknown"));

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    de_emm_ue_net_cap(tvb, ext_tree, pinfo, offset, length, NULL, 0);

    return 3 + length;
}
/*
 * 7.7.100 UE-AMBR
 */

static int
decode_gtp_ue_ambr(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_APN_AMBR_WITH_NSAPI], NULL,
                                        val_to_str_ext_const(GTP_EXT_APN_AMBR_WITH_NSAPI, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    /* 4 to 7 Subscribed UE-AMBR for Uplink */
    proto_tree_add_item(ext_tree, hf_gtp_ext_sub_ue_ambr_ul, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;
    /* 8 to 11 Subscribed UE-AMBR for Downlink */
    proto_tree_add_item(ext_tree, hf_gtp_ext_sub_ue_ambr_dl, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* Authorized UE-AMBR for Uplink and Downlink fields are present in the IE only if the sender has their valid values
     * available. Otherwise, the fields from m to (n+3) shall not be present.
     */
    if(offset >= length)
        return 3 + length;

    /* m to (m+3) Authorized UE-AMBR for Uplink */
    proto_tree_add_item(ext_tree, hf_gtp_ext_auth_ue_ambr_ul, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* (m+4) to (n+3) Authorized UE-AMBR for Downlink */
    proto_tree_add_item(ext_tree, hf_gtp_ext_auth_ue_ambr_dl, tvb, offset, 4, ENC_BIG_ENDIAN);

    proto_tree_add_expert(ext_tree, pinfo, &ei_gtp_undecoded, tvb, offset, length);

    return 3 + length;
}

/*
 * 7.7.101 APN-AMBR with NSAPI
 */
static int
decode_gtp_apn_ambr_with_nsapi(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_UE_AMBR], NULL,
                                        val_to_str_ext_const(GTP_EXT_UE_AMBR, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    proto_tree_add_item(ext_tree, hf_gtp_nsapi, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    offset++;

    /* 5 to 8 Authorized APN-AMBR for Uplink */
    proto_tree_add_item(ext_tree, hf_gtp_ext_auth_apn_ambr_ul, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* 9 to12 Authorized APN-AMBR for Downlink */
    proto_tree_add_item(ext_tree, hf_gtp_ext_auth_apn_ambr_dl, tvb, offset, 4, ENC_BIG_ENDIAN);

    return 3 + length;
}
/*
 * 7.7.102 GGSN Back-Off Time
 */
/* Table 7.7.102.1: GGSN Back-Off Time information element */
static const value_string gtp_ggsn_back_off_time_units_vals[] = {
    {0, "value is incremented in multiples of 2 seconds"},
    {1, "value is incremented in multiples of 1 minute"},
    {2, "value is incremented in multiples of 10 minutes"},
    {3, "value is incremented in multiples of 1 hour"},
    {4, "value is incremented in multiples of 10 hours"},
    {5, "value indicates that the timer is infinite"},
    {0, NULL}
};
static int
decode_gtp_ggsn_back_off_time(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_GGSN_BACK_OFF_TIME], NULL,
                                        val_to_str_ext_const(GTP_EXT_GGSN_BACK_OFF_TIME, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* 4 Timer unit Timer value */
    proto_tree_add_item(ext_tree, hf_gtp_ext_ggsn_back_off_time_units, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree, hf_gtp_ext_ggsn_back_off_timer, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 3 + length;
}

/*
 * 7.7.103 Signalling Priority Indication
 */
static const true_false_string gtp_lapi_tfs = {
        "MS is configured for NAS signalling low priority",
        "MS is not configured for NAS signalling low priority"
};

static int
decode_gtp_sig_pri_ind(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_SIG_PRI_IND], NULL,
                                    val_to_str_ext_const(GTP_EXT_SIG_PRI_IND, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(ext_tree, hf_gtp_lapi, tvb, offset, 1, ENC_NA);

    return 3 + length;
}
/*
 * 7.7.104 Signalling Priority Indication with NSAPI
 */

static int
decode_gtp_sig_pri_ind_w_nsapi(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_SIG_PRI_IND_W_NSAPI], NULL,
                                            val_to_str_ext_const(GTP_EXT_SIG_PRI_IND_W_NSAPI, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(ext_tree, hf_gtp_nsapi, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(ext_tree, hf_gtp_lapi, tvb, offset, 1, ENC_NA);

    return 3 + length;
}
/*
 * 7.7.105 Higher bitrates than 16 Mbps flag
 */
static const value_string gtp_higher_br_16mb_flg_vals[] = {
    {0, "Not allowed"},
    {1, "Allowed"},
    {0, NULL}
};

static int
decode_gtp_higher_br_16mb_flg(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_HIGHER_BR_16MB_FLG], NULL,
                                          val_to_str_ext_const(GTP_EXT_HIGHER_BR_16MB_FLG, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Higher bitrates than 16 Mbps flag */
    proto_tree_add_item(ext_tree, hf_gtp_higher_br_16mb_flg, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 3 + length;
}
/*
 * 7.7.106 Max MBR/APN-AMBR
 */

static int
decode_gtp_max_mbr_apn_ambr(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;
    guint32     max_ul;
    guint32     max_dl;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_MAX_MBR_APN_AMBR], NULL,
                                    val_to_str_ext_const(GTP_EXT_MAX_MBR_APN_AMBR, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

        /* Max MBR/APN-AMBR for uplink */
    max_ul = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint_format_value(ext_tree, hf_gtp_max_mbr_apn_ambr_ul, tvb, offset, 4, max_ul, "%u %s",
                               (max_ul) > 1000 ? max_ul/1000 : max_ul,
                               (max_ul) > 1000 ? "Mbps" : "kbps");

    offset += 4;

    /* Max MBR/APN-AMBR for downlink */
    max_dl = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint_format_value(ext_tree, hf_gtp_max_mbr_apn_ambr_dl, tvb, offset, 4, max_dl, "%u %s",
                                (max_dl) > 1000 ? max_dl/1000 : max_dl,
                                (max_dl) > 1000 ? "Mbps" : "kbps");

    return 3 + length;
}
/*
 * 7.7.107 Additional MM context for SRVCC
 */

static int
decode_gtp_add_mm_ctx_srvcc(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;
    guint32 inf_len;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_ADD_MM_CTX_SRVCC], NULL,
                                        val_to_str_ext_const(GTP_EXT_ADD_MM_CTX_SRVCC, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Length of the Mobile Station Classmark 2 */
    proto_tree_add_item_ret_uint(ext_tree, hf_gtp_ms_cm_2_len, tvb, offset, 1, ENC_BIG_ENDIAN, &inf_len);
    offset++;
    if (inf_len > 0) {
        offset += de_ms_cm_2(tvb, ext_tree, pinfo, offset, inf_len, NULL, 0);
    }

    /* Length of the Mobile Station Classmark 3 */
    proto_tree_add_item_ret_uint(ext_tree, hf_gtp_ms_cm_3_len, tvb, offset, 1, ENC_BIG_ENDIAN, &inf_len);
    offset++;
    if (inf_len > 0) {
        offset += de_ms_cm_3(tvb, ext_tree, pinfo, offset, inf_len, NULL, 0);
    }

    /* Length of the Supported Codec List */
    proto_tree_add_item_ret_uint(ext_tree, hf_gtp_sup_codec_lst_len, tvb, offset, 1, ENC_BIG_ENDIAN, &inf_len);
    offset++;
    if (inf_len > 0) {
        de_sup_codec_list(tvb, ext_tree, pinfo, offset, inf_len, NULL, 0);
    }

    return 3 + length;
}

/*
 * 7.7.108 Additional flags for SRVCC
 */

static int
decode_gtp_add_flgs_srvcc(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_ADD_FLGS_SRVCC], NULL,
                                        val_to_str_ext_const(GTP_EXT_ADD_FLGS_SRVCC, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* 4    Spare ICS */
    proto_tree_add_item(ext_tree, hf_gtp_add_flg_for_srvcc_ics, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 3 + length;
}
/*
 * 7.7.109 STN-SR
 */
static int
decode_gtp_stn_sr(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_STN_SR], NULL,
                                        val_to_str_ext_const(GTP_EXT_STN_SR, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_expert(ext_tree, pinfo, &ei_gtp_undecoded, tvb, offset, length);

    return 3 + length;
}

/*
 * 7.7.110 C-MSISDN
 */

static int
decode_gtp_c_msisdn(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_C_MSISDN], NULL,
                                        val_to_str_ext_const(GTP_EXT_C_MSISDN, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    dissect_e164_msisdn(tvb, ext_tree, offset, length, E164_ENC_BCD);

    return 3 + length;
}
/*
 * 7.7.111 Extended RANAP Cause
 */
static int
decode_gtp_ext_ranap_cause(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;
    tvbuff_t *new_tvb;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_EXT_RANAP_CAUSE], NULL,
                                        val_to_str_ext_const(GTP_EXT_EXT_RANAP_CAUSE, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    new_tvb = tvb_new_subset_remaining(tvb, offset);

    dissect_ranap_Cause_PDU(new_tvb, pinfo, ext_tree, NULL);

    return 3 + length;
}

/*
 * 7.7.112 eNodeB ID
 */

static const value_string gtp_enb_type_vals[] = {
    { 0, "Macro eNodeB ID" },
    { 1, "Home eNodeB ID" },
    { 0, NULL }
};

static int
decode_gtp_ext_enodeb_id(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;
    guint32 enb_type;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_ENODEB_ID], NULL,
        val_to_str_ext_const(GTP_EXT_ENODEB_ID, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* eNodeB Type */
    proto_tree_add_item_ret_uint(ext_tree, hf_gtp_ext_enb_type, tvb, offset, 1, ENC_BIG_ENDIAN, &enb_type);
    offset++;

    dissect_e212_mcc_mnc(tvb, pinfo, ext_tree, offset, E212_NONE, TRUE);
    offset += 3;

    switch (enb_type){
    case 0:
        /* Macro eNodeB ID */
        proto_tree_add_item(ext_tree, hf_gtp_macro_enodeb_id, tvb, offset, 3, ENC_BIG_ENDIAN);
        offset += 3;
        proto_tree_add_item(ext_tree, hf_gtp_tac, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case 1:
        /* Home eNodeB ID */
        proto_tree_add_item(ext_tree, hf_gtp_home_enodeb_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(ext_tree, hf_gtp_tac, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    default:
        proto_tree_add_expert(ext_tree, pinfo, &ei_gtp_undecoded, tvb, offset, length - 4);
        break;
    }

    return 3 + length;
}

/*
 * 7.7.113 Selection Mode with NSAPI
 */

static const value_string gtp_sel_mode_vals[] = {
    { 0, "MS or network provided APN, subscription verified" },
    { 1, "MS provided APN, subscription not verified" },
    { 2, "Network provided APN, subscription not verified" },
    { 3, "For future use. Shall not be sent. If received, shall be interpreted as the value 2" },
    { 0, NULL }
};

static int
decode_gtp_ext_sel_mode_w_nsapi(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_SEL_MODE_W_NSAPI], NULL,
        val_to_str_ext_const(GTP_EXT_SEL_MODE_W_NSAPI, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(ext_tree, hf_gtp_nsapi, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(ext_tree, hf_gtp_sel_mode_val, tvb, offset, 1, ENC_BIG_ENDIAN);


    return 3 + length;
}
/*
 * 7.7.114 ULI Timestamp
 */
static int
decode_gtp_ext_uli_timestamp(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_ULI_TIMESTAMP], NULL,
        val_to_str_ext_const(GTP_EXT_ULI_TIMESTAMP, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(ext_tree, hf_gtp_uli_timestamp, tvb, offset, 4, ENC_TIME_SECS_NTP|ENC_BIG_ENDIAN);

    return 3 + length;
}

/*
 * 7.7.115 Local Home Network ID (LHN-ID) with NSAPI
 */
static int
decode_gtp_ext_lhn_id_w_sapi(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_LHN_ID_W_SAPI], NULL,
        val_to_str_ext_const(GTP_EXT_LHN_ID_W_SAPI, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ext_tree, hf_gtp_nsapi, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(ext_tree, hf_gtp_lhn_id, tvb, offset, length, ENC_APN_STR|ENC_NA);

    return 3 + length;
}
/*
 * 7.7.116 CN Operator Selection Entity
 */
static const value_string gtp_sel_entity_vals[] = {
    { 0, "The Serving Network has been selected by the UE"},
    { 1, "The Serving Network has been selected by the network"},
    { 2, "For future use"},
    { 3, "For future use"},
    { 0, NULL},
};

static int
decode_gtp_ext_cn_op_sel_entity(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_CN_OP_SEL_ENTITY], NULL,
        val_to_str_ext_const(GTP_EXT_CN_OP_SEL_ENTITY, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(ext_tree, hf_gtp_sel_entity, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if (length > 1) {
        proto_tree_add_expert(ext_tree, pinfo, &ei_gtp_undecoded, tvb, offset, length - 1);
    }
    return 3 + length;
}

/*
 * 7.7.117 UE Usage Type
 */
static int
decode_gtp_ue_usage_type(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_UE_USAGE_TYPE], NULL,
        val_to_str_ext_const(GTP_EXT_UE_USAGE_TYPE, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(ext_tree, hf_gtp_ue_usage_type_value, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (length > 4) {
        proto_tree_add_expert(ext_tree, pinfo, &ei_gtp_undecoded, tvb, offset, length - 4);
    }

    return 3 + length;
}

/*
 * 7.7.118 Extended Common Flags II
 */
static int
decode_gtp_extended_common_flgs_II(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_EXT_COMMON_FLGS_II], NULL,
                                        val_to_str_ext_const(GTP_EXT_EXT_COMMON_FLGS_II, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset = offset + 2;

    proto_tree_add_item(ext_tree, hf_gtp_ext_comm_flags_II_pnsi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree, hf_gtp_ext_comm_flags_II_dtci, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree, hf_gtp_ext_comm_flags_II_pmtsmi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree, hf_gtp_ext_comm_flags_II_spare, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    if(length > 1){
        proto_tree_add_expert(ext_tree, pinfo, &ei_gtp_undecoded, tvb, offset, length-1);
    }

    return 3 + length;
}

/*
 * 7.7.119 Node Identifier
 */
static int
decode_gtp_ext_node_id(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    guint32     item_len;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_NODE_IDENTIFIER], NULL,
        val_to_str_ext_const(GTP_EXT_NODE_IDENTIFIER, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* The Node Name and Node Realm are Diameter Identities, which are
     * specified by RFC 6733 to be in ASCII for compatibility with DNS.
     */
    proto_tree_add_item_ret_length(ext_tree, hf_gtp_node_name, tvb, offset, 1, ENC_ASCII | ENC_NA, &item_len);
    offset += item_len;
    proto_tree_add_item_ret_length(ext_tree, hf_gtp_node_realm, tvb, offset, 1, ENC_ASCII | ENC_NA, &item_len);

    return 3 + length;
}

/*
 * 7.7.120 CIoT Optimizations Support Indication
 */
static int
decode_gtp_ciot_opt_sup_ind(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_CIOT_OPT_SUP_IND], NULL,
        val_to_str_ext_const(GTP_EXT_CIOT_OPT_SUP_IND, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(ext_tree, hf_gtp_ciot_opt_sup_ind_sgni_pdn, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(ext_tree, hf_gtp_ciot_opt_sup_ind_scni_pdn, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(ext_tree, hf_gtp_ciot_opt_sup_ind_spare, tvb, offset, 1, ENC_NA);
    offset++;

    if (length > 1) {
        proto_tree_add_expert(ext_tree, pinfo, &ei_gtp_undecoded, tvb, offset, length - 1);
    }

    return 3 + length;
}

/*
 * 7.7.121 SCEF PDN Connection
 */
static int
decode_gtp_scef_pdn_conn(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;
    guint32     apn_length, scef_id_length;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_SCEF_PDN_CONNECTION], NULL,
        val_to_str_ext_const(GTP_EXT_SCEF_PDN_CONNECTION, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item_ret_uint(ext_tree, hf_gtp_apn_length, tvb, offset, 1, ENC_NA, &apn_length);
    decode_apn(tvb, offset + 1, (guint16)apn_length, ext_tree, NULL);

    offset += 1 + apn_length;

    proto_tree_add_item(ext_tree, hf_gtp_nsapi, tvb, offset, 1, ENC_NA);
    offset++;

    proto_tree_add_item_ret_uint(ext_tree, hf_gtp_scef_id_length, tvb, offset, 2, ENC_BIG_ENDIAN, &scef_id_length);
    offset += 2;

    proto_tree_add_item(ext_tree, hf_gtp_scef_id, tvb, offset, scef_id_length, ENC_ASCII);
    offset += scef_id_length;

    if (length > 4 + apn_length + scef_id_length) {
        proto_tree_add_expert(ext_tree, pinfo, &ei_gtp_undecoded, tvb, offset, length - (4 + apn_length + scef_id_length));
    }

    return 3 + length;
}
/*
 * 7.7.122 IOV_updates counter
 */
static int
decode_gtp_iov_updates_counter(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_IOV_UPDATES_COUNTER], NULL,
        val_to_str_ext_const(GTP_EXT_IOV_UPDATES_COUNTER, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(ext_tree, hf_gtp_iov_updates_counter, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if (length > 1) {
        proto_tree_add_expert(ext_tree, pinfo, &ei_gtp_undecoded, tvb, offset, length - 1);
    }

    return 3 + length;
}
/*
 * 7.7.123 Mapped UE Usage Type
 */
static int
decode_gtp_mapped_ue_usage_type(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_MAPPED_UE_USAGE_TYPE], NULL,
        val_to_str_ext_const(GTP_EXT_MAPPED_UE_USAGE_TYPE, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(ext_tree, hf_gtp_mapped_ue_usage_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (length > 2) {
        proto_tree_add_expert(ext_tree, pinfo, &ei_gtp_undecoded, tvb, offset, length - 2);
    }

    return 3 + length;
}
/*
 * 7.7.124 UP Function Selection Indication Flags
 */
static int
decode_gtp_up_fun_sel_ind_flags(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{
    guint16     length;
    proto_tree *ext_tree;

    length = tvb_get_ntohs(tvb, offset + 1);
    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_ies[GTP_EXT_UP_FUN_SEL_IND_FLAGS], NULL,
        val_to_str_ext_const(GTP_EXT_UP_FUN_SEL_IND_FLAGS, &gtpv1_val_ext, "Unknown"));
    proto_tree_add_item(ext_tree, hf_gtp_ie_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    proto_tree_add_item(ext_tree, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(ext_tree, hf_gtp_up_fun_sel_ind_flags_dcnr, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree, hf_gtp_up_fun_sel_ind_flags_spare, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if (length > 1) {
        proto_tree_add_expert(ext_tree, pinfo, &ei_gtp_undecoded, tvb, offset, length - 1);
    }

    return 3 + length;
}

static int
decode_gtp_rel_pack(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length, n, number;
    proto_tree *ext_tree_rel_pack;

    length = tvb_get_ntohs(tvb, offset + 1);

    ext_tree_rel_pack = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_rel_pack, NULL,
                                    "Sequence numbers of released packets IE");

    n = 0;

    while (n < length) {

        number = tvb_get_ntohs(tvb, offset + 3 + n);
        proto_tree_add_uint_format(ext_tree_rel_pack, hf_gtp_seq_num_released, tvb, offset + 3 + n, 2, number, "%u", number);
        n = n + 2;

    }

    return 3 + length;
}

/* GPRS:        12.15
 * UMTS:        33.015
 */
static int
decode_gtp_can_pack(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length, n, number;
    proto_tree *ext_tree_can_pack;

    length = tvb_get_ntohs(tvb, offset + 1);

    ext_tree_can_pack = proto_tree_add_subtree(tree, tvb, offset, 3 + length, ett_gtp_can_pack, NULL,
                                        "Sequence numbers of cancelled  packets IE");

    n = 0;

    while (n < length) {

        number = tvb_get_ntohs(tvb, offset + 3 + n);
        proto_tree_add_uint_format(ext_tree_can_pack, hf_gtp_seq_num_canceled, tvb, offset + 3 + n, 2, number, "%u", number);
        n += 2;
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
static int
decode_gtp_data_req(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length, cdr_length;
    guint8      no, format, app_id, rel_id, ver_id, i;
    gboolean    rel_id_zero = FALSE;
    proto_tree *ext_tree, *ver_tree, *cdr_dr_tree;
    proto_item *fmt_item;
    tvbuff_t   *next_tvb;

    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_gtp_ext, NULL,
                    val_to_str_ext_const(GTP_EXT_DATA_REQ, &gtp_val_ext, "Unknown message"));
    offset++;

    length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(ext_tree, hf_gtp_length, tvb, offset, 2, length);
    offset+=2;

    if (length == 0) {
        return 3;
    }

    /* Octet 4 Number of Data Records */
    no = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(ext_tree, hf_gtp_number_of_data_records, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Octet 5 Data Record Format */
    format   = tvb_get_guint8(tvb, offset);
    fmt_item = proto_tree_add_item(ext_tree, hf_gtp_data_record_format, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* The value range is 1-255 in decimal. The value '0' should not be used.
     * Only the values 1-10 and 51-255 can be used for standards purposes.
     * Values in the range of 11-50 are to be configured only by operators, and are not subject to standardization.
     */
    if(format < 4) {
        proto_item_append_text(fmt_item, " %s", val_to_str_const(format, gtp_cdr_fmt_vals, "Unknown"));
        /* Octet 6 -7  Data Record Format Version
         *    8 7 6 5             4 3 2 1
         * 6 Application Identifier Release Identifier
         * 7 Version Identifier
         *
         * New with Release 15 and higher:
         * 8 Release Identifier Extension
         * The Release Identifier indicates the TS release up to and including
         * 15. The Release Identifier Extension indicates TS releases above 15,
         * in this case the Release Identifier has a value of '0' (decimal)
         */
        app_id = tvb_get_guint8(tvb,offset);
        rel_id = app_id & 0x0f;
        app_id = app_id >>4;
        ver_id = tvb_get_guint8(tvb,offset+1);
        if (rel_id == 0) {
            rel_id_zero = TRUE;
            rel_id = tvb_get_guint8(tvb,offset+2);
        }
        /* The second octet (#7 in Data Record Packet IE) identifies the version of the TS used to encode the CDR,
         * i.e. its value corresponds to the second digit of the version number of the document [51]
         * (as shown on the cover sheet), plus '1'.
         * E.g. for version 3.4.0, the Version Identifier would be "5".
         * In circumstances where the second digit is an alphabetical character, (e.g. 3.b.0), the corresponding ASCII value shall
         * be taken, e.g. the Version Identifier would be "66" (ASCII(b)).
         */
        if(ver_id < 0x65)
            ver_id = ver_id -1;
        /* XXX We don't handle ASCCI version */

        ver_tree = proto_tree_add_subtree_format(ext_tree, tvb, offset, (rel_id_zero || rel_id == 15) ? 3 : 2, ett_gtp_cdr_ver, NULL,
                                "Data record format version: AppId %u Rel %u.%u.0", app_id,rel_id,ver_id);
        proto_tree_add_item(ver_tree, hf_gtp_cdr_app, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ver_tree, hf_gtp_cdr_rel, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(ver_tree, hf_gtp_cdr_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        if(rel_id_zero) {
            /* The Release Identifier indicates the TS release up to and including 15.
             * The Release Identifier Extension indicates TS releases above 15,
             * in this case the Release Identifier has a value of '0' (decimal).
             */
            fmt_item = proto_tree_add_item(ver_tree, hf_gtp_cdr_rel_ext, tvb, offset, 1, ENC_NA);
            offset++;
            if(rel_id < 16) {
                expert_add_info(pinfo, fmt_item, &ei_gtp_cdr_rel_ext_invalid);
            }
        }
        for(i = 0; i < no; ++i) {
            cdr_length = tvb_get_ntohs(tvb, offset);
            cdr_dr_tree = proto_tree_add_subtree_format(ext_tree, tvb, offset, cdr_length+2,
                                    ett_gtp_cdr_dr, NULL, "Data record %d", i + 1);
            proto_tree_add_uint(cdr_dr_tree, hf_gtp_cdr_length, tvb, offset, 2, cdr_length);
            offset+=2;
            proto_tree_add_item(cdr_dr_tree, hf_gtp_cdr_context, tvb, offset, cdr_length, ENC_NA);
            next_tvb = tvb_new_subset_remaining(tvb, offset);

            /* XXX this is for release 6, may not work for higher releases */
            if(format==1) {
                if(rel_id <= 6){
                    dissect_gprscdr_GPRSCallEventRecord_PDU(next_tvb, pinfo, cdr_dr_tree, NULL);
                }else{
                    dissect_gprscdr_GPRSRecord_PDU(next_tvb, pinfo, cdr_dr_tree, NULL);
                }
            } else {
                /* Do we have a dissector regestering for this data format? */
                dissector_try_uint(gtp_cdr_fmt_dissector_table, format, next_tvb, pinfo, cdr_dr_tree);
            }

            offset = offset + cdr_length;
        }

    } else {
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
static int
decode_gtp_data_resp(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length, n, number;
    proto_tree *ext_tree_data_resp;

    length = tvb_get_ntohs(tvb, offset + 1);

    ext_tree_data_resp = proto_tree_add_subtree(tree, tvb, offset, 3 + length,
                                ett_gtp_data_resp, NULL, "Requests responded");

    n = 0;

    while (n < length) {

        number = tvb_get_ntohs(tvb, offset + 3 + n);
        proto_tree_add_uint_format(ext_tree_data_resp, hf_gtp_requests_responded, tvb, offset + 3 + n, 2, number, "%u", number);
        n = n + 2;

    }

    return 3 + length;

}

/* GPRS:        12.15
 * UMTS:        33.015
 */
static int
decode_gtp_node_addr(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, session_args_t * args _U_)
{

    guint16            length;
    proto_tree        *ext_tree_node_addr;
    proto_item        *te;

    length = tvb_get_ntohs(tvb, offset + 1);

    ext_tree_node_addr = proto_tree_add_subtree(tree, tvb, offset, 3 + length,
                                ett_gtp_node_addr, &te, "Node address: ");

    proto_tree_add_item(ext_tree_node_addr, hf_gtp_node_address_length, tvb, offset + 1, 2, ENC_BIG_ENDIAN);

    switch (length) {
    case 4:
        proto_tree_add_item(ext_tree_node_addr, hf_gtp_node_ipv4, tvb, offset + 3, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(te, "%s", tvb_ip_to_str(pinfo->pool, tvb, offset + 3));
        break;
    case 16:
        proto_tree_add_item(ext_tree_node_addr, hf_gtp_node_ipv6, tvb, offset + 3, 16, ENC_NA);
        proto_item_append_text(te, "%s", tvb_ip6_to_str(pinfo->pool, tvb, offset + 3));
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

static int
decode_gtp_priv_ext(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_)
{

    guint16     length, ext_id;
    proto_tree *ext_tree_priv_ext;
    proto_item *te;
    tvbuff_t   *next_tvb;

    ext_tree_priv_ext = proto_tree_add_subtree_format(tree, tvb, offset, 1, ett_gtp_ext, &te,
                "%s : ", val_to_str_ext_const(GTP_EXT_PRIV_EXT, &gtp_val_ext, "Unknown message"));

    offset++;
    length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(ext_tree_priv_ext, hf_gtp_ext_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    if (length >= 2) {
        ext_id = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint(ext_tree_priv_ext, hf_gtp_ext_id, tvb, offset, 2, ext_id);
        proto_item_append_text(te, "%s (%u)", enterprises_lookup(ext_id, "Unknown"), ext_id);
        offset = offset + 2;

       if (length > 2) {
            next_tvb = tvb_new_subset_length(tvb, offset, length-2);
            if(!dissector_try_uint(gtp_priv_ext_dissector_table, ext_id, next_tvb, pinfo, ext_tree_priv_ext)){
                    proto_tree_add_item(ext_tree_priv_ext, hf_gtp_ext_val, tvb, offset, length - 2, ENC_NA);
            }
       }
    }

    return 3 + length;
}

static int
decode_gtp_unknown(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_)
{

    proto_tree_add_expert(tree, pinfo, &ei_gtp_unknown_extension_header, tvb, offset, 1);

    return tvb_reported_length_remaining(tvb, offset);
}

static void
track_gtp_session(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, gtp_hdr_t * gtp_hdr, wmem_list_t *teid_list, wmem_list_t *ip_list, guint32 last_teid, address last_ip)
{
    guint32 *session, frame_teid_cp;
    proto_item *it;

    /* GTP session */
    if (tree) {
        session = (guint32*)g_hash_table_lookup(session_table, &pinfo->num);
        if (session) {
            it = proto_tree_add_uint(tree, hf_gtp_session, tvb, 0, 0, *session);
            proto_item_set_generated(it);
        }
    }


    if (!PINFO_FD_VISITED(pinfo) && gtp_version == 1) {
        /* If the message does not have any session ID */
        session = (guint32*)g_hash_table_lookup(session_table, &pinfo->num);
        if (!session) {
            /* If the message is not a CPDPCRES, CPDPCREQ, UPDPREQ, UPDPRES then we remove its information from teid and ip lists */
            if ((gtp_hdr->message != GTP_MSG_CREATE_PDP_RESP && gtp_hdr->message != GTP_MSG_CREATE_PDP_REQ && gtp_hdr->message != GTP_MSG_UPDATE_PDP_RESP
                && gtp_hdr->message != GTP_MSG_UPDATE_PDP_REQ)) {
                /* If the lists are not empty*/
                if (wmem_list_count(teid_list) && wmem_list_count(ip_list)) {
                    remove_frame_info(&pinfo->num);
                }
            }

            if (gtp_hdr->message == GTP_MSG_CREATE_PDP_REQ) {
                /* If CPDPCREQ and not already in the list then we create a new session*/
                add_gtp_session(pinfo->num, gtp_session_count++);
            } else if (gtp_hdr->message != GTP_MSG_CREATE_PDP_RESP) {
                /* If this is an error indication then we have to check the session id that belongs to the message with the same data teid and ip */
                if (gtp_hdr->message == GTP_MSG_ERR_IND) {
                    if (get_frame(last_ip, last_teid, &frame_teid_cp) == 1) {
                        session = (guint32*)g_hash_table_lookup(session_table, &frame_teid_cp);
                        if (session != NULL) {
                            /* We add the corresponding session to the session list*/
                            add_gtp_session(pinfo->num, *session);
                        }
                    }
                }
                else {
                    /* We have to check if its teid == teid_cp and ip.dst == gsn_ipv4 from the lists, if that is the case then we have to assign
                    the corresponding session ID */
                    if ((get_frame(pinfo->dst, (guint32)gtp_hdr->teid, &frame_teid_cp) == 1)) {
                        /* Then we have to set its session ID */
                        session = (guint32*)g_hash_table_lookup(session_table, &frame_teid_cp);
                        if (session != NULL) {
                            /* We add the corresponding session to the list so that when a response came we can associate its session ID*/
                            add_gtp_session(pinfo->num, *session);
                        }
                    }
                }
            }
        }
    }
}

static int
dissect_nrup(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree,
            void *private_data _U_)
{
    guint32 pdu_type;
    gboolean dl_disc_blk;
    gboolean dl_flush;
    guint32 dl_disc_num_blks;
    gint offset = 0;

    /* NRUP */
    proto_item *nrup_ti;
    proto_tree *nrup_tree;

    /* Protocol subtree */
    nrup_ti = proto_tree_add_item(tree, proto_nrup, tvb, offset, -1, ENC_NA);
    nrup_tree = proto_item_add_subtree(nrup_ti, ett_nrup);


    proto_tree_add_item_ret_uint(nrup_ti, hf_nrup_pdu_type,tvb, offset, 1, ENC_BIG_ENDIAN, &pdu_type);

    switch (pdu_type) {
        case NR_UP_DL_USER_DATA:
        {
            /* 5.5.2.1 */
            gboolean report_delivered;

            /* PDU Type (=0) Spare DL Discard Blocks DL Flush Report polling Octet 1*/
            proto_tree_add_item(nrup_tree, hf_nrup_spr_bit_extnd_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item_ret_boolean(nrup_tree, hf_nrup_dl_discrd_blks, tvb, offset, 1, ENC_BIG_ENDIAN, &dl_disc_blk);
            proto_tree_add_item_ret_boolean(nrup_tree, hf_nrup_dl_flush, tvb, offset, 1, ENC_BIG_ENDIAN, &dl_flush);
            proto_tree_add_item(nrup_tree, hf_nrup_rpt_poll, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            /* Spare    Assistance Info. Report Polling Flag    Retransmission flag*/
            proto_tree_add_item(nrup_tree, hf_nrup_spare, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(nrup_tree, hf_nrup_request_out_of_seq_report, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item_ret_boolean(nrup_tree, hf_nrup_report_delivered, tvb, offset, 1, ENC_BIG_ENDIAN, &report_delivered);
            proto_tree_add_item(nrup_tree, hf_nrup_user_data_existence_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(nrup_tree, hf_nrup_ass_inf_rep_poll_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(nrup_tree, hf_nrup_retransmission_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            /* NR-U Sequence NUmber */
            proto_tree_add_item(nrup_tree, hf_nrup_nr_u_seq_num, tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 3;

            if (dl_flush) {
                /* DL discard NR PDCP PDU SN */
                proto_tree_add_item(nrup_tree, hf_nrup_dl_disc_nr_pdcp_pdu_sn, tvb, offset, 3, ENC_BIG_ENDIAN);
                offset += 3;
            }
            /* Discarded blocks */
            if (dl_disc_blk) {
                /* DL discard Number of blocks */
                proto_tree_add_item_ret_uint(nrup_tree, hf_nrup_dl_disc_num_blks, tvb, offset, 1, ENC_BIG_ENDIAN, &dl_disc_num_blks);
                offset++;
                while (dl_disc_num_blks) {
                    /* DL discard NR PDCP PDU SN start */
                    proto_tree_add_item(nrup_tree, hf_nrup_dl_disc_nr_pdcp_pdu_sn_start, tvb, offset, 3, ENC_BIG_ENDIAN);
                    offset += 3;

                    /* Discarded Block size */
                    proto_tree_add_item(nrup_tree, hf_nrup_dl_disc_blk_sz, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                    dl_disc_num_blks--;
                }
            }

            if (report_delivered) {
                /* DL report NR PDCP PDU SN */
                proto_tree_add_item(nrup_tree, hf_nrup_dl_report_nr_pdcp_pdu_sn, tvb, offset, 3, ENC_BIG_ENDIAN);
                offset += 3;
            }
            break;
        }

        case NR_UP_DL_DATA_DELIVERY_STATUS:
        {
            /* 5.5.2.2 */
            gboolean high_tx_nr_pdcp_sn_ind;
            gboolean high_del_nr_pdcp_sn_ind;
            gboolean lost_packet_report;
            gboolean high_retx_nr_pdcp_sn_ind;
            gboolean high_del_retx_nr_pdcp_sn_ind;
            gboolean cause_rpt;
            gboolean data_rate_ind;
            guint32 lost_NR_U_SN_range;

            proto_tree_add_item_ret_boolean(nrup_tree, hf_nrup_high_tx_nr_pdcp_sn_ind ,tvb, offset,1, ENC_BIG_ENDIAN, &high_tx_nr_pdcp_sn_ind );
            proto_tree_add_item_ret_boolean(nrup_tree, hf_nrup_high_delivered_nr_pdcp_sn_ind ,tvb, offset,1, ENC_BIG_ENDIAN, &high_del_nr_pdcp_sn_ind );
            proto_tree_add_item(nrup_tree, hf_nrup_final_frame_ind,tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item_ret_boolean(nrup_tree, hf_nrup_lost_pkt_rpt,tvb, offset, 1, ENC_BIG_ENDIAN, &lost_packet_report);
            offset++;

            proto_tree_add_item(nrup_tree, hf_nrup_spare, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(nrup_tree, hf_nrup_delivered_nr_pdcp_sn_range_ind ,tvb, offset,1, ENC_BIG_ENDIAN);
            proto_tree_add_item_ret_boolean(nrup_tree, hf_nrup_data_rate_ind,tvb, offset,1, ENC_BIG_ENDIAN, &data_rate_ind);
            proto_tree_add_item_ret_boolean(nrup_tree, hf_nrup_high_retx_nr_pdcp_sn_ind,tvb, offset,1, ENC_BIG_ENDIAN, &high_retx_nr_pdcp_sn_ind);
            proto_tree_add_item_ret_boolean(nrup_tree, hf_nrup_high_delivered_retx_nr_pdcp_sn_ind,tvb, offset,1, ENC_BIG_ENDIAN, &high_del_retx_nr_pdcp_sn_ind);
            proto_tree_add_item_ret_boolean(nrup_tree, hf_nrup_cause_rpt,tvb, offset,1, ENC_BIG_ENDIAN, &cause_rpt);
            offset++;

            proto_tree_add_item(nrup_tree, hf_nrup_desrd_buff_sz_data_radio_bearer,tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            if (data_rate_ind){
                proto_tree_add_item(nrup_tree, hf_nrup_desrd_data_rate,tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            }

            if (lost_packet_report) {
                proto_tree_add_item_ret_uint(nrup_tree, hf_nrup_num_lost_nru_seq_num,tvb, offset, 1, ENC_BIG_ENDIAN, &lost_NR_U_SN_range);
                offset+=1;

                while (lost_NR_U_SN_range) {
                    proto_tree_add_item(nrup_tree, hf_nrup_start_lost_nru_seq_num,tvb, offset, 3, ENC_BIG_ENDIAN);
                    offset += 3;

                     proto_tree_add_item(nrup_tree, hf_nrup_end_lost_nru_seq_num,tvb, offset, 3, ENC_BIG_ENDIAN);
                     offset += 3;
                     lost_NR_U_SN_range--;
                }
            }

            if (high_del_nr_pdcp_sn_ind) {
                proto_tree_add_item(nrup_tree, hf_nrup_high_success_delivered_nr_pdcp_sn,tvb, offset, 3, ENC_BIG_ENDIAN);
                offset += 3;
            }

            if (high_tx_nr_pdcp_sn_ind) {
                proto_tree_add_item(nrup_tree, hf_nrup_high_tx_nr_pdcp_sn,tvb, offset, 3, ENC_BIG_ENDIAN);
                offset += 3;
            }

            if (cause_rpt) {
                proto_tree_add_item(nrup_tree, hf_nrup_cause_val,tvb, offset, 1, ENC_BIG_ENDIAN);
                offset ++;
            }

            if (high_del_retx_nr_pdcp_sn_ind) {
                proto_tree_add_item(nrup_tree, hf_nrup_high_success_delivered_retx_nr_pdcp_sn,tvb, offset, 3, ENC_BIG_ENDIAN);
                offset += 3;
            }

            if (high_retx_nr_pdcp_sn_ind) {
                proto_tree_add_item(nrup_tree, hf_nrup_high_retx_nr_pdcp_sn,tvb, offset, 3, ENC_BIG_ENDIAN);
            }

            break;
        }

        case NR_UP_ASSISTANCE_INFORMATION_DATA:
        {
            /* 5.5.2.3 */
            gboolean pdcp_duplication_indication;
            gboolean assistance_information_ind;
            gboolean ul_delay_ind;
            gboolean dl_delay_ind;
            gboolean pdcp_duplication_suggestion;

            /* Flags */
            proto_tree_add_item_ret_boolean(nrup_tree, hf_nrup_pdcp_duplication_ind, tvb, offset,1, ENC_BIG_ENDIAN, &pdcp_duplication_indication);
            proto_tree_add_item_ret_boolean(nrup_tree, hf_nrup_assistance_information_ind, tvb, offset,1, ENC_BIG_ENDIAN, &assistance_information_ind);
            proto_tree_add_item_ret_boolean(nrup_tree, hf_nrup_ul_delay_ind, tvb, offset,1, ENC_BIG_ENDIAN, &ul_delay_ind);
            proto_tree_add_item_ret_boolean(nrup_tree, hf_nrup_dl_delay_ind, tvb, offset,1, ENC_BIG_ENDIAN, &dl_delay_ind);
            offset++;
            proto_tree_add_item(nrup_tree, hf_nrup_spare_2, tvb, offset,1, ENC_BIG_ENDIAN);
            proto_tree_add_item_ret_boolean(nrup_tree, hf_nrup_pdcp_duplication_activation_suggestion,
                                            tvb, offset,1, ENC_BIG_ENDIAN, &pdcp_duplication_suggestion);
            offset++;

            /* Number of Assistance Information Fields */
            if (assistance_information_ind) {
                guint32  number_of_assistance_information_fields = 0;
                guint32 num_octets_radio_qa_info;

                /* Number of assistance info fields */
                proto_tree_add_item_ret_uint(nrup_tree, hf_nrup_num_assistance_info_fields,
                                             tvb, offset,1, ENC_BIG_ENDIAN, &number_of_assistance_information_fields);
                offset++;

                for (guint n=0; n < number_of_assistance_information_fields; n++) {
                    /* Assistance Information Type */
                    proto_tree_add_item(nrup_tree, hf_nrup_assistance_information_type,
                                        tvb, offset,1, ENC_BIG_ENDIAN);
                    offset++;
                    /* Num octets in assistance info */
                    proto_tree_add_item_ret_uint(nrup_tree, hf_nrup_num_octets_radio_qa_info,
                                                 tvb, offset, 1, ENC_BIG_ENDIAN, &num_octets_radio_qa_info);
                    offset++;
                    /* Radio Quality Assistance info */
                    proto_tree_add_item(nrup_tree, hf_nrup_radio_qa_info, tvb, offset,
                                        num_octets_radio_qa_info, ENC_NA);
                    offset += num_octets_radio_qa_info;
                }
            }

            /* UL Delay DU Result */
            if (ul_delay_ind) {
                proto_tree_add_item(nrup_tree, hf_nrup_ul_delay_du_result, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            }
            /* DL Delay DU Result */
            if (dl_delay_ind) {
                proto_tree_add_item(nrup_tree, hf_nrup_dl_delay_du_result, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            }
            break;
        }
        default:
            /* TODO: expert info error for unexpected PDU type? */
            break;
    }

    return offset;
}

/* TS 38.425 */
static void
addRANContParameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, gint length)
{
    tvbuff_t *next_tvb = tvb_new_subset_length(tvb, offset, length);
    call_dissector(nrup_handle, next_tvb, pinfo, tree);
}

static void
dissect_gtp_tpdu_by_handle(dissector_handle_t handle, tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, int offset)
{
    tvbuff_t        *next_tvb;
    next_tvb = tvb_new_subset_remaining(tvb, offset);
    call_dissector(handle, next_tvb, pinfo, tree);
    col_prepend_fstr(pinfo->cinfo, COL_PROTOCOL, "GTP <");
    col_append_str(pinfo->cinfo, COL_PROTOCOL, ">");
}

static void
dissect_gtp_tpdu_as_pdcp_lte_info(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, gtp_hdr_t *gtp_hdr, int offset)
{
    /* Check if we have info to call the PDCP dissector */
    struct pdcp_lte_info *p_pdcp_info;
    uat_pdcp_lte_keys_record_t * found_record;
    tvbuff_t *pdcp_lte_tvb;

    if ((found_record = look_up_pdcp_lte_keys_record(pinfo, (guint32)gtp_hdr->teid))) {
        /* Look for attached packet info! */
        p_pdcp_info = (struct pdcp_lte_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_pdcp_lte, 0);
        /* If we don't have the data, add it */
        if (p_pdcp_info == NULL) {
            p_pdcp_info = wmem_new0(wmem_file_scope(), pdcp_lte_info);
            /* Channel info is needed for RRC parsing */
            /*p_pdcp_info->direction;*/
            /*p_pdcp_info->ueid;*/
            /*p_pdcp_info->channelType;*/
            /*p_pdcp_info->channelId;*/
            /*p_pdcp_info->BCCHTransport;*/

            /* Details of PDCP header */
            if (found_record->header_present == PDCP_LTE_HEADER_PRESENT) {
                p_pdcp_info->no_header_pdu = FALSE;
            } else {
                p_pdcp_info->no_header_pdu = TRUE;
            }
            p_pdcp_info->plane = found_record->plane;
            p_pdcp_info->seqnum_length = found_record->lte_sn_length;

            /* RoHC settings */
            p_pdcp_info->rohc.rohc_compression = found_record->rohc_compression;
            p_pdcp_info->rohc.rohc_ip_version = 4; /* For now set it explicitly */
            p_pdcp_info->rohc.cid_inclusion_info = FALSE;
            p_pdcp_info->rohc.large_cid_present = FALSE;
            p_pdcp_info->rohc.mode = MODE_NOT_SET;
            p_pdcp_info->rohc.rnd = FALSE;
            p_pdcp_info->rohc.udp_checksum_present = FALSE;
            p_pdcp_info->rohc.profile = found_record->rohc_profile;

            /* p_pdcp_info->is_retx;*/

            /* Used by heuristic dissector only */
            /*p_pdcp_info->pdu_length;*/
            p_add_proto_data(wmem_file_scope(), pinfo, proto_pdcp_lte, 0, p_pdcp_info);
        }
        pdcp_lte_tvb = tvb_new_subset_remaining(tvb, offset);
        call_dissector(pdcp_lte_handle, pdcp_lte_tvb, pinfo, tree);

    } else {
        proto_tree_add_subtree(tree, tvb, offset, -1, ett_gtp_pdcp_no_conf, NULL, "[No PDCP-LTE Configuration data found]");
        proto_tree_add_item(tree, hf_pdcp_cont, tvb, offset, -1, ENC_NA);
    }
}

static void
dissect_gtp_tpsu_as_pdcp_nr_info(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, gtp_hdr_t *gtp_hdr, int offset)
{
    /*NR-U DUD or DDDS PDU
    * This is NR-U DUD/DDDS PDU. It contains PDCP
    * payload as per 3GPP TS 38.323
    */
    /* Check if we have info to call the PDCP dissector */
    uat_pdcp_nr_keys_record_t* found_record;

    if ((found_record = look_up_pdcp_nr_keys_record(pinfo, (guint32)gtp_hdr->teid))) {
        tvbuff_t *pdcp_tvb;
        struct pdcp_nr_info temp_data;

        pdcp_tvb = tvb_new_subset_remaining(tvb, offset);
        /* Fill in pdcp_nr_info */

        temp_data.direction = found_record->direction;
        /*temp_data.ueid*/
        /*temp_data.bearerType;*/
        /*temp_data.bearerId;*/

        /* Details of PDCP header */
        temp_data.plane = found_record->plane;
        temp_data.seqnum_length = found_record->pdcp_nr_sn_length;
        /* PDCP_NR_(U|D)L_sdap_hdr_PRESENT bitmask */
        if (found_record->sdap_header_present == PDCP_NR_SDAP_HEADER_PRESENT) {
            if (temp_data.direction == PDCP_NR_DIRECTION_UPLINK) {
                temp_data.sdap_header = PDCP_NR_UL_SDAP_HEADER_PRESENT;
            } else {
                temp_data.sdap_header = PDCP_NR_DL_SDAP_HEADER_PRESENT;
            }
        } else {
            temp_data.sdap_header = 0;
        }
        temp_data.maci_present = found_record->mac_i_present;

        /* RoHC settings */
        temp_data.rohc.rohc_compression = found_record->rohc_compression;
        temp_data.rohc.rohc_ip_version = 4; /* For now set it explicitly */
        temp_data.rohc.cid_inclusion_info = FALSE;
        temp_data.rohc.large_cid_present = FALSE;
        temp_data.rohc.mode = MODE_NOT_SET;
        temp_data.rohc.rnd = FALSE;
        temp_data.rohc.udp_checksum_present = FALSE;
        temp_data.rohc.profile = found_record->rohc_profile;

        temp_data.is_retx = 0;

        /* Used by heuristic dissector only */
        temp_data.pdu_length = 0;

        call_dissector_with_data(pdcp_nr_handle, pdcp_tvb, pinfo, tree, &temp_data);
    } else {
        proto_tree_add_subtree(tree, tvb, offset, -1, ett_gtp_pdcp_no_conf, NULL, "[No PDCP-NR Configuration data found]");
        proto_tree_add_item(tree, hf_pdcp_cont, tvb, offset, -1, ENC_NA);
    }
}

static int
dissect_gtp_common(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
    guint8           octet;
    gtp_hdr_t       *gtp_hdr = NULL;
    proto_tree      *gtp_tree = NULL, *ext_tree;
    proto_tree      *ran_cont_tree = NULL;
    proto_item      *ti = NULL, *tf, *ext_hdr_len_item, *message_item;
    int              i, offset = 0, checked_field, mandatory;
    gboolean         gtp_prime, has_SN;
    int              seq_no           = 0;
    int              flow_label       = 0;
    guint8           pdu_no, next_hdr = 0;
    guint8           ext_hdr_val;
    guint            ext_hdr_length;
    guint16          ext_hdr_pdcpsn;
    gchar           *tid_str;
    guint8           sub_proto;
    guint8           acfield_len      = 0;
    gtp_msg_hash_t  *gcrp             = NULL;
    conversation_t  *conversation;
    gtp_conv_info_t *gtp_info;
    session_args_t  *args             = NULL;
    ie_decoder      *decoder          = NULL;

    /* Do we have enough bytes for the version and message type? */
    if (!tvb_bytes_exist(tvb, 0, 2)) {
        /* No - reject the packet. */
        return 0;
    }
    octet = tvb_get_guint8(tvb, 0);
    if (((octet >> 5) & 0x07) > 2) {
        /* Version > 2; reject the packet */
        return 0;
    }
    octet = tvb_get_guint8(tvb, 1);
    if (octet == GTP_MSG_UNKNOWN || try_val_to_str(octet, gtp_message_type) == NULL) {
        /* Unknown message type; reject the packet */
        return 0;
    }

    /* Setting everything to 0, so that the TEID is 0 for GTP version 0
     * The magic number should perhaps be replaced.
     */
    gtp_hdr = wmem_new0(wmem_packet_scope(), gtp_hdr_t);

    /* Setting the TEID to -1 to say that the TEID is not valid for this packet */
    gtp_hdr->teid = -1;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GTP");
    col_clear(pinfo->cinfo, COL_INFO);

    if (g_gtp_session) {
        args = wmem_new0(wmem_packet_scope(), session_args_t);
        args->last_cause = 128;                                         /* It stores the last cause decoded. Cause accepted by default */
        /* We create the auxiliary lists */
        args->teid_list = wmem_list_new(wmem_packet_scope());
        args->ip_list = wmem_list_new(wmem_packet_scope());
    }

    /*
    * Do we have a conversation for this connection?
    */
    conversation = find_or_create_conversation(pinfo);

    /*
    * Do we already know this conversation?
    */
    gtp_info = (gtp_conv_info_t *)conversation_get_proto_data(conversation, proto_gtp);
    if (gtp_info == NULL) {
        /* No.  Attach that information to the conversation, and add
        * it to the list of information structures.
        */
        gtp_info = wmem_new(wmem_file_scope(), gtp_conv_info_t);
        /*Request/response matching tables*/
        gtp_info->matched = g_hash_table_new(gtp_sn_hash, gtp_sn_equal_matched);
        gtp_info->unmatched = g_hash_table_new(gtp_sn_hash, gtp_sn_equal_unmatched);

        conversation_add_proto_data(conversation, proto_gtp, gtp_info);

        gtp_info->next = gtp_info_items;
        gtp_info_items = gtp_info;
    }

    gtp_hdr->flags = tvb_get_guint8(tvb, offset);

    if (!(gtp_hdr->flags & 0x10)){
        gtp_prime = TRUE;
    }else{
        gtp_prime = FALSE;
    }

    switch ((gtp_hdr->flags >> 5) & 0x07) {
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
    if (tree) {
        if (gtp_prime) {
            static int * const gtp_prime_flags[] = {
                &hf_gtp_prime_flags_ver,
                &hf_gtp_flags_pt,
                &hf_gtp_flags_spare1,
                NULL
            };
            static int * const gtp_prime_v0_flags[] = {
                &hf_gtp_prime_flags_ver,
                &hf_gtp_flags_pt,
                &hf_gtp_flags_spare1,
                &hf_gtp_flags_hdr_length,
                NULL
            };

            ti = proto_tree_add_item(tree, proto_gtpprime, tvb, 0, -1, ENC_NA);
            gtp_tree = proto_item_add_subtree(ti, ett_gtp);

            /* Octet  8    7    6    5    4    3    2    1
             * 1      Version   | PT| Spare '1 1 1 '| ' 0/1 '
             */

             /* Bit 1 of octet 1 is not used in GTP' (except in v0), and it is marked '0'
              * in the GTP' header. It is in use in GTP' v0 and distinguishes the used header-length.
              * In the case of GTP' v0, this bit being marked one (1) indicates the usage of the 6
              * octets header. If the bit is set to '0' (usually the case) the 20-octet header is used.
              * For all other versions of GTP', this bit is not used and is set to '0'. However,
              * this does not suggest the use of the 20-octet header, rather a shorter 6-octet header.
              */
            if (gtp_version == 0) {
                proto_tree_add_bitmask_value_with_flags(gtp_tree, tvb, offset, hf_gtp_flags,
                    ett_gtp_flags, gtp_prime_v0_flags, gtp_hdr->flags, BMT_NO_APPEND);
            } else {
                proto_tree_add_bitmask_value_with_flags(gtp_tree, tvb, offset, hf_gtp_flags,
                    ett_gtp_flags, gtp_prime_flags, gtp_hdr->flags, BMT_NO_APPEND);
            }
        } else {
            static int * const gtp_flags[] = {
                &hf_gtp_flags_ver,
                &hf_gtp_flags_pt,
                &hf_gtp_flags_spare2,
                &hf_gtp_flags_e,
                &hf_gtp_flags_s,
                &hf_gtp_flags_pn,
                NULL
            };
            static int * const gtp_v0_flags[] = {
                &hf_gtp_flags_ver,
                &hf_gtp_flags_pt,
                &hf_gtp_flags_spare1,
                &hf_gtp_flags_snn,
                NULL
            };
            ti = proto_tree_add_item(tree, proto_gtp, tvb, 0, -1, ENC_NA);
            gtp_tree = proto_item_add_subtree(ti, ett_gtp);

            if (gtp_version == 0) {
                proto_tree_add_bitmask_value_with_flags(gtp_tree, tvb, offset, hf_gtp_flags,
                    ett_gtp_flags, gtp_v0_flags, gtp_hdr->flags, BMT_NO_APPEND);
            } else {
                proto_tree_add_bitmask_value_with_flags(gtp_tree, tvb, offset, hf_gtp_flags,
                    ett_gtp_flags, gtp_flags, gtp_hdr->flags, BMT_NO_APPEND);
            }
        }
    }
    offset++;

    gtp_hdr->message = tvb_get_guint8(tvb, offset);
    /* Link direction is needed to properly dissect PCO */
    switch(gtp_hdr->message){
        case GTP_MSG_DELETE_PDP_REQ:
        case GTP_MSG_UPDATE_PDP_REQ:
        case GTP_MSG_CREATE_PDP_REQ:
        case GTP_MSG_INIT_PDP_CONTEXT_ACT_REQ:
        case GTP_MSG_PDU_NOTIFY_REQ:
        case GTP_MSG_PDU_NOTIFY_REJ_REQ:
        case GTP_MSG_FORW_RELOC_REQ: /* direction added for UTRAN Container & BSS Container decode */
            pinfo->link_dir = P2P_DIR_UL;
            break;
        case GTP_MSG_DELETE_PDP_RESP:
        case GTP_MSG_UPDATE_PDP_RESP:
        case GTP_MSG_CREATE_PDP_RESP:
        case GTP_MSG_INIT_PDP_CONTEXT_ACT_RESP:
        case GTP_MSG_FORW_RELOC_RESP: /* direction added for UTRAN Container & BSS Container decode */
            pinfo->link_dir = P2P_DIR_DL;
            break;
    default:
        break;
    }
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_ext_const(gtp_hdr->message, &gtp_message_type_ext, "Unknown"));
    message_item = proto_tree_add_uint(gtp_tree, hf_gtp_message_type, tvb, offset, 1, gtp_hdr->message);
    offset++;

    gtp_hdr->length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(gtp_tree, hf_gtp_length, tvb, 2, 2, gtp_hdr->length);
    offset += 2;

    /* We initialize the sequence number*/
    has_SN = FALSE;
    if (gtp_prime) {
        seq_no = tvb_get_ntohs(tvb, offset);
        has_SN = TRUE;
        proto_tree_add_uint(gtp_tree, hf_gtp_seq_number, tvb, offset, 2, seq_no);
        offset += 2;
        /* If GTP' version is 0 and bit 1 is 0 20 bytes header is used, dissect it */
        if( (gtp_version == 0) && ((gtp_hdr->flags & 0x01) == 0) ) {
            proto_tree_add_item(gtp_tree, hf_gtp_dummy_octets, tvb, offset, 14, ENC_NA);
            offset += 14;
        }

        set_actual_length(tvb, offset + gtp_hdr->length);
    } else {
        switch (gtp_version) {
        case 0:
            seq_no = tvb_get_ntohs(tvb, offset);
            has_SN = TRUE;
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

            set_actual_length(tvb, offset + gtp_hdr->length);

            break;
        case 1:
            gtp_hdr->teid = tvb_get_ntohl(tvb, offset);
            proto_tree_add_item(gtp_tree, hf_gtp_teid, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            set_actual_length(tvb, offset + gtp_hdr->length);

            /* Are sequence number/N-PDU Number/extension header present?
               See NOTE 5 of Figure 2 of 3GPP TS 29.060 version 4.3.0
               Release 4 - the Sequence Number, N-PDU Number, and
               Next Extension Header fields are present if any of
               GTP_E_MASK, GTP_S_MASK, or GTP_PN_MASK are set. */
            if (gtp_hdr->flags & (GTP_E_MASK|GTP_S_MASK|GTP_PN_MASK)) {
                /* Those fields are only *interpreted* if the
                   particular flag for the field is set. */
                if (gtp_hdr->flags & GTP_S_MASK) {
                    seq_no = tvb_get_ntohs(tvb, offset);
                    has_SN = TRUE;
                    proto_tree_add_uint(gtp_tree, hf_gtp_seq_number, tvb, offset, 2, seq_no);
                }
                offset += 2;

                if (gtp_hdr->flags & GTP_PN_MASK) {
                    pdu_no = tvb_get_guint8(tvb, offset);
                    proto_tree_add_uint(gtp_tree, hf_gtp_npdu_number, tvb, offset, 1, pdu_no);
                }
                offset++;

                if (gtp_hdr->flags & GTP_E_MASK) {
                    proto_item* hdr_ext_item;
                    next_hdr = tvb_get_guint8(tvb, offset);
                    hdr_ext_item = proto_tree_add_uint(gtp_tree, hf_gtp_ext_hdr_next, tvb, offset, 1, next_hdr);
                    offset++;
                    /* Add each extension header found. */
                    while (next_hdr != 0) {
                        ext_hdr_length = tvb_get_guint8(tvb, offset);
                        tf = proto_tree_add_item(gtp_tree, hf_gtp_ext_hdr, tvb, offset, ext_hdr_length*4, ENC_NA);
                        ext_tree = proto_item_add_subtree(tf, ett_gtp_ext_hdr);
                        ext_hdr_len_item = proto_tree_add_item(ext_tree, hf_gtp_ext_hdr_length, tvb, offset,1, ENC_BIG_ENDIAN);
                        if (ext_hdr_length == 0) {
                            expert_add_info_format(pinfo, ext_hdr_len_item, &ei_gtp_ext_length_mal,
                                                   "Extension header length is zero");
                            return tvb_reported_length(tvb);
                        }
                        offset++;
                        proto_item_append_text(tf, " (%s)", val_to_str_const(next_hdr, next_extension_header_fieldvals, "Unknown"));

                        switch (next_hdr) {

                        case GTP_EXT_HDR_UDP_PORT:
                            /* UDP Port
                             * 3GPP 29.281 v9.0.0, 5.2.2.1 UDP Port
                             * "This extension header may be transmitted in
                             * Error Indication messages to provide the UDP
                             * Source Port of the G-PDU that triggered the
                             * Error Indication. It is 4 octets long, and
                             * therefore the Length field has value 1"
                             */
                            if (ext_hdr_length == 1) {
                                /* UDP Port of source */
                                proto_tree_add_item(ext_tree, hf_gtp_ext_hdr_udp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
                            } else {
                                /* Bad length */
                                expert_add_info_format(pinfo, ext_tree, &ei_gtp_ext_length_warn, "The length field for the UDP Port Extension header should be 1.");
                            }
                            break;

                        case GTP_EXT_HDR_RAN_CONT:
                            /* RAN Container
                             * 3GPP 29.281 v15.2.0, 5.2.2.4 RAN Container
                             * This extension header may be transmitted in
                             * a G-PDU over the X2 user plane interface
                             * between the eNBs. The RAN Container has a
                             * variable length and its content is specified
                             * in 3GPP TS 36.425 [25]. A G-PDU message with
                             * this extension header may be sent without a T-PDU.
                             */
                            proto_tree_add_item(ext_tree, hf_gtp_ext_hdr_ran_cont, tvb, offset, (4*ext_hdr_length)-1, ENC_NA);
                            break;

                        case GTP_EXT_HDR_LONG_PDCP_PDU:
                            /* Long PDCP PDU Number
                             * 3GPP 29.281 v15.2.0, 5.2.2.2A Long PDCP PDU Number
                             * This extension header is used for direct X2 or
                             * indirect S1 DL data forwarding during a Handover
                             * procedure between two eNBs. The Long PDCP PDU number
                             * extension header is 8 octets long, and therefore
                             * the Length field has value 2.
                             * The PDCP PDU number field of the Long PDCP PDU number
                             * extension header has a maximum value which requires 18
                             * bits (see 3GPP TS 36.323 [24]). Bit 2 of octet 2 is
                             * the most significant bit and bit 1 of octet 4 is the
                             * least significant bit, see Figure 5.2.2.2A-1. Bits 8 to
                             * 3 of octet 2, and Bits 8 to 1 of octets 5 to 7 shall be
                             * set to 0.
                             * NOTE: A G-PDU which includes a PDCP PDU Number contains
                             * either the extension header PDCP PDU Number or Long PDCP
                             * PDU Number.
                             */
                            if (ext_hdr_length == 2) {
                                proto_tree_add_bits_item(ext_tree, hf_gtp_ext_hdr_spare_bits, tvb, offset<<3, 6, ENC_BIG_ENDIAN);
                                proto_tree_add_item(ext_tree, hf_gtp_ext_hdr_long_pdcp_sn, tvb, offset, 3, ENC_BIG_ENDIAN);
                                proto_tree_add_item(ext_tree, hf_gtp_ext_hdr_spare_bytes, tvb, offset+3, 3, ENC_NA);
                            } else {
                                expert_add_info_format(pinfo, ext_tree, &ei_gtp_ext_length_warn, "The length field for the Long PDCP SN Extension header should be 2.");
                            }
                            break;

                        case GTP_EXT_HDR_XW_RAN_CONT:
                            /* Xw RAN Container
                             * 3GPP 29.281 v15.2.0, 5.2.2.5 Xw RAN Container
                             * This extension header may be transmitted in a
                             * G-PDU over the Xw user plane interface between
                             * the eNB and the WLAN Termination (WT). The Xw
                             * RAN Container has a variable length and its
                             * content is specified in 3GPP TS 36.464 [27].
                             * A G-PDU message with this extension header may
                             * be sent without a T-PDU.
                             */
                            proto_tree_add_item(ext_tree, hf_gtp_ext_hdr_xw_ran_cont, tvb, offset, (4*ext_hdr_length)-1, ENC_NA);
                            break;

                        case GTP_EXT_HDR_NR_RAN_CONT:
                            /* NR RAN Container
                             * 3GPP 29.281 v15.2.0, 5.2.2.6 NR RAN Container
                             * This extension header may be transmitted in a
                             * G-PDU over the X2-U, Xn-U and F1-U user plane
                             * interfaces, within NG-RAN and, for EN-DC, within
                             * E-UTRAN. The NR RAN Container has a variable
                             * length and its content is specified in 3GPP TS
                             * 38.425 [30]. A G-PDU message with this extension
                             * header may be sent without a T-PDU.
                             */
                            ran_cont_tree = proto_tree_add_subtree(ext_tree, tvb, offset, (ext_hdr_length * 4) - 1, ett_gtp_nr_ran_cont, NULL, "NR RAN Container");
                            addRANContParameter(tvb, pinfo, ran_cont_tree, offset, (ext_hdr_length * 4) - 1);
                            break;

                        case GTP_EXT_HDR_PDU_SESSION_CONT:
                        {
                            /* PDU Session Container
                             * 3GPP 29.281 v15.2.0, 5.2.2.7 PDU Session Container
                             * This extension header may be transmitted in a G-PDU
                             * over the N3 and N9 user plane interfaces, between
                             * NG-RAN and UPF, or between two UPFs. The PDU Session
                             * Container has a variable length and its content is
                             * specified in 3GPP TS 38.415 [31].
                             */
                            static int * const flags1[] = {
                                &hf_gtp_ext_hdr_pdu_ses_cont_ppp,
                                &hf_gtp_ext_hdr_pdu_ses_cont_rqi,
                                &hf_gtp_ext_hdr_pdu_ses_cont_qos_flow_id,
                                NULL
                            };
                            static int * const flags2[] = {
                                &hf_gtp_ext_hdr_pdu_ses_cont_ppi,
                                &hf_gtp_spare_b4b0,
                                NULL
                            };
                            static int * const flags3[] = {
                                &hf_gtp_spare_b7b6,
                                &hf_gtp_ext_hdr_pdu_ses_cont_qos_flow_id,
                                NULL
                            };

                            proto_tree *pdu_ses_cont_tree;
                            guint32 pdu_type;
                            guint8 value;

                            pdu_ses_cont_tree = proto_tree_add_subtree(ext_tree, tvb, offset, (ext_hdr_length * 4) - 1, ett_pdu_session_cont, NULL, "PDU Session Container");
                            /* PDU Type    Spare */
                            proto_tree_add_item_ret_uint(pdu_ses_cont_tree, hf_gtp_ext_hdr_pdu_ses_cont_pdu_type, tvb, offset, 1, ENC_BIG_ENDIAN, &pdu_type);
                            proto_tree_add_item(pdu_ses_cont_tree, hf_gtp_spare_h1, tvb, offset, 1, ENC_BIG_ENDIAN);
                            switch (pdu_type) {
                            case 0:
                                /* PDU Type: DL PDU SESSION INFORMATION (0) */
                                /* Octet 1: PPP    RQI    QoS Flow Identifier  */
                                value = tvb_get_guint8(tvb, offset + 1);
                                proto_tree_add_bitmask_list_value(pdu_ses_cont_tree, tvb, offset + 1, 1, flags1, value);
                                if (value & 0x80)
                                {
                                    /* Octet 2 PPI    Spare*/
                                    proto_tree_add_bitmask_list(pdu_ses_cont_tree, tvb, offset + 2, 1, flags2, ENC_BIG_ENDIAN);
                                }
                                break;
                            case 1:
                                /* PDU Type: UL PDU SESSION INFORMATION (1)*/
                                /* Spare    QoS Flow Identifier */
                                proto_tree_add_bitmask_list(pdu_ses_cont_tree, tvb, offset + 1, 1, flags3, ENC_BIG_ENDIAN);
                                break;
                            default:
                                proto_tree_add_expert(pdu_ses_cont_tree, pinfo, &ei_gtp_unknown_pdu_type, tvb, offset, 1);
                                break;
                            }
                        }
                            break;

                        case GTP_EXT_HDR_PDCP_SN:
                            /* PDCP PDU
                             * 3GPP 29.281 v9.0.0, 5.2.2.2 PDCP PDU Number
                             *
                             * "This extension header is transmitted, for
                             * example in UTRAN, at SRNS relocation time,
                             * to provide the PDCP sequence number of not
                             * yet acknowledged N-PDUs. It is 4 octets long,
                             * and therefore the Length field has value 1.
                             *
                             * When used during a handover procedure between
                             * two eNBs at the X2 interface (direct DL data
                             * forwarding) or via the S1 interface (indirect
                             * DL data forwarding) in E-UTRAN, bit 8 of octet
                             * 2 is spare and shall be set to zero.
                             *
                             * Wireshark Note: TS 29.060 does not define bit
                             * 5-6 as spare, so no check is possible unless
                             * a preference is used.
                             */
                            /* First byte is length (should be 1) */
                            if (ext_hdr_length == 1) {
                                proto_item* ext_item;

                                ext_hdr_pdcpsn = tvb_get_ntohs(tvb, offset);
                                ext_item = proto_tree_add_item(ext_tree, hf_gtp_ext_hdr_pdcpsn, tvb, offset, 2, ENC_BIG_ENDIAN);
                                if (ext_hdr_pdcpsn & 0x8000) {
                                    expert_add_info(pinfo, ext_item, &ei_gtp_ext_hdr_pdcpsn);
                                }
                            } else {
                                expert_add_info_format(pinfo, ext_tree, &ei_gtp_ext_length_warn, "The length field for the PDCP SN Extension header should be 1.");
                            }
                            break;

                        case GTP_EXT_HDR_SUSPEND_REQ:
                            /* Suspend Request */
                            break;

                        case GTP_EXT_HDR_SUSPEND_RESP:
                            /* Suspend Response */
                            break;

                        default:
                            {
                                tvbuff_t * ext_hdr_tvb;
                                gtp_hdr_ext_info_t gtp_hdr_ext_info;

                                gtp_hdr_ext_info.hdr_ext_item = hdr_ext_item;
                                /* NOTE Type and lenght included in the call*/
                                ext_hdr_tvb = tvb_new_subset_remaining(tvb, offset - 2);
                                dissector_try_uint_new(gtp_hdr_ext_dissector_table, next_hdr, ext_hdr_tvb, pinfo, ext_tree, FALSE, &gtp_hdr_ext_info);
                                break;
                            }
                        }
                        offset += ext_hdr_length*4 - 2;

                        next_hdr = tvb_get_guint8(tvb, offset);
                        hdr_ext_item = proto_tree_add_uint(ext_tree, hf_gtp_ext_hdr_next, tvb, offset, 1, next_hdr);
                        offset++;
                    }
                } else
                    offset++;
            }
            break;
        default:
            break;
        }
    }

    if (gtp_hdr->message != GTP_MSG_TPDU) {
        /* Dissect IEs */
        mandatory = 0;      /* check order of GTP fields against ETSI */
        while (tvb_reported_length_remaining(tvb, offset) > 0) {
            decoder = NULL;
            ext_hdr_val = tvb_get_guint8(tvb, offset);
            if (g_gtp_etsi_order) {
                checked_field = check_field_presence_and_decoder(gtp_hdr->message, ext_hdr_val, &mandatory, &decoder);
                switch (checked_field) {
                case -2:
                    expert_add_info(pinfo, message_item, &ei_gtp_message_not_found);
                    break;
                case -1:
                    expert_add_info(pinfo, message_item, &ei_gtp_field_not_present);
                    break;
                case 0:
                    break;
                default:
                    expert_add_info_format(pinfo, message_item, &ei_gtp_wrong_next_field, "[WARNING] wrong next field, should be: %s",
                                        val_to_str_ext_const(checked_field, &gtp_val_ext, "Unknown extension field"));
                    break;
                }
            }

            if (decoder == NULL) {
                i = -1;
                while (gtpopt[++i].optcode)
                    if (gtpopt[i].optcode == ext_hdr_val)
                        break;
                decoder = gtpopt[i].decode;
            }

            offset = offset + (*decoder) (tvb, offset, pinfo, gtp_tree, args);
        }

        if (args && !PINFO_FD_VISITED(pinfo)) {
            /* We insert the lists inside the table*/
            fill_map(args->teid_list, args->ip_list, pinfo->num);
        }
        /*Use sequence number to track Req/Resp pairs*/
        if (has_SN) {
            guint8 cause_aux = 128; /* Cause accepted by default. Only used when args is NULL */
            if (args) {
                cause_aux = args->last_cause;
            }
            gcrp = gtp_match_response(tvb, pinfo, gtp_tree, seq_no, gtp_hdr->message, gtp_info, cause_aux);
            /*pass packet to tap for response time reporting*/
            if (gcrp) {
                tap_queue_packet(gtp_tap,pinfo,gcrp);
            }
        }
    }
    if (args) {
        track_gtp_session(tvb, pinfo, gtp_tree, gtp_hdr, args->teid_list, args->ip_list, args->last_teid, args->last_ip);
    }
    proto_item_set_end(ti, tvb, offset);

    if ((gtp_hdr->message == GTP_MSG_TPDU) && (tvb_reported_length_remaining(tvb, offset) > 0)) {
        switch (dissect_tpdu_as) {
        case GTP_TPDU_AS_TPDU_HEUR:
            sub_proto = tvb_get_guint8(tvb, offset);

            if ((sub_proto >= 0x45) && (sub_proto <= 0x4e)) {
                /* this is most likely an IPv4 packet
                * we can exclude 0x40 - 0x44 because the minimum header size is 20 octets
                * 0x4f is excluded because PPP protocol type "IPv6 header compression"
                * with protocol field compression is more likely than a plain IPv4 packet with 60 octet header size */

                dissect_gtp_tpdu_by_handle(ip_handle, tvb, pinfo, tree, offset);

            } else if ((sub_proto & 0xf0) == 0x60) {
                /* this is most likely an IPv6 packet */
                dissect_gtp_tpdu_by_handle(ipv6_handle, tvb, pinfo, tree, offset);
            } else {
                if (tvb_reported_length_remaining(tvb, offset)>14) {
                    guint16 eth_type;
                    eth_type = tvb_get_ntohs(tvb, offset+12);
                    if (eth_type == ETHERTYPE_ARP || eth_type == ETHERTYPE_IPv6 || eth_type == ETHERTYPE_IP) {
                        /* guess this is an ethernet PDU based on the eth type field */
                        dissect_gtp_tpdu_by_handle(eth_handle, tvb, pinfo, tree, offset);
                    }
                } else {
#if 0
                    /* This turns out not to be true, remove the code and try to improve it if we get bug reports */
                    /* this seems to be a PPP packet */

                    if (sub_proto == 0xff) {
                        guint8           control_field;
                        /* this might be an address field, even it shouldn't be here */
                        control_field = tvb_get_guint8(tvb, offset + 1);
                        if (control_field == 0x03)
                            /* now we are pretty sure that address and control field are mistakenly inserted -> ignore it for PPP dissection */
                            acfield_len = 2;
                    }

                    next_tvb = tvb_new_subset_remaining(tvb, offset + acfield_len);
                    call_dissector(ppp_handle, next_tvb, pinfo, tree);
#endif
                    proto_tree_add_item(tree, hf_gtp_tpdu_data, tvb, offset, -1, ENC_NA);

                    col_prepend_fstr(pinfo->cinfo, COL_PROTOCOL, "GTP <");
                    col_append_str(pinfo->cinfo, COL_PROTOCOL, ">");
                }
            }
            break;
        case GTP_TPDU_AS_PDCP_LTE:
            dissect_gtp_tpdu_as_pdcp_lte_info(tvb, pinfo, tree, gtp_hdr, offset);
            break;
        case GTP_TPDU_AS_PDCP_NR:
            dissect_gtp_tpsu_as_pdcp_nr_info(tvb, pinfo, tree, gtp_hdr, offset);
            break;
        case GTP_TPDU_AS_SYNC:
            dissect_gtp_tpdu_by_handle(sync_handle, tvb, pinfo, tree, offset + acfield_len);
            break;
        case GTP_TPDU_AS_ETHERNET:
            dissect_gtp_tpdu_by_handle(eth_handle, tvb, pinfo, tree, offset);
            break;
        case GTP_TPDU_AS_CUSTOM:
            /* Call a custom dissector if available */
            if (gtp_tpdu_custom_handle ||
                 (gtp_tpdu_custom_handle = find_dissector("gtp_tpdu_custom"))) {
                dissect_gtp_tpdu_by_handle(gtp_tpdu_custom_handle, tvb, pinfo, tree, offset);
            } else {
                proto_tree_add_item(tree, hf_gtp_tpdu_data, tvb, offset, -1, ENC_NA);
            }
            break;
        default:
            proto_tree_add_item(tree, hf_gtp_tpdu_data, tvb, offset, -1, ENC_NA);
            break;
        }
    }

    tap_queue_packet(gtpv1_tap,pinfo, gtp_hdr);

    return tvb_reported_length(tvb);
}

static int
dissect_gtpprime(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree,
                void *private_data _U_)
{
    return dissect_gtp_common(tvb, pinfo, tree);
}

static int
dissect_gtp(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree,
            void *private_data _U_)
{
    guint8 version;

    /*
     * Do we have enough data to check the first byte?
     */
    if (!tvb_bytes_exist(tvb, 0, 1)) {
        /* No. */
        return 0;
    }

    /*
     * If this is GTPv2-C call the gtpv2 dissector if present
     * Should this be moved to after the conversation stuff to retain that functionality for GTPv2 ???
     */
    version = tvb_get_guint8(tvb,0)>>5;
    if (version > 2) {
        /* Unknown version - reject the packet */
        return 0;
    }
    if (version == 2) {
        /* GTPv2-C 3GPP TS 29.274 */
        if (gtpv2_handle) {
            call_dissector(gtpv2_handle, tvb, pinfo, tree);
            return tvb_reported_length(tvb);
        }
    }

    return dissect_gtp_common(tvb, pinfo, tree);
}

static void
gtp_init(void)
{
    gtp_session_count = 1;
    session_table = g_hash_table_new(g_int_hash, g_int_equal);
    frame_tree = wmem_tree_new(wmem_file_scope());
}

static void
gtp_cleanup(void)
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
        gtp_info = next;
    }

    /* Free up state attached to the gtp session structures */
    gtp_info_items = NULL;

    if (session_table != NULL) {
        g_hash_table_destroy(session_table);
    }
    session_table = NULL;
}

void
proto_register_gtp(void)
{
    module_t *gtp_module;
    expert_module_t* expert_gtp;
    guint     i;
    guint     last_offset;

    static hf_register_info hf_gtp[] = {

        {&hf_gtp_ie_id,
         { "IE Id", "gtp.ie_id",
           FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gtp_val_ext, 0x0,
           NULL, HFILL}
        },
        {&hf_gtp_response_in,
         { "Response In", "gtp.response_in",
           FT_FRAMENUM, BASE_NONE, NULL, 0x0,
           "The response to this GTP request is in this frame", HFILL}
        },
        {&hf_gtp_response_to,
         { "Response To", "gtp.response_to",
           FT_FRAMENUM, BASE_NONE, NULL, 0x0,
           "This is a response to the GTP request in this frame", HFILL}
        },
        {&hf_gtp_time,
         { "Time", "gtp.time",
           FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
           "The time between the Request and the Response", HFILL}
        },
        {&hf_gtp_apn,
         { "APN", "gtp.apn",
           FT_STRING, BASE_NONE, NULL, 0,
           "Access Point Name", HFILL}
        },
        {&hf_gtp_cause,
         { "Cause", "gtp.cause",
           FT_UINT8, BASE_DEC|BASE_EXT_STRING, &cause_type_ext, 0,
           "Cause of operation", HFILL}
        },
        {&hf_gtp_chrg_char,
         { "Charging characteristics", "gtp.chrg_char",
           FT_UINT16, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_chrg_char_s,
         { "Spare", "gtp.chrg_char_s",
           FT_UINT16, BASE_DEC, NULL, GTP_MASK_CHRG_CHAR_S,
           NULL, HFILL}
        },
        {&hf_gtp_chrg_char_n,
         { "Normal charging", "gtp.chrg_char_n",
           FT_UINT16, BASE_DEC, NULL, GTP_MASK_CHRG_CHAR_N,
           NULL, HFILL}
        },
        {&hf_gtp_chrg_char_p,
         { "Prepaid charging", "gtp.chrg_char_p",
           FT_UINT16, BASE_DEC, NULL, GTP_MASK_CHRG_CHAR_P,
           NULL, HFILL}
        },
        {&hf_gtp_chrg_char_f,
         { "Flat rate charging", "gtp.chrg_char_f",
           FT_UINT16, BASE_DEC, NULL, GTP_MASK_CHRG_CHAR_F,
           NULL, HFILL}
        },
        {&hf_gtp_chrg_char_h,
         { "Hot billing charging", "gtp.chrg_char_h",
           FT_UINT16, BASE_DEC, NULL, GTP_MASK_CHRG_CHAR_H,
           NULL, HFILL}
        },
        {&hf_gtp_chrg_char_r,
         { "Reserved", "gtp.chrg_char_r",
           FT_UINT16, BASE_DEC, NULL, GTP_MASK_CHRG_CHAR_R,
           NULL, HFILL}
        },
        {&hf_gtp_chrg_id,
         { "Charging ID", "gtp.chrg_id",
           FT_UINT32, BASE_HEX_DEC, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_chrg_ipv4,
         { "CG address IPv4", "gtp.chrg_ipv4",
           FT_IPv4, BASE_NONE, NULL, 0,
           "Charging Gateway address IPv4", HFILL}
        },
        {&hf_gtp_chrg_ipv6,
         { "CG address IPv6", "gtp.chrg_ipv6",
           FT_IPv6, BASE_NONE, NULL, 0,
           "Charging Gateway address IPv6", HFILL}
        },
        {&hf_gtp_ext_flow_label,
         { "Flow Label Data I", "gtp.ext_flow_label",
           FT_UINT16, BASE_HEX, NULL, 0,
           "Flow label data", HFILL}
        },
        {&hf_gtp_ext_id,
         { "Extension identifier", "gtp.ext_id",
           FT_UINT16, BASE_ENTERPRISES, STRINGS_ENTERPRISES, 0,
           "Private Enterprise number", HFILL}
        },
        {&hf_gtp_ext_val,
         { "Extension value", "gtp.ext_val",
           FT_BYTES, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_flags,
         { "Flags", "gtp.flags",
           FT_UINT8, BASE_HEX, NULL, 0,
           "Ver/PT/Spare...", HFILL}
        },
        {&hf_gtp_ext_hdr,
         { "Extension header", "gtp.ext_hdr",
           FT_NONE, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_ext_hdr_next,
         { "Next extension header type", "gtp.ext_hdr.next",
           FT_UINT8, BASE_HEX, VALS(next_extension_header_fieldvals), 0,
           NULL, HFILL}
        },
        {&hf_gtp_ext_hdr_ran_cont,
         { "RAN Container", "gtp.ext_hdr.ran_cont",
           FT_BYTES, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_ext_hdr_spare_bits,
         { "Spare", "gtp.ext_hdr.spare_bits",
           FT_UINT8, BASE_HEX, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_ext_hdr_spare_bytes,
         { "Spare", "gtp.ext_hdr.spare_bytes",
           FT_BYTES, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_ext_hdr_long_pdcp_sn,
         { "Long PDCP Sequence Number", "gtp.ext_hdr.long_pdcp_sn",
           FT_UINT24, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_ext_hdr_xw_ran_cont,
         { "Xw RAN Container", "gtp.ext_hdr.xw_ran_cont",
           FT_BYTES, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },

        { &hf_gtp_ext_hdr_pdu_ses_cont_pdu_type,
         { "PDU Type", "gtp.ext_hdr.pdu_ses_con.pdu_type",
           FT_UINT8, BASE_DEC, VALS(gtp_ext_hdr_pdu_ses_cont_pdu_type_vals), 0xf0,
           NULL, HFILL}
        },
        { &hf_gtp_ext_hdr_pdu_ses_cont_ppp,
         { "Paging Policy Presence (PPP)", "gtp.ext_hdr.pdu_ses_cont.ppp",
           FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x80,
           NULL, HFILL}
        },
        { &hf_gtp_ext_hdr_pdu_ses_cont_rqi,
         { "Reflective QoS Indicator (RQI)", "gtp.ext_hdr.pdu_ses_cont.rqi",
           FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x40,
           NULL, HFILL}
        },
        { &hf_gtp_ext_hdr_pdu_ses_cont_qos_flow_id,
         { "QoS Flow Identifier (QFI)", "gtp.ext_hdr.pdu_ses_con.qos_flow_id",
           FT_UINT8, BASE_DEC, NULL, 0x3f,
           NULL, HFILL}
        },
        { &hf_gtp_ext_hdr_pdu_ses_cont_ppi,
         { "Paging Policy Indicator (PPI)", "gtp.ext_hdr.pdu_ses_cont.ppi",
           FT_UINT8, BASE_DEC, NULL, 0xe0,
           NULL, HFILL}
        },

        {&hf_pdcp_cont,
         { "PDCP Protocol", "gtp.pdcp",
           FT_BYTES, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_ext_hdr_pdcpsn,
         { "PDCP Sequence Number", "gtp.ext_hdr.pdcp_sn",
           FT_UINT16, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_ext_hdr_udp_port,
         { "UDP Port", "gtp.ext_hdr.udp_port",
           FT_UINT16, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_ext_hdr_length,
         { "Extension Header Length", "gtp.ext_hdr.length",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_flags_ver,
         { "Version", "gtp.flags.version",
           FT_UINT8, BASE_DEC, VALS(ver_types), GTP_VER_MASK,
           "GTP Version", HFILL}
        },
        {&hf_gtp_prime_flags_ver,
         { "Version", "gtp.prim.flags.version",
           FT_UINT8, BASE_DEC,NULL, GTP_VER_MASK,
           "GTP' Version", HFILL}
        },
        {&hf_gtp_flags_pt,
         { "Protocol type", "gtp.flags.payload",
           FT_UINT8, BASE_DEC, VALS(pt_types), GTP_PT_MASK,
           NULL, HFILL}
        },
        {&hf_gtp_flags_spare1,
         { "Reserved", "gtp.flags.reserved",
           FT_UINT8, BASE_DEC, NULL, GTP_SPARE1_MASK,
           "Reserved (shall be sent as '111' )", HFILL}
        },
        {&hf_gtp_flags_hdr_length,
         { "Header length", "gtp.flags.hdr_length",
           FT_BOOLEAN, 8,  TFS(&gtp_hdr_length_vals), 0x01,
           NULL, HFILL}
        },
        {&hf_gtp_flags_snn,
         { "Is SNDCP N-PDU included?", "gtp.flags.snn",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), GTP_SNN_MASK,
           "Is SNDCP N-PDU LLC Number included? (1 = yes, 0 = no)", HFILL}
        },
        {&hf_gtp_flags_spare2,
         { "Reserved", "gtp.flags.reserved",
           FT_UINT8, BASE_DEC, NULL, GTP_SPARE2_MASK,
           "Reserved (shall be sent as '1' )", HFILL}
        },
        {&hf_gtp_flags_e,
         { "Is Next Extension Header present?", "gtp.flags.e",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), GTP_E_MASK,
           "Is Next Extension Header present? (1 = yes, 0 = no)", HFILL}
        },
        {&hf_gtp_flags_s,
         { "Is Sequence Number present?", "gtp.flags.s",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), GTP_S_MASK,
           "Is Sequence Number present? (1 = yes, 0 = no)", HFILL}
        },
        {&hf_gtp_flags_pn,
         { "Is N-PDU number present?", "gtp.flags.pn",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), GTP_PN_MASK,
           "Is N-PDU number present? (1 = yes, 0 = no)", HFILL}
        },
        {&hf_gtp_flow_ii,
         { "Flow Label Data II", "gtp.flow_ii",
           FT_UINT16, BASE_DEC, NULL, 0,
           "Downlink flow label data", HFILL}
        },
        {&hf_gtp_flow_label,
         { "Flow label", "gtp.flow_label",
           FT_UINT16, BASE_HEX, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_flow_sig,
         { "Flow label Signalling", "gtp.flow_sig",
           FT_UINT16, BASE_HEX, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_gsn_addr_len,
         { "GSN Address Length", "gtp.gsn_addr_len",
           FT_UINT8, BASE_DEC, NULL, GTP_EXT_GSN_ADDR_LEN_MASK,
           NULL, HFILL}
        },
        {&hf_gtp_gsn_addr_type,
         { "GSN Address Type", "gtp.gsn_addr_type",
           FT_UINT8, BASE_DEC, VALS(gsn_addr_type), GTP_EXT_GSN_ADDR_TYPE_MASK,
           NULL, HFILL}
        },
        {&hf_gtp_gsn_ipv4,
         { "GSN address IPv4", "gtp.gsn_ipv4",
           FT_IPv4, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_gsn_ipv6,
         { "GSN address IPv6", "gtp.gsn_ipv6",
           FT_IPv6, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_length,
         { "Length", "gtp.length",
           FT_UINT16, BASE_DEC, NULL, 0,
           "Length (i.e. number of octets after TID or TEID)", HFILL}
        },
        {&hf_gtp_map_cause,
         { "MAP cause", "gtp.map_cause",
           FT_UINT8, BASE_DEC, VALS(gsm_old_GSMMAPLocalErrorcode_vals), 0,
           NULL, HFILL}
        },
        {&hf_gtp_message_type,
         { "Message Type", "gtp.message",
           FT_UINT8, BASE_HEX|BASE_EXT_STRING, &gtp_message_type_ext, 0x0,
           "GTP Message Type", HFILL}
        },
        {&hf_gtp_ms_reason,
         { "MS not reachable reason", "gtp.ms_reason",
           FT_UINT8, BASE_DEC, VALS(ms_not_reachable_type), 0,
           NULL, HFILL}
        },
        {&hf_gtp_ms_valid,
         { "MS validated", "gtp.ms_valid",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_gtp_node_ipv4,
         { "Node address IPv4", "gtp.node_ipv4",
           FT_IPv4, BASE_NONE, NULL, 0,
           "Recommended node address IPv4", HFILL}
        },
        {&hf_gtp_node_ipv6,
         { "Node address IPv6", "gtp.node_ipv6",
           FT_IPv6, BASE_NONE, NULL, 0,
           "Recommended node address IPv6", HFILL}
        },
        {&hf_gtp_node_name,
         { "Node name", "gtp.node_name",
           FT_UINT_STRING, BASE_NONE, NULL, 0,
           "Diameter Identity of the node", HFILL}
        },
        {&hf_gtp_node_realm,
         { "Node realm", "gtp.node_realm",
           FT_UINT_STRING, BASE_NONE, NULL, 0,
           "Diameter Realm Identity of the node", HFILL}
        },
        {&hf_gtp_npdu_number,
         { "N-PDU Number", "gtp.npdu_number",
           FT_UINT8, BASE_HEX, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_nsapi,
         { "NSAPI", "gtp.nsapi",
           FT_UINT8, BASE_DEC, NULL, 0x0f,
           "Network layer Service Access Point Identifier", HFILL}
        },
        {&hf_gtp_qos_version,
         { "Version", "gtp.qos_version",
           FT_UINT8, BASE_HEX, NULL, 0,
           "Version of the QoS Profile", HFILL}
        },
        {&hf_gtp_qos_spare1,
         { "Spare", "gtp.qos_spare1",
           FT_UINT8, BASE_DEC, NULL, GTP_EXT_QOS_SPARE1_MASK,
           "Spare (shall be sent as '00' )", HFILL}
        },
        {&hf_gtp_qos_delay,
         { "QoS delay", "gtp.qos_delay",
           FT_UINT8, BASE_DEC, VALS(qos_delay_type), GTP_EXT_QOS_DELAY_MASK,
           "Quality of Service Delay Class", HFILL}
        },
        {&hf_gtp_qos_reliability,
         { "QoS reliability", "gtp.qos_reliability",
           FT_UINT8, BASE_DEC, VALS(qos_reliability_type), GTP_EXT_QOS_RELIABILITY_MASK,
           "Quality of Service Reliability Class", HFILL}
        },
        {&hf_gtp_qos_peak,
         { "QoS peak", "gtp.qos_peak",
           FT_UINT8, BASE_DEC, VALS(qos_peak_type), GTP_EXT_QOS_PEAK_MASK,
           "Quality of Service Peak Throughput", HFILL}
        },
        {&hf_gtp_qos_spare2,
         { "Spare", "gtp.qos_spare2",
           FT_UINT8, BASE_DEC, NULL, GTP_EXT_QOS_SPARE2_MASK,
           "Spare (shall be sent as 0)", HFILL}
        },
        {&hf_gtp_qos_precedence,
         { "QoS precedence", "gtp.qos_precedence",
           FT_UINT8, BASE_DEC, VALS(qos_precedence_type), GTP_EXT_QOS_PRECEDENCE_MASK,
           "Quality of Service Precedence Class", HFILL}
        },
        {&hf_gtp_qos_spare3,
         { "Spare", "gtp.qos_spare3",
           FT_UINT8, BASE_DEC, NULL, GTP_EXT_QOS_SPARE3_MASK,
           "Spare (shall be sent as '000' )", HFILL}
        },
        {&hf_gtp_qos_mean,
         { "QoS mean", "gtp.qos_mean",
           FT_UINT8, BASE_DEC|BASE_EXT_STRING, &qos_mean_type_ext, GTP_EXT_QOS_MEAN_MASK,
           "Quality of Service Mean Throughput", HFILL}
        },
        {&hf_gtp_qos_al_ret_priority,
         { "Allocation/Retention priority", "gtp.qos_al_ret_priority",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_qos_traf_class,
         { "Traffic class", "gtp.qos_traf_class",
           FT_UINT8, BASE_DEC, VALS(qos_traf_class), GTP_EXT_QOS_TRAF_CLASS_MASK,
           NULL, HFILL}
        },
        {&hf_gtp_qos_del_order,
         { "Delivery order", "gtp.qos_del_order",
           FT_UINT8, BASE_DEC, VALS(qos_del_order), GTP_EXT_QOS_DEL_ORDER_MASK,
           NULL, HFILL}
        },
        {&hf_gtp_qos_del_err_sdu,
         { "Delivery of erroneous SDU", "gtp.qos_del_err_sdu",
           FT_UINT8, BASE_DEC, VALS(qos_del_err_sdu), GTP_EXT_QOS_DEL_ERR_SDU_MASK,
           NULL, HFILL}
        },
        {&hf_gtp_qos_max_sdu_size,
         { "Maximum SDU size", "gtp.qos_max_sdu_size",
           FT_UINT8, BASE_DEC, VALS(qos_max_sdu_size), 0,
           NULL, HFILL}
        },
        {&hf_gtp_qos_max_ul,
         { "Maximum bit rate for uplink", "gtp.qos_max_ul",
           FT_UINT8, BASE_DEC, VALS(qos_max_ul), 0,
           NULL, HFILL}
        },
        {&hf_gtp_qos_max_dl,
         { "Maximum bit rate for downlink", "gtp.qos_max_dl",
           FT_UINT8, BASE_DEC, VALS(qos_max_dl), 0,
           NULL, HFILL}
        },
        {&hf_gtp_qos_res_ber,
         { "Residual BER", "gtp.qos_res_ber",
           FT_UINT8, BASE_DEC, VALS(qos_res_ber), GTP_EXT_QOS_RES_BER_MASK,
           "Residual Bit Error Rate", HFILL}
        },
        {&hf_gtp_qos_sdu_err_ratio,
         { "SDU Error ratio", "gtp.qos_sdu_err_ratio",
           FT_UINT8, BASE_DEC, VALS(qos_sdu_err_ratio), GTP_EXT_QOS_SDU_ERR_RATIO_MASK,
           NULL,
           HFILL}
        },
        {&hf_gtp_qos_trans_delay,
         { "Transfer delay", "gtp.qos_trans_delay",
           FT_UINT8, BASE_DEC|BASE_EXT_STRING, &qos_trans_delay_ext, GTP_EXT_QOS_TRANS_DELAY_MASK,
           NULL, HFILL}
        },
        {&hf_gtp_qos_traf_handl_prio,
         { "Traffic handling priority", "gtp.qos_traf_handl_prio",
           FT_UINT8, BASE_DEC, VALS(qos_traf_handl_prio), GTP_EXT_QOS_TRAF_HANDL_PRIORITY_MASK,
           NULL, HFILL}
        },
        {&hf_gtp_qos_guar_ul,
         { "Guaranteed bit rate for uplink", "gtp.qos_guar_ul",
           FT_UINT8, BASE_DEC, VALS(qos_guar_ul), 0,
           NULL, HFILL}
        },
        {&hf_gtp_qos_guar_dl,
         { "Guaranteed bit rate for downlink", "gtp.qos_guar_dl",
           FT_UINT8, BASE_DEC, VALS(qos_guar_dl), 0,
           NULL, HFILL}
        },
        {&hf_gtp_qos_spare4,
         { "Spare", "gtp.qos_spare4",
           FT_UINT8, BASE_DEC, NULL, GTP_EXT_QOS_SPARE4_MASK,
           "Spare (shall be sent as '000' )", HFILL}
        },
        {&hf_gtp_qos_sig_ind,
         { "Signalling Indication", "gtp.sig_ind",
           FT_BOOLEAN, 8, TFS(&gtp_sig_ind), GTP_EXT_QOS_SIG_IND_MASK,
           NULL, HFILL}
        },
        {&hf_gtp_qos_src_stat_desc,
         { "Source Statistics Descriptor", "gtp.src_stat_desc",
           FT_UINT8, BASE_DEC, VALS(src_stat_desc_vals), GTP_EXT_QOS_SRC_STAT_DESC_MASK,
           NULL, HFILL}
        },
        { &hf_gtp_qos_arp,
          {"Allocation/Retention Priority", "gtp.qos_arp",
          FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL}
        },
        { &hf_gtp_qos_arp_pci,
          {"Pre-emption Capability (PCI)", "gtp.qos_arp_pci",
          FT_BOOLEAN, 16, TFS(&tfs_disabled_enabled), 0x40,
          NULL, HFILL}
        },
        { &hf_gtp_qos_arp_pl,
          {"Priority Level", "gtp.qos_arp_pl",
          FT_UINT16, BASE_DEC, NULL, 0x3c,
          NULL, HFILL}
        },
        { &hf_gtp_qos_arp_pvi,
          {"Pre-emption Vulnerability (PVI)", "gtp.qos_arp_pvi",
          FT_BOOLEAN, 16, TFS(&tfs_disabled_enabled), 0x01,
          NULL, HFILL}
        },
        {&hf_gtp_qos_qci,
         {"QCI", "gtp.qos_qci",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtp_qos_ul_mbr,
         {"Uplink Maximum Bit Rate", "gtp.qos_ul_mbr",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtp_qos_dl_mbr,
         {"Downlink Maximum Bit Rate", "gtp.qos_dl_mbr",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtp_qos_ul_gbr,
         {"Uplink Guaranteed Bit Rate", "gtp.qos_ul_gbr",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtp_qos_dl_gbr,
         {"Downlink Guaranteed Bit Rate", "gtp.qos_dl_gbr",
          FT_UINT64, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtp_qos_ul_apn_ambr,
         {"Uplink APN Aggregate Maximum Bit Rate", "gtp.qos_ul_apn_ambr",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtp_qos_dl_apn_ambr,
         {"Downlink APN Aggregate Maximum Bit Rate", "gtp.qos_dl_apn_ambr",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_gtp_pkt_flow_id,
         { "Packet Flow ID", "gtp.pkt_flow_id",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_ptmsi,
         { "P-TMSI", "gtp.ptmsi",
           FT_UINT32, BASE_DEC_HEX, NULL, 0,
           "Packet-Temporary Mobile Subscriber Identity", HFILL}
        },
        {&hf_gtp_ptmsi_sig,
         { "P-TMSI Signature", "gtp.ptmsi_sig",
           FT_UINT24, BASE_HEX, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_rab_gtpu_dn,
         { "Downlink GTP-U seq number", "gtp.rab_gtp_dn",
           FT_UINT16, BASE_DEC, NULL, 0,
           "Downlink GTP-U sequence number", HFILL}
        },
        {&hf_gtp_rab_gtpu_up,
         { "Uplink GTP-U seq number", "gtp.rab_gtp_up",
           FT_UINT16, BASE_DEC, NULL, 0,
           "Uplink GTP-U sequence number", HFILL}
        },
        {&hf_gtp_rab_pdu_dn,
         { "Downlink next PDCP-PDU seq number", "gtp.rab_pdu_dn",
           FT_UINT16, BASE_DEC, NULL, 0,
           "Downlink next PDCP-PDU sequence number", HFILL}
        },
        {&hf_gtp_rab_pdu_up,
         { "Uplink next PDCP-PDU seq number", "gtp.rab_pdu_up",
           FT_UINT16, BASE_DEC, NULL, 0,
           "Uplink next PDCP-PDU sequence number", HFILL}
        },
        {&hf_gtp_uli_geo_loc_type,
         { "Geographic Location Type", "gtp.geo_loc_type",
           FT_UINT8, BASE_DEC, VALS(geographic_location_type),  0,
           NULL, HFILL}
        },
        {&hf_gtp_cgi_ci,
         { "Cell ID (CI)", "gtp.cgi_ci",
           FT_UINT16, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_sai_sac,
         { "Service Area Code (SAC)", "gtp.sai_sac",
           FT_UINT16, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_rai_rac,
         { "Routing Area Code (RAC)", "gtp.rai_rac",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_lac,
         { "Location Area Code (LAC)", "gtp.lac",
           FT_UINT16, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_gtp_tac,
          {"TAC", "gtp.tac",
           FT_UINT16, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_ranap_cause,
         { "RANAP cause", "gtp.ranap_cause",
           FT_UINT8, BASE_DEC|BASE_EXT_STRING, &ranap_cause_type_ext, 0,
           NULL, HFILL}
        },
        {&hf_gtp_recovery,
         { "Recovery", "gtp.recovery",
           FT_UINT8, BASE_DEC, NULL, 0,
           "Restart counter", HFILL}
        },
        {&hf_gtp_reorder,
         { "Reordering required", "gtp.reorder",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_gtp_rnc_ipv4,
         { "RNC address IPv4", "gtp.rnc_ipv4",
           FT_IPv4, BASE_NONE, NULL, 0,
           "Radio Network Controller address IPv4", HFILL}
        },
        {&hf_gtp_rnc_ipv6,
         { "RNC address IPv6", "gtp.rnc_ipv6",
           FT_IPv6, BASE_NONE, NULL, 0,
           "Radio Network Controller address IPv6", HFILL}
        },
        {&hf_gtp_rp,
         { "Radio Priority", "gtp.rp",
           FT_UINT8, BASE_DEC, NULL, GTPv1_EXT_RP_MASK,
           "Radio Priority for uplink tx", HFILL}
        },
        {&hf_gtp_rp_nsapi,
         { "NSAPI in Radio Priority", "gtp.rp_nsapi",
           FT_UINT8, BASE_DEC, NULL, GTPv1_EXT_RP_NSAPI_MASK,
           "Network layer Service Access Point Identifier in Radio Priority", HFILL}
        },
        {&hf_gtp_rp_sms,
         { "Radio Priority SMS", "gtp.rp_sms",
           FT_UINT8, BASE_DEC, NULL, 0,
           "Radio Priority for MO SMS", HFILL}
        },
        {&hf_gtp_rp_spare,
         { "Reserved", "gtp.rp_spare",
           FT_UINT8, BASE_DEC, NULL, GTPv1_EXT_RP_SPARE_MASK,
           "Spare bit", HFILL}
        },
        {&hf_gtp_sel_mode,
         { "Selection mode", "gtp.sel_mode",
           FT_UINT8, BASE_DEC, VALS(sel_mode_type), 0x03,
           NULL, HFILL}
        },
        {&hf_gtp_seq_number,
         { "Sequence number", "gtp.seq_number",
           FT_UINT16, BASE_HEX_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_gtp_session,
        { "Session", "gtp.session",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
        },
        {&hf_gtp_sndcp_number,
         { "SNDCP N-PDU LLC Number", "gtp.sndcp_number",
           FT_UINT8, BASE_HEX, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_tear_ind,
         { "Teardown Indicator", "gtp.tear_ind",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_gtp_teid,
         { "TEID", "gtp.teid",
           FT_UINT32, BASE_HEX_DEC, NULL, 0,
           "Tunnel Endpoint Identifier", HFILL}
        },
        {&hf_gtp_teid_cp,
         { "TEID Control Plane", "gtp.teid_cp",
           FT_UINT32, BASE_HEX_DEC, NULL, 0,
           "Tunnel Endpoint Identifier Control Plane", HFILL}
        },
        {&hf_gtp_uplink_teid_cp,
         { "Uplink TEID Control Plane", "gtp.uplink_teid_cp",
           FT_UINT32, BASE_HEX_DEC, NULL, 0,
           "Uplink Tunnel Endpoint Identifier Control Plane", HFILL}
        },
        {&hf_gtp_teid_data,
         { "TEID Data I", "gtp.teid_data",
           FT_UINT32, BASE_HEX_DEC, NULL, 0,
           "Tunnel Endpoint Identifier Data I", HFILL}
        },
        {&hf_gtp_uplink_teid_data,
         { "Uplink TEID Data I", "gtp.uplink_teid_data",
           FT_UINT32, BASE_HEX_DEC, NULL, 0,
           "UplinkTunnel Endpoint Identifier Data I", HFILL}
        },
        {&hf_gtp_teid_ii,
         { "TEID Data II", "gtp.teid_ii",
           FT_UINT32, BASE_HEX_DEC, NULL, 0,
           "Tunnel Endpoint Identifier Data II", HFILL}
        },
        {&hf_gtp_tid,
         { "TID", "gtp.tid",
           FT_STRING, BASE_NONE, NULL, 0,
           "Tunnel Identifier", HFILL}
        },
        {&hf_gtp_tlli,
         { "TLLI", "gtp.tlli",
           FT_UINT32, BASE_HEX, NULL, 0,
           "Temporary Logical Link Identity", HFILL}
        },
        {&hf_gtp_tr_comm,
         { "Packet transfer command", "gtp.tr_comm",
           FT_UINT8, BASE_DEC, VALS(tr_comm_type), 0,
           NULL, HFILL}
        },
        {&hf_gtp_trace_ref,
         { "Trace reference", "gtp.trace_ref",
           FT_UINT16, BASE_HEX, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_trace_type,
         { "Trace type", "gtp.trace_type",
           FT_UINT16, BASE_HEX, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_user_addr_pdp_org,
         { "PDP type organization", "gtp.user_addr_pdp_org",
           FT_UINT8, BASE_DEC, VALS(pdp_org_type), 0,
           NULL, HFILL}
        },
        {&hf_gtp_user_addr_pdp_type,
         { "PDP type number", "gtp.user_addr_pdp_type",
           FT_UINT8, BASE_HEX, VALS(pdp_type), 0,
           NULL, HFILL}
        },
        {&hf_gtp_user_ipv4,
         { "End user address IPv4", "gtp.user_ipv4",
           FT_IPv4, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_user_ipv6,
         { "End user address IPv6", "gtp.user_ipv6",
           FT_IPv6, BASE_NONE, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_security_mode,
         { "Security Mode", "gtp.security_mode",
           FT_UINT8, BASE_DEC, VALS(mm_sec_modep), 0xc0,
           NULL, HFILL}
        },
        {&hf_gtp_no_of_vectors,
         { "No of Vectors", "gtp.no_of_vectors",
           FT_UINT8, BASE_DEC, NULL, 0x38,
           NULL, HFILL}
        },
        {&hf_gtp_cipher_algorithm,
         { "Cipher Algorithm", "gtp.cipher_algorithm",
           FT_UINT8, BASE_DEC, VALS(gtp_cipher_algorithm), 0x07,
           NULL, HFILL}
        },
        {&hf_gtp_cksn_ksi,
         { "Ciphering Key Sequence Number (CKSN)/Key Set Identifier (KSI)", "gtp.cksn_ksi",
           FT_UINT8, BASE_DEC, NULL, 0x07,
           "CKSN/KSI", HFILL}
        },
        {&hf_gtp_cksn,
         { "Ciphering Key Sequence Number (CKSN)", "gtp.cksn",
           FT_UINT8, BASE_DEC, NULL, 0x07,
           "CKSN", HFILL}
        },
        {&hf_gtp_ksi,
         { "Key Set Identifier (KSI)", "gtp.ksi",
           FT_UINT8, BASE_DEC, NULL, 0x07,
           "KSI", HFILL}
        },
        {&hf_gtp_ext_length,
         { "Length", "gtp.ext_length",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           "IE Length", HFILL}
        },
        {&hf_gtp_utran_field,
         { "UTRAN Transparent Field", "gtp.utran_field",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_gtp_ext_apn_res,
         { "Restriction Type", "gtp.ext_apn_res",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_gtp_ext_rat_type,
         { "RAT Type", "gtp.ext_rat_type",
           FT_UINT8, BASE_DEC, VALS(gtp_ext_rat_type_vals), 0x0,
           NULL, HFILL}
        },
        {&hf_gtp_ext_imeisv,
         { "IMEI(SV)", "gtp.ext_imeisv",
           FT_STRING, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        { &hf_gtp_target_rnc_id,
          { "targetRNC-ID", "gtp.targetRNC_ID",
            FT_UINT16, BASE_HEX, NULL, 0x0fff,
            NULL, HFILL }
        },
        { &hf_gtp_target_ext_rnc_id,
          { "Extended RNC-ID", "gtp.target_ext_RNC_ID",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        {&hf_gtp_bssgp_cause,
         { "BSSGP Cause", "gtp.bssgp_cause",
           FT_UINT8, BASE_DEC|BASE_EXT_STRING, &bssgp_cause_vals_ext, 0,
           NULL, HFILL}
        },
        { &hf_gtp_bssgp_ra_discriminator,
          { "Routing Address Discriminator", "gtp.bssgp.rad",
            FT_UINT8, BASE_DEC, VALS(gtp_bssgp_ra_discriminator_vals), 0x0f,
            NULL, HFILL }
        },
        {&hf_gtp_sapi,
         { "PS Handover XID SAPI", "gtp.ps_handover_xid_sapi",
           FT_UINT8, BASE_DEC, NULL, 0x0F,
           "SAPI", HFILL}
        },
        {&hf_gtp_xid_par_len,
         { "PS Handover XID parameter length", "gtp.ps_handover_xid_par_len",
           FT_UINT8, BASE_DEC, NULL, 0xFF,
           "XID parameter length", HFILL}
        },
        {&hf_gtp_rep_act_type,
         { "Action", "gtp.ms_inf_chg_rep_act",
           FT_UINT8, BASE_DEC, VALS(chg_rep_act_type_vals), 0xFF,
           NULL, HFILL}
        },
        {&hf_gtp_correlation_id,
         { "Correlation-ID", "gtp.correlation_id",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_earp_pci,
         { "PCI Pre-emption Capability", "gtp.EARP_pre_emption_Capability",
           FT_BOOLEAN, 8, TFS(&tfs_disabled_enabled), 0x40,
           NULL, HFILL}
        },
        {&hf_gtp_earp_pl,
         { "PL Priority Level", "gtp.EARP_priority_level",
           FT_UINT8, BASE_DEC, NULL, 0x3C,
           NULL, HFILL}
        },
        {&hf_gtp_earp_pvi,
         { "PVI Pre-emption Vulnerability", "gtp.EARP_pre_emption_par_vulnerability",
           FT_BOOLEAN, 8, TFS(&tfs_disabled_enabled), 0x01,
           NULL, HFILL}
        },
        {&hf_gtp_ext_comm_flags_uasi,
         { "UASI", "gtp.ext_comm_flags.uasi",
           FT_BOOLEAN, 8, NULL, 0x80,
           NULL, HFILL}
        },
        {&hf_gtp_ext_comm_flags_bdwi,
         { "BDWI", "gtp.ext_comm_flags.bdwi",
           FT_BOOLEAN, 8, NULL, 0x40,
           NULL, HFILL}
        },
        {&hf_gtp_ext_comm_flags_pcri,
         { "PCRI", "gtp.ext_comm_flags.pcri",
           FT_BOOLEAN, 8, NULL, 0x20,
           NULL, HFILL}
        },
        {&hf_gtp_ext_comm_flags_vb,
         { "VB", "gtp.ext_comm_flags.vb",
           FT_BOOLEAN, 8, NULL, 0x10,
           NULL, HFILL}
        },
        {&hf_gtp_ext_comm_flags_retloc,
         { "RetLoc", "gtp.ext_comm_flags.retloc",
           FT_BOOLEAN, 8, NULL, 0x08,
           NULL, HFILL}
        },
        {&hf_gtp_ext_comm_flags_cpsr,
         { "CPSR", "gtp.ext_comm_flags.cpsr",
           FT_BOOLEAN, 8, NULL, 0x04,
           NULL, HFILL}
        },
        {&hf_gtp_ext_comm_flags_ccrsi,
         { "CCRSI", "gtp.ext_comm_flags.ccrsi",
           FT_BOOLEAN, 8, NULL, 0x02,
           NULL, HFILL}
        },
        {&hf_gtp_ext_comm_flags_unauthenticated_imsi,
         { "Unauthenticated IMSI", "gtp.ext_comm_flags.unauthenticated_imsi",
           FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}
        },
        {&hf_gtp_csg_id,
         { "CSG ID", "gtp.csg_id",
           FT_UINT32, BASE_DEC, NULL, 0x07FFFFFF,
           NULL, HFILL}
        },
        {&hf_gtp_access_mode,
         { "Access Mode", "gtp.access_mode",
           FT_UINT8, BASE_DEC, VALS(gtp_access_mode_vals), 0xC0,
           NULL, HFILL }
        },
        {&hf_gtp_cmi,
         { "CSG Membership Indication (CMI)", "gtp.cmi",
           FT_BOOLEAN, 8, TFS(&tfs_no_yes), 0x01,
           NULL, HFILL}
        },
        {&hf_gtp_csg_inf_rep_act_ucicsg,
         { "UCICSG", "gtp.csg_info_rep_act.ucicsg",
           FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
           "Report UCI when the UE enters/leaves/accesses CSG Cell",
           HFILL}
        },
        {&hf_gtp_csg_inf_rep_act_ucishc,
         { "UCISHC", "gtp.csg_info_rep_act.ucishc",
           FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
           "Report UCI when the UE enters/leaves/accesses Subscribed Hybrid Cell",
           HFILL}
        },
        {&hf_gtp_csg_inf_rep_act_uciuhc,
         { "UCIUHC", "gtp.csg_info_rep_act.uciuhc",
           FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04,
           "Report UCI when the UE enters/leaves/accesses Unsubscribed Hybrid Cell",
           HFILL}
        },
        {&hf_gtp_ext_comm_flags_II_pnsi,
         { "PNSI", "gtp.ext_comm_flags_II_pnsi",
           FT_UINT8, BASE_DEC, NULL, 0x01,
           NULL, HFILL}
        },
        {&hf_gtp_ext_comm_flags_II_dtci,
         { "DTCI", "gtp.ext_comm_flags_II_dtci",
           FT_BOOLEAN, 8, NULL, 0x02,
           NULL, HFILL}
        },
        {&hf_gtp_ext_comm_flags_II_pmtsmi,
         { "PMTSMI", "gtp.ext_comm_flags_II_pmtsmi",
           FT_UINT8, BASE_DEC, NULL, 0x04,
           NULL, HFILL}
        },
        {&hf_gtp_ext_comm_flags_II_spare,
         { "SPARE", "gtp.ext_comm_flags_II_spare",
           FT_UINT8, BASE_HEX, NULL, 0xF8,
           NULL, HFILL}
        },
        {&hf_gtp_ciot_opt_sup_ind_sgni_pdn,
         { "SGNI PDN", "gtp.ciot_opt_sup_ind_sgni_pdn",
           FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}
        },
        {&hf_gtp_ciot_opt_sup_ind_scni_pdn,
         { "SCNI PDN", "gtp.ciot_opt_sup_ind_scni_pdn",
           FT_BOOLEAN, 8, NULL, 0x02,
           NULL, HFILL}
        },
        {&hf_gtp_ciot_opt_sup_ind_spare,
         { "SPARE", "gtp.ciot_opt_sup_ind_spare",
           FT_UINT8, BASE_HEX, NULL, 0xfc,
           NULL, HFILL}
        },
        { &hf_gtp_up_fun_sel_ind_flags_dcnr,
          { "DCNR", "gtp.up_fun_sel_ind_flags_dcnr",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        { &hf_gtp_up_fun_sel_ind_flags_spare,
          { "SPARE", "gtp.up_fun_sel_ind_flags_spare",
            FT_UINT8, BASE_HEX, NULL, 0xfe,
            NULL, HFILL}
        },
        {&hf_gtp_cdr_app,
         { "Application Identifier", "gtp.cdr_app",
           FT_UINT8, BASE_DEC, NULL, 0xf0,
           NULL, HFILL}
        },
        { &hf_gtp_cdr_rel,
          { "Release Identifier", "gtp.cdr_rel",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL}
        },
        { &hf_gtp_cdr_ver,
          { "Version Identifier", "gtp.cdr_ver",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_gtp_cdr_rel_ext,
          { "Release Identifier Extension", "gtp.cdr_rel_ext",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_gtp_cdr_length,
          { "Length", "gtp.cdr_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_gtp_cdr_context,
          { "Context", "gtp.cdr_context",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_gtp_cmn_flg_ppc,
         { "Prohibit Payload Compression", "gtp.cmn_flg.ppc",
           FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL}
        },
        {&hf_gtp_cmn_flg_mbs_srv_type,
         { "MBMS Service Type", "gtp.cmn_flg.mbs_srv_type",
           FT_BOOLEAN, 8, NULL, 0x02,
           NULL, HFILL}
        },
        {&hf_gtp_cmn_flg_mbs_ran_pcd_rdy,
         { "RAN Procedures Ready", "gtp.cmn_flg.mbs_ran_pcd_rdy",
           FT_BOOLEAN, 8, NULL, 0x04,
           NULL, HFILL}
        },
        {&hf_gtp_cmn_flg_mbs_cnt_inf,
         { "MBMS Counting Information", "gtp.cmn_flg.mbs_cnt_inf",
           FT_BOOLEAN, 8, NULL, 0x08,
           NULL, HFILL}
        },
        {&hf_gtp_cmn_flg_no_qos_neg,
         { "No QoS negotiation", "gtp.cmn_flg.no_qos_neg",
           FT_BOOLEAN, 8, NULL, 0x10,
           NULL, HFILL}
        },
        {&hf_gtp_cmn_flg_nrsn,
         { "NRSN bit field", "gtp.cmn_flg.nrsn",
           FT_BOOLEAN, 8, NULL, 0x20,
           NULL, HFILL}
        },
        {&hf_gtp_cmn_flg_upgrd_qos_sup,
         { "Upgrade QoS Supported", "gtp.cmn_flg.upgrd_qos_sup",
           FT_BOOLEAN, 8, NULL, 0x40,
           NULL, HFILL}
        },
        {&hf_gtp_cmn_flg_dual_addr_bearer_flg,
         { "Dual Address Bearer Flag", "gtp.cmn_flg.dual_addr_bearer_flg",
           FT_BOOLEAN, 8, NULL, 0x80,
           NULL, HFILL}
        },
        {&hf_gtp_linked_nsapi,
         { "Linked NSAPI", "gtp.linked_nsapi",
           FT_UINT8, BASE_DEC, NULL, 0xf0,
           NULL, HFILL}
        },
        {&hf_gtp_enh_nsapi,
         { "Enhanced NSAPI", "gtp.enhanced_nsapi",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_gtp_tmgi,
         { "Temporary Mobile Group Identity (TMGI)", "gtp.tmgi",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_gtp_no_of_mbms_sa_codes,
         { "Number of MBMS service area codes", "gtp.no_of_mbms_sa_codes",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           "Number N of MBMS service area codes", HFILL}
        },

        {&hf_gtp_mbms_ses_dur_days,
         { "Estimated session duration days", "gtp.mbms_ses_dur_days",
           FT_UINT24, BASE_DEC, NULL, 0x00007F,
           NULL, HFILL}
        },
        {&hf_gtp_mbms_ses_dur_s,
         { "Estimated session duration seconds", "gtp.mbms_ses_dur_s",
           FT_UINT24, BASE_DEC, NULL, 0xFFFF80,
           NULL, HFILL}
        },
        {&hf_gtp_mbms_sa_code,
         { "MBMS service area code", "gtp.mbms_sa_code",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_gtp_trace_ref2,
         { "Trace Reference2", "gtp.trace_ref2",
           FT_UINT24, BASE_HEX, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_trace_rec_session_ref,
         { "Trace Recording Session Reference", "gtp.trace_rec_session_ref",
           FT_UINT16, BASE_HEX, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_trace_triggers_ggsn_mbms,
         { "MBMS Context", "gtp.trace_triggers.ggsn.mbms",
           FT_BOOLEAN, 8, TFS(&gtp_trace_tfs), 0x2,
           NULL, HFILL}
        },
        {&hf_gtp_trace_triggers_ggsn_pdp,
         { "PDP Context", "gtp.trace_triggers.ggsn.pdp",
           FT_BOOLEAN, 8, TFS(&gtp_trace_tfs), 0x1,
           NULL, HFILL}
        },
        {&hf_gtp_trace_triggers_ggsn,
         { "Triggering events in GGSN", "gtp.trace_triggers.ggsn",
           FT_UINT8, BASE_HEX, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_trace_depth,
         { "Trace Depth", "gtp.trace_depth",
           FT_UINT8, BASE_DEC, VALS(gtp_trace_depth_vals), 0,
           NULL, HFILL}
        },
        {&hf_gtp_trace_loi_ggsn_gmb,
         { "Gmb", "gtp.trace_loi.ggsn.gmb",
           FT_BOOLEAN, 8, TFS(&gtp_trace_tfs), 0x4,
           NULL, HFILL}
        },
        {&hf_gtp_trace_loi_ggsn_gi,
         { "Gi", "gtp.trace_loi.ggsn.gi",
           FT_BOOLEAN, 8, TFS(&gtp_trace_tfs), 0x2,
           NULL, HFILL}
        },
        {&hf_gtp_trace_loi_ggsn_gn,
         { "Gn", "gtp.trace_loi.ggsn.gn",
           FT_BOOLEAN, 8, TFS(&gtp_trace_tfs), 0x1,
           NULL, HFILL}
        },
        {&hf_gtp_trace_loi_ggsn,
         { "List of interfaces in GGSN", "gtp.trace_loi.ggsn",
           FT_UINT8, BASE_HEX, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_trace_activity_control,
         { "Trace Activity Control", "gtp.trace_activity_control",
           FT_UINT8, BASE_DEC, VALS(gtp_trace_activity_control_vals), 0,
           NULL, HFILL}
        },
        {&hf_gtp_hop_count,
         { "Hop Counter", "gtp.hop_count",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_gtp_mbs_2g_3g_ind,
         { "MBMS 2G/3G Indicator", "gtp.mbs_2g_3g_ind",
           FT_UINT8, BASE_DEC, VALS(gtp_mbs_2g_3g_ind_vals), 0x0,
           NULL, HFILL}
        },
        {&hf_gtp_trace_triggers_bm_sc_mbms,
         { "MBMS Multicast service activation", "gtp.trace_triggers.bm_sc.mbms",
           FT_BOOLEAN, 8, TFS(&gtp_trace_tfs), 0x1,
           NULL, HFILL}
        },
        {&hf_gtp_trace_triggers_bm_sc,
         { "Triggering events in BM-SC", "gtp.trace_triggers.bm_sc",
           FT_UINT8, BASE_HEX, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_trace_loi_bm_sc_gmb,
         { "Gmb", "gtp.trace_loi.bm_sc.gmb",
           FT_BOOLEAN, 8, TFS(&gtp_trace_tfs), 0x1,
           NULL, HFILL}
        },
        {&hf_gtp_trace_loi_bm_sc,
         { "List of interfaces in BM-SC", "gtp.trace_loi.bm_sc",
           FT_UINT8, BASE_HEX, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_time_2_dta_tr,
         { "Time to MBMS Data Transfer", "gtp.time_2_dta_tr",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
        },
        {&hf_gtp_target_lac,
         { "Target Location Area Code (LAC)", "gtp.target_lac",
           FT_UINT16, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_target_rac,
         { "Target Routing Area Code (RAC)", "gtp.target_rac",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_target_ci,
         { "Target Cell ID (CI)", "gtp.target_ci",
           FT_UINT16, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_gtp_source_type,
          { "Source Type", "gtp.source_type",
            FT_UINT8, BASE_DEC, VALS(gtp_source_type_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_gtp_source_lac,
         { "Source Location Area Code (LAC)", "gtp.source_lac",
           FT_UINT16, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_source_rac,
         { "Source Routing Area Code (RAC)", "gtp.source_rac",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        {&hf_gtp_source_ci,
         { "Source Cell ID (CI)", "gtp.source_ci",
           FT_UINT16, BASE_DEC, NULL, 0,
           NULL, HFILL}
        },
        { &hf_gtp_source_rnc_id,
          { "Source RNC-ID", "gtp.source.rnc_id",
            FT_UINT16, BASE_DEC, NULL, 0x0fff,
            NULL, HFILL }
        },
        { &hf_gtp_ext_ei,
          { "Error Indication (EI)", "gtp.ei",
            FT_UINT8, BASE_DEC, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_gtp_ext_gcsi,
         { "GPRS-CSI (GCSI)", "gtp.gcsi",
           FT_UINT8, BASE_DEC, NULL, 0x02,
           NULL, HFILL}
        },
        { &hf_gtp_ext_dti,
          { "Direct Tunnel Indicator (DTI)", "gtp.dti",
            FT_UINT8, BASE_DEC, NULL, 0x01,
            NULL, HFILL}
        },
        { &hf_gtp_ra_prio_lcs,
          { "Radio Priority LCS", "gtp.raplcs",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL}
        },
        { &hf_gtp_bcm,
          { "Bearer Control Mode", "gtp.bcm",
            FT_UINT8, BASE_DEC, VALS(gtp_pdp_bcm_type_vals), 0,
            NULL, HFILL}
        },
        { &hf_gtp_fqdn,
          { "FQDN", "gtp.fqdn",
            FT_STRING, BASE_NONE, NULL, 0,
            "Fully Qualified Domain Name", HFILL}
        },
        { &hf_gtp_rim_routing_addr,
          { "RIM Routing Address value", "gtp.rim_routing_addr_val",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL}
        },
        { &hf_gtp_mbms_flow_id,
          { "MBMS Flow Identifier", "gtp.mbms_flow_id",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL}
        },
        { &hf_gtp_mbms_dist_indic,
          { "Distribution Indication", "gtp.mbms_dist_indic",
            FT_UINT8, BASE_DEC, VALS(gtp_mbms_dist_indic_vals), 0x03,
            NULL, HFILL}
        },
        { &hf_gtp_ext_apn_ambr_ul,
          { "APN-AMBR for Uplink", "gtp.apn_ambr_ul",
            FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_kbps, 0x0,
            NULL, HFILL}
        },
        { &hf_gtp_ext_apn_ambr_dl,
          { "APN-AMBR for Downlink", "gtp.apn_ambr_dl",
            FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_kbps, 0x0,
            NULL, HFILL}
        },
        { &hf_gtp_ext_sub_ue_ambr_ul,
          { "Subscribed UE-AMBR for Uplink", "gtp.sub_ue_ambr_ul",
            FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_kbps, 0x0,
            NULL, HFILL}
        },
        { &hf_gtp_ext_sub_ue_ambr_dl,
          { "Subscribed UE-AMBR for Downlink", "gtp.sub_ue_ambr_dl",
            FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_kbps, 0x0,
            NULL, HFILL}
        },
        { &hf_gtp_ext_auth_ue_ambr_ul,
          { "Authorized UE-AMBR for Uplink", "gtp.auth_ue_ambr_ul",
            FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_kbps, 0x0,
            NULL, HFILL}
        },
        { &hf_gtp_ext_auth_ue_ambr_dl,
          { "Authorized UE-AMBR for Downlink", "gtp.auth_ue_ambr_dl",
            FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_kbps, 0x0,
            NULL, HFILL}
        },
        { &hf_gtp_ext_auth_apn_ambr_ul,
          { "Authorized APN-AMBR for Uplink", "gtp.auth_apn_ambr_ul",
            FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_kbps, 0x0,
            NULL, HFILL}
        },
        { &hf_gtp_ext_auth_apn_ambr_dl,
          { "Authorized APN-AMBR for Downlink", "gtp.auth_apn_ambr_dl",
            FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_kbps, 0x0,
            NULL, HFILL}
        },
        { &hf_gtp_ext_ggsn_back_off_time_units,
          { "Timer unit", "gtp.ggsn_back_off_time_units",
            FT_UINT8, BASE_DEC, VALS(gtp_ggsn_back_off_time_units_vals), 0xe0,
            NULL, HFILL}
        },
        { &hf_gtp_ext_ggsn_back_off_timer,
          { "Timer value", "gtp.ggsn_back_off_timer",
            FT_UINT8, BASE_DEC, NULL, 0x1f,
            NULL, HFILL}
        },
        { &hf_gtp_lapi,
          { "LAPI", "gtp.lapi",
            FT_BOOLEAN, 8, TFS(&gtp_lapi_tfs), 0x01,
            "Low Access Priority Indication", HFILL}
        },
        { &hf_gtp_higher_br_16mb_flg,
          { "Higher bitrates than 16 Mbps flag", "gtp.higher_br_16mb_flg",
            FT_UINT8, BASE_DEC, VALS(gtp_higher_br_16mb_flg_vals), 0x0,
            NULL, HFILL}
        },
        { &hf_gtp_max_mbr_apn_ambr_ul,
          { "Max MBR/APN-AMBR for uplink", "gtp.max_mbr_apn_ambr_ul",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_gtp_max_mbr_apn_ambr_dl,
          { "Max MBR/APN-AMBR for downlink", "gtp.max_mbr_apn_ambr_dl",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_gtp_uli_timestamp,
          { "ULI Timestamp", "gtp.uli_timestamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gtp_lhn_id,
          { "Local Home Network ID", "gtp.lhn_id",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}
        },
        { &hf_gtp_sel_entity,
          { "Selection Entity", "gtp.selection_entity",
            FT_UINT8, BASE_DEC, VALS(gtp_sel_entity_vals), 0x3,
            NULL, HFILL}
        },
        { &hf_gtp_ue_usage_type_value,
          { "UE Usage Type value", "gtp.ue_usage_type_value",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_gtp_scef_id_length,
          { "SCEF-ID length", "gtp.scef_id_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_gtp_scef_id,
          { "SCEF-ID", "gtp.scef_id",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_gtp_iov_updates_counter,
          { "IOV_updates counter", "gtp.iov_updates_counter",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_gtp_mapped_ue_usage_type,
          { "Mapped UE Usage Type", "gtp.mapped_ue_usage_type",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },

      { &hf_gtp_rand, { "RAND", "gtp.rand", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_sres, { "SRES", "gtp.sres", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_kc, { "Kc", "gtp.kc", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_xres_length, { "XRES length", "gtp.xres_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_xres, { "XRES", "gtp.xres", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_quintuplet_ciphering_key, { "Quintuplet Ciphering Key", "gtp.quintuplet_ciphering_key", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_quintuplet_integrity_key, { "Quintuplet Integrity Key", "gtp.quintuplet_integrity_key", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_authentication_length, { "Authentication length", "gtp.authentication_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_auth, { "AUTH", "gtp.auth", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_ciphering_key_ck, { "Ciphering key CK", "gtp.ciphering_key_ck", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_integrity_key_ik, { "Integrity key IK", "gtp.integrity_key_ik", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_quintuplets_length, { "Quintuplets length", "gtp.quintuplets_length", FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_ciphering_key_kc, { "Ciphering key Kc", "gtp.ciphering_key_kc", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_container_length, { "Container length", "gtp.container_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_extended_end_user_address, { "Extended End User Address", "gtp.extended_end_user_address", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80, NULL, HFILL }},
      { &hf_gtp_vplmn_address_allowed, { "VPLMN address allowed", "gtp.vplmn_address_allowed", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40, NULL, HFILL }},
      { &hf_gtp_activity_status_indicator, { "Activity Status Indicator", "gtp.activity_status_indicator", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20, NULL, HFILL }},
      { &hf_gtp_reordering_required, { "Reordering required", "gtp.reordering_required", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10, NULL, HFILL }},
      { &hf_gtp_pdp_cntxt_sapi, { "SAPI", "gtp.pdp_cntxt.sapi", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }},
      { &hf_gtp_sequence_number_down, { "Sequence number down", "gtp.sequence_number_down", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_sequence_number_up, { "Sequence number up", "gtp.sequence_number_up", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_send_n_pdu_number, { "Send N-PDU number", "gtp.send_n_pdu_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_receive_n_pdu_number, { "Receive N-PDU number", "gtp.receive_n_pdu_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_uplink_flow_label_signalling, { "Uplink flow label signalling", "gtp.uplink_flow_label_signalling", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_pdp_context_identifier, { "PDP context identifier", "gtp.pdp_context_identifier", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_pdp_organization, { "PDP organization", "gtp.pdp_organization", FT_UINT8, BASE_DEC, VALS(pdp_org_type), 0x0F, NULL, HFILL }},
      { &hf_gtp_pdp_type, { "PDP type", "gtp.pdp_type", FT_UINT8, BASE_DEC, VALS(pdp_type), 0x0, NULL, HFILL }},
      { &hf_gtp_pdp_address_length, { "PDP address length", "gtp.pdp_address_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_pdp_address_ipv4, { "PDP address", "gtp.pdp_address.ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_pdp_address_ipv6, { "PDP address", "gtp.pdp_address.ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_sgsn_address_for_control_plane_ipv4, { "SGSN Address for control plane", "gtp.sgsn_address_for_control_plane.ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_sgsn_address_for_control_plane_ipv6, { "SGSN Address for control plane", "gtp.sgsn_address_for_control_plane.ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_sgsn_address_for_user_traffic_ipv4, { "SGSN Address for User Traffic", "gtp.sgsn_address_for_user_traffic.ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_sgsn_address_for_user_traffic_ipv6, { "SGSN Address for User Traffic", "gtp.sgsn_address_for_user_traffic.ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_ggsn_address_length, { "GGSN address length", "gtp.ggsn_address_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_ggsn_address_for_control_plane_ipv4, { "GGSN Address for control plane", "gtp.ggsn_address_for_control_plane.ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_ggsn_address_for_control_plane_ipv6, { "GGSN Address for control plane", "gtp.ggsn_address_for_control_plane.ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_ggsn_address_for_user_traffic_ipv4, { "GGSN Address for User Traffic", "gtp.ggsn_address_for_user_traffic.ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_ggsn_address_for_user_traffic_ipv6, { "GGSN Address for User Traffic", "gtp.ggsn_address_for_user_traffic.ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_apn_length, { "APN length", "gtp.apn_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_transaction_identifier, { "Transaction identifier", "gtp.transaction_identifier", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_gsn_address_length, { "GSN address length", "gtp.gsn_address_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_gsn_address_information_element_length, { "GSN address Information Element length", "gtp.gsn_address_information_element_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_tft_length, { "TFT length", "gtp.tft_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_rab_setup_length, { "RAB setup length", "gtp.rab_setup_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_timezone, { "Timezone", "gtp.timezone", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_timezone_dst, { "DST", "gtp.timezone_dst", FT_UINT8, BASE_DEC, VALS(daylight_saving_time_vals), 0x03, NULL, HFILL }},
      { &hf_gtp_rfsp_index, { "RFSP Index", "gtp.rfsp_index", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_fqdn_length, { "FQDN length", "gtp.fqdn_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_number_of_data_records, { "Number of data records", "gtp.number_of_data_records", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_data_record_format, { "Data record format", "gtp.data_record_format", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_node_address_length, { "Node address length", "gtp.node_address_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_seq_num_released, { "Sequence number released", "gtp.seq_num_released", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_seq_num_canceled, { "Sequence number cancelled", "gtp.seq_num_canceled", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_requests_responded, { "Requests responded", "gtp.requests_responded", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_hyphen_separator, { "Hyphen separator: -", "gtp.hyphen_separator", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_ms_network_cap_content_len, { "Length of MS network capability contents", "gtp.ms_network_cap_content_len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_iei, { "IEI", "gtp.iei", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_iei_mobile_id_len, { "Length", "gtp.iei.mobile_id_len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_qos_umts_length, { "Length", "gtp.qos_umts_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_num_ext_hdr_types, { "Number of Extension Header Types in list (i.e., length)", "gtp.num_ext_hdr_types", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_gtp_ext_hdr_type, { "Extension Header Type", "gtp.ext_hdr_type", FT_UINT8, BASE_DEC, VALS(next_extension_header_fieldvals), 0x0, NULL, HFILL }},
      { &hf_gtp_tpdu_data, { "T-PDU Data", "gtp.tpdu_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
      { &hf_gtp_ext_enb_type, { "enb_type", "gtp.enb_type", FT_UINT8, BASE_DEC, VALS(gtp_enb_type_vals), 0x0, NULL, HFILL } },
      { &hf_gtp_macro_enodeb_id,
      { "Macro eNodeB ID", "gtp.macro_enodeb_id",
      FT_UINT24, BASE_HEX, NULL, 0x0fffff,
      NULL, HFILL }
      },
      { &hf_gtp_home_enodeb_id,
      { "Home eNodeB ID", "gtp.home_enodeb_id",
      FT_UINT32, BASE_HEX, NULL, 0x0fffffff,
      NULL, HFILL }
      },
      { &hf_gtp_dummy_octets,
      { "Dummy octets", "gtp.dummy_octets",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
      },
      { &hf_gtp_spare_b4b0,
      { "Spare", "gtp.spare.b4b0",
      FT_UINT8, BASE_HEX, NULL, 0x1f,
      NULL, HFILL }
      },
      { &hf_gtp_spare_b7b6,
      { "Spare", "gtp.spare.b7b6",
      FT_UINT8, BASE_HEX, NULL, 0xc0,
      NULL, HFILL }
      },
      { &hf_gtp_spare_h1,
      { "Spare", "gtp.spare.h1",
      FT_UINT8, BASE_HEX, NULL, 0xf,
      NULL, HFILL }
      },
      { &hf_gtp_rnc_ip_addr_v4,
      { "RNC IP address", "gtp.rnc_ip_addr_v4",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_gtp_rnc_ip_addr_v6,
      { "RNC IP address", "gtp.rnc_ip_addr_v6",
      FT_IPv6, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_gtp_ms_cm_2_len,
      { "Length of the Mobile Station Classmark 2", "gtp.ms_cm_2_len",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_gtp_ms_cm_3_len,
      { "Length of the Mobile Station Classmark 3", "gtp.ms_cm_3_len",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_gtp_sup_codec_lst_len,
      { "Length of the Supported Codec List", "gtp.sup_codec_lst_len",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_gtp_add_flg_for_srvcc_ics,
      { "ICS (IMS Centralized Service)", "gtp.add_flg_for_srvcc_ics",
      FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
      NULL, HFILL }
      },
      { &hf_gtp_sel_mode_val,
      { "Selection Mode Value", "gtp.sel_mode_val",
      FT_UINT8, BASE_DEC, VALS(gtp_sel_mode_vals), 0x03,
      NULL, HFILL }
      },
};


   static hf_register_info hf_nrup[] =
   {
      {&hf_nrup_pdu_type,
        { "PDU Type", "nrup.pdu_type",
          FT_UINT8, BASE_DEC, VALS(nr_pdu_type_cnst), 0xf0,
          NULL, HFILL}
      },
      {&hf_nrup_spr_bit_extnd_flag,
        { "Spare", "nrup.spr_bit",
          FT_BOOLEAN, 8, NULL, 0x08,
          NULL, HFILL}
      },
      {&hf_nrup_dl_discrd_blks,
        { "DL Discard Blocks", "nrup.dl_disc_blks",
          FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04,
          "Presence of DL discard Number of blocks, discard NR PDCP PDU SN start and Discarded Block size", HFILL}
      },
      {&hf_nrup_dl_flush,
       { "DL Flush", "nrup.dl_flush",
         FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
         "Presence of DL discard NR PDCP PDU SN", HFILL}
      },
      {&hf_nrup_rpt_poll,
        { "Report Polling", "nrup.report_polling",
          FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x01,
          "Indicates that the node hosting the NR PDCP entity requests providing the downlink delivery status report", HFILL}
      },
      {&hf_nrup_retransmission_flag,
        { "Retransmission Flag", "nrup.retransmission_flag",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
           "Indicates whether the NR PDCP PDU is a retransmission NR-U packet sent by the node hosting the NR PDCP entity to the corresponding node", HFILL}
      },
      { &hf_nrup_ass_inf_rep_poll_flag,
        { "Assistance Info. Report Polling Flag", "nrup.ass_inf_rep_poll_flag",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
           NULL, HFILL }
      },
      { &hf_nrup_spare,
        { "Spare", "nrup.spare",
           FT_UINT8, BASE_DEC, NULL, 0xe0,
           NULL, HFILL }
      },
      { &hf_nrup_request_out_of_seq_report,
        { "Request Out Of Seq Report", "nrup.request_out_of_seq_report",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
           NULL, HFILL}
      },

      {&hf_nrup_report_delivered,
         { "Report Delivered", "nrup.report_delivered",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
           "Presence of DL report NR PDCP PDU SN", HFILL}
      },
      {&hf_nrup_user_data_existence_flag,
         { "User Data Existence Flag", "nrup.user_data_existence_flag",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
           "Whether the node hosting the NR PDCP entity has some user data for the concerned data radio bearer", HFILL}
      },
      {&hf_nrup_nr_u_seq_num,
         { "NR-U Sequence Number", "nrup.seq_num",
           FT_UINT24, BASE_DEC, NULL, 0,
           "NR-U sequence number as assigned by the node hosting the NR PDCP entity", HFILL}
      },
      {&hf_nrup_dl_disc_nr_pdcp_pdu_sn,
         { "DL discard NR PDCP PDU SN", "nrup.dl_disc_nr_pdcp_pdu_sn",
           FT_UINT24, BASE_DEC, NULL, 0,
           NULL, HFILL}
      },
      {&hf_nrup_dl_disc_num_blks,
         { "DL discard Number of blocks", "nrup.dl_disc_num_blks",
           FT_UINT8, BASE_DEC, NULL, 0xff,
           NULL, HFILL}
      },
      {&hf_nrup_dl_disc_nr_pdcp_pdu_sn_start,
         { "DL discard NR PDCP PDU SN Start", "nrup.dl_disc_nr_pdcp_pdu_sn_start",
           FT_UINT24, BASE_DEC, NULL, 0,
           NULL, HFILL}
      },
      {&hf_nrup_dl_disc_blk_sz,
         { "Discarded block size", "nrup.disc_blk_sz",
           FT_UINT8, BASE_DEC, NULL, 0,
           "The number of NR PDCP PDUs counted from the starting SN to be discarded", HFILL}
      },
       {&hf_nrup_dl_report_nr_pdcp_pdu_sn,
          { "DL report NR PDCP PDU SN", "nrup.dl_report_nr_pdcp_pdu_sn",
            FT_UINT24, BASE_DEC, NULL, 0,
            "DL delivery status report wanted when this SN has been delivered", HFILL}
       },

      {&hf_nrup_high_tx_nr_pdcp_sn_ind,
         { "Highest Transmitted NR PDCP SN Ind", "nrup.high_tx_nr_pdcp_sn_ind",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
           NULL, HFILL}
      },
      {&hf_nrup_high_delivered_nr_pdcp_sn_ind,
         { "Highest Delivered NR PDCP SN Ind", "nrup.high_delivered_nr_pdcp_sn_ind",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
           NULL, HFILL}
      },
      {&hf_nrup_final_frame_ind,
         { "Final Frame Indication", "nrup.final_frame_ind",
           FT_BOOLEAN, 8, TFS(&tfs_final_frame_indication), 0x02,
           "Whether the frame is the last DL status report", HFILL}
      },
      {&hf_nrup_lost_pkt_rpt,
         { "Lost Packet Report", "nrup.lost_pkt_rpt",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
           "Indicates the presence of Number of lost NR-U Sequence Number ranges reported" , HFILL}
      },
      {&hf_nrup_high_retx_nr_pdcp_sn_ind,
         { "Highest Retransmitted NR PDCP SN Ind", "nrup.high_retx_nr_pdcp_sn_ind",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
           NULL, HFILL}
      },
      {&hf_nrup_cause_rpt,
         { "Cause Report", "nrup.cause_rpt",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
           "Presence of Cause Value", HFILL}
      },
      {&hf_nrup_delivered_nr_pdcp_sn_range_ind,
         { "Delivered NR PDCP SN Range Ind", "nrup.delivered_nr_pdcp_sn_range_ind",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
           NULL, HFILL}
      },
      {&hf_nrup_data_rate_ind,
         { "Data Rate Ind", "nrup.data_rate_ind",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
           NULL, HFILL}
      },
      {&hf_nrup_desrd_buff_sz_data_radio_bearer,
         { "Desired buffer size for the data radio bearer", "nrup.desrd_buff_sz_data_radio_bearer",
           FT_UINT32, BASE_DEC, NULL, 0,
           NULL, HFILL}
      },
      {&hf_nrup_high_delivered_retx_nr_pdcp_sn_ind,
         { "Highest Delivered Retransmitted NR PDCP SN Ind", "nrup.high_delivered_retx_nr_pdcp_sn_ind",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
           NULL, HFILL}
      },
      {&hf_nrup_desrd_data_rate,
         { "Desired data rate", "nrup.desrd_data_rate",
           FT_UINT32, BASE_DEC, NULL, 0,
           NULL, HFILL}
      },
      {&hf_nrup_num_lost_nru_seq_num,
         { "Number of lost NR-U Sequence Number ranges reported", "nrup.num_lost_nru_seq_num",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL}
      },
      {&hf_nrup_start_lost_nru_seq_num,
         { "Start of lost NR-U Sequence Number range", "nrup.start_num_lost_nru_seq_num",
           FT_UINT24, BASE_DEC, NULL, 0,
           NULL, HFILL}
      },
      {&hf_nrup_end_lost_nru_seq_num,
         { "End of lost NR-U Sequence Number range", "nrup.end_num_lost_nru_seq_num",
           FT_UINT24, BASE_DEC, NULL, 0,
           NULL, HFILL}
      },
      {&hf_nrup_high_success_delivered_nr_pdcp_sn,
         { "Highest Successfully Delivered NR PDCP SN", "nrup.high_success_delivered_nr_pdcp_sn",
           FT_UINT24, BASE_DEC, NULL, 0,
           NULL, HFILL}
      },
      {&hf_nrup_high_tx_nr_pdcp_sn,
         { "Highest transmitted NR PDCP SN", "nrup.high_tx_nr_pdcp_sn",
           FT_UINT24, BASE_DEC, NULL, 0,
           NULL, HFILL}
      },
      {&hf_nrup_cause_val ,
         { "Cause Value", "nrup.cause_val",
           FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(nr_up_cause_vals), 0,
           "Indicates specific events reported by the corresponding node", HFILL}
      },
      {&hf_nrup_high_success_delivered_retx_nr_pdcp_sn,
         { "Highest Successfully Delivered Retransmitted NR PDCP SN", "nrup.high_success_delivered_retx_nr_pdcp_sn",
           FT_UINT24, BASE_DEC, NULL, 0,
           NULL, HFILL}
      },
      {&hf_nrup_high_retx_nr_pdcp_sn,
         { "Highest Retransmitted NR PDCP SN Ind", "nrup.high_retx_nr_pdcp_sn",
           FT_UINT24, BASE_DEC, NULL, 0,
           NULL, HFILL}
      },

      {&hf_nrup_pdcp_duplication_ind,
         { "PDCP Duplication Indication", "nrup.pdcp_duplication_ind",
           FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x08,
           NULL, HFILL}
      },
      {&hf_nrup_assistance_information_ind,
         { "Assistance Information Indication", "nrup.assistance_information_ind",
           FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04,
           NULL, HFILL}
      },
      {&hf_nrup_ul_delay_ind,
         { "UL Delay Indicator", "nrup.ul_delay_ind",
           FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
           NULL, HFILL}
      },
      {&hf_nrup_dl_delay_ind,
         { "DL Delay Indicator", "nrup.dl_delay_ind",
           FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
           NULL, HFILL}
      },
      {&hf_nrup_spare_2,
         { "Spare", "nrup.spare",
           FT_UINT8, BASE_HEX, NULL, 0xfe,
           NULL, HFILL}
      },
      {&hf_nrup_pdcp_duplication_activation_suggestion,
         { "PDCP Duplication Activation Suggestion", "nrup.pdcp_duplication_activation_suggestion",
           FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
           NULL, HFILL}
      },
      {&hf_nrup_num_assistance_info_fields,
         { "Number of Assistance Information Fields", "nrup.num_assistance_info_fields",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
      },
      {&hf_nrup_assistance_information_type,
         { "Assistance Information Type", "nrup.assistance_info_type",
           FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(assistance_info_type), 0x0,
           NULL, HFILL}
      },
      {&hf_nrup_num_octets_radio_qa_info,
         { "Number of octets for Radio Quality Assistance Information Fields", "nrup.num_octets_radio_qa_info",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
      },
      {&hf_nrup_radio_qa_info,
         { "Radio Quality Assistance Information", "nrup.radio_qa_info",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL}
      },
      {&hf_nrup_ul_delay_du_result,
         { "UL Delay DU Result", "nrup.ul_delay_du_result",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
      },
      {&hf_nrup_dl_delay_du_result,
         { "DL Delay DU Result", "nrup.dl_delay_du_result",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL}
      }
    };


    static ei_register_info ei[] = {
        { &ei_gtp_ext_length_mal, { "gtp.ext_length.invalid", PI_MALFORMED, PI_ERROR, "Malformed length", EXPFILL }},
        { &ei_gtp_ext_hdr_pdcpsn, { "gtp.ext_hdr.pdcp_sn.non_zero", PI_PROTOCOL, PI_NOTE, "3GPP TS 29.281 v9.0.0: When used between two eNBs at the X2 interface in E-UTRAN, bit 8 of octet 2 is spare. The meaning of the spare bits shall be set to zero.", EXPFILL }},
        { &ei_gtp_ext_length_warn, { "gtp.ext_length.invalid", PI_PROTOCOL, PI_WARN, "Length warning", EXPFILL }},
        { &ei_gtp_undecoded, { "gtp.undecoded", PI_UNDECODED, PI_WARN, "Data not decoded yet", EXPFILL }},
        { &ei_gtp_message_not_found, { "gtp.message_not_found", PI_PROTOCOL, PI_WARN, "Message not found", EXPFILL }},
        { &ei_gtp_field_not_present, { "gtp.field_not_present", PI_PROTOCOL, PI_WARN, "Field not present", EXPFILL }},
        { &ei_gtp_wrong_next_field, { "gtp.wrong_next_field", PI_PROTOCOL, PI_WARN, "Wrong next field", EXPFILL }},
        { &ei_gtp_field_not_support_in_version, { "gtp.field_not_support_in_version", PI_PROTOCOL, PI_WARN, "GTP version not supported for field", EXPFILL }},
        { &ei_gtp_guaranteed_bit_rate_value, { "gtp.guaranteed_bit_rate_value", PI_PROTOCOL, PI_NOTE, "Use the value indicated by the Guaranteed bit rate", EXPFILL }},
        { &ei_gtp_max_bit_rate_value, { "gtp.max_bit_rate_value", PI_PROTOCOL, PI_NOTE, "Use the value indicated by the Maximum bit rate", EXPFILL }},
        { &ei_gtp_ext_geo_loc_type, { "gtp.ext_geo_loc_type.unknown", PI_PROTOCOL, PI_WARN, "Unknown Location type data", EXPFILL }},
        { &ei_gtp_iei, { "gtp.iei.unknown", PI_PROTOCOL, PI_WARN, "Unknown IEI - Later spec than TS 29.060 9.4.0 used?", EXPFILL }},
        { &ei_gtp_unknown_extension_header, { "gtp.unknown_extension_header", PI_PROTOCOL, PI_WARN, "Unknown extension header", EXPFILL }},
        { &ei_gtp_unknown_pdu_type, { "gtp.unknown_pdu_type", PI_PROTOCOL, PI_WARN, "Unknown PDU type", EXPFILL }},
        { &ei_gtp_source_type_unknown, { "gtp.source_type.unknown", PI_PROTOCOL, PI_WARN, "Unknown source type", EXPFILL }},
        { &ei_gtp_cdr_rel_ext_invalid, { "gtp.cdr_rel_ext.invalid", PI_PROTOCOL, PI_WARN, "If Release Identifier is 0, Release Identifier Extension must be >= 16", EXPFILL}},
    };

    /* Setup protocol subtree array */
#define GTP_NUM_INDIVIDUAL_ELEMS    38
    static gint *ett_gtp_array[GTP_NUM_INDIVIDUAL_ELEMS + NUM_GTP_IES];

    ett_gtp_array[0] = &ett_gtp;
    ett_gtp_array[1] = &ett_gtp_flags;
    ett_gtp_array[2] = &ett_gtp_ext;
    ett_gtp_array[3] = &ett_gtp_cdr_dr;
    ett_gtp_array[4] = &ett_gtp_qos;
    ett_gtp_array[5] = &ett_gtp_qos_arp;
    ett_gtp_array[6] = &ett_gtp_flow_ii;
    ett_gtp_array[7] = &ett_gtp_ext_hdr;
    ett_gtp_array[8] = &ett_gtp_rp;
    ett_gtp_array[9] = &ett_gtp_pkt_flow_id;
    ett_gtp_array[10] = &ett_gtp_data_resp;
    ett_gtp_array[11] = &ett_gtp_cdr_ver;
    ett_gtp_array[12] = &ett_gtp_tmgi;
    ett_gtp_array[13] = &ett_gtp_trip;
    ett_gtp_array[14] = &ett_gtp_quint;
    ett_gtp_array[15] = &ett_gtp_drx;
    ett_gtp_array[16] = &ett_gtp_net_cap;
    ett_gtp_array[17] = &ett_gtp_can_pack;
    ett_gtp_array[18] = &ett_gtp_proto;
    ett_gtp_array[19] = &ett_gtp_gsn_addr;
    ett_gtp_array[20] = &ett_gtp_tft;
    ett_gtp_array[21] = &ett_gtp_rab_setup;
    ett_gtp_array[22] = &ett_gtp_hdr_list;
    ett_gtp_array[23] = &ett_gtp_rel_pack;
    ett_gtp_array[24] = &ett_gtp_node_addr;
    ett_gtp_array[25] = &ett_gtp_mm_cntxt;
    ett_gtp_array[26] = &ett_gtp_utran_cont;
    ett_gtp_array[27] = &ett_gtp_nr_ran_cont;
    ett_gtp_array[28] = &ett_gtp_pdcp_no_conf;
    ett_gtp_array[29] = &ett_pdu_session_cont;
    ett_gtp_array[30] = &ett_gtp_trace_triggers_ggsn;
    ett_gtp_array[31] = &ett_gtp_trace_loi_ggsn;
    ett_gtp_array[32] = &ett_gtp_trace_triggers_bm_sc;
    ett_gtp_array[33] = &ett_gtp_trace_loi_bm_sc;
    ett_gtp_array[34] = &ett_gtp_bss_cont;
    ett_gtp_array[35] = &ett_gtp_lst_set_up_pfc;
    ett_gtp_array[36] = &ett_gtp_rrc_cont;
    ett_gtp_array[37] = &ett_nrup;

    last_offset = GTP_NUM_INDIVIDUAL_ELEMS;

    for (i=0; i < NUM_GTP_IES; i++, last_offset++)
    {
        ett_gtp_ies[i] = -1;
        ett_gtp_array[last_offset] = &ett_gtp_ies[i];
    }


    proto_gtp = proto_register_protocol("GPRS Tunneling Protocol", "GTP", "gtp");
    proto_gtpprime = proto_register_protocol("GPRS Tunneling Protocol Prime", "GTP (Prime)", "gtpprime");

    proto_register_field_array(proto_gtp, hf_gtp, array_length(hf_gtp));
    proto_register_subtree_array(ett_gtp_array, array_length(ett_gtp_array));
    expert_gtp = expert_register_protocol(proto_gtp);
    expert_register_field_array(expert_gtp, ei, array_length(ei));

    proto_nrup = proto_register_protocol("NRUP", "NRUP", "nrup");
    proto_register_field_array(proto_nrup, hf_nrup, array_length(hf_nrup));


    gtp_module = prefs_register_protocol(proto_gtp, proto_reg_handoff_gtp);
    /* For reading older preference files with "gtpv0." or "gtpv1." preferences */
    prefs_register_module_alias("gtpv0", gtp_module);
    prefs_register_module_alias("gtpv1", gtp_module);

    prefs_register_uint_preference(gtp_module, "v0_port", "GTPv0 and GTP' port", "GTPv0 and GTP' port (default 3386)", 10, &g_gtpv0_port);
    prefs_register_uint_preference(gtp_module, "v1c_port", "GTPv1 or GTPv2 control plane (GTP-C, GTPv2-C) port", "GTPv1 and GTPv2 control plane port (default 2123)", 10,
                                   &g_gtpv1c_port);
    prefs_register_uint_preference(gtp_module, "v1u_port", "GTPv1 user plane (GTP-U) port", "GTPv1 user plane port (default 2152)", 10,
                                   &g_gtpv1u_port);
    prefs_register_enum_preference(gtp_module, "dissect_tpdu_as",
                                               "Dissect T-PDU as",
                                               "Dissect T-PDU as",
                                               &dissect_tpdu_as,
                                               gtp_decode_tpdu_as,
                                               FALSE);
    prefs_register_uint_preference(gtp_module, "pair_max_interval", "Max interval allowed in pair matching", "Request/reply pair matches only if their timestamps are closer than that value, in ms (default 0, i.e. don't use timestamps)", 10, &pref_pair_matching_max_interval_ms);

    prefs_register_obsolete_preference(gtp_module, "v0_dissect_cdr_as");
    prefs_register_obsolete_preference(gtp_module, "v0_check_etsi");
    prefs_register_obsolete_preference(gtp_module, "v1_check_etsi");
    prefs_register_bool_preference(gtp_module, "check_etsi", "Compare GTP order with ETSI", "GTP ETSI order", &g_gtp_etsi_order);
    prefs_register_obsolete_preference(gtp_module, "ppp_reorder");
    prefs_register_obsolete_preference(gtp_module, "dissect_tpdu");

    /* This preference can be used to disable the dissection of GTP over TCP. Most of the Wireless operators uses GTP over UDP.
     * The preference is set to TRUE by default forbackward compatibility
     */
    prefs_register_bool_preference(gtp_module, "dissect_gtp_over_tcp", "Dissect GTP over TCP", "Dissect GTP over TCP", &g_gtp_over_tcp);
    prefs_register_bool_preference(gtp_module, "track_gtp_session", "Track GTP session", "Track GTP session", &g_gtp_session);

    /* --- PDCP DECODE ADDITIONS --- */

    static uat_field_t pdcp_lte_keys_uat_flds[] = {
        UAT_FLD_CSTRING_OTHER(pdcp_lte_users, ip_addr_str, "Dst IP address", pdcp_uat_fld_ip_chk_cb, "IPv4 or IPv6 address"),
        UAT_FLD_CSTRING_OTHER(pdcp_lte_users, teid_str, "TEID value  or \"" PDCP_TEID_WILDCARD "\"", pdcp_uat_fld_teid_chk_cb, "Tunnel Endpoint Identifier"),
        UAT_FLD_VS(pdcp_lte_users, header_present, "Header present", vs_header_present, "Header present flag"),
        UAT_FLD_VS(pdcp_lte_users, plane, "Plane", vs_pdcp_plane, "Signaling or user plane"),
        UAT_FLD_VS(pdcp_lte_users, lte_sn_length, "PDCP SN length", vs_pdcp_lte_sn_length, "Length of PDCP sequence number"),
        UAT_FLD_VS(pdcp_lte_users, rohc_compression, "ROHC compression", vs_rohc_compression, "Header compression"),
        //UAT_FLD_VS(pdcp_lte_users, rohc_mode, "ROHC mode", vs_rohc_mode, "ROHC mode"),
        UAT_FLD_VS(pdcp_lte_users, rohc_profile, "ROHC profile", vs_rohc_profile, "ROHC profile"),
        UAT_END_FIELDS
    };

    pdcp_lte_keys_uat = uat_new("PDCP-LTE Keys",
        sizeof(uat_pdcp_lte_keys_record_t), /* record size */
        "gtp_pdcp_lte_keys2",                /* filename */
        TRUE,                               /* from_profile */
        &uat_pdcp_lte_keys_records,         /* data_ptr */
        &num_pdcp_lte_keys_uat,             /* numitems_ptr */
        UAT_AFFECTS_DISSECTION,             /* affects dissection of packets, but not set of named fields */
        NULL,                               /* help */
        pdcp_lte_copy_cb,                   /* copy callback */
        pdcp_lte_update_cb,                 /* update callback */
        pdcp_lte_free_cb,                   /* free callback */
        NULL,                               /* post update callback */
        NULL,                               /* reset callback */
        pdcp_lte_keys_uat_flds);            /* UAT field definitions */

    prefs_register_uat_preference(gtp_module,
        "pdcp_lte_table",
        "GTP PDCP-LTE Keys",
        "Preconfigured PDCP-LTE Keys",
        pdcp_lte_keys_uat);

    static uat_field_t pdcp_nr_keys_uat_flds[] = {
        UAT_FLD_CSTRING_OTHER(pdcp_nr_users, ip_addr_str, "Dst IP address", pdcp_uat_fld_ip_chk_cb, "IPv4 or IPv6 address"),
        UAT_FLD_CSTRING_OTHER(pdcp_nr_users, teid_str, "TEID value or \"" PDCP_TEID_WILDCARD "\"", pdcp_uat_fld_teid_chk_cb, "Tunnel Endpoint Identifier"),
        UAT_FLD_VS(pdcp_nr_users, direction, "Direction", vs_direction, "Direction"),
        UAT_FLD_VS(pdcp_nr_users, sdap_header_present, "SDAP header present flag", vs_sdap_header_present, "SDAP header present flag"),
        UAT_FLD_VS(pdcp_nr_users, mac_i_present, "MAC-I present flag", vs_mac_i_present, "MAC-I present flag"),
        UAT_FLD_VS(pdcp_nr_users, plane, "Plane", vs_pdcp_plane, "Signaling or user plane"),
        UAT_FLD_VS(pdcp_nr_users, pdcp_nr_sn_length, "PDCP SN length", vs_pdcp_nr_sn_length, "Length of PDCP sequence number"),
        UAT_FLD_VS(pdcp_nr_users, rohc_compression, "ROHC compression", vs_rohc_compression, "Header compression"),
        //UAT_FLD_VS(pdcp_nr_users, rohc_mode, "ROHC mode", vs_rohc_mode, "ROHC mode"),
        UAT_FLD_VS(pdcp_nr_users, rohc_profile, "ROHC profile", vs_rohc_profile, "ROHC profile"),
        UAT_END_FIELDS
    };

    pdcp_nr_keys_uat = uat_new("PDCP-NR Keys",
        sizeof(uat_pdcp_nr_keys_record_t), /* record size */
        "gtp_pdcp_nr_keys2",                /* filename */
        TRUE,                              /* from_profile */
        &uat_pdcp_nr_keys_records,         /* data_ptr */
        &num_pdcp_nr_keys_uat,             /* numitems_ptr */
        UAT_AFFECTS_DISSECTION,            /* affects dissection of packets, but not set of named fields */
        NULL,                              /* help */
        pdcp_nr_copy_cb,                   /* copy callback */
        pdcp_nr_update_cb,                 /* update callback */
        pdcp_nr_free_cb,                   /* free callback */
        NULL,                              /* post update callback */
        NULL,                              /* reset callback */
        pdcp_nr_keys_uat_flds);            /* UAT field definitions */

    prefs_register_uat_preference(gtp_module,
        "pdcp_nr_table",
        "GTP PDCP-NR Keys",
        "Preconfigured PDCP-NR Keys",
        pdcp_nr_keys_uat);

    /* --- END PDCP NR DECODE ADDITIONS ---*/

    gtp_handle = register_dissector("gtp", dissect_gtp, proto_gtp);
    gtp_prime_handle = register_dissector("gtpprime", dissect_gtpprime, proto_gtpprime);
    nrup_handle = register_dissector("nrup", dissect_nrup, proto_nrup);

    gtp_priv_ext_dissector_table = register_dissector_table("gtp.priv_ext", "GTP Private Extension", proto_gtp, FT_UINT16, BASE_DEC);
    gtp_cdr_fmt_dissector_table = register_dissector_table("gtp.cdr_fmt", "GTP Data Record Type", proto_gtp, FT_UINT16, BASE_DEC);
    gtp_hdr_ext_dissector_table = register_dissector_table("gtp.hdr_ext", "GTP Header Extension", proto_gtp, FT_UINT16, BASE_DEC);

    register_init_routine(gtp_init);
    register_cleanup_routine(gtp_cleanup);
    gtp_tap = register_tap("gtp");
    gtpv1_tap = register_tap("gtpv1");

    register_srt_table(proto_gtp, NULL, 1, gtpstat_packet, gtpstat_init, NULL);
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

void
proto_reg_handoff_gtp(void)
{
    static gboolean           Initialized = FALSE;
    static gboolean           gtp_over_tcp;
    static guint              gtpv0_port;
    static guint              gtpv1c_port;
    static guint              gtpv1u_port;

    if (!Initialized) {

        radius_register_avp_dissector(VENDOR_THE3GPP, 5, dissect_radius_qos_umts);
        radius_register_avp_dissector(VENDOR_THE3GPP, 12, dissect_radius_selection_mode);



        eth_handle           = find_dissector_add_dependency("eth_withoutfcs", proto_gtp);
        ip_handle            = find_dissector_add_dependency("ip", proto_gtp);
        ipv6_handle          = find_dissector_add_dependency("ipv6", proto_gtp);
        ppp_handle           = find_dissector_add_dependency("ppp", proto_gtp);
        sync_handle          = find_dissector_add_dependency("sync", proto_gtp);
        gtpcdr_handle        = find_dissector_add_dependency("gtpcdr", proto_gtp);
        sndcpxid_handle      = find_dissector_add_dependency("sndcpxid", proto_gtp);
        gtpv2_handle         = find_dissector_add_dependency("gtpv2", proto_gtp);
        bssgp_handle         = find_dissector_add_dependency("bssgp", proto_gtp);
        pdcp_nr_handle       = find_dissector_add_dependency("pdcp-nr", proto_gtp);
        pdcp_lte_handle      = find_dissector_add_dependency("pdcp-lte", proto_gtp);
        proto_pdcp_lte       = dissector_handle_get_protocol_index(pdcp_lte_handle);

        bssap_pdu_type_table = find_dissector_table("bssap.pdu_type");
        /* AVP Code: 5 3GPP-GPRS Negotiated QoS profile */
        dissector_add_uint("diameter.3gpp", 5, create_dissector_handle(dissect_diameter_3gpp_qosprofile, proto_gtp));
        /* AVP Code: 903 MBMS-Service-Area */
        dissector_add_uint("diameter.3gpp", 903, create_dissector_handle(dissect_gtp_3gpp_mbms_service_area, proto_gtp));
        /* AVP Code: 904 MBMS-Session-Duration */
        dissector_add_uint("diameter.3gpp", 904, create_dissector_handle(dissect_gtp_mbms_ses_dur, proto_gtp));
        /* AVP Code: 911 MBMS-Time-To-Data-Transfer */
        dissector_add_uint("diameter.3gpp", 911, create_dissector_handle(dissect_gtp_mbms_time_to_data_tr, proto_gtp));

        Initialized = TRUE;
    } else {
        dissector_delete_uint("udp.port", gtpv0_port,  gtp_prime_handle);
        dissector_delete_uint("udp.port", gtpv1c_port, gtp_handle);
        dissector_delete_uint("udp.port", gtpv1u_port, gtp_handle);

        if (gtp_over_tcp) {
            dissector_delete_uint("tcp.port", gtpv0_port,  gtp_prime_handle);
            dissector_delete_uint("tcp.port", gtpv1c_port, gtp_handle);
            dissector_delete_uint("tcp.port", gtpv1u_port, gtp_handle);
        }
    }

    gtp_over_tcp = g_gtp_over_tcp;
    gtpv0_port   = g_gtpv0_port;
    gtpv1c_port  = g_gtpv1c_port;
    gtpv1u_port  = g_gtpv1u_port;

    /* This doesn't use the "auto preference" API because the port
        description is too specific */
    dissector_add_uint("udp.port", g_gtpv0_port, gtp_prime_handle);
    dissector_add_uint("udp.port", g_gtpv1c_port, gtp_handle);
    dissector_add_uint("udp.port", g_gtpv1u_port, gtp_handle);

    if (g_gtp_over_tcp) {
        /* This doesn't use the "auto preference" API because the port
           description is too specific */
        dissector_add_uint("tcp.port", g_gtpv0_port, gtp_prime_handle);
        dissector_add_uint("tcp.port", g_gtpv1c_port, gtp_handle);
        dissector_add_uint("tcp.port", g_gtpv1u_port, gtp_handle);
    }
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
