/* packet-gsm_a_gm.c
 * Routines for GSM A Interface GPRS Mobilty Management and GPRS Session Management
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * Added the GPRS Mobility Managment Protocol and
 * the GPRS Session Managment Protocol
 *   Copyright 2004, Rene Pilz <rene.pilz [AT] ftw.com>
 *   In association with Telecommunications Research Center
 *   Vienna (ftw.)Betriebs-GmbH within the Project Metawin.
 *
 * Various updates, enhancements and fixes
 * Copyright 2009, Gerasimos Dimitriadis <dimeg [AT] intracom.gr>
 * In association with Intracom Telecom SA
 *
 * Title		3GPP			Other
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
 *   Reference [9]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 9.6.0 Release 9)
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/asn1.h>

#include "packet-bssap.h"
#include "packet-sccp.h"
#include "packet-ber.h"
#include "packet-q931.h"
#include "packet-gsm_a_common.h"
#include "packet-e212.h"
#include "packet-ppp.h"

/* PROTOTYPES/FORWARDS */

const value_string gsm_a_dtap_msg_gmm_strings[] = {
	{ 0x01,	"Attach Request" },
	{ 0x02,	"Attach Accept" },
	{ 0x03,	"Attach Complete" },
	{ 0x04,	"Attach Reject" },
	{ 0x05,	"Detach Request" },
	{ 0x06,	"Detach Accept" },
	{ 0x08,	"Routing Area Update Request" },
	{ 0x09,	"Routing Area Update Accept" },
	{ 0x0a,	"Routing Area Update Complete" },
	{ 0x0b,	"Routing Area Update Reject" },
	{ 0x0c,	"Service Request" },
	{ 0x0d,	"Service Accept" },
	{ 0x0e,	"Service Reject" },
	{ 0x10,	"P-TMSI Reallocation Command" },
	{ 0x11,	"P-TMSI Reallocation Complete" },
	{ 0x12,	"Authentication and Ciphering Req" },
	{ 0x13,	"Authentication and Ciphering Resp" },
	{ 0x14,	"Authentication and Ciphering Rej" },
	{ 0x1c,	"Authentication and Ciphering Failure" },
	{ 0x15,	"Identity Request" },
	{ 0x16,	"Identity Response" },
	{ 0x20,	"GMM Status" },
	{ 0x21,	"GMM Information" },
	{ 0, NULL }
};

const value_string gsm_a_dtap_msg_sm_strings[] = {
	{ 0x41,	"Activate PDP Context Request" },
	{ 0x42,	"Activate PDP Context Accept" },
	{ 0x43,	"Activate PDP Context Reject" },
	{ 0x44,	"Request PDP Context Activation" },
	{ 0x45,	"Request PDP Context Activation rej." },
	{ 0x46,	"Deactivate PDP Context Request" },
	{ 0x47,	"Deactivate PDP Context Accept" },
	{ 0x48,	"Modify PDP Context Request(Network to MS direction)" },
	{ 0x49,	"Modify PDP Context Accept (MS to network direction)" },
	{ 0x4a,	"Modify PDP Context Request(MS to network direction)" },
	{ 0x4b,	"Modify PDP Context Accept (Network to MS direction)" },
	{ 0x4c,	"Modify PDP Context Reject" },
	{ 0x4d,	"Activate Secondary PDP Context Request" },
	{ 0x4e,	"Activate Secondary PDP Context Accept" },
	{ 0x4f,	"Activate Secondary PDP Context Reject" },
	{ 0x50,	"Reserved: was allocated in earlier phases of the protocol" },
	{ 0x51,	"Reserved: was allocated in earlier phases of the protocol" },
	{ 0x52,	"Reserved: was allocated in earlier phases of the protocol" },
	{ 0x53,	"Reserved: was allocated in earlier phases of the protocol" },
	{ 0x54,	"Reserved: was allocated in earlier phases of the protocol" },
	{ 0x55,	"SM Status" },
	{ 0x56,	"Activate MBMS Context Request" },
	{ 0x57,	"Activate MBMS Context Accept" },
	{ 0x58,	"Activate MBMS Context Reject" },
	{ 0x59,	"Request MBMS Context Activation" },
	{ 0x5a,	"Request MBMS Context Activation Reject" },
	{ 0x5b,	"Request Secondary PDP Context Activation" },
	{ 0x5c,	"Request Secondary PDP Context Activation Reject" },
	{ 0x5d,	"Notification" },
	{ 0, NULL }
};

const value_string gsm_gm_elem_strings[] = {
	/* GPRS Mobility Management Information Elements 10.5.5 */
	{ 0x00,	"Attach Result" },
	{ 0x00,	"Attach Type" },
	{ 0x00,	"Cipher Algorithm" },
	{ 0x00,	"TMSI Status" },
	{ 0x00,	"Detach Type" },
	{ 0x00,	"DRX Parameter" },
	{ 0x00,	"Force to Standby" },
	{ 0x00, "Force to Standby" },
	{ 0x00,	"P-TMSI Signature" },
	{ 0x00,	"P-TMSI Signature 2" },
	{ 0x00,	"Identity Type 2" },
	{ 0x00,	"IMEISV Request" },
	{ 0x00,	"Receive N-PDU Numbers List" },
	{ 0x00,	"MS Network Capability" },
	{ 0x00,	"MS Radio Access Capability" },
	{ 0x00,	"GMM Cause" },
	{ 0x00,	"Routing Area Identification" },
	{ 0x00,	"Routing Area Identification 2" },
	{ 0x00,	"Update Result" },
	{ 0x00, "Update Type" },
	{ 0x00,	"A&C Reference Number" },
	{ 0x00, "A&C Reference Number" },
	{ 0x00,	"Service Type" },
	{ 0x00,	"Cell Notification" },
	{ 0x00, "PS LCS Capability" },
	{ 0x00,	"Network Feature Support" },
	{ 0x00, "Inter RAT information container" },
	{ 0x00, "Requested MS information" },
	{ 0x00, "UE network capability" },
	{ 0x00, "E-UTRAN inter RAT information container" },
	{ 0x00, "Voice domain preference and UE's usage setting" },
	/* Session Management Information Elements 10.5.6 */
	{ 0x00,	"Access Point Name" },
	{ 0x00,	"Network Service Access Point Identifier" },
	{ 0x00,	"Protocol Configuration Options" },
	{ 0x00,	"Packet Data Protocol Address" },
	{ 0x00,	"Quality Of Service" },
	{ 0x00,	"SM Cause" },
	{ 0x00, "SM Cause 2" },
	{ 0x00,	"Linked TI" },
	{ 0x00,	"LLC Service Access Point Identifier" },
	{ 0x00,	"Tear Down Indicator" },
	{ 0x00,	"Packet Flow Identifier" },
	{ 0x00,	"Traffic Flow Template" },
	{ 0x00, "Temporary Mobile Group Identity (TMGI)" },
	{ 0x00, "MBMS bearer capabilities" },
	{ 0x00, "MBMS protocol configuration options" },
	{ 0x00, "Enhanced network service access point identifier" },
	{ 0x00, "Request type" },
	{ 0x00, "Notification indicator" },
	/* GPRS Common Information Elements 10.5.7 */
	{ 0x00,	"PDP Context Status" },
	{ 0x00,	"Radio Priority" },
	{ 0x00,	"GPRS Timer" },
	{ 0x00,	"GPRS Timer 2" },
	{ 0x00, "Radio Priority 2"},
	{ 0x00,	"MBMS context status"},
	{ 0x00,	"Uplink data status"},
	{ 0x00, "Spare Nibble"},
	{ 0, NULL }
};

#define	DTAP_GMM_IEI_MASK	0xff
#define	DTAP_SM_IEI_MASK	0xff

/* Initialize the protocol and registered fields */
static int proto_a_gm = -1;

static int hf_gsm_a_dtap_msg_gmm_type = -1;
static int hf_gsm_a_dtap_msg_sm_type = -1;
int hf_gsm_a_gm_elem_id = -1;
static int hf_gsm_a_qos_delay_cls	= -1;
static int hf_gsm_a_qos_reliability_cls = -1;
static int hf_gsm_a_qos_traffic_cls = -1;
static int hf_gsm_a_qos_del_order = -1;
static int hf_gsm_a_qos_del_of_err_sdu = -1;
static int hf_gsm_a_qos_ber = -1;
static int hf_gsm_a_qos_sdu_err_rat = -1;
static int hf_gsm_a_qos_traff_hdl_pri = -1;

static int hf_gsm_a_gmm_split_on_ccch = -1;
static int hf_gsm_a_gmm_non_drx_timer = -1;
static int hf_gsm_a_gmm_cn_spec_drs_cycle_len_coef = -1;

static int hf_gsm_a_ptmsi_sig =-1;
static int hf_gsm_a_ptmsi_sig2 =-1;

static int hf_gsm_a_tft_op_code = -1;
static int hf_gsm_a_tft_e_bit = -1;
static int hf_gsm_a_tft_pkt_flt = -1;
static int hf_gsm_a_tft_pkt_flt_id = -1;
static int hf_gsm_a_tft_pkt_flt_dir = -1;
static int hf_gsm_a_sm_ip4_address = -1;
static int hf_gsm_a_sm_ip4_mask = -1;
static int hf_gsm_a_sm_ip6_address = -1;
static int hf_gsm_a_sm_ip6_mask = -1;
static int hf_gsm_a_tft_protocol_header = -1;
static int hf_gsm_a_tft_port = -1;
static int hf_gsm_a_tft_port_low = -1;
static int hf_gsm_a_tft_port_high = -1;
static int hf_gsm_a_tft_security = -1;
static int hf_gsm_a_tft_traffic_mask = -1;
static int hf_gsm_a_tft_flow_label_type = -1;
static int hf_gsm_a_tft_param_id = -1;
static int hf_gsm_a_gm_acc_tech_type = -1;
static int hf_gsm_a_gm_acc_cap_struct_len = -1;
static int hf_gsm_a_gm_sms_value = -1;
static int hf_gsm_a_gm_sm_value = -1;
static int hf_gsm_a_gm_sm_ext = -1;
static int hf_gsm_a_gm_link_dir = -1;
static int hf_gsm_a_gm_cause = -1;

static int hf_gsm_a_gm_fop = -1;
static int hf_gsm_a_gm_res_of_attach = -1;
static int hf_gsm_a_gm_type_of_ciph_alg = -1;
static int hf_gsm_a_gm_imeisv_req = -1;
static int hf_gsm_a_gm_ac_ref_nr = -1;
static int hf_gsm_a_gm_force_to_standby = -1;
static int hf_gsm_a_gm_serv_type = -1;
static int hf_gsm_a_gm_ciph_key_seq_num = -1;
static int hf_gsm_a_gm_for = -1;
static int hf_gsm_a_gm_type_of_attach = -1;
static int hf_gsm_a_gm_tmsi_flag = -1;
static int hf_gsm_a_gm_update_type = -1;
static int hf_gsm_a_gm_gprs_timer_unit = -1;
static int hf_gsm_a_gm_gprs_timer_value = -1;
static int hf_gsm_a_gm_nsapi_5_ul_stat = -1;
static int hf_gsm_a_gm_nsapi_6_ul_stat = -1;
static int hf_gsm_a_gm_nsapi_7_ul_stat = -1;
static int hf_gsm_a_gm_nsapi_8_ul_stat = -1;
static int hf_gsm_a_gm_nsapi_9_ul_stat = -1;
static int hf_gsm_a_gm_nsapi_10_ul_stat = -1;
static int hf_gsm_a_gm_nsapi_11_ul_stat = -1;
static int hf_gsm_a_gm_nsapi_12_ul_stat = -1;
static int hf_gsm_a_gm_nsapi_13_ul_stat = -1;
static int hf_gsm_a_gm_nsapi_14_ul_stat = -1;
static int hf_gsm_a_gm_nsapi_15_ul_stat = -1;
static int hf_gsm_a_gm_pco_pid = -1;
static int hf_gsm_a_gm_type_of_identity = -1;
static int hf_gsm_a_gm_rac = -1;
static int hf_gsm_a_gm_apc = -1;
static int hf_gsm_a_gm_otd_a = -1;
static int hf_gsm_a_gm_otd_b = -1;
static int hf_gsm_a_gm_gps_a = -1;
static int hf_gsm_a_gm_gps_b = -1;
static int hf_gsm_a_gm_gps_c = -1;
static int hf_gsm_a_gm_req_ms_info_irat = -1;
static int hf_gsm_a_gm_req_ms_info_irat2 = -1;
static int hf_gsm_a_gm_ue_usage_setting = -1;
static int hf_gsm_a_gm_voice_domain_pref_for_eutran = -1;
static int hf_gsm_a_sm_pdp_type_org = -1;
static int hf_gsm_a_qos_mean_thr = -1;
static int hf_gsm_a_qos_peak_thr = -1;
static int hf_gsm_a_qos_prec_class = -1;
static int hf_gsm_a_qos_traf_handl_prio = -1;
static int hf_gsm_a_qos_trans_delay = -1;
static int hf_gsm_a_qos_signalling_ind = -1;
static int hf_gsm_a_qos_source_stat_desc = -1;
static int hf_gsm_a_qos_max_bitrate_upl = -1;
static int hf_gsm_a_qos_max_bitrate_downl = -1;
static int hf_gsm_a_qos_guar_bitrate_upl = -1;
static int hf_gsm_a_qos_guar_bitrate_downl = -1;
static int hf_gsm_a_qos_max_bitrate_upl_ext = -1;
static int hf_gsm_a_qos_max_bitrate_downl_ext = -1;
static int hf_gsm_a_qos_guar_bitrate_upl_ext = -1;
static int hf_gsm_a_qos_guar_bitrate_downl_ext = -1;
static int hf_gsm_a_sm_cause = -1;
static int hf_gsm_a_sm_cause_2 = -1;
static int hf_gsm_a_sm_llc_sapi = -1;
static int hf_gsm_a_sm_tdi = -1;
static int hf_gsm_a_sm_packet_flow_id = -1;
static int hf_gsm_a_sm_tmgi = -1;
static int hf_gsm_a_sm_enh_nsapi = -1;
static int hf_gsm_a_sm_req_type = -1;
static int hf_gsm_a_sm_notif_ind = -1;
static int hf_gsm_a_gm_rac_ctrled_early_cm_sending = -1;
static int hf_gsm_a_gm_rac_pseudo_sync = -1;
static int hf_gsm_a_gm_rac_vgcs = -1;
static int hf_gsm_a_gm_rac_vbs = -1;
static int hf_gsm_a_gm_rac_multislot_capability = -1;
static int hf_gsm_a_gm_rac_hscsd_multi_slot_class = -1;
static int hf_gsm_a_gm_rac_gprs_multi_slot_class = -1;
static int hf_gsm_a_gm_rac_gprs_ext_dyn_alloc_cap = -1;
static int hf_gsm_a_gm_rac_ecsd_multi_slot_class = -1;
static int hf_gsm_a_gm_rac_egprs_multi_slot_class = -1;
static int hf_gsm_a_gm_rac_egprs_ext_dyn_alloc_cap = -1;
static int hf_gsm_a_gm_rac_dtm_gprs_multi_slot_class = -1;
static int hf_gsm_a_gm_rac_single_slt_dtm = -1;
static int hf_gsm_a_gm_rac_dtm_egprs_multi_slot_cls_pres = -1;
static int hf_gsm_a_gm_rac_dtm_egprs_multi_slot_class = -1;
static int hf_gsm_a_gm_rac_8psk_pow_cap_pres = -1;
static int hf_gsm_a_gm_rac_comp_int_meas_cap = -1;
static int hf_gsm_a_gm_rel_lev_ind = -1;
static int hf_gsm_a_gm_rac_geran_feat_pkg = -1;
static int hf_gsm_a_gm_rac_umts_fdd_cap = -1;
static int hf_gsm_a_gm_rac_umts_384_tdd_ra_cap = -1;
static int hf_gsm_a_gm_rac_cdma2000_cap = -1;
static int hf_gsm_a_gm_rac_umts_128_tdd_ra_cap = -1;
static int hf_gsm_a_gm_rac_mod_based_multi_slot_class_support = -1;
static int hf_gsm_a_gm_rac_geran_iu_mode_cap = -1;
static int hf_gsm_a_gm_rac_flo_iu_cap = -1;
static int hf_gsm_a_gm_rac_mult_tbf_cap = -1;
static int hf_gsm_a_gm_rac_down_adv_rec_perf = -1;
static int hf_gsm_a_gm_rac_ext_rlc_mac_ctrl_msg_seg_cap = -1;
static int hf_gsm_a_gm_rac_dtm_enh_cap = -1;
static int hf_gsm_a_gm_rac_dtm_gprs_high_multi_slot_class = -1;
static int hf_gsm_a_gm_rac_dtm_egprs_high_multi_slot_class = -1;
static int hf_gsm_a_gm_rac_ps_ho_cap = -1;
static int hf_gsm_a_gm_rac_dtm_ho_cap = -1;
static int hf_gsm_a_gm_rac_multi_slot_cap_red_down_dual_carrier = -1;
static int hf_gsm_a_gm_rac_down_dual_carrier_dtm_cap = -1;
static int hf_gsm_a_gm_rac_flex_ts_assign = -1;
static int hf_gsm_a_gm_rac_gan_ps_ho_cap = -1;
static int hf_gsm_a_gm_rac_rlc_non_pers_mode = -1;
static int hf_gsm_a_gm_rac_reduced_lat_cap = -1;
static int hf_gsm_a_gm_rac_ul_egprs2 = -1;
static int hf_gsm_a_gm_rac_dl_egprs2 = -1;
static int hf_gsm_a_gm_rac_eutra_fdd_support = -1;
static int hf_gsm_a_gm_rac_eutra_tdd_support = -1;
static int hf_gsm_a_gm_rac_geran_to_eutra_support_in_geran_ptm = -1;
static int hf_gsm_a_gm_rac_prio_based_resel_support = -1;
static int hf_gsm_a_gm_rac_alt_efta_multi_slot_class = -1;
static int hf_gsm_a_gm_rac_efta_multi_slot_cap_red_down_dual_carrier = -1;
static int hf_gsm_a_gm_rac_ind_up_layer_pdu_start_cap_for_rlc_um = -1;
static int hf_gsm_a_gm_rac_emst_cap = -1;
static int hf_gsm_a_gm_rac_mtti_cap = -1;
static int hf_gsm_a_gm_rac_utra_csg_cell_report = -1;
static int hf_gsm_a_gm_rac_eutra_csg_cell_report = -1;

static int hf_gsm_a_gmm_net_cap_gea1 = -1;
static int hf_gsm_a_gmm_net_cap_smdch = -1;
static int hf_gsm_a_gmm_net_cap_smgprs = -1;
static int hf_gsm_a_gmm_net_cap_ucs2 = -1;
static int hf_gsm_a_gmm_net_cap_ss_scr_ind = -1;
static int hf_gsm_a_gmm_net_cap_solsa = -1;
static int hf_gsm_a_gmm_net_cap_rev = -1;
static int hf_gsm_a_gmm_net_cap_pfc = -1;
static int hf_gsm_a_gmm_net_cap_ext_gea_bits = -1;
static int hf_gsm_a_gmm_net_cap_gea2 = -1;
static int hf_gsm_a_gmm_net_cap_gea3 = -1;
static int hf_gsm_a_gmm_net_cap_gea4 = -1;
static int hf_gsm_a_gmm_net_cap_gea5 = -1;
static int hf_gsm_a_gmm_net_cap_gea6 = -1;
static int hf_gsm_a_gmm_net_cap_gea7 = -1;
static int hf_gsm_a_gmm_net_cap_lcs = -1;
static int hf_gsm_a_gmm_net_cap_ps_irat_iu = -1;
static int hf_gsm_a_gmm_net_cap_ps_irat_s1 = -1;
static int hf_gsm_a_gmm_net_cap_comb_proc = -1;
static int hf_gsm_a_gmm_net_cap_isr = -1;
static int hf_gsm_a_gmm_net_cap_srvcc_to_geran = -1;
static int hf_gsm_a_gmm_net_cap_epc = -1;
static int hf_gsm_a_gmm_net_cap_nf = -1;

/* Initialize the subtree pointers */
static gint ett_tc_component = -1;
static gint ett_tc_invoke_id = -1;
static gint ett_tc_linked_id = -1;
static gint ett_tc_opr_code = -1;
static gint ett_tc_err_code = -1;
static gint ett_tc_prob_code = -1;
static gint ett_tc_sequence = -1;

static gint ett_gmm_drx = -1;
static gint ett_gmm_detach_type = -1;
static gint ett_gmm_attach_type = -1;
static gint ett_gmm_context_stat = -1;
static gint ett_gmm_update_type = -1;
static gint ett_gmm_radio_cap = -1;
static gint ett_gmm_network_cap = -1;
static gint ett_gsm_a_gm_msrac_multislot_capability = -1;
static gint ett_gmm_rai = -1;
static gint ett_gmm_gprs_timer = -1;

static gint ett_sm_tft = -1;

static dissector_handle_t data_handle;
static dissector_handle_t rrc_irat_ho_info_handle;
static dissector_handle_t lte_rrc_ue_eutra_cap_handle;

static dissector_table_t gprs_sm_pco_subdissector_table; /* GPRS SM PCO PPP Protocols */

#define	NUM_GSM_GM_ELEM (sizeof(gsm_gm_elem_strings)/sizeof(value_string))
gint ett_gsm_gm_elem[NUM_GSM_GM_ELEM];

static const gchar *pdp_str[2]={ "PDP-INACTIVE", "PDP-ACTIVE" };

/*
 * [9] 10.5.5.1 Attach result
 */
static const value_string gsm_a_gm_res_of_attach_vals[] = {
	{ 0x01, "GPRS only attached" },
	{ 0x03, "Combined GPRS/IMSI attached" },
	{ 0, NULL }
};

static guint16
de_gmm_attach_res(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree_add_item(tree, hf_gsm_a_gm_fop, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_res_of_attach, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* no length check possible */
	return(1);
}

/*
 * [9] 10.5.5.2 Attach type
 */
static const value_string gsm_a_gm_type_of_attach_vals[] = {
	{ 0x01, "GPRS attach" },
	{ 0x02, "Not used (In earlier versions: GPRS attach while IMSI attached)" },
	{ 0x03, "Combined GPRS/IMSI attached" },
	{ 0, NULL }
};

static guint16
de_gmm_attach_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_item   *tf = NULL;
	proto_tree   *tf_tree = NULL;

	proto_tree_add_bits_item(tree, hf_gsm_a_gm_ciph_key_seq_num, tvb, offset << 3, 4, ENC_BIG_ENDIAN);

	tf = proto_tree_add_text(tree,
		tvb, offset, 1,
		"Attach Type");

	tf_tree = proto_item_add_subtree(tf, ett_gmm_attach_type );

	proto_tree_add_item(tf_tree, hf_gsm_a_gm_for, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tf_tree, hf_gsm_a_gm_type_of_attach, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* no length check possible */
	return(1);
}

/*
 * [9] 10.5.5.3 Ciphering algorithm
 */
const value_string gsm_a_gm_type_of_ciph_alg_vals[] = {
	{ 0x00, "ciphering not used" },
	{ 0x01, "GPRS Encryption Algorithm GEA/1" },
	{ 0x02, "GPRS Encryption Algorithm GEA/2" },
	{ 0x03, "GPRS Encryption Algorithm GEA/3" },
	{ 0x04, "GPRS Encryption Algorithm GEA/4" },
	{ 0x05, "GPRS Encryption Algorithm GEA/5" },
	{ 0x06, "GPRS Encryption Algorithm GEA/6" },
	{ 0x07, "GPRS Encryption Algorithm GEA/7" },
	{ 0, NULL }
};

static guint16
de_gmm_ciph_alg(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (offset << 3) + 4, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_type_of_ciph_alg, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* no length check possible */
	return(1);
}

/*
 * [9] 10.5.5.4 TMSI status
 */
const true_false_string gsm_a_gm_tmsi_flag_value = {
	"valid TMSI available",
	"no valid TMSI available"
};

static guint16
de_gmm_tmsi_stat(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (offset << 3) + 4, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_tmsi_flag, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* no length check possible */
	return(1);
}

/*
 * [7] 10.5.5.5
 */
static guint16
de_gmm_detach_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8        oct;
	guint32	      curr_offset;
	const gchar  *str;
	const gchar  *str_power;
	proto_item   *tf = NULL;
	proto_tree   *tf_tree = NULL;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch(oct&7)
	{
		case 1:  str="GPRS detach/re-attach required";                            break;
		case 2:  str="IMSI detach/re-attach not required";                        break;
		case 3:  str="Combined GPRS/IMSI detach/IMSI detach (after VLR failure)"; break;
		default: str="Combined GPRS/IMSI detach/re-attach not required";
	}

	switch(oct&8)
	{
		case 8:  str_power="power switched off"; break;
		default: str_power="normal detach";      break;
	}

	tf = proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Detach Type");

	tf_tree = proto_item_add_subtree(tf, ett_gmm_detach_type );

	proto_tree_add_text(tf_tree,
		tvb, curr_offset, 1,
		"Type: %s (%u)",
		str,
		oct&7);

	proto_tree_add_text(tf_tree,
		tvb, curr_offset, 1,
		"Power: %s (%u)",
		str_power,
		(oct>>3)&1);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.6
 *
 * SPLIT on CCCH, octet 3 (bit 4)
 * 0 Split pg cycle on CCCH is not supported by the mobile station
 * 1 Split pg cycle on CCCH is supported by the mobile station
 */
static const true_false_string gsm_a_gmm_split_on_ccch_value  = {
	"Split pg cycle on CCCH is supported by the mobile station",
	"Split pg cycle on CCCH is not supported by the mobile station"
};

/* non-DRX timer, octet 3
 * bit
 * 3 2 1
 */
static const value_string gsm_a_gmm_non_drx_timer_strings[] = {
	{ 0x00,	"no non-DRX mode after transfer state" },
	{ 0x01,	"max. 1 sec non-DRX mode after transfer state" },
	{ 0x02,	"max. 2 sec non-DRX mode after transfer state" },
	{ 0x03,	"max. 4 sec non-DRX mode after transfer state" },
	{ 0x04,	"max. 8 sec non-DRX mode after transfer state" },
	{ 0x05,	"max. 16 sec non-DRX mode after transfer state" },
	{ 0x06,	"max. 32 sec non-DRX mode after transfer state" },
	{ 0x07,	"max. 64 sec non-DRX mode after transfer state" },
	{ 0, NULL },
};
/*
 * CN Specific DRX cycle length coefficient, octet 3
 * bit
 * 8 7 6 5 Iu mode specific
 * 0 0 0 0 CN Specific DRX cycle length coefficient not specified by the MS, ie. the
 * system information value 'CN domain specific DRX cycle length' is used.
 * (Ref 3GPP TS 25.331)
 * 0 1 1 0 CN Specific DRX cycle length coefficient 6
 * 0 1 1 1 CN Specific DRX cycle length coefficient 7
 * 1 0 0 0 CN Specific DRX cycle length coefficient 8
 * 1 0 0 1 CN Specific DRX cycle length coefficient 9
 * All other values shall be interpreted as "CN Specific DRX cycle length coefficient not
 * specified by the MS " by this version of the protocol.
 * NOTE: In Iu mode this field (octet 3 bits 8 to 5) is used, but was spare in earlier
 * versions of this protocol.
 */
static const range_string gsm_a_gmm_cn_spec_drs_cycle_len_coef_strings[] = {
	{ 0x00,	0x05, "CN Specific DRX cycle length coefficient not specified by the MS" },
	{ 0x06,	0x06, "CN Specific DRX cycle length coefficient 6" },
	{ 0x07,	0x07, "CN Specific DRX cycle length coefficient 7" },
	{ 0x08,	0x08, "CN Specific DRX cycle length coefficient 8" },
	{ 0x09,	0x09, "CN Specific DRX cycle length coefficient 9" },
	{ 0x0a, 0x0f, "CN Specific DRX cycle length coefficient not specified by the MS" },
	{ 0, 0, NULL },
};
guint16
de_gmm_drx_param(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8        oct;
	guint32	      curr_offset;
	const gchar  *str;
	proto_item   *tf = NULL;
	proto_tree   *tf_tree = NULL;

	curr_offset = offset;

	tf = proto_tree_add_text(tree,
		tvb, curr_offset, 2,
		"DRX Parameter");

	tf_tree = proto_item_add_subtree(tf, ett_gmm_drx );

	oct = tvb_get_guint8(tvb, curr_offset);

	switch(oct)
	{
		case 0:  str="704"; break;
		case 65: str="71";  break;
		case 66: str="72";  break;
		case 67: str="74";  break;
		case 68: str="75";  break;
		case 69: str="77";  break;
		case 70: str="79";  break;
		case 71: str="80";  break;
		case 72: str="83";  break;
		case 73: str="86";  break;
		case 74: str="88";  break;
		case 75: str="90";  break;
		case 76: str="92";  break;
		case 77: str="96";  break;
		case 78: str="101"; break;
		case 79: str="103"; break;
		case 80: str="107"; break;
		case 81: str="112"; break;
		case 82: str="116"; break;
		case 83: str="118"; break;
		case 84: str="128"; break;
		case 85: str="141"; break;
		case 86: str="144"; break;
		case 87: str="150"; break;
		case 88: str="160"; break;
		case 89: str="171"; break;
		case 90: str="176"; break;
		case 91: str="192"; break;
		case 92: str="214"; break;
		case 93: str="224"; break;
		case 94: str="235"; break;
		case 95: str="256"; break;
		case 96: str="288"; break;
		case 97: str="320"; break;
		case 98: str="352"; break;
		default: str="Reserved, interpreted as 1";
	}

	proto_tree_add_text(tf_tree,
		tvb, curr_offset, 1,
		"Split PG Cycle Code: %s (%u)",
		str,
		oct);

	curr_offset++;
	proto_tree_add_item(tf_tree, hf_gsm_a_gmm_cn_spec_drs_cycle_len_coef, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tf_tree, hf_gsm_a_gmm_split_on_ccch, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tf_tree, hf_gsm_a_gmm_non_drx_timer, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [9] 10.5.5.7 Force to standby (lower nibble)
 */
static const range_string gsm_a_gm_force_to_standby_vals[] = {
	{ 0x00, 0x00, "Force to standby not indicated" },
	{ 0x01, 0x01, "Force to standby indicated" },
	{ 0x02, 0x07, "Unknown, interpreted as Force to standby not indicated" },
	{ 0, 0, NULL }
};

static guint16
de_gmm_ftostby(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	bit_offset;

	/* IMPORTANT - IT'S ASSUMED THAT THE INFORMATION IS IN THE LOWER NIBBLE */
	bit_offset = (offset << 3) + 4;
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_force_to_standby, tvb, bit_offset + 1, 3, ENC_BIG_ENDIAN);

	/* no length check possible */
	return(1);
}

/*
 * [9] 10.5.5.7 Force to standby (higher nibble)
 */
static guint16
de_gmm_ftostby_h(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	bit_offset;

	/* IMPORTANT - IT'S ASSUMED THAT THE INFORMATION IS IN THE HIGHER NIBBLE */
	bit_offset = offset << 3;
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_force_to_standby, tvb, bit_offset + 1, 3, ENC_BIG_ENDIAN);

	/* no length check possible */
	return(1);
}

/*
 * [7] 10.5.5.8
 */
static guint16
de_gmm_ptmsi_sig(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32       curr_offset;
	proto_item   *curr_item;

	curr_offset = offset;

	curr_item= proto_tree_add_item(tree,hf_gsm_a_ptmsi_sig,tvb,curr_offset,3,ENC_BIG_ENDIAN);
	proto_item_append_text(curr_item,"%s",add_string ? add_string : "");

	curr_offset+=3;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.8a
 */
static guint16
de_gmm_ptmsi_sig2(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string, int string_len _U_)
{
	guint32       curr_offset;
	proto_item   *curr_item;

	curr_offset = offset;

	curr_item= proto_tree_add_item(tree,hf_gsm_a_ptmsi_sig2,tvb,curr_offset,3,ENC_BIG_ENDIAN);
	proto_item_append_text(curr_item,"%s",add_string ? add_string : "");
	curr_offset+=3;

	EXTRANEOUS_DATA_CHECK_EXPERT(len, curr_offset - offset, pinfo);

	return(curr_offset - offset);
}

/*
 * [9] 10.5.5.9 Identity type 2
 */
static const value_string gsm_a_gm_type_of_identity_vals[] = {
	{ 0x01, "IMSI" },
	{ 0x02, "IMEI" },
	{ 0x03, "IMEISV" },
	{ 0x04, "TMSI" },
	{ 0, NULL }
};

static guint16
de_gmm_ident_type2(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (offset << 3) + 4, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_type_of_identity, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* no length check possible */
	return(1);
}

/*
 * [9] 10.5.5.10 IMEISV request
 */
static const range_string gsm_a_gm_imeisv_req_vals[] = {
	{ 0x00, 0x00, "IMEISV not requested" },
	{ 0x01, 0x01, "IMEISV requested" },
	{ 0x02, 0x07, "Unknown, interpreted as IMEISV not requested" },
	{ 0, 0, NULL }
};

static guint16
de_gmm_imeisv_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	bit_offset;

	/* IMPORTANT - IT'S ASSUMED THAT THE INFORMATION IS IN THE HIGHER NIBBLE */
	bit_offset = offset << 3;
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_imeisv_req, tvb, bit_offset + 1, 3, ENC_BIG_ENDIAN);

	/* no length check possible */
	return(1);
}

/*
 * [7] 10.5.5.11
 */
static guint16
de_gmm_rec_npdu_lst(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint	curr_len;

	curr_len = len;
	curr_offset = offset;

	if ( len == 0 ) return 0;

	do
	{
		guint32	oct;
		oct = tvb_get_guint8(tvb, curr_offset);
		oct <<=8;
		oct |= tvb_get_guint8(tvb, curr_offset+1);
		curr_len -= 2;
		oct <<=8;

		proto_tree_add_text(tree,
			tvb, curr_offset, 2,
			"NSAPI %d: 0x%02x (%u)",
			oct>>20,
			(oct>>12)&0xff,
			(oct>>12)&0xff);
		curr_offset+= 2;

		if ( curr_len > 2 )
		{
			oct |= tvb_get_guint8(tvb, curr_offset+2);
			curr_len--;
			oct <<= 12;

			proto_tree_add_text(tree,
				tvb, curr_offset-1, 2,
				"NSAPI %d: 0x%02x (%u)",
				oct>>20,
				(oct>>12)&0xff,
				(oct>>12)&0xff);
			curr_offset++;
		}

	} while ( curr_len > 1 );

	EXTRANEOUS_DATA_CHECK_EXPERT(len, curr_offset - offset, pinfo);

	return(curr_offset - offset);
}

/*
 * [9] 10.5.5.12 MS network capability
 */
static const true_false_string gsm_a_gmm_net_cap_gea_vals = {
	"Encryption algorithm available",
	"Encryption algorithm not available"
};

static const true_false_string gsm_a_gmm_net_cap_smdch_vals = {
	"Mobile station supports mobile terminated point to point SMS via dedicated signalling channels",
	"Mobile station does not support mobile terminated point to point SMS via dedicated signalling channels"
};

static const true_false_string gsm_a_gmm_net_cap_smgprs_vals = {
	"Mobile station supports mobile terminated point to point SMS via GPRS packet data channels",
	"Mobile station does not support mobile terminated point to point SMS via GPRS packet data channels"
};

static const true_false_string gsm_a_gmm_net_cap_ucs2_vals = {
	"The ME has no preference between the use of the default alphabet and the use of UCS2",
	"The ME has a preference for the default alphabet (defined in 3GPP TS 23.038 [8b]) over UCS2"
};

static const value_string gsm_a_gmm_net_cap_ss_scr_ind_vals[]={
	{ 0x00, "Default value of phase 1" },
	{ 0x01, "capability of handling of ellipsis notation and phase 2 error handling" },
	{ 0x02, "For future use, interpreted as Capability of handling of ellipsis notation and phase 2 error handling" },
	{ 0x03, "For future use, interpreted as Capability of handling of ellipsis notation and phase 2 error handling" },
	{ 0x00, NULL }
};

static const true_false_string gsm_a_gmm_net_cap_solsa_vals = {
	"The ME supports SoLSA",
	"The ME does not support SoLSA"
};

static const true_false_string gsm_a_gmm_net_cap_rev_vals = {
	"Used by a mobile station supporting R99 or later versions of the protocol",
	"Used by a mobile station not supporting R99 or later versions of the protocol"
};

static const true_false_string gsm_a_gmm_net_cap_pfc_vals = {
	"Mobile station does support BSS packet flow procedures",
	"Mobile station does not support BSS packet flow procedures"
};

static const true_false_string gsm_a_gmm_net_cap_lcs_vals = {
	"LCS value added location request notification capability supported",
	"LCS value added location request notification capability not supported"
};

static const true_false_string gsm_a_gmm_net_cap_ps_irat_iu_vals = {
	"PS inter-RAT HO to UTRAN Iu mode supported",
	"PS inter-RAT HO to UTRAN Iu mode not supported"
};

static const true_false_string gsm_a_gmm_net_cap_ps_irat_s1_vals = {
	"PS inter-RAT HO to E-UTRAN S1 mode supported",
	"PS inter-RAT HO to E-UTRAN S1 mode not supported"
};

static const true_false_string gsm_a_gmm_net_cap_comb_proc_vals = {
	"Mobile station supports EMM combined procedures",
	"Mobile station does not support EMM combined procedures"
};

static const true_false_string gsm_a_gmm_net_cap_isr_vals = {
	"The mobile station supports ISR",
	"The mobile station does not support ISR"
};

static const true_false_string gsm_a_gmm_net_cap_srvcc_to_geran_vals = {
	"SRVCC from UTRAN HSPA or E-UTRAN to GERAN/UTRAN supported",
	"SRVCC from UTRAN HSPA or E-UTRAN to GERAN/UTRAN not supported"
};

static const true_false_string gsm_a_gmm_net_cap_epc_vals = {
	"EPC supported",
	"EPC not supported"
};

static const true_false_string gsm_a_gmm_net_cap_nf_vals = {
	"Mobile station supports the notification procedure",
	"Mobile station does not support the notification procedure"
};

guint16
de_gmm_ms_net_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	proto_tree	*subtree;
	proto_item	*item;

	curr_offset = offset;

	/* bit 8: GEA1 */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_gea1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bit 7: SM capabilities via dedicated channels */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_smdch, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bit 6: SM capabilities via GPRS channels */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_smgprs, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bit 5: UCS2 support */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_ucs2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bits 4 3: SS Screening Indicator */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_ss_scr_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bit 2: SoLSA Capability */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_solsa, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bit 1 */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_rev, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	curr_offset++;
	NO_MORE_DATA_CHECK(len);

	/* bit 8: PFC feature mode */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_pfc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bits 7 6 5 4 3 2: Extended GEA bits */
	item = proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_ext_gea_bits, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	subtree = proto_item_add_subtree(item, ett_gmm_network_cap);
	proto_tree_add_item(subtree, hf_gsm_a_gmm_net_cap_gea2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(subtree, hf_gsm_a_gmm_net_cap_gea3, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(subtree, hf_gsm_a_gmm_net_cap_gea4, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(subtree, hf_gsm_a_gmm_net_cap_gea5, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(subtree, hf_gsm_a_gmm_net_cap_gea6, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(subtree, hf_gsm_a_gmm_net_cap_gea7, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bit 1: LCS VA capability */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_lcs, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	curr_offset++;
	NO_MORE_DATA_CHECK(len);

	/* bit 8: PS inter-RAT HO to UTRAN Iu mode capability */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_ps_irat_iu, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bit 7: PS inter-RAT HO to E-UTRAN S1 mode capability */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_ps_irat_s1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bit 6: EMM Combined procedures capability */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_comb_proc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bit 5: ISR support */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_isr, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bit 4: SRVCC to GERAN/UTRAN capability */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_srvcc_to_geran, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bit 3: EPC capability */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_epc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bit 3: NF capability */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_nf, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bits 1: Spare bit */
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3)+7, 1, ENC_BIG_ENDIAN);

	curr_offset++;
	EXTRANEOUS_DATA_CHECK_EXPERT(len, curr_offset - offset, pinfo);

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.12a
 */
#define GET_DATA				/* check if we have enough bits left */ \
	if ( curr_bits_length < bits_needed ) \
		continue; \
	/* check if oct has enougth bits */ \
	if ( bits_in_oct < bits_needed ) \
	{ \
		guint32 tmp_oct; \
		if ( curr_len == 0 ) \
		{ \
			proto_tree_add_text(tf_tree, \
				tvb, curr_offset, 1, \
				"Not enough data available"); \
		} \
		tmp_oct = tvb_get_guint8(tvb, curr_offset); \
		oct |= tmp_oct<<(32-8-bits_in_oct); \
		curr_len--; \
		curr_offset++; \
		if ( bits_in_oct != 0 ) \
			add_ocetets = 1; \
		else \
			add_ocetets = 0; \
		bits_in_oct += 8; \
	} \
	else \
		add_ocetets = 0;

/* Access Technology Type */

static const value_string gsm_a_gm_acc_tech_type_vals[] = {
	{ 0x00, "GSM P" },
	{ 0x01, "GSM E --note that GSM E covers GSM P" },
	{ 0x02, "GSM R --note that GSM R covers GSM E and GSM P" },
	{ 0x03, "GSM 1800" },
	{ 0x04, "GSM 1900" },
	{ 0x05, "GSM 450" },
	{ 0x06, "GSM 480" },
	{ 0x07, "GSM 850" },
	{ 0x08, "GSM 750" },
	{ 0x09, "GSM T 380" },
	{ 0x0a, "GSM T 410" },
	{ 0x0b, "GSM T 900" },
	{ 0x0c, "GSM 710" },
	{ 0x0d, "GSM T 810" },
	{ 0x0f, "Indicates the presence of a list of Additional access technologies" },
	{ 0, NULL }
};

static const true_false_string gsm_a_gm_vgcs = {
	"VGCS capability and notifications wanted",
	"no VGCS capability or no notifications wanted"
};

static const true_false_string gsm_a_gm_vbs = {
	"VBS capability and notifications wanted",
	"no VBS capability or no notifications wanted"
};

static const value_string gsm_a_gm_multi_slot_vals[] = {
	{ 0x00,	"Not specified" },
	{ 0x01, "Max Rx-Slot/TDMA:1 Max Tx-Slot/TDMA:1 Max-Sum-Slot/TDMA:2 Tta:3 Ttb:2 Tra:4 Trb:2 Type:1" },
	{ 0x02, "Max Rx-Slot/TDMA:2 Max Tx-Slot/TDMA:1 Max-Sum-Slot/TDMA:3 Tta:3 Ttb:2 Tra:3 Trb:1 Type:1" },
	{ 0x03, "Max Rx-Slot/TDMA:2 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:3 Tta:3 Ttb:2 Tra:3 Trb:1 Type:1" },
	{ 0x04, "Max Rx-Slot/TDMA:3 Max Tx-Slot/TDMA:1 Max-Sum-Slot/TDMA:4 Tta:3 Ttb:1 Tra:3 Trb:1 Type:1" },
	{ 0x05, "Max Rx-Slot/TDMA:2 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:4 Tta:3 Ttb:1 Tra:3 Trb:1 Type:1" },
	{ 0x06, "Max Rx-Slot/TDMA:3 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:4 Tta:3 Ttb:1 Tra:3 Trb:1 Type:1" },
	{ 0x07, "Max Rx-Slot/TDMA:3 Max Tx-Slot/TDMA:3 Max-Sum-Slot/TDMA:4 Tta:3 Ttb:1 Tra:3 Trb:1 Type:1" },
	{ 0x08, "Max Rx-Slot/TDMA:4 Max Tx-Slot/TDMA:1 Max-Sum-Slot/TDMA:5 Tta:3 Ttb:1 Tra:2 Trb:1 Type:1" },
	{ 0x09, "Max Rx-Slot/TDMA:3 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:5 Tta:3 Ttb:1 Tra:2 Trb:1 Type:1" },
	{ 0x0a, "Max Rx-Slot/TDMA:4 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:5 Tta:3 Ttb:1 Tra:2 Trb:1 Type:1" },
	{ 0x0b, "Max Rx-Slot/TDMA:4 Max Tx-Slot/TDMA:3 Max-Sum-Slot/TDMA:5 Tta:3 Ttb:1 Tra:2 Trb:1 Type:1" },
	{ 0x0c, "Max Rx-Slot/TDMA:4 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:5 Tta:2 Ttb:1 Tra:2 Trb:1 Type:1" },
	{ 0x0d, "Max Rx-Slot/TDMA:3 Max Tx-Slot/TDMA:3 Max-Sum-Slot/TDMA:NA Tta:NA Ttb:a) Tra:3 Trb:a) Type:2 (a: 1 with frequency hopping, 0 otherwise)" },
	{ 0x0e, "Max Rx-Slot/TDMA:4 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:NA Tta:NA Ttb:a) Tra:3 Trb:a) Type:2 (a: 1 with frequency hopping, 0 otherwise)" },
	{ 0x0f, "Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:5 Max-Sum-Slot/TDMA:NA Tta:NA Ttb:a) Tra:3 Trb:a) Type:2 (a: 1 with frequency hopping, 0 otherwise)" },
	{ 0x10, "Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:6 Max-Sum-Slot/TDMA:NA Tta:NA Ttb:a) Tra:2 Trb:a) Type:2 (a: 1 with frequency hopping, 0 otherwise)" },
	{ 0x11, "Max Rx-Slot/TDMA:7 Max Tx-Slot/TDMA:7 Max-Sum-Slot/TDMA:NA Tta:NA Ttb:a) Tra:1 Trb:0 Type:2 (a: 1 with frequency hopping, 0 otherwise)" },
	{ 0x12, "Max Rx-Slot/TDMA:8 Max Tx-Slot/TDMA:8 Max-Sum-Slot/TDMA:NA Tta:NA Ttb:0 Tra:0 Trb:0 Type:2" },
	{ 0x13, "Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise" },
	{ 0x14, "Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:3 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise" },
	{ 0x15, "Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise" },
	{ 0x16, "Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise" },
	{ 0x17, "Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:6 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise" },
	{ 0x18, "Max Rx-Slot/TDMA:8 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise" },
	{ 0x19, "Max Rx-Slot/TDMA:8 Max Tx-Slot/TDMA:3 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise" },
	{ 0x1a, "Max Rx-Slot/TDMA:8 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise" },
	{ 0x1b, "Max Rx-Slot/TDMA:8 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise" },
	{ 0x1c, "Max Rx-Slot/TDMA:8 Max Tx-Slot/TDMA:6 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise" },
	{ 0x1d, "Max Rx-Slot/TDMA:8 Max Tx-Slot/TDMA:8 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise" },
	{ 0x1e, "Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:1 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1 Trb:1 Type:1" },
	{ 0x1f, "Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1 Trb:1 Type:1" },
	{ 0x20, "Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:3 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1 Trb:1 Type:1" },
	{ 0x21, "Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1 Trb:1 Type:1" },
	{ 0x22, "Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:5 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1 Trb:1 Type:1" },
	{ 0x23, "Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:1 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1+to Trb:1 Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))" },
	{ 0x24, "Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1+to Trb:1 Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))" },
	{ 0x25, "Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:3 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1+to Trb:1 Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))" },
	{ 0x26, "Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1+to Trb:1 Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))" },
	{ 0x27, "Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:5 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1+to Trb:1 Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))" },
	{ 0x28, "Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:1 Max-Sum-Slot/TDMA:7 Tta:1 Ttb:1 Tra:1 Trb:to Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))" },
	{ 0x29, "Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:7 Tta:1 Ttb:1 Tra:1 Trb:to Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))" },
	{ 0x2a, "Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:3 Max-Sum-Slot/TDMA:7 Tta:1 Ttb:1 Tra:1 Trb:to Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))" },
	{ 0x2b, "Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:7 Tta:1 Ttb:1 Tra:1 Trb:to Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))" },
	{ 0x2c, "Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:5 Max-Sum-Slot/TDMA:7 Tta:1 Ttb:1 Tra:1 Trb:to Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))" },
	{ 0x2d, "Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:6 Max-Sum-Slot/TDMA:7 Tta:1 Ttb:1 Tra:1 Trb:to Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))" },
	{ 0, NULL }
};

static const value_string gsm_a_gm_dtm_gprs_multi_slot_class_vals[] = {
	{ 0x00, "Unused. If received, the network shall interpret this as Multislot class 5" },
	{ 0x01, "Multislot class 5 supported" },
	{ 0x02, "Multislot class 9 supported" },
	{ 0x03, "Multislot class 11 supported" },
	{ 0, NULL }
};

static const true_false_string gsm_a_gm_revision_level_indicator = {
	"The ME is Release '99 onwards",
	"The ME is Release '98 or older"
};

static const value_string gsm_a_gm_down_adv_rec_perf_vals[] = {
	{ 0x00, "Downlink Advanced Receiver Performance not supported" },
	{ 0x01, "Downlink Advanced Receiver Performance - phase I supported" },
	{ 0x02, "Downlink Advanced Receiver Performance - phase II supported" },
	{ 0, NULL }
};

static const true_false_string gsm_a_gm_dtm_enh_cap = {
	"The mobile station supports enhanced DTM CS establishment and enhanced DTM CS release procedures",
	"The mobile station does not support enhanced DTM CS establishment and enhanced DTM CS release procedures"
};

static const value_string gsm_a_gm_dtm_gprs_high_multi_slot_class_vals[] = {
	{ 0x00, "Unused. If received, the network shall interpret this as 'Multislot class 31 or 36 supported'" },
	{ 0x01, "Multislot class 31 or 36 supported" },
	{ 0x02, "Multislot class 32 or 37 supported" },
	{ 0x03, "Multislot class 33 or 38 supported" },
	{ 0x04, "Multislot class 41 supported" },
	{ 0x05, "Multislot class 42 supported" },
	{ 0x06, "Multislot class 43 supported" },
	{ 0x07, "Multislot class 44 supported" },
	{ 0, NULL }
};

static const value_string gsm_a_gm_multi_slot_cap_red_down_dual_carrier_vals[] = {
	{ 0x00, "No reduction" },
	{ 0x01, "The MS supports 1 timeslot fewer than the maximum number of receive timeslots" },
	{ 0x02, "The MS supports 2 timeslots fewer than the maximum number of receive timeslots" },
	{ 0x03, "The MS supports 3 timeslots fewer than the maximum number of receive timeslots" },
	{ 0x04, "The MS supports 4 timeslots fewer than the maximum number of receive timeslots" },
	{ 0x05, "The MS supports 5 timeslots fewer than the maximum number of receive timeslots" },
	{ 0x06, "The MS supports 6 timeslots fewer than the maximum number of receive timeslots" },
	{ 0x07, "Reserved for future use" },
	{ 0, NULL }
};

static const value_string gsm_a_gm_ul_egprs2_vals[] = {
	{ 0x00, "The mobile station does not support either EGPRS2-A or EGPRS2-B in the uplink" },
	{ 0x01, "The mobile station supports EGPRS2-A in the uplink" },
	{ 0x02, "The mobile station supports both EGPRS2-A and EGPRS2-B in the uplink" },
	{ 0x03, "This value is not used in this release/version of the specifications. If received it shall be interpreted as 'The mobile station supports both EGPRS2-A and EGPRS2-B in the uplink'" },
	{ 0, NULL }
};

static const value_string gsm_a_gm_dl_egprs2_vals[] = {
	{ 0x00, "The mobile station does not support either EGPRS2-A or EGPRS2-B in the downlink" },
	{ 0x01, "The mobile station supports EGPRS2-A in the downlink" },
	{ 0x02, "The mobile station supports both EGPRS2-A and EGPRS2-B in the downlink" },
	{ 0x03, "This value is not used in this release/version of the specifications. If received it shall be interpreted as 'The mobile station supports both EGPRS2-A and EGPRS2-B in the downlink'" },
	{ 0, NULL }
};

static const value_string gsm_a_gm_geran_to_eutra_support_in_geran_ptm_vals[] = {
	{ 0x00, "None" },
	{ 0x01, "E-UTRAN Neighbour Cell measurements and MS autonomous cell reselection to E-UTRAN supported" },
	{ 0x02, "CCN towards E-UTRAN, E-UTRAN Neighbour Cell measurement reporting and Network controlled cell reselection to E-UTRAN supported in addition to capabilities indicated by '01'" },
	{ 0x03, "PS Handover to E-UTRAN supported in addition to capabilities indicated by '01' and '10'" },
	{ 0, NULL }
};

static const value_string gsm_a_gm_alt_efta_multi_slot_class_vals[] = {
	{ 0x00, "No Alternative EFTA multislot class is indicated. Use (DTM) EGPRS (high) multislot class only" },
	{ 0x01, "Alternative EFTA multislot class is Multislot class 19" },
	{ 0x02, "Alternative EFTA multislot class is Multislot class 20" },
	{ 0x03, "Alternative EFTA multislot class is Multislot class 21" },
	{ 0x04, "Alternative EFTA multislot class is Multislot class 22" },
	{ 0x05, "Alternative EFTA multislot class is Multislot class 23" },
	{ 0x06, "Alternative EFTA multislot class is Multislot class 24" },
	{ 0x07, "Alternative EFTA multislot class is Multislot class 25" },
	{ 0x08, "Alternative EFTA multislot class is Multislot class 26" },
	{ 0x09, "Alternative EFTA multislot class is Multislot class 27" },
	{ 0x0a, "Alternative EFTA multislot class is Multislot class 28" },
	{ 0x0b, "Alternative EFTA multislot class is Multislot class 29" },
	{ 0x0c, "Unused" },
	{ 0x0d, "Unused" },
	{ 0x0e, "Unused" },
	{ 0x0f, "Unused" },
	{ 0, NULL }
};

guint16
de_gmm_ms_radio_acc_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32      curr_offset;
	guint        curr_len;
	int          bit_offset;
	proto_item  *tf = NULL, *mc_item = NULL;
	proto_tree  *tf_tree = NULL, *mc_tree = NULL;
	guint32      oct;
	guchar       bits_in_oct;
	guchar       bits_needed;
	guint        bits_length;
	guint        add_ocetets;	/* octets which are covered by one element -1 */
	guint        curr_bits_length;
	guchar       acc_type;
	guint        value;
	const gchar *str;
	guint indx = 0;
	guchar dtm_gprs_mslot = 0;
	guchar dtm_egprs_mslot = 4;
	gboolean finished = TRUE;

	curr_len = len;
	curr_offset = offset;
	bit_offset = offset<<3;

	bits_in_oct = 0;
	oct = 0;


	do
	{
		/* check for a new round */
		if (( curr_len*8 + bits_in_oct ) < 11 )
			break;

		/* now read the first 11 bits */
		curr_bits_length = 11;
		/*
		 *
		 */
		if ( curr_len != len )
		{
			bits_needed = 1;
			GET_DATA;

			if (( oct>>(32-bits_needed) ) == 1 )
			{
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
				bit_offset++;

				if (( curr_len*8 + bits_in_oct ) < 11 )
					break;
				curr_bits_length = 11;
			}
			else
			{
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
				bit_offset++;
				break;
			}
		}

		indx++;
		tf = proto_tree_add_text(tree,
				tvb, curr_offset, 1,
				"MS RA capability %d",indx);

		tf_tree = proto_item_add_subtree(tf, ett_gmm_radio_cap );

		/*
		 * Access Technology
		 */
		bits_needed = 4;
		GET_DATA;

		acc_type = oct>>(32-bits_needed);

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_acc_tech_type, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
		bit_offset+=4;

		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/* < Access capabilities struct > ::= */
		/*
		 * get bits_length
		 */
		bits_needed = 7;
		GET_DATA;

		bits_length = curr_bits_length = oct>>(32-bits_needed);

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_acc_cap_struct_len, tvb, bit_offset, 7, ENC_BIG_ENDIAN);
		proto_item_set_len(tf, (bits_length>>3)+1);
		/* This is already done - length doesn't contain this field
		 curr_bits_length -= bits_needed;
		*/
		bit_offset+=7;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		if ( acc_type == 0x0f )
		{
			do
			{
				/*
				 * Additional access technologies:
				 */
				finished = TRUE; /* Break out of the loop unless proven unfinished */

				/*
				 * Presence bit
				 */
				bits_needed = 1;
				GET_DATA;

				/* analyse bits */
				switch ( oct>>(32-bits_needed) )
				{
					case 0x00: str="Not Present"; finished = TRUE; break;
					case 0x01: str="Present"; finished = FALSE;    break;
					default:   str="This should not happen";
				}

				proto_tree_add_text(tf_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"Presence: %s (%u)", str, oct>>(32-bits_needed));
				bit_offset++;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;

				if (finished)
				{
					/*
					 * No more valid data, get spare bits if any
					 */
					while ( curr_bits_length > 0 )
					{
						if ( curr_bits_length > 8 )
							bits_needed = 8;
						else
							bits_needed = curr_bits_length;
						GET_DATA;
						curr_bits_length -= bits_needed;
						oct <<= bits_needed;
						bits_in_oct -= bits_needed;
						bit_offset+= bits_needed;
					}
					continue;
				}

				/*
				 * Access Technology
				 */
				bits_needed = 4;
				GET_DATA;

				acc_type = oct>>(32-bits_needed);

				proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_acc_cap_struct_len, tvb, bit_offset, 7, ENC_BIG_ENDIAN);
				bit_offset+=4;

				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;

				/*
				 * RF Power
				 */
				bits_needed = 3;
				GET_DATA;

				value = tvb_get_bits8(tvb, bit_offset, 3);
				/* analyse bits */
				if ( acc_type == 0x04 )	/* GSM 1900 */
				{
					switch ( value )
					{
						case 0x01: str="1 W (30 dBm)";    break;
						case 0x02: str="0,25 W (24 dBm)"; break;
						case 0x03: str="2 W (33 dBm)";    break;
						default:   str="Not specified";
					}
				}
				else if ( acc_type == 0x03 )
				{
					/*
					 * 3 GSM 1800
					 */
					switch ( value )
					{
						case 0x01: str="1 W (30 dBm)";    break;
						case 0x02: str="0,25 W (24 dBm)"; break;
						case 0x03: str="4 W (36 dBm)";    break;
						default:   str="Not specified";
					}
				}
				else if ( acc_type <= 0x08 )
				{
					/* 0 GSM P
					 * 1 GSM E
					 * 2 GSM R
					 * 5 GSM 450
					 * 6 GSM 480
					 * 7 GSM 850
					 */

					switch ( value )
					{
						case 0x02: str="8 W (39 dBm)";   break;
						case 0x03: str="5 W (37 dBm)";   break;
						case 0x04: str="2 W (33 dBm)";   break;
						case 0x05: str="0,8 W (29 dBm)"; break;
						default:   str="Not specified";
					}
				}
				else
					str="Not specified??";

				/* decode_bits_in_field(gint bit_offset, gint no_of_bits, guint64 value)*/
				proto_tree_add_text(tf_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"%s RF Power Capability, GMSK Power Class: %s (%u)", decode_bits_in_field(bit_offset, 3, value), str, value);
				bit_offset+=3;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;

				/*
				 * 8PSK Power Class
				 */
				bits_needed = 2;
				GET_DATA;

				value = tvb_get_bits8(tvb, bit_offset, 2);
				/* analyse bits */
				switch ( value )
				{
					case 0x00: str="8PSK modulation not supported for uplink"; break;
					case 0x01: str="Power class E1"; break;
					case 0x02: str="Power class E2"; break;
					case 0x03: str="Power class E3"; break;
					default:   str="This should not happen";
				}

				proto_tree_add_text(tf_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"8PSK Power Class: %s (%u)",str,value);
				bit_offset+=2;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;

			} while (!finished);

			/* goto next one */
			continue;
		}
		/*
		 * RF Power
		 */
		bits_needed = 3;
		GET_DATA;

		value = tvb_get_bits8(tvb, bit_offset, 3);
		/* analyse bits */
		if ( acc_type == 0x04 )	/* GSM 1900 */
		{
			switch ( value )
			{
				case 0x01: str="1 W (30 dBm)";    break;
				case 0x02: str="0,25 W (24 dBm)"; break;
				case 0x03: str="2 W (33 dBm)";    break;
				default:   str="Not specified";
			}
		}
		else if ( acc_type == 0x03 )
		{
			switch ( value )
			{
				case 0x01: str="1 W (30 dBm)";    break;
				case 0x02: str="0,25 W (24 dBm)"; break;
				case 0x03: str="4 W (36 dBm)";    break;
				default:   str="Not specified";
			}
		}
		else if ( acc_type <= 0x08 )
		{
			switch ( value )
			{
				case 0x02: str="8 W (39 dBm)";   break;
				case 0x03: str="5 W (37 dBm)";   break;
				case 0x04: str="2 W (33 dBm)";   break;
				case 0x05: str="0,8 W (29 dBm)"; break;
				default:   str="Not specified";
			}
		}
		else
			str="Not specified??";

		proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"%s RF Power Capability, GMSK Power Class: %s (%u)", decode_bits_in_field(bit_offset, 3, value),str,value);

		bit_offset+=3;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * A5 Bits?
		 */
		bits_needed = 1;
		GET_DATA;

		/* analyse bits */
		if ((oct>>(32-bits_needed))==0)
		{
			proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"A5 Bits: Same values apply for parameters as in the immediately preceding Access capabilities field within this IE (%u)",oct>>(32-bits_needed));
			bit_offset++;
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
		}
		else
		{
			int i;

			proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"A5 Bits: A5 bits follow (%u)",oct>>(32-bits_needed));

			bit_offset++;
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;

			for (i=1; i<= 7 ; i++ )
			{
				/*
				 * A5 Bits decoding
				 */
				bits_needed = 1;
				GET_DATA;

				/* analyse bits */
				switch ( oct>>(32-bits_needed) )
				{
					case 0x00: str="encryption algorithm not available"; break;
					case 0x01: str="encryption algorithm available";     break;
					default:   str="This should not happen";
				}

				proto_tree_add_text(tf_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"A5/%d: %s (%u)",i,str,oct>>(32-bits_needed));
				bit_offset++;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
			}
		}

		/*
		 * ES IND
		 */
		bits_needed = 1;
		GET_DATA;

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_ctrled_early_cm_sending, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset++;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * PS
		 */
		bits_needed = 1;
		GET_DATA;

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_pseudo_sync, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset++;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * VGCS
		 */
		bits_needed = 1;
		GET_DATA;

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_vgcs, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset++;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * VBS
		 */
		bits_needed = 1;
		GET_DATA;

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_vbs, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset++;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * Multislot capability?
		 */
		bits_needed = 1;
		GET_DATA;

		value = oct>>(32-bits_needed);

		mc_item = proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_multislot_capability, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset++;

		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/* analyse bits */
		if (value==1)
		{
			mc_tree = proto_item_add_subtree(mc_item, ett_gsm_a_gm_msrac_multislot_capability);
			/*
			 * HSCSD multislot class?
			 */
			bits_needed = 1;
			GET_DATA;

			/* analyse bits */
			if ((oct>>(32-bits_needed))==0)
			{
				proto_tree_add_text(mc_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"HSCSD multislot class: Bits are not available (%u)",oct>>(32-bits_needed));
				bit_offset++;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
			}
			else
			{
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
				bit_offset++;

				/*
				 * HSCSD multislot class
				 */
				bits_needed = 5;
				GET_DATA;

				proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_hscsd_multi_slot_class, tvb, bit_offset, 5, ENC_BIG_ENDIAN);
				bit_offset+=5;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
			}

			/*
			 * GPRS multislot class?
			 */
			bits_needed = 1;
			GET_DATA;

			/* analyse bits */
			if ((oct>>(32-bits_needed))==0)
			{
				proto_tree_add_text(mc_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"GPRS multislot class: Bits are not available (%u)",oct>>(32-bits_needed));
				bit_offset++;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
			}
			else
			{
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
				bit_offset++;

				/*
				 * GPRS multislot class
				 */
				bits_needed = 5;
				GET_DATA;

				proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_gprs_multi_slot_class, tvb, bit_offset, 5, ENC_BIG_ENDIAN);
				bit_offset+=5;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;

				/*
				 * GPRS Extended Dynamic Allocation Capability
				 */
				bits_needed = 1;
				GET_DATA;

				proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_gprs_ext_dyn_alloc_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
				bit_offset++;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
			}

			/*
			 * SMS/SM values
			 */
			bits_needed = 1;
			GET_DATA;

			/* analyse bits */
			if ((oct>>(32-bits_needed))==0)
			{
				proto_tree_add_text(mc_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"SMS/SM values: Bits are not available (%u)",oct>>(32-bits_needed));
				bit_offset++;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
   	 			bits_in_oct -= bits_needed;
			}
			else
			{
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
				bit_offset++;

				/*
				 * Switch-Measure-Switch value
				 */
				bits_needed = 4;
				GET_DATA;

				/* analyse bits */
				proto_tree_add_bits_item(mc_tree, hf_gsm_a_gm_sms_value, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
				bit_offset+=4;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;

				/*
				 * Switch-Measure value
				 */
				bits_needed = 4;
				GET_DATA;

				/* analyse bits */
				proto_tree_add_bits_item(mc_tree, hf_gsm_a_gm_sm_value, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
				bit_offset+=4;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
			}

			/*
			 * ECSD multislot class?
			 */
			bits_needed = 1;
			GET_DATA;

			/* analyse bits */
			if ((oct>>(32-bits_needed))==0)
			{
				proto_tree_add_text(mc_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"ECSD multislot class: Bits are not available (%u)",oct>>(32-bits_needed));
				bit_offset++;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
			}
			else
			{
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
				bit_offset++;

				/*
				 * ECSD multislot class
				 */
				bits_needed = 5;
				GET_DATA;

				proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_ecsd_multi_slot_class, tvb, bit_offset, 5, ENC_BIG_ENDIAN);
				bit_offset+=5;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
			}

			/*
			 * EGPRS multislot class?
			 */
			bits_needed = 1;
			GET_DATA;

			/* analyse bits */
			if ((oct>>(32-bits_needed))==0)
			{
				proto_tree_add_text(mc_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"EGPRS multislot class: Bits are not available (%u)",oct>>(32-bits_needed));
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
				bit_offset++;
			}
			else
			{
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
				bit_offset++;

				/*
				 * EGPRS multislot class
				 */
				bits_needed = 5;
				GET_DATA;

				proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_egprs_multi_slot_class, tvb, bit_offset, 5, ENC_BIG_ENDIAN);
				bit_offset+=5;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;

				/*
				 * EGPRS Extended Dynamic Allocation Capability
				 */
				bits_needed = 1;
				GET_DATA;

				proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_egprs_ext_dyn_alloc_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
				bit_offset++;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
			}

			/*
			 * DTM GPRS Multi Slot Class ?
			*/
			bits_needed = 1;
			GET_DATA;

			/* analyse bits */
			if ((oct>>(32-bits_needed))==0)
			{
				proto_tree_add_text(mc_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"DTM GPRS Multi Slot Class: Bits are not available (%u)",oct>>(32-bits_needed));
				bit_offset++;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
   	 			bits_in_oct -= bits_needed;
			}
			else
			{
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
   	 			bits_in_oct -= bits_needed;
				bit_offset++;

				/*
				 * DTM GPRS Multi Slot Class
				 */
				bits_needed = 2;
				GET_DATA;

				/* analyse bits */
				dtm_gprs_mslot = oct>>(32-bits_needed);

				proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_dtm_gprs_multi_slot_class, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
				bit_offset+=2;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;

				/*
				 * Single Slot DTM
				 */
				bits_needed = 1;
				GET_DATA;

				proto_tree_add_bits_item(mc_tree, hf_gsm_a_gm_rac_single_slt_dtm, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
				bit_offset++;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;

				/*
				 * DTM EGPRS Multi Slot Class ?
				*/
				bits_needed = 1;
				GET_DATA;

				/* analyse bits */
				dtm_egprs_mslot = oct>>(32-bits_needed);
				proto_tree_add_bits_item(mc_tree, hf_gsm_a_gm_rac_dtm_egprs_multi_slot_cls_pres, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
				bit_offset++;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
 				bits_in_oct -= bits_needed;

				if ((oct>>(32-bits_needed))==1)
				{
					/*
					 * DTM EGPRS Multi Slot Class
					 */
					bits_needed = 2;
					GET_DATA;

					proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_dtm_egprs_multi_slot_class, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
					bit_offset+=2;
					curr_bits_length -= bits_needed;
					oct <<= bits_needed;
					bits_in_oct -= bits_needed;
				}
			}
		}

		/*
		 * 8PSK Power Capability?
		 */
		bits_needed = 1;
		GET_DATA;

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_8psk_pow_cap_pres, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset++;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/* analyse bits */
		if ((oct>>(32-bits_needed))==1)
		{
			/*
			 * 8PSK Power Capability
			 */
			bits_needed = 2;
			GET_DATA;

			/* analyse bits */
			switch ( oct>>(32-bits_needed) )
			{
				case 0x00: str="Reserved";       break;
				case 0x01: str="Power class E1"; break;
				case 0x02: str="Power class E2"; break;
				case 0x03: str="Power class E3"; break;
				default:   str="This should not happen";
			}

			proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"8PSK Power Capability: %s (%u)",str,oct>>(32-bits_needed));
			bit_offset+=2;
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
		}

		/*
		 * COMPACT Interference Measurement Capability
		 */
		bits_needed = 1;
		GET_DATA;

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_comp_int_meas_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset++;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * Revision Level Indicator
		 */
		bits_needed = 1;
		GET_DATA;

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rel_lev_ind, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset++;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * UMTS FDD Radio Access Technology Capability
		 */
		bits_needed = 1;
		GET_DATA;

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_umts_fdd_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset++;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * UMTS 3.84 Mcps TDD Radio Access Technology Capability
		 */
		bits_needed = 1;
		GET_DATA;

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_umts_384_tdd_ra_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset++;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * CDMA 2000 Radio Access Technology Capability
		 */
		bits_needed = 1;
		GET_DATA;

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_cdma2000_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset++;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * UMTS 1.28 Mcps TDD Radio Access Technology Capability
		 */
		bits_needed = 1;
		GET_DATA;

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_umts_128_tdd_ra_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset++;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * GERAN Feature Package 1
		 */
		bits_needed = 1;
		GET_DATA;

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_geran_feat_pkg, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset++;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * Extended DTM (E)GPRS Multi Slot Class
		 */

		bits_needed = 1;
		GET_DATA;

		/* analyse bits */
		if ((oct>>(32-bits_needed))==0)
		{
			proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"Extended DTM (E)GPRS Multi Slot Class: Bits are not available (%u)",oct>>(32-bits_needed));
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
			bit_offset++;
		}
		else
		{
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
			bit_offset++;

			/*
			 * Extended DTM GPRS Multi Slot Class
			 */
			bits_needed = 2;
			GET_DATA;

			/* analyse bits */
			switch ( (oct>>(32-bits_needed))|(dtm_gprs_mslot<<4) )
			{
				case 0x00: str="Unused. If received, it shall be interpreted as Multislot class 5 supported";  break;
				case 0x01: str="Unused. If received, it shall be interpreted as Multislot class 5 supported";  break;
				case 0x02: str="Unused. If received, it shall be interpreted as Multislot class 5 supported";  break;
				case 0x03: str="Unused. If received, it shall be interpreted as Multislot class 5 supported";  break;
				case 0x10: str="Multislot class 5 supported";  break;
				case 0x11: str="Multislot class 6 supported";  break;
				case 0x12: str="Unused. If received, it shall be interpreted as Multislot class 5 supported";  break;
				case 0x13: str="Unused. If received, it shall be interpreted as Multislot class 5 supported";  break;
				case 0x20: str="Multislot class 9 supported";  break;
				case 0x21: str="Multislot class 10 supported"; break;
				case 0x22: str="Unused. If received, it shall be interpreted as Multislot class 9 supported";  break;
				case 0x23: str="Unused. If received, it shall be interpreted as Multislot class 9 supported";  break;
				case 0x30: str="Multislot class 11 supported"; break;
				case 0x31: str="Unused. If received, it shall be interpreted as Multislot class 11 supported"; break;
				case 0x32: str="Unused. If received, it shall be interpreted as Multislot class 11 supported"; break;
				case 0x33: str="Unused. If received, it shall be interpreted as Multislot class 11 supported"; break;
				default:   str="This should not happen";
			}

			proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"Extended DTM GPRS Multi Slot Class: %s (%u)",str,oct>>(32-bits_needed));
			bit_offset+=2;
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;

			if ( dtm_egprs_mslot <= 3 )
			{
				/*
				 * Extended DTM EGPRS Multi Slot Class
				 */
				bits_needed = 2;
				GET_DATA;

				/* analyse bits */
				switch ( (oct>>(32-bits_needed))|(dtm_egprs_mslot<<4) )
				{
					case 0x00: str="Unused. If received, it shall be interpreted as Multislot class 5 supported";  break;
					case 0x01: str="Unused. If received, it shall be interpreted as Multislot class 5 supported";  break;
					case 0x02: str="Unused. If received, it shall be interpreted as Multislot class 5 supported";  break;
					case 0x03: str="Unused. If received, it shall be interpreted as Multislot class 5 supported";  break;
					case 0x10: str="Multislot class 5 supported";  break;
					case 0x11: str="Multislot class 6 supported";  break;
					case 0x12: str="Unused. If received, it shall be interpreted as Multislot class 5 supported";  break;
					case 0x13: str="Unused. If received, it shall be interpreted as Multislot class 5 supported";  break;
					case 0x20: str="Multislot class 9 supported";  break;
					case 0x21: str="Multislot class 10 supported"; break;
					case 0x22: str="Unused. If received, it shall be interpreted as Multislot class 9 supported";  break;
					case 0x23: str="Unused. If received, it shall be interpreted as Multislot class 9 supported";  break;
					case 0x30: str="Multislot class 11 supported"; break;
					case 0x31: str="Unused. If received, it shall be interpreted as Multislot class 11 supported"; break;
					case 0x32: str="Unused. If received, it shall be interpreted as Multislot class 11 supported"; break;
					case 0x33: str="Unused. If received, it shall be interpreted as Multislot class 11 supported"; break;
					default:   str="This should not happen";
				}

				proto_tree_add_text(tf_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"Extended DTM EGPRS Multi Slot Class: %s (%u)",str, oct>>(32-bits_needed));
				bit_offset+=2;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
			}
		}

		/*
		 * Modulation based multislot class support
		 */
		bits_needed = 1;
		GET_DATA;

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_mod_based_multi_slot_class_support, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset++;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * High Multislot Capability
		 */
		bits_needed = 1;
		GET_DATA;

		/* analyse bits */
		if ((oct>>(32-bits_needed))==0)
		{
			proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"High Multislot Capability: Bits are not available (%u)",oct>>(32-bits_needed));
			bit_offset++;
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
		}
		else
		{
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
			bit_offset++;

			/*
			 * High Multislot Capability
			 */
			bits_needed = 2;
			GET_DATA;

			/* analyse bits */
			proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					    "High Multislot Capability: 0x%02x (%u)"
					    " - This field effect all other multislot fields."
					    " To understand the value please read TS 24.008 5.6.0"
					    " Release 5 Chap 10.5.5.12 Page 406",
					    oct>>(32-bits_needed),
					    oct>>(32-bits_needed));
			bit_offset+=2;
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
		}

		/*
		 * GERAN Iu Mode Capability
		 */
		bits_needed = 1;
		GET_DATA;

		value = tvb_get_bits8(tvb, bit_offset, 1);
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_geran_iu_mode_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset+=bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;
		if (value)
		{
			/* GERAN Iu Mode Capabilities struct present */
			bits_needed = 4;
			GET_DATA;
			value = tvb_get_bits8(tvb, bit_offset, 4);
			bit_offset+=bits_needed;
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
			if (value)
			{
				/*
				 * FLO Iu Capability
				 */
				bits_needed = 1;
				GET_DATA;
				proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_flo_iu_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
				bit_offset+=bits_needed;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
				value--;
				
				/* skip spare bits */
				bit_offset+=value;
				curr_bits_length -= value;
				oct <<= value;
				bits_in_oct -= value;
			}
		}

		/*
		 * GMSK Multislot Power Profile
		 */
		bits_needed = 2;
		GET_DATA;

		/* analyse bits */
		switch ( oct>>(32-bits_needed) )
		{
			case 0x00: str="GMSK_MULTISLOT_POWER_PROFILE 0"; break;
			case 0x01: str="GMSK_MULTISLOT_POWER_PROFILE 1"; break;
			case 0x02: str="GMSK_MULTISLOT_POWER_PROFILE 2"; break;
			case 0x03: str="GMSK_MULTISLOT_POWER_PROFILE 3"; break;
			default:   str="This should not happen";
		}

		proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"GMSK Multislot Power Profile: %s (%u)",str,oct>>(32-bits_needed));
		bit_offset+=2;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * 8-PSK Multislot Power Profile
		 */
		bits_needed = 2;
		GET_DATA;

		/* analyse bits */
		switch ( oct>>(32-bits_needed) )
		{
			case 0x00: str="8-PSK_MULTISLOT_POWER_PROFILE 0"; break;
			case 0x01: str="8-PSK_MULTISLOT_POWER_PROFILE 1"; break;
			case 0x02: str="8-PSK_MULTISLOT_POWER_PROFILE 2"; break;
			case 0x03: str="8-PSK_MULTISLOT_POWER_PROFILE 3"; break;
			default:   str="This should not happen";
		}

		proto_tree_add_text(tf_tree,
		tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
		"8-PSK Multislot Power Profile: %s (%u)",str,oct>>(32-bits_needed));
		bit_offset+=2;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * Release 6
		 */
		 
		/*
		 * Multiple TBF Capability
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_mult_tbf_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset+=bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;
		
		/*
		 * Downlink Advanced Receiver Performance
		 */
		bits_needed = 2;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_down_adv_rec_perf, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
		bit_offset+=bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;
		
		/*
		 * Extended RLC/MAC Control Message Segmentation Capability
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_ext_rlc_mac_ctrl_msg_seg_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset+=bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * DTM Enhancements Capability
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_dtm_enh_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset+=bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * DTM GPRS High Multi Slot Class & DTM EGPRS High Multi Slot Class
		 */
		bits_needed = 1;
		GET_DATA;
		if ((oct>>(32-bits_needed))==0)
		{
			bit_offset+=bits_needed;
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
		}
		else
		{
			bit_offset+=bits_needed;
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;

			/*
			 * DTM GPRS High Multi Slot Class
			 */
			bits_needed = 3;
			GET_DATA;
			proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_dtm_gprs_high_multi_slot_class, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
			bit_offset+=bits_needed;
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;

			bits_needed = 1;
			GET_DATA;
			if ((oct>>(32-bits_needed))==0)
			{
				bit_offset+=bits_needed;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
			}
			else
			{
				bit_offset+=bits_needed;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;

				/*
				 * DTM EGPRS High Multi Slot Class
				 */
				bits_needed = 3;
				GET_DATA;
				proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_dtm_egprs_high_multi_slot_class, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
				bit_offset+=bits_needed;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
			}
		}
		
		/*
		 * PS Handover Capability
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_ps_ho_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset+=bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;
			
		/*
		 * Release 7
		 */
 
		/*
		 * DTM Handover Capability
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_dtm_ho_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset+=bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * Multislot Capability Reduction for Downlink Dual Carrier & Downlink Dual Carrier for DTM Capability
		 */
		bits_needed = 1;
		GET_DATA;
		if ((oct>>(32-bits_needed))==0)
		{
			bit_offset+=bits_needed;
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
		}
		else
		{
			bit_offset+=bits_needed;
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;

			/*
			 * Multislot Capability Reduction for Downlink Dual Carrier
			 */
			bits_needed = 3;
			GET_DATA;
			proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_multi_slot_cap_red_down_dual_carrier, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
			bit_offset+=bits_needed;
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;

			/*
			 * Downlink Dual Carrier for DTM Capability
			 */
			bits_needed = 1;
			GET_DATA;
			proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_down_dual_carrier_dtm_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
			bit_offset+=bits_needed;
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
		}

		/*
		 * Flexible Timeslot Assignment
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_flex_ts_assign, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset+=bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;
 
		/*
		 * GAN PS Handover Capability
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_gan_ps_ho_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset+=bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;
 
		/*
		 * RLC Non-persistent Mode
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_rlc_non_pers_mode, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset+=bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;
 
		/*
		 * Reduced Latency Capability
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_reduced_lat_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset+=bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;
 
		/*
		 * Uplink EGPRS2
		 */
		bits_needed = 2;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_ul_egprs2, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
		bit_offset+=bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;
 
		/*
		 * Downlink EGPRS2
		 */
		bits_needed = 2;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_dl_egprs2, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
		bit_offset+=bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;
 
		/*
		 * Release 8
		 */
 
		/*
		 * E-UTRA FDD support
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_eutra_fdd_support, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset+=bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;
 
		/*
		 * E-UTRA TDD support
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_eutra_tdd_support, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset+=bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;
 
		/*
		 * GERAN to E-UTRA support in GERAN packet transfer mode
		 */
		bits_needed = 2;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_geran_to_eutra_support_in_geran_ptm, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
		bit_offset+=bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;
 
		/*
		 * Priority-based reselection support
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_prio_based_resel_support, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset+=bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;
 
		/*
		 * Release 9
		 */

		/*
		 * Enhanced Flexible Timeslot Assignment
		 */
		bits_needed = 1;
		GET_DATA;
		if ((oct>>(32-bits_needed))==0)
		{
			bit_offset+=bits_needed;
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
		}
		else
		{
			bit_offset+=bits_needed;
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;

			/*
			 * Alternative EFTA Multislot Class
			 */
			bits_needed = 4;
			GET_DATA;
			proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_alt_efta_multi_slot_class, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
			bit_offset+=bits_needed;
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
 
			/*
			 * EFTA Multislot Capability Reduction for Downlink Dual Carrier
			 */
			bits_needed = 3;
			GET_DATA;
			proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_efta_multi_slot_cap_red_down_dual_carrier, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
			bit_offset+=bits_needed;
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
		}
 
		/*
		 * Indication of Upper Layer PDU Start Capability for RLC UM
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_ind_up_layer_pdu_start_cap_for_rlc_um, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset+=bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * EMST Capability
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_emst_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset+=bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * MTTI Capability
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_mtti_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset+=bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * UTRA CSG Cells Reporting
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_utra_csg_cell_report, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset+=bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * E-UTRA CSG Cells Reporting
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_eutra_csg_cell_report, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset+=bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * we are too long ... so jump over it
		 */
		while ( curr_bits_length > 0 )
		{
			if ( curr_bits_length > 8 )
				bits_needed = 8;
			else
				bits_needed = curr_bits_length;
			GET_DATA;
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
		}


	} while ( 1 );

	curr_offset+= curr_len;

	EXTRANEOUS_DATA_CHECK_EXPERT(len, curr_offset - offset, pinfo);

	return(curr_offset - offset);
}

/*
 * [9] 10.5.5.14
 */
static const range_string gmm_cause_vals[] = {
	{ 0x00, 0x01, "Protocol error, unspecified(Not def in v8.6.0)"},
	{ 0x02, 0x02, "IMSI unknown in HLR"},
	{ 0x03, 0x03, "Illegal MS"},
	{ 0x04, 0x04, "IMSI unknown in VLR"}, /* Annex G.1 */
	{ 0x05, 0x05, "IMEI not accepted"}, /* Annex G.1 */
	{ 0x06, 0x06, "Illegal ME"},
	{ 0x07, 0x07, "GPRS services not allowed"},
	{ 0x08, 0x08, "GPRS services and non-GPRS services not allowed"},
	{ 0x09, 0x09, "MS identity cannot be derived by the network"},
	{ 0x0a, 0x0a, "Implicitly detached"},
	{ 0x0b, 0x0b, "PLMN not allowed"},
	{ 0x0c, 0x0c, "Location Area not allowed"},
	{ 0x0d, 0x0d, "Roaming not allowed in this location area"},
	{ 0x0e, 0x0e, "GPRS services not allowed in this PLMN"},
	{ 0x0f, 0x0f, "No Suitable Cells In Location Area"},
	{ 0x10, 0x10, "MSC temporarily not reachable"},
	{ 0x11, 0x11, "Network failure"},
	{ 0x12, 0x13, "Protocol error, unspecified(Not def in v8.6.0)"},
	{ 0x14, 0x14, "MAC failure"},
	{ 0x15, 0x15, "Synch failure"},
	{ 0x16, 0x16, "Congestion"},
	{ 0x17, 0x17, "GSM authentication unacceptable"},
	{ 0x18, 0x18, "Protocol error, unspecified(Not def in v8.6.0)"},
	{ 0x19, 0x19, "Not authorized for this CSG"},
	{ 0x20, 0x20, "Service option not supported"},						/* Annex G.4 */
	{ 0x21, 0x21, "Requested service option not subscribed"},			/* Annex G.4 */
	{ 0x22, 0x22, "Service option temporarily out of order"},			/* Annex G.4 */

	{ 0x23, 0x25, "Protocol error, unspecified(Not def in v8.6.0)"},

	{ 0x26, 0x26, "Call cannot be identified(non-GPRS services only)"},	/* Annex G.4 */
	{ 0x27, 0x27, "Protocol error, unspecified(Not def in v8.6.0)"},
	{ 0x28, 0x28, "No PDP context activated"},
	{ 0x29, 0x2f, "Protocol error, unspecified(Not def in v8.6.0)"},
	{ 0x30, 0x3f, "Retry upon entry into a new cell"},

	{ 0x40, 0x5e, "Protocol error, unspecified(Not def in v8.6.0)"},

	{ 0x5f, 0x5f, "Semantically incorrect message"},
	{ 0x60, 0x60, "Invalid mandatory information"},
	{ 0x61, 0x61, "Message type non-existent or not implemented"},
	{ 0x62, 0x62, "Message type not compatible with the protocol state"},
	{ 0x63, 0x63, "Information element non-existent or notimplemented"},
	{ 0x64, 0x64, "Conditional IE error"},
	{ 0x65, 0x65, "Message not compatible with the protocol state"},

	{ 0x66, 0x6e, "Protocol error, unspecified(Not def in v8.6.0)"},

	{ 0x6f, 0x6f, "Protocol error, unspecified"},
	{ 0x70, 0xff, "Protocol error, unspecified(Not def in v8.6.0)"},
	{ 0, 0, NULL }
};
/* NOTE 1 TS 124 008 V8.6.0 (2009-07)
	"Any other value received by the mobile station shall be treated as 0110 1111, "Protocol
	error, unspecified". Any other value received by the network shall be treated as
	0110 1111, "Protocol error, unspecified".
 */

/* NOTE: The listed reject cause values are defined in annex G. */

static guint16
de_gmm_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32       curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_gm_cause, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.15 Routing area identification
 */
guint16
de_gmm_rai(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree   *subtree;
	proto_item   *item;
	guint32	      mcc;
	guint32	      mnc;
	guint32	      lac;
	guint32	      rac;
	guint32	      curr_offset;

	curr_offset = offset;

	mcc = (tvb_get_guint8(tvb, curr_offset) & 0x0f) <<8;
	mcc |= (tvb_get_guint8(tvb, curr_offset) & 0xf0);
	mcc |= (tvb_get_guint8(tvb, curr_offset+1) & 0x0f);
	mnc = (tvb_get_guint8(tvb, curr_offset+2) & 0x0f) <<8;
	mnc |= (tvb_get_guint8(tvb, curr_offset+2) & 0xf0);
	mnc |= (tvb_get_guint8(tvb, curr_offset+1) & 0xf0) >>4;
	if ((mnc&0x000f) == 0x000f)
		 mnc = mnc>>4;

	lac = tvb_get_ntohs(tvb, curr_offset+3);
	rac = tvb_get_guint8(tvb, curr_offset+5);

	item = proto_tree_add_text(tree,
		tvb, curr_offset, 6,
		"Routing area identification: %x-%x-%u-%u",
		mcc,mnc,lac,rac);

	subtree = proto_item_add_subtree(item, ett_gmm_rai);
	dissect_e212_mcc_mnc(tvb, pinfo, subtree, offset, TRUE);

	proto_tree_add_item(subtree, hf_gsm_a_lac, tvb, curr_offset+3, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(subtree, hf_gsm_a_gm_rac, tvb, curr_offset+5, 1, ENC_BIG_ENDIAN);

	curr_offset+=6;
    if (add_string)
    {
        if (add_string[0] == '\0')
        {
            g_snprintf(add_string, string_len, " - RAI: %x-%x-%u-%u", mcc,mnc,lac,rac);
        }
    }


	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.15a Routing area identification 2
 */
guint16
de_gmm_rai2(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	/* The routing area identification 2 value is coded as octet 2 to 7 of the Routing area identification information element. */
	return de_gmm_rai(tvb, tree, pinfo, offset, len, add_string, string_len);
}

/*
 * [7] 10.5.5.17
 */
static guint16
de_gmm_update_res(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8        oct;
	guint32       curr_offset;
	const gchar  *str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	/* IMPORTANT - IT'S ASSUMED THAT THE INFORMATION IS IN THE HIGHER NIBBLE */
	oct >>= 4;

	switch(oct&7)
	{
		case 0:  str="RA updated";              break;
		case 1:  str="combined RA/LA updated";	break;
		default: str="reserved";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Update Result: %s (%u)",
		str,
		oct&7);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [9] 10.5.5.18 Update Type
 */
static const value_string gsm_a_gm_update_type_vals[] = {
	{ 0x00, "RA updating" },
	{ 0x01, "combined RA/LA updating" },
	{ 0x02, "combined RA/LA updating with IMSI attach" },
	{ 0x03, "Periodic updating" },
	{ 0, NULL }
};

static guint16
de_gmm_update_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_item   *tf = NULL;
	proto_tree   *tf_tree = NULL;

	proto_tree_add_bits_item(tree, hf_gsm_a_gm_ciph_key_seq_num, tvb, offset << 3, 4, ENC_BIG_ENDIAN);

	tf = proto_tree_add_text(tree,
		tvb, offset, 1,
		"Update Type");

	tf_tree = proto_item_add_subtree(tf, ett_gmm_update_type );

	proto_tree_add_item(tf_tree, hf_gsm_a_gm_for, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tf_tree, hf_gsm_a_gm_update_type, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* no length check possible */
	return(1);
}

/*
 * [9] 10.5.5.19 A&C reference number (lower nibble)
 */
static guint16
de_gmm_ac_ref_nr(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	/* IMPORTANT - IT'S ASSUMED THAT THE INFORMATION IS IN THE LOWER NIBBLE */
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_ac_ref_nr, tvb, (offset << 3) + 4, 4, ENC_BIG_ENDIAN);

	/* no length check possible */
	return(1);
}

/*
 * [9] 10.5.5.19 A&C reference number (higher nibble)
 */
static guint16
de_gmm_ac_ref_nr_h(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	/* IMPORTANT - IT'S ASSUMED THAT THE INFORMATION IS IN THE HIGHER NIBBLE */
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_ac_ref_nr, tvb, offset << 3, 4, ENC_BIG_ENDIAN);

	/* no length check possible */
	return(1);
}

/*
 * [9] 10.5.5.20 Service type
 */
static const value_string gsm_a_gm_serv_type_vals[] = {
	{ 0x00,	"Signalling" },
	{ 0x01,	"Data" },
	{ 0x02,	"Paging response" },
	{ 0x03,	"MBMS Multicast Service Reception" },
	{ 0x04,	"MBMS Broadcast Service Reception" },
	{ 0, NULL }
};

static guint16
de_gmm_service_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	bit_offset;

	bit_offset = offset << 3;
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset += 1;
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_serv_type, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
	bit_offset += 3;
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset += 1;
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_ciph_key_seq_num, tvb, bit_offset, 3, ENC_BIG_ENDIAN);

	/* no length check possible */
	return(1);
}

/*
 * [9] 10.5.5.21 Cell Notification
 * No data
 */

/*
 * [9] 10.5.5.22 PS LCS Capability
 */
static const true_false_string gsm_a_gm_apc_vals = {
	"Additional Positioning Capabilities which can be retrieved by RRLP are supported",
	"Additional Positioning Capabilities which can be retrieved by RRLP are not supported"
};

static const true_false_string gsm_a_gm_otd_a_vals = {
	"MS assisted E-OTD supported",
	"MS assisted E-OTD not supported"
};

static const true_false_string gsm_a_gm_otd_b_vals = {
	"MS based E-OTD supported",
	"MS based E-OTD not supported"
};

static const true_false_string gsm_a_gm_gps_a_vals = {
	"MS assisted GPS supported",
	"MS assisted GPS not supported"
};

static const true_false_string gsm_a_gm_gps_b_vals = {
	"MS based GPS supported",
	"MS based GPS not supported"
};

static const true_false_string gsm_a_gm_gps_c_vals = {
	"Conventional GPS supported",
	"Conventional GPS not supported"
};

static guint16
de_gmm_ps_lcs_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, curr_offset << 3, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_apc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_otd_a, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_otd_b, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_gps_a, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_gps_b, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_gps_c, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	curr_offset++;

	EXTRANEOUS_DATA_CHECK_EXPERT(len, curr_offset - offset, pinfo);

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.23
 */
static guint16
de_gmm_net_feat_supp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch(oct&8)
	{
		case 8: str="LCS-MOLR via PS domain not supported"; break;
		default: str="LCS-MOLR via PS domain supported";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Network Feature Support: %s (%u)",
		str,
		(oct>>3)&1);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/* [7] 10.5.5.24 Inter RAT information container */
static guint16
de_gmm_rat_info_container(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	tvbuff_t *rrc_irat_ho_info_tvb;

	curr_offset = offset;

/* The value part of the Inter RAT information container information element is the INTER RAT HANDOVER INFO as
defined in 3GPP TS 25.331 [23c]. If this field includes padding bits, they are defined in 3GPP TS 25.331 [23c].*/
	rrc_irat_ho_info_tvb = tvb_new_subset(tvb, curr_offset, len, len);
	if (rrc_irat_ho_info_handle)
		call_dissector(rrc_irat_ho_info_handle, rrc_irat_ho_info_tvb,pinfo , tree);
	else
		proto_tree_add_text(tree, tvb, curr_offset, len,"INTER RAT HANDOVER INFO - Not decoded");

	return len;

}

/* [7] 10.5.5.25 Requested MS information */
static const true_false_string gsm_a_gm_req_ms_info_irat_vals = {
	"Inter RAT information container IE requested",
	"Inter RAT information container IE not requested"
};
static const true_false_string gsm_a_gm_req_ms_info_irat2_vals = {
	"E-UTRAN inter RAT information container IE requested",
	"E-UTRAN inter RAT information container IE not requested"
};

static guint16
de_gmm_req_ms_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint32 bit_offset;

	curr_offset = offset;
	bit_offset = (curr_offset<<3)+4;

	proto_tree_add_bits_item(tree, hf_gsm_a_gm_req_ms_info_irat, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_req_ms_info_irat2, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
	bit_offset+=2;
	curr_offset++;

	return len;
}

/* [7] 10.5.5.26 UE network capability
 * See subclause 9.9.3.x in 3GPP TS 24.301 [120].
 */

/* [7] 10.5.5.27 E-UTRAN inter RAT information container */
static guint16
de_gmm_eutran_irat_info_container(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	tvbuff_t *lte_rrc_ue_eutra_cap_tvb;

	curr_offset = offset;

/* The value part of the E-UTRAN inter RAT information container information element
   is formatted and coded according to the UE-EUTRA-Capability IE defined in 3GPP TS 36.331 [129]*/
	lte_rrc_ue_eutra_cap_tvb = tvb_new_subset(tvb, curr_offset, len, len);
	if (lte_rrc_ue_eutra_cap_handle)
		call_dissector(lte_rrc_ue_eutra_cap_handle, lte_rrc_ue_eutra_cap_tvb, pinfo, tree);
	else
		proto_tree_add_text(tree, tvb, curr_offset, len,"E-UTRAN Inter RAT information container - Not decoded");

	return len;
}

/* [7] 10.5.5.28 Voice domain preference and UE's usage setting */
static const true_false_string gsm_a_gm_ue_usage_setting_vals = {
	"Data centric",
	"Voice centric"
};
static const value_string gsm_a_gm_voice_domain_pref_for_eutran_vals[] = {
	{0x0,	"CS Voice only"},
	{0x1,	"IMS PS Voice only"},
	{0x2,	"CS voice preferred, IMS PS Voice as secondary"},
	{0x3,	"IMS PS voice preferred, CS Voice as secondary"},
	{  0,	NULL }
};

static guint16
de_gmm_voice_domain_pref(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint32 bit_offset;

	curr_offset = offset;
	bit_offset = curr_offset<<3;

	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, bit_offset, 5, ENC_BIG_ENDIAN);
	bit_offset+=5;
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_ue_usage_setting, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_voice_domain_pref_for_eutran, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
	bit_offset+=2;
	curr_offset++;

	return len;
}

/*
 * [7] 10.5.7.1
 */
static guint16
de_gc_context_stat(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint16	pdp_nr;
	guint32	curr_offset;
	proto_item  *tf = NULL;
	proto_tree  *tf_tree = NULL;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	tf = proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"PDP Context Status");

	tf_tree = proto_item_add_subtree(tf, ett_gmm_context_stat );

	oct = tvb_get_guint8(tvb, curr_offset);

	for ( pdp_nr=0;pdp_nr<16; pdp_nr++ )
	{
		if ( pdp_nr == 8 )
		{
			curr_offset++;
			oct = tvb_get_guint8(tvb, curr_offset);
		}
		proto_tree_add_text(tf_tree,
			tvb, curr_offset, 1,
			"NSAPI %d: %s (%u)",pdp_nr,
			pdp_str[oct&1],
			oct&1);
		oct>>=1;
	}

	curr_offset++;

	EXTRANEOUS_DATA_CHECK_EXPERT(len, curr_offset - offset, pinfo);

	return(curr_offset - offset);
}

/*
 * [7] 10.5.7.2
 */
static guint16
de_gc_radio_prio(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct&7 )
	{
		case 1: str="priority level 1 (highest)"; break;
		case 2: str="priority level 2"; break;
		case 3: str="priority level 3"; break;
		case 4: str="priority level 4 (lowest)"; break;
		default: str="priority level 4 (lowest)";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Radio Priority (PDP or SMS): %s (%u)",
		str,
		oct&7);

	curr_offset++;

	return(curr_offset - offset);
}

/*
 * [9] 10.5.7.3 GPRS Timer
 */
static const value_string gsm_a_gm_gprs_timer_unit_vals[] = {
	{ 0x00, "value is incremented in multiples of 2 seconds" },
	{ 0x01, "value is incremented in multiples of 1 minute" },
	{ 0x02, "value is incremented in multiples of decihours" },
	{ 0x07, "value indicates that the timer is deactivated" },
	{ 0, NULL }
};

static guint16
de_gc_timer(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint16	val;
	const gchar	*str;
	proto_tree	*subtree;
	proto_item	*item;

	oct = tvb_get_guint8(tvb, offset);
	val = oct&0x1f;

	switch(oct>>5)
	{
		case 0: str="sec"; val*=2; break;
		case 1: str="min"; break;
		case 2: str="min"; val*=6; break;
		case 7:
			proto_tree_add_text(tree,
				tvb, offset, 1,
				"GPRS Timer: timer is deactivated");

		default: str="min";
	}

	item = proto_tree_add_text(tree,
		tvb, offset, 1,
		"GPRS Timer: %u %s",
		val,
		str);

	subtree = proto_item_add_subtree(item, ett_gmm_gprs_timer);
	proto_tree_add_item(subtree, hf_gsm_a_gm_gprs_timer_unit, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(subtree, hf_gsm_a_gm_gprs_timer_value, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* no length check possible */
	return(1);
}

/*
 * [7] 10.5.7.4
 */
static guint16
de_gc_timer2(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string, int string_len _U_)
{
	guint8	oct;
	guint16	val;
	guint32	curr_offset;
	const gchar	*str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	val = oct&0x1f;

	switch(oct>>5)
	{
		case 0: str="sec"; val*=2; break;
		case 1: str="min"; break;
		case 2: str="min"; val*=6; break;
		case 7:
			proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"GPRS Timer: timer is deactivated");

		default: str="min";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"GPRS Timer: %u %s %s (%u)",
		val,
		str, add_string ? add_string : "", oct);

	curr_offset++;

	return(curr_offset - offset);
}

/*
 * [7] 10.5.7.5
 */
static guint16
de_gc_radio_prio2(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	/* IMPORTANT - IT'S ASSUMED THAT THE INFORMATION IS IN THE HIGHER NIBBLE */
	oct >>= 4;

	switch ( oct&7 )
	{
		case 1: str="priority level 1 (highest)"; break;
		case 2: str="priority level 2"; break;
		case 3: str="priority level 3"; break;
		case 4: str="priority level 4 (lowest)"; break;
		default: str="priority level 4 (lowest)";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Radio Priority (TOM8): %s (%u)",
		str,
		oct&7);

	curr_offset++;

	return(curr_offset - offset);
}

/*
 * [8] 10.5.7.6 MBMS context status
 */
static guint16
de_gc_mbms_context_stat(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint   i;
	guint8	oct, j;
	proto_item  *tf = NULL;
	proto_tree  *tf_tree = NULL;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	tf = proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"MBMS Context Status");

	tf_tree = proto_item_add_subtree(tf, ett_gmm_context_stat );

	for (i=0; i<len; i++)
	{
		oct = tvb_get_guint8(tvb, curr_offset);

		for (j=0; j<8; j++)
		{
			proto_tree_add_text(tf_tree,
				tvb, curr_offset, 1,
				"NSAPI %d: %s (%u)",128+i*8+j,
				pdp_str[oct&1],
				oct&1);
			oct>>=1;
		}
		curr_offset++;
	}

	return(len);
}

/*
 * [8] 10.5.7.7 Uplink data status
 */
static const true_false_string gsm_a_gm_nsapi_ul_stat_vals = {
	"uplink data are pending for the preserved PDP context",
	"no uplink data are pending for the preserved PDP context or the PDP context is PDP-INACTIVE or is PDP-ACTIVE with a RAB already established"
};

static guint16
de_gc_uplink_data_stat(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint32 bit_offset;

	curr_offset = offset;
	bit_offset = curr_offset<<3;

	proto_tree_add_bits_item(tree, hf_gsm_a_gm_nsapi_7_ul_stat, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_nsapi_6_ul_stat, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_nsapi_5_ul_stat, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, bit_offset, 5, ENC_BIG_ENDIAN);
	bit_offset+=5;
	curr_offset++;
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_nsapi_15_ul_stat, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_nsapi_14_ul_stat, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_nsapi_13_ul_stat, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_nsapi_12_ul_stat, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_nsapi_11_ul_stat, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_nsapi_10_ul_stat, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_nsapi_9_ul_stat, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_nsapi_8_ul_stat, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;
	curr_offset++;

	return(len);
}

/*
 * [7] 10.5.6.1
 */
#define MAX_APN_LENGTH		50

guint16
de_sm_apn(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string, int string_len _U_)
{
	guint32	curr_offset;
	guint	curr_len;
	guint8	  str[MAX_APN_LENGTH+1];

	curr_offset = offset;

	/* init buffer and copy it */
	memset ( str , 0 , MAX_APN_LENGTH );
	tvb_memcpy(tvb, str, offset, len<MAX_APN_LENGTH?len:MAX_APN_LENGTH);

	curr_len = 0;
	while (( curr_len < len ) && ( curr_len < MAX_APN_LENGTH ))
	{
		guint step = str[curr_len];
		str[curr_len]='.';
		curr_len += step+1;
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, len,
		"APN: %s %s", str+1 , add_string ? add_string : "");

	curr_offset+= len;

	EXTRANEOUS_DATA_CHECK_EXPERT(len, curr_offset - offset, pinfo);

	return(curr_offset - offset);
}

/*
 * [7] 10.5.6.2
 */
static guint16
de_sm_nsapi(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"NSAPI: 0x%02x (%u) %s",
		oct&0x0f, oct&0x0f,add_string ? add_string : "");

	curr_offset++;

	return(curr_offset - offset);
}

/*
 * [7] 10.5.6.3 Protocol configuration options
 */
static const value_string gsm_a_sm_pco_ms2net_prot_vals[] = {
	{ 0x01, "P-CSCF IPv6 Address Request" },
	{ 0x02, "IM CN Subsystem Signaling Flag" },
	{ 0x03, "DNS Server IPv6 Address Request" },
	{ 0x04, "Not Supported" },
	{ 0x05, "MS Support of Network Requested Bearer Control indicator" },
	{ 0x06,	"Reserved" },
	{ 0x07,	"DSMIPv6 Home Agent Address Request" },
	{ 0x08,	"DSMIPv6 Home Network Prefix Request" },
	{ 0x09,	"DSMIPv6 IPv4 Home Agent Address Request" },
	{ 0x0a,	"IP address allocation via NAS signalling" },
	{ 0x0b,	"IPv4 address allocation via DHCPv4" },
	{ 0x0c,	"P-CSCF IPv4 Address Request" },
	{ 0x0d,	"DNS Server IPv4 Address Request" },
	{ 0x0e,	"MSISDN Request" },
	{ 0, NULL }
};
static const value_string gsm_a_sm_pco_net2ms_prot_vals[] = {
	{ 0x01, "P-CSCF IPv6 Address" },
	{ 0x02, "IM CN Subsystem Signaling Flag" },
	{ 0x03, "DNS Server IPv6 Address" },
	{ 0x04, "Policy Control rejection code" },
	{ 0x05, "Selected Bearer Control Mode" },
	{ 0x06,	"Reserved" },
	{ 0x07,	"DSMIPv6 Home Agent Address" },
	{ 0x08,	"DSMIPv6 Home Network Prefix" },
	{ 0x09,	"DSMIPv6 IPv4 Home Agent Address" },
	{ 0x0a,	"Reserved" },
	{ 0x0b,	"Reserved" },
	{ 0x0c,	"P-CSCF IPv4 Address" },
	{ 0x0d,	"DNS Server IPv4 Address" },
	{ 0x0e,	"MSISDN" },
	{ 0, NULL }
};

static const value_string gsm_a_gm_link_dir_vals[] = {
	{ -1, "Unknown" },
	{ 0x0, "MS to network" },
	{ 0x1, "Network to MS" },
	{ 0, NULL }
};

guint16
de_sm_pco(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	proto_item   *generated_item = NULL;
	guint32	curr_offset;
	guint	curr_len;
	guchar	oct;
	struct e_in6_addr ipv6_addr;
	int     link_dir;

	curr_len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	link_dir = pinfo->link_dir;
	generated_item =proto_tree_add_int(tree, hf_gsm_a_gm_link_dir, tvb, curr_offset, 0, link_dir);
	PROTO_ITEM_SET_GENERATED(generated_item);


	/* 1 ext 0 0 0 0 Spare  Configuration protocol */
	proto_tree_add_item(tree, hf_gsm_a_gm_sm_ext, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* Configuration protocol (octet 3)
	 * Bits
	 * 3 2 1
	 * 0 0 0 PPP for use with IP PDP type or IP PDN type (see 3GPP TS 24.301 [120])
	 *
	 * All other values are interpreted as PPP in this version of the protocol.
	 * (3GPP TS 24.008 version 9.4.0 Release 9)
	 */
	proto_tree_add_text(tree,tvb, curr_offset, 1, "Configuration Protocol: PPP (%u)",oct&0x07);
	curr_len--;
	curr_offset++;

	while ( curr_len > 0 )
	{
		guchar e_len;
		guint16 prot;
		tvbuff_t *l3_tvb;
		dissector_handle_t handle = NULL;

		/* Protocol ID 1                    octet 4
		 *                                  octet 5
		 * Length of protocol ID 1 contents octet 6
		 * Protocol ID 1 contents           octet 7
		 */

		prot = tvb_get_ntohs(tvb,curr_offset);
		proto_tree_add_uint_format(tree, hf_gsm_a_gm_pco_pid, tvb, curr_offset, 2, (guint32)prot,
				"Protocol or Container ID: %s (%u)",
				link_dir ?
					val_to_str_const((guint32)prot, gsm_a_sm_pco_net2ms_prot_vals, val_to_str_ext_const(prot, &ppp_vals_ext, "Unknown")) :
					val_to_str_const((guint32)prot, gsm_a_sm_pco_ms2net_prot_vals, val_to_str_ext_const(prot, &ppp_vals_ext, "Unknown")),
				(guint32)prot);

		curr_len-=2;
		curr_offset+=2;
		e_len = tvb_get_guint8(tvb, curr_offset);
		proto_tree_add_text(tree,tvb, curr_offset, 1, "Length: 0x%02x (%u)", e_len , e_len);
		curr_len-=1;
		curr_offset+=1;

		switch ( prot )
		{
			case 0x0001:
			{
				if (e_len > 0) {
					tvb_get_ipv6(tvb, curr_offset, &ipv6_addr);
					proto_tree_add_text(tree,
					tvb, curr_offset, 16,
					"IPv6: %s", ip6_to_str(&ipv6_addr));
				}
				break;
			}
			case 0x0002:
				break;
			case 0x0003:
			{
				if (e_len > 0) {
					tvb_get_ipv6(tvb, curr_offset, &ipv6_addr);
					proto_tree_add_text(tree,
					tvb, curr_offset, 16,
					"IPv6: %s", ip6_to_str(&ipv6_addr));
				}
				break;
			}
			case 0x0004:
				oct = tvb_get_guint8(tvb, curr_offset);
				proto_tree_add_text(tree,tvb, curr_offset, 1, "Reject Code: 0x%02x (%u)", e_len , e_len);
				break;
			default:
			{
				handle = dissector_get_uint_handle ( gprs_sm_pco_subdissector_table , prot );
				if ( handle != NULL )
				{
					/*
					 * dissect the embedded message
					 */
					l3_tvb = tvb_new_subset(tvb, curr_offset, e_len, e_len);
					/* In this case we do not want the columns updated */
					col_set_writable(pinfo->cinfo, FALSE);
					call_dissector(handle, l3_tvb , pinfo  , tree );
					col_set_writable(pinfo->cinfo, TRUE);
				}
				else
				{
					/*
					* dissect the embedded DATA message
					*/
					l3_tvb = tvb_new_subset(tvb, curr_offset, e_len, e_len);
					call_dissector(data_handle, l3_tvb, pinfo , tree);
				}
			}
		}

		curr_len-= e_len;
		curr_offset+= e_len;
	}
	curr_offset+= curr_len;

	EXTRANEOUS_DATA_CHECK_EXPERT(len, curr_offset - offset, pinfo);

	return(curr_offset - offset);
}

/*
 * [9] 10.5.6.4 Packet data protocol address
 */
static const value_string gsm_a_sm_pdp_type_org_vals[] = {
	{ 0x00, "ETSI allocated address" },
	{ 0x01, "IETF allocated address" },
	{ 0x0f, "Empty PDP type" },
	{ 0, NULL }
};

static guint16
de_sm_pdp_addr(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	const gchar	*str;
	guchar	  pdp_type_org, pdp_type_num;

	curr_offset = offset;

	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset << 3), 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_sm_pdp_type_org, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	pdp_type_org = tvb_get_guint8(tvb, curr_offset) & 0x0f;
	curr_offset += 1;
	pdp_type_num = tvb_get_guint8(tvb, curr_offset);

	if (pdp_type_org == 0 )
	{
		/* ETSI allocated address */
		switch (pdp_type_num)
		{
			case 0x00: str="Reserved, used in earlier version of this protocol"; break;
			case 0x01: str="PDP-type PPP"; break;
			default: str="reserved";
		}
	}
	else if (pdp_type_org == 1)
	{
		/* IETF allocated addres */
		switch (pdp_type_num)
		{
			case 0x21: str="IPv4 address"; break;
			case 0x57: str="IPv6 address"; break;
			case 0x8d: str="IPv4v6 address"; break;
			default: str="Unknown, interpreted as IPv4 address";
		}
	}
	else if ((pdp_type_num == 0) && (pdp_type_org == 0x0f))
		str="Empty";
	else
		str="Not specified";

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"PDP type number: %s (%u)",str,pdp_type_num);

	if (( len == 2 ) && (( pdp_type_num == 0x21 ) || ( pdp_type_num == 0x57 ) || (pdp_type_num == 0x8d)))
	{
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Dynamic addressing");
		curr_offset += 1;
		return(curr_offset - offset);
	}
	else if ( len == 2 )
	{
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"No PDP address is included");
		curr_offset += 1;
		return(curr_offset - offset);
	}

	curr_offset += 1;
	if (pdp_type_org == 1)
	switch (pdp_type_num)
	{
		case 0x57:
			proto_tree_add_item(tree,hf_gsm_a_sm_ip6_address,tvb,curr_offset,16,ENC_BIG_ENDIAN);
			curr_offset+=16;
			break;

		case 0x8d:
			proto_tree_add_item(tree,hf_gsm_a_sm_ip4_address,tvb,curr_offset,4,ENC_BIG_ENDIAN);
			curr_offset+=4;
			proto_tree_add_item(tree,hf_gsm_a_sm_ip6_address,tvb,curr_offset,16,ENC_BIG_ENDIAN);
			curr_offset+=16;
			break;

		default:
			proto_tree_add_item(tree,hf_gsm_a_sm_ip4_address,tvb,curr_offset,4,ENC_BIG_ENDIAN);
			curr_offset+=4;
	}

	EXTRANEOUS_DATA_CHECK_EXPERT(len, curr_offset - offset, pinfo);

	return(curr_offset - offset);
}

/*
 * [9] 10.5.6.5 Quality of service
 */
static const value_string gsm_a_qos_delay_cls_vals[] = {
	{ 0x00, "Subscribed delay class (in MS to network direction)" },
	{ 0x01, "Delay class 1" },
	{ 0x02, "Delay class 2" },
	{ 0x03, "Delay class 3" },
	{ 0x04, "Delay class 4 (best effort)" },
	{ 0x07,	"Reserved" },
	{ 0, NULL }
};

static const value_string gsm_a_qos_reliability_vals[] = {
	{ 0x00, "Subscribed reliability class (in MS to network direction)" },
	{ 0x01, "Acknowledged GTP, LLC, and RLC; Protected data" },
	{ 0x02, "Unacknowledged GTP, Ack LLC/RLC, Protected data" },
	{ 0x03, "Unacknowledged GTP/LLC, Ack RLC, Protected data" },
	{ 0x04, "Unacknowledged GTP/LLC/RLC, Protected data" },
	{ 0x05, "Unacknowledged GTP/LLC/RLC, Unprotected data" },
	{ 0x07, "Reserved" },
	{ 0, NULL }
};
 /* Delivery of erroneous SDUs, octet 6 (see 3GPP TS 23.107) Bits 3 2 1 */
const value_string gsm_a_qos_del_of_err_sdu_vals[] = {
	{ 0, "Subscribed delivery of erroneous SDUs/Reserved" },
	{ 1, "No detect('-')" },
	{ 2, "Erroneous SDUs are delivered('yes')" },
	{ 3, "Erroneous SDUs are not delivered('No')" },
	{ 7, "Reserved" },
	{ 0, NULL }
};

 /* Delivery order, octet 6 (see 3GPP TS 23.107) Bits 5 4 3 */
const value_string gsm_a_qos_del_order_vals[] = {
	{ 0, "Subscribed delivery order/Reserved" },
	{ 1, "With delivery order ('yes')" },
	{ 2, "Without delivery order ('no')" },
	{ 3, "Reserved" },
	{ 0, NULL }
};
/* Traffic class, octet 6 (see 3GPP TS 23.107) Bits 8 7 6 */
const value_string gsm_a_qos_traffic_cls_vals[] = {
	{ 0, "Subscribed traffic class/Reserved" },
	{ 1, "Conversational class" },
	{ 2, "Streaming class" },
	{ 3, "Interactive class" },
	{ 4, "Background class" },
	{ 7, "Reserved" },
	{ 0, NULL }
};

/* Residual Bit Error Rate (BER), octet 10 (see 3GPP TS 23.107) Bits 8 7 6 5 */
const value_string gsm_a_qos_ber_vals[] = {
	{ 0, "Subscribed residual BER/Reserved" },
	{ 1, "5*10-2" },
	{ 2, "1*10-2" },
	{ 3, "5*10-3" },
	{ 4, "4*10-3" },
	{ 5, "1*10-3" },
	{ 6, "1*10-4" },
	{ 7, "1*10-5" },
	{ 8, "1*10-6" },
	{ 9, "6*10-8" },
	{ 10, "Reserved" },
	{ 0, NULL }
};

/* SDU error ratio, octet 10 (see 3GPP TS 23.107) Bits 4 3 2 1 */
const value_string gsm_a_qos_sdu_err_rat_vals[] = {
	{ 0, "Subscribed SDU error ratio/Reserved" },
	{ 1, "1*10-2" },
	{ 2, "7*10-3" },
	{ 3, "1*10-3" },
	{ 4, "1*10-4" },
	{ 5, "1*10-5" },
	{ 6, "1*10-6" },
	{ 7, "1*10-1" },
	{ 15, "Reserved" },
	{ 0, NULL }
};

/* Traffic handling priority, octet 11 (see 3GPP TS 23.107) Bits 2 1 */
const value_string gsm_a_qos_traff_hdl_pri_vals[] = {
	{ 0, "Subscribed traffic handling priority/Reserved" },
	{ 1, "Priority level 1" },
	{ 2, "Priority level 2" },
	{ 3, "Priority level 3" },
	{ 0, NULL }
};

const range_string gsm_a_qos_peak_thr_vals[] = {
	{ 0x00, 0x00, "Subscribed peak throughput/reserved" },
	{ 0x01, 0x01, "Up to 1 000 octet/s" },
	{ 0x02, 0x02, "Up to 2 000 octet/s" },
	{ 0x03, 0x03, "Up to 4 000 octet/s" },
	{ 0x04, 0x04, "Up to 8 000 octet/s" },
	{ 0x05, 0x05, "Up to 16 000 octet/s" },
	{ 0x06, 0x06, "Up to 32 000 octet/s" },
	{ 0x07, 0x07, "Up to 64 000 octet/s" },
	{ 0x08, 0x08, "Up to 128 000 octet/s" },
	{ 0x09, 0x09, "Up to 256 000 octet/s" },
	{ 0x0a, 0x0e, "Interpreted as Up to 1 000 octet/s" },
	{ 0x0f, 0x0f, "Reserved" },
	{ 0, 0, NULL }
};

const range_string gsm_a_qos_mean_thr_vals[] = {
	{ 0x00, 0x00, "Subscribed peak throughput/reserved" },
	{ 0x01, 0x01, "100 octet/h" },
	{ 0x02, 0x02, "200 octet/h" },
	{ 0x03, 0x03, "500 octet/h" },
	{ 0x04, 0x04, "1 000 octet/h" },
	{ 0x05, 0x05, "2 000 octet/h" },
	{ 0x06, 0x06, "5 000 octet/h" },
	{ 0x07, 0x07, "10 000 octet/h" },
	{ 0x08, 0x08, "20 000 octet/h" },
	{ 0x09, 0x09, "50 000 octet/h" },
	{ 0x0a, 0x0a, "100 000 octet/h" },
	{ 0x0b, 0x0b, "200 000 octet/h" },
	{ 0x0c, 0x0c, "500 000 octet/h" },
	{ 0x0d, 0x0d, "1 000 000 octet/h" },
	{ 0x0e, 0x0e, "2 000 000 octet/h" },
	{ 0x0f, 0x0f, "5 000 000 octet/h" },
	{ 0x10, 0x10, "10 000 000 octet/h" },
	{ 0x11, 0x11, "20 000 000 octet/h" },
	{ 0x12, 0x12, "50 000 000 octet/h" },
	{ 0x13, 0x1d, "Interpreted as Best effort" },
	{ 0x1e, 0x1e, "Reserved" },
	{ 0x1f, 0x1f, "Best effort" },
	{ 0, 0, NULL }
};

const range_string gsm_a_qos_prec_class_vals[] = {
	{ 0x00, 0x00, "Subscribed precedence/reserved" },
	{ 0x01, 0x01, "High priority" },
	{ 0x02, 0x02, "Normal priority" },
	{ 0x03, 0x03, "Low priority" },
	{ 0x04, 0x06, "Interpreted as Normal priority" },
	{ 0x07, 0x07, "Reserved" },
	{ 0, 0, NULL }
};

const true_false_string gsm_a_qos_signalling_ind_value = {
	"Optimised for signalling traffic",
	"Not optimised for signalling traffic"
};

/* Helper function returning the main bitrates in kbps */
static guint32
qos_calc_bitrate(guint8 oct)
{
	if (oct <= 0x3f)
		return oct;
	if (oct <= 0x7f)
		return 64 + (oct-0x40) * 8;

	return 576 + (oct-0x80) * 64;
}

/* Helper function returning the extended bitrates in kbps */
static guint32
qos_calc_ext_bitrate(guint8 oct)
{
	if (oct <= 0x4a)
		return 8600 + oct * 100;
	if (oct <= 0xba)
		return 16000 + (oct-0x4a) * 1000;

	return 128000 + (oct - 0xba) * 2000;
}

guint16
de_sm_qos(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guchar	   oct, tmp_oct;
	const gchar	*str;
	guint32	temp32;

	curr_offset = offset;

	/* Octet 3 */
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset << 3), 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_qos_delay_cls, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_qos_reliability_cls, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset+= 1;

	/* Octet 4 */
	oct = tvb_get_guint8(tvb, curr_offset);
	proto_tree_add_item(tree, hf_gsm_a_qos_peak_thr, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset << 3) + 4, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_qos_prec_class, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset+= 1;

	/* Octet 5 */
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset << 3), 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_qos_mean_thr, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset+= 1;

	NO_MORE_DATA_CHECK(len);

	/* Octet 6 */
	proto_tree_add_item(tree, hf_gsm_a_qos_traffic_cls, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_qos_del_order, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_qos_del_of_err_sdu, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset+= 1;

	NO_MORE_DATA_CHECK(len);

	/* Octet 7 */
	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct )
	{
		case 0x00: str="Subscribed maximum SDU size/reserved"; break;
		case 0x97: str="1502 octets"; break;
		case 0x98: str="1510 octets"; break;
		case 0x99: str="1520 octets"; break;
		case 0xff: str="Reserved"; break;
		default: str="Unspecified";
	}

	if (( oct >= 1 ) && ( oct <= 0x96 ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Maximum SDU size: %u octets (%u)",oct*10, oct);
	else
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Maximum SDU size: %s (%u)",str, oct);

	curr_offset+= 1;

	NO_MORE_DATA_CHECK(len);

	/* Octet 8 */
	oct = tvb_get_guint8(tvb, curr_offset);

	switch (oct)
	{
		case 0x00: str = "Subscribed maximum bit rate for uplink/reserved"; break;
		case 0xff: str = "0 kbps"; break;
		default: str = ep_strdup_printf("%u kbps", qos_calc_bitrate(oct));
	}

	proto_tree_add_uint_format_value(tree, hf_gsm_a_qos_max_bitrate_upl, tvb,
		curr_offset, 1, oct, "%s (%u)", str, oct);
	curr_offset+= 1;

	NO_MORE_DATA_CHECK(len);

	/* Octet 9 */
	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct )
	{
		case 0x00: str="Subscribed maximum bit rate for downlink/reserved"; break;
		case 0xff: str="0 kbps"; break;
		default: str = ep_strdup_printf("%u kbps", qos_calc_bitrate(oct));
	}

	proto_tree_add_uint_format_value(tree, hf_gsm_a_qos_max_bitrate_downl, tvb,
		curr_offset, 1, oct, "%s (%u)", str, oct);
	curr_offset+= 1;

	NO_MORE_DATA_CHECK(len);

	/* Octet 10 */
	proto_tree_add_item(tree, hf_gsm_a_qos_ber, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_qos_sdu_err_rat, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	curr_offset+= 1;
	NO_MORE_DATA_CHECK(len);

	/* Octet 11 */
	oct = tvb_get_guint8(tvb, curr_offset);

	tmp_oct = oct >> 2;
	switch (tmp_oct)
	{
		case 0x00: str="Subscribed transfer delay/reserved"; break;
		case 0x3f: str="Reserved"; break;
		default:
			if (tmp_oct <= 0x0f)
				temp32 = tmp_oct * 10;
			else if (tmp_oct <= 0x1f)
				temp32 = (tmp_oct - 0x10) * 50 + 200;
			else
				temp32 = (tmp_oct - 0x20) * 100 + 1000;
			str = ep_strdup_printf("%u ms", temp32);
	}

	proto_tree_add_uint_format_value(tree, hf_gsm_a_qos_trans_delay, tvb,
		curr_offset, 1, oct, "%s (%u)", str, tmp_oct);

	tmp_oct = oct & 0x03;
	if (tmp_oct == 0)
		str = "Subscribed traffic handling priority/reserved";
	else
		str = ep_strdup_printf("Priority level %u", tmp_oct);

	proto_tree_add_uint_format_value(tree, hf_gsm_a_qos_traf_handl_prio, tvb,
		curr_offset, 1, oct, "%s (%u)", str, tmp_oct);

	curr_offset+= 1;
	NO_MORE_DATA_CHECK(len);

	/* Octet 12 */
	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct )
	{
		case 0x00: str="Subscribed guaranteed bit rate for uplink/reserved"; break;
		case 0xff: str="0 kbps"; break;
		default: str = ep_strdup_printf("%u kbps", qos_calc_bitrate(oct));
	}

	proto_tree_add_uint_format_value(tree, hf_gsm_a_qos_guar_bitrate_upl, tvb,
		curr_offset, 1, oct, "%s (%u)", str, oct);

	curr_offset+= 1;
	NO_MORE_DATA_CHECK(len);

	/* Octet 13 */
	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct )
	{
		case 0x00: str="Subscribed guaranteed bit rate for downlink/reserved"; break;
		case 0xff: str="0 kbps"; break;
		default: str = ep_strdup_printf("%u kbps", qos_calc_bitrate(oct));
	}

	proto_tree_add_uint_format_value(tree, hf_gsm_a_qos_guar_bitrate_downl, tvb,
		curr_offset, 1, oct, "%s (%u)", str, oct);

	curr_offset+= 1;
	NO_MORE_DATA_CHECK(len);

	/* Ocet 14 */
	oct = tvb_get_guint8(tvb, curr_offset);
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset << 3), 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_qos_signalling_ind, tvb , curr_offset, 1, ENC_BIG_ENDIAN);

	tmp_oct = oct & 7;
	if (tmp_oct == 0x01)
		str = "speech";
	else
		str = "unknown";

	proto_tree_add_uint_format_value(tree, hf_gsm_a_qos_source_stat_desc, tvb,
		curr_offset, 1, oct, "%s (%u)", str, tmp_oct);

	curr_offset+= 1;
	NO_MORE_DATA_CHECK(len);

	/* Octet 15 */
	oct = tvb_get_guint8(tvb, curr_offset);

	if (oct == 0x00)
		str = "Use the value indicated by the Maximum bit rate for downlink";
	else
	{
		temp32 = qos_calc_ext_bitrate(oct);
		if (temp32 % 1000 == 0)
			str = ep_strdup_printf("%u Mbps", temp32 / 1000);
		else
			str = ep_strdup_printf("%u kbps", temp32);
	}
	proto_tree_add_uint_format_value(tree, hf_gsm_a_qos_max_bitrate_downl_ext, tvb,
		curr_offset, 1, oct, "%s (%u)", str, oct);

	curr_offset+= 1;
	NO_MORE_DATA_CHECK(len);

	/* Octet 16 */
	oct = tvb_get_guint8(tvb, curr_offset);

	if (oct == 0x00)
		str = "Use the value indicated by the Guaranteed bit rate for downlink";
	else
	{
		temp32 = qos_calc_ext_bitrate(oct);
		if (temp32 % 1000 == 0)
			str = ep_strdup_printf("%u Mbps", temp32 / 1000);
		else
			str = ep_strdup_printf("%u kbps", temp32);
	}
	proto_tree_add_uint_format_value(tree, hf_gsm_a_qos_guar_bitrate_downl_ext, tvb,
		curr_offset, 1, oct, "%s (%u)", str, oct);

	curr_offset+= 1;
	NO_MORE_DATA_CHECK(len);

	/* Maximum bit rate for uplink (extended) Octet 17 */
	oct = tvb_get_guint8(tvb, curr_offset);

	if (oct == 0x00)
		str = "Use the value indicated by the Maximum bit rate for uplink";
	else
	{
		temp32 = qos_calc_ext_bitrate(oct);
		if (temp32 % 1000 == 0)
			str = ep_strdup_printf("%u Mbps", temp32 / 1000);
		else
			str = ep_strdup_printf("%u kbps", temp32);
	}
	proto_tree_add_uint_format_value(tree, hf_gsm_a_qos_max_bitrate_upl_ext, tvb,
		curr_offset, 1, oct, "%s (%u)", str, oct);

	curr_offset+= 1;
	NO_MORE_DATA_CHECK(len);

	/* Guaranteed bit rate for uplink (extended) Octet 18 */
	oct = tvb_get_guint8(tvb, curr_offset);

	if (oct == 0x00)
		str = "Use the value indicated by the Guaranteed bit rate for uplink";
	else
	{
		temp32 = qos_calc_ext_bitrate(oct);
		if (temp32 % 1000 == 0)
			str = ep_strdup_printf("%u Mbps", temp32 / 1000);
		else
			str = ep_strdup_printf("%u kbps", temp32);
	}
	proto_tree_add_uint_format_value(tree, hf_gsm_a_qos_guar_bitrate_upl_ext, tvb,
		curr_offset, 1, oct, "%s (%u)", str, oct);

	curr_offset+= 1;

	EXTRANEOUS_DATA_CHECK_EXPERT(len, curr_offset - offset, pinfo);

	return(curr_offset - offset);
}

/*
 * [9] 10.5.6.6 SM cause
 */
static const value_string gsm_a_sm_cause_vals[] = {
	{ 0x08, "Operator Determined Barring" },
	{ 0x18, "MBMS bearer capabilities insufficient for the service" },
	{ 0x19, "LLC or SNDCP failure(GSM only)" },
	{ 0x1a, "Insufficient resources" },
	{ 0x1b, "Missing or unknown APN" },
	{ 0x1c, "Unknown PDP address or PDP type" },
	{ 0x1d, "User Authentication failed" },
	{ 0x1e, "Activation rejected by GGSN" },
	{ 0x1f, "Activation rejected, unspecified" },
	{ 0x20, "Service option not supported" },
	{ 0x21, "Requested service option not subscribed" },
	{ 0x22, "Service option temporarily out of order" },
	{ 0x23, "NSAPI already used (not sent)" },
	{ 0x24, "Regular deactivation" },
	{ 0x25, "QoS not accepted" },
	{ 0x26, "Network failure" },
	{ 0x27, "Reactivation required" },
	{ 0x28, "Feature not supported" },
	{ 0x29, "Semantic error in the TFT operation" },
	{ 0x2a, "Syntactical error in the TFT operation" },
	{ 0x2b, "Unknown PDP context" },
	{ 0x2c, "Semantic errors in packet filter(s)" },
	{ 0x2d, "Syntactical errors in packet filter(s)" },
	{ 0x2e, "PDP context without TFT already activated" },
	{ 0x2f, "Multicast group membership time-out" },
	{ 0x2c, "Semantic errors in packet filter(s)" },
	{ 0x2d, "Syntactical errors in packet filter(s)" },
	{ 0x30, "Activation rejected, BCM violation" },
	{ 0x32, "PDP type IPv4 only allowed" },
	{ 0x33, "PDP type IPv6 only allowed" },
	{ 0x34, "Single address bearers only allowed" },
	{ 0x51, "Invalid transaction identifier value" },
	{ 0x5f, "Semantically incorrect message" },
	{ 0x60, "Invalid mandatory information" },
	{ 0x61, "Message type non-existent or not implemented" },
	{ 0x62, "Message type not compatible with the protocol state" },
	{ 0x63, "Information element non-existent or not implemented" },
	{ 0x64, "Conditional IE error" },
	{ 0x65, "Message not compatible with the protocol state" },
	{ 0x6f, "Protocol error, unspecified" },
	{ 0x70, "APN restriction value incompatible with active PDP context" },
	{ 0, NULL }
};

static guint16
de_sm_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	const gchar	*str;

	oct = tvb_get_guint8(tvb, offset);

	/* SM Cause can be sent in both directions */
	str = val_to_str_const(oct, gsm_a_sm_cause_vals,
			       "Protocol error, unspecified / Service option temporarily out of order");

	proto_tree_add_uint_format_value(tree, hf_gsm_a_sm_cause, tvb,
				offset, 1, oct, "%s (%u)", str, oct);

	/* no length check possible */
	return(1);
}

/*
 * [9] 10.5.6.6a SM cause 2
 */
static guint16
de_sm_cause_2(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	const gchar	*str;

	oct = tvb_get_guint8(tvb, offset);

	/* SM Cause 2 is sent only in the Network-to-MS direction */
	str = val_to_str_const(oct, gsm_a_sm_cause_vals,
			       "Service option temporarily out of order");

	proto_tree_add_uint_format_value(tree, hf_gsm_a_sm_cause_2, tvb,
				offset, 1, oct, "%s (%u)", str, oct);

	/* no length check possible */
	return(1);
}
/*
 * [7] 10.5.6.7
 */
static guint16
de_sm_linked_ti(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint	curr_len;
	gchar	oct;

	static const gchar *ti_flag[2]={
		"The message is sent from the side that originates the TI" ,
		"The message is sent to the side that originates the TI" };

	curr_len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"TI flag: %s (%u)",ti_flag[oct>>7],oct>>7);

	if ( curr_len > 1 )
	{
		oct = tvb_get_guint8(tvb, curr_offset);

		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"TI value: 0x%02x (%u)",oct&0x7f,oct&0x7f);

		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"ext: 0x%02x (%u)",oct>>7,oct>>7);

	}
	else
	{
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"TI value: 0x%02x (%u)",(oct>>4)&7,(oct>>4)&7);
	}

	curr_offset+= curr_len;

	EXTRANEOUS_DATA_CHECK_EXPERT(len, curr_offset - offset, pinfo);

	return(curr_offset - offset);
}

/*
 * [9] 10.5.6.9 LLC service access point identifier
 */
static const value_string gsm_a_sm_llc_sapi_vals[] = {
	{ 0, "LLC SAPI not assigned" },
	{ 3, "SAPI 3" },
	{ 5, "SAPI 5" },
	{ 9, "SAPI 9" },
	{ 11, "SAPI 11" },
	{ 0, NULL }
};

static guint16
de_sm_sapi(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, offset << 3, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_sm_llc_sapi, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* no length check possible */
	return(1);
}

/*
 * [9] 10.5.6.10 Tear down indicator
 */
const true_false_string gsm_a_sm_tdi_value = {
	"Tear down requested",
	"Tear down not requested"
};

static guint16
de_sm_tear_down(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (offset << 3) + 4, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_sm_tdi, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* no length check possible */
	return(1);
}

/*
 * [9] 10.5.6.11 Packet Flow Identifier
 */
static const range_string gsm_a_sm_packet_flow_id_vals[] = {
	{ 0x00,	0x00, "Best Effort"},
	{ 0x01,	0x01, "Signaling"},
	{ 0x02,	0x02, "SMS"},
	{ 0x03,	0x03, "TOM8"},
	{ 0x04,	0x07, "Reserved"},
	{ 0x08,	0x7f, "Dynamically assigned"},
	{ 0x00, 0x00, NULL }
};

guint16
de_sm_pflow_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint value;

	curr_offset = offset;
	value = tvb_get_guint8(tvb,curr_offset);
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, curr_offset << 3, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_sm_packet_flow_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

    if (add_string)
        g_snprintf(add_string, string_len, " - %s", rval_to_str(value, gsm_a_sm_packet_flow_id_vals, "Unknown"));

	EXTRANEOUS_DATA_CHECK_EXPERT(len, curr_offset - offset, pinfo);

	return(curr_offset - offset);
}

/*
 * [7] 10.5.6.12     TFT - Traffic Flow Template
 */
/* TFT operation code (octet 3) */
static const value_string gsm_a_tft_op_code_vals[] = {
	{ 0,		"Spare"},
	{ 1,		"Create new TFT"},
	{ 2,		"Delete existing TFT"},
	{ 3,		"Add packet filters to existing TFT"},
	{ 4,		"Replace packet filters in existing TFT"},
	{ 5,		"Delete packet filters from existing TFT"},
	{ 6,		"No TFT operation"},
	{ 7,		"Reserved"},
	{ 0,	NULL }
};

static const true_false_string gsm_a_tft_e_bit  = {
  "Parameters list is included",
  "Parameters list is not included"
};

static const value_string gsm_a_tft_pkt_flt_dir_vals[] = {
	{ 0,	"Pre Rel-7 TFT filter"},
	{ 1,	"Downlink only"},
	{ 2,	"Uplink only"},
	{ 3,	"Bidirectional"},
	{ 0,	NULL }
};

static const value_string gsm_a_tft_param_id_vals[] = {
	{ 1,	"Authorization Token"},
	{ 2,	"Flow Identifier"},
	{ 3,	"Packet Filter Identifier"},
	{ 0,	NULL }
};

guint16
de_sm_tflow_temp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	      curr_offset;
	guint	      curr_len;
	proto_item   *tf = NULL;
	proto_tree   *tf_tree = NULL;
	proto_tree   *comp_tree = NULL;
	guchar        op_code;
	guchar        pkt_fil_count;
	guchar        e_bit;
	const gchar  *str;
	guchar        count;
	guchar        oct;
	gint          pf_length;
	gint          i;
	gint          pack_component_type;
	gint          param;

	curr_len = len;
	curr_offset = offset;

	/*
	 * parse first octet. It contain TFT operation code, E bit and Number of packet filters
	 */
	oct = tvb_get_guint8(tvb, curr_offset);

	op_code = oct>>5;
	pkt_fil_count = oct&0x0f;
	e_bit = (oct>>4)&1;

	proto_tree_add_item(tree,hf_gsm_a_tft_op_code,tvb,curr_offset,1,ENC_BIG_ENDIAN);
	proto_tree_add_item(tree,hf_gsm_a_tft_e_bit,tvb,curr_offset,1,ENC_BIG_ENDIAN);
	proto_tree_add_item(tree,hf_gsm_a_tft_pkt_flt,tvb,curr_offset,1,ENC_BIG_ENDIAN);

	curr_offset++;
	curr_len--;

	/* Packet filter list dissect */

	count = 0;
	if ( op_code == 2 )			/* delete TFT contains no packet filters. so we will jump over it */
		count = pkt_fil_count;
	while ( count < pkt_fil_count )
	{
		tf = proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Packet filter %d",count);   /* 0-> 7 */

		tf_tree = proto_item_add_subtree(tf, ett_sm_tft );

		if ( op_code == 5 )  /* Delete packet filters from existing TFT - just a list of identifiers */
		{
			if ((curr_offset-offset)<1) {
				proto_tree_add_text(tf_tree,tvb, curr_offset, 1,"Not enough data");
				return(len);
			}
			proto_tree_add_bits_item(tf_tree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3), 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(tf_tree, hf_gsm_a_tft_pkt_flt_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
			curr_offset++;
			curr_len--;
			count++;
		}
		else				/* create new, Add packet filters or Replace packet filters */
		{

			if ((curr_offset-offset)<1) {
				proto_tree_add_text(tf_tree,tvb, curr_offset, 1,"Not enough data");
				return(len);
			}
			proto_tree_add_bits_item(tf_tree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3), 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tf_tree, hf_gsm_a_tft_pkt_flt_dir, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tf_tree, hf_gsm_a_tft_pkt_flt_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
			curr_offset++;
			curr_len--;

			if ((curr_offset-offset)<1) {
				proto_tree_add_text(tf_tree,tvb, curr_offset, 1,"Not enough data");
				return(len);
			}
			oct = tvb_get_guint8(tvb, curr_offset);
			curr_offset++;
			curr_len--;

			proto_tree_add_text(tf_tree,
				tvb, curr_offset-1, 1,
				"Packet evaluation precedence: 0x%02x (%u)",oct,oct );

			if ((curr_offset-offset)<1) { proto_tree_add_text(tf_tree,tvb, curr_offset, 1,"Not enough data"); return(len);}
			pf_length = tvb_get_guint8(tvb, curr_offset);
			curr_offset++;
			curr_len--;

			proto_tree_add_text(tf_tree,
				tvb, curr_offset-1, 1,
				"Packet filter length: 0x%02x (%u)",pf_length,pf_length );
			/* New tree for component */

			/* Dissect Packet filter Component */
			/* while ( filter_len > 1 ) */
			/* packet filter component type identifier: */

			while (pf_length > 0 ){
				if ((curr_offset-offset)<1) {
					proto_tree_add_text(tf_tree,tvb, curr_offset, 1,"Not enough data");
					return(len);
				}
				pack_component_type = tvb_get_guint8(tvb, curr_offset);
				curr_offset++;
				curr_len--;
				pf_length--;

				tf=proto_tree_add_text(tf_tree,tvb, curr_offset-1, 1,"Packet filter component type identifier: ");
				comp_tree = proto_item_add_subtree(tf, ett_sm_tft );

				switch ( pack_component_type ){

				case 0x10:
					str="IPv4 remote address type";
					proto_tree_add_item(comp_tree,hf_gsm_a_sm_ip4_address,tvb,curr_offset,4,ENC_BIG_ENDIAN);
					curr_offset+=4;
					curr_len-=4;
					proto_tree_add_item(comp_tree,hf_gsm_a_sm_ip4_mask,tvb,curr_offset,4,ENC_BIG_ENDIAN);
					curr_offset+=4;
					curr_len-=4;
					pf_length-=8;
					break;

				case 0x20:
					str="IPv6 remote address type";
					proto_tree_add_item(comp_tree,hf_gsm_a_sm_ip6_address,tvb,curr_offset,16,ENC_BIG_ENDIAN);
					curr_offset+=16;
					curr_len-=16;
					proto_tree_add_item(comp_tree,hf_gsm_a_sm_ip6_mask,tvb,curr_offset,16,ENC_BIG_ENDIAN);
					curr_offset+=16;
					curr_len-=16;
					pf_length-=32;
					break;

				case 0x30:
					str="Protocol identifier/Next header type";
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_protocol_header,tvb,curr_offset,1,ENC_BIG_ENDIAN);
					curr_offset+=1;
					curr_len-=1;
					pf_length-=1;
					break;

				case 0x40:
					str="Single local port type";
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_port,tvb,curr_offset,2,ENC_BIG_ENDIAN);
					curr_offset+=2;
					curr_len-=2;
					pf_length-=2;
					break;

				case 0x41:
					str="Local port range type";
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_port_low,tvb,curr_offset,2,ENC_BIG_ENDIAN);
					curr_offset+=2;
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_port_high,tvb,curr_offset,2,ENC_BIG_ENDIAN);
					curr_offset+=2;
					curr_len-=4;
					pf_length-=4;
					break;

				case 0x50:
					str="Single remote port type";
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_port,tvb,curr_offset,2,ENC_BIG_ENDIAN);
					curr_offset+=2;
					curr_len-=2;
					pf_length-=2;
					break;

				case 0x51:
					str="Remote port range type";
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_port_low,tvb,curr_offset,2,ENC_BIG_ENDIAN);
					curr_offset+=2;
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_port_high,tvb,curr_offset,2,ENC_BIG_ENDIAN);
					curr_offset+=2;
					curr_len-=4;
					pf_length-=4;
					break;

				case 0x60:
					str="Security parameter index type";
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_security,tvb,curr_offset,4,ENC_BIG_ENDIAN);
					curr_offset+=4;
					curr_len-=4;
					pf_length-=4;
					break;


				case 0x70:
					str="Type of service/Traffic class type";
					proto_tree_add_item(comp_tree,hf_gsm_a_qos_traffic_cls,tvb,curr_offset,1,ENC_BIG_ENDIAN);
					curr_offset++;
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_traffic_mask,tvb,curr_offset,1,ENC_BIG_ENDIAN);
					curr_offset++;
					curr_len-=2;
					pf_length-=2;
					break;

				case 0x80:
					str="Flow label type";
					proto_tree_add_bits_item(comp_tree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3), 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_flow_label_type,tvb,curr_offset,3,ENC_BIG_ENDIAN);
					curr_offset+=3;
					curr_len-=3;
					pf_length-=3;
					break;

				default:
					str="not specified";
					curr_offset+=pf_length;
					curr_len-=pf_length;
					pf_length=0;
				}
				proto_item_append_text(tf, "%s (%u)", str, pack_component_type);
			}
			count++;
		}
	}

	/* The parameters list contains a variable number of parameters that might need to be
	 * transferred in addition to the packet filters. If the parameters list is included, the E
	 * bit is set to 1; otherwise, the E bit is set to 0.
	 */
	if ((e_bit == 1) && curr_len) {
		count = 0;
		while (curr_len) {
			pf_length = tvb_get_guint8(tvb, curr_offset+1);
			tf = proto_tree_add_text(tree, tvb, curr_offset, pf_length+2, "Parameter %d" ,count);
			tf_tree = proto_item_add_subtree(tf, ett_sm_tft );
			param = tvb_get_guint8(tvb, curr_offset);
			proto_tree_add_item(tf_tree, hf_gsm_a_tft_param_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
			curr_offset += 2;
			curr_len -= 2;
			switch (param) {
			case 0x01:
				proto_tree_add_text(tf_tree, tvb, curr_offset, pf_length, "Authorization token value: 0x%s",
			                        tvb_bytes_to_str(tvb, curr_offset, pf_length));
				break;

			case 0x02:
				proto_tree_add_text(tf_tree, tvb, curr_offset, 2, "Media Component number value: 0x%x",
			                        tvb_get_bits16(tvb, curr_offset<<3, 16, FALSE));
				proto_tree_add_text(tf_tree, tvb, curr_offset+2, 2, "IP flow number: 0x%x",
			                        tvb_get_bits16(tvb, (curr_offset+2)<<3, 16, FALSE));
				break;

			case 0x03:
				for (i = 0; i < pf_length; i++) {
					proto_tree_add_text(tf_tree, tvb, curr_offset+i, 1, "Packet filter identifier %d: %d",
			                            i, tvb_get_guint8(tvb, curr_offset+i));
				}
				break;

			default:
				proto_tree_add_text(tf_tree, tvb, curr_offset, pf_length, "Parameter content: 0x%s",
				                    tvb_bytes_to_str(tvb, curr_offset, pf_length));
				break;
			}
			curr_offset += pf_length;
			curr_len -= pf_length;
			count++;
		}
	}

	EXTRANEOUS_DATA_CHECK_EXPERT(len, curr_offset - offset, pinfo);

	return(len);
}

/*
 * [9] 10.5.6.13 Temporary Mobile Group Identity (TMGI)
 */
static guint16
de_sm_tmgi(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_sm_tmgi, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
	curr_offset += 3;

	NO_MORE_DATA_CHECK(len);
	curr_offset = dissect_e212_mcc_mnc(tvb, pinfo, tree, curr_offset, TRUE);

	EXTRANEOUS_DATA_CHECK_EXPERT(len, curr_offset - offset, pinfo);

	return(curr_offset - offset);
}

/*
 * [9] 10.5.6.14 MBMS bearer capabilities
 */
static guint16
de_sm_mbms_bearer_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset, temp32;
	guint8 oct;
	const gchar *str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch (oct)
	{
		case 0x00: str="Subscribed maximum bit rate for downlink/reserved"; break;
		case 0xff: str="0 kbps"; break;
		default: str = ep_strdup_printf("%u kbps", qos_calc_bitrate(oct));
	}

	proto_tree_add_uint_format_value(tree, hf_gsm_a_qos_max_bitrate_downl, tvb,
		curr_offset, 1, oct, "%s (%u)", str, oct);
	curr_offset+= 1;

	NO_MORE_DATA_CHECK(len);

	oct = tvb_get_guint8(tvb, curr_offset);

	if (oct == 0x00)
		str = "Use the value indicated by the Maximum bit rate for downlink";
	else
	{
		temp32 = qos_calc_ext_bitrate(oct);
		if (temp32 % 1000 == 0)
			str = ep_strdup_printf("%u Mbps", temp32 / 1000);
		else
			str = ep_strdup_printf("%u kbps", temp32);
	}
	proto_tree_add_uint_format_value(tree, hf_gsm_a_qos_max_bitrate_downl_ext, tvb,
		curr_offset, 1, oct, "%s (%u)", str, oct);

	curr_offset+= 1;

	EXTRANEOUS_DATA_CHECK_EXPERT(len, curr_offset - offset, pinfo);

	return(curr_offset - offset);
}

/*
 * [9] 10.5.6.15 MBMS protocol configuration options
 */
static guint16
de_sm_mbms_prot_conf_opt(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3), 8, ENC_BIG_ENDIAN);
	curr_offset++;

	EXTRANEOUS_DATA_CHECK_EXPERT(len, curr_offset - offset, pinfo);

	return(curr_offset - offset);
}

/*
 * [9] 10.5.6.16 Enhanced network service access point identifier
 */
static guint16
de_sm_enh_nsapi(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	const gchar *str;

	oct = tvb_get_guint8(tvb, offset);

	if(oct < 0x80)
		str = "Reserved";
	else if (oct < 0xff)
			str = ep_strdup_printf("NSAPI %u for Multimedia Broadcast/Multicast Service (MBMS) Multicast mode", oct);
		else
			str = "Reserved for use by lower layers in the p2p radio bearer allocation message for MBMS Broadcast mode";


	proto_tree_add_uint_format_value(tree, hf_gsm_a_sm_enh_nsapi, tvb,
		offset, 1, oct, "%s (%u)", str, oct);

	/* no length check possible */
	return(1);
}

/*
 * [9] 10.5.6.17 Request type
 */
static const value_string gsm_a_sm_req_type_vals[] = {
	{ 0x01,	"Initial request" },
	{ 0x02, "Handover" },
	{ 0x03, "Unused. If received, the network shall interpret this as \"Initial request\"." },
	{ 0, NULL }
};

static guint16
de_sm_req_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (offset<<3) + 4, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_sm_req_type, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* no length check possible */
	return(1);
}

/*
 * [9] 10.5.6.18 Notification indicator
 */
static const value_string gsm_a_sm_notif_ind_vals[] = {
	{ 0x0,	"Reserved"},
	{ 0x1,	"SRVCC handover cancelled, IMS session re-establishment required"},
	{ 0, NULL }
};

static guint16
de_sm_notif_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_sm_notif_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	return(len);
}


guint16 (*gm_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string, int string_len) = {
	/* GPRS Mobility Management Information Elements 10.5.5 */
	de_gmm_attach_res,	/* Attach Result */
	de_gmm_attach_type,	/* Attach Type */
	de_gmm_ciph_alg,	/* Cipher Algorithm */
	de_gmm_tmsi_stat,	/* TMSI Status */
	de_gmm_detach_type,	/* Detach Type */
	de_gmm_drx_param,	/* DRX Parameter */
	de_gmm_ftostby,		/* Force to Standby */
	de_gmm_ftostby_h,	/* Force to Standby - Info is in the high nibble */
	de_gmm_ptmsi_sig,	/* P-TMSI Signature */
	de_gmm_ptmsi_sig2,	/* P-TMSI Signature 2 */
	de_gmm_ident_type2,	/* Identity Type 2 */
	de_gmm_imeisv_req,	/* IMEISV Request */
	de_gmm_rec_npdu_lst,	/* Receive N-PDU Numbers List */
	de_gmm_ms_net_cap,	/* MS Network Capability */
	de_gmm_ms_radio_acc_cap,/* MS Radio Access Capability */
	de_gmm_cause,		/* GMM Cause */
	de_gmm_rai,		/* Routing Area Identification */
	de_gmm_rai2,	/* Routing Area Identification 2 */
	de_gmm_update_res,	/* Update Result */
	de_gmm_update_type,	/* Update Type */
	de_gmm_ac_ref_nr,	/* A&C Reference Number */
	de_gmm_ac_ref_nr_h, 	/* A&C Reference Numer - Info is in the high nibble */
	de_gmm_service_type,	/* Service Type */
	NULL /* no associated data */,	/* Cell Notification */
	de_gmm_ps_lcs_cap,	/* PS LCS Capability */
	de_gmm_net_feat_supp,	/* Network Feature Support */
	de_gmm_rat_info_container, /* Inter RAT information container */
	de_gmm_req_ms_info, /* Requested MS information */
    NULL, /* UE network capability */
    de_gmm_eutran_irat_info_container, /* E-UTRAN inter RAT information container */
    de_gmm_voice_domain_pref, /* Voice domain preference and UE's usage setting */
	/* Session Management Information Elements 10.5.6 */
	de_sm_apn,		/* Access Point Name */
	de_sm_nsapi,		/* Network Service Access Point Identifier */
	de_sm_pco,		/* Protocol Configuration Options */
	de_sm_pdp_addr,		/* Packet Data Protocol Address */
	de_sm_qos,		/* Quality Of Service */
	de_sm_cause,		/* SM Cause */
	de_sm_cause_2,		/* SM Cause 2 */
	de_sm_linked_ti,	/* Linked TI */
	de_sm_sapi,		/* LLC Service Access Point Identifier */
	de_sm_tear_down,	/* Tear Down Indicator */
	de_sm_pflow_id,		/* Packet Flow Identifier */
	de_sm_tflow_temp,	/* Traffic Flow Template */
	de_sm_tmgi,		/* Temporary Mobile Group Identity (TMGI) */
	de_sm_mbms_bearer_cap,	/* MBMS bearer capabilities */
	de_sm_mbms_prot_conf_opt,	/* MBMS protocol configuration options */
	de_sm_enh_nsapi,	/* Enhanced network service access point identifier */
	de_sm_req_type,		/* Request type */
	de_sm_notif_ind,	/* Notification indicator */
	/* GPRS Common Information Elements 10.5.7 */
	de_gc_context_stat,	/* PDP Context Status */
	de_gc_radio_prio,	/* Radio Priority */
	de_gc_timer,		/* GPRS Timer */
	de_gc_timer2,		/* GPRS Timer 2 */
	de_gc_radio_prio2,	/* Radio Priority 2 */
	de_gc_mbms_context_stat,/* 10.5.7.6 MBMS context status */
	de_gc_uplink_data_stat, /* 10.5.7.7 Uplink data status */
	NULL,	/* NONE */
};

/* MESSAGE FUNCTIONS */

/*
 * [7] 9.4.1
 */
static void
dtap_gmm_attach_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_RECV;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_MS_NET_CAP, NULL);

	/* Included in attach type

	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_CIPH_KEY_SEQ_NUM, NULL);
	curr_offset--;
	curr_len++;
	*/

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_ATTACH_TYPE, NULL);

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_DRX_PARAM, NULL);

	ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID , NULL);

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_RAI, " - Old routing area identification");

	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_MS_RAD_ACC_CAP , NULL);

	ELEM_OPT_TV( 0x19 , GSM_A_PDU_TYPE_GM, DE_P_TMSI_SIG, " - Old P-TMSI Signature");

	ELEM_OPT_TV( 0x17 , GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER , " - Ready Timer" );

	ELEM_OPT_TV_SHORT( 0x90 , GSM_A_PDU_TYPE_GM, DE_TMSI_STAT , NULL);

	ELEM_OPT_TLV( 0x33 , GSM_A_PDU_TYPE_GM, DE_PS_LCS_CAP , NULL);

	ELEM_OPT_TLV(0x11, GSM_A_PDU_TYPE_COMMON, DE_MS_CM_2, NULL);

	ELEM_OPT_TLV(0x20, GSM_A_PDU_TYPE_COMMON, DE_MS_CM_3, NULL);

	ELEM_OPT_TLV(0x40, GSM_A_PDU_TYPE_DTAP, DE_SUP_CODEC_LIST, NULL);

	ELEM_OPT_TLV(0x58, NAS_PDU_TYPE_EMM, DE_EMM_UE_NET_CAP, NULL);

	ELEM_OPT_TLV(0x1A, GSM_A_PDU_TYPE_COMMON, DE_MID, " - Additional mobile identity");

	ELEM_OPT_TLV(0x1B, GSM_A_PDU_TYPE_GM, DE_RAI_2, " - Additional old routing area identification");

	ELEM_OPT_TLV(0x5D, GSM_A_PDU_TYPE_GM, DE_VOICE_DOMAIN_PREF, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [7] 9.4.2
 */
static void
dtap_gmm_attach_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_FORCE_TO_STAND_H, NULL);
	curr_len++;
	curr_offset--;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_ATTACH_RES, NULL);

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER, NULL);

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_RAD_PRIO_2, " - Radio priority for TOM8");
	curr_len++;
	curr_offset--;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_RAD_PRIO, " - Radio priority for SMS");

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_RAI, NULL);

	ELEM_OPT_TV( 0x19 , GSM_A_PDU_TYPE_GM, DE_P_TMSI_SIG, NULL);

	ELEM_OPT_TV( 0x17 , GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER , " - Negotiated Ready Timer" );

	ELEM_OPT_TLV( 0x18 , GSM_A_PDU_TYPE_COMMON, DE_MID , " - Allocated P-TMSI" );

	ELEM_OPT_TLV( 0x23 , GSM_A_PDU_TYPE_COMMON, DE_MID , NULL);

	ELEM_OPT_TV( 0x25 , GSM_A_PDU_TYPE_GM, DE_GMM_CAUSE , NULL);

	ELEM_OPT_TLV( 0x2A , GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2 , " - T3302" );

	ELEM_OPT_T( 0x8C , GSM_A_PDU_TYPE_GM, DE_CELL_NOT , NULL);

	ELEM_OPT_TLV( 0x4A , GSM_A_PDU_TYPE_COMMON, DE_PLMN_LIST , NULL);

	ELEM_OPT_TV_SHORT( 0xB0 , GSM_A_PDU_TYPE_GM, DE_NET_FEAT_SUP , NULL);

	ELEM_OPT_TLV( 0x34 , GSM_A_PDU_TYPE_DTAP, DE_EMERGENCY_NUM_LIST , NULL);

	ELEM_OPT_TV_SHORT( 0xA0 , GSM_A_PDU_TYPE_GM , DE_REQ_MS_INFO , NULL);

	ELEM_OPT_TLV( 0x37 , GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2 , " - T3319" );

	ELEM_OPT_TLV( 0x38 , GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2 , " - T3323" );

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [7] 9.4.3
 */
static void
dtap_gmm_attach_com(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{

	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_RECV;

	ELEM_OPT_TLV(0x27, GSM_A_PDU_TYPE_GM, DE_RAT_INFO_CONTAINER, " - Inter RAT handover information");

	ELEM_OPT_TLV(0x2B, GSM_A_PDU_TYPE_GM, DE_EUTRAN_IRAT_INFO_CONTAINER, " - E-UTRAN inter RAT handover information");

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [7] 9.4.4
 */
static void
dtap_gmm_attach_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_GMM_CAUSE, NULL);

	ELEM_OPT_TLV( 0x2A , GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2 , " - T3302" );

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [7] 9.4.5
 */
static void
dtap_gmm_detach_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_FORCE_TO_STAND_H, NULL);
	/* Force to standy might be wrong - To decode it correct, we need the direction */
	curr_len++;
	curr_offset--;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_DETACH_TYPE, NULL);

	ELEM_OPT_TV( 0x25 , GSM_A_PDU_TYPE_GM, DE_GMM_CAUSE , NULL);

	ELEM_OPT_TLV( 0x18 , GSM_A_PDU_TYPE_COMMON, DE_MID , " - P-TMSI" );

	ELEM_OPT_TLV( 0x19 , GSM_A_PDU_TYPE_GM, DE_P_TMSI_SIG_2 , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [7] 9.4.6
 */
static void
dtap_gmm_detach_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_RECV;

	if ( curr_len != 0 )
	{
		ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_SPARE_NIBBLE, NULL);
		curr_len++;
		curr_offset--;

		ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_FORCE_TO_STAND, NULL);
	}

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [7] 9.4.7
 */
static void
dtap_gmm_ptmsi_realloc_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID , " - Allocated P-TMSI" );

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_RAI, NULL);

	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_SPARE_NIBBLE, NULL);
	curr_len++;
	curr_offset--;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_FORCE_TO_STAND, NULL);

	ELEM_OPT_TV( 0x19 , GSM_A_PDU_TYPE_GM, DE_P_TMSI_SIG , " - P-TMSI Signature" );

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [7] 9.4.8
 */
static void
dtap_gmm_ptmsi_realloc_com(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
/*    guint32	consumed; */
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_RECV;

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [7] 9.4.9
 */
static void
dtap_gmm_auth_ciph_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint   curr_len;
	guint8  oct;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_IMEISV_REQ, NULL);
	curr_offset--;
	curr_len++;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_CIPH_ALG, NULL);

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_AC_REF_NUM_H, NULL);
	curr_offset--;
	curr_len++;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_FORCE_TO_STAND, NULL);

	ELEM_OPT_TV( 0x21 , GSM_A_PDU_TYPE_DTAP, DE_AUTH_PARAM_RAND , NULL);

#if 0
	ELEM_OPT_TV_SHORT( 0x08 , GSM_A_PDU_TYPE_COMMON, DE_CIPH_KEY_SEQ_NUM , NULL);
#else
	if ( curr_len > 0 )
	{
		oct = tvb_get_guint8(tvb, curr_offset);
		if (( oct & 0xf0 ) == 0x80 )
		{
			/* The ciphering key sequence number is added here */
			proto_tree_add_text(tree,
				tvb, curr_offset, 1,
				"Ciphering key sequence number: 0x%02x (%u)",
				oct&7,
				oct&7);
			curr_offset++;
			curr_len--;
		}
	}
#endif

	if ( curr_len == 0  )
	{
		EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
	return;
	}

	ELEM_OPT_TLV( 0x28 , GSM_A_PDU_TYPE_DTAP, DE_AUTH_PARAM_AUTN , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [7] 9.4.10
 */
static void
dtap_gmm_auth_ciph_resp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_RECV;

	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_SPARE_NIBBLE, NULL);
	curr_offset--;
	curr_len++;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_AC_REF_NUM, NULL);

	ELEM_OPT_TV( 0x22 , GSM_A_PDU_TYPE_DTAP, DE_AUTH_RESP_PARAM , NULL);

	ELEM_OPT_TLV( 0x23 , GSM_A_PDU_TYPE_COMMON, DE_MID , " - IMEISV" );

	ELEM_OPT_TLV( 0x29 , GSM_A_PDU_TYPE_DTAP, DE_AUTH_RESP_PARAM_EXT , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [7] 9.4.11
 */
static void
dtap_gmm_auth_ciph_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [7] 9.4.10a
 */
static void
dtap_gmm_auth_ciph_fail(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_RECV;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_GMM_CAUSE, NULL);

	ELEM_OPT_TLV( 0x30 , GSM_A_PDU_TYPE_DTAP, DE_AUTH_FAIL_PARAM , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [7] 9.4.12
 */
static void
dtap_gmm_ident_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

/*  If the half octect that are about to get decoded is the LAST in the octetstream, the macro will call return BEFORE we get a chance to fix the index. The end result will be that the first half-octet will be decoded but not the last. */
#if 0
	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_ID_TYPE_2, NULL);
	curr_offset--;
	curr_len++;
	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_FORCE_TO_STAND_H, NULL);
#endif

	elem_v(tvb, tree, pinfo, GSM_A_PDU_TYPE_GM, DE_FORCE_TO_STAND_H, curr_offset, NULL);
	elem_v(tvb, tree, pinfo, GSM_A_PDU_TYPE_GM, DE_ID_TYPE_2, curr_offset, NULL);

	curr_offset+=1;
	curr_len-=1;

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [7] 9.4.13
 */
static void
dtap_gmm_ident_res(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_RECV;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [7] 9.4.14
 */
static void
dtap_gmm_rau_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_RECV;

	/* is included in update type
	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_CIPH_KEY_SEQ_NUM, NULL);
	curr_offset--;
	curr_len++;
	*/

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_UPD_TYPE, NULL);

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_RAI, " - Old routing area identification");

	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_MS_RAD_ACC_CAP , NULL);

	ELEM_OPT_TV( 0x19 , GSM_A_PDU_TYPE_GM, DE_P_TMSI_SIG , " - Old P-TMSI Signature" );

	ELEM_OPT_TV( 0x17 , GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER , " - Requested Ready Timer" );

	ELEM_OPT_TV( 0x27 , GSM_A_PDU_TYPE_GM, DE_DRX_PARAM , NULL);

	ELEM_OPT_TV_SHORT( 0x90 , GSM_A_PDU_TYPE_GM, DE_TMSI_STAT , NULL);

	ELEM_OPT_TLV( 0x18 , GSM_A_PDU_TYPE_COMMON, DE_MID , " - P-TMSI" );

	ELEM_OPT_TLV( 0x31 , GSM_A_PDU_TYPE_GM, DE_MS_NET_CAP , NULL);

	ELEM_OPT_TLV( 0x32 , GSM_A_PDU_TYPE_GM, DE_PDP_CONTEXT_STAT , NULL);

	ELEM_OPT_TLV( 0x33 , GSM_A_PDU_TYPE_GM, DE_PS_LCS_CAP , NULL);

	ELEM_OPT_TLV(0x35, GSM_A_PDU_TYPE_GM, DE_MBMS_CTX_STATUS, NULL);

	ELEM_OPT_TLV(0x58, NAS_PDU_TYPE_EMM, DE_EMM_UE_NET_CAP, NULL);

	ELEM_OPT_TLV(0x1A, GSM_A_PDU_TYPE_COMMON, DE_MID, " - Additional mobile identity");

	ELEM_OPT_TLV(0x1B, GSM_A_PDU_TYPE_GM, DE_RAI_2, " - Additional old routing area identification");

	ELEM_OPT_TLV(0x11, GSM_A_PDU_TYPE_COMMON, DE_MS_CM_2, NULL);

	ELEM_OPT_TLV(0x20, GSM_A_PDU_TYPE_COMMON, DE_MS_CM_3, NULL);

	ELEM_OPT_TLV(0x40, GSM_A_PDU_TYPE_DTAP, DE_SUP_CODEC_LIST, NULL);

	ELEM_OPT_TLV(0x5D, GSM_A_PDU_TYPE_GM, DE_VOICE_DOMAIN_PREF, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [7] 9.4.15
 */
static void
dtap_gmm_rau_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_UPD_RES, NULL);
	curr_offset--;
	curr_len++;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_FORCE_TO_STAND, NULL);

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER, " - Periodic RA update timer");

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_RAI, NULL);

	ELEM_OPT_TV( 0x19 , GSM_A_PDU_TYPE_GM, DE_P_TMSI_SIG , NULL);

	ELEM_OPT_TLV( 0x18 , GSM_A_PDU_TYPE_COMMON, DE_MID , " - Allocated P-TMSI");

	ELEM_OPT_TLV( 0x23 , GSM_A_PDU_TYPE_COMMON, DE_MID , " - MS identity");

	ELEM_OPT_TLV( 0x26 , GSM_A_PDU_TYPE_GM, DE_REC_N_PDU_NUM_LIST , NULL);

	ELEM_OPT_TV( 0x17 , GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER , " - Negotiated Ready Timer" );

	ELEM_OPT_TV( 0x25 , GSM_A_PDU_TYPE_GM, DE_GMM_CAUSE , NULL);

	ELEM_OPT_TLV( 0x2A , GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2 , " - T3302" );

	ELEM_OPT_T( 0x8C , GSM_A_PDU_TYPE_GM, DE_CELL_NOT , NULL);

	ELEM_OPT_TLV( 0x4A , GSM_A_PDU_TYPE_COMMON, DE_PLMN_LIST , NULL);

	ELEM_OPT_TLV( 0x32 , GSM_A_PDU_TYPE_GM, DE_PDP_CONTEXT_STAT , NULL);

	ELEM_OPT_TV_SHORT ( 0xB0 , GSM_A_PDU_TYPE_GM, DE_NET_FEAT_SUP , NULL);

	ELEM_OPT_TLV( 0x34 , GSM_A_PDU_TYPE_DTAP, DE_EMERGENCY_NUM_LIST , NULL);

	ELEM_OPT_TLV(0x35 , GSM_A_PDU_TYPE_GM, DE_MBMS_CTX_STATUS , NULL);

	ELEM_OPT_TV_SHORT(0xA0 , GSM_A_PDU_TYPE_GM , DE_REQ_MS_INFO , NULL);

	ELEM_OPT_TLV(0x37 , GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2 , " - T3319");

	ELEM_OPT_TLV(0x38 , GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2 , " - T3323");

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [7] 9.4.16
 */
static void
dtap_gmm_rau_com(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_RECV;
	/* [7] 10.5.5.11 */
	ELEM_OPT_TLV( 0x26 , GSM_A_PDU_TYPE_GM, DE_REC_N_PDU_NUM_LIST , NULL);
	/* Inter RAT information container 10.5.5.24 TS 24.008 version 6.8.0 Release 6 */
	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_RAT_INFO_CONTAINER , " - Inter RAT handover information");

	ELEM_OPT_TLV(0x2B, GSM_A_PDU_TYPE_GM, DE_EUTRAN_IRAT_INFO_CONTAINER, " - E-UTRAN inter RAT handover information");

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [7] 9.4.17
 */
static void
dtap_gmm_rau_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_GMM_CAUSE, NULL);

	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_SPARE_NIBBLE, NULL);
	curr_offset--;
	curr_len++;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_FORCE_TO_STAND, NULL);

	ELEM_OPT_TLV( 0x26 , GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2 , " - T3302" );

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [7] 9.4.18
 */
static void
dtap_gmm_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_GMM_CAUSE, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [8] 9.4.19 GMM Information
 */
static void
dtap_gmm_information(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_OPT_TLV( 0x43 , GSM_A_PDU_TYPE_DTAP, DE_NETWORK_NAME , " - Full Name" );

	ELEM_OPT_TLV( 0x45 , GSM_A_PDU_TYPE_DTAP, DE_NETWORK_NAME , " - Short Name" );

	ELEM_OPT_TV( 0x46 , GSM_A_PDU_TYPE_DTAP, DE_TIME_ZONE , NULL);

	ELEM_OPT_TV( 0x47 , GSM_A_PDU_TYPE_DTAP, DE_TIME_ZONE_TIME , NULL);

	ELEM_OPT_TLV( 0x48 , GSM_A_PDU_TYPE_DTAP, DE_LSA_ID , NULL);

	ELEM_OPT_TLV( 0x49 , GSM_A_PDU_TYPE_DTAP, DE_DAY_SAVING_TIME , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [7] 9.4.20
 */
static void
dtap_gmm_service_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_RECV;

	/* Is included in SRVC TYPE
	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_CIPH_KEY_SEQ_NUM, NULL);
	curr_offset--;
	curr_len++;
	*/

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_SRVC_TYPE, NULL);

	/* P-TMSI Mobile station identity 10.5.1.4 M LV 6 */
	ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID, NULL);

	ELEM_OPT_TLV( 0x32 , GSM_A_PDU_TYPE_GM, DE_PDP_CONTEXT_STAT , NULL);

	/* MBMS context status 10.5.7.6 TLV 2 - 18 */
	ELEM_OPT_TLV( 0x35 , GSM_A_PDU_TYPE_GM, DE_MBMS_CTX_STATUS , NULL);

	ELEM_OPT_TLV(0x36, GSM_A_PDU_TYPE_GM, DE_UPLINK_DATA_STATUS, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [7] 9.4.21
 */
static void
dtap_gmm_service_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_OPT_TLV( 0x32 , GSM_A_PDU_TYPE_GM, DE_PDP_CONTEXT_STAT , NULL);

	/* MBMS context status 10.5.7.6 TLV 2 - 18 */
	ELEM_OPT_TLV( 0x35 , GSM_A_PDU_TYPE_GM, DE_MBMS_CTX_STATUS , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [7] 9.4.22
 */
static void
dtap_gmm_service_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_GMM_CAUSE, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [8] 9.5.1 Activate PDP context request
 * Direction:			MS to network
 */
static void
dtap_sm_act_pdp_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	/* MS to network */
	pinfo->link_dir = P2P_DIR_UL;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_NET_SAPI, " - Requested NSAPI");

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_LLC_SAPI, " - Requested LLC SAPI");

	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_QOS , " - Requested QoS" );

	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_PD_PRO_ADDR , " - Requested PDP address" );

	ELEM_OPT_TLV( 0x28 , GSM_A_PDU_TYPE_GM, DE_ACC_POINT_NAME , NULL);

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL);

	ELEM_OPT_TV_SHORT(0xA0, GSM_A_PDU_TYPE_GM, DE_REQ_TYPE, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [9] 9.5.2 Activate PDP context accept
 * Direction:			network to MS
 */
static void
dtap_sm_act_pdp_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	/* Network to MS*/
	pinfo->link_dir = P2P_DIR_DL;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_LLC_SAPI, " - Negotiated LLC SAPI");

	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_QOS , " - Negotiated QoS" );

#if 0
	/* This is done automatically */
	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_SPARE, NULL);
	curr_offset--;
	curr_len++;
#endif

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_RAD_PRIO, NULL);

	ELEM_OPT_TLV( 0x2B , GSM_A_PDU_TYPE_GM, DE_PD_PRO_ADDR , " - PDP address");

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL);

	ELEM_OPT_TLV( 0x34 , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);

	ELEM_OPT_TLV( 0x39 , GSM_A_PDU_TYPE_GM, DE_SM_CAUSE_2, " - SM cause");

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [8] 9.5.3 Activate PDP context reject
 * Direction:			network to MS
 */
static void
dtap_sm_act_pdp_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	/* Network to MS*/
	pinfo->link_dir = P2P_DIR_DL;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_SM_CAUSE, NULL);

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [8] 9.5.4 Activate Secondary PDP Context Request
 * Direction:			MS to network
 */
static void
dtap_sm_act_sec_pdp_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	/* MS to Network */
	pinfo->link_dir = P2P_DIR_UL;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_NET_SAPI, " - Requested NSAPI");

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_LLC_SAPI, " - Requested LLC SAPI");

	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_QOS , " - Requested QoS" );

	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_LINKED_TI , NULL);

	/* 3GPP TS 24.008 version 6.8.0 Release 6, 36 TFT Traffic Flow Template 10.5.6.12 O TLV 3-257 */
	ELEM_OPT_TLV( 0x36 , GSM_A_PDU_TYPE_GM, DE_TRAFFIC_FLOW_TEMPLATE , NULL);

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [7] 9.5.5	Activate Secondary PDP Context Accept
 * Direction:			network to MS
 */
static void
dtap_sm_act_sec_pdp_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	/* Network to MS*/
	pinfo->link_dir = P2P_DIR_DL;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_LLC_SAPI, " - Negotiated LLC SAPI");

	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_QOS , " - Negotiated QoS" );

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_RAD_PRIO, NULL);

#if 0
	/* This is done automatically */
	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_SPARE, NULL);
	curr_offset--;
	curr_len++;
#endif

	ELEM_OPT_TLV( 0x34 , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [8] 9.5.6 Activate Secondary PDP Context Reject
 * Direction:			network to MS
 */
static void
dtap_sm_act_sec_pdp_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	/* Network to MS*/
	pinfo->link_dir = P2P_DIR_DL;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_SM_CAUSE, NULL);

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [8] 9.5.7 Request PDP context activation
 * Direction:			network to MS
 */
static void
dtap_sm_req_pdp_act(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	/* Network to MS*/
	pinfo->link_dir = P2P_DIR_DL;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_PD_PRO_ADDR , " - Offered PDP address" );

	ELEM_OPT_TLV( 0x28 , GSM_A_PDU_TYPE_GM, DE_ACC_POINT_NAME , NULL);

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [8] 9.5.8 Request PDP context activation reject
 * Direction:			MS to network
 */
static void
dtap_sm_req_pdp_act_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	/* MS to  Network */
	pinfo->link_dir = P2P_DIR_UL;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_SM_CAUSE, NULL);

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [8] 9.5.9 Modify PDP context request (Network to MS direction)
 * Direction:			network to MS
 */
static void
dtap_sm_mod_pdp_req_net(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	/* Network to MS */
	pinfo->link_dir = P2P_DIR_DL;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM,DE_RAD_PRIO, NULL);
#if 0
	/* This is done automatically */
	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_SPARE, NULL);
	curr_offset--;
	curr_len++;
#endif

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_LLC_SAPI, " - Requested LLC SAPI");

	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_QOS , " - New QoS" );

	ELEM_OPT_TLV( 0x2B , GSM_A_PDU_TYPE_GM, DE_PD_PRO_ADDR , " - PDP address");

	ELEM_OPT_TLV( 0x34 , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL);

	ELEM_OPT_TLV(0x36 , GSM_A_PDU_TYPE_GM, DE_TRAFFIC_FLOW_TEMPLATE , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [8] 9.5.10 Modify PDP context request (MS to network direction)
 * Direction:			MS to network
 */
static void
dtap_sm_mod_pdp_req_ms(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	/* MS to Network */
	pinfo->link_dir = P2P_DIR_UL;

	ELEM_OPT_TV( 0x32 , GSM_A_PDU_TYPE_GM, DE_LLC_SAPI , " - Requested LLC SAPI" );

	ELEM_OPT_TLV( 0x30 , GSM_A_PDU_TYPE_GM, DE_QOS , " - Requested new QoS" );

	ELEM_OPT_TLV( 0x31 , GSM_A_PDU_TYPE_GM, DE_TRAFFIC_FLOW_TEMPLATE , " - New TFT" );

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [8] 9.5.11 Modify PDP context accept (MS to network direction)
 * Direction:			MS to network
 */
static void
dtap_sm_mod_pdp_acc_ms(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	/* MS to Network */
	pinfo->link_dir = P2P_DIR_UL;

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [8] 9.5.12 Modify PDP context accept (Network to MS direction)
 * Direction:			Network to MS
 */
static void
dtap_sm_mod_pdp_acc_net(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	/* Network to MS */
	pinfo->link_dir = P2P_DIR_DL;

	ELEM_OPT_TLV( 0x30 , GSM_A_PDU_TYPE_GM, DE_QOS , " - Negotiated QoS" );

	ELEM_OPT_TV( 0x32 , GSM_A_PDU_TYPE_GM, DE_LLC_SAPI , " - Negotiated LLC SAPI" );

	ELEM_OPT_TV_SHORT ( 0x80 , GSM_A_PDU_TYPE_GM , DE_RAD_PRIO , " - New radio priority" );

	ELEM_OPT_TLV( 0x34 , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [8] 9.5.13 Modify PDP Context Reject
 * Direction:			both
 */
static void
dtap_sm_mod_pdp_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	/* Network or the MS */
	pinfo->link_dir = LINK_DIR_UNKNOWN;


	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_SM_CAUSE, NULL);

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [8] 9.5.14 Deactivate PDP context request
 * Direction:			both
 */
static void
dtap_sm_deact_pdp_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	pinfo->link_dir = LINK_DIR_UNKNOWN;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_SM_CAUSE, NULL);

	ELEM_OPT_TV_SHORT( 0x90 , GSM_A_PDU_TYPE_GM , DE_TEAR_DOWN_IND , NULL);

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL);

	/* MBMS context status 10.5.7.6 TLV 2 - 18 */
	ELEM_OPT_TLV( 0x35 , GSM_A_PDU_TYPE_GM, DE_MBMS_CTX_STATUS , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [8] 9.5.15 Deactivate PDP context accept
 * Direction:			both
 */
static void
dtap_sm_deact_pdp_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	pinfo->link_dir = LINK_DIR_UNKNOWN;

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , NULL);

	/* MBMS context status 10.5.7.6 TLV 2 - 18 */
	ELEM_OPT_TLV( 0x35 , GSM_A_PDU_TYPE_GM, DE_MBMS_CTX_STATUS , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [8] 9.5.15a Request Secondary PDP Context Activation
 * Direction:			network to MS
 */
static void
dtap_sm_req_sec_pdp_act(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	pinfo->link_dir = P2P_DIR_DL;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_QOS , " - Required QoS");

	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_LINKED_TI , NULL);

	ELEM_OPT_TLV(0x36, GSM_A_PDU_TYPE_GM, DE_TRAFFIC_FLOW_TEMPLATE, NULL);

	ELEM_OPT_TLV(0x27, GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [8] 9.5.15b Request Secondary PDP Context Activation Reject
 * Direction:			MS to network
 */
static void
dtap_sm_req_sec_pdp_act_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	pinfo->link_dir = P2P_DIR_UL;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_SM_CAUSE, NULL);

	ELEM_OPT_TLV(0x27, GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [8] 9.5.16a Notification
 * Direction:			network to MS
 */
static void
dtap_sm_notif(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	pinfo->link_dir = P2P_DIR_DL;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_SM_NOTIF_IND, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [8] 9.5.21 SM Status
 * Direction:			both
 */
static void
dtap_sm_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	pinfo->link_dir = LINK_DIR_UNKNOWN;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_SM_CAUSE, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [9] 9.5.22 Activate MBMS Context Request
 * Direction:			MS to network
 */
static void
dtap_sm_act_mbms_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_RECV;

	/* Requested MBMS NSAPI Enhanced Network service access point identifier 10.5.6.16 M V */
	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_ENH_NSAPI, " - Requested MBMS NSAPI");

	/* Requested LLC SAPI LLC service access point identifier 10.5.6.9 M V 1 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_LLC_SAPI, " - Requested LLC SAPI");

	/* Supported MBMS bearer capabilities MBMS bearer capabilities 10.5.6.14 M LV 2 - 3 */
	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_MBMS_BEARER_CAP , NULL );

	/* Requested multicast address Packet data protocol address 10.5.6.4 M LV 3 - 19 */
	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_PD_PRO_ADDR , " - Requested multicast address" );

	/* Access point name Access point name 10.5.6.1 M LV 2 - 101 */
	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_ACC_POINT_NAME , NULL );

	/* 35 MBMS protocol configuration options MBMS protocol configuration options 10.5.6.15 O TLV 3 - 253 */
	ELEM_OPT_TLV( 0x35 , GSM_A_PDU_TYPE_GM, DE_MBMS_PROT_CONF_OPT , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [9] 9.5.23 Activate MBMS Context Accept
 * Direction:			network to MS
 */
static void
dtap_sm_act_mbms_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_TMGI, NULL);

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_LLC_SAPI, " - Negotiated LLC SAPI");

	ELEM_OPT_TLV( 0x35 , GSM_A_PDU_TYPE_GM, DE_MBMS_PROT_CONF_OPT , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [9] 9.5.24 Activate MBMS Context Reject
 * Direction:			network to MS
 */
static void
dtap_sm_act_mbms_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_SM_CAUSE, NULL);

	ELEM_OPT_TLV( 0x35 , GSM_A_PDU_TYPE_GM, DE_MBMS_PROT_CONF_OPT , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [9] 9.5.25 Request MBMS Context Activation
 * Direction:			network to MS
 */
static void
dtap_sm_req_mbms_act(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_NET_SAPI, " - Linked NSAPI");

	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_PD_PRO_ADDR , " - Offered multicast address" );

	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_ACC_POINT_NAME , NULL );

	ELEM_OPT_TLV( 0x35 , GSM_A_PDU_TYPE_GM, DE_MBMS_PROT_CONF_OPT , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

/*
 * [8] 9.5.26 Request MBMS Context Activation Reject
 * Direction:			MS to network
 */
static void
dtap_sm_req_mbms_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	pinfo->p2p_dir = P2P_DIR_RECV;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_SM_CAUSE, NULL);

	ELEM_OPT_TLV( 0x35 , GSM_A_PDU_TYPE_GM, DE_MBMS_PROT_CONF_OPT , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, pinfo);
}

#define	NUM_GSM_DTAP_MSG_GMM (sizeof(gsm_a_dtap_msg_gmm_strings)/sizeof(value_string))
static gint ett_gsm_dtap_msg_gmm[NUM_GSM_DTAP_MSG_GMM];
static void (*dtap_msg_gmm_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len) = {
	dtap_gmm_attach_req,		/* Attach Request */
	dtap_gmm_attach_acc,		/* Attach Accept */
	dtap_gmm_attach_com,		/* Attach Complete */
	dtap_gmm_attach_rej,		/* Attach Reject */
	dtap_gmm_detach_req,		/* Detach Request */
	dtap_gmm_detach_acc,		/* Detach Accept */
	dtap_gmm_rau_req,			/* Routing Area Update Request */
	dtap_gmm_rau_acc,			/* Routing Area Update Accept */
	dtap_gmm_rau_com,			/* Routing Area Update Complete */
	dtap_gmm_rau_rej,			/* Routing Area Update Reject */
	dtap_gmm_service_req,		/* Service Request */
	dtap_gmm_service_acc,		/* Service Accept */
	dtap_gmm_service_rej,		/* Service Reject */
	dtap_gmm_ptmsi_realloc_cmd,	/* P-TMSI Reallocation Command */
	dtap_gmm_ptmsi_realloc_com,	/* P-TMSI Reallocation Complete */
	dtap_gmm_auth_ciph_req,		/* Authentication and Ciphering Req */
	dtap_gmm_auth_ciph_resp,	/* Authentication and Ciphering Resp */
	dtap_gmm_auth_ciph_rej,		/* Authentication and Ciphering Rej */
	dtap_gmm_auth_ciph_fail,	/* Authentication and Ciphering Failure */
	dtap_gmm_ident_req,			/* Identity Request */
	dtap_gmm_ident_res,			/* Identity Response */
	dtap_gmm_status,			/* GMM Status */
	dtap_gmm_information,		/* GMM Information */
	NULL,	/* NONE */
};

#define	NUM_GSM_DTAP_MSG_SM (sizeof(gsm_a_dtap_msg_sm_strings)/sizeof(value_string))
static gint ett_gsm_dtap_msg_sm[NUM_GSM_DTAP_MSG_SM];
static void (*dtap_msg_sm_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len) = {
	dtap_sm_act_pdp_req,		/* Activate PDP Context Request */
	dtap_sm_act_pdp_acc,		/* Activate PDP Context Accept */
	dtap_sm_act_pdp_rej,		/* Activate PDP Context Reject */
	dtap_sm_req_pdp_act,		/* Request PDP Context Activation */
	dtap_sm_req_pdp_act_rej,	/* Request PDP Context Activation rej. */
	dtap_sm_deact_pdp_req,		/* Deactivate PDP Context Request */
	dtap_sm_deact_pdp_acc,		/* Deactivate PDP Context Accept */
	dtap_sm_mod_pdp_req_net,	/* Modify PDP Context Request(Network to MS direction) */
	dtap_sm_mod_pdp_acc_ms,		/* Modify PDP Context Accept (MS to network direction) */
	dtap_sm_mod_pdp_req_ms,		/* Modify PDP Context Request(MS to network direction) */
	dtap_sm_mod_pdp_acc_net,	/* Modify PDP Context Accept (Network to MS direction) */
	dtap_sm_mod_pdp_rej,		/* Modify PDP Context Reject */
	dtap_sm_act_sec_pdp_req,	/* Activate Secondary PDP Context Request */
	dtap_sm_act_sec_pdp_acc,	/* Activate Secondary PDP Context Accept */
	dtap_sm_act_sec_pdp_rej,	/* Activate Secondary PDP Context Reject */
	NULL,						/* Reserved: was allocated in earlier phases of the protocol */
	NULL,						/* Reserved: was allocated in earlier phases of the protocol */
	NULL,						/* Reserved: was allocated in earlier phases of the protocol */
	NULL,						/* Reserved: was allocated in earlier phases of the protocol */
	NULL,						/* Reserved: was allocated in earlier phases of the protocol */
	dtap_sm_status,				/* SM Status */
	dtap_sm_act_mbms_req,		/* Activate MBMS Context Request */
	dtap_sm_act_mbms_acc,		/* Activate MBMS Context Accept */
	dtap_sm_act_mbms_rej,		/* Activate MBMS Context Reject */
	dtap_sm_req_mbms_act,		/* Request MBMS Context Activation */
	dtap_sm_req_mbms_rej,		/* Request MBMS Context Activation Reject */
	dtap_sm_req_sec_pdp_act,	/* Request Secondary PDP Context Activation */
	dtap_sm_req_sec_pdp_act_rej,/* Request Secondary PDP Context Activation Reject */
	dtap_sm_notif,              /* Notification */
	NULL,	/* NONE */
};

void get_gmm_msg_params(guint8 oct, const gchar **msg_str, int *ett_tree, int *hf_idx, msg_fcn *dtap_msg_fcn)
{
	gint			idx;

	*msg_str = match_strval_idx((guint32) (oct & DTAP_GMM_IEI_MASK), gsm_a_dtap_msg_gmm_strings, &idx);
	*ett_tree = ett_gsm_dtap_msg_gmm[idx];
	*hf_idx = hf_gsm_a_dtap_msg_gmm_type;
	*dtap_msg_fcn = dtap_msg_gmm_fcn[idx];

	return;
}

void get_sm_msg_params(guint8 oct, const gchar **msg_str, int *ett_tree, int *hf_idx, msg_fcn *dtap_msg_fcn)
{
	gint			idx;

	*msg_str = match_strval_idx((guint32) (oct & DTAP_SM_IEI_MASK), gsm_a_dtap_msg_sm_strings, &idx);
	*ett_tree = ett_gsm_dtap_msg_sm[idx];
	*hf_idx = hf_gsm_a_dtap_msg_sm_type;
	*dtap_msg_fcn = dtap_msg_sm_fcn[idx];

	return;
}

/* Register the protocol with Wireshark */
void
proto_register_gsm_a_gm(void)
{
	guint		i;
	guint		last_offset;

	/* Setup list of header fields */

	static hf_register_info hf[] =
	{
	{ &hf_gsm_a_dtap_msg_gmm_type,
		{ "DTAP GPRS Mobility Management Message Type",	"gsm_a.dtap_msg_gmm_type",
		  FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_msg_gmm_strings), 0x0,
		  NULL, HFILL }
	},
	{ &hf_gsm_a_dtap_msg_sm_type,
	  	{ "DTAP GPRS Session Management Message Type",	"gsm_a.dtap_msg_sm_type",
		  FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_msg_sm_strings), 0x0,
		  NULL, HFILL }
	},
	{ &hf_gsm_a_gm_elem_id,
		{ "Element ID",	"gsm_a_gm.elem_id",
		FT_UINT8, BASE_DEC, NULL, 0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_qos_delay_cls,
		{ "Quality of Service Delay class", "gsm_a.qos.delay_cls",
		  FT_UINT8, BASE_DEC, VALS(gsm_a_qos_delay_cls_vals), 0x38,
		  NULL, HFILL }
	},
	{ &hf_gsm_a_qos_reliability_cls,
		{ "Reliability class", "gsm_a.qos.delay_cls",
		  FT_UINT8, BASE_DEC, VALS(gsm_a_qos_delay_cls_vals), 0x07,
		  NULL, HFILL }
	},
	{ &hf_gsm_a_qos_traffic_cls,
	 	{ "Traffic class", "gsm_a.qos.traffic_cls",
		  FT_UINT8, BASE_DEC, VALS(gsm_a_qos_traffic_cls_vals), 0xe0,
		  NULL, HFILL }
	},
	{ &hf_gsm_a_qos_del_order,
	  	{ "Delivery order", "gsm_a.qos.del_order",
		  FT_UINT8, BASE_DEC, VALS(gsm_a_qos_del_order_vals), 0x18,
		  NULL, HFILL }
	},
	{ &hf_gsm_a_qos_del_of_err_sdu,
	  	{ "Delivery of erroneous SDUs", "gsm_a.qos.del_of_err_sdu",
		  FT_UINT8, BASE_DEC, VALS(gsm_a_qos_del_of_err_sdu_vals), 0x07,
		  NULL, HFILL }
	},
	{ &hf_gsm_a_qos_ber,
	  	{ "Residual Bit Error Rate (BER)", "gsm_a.qos.ber",
		  FT_UINT8, BASE_DEC, VALS(gsm_a_qos_ber_vals), 0xf0,
		  NULL, HFILL }
	},
	{ &hf_gsm_a_qos_sdu_err_rat,
	  	{ "SDU error ratio", "gsm_a.qos.sdu_err_rat",
		  FT_UINT8, BASE_DEC, VALS(gsm_a_qos_sdu_err_rat_vals), 0x0f,
		  NULL, HFILL }
	},
	{ &hf_gsm_a_qos_traff_hdl_pri,
	  	{ "Traffic handling priority", "gsm_a.qos.traff_hdl_pri",
		  FT_UINT8, BASE_DEC, VALS(gsm_a_qos_traff_hdl_pri_vals), 0x03,
		  NULL, HFILL }
	},
	{ &hf_gsm_a_gmm_split_on_ccch,
		{ "SPLIT on CCCH","gsm_a.gmm.split_on_ccch",
		  FT_BOOLEAN, 8, TFS(&gsm_a_gmm_split_on_ccch_value), 0x08,
		  NULL, HFILL }
	},
	{ &hf_gsm_a_gmm_non_drx_timer,
		{ "Non-DRX timer","gsm_a.gmm.non_drx_timer",
		  FT_UINT8, BASE_DEC, VALS(gsm_a_gmm_non_drx_timer_strings), 0x07,
		  NULL, HFILL }
	},
	{ &hf_gsm_a_gmm_cn_spec_drs_cycle_len_coef,
		{ "CN Specific DRX cycle length coefficient","gsm_a.gmm.cn_spec_drs_cycle_len_coef",
		  FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gsm_a_gmm_cn_spec_drs_cycle_len_coef_strings), 0xf0,
		  NULL, HFILL }
	},
	{ &hf_gsm_a_tft_op_code,
		{ "TFT operation code", "gsm_a.tft.op_code",
		  FT_UINT8, BASE_DEC, VALS(gsm_a_tft_op_code_vals), 0xe0,
		  NULL, HFILL }
	},
	{ &hf_gsm_a_tft_e_bit,
		{ "E bit","gsm_a.tft.e_bit",
		  FT_BOOLEAN, 8, TFS(&gsm_a_tft_e_bit), 0x10,
		  NULL, HFILL }
	},
	{ &hf_gsm_a_tft_pkt_flt,
		{ "Number of packet filters", "gsm_a.tft.pkt_flt",
		  FT_UINT8, BASE_DEC, NULL, 0x0f,
		  NULL, HFILL }
	},
	{ &hf_gsm_a_tft_pkt_flt_dir,
		{ "Packet filter direction", "gsm_a.tft.pkt_flt_dir",
		  FT_UINT8, BASE_DEC, VALS(gsm_a_tft_pkt_flt_dir_vals), 0x30,
		  NULL, HFILL }
	},
	{ &hf_gsm_a_tft_pkt_flt_id,
		{ "Packet filter identifier", "gsm_a.tft.pkt_flt_id",
		  FT_UINT8, BASE_DEC, NULL, 0x0f,
		  NULL, HFILL }
	},
	{ &hf_gsm_a_sm_ip4_address,
		{ "IPv4 address", "gsm_a.sm.ip4_address",
		  FT_IPv4, BASE_NONE, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_sm_ip4_mask,
		{ "IPv4 address mask", "gsm_a.sm.ip4_mask",
		  FT_IPv4, BASE_NONE, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_sm_ip6_address,
		{ "IPv6 address", "gsm_a.sm.ip6_address",
		  FT_IPv6, BASE_NONE, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_sm_ip6_mask,
		{ "IPv6 address mask", "gsm_a.sm.ip6_mask",
		  FT_IPv6, BASE_NONE, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_tft_protocol_header,
		{ "Protocol/header", "gsm_a.tft.protocol_header",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_tft_port,
		{ "Port", "gsm_a.tft.port",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_tft_port_low,
		{ "Low limit port", "gsm_a.tft.port_low",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_tft_port_high,
		{ "High limit port", "gsm_a.tft.port_high",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_tft_security,
		{ "IPSec security parameter index", "gsm_a.tft.security",
		  FT_UINT32, BASE_HEX, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_tft_traffic_mask,
		{ "Mask field", "gsm_a.tft.traffic_mask",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_tft_flow_label_type,
		{ "Flow Label Type", "gsm_a.tft.flow_label_type",
		  FT_UINT24, BASE_HEX, NULL, 0x0FFFFF,
		NULL, HFILL }
	},
	{ &hf_gsm_a_tft_param_id,
		{ "Parameter identifier", "gsm_a.tft.param_id",
		  FT_UINT8, BASE_DEC, VALS(gsm_a_tft_param_id_vals), 0x0,
		  NULL, HFILL }
	},
	{ &hf_gsm_a_ptmsi_sig,
		{ "P-TMSI Signature", "gsm_a.ptmsi_sig",
		  FT_UINT24, BASE_HEX, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_ptmsi_sig2,
		{ "P-TMSI Signature 2", "gsm_a.ptmsi_sig2",
		  FT_UINT24, BASE_HEX, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_acc_tech_type,
		{ "Access Technology Type", "gsm_a.gm.acc_tech_type",
		  FT_UINT8, BASE_DEC, VALS(gsm_a_gm_acc_tech_type_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_acc_cap_struct_len,
		{ "Length in bits", "gsm_a.gm.acc_cap_struct_len",
		  FT_UINT8, BASE_HEX_DEC,NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_sms_value,
		{ "SMS_VALUE (Switch-Measure-Switch)", "gsm_a.gm.sms",
		  FT_UINT8, BASE_DEC, VALS(gsm_a_sms_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_sm_value,
		{ "(SM_VALUE) Switch-Measure", "gsm_a.gm.sm",
		  FT_UINT8, BASE_DEC, VALS(gsm_a_sms_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_sm_ext,
		{ "Ext", "gsm_a.gm.sm.ext",
		  FT_UINT8, BASE_HEX, NULL, 0x80,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_link_dir,
		{ "Link direction", "gsm_a.gm.link_dir",
		  FT_INT32, BASE_DEC, VALS(gsm_a_gm_link_dir_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_cause,
		{ "gmm Cause", "gsm_a.gm.cause",
		  FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gmm_cause_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_fop,
		{ "Follow-on proceed", "gsm_a.gm.fop",
		FT_BOOLEAN, 8, NULL, 0x08,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_res_of_attach,
		{ "Result of attach", "gsm_a.gm.res_of_attach",
		FT_UINT8, BASE_DEC, VALS(gsm_a_gm_res_of_attach_vals), 0x07,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_type_of_ciph_alg,
		{ "Type of ciphering algorithm", "gsm_a.gm.type_of_ciph_alg",
		FT_UINT8, BASE_DEC, VALS(gsm_a_gm_type_of_ciph_alg_vals), 0x07,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_imeisv_req,
		{ "IMEISV request", "gsm_a.gm.imeisv_req",
		FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gsm_a_gm_imeisv_req_vals), 0x00,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_ac_ref_nr,
		{ "A&C reference number", "gsm_a.gm.ac_ref_nr",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_force_to_standby,
		{ "Force to standby", "gsm_a.gm.force_to_standby",
		FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gsm_a_gm_force_to_standby_vals), 0x00,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_ciph_key_seq_num,
		{ "Ciphering key sequence number", "gsm_a.gm.ciph_key_seq_num",
		FT_UINT8, BASE_DEC, NULL, 0x00,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_serv_type,
		{ "Service type", "gsm_a.gm.serv_type",
		FT_UINT8, BASE_DEC, VALS(gsm_a_gm_serv_type_vals), 0x00,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_for,
		{ "Follow-on request pending", "gsm_a.gm.for",
		FT_BOOLEAN, 8, NULL, 0x08,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_type_of_attach,
		{ "Type of attach", "gsm_a.gm.type_of_attach",
		FT_UINT8, BASE_DEC, VALS(gsm_a_gm_type_of_attach_vals), 0x07,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_tmsi_flag,
		{ "TMSI flag", "gsm_a.gm.tmsi_flag",
		FT_BOOLEAN, 8, TFS(&gsm_a_gm_tmsi_flag_value), 0x01,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_update_type,
		{ "Update type", "gsm_a.gm.update_type",
		FT_UINT8, BASE_DEC, VALS(gsm_a_gm_update_type_vals), 0x07,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_gprs_timer_unit,
		{ "Unit", "gsm_a.gm.gprs_timer_unit",
		FT_UINT8, BASE_DEC, VALS(gsm_a_gm_gprs_timer_unit_vals), 0xe0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_gprs_timer_value,
		{ "Timer value", "gsm_a.gm.gprs_timer_value",
		FT_UINT8, BASE_DEC, NULL, 0x1f,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_nsapi_5_ul_stat,
		{ "NSAPI(5) uplink status", "gsm_a.gm.nsapi_5_ul_stat",
		FT_BOOLEAN, 8, TFS(&gsm_a_gm_nsapi_ul_stat_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_nsapi_6_ul_stat,
		{ "NSAPI(6) uplink status", "gsm_a.gm.nsapi_6_ul_stat",
		FT_BOOLEAN, 8, TFS(&gsm_a_gm_nsapi_ul_stat_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_nsapi_7_ul_stat,
		{ "NSAPI(7) uplink status", "gsm_a.gm.nsapi_7_ul_stat",
		FT_BOOLEAN, 8, TFS(&gsm_a_gm_nsapi_ul_stat_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_nsapi_8_ul_stat,
		{ "NSAPI(8) uplink status", "gsm_a.gm.nsapi_8_ul_stat",
		FT_BOOLEAN, 8, TFS(&gsm_a_gm_nsapi_ul_stat_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_nsapi_9_ul_stat,
		{ "NSAPI(9) uplink status", "gsm_a.gm.nsapi_9_ul_stat",
		FT_BOOLEAN, 8, TFS(&gsm_a_gm_nsapi_ul_stat_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_nsapi_10_ul_stat,
		{ "NSAPI(10) uplink status", "gsm_a.gm.nsapi_10_ul_stat",
		FT_BOOLEAN, 8, TFS(&gsm_a_gm_nsapi_ul_stat_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_nsapi_11_ul_stat,
		{ "NSAPI(11) uplink status", "gsm_a.gm.nsapi_11_ul_stat",
		FT_BOOLEAN, 8, TFS(&gsm_a_gm_nsapi_ul_stat_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_nsapi_12_ul_stat,
		{ "NSAPI(12) uplink status", "gsm_a.gm.nsapi_12_ul_stat",
		FT_BOOLEAN, 8, TFS(&gsm_a_gm_nsapi_ul_stat_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_nsapi_13_ul_stat,
		{ "NSAPI(13) uplink status", "gsm_a.gm.nsapi_13_ul_stat",
		FT_BOOLEAN, 8, TFS(&gsm_a_gm_nsapi_ul_stat_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_nsapi_14_ul_stat,
		{ "NSAPI(14) uplink status", "gsm_a.gm.nsapi_14_ul_stat",
		FT_BOOLEAN, 8, TFS(&gsm_a_gm_nsapi_ul_stat_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_nsapi_15_ul_stat,
		{ "NSAPI(15) uplink status", "gsm_a.gm.nsapi_15_ul_stat",
		FT_BOOLEAN, 8, TFS(&gsm_a_gm_nsapi_ul_stat_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_pco_pid,
		{ "Protocol or Container ID", "gsm_a.gm.pco_pid",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_type_of_identity,
		{ "Type of identity", "gsm_a.gm.type_of_identity",
		FT_UINT8, BASE_DEC, VALS(gsm_a_gm_type_of_identity_vals), 0x07,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac,
		{ "Routing Area Code (RAC)","gsm_a.gm.rac",
		FT_UINT8, BASE_HEX_DEC, NULL, 0x00,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_apc,
		{ "APC","gsm_a.gm.apc",
		FT_BOOLEAN, 8, TFS(&gsm_a_gm_apc_vals), 0x20,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_otd_a,
		{ "OTD-A","gsm_a.gm.otd_a",
		FT_BOOLEAN, 8, TFS(&gsm_a_gm_otd_a_vals), 0x10,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_otd_b,
		{ "OTD-B","gsm_a.gm.otd_b",
		FT_BOOLEAN, 8, TFS(&gsm_a_gm_otd_b_vals), 0x08,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_gps_a,
		{ "GPS-A","gsm_a.gm.gps_a",
		FT_BOOLEAN, 8, TFS(&gsm_a_gm_gps_a_vals), 0x04,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_gps_b,
		{ "GPS-B","gsm_a.gm.gps_b",
		FT_BOOLEAN, 8, TFS(&gsm_a_gm_gps_b_vals), 0x02,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_gps_c,
		{ "GPS-C","gsm_a.gm.gps_c",
		FT_BOOLEAN, 8, TFS(&gsm_a_gm_gps_c_vals), 0x01,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_req_ms_info_irat,
		{ "I-RAT","gsm_a.gm.req_ms_info_irat",
		FT_BOOLEAN, 8, TFS(&gsm_a_gm_req_ms_info_irat_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_req_ms_info_irat2,
		{ "I-RAT2","gsm_a.gm.req_ms_info_irat2",
		FT_BOOLEAN, 8, TFS(&gsm_a_gm_req_ms_info_irat2_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_ue_usage_setting,
		{ "UE's usage setting","gsm_a.gm.ue_usage_setting",
		FT_BOOLEAN, 8, TFS(&gsm_a_gm_ue_usage_setting_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_voice_domain_pref_for_eutran,
		{ "Voice domain preference for E-UTRAN","gsm_a.gm.voice_domain_pref_for_eutran",
		FT_UINT8, BASE_DEC, VALS(gsm_a_gm_voice_domain_pref_for_eutran_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_sm_pdp_type_org,
		{ "PDP type organization", "gsm_a.sm.pdp_type_org",
		FT_UINT8, BASE_DEC, VALS(gsm_a_sm_pdp_type_org_vals), 0x0f,
		NULL, HFILL }
	},
	{ &hf_gsm_a_qos_mean_thr,
		{ "Mean throughput", "gsm_a.qos.mean_throughput",
		FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gsm_a_qos_mean_thr_vals), 0x1f,
		NULL, HFILL }
	},
	{ &hf_gsm_a_qos_peak_thr,
		{ "Peak throughput", "gsm_a.qos.peak_throughput",
		FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gsm_a_qos_peak_thr_vals), 0xf0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_qos_prec_class,
		{ "Precedence class", "gsm_a.qos.prec_class",
		FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gsm_a_qos_prec_class_vals), 0x07,
		NULL, HFILL }
	},
	{ &hf_gsm_a_qos_traf_handl_prio,
		{ "Traffic handling priority", "gsm_a.qos.traf_handl_prio",
		FT_UINT8, BASE_DEC, NULL, 0x03,
		NULL, HFILL }
	},
	{ &hf_gsm_a_qos_trans_delay,
		{ "Transfer delay", "gsm_a.qos.trans_delay",
		FT_UINT8, BASE_DEC, NULL, 0xfc,
		NULL, HFILL }
	},
	{ &hf_gsm_a_qos_signalling_ind,
		{ "Signalling indication", "gsm_a.qos.signalling_ind",
		FT_BOOLEAN, 8, TFS(&gsm_a_qos_signalling_ind_value), 0x10,
		NULL, HFILL }
	},
	{ &hf_gsm_a_qos_source_stat_desc,
		{ "Source statistics description", "gsm_a.qos.source_stat_desc",
		FT_UINT8, BASE_DEC, NULL, 0x0f,
		NULL, HFILL }
	},
	{ &hf_gsm_a_qos_max_bitrate_upl,
		{ "Maximum bitrate for uplink", "gsm_a.qos.max_bitrate_upl",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_qos_max_bitrate_downl,
		{ "Maximum bitrate for downlink", "gsm_a.qos.max_bitrate_downl",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_qos_guar_bitrate_upl,
		{ "Guaranteed bitrate for uplink", "gsm_a.qos.guar_bitrate_upl",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_qos_guar_bitrate_downl,
		{ "Guaranteed bitrate for downlink", "gsm_a.qos.guar_bitrate_downl",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_qos_max_bitrate_upl_ext,
		{ "Maximum bitrate for uplink (extended)", "gsm_a.qos.max_bitrate_upl_ext",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_qos_max_bitrate_downl_ext,
		{ "Maximum bitrate for downlink (extended)", "gsm_a.qos.max_bitrate_downl_ext",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_qos_guar_bitrate_upl_ext,
		{ "Guaranteed bitrate for uplink (extended)", "gsm_a.qos.guar_bitrate_upl_ext",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_qos_guar_bitrate_downl_ext,
		{ "Guaranteed bitrate for downlink (extended)", "gsm_a.qos.guar_bitrate_downl_ext",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_sm_cause,
		{ "SM Cause", "gsm_a.sm.cause",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_sm_cause_2,
		{ "SM Cause 2", "gsm_a.sm.cause_2",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_sm_llc_sapi,
		{ "LLC SAPI", "gsm_a.sm.llc_sapi",
		FT_UINT8, BASE_DEC, VALS(gsm_a_sm_llc_sapi_vals), 0x0f,
		NULL, HFILL }
	},
	{ &hf_gsm_a_sm_tdi,
		{ "Tear Down Indicator (TDI)", "gsm_a.sm.tdi",
		FT_BOOLEAN, 8, TFS(&gsm_a_sm_tdi_value), 0x01,
		NULL, HFILL }
	},
	{ &hf_gsm_a_sm_packet_flow_id,
		{ "Packet Flow Identifier (PFI)", "gsm_a.sm.packet_flow_id",
		FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gsm_a_sm_packet_flow_id_vals), 0x7f,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gmm_net_cap_gea1,
		{ "GEA/1", "gsm_a.gmm.net_cap.gea1",
		FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_gea_vals), 0x80,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gmm_net_cap_smdch,
		{ "SM capabilities via dedicated channels", "gsm_a.gmm.net_cap.smdch",
		FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_smdch_vals), 0x40,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gmm_net_cap_smgprs,
		{ "SM capabilities via GPRS channels", "gsm_a.gmm.net_cap.smgprs",
		FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_smgprs_vals), 0x20,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gmm_net_cap_ucs2,
		{ "UCS2 support", "gsm_a.gmm.net_cap.ucs2",
		FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_smgprs_vals), 0x10,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gmm_net_cap_ss_scr_ind,
		{ "SS Screening Indicator", "gsm_a.gmm.net_cap.ss_scr_ind",
		FT_UINT8, BASE_HEX, VALS(gsm_a_gmm_net_cap_ss_scr_ind_vals), 0x0c,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gmm_net_cap_solsa,
		{ "SoLSA Capability", "gsm_a.gmm.net_cap.solsa",
		FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_solsa_vals), 0x02,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gmm_net_cap_rev,
		{ "Revision level indicator", "gsm_a.gmm.net_cap.rev",
		FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_rev_vals), 0x01,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gmm_net_cap_pfc,
		{ "PFC feature mode", "gsm_a.gmm.net_cap.pfc",
		FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_pfc_vals), 0x80,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gmm_net_cap_ext_gea_bits,
		{ "Extended GEA bits", "gsm_a.gmm.net_cap.ext_gea_bits",
		FT_UINT8, BASE_HEX, NULL, 0x7e,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gmm_net_cap_gea2,
		{ "GEA/2", "gsm_a.gmm.net_cap.gea2",
		FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_gea_vals), 0x40,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gmm_net_cap_gea3,
		{ "GEA/3", "gsm_a.gmm.net_cap.gea3",
		FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_gea_vals), 0x20,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gmm_net_cap_gea4,
		{ "GEA/4", "gsm_a.gmm.net_cap.gea4",
		FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_gea_vals), 0x10,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gmm_net_cap_gea5,
		{ "GEA/5", "gsm_a.gmm.net_cap.gea5",
		FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_gea_vals), 0x08,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gmm_net_cap_gea6,
		{ "GEA/6", "gsm_a.gmm.net_cap.gea6",
		FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_gea_vals), 0x04,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gmm_net_cap_gea7,
		{ "GEA/7", "gsm_a.gmm.net_cap.gea7",
		FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_gea_vals), 0x02,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gmm_net_cap_lcs,
		{ "LCS VA capability", "gsm_a.gmm.net_cap.lcs",
		FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_lcs_vals), 0x01,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gmm_net_cap_ps_irat_iu,
		{ "PS inter-RAT HO to UTRAN Iu mode capability", "gsm_a.gmm.net_cap.ps_irat_iu",
		FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_ps_irat_iu_vals), 0x80,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gmm_net_cap_ps_irat_s1,
		{ "PS inter-RAT HO to E-UTRAN S1 mode capability", "gsm_a.gmm.net_cap.ps_irat_s1",
		FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_ps_irat_s1_vals), 0x40,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gmm_net_cap_comb_proc,
		{ "EMM Combined procedures capability", "gsm_a.gmm.net_cap.comb_proc",
		FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_comb_proc_vals), 0x20,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gmm_net_cap_isr,
		{ "ISR support", "gsm_a.gmm.net_cap.isr",
		FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_isr_vals), 0x10,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gmm_net_cap_srvcc_to_geran,
		{ "SRVCC to GERAN/UTRAN capability", "gsm_a.gmm.net_cap.srvcc_to_geran",
		FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_srvcc_to_geran_vals), 0x08,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gmm_net_cap_epc,
		{ "EPC Capability", "gsm_a.gmm.net_cap.epc",
		FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_epc_vals), 0x04,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gmm_net_cap_nf,
		{ "NF Capability", "gsm_a.gmm.net_cap.nf",
		FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_nf_vals), 0x02,
		NULL, HFILL }
	},
	{ &hf_gsm_a_sm_tmgi,
		{ "Temporary Mobile Group Identity (TMGI)", "gsm_a.sm.tmgi",
		  FT_UINT24, BASE_HEX, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_sm_enh_nsapi,
		{ "Enhanced NSAPI", "gsm_a.sm.enh_nsapi",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_sm_req_type,
		{ "Request type", "gsm_a.sm.req_type",
		  FT_UINT8, BASE_DEC, VALS(gsm_a_sm_req_type_vals), 0x07,
		NULL, HFILL }
	},
	{ &hf_gsm_a_sm_notif_ind,
		{ "Notification indicator value", "gsm_a.sm.notif_ind",
		  FT_UINT8, BASE_DEC, VALS(gsm_a_sm_notif_ind_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_ctrled_early_cm_sending,
		{ "Controlled early Classmark Sending", "gsm_a.gm.rac.comp_int_meas_cap",
		   FT_BOOLEAN, 8, TFS(&tfs_implemented_not_implemented), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_pseudo_sync,
		{ "Pseudo Synchronisation", "gsm_a.gm.rac.pseudo_sync",
		   FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_vgcs,
		{ "Voice Group Call Service", "gsm_a.gm.rac.vgcs",
		   FT_BOOLEAN, 8, TFS(&gsm_a_gm_vgcs), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_vbs,
		{ "Voice Broadcast Service", "gsm_a.gm.rac.vbs",
		   FT_BOOLEAN, 8, TFS(&gsm_a_gm_vbs), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_multislot_capability,
		{ "Multislot capability struct", "gsm_a.gm.rac.multislot_capability",
		   FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_hscsd_multi_slot_class,
		{ "HSCSD multislot class", "gsm_a.gm.rac.hscsd_multi_slot_class",
		   FT_UINT8, BASE_DEC, VALS(gsm_a_gm_multi_slot_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_gprs_multi_slot_class,
		{ "GPRS multislot class", "gsm_a.gm.rac.gprs_multi_slot_class",
		   FT_UINT8, BASE_DEC, VALS(gsm_a_gm_multi_slot_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_gprs_ext_dyn_alloc_cap,
		{ "GPRS Extended Dynamic Allocation Capability", "gsm_a.gm.rac.gprs_ext_dyn_alloc_cap",
		   FT_BOOLEAN, 8, TFS(&tfs_implemented_not_implemented), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_ecsd_multi_slot_class,
		{ "ECSD multislot class", "gsm_a.gm.rac.ecsd_multi_slot_class",
		   FT_UINT8, BASE_DEC, VALS(gsm_a_gm_multi_slot_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_egprs_multi_slot_class,
		{ "EGPRS multislot class", "gsm_a.gm.rac.egprs_multi_slot_class",
		   FT_UINT8, BASE_DEC, VALS(gsm_a_gm_multi_slot_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_egprs_ext_dyn_alloc_cap,
		{ "EGPRS Extended Dynamic Allocation Capability", "gsm_a.gm.rac.egprs_ext_dyn_alloc_cap",
		   FT_BOOLEAN, 8, TFS(&tfs_implemented_not_implemented), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_dtm_gprs_multi_slot_class,
		{ "DTM GPRS Multi Slot Class", "gsm_a.gm.rac.dtm_gprs_multi_slot_class",
		   FT_UINT8, BASE_DEC, VALS(gsm_a_gm_dtm_gprs_multi_slot_class_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_single_slt_dtm,
		{ "Single Slot DTM", "gsm_a.gm.rac.single_slt_dtm",
		   FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_dtm_egprs_multi_slot_cls_pres,
		{ "DTM EGPRS Multi Slot Class", "gsm_a.gm.rac.dtm_egprs_multi_slot_cls_pres",
		   FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_dtm_egprs_multi_slot_class,
		{ "DTM EGPRS Multi Slot Class", "gsm_a.gm.rac.dtm_egprs_multi_slot_class",
		   FT_UINT8, BASE_DEC, VALS(gsm_a_gm_dtm_gprs_multi_slot_class_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_8psk_pow_cap_pres,
		{ "8PSK Power Capability Bits", "gsm_a.gm.rac.8psk_pow_cap_pres",
		   FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_comp_int_meas_cap,
		{ "COMPACT Interference Measurement Capability", "gsm_a.gm.rac.comp_int_meas_cap",
		   FT_BOOLEAN, 8, TFS(&tfs_implemented_not_implemented), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rel_lev_ind,
		{ "Revision Level Indicator", "gsm_a.gm.rel_lev_ind",
		   FT_BOOLEAN, 8, TFS(&gsm_a_gm_revision_level_indicator), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_umts_fdd_cap,
		{ "UMTS FDD Radio Access Technology Capability", "gsm_a.gm.rac.umts_fdd_cap",
		   FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_umts_384_tdd_ra_cap,
		{ "UMTS 3.84 Mcps TDD Radio Access Technology Capability", "gsm_a.gm.rac.umts_384_tdd_ra_cap",
		   FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_cdma2000_cap,
		{ "CDMA 2000 Radio Access Technology Capability", "gsm_a.gm.rac.cdma2000_cap",
		   FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_umts_128_tdd_ra_cap,
		{ "UMTS 1.28 Mcps TDD Radio Access Technology Capability", "gsm_a.gm.rac.umts_128_tdd_ra_cap",
		   FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_geran_feat_pkg,
		{ "GERAN Feature Package 1", "gsm_a.gm.rac.geran_feat_pkg",
		   FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_mod_based_multi_slot_class_support,
		{ "Modulation based multislot class support", "gsm_a.gm.rac.mod_based_multi_slot_class_support",
		   FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_geran_iu_mode_cap,
		{ "GERAN Iu mode", "gsm_a.gm.rac.geran_iu_mode_cap",
		   FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_flo_iu_cap,
		{ "FLO Iu Capability", "gsm_a.gm.rac.flo_iu_cap",
		   FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_mult_tbf_cap,
		{ "Multiple TBF Capability", "gsm_a.gm.rac.mult_tbf_cap",
		   FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_down_adv_rec_perf,
		{ "Downlink Advanced Receiver Performance", "gsm_a.gm.rac.down_adv_rec_perf",
		   FT_UINT8, BASE_DEC, VALS(gsm_a_gm_down_adv_rec_perf_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_ext_rlc_mac_ctrl_msg_seg_cap,
		{ "Extended RLC/MAC Control Message Segmentation Capability", "gsm_a.gm.rac.ext_rlc_mac_ctrl_msg_seg_cap",
		   FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_dtm_enh_cap,
		{ "DTM Enhancements Capability", "gsm_a.gm.rac.dtm_enh_cap",
		   FT_BOOLEAN, 8, TFS(&gsm_a_gm_dtm_enh_cap), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_dtm_gprs_high_multi_slot_class,
		{ "DTM GPRS High Multi Slot Class", "gsm_a.gm.rac.dtm_gprs_high_multi_slot_class",
		   FT_UINT8, BASE_DEC, VALS(gsm_a_gm_dtm_gprs_high_multi_slot_class_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_dtm_egprs_high_multi_slot_class,
		{ "DTM EGPRS High Multi Slot Class", "gsm_a.gm.rac.dtm_egprs_high_multi_slot_class",
		   FT_UINT8, BASE_DEC, VALS(gsm_a_gm_dtm_gprs_high_multi_slot_class_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_ps_ho_cap,
		{ "PS Handover Capability", "gsm_a.gm.rac.ps_ho_cap",
		   FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_dtm_ho_cap,
		{ "DTM Handover Capability", "gsm_a.gm.rac.dtm_ho_cap",
		   FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_multi_slot_cap_red_down_dual_carrier,
		{ "Multislot Capability Reduction for Downlink Dual Carrier", "gsm_a.gm.rac.multi_slot_cap_red_down_dual_carrier",
		   FT_UINT8, BASE_DEC, VALS(gsm_a_gm_multi_slot_cap_red_down_dual_carrier_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_down_dual_carrier_dtm_cap,
		{ "Downlink Dual Carrier for DTM Capability", "gsm_a.gm.rac.down_dual_carrier_dtm_cap",
		   FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_flex_ts_assign,
		{ "Flexible Timeslot Assignment", "gsm_a.gm.rac.flex_ts_assign",
		   FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_gan_ps_ho_cap,
		{ "GAN PS Handover Capability", "gsm_a.gm.rac.gan_ps_ho_cap",
		   FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_rlc_non_pers_mode,
		{ "RLC Non-persistent Mode", "gsm_a.gm.rac.rlc_non_pers_mode",
		   FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_reduced_lat_cap,
		{ "Reduced Latency Capability", "gsm_a.gm.rac.reduced_lat_cap",
		   FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_ul_egprs2,
		{ "Uplink EGPRS2", "gsm_a.gm.rac.ul_egprs2",
		   FT_UINT8, BASE_DEC, VALS(gsm_a_gm_ul_egprs2_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_dl_egprs2,
		{ "Downlink EGPRS2", "gsm_a.gm.rac.dl_egprs2",
		   FT_UINT8, BASE_DEC, VALS(gsm_a_gm_dl_egprs2_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_eutra_fdd_support,
		{ "E-UTRA FDD support", "gsm_a.gm.rac.eutra_fdd_support",
		   FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_eutra_tdd_support,
		{ "E-UTRA TDD support", "gsm_a.gm.rac.eutra_tdd_support",
		   FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_geran_to_eutra_support_in_geran_ptm,
		{ "GERAN to E-UTRA support in GERAN packet transfer mode", "gsm_a.gm.rac.geran_to_eutra_support_in_geran_ptm",
		   FT_UINT8, BASE_DEC, VALS(gsm_a_gm_geran_to_eutra_support_in_geran_ptm_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_prio_based_resel_support,
		{ "Priority-based reselection support", "gsm_a.gm.rac.prio_based_resel_support",
		   FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_alt_efta_multi_slot_class,
		{ "Alternative EFTA Multislot Class", "gsm_a.gm.rac.alt_efta_multi_slot_class",
		   FT_UINT8, BASE_DEC, VALS(gsm_a_gm_alt_efta_multi_slot_class_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_efta_multi_slot_cap_red_down_dual_carrier,
		{ "EFTA Multislot Capability Reduction for Downlink Dual Carrier", "gsm_a.gm.rac.efta_multi_slot_cap_red_down_dual_carrier",
		   FT_UINT8, BASE_DEC, VALS(gsm_a_gm_multi_slot_cap_red_down_dual_carrier_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_ind_up_layer_pdu_start_cap_for_rlc_um,
		{ "Indication of Upper Layer PDU Start Capability for RLC UM", "gsm_a.gm.rac.ind_up_layer_pdu_start_cap_for_rlc_um",
		   FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_emst_cap,
		{ "Enhanced Multiplexing for Single TBF Capability", "gsm_a.gm.rac.emst_cap",
		   FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_mtti_cap,
		{ "Multiple TTI Capability", "gsm_a.gm.rac.mtti_cap",
		   FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_utra_csg_cell_report,
		{ "UTRA CSG Cells Reporting", "gsm_a.gm.rac.utra_csg_cell_report",
		   FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x0,
		NULL, HFILL }
	},
	{ &hf_gsm_a_gm_rac_eutra_csg_cell_report,
		{ "E-UTRA CSG Cells Reporting", "gsm_a.gm.rac.mtti_cap",
		   FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x0,
		NULL, HFILL }
	},
	};

	/* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_ELEMS	18
	gint *ett[NUM_INDIVIDUAL_ELEMS +
		  NUM_GSM_DTAP_MSG_GMM + NUM_GSM_DTAP_MSG_SM +
		  NUM_GSM_GM_ELEM];

	ett[0]  = &ett_tc_component;
	ett[1]  = &ett_tc_invoke_id;
	ett[2]  = &ett_tc_linked_id;
	ett[3]  = &ett_tc_opr_code;
	ett[4]  = &ett_tc_err_code;
	ett[5]  = &ett_tc_prob_code;
	ett[6]  = &ett_tc_sequence;
	ett[7]  = &ett_gmm_drx;
	ett[8]  = &ett_gmm_detach_type;
	ett[9]  = &ett_gmm_attach_type;
	ett[10] = &ett_gmm_context_stat;
	ett[11] = &ett_gmm_update_type;
	ett[12] = &ett_gmm_radio_cap;
	ett[13] = &ett_gmm_rai;
	ett[14] = &ett_sm_tft;
	ett[15] = &ett_gmm_gprs_timer;
	ett[16] = &ett_gmm_network_cap;
	ett[17] = &ett_gsm_a_gm_msrac_multislot_capability;

	last_offset = NUM_INDIVIDUAL_ELEMS;

	for (i=0; i < NUM_GSM_DTAP_MSG_GMM; i++, last_offset++)
	{
		ett_gsm_dtap_msg_gmm[i] = -1;
		ett[last_offset] = &ett_gsm_dtap_msg_gmm[i];
	}

	for (i=0; i < NUM_GSM_DTAP_MSG_SM; i++, last_offset++)
	{
		ett_gsm_dtap_msg_sm[i] = -1;
		ett[last_offset] = &ett_gsm_dtap_msg_sm[i];
	}

	for (i=0; i < NUM_GSM_GM_ELEM; i++, last_offset++)
	{
		ett_gsm_gm_elem[i] = -1;
		ett[last_offset] = &ett_gsm_gm_elem[i];
	}

	proto_a_gm =
		proto_register_protocol("GSM A-I/F GPRS Mobility and Session Management", "GSM Management", "gsm_a_gm");

	proto_register_field_array(proto_a_gm, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));

	/* subdissector code */
	gprs_sm_pco_subdissector_table = register_dissector_table("sm_pco.protocol",
		"GPRS SM PCO PPP protocol", FT_UINT16, BASE_HEX);
}

void
proto_reg_handoff_gsm_a_gm(void)
{
	data_handle = find_dissector("data");
	rrc_irat_ho_info_handle = find_dissector("rrc.irat.irat_ho_info");
	lte_rrc_ue_eutra_cap_handle = find_dissector("lte-rrc.ue_eutra_cap");
}
