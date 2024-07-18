/* packet-gsm_a_gm.c
 * Routines for GSM A Interface GPRS Mobility Management and GPRS Session Management
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * Added the GPRS Mobility Management Protocol and
 * the GPRS Session Management Protocol
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
 *   Reference [10]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 10.6.1 Release 10)
 *
 *   Reference [11]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 11.7.0 Release 11)
 *
 *   Reference [12]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 12.10.0 Release 12)
 *
 *   Reference [13]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 13.8.0 Release 13)
 *
 *   Reference [14]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 14.6.0 Release 14)
 *
 *   Reference [15]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 15.6.0 Release 15)
 *
 *   Reference [16]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 16.6.0 Release 16)
 *
 *   Reference [17]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 17.8.0 Release 17)
 *
 *   Reference [18]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 18.6.0 Release 18)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"


#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/ipproto.h>
#include <epan/etypes.h>
#include "packet-ber.h"
#include "packet-gsm_a_common.h"
#include "packet-e212.h"
#include "packet-ppp.h"
#include "packet-e164.h"

void proto_register_gsm_a_gm(void);
void proto_reg_handoff_gsm_a_gm(void);

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
	{ 0x15,	"Identity Request" },
	{ 0x16,	"Identity Response" },
	{ 0x1c,	"Authentication and Ciphering Failure" },
	{ 0x20,	"GMM Status" },
	{ 0x21,	"GMM Information" },
	{ 0, NULL }
};
static value_string_ext gsm_a_dtap_msg_gmm_strings_ext = VALUE_STRING_EXT_INIT(gsm_a_dtap_msg_gmm_strings);


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
static value_string_ext gsm_a_dtap_msg_sm_strings_ext = VALUE_STRING_EXT_INIT(gsm_a_dtap_msg_sm_strings);


static const value_string gsm_gm_elem_strings[] = {
	/* GPRS Mobility Management Information Elements 10.5.5 */
	{ DE_ADD_UPD_TYPE,		 "Additional Update Type" },
	{ DE_ATTACH_RES,		 "Attach Result" },
	{ DE_ATTACH_TYPE,		 "Attach Type" },
	{ DE_CIPH_ALG,			 "Ciphering Algorithm" },
	{ DE_INTEG_ALG, 		 "Integrity Algorithm" },
	{ DE_TMSI_STAT,			 "TMSI Status" },
	{ DE_DETACH_TYPE,		 "Detach Type" },
	{ DE_DRX_PARAM,			 "DRX Parameter" },
	{ DE_FORCE_TO_STAND,		 "Force to Standby" },
	{ DE_FORCE_TO_STAND_H,		 "Force to Standby" },
	{ DE_P_TMSI_SIG,		 "P-TMSI Signature" },
	{ DE_P_TMSI_SIG_2,		 "P-TMSI Signature 2" },
	{ DE_ID_TYPE_2,			 "Identity Type 2" },
	{ DE_IMEISV_REQ,		 "IMEISV Request" },
	{ DE_REC_N_PDU_NUM_LIST,	 "Receive N-PDU Numbers List" },
	{ DE_MS_NET_CAP,		 "MS Network Capability" },
	{ DE_MS_RAD_ACC_CAP,		 "MS Radio Access Capability" },
	{ DE_GMM_CAUSE,			 "GMM Cause" },
	{ DE_RAI,			 "Routing Area Identification" },
	{ DE_RAI_2,			 "Routing Area Identification 2" },
	{ DE_UPD_RES,			 "Update Result" },
	{ DE_UPD_TYPE,			 "Update Type" },
	{ DE_AC_REF_NUM,		 "A&C Reference Number" },
	{ DE_AC_REF_NUM_H,		 "A&C Reference Number" },
	{ DE_SRVC_TYPE,			 "Service Type" },
	{ DE_CELL_NOT,			 "Cell Notification" },
	{ DE_PS_LCS_CAP,		 "PS LCS Capability" },
	{ DE_NET_FEAT_SUP,		 "Network Feature Support" },
	{ DE_ADD_NET_FEAT_SUP,		 "Additional Network Feature Support" },
	{ DE_RAT_INFO_CONTAINER,	 "Inter RAT Information Container" },
	{ DE_REQ_MS_INFO,		 "Requested MS Information" },
	{ DE_UE_NETWORK_CAP,		 "UE Network Capability" },
	{ DE_EUTRAN_IRAT_INFO_CONTAINER, "E-UTRAN Inter RAT Information Container" },
	{ DE_VOICE_DOMAIN_PREF,		 "Voice Domain Preference and UE's Usage Setting" },
	{ DE_PTMSI_TYPE,		 "P-TMSI Type" },
	{ DE_LAI_2,			 "Location Area Identification 2" },
	{ DE_NET_RES_ID_CONT,		 "Network Resource Identifier Container" },
	{ DE_EXT_DRX_PARAMS,		 "Extended DRX Parameters" },
	{ DE_MAC,			 "Message Authentication Code" },
	{ DE_UP_INTEG_IND,		 "User Plane Integrity Indicator" },
	{ DE_DCN_ID, 			 "DCN-ID"},
	{ DE_PLMN_ID_CN_OPERATOR,	 "PLMN identity of the CN operator"},
	{ DE_NON_3GPP_NW_PROV_POL, 	 "Non-3GPP NW provided policies"},
	/* Session Management Information Elements 10.5.6 */
	{ DE_ACC_POINT_NAME,		 "Access Point Name" },
	{ DE_NET_SAPI,			 "Network Service Access Point Identifier" },
	{ DE_PRO_CONF_OPT,		 "Protocol Configuration Options" },
	{ DE_EXT_PRO_CONF_OPT,		 "Extended Protocol Configuration Options" },
	{ DE_PD_PRO_ADDR,		 "Packet Data Protocol Address" },
	{ DE_QOS,			 "Quality Of Service" },
	{ DE_RE_ATTEMPT_IND,		 "Re-attempt Indicator" },
	{ DE_EXT_QOS,			 "Extended Quality Of Service" },
	{ DE_SM_CAUSE,			 "SM Cause" },
	{ DE_SM_CAUSE_2,		 "SM Cause 2" },
	{ DE_LINKED_TI,			 "Linked TI" },
	{ DE_LLC_SAPI,			 "LLC Service Access Point Identifier" },
	{ DE_TEAR_DOWN_IND,		 "Tear Down Indicator" },
	{ DE_PACKET_FLOW_ID,		 "Packet Flow Identifier" },
	{ DE_TRAFFIC_FLOW_TEMPLATE,	 "Traffic Flow Template" },
	{ DE_TMGI,			 "Temporary Mobile Group Identity (TMGI)" },
	{ DE_MBMS_BEARER_CAP,		 "MBMS bearer capabilities" },
	{ DE_MBMS_PROT_CONF_OPT,	 "MBMS protocol configuration options" },
	{ DE_ENH_NSAPI,			 "Enhanced network service access point identifier" },
	{ DE_REQ_TYPE,			 "Request type" },
	{ DE_SM_NOTIF_IND,		 "Notification indicator" },
	{ DE_SM_CONNECTIVITY_TYPE,	 "Connectivity type" },
	{ DE_SM_WLAN_OFFLOAD_ACCEPT,	 "WLAN offload acceptability" },
	{ DE_NBIFOM_CONT,		 "NBIFOM container" },
	/* GPRS Common Information Elements 10.5.7 */
	{ DE_PDP_CONTEXT_STAT,		 "PDP Context Status" },
	{ DE_RAD_PRIO,			 "Radio Priority" },
	{ DE_GPRS_TIMER,		 "GPRS Timer" },
	{ DE_GPRS_TIMER_2,		 "GPRS Timer 2" },
	{ DE_GPRS_TIMER_3,		 "GPRS Timer 3" },
	{ DE_RAD_PRIO_2,		 "Radio Priority 2"},
	{ DE_MBMS_CTX_STATUS,		 "MBMS context status"},
	{ DE_UPLINK_DATA_STATUS,	 "Uplink data status"},
	{ DE_DEVICE_PROPERTIES,		 "Device properties"},
	{ 0, NULL }
};
value_string_ext gsm_gm_elem_strings_ext = VALUE_STRING_EXT_INIT(gsm_gm_elem_strings);

#define	DTAP_GMM_IEI_MASK	0xff
#define	DTAP_SM_IEI_MASK	0xff

/* Initialize the protocol and registered fields */
static int proto_a_gm;

static int hf_gsm_a_dtap_msg_gmm_type;
static int hf_gsm_a_dtap_msg_sm_type;
int hf_gsm_a_gm_elem_id;
static int hf_gsm_a_sm_qos_delay_cls;
static int hf_gsm_a_sm_qos_reliability_cls;
static int hf_gsm_a_sm_qos_traffic_cls;
static int hf_gsm_a_sm_qos_del_order;
static int hf_gsm_a_sm_qos_del_of_err_sdu;
static int hf_gsm_a_sm_qos_ber;
static int hf_gsm_a_sm_qos_sdu_err_rat;
static int hf_gsm_a_sm_qos_traff_hdl_pri;

static int hf_gsm_a_gmm_split_pg_cycle_code;
static int hf_gsm_a_gmm_split_on_ccch;
static int hf_gsm_a_gmm_non_drx_timer;
static int hf_gsm_a_gmm_cn_spec_drx_cycle_len_coef;

static int hf_gsm_a_gmm_ptmsi_sig;
static int hf_gsm_a_gmm_ptmsi_sig2;

static int hf_gsm_a_sm_tft_op_code;
static int hf_gsm_a_sm_tft_e_bit;
static int hf_gsm_a_sm_tft_pkt_flt;
static int hf_gsm_a_sm_tft_pkt_flt_id;
static int hf_gsm_a_sm_tft_pkt_flt_dir;
static int hf_gsm_a_sm_ip4_address;
static int hf_gsm_a_sm_ip4_mask;
static int hf_gsm_a_sm_ip6_address;
static int hf_gsm_a_sm_ip6_mask;
static int hf_gsm_a_sm_ip6_prefix_length;
static int hf_gsm_a_sm_tft_protocol_header;
static int hf_gsm_a_sm_tft_port;
static int hf_gsm_a_sm_tft_port_low;
static int hf_gsm_a_sm_tft_port_high;
static int hf_gsm_a_sm_tft_security;
static int hf_gsm_a_sm_tft_traffic_class;
static int hf_gsm_a_sm_tft_traffic_mask;
static int hf_gsm_a_sm_tft_flow_label_type;
static int hf_gsm_a_sm_tft_param_id;
static int hf_gsm_a_sm_tft_packet_filter;
static int hf_gsm_a_sm_tft_packet_evaluation_precedence;
static int hf_gsm_a_sm_tft_packet_filter_length;
static int hf_gsm_a_sm_tft_authorization_token_value;
static int hf_gsm_a_sm_tft_media_component_number_value;
static int hf_gsm_a_sm_tft_ip_flow_number;
static int hf_gsm_a_sm_tft_packet_filter_identifier;
static int hf_gsm_a_sm_tft_parameter_content;
static int hf_gsm_a_sm_tft_packet_filter_component_type_id;
static int hf_gsm_a_sm_tft_mac_addr;
static int hf_gsm_a_sm_tft_vlan_tag_vid;
static int hf_gsm_a_sm_tft_vlan_tag_pcp;
static int hf_gsm_a_sm_tft_vlan_tag_dei;
static int hf_gsm_a_sm_tft_ethertype;
static int hf_gsm_a_gm_acc_tech_type;
static int hf_gsm_a_gm_acc_cap_struct_len;
static int hf_gsm_a_gm_sms_value;
static int hf_gsm_a_gm_sm_value;
static int hf_gsm_a_gm_link_dir;
static int hf_gsm_a_gm_cause;

static int hf_gsm_a_gm_add_upd_type;
static int hf_gsm_a_gm_fop;
static int hf_gsm_a_gm_res_of_attach;
static int hf_gsm_a_gm_type_of_ciph_alg;
static int hf_gsm_a_gm_type_of_integ_alg;
static int hf_gsm_a_gm_imeisv_req;
static int hf_gsm_a_gm_nsapi;
static int hf_gsm_a_gm_ac_ref_nr;
static int hf_gsm_a_gm_force_to_standby;
static int hf_gsm_a_gm_serv_type;
static int hf_gsm_a_gm_for;
static int hf_gsm_a_gm_type_of_attach;
static int hf_gsm_a_gm_tmsi_flag;
static int hf_gsm_a_gm_power_off;
static int hf_gsm_a_gm_type_of_detach_mo;
static int hf_gsm_a_gm_type_of_detach_mt;
static int hf_gsm_a_gm_update_type;
static int hf_gsm_a_gm_gprs_timer;
static int hf_gsm_a_gm_gprs_timer_unit;
static int hf_gsm_a_gm_gprs_timer_value;
static int hf_gsm_a_gm_gprs_timer2;
static int hf_gsm_a_gm_gprs_timer2_unit;
static int hf_gsm_a_gm_gprs_timer2_value;
static int hf_gsm_a_gm_gprs_timer3;
static int hf_gsm_a_gm_gprs_timer3_unit;
static int hf_gsm_a_gm_gprs_timer3_value;
static int hf_gsm_a_gm_nsapi_5_ul_stat;
static int hf_gsm_a_gm_nsapi_6_ul_stat;
static int hf_gsm_a_gm_nsapi_7_ul_stat;
static int hf_gsm_a_gm_nsapi_8_ul_stat;
static int hf_gsm_a_gm_nsapi_9_ul_stat;
static int hf_gsm_a_gm_nsapi_10_ul_stat;
static int hf_gsm_a_gm_nsapi_11_ul_stat;
static int hf_gsm_a_gm_nsapi_12_ul_stat;
static int hf_gsm_a_gm_nsapi_13_ul_stat;
static int hf_gsm_a_gm_nsapi_14_ul_stat;
static int hf_gsm_a_gm_nsapi_15_ul_stat;
static int hf_gsm_a_gm_device_prop_low_prio;
static int hf_gsm_a_gm_apn;
static int hf_gsm_a_gm_pco_pid;
static int hf_gsm_a_gm_pco_app_spec_info;
static int hf_gsm_a_gm_type_of_identity;
int hf_gsm_a_gm_rac;
static int hf_gsm_a_gm_mta_e;
static int hf_gsm_a_gm_mta_r;
static int hf_gsm_a_gm_apc;
static int hf_gsm_a_gm_otd_a;
static int hf_gsm_a_gm_otd_b;
static int hf_gsm_a_gm_gps_a;
static int hf_gsm_a_gm_gps_b;
static int hf_gsm_a_gm_gps_c;
static int hf_gsm_a_gm_motd;
static int hf_gsm_a_gm_mta_a;
static int hf_gsm_a_gm_lcs_molr;
static int hf_gsm_a_gm_mbms;
static int hf_gsm_a_gm_ims_vops;
static int hf_gsm_a_gm_emc_bs;
static int hf_gsm_a_gm_epco;
static int hf_gsm_a_gm_restrict_ec;
static int hf_gsm_a_gm_gprs_sms;
static int hf_gsm_a_gm_req_ms_info_irat;
static int hf_gsm_a_gm_req_ms_info_irat2;
static int hf_gsm_a_gm_ue_usage_setting;
static int hf_gsm_a_gm_voice_domain_pref_for_eutran;
static int hf_gsm_a_gm_ptmsi_type;
static int hf_gsm_a_gm_nri_cont;
static int hf_gsm_a_gm_paging_time_window;
static int hf_gsm_a_gm_edrx_value;
static int hf_gsm_a_gm_ext_paging_time_window;
static int hf_gsm_a_gm_mac;
static int hf_gsm_a_gm_up_integ_ind;
static int hf_gsm_a_gm_dcn_id;
static int hf_gsm_a_gm_n3en_ind;
static int hf_gsm_a_sm_pdp_type_org;
static int hf_gsm_a_sm_qos_mean_thr;
static int hf_gsm_a_sm_qos_peak_thr;
static int hf_gsm_a_sm_qos_prec_class;
static int hf_gsm_a_sm_qos_trans_delay;
static int hf_gsm_a_sm_qos_signalling_ind;
static int hf_gsm_a_sm_qos_source_stat_desc;
static int hf_gsm_a_sm_qos_max_bitrate_upl;
static int hf_gsm_a_sm_qos_max_bitrate_downl;
static int hf_gsm_a_sm_qos_guar_bitrate_upl;
static int hf_gsm_a_sm_qos_guar_bitrate_downl;
static int hf_gsm_a_sm_qos_max_bitrate_upl_ext;
static int hf_gsm_a_sm_qos_max_bitrate_downl_ext;
static int hf_gsm_a_sm_qos_guar_bitrate_upl_ext;
static int hf_gsm_a_sm_qos_guar_bitrate_downl_ext;
static int hf_gsm_a_sm_qos_max_bitrate_upl_ext2;
static int hf_gsm_a_sm_qos_max_bitrate_downl_ext2;
static int hf_gsm_a_sm_qos_guar_bitrate_upl_ext2;
static int hf_gsm_a_sm_qos_guar_bitrate_downl_ext2;
static int hf_gsm_a_sm_qos_maximum_sdu_size;
static int hf_gsm_a_sm_eplmnc;
static int hf_gsm_a_sm_ratc;
static int hf_gsm_a_sm_cause;
static int hf_gsm_a_sm_cause_2;
static int hf_gsm_a_sm_llc_sapi;
static int hf_gsm_a_sm_tdi;
static int hf_gsm_a_sm_packet_flow_id;
static int hf_gsm_a_sm_tmgi;
static int hf_gsm_a_sm_enh_nsapi;
static int hf_gsm_a_sm_req_type;
static int hf_gsm_a_sm_notif_ind;
static int hf_gsm_a_sm_connectivity_type;
static int hf_gsm_a_sm_wlan_utran_offload_accept;
static int hf_gsm_a_sm_wlan_eutran_offload_accept;
static int hf_gsm_a_sm_nbifom_cont;
static int hf_gsm_a_gm_rac_ctrled_early_cm_sending;
static int hf_gsm_a_gm_rac_pseudo_sync;
static int hf_gsm_a_gm_rac_vgcs;
static int hf_gsm_a_gm_rac_vbs;
static int hf_gsm_a_gm_rac_multislot_capability;
static int hf_gsm_a_gm_rac_hscsd_multi_slot_class;
static int hf_gsm_a_gm_rac_gprs_multi_slot_class;
static int hf_gsm_a_gm_rac_gprs_ext_dyn_alloc_cap;
static int hf_gsm_a_gm_rac_ecsd_multi_slot_class;
static int hf_gsm_a_gm_rac_egprs_multi_slot_class;
static int hf_gsm_a_gm_rac_egprs_ext_dyn_alloc_cap;
static int hf_gsm_a_gm_rac_dtm_gprs_multi_slot_class;
static int hf_gsm_a_gm_rac_single_slt_dtm;
static int hf_gsm_a_gm_rac_dtm_egprs_multi_slot_cls_pres;
static int hf_gsm_a_gm_rac_dtm_egprs_multi_slot_class;
static int hf_gsm_a_gm_rac_8psk_pow_cap_pres;
static int hf_gsm_a_gm_rac_comp_int_meas_cap;
static int hf_gsm_a_gm_rel_lev_ind;
static int hf_gsm_a_gm_rac_geran_feat_pkg;
static int hf_gsm_a_gm_rac_umts_fdd_cap;
static int hf_gsm_a_gm_rac_umts_384_tdd_ra_cap;
static int hf_gsm_a_gm_rac_cdma2000_cap;
static int hf_gsm_a_gm_rac_umts_128_tdd_ra_cap;
static int hf_gsm_a_gm_rac_mod_based_multi_slot_class_support;
static int hf_gsm_a_gm_rac_geran_iu_mode_cap;
static int hf_gsm_a_gm_rac_flo_iu_cap;
static int hf_gsm_a_gm_rac_mult_tbf_cap;
static int hf_gsm_a_gm_rac_down_adv_rec_perf;
static int hf_gsm_a_gm_rac_ext_rlc_mac_ctrl_msg_seg_cap;
static int hf_gsm_a_gm_rac_dtm_enh_cap;
static int hf_gsm_a_gm_rac_dtm_gprs_high_multi_slot_class;
static int hf_gsm_a_gm_rac_dtm_egprs_high_multi_slot_class;
static int hf_gsm_a_gm_rac_ps_ho_cap;
static int hf_gsm_a_gm_rac_dtm_ho_cap;
static int hf_gsm_a_gm_rac_multi_slot_cap_red_down_dual_carrier;
static int hf_gsm_a_gm_rac_down_dual_carrier_dtm_cap;
static int hf_gsm_a_gm_rac_flex_ts_assign;
static int hf_gsm_a_gm_rac_gan_ps_ho_cap;
static int hf_gsm_a_gm_rac_rlc_non_pers_mode;
static int hf_gsm_a_gm_rac_reduced_lat_cap;
static int hf_gsm_a_gm_rac_ul_egprs2;
static int hf_gsm_a_gm_rac_dl_egprs2;
static int hf_gsm_a_gm_rac_eutra_fdd_support;
static int hf_gsm_a_gm_rac_eutra_tdd_support;
static int hf_gsm_a_gm_rac_geran_to_eutra_support_in_geran_ptm;
static int hf_gsm_a_gm_rac_prio_based_resel_support;
static int hf_gsm_a_gm_rac_alt_efta_multi_slot_class;
static int hf_gsm_a_gm_rac_efta_multi_slot_cap_red_down_dual_carrier;
static int hf_gsm_a_gm_rac_ind_up_layer_pdu_start_cap_for_rlc_um;
static int hf_gsm_a_gm_rac_emst_cap;
static int hf_gsm_a_gm_rac_mtti_cap;
static int hf_gsm_a_gm_rac_utra_csg_cell_report;
static int hf_gsm_a_gm_rac_eutra_csg_cell_report;
static int hf_gsm_a_gm_rac_dtr_cap;
static int hf_gsm_a_gm_rac_emsr_cap;
static int hf_gsm_a_gm_rac_fast_down_freq_switch_cap;
static int hf_gsm_a_gm_rac_tighter_cap;
static int hf_gsm_a_gm_rac_fanr_cap;
static int hf_gsm_a_gm_rac_ipa_cap;
static int hf_gsm_a_gm_rac_geran_nw_sharing_support;
static int hf_gsm_a_gm_rac_eutra_wb_rsrq_support;
static int hf_gsm_a_gm_rac_utra_mfbi_support;
static int hf_gsm_a_gm_rac_eutra_mfbi_support;
static int hf_gsm_a_gm_rac_dlmc_non_contig_intra_band_recep;
static int hf_gsm_a_gm_rac_dlmc_inter_band_recep;
static int hf_gsm_a_gm_rac_dlmc_max_bandwidth;
static int hf_gsm_a_gm_rac_dlmc_max_nb_dl_ts;
static int hf_gsm_a_gm_rac_dlmc_max_nb_dl_carriers;
static int hf_gsm_a_gm_rac_ext_tsc_set_cap_support;
static int hf_gsm_a_gm_rac_ext_earfcn_value_range;
static int hf_gsm_a_gm_rac_ec_pch_mon_support;
static int hf_gsm_a_gm_rac_ms_sync_accuracy;
static int hf_gsm_a_gm_rac_ec_ul_cov_enh_support;
static int hf_gsm_a_gm_rac_mta_access_sec_support;
static int hf_gsm_a_gm_rac_ec_paging_ind_chan_mon_support;
static int hf_gsm_a_sm_ti_flag;
static int hf_gsm_a_sm_ext;

static int hf_gsm_a_gmm_net_cap_gea1;
static int hf_gsm_a_gmm_net_cap_smdch;
static int hf_gsm_a_gmm_net_cap_smgprs;
static int hf_gsm_a_gmm_net_cap_ucs2;
static int hf_gsm_a_gmm_net_cap_ss_scr_ind;
static int hf_gsm_a_gmm_net_cap_solsa;
static int hf_gsm_a_gmm_net_cap_rev;
static int hf_gsm_a_gmm_net_cap_pfc;
static int hf_gsm_a_gmm_net_cap_ext_gea_bits;
static int hf_gsm_a_gmm_net_cap_gea2;
static int hf_gsm_a_gmm_net_cap_gea3;
static int hf_gsm_a_gmm_net_cap_gea4;
static int hf_gsm_a_gmm_net_cap_gea5;
static int hf_gsm_a_gmm_net_cap_gea6;
static int hf_gsm_a_gmm_net_cap_gea7;
static int hf_gsm_a_gmm_net_cap_lcs;
static int hf_gsm_a_gmm_net_cap_ps_irat_iu;
static int hf_gsm_a_gmm_net_cap_ps_irat_s1;
static int hf_gsm_a_gmm_net_cap_comb_proc;
static int hf_gsm_a_gmm_net_cap_isr;
static int hf_gsm_a_gmm_net_cap_srvcc_to_geran;
static int hf_gsm_a_gmm_net_cap_epc;
static int hf_gsm_a_gmm_net_cap_nf;
static int hf_gsm_a_gmm_net_geran_net_sharing;
static int hf_gsm_a_gmm_net_cap_up_int_prot;
static int hf_gsm_a_gmm_net_cap_up_gia4;
static int hf_gsm_a_gmm_net_cap_up_gia5;
static int hf_gsm_a_gmm_net_cap_up_gia6;
static int hf_gsm_a_gmm_net_cap_up_gia7;
static int hf_gsm_a_gmm_net_cap_epco_ie_ind;
static int hf_gsm_a_gmm_net_cap_restrict_use_enh_cov;
static int hf_gsm_a_gmm_net_cap_dc_eutra_nr_cap;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_gsm_a_gm_presence;
static int hf_gsm_a_gm_8psk_power_class;
static int hf_gsm_a_gm_rf_power_capability;
static int hf_gsm_a_gm_a5_bits;
static int hf_gsm_a_gm_8psk_power_capability;
static int hf_gsm_a_gm_extended_dtm_gprs_multi_slot_class;
static int hf_gsm_a_gm_extended_dtm_egprs_multi_slot_class;
static int hf_gsm_a_gm_high_multislot_capability;
static int hf_gsm_a_gm_gmsk_multislot_power_profile;
static int hf_gsm_a_gm_8psk_multislot_power_profile;
static int hf_gsm_a_gm_update_result;
static int hf_gsm_a_gm_radio_priority_pdp;
static int hf_gsm_a_gm_radio_priority_tom8;
static int hf_gsm_a_gm_configuration_protocol;
static int hf_gsm_a_gm_sm_pco_length;
static int hf_gsm_a_gm_sm_pco_length2;
static int hf_gsm_a_gm_sm_pco_pcscf_ipv6;
static int hf_gsm_a_gm_sm_pco_dns_ipv6;
static int hf_gsm_a_gm_sm_pco_dsmipv6_home_agent_ipv6;
static int hf_gsm_a_gm_sm_pco_dsmipv6_home_network_ipv6;
static int hf_gsm_a_gm_sm_pco_reject_code;
static int hf_gsm_a_gm_sm_pco_dsmipv6_home_network_prefix_length;
static int hf_gsm_a_gm_sm_pco_dsmipv6_home_agent_ipv4;
static int hf_gsm_a_gm_sm_pco_pcscf_ipv4;
static int hf_gsm_a_gm_sm_pco_dns_ipv4;
static int hf_gsm_a_gm_sm_pco_ipv4_link_mtu_size;
static int hf_gsm_a_gm_sm_pco_nbifom_mode;
static int hf_gsm_a_gm_sm_pco_non_ip_link_mtu_size;
static int hf_gsm_a_gm_sm_pco_apn_rate_ctrl_params_aer;
static int hf_gsm_a_gm_sm_pco_apn_rate_ctrl_params_ul_time_unit;
static int hf_gsm_a_gm_sm_pco_apn_rate_ctrl_params_max_ul_rate;
static int hf_gsm_a_gm_sm_pco_3gpp_data_off_ue_status;
static int hf_gsm_a_gm_sm_pco_sel_bearer_ctrl_mode;
static int hf_gsm_a_gm_sm_pco_add_apn_rate_ctrl_params_ul_time_unit;
static int hf_gsm_a_gm_sm_pco_add_apn_rate_ctrl_params_max_ul_rate;
static int hf_gsm_a_gm_sm_pco_pdu_session_id;
static int hf_gsm_a_gm_sm_pco_pdu_session_address_lifetime;
static int hf_gsm_a_gm_sm_pco_eth_frame_payload_mtu;
static int hf_gsm_a_gm_sm_pco_unstruct_link_mtu;
static int hf_gsm_a_gm_sm_pco_5gsm_cause;
static int hf_gsm_a_gm_sm_pco_acs_info;
static int hf_gsm_a_gm_sm_pco_init_small_data_rate_ctrl_params_max_ul_rate_allowed;
static int hf_gsm_a_gm_sm_pco_init_small_data_rate_ctrl_params_termination_timestamp;
static int hf_gsm_a_gm_sm_pco_atsss_response;
static int hf_gsm_a_gm_sm_pco_dns_serv_sec_info_type;
static int hf_gsm_a_gm_sm_pco_dns_serv_sec_info_sec_proto_type;
static int hf_gsm_a_gm_sm_pco_dns_serv_sec_info_port_number;
static int hf_gsm_a_gm_sm_pco_dns_serv_sec_info_auth_domain_name;
static int hf_gsm_a_gm_sm_pco_dns_serv_sec_info_spki_pin_set;
static int hf_gsm_a_gm_sm_pco_dns_serv_sec_info_root_certificate;
static int hf_gsm_a_gm_sm_pco_dns_serv_sec_info_raw_public_key;
static int hf_gsm_a_gm_sm_pco_dns_serv_sec_info_value_part;
static int hf_gsm_a_gm_sm_pco_ecs_addr_type;
static int hf_gsm_a_gm_sm_pco_ecs_addr_spatial_valid_cond_type;
static int hf_gsm_a_gm_sm_pco_ecs_addr_ipv4;
static int hf_gsm_a_gm_sm_pco_ecs_addr_ipv6;
static int hf_gsm_a_gm_sm_pco_ecs_addr_fqdn_len;
static int hf_gsm_a_gm_sm_pco_ecs_addr_fqdn;
static int hf_gsm_a_gm_sm_pco_ecs_addr_spatial_valid_cond_cont;
static int hf_gsm_a_gm_sm_pco_ecsp_id;
static int hf_gsm_a_gm_sm_pco_pvs_ipv4;
static int hf_gsm_a_gm_sm_pco_pvs_ipv6;
static int hf_gsm_a_gm_sm_pco_pvs_name_len;
static int hf_gsm_a_gm_sm_pco_pvs_name;
static int hf_gsm_a_gm_sm_pco_pvs_s_nssai_ind;
static int hf_gsm_a_gm_sm_pco_pvs_dnn_ind;
static int hf_gsm_a_gm_sm_pco_pvs_dnn_len;
static int hf_gsm_a_gm_sm_pco_pvs_s_nssai_len;
static int hf_gsm_a_gm_sm_pco_dns_serv_sec_prot_support;
static int hf_gsm_a_gm_sm_pco_eas_rediscovery_support_ind_fqdn;
static int hf_gsm_a_gm_sm_pco_eas_rediscovery_support_ind_ipv6;
static int hf_gsm_a_gm_sm_pco_eas_rediscovery_support_ind_ipv4;
static int hf_gsm_a_gm_sm_pco_eas_rediscovery_support_ind_with_impacted_eas_ipv4_range_low;
static int hf_gsm_a_gm_sm_pco_eas_rediscovery_support_ind_with_impacted_eas_ipv4_range_high;
static int hf_gsm_a_gm_sm_pco_eas_rediscovery_support_ind_with_impacted_eas_ipv6_range_low;
static int hf_gsm_a_gm_sm_pco_eas_rediscovery_support_ind_with_impacted_eas_ipv6_range_high;
static int hf_gsm_a_gm_sm_pco_eas_rediscovery_support_ind_with_impacted_eas_fqdn;
static int hf_gsm_a_gm_sm_pco_sdnaepc_dn_specific_id;
static int hf_gsm_a_sm_pdp_type_number;
static int hf_gsm_a_sm_pdp_address;
static int hf_gsm_a_gm_ti_value;

/* Initialize the subtree pointers */
static int ett_gmm_radio_cap;
static int ett_gmm_network_cap;
static int ett_gsm_a_gm_msrac_multislot_capability;
static int ett_gmm_rai;
static int ett_gmm_gprs_timer;

static int ett_sm_tft;
static int ett_sm_pco;

static expert_field ei_gsm_a_gm_extraneous_data;
static expert_field ei_gsm_a_gm_not_enough_data;
static expert_field ei_gsm_a_gm_undecoded;
static expert_field ei_gsm_a_gm_missing_mandatory_element;

static dissector_handle_t rrc_irat_ho_info_handle;
static dissector_handle_t lte_rrc_ue_eutra_cap_handle;
static dissector_handle_t nbifom_handle;
static dissector_handle_t eap_handle;

static dissector_table_t gprs_sm_pco_subdissector_table; /* GPRS SM PCO PPP Protocols */

static const unit_name_string units_message_messages = { " message", " messages" };

#define	NUM_GSM_GM_ELEM array_length(gsm_gm_elem_strings)
int ett_gsm_gm_elem[NUM_GSM_GM_ELEM];

static const char *pdp_str[2]={ "PDP-INACTIVE", "PDP-ACTIVE" };

/*
 * [9] 10.5.5.0 Additional Update Type
 */
static const true_false_string gsm_a_gm_add_upd_type_value = {
	"SMS only",
	"No additional information (shall be interpreted as request for combined attach or combined tracking area updating)"
};
static uint16_t
de_gmm_add_upd_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	uint32_t curr_offset, bit_offset;

	curr_offset = offset;
	bit_offset  = (curr_offset<<3)+4;

	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
	bit_offset += 3;
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_add_upd_type, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return (curr_offset - offset);
}

 /*
 * [9] 10.5.5.1 Attach result
 */
static const value_string gsm_a_gm_res_of_attach_vals[] = {
	{ 0x01, "GPRS only attached" },
	{ 0x03, "Combined GPRS/IMSI attached" },
	{ 0, NULL }
};

static uint16_t
de_gmm_attach_res(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_item(tree, hf_gsm_a_gm_fop, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_res_of_attach, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* no length check possible */
	return 1;
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

static uint16_t
de_gmm_attach_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_item(tree, hf_gsm_a_gm_for, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_type_of_attach, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* no length check possible */
	return 1;
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

static uint16_t
de_gmm_ciph_alg(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (offset << 3) + 4, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_type_of_ciph_alg, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* no length check possible */
	return 1;
}

/*
 * [13] 10.5.5.3a Integrity protection algorithm
 */
static const value_string gsm_a_gm_type_of_integ_alg_vals[] = {
	{ 0x00, "GPRS Integrity Algorithm GIA/4" },
	{ 0x01, "GPRS Integrity Algorithm GIA/5" },
	{ 0x02, "GPRS Integrity Algorithm GIA/6" },
	{ 0x03, "GPRS Integrity Algorithm GIA/7" },
	{ 0, NULL }
};

static uint16_t
de_gmm_integ_alg(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (offset << 3) + 4, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_type_of_integ_alg, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* no length check possible */
	return 1;
}

/*
 * [9] 10.5.5.4 TMSI status
 */
static const true_false_string gsm_a_gm_tmsi_flag_value = {
	"valid TMSI available",
	"no valid TMSI available"
};

static uint16_t
de_gmm_tmsi_stat(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (offset << 3) + 4, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_tmsi_flag, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* no length check possible */
	return 1;
}

/*
 * [7] 10.5.5.5
 */
static const true_false_string gsm_a_gm_power_off_value = {
	"power switched off",
	"normal detach"
};

static const value_string gsm_a_gm_type_of_detach_mo_vals[] = {
	{ 0x01, "GPRS detach" },
	{ 0x02, "IMSI detach" },
	{ 0x03, "Combined GPRS/IMSI detach" },
	{ 0, NULL }
};

static const value_string gsm_a_gm_type_of_detach_mt_vals[] = {
	{ 0x01, "re-attach required" },
	{ 0x02, "re-attach not required" },
	{ 0x03, "IMSI detach (after VLR failure)" },
	{ 0, NULL }
};

static uint16_t
de_gmm_detach_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	uint32_t curr_offset;

	curr_offset = offset;

	if (pinfo->p2p_dir == P2P_DIR_RECV) {
		proto_tree_add_item(tree, hf_gsm_a_gm_power_off, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_gsm_a_gm_type_of_detach_mo, tvb, offset, 1, ENC_BIG_ENDIAN);
	} else {
		proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (offset << 3) + 4, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_gsm_a_gm_type_of_detach_mt, tvb, offset, 1, ENC_BIG_ENDIAN);
	}

	curr_offset++;

	/* no length check possible */

	return (curr_offset - offset);
}

/*
 * [7] 10.5.5.6
 */

/* SPLIT PG CYCLE CODE, octet 2 */
static const value_string gsm_a_gmm_split_pg_cycle_code_strings[] = {
	{  0, "704 (equivalent to no DRX)" },
	{  1, "1" },
	{  2, "2" },
	{  3, "3" },
	{  4, "4" },
	{  5, "5" },
	{  6, "6" },
	{  7, "7" },
	{  8, "8" },
	{  9, "9" },
	{ 10, "10" },
	{ 11, "11" },
	{ 12, "12" },
	{ 13, "13" },
	{ 14, "14" },
	{ 15, "15" },
	{ 16, "16" },
	{ 17, "17" },
	{ 18, "18" },
	{ 19, "19" },
	{ 20, "20" },
	{ 21, "21" },
	{ 22, "22" },
	{ 23, "23" },
	{ 24, "24" },
	{ 25, "25" },
	{ 26, "26" },
	{ 27, "27" },
	{ 28, "28" },
	{ 29, "29" },
	{ 30, "30" },
	{ 31, "31" },
	{ 32, "32" },
	{ 33, "33" },
	{ 34, "34" },
	{ 35, "35" },
	{ 36, "36" },
	{ 37, "37" },
	{ 38, "38" },
	{ 39, "39" },
	{ 40, "40" },
	{ 41, "41" },
	{ 42, "42" },
	{ 43, "43" },
	{ 44, "44" },
	{ 45, "45" },
	{ 46, "46" },
	{ 47, "47" },
	{ 48, "48" },
	{ 49, "49" },
	{ 50, "50" },
	{ 51, "51" },
	{ 52, "52" },
	{ 53, "53" },
	{ 54, "54" },
	{ 55, "55" },
	{ 56, "56" },
	{ 57, "57" },
	{ 58, "58" },
	{ 59, "59" },
	{ 60, "60" },
	{ 61, "61" },
	{ 62, "62" },
	{ 63, "63" },
	{ 64, "64" },
	{ 65, "71" },
	{ 66, "72" },
	{ 67, "74" },
	{ 68, "75" },
	{ 69, "77" },
	{ 70, "79" },
	{ 71, "80" },
	{ 72, "83" },
	{ 73, "86" },
	{ 74, "88" },
	{ 75, "90" },
	{ 76, "92" },
	{ 77, "96" },
	{ 78, "101" },
	{ 79, "103" },
	{ 80, "107" },
	{ 81, "112" },
	{ 82, "116" },
	{ 83, "118" },
	{ 84, "128" },
	{ 85, "141" },
	{ 86, "144" },
	{ 87, "150" },
	{ 88, "160" },
	{ 89, "171" },
	{ 90, "176" },
	{ 91, "192" },
	{ 92, "214" },
	{ 93, "224" },
	{ 94, "235" },
	{ 95, "256" },
	{ 96, "288" },
	{ 97, "320" },
	{ 98, "352" },
	{ 0, NULL }
};
static value_string_ext gsm_a_gmm_split_pg_cycle_code_strings_ext = VALUE_STRING_EXT_INIT(gsm_a_gmm_split_pg_cycle_code_strings);

/* SPLIT on CCCH, octet 3 (bit 4)
 * 0 Split pg cycle on CCCH is not supported by the mobile station
 * 1 Split pg cycle on CCCH is supported by the mobile station
 */
static const true_false_string gsm_a_gmm_split_on_ccch_value = {
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
 * 8 7 6 5 Iu and S1 mode specific
 * 0 0 0 0 For Iu mode, CN Specific DRX cycle length coefficient not specified by the MS, ie. the
 * system information value 'CN domain specific DRX cycle length' is used.
 * For S1 mode, DRX value not specified by the MS.
 * (Ref 3GPP TS 25.331 and 36.304)
 * 0 1 1 0 CN Specific DRX cycle length coefficient 6 and T = 32
 * 0 1 1 1 CN Specific DRX cycle length coefficient 7 and T = 64
 * 1 0 0 0 CN Specific DRX cycle length coefficient 8 and T = 128
 * 1 0 0 1 CN Specific DRX cycle length coefficient 9 and T = 256
 * All other values shall be interpreted as "CN Specific DRX cycle length coefficient not
 * specified by the MS" and "DRX value not specified by the MS" by this version of the protocol.
 * NOTE: For Iu mode and S1 mode, this field (octet 3 bits 8 to 5) is used, but was spare in earlier
 * versions of this protocol.
 */
static const range_string gsm_a_gmm_cn_spec_drx_cycle_len_coef_strings[] = {
	{ 0x00,	0x05, "CN Specific DRX cycle length coefficient / value not specified by the MS" },
	{ 0x06,	0x06, "CN Specific DRX cycle length coefficient 6 and T = 32" },
	{ 0x07,	0x07, "CN Specific DRX cycle length coefficient 7 and T = 64" },
	{ 0x08,	0x08, "CN Specific DRX cycle length coefficient 8 and T = 128" },
	{ 0x09,	0x09, "CN Specific DRX cycle length coefficient 9 and T = 256" },
	{ 0x0a, 0x0f, "CN Specific DRX cycle length coefficient / value not specified by the MS" },
	{ 0, 0, NULL },
};
uint16_t
de_gmm_drx_param(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	uint32_t curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_gmm_split_pg_cycle_code, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;
	proto_tree_add_item(tree, hf_gsm_a_gmm_cn_spec_drx_cycle_len_coef, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gmm_split_on_ccch, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gmm_non_drx_timer, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	curr_offset++;

	/* no length check possible */

	return (curr_offset - offset);
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

static uint16_t
de_gmm_ftostby(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	uint32_t	bit_offset;

	/* IMPORTANT - IT'S ASSUMED THAT THE INFORMATION IS IN THE LOWER NIBBLE */
	bit_offset = (offset << 3) + 4;
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_force_to_standby, tvb, bit_offset + 1, 3, ENC_BIG_ENDIAN);

	/* no length check possible */
	return 1;
}

/*
 * [9] 10.5.5.7 Force to standby (higher nibble)
 */
static uint16_t
de_gmm_ftostby_h(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	uint32_t	bit_offset;

	/* IMPORTANT - IT'S ASSUMED THAT THE INFORMATION IS IN THE HIGHER NIBBLE */
	bit_offset = offset << 3;
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_force_to_standby, tvb, bit_offset + 1, 3, ENC_BIG_ENDIAN);

	/* no length check possible */
	return 1;
}

/*
 * [7] 10.5.5.8
 */
static uint16_t
de_gmm_ptmsi_sig(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	uint32_t    curr_offset;
	proto_item *curr_item;

	curr_offset = offset;

	curr_item= proto_tree_add_item(tree, hf_gsm_a_gmm_ptmsi_sig, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
	proto_item_append_text(curr_item, "%s", add_string ? add_string : "");

	curr_offset += 3;

	/* no length check possible */

	return (curr_offset - offset);
}

/*
 * [7] 10.5.5.8a
 */
static uint16_t
de_gmm_ptmsi_sig2(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len _U_)
{
	uint32_t    curr_offset;
	proto_item *curr_item;

	curr_offset = offset;

	curr_item= proto_tree_add_item(tree, hf_gsm_a_gmm_ptmsi_sig2, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
	proto_item_append_text(curr_item, "%s", add_string ? add_string : "");
	curr_offset += 3;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_gm_extraneous_data);

	return (curr_offset - offset);
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

static uint16_t
de_gmm_ident_type2(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (offset << 3) + 4, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_type_of_identity, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* no length check possible */
	return 1;
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

static uint16_t
de_gmm_imeisv_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	uint32_t	bit_offset;

	/* IMPORTANT - IT'S ASSUMED THAT THE INFORMATION IS IN THE HIGHER NIBBLE */
	bit_offset = offset << 3;
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_imeisv_req, tvb, bit_offset + 1, 3, ENC_BIG_ENDIAN);

	/* no length check possible */
	return 1;
}

/*
 * [7] 10.5.5.11
 */
static uint16_t
de_gmm_rec_npdu_lst(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t	curr_offset;
	unsigned	curr_len;

	curr_len    = len;
	curr_offset = offset;

	if (len == 0) return 0;

	do
	{
		uint32_t	oct;
		oct = tvb_get_guint8(tvb, curr_offset);
		oct <<= 8;
		oct |= tvb_get_guint8(tvb, curr_offset+1);
		curr_len -= 2;
		oct <<= 8;

		proto_tree_add_uint_format(tree, hf_gsm_a_gm_nsapi, tvb, curr_offset, 2, (oct>>12)&0xff, "NSAPI %d: 0x%02x (%u)", oct>>20, (oct>>12)&0xff, (oct>>12)&0xff);
		curr_offset +=  2;

		if (curr_len > 2)
		{
			oct |= tvb_get_guint8(tvb, curr_offset+2);
			curr_len--;
			oct <<= 12;

			proto_tree_add_uint_format(tree, hf_gsm_a_gm_nsapi, tvb, curr_offset-1, 2, (oct>>12)&0xff, "NSAPI %d: 0x%02x (%u)", oct>>20, (oct>>12)&0xff, (oct>>12)&0xff);
			curr_offset++;
		}

	} while (curr_len > 1);

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_gm_extraneous_data);

	return (curr_offset - offset);
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

static const true_false_string gsm_a_gmm_net_geran_net_vals = {
	"Mobile station supports GERAN network sharing",
	"Mobile station does not support GERAN network sharing"
};

static const true_false_string gsm_a_gmm_net_cap_gia_vals = {
	"Integrity algorithm available",
	"Integrity algorithm not available"
};

static const true_false_string gsm_a_gmm_net_cap_epco_ie_ind_vals = {
	"Used by a mobile station supporting extended protocol configuration options IE",
	"Used by a mobile station not supporting extended protocol configuration options IE"
};

static const true_false_string gsm_a_gmm_net_cap_restrict_use_enh_cov_vals = {
	"Mobile station supports restriction on use of enhanced coverage",
	"Mobile station does not support restriction on use of enhanced coverage"
};

static const true_false_string gsm_a_gmm_net_cap_dc_eutra_nr_cap_vals = {
	"Mobile station supports dual connectivity of E-UTRA with NR",
	"Mobile station does not support dual connectivity of E-UTRA with NR"
};

uint16_t
de_gmm_ms_net_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t    curr_offset;
	proto_tree *subtree;
	proto_item *item;

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

	/* bit 8: PS inter-RAT HO from GERAN to UTRAN Iu mode capability */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_ps_irat_iu, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bit 7: PS inter-RAT HO from GERAN to E-UTRAN S1 mode capability */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_ps_irat_s1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bit 6: EMM Combined procedures capability */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_comb_proc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bit 5: ISR support */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_isr, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bit 4: SRVCC to GERAN/UTRAN capability */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_srvcc_to_geran, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bit 3: EPC capability */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_epc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bit 2: NF capability */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_nf, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bits 1: GERAN network sharing capability */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_geran_net_sharing, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	curr_offset++;
	NO_MORE_DATA_CHECK(len);

	/* bit 8: User plane integrity protection support */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_up_int_prot, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bit 7: GIA/4 */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_up_gia4, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bit 6: GIA/5 */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_up_gia5, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bit 5: GIA/6 */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_up_gia6, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bit 4: GIA/7 */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_up_gia7, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bit 3: ePCO IE indicator */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_epco_ie_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bit 2: Restriction on use of enhanced coverage capability */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_restrict_use_enh_cov, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	/* bit 1: Dual connectivity of E-UTRA with NR capability */
	proto_tree_add_item(tree, hf_gsm_a_gmm_net_cap_dc_eutra_nr_cap, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	curr_offset++;
	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_gm_extraneous_data);

	return (curr_offset - offset);
}

/*
 * [7] 10.5.5.12a
 */
#define GET_DATA				/* check if we have enough bits left */ \
	if (curr_bits_length < bits_needed) \
		continue; \
	/* check if oct has enough bits */ \
	if (bits_in_oct < bits_needed) \
	{ \
		uint32_t tmp_oct; \
		if (curr_len == 0) \
		{ \
			proto_tree_add_expert(tf_tree, pinfo, &ei_gsm_a_gm_not_enough_data, tvb, curr_offset, 1); \
		} \
		tmp_oct = tvb_get_guint8(tvb, curr_offset); \
		oct |= tmp_oct<<(32-8-bits_in_oct); \
		curr_len--; \
		curr_offset++; \
		if (bits_in_oct != 0) \
			add_octets = 1; \
		else \
			add_octets = 0; \
		bits_in_oct += 8; \
	} \
	else \
		add_octets = 0;

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
	{ 0x03, "The mobile station supports both EGPRS2-A and EGPRS2-B in the uplink" },
	{ 0, NULL }
};

static const value_string gsm_a_gm_dl_egprs2_vals[] = {
	{ 0x00, "The mobile station does not support either EGPRS2-A or EGPRS2-B in the downlink" },
	{ 0x01, "The mobile station supports EGPRS2-A in the downlink" },
	{ 0x02, "The mobile station supports both EGPRS2-A and EGPRS2-B in the downlink" },
	{ 0x03, "The mobile station supports both EGPRS2-A and EGPRS2-B in the downlink" },
	{ 0, NULL }
};

static const value_string gsm_a_gm_geran_to_eutra_support_in_geran_ptm_vals[] = {
	{ 0x00, "None" },
	{ 0x01, "E-UTRAN neighbour cell measurements and MS autonomous cell reselection to E-UTRAN supported" },
	{ 0x02, "E-UTRAN neighbour cell meas and report, MS autonomous cell resel, CCN and network controlled cell reselection to E-UTRAN" },
	{ 0x03, "E-UTRAN neighbour cell meas and report, MS autonomous cell resel, CCN, network controlled cell reselection and PS Handover to E-UTRAN" },
	{ 0, NULL }
};

static const value_string gsm_a_gm_alt_efta_multi_slot_class_vals[] = {
	{ 0x00, "No Alternative EFTA multislot class is indicated. Use (DTM) EGPRS (high) multislot class only" },
	{ 0x01, "Alternative EFTA multislot class 1" },
	{ 0x02, "Alternative EFTA multislot class 2" },
	{ 0x03, "Alternative EFTA multislot class 3" },
	{ 0x04, "Unused" },
	{ 0x05, "Unused" },
	{ 0x06, "Unused" },
	{ 0x07, "Unused" },
	{ 0x08, "Unused" },
	{ 0x09, "Unused" },
	{ 0x0a, "Unused" },
	{ 0x0b, "Unused" },
	{ 0x0c, "Unused" },
	{ 0x0d, "Unused" },
	{ 0x0e, "Unused" },
	{ 0x0f, "Unused" },
	{ 0, NULL }
};

static const value_string gsm_a_gm_dlmc_non_contig_intra_band_recep_vals[] = {
	{ 0x00, "Not supported" },
	{ 0x01, "Supported in band E-GSM or GSM850" },
	{ 0x02, "Supported in band DCS1800 or PCS1900" },
	{ 0x03, "Supported in band E-GSM, or GSM850, or DCS1800 or PCS1900" },
	{ 0, NULL }
};

static const true_false_string gsm_a_gm_dlmc_inter_band_recep_val = {
	"Supported in band combination (E-GSM, DCS1800), or band combination (GSM850, PCS1900)",
	"Not supported"
};

static const value_string gsm_a_gm_dlmc_max_bandwidth_vals[] = {
	{ 0x00, "5 MHz" },
	{ 0x01, "10 MHz" },
	{ 0x02, "15 MHz" },
	{ 0x03, "20 MHz" },
	{ 0, NULL }
};

static void
gsm_a_gm_dlmc_max_nb_dl_ts_fmt(char *s, uint32_t v)
{
	if (v < 0x3E)
		snprintf(s, ITEM_LABEL_LENGTH, "%u TS supported (%u)",
		           2*v + 6, v);
	else
		snprintf(s, ITEM_LABEL_LENGTH, "Reserved (%u)", v);
}

static const value_string gsm_a_gm_dlmc_max_nb_dl_carriers_vals[] = {
	{ 0x00, "2 carriers supported" },
	{ 0x01, "4 carriers supported" },
	{ 0x02, "6 carriers supported" },
	{ 0x03, "8 carriers supported" },
	{ 0x04, "10 carriers supported" },
	{ 0x05, "12 carriers supported" },
	{ 0x06, "14 carriers supported" },
	{ 0x07, "16 carriers supported" },
	{ 0, NULL }
};

static const value_string gsm_a_gm_8psk_power_class_vals[] = {
	{0x00, "8PSK modulation not supported for uplink" },
	{0x01, "Power class E1"},
	{0x02, "Power class E2"},
	{0x03, "Power class E3"},
	{0, NULL},
};


static const value_string gsm_a_gm_8psk_power_cap_vals[] = {
	{0x00, "Reserved" },
	{0x01, "Power class E1"},
	{0x02, "Power class E2"},
	{0x03, "Power class E3"},
	{0, NULL},
};

static const value_string gsm_a_gm_extended_dtm_gprs_multi_slot_class_vals[] = {
	{0x00,  "Unused. If received, it shall be interpreted as Multislot class 5 supported" },
	{0x01,  "Unused. If received, it shall be interpreted as Multislot class 5 supported"},
	{0x02,  "Unused. If received, it shall be interpreted as Multislot class 5 supported"},
	{0x03,  "Unused. If received, it shall be interpreted as Multislot class 5 supported"},
	{0x10,  "Multislot class 5 supported"},
	{0x11,  "Multislot class 6 supported"},
	{0x12,  "Unused. If received, it shall be interpreted as Multislot class 5 supported"},
	{0x13,  "Unused. If received, it shall be interpreted as Multislot class 5 supported"},
	{0x20,  "Multislot class 9 supported"},
	{0x21,  "Multislot class 10 supported"},
	{0x22,  "Unused. If received, it shall be interpreted as Multislot class 9 supported"},
	{0x23,  "Unused. If received, it shall be interpreted as Multislot class 9 supported"},
	{0x30,  "Multislot class 11 supported"},
	{0x31,  "Unused. If received, it shall be interpreted as Multislot class 11 supported"},
	{0x32,  "Unused. If received, it shall be interpreted as Multislot class 11 supported"},
	{0x33,  "Unused. If received, it shall be interpreted as Multislot class 11 supported"},
	{0, NULL}
};

static const value_string gsm_a_gm_gmsk_multislot_power_profile_vals[] = {
	{0x00,  "GMSK_MULTISLOT_POWER_PROFILE 0" },
	{0x01,  "GMSK_MULTISLOT_POWER_PROFILE 1"},
	{0x02,  "GMSK_MULTISLOT_POWER_PROFILE 2"},
	{0x03,  "GMSK_MULTISLOT_POWER_PROFILE 3"},
	{0, NULL}
};

static const value_string gsm_a_gm_8psk_multislot_power_profile_vals[] = {
	{0x00,  "8-PSK_MULTISLOT_POWER_PROFILE 0" },
	{0x01,  "8-PSK_MULTISLOT_POWER_PROFILE 1"},
	{0x02,  "8-PSK_MULTISLOT_POWER_PROFILE 2"},
	{0x03,  "8-PSK_MULTISLOT_POWER_PROFILE 3"},
	{0, NULL}
};

static const value_string gsm_a_gm_ec_pch_mon_support_vals[] = {
	{0x00, "PCH supported"},
	{0x01, "EC-PCH supported"},
	{0x02, "PCH and EC-PCH supported"},
	{0x03, "Reserved"},
	{0, NULL}
};

uint16_t
de_gmm_ms_radio_acc_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t     curr_offset;
	unsigned     curr_len;
	int          bit_offset;
	proto_item  *tf = NULL, *mc_item = NULL, *ti;
	proto_tree  *tf_tree = NULL, *mc_tree = NULL;
	uint32_t     oct;
	unsigned char       bits_in_oct;
	unsigned char       bits_needed;
	unsigned     bits_length;
	unsigned     add_octets;	/* octets which are covered by one element -1 */
	unsigned     curr_bits_length;
	unsigned char       acc_type;
	unsigned     value;
	const char *str;
	unsigned indx = 0;

	unsigned char   dtm_gprs_mslot  = 0;
	unsigned char   dtm_egprs_mslot = 4;
	bool finished = true;

	curr_len    = len;
	curr_offset = offset;
	bit_offset  = offset<<3;

	bits_in_oct = 0;
	oct = 0;


	do
	{
		/* check for a new round */
		if ((curr_len*8 + bits_in_oct) < 11)
			break;

		/* now read the first 11 bits */
		curr_bits_length = 11;
		/*
		 *
		 */
		if (curr_len != len)
		{
			bits_needed = 1;
			GET_DATA;

			if ((oct>>(32-bits_needed)) != 1)
			{
				break;
			}
			oct	    <<= bits_needed;
			bits_in_oct  -= bits_needed;
			bit_offset++;

			if ((curr_len*8 + bits_in_oct) < 11)
				break;
			curr_bits_length = 11;
		}

		indx++;
		tf_tree = proto_tree_add_subtree_format(tree,
				tvb, curr_offset, 1,
				ett_gmm_radio_cap, &tf, "MS RA capability %d", indx);

		/*
		 * Access Technology
		 */
		bits_needed = 4;
		GET_DATA;

		acc_type = oct>>(32-bits_needed);

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_acc_tech_type, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
		bit_offset += 4;

		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

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
		bit_offset   += 7;
		oct	    <<= bits_needed;
		bits_in_oct  -= bits_needed;

		if (acc_type == 0x0f)
		{
			do
			{
				/*
				 * Additional access technologies:
				 */
				finished = true; /* Break out of the loop unless proven unfinished */

				/*
				 * Presence bit
				 */
				bits_needed = 1;
				GET_DATA;

				/* analyse bits */
				switch (oct>>(32-bits_needed))
				{
					case 0x00: str = "Not Present"; finished = true; break;
					case 0x01: str = "Present"; finished = false;    break;
					default:   str = "This should not happen";
				}

				proto_tree_add_uint_format_value(tf_tree, hf_gsm_a_gm_presence, tvb, curr_offset-1-add_octets, 1+add_octets, oct>>(32-bits_needed), "%s (%u)", str, oct>>(32-bits_needed));
				bit_offset++;
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;

				if (finished)
				{
					/*
					 * No more valid data, get spare bits if any
					 */
					while (curr_bits_length > 0)
					{
						if (curr_bits_length > 8)
							bits_needed = 8;
						else
							bits_needed = curr_bits_length;
						GET_DATA;
						curr_bits_length  -= bits_needed;
						oct		 <<= bits_needed;
						bits_in_oct	  -= bits_needed;
						bit_offset	  += bits_needed;
					}
					continue;
				}

				/*
				 * Access Technology
				 */
				bits_needed = 4;
				GET_DATA;

				acc_type = oct>>(32-bits_needed);

				proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_acc_tech_type, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
				bit_offset += 4;

				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;

				/*
				 * RF Power
				 */
				bits_needed = 3;
				GET_DATA;

				value = tvb_get_bits8(tvb, bit_offset, 3);
				/* analyse bits */
				if (acc_type == 0x04)	/* GSM 1900 */
				{
					switch (value)
					{
						case 0x01: str = "1 W (30 dBm)";    break;
						case 0x02: str = "0,25 W (24 dBm)"; break;
						case 0x03: str = "2 W (33 dBm)";    break;
						default:   str = "Not specified";
					}
				}
				else if (acc_type == 0x03)
				{
					/*
					 * 3 GSM 1800
					 */
					switch (value)
					{
						case 0x01: str = "1 W (30 dBm)";    break;
						case 0x02: str = "0,25 W (24 dBm)"; break;
						case 0x03: str = "4 W (36 dBm)";    break;
						default:   str = "Not specified";
					}
				}
				else if (acc_type <= 0x08)
				{
					/* 0 GSM P
					 * 1 GSM E
					 * 2 GSM R
					 * 5 GSM 450
					 * 6 GSM 480
					 * 7 GSM 850
					 */

					switch (value)
					{
						case 0x02: str = "8 W (39 dBm)";   break;
						case 0x03: str = "5 W (37 dBm)";   break;
						case 0x04: str = "2 W (33 dBm)";   break;
						case 0x05: str = "0,8 W (29 dBm)"; break;
						default:   str = "Not specified";
					}
				}
				else
					str = "Not specified??";

				/* decode_bits_in_field(int bit_offset, int no_of_bits, uint64_t value)*/
				proto_tree_add_uint_format(tf_tree, hf_gsm_a_gm_rf_power_capability, tvb, curr_offset-1-add_octets, 1+add_octets, value,
												"%s RF Power Capability, GMSK Power Class: %s (%u)", decode_bits_in_field(pinfo->pool, bit_offset, 3, value, ENC_BIG_ENDIAN), str, value);
				bit_offset	  += 3;
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;

				/*
				 * 8PSK Power Class
				 */
				bits_needed = 2;
				GET_DATA;

				value = tvb_get_bits8(tvb, bit_offset, 2);
				/* analyse bits */
				proto_tree_add_uint(tf_tree, hf_gsm_a_gm_8psk_power_class, tvb, curr_offset-1-add_octets, 1+add_octets, value);
				bit_offset	  += 2;
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;

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
		if (acc_type == 0x04)	/* GSM 1900 */
		{
			switch (value)
			{
				case 0x01: str = "1 W (30 dBm)";    break;
				case 0x02: str = "0,25 W (24 dBm)"; break;
				case 0x03: str = "2 W (33 dBm)";    break;
				default:   str = "Not specified";
			}
		}
		else if (acc_type == 0x03)
		{
			switch (value)
			{
				case 0x01: str = "1 W (30 dBm)";    break;
				case 0x02: str = "0,25 W (24 dBm)"; break;
				case 0x03: str = "4 W (36 dBm)";    break;
				default:   str = "Not specified";
			}
		}
		else if (acc_type <= 0x08)
		{
			switch (value)
			{
				case 0x02: str = "8 W (39 dBm)";   break;
				case 0x03: str = "5 W (37 dBm)";   break;
				case 0x04: str = "2 W (33 dBm)";   break;
				case 0x05: str = "0,8 W (29 dBm)"; break;
				default:   str = "Not specified";
			}
		}
		else
			str = "Not specified??";

		proto_tree_add_uint_format(tf_tree, hf_gsm_a_gm_rf_power_capability, tvb, curr_offset-1-add_octets, 1+add_octets, value,
						"%s RF Power Capability, GMSK Power Class: %s (%u)", decode_bits_in_field(pinfo->pool, bit_offset, 3, value, ENC_BIG_ENDIAN), str, value);

		bit_offset	  += 3;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * A5 Bits?
		 */
		bits_needed = 1;
		GET_DATA;

		/* analyse bits */
		if ((oct>>(32-bits_needed)) == 0)
		{
			proto_tree_add_uint_format_value(tf_tree, hf_gsm_a_gm_a5_bits, tvb, curr_offset-1-add_octets, 1+add_octets, oct>>(32-bits_needed),
						"Same values apply for parameters as in the immediately preceding Access capabilities field within this IE (%u)",
						oct>>(32-bits_needed));
			bit_offset++;
			curr_bits_length  -= bits_needed;
			oct		 <<= bits_needed;
			bits_in_oct	  -= bits_needed;
		}
		else
		{
			int i;

			proto_tree_add_uint_format_value(tf_tree, hf_gsm_a_gm_a5_bits, tvb, curr_offset-1-add_octets, 1+add_octets, oct>>(32-bits_needed), "A5 bits follow (%u)", oct>>(32-bits_needed));

			bit_offset++;
			curr_bits_length  -= bits_needed;
			oct		 <<= bits_needed;
			bits_in_oct	  -= bits_needed;

			for (i=1; i<=7 ; i++)
			{
				/*
				 * A5 Bits decoding
				 */
				bits_needed = 1;
				GET_DATA;

				/* analyse bits */
				switch (oct>>(32-bits_needed))
				{
					case 0x00: str = "encryption algorithm not available"; break;
					case 0x01: str = "encryption algorithm available";     break;
					default:   str = "This should not happen";
				}

				proto_tree_add_uint_format(tf_tree, hf_gsm_a_gm_a5_bits, tvb, curr_offset-1-add_octets, 1+add_octets, oct>>(32-bits_needed), "A5/%d: %s (%u)", i, str, oct>>(32-bits_needed));
				bit_offset++;
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;
			}
		}

		/*
		 * ES IND
		 */
		bits_needed = 1;
		GET_DATA;

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_ctrled_early_cm_sending, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset++;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * PS
		 */
		bits_needed = 1;
		GET_DATA;

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_pseudo_sync, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset++;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * VGCS
		 */
		bits_needed = 1;
		GET_DATA;

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_vgcs, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset++;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * VBS
		 */
		bits_needed = 1;
		GET_DATA;

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_vbs, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset++;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * Multislot capability?
		 */
		bits_needed = 1;
		GET_DATA;

		value = oct>>(32-bits_needed);

		mc_item = proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_multislot_capability, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset++;

		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/* analyse bits */
		if (value == 1)
		{
			mc_tree = proto_item_add_subtree(mc_item, ett_gsm_a_gm_msrac_multislot_capability);
			/*
			 * HSCSD multislot class?
			 */
			bits_needed = 1;
			GET_DATA;

			/* analyse bits */
			if ((oct>>(32-bits_needed)) == 0)
			{
				proto_tree_add_uint_format_value(mc_tree, hf_gsm_a_gm_rac_hscsd_multi_slot_class, tvb, curr_offset-1-add_octets, 1+add_octets, 0xFF,
												 "Bits are not available (%u)", oct>>(32-bits_needed));
				bit_offset++;
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;
			}
			else
			{
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;
				bit_offset++;

				/*
				 * HSCSD multislot class
				 */
				bits_needed = 5;
				GET_DATA;

				proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_hscsd_multi_slot_class, tvb, bit_offset, 5, ENC_BIG_ENDIAN);
				bit_offset	  += 5;
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;
			}

			/*
			 * GPRS multislot class?
			 */
			bits_needed = 1;
			GET_DATA;

			/* analyse bits */
			if ((oct>>(32-bits_needed)) == 0)
			{
				proto_tree_add_uint_format_value(mc_tree, hf_gsm_a_gm_rac_gprs_multi_slot_class, tvb, curr_offset-1-add_octets, 1+add_octets, 0xFF,
												"Bits are not available (%u)", oct>>(32-bits_needed));
				bit_offset++;
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;
			}
			else
			{
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;
				bit_offset++;

				/*
				 * GPRS multislot class
				 */
				bits_needed = 5;
				GET_DATA;

				proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_gprs_multi_slot_class, tvb, bit_offset, 5, ENC_BIG_ENDIAN);
				bit_offset	  += 5;
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;

				/*
				 * GPRS Extended Dynamic Allocation Capability
				 */
				bits_needed = 1;
				GET_DATA;

				proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_gprs_ext_dyn_alloc_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
				bit_offset++;
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;
			}

			/*
			 * SMS/SM values
			 */
			bits_needed = 1;
			GET_DATA;

			/* analyse bits */
			if ((oct>>(32-bits_needed)) == 0)
			{
				proto_tree_add_uint_format_value(mc_tree, hf_gsm_a_gm_sms_value, tvb, curr_offset-1-add_octets, 1+add_octets, 0xFF,
												"Bits are not available (%u)", oct>>(32-bits_needed));
				bit_offset++;
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;
			}
			else
			{
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;
				bit_offset++;

				/*
				 * Switch-Measure-Switch value
				 */
				bits_needed = 4;
				GET_DATA;

				/* analyse bits */
				proto_tree_add_bits_item(mc_tree, hf_gsm_a_gm_sms_value, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
				bit_offset	  += 4;
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;

				/*
				 * Switch-Measure value
				 */
				bits_needed = 4;
				GET_DATA;

				/* analyse bits */
				proto_tree_add_bits_item(mc_tree, hf_gsm_a_gm_sm_value, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
				bit_offset	  += 4;
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;
			}

			/*
			 * ECSD multislot class?
			 */
			bits_needed = 1;
			GET_DATA;

			/* analyse bits */
			if ((oct>>(32-bits_needed)) == 0)
			{
				proto_tree_add_uint_format_value(mc_tree, hf_gsm_a_gm_rac_ecsd_multi_slot_class, tvb, curr_offset-1-add_octets, 1+add_octets, 0xFF,
												"Bits are not available (%u)", oct>>(32-bits_needed));
				bit_offset++;
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;
			}
			else
			{
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;
				bit_offset++;

				/*
				 * ECSD multislot class
				 */
				bits_needed = 5;
				GET_DATA;

				proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_ecsd_multi_slot_class, tvb, bit_offset, 5, ENC_BIG_ENDIAN);
				bit_offset	  += 5;
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;
			}

			/*
			 * EGPRS multislot class?
			 */
			bits_needed = 1;
			GET_DATA;

			/* analyse bits */
			if ((oct>>(32-bits_needed)) == 0)
			{
				proto_tree_add_uint_format_value(mc_tree, hf_gsm_a_gm_rac_egprs_multi_slot_class, tvb, curr_offset-1-add_octets, 1+add_octets, 0xFF,
												"Bits are not available (%u)", oct>>(32-bits_needed));
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;
				bit_offset++;
			}
			else
			{
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;
				bit_offset++;

				/*
				 * EGPRS multislot class
				 */
				bits_needed = 5;
				GET_DATA;

				proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_egprs_multi_slot_class, tvb, bit_offset, 5, ENC_BIG_ENDIAN);
				bit_offset	  += 5;
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;

				/*
				 * EGPRS Extended Dynamic Allocation Capability
				 */
				bits_needed = 1;
				GET_DATA;

				proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_egprs_ext_dyn_alloc_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
				bit_offset++;
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;
			}

			/*
			 * DTM GPRS Multi Slot Class ?
			*/
			bits_needed = 1;
			GET_DATA;

			/* analyse bits */
			if ((oct>>(32-bits_needed)) == 0)
			{
				proto_tree_add_uint_format_value(mc_tree, hf_gsm_a_gm_rac_dtm_gprs_multi_slot_class, tvb, curr_offset-1-add_octets, 1+add_octets, 0xFF,
												"Bits are not available (%u)", oct>>(32-bits_needed));
				bit_offset++;
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;
			}
			else
			{
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;
				bit_offset++;

				/*
				 * DTM GPRS Multi Slot Class
				 */
				bits_needed = 2;
				GET_DATA;

				/* analyse bits */
				dtm_gprs_mslot = oct>>(32-bits_needed);

				proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_dtm_gprs_multi_slot_class, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
				bit_offset	  += 2;
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;

				/*
				 * Single Slot DTM
				 */
				bits_needed = 1;
				GET_DATA;

				proto_tree_add_bits_item(mc_tree, hf_gsm_a_gm_rac_single_slt_dtm, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
				bit_offset++;
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;

				/*
				 * DTM EGPRS Multi Slot Class ?
				*/
				bits_needed = 1;
				GET_DATA;

				/* analyse bits */
				dtm_egprs_mslot	   = oct>>(32-bits_needed);
				proto_tree_add_bits_item(mc_tree, hf_gsm_a_gm_rac_dtm_egprs_multi_slot_cls_pres, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
				bit_offset++;
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
 				bits_in_oct	  -= bits_needed;

				if ((oct>>(32-bits_needed)) == 1)
				{
					/*
					 * DTM EGPRS Multi Slot Class
					 */
					bits_needed = 2;
					GET_DATA;

					proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_dtm_egprs_multi_slot_class, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
					bit_offset	  += 2;
					curr_bits_length  -= bits_needed;
					oct		 <<= bits_needed;
					bits_in_oct	  -= bits_needed;
				}
			}
		}

		/*
		 * 8PSK Power Capability?
		 */
		bits_needed = 1;
		GET_DATA;
		value = oct>>(32-bits_needed);

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_8psk_pow_cap_pres, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset++;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/* analyse bits */
		if (value == 1)
		{
			/*
			 * 8PSK Power Capability
			 */
			bits_needed = 2;
			GET_DATA;


			proto_tree_add_uint(tf_tree, hf_gsm_a_gm_8psk_power_capability, tvb, curr_offset-1-add_octets, 1+add_octets, oct>>(32-bits_needed));
			bit_offset	  += 2;
			curr_bits_length  -= bits_needed;
			oct		 <<= bits_needed;
			bits_in_oct	  -= bits_needed;
		}

		/*
		 * COMPACT Interference Measurement Capability
		 */
		bits_needed = 1;
		GET_DATA;

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_comp_int_meas_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset++;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * Revision Level Indicator
		 */
		bits_needed = 1;
		GET_DATA;

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rel_lev_ind, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset++;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * UMTS FDD Radio Access Technology Capability
		 */
		bits_needed = 1;
		GET_DATA;

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_umts_fdd_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset++;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * UMTS 3.84 Mcps TDD Radio Access Technology Capability
		 */
		bits_needed = 1;
		GET_DATA;

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_umts_384_tdd_ra_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset++;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * CDMA 2000 Radio Access Technology Capability
		 */
		bits_needed = 1;
		GET_DATA;

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_cdma2000_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset++;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * UMTS 1.28 Mcps TDD Radio Access Technology Capability
		 */
		bits_needed = 1;
		GET_DATA;

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_umts_128_tdd_ra_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset++;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * GERAN Feature Package 1
		 */
		bits_needed = 1;
		GET_DATA;

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_geran_feat_pkg, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset++;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * Extended DTM (E)GPRS Multi Slot Class
		 */

		bits_needed = 1;
		GET_DATA;

		/* analyse bits */
		if ((oct>>(32-bits_needed)) == 0)
		{
			proto_tree_add_uint_format_value(tf_tree, hf_gsm_a_gm_extended_dtm_egprs_multi_slot_class, tvb, curr_offset-1-add_octets, 1+add_octets, 0xFF, "Bits are not available (%u)", oct>>(32-bits_needed));
			curr_bits_length  -= bits_needed;
			oct		 <<= bits_needed;
			bits_in_oct	  -= bits_needed;
			bit_offset++;
		}
		else
		{
			curr_bits_length  -= bits_needed;
			oct		 <<= bits_needed;
			bits_in_oct	  -= bits_needed;
			bit_offset++;

			/*
			 * Extended DTM GPRS Multi Slot Class
			 */
			bits_needed = 2;
			GET_DATA;

			/* analyse bits */
			proto_tree_add_uint(tf_tree, hf_gsm_a_gm_extended_dtm_gprs_multi_slot_class, tvb, curr_offset-1-add_octets, 1+add_octets, (oct>>(32-bits_needed))|(dtm_gprs_mslot<<4));
			bit_offset	  += 2;
			curr_bits_length  -= bits_needed;
			oct		 <<= bits_needed;
			bits_in_oct	  -= bits_needed;

			if (dtm_egprs_mslot <= 3)
			{
				/*
				 * Extended DTM EGPRS Multi Slot Class
				 */
				bits_needed = 2;
				GET_DATA;

				/* analyse bits */
				proto_tree_add_uint(tf_tree, hf_gsm_a_gm_extended_dtm_egprs_multi_slot_class, tvb, curr_offset-1-add_octets, 1+add_octets, (oct>>(32-bits_needed))|(dtm_egprs_mslot<<4));
				bit_offset	  += 2;
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;
			}
		}

		/*
		 * Modulation based multislot class support
		 */
		bits_needed = 1;
		GET_DATA;

		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_mod_based_multi_slot_class_support, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset++;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * High Multislot Capability
		 */
		bits_needed = 1;
		GET_DATA;

		/* analyse bits */
		if ((oct>>(32-bits_needed)) == 0)
		{
			proto_tree_add_uint_format_value(tf_tree, hf_gsm_a_gm_high_multislot_capability, tvb, curr_offset-1-add_octets, 1+add_octets, 0xFF, "Bits are not available (%u)", oct>>(32-bits_needed));
			bit_offset++;
			curr_bits_length  -= bits_needed;
			oct		 <<= bits_needed;
			bits_in_oct	  -= bits_needed;
		}
		else
		{
			curr_bits_length  -= bits_needed;
			oct		 <<= bits_needed;
			bits_in_oct	  -= bits_needed;
			bit_offset++;

			/*
			 * High Multislot Capability
			 */
			bits_needed = 2;
			GET_DATA;

			/* analyse bits */
			ti = proto_tree_add_uint(tf_tree, hf_gsm_a_gm_high_multislot_capability, tvb, curr_offset-1-add_octets, 1+add_octets, oct>>(32-bits_needed));
			proto_item_append_text(ti, " - This field effect all other multislot fields."
									    " To understand the value please read TS 24.008 5.6.0"
									    " Release 5 Chap 10.5.5.12 Page 406");
			bit_offset	  += 2;
			curr_bits_length  -= bits_needed;
			oct		 <<= bits_needed;
			bits_in_oct	  -= bits_needed;
		}

		/*
		 * GERAN Iu Mode Capability
		 */
		bits_needed = 1;
		GET_DATA;

		value		   = tvb_get_bits8(tvb, bit_offset, 1);
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_geran_iu_mode_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset	  += bits_needed;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;
		if (value)
		{
			/* GERAN Iu Mode Capabilities struct present */
			bits_needed	   = 4;
			GET_DATA;
			value		   = tvb_get_bits8(tvb, bit_offset, 4);
			bit_offset	  += bits_needed;
			curr_bits_length  -= bits_needed;
			oct		 <<= bits_needed;
			bits_in_oct	  -= bits_needed;
			if (value)
			{
				/*
				 * FLO Iu Capability
				 */
				bits_needed	   = 1;
				GET_DATA;
				proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_flo_iu_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
				bit_offset	  += bits_needed;
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;
				value--;

				/* skip spare bits */
				bit_offset	  += value;
				curr_bits_length  -= value;
				oct		 <<= value;
				bits_in_oct	  -= value;
			}
		}

		/*
		 * GMSK Multislot Power Profile
		 */
		bits_needed = 2;
		GET_DATA;

		/* analyse bits */
		proto_tree_add_uint(tf_tree, hf_gsm_a_gm_gmsk_multislot_power_profile, tvb, curr_offset-1-add_octets, 1+add_octets, oct>>(32-bits_needed));
		bit_offset	  += 2;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * 8-PSK Multislot Power Profile
		 */
		bits_needed = 2;
		GET_DATA;

		/* analyse bits */
		proto_tree_add_uint(tf_tree, hf_gsm_a_gm_8psk_multislot_power_profile, tvb, curr_offset-1-add_octets, 1+add_octets, oct>>(32-bits_needed));
		bit_offset	  += 2;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * Release 6
		 */

		/*
		 * Multiple TBF Capability
		 */
		bits_needed	   = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_mult_tbf_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset	  += bits_needed;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * Downlink Advanced Receiver Performance
		 */
		bits_needed	   = 2;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_down_adv_rec_perf, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
		bit_offset	  += bits_needed;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * Extended RLC/MAC Control Message Segmentation Capability
		 */
		bits_needed	   = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_ext_rlc_mac_ctrl_msg_seg_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset	  += bits_needed;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * DTM Enhancements Capability
		 */
		bits_needed	   = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_dtm_enh_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset	  += bits_needed;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * DTM GPRS High Multi Slot Class & DTM EGPRS High Multi Slot Class
		 */
		bits_needed = 1;
		GET_DATA;
		if ((oct>>(32-bits_needed)) == 0)
		{
			bit_offset	  += bits_needed;
			curr_bits_length  -= bits_needed;
			oct		 <<= bits_needed;
			bits_in_oct	  -= bits_needed;
		}
		else
		{
			bit_offset	  += bits_needed;
			curr_bits_length  -= bits_needed;
			oct		 <<= bits_needed;
			bits_in_oct	  -= bits_needed;

			/*
			 * DTM GPRS High Multi Slot Class
			 */
			bits_needed	   = 3;
			GET_DATA;
			proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_dtm_gprs_high_multi_slot_class, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
			bit_offset	  += bits_needed;
			curr_bits_length  -= bits_needed;
			oct		 <<= bits_needed;
			bits_in_oct	  -= bits_needed;

			bits_needed = 1;
			GET_DATA;
			if ((oct>>(32-bits_needed)) == 0)
			{
				bit_offset	  += bits_needed;
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;
			}
			else
			{
				bit_offset	  += bits_needed;
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;

				/*
				 * DTM EGPRS High Multi Slot Class
				 */
				bits_needed	   = 3;
				GET_DATA;
				proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_dtm_egprs_high_multi_slot_class, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
				bit_offset	  += bits_needed;
				curr_bits_length  -= bits_needed;
				oct		 <<= bits_needed;
				bits_in_oct	  -= bits_needed;
			}
		}

		/*
		 * PS Handover Capability
		 */
		bits_needed	   = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_ps_ho_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset	  += bits_needed;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * Release 7
		 */

		/*
		 * DTM Handover Capability
		 */
		bits_needed	   = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_dtm_ho_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset	  += bits_needed;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * Multislot Capability Reduction for Downlink Dual Carrier & Downlink Dual Carrier for DTM Capability
		 */

		bits_needed = 1;
		GET_DATA;
		if ((oct>>(32-bits_needed)) == 0)
		{
			bit_offset	  += bits_needed;
			curr_bits_length  -= bits_needed;
			oct		 <<= bits_needed;
			bits_in_oct	  -= bits_needed;
		}
		else
		{
			bit_offset	  += bits_needed;
			curr_bits_length  -= bits_needed;
			oct		 <<= bits_needed;
			bits_in_oct	  -= bits_needed;

			/*
			 * Multislot Capability Reduction for Downlink Dual Carrier
			 */
			bits_needed	   = 3;
			GET_DATA;
			proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_multi_slot_cap_red_down_dual_carrier, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
			bit_offset	  += bits_needed;
			curr_bits_length  -= bits_needed;
			oct		 <<= bits_needed;
			bits_in_oct	  -= bits_needed;

			/*
			 * Downlink Dual Carrier for DTM Capability
			 */
			bits_needed	   = 1;
			GET_DATA;
			proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_down_dual_carrier_dtm_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
			bit_offset	  += bits_needed;
			curr_bits_length  -= bits_needed;
			oct		 <<= bits_needed;
			bits_in_oct	  -= bits_needed;
		}

		/*
		 * Flexible Timeslot Assignment
		 */
		bits_needed	   = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_flex_ts_assign, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset	  += bits_needed;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * GAN PS Handover Capability
		 */
		bits_needed	   = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_gan_ps_ho_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset	  += bits_needed;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * RLC Non-persistent Mode
		 */
		bits_needed	   = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_rlc_non_pers_mode, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset	  += bits_needed;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * Reduced Latency Capability
		 */
		bits_needed	   = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_reduced_lat_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset	  += bits_needed;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * Uplink EGPRS2
		 */
		bits_needed	   = 2;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_ul_egprs2, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
		bit_offset	  += bits_needed;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * Downlink EGPRS2
		 */
		bits_needed	   = 2;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_dl_egprs2, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
		bit_offset	  += bits_needed;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * Release 8
		 */

		/*
		 * E-UTRA FDD support
		 */
		bits_needed	   = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_eutra_fdd_support, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset	  += bits_needed;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * E-UTRA TDD support
		 */
		bits_needed	   = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_eutra_tdd_support, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset	  += bits_needed;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * GERAN to E-UTRA support in GERAN packet transfer mode
		 */
		bits_needed	   = 2;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_geran_to_eutra_support_in_geran_ptm, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
		bit_offset	  += bits_needed;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * Priority-based reselection support
		 */
		bits_needed	   = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_prio_based_resel_support, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset	  += bits_needed;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * Release 9
		 */

		/*
		 * Enhanced Flexible Timeslot Assignment
		 */
		bits_needed = 1;
		GET_DATA;
		if ((oct>>(32-bits_needed)) == 0)
		{
			bit_offset	  += bits_needed;
			curr_bits_length  -= bits_needed;
			oct		 <<= bits_needed;
			bits_in_oct	  -= bits_needed;
		}
		else
		{
			bit_offset	  += bits_needed;
			curr_bits_length  -= bits_needed;
			oct		 <<= bits_needed;
			bits_in_oct	  -= bits_needed;

			/*
			 * Alternative EFTA Multislot Class
			 */
			bits_needed	   = 4;
			GET_DATA;
			proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_alt_efta_multi_slot_class, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
			bit_offset	  += bits_needed;
			curr_bits_length  -= bits_needed;
			oct		 <<= bits_needed;
			bits_in_oct	  -= bits_needed;

			/*
			 * EFTA Multislot Capability Reduction for Downlink Dual Carrier
			 */
			bits_needed	   = 3;
			GET_DATA;
			proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_efta_multi_slot_cap_red_down_dual_carrier, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
			bit_offset	  += bits_needed;
			curr_bits_length  -= bits_needed;
			oct		 <<= bits_needed;
			bits_in_oct	  -= bits_needed;
		}

		/*
		 * Indication of Upper Layer PDU Start Capability for RLC UM
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_ind_up_layer_pdu_start_cap_for_rlc_um, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset	  += bits_needed;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * EMST Capability
		 */
		bits_needed       = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_emst_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset	  += bits_needed;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * MTTI Capability
		 */
		bits_needed	   = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_mtti_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset	  += bits_needed;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * UTRA CSG Cells Reporting
		 */
		bits_needed	   = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_utra_csg_cell_report, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset	  += bits_needed;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * E-UTRA CSG Cells Reporting
		 */
		bits_needed	   = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_eutra_csg_cell_report, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset	  += bits_needed;
		curr_bits_length  -= bits_needed;
		oct		 <<= bits_needed;
		bits_in_oct	  -= bits_needed;

		/*
		 * Release 10
		 */

		 /*
		 * DTR Capability
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_dtr_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset += bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		 /*
		 * EMSR Capability
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_emsr_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset += bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		 /*
		 * Fast Downlink Frequency Switching Capability
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_fast_down_freq_switch_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset += bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		 /*
		 * TIGHTER Capability
		 */
		bits_needed = 2;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_tighter_cap, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
		bit_offset += bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * Release 11
		 */

		 /*
		 * FANR Capability
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_fanr_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset += bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		 /*
		 * IPA Capability
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_ipa_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset += bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		 /*
		 * GERAN Network Sharing support
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_geran_nw_sharing_support, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset += bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		 /*
		 * E-UTRA Wideband RSRQ measurements support
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_eutra_wb_rsrq_support, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset += bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * Release 12
		 */

		 /*
		 * UTRA Multiple Frequency Band Indicators support
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_utra_mfbi_support, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset += bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		 /*
		 * E-UTRA Multiple Frequency Band Indicators support
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_eutra_mfbi_support, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset += bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		 /*
		 * DLMC Capability
		 */
		bits_needed = 1;
		GET_DATA;
		if ((oct>>(32-bits_needed)) == 0)
		{
			bit_offset += bits_needed;
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
		}
		else
		{
			bit_offset += bits_needed;
			curr_bits_length -= bits_needed;
			oct  <<= bits_needed;
			bits_in_oct -= bits_needed;

			bits_needed = 1;
			GET_DATA;
			if ((oct>>(32-bits_needed)) == 0)
			{
				bit_offset += bits_needed;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
			}
			else
			{
				bit_offset += bits_needed;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;

				/*
				 * DLMC - Non-contiguous intra-band reception
				*/
				bits_needed = 2;
				GET_DATA;
				proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_dlmc_non_contig_intra_band_recep, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
				bit_offset += bits_needed;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;

				/*
				 * DLMC - Inter-band reception
				*/
				bits_needed = 1;
				GET_DATA;
				proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_dlmc_inter_band_recep, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
				bit_offset += bits_needed;
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
			}

			/*
			 * DLMC - Maximum Bandwidth
			*/
			bits_needed = 2;
			GET_DATA;
			proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_dlmc_max_bandwidth, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
			bit_offset += bits_needed;
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;

			/*
			 * DLMC - Maximum Number of Downlink Timeslots
			*/
			bits_needed = 6;
			GET_DATA;
			proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_dlmc_max_nb_dl_ts, tvb, bit_offset, 6, ENC_BIG_ENDIAN);
			bit_offset += bits_needed;
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;

			/*
			 * DLMC - Maximum Number of Downlink Carriers
			*/
			bits_needed = 3;
			GET_DATA;
			proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_dlmc_max_nb_dl_carriers, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
			bit_offset += bits_needed;
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
		}

		/*
		 * Extended TSC Set Capability support
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_ext_tsc_set_cap_support, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset += bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * Extended EARFCN value range
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_ext_earfcn_value_range, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset += bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * Release 13
		 */

		/*
		 * (EC-)PCH monitoring support
		 */
		bits_needed = 2;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_ec_pch_mon_support, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
		bit_offset += bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * Release 14
		 */

		/*
		 * MS Sync Accuracy
		 */
		bits_needed = 1;
		GET_DATA;
		if ((oct>>(32-bits_needed)) == 0)
		{
			bit_offset += bits_needed;
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
		}
		else
		{
			bits_needed = 4;
			GET_DATA;
			proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_ms_sync_accuracy, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
			bit_offset += bits_needed;
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
		}

		/*
		 * EC uplink coverage enhancement support
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_ec_ul_cov_enh_support, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset += bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * Release 15
		 */

		/*
		 * MTA Access Security support
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_mta_access_sec_support, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset += bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * EC paging indication channel monitoring support
		 */
		bits_needed = 1;
		GET_DATA;
		proto_tree_add_bits_item(tf_tree, hf_gsm_a_gm_rac_ec_paging_ind_chan_mon_support, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		bit_offset += bits_needed;
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		 /*
		 * we are too long ... so jump over it
		 */
		while (curr_bits_length > 0)
		{
			if (curr_bits_length > 8)
				bits_needed = 8;
			else
				bits_needed = curr_bits_length;
			GET_DATA;
			curr_bits_length  -= bits_needed;
			oct		 <<= bits_needed;
			bits_in_oct	  -= bits_needed;
		}


	} while (1);

	curr_offset += curr_len;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_gm_extraneous_data);

	return (curr_offset - offset);
}

/*
 * [9] 10.5.5.14
 */
static const range_string gmm_cause_vals[] = {
	{ 0x00, 0x01, "Protocol error, unspecified"},
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
	{ 0x12, 0x13, "Protocol error, unspecified"},
	{ 0x14, 0x14, "MAC failure"},
	{ 0x15, 0x15, "Synch failure"},
	{ 0x16, 0x16, "Congestion"},
	{ 0x17, 0x17, "GSM authentication unacceptable"},
	{ 0x18, 0x18, "Protocol error, unspecified"},
	{ 0x19, 0x19, "Not authorized for this CSG"},
	{ 0x1c, 0x1c, "SMS provided via GPRS in this routing area"},
	{ 0x20, 0x20, "Service option not supported"},						/* Annex G.4 */
	{ 0x21, 0x21, "Requested service option not subscribed"},			/* Annex G.4 */
	{ 0x22, 0x22, "Service option temporarily out of order"},			/* Annex G.4 */
	{ 0x23, 0x25, "Protocol error, unspecified"},
	{ 0x26, 0x26, "Call cannot be identified(non-GPRS services only)"},	/* Annex G.4 */
	{ 0x27, 0x27, "Protocol error, unspecified"},
	{ 0x28, 0x28, "No PDP context activated"},
	{ 0x29, 0x2f, "Protocol error, unspecified"},
	{ 0x30, 0x3f, "Retry upon entry into a new cell"},
	{ 0x40, 0x5e, "Protocol error, unspecified"},
	{ 0x5f, 0x5f, "Semantically incorrect message"},
	{ 0x60, 0x60, "Invalid mandatory information"},
	{ 0x61, 0x61, "Message type non-existent or not implemented"},
	{ 0x62, 0x62, "Message type not compatible with the protocol state"},
	{ 0x63, 0x63, "Information element non-existent or not implemented"},
	{ 0x64, 0x64, "Conditional IE error"},
	{ 0x65, 0x65, "Message not compatible with the protocol state"},
	{ 0x66, 0x6e, "Protocol error, unspecified"},
	{ 0x6f, 0x6f, "Protocol error, unspecified"},
	{ 0x70, 0xff, "Protocol error, unspecified"},
	{ 0, 0, NULL }
};
/* NOTE 1 TS 124 008 V8.6.0 (2009-07)
	"Any other value received by the mobile station shall be treated as 0110 1111, "Protocol
	error, unspecified". Any other value received by the network shall be treated as
	0110 1111, "Protocol error, unspecified".
 */

/* NOTE: The listed reject cause values are defined in annex G. */

static uint16_t
de_gmm_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	uint32_t curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_gm_cause, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	curr_offset++;

	/* no length check possible */

	return (curr_offset - offset);
}

/*
 * [7] 10.5.5.15 Routing area identification
 */
uint16_t
de_gmm_rai(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	proto_tree *subtree;
	uint32_t	    mcc;
	uint32_t	    mnc;
	uint32_t	    lac;
	uint32_t	    rac;
	uint32_t	    curr_offset;

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

	subtree = proto_tree_add_subtree_format(tree,
		tvb, curr_offset, 6, ett_gmm_rai, NULL,
		"Routing area identification: %x-%x-%u-%u",
		mcc, mnc, lac, rac);

	dissect_e212_mcc_mnc(tvb, pinfo, subtree, offset, E212_RAI, true);

	proto_tree_add_item(subtree, hf_gsm_a_lac, tvb, curr_offset+3, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(subtree, hf_gsm_a_gm_rac, tvb, curr_offset+5, 1, ENC_BIG_ENDIAN);

	curr_offset += 6;
	if (add_string)
	{
		if (add_string[0] == '\0')
		{
			snprintf(add_string, string_len, " - RAI: %x-%x-%u-%u", mcc, mnc, lac, rac);
		}
	}


	/* no length check possible */

	return (curr_offset - offset);
}

/*
 * [7] 10.5.5.15a Routing area identification 2
 */
static uint16_t
de_gmm_rai2(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	/* The routing area identification 2 value is coded as octet 2 to 7 of the Routing area identification information element. */
	return de_gmm_rai(tvb, tree, pinfo, offset, len, add_string, string_len);
}

/*
 * [7] 10.5.5.17
 */
static const value_string gsm_a_gm_update_res_vals[] = {
	{0,  "RA updated" },
	{1,  "Combined RA/LA updated"},
	{2,  "Reserved"},
	{3,  "Reserved"},
	{4,  "Reserved"},
	{5,  "Reserved"},
	{6,  "Reserved"},
	{7,  "Reserved"},
	{0, NULL}
};


static uint16_t
de_gmm_update_res(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	uint32_t     curr_offset = offset;

	/* IMPORTANT - IT'S ASSUMED THAT THE INFORMATION IS IN THE HIGHER NIBBLE */
	proto_tree_add_item(tree, hf_gsm_a_gm_update_result, tvb, curr_offset, 1, ENC_NA);

	curr_offset++;

	/* no length check possible */

	return (curr_offset - offset);
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

static uint16_t
de_gmm_update_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_item(tree, hf_gsm_a_gm_for, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_update_type, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* no length check possible */
	return 1;
}

/*
 * [9] 10.5.5.19 A&C reference number (lower nibble)
 */
static uint16_t
de_gmm_ac_ref_nr(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	/* IMPORTANT - IT'S ASSUMED THAT THE INFORMATION IS IN THE LOWER NIBBLE */
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_ac_ref_nr, tvb, (offset << 3) + 4, 4, ENC_BIG_ENDIAN);

	/* no length check possible */
	return 1;
}

/*
 * [9] 10.5.5.19 A&C reference number (higher nibble)
 */
static uint16_t
de_gmm_ac_ref_nr_h(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	/* IMPORTANT - IT'S ASSUMED THAT THE INFORMATION IS IN THE HIGHER NIBBLE */
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_ac_ref_nr, tvb, offset << 3, 4, ENC_BIG_ENDIAN);

	/* no length check possible */
	return 1;
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

static uint16_t
de_gmm_service_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	uint32_t	bit_offset;

	bit_offset = offset << 3;
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset  +=  1;
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_serv_type, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
	/*bit_offset  +=  3;*/

	/* no length check possible */
	return 1;
}

/*
 * [9] 10.5.5.21 Cell Notification
 * No data
 */

/*
 * [9] 10.5.5.22 PS LCS Capability
 */
static const true_false_string gsm_a_gm_mta_e_vals = {
	"Multilateration Timing Advance using Extended Access Burst method supported",
	"Multilateration Timing Advance using Extended Access Burst method not supported"
};

static const true_false_string gsm_a_gm_mta_r_vals = {
	"Multilateration Timing Advance using RLC data block method supported",
	"Multilateration Timing Advance using RLC data block method not supported"
};

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

static const true_false_string gsm_a_gm_motd_vals = {
	"Multilateration Observed Time Difference supported",
	"Multilateration Observed Time Difference not supported"
};

static const true_false_string gsm_a_gm_mta_a_vals = {
	"Multilateration Timing Advance using Access Burst method supported",
	"Multilateration Timing Advance using Access Burst method not supported"
};

static uint16_t
de_gmm_ps_lcs_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	uint32_t	curr_offset;

	curr_offset = offset;
	proto_tree_add_item(tree, hf_gsm_a_gm_mta_e, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_mta_r, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_apc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_otd_a, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_otd_b, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_gps_a, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_gps_b, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_gps_c, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	curr_offset++;

	if (len > 2) {
		proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, curr_offset << 3, 6, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_gsm_a_gm_motd, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_gsm_a_gm_mta_a, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	}

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_gm_extraneous_data);

	return (curr_offset - offset);
}

/*
 * [7] 10.5.5.23
 */
static const true_false_string gsm_a_gm_lcs_molr_value = {
	"LCS-MOLR via PS domain supported",
	"LCS-MOLR via PS domain not supported"
};
static const true_false_string gsm_a_gm_ims_vops_value = {
	"IMS voice over PS session supported in Iu mode, but not supported in A/Gb mode",
	"IMS voice over PS session in Iu mode and A/Gb mode not supported"
};
static const true_false_string gsm_a_gm_emc_bs_value = {
	"Emergency bearer services supported in Iu mode, but not supported in A/Gb mode",
	"Emergency bearer services in Iu mode and A/Gb mode not supported"
};
static uint16_t
de_gmm_net_feat_supp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	uint32_t curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_gm_lcs_molr, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_mbms, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_ims_vops, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_emc_bs, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return (curr_offset - offset);
}

/*
 * [7] 10.5.5.23a Additional network feature support
 */
static const true_false_string gsm_a_gm_epco_value = {
	"Extended protocol configuration options IE supported",
	"Extended protocol configuration options IE not supported"
};
static const true_false_string gsm_a_gm_restrict_ec_value = {
	"Enhanced coverage restricted",
	"Enhanced coverage not restricted"
};
static const true_false_string gsm_a_gm_gprs_sms_value = {
	"SMS via GPRS not supported",
	"SMS via GPRS supported"
};
static uint16_t
de_gmm_add_net_feat_supp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	uint32_t curr_offset;

	curr_offset = offset;

	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, curr_offset << 3, 5, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_epco, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_restrict_ec, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_gprs_sms, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return (curr_offset - offset);
}

/* [7] 10.5.5.24 Inter RAT information container */
static uint16_t
de_gmm_rat_info_container(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t  curr_offset;
	tvbuff_t *rrc_irat_ho_info_tvb;

	curr_offset = offset;

/* The value part of the Inter RAT information container information element is the INTER RAT HANDOVER INFO as
defined in 3GPP TS 25.331 [23c]. If this field includes padding bits, they are defined in 3GPP TS 25.331 [23c].*/
	rrc_irat_ho_info_tvb = tvb_new_subset_length(tvb, curr_offset, len);
	if (rrc_irat_ho_info_handle)
		call_dissector(rrc_irat_ho_info_handle, rrc_irat_ho_info_tvb, pinfo, tree);
	else
		proto_tree_add_expert_format(tree, pinfo, &ei_gsm_a_gm_undecoded, tvb, curr_offset, len, "INTER RAT HANDOVER INFO - Not decoded");

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

static uint16_t
de_gmm_req_ms_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t	curr_offset;
	uint32_t bit_offset;

	curr_offset = offset;
	bit_offset  = (curr_offset<<3)+4;

	proto_tree_add_bits_item(tree, hf_gsm_a_gm_req_ms_info_irat, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_req_ms_info_irat2, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
	/*bit_offset += 2;
	curr_offset++;*/

	return len;
}

/* [7] 10.5.5.26 UE network capability
 * See subclause 9.9.3.x in 3GPP TS 24.301 [120].
 */

/* [7] 10.5.5.27 E-UTRAN inter RAT information container */
static uint16_t
de_gmm_eutran_irat_info_container(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t  curr_offset;
	tvbuff_t *lte_rrc_ue_eutra_cap_tvb;

	curr_offset = offset;

/* The value part of the E-UTRAN inter RAT information container information element
   is formatted and coded according to the UE-EUTRA-Capability IE defined in 3GPP TS 36.331 [129]*/
	lte_rrc_ue_eutra_cap_tvb = tvb_new_subset_length(tvb, curr_offset, len);
	if (lte_rrc_ue_eutra_cap_handle)
		call_dissector(lte_rrc_ue_eutra_cap_handle, lte_rrc_ue_eutra_cap_tvb, pinfo, tree);
	else
		proto_tree_add_expert_format(tree, pinfo, &ei_gsm_a_gm_undecoded, tvb, curr_offset, len, "E-UTRAN Inter RAT information container - Not decoded");

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

uint16_t
de_gmm_voice_domain_pref(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t	curr_offset;
	uint32_t bit_offset;

	curr_offset = offset;
	bit_offset  = curr_offset<<3;

	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, bit_offset, 5, ENC_BIG_ENDIAN);
	bit_offset += 5;
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_ue_usage_setting, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_voice_domain_pref_for_eutran, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
	/*bit_offset += 2;
	curr_offset++;*/

	return len;
}

/* [10] 10.5.5.29 P-TMSI type */
static const true_false_string gsm_a_gm_ptmsi_type_value = {
	"Mapped P-TMSI",
	"Native P-TMSI"
};

static uint16_t
de_gmm_ptmsi_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	uint32_t curr_offset, bit_offset;

	curr_offset = offset;
	bit_offset  = (curr_offset<<3)+4;

	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
	bit_offset += 3;
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_ptmsi_type, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return (curr_offset - offset);
}

/* [10] 10.5.5.30 Location Area Identification 2 */
static uint16_t
de_gmm_lai_2(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len)
{
	/* The Location Area Identification 2 value is coded as octet 2 to 6 of the */
	/* Location Area Identification information element */
	return de_lai(tvb, tree, pinfo, offset, len, add_string, string_len);
}

/* [11] 10.5.5.31 Network resource identifier container */
static uint16_t
de_gmm_net_res_id_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t	curr_offset;
	uint32_t bit_offset;

	curr_offset = offset;
	bit_offset  = curr_offset<<3;

	proto_tree_add_item(tree, hf_gsm_a_gm_nri_cont, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
	bit_offset += 10;
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, bit_offset, 6, ENC_BIG_ENDIAN);

	return len;
}

/* [13] 10.5.5.32 Extended DRX parameters */
static const value_string gsm_a_gm_paging_time_window_vals[] = {
	{0x0,	"Iu: 0 s / WB-S1/WB-N1: 1.28 s / NB-S1/NB-N1: 2.56 s"},
	{0x1,	"Iu: 1 s / WB-S1/WB-N1: 2.56 s / NB-S1/NB-N1: 5.12 s"},
	{0x2,	"Iu: 2 s / WB-S1/WB-N1: 3.84 s / NB-S1/NB-N1: 7.68 s"},
	{0x3,	"Iu: 3 s / WB-S1/WB-N1: 5.12 s / NB-S1/NB-N1: 10.24 s"},
	{0x4,	"Iu: 4 s / WB-S1/WB-N1: 6.4 s / NB-S1/NB-N1: 12.8 s"},
	{0x5,	"Iu: 5 s / WB-S1/WB-N1: 7.68 s / NB-S1/NB-N1: 15.36 s"},
	{0x6,	"Iu: 6 s / WB-S1/WB-N1: 8.96 s / NB-S1/NB-N1: 17.92 s"},
	{0x7,	"Iu: 7 s / WB-S1/WB-N1: 10.24 s / NB-S1/NB-N1: 20.48 s"},
	{0x8,	"Iu: 8 s / WB-S1/WB-N1: 11.52 s / NB-S1/NB-N1: 23.04 s"},
	{0x9,	"Iu: 9 s / WB-S1/WB-N1: 12.8 s / NB-S1/NB-N1: 25.6 s"},
	{0xa,	"Iu: 10 s / WB-S1/WB-N1: 14.08 s / NB-S1/NB-N1: 28.16 s"},
	{0xb,	"Iu: 12 s / WB-S1/WB-N1: 15.36 s / NB-S1/NB-N1: 30.72 s"},
	{0xc,	"Iu: 14 s / WB-S1/WB-N1: 16.64 s / NB-S1/NB-N1: 33.28 s"},
	{0xd,	"Iu: 16 s / WB-S1/WB-N1: 17.92 s / NB-S1/NB-N1: 35.84 s"},
	{0xe,	"Iu: 18 s / WB-S1/WB-N1: 19.2 s / NB-S1/NB-N1: 38.4 s"},
	{0xf,	"Iu: 20 s / WB-S1/WB-N1: 20.48 s / NB-S1/NB-N1: 40.96 s"},
	{  0,	NULL }
};

static const value_string gsm_a_gm_edrx_vals[] = {
	{0x0,	"GERAN: 1.88 s / UTRAN: 10.24 s / S1,NB-N1,WB-N1: 5.12 s / NR-5GCN: 2.56 s"},
	{0x1,	"GERAN: 3.76 s / UTRAN: 20.48 s / S1,NB-N1,WB-N1: 10.24 s / NR-5GCN: 5.12 s"},
	{0x2,	"GERAN: 7.53 s / UTRAN: 40.96 s / S1,NB-N1,WB-N1: 20.48 s / NR-5GCN: 10.24 s"},
	{0x3,	"GERAN: 12.24 s / UTRAN: 81.92 s / S1,NB-N1,WB-N1: 40.96 s / NR-5GCN: 20,48 s"},
	{0x4,	"GERAN: 24.48 s / UTRAN: 163.84 s / S1,NB-N1,WB-N1: 61.44 s / NR-5GCN: 40.96 s"},
	{0x5,	"GERAN: 48.96 s / UTRAN: 327.68 s / S1,NB-N1,WB-N1: 81.92 s / NR-5GCN: 81.92 s"},
	{0x6,	"GERAN: 97.92 s / UTRAN: 655.36 s / S1,NB-N1,WB-N1: 102.4 s / NR-5GCN: 163.84 s"},
	{0x7,	"GERAN: 195.84 s / UTRAN: 1310.72 s / S1,NB-N1,WB-N1: 122.88 s / NR-5GCN: 327.68 s"},
	{0x8,	"GERAN: 391.68 s / UTRAN: 1966.08 s / S1,NB-N1,WB-N1: 143.36 s / NR-5GCN: 655.36 s"},
	{0x9,	"GERAN: 783.36 s / UTRAN: 2621.44 s / S1,NB-N1,WB-N1: 163.84 s / NR-5GCN: 1310.72 s"},
	{0xa,	"GERAN: 1566.72 s / UTRAN: 10.24 s / S1,NB-N1,WB-N1: 327.68 s / NR-5GCN: 2621.44 s"},
	{0xb,	"GERAN: 3133.44 s / UTRAN: 10.24 s / S1,NB-N1,WB-N1: 655.36 s / NR-5GCN: 5242.88 s"},
	{0xc,	"GERAN: 1.88 s / UTRAN: 10.24 s / S1,NB-N1,WB-N1: 1310.72 s / NR-5GCN: 10485.76 s"},
	{0xd,	"GERAN: 1.88 s / UTRAN: 10.24 s / S1,NB-N1,WB-N1: 2621.44 s / NR-5GCN: 2.56 s"},
	{0xe,	"GERAN: 1.88 s / UTRAN: 10.24 s / S1,NB-N1,WB-N1: 5242.88 s / NR-5GCN: 2.56 s"},
	{0xf,	"GERAN: 1.88 s / UTRAN: 10.24 s / S1,NB-N1,WB-N1: 10485.76 s / NR-5GCN: 2.56 s"},
	{  0,	NULL }
};

static const value_string gsm_a_gm_paging_time_window_nr_5gcn_vals[] = {
	{0x00,	"NR-5GCN: 1.28 s"},
	{0x01,	"NR-5GCN: 2.56 s"},
	{0x02,	"NR-5GCN: 3.84 s"},
	{0x03,	"NR-5GCN: 5.12 s"},
	{0x04,	"NR-5GCN: 6.4 s"},
	{0x05,	"NR-5GCN: 7.68 s"},
	{0x06,	"NR-5GCN: 8.96 s"},
	{0x07,	"NR-5GCN: 10.24 s"},
	{0x08,	"NR-5GCN: 11.52 s"},
	{0x09,	"NR-5GCN: 12.8 s"},
	{0x0a,	"NR-5GCN: 14.08 s"},
	{0x0b,	"NR-5GCN: 15.36 s"},
	{0x0c,	"NR-5GCN: 16.64 s"},
	{0x0d,	"NR-5GCN: 17.92 s"},
	{0x0e,	"NR-5GCN: 19.2 s"},
	{0x0f,	"NR-5GCN: 20.48 s"},
	{0x10,	"NR-5GCN: 21.76 s"},
	{0x11,	"NR-5GCN: 23.04 s"},
	{0x12,	"NR-5GCN: 24.32 s"},
	{0x13,	"NR-5GCN: 25.6 s"},
	{0x14,	"NR-5GCN: 26.88 s"},
	{0x15,	"NR-5GCN: 28.16 s"},
	{0x16,	"NR-5GCN: 29.44 s"},
	{0x17,	"NR-5GCN: 30.72 s"},
	{0x18,	"NR-5GCN: 32 s"},
	{0x19,	"NR-5GCN: 33.28 s"},
	{0x1a,	"NR-5GCN: 34.56 s"},
	{0x1b,	"NR-5GCN: 35.84 s"},
	{0x1c,	"NR-5GCN: 37.12 s"},
	{0x1d,	"NR-5GCN: 38.4 s"},
	{0x1e,	"NR-5GCN: 39.68 s"},
	{0x1f,	"NR-5GCN: 40.96 s"},
	{  0,	NULL }
};

static uint16_t
de_gmm_ext_drx_params(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_gm_paging_time_window, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_edrx_value, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	if ((curr_offset - offset) >= len)
		return len;

	proto_tree_add_item(tree, hf_gsm_a_gm_ext_paging_time_window, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	return len;
}

/* [13] 10.5.5.33 Message authentication code */
static uint16_t
de_gmm_mac(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_item(tree, hf_gsm_a_gm_mac, tvb, offset, 4, ENC_BIG_ENDIAN);

	return len;
}

/* [13] 10.5.5.34 User Plane integrity indicator */
static const true_false_string gsm_a_gm_up_integ_ind_value = {
	"MS shall enable integrity protection of user plane data in LLC layer",
	"MS shall disable integrity protection of user plane data in LLC layer"
};

static uint16_t
de_gmm_up_integ_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (offset << 3) + 4, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_up_integ_ind, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* no length check possible */
	return 1;
}

/* [14] 10.5.5.35 DCN-ID */
static uint16_t
de_gmm_dcn_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_item(tree, hf_gsm_a_gm_dcn_id, tvb, offset, 2, ENC_BIG_ENDIAN);

	return 2;
}

/* [14] 10.5.5.36 PLMN identity of the CN operator */
static uint16_t
de_gmm_plmn_id_cn_operator(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	dissect_e212_mcc_mnc(tvb, pinfo, tree, offset, E212_NONE, true);

	return 3;
}

/* [14] 10.5.5.37 Non-3GPP NW provided policies */
static const true_false_string gsm_a_gm_n3en_ind_value = {
	"Use of non-3GPP emergency numbers permitted",
	"Use of non-3GPP emergency numbers not permitted"
};

static uint16_t
de_gmm_non_3gpp_nw_prov_pol(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (offset << 3) + 4, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_gm_n3en_ind, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* no length check possible */
	return 1;
}

/*
 * [7] 10.5.7.1
 */
static uint16_t
de_gc_context_stat(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	uint8_t     oct;
	uint16_t    pdp_nr;
	uint32_t    curr_offset;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	for (pdp_nr=0; pdp_nr<16; pdp_nr++)
	{
		if (pdp_nr == 8)
		{
			curr_offset++;
			oct = tvb_get_guint8(tvb, curr_offset);
		}
		proto_tree_add_uint_format(tree, hf_gsm_a_gm_nsapi, tvb, curr_offset, 1, oct&1, "NSAPI %d: %s (%u)", pdp_nr, pdp_str[oct&1], oct&1);
		oct>>=1;
	}

	curr_offset++;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_gm_extraneous_data);

	return (curr_offset - offset);
}

/*
 * [7] 10.5.7.2
 */
static const value_string gsm_a_gm_radio_prio_vals[] = {
	{0,  "priority level 4 (lowest)" },
	{1,  "priority level 1 (highest)"},
	{2,  "priority level 2"},
	{3,  "priority level 3"},
	{4,  "priority level 4 (lowest)"},
	{5,  "priority level 4 (lowest)"},
	{6,  "priority level 4 (lowest)"},
	{7,  "priority level 4 (lowest)"},
	{0, NULL}
};

static uint16_t
de_gc_radio_prio(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	uint32_t     curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_gm_radio_priority_pdp, tvb, curr_offset, 1, ENC_NA);

	curr_offset++;

	return (curr_offset - offset);
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

uint16_t
de_gc_timer(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	uint8_t      oct;
	uint16_t     val;
	const char *str;
	proto_item  *item = NULL;
	proto_tree  *subtree;

	oct = tvb_get_guint8(tvb, offset);
	val = oct&0x1f;

	switch (oct>>5)
	{
		case 0:
			str = "sec"; val*=2;
			break;
		case 1:
			str = "min";
			break;
		case 2:
			str = "min"; val*=6;
			break;
		case 7:
			str = "";
			item = proto_tree_add_uint_format_value(tree, hf_gsm_a_gm_gprs_timer, tvb, offset, 1, val, "timer is deactivated");
			break;
		default:  str = "min";
	}

	if (item == NULL) {
		item = proto_tree_add_uint_format_value(tree, hf_gsm_a_gm_gprs_timer, tvb, offset, 1, val, "%u %s", val, str);
	}

	subtree = proto_item_add_subtree(item, ett_gmm_gprs_timer);
	proto_tree_add_item(subtree, hf_gsm_a_gm_gprs_timer_unit, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(subtree, hf_gsm_a_gm_gprs_timer_value, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* no length check possible */
	return 1;
}

/*
 * [7] 10.5.7.4
 */
static uint16_t
de_gc_timer2(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string, int string_len _U_)
{
	uint8_t      oct;
	uint16_t     val;
	uint32_t     curr_offset;
	const char *str = NULL;
	proto_tree  *subtree;
	proto_item  *item = NULL;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	val = oct&0x1f;

	switch (oct>>5)
	{
		case 0:
			str = "sec"; val*=2;
			break;
		case 1:
			str = "min";
			break;
		case 2:
			str = "min"; val*=6;
			break;
		case 7:
			item = proto_tree_add_uint_format_value(tree, hf_gsm_a_gm_gprs_timer2, tvb, curr_offset, 1, val, "timer is deactivated");
			break;
		default:  str = "min";
	}

	if (item == NULL) {
		item = proto_tree_add_uint_format_value(tree, hf_gsm_a_gm_gprs_timer2, tvb, curr_offset, 1, val, "%u %s %s", val, str, add_string ? add_string : "");
	}

	subtree = proto_item_add_subtree(item, ett_gmm_gprs_timer);
	proto_tree_add_item(subtree, hf_gsm_a_gm_gprs_timer2_unit, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(subtree, hf_gsm_a_gm_gprs_timer2_value, tvb, offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return (curr_offset - offset);
}

/*
 * [10] 10.5.7.4a
 */
static const value_string gsm_a_gm_gprs_timer3_unit_vals[] = {
	{ 0x00, "value is incremented in multiples of 10 minutes" },
	{ 0x01, "value is incremented in multiples of 1 hour" },
	{ 0x02, "value is incremented in multiples of 10 hours" },
	{ 0x03, "value is incremented in multiples of 2 seconds" },
	{ 0x04, "value is incremented in multiples of 30 seconds" },
	{ 0x05, "value is incremented in multiples of 1 minute" },
	{ 0x06, "value is incremented in multiples of 320 hours (for T3312/T3412 extended), 1 hour otherwise" },
	{ 0x07, "value indicates that the timer is deactivated" },
	{ 0, NULL }
};

uint16_t
de_gc_timer3(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	uint8_t      oct;
	uint16_t     val;
	uint32_t     curr_offset;
	const char *str = NULL;
	proto_tree  *subtree;
	proto_item  *item = NULL;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	val = oct&0x1f;

	switch (oct>>5)
	{
		case 0:  str = "min"; val*=10; break;
		case 1:  str = "hr"; break;
		case 2:  str = "hr"; val*=10; break;
		case 3:  str = "sec"; val*=2; break;
		case 4:  str = "sec"; val*=30; break;
		case 5:  str = "min"; break;
		case 6:  str = "hours"; val *= 320; break;
		case 7:
			item = proto_tree_add_uint_format_value(tree, hf_gsm_a_gm_gprs_timer3, tvb, curr_offset, 1, val, "timer is deactivated");
			break;
	}

	if (item == NULL) {
		item = proto_tree_add_uint_format_value(tree, hf_gsm_a_gm_gprs_timer3, tvb, curr_offset, 1, val, "%u %s", val, str);
	}

	subtree = proto_item_add_subtree(item, ett_gmm_gprs_timer);
	proto_tree_add_item(subtree, hf_gsm_a_gm_gprs_timer3_unit, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(subtree, hf_gsm_a_gm_gprs_timer3_value, tvb, offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return (curr_offset - offset);
}

/*
 * [7] 10.5.7.5
 */
static uint16_t
de_gc_radio_prio2(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	uint32_t     curr_offset = offset;

	/* IMPORTANT - IT'S ASSUMED THAT THE INFORMATION IS IN THE HIGHER NIBBLE */
	proto_tree_add_item(tree, hf_gsm_a_gm_radio_priority_tom8, tvb, curr_offset, 1, ENC_NA);

	curr_offset++;

	return (curr_offset - offset);
}

/*
 * [8] 10.5.7.6 MBMS context status
 */
static uint16_t
de_gc_mbms_context_stat(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t    curr_offset;
	unsigned    i;
	uint8_t     oct, j;

	curr_offset = offset;

	for (i=0; i<len; i++)
	{
		oct = tvb_get_guint8(tvb, curr_offset);

		for (j=0; j<8; j++)
		{
			proto_tree_add_uint_format(tree, hf_gsm_a_gm_nsapi, tvb, curr_offset, 1, oct&1, "NSAPI %d: %s (%u)", 128+i*8+j, pdp_str[oct&1], oct&1);
			oct>>=1;
		}
		curr_offset++;
	}

	return (len);
}

/*
 * [8] 10.5.7.7 Uplink data status
 */
static const true_false_string gsm_a_gm_nsapi_ul_stat_vals = {
	"uplink data are pending for the preserved PDP context",
	"no uplink data are pending for the preserved PDP context or the PDP context is PDP-INACTIVE or is PDP-ACTIVE with a RAB already established"
};

static uint16_t
de_gc_uplink_data_stat(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t	curr_offset;
	uint32_t bit_offset;

	curr_offset = offset;
	bit_offset  = curr_offset<<3;

	proto_tree_add_bits_item(tree, hf_gsm_a_gm_nsapi_7_ul_stat, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_nsapi_6_ul_stat, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_nsapi_5_ul_stat, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, bit_offset, 5, ENC_BIG_ENDIAN);
	bit_offset += 5;
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
/*
	bit_offset++;
	curr_offset++;
*/
	return (len);
}

/*
 * [8] 10.5.7.8 Device properties
 */
static const true_false_string gsm_a_gm_device_prop_low_prio_value = {
	"MS is configured for NAS signalling low priority",
	"MS is not configured for NAS signalling low priority"
};

static uint16_t
de_gc_device_properties(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	uint32_t	curr_offset;
	uint32_t bit_offset;

	curr_offset = offset;
	bit_offset  = (curr_offset<<3)+4;

	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
	bit_offset += 3;
	proto_tree_add_bits_item(tree, hf_gsm_a_gm_device_prop_low_prio, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return (curr_offset - offset);
}

/*
 * [7] 10.5.6.1
 */
uint16_t
de_sm_apn(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t    curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_gm_apn, tvb, curr_offset, len, ENC_APN_STR | ENC_NA);
	curr_offset += len;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_gm_extraneous_data);

	return (curr_offset - offset);
}

/*
 * [7] 10.5.6.2
 */
static uint16_t
de_sm_nsapi(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string, int string_len _U_)
{
	uint8_t	oct;
	uint32_t	curr_offset;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	proto_tree_add_uint_format_value(tree, hf_gsm_a_gm_nsapi, tvb, curr_offset, 1, oct&0x0f, "0x%02x (%u) %s", oct&0x0f, oct&0x0f, add_string ? add_string : "");

	curr_offset++;

	return (curr_offset - offset);
}

/*
 * [7] 10.5.6.3 Protocol configuration options
 */
static const range_string gsm_a_sm_pco_ms2net_prot_vals[] = {
	{ 0x0001, 0x0001, "P-CSCF IPv6 Address Request" },
	{ 0x0002, 0x0002, "IM CN Subsystem Signaling Flag" },
	{ 0x0003, 0x0003, "DNS Server IPv6 Address Request" },
	{ 0x0004, 0x0004, "Not Supported" },
	{ 0x0005, 0x0005, "MS Support of Network Requested Bearer Control indicator" },
	{ 0x0006, 0x0006, "Reserved" },
	{ 0x0007, 0x0007, "DSMIPv6 Home Agent Address Request" },
	{ 0x0008, 0x0008, "DSMIPv6 Home Network Prefix Request" },
	{ 0x0009, 0x0009, "DSMIPv6 IPv4 Home Agent Address Request" },
	{ 0x000a, 0x000a, "IP address allocation via NAS signalling" },
	{ 0x000b, 0x000b, "IPv4 address allocation via DHCPv4" },
	{ 0x000c, 0x000c, "P-CSCF IPv4 Address Request" },
	{ 0x000d, 0x000d, "DNS Server IPv4 Address Request" },
	{ 0x000e, 0x000e, "MSISDN Request" },
	{ 0x000f, 0x000f, "IFOM-Support-Request" },
	{ 0x0010, 0x0010, "IPv4 Link MTU Request" },
	{ 0x0011, 0x0011, "MS support of Local address in TFT indicator" },
	{ 0x0012, 0x0012, "P-CSCF Re-selection support" },
	{ 0x0013, 0x0013, "NBIFOM request indicator" },
	{ 0x0014, 0x0014, "NBIFOM mode" },
	{ 0x0015, 0x0015, "Non-IP Link MTU Request" },
	{ 0x0016, 0x0016, "APN rate control support indicator" },
	{ 0x0017, 0x0017, "3GPP PS data off UE status" },
	{ 0x0018, 0x0018, "Reliable Data Service request indicator" },
	{ 0x0019, 0x0019, "Additional APN rate control for exception data support indicator" },
	{ 0x001a, 0x001a, "PDU session ID" },
	{ 0x001b, 0x001f, "Reserved" },
	{ 0x0020, 0x0020, "Ethernet Frame Payload MTU Request" },
	{ 0x0021, 0x0021, "Unstructured Link MTU Request" },
	{ 0x0022, 0x0022, "5GSM cause value" },
	{ 0x0023, 0x0023, "QoS rules with the length of two octets support indicator" },
	{ 0x0024, 0x0024, "QoS flow descriptions with the length of two octets support indicator" },
	{ 0x0027, 0x0027, "ACS information request" },
	{ 0x0030, 0x0030, "ATSSS request" },
	{ 0x0031, 0x0031, "DNS server security information indicator" },
	{ 0x0032, 0x0032, "ECS configuration information provisioning support indicator" },
	{ 0x0036, 0x0036, "PVS information request" },
	{ 0x0039, 0x0039, "DNS server security protocol support" },
	{ 0x003a, 0x003a, "EAS rediscovery support indication" },
	{ 0x0041, 0x0041, "Service-level-AA container with the length of two octets" },
	{ 0x0047, 0x0047, "EDC support indicator" },
	{ 0x004a, 0x004a, "MS support of MAC address range in 5GS indicator" },
	{ 0x0050, 0x0050, "SDNAEPC support indicator" },
	{ 0x0051, 0x0051, "SDNAEPC EAP message with the length of two octets" },
	{ 0x0052, 0x0052, "SDNAEPC DN-specific identity" },
	{ 0x0056, 0x0056, "UE policy container with the length of two octets" },
	{ 0xff00, 0xffff, "Operator Specific Use" },
	{ 0, 0, NULL }
};
static const range_string gsm_a_sm_pco_net2ms_prot_vals[] = {
	{ 0x0001, 0x0001, "P-CSCF IPv6 Address" },
	{ 0x0002, 0x0002, "IM CN Subsystem Signaling Flag" },
	{ 0x0003, 0x0003, "DNS Server IPv6 Address" },
	{ 0x0004, 0x0004, "Policy Control rejection code" },
	{ 0x0005, 0x0005, "Selected Bearer Control Mode" },
	{ 0x0006, 0x0006, "Reserved" },
	{ 0x0007, 0x0007, "DSMIPv6 Home Agent Address" },
	{ 0x0008, 0x0008, "DSMIPv6 Home Network Prefix" },
	{ 0x0009, 0x0009, "DSMIPv6 IPv4 Home Agent Address" },
	{ 0x000a, 0x000a, "Reserved" },
	{ 0x000b, 0x000b, "Reserved" },
	{ 0x000c, 0x000c, "P-CSCF IPv4 Address" },
	{ 0x000d, 0x000d, "DNS Server IPv4 Address" },
	{ 0x000e, 0x000e, "MSISDN" },
	{ 0x000f, 0x000f, "IFOM-Support" },
	{ 0x0010, 0x0010, "IPv4 Link MTU" },
	{ 0x0011, 0x0011, "Network support of Local address in TFT indicator" },
	{ 0x0012, 0x0012, "Reserved" },
	{ 0x0013, 0x0013, "NBIFOM accepted indicator" },
	{ 0x0014, 0x0014, "NBIFOM mode" },
	{ 0x0015, 0x0015, "Non-IP Link MTU" },
	{ 0x0016, 0x0016, "APN rate control parameters" },
	{ 0x0017, 0x0017, "3GPP PS data off support indication" },
	{ 0x0018, 0x0018, "Reliable Data Service accepted indicator" },
	{ 0x0019, 0x0019, "Additional APN rate control for exception data parameters" },
	{ 0x001a, 0x001a, "Reserved" },
	{ 0x001b, 0x001b, "S-NSSAI" },
	{ 0x001c, 0x001c, "QoS rules" },
	{ 0x001d, 0x001d, "Session-AMBR" },
	{ 0x001e, 0x001e, "PDU session address lifetime" },
	{ 0x001f, 0x001f, "QoS flow descriptions" },
	{ 0x0020, 0x0020, "Ethernet Frame Payload MTU" },
	{ 0x0021, 0x0021, "Unstructured Link MTU" },
	{ 0x0022, 0x0022, "Reserved" },
	{ 0x0023, 0x0023, "QoS rules with the length of two octets" },
	{ 0x0024, 0x0024, "QoS flow descriptions with the length of two octets" },
	{ 0x0025, 0x0025, "Small data rate control parameters" },
	{ 0x0026, 0x0026, "Additional small data rate control for exception data parameters" },
	{ 0x0027, 0x0027, "ACS information" },
	{ 0x0028, 0x0028, "Initial small data rate control parameters" },
	{ 0x0029, 0x0029, "Initial additional small data rate control for exception data parameters" },
	{ 0x002a, 0x002a, "Initial APN rate control parameters" },
	{ 0x002b, 0x002b, "Initial additional APN rate control for exception data parameters" },
	{ 0x0030, 0x0030, "ATSSS response with the length of two octets" },
	{ 0x0031, 0x0031, "DNS server security information with length of two octets" },
	{ 0x0032, 0x0032, "ECS address with the length of two octets" },
	{ 0x0035, 0x0035, "ECSP identifier" },
	{ 0x0036, 0x0036, "PVS IPv4 Address" },
	{ 0x0037, 0x0037, "PVS IPv6 Address" },
	{ 0x0038, 0x0038, "PVS name" },
	{ 0x003a, 0x003a, "EAS rediscovery indication without indicated impact" },
	{ 0x003b, 0x003b, "EAS rediscovery indication with impacted EAS IPv4 address range" },
	{ 0x003c, 0x003c, "EAS rediscovery indication with impacted EAS IPv6 address range" },
	{ 0x003d, 0x003d, "EAS rediscovery indication with impacted EAS FQDN" },
	{ 0x003e, 0x003e, "Uplink data not allowed" },
	{ 0x003f, 0x003f, "Uplink data allowed" },
	{ 0x0040, 0x0040, "UAS services not allowed indication" },
	{ 0x0041, 0x0041, "Service-level-AA container with the length of two octets" },
	{ 0x0048, 0x0048, "EDC usage allowed indicator" },
	{ 0x0049, 0x0049, "EDC usage required indicator" },
	{ 0x004a, 0x004a, "Network support of MAC address range in 5GS indicator" },
	{ 0x0051, 0x0051, "SDNAEPC EAP message with the length of two octets" },
	{ 0x0056, 0x0056, "UE policy container with the length of two octets" },
	{ 0xff00, 0xffff, "Operator Specific Use" },
	{ 0, 0, NULL }
};

static const value_string gsm_a_gm_link_dir_vals[] = {
	{ -1, "Unknown" },
	{ 0x0, "MS to network" },
	{ 0x1, "Network to MS" },
	{ 0, NULL }
};

static const value_string gsm_a_gm_sel_bearer_ctrl_mode_vals[] = {
	{ 1, "MS only" },
	{ 2, "MS/NW" },
	{ 0, NULL }
};

static const value_string gsm_a_gm_nbifom_mode_vals[] = {
	{ 0, "UE-initiated" },
	{ 1, "Network-initiated" },
	{ 0, NULL }
};

static const true_false_string gsm_a_gm_apn_rate_ctrl_params_aer_value = {
	"Additional exception reports at maximum rate reached are allowed",
	"Additional exception reports at maximum rate reached are not allowed"
};

static const value_string gsm_a_gm_apn_rate_ctrl_ul_time_unit_vals[] = {
	{ 0, "Unrestricted" },
	{ 1, "Minute" },
	{ 2, "Hour" },
	{ 3, "Day" },
	{ 4, "Week" },
	{ 0, NULL }
};

static const value_string gsm_a_gm_sm_pco_3gpp_data_off_ue_status_vals[] = {
	{ 1, "Deactivated"},
	{ 2, "Activated"},
	{ 0, NULL}
};

static const value_string gsm_a_gm_sm_pco_dns_serv_sec_info_type_vals[] = {
	{ 0, "Security protocol type"},
	{ 1, "Port number"},
	{ 2, "Authentication domain name"},
	{ 3, "SPKI pin set"},
	{ 4, "Root certificate"},
	{ 5, "Raw public key"},
	{ 0, NULL}
};

static const value_string gsm_a_gm_sm_pco_dns_serv_sec_info_sec_proto_vals[] = {
	{ 0, "TLS"},
	{ 1, "DTLS"},
	{ 0, NULL}
};

static const value_string gsm_a_gm_sm_pco_ecs_addr_type_vals[] = {
	{ 0, "IPv4"},
	{ 1, "IPv6"},
	{ 2, "FQDN"},
	{ 0, NULL}
};

static const value_string gsm_a_gm_sm_pco_ecs_addr_spatial_valid_cond_type_vals[] = {
	{ 0, "No spatial validity condition"},
	{ 1, "Geographical service area"},
	{ 2, "Tracking area"},
	{ 3, "Country-wide"},
	{ 0, NULL}
};

static const value_string gsm_a_gm_sm_pco_dns_serv_sec_prot_support_vals[] = {
	{ 1, "TLS"},
	{ 2, "DTLS"},
	{ 0, NULL}
};

uint16_t
de_sm_pco(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	proto_item        *generated_item;
	uint32_t           curr_offset;
	int                curr_len;
	unsigned char      oct;
	int                link_dir;
	proto_item        *pco_item;
	proto_tree        *pco_tree;

	curr_len    = (int)len; /* length field is only 1 or 2 bytes long */
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	link_dir = pinfo->link_dir;
	generated_item = proto_tree_add_int(tree, hf_gsm_a_gm_link_dir, tvb, curr_offset, 0, link_dir);
	proto_item_set_generated(generated_item);


	/* 1 ext 0 0 0 0 Spare  Configuration protocol */
	proto_tree_add_item(tree, hf_gsm_a_sm_ext, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* Configuration protocol (octet 3)
	 * Bits
	 * 3 2 1
	 * 0 0 0 PPP for use with IP PDP type or IP PDN type (see 3GPP TS 24.301 [120])
	 *
	 * All other values are interpreted as PPP in this version of the protocol.
	 * (3GPP TS 24.008 version 9.4.0 Release 9)
	 */
	proto_tree_add_uint_format_value(tree, hf_gsm_a_gm_configuration_protocol, tvb, curr_offset, 1, oct&0x07, "PPP for use with IP PDP type or IP PDN type (%u)", oct&0x07);
	curr_len--;
	curr_offset++;

	while (curr_len >= 3) /* 2 bytes protocol/container ID + 1 byte length */
	{
		uint32_t e_len;
		uint16_t prot;
		tvbuff_t *l3_tvb;

		/* Protocol ID 1                    octet 4
		 *                                  octet 5
		 * Length of protocol ID 1 contents octet 6
		 * Protocol ID 1 contents           octet 7
		 */

		prot = tvb_get_ntohs(tvb, curr_offset);
		pco_item = proto_tree_add_uint_format_value(tree, hf_gsm_a_gm_pco_pid, tvb, curr_offset, 2, (uint32_t)prot,
				"%s (0x%04x)",
				link_dir ?
					rval_to_str_const((uint32_t)prot, gsm_a_sm_pco_net2ms_prot_vals, val_to_str_ext_const(prot, &ppp_vals_ext, "Unknown")) :
					rval_to_str_const((uint32_t)prot, gsm_a_sm_pco_ms2net_prot_vals, val_to_str_ext_const(prot, &ppp_vals_ext, "Unknown")),
				(uint32_t)prot);
		pco_tree = proto_item_add_subtree(pco_item, ett_sm_pco);

		curr_len    -= 2;
		curr_offset += 2;
		if ((link_dir == P2P_DIR_DL && (prot == 0x0023 || prot == 0x0024 || prot == 0x0030 || prot == 0x0031 ||
		                                prot == 0x0032 || prot == 0x0041 || prot == 0x0051 || prot == 0x0056)) ||
		    (link_dir == P2P_DIR_UL && (prot == 0x0041 || prot == 0x0051 || prot == 0x0056))) {
			proto_tree_add_item_ret_uint(pco_tree, hf_gsm_a_gm_sm_pco_length2, tvb, curr_offset, 2, ENC_BIG_ENDIAN, &e_len);
			curr_len    -= 2;
			curr_offset += 2;
		} else {
			proto_tree_add_item_ret_uint(pco_tree, hf_gsm_a_gm_sm_pco_length, tvb, curr_offset, 1, ENC_NA, &e_len);
			curr_len    -= 1;
			curr_offset += 1;
		}

		switch (prot)
		{
			case 0x0001:
				if ((link_dir == P2P_DIR_DL) && (e_len > 0)) {
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_pcscf_ipv6, tvb, curr_offset, 16, ENC_NA);
				}
				break;
			case 0x0003:
				if ((link_dir == P2P_DIR_DL) && (e_len > 0)) {
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_dns_ipv6, tvb, curr_offset, 16, ENC_NA);
				}
				break;
			case 0x0007:
				if ((link_dir == P2P_DIR_DL) && (e_len > 0)) {
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_dsmipv6_home_agent_ipv6, tvb, curr_offset, 16, ENC_NA);
				}
				break;
			case 0x0002:
			case 0x0006:
			case 0x000A:
			case 0x000B:
			case 0x000F:
			case 0x0011:
			case 0x0012:
			case 0x0013:
			case 0x0018:
			case 0x003e:
			case 0x003f:
			case 0x0040:
			case 0x0047:
			case 0x0048:
			case 0x0049:
			case 0x004a:
			case 0x0050:
				break;
			case 0x0004:
				if ((link_dir == P2P_DIR_DL) && (e_len == 1)) {
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_reject_code, tvb, curr_offset, 1, ENC_NA);
				}
				break;
			case 0x0005:
				if ((link_dir == P2P_DIR_DL) && (e_len == 1)) {
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_sel_bearer_ctrl_mode, tvb, curr_offset, 1, ENC_NA);
				}
				break;
			case 0x0008:
				if ((link_dir == P2P_DIR_DL) && (e_len > 0)) {
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_dsmipv6_home_network_ipv6, tvb, curr_offset, 16, ENC_NA);
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_dsmipv6_home_network_prefix_length, tvb, curr_offset+16, 1, ENC_NA);
				}
				break;
			case 0x0009:
				if ((link_dir == P2P_DIR_DL) && (e_len > 0)) {
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_dsmipv6_home_agent_ipv4, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
				}
				break;
			case 0x000C:
				if ((link_dir == P2P_DIR_DL) && (e_len > 0)) {
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_pcscf_ipv4, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
				}
				break;
			case 0x000D:
				if ((link_dir == P2P_DIR_DL) && (e_len > 0)) {
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_dns_ipv4, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
				}
				break;
			case 0x000E:
				if ((link_dir == P2P_DIR_DL) && (e_len > 0)) {
					dissect_e164_msisdn(tvb, pco_tree, curr_offset, e_len, E164_ENC_BCD);
				}
				break;
			case 0x0010:
				if ((link_dir == P2P_DIR_DL) && (e_len == 2)) {
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_ipv4_link_mtu_size, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
				}
				break;
			case 0x0014:
				if (e_len == 1) {
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_nbifom_mode, tvb, curr_offset, 1, ENC_NA);
				}
				break;
			case 0x0015:
				if ((link_dir == P2P_DIR_DL) && (e_len == 2)) {
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_non_ip_link_mtu_size, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
				}
				break;
			case 0x0016:
			case 0x0025:
				if (link_dir == P2P_DIR_DL) {
					proto_tree_add_bits_item(pco_tree, hf_gsm_a_spare_bits, tvb, (curr_offset << 3), 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_apn_rate_ctrl_params_aer, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_apn_rate_ctrl_params_ul_time_unit, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
					if (e_len >= 4) {
						proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_apn_rate_ctrl_params_max_ul_rate, tvb, curr_offset+1, 3, ENC_BIG_ENDIAN);
					}
				}
				break;
			case 0x0017:
				if (link_dir == P2P_DIR_UL && e_len >= 1) {
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_3gpp_data_off_ue_status, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
				}
				break;
			case 0x0019:
			case 0x0026:
				if (link_dir == P2P_DIR_DL) {
					proto_tree_add_bits_item(pco_tree, hf_gsm_a_spare_bits, tvb, (curr_offset << 3), 5, ENC_BIG_ENDIAN);
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_add_apn_rate_ctrl_params_ul_time_unit, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
					if (e_len >= 3) {
						proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_add_apn_rate_ctrl_params_max_ul_rate, tvb, curr_offset+1, 2, ENC_BIG_ENDIAN);
					}
				}
				break;
			case 0x001a:
				if (link_dir == P2P_DIR_UL) {
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_pdu_session_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
				}
				break;
			case 0x001b:
				if (link_dir == P2P_DIR_DL && e_len >= 4) {
					de_nas_5gs_cmn_s_nssai(tvb, pco_tree, pinfo, curr_offset, e_len - 3, NULL, 0);
					dissect_e212_mcc_mnc(tvb, pinfo, pco_tree, curr_offset + e_len - 3, E212_NONE, true);
				}
				break;
			case 0x001c:
			case 0x0023:
				if (link_dir == P2P_DIR_DL) {
					de_nas_5gs_sm_qos_rules(tvb, pco_tree, pinfo, curr_offset, e_len, NULL, 0);
				}
				break;
			case 0x001d:
				if (link_dir == P2P_DIR_DL) {
					/* Network to MS direction */
					de_nas_5gs_sm_session_ambr(tvb, pco_tree, pinfo, curr_offset, e_len, NULL, 0);
				}
				break;
			case 0x001e:
				if (link_dir == P2P_DIR_DL && e_len == 2) {
					/* When the container identifier indicates PDU session address lifetime,
					 * the length of container identifier contents indicates a length equal to two.
					 * The container identifier contents field contains the binary coded representation
					 * of how long the network is willing to maintain the PDU session in units of seconds.
					 * ...If the length of container identifier contents is different from two octets,
					 * then it shall be ignored by the receiver
					 */
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_pdu_session_address_lifetime, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
				}
				break;
			case 0x001f:
			case 0x0024:
				if (link_dir == P2P_DIR_DL && e_len > 0) {
					de_nas_5gs_sm_qos_flow_des(tvb, pco_tree, pinfo, curr_offset, e_len, NULL, 0);
				}
				break;
			case 0x0020:
				if (link_dir == P2P_DIR_DL && e_len == 2) {
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_eth_frame_payload_mtu, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
				}
				break;
			case 0x0021:
				if (link_dir == P2P_DIR_DL && e_len == 2) {
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_unstruct_link_mtu, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
				}
				break;
			case 0x0022:
				if (link_dir == P2P_DIR_UL && e_len == 1) {
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_5gsm_cause, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
				}
				break;
			case 0x0027:
				if (link_dir == P2P_DIR_DL && e_len > 0) {
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_acs_info, tvb, curr_offset, e_len, ENC_NA|ENC_UTF_8);
				}
				break;
			case 0x0028:
			case 0x0029:
			case 0x002a:
			case 0x002b:
				if (link_dir == P2P_DIR_DL && e_len == 7) {
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_init_small_data_rate_ctrl_params_max_ul_rate_allowed, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_init_small_data_rate_ctrl_params_termination_timestamp, tvb, curr_offset+4, 4, ENC_TIME_SECS_NTP|ENC_BIG_ENDIAN);
				}
				break;
			case 0x0030:
				if (link_dir == P2P_DIR_DL && e_len > 0) {
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_atsss_response, tvb, curr_offset, e_len, ENC_NA);
				}
				break;
			case 0x0031:
				if (link_dir == P2P_DIR_DL && e_len > 1) {
					uint32_t type;

					proto_tree_add_item_ret_uint(pco_tree, hf_gsm_a_gm_sm_pco_dns_serv_sec_info_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &type);
					switch (type) {
						case 0:
							proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_dns_serv_sec_info_sec_proto_type, tvb, curr_offset+1, 1, ENC_BIG_ENDIAN);
							break;
						case 1:
							proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_dns_serv_sec_info_port_number, tvb, curr_offset+1, 2, ENC_BIG_ENDIAN);
							break;
						case 2:
							proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_dns_serv_sec_info_auth_domain_name, tvb, curr_offset+1, e_len-1, ENC_APN_STR | ENC_NA);
							break;
						case 3:
							proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_dns_serv_sec_info_spki_pin_set, tvb, curr_offset+1, e_len-1, ENC_NA);
							break;
						case 4:
							proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_dns_serv_sec_info_root_certificate, tvb, curr_offset+1, e_len-1, ENC_NA);
							break;
						case 5:
							proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_dns_serv_sec_info_raw_public_key, tvb, curr_offset+1, e_len-1, ENC_NA);
							break;
						default:
							proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_dns_serv_sec_info_value_part, tvb, curr_offset+1, e_len-1, ENC_NA);
							break;
					}
				}
				break;
			case 0x0032:
				if (link_dir == P2P_DIR_DL && e_len > 1) {
					uint32_t ecs_addr_type, ie_offset, fqdn_len;

					ie_offset = curr_offset;
					proto_tree_add_item_ret_uint(pco_tree, hf_gsm_a_gm_sm_pco_ecs_addr_type, tvb, ie_offset, 1, ENC_BIG_ENDIAN, &ecs_addr_type);
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_ecs_addr_spatial_valid_cond_type, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
					ie_offset++;
					switch (ecs_addr_type) {
						case 0:
							proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_ecs_addr_ipv4, tvb, ie_offset, 4, ENC_BIG_ENDIAN);
							ie_offset += 4;
							break;
						case 1:
							proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_ecs_addr_ipv6, tvb, ie_offset, 16, ENC_NA);
							ie_offset += 16;
							break;
						case 2:
							proto_tree_add_item_ret_uint(pco_tree, hf_gsm_a_gm_sm_pco_ecs_addr_fqdn_len, tvb, ie_offset, 1, ENC_BIG_ENDIAN, &fqdn_len);
							ie_offset++;
							proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_ecs_addr_fqdn, tvb, ie_offset, fqdn_len, ENC_NA|ENC_APN_STR);
							ie_offset += fqdn_len;
							break;
						default:
							goto skip_ecs_addr;
					}
					if ((ie_offset - curr_offset) < e_len)
						proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_ecs_addr_spatial_valid_cond_cont, tvb, ie_offset, e_len - (ie_offset - curr_offset), ENC_NA);
					skip_ecs_addr:;
				}
				break;
			case 0x0035:
				if (link_dir == P2P_DIR_DL && e_len > 1) {
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_ecsp_id, tvb, curr_offset, e_len, ENC_NA|ENC_UTF_8);
				}
				break;
			case 0x0036:
			case 0x0037:
			case 0x0038:
				if (link_dir == P2P_DIR_DL) {
					uint64_t flags;
					uint32_t field_len, ie_offset = curr_offset;
					static int* const ind[] = {
						&hf_gsm_a_gm_sm_pco_pvs_s_nssai_ind,
						&hf_gsm_a_gm_sm_pco_pvs_dnn_ind,
						NULL
					};

					if (prot == 0x0036) {
						proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_pvs_ipv4, tvb, ie_offset, 4, ENC_BIG_ENDIAN);
						ie_offset += 4;
					} else if (prot == 0x0037) {
						proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_pvs_ipv6, tvb, ie_offset, 16, ENC_NA);
						ie_offset += 16;
					} else {
						proto_tree_add_item_ret_uint(pco_tree, hf_gsm_a_gm_sm_pco_pvs_name_len, tvb, ie_offset, 1, ENC_BIG_ENDIAN, &field_len);
						ie_offset++;
						proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_pvs_name, tvb, ie_offset, field_len, ENC_NA|ENC_APN_STR);
						ie_offset += field_len;
					}
					proto_tree_add_bitmask_list_ret_uint64(pco_tree, tvb, ie_offset, 1, ind, ENC_BIG_ENDIAN, &flags);
					ie_offset++;
					if (flags & 0x01) {
						proto_tree_add_item_ret_uint(tree, hf_gsm_a_gm_sm_pco_pvs_dnn_len, tvb, ie_offset, 1, ENC_BIG_ENDIAN, &field_len);
						ie_offset++;
						ie_offset += de_nas_5gs_cmn_dnn(tvb, pco_tree, pinfo, ie_offset, field_len, NULL, 0);
					}
					if (flags & 0x02) {
						proto_tree_add_item_ret_uint(tree, hf_gsm_a_gm_sm_pco_pvs_s_nssai_len, tvb, ie_offset, 1, ENC_BIG_ENDIAN, &field_len);
						ie_offset++;
						de_nas_5gs_cmn_s_nssai(tvb, pco_tree, pinfo, ie_offset, field_len, NULL, 0);
					}
				}
				break;
			case 0x0039:
				if (link_dir == P2P_DIR_UL && e_len == 1) {
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_dns_serv_sec_prot_support, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
				}
				break;
			case 0x003a:
				if (link_dir == P2P_DIR_UL && e_len > 0) {
					static int* const oct1_flags[] = {
						&hf_gsm_a_gm_sm_pco_eas_rediscovery_support_ind_fqdn,
						&hf_gsm_a_gm_sm_pco_eas_rediscovery_support_ind_ipv6,
						&hf_gsm_a_gm_sm_pco_eas_rediscovery_support_ind_ipv4,
						NULL
					};
					proto_tree_add_bitmask_list(pco_tree, tvb, curr_offset, 1, oct1_flags, ENC_BIG_ENDIAN);
				}
				break;
			case 0x003b:
				if (link_dir == P2P_DIR_DL && e_len == 8) {
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_eas_rediscovery_support_ind_with_impacted_eas_ipv4_range_low, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_eas_rediscovery_support_ind_with_impacted_eas_ipv4_range_high, tvb, curr_offset+4, 4, ENC_BIG_ENDIAN);
				}
				break;
			case 0x003c:
				if (link_dir == P2P_DIR_DL && e_len == 32) {
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_eas_rediscovery_support_ind_with_impacted_eas_ipv6_range_low, tvb, curr_offset, 16, ENC_NA);
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_eas_rediscovery_support_ind_with_impacted_eas_ipv6_range_high, tvb, curr_offset+16, 16, ENC_NA);
				}
				break;
			case 0x003d:
				if (link_dir == P2P_DIR_DL && e_len > 0) {
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_eas_rediscovery_support_ind_with_impacted_eas_fqdn, tvb, curr_offset, e_len, ENC_NA|ENC_APN_STR);
				}
				break;
			 case 0x0041:
				de_nas_5gs_cmn_service_level_aa_cont(tvb, pco_tree, pinfo, curr_offset, e_len, NULL, 0);
				break;
			case 0x0051:
				if (eap_handle) {
					col_append_str(pinfo->cinfo, COL_PROTOCOL, "/");
					col_set_fence(pinfo->cinfo, COL_PROTOCOL);
					col_append_str(pinfo->cinfo, COL_INFO, ", ");
					col_set_fence(pinfo->cinfo, COL_INFO);
					call_dissector(eap_handle, tvb_new_subset_length(tvb, curr_offset, e_len), pinfo, pco_tree);
				} else {
					call_data_dissector(tvb_new_subset_length(tvb, curr_offset, e_len), pinfo, pco_tree);
				}
				break;
			case 0x0052:
				if (link_dir == P2P_DIR_UL && e_len > 0) {
					proto_tree_add_item(pco_tree, hf_gsm_a_gm_sm_pco_sdnaepc_dn_specific_id, tvb, curr_offset, e_len, ENC_NA|ENC_UTF_8);
				}
				break;
			case 0x0056:
				if (e_len > 0) {
					dissect_nas_5gs_updp(tvb_new_subset_length(tvb, curr_offset, e_len), pinfo, pco_tree);
				}
				break;
			default:
			{
				if (e_len > 0) {
					if (prot >= 0xff00) {
						dissect_e212_mcc_mnc(tvb, pinfo, pco_tree, curr_offset, E212_NONE, true);
						if ((e_len - 3) > 0) {
							proto_tree_add_item(pco_tree, hf_gsm_a_gm_pco_app_spec_info, tvb, curr_offset+3, e_len-3, ENC_NA);
						}
					} else {
						dissector_handle_t handle;
						handle = dissector_get_uint_handle (gprs_sm_pco_subdissector_table, prot);
						l3_tvb = tvb_new_subset_length(tvb, curr_offset, e_len);
						if (handle != NULL)
						{
							/*
							 * dissect the embedded message
							*/
							/* In this case we do not want the columns updated */
							col_set_writable(pinfo->cinfo, -1, false);
							call_dissector(handle, l3_tvb, pinfo, pco_tree);
							col_set_writable(pinfo->cinfo, -1, true);
						}
						else
						{
							/*
							* dissect the embedded DATA message
							*/
							call_data_dissector(l3_tvb, pinfo, pco_tree);
						}
					}
				}
			}
		}
		curr_len    -= e_len;
		curr_offset += e_len;
	}

	if (curr_len < 0) {
		proto_tree_add_expert(tree, pinfo, &ei_gsm_a_gm_not_enough_data, tvb, offset, len);
	} else {
		EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_gm_extraneous_data);
	}

	return len;
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

uint16_t
de_sm_pdp_addr(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t     curr_offset;
	const char *str;
	unsigned char       pdp_type_org, pdp_type_num;

	curr_offset = offset;

	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset << 3), 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_sm_pdp_type_org, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	pdp_type_org = tvb_get_guint8(tvb, curr_offset) & 0x0f;
	curr_offset += 1;
	pdp_type_num = tvb_get_guint8(tvb, curr_offset);

	if (pdp_type_org == 0)
	{
		/* ETSI allocated address */
		switch (pdp_type_num)
		{
			case 0x00: str = "Reserved, used in earlier version of this protocol"; break;
			case 0x01: str = "PDP-type PPP"; break;
			case 0x02: str = "non IP"; break;
			default:   str = "reserved";
		}
	}
	else if (pdp_type_org == 1)
	{
		/* IETF allocated address */
		switch (pdp_type_num)
		{
			case 0x21: str = "IPv4 address"; break;
			case 0x57: str = "IPv6 address"; break;
			case 0x8d: str = "IPv4v6 address"; break;
			default:   str = "Unknown, interpreted as IPv4 address";
		}
	}
	else if ((pdp_type_num == 0) && (pdp_type_org == 0x0f))
		str = "Empty";
	else
		str = "Not specified";

	proto_tree_add_uint_format_value(tree, hf_gsm_a_sm_pdp_type_number, tvb, curr_offset, 1, pdp_type_num, "%s (%u)", str, pdp_type_num);

	if ((len == 2) && ((pdp_type_num == 0x21) || (pdp_type_num == 0x57) || (pdp_type_num == 0x8d)))
	{
		proto_tree_add_uint_format(tree, hf_gsm_a_sm_pdp_address, tvb, curr_offset, 1, pdp_type_num, "Dynamic addressing");
		curr_offset += 1;
		return (curr_offset - offset);
	}
	else if (len == 2)
	{
		proto_tree_add_uint_format(tree, hf_gsm_a_sm_pdp_address, tvb, curr_offset, 1, 0, "No PDP address is included");
		curr_offset += 1;
		return (curr_offset - offset);
	}

	curr_offset += 1;
	if (pdp_type_org == 1)
	switch (pdp_type_num)
	{
		case 0x57:
			proto_tree_add_item(tree, hf_gsm_a_sm_ip6_address, tvb, curr_offset, 16, ENC_NA);
			curr_offset += 16;
			break;

		case 0x8d:
			proto_tree_add_item(tree, hf_gsm_a_sm_ip4_address, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
			curr_offset += 4;
			proto_tree_add_item(tree, hf_gsm_a_sm_ip6_address, tvb, curr_offset, 16, ENC_NA);
			curr_offset += 16;
			break;

		default:
			proto_tree_add_item(tree, hf_gsm_a_sm_ip4_address, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
			curr_offset += 4;
	}

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_gm_extraneous_data);

	return (curr_offset - offset);
}

/*
 * [9] 10.5.6.5 Quality of service
 */
static const value_string gsm_a_sm_qos_delay_cls_vals[] = {
	{ 0x00, "Subscribed delay class (in MS to network direction)" },
	{ 0x01, "Delay class 1" },
	{ 0x02, "Delay class 2" },
	{ 0x03, "Delay class 3" },
	{ 0x04, "Delay class 4 (best effort)" },
	{ 0x07,	"Reserved" },
	{ 0, NULL }
};

static const value_string gsm_a_sm_qos_reliability_vals[] = {
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
const value_string gsm_a_sm_qos_del_of_err_sdu_vals[] = {
	{ 0, "Subscribed delivery of erroneous SDUs/Reserved" },
	{ 1, "No detect('-')" },
	{ 2, "Erroneous SDUs are delivered('yes')" },
	{ 3, "Erroneous SDUs are not delivered('No')" },
	{ 7, "Reserved" },
	{ 0, NULL }
};

 /* Delivery order, octet 6 (see 3GPP TS 23.107) Bits 5 4 */
static const value_string gsm_a_sm_qos_del_order_vals[] = {
	{ 0, "Subscribed delivery order/Reserved" },
	{ 1, "With delivery order ('yes')" },
	{ 2, "Without delivery order ('no')" },
	{ 3, "Reserved" },
	{ 0, NULL }
};
/* Traffic class, octet 6 (see 3GPP TS 23.107) Bits 8 7 6 */
const value_string gsm_a_sm_qos_traffic_cls_vals[] = {
	{ 0, "Subscribed traffic class/Reserved" },
	{ 1, "Conversational class" },
	{ 2, "Streaming class" },
	{ 3, "Interactive class" },
	{ 4, "Background class" },
	{ 7, "Reserved" },
	{ 0, NULL }
};

/* Residual Bit Error Rate (BER), octet 10 (see 3GPP TS 23.107) Bits 8 7 6 5 */
const value_string gsm_a_sm_qos_ber_vals[] = {
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
const value_string gsm_a_sm_qos_sdu_err_rat_vals[] = {
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
const value_string gsm_a_sm_qos_traff_hdl_pri_vals[] = {
	{ 0, "Subscribed traffic handling priority/Reserved" },
	{ 1, "Priority level 1" },
	{ 2, "Priority level 2" },
	{ 3, "Priority level 3" },
	{ 0, NULL }
};

static const range_string gsm_a_sm_qos_peak_thr_vals[] = {
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

static const range_string gsm_a_sm_qos_mean_thr_vals[] = {
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

static const range_string gsm_a_sm_qos_prec_class_vals[] = {
	{ 0x00, 0x00, "Subscribed precedence/reserved" },
	{ 0x01, 0x01, "High priority" },
	{ 0x02, 0x02, "Normal priority" },
	{ 0x03, 0x03, "Low priority" },
	{ 0x04, 0x06, "Interpreted as Normal priority" },
	{ 0x07, 0x07, "Reserved" },
	{ 0, 0, NULL }
};

static const true_false_string gsm_a_sm_qos_signalling_ind_value = {
	"Optimised for signalling traffic",
	"Not optimised for signalling traffic"
};

/* Helper function returning the main bitrates in kbps */
static uint32_t
qos_calc_bitrate(uint8_t oct)
{
	if (oct <= 0x3f)
		return oct;
	if (oct <= 0x7f)
		return 64 + (oct-0x40) * 8;

	return 576 + (oct-0x80) * 64;
}

/* Helper function returning the extended bitrates in kbps */
static uint32_t
qos_calc_ext_bitrate(uint8_t oct)
{
	if (oct <= 0x4a)
		return 8600 + oct * 100;
	if (oct <= 0xba)
		return 16000 + (oct-0x4a) * 1000;

	return 128000 + (oct - 0xba) * 2000;
}

static uint32_t
qos_calc_ext2_bitrate(uint8_t oct)
{
	if (oct <= 0x3d)
		return (256 + oct * 4);
	if (oct <= 0xa1)
		return (500 + (oct-0x3d) * 10);
	if (oct <= 0xf6)
		return (1500 + (oct-0xa1) * 100);

	return 10000;
}

/*
 * 10.5.6.5 Quality of service
 */
uint16_t
de_sm_qos(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t     curr_offset;
	unsigned char       oct, tmp_oct;
	const char *str;
	uint32_t     temp32;

	curr_offset = offset;

	/* Octet 3 */
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset << 3), 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_sm_qos_delay_cls, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_sm_qos_reliability_cls, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset += 1;

	/* Octet 4 */
	proto_tree_add_item(tree, hf_gsm_a_sm_qos_peak_thr, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset << 3) + 4, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_sm_qos_prec_class, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset += 1;

	/* Octet 5 */
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset << 3), 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_sm_qos_mean_thr, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset += 1;

	NO_MORE_DATA_CHECK(len);

	/* Octet 6 */
	proto_tree_add_item(tree, hf_gsm_a_sm_qos_traffic_cls, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_sm_qos_del_order, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_sm_qos_del_of_err_sdu, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset += 1;

	NO_MORE_DATA_CHECK(len);

	/* Octet 7 */
	oct = tvb_get_guint8(tvb, curr_offset);

	switch (oct)
	{
		case 0x00: str = "Subscribed maximum SDU size/reserved"; break;
		case 0x97: str = "1502 octets"; break;
		case 0x98: str = "1510 octets"; break;
		case 0x99: str = "1520 octets"; break;
		case 0xff: str = "Reserved"; break;
		default:   str = "Unspecified";
	}

	if ((oct >= 1) && (oct <= 0x96))
		proto_tree_add_uint_format_value(tree, hf_gsm_a_sm_qos_maximum_sdu_size, tvb, curr_offset, 1, oct, "%u octets (%u)", oct*10, oct);
	else
		proto_tree_add_uint_format_value(tree, hf_gsm_a_sm_qos_maximum_sdu_size, tvb, curr_offset, 1, oct, "%s (%u)", str, oct);

	curr_offset += 1;

	NO_MORE_DATA_CHECK(len);

	/* Octet 8 */
	oct = tvb_get_guint8(tvb, curr_offset);

	switch (oct)
	{
		case 0x00: str = "Subscribed maximum bit rate for uplink/reserved"; break;
		case 0xff: str = "0 kbps"; break;
		default:   str = wmem_strdup_printf(pinfo->pool, "%u kbps", qos_calc_bitrate(oct));
	}

	proto_tree_add_uint_format_value(tree, hf_gsm_a_sm_qos_max_bitrate_upl, tvb,
		curr_offset, 1, oct, "%s (%u)", str, oct);
	curr_offset += 1;

	NO_MORE_DATA_CHECK(len);

	/* Octet 9 */
	oct = tvb_get_guint8(tvb, curr_offset);

	switch (oct)
	{
		case 0x00: str = "Subscribed maximum bit rate for downlink/reserved"; break;
		case 0xff: str = "0 kbps"; break;
		default:   str = wmem_strdup_printf(pinfo->pool, "%u kbps", qos_calc_bitrate(oct));
	}

	proto_tree_add_uint_format_value(tree, hf_gsm_a_sm_qos_max_bitrate_downl, tvb,
		curr_offset, 1, oct, "%s (%u)", str, oct);
	curr_offset += 1;

	NO_MORE_DATA_CHECK(len);

	/* Octet 10 */
	proto_tree_add_item(tree, hf_gsm_a_sm_qos_ber, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_sm_qos_sdu_err_rat, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	curr_offset += 1;
	NO_MORE_DATA_CHECK(len);

	/* Octet 11 */
	oct = tvb_get_guint8(tvb, curr_offset);

	tmp_oct = oct>>2;
	switch (tmp_oct)
	{
		case 0x00: str = "Subscribed transfer delay/reserved"; break;
		case 0x3f: str = "Reserved"; break;
		default:
			if (tmp_oct <= 0x0f)
				temp32 = tmp_oct * 10;
			else if (tmp_oct <= 0x1f)
				temp32 = (tmp_oct - 0x10) * 50 + 200;
			else
				temp32 = (tmp_oct - 0x20) * 100 + 1000;
			str = wmem_strdup_printf(pinfo->pool, "%u ms", temp32);
	}

	proto_tree_add_uint_format_value(tree, hf_gsm_a_sm_qos_trans_delay, tvb,
		curr_offset, 1, oct, "%s (%u)", str, tmp_oct);

	proto_tree_add_item(tree, hf_gsm_a_sm_qos_traff_hdl_pri, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	curr_offset += 1;
	NO_MORE_DATA_CHECK(len);

	/* Octet 12 */
	oct = tvb_get_guint8(tvb, curr_offset);

	switch (oct)
	{
		case 0x00: str = "Subscribed guaranteed bit rate for uplink/reserved"; break;
		case 0xff: str = "0 kbps"; break;
		default:   str = wmem_strdup_printf(pinfo->pool, "%u kbps", qos_calc_bitrate(oct));
	}

	proto_tree_add_uint_format_value(tree, hf_gsm_a_sm_qos_guar_bitrate_upl, tvb,
		curr_offset, 1, oct, "%s (%u)", str, oct);

	curr_offset += 1;
	NO_MORE_DATA_CHECK(len);

	/* Octet 13 */
	oct = tvb_get_guint8(tvb, curr_offset);

	switch (oct)
	{
		case 0x00: str = "Subscribed guaranteed bit rate for downlink/reserved"; break;
		case 0xff: str = "0 kbps"; break;
		default:   str = wmem_strdup_printf(pinfo->pool, "%u kbps", qos_calc_bitrate(oct));
	}

	proto_tree_add_uint_format_value(tree, hf_gsm_a_sm_qos_guar_bitrate_downl, tvb,
		curr_offset, 1, oct, "%s (%u)", str, oct);

	curr_offset += 1;
	NO_MORE_DATA_CHECK(len);

	/* Ocet 14 */
	oct = tvb_get_guint8(tvb, curr_offset);
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset << 3), 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_sm_qos_signalling_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	tmp_oct = oct & 7;
	if (tmp_oct == 0x01)
		str = "speech";
	else
		str = "unknown";

	proto_tree_add_uint_format_value(tree, hf_gsm_a_sm_qos_source_stat_desc, tvb,
		curr_offset, 1, oct, "%s (%u)", str, tmp_oct);

	curr_offset += 1;
	NO_MORE_DATA_CHECK(len);

	/* Octet 15 */
	oct = tvb_get_guint8(tvb, curr_offset);

	if (oct == 0x00)
		str = "Use the value indicated by the Maximum bit rate for downlink";
	else
	{
		temp32 = qos_calc_ext_bitrate(oct);
		if (temp32 % 1000 == 0)
			str = wmem_strdup_printf(pinfo->pool, "%u Mbps", temp32 / 1000);
		else
			str = wmem_strdup_printf(pinfo->pool, "%u kbps", temp32);
	}
	proto_tree_add_uint_format_value(tree, hf_gsm_a_sm_qos_max_bitrate_downl_ext, tvb,
		curr_offset, 1, oct, "%s (%u)", str, oct);

	curr_offset += 1;
	NO_MORE_DATA_CHECK(len);

	/* Octet 16 */
	oct = tvb_get_guint8(tvb, curr_offset);

	if (oct == 0x00)
		str = "Use the value indicated by the Guaranteed bit rate for downlink";
	else
	{
		temp32 = qos_calc_ext_bitrate(oct);
		if (temp32 % 1000 == 0)
			str = wmem_strdup_printf(pinfo->pool, "%u Mbps", temp32 / 1000);
		else
			str = wmem_strdup_printf(pinfo->pool, "%u kbps", temp32);
	}
	proto_tree_add_uint_format_value(tree, hf_gsm_a_sm_qos_guar_bitrate_downl_ext, tvb,
		curr_offset, 1, oct, "%s (%u)", str, oct);

	curr_offset += 1;
	NO_MORE_DATA_CHECK(len);

	/* Maximum bit rate for uplink (extended) Octet 17 */
	oct = tvb_get_guint8(tvb, curr_offset);

	if (oct == 0x00)
		str = "Use the value indicated by the Maximum bit rate for uplink";
	else
	{
		temp32 = qos_calc_ext_bitrate(oct);
		if (temp32 % 1000 == 0)
			str = wmem_strdup_printf(pinfo->pool, "%u Mbps", temp32 / 1000);
		else
			str = wmem_strdup_printf(pinfo->pool, "%u kbps", temp32);
	}
	proto_tree_add_uint_format_value(tree, hf_gsm_a_sm_qos_max_bitrate_upl_ext, tvb,
		curr_offset, 1, oct, "%s (%u)", str, oct);

	curr_offset += 1;
	NO_MORE_DATA_CHECK(len);

	/* Guaranteed bit rate for uplink (extended) Octet 18 */
	oct = tvb_get_guint8(tvb, curr_offset);

	if (oct == 0x00)
		str = "Use the value indicated by the Guaranteed bit rate for uplink";
	else
	{
		temp32 = qos_calc_ext_bitrate(oct);
		if (temp32 % 1000 == 0)
			str = wmem_strdup_printf(pinfo->pool, "%u Mbps", temp32 / 1000);
		else
			str = wmem_strdup_printf(pinfo->pool, "%u kbps", temp32);
	}
	proto_tree_add_uint_format_value(tree, hf_gsm_a_sm_qos_guar_bitrate_upl_ext, tvb,
		curr_offset, 1, oct, "%s (%u)", str, oct);

	curr_offset += 1;
	NO_MORE_DATA_CHECK(len);

	/* Maximum bit rate for downlink (extended-2) Octet 19 */
	oct = tvb_get_guint8(tvb, curr_offset);

	if (oct == 0x00)
		str = "Use the value indicated by the Maximum bit rate for downlink";
	else
	{
		temp32 = qos_calc_ext2_bitrate(oct);
		str = wmem_strdup_printf(pinfo->pool, "%u Mbps", temp32);
	}
	proto_tree_add_uint_format_value(tree, hf_gsm_a_sm_qos_max_bitrate_downl_ext2, tvb,
		curr_offset, 1, oct, "%s (%u)", str, oct);

	curr_offset += 1;
	NO_MORE_DATA_CHECK(len);

	/* Guaranteed bit rate for downlink (extended-2) Octet 20 */
	oct = tvb_get_guint8(tvb, curr_offset);

	if (oct == 0x00)
		str = "Use the value indicated by the Guaranteed bit rate for downlink";
	else
	{
		temp32 = qos_calc_ext2_bitrate(oct);
		str = wmem_strdup_printf(pinfo->pool, "%u Mbps", temp32);
	}
	proto_tree_add_uint_format_value(tree, hf_gsm_a_sm_qos_guar_bitrate_downl_ext2, tvb,
		curr_offset, 1, oct, "%s (%u)", str, oct);

	curr_offset += 1;
	NO_MORE_DATA_CHECK(len);

	/* Maximum bit rate for uplink (extended-2) Octet 21 */
	oct = tvb_get_guint8(tvb, curr_offset);

	if (oct == 0x00)
		str = "Use the value indicated by the Maximum bit rate for uplink";
	else
	{
		temp32 = qos_calc_ext2_bitrate(oct);
		str = wmem_strdup_printf(pinfo->pool, "%u Mbps", temp32);
	}
	proto_tree_add_uint_format_value(tree, hf_gsm_a_sm_qos_max_bitrate_upl_ext2, tvb,
		curr_offset, 1, oct, "%s (%u)", str, oct);

	curr_offset += 1;
	NO_MORE_DATA_CHECK(len);

	/* Guaranteed bit rate for uplink (extended-2) Octet 22 */
	oct = tvb_get_guint8(tvb, curr_offset);

	if (oct == 0x00)
		str = "Use the value indicated by the Guaranteed bit rate for uplink";
	else
	{
		temp32 = qos_calc_ext2_bitrate(oct);
		str = wmem_strdup_printf(pinfo->pool, "%u Mbps", temp32);
	}
	proto_tree_add_uint_format_value(tree, hf_gsm_a_sm_qos_guar_bitrate_upl_ext2, tvb,
		curr_offset, 1, oct, "%s (%u)", str, oct);

	curr_offset += 1;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_gm_extraneous_data);

	return (curr_offset - offset);
}

/*
 * [12] 10.5.6.5a Re-attempt indicator
 */
static const true_false_string gsm_a_gm_eplmnc_value = {
	"MS is not allowed to re-attempt the procedure in an equivalent PLMN",
	"MS is allowed to re-attempt the procedure in an equivalent PLMN"
};

static const true_false_string gsm_a_gm_ratc_value = {
	"MS is not allowed to re-attempt the procedure in S1 mode",
	"MS is allowed to re-attempt the procedure in S1 mode"
};

static uint16_t
de_sm_re_attempt_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t curr_offset;

	curr_offset = offset;

	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, offset << 3, 6, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_sm_eplmnc, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_sm_ratc, tvb, offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_gm_extraneous_data);

	return len;
}

/*
 * [15] 10.5.6.5b Extended quality of service
 */
static uint16_t
de_sm_ext_qos(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t curr_offset;

	curr_offset = offset;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_gm_extraneous_data);

	return len;
}

/*
 * [9] 10.5.6.6 SM cause
 */
static const value_string gsm_a_sm_cause_vals[] = {
	{ 0x08, "Operator Determined Barring" },
	{ 0x18, "MBMS bearer capabilities insufficient for the service" },
	{ 0x19, "LLC or SNDCP failure(A/Gb only)" },
	{ 0x1a, "Insufficient resources" },
	{ 0x1b, "Missing or unknown APN" },
	{ 0x1c, "Unknown PDP address or PDP type" },
	{ 0x1d, "User authentication failed" },
	{ 0x1e, "Activation rejected by GGSN, Serving GW or PDN GW" },
	{ 0x1f, "Activation rejected, unspecified" },
	{ 0x20, "Service option not supported" },
	{ 0x21, "Requested service option not subscribed" },
	{ 0x22, "Service option temporarily out of order" },
	{ 0x23, "NSAPI already used (not sent)" },
	{ 0x24, "Regular deactivation" },
	{ 0x25, "QoS not accepted" },
	{ 0x26, "Network failure" },
	{ 0x27, "Reactivation requested" },
	{ 0x28, "Feature not supported" },
	{ 0x29, "Semantic error in the TFT operation" },
	{ 0x2a, "Syntactical error in the TFT operation" },
	{ 0x2b, "Unknown PDP context" },
	{ 0x2c, "Semantic errors in packet filter(s)" },
	{ 0x2d, "Syntactical errors in packet filter(s)" },
	{ 0x2e, "PDP context without TFT already activated" },
	{ 0x2f, "Multicast group membership time-out" },
	{ 0x30, "Request rejected, BCM violation" },
	{ 0x32, "PDP type IPv4 only allowed" },
	{ 0x33, "PDP type IPv6 only allowed" },
	{ 0x34, "Single address bearers only allowed" },
	{ 0x38, "Collision with network initiated request" },
	{ 0x39, "PDP type IPv4v6 only allowed" },
	{ 0x3a, "PDP type non IP only allowed" },
	{ 0x3c, "Bearer handling not supported" },
	{ 0x41, "Maximum number of PDP contexts reached" },
	{ 0x42, "Requested APN not supported in current RAT and PLMN combination" },
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
	{ 0x71, "Multiple accesses to a PDN connection not allowed" },
	{ 0, NULL }
};
static value_string_ext gsm_a_sm_cause_vals_ext = VALUE_STRING_EXT_INIT(gsm_a_sm_cause_vals);

uint16_t
de_sm_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	uint8_t      oct;
	const char *str;

	oct = tvb_get_guint8(tvb, offset);

	/* SM Cause can be sent in both directions */
	str = val_to_str_ext_const(oct, &gsm_a_sm_cause_vals_ext,
			       "Protocol error, unspecified / Service option temporarily out of order");

	proto_tree_add_uint_format_value(tree, hf_gsm_a_sm_cause, tvb,
				offset, 1, oct, "%s (%u)", str, oct);

	/* no length check possible */
	return 1;
}

/*
 * [9] 10.5.6.6a SM cause 2
 */
static uint16_t
de_sm_cause_2(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	uint8_t      oct;
	const char *str;

	oct = tvb_get_guint8(tvb, offset);

	/* SM Cause 2 is sent only in the Network-to-MS direction */
	str = val_to_str_ext_const(oct, &gsm_a_sm_cause_vals_ext,
			       "Service option temporarily out of order");

	proto_tree_add_uint_format_value(tree, hf_gsm_a_sm_cause_2, tvb,
				offset, 1, oct, "%s (%u)", str, oct);

	/* no length check possible */
	return 1;
}
/*
 * [7] 10.5.6.7
 */

static const true_false_string gsm_a_sm_ti_flag_vals = {
	"The message is sent to the side that originates the TI",
	"The message is sent from the side that originates the TI"
};

static uint16_t
de_sm_linked_ti(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t	curr_offset;
	unsigned	curr_len;
	char	oct;

	curr_len    = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	proto_tree_add_item(tree, hf_gsm_a_sm_ti_flag, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* The TI value and the TI flag occupy bits 5 - 7 and bit 8 of the first octet respectively.
	 * The extended TI shall not be used unless TI values of 7 or greater are needed.
	 * Where the extended TI is used, the TI IE includes a second octet. The TI value in the first octet is ignored, and the TI
	 * value is encoded in bits 7-1 of the second octet.
	 */

	if (curr_len > 1)
	{
		curr_offset++;
		oct = tvb_get_guint8(tvb, curr_offset);

		proto_tree_add_uint(tree, hf_gsm_a_gm_ti_value, tvb, curr_offset, 1, oct&0x7f);

		proto_tree_add_item(tree, hf_gsm_a_sm_ext, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

		curr_offset++;
	}
	else
	{
		proto_tree_add_uint(tree, hf_gsm_a_gm_ti_value, tvb, curr_offset, 1, (oct>>4)&7);
		curr_offset++;
	}


	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_gm_extraneous_data);

	return (curr_offset - offset);
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

static uint16_t
de_sm_sapi(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, offset << 3, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_sm_llc_sapi, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* no length check possible */
	return 1;
}

/*
 * [9] 10.5.6.10 Tear down indicator
 */
static const true_false_string gsm_a_sm_tdi_value = {
	"Tear down requested",
	"Tear down not requested"
};

static uint16_t
de_sm_tear_down(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (offset << 3) + 4, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_sm_tdi, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* no length check possible */
	return 1;
}

/*
 * [9] 10.5.6.11 Packet Flow Identifier
 */
static const range_string gsm_a_sm_packet_flow_id_vals[] = {
	{ 0x00,	0x00, "Best Effort"},
	{ 0x01,	0x01, "Signalling"},
	{ 0x02,	0x02, "SMS"},
	{ 0x03,	0x03, "TOM8"},
	{ 0x04,	0x07, "Reserved"},
	{ 0x08,	0x7f, "Dynamically assigned"},
	{ 0x00, 0x00, NULL }
};

uint16_t
de_sm_pflow_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t	curr_offset;
	unsigned   value;

	curr_offset = offset;
	value = tvb_get_guint8(tvb, curr_offset);
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, curr_offset << 3, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_sm_packet_flow_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	if (add_string)
		snprintf(add_string, string_len, " - %s", rval_to_str_const(value, gsm_a_sm_packet_flow_id_vals, "Unknown"));

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_gm_extraneous_data);

	return (curr_offset - offset);
}

/*
 * [7] 10.5.6.12     TFT - Traffic Flow Template
 */
/* TFT operation code (octet 3) */
static const value_string gsm_a_sm_tft_op_code_vals[] = {
	{ 0,		"Ignore this IE"},
	{ 1,		"Create new TFT"},
	{ 2,		"Delete existing TFT"},
	{ 3,		"Add packet filters to existing TFT"},
	{ 4,		"Replace packet filters in existing TFT"},
	{ 5,		"Delete packet filters from existing TFT"},
	{ 6,		"No TFT operation"},
	{ 7,		"Reserved"},
	{ 0,	NULL }
};

static const true_false_string gsm_a_sm_tft_e_bit  = {
	"Parameters list is included",
	"Parameters list is not included"
};

static const value_string gsm_a_sm_tft_pkt_flt_dir_vals[] = {
	{ 0,	"Pre Rel-7 TFT filter"},
	{ 1,	"Downlink only"},
	{ 2,	"Uplink only"},
	{ 3,	"Bidirectional"},
	{ 0,	NULL }
};

static const value_string gsm_a_sm_tft_param_id_vals[] = {
	{ 1,	"Authorization Token"},
	{ 2,	"Flow Identifier"},
	{ 3,	"Packet Filter Identifier"},
	{ 0,	NULL }
};

static const value_string packet_filter_component_type_vals[] = {
	{0x10,  "IPv4 remote address type" },
	{0x11,  "IPv4 local address type"},
	{0x20,  "IPv6 remote address type"},
	{0x21,  "IPv6 remote address/prefix length type"},
	{0x23,  "IPv6 local address/prefix length type"},
	{0x30,  "Protocol identifier/Next header type"},
	{0x40,  "Single local port type"},
	{0x41,  "Local port range type"},
	{0x50,  "Single remote port type"},
	{0x51,  "Remote port range type"},
	{0x60,  "Security parameter index type"},
	{0x70,  "Type of service/Traffic class type"},
	{0x80,  "Flow label type"},
	{0x81,  "Destination MAC address type" },
	{0x82,  "Source MAC address type" },
	{0x83,  "802.1Q C-TAG VID type" },
	{0x84,  "802.1Q S-TAG VID type" },
	{0x85,  "802.1Q C-TAG PCP/DEI type" },
	{0x86,  "802.1Q S-TAG PCP/DEI type" },
	{0x87,  "Ethertype type" },
	{0, NULL}
};

uint16_t
de_sm_tflow_temp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t	      curr_offset, prev_offset;
	unsigned	      curr_len;
	uint8_t       op_code;
	uint8_t       pkt_fil_count;
	uint8_t       e_bit;
	uint8_t       count;
	uint8_t       oct;
	int           pf_length;
	int           i;
	int           pack_component_type;
	int           param;

	curr_len    = len;
	curr_offset = offset;

	/*
	 * parse first octet. It contain TFT operation code, E bit and Number of packet filters
	 */
	oct = tvb_get_guint8(tvb, curr_offset);

	op_code = oct>>5;
	pkt_fil_count = oct&0x0f;
	e_bit = (oct>>4)&1;

	proto_tree_add_item(tree, hf_gsm_a_sm_tft_op_code, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_sm_tft_e_bit,   tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_sm_tft_pkt_flt, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	curr_offset++;
	curr_len--;

	/* Packet filter list dissect */

	count = 0;
	if (op_code == 2)			/* delete TFT contains no packet filters. so we will jump over it */
		count = pkt_fil_count;
	while (count < pkt_fil_count)
	{
		proto_item *tf_pf;
		proto_tree *tf_tree;
		prev_offset = curr_offset;
		tf_pf = proto_tree_add_uint(tree, hf_gsm_a_sm_tft_packet_filter, tvb, curr_offset, 1, count);   /* 0-> 7 */

		tf_tree = proto_item_add_subtree(tf_pf, ett_sm_tft);

		if ((curr_offset-offset)<1) {
			proto_tree_add_expert(tf_tree, pinfo, &ei_gsm_a_gm_not_enough_data, tvb, curr_offset, 1);
			return (len);
		}

		if (op_code == 5)  /* Delete packet filters from existing TFT - just a list of identifiers */
		{
			proto_tree_add_bits_item(tf_tree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3), 4, ENC_BIG_ENDIAN);
			oct = tvb_get_guint8(tvb, curr_offset) & 0x0f;
			proto_tree_add_uint_format_value(tf_tree, hf_gsm_a_sm_tft_pkt_flt_id, tvb, curr_offset, 1, oct, "%d (%d)", oct+1, oct);
			curr_offset++;
			curr_len--;
			count++;
		}
		else				/* create new, Add packet filters or Replace packet filters */
		{
			proto_tree_add_bits_item(tf_tree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3), 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tf_tree, hf_gsm_a_sm_tft_pkt_flt_dir, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
			oct = tvb_get_guint8(tvb, curr_offset) & 0x0f;
			proto_tree_add_uint_format_value(tf_tree, hf_gsm_a_sm_tft_pkt_flt_id, tvb, curr_offset, 1, oct, "%d (%d)", oct+1, oct);
			curr_offset++;
			curr_len--;

			if ((curr_offset-offset) < 1) {
				proto_tree_add_expert(tf_tree, pinfo, &ei_gsm_a_gm_not_enough_data, tvb, curr_offset, 1);
				return (len);
			}
			proto_tree_add_item(tf_tree, hf_gsm_a_sm_tft_packet_evaluation_precedence, tvb, curr_offset, 1, ENC_NA);
			curr_offset++;
			curr_len--;

			if ((curr_offset-offset)<1) {
				proto_tree_add_expert(tf_tree, pinfo, &ei_gsm_a_gm_not_enough_data, tvb, curr_offset, 1);
				return (len);
			}
			pf_length = tvb_get_guint8(tvb, curr_offset);
			proto_tree_add_item(tf_tree, hf_gsm_a_sm_tft_packet_filter_length, tvb, curr_offset, 1, ENC_NA);
			curr_offset++;
			curr_len--;

			/* New tree for component */

			/* Dissect Packet filter Component */
			/* while (filter_len > 1) */
			/* packet filter component type identifier: */

			while (pf_length > 0) {
				proto_item *tf;
				proto_tree *comp_tree;
				if ((curr_offset-offset) < 1) {
					proto_tree_add_expert(tf_tree, pinfo, &ei_gsm_a_gm_not_enough_data, tvb, curr_offset, 1);
					return (len);
				}
				pack_component_type = tvb_get_guint8(tvb, curr_offset);
				tf = proto_tree_add_item(tf_tree, hf_gsm_a_sm_tft_packet_filter_component_type_id, tvb, curr_offset, 1, ENC_NA);
				comp_tree = proto_item_add_subtree(tf, ett_sm_tft);

				curr_offset++;
				curr_len--;
				pf_length--;

				switch (pack_component_type) {

				case 0x10:
					proto_tree_add_item(comp_tree, hf_gsm_a_sm_ip4_address, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
					curr_offset += 4;
					curr_len    -= 4;
					proto_tree_add_item(comp_tree, hf_gsm_a_sm_ip4_mask, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
					curr_offset += 4;
					curr_len    -= 4;
					pf_length   -= 8;
					break;

				case 0x11:
					proto_tree_add_item(comp_tree, hf_gsm_a_sm_ip4_address, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
					curr_offset += 4;
					curr_len    -= 4;
					proto_tree_add_item(comp_tree, hf_gsm_a_sm_ip4_mask, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
					curr_offset += 4;
					curr_len    -= 4;
					pf_length   -= 8;
					break;

				case 0x20:
					proto_tree_add_item(comp_tree, hf_gsm_a_sm_ip6_address, tvb, curr_offset, 16, ENC_NA);
					curr_offset += 16;
					curr_len    -= 16;
					proto_tree_add_item(comp_tree, hf_gsm_a_sm_ip6_mask, tvb, curr_offset, 16, ENC_NA);
					curr_offset += 16;
					curr_len    -= 16;
					pf_length   -= 32;
					break;

				case 0x21:
					proto_tree_add_item(comp_tree, hf_gsm_a_sm_ip6_address, tvb, curr_offset, 16, ENC_NA);
					curr_offset += 16;
					curr_len    -= 16;
					proto_tree_add_item(comp_tree, hf_gsm_a_sm_ip6_prefix_length, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
					curr_offset += 1;
					curr_len    -= 1;
					pf_length   -= 17;
					break;

				case 0x23:
					proto_tree_add_item(comp_tree, hf_gsm_a_sm_ip6_address, tvb, curr_offset, 16, ENC_NA);
					curr_offset += 16;
					curr_len    -= 16;
					proto_tree_add_item(comp_tree, hf_gsm_a_sm_ip6_prefix_length, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
					curr_offset += 1;
					curr_len    -= 1;
					pf_length   -= 17;
					break;

				case 0x30:
					proto_tree_add_item(comp_tree, hf_gsm_a_sm_tft_protocol_header, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
					curr_offset += 1;
					curr_len    -= 1;
					pf_length   -= 1;
					break;

				case 0x40:
					proto_tree_add_item(comp_tree, hf_gsm_a_sm_tft_port, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
					curr_offset += 2;
					curr_len    -= 2;
					pf_length   -= 2;
					break;

				case 0x41:
					proto_tree_add_item(comp_tree, hf_gsm_a_sm_tft_port_low, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
					curr_offset += 2;
					proto_tree_add_item(comp_tree, hf_gsm_a_sm_tft_port_high, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
					curr_offset += 2;
					curr_len    -= 4;
					pf_length   -= 4;
					break;

				case 0x50:
					proto_tree_add_item(comp_tree, hf_gsm_a_sm_tft_port, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
					curr_offset += 2;
					curr_len    -= 2;
					pf_length   -= 2;
					break;

				case 0x51:
					proto_tree_add_item(comp_tree, hf_gsm_a_sm_tft_port_low, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
					curr_offset += 2;
					proto_tree_add_item(comp_tree, hf_gsm_a_sm_tft_port_high, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
					curr_offset += 2;
					curr_len    -= 4;
					pf_length   -= 4;
					break;

				case 0x60:
					proto_tree_add_item(comp_tree, hf_gsm_a_sm_tft_security, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
					curr_offset += 4;
					curr_len    -= 4;
					pf_length   -= 4;
					break;


				case 0x70:
					proto_tree_add_item(comp_tree, hf_gsm_a_sm_tft_traffic_class, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
					curr_offset++;
					proto_tree_add_item(comp_tree, hf_gsm_a_sm_tft_traffic_mask, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
					curr_offset++;
					curr_len-=2;
					pf_length-=2;
					break;

				case 0x80:
					proto_tree_add_bits_item(comp_tree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3), 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(comp_tree, hf_gsm_a_sm_tft_flow_label_type, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
					curr_offset += 3;
					curr_len    -= 3;
					pf_length   -= 3;
					break;

				case 0x81:
				case 0x82:
					proto_tree_add_item(comp_tree, hf_gsm_a_sm_tft_mac_addr, tvb, curr_offset, 6, ENC_NA);
					curr_offset += 6;
					curr_len    -= 6;
					pf_length   -= 6;
					break;

				case 0x83:
				case 0x84:
					proto_tree_add_item(comp_tree, hf_gsm_a_sm_tft_vlan_tag_vid, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
					curr_offset += 2;
					curr_len    -= 2;
					pf_length   -= 2;
					break;

				case 0x85:
				case 0x86:
					proto_tree_add_item(comp_tree, hf_gsm_a_sm_tft_vlan_tag_pcp, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(comp_tree, hf_gsm_a_sm_tft_vlan_tag_dei, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
					curr_offset += 1;
					curr_len    -= 1;
					pf_length   -= 1;
					break;

				case 0x87:
					proto_tree_add_item(comp_tree, hf_gsm_a_sm_tft_ethertype, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
					curr_offset += 2;
					curr_len    -= 2;
					pf_length   -= 2;
					break;

				default:
					curr_offset += pf_length;
					curr_len    -= pf_length;
					pf_length    = 0;
				}
			}
			count++;
		}
		proto_item_set_len(tf_pf, curr_offset - prev_offset);
	}

	/* The parameters list contains a variable number of parameters that might need to be
	 * transferred in addition to the packet filters. If the parameters list is included, the E
	 * bit is set to 1; otherwise, the E bit is set to 0.
	 */
	if ((e_bit == 1) && curr_len) {
		count = 0;
		while (curr_len) {
			proto_tree *tf_tree;
			pf_length = tvb_get_guint8(tvb, curr_offset+1);
			tf_tree   = proto_tree_add_subtree_format(tree, tvb, curr_offset, pf_length+2, ett_sm_tft, NULL, "Parameter %d", count);
			param     = tvb_get_guint8(tvb, curr_offset);
			proto_tree_add_item(tf_tree, hf_gsm_a_sm_tft_param_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
			curr_offset += 2;
			curr_len    -= 2;
			switch (param) {
			case 0x01:
				proto_tree_add_item(tf_tree, hf_gsm_a_sm_tft_authorization_token_value, tvb, curr_offset, pf_length, ENC_NA);
				break;

			case 0x02:
				proto_tree_add_item(tf_tree, hf_gsm_a_sm_tft_media_component_number_value, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(tf_tree, hf_gsm_a_sm_tft_ip_flow_number, tvb, curr_offset+2, 2, ENC_BIG_ENDIAN);
				break;

			case 0x03:
				for (i=0; i<pf_length; i++) {
					oct = tvb_get_guint8(tvb, curr_offset+i) & 0x0f;
					proto_tree_add_uint_format(tf_tree, hf_gsm_a_sm_tft_packet_filter_identifier, tvb, curr_offset+i, 1, oct+1, "Packet filter identifier %d: %d (%d)", i, oct+1, oct);
				}
				break;

			default:
				proto_tree_add_item(tf_tree, hf_gsm_a_sm_tft_parameter_content, tvb, curr_offset, pf_length, ENC_NA);
				break;
			}
			curr_offset += pf_length;
			curr_len    -= pf_length;
			count++;
		}
	}

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_gm_extraneous_data);

	return (len);
}

/*
 * [9] 10.5.6.13 Temporary Mobile Group Identity (TMGI)
 */
uint16_t
de_sm_tmgi(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_sm_tmgi, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
	curr_offset += 3;

	NO_MORE_DATA_CHECK(len);
	curr_offset = dissect_e212_mcc_mnc(tvb, pinfo, tree, curr_offset, E212_NONE, true);

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_gm_extraneous_data);

	return (curr_offset - offset);
}

/*
 * [9] 10.5.6.14 MBMS bearer capabilities
 */
static uint16_t
de_sm_mbms_bearer_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t     curr_offset, temp32;
	uint8_t      oct;
	const char *str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch (oct)
	{
		case 0x00: str = "Subscribed maximum bit rate for downlink/reserved"; break;
		case 0xff: str = "0 kbps"; break;
		default:   str = wmem_strdup_printf(pinfo->pool, "%u kbps", qos_calc_bitrate(oct));
	}

	proto_tree_add_uint_format_value(tree, hf_gsm_a_sm_qos_max_bitrate_downl, tvb,
		curr_offset, 1, oct, "%s (%u)", str, oct);
	curr_offset += 1;

	NO_MORE_DATA_CHECK(len);

	oct = tvb_get_guint8(tvb, curr_offset);

	if (oct == 0x00)
		str = "Use the value indicated by the Maximum bit rate for downlink";
	else
	{
		temp32 = qos_calc_ext_bitrate(oct);
		if (temp32 % 1000 == 0)
			str = wmem_strdup_printf(pinfo->pool, "%u Mbps", temp32 / 1000);
		else
			str = wmem_strdup_printf(pinfo->pool, "%u kbps", temp32);
	}
	proto_tree_add_uint_format_value(tree, hf_gsm_a_sm_qos_max_bitrate_downl_ext, tvb,
		curr_offset, 1, oct, "%s (%u)", str, oct);

	curr_offset += 1;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_gm_extraneous_data);

	return (curr_offset - offset);
}

/*
 * [9] 10.5.6.15 MBMS protocol configuration options
 */
uint16_t
de_sm_mbms_prot_conf_opt(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t	curr_offset;

	curr_offset = offset;
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3), 8, ENC_BIG_ENDIAN);
	curr_offset++;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_gm_extraneous_data);

	return (curr_offset - offset);
}

/*
 * [9] 10.5.6.16 Enhanced network service access point identifier
 */
static uint16_t
de_sm_enh_nsapi(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	uint8_t      oct;
	const char *str;

	oct = tvb_get_guint8(tvb, offset);

	if(oct < 0x80)
		str = "Reserved";
	else if (oct < 0xff)
			str = wmem_strdup_printf(pinfo->pool, "NSAPI %u for Multimedia Broadcast/Multicast Service (MBMS) Multicast mode", oct);
		else
			str = "Reserved for use by lower layers in the p2p radio bearer allocation message for MBMS Broadcast mode";


	proto_tree_add_uint_format_value(tree, hf_gsm_a_sm_enh_nsapi, tvb,
		offset, 1, oct, "%s (%u)", str, oct);

	/* no length check possible */
	return 1;
}

/*
 * [9] 10.5.6.17 Request type
 */
static const value_string gsm_a_sm_req_type_vals[] = {
	{ 0x01,	"Initial request" },
	{ 0x02, "Handover" },
	{ 0x03, "RLOS" },
	{ 0x04, "Emergency" },
	{ 0x06, "Handover of emergency bearer services" },
	{ 0, NULL }
};

static uint16_t
de_sm_req_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (offset<<3) + 4, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_gsm_a_sm_req_type, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* no length check possible */
	return 1;
}

/*
 * [9] 10.5.6.18 Notification indicator
 */
static const value_string gsm_a_sm_notif_ind_vals[] = {
	{ 0x0,	"Reserved"},
	{ 0x1,	"SRVCC handover cancelled, IMS session re-establishment required"},
	{ 0, NULL }
};

static uint16_t
de_sm_notif_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_sm_notif_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	return (len);
}

/*
 * [10] 10.5.6.19 Connectivity type
 */
static const range_string gsm_a_sm_connectivity_type_vals[] = {
	{ 0x0,	0x0, "The PDN connection type is not indicated"},
	{ 0x1,	0x1, "The PDN connection is considered a LIPA PDN connection"},
	{ 0x2,	0xF, "The PDN connection type is not indicated"},
	{ 0, 0, NULL }
};

static uint16_t
de_sm_connectivity_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_item(tree, hf_gsm_a_sm_connectivity_type, tvb, offset, 1, ENC_BIG_ENDIAN);

	return (len);
}

/*
 * [12] 10.5.6.20 WLAN offload acceptability
 */
static const true_false_string gsm_a_sm_wlan_utran_offload_accept_value = {
	"Offloading the traffic of the PDN connection via a WLAN when in Iu mode is acceptable",
	"Offloading the traffic of the PDN connection via a WLAN when in Iu mode is not acceptable"
};

static const true_false_string gsm_a_sm_wlan_eutran_offload_accept_value = {
	"Offloading the traffic of the PDN connection via a WLAN when in S1 mode is acceptable",
	"Offloading the traffic of the PDN connection via a WLAN when in S1 mode is not acceptable"
};

static uint16_t
de_sm_wlan_offload_accept(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (offset<<3)+4, 2, ENC_BIG_ENDIAN);
	proto_tree_add_bits_item(tree, hf_gsm_a_sm_wlan_utran_offload_accept, tvb, (offset<<3)+6, 1, ENC_BIG_ENDIAN);
	proto_tree_add_bits_item(tree, hf_gsm_a_sm_wlan_eutran_offload_accept, tvb, (offset<<3)+7, 1, ENC_BIG_ENDIAN);

	return (len);
}

/*
 * [13] 10.5.6.21 NBIFOM container
 */
static uint16_t
de_sm_nbifom_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	if (nbifom_handle) {
		tvbuff_t *nbifom_tvb = tvb_new_subset_length(tvb, offset, len);

		call_dissector(nbifom_handle, nbifom_tvb, pinfo, tree);
	} else {
		proto_tree_add_item(tree, hf_gsm_a_sm_nbifom_cont, tvb, offset, len, ENC_NA);
	}

	return len;
}

uint16_t (*gm_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string, int string_len) = {
	/* GPRS Mobility Management Information Elements 10.5.5 */
	de_gmm_add_upd_type,               /* Additional Update Type */
	de_gmm_attach_res,                 /* Attach Result */
	de_gmm_attach_type,                /* Attach Type */
	de_gmm_ciph_alg,                   /* Ciphering Algorithm */
	de_gmm_integ_alg,                  /* Integrity Algorithm */
	de_gmm_tmsi_stat,                  /* TMSI Status */
	de_gmm_detach_type,                /* Detach Type */
	de_gmm_drx_param,                  /* DRX Parameter */
	de_gmm_ftostby,                    /* Force to Standby */
	de_gmm_ftostby_h,                  /* Force to Standby - Info is in the high nibble */
	de_gmm_ptmsi_sig,                  /* P-TMSI Signature */
	de_gmm_ptmsi_sig2,                 /* P-TMSI Signature 2 */
	de_gmm_ident_type2,                /* Identity Type 2 */
	de_gmm_imeisv_req,                 /* IMEISV Request */
	de_gmm_rec_npdu_lst,               /* Receive N-PDU Numbers List */
	de_gmm_ms_net_cap,                 /* MS Network Capability */
	de_gmm_ms_radio_acc_cap,           /* MS Radio Access Capability */
	de_gmm_cause,                      /* GMM Cause */
	de_gmm_rai,                        /* Routing Area Identification */
	de_gmm_rai2,                       /* Routing Area Identification 2 */
	de_gmm_update_res,                 /* Update Result */
	de_gmm_update_type,                /* Update Type */
	de_gmm_ac_ref_nr,                  /* A&C Reference Number */
	de_gmm_ac_ref_nr_h,                /* A&C Reference Number - Info is in the high nibble */
	de_gmm_service_type,               /* Service Type */
	NULL  /* no associated data */,	   /* Cell Notification */
	de_gmm_ps_lcs_cap,                 /* PS LCS Capability */
	de_gmm_net_feat_supp,              /* Network Feature Support */
	de_gmm_add_net_feat_supp,          /* Network Feature Support */
	de_gmm_rat_info_container,         /* Inter RAT information container */
	de_gmm_req_ms_info,                /* Requested MS information */
	NULL,                              /* UE network capability */
	de_gmm_eutran_irat_info_container, /* E-UTRAN inter RAT information container */
	de_gmm_voice_domain_pref,          /* Voice domain preference and UE's usage setting */
	de_gmm_ptmsi_type,                 /* P-TMSI type */
	de_gmm_lai_2,                      /* Location Area Identification 2 */
	de_gmm_net_res_id_cont,            /* Network resource identifier container */
	de_gmm_ext_drx_params,             /* Extended DRX parameters */
	de_gmm_mac,                        /* Message authentication code */
	de_gmm_up_integ_ind,               /* User Plane integrity indicator */
	de_gmm_dcn_id,                     /* DCN-ID */
	de_gmm_plmn_id_cn_operator,        /* PLMN identity of the CN operator */
	de_gmm_non_3gpp_nw_prov_pol,       /* Non-3GPP NW provided policies */
	/* Session Management Information Elements 10.5.6 */
	de_sm_apn,                         /* Access Point Name */
	de_sm_nsapi,                       /* Network Service Access Point Identifier */
	de_sm_pco,                         /* Protocol Configuration Options */
	de_sm_pco,                         /* Extended Protocol Configuration Options */
	de_sm_pdp_addr,                    /* Packet Data Protocol Address */
	de_sm_qos,                         /* Quality Of Service */
	de_sm_re_attempt_ind,              /* Re-attempt indicator */
	de_sm_ext_qos,                     /* Extended quality of service */
	de_sm_cause,                       /* SM Cause */
	de_sm_cause_2,                     /* SM Cause 2 */
	de_sm_linked_ti,                   /* Linked TI */
	de_sm_sapi,                        /* LLC Service Access Point Identifier */
	de_sm_tear_down,                   /* Tear Down Indicator */
	de_sm_pflow_id,                    /* Packet Flow Identifier */
	de_sm_tflow_temp,                  /* Traffic Flow Template */
	de_sm_tmgi,                        /* Temporary Mobile Group Identity (TMGI) */
	de_sm_mbms_bearer_cap,             /* MBMS bearer capabilities */
	de_sm_mbms_prot_conf_opt,          /* MBMS protocol configuration options */
	de_sm_enh_nsapi,                   /* Enhanced network service access point identifier */
	de_sm_req_type,                    /* Request type */
	de_sm_notif_ind,                   /* Notification indicator */
	de_sm_connectivity_type,           /* Connectivity type */
	de_sm_wlan_offload_accept,         /* WLAN offload acceptability */
	de_sm_nbifom_cont,                 /* NBIFOM container */
	/* GPRS Common Information Elements 10.5.7 */
	de_gc_context_stat,                /* PDP Context Status */
	de_gc_radio_prio,                  /* Radio Priority */
	de_gc_timer,                       /* GPRS Timer */
	de_gc_timer2,                      /* GPRS Timer 2 */
	de_gc_timer3,                      /* GPRS Timer 3 */
	de_gc_radio_prio2,                 /* Radio Priority 2 */
	de_gc_mbms_context_stat,           /* 10.5.7.6 MBMS context status */
	de_gc_uplink_data_stat,            /* 10.5.7.7 Uplink data status */
	de_gc_device_properties,           /* 10.5.7.8 Device properties */
	NULL,	/* NONE */
};

/* MESSAGE FUNCTIONS */

/*
 * [7] 9.4.1
 */
static void
dtap_gmm_attach_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_RECV;

	ELEM_MAND_LV( GSM_A_PDU_TYPE_GM, DE_MS_NET_CAP, NULL, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_VV_SHORT(GSM_A_PDU_TYPE_GM, DE_ATTACH_TYPE, GSM_A_PDU_TYPE_COMMON, DE_CIPH_KEY_SEQ_NUM, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_DRX_PARAM, NULL, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_LV( GSM_A_PDU_TYPE_COMMON, DE_MID, NULL, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_RAI, " - Old routing area identification", ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_LV( GSM_A_PDU_TYPE_GM, DE_MS_RAD_ACC_CAP, NULL, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_OPT_TV( 0x19, GSM_A_PDU_TYPE_GM, DE_P_TMSI_SIG, " - Old P-TMSI Signature");

	ELEM_OPT_TV( 0x17, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER, " - Ready Timer");

	ELEM_OPT_TV_SHORT( 0x90, GSM_A_PDU_TYPE_GM, DE_TMSI_STAT, NULL);

	ELEM_OPT_TLV( 0x33, GSM_A_PDU_TYPE_GM, DE_PS_LCS_CAP, NULL);

	ELEM_OPT_TLV( 0x11, GSM_A_PDU_TYPE_COMMON, DE_MS_CM_2, NULL);

	ELEM_OPT_TLV( 0x20, GSM_A_PDU_TYPE_COMMON, DE_MS_CM_3, NULL);

	ELEM_OPT_TLV( 0x40, GSM_A_PDU_TYPE_DTAP, DE_SUP_CODEC_LIST, NULL);

	ELEM_OPT_TLV( 0x58, NAS_PDU_TYPE_EMM, DE_EMM_UE_NET_CAP, NULL);

	ELEM_OPT_TLV( 0x1A, GSM_A_PDU_TYPE_COMMON, DE_MID, " - Additional mobile identity");

	ELEM_OPT_TLV( 0x1B, GSM_A_PDU_TYPE_GM, DE_RAI_2, " - Additional old routing area identification");

	ELEM_OPT_TLV( 0x5D, GSM_A_PDU_TYPE_GM, DE_VOICE_DOMAIN_PREF, NULL);

	ELEM_OPT_TV_SHORT(0xD0, GSM_A_PDU_TYPE_GM, DE_DEVICE_PROPERTIES, NULL);

	ELEM_OPT_TV_SHORT(0xE0, GSM_A_PDU_TYPE_GM, DE_PTMSI_TYPE, NULL);

	ELEM_OPT_TV_SHORT(0xC0, GSM_A_PDU_TYPE_COMMON, DE_MS_NET_FEAT_SUP, NULL);

	ELEM_OPT_TLV(0x14, GSM_A_PDU_TYPE_GM, DE_LAI_2, " - Old location area identification");

	ELEM_OPT_TV_SHORT(0xF0, GSM_A_PDU_TYPE_GM, DE_ADD_UPD_TYPE, NULL);

	ELEM_OPT_TLV(0x10, GSM_A_PDU_TYPE_GM, DE_NET_RES_ID_CONT, " - TMSI based NRI container");

	ELEM_OPT_TLV(0x6A, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3324 value");

	ELEM_OPT_TLV(0x39, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - T3312 extended value");

	ELEM_OPT_TLV(0x6E, GSM_A_PDU_TYPE_GM, DE_EXT_DRX_PARAMS, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [7] 9.4.2
 */
static void
dtap_gmm_attach_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_VV_SHORT(GSM_A_PDU_TYPE_GM, DE_ATTACH_RES, GSM_A_PDU_TYPE_GM, DE_FORCE_TO_STAND_H, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER, NULL, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_RAD_PRIO_2, " - Radio priority for TOM8", ei_gsm_a_gm_missing_mandatory_element);
	curr_len++;
	curr_offset--;

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_RAD_PRIO, " - Radio priority for SMS", ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_RAI, NULL, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_OPT_TV( 0x19, GSM_A_PDU_TYPE_GM, DE_P_TMSI_SIG, NULL);

	ELEM_OPT_TV( 0x17, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER, " - Negotiated Ready Timer");

	ELEM_OPT_TLV( 0x18, GSM_A_PDU_TYPE_COMMON, DE_MID, " - Allocated P-TMSI");

	ELEM_OPT_TLV( 0x23, GSM_A_PDU_TYPE_COMMON, DE_MID, NULL);

	ELEM_OPT_TV( 0x25, GSM_A_PDU_TYPE_GM, DE_GMM_CAUSE, NULL);

	ELEM_OPT_TLV( 0x2A, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3302 value");

	ELEM_OPT_T( 0x8C, GSM_A_PDU_TYPE_GM, DE_CELL_NOT, NULL);

	ELEM_OPT_TLV( 0x4A, GSM_A_PDU_TYPE_COMMON, DE_PLMN_LIST, NULL);

	ELEM_OPT_TV_SHORT( 0xB0, GSM_A_PDU_TYPE_GM, DE_NET_FEAT_SUP, NULL);

	ELEM_OPT_TLV( 0x34, GSM_A_PDU_TYPE_DTAP, DE_EMERGENCY_NUM_LIST, NULL);

	ELEM_OPT_TV_SHORT( 0xA0, GSM_A_PDU_TYPE_GM, DE_REQ_MS_INFO, NULL);

	ELEM_OPT_TLV( 0x37, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3319 value");

	ELEM_OPT_TLV( 0x38, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3323 value" );

	ELEM_OPT_TLV(0x39, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - T3312 extended value");

	ELEM_OPT_TLV(0x66, GSM_A_PDU_TYPE_GM, DE_ADD_NET_FEAT_SUP, NULL);

	ELEM_OPT_TLV(0x6A, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3324 value");

	ELEM_OPT_TLV(0x6E, GSM_A_PDU_TYPE_GM, DE_EXT_DRX_PARAMS, NULL);

	ELEM_OPT_TV_SHORT(0xC0, GSM_A_PDU_TYPE_GM, DE_UP_INTEG_IND, NULL);

	ELEM_OPT_TLV(0x31, GSM_A_PDU_TYPE_GM, DE_MS_NET_CAP, " - Replayed MS network capability");

	ELEM_OPT_TLV(0x33, GSM_A_PDU_TYPE_GM, DE_MS_RAD_ACC_CAP, " - Replayed MS Radio Access capability");

	ELEM_OPT_TLV(0x65, GSM_A_PDU_TYPE_GM, DE_DCN_ID, NULL);

	ELEM_OPT_TLV(0x63, GSM_A_PDU_TYPE_GM, DE_PLMN_ID_CN_OPERATOR, NULL);

	ELEM_OPT_TV_SHORT(0xD0, GSM_A_PDU_TYPE_GM, DE_NON_3GPP_NW_PROV_POL, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [7] 9.4.3
 */
static void
dtap_gmm_attach_com(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{

	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_RECV;

	ELEM_OPT_TLV( 0x27, GSM_A_PDU_TYPE_GM, DE_RAT_INFO_CONTAINER, " - Inter RAT handover information");

	ELEM_OPT_TLV( 0x2B, GSM_A_PDU_TYPE_GM, DE_EUTRAN_IRAT_INFO_CONTAINER, " - E-UTRAN inter RAT handover information");

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [7] 9.4.4
 */
static void
dtap_gmm_attach_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_GMM_CAUSE, NULL, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_OPT_TLV( 0x2A, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3302 value" );

	ELEM_OPT_TLV(0x3A, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3346 value");

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [7] 9.4.5
 */
static void
dtap_gmm_detach_req_MT(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_VV_SHORT(GSM_A_PDU_TYPE_GM, DE_DETACH_TYPE, GSM_A_PDU_TYPE_GM, DE_FORCE_TO_STAND_H, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_OPT_TV( 0x25, GSM_A_PDU_TYPE_GM, DE_GMM_CAUSE, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

static void
dtap_gmm_detach_req_MO(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_RECV;

	ELEM_MAND_VV_SHORT(GSM_A_PDU_TYPE_GM, DE_DETACH_TYPE, GSM_A_PDU_TYPE_COMMON, DE_SPARE_NIBBLE, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_OPT_TLV( 0x18, GSM_A_PDU_TYPE_COMMON, DE_MID, NULL);

	ELEM_OPT_TLV( 0x19, GSM_A_PDU_TYPE_GM, DE_P_TMSI_SIG_2, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

static void
dtap_gmm_detach_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	if (pinfo->link_dir == P2P_DIR_UL) {
		dtap_gmm_detach_req_MO(tvb, tree, pinfo, offset, len);
		return;
	}else if (pinfo->link_dir == P2P_DIR_DL) {
		dtap_gmm_detach_req_MT(tvb, tree, pinfo, offset, len);
		return;
	} else {
		/* Unknown direction. Try heuristics based on message length. */
		if (len > 5) {
			dtap_gmm_detach_req_MO(tvb, tree, pinfo, offset, len);
		} else {
			dtap_gmm_detach_req_MT(tvb, tree, pinfo, offset, len);
		}
	}
}

/*
 * [7] 9.4.6
 */
static void
dtap_gmm_detach_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_RECV;

	if (curr_len == 0) {
		return;
	}

	ELEM_MAND_VV_SHORT(GSM_A_PDU_TYPE_GM, DE_FORCE_TO_STAND, GSM_A_PDU_TYPE_COMMON, DE_SPARE_NIBBLE, ei_gsm_a_gm_missing_mandatory_element);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [7] 9.4.7
 */
static void
dtap_gmm_ptmsi_realloc_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_LV( GSM_A_PDU_TYPE_COMMON, DE_MID, " - Allocated P-TMSI", ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_RAI, NULL, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_VV_SHORT(GSM_A_PDU_TYPE_GM, DE_FORCE_TO_STAND, GSM_A_PDU_TYPE_COMMON, DE_SPARE_NIBBLE, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_OPT_TV( 0x19, GSM_A_PDU_TYPE_GM, DE_P_TMSI_SIG, " - P-TMSI Signature" );

	ELEM_OPT_TLV(0x65, GSM_A_PDU_TYPE_GM, DE_DCN_ID, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [7] 9.4.8
 */
static void
dtap_gmm_ptmsi_realloc_com(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
/*    uint32_t	consumed; */
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_RECV;

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [7] 9.4.9
 */
static void
dtap_gmm_auth_ciph_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned   curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_VV_SHORT(GSM_A_PDU_TYPE_GM, DE_CIPH_ALG, GSM_A_PDU_TYPE_GM, DE_IMEISV_REQ, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_VV_SHORT(GSM_A_PDU_TYPE_GM, DE_FORCE_TO_STAND, GSM_A_PDU_TYPE_GM, DE_AC_REF_NUM_H, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_OPT_TV(0x21, GSM_A_PDU_TYPE_DTAP, DE_AUTH_PARAM_RAND, NULL);

	ELEM_OPT_TV_SHORT(0x80, GSM_A_PDU_TYPE_COMMON, DE_CIPH_KEY_SEQ_NUM, NULL);

	ELEM_OPT_TLV(0x28, GSM_A_PDU_TYPE_DTAP, DE_AUTH_PARAM_AUTN, NULL);

	ELEM_OPT_TLV(0x31, GSM_A_PDU_TYPE_GM, DE_MS_NET_CAP, " - Replayed MS network capability");

	ELEM_OPT_TLV(0x42, GSM_A_PDU_TYPE_GM, DE_INTEG_ALG, NULL);

	ELEM_OPT_TLV(0x43, GSM_A_PDU_TYPE_GM, DE_MAC, NULL);

	ELEM_OPT_TLV(0x33, GSM_A_PDU_TYPE_GM, DE_MS_RAD_ACC_CAP, " - Replayed MS Radio Access capability");

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [7] 9.4.10
 */
static void
dtap_gmm_auth_ciph_resp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_RECV;

	ELEM_MAND_VV_SHORT(GSM_A_PDU_TYPE_GM, DE_AC_REF_NUM, GSM_A_PDU_TYPE_COMMON, DE_SPARE_NIBBLE, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_OPT_TV(0x22, GSM_A_PDU_TYPE_DTAP, DE_AUTH_RESP_PARAM, NULL);

	ELEM_OPT_TLV(0x23, GSM_A_PDU_TYPE_COMMON, DE_MID, " - IMEISV" );

	ELEM_OPT_TLV(0x29, GSM_A_PDU_TYPE_DTAP, DE_AUTH_RESP_PARAM_EXT, NULL);

	ELEM_OPT_TLV(0x43, GSM_A_PDU_TYPE_GM, DE_MAC, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [7] 9.4.11
 */
static void
dtap_gmm_auth_ciph_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [7] 9.4.10a
 */
static void
dtap_gmm_auth_ciph_fail(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_RECV;

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_GMM_CAUSE, NULL, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_OPT_TLV( 0x30, GSM_A_PDU_TYPE_DTAP, DE_AUTH_FAIL_PARAM, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [7] 9.4.12
 */
static void
dtap_gmm_ident_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_VV_SHORT(GSM_A_PDU_TYPE_GM, DE_ID_TYPE_2, GSM_A_PDU_TYPE_GM, DE_FORCE_TO_STAND_H, ei_gsm_a_gm_missing_mandatory_element);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [7] 9.4.13
 */
static void
dtap_gmm_ident_res(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_RECV;

	ELEM_MAND_LV( GSM_A_PDU_TYPE_COMMON, DE_MID, NULL, ei_gsm_a_gm_missing_mandatory_element);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [7] 9.4.14
 */
static void
dtap_gmm_rau_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_RECV;

	ELEM_MAND_VV_SHORT(GSM_A_PDU_TYPE_GM, DE_UPD_TYPE, GSM_A_PDU_TYPE_COMMON, DE_CIPH_KEY_SEQ_NUM, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_RAI, " - Old routing area identification", ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_LV( GSM_A_PDU_TYPE_GM, DE_MS_RAD_ACC_CAP, NULL, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_OPT_TV( 0x19, GSM_A_PDU_TYPE_GM, DE_P_TMSI_SIG, " - Old P-TMSI Signature" );

	ELEM_OPT_TV( 0x17, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER, " - Requested Ready Timer" );

	ELEM_OPT_TV( 0x27, GSM_A_PDU_TYPE_GM, DE_DRX_PARAM, NULL);

	ELEM_OPT_TV_SHORT( 0x90, GSM_A_PDU_TYPE_GM, DE_TMSI_STAT, NULL);

	ELEM_OPT_TLV( 0x18, GSM_A_PDU_TYPE_COMMON, DE_MID, " - P-TMSI" );

	ELEM_OPT_TLV( 0x31, GSM_A_PDU_TYPE_GM, DE_MS_NET_CAP, NULL);

	ELEM_OPT_TLV( 0x32, GSM_A_PDU_TYPE_GM, DE_PDP_CONTEXT_STAT, NULL);

	ELEM_OPT_TLV( 0x33, GSM_A_PDU_TYPE_GM, DE_PS_LCS_CAP, NULL);

	ELEM_OPT_TLV( 0x35, GSM_A_PDU_TYPE_GM, DE_MBMS_CTX_STATUS, NULL);

	ELEM_OPT_TLV( 0x58, NAS_PDU_TYPE_EMM, DE_EMM_UE_NET_CAP, NULL);

	ELEM_OPT_TLV( 0x1A, GSM_A_PDU_TYPE_COMMON, DE_MID, " - Additional mobile identity");

	ELEM_OPT_TLV( 0x1B, GSM_A_PDU_TYPE_GM, DE_RAI_2, " - Additional old routing area identification");

	ELEM_OPT_TLV( 0x11, GSM_A_PDU_TYPE_COMMON, DE_MS_CM_2, NULL);

	ELEM_OPT_TLV( 0x20, GSM_A_PDU_TYPE_COMMON, DE_MS_CM_3, NULL);

	ELEM_OPT_TLV( 0x40, GSM_A_PDU_TYPE_DTAP, DE_SUP_CODEC_LIST, NULL);

	ELEM_OPT_TLV( 0x5D, GSM_A_PDU_TYPE_GM, DE_VOICE_DOMAIN_PREF, NULL);

	ELEM_OPT_TV_SHORT(0xE0, GSM_A_PDU_TYPE_GM, DE_PTMSI_TYPE, NULL);

	ELEM_OPT_TV_SHORT(0xD0, GSM_A_PDU_TYPE_GM, DE_DEVICE_PROPERTIES, NULL);

	ELEM_OPT_TV_SHORT(0xC0, GSM_A_PDU_TYPE_COMMON, DE_MS_NET_FEAT_SUP, NULL);

	ELEM_OPT_TLV(0x14, GSM_A_PDU_TYPE_GM, DE_LAI_2, " - Old location area identification");

	ELEM_OPT_TV_SHORT(0xF0, GSM_A_PDU_TYPE_GM, DE_ADD_UPD_TYPE, NULL);

	ELEM_OPT_TLV(0x10, GSM_A_PDU_TYPE_GM, DE_NET_RES_ID_CONT, " - TMSI based NRI container");

	ELEM_OPT_TLV(0x6A, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3324 value");

	ELEM_OPT_TLV(0x39, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - T3312 extended value");

	ELEM_OPT_TLV(0x6E, GSM_A_PDU_TYPE_GM, DE_EXT_DRX_PARAMS, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [7] 9.4.15
 */
static void
dtap_gmm_rau_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_VV_SHORT(GSM_A_PDU_TYPE_GM, DE_FORCE_TO_STAND, GSM_A_PDU_TYPE_GM, DE_UPD_RES, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER, " - Periodic RA update timer", ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_RAI, NULL, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_OPT_TV( 0x19, GSM_A_PDU_TYPE_GM, DE_P_TMSI_SIG, NULL);

	ELEM_OPT_TLV( 0x18, GSM_A_PDU_TYPE_COMMON, DE_MID, " - Allocated P-TMSI");

	ELEM_OPT_TLV( 0x23, GSM_A_PDU_TYPE_COMMON, DE_MID, " - MS identity");

	ELEM_OPT_TLV( 0x26, GSM_A_PDU_TYPE_GM, DE_REC_N_PDU_NUM_LIST, NULL);

	ELEM_OPT_TV( 0x17, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER, " - Negotiated Ready Timer" );

	ELEM_OPT_TV( 0x25, GSM_A_PDU_TYPE_GM, DE_GMM_CAUSE, NULL);

	ELEM_OPT_TLV( 0x2A, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3302 value" );

	ELEM_OPT_T( 0x8C, GSM_A_PDU_TYPE_GM, DE_CELL_NOT, NULL);

	ELEM_OPT_TLV( 0x4A, GSM_A_PDU_TYPE_COMMON, DE_PLMN_LIST, NULL);

	ELEM_OPT_TLV( 0x32, GSM_A_PDU_TYPE_GM, DE_PDP_CONTEXT_STAT, NULL);

	ELEM_OPT_TV_SHORT( 0xB0, GSM_A_PDU_TYPE_GM, DE_NET_FEAT_SUP, NULL);

	ELEM_OPT_TLV( 0x34, GSM_A_PDU_TYPE_DTAP, DE_EMERGENCY_NUM_LIST, NULL);

	ELEM_OPT_TLV( 0x35, GSM_A_PDU_TYPE_GM, DE_MBMS_CTX_STATUS, NULL);

	ELEM_OPT_TV_SHORT( 0xA0, GSM_A_PDU_TYPE_GM, DE_REQ_MS_INFO, NULL);

	ELEM_OPT_TLV( 0x37, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3319 value");

	ELEM_OPT_TLV( 0x38, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3323 value");

	ELEM_OPT_TLV(0x39, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - T3312 extended value");

	ELEM_OPT_TLV(0x66, GSM_A_PDU_TYPE_GM, DE_ADD_NET_FEAT_SUP, NULL);

	ELEM_OPT_TLV(0x6A, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3324 value");

	ELEM_OPT_TLV(0x6E, GSM_A_PDU_TYPE_GM, DE_EXT_DRX_PARAMS, NULL);

	ELEM_OPT_TV_SHORT(0xC0, GSM_A_PDU_TYPE_GM, DE_UP_INTEG_IND, NULL);

	ELEM_OPT_TLV(0x31, GSM_A_PDU_TYPE_GM, DE_MS_NET_CAP, " - Replayed MS network capability");

	ELEM_OPT_TLV(0x33, GSM_A_PDU_TYPE_GM, DE_MS_RAD_ACC_CAP, " - Replayed MS Radio Access capability");

	ELEM_OPT_TLV(0x65, GSM_A_PDU_TYPE_GM, DE_DCN_ID, NULL);

	ELEM_OPT_TLV(0x63, GSM_A_PDU_TYPE_GM, DE_PLMN_ID_CN_OPERATOR, NULL);

	ELEM_OPT_TV_SHORT(0xD0, GSM_A_PDU_TYPE_GM, DE_NON_3GPP_NW_PROV_POL, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [7] 9.4.16
 */
static void
dtap_gmm_rau_com(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_RECV;
	/* [7] 10.5.5.11 */
	ELEM_OPT_TLV( 0x26, GSM_A_PDU_TYPE_GM, DE_REC_N_PDU_NUM_LIST, NULL);
	/* Inter RAT information container 10.5.5.24 TS 24.008 version 6.8.0 Release 6 */
	ELEM_OPT_TLV( 0x27, GSM_A_PDU_TYPE_GM, DE_RAT_INFO_CONTAINER, " - Inter RAT handover information");

	ELEM_OPT_TLV( 0x2B, GSM_A_PDU_TYPE_GM, DE_EUTRAN_IRAT_INFO_CONTAINER, " - E-UTRAN inter RAT handover information");

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [7] 9.4.17
 */
static void
dtap_gmm_rau_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_GMM_CAUSE, NULL, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_VV_SHORT(GSM_A_PDU_TYPE_GM, DE_FORCE_TO_STAND, GSM_A_PDU_TYPE_COMMON, DE_SPARE_NIBBLE, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_OPT_TLV(0x2A, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3302 value");

	ELEM_OPT_TLV(0x3A, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3346 value");

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [7] 9.4.18
 */
static void
dtap_gmm_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_GMM_CAUSE, NULL, ei_gsm_a_gm_missing_mandatory_element);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [8] 9.4.19 GMM Information
 */
static void
dtap_gmm_information(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_OPT_TLV( 0x43, GSM_A_PDU_TYPE_DTAP, DE_NETWORK_NAME, " - Full Name" );

	ELEM_OPT_TLV( 0x45, GSM_A_PDU_TYPE_DTAP, DE_NETWORK_NAME, " - Short Name" );

	ELEM_OPT_TV( 0x46, GSM_A_PDU_TYPE_DTAP, DE_TIME_ZONE, NULL);

	ELEM_OPT_TV( 0x47, GSM_A_PDU_TYPE_DTAP, DE_TIME_ZONE_TIME, NULL);

	ELEM_OPT_TLV( 0x48, GSM_A_PDU_TYPE_DTAP, DE_LSA_ID, NULL);

	ELEM_OPT_TLV( 0x49, GSM_A_PDU_TYPE_DTAP, DE_DAY_SAVING_TIME, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [7] 9.4.20
 */
static void
dtap_gmm_service_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_RECV;

	ELEM_MAND_VV_SHORT(GSM_A_PDU_TYPE_COMMON, DE_CIPH_KEY_SEQ_NUM, GSM_A_PDU_TYPE_GM, DE_SRVC_TYPE, ei_gsm_a_gm_missing_mandatory_element);

	/* P-TMSI Mobile station identity 10.5.1.4 M LV 6 */
	ELEM_MAND_LV( GSM_A_PDU_TYPE_COMMON, DE_MID, NULL, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_OPT_TLV( 0x32, GSM_A_PDU_TYPE_GM, DE_PDP_CONTEXT_STAT, NULL);

	/* MBMS context status 10.5.7.6 TLV 2 - 18 */
	ELEM_OPT_TLV( 0x35, GSM_A_PDU_TYPE_GM, DE_MBMS_CTX_STATUS, NULL);

	ELEM_OPT_TLV( 0x36, GSM_A_PDU_TYPE_GM, DE_UPLINK_DATA_STATUS, NULL);

	ELEM_OPT_TV_SHORT(0xD0, GSM_A_PDU_TYPE_GM, DE_DEVICE_PROPERTIES, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [7] 9.4.21
 */
static void
dtap_gmm_service_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_OPT_TLV( 0x32, GSM_A_PDU_TYPE_GM, DE_PDP_CONTEXT_STAT, NULL);

	/* MBMS context status 10.5.7.6 TLV 2 - 18 */
	ELEM_OPT_TLV( 0x35, GSM_A_PDU_TYPE_GM, DE_MBMS_CTX_STATUS, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [7] 9.4.22
 */
static void
dtap_gmm_service_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_GMM_CAUSE, NULL, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_OPT_TLV(0x3A, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3346 value");

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [8] 9.5.1 Activate PDP context request
 * Direction:			MS to network
 */
static void
dtap_sm_act_pdp_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	/* MS to network */
	pinfo->link_dir = P2P_DIR_UL;

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_NET_SAPI, " - Requested NSAPI", ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_LLC_SAPI, " - Requested LLC SAPI", ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_LV( GSM_A_PDU_TYPE_GM, DE_QOS, " - Requested QoS", ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_LV( GSM_A_PDU_TYPE_GM, DE_PD_PRO_ADDR, " - Requested PDP address", ei_gsm_a_gm_missing_mandatory_element);

	ELEM_OPT_TLV( 0x28, GSM_A_PDU_TYPE_GM, DE_ACC_POINT_NAME, NULL);

	ELEM_OPT_TLV( 0x27, GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT, NULL);

	ELEM_OPT_TV_SHORT( 0xA0, GSM_A_PDU_TYPE_GM, DE_REQ_TYPE, NULL);

	ELEM_OPT_TV_SHORT(0xC0, GSM_A_PDU_TYPE_GM, DE_DEVICE_PROPERTIES, NULL);

	ELEM_OPT_TLV(0x33, GSM_A_PDU_TYPE_GM, DE_NBIFOM_CONT, NULL);

	ELEM_OPT_TLV_E(0x7B, GSM_A_PDU_TYPE_GM, DE_EXT_PRO_CONF_OPT, NULL);

	ELEM_OPT_TLV(0x5C, GSM_A_PDU_TYPE_GM, DE_EXT_QOS, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [9] 9.5.2 Activate PDP context accept
 * Direction:			network to MS
 */
static void
dtap_sm_act_pdp_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	/* Network to MS*/
	pinfo->link_dir = P2P_DIR_DL;

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_LLC_SAPI, " - Negotiated LLC SAPI", ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_LV( GSM_A_PDU_TYPE_GM, DE_QOS, " - Negotiated QoS", ei_gsm_a_gm_missing_mandatory_element);

#if 0
	/* This is done automatically */
	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_SPARE, NULL, ei_gsm_a_gm_missing_mandatory_element);
	curr_offset--;
	curr_len++;
#endif

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_RAD_PRIO, NULL, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_OPT_TLV( 0x2B, GSM_A_PDU_TYPE_GM, DE_PD_PRO_ADDR, " - PDP address");

	ELEM_OPT_TLV( 0x27, GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT, NULL);

	ELEM_OPT_TLV( 0x34, GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID, NULL);

	ELEM_OPT_TLV( 0x39, GSM_A_PDU_TYPE_GM, DE_SM_CAUSE_2, " - SM cause");

	ELEM_OPT_TV_SHORT(0xB0 , GSM_A_PDU_TYPE_GM, DE_SM_CONNECTIVITY_TYPE, NULL);

	ELEM_OPT_TV_SHORT(0xC0 , GSM_A_PDU_TYPE_GM, DE_SM_WLAN_OFFLOAD_ACCEPT, " - WLAN offload indication");

	ELEM_OPT_TLV(0x33, GSM_A_PDU_TYPE_GM, DE_NBIFOM_CONT, NULL);

	ELEM_OPT_TLV_E(0x7B, GSM_A_PDU_TYPE_GM, DE_EXT_PRO_CONF_OPT, NULL);

	ELEM_OPT_TLV(0x5C, GSM_A_PDU_TYPE_GM, DE_EXT_QOS, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [8] 9.5.3 Activate PDP context reject
 * Direction:			network to MS
 */
static void
dtap_sm_act_pdp_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	/* Network to MS*/
	pinfo->link_dir = P2P_DIR_DL;

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_SM_CAUSE, NULL, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_OPT_TLV( 0x27, GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT, NULL);

	ELEM_OPT_TLV(0x37, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - Back-off timer value");

	ELEM_OPT_TLV(0x6B, GSM_A_PDU_TYPE_GM, DE_RE_ATTEMPT_IND, NULL);

	ELEM_OPT_TLV(0x33, GSM_A_PDU_TYPE_GM, DE_NBIFOM_CONT, NULL);

	ELEM_OPT_TLV_E(0x7B, GSM_A_PDU_TYPE_GM, DE_EXT_PRO_CONF_OPT, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [8] 9.5.4 Activate Secondary PDP Context Request
 * Direction:			MS to network
 */
static void
dtap_sm_act_sec_pdp_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	/* MS to Network */
	pinfo->link_dir = P2P_DIR_UL;

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_NET_SAPI, " - Requested NSAPI", ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_LLC_SAPI, " - Requested LLC SAPI", ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_LV( GSM_A_PDU_TYPE_GM, DE_QOS, " - Requested QoS", ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_LV( GSM_A_PDU_TYPE_GM, DE_LINKED_TI, NULL, ei_gsm_a_gm_missing_mandatory_element);

	/* 3GPP TS 24.008 version 6.8.0 Release 6, 36 TFT Traffic Flow Template 10.5.6.12 O TLV 3-257 */
	ELEM_OPT_TLV( 0x36, GSM_A_PDU_TYPE_GM, DE_TRAFFIC_FLOW_TEMPLATE, NULL);

	ELEM_OPT_TLV( 0x27, GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT, NULL);

	ELEM_OPT_TV_SHORT(0xC0, GSM_A_PDU_TYPE_GM, DE_DEVICE_PROPERTIES, NULL);

	ELEM_OPT_TLV(0x33, GSM_A_PDU_TYPE_GM, DE_NBIFOM_CONT, NULL);

	ELEM_OPT_TLV_E(0x7B, GSM_A_PDU_TYPE_GM, DE_EXT_PRO_CONF_OPT, NULL);

	ELEM_OPT_TLV(0x5C, GSM_A_PDU_TYPE_GM, DE_EXT_QOS, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [7] 9.5.5	Activate Secondary PDP Context Accept
 * Direction:			network to MS
 */
static void
dtap_sm_act_sec_pdp_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	/* Network to MS*/
	pinfo->link_dir = P2P_DIR_DL;

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_LLC_SAPI, " - Negotiated LLC SAPI", ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_LV( GSM_A_PDU_TYPE_GM, DE_QOS, " - Negotiated QoS", ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_RAD_PRIO, NULL, ei_gsm_a_gm_missing_mandatory_element);

#if 0
	/* This is done automatically */
	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_SPARE, NULL, ei_gsm_a_gm_missing_mandatory_element);
	curr_offset--;
	curr_len++;
#endif

	ELEM_OPT_TLV( 0x34, GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID, NULL);

	ELEM_OPT_TLV( 0x27, GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT, NULL);

	ELEM_OPT_TV_SHORT(0xC0 , GSM_A_PDU_TYPE_GM, DE_SM_WLAN_OFFLOAD_ACCEPT, " - WLAN offload indication");

	ELEM_OPT_TLV(0x33, GSM_A_PDU_TYPE_GM, DE_NBIFOM_CONT, NULL);

	ELEM_OPT_TLV_E(0x7B, GSM_A_PDU_TYPE_GM, DE_EXT_PRO_CONF_OPT, NULL);

	ELEM_OPT_TLV(0x5C, GSM_A_PDU_TYPE_GM, DE_EXT_QOS, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [8] 9.5.6 Activate Secondary PDP Context Reject
 * Direction:			network to MS
 */
static void
dtap_sm_act_sec_pdp_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	/* Network to MS*/
	pinfo->link_dir = P2P_DIR_DL;

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_SM_CAUSE, NULL, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_OPT_TLV( 0x27, GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT, NULL);

	ELEM_OPT_TLV(0x37, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - Back-off timer value");

	ELEM_OPT_TLV(0x6B, GSM_A_PDU_TYPE_GM, DE_RE_ATTEMPT_IND, NULL);

	ELEM_OPT_TLV(0x33, GSM_A_PDU_TYPE_GM, DE_NBIFOM_CONT, NULL);

	ELEM_OPT_TLV_E(0x7B, GSM_A_PDU_TYPE_GM, DE_EXT_PRO_CONF_OPT, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [8] 9.5.7 Request PDP context activation
 * Direction:			network to MS
 */
static void
dtap_sm_req_pdp_act(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	/* Network to MS*/
	pinfo->link_dir = P2P_DIR_DL;

	ELEM_MAND_LV( GSM_A_PDU_TYPE_GM, DE_PD_PRO_ADDR, " - Offered PDP address", ei_gsm_a_gm_missing_mandatory_element);

	ELEM_OPT_TLV( 0x28, GSM_A_PDU_TYPE_GM, DE_ACC_POINT_NAME, NULL);

	ELEM_OPT_TLV( 0x27, GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT, NULL);

	ELEM_OPT_TLV(0x33, GSM_A_PDU_TYPE_GM, DE_NBIFOM_CONT, NULL);

	ELEM_OPT_TLV_E(0x7B, GSM_A_PDU_TYPE_GM, DE_EXT_PRO_CONF_OPT, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [8] 9.5.8 Request PDP context activation reject
 * Direction:			MS to network
 */
static void
dtap_sm_req_pdp_act_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	/* MS to  Network */
	pinfo->link_dir = P2P_DIR_UL;

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_SM_CAUSE, NULL, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_OPT_TLV( 0x27, GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT, NULL);

	ELEM_OPT_TLV(0x33, GSM_A_PDU_TYPE_GM, DE_NBIFOM_CONT, NULL);

	ELEM_OPT_TLV_E(0x7B, GSM_A_PDU_TYPE_GM, DE_EXT_PRO_CONF_OPT, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [8] 9.5.9 Modify PDP context request (Network to MS direction)
 * Direction:			network to MS
 */
static void
dtap_sm_mod_pdp_req_net(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	/* Network to MS */
	pinfo->link_dir = P2P_DIR_DL;

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_RAD_PRIO, NULL, ei_gsm_a_gm_missing_mandatory_element);
#if 0
	/* This is done automatically */
	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_SPARE, NULL, ei_gsm_a_gm_missing_mandatory_element);
	curr_offset--;
	curr_len++;
#endif

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_LLC_SAPI, " - Requested LLC SAPI", ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_LV( GSM_A_PDU_TYPE_GM, DE_QOS, " - New QoS", ei_gsm_a_gm_missing_mandatory_element);

	ELEM_OPT_TLV( 0x2B, GSM_A_PDU_TYPE_GM, DE_PD_PRO_ADDR, " - PDP address");

	ELEM_OPT_TLV( 0x34, GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID, NULL);

	ELEM_OPT_TLV( 0x27, GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT, NULL);

	ELEM_OPT_TLV( 0x36, GSM_A_PDU_TYPE_GM, DE_TRAFFIC_FLOW_TEMPLATE, NULL);

	ELEM_OPT_TV_SHORT(0xC0 , GSM_A_PDU_TYPE_GM, DE_SM_WLAN_OFFLOAD_ACCEPT, " - WLAN offload indication");

	ELEM_OPT_TLV(0x33, GSM_A_PDU_TYPE_GM, DE_NBIFOM_CONT, NULL);

	ELEM_OPT_TLV_E(0x7B, GSM_A_PDU_TYPE_GM, DE_EXT_PRO_CONF_OPT, NULL);

	ELEM_OPT_TLV(0x5C, GSM_A_PDU_TYPE_GM, DE_EXT_QOS, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [8] 9.5.10 Modify PDP context request (MS to network direction)
 * Direction:			MS to network
 */
static void
dtap_sm_mod_pdp_req_ms(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	/* MS to Network */
	pinfo->link_dir = P2P_DIR_UL;

	ELEM_OPT_TV( 0x32, GSM_A_PDU_TYPE_GM, DE_LLC_SAPI, " - Requested LLC SAPI" );

	ELEM_OPT_TLV( 0x30, GSM_A_PDU_TYPE_GM, DE_QOS, " - Requested new QoS" );

	ELEM_OPT_TLV( 0x31, GSM_A_PDU_TYPE_GM, DE_TRAFFIC_FLOW_TEMPLATE, " - New TFT" );

	ELEM_OPT_TLV( 0x27, GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT, NULL);

	ELEM_OPT_TV_SHORT(0xC0, GSM_A_PDU_TYPE_GM, DE_DEVICE_PROPERTIES, NULL);

	ELEM_OPT_TLV(0x33, GSM_A_PDU_TYPE_GM, DE_NBIFOM_CONT, NULL);

	ELEM_OPT_TLV_E(0x7B, GSM_A_PDU_TYPE_GM, DE_EXT_PRO_CONF_OPT, NULL);

	ELEM_OPT_TLV(0x5C, GSM_A_PDU_TYPE_GM, DE_EXT_QOS, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [8] 9.5.11 Modify PDP context accept (MS to network direction)
 * Direction:			MS to network
 */
static void
dtap_sm_mod_pdp_acc_ms(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	/* MS to Network */
	pinfo->link_dir = P2P_DIR_UL;

	ELEM_OPT_TLV( 0x27, GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT, NULL);

	ELEM_OPT_TLV(0x33, GSM_A_PDU_TYPE_GM, DE_NBIFOM_CONT, NULL);

	ELEM_OPT_TLV_E(0x7B, GSM_A_PDU_TYPE_GM, DE_EXT_PRO_CONF_OPT, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [8] 9.5.12 Modify PDP context accept (Network to MS direction)
 * Direction:			Network to MS
 */
static void
dtap_sm_mod_pdp_acc_net(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	/* Network to MS */
	pinfo->link_dir = P2P_DIR_DL;

	ELEM_OPT_TLV( 0x30, GSM_A_PDU_TYPE_GM, DE_QOS, " - Negotiated QoS" );

	ELEM_OPT_TV( 0x32, GSM_A_PDU_TYPE_GM, DE_LLC_SAPI, " - Negotiated LLC SAPI" );

	ELEM_OPT_TV_SHORT ( 0x80, GSM_A_PDU_TYPE_GM, DE_RAD_PRIO, " - New radio priority" );

	ELEM_OPT_TLV( 0x34, GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID, NULL);

	ELEM_OPT_TLV( 0x27, GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT, NULL);

	ELEM_OPT_TV_SHORT(0xC0 , GSM_A_PDU_TYPE_GM, DE_SM_WLAN_OFFLOAD_ACCEPT, " - WLAN offload indication");

	ELEM_OPT_TLV(0x33, GSM_A_PDU_TYPE_GM, DE_NBIFOM_CONT, NULL);

	ELEM_OPT_TLV_E(0x7B, GSM_A_PDU_TYPE_GM, DE_EXT_PRO_CONF_OPT, NULL);

	ELEM_OPT_TLV(0x5C, GSM_A_PDU_TYPE_GM, DE_EXT_QOS, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [8] 9.5.13 Modify PDP Context Reject
 * Direction:			both
 */
static void
dtap_sm_mod_pdp_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	/* Network or the MS; do not reset link_dir in case it was set by lower layers */
	/* pinfo->link_dir = LINK_DIR_UNKNOWN; */


	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_SM_CAUSE, NULL, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_OPT_TLV( 0x27, GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT, NULL);

	ELEM_OPT_TLV(0x37, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - Back-off timer value");

	ELEM_OPT_TLV(0x6B, GSM_A_PDU_TYPE_GM, DE_RE_ATTEMPT_IND, NULL);

	ELEM_OPT_TLV(0x33, GSM_A_PDU_TYPE_GM, DE_NBIFOM_CONT, NULL);

	ELEM_OPT_TLV_E(0x7B, GSM_A_PDU_TYPE_GM, DE_EXT_PRO_CONF_OPT, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [8] 9.5.14 Deactivate PDP context request
 * Direction:			both
 */
static void
dtap_sm_deact_pdp_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	pinfo->link_dir = LINK_DIR_UNKNOWN;

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_SM_CAUSE, NULL, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_OPT_TV_SHORT( 0x90, GSM_A_PDU_TYPE_GM, DE_TEAR_DOWN_IND, NULL);

	ELEM_OPT_TLV( 0x27, GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT, NULL);

	ELEM_OPT_TLV( 0x35, GSM_A_PDU_TYPE_GM, DE_MBMS_PROT_CONF_OPT, NULL);

	ELEM_OPT_TLV(0x37, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - T3396 value");

	ELEM_OPT_TV_SHORT(0xC0 , GSM_A_PDU_TYPE_GM, DE_SM_WLAN_OFFLOAD_ACCEPT, " - WLAN offload indication");

	ELEM_OPT_TLV_E(0x7B, GSM_A_PDU_TYPE_GM, DE_EXT_PRO_CONF_OPT, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [8] 9.5.15 Deactivate PDP context accept
 * Direction:			both
 */
static void
dtap_sm_deact_pdp_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	pinfo->link_dir = LINK_DIR_UNKNOWN;

	ELEM_OPT_TLV( 0x27, GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT, NULL);

	ELEM_OPT_TLV( 0x35, GSM_A_PDU_TYPE_GM, DE_MBMS_PROT_CONF_OPT, NULL);

	ELEM_OPT_TLV_E(0x7B, GSM_A_PDU_TYPE_GM, DE_EXT_PRO_CONF_OPT, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [8] 9.5.15a Request Secondary PDP Context Activation
 * Direction:			network to MS
 */
static void
dtap_sm_req_sec_pdp_act(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	pinfo->link_dir = P2P_DIR_DL;

	/* Required QoS Quality of service 10.5.6.5 M LV 13-17 */
	ELEM_MAND_LV( GSM_A_PDU_TYPE_GM, DE_QOS, " - Required QoS", ei_gsm_a_gm_missing_mandatory_element);

	/* Linked TI Linked TI 10.5.6.7 M LV 2-3 */
	ELEM_MAND_LV( GSM_A_PDU_TYPE_GM, DE_LINKED_TI, NULL, ei_gsm_a_gm_missing_mandatory_element);

	/* 36 TFT Traffic Flow Template 10.5.6.12 O TLV 3-257 */
	ELEM_OPT_TLV( 0x36, GSM_A_PDU_TYPE_GM, DE_TRAFFIC_FLOW_TEMPLATE, NULL);

	/* 27 Protocol configuration options Protocol configuration options 10.5.6.3 O TLV 3 - 253 */
	ELEM_OPT_TLV( 0x27, GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT, NULL);

	/* C- WLAN offload acceptability 10.5.6.20 O TV 1 */
	ELEM_OPT_TV_SHORT(0xC0 , GSM_A_PDU_TYPE_GM, DE_SM_WLAN_OFFLOAD_ACCEPT, " - WLAN offload indication");

	ELEM_OPT_TLV(0x33, GSM_A_PDU_TYPE_GM, DE_NBIFOM_CONT, NULL);

	ELEM_OPT_TLV_E(0x7B, GSM_A_PDU_TYPE_GM, DE_EXT_PRO_CONF_OPT, NULL);

	ELEM_OPT_TLV(0x5C, GSM_A_PDU_TYPE_GM, DE_EXT_QOS, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [8] 9.5.15b Request Secondary PDP Context Activation Reject
 * Direction:			MS to network
 */
static void
dtap_sm_req_sec_pdp_act_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	pinfo->link_dir = P2P_DIR_UL;

	/* SM cause SM cause 10.5.6.6 M V 1 */
	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_SM_CAUSE, NULL, ei_gsm_a_gm_missing_mandatory_element);

	/* 27 Protocol configuration options Protocol configuration options 10.5.6.3 O TLV 3 - 253 */
	ELEM_OPT_TLV( 0x27, GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT, NULL);

	ELEM_OPT_TLV(0x33, GSM_A_PDU_TYPE_GM, DE_NBIFOM_CONT, NULL);

	ELEM_OPT_TLV_E(0x7B, GSM_A_PDU_TYPE_GM, DE_EXT_PRO_CONF_OPT, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [8] 9.5.16a Notification
 * Direction:			network to MS
 */
static void
dtap_sm_notif(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	pinfo->link_dir = P2P_DIR_DL;

	ELEM_MAND_LV( GSM_A_PDU_TYPE_GM, DE_SM_NOTIF_IND, NULL, ei_gsm_a_gm_missing_mandatory_element);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [8] 9.5.21 SM Status
 * Direction:			both
 */
static void
dtap_sm_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_UNKNOWN;
	pinfo->link_dir = LINK_DIR_UNKNOWN;

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_SM_CAUSE, NULL, ei_gsm_a_gm_missing_mandatory_element);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [9] 9.5.22 Activate MBMS Context Request
 * Direction:			MS to network
 */
static void
dtap_sm_act_mbms_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_RECV;

	/* Requested MBMS NSAPI Enhanced Network service access point identifier 10.5.6.16 M V */
	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_ENH_NSAPI, " - Requested MBMS NSAPI", ei_gsm_a_gm_missing_mandatory_element);

	/* Requested LLC SAPI LLC service access point identifier 10.5.6.9 M V 1 */
	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_LLC_SAPI, " - Requested LLC SAPI", ei_gsm_a_gm_missing_mandatory_element);

	/* Supported MBMS bearer capabilities MBMS bearer capabilities 10.5.6.14 M LV 2 - 3 */
	ELEM_MAND_LV( GSM_A_PDU_TYPE_GM, DE_MBMS_BEARER_CAP, NULL, ei_gsm_a_gm_missing_mandatory_element);

	/* Requested multicast address Packet data protocol address 10.5.6.4 M LV 3 - 19 */
	ELEM_MAND_LV( GSM_A_PDU_TYPE_GM, DE_PD_PRO_ADDR, " - Requested multicast address", ei_gsm_a_gm_missing_mandatory_element);

	/* Access point name Access point name 10.5.6.1 M LV 2 - 101 */
	ELEM_MAND_LV( GSM_A_PDU_TYPE_GM, DE_ACC_POINT_NAME, NULL, ei_gsm_a_gm_missing_mandatory_element);

	/* 35 MBMS protocol configuration options MBMS protocol configuration options 10.5.6.15 O TLV 3 - 253 */
	ELEM_OPT_TLV( 0x35, GSM_A_PDU_TYPE_GM, DE_MBMS_PROT_CONF_OPT, NULL);

	ELEM_OPT_TV_SHORT(0xC0, GSM_A_PDU_TYPE_GM, DE_DEVICE_PROPERTIES, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [9] 9.5.23 Activate MBMS Context Accept
 * Direction:			network to MS
 */
static void
dtap_sm_act_mbms_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_LV(  GSM_A_PDU_TYPE_GM, DE_TMGI, NULL, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_V(  GSM_A_PDU_TYPE_GM, DE_LLC_SAPI, " - Negotiated LLC SAPI", ei_gsm_a_gm_missing_mandatory_element);

	ELEM_OPT_TLV( 0x35, GSM_A_PDU_TYPE_GM, DE_MBMS_PROT_CONF_OPT, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [9] 9.5.24 Activate MBMS Context Reject
 * Direction:			network to MS
 */
static void
dtap_sm_act_mbms_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_SM_CAUSE, NULL, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_OPT_TLV( 0x35, GSM_A_PDU_TYPE_GM, DE_MBMS_PROT_CONF_OPT, NULL);

	ELEM_OPT_TLV(0x37, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - T3396 value");

	ELEM_OPT_TLV(0x6B, GSM_A_PDU_TYPE_GM, DE_RE_ATTEMPT_IND, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [9] 9.5.25 Request MBMS Context Activation
 * Direction:			network to MS
 */
static void
dtap_sm_req_mbms_act(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_NET_SAPI, " - Linked NSAPI", ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_LV( GSM_A_PDU_TYPE_GM, DE_PD_PRO_ADDR, " - Offered multicast address", ei_gsm_a_gm_missing_mandatory_element);

	ELEM_MAND_LV( GSM_A_PDU_TYPE_GM, DE_ACC_POINT_NAME, NULL, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_OPT_TLV( 0x35, GSM_A_PDU_TYPE_GM, DE_MBMS_PROT_CONF_OPT, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

/*
 * [8] 9.5.26 Request MBMS Context Activation Reject
 * Direction:			MS to network
 */
static void
dtap_sm_req_mbms_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len    = len;

	pinfo->p2p_dir = P2P_DIR_RECV;

	ELEM_MAND_V( GSM_A_PDU_TYPE_GM, DE_SM_CAUSE, NULL, ei_gsm_a_gm_missing_mandatory_element);

	ELEM_OPT_TLV( 0x35, GSM_A_PDU_TYPE_GM, DE_MBMS_PROT_CONF_OPT, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_gm_extraneous_data);
}

#define	NUM_GSM_DTAP_MSG_GMM array_length(gsm_a_dtap_msg_gmm_strings)
static int ett_gsm_dtap_msg_gmm[NUM_GSM_DTAP_MSG_GMM];
static void (*dtap_msg_gmm_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len) = {
	dtap_gmm_attach_req,		/* Attach Request */
	dtap_gmm_attach_acc,		/* Attach Accept */
	dtap_gmm_attach_com,		/* Attach Complete */
	dtap_gmm_attach_rej,		/* Attach Reject */
	dtap_gmm_detach_req,		/* Detach Request */
	dtap_gmm_detach_acc,		/* Detach Accept */
	dtap_gmm_rau_req,		/* Routing Area Update Request */
	dtap_gmm_rau_acc,		/* Routing Area Update Accept */
	dtap_gmm_rau_com,		/* Routing Area Update Complete */
	dtap_gmm_rau_rej,		/* Routing Area Update Reject */
	dtap_gmm_service_req,		/* Service Request */
	dtap_gmm_service_acc,		/* Service Accept */
	dtap_gmm_service_rej,		/* Service Reject */
	dtap_gmm_ptmsi_realloc_cmd,	/* P-TMSI Reallocation Command */
	dtap_gmm_ptmsi_realloc_com,	/* P-TMSI Reallocation Complete */
	dtap_gmm_auth_ciph_req,		/* Authentication and Ciphering Req */
	dtap_gmm_auth_ciph_resp,	/* Authentication and Ciphering Resp */
	dtap_gmm_auth_ciph_rej,		/* Authentication and Ciphering Rej */
	dtap_gmm_ident_req,		/* Identity Request */
	dtap_gmm_ident_res,		/* Identity Response */
	dtap_gmm_auth_ciph_fail,	/* Authentication and Ciphering Failure */
	dtap_gmm_status,		/* GMM Status */
	dtap_gmm_information,		/* GMM Information */
	NULL,	/* NONE */
};

#define	NUM_GSM_DTAP_MSG_SM array_length(gsm_a_dtap_msg_sm_strings)
static int ett_gsm_dtap_msg_sm[NUM_GSM_DTAP_MSG_SM];
static void (*dtap_msg_sm_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len) = {
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
	NULL,				/* Reserved: was allocated in earlier phases of the protocol */
	NULL,				/* Reserved: was allocated in earlier phases of the protocol */
	NULL,				/* Reserved: was allocated in earlier phases of the protocol */
	NULL,				/* Reserved: was allocated in earlier phases of the protocol */
	NULL,				/* Reserved: was allocated in earlier phases of the protocol */
	dtap_sm_status,			/* SM Status */
	dtap_sm_act_mbms_req,		/* Activate MBMS Context Request */
	dtap_sm_act_mbms_acc,		/* Activate MBMS Context Accept */
	dtap_sm_act_mbms_rej,		/* Activate MBMS Context Reject */
	dtap_sm_req_mbms_act,		/* Request MBMS Context Activation */
	dtap_sm_req_mbms_rej,		/* Request MBMS Context Activation Reject */
	dtap_sm_req_sec_pdp_act,	/* Request Secondary PDP Context Activation */
	dtap_sm_req_sec_pdp_act_rej,	/* Request Secondary PDP Context Activation Reject */
	dtap_sm_notif,              	/* Notification */
	NULL,	/* NONE */
};

void
get_gmm_msg_params(uint8_t oct, const char **msg_str, int *ett_tree, int *hf_idx, msg_fcn *dtap_msg_fcn)
{
	int idx;

	*msg_str      = try_val_to_str_idx_ext((uint32_t) (oct & DTAP_GMM_IEI_MASK), &gsm_a_dtap_msg_gmm_strings_ext, &idx);
	*hf_idx	      = hf_gsm_a_dtap_msg_gmm_type;
	if (*msg_str != NULL) {
		*ett_tree     = ett_gsm_dtap_msg_gmm[idx];
		*dtap_msg_fcn = dtap_msg_gmm_fcn[idx];
	}

	return;
}

void
get_sm_msg_params(uint8_t oct, const char **msg_str, int *ett_tree, int *hf_idx, msg_fcn *dtap_msg_fcn)
{
	int idx;

	*msg_str      = try_val_to_str_idx_ext((uint32_t) (oct & DTAP_SM_IEI_MASK), &gsm_a_dtap_msg_sm_strings_ext, &idx);
	*hf_idx	      = hf_gsm_a_dtap_msg_sm_type;
	if (*msg_str != NULL) {
		*ett_tree     = ett_gsm_dtap_msg_sm[idx];
		*dtap_msg_fcn = dtap_msg_sm_fcn[idx];
	}

	return;
}

/* Register the protocol with Wireshark */
void
proto_register_gsm_a_gm(void)
{
	unsigned i;
	unsigned last_offset;

	/* Setup list of header fields */

	static hf_register_info hf[] = {
		{ &hf_gsm_a_dtap_msg_gmm_type,
		  { "DTAP GPRS Mobility Management Message Type",	"gsm_a.dtap.msg_gmm_type",
		    FT_UINT8, BASE_HEX | BASE_EXT_STRING, &gsm_a_dtap_msg_gmm_strings_ext, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_dtap_msg_sm_type,
		  { "DTAP GPRS Session Management Message Type",	"gsm_a.dtap.msg_sm_type",
		    FT_UINT8, BASE_HEX | BASE_EXT_STRING, &gsm_a_dtap_msg_sm_strings_ext, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_elem_id,
		  { "Element ID",	"gsm_a.gm.elem_id",
		    FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_qos_delay_cls,
		  { "Quality of Service Delay class", "gsm_a.gm.sm.qos.delay_cls",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_sm_qos_delay_cls_vals), 0x38,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_qos_reliability_cls,
		  { "Reliability class", "gsm_a.gm.sm.qos.reliability_cls",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_sm_qos_reliability_vals), 0x07,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_qos_traffic_cls,
		  { "Traffic class", "gsm_a.gm.sm.qos.traffic_cls",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_sm_qos_traffic_cls_vals), 0xe0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_qos_del_order,
		  { "Delivery order", "gsm_a.gm.sm.qos.del_order",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_sm_qos_del_order_vals), 0x18,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_qos_del_of_err_sdu,
		  { "Delivery of erroneous SDUs", "gsm_a.gm.sm.qos.del_of_err_sdu",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_sm_qos_del_of_err_sdu_vals), 0x07,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_qos_ber,
		  { "Residual Bit Error Rate (BER)", "gsm_a.gm.sm.qos.ber",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_sm_qos_ber_vals), 0xf0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_qos_sdu_err_rat,
		  { "SDU error ratio", "gsm_a.gm.sm.qos.sdu_err_rat",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_sm_qos_sdu_err_rat_vals), 0x0f,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_qos_traff_hdl_pri,
		  { "Traffic handling priority", "gsm_a.gm.sm.qos.traff_hdl_pri",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_sm_qos_traff_hdl_pri_vals), 0x03,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_split_pg_cycle_code,
		  { "SPLIT PG CYCLE CODE", "gsm_a.gm.gmm.split_pg_cycle_code",
		    FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gsm_a_gmm_split_pg_cycle_code_strings_ext, 0x00,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_split_on_ccch,
		  { "SPLIT on CCCH", "gsm_a.gm.gmm.split_on_ccch",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_split_on_ccch_value), 0x08,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_non_drx_timer,
		  { "Non-DRX timer", "gsm_a.gm.gmm.non_drx_timer",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gmm_non_drx_timer_strings), 0x07,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_cn_spec_drx_cycle_len_coef,
		  { "CN Specific DRX cycle length coefficient", "gsm_a.gm.gmm.cn_spec_drx_cycle_len_coef",
		    FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gsm_a_gmm_cn_spec_drx_cycle_len_coef_strings), 0xf0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_tft_op_code,
		  { "TFT operation code", "gsm_a.gm.sm.tft.op_code",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_sm_tft_op_code_vals), 0xe0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_tft_e_bit,
		  { "E bit", "gsm_a.gm.sm.tft.e_bit",
		    FT_BOOLEAN, 8, TFS(&gsm_a_sm_tft_e_bit), 0x10,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_tft_pkt_flt,
		  { "Number of packet filters", "gsm_a.gm.sm.tft.pkt_flt",
		    FT_UINT8, BASE_DEC, NULL, 0x0f,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_tft_pkt_flt_dir,
		  { "Packet filter direction", "gsm_a.gm.sm.tft.pkt_flt_dir",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_sm_tft_pkt_flt_dir_vals), 0x30,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_tft_pkt_flt_id,
		  { "Packet filter identifier", "gsm_a.gm.sm.tft.pkt_flt_id",
		    FT_UINT8, BASE_DEC, NULL, 0x0f,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_ip4_address,
		  { "IPv4 address", "gsm_a.gm.sm.ip4_address",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_ip4_mask,
		  { "IPv4 address mask", "gsm_a.gm.sm.ip4_mask",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_ip6_address,
		  { "IPv6 address", "gsm_a.gm.sm.ip6_address",
		    FT_IPv6, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_ip6_mask,
		  { "IPv6 address mask", "gsm_a.gm.sm.ip6_mask",
		    FT_IPv6, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_ip6_prefix_length,
		  { "IPv6 prefix length", "gsm_a.gm.sm.ip6_prefix_length",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_tft_protocol_header,
		  { "Protocol/header", "gsm_a.gm.sm.tft.protocol_header",
		    FT_UINT8, BASE_HEX|BASE_EXT_STRING, &ipproto_val_ext, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_tft_port,
		  { "Port", "gsm_a.gm.sm.tft.port",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_tft_port_low,
		  { "Low limit port", "gsm_a.gm.sm.tft.port_low",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_tft_port_high,
		  { "High limit port", "gsm_a.gm.sm.tft.port_high",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_tft_security,
		  { "IPSec security parameter index", "gsm_a.gm.sm.tft.security",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_tft_traffic_class,
		  { "Type of service/Traffic class field", "gsm_a.gm.sm.tft.traffic_class",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_tft_traffic_mask,
		  { "Mask field", "gsm_a.gm.sm.tft.traffic_mask",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_tft_flow_label_type,
		  { "Flow Label Type", "gsm_a.gm.sm.tft.flow_label_type",
		    FT_UINT24, BASE_HEX, NULL, 0x0FFFFF,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_tft_param_id,
		  { "Parameter identifier", "gsm_a.gm.sm.tft.param_id",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_sm_tft_param_id_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_tft_mac_addr,
		  { "MAC address", "gsm_a.gm.sm.tft.mac_addr",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_tft_vlan_tag_vid,
		  { "VID", "gsm_a.gm.sm.tft.vlan_tag_vid",
		    FT_UINT16, BASE_HEX, NULL, 0x0fff,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_tft_vlan_tag_pcp,
		  { "PCP", "gsm_a.gm.sm.tft.vlan_tag_pcp",
		    FT_UINT8, BASE_HEX, NULL, 0x0e,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_tft_vlan_tag_dei,
		  { "DEI", "gsm_a.gm.sm.tft.vlan_tag_dei",
		    FT_UINT8, BASE_HEX, NULL, 0x01,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_tft_ethertype,
		  { "Ethertype", "gsm_a.gm.sm.tft.ethertype",
		    FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
		    NULL, HFILL }
		},

		{ &hf_gsm_a_gmm_ptmsi_sig,
		  { "P-TMSI Signature", "gsm_a.gm.gmm.ptmsi_sig",
		    FT_UINT24, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_ptmsi_sig2,
		  { "P-TMSI Signature 2", "gsm_a.gm.gmm.ptmsi_sig2",
		    FT_UINT24, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_acc_tech_type,
		  { "Access Technology Type", "gsm_a.gm.gmm.acc_tech_type",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_acc_tech_type_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_acc_cap_struct_len,
		  { "Length in bits", "gsm_a.gm.gmm.acc_cap_struct_len",
		    FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sms_value,
		  { "SMS_VALUE (Switch-Measure-Switch)", "gsm_a.gm.gmm.sms",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_sms_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_value,
		  { "(SM_VALUE) Switch-Measure", "gsm_a.gm.gmm.sm",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_sms_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_link_dir,
		  { "Link direction", "gsm_a.gm.sm.link_dir",
		    FT_INT32, BASE_DEC, VALS(gsm_a_gm_link_dir_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_cause,
		  { "GMM Cause", "gsm_a.gm.gmm.cause",
		    FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gmm_cause_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_add_upd_type,
		  { "Additional update type", "gsm_a.gm.gmm.add_upd_type",
		    FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_gm_add_upd_type_value), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_fop,
		  { "Follow-on proceed", "gsm_a.gm.gmm.fop",
		    FT_BOOLEAN, 8, NULL, 0x08,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_res_of_attach,
		  { "Result of attach", "gsm_a.gm.gmm.res_of_attach",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_res_of_attach_vals), 0x07,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_type_of_ciph_alg,
		  { "Type of ciphering algorithm", "gsm_a.gm.gmm.type_of_ciph_alg",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_type_of_ciph_alg_vals), 0x07,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_type_of_integ_alg,
		  { "Type of integrity algorithm", "gsm_a.gm.gmm.type_of_integ_alg",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_type_of_integ_alg_vals), 0x07,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_imeisv_req,
		  { "IMEISV request", "gsm_a.gm.gmm.imeisv_req",
		    FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gsm_a_gm_imeisv_req_vals), 0x00,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_nsapi,
		  { "NSAPI", "gsm_a.gm.gmm.nsapi",
		    FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_ac_ref_nr,
		  { "A&C reference number", "gsm_a.gm.gmm.ac_ref_nr",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_force_to_standby,
		  { "Force to standby", "gsm_a.gm.gmm.force_to_standby",
		    FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gsm_a_gm_force_to_standby_vals), 0x00,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_serv_type,
		  { "Service type", "gsm_a.gm.gmm.serv_type",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_serv_type_vals), 0x00,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_for,
		  { "Follow-on request pending", "gsm_a.gm.gmm.for",
		    FT_BOOLEAN, 8, NULL, 0x08,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_type_of_attach,
		  { "Type of attach", "gsm_a.gm.gmm.type_of_attach",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_type_of_attach_vals), 0x07,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_tmsi_flag,
		  { "TMSI flag", "gsm_a.gm.gmm.tmsi_flag",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gm_tmsi_flag_value), 0x01,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_power_off,
		  { "Power off", "gsm_a.gm.gmm.power_off",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gm_power_off_value), 0x08,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_type_of_detach_mo,
		  { "Type of detach", "gsm_a.gm.gmm.type_of_detach",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_type_of_detach_mo_vals), 0x07,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_type_of_detach_mt,
		  { "Type of detach", "gsm_a.gm.gmm.type_of_detach",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_type_of_detach_mt_vals), 0x07,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_update_type,
		  { "Update type", "gsm_a.gm.gmm.update_type",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_update_type_vals), 0x07,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_gprs_timer,
		  { "GPRS Timer", "gsm_a.gm.gmm.gprs_timer",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_gprs_timer_unit,
		  { "Unit", "gsm_a.gm.gmm.gprs_timer_unit",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_gprs_timer_unit_vals), 0xe0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_gprs_timer_value,
		  { "Timer value", "gsm_a.gm.gmm.gprs_timer_value",
		    FT_UINT8, BASE_DEC, NULL, 0x1f,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_gprs_timer2,
		  { "GPRS Timer", "gsm_a.gm.gmm.gprs_timer2",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_gprs_timer2_unit,
		  { "Unit", "gsm_a.gm.gmm.gprs_timer2_unit",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_gprs_timer_unit_vals), 0xe0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_gprs_timer2_value,
		  { "Timer value", "gsm_a.gm.gmm.gprs_timer2_value",
		    FT_UINT8, BASE_DEC, NULL, 0x1f,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_gprs_timer3,
		  { "GPRS Timer", "gsm_a.gm.gmm.gprs_timer3",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_gprs_timer3_unit,
		  { "Unit", "gsm_a.gm.gmm.gprs_timer3_unit",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_gprs_timer3_unit_vals), 0xe0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_gprs_timer3_value,
		  { "Timer value", "gsm_a.gm.gmm.gprs_timer3_value",
		    FT_UINT8, BASE_DEC, NULL, 0x1f,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_nsapi_5_ul_stat,
		  { "NSAPI(5) uplink status", "gsm_a.gm.gmm.nsapi_5_ul_stat",
		    FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_gm_nsapi_ul_stat_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_nsapi_6_ul_stat,
		  { "NSAPI(6) uplink status", "gsm_a.gm.gmm.nsapi_6_ul_stat",
		    FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_gm_nsapi_ul_stat_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_nsapi_7_ul_stat,
		  { "NSAPI(7) uplink status", "gsm_a.gm.gmm.nsapi_7_ul_stat",
		    FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_gm_nsapi_ul_stat_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_nsapi_8_ul_stat,
		  { "NSAPI(8) uplink status", "gsm_a.gm.gmm.nsapi_8_ul_stat",
		    FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_gm_nsapi_ul_stat_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_nsapi_9_ul_stat,
		  { "NSAPI(9) uplink status", "gsm_a.gm.gmm.nsapi_9_ul_stat",
		    FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_gm_nsapi_ul_stat_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_nsapi_10_ul_stat,
		  { "NSAPI(10) uplink status", "gsm_a.gm.gmm.nsapi_10_ul_stat",
		    FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_gm_nsapi_ul_stat_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_nsapi_11_ul_stat,
		  { "NSAPI(11) uplink status", "gsm_a.gm.gmm.nsapi_11_ul_stat",
		    FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_gm_nsapi_ul_stat_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_nsapi_12_ul_stat,
		  { "NSAPI(12) uplink status", "gsm_a.gm.gmm.nsapi_12_ul_stat",
		    FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_gm_nsapi_ul_stat_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_nsapi_13_ul_stat,
		  { "NSAPI(13) uplink status", "gsm_a.gm.gmm.nsapi_13_ul_stat",
		    FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_gm_nsapi_ul_stat_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_nsapi_14_ul_stat,
		  { "NSAPI(14) uplink status", "gsm_a.gm.gmm.nsapi_14_ul_stat",
		    FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_gm_nsapi_ul_stat_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_nsapi_15_ul_stat,
		  { "NSAPI(15) uplink status", "gsm_a.gm.gmm.nsapi_15_ul_stat",
		    FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_gm_nsapi_ul_stat_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_device_prop_low_prio,
		  { "Low priority", "gsm_a.gm.gmm.device_prop_low_prio",
		    FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_gm_device_prop_low_prio_value), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_apn,
		  { "APN", "gsm_a.gm.sm.apn",
		    FT_STRING,BASE_NONE, NULL,0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_pco_pid,
		  { "Protocol or Container ID", "gsm_a.gm.sm.pco_pid",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_pco_app_spec_info,
		  { "Application specific information", "gsm_a.gm.sm.app_spec_info",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_type_of_identity,
		  { "Type of identity", "gsm_a.gm.gmm.type_of_identity",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_type_of_identity_vals), 0x07,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac,
		  { "Routing Area Code (RAC)", "gsm_a.gm.gmm.rac",
		    FT_UINT8, BASE_HEX_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_mta_e,
		  { "MTA-E", "gsm_a.gm.gmm.mta_e",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gm_mta_e_vals), 0x80,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_mta_r,
		  { "MTA-R", "gsm_a.gm.gmm.mta_r",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gm_mta_r_vals), 0x40,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_apc,
		  { "APC", "gsm_a.gm.gmm.apc",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gm_apc_vals), 0x20,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_otd_a,
		  { "OTD-A", "gsm_a.gm.gmm.otd_a",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gm_otd_a_vals), 0x10,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_otd_b,
		  { "OTD-B", "gsm_a.gm.gmm.otd_b",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gm_otd_b_vals), 0x08,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_gps_a,
		  { "GPS-A", "gsm_a.gm.gmm.gps_a",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gm_gps_a_vals), 0x04,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_gps_b,
		  { "GPS-B", "gsm_a.gm.gmm.gps_b",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gm_gps_b_vals), 0x02,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_gps_c,
		  { "GPS-C", "gsm_a.gm.gmm.gps_c",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gm_gps_c_vals), 0x01,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_motd,
		  { "MOTD", "gsm_a.gm.gmm.motd",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gm_motd_vals), 0x02,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_mta_a,
		  { "MTA-A", "gsm_a.gm.gmm.mta_a",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gm_mta_a_vals), 0x01,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_lcs_molr,
		  { "LCS-MOLR", "gsm_a.gm.gmm.lcs_molr",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gm_lcs_molr_value), 0x08,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_mbms,
		  { "MBMS", "gsm_a.gm.gmm.mbms",
		    FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_ims_vops,
		  { "IMS VoPS", "gsm_a.gm.gmm.ims_vops",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gm_ims_vops_value), 0x02,
		    "IMS voice over PS session indicator", HFILL }
		},
		{ &hf_gsm_a_gm_emc_bs,
		  { "EMC BS", "gsm_a.gm.gmm.emc_bs",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gm_emc_bs_value), 0x01,
		    "Emergency bearer services indicator", HFILL }
		},
		{ &hf_gsm_a_gm_epco,
		  { "ePCO", "gsm_a.gm.gmm.epco",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gm_epco_value), 0x04,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_restrict_ec,
		  { "RestrictEC", "gsm_a.gm.gmm.restrict_ec",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gm_restrict_ec_value), 0x02,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_gprs_sms,
		  { "GPRS-SMS", "gsm_a.gm.gmm.gprs_sms",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gm_gprs_sms_value), 0x01,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_req_ms_info_irat,
		  { "I-RAT", "gsm_a.gm.gmm.req_ms_info_irat",
		    FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_gm_req_ms_info_irat_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_req_ms_info_irat2,
		  { "I-RAT2", "gsm_a.gm.gmm.req_ms_info_irat2",
		    FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_gm_req_ms_info_irat2_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_ue_usage_setting,
		  { "UE's usage setting", "gsm_a.gm.gmm.ue_usage_setting",
		    FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_gm_ue_usage_setting_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_voice_domain_pref_for_eutran,
		  { "Voice domain preference for E-UTRAN", "gsm_a.gm.gmm.voice_domain_pref_for_eutran",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_voice_domain_pref_for_eutran_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_ptmsi_type,
		  { "P-TMSI type", "gsm_a.gm.gmm.ptmsi_type",
		    FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_gm_ptmsi_type_value), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_nri_cont,
		  { "NRI container value", "gsm_a.gm.gmm.nri_cont_value",
		    FT_UINT16, BASE_HEX, NULL, 0xffc0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_paging_time_window,
		  { "Paging Time Window", "gsm_a.gm.gmm.paging_time_window",
		    FT_UINT8, BASE_HEX, VALS(gsm_a_gm_paging_time_window_vals), 0xf0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_edrx_value,
		  { "eDRX value", "gsm_a.gm.gmm.edrx_value",
		    FT_UINT8, BASE_HEX, VALS(gsm_a_gm_edrx_vals), 0x0f,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_ext_paging_time_window,
		  { "Extended Paging Time Window", "gsm_a.gm.gmm.extended_paging_time_window",
		    FT_UINT8, BASE_HEX, VALS(gsm_a_gm_paging_time_window_nr_5gcn_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_mac,
		  { "Message authentication code value", "gsm_a.gm.gmm.mac",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_up_integ_ind,
		  { "Integrity indicator", "gsm_a.gm.gmm.up_integ_ind",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gm_up_integ_ind_value), 0x01,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_dcn_id,
		  { "DCN-ID", "gsm_a.gm.gmm.dcn_id",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_n3en_ind,
		  { "N3EN indicator", "gsm_a.gm.gmm.n3en_ind",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gm_n3en_ind_value), 0x01,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_pdp_type_org,
		  { "PDP type organization", "gsm_a.gm.sm.pdp_type_org",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_sm_pdp_type_org_vals), 0x0f,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_qos_mean_thr,
		  { "Mean throughput", "gsm_a.gm.sm.qos.mean_throughput",
		    FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gsm_a_sm_qos_mean_thr_vals), 0x1f,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_qos_peak_thr,
		  { "Peak throughput", "gsm_a.gm.sm.qos.peak_throughput",
		    FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gsm_a_sm_qos_peak_thr_vals), 0xf0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_qos_prec_class,
		  { "Precedence class", "gsm_a.gm.sm.qos.prec_class",
		    FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gsm_a_sm_qos_prec_class_vals), 0x07,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_qos_trans_delay,
		  { "Transfer delay", "gsm_a.gm.sm.qos.trans_delay",
		    FT_UINT8, BASE_DEC, NULL, 0xfc,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_qos_signalling_ind,
		  { "Signalling indication", "gsm_a.gm.sm.qos.signalling_ind",
		    FT_BOOLEAN, 8, TFS(&gsm_a_sm_qos_signalling_ind_value), 0x10,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_qos_source_stat_desc,
		  { "Source statistics description", "gsm_a.gm.sm.qos.source_stat_desc",
		    FT_UINT8, BASE_DEC, NULL, 0x0f,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_qos_max_bitrate_upl,
		  { "Maximum bitrate for uplink", "gsm_a.gm.sm.qos.max_bitrate_upl",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_qos_max_bitrate_downl,
		  { "Maximum bitrate for downlink", "gsm_a.gm.sm.qos.max_bitrate_downl",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_qos_guar_bitrate_upl,
		  { "Guaranteed bitrate for uplink", "gsm_a.gm.sm.qos.guar_bitrate_upl",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_qos_guar_bitrate_downl,
		  { "Guaranteed bitrate for downlink", "gsm_a.gm.sm.qos.guar_bitrate_downl",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_qos_max_bitrate_upl_ext,
		  { "Maximum bitrate for uplink (extended)", "gsm_a.gm.sm.qos.max_bitrate_upl_ext",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_qos_max_bitrate_downl_ext,
		  { "Maximum bitrate for downlink (extended)", "gsm_a.gm.sm.qos.max_bitrate_downl_ext",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_qos_guar_bitrate_upl_ext,
		  { "Guaranteed bitrate for uplink (extended)", "gsm_a.gm.sm.qos.guar_bitrate_upl_ext",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_qos_guar_bitrate_downl_ext,
		  { "Guaranteed bitrate for downlink (extended)", "gsm_a.gm.sm.qos.guar_bitrate_downl_ext",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_qos_max_bitrate_upl_ext2,
		  { "Maximum bitrate for uplink (extended-2)", "gsm_a.gm.sm.qos.max_bitrate_upl_ext2",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_qos_max_bitrate_downl_ext2,
		  { "Maximum bitrate for downlink (extended-2)", "gsm_a.gm.sm.qos.max_bitrate_downl_ext2",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_qos_guar_bitrate_upl_ext2,
		  { "Guaranteed bitrate for uplink (extended-2)", "gsm_a.gm.sm.qos.guar_bitrate_upl_ext2",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_qos_guar_bitrate_downl_ext2,
		  { "Guaranteed bitrate for downlink (extended-2)", "gsm_a.gm.sm.qos.guar_bitrate_downl_ext2",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_eplmnc,
		  { "EPLMNC", "gsm_a.gm.sm.re_attempt_ind.eplmnc",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gm_eplmnc_value), 0x02,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_ratc,
		  { "RATC", "gsm_a.gm.sm.re_attempt_ind.ratc",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gm_ratc_value), 0x01,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_cause,
		  { "SM Cause", "gsm_a.gm.sm.cause",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_cause_2,
		  { "SM Cause 2", "gsm_a.gm.sm.cause_2",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_llc_sapi,
		  { "LLC SAPI", "gsm_a.gm.sm.llc_sapi",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_sm_llc_sapi_vals), 0x0f,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_tdi,
		  { "Tear Down Indicator (TDI)", "gsm_a.gm.sm.tdi",
		    FT_BOOLEAN, 8, TFS(&gsm_a_sm_tdi_value), 0x01,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_packet_flow_id,
		  { "Packet Flow Identifier (PFI)", "gsm_a.gm.sm.packet_flow_id",
		    FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gsm_a_sm_packet_flow_id_vals), 0x7f,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_gea1,
		  { "GEA/1", "gsm_a.gm.gmm.net_cap.gea1",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_gea_vals), 0x80,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_smdch,
		  { "SM capabilities via dedicated channels", "gsm_a.gm.gmm.net_cap.smdch",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_smdch_vals), 0x40,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_smgprs,
		  { "SM capabilities via GPRS channels", "gsm_a.gm.gmm.net_cap.smgprs",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_smgprs_vals), 0x20,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_ucs2,
		  { "UCS2 support", "gsm_a.gm.gmm.net_cap.ucs2",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_ucs2_vals), 0x10,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_ss_scr_ind,
		  { "SS Screening Indicator", "gsm_a.gm.gmm.net_cap.ss_scr_ind",
		    FT_UINT8, BASE_HEX, VALS(gsm_a_gmm_net_cap_ss_scr_ind_vals), 0x0c,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_solsa,
		  { "SoLSA Capability", "gsm_a.gm.gmm.net_cap.solsa",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_solsa_vals), 0x02,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_rev,
		  { "Revision level indicator", "gsm_a.gm.gmm.net_cap.rev",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_rev_vals), 0x01,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_pfc,
		  { "PFC feature mode", "gsm_a.gm.gmm.net_cap.pfc",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_pfc_vals), 0x80,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_ext_gea_bits,
		  { "Extended GEA bits", "gsm_a.gm.gmm.net_cap.ext_gea_bits",
		    FT_UINT8, BASE_HEX, NULL, 0x7e,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_gea2,
		  { "GEA/2", "gsm_a.gm.gmm.net_cap.gea2",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_gea_vals), 0x40,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_gea3,
		  { "GEA/3", "gsm_a.gm.gmm.net_cap.gea3",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_gea_vals), 0x20,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_gea4,
		  { "GEA/4", "gsm_a.gm.gmm.net_cap.gea4",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_gea_vals), 0x10,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_gea5,
		  { "GEA/5", "gsm_a.gm.gmm.net_cap.gea5",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_gea_vals), 0x08,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_gea6,
		  { "GEA/6", "gsm_a.gm.gmm.net_cap.gea6",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_gea_vals), 0x04,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_gea7,
		  { "GEA/7", "gsm_a.gm.gmm.net_cap.gea7",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_gea_vals), 0x02,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_lcs,
		  { "LCS VA capability", "gsm_a.gm.gmm.net_cap.lcs",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_lcs_vals), 0x01,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_ps_irat_iu,
		  { "PS inter-RAT HO from GERAN to UTRAN Iu mode capability", "gsm_a.gm.gmm.net_cap.ps_irat_iu",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_ps_irat_iu_vals), 0x80,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_ps_irat_s1,
		  { "PS inter-RAT HO from GERAN to E-UTRAN S1 mode capability", "gsm_a.gm.gmm.net_cap.ps_irat_s1",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_ps_irat_s1_vals), 0x40,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_comb_proc,
		  { "EMM Combined procedures capability", "gsm_a.gm.gmm.net_cap.comb_proc",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_comb_proc_vals), 0x20,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_isr,
		  { "ISR support", "gsm_a.gm.gmm.net_cap.isr",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_isr_vals), 0x10,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_srvcc_to_geran,
		  { "SRVCC to GERAN/UTRAN capability", "gsm_a.gm.gmm.net_cap.srvcc_to_geran",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_srvcc_to_geran_vals), 0x08,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_epc,
		  { "EPC capability", "gsm_a.gm.gmm.net_cap.epc",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_epc_vals), 0x04,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_nf,
		  { "NF capability", "gsm_a.gm.gmm.net_cap.nf",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_nf_vals), 0x02,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_geran_net_sharing,
		  { "GERAN network sharing capability", "gsm_a.gm.gmm.net_cap.geran_net_sharing",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_geran_net_vals), 0x01,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_up_int_prot,
		  { "User plane integrity protection support", "gsm_a.gm.gmm.net_cap.up_int_prot",
		    FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_up_gia4,
		  { "GIA/4", "gsm_a.gm.gmm.net_cap.gia4",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_gia_vals), 0x40,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_up_gia5,
		  { "GIA/5", "gsm_a.gm.gmm.net_cap.gia5",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_gia_vals), 0x20,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_up_gia6,
		  { "GIA/6", "gsm_a.gm.gmm.net_cap.gia6",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_gia_vals), 0x10,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_up_gia7,
		  { "GIA/7", "gsm_a.gm.gmm.net_cap.gia7",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_gia_vals), 0x08,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_epco_ie_ind,
		  { "ePCO IE indicator", "gsm_a.gm.gmm.net_cap.epco_ie_ind",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_epco_ie_ind_vals), 0x04,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_restrict_use_enh_cov,
		  { "Restriction on use of enhanced coverage capability", "gsm_a.gm.gmm.net_cap.restrict_use_enh_cov",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_restrict_use_enh_cov_vals), 0x02,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gmm_net_cap_dc_eutra_nr_cap,
		  { "Dual connectivity of E-UTRA with NR capability", "gsm_a.gm.gmm.net_cap.dc_eutra_nr_cap",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gmm_net_cap_dc_eutra_nr_cap_vals), 0x01,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_tmgi,
		  { "Temporary Mobile Group Identity (TMGI)", "gsm_a.gm.sm.tmgi",
		    FT_UINT24, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_enh_nsapi,
		  { "Enhanced NSAPI", "gsm_a.gm.sm.enh_nsapi",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_req_type,
		  { "Request type", "gsm_a.gm.sm.req_type",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_sm_req_type_vals), 0x07,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_notif_ind,
		  { "Notification indicator", "gsm_a.gm.sm.notif_ind",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_sm_notif_ind_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_connectivity_type,
		  { "Connectivity type", "gsm_a.gm.sm.connectivity_type",
		    FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gsm_a_sm_connectivity_type_vals), 0x0F,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_wlan_utran_offload_accept,
		  { "WLAN UTRAN offload acceptability", "gsm_a.gm.sm.wlan_utran_offload_accept",
		    FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_sm_wlan_utran_offload_accept_value), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_wlan_eutran_offload_accept,
		  { "WLAN E-UTRAN offload acceptability", "gsm_a.gm.sm.wlan_eutran_offload_accept",
		    FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_sm_wlan_eutran_offload_accept_value), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_nbifom_cont,
		  { "NBIFOM container content", "gsm_a.gm.sm.nbifom_cont",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_ctrled_early_cm_sending,
		  { "Controlled early Classmark Sending", "gsm_a.gm.gmm.rac.ctrled_early_cm_sending",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_implemented_not_implemented), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_pseudo_sync,
		  { "Pseudo Synchronisation", "gsm_a.gm.gmm.rac.pseudo_sync",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_present_not_present), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_vgcs,
		  { "Voice Group Call Service", "gsm_a.gm.gmm.rac.vgcs",
		    FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_gm_vgcs), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_vbs,
		  { "Voice Broadcast Service", "gsm_a.gm.gmm.rac.vbs",
		    FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_gm_vbs), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_multislot_capability,
		  { "Multislot capability struct", "gsm_a.gm.gmm.rac.multislot_capability",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_present_not_present), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_hscsd_multi_slot_class,
		  { "HSCSD multislot class", "gsm_a.gm.gmm.rac.hscsd_multi_slot_class",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_multi_slot_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_gprs_multi_slot_class,
		  { "GPRS multislot class", "gsm_a.gm.gmm.rac.gprs_multi_slot_class",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_multi_slot_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_gprs_ext_dyn_alloc_cap,
		  { "GPRS Extended Dynamic Allocation Capability", "gsm_a.gm.gmm.rac.gprs_ext_dyn_alloc_cap",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_implemented_not_implemented), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_ecsd_multi_slot_class,
		  { "ECSD multislot class", "gsm_a.gm.gmm.rac.ecsd_multi_slot_class",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_multi_slot_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_egprs_multi_slot_class,
		  { "EGPRS multislot class", "gsm_a.gm.gmm.rac.egprs_multi_slot_class",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_multi_slot_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_egprs_ext_dyn_alloc_cap,
		  { "EGPRS Extended Dynamic Allocation Capability", "gsm_a.gm.gmm.rac.egprs_ext_dyn_alloc_cap",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_implemented_not_implemented), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_dtm_gprs_multi_slot_class,
		  { "DTM GPRS Multi Slot Class", "gsm_a.gm.gmm.rac.dtm_gprs_multi_slot_class",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_dtm_gprs_multi_slot_class_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_single_slt_dtm,
		  { "Single Slot DTM", "gsm_a.gm.gmm.rac.single_slt_dtm",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_dtm_egprs_multi_slot_cls_pres,
		  { "DTM EGPRS Multi Slot Class", "gsm_a.gm.gmm.rac.dtm_egprs_multi_slot_cls_pres",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_present_not_present), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_dtm_egprs_multi_slot_class,
		  { "DTM EGPRS Multi Slot Class", "gsm_a.gm.gmm.rac.dtm_egprs_multi_slot_class",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_dtm_gprs_multi_slot_class_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_8psk_pow_cap_pres,
		  { "8PSK Power Capability Bits", "gsm_a.gm.gmm.rac.8psk_pow_cap_pres",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_present_not_present), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_comp_int_meas_cap,
		  { "COMPACT Interference Measurement Capability", "gsm_a.gm.gmm.rac.comp_int_meas_cap",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_implemented_not_implemented), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rel_lev_ind,
		  { "Revision Level Indicator", "gsm_a.gm.gmm.rel_lev_ind",
		    FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_gm_revision_level_indicator), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_umts_fdd_cap,
		  { "UMTS FDD Radio Access Technology Capability", "gsm_a.gm.gmm.rac.umts_fdd_cap",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_umts_384_tdd_ra_cap,
		  { "UMTS 3.84 Mcps TDD Radio Access Technology Capability", "gsm_a.gm.gmm.rac.umts_384_tdd_ra_cap",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_cdma2000_cap,
		  { "CDMA 2000 Radio Access Technology Capability", "gsm_a.gm.gmm.rac.cdma2000_cap",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_umts_128_tdd_ra_cap,
		  { "UMTS 1.28 Mcps TDD Radio Access Technology Capability", "gsm_a.gm.gmm.rac.umts_128_tdd_ra_cap",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_geran_feat_pkg,
		  { "GERAN Feature Package 1", "gsm_a.gm.gmm.rac.geran_feat_pkg",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_mod_based_multi_slot_class_support,
		  { "Modulation based multislot class support", "gsm_a.gm.gmm.rac.mod_based_multi_slot_class_support",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_geran_iu_mode_cap,
		  { "GERAN Iu mode", "gsm_a.gm.gmm.rac.geran_iu_mode_cap",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_flo_iu_cap,
		  { "FLO Iu Capability", "gsm_a.gm.gmm.rac.flo_iu_cap",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_mult_tbf_cap,
		  { "Multiple TBF Capability", "gsm_a.gm.gmm.rac.mult_tbf_cap",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_down_adv_rec_perf,
		  { "Downlink Advanced Receiver Performance", "gsm_a.gm.gmm.rac.down_adv_rec_perf",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_down_adv_rec_perf_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_ext_rlc_mac_ctrl_msg_seg_cap,
		  { "Extended RLC/MAC Control Message Segmentation Capability", "gsm_a.gm.gmm.rac.ext_rlc_mac_ctrl_msg_seg_cap",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_dtm_enh_cap,
		  { "DTM Enhancements Capability", "gsm_a.gm.gmm.rac.dtm_enh_cap",
		    FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_gm_dtm_enh_cap), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_dtm_gprs_high_multi_slot_class,
		  { "DTM GPRS High Multi Slot Class", "gsm_a.gm.gmm.rac.dtm_gprs_high_multi_slot_class",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_dtm_gprs_high_multi_slot_class_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_dtm_egprs_high_multi_slot_class,
		  { "DTM EGPRS High Multi Slot Class", "gsm_a.gm.gmm.rac.dtm_egprs_high_multi_slot_class",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_dtm_gprs_high_multi_slot_class_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_ps_ho_cap,
		  { "PS Handover Capability", "gsm_a.gm.gmm.rac.ps_ho_cap",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_dtm_ho_cap,
		  { "DTM Handover Capability", "gsm_a.gm.gmm.rac.dtm_ho_cap",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_multi_slot_cap_red_down_dual_carrier,
		  { "Multislot Capability Reduction for Downlink Dual Carrier", "gsm_a.gm.gmm.rac.multi_slot_cap_red_down_dual_carrier",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_multi_slot_cap_red_down_dual_carrier_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_down_dual_carrier_dtm_cap,
		  { "Downlink Dual Carrier for DTM Capability", "gsm_a.gm.gmm.rac.down_dual_carrier_dtm_cap",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_flex_ts_assign,
		  { "Flexible Timeslot Assignment", "gsm_a.gm.gmm.rac.flex_ts_assign",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_gan_ps_ho_cap,
		  { "GAN PS Handover Capability", "gsm_a.gm.gmm.rac.gan_ps_ho_cap",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_rlc_non_pers_mode,
		  { "RLC Non-persistent Mode", "gsm_a.gm.gmm.rac.rlc_non_pers_mode",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_reduced_lat_cap,
		  { "Reduced Latency Capability", "gsm_a.gm.gmm.rac.reduced_lat_cap",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_ul_egprs2,
		  { "Uplink EGPRS2", "gsm_a.gm.gmm.rac.ul_egprs2",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_ul_egprs2_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_dl_egprs2,
		  { "Downlink EGPRS2", "gsm_a.gm.gmm.rac.dl_egprs2",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_dl_egprs2_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_eutra_fdd_support,
		  { "E-UTRA FDD support", "gsm_a.gm.gmm.rac.eutra_fdd_support",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_eutra_tdd_support,
		  { "E-UTRA TDD support", "gsm_a.gm.gmm.rac.eutra_tdd_support",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_geran_to_eutra_support_in_geran_ptm,
		  { "GERAN to E-UTRA support in GERAN packet transfer mode", "gsm_a.gm.gmm.rac.geran_to_eutra_support_in_geran_ptm",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_geran_to_eutra_support_in_geran_ptm_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_prio_based_resel_support,
		  { "Priority-based reselection support", "gsm_a.gm.gmm.rac.prio_based_resel_support",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_alt_efta_multi_slot_class,
		  { "Alternative EFTA Multislot Class", "gsm_a.gm.gmm.rac.alt_efta_multi_slot_class",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_alt_efta_multi_slot_class_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_efta_multi_slot_cap_red_down_dual_carrier,
		  { "EFTA Multislot Capability Reduction for Downlink Dual Carrier", "gsm_a.gm.gmm.rac.efta_multi_slot_cap_red_down_dual_carrier",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_multi_slot_cap_red_down_dual_carrier_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_ind_up_layer_pdu_start_cap_for_rlc_um,
		  { "Indication of Upper Layer PDU Start Capability for RLC UM", "gsm_a.gm.gmm.rac.ind_up_layer_pdu_start_cap_for_rlc_um",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_emst_cap,
		  { "Enhanced Multiplexing for Single TBF Capability", "gsm_a.gm.gmm.rac.emst_cap",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_mtti_cap,
		  { "Multiple TTI Capability", "gsm_a.gm.gmm.rac.mtti_cap",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_utra_csg_cell_report,
		  { "Reporting of UTRAN CSG cells in packet transfer mode", "gsm_a.gm.gmm.rac.utra_csg_cell_report",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_eutra_csg_cell_report,
		  { "Reporting of E-UTRAN CSG cells in packet transfer mode", "gsm_a.gm.gmm.rac.eutra_csg_cell_report",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_dtr_cap,
		  { "Dynamic Timeslot Reduction Capability", "gsm_a.gm.gmm.rac.dtr_cap",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_emsr_cap,
		  { "Enhanced Multiplexing for Single RLC Entity Capability", "gsm_a.gm.gmm.rac.emsr_cap",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_fast_down_freq_switch_cap,
		  { "Fast Downlink Frequency Switching Capability", "gsm_a.gm.gmm.rac.fast_down_freq_switch_cap",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_tighter_cap,
		  { "TIGHTER Capability", "gsm_a.gm.gmm.rac.tighter_cap",
		    FT_UINT8, BASE_DEC, VALS(tighter_cap_level_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_fanr_cap,
		  { "Fast Ack/Nack Reporting Capability", "gsm_a.gm.gmm.rac.fanr_cap",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_ipa_cap,
		  { "Immediate Packet Assignment Capability", "gsm_a.gm.gmm.rac.ipa_cap",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_geran_nw_sharing_support,
		  { "GERAN Network Sharing support", "gsm_a.gm.gmm.rac.geran_nw_sharing_support",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_eutra_wb_rsrq_support,
		  { "E-UTRA Wideband RSRQ measurements support", "gsm_a.gm.gmm.rac.eutra_wb_rsrq_support",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_utra_mfbi_support,
		  { "UTRA Multiple Frequency Band Indicators support", "gsm_a.gm.gmm.rac.utra_mfbi_support",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_eutra_mfbi_support,
		  { "E-UTRA Multiple Frequency Band Indicators support", "gsm_a.gm.gmm.rac.eutra_mfbi_support",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_dlmc_non_contig_intra_band_recep,
		  { "DLMC - Non-contiguous intra-band reception", "gsm_a.gm.gmm.rac.dlmc.non_contig_intra_band_recep",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_dlmc_non_contig_intra_band_recep_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_dlmc_inter_band_recep,
		  { "DLMC - Inter-band reception", "gsm_a.gm.gmm.rac.dlmc.inter_band_recep",
		    FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_gm_dlmc_inter_band_recep_val), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_dlmc_max_bandwidth,
		  { "DLMC - Maximum Bandwidth", "gsm_a.gm.gmm.rac.dlmc.max_bandwidth",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_dlmc_max_bandwidth_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_dlmc_max_nb_dl_ts,
		  { "DLMC - Maximum Number of Downlink Timeslots", "gsm_a.gm.gmm.rac.dlmc.max_nb_dl_ts",
		    FT_UINT8, BASE_CUSTOM, CF_FUNC(gsm_a_gm_dlmc_max_nb_dl_ts_fmt), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_dlmc_max_nb_dl_carriers,
		  { "DLMC - Maximum Number of Downlink Carriers", "gsm_a.gm.gmm.rac.dlmc.max_nb_dl_carriers",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_dlmc_max_nb_dl_carriers_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_ext_tsc_set_cap_support,
		  { "Extended TSC Set Capability support", "gsm_a.gm.gmm.rac.ext_tsc_set_cap_support",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_ext_earfcn_value_range,
		  { "Extended EARFCN value range", "gsm_a.gm.gmm.rac.ext_earfcn_value_range",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_ec_pch_mon_support,
		  { "(EC-)PCH monitoring support", "gsm_a.gm.gmm.rac.ec_pch_mon_support",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_ec_pch_mon_support_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_ms_sync_accuracy,
		  { "MS Sync Accuracy", "gsm_a.gm.gmm.rac.ms_sync_accuracy",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_ec_ul_cov_enh_support,
		  { "EC uplink coverage enhancement support", "gsm_a.gm.gmm.rac.ec_ul_cov_enh_support",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_mta_access_sec_support,
		  { "MTA Access Security support", "gsm_a.gm.gmm.rac.mta_access_sec_support",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_rac_ec_paging_ind_chan_mon_support,
		  { "EC paging indication channel monitoring support", "gsm_a.gm.gmm.rac.ec_paging_ind_chan_mon_support",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_ti_flag,
		  { "TI Flag", "gsm_a.gm.sm.ti_flag",
		    FT_BOOLEAN, 8, TFS(&gsm_a_sm_ti_flag_vals), 0x80,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_sm_ext,
		  { "Extension", "gsm_a.gm.sm.ext",
		    FT_BOOLEAN, 8, NULL, 0x80,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_apn_rate_ctrl_params_aer,
		  { "AER", "gsm_a.gm.sm.pco.apn_rate_ctrl_params.aer",
		    FT_BOOLEAN, 8, TFS(&gsm_a_gm_apn_rate_ctrl_params_aer_value), 0x08,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_apn_rate_ctrl_params_ul_time_unit,
		  { "Uplink time unit", "gsm_a.gm.sm.pco.apn_rate_ctrl_params.ul_time_unit",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_apn_rate_ctrl_ul_time_unit_vals), 0x07,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_apn_rate_ctrl_params_max_ul_rate,
		  { "Maximum uplink rate", "gsm_a.gm.sm.pco.apn_rate_ctrl_params.max_ul_rate",
		    FT_UINT24, BASE_DEC|BASE_UNIT_STRING, &units_message_messages, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_3gpp_data_off_ue_status,
		  { "3GPP PS data off UE status", "gsm_a.gm.sm.pco.3gpp_data_off_ue_status",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_sm_pco_3gpp_data_off_ue_status_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_add_apn_rate_ctrl_params_ul_time_unit,
		  { "Uplink time unit", "gsm_a.gm.sm.pco.add_apn_rate_ctrl_params.ul_time_unit",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_apn_rate_ctrl_ul_time_unit_vals), 0x07,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_add_apn_rate_ctrl_params_max_ul_rate,
		  { "Additional uplink rate for exception data", "gsm_a.gm.sm.pco.add_apn_rate_ctrl_params.max_ul_rate",
		    FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_message_messages, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_pdu_session_id,
		  { "PDU session identity", "gsm_a.gm.sm.pco.pdu_session_id",
		    FT_UINT8, BASE_DEC, VALS(nas_5gs_pdu_session_id_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_pdu_session_address_lifetime,
		  { "PDU session address lifetime", "gsm_a.gm.sm.pco.pdu_session_address_lifetime",
		    FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_second_seconds, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_eth_frame_payload_mtu,
		  { "Ethernet Frame Payload MTU", "gsm_a.gm.sm.pco.eth_frame_payload_mtu",
		    FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_unstruct_link_mtu,
		  { "Unstructured Link MTU", "gsm_a.gm.sm.pco.unstruct_link_mtu",
		    FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_5gsm_cause,
		  { "5GSM cause", "gsm_a.gm.sm.pco.5gsm_cause",
		    FT_UINT8, BASE_DEC, VALS(nas_5gs_sm_cause_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_acs_info,
		  { "ACS information", "gsm_a.gm.sm.pco.acs_info",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_init_small_data_rate_ctrl_params_max_ul_rate_allowed,
		  { "Maximum uplink rate allowed", "gsm_a.gm.sm.pco.init_small_data_rate_ctrl_params.max_ul_rate_allowed",
		    FT_UINT24, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_init_small_data_rate_ctrl_params_termination_timestamp,
		  { "Termination timestamp", "gsm_a.gm.sm.pco.init_small_data_rate_ctrl_params.termination_timestamp",
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_atsss_response,
		  { "ATSSS response", "gsm_a.gm.sm.pco.atsss_response",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_dns_serv_sec_info_type,
		  { "Type", "gsm_a.gm.sm.pco.dns_serv_sec_info.type",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_sm_pco_dns_serv_sec_info_type_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_dns_serv_sec_info_sec_proto_type,
		  { "Security protocol type", "gsm_a.gm.sm.pco.dns_serv_sec_info.sec_proto_type",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_sm_pco_dns_serv_sec_info_sec_proto_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_dns_serv_sec_info_port_number,
		  { "Port number", "gsm_a.gm.sm.pco.dns_serv_sec_info.port_number",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_dns_serv_sec_info_auth_domain_name,
		  { "Authentication domain name", "gsm_a.gm.sm.pco.dns_serv_sec_info.auth_domain_name",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_dns_serv_sec_info_spki_pin_set,
		  { "SPKI pin set", "gsm_a.gm.sm.pco.dns_serv_sec_info.spki_pin_set",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_dns_serv_sec_info_root_certificate,
		  { "Root certificate", "gsm_a.gm.sm.pco.dns_serv_sec_info.root_certificate",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_dns_serv_sec_info_raw_public_key,
		  { "Raw public key", "gsm_a.gm.sm.pco.dns_serv_sec_info.raw_public_key",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_dns_serv_sec_info_value_part,
		  { "Value part", "gsm_a.gm.sm.pco.dns_serv_sec_info.value_part",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_ecs_addr_type,
		  { "Type of ECS address", "gsm_a.gm.sm.pco.ecs_addr.type",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_sm_pco_ecs_addr_type_vals), 0xf0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_ecs_addr_spatial_valid_cond_type,
		  { "Type of spatial validity condition", "gsm_a.gm.sm.pco.ecs_addr.spatial_valid_cond_type",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_sm_pco_ecs_addr_spatial_valid_cond_type_vals), 0x0f,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_ecs_addr_ipv4,
		  { "ECS IPv4 address", "gsm_a.gm.sm.pco.ecs_addr.ipv4",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_ecs_addr_ipv6,
		  { "ECS IPv6 address", "gsm_a.gm.sm.pco.ecs_addr.ipv6",
		    FT_IPv6, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_ecs_addr_fqdn_len,
		  { "ECS FQDN address length", "gsm_a.gm.sm.pco.ecs_addr.fqdn.len",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_ecs_addr_fqdn,
		  { "ECS FQDN address", "gsm_a.gm.sm.pco.ecs_addr.fqdn",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_ecs_addr_spatial_valid_cond_cont,
		  { "Spatial validity condition contents", "gsm_a.gm.sm.pco.ecs_addr.spatial_valid_cond_cont",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_ecsp_id,
		  { "ECSP identifier", "gsm_a.gm.sm.pco.ecsp_id",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_pvs_ipv4,
		  { "PVS IPv4 address", "gsm_a.gm.sm.pco.pvs.ipv4",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_pvs_ipv6,
		  { "PVS IPv6 address", "gsm_a.gm.sm.pco.pvs.ipv6",
		    FT_IPv6, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_pvs_name_len,
		  { "PVS name length", "gsm_a.gm.sm.pco.pvs.name.len",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_pvs_name,
		  { "PVS name", "gsm_a.gm.sm.pco.pvs.name",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_pvs_s_nssai_ind,
		  { "S-NSSAI indicator", "gsm_a.gm.sm.pco.pvs.s_nssai_ind",
		    FT_BOOLEAN, 8, TFS(&tfs_present_absent), 0x02,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_pvs_dnn_ind,
		  { "DNN indicator", "gsm_a.gm.sm.pco.pvs.dnn_ind",
		    FT_BOOLEAN, 8, TFS(&tfs_present_absent), 0x01,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_pvs_dnn_len,
		  { "DNN length", "gsm_a.gm.sm.pco.pvs.dnn_len",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_pvs_s_nssai_len,
		  { "S-NSSAI length", "gsm_a.gm.sm.pco.pvs.s_nssai_len",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_dns_serv_sec_prot_support,
		  { "DNS server security protocol type", "gsm_a.gm.sm.pco.dns_serv_sec_prot_support",
		    FT_UINT8, BASE_DEC, VALS(gsm_a_gm_sm_pco_dns_serv_sec_prot_support_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_eas_rediscovery_support_ind_fqdn,
		  { "With impacted EAS FQDN address range", "gsm_a.gm.sm.pco.eas_rediscovery_support_ind.fqdn",
		    FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_eas_rediscovery_support_ind_ipv6,
		  { "With impacted EAS IPv6 address range", "gsm_a.gm.sm.pco.eas_rediscovery_support_ind.ipv6",
		    FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_eas_rediscovery_support_ind_ipv4,
		  { "With impacted EAS IPv4 address range", "gsm_a.gm.sm.pco.eas_rediscovery_support_ind.ipv4",
		    FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_eas_rediscovery_support_ind_with_impacted_eas_ipv4_range_low,
		  { "With impacted EAS IPv4 address range low", "gsm_a.gm.sm.pco.eas_rediscovery_support_ind_with_impacted_eas_ipv4_range.low",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_eas_rediscovery_support_ind_with_impacted_eas_ipv4_range_high,
		  { "With impacted EAS IPv4 address range high", "gsm_a.gm.sm.pco.eas_rediscovery_support_ind_with_impacted_eas_ipv4_range.high",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_eas_rediscovery_support_ind_with_impacted_eas_ipv6_range_low,
		  { "With impacted EAS IPv6 address range low", "gsm_a.gm.sm.pco.eas_rediscovery_support_ind_with_impacted_eas_ipv6_range.low",
		    FT_IPv6, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_eas_rediscovery_support_ind_with_impacted_eas_ipv6_range_high,
		  { "With impacted EAS IPv6 address range high", "gsm_a.gm.sm.pco.eas_rediscovery_support_ind_with_impacted_eas_ipv6_range.high",
		    FT_IPv6, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_eas_rediscovery_support_ind_with_impacted_eas_fqdn,
		  { "With impacted EAS FQDN", "gsm_a.gm.sm.pco.eas_rediscovery_support_ind_with_impacted_eas_fqdn",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_a_gm_sm_pco_sdnaepc_dn_specific_id,
		  { "SDNAEPC DN-specific identity", "gsm_a.gm.sm.pco.sdnaepc_dn_specific_id",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		/* Generated from convert_proto_tree_add_text.pl */
		{ &hf_gsm_a_gm_presence, { "Presence", "gsm_a.gm.gmm.presence", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_gm_8psk_power_class, { "8PSK Power Class", "gsm_a.gm.8psk_power_class", FT_UINT8, BASE_DEC, VALS(gsm_a_gm_8psk_power_class_vals), 0x0, NULL, HFILL }},
		{ &hf_gsm_a_gm_rf_power_capability, { "RF Power Capability", "gsm_a.gm.rf_power_capability", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_gm_a5_bits, { "A5 Bits", "gsm_a.gm.a5_bits", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_gm_8psk_power_capability, { "8PSK Power Capability", "gsm_a.gm.8psk_power_capability", FT_UINT8, BASE_DEC, VALS(gsm_a_gm_8psk_power_cap_vals), 0x0, NULL, HFILL }},
		{ &hf_gsm_a_gm_extended_dtm_gprs_multi_slot_class, { "Extended DTM GPRS Multi Slot Class", "gsm_a.gm.extended_dtm_gprs_multi_slot_class", FT_UINT8, BASE_DEC, VALS(gsm_a_gm_extended_dtm_gprs_multi_slot_class_vals), 0x0, NULL, HFILL }},
		{ &hf_gsm_a_gm_extended_dtm_egprs_multi_slot_class, { "Extended DTM EGPRS Multi Slot Class", "gsm_a.gm.extended_dtm_egprs_multi_slot_class", FT_UINT8, BASE_DEC, VALS(gsm_a_gm_extended_dtm_gprs_multi_slot_class_vals), 0x0, NULL, HFILL }},
		{ &hf_gsm_a_gm_high_multislot_capability, { "High Multislot Capability", "gsm_a.gm.high_multislot_capability", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_gm_gmsk_multislot_power_profile, { "GMSK Multislot Power Profile", "gsm_a.gm.gmsk_multislot_power_profile", FT_UINT8, BASE_DEC, VALS(gsm_a_gm_gmsk_multislot_power_profile_vals), 0x0, NULL, HFILL }},
		{ &hf_gsm_a_gm_8psk_multislot_power_profile, { "8-PSK Multislot Power Profile", "gsm_a.gm.8psk_multislot_power_profile", FT_UINT8, BASE_DEC, VALS(gsm_a_gm_8psk_multislot_power_profile_vals), 0x0, NULL, HFILL }},
		{ &hf_gsm_a_gm_update_result, { "Update Result", "gsm_a.gm.gmm.update_result", FT_UINT8, BASE_DEC, VALS(gsm_a_gm_update_res_vals), 0x70, NULL, HFILL }},
		{ &hf_gsm_a_gm_radio_priority_pdp, { "Radio Priority (PDP or SMS)", "gsm_a.gm.radio_priority_pdp", FT_UINT8, BASE_DEC, VALS(gsm_a_gm_radio_prio_vals), 0x07, NULL, HFILL }},
		{ &hf_gsm_a_gm_radio_priority_tom8, { "Radio Priority (TOM8)", "gsm_a.gm.radio_priority_tom8", FT_UINT8, BASE_DEC, VALS(gsm_a_gm_radio_prio_vals), 0x70, NULL, HFILL }},
		{ &hf_gsm_a_gm_configuration_protocol, { "Configuration Protocol", "gsm_a.gm.configuration_protocol", FT_UINT8, BASE_DEC, NULL, 0x7, NULL, HFILL }},
		{ &hf_gsm_a_gm_sm_pco_length, { "Length", "gsm_a.gm.sm.pco.length", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_gm_sm_pco_length2, { "Length", "gsm_a.gm.sm.pco.length", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_gm_sm_pco_pcscf_ipv6, { "IPv6", "gsm_a.gm.sm.pco.pcscf.ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_gm_sm_pco_dns_ipv6, { "IPv6", "gsm_a.gm.sm.pco.dns.ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_gm_sm_pco_dsmipv6_home_agent_ipv6, { "IPv6", "gsm_a.gm.sm.pco.dsmipv6_home_agent.ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_gm_sm_pco_dsmipv6_home_network_ipv6, { "IPv6", "gsm_a.gm.sm.pco.dsmipv6_home_network.ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_gm_sm_pco_dsmipv6_home_network_prefix_length, { "Prefix length", "gsm_a.gm.sm.pco.dsmipv6_home_network.ipv6_prefix_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_gm_sm_pco_reject_code, { "Reject Code", "gsm_a.gm.sm.pco.reject_code", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_gm_sm_pco_dsmipv6_home_agent_ipv4, { "IPv4", "gsm_a.gm.sm.pco.dsmipv6_home_agent.ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_gm_sm_pco_pcscf_ipv4, { "IPv4", "gsm_a.gm.sm.pco.pcscf.ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_gm_sm_pco_dns_ipv4, { "IPv4", "gsm_a.gm.sm.pco.dns.ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_gm_sm_pco_ipv4_link_mtu_size, { "IPv4 link MTU size", "gsm_a.gm.sm.pco.ipv4_link_mtu_size", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_gm_sm_pco_nbifom_mode, { "NBIFOM mode", "gsm_a.gm.sm.pco.nbifom_mode", FT_UINT8, BASE_HEX, VALS(gsm_a_gm_nbifom_mode_vals), 0x0, NULL, HFILL }},
		{ &hf_gsm_a_gm_sm_pco_non_ip_link_mtu_size, { "Non-IP link MTU size", "gsm_a.gm.sm.pco.non_ip_link_mtu_size", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_gm_sm_pco_sel_bearer_ctrl_mode, { "Selected Bearer Control Mode", "gsm_a.gm.sm.pco.sel_bearer_ctrl_mode", FT_UINT8, BASE_DEC, VALS(gsm_a_gm_sel_bearer_ctrl_mode_vals), 0x0, NULL, HFILL }},
		{ &hf_gsm_a_sm_pdp_type_number, { "PDP type number", "gsm_a.gm.sm.pdp_type_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_sm_pdp_address, { "PDP address", "gsm_a.gm.sm.pdp_address", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_sm_qos_maximum_sdu_size, { "Maximum SDU size", "gsm_a.gm.sm.qos.maximum_sdu_size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_gm_ti_value, { "TI value", "gsm_a.gm.ti_value", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_sm_tft_packet_filter, { "Packet filter", "gsm_a.gm.sm.tft.packet_filter", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_sm_tft_packet_evaluation_precedence, { "Packet evaluation precedence", "gsm_a.gm.sm.tft.packet_evaluation_precedence", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_sm_tft_packet_filter_length, { "Packet filter length", "gsm_a.gm.sm.tft.packet_filter_length", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_sm_tft_authorization_token_value, { "Authorization token value", "gsm_a.gm.sm.tft.authorization_token_value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_sm_tft_media_component_number_value, { "Media Component number value", "gsm_a.gm.sm.tft.media_component_number_value", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_sm_tft_ip_flow_number, { "IP flow number", "gsm_a.gm.sm.tft.ip_flow_number", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_sm_tft_packet_filter_identifier, { "Packet filter identifier", "gsm_a.gm.sm.tft.packet_filter_identifier", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_sm_tft_parameter_content, { "Parameter content", "gsm_a.gm.sm.tft.parameter_content", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_gsm_a_sm_tft_packet_filter_component_type_id, { "Packet filter component type identifier", "gsm_a.gm.sm.tft.packet_filter_component_type_id", FT_UINT8, BASE_DEC, VALS(packet_filter_component_type_vals), 0x0, NULL, HFILL }},
	};

	static ei_register_info ei[] = {
		{ &ei_gsm_a_gm_extraneous_data, { "gsm_a.gm.extraneous_data", PI_PROTOCOL, PI_NOTE, "Extraneous Data, dissector bug or later version spec (report to wireshark.org)", EXPFILL }},
		{ &ei_gsm_a_gm_not_enough_data, { "gsm_a.gm.not_enough_data", PI_PROTOCOL, PI_WARN, "Not enough data", EXPFILL }},
		{ &ei_gsm_a_gm_undecoded, { "gsm_a.gm.undecoded", PI_UNDECODED, PI_WARN, "Not decoded", EXPFILL }},
		{ &ei_gsm_a_gm_missing_mandatory_element, { "gsm_a.gm.missing_mandatory_element", PI_PROTOCOL, PI_ERROR, "Missing Mandatory element, rest of dissection is suspect", EXPFILL }},
	};

	expert_module_t* expert_gsm_a_gm;

	/* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_ELEMS	7
	int *ett[NUM_INDIVIDUAL_ELEMS +
		  NUM_GSM_DTAP_MSG_GMM + NUM_GSM_DTAP_MSG_SM +
		  NUM_GSM_GM_ELEM];

	ett[0]  = &ett_gmm_radio_cap;
	ett[1]  = &ett_gmm_rai;
	ett[2]  = &ett_sm_tft;
	ett[3]  = &ett_gmm_gprs_timer;
	ett[4]  = &ett_gmm_network_cap;
	ett[5]  = &ett_gsm_a_gm_msrac_multislot_capability;
	ett[6]  = &ett_sm_pco;

	last_offset = NUM_INDIVIDUAL_ELEMS;

	for (i=0; i<NUM_GSM_DTAP_MSG_GMM; i++, last_offset++)
	{
		ett[last_offset] = &ett_gsm_dtap_msg_gmm[i];
	}

	for (i=0; i<NUM_GSM_DTAP_MSG_SM; i++, last_offset++)
	{
		ett[last_offset] = &ett_gsm_dtap_msg_sm[i];
	}

	for (i=0; i<NUM_GSM_GM_ELEM; i++, last_offset++)
	{
		ett[last_offset] = &ett_gsm_gm_elem[i];
	}

	proto_a_gm =
		proto_register_protocol("GSM A-I/F GPRS Mobility and Session Management", "GSM Management", "gsm_a.gm");

	proto_register_field_array(proto_a_gm, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));
	expert_gsm_a_gm = expert_register_protocol(proto_a_gm);
	expert_register_field_array(expert_gsm_a_gm, ei, array_length(ei));

	/* subdissector code */
	gprs_sm_pco_subdissector_table = register_dissector_table("sm_pco.protocol",
		"GPRS SM PCO PPP protocol", proto_a_gm, FT_UINT16, BASE_HEX);
}

void
proto_reg_handoff_gsm_a_gm(void)
{
	rrc_irat_ho_info_handle = find_dissector_add_dependency("rrc.irat.irat_ho_info", proto_a_gm);
	lte_rrc_ue_eutra_cap_handle = find_dissector_add_dependency("lte-rrc.ue_eutra_cap", proto_a_gm);
	nbifom_handle = find_dissector_add_dependency("nbifom", proto_a_gm);
	eap_handle = find_dissector_add_dependency("eap", proto_a_gm);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
