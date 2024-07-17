/* packet-dect-mitel-eth.c
 *
 * Dissector for the proprietary protocol of the internal ethernet link
 * between DECT burst processor and ARM processor in Aastra/Mitel DECT
 * base stations.
 *
 * Copyright 2018 by Harald Welte <laforge@gnumonks.org>
 * Copyright 2022 by Bernhard Dick <bernhard@bdick.de>
 *
 * Parts are based on the EVENTPHONE rfpproxy project that is MIT licensed
 * and Copyright (c) 2019 Bianco Veigel <devel at zivillian.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/packet_info.h>
#include <epan/value_string.h>
#include <ftypes/ftypes.h>
#include <epan/proto.h>
#include <epan/tfs.h>
#include <tvbuff.h>

void proto_register_dect_mitel_eth(void);
void proto_reg_handoff_dect_mitel_eth(void);

static int proto_dect_mitel_eth;

static int hf_dect_mitel_eth_len;
static int hf_dect_mitel_eth_layer;
static int hf_dect_mitel_eth_prim_type;
static int hf_dect_mitel_eth_mcei;
static int hf_dect_mitel_eth_mac_info_ind_string;
static int hf_dect_mitel_eth_pmid;
static int hf_dect_mitel_eth_subfield;

static int hf_dect_mitel_eth_rfpc_message_type;
static int hf_dect_mitel_eth_rfpc_item_type;
static int hf_dect_mitel_eth_rfpc_item_length;
static int hf_dect_mitel_eth_rfpc_item_value;

static int hf_dect_mitel_eth_rfpc_revision_generation;
static int hf_dect_mitel_eth_rfpc_revision_boot_software;
static int hf_dect_mitel_eth_rfpc_revision_prog_software;
static int hf_dect_mitel_eth_rfpc_revision_hardware;

static int hf_dect_mitel_eth_rfpc_rfpi_saris_available;
static int hf_dect_mitel_eth_rfpc_rfpi_ari_class;

static int hf_dect_mitel_eth_rfpc_higher_layer_capabilities_flags;
static int hf_dect_mitel_eth_rfpc_higher_layer_capabilities_connection_handover_supported;
static int hf_dect_mitel_eth_rfpc_higher_layer_capabilities_external_handover_supported;
static int hf_dect_mitel_eth_rfpc_higher_layer_capabilities_access_rights_requests_supported;
static int hf_dect_mitel_eth_rfpc_higher_layer_capabilities_coms_service_available;
static int hf_dect_mitel_eth_rfpc_higher_layer_capabilities_clms_service_available;
static int hf_dect_mitel_eth_rfpc_higher_layer_capabilities_ciss_services_available;
static int hf_dect_mitel_eth_rfpc_higher_layer_capabilities_non_static_fixed_part;
static int hf_dect_mitel_eth_rfpc_higher_layer_capabilities_sim_services_available;
static int hf_dect_mitel_eth_rfpc_higher_layer_capabilities_location_registration_supported;
static int hf_dect_mitel_eth_rfpc_higher_layer_capabilities_dsc_supported;
static int hf_dect_mitel_eth_rfpc_higher_layer_capabilities_dsaa_required;
static int hf_dect_mitel_eth_rfpc_higher_layer_capabilities_non_voice_packet_switched_service;
static int hf_dect_mitel_eth_rfpc_higher_layer_capabilities_non_voice_circuit_switched_service;
static int hf_dect_mitel_eth_rfpc_higher_layer_capabilities_gap_basic_speech;
static int hf_dect_mitel_eth_rfpc_higher_layer_capabilities_g726;

static int hf_dect_mitel_eth_rfpc_extended_capabilities_wireless_relay_stations;
static int hf_dect_mitel_eth_rfpc_extended_capabilities_flags;
static int hf_dect_mitel_eth_rfpc_extended_capabilities_isdn_data_services;
static int hf_dect_mitel_eth_rfpc_extended_capabilities_dprs_class_2;
static int hf_dect_mitel_eth_rfpc_extended_capabilities_dprs_class_3_or_4;
static int hf_dect_mitel_eth_rfpc_extended_capabilities_data_service_profile_d;
static int hf_dect_mitel_eth_rfpc_extended_capabilities_lrms;
static int hf_dect_mitel_eth_rfpc_extended_capabilities_asymmetric_bearers_supported;
static int hf_dect_mitel_eth_rfpc_extended_capabilities_emergency_call_supported;
static int hf_dect_mitel_eth_rfpc_extended_capabilities_location_registration_with_tpui_allowed;
static int hf_dect_mitel_eth_rfpc_extended_capabilities_sync_to_gps_achieved;
static int hf_dect_mitel_eth_rfpc_extended_capabilities_isdn_intermediate_system;
static int hf_dect_mitel_eth_rfpc_extended_capabilities_rap_part_1_profile;
static int hf_dect_mitel_eth_rfpc_extended_capabilities_v24;
static int hf_dect_mitel_eth_rfpc_extended_capabilities_ppp;
static int hf_dect_mitel_eth_rfpc_extended_capabilities_ip;
static int hf_dect_mitel_eth_rfpc_extended_capabilities_token_ring;
static int hf_dect_mitel_eth_rfpc_extended_capabilities_ethernet;
static int hf_dect_mitel_eth_rfpc_extended_capabilities_ip_roaming_unrestricted_supported;
static int hf_dect_mitel_eth_rfpc_extended_capabilities_dprs_supported;
static int hf_dect_mitel_eth_rfpc_extended_capabilities_basis_odap_supported;
static int hf_dect_mitel_eth_rfpc_extended_capabilities_fmms_interworking_profile_supported;
static int hf_dect_mitel_eth_rfpc_extended_capabilities_extended_fp_info2;
static int hf_dect_mitel_eth_rfpc_extended_capabilities_ipq_services_supported;
static int hf_dect_mitel_eth_rfpc_extended_capabilities_mac_suspend_resume;
static int hf_dect_mitel_eth_rfpc_extended_capabilities_frequency_replacement_supported;
static int hf_dect_mitel_eth_rfpc_extended_capabilities_syncronization;

static int hf_dect_mitel_eth_rfpc_mac_capabilities_flags;
static int hf_dect_mitel_eth_rfpc_mac_capabilities_multibearer_connections;
static int hf_dect_mitel_eth_rfpc_mac_capabilities_ipmr_error_correction;
static int hf_dect_mitel_eth_rfpc_mac_capabilities_ipm_error_detection;
static int hf_dect_mitel_eth_rfpc_mac_capabilities_inb_normal_delay;
static int hf_dect_mitel_eth_rfpc_mac_capabilities_ina_minimum_delay;
static int hf_dect_mitel_eth_rfpc_mac_capabilities_cf_messages;
static int hf_dect_mitel_eth_rfpc_mac_capabilities_b_field_setup;
static int hf_dect_mitel_eth_rfpc_mac_capabilities_advanced_a_field_setup;
static int hf_dect_mitel_eth_rfpc_mac_capabilities_basic_a_field_setup;
static int hf_dect_mitel_eth_rfpc_mac_capabilities_cl_downlink;
static int hf_dect_mitel_eth_rfpc_mac_capabilities_cl_uplink;
static int hf_dect_mitel_eth_rfpc_mac_capabilities_co_setup_on_dummy_allowed;
static int hf_dect_mitel_eth_rfpc_mac_capabilities_page_repetition;
static int hf_dect_mitel_eth_rfpc_mac_capabilities_frequency_control;
static int hf_dect_mitel_eth_rfpc_mac_capabilities_slot_size_full;
static int hf_dect_mitel_eth_rfpc_mac_capabilities_slot_size_half;
static int hf_dect_mitel_eth_rfpc_mac_capabilities_slot_size_double;
static int hf_dect_mitel_eth_rfpc_mac_capabilities_double_duplex_bearer_connections;
static int hf_dect_mitel_eth_rfpc_mac_capabilities_extended_fp_info;

static int hf_dect_mitel_eth_rfpc_statistic_data_bmc_connections_1_3;
static int hf_dect_mitel_eth_rfpc_statistic_data_bmc_connections_4_6;
static int hf_dect_mitel_eth_rfpc_statistic_data_bmc_connections_7_9;
static int hf_dect_mitel_eth_rfpc_statistic_data_bmc_connections_10_12;
static int hf_dect_mitel_eth_rfpc_statistic_data_bmc_dsp_channels_1_2;
static int hf_dect_mitel_eth_rfpc_statistic_data_bmc_dsp_channels_3_4;
static int hf_dect_mitel_eth_rfpc_statistic_data_bmc_dsp_channels_5_6;
static int hf_dect_mitel_eth_rfpc_statistic_data_bmc_dsp_channels_7_8;
static int hf_dect_mitel_eth_rfpc_statistic_data_lost_connections;
static int hf_dect_mitel_eth_rfpc_statistic_data_mac_reset;
static int hf_dect_mitel_eth_rfpc_statistic_data_reject_dummy;
static int hf_dect_mitel_eth_rfpc_statistic_data_handoff_timer;
static int hf_dect_mitel_eth_rfpc_statistic_data_bad_frames;
static int hf_dect_mitel_eth_rfpc_statistic_data_good_frames;

static int hf_dect_mitel_eth_rfpc_rfp_pli_length_indicator;

static int hf_dect_mitel_eth_rfpc_extended_capabilities2_mac_capability_flags;
static int hf_dect_mitel_eth_rfpc_extended_capabilities2_mac_capability_slot_type_long_640;
static int hf_dect_mitel_eth_rfpc_extended_capabilities2_mac_capability_slot_type_long_672;
static int hf_dect_mitel_eth_rfpc_extended_capabilities2_mac_capability_mux_e_u;
static int hf_dect_mitel_eth_rfpc_extended_capabilities2_mac_capability_channel_ipf;
static int hf_dect_mitel_eth_rfpc_extended_capabilities2_mac_capability_channel_sipf;
static int hf_dect_mitel_eth_rfpc_extended_capabilities2_mac_capability_channel_gf;
static int hf_dect_mitel_eth_rfpc_extended_capabilities2_mac_capability_wrs_ule;
static int hf_dect_mitel_eth_rfpc_extended_capabilities2_mac_capability_no_emission_preferred_cn;
static int hf_dect_mitel_eth_rfpc_extended_capabilities2_flags;
static int hf_dect_mitel_eth_rfpc_extended_capabilities2_ng_dect_1;
static int hf_dect_mitel_eth_rfpc_extended_capabilities2_dprs_data_category;
static int hf_dect_mitel_eth_rfpc_extended_capabilities2_ng_dect_3;
static int hf_dect_mitel_eth_rfpc_extended_capabilities2_permanent_clir;
static int hf_dect_mitel_eth_rfpc_extended_capabilities2_third_party_conference;
static int hf_dect_mitel_eth_rfpc_extended_capabilities2_intrusion_call;
static int hf_dect_mitel_eth_rfpc_extended_capabilities2_call_deflection;
static int hf_dect_mitel_eth_rfpc_extended_capabilities2_multiple_lines;
static int hf_dect_mitel_eth_rfpc_extended_capabilities2_no_emission;
static int hf_dect_mitel_eth_rfpc_extended_capabilities2_ng_dect_5;
static int hf_dect_mitel_eth_rfpc_extended_capabilities2_re_keying;
static int hf_dect_mitel_eth_rfpc_extended_capabilities2_dsaa2;
static int hf_dect_mitel_eth_rfpc_extended_capabilities2_dsc2;
static int hf_dect_mitel_eth_rfpc_extended_capabilities2_light_data;

static int hf_dect_mitel_eth_mac_con_ind_flags;
static int hf_dect_mitel_eth_mac_con_ind_flag_handover;

static int hf_dect_mitel_eth_mac_dis_ind_reason;

static int hf_dect_mitel_eth_mac_page_req_flags;

static int hf_dect_mitel_eth_mac_enc_key_req_key;
static int hf_dect_mitel_eth_mac_enc_key_req_id;

static int hf_dect_mitel_eth_mac_enc_eks_ind_type;
static int hf_dect_mitel_eth_mac_enc_eks_ind_id;
static int hf_dect_mitel_eth_mac_enc_eks_ind_ppn;

static int hf_dect_mitel_eth_mac_ho_in_progress_res_key;
static int hf_dect_mitel_eth_mac_ho_in_progress_res_id;

static int hf_dect_mitel_eth_mac_ho_failed_ind_reason;

static int hf_dect_mitel_eth_mt_item_key;
static int hf_dect_mitel_eth_mt_item_length;
static int hf_dect_mitel_eth_mt_item_value;

static int ett_dect_mitel_eth;

static int ett_dect_mitel_eth_rfpc_item;

static int ett_dect_mitel_eth_higher_layer_capabilities_flags;
static int ett_dect_mitel_eth_extended_capabilities_flags;
static int ett_dect_mitel_eth_mac_capabilities_flags;
static int ett_dect_mitel_eth_extended_capabilities2_mac_capability_flags;
static int ett_dect_mitel_eth_extended_capabilities2_flags;

static dissector_handle_t dlc_handle;

#define DECT_MITEL_ETH_T_XDLC	0xA000
#define DECT_MITEL_ETH_T_DOWNLOAD	0xA002
#define DECT_MITEL_ETH_T_VIDEO	0xA003
#define DECT_MITEL_ETH_T_AUDIOLOG	0xA004

enum dect_mitel_eth_layer_coding {
	DECT_MITEL_ETH_LAYER_RFPC = 0x78,
	DECT_MITEL_ETH_LAYER_LC   = 0x79,
	DECT_MITEL_ETH_LAYER_MAC  = 0x7A,
	DECT_MITEL_ETH_LAYER_MT   = 0x7C,
	DECT_MITEL_ETH_LAYER_SYNC = 0x7D,
};

enum dect_mitel_eth_prim_coding {
	DECT_MITEL_ETH_MAC_CON_IND              = 0x01,
	DECT_MITEL_ETH_MAC_DIS_REQ              = 0x02,
	DECT_MITEL_ETH_MAC_DIS_IND              = 0x03,
	DECT_MITEL_ETH_LC_DATA_REQ              = 0x05,
	DECT_MITEL_ETH_LC_DATA_IND              = 0x06,
	DECT_MITEL_ETH_LC_DTR_IND               = 0x07,
	DECT_MITEL_ETH_MAC_PAGE_REQ             = 0x08,
	DECT_MITEL_ETH_MAC_ENC_KEY_REQ          = 0x09,
	DECT_MITEL_ETH_MAC_ENC_EKS_IND          = 0x0a,
	DECT_MITEL_ETH_MAC_HO_IN_PROGRESS_IND   = 0x0b,
	DECT_MITEL_ETH_MAC_HO_IN_PROGRESS_RES   = 0x0c,
	DECT_MITEL_ETH_MAC_HO_FAILED_IND        = 0x0d,
	DECT_MITEL_ETH_HO_FAILED_REQ            = 0x0e,
	DECT_MITEL_ETH_DLC_RFP_ERROR_IND        = 0x14,
	DECT_MITEL_ETH_MAC_CON_EXT_IND          = 0x15,
	DECT_MITEL_ETH_HO_IN_PROGRESS_EXT_IND   = 0x16,
	DECT_MITEL_ETH_MAC_MOD_REQ              = 0x17,
	DECT_MITEL_ETH_MAC_MOD_CNF              = 0x18,
	DECT_MITEL_ETH_MAC_MOD_IND              = 0x19,
	DECT_MITEL_ETH_MAC_MOD_REJ              = 0x1a,
	DECT_MITEL_ETH_MAC_RECORD_AUDIO         = 0x1b,
	DECT_MITEL_ETH_MAC_INFO_IND             = 0x1c,
	DECT_MITEL_ETH_MAC_GET_DEF_CKEY_IND     = 0x1d,
	DECT_MITEL_ETH_MAC_GET_DEF_CKEY_RES     = 0x1e,
	DECT_MITEL_ETH_MAC_CLEAR_DEF_CKEY_REQ   = 0x1f,
	DECT_MITEL_ETH_MAC_GET_CURR_CKEY_ID_REQ = 0x20,
	DECT_MITEL_ETH_MAC_GET_CURR_CKEY_ID_CNF = 0x21,
};

/* RFPC */
enum dect_mitel_eth_rfpc_message_type_coding {
	DECT_MITEL_ETH_RFPC_MESSAGE_TYPE_READY_IND                            = 0x01,
	DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_INIT_REQ                             = 0x02,
	DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_INIT_CFM                             = 0x03,
	DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_SARI_LIST_REQ                        = 0x05,
	DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_CHANGE_HIGHER_LAYER_CAPABILITIES_REQ = 0x06,
	DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_CHANGE_HIGHER_LAYER_CAPABILITIES_CFM = 0x07,
	DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_CHANGE_STATUS_INFO_REQ               = 0x08,
	DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_CHANGE_STATUS_INFO_CFM               = 0x09,
	DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_ACTIVATE_REQ                         = 0x0f,
	DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_ACTIVATE_CFM                         = 0x10,
	DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_DEACTIVATE_REQ                       = 0x11,
	DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_DEACTIVATE_CFM                       = 0x12,
	DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_RESET_REQ                            = 0x13,
	DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_STATISTICS_DATA_REQ                  = 0x16,
	DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_STATISTICS_DATA_CFM                  = 0x17,
	DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_ERROR_IND                            = 0x18,
	DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_TO_RFP_IND                           = 0x20,
	DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_TO_RFP_REQ                           = 0x21,
	DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_TOPO_DATA_REQ                        = 0x22,
	DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_TOPO_DATA_IND                        = 0x23,
	DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_BMC_RESTART_REQ                      = 0x24,
	DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_CHANGE_MASTER_REQ                    = 0x25,
	DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_INFO_IND                             = 0x26,
	DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_ACTIVE_IND                           = 0x30,
	DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_ACTIVE_RES                           = 0x31,
	DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_PAGING_QUEUE_OVERFLOW_IND            = 0x32,
};

enum dect_mitel_eth_rfpc_item_type_coding {
	DECT_MITEL_ETH_RFPC_ITEM_TYPE_NUMBER_OF_UPN             = 0x01,
	DECT_MITEL_ETH_RFPC_ITEM_TYPE_REVISION                  = 0x02,
	DECT_MITEL_ETH_RFPC_ITEM_TYPE_NUMBER_OF_BEARER          = 0x03,
	DECT_MITEL_ETH_RFPC_ITEM_TYPE_RFPI                      = 0x04,
	DECT_MITEL_ETH_RFPC_ITEM_TYPE_SARI                      = 0x05,
	DECT_MITEL_ETH_RFPC_ITEM_TYPE_HIGHER_LAYER_CAPABILITIES = 0x06,
	DECT_MITEL_ETH_RFPC_ITEM_TYPE_EXTENDED_CAPABILITIES     = 0x07,
	DECT_MITEL_ETH_RFPC_ITEM_TYPE_STATUS_INFO               = 0x08,
	DECT_MITEL_ETH_RFPC_ITEM_TYPE_MAC_CAPABILITIES          = 0x0d,
	DECT_MITEL_ETH_RFPC_ITEM_TYPE_STATISTIC_DATA_RESET      = 0x0f,
	DECT_MITEL_ETH_RFPC_ITEM_TYPE_STATISTIC_DATA            = 0x10,
	DECT_MITEL_ETH_RFPC_ITEM_TYPE_ERROR_CAUSE               = 0x11,
	DECT_MITEL_ETH_RFPC_ITEM_TYPE_RFP_FU6_WINDOW_SIZE       = 0x12,
	DECT_MITEL_ETH_RFPC_ITEM_TYPE_RFP_TO_RFP                = 0x14,
	DECT_MITEL_ETH_RFPC_ITEM_TYPE_RFP_TOPO                  = 0x15,
	DECT_MITEL_ETH_RFPC_ITEM_TYPE_LAST_ERROR                = 0x20,
	DECT_MITEL_ETH_RFPC_ITEM_TYPE_PABX_DATA                 = 0x21,
	DECT_MITEL_ETH_RFPC_ITEM_TYPE_MONI_DATA                 = 0x22,
	DECT_MITEL_ETH_RFPC_ITEM_TYPE_LAST_ERROR_EXT            = 0x23,
	DECT_MITEL_ETH_RFPC_ITEM_TYPE_FPGA_REVISION             = 0x24,
	DECT_MITEL_ETH_RFPC_ITEM_TYPE_RFP_STRING                = 0x25,
	DECT_MITEL_ETH_RFPC_ITEM_TYPE_RFP_SITE_LOCATION         = 0x26,
	DECT_MITEL_ETH_RFPC_ITEM_TYPE_RFP_PLI                   = 0x27,
	DECT_MITEL_ETH_RFPC_ITEM_TYPE_REFLECTING_ENVIRONMENT    = 0x28,
	DECT_MITEL_ETH_RFPC_ITEM_TYPE_EXTENDED_CAPABILITIES2    = 0x29,
	DECT_MITEL_ETH_RFPC_ITEM_TYPE_FREQUENCY_BAND            = 0x2a,
	DECT_MITEL_ETH_RFPC_ITEM_TYPE_RF_POWER                  = 0x2b,
};

/* RFPc RFPI */
enum dect_mitel_eth_rfpc_rfpi_coding {
	DECT_MITEL_ETH_RFPC_RFPI_SARIS_AVAILABLE = 0x80,
};

enum dect_mitel_eth_rfpc_rfpi_ari_class_coding {
	DECT_MITEL_ETH_RFPC_RFPI_ARI_CLASS_A = 0x0,
	DECT_MITEL_ETH_RFPC_RFPI_ARI_CLASS_B = 0x1,
	DECT_MITEL_ETH_RFPC_RFPI_ARI_CLASS_C = 0x2,
	DECT_MITEL_ETH_RFPC_RFPI_ARI_CLASS_D = 0x3,
	DECT_MITEL_ETH_RFPC_RFPI_ARI_CLASS_E = 0x4,
};

/* RFPc Higher layer capabilities */
enum dect_mitel_eth_rfpc_higher_layer_capabilities_flags_coding {
	DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_CONNECTION_HANDOVER_SUPPORTED      = 0x0002,
	DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_EXTERNAL_HANDOVER_SUPPORTED        = 0x0004,
	DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_ACCESS_RIGHTS_REQUESTS_SUPPORTED   = 0x0008,
	DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_COMS_SERVICE_AVAILABLE             = 0x0010,
	DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_CLMS_SERVICE_AVAILABLE             = 0x0020,
	DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_CISS_SERVICES_AVAILABLE            = 0x0040,
	DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_NON_STATIC_FIXED_PART              = 0x0080,
	DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_SIM_SERVICES_AVAILABLE             = 0x0100,
	DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_LOCATION_REGISTRATION_SUPPORTED    = 0x0200,
	DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_DSC_SUPPORTED                      = 0x0400,
	DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_DSAA_REQUIRED                      = 0x0800,
	DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_NON_VOICE_PACKET_SWITCHED_SERVICE  = 0x1000,
	DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_NON_VOICE_CIRCUIT_SWITCHED_SERVICE = 0x2000,
	DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_GAP_BASIC_SPEECH                   = 0x4000,
	DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_G726                               = 0x8000,
};

/* RFPc Extended Capabilities*/
enum dect_mitel_eth_rfpc_extended_capabilities_flags_coding {
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_ISDN_DATA_SERVICES                      = 0x00000001,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_DPRS_CLASS_2                            = 0x00000002,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_DPRS_CLASS_3_OR_4                       = 0x00000004,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_DATA_SERVICE_PROFILE_D                  = 0x00000008,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_LRMS                                    = 0x00000010,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_ASYMMETRIC_BEARERS_SUPPORTED            = 0x00000020,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_EMERGENCY_CALL_SUPPORTED                = 0x00000040,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_LOCATION_REGISTRATION_WITH_TPUI_ALLOWED = 0x00000080,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_SYNCHRONIZATION_TO_GPS_ACHIEVED         = 0x00000100,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_ISDN_INTERMEDIATE_SYSTEM                = 0x00000200,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_RAP_PART_1_PROFILE                      = 0x00000400,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_V24                                     = 0x00000800,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_PPP                                     = 0x00001000,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_IP                                      = 0x00002000,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_TOKEN_RING                              = 0x00004000,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_ETHERNET                                = 0x00008000,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_IP_ROAMING_UNRESTRICTED_SUPPORTED       = 0x00010000,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_DPRS_SUPPORTED                          = 0x00020000,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_BASIC_ODAP_SUPPORTED                    = 0x00040000,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_FMMS_INTERWORKING_PROFILE_SUPPORTED     = 0x00080000,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_EXTENDED_FP_INFOR_2                     = 0x01000000,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_IPQ_SERVICES_SUPPORTED                  = 0x02000000,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_MAC_SUSPEND_RESUME                      = 0x04000000,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_FREQUENCY_REPLACEMENT_SUPPORTED         = 0x08000000,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_SYNCHRONIZATION                         = 0x10000000,
};

/* RFPc MAC Capabilities */
enum dect_mitel_eth_rfpc_mac_capabilities_flags {
	DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_MULTIBEARER_CONNECTIONS          = 0x00001,
	DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_IPMR_ERROR_CORRECTION            = 0x00002,
	DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_IPM_ERROR_DETECTION              = 0x00004,
	DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_INB_NORMAL_DELAY                 = 0x00008,
	DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_INA_MINIMUM_DELAY                = 0x00010,
	DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_CF_MESSAGES                      = 0x00020,
	DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_B_FIELD_SETUP                    = 0x00040,
	DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_ADVANCED_A_FIELD_SETUP           = 0x00080,
	DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_BASIC_A_FIELD_SETUP              = 0x00100,
	DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_CL_DOWNLINK                      = 0x00200,
	DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_CL_UPLINK                        = 0x00400,
	DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_CO_SETUP_ON_DUMMY_ALLOWED        = 0x00800,
	DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_PAGE_REPETITION                  = 0x01000,
	DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_FREQUENCY_CONTROL                = 0x02000,
	DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_SLOT_SIZE_FULL                   = 0x04000,
	DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_SLOT_SIZE_HALF                   = 0x08000,
	DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_SLOT_SIZE_DOUBLE                 = 0x10000,
	DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_DOUBLE_DUPLEX_BEARER_CONNECTIONS = 0x40000,
	DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_EXTENDED_FP_INFO                 = 0x80000,
};

/* RFPc Extended Capabilities 2 */
enum dect_mitel_eth_rfpc_extended_capabilities2_mac_capability_flags_coding {
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_MAC_CAPABILITY_SLOT_TYPE_LONG_640       = 0x800,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_MAC_CAPABILITY_SLOT_TYPE_LONG_672       = 0x400,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_MAC_CAPABILITY_MUX_E_U                  = 0x200,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_MAC_CAPABILITY_CHANNEL_IPF              = 0x100,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_MAC_CAPABILITY_CHANNEL_SIPF             = 0x080,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_MAC_CAPABILITY_CHANNEL_GF               = 0x040,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_MAC_CAPABILITY_WRS_ULE                  = 0x020,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_MAC_CAPABILITY_NO_EMISSION_PREFERRED_CN = 0x001,
};

enum dect_mitel_eth_rfpc_extended_capabilities2_flags_coding {
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_NG_DECT_1              = 0x800000,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_NG_DECT_3              = 0x040000,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_PERMANENT_CLIR         = 0x020000,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_THIRD_PARTY_CONFERENCE = 0x010000,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_INTRUSION_CALL         = 0x008000,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_CALL_DEFLECTION        = 0x004000,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_MULTIPLE_LINES         = 0x002000,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_NO_EMISSION            = 0x001000,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_NG_DECT_5              = 0x000800,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_RE_KEYING              = 0x000020,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_DSAA2                  = 0x000010,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_DSC2                   = 0x000008,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_LIGHT_DATA             = 0x000004,
};

enum dect_mitel_eth_rfpc_extended_capabilities2_dprs_data_category_coding {
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_DPRS_DATA_CATEGORY_NOT_SUPPORTED = 0x0,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_DPRS_DATA_CATEGORY_1             = 0x1,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_DPRS_DATA_CATEGORY_2             = 0x2,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_DPRS_DATA_CATEGORY_3             = 0x3,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_DPRS_DATA_CATEGORY_4             = 0x4,
	DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_DPRS_DATA_CATEGORY_5             = 0x5,
};


/* MAC_CON_IND */
enum dect_mitel_eth_mac_con_ind_flags_coding {
	DECT_MITEL_ETH_MAC_CON_IND_FLAG_HANDOVER = 0x02,
};

/* MAC_DIS_IND */
enum dect_mitel_eth_mac_dis_ind_reason_coding {
	DECT_MITEL_ETH_MAC_DIS_IND_REASON_UNSPECIFIED = 0x01,
	DECT_MITEL_ETH_MAC_DIS_IND_REASON_NORMAL      = 0x02,
	DECT_MITEL_ETH_MAC_DIS_IND_REASON_ABNORMAL    = 0x03,
};

/* MAC_ENC_EKS_IND */
enum dect_mitel_eth_mac_enc_eks_ind_type_coding {
	DECT_MITEL_ETH_MAC_ENC_EKS_IND_TYPE_ENCRYPTED         = 0x01,
	DECT_MITEL_ETH_MAC_ENC_EKS_IND_TYPE_ENCRYPTED_WITH_ID = 0x02,
};

/* MAC_HO_FAILED_IND */
enum dect_mitel_eth_mac_ho_failed_ind_reason_coding {
	DECT_MITEL_ETH_MAC_HO_FAILED_IND_REASON_SETUP_FAILED = 0x01,
};

static const value_string dect_mitel_eth_layer_val[] = {
	{ DECT_MITEL_ETH_LAYER_RFPC, "RFPc" },
	{ DECT_MITEL_ETH_LAYER_LC,   "Lc" },
	{ DECT_MITEL_ETH_LAYER_MAC,  "MAC" },
	{ DECT_MITEL_ETH_LAYER_MT,   "Mt" },
	{ DECT_MITEL_ETH_LAYER_SYNC, "Sync" },
	{ 0, NULL }
};

static const value_string dect_mitel_eth_prim_coding_val[] = {
	{ DECT_MITEL_ETH_MAC_CON_IND,              "MAC_CON_IND" },
	{ DECT_MITEL_ETH_MAC_DIS_REQ,              "MAC_DIS_REQ" },
	{ DECT_MITEL_ETH_MAC_DIS_IND,              "MAC_DIS_IND" },
	{ DECT_MITEL_ETH_LC_DATA_REQ,              "LC_DATA_REQ" },
	{ DECT_MITEL_ETH_LC_DATA_IND,              "LC_DATA_IND" },
	{ DECT_MITEL_ETH_LC_DTR_IND,               "LC_DTR_IND" },
	{ DECT_MITEL_ETH_MAC_PAGE_REQ,             "MAC_PAGE_REQ" },
	{ DECT_MITEL_ETH_MAC_ENC_KEY_REQ,          "MAC_ENC_KEY_REQ" },
	{ DECT_MITEL_ETH_MAC_ENC_EKS_IND,          "MAC_ENC_EKS_IND" },
	{ DECT_MITEL_ETH_MAC_HO_IN_PROGRESS_IND,   "MAC_HO_IN_PROGRESS_IND" },
	{ DECT_MITEL_ETH_MAC_HO_IN_PROGRESS_RES,   "MAC_HO_IN_PROGRESS_RES" },
	{ DECT_MITEL_ETH_MAC_HO_FAILED_IND,        "MAC_HO_FAILED_IND" },
	{ DECT_MITEL_ETH_HO_FAILED_REQ,            "HO_FAILED_REQ" },
	{ DECT_MITEL_ETH_DLC_RFP_ERROR_IND,        "RFP_ERROR_IND" },
	{ DECT_MITEL_ETH_MAC_CON_EXT_IND,          "MAC_CON_EXT_IND" },
	{ DECT_MITEL_ETH_HO_IN_PROGRESS_EXT_IND,   "HO_IN_PROGRESS_EXT_IND" },
	{ DECT_MITEL_ETH_MAC_MOD_REQ,              "MAC_MOD_REQ" },
	{ DECT_MITEL_ETH_MAC_MOD_CNF,              "MAC_MOD_CNF" },
	{ DECT_MITEL_ETH_MAC_MOD_IND,              "MAC_MOD_IND" },
	{ DECT_MITEL_ETH_MAC_MOD_REQ,              "MAC_MOD_REQ" },
	{ DECT_MITEL_ETH_MAC_RECORD_AUDIO,         "MAC_RECORD_AUDIO" },
	{ DECT_MITEL_ETH_MAC_INFO_IND,             "MAC_INFO_IND" },
	{ DECT_MITEL_ETH_MAC_GET_DEF_CKEY_IND,     "MAC_GET_DEF_CKEY_IND" },
	{ DECT_MITEL_ETH_MAC_GET_DEF_CKEY_RES,     "MAC_GET_DEF_CKEY_RES" },
	{ DECT_MITEL_ETH_MAC_CLEAR_DEF_CKEY_REQ,   "MAC_CLEAR_DEF_CKEY_REQ" },
	{ DECT_MITEL_ETH_MAC_GET_CURR_CKEY_ID_REQ, "MAC_GET_CURR_CKEY_ID_REQ"},
	{ DECT_MITEL_ETH_MAC_GET_CURR_CKEY_ID_CNF, "MAC_GET_CURR_CKEY_ID_CNF" },
	{ 0, NULL }
};

static const value_string dect_mitel_eth_subfield_val[] = {
	{ 0x00, "B0" },
	{ 0x10, "B1" },
	{ 0, NULL }
};

/* RFPC */
static const value_string dect_mitel_eth_rfpc_message_type_val[] = {
	{ DECT_MITEL_ETH_RFPC_MESSAGE_TYPE_READY_IND,                            "READY_IND" },
	{ DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_INIT_REQ,                             "INIT_REQ" },
	{ DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_INIT_CFM,                             "INIT_CFM" },
	{ DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_SARI_LIST_REQ,                        "SARI_LIST_REQ" },
	{ DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_CHANGE_HIGHER_LAYER_CAPABILITIES_REQ, "CHANGE_HIGHER_LAYER_CAPABILITIES_REQ" },
	{ DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_CHANGE_HIGHER_LAYER_CAPABILITIES_CFM, "CHANGE_HIGHER_LAYER_CAPABILITIES_CFM" },
	{ DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_CHANGE_STATUS_INFO_REQ,               "CHANGE_STATUS_INFO_REQ" },
	{ DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_CHANGE_STATUS_INFO_CFM,               "CHANGE_STATUS_INFO_CFM" },
	{ DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_ACTIVATE_REQ,                         "ACTIVATE_REQ" },
	{ DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_ACTIVATE_CFM,                         "ACTIVATE_CFM" },
	{ DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_DEACTIVATE_REQ,                       "DEACTIVATE_REQ" },
	{ DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_DEACTIVATE_CFM,                       "DEACTIVATE_CFM" },
	{ DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_RESET_REQ,                            "RESET_REQ" },
	{ DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_STATISTICS_DATA_REQ,                  "STATISTICS_DATA_REQ" },
	{ DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_STATISTICS_DATA_CFM,                  "STATISTICS_DATA_CFM" },
	{ DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_ERROR_IND,                            "ERROR_IND" },
	{ DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_TO_RFP_IND,                           "TO_RFP_IND" },
	{ DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_TO_RFP_REQ,                           "TO_RFP_REQ" },
	{ DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_TOPO_DATA_REQ,                        "TOPO_DATA_REQ" },
	{ DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_TOPO_DATA_IND,                        "TOPO_DATA_IND" },
	{ DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_BMC_RESTART_REQ,                      "BMC_RESTART_REQ" },
	{ DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_CHANGE_MASTER_REQ,                    "CHANGE_MASTER_REQ" },
	{ DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_INFO_IND,                             "INFO_IND" },
	{ DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_ACTIVE_IND,                           "ACTIVE_IND" },
	{ DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_ACTIVE_RES,                           "ACTIVE_RES" },
	{ DECT_MITEL_ETH_RPFC_MESSAGE_TYPE_PAGING_QUEUE_OVERFLOW_IND,            "PAGING_QUEUE_OVERFLOW_IND" },
	{ 0, NULL }
};

static const value_string  dect_mitel_eth_rfpc_item_type_val[] = {
	{ DECT_MITEL_ETH_RFPC_ITEM_TYPE_NUMBER_OF_UPN,             "NUMBER_OF_UPN" },
	{ DECT_MITEL_ETH_RFPC_ITEM_TYPE_REVISION,                  "REVISION" },
	{ DECT_MITEL_ETH_RFPC_ITEM_TYPE_NUMBER_OF_BEARER,          "NUMBER_OF_BEARER" },
	{ DECT_MITEL_ETH_RFPC_ITEM_TYPE_RFPI,                      "RFPI" },
	{ DECT_MITEL_ETH_RFPC_ITEM_TYPE_SARI,                      "SARI" },
	{ DECT_MITEL_ETH_RFPC_ITEM_TYPE_HIGHER_LAYER_CAPABILITIES, "HIGHER_LAYER_CAPABILITIES" },
	{ DECT_MITEL_ETH_RFPC_ITEM_TYPE_EXTENDED_CAPABILITIES,     "EXTENDED_CAPABILITIES" },
	{ DECT_MITEL_ETH_RFPC_ITEM_TYPE_STATUS_INFO,               "STATUS_INFO" },
	{ DECT_MITEL_ETH_RFPC_ITEM_TYPE_MAC_CAPABILITIES,          "MAC_CAPABILITIES" },
	{ DECT_MITEL_ETH_RFPC_ITEM_TYPE_STATISTIC_DATA_RESET,      "STATISTIC_DATA_RESET" },
	{ DECT_MITEL_ETH_RFPC_ITEM_TYPE_STATISTIC_DATA,            "STATISTIC_DATA" },
	{ DECT_MITEL_ETH_RFPC_ITEM_TYPE_ERROR_CAUSE,               "ERROR_CAUSE" },
	{ DECT_MITEL_ETH_RFPC_ITEM_TYPE_RFP_FU6_WINDOW_SIZE,       "RFP_FU6_WINDOW_SIZE" },
	{ DECT_MITEL_ETH_RFPC_ITEM_TYPE_RFP_TO_RFP,                "RFP_TO_RFP" },
	{ DECT_MITEL_ETH_RFPC_ITEM_TYPE_RFP_TOPO,                  "RFP_TOPO" },
	{ DECT_MITEL_ETH_RFPC_ITEM_TYPE_LAST_ERROR,                "LAST_ERROR" },
	{ DECT_MITEL_ETH_RFPC_ITEM_TYPE_PABX_DATA,                 "PABX_DATA" },
	{ DECT_MITEL_ETH_RFPC_ITEM_TYPE_MONI_DATA,                 "MONI_DATA" },
	{ DECT_MITEL_ETH_RFPC_ITEM_TYPE_LAST_ERROR_EXT,            "LAST_ERROR_EXT" },
	{ DECT_MITEL_ETH_RFPC_ITEM_TYPE_FPGA_REVISION,             "FPGA_REVISION" },
	{ DECT_MITEL_ETH_RFPC_ITEM_TYPE_RFP_STRING,                "RFP_STRING" },
	{ DECT_MITEL_ETH_RFPC_ITEM_TYPE_RFP_SITE_LOCATION,         "RFP_SITE_LOCATION" },
	{ DECT_MITEL_ETH_RFPC_ITEM_TYPE_RFP_PLI,                   "RFP_PLI" },
	{ DECT_MITEL_ETH_RFPC_ITEM_TYPE_REFLECTING_ENVIRONMENT,    "REFLECTING_ENVIRONMENT" },
	{ DECT_MITEL_ETH_RFPC_ITEM_TYPE_EXTENDED_CAPABILITIES2,    "EXTENDED_CAPABILITIES2" },
	{ DECT_MITEL_ETH_RFPC_ITEM_TYPE_FREQUENCY_BAND,            "FREQUENCY_BAND" },
	{ DECT_MITEL_ETH_RFPC_ITEM_TYPE_RF_POWER,                  "RF_POWER" },
	{ 0, NULL }
};

/* RFPc RFPI */
static const value_string dect_mitel_eth_rfpc_rfpi_ari_class_val[] = {
	{ DECT_MITEL_ETH_RFPC_RFPI_ARI_CLASS_A, "Class A" },
	{ DECT_MITEL_ETH_RFPC_RFPI_ARI_CLASS_B, "Class B" },
	{ DECT_MITEL_ETH_RFPC_RFPI_ARI_CLASS_C, "Class C" },
	{ DECT_MITEL_ETH_RFPC_RFPI_ARI_CLASS_D, "Class D" },
	{ DECT_MITEL_ETH_RFPC_RFPI_ARI_CLASS_E, "Class E" },
	{ 0, NULL }
};

/* RFPc Extended Capabilities*/
static const true_false_string tfs_prolonged_standard = {
	"Prolonged",
	"Standard"
};

/* RFPc Extended Capabilities 2 */
static const value_string dect_mitel_eth_rfpc_extended_capabilities2_dprs_data_category_val[] = {
	{ DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_DPRS_DATA_CATEGORY_NOT_SUPPORTED, "Not supported" },
	{ DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_DPRS_DATA_CATEGORY_1,             "Cat 1" },
	{ DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_DPRS_DATA_CATEGORY_2,             "Cat 2" },
	{ DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_DPRS_DATA_CATEGORY_3,             "Cat 3" },
	{ DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_DPRS_DATA_CATEGORY_4,             "Cat 4" },
	{ DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_DPRS_DATA_CATEGORY_5,             "Cat 5" },
	{ 0, NULL }
};

/* MAC_DIS_IND */
static const value_string dect_mitel_eth_mac_dis_ind_reason_val[] = {
	{ DECT_MITEL_ETH_MAC_DIS_IND_REASON_UNSPECIFIED, "Unspecified" },
	{ DECT_MITEL_ETH_MAC_DIS_IND_REASON_NORMAL,      "Normal" },
	{ DECT_MITEL_ETH_MAC_DIS_IND_REASON_ABNORMAL,    "Abnormal" },
	{ 0, NULL }
};

/* MAC_ENC_EKS_IND */
static const value_string dect_mitel_eth_mac_enc_eks_ind_type_val[] = {
	{ DECT_MITEL_ETH_MAC_ENC_EKS_IND_TYPE_ENCRYPTED,         "Encrypted" },
	{ DECT_MITEL_ETH_MAC_ENC_EKS_IND_TYPE_ENCRYPTED_WITH_ID, "Encrypted with ID" },
	{ 0, NULL }
};

/* MAC_HO_FAILED_IND */
static const value_string dect_mitel_eth_mac_ho_failed_ind_reason_val[] = {
	{ DECT_MITEL_ETH_MAC_HO_FAILED_IND_REASON_SETUP_FAILED, "Setup failed" },
	{ 0, NULL }
};

static unsigned dissect_dect_mitel_eth_mcei_field(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_, unsigned offset)
{
	uint8_t mcei;
	mcei = tvb_get_uint8(tvb, offset);
	conversation_set_elements_by_id(pinfo, CONVERSATION_NONE, mcei);
	col_append_fstr(pinfo->cinfo, COL_INFO, "MCEI=%02x ", mcei);
	proto_tree_add_item(tree, hf_dect_mitel_eth_mcei, tvb, offset, 1, ENC_NA);
	offset++;

	return offset;
}

/*
RFPc Revision
| Offset | Len | Content       |
| ------ | --- | ------------- |
|      0 |   1 | Generation    |
|      1 |   2 | Boot Software |
|      3 |   2 | Prog Software |
|      5 |   2 | Hardware      |
 */
static unsigned dissect_dect_mitel_eth_rfpc_revision(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_eth_rfpc_revision_generation, tvb, offset, 1, ENC_NA);
	offset++;

	proto_tree_add_item(tree, hf_dect_mitel_eth_rfpc_revision_boot_software, tvb, offset, 2, ENC_NA);
	offset += 2;

	proto_tree_add_item(tree, hf_dect_mitel_eth_rfpc_revision_prog_software, tvb, offset, 2, ENC_NA);
	offset += 2;

	proto_tree_add_item(tree, hf_dect_mitel_eth_rfpc_revision_hardware, tvb, offset, 2, ENC_NA);
	offset += 2;
	return offset;
}

/*
RFPc RFPI
| Offset | Len | Content |
| ------ | --- | ------- |
|      0 |   5 | RFPI    |
See also ETSI EN 300 175-6 Chapter 5
 */
static unsigned dissect_dect_mitel_eth_rfpc_rfpi(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_eth_rfpc_rfpi_saris_available, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_dect_mitel_eth_rfpc_rfpi_ari_class, tvb, offset, 1, ENC_NA);
	offset += 5;

	/* TODO RFPI decoding based on ARI class*/
	return offset;
}

/*
RFPc Higher layer capabilities field
| Offset | Len | Content |
| ------ | --- | ------- |
|      0 |   2 | Flags   |
 */
static unsigned dissect_dect_mitel_eth_rfpc_higher_layer_capabilities(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	static int* const flags[] = {
		&hf_dect_mitel_eth_rfpc_higher_layer_capabilities_connection_handover_supported,
		&hf_dect_mitel_eth_rfpc_higher_layer_capabilities_external_handover_supported,
		&hf_dect_mitel_eth_rfpc_higher_layer_capabilities_access_rights_requests_supported,
		&hf_dect_mitel_eth_rfpc_higher_layer_capabilities_coms_service_available,
		&hf_dect_mitel_eth_rfpc_higher_layer_capabilities_clms_service_available,
		&hf_dect_mitel_eth_rfpc_higher_layer_capabilities_ciss_services_available,
		&hf_dect_mitel_eth_rfpc_higher_layer_capabilities_non_static_fixed_part,
		&hf_dect_mitel_eth_rfpc_higher_layer_capabilities_sim_services_available,
		&hf_dect_mitel_eth_rfpc_higher_layer_capabilities_location_registration_supported,
		&hf_dect_mitel_eth_rfpc_higher_layer_capabilities_dsc_supported,
		&hf_dect_mitel_eth_rfpc_higher_layer_capabilities_dsaa_required,
		&hf_dect_mitel_eth_rfpc_higher_layer_capabilities_non_voice_packet_switched_service,
		&hf_dect_mitel_eth_rfpc_higher_layer_capabilities_non_voice_circuit_switched_service,
		&hf_dect_mitel_eth_rfpc_higher_layer_capabilities_gap_basic_speech,
		&hf_dect_mitel_eth_rfpc_higher_layer_capabilities_g726,
		NULL
	};

	proto_tree_add_bitmask(tree, tvb, offset, hf_dect_mitel_eth_rfpc_higher_layer_capabilities_flags, ett_dect_mitel_eth_higher_layer_capabilities_flags, flags, ENC_NA);
	offset += 2;
	return offset;
}

/*
RFPc Extended capabilities field
| Offset | Len | Content                 | Mask         |
| ------ | --- | ----------------------- | ------------ |
|      0 |   2 | Wireless Relay Stations | 0x0FC0       |
|      1 |   4 | Flags                   | 0x3FFFFFFFFF |
 */
static unsigned dissect_dect_mitel_eth_rfpc_extended_capabilities(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	static int* const flags[] = {
		&hf_dect_mitel_eth_rfpc_extended_capabilities_isdn_data_services,
		&hf_dect_mitel_eth_rfpc_extended_capabilities_dprs_class_2,
		&hf_dect_mitel_eth_rfpc_extended_capabilities_dprs_class_3_or_4,
		&hf_dect_mitel_eth_rfpc_extended_capabilities_data_service_profile_d,
		&hf_dect_mitel_eth_rfpc_extended_capabilities_lrms,
		&hf_dect_mitel_eth_rfpc_extended_capabilities_asymmetric_bearers_supported,
		&hf_dect_mitel_eth_rfpc_extended_capabilities_emergency_call_supported,
		&hf_dect_mitel_eth_rfpc_extended_capabilities_location_registration_with_tpui_allowed,
		&hf_dect_mitel_eth_rfpc_extended_capabilities_sync_to_gps_achieved,
		&hf_dect_mitel_eth_rfpc_extended_capabilities_isdn_intermediate_system,
		&hf_dect_mitel_eth_rfpc_extended_capabilities_rap_part_1_profile,
		&hf_dect_mitel_eth_rfpc_extended_capabilities_v24,
		&hf_dect_mitel_eth_rfpc_extended_capabilities_ppp,
		&hf_dect_mitel_eth_rfpc_extended_capabilities_ip,
		&hf_dect_mitel_eth_rfpc_extended_capabilities_token_ring,
		&hf_dect_mitel_eth_rfpc_extended_capabilities_ethernet,
		&hf_dect_mitel_eth_rfpc_extended_capabilities_ip_roaming_unrestricted_supported,
		&hf_dect_mitel_eth_rfpc_extended_capabilities_dprs_supported,
		&hf_dect_mitel_eth_rfpc_extended_capabilities_basis_odap_supported,
		&hf_dect_mitel_eth_rfpc_extended_capabilities_fmms_interworking_profile_supported,
		&hf_dect_mitel_eth_rfpc_extended_capabilities_extended_fp_info2,
		&hf_dect_mitel_eth_rfpc_extended_capabilities_ipq_services_supported,
		&hf_dect_mitel_eth_rfpc_extended_capabilities_mac_suspend_resume,
		&hf_dect_mitel_eth_rfpc_extended_capabilities_frequency_replacement_supported,
		&hf_dect_mitel_eth_rfpc_extended_capabilities_syncronization,
		NULL
	};

	proto_tree_add_item(tree, hf_dect_mitel_eth_rfpc_extended_capabilities_wireless_relay_stations, tvb, offset, 2, ENC_NA);
	offset++;
	proto_tree_add_bitmask(tree, tvb, offset, hf_dect_mitel_eth_rfpc_extended_capabilities_flags, ett_dect_mitel_eth_extended_capabilities_flags, flags, ENC_NA);

	offset += 4;
	return offset;
}

/*
RFPc MAC capabilities field
| Offset | Len | Content              | Mask     |
| ------ | --- | -------------------- | -------- |
|      0 |   3 | MAC capability flags | 0x0FFFFF |
 */
static unsigned dissect_dect_mitel_eth_rfpc_mac_capabilities(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	static int* const flags[] = {
		&hf_dect_mitel_eth_rfpc_mac_capabilities_multibearer_connections,
		&hf_dect_mitel_eth_rfpc_mac_capabilities_ipmr_error_correction,
		&hf_dect_mitel_eth_rfpc_mac_capabilities_ipm_error_detection,
		&hf_dect_mitel_eth_rfpc_mac_capabilities_inb_normal_delay,
		&hf_dect_mitel_eth_rfpc_mac_capabilities_ina_minimum_delay,
		&hf_dect_mitel_eth_rfpc_mac_capabilities_cf_messages,
		&hf_dect_mitel_eth_rfpc_mac_capabilities_b_field_setup,
		&hf_dect_mitel_eth_rfpc_mac_capabilities_advanced_a_field_setup,
		&hf_dect_mitel_eth_rfpc_mac_capabilities_basic_a_field_setup,
		&hf_dect_mitel_eth_rfpc_mac_capabilities_cl_downlink,
		&hf_dect_mitel_eth_rfpc_mac_capabilities_cl_uplink,
		&hf_dect_mitel_eth_rfpc_mac_capabilities_co_setup_on_dummy_allowed,
		&hf_dect_mitel_eth_rfpc_mac_capabilities_page_repetition,
		&hf_dect_mitel_eth_rfpc_mac_capabilities_frequency_control,
		&hf_dect_mitel_eth_rfpc_mac_capabilities_slot_size_full,
		&hf_dect_mitel_eth_rfpc_mac_capabilities_slot_size_half,
		&hf_dect_mitel_eth_rfpc_mac_capabilities_slot_size_double,
		&hf_dect_mitel_eth_rfpc_mac_capabilities_double_duplex_bearer_connections,
		&hf_dect_mitel_eth_rfpc_mac_capabilities_extended_fp_info,
		NULL
	};

	proto_tree_add_bitmask(tree, tvb, offset, hf_dect_mitel_eth_rfpc_mac_capabilities_flags, ett_dect_mitel_eth_mac_capabilities_flags, flags, ENC_NA);

	offset += 3;
	return offset;
}

/*
RFPc Statistics data
| Offset | Len | Content               |
| ------ | --- | --------------------- |
|      0 |   2 | BMC connections 1-3   |
|      2 |   2 | BMC connections 4-6   |
|      4 |   2 | BMC connections 7-9   |
|      6 |   2 | BMC connections 10-12 |
|      8 |   2 | BMC DSP channels 1+2  |
|     10 |   2 | BMC DSP channels 3+4  |
|     12 |   2 | BMC DSP channels 5+6  |
|     14 |   2 | BMC DSP channels 7+8  |
|     16 |   2 | Lost connections      |
|     34 |   2 | MAC reset             |
|     40 |   2 | Reject dummy          |
|     42 |   4 | Bad frames            |
|     46 |   4 | Good frames           |
|     50 |   2 | Handoff timer         |
 */
static unsigned dissect_dect_mitel_eth_rfpc_statistic_data(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_eth_rfpc_statistic_data_bmc_connections_1_3, tvb, offset, 2, ENC_NA);
	offset += 2;

	proto_tree_add_item(tree, hf_dect_mitel_eth_rfpc_statistic_data_bmc_connections_4_6, tvb, offset, 2, ENC_NA);
	offset += 2;

	proto_tree_add_item(tree, hf_dect_mitel_eth_rfpc_statistic_data_bmc_connections_7_9, tvb, offset, 2, ENC_NA);
	offset += 2;

	proto_tree_add_item(tree, hf_dect_mitel_eth_rfpc_statistic_data_bmc_connections_10_12, tvb, offset, 2, ENC_NA);
	offset += 2;

	proto_tree_add_item(tree, hf_dect_mitel_eth_rfpc_statistic_data_bmc_dsp_channels_1_2, tvb, offset, 2, ENC_NA);
	offset += 2;

	proto_tree_add_item(tree, hf_dect_mitel_eth_rfpc_statistic_data_bmc_dsp_channels_3_4, tvb, offset, 2, ENC_NA);
	offset += 2;

	proto_tree_add_item(tree, hf_dect_mitel_eth_rfpc_statistic_data_bmc_dsp_channels_5_6, tvb, offset, 2, ENC_NA);
	offset += 2;

	proto_tree_add_item(tree, hf_dect_mitel_eth_rfpc_statistic_data_bmc_dsp_channels_7_8, tvb, offset, 2, ENC_NA);
	offset += 2;

	proto_tree_add_item(tree, hf_dect_mitel_eth_rfpc_statistic_data_lost_connections, tvb, offset, 2, ENC_NA);
	offset += 18;

	proto_tree_add_item(tree, hf_dect_mitel_eth_rfpc_statistic_data_mac_reset, tvb, offset, 2, ENC_NA);
	offset += 6;

	proto_tree_add_item(tree, hf_dect_mitel_eth_rfpc_statistic_data_reject_dummy, tvb, offset, 2, ENC_NA);
	offset += 2;

	proto_tree_add_item(tree, hf_dect_mitel_eth_rfpc_statistic_data_bad_frames, tvb, offset, 4, ENC_NA);
	offset += 4;

	proto_tree_add_item(tree, hf_dect_mitel_eth_rfpc_statistic_data_good_frames, tvb, offset, 4, ENC_NA);
	offset += 4;

	proto_tree_add_item(tree, hf_dect_mitel_eth_rfpc_statistic_data_handoff_timer, tvb, offset, 2, ENC_NA);
	offset += 2;

	return offset;
}

/*
RFPc RFP_PLI
| Offset | Len | Content               |
| ------ | --- | --------------------- |
|      0 |   1 | PARK length indicator |
 */
static unsigned dissect_dect_mitel_eth_rfpc_rfp_pli(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_eth_rfpc_rfp_pli_length_indicator, tvb, offset, 1, ENC_NA);
	offset ++;

	return offset;
}

/*
RFPc Extended capabilities2 field
| Offset | Len | Content                 | Mask         |
| ------ | --- | ----------------------- | ------------ |
|      0 |   2 | MAC capability flags    | 0x0FFF       |
|      2 |   3 | Capability information  | 0xFFFFFF     |
 */
static unsigned dissect_dect_mitel_eth_rfpc_extended_capabilities2(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	static int* const mac_capability_flags[] = {
		&hf_dect_mitel_eth_rfpc_extended_capabilities2_mac_capability_slot_type_long_640,
		&hf_dect_mitel_eth_rfpc_extended_capabilities2_mac_capability_slot_type_long_672,
		&hf_dect_mitel_eth_rfpc_extended_capabilities2_mac_capability_mux_e_u,
		&hf_dect_mitel_eth_rfpc_extended_capabilities2_mac_capability_channel_ipf,
		&hf_dect_mitel_eth_rfpc_extended_capabilities2_mac_capability_channel_sipf,
		&hf_dect_mitel_eth_rfpc_extended_capabilities2_mac_capability_channel_gf,
		&hf_dect_mitel_eth_rfpc_extended_capabilities2_mac_capability_wrs_ule,
		&hf_dect_mitel_eth_rfpc_extended_capabilities2_mac_capability_no_emission_preferred_cn,
		NULL
	};

	static int* const capability_flags[] = {
		&hf_dect_mitel_eth_rfpc_extended_capabilities2_ng_dect_1,
		&hf_dect_mitel_eth_rfpc_extended_capabilities2_dprs_data_category,
		&hf_dect_mitel_eth_rfpc_extended_capabilities2_ng_dect_3,
		&hf_dect_mitel_eth_rfpc_extended_capabilities2_permanent_clir,
		&hf_dect_mitel_eth_rfpc_extended_capabilities2_third_party_conference,
		&hf_dect_mitel_eth_rfpc_extended_capabilities2_intrusion_call,
		&hf_dect_mitel_eth_rfpc_extended_capabilities2_call_deflection,
		&hf_dect_mitel_eth_rfpc_extended_capabilities2_multiple_lines,
		&hf_dect_mitel_eth_rfpc_extended_capabilities2_no_emission,
		&hf_dect_mitel_eth_rfpc_extended_capabilities2_ng_dect_5,
		&hf_dect_mitel_eth_rfpc_extended_capabilities2_re_keying,
		&hf_dect_mitel_eth_rfpc_extended_capabilities2_dsaa2,
		&hf_dect_mitel_eth_rfpc_extended_capabilities2_dsc2,
		&hf_dect_mitel_eth_rfpc_extended_capabilities2_light_data,
		NULL
	};

	proto_tree_add_bitmask(tree, tvb, offset, hf_dect_mitel_eth_rfpc_extended_capabilities2_mac_capability_flags, ett_dect_mitel_eth_extended_capabilities2_mac_capability_flags, mac_capability_flags, ENC_NA);
	offset += 2;

	proto_tree_add_bitmask(tree, tvb, offset, hf_dect_mitel_eth_rfpc_extended_capabilities2_flags, ett_dect_mitel_eth_extended_capabilities2_flags, capability_flags, ENC_NA);
	offset += 3;
	return offset;
}

/*
RFPc Message
| Offset  | Len | Content           |
| ------- | --- | ----------------- |
|       0 |   1 | RFPc Message Type |
|       1 |   1 | Element0 key      |
|       2 |   1 | Element0 length   |
|       3 | len | Element0 content  |
|   3+len |   1 | Element1 key      |
| 3+len+1 |   1 | Element1 length   |
| 3+len+2 | len | Element1 content  |
| ...     | ... | ...               |

 */
static unsigned dissect_dect_mitel_eth_rfpc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	uint8_t message_type, item_type, item_length;
	proto_tree *rfpc_item_tree;
	proto_item *rfpc_item_tree_item;

	proto_tree_add_item(tree, hf_dect_mitel_eth_rfpc_message_type, tvb, offset, 1, ENC_NA);
	message_type = tvb_get_uint8(tvb, offset);
	col_append_fstr(pinfo->cinfo, COL_INFO, "RFPc: %s ",
				val_to_str(message_type, dect_mitel_eth_rfpc_message_type_val, "Unknown 0x%02x"));
	offset++;

	while ( tvb_reported_length_remaining(tvb, offset) ) {
		item_type = tvb_get_uint8(tvb, offset);
		rfpc_item_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_dect_mitel_eth_rfpc_item, &rfpc_item_tree_item,
			"Item: %s", val_to_str(item_type, dect_mitel_eth_rfpc_item_type_val, "Unknown: 0x%0x"));
		proto_tree_add_item(rfpc_item_tree, hf_dect_mitel_eth_rfpc_item_type, tvb, offset, 1, ENC_NA);
		offset++;

		item_length = tvb_get_uint8(tvb, offset);
		proto_tree_add_item(rfpc_item_tree, hf_dect_mitel_eth_rfpc_item_length, tvb, offset, 1, ENC_NA);
		proto_item_set_len(rfpc_item_tree_item, item_length + 2);
		offset ++;

		switch (item_type) {
			case DECT_MITEL_ETH_RFPC_ITEM_TYPE_REVISION:
				offset = dissect_dect_mitel_eth_rfpc_revision(tvb, pinfo, rfpc_item_tree, data, offset);
				break;
			case DECT_MITEL_ETH_RFPC_ITEM_TYPE_RFPI:
				offset = dissect_dect_mitel_eth_rfpc_rfpi(tvb, pinfo, rfpc_item_tree, data, offset);
				break;
			case DECT_MITEL_ETH_RFPC_ITEM_TYPE_HIGHER_LAYER_CAPABILITIES:
				offset = dissect_dect_mitel_eth_rfpc_higher_layer_capabilities(tvb, pinfo, rfpc_item_tree, data, offset);
				break;
			case DECT_MITEL_ETH_RFPC_ITEM_TYPE_EXTENDED_CAPABILITIES:
				offset = dissect_dect_mitel_eth_rfpc_extended_capabilities(tvb, pinfo, rfpc_item_tree, data, offset);
				break;
			case DECT_MITEL_ETH_RFPC_ITEM_TYPE_MAC_CAPABILITIES:
				offset = dissect_dect_mitel_eth_rfpc_mac_capabilities(tvb, pinfo, rfpc_item_tree, data, offset);
				break;
			case DECT_MITEL_ETH_RFPC_ITEM_TYPE_STATISTIC_DATA:
				offset = dissect_dect_mitel_eth_rfpc_statistic_data(tvb, pinfo, rfpc_item_tree, data, offset);
				break;
			case DECT_MITEL_ETH_RFPC_ITEM_TYPE_RFP_PLI:
				offset = dissect_dect_mitel_eth_rfpc_rfp_pli(tvb, pinfo, rfpc_item_tree, data, offset);
				break;
			case DECT_MITEL_ETH_RFPC_ITEM_TYPE_EXTENDED_CAPABILITIES2:
				offset = dissect_dect_mitel_eth_rfpc_extended_capabilities2(tvb, pinfo, rfpc_item_tree, data, offset);
				break;
			default:
				proto_tree_add_item(rfpc_item_tree, hf_dect_mitel_eth_rfpc_item_value, tvb, offset, item_length, ENC_NA);
				offset += item_length;
				break;
		}
	}
	return offset;
}

/*
MAC_CON_IND Message
| Offset | Len | Content               |
| ------ | --- | --------------------- |
|      0 |   1 | MCEI                  |
|      1 |   3 | PMID (in last 20bits) |
|      4 |   1 | Flags                 |
*/
static unsigned dissect_dect_mitel_eth_mac_con_ind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, unsigned offset)
{
	static int *const mac_con_ind_flags[] = {
		&hf_dect_mitel_eth_mac_con_ind_flag_handover,
		NULL
	};

	pinfo->p2p_dir = P2P_DIR_RECV;
	offset = dissect_dect_mitel_eth_mcei_field(tvb, pinfo, tree, data, offset);

	proto_tree_add_item(tree, hf_dect_mitel_eth_pmid, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset+=3;
	proto_tree_add_bitmask(tree, tvb, offset, hf_dect_mitel_eth_mac_con_ind_flags, ett_dect_mitel_eth, mac_con_ind_flags, ENC_NA);
	offset++;
	return offset;
}

/*
MAC_DIS_IND Message
| Offset | Len | Content |
| ------ | --- | ------- |
|      0 |   1 | MCEI    |
|      1 |   1 | Reason  |
*/
static unsigned dissect_dect_mitel_eth_mac_dis_ind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, unsigned offset)
{
	offset = dissect_dect_mitel_eth_mcei_field(tvb, pinfo, tree, data, offset);

	proto_tree_add_item(tree, hf_dect_mitel_eth_mac_dis_ind_reason, tvb, offset, 1, ENC_NA);

	return offset;
}

/*
MAC_PAGE_REQ Message
| Offset | Len | Content         |
| ------ | --- | --------------- |
|      1 |   1 | Flags (unknown) |
 */
static unsigned dissect_dect_mitel_eth_mac_page_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	pinfo->p2p_dir = P2P_DIR_SENT;
	offset++;
	proto_tree_add_item(tree, hf_dect_mitel_eth_mac_page_req_flags, tvb, offset, 1, ENC_NA);
	offset += 3;
	return offset;
}

/*
MAC_ENC_KEY_REQ Message
| Offset | Len | Content   |
| ------ | --- | --------- |
|      0 |   1 | MCEI      |
|      1 |   8 | Key       |
|      9 |   1 | (Key?) ID |
 */
static unsigned dissect_dect_mitel_eth_mac_enc_key_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, unsigned offset)
{
	offset = dissect_dect_mitel_eth_mcei_field(tvb, pinfo, tree, data, offset);

	proto_tree_add_item(tree, hf_dect_mitel_eth_mac_enc_key_req_key, tvb, offset, 8, ENC_NA);
	offset += 8;
	proto_tree_add_item(tree, hf_dect_mitel_eth_mac_enc_key_req_id, tvb, offset, 1, ENC_NA);
	offset++;
	return offset;
}

/*
MAC_ENC_EKS_IND Message
| Offset | Len | Content   | Comment            |
| ------ | --- | --------- | ------------------ |
|      0 |   1 | MCEI      |                    |
|      1 |   1 | Type      |                    |
|      2 |   1 | (Key?) ID | if Type == with ID |
|      3 |   2 | PPN       | if Type == with ID |
 */
static unsigned dissect_dect_mitel_eth_mac_enc_eks_ind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, unsigned offset)
{
	uint8_t type;
	offset = dissect_dect_mitel_eth_mcei_field(tvb, pinfo, tree, data, offset);

	proto_tree_add_item(tree, hf_dect_mitel_eth_mac_enc_eks_ind_type, tvb, offset, 1, ENC_NA);
	type = tvb_get_uint8(tvb, offset);
	offset++;
	if ( type == DECT_MITEL_ETH_MAC_ENC_EKS_IND_TYPE_ENCRYPTED_WITH_ID ) {
		proto_tree_add_item(tree, hf_dect_mitel_eth_mac_enc_eks_ind_id, tvb, offset, 1, ENC_NA);
		offset++;
		proto_tree_add_item(tree, hf_dect_mitel_eth_mac_enc_eks_ind_ppn, tvb, offset, 2, ENC_NA);
		offset += 2;
	}
	return offset;
}

/*
DECT_MITEL_ETH_MAC_HO_IN_PROGRESS_IND Message
| Offset | Len | Content               |
| ------ | --- | --------------------- |
|      0 |   1 | MCEI                  |
|      1 |   3 | PMID (in last 20bits) |
 */
static unsigned dissect_dect_mitel_eth_mac_ho_in_progress_ind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, unsigned offset)
{
	offset = dissect_dect_mitel_eth_mcei_field(tvb, pinfo, tree, data, offset);

	proto_tree_add_item(tree, hf_dect_mitel_eth_pmid, tvb, offset, 3, ENC_NA);
	offset += 3;
	return offset;
}

/*
DECT_MITEL_ETH_MAC_HO_IN_PROGRESS_RES Message
| Offset | Len | Content   |
| ------ | --- | --------- |
|      0 |   1 | MCEI      |
|      2 |   8 | Key       |
|     11 |   1 | (Key?) ID |
 */
static unsigned dissect_dect_mitel_eth_mac_ho_in_progress_res(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, unsigned offset)
{
	offset = dissect_dect_mitel_eth_mcei_field(tvb, pinfo, tree, data, offset);

	offset++;

	proto_tree_add_item(tree, hf_dect_mitel_eth_mac_ho_in_progress_res_key, tvb, offset, 8, ENC_NA);
	offset += 9;

	proto_tree_add_item(tree, hf_dect_mitel_eth_mac_ho_in_progress_res_id, tvb, offset, 1, ENC_NA);
	offset++;
	return offset;
}

/*
MAC_HO_FAILED_IND Message
| Offset | Len | Content |
| ------ | --- | ------- |
|      0 |   1 | MCEI    |
|      1 |   1 | Reason  |
 */
static unsigned dissect_dect_mitel_eth_mac_ho_failed_ind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, unsigned offset)
{
	offset = dissect_dect_mitel_eth_mcei_field(tvb, pinfo, tree, data, offset);

	proto_tree_add_item(tree, hf_dect_mitel_eth_mac_ho_failed_ind_reason, tvb, offset, 1, ENC_NA);
	offset++;
	return offset;
}

/*
MAC_INFO_IND Message
| Offset | Len | Content               |
| ------ | --- | --------------------- |
|      0 |   1 | MCEI                  |
|      1 |   3 | PMID (in last 20bits) |
|      5 |     | String                |
*/
static unsigned dissect_dect_mitel_eth_mac_info_ind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, unsigned offset)
{
	pinfo->p2p_dir = P2P_DIR_RECV;
	offset = dissect_dect_mitel_eth_mcei_field(tvb, pinfo, tree, data, offset);

	proto_tree_add_item(tree, hf_dect_mitel_eth_pmid, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset+=4;

	proto_tree_add_item(tree, hf_dect_mitel_eth_mac_info_ind_string, tvb, offset,
				tvb_captured_length_remaining(tvb, offset+9), ENC_ASCII|ENC_NA);
	return offset;
}

/*
MAC_CLEAR_DEF_CKEY_REQ Message
| Offset | Len | Content               |
| ------ | --- | --------------------- |
|      0 |   3 | PMID (in last 20bits) |
*/
static unsigned dissect_dect_mitel_eth_mac_clear_def_ckey_req(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_, unsigned offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_eth_pmid, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset+=3;
	return offset;
}

static int dissect_dect_mitel_eth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	proto_item *dect_mitel_eth_tree_item;
	proto_tree *dect_mitel_eth_tree;

	uint16_t mitel_eth_len, payload_len;
	uint8_t prim_type, layer, mt_item_length;
	int offset = 0;
	bool ip_encapsulated;
	tvbuff_t *payload_tvb = NULL;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MI-DECToE");
	col_clear(pinfo->cinfo, COL_INFO);

	dect_mitel_eth_tree_item = proto_tree_add_item(tree, proto_dect_mitel_eth, tvb, 0, -1, ENC_NA);
	dect_mitel_eth_tree = proto_item_add_subtree(dect_mitel_eth_tree_item, ett_dect_mitel_eth);
	/*
	 * When the protocol is used within the internal Ethernet channel in the RFP there is a two byte
	 * field with not yet really known content and a two byte length field. This is not in place / consumed
	 * by the upper layer dissector if this protocol is used in OMM<>RFP communication. So the data parameter
	 * is used to get information from the dect-mitel-rfp dissector whether it was IP encapsulated or not.
	 */
	if(data) {
		ip_encapsulated = *( ( bool* )data );
	} else {
		ip_encapsulated = false;
	}
	if(!ip_encapsulated) {
		mitel_eth_len = tvb_get_uint16(tvb, offset, 2);
		proto_tree_add_item(dect_mitel_eth_tree, hf_dect_mitel_eth_len, tvb, offset, 2, ENC_BIG_ENDIAN);
		if (mitel_eth_len < 3)
			return tvb_captured_length(tvb);
		offset += 4;
	}

	proto_tree_add_item(dect_mitel_eth_tree, hf_dect_mitel_eth_layer, tvb, offset, 1, ENC_NA);
	layer = tvb_get_uint8(tvb, offset);
	offset++;

	if ( layer != DECT_MITEL_ETH_LAYER_RFPC) {
		prim_type = tvb_get_uint8(tvb, offset);
		proto_tree_add_item(dect_mitel_eth_tree, hf_dect_mitel_eth_prim_type, tvb, offset, 1, ENC_NA);

		col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
				val_to_str(prim_type, dect_mitel_eth_prim_coding_val, "Unknown 0x%02x"));
		offset++;
	}

	switch (layer) {
		case DECT_MITEL_ETH_LAYER_RFPC:
			dissect_dect_mitel_eth_rfpc(tvb, pinfo, dect_mitel_eth_tree, data, offset);
			break;
		case DECT_MITEL_ETH_LAYER_MT:
			while ( tvb_reported_length_remaining(tvb, offset) ) {
				proto_tree_add_item(dect_mitel_eth_tree, hf_dect_mitel_eth_mt_item_key, tvb, offset, 1, ENC_NA);
				offset++;
				proto_tree_add_item(dect_mitel_eth_tree, hf_dect_mitel_eth_mt_item_length, tvb, offset, 1, ENC_NA);
				mt_item_length = tvb_get_uint8(tvb, offset);
				offset++;
				proto_tree_add_item(dect_mitel_eth_tree, hf_dect_mitel_eth_mt_item_value, tvb, offset, mt_item_length, ENC_NA);
				offset += mt_item_length;
			}
			break;
		case DECT_MITEL_ETH_LAYER_LC:
		case DECT_MITEL_ETH_LAYER_MAC:
			switch (prim_type) {
				case DECT_MITEL_ETH_MAC_PAGE_REQ:
					dissect_dect_mitel_eth_mac_page_req(tvb, pinfo, dect_mitel_eth_tree, data, offset);
					break;
				case DECT_MITEL_ETH_MAC_ENC_KEY_REQ:
					dissect_dect_mitel_eth_mac_enc_key_req(tvb, pinfo, dect_mitel_eth_tree, data, offset);
					break;
				case DECT_MITEL_ETH_MAC_ENC_EKS_IND:
					dissect_dect_mitel_eth_mac_enc_eks_ind(tvb, pinfo, dect_mitel_eth_tree, data, offset);
					break;
				case DECT_MITEL_ETH_MAC_HO_IN_PROGRESS_IND:
					dissect_dect_mitel_eth_mac_ho_in_progress_ind(tvb, pinfo, dect_mitel_eth_tree, data, offset);
					break;
				case DECT_MITEL_ETH_MAC_HO_IN_PROGRESS_RES:
					dissect_dect_mitel_eth_mac_ho_in_progress_res(tvb, pinfo, dect_mitel_eth_tree, data, offset);
					break;
				case DECT_MITEL_ETH_MAC_HO_FAILED_IND:
					dissect_dect_mitel_eth_mac_ho_failed_ind(tvb, pinfo, dect_mitel_eth_tree, data, offset);
					break;
				case DECT_MITEL_ETH_MAC_CON_IND:
					dissect_dect_mitel_eth_mac_con_ind(tvb, pinfo, dect_mitel_eth_tree, data, offset);
					break;
				case DECT_MITEL_ETH_MAC_INFO_IND:
					dissect_dect_mitel_eth_mac_info_ind(tvb, pinfo, dect_mitel_eth_tree, data, offset);
					break;
				case DECT_MITEL_ETH_MAC_CLEAR_DEF_CKEY_REQ:
					dissect_dect_mitel_eth_mac_clear_def_ckey_req(tvb, pinfo, dect_mitel_eth_tree, data, offset);
					break;
				case DECT_MITEL_ETH_MAC_DIS_REQ:
					pinfo->p2p_dir = P2P_DIR_SENT;
					dissect_dect_mitel_eth_mcei_field(tvb, pinfo, dect_mitel_eth_tree, data, offset);
					break;
				case DECT_MITEL_ETH_MAC_DIS_IND:
					dissect_dect_mitel_eth_mac_dis_ind(tvb, pinfo, dect_mitel_eth_tree, data, offset);
					break;
				case DECT_MITEL_ETH_LC_DTR_IND:
					pinfo->p2p_dir = P2P_DIR_RECV;
					offset = dissect_dect_mitel_eth_mcei_field(tvb, pinfo, dect_mitel_eth_tree, data, offset);

					proto_tree_add_item(dect_mitel_eth_tree, hf_dect_mitel_eth_subfield, tvb, offset, 1, ENC_NA);
					break;
				case DECT_MITEL_ETH_LC_DATA_REQ:
				case DECT_MITEL_ETH_LC_DATA_IND:
					if(prim_type == DECT_MITEL_ETH_LC_DATA_REQ) {
						pinfo->p2p_dir = P2P_DIR_SENT;
					} else {
						pinfo->p2p_dir = P2P_DIR_RECV;
					}
					offset = dissect_dect_mitel_eth_mcei_field(tvb, pinfo, dect_mitel_eth_tree, data, offset);

					proto_tree_add_item(dect_mitel_eth_tree, hf_dect_mitel_eth_subfield, tvb, offset, 1, ENC_NA);
					offset++;
					payload_len = tvb_get_uint8(tvb, offset);
					offset++;
					payload_tvb = tvb_new_subset_length(tvb, offset, payload_len);
					if (payload_tvb)
						call_dissector(dlc_handle, payload_tvb, pinfo, tree);
					payload_tvb = NULL;
					break;
				default:
					break;
			}
			break;
	}

	return tvb_captured_length(tvb);
}

void proto_register_dect_mitel_eth(void)
{

	static hf_register_info hf[] =
	{
		{ &hf_dect_mitel_eth_len,
			{ "Length", "dect_mitel_eth.length", FT_UINT16, BASE_DEC,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_layer,
			{ "Interface layer", "dect_mitel_eth.layer", FT_UINT8, BASE_HEX,
				 VALS(dect_mitel_eth_layer_val), 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_prim_type,
			{ "Primitive Type", "dect_mitel_eth.prim", FT_UINT8, BASE_HEX,
				 VALS(dect_mitel_eth_prim_coding_val), 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_mcei,
			{ "MCEI", "dect_mitel_eth.mcei", FT_UINT8, BASE_HEX,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_mac_info_ind_string,
			{ "MAC Info String", "dect_mitel_eth.mac_info_str", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_pmid,
			{ "PMID", "dect_mitel_eth.pmid", FT_UINT24, BASE_HEX,
				NULL, 0x0FFFFF, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_subfield,
			{ "Subfield", "dect_mitel_eth.subfield", FT_UINT8, BASE_HEX,
				VALS(dect_mitel_eth_subfield_val), 0, NULL, HFILL
			}
		},
		/* RFPc Message */
		{ &hf_dect_mitel_eth_rfpc_message_type,
			{ "Message Type", "dect_mitel_eth.rfpc.message_type", FT_UINT8, BASE_HEX,
				VALS(dect_mitel_eth_rfpc_message_type_val), 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_item_type,
			{ "Type", "dect_mitel_eth.rfpc.item.type", FT_UINT8, BASE_HEX,
				VALS(dect_mitel_eth_rfpc_item_type_val), 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_item_length,
			{ "Length", "dect_mitel_eth.rfpc.item.length", FT_UINT8, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_item_value,
			{ "Value", "dect_mitel_eth.rfpc.item.value", FT_BYTES, BASE_NONE,
				NULL, 0, NULL, HFILL
			}
		},
		/* RFPc Revision */
		{ &hf_dect_mitel_eth_rfpc_revision_generation,
			{ "Generation", "dect_mitel_eth.rfpc.revision.generation", FT_UINT8, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_revision_boot_software,
			{ "Boot Software", "dect_mitel_eth.rfpc.revision.boot_software", FT_UINT16, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_revision_prog_software,
			{ "Prog Software", "dect_mitel_eth.rfpc.revision.prog_software", FT_UINT16, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_revision_hardware,
			{ "Hardware", "dect_mitel_eth.rfpc.revision.hardware", FT_UINT16, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		/* RFPc RFPI */
		{ &hf_dect_mitel_eth_rfpc_rfpi_saris_available,
			{ "SARIs available", "dect_mitel_eth.rfpc.rfpi.e", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_RFPI_SARIS_AVAILABLE, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_rfpi_ari_class,
			{ "ARI class", "dect_mitel_eth.rfpc.rfpi.ari_class", FT_UINT8, BASE_HEX,
				VALS(dect_mitel_eth_rfpc_rfpi_ari_class_val), 0x70, NULL, HFILL
			}
		},
		/* RFPc Higher layer capabilities */
		{ &hf_dect_mitel_eth_rfpc_higher_layer_capabilities_flags,
			{ "MAC capability flags", "dect_mitel_eth.rfpc.higher_layer_capabilities.flags", FT_UINT16, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_higher_layer_capabilities_connection_handover_supported,
			{ "Connection handover supported", "dect_mitel_eth.rfpc.higher_layer_capabilities.connect_handover_supported", FT_BOOLEAN, 16,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_CONNECTION_HANDOVER_SUPPORTED, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_higher_layer_capabilities_external_handover_supported,
			{ "External handover supported", "dect_mitel_eth.rfpc.higher_layer_capabilities.external_handover_supported", FT_BOOLEAN, 16,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_EXTERNAL_HANDOVER_SUPPORTED, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_higher_layer_capabilities_access_rights_requests_supported,
			{ "Access rights requests supported", "dect_mitel_eth.rfpc.higher_layer_capabilities.access_rights_requests_supported", FT_BOOLEAN, 16,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_ACCESS_RIGHTS_REQUESTS_SUPPORTED, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_higher_layer_capabilities_coms_service_available,
			{ "COMS service available", "dect_mitel_eth.rfpc.higher_layer_capabilities.coms_service_available", FT_BOOLEAN, 16,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_COMS_SERVICE_AVAILABLE, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_higher_layer_capabilities_clms_service_available,
			{ "CLMS service available", "dect_mitel_eth.rfpc.higher_layer_capabilities.clms_service_available", FT_BOOLEAN, 16,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_CLMS_SERVICE_AVAILABLE, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_higher_layer_capabilities_ciss_services_available,
			{ "CISS service available", "dect_mitel_eth.rfpc.higher_layer_capabilities.ciss_service_available", FT_BOOLEAN, 16,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_CISS_SERVICES_AVAILABLE, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_higher_layer_capabilities_non_static_fixed_part,
			{ "Non-static fixed part", "dect_mitel_eth.rfpc.higher_layer_capabilities.non_static_fixed_part", FT_BOOLEAN, 16,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_NON_STATIC_FIXED_PART, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_higher_layer_capabilities_sim_services_available,
			{ "SIM services available", "dect_mitel_eth.rfpc.higher_layer_capabilities.sim_services_available", FT_BOOLEAN, 16,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_SIM_SERVICES_AVAILABLE, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_higher_layer_capabilities_location_registration_supported,
			{ "Location registration supported", "dect_mitel_eth.rfpc.higher_layer_capabilities.location_registration_supported", FT_BOOLEAN, 16,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_LOCATION_REGISTRATION_SUPPORTED, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_higher_layer_capabilities_dsc_supported,
			{ "DSC supported", "dect_mitel_eth.rfpc.higher_layer_capabilities.dsc_supported", FT_BOOLEAN, 16,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_DSC_SUPPORTED, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_higher_layer_capabilities_dsaa_required,
			{ "DSAA required", "dect_mitel_eth.rfpc.higher_layer_capabilities.dsaa_required", FT_BOOLEAN, 16,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_DSAA_REQUIRED, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_higher_layer_capabilities_non_voice_packet_switched_service,
			{ "Non-voice packet switched service", "dect_mitel_eth.rfpc.higher_layer_capabilities.non_voice_packet_switched_service", FT_BOOLEAN, 16,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_NON_VOICE_PACKET_SWITCHED_SERVICE, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_higher_layer_capabilities_non_voice_circuit_switched_service,
			{ "Non-voice circuit switched service", "dect_mitel_eth.rfpc.higher_layer_capabilities.non_voice_circuit_switched_service", FT_BOOLEAN, 16,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_NON_VOICE_CIRCUIT_SWITCHED_SERVICE, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_higher_layer_capabilities_gap_basic_speech,
			{ "GAP basic speech", "dect_mitel_eth.rfpc.higher_layer_capabilities.gap_basic_speech", FT_BOOLEAN, 16,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_GAP_BASIC_SPEECH, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_higher_layer_capabilities_g726,
			{ "ADPCM/G-726 Voice service", "dect_mitel_eth.rfpc.higher_layer_capabilities.g726", FT_BOOLEAN, 16,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_HIGHER_LAYER_CAPABILITIES_G726, NULL, HFILL
			}
		},
		/* RFPc Extended capabilities */
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_wireless_relay_stations,
			{ "Wireless relay stations", "dect_mitel_eth.rfpc.extended_capabilities.wireless_relay_stations", FT_UINT16, BASE_DEC,
				NULL, 0x0FC0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_flags,
			{ "Flags", "dect_mitel_eth.rfpc.extended_capabilities.flags", FT_UINT32, BASE_HEX,
				NULL, 0x3FFFFFFF, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_isdn_data_services,
			{ "ISDN data services", "dect_mitel_eth.rfpc.extended_capabilities.isdn_data_services", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_ISDN_DATA_SERVICES, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_dprs_class_2,
			{ "DPRS class 2", "dect_mitel_eth.rfpc.extended_capabilities.dprs_class_2", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_DPRS_CLASS_2, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_dprs_class_3_or_4,
			{ "DPRS class 3 or 4", "dect_mitel_eth.rfpc.extended_capabilities.dprs_class_3_or_4", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_DPRS_CLASS_3_OR_4, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_data_service_profile_d,
			{ "Data service profile D", "dect_mitel_eth.rfpc.extended_capabilities.data_service_profile_d", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_DATA_SERVICE_PROFILE_D, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_lrms,
			{ "LRMS", "dect_mitel_eth.rfpc.extended_capabilities.lrms", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_LRMS, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_asymmetric_bearers_supported,
			{ "Asymmetric bearers supported", "dect_mitel_eth.rfpc.extended_capabilities.asymmetric_bearers_supported", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_ASYMMETRIC_BEARERS_SUPPORTED, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_emergency_call_supported,
			{ "Emergency call supported", "dect_mitel_eth.rfpc.extended_capabilities.emergency_call_supported", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_EMERGENCY_CALL_SUPPORTED, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_location_registration_with_tpui_allowed,
			{ "Location registration with TPUI allowed", "dect_mitel_eth.rfpc.extended_capabilities.location_registration_with_tpui_allowed", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_LOCATION_REGISTRATION_WITH_TPUI_ALLOWED, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_sync_to_gps_achieved,
			{ "Sync to GPS achieved", "dect_mitel_eth.rfpc.extended_capabilities.sync_to_gps_achieved", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_SYNCHRONIZATION_TO_GPS_ACHIEVED, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_isdn_intermediate_system,
			{ "ISDN intermediate system", "dect_mitel_eth.rfpc.extended_capabilities.isdn_intermediate_system", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_ISDN_INTERMEDIATE_SYSTEM, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_rap_part_1_profile,
			{ "RAP part 1 profile", "dect_mitel_eth.rfpc.extended_capabilities.rap_part_1_profile", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_RAP_PART_1_PROFILE, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_v24,
			{ "V24", "dect_mitel_eth.rfpc.extended_capabilities.v24", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_V24, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_ppp,
			{ "PPP", "dect_mitel_eth.rfpc.extended_capabilities.ppp", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_PPP, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_ip,
			{ "IP", "dect_mitel_eth.rfpc.extended_capabilities.ip", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_IP, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_token_ring,
			{ "Token Ring", "dect_mitel_eth.rfpc.extended_capabilities.token_ring", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_TOKEN_RING, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_ethernet,
			{ "Ethernet", "dect_mitel_eth.rfpc.extended_capabilities.ethernet", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_ETHERNET, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_ip_roaming_unrestricted_supported,
			{ "IP roaming unrestricted supported", "dect_mitel_eth.rfpc.extended_capabilities.ip_roaming_unrestricted_supported", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_IP_ROAMING_UNRESTRICTED_SUPPORTED, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_dprs_supported,
			{ "DPRS supported", "dect_mitel_eth.rfpc.extended_capabilities.dprs_supported", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_DPRS_SUPPORTED, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_basis_odap_supported,
			{ "Basic ODAP supported", "dect_mitel_eth.rfpc.extended_capabilities.basic_odap_supported", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_BASIC_ODAP_SUPPORTED, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_fmms_interworking_profile_supported,
			{ "FMMS interworking profile supported", "dect_mitel_eth.rfpc.extended_capabilities.fmms_interworking_profile_supported", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_FMMS_INTERWORKING_PROFILE_SUPPORTED, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_extended_fp_info2,
			{ "Extended FP info 2", "dect_mitel_eth.rfpc.extended_capabilities.extended_fp_info2", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_EXTENDED_FP_INFOR_2, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_ipq_services_supported,
			{ "IPq services supported", "dect_mitel_eth.rfpc.extended_capabilities.ipq_services_supported", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_IPQ_SERVICES_SUPPORTED, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_mac_suspend_resume,
			{ "MAC suspend resume", "dect_mitel_eth.rfpc.extended_capabilities.mac_suspend_resume", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_MAC_SUSPEND_RESUME, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_frequency_replacement_supported,
			{ "Frequency replacement supported", "dect_mitel_eth.rfpc.extended_capabilities.frequency_replacement_supported", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_FREQUENCY_REPLACEMENT_SUPPORTED, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_syncronization,
			{ "Synchronization", "dect_mitel_eth.rfpc.extended_capabilities.synchronization", FT_BOOLEAN, 32,
				TFS(&tfs_prolonged_standard), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITY_SYNCHRONIZATION, NULL, HFILL
			}
		},
		/* RFPc MAC capabilities */
		{ &hf_dect_mitel_eth_rfpc_mac_capabilities_flags,
			{ "MAC capability flags", "dect_mitel_eth.rfpc.mac_capabilities.flags", FT_UINT24, BASE_HEX,
				NULL, 0x0FFFFF, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_mac_capabilities_multibearer_connections,
			{ "Multibearer connections", "dect_mitel_eth.rfpc.mac_capabilities.multibearer_connections", FT_BOOLEAN, 20,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_MULTIBEARER_CONNECTIONS, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_mac_capabilities_ipmr_error_correction,
			{ "Ipmr error correction", "dect_mitel_eth.rfpc.mac_capabilities.ipmr_error_correction", FT_BOOLEAN, 20,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_IPMR_ERROR_CORRECTION, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_mac_capabilities_ipm_error_detection,
			{ "Ipm error detection", "dect_mitel_eth.rfpc.mac_capabilities.ipm_error_detection", FT_BOOLEAN, 20,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_IPM_ERROR_DETECTION, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_mac_capabilities_inb_normal_delay,
			{ "Inb normal delay", "dect_mitel_eth.rfpc.mac_capabilities.inb_normal_delay", FT_BOOLEAN, 20,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_INB_NORMAL_DELAY, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_mac_capabilities_ina_minimum_delay,
			{ "Ina minimum delay", "dect_mitel_eth.rfpc.mac_capabilities.ina_minimum_delay", FT_BOOLEAN, 20,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_INA_MINIMUM_DELAY, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_mac_capabilities_cf_messages,
			{ "Cf messages", "dect_mitel_eth.rfpc.mac_capabilities.cf_messages", FT_BOOLEAN, 20,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_CF_MESSAGES, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_mac_capabilities_b_field_setup,
			{ "B-field setup", "dect_mitel_eth.rfpc.mac_capabilities.b_field_setup", FT_BOOLEAN, 20,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_B_FIELD_SETUP, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_mac_capabilities_advanced_a_field_setup,
			{ "Advanced A-field setup", "dect_mitel_eth.rfpc.mac_capabilities.advanced_a_field_setup", FT_BOOLEAN, 20,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_ADVANCED_A_FIELD_SETUP, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_mac_capabilities_basic_a_field_setup,
			{ "Basic A-field setup", "dect_mitel_eth.rfpc.mac_capabilities.basic_a_field_setup", FT_BOOLEAN, 20,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_BASIC_A_FIELD_SETUP, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_mac_capabilities_cl_downlink,
			{ "Cl downlink", "dect_mitel_eth.rfpc.mac_capabilities.cl_downlink", FT_BOOLEAN, 20,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_CL_DOWNLINK, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_mac_capabilities_cl_uplink,
			{ "Cl uplink", "dect_mitel_eth.rfpc.mac_capabilities.cl_uplink", FT_BOOLEAN, 20,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_CL_UPLINK, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_mac_capabilities_co_setup_on_dummy_allowed,
			{ "CO setup on dummy allowed", "dect_mitel_eth.rfpc.mac_capabilities.co_setup_on_dummy_allowed", FT_BOOLEAN, 20,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_CO_SETUP_ON_DUMMY_ALLOWED, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_mac_capabilities_page_repetition,
			{ "Page repetition", "dect_mitel_eth.rfpc.mac_capabilities.page_repetition", FT_BOOLEAN, 20,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_PAGE_REPETITION, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_mac_capabilities_frequency_control,
			{ "Frequency control", "dect_mitel_eth.rfpc.mac_capabilities.frequency_control", FT_BOOLEAN, 20,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_FREQUENCY_CONTROL, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_mac_capabilities_slot_size_full,
			{ "Slot size full", "dect_mitel_eth.rfpc.mac_capabilities.slot_size_full", FT_BOOLEAN, 20,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_SLOT_SIZE_FULL, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_mac_capabilities_slot_size_half,
			{ "Slot size half", "dect_mitel_eth.rfpc.mac_capabilities.slot_size_half", FT_BOOLEAN, 20,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_SLOT_SIZE_HALF, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_mac_capabilities_slot_size_double,
			{ "Slot size double", "dect_mitel_eth.rfpc.mac_capabilities.slot_size_double", FT_BOOLEAN, 20,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_SLOT_SIZE_DOUBLE, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_mac_capabilities_double_duplex_bearer_connections,
			{ "Double duplexe bearer connections", "dect_mitel_eth.rfpc.mac_capabilities.double_duplex_bearer_connections", FT_BOOLEAN, 20,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_DOUBLE_DUPLEX_BEARER_CONNECTIONS, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_mac_capabilities_extended_fp_info,
			{ "Extended FP info", "dect_mitel_eth.rfpc.mac_capabilities.extended_fp_info", FT_BOOLEAN, 20,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_MAC_CAPABILITIES_EXTENDED_FP_INFO, NULL, HFILL
			}
		},
		/* RFPc Statistic data */
		{ &hf_dect_mitel_eth_rfpc_statistic_data_bmc_connections_1_3,
			{ "BMC connections 1-3", "dect_mitel_eth.rfpc.statistic_data.bmc_connections_1_3", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_statistic_data_bmc_connections_4_6,
			{ "BMC connections 4-6", "dect_mitel_eth.rfpc.statistic_data.bmc_connections_4_6", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_statistic_data_bmc_connections_7_9,
			{ "BMC connections 7-9", "dect_mitel_eth.rfpc.statistic_data.bmc_connections_7_9", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_statistic_data_bmc_connections_10_12,
			{ "BMC connections 10-12", "dect_mitel_eth.rfpc.statistic_data.bmc_connections_10_12", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_statistic_data_bmc_dsp_channels_1_2,
			{ "BMC DSP Channels 1+2", "dect_mitel_eth.rfpc.statistic_data.bmc_channels_1_2", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_statistic_data_bmc_dsp_channels_3_4,
			{ "BMC DSP Channels 3+4", "dect_mitel_eth.rfpc.statistic_data.bmc_channels_3_4", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_statistic_data_bmc_dsp_channels_5_6,
			{ "BMC DSP Channels 5+6", "dect_mitel_eth.rfpc.statistic_data.bmc_channels_5_6", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_statistic_data_bmc_dsp_channels_7_8,
			{ "BMC DSP Channels 7+8", "dect_mitel_eth.rfpc.statistic_data.bmc_channels_7_8", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_statistic_data_lost_connections,
			{ "Lost connection", "dect_mitel_eth.rfpc.statistic_data.lost_connections", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_statistic_data_mac_reset,
			{ "MAC reset", "dect_mitel_eth.rfpc.statistic_data.mac_reset", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_statistic_data_reject_dummy,
			{ "Reject dummy", "dect_mitel_eth.rfpc.statistic_data.reject_dummy", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_statistic_data_handoff_timer,
			{ "Handoff timer", "dect_mitel_eth.rfpc.statistic_data.handoff_timer", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_statistic_data_bad_frames,
			{ "Bad frames", "dect_mitel_eth.rfpc.statistic_data.bad_frames", FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_statistic_data_good_frames,
			{ "Good frames", "dect_mitel_eth.rfpc.statistic_data.good_frames", FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		/* RFPc RFP_PLI */
		{ &hf_dect_mitel_eth_rfpc_rfp_pli_length_indicator,
			{ "PARK length indicator", "dect_mitel_eth.rfpc.rfp_pli.length_indicator", FT_UINT8, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		/* RFPc Extended capabilities 2 */
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities2_mac_capability_flags,
			{ "MAC capability flags", "dect_mitel_eth.rfpc.extended_capabilities2.mac_capability.flags", FT_UINT16, BASE_HEX,
				NULL, 0x0FFF, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities2_mac_capability_slot_type_long_640,
			{ "Long slot; j = 640", "dect_mitel_eth.rfpc.extended_capabilities2.mac_capability.slot_type.long_640", FT_BOOLEAN, 12,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_MAC_CAPABILITY_SLOT_TYPE_LONG_640, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities2_mac_capability_slot_type_long_672,
			{ "Long slot; j = 672", "dect_mitel_eth.rfpc.extended_capabilities2.mac_capability.slot_type.long_672", FT_BOOLEAN, 12,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_MAC_CAPABILITY_SLOT_TYPE_LONG_672, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities2_mac_capability_mux_e_u,
			{ "E+U-type mux and channel I PF basic procedures", "dect_mitel_eth.rfpc.extended_capabilities2.mac_capability.mux_e_u", FT_BOOLEAN, 12,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_MAC_CAPABILITY_MUX_E_U, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities2_mac_capability_channel_ipf,
			{ "Channel I PF advanced procedures", "dect_mitel_eth.rfpc.extended_capabilities2.mac_capability.channel_ipf", FT_BOOLEAN, 12,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_MAC_CAPABILITY_CHANNEL_IPF, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities2_mac_capability_channel_sipf,
			{ "Channel SI PF", "dect_mitel_eth.rfpc.extended_capabilities2.mac_capability.channel_sipf", FT_BOOLEAN, 12,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_MAC_CAPABILITY_CHANNEL_SIPF, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities2_mac_capability_channel_gf,
			{ "Channel GF", "dect_mitel_eth.rfpc.extended_capabilities2.mac_capability.channel_gf", FT_BOOLEAN, 12,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_MAC_CAPABILITY_CHANNEL_GF, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities2_mac_capability_wrs_ule,
			{ "WRS for ULE", "dect_mitel_eth.rfpc.extended_capabilities2.mac_capability.wrs_ule", FT_BOOLEAN, 12,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_MAC_CAPABILITY_WRS_ULE, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities2_mac_capability_no_emission_preferred_cn,
			{ "No emission mode preferred cn", "dect_mitel_eth.rfpc.extended_capabilities2.mac_capability.no_emission_preferred_cn", FT_BOOLEAN, 12,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_MAC_CAPABILITY_NO_EMISSION_PREFERRED_CN, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities2_flags,
			{ "Capability flags", "dect_mitel_eth.rfpc.extended_capabilities2.flags", FT_UINT24, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities2_dprs_data_category,
			{ "Light data services", "dect_mitel_eth.rfpc.extended_capabilities2.dprs_data_category", FT_UINT8, BASE_HEX,
				VALS(dect_mitel_eth_rfpc_extended_capabilities2_dprs_data_category_val), 0x78, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities2_ng_dect_1,
			{ "NG-DECT Part 1: Wideband voice", "dect_mitel_eth.rfpc.extended_capabilities2.ng_dect_1", FT_BOOLEAN, 24,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_NG_DECT_1, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities2_ng_dect_3,
			{ "NG-DECT Part 3: Extended wideband voice", "dect_mitel_eth.rfpc.extended_capabilities2.ng_dect_3", FT_BOOLEAN, 24,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_NG_DECT_3, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities2_permanent_clir,
			{ "Permanent CLIR", "dect_mitel_eth.rfpc.extended_capabilities2.permanent_clir", FT_BOOLEAN, 24,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_PERMANENT_CLIR, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities2_third_party_conference,
			{ "Third party conference", "dect_mitel_eth.rfpc.extended_capabilities2.third_party_conference", FT_BOOLEAN, 24,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_THIRD_PARTY_CONFERENCE, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities2_intrusion_call,
			{ "Intrusion call", "dect_mitel_eth.rfpc.extended_capabilities2.intrusion_call", FT_BOOLEAN, 24,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_INTRUSION_CALL, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities2_call_deflection,
			{ "Call deflection", "dect_mitel_eth.rfpc.extended_capabilities2.call_deflection", FT_BOOLEAN, 24,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_CALL_DEFLECTION, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities2_multiple_lines,
			{ "Multiple lines", "dect_mitel_eth.rfpc.extended_capabilities2.multiple_lines", FT_BOOLEAN, 24,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_MULTIPLE_LINES, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities2_no_emission,
			{ "Capability to support \"no emission\" or U-NEMo mode", "dect_mitel_eth.rfpc.extended_capabilities2.no_emission", FT_BOOLEAN, 24,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_NO_EMISSION, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities2_ng_dect_5,
			{ "NG-DECT Part 5", "dect_mitel_eth.rfpc.extended_capabilities2.ng_dect_5", FT_BOOLEAN, 24,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_NG_DECT_5, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities2_re_keying,
			{ "Re-keying and default cipher key early encryption mechanism", "dect_mitel_eth.rfpc.extended_capabilities2.re_keying", FT_BOOLEAN, 24,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_RE_KEYING, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities2_dsaa2,
			{ "DSAA2 supported", "dect_mitel_eth.rfpc.extended_capabilities2.dsaa2", FT_BOOLEAN, 24,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_DSAA2, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities2_dsc2,
			{ "DSC2 supported", "dect_mitel_eth.rfpc.extended_capabilities2.dsc2", FT_BOOLEAN, 24,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_DSC2, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities2_light_data,
			{ "Light data services", "dect_mitel_eth.rfpc.extended_capabilities2.light_data", FT_BOOLEAN, 24,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_RFPC_EXTENDED_CAPABILITIES2_LIGHT_DATA, NULL, HFILL
			}
		},
		/* MAC_CON_IND */
		{ &hf_dect_mitel_eth_mac_con_ind_flags,
			{ "Flags", "dect_mitel_eth.mac_con_ind.flags", FT_UINT8, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_mac_con_ind_flag_handover,
			{ "Handover", "dect_mitel_eth.mac_con_ind.flags.handover", FT_BOOLEAN, 8,
				TFS(&tfs_yes_no), DECT_MITEL_ETH_MAC_CON_IND_FLAG_HANDOVER, NULL, HFILL
			}
		},
		/* MAC_DIS_IND */
		{ &hf_dect_mitel_eth_mac_dis_ind_reason,
			{ "Reason", "dect_mitel_eth.mac_dis_ind.reason", FT_UINT8, BASE_HEX,
				VALS(dect_mitel_eth_mac_dis_ind_reason_val), 0x0, NULL, HFILL
			}
		},
		/* MAC_PAGE_REQ */
		{ &hf_dect_mitel_eth_mac_page_req_flags,
			{ "Flags", "dect_mitel_eth.mac_page_req.flags", FT_UINT8, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		/* MAC_ENC_KEY_REQ */
		{ &hf_dect_mitel_eth_mac_enc_key_req_key,
			{ "Key", "dect_mitel_eth.mac.enc_key_req.key", FT_UINT64, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_mac_enc_key_req_id,
			{ "ID", "dect_mitel_eth.mac.enc_key_req.id", FT_UINT8, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		/* MAC_ENC_EKS_IND */
		{ &hf_dect_mitel_eth_mac_enc_eks_ind_type,
			{ "Type", "dect_mitel_eth.mac.enc_eks_ind.type", FT_UINT8, BASE_HEX,
				VALS(dect_mitel_eth_mac_enc_eks_ind_type_val), 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_mac_enc_eks_ind_id,
			{ "ID", "dect_mitel_eth.mac.enc_eks_ind.id", FT_UINT8, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_mac_enc_eks_ind_ppn,
			{ "PPN", "dect_mitel_eth.mac.enc_eks_ind.ppn", FT_UINT16, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		/* MAC_HO_IN_PROGRESS_RES */
		{ &hf_dect_mitel_eth_mac_ho_in_progress_res_key,
			{ "Key", "dect_mitel_eth.mac.ho_in_progress_res.key", FT_UINT64, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_mac_ho_in_progress_res_id,
			{ "ID", "dect_mitel_eth.mac.ho_in_progress_res.id", FT_UINT8, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		/* MAC_HO_FAILED_IND */
		{ &hf_dect_mitel_eth_mac_ho_failed_ind_reason,
			{ "Reason", "dect_mitel_eth.mac.ho_failed_ind.reason", FT_UINT8, BASE_HEX,
				VALS(dect_mitel_eth_mac_ho_failed_ind_reason_val), 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_mt_item_key,
			{ "Key", "dect_mitel_eth.mt.item.key", FT_UINT8, BASE_HEX,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_mt_item_length,
			{ "Length", "dect_mitel_eth.mt.item.length", FT_UINT8, BASE_DEC,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_mt_item_value,
			{ "Value", "dect_mitel_eth.mt.item.value", FT_BYTES, BASE_NONE,
				 NULL, 0x0, NULL, HFILL
			}
		},
	};

	static int *ett[] = {
		&ett_dect_mitel_eth,
		&ett_dect_mitel_eth_rfpc_item,
		&ett_dect_mitel_eth_higher_layer_capabilities_flags,
		&ett_dect_mitel_eth_extended_capabilities_flags,
		&ett_dect_mitel_eth_mac_capabilities_flags,
		&ett_dect_mitel_eth_extended_capabilities2_mac_capability_flags,
		&ett_dect_mitel_eth_extended_capabilities2_flags,
	};

	/* Register protocol */
	proto_dect_mitel_eth = proto_register_protocol("Aastra/Mitel DECT-over-Ethernet", "Mitel-DECToE", "dect_mitel_eth");

	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_dect_mitel_eth, hf, array_length(hf));

	register_dissector("dect_mitel_eth", dissect_dect_mitel_eth, proto_dect_mitel_eth);
}

void proto_reg_handoff_dect_mitel_eth(void)
{
	dissector_handle_t dect_mitel_eth_handle  =
	    create_dissector_handle(dissect_dect_mitel_eth, proto_dect_mitel_eth);
	dissector_add_uint("ethertype", DECT_MITEL_ETH_T_XDLC, dect_mitel_eth_handle);

	dlc_handle = find_dissector("dect_dlc");
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
