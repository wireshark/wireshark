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
void proto_reg_handoff_dect_mitelrfp(void);

static int proto_dect_mitel_eth = -1;

static gint hf_dect_mitel_eth_len = -1;
static gint hf_dect_mitel_eth_layer = -1;
static gint hf_dect_mitel_eth_prim_type = -1;
static gint hf_dect_mitel_eth_mcei = -1;
static gint hf_dect_mitel_eth_mac_info_ind_string = -1;
static gint hf_dect_mitel_eth_pmid = -1;
static gint hf_dect_mitel_eth_subfield = -1;

static gint hf_dect_mitel_eth_rfpc_message_type = -1;
static gint hf_dect_mitel_eth_rfpc_item_type = -1;
static gint hf_dect_mitel_eth_rfpc_item_length = -1;
static gint hf_dect_mitel_eth_rfpc_item_value = -1;

static gint hf_dect_mitel_eth_rfpc_extended_capabilities_wireless_relay_stations = -1;
static gint hf_dect_mitel_eth_rfpc_extended_capabilities_flags = -1;
static gint hf_dect_mitel_eth_rfpc_extended_capabilities_isdn_data_services = -1;
static gint hf_dect_mitel_eth_rfpc_extended_capabilities_dprs_class_2 = -1;
static gint hf_dect_mitel_eth_rfpc_extended_capabilities_dprs_class_3_or_4 = -1;
static gint hf_dect_mitel_eth_rfpc_extended_capabilities_data_service_profile_d = -1;
static gint hf_dect_mitel_eth_rfpc_extended_capabilities_lrms = -1;
static gint hf_dect_mitel_eth_rfpc_extended_capabilities_asymmetric_bearers_supported = -1;
static gint hf_dect_mitel_eth_rfpc_extended_capabilities_emergency_call_supported = -1;
static gint hf_dect_mitel_eth_rfpc_extended_capabilities_location_registration_with_tpui_allowed = -1;
static gint hf_dect_mitel_eth_rfpc_extended_capabilities_sync_to_gps_achieved = -1;
static gint hf_dect_mitel_eth_rfpc_extended_capabilities_isdn_intermediate_system = -1;
static gint hf_dect_mitel_eth_rfpc_extended_capabilities_rap_part_1_profile = -1;
static gint hf_dect_mitel_eth_rfpc_extended_capabilities_v24 = -1;
static gint hf_dect_mitel_eth_rfpc_extended_capabilities_ppp = -1;
static gint hf_dect_mitel_eth_rfpc_extended_capabilities_ip = -1;
static gint hf_dect_mitel_eth_rfpc_extended_capabilities_token_ring = -1;
static gint hf_dect_mitel_eth_rfpc_extended_capabilities_ethernet = -1;
static gint hf_dect_mitel_eth_rfpc_extended_capabilities_ip_roaming_unrestricted_supported = -1;
static gint hf_dect_mitel_eth_rfpc_extended_capabilities_dprs_supported = -1;
static gint hf_dect_mitel_eth_rfpc_extended_capabilities_basis_odap_supported = -1;
static gint hf_dect_mitel_eth_rfpc_extended_capabilities_fmms_interworking_profile_supported = -1;
static gint hf_dect_mitel_eth_rfpc_extended_capabilities_extended_fp_info2 = -1;
static gint hf_dect_mitel_eth_rfpc_extended_capabilities_ipq_services_supported = -1;
static gint hf_dect_mitel_eth_rfpc_extended_capabilities_mac_suspend_resume = -1;
static gint hf_dect_mitel_eth_rfpc_extended_capabilities_frequency_replacement_supported = -1;
static gint hf_dect_mitel_eth_rfpc_extended_capabilities_syncronization = -1;

static gint hf_dect_mitel_eth_mac_con_ind_flags = -1;
static gint hf_dect_mitel_eth_mac_con_ind_flag_handover = -1;

static gint hf_dect_mitel_eth_mac_dis_ind_reason = -1;

static gint hf_dect_mitel_eth_mac_page_req_flags = -1;

static gint hf_dect_mitel_eth_mac_enc_key_req_key = -1;
static gint hf_dect_mitel_eth_mac_enc_key_req_id = -1;

static gint hf_dect_mitel_eth_mac_enc_eks_ind_type = -1;
static gint hf_dect_mitel_eth_mac_enc_eks_ind_id = -1;
static gint hf_dect_mitel_eth_mac_enc_eks_ind_ppn = -1;

static gint hf_dect_mitel_eth_mac_ho_in_progress_res_key = -1;
static gint hf_dect_mitel_eth_mac_ho_in_progress_res_id = -1;

static gint hf_dect_mitel_eth_mac_ho_failed_ind_reason = -1;

static gint hf_dect_mitel_eth_mt_item_key = -1;
static gint hf_dect_mitel_eth_mt_item_length = -1;
static gint hf_dect_mitel_eth_mt_item_value = -1;

static gint ett_dect_mitel_eth = -1;

static dissector_handle_t data_handle;
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
	{ DECT_MITEL_ETH_MAC_HO_IN_PROGRESS_IND,   "MAC_HO_IN_PROGRRESS_IND" },
	{ DECT_MITEL_ETH_MAC_HO_IN_PROGRESS_RES,   "MAC_HO_IN_PROGRERSS_RES" },
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

/* RFPc Extended Capabilities*/
static const true_false_string tfs_prolonged_standard = {
	"Prolonged",
	"Standard"
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


/*
RFPc Extended capabilities field
| Offset | Len | Content                 | Mask         |
| ------ | --- | ----------------------- | ------------ |
|      0 |   2 | Wireless Relay Stations | 0x0FC0       |
|      1 |   4 | Flags                   | 0x3FFFFFFFFF |
 */
static guint dissect_dect_mitel_eth_rfpc_extended_capabilities(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, guint offset)
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
	proto_tree_add_bitmask(tree, tvb, offset, hf_dect_mitel_eth_rfpc_extended_capabilities_flags, ett_dect_mitel_eth, flags, ENC_NA);

	offset += 4;
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
static guint dissect_dect_mitel_eth_rfpc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, guint offset)
{
	guint8 message_type, item_type, item_length;
	proto_tree_add_item(tree, hf_dect_mitel_eth_rfpc_message_type, tvb, offset, 1, ENC_NA);
	message_type = tvb_get_guint8(tvb, offset);
	col_append_fstr(pinfo->cinfo, COL_INFO, "RFPc: %s ",
				val_to_str(message_type, dect_mitel_eth_rfpc_message_type_val, "Unknown 0x%02x"));
	offset++;

	while ( tvb_reported_length_remaining(tvb, offset) ) {
		proto_tree_add_item(tree, hf_dect_mitel_eth_rfpc_item_type, tvb, offset, 1, ENC_NA);
		item_type = tvb_get_guint8(tvb, offset);
		offset++;

		proto_tree_add_item(tree, hf_dect_mitel_eth_rfpc_item_length, tvb, offset, 1, ENC_NA);
		item_length = tvb_get_guint8(tvb, offset);
		offset ++;

		switch (item_type) {
			case DECT_MITEL_ETH_RFPC_ITEM_TYPE_EXTENDED_CAPABILITIES:
				offset = dissect_dect_mitel_eth_rfpc_extended_capabilities(tvb, pinfo, tree, data, offset);
				break;
			default:
				proto_tree_add_item(tree, hf_dect_mitel_eth_rfpc_item_value, tvb, offset, item_length, ENC_NA);
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
static guint dissect_dect_mitel_eth_mac_con_ind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_, guint offset)
{
	guint8 mcei;

	static int *const mac_con_ind_flags[] = {
		&hf_dect_mitel_eth_mac_con_ind_flag_handover,
	};

	pinfo->p2p_dir = P2P_DIR_RECV;
	mcei = tvb_get_guint8(tvb, offset);
	conversation_set_elements_by_id(pinfo, CONVERSATION_NONE, mcei);
	col_append_fstr(pinfo->cinfo, COL_INFO, "MCEI=%02x ", mcei);
	proto_tree_add_item(tree, hf_dect_mitel_eth_mcei, tvb, offset, 1, ENC_NA);
	offset++;
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
static guint dissect_dect_mitel_eth_mac_dis_ind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_, guint offset)
{
	guint8 mcei;

	pinfo->p2p_dir = P2P_DIR_RECV;
	mcei = tvb_get_guint8(tvb, offset);
	conversation_set_elements_by_id(pinfo, CONVERSATION_NONE, mcei);
	col_append_fstr(pinfo->cinfo, COL_INFO, "MCEI=%02x ", mcei);
	proto_tree_add_item(tree, hf_dect_mitel_eth_mcei, tvb, offset, 1, ENC_NA);
	offset++;

	proto_tree_add_item(tree, hf_dect_mitel_eth_mac_dis_ind_reason, tvb, offset, 1, ENC_NA);

	return offset;
}

/*
MAC_PAGE_REQ Message
| Offset | Len | Content         |
| ------ | --- | --------------- |
|      1 |   1 | Flags (unknown) |
 */
static guint dissect_dect_mitel_eth_mac_page_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, guint offset)
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
|      0 |   8 | Key       |
|      8 |   1 | (Key?) ID |
 */
static guint dissect_dect_mitel_eth_mac_enc_key_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, guint offset)
{
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
|      0 |   1 | Type      |                    |
|      1 |   1 | (Key?) ID | if Type == with ID |
|      2 |   2 | PPN       | if Type == with ID |
 */
static guint dissect_dect_mitel_eth_mac_enc_eks_ind(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, guint offset)
{
	guint8 type;
	proto_tree_add_item(tree, hf_dect_mitel_eth_mac_enc_eks_ind_type, tvb, offset, 1, ENC_NA);
	type = tvb_get_guint8(tvb, offset);
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
static guint dissect_dect_mitel_eth_mac_ho_in_progress_ind(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, guint offset)
{
	guint8 mcei;

	mcei = tvb_get_guint8(tvb, offset);
	conversation_set_elements_by_id(pinfo, CONVERSATION_NONE, mcei);
	col_append_fstr(pinfo->cinfo, COL_INFO, "MCEI=%02x ", mcei);
	proto_tree_add_item(tree, hf_dect_mitel_eth_mcei, tvb, offset, 1, ENC_NA);
	offset++;

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
static guint dissect_dect_mitel_eth_mac_ho_in_progress_res(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, guint offset)
{
	guint8 mcei;

	mcei = tvb_get_guint8(tvb, offset);
	conversation_set_elements_by_id(pinfo, CONVERSATION_NONE, mcei);
	col_append_fstr(pinfo->cinfo, COL_INFO, "MCEI=%02x ", mcei);
	proto_tree_add_item(tree, hf_dect_mitel_eth_mcei, tvb, offset, 1, ENC_NA);
	offset+=2;

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
|      0 |   1 | Reason  |
 */
static guint dissect_dect_mitel_eth_mac_ho_failed_ind(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, guint offset)
{
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
static guint dissect_dect_mitel_eth_mac_info_ind(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_, guint offset)
{
	guint8 mcei;

	pinfo->p2p_dir = P2P_DIR_RECV;
	mcei = tvb_get_guint8(tvb, offset);
	conversation_set_elements_by_id(pinfo, CONVERSATION_NONE, mcei);
	col_append_fstr(pinfo->cinfo, COL_INFO, "MCEI=%02x ", mcei);
	proto_tree_add_item(tree, hf_dect_mitel_eth_mcei, tvb, offset, 1, ENC_NA);
	offset++;

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
static guint dissect_dect_mitel_eth_mac_clear_def_ckey_req(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_, guint offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_eth_pmid, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset+=3;
	return offset;
}

static int dissect_dect_mitel_eth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	guint16 mitel_eth_len, payload_len;
	guint8 prim_type, layer, mcei, mt_item_length;
	int offset = 0;
	gboolean ip_encapsulated;
	tvbuff_t *payload_tvb = NULL;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MI-DECToE");
	col_clear(pinfo->cinfo, COL_INFO);

	/*
	 * When the protocol is used within the internal Ethernet channel in the RFP there is a two byte
	 * field with not yet really known content and a two byte length field. This is not in place / consumed
	 * by the upper layer dissector if this protocol is used in OMM<>RFP communication. So the data parameter
	 * is used to get information from the dect-mitel-rfp dissector whether it was IP encapsulated or not.
     */
	if(data) {
		ip_encapsulated = *( ( gboolean* )data );
	} else {
		ip_encapsulated = false;
	}
	if(!ip_encapsulated) {
		mitel_eth_len = tvb_get_guint16(tvb, offset, 2);
		proto_tree_add_item(tree, hf_dect_mitel_eth_len, tvb, offset, 2, ENC_BIG_ENDIAN);
		if (mitel_eth_len < 3)
			return tvb_captured_length(tvb);
		offset += 4;
	}

	proto_tree_add_item(tree, hf_dect_mitel_eth_layer, tvb, offset, 1, ENC_NA);
	layer = tvb_get_guint8(tvb, offset);
	offset++;

	if ( layer != DECT_MITEL_ETH_LAYER_RFPC) {
		prim_type = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_dect_mitel_eth_prim_type, tvb, offset, 1, ENC_NA);

		col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
				val_to_str(prim_type, dect_mitel_eth_prim_coding_val, "Unknown 0x%02x"));
		offset++;
	}

	switch (layer) {
		case DECT_MITEL_ETH_LAYER_RFPC:
			offset = dissect_dect_mitel_eth_rfpc(tvb, pinfo, tree, data, offset);
			break;
		case DECT_MITEL_ETH_LAYER_MT:
			while ( tvb_reported_length_remaining(tvb, offset) ) {
				proto_tree_add_item(tree, hf_dect_mitel_eth_mt_item_key, tvb, offset, 1, ENC_NA);
				offset++;
				proto_tree_add_item(tree, hf_dect_mitel_eth_mt_item_length, tvb, offset, 1, ENC_NA);
				mt_item_length = tvb_get_guint8(tvb, offset);
				offset++;
				proto_tree_add_item(tree, hf_dect_mitel_eth_mt_item_value, tvb, offset, mt_item_length, ENC_NA);
				offset += mt_item_length;
			}
			break;
		case DECT_MITEL_ETH_LAYER_LC:
		case DECT_MITEL_ETH_LAYER_MAC:
			switch (prim_type) {
				case DECT_MITEL_ETH_MAC_PAGE_REQ:
					offset = dissect_dect_mitel_eth_mac_page_req(tvb, pinfo, tree, data, offset);
					break;
				case DECT_MITEL_ETH_MAC_ENC_KEY_REQ:
					offset = dissect_dect_mitel_eth_mac_enc_key_req(tvb, pinfo, tree, data, offset);
					break;
				case DECT_MITEL_ETH_MAC_ENC_EKS_IND:
					offset = dissect_dect_mitel_eth_mac_enc_eks_ind(tvb, pinfo, tree, data, offset);
					break;
				case DECT_MITEL_ETH_MAC_HO_IN_PROGRESS_IND:
					offset = dissect_dect_mitel_eth_mac_ho_in_progress_ind(tvb, pinfo, tree, data, offset);
					break;
				case DECT_MITEL_ETH_MAC_HO_IN_PROGRESS_RES:
					offset = dissect_dect_mitel_eth_mac_ho_in_progress_res(tvb, pinfo, tree, data, offset);
					break;
				case DECT_MITEL_ETH_MAC_HO_FAILED_IND:
					offset = dissect_dect_mitel_eth_mac_ho_failed_ind(tvb, pinfo, tree, data, offset);
					break;
				case DECT_MITEL_ETH_MAC_CON_IND:
					offset = dissect_dect_mitel_eth_mac_con_ind(tvb, pinfo, tree, data, offset);
					break;
				case DECT_MITEL_ETH_MAC_INFO_IND:
					offset = dissect_dect_mitel_eth_mac_info_ind(tvb, pinfo, tree, data, offset);
					break;
				case DECT_MITEL_ETH_MAC_CLEAR_DEF_CKEY_REQ:
					offset = dissect_dect_mitel_eth_mac_clear_def_ckey_req(tvb, pinfo, tree, data, offset);
					break;
				case DECT_MITEL_ETH_MAC_DIS_REQ:
					pinfo->p2p_dir = P2P_DIR_SENT;
					mcei = tvb_get_guint8(tvb, offset);
					conversation_set_elements_by_id(pinfo, CONVERSATION_NONE, mcei);
					col_append_fstr(pinfo->cinfo, COL_INFO, "MCEI=%02x ", mcei);
					proto_tree_add_item(tree, hf_dect_mitel_eth_mcei, tvb, offset, 1, ENC_NA);
					break;
				case DECT_MITEL_ETH_MAC_DIS_IND:
					offset = dissect_dect_mitel_eth_mac_dis_ind(tvb, pinfo, tree, data, offset);
					break;
				case DECT_MITEL_ETH_LC_DTR_IND:
					pinfo->p2p_dir = P2P_DIR_RECV;
					mcei = tvb_get_guint8(tvb, offset);
					conversation_set_elements_by_id(pinfo, CONVERSATION_NONE, mcei);
					col_append_fstr(pinfo->cinfo, COL_INFO, "MCEI=%02x ", mcei);
					proto_tree_add_item(tree, hf_dect_mitel_eth_mcei, tvb, offset, 1, ENC_NA);
					offset++;
					proto_tree_add_item(tree, hf_dect_mitel_eth_subfield, tvb, offset, 1, ENC_NA);
					break;
				case DECT_MITEL_ETH_LC_DATA_REQ:
				case DECT_MITEL_ETH_LC_DATA_IND:
					if(prim_type == DECT_MITEL_ETH_LC_DATA_REQ) {
						pinfo->p2p_dir = P2P_DIR_SENT;
					} else {
						pinfo->p2p_dir = P2P_DIR_RECV;
					}
					mcei = tvb_get_guint8(tvb, offset);
					conversation_set_elements_by_id(pinfo, CONVERSATION_NONE, mcei);
					col_append_fstr(pinfo->cinfo, COL_INFO, "MCEI=%02x ", mcei);
					proto_tree_add_item(tree, hf_dect_mitel_eth_mcei, tvb, offset, 1, ENC_NA);
					offset++;
					proto_tree_add_item(tree, hf_dect_mitel_eth_subfield, tvb, offset, 1, ENC_NA);
					offset++;
					payload_len = tvb_get_guint8(tvb, offset);
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

	if (payload_tvb)
		call_dissector(data_handle, payload_tvb, pinfo, tree);

	return tvb_captured_length(tvb);
}

void proto_register_dect_mitelrfp(void)
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
			{ "Item Type", "dect_mitel_eth.rfpc.item.type", FT_UINT8, BASE_HEX,
				VALS(dect_mitel_eth_rfpc_item_type_val), 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_item_length,
			{ "Item Length", "dect_mitel_eth.rfpc.item.length", FT_UINT8, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_item_value,
			{ "Item Value", "dect_mitel_eth.rfpc.item.value", FT_BYTES, BASE_NONE,
				NULL, 0, NULL, HFILL
			}
		},
		/* RFPc Extended capabilities */
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_wireless_relay_stations,
			{ "Wireless relay stations", "dect_mitel_eth.rfpc.extended_capabilities.wireless_relay_stations", FT_UINT16, BASE_DEC,
				NULL, 0x0FC0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_eth_rfpc_extended_capabilities_flags,
			{ "Flags", "dect_mitel_eth.rfpc.extended_capabilities.isdn_data_services", FT_UINT32, BASE_HEX,
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
			{ "IPq serices supported", "dect_mitel_eth.rfpc.extended_capabilities.ipq_services_supported", FT_BOOLEAN, 32,
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

	static gint *ett[] = {
		&ett_dect_mitel_eth,
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

	data_handle = find_dissector("data");
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
