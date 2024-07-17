/* packet-cfm.c
 * Routines for CFM EOAM dissection
 * Copyright 2007, Keith Mercer <keith.mercer@alcatel-lucent.com>
 * Copyright 2011, Peter Nahas <pnahas@mrv.com>
 * Copyright 2012, Wim Leflere <wim.leflere-ext@oneaccess-net.com>
 * Copyright 2013, Andreas Urke <arurke@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* This code is based on the following documents:
 * - IEEE 802.1Q-2022 - IEEE Standard for Local and metropolitan area networks — Bridges and Bridged Networks
 * - ITU-T Rec. G.8013/Y.1731 (08/2015) - OAM functions and mechanisms for Ethernet-based networks
 * - ITU-T Rec. G.8031/Y.1342 (01/2015) - Ethernet linear protection switching
 * - ITU-T Rec. G.8032/Y.1344 (03/2020) - Ethernet ring protection switching
 * - ITU-T Rec. G.8113/Y.1372 (04/2016) - OAM mechanisms for MPLS-TP in packet transport networks
 * - IEEE 802.1AB-2016 - IEEE Standard for Local and metropolitan area networks — Station and Media Access Control Connectivity Discovery
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/etypes.h>
#include <epan/afn.h>
#include <epan/addr_resolv.h>
#include "packet-mpls.h"


/* Value declarations for CFM EOAM dissection */
/* CFM Common header */
#define CFM_COMMON_HEADER_LEN     4
#define CFM_LEVEL_VERSION_OFFSET  0
#define CFM_LEVEL_MASK            0xE0
#define CFM_LEVEL_SHIFT           5
#define CFM_VERSION_MASK          0x1F
#define CFM_VERSION_SHIFT         0
#define CFM_OPCODE_OFFSET         1
#define CFM_FLAGS_OFFSET          2
#define CFM_1ST_TLV_OFFSET        3

/* Defined by IEEE 802.1Q */
#define IEEE8021 0x00
#define CCM 0x01
#define LBR 0x02
#define LBM 0x03
#define LTR 0x04
#define LTM 0X05
#define RFM 0x06
#define SFM 0x07

/* Defined by ITU-T G.8013/Y.1731 */
#define GNM 0x20
#define AIS 0x21
#define LCK 0x23
#define TST 0x25
#define APS 0x27
#define RAPS 0x28
#define MCC 0x29
#define LMM 0x2B
#define LMR 0x2A
#define ODM 0x2D
#define DMM 0x2F
#define DMR 0x2E
#define EXM 0x31
#define EXR 0x30
#define VSM 0x33
#define VSR 0x32
#define CSF 0x34
#define OSL 0x35
#define SLM 0x37
#define SLR 0x36

/* Defined by IEEE 802.1Q */
#define END_TLV            0x00
#define SENDER_ID_TLV      0x01
#define PORT_STAT_TLV      0x02
#define DATA_TLV           0x03
#define INTERF_STAT_TLV    0x04
#define REPLY_ING_TLV      0x05
#define REPLY_EGR_TLV      0x06
#define LTM_EGR_ID_TLV     0x07
#define LTR_EGR_ID_TLV     0x08
#define PPB_TE_MIP_TLV     0x09
#define DATA_PART1_TLV     0x0A
#define DATA_PART2_TLV     0x0B
#define TRUNC_DATA_TLV     0x0C
// XXX - Does this TLV even exist?
#define GNM_TLV            0x0D
#define ORG_SPEC_TLV       0x1F
/* Defined by ITU-T Y.1731 */
#define TEST_TLV           0x20
/* Defined by ITU-T Y.1372.1 */
#define TGT_MEP_MIP_ID_TLV 0x21
#define RPL_MEP_MIP_ID_TLV 0x22
#define REQ_MEP_ID_TLV     0x23
/* Defined by ITU-T Y.1731 */
#define TEST_ID_TLV        0x24

/* Sub-OpCode for GNM */
#define BNM 0x01

/* MAID values */
#define MD_NAME_FMT_RESVD      0
#define MD_NAME_FMT_NONE       1
#define MD_NAME_FMT_DOMAIN     2
#define MD_NAME_FMT_MAC_ID     3
#define MD_NAME_FMT_STRING     4

#define MA_NAME_FMT_RESVD      0
#define MA_NAME_FMT_PVID       1
#define MA_NAME_FMT_STRING     2
#define MA_NAME_FMT_ID         3
#define MA_NAME_FMT_VPN_ID     4
#define MA_NAME_FMT_ICC       32
#define MA_NAME_FMT_ICC_CC    33

/* R-APS values */
#define RAPS_REQ_ST_MASK    0xF0
#define RAPS_REQ_ST_SHIFT      4
#define RAPS_SUB_CODE_MASK  0x0F
#define RAPS_SUB_CODE_SHIFT    0

#define RAPS_REQ_ST_NO_REQ     0
#define RAPS_REQ_ST_MAN_SW     7
#define RAPS_REQ_ST_SIG_FAIL  11
#define RAPS_REQ_ST_FCED_SW   13
#define RAPS_REQ_ST_EVENT     14


static const value_string opcode_type_name_vals[] = {
	{ IEEE8021, "Reserved for IEEE 802.1" },
	{ CCM,  "Continuity Check Message (CCM)" },
	{ LBR,  "Loopback Reply (LBR)" },
	{ LBM,  "Loopback Message (LBM)" },
	{ LTR,  "Linktrace Reply (LTR)" },
	{ LTM,  "Linktrace Message (LTM)" },
	{ RFM,  "Reflected Frame Message (RFM)" },
	{ SFM,  "Send Frame Message (SFM)" },
	{ GNM,  "Generic Notification Message (GNM)" },
	{ AIS,  "Alarm Indication Signal (AIS)" },
	{ LCK,  "Lock Signal (LCK)" },
	{ TST,  "Test Signal (TST)" },
	{ APS,  "Automatic Protection Switching (APS)" },
	{ RAPS, "Ring-Automatic Protection Switching (R-APS)" },
	{ MCC, "Maintenance Communication Channel (MCC)" },
	{ LMM, "Loss Measurement Message (LMM)" },
	{ LMR, "Loss Measurement Reply (LMR)" },
	{ ODM, "One Way Delay Measurement (1DM)" },
	{ DMM, "Delay Measurement Message (DMM)" },
	{ DMR, "Delay Measurement Reply (DMR)" },
	{ EXM, "Experimental OAM Message (EXM)" },
	{ EXR, "Experimental OAM Reply (EXR)" },
	{ VSM, "Vendor Specific Message (VSM)" },
	{ VSR, "Vendor Specific Reply (VSR)" },
	{ CSF, "Client Signal Fail (CSF)" },
	{ OSL, "One Way Synthetic Loss Measurement (1SL)" },
	{ SLM, "Synthetic Loss Message (SLM)" },
	{ SLR, "Synthetic Loss Reply (SLR)" },
	{ 0,   NULL }
};

static const value_string tlv_type_field_vals[] = {
	{ END_TLV,             "End TLV" },
	{ SENDER_ID_TLV,       "Sender ID TLV" },
	{ PORT_STAT_TLV,       "Port Status TLV" },
	{ DATA_TLV,            "Data TLV" },
	{ INTERF_STAT_TLV,     "Interface Status TLV" },
	{ REPLY_ING_TLV,       "Reply Ingress TLV" },
	{ REPLY_EGR_TLV,       "Reply Egress TLV" },
	{ LTM_EGR_ID_TLV,      "LTM Egress Identifier TLV" },
	{ LTR_EGR_ID_TLV,      "LTR Egress Identifier TLV" },
	{ PPB_TE_MIP_TLV,      "PBB-TE MIP TLV" },
	{ DATA_PART1_TLV,      "Data Part 1 TLV" },
	{ DATA_PART2_TLV,      "Data Part 2 TLV" },
	{ TRUNC_DATA_TLV,      "Truncated Data TLV" },
	{ GNM_TLV,             "Generic Notification Message TLV" },
	{ ORG_SPEC_TLV,        "Organizational-Specific TLV" },
	{ TEST_TLV,            "Test TLV" },
	{ TGT_MEP_MIP_ID_TLV,  "Target MEP/MIP ID TLV" },
	{ RPL_MEP_MIP_ID_TLV,  "Replying MEP/MIP ID TLV" },
	{ REQ_MEP_ID_TLV,      "Requesting MEP ID TLV" },
	{ TEST_ID_TLV,         "Test ID TLV" },
	{ 0,                   NULL }
};

static const value_string md_name_format_type_vals[] = {
	{ MD_NAME_FMT_RESVD,  "Reserved for IEEE 802.1" },
	{ MD_NAME_FMT_NONE,   "No Maintenance Domain Name present" },
	{ MD_NAME_FMT_DOMAIN, "Domain Name-based string" },
	{ MD_NAME_FMT_MAC_ID, "MAC address + 2-octet integer" },
	{ MD_NAME_FMT_STRING, "Character String" },
	{ 0, NULL }
};

static const value_string ma_name_format_type_vals[] = {
	// IEEE 802.1Q
	{ MA_NAME_FMT_RESVD,  "Reserved for IEEE 802.1" },
	{ MA_NAME_FMT_PVID,   "Primary VID" },
	{ MA_NAME_FMT_STRING, "Character String" },
	{ MA_NAME_FMT_ID,     "2-octet integer" },
	{ MA_NAME_FMT_VPN_ID, "RFC 2685 VPN ID" },
	// Y.1731 Annex A
	{ MA_NAME_FMT_ICC,    "ICC-based Format" },
	{ MA_NAME_FMT_ICC_CC, "ICC and CC based Format" },
	{ 0,  NULL }
};

static const value_string ccm_interval_field_encoding_vals[] = {
	{ 0, "invalid" },
	{ 1, "Trans Int 3.33ms, max Lifetime 11.66ms, min Lifetime 10.83ms" },
	{ 2, "Trans Int 10ms, max Lifetime 35ms, min Lifetime 32.5ms" },
	{ 3, "Trans Int 100ms, max Lifetime 350ms, min Lifetime 325ms" },
	{ 4, "Trans Int 1s, max Lifetime 3.5s, min Lifetime 3.25s" },
	{ 5, "Trans Int 10s, max Lifetime 35s, min Lifetime 32.5s" },
	{ 6, "Trans Int 1min, max Lifetime 3.5min, min Lifetime 3.25min" },
	{ 7, "Trans Int 10min, max Lifetime 35min, min Lifetime 32.5min" },
	{ 0, NULL }
};

static const value_string relay_action_type_vals[] = {
	{ 1, "RlyHit" },
	{ 2, "RlyFDB" },
	{ 3, "RlyMPDB" },
	{ 0, NULL }
};

static const value_string ais_lck_period_type_vals[] = {
	{ 0, "Invalid Value for AIS/LCK PDU's" },
	{ 1, "Invalid Value for AIS/LCK PDU's" },
	{ 2, "Invalid Value for AIS/LCK PDU's" },
	{ 3, "Invalid Value for AIS/LCK PDU's" },
	{ 4, "1 frame per second" },
	{ 5, "Invalid Value for AIS/LCK PDU's" },
	{ 6, "1 frame per minute" },
	{ 7, "Invalid Value for AIS/LCK PDU's" },
	{ 0, NULL }
};

static const value_string sender_id_tlv_chassis_id_subtype_vals[] = {
	{ 1, "Chassis component" },
	{ 2, "Interface alias" },
	{ 3, "Port component" },
	{ 4, "MAC address" },
	{ 5, "Network address" },
	{ 6, "Interface name" },
	{ 7, "Locally assigned" },
	{ 0, NULL }
};

static const value_string port_stat_tlv_vals[] = {
	{ 1, "psBlocked" },
	{ 2, "psUp" },
	{ 0, NULL }
};

static const value_string interface_stat_tlv_vals[] = {
	{ 1, "isUp" },
	{ 2, "isDown" },
	{ 3, "isTesting" },
	{ 4, "isUnknown" },
	{ 5, "isDormant" },
	{ 6, "isNotPresent" },
	{ 7, "isLowerLayerDown" },
	{ 0, NULL }
};

static const value_string reply_ingress_tlv_vals[] = {
	{ 1, "IngOK" },
	{ 2, "IngDown" },
	{ 3, "IngBlocked" },
	{ 4, "IngVID" },
	{ 0, NULL }
};

static const value_string reply_egress_tlv_vals[] = {
	{ 1, "EgrOK" },
	{ 2, "EgrDown" },
	{ 3, "EgrBlocked" },
	{ 4, "EgrVID" },
	{ 0, NULL }
};

static const value_string aps_request_state_vals[] = {
	{ 0,  "No request" },
	{ 1,  "Do not revert" },
	{ 2,  "Reverse request" },
	{ 3,  "Unknown" },
	{ 4,  "Exercise" },
	{ 5,  "Wait to restore" },
	{ 6,  "Depreciated" },
	{ 7,  "Manual switch" },
	{ 8,  "Unknown" },
	{ 9,  "Signal degrade" },
	{ 10, "Unknown" },
	{ 11, "Signal fail for working" },
	{ 12, "Unknown" },
	{ 13, "Forced switch" },
	{ 14, "Signal fail on protection" },
	{ 15, "Lockout of protection" },
	{ 0,  NULL }
};

static const true_false_string tfs_aps_protection_type_A = {
	"APS channel",
	"No APS channel"
};

static const true_false_string tfs_aps_protection_type_B = {
	"1:1 (no permanent bridge)",
	"1+1 (permanent bridge)"
};

static const true_false_string tfs_aps_protection_type_D = {
	"Bidirectional switching",
	"Unidirectional switching"
};

static const true_false_string tfs_aps_protection_type_R = {
	"Revertive operation",
	"Non-revertive operation"
};

static const value_string aps_requested_signal_values[] = {
	{ 0, "Null" },
	{ 1, "Normal traffic" },
	{ 0, NULL }
};

static const value_string aps_bridged_signal_values[] = {
	{ 0, "Null" },
	{ 1, "Normal traffic" },
	{ 0, NULL }
};

static const value_string aps_bridge_type_values[] = {
	{ 0, "Selector" },
	{ 1, "Broadcast" },
	{ 0, NULL }
};

static const value_string raps_request_state_values[] = {
	{ RAPS_REQ_ST_NO_REQ,   "No Request" },
	{ RAPS_REQ_ST_MAN_SW,   "Manual Switch" },
	{ RAPS_REQ_ST_SIG_FAIL, "Signal Fail" },
	{ RAPS_REQ_ST_FCED_SW,  "Forced Switch" },
	{ RAPS_REQ_ST_EVENT,    "Event" },
	{ 0, NULL }
};

static const value_string rasp_event_subcode_vals[] = {
	{ 0, "Flush Request" },
	{ 0, NULL }
};

static const true_false_string tfs_rasp_rpl_blocked = {
	"Blocked",
	"Not Blocked"
};

static const true_false_string tfs_rasp_dnf = {
	"Do Not Flush DB",
	"May Flush DB"
};

static const true_false_string tfs_rasp_bpr = {
	"Ring link 1",
	"Ring link 0"
};

static const value_string gnm_sub_opcode_type_name_vals[] = {
	{ BNM, "Bandwidth Notification Message" },
	{ 0,   NULL }
};

static const value_string cfm_bnm_flags_period_vals[] = {
	{ 0, "Invalid" },
	{ 1, "For further study" },
	{ 2, "For further study" },
	{ 3, "For further study" },
	{ 4, "1s" },
	{ 5, "10s" },
	{ 6, "1 min" },
	{ 7, "Invalid" },
	{ 0, NULL }
};

static const value_string cfm_csf_flags_type_vals[] = {
	{ 0, "LOS" },
	{ 1, "FDI/AIS" },
	{ 2, "RDI" },
	{ 3, "DCI" },
	{ 0, NULL }
};

static const value_string cfm_csf_flags_period_vals[] = {
	{ 0, "Invalid" },
	{ 1, "For further study" },
	{ 2, "For further study" },
	{ 3, "For further study" },
	{ 4, "1s" },
	{ 5, "For further study" },
	{ 6, "1 min" },
	{ 7, "For further study" },
	{ 0, NULL }
};

static const true_false_string tfs_lmm_lmr_type = {
	"Proactive",
	"On-demand"
};

static const true_false_string tfs_odm_dmm_dmr_type = {
	"Proactive",
	"On-demand"
};

static const value_string test_tlv_pattern_type_vals[] = {
	{ 0, "Null signal without CRC-32" },
	{ 1, "Null signal with CRC-32" },
	{ 2, "PRBS (2.e-31 -1), without CRC-32" },
	{ 3, "PRBS (2.e-31 -1), with CRC-32" },
	{ 0, NULL }
};

static const value_string mep_mip_id_tlv_subtype_vals[] = {
	{ 0x00, "Discovery ingress/node MEP/MIP" },
	{ 0x01, "Discovery egress MEP/MIP" },
	{ 0x02, "MEP ID" },
	{ 0x03, "MIP ID" },
	{ 0, NULL }
};

static const value_string req_mep_id_tlv_lb_vals[] = {
	{ 0x00, "LBM PDU" },
	{ 0x01, "LBR PDU" },
	{ 0, NULL }
};


void proto_register_cfm(void);
void proto_reg_handoff_cfm(void);

static int proto_cfm;

static int hf_cfm_md_level;
static int hf_cfm_version;
static int hf_cfm_opcode;
static int hf_cfm_flags;
static int hf_cfm_flags_Reserved;
static int hf_cfm_first_tlv_offset;

static int hf_cfm_mep_id;
static int hf_cfm_maid;
static int hf_cfm_maid_md_name_format;
static int hf_cfm_maid_md_name_length;
static int hf_cfm_maid_md_name_string;
static int hf_cfm_maid_md_name_hex;
static int hf_cfm_maid_md_name_mac;
static int hf_cfm_maid_md_name_mac_id;
static int hf_cfm_maid_ma_name_format;
static int hf_cfm_maid_ma_name_length;
static int hf_cfm_maid_ma_name_pvid;
static int hf_cfm_maid_ma_name_string;
static int hf_cfm_maid_ma_name_id;
static int hf_cfm_maid_ma_name_vpnid_oui;
static int hf_cfm_maid_ma_name_vpnid_index;
static int hf_cfm_maid_ma_name_icc_umc;
static int hf_cfm_maid_ma_name_cc;
static int hf_cfm_maid_ma_name_hex;
static int hf_cfm_maid_padding;

static int hf_cfm_ccm_pdu;
static int hf_cfm_ccm_flags_RDI;
static int hf_cfm_ccm_flags_Traffic;
static int hf_cfm_ccm_flags_Reserved;
static int hf_cfm_ccm_flags_Interval;
static int hf_cfm_ccm_seq_number;
static int hf_cfm_ccm_itu_t_y1731;
static int hf_cfm_ccm_itu_TxFCf;
static int hf_cfm_ccm_itu_RxFCb;
static int hf_cfm_ccm_itu_TxFCb;
static int hf_cfm_ccm_itu_reserved;

static int hf_cfm_lbm_pdu;
static int hf_cfm_lbm_lbr_transaction_id;

static int hf_cfm_lbr_pdu;

static int hf_cfm_ltm_pdu;
static int hf_cfm_ltm_flags_UseFDBonly;
static int hf_cfm_ltm_flags_Reserved;
static int hf_cfm_ltm_ltr_transaction_id;
static int hf_cfm_ltm_ltr_ttl;
static int hf_cfm_ltm_orig_addr;
static int hf_cfm_ltm_targ_addr;

static int hf_cfm_ltr_pdu;
static int hf_cfm_ltr_flags_UseFDBonly;
static int hf_cfm_ltr_flags_FwdYes;
static int hf_cfm_ltr_flags_TerminalMEP;
static int hf_cfm_ltr_flags_Reserved;
static int hf_cfm_ltr_relay_action;

static int hf_cfm_rfm_pdu;
static int hf_cfm_rfm_transaction_id;

static int hf_cfm_sfm_pdu;
static int hf_cfm_sfm_transaction_id;

static int hf_cfm_gnm_pdu;
static int hf_cfm_gnm_unknown_flags;
static int hf_cfm_gnm_subopcode;

static int hf_cfm_bnm_flags_Reserved;
static int hf_cfm_bnm_flags_Period;
static int hf_cfm_bnm_pdu;
static int hf_cfm_bnm_nominal_bw;
static int hf_cfm_bnm_current_bw;
static int hf_cfm_bnm_port_id;

static int hf_cfm_ais_pdu;
static int hf_cfm_ais_flags_Reserved;
static int hf_cfm_ais_flags_Period;

static int hf_cfm_lck_pdu;
static int hf_cfm_lck_flags_Reserved;
static int hf_cfm_lck_flags_Period;

static int hf_cfm_tst_pdu;
static int hf_cfm_tst_sequence_num;

static int hf_cfm_aps_pdu;
static int hf_cfm_aps_req_st;
static int hf_cfm_aps_protection_type_A;
static int hf_cfm_aps_protection_type_B;
static int hf_cfm_aps_protection_type_D;
static int hf_cfm_aps_protection_type_R;
static int hf_cfm_aps_requested_signal;
static int hf_cfm_aps_bridged_signal;
static int hf_cfm_aps_bridge_type;

static int hf_cfm_raps_pdu;
static int hf_cfm_raps_req_st;
static int hf_cfm_raps_event_subcode;
static int hf_cfm_raps_subcode_reserved;
static int hf_cfm_raps_status;
static int hf_cfm_raps_status_rb;
static int hf_cfm_raps_status_dnf;
static int hf_cfm_raps_status_bpr;
static int hf_cfm_raps_status_reserved_v1;
static int hf_cfm_raps_status_reserved_v2;
static int hf_cfm_raps_node_id;
static int hf_cfm_raps_reserved;

static int hf_cfm_mcc_pdu;
static int hf_cfm_mcc_oui;
static int hf_cfm_mcc_subopcode;
static int hf_cfm_mcc_data;

static int hf_cfm_lmm_pdu;
static int hf_cfm_lmm_lmr_flags_Reserved;
static int hf_cfm_lmm_lmr_flags_Type;
static int hf_cfm_lmm_lmr_TxFCf;
static int hf_cfm_lmm_lmr_RxFCf;
static int hf_cfm_lmm_lmr_TxFCb;

static int hf_cfm_lmr_pdu;

static int hf_cfm_odm_pdu;
static int hf_cfm_odm_dmm_dmr_flags_Reserved;
static int hf_cfm_odm_dmm_dmr_flags_Type;
static int hf_cfm_odm_dmm_dmr_TxTimestampf;
static int hf_cfm_odm_dmm_dmr_RxTimestampf;

static int hf_cfm_dmm_pdu;
static int hf_cfm_dmm_dmr_TxTimestampb;
static int hf_cfm_dmm_dmr_RxTimestampb;

static int hf_cfm_dmr_pdu;

static int hf_cfm_exm_pdu;
static int hf_cfm_exm_oui;
static int hf_cfm_exm_subopcode;
static int hf_cfm_exm_data;

static int hf_cfm_exr_pdu;
static int hf_cfm_exr_oui;
static int hf_cfm_exr_subopcode;
static int hf_cfm_exr_data;

static int hf_cfm_vsm_pdu;
static int hf_cfm_vsm_oui;
static int hf_cfm_vsm_subopcode;
static int hf_cfm_vsm_data;

static int hf_cfm_vsr_pdu;
static int hf_cfm_vsr_oui;
static int hf_cfm_vsr_subopcode;
static int hf_cfm_vsr_data;

static int hf_cfm_csf_pdu;
static int hf_cfm_csf_flags_Reserved;
static int hf_cfm_csf_flags_Type;
static int hf_cfm_csf_flags_Period;

static int hf_cfm_osl_pdu;
static int hf_cfm_osl_src_mep;
static int hf_cfm_osl_reserved;
static int hf_cfm_osl_testid;
static int hf_cfm_osl_txfcf;

static int hf_cfm_slm_pdu;
static int hf_cfm_slm_slr_src_mep;
static int hf_cfm_slm_reserved;
static int hf_cfm_slm_slr_testid;
static int hf_cfm_slm_slr_txfcf;

static int hf_cfm_slr_pdu;
static int hf_cfm_slr_rsp_mep;
static int hf_cfm_slr_txfcb;

static int hf_cfm_unknown_pdu;
static int hf_cfm_unknown_flags;
static int hf_cfm_unknown_data;

static int hf_cfm_all_tlvs;
static int hf_cfm_tlv_type;
static int hf_cfm_tlv_length;

static int hf_tlv_chassis_id_length;
static int hf_tlv_chassis_id_subtype;
static int hf_tlv_chassis_id_chassis_component;
static int hf_tlv_chassis_id_interface_alias;
static int hf_tlv_chassis_id_port_component;
static int hf_tlv_chassis_id_mac_address;
static int hf_tlv_chassis_id_network_address_family;
static int hf_tlv_chassis_id_network_address_ipv4;
static int hf_tlv_chassis_id_network_address_ipv6;
static int hf_tlv_chassis_id_network_address_unknown;
static int hf_tlv_chassis_id_interface_name;
static int hf_tlv_chassis_id_locally_assigned;
static int hf_tlv_chassis_id_unknown;
static int hf_tlv_ma_domain_length;
static int hf_tlv_ma_domain;
static int hf_tlv_management_addr_length;
static int hf_tlv_management_addr_ipv4;
static int hf_tlv_management_addr_ipv6;
static int hf_tlv_management_addr_eth;
static int hf_tlv_management_addr_unknown;
static int hf_tlv_port_status_value;
static int hf_tlv_data_value;
static int hf_tlv_interface_status_value;

static int hf_tlv_reply_ingress_action;
static int hf_tlv_reply_ingress_mac_address;
static int hf_tlv_reply_ing_egr_portid_length;
static int hf_tlv_reply_ing_egr_portid_subtype;
static int hf_tlv_reply_ing_egr_portid_interface_alias;
static int hf_tlv_reply_ing_egr_portid_port_component;
static int hf_tlv_reply_ing_egr_portid_mac_address;
static int hf_tlv_reply_ing_egr_portid_network_address_family;
static int hf_tlv_reply_ing_egr_portid_network_address_ipv4;
static int hf_tlv_reply_ing_egr_portid_network_address_ipv6;
static int hf_tlv_reply_ing_egr_portid_network_address_unknown;
static int hf_tlv_reply_ing_egr_portid_interface_name;
static int hf_tlv_reply_ing_egr_portid_agent_circuit_id;
static int hf_tlv_reply_ing_egr_portid_locally_assigned;
static int hf_tlv_reply_ing_egr_portid_unknown;
static int hf_tlv_reply_egress_action;
static int hf_tlv_reply_egress_mac_address;

static int hf_tlv_ltr_egress_last_id_mac;
static int hf_tlv_ltr_egress_last_id_unique_identifier;
static int hf_tlv_ltr_egress_next_id_mac;
static int hf_tlv_ltr_egress_next_id_unique_identifier;
static int hf_tlv_ltm_egress_id_mac;
static int hf_tlv_ltm_egress_id_unique_identifier;

static int hf_tlv_pbb_te_mip_mac_address;
static int hf_tlv_pbb_te_reverse_vid;
static int hf_tlv_pbb_te_reverse_mac;

static int hf_tlv_org_spec_oui;
static int hf_tlv_org_spec_subtype;
static int hf_tlv_org_spec_value;
static int hf_tlv_tst_test_pattern_type;
static int hf_tlv_tst_test_pattern;
static int hf_tlv_tst_CRC32;

static int hf_tlv_tgt_rpl_mep_mip_id_subtype;
static int hf_tlv_tgt_rpl_padding;
static int hf_tlv_tgt_rpl_mep_id;
static int hf_tlv_tgt_rpl_mip_id_icc;
static int hf_tlv_tgt_rpl_mip_id_node_id;
static int hf_tlv_tgt_rpl_mip_id_if_num;
static int hf_tlv_tgt_rpl_mip_id_cc;

static int hf_tlv_req_mep_id_lb;
static int hf_tlv_req_mep_id_reserved;

static int hf_tlv_tst_id_test_id;

static int hf_tlv_unknown_data;

static int ett_cfm;
static int ett_cfm_pdu;
static int ett_cfm_flags;
static int ett_cfm_maid;
static int ett_cfm_ccm_itu;
static int ett_cfm_all_tlvs;
static int ett_cfm_tlv;
static int ett_cfm_raps_status;

static expert_field ei_tlv_tst_id_length;
static expert_field ei_tlv_management_addr_length;

static dissector_handle_t cfm_handle;

/* CFM EOAM sub-protocol dissectors */

static int dissect_mep_maid(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_tree *cfm_maid_tree;

	int maid_offset;

	uint32_t maid_md_name_format;
	uint32_t maid_ma_name_format;
	uint32_t maid_ma_name_length;


	proto_tree_add_item(tree, hf_cfm_mep_id, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	ti = proto_tree_add_item(tree, hf_cfm_maid, tvb, offset, 48, ENC_NA);
	cfm_maid_tree = proto_item_add_subtree(ti, ett_cfm_maid);
	maid_offset = offset;
	proto_tree_add_item_ret_uint(cfm_maid_tree, hf_cfm_maid_md_name_format, tvb, maid_offset, 1, ENC_NA, &maid_md_name_format);
	maid_offset += 1;

	if (maid_md_name_format != MD_NAME_FMT_NONE) {  // NOTE: true for IEEE 802.1Q CCM only
		uint8_t maid_md_name_length;
		proto_tree_add_item(cfm_maid_tree, hf_cfm_maid_md_name_length,
				tvb, maid_offset, 1, ENC_NA);
		maid_md_name_length = tvb_get_uint8(tvb, maid_offset);
		maid_offset += 1;
		if (maid_md_name_length) {  // NOTE: Between 1 and 43
			switch (maid_md_name_format) {
			case MD_NAME_FMT_MAC_ID:
				if (maid_md_name_length != 8) {
					proto_tree_add_item(cfm_maid_tree, hf_cfm_maid_md_name_hex,
						tvb, maid_offset, maid_md_name_length, ENC_NA);
				} else {
					proto_tree_add_item(cfm_maid_tree, hf_cfm_maid_md_name_mac,
						tvb, maid_offset, 6, ENC_NA);
					proto_tree_add_item(cfm_maid_tree, hf_cfm_maid_md_name_mac_id,
						tvb, maid_offset + 6, 2, ENC_NA);
				}
				break;
			case MD_NAME_FMT_DOMAIN:
			case MD_NAME_FMT_STRING:
				proto_tree_add_item(cfm_maid_tree, hf_cfm_maid_md_name_string,
					tvb, maid_offset, maid_md_name_length, ENC_ASCII|ENC_NA);
				break;
			default:
				proto_tree_add_item(cfm_maid_tree, hf_cfm_maid_md_name_hex,
					tvb, maid_offset, maid_md_name_length, ENC_NA);
				break;
			}
			maid_offset += maid_md_name_length;
		}
	}
	proto_tree_add_item_ret_uint(cfm_maid_tree, hf_cfm_maid_ma_name_format, tvb, maid_offset, 1, ENC_NA, &maid_ma_name_format);
	maid_offset += 1;
	proto_tree_add_item_ret_uint(cfm_maid_tree, hf_cfm_maid_ma_name_length, tvb, maid_offset, 1, ENC_NA, &maid_ma_name_length);
	maid_offset += 1;

	switch (maid_ma_name_format) {
	case MA_NAME_FMT_RESVD:
		proto_tree_add_item(cfm_maid_tree, hf_cfm_maid_ma_name_hex,
			tvb, maid_offset, maid_ma_name_length, ENC_NA);
		break;
	case MA_NAME_FMT_PVID:
		if (maid_ma_name_length != 2) {
			proto_tree_add_item(cfm_maid_tree, hf_cfm_maid_ma_name_hex,
				tvb, maid_offset, maid_ma_name_length, ENC_NA);
		} else {
			proto_tree_add_item(cfm_maid_tree, hf_cfm_maid_ma_name_pvid,
				tvb, maid_offset, 2, ENC_NA);
		}
		break;
	case MA_NAME_FMT_STRING:
		proto_tree_add_item(cfm_maid_tree, hf_cfm_maid_ma_name_string,
			tvb, maid_offset, maid_ma_name_length, ENC_ASCII|ENC_NA);
		break;
	case MA_NAME_FMT_ID:
		if (maid_ma_name_length != 2) {
			proto_tree_add_item(cfm_maid_tree, hf_cfm_maid_ma_name_hex,
				tvb, maid_offset, maid_ma_name_length, ENC_NA);
		} else {
			proto_tree_add_item(cfm_maid_tree, hf_cfm_maid_ma_name_id,
				tvb, maid_offset, 2, ENC_NA);
		}
		break;
	case MA_NAME_FMT_VPN_ID:
		if (maid_ma_name_length != 7) {
			proto_tree_add_item(cfm_maid_tree, hf_cfm_maid_ma_name_hex,
				tvb, maid_offset, maid_ma_name_length, ENC_NA);
		} else {
			proto_tree_add_item(cfm_maid_tree, hf_cfm_maid_ma_name_vpnid_oui,
				tvb, maid_offset, 3, ENC_NA);
			proto_tree_add_item(cfm_maid_tree, hf_cfm_maid_ma_name_vpnid_index,
				tvb, maid_offset + 3, 4, ENC_NA);
		}
		break;
	case MA_NAME_FMT_ICC:
		if (maid_ma_name_length != 13) {
			proto_tree_add_item(cfm_maid_tree, hf_cfm_maid_ma_name_hex,
				tvb, maid_offset, maid_ma_name_length, ENC_NA);
		} else {
			proto_tree_add_item(cfm_maid_tree, hf_cfm_maid_ma_name_icc_umc,
				tvb, maid_offset, 13, ENC_ASCII|ENC_NA);
		}
		break;
	case MA_NAME_FMT_ICC_CC:
		if (maid_ma_name_length != 15) {
			proto_tree_add_item(cfm_maid_tree, hf_cfm_maid_ma_name_hex,
				tvb, maid_offset, maid_ma_name_length, ENC_NA);
		} else {
			proto_tree_add_item(cfm_maid_tree, hf_cfm_maid_ma_name_cc,
				tvb, maid_offset, 2, ENC_ASCII|ENC_NA);
			proto_tree_add_item(cfm_maid_tree, hf_cfm_maid_ma_name_icc_umc,
				tvb, maid_offset + 2, 13, ENC_ASCII|ENC_NA);
		}
		break;
	default:
		proto_tree_add_item(cfm_maid_tree, hf_cfm_maid_ma_name_hex,
			tvb, maid_offset, maid_ma_name_length, ENC_NA);
		break;
	}

	maid_offset += maid_ma_name_length;
	offset += 48;
	if (offset > maid_offset) {
		int padding_length;
		padding_length = offset - maid_offset;
		proto_tree_add_item(cfm_maid_tree, hf_cfm_maid_padding,
			tvb, maid_offset, padding_length, ENC_NA);
	}

	return offset;
}

static int dissect_cfm_ccm(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        length_remaining;

	proto_item *wi;
	proto_tree *cfm_ccm_itu_tree;

	ti = proto_tree_add_item(tree, hf_cfm_ccm_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_ccm_flags_RDI, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_ccm_flags_Traffic, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_ccm_flags_Reserved, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_ccm_flags_Interval, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_ccm_seq_number, tvb, offset, 4, ENC_BIG_ENDIAN);  // NOTE: Zero in Y.1731
	offset += 4;

	/* dissect CCM MEP ID + MAID */
	offset = dissect_mep_maid(tvb, pinfo, cfm_pdu_tree, offset);

	/* Dissect 16 octets reserved for Y.1731, samples of the wrap-around frame counters */
	wi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_ccm_itu_t_y1731, tvb, offset, 16, ENC_NA);
	cfm_ccm_itu_tree = proto_item_add_subtree(wi, ett_cfm_ccm_itu);
	proto_tree_add_item(cfm_ccm_itu_tree, hf_cfm_ccm_itu_TxFCf, tvb, offset, 4, ENC_NA);
	offset += 4;
	proto_tree_add_item(cfm_ccm_itu_tree, hf_cfm_ccm_itu_RxFCb, tvb, offset, 4, ENC_NA);
	offset += 4;
	proto_tree_add_item(cfm_ccm_itu_tree, hf_cfm_ccm_itu_TxFCb, tvb, offset, 4, ENC_NA);
	offset += 4;
	proto_tree_add_item(cfm_ccm_itu_tree, hf_cfm_ccm_itu_reserved, tvb, offset, 4, ENC_NA);
	offset += 4;

	length_remaining = first_tlv_offset - (offset - (start_offset + 2));

	if (length_remaining > 0) {
		proto_tree_add_item(cfm_pdu_tree, hf_cfm_unknown_data, tvb, offset, length_remaining, ENC_NA);
		offset += length_remaining;
	}

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

static int dissect_cfm_lbm(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        length_remaining;

	ti = proto_tree_add_item(tree, hf_cfm_lbm_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_flags_Reserved, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_lbm_lbr_transaction_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	length_remaining = first_tlv_offset - (offset - (start_offset + 2));

	if (length_remaining > 0) {
		proto_tree_add_item(cfm_pdu_tree, hf_cfm_unknown_data, tvb, offset, length_remaining, ENC_NA);
		offset += length_remaining;
	}

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

static int dissect_cfm_lbr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        length_remaining;

	ti = proto_tree_add_item(tree, hf_cfm_lbr_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_flags_Reserved, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_lbm_lbr_transaction_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	length_remaining = first_tlv_offset - (offset - (start_offset + 2));

	if (length_remaining > 0) {
		proto_tree_add_item(cfm_pdu_tree, hf_cfm_unknown_data, tvb, offset, length_remaining, ENC_NA);
		offset += length_remaining;
	}

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

static int dissect_cfm_ltm(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        length_remaining;

	ti = proto_tree_add_item(tree, hf_cfm_ltm_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_ltm_flags_UseFDBonly, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_ltm_flags_Reserved, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_ltm_ltr_transaction_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_ltm_ltr_ttl, tvb, offset, 1, ENC_NA);
	offset += 1;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_ltm_orig_addr, tvb, offset, 6, ENC_NA);
	offset += 6;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_ltm_targ_addr, tvb, offset, 6, ENC_NA);
	offset += 6;

	length_remaining = first_tlv_offset - (offset - (start_offset + 2));

	if (length_remaining > 0) {
		proto_tree_add_item(cfm_pdu_tree, hf_cfm_unknown_data, tvb, offset, length_remaining, ENC_NA);
		offset += length_remaining;
	}

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

static int dissect_cfm_ltr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        length_remaining;

	ti = proto_tree_add_item(tree, hf_cfm_ltr_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_ltr_flags_UseFDBonly, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_ltr_flags_FwdYes, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_ltr_flags_TerminalMEP, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_ltr_flags_Reserved, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_ltm_ltr_transaction_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_ltm_ltr_ttl, tvb, offset, 1, ENC_NA);
	offset += 1;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_ltr_relay_action, tvb, offset, 1, ENC_NA);
	offset += 1;

	length_remaining = first_tlv_offset - (offset - (start_offset + 2));

	if (length_remaining > 0) {
		proto_tree_add_item(cfm_pdu_tree, hf_cfm_unknown_data, tvb, offset, length_remaining, ENC_NA);
		offset += length_remaining;
	}

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

static int dissect_cfm_rfm(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        length_remaining;

	ti = proto_tree_add_item(tree, hf_cfm_rfm_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_flags_Reserved, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_rfm_transaction_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	length_remaining = first_tlv_offset - (offset - (start_offset + 2));

	if (length_remaining > 0) {
		proto_tree_add_item(cfm_pdu_tree, hf_cfm_unknown_data, tvb, offset, length_remaining, ENC_NA);
		offset += length_remaining;
	}

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

static int dissect_cfm_sfm(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        length_remaining;

	ti = proto_tree_add_item(tree, hf_cfm_sfm_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_flags_Reserved, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_sfm_transaction_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	length_remaining = first_tlv_offset - (offset - (start_offset + 2));

	if (length_remaining > 0) {
		proto_tree_add_item(cfm_pdu_tree, hf_cfm_unknown_data, tvb, offset, length_remaining, ENC_NA);
		offset += length_remaining;
	}

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

static int dissect_cfm_bnm(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        length_remaining;

	ti = proto_tree_add_item(tree, hf_cfm_bnm_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_bnm_flags_Reserved, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_bnm_flags_Period, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_gnm_subopcode, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_bnm_nominal_bw, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_bnm_current_bw, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_bnm_port_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	length_remaining = first_tlv_offset - (offset - (start_offset + 2));

	if (length_remaining > 0) {
		proto_tree_add_item(cfm_pdu_tree, hf_cfm_unknown_data, tvb, offset, length_remaining, ENC_NA);
		offset += length_remaining;
	}

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

static int dissect_cfm_gnm_unknown(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        length_remaining;

	ti = proto_tree_add_item(tree, hf_cfm_gnm_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_gnm_unknown_flags, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_gnm_subopcode, tvb, offset, 1, ENC_NA);
	offset += 1;

	length_remaining = first_tlv_offset - (offset - (start_offset + 2));

	if (length_remaining > 0) {
		proto_tree_add_item(cfm_pdu_tree, hf_cfm_unknown_data, tvb, offset, length_remaining, ENC_NA);
		offset += length_remaining;
	}

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

static int dissect_cfm_gnm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	uint8_t cfm_gnm_pdu_type = tvb_get_uint8(tvb, offset + 4);

	switch (cfm_gnm_pdu_type) {
	case BNM:
		offset = dissect_cfm_bnm(tvb, pinfo, tree, offset);
		break;
	default:
		offset = dissect_cfm_gnm_unknown(tvb, pinfo, tree, offset);
		break;
	}

	return offset;
}

static int dissect_cfm_ais(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        length_remaining;

	ti = proto_tree_add_item(tree, hf_cfm_ais_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_ais_flags_Reserved, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_ais_flags_Period, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	length_remaining = first_tlv_offset - (offset - (start_offset + 2));

	if (length_remaining > 0) {
		proto_tree_add_item(cfm_pdu_tree, hf_cfm_unknown_data, tvb, offset, length_remaining, ENC_NA);
		offset += length_remaining;
	}

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

static int dissect_cfm_lck(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        length_remaining;

	ti = proto_tree_add_item(tree, hf_cfm_lck_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_lck_flags_Reserved, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_lck_flags_Period, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	length_remaining = first_tlv_offset - (offset - (start_offset + 2));

	if (length_remaining > 0) {
		proto_tree_add_item(cfm_pdu_tree, hf_cfm_unknown_data, tvb, offset, length_remaining, ENC_NA);
		offset += length_remaining;
	}

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

static int dissect_cfm_tst(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        length_remaining;

	ti = proto_tree_add_item(tree, hf_cfm_tst_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_flags_Reserved, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_tst_sequence_num, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	length_remaining = first_tlv_offset - (offset - (start_offset + 2));

	if (length_remaining > 0) {
		proto_tree_add_item(cfm_pdu_tree, hf_cfm_unknown_data, tvb, offset, length_remaining, ENC_NA);
		offset += length_remaining;
	}

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

static int dissect_cfm_aps(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        length_remaining;

	ti = proto_tree_add_item(tree, hf_cfm_aps_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_flags_Reserved, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_aps_req_st, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_aps_protection_type_A, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_aps_protection_type_B, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_aps_protection_type_D, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_aps_protection_type_R, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_aps_requested_signal, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_aps_bridged_signal, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_aps_bridge_type, tvb, offset, 1, ENC_NA);
	offset += 1;

	length_remaining = first_tlv_offset - (offset - (start_offset + 2));

	if (length_remaining > 0) {
		proto_tree_add_item(cfm_pdu_tree, hf_cfm_unknown_data, tvb, offset, length_remaining, ENC_NA);
		offset += length_remaining;
	}

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

static int dissect_cfm_raps(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        length_remaining;

	unsigned version;
	uint32_t raps_requeststate;
	proto_item *ri;
	proto_tree *raps_status_tree;

	ti = proto_tree_add_item(tree, hf_cfm_raps_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_flags_Reserved, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_raps_req_st, tvb, offset, 1, ENC_NA, &raps_requeststate);

	version = (tvb_get_uint8(tvb, CFM_LEVEL_VERSION_OFFSET) & CFM_VERSION_MASK) >> CFM_VERSION_SHIFT;

	if (version == 1 && raps_requeststate == RAPS_REQ_ST_EVENT) {
		proto_tree_add_item(cfm_pdu_tree, hf_cfm_raps_event_subcode, tvb, offset, 1, ENC_NA);
	} else {
		proto_tree_add_item(cfm_pdu_tree, hf_cfm_raps_subcode_reserved, tvb, offset, 1, ENC_NA);
	}

	offset += 1;

	ri = proto_tree_add_item(cfm_pdu_tree, hf_cfm_raps_status, tvb, offset, 1, ENC_NA);
	raps_status_tree = proto_item_add_subtree(ri, ett_cfm_raps_status);
	proto_tree_add_item(raps_status_tree, hf_cfm_raps_status_rb, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(raps_status_tree, hf_cfm_raps_status_dnf, tvb, offset, 1, ENC_NA);

	/* R-APS(G.8032) v2 only */
	if (version == 1) {
		proto_tree_add_item(raps_status_tree, hf_cfm_raps_status_bpr, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(raps_status_tree, hf_cfm_raps_status_reserved_v2, tvb, offset, 1, ENC_NA);
	} else {
		proto_tree_add_item(raps_status_tree, hf_cfm_raps_status_reserved_v1, tvb, offset, 1, ENC_NA);
	}

	offset += 1;

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_raps_node_id, tvb, offset, 6, ENC_NA);
	offset += 6;

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_raps_reserved, tvb, offset, 24, ENC_NA);
	offset += 24;

	length_remaining = first_tlv_offset - (offset - (start_offset + 2));

	if (length_remaining > 0) {
		proto_tree_add_item(cfm_pdu_tree, hf_cfm_unknown_data, tvb, offset, length_remaining, ENC_NA);
		offset += length_remaining;
	}

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

static int find_end_tlv(tvbuff_t *tvb, int first_tlv_offset)
{
	/*
	 * XXX - how to handle TLVs in MCC, EXM, EXR, VSM or VSR PDU data?
	 * The TLV Offset points to the first TLV, which may part of PDU Data, therefore defined
	 * 'outside the scope of this standard'. Therefore these cannot be simply handed off the
	 * standard TLV dissection functions. We do however want to find the End TLV.
	 * All we can do is iterate over these unknown TLVs, under the assumption they use the
	 * same format as defined in this standard, until we find the End TLV.
	 * Don't break dissection if we can't find it this way, e.g. when the captured frame is
	 * cut short. Then assume all remaining captured frame data is PDU data.
	 */

	int tlv_tvb_offset = CFM_COMMON_HEADER_LEN + first_tlv_offset;
	for (;;) {
		// Does a tag exist in the captured data?
		if (tvb_bytes_exist(tvb, tlv_tvb_offset, 1)) {
			// Is this the End TLV
			if (tvb_get_uint8(tvb, tlv_tvb_offset)) {
				// Following the tag, does the length exist in the captured data?
				if (tvb_captured_length_remaining(tvb, tlv_tvb_offset) < 3) {
					tlv_tvb_offset = 0;
					break;
				}
				// Go to the next tag
				tlv_tvb_offset += tvb_get_ntohs(tvb, tlv_tvb_offset + 1) + 3;
			} else {
				break; // we found the END_TLV
			}
		} else {
			tlv_tvb_offset = 0;
			break;
		}
	}

	return tlv_tvb_offset;
}

static int dissect_cfm_mcc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        tlv_tvb_offset;

	ti = proto_tree_add_item(tree, hf_cfm_mcc_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_flags_Reserved, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	/* XXX - Introducing a dissector table would allow to register subdissectors based on
	 * their subopcode, per OUI. The OUI table creation would be similar to the registration
	 * function in the IEEE 802a dissector.
	 */

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_mcc_oui, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset += 3;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_mcc_subopcode, tvb, offset, 1, ENC_NA);
	offset += 1;

	tlv_tvb_offset = find_end_tlv(tvb, first_tlv_offset);

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_mcc_data, tvb, offset, (tlv_tvb_offset) ? (tlv_tvb_offset - offset) : -1, ENC_NA);
	offset = (tlv_tvb_offset) ? tlv_tvb_offset : (int)tvb_captured_length(tvb);

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

static int dissect_cfm_lmm(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        length_remaining;

	ti = proto_tree_add_item(tree, hf_cfm_lmm_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_lmm_lmr_flags_Reserved, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_lmm_lmr_flags_Type, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_lmm_lmr_TxFCf, tvb, offset, 4, ENC_NA);
	offset += 4;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_lmm_lmr_RxFCf, tvb, offset, 4, ENC_NA);
	offset += 4;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_lmm_lmr_TxFCb, tvb, offset, 4, ENC_NA);
	offset += 4;

	length_remaining = first_tlv_offset - (offset - (start_offset + 2));

	if (length_remaining > 0) {
		proto_tree_add_item(cfm_pdu_tree, hf_cfm_unknown_data, tvb, offset, length_remaining, ENC_NA);
		offset += length_remaining;
	}

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

static int dissect_cfm_lmr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        length_remaining;

	ti = proto_tree_add_item(tree, hf_cfm_lmr_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_lmm_lmr_flags_Reserved, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_lmm_lmr_flags_Type, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_lmm_lmr_TxFCf, tvb, offset, 4, ENC_NA);
	offset += 4;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_lmm_lmr_RxFCf, tvb, offset, 4, ENC_NA);
	offset += 4;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_lmm_lmr_TxFCb, tvb, offset, 4, ENC_NA);
	offset += 4;

	length_remaining = first_tlv_offset - (offset - (start_offset + 2));

	if (length_remaining > 0) {
		proto_tree_add_item(cfm_pdu_tree, hf_cfm_unknown_data, tvb, offset, length_remaining, ENC_NA);
		offset += length_remaining;
	}

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

static int dissect_cfm_odm(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        length_remaining;

	ti = proto_tree_add_item(tree, hf_cfm_odm_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_odm_dmm_dmr_flags_Reserved, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_odm_dmm_dmr_flags_Type, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_odm_dmm_dmr_TxTimestampf, tvb, offset, 8, ENC_TIME_SECS_NSECS|ENC_BIG_ENDIAN);
	offset += 8;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_odm_dmm_dmr_RxTimestampf, tvb, offset, 8, ENC_TIME_SECS_NSECS|ENC_BIG_ENDIAN);
	offset += 8;

	length_remaining = first_tlv_offset - (offset - (start_offset + 2));

	if (length_remaining > 0) {
		proto_tree_add_item(cfm_pdu_tree, hf_cfm_unknown_data, tvb, offset, length_remaining, ENC_NA);
		offset += length_remaining;
	}

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

static int dissect_cfm_dmm(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        length_remaining;

	ti = proto_tree_add_item(tree, hf_cfm_dmm_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_odm_dmm_dmr_flags_Reserved, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_odm_dmm_dmr_flags_Type, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_odm_dmm_dmr_TxTimestampf, tvb, offset, 8, ENC_TIME_SECS_NSECS|ENC_BIG_ENDIAN);
	offset += 8;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_odm_dmm_dmr_RxTimestampf, tvb, offset, 8, ENC_TIME_SECS_NSECS|ENC_BIG_ENDIAN);
	offset += 8;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_dmm_dmr_TxTimestampb, tvb, offset, 8, ENC_TIME_SECS_NSECS|ENC_BIG_ENDIAN);
	offset += 8;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_dmm_dmr_RxTimestampb, tvb, offset, 8, ENC_TIME_SECS_NSECS|ENC_BIG_ENDIAN);
	offset += 8;

	length_remaining = first_tlv_offset - (offset - (start_offset + 2));

	if (length_remaining > 0) {
		proto_tree_add_item(cfm_pdu_tree, hf_cfm_unknown_data, tvb, offset, length_remaining, ENC_NA);
		offset += length_remaining;
	}

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

static int dissect_cfm_dmr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        length_remaining;

	ti = proto_tree_add_item(tree, hf_cfm_dmr_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_odm_dmm_dmr_flags_Reserved, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_odm_dmm_dmr_flags_Type, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_odm_dmm_dmr_TxTimestampf, tvb, offset, 8, ENC_TIME_SECS_NSECS|ENC_BIG_ENDIAN);
	offset += 8;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_odm_dmm_dmr_RxTimestampf, tvb, offset, 8, ENC_TIME_SECS_NSECS|ENC_BIG_ENDIAN);
	offset += 8;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_dmm_dmr_TxTimestampb, tvb, offset, 8, ENC_TIME_SECS_NSECS|ENC_BIG_ENDIAN);
	offset += 8;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_dmm_dmr_RxTimestampb, tvb, offset, 8, ENC_TIME_SECS_NSECS|ENC_BIG_ENDIAN);
	offset += 8;

	length_remaining = first_tlv_offset - (offset - (start_offset + 2));

	if (length_remaining > 0) {
		proto_tree_add_item(cfm_pdu_tree, hf_cfm_unknown_data, tvb, offset, length_remaining, ENC_NA);
		offset += length_remaining;
	}

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

static int dissect_cfm_exm(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        tlv_tvb_offset;

	ti = proto_tree_add_item(tree, hf_cfm_exm_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_flags_Reserved, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	/* XXX - Introducing a dissector table would allow to register subdissectors based on
	 * their subopcode, per OUI. The OUI table creation would be similar to the registration
	 * function in the IEEE 802a dissector.
	 */

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_exm_oui, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset += 3;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_exm_subopcode, tvb, offset, 1, ENC_NA);
	offset += 1;

	tlv_tvb_offset = find_end_tlv(tvb, first_tlv_offset);

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_exm_data, tvb, offset, (tlv_tvb_offset) ? (tlv_tvb_offset - offset) : -1, ENC_NA);
	offset = (tlv_tvb_offset) ? tlv_tvb_offset : (int)tvb_captured_length(tvb);

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

static int dissect_cfm_exr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        tlv_tvb_offset;

	ti = proto_tree_add_item(tree, hf_cfm_exr_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_flags_Reserved, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	/* XXX - Introducing a dissector table would allow to register subdissectors based on
	 * their subopcode, per OUI. The OUI table creation would be similar to the registration
	 * function in the IEEE 802a dissector.
	 */

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_exr_oui, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset += 3;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_exr_subopcode, tvb, offset, 1, ENC_NA);
	offset += 1;

	tlv_tvb_offset = find_end_tlv(tvb, first_tlv_offset);

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_exr_data, tvb, offset, (tlv_tvb_offset) ? (tlv_tvb_offset - offset) : -1, ENC_NA);
	offset = (tlv_tvb_offset) ? tlv_tvb_offset : (int)tvb_captured_length(tvb);

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

static int dissect_cfm_vsm(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        tlv_tvb_offset;

	ti = proto_tree_add_item(tree, hf_cfm_vsm_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_flags_Reserved, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	/* XXX - Introducing a dissector table would allow to register subdissectors based on
	 * their subopcode, per OUI. The OUI table creation would be similar to the registration
	 * function in the IEEE 802a dissector.
	 */

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_vsm_oui, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset += 3;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_vsm_subopcode, tvb, offset, 1, ENC_NA);
	offset += 1;

	tlv_tvb_offset = find_end_tlv(tvb, first_tlv_offset);

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_vsm_data, tvb, offset, (tlv_tvb_offset) ? (tlv_tvb_offset - offset) : -1, ENC_NA);
	offset = (tlv_tvb_offset) ? tlv_tvb_offset : (int)tvb_captured_length(tvb);

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

static int dissect_cfm_vsr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        tlv_tvb_offset;

	ti = proto_tree_add_item(tree, hf_cfm_vsr_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_flags_Reserved, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	/* XXX - Introducing a dissector table would allow to register subdissectors based on
	 * their subopcode, per OUI. The OUI table creation would be similar to the registration
	 * function in the IEEE 802a dissector.
	 */

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_vsr_oui, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset += 3;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_vsr_subopcode, tvb, offset, 1, ENC_NA);
	offset += 1;

	tlv_tvb_offset = find_end_tlv(tvb, first_tlv_offset);

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_vsr_data, tvb, offset, (tlv_tvb_offset) ? (tlv_tvb_offset - offset) : -1, ENC_NA);
	offset = (tlv_tvb_offset) ? tlv_tvb_offset : (int)tvb_captured_length(tvb);

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

static int dissect_cfm_csf(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        length_remaining;

	ti = proto_tree_add_item(tree, hf_cfm_csf_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_csf_flags_Reserved, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_csf_flags_Type, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_csf_flags_Period, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	length_remaining = first_tlv_offset - (offset - (start_offset + 2));

	if (length_remaining > 0) {
		proto_tree_add_item(cfm_pdu_tree, hf_cfm_unknown_data, tvb, offset, length_remaining, ENC_NA);
		offset += length_remaining;
	}

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

static int dissect_cfm_osl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        length_remaining;

	ti = proto_tree_add_item(tree, hf_cfm_osl_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_flags_Reserved, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_osl_src_mep, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_osl_reserved, tvb, offset, 2, ENC_NA);
	offset += 2;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_osl_testid, tvb, offset, 4, ENC_NA);
	offset += 4;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_osl_txfcf, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_osl_reserved, tvb, offset, 4, ENC_NA);
	offset += 4;

	length_remaining = first_tlv_offset - (offset - (start_offset + 2));

	if (length_remaining > 0) {
		proto_tree_add_item(cfm_pdu_tree, hf_cfm_unknown_data, tvb, offset, length_remaining, ENC_NA);
		offset += length_remaining;
	}

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

static int dissect_cfm_slm(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        length_remaining;

	ti = proto_tree_add_item(tree, hf_cfm_slm_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_flags_Reserved, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_slm_slr_src_mep, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_slm_reserved, tvb, offset, 2, ENC_NA);
	offset += 2;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_slm_slr_testid, tvb, offset, 4, ENC_NA);
	offset += 4;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_slm_slr_txfcf, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_slm_reserved, tvb, offset, 4, ENC_NA);
	offset += 4;

	length_remaining = first_tlv_offset - (offset - (start_offset + 2));

	if (length_remaining > 0) {
		proto_tree_add_item(cfm_pdu_tree, hf_cfm_unknown_data, tvb, offset, length_remaining, ENC_NA);
		offset += length_remaining;
	}

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

static int dissect_cfm_slr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        length_remaining;

	ti = proto_tree_add_item(tree, hf_cfm_slr_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_flags_Reserved, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	proto_tree_add_item(cfm_pdu_tree, hf_cfm_slm_slr_src_mep, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_slr_rsp_mep, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_slm_slr_testid, tvb, offset, 4, ENC_NA);
	offset += 4;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_slm_slr_txfcf, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(cfm_pdu_tree, hf_cfm_slr_txfcb, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	length_remaining = first_tlv_offset - (offset - (start_offset + 2));

	if (length_remaining > 0) {
		proto_tree_add_item(cfm_pdu_tree, hf_cfm_unknown_data, tvb, offset, length_remaining, ENC_NA);
		offset += length_remaining;
	}

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

static int dissect_cfm_unknown(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_item *fi;
	proto_tree *cfm_pdu_tree;
	proto_tree *cfm_flag_tree;
	uint32_t   first_tlv_offset;
	int        start_offset = offset;
	int        length_remaining;

	ti = proto_tree_add_item(tree, hf_cfm_unknown_pdu, tvb, offset, -1, ENC_NA);
	cfm_pdu_tree = proto_item_add_subtree(ti, ett_cfm_pdu);

	fi = proto_tree_add_item(cfm_pdu_tree, hf_cfm_flags, tvb, offset, 1, ENC_NA);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_unknown_flags, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(cfm_pdu_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, ENC_NA, &first_tlv_offset);
	offset += 1;

	length_remaining = first_tlv_offset - (offset - (start_offset + 2));

	if (length_remaining > 0) {
		proto_tree_add_item(cfm_pdu_tree, hf_cfm_unknown_data, tvb, offset, length_remaining, ENC_NA);
		offset += length_remaining;
	}

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}

/* Inspired by packet-lldp.c:dissect_lldp_chassis_id() */
static int sender_id_tlv_chassis_id(proto_tree *cfm_tlv_tree, tvbuff_t *tvb, int tlv_data_offset, uint8_t tlv_chassis_id_length)
{
	proto_tree_add_item(cfm_tlv_tree, hf_tlv_chassis_id_subtype, tvb, tlv_data_offset, 1, ENC_NA);
	uint8_t chassis_id_subtype = tvb_get_uint8(tvb, tlv_data_offset);
	tlv_data_offset += 1;
	tlv_chassis_id_length -= 1;

	switch (chassis_id_subtype) {
	case 1:
		proto_tree_add_item(cfm_tlv_tree, hf_tlv_chassis_id_chassis_component, tvb, tlv_data_offset, tlv_chassis_id_length, ENC_UTF_8);
		break;
	case 2:
		proto_tree_add_item(cfm_tlv_tree, hf_tlv_chassis_id_interface_alias, tvb, tlv_data_offset, tlv_chassis_id_length, ENC_UTF_8);
		break;
	case 3:
		proto_tree_add_item(cfm_tlv_tree, hf_tlv_chassis_id_port_component, tvb, tlv_data_offset, tlv_chassis_id_length, ENC_NA);
		break;
	case 4:
		proto_tree_add_item(cfm_tlv_tree, hf_tlv_chassis_id_mac_address, tvb, tlv_data_offset, tlv_chassis_id_length, ENC_NA);
		break;
	case 5:
		proto_tree_add_item(cfm_tlv_tree, hf_tlv_chassis_id_network_address_family, tvb, tlv_data_offset, 1, ENC_NA);

		switch (tvb_get_uint8(tvb, tlv_data_offset)) {
		case AFNUM_INET:
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_chassis_id_network_address_ipv4, tvb, tlv_data_offset+1, tlv_chassis_id_length-1, ENC_BIG_ENDIAN);
			break;
		case AFNUM_INET6:
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_chassis_id_network_address_ipv6, tvb, tlv_data_offset+1, tlv_chassis_id_length-1, ENC_NA);
			break;
		default:
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_chassis_id_network_address_unknown, tvb, tlv_data_offset+1, tlv_chassis_id_length-1, ENC_NA);
			break;
		}
		break;
	case 6:
		proto_tree_add_item(cfm_tlv_tree, hf_tlv_chassis_id_interface_name, tvb, tlv_data_offset, tlv_chassis_id_length, ENC_UTF_8);
		break;
	case 7:
		proto_tree_add_item(cfm_tlv_tree, hf_tlv_chassis_id_locally_assigned, tvb, tlv_data_offset, tlv_chassis_id_length, ENC_UTF_8);
		break;
	default:
		proto_tree_add_item(cfm_tlv_tree, hf_tlv_chassis_id_unknown, tvb, tlv_data_offset, tlv_chassis_id_length, ENC_NA);
		break;
	}

	tlv_data_offset += tlv_chassis_id_length;

	return tlv_data_offset;
}

static int sender_id_tlv_management_address(proto_tree *cfm_tlv_tree, tvbuff_t *tvb, void *tlv_ma_domain_oid, uint8_t tlv_ma_domain_length, int tlv_data_offset, uint8_t tlv_management_addr_length)
{
	struct {
		const uint8_t *oid;  // BER encoded
		const size_t oid_length;
		const int *header_field;
		const int encoding;
	} management_address_type[] = {
		// transportDomainUdpIpv4 : 1.3.6.1.2.1.100.1.1
		{ (const uint8_t[]){ 0x2B, 0x06, 0x01, 0x02, 0x01, 0x64, 0x01, 0x01 }, 8, &hf_tlv_management_addr_ipv4, ENC_BIG_ENDIAN },
		// transportDomainUdpIpv6 : 1.3.6.1.2.1.100.1.2
		{ (const uint8_t[]){ 0x2B, 0x06, 0x01, 0x02, 0x01, 0x64, 0x01, 0x02 }, 8, &hf_tlv_management_addr_ipv6, ENC_NA },
		// transportDomainTcpIpv4 : 1.3.6.1.2.1.100.1.5
		{ (const uint8_t[]){ 0x2B, 0x06, 0x01, 0x02, 0x01, 0x64, 0x01, 0x05 }, 8, &hf_tlv_management_addr_ipv4, ENC_BIG_ENDIAN },
		// transportDomainTcpIpv6 : 1.3.6.1.2.1.100.1.6
		{ (const uint8_t[]){ 0x2B, 0x06, 0x01, 0x02, 0x01, 0x64, 0x01, 0x06 }, 8, &hf_tlv_management_addr_ipv6, ENC_NA },
		// transportDomainSctpIpv4 : 1.3.6.1.2.1.100.1.9
		{ (const uint8_t[]){ 0x2B, 0x06, 0x01, 0x02, 0x01, 0x64, 0x01, 0x09 }, 8, &hf_tlv_management_addr_ipv4, ENC_BIG_ENDIAN },
		// transportDomainSctpIpv6 : 1.3.6.1.2.1.100.1.10
		{ (const uint8_t[]){ 0x2B, 0x06, 0x01, 0x02, 0x01, 0x64, 0x01, 0x0A }, 8, &hf_tlv_management_addr_ipv6, ENC_NA },
		// snmpIeee802Domain : 1.3.6.1.6.1.6
		{ (const uint8_t[]){ 0x2B, 0x06, 0x01, 0x06, 0x01, 0x06 }, 6, &hf_tlv_management_addr_eth, ENC_NA },
		// End tag
		{ NULL, 0, NULL, ENC_NA }
	};

	for (size_t i = 0; i < array_length(management_address_type); i++) {
		if (management_address_type[i].oid == NULL) {
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_management_addr_unknown,
				tvb, tlv_data_offset, tlv_management_addr_length, ENC_NA);
			break;
		}
		if (tlv_ma_domain_length == management_address_type[i].oid_length) {
			if (!(memcmp(tlv_ma_domain_oid, management_address_type[i].oid, tlv_ma_domain_length))) {
				proto_tree_add_item(cfm_tlv_tree, *management_address_type[i].header_field,
					tvb, tlv_data_offset, tlv_management_addr_length, management_address_type[i].encoding);
				break;
			}
		}
	}

	tlv_data_offset += tlv_management_addr_length;

	return tlv_data_offset;
}

/* Inspired by packet-lldp.c:dissect_lldp_port_id() */
static int reply_ing_egr_tlv_port_id(proto_tree *cfm_tlv_tree, tvbuff_t *tvb, int tlv_data_offset, uint8_t tlv_reply_ingress_portid_length)
{
	proto_tree_add_item(cfm_tlv_tree, hf_tlv_reply_ing_egr_portid_subtype,
		tvb, tlv_data_offset, 1, ENC_NA);
	uint8_t port_id_subtype = tvb_get_uint8(tvb, tlv_data_offset);
	tlv_data_offset += 1;
	tlv_reply_ingress_portid_length -= 1;

	switch (port_id_subtype) {
	case 1:
		proto_tree_add_item(cfm_tlv_tree, hf_tlv_reply_ing_egr_portid_interface_alias, tvb, tlv_data_offset, tlv_reply_ingress_portid_length, ENC_UTF_8);
		break;
	case 2:
		proto_tree_add_item(cfm_tlv_tree, hf_tlv_reply_ing_egr_portid_port_component, tvb, tlv_data_offset, tlv_reply_ingress_portid_length, ENC_NA);
		break;
	case 3:
		proto_tree_add_item(cfm_tlv_tree, hf_tlv_reply_ing_egr_portid_mac_address, tvb, tlv_data_offset, tlv_reply_ingress_portid_length, ENC_NA);
		break;
	case 4:
		proto_tree_add_item(cfm_tlv_tree, hf_tlv_reply_ing_egr_portid_network_address_family, tvb, tlv_data_offset, 1, ENC_NA);

		switch (tvb_get_uint8(tvb, tlv_data_offset)) {
		case AFNUM_INET:
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_reply_ing_egr_portid_network_address_ipv4, tvb, tlv_data_offset+1, tlv_reply_ingress_portid_length-1, ENC_BIG_ENDIAN);
			break;
		case AFNUM_INET6:
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_reply_ing_egr_portid_network_address_ipv6, tvb, tlv_data_offset+1, tlv_reply_ingress_portid_length-1, ENC_NA);
			break;
		default:
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_reply_ing_egr_portid_network_address_unknown, tvb, tlv_data_offset+1, tlv_reply_ingress_portid_length-1, ENC_NA);
			break;
		}
		break;
	case 5:
		proto_tree_add_item(cfm_tlv_tree, hf_tlv_reply_ing_egr_portid_interface_name, tvb, tlv_data_offset, tlv_reply_ingress_portid_length, ENC_UTF_8);
		break;
	case 6:
		proto_tree_add_item(cfm_tlv_tree, hf_tlv_reply_ing_egr_portid_agent_circuit_id, tvb, tlv_data_offset, tlv_reply_ingress_portid_length, ENC_NA);
		break;
	case 7:
		proto_tree_add_item(cfm_tlv_tree, hf_tlv_reply_ing_egr_portid_locally_assigned, tvb, tlv_data_offset, tlv_reply_ingress_portid_length, ENC_UTF_8);
		break;
	default:
		proto_tree_add_item(cfm_tlv_tree, hf_tlv_reply_ing_egr_portid_unknown, tvb, tlv_data_offset, tlv_reply_ingress_portid_length, ENC_NA);
		break;
	}

	tlv_data_offset += tlv_reply_ingress_portid_length;

	return tlv_data_offset;
}

/* Main CFM EOAM protocol dissector */
static int dissect_cfm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	int offset = 0;
	uint8_t cfm_pdu_type;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CFM");
	col_clear(pinfo->cinfo, COL_INFO);

	cfm_pdu_type = tvb_get_uint8(tvb, CFM_OPCODE_OFFSET);
	col_add_fstr(pinfo->cinfo, COL_INFO, "Type %s",
		val_to_str(cfm_pdu_type, opcode_type_name_vals, "Unknown (0x%02x)"));

	proto_item *ti;
	proto_tree *cfm_tree;

	/* isolate the payload of the packet */
	ti = proto_tree_add_item(tree, proto_cfm, tvb, 0, -1, ENC_NA);

	/* report type of CFM packet to base of dissection tree */
	proto_item_append_text(ti, ", Type %s",
		val_to_str(cfm_pdu_type, opcode_type_name_vals, "Unknown (0x%02x)"));

	/* dissecting the common CFM header */
	cfm_tree = proto_item_add_subtree(ti, ett_cfm);
	proto_tree_add_item(cfm_tree, hf_cfm_md_level, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(cfm_tree, hf_cfm_version, tvb, offset, 1, ENC_NA);
	offset += 1;
	proto_tree_add_item(cfm_tree, hf_cfm_opcode, tvb, offset, 1, ENC_NA);
	offset += 1;

	switch (cfm_pdu_type) {
	case CCM:
		offset = dissect_cfm_ccm(tvb, pinfo, cfm_tree, offset);
		break;
	case LBM:
		offset = dissect_cfm_lbm(tvb, pinfo, cfm_tree, offset);
		break;
	case LBR:
		offset = dissect_cfm_lbr(tvb, pinfo, cfm_tree, offset);
		break;
	case LTM:
		offset = dissect_cfm_ltm(tvb, pinfo, cfm_tree, offset);
		break;
	case LTR:
		offset = dissect_cfm_ltr(tvb, pinfo, cfm_tree, offset);
		break;
	case RFM:
		offset = dissect_cfm_rfm(tvb, pinfo, cfm_tree, offset);
		break;
	case SFM:
		offset = dissect_cfm_sfm(tvb, pinfo, cfm_tree, offset);
		break;
	case GNM:
		offset = dissect_cfm_gnm(tvb, pinfo, cfm_tree, offset);
		break;
	case AIS:
		offset = dissect_cfm_ais(tvb, pinfo, cfm_tree, offset);
		break;
	case LCK:
		offset = dissect_cfm_lck(tvb, pinfo, cfm_tree, offset);
		break;
	case TST:
		offset = dissect_cfm_tst(tvb, pinfo, cfm_tree, offset);
		break;
	case APS:
		offset = dissect_cfm_aps(tvb, pinfo, cfm_tree, offset);
		break;
	case RAPS:
		offset = dissect_cfm_raps(tvb, pinfo, cfm_tree, offset);
		break;
	case MCC:
		offset = dissect_cfm_mcc(tvb, pinfo, cfm_tree, offset);
		break;
	case LMM:
		offset = dissect_cfm_lmm(tvb, pinfo, cfm_tree, offset);
		break;
	case LMR:
		offset = dissect_cfm_lmr(tvb, pinfo, cfm_tree, offset);
		break;
	case ODM:
		offset = dissect_cfm_odm(tvb, pinfo, cfm_tree, offset);
		break;
	case DMM:
		offset = dissect_cfm_dmm(tvb, pinfo, cfm_tree, offset);
		break;
	case DMR:
		offset = dissect_cfm_dmr(tvb, pinfo, cfm_tree, offset);
		break;
	case EXM:
		offset = dissect_cfm_exm(tvb, pinfo, cfm_tree, offset);
		break;
	case EXR:
		offset = dissect_cfm_exr(tvb, pinfo, cfm_tree, offset);
		break;
	case VSM:
		offset = dissect_cfm_vsm(tvb, pinfo, cfm_tree, offset);
		break;
	case VSR:
		offset = dissect_cfm_vsr(tvb, pinfo, cfm_tree, offset);
		break;
	case CSF:
		offset = dissect_cfm_csf(tvb, pinfo, cfm_tree, offset);
		break;
	case OSL:
		offset = dissect_cfm_osl(tvb, pinfo, cfm_tree, offset);
		break;
	case SLM:
		offset = dissect_cfm_slm(tvb, pinfo, cfm_tree, offset);
		break;
	case SLR:
		offset = dissect_cfm_slr(tvb, pinfo, cfm_tree, offset);
		break;
	default:
		offset = dissect_cfm_unknown(tvb, pinfo, cfm_tree, offset);
		break;
	}

	/* Get the First TLV offset and add the offset of the common CFM header*/
	int cfm_first_tlv_offset = tvb_get_uint8(tvb, CFM_1ST_TLV_OFFSET) + CFM_COMMON_HEADER_LEN;

	/* The TLV offset should be the same as where the PDU left off or we have a problem */
	if (cfm_first_tlv_offset != offset) {
		// TODO: Report error, recover and continue
		cfm_first_tlv_offset = offset;
	}

	/* Begin dissecting the TLV's */
	proto_item *cfm_all_tlvs_ti;
	proto_tree *cfm_all_tlvs_tree;
	cfm_all_tlvs_ti = proto_tree_add_item(cfm_tree, hf_cfm_all_tlvs, tvb, cfm_first_tlv_offset, -1, ENC_NA);
	cfm_all_tlvs_tree = proto_item_add_subtree(cfm_all_tlvs_ti, ett_cfm_all_tlvs);

	int cfm_tlv_offset = cfm_first_tlv_offset;

	do
	{
		uint8_t cfm_tlv_type;
		uint16_t cfm_tlv_length;
		proto_tree *cfm_tlv_tree;
		proto_item *cfm_tlv_ti, *expert_ti;
		int tlv_data_offset;
		bool test_id_length_bogus = false;

		cfm_tlv_type = tvb_get_uint8(tvb, cfm_tlv_offset);

		if (cfm_tlv_type == END_TLV) {
			cfm_tlv_tree = proto_tree_add_subtree_format(cfm_all_tlvs_tree, tvb, cfm_tlv_offset, 1,
				ett_cfm_tlv, NULL, "TLV: End TLV (t=0,l=0)");
			proto_tree_add_item(cfm_tlv_tree, hf_cfm_tlv_type, tvb, cfm_tlv_offset, 1, ENC_NA);
			cfm_tlv_offset += 1;
			break;
		}

		cfm_tlv_length = tvb_get_ntohs(tvb, cfm_tlv_offset+1);
		if (cfm_tlv_type == TEST_ID_TLV && cfm_tlv_length == 32) {
			/* ITU-T G.8013/Y.1731 9.14.2 indicates that the
			 * Length of the Test ID TLV "must be 32" (indicating
			 * the bit length?) even though the Value is 4 octets,
			 * contradicting IEEE 802.1Q 21.5 TLV format:
			 * "The 16 bits of the Length field indicate the size,
			 * in octets, of the Value field."
			 */
			cfm_tlv_length = 4;
			test_id_length_bogus = true;
		}

		cfm_tlv_tree = proto_tree_add_subtree_format(cfm_all_tlvs_tree, tvb, cfm_tlv_offset, cfm_tlv_length+3,
				ett_cfm_tlv, NULL, "TLV: %s (t=%d,l=%d)", val_to_str(cfm_tlv_type, tlv_type_field_vals, "Unknown (0x%02x)"),
				cfm_tlv_type, cfm_tlv_length);

		proto_tree_add_item(cfm_tlv_tree, hf_cfm_tlv_type, tvb, cfm_tlv_offset, 1, ENC_NA);
		cfm_tlv_offset += 1;

		cfm_tlv_ti = proto_tree_add_item(cfm_tlv_tree, hf_cfm_tlv_length, tvb, cfm_tlv_offset, 2, ENC_BIG_ENDIAN);
		if (test_id_length_bogus) {
			expert_add_info(pinfo, cfm_tlv_ti, &ei_tlv_tst_id_length);
		}
		cfm_tlv_offset += 2;

		if (cfm_tlv_length == 0)
			continue;

		tlv_data_offset = cfm_tlv_offset;

		switch(cfm_tlv_type) {
		case SENDER_ID_TLV:
		{
			uint8_t tlv_chassis_id_length;

			proto_tree_add_item(cfm_tlv_tree, hf_tlv_chassis_id_length,
				tvb, tlv_data_offset, 1, ENC_NA);
			tlv_chassis_id_length = tvb_get_uint8(tvb,tlv_data_offset);
			tlv_data_offset += 1;

			if (tlv_chassis_id_length > 0) {
				tlv_data_offset = sender_id_tlv_chassis_id(cfm_tlv_tree, tvb, tlv_data_offset, tlv_chassis_id_length);
			}

			/* IEEE 802.1Q 21.5.3.2 If the Chassis ID Length field
			 * is 0, then the Chassis ID Subtype is not present.
			 */
			uint16_t chassis_id_tot_length = tlv_chassis_id_length ? 2 + tlv_chassis_id_length : 1;
			/* If the TLV length is greater than the number of octets used for the
			 * Chassis ID, then we must have a Management Address Domain
			 */
			if (cfm_tlv_length > chassis_id_tot_length) {
				uint8_t tlv_ma_domain_length;
				void *tlv_ma_domain_oid = NULL;
				proto_tree_add_item(cfm_tlv_tree, hf_tlv_ma_domain_length,
					tvb, tlv_data_offset, 1, ENC_NA);
				tlv_ma_domain_length = tvb_get_uint8(tvb, tlv_data_offset);
				tlv_data_offset += 1;
				if (tlv_ma_domain_length > 0) {
					// Ref ITU-T X690-2002 for OID. RFC 2579 for TDomain.
					proto_tree_add_item(cfm_tlv_tree, hf_tlv_ma_domain,
						tvb, tlv_data_offset, tlv_ma_domain_length, ENC_NA);
					tlv_ma_domain_oid = tvb_memdup(pinfo->pool, tvb, tlv_data_offset, tlv_ma_domain_length);
					tlv_data_offset += tlv_ma_domain_length;
				}

				/* If the TLV length is greater than the number of octets used for the
				 * Chassis ID and the Management Address Domain, then we must have a
				 * Management Address
				 */
				if (cfm_tlv_length > (chassis_id_tot_length + 1 + tlv_ma_domain_length)) {
					uint8_t tlv_management_addr_length;
					expert_ti = proto_tree_add_item(cfm_tlv_tree, hf_tlv_management_addr_length,
						tvb, tlv_data_offset, 1, ENC_NA);
					/* IEEE 802.1Q 21.5.3.6 "[Management Address Length] is not
					 * present if the Management Address Domain Length is not
					 * present or contains a 0."
					 */
					if (tlv_ma_domain_length == 0) {
						expert_add_info(pinfo, expert_ti, &ei_tlv_management_addr_length);
					}
					tlv_management_addr_length = tvb_get_uint8(tvb, tlv_data_offset);
					tlv_data_offset += 1;
					if (tlv_management_addr_length > 0) {
						tlv_data_offset = sender_id_tlv_management_address(cfm_tlv_tree, tvb, tlv_ma_domain_oid,
												   tlv_ma_domain_length, tlv_data_offset,
												   tlv_management_addr_length);
					}
				}
			}
			break;
		}
		case PORT_STAT_TLV:
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_port_status_value,
				tvb, tlv_data_offset, 1, ENC_NA);
			tlv_data_offset += 1;
			break;
		case DATA_TLV:
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_data_value,
				tvb, tlv_data_offset, cfm_tlv_length, ENC_NA);
			tlv_data_offset += cfm_tlv_length;
			break;
		case INTERF_STAT_TLV:
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_interface_status_value,
				tvb, tlv_data_offset, 1, ENC_NA);
			tlv_data_offset += 1;
			break;
		case REPLY_ING_TLV:
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_reply_ingress_action,
				tvb, tlv_data_offset, 1, ENC_NA);
			tlv_data_offset += 1;
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_reply_ingress_mac_address,
				tvb, tlv_data_offset, 6, ENC_NA);
			tlv_data_offset += 6;

			/* For the IEEE standard if the TLV length is greater than 7 then we have an ingress port ID */
			if (cfm_tlv_length > 7) {
				uint8_t tlv_reply_ingress_portid_length;
				proto_tree_add_item(cfm_tlv_tree, hf_tlv_reply_ing_egr_portid_length,
					tvb, tlv_data_offset, 1, ENC_NA);
				tlv_reply_ingress_portid_length = tvb_get_uint8(tvb,tlv_data_offset);
				tlv_data_offset += 1;

				if (tlv_reply_ingress_portid_length > 0) {
					tlv_data_offset = reply_ing_egr_tlv_port_id(cfm_tlv_tree, tvb, tlv_data_offset, tlv_reply_ingress_portid_length);
				} else {
					// TODO: Report error, cannot be zero.
				}
			}
			break;
		case REPLY_EGR_TLV:
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_reply_egress_action,
				tvb, tlv_data_offset, 1, ENC_NA);
			tlv_data_offset += 1;
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_reply_egress_mac_address,
				tvb, tlv_data_offset, 6, ENC_NA);
			tlv_data_offset += 6;

			/* For the IEEE standard if the TLV length is greater than 7 then we have an egress port ID */
			if (cfm_tlv_length > 7) {
				uint8_t tlv_reply_egress_portid_length;
				proto_tree_add_item(cfm_tlv_tree, hf_tlv_reply_ing_egr_portid_length,
					tvb, tlv_data_offset, 1, ENC_NA);
				tlv_reply_egress_portid_length = tvb_get_uint8(tvb,tlv_data_offset);
				tlv_data_offset += 1;

				if (tlv_reply_egress_portid_length > 0) {
					tlv_data_offset = reply_ing_egr_tlv_port_id(cfm_tlv_tree, tvb, tlv_data_offset, tlv_reply_egress_portid_length);
				} else {
					// TODO: Report error, cannot be zero.
				}
			}
			break;
		case LTM_EGR_ID_TLV:
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_ltm_egress_id_unique_identifier,
				tvb, tlv_data_offset, 2, ENC_NA);
			tlv_data_offset += 2;
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_ltm_egress_id_mac,
				tvb, tlv_data_offset, 6, ENC_NA);
			tlv_data_offset += 6;
			break;
		case LTR_EGR_ID_TLV:
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_ltr_egress_last_id_unique_identifier,
				tvb, tlv_data_offset, 2, ENC_NA);
			tlv_data_offset += 2;
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_ltr_egress_last_id_mac,
				tvb, tlv_data_offset, 6, ENC_NA);
			tlv_data_offset += 6;
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_ltr_egress_next_id_unique_identifier,
				tvb, tlv_data_offset, 2, ENC_NA);
			tlv_data_offset += 2;
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_ltr_egress_next_id_mac,
				tvb, tlv_data_offset, 6, ENC_NA);
			tlv_data_offset += 6;
			break;
		case PPB_TE_MIP_TLV:
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_pbb_te_mip_mac_address,
				tvb, tlv_data_offset, 6, ENC_NA);
			tlv_data_offset += 6;
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_pbb_te_reverse_vid,
				tvb, tlv_data_offset, 2, ENC_BIG_ENDIAN);
			tlv_data_offset += 2;
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_pbb_te_reverse_mac,
				tvb, tlv_data_offset, 6, ENC_NA);
			tlv_data_offset += 6;
			break;
		case DATA_PART1_TLV:
		case TRUNC_DATA_TLV:
			// TODO: hand off to ethertype dissector
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_data_value,
				tvb, tlv_data_offset, cfm_tlv_length, ENC_NA);
			tlv_data_offset += cfm_tlv_length;
			break;
		case DATA_PART2_TLV:
			// NOTE: Appended to DATA_PART1_TLV this makes a complete Ethernet frame
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_data_value,
				tvb, tlv_data_offset, cfm_tlv_length, ENC_NA);
			tlv_data_offset += cfm_tlv_length;
			break;
		case ORG_SPEC_TLV:
			if (cfm_tlv_length > 3) {
				proto_tree_add_item(cfm_tlv_tree, hf_tlv_org_spec_oui,
					tvb, tlv_data_offset, 3, ENC_BIG_ENDIAN);
				proto_tree_add_item(cfm_tlv_tree, hf_tlv_org_spec_subtype,
					tvb, tlv_data_offset + 3, 1, ENC_NA);
				// TODO: introduce subdissector table for this
				proto_tree_add_item(cfm_tlv_tree, hf_tlv_org_spec_value,
					tvb, tlv_data_offset + 4, cfm_tlv_length-4, ENC_NA);
			} else {
				// TODO: report error
			}
			tlv_data_offset += cfm_tlv_length;
			break;
		case TEST_TLV:
		{
			uint32_t tlv_tst_test_pattern_type;

			proto_tree_add_item_ret_uint(cfm_tlv_tree, hf_tlv_tst_test_pattern_type,
				tvb, tlv_data_offset, 1, ENC_NA, &tlv_tst_test_pattern_type);
			tlv_data_offset += 1;
			if (cfm_tlv_length > 1) {
				switch (tlv_tst_test_pattern_type) {
				case 0:
				case 2:
				default:
					proto_tree_add_item(cfm_tlv_tree, hf_tlv_tst_test_pattern,
						tvb, tlv_data_offset, cfm_tlv_length - 1, ENC_NA);
					tlv_data_offset += cfm_tlv_length - 1;
					break;
				case 1:
				case 3:
					proto_tree_add_item(cfm_tlv_tree, hf_tlv_tst_test_pattern,
						tvb, tlv_data_offset, cfm_tlv_length - 5, ENC_NA);
					tlv_data_offset += cfm_tlv_length - 5;
					// TODO: look at using proto_tree_add_checksum()
					proto_tree_add_item(cfm_tlv_tree, hf_tlv_tst_CRC32,
						tvb, tlv_data_offset, 4, ENC_NA);
					tlv_data_offset += 4;
					break;
				}
			} else {
				// TODO: report error
			}
			break;
		}
		case TGT_MEP_MIP_ID_TLV:
		case RPL_MEP_MIP_ID_TLV:
		{
			uint32_t mep_mip_id_subtype;

			proto_tree_add_item_ret_uint(cfm_tlv_tree, hf_tlv_tgt_rpl_mep_mip_id_subtype,
				tvb, tlv_data_offset, 1, ENC_NA, &mep_mip_id_subtype);
			tlv_data_offset += 1;
			if (cfm_tlv_length > 1) {
				switch (mep_mip_id_subtype) {
					case 0x00:  // Discovery ingress/node MEP/MIP
					case 0x01:  // Discovery egress MEP/MIP
						proto_tree_add_item(cfm_tlv_tree, hf_tlv_tgt_rpl_padding,
							tvb, tlv_data_offset, cfm_tlv_length - 1, ENC_NA);
						break;
					case 0x02:  // MEP ID
						proto_tree_add_item(cfm_tlv_tree, hf_tlv_tgt_rpl_mep_id,
							tvb, tlv_data_offset, 2, ENC_BIG_ENDIAN);
						proto_tree_add_item(cfm_tlv_tree, hf_tlv_tgt_rpl_padding,
							tvb, tlv_data_offset + 2, cfm_tlv_length - 3, ENC_NA);
						break;
					case 0x03:  // MIP ID
						proto_tree_add_item(cfm_tlv_tree, hf_tlv_tgt_rpl_mip_id_icc,
							tvb, tlv_data_offset, 6, ENC_ASCII|ENC_NA);
						proto_tree_add_item(cfm_tlv_tree, hf_tlv_tgt_rpl_mip_id_node_id,
							tvb, tlv_data_offset + 6, 4, ENC_BIG_ENDIAN);
						proto_tree_add_item(cfm_tlv_tree, hf_tlv_tgt_rpl_mip_id_if_num,
							tvb, tlv_data_offset + 10, 4, ENC_BIG_ENDIAN);
						proto_tree_add_item(cfm_tlv_tree, hf_tlv_tgt_rpl_mip_id_cc,
							tvb, tlv_data_offset + 14, 2, ENC_ASCII|ENC_NA);
						proto_tree_add_item(cfm_tlv_tree, hf_tlv_tgt_rpl_padding,
							tvb, tlv_data_offset + 16, cfm_tlv_length - 17, ENC_NA);
						break;
					default:
						proto_tree_add_item(cfm_tlv_tree, hf_tlv_tgt_rpl_padding,
							tvb, tlv_data_offset, cfm_tlv_length - 1, ENC_NA);
						break;
				}
				tlv_data_offset += cfm_tlv_length;
			} else {
				// TODO: report error
			}
			break;
		}
		case REQ_MEP_ID_TLV:
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_req_mep_id_lb,
				tvb, tlv_data_offset, 1, ENC_NA);
			tlv_data_offset += 1;
			tlv_data_offset = dissect_mep_maid(tvb, pinfo, cfm_tlv_tree, tlv_data_offset);
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_req_mep_id_reserved,
				tvb, tlv_data_offset, 2, ENC_NA);
			tlv_data_offset += 2;
			break;
		case TEST_ID_TLV:
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_tst_id_test_id,
				tvb, tlv_data_offset, 4, ENC_NA);
			tlv_data_offset += 4;
			break;
		default:
			// TODO: report error
			proto_tree_add_item(cfm_tlv_tree, hf_tlv_unknown_data,
				tvb, tlv_data_offset, cfm_tlv_length, ENC_NA);
			tlv_data_offset += cfm_tlv_length;
			break;
		}

		// TODO: add check here that matches tlv_data_offset to cfm_tlv_offset + cfm_tlv_length
		cfm_tlv_offset = tlv_data_offset;

	} while (true);

	proto_item_set_len(cfm_all_tlvs_ti, cfm_tlv_offset - cfm_first_tlv_offset);
	proto_item_set_len(ti, cfm_tlv_offset);

	return cfm_tlv_offset;
}

/* Register CFM EOAM protocol */
void proto_register_cfm(void)
{
	static hf_register_info hf[] = {
		/* CFM Common header */
		{ &hf_cfm_md_level,
			{ "CFM MD Level", "cfm.md_level", FT_UINT8,
			BASE_DEC, NULL, 0xe0, "MD level/MEG level", HFILL }
		},
		{ &hf_cfm_version,
			{ "CFM Version", "cfm.version", FT_UINT8,
			BASE_DEC, NULL, 0x1f, NULL, HFILL }
		},
		{ &hf_cfm_opcode,
			{ "CFM OpCode", "cfm.opcode", FT_UINT8,
			BASE_DEC, VALS(opcode_type_name_vals), 0x0, NULL, HFILL }
		},
		{ &hf_cfm_flags,
			{ "Flags", "cfm.flags", FT_UINT8,
			BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_flags_Reserved,
			{ "Reserved", "cfm.flags.reserved", FT_UINT8,
			BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_first_tlv_offset,
			{ "First TLV Offset", "cfm.first_tlv_offset", FT_UINT8,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* MEP and MAID */
		{ &hf_cfm_mep_id,
			{ "Maintenance Association Endpoint Identifier", "cfm.mep_id",
			 FT_UINT16, BASE_DEC, NULL, 0x1FFF, NULL, HFILL }
		},
		{ &hf_cfm_maid,
			{ "Maintenance Association Identifier", "cfm.maid", FT_NONE,
			 BASE_NONE, NULL, 0x0, "MEG ID (G.8013/Y.1731)", HFILL }
		},
		{ &hf_cfm_maid_md_name_format,
			{ "MD Name Format", "cfm.maid.md_name.format", FT_UINT8,
			BASE_DEC, VALS(md_name_format_type_vals), 0x0, "Reserved (01) in G.8013/Y.1731", HFILL }
		},
		{ &hf_cfm_maid_md_name_length,
			{ "MD Name Length", "cfm.maid.md_name.length", FT_UINT8,
			BASE_DEC, NULL, 0x0, "MEG ID length (G.8013/Y.1731)", HFILL }
		},
		{ &hf_cfm_maid_md_name_string,
			{ "MD Name (String)", "cfm.maid.md_name.string", FT_STRING,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_maid_md_name_hex,
			{ "MD Name", "cfm.maid.md_name.hex", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_maid_md_name_mac,
			{ "MD Name (MAC+ID)", "cfm.maid.md_name.mac", FT_ETHER,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_maid_md_name_mac_id,
			{ "MD Name (MAC+ID)", "cfm.maid.md_name.mac.id", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_maid_ma_name_format,
			{ "Short MA Name (MEG ID) Format", "cfm.maid.ma_name.format", FT_UINT8,
			BASE_DEC, VALS(ma_name_format_type_vals), 0x0, NULL, HFILL }
		},
		{ &hf_cfm_maid_ma_name_length,
			{ "Short MA Name (MEG ID) Length", "cfm.maid.ma_name.length", FT_UINT8,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_maid_ma_name_pvid,
			{ "Short MA Name PVID", "cfm.maid.ma_name.pvid", FT_UINT16,
			BASE_DEC, NULL, 0x0FFF, NULL, HFILL },
		},
		{ &hf_cfm_maid_ma_name_string,
			{ "Short MA Name", "cfm.maid.ma_name.string", FT_STRING,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_maid_ma_name_id,
			{ "Short MA Name ID", "cfm.maid.ma_name.id", FT_UINT16,
			BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_cfm_maid_ma_name_vpnid_oui,
			{ "Short MA Name VPN ID OUI", "cfm.maid.ma_name.vpnid.oui", FT_UINT24,
			BASE_OUI, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_cfm_maid_ma_name_vpnid_index,
			{ "Short MA Name VPN ID index", "cfm.maid.ma_name.vpnid.index", FT_UINT32,
			BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_cfm_maid_ma_name_icc_umc,
			{ "MEG ID ICC", "cfm.maid.ma_name.icc", FT_STRING,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_maid_ma_name_cc,
			{ "MEG ID CC", "cfm.maid.ma_name.cc", FT_STRING,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_maid_ma_name_hex,
			{ "Short MA Name", "cfm.maid.ma_name.hex", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_maid_padding,
			{ "Zero-Padding", "cfm.ccm.maid.padding", FT_NONE,
			 BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* CFM CCM*/
		{ &hf_cfm_ccm_pdu,
			{ "CFM CCM PDU", "cfm.ccm.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_ccm_flags_RDI,
			{ "RDI", "cfm.ccm.flags.rdi", FT_UINT8,
			BASE_DEC, NULL, 0x80, NULL, HFILL }
		},
		{ &hf_cfm_ccm_flags_Traffic,
			{ "Traffic", "cfm.ccm.flags.traffic", FT_UINT8,
			BASE_DEC, NULL, 0x40, NULL, HFILL }
		},
		{ &hf_cfm_ccm_flags_Reserved,
			{ "Reserved", "cfm.ccm.flags.reserved", FT_UINT8,
			BASE_DEC, NULL, 0x38, NULL, HFILL }
		},
		{ &hf_cfm_ccm_flags_Interval,
			{ "Interval Field", "cfm.ccm.flags.interval", FT_UINT8,
			BASE_DEC, VALS(ccm_interval_field_encoding_vals), 0x07, NULL, HFILL }
		},
		{ &hf_cfm_ccm_seq_number,
			{ "Sequence Number", "cfm.ccm.seq_num", FT_UINT32,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_ccm_itu_t_y1731,
			{ "Defined by ITU-T Y.1731", "cfm.ccm.itu", FT_NONE,
			 BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_ccm_itu_TxFCf,
			{ "TxFCf", "cfm.ccm.itu.txfcf", FT_UINT32,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_ccm_itu_RxFCb,
			{ "RxFCb", "cfm.ccm.itu.rxfcb", FT_UINT32,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_ccm_itu_TxFCb,
			{ "TxFCb", "cfm.ccm.itu.txfcb", FT_UINT32,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_ccm_itu_reserved,
			{ "Reserved", "cfm.ccm.itu.reserved", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* CFM LBM*/
		{ &hf_cfm_lbm_pdu,
			{ "CFM LBM PDU", "cfm.lbm.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_lbm_lbr_transaction_id,
			{ "Loopback Transaction Identifier", "cfm.lbm.lbr.transaction_id", FT_UINT32,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* CFM LBR*/
		{ &hf_cfm_lbr_pdu,
			{ "CFM LBR PDU", "cfm.lbr.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* CFM LTM*/
		{ &hf_cfm_ltm_pdu,
			{ "CFM LTM PDU", "cfm.ltm.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_ltm_flags_UseFDBonly,
			{ "UseFDBonly", "cfm.ltm.flags.usefdbonly", FT_UINT8,
			BASE_DEC, NULL, 0x80, NULL, HFILL }
		},
		{ &hf_cfm_ltm_flags_Reserved,
			{ "Reserved", "cfm.ltm.flags.reserved", FT_UINT8,
			BASE_DEC, NULL, 0x7F, NULL, HFILL }
		},
		{ &hf_cfm_ltm_ltr_transaction_id,
			{ "Linktrace Transaction Identifier", "cfm.ltm.ltr.transaction_id", FT_UINT32,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_ltm_ltr_ttl,
			{ "Linktrace TTL", "cfm.ltm.ltr.ttl", FT_UINT8,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_ltm_orig_addr,
			{ "Linktrace Message: Original Address", "cfm.ltm.orig_addr", FT_ETHER,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_ltm_targ_addr,
			{ "Linktrace Message:   Target Address", "cfm.ltm.target_addr", FT_ETHER,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* CFM LTR*/
		{ &hf_cfm_ltr_pdu,
			{ "CFM LTR PDU", "cfm.ltr.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_ltr_flags_UseFDBonly,
			{ "UseFDBonly", "cfm.ltr.flags.usefdbonly", FT_UINT8,
			BASE_DEC, NULL, 0x80, NULL, HFILL }
		},
		{ &hf_cfm_ltr_flags_FwdYes,
			{ "FwdYes", "cfm.ltr.flags.fwdyes", FT_UINT8,
			BASE_DEC, NULL, 0x40, NULL, HFILL }
		},
		{ &hf_cfm_ltr_flags_TerminalMEP,
			{ "TerminalMEP", "cfm.ltr.flags.terminalmep", FT_UINT8,
			BASE_DEC, NULL, 0x20, NULL, HFILL }
		},
		{ &hf_cfm_ltr_flags_Reserved,
			{ "Reserved", "cfm.ltr.flags.reserved", FT_UINT8,
			BASE_DEC, NULL, 0x1F, NULL, HFILL }
		},
		{ &hf_cfm_ltr_relay_action,
			{ "Linktrace Reply Relay Action", "cfm.ltr.relay_action", FT_UINT8,
			BASE_DEC, VALS(relay_action_type_vals), 0x0, NULL, HFILL }
		},

		/* CFM RFM */
		{ &hf_cfm_rfm_pdu,
			{ "CFM RFM PDU", "cfm.rfm.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_rfm_transaction_id,
			{ "RFM Transaction Identifier", "cfm.rfm.transaction_id", FT_UINT32,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* CFM SFM */
		{ &hf_cfm_sfm_pdu,
			{ "CFM SFM PDU", "cfm.sfm.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_sfm_transaction_id,
			{ "SFM Transaction Identifier", "cfm.sfm.transaction_id", FT_UINT32,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

                /* CFM GNM */
		{ &hf_cfm_gnm_pdu,
			{ "CFM GNM PDU", "cfm.gnm.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_gnm_unknown_flags,
			{ "Unknown flags", "cfm.gnm.unknown.flags", FT_UINT8,
			BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_gnm_subopcode,
			{ "Sub-OpCode", "cfm.gnm.subopcode", FT_UINT8,
			BASE_HEX, VALS(gnm_sub_opcode_type_name_vals), 0x0, NULL, HFILL }
		},

		/* CFM BNM*/
		{ &hf_cfm_bnm_flags_Reserved,
			{ "Reserved", "cfm.bnm.flags.Reserved", FT_UINT8,
			BASE_DEC, NULL, 0xF8, NULL, HFILL }
		},
		{ &hf_cfm_bnm_flags_Period,
			{ "Period", "cfm.bnm.flags.Period", FT_UINT8,
			BASE_DEC, VALS(cfm_bnm_flags_period_vals), 0x07, NULL, HFILL }
		},
		{ &hf_cfm_bnm_pdu,
			{ "CFM BNM PDU", "cfm.bnm.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_bnm_nominal_bw,
			{ "Nominal Bandwidth", "cfm.bnm.nominal_bw", FT_UINT32,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_bnm_current_bw,
			{ "Current Bandwidth", "cfm.bnm.current_bw", FT_UINT32,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_bnm_port_id,
			{ "Port ID", "cfm.bnm.port_id", FT_UINT32,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* CFM AIS*/
		{ &hf_cfm_ais_pdu,
			{ "CFM AIS PDU", "cfm.ais.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_ais_flags_Reserved,
			{ "Reserved", "cfm.ais.flags.Reserved", FT_UINT8,
			BASE_DEC, NULL, 0xF8, NULL, HFILL }
		},
		{ &hf_cfm_ais_flags_Period,
			{ "Period", "cfm.ais.flags.Period", FT_UINT8,
			BASE_DEC, VALS(ais_lck_period_type_vals), 0x07, NULL, HFILL }
		},

		/* CFM LCK */
		{ &hf_cfm_lck_pdu,
			{ "CFM LCK PDU", "cfm.lck.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_lck_flags_Reserved,
			{ "Reserved", "cfm.lck.flags.Reserved", FT_UINT8,
			BASE_DEC, NULL, 0xF8, NULL, HFILL }
		},
		{ &hf_cfm_lck_flags_Period,
			{ "Period", "cfm.lck.flags.Period", FT_UINT8,
			BASE_DEC, VALS(ais_lck_period_type_vals), 0x07, NULL, HFILL }
		},

		/* CFM TST */
		{ &hf_cfm_tst_pdu,
			{ "CFM TST PDU", "cfm.tst.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_tst_sequence_num,
			{ "Sequence Number", "cfm.tst.sequence_num", FT_UINT32,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* CFM APS */
		{ &hf_cfm_aps_pdu,
			{ "CFM APS PDU", "cfm.aps.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_aps_req_st,
			{ "Request/State", "cfm.aps.req_st", FT_UINT8,
			BASE_DEC, VALS(aps_request_state_vals), 0xf0, NULL, HFILL }
		},
		{ &hf_cfm_aps_protection_type_A,
			{ "Protection type A", "cfm.aps.protec.type_A", FT_BOOLEAN,
			8, TFS(&tfs_aps_protection_type_A), 0x08, NULL, HFILL }
		},
		{ &hf_cfm_aps_protection_type_B,
			{ "Protection type B", "cfm.aps.protec.type_B", FT_BOOLEAN,
			8, TFS(&tfs_aps_protection_type_B), 0x04, NULL, HFILL }
		},
		{ &hf_cfm_aps_protection_type_D,
			{ "Protection type D", "cfm.aps.protec.type_D", FT_BOOLEAN,
			8, TFS(&tfs_aps_protection_type_D), 0x02, NULL, HFILL }
		},
		{ &hf_cfm_aps_protection_type_R,
			{ "Protection type R", "cfm.aps.protec.type_R", FT_BOOLEAN,
			8, TFS(&tfs_aps_protection_type_R), 0x01, NULL, HFILL }
		},
		{ &hf_cfm_aps_requested_signal,
			{ "Requested signal", "cfm.aps.req_signal", FT_UINT8,
			BASE_HEX, VALS(aps_requested_signal_values), 0x0, NULL, HFILL }
		},
		{ &hf_cfm_aps_bridged_signal,
			{ "Bridged signal", "cfm.aps.bridged_signal", FT_UINT8,
			BASE_HEX, VALS(aps_bridged_signal_values), 0x0, NULL, HFILL }
		},
		{ &hf_cfm_aps_bridge_type,
			{ "Bridge type", "cfm.aps.bridge_type", FT_UINT8,
			BASE_HEX, VALS(aps_bridge_type_values), 0x80, NULL, HFILL }
		},

		/* CFM R-APS */
		{ &hf_cfm_raps_pdu,
			{ "CFM R-APS PDU", "cfm.raps.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_raps_req_st,
			{ "Request/State", "cfm.raps.req_st", FT_UINT8,
			BASE_HEX, VALS(raps_request_state_values), RAPS_REQ_ST_MASK, NULL, HFILL }
		},
		{ &hf_cfm_raps_event_subcode,
			{ "Sub-code", "cfm.raps.event.subcode", FT_UINT8,
			BASE_HEX, VALS(rasp_event_subcode_vals), RAPS_SUB_CODE_MASK, NULL, HFILL }
		},
		{ &hf_cfm_raps_subcode_reserved,
			{ "Reserved", "cfm.raps.subcode.reserved", FT_UINT8,
			BASE_HEX, NULL, RAPS_SUB_CODE_MASK, NULL, HFILL }
		},
		{ &hf_cfm_raps_status,
			{ "R-APS status", "cfm.raps.status", FT_UINT8,
			BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_raps_status_rb,
			{ "RPL Blocked", "cfm.raps.status.rb", FT_BOOLEAN,
			8, TFS(&tfs_rasp_rpl_blocked), 0x80, NULL, HFILL }
		},
		{ &hf_cfm_raps_status_dnf,
			{ "Do Not Flush", "cfm.raps.status.dnf", FT_BOOLEAN,
			8, TFS(&tfs_rasp_dnf), 0x40, NULL, HFILL }
		},
		{ &hf_cfm_raps_status_bpr,
			{ "Blocked Port Reference", "cfm.raps.status.bpr", FT_BOOLEAN,
			8, TFS(&tfs_rasp_bpr), 0x20, NULL, HFILL }
		},
		{ &hf_cfm_raps_status_reserved_v1,
			{ "Reserved", "cfm.raps.status.reserved_v1", FT_UINT8,
			BASE_HEX, NULL, 0x3F, NULL, HFILL }
		},
		{ &hf_cfm_raps_status_reserved_v2,
			{ "Reserved", "cfm.raps.status.reserved_v2", FT_UINT8,
			BASE_HEX, NULL, 0x1F, NULL, HFILL }
		},
		{ &hf_cfm_raps_node_id,
			{ "R-APS Node ID", "cfm.raps.node_id", FT_ETHER,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_raps_reserved,
			{ "R-APS Reserved", "cfm.raps.reserved", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* CFM MCC */
		{ &hf_cfm_mcc_pdu,
			{ "CFM MCC PDU", "cfm.mcc.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_mcc_oui,
			{ "OUI", "cfm.mcc.oui", FT_UINT24,
			BASE_OUI, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_mcc_subopcode,
			{ "Subopcode", "cfm.mcc.subopcode", FT_UINT8,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_mcc_data,
			{ "MCC data", "cfm.mcc.data", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* CFM LMM */
		{ &hf_cfm_lmm_pdu,
			{ "CFM LMM PDU", "cfm.lmm.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_lmm_lmr_flags_Reserved,
			{ "Reserved", "cfm.lmm.lmr.flags.Reserved", FT_UINT8,
			BASE_HEX, NULL, 0xFE, NULL, HFILL }
		},
		{ &hf_cfm_lmm_lmr_flags_Type,
			{ "Type", "cfm.lmm.lmr.flags.Type", FT_BOOLEAN,
			8, TFS(&tfs_lmm_lmr_type), 0x01, NULL, HFILL }
		},
		{ &hf_cfm_lmm_lmr_TxFCf,
			{ "TxFCf", "cfm.lmm.lmr.txfcf", FT_UINT32,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_lmm_lmr_RxFCf,
			{ "RxFCf", "cfm.lmm.lmr.rxfcf", FT_UINT32,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_lmm_lmr_TxFCb,
			{ "TxFCb", "cfm.lmm.lmr.txfcb", FT_UINT32,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* CFM LMR */
		{ &hf_cfm_lmr_pdu,
			{ "CFM LMR PDU", "cfm.lmr.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* CFM 1DM */
		{ &hf_cfm_odm_pdu,
			{ "CFM 1DM PDU", "cfm.odm.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_odm_dmm_dmr_flags_Reserved,
			{ "Reserved", "cfm.odm.dmm.dmr.flags.Reserved", FT_UINT8,
			BASE_HEX, NULL, 0xFE, NULL, HFILL }
		},
		{ &hf_cfm_odm_dmm_dmr_flags_Type,
			{ "Type", "cfm.odm.dmm.dmr.flags.Type", FT_BOOLEAN,
			8, TFS(&tfs_odm_dmm_dmr_type), 0x01, NULL, HFILL }
		},
		{ &hf_cfm_odm_dmm_dmr_TxTimestampf,
			{ "TxTimestampf", "cfm.odm.dmm.dmr.txtimestampf", FT_RELATIVE_TIME,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_odm_dmm_dmr_RxTimestampf,
			{ "RxTimestampf", "cfm.odm.dmm.dmr.rxtimestampf", FT_RELATIVE_TIME,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* CFM DMM */
		{ &hf_cfm_dmm_pdu,
			{ "CFM DMM PDU", "cfm.dmm.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_dmm_dmr_TxTimestampb,
			{ "TxTimestampb", "cfm.dmm.dmr.txtimestampb", FT_RELATIVE_TIME,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_dmm_dmr_RxTimestampb,
			{ "RxTimestampb", "cfm.dmm.dmr.rxtimestampb", FT_RELATIVE_TIME,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* CFM DMR */
		{ &hf_cfm_dmr_pdu,
			{ "CFM DMR PDU", "cfm.dmr.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* CFM EXM */
		{ &hf_cfm_exm_pdu,
			{ "CFM EXM PDU", "cfm.exm.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_exm_oui,
			{ "OUI", "cfm.exm.oui", FT_UINT24,
			BASE_OUI, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_exm_subopcode,
			{ "Subopcode", "cfm.exm.subopcode", FT_UINT8,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_exm_data,
			{ "EXM data", "cfm.exm.data", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* CFM EXR */
		{ &hf_cfm_exr_pdu,
			{ "CFM EXR PDU", "cfm.exr.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_exr_oui,
			{ "OUI", "cfm.exr.oui", FT_UINT24,
			BASE_OUI, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_exr_subopcode,
			{ "Subopcode", "cfm.exr.subopcode", FT_UINT8,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_exr_data,
			{ "EXR data", "cfm.exr.data", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* CFM VSM */
		{ &hf_cfm_vsm_pdu,
			{ "CFM VSM PDU", "cfm.vsm.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_vsm_oui,
			{ "OUI", "cfm.vsm.oui", FT_UINT24,
			BASE_OUI, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_vsm_subopcode,
			{ "Subopcode", "cfm.vsm.subopcode", FT_UINT8,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_vsm_data,
			{ "VSM data", "cfm.vsm.data", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* CFM VSR */
		{ &hf_cfm_vsr_pdu,
			{ "CFM VSR PDU", "cfm.vsr.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_vsr_oui,
			{ "OUI", "cfm.vsr.oui", FT_UINT24,
			BASE_OUI, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_vsr_subopcode,
			{ "Subopcode", "cfm.vsr.subopcode", FT_UINT8,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_vsr_data,
			{ "VSR data", "cfm.vsr.data", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* CFM CSF */
		{ &hf_cfm_csf_pdu,
			{ "CFM CSF PDU", "cfm.csf.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_csf_flags_Reserved,
			{ "Reserved", "cfm.csf.flags.Reserved", FT_UINT8,
			BASE_HEX, NULL, 0xC0, NULL, HFILL }
		},
		{ &hf_cfm_csf_flags_Type,
			{ "Type", "cfm.csf.flags.Type", FT_UINT8,
			BASE_DEC, VALS(cfm_csf_flags_type_vals), 0x38, NULL, HFILL }
		},
		{ &hf_cfm_csf_flags_Period,
			{ "Type", "cfm.csf.flags.Period", FT_UINT8,
			BASE_DEC, VALS(cfm_csf_flags_period_vals), 0x07, NULL, HFILL }
		},

		/* CFM 1SL */
		{ &hf_cfm_osl_pdu,
			{ "CFM 1SL PDU", "cfm.osf.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_osl_src_mep,
			{ "Source MEP ID", "cfm.osl.src_mep_id", FT_UINT16,
			BASE_DEC, NULL, 0x1FFF, NULL, HFILL }
		},
		{ &hf_cfm_osl_reserved,
			{ "1SL Reserved", "cfm.osl.reserved", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_osl_testid,
			{ "TestID", "cfm.osl.test_id", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_osl_txfcf,
			{ "TxFcF", "cfm.osl.txfcf", FT_UINT32,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* CFM SLM */
		{ &hf_cfm_slm_pdu,
			{ "CFM SLM PDU", "cfm.slm.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_slm_slr_src_mep,
			{ "Source MEP ID", "cfm.slm.slr.src_mep_id", FT_UINT16,
			BASE_DEC, NULL, 0x1FFF, NULL, HFILL }
		},
		{ &hf_cfm_slm_reserved,
			{ "SLM Reserved", "cfm.slm.reserved", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_slm_slr_testid,
			{ "TestID", "cfm.slm.slr.test_id", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_slm_slr_txfcf,
			{ "TxFcF", "cfm.slm.slr.txfcf", FT_UINT32,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* CFM SLR */
		{ &hf_cfm_slr_pdu,
			{ "CFM SLR PDU", "cfm.slr.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_slr_rsp_mep,
			{ "Responder MEP ID", "cfm.slr.rsp_mep_id", FT_UINT16,
			BASE_DEC, NULL, 0x1FFF, NULL, HFILL }
		},
		{ &hf_cfm_slr_txfcb,
			{ "TxFcB", "cfm.slr.txfcb", FT_UINT32,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* Unknown */
		{ &hf_cfm_unknown_pdu,
			{ "Unknown PDU", "cfm.unknown.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_unknown_flags,
			{ "Unknown flags", "cfm.unknown.flags", FT_UINT8,
			BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_unknown_data,
			{ "Unknown data", "cfm.unknown.data", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/******************************* TLVs ****************************/
		{ &hf_cfm_all_tlvs,
			{ "CFM TLVs", "cfm.all_tlvs", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_tlv_type,
			{ "TLV Type", "cfm.tlv.type", FT_UINT8,
			BASE_DEC, VALS(tlv_type_field_vals), 0x0, NULL, HFILL }
		},
		{ &hf_cfm_tlv_length,
			{ "TLV Length", "cfm.tlv.length", FT_UINT16,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
				/* Sender ID TLV */
		{ &hf_tlv_chassis_id_length,
			{ "Chassis ID Length", "cfm.tlv.sender_id.chassis_id.length", FT_UINT8,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_chassis_id_subtype,
			{ "Chassis ID Sub-type", "cfm.tlv.sender_id.chassis_id.subtype", FT_UINT8,
			BASE_DEC, VALS(sender_id_tlv_chassis_id_subtype_vals), 0x0, NULL, HFILL }
		},
		{ &hf_tlv_chassis_id_chassis_component,
			{ "Chassis component", "cfm.tlv.sender_id.chassis_id.chassis_component", FT_STRINGZPAD,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_chassis_id_interface_alias,
			{ "Interface alias", "cfm.tlv.sender_id.chassis_id.intf_alias", FT_STRINGZPAD,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_chassis_id_port_component,
			{ "Port component", "cfm.tlv.sender_id.chassis_id.port_component", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_chassis_id_mac_address,
			{ "MAC address", "cfm.tlv.sender_id.chassis_id.mac_address", FT_ETHER,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_chassis_id_network_address_family,
			{ "Network address family", "cfm.tlv.sender_id.chassis_id.network_address.family", FT_UINT8,
			BASE_DEC, VALS(afn_vals), 0x0, NULL, HFILL }
		},
		{ &hf_tlv_chassis_id_network_address_ipv4,
			{ "Network address", "cfm.tlv.sender_id.chassis_id.network_address.ipv4", FT_IPv4,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_chassis_id_network_address_ipv6,
			{ "Network address", "cfm.tlv.sender_id.chassis_id.network_address.ipv6", FT_IPv6,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_chassis_id_network_address_unknown,
			{ "Network address", "cfm.tlv.sender_id.chassis_id.network_address.unknown", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_chassis_id_interface_name,
			{ "Interface name", "cfm.tlv.sender_id.chassis_id.intf_name", FT_STRINGZPAD,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_chassis_id_locally_assigned,
			{ "Locally assigned", "cfm.tlv.sender_id.chassis_id.locally_assigned", FT_STRINGZPAD,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_chassis_id_unknown,
			{ "Unknown", "cfm.tlv.sender_id.chassis_id.unknown", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_ma_domain_length,
			{ "Management Address Domain Length", "cfm.tlv.sender_id.ma_domain.length", FT_UINT8,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_ma_domain,
			{ "Management Address Domain", "cfm.tlv.sender_id.ma_domain", FT_OID,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_management_addr_length,
			{ "Management Address Length", "cfm.tlv.sender_id.management_addr.length", FT_UINT8,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_management_addr_ipv4,
			{ "Management Address", "cfm.tlv.sender_id.management_addr.ipv4", FT_IPv4,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_management_addr_ipv6,
			{ "Management Address", "cfm.tlv.sender_id.management_addr.ipv6", FT_IPv6,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_management_addr_eth,
			{ "Management Address", "cfm.tlv.sender_id.management_addr.eth", FT_ETHER,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_management_addr_unknown,
			{ "Management Address", "cfm.tlv.sender_id.management_addr.unknown", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

				/* Port Status TLV */
		{ &hf_tlv_port_status_value,
			{ "Port Status value", "cfm.tlv.port_status.value", FT_UINT8,
			BASE_DEC, VALS(port_stat_tlv_vals), 0x0, NULL, HFILL }
		},

				/* Data TLV, Truncated Data TLV, Data Part 1 TLV, Data Part 2 TLV */
		{ &hf_tlv_data_value,
			{ "Data Value", "cfm.tlv.data.value", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

				/* Interface status TLV */
		{ &hf_tlv_interface_status_value,
			{ "Interface Status value", "cfm.tlv.intf_status.value", FT_UINT8,
			BASE_DEC, VALS(interface_stat_tlv_vals), 0x0, NULL, HFILL }
		},

				/* Reply Ingress TLV, Reply Egress TLV */
		{ &hf_tlv_reply_ingress_action,
			{ "Ingress Action", "cfm.tlv.reply_ingress.action", FT_UINT8,
			BASE_DEC, VALS(reply_ingress_tlv_vals), 0x0, NULL, HFILL }
		},
		{ &hf_tlv_reply_ingress_mac_address,
			{ "Ingress MAC address", "cfm.tlv.reply_ingress.mac_address", FT_ETHER,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_reply_ing_egr_portid_length,
			{ "Chassis ID Length", "cfm.tlv.reply_ing_egr.portid.length", FT_UINT8,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_reply_ing_egr_portid_subtype,
			{ "Chassis ID Sub-type", "cfm.tlv.reply_ing_egr.portid.subtype", FT_UINT8,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_reply_ing_egr_portid_interface_alias,
			{ "Interface alias", "cfm.tlv.reply_ing_egr.portid.intf_alias", FT_STRING,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_reply_ing_egr_portid_port_component,
			{ "Port component", "cfm.tlv.reply_ing_egr.portid.port_comp", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_reply_ing_egr_portid_mac_address,
			{ "MAC address", "cfm.tlv.reply_ing_egr.portid.mac_address", FT_ETHER,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_reply_ing_egr_portid_network_address_family,
			{ "Network address family", "cfm.tlv.reply_ing_egr.portid.network_address.family", FT_UINT8,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_reply_ing_egr_portid_network_address_ipv4,
			{ "Network address", "cfm.tlv.reply_ing_egr.portid.network_address.ipv4", FT_IPv4,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_reply_ing_egr_portid_network_address_ipv6,
			{ "Network address", "cfm.tlv.reply_ing_egr.portid.network_address.ipv6", FT_IPv6,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_reply_ing_egr_portid_network_address_unknown,
			{ "Network address", "cfm.tlv.reply_ing_egr.portid.network_address.unknown", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_reply_ing_egr_portid_interface_name,
			{ "Interface name", "cfm.tlv.reply_ing_egr.portid.intf_name", FT_STRINGZPAD,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_reply_ing_egr_portid_agent_circuit_id,
			{ "Agent circuit ID", "cfm.tlv.reply_ing_egr.portid.agent_circuit_id", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_reply_ing_egr_portid_locally_assigned,
			{ "Locally assigned", "cfm.tlv.reply_ing_egr.portid.locally_assigned", FT_STRINGZPAD,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_reply_ing_egr_portid_unknown,
			{ "Chassis ID", "cfm.tlv.reply_ing_egr.portid.unknown", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

				/* Reply Egress TLV */
		{ &hf_tlv_reply_egress_action,
			{ "Egress Action", "cfm.tlv.reply_egress.action", FT_UINT8,
			BASE_DEC, VALS(reply_egress_tlv_vals), 0x0, NULL, HFILL }
		},
		{ &hf_tlv_reply_egress_mac_address,
			{ "Egress MAC address", "cfm.tlv.reply_egress.mac_address", FT_ETHER,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

				/* LTM Egress Identifier TLV */
		{ &hf_tlv_ltm_egress_id_mac,
			{ "Egress Identifier - MAC of LT Initiator/Responder", "cfm.tlv.ltm_egress.id.mac", FT_ETHER,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_ltm_egress_id_unique_identifier,
			{ "Egress Identifier - Unique Identifier", "cfm.tlv.ltm_egress.id.ui", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

				/* LTR Egress Identifier TLV */
		{ &hf_tlv_ltr_egress_last_id_mac,
			{ "Last Egress Identifier - MAC address", "cfm.tlv.ltr_egress.last_id.mac", FT_ETHER,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_ltr_egress_last_id_unique_identifier,
			{ "Last Egress Identifier - Unique Identifier", "cfm.tlv.ltr_egress.last_id.ui", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_ltr_egress_next_id_mac,
			{ "Next Egress Identifier - MAC address", "cfm.tlv.ltr_egress.next_id.mac", FT_ETHER,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_ltr_egress_next_id_unique_identifier,
			{ "Next Egress Identifier - Unique Identifier", "cfm.tlv.ltr_egress.next_id.ui", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

				/* PBB-TE TLV */
		{ &hf_tlv_pbb_te_mip_mac_address,
			{ "MIP MAC address", "cfm.tlv.pbb_te.mip_mac", FT_ETHER,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_pbb_te_reverse_vid,
			{ "Reverse VID", "cfm.tlv.pbb_te.reverse_vid", FT_UINT16,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_pbb_te_reverse_mac,
			{ "Reverse MAC", "cfm.tlv.pbb_te.reverse_mac", FT_ETHER,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

				/* Organization-Specific TLV */
		{ &hf_tlv_org_spec_oui,
			{ "OUI", "cfm.tlv.org_spec.oui", FT_UINT24,
			BASE_OUI, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_org_spec_subtype,
			{ "Sub-Type", "cfm.tlv.org_spec.subtype", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_org_spec_value,
			{ "Value", "cfm.tlv.org_spec.value", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

				/* Test TLV */
		{ &hf_tlv_tst_test_pattern_type,
			{ "Test Pattern Type", "cfm.tlv.tst.test.pattern.type", FT_UINT8,
			BASE_DEC, VALS(test_tlv_pattern_type_vals), 0x0, NULL, HFILL }
		},
		{ &hf_tlv_tst_test_pattern,
			{ "Test Pattern", "cfm.tlv.tst.test.pattern", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_tst_CRC32,
			{ "CRC-32", "cfm.tlv.tst.crc32", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

				/* Target MEP/MIP ID TLV, Replying MEP/MIP ID TLV */
		{ &hf_tlv_tgt_rpl_mep_mip_id_subtype,
			{ "ID subtype", "cfm.tlv.tgt_rpl_mep_mip.id_subtype", FT_UINT8,
			BASE_DEC, VALS(mep_mip_id_tlv_subtype_vals), 0x0, NULL, HFILL }
		},
		{ &hf_tlv_tgt_rpl_padding,
			{ "Padding", "cfm.tlv.tgt_rpl_mep_mip.padding", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_tgt_rpl_mep_id,
			{ "MEP ID", "cfm.tlv.tgt_rpl_mep_mip.mep_id", FT_UINT16,
			BASE_DEC, NULL, 0x1FFF, NULL, HFILL }
		},
		{ &hf_tlv_tgt_rpl_mip_id_icc,
			{ "ITU-T Carrier Code", "cfm.tlv.tgt_rpl_mep_mip.icc", FT_STRINGZPAD,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_tgt_rpl_mip_id_node_id,
			{ "Node ID", "cfm.tlv.tgt_rpl_mep_mip.node_id", FT_UINT32,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_tgt_rpl_mip_id_if_num,
			{ "IF Num", "cfm.tlv.tgt_rpl_mep_mip.if_num", FT_UINT32,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_tlv_tgt_rpl_mip_id_cc,
			{ "Country Code", "cfm.tlv.tgt_rpl_mep_mip.cc", FT_STRINGZPAD,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

				/* Requesting MEP ID TLV */
		{ &hf_tlv_req_mep_id_lb,
			{ "ID subtype", "cfm.tlv.req_mep_id.lb", FT_UINT8,
			BASE_DEC, VALS(req_mep_id_tlv_lb_vals), 0x0, NULL, HFILL }
		},
		{ &hf_tlv_req_mep_id_reserved,
			{ "Reserved", "cfm.tlv.req_mep_id.reserved", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

				/* Test ID TLV */
		{ &hf_tlv_tst_id_test_id,
			{ "Test ID", "cfm.tlv.tst_id.test_id", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

				/* Unknown TLV */
		{ &hf_tlv_unknown_data,
			{ "TLV Data", "cfm.tlv.unknown.data", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
	};

	/* Setup protocol subtree array */
	static int *ett[] = {
		&ett_cfm,
		&ett_cfm_flags,
		&ett_cfm_maid,
		&ett_cfm_ccm_itu,
		&ett_cfm_pdu,
		&ett_cfm_all_tlvs,
		&ett_cfm_tlv,
		&ett_cfm_raps_status,
	};

	static ei_register_info ei[] = {
		{ &ei_tlv_tst_id_length,
			{ "cfm.tlv.tst_id.length", PI_PROTOCOL, PI_NOTE,
			  "Test ID TLV length is bits, not octets, unlike other TLVs",
			  EXPFILL }
		},
		{ &ei_tlv_management_addr_length,
			{ "cfm.tlv.sender_id.management_addr.length.zero",
			  PI_PROTOCOL, PI_WARN,
			  "Management Address Length should not be present if Management Address Domain Length is 0",
			  EXPFILL }
		},
	};

	expert_module_t* expert_cfm;

	proto_cfm = proto_register_protocol("CFM EOAM IEEE 802.1Q/ITU-T Y.1731 Protocol", "CFM", "cfm");

	cfm_handle = register_dissector("cfm", dissect_cfm, proto_cfm);

	proto_register_field_array(proto_cfm, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_cfm = expert_register_protocol(proto_cfm);
	expert_register_field_array(expert_cfm, ei, array_length(ei));
}

/* Register CFM EOAM protocol handler */
void proto_reg_handoff_cfm(void)
{
	dissector_add_uint("ethertype", ETHERTYPE_CFM, cfm_handle);
	dissector_add_uint("pwach.channel_type", PW_ACH_TYPE_MPLSTP_OAM, cfm_handle);
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
