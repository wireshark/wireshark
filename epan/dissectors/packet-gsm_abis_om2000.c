/* packet-abis_om2000.c
 * Routines for packet dissection of Ericsson A-bis OML (OM 2000)
 * Copyright 2010-2012 by Harald Welte <laforge@gnumonks.org>
 *
 * This dissector is not 100% complete, i.e. there are a number of FIXMEs
 * indicating where portions of the protocol are not dissected completely.
 * However, even a partial protocol decode is much more useful than no protocol
 * decode at all...
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

void proto_register_abis_om2000(void);

/* initialize the protocol and registered fields */
static int proto_abis_om2000;

static int hf_om2k_msg_code;
static int hf_om2k_mo_if;
static int hf_om2k_mo_class;
static int hf_om2k_mo_sub1;
static int hf_om2k_mo_sub2;
static int hf_om2k_mo_instance;

static int hf_om2k_aip;
static int hf_om2k_oip;
static int hf_om2k_comb;
static int hf_om2k_ts;
static int hf_om2k_hsn;
static int hf_om2k_maio;
static int hf_om2k_bsic;
static int hf_om2k_diversity;
static int hf_om2k_fn_offs;
static int hf_om2k_ext_range;
static int hf_om2k_irc;
static int hf_om2k_bs_pa_mfrms;
static int hf_om2k_bs_ag_blks_res;
static int hf_om2k_drx_dev_max;
static int hf_om2k_cr;
static int hf_om2k_ipt3;
static int hf_om2k_aop;
static int hf_om2k_t3105;
static int hf_om2k_ny1;
static int hf_om2k_cbi;
static int hf_om2k_tsc;
static int hf_om2k_icm;
static int hf_om2k_tta;
static int hf_om2k_icm_cr;
static int hf_om2k_lsc_fm;
static int hf_om2k_lsc_lsi;
static int hf_om2k_lsc_lsa;
static int hf_om2k_ls_ft;
static int hf_om2k_cst;
static int hf_om2k_ea;
static int hf_om2k_unknown_tag;
static int hf_om2k_unknown_val;
static int hf_om2k_nom_pwr;
static int hf_om2k_fill_mark;
static int hf_om2k_bcc;
static int hf_om2k_mo_state;
static int hf_om2k_la_state;
static int hf_om2k_tsn_state;
static int hf_om2k_bts_manuf;
static int hf_om2k_bts_gen;
static int hf_om2k_bts_rev;
static int hf_om2k_bts_var;
static int hf_om2k_brr;
static int hf_om2k_bfr;
static int hf_om2k_hwinfo_sig;
static int hf_om2k_capa_sig;
static int hf_om2k_file_rev;
static int hf_om2k_filerel_ilr;
static int hf_om2k_filerel_cur;
static int hf_om2k_filerel_other;
static int hf_om2k_cal_time;
static int hf_om2k_list_nr;
static int hf_om2k_list_nr_end;
static int hf_om2k_isl;
static int hf_om2k_isl_icp1;
static int hf_om2k_isl_icp2;
static int hf_om2k_isl_ci;
static int hf_om2k_conl;
static int hf_om2k_conl_nr_cgs;
static int hf_om2k_conl_nr_cps_cg;
static int hf_om2k_conl_ccp;
static int hf_om2k_conl_ci;
static int hf_om2k_conl_tag;
static int hf_om2k_conl_tei;
static int hf_om2k_tf_mode;
static int hf_om2k_tf_fs_offset;
static int hf_om2k_attr_id;
static int hf_om2k_attr_index;
static int hf_om2k_result_code;
static int hf_om2k_reason_code;
static int hf_om2k_iwd_type;
static int hf_om2k_iwd_gen_rev;
static int hf_om2k_trxc_list;
static int hf_om2k_max_allowed_power;
static int hf_om2k_max_allowed_num_trxcs;
static int hf_om2k_mctr_feat_sts_bitmap;
static int hf_om2k_config_type;
static int hf_om2k_jitter_size;
static int hf_om2k_packing_algo;
static int hf_om2k_power_bo_ctype_map;
static int hf_om2k_power_bo_priority;
static int hf_om2k_power_bo_value;

/* initialize the subtree pointers */
static int ett_om2000;
static int ett_om2k_mo;
static int ett_om2k_isl;
static int ett_om2k_conl;
static int ett_om2k_iwd;

static expert_field ei_om2k_not_performed;
static expert_field ei_om2k_reject;
static expert_field ei_om2k_nack;
static expert_field ei_om2k_ena_res_disabled;

static const value_string om2k_msgcode_vals[] = {
	{ 0x0000, "Abort SP Command" },
	{ 0x0002, "Abort SP Complete" },
	{ 0x0004, "Alarm Report ACK" },
	{ 0x0005, "Alarm Report NACK" },
	{ 0x0006, "Alarm Report" },
	{ 0x0008, "Alarm Status Request" },
	{ 0x000a, "Alarm Status Request Accept" },
	{ 0x000b, "Alarm Status Request Reject" },
	{ 0x000c, "Alarm Status Result ACK" },
	{ 0x000d, "Alarm Status Result NACK" },
	{ 0x000e, "Alarm Status Result" },
	{ 0x0010, "Calendar Time Response" },
	{ 0x0011, "Calendar Time Reject" },
	{ 0x0012, "Calendar Time Request" },
	{ 0x0014, "CON Configuration Request" },
	{ 0x0016, "CON Configuration Request Accept" },
	{ 0x0017, "CON Configuration Request Reject" },
	{ 0x0018, "CON Configuration Result ACK" },
	{ 0x0019, "CON Configuration Result NACK" },
	{ 0x001a, "CON Configuration Result" },
	{ 0x001c, "Connect Command" },
	{ 0x001e, "Connect Complete" },
	{ 0x001f, "Connect Reject" },
	{ 0x0028, "Disable Request" },
	{ 0x002a, "Disable Request Accept" },
	{ 0x002b, "Disable Request Reject" },
	{ 0x002c, "Disable Result ACK" },
	{ 0x002d, "Disable Result NACK" },
	{ 0x002e, "Disable Result" },
	{ 0x0030, "Disconnect Command" },
	{ 0x0032, "Disconnect Complete" },
	{ 0x0033, "Disconnect Reject" },
	{ 0x0034, "Enable Request" },
	{ 0x0036, "Enable Request Accept" },
	{ 0x0037, "Enable Request Reject" },
	{ 0x0038, "Enable Result ACK" },
	{ 0x0039, "Enable Result NACK" },
	{ 0x003a, "Enable Result" },
	{ 0x003c, "Escape Downlink Normal" },
	{ 0x003d, "Escape Downlink NACK" },
	{ 0x003e, "Escape Uplink Normal" },
	{ 0x003f, "Escape Uplink NACK" },
	{ 0x0040, "Fault Report ACK" },
	{ 0x0041, "Fault Report NACK" },
	{ 0x0042, "Fault Report" },
	{ 0x0044, "File Package End Command" },
	{ 0x0046, "File Package End Result" },
	{ 0x0047, "File Package End Reject" },
	{ 0x0048, "File Relation Request" },
	{ 0x004a, "File Relation Response" },
	{ 0x004b, "File Relation Request Reject" },
	{ 0x004c, "File Segment Transfer" },
	{ 0x004e, "File Segment Transfer Complete" },
	{ 0x004f, "File Segment Transfer Reject" },
	{ 0x0050, "HW Information Request" },
	{ 0x0052, "HW Information Request Accept" },
	{ 0x0053, "HW Information Request Reject" },
	{ 0x0054, "HW Information Result ACK" },
	{ 0x0055, "HW Information Result NACK" },
	{ 0x0056, "HW Information Result" },
	{ 0x0060, "IS Configuration Request" },
	{ 0x0062, "IS Configuration Request Accept" },
	{ 0x0063, "IS Configuration Request Reject" },
	{ 0x0064, "IS Configuration Result ACK" },
	{ 0x0065, "IS Configuration Result NACK" },
	{ 0x0066, "IS Configuration Result" },
	{ 0x0068, "Load Data End" },
	{ 0x006a, "Load Data End Result" },
	{ 0x006b, "Load Data End Reject" },
	{ 0x006c, "Load Data Init" },
	{ 0x006e, "Load Data Init Accept" },
	{ 0x006f, "Load Data Init Reject" },
	{ 0x0070, "Loop Control Command" },
	{ 0x0072, "Loop Control Complete" },
	{ 0x0073, "Loop Control Reject" },
	{ 0x0074, "Operational Information" },
	{ 0x0076, "Operational Information Accept" },
	{ 0x0077, "Operational Information Reject" },
	{ 0x0078, "Reset Command" },
	{ 0x007a, "Reset Complete" },
	{ 0x007b, "Reset Reject" },
	{ 0x007c, "RX Configuration Request" },
	{ 0x007e, "RX Configuration Request Accept" },
	{ 0x007f, "RX Configuration Request Reject" },
	{ 0x0080, "RX Configuration Result ACK" },
	{ 0x0081, "RX Configuration Result NACK" },
	{ 0x0082, "RX Configuration Result" },
	{ 0x0084, "Start Request" },
	{ 0x0086, "Start Request Accept" },
	{ 0x0087, "Start Request Reject" },
	{ 0x0088, "Start Result ACK" },
	{ 0x0089, "Start Result NACK" },
	{ 0x008a, "Start Result" },
	{ 0x008c, "Status Request" },
	{ 0x008e, "Status Response" },
	{ 0x008f, "Status Reject" },
	{ 0x0094, "Test Request" },
	{ 0x0096, "Test Request Accept" },
	{ 0x0097, "Test Request Reject" },
	{ 0x0098, "Test Result ACK" },
	{ 0x0099, "Test Result NACK" },
	{ 0x009a, "Test Result" },
	{ 0x00a0, "TF Configuration Request" },
	{ 0x00a2, "TF Configuration Request Accept" },
	{ 0x00a3, "TF Configuration Request Reject" },
	{ 0x00a4, "TF Configuration Result ACK" },
	{ 0x00a5, "TF Configuration Result NACK" },
	{ 0x00a6, "TF Configuration Result" },
	{ 0x00a8, "TS Configuration Request" },
	{ 0x00aa, "TS Configuration Request Accept" },
	{ 0x00ab, "TS Configuration Request Reject" },
	{ 0x00ac, "TS Configuration Result ACK" },
	{ 0x00ad, "TS Configuration Result NACK" },
	{ 0x00ae, "TS Configuration Result" },
	{ 0x00b0, "TX Configuration Request" },
	{ 0x00b2, "TX Configuration Request Accept" },
	{ 0x00b3, "TX Configuration Request Reject" },
	{ 0x00b4, "TX Configuration Result ACK" },
	{ 0x00b5, "TX Configuration Result NACK" },
	{ 0x00b6, "TX Configuration Result" },
	{ 0x00bc, "DIP Alarm Report ACK" },
	{ 0x00bd, "DIP Alarm Report NACK" },
	{ 0x00be, "DIP Alarm Report" },
	{ 0x00c0, "DIP Alarm Status Request" },
	{ 0x00c2, "DIP Alarm Status Response" },
	{ 0x00c3, "DIP Alarm Status Reject" },
	{ 0x00c4, "DIP Quality Report I ACK" },
	{ 0x00c5, "DIP Quality Report I NACK" },
	{ 0x00c6, "DIP Quality Report I" },
	{ 0x00c8, "DIP Quality Report II ACK" },
	{ 0x00c9, "DIP Quality Report II NACK" },
	{ 0x00ca, "DIP Quality Report II" },
	{ 0x00dc, "DP Configuration Request" },
	{ 0x00de, "DP Configuration Request Accept" },
	{ 0x00df, "DP Configuration Request Reject" },
	{ 0x00e0, "DP Configuration Result ACK" },
	{ 0x00e1, "DP Configuration Result NACK" },
	{ 0x00e2, "DP Configuration Result" },
	{ 0x00e4, "Capabilities HW Info Report ACK" },
	{ 0x00e5, "Capabilities HW Info Report NACK" },
	{ 0x00e6, "Capabilities HW Info Report" },
	{ 0x00e8, "Capabilities Request" },
	{ 0x00ea, "Capabilities Request Accept" },
	{ 0x00eb, "Capabilities Request Reject" },
	{ 0x00ec, "Capabilities Result ACK" },
	{ 0x00ed, "Capabilities Result NACK" },
	{ 0x00ee, "Capabilities Result" },
	{ 0x00f0, "FM Configuration Request" },
	{ 0x00f2, "FM Configuration Request Accept" },
	{ 0x00f3, "FM Configuration Request Reject" },
	{ 0x00f4, "FM Configuration Result ACK" },
	{ 0x00f5, "FM Configuration Result NACK" },
	{ 0x00f6, "FM Configuration Result" },
	{ 0x00f8, "FM Report Request" },
	{ 0x00fa, "FM Report Response" },
	{ 0x00fb, "FM Report Reject" },
	{ 0x00fc, "FM Start Command" },
	{ 0x00fe, "FM Start Complete" },
	{ 0x00ff, "FM Start Reject" },
	{ 0x0100, "FM Stop Command" },
	{ 0x0102, "FM Stop Complete" },
	{ 0x0103, "FM Stop Reject" },
	{ 0x0104, "Negotiation Request ACK" },
	{ 0x0105, "Negotiation Request NACK" },
	{ 0x0106, "Negotiation Request" },
	{ 0x0108, "BTS Initiated Request ACK" },
	{ 0x0109, "BTS Initiated Request NACK" },
	{ 0x010a, "BTS Initiated Request" },
	{ 0x010c, "Radio Channels Release Command" },
	{ 0x010e, "Radio Channels Release Complete" },
	{ 0x010f, "Radio Channels Release Reject" },
	{ 0x0118, "Feature Control Command" },
	{ 0x011a, "Feature Control Complete" },
	{ 0x011b, "Feature Control Reject" },

	/* Observed with RBS6000 / DUG 20 */
	{ 0x012c, "MCTR Configuration Request" },
	{ 0x012e, "MCTR Configuration Request Accept" },
	{ 0x012f, "MCTR Configuration Request Reject" },
	{ 0x0130, "MCTR Configuration Result ACK" },
	{ 0x0131, "MCTR Configuration Result NACK" },
	{ 0x0132, "MCTR Configuration Result" },

	{ 0, NULL }
};
static value_string_ext om2k_msgcode_vals_ext = VALUE_STRING_EXT_INIT(om2k_msgcode_vals);

/* TS 12.21 Section 9.4: Attributes */
static const value_string om2k_attr_vals[] = {
	{ 0x00, "Accordance indication" },
	{ 0x01, "Alarm Id" },
	{ 0x02, "Alarm Data" },
	{ 0x03, "Alarm Severity" },
	{ 0x04, "Alarm Status" },
	{ 0x05, "Alarm Status Type" },
	{ 0x06, "BCC" },
	{ 0x07, "BS_AG_BKS_RES" },
	{ 0x09, "BSIC" },
	{ 0x0a, "BA_PA_MFRMS" },
	{ 0x0b, "CBCH Indicator" },
	{ 0x0c, "CCCH Options" },
	{ 0x0d, "Calendar Time" },
	{ 0x0f, "Channel Combination" },
	{ 0x10, "CON Connection List" },
	{ 0x11, "Data End Indication" },
	{ 0x12, "DRX_DEV_MAX" },
	{ 0x13, "End List Number" },
	{ 0x14, "External Condition Map Class 1" },
	{ 0x15, "External Condition Map Class 2" },
	{ 0x16, "File Relation Indication" },
	{ 0x17, "File Revision" },
	{ 0x18, "File Segment Data" },
	{ 0x19, "File Segment Length" },
	{ 0x1a, "File Segment Sequence Number" },
	{ 0x1b, "File Size" },
	{ 0x1c, "Filling Marker" },
	{ 0x1d, "FN Offset" },
	{ 0x1e, "Frequency List" },
	{ 0x1f, "Frequency Specifier RX" },
	{ 0x20, "Frequency Specifier TX" },
	{ 0x21, "HSN" },
	{ 0x22, "ICM Indicator" },
	{ 0x23, "Internal Fault Map Class 1A" },
	{ 0x24, "Internal Fault Map Class 1B" },
	{ 0x25, "Internal Fault Map Class 2A" },
	{ 0x26, "Internal Fault Map Class 2A Extension" },
	{ 0x27, "IS Connection List" },
	{ 0x28, "List Number" },
	{ 0x29, "File Package State Indication" },
	{ 0x2a, "Local Access State" },
	{ 0x2b, "MAIO" },
	{ 0x2c, "MO State" },
	{ 0x2d, "Ny1" },
	{ 0x2e, "Operational Information" },
	{ 0x2f, "Power" },
	{ 0x30, "RU Position Data" },
	{ 0x31, "Protocol Error" },
	{ 0x32, "Reason Code" },
	{ 0x33, "Receiver Diversity" },
	{ 0x34, "Replacement Unit Map" },
	{ 0x35, "Result Code" },
	{ 0x36, "RU Revision Data" },
	{ 0x38, "T3105" },
	{ 0x39, "Test Loop Setting" },
	{ 0x3a, "TF Mode" },
	{ 0x3b, "TF Compensation Value" },
	{ 0x3c, "Time Slot Number" },
	{ 0x3d, "TSC" },
	{ 0x3e, "RU Logical Id" },
	{ 0x3f, "RU Serial Number Data" },
	{ 0x40, "BTS Version" },
	{ 0x41, "OML IWD Version" },
	{ 0x42, "RWL IWD Version" },
	{ 0x43, "OML Function Map 1" },
	{ 0x44, "OML Function Map 2" },
	{ 0x45, "RSL Function Map 1" },
	{ 0x46, "RSL Function Map 2" },
	{ 0x47, "Extended Range Indicator" },
	{ 0x48, "Request Indicators" },
	{ 0x49, "DIP Alarm Condition Map" },
	{ 0x4a, "ES Incoming" },
	{ 0x4b, "ES Outgoing" },
	{ 0x4e, "SES Incoming" },
	{ 0x4f, "SES Outgoing" },
	{ 0x50, "Replacement Unit Map Extension" },
	{ 0x52, "UAS Incoming" },
	{ 0x53, "UAS Outgoing" },
	{ 0x58, "DF Incoming" },
	{ 0x5a, "DF Outgoing" },
	{ 0x5c, "SF" },
	{ 0x60, "S Bits Setting" },
	{ 0x61, "CRC-4 Use Option" },
	{ 0x62, "T Parameter" },
	{ 0x63, "N Parameter" },
	{ 0x64, "N1 Parameter" },
	{ 0x65, "N3 Parameter" },
	{ 0x66, "N4 Parameter" },
	{ 0x67, "P Parameter" },
	{ 0x68, "Q Parameter" },
	{ 0x69, "BI_Q1" },
	{ 0x6a, "BI_Q2" },
	{ 0x74, "ICM Boundary Parameters" },
	{ 0x77, "AFT" },
	{ 0x78, "AFT RAI" },
	{ 0x79, "Link Supervision Control" },
	{ 0x7a, "Link Supervision Filtering Time" },
	{ 0x7b, "Call Supervision Time" },
	{ 0x7c, "Interval Length UAS Incoming" },
	{ 0x7d, "Interval Length UAS Outgoing" },
	{ 0x7e, "ICM Channel Rate" },
	{ 0x7f, "Attribute Identifier" },
	{ 0x80, "FM Frequency List" },
	{ 0x81, "FM Frequency Report" },
	{ 0x82, "FM Percentile" },
	{ 0x83, "FM Clear Indication" },
	{ 0x84, "HW Info Signature" },
	{ 0x85, "MO Record" },
	{ 0x86, "TF Synchronisation Source" },
	{ 0x87, "TTA" },
	{ 0x88, "End Segment Number" },
	{ 0x89, "Segment Number" },
	{ 0x8a, "Capabilities Signature" },
	{ 0x8c, "File Relation List" },
	{ 0x90, "Negotiation Record I" },
	{ 0x91, "Negotiation Record II" },
	{ 0x92, "Encryption Algorithm" },
	{ 0x94, "Interference Rejection Combining" },
	{ 0x95, "Dedication Information" },
	{ 0x97, "Feature Code" },
	{ 0x98, "FS Offset" },
	{ 0x99, "ESB Timeslot" },
	{ 0x9a, "Master TG Instance" },
	{ 0x9b, "Master TX Chain Delay" },
	{ 0x9c, "External Condition Class 2 Extension" },
	{ 0x9d, "TSs MO State" },
	{ 0x9e, "Configuration Type" },
	{ 0x9f, "Jitter Size" },
	{ 0xa0, "Packing Algorithm" },
	{ 0xa8, "TRXC List" },
	{ 0xa9, "Maximum Allowed Power" },
	{ 0xaa, "Maximum Allowed Number of TRXCs" },
	{ 0xab, "MCTR Feature Status Bitmap" },
	{ 0xae, "Power Back-off Channel Type Map" },
	{ 0xaf, "Power Back-off Priority" },
	{ 0xb0, "Power Back-off Value" },
	{ 0, NULL }
};
static value_string_ext om2k_attr_vals_ext = VALUE_STRING_EXT_INIT(om2k_attr_vals);

static const value_string om2k_diversity_vals[] = {
	{ 0x01, "B receiver side" },
	{ 0x02, "A receiver side" },
	{ 0x03, "A+B receiver sides" },
	{ 0x04, "A+B+C+D receiver sides" },
	{ 0, NULL }
};

static const value_string om2k_oip_vals[] = {
	{ 0x00, "Not Operational" },
	{ 0x01, "Operational" },
	{ 0, NULL }
};

static const value_string om2k_aip_vals[] = {
	{ 0x00, "Data according to request" },
	{ 0x01, "Data not according to request" },
	{ 0x02, "Inconsistent MO data" },
	{ 0x03, "Capability constraint violation" },
	{ 0, NULL }
};

static const value_string om2k_comb_vals[] = {
	{ 0x03, "SDCCH/8 + SACCH/C8" },
	{ 0x04, "BCCH, non-combined" },
	{ 0x05, "BCCH, combined (SDCCH/4)" },
	{ 0x08, "TCH Type, unspecified" },
	{ 0, NULL }
};

static const value_string om2k_icmcr_vals[] = {
	{ 0x00, "ICM as per TCH/F" },
	{ 0x01, "ICM as per TCH/H(0 and 1)" },
	{ 0, NULL }
};

static const value_string om2k_ea_vals[] = {
	{ 0x00, "A5/1 and A5/2" },
	{ 0x01, "A5/2 only" },
	{ 0, NULL }
};

static const value_string om2k_fill_vals[] = {
	{ 0x00, "Filling" },
	{ 0x01, "No filling" },
	{ 0, NULL }
};

static const value_string om2k_mo_state_vals[] = {
	{ 0x00, "RESET" },
	{ 0x01, "STARTED" },
	{ 0x02, "ENABLED" },
	{ 0x03, "DISABLED" },
	{ 0, NULL }
};

static const value_string om2k_la_state_vals[] = {
	{ 0x00, "LOCALLY CONNECTED" },
	{ 0x01, "LOCALLY DISCONNECTED" },
	{ 0, NULL }
};

static const value_string filerel_state_vals[] = {
	{ 0x00, "Not known in current state (unknown file)" },
	{ 0x01, "allowed, already loaded" },
	{ 0x02, "allowed, not loaded" },
	{ 0x03, "not allowed" },
	{ 0, NULL }
};

static const value_string om2k_mo_class_short_vals[] = {
	{ 0x01, "TRXC" },
	{ 0x02, "TG" },
	{ 0x03, "TS" },
	{ 0x04, "TF" },
	{ 0x05, "IS" },
	{ 0x06, "CON" },
	{ 0x07, "DP" },
	{ 0x08, "MCTR" },
	{ 0x0a, "CF" },
	{ 0x0b, "TX" },
	{ 0x0c, "RX" },
	{ 0, NULL }
};

static const value_string om2k_mo_class_vals[] = {
	{ 0x01, "TRXC (TRX Controller)" },
	{ 0x02, "TG (TRX Group)" },
	{ 0x03, "TS (Timeslot)" },
	{ 0x04, "TF (Timing Function)" },
	{ 0x05, "IS (Interface Switch)" },
	{ 0x06, "CON (Concentrator)" },
	{ 0x07, "DP (Data Path)" },
	{ 0x08, "MCTR (Multi Carrier TRansceiver)" },
	{ 0x0a, "CF (Central Function)" },
	{ 0x0b, "TX (Transmitter)" },
	{ 0x0c, "RX (Receiver)" },
	{ 0, NULL }
};

static const value_string om2k_tf_mode_vals[] = {
	{ 0x00, "Master" },
	{ 0x01, "Standalone" },
	{ 0x02, "Slave" },
	{ 0xff, "Not defined" },
	{ 0, NULL }
};

static const value_string om2k_attr_id_vals[] = {
	{ 0x0005, "Alarm Status Type" },
	{ 0x0007, "Input BS_AG_BLKS_RES" },
	{ 0x001d, "Input FN Offset" },
	{ 0x002f, "Power GMSK" },
	{ 0x0033, "Receiver Diversity" },
	{ 0x0037, "Power 8-PSK" },
	{ 0x003a, "TF Mode" },
	{ 0x0043, "File Supported Functions OML I" },
	{ 0x0044, "File Supported Functions OML II" },
	{ 0x0045, "File Supported Functions RSL I" },
	{ 0x0046, "File Supported Functions RSL II" },
	{ 0x0047, "Input Extended Range" },
	{ 0x0086, "TF Synchronization Source" },
	{ 0x0101, "Alarm Information" },
	{ 0x0127, "ICPs Signaling" },
	{ 0x0143, "TG Supported Functions OML I" },
	{ 0x0144, "TG Supported Functions OML II" },
	{ 0x0145, "TG Supported Functions RSL I" },
	{ 0x0146, "TG Supported Functions RSL II" },
	{ 0x01ff, "ICPs IS" },
	{ 0x0227, "ICPs Traffic" },
	{ 0x0243, "TRXC Supported Functions OML I" },
	{ 0x0244, "TRXC Supported Functions OML II" },
	{ 0x0245, "TRXC Supported Functions RSL I" },
	{ 0x0246, "TRXC Supported Functions RSL II" },
	{ 0x02ff, "Cascadable" },
	{ 0x0327, "ICPs PCM" },
	{ 0x03ff, "TEI" },
	{ 0x041f, "ARFCN AB RX" },
	{ 0x0420, "ARFCN TX" },
	{ 0x0427, "ICPs CON" },
	{ 0x04ff, "TCH Capabilities" },
	{ 0x0527, "ICP Group" },
	{ 0x05ff, "Cascade downlink" },
	{ 0x0627, "ICP Group Capacity" },
	{ 0x07ff, "CRC-4 Option" },
	{ 0x0bff, "Hopping Type" },
	{ 0x0cff, "TRXC Domain" },
	{ 0x19ff, "Band AB RX" },
	{ 0x1aff, "Band TX" },
	{ 0x1bff, "TX Chain Delay" },
	{ 0, NULL }
};

static value_string_ext om2k_attr_id_vals_ext = VALUE_STRING_EXT_INIT(om2k_attr_id_vals);

static const value_string om2k_res_code_vals[] = {
	{ 0x02, "Wrong state or out of sequence" },
	{ 0x03, "File error" },
	{ 0x04, "Fault, unspecified" },
	{ 0x05, "Tuning fault" },
	{ 0x06, "Protocol error" },
	{ 0x07, "MO not connected" },
	{ 0x08, "Parameter error" },
	{ 0x09, "Operational function not supported" },
	{ 0x0a, "Local Access state LOCALLY DISCONNECTED" },
	{ 0, NULL }
};

static const value_string om2k_iwd_type_vals[] = {
	{ 0x00, "OML" },
	{ 0x01, "RSL" },
	{ 0x02, "GSL" },
	{ 0x03, "TRA" },
	{ 0, NULL }
};

static int
dissect_tss_mo_state(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	uint8_t tmp;
	unsigned  i = 0;

	for (i = 0; i < 8; i+= 2) {
		tmp = tvb_get_guint8(tvb, offset);
		proto_tree_add_uint_format(tree, hf_om2k_tsn_state, tvb, offset, 1, tmp & 0xf,
					   "Timeslot %u MO State: %s", i,
					   val_to_str(tmp & 0xf, om2k_mo_state_vals, "unknown (%02d)"));
		proto_tree_add_uint_format(tree, hf_om2k_tsn_state, tvb, offset, 1, tmp >> 4,
					   "Timeslot %u MO State: %s", i+1,
					   val_to_str(tmp >> 4, om2k_mo_state_vals, "unknown (%02d)"));
		offset++;
	}

	return 4;
}


static int
dissect_om2k_time(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	nstime_t  tmptime;
	time_t    tval;
	struct tm _time;

	_time.tm_year  = 100 + tvb_get_guint8(tvb, offset++);
	_time.tm_mon   = tvb_get_guint8(tvb, offset++) - 1;
	_time.tm_mday  = tvb_get_guint8(tvb, offset++);
	_time.tm_hour  = tvb_get_guint8(tvb, offset++);
	_time.tm_min   = tvb_get_guint8(tvb, offset++);
	_time.tm_sec   = tvb_get_guint8(tvb, offset++);
	_time.tm_isdst = -1;

	tval           = mktime(&_time);
	tmptime.secs   = tval;
	tmptime.nsecs  = 0;

	proto_tree_add_time(tree, hf_om2k_cal_time, tvb, offset, 6,
			    &tmptime);
	return 6;
}

static int
dissect_om2k_attr_unkn(tvbuff_t *tvb, packet_info *pinfo, int offset, int len, int iei, proto_tree *tree)
{
	proto_tree_add_bytes_format(tree, hf_om2k_unknown_val, tvb,
				    offset, len, NULL,
				    "%s: %s",
				    val_to_str_ext(iei, &om2k_attr_vals_ext, "0x%02x"),
				    tvb_bytes_to_str(pinfo->pool, tvb, offset, len));
	return len;
}

static int
dissect_om2k_is_list(tvbuff_t *tvb, int base_offset, proto_tree *tree)
{
	int         offset = base_offset;
	proto_item *ti;
	proto_tree *isl_tree;
	uint8_t     len    = tvb_get_guint8(tvb, offset++);

	ti       = proto_tree_add_item(tree, hf_om2k_isl, tvb, offset, len, ENC_NA);
	isl_tree = proto_item_add_subtree(ti, ett_om2k_isl);

	while (offset < base_offset + len) {
		proto_tree_add_item(isl_tree, hf_om2k_isl_icp1, tvb,
				    offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(isl_tree, hf_om2k_isl_icp2, tvb,
				    offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(isl_tree, hf_om2k_isl_ci, tvb,
				    offset++, 1, ENC_BIG_ENDIAN);
	}
	return offset - base_offset;
}

static int
dissect_om2k_con_list(tvbuff_t *tvb, int base_offset, proto_tree *tree)
{
	int         offset = base_offset;
	proto_item *ti;
	proto_tree *conl_tree;
	uint8_t     len    = tvb_get_guint8(tvb, offset++);

	ti = proto_tree_add_item(tree, hf_om2k_conl, tvb, offset, len, ENC_NA);
	conl_tree = proto_item_add_subtree(ti, ett_om2k_conl);

	proto_tree_add_item(conl_tree, hf_om2k_conl_nr_cgs, tvb,
			    offset++, 1, ENC_BIG_ENDIAN);

	while (offset < base_offset + len) {
		uint8_t nr_cps_cg = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(conl_tree, hf_om2k_conl_nr_cps_cg, tvb,
				    offset++, 1, ENC_BIG_ENDIAN);
		while (nr_cps_cg--) {
			proto_tree_add_item(conl_tree, hf_om2k_conl_ccp, tvb,
				    offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(conl_tree, hf_om2k_conl_ci, tvb,
				    offset++, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(conl_tree, hf_om2k_conl_tag, tvb,
				    offset++, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(conl_tree, hf_om2k_conl_tei, tvb,
				    offset++, 1, ENC_BIG_ENDIAN);
		}
	}
	return offset - base_offset;
}

static int
dissect_om2k_negotiation_record1(tvbuff_t *tvb, int base_offset, proto_tree *tree)
{
	int offset = base_offset;
	uint8_t i;
	uint8_t num_iwd = tvb_get_guint8(tvb, offset++);

	for (i = 0; i < num_iwd; i++) {
		uint8_t j;
		proto_item *ti;
		proto_tree *iwd_tree;
		uint8_t num_vers = tvb_get_guint8(tvb, offset++);

		ti = proto_tree_add_item(tree, hf_om2k_iwd_type, tvb, offset++, 1, ENC_NA);
		iwd_tree = proto_item_add_subtree(ti, ett_om2k_iwd);

		for (j = 0; j < num_vers; j++) {
			proto_tree_add_item(iwd_tree, hf_om2k_iwd_gen_rev, tvb,
					    offset, 6, ENC_ASCII);
			offset += 6;
		}
	}
	return offset - base_offset;
}

static int
dissect_om2k_mo_record(tvbuff_t *tvb, packet_info *pinfo, int base_offset, int len, proto_tree *tree)
{
	int offset = base_offset;
	proto_tree_add_item(tree, hf_om2k_mo_class, tvb, offset++, 1, ENC_NA);
	proto_tree_add_item(tree, hf_om2k_mo_instance, tvb, offset++, 1, ENC_NA);

	while (offset < len) {
		uint16_t attr_id;
		uint8_t attr_len;

		attr_id = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
		offset += 2;
		attr_len = tvb_get_guint8(tvb, offset++);
		offset += dissect_om2k_attr_unkn(tvb, pinfo, offset, attr_len, attr_id, tree);
	}

	return offset - base_offset;
}

static int
dissect_om2k_negotiation_record2(tvbuff_t *tvb, int base_offset, proto_tree *tree)
{
	int offset = base_offset;
	uint8_t i;
	uint8_t num_iwd = tvb_get_guint8(tvb, offset++);

	for (i = 0; i < num_iwd; i++) {
		proto_item *ti;
		proto_tree *iwd_tree;

		ti = proto_tree_add_item(tree, hf_om2k_iwd_type, tvb, offset++, 1, ENC_NA);
		iwd_tree = proto_item_add_subtree(ti, ett_om2k_iwd);

		proto_tree_add_item(iwd_tree, hf_om2k_iwd_gen_rev, tvb,
				    offset, 6, ENC_ASCII);
		offset += 6;
	}
	return offset - base_offset;
}



static int
dissect_om2k_attrs(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, uint16_t msg_code)
{
	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		uint8_t iei = tvb_get_guint8(tvb, offset++);
		uint8_t len, tmp;
		proto_item *ti;

		switch (iei) {
		case 0x00: /* Accordance Information */
			tmp = tvb_get_guint8(tvb, offset);
			ti = proto_tree_add_item(tree, hf_om2k_aip, tvb,
						 offset++, 1, ENC_BIG_ENDIAN);
			if (tmp != 0x00)
				expert_add_info(pinfo, ti, &ei_om2k_not_performed);
			break;
		case 0x06: /* BCC */
			proto_tree_add_item(tree, hf_om2k_bcc, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x07: /* BS_AG_BLKS_RES */
			proto_tree_add_item(tree, hf_om2k_bs_ag_blks_res, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x09: /* BSIC */
			proto_tree_add_item(tree, hf_om2k_bsic, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x0a: /* BS_PA_MFRMS */
			proto_tree_add_item(tree, hf_om2k_bs_pa_mfrms, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x0b: /* CBCH indicator */
			proto_tree_add_item(tree, hf_om2k_cbi, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x0c: /* CCCH Options */
			proto_tree_add_item(tree, hf_om2k_cr, tvb,
					    offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_om2k_ipt3, tvb,
					    offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_om2k_aop, tvb,
					    offset, 1, ENC_BIG_ENDIAN);
			offset++;
			break;
		case 0x0d: /* Calendar Time */
			offset += dissect_om2k_time(tvb, offset, tree);
			break;
		case 0x0f: /* Combination */
			proto_tree_add_item(tree, hf_om2k_comb, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x10: /* CON Connection List */
			offset += dissect_om2k_con_list(tvb, offset, tree);
			break;
		case 0x12: /* DRX_DEV_MAX */
			proto_tree_add_item(tree, hf_om2k_drx_dev_max, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x13: /* End List Number */
			proto_tree_add_item(tree, hf_om2k_list_nr_end, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x14: /* External Condition Map Class 1 */
			/* FIXME */
		case 0x15: /* External Condition Map Class 2 */
			/* FIXME */
			offset += dissect_om2k_attr_unkn(tvb, pinfo, offset, 2, iei, tree);
			break;
		case 0x16: /* File Relation Indication */
			proto_tree_add_item(tree, hf_om2k_filerel_ilr, tvb,
					    offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_om2k_filerel_cur, tvb,
					    offset, 1, ENC_BIG_ENDIAN);
			offset++;
			proto_tree_add_item(tree, hf_om2k_filerel_other, tvb,
					    offset, 1, ENC_BIG_ENDIAN);
			offset++;
			break;
		case 0x17: /* File Revision */
			proto_tree_add_item(tree, hf_om2k_file_rev, tvb,
					    offset, 8, ENC_ASCII);
			offset += 8;
			break;
		case 0x1c: /* Filling Marker */
			proto_tree_add_item(tree, hf_om2k_fill_mark, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x1d: /* FN Offset */
			proto_tree_add_item(tree, hf_om2k_fn_offs, tvb,
					    offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			break;
		case 0x1e: /* Frequency List */
			len = tvb_get_guint8(tvb, offset++);
			/* FIXME */
			offset += dissect_om2k_attr_unkn(tvb, pinfo, offset, len, iei, tree);
			break;
		case 0x1f: /* Frequency Specifier Rx */
			/* FIXME */
		case 0x20: /* Frequency Specifier Rx */
			/* FIXME */
			offset += dissect_om2k_attr_unkn(tvb, pinfo, offset, 2, iei, tree);
			break;
		case 0x21: /* HSN */
			proto_tree_add_item(tree, hf_om2k_hsn, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x22: /* ICM */
			proto_tree_add_item(tree, hf_om2k_icm, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x23: /* Internal Fault Map Class 1A */
			/* FIXME */
		case 0x24: /* Internal Fault Map Class 1B */
			/* FIXME */
		case 0x25: /* Internal Fault Map Class 2A */
			/* FIXME */
		case 0x26: /* Internal Fault Map Class 2A Ext */
			/* FIXME */
			offset += dissect_om2k_attr_unkn(tvb, pinfo, offset, 6, iei, tree);
			break;
		case 0x27: /* IS Connection List */
			offset += dissect_om2k_is_list(tvb, offset, tree);
			break;
		case 0x28: /* List Number */
			proto_tree_add_item(tree, hf_om2k_list_nr, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x2a: /* Local Access State */
			proto_tree_add_item(tree, hf_om2k_la_state, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x2b: /* MAIO */
			proto_tree_add_item(tree, hf_om2k_maio, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x2c: /* MO State */
			tmp = tvb_get_guint8(tvb, offset);
			ti = proto_tree_add_item(tree, hf_om2k_mo_state, tvb,
						 offset++, 1, ENC_BIG_ENDIAN);
			if (msg_code == 0x3a && tmp != 0x02)
				expert_add_info(pinfo, ti, &ei_om2k_ena_res_disabled);
			break;
		case 0x2d: /* Ny1 */
			proto_tree_add_item(tree, hf_om2k_ny1, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x2e: /* Operational Information */
			proto_tree_add_item(tree, hf_om2k_oip, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x2f: /* Nominal Power */
			proto_tree_add_item(tree, hf_om2k_nom_pwr, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x32: /* Reason Code */
			proto_tree_add_item(tree, hf_om2k_reason_code, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x33: /* Receiver Diversity */
			proto_tree_add_item(tree, hf_om2k_diversity, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x34: /* Replacement Unit Map */
			/* FIXME */
			offset += dissect_om2k_attr_unkn(tvb, pinfo, offset, 6, iei, tree);
			break;
		case 0x35: /* Result Code */
			proto_tree_add_item(tree, hf_om2k_result_code, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x38: /* T3105 */
			proto_tree_add_item(tree, hf_om2k_t3105, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x3a: /* TF Mode */
			proto_tree_add_item(tree, hf_om2k_tf_mode, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x3c: /* TS Number */
			proto_tree_add_item(tree, hf_om2k_ts, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x3d: /* TSC */
			proto_tree_add_item(tree, hf_om2k_tsc, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x40: /* BTS Version */
			proto_tree_add_item(tree, hf_om2k_bts_manuf, tvb,
					    offset, 3, ENC_ASCII);
			offset += 3;
			proto_tree_add_item(tree, hf_om2k_bts_gen, tvb,
					    offset, 3, ENC_ASCII);
			offset += 3;
			proto_tree_add_item(tree, hf_om2k_bts_rev, tvb,
					    offset, 3, ENC_ASCII);
			offset += 3;
			proto_tree_add_item(tree, hf_om2k_bts_var, tvb,
					    offset, 3, ENC_ASCII);
			offset += 3;
			break;
		case 0x43: /* OML Function Map 1 */
		case 0x44: /* OML Function Map 2 */
		case 0x45: /* RSL Function Map 1 */
		case 0x46: /* RSL Function Map 2 */
			len = tvb_get_guint8(tvb, offset++);
			/* FIXME */
			offset += dissect_om2k_attr_unkn(tvb, pinfo, offset, len, iei, tree);
			break;
		case 0x47: /* Ext Range */
			proto_tree_add_item(tree, hf_om2k_ext_range, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x48: /* Request Indicators */
			proto_tree_add_item(tree, hf_om2k_brr, tvb,
					    offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_om2k_bfr, tvb,
					    offset, 1, ENC_BIG_ENDIAN);
			offset++;
			break;
		case 0x50: /* Replacement Unit Map Extension */
			/* FIXME */
			offset += dissect_om2k_attr_unkn(tvb, pinfo, offset, 6, iei, tree);
			break;
		case 0x74: /* ICM Boundary */
			/* FIXME */
			offset += dissect_om2k_attr_unkn(tvb, pinfo, offset, 5, iei, tree);
			break;
		case 0x79: /* Link Supervision Control */
			proto_tree_add_item(tree, hf_om2k_lsc_fm, tvb,
					    offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_om2k_lsc_lsi, tvb,
					    offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_om2k_lsc_lsa, tvb,
					    offset, 1, ENC_BIG_ENDIAN);
			offset++;
			break;
		case 0x7a: /* Link Supervision Control */
			proto_tree_add_item(tree, hf_om2k_ls_ft, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x7b: /* Call Supervision Time */
			proto_tree_add_item(tree, hf_om2k_cst, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x7e: /* ICM Channel Rate */
			proto_tree_add_item(tree, hf_om2k_icm_cr, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x7f: /* Attribute ID */
			proto_tree_add_item(tree, hf_om2k_attr_id, tvb,
					    offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_om2k_attr_index, tvb,
					    offset+2, 1, ENC_BIG_ENDIAN);
			offset += 3;
			break;
		case 0x84: /* HW Info Signature */
			proto_tree_add_item(tree, hf_om2k_hwinfo_sig, tvb,
					    offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			break;
		case 0x85: /* MO Record */
			offset += dissect_om2k_mo_record(tvb, pinfo, offset, tvb_reported_length_remaining(tvb, offset), tree);
			break;
		case 0x87: /* TTA */
			proto_tree_add_item(tree, hf_om2k_tta, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x8a: /* Capabilities Signature */
			proto_tree_add_item(tree, hf_om2k_capa_sig, tvb,
					    offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			break;
		case 0x90: /* Negotiation Record I */
			offset++; /* skip len field */
			offset += dissect_om2k_negotiation_record1(tvb, offset, tree);
			break;
		case 0x91: /* Negotiation Record II */
			offset++; /* skip len field */
			offset += dissect_om2k_negotiation_record2(tvb, offset, tree);
			break;
		case 0x92: /* Encryption Algorithm */
			proto_tree_add_item(tree, hf_om2k_ea, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x94: /* Interference Rejection Combining */
			proto_tree_add_item(tree, hf_om2k_irc, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x95: /* Dedication information */
			/* FIXME */
			offset += dissect_om2k_attr_unkn(tvb, pinfo, offset, 3, iei, tree);
			break;
		case 0x98: /* FS Offset */
			proto_tree_add_item(tree, hf_om2k_tf_fs_offset, tvb,
					    offset, 5, ENC_BIG_ENDIAN);
			offset += 5;
			break;
		case 0x9c: /* External Condition Class 2 Extension */
			/* FIXME */
			offset += dissect_om2k_attr_unkn(tvb, pinfo, offset, 4, iei, tree);
			break;
		case 0x9d: /* TSs MO State */
			offset += dissect_tss_mo_state(tvb, offset, tree);
			break;
		case 0x9e: /* Configuration Type */
			proto_tree_add_item(tree, hf_om2k_config_type, tvb, offset++, 1, ENC_NA);
			break;
		case 0x9f: /* Jitter Size */
			proto_tree_add_item(tree, hf_om2k_jitter_size, tvb, offset++, 1, ENC_NA);
			break;
		case 0xa0: /* Packing Algorithm */
			proto_tree_add_item(tree, hf_om2k_packing_algo, tvb, offset++, 1, ENC_NA);
			break;
		case 0xa8: /* TRXC List (bitmap) */
			proto_tree_add_item(tree, hf_om2k_trxc_list, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
			break;
		case 0xa9: /* Maximum Allowed Power */
			proto_tree_add_item(tree, hf_om2k_max_allowed_power, tvb, offset, 1, ENC_NA);
			offset += 1;
			break;
		case 0xaa: /* Maximum Allowed Number of TRXCs */
			proto_tree_add_item(tree, hf_om2k_max_allowed_num_trxcs, tvb, offset, 1, ENC_NA);
			offset += 1;
			break;
		case 0xab: /* MCTR Feature Status Bitmap */
			tmp = tvb_get_guint8(tvb, offset++);
			proto_tree_add_item(tree, hf_om2k_mctr_feat_sts_bitmap, tvb, offset, tmp, ENC_NA);
			offset += tmp;
			break;
		case 0xae: /* Power Back-Off Channel Type Map */
			tmp = tvb_get_guint8(tvb, offset++);
			proto_tree_add_item(tree, hf_om2k_power_bo_ctype_map, tvb, offset, tmp, ENC_NA);
			offset += tmp;
			break;
		case 0xaf: /* Power Back-Off Priority */
			tmp = tvb_get_guint8(tvb, offset++);
			proto_tree_add_item(tree, hf_om2k_power_bo_priority, tvb, offset, tmp, ENC_NA);
			offset += tmp;
			break;
		case 0xb0: /* Power Back-Off Value */
			tmp = tvb_get_guint8(tvb, offset++);
			proto_tree_add_item(tree, hf_om2k_power_bo_value, tvb, offset, tmp, ENC_NA);
			offset += tmp;
			break;
		case 0xa3:
		case 0xa5:
		case 0xa6:
			/* we don't know any of the above, but the
			 * TLV structure is quite clear in the protocol
			 * traces */
			tmp = tvb_get_guint8(tvb, offset++);
			offset += dissect_om2k_attr_unkn(tvb, pinfo, offset, tmp, iei, tree);
			break;
		case 0xb5: /* unknown 2-bytes fixed length attribute of TX Config */
			offset += dissect_om2k_attr_unkn(tvb, pinfo, offset, 2, iei, tree);
			break;
		case 0xd2: /* unknown 6-bytes fixed length attribute of TRXC Fault Rep */
			offset += dissect_om2k_attr_unkn(tvb, pinfo, offset, 6, iei, tree);
			break;
		case 0xac: /* unknown 58-bytes fixed length attribute of message type 0x0136 */
			offset += dissect_om2k_attr_unkn(tvb, pinfo, offset, 58, iei, tree);
			break;
		default:
			tmp = tvb_get_guint8(tvb, offset);
			proto_tree_add_uint_format(tree, hf_om2k_unknown_tag, tvb,
					    offset-1, 1, tmp, "Tag %s: 0x%02x",
					    val_to_str_ext(iei, &om2k_attr_vals_ext, "0x%02x"), tmp);
			offset++;
			break;
		}
	}

	return offset;
}

static unsigned
dissect_om2k_mo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	uint8_t     mo_class = tvb_get_guint8(tvb, offset);
	uint8_t     inst  = tvb_get_guint8(tvb, offset+3);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", (%-4s %u)",
				val_to_str(mo_class, om2k_mo_class_short_vals,
					   "0x%02x"), inst);
	if (tree) {
		proto_item *ti;
		proto_tree *mo_tree;
		uint8_t     sub1  = tvb_get_guint8(tvb, offset+1);
		uint8_t     sub2  = tvb_get_guint8(tvb, offset+2);

		ti      = proto_tree_add_item(tree, hf_om2k_mo_if, tvb, offset,
					      4, ENC_NA);
		mo_tree = proto_item_add_subtree(ti, ett_om2k_mo);
		proto_tree_add_item(mo_tree, hf_om2k_mo_class, tvb, offset,
				    1, ENC_BIG_ENDIAN);
		proto_tree_add_item(mo_tree, hf_om2k_mo_sub1, tvb, offset+1,
				    1, ENC_BIG_ENDIAN);
		proto_tree_add_item(mo_tree, hf_om2k_mo_sub2, tvb, offset+2,
				    1, ENC_BIG_ENDIAN);
		proto_tree_add_item(mo_tree, hf_om2k_mo_instance, tvb, offset+3,
				    1, ENC_BIG_ENDIAN);
		proto_item_append_text(ti, ", Class: %s, Sub: %02x/%02x, Instance: %u",
				       val_to_str(mo_class, om2k_mo_class_vals, "0x%02x"),
				       sub1, sub2, inst);
	}
	return 4;
}

static int
dissect_abis_om2000(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti;
	proto_tree *om2k_tree;
	uint16_t    msg_code;
	uint8_t     tmp;
	const char *msgt_str;

	int offset;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "OM2000");
	/* Don't do col_clear() so this dissector can append to COL_INFO*/

	offset = 0;

	ti = proto_tree_add_item(tree, proto_abis_om2000,
				 tvb, 0, -1, ENC_NA);
	om2k_tree = proto_item_add_subtree(ti, ett_om2000);

	msg_code = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(om2k_tree, hf_om2k_msg_code, tvb, offset,
			    2, ENC_BIG_ENDIAN);
	offset += 2;

	offset += dissect_om2k_mo(tvb, offset, pinfo, om2k_tree);  /* appends to COL_INFO */

	col_append_fstr(pinfo->cinfo, COL_INFO, " %s ",
			val_to_str_ext(msg_code, &om2k_msgcode_vals_ext,
				   "unknown 0x%04x"));

	if (tree == NULL)
		return tvb_captured_length(tvb);   /* No refs to COL_...  beyond this point */

	msgt_str = val_to_str_ext(msg_code, &om2k_msgcode_vals_ext, "unknown 0x%04x");
	proto_item_append_text(ti, " %s ", msgt_str);

	switch (msg_code) {
	case 0x74: /* Operational Info */
		tmp = tvb_get_guint8(tvb, offset+1);
		proto_item_append_text(ti, ": %s",
				       val_to_str(tmp, om2k_oip_vals,
						  "unknown 0x%02x"));
		break;
	case 0x1A: /* CON Configuration Result */
	case 0x66: /* IS Configuration Result */
	case 0x82: /* RX Configuration Result */
	case 0xA6: /* TF Configuration Result */
	case 0xAE: /* TS Configuration Result */
	case 0xB6: /* TX Configuration Result */
	case 0xE2: /* DP Configuration Result */
	case 0xF6: /* DP Configuration Result */
		tmp = tvb_get_guint8(tvb, offset+1);
		proto_item_append_text(ti, ": %s",
				       val_to_str(tmp, om2k_aip_vals,
						  "unknown 0x%02x"));
		break;
	default:
		break;
	}

	if (strstr(msgt_str, "Reject"))
		expert_add_info(pinfo, ti, &ei_om2k_reject);
	if (strstr(msgt_str, "NACK"))
		expert_add_info(pinfo, ti, &ei_om2k_nack);

	dissect_om2k_attrs(tvb, pinfo, offset, om2k_tree, msg_code);
	return tvb_captured_length(tvb);
}

void
proto_register_abis_om2000(void)
{
	static hf_register_info hf[] = {
		{ &hf_om2k_msg_code,
		  { "Message Code", "gsm_abis_om2000.msg_code",
		    FT_UINT16, BASE_HEX|BASE_EXT_STRING, &om2k_msgcode_vals_ext, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_mo_if,
		  { "MO Interface", "gsm_abis_om2000.mo_if",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_mo_class,
		  { "MO IF Class", "gsm_abis_om2000.mo_if.class",
		    FT_UINT8, BASE_HEX, VALS(om2k_mo_class_vals), 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_mo_sub1,
			{ "MO IF Sub 1", "gsm_abis_om2000.mo_if.sub1",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_om2k_mo_sub2,
			{ "MO IF Sub 2", "gsm_abis_om2000.mo_if.sub2",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_om2k_mo_instance,
		  { "MO IF Instance", "gsm_abis_om2000.mo_if.instance",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_oip,
		  { "OIP (Operational Info)", "gsm_abis_om2000.oip",
		    FT_UINT8, BASE_HEX, VALS(om2k_oip_vals), 0,
		    "Operational Information Parameter", HFILL }
		},
		{ &hf_om2k_aip,
		  { "AIP (Accordance Info)", "gsm_abis_om2000.aip",
		    FT_UINT8, BASE_HEX, VALS(om2k_aip_vals), 0,
		    "Accordance Information Parameter", HFILL }
		},
		{ &hf_om2k_comb,
		  { "Channel Combination", "gsm_abis_om2000.chan_comb",
		    FT_UINT8, BASE_DEC, VALS(om2k_comb_vals), 0,
		    "Logical Channel Combination", HFILL }
		},
		{ &hf_om2k_ts,
		  { "Timeslot Number", "gsm_abis_om2000.ts",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_hsn,
		  { "HSN", "gsm_abis_om2000.hsn",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    "Hopping Sequence Number", HFILL }
		},
		{ &hf_om2k_maio,
		  { "MAIO", "gsm_abis_om2000.maio",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    "Mobile Allocation Index Offset", HFILL }
		},
		{ &hf_om2k_bsic,
		  { "BSIC", "gsm_abis_om2000.bsic",
		    FT_UINT8, BASE_HEX, NULL, 0,
		    "Base Station Identity Code", HFILL }
		},
		{ &hf_om2k_diversity,
		  { "Receiver Diversity", "gsm_abis_om2000.diversity",
		    FT_UINT8, BASE_HEX, VALS(om2k_diversity_vals), 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_fn_offs,
		  { "FN Offset", "gsm_abis_om2000.fn_offset",
		    FT_UINT16, BASE_DEC, NULL, 0,
		    "GSM Frame Number Offset", HFILL }
		},
		{ &hf_om2k_ext_range,
		  { "Extended Range", "gsm_abis_om2000.ext_range",
		    FT_BOOLEAN, BASE_NONE, NULL, 0,          /* XXX: bitmask needed? 'FT_BOOLEAN, 8, NULL, 0x01' ? */
		    NULL, HFILL }
		},
		{ &hf_om2k_irc,
		  { "Interference Rejection Combining", "gsm_abis_om2000.irc",
		    FT_BOOLEAN, BASE_NONE, NULL, 0,          /* XXX: bitmask needed? 'FT_BOOLEAN, 8, NULL, 0x01,' ? */
		    NULL, HFILL }
		},
		{ &hf_om2k_bs_pa_mfrms,
		  { "BS_PA_MFRMS", "gsm_abis_om2000.bs_pa_mfrms",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_bs_ag_blks_res,
		  { "BS_AG_BLKS_RES", "gsm_abis_om2000.bs_ag_blks_res",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_drx_dev_max,
		  { "DRX_DEV_MAX", "gsm_abis_om2000.drx_dev_max",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_cr,
		  { "CCCH Repeat", "gsm_abis_om2000.ccch_repeat",
		    FT_BOOLEAN, BASE_NONE, NULL, 0,          /* XXX: bitmask needed? 'FT_BOOLEAN, 8, NULL, 0x01,' ? */
		    NULL, HFILL }
		},
		{ &hf_om2k_ipt3,
		  { "Inhibit Paging Request Type 3", "gsm_abis_om2000.ipt3",
		    FT_BOOLEAN, BASE_NONE, NULL, 0,          /* XXX: bitmask needed? 'FT_BOOLEAN, 8, NULL, 0x02,' ? */
		    NULL, HFILL }
		},
		{ &hf_om2k_aop,
		  { "Age Of Paging", "gsm_abis_om2000.aop",
		    FT_UINT8, BASE_DEC, NULL, 0x3C,  /* XXX: Verify bitmask */
		    NULL, HFILL }
		},
		{ &hf_om2k_t3105,
		  { "T3105 (in 10ms)", "gsm_abis_om2000.t3105",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_ny1,
		  { "Ny1", "gsm_abis_om2000.ny1",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_cbi,
		  { "CBCH Indicator", "gsm_abis_om2000.cbi",
		    FT_BOOLEAN, BASE_NONE, NULL, 0,          /* XXX: bitmask needed? 'FT_BOOLEAN, 8, NULL, 0x01,' ? */
		    NULL, HFILL }
		},
		{ &hf_om2k_tsc,
		  { "Training Sequence Code", "gsm_abis_om2000.tsc",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_icm,
		  { "Idle Channel Measurement", "gsm_abis_om2000.icm",
		    FT_BOOLEAN, BASE_NONE, NULL, 0,          /* XXX: bitmask needed? 'FT_BOOLEAN, 8, NULL, 0x01,' ? */
		    NULL, HFILL }
		},
		{ &hf_om2k_tta,
		  { "Timer for Time Alignment", "gsm_abis_om2000.tta",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_icm_cr,
		  { "ICM Channel Rate", "gsm_abis_om2000.icm_cr",
		    FT_UINT8, BASE_DEC, VALS(om2k_icmcr_vals), 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_lsc_fm,
		  { "LSC Dummy Frequency Measurement", "gsm_abis_om2000.lsc.fm",
		    FT_BOOLEAN, 8, NULL, 0x80,
		    NULL, HFILL }
		},
		{ &hf_om2k_lsc_lsi,
		  { "LSC Idle Channels", "gsm_abis_om2000.ls.lsi",
		    FT_BOOLEAN, 8, NULL, 0x01,
		    NULL, HFILL }
		},
		{ &hf_om2k_lsc_lsa,
		  { "LSC Active Channels", "gsm_abis_om2000.ls.lsa",
		    FT_BOOLEAN, 8, NULL, 0x02,
		    NULL, HFILL }
		},
		{ &hf_om2k_ls_ft,
		  { "Link Supervision Filtering Time (100ms)", "gsm_abis_om2000.ls_ft",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_cst,
		  { "Call Supervision Time (480ms)", "gsm_abis_om2000.cst",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_ea,
		  { "Encryption Algorithm", "gsm_abis_om2000.ea",
		    FT_UINT8, BASE_DEC, VALS(om2k_ea_vals), 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_nom_pwr,
		  { "Nominal Power (dBm)", "gsm_abis_om2000.pwr",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_fill_mark,
		  { "Filling Marker", "gsm_abis_om2000.filling",
		    FT_UINT8, BASE_DEC, VALS(om2k_fill_vals), 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_bcc,
		  { "BCC", "gsm_abis_om2000.bcc",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    "Base Station Color Code", HFILL }
		},
		{ &hf_om2k_mo_state,
		  { "MO State", "gsm_abis_om2000.mo_state",
		    FT_UINT8, BASE_DEC, VALS(om2k_mo_state_vals), 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_la_state,
		  { "Local Access State", "gsm_abis_om2000.la_state",
		    FT_UINT8, BASE_DEC, VALS(om2k_la_state_vals), 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_tsn_state,
		  { "Time Slot N MO State", "gsm_abis_om2000.tsn_mo_state",
		    FT_UINT8, BASE_DEC, VALS(om2k_mo_state_vals), 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_bts_manuf,
		  { "BTS Manufacturer ID", "gsm_abis_om2000.bts_ver.manuf",
		    FT_STRING, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_bts_gen,
		  { "BTS Generation", "gsm_abis_om2000.bts_ver.gen",
		    FT_STRING, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_bts_rev,
		  { "BTS Revision", "gsm_abis_om2000.bts_ver.rev",
		    FT_STRING, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_bts_var,
		  { "BTS Variant", "gsm_abis_om2000.bts_ver.variant",
		    FT_STRING, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_brr,
		  { "BTS Requested Restart", "gsm_abis_om2000.brr",
		    FT_BOOLEAN, 0x01, NULL, 0,          /* XXX: bitmask needed? 'FT_BOOLEAN, 8, NULL, 0x??,' ? */
		    NULL, HFILL }
		},
		{ &hf_om2k_bfr,
		  { "BTS Requested File Relation", "gsm_abis_om2000.bfr",
		    FT_BOOLEAN, 0x01, NULL, 0,          /* XXX: bitmask needed? 'FT_BOOLEAN, 8, NULL, 0x??,' ? */
		    NULL, HFILL }
		},
		{ &hf_om2k_hwinfo_sig,
		  { "HW Info Signature", "gsm_abis_om2000.hwinfo_sig",
		    FT_UINT16, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_capa_sig,
		  { "Capabilities Signature", "gsm_abis_om2000.capa_sig",
		    FT_UINT16, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_om2k_unknown_tag,
		  { "Unknown Tag", "gsm_abis_om2000.unknown.tag",
		    FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_unknown_val,
		  { "Unknown Value", "gsm_abis_om2000.unknown.val",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_om2k_file_rev,
		  { "File Revision", "gsm_abis_om2000.file_rev",
		    FT_STRING, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_filerel_ilr,
		  { "Immediate Load Requested", "gsm_abis_om2000.filerel.ilr",
		    FT_BOOLEAN, 8, NULL, 0x08,
		    NULL, HFILL }
		},
		{ &hf_om2k_filerel_cur,
		  { "Current State", "gsm_abis_om2000.filerel.cur",
		    FT_UINT8, BASE_HEX, VALS(filerel_state_vals), 0x07,
		    NULL, HFILL }
		},
		{ &hf_om2k_filerel_other,
		  { "Other State", "gsm_abis_om2000.filerel.other",
		    FT_UINT8, BASE_HEX, VALS(filerel_state_vals), 0x07,
		    NULL, HFILL }
		},
		{ &hf_om2k_cal_time,
		  { "Calendar Time", "gsm_abis_om2000.cal_time",
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_list_nr,
		  { "List Number", "gsm_abis_om2000.list_nr",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_list_nr_end,
		  { "End List Number", "gsm_abis_om2000.list_nr_end",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_isl,
		  { "IS Connection List", "gsm_abis_om2000.is_list",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_isl_icp1,
		  { "ICP1", "gsm_abis_om2000.is_list.icp1",
		    FT_UINT16, BASE_DEC, NULL, 0x07ff,
		    NULL, HFILL }
		},
		{ &hf_om2k_isl_icp2,
		  { "ICP2", "gsm_abis_om2000.is_list.icp2",
		    FT_UINT16, BASE_DEC, NULL, 0x07ff,
		    NULL, HFILL }
		},
		{ &hf_om2k_isl_ci,
		  { "Contiguity Index", "gsm_abis_om2000.is_list.ci",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_conl,
		  { "Connection List", "gsm_abis_om2000.con_list",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_conl_nr_cgs,
		  { "Number of CGs", "gsm_abis_om2000.con_list.nr_cgs",
		    FT_UINT8, BASE_DEC, NULL, 0x1f,
		    "Number of Concentration Groups in the DE", HFILL }
		},
		{ &hf_om2k_conl_nr_cps_cg,
		  { "Number of CPS in CG", "gsm_abis_om2000.con_list.nr_cps_cg",
		    FT_UINT8, BASE_DEC, NULL, 0x1f,
		    "Number of CPS in Concentration Group", HFILL }
		},
		{ &hf_om2k_conl_ccp,
		  { "CON Connection Point", "gsm_abis_om2000.con_list.cpp",
            FT_UINT16, BASE_DEC, NULL, 0x07ff,
		    NULL, HFILL }
		},
		{ &hf_om2k_conl_ci,
		  { "Contiguity Index", "gsm_abis_om2000.con_list.ci",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_conl_tag,
		  { "Tag", "gsm_abis_om2000.con_list.tag",
		    FT_UINT8, BASE_DEC, NULL, 0x1f,
		    NULL, HFILL }
		},
		{ &hf_om2k_conl_tei,
		  { "TEI", "gsm_abis_om2000.con_list.tei",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_tf_mode,
		  { "TF Mode", "gsm_abis_om2000.tf_mode",
		    FT_UINT8, BASE_HEX, VALS(om2k_tf_mode_vals), 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_tf_fs_offset,
		  { "TF FS Offset", "gsm_abis_om2000.tf_fs_offset",
		    FT_UINT64, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_attr_id,
		  { "Attribute Identifier", "gsm_abis_om2000.attr_id",
		    FT_UINT16, BASE_HEX|BASE_EXT_STRING, &om2k_attr_id_vals_ext, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_attr_index,
		  { "Attribute Index", "gsm_abis_om2000.attr_index",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_reason_code,
		  { "Reason Code", "gsm_abis_om2000.reason_code",
		    FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_result_code,
		  { "Result Code", "gsm_abis_om2000.res_code",
		    FT_UINT8, BASE_HEX, VALS(om2k_res_code_vals), 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_iwd_type,
		  { "IWD", "gsm_abis_om2000.iwd_type",
		    FT_UINT8, BASE_HEX, VALS(om2k_iwd_type_vals), 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_iwd_gen_rev,
		  { "IWD Generation/Revision", "gsm_abis_om2000.iwd_gen_rev",
		    FT_STRING, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_trxc_list,
		  { "TRXC List", "gsm_abis_om2000.trxc_list",
		    FT_UINT16, BASE_HEX, NULL, 0xFFFF,
		    NULL, HFILL }
		},
		{ &hf_om2k_max_allowed_power,
		  { "Maximum allowed power", "gsm_abis_om2000.max_allowed_power",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_max_allowed_num_trxcs,
		  { "Maximum allowed number of TRXCs", "gsm_abis_om2000.max_allowed_num_trxcs",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_mctr_feat_sts_bitmap,
		  { "MCTR Feature status bitmap", "gsm_abis_om2000.mctr_feat_sts_bitmap",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_config_type,
		  { "Configuration Type", "gsm_abis_om2000.config_type",
		    FT_BOOLEAN, 8, NULL, 0x01,
		    NULL, HFILL }
		},
		{ &hf_om2k_jitter_size,
		  { "Jitter Size", "gsm_abis_om2000.jitter_size",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_packing_algo,
		  { "Packing Algorithm", "gsm_abis_om2000.packing_algo",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_power_bo_ctype_map,
		  { "Power Back-Off Channel Type Map", "gsm_abis_om2000.power_bo_ctype_map",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_power_bo_priority,
		  { "Power Back-Off Priority", "gsm_abis_om2000.power_bo_priority",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_power_bo_value,
		  { "Power Back-Off Value", "gsm_abis_om2000.power_bo_value",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},
	};
	static int *ett[] = {
		&ett_om2000,
		&ett_om2k_mo,
		&ett_om2k_isl,
		&ett_om2k_conl,
		&ett_om2k_iwd,
	};
	static ei_register_info ei[] = {
		{ &ei_om2k_not_performed,
		  { "gsm_abis_om2000.not_performed", PI_RESPONSE_CODE, PI_WARN,
		    "Operation not performed as per request", EXPFILL }
		},
		{ &ei_om2k_reject,
		  { "gsm_abis_om2000.reject", PI_RESPONSE_CODE, PI_WARN,
		    "Operation Rejected by RBS", EXPFILL }
		},
		{ &ei_om2k_nack,
		  { "gsm_abis_om2000.nack", PI_RESPONSE_CODE, PI_ERROR,
		    "Operation NACKed by peer", EXPFILL }
		},
		{ &ei_om2k_ena_res_disabled,
		  { "gsm_abis_om2000.ena_res_disabled", PI_RESPONSE_CODE, PI_WARN,
		    "Enable Result != Enabled", EXPFILL }
		},

	};
	expert_module_t *expert_om2000;

	proto_abis_om2000 = proto_register_protocol("Ericsson A-bis OML",
						    "Ericsson OML",
						    "gsm_abis_om2000");

	expert_om2000 = expert_register_protocol(proto_abis_om2000);
	expert_register_field_array(expert_om2000, ei, array_length(ei));
	proto_register_field_array(proto_abis_om2000, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("gsm_abis_om2000", dissect_abis_om2000,
			   proto_abis_om2000);
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
