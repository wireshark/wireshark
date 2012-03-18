/* packet-abis_om2000.c
 * Routines for packet dissection of Ericsson A-bis OML (OM 2000)
 * Copyright 2010-2012 by Harald Welte <laforge@gnumonks.org>
 *
 * $Id$
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

#include <glib.h>

#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/lapd_sapi.h>

#include "packet-gsm_a_common.h"

#include <stdio.h>

/* initialize the protocol and registered fields */
static int proto_abis_om2000 = -1;

static int hf_om2k_msg_code = -1;
static int hf_om2k_mo_if = -1;
static int hf_om2k_mo_class = -1;
static int hf_om2k_mo_instance = -1;

static int hf_om2k_aip = -1;
static int hf_om2k_oip = -1;
static int hf_om2k_comb = -1;
static int hf_om2k_ts = -1;
static int hf_om2k_hsn = -1;
static int hf_om2k_maio = -1;
static int hf_om2k_bsic = -1;
static int hf_om2k_diversity = -1;
static int hf_om2k_fn_offs = -1;
static int hf_om2k_ext_range = -1;
static int hf_om2k_irc = -1;
static int hf_om2k_bs_pa_mfrms = -1;
static int hf_om2k_bs_ag_blks_res= -1;
static int hf_om2k_drx_dev_max = -1;
static int hf_om2k_cr = -1;
static int hf_om2k_ipt3 = -1;
static int hf_om2k_aop = -1;
static int hf_om2k_t3105 = -1;
static int hf_om2k_ny1 = -1;
static int hf_om2k_cbi = -1;
static int hf_om2k_tsc = -1;
static int hf_om2k_icm = -1;
static int hf_om2k_tta = -1;
static int hf_om2k_icm_cr = -1;
static int hf_om2k_lsc_fm = -1;
static int hf_om2k_lsc_lsi = -1;
static int hf_om2k_lsc_lsa = -1;
static int hf_om2k_ls_ft = -1;
static int hf_om2k_cst = -1;
static int hf_om2k_ea = -1;
static int hf_om2k_unknown_tag = -1;
static int hf_om2k_unknown_val = -1;
static int hf_om2k_nom_pwr = -1;
static int hf_om2k_fill_mark = -1;
static int hf_om2k_bcc = -1;
static int hf_om2k_mo_state = -1;
static int hf_om2k_la_state = -1;
static int hf_om2k_tsn_state = -1;
static int hf_om2k_bts_manuf = -1;
static int hf_om2k_bts_gen = -1;
static int hf_om2k_bts_rev = -1;
static int hf_om2k_bts_var = -1;
static int hf_om2k_brr = -1;
static int hf_om2k_bfr = -1;
static int hf_om2k_hwinfo_sig = -1;
static int hf_om2k_capa_sig = -1;
static int hf_om2k_file_rev = -1;
static int hf_om2k_filerel_ilr = -1;
static int hf_om2k_filerel_cur = -1;
static int hf_om2k_filerel_other = -1;
static int hf_om2k_cal_time = -1;
static int hf_om2k_list_nr = -1;
static int hf_om2k_list_nr_end = -1;
static int hf_om2k_isl = -1;
static int hf_om2k_isl_icp1 = -1;
static int hf_om2k_isl_icp2 = -1;
static int hf_om2k_isl_ci = -1;
static int hf_om2k_conl = -1;
static int hf_om2k_conl_nr_cgs = -1;
static int hf_om2k_conl_nr_cps_cg = -1;
static int hf_om2k_conl_ccp = -1;
static int hf_om2k_conl_ci = -1;
static int hf_om2k_conl_tag = -1;
static int hf_om2k_conl_tei = -1;
static int hf_om2k_tf_mode = -1;
static int hf_om2k_tf_fs_offset = -1;

/* initialize the subtree pointers */
static int ett_om2000 = -1;
static int ett_om2k_mo = -1;
static int ett_om2k_isl = -1;
static int ett_om2k_conl = -1;

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
	{ 0x001f, "Connect Rejecte" },
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
	{ 0x03, "TS" },
	{ 0x04, "TF" },
	{ 0x05, "IS" },
	{ 0x06, "CON" },
	{ 0x0a, "CF" },
	{ 0x0b, "TX" },
	{ 0x0c, "RX" },
	{ 0, NULL }
};

static const value_string om2k_mo_class_vals[] = {
	{ 0x01, "TRXC (TRX Controller)" },
	{ 0x03, "TS (Timeslot)" },
	{ 0x04, "TF (Timing Function)" },
	{ 0x05, "IS (Interface Switch)" },
	{ 0x06, "CON (Concentrator)" },
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

static gint
dissect_tss_mo_state(tvbuff_t *tvb, gint offset, proto_tree *tree)
{
	guint8 tmp;
	guint  i = 0;

	for (i = 0; i < 8; i+= 2) {
		tmp = tvb_get_guint8(tvb, offset);
		proto_tree_add_uint_format(tree, hf_om2k_tsn_state, tvb, offset, 1, tmp & 0xf,
					   "Timslot %u MO State: %s", i,
					   val_to_str(tmp & 0xf, om2k_mo_state_vals, "unknown (%02d)"));
		proto_tree_add_uint_format(tree, hf_om2k_tsn_state, tvb, offset, 1, tmp >> 4,
					   "Timslot %u MO State: %s", i+1,
					   val_to_str(tmp >> 4, om2k_mo_state_vals, "unknown (%02d)"));
		offset++;
	}

	return offset;
}


static gint
dissect_om2k_time(tvbuff_t *tvb, gint offset, proto_tree *tree)
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

static gint
dissect_om2k_attr_unkn(tvbuff_t *tvb, gint offset, gint len, gint iei, proto_tree *tree)
{
	proto_tree_add_bytes_format(tree, hf_om2k_unknown_val, tvb,
				    offset, len, tvb_get_ptr(tvb, offset, len),
				    "%s: %s",
				    val_to_str_ext(iei, &om2k_attr_vals_ext, "0x%02x"),
				    tvb_bytes_to_str(tvb, offset, len));
	return len;
}

static gint
dissect_om2k_is_list(tvbuff_t *tvb, gint base_offset, proto_tree *tree)
{
	gint        offset = base_offset;
	proto_item *ti;
	proto_tree *isl_tree;
	guint8      len    = tvb_get_guint8(tvb, offset++);

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

static gint
dissect_om2k_con_list(tvbuff_t *tvb, gint base_offset, proto_tree *tree)
{
	gint        offset = base_offset;
	proto_item *ti;
	proto_tree *conl_tree;
	guint8      len    = tvb_get_guint8(tvb, offset++);

	ti = proto_tree_add_item(tree, hf_om2k_conl, tvb, offset, len, ENC_NA);
	conl_tree = proto_item_add_subtree(ti, ett_om2k_conl);

	proto_tree_add_item(conl_tree, hf_om2k_conl_nr_cgs, tvb,
			    offset++, 1, ENC_BIG_ENDIAN);

	while (offset < base_offset + len) {
		guint8 nr_cps_cg = tvb_get_guint8(tvb, offset);
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


static gint
dissect_om2k_attrs(tvbuff_t *tvb, gint offset, proto_tree *tree)
{
	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		guint8 iei = tvb_get_guint8(tvb, offset++);
		guint8 len, tmp;

		switch (iei) {
		case 0x00: /* Accordance Information */
			proto_tree_add_item(tree, hf_om2k_aip, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
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
			offset += dissect_om2k_attr_unkn(tvb, offset, 2, iei, tree);
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
					    offset, 8, ENC_ASCII|ENC_NA);
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
			offset += dissect_om2k_attr_unkn(tvb, offset, len, iei, tree);
			break;
		case 0x1f: /* Frequency Specifier Rx */
			/* FIXME */
		case 0x20: /* Frequency Specifier Rx */
			/* FIXME */
			offset += dissect_om2k_attr_unkn(tvb, offset, 2, iei, tree);
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
			offset += dissect_om2k_attr_unkn(tvb, offset, 6, iei, tree);
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
			proto_tree_add_item(tree, hf_om2k_mo_state, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
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
		case 0x33: /* Receiver Diversity */
			proto_tree_add_item(tree, hf_om2k_diversity, tvb,
					    offset++, 1, ENC_BIG_ENDIAN);
			break;
		case 0x34: /* Replacement Unit Map */
			/* FIXME */
			offset += dissect_om2k_attr_unkn(tvb, offset, 6, iei, tree);
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
					    offset, 3, ENC_ASCII|ENC_NA);
			offset += 3;
			proto_tree_add_item(tree, hf_om2k_bts_gen, tvb,
					    offset, 3, ENC_ASCII|ENC_NA);
			offset += 3;
			proto_tree_add_item(tree, hf_om2k_bts_rev, tvb,
					    offset, 3, ENC_ASCII|ENC_NA);
			offset += 3;
			proto_tree_add_item(tree, hf_om2k_bts_var, tvb,
					    offset, 3, ENC_ASCII|ENC_NA);
			offset += 3;
			break;
		case 0x43: /* OML Function Map 1 */
		case 0x44: /* OML Function Map 2 */
		case 0x45: /* RSL Function Map 1 */
		case 0x46: /* RSL Function Map 2 */
			len = tvb_get_guint8(tvb, offset++);
			/* FIXME */
			offset += dissect_om2k_attr_unkn(tvb, offset, len, iei, tree);
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
			offset += dissect_om2k_attr_unkn(tvb, offset, 6, iei, tree);
			break;
		case 0x74: /* ICM Boundary */
			/* FIXME */
			offset += dissect_om2k_attr_unkn(tvb, offset, 5, iei, tree);
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
		case 0x84: /* HW Info Signature */
			proto_tree_add_item(tree, hf_om2k_hwinfo_sig, tvb,
					    offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
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
		case 0x91: /* Negotiation Record II */
			len = tvb_get_guint8(tvb, offset++);
			/* FIXME */
			offset += dissect_om2k_attr_unkn(tvb, offset, len, iei, tree);
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
			offset += dissect_om2k_attr_unkn(tvb, offset, 3, iei, tree);
			break;
		case 0x98: /* FS Offset */
			proto_tree_add_item(tree, hf_om2k_tf_fs_offset, tvb,
					    offset, 5, ENC_BIG_ENDIAN);
			offset += 5;
			break;
		case 0x9c: /* External Condition Class 2 Extension */
			/* FIXME */
			offset += dissect_om2k_attr_unkn(tvb, offset, 4, iei, tree);
			break;
		case 0x9d: /* TSs MO State */
			dissect_tss_mo_state(tvb, offset, tree);
			offset += 4;
			break;
		case 0x9e:
		case 0x9f:
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

static guint
dissect_om2k_mo(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree)
{
	guint8      class = tvb_get_guint8(tvb, offset);
	guint8      inst  = tvb_get_guint8(tvb, offset+3);

	col_append_fstr(pinfo->cinfo, COL_INFO, ", (%-4s %u)",
				val_to_str(class, om2k_mo_class_short_vals,
					   "0x%02x"), inst);
	if (tree) {
		proto_item *ti;
		proto_tree *mo_tree;

		ti      = proto_tree_add_item(tree, hf_om2k_mo_if, tvb, offset,
					      4, ENC_NA);
		mo_tree = proto_item_add_subtree(ti, ett_om2k_mo);
		proto_tree_add_item(mo_tree, hf_om2k_mo_class, tvb, offset,
				    1, ENC_BIG_ENDIAN);
		proto_tree_add_item(mo_tree, hf_om2k_mo_instance, tvb, offset+3,
				    1, ENC_BIG_ENDIAN);
		proto_item_append_text(ti, ", Class: %s, Instance: %u",
				       val_to_str(class, om2k_mo_class_vals, "0x%02x"),
				       inst);
	}
	return 4;
}

static void
dissect_abis_om2000(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *om2k_tree;
	guint16     msg_code;
	guint8      tmp;

	int offset;

	if ((tree == NULL) && (pinfo->cinfo == NULL))
		return;   /* no dissection required */

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
		return;   /* No refs to COL_...  beyond this point */

	proto_item_append_text(ti, " %s ",
			       val_to_str_ext(msg_code, &om2k_msgcode_vals_ext,
					  "unknown 0x%04x"));

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
	dissect_om2k_attrs(tvb, offset, om2k_tree);
}

void
proto_register_abis_om2000(void)
{
	static hf_register_info hf[] = {
		{ &hf_om2k_msg_code,
		  { "Message Code", "om2000.msg_code",
		    FT_UINT16, BASE_HEX|BASE_EXT_STRING, &om2k_msgcode_vals_ext, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_mo_if,
		  { "MO Interface", "om2000.mo_if",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_mo_class,
		  { "MO IF Class", "om2000.mo_if.class",
		    FT_UINT8, BASE_HEX, VALS(om2k_mo_class_vals), 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_mo_instance,
		  { "MO IF Instance", "om2000.mo_if.instance",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_oip,
		  { "OIP (Operational Info)", "om2000.oip",
		    FT_UINT8, BASE_HEX, VALS(om2k_oip_vals), 0,
		    "Operational Information Parameter", HFILL }
		},
		{ &hf_om2k_aip,
		  { "AIP (Accordance Info)", "om2000.aip",
		    FT_UINT8, BASE_HEX, VALS(om2k_aip_vals), 0,
		    "Accordance Information Parameter", HFILL }
		},
		{ &hf_om2k_comb,
		  { "Channel Combination", "om2000.chan_comb",
		    FT_UINT8, BASE_DEC, VALS(om2k_comb_vals), 0,
		    "Logical Channel Combination", HFILL }
		},
		{ &hf_om2k_ts,
		  { "Timeslot Number", "om2000.ts",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_hsn,
		  { "HSN", "om2000.hsn",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    "Hopping Sequence Number", HFILL }
		},
		{ &hf_om2k_maio,
		  { "MAIO", "om2000.maio",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    "Mobile Allication Index Offset", HFILL }
		},
		{ &hf_om2k_bsic,
		  { "BSIC", "om2000.bsic",
		    FT_UINT8, BASE_HEX, NULL, 0,
		    "Base Station Identity Code", HFILL }
		},
		{ &hf_om2k_diversity,
		  { "Receiver Diversity", "om2000.diversity",
		    FT_UINT8, BASE_HEX, VALS(om2k_diversity_vals), 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_fn_offs,
		  { "FN Offset", "om2000.fn_offset",
		    FT_UINT16, BASE_DEC, NULL, 0,
		    "GSM Frame Number Offset", HFILL }
		},
		{ &hf_om2k_ext_range,
		  { "Extended Range", "om2000.ext_range",
		    FT_BOOLEAN, 1, NULL, 0,          /* XXX: bitmask needed? 'FT_BOOLEAN, 8, NULL, 0x01' ? */
		    NULL, HFILL }
		},
		{ &hf_om2k_irc,
		  { "Interference Rejection Combining", "om2000.irc",
		    FT_BOOLEAN, 1, NULL, 0,          /* XXX: bitmask needed? 'FT_BOOLEAN, 8, NULL, 0x01,' ? */
		    NULL, HFILL }
		},
		{ &hf_om2k_bs_pa_mfrms,
		  { "BS_PA_MFRMS", "om2000.bs_pa_mfrms",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_bs_ag_blks_res,
		  { "BS_AG_BLKS_RES", "om2000.bs_ag_blks_res",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_drx_dev_max,
		  { "DRX_DEV_MAX", "om2000.drx_dev_max",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_cr,
		  { "CCCH Repeat", "om2000.ccch_repeat",
		    FT_BOOLEAN, 1, NULL, 0,          /* XXX: bitmask needed? 'FT_BOOLEAN, 8, NULL, 0x01,' ? */
		    NULL, HFILL }
		},
		{ &hf_om2k_ipt3,
		  { "Inhibit Paging Request Type 3", "om2000.ipt3",
		    FT_BOOLEAN, 2, NULL, 0,          /* XXX: bitmask needed? 'FT_BOOLEAN, 8, NULL, 0x02,' ? */
		    NULL, HFILL }
		},
		{ &hf_om2k_aop,
		  { "Age Of Paging", "om2000.aop",
		    FT_UINT8, BASE_DEC, NULL, 0x3C,  /* XXX: Verify bitmask */
		    NULL, HFILL }
		},
		{ &hf_om2k_t3105,
		  { "T3105 (in 10ms)", "om2000.t3105",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_ny1,
		  { "Ny1", "om2000.ny1",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_cbi,
		  { "CBCH Indicator", "om2000.ny1",
		    FT_BOOLEAN, 1, NULL, 0,          /* XXX: bitmask needed? 'FT_BOOLEAN, 8, NULL, 0x01,' ? */
		    NULL, HFILL }
		},
		{ &hf_om2k_tsc,
		  { "Training Sequence Code", "om2000.tsc",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_icm,
		  { "Idle Channel Measurement", "om2000.icm",
		    FT_BOOLEAN, 1, NULL, 0,          /* XXX: bitmask needed? 'FT_BOOLEAN, 8, NULL, 0x01,' ? */
		    NULL, HFILL }
		},
		{ &hf_om2k_tta,
		  { "Timer for Time Alignment", "om2000.tta",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_icm_cr,
		  { "ICM Channel Rate", "om2000.icm_cr",
		    FT_UINT8, BASE_DEC, VALS(om2k_icmcr_vals), 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_lsc_fm,
		  { "LSC Dummy Frequency Measurement", "om2000.lsc.fm",
		    FT_BOOLEAN, 8, NULL, 0x80,
		    NULL, HFILL }
		},
		{ &hf_om2k_lsc_lsi,
		  { "LSC Idle Channels", "om2000.ls.lsi",
		    FT_BOOLEAN, 8, NULL, 0x01,
		    NULL, HFILL }
		},
		{ &hf_om2k_lsc_lsa,
		  { "LSC Active Channels", "om2000.ls.lsa",
		    FT_BOOLEAN, 8, NULL, 0x02,
		    NULL, HFILL }
		},
		{ &hf_om2k_ls_ft,
		  { "Link Supervision Filtering Time (100ms)", "om2000.ls_ft",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_cst,
		  { "Call Supervision Time (480ms)", "om2000.cst",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_ea,
		  { "Encryption Algorithm", "om2000.ea",
		    FT_UINT8, BASE_DEC, VALS(om2k_ea_vals), 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_nom_pwr,
		  { "Nominal Power (dBm)", "om2000.pwr",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_fill_mark,
		  { "Filling Marker", "om2000.filling",
		    FT_UINT8, BASE_DEC, VALS(om2k_fill_vals), 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_bcc,
		  { "BCC", "om2000.bcc",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    "Base Station Color Code", HFILL }
		},
		{ &hf_om2k_mo_state,
		  { "MO State", "om2000.mo_state",
		    FT_UINT8, BASE_DEC, VALS(om2k_mo_state_vals), 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_la_state,
		  { "Local Access State", "om2000.la_state",
		    FT_UINT8, BASE_DEC, VALS(om2k_la_state_vals), 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_tsn_state,
		  { "Time Slot N MO State", "om2000.tsn_mo_state",
		    FT_UINT8, BASE_DEC, VALS(om2k_mo_state_vals), 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_bts_manuf,
		  { "BTS Manufacturer ID", "om2000.bts_ver.manuf",
		    FT_STRING, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_bts_gen,
		  { "BTS Generation", "om2000.bts_ver.gen",
		    FT_STRING, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_bts_rev,
		  { "BTS Revision", "om2000.bts_ver.rev",
		    FT_STRING, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_bts_var,
		  { "BTS Variant", "om2000.bts_ver.variant",
		    FT_STRING, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_brr,
		  { "BTS Requested Restart", "om2000.brr",
		    FT_BOOLEAN, 0x01, NULL, 0,          /* XXX: bitmask needed? 'FT_BOOLEAN, 8, NULL, 0x??,' ? */
		    NULL, HFILL }
		},
		{ &hf_om2k_bfr,
		  { "BTS Requested File Relation", "om2000.bfr",
		    FT_BOOLEAN, 0x01, NULL, 0,          /* XXX: bitmask needed? 'FT_BOOLEAN, 8, NULL, 0x??,' ? */
		    NULL, HFILL }
		},
		{ &hf_om2k_hwinfo_sig,
		  { "HW Info Signature", "om2000.hwinfo_sig",
		    FT_UINT16, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_capa_sig,
		  { "Capabilities Signature", "om2000.capa_sig",
		    FT_UINT16, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_om2k_unknown_tag,
		  { "Unknown Tag", "om2000.unknown.tag",
		    FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_unknown_val,
		  { "Unknown Value", "om2000.unknown.val",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_om2k_file_rev,
		  { "File Revision", "om2000.file_rev",
		    FT_STRING, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_filerel_ilr,
		  { "Immediate Load Requested", "om2000.filerel.ilr",
		    FT_BOOLEAN, 8, NULL, 0x08,
		    NULL, HFILL }
		},
		{ &hf_om2k_filerel_cur,
		  { "Current State", "om2000.filerel.cur",
		    FT_UINT8, BASE_HEX, VALS(filerel_state_vals), 0x07,
		    NULL, HFILL }
		},
		{ &hf_om2k_filerel_other,
		  { "Other State", "om2000.filerel.other",
		    FT_UINT8, BASE_HEX, VALS(filerel_state_vals), 0x07,
		    NULL, HFILL }
		},
		{ &hf_om2k_cal_time,
		  { "Calendar Time", "om2000.cal_time",
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_list_nr,
		  { "List Number", "om2000.list_nr",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_list_nr_end,
		  { "End List Number", "om2000.list_nr_end",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_isl,
		  { "IS Connection List", "om2000.is_list",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_isl_icp1,
		  { "ICP1", "om2000.is_list.icp1",
		    FT_UINT16, BASE_DEC, NULL, 0x7ff,
		    NULL, HFILL }
		},
		{ &hf_om2k_isl_icp2,
		  { "ICP2", "om2000.is_list.icp2",
		    FT_UINT16, BASE_DEC, NULL, 0x7ff,
		    NULL, HFILL }
		},
		{ &hf_om2k_isl_ci,
		  { "Contiguity Index", "om2000.is_list.ci",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_conl,
		  { "Connection List", "om2000.con_list",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_conl_nr_cgs,
		  { "Number of CGs", "om2000.con_list.nr_cgs",
		    FT_UINT8, BASE_DEC, NULL, 0x1f,
		    "Number of Concentration Groups in the DE", HFILL }
		},
		{ &hf_om2k_conl_nr_cps_cg,
		  { "Number of CPS in CG", "om2000.con_list.nr_cps_cg",
		    FT_UINT8, BASE_DEC, NULL, 0x1f,
		    "Number of CPS in Concentration Group", HFILL }
		},
		{ &hf_om2k_conl_ccp,
		  { "CON Connection Point", "om2000.con_list.cpp",
		    FT_UINT16, BASE_DEC, NULL, 0x3ff,
		    NULL, HFILL }
		},
		{ &hf_om2k_conl_ci,
		  { "Contiguity Index", "om2000.con_list.ci",
		    FT_UINT8, BASE_DEC, NULL, 0x7,
		    NULL, HFILL }
		},
		{ &hf_om2k_conl_tag,
		  { "Tag", "om2000.con_list.tag",
		    FT_UINT8, BASE_DEC, NULL, 0x1f,
		    NULL, HFILL }
		},
		{ &hf_om2k_conl_tei,
		  { "TEI", "om2000.con_list.tei",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_tf_mode,
		  { "TF Mode", "om2000.tf_mode",
		    FT_UINT8, BASE_HEX, VALS(om2k_tf_mode_vals), 0,
		    NULL, HFILL }
		},
		{ &hf_om2k_tf_fs_offset,
		  { "TF FS Offset", "om2000.tf_fs_offset",
		    FT_UINT64, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
	};
	static gint *ett[] = {
		&ett_om2000,
		&ett_om2k_mo,
		&ett_om2k_isl,
		&ett_om2k_conl,
	};

	proto_abis_om2000 = proto_register_protocol("Ericsson A-bis OML",
						    "Ericsson OML",
						    "gsm_abis_om2000");

	proto_register_field_array(proto_abis_om2000, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("gsm_abis_om2000", dissect_abis_om2000,
			   proto_abis_om2000);
}

