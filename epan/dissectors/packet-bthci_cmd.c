/* packet-bthci-cmd.c
 * Routines for the Bluetooth HCI Command dissection
 * Copyright 2002, Christoph Scholz <scholz@cs.uni-bonn.de>
 *  From: http://affix.sourceforge.net/archive/ethereal_affix-3.patch
 *
 * Refactored for ethereal checkin
 *   Ronnie Sahlberg 2006
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
#include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <etypes.h>
#include <packet-hci_h4.h>

/* Initialize the protocol and registered fields */
static int proto_bthci_cmd = -1;
static int hf_bthci_cmd_opcode = -1;
static int hf_bthci_cmd_ogf = -1;
static int hf_bthci_cmd_ocf = -1;
static int hf_bthci_cmd_param_length = -1;
static int hf_bthci_cmd_params = -1;
static int hf_bthci_cmd_lap = -1;
static int hf_bthci_cmd_inq_length = -1;
static int hf_bthci_cmd_num_responses = -1;
static int hf_bthci_cmd_encrypt_mode = -1;
static int hf_bthci_cmd_bd_addr = -1;
static int hf_bthci_cmd_packet_type_dm1 = -1;
static int hf_bthci_cmd_packet_type_dm3 = -1;
static int hf_bthci_cmd_packet_type_dm5 = -1;
static int hf_bthci_cmd_packet_type_dh1 = -1;
static int hf_bthci_cmd_packet_type_dh3 = -1;
static int hf_bthci_cmd_packet_type_dh5 = -1;
static int hf_bthci_cmd_clock_offset = -1;
static int hf_bthci_cmd_clock_offset_valid = -1;
static int hf_bthci_cmd_allow_role_switch = -1;
static int hf_bthci_cmd_page_scan_mode = -1;
static int hf_bthci_cmd_page_scan_repetition_mode = -1;
static int hf_bthci_cmd_page_scan_period_mode = -1;
static int hf_bthci_cmd_status = -1;
static int hf_bthci_cmd_max_period_length = -1;
static int hf_bthci_cmd_min_period_length = -1;
static int hf_bthci_cmd_connection_handle = -1;
static int hf_bthci_cmd_reason = -1;
static int hf_bthci_cmd_num_link_keys = -1;
static int hf_bthci_cmd_link_key = -1;
static int hf_bthci_cmd_packet_type_hv1 = -1;
static int hf_bthci_cmd_packet_type_hv2 = -1;
static int hf_bthci_cmd_packet_type_hv3 = -1;
static int hf_bthci_cmd_role = -1;
static int hf_bthci_cmd_pin_code_length = -1;
static int hf_bthci_cmd_pin_code = -1;
static int hf_bthci_cmd_pin_type = -1;
static int hf_bthci_cmd_encryption_enable = -1;
static int hf_bthci_cmd_key_flag = -1;
static int hf_bthci_cmd_max_interval_hold = -1;
static int hf_bthci_cmd_min_interval_hold = -1;
static int hf_bthci_cmd_max_interval_sniff = -1;
static int hf_bthci_cmd_min_interval_sniff = -1;
static int hf_bthci_cmd_sniff_attempt = -1;
static int hf_bthci_cmd_timeout = -1;
static int hf_bthci_cmd_max_interval_beacon = -1;
static int hf_bthci_cmd_min_interval_beacon = -1;
static int hf_bthci_cmd_flags = -1;
static int hf_bthci_cmd_service_type = -1;
static int hf_bthci_cmd_token_rate = -1;
static int hf_bthci_cmd_peak_bandwidth = -1;
static int hf_bthci_cmd_latency = -1;
static int hf_bthci_cmd_delay_variation = -1;
static int hf_bthci_cmd_link_policy_setting_switch = -1;
static int hf_bthci_cmd_link_policy_setting_hold = -1;
static int hf_bthci_cmd_link_policy_setting_sniff = -1;
static int hf_bthci_cmd_link_policy_setting_park = -1;
static int hf_bthci_cmd_filter_type = -1;
static int hf_bthci_cmd_inquiry_result_filter_condition_type = -1;
static int hf_bthci_cmd_connection_setup_filter_condition_type = -1;
static int hf_bthci_cmd_class_of_device = -1;
static int hf_bthci_cmd_class_of_device_mask = -1;
static int hf_bthci_cmd_auto_acc_flag = -1;
static int hf_bthci_cmd_read_all_flag = -1;
static int hf_bthci_cmd_delete_all_flag = -1;
static int hf_bthci_cmd_authentication_enable = -1;
static int hf_bthci_cmd_input_coding = -1;
static int hf_bthci_cmd_input_data_format = -1;
static int hf_bthci_cmd_input_sample_size = -1;
static int hf_bthci_cmd_linear_pcm_bit_pos = -1;
static int hf_bthci_cmd_air_coding_format = -1;
static int hf_bthci_cmd_num_broadcast_retransmissions = -1;
static int hf_bthci_cmd_hold_mode_act_page = -1;
static int hf_bthci_cmd_hold_mode_act_inquiry = -1;
static int hf_bthci_cmd_hold_mode_act_periodic = -1;
static int hf_bthci_cmd_scan_enable = -1;
static int hf_bthci_cmd_interval = -1;
static int hf_bthci_cmd_window = -1;
static int hf_bthci_cmd_local_name = -1;
static int hf_bthci_cmd_num_curr_iac = -1;
static int hf_bthci_cmd_iac_lap = -1;
static int hf_bthci_cmd_evt_mask_01 = -1;
static int hf_bthci_cmd_evt_mask_02 = -1;
static int hf_bthci_cmd_evt_mask_03 = -1;
static int hf_bthci_cmd_evt_mask_04 = -1;
static int hf_bthci_cmd_evt_mask_05 = -1;
static int hf_bthci_cmd_evt_mask_06 = -1;
static int hf_bthci_cmd_evt_mask_07 = -1;
static int hf_bthci_cmd_evt_mask_08 = -1;
static int hf_bthci_cmd_evt_mask_09 = -1;
static int hf_bthci_cmd_evt_mask_0a = -1;
static int hf_bthci_cmd_evt_mask_0b = -1;
static int hf_bthci_cmd_evt_mask_0c = -1;
static int hf_bthci_cmd_evt_mask_0d = -1;
static int hf_bthci_cmd_evt_mask_0e = -1;
static int hf_bthci_cmd_evt_mask_0f = -1;
static int hf_bthci_cmd_evt_mask_10 = -1;
static int hf_bthci_cmd_evt_mask_11 = -1;
static int hf_bthci_cmd_evt_mask_12 = -1;
static int hf_bthci_cmd_evt_mask_13 = -1;
static int hf_bthci_cmd_evt_mask_14 = -1;
static int hf_bthci_cmd_evt_mask_15 = -1;
static int hf_bthci_cmd_evt_mask_16 = -1;
static int hf_bthci_cmd_evt_mask_17 = -1;
static int hf_bthci_cmd_evt_mask_18 = -1;
static int hf_bthci_cmd_evt_mask_19 = -1;
static int hf_bthci_cmd_evt_mask_1a = -1;
static int hf_bthci_cmd_evt_mask_1b = -1;
static int hf_bthci_cmd_evt_mask_1c = -1;
static int hf_bthci_cmd_evt_mask_1d = -1;
static int hf_bthci_cmd_evt_mask_1e = -1;
static int hf_bthci_cmd_evt_mask_1f = -1;
static int hf_bthci_cmd_evt_mask_20 = -1;
static int hf_bthci_cmd_sco_flow_control = -1;
static int hf_bthci_cmd_num_handles = -1;
static int hf_bthci_cmd_num_compl_packets = -1;
static int hf_bthci_cmd_flow_contr_enable = -1;
static int hf_bthci_cmd_host_data_packet_length_acl = -1;
static int hf_bthci_cmd_host_data_packet_length_sco = -1;
static int hf_bthci_cmd_host_total_num_acl_data_packets = -1;
static int hf_bthci_cmd_host_total_num_sco_data_packets = -1;
static int hf_bthci_cmd_power_level_type = -1;
static int hf_bthci_cmd_loopback_mode = -1;

/* Initialize the subtree pointers */
static gint ett_bthci_cmd = -1;
static gint ett_opcode = -1;


static const value_string cmd_opcode_vals[] = {
	{0x0000, "No Operation"},
	{0x0401, "Inquiry"},
	{0x0402, "Inquiry Cancel"},
	{0x0403, "Periodic Inquiry Mode"},
	{0x0404, "Exit Periodic Inquiry Mode"},
	{0x0405, "Create Connection"},
	{0x0406, "Disconnect"},
	{0x0407, "Add SCO Connection"},
	{0x0409, "Accept Connection Request"},
	{0x040a, "Reject Connection Request"},
	{0x040b, "Link Key Request Reply"},
	{0x040c, "Link Key Request Negative Reply"},
	{0x040d, "PIN Code Request Reply"},
	{0x040e, "PIN Code Request Negative Reply"},
	{0x040f, "Change Connection Packet Type"},
	{0x0411, "Authentication Requested"},
	{0x0413, "Set Connection Encryption"},
	{0x0415, "Change Connection Link Key"},
	{0x0417, "Master Link Key"},
	{0x0419, "Remote Name Request"},
	{0x041b, "Read Remote Supported Features"},
	{0x041d, "Read Remote Version Information"},
	{0x041f, "Read Clock offset"},
	{0x0801, "Hold Mode"},
	{0x0803, "Sniff Mode"},
	{0x0804, "Exit Sniff Mode"},
	{0x0805, "Park Mode"},
	{0x0806, "Exit Park Mode"},
	{0x0807, "QoS Setup"},
	{0x0809, "Role Discovery"},
	{0x080b, "Switch Role"},
	{0x080c, "Read Link Policy Settings"},
	{0x080d, "Write Link Policy Settings"},
	{0x0c01, "Set Event Mask"},
	{0x0c03, "Reset"},
	{0x0c05, "Set Event Filter"},
	{0x0c08, "Flush"},
	{0x0c09, "Read PIN Type "},
	{0x0c0a, "Write PIN Type"},
	{0x0c0b, "Create New Unit Key"},
	{0x0c0d, "Read Stored Link Key"},
	{0x0c11, "Write Stored Link Key"},
	{0x0c12, "Delete Stored Link Key"},
	{0x0c13, "Change Local Name"},
	{0x0c14, "Read Local Name"},
	{0x0c15, "Read Connection Accept Timeout"},
	{0x0c16, "Write Connection Accept Timeout"},
	{0x0c17, "Read Page Timeout"},
	{0x0c18, "Write Page Timeout"},
	{0x0c19, "Read Scan Enable"},
	{0x0c1a, "Write Scan Enable"},
	{0x0c1b, "Read Page Scan Activity"},
	{0x0c1c, "Write Page Scan Activity"},
	{0x0c1d, "Read Inquiry Scan Activity"},
	{0x0c1e, "Write Inquiry Scan Activity"},
	{0x0c1f, "Read Authentication Enable"},
	{0x0c20, "Write Authentication Enable"},
	{0x0c21, "Read Encryption Mode"},
	{0x0c22, "Write Encryption Mode"},
	{0x0c23, "Read Class of Device"},
	{0x0c24, "Write Class of Device"},
	{0x0c25, "Read Voice Setting"},
	{0x0c26, "Write Voice Setting"},
	{0x0c27, "Read Automatic Flush Timeout"},
	{0x0c28, "Write Automatic Flush Timeout"},
	{0x0c29, "Read Num Broadcast Retransmissions"},
	{0x0c2a, "Write Num Broadcast Retransmissions"},
	{0x0c2b, "Read Hold Mode Activity "},
	{0x0c2c, "Write Hold Mode Activity"},
	{0x0c2d, "Read Transmit Power Level"},
	{0x0c2e, "Read SCO Flow Control Enable"},
	{0x0c2f, "Write SCO Flow Control Enable"},
	{0x0c31, "Set Host Controller To Host Flow Control"},
	{0x0c33, "Host Buffer Size"},
	{0x0c35, "Host Number of Completed Packets"},
	{0x0c36, "Read Link Supervision Timeout"},
	{0x0c37, "Write Link Supervision Timeout"},
	{0x0c38, "Read Number of Supported IAC"},
	{0x0c39, "Read Current IAC LAP"},
	{0x0c3a, "Write Current IAC LAP"},
	{0x0c3b, "Read Page Scan Period Mode"},
	{0x0c3c, "Write Page Scan Period Mode"},
	{0x0c3d, "Read Page Scan Mode"},
	{0x0c3e, "Write Page Scan Mode"},
	{0x1001, "Read Local Version Information"},
	{0x1003, "Read Local Supported Features"},
	{0x1005, "Read Buffer Size"},
	{0x1007, "Read Country Code"},
	{0x1009, "Read BD ADDR"},
	{0x1401, "Read Failed Contact Counter"},
	{0x1402, "Reset Failed Contact Counter"},
	{0x1403, "Get Link Quality"},
	{0x1405, "Read RSSI"},
	{0x1801, "Read Loopback Mode"},
	{0x1802, "Write Loopback Mode"},
	{0x1803, "Enable Device Under Test Mode"},
	{0, NULL}
};

static const value_string cmd_status_vals[] = {
	{0x00, "Command Succeeded"},
	{0x01, "Unknown HCI Command"},
	{0x02, "No Connection"},
	{0x03, "Hardware Failure"},
	{0x04, "Page Timeout"},
	{0x05, "Authentication Failure"},
	{0x06, "Key Missing"},
	{0x07, "Memory Full"},
	{0x08, "Connection Timeout"},
	{0x09, "Max Number Of Connections"},
	{0x0A, "Max Number Of SCO Connections To A Device"},
	{0x0B, "ACL connection already exists"},
	{0x0C, "Command Disallowed"},
	{0x0D, "Host Rejected due to limited resources"},
	{0x0E, "Host Rejected due to security reasons"},
	{0x0F, "Host Rejected due to remote device is only a personal device"},
	{0x10, "Host Timeout"},
	{0x11, "Unsupported Feature or Parameter Value"},
	{0x12, "Invalid HCI Command Parameters"},
	{0x13, "Other End Terminated Connection: User Ended Connection"},
	{0x14, "Other End Terminated Connection: Low Resources"},
	{0x15, "Other End Terminated Connection: About to Power Off"},
	{0x16, "Connection Terminated by Local Host"},
	{0x17, "Repeated Attempts"},
	{0x18, "Pairing Not Allowed"},
	{0x19, "Unknown LMP PDU"},
	{0x1A, "Unsupported Remote Feature"},
	{0x1B, "SCO Offset Rejected"},
	{0x1C, "SCO Interval Rejected"},
	{0x1D, "SCO Air Mode Rejected"},
	{0x1E, "Invalid LMP Parameters"},
	{0x1F, "Unspecified Error"},
	{0x20, "Unsupported LMP Parameter Value"},
	{0x21, "Role Change Not Allowed"},
	{0x22, "LMP Response Timeout"},
	{0x23, "LMP Error Transaction Collision"},
	{0x24, "LMP PDU Not Allowed"},
	{0x25, "Encryption Mode Not Acceptable"},
	{0x26, "Unit Key Used"},
	{0x27, "QoS is Not Supported"},
	{0x28, "Instant Passed"},
	{0x29, "Pairing with Unit Key Not Supported"},
	{0, NULL }
};

static const value_string cmd_role_vals[] = {
	{0x00, "Become Master"},
	{0x01, "Remain Slave"},
	{0, NULL }
};

static const value_string cmd_pin_types[] = {
	{0x00, "Variable PIN" },
	{0x01, "Fixed PIN" },
	{0, NULL }
};

static const value_string cmd_encryption_enable[] = {
	{0x00, "Link Level Encryption is OFF"},
	{0x01, "Link Level Encryption is ON"},
	{0, NULL }
};

static const value_string cmd_key_flag[] = {
	{0x00, "Using Semi-permanent Link Key"},
	{0x01, "Using Temporary Link Key"},
	{0, NULL }
};

static const value_string cmd_filter_types[] = {
	{0x00, "Clear all Filters" },
	{0x01, "Inquiry Result" },
	{0x02, "Connection Setup" },
	{0, NULL }
};

static const value_string cmd_inquiry_result_filter_condition_types[] = {
	{0x00, "A new device responded" },
	{0x01, "A device with the specified Class of Device responded" },
	{0x02, "A device with the specified BD_ADDR responded" },
	{0, NULL }
};

static const value_string cmd_service_types[] = {
	{0x00, "No Traffic"},
	{0x01, "Best Effort"},
	{0x02, "Guaranteed"},
	{0, NULL }
};

static const value_string cmd_connection_setup_filter_condition_types[] = {
	{0x00, "Allow Connections from all devices" },
	{0x01, "Allow Connections from a device with a specific Class of Device" },
	{0x02, "Allow Connections from a device with a specific BD_ADDR" },
	{0, NULL }
};

static const value_string cmd_auto_acc_flag_values[] = {
	{0x01, "Do NOT Auto accept" },
	{0x02, "Do Auto accept, role switch disabled" },
	{0x03, "Do Auto accept, role switch enabled" },
	{0, NULL }
};

static const value_string cmd_read_all_flag_values[] = {
	{0x00, "Return Link Key for speified BD_ADDR" },
	{0x01, "Return all stored Link Keys" },
	{0, NULL }
}; 

static const value_string cmd_delete_all_flag_values[] = {
	{0x00, "Delete only Link Key for speified BD_ADDR" },
	{0x01, "Delete all stored Link Keys" },
	{0, NULL }
}; 

static const value_string cmd_scan_enable_values[] = {
	{0x00, "No Scans enabled" },
	{0x01, "Inquiry Scan enabled/Page Scan disable" },
	{0x02, "Inquiry Scan disabled/Page Scan enabled" },
	{0x03, "Inquiry Scan enabled/Page Scan enabled" },
	{0, NULL }
};

static const value_string cmd_authentication_enable_values[] = {
	{0x00, "Authentication disabled" },
	{0x01, "Authentication enabled for all connection" },
	{0, NULL }
};

static const value_string cmd_input_coding_values[] = {
	{0x0, "Linear" },
	{0x1, "\xb5-law" },
	{0x2, "A-law" },
	{0, NULL }
};

static const value_string cmd_input_data_format_values[] = {
	{0x0, "1's complement" },
	{0x1, "2's complement" },
	{0x2, "Sign-Magnitude" },
	{0, NULL }
};

static const value_string cmd_input_sample_size_values[] = {
	{0x0, "8 bit (only for Linear PCM)" },
	{0x1, "16 bit (only for Linear PCM)" },
	{0, NULL }
};

static const value_string cmd_air_coding_format_values[] = {
	{0x0, "CVSD" },
	{0x1, "\xb5-law" },
	{0x2, "A-law" },
	{0, NULL }
};

static const value_string cmd_en_disabled[] = {
	{0x00, "disabled" },
	{0x01, "enabled" },
	{0, NULL }
};

static const value_string cmd_flow_contr_enable[] = {
	{0x00, "Flow control off in direction from Host Controller to Host." },
	{0x01, "ON - HCI ACL Data Packets / OFF - HCI SCO Data Packets" }, 
	{0x02, "OFF - HCI ACL Data Packets / ON - HCI SCO Data Packets" }, 
	{0x03, "ON - HCI ACL Data Packets / ON - HCI SCO Data Packets" },
	{0, NULL }
};

static const value_string cmd_power_level_types[] = {
	{0x00, "Read Current Transmission Power Level" },
	{0x01, "Read Maximum Transmission Power Level" },
	{0, NULL }
};

static const value_string cmd_loopback_modes[] = {
	{0x00, "No Loopback mode enabled" },
	{0x01, "Enable Local Loopback" },
	{0x02, "Enable Remote Loopback" },
	{0, NULL }
};


/*
 * The HCI_OGF_ values for "ogf".
 */
#define HCI_OGF_LINK_CONTROL		0x01
#define HCI_OGF_LINK_POLICY		0x02
#define HCI_OGF_HOST_CONTROLLER		0x03
#define HCI_OGF_INFORMATIONAL		0x04
#define HCI_OGF_STATUS		        0x05
#define HCI_OGF_TESTING		        0x06

static const value_string ogf_vals[] = {
	{ HCI_OGF_LINK_CONTROL,	"Link Control Commands" },
	{ HCI_OGF_LINK_POLICY,	"Link Policy Commands" },
	{ HCI_OGF_HOST_CONTROLLER,"Host Controller & Baseband Commands" },
	{ HCI_OGF_INFORMATIONAL,"Informational Parameters" },
	{ HCI_OGF_STATUS,	"Status Parameters" },
	{ HCI_OGF_TESTING,	"Testing Commands" },
	{ 0, NULL }
};


static const value_string encrypt_mode_vals[] = {
	{ 0x00,	"Encryption Disabled" },
	{ 0x01,	"Encryption only for Point-To-Point Packets" },
	{ 0x02, "Encryption for Point-To-Point and Broadcast Packets" },
	{ 0, NULL }
};


static const value_string cmd_boolean[] = {
	{0, "false" },
	{1, "true" },
	{0, NULL }
};


static const value_string cmd_page_scan_modes[] = {
	{0, "Mandatory Page Scan Mode"},
	{1, "Optional Page Scan Mode I"},
	{2, "Optional Page Scan Mode II"},
	{3, "Optional Page Scan Mode III"},
	{0, NULL }
};

static const value_string cmd_page_scan_repetition_modes[] = {
	{0, "R0"},
	{1, "R1"},
	{2, "R2"},
	{0, NULL }
};

static const value_string cmd_page_scan_period_modes[] = {
	{0, "P0"},
	{1, "P1"},
	{2, "P2"},
	{0, NULL }
};

static const value_string cmd_role_switch_modes[] = {
	{0, "Local device will be master, and will not accept a master-slave switch request." },
	{1, "Local device may be master, or may become slave after accepting a master slave switch." },
	{0, NULL }
};


void
dissect_link_control_cmd(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, guint16 cmd_ocf)
{
	proto_item *item;
	guint32 clock;

	switch(cmd_ocf) {
		case 0x0001: /* Inquiry */  
			proto_tree_add_item(tree, hf_bthci_cmd_lap, tvb, offset, 3, TRUE);
			offset+=3;
			proto_tree_add_item(tree, hf_bthci_cmd_inq_length, tvb, offset, 1, TRUE);
			offset++;
			proto_tree_add_item(tree, hf_bthci_cmd_num_responses, tvb, offset, 1, TRUE);
			offset++;
			break;

		case 0x0002: /* Inquiry Cancel */
			/* no parameters */
			break;

		case 0x0003: /* Periodic Inquiry Mode */
			proto_tree_add_item(tree, hf_bthci_cmd_max_period_length, tvb, offset, 2, TRUE);
			offset+=2;
			proto_tree_add_item(tree, hf_bthci_cmd_min_period_length, tvb, offset, 2, TRUE);
			offset+=2;
			proto_tree_add_item(tree, hf_bthci_cmd_lap, tvb, offset, 3, TRUE);
			offset+=3;
			proto_tree_add_item(tree, hf_bthci_cmd_inq_length, tvb, offset, 1, TRUE);
			offset++;
			proto_tree_add_item(tree, hf_bthci_cmd_num_responses, tvb, offset, 1, TRUE);
			offset++;
			break;

		case 0x0004: /* Exit Periodic Inquiry Mode */
			/* no parameters */
			break;

		case 0x0005: /* Create Connection */
			proto_tree_add_item(tree, hf_bthci_cmd_bd_addr, tvb, offset, 6, TRUE);
			offset+=6;

			proto_tree_add_item(tree, hf_bthci_cmd_packet_type_dm1, tvb, offset, 2, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_packet_type_dh1, tvb, offset, 2, TRUE); 
			proto_tree_add_item(tree, hf_bthci_cmd_packet_type_dm3, tvb, offset, 2, TRUE); 
			proto_tree_add_item(tree, hf_bthci_cmd_packet_type_dh3, tvb, offset, 2, TRUE); 
			proto_tree_add_item(tree, hf_bthci_cmd_packet_type_dm5, tvb, offset, 2, TRUE); 
			proto_tree_add_item(tree, hf_bthci_cmd_packet_type_dh5, tvb, offset, 2, TRUE); 
			offset+=2;

			proto_tree_add_item(tree, hf_bthci_cmd_page_scan_repetition_mode, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_cmd_page_scan_mode, tvb, offset, 1, TRUE);
			offset++;

			item = proto_tree_add_item(tree, hf_bthci_cmd_clock_offset, tvb, offset, 2, TRUE);
			clock = tvb_get_letohs(tvb, 13) & 32767; /* only bit0-14 are valid  */
			proto_item_append_text(item, " (%g ms)", 1.25*clock);
			proto_tree_add_item(tree, hf_bthci_cmd_clock_offset_valid , tvb, offset, 2, TRUE);
			offset+=2;

			proto_tree_add_item(tree, hf_bthci_cmd_allow_role_switch, tvb, offset, 1, TRUE); 
			offset++;
			break;

		case 0x0006: /* Disconnect */
			proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, TRUE);
			offset+=2;
			proto_tree_add_item(tree, hf_bthci_cmd_reason, tvb, offset, 1, TRUE);
			offset++;
			break;

		case 0x0007: /* Add SCO Connection */
			proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, TRUE);
			offset+=2;
			proto_tree_add_item(tree, hf_bthci_cmd_packet_type_hv1, tvb, offset, 2, TRUE); 
			proto_tree_add_item(tree, hf_bthci_cmd_packet_type_hv2, tvb, offset, 2, TRUE); 
			proto_tree_add_item(tree, hf_bthci_cmd_packet_type_hv3, tvb, offset, 2, TRUE); 
			offset+=2;
			break;

		case 0x0009: /* Accept Connection Request */
			proto_tree_add_item(tree, hf_bthci_cmd_bd_addr, tvb, offset, 6, TRUE);
			offset+=6;
			proto_tree_add_item(tree, hf_bthci_cmd_role, tvb, offset, 1, TRUE);
			offset++;
			break;

		case 0x000a: /* Reject Connection Request */
			proto_tree_add_item(tree, hf_bthci_cmd_bd_addr, tvb, offset, 6, TRUE);
			offset+=6;
			proto_tree_add_item(tree, hf_bthci_cmd_reason, tvb, offset, 1, TRUE);
			offset++;
			break;

		case 0x000b: /* Link Key Request Reply */
			proto_tree_add_item(tree, hf_bthci_cmd_bd_addr, tvb, offset, 6, TRUE);
			offset+=6;
			proto_tree_add_item(tree, hf_bthci_cmd_link_key, tvb, offset, 16, TRUE);
			offset+=16;
			break; 

		case 0x000c: /* Link Key Request Negative Reply */
			proto_tree_add_item(tree, hf_bthci_cmd_bd_addr, tvb, offset, 6, TRUE);
			offset+=6;
			break;

		case 0x000d: /* PIN Code Request Reply */
			proto_tree_add_item(tree, hf_bthci_cmd_bd_addr, tvb, offset, 6, TRUE);
			offset+=6;
			proto_tree_add_item(tree, hf_bthci_cmd_pin_code_length ,tvb, offset, 1, TRUE);
			offset++;
			proto_tree_add_item(tree, hf_bthci_cmd_pin_code ,tvb, offset, 16, TRUE);
			offset+=16;
			break;

		case 0x000e: /* PIN Code Request Negative Reply */
			proto_tree_add_item(tree, hf_bthci_cmd_bd_addr, tvb, offset, 6, TRUE);
			offset+=6;
			break;

		case 0x000f: /* Change Connection Packet Type */
			proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, TRUE);
			offset+=2;
			proto_tree_add_item(tree, hf_bthci_cmd_packet_type_dm1, tvb, offset, 2, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_packet_type_dh1, tvb, offset, 2, TRUE); 
			proto_tree_add_item(tree, hf_bthci_cmd_packet_type_dm3, tvb, offset, 2, TRUE); 
			proto_tree_add_item(tree, hf_bthci_cmd_packet_type_dh3, tvb, offset, 2, TRUE); 
			proto_tree_add_item(tree, hf_bthci_cmd_packet_type_dm5, tvb, offset, 2, TRUE); 
			proto_tree_add_item(tree, hf_bthci_cmd_packet_type_dh5, tvb, offset, 2, TRUE); 
			proto_tree_add_item(tree, hf_bthci_cmd_packet_type_hv1, tvb, offset, 2, TRUE); 
			proto_tree_add_item(tree, hf_bthci_cmd_packet_type_hv2, tvb, offset, 2, TRUE); 
			proto_tree_add_item(tree, hf_bthci_cmd_packet_type_hv3, tvb, offset, 2, TRUE); 
			offset+=2;
			break;

		case 0x0011: /* Authentication Request */
			proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, TRUE);
			offset+=2;
			break;

		case 0x0013: /* Set Connection Encryption */
			proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, TRUE);
			offset+=2;
			proto_tree_add_item(tree, hf_bthci_cmd_encryption_enable, tvb, offset, 1, TRUE);
			offset++;
			break; 

		case 0x0017: /* Master Link Key */
			proto_tree_add_item(tree, hf_bthci_cmd_key_flag, tvb, offset, 1, TRUE);
			offset++;
			break;

		case 0x0019: /* Remote Name Request */
			proto_tree_add_item(tree, hf_bthci_cmd_bd_addr, tvb, offset, 6, TRUE);
			offset+=6;
			proto_tree_add_item(tree, hf_bthci_cmd_page_scan_repetition_mode, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_cmd_page_scan_mode, tvb, offset, 1, TRUE);
			offset++;

			item = proto_tree_add_item(tree, hf_bthci_cmd_clock_offset, tvb, offset, 2, TRUE);
			clock = tvb_get_letohs(tvb, offset) & 32767; /* only bit0-14 are valid  */
			proto_item_append_text(item, " (%g ms)", 1.25*clock);
			proto_tree_add_item(tree, hf_bthci_cmd_clock_offset_valid , tvb, offset, 2, TRUE);
			offset+=2;
			break;

		case 0x0015: /* Change Connection Link Key */
		case 0x001b: /* Read Remote Supported Features */
		case 0x001d: /* Read Remote Version Information */
		case 0x001f: /* Read Clock Offset*/
			proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, TRUE);
			offset+=2;
			break;

		default:
			proto_tree_add_item(tree, hf_bthci_cmd_params, tvb, offset, -1, TRUE);
			offset+=tvb_length_remaining(tvb, offset);
			break;
	}
}

void
dissect_link_policy_cmd(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, guint16 cmd_ocf)
{
	proto_item *item;
	guint16 timeout;

	switch(cmd_ocf) {

		case 0x0001: /* Hold Mode */
			proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, TRUE);
			offset+=2;
			proto_tree_add_item(tree, hf_bthci_cmd_max_interval_hold, tvb, offset, 2, TRUE);
			offset+=2;
			proto_tree_add_item(tree, hf_bthci_cmd_min_interval_hold, tvb, offset, 2, TRUE);
			offset+=2;
			break;

		case 0x0003: /* sniff mode */
			proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, TRUE);
			offset+=2;
			proto_tree_add_item(tree, hf_bthci_cmd_max_interval_sniff, tvb, offset, 2, TRUE);
			offset+=2;
			proto_tree_add_item(tree, hf_bthci_cmd_min_interval_sniff, tvb, offset, 2, TRUE);
			offset+=2;
			proto_tree_add_item(tree, hf_bthci_cmd_sniff_attempt, tvb, offset, 2, TRUE);
			offset+=2;
			item = proto_tree_add_item(tree, hf_bthci_cmd_timeout, tvb, offset, 2, TRUE);
			timeout = tvb_get_letohs(tvb, 11);
			if(timeout>0){
				proto_item_append_text(item, " (%g msec)", (2*timeout-1)*0.625);
			} else {
				proto_item_append_text(item, " (0 msec)");
			}
			offset+=2;
			break;

		case 0x0005: /* Park Mode */
			proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, TRUE);
			offset+=2;
			proto_tree_add_item(tree, hf_bthci_cmd_max_interval_beacon, tvb, offset, 2, TRUE);
			offset+=2;
			proto_tree_add_item(tree, hf_bthci_cmd_min_interval_beacon, tvb, offset, 2, TRUE);
			offset+=2;
			break;

		case 0x0007: /* QoS Setup */
			proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, TRUE);
			offset+=2;
			proto_tree_add_item(tree, hf_bthci_cmd_flags, tvb, offset, 1, TRUE);
			offset++;
			proto_tree_add_item(tree, hf_bthci_cmd_service_type, tvb, offset, 1, TRUE);
			offset++;
			proto_tree_add_item(tree, hf_bthci_cmd_token_rate, tvb, offset, 4, TRUE);
			offset+=4;
			proto_tree_add_item(tree, hf_bthci_cmd_peak_bandwidth, tvb, offset, 4, TRUE);
			offset+=4;
			proto_tree_add_item(tree, hf_bthci_cmd_latency, tvb, offset, 4, TRUE);
			offset+=4;
			proto_tree_add_item(tree, hf_bthci_cmd_delay_variation, tvb, offset, 4, TRUE);
			offset+=4;
			break;

		case 0x000b: /* Switch Role */
			proto_tree_add_item(tree, hf_bthci_cmd_bd_addr, tvb, offset, 6, TRUE);
			offset+=6;
			proto_tree_add_item(tree, hf_bthci_cmd_role, tvb, offset, 1, TRUE);
			offset++;
			break;

		case 0x000d: /* Write Link Policy Settings */
			proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, TRUE);
			offset+=2;
			proto_tree_add_item(tree, hf_bthci_cmd_link_policy_setting_switch, tvb, offset, 2, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_link_policy_setting_hold  , tvb, offset, 2, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_link_policy_setting_sniff , tvb, offset, 2, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_link_policy_setting_park  , tvb, offset, 2, TRUE);
			offset+=2;
			break;

		case 0x0004: /* Exit Sniff Mode */
		case 0x0006: /* Exit Park Mode */
		case 0x0009: /* Role Discovery */
		case 0x000c: /* Read Link Policy Settings */
			proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, TRUE);
			offset+=2;
			break;

		default:
			proto_tree_add_item(tree, hf_bthci_cmd_params, tvb, offset, -1, TRUE);
			offset+=tvb_length_remaining(tvb, offset);
			break;

	}
}

void
dissect_host_controller_baseband_cmd(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, 
		proto_tree *tree, guint16 cmd_ocf)
{
	proto_item *item;
	guint16 timeout;
	guint8 filter_type, filter_condition_type, num8;
	int i;

	switch(cmd_ocf) {

		case 0x0001: /* Set Event Mask */
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_01, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_02, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_03, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_04, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_05, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_06, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_07, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_08, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_09, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_0a, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_0b, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_0c, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_0d, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_0e, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_0f, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_10, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_11, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_12, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_13, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_14, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_15, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_16, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_17, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_18, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_19, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_1a, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_1b, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_1c, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_1d, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_1e, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_1f, tvb, offset, 4, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_evt_mask_20, tvb, offset, 4, TRUE);
			offset+=4;
			break;

		case 0x0005: /* Set Event Filter */
			proto_tree_add_item(tree, hf_bthci_cmd_filter_type, tvb, offset, 1, TRUE);
			filter_type = tvb_get_guint8(tvb, 3);
			offset++;
			switch (filter_type) {

				case 0x01: /* Inquiry Result Filter */
					proto_tree_add_item(tree, hf_bthci_cmd_inquiry_result_filter_condition_type,
							tvb, offset, 1, TRUE);
					filter_condition_type = tvb_get_guint8(tvb, offset); 
					offset++;
					switch (filter_condition_type) {
						case 0x01:
							proto_tree_add_item(tree, hf_bthci_cmd_class_of_device, tvb, offset, 3, TRUE);
							offset+=3;
							proto_tree_add_item(tree, hf_bthci_cmd_class_of_device_mask, tvb, offset, 3, TRUE);
							offset+=3;
							break;

						case 0x02:
							proto_tree_add_item(tree, hf_bthci_cmd_bd_addr, tvb, offset, 6, TRUE);
							offset+=6;
							break;

						default:
							break;

					}
					break;

				case 0x02: /* Connection Setup Filter */
					proto_tree_add_item(tree, hf_bthci_cmd_connection_setup_filter_condition_type,
							tvb, offset, 1, TRUE);
					filter_condition_type = tvb_get_guint8(tvb, offset); 
					offset++;
					switch (filter_condition_type) {
						case 0x00:
							proto_tree_add_item(tree, hf_bthci_cmd_auto_acc_flag, tvb, offset, 1, TRUE);
							offset++;
							break;

						case 0x01:
							proto_tree_add_item(tree, hf_bthci_cmd_class_of_device, tvb, offset, 3, TRUE);
							offset+=3;
							proto_tree_add_item(tree, hf_bthci_cmd_class_of_device_mask, tvb, offset, 3, TRUE);
							offset+=3;
							proto_tree_add_item(tree, hf_bthci_cmd_auto_acc_flag, tvb, offset, 1, TRUE);
							offset++;
							break;

						case 0x02:
							proto_tree_add_item(tree, hf_bthci_cmd_bd_addr, tvb, offset, 6, TRUE);
							offset+=6;
							proto_tree_add_item(tree, hf_bthci_cmd_auto_acc_flag, tvb, offset, 1, TRUE);
							offset++;
							break;

						default:
							break;

					}
					break;

				default:
					break;

			}

			break;
		case 0x000a: /* Write PIN Type */
			proto_tree_add_item(tree, hf_bthci_cmd_pin_type, tvb, offset, 1, TRUE);
			offset++;
			break;

		case 0x000d: /* Read Stored Link Key */
			proto_tree_add_item(tree, hf_bthci_cmd_bd_addr, tvb, offset, 6, TRUE);
			offset+=6;
			proto_tree_add_item(tree, hf_bthci_cmd_read_all_flag, tvb, offset, 1, TRUE);
			offset++;
			break;

		case 0x0011: /* Write Stored Link Key */
			proto_tree_add_item(tree, hf_bthci_cmd_num_link_keys, tvb, offset, 1, TRUE);
			num8 = tvb_get_guint8(tvb, offset);
			offset++;
			for (i=0; i<num8; i++) {
				proto_tree_add_item(tree, hf_bthci_cmd_bd_addr, tvb, offset+(i*22), 6, TRUE);
				proto_tree_add_item(tree, hf_bthci_cmd_link_key, tvb, offset+6+(i*22), 16, TRUE);
			}
			break;

		case 0x0012: /* Delete Stored Link Key */
			proto_tree_add_item(tree, hf_bthci_cmd_bd_addr, tvb, offset, 6, TRUE);
			offset+=6;
			proto_tree_add_item(tree, hf_bthci_cmd_delete_all_flag, tvb, offset, 1, TRUE);
			offset++;
			break;

		case 0x0013: /* Change Local Name */
			proto_tree_add_item(tree, hf_bthci_cmd_local_name, 
					tvb, offset, 248, FALSE);
			offset+=248;
			break;

		case 0x0016: /* Write Connection Accept Timeout */
			item = proto_tree_add_item(tree, hf_bthci_cmd_timeout, tvb, offset, 2, TRUE);
			timeout = tvb_get_letohs(tvb, offset);
			proto_item_append_text(item, " slots (%g msec)", timeout*0.625);
			offset+=2;
			break;

		case 0x0018: /* Write Page Timeout */
			item = proto_tree_add_item(tree, hf_bthci_cmd_timeout, tvb, offset, 2, TRUE);
			timeout = tvb_get_letohs(tvb, offset);
			if(timeout > 0){
				proto_item_append_text(item, " slots (%g msec)", timeout*0.625);
			} else {
				proto_item_append_text(item, " Illegal Page Timeout");
			}
			offset+=2;
			break;

		case 0x001a: /* Write Scan Anable */
			proto_tree_add_item(tree, hf_bthci_cmd_scan_enable, 
					tvb, offset, 1, TRUE);
			offset++;
			break; 

		case 0x0020: /* Write Authentication Enable */
			proto_tree_add_item(tree, hf_bthci_cmd_authentication_enable, 
					tvb, offset, 1, TRUE);
			offset++;
			break;

		case 0x0022: /* Write Encryption Mode */ 
			proto_tree_add_item(tree, hf_bthci_cmd_encrypt_mode, tvb, offset, 1, TRUE);
			offset++;
			break;

		case 0x0024: /* Write Class of Device */
			proto_tree_add_item(tree, hf_bthci_cmd_class_of_device,
					tvb, offset, 3, TRUE);
			offset+=3;
			break;

		case 0x0026: /* Write Voice Setting */
			proto_tree_add_item(tree, hf_bthci_cmd_input_coding,
					tvb, offset, 2, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_input_data_format,
					tvb, offset, 2, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_input_sample_size,
					tvb, offset, 2, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_linear_pcm_bit_pos,
					tvb, offset, 2, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_air_coding_format,
					tvb, offset, 2, TRUE);
			offset+=2;
			break;

		case 0x0028: /* Write Automatic Flush Timeout */
			proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, TRUE);
			offset+=2;
			item = proto_tree_add_item(tree, hf_bthci_cmd_timeout, tvb, offset, 2, TRUE);
			timeout = tvb_get_letohs(tvb, offset);
			if(timeout>0){
				proto_item_append_text(item, " slots (%g msec)", timeout*0.625);
			} else {
				proto_item_append_text(item, " (= No Automatic Flush )");
			}
			offset+=2;
			break;

		case 0x002a: /* Write Num of Broadcast Retransmissions */
			proto_tree_add_item(tree, hf_bthci_cmd_num_broadcast_retransmissions,
					tvb, offset, 1, TRUE);
			offset++;
			break;

		case 0x002c: /* Write Hold Mode Activity */
			proto_tree_add_item(tree, hf_bthci_cmd_hold_mode_act_page,
					tvb, offset, 1, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_hold_mode_act_inquiry, 
					tvb, offset, 1, TRUE);
			proto_tree_add_item(tree, hf_bthci_cmd_hold_mode_act_periodic, 
					tvb, offset, 1, TRUE);
			offset++;
			break;

		case 0x002d: /* Read Transmit Power Level */
			proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, 
					tvb, offset, 2, TRUE);
			offset+=2;
			proto_tree_add_item(tree, hf_bthci_cmd_power_level_type,
					tvb, offset, 1, TRUE);
			offset++;
			break;

		case 0x002f: /* Write SCO Flow Control Enable */
			proto_tree_add_item(tree, hf_bthci_cmd_sco_flow_control,
					tvb, offset, 1, TRUE);
			offset++;
			break;

		case 0x0031: /* Set Host Controller To Host Flow Control */
			proto_tree_add_item(tree, hf_bthci_cmd_flow_contr_enable, 
					tvb, offset, 1, TRUE);
			offset++;
			break;

		case 0x0033: /* Host Buffer Size */
			proto_tree_add_item(tree, hf_bthci_cmd_host_data_packet_length_acl,
					tvb, offset, 2, TRUE);
			offset+=2;
			proto_tree_add_item(tree, hf_bthci_cmd_host_data_packet_length_sco,
					tvb, offset, 1, TRUE);
			offset++;
			proto_tree_add_item(tree, hf_bthci_cmd_host_total_num_acl_data_packets,
					tvb, offset, 2, TRUE);
			offset+=2;
			proto_tree_add_item(tree, hf_bthci_cmd_host_total_num_sco_data_packets,
					tvb, offset, 2, TRUE);
			offset+=2;
			break;

		case 0x0035: /* Host Number Of Completed Packets */
			proto_tree_add_item(tree, hf_bthci_cmd_num_handles, 
					tvb, offset, 1, TRUE);
			num8 = tvb_get_guint8(tvb, offset);
			offset++;
			for (i=0; i<num8; i++) {
				proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, 
						tvb, offset+(i*4), 2, TRUE);
				proto_tree_add_item(tree, hf_bthci_cmd_num_compl_packets, 
						tvb, offset+2+(i*4), 2, TRUE);
			}
			break;

		case 0x0037: /* Write Link Supervision Timeout */
			proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, 
					tvb, offset, 2, TRUE);
			offset+=2;
			item = proto_tree_add_item(tree, hf_bthci_cmd_timeout, 
					tvb, offset, 2, TRUE);
			timeout = tvb_get_letohs(tvb, offset);
			if(timeout>0){
				proto_item_append_text(item, " slots (%g msec)", timeout*0.625);
			} else {
				proto_item_append_text(item, " (= No Link Supervision Timeout)");
			}
			offset+=2;
			break;

		case 0x003a: /* Write Current IAC LAP */
			proto_tree_add_item(tree, hf_bthci_cmd_num_curr_iac, tvb, offset, 1, TRUE);
			num8 = tvb_get_guint8(tvb, offset);
			offset++;
			for (i=0; i<num8; i++) {
				proto_tree_add_item(tree, hf_bthci_cmd_iac_lap, tvb, offset+(i*3), 3, TRUE);
			}
			break;

		case 0x003c: /* Write Page Scan Period Mode */
			proto_tree_add_item(tree, hf_bthci_cmd_page_scan_period_mode,
					tvb, offset, 1, TRUE);
			offset++;
			break;

		case 0x003e: /* Write Page Scan Mode */
			proto_tree_add_item(tree, hf_bthci_cmd_page_scan_mode, 
					tvb, 3, 1, TRUE);
			break;

		case 0x0008: /* Flush */
		case 0x0027: /* Read Automatic Flush Timeout */
		case 0x0036: /* Read Link Supervision Timeout */
			proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, TRUE);
			offset+=2;
			break;

		case 0x001c: /* Write Page Scan Activity */
		case 0x001e: /* Write Inquiry Scan Activity */
			item = proto_tree_add_item(tree, hf_bthci_cmd_interval, tvb, offset, 2, TRUE);
			proto_item_append_text(item, " slots (%g msec)",  tvb_get_letohs(tvb, offset)*0.625);
			offset+=2;
			item = proto_tree_add_item(tree, hf_bthci_cmd_window, tvb, offset, 2, TRUE); 
			proto_item_append_text(item, " slots (%g msec)",  tvb_get_letohs(tvb, offset)*0.625);
			offset+=2;
			break;

		default:
			proto_tree_add_item(tree, hf_bthci_cmd_params, tvb, offset, -1, TRUE);
			offset+=tvb_length_remaining(tvb, offset);
			break;

	}
}

void dissect_informational_parameters_cmd(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, 
		proto_tree *tree, guint16 cmd_ocf)
{
	switch(cmd_ocf) {

		/* There should be no command parameters to dissect */

		default:
			proto_tree_add_item(tree, hf_bthci_cmd_params, tvb, offset, -1, TRUE);
			offset+=tvb_length_remaining(tvb, offset);
			break;

	}
}

void
dissect_status_parameters_cmd(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, 
		proto_tree *tree, guint16 cmd_ocf)
{
	switch(cmd_ocf) {

		case 0x0001: /* Read Failed Contact Counter */
		case 0x0002: /* Reset Failed Contact Counter */
		case 0x0003: /* Get Link Quality */
		case 0x0005: /* Read RSSI */
			proto_tree_add_item(tree, hf_bthci_cmd_connection_handle, tvb, offset, 2, TRUE);
			offset+=2;
			break;

		default:
			proto_tree_add_item(tree, hf_bthci_cmd_params, tvb, offset, -1, TRUE);
			offset+=tvb_length_remaining(tvb, offset);
			break;

	}
}

void
dissect_testing_cmd(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, guint16 cmd_ocf)
{
	switch(cmd_ocf) {

		case 0x0002: /* Write Loopback Mode */
			proto_tree_add_item(tree, hf_bthci_cmd_loopback_mode, tvb, offset, 1, TRUE);
			offset++;
			break;

		default:
			proto_tree_add_item(tree, hf_bthci_cmd_params, tvb, offset, -1, TRUE);
			offset+=tvb_length_remaining(tvb, offset);
			break;

	}
}

/* Code to actually dissect the packets */
static void
dissect_bthci_cmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti_cmd=NULL;
	proto_tree *bthci_cmd_tree=NULL;
	guint16 opcode, ocf;
	guint8 param_length, ogf;
	int offset=0;

	proto_item *ti_opcode;
	proto_tree *opcode_tree;

	if(tree){
		ti_cmd = proto_tree_add_item(tree, proto_bthci_cmd, tvb, offset, -1, FALSE);
		bthci_cmd_tree = proto_item_add_subtree(ti_cmd, ett_bthci_cmd);
	}

	opcode = tvb_get_letohs(tvb, offset);
	ocf = opcode & 0x03ff;
	ogf = tvb_get_guint8(tvb, 1) >> 2;

	proto_item_append_text(ti_cmd," - %s", val_to_str(opcode, cmd_opcode_vals, "Unknown 0x%04x"));

	if(check_col(pinfo->cinfo, COL_PROTOCOL)){
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "HCI_CMD");
	}

	if((check_col(pinfo->cinfo, COL_INFO))){
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(opcode, cmd_opcode_vals, "Unknown 0x%04x"));
	}


	ti_opcode = proto_tree_add_item(bthci_cmd_tree, hf_bthci_cmd_opcode, tvb, offset, 2, TRUE);
	opcode_tree = proto_item_add_subtree(ti_opcode, ett_opcode);
	proto_tree_add_item(opcode_tree, hf_bthci_cmd_ogf, tvb, offset, 2, TRUE);
	proto_tree_add_item(opcode_tree, hf_bthci_cmd_ocf, tvb, offset, 2, TRUE);
	offset+=2;


	proto_tree_add_item(bthci_cmd_tree, hf_bthci_cmd_param_length, tvb, offset, 1, TRUE);
	param_length = tvb_get_guint8(tvb, offset);
	offset++;

	if(param_length>0){
		switch(ogf){
			case 0x01: /* Link Control Command */
				dissect_link_control_cmd(tvb, offset, pinfo, bthci_cmd_tree, ocf);
				break;

			case 0x02: /* Link Policy Command */
				dissect_link_policy_cmd(tvb, offset, pinfo, bthci_cmd_tree, ocf);
				break;

			case 0x03: /* Host Controller & Baseband Command */
				dissect_host_controller_baseband_cmd(tvb, offset, pinfo, bthci_cmd_tree, ocf);
				break;

			case 0x04: /* Informational Parameter Command */
				dissect_informational_parameters_cmd(tvb, offset, pinfo, bthci_cmd_tree, ocf);
				break;

			case 0x05: /* Status Parameter Command */
				dissect_status_parameters_cmd(tvb, offset, pinfo, bthci_cmd_tree, ocf);
				break;

			case 0x06: /* Testing Command */
				dissect_testing_cmd(tvb, offset, pinfo, bthci_cmd_tree, ocf);
				break;

				/*    case 0x0c22:*/ /* Write Encryption Mode */
				/*      proto_tree_add_item(bthci_cmd_tree, hf_bthci_cmd_encrypt_mode, tvb, 3, 1, TRUE);
					break;
					*/
			default:
				proto_tree_add_item(bthci_cmd_tree, hf_bthci_cmd_params, tvb, 3, -1, TRUE);
				break;
		}
	}
}


/* Register the protocol with Ethereal */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
   */
void
proto_register_bthci_cmd(void)
{                 

	/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_bthci_cmd_opcode,
			{ "Command Opcode","bthci_cmd.opcode", FT_UINT16, BASE_HEX, 
				VALS(cmd_opcode_vals), 0x0, "HCI Command Opcode", HFILL }
		},
		{ &hf_bthci_cmd_ogf,
			{ "ogf",           "bthci_cmd.ogf",
				FT_UINT16, BASE_HEX, VALS(ogf_vals), 0xfc00,          
				"Opcode Group Field", HFILL }
		},
		{ &hf_bthci_cmd_ocf,
			{ "ocf",           "bthci_cmd.ocf",
				FT_UINT16, BASE_HEX, NULL, 0x03ff,          
				"Opcode Command Field", HFILL }
		},
		{ &hf_bthci_cmd_param_length,
			{ "Parameter Total Length",           "bthci_cmd.param_length",
				FT_UINT8, BASE_DEC, NULL, 0x0,          
				"Parameter Total Length", HFILL }
		},
		{ &hf_bthci_cmd_params,
			{ "Command Parameters",           "bthci_cmd.params",
				FT_BYTES, BASE_HEX, NULL, 0x0,          
				"Command Parameters", HFILL }
		},
		{ &hf_bthci_cmd_lap,
			{ "LAP",           "bthci_cmd.lap",
				FT_UINT24, BASE_HEX, NULL, 0x0,          
				"LAP for the inquiry access code", HFILL }
		},
		{ &hf_bthci_cmd_inq_length,
			{ "Inquiry Length",           "bthci_cmd.inq_length",
				FT_UINT8, BASE_DEC, NULL, 0x0,          
				"Inquiry Length (*1.28s)", HFILL }
		},
		{ &hf_bthci_cmd_num_responses,
			{ "Num Responses",           "bthci_cmd.num_responses",
				FT_UINT8, BASE_DEC, NULL, 0x0,          
				"Number of Responses", HFILL }
		},
		{ &hf_bthci_cmd_encrypt_mode,
			{ "Encryption Mode",           "bthci_cmd.encrypt_mode",
				FT_UINT8, BASE_HEX, VALS(encrypt_mode_vals), 0x0,          
				"Encryption Mode", HFILL }
		},
		{ &hf_bthci_cmd_bd_addr,
			{ "BD_ADDR",          "bthci_cmd.bd_addr",
				FT_ETHER, BASE_HEX, NULL, 0x0,
				"Bluetooth Device Address", HFILL}
		},
		{ &hf_bthci_cmd_packet_type_dm1,
			{ "Packet Type DM1",        "bthci_cmd.packet_type_dm1",
				FT_UINT16, BASE_DEC, VALS(cmd_boolean), 0x0008,
				"Packet Type DM1", HFILL }
		},
		{ &hf_bthci_cmd_packet_type_dh1,
			{ "Packet Type DH1",        "bthci_cmd.packet_type_dh1",
				FT_UINT16, BASE_DEC, VALS(cmd_boolean), 0x0010,
				"Packet Type DH1", HFILL }
		},
		{ &hf_bthci_cmd_packet_type_dm3,
			{ "Packet Type DM3",        "bthci_cmd.packet_type_dm3",
				FT_UINT16, BASE_DEC, VALS(cmd_boolean), 0x0400,
				"Packet Type DM3", HFILL }
		},
		{ &hf_bthci_cmd_packet_type_dh3,
			{ "Packet Type DH3",        "bthci_cmd.packet_type_dh3",
				FT_UINT16, BASE_DEC, VALS(cmd_boolean), 0x0800,
				"Packet Type DH3", HFILL }
		},
		{ &hf_bthci_cmd_packet_type_dm5,
			{ "Packet Type DM5",        "bthci_cmd.packet_type_dm5",
				FT_UINT16, BASE_DEC, VALS(cmd_boolean), 0x4000,
				"Packet Type DM5", HFILL }
		},
		{ &hf_bthci_cmd_packet_type_dh5,
			{ "Packet Type DH5",        "bthci_cmd.packet_type_dh5",
				FT_UINT16, BASE_DEC, VALS(cmd_boolean), 0x8000,
				"Packet Type DH5", HFILL }
		},
		{ &hf_bthci_cmd_page_scan_mode,
			{ "Page Scan Mode",        "bthci_cmd.page_scan_mode",
				FT_UINT8, BASE_HEX, VALS(cmd_page_scan_modes), 0x0,
				"Page Scan Mode", HFILL }
		},
		{ &hf_bthci_cmd_page_scan_repetition_mode,
			{ "Page Scan Repetition Mode",        "bthci_cmd.page_scan_repetition_mode",
				FT_UINT8, BASE_HEX, VALS(cmd_page_scan_repetition_modes), 0x0,
				"Page Scan Repetition Mode", HFILL }
		},
		{ &hf_bthci_cmd_page_scan_period_mode,
			{ "Page Scan Period Mode",        "bthci_cmd.page_scan_period_mode",
				FT_UINT8, BASE_HEX, VALS(cmd_page_scan_period_modes), 0x0,
				"Page Scan Period Mode", HFILL }
		},
		{ &hf_bthci_cmd_clock_offset,
			{ "Clock Offset",        "bthci_cmd.clock_offset",
				FT_UINT16, BASE_HEX, NULL, 0x7FFF,
				"Bit 2-16 of the Clock Offset between CLKmaster-CLKslave", HFILL }
		},
		{ &hf_bthci_cmd_clock_offset_valid,
			{ "Clock_Offset_Valid_Flag",     "bthci_cmd.clock_offset_valid",
				FT_UINT16, BASE_DEC, VALS(cmd_boolean), 0x8000,
				"Indicates if clock offset is valid", HFILL }
		},
		{ &hf_bthci_cmd_allow_role_switch,
			{ "Allow Role Switch",         "bthci_cmd.allow_role_switch",
				FT_UINT8, BASE_HEX, VALS(cmd_role_switch_modes), 0x0,
				"Allow Role Switch", HFILL }
		},
		{ &hf_bthci_cmd_status,
			{ "Status",           "bthci_cmd.status",
				FT_UINT8, BASE_HEX, VALS(cmd_status_vals), 0x0,          
				"Status", HFILL }
		},

		{ &hf_bthci_cmd_max_period_length,       
			{ "Max Period Length",           "bthci_cmd.max_period_length",
				FT_UINT16, BASE_DEC, NULL, 0x0,          
				"Maximum amount of time specified between consecutive inquiries.", HFILL }
		},
		{ &hf_bthci_cmd_min_period_length,       
			{ "Min Period Length",           "bthci_cmd.min_period_length",
				FT_UINT16, BASE_DEC, NULL, 0x0,          
				"Minimum amount of time specified between consecutive inquiries.", HFILL }
		},
		{ &hf_bthci_cmd_connection_handle,
			{ "Connection Handle",             "bthci_cmd.connection_handle",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				"Connection Handle", HFILL }
		},
		{ &hf_bthci_cmd_reason,
			{ "Reason",           "bthci_cmd.reason",
				FT_UINT8, BASE_HEX, VALS(cmd_status_vals), 0x0,          
				"Reason", HFILL }
		},
		{ &hf_bthci_cmd_num_link_keys,
			{ "Number of Link Keys", "bthci_cmd_num_link_keys",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				"Number of Link Keys", HFILL }
		},
		{ &hf_bthci_cmd_link_key,
			{ "Link Key",        "bthci_cmd.link_key",
				FT_BYTES, BASE_HEX, NULL, 0x0,
				"Link Key for the associated BD_ADDR", HFILL }
		},
		{ &hf_bthci_cmd_packet_type_hv1,
			{ "Packet Type HV1",        "bthci_cmd.packet_type_hv1",
				FT_UINT16, BASE_DEC, VALS(cmd_boolean), 0x0020,
				"Packet Type HV1", HFILL }
		},
		{ &hf_bthci_cmd_packet_type_hv2,
			{ "Packet Type HV2",        "bthci_cmd.packet_type_hv2",
				FT_UINT16, BASE_DEC, VALS(cmd_boolean), 0x0040,
				"Packet Type HV2", HFILL }
		},
		{ &hf_bthci_cmd_packet_type_hv3,
			{ "Packet Type HV3",        "bthci_cmd.packet_type_hv3",
				FT_UINT16, BASE_DEC, VALS(cmd_boolean), 0x0080,
				"Packet Type HV3", HFILL }
		},
		{ &hf_bthci_cmd_role,
			{ "Role",        "bthci_cmd.role",
				FT_UINT8, BASE_HEX, VALS(cmd_role_vals), 0x0,
				"Role", HFILL }
		},
		{ &hf_bthci_cmd_pin_code_length,
			{ "PIN Code Length",        "bthci_cmd.pin_code_length",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				"PIN Code Length", HFILL }
		},
		{ &hf_bthci_cmd_pin_code,
			{ "PIN Code",        "bthci_cmd.pin_code",
				FT_STRING, BASE_HEX, NULL, 0x0,
				"PIN Code", HFILL }
		},
		{ &hf_bthci_cmd_pin_type,
			{ "PIN Type", "bthci_cmd.pin_type",
				FT_UINT8, BASE_HEX, VALS(cmd_pin_types), 0x0,
				"PIN Types", HFILL }
		},
		{ &hf_bthci_cmd_encryption_enable,
			{ "Encryption Enable",        "bthci_cmd.encryption_enable",
				FT_UINT8, BASE_HEX, VALS(cmd_encryption_enable), 0x0,
				"Encryption Enable", HFILL }
		},
		{ &hf_bthci_cmd_key_flag,
			{ "Key Flag",        "bthci_cmd.key_flag",
				FT_UINT8, BASE_HEX, VALS(cmd_key_flag), 0x0,
				"Key Flag", HFILL }
		},
		{ &hf_bthci_cmd_max_interval_hold,
			{ "Hold Mode Max Interval",        "bthci_cmd.hold_mode_max_int",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				"Maximal acceptable number of Baseband slots to wait in Hold Mode.", HFILL }
		},
		{ &hf_bthci_cmd_min_interval_hold,
			{ "Hold Mode Min Interval",        "bthci_cmd.hold_mode_min_int",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				"Minimum acceptable number of Baseband slots to wait in Hold Mode.", HFILL }
		},
		{ &hf_bthci_cmd_max_interval_sniff,
			{ "Sniff Max Interval",        "bthci_cmd.sniff_max_int",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				"Maximal acceptable number of Baseband slots between each sniff period.", HFILL }
		},
		{ &hf_bthci_cmd_min_interval_sniff,
			{ "Sniff Min Interval",        "bthci_cmd.sniff_min_int",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				"Minimum acceptable number of Baseband slots between each sniff period.", HFILL }
		},
		{ &hf_bthci_cmd_sniff_attempt,
			{ "Sniff Attempt",        "bthci_cmd.sniff_attempt",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				"Number of Baseband receive slots for sniff attempt.", HFILL }
		},
		{ &hf_bthci_cmd_timeout,
			{ "Timeout",        "bthci_cmd.timeout",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				"Number of Baseband slots for timeout.", HFILL }
		},
		{ &hf_bthci_cmd_max_interval_beacon,
			{ "Beacon Max Interval",        "bthci_cmd.beacon_max_int",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				"Maximal acceptable number of Baseband slots between consecutive beacons.", HFILL }
		},
		{ &hf_bthci_cmd_min_interval_beacon,
			{ "Beacon Min Interval",        "bthci_cmd.beacon_min_int",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				"Minimum acceptable number of Baseband slots between consecutive beacons.", HFILL }
		},
		{ &hf_bthci_cmd_flags,
			{ "Flags",        "bthci_cmd.flags",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				"Flags", HFILL }
		},
		{ &hf_bthci_cmd_service_type,
			{ "Service Type",        "bthci_cmd.service_type",
				FT_UINT8, BASE_HEX, VALS(cmd_service_types), 0x0,
				"Service Type", HFILL }
		},
		{ &hf_bthci_cmd_token_rate,
			{ "Available Token Rate",        "bthci_cmd.token_rate",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				"Token Rate, in bytes per second", HFILL }
		},
		{ &hf_bthci_cmd_peak_bandwidth,
			{ "Peak Bandwidth",        "bthci_cmd.peak_bandwidth",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				"Peak Bandwidth, in bytes per second", HFILL }
		},
		{ &hf_bthci_cmd_latency,
			{ "Latecy",        "bthci_cmd.latency",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				"Latency, in microseconds", HFILL }
		},
		{ &hf_bthci_cmd_delay_variation,
			{ "Delay Variation",        "bthci_cmd.delay_variation",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				"Delay Variation, in microseconds", HFILL }
		},
		{ &hf_bthci_cmd_link_policy_setting_switch,
			{ "Enable Master Slave Switch", "bthci_cmd.link_policy_switch",
				FT_UINT16, BASE_DEC, VALS(cmd_boolean), 0x0001,
				"Enable Master Slave Switch", HFILL }
		}, 
		{ &hf_bthci_cmd_link_policy_setting_hold,
			{ "Enable Hold Mode", "bthci_cmd.link_policy_hold",
				FT_UINT16, BASE_DEC, VALS(cmd_boolean), 0x0002,
				"Enable Hold Mode", HFILL }
		},
		{ &hf_bthci_cmd_link_policy_setting_sniff,
			{ "Enable Sniff Mode", "bthci_cmd.link_policy_sniff",
				FT_UINT16, BASE_DEC, VALS(cmd_boolean), 0x0004,
				"Enable Sniff Mode", HFILL }
		},
		{ &hf_bthci_cmd_link_policy_setting_park,
			{ "Enable Park Mode", "bthci_cmd.link_policy_park",
				FT_UINT16, BASE_DEC, VALS(cmd_boolean), 0x0008,
				"Enable Park Mode", HFILL }
		},
		{ &hf_bthci_cmd_filter_type,
			{ "Filter Type", "bthci_cmd.filter_type",
				FT_UINT8, BASE_HEX, VALS(cmd_filter_types), 0x0,
				"Filter Type", HFILL }
		},
		{ &hf_bthci_cmd_inquiry_result_filter_condition_type,
			{ "Filter Condition Type", "bthci_cmd.filter_condition_type",
				FT_UINT8, BASE_HEX, VALS(cmd_inquiry_result_filter_condition_types), 0x0,
				"Filter Condition Type", HFILL }
		},
		{ &hf_bthci_cmd_connection_setup_filter_condition_type,
			{ "Filter Condition Type", "bthci_cmd.filter_condition_type",
				FT_UINT8, BASE_HEX, VALS(cmd_connection_setup_filter_condition_types), 0x0,
				"Filter Condition Type", HFILL }
		},
		{ &hf_bthci_cmd_class_of_device,
			{ "Class of Device", "bthci_cmd.class_of_device",
				FT_UINT24, BASE_HEX, NULL, 0x0,
				"Class of Device", HFILL }
		},
		{ &hf_bthci_cmd_class_of_device_mask,
			{ "Class of Device Mask", "bthci_cmd.class_of_device_mask",
				FT_UINT24, BASE_DEC, NULL, 0x0,
				"Bit Mask used to determine which bits of the Class of Device parameter are of interest.", HFILL }
		},
		{ &hf_bthci_cmd_auto_acc_flag,
			{ "Auto Accept Flag", "bthci_cmd.auto_accept_flag",
				FT_UINT8, BASE_HEX, VALS(cmd_auto_acc_flag_values), 0x0,
				"Class of Device of Interest", HFILL }
		},
		{ &hf_bthci_cmd_read_all_flag,
			{ "Read All Flag", "bthci_cmd.read_all_flag",
				FT_UINT8, BASE_HEX, VALS(cmd_read_all_flag_values), 0x0,
				"Read All Flag", HFILL }
		},
		{ &hf_bthci_cmd_delete_all_flag,
			{ "Delete All Flag", "bthci_cmd.delete_all_flag",
				FT_UINT8, BASE_HEX, VALS(cmd_delete_all_flag_values), 0x0,
				"Delete All Flag", HFILL }
		},
		{ &hf_bthci_cmd_authentication_enable,
			{ "Authentication Enable", "bthci_cmd.auth_enable",
				FT_UINT8, BASE_HEX, VALS(cmd_authentication_enable_values), 0x0,
				"Authentication Enable", HFILL }
		},  
		{ &hf_bthci_cmd_input_coding,
			{ "Input Coding", "bthci_cmd.input_coding",
				FT_UINT16, BASE_DEC, VALS(cmd_input_coding_values), 0x0300,
				"Authentication Enable", HFILL }
		},
		{ &hf_bthci_cmd_input_data_format,
			{ "Input Data Format", "bthci_cmd.input_data_format",
				FT_UINT16, BASE_DEC, VALS(cmd_input_data_format_values), 0x00c0,
				"Input Data Format", HFILL }
		},  
		{ &hf_bthci_cmd_input_sample_size,
			{ "Input Sample Size", "bthci_cmd.input_sample_size",
				FT_UINT16, BASE_DEC, VALS(cmd_input_sample_size_values), 0x0020,
				"Input Sample Size", HFILL }
		}, 
		{ &hf_bthci_cmd_linear_pcm_bit_pos,
			{ "Linear PCM Bit Pos", "bthci_cmd.lin_pcm_bit_pos",
				FT_UINT16, BASE_DEC, NULL, 0x001c,
				"# bit pos. that MSB of sample is away from starting at MSB", HFILL }
		},
		{ &hf_bthci_cmd_air_coding_format,
			{ "Air Coding Format", "bthci_cmd.air_coding_format",
				FT_UINT16, BASE_DEC, VALS(cmd_air_coding_format_values), 0x0003,
				"Air Coding Format", HFILL }
		},
		{ &hf_bthci_cmd_num_broadcast_retransmissions,
			{ "Num Broadcast Retran", "bthci_cmd.num_broad_retran",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				"Number of Broadcast Retransmissions", HFILL }
		},
		{ &hf_bthci_cmd_hold_mode_act_page,
			{ "Suspend Page Scan", "bthci_cmd.hold_mode_page",
				FT_UINT8, BASE_DEC, VALS(cmd_boolean), 0x1,
				"Device can enter low power state", HFILL }
		},
		{ &hf_bthci_cmd_hold_mode_act_inquiry,
			{ "Suspend Inquiry Scan", "bthci_cmd.hold_mode_inquiry",
				FT_UINT8, BASE_DEC, VALS(cmd_boolean), 0x2,
				"Device can enter low power state", HFILL }
		},
		{ &hf_bthci_cmd_hold_mode_act_periodic,
			{ "Suspend Periodic Inquiries", "bthci_cmd.hold_mode_periodic",
				FT_UINT8, BASE_DEC, VALS(cmd_boolean), 0x4,
				"Device can enter low power state", HFILL }
		},
		{ &hf_bthci_cmd_scan_enable,
			{ "Scan Enable", "bthci_cmd.scan_enable",
				FT_UINT8, BASE_HEX, VALS(cmd_scan_enable_values), 0x0,
				"Scan Enable", HFILL }
		},
		{ &hf_bthci_cmd_interval,
			{ "Interval", "bthci_cmd.interval",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				"Interval", HFILL }
		},
		{ &hf_bthci_cmd_window,
			{ "Interval", "bthci_cmd.window",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				"Window", HFILL }
		},
		{ &hf_bthci_cmd_local_name,
			{ "Remote Name",           "bthci_cmd.local_name",
				FT_STRINGZ, BASE_NONE, NULL, 0x0,          
				"Userfriendly descriptive name for the device", HFILL }
		},
		{ &hf_bthci_cmd_num_curr_iac,
			{ "Number of Current IAC", "bthci_cmd.num_curr_iac",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				"Number of IACs which are currently in use", HFILL }
		},
		{ &hf_bthci_cmd_iac_lap,
			{ "IAC LAP", "bthci_cmd.num_curr_iac",
				FT_UINT24, BASE_HEX, NULL, 0x0,
				"LAP(s)used to create IAC", HFILL }
		},
		{ &hf_bthci_cmd_evt_mask_01,
			{ "Inquiry Complete                   ", "bthci_cmd.evt_mask_01",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x00000001,
				"Inquiry Complete Bit", HFILL }
		},
		{ &hf_bthci_cmd_evt_mask_02,
			{ "Inquiry Result                     ", "bthci_cmd.evt_mask_02",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x00000002,
				"Inquiry Result Bit", HFILL }
		},
		{ &hf_bthci_cmd_evt_mask_03,
			{ "Connect Complete                   ", "bthci_cmd.evt_mask_03",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x00000004,
				"Connection Complete Bit", HFILL }
		},
		{ &hf_bthci_cmd_evt_mask_04,
			{ "Connect Request                    ", "bthci_cmd.evt_mask_04",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x00000008,
				"Connect Request Bit", HFILL }
		},
		{ &hf_bthci_cmd_evt_mask_05,
			{ "Disconnect Complete                   ", "bthci_cmd.evt_mask_05",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x00000010,
				"Disconnect Complete Bit", HFILL }
		},
		{ &hf_bthci_cmd_evt_mask_06,
			{ "Auth Complete                      ", "bthci_cmd.evt_mask_06",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x00000020,
				"Auth Complete Bit", HFILL }
		},
		{ &hf_bthci_cmd_evt_mask_07,
			{ "Remote Name Req Complete           ", "bthci_cmd.evt_mask_07",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x00000040,
				"Remote Name Req Complete Bit", HFILL }
		},
		{ &hf_bthci_cmd_evt_mask_08,
			{ "Encrypt Change                     ", "bthci_cmd.evt_mask_08",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x00000080,
				"Encrypt Change Bit", HFILL }
		},
		{ &hf_bthci_cmd_evt_mask_09,
			{ "Change Connection Link Key Complete", "bthci_cmd.evt_mask_09",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x00000100,
				"Change Connection Link Key Complete Bit", HFILL }
		},
		{ &hf_bthci_cmd_evt_mask_0a,
			{ "Master Link Key Complete           ", "bthci_cmd.evt_mask_0a",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x00000200,
				"Master Link Key Complete Bit", HFILL }
		},
		{ &hf_bthci_cmd_evt_mask_0b,
			{ "Read Remote Supported Features     ", "bthci_cmd.evt_mask_0b",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x00000400,
				"Read Remote Supported Features Bit", HFILL }
		},
		{ &hf_bthci_cmd_evt_mask_0c,
			{ "Read Remote Ver Info Complete      ", "bthci_cmd.evt_mask_0c",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x00000800,
				"Read Remote Ver Info Complete Bit", HFILL }
		},
		{ &hf_bthci_cmd_evt_mask_0d,
			{ "QoS Setup Complete                 ", "bthci_cmd.evt_mask_0d",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x00001000,
				"QoS Setup Complete Bit", HFILL }
		},
		{ &hf_bthci_cmd_evt_mask_0e,
			{ "Command Complete                   ", "bthci_cmd.evt_mask_0e",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x00002000,
				"Command Complete Bit", HFILL }
		},
		{ &hf_bthci_cmd_evt_mask_0f,
			{ "Command Status                     ", "bthci_cmd.evt_mask_0f",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x00004000,
				"Command Status Bit", HFILL }
		},
		{ &hf_bthci_cmd_evt_mask_10,
			{ "Hardware Error                     ", "bthci_cmd.evt_mask_10",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x00008000,
				"Hardware Error Bit", HFILL }
		},
		{ &hf_bthci_cmd_evt_mask_11,
			{ "Flush Occurred                     ", "bthci_cmd.evt_mask_11",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x00010000,
				"Flush Occurred Bit", HFILL }
		},
		{ &hf_bthci_cmd_evt_mask_12,
			{ "Role Change                        ", "bthci_cmd.evt_mask_12",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x00020000,
				"Role Change Bit", HFILL }
		},
		{ &hf_bthci_cmd_evt_mask_13,
			{ "Number of Completed Packets        ", "bthci_cmd.evt_mask_13",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x00040000,
				"Number of Completed Packets Bit", HFILL }
		},
		{ &hf_bthci_cmd_evt_mask_14,
			{ "Mode Change                        ", "bthci_cmd.evt_mask_14",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x00080000,
				"Mode Change Bit", HFILL }
		},
		{ &hf_bthci_cmd_evt_mask_15,
			{ "Return Link Keys                   ", "bthci_cmd.evt_mask_15",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x00100000,
				"Return Link Keys Bit", HFILL }
		},
		{ &hf_bthci_cmd_evt_mask_16,
			{ "PIN Code Request                   ", "bthci_cmd.evt_mask_16",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x00200000,
				"PIN Code Request Bit", HFILL }
		},
		{ &hf_bthci_cmd_evt_mask_17,
			{ "Link Key Request                   ", "bthci_cmd.evt_mask_17",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x00400000,
				"Link Key Request Bit", HFILL }
		},  
		{ &hf_bthci_cmd_evt_mask_18,
			{ "Link Key Notification              ", "bthci_cmd.evt_mask_18",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x00800000,
				"Link Key Notification Bit", HFILL }
		}, 
		{ &hf_bthci_cmd_evt_mask_19,
			{ "Loopback Command                   ", "bthci_cmd.evt_mask_19",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x01000000,
				"Loopback Command Bit", HFILL }
		}, 
		{ &hf_bthci_cmd_evt_mask_1a,
			{"Data Buffer Overflow               " , "bthci_cmd.evt_mask_1a",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x02000000,
				"Data Buffer Overflow Bit", HFILL }
		}, 
		{ &hf_bthci_cmd_evt_mask_1b,
			{ "Max Slots Change                   ", "bthci_cmd.evt_mask_1b",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x04000000,
				"Max Slots Change Bit", HFILL }
		}, 
		{ &hf_bthci_cmd_evt_mask_1c,
			{ "Read Clock Offset Complete         ", "bthci_cmd.evt_mask_1c",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x08000000,
				"Read Clock Offset Complete Bit", HFILL }
		}, 
		{ &hf_bthci_cmd_evt_mask_1d,
			{ "Connection Packet Type Changed     ", "bthci_cmd.evt_mask_1d",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x10000000,
				"Connection Packet Type Changed Bit", HFILL }
		}, 
		{ &hf_bthci_cmd_evt_mask_1e,
			{ "QoS Violation                      ", "bthci_cmd.evt_mask_1e",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x20000000,
				"QoS Violation Bit", HFILL }
		}, 
		{ &hf_bthci_cmd_evt_mask_1f,
			{ "Page Scan Mode Change              ", "bthci_cmd.evt_mask_1f",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x40000000,
				"Page Scan Mode Change Bit", HFILL }
		}, 
		{ &hf_bthci_cmd_evt_mask_20,
			{ "Page Scan Repetition Mode Change   ", "bthci_cmd.evt_mask_20",
				FT_UINT32, BASE_HEX, VALS(cmd_boolean), 0x80000000,
				"Page Scan Repetition Mode Change Bit", HFILL }
		}, 
		{ &hf_bthci_cmd_sco_flow_control,
			{ "SCO Flow Control","bthci_cmd.flow_control",
				FT_UINT8, BASE_HEX, VALS(cmd_en_disabled), 0x0,
				"SCO Flow Control", HFILL }
		},
		{ &hf_bthci_cmd_num_handles,
			{ "Number of Handles", "bthci_cmd.num_handles",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				"Number of Handles", HFILL }
		},

		{ &hf_bthci_cmd_num_compl_packets,
			{ "Number of Completed Packets", "bthci_cmd.num_compl_packets",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				"Number of Completed HCI Data Packets", HFILL }
		},
		{ &hf_bthci_cmd_flow_contr_enable,
			{ "Flow Control Enable", "bthci_cmd.flow_contr_enable",
				FT_UINT8, BASE_HEX, VALS(cmd_flow_contr_enable), 0x0,
				"Flow Control Enable", HFILL }
		},
		{ &hf_bthci_cmd_host_data_packet_length_acl,
			{"Host ACL Data Packet Length (bytes)", "bthci_cmd.max_data_length_acl",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				"Max Host ACL Data Packet length of data portion host is able to accept", HFILL }
		}, 
		{ &hf_bthci_cmd_host_data_packet_length_sco,
			{"Host SCO Data Packet Length (bytes)", "bthci_cmd.max_data_length_sco",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				"Max Host SCO Data Packet length of data portion host is able to accept", HFILL }
		}, 
		{ &hf_bthci_cmd_host_total_num_acl_data_packets,
			{"Host Total Num ACL Data Packets", "bthci_cmd.max_data_num_acl",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				"Total Number of HCI ACL Data Packets that can be stored in the data buffers of the Host", HFILL }
		}, 
		{ &hf_bthci_cmd_host_total_num_sco_data_packets,
			{"Host Total Num SCO Data Packets", "bthci_cmd.max_data_num_sco",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				"Total Number of HCI SCO Data Packets that can be stored in the data buffers of the Host", HFILL }
		}, 
		{ &hf_bthci_cmd_power_level_type,
			{"Type", "bthci_cmd.power_level_type",
				FT_UINT8, BASE_HEX, VALS(cmd_power_level_types), 0x0,
				"Type", HFILL}
		},
		{ &hf_bthci_cmd_loopback_mode,
			{"Loopback Mode", "bthci_cmd.loopback_mode",
				FT_UINT8, BASE_HEX, VALS(cmd_loopback_modes), 0x0,
				"Loopback Mode", HFILL}
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_bthci_cmd,
		&ett_opcode,
	};

	/* Register the protocol name and description */
	proto_bthci_cmd = proto_register_protocol("Bluetooth HCI Command", "HCI_CMD", "bthci_cmd");

	register_dissector("bthci_cmd", dissect_bthci_cmd, proto_bthci_cmd);

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_bthci_cmd, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
   */
void
proto_reg_handoff_bthci_cmd(void)
{
	dissector_handle_t bthci_cmd_handle;
	bthci_cmd_handle = find_dissector("bthci_cmd");
	dissector_add("hci_h4.type", HCI_H4_TYPE_CMD, bthci_cmd_handle);
}

