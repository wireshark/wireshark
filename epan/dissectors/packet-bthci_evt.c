/* packet-bthci_evt.c
 * Routines for the Bluetooth HCI Event dissection
 * Copyright 2002, Christoph Scholz <scholz@cs.uni-bonn.de>
 *  From: http://affix.sourceforge.net/archive/ethereal_affix-3.patch
 *
 * Refactored for ethereal checkin
 *   Ronnie Sahlberg 2006
 *
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
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <etypes.h>
#include <packet-hci_h4.h>

static dissector_handle_t bthci_com_handle;

/* Initialize the protocol and registered fields */
static int proto_bthci_evt = -1;
static int hf_bthci_evt_code = -1;
static int hf_bthci_evt_param_length = -1;
static int hf_bthci_evt_params = -1;
static int hf_bthci_evt_num_command_packets = -1;
static int hf_bthci_evt_num_handles = -1;
static int hf_bthci_evt_connection_handle = -1;
static int hf_bthci_evt_num_compl_packets = -1;
static int hf_bthci_evt_com_opcode = -1;
static int hf_bthci_evt_ret_params = -1;
static int hf_bthci_evt_status = -1;
static int hf_bthci_evt_ocf = -1;
static int hf_bthci_evt_ogf = -1;
static int hf_bthci_evt_bd_addr = -1;
static int hf_bthci_evt_link_type = -1;
static int hf_bthci_evt_encryption_mode = -1;
static int hf_bthci_evt_class_of_device = -1;
static int hf_bthci_evt_reason = -1;
static int hf_bthci_evt_remote_name = -1;
static int hf_bthci_evt_encryption_enable = -1;
static int hf_bthci_evt_key_flag = -1;
static int hf_bthci_evt_vers_nr = -1;
static int hf_bthci_evt_hci_vers_nr = -1;
static int hf_bthci_evt_hci_revision = -1;
static int hf_bthci_evt_comp_id = -1;
static int hf_bthci_evt_sub_vers_nr = -1;
static int hf_bthci_evt_flags = -1;
static int hf_bthci_evt_service_type = -1;
static int hf_bthci_evt_token_rate = -1;
static int hf_bthci_evt_peak_bandwidth = -1;
static int hf_bthci_evt_latency = -1;
static int hf_bthci_evt_delay_variation = -1;
static int hf_bthci_evt_hardware_code = -1;
static int hf_bthci_evt_role = -1;
static int hf_bthci_evt_curr_role = -1;
static int hf_bthci_evt_curr_mode = -1;
static int hf_bthci_evt_interval = -1;
static int hf_bthci_evt_link_key = -1;
static int hf_bthci_evt_key_type = -1;
static int hf_bthci_evt_max_slots = -1;
static int hf_bthci_evt_clock_offset = -1;
static int hf_bthci_evt_link_type_dm1 = -1;
static int hf_bthci_evt_link_type_dh1 = -1;
static int hf_bthci_evt_link_type_dm3 = -1;
static int hf_bthci_evt_link_type_dh3 = -1;
static int hf_bthci_evt_link_type_dm5 = -1;
static int hf_bthci_evt_link_type_dh5 = -1;
static int hf_bthci_evt_link_type_hv1 = -1;
static int hf_bthci_evt_link_type_hv2 = -1;
static int hf_bthci_evt_link_type_hv3 = -1;
static int hf_bthci_evt_page_scan_mode = -1;
static int hf_bthci_evt_page_scan_repetition_mode = -1;
static int hf_bthci_evt_page_scan_period_mode = -1;
static int hf_bthci_evt_lmp_feature_00 = -1;
static int hf_bthci_evt_lmp_feature_01 = -1;
static int hf_bthci_evt_lmp_feature_02 = -1;
static int hf_bthci_evt_lmp_feature_03 = -1;
static int hf_bthci_evt_lmp_feature_04 = -1;
static int hf_bthci_evt_lmp_feature_05 = -1;
static int hf_bthci_evt_lmp_feature_06 = -1;
static int hf_bthci_evt_lmp_feature_07 = -1;
static int hf_bthci_evt_lmp_feature_10 = -1;
static int hf_bthci_evt_lmp_feature_11 = -1;
static int hf_bthci_evt_lmp_feature_12 = -1;
static int hf_bthci_evt_lmp_feature_13 = -1;
static int hf_bthci_evt_lmp_feature_14 = -1;
static int hf_bthci_evt_lmp_feature_15 = -1;
static int hf_bthci_evt_lmp_feature_16 = -1;
static int hf_bthci_evt_lmp_feature_17 = -1;
static int hf_bthci_evt_lmp_feature_20 = -1;
static int hf_bthci_evt_lmp_feature_21 = -1;
static int hf_bthci_evt_lmp_feature_22 = -1;
static int hf_bthci_evt_lmp_feature_23 = -1;
static int hf_bthci_evt_lmp_feature_24 = -1;
static int hf_bthci_evt_num_keys = -1;
static int hf_bthci_evt_num_keys_read = -1;
static int hf_bthci_evt_max_num_keys = -1;
static int hf_bthci_evt_num_responses = -1;
static int hf_bthci_evt_num_keys_written = -1;
static int hf_bthci_evt_num_keys_deleted = -1;
static int hf_bthci_evt_link_policy_setting_switch = -1;
static int hf_bthci_evt_link_policy_setting_hold = -1;
static int hf_bthci_evt_link_policy_setting_sniff = -1;
static int hf_bthci_evt_link_policy_setting_park = -1;
static int hf_bthci_evt_pin_type = -1;
static int hf_bthci_evt_name = -1;
static int hf_bthci_evt_timeout = -1;
static int hf_bthci_evt_scan_enable = -1;
static int hf_bthci_evt_authentication_enable = -1;
static int hf_bthci_evt_sco_flow_cont_enable = -1;
static int hf_bthci_evt_window = -1;
static int hf_bthci_evt_input_coding = -1;
static int hf_bthci_evt_input_data_format = -1;
static int hf_bthci_evt_input_sample_size = -1;
static int hf_bthci_evt_num_broadcast_retransm = -1;
static int hf_bthci_evt_hold_mode_act_page = -1;
static int hf_bthci_evt_hold_mode_act_inquiry = -1;
static int hf_bthci_evt_hold_mode_act_periodic = -1;
static int hf_bthci_evt_transmit_power_level = -1;
static int hf_bthci_evt_num_supp_iac = -1;
static int hf_bthci_evt_num_curr_iac = -1;
static int hf_bthci_evt_iac_lap = -1;
static int hf_bthci_evt_loopback_mode = -1;
static int hf_bthci_evt_country_code = -1;
static int hf_bthci_evt_failed_contact_counter = -1;
static int hf_bthci_evt_link_quality = -1;
static int hf_bthci_evt_rssi = -1;
static int hf_bthci_evt_host_data_packet_length_acl = -1;
static int hf_bthci_evt_host_data_packet_length_sco = -1;
static int hf_bthci_evt_host_total_num_acl_data_packets = -1;
static int hf_bthci_evt_host_total_num_sco_data_packets = -1;

/* Initialize the subtree pointers */
static gint ett_bthci_evt = -1;
static gint ett_opcode = -1;
static gint ett_lmp_subtree = -1;
static gint ett_ptype_subtree = -1;


static const value_string evt_code_vals[] = {
	{0x01, "Inquiry Complete"},
	{0x02, "Inquiry Result"},
	{0x03, "Connect Complete"},
	{0x04, "Connect Request"},
	{0x05, "Disconnect Complete"},
	{0x06, "Auth Complete"},
	{0x07, "Remote Name Req Complete"},
	{0x08, "Encrypt Change"},
	{0x09, "Change Connection Link Key Complete"},
	{0x0a, "Master Link Key Complete"},
	{0x0b, "Read Remote Supported Features"},
	{0x0c, "Read Remote Ver Info Complete"},
	{0x0d, "QoS Setup Complete"},
	{0x0e, "Command Complete"},
	{0x0f, "Command Status"},
	{0x10, "Hardware Error"},
	{0x11, "Flush Occurred"},
	{0x12, "Role Change"},
	{0x13, "Number of Completed Packets"},
	{0x14, "Mode Change"},
	{0x15, "Return Link Keys"},
	{0x16, "PIN Code Request"},
	{0x17, "Link Key Request"},
	{0x18, "Link Key Notification"},
	{0x19, "Loopback Command"},
	{0x1a, "Data Buffer Overflow"},
	{0x1b, "Max Slots Change"},
	{0x1c, "Read Clock Offset Complete"},
	{0x1d, "Connection Packet Type Changed"},
	{0x1e, "QoS Violation"},
	{0x1f, "Page Scan Mode Change"},
	{0x20, "Page Scan Repetition Mode Change"},
	{0, NULL}
};

static const value_string evt_status_vals[] = {
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
	{0, NULL}
};

static const value_string evt_link_types[]  = {
	{0x00, "SCO connection (Voice Channels)"},
	{0x01, "ACL connection (Data Channels)"},
	{0, NULL }
};

static const value_string evt_encryption_modes[] = {
	{0x00, "Encryption Disabled"},
	{0x01, "Encryption only for point-to-point packets"},
	{0x02, "Encryption for both point-to-point and broadcast packets"},
	{0, NULL }
};

static const value_string evt_encryption_enable[] = {
	{0x00, "Link Level Encryption is OFF"},
	{0x01, "Link Level Encryption is ON"},
	{0, NULL }
};

static const value_string evt_key_flag[] = {
	{0x00, "Using Semi-permanent Link Key"},
	{0x01, "Using Temporary Link Key"},
	{0, NULL }
};

static const value_string evt_lmp_vers_nr[] = {
	{0x00, "Bluetooth LMP 1.0"},
	{0x01, "Bluetooth LMP 1.1"},
	{0, NULL }
};

static const value_string evt_hci_vers_nr[] = {
	{0x00, "Bluetooth HCI Specification 1.0B"},
	{0x01, "Bluetooth HCI Specification 1.1"},
	{0, NULL }
};

static const value_string evt_comp_id[] = {
	{0x0000, "Ericsson Mobile Communications"},
	{0x0001, "Nokia Mobile Phones"},
	{0x0002, "Intel Corp."},
	{0x0003, "IBM Corp."},
	{0x0004, "Toshiba Corp."},
	{0x0005, "3Com"},
	{0x0006, "Microsoft"},
	{0x0007, "Lucent"},
	{0x0008, "Motorola"},
	{0x0009, "Infineon Technologies AG"},
	{0x000a, "Cambridge Silicon Radio"},
	{0x000b, "Silicon Wave"},
	{0x000c, "Digianswer"},
	{0xFFFF, "For use in internal and interoperability tests."},
	{0, NULL }
};

static const value_string evt_service_types[] = {
	{0x00, "No Traffic Available"},
	{0x01, "Best Effort Available"},
	{0x02, "Guaranteed Available"},
	{0, NULL }
};

static const value_string evt_role_vals[] = {
	{0x00, "Currently the Master for specified BD_ADDR"},
	{0x01, "Currently the Slave for specified BD_ADDR"},
	{0, NULL }
};

static const value_string evt_role_vals_handle[] = {
	{0x00, "Currently the Master for this connection handle"},
	{0x01, "Currently the Slave for this connection handle"},
	{0, NULL }
};

static const value_string evt_modes[] = {
	{0x00, "Active Mode"},
	{0x01, "Hold Mode"},
	{0x02, "Sniff Mode"},
	{0x03, "Park Mode"},
	{0, NULL }
};

static const value_string evt_key_types[] = {
	{0x00, "Combination Key"},
	{0x01, "Local Unit Key"},
	{0x02, "Remote Unit Key"},
	{0, NULL }
};

static const value_string evt_page_scan_modes[] = {
	{0x00, "Mandatory Page Scan Mode"},
	{0x01, "Optional Page Scan Mode I"},
	{0x02, "Optional Page Scan Mode II"},
	{0x03, "Optional Page Scan Mode III"},
	{0, NULL }
};

static const value_string evt_page_scan_repetition_modes[] = {
	{0x00, "R0"},
	{0x01, "R1"},
	{0x02, "R2"},
	{0, NULL }
};

static const value_string evt_page_scan_period_modes[] = {
	{0x00, "P0"},
	{0x01, "P1"},
	{0x02, "P2"},
	{0, NULL }
};

static const value_string evt_boolean[] = {
	{0x0 , "false" },
	{0x1 , "true" },
	{0, NULL }
};

static const value_string evt_pin_types[] = {
	{0x00, "Variable PIN" },
	{0x01, "Fixed PIN" },
	{0, NULL }
};

static const value_string evt_scan_enable_values[] = {
	{0x00, "No Scans enabled" },
	{0x01, "Inquiry Scan enabled/Page Scan disable" },
	{0x02, "Inquiry Scan disabled/Page Scan enabled" },
	{0x03, "Inquiry Scan enabled/Page Scan enabled" },
	{0, NULL }
};

static const value_string evt_auth_enable_values[] = {
	{0x00, "Disabled" },
	{0x01, "Enabled for all connections "},
	{0, NULL }
};

static const value_string evt_enable_values[] = {
	{0x00, "Disabled" },
	{0x01, "Enabled"},
	{0, NULL }
};

static const value_string evt_input_coding_values[] = {
	{0x0, "Linear" },
	{0x1, "\xb5-law" },
	{0x2, "A-law" },
	{0, NULL }
};

static const value_string evt_input_data_format_values[] = {
	{0x0, "1's complement" },
	{0x1, "2's complement" },
	{0x2, "Sign-Magnitude" },
	{0, NULL }
};

static const value_string evt_input_sample_size_values[] = {
	{0x0, "8 bit (only for Linear PCM)" },
	{0x1, "16 bit (only for Linear PCM)" },
	{0, NULL }
};

static const value_string evt_loopback_modes[] = {
	{0x00, "No Loopback mode enabled" },
	{0x01, "Enable Local Loopback" },
	{0x02, "Enable Remote Loopback" },
	{0, NULL }
};

static const value_string evt_country_code_values[] = {
	{0x0, "North America & Europe (except France) and Japan" },
	{0x1, "France" },
	{0, NULL }
};

static int 
dissect_bthci_evt_inq_complete(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE); 
	offset++;

	return offset;
}

static int 
dissect_bthci_evt_conn_complete(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
	offset++;

	proto_tree_add_item(tree, hf_bthci_evt_connection_handle, tvb, offset, 2, TRUE);
	offset+=2;

	proto_tree_add_item(tree, hf_bthci_evt_bd_addr, tvb, offset, 6, TRUE);
	offset+=6;

	proto_tree_add_item(tree, hf_bthci_evt_link_type, tvb, offset, 1, TRUE);
	offset++;

	proto_tree_add_item(tree, hf_bthci_evt_encryption_mode, tvb, offset, 1, TRUE);
	offset++;

	return offset;
}

static int 
dissect_bthci_evt_conn_request(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_bthci_evt_bd_addr, tvb, offset, 6, TRUE);
	offset+=6;

	proto_tree_add_item(tree, hf_bthci_evt_class_of_device, tvb, offset, 3, TRUE);
	offset+=3;

	proto_tree_add_item(tree, hf_bthci_evt_link_type, tvb, offset, 1, TRUE);
	offset++;

	return offset;
}

static int 
dissect_bthci_evt_disconn_complete(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
	offset++;

	proto_tree_add_item(tree, hf_bthci_evt_connection_handle, tvb, offset, 2, TRUE);
	offset+=2;

	proto_tree_add_item(tree, hf_bthci_evt_reason, tvb, offset, 1, TRUE);
	offset++;

	return offset;
}

static int 
dissect_bthci_evt_auth_complete(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
	offset++;

	proto_tree_add_item(tree, hf_bthci_evt_connection_handle, tvb, offset, 2, TRUE);
	offset+=2;

	return offset;
}

static int 
dissect_bthci_evt_lmp_features(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item *ti_lmp_features=NULL;
	proto_item *ti_lmp_subtree=NULL;

	if(tree){
		ti_lmp_features=proto_tree_add_text(tree, tvb, offset, 8, "LMP_Features");
		ti_lmp_subtree=proto_item_add_subtree(ti_lmp_features, ett_lmp_subtree);
	}
	
	proto_tree_add_item(ti_lmp_subtree,hf_bthci_evt_lmp_feature_00, tvb, offset, 1, TRUE);
	proto_tree_add_item(ti_lmp_subtree,hf_bthci_evt_lmp_feature_01, tvb, offset, 1, TRUE);
	proto_tree_add_item(ti_lmp_subtree,hf_bthci_evt_lmp_feature_02, tvb, offset, 1, TRUE);
	proto_tree_add_item(ti_lmp_subtree,hf_bthci_evt_lmp_feature_03, tvb, offset, 1, TRUE);
	proto_tree_add_item(ti_lmp_subtree,hf_bthci_evt_lmp_feature_04, tvb, offset, 1, TRUE);
	proto_tree_add_item(ti_lmp_subtree,hf_bthci_evt_lmp_feature_05, tvb, offset, 1, TRUE);
	proto_tree_add_item(ti_lmp_subtree,hf_bthci_evt_lmp_feature_06, tvb, offset, 1, TRUE);
	proto_tree_add_item(ti_lmp_subtree,hf_bthci_evt_lmp_feature_07, tvb, offset, 1, TRUE);
	offset++;

	proto_tree_add_item(ti_lmp_subtree,hf_bthci_evt_lmp_feature_10, tvb, offset, 1, TRUE);
	proto_tree_add_item(ti_lmp_subtree,hf_bthci_evt_lmp_feature_11, tvb, offset, 1, TRUE);
	proto_tree_add_item(ti_lmp_subtree,hf_bthci_evt_lmp_feature_12, tvb, offset, 1, TRUE);
	proto_tree_add_item(ti_lmp_subtree,hf_bthci_evt_lmp_feature_13, tvb, offset, 1, TRUE);
	proto_tree_add_item(ti_lmp_subtree,hf_bthci_evt_lmp_feature_14, tvb, offset, 1, TRUE);
	proto_tree_add_item(ti_lmp_subtree,hf_bthci_evt_lmp_feature_15, tvb, offset, 1, TRUE);
	proto_tree_add_item(ti_lmp_subtree,hf_bthci_evt_lmp_feature_16, tvb, offset, 1, TRUE);
	proto_tree_add_item(ti_lmp_subtree,hf_bthci_evt_lmp_feature_17, tvb, offset, 1, TRUE);
	offset++;

	proto_tree_add_item(ti_lmp_subtree,hf_bthci_evt_lmp_feature_20, tvb, offset, 1, TRUE);
	proto_tree_add_item(ti_lmp_subtree,hf_bthci_evt_lmp_feature_21, tvb, offset, 1, TRUE);
	proto_tree_add_item(ti_lmp_subtree,hf_bthci_evt_lmp_feature_22, tvb, offset, 1, TRUE);
	proto_tree_add_item(ti_lmp_subtree,hf_bthci_evt_lmp_feature_23, tvb, offset, 1, TRUE);
	proto_tree_add_item(ti_lmp_subtree,hf_bthci_evt_lmp_feature_24, tvb, offset, 1, TRUE);
	offset++;

	offset+=5;

	return offset;
}

static int 
dissect_bthci_evt_pin_code_request(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_bthci_evt_bd_addr, tvb, offset, 6, TRUE);
	offset+=6;

	return offset;
}

static int 
dissect_bthci_evt_link_key_request(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_bthci_evt_bd_addr, tvb, offset, 6, TRUE);
	offset+=6;

	return offset;
}

static int 
dissect_bthci_evt_link_key_notification(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_bthci_evt_bd_addr, tvb, offset, 6, TRUE);
	offset+=6;

	proto_tree_add_item(tree, hf_bthci_evt_link_key, tvb, offset, 16, TRUE);
	offset+=16;

	proto_tree_add_item(tree, hf_bthci_evt_key_type, tvb, offset, 1, TRUE);
	offset+=1;

	return offset;
}

static int 
dissect_bthci_evt_return_link_keys(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	guint8 evt_num_keys;

	evt_num_keys = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_bthci_evt_num_keys, tvb, offset, 1, TRUE);
	offset++;

	while(evt_num_keys--){
		proto_tree_add_item(tree, hf_bthci_evt_bd_addr, tvb, offset, 6, TRUE);
		offset+=6;

		proto_tree_add_item(tree, hf_bthci_evt_link_key, tvb, offset, 16, TRUE);
		offset+=16;

	} 

	return offset;
}

static int 
dissect_bthci_evt_read_remote_support_features_complete(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
	offset++;

	proto_tree_add_item(tree, hf_bthci_evt_connection_handle, tvb, offset, 2, TRUE);
	offset+=2;

	offset=dissect_bthci_evt_lmp_features(tvb, offset, pinfo,tree);

	return offset;
}

static int 
dissect_bthci_evt_remote_name_req_complete(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
	offset++;

	proto_tree_add_item(tree, hf_bthci_evt_bd_addr, tvb, offset, 6, TRUE);
	offset+=6;

	proto_tree_add_item(tree, hf_bthci_evt_remote_name, tvb, offset, 248, FALSE);
	offset+=248;

	return offset;
}

static int 
dissect_bthci_evt_read_remote_version_information_complete(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
	offset++;

	proto_tree_add_item(tree, hf_bthci_evt_connection_handle, tvb, offset, 2, TRUE);
	offset+=2;

	proto_tree_add_item(tree, hf_bthci_evt_vers_nr, tvb, offset, 1, TRUE);
	offset++;

	proto_tree_add_item(tree, hf_bthci_evt_comp_id, tvb, offset, 2, TRUE);
	offset+=2;

	proto_tree_add_item(tree, hf_bthci_evt_sub_vers_nr, tvb, offset, 2, TRUE);
	offset+=2;

	return offset;
}

static int 
dissect_bthci_evt_flush_occured(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_bthci_evt_connection_handle, tvb, offset, 2, TRUE);
	offset+=2;

	return offset;
}

static int 
dissect_bthci_evt_number_of_completed_packets(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	guint8 evt_num_handles;

	evt_num_handles = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_bthci_evt_num_handles, tvb, offset, 1, TRUE);
	offset++;

	while(evt_num_handles--){
		proto_tree_add_item(tree, hf_bthci_evt_connection_handle, tvb, offset, 2, TRUE);
		offset+=2;

		proto_tree_add_item(tree, hf_bthci_evt_num_compl_packets, tvb, offset, 2, TRUE);
		offset+=2;

	}  

	return offset;
}

static int 
dissect_bthci_evt_mode_change(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item *handle_item;

	proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
	offset++;

	proto_tree_add_item(tree, hf_bthci_evt_connection_handle, tvb, offset, 2, TRUE);
	offset+=2;

	proto_tree_add_item(tree, hf_bthci_evt_curr_mode, tvb, offset, 1, TRUE);
	offset++;

	handle_item = proto_tree_add_item(tree, hf_bthci_evt_interval, tvb, offset, 2, TRUE);
	proto_item_append_text(handle_item, " Baseband slots (%f msec)", tvb_get_letohs(tvb, offset)*0.625); 
	offset+=2;

	return offset;
}

static int 
dissect_bthci_evt_role_change(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
	offset++;

	proto_tree_add_item(tree, hf_bthci_evt_bd_addr, tvb, offset, 6, TRUE);
	offset+=6;

	proto_tree_add_item(tree, hf_bthci_evt_role, tvb, offset, 1, TRUE);
	offset++;

	return offset;
}

static int 
dissect_bthci_evt_hardware_error(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_bthci_evt_hardware_code, tvb, offset, 1, TRUE);
	offset++;

	return offset;
}

static int 
dissect_bthci_evt_loopback_command(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	tvbuff_t *next_tvb;

	next_tvb = tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset), -1);
	if(bthci_com_handle){
		call_dissector(bthci_com_handle, next_tvb, pinfo, tree);
	}
	offset+=tvb_length_remaining(tvb, offset);

	return offset;
}

static int 
dissect_bthci_evt_data_buffer_overflow(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_bthci_evt_link_type, tvb, offset, 1, TRUE);
	offset++;

	return offset;
}

static int 
dissect_bthci_evt_read_clock_offset_complete(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item *handle_item;
	gint16 clk;

	proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
	offset++;

	proto_tree_add_item(tree, hf_bthci_evt_connection_handle, tvb, offset, 2, TRUE);
	offset+=2;

	handle_item = proto_tree_add_item(tree, hf_bthci_evt_clock_offset, tvb, offset, 2, TRUE);
	clk=tvb_get_letohs(tvb, offset) & 32767; /* only bit0-14 are valid  */
	proto_item_append_text(handle_item, " (%g ms)", 1.25*clk);
	offset+=2;

	return offset;
}

static int 
dissect_bthci_evt_max_slots_change(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_bthci_evt_connection_handle, tvb, offset, 2, TRUE);
	offset+=2;

	proto_tree_add_item(tree, hf_bthci_evt_max_slots, tvb, offset, 1, TRUE);
	offset++;

	return offset;
}

static int 
dissect_bthci_evt_qos_violation(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_bthci_evt_connection_handle, tvb, offset, 2, TRUE);
	offset+=2;

	return offset;
}

static int 
dissect_bthci_evt_conn_packet_type_changed(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	guint16 flags;
	int flag_DM1, flag_DM3, flag_DM5, flag_DH1, flag_DH3, flag_DH5, flag_HV1, flag_HV2, flag_HV3;
	proto_tree *handle_tree=NULL;
	proto_item *ti_ptype_subtree=NULL;

	proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
	offset++;

	flags=tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_bthci_evt_connection_handle, tvb, offset, 2, TRUE);
	flag_DM1 = (flags & 0x0008) ? 1 : 0;
	flag_DH1 = (flags & 0x0010) ? 1 : 0;
	flag_DM3 = (flags & 0x0400) ? 1 : 0;
	flag_DH3 = (flags & 0x0800) ? 1 : 0;
	flag_DM5 = (flags & 0x4000) ? 1 : 0;
	flag_DH5 = (flags & 0x8000) ? 1 : 0;
	flag_HV1 = (flags & 0x0020) ? 1 : 0;
	flag_HV2 = (flags & 0x0040) ? 1 : 0;
	flag_HV3 = (flags & 0x0080) ? 1 : 0;
	offset+=2;

	handle_tree = proto_tree_add_text(tree, tvb, offset, 2, "Usable packet types: ");
	ti_ptype_subtree = proto_item_add_subtree(handle_tree, ett_ptype_subtree);

	if (flag_DM1)
		proto_item_append_text(handle_tree, "DM1 ");
	if (flag_DH1)
		proto_item_append_text(handle_tree, "DH3 ");
	if (flag_DM3)
		proto_item_append_text(handle_tree, "DM3 ");
	if (flag_DH3)
		proto_item_append_text(handle_tree, "DH3 ");
	if (flag_DM5)
		proto_item_append_text(handle_tree, "DM5 ");
	if (flag_DH5)
		proto_item_append_text(handle_tree, "DH5 ");
	if (flag_HV1)
		proto_item_append_text(handle_tree, "HV1 ");
	if (flag_HV2)
		proto_item_append_text(handle_tree, "HV2 ");
	if (flag_HV3)
		proto_item_append_text(handle_tree, "HV3 ");

	proto_tree_add_item(ti_ptype_subtree, hf_bthci_evt_link_type_dm1, tvb, offset, 2, TRUE);
	proto_tree_add_item(ti_ptype_subtree, hf_bthci_evt_link_type_dh1, tvb, offset, 2, TRUE); 
	proto_tree_add_item(ti_ptype_subtree, hf_bthci_evt_link_type_dm3, tvb, offset, 2, TRUE); 
	proto_tree_add_item(ti_ptype_subtree, hf_bthci_evt_link_type_dh3, tvb, offset, 2, TRUE); 
	proto_tree_add_item(ti_ptype_subtree, hf_bthci_evt_link_type_dm5, tvb, offset, 2, TRUE); 
	proto_tree_add_item(ti_ptype_subtree, hf_bthci_evt_link_type_dh5, tvb, offset, 2, TRUE); 
	proto_tree_add_item(ti_ptype_subtree, hf_bthci_evt_link_type_hv1, tvb, offset, 2, TRUE); 
	proto_tree_add_item(ti_ptype_subtree, hf_bthci_evt_link_type_hv2, tvb, offset, 2, TRUE); 
	proto_tree_add_item(ti_ptype_subtree, hf_bthci_evt_link_type_hv3, tvb, offset, 2, TRUE); 
	offset+=2;

	return offset;
}

static int 
dissect_bthci_evt_command_status(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
	offset++;

	proto_tree_add_item(tree, hf_bthci_evt_num_command_packets, tvb, offset, 1, TRUE);
	offset++;

	proto_tree_add_item(tree, hf_bthci_evt_com_opcode, tvb, offset, 2, TRUE);
	offset+=2;

	return offset;
}

static int 
dissect_bthci_evt_page_scan_mode_change(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_bthci_evt_bd_addr, tvb, offset, 6, TRUE);
	offset+=6;

	proto_tree_add_item(tree, hf_bthci_evt_page_scan_mode, tvb, offset, 1, TRUE);
	offset++;

	return offset;
}

static int 
dissect_bthci_evt_page_scan_repetition_mode_change(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_bthci_evt_bd_addr, tvb, offset, 6, TRUE);
	offset+=6;

	proto_tree_add_item(tree, hf_bthci_evt_page_scan_repetition_mode, tvb, offset, 1, TRUE);
	offset++;

	return offset;
}

static int 
dissect_bthci_evt_command_complete(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item *ti_opcode=NULL;
	proto_tree *opcode_tree=NULL;
	proto_item *item;
	gint16 timeout;
	guint8 num8, i;
	guint16 com_opcode;

	proto_tree_add_item(tree, hf_bthci_evt_num_command_packets, tvb, offset, 1, TRUE);
	offset++;

	com_opcode = tvb_get_letohs(tvb, offset);
	ti_opcode = proto_tree_add_item(tree, hf_bthci_evt_com_opcode, tvb, offset, 2, TRUE);
	opcode_tree = proto_item_add_subtree(ti_opcode, ett_opcode);
	proto_tree_add_item(opcode_tree, hf_bthci_evt_ogf, tvb, offset, 2, TRUE);
	proto_tree_add_item(opcode_tree, hf_bthci_evt_ocf, tvb, offset, 2, TRUE);
	offset+=2;


	switch(com_opcode) {
		/* This is a list of Commands that all return just the status */
		case 0x0402: /* Inquiry Cancel */
		case 0x0403: /* Periodic Inquiry Mode */
		case 0x0404: /* Exit Periodic Enquiry Mode */
		case 0x0c01: /* Set Event Mask */
		case 0x0c03: /* Reset */
		case 0x0c05: /* Set Event Filter */
		case 0x0c0a: /* Write PIN Type */
		case 0x0c0b: /* Create Unit Key */
		case 0x0c13: /* Change Local Name */
		case 0x0c16: /* Write Connection Accept Timeout */
		case 0x0c18: /* Write Page Timeout */
		case 0x0c1a: /* Write Scan Enable */
		case 0x0c1c: /* Write Page Scan Activity */
		case 0x0c1e: /* Write Inquiry Scan Activity */
		case 0x0c20: /* Write Authentication Enable */
		case 0x0c22: /* Write Encryption Mode  */
		case 0x0c24: /* Write Class of Device */
		case 0x0c26: /* Write Voice Setting */
		case 0x0c2a: /* Write Num Broadcast Retransmissions */
		case 0x0c2c: /* Write Hold Mode Activity */
		case 0x0c2f: /* Write SCO Flow Control Enable */
		case 0x0c31: /* Set Host Controller To Host Flow Control */
		case 0x0c33: /* Host Buffer Size */
		case 0x0c3a: /* Write Current IAC LAP */	    
		case 0x0c3c: /* Write Page Scan Period Mode */
		case 0x0c3e: /* Write Page Scan Mode */
		case 0x1802: /* Write Loopback Mode */
		case 0x1803: /* Enable Device Under Test Mode */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;
			break;

		/* This is a list of Commands that all return status and BD_ADDR */
		case 0x040b: /* Link Key Request Reply */
		case 0x040c: /* Link Key Request Negative Reply */
		case 0x040d: /* PIN Code Request Reply */
		case 0x040e: /* PIN Code Request Negative Reply */
		case 0x1009: /* Read BD_ADDR */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_bd_addr, tvb, offset, 6, TRUE);
			offset+=6;

			break;

		/* This is a list of Commands that all return status and connection_handle */
		case 0x080d: /* Write Link Policy Settings */
		case 0x0c08: /* Flush */
		case 0x0c28: /* Write Automatic Flush Timeout */
		case 0x0c37: /* Write Link Supervision Timeout */
		case 0x1402: /* Reset Failed Contact Counter */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_connection_handle, tvb, offset, 2, TRUE);
			offset+=2;

			break;

		/* This is a list of Commands that all return status and timeout */
		case 0x0c15: /* Read Connection Accept Timeout */
		case 0x0c17: /* Read Page Timeout */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			timeout = tvb_get_letohs(tvb, offset);
			item = proto_tree_add_item(tree, hf_bthci_evt_timeout, tvb, offset, 2, TRUE);
			proto_item_append_text(item, " slots (%g msec)", timeout*0.625);
			offset+=2;

			break;

		/* This is a list of Commands that all return status, connection handle and timeout */
		case 0x0c27: /* Read Automatic Flush Timeout */
		case 0x0c36: /* Read Link Supervision Timeout */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_connection_handle, tvb, offset, 2, TRUE);
			offset+=2;

			timeout = tvb_get_letohs(tvb, offset);
			item = proto_tree_add_item(tree, hf_bthci_evt_timeout, tvb, offset, 2, TRUE);
			proto_item_append_text(item, " slots (%g msec)", timeout*0.625);
			offset+=2;

			break;

		/* This is a list of Commands that all return status, interval and window */
		case 0x0c1b: /* Read Page Scan Activity */
		case 0x0c1d: /* Read Inquiry Scan Activity */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_interval, tvb, offset, 2, TRUE);
			offset+=2;

			proto_tree_add_item(tree, hf_bthci_evt_window, tvb, offset, 2, TRUE);
			offset+=2;

			break;

		case 0x0809: /* Role Discovery */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_connection_handle, tvb, offset, 2, TRUE);
			offset+=2;

			proto_tree_add_item(tree, hf_bthci_evt_curr_role, tvb, offset, 1, TRUE);
			offset++;

			break;

		case 0x080c: /* Read Link Policy Settings */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_connection_handle, tvb, offset, 2, TRUE);
			offset+=2;

			proto_tree_add_item(tree, hf_bthci_evt_link_policy_setting_switch, tvb, offset, 2, TRUE);
			proto_tree_add_item(tree, hf_bthci_evt_link_policy_setting_hold  , tvb, offset, 2, TRUE);
			proto_tree_add_item(tree, hf_bthci_evt_link_policy_setting_sniff , tvb, offset, 2, TRUE);
			proto_tree_add_item(tree, hf_bthci_evt_link_policy_setting_park  , tvb, offset, 2, TRUE);
			offset+=2;

			break;

		case 0x0c09: /* Read PIN Type */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_pin_type, tvb, offset, 1, TRUE);
			offset++;

			break;

		case 0x0c0d: /* Read Stored Link Key */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_max_num_keys, tvb, offset, 2, TRUE);
			offset+=2;

			proto_tree_add_item(tree, hf_bthci_evt_num_keys_read, tvb, offset, 2, TRUE);
			offset+=2;

			break;

		case 0x0c11: /* Write Stored Link Key */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_num_keys_written, tvb, offset, 1, TRUE);
			offset++;

			break;

		case 0x0c12: /* Delete Stored Link Key */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_num_keys_deleted, tvb, offset, 2, TRUE);
			offset+=2;

			break;

		case 0x0c14: /* Read Local Name */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_name, tvb, offset, 248, FALSE);
			offset+=248;

			break;

		case 0x0c19: /* Read Scan Enable */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_scan_enable, tvb, offset, 1, TRUE);
			offset++;

			break;

		case 0x0c1f: /* Read Authentication Enable */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_authentication_enable, tvb, offset, 1, TRUE);
			offset++;

			break;

		case 0x0c21: /* Read Encryption Mode */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_encryption_mode, tvb, offset, 1, TRUE);
			offset++;

			break;

		case 0x0c23: /* Read Class of Device */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_class_of_device, tvb, offset, 3, TRUE);
			offset+=3;

			break;

		case 0x0c25: /* Read Voice Setting */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_input_coding, tvb, offset, 2, TRUE);
			proto_tree_add_item(tree, hf_bthci_evt_input_data_format, tvb, offset, 2, TRUE);
			proto_tree_add_item(tree, hf_bthci_evt_input_sample_size, tvb, offset, 2, TRUE);
			offset+=2;

			break;

		case 0x0c29: /* Read Num Broadcast Retransmissions */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_num_broadcast_retransm, tvb, offset, 1, TRUE);
			offset++;

			break;

		case 0x0c2b: /* Read Hold Mode Activity */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_hold_mode_act_page, tvb, offset, 1, TRUE);
			proto_tree_add_item(tree, hf_bthci_evt_hold_mode_act_inquiry, tvb, offset, 1, TRUE);
			proto_tree_add_item(tree, hf_bthci_evt_hold_mode_act_periodic, tvb, offset, 1, TRUE);
			offset++;

			break;

		case 0x0c2d: /* Read Transmit Power Level */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_connection_handle, tvb, offset, 2, TRUE);
			offset+=2;

			proto_tree_add_item(tree, hf_bthci_evt_transmit_power_level, tvb, offset, 1, TRUE);
			offset++;

			break;

		case 0x0c2e: /* Read SCO Flow Control Enable */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_sco_flow_cont_enable, tvb, offset, 1, TRUE);
			offset++;

			break;


		case 0x0c38: /* Read Number of Supported IAC */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_num_supp_iac, tvb, offset, 1, TRUE);
			offset++;

			break; 

		case 0x0c39: /* Read Current IAC LAP */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			num8 = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(tree, hf_bthci_evt_num_curr_iac, tvb, offset, 1, TRUE);

			for (i=0; i<num8; i++) {
				proto_tree_add_item(tree, hf_bthci_evt_iac_lap, tvb, offset, 3, TRUE);
				offset+=3;
			}
			break;

		case 0x0c3b: /* Read Page Scan Period Mode */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_page_scan_period_mode, tvb, offset, 1, TRUE);
			offset++;

			break;

		case 0x0c3d: /* Read Page Scan Mode */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_page_scan_mode, tvb, offset, 1, TRUE);
			offset++;

			break;

		case 0x1001: /* Read Local Version Information */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_hci_vers_nr, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_hci_revision, tvb, offset, 2, TRUE);
			offset+=2;

			proto_tree_add_item(tree, hf_bthci_evt_vers_nr, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_comp_id, tvb, offset, 2, TRUE);
			offset+=2;

			proto_tree_add_item(tree, hf_bthci_evt_sub_vers_nr, tvb, offset, 2, TRUE);
			offset+=2;

			break;

		case 0x1003: /* Read Local Supported Features */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			offset=dissect_bthci_evt_lmp_features(tvb, offset, pinfo, tree);

			break;

		case 0x1005: /* Read Buffer Size */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_host_data_packet_length_acl, tvb, offset, 2, TRUE);
			offset+=2;

			proto_tree_add_item(tree, hf_bthci_evt_host_data_packet_length_sco, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_host_total_num_acl_data_packets, tvb, offset, 2, TRUE);
			offset+=2;

			proto_tree_add_item(tree, hf_bthci_evt_host_total_num_sco_data_packets, tvb, offset, 2, TRUE);
			offset+=2;

			break;

		case 0x1007: /* Read Country Code */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_country_code, tvb, offset, 1, TRUE);
			offset++;

			break;

		case 0x1401: /* Read Failed Contact Counter */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++; 

			proto_tree_add_item(tree, hf_bthci_evt_connection_handle, tvb, offset, 2, TRUE);
			offset+=2;

			proto_tree_add_item(tree, hf_bthci_evt_failed_contact_counter, tvb, offset, 2, TRUE);
			offset+=2;

			break;

		case 0x1403: /* Get Link Quality */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_connection_handle, tvb, offset, 2, TRUE);
			offset+=2;

			proto_tree_add_item(tree, hf_bthci_evt_link_quality, tvb, offset, 1, TRUE);
			offset++;

			break;

		case 0x1405: /* Read RSSI */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_connection_handle, tvb, offset, 2, TRUE);
			offset+=2;

			proto_tree_add_item(tree, hf_bthci_evt_rssi, tvb, offset, 1, TRUE);
			offset++;

			break;

		case 0x1801: /* Read Loopback Mode */
			proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(tree, hf_bthci_evt_loopback_mode, tvb, offset, 1, TRUE);
			offset++;

			break;

		default:
			proto_tree_add_item(tree, hf_bthci_evt_ret_params, tvb, offset, -1, TRUE);
			offset+=tvb_length_remaining(tvb, offset);
			break;
	}

	return offset;
}

static int 
dissect_bthci_evt_qos_setup_complete(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
	offset++;

	proto_tree_add_item(tree, hf_bthci_evt_connection_handle, tvb, offset, 2, TRUE);
	offset+=2;

	proto_tree_add_item(tree, hf_bthci_evt_flags, tvb, offset, 1, TRUE);
	offset++;

	proto_tree_add_item(tree, hf_bthci_evt_service_type, tvb, offset, 1, TRUE);
	offset++;

	proto_tree_add_item(tree, hf_bthci_evt_token_rate, tvb, offset, 4, TRUE);
	offset+=4;

	proto_tree_add_item(tree, hf_bthci_evt_peak_bandwidth, tvb, offset, 4, TRUE);
	offset+=4;

	proto_tree_add_item(tree, hf_bthci_evt_latency, tvb, offset, 4, TRUE);
	offset+=4;

	proto_tree_add_item(tree, hf_bthci_evt_delay_variation, tvb, offset, 4, TRUE);
	offset+=4;

	return offset;
}

static int 
dissect_bthci_evt_change_conn_link_key_complete(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
	offset++;

	proto_tree_add_item(tree, hf_bthci_evt_connection_handle, tvb, offset, 2, TRUE);
	offset+=2;

	return offset;
}

static int 
dissect_bthci_evt_master_link_key_complete(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
	offset++;

	proto_tree_add_item(tree, hf_bthci_evt_connection_handle, tvb, offset, 2, TRUE);
	offset+=2;

	proto_tree_add_item(tree, hf_bthci_evt_key_flag, tvb, offset, 1, TRUE);
	offset++;

	return offset;
}

static int 
dissect_bthci_evt_encryption_change(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_bthci_evt_status, tvb, offset, 1, TRUE);
	offset++;

	proto_tree_add_item(tree, hf_bthci_evt_connection_handle, tvb, offset, 2, TRUE);
	offset+=2;

	proto_tree_add_item(tree, hf_bthci_evt_encryption_enable, tvb, offset, 1, TRUE);
	offset++;

	return offset;
}

static int 
dissect_bthci_evt_inq_result(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	guint8 num, evt_num_responses;

	evt_num_responses = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_bthci_evt_num_responses, tvb, offset, 1, TRUE);
	offset++;

	for(num=0;num<evt_num_responses;num++){
		proto_tree_add_item(tree, hf_bthci_evt_bd_addr, tvb, offset, 6, TRUE);
		offset+=6;

		proto_tree_add_item(tree, hf_bthci_evt_page_scan_repetition_mode, tvb, offset, 1, TRUE);
		offset++;

		proto_tree_add_item(tree, hf_bthci_evt_page_scan_period_mode, tvb, offset, 1, TRUE);
		offset++;

		proto_tree_add_item(tree, hf_bthci_evt_page_scan_mode, tvb, offset, 1, TRUE);
		offset++;

		proto_tree_add_item(tree, hf_bthci_evt_class_of_device, tvb, offset, 3, TRUE);
		offset+=3;

		proto_tree_add_item(tree, hf_bthci_evt_clock_offset, tvb, offset, 2, TRUE);
		offset+=2;
	}

	return offset;
}


/* Code to actually dissect the packets */
static void 
dissect_bthci_evt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *bthci_evt_tree=NULL;
	guint8 param_length, evt_code;
	int offset=0;

	if(tree){
		ti=proto_tree_add_item(tree, proto_bthci_evt, tvb, offset, -1, FALSE);
		bthci_evt_tree=proto_item_add_subtree(ti, ett_bthci_evt);
	}

	evt_code = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(bthci_evt_tree, hf_bthci_evt_code, tvb, offset, 1, TRUE);
	proto_item_append_text(bthci_evt_tree, " - %s", val_to_str(evt_code, evt_code_vals, "Unknown 0x%08x"));
	offset++;

	param_length = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(bthci_evt_tree, hf_bthci_evt_param_length, tvb, offset, 1, TRUE);
	offset++;


	if(check_col(pinfo->cinfo, COL_PROTOCOL)){
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "HCI_EVT");
	}

	if((check_col(pinfo->cinfo, COL_INFO))){
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(evt_code, evt_code_vals, "Unknown 0x%08x"));
	}


	if (param_length > 0) {
		switch(evt_code) {
		case 0x01: /* Inquiry Complete */
			offset=dissect_bthci_evt_inq_complete(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x02: /* Inquiry result event  */
			offset=dissect_bthci_evt_inq_result(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x03: /* Connection Complete */
			offset=dissect_bthci_evt_conn_complete(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x04: /* Connection Request */
			offset=dissect_bthci_evt_conn_request(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x05: /* Disconnection Complete */
			offset=dissect_bthci_evt_disconn_complete(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x06: /* Authentication Complete */
			offset=dissect_bthci_evt_auth_complete(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x07: /* Remote Name Request Complete */
			offset=dissect_bthci_evt_remote_name_req_complete(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x08: /* Encryption Change */
			offset=dissect_bthci_evt_encryption_change(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x09: /* Change Connection Link Key Complete */
			offset=dissect_bthci_evt_change_conn_link_key_complete(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x0a: /* Master Link Key Complete */
			offset=dissect_bthci_evt_master_link_key_complete(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x0b: /* Read Remote Support Features Complete */
			offset=dissect_bthci_evt_read_remote_support_features_complete(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x0c: /* Read Remote Version Information Complete */
			offset=dissect_bthci_evt_read_remote_version_information_complete(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x0d: /* QoS Setup Complete */
			offset=dissect_bthci_evt_qos_setup_complete(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x0e: /* Command Complete */
			offset=dissect_bthci_evt_command_complete(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x0f: /* Command Status */
			offset=dissect_bthci_evt_command_status(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x10: /* Hardware Error */
			offset=dissect_bthci_evt_hardware_error(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x11: /* Flush Occurred */
			offset=dissect_bthci_evt_flush_occured(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x12: /* Role Change */
			offset=dissect_bthci_evt_role_change(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x13: /* Number Of Completed Packets */ 
			offset=dissect_bthci_evt_number_of_completed_packets(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x14: /* Mode Change */
			offset=dissect_bthci_evt_mode_change(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x15: /* Return Link Keys */
			offset=dissect_bthci_evt_return_link_keys(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x16: /* PIN Code Request */
			offset=dissect_bthci_evt_pin_code_request(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x17: /* Link Key Request */
			offset=dissect_bthci_evt_link_key_request(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x18: /* Link Key Notification */
			offset=dissect_bthci_evt_link_key_notification(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x19: /* Loopback Command */
			offset=dissect_bthci_evt_loopback_command(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x1a: /* Data Buffer Overflow */
			offset=dissect_bthci_evt_data_buffer_overflow(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x1b: /* Max Slots Change */
			offset=dissect_bthci_evt_max_slots_change(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x1c: /* Read Clock Offset Complete */
			offset=dissect_bthci_evt_read_clock_offset_complete(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x1d: /* Connection Packet Type Changed */
			offset=dissect_bthci_evt_conn_packet_type_changed(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x1e: /* QoS Violation */
			offset=dissect_bthci_evt_qos_violation(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x1f: /* Page Scan Mode Change */
			offset=dissect_bthci_evt_page_scan_mode_change(tvb, offset, pinfo, bthci_evt_tree);
			break;

		case 0x20: /*Page Scan Repetition Mode Change */
			offset=dissect_bthci_evt_page_scan_repetition_mode_change(tvb, offset, pinfo, bthci_evt_tree);
			break;

		default:
			proto_tree_add_item(bthci_evt_tree, hf_bthci_evt_params, tvb, 2, -1, TRUE);    
			break;
		}

	}
}


/* Register the protocol with Ethereal */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
   */

void
proto_register_bthci_evt(void)
{                 

	/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_bthci_evt_code,
			{ "Event Code",           "bthci_evt.code",
				FT_UINT8, BASE_HEX, VALS(evt_code_vals), 0x0,          
				"Event Code", HFILL }
		},
		{ &hf_bthci_evt_param_length,
			{ "Parameter Total Length",           "bthci_evt.param_length",
				FT_UINT8, BASE_DEC, NULL, 0x0,          
				"Parameter Total Length", HFILL }
		},
		{ &hf_bthci_evt_params,
			{ "Event Parameter",           "bthci_evt.params",
				FT_NONE, BASE_NONE, NULL, 0x0,          
				"Event Parameter", HFILL }
		},
		{ &hf_bthci_evt_num_command_packets,
			{ "Number of Allowed Command Packets",           "bthci_evt.num_command_packets",
				FT_UINT8, BASE_DEC, NULL, 0x0,          
				"Number of Allowed Command Packets", HFILL }
		},
		{ &hf_bthci_evt_num_handles,
			{ "Number of Connection Handles",           "bthci_evt.num_handles",
				FT_UINT8, BASE_DEC, NULL, 0x0,          
				"Number of Connection Handles and Num_HCI_Data_Packets parameter pairs", HFILL }
		},
		{ &hf_bthci_evt_connection_handle,
			{ "Connection Handle",             "bthci_evt.connection_handle",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				"Connection Handle", HFILL }
		},

		{ &hf_bthci_evt_num_compl_packets,
			{ "Number of Completed Packets",        "bthci_evt.num_compl_packets",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				"The number of HCI Data Packets that have been completed", HFILL }
		},

		{ &hf_bthci_evt_com_opcode,
			{ "Command Opcode",           "bthci_evt.com_opcode",
				FT_UINT16, BASE_HEX, VALS(bthci_cmd_opcode_vals), 0x0,          
				"Command Opcode", HFILL }
		},
		{ &hf_bthci_evt_ogf,
			{ "ogf",           "bthci_evt.ogf",
				FT_UINT16, BASE_HEX, VALS(bthci_ogf_vals), 0xfc00,          
				"Opcode Group Field", HFILL }
		},
		{ &hf_bthci_evt_ocf,
			{ "ocf",           "bthci_evt.ocf",
				FT_UINT16, BASE_HEX, NULL, 0x03ff,          
				"Opcode Command Field", HFILL }
		},
		{ &hf_bthci_evt_ret_params,
			{ "Return Parameter",           "bthci_evt.ret_params",
				FT_NONE, BASE_NONE, NULL, 0x0,          
				"Return Parameter", HFILL }
		},
		{ &hf_bthci_evt_status,
			{ "Status",           "bthci_evt.status",
				FT_UINT8, BASE_HEX, VALS(evt_status_vals), 0x0,          
				"Status", HFILL }
		},
		{ &hf_bthci_evt_bd_addr,
			{ "BD_ADDR",          "bthci_evt.bd_addr",
				FT_ETHER, BASE_HEX, NULL, 0x0,
				"Bluetooth Device Address", HFILL}
		},
		{ &hf_bthci_evt_link_type,
			{ "Link Type",        "bthci_evt.link_type",
				FT_UINT8, BASE_HEX, VALS(evt_link_types), 0x0,
				"Link Type", HFILL }
		},
		{ &hf_bthci_evt_encryption_mode,
			{ "Encryption Mode",  "bthci_evt.encryption_mode",
				FT_UINT8, BASE_HEX, VALS(evt_encryption_modes), 0x0,
				"Encryption Mode", HFILL }
		},
		{ &hf_bthci_evt_class_of_device,
			{ "Class of Device",  "bthci_evt.class_of_device",
				FT_INT24, BASE_HEX, NULL, 0x0,
				"Class of Device for the Device, which requested the connection", HFILL}
		},
		{ &hf_bthci_evt_reason,
			{ "Reason",           "bthci_evt.reason",
				FT_UINT8, BASE_HEX, VALS(evt_status_vals), 0x0,          
				"Reason", HFILL }
		},
		{ &hf_bthci_evt_remote_name,
			{ "Remote Name",           "bthci_evt.remote_name",
				FT_STRINGZ, BASE_NONE, NULL, 0x0,          
				"Userfriendly descriptive name for the remote device", HFILL }
		},
		{ &hf_bthci_evt_encryption_enable,
			{ "Encryption Enable",        "bthci_evt.encryption_enable",
				FT_UINT8, BASE_HEX, VALS(evt_encryption_enable), 0x0,
				"Encryption Enable", HFILL }
		},
		{ &hf_bthci_evt_key_flag,
			{ "Key Flag",        "bthci_evt.key_flag",
				FT_UINT8, BASE_HEX, VALS(evt_key_flag), 0x0,
				"Key Flag", HFILL }
		},
		{ &hf_bthci_evt_vers_nr,
			{ "LMP Version",        "bthci_evt.lmp_vers_nr",
				FT_UINT8, BASE_HEX, VALS(evt_lmp_vers_nr), 0x0,
				"Version of the Current LMP", HFILL }
		},
		{ &hf_bthci_evt_hci_vers_nr,
			{ "HCI Version",        "bthci_evt.hci_vers_nr",
				FT_UINT8, BASE_HEX, VALS(evt_hci_vers_nr), 0x0,
				"Version of the Current HCI", HFILL }
		},
		{ &hf_bthci_evt_hci_revision,
			{ "HCI Revision",        "bthci_evt.hci_vers_nr",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				"Revision of the Current HCI", HFILL }
		},
		{ &hf_bthci_evt_comp_id,
			{ "Manufacturer Name",        "bthci_evt.comp_id",
				FT_UINT16, BASE_HEX, VALS(evt_comp_id), 0x0,
				"Manufacturer Name of Bluetooth Hardware", HFILL }
		},
		{ &hf_bthci_evt_sub_vers_nr,
			{ "LMP Subversion",        "bthci_evt.lmp_sub_vers_nr",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				"Subversion of the Current LMP", HFILL }
		},
		{ &hf_bthci_evt_flags,
			{ "Flags",        "bthci_evt.flags",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				"Flags", HFILL }
		},
		{ &hf_bthci_evt_service_type,
			{ "Service Type",        "bthci_evt.service_type",
				FT_UINT8, BASE_HEX, VALS(evt_service_types), 0x0,
				"Service Type", HFILL }
		},
		{ &hf_bthci_evt_token_rate,
			{ "Available Token Rate",        "bthci_evt.token_rate",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				"Available Token Rate, in bytes per second", HFILL }
		},
		{ &hf_bthci_evt_peak_bandwidth,
			{ "Available Peak Bandwidth",        "bthci_evt.peak_bandwidth",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				"Available Peak Bandwidth, in bytes per second", HFILL }
		},
		{ &hf_bthci_evt_latency,
			{ "Available Latecy",        "bthci_evt.latency",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				"Available Latency, in microseconds", HFILL }
		},
		{ &hf_bthci_evt_delay_variation,
			{ "Available Delay Variation",        "bthci_evt.delay_variation",
				FT_UINT32, BASE_DEC, NULL, 0x0,
				"Available Delay Variation, in microseconds", HFILL }
		},
		{ &hf_bthci_evt_hardware_code,
			{ "Hardware Code",        "bthci_evt.hardware_code",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				"Hardware Code (implementation specific)", HFILL }
		},
		{ &hf_bthci_evt_role,
			{ "Role",        "bthci_evt.role",
				FT_UINT8, BASE_HEX, VALS(evt_role_vals), 0x0,
				"Role", HFILL }
		},
		{ &hf_bthci_evt_curr_mode,
			{ "Current Mode",        "bthci_evt.current_mode",
				FT_UINT8, BASE_HEX, VALS(evt_modes), 0x0,
				"Current Mode", HFILL }
		},
		{ &hf_bthci_evt_interval,
			{ "Interval",        "bthci_evt.interval",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				"Interval - Number of Baseband slots", HFILL }
		},
		{ &hf_bthci_evt_link_key,
			{ "Link Key",        "bthci_evt.link_key",
				FT_BYTES, BASE_HEX, NULL, 0x0,
				"Link Key for the associated BD_ADDR", HFILL }
		},
		{ &hf_bthci_evt_key_type,
			{ "Key Type",        "bthci_evt.key_type",
				FT_UINT8, BASE_HEX, VALS(evt_key_types), 0x0,
				"Key Type", HFILL }
		},
		{ &hf_bthci_evt_max_slots,
			{ "Maximum Number of Slots",        "bthci_evt.max_slots",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				"Maximum Number of slots allowed for baseband packets", HFILL }
		},
		{ &hf_bthci_evt_clock_offset,
			{ "Clock Offset",        "bthci_evt.clock_offset",
				FT_UINT16, BASE_HEX, NULL, 0x7FFF,
				"Bit 2-16 of the Clock Offset between CLKmaster-CLKslave", HFILL }
		},
		{ &hf_bthci_evt_page_scan_mode,
			{ "Page Scan Mode",        "bthci_evt.page_scan_mode",
				FT_UINT8, BASE_HEX, VALS(evt_page_scan_modes), 0x0,
				"Page Scan Mode", HFILL }
		},
		{ &hf_bthci_evt_page_scan_repetition_mode,
			{ "Page Scan Repetition Mode",        "bthci_evt.page_scan_repetition_mode",
				FT_UINT8, BASE_HEX, VALS(evt_page_scan_repetition_modes), 0x0,
				"Page Scan Repetition Mode", HFILL }
		},
		{ &hf_bthci_evt_page_scan_period_mode,
			{ "Page Scan Period Mode",        "bthci_evt.page_scan_period_mode",
				FT_UINT8, BASE_HEX, VALS(evt_page_scan_period_modes), 0x0,
				"Page Scan Period Mode", HFILL }
		},
		{ &hf_bthci_evt_link_type_dm1,
			{ "ACL Link Type DM1",        "bthci_evt.link_type_dm1",
				FT_UINT16, BASE_DEC, VALS(evt_boolean), 0x0008,
				"ACL Link Type DM1", HFILL }
		},
		{ &hf_bthci_evt_link_type_dh1,
			{ "ACL Link Type DH1",        "bthci_evt.link_type_dh1",
				FT_UINT16, BASE_DEC, VALS(evt_boolean), 0x0010,
				"ACL Link Type DH1", HFILL }
		},
		{ &hf_bthci_evt_link_type_dm3,
			{ "ACL Link Type DM3",        "bthci_evt.link_type_dm3",
				FT_UINT16, BASE_DEC, VALS(evt_boolean), 0x0400,
				"ACL Link Type DM3", HFILL }
		},
		{ &hf_bthci_evt_link_type_dh3,
			{ "ACL Link Type DH3",        "bthci_evt.link_type_dh3",
				FT_UINT16, BASE_DEC, VALS(evt_boolean), 0x0800,
				"ACL Link Type DH3", HFILL }
		},
		{ &hf_bthci_evt_link_type_dm5,
			{ "ACL Link Type DM5",        "bthci_evt.link_type_dm5",
				FT_UINT16, BASE_DEC, VALS(evt_boolean), 0x4000,
				"ACL Link Type DM5", HFILL }
		},
		{ &hf_bthci_evt_link_type_dh5,
			{ "ACL Link Type DH5",        "bthci_evt.link_type_dh5",
				FT_UINT16, BASE_DEC, VALS(evt_boolean), 0x8000,
				"ACL Link Type DH5", HFILL }
		},
		{ &hf_bthci_evt_link_type_hv1,
			{ "SCO Link Type HV1",        "bthci_evt.link_type_hv1",
				FT_UINT16, BASE_DEC, VALS(evt_boolean), 0x0020,
				"SCO Link Type HV1", HFILL }
		},
		{ &hf_bthci_evt_link_type_hv2,
			{ "SCO Link Type HV2",        "bthci_evt.link_type_hv2",
				FT_UINT16, BASE_DEC, VALS(evt_boolean), 0x0040,
				"SCO Link Type HV2", HFILL }
		},
		{ &hf_bthci_evt_link_type_hv3,
			{ "SCO Link Type HV3",        "bthci_evt.link_type_hv3",
				FT_UINT16, BASE_DEC, VALS(evt_boolean), 0x0080,
				"SCO Link Type HV3", HFILL }
		},
		{ &hf_bthci_evt_lmp_feature_00,
			{ "3-slot packets",        "bthci_evt.lmp_feature",
				FT_UINT8, BASE_DEC, VALS(evt_boolean), 0x01,
				"3-slot packets", HFILL }
		},
		{ &hf_bthci_evt_lmp_feature_01,
			{ "5-slot packets",        "bthci_evt.lmp_feature",
				FT_UINT8, BASE_DEC, VALS(evt_boolean), 0x02,
				"5-slot packets", HFILL }
		},
		{ &hf_bthci_evt_lmp_feature_02,
			{ "encryption",        "bthci_evt.lmp_feature",
				FT_UINT8, BASE_DEC, VALS(evt_boolean), 0x04,
				"encryption", HFILL }
		},
		{ &hf_bthci_evt_lmp_feature_03,
			{ "slot offset",        "bthci_evt.lmp_feature",
				FT_UINT8, BASE_DEC, VALS(evt_boolean), 0x08,
				"slot offset", HFILL }
		},
		{ &hf_bthci_evt_lmp_feature_04,
			{ "timing accuracy",        "bthci_evt.lmp_feature",
				FT_UINT8, BASE_DEC, VALS(evt_boolean), 0x10,
				"timing accuracy", HFILL }
		},
		{ &hf_bthci_evt_lmp_feature_05,
			{ "switch",        "bthci_evt.lmp_feature",
				FT_UINT8, BASE_DEC, VALS(evt_boolean), 0x20,
				"switch", HFILL }
		},
		{ &hf_bthci_evt_lmp_feature_06,
			{ "hold mode",        "bthci_evt.lmp_feature",
				FT_UINT8, BASE_DEC, VALS(evt_boolean), 0x40,
				"hold mode", HFILL }
		},
		{ &hf_bthci_evt_lmp_feature_07,
			{ "sniff mode",        "bthci_evt.lmp_feature",
				FT_UINT8, BASE_DEC, VALS(evt_boolean), 0x80,
				"sniff mode", HFILL }
		},
		{ &hf_bthci_evt_lmp_feature_10,
			{ "park mode",        "bthci_evt.lmp_feature",
				FT_UINT8, BASE_DEC, VALS(evt_boolean), 0x01,
				"park mode", HFILL }
		},
		{ &hf_bthci_evt_lmp_feature_11,
			{ "RSSI",        "bthci_evt.lmp_feature",
				FT_UINT8, BASE_DEC, VALS(evt_boolean), 0x02,
				"RSSI", HFILL }
		},
		{ &hf_bthci_evt_lmp_feature_12,
			{ "channel quality driven data rate",        "bthci_evt.lmp_feature",
				FT_UINT8, BASE_DEC, VALS(evt_boolean), 0x04,
				"channel quality driven data rate", HFILL }
		},
		{ &hf_bthci_evt_lmp_feature_13,
			{ "SCO link",        "bthci_evt.lmp_feature",
				FT_UINT8, BASE_DEC, VALS(evt_boolean), 0x08,
				"SCO link", HFILL }
		},
		{ &hf_bthci_evt_lmp_feature_14,
			{ "HV2 packets",        "bthci_evt.lmp_feature",
				FT_UINT8, BASE_DEC, VALS(evt_boolean), 0x10,
				"HV2 packets", HFILL }
		},
		{ &hf_bthci_evt_lmp_feature_15,
			{ "HV3 packets",        "bthci_evt.lmp_feature",
				FT_UINT8, BASE_DEC, VALS(evt_boolean), 0x20,
				"HV3 packets", HFILL }
		},
		{ &hf_bthci_evt_lmp_feature_16,
			{ "u-law log",        "bthci_evt.lmp_feature",
				FT_UINT8, BASE_DEC, VALS(evt_boolean), 0x40,
				"u-law log", HFILL }
		},
		{ &hf_bthci_evt_lmp_feature_17,
			{ "A-law log",        "bthci_evt.lmp_feature",
				FT_UINT8, BASE_DEC, VALS(evt_boolean), 0x80,
				"A-law log", HFILL }
		},
		{ &hf_bthci_evt_lmp_feature_20,
			{ "CVSD",        "bthci_evt.lmp_feature",
				FT_UINT8, BASE_DEC, VALS(evt_boolean), 0x01,
				"CVSD", HFILL }
		},
		{ &hf_bthci_evt_lmp_feature_21,
			{ "paging scheme",        "bthci_evt.lmp_feature",
				FT_UINT8, BASE_DEC, VALS(evt_boolean), 0x02,
				"paging scheme", HFILL }
		},
		{ &hf_bthci_evt_lmp_feature_22,
			{ "power control",        "bthci_evt.lmp_feature",
				FT_UINT8, BASE_DEC, VALS(evt_boolean), 0x04,
				"power control", HFILL }
		},
		{ &hf_bthci_evt_lmp_feature_23,
			{ "transparent SCO data",        "bthci_evt.lmp_feature",
				FT_UINT8, BASE_DEC, VALS(evt_boolean), 0x08,
				"transparent SCO data", HFILL }
		},
		{ &hf_bthci_evt_lmp_feature_24,
			{ "Flow control lag",        "bthci_evt.lmp_feature",
				FT_UINT8, BASE_DEC, VALS(evt_boolean), 0x70,
				"Flow control lag", HFILL }
		},
		{ &hf_bthci_evt_num_keys,
			{ "Number of Link Keys",        "bthci_evt.num_keys",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				"Number of Link Keys contained", HFILL }
		},
		{ &hf_bthci_evt_num_keys_read,
			{ "Number of Link Keys Read",        "bthci_evt.num_keys_read",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				"Number of Link Keys Read", HFILL }
		},
		{ &hf_bthci_evt_num_keys_deleted,
			{ "Number of Link Keys Deleted",        "bthci_evt.num_keys_deleted",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				"Number of Link Keys Deleted", HFILL }
		},
		{ &hf_bthci_evt_num_keys_written,
			{ "Number of Link Keys Written",        "bthci_evt.num_keys_written",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				"Number of Link Keys Written", HFILL }
		},
		{ &hf_bthci_evt_max_num_keys,
			{ "Max Num Keys",        "bthci_evt.max_num_keys",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				"Total Number of Link Keys that the Host Controller can store", HFILL }
		},
		{ &hf_bthci_evt_num_responses,
			{ "Number of responses",        "bthci_evt.num_responses",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				"Number of Responses from Inquiry ", HFILL }
		},
		{ &hf_bthci_evt_link_policy_setting_switch,
			{ "Enable Master Slave Switch", "bthci_evt.link_policy_switch",
				FT_UINT16, BASE_DEC, VALS(evt_boolean), 0x0001,
				"Enable Master Slave Switch", HFILL }
		}, 
		{ &hf_bthci_evt_link_policy_setting_hold,
			{ "Enable Hold Mode", "bthci_evt.link_policy_hold",
				FT_UINT16, BASE_DEC, VALS(evt_boolean), 0x0002,
				"Enable Hold Mode", HFILL }
		},
		{ &hf_bthci_evt_link_policy_setting_sniff,
			{ "Enable Sniff Mode", "bthci_evt.link_policy_sniff",
				FT_UINT16, BASE_DEC, VALS(evt_boolean), 0x0004,
				"Enable Sniff Mode", HFILL }
		},
		{ &hf_bthci_evt_link_policy_setting_park,
			{ "Enable Park Mode", "bthci_evt.link_policy_park",
				FT_UINT16, BASE_DEC, VALS(evt_boolean), 0x0008,
				"Enable Park Mode", HFILL }
		},
		{ &hf_bthci_evt_curr_role,
			{ "Current Role", "bthci_evt_curr_role",
				FT_UINT8, BASE_HEX, VALS(evt_role_vals_handle), 0x0,
				"Current role for this connection handle", HFILL }
		},
		{ &hf_bthci_evt_pin_type,
			{ "PIN Type", "bthci_evt.pin_type",
				FT_UINT8, BASE_HEX, VALS(evt_pin_types), 0x0,
				"PIN Types", HFILL }
		},
		{ &hf_bthci_evt_name,
			{ "Name",           "bthci_evt.local_name",
				FT_STRINGZ, BASE_NONE, NULL, 0x0,          
				"Userfriendly descriptive name for the device", HFILL }
		},
		{ &hf_bthci_evt_timeout,
			{ "Timeout",        "bthci_evt.timeout",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				"Number of Baseband slots for timeout.", HFILL }
		},
		{ &hf_bthci_evt_scan_enable,
			{ "Scan", "bthci_evt.scan_enable",
				FT_UINT8, BASE_HEX, VALS(evt_scan_enable_values), 0x0,
				"Scan Enable", HFILL }
		},
		{ &hf_bthci_evt_authentication_enable,
			{ "Authentication", "bthci_evt.auth_enable",
				FT_UINT8, BASE_HEX, VALS(evt_auth_enable_values), 0x0,
				"Authentication Enable", HFILL }
		},
		{ &hf_bthci_evt_sco_flow_cont_enable,
			{ "SCO Flow Control", "bthci_evt.sco_flow_cont_enable",
				FT_UINT8, BASE_HEX, VALS(evt_enable_values), 0x0,
				"SCO Flow Control Enable", HFILL }
		},
		{ &hf_bthci_evt_window,
			{ "Interval", "bthci_evt.window",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				"Window", HFILL }
		},
		{ &hf_bthci_evt_input_coding,
			{ "Input Coding", "bthci_evt.input_coding",
				FT_UINT16, BASE_DEC, VALS(evt_input_coding_values), 0x0300,
				"Authentication Enable", HFILL }
		},
		{ &hf_bthci_evt_input_data_format,
			{ "Input Data Format", "bthci_evt.input_data_format",
				FT_UINT16, BASE_DEC, VALS(evt_input_data_format_values), 0x00c0,
				"Input Data Format", HFILL }
		},  
		{ &hf_bthci_evt_input_sample_size,
			{ "Input Sample Size", "bthci_evt.input_sample_size",
				FT_UINT16, BASE_DEC, VALS(evt_input_sample_size_values), 0x0020,
				"Input Sample Size", HFILL }
		}, 
		{ &hf_bthci_evt_num_broadcast_retransm,
			{ "Num Broadcast Retran", "bthci_evt.num_broad_retran",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				"Number of Broadcast Retransmissions", HFILL }
		},
		{ &hf_bthci_evt_hold_mode_act_page,
			{ "Suspend Page Scan", "bthci_evt.hold_mode_page",
				FT_UINT8, BASE_DEC, VALS(evt_boolean), 0x1,
				"Device can enter low power state", HFILL }
		},
		{ &hf_bthci_evt_hold_mode_act_inquiry,
			{ "Suspend Inquiry Scan", "bthci_evt.hold_mode_inquiry",
				FT_UINT8, BASE_DEC, VALS(evt_boolean), 0x2,
				"Device can enter low power state", HFILL }
		},
		{ &hf_bthci_evt_hold_mode_act_periodic,
			{ "Suspend Periodic Inquiries", "bthci_evt.hold_mode_periodic",
				FT_UINT8, BASE_DEC, VALS(evt_boolean), 0x4,
				"Device can enter low power state", HFILL }
		},
		{ &hf_bthci_evt_transmit_power_level,
			{ "Transmit Power Level (dBm)", "bthci_evt.transmit_power_level",
				FT_INT8, BASE_DEC, NULL, 0x0,
				"Transmit Power Level (dBm)", HFILL }
		},
		{ &hf_bthci_evt_num_supp_iac,
			{" Num Support IAC", "bthci_evt.num_supp_iac",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				"Num of supported IAC the device can simultaneously listen", HFILL }
		},
		{ &hf_bthci_evt_num_curr_iac,
			{" Num Current IAC", "bthci_evt.num_curr_iac",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				"Num of IACs currently in use to simultaneously listen", HFILL }
		},
		{ &hf_bthci_evt_iac_lap,
			{ "IAC LAP", "bthci_evt.num_curr_iac",
				FT_UINT24, BASE_HEX, NULL, 0x0,
				"LAP(s)used to create IAC", HFILL }
		},
		{ &hf_bthci_evt_loopback_mode,
			{"Loopback Mode", "bthci_evt.loopback_mode",
				FT_UINT8, BASE_HEX, VALS(evt_loopback_modes), 0x0,
				"Loopback Mode", HFILL }
		},
		{ &hf_bthci_evt_country_code,
			{"Country Code", "bthci_evt.country_code",
				FT_UINT8, BASE_HEX, VALS(evt_country_code_values), 0x0,
				"Country Code", HFILL }
		},
		{ &hf_bthci_evt_failed_contact_counter,
			{"Failed Contact Counter", "bthci_evt.failed_contact_counter",
				FT_UINT16, BASE_DEC, NULL, 0x0,  
				"Failed Contact Counter", HFILL }
		},   
		{ &hf_bthci_evt_link_quality,
			{"Link Quality", "bthci_evt.link_quality",
				FT_UINT8, BASE_DEC, NULL, 0x0,  
				"Link Quality (0x00 - 0xFF Higher Value = Better Link)", HFILL }
		},
		{ &hf_bthci_evt_rssi,
			{ "RSSI (dB)", "bthci_evt.rssi",
				FT_INT8, BASE_DEC, NULL, 0x0,
				"RSSI (dB)", HFILL }
		},
		{ &hf_bthci_evt_host_data_packet_length_acl,
			{"Host ACL Data Packet Length (bytes)", "bthci_evt.max_data_length_acl",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				"Max Host ACL Data Packet length of data portion host is able to accept", HFILL }
		}, 
		{ &hf_bthci_evt_host_data_packet_length_sco,
			{"Host SCO Data Packet Length (bytes)", "bthci_evt.max_data_length_sco",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				"Max Host SCO Data Packet length of data portion host is able to accept", HFILL }
		}, 
		{ &hf_bthci_evt_host_total_num_acl_data_packets,
			{"Host Total Num ACL Data Packets", "bthci_evt.max_data_num_acl",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				"Total Number of HCI ACL Data Packets that can be stored in the data buffers of the Host", HFILL }
		}, 
		{ &hf_bthci_evt_host_total_num_sco_data_packets,
			{"Host Total Num SCO Data Packets", "bthci_evt.max_data_num_sco",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				"Total Number of HCI SCO Data Packets that can be stored in the data buffers of the Host", HFILL }
		}, 
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_bthci_evt,
		&ett_opcode,
		&ett_lmp_subtree,
		&ett_ptype_subtree,
	};

	/* Register the protocol name and description */
	proto_bthci_evt = proto_register_protocol("Bluetooth HCI Event",
			"HCI_EVT", "bthci_evt");

	register_dissector("bthci_evt", dissect_bthci_evt, proto_bthci_evt);



	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_bthci_evt, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
   */
void
proto_reg_handoff_bthci_evt(void)
{
	dissector_handle_t bthci_evt_handle;

	bthci_evt_handle = find_dissector("bthci_evt");
	dissector_add("hci_h4.type", HCI_H4_TYPE_EVT, bthci_evt_handle);

	bthci_com_handle = find_dissector("bthci_cmd");
}


