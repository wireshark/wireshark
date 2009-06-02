/* packet-capwap.c
 * Routines for CAPWAP dissection (RFC 5415)
 * Copyright 2009,  Alexis La Goutte <alexis.lagoutte at gmail dot com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <epan/packet.h>
#include <epan/prefs.h>

#include <epan/sminmpec.h>

#define UDP_PORT_CAPWAP_CONTROL 5246
#define UDP_PORT_CAPWAP_DATA 5247

static guint global_capwap_control_udp_port = UDP_PORT_CAPWAP_CONTROL;
static guint global_capwap_data_udp_port = UDP_PORT_CAPWAP_DATA;



/* TODO LIST !
* add support of optional Header (Radio Mac/Wireless Specific Information : Section 4.3)
* add dencryption of DLTS Message
* add Support of All Messages Element Type
*/

/* Forward declaration we need below */
void proto_reg_handoff_capwap(void);

/* Initialize the protocol and registered fields */
static int proto_capwap = -1;

static int hf_capwap_preamble = -1;
static int hf_capwap_preamble_version = -1;
static int hf_capwap_preamble_type = -1;
static int hf_capwap_preamble_reserved = -1;

static int hf_capwap_header = -1;
static int hf_capwap_header_hlen = -1;
static int hf_capwap_header_rid = -1;
static int hf_capwap_header_wbid = -1;

static int hf_capwap_header_flags = -1;
static int hf_capwap_header_flags_t = -1;
static int hf_capwap_header_flags_f = -1;
static int hf_capwap_header_flags_l = -1;
static int hf_capwap_header_flags_w = -1;
static int hf_capwap_header_flags_m = -1;
static int hf_capwap_header_flags_k = -1;
static int hf_capwap_header_flags_r = -1;

static int hf_capwap_header_fragment_id = -1;
static int hf_capwap_header_fragment_offset = -1;
static int hf_capwap_header_reserved = -1;

static int hf_capwap_control_header = -1;
static int hf_capwap_control_header_msg_type = -1;
static int hf_capwap_control_header_msg_type_enterprise_nbr = -1;
static int hf_capwap_control_header_msg_type_enterprise_specific = -1;
static int hf_capwap_control_header_seq_number = -1;
static int hf_capwap_control_header_flags = -1;
static int hf_capwap_control_header_msg_element_length = -1;

static int hf_capwap_message_element = -1;
static int hf_capwap_msg_element_type = -1;
static int hf_capwap_msg_element_length = -1;
static int hf_capwap_msg_element_value = -1;

static int hf_capwap_msg_element_type_ac_descriptor_stations = -1;
static int hf_capwap_msg_element_type_ac_descriptor_limit = -1;
static int hf_capwap_msg_element_type_ac_descriptor_active_wtp = -1;
static int hf_capwap_msg_element_type_ac_descriptor_max_wtp = -1;

/* AC Descriptor Security Flags... */
static int hf_capwap_msg_element_type_ac_descriptor_security = -1;
static int hf_capwap_msg_element_type_ac_descriptor_security_s = -1;
static int hf_capwap_msg_element_type_ac_descriptor_security_x = -1;
static int hf_capwap_msg_element_type_ac_descriptor_security_r = -1;
static int hf_capwap_msg_element_type_ac_descriptor_rmac_field = -1;
static int hf_capwap_msg_element_type_ac_descriptor_reserved = -1;

/* AC Descriptor DTLS Policy Flags... */
static int hf_capwap_msg_element_type_ac_descriptor_dtls_policy = -1;
static int hf_capwap_msg_element_type_ac_descriptor_dtls_policy_d = -1;
static int hf_capwap_msg_element_type_ac_descriptor_dtls_policy_c = -1;
static int hf_capwap_msg_element_type_ac_descriptor_dtls_policy_r = -1;

static int hf_capwap_msg_element_type_ac_information_vendor = -1;
static int hf_capwap_msg_element_type_ac_information_type = -1;
static int hf_capwap_msg_element_type_ac_information_length = -1;
static int hf_capwap_msg_element_type_ac_information_value = -1;
static int hf_capwap_msg_element_type_ac_information_hardware_version = -1;
static int hf_capwap_msg_element_type_ac_information_software_version = -1;

static int hf_capwap_msg_element_type_ac_name = -1;	
static int hf_capwap_msg_element_type_capwap_control_ipv4 = -1;	
static int hf_capwap_msg_element_type_capwap_control_wtp_count = -1;	
static int hf_capwap_msg_element_type_discovery_type = -1;

static int hf_capwap_msg_element_type_wtp_board_data_vendor = -1;
static int hf_capwap_msg_element_type_wtp_board_data_type = -1;
static int hf_capwap_msg_element_type_wtp_board_data_length = -1;
static int hf_capwap_msg_element_type_wtp_board_data_value = -1;
static int hf_capwap_msg_element_type_wtp_board_data_wtp_model_number  = -1;
static int hf_capwap_msg_element_type_wtp_board_data_wtp_serial_number  = -1;
static int hf_capwap_msg_element_type_wtp_board_data_wtp_board_id  = -1;
static int hf_capwap_msg_element_type_wtp_board_data_wtp_board_revision  = -1;
static int hf_capwap_msg_element_type_wtp_board_data_base_mac_address  = -1;

static int hf_capwap_msg_element_type_wtp_descriptor_max_radios = -1;
static int hf_capwap_msg_element_type_wtp_descriptor_radio_in_use = -1;
static int hf_capwap_msg_element_type_wtp_descriptor_number_encrypt = -1;
static int hf_capwap_msg_element_type_wtp_descriptor_encrypt_reserved = -1;
static int hf_capwap_msg_element_type_wtp_descriptor_encrypt_wbid = -1;
static int hf_capwap_msg_element_type_wtp_descriptor_encrypt_capabilities = -1;
static int hf_capwap_msg_element_type_wtp_descriptor_vendor = -1;
static int hf_capwap_msg_element_type_wtp_descriptor_type = -1;
static int hf_capwap_msg_element_type_wtp_descriptor_length = -1;
static int hf_capwap_msg_element_type_wtp_descriptor_value = -1;
static int hf_capwap_msg_element_type_wtp_descriptor_hardware_version = -1;
static int hf_capwap_msg_element_type_wtp_descriptor_active_software_version = -1;
static int hf_capwap_msg_element_type_wtp_descriptor_boot_version = -1;
static int hf_capwap_msg_element_type_wtp_descriptor_other_software_version = -1;

static int hf_capwap_msg_element_type_wtp_frame_tunnel_mode = -1;
static int hf_capwap_msg_element_type_wtp_frame_tunnel_mode_n = -1;
static int hf_capwap_msg_element_type_wtp_frame_tunnel_mode_e = -1;
static int hf_capwap_msg_element_type_wtp_frame_tunnel_mode_l = -1;
static int hf_capwap_msg_element_type_wtp_frame_tunnel_mode_r = -1;

static int hf_capwap_msg_element_type_wtp_mac_type = -1;

static dissector_handle_t dtls_handle;
static dissector_handle_t ieee8023_handle;
static dissector_handle_t ieee80211_handle;
static dissector_handle_t data_handle;

/* Initialize the subtree pointers */
static gint ett_capwap = -1;
/* ************************************************************************* */
/*                  Header Type				                     */
/* ************************************************************************* */

static const value_string type_header_vals[] = {
  { 0, "CAPWAP Header" },
  { 1, "CAPWAP DTLS Header" },
  { 0,     NULL     }
};

/* ************************************************************************* */
/*                   Wireless Binding IDentifier (WBID)                      */
/* ************************************************************************* */

static const value_string type_wbid[] = {
  { 0, "Reserved" },
  { 1, "IEEE 802.11" },
  { 2, "IEEE 802.16" }, /* From old RFC Draft... */
  { 3, "EPCGlobal" },
  { 0,     NULL     }
};

/* ************************************************************************* */
/*                 flag Type Transported (payload)	                     */
/* ************************************************************************* */
static const true_false_string flag_type_t = {
  "Native frame format (see Wireless Binding ID field)",
  "IEEE 802.3 frame"
};

/* ************************************************************************* */
/*                 flag Type Fragment 			                     */
/* ************************************************************************* */
static const true_false_string flag_type_f = {
  "Fragmented",
  "Don't Fragment"
};

/* ************************************************************************* */
/*                 flag Type Last Fragment 		                     */
/* ************************************************************************* */
static const true_false_string flag_type_l = {
  "This is the last fragment",
  "More fragments follow"
 };

/* ************************************************************************* */
/*                 flag Type Wireless  		    	                     */
/* ************************************************************************* */
static const true_false_string flag_type_w = {
  "Wireless Specific Information is present",
  "No Wireless Specific Information"
 };

/* ************************************************************************* */
/*                 flag Type Radio Mac 		    	                     */
/* ************************************************************************* */
static const true_false_string flag_type_m = {
  "Radio MAC Address is present",
  "No Radio MAC Address"
 };

/* ************************************************************************* */
/*                 flag Type Keep Alive		    	                     */
/* ************************************************************************* */
static const true_false_string flag_type_k = {
  "Keep-Alive Packet",
  "No Keep-Alive"
 };

/* ************************************************************************* */
/*                  Message Type Value			                     */
/* ************************************************************************* */
static const value_string message_type[] = {
  { 1, "Discovery Request" },
  { 2, "Discovery Response" },
  { 3, "Join Request" },
  { 4, "Join Response" },
  { 5, "Configuration Status Request" },
  { 6, "Configuration Status Response" },
  { 7, "Configuration Update Request" },
  { 8, "Configuration Update Response" },
  { 9, "WTP Event Request" },
  { 10, "WTP Event Response" },
  { 11, "Change State Request" },
  { 12, "Change State Response" },
  { 13, "Echo Request" },
  { 14, "Echo Response" },
  { 15, "Image Data Request" },
  { 16, "Image Data Response" },
  { 17, "Reset Request" },
  { 18, "Reset Response" },
  { 19, "Primary Discovery Request" },
  { 20, "Primary Discovery Response" },
  { 21, "Data Transfer Request" },
  { 22, "Data Transfer Response" },
  { 23, "Clear Configuration Request" },
  { 24, "Clear Configuration Response" },
  { 25, "Station Configuration Request" },
  { 26, "Station Configuration Response" },
  { 0,     NULL     }
};

/* ************************************************************************* */
/*       		Message Element Type			             */
/* ************************************************************************* */
#define TYPE_AC_DESCRIPTOR                       1  
#define TYPE_AC_IPV4_LIST                        2  
#define TYPE_AC_IPV6_LIST                        3
#define TYPE_AC_NAME                             4
#define TYPE_AC_NAME_W_PRIORITY                  5
#define TYPE_AC_TIMESTAMP                        6
#define TYPE_ADD_MAC_ACL_ENTRY                   7
#define TYPE_ADD_STATION                         8
#define TYPE_RESERVED_9                          9
#define TYPE_CAPWAP_CONTROL_IPV4_ADDRESS         10
#define TYPE_CAPWAP_CONTROL_IPV6_ADDRESS         11 
#define TYPE_CAPWAP_TIMERS                       12
#define TYPE_DATA_TRANSFER_DATA                  13
#define TYPE_DATA_TRANSFER_MODE                  14
#define TYPE_DESCRYPTION_ERROR_REPORT            15
#define TYPE_DECRYPTION_ERROR_REPORT_PERIOD      16
#define TYPE_DELETE_MAC_ENTRY                    17
#define TYPE_DELETE_STATION                      18
#define TYPE_RESERVED_19                         19   
#define TYPE_DISCOVERY_TYPE                      20
#define TYPE_DUPLICATE_IPV4_ADDRESS              21
#define TYPE_DUPLICATE_IPV6_ADDRESS              22
#define TYPE_IDLE_TIMEOUT                        23
#define TYPE_IMAGE_DATA                          24
#define TYPE_IMAGE_IDENTIFIER                    25
#define TYPE_IMAGE_INFORMATION                   26
#define TYPE_INITIATE_DOWNLOAD                   27
#define TYPE_LOCATION_DATA                       28
#define TYPE_MAXIMUM_MESSAGE_LENGTH              29
#define TYPE_CAPWAP_LOCAL_IPV4_ADDRESS           30
#define TYPE_RADIO_ADMINISTRATIVE_STATE          31
#define TYPE_RADIO_OPERATIONAL_STATE             32
#define TYPE_RESULT_CODE                         33
#define TYPE_RETURNED_MESSAGE_ELEMENT            34
#define TYPE_SESSION_ID                          35
#define TYPE_STATISTICS_TIMER                    36
#define TYPE_VENDOR_SPECIFIC_PAYLOAD             37
#define TYPE_WTP_BOARD_DATA                      38
#define TYPE_WTP_DESCRIPTOR                      39
#define TYPE_WTP_FALLBACK                        40
#define TYPE_WTP_FRAME_TUNNEL_MODE               41
#define TYPE_RESERVED_42                         42
#define TYPE_RESERVED_43                         43
#define TYPE_WTP_MAC_TYPE                        44
#define TYPE_WTP_NAME                            45
#define TYPE_RESERVED_46                         46
#define TYPE_WTP_RADIO_STATISTICS                47
#define TYPE_WTP_REBOOT_STATISTICS               48
#define TYPE_WTP_STATIC_IP_ADDRESS_INFORMATION   49
#define TYPE_CAPWAP_LOCAL_IPV6_ADDRESS           50
#define TYPE_CAPWAP_TRANSPORT_PROTOCOL           51
#define TYPE_MTU_DISCOVERY_PADDING               52
#define TYPE_ECN_SUPPORT                         53

/* ************************************************************************* */
/*       		Message Element Type Value		             */
/* ************************************************************************* */
static const value_string message_element_type_vals[] = {
  { TYPE_AC_DESCRIPTOR, "AC Descriptor" },
  { TYPE_AC_IPV4_LIST, "AC IPv4 List" },
  { TYPE_AC_IPV6_LIST, "AC IPv6 List" },
  { TYPE_AC_NAME, "AC Name" },
  { TYPE_AC_NAME_W_PRIORITY, "AC Name With Priority" },
  { TYPE_AC_TIMESTAMP, "AC Timestamp" },
  { TYPE_ADD_MAC_ACL_ENTRY, "Add MAC ACL Entry" },
  { TYPE_ADD_STATION, "Add Station" },
  { TYPE_RESERVED_9, "Reserved" },
  { TYPE_CAPWAP_CONTROL_IPV4_ADDRESS, "CAPWAP Control IPv4 Address" },
  { TYPE_CAPWAP_CONTROL_IPV6_ADDRESS, "CAPWAP Control IPv6 Address" }, 
  { TYPE_CAPWAP_TIMERS, "CAPWAP Timers" },
  { TYPE_DATA_TRANSFER_DATA, "Data Transfer Data" },
  { TYPE_DATA_TRANSFER_MODE, "Data Transfer Mode" },
  { TYPE_DESCRYPTION_ERROR_REPORT, "Decryption Error Report" },
  { TYPE_DECRYPTION_ERROR_REPORT_PERIOD, "Decryption Error Report Period" },
  { TYPE_DELETE_MAC_ENTRY, "Delete MAC ACL Entry" },
  { TYPE_DELETE_STATION, "Delete Station" },
  { TYPE_RESERVED_19, "Reserved" },   
  { TYPE_DISCOVERY_TYPE, "Discovery Type" },
  { TYPE_DUPLICATE_IPV4_ADDRESS, "Duplicate IPv4 Address" },
  { TYPE_DUPLICATE_IPV6_ADDRESS, "Duplicate IPv6 Address" },
  { TYPE_IDLE_TIMEOUT, "Idle Timeout" },
  { TYPE_IMAGE_DATA, "Image Data" },
  { TYPE_IMAGE_IDENTIFIER, "Image Identifier" },
  { TYPE_IMAGE_INFORMATION, "Image Information" },
  { TYPE_INITIATE_DOWNLOAD, "Initiate Download" },
  { TYPE_LOCATION_DATA, "Location Data" },
  { TYPE_MAXIMUM_MESSAGE_LENGTH, "Maximum Message Length" },
  { TYPE_CAPWAP_LOCAL_IPV4_ADDRESS, "CAPWAP Local IPv4 Address" },
  { TYPE_RADIO_ADMINISTRATIVE_STATE, "Radio Administrative State " },
  { TYPE_RADIO_OPERATIONAL_STATE, "Radio Operational State" },
  { TYPE_RESULT_CODE, "Result Code" },
  { TYPE_RETURNED_MESSAGE_ELEMENT, "Returned Message Element" },
  { TYPE_SESSION_ID, "Session ID" },
  { TYPE_STATISTICS_TIMER, "Statistics Timer" },
  { TYPE_VENDOR_SPECIFIC_PAYLOAD, "Vendor Specific Payload" },
  { TYPE_WTP_BOARD_DATA, "WTP Board Data" },
  { TYPE_WTP_DESCRIPTOR, "WTP Descriptor" },
  { TYPE_WTP_FALLBACK, "WTP Fallback " },
  { TYPE_WTP_FRAME_TUNNEL_MODE, "WTP Frame Tunnel Mode " },
  { TYPE_RESERVED_42, "Reserved" },
  { TYPE_RESERVED_43, "Reserved" },
  { TYPE_WTP_MAC_TYPE, "WTP MAC Type" },
  { TYPE_WTP_NAME, "WTP Name" },
  { TYPE_RESERVED_46, "Unused/Reserved" },
  { TYPE_WTP_RADIO_STATISTICS, "WTP Radio Statistics" },
  { TYPE_WTP_REBOOT_STATISTICS, "WTP Reboot Statistics" },
  { TYPE_WTP_STATIC_IP_ADDRESS_INFORMATION, "WTP Static IP Address Information" },
  { TYPE_CAPWAP_LOCAL_IPV6_ADDRESS, "CAPWAP Local IPv6 Address" },
  { TYPE_CAPWAP_TRANSPORT_PROTOCOL, "CAPWAP Transport Protocol" },
  { TYPE_MTU_DISCOVERY_PADDING, "MTU Discovery Padding" },
  { TYPE_ECN_SUPPORT, "ECN Support" },
  { 0,     NULL     }
};

/* ************************************************************************* */
/*       		Discovery Type				             */
/* ************************************************************************* */
static const value_string discovery_type_vals[] = {
  { 0, "Unknown" },
  { 1, "Static Configuration" },
  { 2, "DHCP" },
  { 3, "DNS" },
  { 4, "AC Referral" },
  { 0,     NULL     }
};

/* ************************************************************************* */
/*       		Radio MAC Address Field			             */
/* ************************************************************************* */
static const value_string rmac_field_vals[] = {
  { 0, "Reserved" },
  { 1, "Supported" },
  { 2, "Not Supported" },
  { 0,     NULL     }
};

/* ************************************************************************* */
/*       		Board Data Type Value		           	     */
/* ************************************************************************* */
#define BOARD_DATA_WTP_MODEL_NUMBER 0
#define BOARD_DATA_WTP_SERIAL_NUMBER 1
#define BOARD_DATA_BOARD_ID 2
#define BOARD_DATA_BOARD_REVISION 3
#define BOARD_DATA_BASE_MAC_ADDRESS 4

static const value_string board_data_type_vals[] = {
  { BOARD_DATA_WTP_MODEL_NUMBER, "WTP Model Number" },
  { BOARD_DATA_WTP_SERIAL_NUMBER, "WTP Serial Number" },
  { BOARD_DATA_BOARD_ID, "Board ID" },
  { BOARD_DATA_BOARD_REVISION, "Board Revision" },
  { BOARD_DATA_BASE_MAC_ADDRESS, "Base MAC Address" },
  { 0,     NULL     }
};

/* ************************************************************************* */
/*       		Descriptor WTP Type Value	           	     */
/* ************************************************************************* */
#define WTP_DESCRIPTOR_HARDWARE_VERSION 0
#define WTP_DESCRIPTOR_ACTIVE_SOFTWARE_VERSION 1
#define WTP_DESCRIPTOR_BOOT_VERSION 2
#define WTP_DESCRIPTOR_OTHER_SOFTWARE_VERSION 3

static const value_string wtp_descriptor_type_vals[] = {
  { WTP_DESCRIPTOR_HARDWARE_VERSION, "WTP Hardware Version" },
  { WTP_DESCRIPTOR_ACTIVE_SOFTWARE_VERSION, "WTP Active Software Version" },
  { WTP_DESCRIPTOR_BOOT_VERSION, "WTP Boot Version" },
  { WTP_DESCRIPTOR_OTHER_SOFTWARE_VERSION, "WTP Other Software Version" },
  { 0,     NULL     }
};

/* ************************************************************************* */
/*       		AC Information Type Value	           	     */
/* ************************************************************************* */
#define AC_INFORMATION_HARDWARE_VERSION 4
#define AC_INFORMATION_SOFTWARE_VERSION 5

static const value_string ac_information_type_vals[] = {
  { AC_INFORMATION_HARDWARE_VERSION, "AC Hardware Version" },
  { AC_INFORMATION_SOFTWARE_VERSION, "AC  Software Version" },
  { 0,     NULL     }
};

/* ************************************************************************* */
/*                 WTP MAC Type				                     */
/* ************************************************************************* */
static const value_string wtp_mac_vals[] = {
  { 0, "Local MAC" },
  { 1, "Split MAC" },
  { 2, "Both (Local and Split MAC)" },
  { 0,     NULL     }
};

/* Variable */
static guint8 type_header = 0;
static guint8 payload_type = 0;
static guint8 payload_wbid = 0;

static void
dissect_capwap_encryption_capabilities(tvbuff_t *tvb, proto_tree *encryption_capabilities_tree, guint offset)
{
	guint wbid,encryption_capabilities = 0;
	proto_item *encryption_capabilities_item;
	proto_tree *sub_encryption_capabilities_tree;
	
	encryption_capabilities = tvb_get_ntohs(tvb, offset+1);
	wbid = tvb_get_bits8(tvb, offset*8+3,5);

	encryption_capabilities_item = proto_tree_add_text(encryption_capabilities_tree, tvb, offset, 3,	    			"Encryption Capabilities: (WBID=%d) %d", wbid,encryption_capabilities);
	sub_encryption_capabilities_tree = proto_item_add_subtree(encryption_capabilities_item, ett_capwap);

        proto_tree_add_uint(sub_encryption_capabilities_tree,hf_capwap_msg_element_type_wtp_descriptor_encrypt_reserved, tvb, offset, 1, tvb_get_bits8(tvb, offset*8,3));

        proto_tree_add_uint(sub_encryption_capabilities_tree,hf_capwap_msg_element_type_wtp_descriptor_encrypt_wbid, tvb, offset, 1, wbid);

	proto_tree_add_item(sub_encryption_capabilities_tree, hf_capwap_msg_element_type_wtp_descriptor_encrypt_capabilities, tvb, offset+1, 2, FALSE);
}

/* Returns the number of bytes consumed by this option. */
static int
dissect_capwap_ac_information(tvbuff_t *tvb, proto_tree *ac_information_type_tree, guint offset)
{
	guint optlen,ac_information_type = 0;
	proto_item *ac_information_type_item;
	proto_tree *sub_ac_information_type_tree;
	
	ac_information_type = tvb_get_ntohs(tvb, offset+4);
	optlen = tvb_get_ntohs(tvb, offset+6);
	ac_information_type_item = proto_tree_add_text(ac_information_type_tree, tvb, offset, 4+2+2+optlen,	    			"AC Information Type: (t=%d,l=%d) %s", ac_information_type, optlen, val_to_str(ac_information_type,ac_information_type_vals,"Unknown AC Information Type (%02d)") );
	sub_ac_information_type_tree = proto_item_add_subtree(ac_information_type_item, ett_capwap);

        proto_tree_add_item(sub_ac_information_type_tree, hf_capwap_msg_element_type_ac_information_vendor, tvb, offset, 4, FALSE);

	proto_tree_add_item(sub_ac_information_type_tree, hf_capwap_msg_element_type_ac_information_type, tvb, offset+4, 2, FALSE );
	
	proto_tree_add_item(sub_ac_information_type_tree, hf_capwap_msg_element_type_ac_information_length, tvb, offset+6, 2, FALSE);
	
	proto_tree_add_item(sub_ac_information_type_tree, hf_capwap_msg_element_type_ac_information_value, tvb, offset+8, optlen, FALSE);
	switch (ac_information_type) {
	case AC_INFORMATION_HARDWARE_VERSION:
		proto_tree_add_item(sub_ac_information_type_tree, hf_capwap_msg_element_type_ac_information_hardware_version, tvb, offset+8, optlen, FALSE);
		break;

	case AC_INFORMATION_SOFTWARE_VERSION:
		proto_tree_add_item(sub_ac_information_type_tree, hf_capwap_msg_element_type_ac_information_software_version, tvb, offset+8, optlen, FALSE);
		break;

	default:
		/* No Default Action */
		break;
	}

	return 4+2+2+optlen;
}

/* Returns the number of bytes consumed by this option. */
static int
dissect_capwap_wtp_descriptor(tvbuff_t *tvb, proto_tree *wtp_descriptor_type_tree, guint offset)
{
	guint optlen,wtp_descriptor_type = 0;
	proto_item *wtp_descriptor_type_item;
	proto_tree *sub_wtp_descriptor_type_tree;
	
	wtp_descriptor_type = tvb_get_ntohs(tvb, offset+4);
	optlen = tvb_get_ntohs(tvb, offset+6);
	wtp_descriptor_type_item = proto_tree_add_text(wtp_descriptor_type_tree, tvb, offset, 4+2+2+optlen,	    			"WTP Descriptor Type: (t=%d,l=%d) %s", wtp_descriptor_type, optlen, val_to_str(wtp_descriptor_type,wtp_descriptor_type_vals,"Unknown WTP Descriptor Type (%02d)") );
	sub_wtp_descriptor_type_tree = proto_item_add_subtree(wtp_descriptor_type_item, ett_capwap);

        proto_tree_add_item(sub_wtp_descriptor_type_tree, hf_capwap_msg_element_type_wtp_descriptor_vendor, tvb, offset, 4, FALSE);

	proto_tree_add_item(sub_wtp_descriptor_type_tree, hf_capwap_msg_element_type_wtp_descriptor_type, tvb, offset+4, 2, FALSE );
	
	proto_tree_add_item(sub_wtp_descriptor_type_tree, hf_capwap_msg_element_type_wtp_descriptor_length, tvb, offset+6, 2, FALSE);
	
	proto_tree_add_item(sub_wtp_descriptor_type_tree, hf_capwap_msg_element_type_wtp_descriptor_value, tvb, offset+8, optlen, FALSE);

	switch (wtp_descriptor_type) {
	case WTP_DESCRIPTOR_HARDWARE_VERSION:
		proto_tree_add_item(sub_wtp_descriptor_type_tree, hf_capwap_msg_element_type_wtp_descriptor_hardware_version, tvb, offset+8, optlen, FALSE);
		break;

	case WTP_DESCRIPTOR_ACTIVE_SOFTWARE_VERSION:
		proto_tree_add_item(sub_wtp_descriptor_type_tree, hf_capwap_msg_element_type_wtp_descriptor_active_software_version, tvb, offset+8, optlen, FALSE);
		break;

	case WTP_DESCRIPTOR_BOOT_VERSION:
		proto_tree_add_item(sub_wtp_descriptor_type_tree, hf_capwap_msg_element_type_wtp_descriptor_boot_version, tvb, offset+8, optlen, FALSE);
		break;

	case WTP_DESCRIPTOR_OTHER_SOFTWARE_VERSION:
		proto_tree_add_item(sub_wtp_descriptor_type_tree, hf_capwap_msg_element_type_wtp_descriptor_other_software_version, tvb, offset+8, optlen, FALSE);
		break;

	default:
		/* No Default Action */
		break;
	}

	return 4+2+2+optlen;
}

/* Returns the number of bytes consumed by this option. */
static int
dissect_capwap_board_data(tvbuff_t *tvb, proto_tree *board_data_type_tree, guint offset)
{
	guint optlen,board_data_type = 0;
	proto_item *board_data_type_item;
	proto_tree *sub_board_data_type_tree;
	
	board_data_type = tvb_get_ntohs(tvb, offset);
	optlen = tvb_get_ntohs(tvb, offset+2);
	board_data_type_item = proto_tree_add_text(board_data_type_tree, tvb, offset, 2+2+optlen,	    			"Board Data Type: (t=%d,l=%d) %s", board_data_type, optlen, val_to_str(board_data_type,board_data_type_vals,"Unknown Board Data Type (%02d)") );
	sub_board_data_type_tree = proto_item_add_subtree(board_data_type_item, ett_capwap);

	proto_tree_add_item(sub_board_data_type_tree, hf_capwap_msg_element_type_wtp_board_data_type,tvb, offset, 2, FALSE );
	
	proto_tree_add_item(sub_board_data_type_tree, hf_capwap_msg_element_type_wtp_board_data_length, tvb, offset+2, 2, FALSE);
	
	proto_tree_add_item(sub_board_data_type_tree, hf_capwap_msg_element_type_wtp_board_data_value, tvb, offset+4, optlen, FALSE);
	switch (board_data_type) {
	case BOARD_DATA_WTP_MODEL_NUMBER:
		proto_tree_add_item(sub_board_data_type_tree, hf_capwap_msg_element_type_wtp_board_data_wtp_model_number, tvb, offset+4, optlen, FALSE);
		break;

	case BOARD_DATA_WTP_SERIAL_NUMBER:
		proto_tree_add_item(sub_board_data_type_tree, hf_capwap_msg_element_type_wtp_board_data_wtp_serial_number, tvb, offset+4, optlen, FALSE);
		break;

	case BOARD_DATA_BOARD_ID:
		proto_tree_add_item(sub_board_data_type_tree, hf_capwap_msg_element_type_wtp_board_data_wtp_board_id, tvb, offset+4, optlen, FALSE);
		break;

	case BOARD_DATA_BOARD_REVISION:
		proto_tree_add_item(sub_board_data_type_tree, hf_capwap_msg_element_type_wtp_board_data_wtp_board_revision, tvb, offset+4, optlen, FALSE);
		break;

	case BOARD_DATA_BASE_MAC_ADDRESS:
		proto_tree_add_item (sub_board_data_type_tree, hf_capwap_msg_element_type_wtp_board_data_base_mac_address , tvb, offset+4, 6,FALSE);
		break;

	default:
		/* No Default Action */
		break;	
	}

	return 2+2+optlen;
}
/* Returns the number of bytes consumed by this option. */
static int
dissect_capwap_message_element_type(tvbuff_t *tvb, proto_tree *msg_element_type_tree, guint offset)
{
	guint optlen, offset_end, number_encrypt, i, msg_element_type = 0;
	proto_item *msg_element_type_item, *msg_element_type_item_flag;
	proto_tree *sub_msg_element_type_tree, *sub_msg_element_type_flag_tree;

	msg_element_type = tvb_get_ntohs(tvb, offset);
	optlen = tvb_get_ntohs(tvb, offset+2);
	msg_element_type_item = proto_tree_add_text(msg_element_type_tree, tvb, offset, 2+2+optlen,	    			"Type: (t=%d,l=%d) %s", msg_element_type, optlen, val_to_str(msg_element_type,message_element_type_vals,"Unknown Message Element Type (%02d)") );
	sub_msg_element_type_tree = proto_item_add_subtree(msg_element_type_item, ett_capwap);

	proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type,tvb, offset, 2, FALSE );

	proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_length, tvb, offset+2, 2, FALSE);
	
	proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_value, tvb, offset+4, optlen, FALSE);


	switch (msg_element_type) {
	case TYPE_AC_DESCRIPTOR: /* AC Descriptor (1) */
		proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ac_descriptor_stations, tvb, offset+4, 2, FALSE);
		proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ac_descriptor_limit, tvb, offset+6, 2, FALSE);
		proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ac_descriptor_active_wtp, tvb, offset+8, 2, FALSE);
		proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ac_descriptor_max_wtp, tvb, offset+10, 2, FALSE);

		/* AC Descriptor Security Flags... */
		msg_element_type_item_flag = proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ac_descriptor_security, tvb, offset+12, 1 ,FALSE);
		sub_msg_element_type_flag_tree = proto_item_add_subtree(msg_element_type_item_flag, ett_capwap); 

		proto_tree_add_boolean(sub_msg_element_type_flag_tree, hf_capwap_msg_element_type_ac_descriptor_security_r, tvb, offset+12, 1,FALSE);
		proto_tree_add_boolean(sub_msg_element_type_flag_tree, hf_capwap_msg_element_type_ac_descriptor_security_s, tvb, offset+12, 1,FALSE);
		proto_tree_add_boolean (sub_msg_element_type_flag_tree, hf_capwap_msg_element_type_ac_descriptor_security_x, tvb, offset+12, 1,FALSE);

		proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ac_descriptor_rmac_field, tvb, offset+13, 1, FALSE);
		proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ac_descriptor_reserved, tvb, offset+14, 1, FALSE);

		/* AC Descriptor DTLS Flags... */
		msg_element_type_item_flag = proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ac_descriptor_dtls_policy, tvb, offset+15, 1 ,FALSE);
		sub_msg_element_type_flag_tree = proto_item_add_subtree(msg_element_type_item_flag, ett_capwap); 

		proto_tree_add_item(sub_msg_element_type_flag_tree, hf_capwap_msg_element_type_ac_descriptor_dtls_policy_r, tvb, offset+15, 1,FALSE);
		proto_tree_add_item(sub_msg_element_type_flag_tree, hf_capwap_msg_element_type_ac_descriptor_dtls_policy_d, tvb, offset+15, 1,FALSE);
		proto_tree_add_item (sub_msg_element_type_flag_tree, hf_capwap_msg_element_type_ac_descriptor_dtls_policy_c, tvb, offset+15, 1,FALSE);

		offset_end = offset + optlen -4;	
		offset += 4 + 12;
		while (offset < offset_end) {
			offset += dissect_capwap_ac_information(tvb, sub_msg_element_type_tree, offset);	
		}
		break;

	case TYPE_AC_NAME: /* AC Name (4) */
		proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_ac_name, tvb, offset+4, optlen, FALSE);
		break;

	case TYPE_CAPWAP_CONTROL_IPV4_ADDRESS: /* CAPWAP Control IPv4 Address (10) */
		proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_capwap_control_ipv4, tvb, offset+4, 4, FALSE);
		proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_capwap_control_wtp_count, tvb, offset+8, 2, FALSE);
		break;

	case TYPE_DISCOVERY_TYPE: /* Discovery Type (20) */
		proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_discovery_type, tvb, offset+4, optlen, FALSE);
		break;

	case TYPE_WTP_BOARD_DATA: /* WTP Board Data (38) */
		proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_wtp_board_data_vendor, tvb, offset+4, 4, FALSE);
		offset += 8; 
		offset_end = offset + optlen -4;
		while (offset < offset_end) {
			offset += dissect_capwap_board_data(tvb, sub_msg_element_type_tree, offset);	
		}
		break;

	case TYPE_WTP_DESCRIPTOR: /* WTP Descriptor (39) */
		proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_wtp_descriptor_max_radios, tvb, offset+4, 1, FALSE);
		proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_wtp_descriptor_radio_in_use, tvb, offset+5, 1, FALSE);
 
		number_encrypt = tvb_get_guint8(tvb,offset+6);
		msg_element_type_item_flag = proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_wtp_descriptor_number_encrypt, tvb, offset+6, 1,FALSE);
		sub_msg_element_type_flag_tree = proto_item_add_subtree(msg_element_type_item_flag, ett_capwap); 
		for (i=0; i < number_encrypt; i++) {
			dissect_capwap_encryption_capabilities(tvb, sub_msg_element_type_flag_tree, offset+4+3+i*3);
		}

		offset_end = offset + optlen -4;		
		offset += 4 + 3 + number_encrypt * 3;
		while (offset < offset_end) {
			offset += dissect_capwap_wtp_descriptor(tvb, sub_msg_element_type_tree, offset);	
		}
		break;

	case TYPE_WTP_FRAME_TUNNEL_MODE: /* WTP Frame Tunnel Mode (41) */
		msg_element_type_item_flag = proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_wtp_frame_tunnel_mode, tvb, offset+4, 1 ,FALSE);
		sub_msg_element_type_flag_tree = proto_item_add_subtree(msg_element_type_item_flag, ett_capwap); 

		proto_tree_add_item(sub_msg_element_type_flag_tree, hf_capwap_msg_element_type_wtp_frame_tunnel_mode_n, tvb, offset+4, 1,FALSE);
		proto_tree_add_item(sub_msg_element_type_flag_tree, hf_capwap_msg_element_type_wtp_frame_tunnel_mode_e, tvb, offset+4, 1,FALSE);
		proto_tree_add_item(sub_msg_element_type_flag_tree, hf_capwap_msg_element_type_wtp_frame_tunnel_mode_l, tvb, offset+4, 1,FALSE);
		proto_tree_add_item(sub_msg_element_type_flag_tree, hf_capwap_msg_element_type_wtp_frame_tunnel_mode_r, tvb, offset+4, 1,FALSE);
		break;

	case TYPE_WTP_MAC_TYPE: /* WTP MAC Type (44) */
		proto_tree_add_item(sub_msg_element_type_tree, hf_capwap_msg_element_type_wtp_mac_type, tvb, offset+4, optlen, FALSE);
		break;

	default:
		/* No Default Action */
		break;	
	}
	
	return 2+2+optlen;
}

/* Returns the number of bytes consumed by this option. */
static int
dissect_capwap_message_element(tvbuff_t *tvb, proto_tree *capwap_control_tree, guint offset)
{
	guint plen = 0, offset_end;
	proto_item *ti;
	proto_tree *capwap_message_element_tree;
   	
	ti = proto_tree_add_item(capwap_control_tree, hf_capwap_message_element, tvb, offset, tvb_reported_length(tvb) - offset,FALSE);
      	capwap_message_element_tree = proto_item_add_subtree(ti, ett_capwap); 
	
	offset_end = tvb_reported_length(tvb);

 	while (offset+plen < offset_end) {
		plen += dissect_capwap_message_element_type(tvb, capwap_message_element_tree, offset+plen);
	}

	return plen;
}

/* Returns the number of bytes consumed by this option. */
static int
dissect_capwap_control_header(tvbuff_t *tvb, proto_tree *capwap_control_tree, guint offset, packet_info *pinfo )
{
	guint plen = 0;
	proto_item *ti, *ti_flag;
	proto_tree *capwap_control_header_tree;
	proto_tree *capwap_control_msg_type_tree;
   	
	ti = proto_tree_add_item(capwap_control_tree, hf_capwap_control_header, tvb, offset, 8,FALSE);
      	capwap_control_header_tree = proto_item_add_subtree(ti, ett_capwap); 

	/* Message Type 32 bits*/
   	ti_flag = proto_tree_add_item(capwap_control_header_tree, hf_capwap_control_header_msg_type, tvb, offset, 4, FALSE);
      	capwap_control_msg_type_tree = proto_item_add_subtree(ti_flag, ett_capwap); 

	proto_tree_add_item(capwap_control_msg_type_tree, hf_capwap_control_header_msg_type_enterprise_nbr, tvb, offset, 3, FALSE);
	proto_tree_add_item(capwap_control_msg_type_tree, hf_capwap_control_header_msg_type_enterprise_specific, tvb, offset+3, 1, FALSE);

	col_append_fstr(pinfo->cinfo, COL_INFO, " - %s",val_to_str(tvb_get_guint8(tvb, offset+3),message_type,"Unknown Message Type (0x%02x)"));

	plen += 4;

	/* Sequence 8 bits */
	proto_tree_add_uint(capwap_control_header_tree, hf_capwap_control_header_seq_number, tvb, offset+plen, 1, tvb_get_guint8(tvb, offset));
	plen += 1;
	
	/* Message Element Length 16 bits */
	proto_tree_add_item(capwap_control_header_tree, hf_capwap_control_header_msg_element_length, tvb, offset+plen, 2, FALSE);
	plen += 2;

	/* Flags 8 bits */
	proto_tree_add_item(capwap_control_header_tree, hf_capwap_control_header_flags, tvb, offset+plen, 1, FALSE);
	plen += 1;

	return plen;
}

/* Returns the number of bytes consumed by this option. */
static int
dissect_capwap_header(tvbuff_t *tvb, proto_tree *capwap_control_tree, guint offset)
{
	guint plen = 0;
	proto_item *ti, *ti_flag;
	proto_tree *capwap_header_tree;
	proto_tree *capwap_header_flags_tree;
	guint flags = 0;

	ti = proto_tree_add_item(capwap_control_tree, hf_capwap_header, tvb, offset+plen, tvb_get_bits8(tvb, (offset+plen)*8, 5),FALSE);
	capwap_header_tree = proto_item_add_subtree(ti, ett_capwap); 

	/* Header Length : 5 Bits */
	proto_tree_add_uint(capwap_header_tree, hf_capwap_header_hlen, tvb, offset+plen, 1, tvb_get_bits8(tvb, (offset+plen)*8, 5));
	/* Radio ID : 5 Bits */
	proto_tree_add_uint(capwap_header_tree, hf_capwap_header_rid, tvb, offset+plen, 1, tvb_get_bits8(tvb, (offset+plen)*8+5, 5));
	plen++;
	/* Wireless Binding ID : 5 Bits */
	proto_tree_add_uint(capwap_header_tree, hf_capwap_header_wbid, tvb, offset+plen, 1, tvb_get_bits8(tvb, (offset+plen)*8+10, 5));
		
	/* Flags : 9 Bits */
	flags = tvb_get_bits16(tvb, (offset+plen)*8+7, 9,0);
	ti_flag = proto_tree_add_uint_format(capwap_header_tree, hf_capwap_header_flags, tvb, offset+plen, 1 ,0,"Header flags");
	capwap_header_flags_tree = proto_item_add_subtree(ti_flag, ett_capwap); 
	
	proto_tree_add_boolean (capwap_header_flags_tree, hf_capwap_header_flags_t, tvb, offset+plen, 1,flags);
	proto_tree_add_boolean (capwap_header_flags_tree, hf_capwap_header_flags_f, tvb, offset+plen, 1,flags);
	proto_tree_add_boolean (capwap_header_flags_tree, hf_capwap_header_flags_l, tvb, offset+plen, 1,flags);
	proto_tree_add_boolean (capwap_header_flags_tree, hf_capwap_header_flags_w, tvb, offset+plen, 1,flags);
	proto_tree_add_boolean (capwap_header_flags_tree, hf_capwap_header_flags_m, tvb, offset+plen, 1,flags);
	proto_tree_add_boolean (capwap_header_flags_tree, hf_capwap_header_flags_k, tvb, offset+plen, 1,flags);
	proto_tree_add_boolean (capwap_header_flags_tree, hf_capwap_header_flags_r, tvb, offset+plen, 1,flags);

	/* Type of Payload (for CAPWAP Data Packet) */
	payload_wbid = tvb_get_bits8(tvb, (offset+plen)*8+10, 5);
	payload_type = tvb_get_bits8(tvb, (offset+plen)*8+7,1);

	plen += 2;

	/* Fragment ID : 16 Bits */ 		
	proto_tree_add_item(capwap_header_tree, hf_capwap_header_fragment_id, tvb, offset+plen, 2, FALSE);
	plen += 2;

	/* Fragment offset : 13 Bits */ 		
	proto_tree_add_uint(capwap_header_tree, hf_capwap_header_fragment_offset, tvb, offset+plen, 2, tvb_get_bits16(tvb, (offset+plen)*8, 13,0));
		
	/* Reserved 3bits  */
	proto_tree_add_uint(capwap_header_tree, hf_capwap_header_reserved, tvb, offset+plen+1, 1, tvb_get_bits8(tvb, (offset+plen)*8+13, 3));
	plen += 2; 

	return plen;
}

/* Returns the number of bytes consumed by this option. */
static int
dissect_capwap_preamble(tvbuff_t *tvb, proto_tree *capwap_control_tree, guint offset)
{
	guint plen = 0;
	proto_item *ti;
	proto_tree *capwap_preamble_tree;	

	ti = proto_tree_add_item(capwap_control_tree, hf_capwap_preamble, tvb, offset+plen, -1,FALSE);
  	capwap_preamble_tree = proto_item_add_subtree(ti, ett_capwap); 

	proto_tree_add_uint(capwap_preamble_tree, hf_capwap_preamble_version, tvb, offset+plen, 1, hi_nibble(tvb_get_guint8(tvb, offset+plen)));
	proto_tree_add_uint(capwap_preamble_tree, hf_capwap_preamble_type, tvb, offset+plen, 1, lo_nibble(tvb_get_guint8(tvb, offset+plen)));
	type_header = lo_nibble(tvb_get_guint8(tvb, offset+plen));
	plen++;

	/* DTLS Header ? */
	if (type_header == 1) {
		proto_tree_add_item(capwap_preamble_tree, hf_capwap_preamble_reserved, tvb, offset+plen, 3, FALSE);
		plen +=3;
	}
	proto_item_set_len(ti,plen);

	return plen;
}

/* Code to actually dissect the packets */
static void
dissect_capwap_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

	/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *capwap_control_tree;
  	guint offset = 0;
	tvbuff_t *next_tvb;

	/* Make entries in Protocol column and Info column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CAPWAP");
	col_set_str(pinfo->cinfo, COL_INFO, "CAPWAP-Control");

	ti = proto_tree_add_item(tree, proto_capwap, tvb, 0, -1, FALSE);
	capwap_control_tree = proto_item_add_subtree(ti, ett_capwap);
		
	/* CAPWAP Preamble */
	offset += dissect_capwap_preamble(tvb, capwap_control_tree, offset);
		
	if (type_header == 1) {
		next_tvb = tvb_new_subset (tvb, offset, -1, -1);
		call_dissector(dtls_handle, next_tvb, pinfo, tree);
		return;
	}
		
	/* CAPWAP Header */
	offset += dissect_capwap_header(tvb, capwap_control_tree, offset);

	/* CAPWAP Control Header */
	offset += dissect_capwap_control_header(tvb, capwap_control_tree, offset, pinfo);	

	/* CAPWAP Message Element */ 
	offset += dissect_capwap_message_element(tvb, capwap_control_tree, offset);	
}

/* Code to actually dissect the packets */
static void
dissect_capwap_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *capwap_data_tree;
  	guint offset = 0;
	tvbuff_t *next_tvb;

	/* Make entries in Protocol column and Info column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CAPWAP");
	col_set_str(pinfo->cinfo, COL_INFO, "CAPWAP-Data");

	ti = proto_tree_add_item(tree, proto_capwap, tvb, 0, -1, FALSE);
	capwap_data_tree = proto_item_add_subtree(ti, ett_capwap);
		
	/* CAPWAP Preamble */
	offset += dissect_capwap_preamble(tvb, capwap_data_tree, offset);
		
	if (type_header == 1) {
		next_tvb = tvb_new_subset (tvb, offset, -1, -1);
		call_dissector(dtls_handle, next_tvb, pinfo, tree);
		return;
	}
		
	/* CAPWAP Header */
	offset += dissect_capwap_header(tvb, capwap_data_tree, offset);

	/* CAPWAP Data Payload */
	next_tvb = tvb_new_subset (tvb, offset, -1, -1);
	
	if (payload_type == 0) {
		/* IEEE 802.3 Frame */	
		call_dissector(ieee8023_handle, next_tvb, pinfo, tree);
	} else if (payload_wbid == 1) {
		/* IEEE 802.11 */
		call_dissector(ieee80211_handle, next_tvb, pinfo, tree);
	} else {
		/* Unknown Data */
		call_dissector(data_handle, next_tvb, pinfo, tree);
	}
}

void
proto_register_capwap_control(void)
{
	module_t *capwap_module;

	static hf_register_info hf[] = {
		/* Preamble */
		{ &hf_capwap_preamble,
		{ "Preamble",	"capwap.preamble", 
			FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_capwap_preamble_version,
		{ "Version",           "capwap.preamble.version",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Version of CAPWAP", HFILL }},
		{ &hf_capwap_preamble_type,
		{ "Type",           "capwap.preamble.type",
			FT_UINT8, BASE_DEC, VALS(type_header_vals), 0x0,
			"Type of Payload", HFILL }},
		{ &hf_capwap_preamble_reserved,
			{ "Reserved",           "capwap.preamble.reserved",
			FT_UINT24, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		/* CAPWAP Header */
		{ &hf_capwap_header,
		{ "Header",	"capwap.header", 
			FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},	
		{ &hf_capwap_header_hlen,
		{ "Header Lenght",	"capwap.header.lenght", 
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},	
		{ &hf_capwap_header_rid,
		{ "Radio ID",	"capwap.header.rid", 
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},	
		{ &hf_capwap_header_wbid,
		{ "Wireless Binding ID",	"capwap.header.wbid", 
			FT_UINT8, BASE_DEC, VALS(type_wbid), 0x0,
			NULL, HFILL }},	
		{ &hf_capwap_header_flags,
		{ "Header Flags",	"capwap.header.flags", 
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},	
		{ &hf_capwap_header_flags_t,
		{ "Payload Type",	"capwap.header.flags.t", 
			FT_BOOLEAN, 9, TFS (&flag_type_t), 0x100,
			NULL, HFILL }},
		{ &hf_capwap_header_flags_f,
		{ "Fragment",	"capwap.header.flags.f", 
			FT_BOOLEAN, 9, TFS (&flag_type_f), 0x80,
			NULL, HFILL }},	
		{ &hf_capwap_header_flags_l,
		{ "Last Fragment",	"capwap.header.flags.l", 
			FT_BOOLEAN, 9, TFS (&flag_type_l), 0x40,
			NULL, HFILL }},
		{ &hf_capwap_header_flags_w,
		{ "Wireless header",	"capwap.header.flags.w", 
			FT_BOOLEAN, 9, TFS (&flag_type_w), 0x20,
			NULL, HFILL }},	
		{ &hf_capwap_header_flags_m,
		{ "Radio MAC header",	"capwap.header.flags.m", 
			FT_BOOLEAN, 9, TFS (&flag_type_m), 0x10,
			NULL, HFILL }},
		{ &hf_capwap_header_flags_k,
		{ "Keep-Alive",	"capwap.header.flags.k", 
			FT_BOOLEAN, 9, TFS (&flag_type_k), 0x08,
			NULL, HFILL }},	
		{ &hf_capwap_header_flags_r,
		{ "Reserved",	"capwap.header.flags.r", 
			FT_BOOLEAN, 9, TFS(&tfs_set_notset), 0x07,
			NULL, HFILL }},	
		{ &hf_capwap_header_fragment_id,
		{ "Fragment ID",	"capwap.header.fragment.id", 
			FT_UINT16, BASE_DEC, NULL, 0x00,
			NULL, HFILL }},	
		{ &hf_capwap_header_fragment_offset,
		{ "Fragment Offset",	"capwap.header.fragment.offset", 
			FT_UINT16, BASE_DEC, NULL, 0x00,
			NULL, HFILL }},	
		{ &hf_capwap_header_reserved,
		{ "Reserved",	"capwap.header.fragment.reserved", 
			FT_UINT8, BASE_DEC, NULL, 0x00,
			NULL, HFILL }},

		/* CAPWAP Control Header Message 	*/
		{ &hf_capwap_control_header,
		{ "Control Header",	"capwap.control.header", 
			FT_NONE, BASE_NONE, NULL, 0x00,
			NULL, HFILL }},
		{ &hf_capwap_control_header_msg_type,
		{ "Message Type",	"capwap.control.header.message_type", 
			FT_UINT32, BASE_DEC, NULL, 0x00,
			NULL, HFILL }},
		{ &hf_capwap_control_header_msg_type_enterprise_nbr,
		{ "Message Type (Entreprise Number)",	"capwap.control.header.message_type.enterprise_number", 
			FT_UINT32, BASE_DEC, VALS(sminmpec_values), 0x00,
			NULL, HFILL }},
		{ &hf_capwap_control_header_msg_type_enterprise_specific,
		{ "Message Type (Entreprise Specific)",	"capwap.control.header.message_type.enterprise_specific", 
			FT_UINT8, BASE_DEC, VALS(message_type), 0x00,
			NULL, HFILL }},
		{ &hf_capwap_control_header_seq_number,
		{ "Sequence Number",	"capwap.control.header.sequence_number", 
			FT_UINT8, BASE_DEC, NULL, 0x00,
			NULL, HFILL }},	
		{ &hf_capwap_control_header_msg_element_length,
		{ "Message Element Length",	"capwap.control.header.message_element_length", 
			FT_UINT16, BASE_DEC, NULL, 0x00,
			NULL, HFILL }},
		{ &hf_capwap_control_header_flags,
		{ "Flags",	"capwap.control.header.flags", 
			FT_UINT8, BASE_DEC, NULL, 0x00,
			NULL, HFILL }},

 		/* CAPWAP Protocol Message Elements	*/	
		{ &hf_capwap_message_element,
		{ "Message Element",	"capwap.message_element", 
			FT_NONE, BASE_NONE, NULL, 0x00,
			NULL, HFILL }},

		{ &hf_capwap_msg_element_type,
		{ "Type",	"capwap.message_element.type",
			FT_UINT16, BASE_DEC, VALS(message_element_type_vals), 0x00,
			"CAPWAP Message Element type", HFILL }},

		{ &hf_capwap_msg_element_length,
		{ "Length",	"capwap.message_element.length",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"CAPWAP Message Element length", HFILL }},

		{ &hf_capwap_msg_element_value,
		{ "Value",	"capwap.message_element.value",
			FT_BYTES, BASE_NONE, NULL, 0x00,
			"CAPWAP Message Element value", HFILL }},

		/* CAPWAP Protocol Message Element Type */

		/* AC Descriptor */
		{ &hf_capwap_msg_element_type_ac_descriptor_stations,
		{ "Stations",	"capwap.control.message_element.ac_descriptor.stations", 
			FT_UINT16, BASE_DEC, NULL, 0x00,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_ac_descriptor_limit,
		{ "Limit Stations",	"capwap.control.message_element.ac_descriptor.limit", 
			FT_UINT16, BASE_DEC, NULL, 0x00,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_ac_descriptor_active_wtp,
		{ "Active WTPs",	"capwap.control.message_element.ac_descriptor.active_wtp", 
			FT_UINT16, BASE_DEC, NULL, 0x00,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_ac_descriptor_max_wtp,
		{ "Max WTPs",	"capwap.control.message_element.ac_descriptor.max_wtp", 
			FT_UINT16, BASE_DEC, NULL, 0x00,
			NULL, HFILL }},

		/* AC Descriptor Security Flags... */
		{ &hf_capwap_msg_element_type_ac_descriptor_security,
		{ "Security Flags",	"capwap.control.message_element.ac_descriptor.security", 
			FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_ac_descriptor_security_s,
		{ "AC supports the pre-shared",	"capwap.control.message_element.ac_descriptor.security.s", 
			FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x04,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_ac_descriptor_security_x,
		{ "AC supports X.509 Certificate",	"capwap.control.message_element.ac_descriptor.security.x", 
			FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x02,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_ac_descriptor_security_r,
		{ "Reserved",	"capwap.control.message_element.ac_descriptor.security.r", 
			FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0xF9,
			NULL, HFILL }},

		{ &hf_capwap_msg_element_type_ac_descriptor_rmac_field,
		{ "R-MAC Field",	"capwap.control.message_element.ac_descriptor.rmac_field", 
			FT_UINT8, BASE_DEC, VALS(rmac_field_vals), 0x00,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_ac_descriptor_reserved,
		{ "Reserved",	"capwap.control.message_element.ac_descriptor.reserved", 
			FT_UINT8, BASE_DEC, NULL, 0x00,
			NULL, HFILL }},

		/* AC Descriptor DTLS Policy Flags... */
		{ &hf_capwap_msg_element_type_ac_descriptor_dtls_policy,
		{ "DTLS Policy Flags",	"capwap.control.message_element.ac_descriptor.dtls_policy", 
			FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_ac_descriptor_dtls_policy_d,
		{ "DTLS-Enabled Data Channel Supported", "capwap.control.message_element.ac_descriptor.dtls_policy.d", 
			FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x04,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_ac_descriptor_dtls_policy_c,
		{ "Clear Text Data Channel Supported",	"capwap.control.message_element.ac_descriptor.dtls_policy.c", 
			FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x02,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_ac_descriptor_dtls_policy_r,
		{ "Reserved",	"capwap.control.message_element.ac_descriptor.dtls_policy.r", 
			FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0xF9,
			NULL, HFILL }},

		{ &hf_capwap_msg_element_type_ac_information_vendor,
		{ "AC Information Vendor",	"capwap.control.message_element.ac_information.vendor", 
			FT_UINT32, BASE_DEC, VALS(sminmpec_values), 0x00,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_ac_information_type,
		{ "AC Information Type",	"capwap.control.message_element.ac_information.type", 
			FT_UINT16, BASE_DEC, VALS(ac_information_type_vals), 0x00,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_ac_information_length,
		{ "AC Information Lenght",	"capwap.control.message_element.ac_information.length",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_capwap_msg_element_type_ac_information_value,
		{ "AC Information Value",	"capwap.control.message_element.ac_information.value",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }}, 
		{ &hf_capwap_msg_element_type_ac_information_hardware_version,
		{ "AC Hardware Version",	"capwap.control.message_element.ac_information.hardware_version",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_ac_information_software_version,
		{ "AC Software Version",	"capwap.control.message_element.ac_information.software_version",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		/* CAPWAP Control IPvX Address*/
		{ &hf_capwap_msg_element_type_capwap_control_ipv4,
		{ "Control IP Address",	"capwap.control.message_element.message_element.capwap_control_ipv4", 
			FT_IPv4, BASE_NONE, NULL, 0x00,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_capwap_control_wtp_count,
		{ "Control WTP Count",	"capwap.control.message_element.capwap_control_wtp_count", 
			FT_UINT16, BASE_DEC, NULL, 0x00,
			NULL, HFILL }},

		{ &hf_capwap_msg_element_type_ac_name,
		{ "AC Name",	"capwap.control.message_element.ac_name", 
			FT_STRING, BASE_NONE, NULL, 0x00,
			NULL, HFILL }},

		{ &hf_capwap_msg_element_type_discovery_type,
		{ "Discovery Type",	"capwap.control.message_element.discovery_type", 
			FT_UINT8, BASE_DEC, VALS(discovery_type_vals), 0x00,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_wtp_board_data_vendor,
		{ "WTP Board Data Vendor",	"capwap.control.message_element.wtp_board_data.vendor", 
			FT_UINT32, BASE_DEC, VALS(sminmpec_values), 0x00,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_wtp_board_data_type,
		{ "Board Data Type",	"capwap.control.message_element.wtp_board_data.type",
			FT_UINT16, BASE_DEC, VALS(board_data_type_vals), 0x00,
			NULL, HFILL }},

		{ &hf_capwap_msg_element_type_wtp_board_data_length,
		{ "Board Data Length",	"capwap.control.message_element.wtp_board_data.length",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			NULL, HFILL }},

		{ &hf_capwap_msg_element_type_wtp_board_data_value,
		{ "Board Data Value",	"capwap.control.message_element.wtp_board_data.value",
			FT_BYTES, BASE_NONE, NULL, 0x00,
			NULL, HFILL }}, 
		{ &hf_capwap_msg_element_type_wtp_board_data_wtp_model_number,
		{ "WTP Model Number",	"capwap.control.message_element.wtp_board_data.wtp_model_number",
			FT_STRING, BASE_DEC, NULL, 0x00,
			NULL, HFILL }}, 
		{ &hf_capwap_msg_element_type_wtp_board_data_wtp_serial_number,
		{ "WTP Serial Number",	"capwap.control.message_element.wtp_board_data.wtp_serial_number",
			FT_STRING, BASE_NONE, NULL, 0x00,
			NULL, HFILL }}, 
		{ &hf_capwap_msg_element_type_wtp_board_data_wtp_board_id,
		{ "WTP Board ID",	"capwap.control.message_element.wtp_board_data.wtp_board_id",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }}, 	
		{ &hf_capwap_msg_element_type_wtp_board_data_wtp_board_revision,
		{ "WTP Board Revision",	"capwap.control.message_element.wtp_board_data.wtp_board_revision",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }}, 	
		{ &hf_capwap_msg_element_type_wtp_board_data_base_mac_address,
		{ "Base Mac Address",	"capwap.control.message_element.wtp_board_data.base_mac_address",
			FT_ETHER, BASE_NONE, NULL, 0x0,
			NULL, HFILL }}, 	

		{ &hf_capwap_msg_element_type_wtp_descriptor_max_radios,
		{ "Max Radios",	"capwap.control.message_element.wtp_descriptor.max_radios", 
			FT_UINT8, BASE_DEC, NULL, 0x00,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_wtp_descriptor_radio_in_use,
		{ "Radio in use",	"capwap.control.message_element.wtp_descriptor.radio_in_use", 
			FT_UINT8, BASE_DEC, NULL, 0x00,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_wtp_descriptor_number_encrypt,
		{ "Encryption Capabilities (Number)",	"capwap.control.message_element.wtp_descriptor.number_encrypt", 
			FT_UINT8, BASE_DEC, NULL, 0x00,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_wtp_descriptor_encrypt_reserved,
		{ "Reserved (Encrypt)",	"capwap.control.message_element.wtp_descriptor.encrypt_reserved", 
			FT_UINT8, BASE_DEC, NULL, 0x00,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_wtp_descriptor_encrypt_wbid,
		{ "Encrypt WBID",	"capwap.control.message_element.wtp_descriptor.encrypt_wbid", 
			FT_UINT8, BASE_DEC, VALS(type_wbid), 0x00,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_wtp_descriptor_encrypt_capabilities,
		{ "Encryption Capabilities",	"capwap.control.message_element.wtp_descriptor.encrypt_capabilities", 
			FT_UINT16, BASE_DEC, NULL, 0x00,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_wtp_descriptor_vendor,
		{ "WTP Descriptor Vendor",	"capwap.control.message_element.wtp_descriptor.vendor", 
			FT_UINT32, BASE_DEC, VALS(sminmpec_values), 0x00,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_wtp_descriptor_type,
		{ "Descriptor Type",	"capwap.control.message_element.wtp_descriptor.type",
			FT_UINT16, BASE_DEC, VALS(wtp_descriptor_type_vals), 0x0,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_wtp_descriptor_length,
		{ "Descriptor Lenght",	"capwap.control.message_element.wtp_descriptor.length",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_wtp_descriptor_value,
		{ "Descriptor Value",	"capwap.control.message_element.wtp_descriptor.value",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }}, 
		{ &hf_capwap_msg_element_type_wtp_descriptor_hardware_version,
		{ "WTP Hardware Version",	"capwap.control.message_element.wtp_descriptor.hardware_version",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_wtp_descriptor_active_software_version,
		{ "WTP Active Software Version",	"capwap.control.message_element.wtp_descriptor.active_software_version",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_wtp_descriptor_boot_version,
		{ "WTP Boot Version",	"capwap.control.message_element.wtp_descriptor.boot_version",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_wtp_descriptor_other_software_version,
		{ "WTP Other Software Version",	"capwap.control.message_element.wtp_descriptor.other_software_version",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_capwap_msg_element_type_wtp_frame_tunnel_mode,
		{ "WTP Frame Tunnel Mode",	"capwap.control.message_element.wtp_frame_tunnel_mode", 
			FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_wtp_frame_tunnel_mode_n,
		{ "Native Frame Tunnel Mode",	"capwap.control.message_element.wtp_frame_tunnel_mode.n", 
			FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x08,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_wtp_frame_tunnel_mode_e,
		{ "802.3 Frame Tunnel Mode",	"capwap.control.message_element.wtp_frame_tunnel_mode.e", 
			FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x04,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_wtp_frame_tunnel_mode_l,
		{ "Local Bridging",	"capwap.control.message_element.wtp_frame_tunnel_mode.l", 
			FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x02,
			NULL, HFILL }},
		{ &hf_capwap_msg_element_type_wtp_frame_tunnel_mode_r,
		{ "Reserved",	"capwap.control.message_element.wtp_frame_tunnel_mode.r", 
			FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0xF1,
			NULL, HFILL }},

		{ &hf_capwap_msg_element_type_wtp_mac_type,
			{ "WTP MAC Type",           "capwap.control.message_element.wtp_mac_type",
			FT_UINT8, BASE_DEC, VALS(wtp_mac_vals), 0x0,
			"The MAC mode of operation supported by the WTP", HFILL }},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_capwap,
	};

	/* Register the protocol name and description */
	proto_capwap = proto_register_protocol("Control And Provisioning of Wireless Access Points", "CAPWAP", "capwap");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_capwap, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));

	/* Register preferences module (See Section 2.6 for more on preferences) */
	capwap_module = prefs_register_protocol(proto_capwap,proto_reg_handoff_capwap);

 	prefs_register_uint_preference(capwap_module, "udp.port.control", "CAPWAP Control UDP Port",
				 "Set the port for CAPWAP Control messages (if other"
				 " than the default of 5246)",
				 10, &global_capwap_control_udp_port);

	prefs_register_uint_preference(capwap_module, "udp.port.data", "CAPWAP Data UDP Port",
				 "Set the port for CAPWAP Data messages (if other"
				 " than the default of 5247)",
				 10, &global_capwap_data_udp_port);
}

void
proto_reg_handoff_capwap(void)
{
	static gboolean inited = FALSE;
  	static dissector_handle_t capwap_control_handle, capwap_data_handle;
	static guint capwap_control_udp_port, capwap_data_udp_port;
	
	if (!inited) {
 		capwap_control_handle = create_dissector_handle(dissect_capwap_control, proto_capwap);
		capwap_data_handle = create_dissector_handle(dissect_capwap_data, proto_capwap);
		inited = TRUE;
	} else {
		dissector_delete("udp.port", capwap_control_udp_port, capwap_control_handle);
		dissector_delete("udp.port", capwap_data_udp_port, capwap_data_handle);
	}

	dissector_add("udp.port", global_capwap_control_udp_port, capwap_control_handle);
	dissector_add("udp.port", global_capwap_data_udp_port, capwap_data_handle);

	capwap_control_udp_port = global_capwap_control_udp_port;
	capwap_data_udp_port 	= global_capwap_data_udp_port;

	dtls_handle 	= find_dissector("dtls");
	ieee8023_handle = find_dissector("eth_withoutfcs");
	ieee80211_handle = find_dissector("wlan");
	data_handle = find_dissector("data");
}
