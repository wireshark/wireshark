/* packet-btsdp.c
 * Routines for Bluetooth SDP dissection
 * Copyright 2002, Wolfgang Hansmann <hansmann@cs.uni-bonn.de>
 * Copyright 2006, Ronnie Sahlberg
 *     - refactored for Wireshark checkin
 * Copyright 2013, Michal Labedzki  for Tieto Corporation
 *     - support SDP fragmentation (Continuation State)
 *     - implement DI 1.3
 *     - dissect profile specific attributes
 *     - fix service recognize
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/etypes.h>
#include <epan/tap.h>
#include <epan/ip_opts.h>
#include <epan/wmem/wmem.h>

#include "packet-btsdp.h"
#include "packet-btl2cap.h"
#include "packet-bluetooth-hci.h"

static gint proto_btsdp                                                    = -1;

static gint hf_pdu_id                                                      = -1;
static gint hf_tid                                                         = -1;
static gint hf_parameter_length                                            = -1;
static gint hf_ssr_total_count                                             = -1;
static gint hf_ssr_current_count                                           = -1;
static gint hf_error_code                                                  = -1;
static gint hf_attribute_list_byte_count                                   = -1;
static gint hf_maximum_service_record_count                                = -1;
static gint hf_maximum_attribute_byte_count                                = -1;
static gint hf_continuation_state_length                                   = -1;
static gint hf_continuation_state_value                                    = -1;
static gint hf_fragment                                                    = -1;
static gint hf_data_element_size                                           = -1;
static gint hf_data_element_type                                           = -1;
static gint hf_data_element_var_size                                       = -1;
static gint hf_data_element_value                                          = -1;
static gint hf_sdp_service_record_handle                                   = -1;
static gint hf_service_attribute_id_generic                                = -1;

static gint ett_btsdp                                     = -1;
static gint ett_btsdp_ssr                                 = -1;
static gint ett_btsdp_des                                 = -1;
static gint ett_btsdp_attribute                           = -1;
static gint ett_btsdp_attribute_id                        = -1;
static gint ett_btsdp_attribute_value                     = -1;
static gint ett_btsdp_attribute_idlist                    = -1;
static gint ett_btsdp_service_search_pattern              = -1;
static gint ett_btsdp_continuation_state                  = -1;
static gint ett_btsdp_data_element                        = -1;
static gint ett_btsdp_data_element_value                  = -1;
static gint ett_btsdp_reassembled                         = -1;

static gint btsdp_tap = -1;

static emem_tree_t *tid_requests        = NULL;
static emem_tree_t *continuation_states = NULL;
static emem_tree_t *service_infos       = NULL;

static sdp_package_t sdp_package;

typedef struct _tid_request_t {
    guint32  interface_id;
    guint32  adapter_id;
    guint32  chandle;
    guint32  psm;
    guint32  tid;
    guint32  pdu_type;

    guint8  *continuation_state;
    guint8   continuation_state_length;

    guint32  data_length;
    guint8  *data;
} tid_request_t;

typedef struct _continuation_state_data_t {
    guint32  interface_id;
    guint32  adapter_id;
    guint32  chandle;
    guint32  psm;
    guint32  pdu_type;
    guint32  continuation_state[5];

    guint32  data_length;
    guint8  *data;
} continuation_state_data_t;

#define PDU_TYPE_SERVICE_SEARCH            0x00
#define PDU_TYPE_SERVICE_ATTRIBUTE         0x01
#define PDU_TYPE_SERVICE_SEARCH_ATTRIBUTE  0x02

#define MAX_SDP_LEN 1024

extern value_string_ext ext_usb_vendors_vals;

static const value_string vs_pduid[] = {
    { 0x01,   "Error Response" },
    { 0x02,   "Service Search Request" },
    { 0x03,   "Service Search Response" },
    { 0x04,   "Service Attribute Request" },
    { 0x05,   "Service Attribute Response" },
    { 0x06,   "Service Search Attribute Request" },
    { 0x07,   "Service Search Attribute Response" },
    { 0, NULL }
};

static const value_string vs_general_attribute_id[] = {
    { 0x0000,   "Service Record Handle" },
    { 0x0001,   "Service Class ID List" },
    { 0x0002,   "Service Record State" },
    { 0x0003,   "Service ID" },
    { 0x0004,   "Protocol Descriptor List" },
    { 0x0005,   "Browse Group List" },
    { 0x0006,   "Language Base Attribute ID List" },
    { 0x0007,   "Service Info Time To Live" },
    { 0x0008,   "Service Availability" },
    { 0x0009,   "Bluetooth Profile Descriptor List" },
    { 0x000A,   "Documentation URL" },
    { 0x000B,   "Client Executable URL" },
    { 0x000C,   "Icon URL" },
    { 0x000D,   "Additional Protocol Descriptor Lists" },
    /* Localized string default offset is 0x100,
       the rest based on Language Base Attribute ID List */
    { 0x0100,   "Service Name" },
    { 0x0101,   "Service Description" },
    { 0x0102,   "Provider Name" },
    { 0, NULL }
};

static const value_string vs_a2dp_attribute_id[] = {
    { 0x0311,   "Supported Features" },
    { 0, NULL }
};

static const value_string vs_avrcp_attribute_id[] = {
    { 0x0311,   "Supported Features" },
    { 0, NULL }
};

static const value_string vs_bip_imaging_responder_attribute_id[] = {
    { 0x0200,   "GOEP L2CAP PSM" },
    { 0x0310,   "Supported Capabilities" },
    { 0x0311,   "Supported Features" },
    { 0x0312,   "Supported Functions" },
    { 0x0313,   "Total Imaging Data Capacity" },
    { 0, NULL }
};

static const value_string vs_bip_imaging_other_attribute_id[] = {
    { 0x0200,   "GOEP L2CAP PSM" },
    { 0x0312,   "Supported Functions" },
    { 0, NULL }
};

static const value_string vs_bpp_attribute_id[] = {
    { 0x0350,   "Document Formats Supported" },
    { 0x0352,   "Character Repertoires Supported" },
    { 0x0354,   "XHTML-Print Image Formats Supported" },
    { 0x0356,   "Color Supported" },
    { 0x0358,   "1284ID" },
    { 0x035A,   "Printer Name" },
    { 0x035C,   "Printer Location" },
    { 0x035E,   "Duplex Supported" },
    { 0x0360,   "Media Types Supported" },
    { 0x0362,   "Max Media Width" },
    { 0x0364,   "Max Media Length" },
    { 0x0366,   "Enhanced Layout Supported" },
    { 0x0368,   "RUI Formats Supported" },
    { 0x0370,   "Reference Printing RUI Supported" },
    { 0x0372,   "Direct Printing RUI Supported" },
    { 0x0374,   "Reference Printing Top URL" },
    { 0x0376,   "Direct Printing Top URL" },
    { 0x037A,   "Device Name" },
    { 0, NULL }
};

static const value_string vs_bpp_reflected_ui_attribute_id[] = {
    { 0x0368,   "RUI Formats Supported" },
    { 0x0378,   "Printer Admin RUI Top URL" },
    { 0, NULL }
};

static const value_string vs_ctp_attribute_id[] = {
    { 0x0301,   "External Network" },
    { 0, NULL }
};

static const value_string vs_did_attribute_id[] = {
    { 0x0200,   "Specification ID" },
    { 0x0201,   "Vendor ID" },
    { 0x0202,   "Product ID" },
    { 0x0203,   "Version" },
    { 0x0204,   "Primary Record" },
    { 0x0205,   "Vendor ID Source" },
    { 0, NULL }
};

static const value_string vs_dun_attribute_id[] = {
    { 0x0305,   "Audio Feedback Support" },
    { 0x0306,   "Escape Sequence" },
    { 0, NULL }
};


static const value_string vs_fax_attribute_id[] = {
    { 0x0302,   "Fax Class 1 Support" },
    { 0x0303,   "Fax Class 2.0 Support" },
    { 0x0304,   "Fax Class 2 Support (vendor-specific class)" },
    { 0x0305,   "Audio Feedback Support" },
    { 0, NULL }
};

static const value_string vs_ftp_attribute_id[] = {
    { 0x0200,   "GOEP L2CAP PSM" },
    { 0, NULL }
};

static const value_string vs_gnss_attribute_id[] = {
    { 0x0200,   "Supported Features" },
    { 0, NULL }
};

static const value_string vs_hfp_gw_attribute_id[] = {
    { 0x0311,   "Supported Features" },
    { 0, NULL }
};

static const value_string vs_hfp_ag_attribute_id[] = {
    { 0x0301,   "Network" },
    { 0x0311,   "Supported Features" },
    { 0, NULL }
};

static const value_string vs_hcrp_attribute_id[] = {
    { 0x0300,   "1284ID" },
    { 0x0302,   "Device Name" },
    { 0x0304,   "Friendly Name" },
    { 0x0306,   "Device Location" },
    { 0, NULL }
};

static const value_string vs_hsp_attribute_id[] = {
    { 0x0302,   "Remote Audio Volume Control" },
    { 0, NULL }
};

static const value_string vs_hdp_attribute_id[] = {
    { 0x0200,   "Support Features List" },
    { 0x0301,   "Data Exchange Specification" },
    { 0x0302,   "MCAP Supported Procedures" },
    { 0, NULL }
};

static const value_string vs_hid_attribute_id[] = {
    { 0x0200,   "Device Release Number" },
    { 0x0201,   "Parser Version" },
    { 0x0202,   "Device Subclass" },
    { 0x0203,   "Country Code" },
    { 0x0204,   "Virtual Cable" },
    { 0x0205,   "Reconnect Initiate" },
    { 0x0206,   "Descriptor List" },
    { 0x0207,   "LANG ID Base List" },
    { 0x0208,   "SDP Disable" },
    { 0x0209,   "Battery Power" },
    { 0x020A,   "Remote Wake" },
    { 0x020B,   "Profile Version" },
    { 0x020C,   "Supervision Timeout" },
    { 0x020D,   "Normally Connectable" },
    { 0x020E,   "BootDevice" },
    { 0x020F,   "SSR Host Max Latency" },
    { 0x0210,   "SSR Host Min Timeout" },
    { 0, NULL }
};

static const value_string vs_wap_attribute_id[] = {
    { 0x0306,   "Network Address" },
    { 0x0307,   "WAP Gateway" },
    { 0x0308,   "Home Page URL" },
    { 0x0309,   "WAP Stack Type" },
    { 0, NULL }
};

static const value_string vs_map_mas_attribute_id[] = {
    { 0x0315,   "MAS Instance ID" },
    { 0x0316,   "Supported Message Types" },
    { 0, NULL }
};

static const value_string vs_opp_attribute_id[] = {
    { 0x0200,   "GOEP L2CAP PSM" },
    { 0x0300,   "Service Version" },
    { 0x0303,   "Supported Formats List" },
    { 0, NULL }
};

static const value_string vs_pan_nap_attribute_id[] = {
    { 0x0200,   "IP Subnet" }, /* Deprecated */
    { 0x030A,   "Security Description" },
    { 0x030B,   "Net Access Type" },
    { 0x030C,   "Max Net Access Rate" },
    { 0x030D,   "IPv4Subnet" },
    { 0x030E,   "IPv6Subnet" },
    { 0, NULL }
};

static const value_string vs_pan_gn_attribute_id[] = {
    { 0x0200,   "IP Subnet" }, /* Deprecated */
    { 0x030A,   "Security Description" },
    { 0x030D,   "IPv4Subnet" },
    { 0x030E,   "IPv6Subnet" },
    { 0, NULL }
};

static const value_string vs_pan_panu_attribute_id[] = {
    { 0x030A,   "Security Description" },
    { 0, NULL }
};

static const value_string vs_pbap_attribute_id[] = {
    { 0x0314,   "Supported Repositories" },
    { 0, NULL }
};

static const value_string vs_synch_attribute_id[] = {
    { 0x0301,   "Supported Data Stores List" },
    { 0, NULL }
};

static const value_string did_vendor_id_source_vals[] = {
    { 0x0001,   "Bluetooth SIG" },
    { 0x0002,   "USB Implementer's Forum" },
    { 0, NULL }
};

static const value_string synch_supported_data_store_vals[] = {
    { 0x01,   "Phonebook" },
    { 0x03,   "Calendar" },
    { 0x05,   "Notes" },
    { 0x06,   "Messages" },
    { 0, NULL }
};

static const value_string ctp_external_network_vals[] = {
    { 0x01,   "Phonebook" },
    { 0x02,   "ISDN" },
    { 0x03,   "GSM" },
    { 0x04,   "CDMA" },
    { 0x05,   "Analogue Cellular" },
    { 0x06,   "Packet-switched" },
    { 0x07,   "Other" },
    { 0, NULL }
};

static const value_string wap_stack_type_vals[] = {
    { 0x01,   "Connectionless" },
    { 0x02,   "Connection Oriented" },
    { 0x03,   "All (Connectionless + Connection Oriented)" },
    { 0, NULL }
};

static const value_string wap_gateway_vals[] = {
    { 0x01,   "Origin Server" },
    { 0x02,   "Proxy" },
    { 0, NULL }
};

static const value_string hdp_data_exchange_specification_vals[] = {
    { 0x01,   "ISO/IEEE 11073-20601 (Health informatics)" },
    { 0, NULL }
};

static const range_string hdp_mdep_id_rvals[] = {
    { 0x00, 0x00,  "Reserved For Echo Test Function" },
    { 0x01, 0x7F,  "Available for use" },
    { 0x80, 0xFF,  "Reserved by MCAP" },
    { 0, 0, NULL }
};

static const value_string hdp_mdep_role_vals[] = {
    { 0x00,   "Source" },
    { 0x01,   "Sink" },
    { 0, NULL }
};

static const value_string pan_security_description_vals[] = {
    { 0x0000,   "None" },
    { 0x0001,   "Service-level Enforced Security" },
    { 0x0002,   "802.1x Security" },
    { 0, NULL }
};

static const value_string opp_supported_format_vals[] = {
    { 0x01,   "vCard 2.1" },
    { 0x02,   "vCard 3.0" },
    { 0x03,   "vCal 1.0" },
    { 0x04,   "iCal 2.0" },
    { 0x05,   "vNote" },
    { 0x06,   "vMessage" },
    { 0xFF,   "AllFormats" },
    { 0, NULL }
};

static const value_string pan_net_access_type_vals[] = {
    { 0x0000,   "PSTN" },
    { 0x0001,   "ISDN" },
    { 0x0002,   "DSL" },
    { 0x0003,   "Cable Modem" },
    { 0x0004,   "10Mb Ethernet" },
    { 0x0005,   "100Mb Ethernet" },
    { 0x0006,   "4Mb Token Ring" },
    { 0x0007,   "16Mb Token Ring" },
    { 0x0008,   "100Mb Token Ring" },
    { 0x0009,   "FDDI" },
    { 0x000A,   "GSM" },
    { 0x000B,   "CDMA" },
    { 0x000c,   "GPRS" },
    { 0x000D,   "3G" },
    { 0xFFFE,   "Other" },
    { 0, NULL }
};

static const value_string hfp_gw_network_vals[] = {
    { 0x00,   "No ability to reject a call" },
    { 0x01,   "Ability to reject a call" },
    { 0, NULL }
};

static const value_string hid_device_subclass_type_vals[] = {
    { 0x00,   "Not Keyboard / Not Pointing Device" },
    { 0x01,   "Keyboard" },
    { 0x02,   "Pointing Device" },
    { 0x03,   "Combo keyboard/pointing device" },
    { 0, NULL }
};

static const value_string hid_device_subclass_subtype_vals[] = {
    { 0x00,   "Uncategorized device" },
    { 0x01,   "Joystick" },
    { 0x02,   "Gamepad" },
    { 0x03,   "Remote control" },
    { 0x04,   "Sensing device" },
    { 0x05,   "Digitizer tablet" },
    { 0x06,   "Card Reader" },
    { 0, NULL }
};

/* USB HID 1.11 bCountryCode */
static const value_string hid_country_code_vals[] = {
    {  0,   "Not Supported" },
    {  1,   "Arabic" },
    {  2,   "Belgian" },
    {  3,   "Canadian-Bilingual" },
    {  4,   "Canadian-French" },
    {  5,   "Czech Republic" },
    {  6,   "Danish" },
    {  7,   "Finnish" },
    {  8,   "French" },
    {  9,   "German" },
    { 10,   "Greek" },
    { 11,   "Hebrew" },
    { 12,   "Hungary" },
    { 13,   "International (ISO)" },
    { 14,   "Italian" },
    { 15,   "Japan (Katakana)" },
    { 16,   "Korean" },
    { 17,   "Latin American" },
    { 18,   "Netherlands/Dutch" },
    { 19,   "Norwegian" },
    { 20,   "Persian (Farsi)" },
    { 21,   "Poland" },
    { 22,   "Portuguese" },
    { 23,   "Russia" },
    { 24,   "Slovakia" },
    { 25,   "Spanish" },
    { 26,   "Swedish" },
    { 27,   "Swiss/French" },
    { 28,   "Swiss/German" },
    { 29,   "Switzerland" },
    { 30,   "Taiwan" },
    { 31,   "Turkish-Q" },
    { 32,   "UK" },
    { 33,   "US" },
    { 34,   "Yugoslavia" },
    { 35,   "Turkish-F" },
    { 0, NULL }
};


static const value_string descriptor_list_type_vals[] = {
    { 0x22,  "Report" },
    { 0x23,  "Physical"},
    { 0, NULL }
};


/* service UUIDs */
static const value_string vs_service_classes[] = {
    { 0x0001,   "SDP" },
    { 0x0002,   "UDP" },
    { 0x0003,   "RFCOMM" },
    { 0x0004,   "TCP" },
    { 0x0005,   "TCS-BIN" },
    { 0x0006,   "TCS-AT" },
    { 0x0007,   "ATT" },
    { 0x0008,   "OBEX" },
    { 0x0009,   "IP" },
    { 0x000A,   "FTP" },
    { 0x000C,   "HTTP" },
    { 0x000E,   "WSP" },
    { 0x000F,   "BNEP" },
    { 0x0010,   "UPNP" },
    { 0x0011,   "HIDP" },
    { 0x0012,   "Hardcopy Control Channel" },
    { 0x0014,   "Hardcopy Data Channel" },
    { 0x0016,   "Hardcopy Notification" },
    { 0x0017,   "AVCTP" },
    { 0x0019,   "AVDTP" },
    { 0x001B,   "CMPT" },
    { 0x001D,   "UDI C-Plane" }, /* unofficial */
    { 0x001E,   "MCAP Control Channel" },
    { 0x001F,   "MCAP Data Channel" },
    { 0x0100,   "L2CAP" },
    { 0x1000,   "Service Discovery Server Service Class ID" },
    { 0x1001,   "Browse Group Descriptor Service Class ID" },
    { 0x1002,   "Public Browse Group" },
    { 0x1101,   "Serial Port" },
    { 0x1102,   "LAN Access Using PPP" },
    { 0x1103,   "Dialup Networking" },
    { 0x1104,   "IrMC Sync" },
    { 0x1105,   "OBEX Object Push" },
    { 0x1106,   "OBEX File Transfer" },
    { 0x1107,   "IrMC Sync Command" },
    { 0x1108,   "Headset" },
    { 0x1109,   "Cordless Telephony" },
    { 0x110A,   "Audio Source" },
    { 0x110B,   "Audio Sink" },
    { 0x110C,   "A/V Remote Control Target" },
    { 0x110D,   "Advanced Audio Distribution" },
    { 0x110E,   "A/V Remote Control" },
    { 0x110F,   "Video Conferencing" },
    { 0x1110,   "Intercom" },
    { 0x1111,   "Fax" },
    { 0x1112,   "Headset Audio Gateway" },
    { 0x1113,   "WAP" },
    { 0x1114,   "WAP Client" },
    { 0x1115,   "PANU" },
    { 0x1116,   "NAP" },
    { 0x1117,   "GN" },
    { 0x1118,   "Direct Printing" },
    { 0x1119,   "Reference Printing" },
    { 0x111A,   "Imaging" },
    { 0x111B,   "Imaging Responder" },
    { 0x111C,   "Imaging Automatic Archive" },
    { 0x111D,   "Imaging Referenced Objects" },
    { 0x111E,   "Handsfree" },
    { 0x111F,   "Handsfree Audio Gateway" },
    { 0x1120,   "Direct Printing Reference Objects Service" },
    { 0x1121,   "Reflected UI" },
    { 0x1122,   "Basic Printing" },
    { 0x1123,   "Printing Status" },
    { 0x1124,   "Human Interface Device Service" },
    { 0x1125,   "Hardcopy Cable Replacement" },
    { 0x1126,   "HCR Print" },
    { 0x1127,   "HCR Scan" },
    { 0x1128,   "Common ISDN Access" },
    { 0x1129,   "Video Conferencing GW" },
    { 0x112A,   "UDI MT" },
    { 0x112B,   "UDI TA" },
    { 0x112C,   "Audio/Video" },
    { 0x112D,   "SIM Access" },
    { 0x112E,   "Phonebook Access Client" },
    { 0x112F,   "Phonebook Access Server" },
    { 0x1130,   "Phonebook Access Profile" },
    { 0x1131,   "Headset HS" },
    { 0x1132,   "Message Access Server" },
    { 0x1133,   "Message Notification Server" },
    { 0x1134,   "Message Access Profile" },
    { 0x1135,   "Global Navigation Satellite System" },
    { 0x1136,   "Global Navigation Satellite System Server" },
    { 0x1200,   "PnP Information" },
    { 0x1201,   "Generic Networking" },
    { 0x1202,   "Generic File Transfer" },
    { 0x1203,   "Generic Audio" },
    { 0x1204,   "Generic Telephony" },
    { 0x1205,   "UPNP Service" },
    { 0x1206,   "UPNP IP Service" },
    { 0x1300,   "ESDP UPNP_IP PAN" },
    { 0x1301,   "ESDP UPNP IP LAP" },
    { 0x1302,   "ESDP UPNP L2CAP" },
    { 0x1303,   "Video Source" },
    { 0x1304,   "Video Sink" },
    { 0x1305,   "Video Distribution" },
    { 0x1400,   "Health Device Profile" },
    { 0x1401,   "Health Device Source" },
    { 0x1402,   "Health Device Sink" },
    { 0x1800,   "Generic Access Profile" },
    { 0x1801,   "Generic Attribute Profile" },
    { 0, NULL }
};

value_string_ext vs_service_classes_ext = VALUE_STRING_EXT_INIT(vs_service_classes);

static const value_string vs_error_code[] = {
    { 0x0001,   "Invalid/Unsupported SDP Version" },
    { 0x0002,   "Invalid Service Record Handle" },
    { 0x0003,   "Invalid Request Syntax" },
    { 0x0004,   "Invalid PDU Size" },
    { 0x0005,   "Invalid Continuation State" },
    { 0x0006,   "Insufficient Resources to Satisfy Request" },
    { 0, NULL }
};

static const value_string vs_data_element_size[] = {
    { 0x00,   "1 byte (0 bytes if Nil)" },
    { 0x01,   "2 bytes" },
    { 0x02,   "4 bytes" },
    { 0x03,   "8 bytes" },
    { 0x04,   "16 bytes" },
    { 0x05,   "uint8" },
    { 0x06,   "uint16" },
    { 0x07,   "uint32" },
    { 0, NULL }
};

static const value_string vs_data_element_type[] = {
    { 0x00,   "Nil" },
    { 0x01,   "Unsigned Integer" },
    { 0x02,   "Signed Twos-Complement Integer" },
    { 0x03,   "UUID" },
    { 0x04,   "Text string" },
    { 0x05,   "Boolean" },
    { 0x06,   "Sequence" },
    { 0x07,   "Alternative" },
    { 0x08,   "URL" },
    { 0, NULL }
};

void proto_register_btsdp(void);
void proto_reg_handoff_btsdp(void);

static gint
get_type_length(tvbuff_t *tvb, gint offset, gint *length)
{
    gint    size  = 0;
    guint8  byte;

    byte = tvb_get_guint8(tvb, offset);
    offset += 1;

    switch (byte & 0x07) {
    case 0:
        size = (byte >> 3) == 0 ? 0 : 1;
        break;
    case 1:
        size = 2;
        break;
    case 2:
        size = 4;
        break;
    case 3:
        size = 8;
        break;
    case 4:
        size = 16;
        break;
    case 5:
        size = tvb_get_guint8(tvb, offset);
        offset += 1;
        break;
    case 6:
        size = tvb_get_ntohs(tvb, offset);
        offset += 2;
        break;
    case 7:
        size = tvb_get_ntohl(tvb, offset);
        offset += 4;
        break;
    }

    *length = size;
    return offset;
}


static guint32
get_uint_by_size(tvbuff_t *tvb, gint off, gint size)
{
    switch (size) {
    case 0:
        return tvb_get_guint8(tvb, off);
    case 1:
        return tvb_get_ntohs(tvb, off);
    case 2:
        return tvb_get_ntohl(tvb, off);
    default:
        return 0xffffffff;
    }
}


static gint32
get_int_by_size(tvbuff_t *tvb, gint off, gint size)
{
    switch (size) {
    case 0:
        return tvb_get_guint8(tvb, off);
    case 1:
        return tvb_get_ntohs(tvb, off);
    case 2:
        return tvb_get_ntohl(tvb, off);
    default:
        return -1;
    }
}



static gint
dissect_continuation_state(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
        gint offset)
{
    proto_item  *cont_item;
    guint length;

    length = tvb_length_remaining(tvb, offset);
    if (length == 0)  {
        cont_item = proto_tree_add_text(tree, tvb, offset, -1, "[Malformed packet] - no Continuation State");
        expert_add_info_format(pinfo, cont_item, PI_MALFORMED, PI_WARN, "There is no Continuation State");
    } else if (length > 17) {
        cont_item = proto_tree_add_text(tree, tvb, offset, -1, "[Malformed packet] - Continuation State data is longer then 16");
        expert_add_info_format(pinfo, cont_item, PI_MALFORMED, PI_WARN, "Continuation State data is longer then 16");
    } else if (length == 1 && tvb_get_guint8(tvb, offset) == 0x00) {
        proto_tree_add_text(tree, tvb, offset, -1, "Continuation State: no (0x00)");
    } else {
        proto_item  *cont_tree;
        guint        data;
        guint8       i_data;
        guint8       continuation_state_length;

        continuation_state_length = tvb_get_guint8(tvb, offset);
        cont_item = proto_tree_add_text(tree, tvb, offset,
                1 + continuation_state_length, "Continuation State: ");
        cont_tree = proto_item_add_subtree(cont_item, ett_btsdp_continuation_state);

        proto_tree_add_item(cont_tree, hf_continuation_state_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(cont_tree, hf_continuation_state_value, tvb, offset,
                continuation_state_length, ENC_NA);

        proto_item_append_text(cont_item, "yes (");
        for (i_data = 0; i_data < continuation_state_length - 1; ++i_data) {
            data = tvb_get_guint8(tvb, offset);
            proto_item_append_text(cont_item, "%02X ", data);
            offset += 1;
        }

        data = tvb_get_guint8(tvb, offset);
        proto_item_append_text(cont_item, "%02X)", data);
        offset += 1;
    }

    return offset;
}

static gint
reassemble_continuation_state(tvbuff_t *tvb, packet_info *pinfo,
        gint offset, guint tid, gboolean is_request,
        gint attribute_list_byte_offset, gint attribute_list_byte_count,
        guint32 pdu_type, tvbuff_t **new_tvb, gboolean *is_first,
        gboolean *is_continued)
{
    guint              length;
    btl2cap_data_t    *l2cap_data;
    tid_request_t     *tid_request;
    continuation_state_data_t *continuation_state_data;
    emem_tree_key_t    key[12];
    guint32            k_interface_id;
    guint32            k_adapter_id;
    guint32            k_chandle;
    guint32            k_psm;
    guint32            k_tid;
    guint32            k_pdu_type;
    guint32            k_frame_number;
    guint8             *k_continuation_state;
    guint32            interface_id;
    guint32            adapter_id;
    guint32            chandle;
    guint32            psm;
    guint32            frame_number;
    guint32           *continuation_state_array;

    l2cap_data = (btl2cap_data_t *) pinfo->private_data;
    if (new_tvb) *new_tvb = NULL;

    interface_id = l2cap_data->interface_id;
    adapter_id   = l2cap_data->adapter_id;
    chandle      = l2cap_data->chandle;
    psm          = l2cap_data->psm;
    frame_number = pinfo->fd->num;

    k_interface_id = interface_id;
    k_adapter_id   = adapter_id;
    k_chandle      = chandle;
    k_psm          = psm;
    k_tid          = tid;
    k_frame_number = frame_number;

    key[0].length = 1;
    key[0].key    = &k_interface_id;
    key[1].length = 1;
    key[1].key    = &k_adapter_id;
    key[2].length = 1;
    key[2].key    = &k_chandle;
    key[3].length = 1;
    key[3].key    = &k_psm;
    key[4].length = 1;
    key[4].key    = &k_tid;
    key[5].length = 1;
    key[5].key    = &k_frame_number;
    key[6].length = 0;
    key[6].key    = NULL;

    if (is_first) *is_first = TRUE;
    if (is_continued) *is_continued = TRUE;

    length = tvb_length_remaining(tvb, offset);
    if (length == 0)  {
        return offset;
    } else if (length > 17) {
        return offset;
    } else if (length == 1 && tvb_get_guint8(tvb, offset) == 0x00) {
        if (is_continued) *is_continued = FALSE;

        if (!pinfo->fd->flags.visited) {
            if (is_request) {
                tid_request = (tid_request_t *) wmem_new(wmem_file_scope(), tid_request_t);
                tid_request->interface_id = interface_id;
                tid_request->adapter_id   = adapter_id;
                tid_request->chandle      = chandle;
                tid_request->psm          = psm;
                tid_request->tid          = tid;

                tid_request->data         = NULL;
                tid_request->data_length  = 0;

                tid_request->pdu_type = pdu_type;

                tid_request->continuation_state        = NULL;
                tid_request->continuation_state_length = 0;

                se_tree_insert32_array(tid_requests, key, tid_request);
            } else {
                tid_request = (tid_request_t *) se_tree_lookup32_array_le(tid_requests, key);
                if (tid_request && tid_request->interface_id == interface_id &&
                        tid_request->adapter_id == adapter_id &&
                        tid_request->chandle == chandle &&
                        tid_request->psm == psm &&
                        tid_request->tid == tid) {
                    if (tid_request->continuation_state_length > 0) {
                        /* fetch tid_request->continuation_state */

                        k_continuation_state = (guint8 *) wmem_alloc0(wmem_packet_scope(), 20);
                        k_continuation_state[0] = tid_request->continuation_state_length;
                        memcpy(&k_continuation_state[1], tid_request->continuation_state, tid_request->continuation_state_length);
                        continuation_state_array = (guint32 *) k_continuation_state;

                        k_continuation_state = (guint8 *) wmem_alloc0(wmem_packet_scope(), 20);
                        k_continuation_state[0] = tid_request->continuation_state_length;
                        memcpy(&k_continuation_state[1], tid_request->continuation_state, tid_request->continuation_state_length);

                        k_interface_id       = interface_id;
                        k_adapter_id         = adapter_id;
                        k_chandle            = chandle;
                        k_psm                = psm;
                        k_pdu_type           = tid_request->pdu_type;
                        k_frame_number       = frame_number;

                        key[0].length = 1;
                        key[0].key    = &k_interface_id;
                        key[1].length = 1;
                        key[1].key    = &k_adapter_id;
                        key[2].length = 1;
                        key[2].key    = &k_chandle;
                        key[3].length = 1;
                        key[3].key    = &k_psm;
                        key[4].length = 1;
                        key[4].key    = &k_pdu_type;
                        key[5].length = 1;
                        key[5].key    = (guint32 *) &k_continuation_state[0];
                        key[6].length = 1;
                        key[6].key    = (guint32 *) &k_continuation_state[4];
                        key[7].length = 1;
                        key[7].key    = (guint32 *) &k_continuation_state[8];
                        key[8].length = 1;
                        key[8].key    = (guint32 *) &k_continuation_state[12];
                        key[9].length = 1;
                        key[9].key    = (guint32 *) &k_continuation_state[16];
                        key[10].length = 1;
                        key[10].key    = &k_frame_number;
                        key[11].length = 0;
                        key[11].key    = NULL;

                        continuation_state_data = (continuation_state_data_t *) se_tree_lookup32_array_le(continuation_states, key);
                        if (continuation_state_data && continuation_state_data->interface_id == interface_id &&
                                continuation_state_data->adapter_id == adapter_id &&
                                continuation_state_data->chandle == chandle &&
                                continuation_state_data->psm == psm &&
                                continuation_state_data->pdu_type == tid_request->pdu_type &&
                                continuation_state_data->continuation_state[0] == continuation_state_array[0] &&
                                continuation_state_data->continuation_state[1] == continuation_state_array[1] &&
                                continuation_state_data->continuation_state[2] == continuation_state_array[2] &&
                                continuation_state_data->continuation_state[3] == continuation_state_array[3] &&
                                continuation_state_data->continuation_state[4] == continuation_state_array[4]) {
                            tid_request->data = (guint8 *) wmem_alloc(wmem_file_scope(), continuation_state_data->data_length + attribute_list_byte_count);
                            tid_request->data_length = continuation_state_data->data_length + attribute_list_byte_count;
                            memcpy(tid_request->data, continuation_state_data->data, continuation_state_data->data_length);
                            tvb_memcpy(tvb, tid_request->data + continuation_state_data->data_length, attribute_list_byte_offset, attribute_list_byte_count);
                        }
                    } else {
                        tid_request->data        = (guint8 *) wmem_alloc(wmem_file_scope(), attribute_list_byte_count);
                        tid_request->data_length = attribute_list_byte_count;

                        tvb_memcpy(tvb, tid_request->data, attribute_list_byte_offset, attribute_list_byte_count);
                    }
                }
            }

            k_interface_id = interface_id;
            k_adapter_id   = adapter_id;
            k_chandle      = chandle;
            k_psm          = psm;
            k_tid          = tid;
            k_frame_number = frame_number;

            key[0].length = 1;
            key[0].key    = &k_interface_id;
            key[1].length = 1;
            key[1].key    = &k_adapter_id;
            key[2].length = 1;
            key[2].key    = &k_chandle;
            key[3].length = 1;
            key[3].key    = &k_psm;
            key[4].length = 1;
            key[4].key    = &k_tid;
            key[5].length = 1;
            key[5].key    = &k_frame_number;
            key[6].length = 0;
            key[6].key    = NULL;
        }

        /* full reassemble */
        if (!is_request) {
            tid_request = (tid_request_t *) se_tree_lookup32_array_le(tid_requests, key);
            if (tid_request && tid_request->interface_id == interface_id &&
                    tid_request->adapter_id == adapter_id &&
                    tid_request->chandle == chandle &&
                    tid_request->psm == psm &&
                    tid_request->tid == tid) {
                tvbuff_t *next_tvb;

                next_tvb = tvb_new_child_real_data(tvb, tid_request->data,
                        tid_request->data_length, tid_request->data_length);

                if (new_tvb) *new_tvb = next_tvb;
                if (tid_request->continuation_state_length) *is_first = FALSE;
            }

        }
    } else {
        guint8      *continuation_state;
        guint8       continuation_state_length;
        guint8      *packet_scope_string;

        continuation_state_length = tvb_get_guint8(tvb, offset);
        offset++;

        continuation_state = (guint8 *) wmem_alloc(wmem_file_scope(), continuation_state_length);
        packet_scope_string = tvb_bytes_to_str(tvb, offset, continuation_state_length);
        memcpy(continuation_state, packet_scope_string, continuation_state_length);

        if (!pinfo->fd->flags.visited) {
            if (is_request) {
                tid_request = (tid_request_t *) wmem_new(wmem_file_scope(), tid_request_t);
                tid_request->interface_id              = interface_id;
                tid_request->adapter_id                = adapter_id;
                tid_request->chandle                   = chandle;
                tid_request->psm                       = psm;
                tid_request->tid                       = tid;

                /* fetch data saved in continuation_state */
                tid_request->data        = NULL;
                tid_request->data_length = 0;

                tid_request->pdu_type = pdu_type;

                tid_request->continuation_state        = continuation_state;
                tid_request->continuation_state_length = continuation_state_length;

                se_tree_insert32_array(tid_requests, key, tid_request);
            } else {
                tid_request = (tid_request_t *) se_tree_lookup32_array_le(tid_requests, key);
                if (tid_request && tid_request->interface_id == interface_id &&
                        tid_request->adapter_id == adapter_id &&
                        tid_request->chandle == chandle &&
                        tid_request->psm == psm &&
                        tid_request->tid == tid) {
                    /* data comes from here and saved in previous continuation_state */

                    if (tid_request->continuation_state_length > 0) {
                        /* fetch tid_request->continuation_state */

                        k_continuation_state = (guint8 *) wmem_alloc0(wmem_packet_scope(), 20);
                        k_continuation_state[0] = tid_request->continuation_state_length;
                        memcpy(&k_continuation_state[1], tid_request->continuation_state, tid_request->continuation_state_length);
                        continuation_state_array = (guint32 *) k_continuation_state;

                        k_continuation_state = (guint8 *) wmem_alloc0(wmem_packet_scope(), 20);
                        k_continuation_state[0] = tid_request->continuation_state_length;
                        memcpy(&k_continuation_state[1], tid_request->continuation_state, tid_request->continuation_state_length);

                        k_interface_id       = interface_id;
                        k_adapter_id         = adapter_id;
                        k_chandle            = chandle;
                        k_psm                = psm;
                        k_pdu_type           = tid_request->pdu_type;
                        k_frame_number       = frame_number;

                        key[0].length = 1;
                        key[0].key    = &k_interface_id;
                        key[1].length = 1;
                        key[1].key    = &k_adapter_id;
                        key[2].length = 1;
                        key[2].key    = &k_chandle;
                        key[3].length = 1;
                        key[3].key    = &k_psm;
                        key[4].length = 1;
                        key[4].key    = &k_pdu_type;
                        key[5].length = 1;
                        key[5].key    = (guint32 *) &k_continuation_state[0];
                        key[6].length = 1;
                        key[6].key    = (guint32 *) &k_continuation_state[4];
                        key[7].length = 1;
                        key[7].key    = (guint32 *) &k_continuation_state[8];
                        key[8].length = 1;
                        key[8].key    = (guint32 *) &k_continuation_state[12];
                        key[9].length = 1;
                        key[9].key    = (guint32 *) &k_continuation_state[16];
                        key[10].length = 1;
                        key[10].key    = &k_frame_number;
                        key[11].length = 0;
                        key[11].key    = NULL;

                        continuation_state_data = (continuation_state_data_t *) se_tree_lookup32_array_le(continuation_states, key);
                        if (continuation_state_data && continuation_state_data->interface_id == interface_id &&
                                continuation_state_data->adapter_id == adapter_id &&
                                continuation_state_data->chandle == chandle &&
                                continuation_state_data->psm == psm &&
                                continuation_state_data->pdu_type == tid_request->pdu_type &&
                                continuation_state_data->continuation_state[0] == continuation_state_array[0] &&
                                continuation_state_data->continuation_state[1] == continuation_state_array[1] &&
                                continuation_state_data->continuation_state[2] == continuation_state_array[2] &&
                                continuation_state_data->continuation_state[3] == continuation_state_array[3] &&
                                continuation_state_data->continuation_state[4] == continuation_state_array[4]) {
                            tid_request->data = (guint8 *) wmem_alloc(wmem_file_scope(), continuation_state_data->data_length + attribute_list_byte_count);
                            tid_request->data_length = continuation_state_data->data_length + attribute_list_byte_count;
                            memcpy(tid_request->data, continuation_state_data->data, continuation_state_data->data_length);
                            tvb_memcpy(tvb, tid_request->data + continuation_state_data->data_length, attribute_list_byte_offset, attribute_list_byte_count);
                        }
                    } else {
                        tid_request->data        = (guint8 *) wmem_alloc(wmem_file_scope(), attribute_list_byte_count);
                        tid_request->data_length = attribute_list_byte_count;

                        tvb_memcpy(tvb, tid_request->data, attribute_list_byte_offset, attribute_list_byte_count);
                    }

                    /* save tid_request in continuation_state data */
                    k_continuation_state = (guint8 *) wmem_alloc0(wmem_packet_scope(), 20);
                    k_continuation_state[0] = continuation_state_length;
                    memcpy(&k_continuation_state[1], continuation_state, continuation_state_length);
                    continuation_state_array = (guint32 *) k_continuation_state;

                    k_continuation_state = (guint8 *) wmem_alloc0(wmem_packet_scope(), 20);
                    k_continuation_state[0] = continuation_state_length;
                    memcpy(&k_continuation_state[1], continuation_state, continuation_state_length);

                    k_interface_id       = interface_id;
                    k_adapter_id         = adapter_id;
                    k_chandle            = chandle;
                    k_psm                = psm;
                    k_pdu_type           = pdu_type;
                    k_frame_number       = frame_number;

                    key[0].length = 1;
                    key[0].key    = &k_interface_id;
                    key[1].length = 1;
                    key[1].key    = &k_adapter_id;
                    key[2].length = 1;
                    key[2].key    = &k_chandle;
                    key[3].length = 1;
                    key[3].key    = &k_psm;
                    key[4].length = 1;
                    key[4].key    = &k_pdu_type;
                    key[5].length = 1;
                    key[5].key    = (guint32 *) &k_continuation_state[0];
                    key[6].length = 1;
                    key[6].key    = (guint32 *) &k_continuation_state[4];
                    key[7].length = 1;
                    key[7].key    = (guint32 *) &k_continuation_state[8];
                    key[8].length = 1;
                    key[8].key    = (guint32 *) &k_continuation_state[12];
                    key[9].length = 1;
                    key[9].key    = (guint32 *) &k_continuation_state[16];
                    key[10].length = 1;
                    key[10].key    = &k_frame_number;
                    key[11].length = 0;
                    key[11].key    = NULL;

                    continuation_state_data = (continuation_state_data_t *) wmem_new(wmem_file_scope(), continuation_state_data_t);
                    continuation_state_data->interface_id = interface_id;
                    continuation_state_data->adapter_id = adapter_id;
                    continuation_state_data->chandle = chandle;
                    continuation_state_data->psm = psm;
                    continuation_state_data->pdu_type = pdu_type;
                    continuation_state_data->continuation_state[0] = continuation_state_array[0];
                    continuation_state_data->continuation_state[1] = continuation_state_array[1];
                    continuation_state_data->continuation_state[2] = continuation_state_array[2];
                    continuation_state_data->continuation_state[3] = continuation_state_array[3];
                    continuation_state_data->continuation_state[4] = continuation_state_array[4];
                    continuation_state_data->data = tid_request->data;
                    continuation_state_data->data_length = tid_request->data_length;

                    se_tree_insert32_array(continuation_states, key, continuation_state_data);
                }
            }

            k_interface_id = interface_id;
            k_adapter_id   = adapter_id;
            k_chandle      = chandle;
            k_psm          = psm;
            k_tid          = tid;
            k_frame_number = frame_number;

            key[0].length = 1;
            key[0].key    = &k_interface_id;
            key[1].length = 1;
            key[1].key    = &k_adapter_id;
            key[2].length = 1;
            key[2].key    = &k_chandle;
            key[3].length = 1;
            key[3].key    = &k_psm;
            key[4].length = 1;
            key[4].key    = &k_tid;
            key[5].length = 1;
            key[5].key    = &k_frame_number;
            key[6].length = 0;
            key[6].key    = NULL;
        }

        /* partial reassemble */
        if (!is_request) {
            tid_request = (tid_request_t *) se_tree_lookup32_array_le(tid_requests, key);
            if (tid_request && tid_request->interface_id == interface_id &&
                    tid_request->adapter_id == adapter_id &&
                    tid_request->chandle == chandle &&
                    tid_request->psm == psm &&
                    tid_request->tid == tid) {
                tvbuff_t *next_tvb;

                next_tvb = tvb_new_child_real_data(tvb, tid_request->data,
                        tid_request->data_length, tid_request->data_length);

                if (new_tvb) *new_tvb = next_tvb;
                if (tid_request->continuation_state_length) *is_first = FALSE;
            }

        }
    }

    return offset;
}

static gint
dissect_data_element(proto_tree *tree, proto_tree **next_tree,
        packet_info *pinfo, tvbuff_t *tvb, gint offset)
{
    proto_item  *pitem;
    proto_tree  *ptree;
    gint        new_offset;
    gint        length;
    gint        len;
    guint8      type;
    guint8      size;

    new_offset = get_type_length(tvb, offset, &length) - 1;
    type = tvb_get_guint8(tvb, offset);
    size = type & 0x07;
    type = type >> 3;


    pitem = proto_tree_add_text(tree, tvb, offset, 0,
            "Data Element: %s %s",
            val_to_str_const(type, vs_data_element_type, "Unknown Type"),
            val_to_str_const(size, vs_data_element_size, "Unknown Size"));
    ptree = proto_item_add_subtree(pitem, ett_btsdp_data_element);

    len = (new_offset - offset) + length;


    proto_item_set_len(pitem, len + 1);

    proto_tree_add_item(ptree, hf_data_element_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ptree, hf_data_element_size, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (new_offset > offset - 1) {
        proto_tree_add_uint(ptree, hf_data_element_var_size, tvb,
                offset, len - length, length);
        proto_item_append_text(pitem, (length != 1) ? " %u bytes" : " %u byte", length);
        offset += len - length;
    }

    pitem = proto_tree_add_item(ptree, hf_data_element_value, tvb, offset,  0, ENC_NA);
    if (length > tvb_length_remaining(tvb, offset)) {
        expert_add_info_format(pinfo, pitem, PI_MALFORMED, PI_WARN, "Data size exceeds the length of payload");
        length = 0;
    }
    proto_item_set_len(pitem, length);

    if (next_tree) *next_tree = proto_item_add_subtree(pitem, ett_btsdp_data_element_value);
    offset += length;

    return offset;
}


static gint
dissect_attribute_id_list(proto_tree *tree, tvbuff_t *tvb, gint offset, packet_info *pinfo)
{
    proto_item  *list_item;
    proto_tree  *list_tree;
    proto_tree  *next_tree;
    gint         start_offset;
    gint         bytes_to_go;
    guint16      id;
    const gchar *att_name;

    start_offset = offset;
    list_item = proto_tree_add_text(tree, tvb, offset, 2, "Attribute ID List");
    list_tree = proto_item_add_subtree(list_item, ett_btsdp_attribute_idlist);

    dissect_data_element(list_tree, &next_tree, pinfo, tvb, offset);

    offset = get_type_length(tvb, offset, &bytes_to_go);
    proto_item_set_len(list_item, offset - start_offset + bytes_to_go);

    while (bytes_to_go > 0) {
        guint8 byte0 = tvb_get_guint8(tvb, offset);
        dissect_data_element(next_tree, &next_tree, pinfo, tvb, offset);
        offset += 1;
        bytes_to_go -= 1;

        if (byte0 == 0x09) { /* 16 bit attribute id */
            id = tvb_get_ntohs(tvb, offset);

            /* Attribute id can be profile/service specific (not unique),
               the list can be requested for various profiles/services,
               so solve only generic attribute ids */
            att_name = val_to_str_const(id, vs_general_attribute_id, "Unknown");
            proto_tree_add_text(next_tree, tvb, offset, 2, "%s (0x%04x)", att_name, id);
            offset      += 2;
            bytes_to_go -= 2;

            col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%04x (%s) ", id, att_name);
        } else if (byte0 == 0x0a) { /* 32 bit attribute range */
            col_append_fstr(pinfo->cinfo, COL_INFO, " (0x%04x - 0x%04x) ",
                            tvb_get_ntohs(tvb, offset), tvb_get_ntohs(tvb, offset + 2));

            proto_tree_add_text(next_tree, tvb, offset, 4, "0x%04x - 0x%04x",
                        tvb_get_ntohs(tvb, offset),
                        tvb_get_ntohs(tvb, offset + 2));
            offset      += 4;
            bytes_to_go -= 4;
        } else {
            break;
        }
    }
    return offset - start_offset;
}


static gint
dissect_sdp_error_response(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
    proto_tree_add_item(tree, hf_error_code, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

static gint
dissect_sdp_type(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
        gint offset, gint attribute, guint16 service_uuid, gint service_data,
        service_info_t  *service_info, gchar **attr_val)
{
    proto_tree    *next_tree;
    gint           strpos = 0;
    gint           size;
    gchar         *str;
    guint8         byte;
    guint8         type;
    guint8         size_index;
    gint           start_offset;
    gint           new_offset;

    str          = (char *) wmem_alloc(wmem_packet_scope(), MAX_SDP_LEN + 1);
    *attr_val    = str;
    str[0]       = 0;

    byte         = tvb_get_guint8(tvb, offset);
    type         = (byte >> 3) & 0x1f;
    size_index   = byte & 0x07;

    start_offset = offset;
    new_offset = dissect_data_element(tree, &next_tree, pinfo, tvb, offset);

    offset = get_type_length(tvb, offset, &size);

    switch (type) {
    case 0:
        proto_tree_add_text(next_tree, tvb, offset, size, "Nil ");
        if (strpos<MAX_SDP_LEN) {
            g_snprintf(str+strpos, MAX_SDP_LEN-strpos, "Nil ");
        }
        break;
    case 1: {
        guint32 val = get_uint_by_size(tvb, offset, size_index);
        proto_tree_add_text(next_tree, tvb, offset, size,
                    "unsigned int %d ", val);
        if (strpos<MAX_SDP_LEN) {
            g_snprintf(str+strpos, MAX_SDP_LEN-strpos, "%u ", val);
        }
        break;
    }
    case 2: {
        guint32 val = get_int_by_size(tvb, offset, size_index);
        proto_tree_add_text(next_tree, tvb, offset, size,
                    "signed int %d ", val);
        if (strpos < MAX_SDP_LEN) {
            g_snprintf(str+strpos, MAX_SDP_LEN-strpos, "%d ", val);
        }
        break;
    }
    case 3: {
        guint32 id;
        const gchar *uuid_name;
        gchar *ptr = tvb_bytes_to_str(tvb, offset, size);

        if (size == 2) {
            id = tvb_get_ntohs(tvb, offset);
        } else {
            id = tvb_get_ntohl(tvb, offset);
        }
        uuid_name = val_to_str_ext_const(id, &vs_service_classes_ext, "Unknown service");

        proto_tree_add_text(next_tree, tvb, offset, size, "%s (0x%s) ", uuid_name, ptr);

        if (strpos < MAX_SDP_LEN) {
            g_snprintf(str+strpos, MAX_SDP_LEN-strpos, ": %s", uuid_name);
        }
        break;
    }
    case 8: /* fall through */
    case 4: {
        gchar *ptr = (gchar*)tvb_get_ephemeral_string(tvb, offset, size);

        proto_tree_add_text(next_tree, tvb, offset, size, "%s \"%s\"",
                    type == 8 ? "URL" : "String", ptr);
        if (strpos < MAX_SDP_LEN) {
            g_snprintf(str+strpos, MAX_SDP_LEN-strpos, "%s ", ptr);
        }
        break;
    }
    case 5: {
        guint8 var = tvb_get_guint8(tvb, offset);

        proto_tree_add_text(next_tree, tvb, offset, size, "%s",
                    var ? "true" : "false");
        if (strpos < MAX_SDP_LEN) {
            g_snprintf(str+strpos, MAX_SDP_LEN-strpos, "%s ", var?"true":"false");
        }
        break;
    }
    case 6: /* Data Element sequence */
    case 7: /* Data Element alternative */ {
        proto_tree *st;
        proto_item *ti;
        gint        bytes_to_go = size;
        gint        first       = 1;
        gchar      *substr;

        ti = proto_tree_add_text(next_tree, tvb, offset, size, "%s",
                     type == 6 ? "Data Element sequence" :
                     "Data Element alternative");
        st = proto_item_add_subtree(ti, ett_btsdp_des);

        if (strpos < MAX_SDP_LEN) {
            strpos += g_snprintf(str+strpos, MAX_SDP_LEN-strpos, "{ ");
        }

        while (bytes_to_go > 0) {
            if (!first) {
                if (strpos<MAX_SDP_LEN) {
                    strpos += g_snprintf(str+strpos, MAX_SDP_LEN-strpos, ", ");
                }
            } else {
                first = 0;
            }

            size = dissect_sdp_type(st, pinfo, tvb, offset, attribute, service_uuid, service_data, service_info, &substr);
            if (size < 1) {
                break;
            }
            if (strpos < MAX_SDP_LEN) {
                strpos += g_snprintf(str+strpos, MAX_SDP_LEN-strpos, "%s ", substr);
            }
            offset += size ;
            bytes_to_go -= size;
        }

        if (strpos < MAX_SDP_LEN) {
            /* strpos += */ g_snprintf(str+strpos, MAX_SDP_LEN-strpos, "} ");
        }
        break;
    }
    }

    /* make sure the string is 0 terminated */
    str[MAX_SDP_LEN]='\0';


    return new_offset - start_offset;
}

static gint
dissect_sdp_service_attribute(proto_tree *tree, tvbuff_t *tvb, gint offset,
        packet_info *pinfo, guint16 service_uuid,
        service_info_t  *service_info)
{
    proto_tree          *attribute_tree;
    proto_item          *attribute_item;
    proto_tree          *attribute_id_tree;
    proto_item          *attribute_id_item;
    proto_tree          *attribute_value_tree;
    proto_item          *attribute_value_item;
    proto_tree          *next_tree;
    gint                 size;
    const gchar         *attribute_name;
    gchar               *attribute_value;
    guint16              id;
    gint                 service_data = 0;
    gint                 hfx_attribute_id = hf_service_attribute_id_generic;
    const value_string  *name_vals = NULL;
    const guint8        *profile_speficic = "";
    gint                 new_offset;
    gint                 old_offset;

    id = tvb_get_ntohs(tvb, offset + 1);

    if (name_vals && try_val_to_str(id, name_vals)) {
        attribute_name = val_to_str(id, name_vals, "Unknown");
    } else {
        attribute_name = val_to_str(id, vs_general_attribute_id, "Unknown");
        profile_speficic = "";
        hfx_attribute_id = hf_service_attribute_id_generic;
    }

    attribute_item = proto_tree_add_text(tree, tvb, offset, -1,
                    "Service Attribute: %s%s (0x%x)", profile_speficic, attribute_name, id);
    attribute_tree = proto_item_add_subtree(attribute_item, ett_btsdp_attribute);

    attribute_id_item = proto_tree_add_text(attribute_tree, tvb, offset, 3, "Attribute ID: %s", attribute_name);
    attribute_id_tree = proto_item_add_subtree(attribute_id_item, ett_btsdp_attribute_id);

    new_offset = dissect_data_element(attribute_id_tree, &next_tree, pinfo, tvb, offset);
    proto_tree_add_item(next_tree, hfx_attribute_id, tvb, offset + 1, 2, ENC_BIG_ENDIAN);
    offset = new_offset;

    attribute_value_item = proto_tree_add_text(attribute_tree, tvb, offset, -1, "Attribute Value");
    attribute_value_tree = proto_item_add_subtree(attribute_value_item, ett_btsdp_attribute_value);

    dissect_sdp_type(attribute_value_tree, pinfo, tvb, offset, id, service_uuid,
            service_data, service_info, &attribute_value);
    old_offset = offset;
    offset = get_type_length(tvb, offset, &size);
    proto_item_append_text(attribute_item, ", value = %s", attribute_value);

    proto_item_set_len(attribute_item, 3 + size + (offset - old_offset));
    proto_item_set_len(attribute_value_item, size + (offset - old_offset));

    return offset + size;
}


static gint
dissect_sdp_service_attribute_list(proto_tree *tree, tvbuff_t *tvb, gint offset,
        packet_info *pinfo, gint length _U_)
{
    proto_item      *list_item;
    proto_tree      *list_tree;
    proto_tree      *next_tree;
    gint             start_offset = offset;
    gint             search_offset;
    gint             search_length;
    gint             len;
    guint            number_of_attributes;
    guint16          attribute;
    gint             element_length;
    gint             new_offset;
    guint16          service_uuid = 0;

    offset = get_type_length(tvb, offset, &len);

    list_item = proto_tree_add_text(tree, tvb,
            start_offset, len + (offset - start_offset), "Attribute List");
    list_tree = proto_item_add_subtree(list_item, ett_btsdp_attribute);
    dissect_data_element(list_tree, &next_tree, pinfo, tvb, start_offset);

    /* search for main service uuid */
    search_offset = offset;
    number_of_attributes = 0;
    while ((search_offset - start_offset) < len) {
        search_offset = get_type_length(tvb, search_offset, &search_length);
        attribute = tvb_get_ntohs(tvb, search_offset);

        search_offset += search_length;
        search_offset = get_type_length(tvb, search_offset, &search_length);

        if (attribute == 0x01) {
            new_offset = 0;
            while (new_offset < search_offset) {
                new_offset = get_type_length(tvb, search_offset, &element_length);
                if (element_length == 2) {
                    service_uuid = get_uint_by_size(tvb, new_offset, 1);
                } else {
                    /* Currently we do not support service uuid longer then 2 */
                    service_uuid = 0;
                }
                new_offset += element_length;
            }
        }

        search_offset += search_length;
        number_of_attributes += 1;
    }

    while ((offset - start_offset) < len) {
        offset = dissect_sdp_service_attribute(next_tree, tvb, offset, pinfo,
                service_uuid, NULL);
    }

    proto_item_set_len(list_item, offset - start_offset);
    proto_item_append_text(list_tree, " [count = %2u] (%s)",
            number_of_attributes, val_to_str_const(service_uuid, vs_service_classes, "Unknown Service"));

    return offset;
}


static gint
dissect_sdp_service_attribute_list_array(proto_tree *tree, tvbuff_t *tvb,
        gint offset, packet_info *pinfo, gint attribute_list_byte_count)
{
    proto_item   *lists_item;
    proto_tree   *lists_tree;
    proto_tree   *next_tree;
    gint          start_offset;
    gint          length;
    gint          len;
    guint         number_of_attributes;

    start_offset = offset;

    offset = get_type_length(tvb, offset, &len);

    lists_item = proto_tree_add_text(tree, tvb, start_offset,
            attribute_list_byte_count, "Attribute Lists");
    lists_tree = proto_item_add_subtree(lists_item, ett_btsdp_attribute);
    dissect_data_element(lists_tree, &next_tree, pinfo, tvb, start_offset);

    number_of_attributes = 0;

    while (offset - start_offset < attribute_list_byte_count) {
        number_of_attributes += 1;

        get_type_length(tvb, offset, &length);

        offset = dissect_sdp_service_attribute_list(next_tree, tvb, offset,
                pinfo, length);
    }

    proto_item_append_text(lists_tree, " [count = %2u]", number_of_attributes);

    return offset;
}


static gint
dissect_sdp_service_search_attribute_response(proto_tree *tree, tvbuff_t *tvb,
        gint offset, packet_info *pinfo, guint16 tid)
{
    gint       attribute_list_byte_count;
    gboolean   is_first;
    gboolean   is_continued;
    tvbuff_t  *new_tvb;

    proto_tree_add_item(tree, hf_attribute_list_byte_count, tvb, offset, 2, ENC_BIG_ENDIAN);
    attribute_list_byte_count = tvb_get_ntohs(tvb, offset);
    offset += 2;

    reassemble_continuation_state(tvb, pinfo,
            offset + attribute_list_byte_count, tid, FALSE,
            offset, attribute_list_byte_count,
            PDU_TYPE_SERVICE_SEARCH_ATTRIBUTE, &new_tvb, &is_first,
            &is_continued);

    if (is_first && !is_continued) {
        dissect_sdp_service_attribute_list_array(tree, tvb, offset, pinfo,
                attribute_list_byte_count);
    } else {
        proto_tree_add_item(tree, hf_fragment, tvb, offset,
                attribute_list_byte_count, ENC_NA);
    }

    if (is_continued) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "(fragment)");
    }

    offset = dissect_continuation_state(tvb, tree, pinfo, offset + attribute_list_byte_count);

    if (!is_first && new_tvb) {
        proto_item *reassembled_item;
        proto_tree *reassembled_tree;

        add_new_data_source(pinfo, new_tvb, (is_continued) ? "Partial Reassembled SDP" : "Reassembled SDP");

        reassembled_item = proto_tree_add_text(tree, new_tvb, 0, tvb_length(new_tvb),
                (is_continued) ? "Partial Attribute List" : "Reassembled Attribute List");
        reassembled_tree = proto_item_add_subtree(reassembled_item, ett_btsdp_reassembled);
        PROTO_ITEM_SET_GENERATED(reassembled_item);

        if (!is_continued)
            dissect_sdp_service_attribute_list_array(reassembled_tree, new_tvb, 0,
                    pinfo, tvb_length(new_tvb));
    }

    return offset;
}


static gint
dissect_sdp_service_search_attribute_request(proto_tree *tree, tvbuff_t *tvb,
        gint offset, packet_info *pinfo, guint16 tid)
{
    proto_tree   *ptree;
    proto_item   *pitem;
    proto_tree   *next_tree;
    gint         start_offset;
    gint         size;
    gint         bytes_to_go;
    gchar        *str;

    start_offset = offset;
    pitem = proto_tree_add_text(tree, tvb, offset, 2, "Service Search Pattern");
    ptree = proto_item_add_subtree(pitem, ett_btsdp_attribute);

    dissect_data_element(ptree, &next_tree, pinfo, tvb, offset);
    offset = get_type_length(tvb, offset, &bytes_to_go);
    proto_item_set_len(pitem, bytes_to_go + (offset - start_offset));

    while (bytes_to_go > 0) {
        size = dissect_sdp_type(next_tree, pinfo, tvb, offset, -1, 0, 0, NULL, &str);
        proto_item_append_text(ptree, "%s", str);
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s", str);

        offset      += size;
        bytes_to_go -= size;
    }

    proto_tree_add_item(tree, hf_maximum_attribute_byte_count, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    offset += dissect_attribute_id_list(tree, tvb, offset, pinfo);

    reassemble_continuation_state(tvb, pinfo, offset, tid, TRUE,
            0, 0, PDU_TYPE_SERVICE_SEARCH_ATTRIBUTE, NULL, NULL, NULL);

    offset = dissect_continuation_state(tvb, tree, pinfo, offset);

    return offset;
}


static gint
dissect_sdp_service_attribute_response(proto_tree *tree, tvbuff_t *tvb,
        gint offset, packet_info *pinfo, guint16 tid)
{
    gint       attribute_list_byte_count;
    gboolean   is_first;
    gboolean   is_continued;
    tvbuff_t  *new_tvb;

    proto_tree_add_item(tree, hf_attribute_list_byte_count, tvb, offset, 2, ENC_BIG_ENDIAN);
    attribute_list_byte_count = tvb_get_ntohs(tvb, offset);
    offset += 2;

    reassemble_continuation_state(tvb, pinfo,
            offset + attribute_list_byte_count, tid, FALSE,
            offset, attribute_list_byte_count,
            PDU_TYPE_SERVICE_ATTRIBUTE, &new_tvb, &is_first,
            &is_continued);

    if (is_first && !is_continued) {
        dissect_sdp_service_attribute_list(tree, tvb, offset, pinfo,
                attribute_list_byte_count);
    } else {
        proto_tree_add_item(tree, hf_fragment, tvb, offset,
                attribute_list_byte_count, ENC_NA);
    }

    if (is_continued) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "(fragment)");
    }

    offset = dissect_continuation_state(tvb, tree, pinfo, offset + attribute_list_byte_count);

    if (!is_first && new_tvb) {
        proto_item *reassembled_item;
        proto_tree *reassembled_tree;

        add_new_data_source(pinfo, new_tvb, (is_continued) ? "Partial Reassembled SDP" : "Reassembled SDP");

        reassembled_item = proto_tree_add_text(tree, new_tvb, 0, tvb_length(new_tvb),
                (is_continued) ? "Partial Attribute List" : "Reassembled Attribute List");
        reassembled_tree = proto_item_add_subtree(reassembled_item, ett_btsdp_reassembled);
        PROTO_ITEM_SET_GENERATED(reassembled_item);

        if (!is_continued)
            dissect_sdp_service_attribute_list(reassembled_tree, new_tvb, 0, pinfo, tvb_length(new_tvb));
    }

    return offset;
}


static gint
dissect_sdp_service_attribute_request(proto_tree *tree, tvbuff_t *tvb,
        gint offset, packet_info *pinfo, guint16 tid)
{
    guint32 value;

    proto_tree_add_item(tree, hf_sdp_service_record_handle, tvb, offset, 4, ENC_BIG_ENDIAN);
    value = tvb_get_ntohl(tvb, offset);
    col_append_fstr(pinfo->cinfo, COL_INFO, ": 0x%08x - ", value);
    offset += 4;

    proto_tree_add_item(tree, hf_maximum_attribute_byte_count, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    offset += dissect_attribute_id_list(tree, tvb, offset, pinfo);

    reassemble_continuation_state(tvb, pinfo, offset, tid, TRUE,
            0, 0, PDU_TYPE_SERVICE_ATTRIBUTE, NULL, NULL, NULL);

    offset = dissect_continuation_state(tvb, tree, pinfo, offset);

    return offset;
}


static gint
dissect_sdp_service_search_request(proto_tree *tree, tvbuff_t *tvb, gint offset,
        packet_info *pinfo, guint16 tid)
{
    gint        start_offset;
    gint        bytes_to_go;
    gint        size;
    proto_item  *ti;
    proto_tree  *st;

    start_offset = offset;

    ti = proto_tree_add_text(tree, tvb, offset, 2, "Service Search Pattern");
    st = proto_item_add_subtree(ti, ett_btsdp_service_search_pattern);

    dissect_data_element(st, NULL, pinfo, tvb, offset);
    offset = get_type_length(tvb, offset, &bytes_to_go);
    proto_item_set_len(ti, offset - start_offset + bytes_to_go);

    while (bytes_to_go > 0) {
        gchar *str;

        size = dissect_sdp_type(st, pinfo, tvb, offset, -1, 0, 0, NULL, &str);

        proto_item_append_text(st, " %s", str);
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s", str);

        if (size < 1)
            break;

        offset      += size;
        bytes_to_go -= size;
    }

    proto_tree_add_item(tree, hf_maximum_service_record_count, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    reassemble_continuation_state(tvb, pinfo, offset, tid, TRUE,
            0, 0, PDU_TYPE_SERVICE_SEARCH, NULL, NULL, NULL);

    offset = dissect_continuation_state(tvb, tree, pinfo, offset);

    return offset;
}


static gint
dissect_sdp_service_search_response(proto_tree *tree, tvbuff_t *tvb,
        gint offset, packet_info *pinfo, guint16 tid)
{
    proto_tree *st;
    proto_item *ti;
    guint16     current_count;
    gboolean    is_first;
    gboolean    is_continued;
    tvbuff_t   *new_tvb;

    proto_tree_add_item(tree, hf_ssr_total_count, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    current_count = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ssr_current_count, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    ti = proto_tree_add_text(tree, tvb, offset,
                 current_count * 4, "Service Record Handle List [count = %u]", current_count);
    st = proto_item_add_subtree(ti, ett_btsdp_ssr);

    while (current_count > 0) {
        proto_tree_add_item(st, hf_sdp_service_record_handle, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset     += 4;
        current_count -= 1;
    }

    reassemble_continuation_state(tvb, pinfo, offset, tid, FALSE,
            offset - current_count * 4, current_count * 4, PDU_TYPE_SERVICE_SEARCH,
            &new_tvb, &is_first, &is_continued);

    offset = dissect_continuation_state(tvb, tree, pinfo, offset);

    if (!is_first && new_tvb) {
        proto_item *reassembled_item;
        proto_tree *reassembled_tree;
        gint        new_offset = 0;
        gint        new_length;

        new_length = tvb_length(new_tvb);

        reassembled_item = proto_tree_add_text(tree, new_tvb, 0, new_length,
                (is_continued) ? "Partial Record Handle List" : "Reassembled Record Handle List");
        proto_item_append_text(reassembled_item, " [count = %u]", new_length / 4);
        reassembled_tree = proto_item_add_subtree(reassembled_item, ett_btsdp_reassembled);
        PROTO_ITEM_SET_GENERATED(reassembled_item);

        while (new_length > 0) {
            proto_tree_add_item(reassembled_tree, hf_sdp_service_record_handle, new_tvb,
                    new_offset, 4, ENC_BIG_ENDIAN);
            new_offset  += 4;
            new_length -= 4;
        }
    }

    return offset;
}


static gint
dissect_btsdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item    *ti;
    proto_tree    *st;
    gint          offset = 0;
    guint8        pdu_id;
    guint16       tid;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SDP");

    ti = proto_tree_add_item(tree, proto_btsdp, tvb, 0, -1, ENC_NA);
    st = proto_item_add_subtree(ti, ett_btsdp);

    tap_queue_packet(btsdp_tap, NULL, (void *) &sdp_package);

    switch (pinfo->p2p_dir) {
        case P2P_DIR_SENT:
            col_add_str(pinfo->cinfo, COL_INFO, "Sent ");
            break;
        case P2P_DIR_RECV:
            col_add_str(pinfo->cinfo, COL_INFO, "Rcvd ");
            break;
        default:
            col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown direction %d ",
                pinfo->p2p_dir);
            break;
    }

    proto_tree_add_item(st, hf_pdu_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    pdu_id = tvb_get_guint8(tvb, offset);
    offset += 1;

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
            val_to_str_const(pdu_id, vs_pduid, "Unknown"));

    proto_tree_add_item(st, hf_tid, tvb, offset, 2, ENC_BIG_ENDIAN);
    tid = tvb_get_ntohs(tvb, offset);
    offset += 2;

    proto_tree_add_item(st, hf_parameter_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    switch (pdu_id) {
        case 0x01:
            offset = dissect_sdp_error_response(st, tvb, offset);
            break;
        case 0x02:
            offset = dissect_sdp_service_search_request(st, tvb, offset, pinfo, tid);
            break;
        case 0x03:
            offset = dissect_sdp_service_search_response(st, tvb, offset, pinfo, tid);
            break;
        case 0x04:
            offset = dissect_sdp_service_attribute_request(st, tvb, offset, pinfo, tid);
            break;
        case 0x05:
            offset = dissect_sdp_service_attribute_response(st, tvb, offset, pinfo, tid);
            break;
        case 0x06:
            offset = dissect_sdp_service_search_attribute_request(st, tvb, offset, pinfo, tid);
            break;
        case 0x07:
            offset = dissect_sdp_service_search_attribute_response(st, tvb, offset, pinfo, tid);
            break;
    }

    return offset;
}

void
proto_register_btsdp(void)
{
    module_t *module;

    static hf_register_info hf[] = {
        { &hf_pdu_id,
            { "PDU",                             "btsdp.pdu",
            FT_UINT8, BASE_HEX, VALS(vs_pduid), 0,
            "PDU type", HFILL }
        },
        { &hf_tid,
            { "Transaction Id",                  "btsdp.tid",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL}
        },
        { &hf_parameter_length,
          { "Parameter Length",                  "btsdp.len",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}
        },
        { &hf_error_code,
            { "Error Code",                      "btsdp.error_code",
            FT_UINT16, BASE_HEX, VALS(vs_error_code), 0,
            NULL, HFILL}
        },
        { &hf_ssr_total_count,
            { "Total Service Record Count",      "btsdp.ssr.total_count",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Total count of service records", HFILL}
        },
        { &hf_ssr_current_count,
            { "Current Service Record Count",    "btsdp.ssr.current_count",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Count of service records in this message", HFILL}
        },
        { &hf_attribute_list_byte_count,
            { "Attribute List Byte Count",       "btsdp.attribute_list_byte_count",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Count of bytes in attribute list response", HFILL}
        },
        { &hf_maximum_service_record_count,
            {"Maximum Service Record Count",     "btsdp.maximum_service_record_count",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}
        },
        { &hf_maximum_attribute_byte_count,
            {"Maximum Attribute Byte Count",     "btsdp.maximum_attribute_byte_count",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}
        },
        { &hf_continuation_state_length,
            { "Continuation State Length",       "btsdp.continuation_state_length",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_continuation_state_value,
            { "Continuation State Value",        "btsdp.continuation_state_value",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_data_element_type,
            { "Data Element Type",               "btsdp.data_element.type",
            FT_UINT8, BASE_DEC, VALS(vs_data_element_type), 0xF8,
            NULL, HFILL }
        },
        { &hf_data_element_size,
            { "Data Element Size",               "btsdp.data_element.size",
            FT_UINT8, BASE_DEC, VALS(vs_data_element_size), 0x07,
            NULL, HFILL }
        },
        { &hf_data_element_var_size,
            { "Data Element Var Size",           "btsdp.data_element.var_size",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_data_element_value,
            { "Data Value",                      "btsdp.data_element.value",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_fragment,
            { "Data Fragment",                   "btsdp.fragment",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_service_attribute_id_generic,
            { "Attribute ID",                    "btsdp.service.attribute",
            FT_UINT16, BASE_HEX, VALS(vs_general_attribute_id), 0,
            NULL, HFILL }
        },
        { &hf_sdp_service_record_handle,
            { "Service Record Handle",           "btsdp.service_record_handle",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_btsdp,
        &ett_btsdp_ssr,
        &ett_btsdp_des,
        &ett_btsdp_attribute,
        &ett_btsdp_attribute_id,
        &ett_btsdp_attribute_value,
        &ett_btsdp_service_search_pattern,
        &ett_btsdp_attribute_idlist,
        &ett_btsdp_continuation_state,
        &ett_btsdp_data_element,
        &ett_btsdp_data_element_value,
        &ett_btsdp_reassembled
    };

    proto_btsdp = proto_register_protocol("Bluetooth SDP Protocol", "BT SDP", "btsdp");
    new_register_dissector("btsdp", dissect_btsdp, proto_btsdp);

    proto_register_field_array(proto_btsdp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    tid_requests = se_tree_create(EMEM_TREE_TYPE_RED_BLACK,
            "btsdp reassembling by tid");
    continuation_states = se_tree_create(EMEM_TREE_TYPE_RED_BLACK,
            "btsdp reassembling by continuation state");

    service_infos = se_tree_create(EMEM_TREE_TYPE_RED_BLACK,
            "btsdp service infos");
    sdp_package.service_infos = service_infos;
    btsdp_tap = register_tap("btsdp");

    module = prefs_register_protocol(proto_btsdp, NULL);
    prefs_register_static_text_preference(module, "bnep.version",
            "Bluetooth Protocol SDP version from Core 4.0",
            "Version of protocol supported by this dissector.");
}


void
proto_reg_handoff_btsdp(void)
{
    dissector_handle_t btsdp_handle;

    btsdp_handle = find_dissector("btsdp");
    dissector_add_uint("btl2cap.psm", BTL2CAP_PSM_SDP, btsdp_handle);
    dissector_add_handle("btl2cap.cid", btsdp_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
