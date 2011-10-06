/* packet-wifi-p2p.c
 *
 * Wi-Fi P2P
 *
 * Copyright 2009-2010 Atheros Communications
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/expert.h>

#include "packet-wifi-p2p.h"

enum {
  P2P_ATTR_STATUS = 0,
  P2P_ATTR_MINOR_REASON_CODE = 1,
  P2P_ATTR_P2P_CAPABILITY = 2,
  P2P_ATTR_P2P_DEVICE_ID = 3,
  P2P_ATTR_GROUP_OWNER_INTENT = 4,
  P2P_ATTR_CONFIGURATION_TIMEOUT = 5,
  P2P_ATTR_LISTEN_CHANNEL = 6,
  P2P_ATTR_P2P_GROUP_BSSID = 7,
  P2P_ATTR_EXTENDED_LISTEN_TIMING = 8,
  P2P_ATTR_INTENDED_P2P_INTERFACE_ADDRESS = 9,
  P2P_ATTR_P2P_MANAGEABILITY = 10,
  P2P_ATTR_CHANNEL_LIST = 11,
  P2P_ATTR_NOTICE_OF_ABSENCE = 12,
  P2P_ATTR_P2P_DEVICE_INFO = 13,
  P2P_ATTR_P2P_GROUP_INFO = 14,
  P2P_ATTR_P2P_GROUP_ID = 15,
  P2P_ATTR_P2P_INTERFACE = 16,
  P2P_ATTR_OPERATING_CHANNEL = 17,
  P2P_ATTR_INVITATION_FLAGS = 18,
  /* 19-220 Reserved */
  P2P_ATTR_VENDOR_SPECIFIC = 221,
  /* 222-255 Reserved */
};

static const value_string p2p_attr_types[] = {
  { P2P_ATTR_STATUS, "Status" },
  { P2P_ATTR_MINOR_REASON_CODE, "Minor Reason Code" },
  { P2P_ATTR_P2P_CAPABILITY, "P2P Capability" },
  { P2P_ATTR_P2P_DEVICE_ID, "P2P Device ID" },
  { P2P_ATTR_GROUP_OWNER_INTENT, "Group Owner Intent" },
  { P2P_ATTR_CONFIGURATION_TIMEOUT, "Configuration Timeout" },
  { P2P_ATTR_LISTEN_CHANNEL, "Listen Channel" },
  { P2P_ATTR_P2P_GROUP_BSSID, "P2P Group BSSID" },
  { P2P_ATTR_EXTENDED_LISTEN_TIMING, "Extended Listen Timing" },
  { P2P_ATTR_INTENDED_P2P_INTERFACE_ADDRESS,
    "Intended P2P Interface Address" },
  { P2P_ATTR_P2P_MANAGEABILITY, "P2P Manageability" },
  { P2P_ATTR_CHANNEL_LIST, "Channel List" },
  { P2P_ATTR_NOTICE_OF_ABSENCE, "Notice of Absence" },
  { P2P_ATTR_P2P_DEVICE_INFO, "P2P Device Info" },
  { P2P_ATTR_P2P_GROUP_INFO, "P2P Group Info" },
  { P2P_ATTR_P2P_GROUP_ID, "P2P Group ID" },
  { P2P_ATTR_P2P_INTERFACE, "P2P Interface" },
  { P2P_ATTR_OPERATING_CHANNEL, "Operating Channel" },
  { P2P_ATTR_INVITATION_FLAGS, "Invitation Flags" },
  { P2P_ATTR_VENDOR_SPECIFIC, "Vendor specific attribute" },
  { 0, NULL }
};

#define P2P_DEV_CAPAB_SERVICE_DISCOVERY 0x01
#define P2P_DEV_CAPAB_P2P_CLIENT_DISCOVERABILITY 0x02
#define P2P_DEV_CAPAB_CONCURRENT_OPERATION 0x04
#define P2P_DEV_CAPAB_P2P_INFRASTRUCTURE_MANAGED 0x08
#define P2P_DEV_CAPAB_P2P_DEVICE_LIMIT 0x10
#define P2P_DEV_CAPAB_P2P_INVITATION_PROCEDURE 0x20

#define P2P_GROUP_CAPAB_P2P_GROUP_OWNER 0x01
#define P2P_GROUP_CAPAB_PERSISTENT_P2P_GROUP 0x02
#define P2P_GROUP_CAPAB_P2P_GROUP_LIMIT 0x04
#define P2P_GROUP_CAPAB_INTRA_BSS_DISTRIBUTION 0x08
#define P2P_GROUP_CAPAB_CROSS_CONNECTION 0x10
#define P2P_GROUP_CAPAB_PERSISTENT_RECONNECT 0x20
#define P2P_GROUP_CAPAB_GROUP_FORMATION 0x40

#define WPS_CONF_METH_USBA 0x0001
#define WPS_CONF_METH_ETHERNET 0x0002
#define WPS_CONF_METH_LABEL 0x0004
#define WPS_CONF_METH_DISPLAY 0x0008
#define WPS_CONF_METH_EXT_NFC_TOKEN 0x0010
#define WPS_CONF_METH_INT_NFC_TOKEN 0x0020
#define WPS_CONF_METH_NFC_INTERFACE 0x0040
#define WPS_CONF_METH_PUSHBUTTON 0x0080
#define WPS_CONF_METH_KEYPAD 0x0100

enum {
  P2P_ACT_GO_NEG_REQ = 0,
  P2P_ACT_GO_NEG_RESP = 1,
  P2P_ACT_GO_NEG_CONF = 2,
  P2P_ACT_INVITATION_REQ = 3,
  P2P_ACT_INVITATION_RESP = 4,
  P2P_ACT_DEV_DISC_REQ = 5,
  P2P_ACT_DEV_DISC_RESP = 6,
  P2P_ACT_PROV_DISC_REQ = 7,
  P2P_ACT_PROV_DISC_RESP = 8,
};

static const value_string p2p_public_action_subtypes[] = {
  { P2P_ACT_GO_NEG_REQ, "GO Negotiation Request" },
  { P2P_ACT_GO_NEG_RESP, "GO Negotiation Response" },
  { P2P_ACT_GO_NEG_CONF, "GO Negotiation Confirmation" },
  { P2P_ACT_INVITATION_REQ, "P2P Invitation Request" },
  { P2P_ACT_INVITATION_RESP, "P2P Invitation Response" },
  { P2P_ACT_DEV_DISC_REQ, "Device Discoverability Request" },
  { P2P_ACT_DEV_DISC_RESP, "Device Discoverability Response" },
  { P2P_ACT_PROV_DISC_REQ, "Provision Discovery Request" },
  { P2P_ACT_PROV_DISC_RESP, "Provision Discovery Response" },
  { 0, NULL }
};

enum {
  P2P_ACT_NOA = 0,
  P2P_ACT_P2P_PRESENCE_REQ = 1,
  P2P_ACT_P2P_PRESENCE_RESP = 2,
  P2P_ACT_GO_DISC_REQ = 3,
};

static const value_string p2p_action_subtypes[] = {
  { P2P_ACT_NOA, "Notice of Absence" },
  { P2P_ACT_P2P_PRESENCE_REQ, "P2P Presence Request" },
  { P2P_ACT_P2P_PRESENCE_RESP, "P2P Presence Response" },
  { P2P_ACT_GO_DISC_REQ, "GO Discoverability Request" },
  { 0, NULL }
};

enum {
  P2P_STATUS_SUCCESS = 0,
  P2P_FAIL_INFORMATION_CURRENTLY_UNAVAILABLE = 1,
  P2P_FAIL_INCOMPATIBLE_PARAMETERS = 2,
  P2P_FAIL_LIMIT_REACHED = 3,
  P2P_FAIL_INVALID_PARAMETERS = 4,
  P2P_FAIL_UNABLE_TO_ACCOMMODATE = 5,
  P2P_FAIL_PREVIOUS_PROTOCOL_ERROR = 6,
  P2P_FAIL_NO_COMMON_CHANNELS = 7,
  P2P_FAIL_UNKNOWN_P2P_GROUP = 8,
  P2P_FAIL_BOTH_DEVICES_GO = 9,
  P2P_FAIL_INCOMPATIBLE_PROVISION_METHOD = 10,
  P2P_FAIL_REJECTED_BY_USER = 11,
};

static const value_string p2p_status_codes[] = {
  { P2P_STATUS_SUCCESS, "Success" },
  { P2P_FAIL_INFORMATION_CURRENTLY_UNAVAILABLE, "Fail; information is "
    "currently unavailable" },
  { P2P_FAIL_INCOMPATIBLE_PARAMETERS, "Fail; incompatible parameters" },
  { P2P_FAIL_LIMIT_REACHED, "Fail; limit reached" },
  { P2P_FAIL_INVALID_PARAMETERS, "Fail; invalid parameters" },
  { P2P_FAIL_UNABLE_TO_ACCOMMODATE, "Fail; unable to accommodate request" },
  { P2P_FAIL_PREVIOUS_PROTOCOL_ERROR, "Fail; previous protocol error, or "
    "disruptive behavior" },
  { P2P_FAIL_NO_COMMON_CHANNELS, "Fail; no common channels" },
  { P2P_FAIL_UNKNOWN_P2P_GROUP, "Fail; unknown P2P Group" },
  { P2P_FAIL_BOTH_DEVICES_GO, "Fail; both P2P Devices indicated an Intent of "
    "15 in Group Owner Negotiation" },
  { P2P_FAIL_INCOMPATIBLE_PROVISION_METHOD, "Fail; incompatible provisioning "
    "method" },
  { P2P_FAIL_REJECTED_BY_USER, "Fail; rejected by user" },
  { 0, NULL }
};

enum {
  P2P_MINOR_RESERVED = 0,
  P2P_MINOR_DISCONNECT_DUE_TO_CROSS_CONNECTION = 1,
  P2P_MINOR_DISCONNECT_DUE_TO_NOT_P2P_MANAGED = 2,
  P2P_MINOR_DISCONNECT_DUE_TO_NO_COEXISTENCE = 3,
  P2P_MINOR_DISCONNECT_DUE_TO_OUTSIDE_POLICY = 4,
};

static const value_string p2p_minor_reason_codes[] = {
  { P2P_MINOR_RESERVED, "Reserved" },
  { P2P_MINOR_DISCONNECT_DUE_TO_CROSS_CONNECTION,
    "Disconnected because Cross Connection capability is not allow" },
  { P2P_MINOR_DISCONNECT_DUE_TO_NOT_P2P_MANAGED,
    "Disconnected because P2P Infrastructure Managed not supported" },
  { P2P_MINOR_DISCONNECT_DUE_TO_NO_COEXISTENCE,
    "Disconnected because concurrent device is not setting coexistence "
    "parameters" },
  { P2P_MINOR_DISCONNECT_DUE_TO_OUTSIDE_POLICY,
    "Disconnected because P2P operation is outside the IT defined policy" },
  { 0, NULL }
};

static const value_string invitation_types[] = {
  { 0, "Join active P2P Group" },
  { 1, "Reinvoke Persistent Group" },
  { 0, NULL }
};

static const value_string p2p_service_protocol_types[] = {
  { 0, "All Service Protocol Types" },
  { 1, "Bonjour" },
  { 2, "UPnP" },
  { 3, "WS-Discovery" },
  { 0, NULL }
};

static const value_string p2p_sd_status_codes[] = {
  { 0, "Success" },
  { 1, "Service Protocol Type not available" },
  { 2, "Requested information not available" },
  { 3, "Bad Request" },
  { 0, NULL }
};

static int proto_p2p = -1;

static gint ett_p2p_tlv = -1;
static gint ett_p2p_service_tlv = -1;

static int hf_p2p_attr_type = -1;
static int hf_p2p_attr_len = -1;

static int hf_p2p_attr_capab = -1;
static int hf_p2p_attr_capab_device = -1;
static int hf_p2p_attr_capab_device_service_discovery = -1;
static int hf_p2p_attr_capab_device_client_discoverability = -1;
static int hf_p2p_attr_capab_device_concurrent_operation = -1;
static int hf_p2p_attr_capab_device_infrastructure_managed = -1;
static int hf_p2p_attr_capab_device_limit = -1;
static int hf_p2p_attr_capab_invitation_procedure = -1;
static int hf_p2p_attr_capab_group = -1;
static int hf_p2p_attr_capab_group_owner = -1;
static int hf_p2p_attr_capab_group_persistent = -1;
static int hf_p2p_attr_capab_group_limit = -1;
static int hf_p2p_attr_capab_group_intra_bss_distribution = -1;
static int hf_p2p_attr_capab_group_cross_connection = -1;
static int hf_p2p_attr_capab_group_persistent_reconnect = -1;
static int hf_p2p_attr_capab_group_group_formation = -1;

static int hf_p2p_attr_device_id = -1;

static int hf_p2p_attr_status = -1;

static int hf_p2p_attr_go_intent = -1;
static int hf_p2p_attr_go_intent_tie_breaker = -1;

static int hf_p2p_attr_listen_channel = -1;
static int hf_p2p_attr_listen_channel_country = -1;
static int hf_p2p_attr_listen_channel_oper_class = -1;
static int hf_p2p_attr_listen_channel_number = -1;

static int hf_p2p_attr_operating_channel = -1;
static int hf_p2p_attr_operating_channel_country = -1;
static int hf_p2p_attr_operating_channel_oper_class = -1;
static int hf_p2p_attr_operating_channel_number = -1;

static int hf_p2p_attr_channel_list = -1;
static int hf_p2p_attr_channel_list_country = -1;
static int hf_p2p_attr_channel_list_oper_class = -1;
static int hf_p2p_attr_channel_list_num_chan = -1;
static int hf_p2p_attr_channel_list_chan = -1;

static int hf_p2p_attr_dev_info = -1;
static int hf_p2p_attr_dev_info_p2p_dev_addr = -1;
static int hf_p2p_attr_dev_info_pri_dev_type = -1;
static int hf_p2p_attr_dev_info_pri_dev_type_category = -1;
static int hf_p2p_attr_dev_info_pri_dev_type_oui = -1;
static int hf_p2p_attr_dev_info_pri_dev_type_subcategory = -1;
static int hf_p2p_attr_dev_info_num_sec = -1;
static int hf_p2p_attr_dev_info_sec_dev_type = -1;
static int hf_p2p_attr_dev_info_dev_name_type = -1;
static int hf_p2p_attr_dev_info_dev_name_len = -1;
static int hf_p2p_attr_dev_info_dev_name = -1;
static int hf_p2p_attr_dev_info_config_methods = -1;
static int hf_p2p_attr_dev_info_config_methods_usba = -1;
static int hf_p2p_attr_dev_info_config_methods_ethernet = -1;
static int hf_p2p_attr_dev_info_config_methods_label = -1;
static int hf_p2p_attr_dev_info_config_methods_display = -1;
static int hf_p2p_attr_dev_info_config_methods_ext_nfc_token = -1;
static int hf_p2p_attr_dev_info_config_methods_int_nfc_token = -1;
static int hf_p2p_attr_dev_info_config_methods_nfc_interface = -1;
static int hf_p2p_attr_dev_info_config_methods_pushbutton = -1;
static int hf_p2p_attr_dev_info_config_methods_keypad = -1;
static int hf_p2p_attr_config_timeout_go = -1;
static int hf_p2p_attr_config_timeout_client = -1;
static int hf_p2p_attr_intended_interface_addr = -1;
static int hf_p2p_attr_extended_listen_timing_period = -1;
static int hf_p2p_attr_extended_listen_timing_interval = -1;
static int hf_p2p_attr_p2p_group_id_dev_addr = -1;
static int hf_p2p_attr_p2p_group_id_ssid = -1;
static int hf_p2p_attr_p2p_group_bssid = -1;

static int hf_p2p_attr_noa_index = -1;
static int hf_p2p_attr_noa_params = -1;
static int hf_p2p_attr_noa_params_opp_ps = -1;
static int hf_p2p_attr_noa_params_ctwindow = -1;
static int hf_p2p_attr_noa_count_type = -1;
static int hf_p2p_attr_noa_duration = -1;
static int hf_p2p_attr_noa_interval = -1;
static int hf_p2p_attr_noa_start_time = -1;

static int hf_p2p_attr_gi = -1;
static int hf_p2p_attr_gi_length = -1;
static int hf_p2p_attr_gi_p2p_dev_addr = -1;
static int hf_p2p_attr_gi_p2p_iface_addr = -1;
static int hf_p2p_attr_gi_dev_capab = -1;
static int hf_p2p_attr_gi_dev_capab_service_discovery = -1;
static int hf_p2p_attr_gi_dev_capab_client_discoverability = -1;
static int hf_p2p_attr_gi_dev_capab_concurrent_operation = -1;
static int hf_p2p_attr_gi_dev_capab_infrastructure_managed = -1;
static int hf_p2p_attr_gi_dev_capab_limit = -1;
static int hf_p2p_attr_gi_dev_capab_invitation_procedure = -1;
static int hf_p2p_attr_gi_config_methods = -1;
static int hf_p2p_attr_gi_config_methods_usba = -1;
static int hf_p2p_attr_gi_config_methods_ethernet = -1;
static int hf_p2p_attr_gi_config_methods_label = -1;
static int hf_p2p_attr_gi_config_methods_display = -1;
static int hf_p2p_attr_gi_config_methods_ext_nfc_token = -1;
static int hf_p2p_attr_gi_config_methods_int_nfc_token = -1;
static int hf_p2p_attr_gi_config_methods_nfc_interface = -1;
static int hf_p2p_attr_gi_config_methods_pushbutton = -1;
static int hf_p2p_attr_gi_config_methods_keypad = -1;
static int hf_p2p_attr_gi_pri_dev_type = -1;
static int hf_p2p_attr_gi_pri_dev_type_category = -1;
static int hf_p2p_attr_gi_pri_dev_type_oui = -1;
static int hf_p2p_attr_gi_pri_dev_type_subcategory = -1;
static int hf_p2p_attr_gi_num_sec_dev_types = -1;
static int hf_p2p_attr_gi_sec_dev_type = -1;
static int hf_p2p_attr_gi_dev_name_type = -1;
static int hf_p2p_attr_gi_dev_name_len = -1;
static int hf_p2p_attr_gi_dev_name = -1;

static int hf_p2p_attr_invitation_flags = -1;
static int hf_p2p_attr_invitation_flags_type = -1;

static int hf_p2p_attr_manageability_bitmap = -1;
static int hf_p2p_attr_manageability_bitmap_mgmt = -1;
static int hf_p2p_attr_manageability_bitmap_cross_connect = -1;
static int hf_p2p_attr_manageability_bitmap_coex_opt = -1;

static int hf_p2p_attr_minor_reason_code = -1;

static int hf_p2p_anqp_service_update_indicator = -1;
static int hf_p2p_anqp_length = -1;
static int hf_p2p_anqp_service_protocol_type = -1;
static int hf_p2p_anqp_service_transaction_id = -1;
static int hf_p2p_anqp_query_data = -1;
static int hf_p2p_anqp_status_code = -1;
static int hf_p2p_anqp_response_data = -1;

static int hf_p2p_action_subtype = -1;
static int hf_p2p_action_dialog_token = -1;
static int hf_p2p_public_action_subtype = -1;
static int hf_p2p_public_action_dialog_token = -1;

static void dissect_wifi_p2p_capability(proto_item *tlv_root,
                                        proto_item *tlv_item,
                                        tvbuff_t *tvb, int offset)
{
  proto_tree_add_item(tlv_root, hf_p2p_attr_capab_device, tvb,
                      offset + 3, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root,
                      hf_p2p_attr_capab_device_service_discovery, tvb,
                      offset + 3, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root,
                      hf_p2p_attr_capab_device_client_discoverability,
                      tvb, offset + 3, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root,
                      hf_p2p_attr_capab_device_concurrent_operation,
                      tvb, offset + 3, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root,
                      hf_p2p_attr_capab_device_infrastructure_managed,
                      tvb, offset + 3, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root, hf_p2p_attr_capab_device_limit, tvb,
                      offset + 3, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root, hf_p2p_attr_capab_invitation_procedure, tvb,
                      offset + 3, 1, ENC_BIG_ENDIAN);

  proto_tree_add_item(tlv_root, hf_p2p_attr_capab_group,
                      tvb, offset + 4, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root, hf_p2p_attr_capab_group_owner,
                      tvb, offset + 4, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root, hf_p2p_attr_capab_group_persistent,
                      tvb, offset + 4, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root, hf_p2p_attr_capab_group_limit,
                      tvb, offset + 4, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root,
                      hf_p2p_attr_capab_group_intra_bss_distribution,
                      tvb, offset + 4, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root, hf_p2p_attr_capab_group_cross_connection,
                      tvb, offset + 4, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root,
                      hf_p2p_attr_capab_group_persistent_reconnect,
                      tvb, offset + 4, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root, hf_p2p_attr_capab_group_group_formation,
                      tvb, offset + 4, 1, ENC_BIG_ENDIAN);

  proto_item_append_text(tlv_item, ": Device 0x%x  Group 0x%x",
                         tvb_get_guint8(tvb, offset + 3),
                         tvb_get_guint8(tvb, offset + 4));
}

static void dissect_device_id(proto_item *tlv_root, proto_item *tlv_item,
                              tvbuff_t *tvb, int offset)
{
  guint8 addr[6];
  proto_tree_add_item(tlv_root, hf_p2p_attr_device_id, tvb,
                      offset + 3, 6, FALSE);
  tvb_memcpy(tvb, addr, offset + 3, 6);
  proto_item_append_text(tlv_item, ": %s", ether_to_str(addr));
}

static void dissect_group_owner_intent(proto_item *tlv_root,
                                       proto_item *tlv_item,
                                       tvbuff_t *tvb, int offset)
{
  proto_tree_add_item(tlv_root, hf_p2p_attr_go_intent, tvb,
                      offset + 3, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root, hf_p2p_attr_go_intent_tie_breaker, tvb,
                      offset + 3, 1, ENC_BIG_ENDIAN);
  proto_item_append_text(tlv_item, ": Intent %u  Tie breaker %u",
                         tvb_get_guint8(tvb, offset + 3) >> 1,
                         tvb_get_guint8(tvb, offset + 3) & 0x01);
}

static void dissect_status(proto_item *tlv_root, proto_item *tlv_item,
                           tvbuff_t *tvb, int offset)
{
  proto_tree_add_item(tlv_root, hf_p2p_attr_status, tvb,
                      offset + 3, 1, ENC_BIG_ENDIAN);
  proto_item_append_text(tlv_item, ": %u (%s)",
                         tvb_get_guint8(tvb, offset + 3),
                         val_to_str(tvb_get_guint8(tvb, offset + 3),
                                    p2p_status_codes,
                                    "Unknown Status Code (%u)"));
}

static void dissect_listen_channel(proto_item *tlv_root, proto_item *tlv_item,
                                   tvbuff_t *tvb, int offset)
{
  proto_tree_add_item(tlv_root, hf_p2p_attr_listen_channel_country, tvb,
                      offset + 3, 3, FALSE);
  proto_tree_add_item(tlv_root, hf_p2p_attr_listen_channel_oper_class, tvb,
                      offset + 6, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root, hf_p2p_attr_listen_channel_number, tvb,
                      offset + 7, 1, ENC_BIG_ENDIAN);
  proto_item_append_text(tlv_item, ": Operating Class %u  "
                         "Channel Number %u",
                         tvb_get_guint8(tvb, offset + 6),
                         tvb_get_guint8(tvb, offset + 7));
}

static void dissect_operating_channel(proto_item *tlv_root,
                                      proto_item *tlv_item,
                                      tvbuff_t *tvb, int offset)
{
  proto_tree_add_item(tlv_root, hf_p2p_attr_operating_channel_country, tvb,
                      offset + 3, 3, FALSE);
  proto_tree_add_item(tlv_root, hf_p2p_attr_operating_channel_oper_class, tvb,
                      offset + 6, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root, hf_p2p_attr_operating_channel_number, tvb,
                      offset + 7, 1, ENC_BIG_ENDIAN);
  proto_item_append_text(tlv_item, ": Operating Class %u  "
                         "Channel Number %u",
                         tvb_get_guint8(tvb, offset + 6),
                         tvb_get_guint8(tvb, offset + 7));
}

static void dissect_channel_list(proto_item *tlv_root, tvbuff_t *tvb,
                                 int offset, guint16 slen)
{
  int s_offset = offset + 3;
  guint8 num_chan;

  proto_tree_add_item(tlv_root, hf_p2p_attr_channel_list_country, tvb,
                      s_offset, 3, FALSE);
  s_offset += 3;

  while (offset + 3 + slen > s_offset) {
    proto_tree_add_item(tlv_root, hf_p2p_attr_channel_list_oper_class, tvb,
                        s_offset, 1, ENC_BIG_ENDIAN);
    s_offset++;

    proto_tree_add_item(tlv_root, hf_p2p_attr_channel_list_num_chan, tvb,
                        s_offset, 1, ENC_BIG_ENDIAN);
    num_chan = tvb_get_guint8(tvb, s_offset);
    s_offset++;

    proto_tree_add_item(tlv_root, hf_p2p_attr_channel_list_chan, tvb,
                        s_offset, num_chan, ENC_NA);
    s_offset += num_chan;
  }
}

static void dissect_wifi_p2p_device_info(packet_info *pinfo,
                                         proto_item *tlv_root, tvbuff_t *tvb,
                                         int offset, guint16 slen)
{
  int s_offset, nlen;
  guint8 num_sec;
  guint16 attr_type, attr_len;
  proto_item *item;

  s_offset = offset + 3;

  proto_tree_add_item(tlv_root, hf_p2p_attr_dev_info_p2p_dev_addr, tvb,
                      s_offset, 6, FALSE);
  s_offset += 6;

  proto_tree_add_item(tlv_root, hf_p2p_attr_dev_info_config_methods,
                      tvb, s_offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root,
                      hf_p2p_attr_dev_info_config_methods_usba,
                      tvb, s_offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root,
                      hf_p2p_attr_dev_info_config_methods_ethernet,
                      tvb, s_offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root,
                      hf_p2p_attr_dev_info_config_methods_label,
                      tvb, s_offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root,
                      hf_p2p_attr_dev_info_config_methods_display,
                      tvb, s_offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root,
                      hf_p2p_attr_dev_info_config_methods_ext_nfc_token,
                      tvb, s_offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root,
                      hf_p2p_attr_dev_info_config_methods_int_nfc_token,
                      tvb, s_offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root,
                      hf_p2p_attr_dev_info_config_methods_nfc_interface,
                      tvb, s_offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root,
                      hf_p2p_attr_dev_info_config_methods_pushbutton,
                      tvb, s_offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root,
                      hf_p2p_attr_dev_info_config_methods_keypad,
                      tvb, s_offset, 2, ENC_BIG_ENDIAN);

  s_offset += 2;

  proto_tree_add_item(tlv_root, hf_p2p_attr_dev_info_pri_dev_type, tvb,
                      s_offset, 8, ENC_NA);
  proto_tree_add_item(tlv_root, hf_p2p_attr_dev_info_pri_dev_type_category,
                      tvb, s_offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root, hf_p2p_attr_dev_info_pri_dev_type_oui,
                      tvb, s_offset + 2, 4, ENC_NA);
  proto_tree_add_item(tlv_root, hf_p2p_attr_dev_info_pri_dev_type_subcategory,
                      tvb, s_offset + 6, 2, ENC_BIG_ENDIAN);
  s_offset += 8;

  num_sec = tvb_get_guint8(tvb, s_offset);
  proto_tree_add_item(tlv_root, hf_p2p_attr_dev_info_num_sec, tvb,
                      s_offset, 1, ENC_BIG_ENDIAN);
  s_offset++;

  while (num_sec > 0) {
    proto_tree_add_item(tlv_root, hf_p2p_attr_dev_info_sec_dev_type,
                        tvb, s_offset, 8, ENC_NA);
    s_offset += 8;
    num_sec--;
  }

  item = proto_tree_add_item(tlv_root, hf_p2p_attr_dev_info_dev_name_type,
                             tvb, s_offset, 2, ENC_BIG_ENDIAN);
  attr_type = tvb_get_ntohs(tvb, s_offset);
  if (attr_type != 0x1011) {
    expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR,
                           "Incorrect Device Name attribute type");
  }
  s_offset += 2;
  item = proto_tree_add_item(tlv_root, hf_p2p_attr_dev_info_dev_name_len,
                             tvb, s_offset, 2, ENC_BIG_ENDIAN);
  attr_len = tvb_get_ntohs(tvb, s_offset);
  s_offset += 2;
  if (attr_len > offset + 3 + slen - s_offset) {
    expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR,
                           "Invalid Device Name attribute length");
    return;
  }
  nlen = offset + 3 + slen - s_offset;
  if (nlen > 0)
    item = proto_tree_add_item(tlv_root, hf_p2p_attr_dev_info_dev_name,
                               tvb, s_offset,
                               nlen > attr_len ? attr_len : nlen,
                               FALSE);
  if (nlen != attr_len) {
    expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR,
                           "Invalid Device Name attribute");
  }
}

static void dissect_configuration_timeout(proto_item *tlv_root,
                                          proto_item *tlv_item,
                                          tvbuff_t *tvb, int offset)
{
  proto_tree_add_item(tlv_root, hf_p2p_attr_config_timeout_go, tvb,
                      offset + 3, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root, hf_p2p_attr_config_timeout_client, tvb,
                      offset + 4, 1, ENC_BIG_ENDIAN);
  proto_item_append_text(tlv_item, ": GO %u msec, client %u msec",
                         tvb_get_guint8(tvb, offset + 3) * 10,
                         tvb_get_guint8(tvb, offset + 4) * 10);
}

static void dissect_intended_interface_addr(proto_item *tlv_root,
                                            proto_item *tlv_item,
                                            tvbuff_t *tvb, int offset)
{
  guint8 addr[6];
  proto_tree_add_item(tlv_root, hf_p2p_attr_intended_interface_addr, tvb,
                      offset + 3, 6, FALSE);
  tvb_memcpy(tvb, addr, offset + 3, 6);
  proto_item_append_text(tlv_item, ": %s", ether_to_str(addr));
}

static void dissect_extended_listen_timing(proto_item *tlv_root,
                                           proto_item *tlv_item,
                                           tvbuff_t *tvb, int offset)
{
  guint16 period, interval;
  period = tvb_get_letohs(tvb, offset + 3);
  interval = tvb_get_letohs(tvb, offset + 5);
  proto_tree_add_uint(tlv_root, hf_p2p_attr_extended_listen_timing_period, tvb,
                      offset + 3, 2, period);
  proto_tree_add_uint(tlv_root, hf_p2p_attr_extended_listen_timing_interval,
                      tvb, offset + 5, 2, interval);
  proto_item_append_text(tlv_item, ": Availability Period %u msec, "
                         "Availability Interval %u msec", period, interval);
}

static void dissect_wifi_p2p_group_id(proto_item *tlv_root,
                                      proto_item *tlv_item, tvbuff_t *tvb,
                                      int offset, guint16 slen)
{
  int s_offset;
  guint8 addr[6];

  s_offset = offset + 3;
  proto_tree_add_item(tlv_root, hf_p2p_attr_p2p_group_id_dev_addr, tvb,
                      s_offset, 6, FALSE);
  tvb_memcpy(tvb, addr, offset + 3, 6);
  proto_item_append_text(tlv_item, ": %s", ether_to_str(addr));
  s_offset += 6;
  proto_tree_add_item(tlv_root, hf_p2p_attr_p2p_group_id_ssid, tvb,
                      s_offset, offset + 3 + slen - s_offset, FALSE);
}

static void dissect_wifi_p2p_group_bssid(packet_info *pinfo,
                                         proto_item *tlv_root,
                                         proto_item *tlv_item, tvbuff_t *tvb,
                                         int offset, guint16 slen)
{
  int s_offset;
  guint8 addr[6];

  if (slen != 6) {
    expert_add_info_format(pinfo, tlv_item, PI_MALFORMED, PI_ERROR,
                           "Invalid ethernet address");
    return;
  }

  s_offset = offset + 3;
  proto_tree_add_item(tlv_root, hf_p2p_attr_p2p_group_bssid, tvb,
                      s_offset, 6, FALSE);
  tvb_memcpy(tvb, addr, offset + 3, 6);
  proto_item_append_text(tlv_item, ": %s", ether_to_str(addr));
}

static void dissect_notice_of_absence(packet_info *pinfo, proto_item *tlv_root,
                                      proto_item *tlv_item,
                                      tvbuff_t *tvb, int offset, guint16 slen)
{
  int s_offset = offset + 3;

  if (slen < 2) {
    expert_add_info_format(pinfo, tlv_item, PI_MALFORMED, PI_ERROR,
                           "Too short NoA");
    return;
  }

  proto_tree_add_item(tlv_root, hf_p2p_attr_noa_index, tvb, s_offset, 1,
                      ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root, hf_p2p_attr_noa_params, tvb, s_offset + 1, 1,
                      ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root, hf_p2p_attr_noa_params_opp_ps, tvb,
                      s_offset + 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root, hf_p2p_attr_noa_params_ctwindow, tvb,
                      s_offset + 1, 1, ENC_BIG_ENDIAN);

  s_offset += 2;
  while (offset + 3 + slen >= s_offset + 13) {
    proto_tree_add_item(tlv_root, hf_p2p_attr_noa_count_type, tvb, s_offset, 1,
                        ENC_BIG_ENDIAN);
    s_offset++;
    proto_tree_add_item(tlv_root, hf_p2p_attr_noa_duration, tvb, s_offset, 4,
                        ENC_LITTLE_ENDIAN);
    s_offset += 4;
    proto_tree_add_item(tlv_root, hf_p2p_attr_noa_interval, tvb, s_offset, 4,
                        ENC_LITTLE_ENDIAN);
    s_offset += 4;
    proto_tree_add_item(tlv_root, hf_p2p_attr_noa_start_time, tvb, s_offset, 4,
                        ENC_LITTLE_ENDIAN);
    s_offset += 4;
  }
}

static void dissect_wifi_p2p_group_info(packet_info *pinfo,
                                        proto_item *tlv_root,
                                        proto_item *tlv_item,
                                        tvbuff_t *tvb, int offset,
                                        guint16 slen)
{
  int s_offset = offset + 3;
  int next_offset, ci_len, num_sec, left, nlen;
  guint16 attr_type, attr_len;
  proto_item *item;

  while (offset + 3 + slen > s_offset) {
    if (offset + 3 + slen - s_offset < 25) {
      expert_add_info_format(pinfo, tlv_item, PI_MALFORMED, PI_ERROR,
                             "Too short P2P Client Info Descriptor");
      break;
    }

    item = proto_tree_add_item(tlv_root, hf_p2p_attr_gi_length, tvb, s_offset,
                               1, ENC_BIG_ENDIAN);
    ci_len = tvb_get_guint8(tvb, s_offset);
    if (ci_len < 24 || s_offset + ci_len > offset + 3 + slen) {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR,
                             "Invalid P2P Client Info Descriptor Length");
      break;
    }
    s_offset++;
    next_offset = s_offset + ci_len;

    proto_tree_add_item(tlv_root, hf_p2p_attr_gi_p2p_dev_addr, tvb, s_offset,
                        6, FALSE);
    s_offset += 6;

    proto_tree_add_item(tlv_root, hf_p2p_attr_gi_p2p_iface_addr, tvb, s_offset,
                        6, FALSE);
    s_offset += 6;

    proto_tree_add_item(tlv_root, hf_p2p_attr_gi_dev_capab, tvb, s_offset, 1,
                        ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_root,
                        hf_p2p_attr_gi_dev_capab_service_discovery, tvb,
                        s_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_root,
                        hf_p2p_attr_gi_dev_capab_client_discoverability,
                        tvb, s_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_root,
                        hf_p2p_attr_gi_dev_capab_concurrent_operation,
                        tvb, s_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_root,
                        hf_p2p_attr_gi_dev_capab_infrastructure_managed,
                        tvb, s_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_root, hf_p2p_attr_gi_dev_capab_limit, tvb,
                        s_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_root, hf_p2p_attr_capab_invitation_procedure, tvb,
                        s_offset, 1, ENC_BIG_ENDIAN);
    s_offset++;

    proto_tree_add_item(tlv_root, hf_p2p_attr_gi_config_methods, tvb, s_offset,
                        2, ENC_BIG_ENDIAN);
    s_offset += 2;

    proto_tree_add_item(tlv_root, hf_p2p_attr_gi_pri_dev_type, tvb,
                        s_offset, 8, ENC_NA);
    proto_tree_add_item(tlv_root, hf_p2p_attr_gi_pri_dev_type_category,
                        tvb, s_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_root, hf_p2p_attr_gi_pri_dev_type_oui,
                        tvb, s_offset + 2, 4, ENC_NA);
    proto_tree_add_item(tlv_root, hf_p2p_attr_gi_pri_dev_type_subcategory,
                        tvb, s_offset + 6, 2, ENC_BIG_ENDIAN);
    s_offset += 8;

    item = proto_tree_add_item(tlv_root, hf_p2p_attr_gi_num_sec_dev_types, tvb,
                               s_offset, 1, ENC_BIG_ENDIAN);
    num_sec = tvb_get_guint8(tvb, s_offset);
    s_offset++;
    left = offset + 3 + slen - s_offset;
    if (left < 8 * num_sec) {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR,
                             "Invalid Secondary Device Type List");
      break;
    }
    while (num_sec > 0) {
      proto_tree_add_item(tlv_root, hf_p2p_attr_gi_sec_dev_type,
                          tvb, s_offset, 8, ENC_NA);
      s_offset += 8;
      num_sec--;
    }

    item = proto_tree_add_item(tlv_root, hf_p2p_attr_gi_dev_name_type,
                               tvb, s_offset, 2, ENC_BIG_ENDIAN);
    attr_type = tvb_get_ntohs(tvb, s_offset);
    if (attr_type != 0x1011) {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR,
                             "Incorrect Device Name attribute type");
    }
    s_offset += 2;
    item = proto_tree_add_item(tlv_root, hf_p2p_attr_gi_dev_name_len,
                               tvb, s_offset, 2, ENC_BIG_ENDIAN);
    attr_len = tvb_get_ntohs(tvb, s_offset);
    s_offset += 2;
    if (attr_len > offset + 3 + slen - s_offset) {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR,
                             "Invalid Device Name attribute length");
      break;
    }
    nlen = offset + 3 + slen - s_offset;
    if (nlen > 0)
      item = proto_tree_add_item(tlv_root, hf_p2p_attr_gi_dev_name,
                                 tvb, s_offset,
                                 nlen > attr_len ? attr_len : nlen,
                                 FALSE);
    if (nlen != attr_len) {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR,
                             "Invalid Device Name attribute");
    }

    s_offset = next_offset;
  }
}

static void dissect_invitation_flags(proto_item *tlv_root,
                                     proto_item *tlv_item,
                                     tvbuff_t *tvb, int offset)
{
  proto_tree_add_item(tlv_root, hf_p2p_attr_invitation_flags, tvb,
                      offset + 3, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root, hf_p2p_attr_invitation_flags_type, tvb,
                      offset + 3, 1, ENC_BIG_ENDIAN);
  proto_item_append_text(tlv_item, ": Invitation Flags 0x%x",
                         tvb_get_guint8(tvb, offset + 3));
}

static void dissect_manageability(proto_item *tlv_root,
                                  proto_item *tlv_item,
                                  tvbuff_t *tvb, int offset)
{
  proto_tree_add_item(tlv_root, hf_p2p_attr_manageability_bitmap, tvb,
                      offset + 3, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root, hf_p2p_attr_manageability_bitmap_mgmt, tvb,
                      offset + 3, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root, hf_p2p_attr_manageability_bitmap_cross_connect,
                      tvb, offset + 3, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_root, hf_p2p_attr_manageability_bitmap_coex_opt, tvb,
                      offset + 3, 1, ENC_BIG_ENDIAN);
  proto_item_append_text(tlv_item, ": Bitmap field 0x%x",
                         tvb_get_guint8(tvb, offset + 3));
}

static void dissect_minor_reason_code(proto_item *tlv_root,
                                      proto_item *tlv_item,
                                      tvbuff_t *tvb, int offset)
{
  proto_tree_add_item(tlv_root, hf_p2p_attr_minor_reason_code, tvb,
                      offset + 3, 1, ENC_BIG_ENDIAN);
  proto_item_append_text(tlv_item, ": %u (%s)",
                         tvb_get_guint8(tvb, offset + 3),
                         val_to_str(tvb_get_guint8(tvb, offset + 3),
                                    p2p_minor_reason_codes,
                                    "Unknown Minor Reason Code (%u)"));
}

void dissect_wifi_p2p_ie(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb,
                         int offset, gint size)
{
  guint16 slen = 0;
  guint8 stype = 0;
  proto_item *tlv_root, *tlv_item;

  while (size > 0) {
    if (size < 3) {
      expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR,
                             "Packet too short for P2P IE");
      break;
    }

    stype = tvb_get_guint8(tvb, offset);
    slen = tvb_get_letohs(tvb, offset + 1);

    tlv_item = proto_tree_add_text(tree, tvb, offset, 3 + slen, "%s",
                                   val_to_str(stype, p2p_attr_types,
                                              "Unknown attribute type (%u)"));
    tlv_root = proto_item_add_subtree(tlv_item, ett_p2p_tlv);

    proto_tree_add_item(tlv_root, hf_p2p_attr_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_uint(tlv_root, hf_p2p_attr_len, tvb, offset + 1, 2,
                        slen);

    switch(stype) {
    case P2P_ATTR_P2P_CAPABILITY:
      dissect_wifi_p2p_capability(tlv_root, tlv_item, tvb, offset);
      break;
    case P2P_ATTR_P2P_DEVICE_ID:
      dissect_device_id(tlv_root, tlv_item, tvb, offset);
      break;
    case P2P_ATTR_GROUP_OWNER_INTENT:
      dissect_group_owner_intent(tlv_root, tlv_item, tvb, offset);
      break;
    case P2P_ATTR_STATUS:
      dissect_status(tlv_root, tlv_item, tvb, offset);
      break;
    case P2P_ATTR_LISTEN_CHANNEL:
      dissect_listen_channel(tlv_root, tlv_item, tvb, offset);
      break;
    case P2P_ATTR_OPERATING_CHANNEL:
      dissect_operating_channel(tlv_root, tlv_item, tvb, offset);
      break;
    case P2P_ATTR_CHANNEL_LIST:
      dissect_channel_list(tlv_root, tvb, offset, slen);
      break;
    case P2P_ATTR_P2P_DEVICE_INFO:
      dissect_wifi_p2p_device_info(pinfo, tlv_root, tvb, offset, slen);
      break;
    case P2P_ATTR_CONFIGURATION_TIMEOUT:
      dissect_configuration_timeout(tlv_root, tlv_item, tvb, offset);
      break;
    case P2P_ATTR_INTENDED_P2P_INTERFACE_ADDRESS:
      dissect_intended_interface_addr(tlv_root, tlv_item, tvb, offset);
      break;
    case P2P_ATTR_EXTENDED_LISTEN_TIMING:
      dissect_extended_listen_timing(tlv_root, tlv_item, tvb, offset);
      break;
    case P2P_ATTR_P2P_GROUP_ID:
      dissect_wifi_p2p_group_id(tlv_root, tlv_item, tvb, offset, slen);
      break;
    case P2P_ATTR_P2P_GROUP_BSSID:
      dissect_wifi_p2p_group_bssid(pinfo, tlv_root, tlv_item, tvb, offset, slen);
      break;
    case P2P_ATTR_NOTICE_OF_ABSENCE:
      dissect_notice_of_absence(pinfo, tlv_root, tlv_item, tvb, offset, slen);
      break;
    case P2P_ATTR_P2P_GROUP_INFO:
      dissect_wifi_p2p_group_info(pinfo, tlv_root, tlv_item, tvb, offset,
                                  slen);
      break;
    case P2P_ATTR_INVITATION_FLAGS:
      dissect_invitation_flags(tlv_root, tlv_item, tvb, offset);
      break;
    case P2P_ATTR_P2P_MANAGEABILITY:
      dissect_manageability(tlv_root, tlv_item, tvb, offset);
      break;
    case P2P_ATTR_MINOR_REASON_CODE:
      dissect_minor_reason_code(tlv_root, tlv_item, tvb, offset);
      break;
    }

    offset += 3 + slen;
    size -= 3 + slen;
  }
}

int dissect_wifi_p2p_public_action(proto_tree *tree, tvbuff_t *tvb, int offset)
{
  proto_tree_add_item(tree, hf_p2p_public_action_subtype, tvb, offset, 1,
                      ENC_BIG_ENDIAN);
  offset++;
  proto_tree_add_item(tree, hf_p2p_public_action_dialog_token, tvb, offset, 1,
                      ENC_BIG_ENDIAN);
  offset++;
  /* Followed by variable length IEs dissected by packet-ieee80211.c */
  return offset;
}

int dissect_wifi_p2p_action(proto_tree *tree, tvbuff_t *tvb, int offset)
{
  proto_tree_add_item(tree, hf_p2p_action_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;
  proto_tree_add_item(tree, hf_p2p_action_dialog_token, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;
  /* Followed by variable length IEs dissected by packet-ieee80211.c */
  return offset;
}

void dissect_wifi_p2p_anqp(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb,
                           int offset, gboolean request)
{
  proto_item *item;

  item = proto_tree_add_item(tree, hf_p2p_anqp_service_update_indicator, tvb,
                             offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

  while (tvb_length_remaining(tvb, offset) >= (request ? 4 : 5)) {
    guint16 len;
    proto_tree *tlv;
    guint8 type, id;

    len = tvb_get_letohs(tvb, offset);
    if (len < 2) {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR,
                             "Too short Service TLV field");
      return;
    }
    if (len > tvb_length_remaining(tvb, offset + 2)) {
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR,
                             "Too short frame for Service TLV field");
      return;
    }

    type = tvb_get_guint8(tvb, offset + 2);
    id = tvb_get_guint8(tvb, offset + 3);
    item = proto_tree_add_text(tree, tvb, offset, 2 + len,
                               "Service TLV (Transaction ID: %u  Type: %s)",
                               id, val_to_str(type, p2p_service_protocol_types,
                                              "Unknown (%u)"));
    tlv = proto_item_add_subtree(item, ett_p2p_service_tlv);

    proto_tree_add_item(tlv, hf_p2p_anqp_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tlv, hf_p2p_anqp_service_protocol_type, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv, hf_p2p_anqp_service_transaction_id, tvb,
                        offset + 1, 1, ENC_BIG_ENDIAN);
    if (request) {
      proto_tree_add_item(tlv, hf_p2p_anqp_query_data, tvb,
                          offset + 2, len - 2, ENC_NA);
    } else {
      proto_tree_add_item(tlv, hf_p2p_anqp_status_code, tvb,
                          offset + 2, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tlv, hf_p2p_anqp_response_data, tvb,
                          offset + 3, len - 3, ENC_NA);
    }
    offset += len;
  }

  if (tvb_length_remaining(tvb, offset) > 0) {
    expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR,
                           "Unexpected padding in the end of P2P ANQP");
  }
}

void
proto_register_p2p(void)
{
  static hf_register_info hf[] = {
    { &hf_p2p_attr_type,
      { "Attribute Type", "wifi_p2p.type",
        FT_UINT8, BASE_DEC, VALS(p2p_attr_types), 0x0, NULL, HFILL }},
    { &hf_p2p_attr_len,
      { "Attribute Length", "wifi_p2p.length",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_p2p_attr_capab,
      { "P2P Capability", "wifi_p2p.p2p_capability",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_capab_device,
      { "Device Capability Bitmap",
        "wifi_p2p.p2p_capability.device_capability",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_capab_device_service_discovery,
      { "Service Discovery",
        "wifi_p2p.p2p_capability.device_capability.service_discovery",
        FT_UINT8, BASE_HEX, NULL, P2P_DEV_CAPAB_SERVICE_DISCOVERY, NULL, HFILL
      }},
    { &hf_p2p_attr_capab_device_client_discoverability,
      { "P2P Client Discoverability",
        "wifi_p2p.p2p_capability.device_capability.client_discoverability",
        FT_UINT8, BASE_HEX, NULL, P2P_DEV_CAPAB_P2P_CLIENT_DISCOVERABILITY,
        NULL, HFILL
      }},
    { &hf_p2p_attr_capab_device_concurrent_operation,
      { "Concurrent Operation",
        "wifi_p2p.p2p_capability.device_capability.concurrent_operation",
        FT_UINT8, BASE_HEX, NULL, P2P_DEV_CAPAB_CONCURRENT_OPERATION, NULL,
        HFILL
      }},
    { &hf_p2p_attr_capab_device_infrastructure_managed,
      { "P2P Infrastructure Managed",
        "wifi_p2p.p2p_capability.device_capability.infrastructure_managed",
        FT_UINT8, BASE_HEX, NULL, P2P_DEV_CAPAB_P2P_INFRASTRUCTURE_MANAGED,
        NULL, HFILL
      }},
    { &hf_p2p_attr_capab_device_limit,
      { "P2P Device Limit",
        "wifi_p2p.p2p_capability.device_capability.device_limit",
        FT_UINT8, BASE_HEX, NULL, P2P_DEV_CAPAB_P2P_DEVICE_LIMIT, NULL, HFILL
      }},
    { &hf_p2p_attr_capab_invitation_procedure,
      { "P2P Invitation Procedure",
        "wifi_p2p.p2p_capability.device_capability.invitation_procedure",
        FT_UINT8, BASE_HEX, NULL, P2P_DEV_CAPAB_P2P_INVITATION_PROCEDURE, NULL,
        HFILL
      }},
    { &hf_p2p_attr_capab_group,
      { "Group Capability Bitmap", "wifi_p2p.p2p_capability.group_capability",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_capab_group_owner,
      { "P2P Group Owner",
        "wifi_p2p.p2p_capability.group_capability.group_owner",
        FT_UINT8, BASE_HEX, NULL, P2P_GROUP_CAPAB_P2P_GROUP_OWNER, NULL, HFILL
      }},
    { &hf_p2p_attr_capab_group_persistent,
      { "Persistent P2P Group",
        "wifi_p2p.p2p_capability.group_capability.persistent_group",
        FT_UINT8, BASE_HEX, NULL, P2P_GROUP_CAPAB_PERSISTENT_P2P_GROUP, NULL,
        HFILL }},
    { &hf_p2p_attr_capab_group_limit,
      { "P2P Group Limit",
        "wifi_p2p.p2p_capability.group_capability.group_limit",
        FT_UINT8, BASE_HEX, NULL, P2P_GROUP_CAPAB_P2P_GROUP_LIMIT, NULL, HFILL
      }},
    { &hf_p2p_attr_capab_group_intra_bss_distribution,
      { "Intra-BSS Distribution",
        "wifi_p2p.p2p_capability.group_capability.intra_bss_distribution",
        FT_UINT8, BASE_HEX, NULL, P2P_GROUP_CAPAB_INTRA_BSS_DISTRIBUTION, NULL,
        HFILL }},
    { &hf_p2p_attr_capab_group_cross_connection,
      { "Cross Connection",
        "wifi_p2p.p2p_capability.group_capability.cross_connection",
        FT_UINT8, BASE_HEX, NULL, P2P_GROUP_CAPAB_CROSS_CONNECTION, NULL, HFILL
      }},
    { &hf_p2p_attr_capab_group_persistent_reconnect,
      { "Persistent Reconnect",
        "wifi_p2p.p2p_capability.group_capability.persistent_reconnect",
        FT_UINT8, BASE_HEX, NULL, P2P_GROUP_CAPAB_PERSISTENT_RECONNECT, NULL,
        HFILL }},
    { &hf_p2p_attr_capab_group_group_formation,
      { "Group Formation",
        "wifi_p2p.p2p_capability.group_capability.group_formation",
        FT_UINT8, BASE_HEX, NULL, P2P_GROUP_CAPAB_GROUP_FORMATION, NULL, HFILL
      }},

    { &hf_p2p_attr_device_id,
      { "Device ID", "wifi_p2p.device_id",
        FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_p2p_attr_status,
      { "Status Code", "wifi_p2p.status",
        FT_UINT8, BASE_DEC, VALS(p2p_status_codes), 0x0, NULL, HFILL }},

    { &hf_p2p_attr_go_intent,
      { "Group Owner Intent", "wifi_p2p.go_intent",
        FT_UINT8, BASE_DEC, NULL, 0x1e, NULL, HFILL }},
    { &hf_p2p_attr_go_intent_tie_breaker,
      { "Group Owner Intent Tie Breaker", "wifi_p2p.go_intent_tie_breaker",
        FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL }},

    { &hf_p2p_attr_listen_channel,
      { "Listen Channel", "wifi_p2p.listen_channel",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_listen_channel_country,
      { "Country String", "wifi_p2p.listen_channel.country_string",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_listen_channel_oper_class,
      { "Operating Class", "wifi_p2p.listen_channel.operating_class",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_listen_channel_number,
      { "Channel Number", "wifi_p2p.listen_channel.channel_number",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_p2p_attr_operating_channel,
      { "Operating Channel", "wifi_p2p.operating_channel",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_operating_channel_country,
      { "Country String", "wifi_p2p.operating_channel.country_string",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_operating_channel_oper_class,
      { "Operating Class", "wifi_p2p.channel.operating_class",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_operating_channel_number,
      { "Channel Number", "wifi_p2p.channel.channel_number",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_p2p_attr_channel_list,
      { "Channel List", "wifi_p2p.channel_list",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_channel_list_country,
      { "Country String", "wifi_p2p.channel_list.country_string",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_channel_list_oper_class,
      { "Operating Class", "wifi_p2p.channel_list.operating_class",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_channel_list_num_chan,
      { "Number of Channels", "wifi_p2p.channel_list.num_chan",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_channel_list_chan,
      { "Channel List", "wifi_p2p.channel_list.channel_list",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_p2p_attr_dev_info,
      { "Device Info", "wifi_p2p.dev_info",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_dev_info_p2p_dev_addr,
      { "P2P Device address", "wifi_p2p.dev_info.p2p_dev_addr",
        FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_dev_info_pri_dev_type,
      { "Primary Device Type", "wifi_p2p.dev_info.pri_dev_type",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_dev_info_pri_dev_type_category,
      { "Primary Device Type: Category",
        "wifi_p2p.dev_info.pri_dev_type.category",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_dev_info_pri_dev_type_oui,
      { "Primary Device Type: OUI", "wifi_p2p.dev_info.pri_dev_type.oui",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_dev_info_pri_dev_type_subcategory,
      { "Primary Device Type: Subcategory",
        "wifi_p2p.dev_info.pri_dev_type.subcategory",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_dev_info_num_sec,
      { "Number of Secondary Device Types", "wifi_p2p.dev_info.num_sec",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_dev_info_sec_dev_type,
      { "Secondary Device Type", "wifi_p2p.dev_info.sec_dev_type",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_dev_info_dev_name_type,
      { "Device Name attribute type", "wifi_p2p.dev_info.dev_name_type",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_dev_info_dev_name_len,
      { "Device Name attribute length", "wifi_p2p.dev_info.dev_name",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_dev_info_dev_name,
      { "Device Name", "wifi_p2p.dev_info.dev_name",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_dev_info_config_methods,
      { "Config Methods", "wifi_p2p.dev_info.config_methods",
        FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
    { &hf_p2p_attr_dev_info_config_methods_usba,
      { "USBA (Flash Drive)", "wifi_p2p.dev_info.config_methods.usba",
        FT_UINT16, BASE_HEX, NULL, WPS_CONF_METH_USBA, NULL, HFILL }},
    { &hf_p2p_attr_dev_info_config_methods_ethernet,
      { "Ethernet", "wifi_p2p.dev_info.config_methods.ethernet",
        FT_UINT16, BASE_HEX, NULL, WPS_CONF_METH_ETHERNET, NULL, HFILL }},
    { &hf_p2p_attr_dev_info_config_methods_label,
      { "Label", "wifi_p2p.dev_info.config_methods.label",
        FT_UINT16, BASE_HEX, NULL, WPS_CONF_METH_LABEL, NULL, HFILL }},
    { &hf_p2p_attr_dev_info_config_methods_display,
      { "Display", "wifi_p2p.dev_info.config_methods.display",
        FT_UINT16, BASE_HEX, NULL, WPS_CONF_METH_DISPLAY, NULL, HFILL }},
    { &hf_p2p_attr_dev_info_config_methods_ext_nfc_token,
      { "External NFC Token", "wifi_p2p.dev_info.config_methods.ext_nfc_token",
        FT_UINT16, BASE_HEX, NULL, WPS_CONF_METH_EXT_NFC_TOKEN, NULL, HFILL }},
    { &hf_p2p_attr_dev_info_config_methods_int_nfc_token,
      { "Integrated NFC Token",
        "wifi_p2p.dev_info.config_methods.int_nfc_token",
        FT_UINT16, BASE_HEX, NULL, WPS_CONF_METH_INT_NFC_TOKEN, NULL, HFILL }},
    { &hf_p2p_attr_dev_info_config_methods_nfc_interface,
      { "NFC Interface", "wifi_p2p.dev_info.config_methods.nfc_interface",
        FT_UINT16, BASE_HEX, NULL, WPS_CONF_METH_NFC_INTERFACE, NULL, HFILL }},
    { &hf_p2p_attr_dev_info_config_methods_pushbutton,
      { "PushButton", "wifi_p2p.dev_info.config_methods.pushbutton",
        FT_UINT16, BASE_HEX, NULL, WPS_CONF_METH_PUSHBUTTON, NULL, HFILL }},
    { &hf_p2p_attr_dev_info_config_methods_keypad,
      { "Keypad", "wifi_p2p.dev_info.config_methods.keypad",
        FT_UINT16, BASE_HEX, NULL, WPS_CONF_METH_KEYPAD, NULL, HFILL }},
    { &hf_p2p_attr_config_timeout_go,
      { "GO Configuration Timeout", "wifi_p2p.config_timeout.go",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_config_timeout_client,
      { "Client Configuration Timeout", "wifi_p2p.config_timeout.client",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_intended_interface_addr,
      { "P2P Interface Address", "wifi_p2p.intended_interface_addr",
        FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_extended_listen_timing_period,
      { "Availability Period", "wifi_p2p.extended_listen_timing.period",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_extended_listen_timing_interval,
      { "Availability Interval", "wifi_p2p.extended_listen_timing.interval",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_p2p_group_id_dev_addr,
      { "P2P Device address", "wifi_p2p.p2p_group_id.p2p_dev_addr",
        FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_p2p_group_id_ssid,
      { "SSID", "wifi_p2p.p2p_group_id.ssid",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_p2p_group_bssid,
      { "BSSID", "wifi_p2p.p2p_group_bssid",
        FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_p2p_attr_noa_index,
      { "Index", "wifi_p2p.noa.index",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_noa_params,
      { "CTWindow and OppPS Parameters", "wifi_p2p.noa.params",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_noa_params_opp_ps,
      { "OppPS", "wifi_p2p.noa.params.opp_ps",
        FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }},
    { &hf_p2p_attr_noa_params_ctwindow,
      { "CTWindow", "wifi_p2p.noa.params.ctwindow",
        FT_UINT8, BASE_DEC, NULL, 0x7f, NULL, HFILL }},
    { &hf_p2p_attr_noa_count_type,
      { "Count/Type", "wifi_p2p.noa.count_type",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_noa_duration,
      { "Duration", "wifi_p2p.noa.duration",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_noa_interval,
      { "Interval", "wifi_p2p.noa.interval",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_noa_start_time,
      { "Start Time", "wifi_p2p.noa.start_time",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_p2p_attr_gi,
      { "Device Info", "wifi_p2p.group_info",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_gi_length,
      { "P2P Client Info Descriptor Length", "wifi_p2p.group_info.length",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_gi_p2p_dev_addr,
      { "P2P Device address", "wifi_p2p.group_info.p2p_dev_addr",
        FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_gi_p2p_iface_addr,
      { "P2P Interface address", "wifi_p2p.group_info.p2p_interface_addr",
        FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_gi_dev_capab,
      { "Device Capability Bitmap", "wifi_p2p.group_info.device_capability",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_gi_dev_capab_service_discovery,
      { "Service Discovery",
        "wifi_p2p.group_info.device_capability.service_discovery",
        FT_UINT8, BASE_HEX, NULL, P2P_DEV_CAPAB_SERVICE_DISCOVERY, NULL, HFILL
      }},
    { &hf_p2p_attr_gi_dev_capab_client_discoverability,
      { "P2P Client Discoverability",
        "wifi_p2p.group_info.device_capability.client_discoverability",
        FT_UINT8, BASE_HEX, NULL, P2P_DEV_CAPAB_P2P_CLIENT_DISCOVERABILITY,
        NULL, HFILL
      }},
    { &hf_p2p_attr_gi_dev_capab_concurrent_operation,
      { "Concurrent Operation",
        "wifi_p2p.group_info.device_capability.concurrent_operation",
        FT_UINT8, BASE_HEX, NULL, P2P_DEV_CAPAB_CONCURRENT_OPERATION, NULL,
        HFILL
      }},
    { &hf_p2p_attr_gi_dev_capab_infrastructure_managed,
      { "P2P Infrastructure Managed",
        "wifi_p2p.group_info.device_capability.infrastructure_managed",
        FT_UINT8, BASE_HEX, NULL, P2P_DEV_CAPAB_P2P_INFRASTRUCTURE_MANAGED,
        NULL, HFILL
      }},
    { &hf_p2p_attr_gi_dev_capab_limit,
      { "P2P Device Limit",
        "wifi_p2p.group_info.device_capability.device_limit",
        FT_UINT8, BASE_HEX, NULL, P2P_DEV_CAPAB_P2P_DEVICE_LIMIT, NULL, HFILL
      }},
    { &hf_p2p_attr_gi_dev_capab_invitation_procedure,
      { "P2P Invitation Procedure",
        "wifi_p2p.group_info.device_capability.invitation_procedure",
        FT_UINT8, BASE_HEX, NULL, P2P_DEV_CAPAB_P2P_INVITATION_PROCEDURE, NULL,
        HFILL
      }},
    { &hf_p2p_attr_gi_pri_dev_type,
      { "Primary Device Type", "wifi_p2p.group_info.pri_dev_type",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_gi_pri_dev_type_category,
      { "Primary Device Type: Category",
        "wifi_p2p.group_info.pri_dev_type.category",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_gi_pri_dev_type_oui,
      { "Primary Device Type: OUI", "wifi_p2p.group_info.pri_dev_type.oui",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_gi_pri_dev_type_subcategory,
      { "Primary Device Type: Subcategory",
        "wifi_p2p.group_info.pri_dev_type.subcategory",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_gi_num_sec_dev_types,
      { "Number of Secondary Device Types", "wifi_p2p.group_info.num_sec",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_gi_sec_dev_type,
      { "Secondary Device Type", "wifi_p2p.group_info.sec_dev_type",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_gi_dev_name_type,
      { "Device Name attribute type", "wifi_p2p.group_info.dev_name_type",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_gi_dev_name_len,
      { "Device Name attribute length", "wifi_p2p.group_info.dev_name",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_gi_dev_name,
      { "Device Name", "wifi_p2p.group_info.dev_name",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_gi_config_methods,
      { "Config Methods", "wifi_p2p.group_info.config_methods",
        FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
    { &hf_p2p_attr_gi_config_methods_usba,
      { "USBA (Flash Drive)", "wifi_p2p.group_info.config_methods.usba",
        FT_UINT16, BASE_HEX, NULL, WPS_CONF_METH_USBA, NULL, HFILL }},
    { &hf_p2p_attr_gi_config_methods_ethernet,
      { "Ethernet", "wifi_p2p.group_info.config_methods.ethernet",
        FT_UINT16, BASE_HEX, NULL, WPS_CONF_METH_ETHERNET, NULL, HFILL }},
    { &hf_p2p_attr_gi_config_methods_label,
      { "Label", "wifi_p2p.group_info.config_methods.label",
        FT_UINT16, BASE_HEX, NULL, WPS_CONF_METH_LABEL, NULL, HFILL }},
    { &hf_p2p_attr_gi_config_methods_display,
      { "Display", "wifi_p2p.group_info.config_methods.display",
        FT_UINT16, BASE_HEX, NULL, WPS_CONF_METH_DISPLAY, NULL, HFILL }},
    { &hf_p2p_attr_gi_config_methods_ext_nfc_token,
      { "External NFC Token",
        "wifi_p2p.group_info.config_methods.ext_nfc_token",
        FT_UINT16, BASE_HEX, NULL, WPS_CONF_METH_EXT_NFC_TOKEN, NULL, HFILL }},
    { &hf_p2p_attr_gi_config_methods_int_nfc_token,
      { "Integrated NFC Token",
        "wifi_p2p.group_info.config_methods.int_nfc_token",
        FT_UINT16, BASE_HEX, NULL, WPS_CONF_METH_INT_NFC_TOKEN, NULL, HFILL }},
    { &hf_p2p_attr_gi_config_methods_nfc_interface,
      { "NFC Interface", "wifi_p2p.group_info.config_methods.nfc_interface",
        FT_UINT16, BASE_HEX, NULL, WPS_CONF_METH_NFC_INTERFACE, NULL, HFILL }},
    { &hf_p2p_attr_gi_config_methods_pushbutton,
      { "PushButton", "wifi_p2p.group_info.config_methods.pushbutton",
        FT_UINT16, BASE_HEX, NULL, WPS_CONF_METH_PUSHBUTTON, NULL, HFILL }},
    { &hf_p2p_attr_gi_config_methods_keypad,
      { "Keypad", "wifi_p2p.group_info.config_methods.keypad",
        FT_UINT16, BASE_HEX, NULL, WPS_CONF_METH_KEYPAD, NULL, HFILL }},

    { &hf_p2p_attr_invitation_flags,
      { "Invitation Flags", "wifi_p2p.invitation_flags",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_invitation_flags_type,
      { "Invitation Type", "wifi_p2p.invitation_flags.type",
        FT_UINT8, BASE_HEX, VALS(invitation_types), 0x01, NULL, HFILL }},

    { &hf_p2p_attr_manageability_bitmap,
      { "Manageability Bitmap field", "wifi_p2p.manageability.bitmap",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_attr_manageability_bitmap_mgmt,
      { "P2P Device Management", "wifi_p2p.manageability.bitmap.dev_mgmt",
        FT_UINT8, BASE_HEX, NULL, 0x01, NULL, HFILL }},
    { &hf_p2p_attr_manageability_bitmap_cross_connect,
      { "Cross Connection Permitted",
        "wifi_p2p.manageability.bitmap.cross_connect",
        FT_UINT8, BASE_HEX, NULL, 0x02, NULL, HFILL }},
    { &hf_p2p_attr_manageability_bitmap_coex_opt,
      { "Coexistence Optional", "wifi_p2p.manageability.bitmap.coex_opt",
        FT_UINT8, BASE_HEX, NULL, 0x04, NULL, HFILL }},

    { &hf_p2p_attr_minor_reason_code,
      { "Minor Reason Code", "wifi_p2p.minor_reason_code",
        FT_UINT8, BASE_DEC, VALS(p2p_minor_reason_codes), 0x0, NULL, HFILL }},

    { &hf_p2p_anqp_service_update_indicator,
      { "Service Update Indicator", "wifi_p2p.anqp.service_update_indicator",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_anqp_length,
      { "Length", "wifi_p2p.anqp.length",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_anqp_service_protocol_type,
      { "Service Protocol Type", "wifi_p2p.anqp.service_protocol_type",
        FT_UINT8, BASE_DEC, VALS(p2p_service_protocol_types), 0x0, NULL,
        HFILL }},
    { &hf_p2p_anqp_service_transaction_id,
      { "Service Transaction ID", "wifi_p2p.anqp.service_transaction_id",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_anqp_query_data,
      { "Query Data", "wifi_p2p.anqp.query_data",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_anqp_status_code,
      { "Status Code", "wifi_p2p.anqp.status_code",
        FT_UINT8, BASE_DEC, VALS(p2p_sd_status_codes), 0x0,
        "Service Query Status Code", HFILL }},
    { &hf_p2p_anqp_response_data,
      { "Response Data", "wifi_p2p.anqp.response_data",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_p2p_action_subtype,
      { "P2P Action Subtype", "wifi_p2p.action.subtype",
        FT_UINT8, BASE_DEC, VALS(p2p_action_subtypes), 0x0, NULL, HFILL }},
    { &hf_p2p_action_dialog_token,
      { "P2P Action Dialog Token", "wifi_p2p.action.dialog_token",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_p2p_public_action_subtype,
      { "P2P Public Action Subtype", "wifi_p2p.public_action.subtype",
        FT_UINT8, BASE_DEC, VALS(p2p_public_action_subtypes), 0x0, NULL, HFILL
      }},
    { &hf_p2p_public_action_dialog_token,
      { "P2P Public Action Dialog Token",
        "wifi_p2p.public_action.dialog_token",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }}
  };
  static gint *ett[] = {
    &ett_p2p_tlv,
    &ett_p2p_service_tlv
  };

  proto_p2p = proto_register_protocol("Wi-Fi Peer-to-Peer", "Wi-Fi P2P",
                                      "wifi_p2p");
  proto_register_field_array(proto_p2p, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
