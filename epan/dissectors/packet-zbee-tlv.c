/* packet-zbee-tlv.c
 * Dissector routines for the Zbee TLV (R23+)
 * Copyright 2021 DSR Corporation, http://dsr-wireless.com/
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/proto_data.h>

#include "packet-ieee802154.h"
#include "packet-ieee802154.h"
#include "packet-zbee-tlv.h"
#include "packet-zbee.h"
#include "packet-zbee-nwk.h"
#include "packet-zbee-zdp.h"
#include "packet-zbee-aps.h"
#include "packet-zbee-direct.h"

#include "conversation.h"

/*-------------------------------------
 * Dissector Function Prototypes
 *-------------------------------------
 */
static int   dissect_zbee_tlv_default(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);
static unsigned dissect_zdp_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset, unsigned cmd_id);
static unsigned dissect_aps_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset, void *data, unsigned cmd_id);
static unsigned dissect_zbd_local_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset, void* data _U_, unsigned cmd_id);
static unsigned dissect_unknown_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);

//Global TLV Dissector Routines
static unsigned dissect_zbee_tlv_manufacturer_specific(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset, uint8_t length);
static unsigned dissect_zbee_tlv_supported_key_negotiation_methods(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_configuration_parameters(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_dev_cap_ext(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_panid_conflict_report(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_next_pan_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_next_channel_change(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_passphrase(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_router_information(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_fragmentation_parameters(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_potential_parents(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);

//Local TLV Dissector Routines
static unsigned dissect_zbee_tlv_selected_key_negotiation_method(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_public_point(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset, uint8_t length);
static unsigned dissect_zbee_tlv_eui64(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_clear_all_bindigs_eui64(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_requested_auth_token_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_target_ieee_address(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_device_auth_level(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_chanmask(proto_tree *tree, tvbuff_t *tvb, unsigned offset, int hf_page, int hf_channel);
static unsigned dissect_zbee_tlv_ext_pan_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_short_pan_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_nwk_key(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_dev_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_nwk_addr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_join_method(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_ieee_addr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_tc_addr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_nwk_upd_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_key_seq_num(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_adm_key(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_mj_prov_lnk_key(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_mj_ieee_addr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_mj_cmd(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_nwk_channel_list(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_link_key(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_nwk_status_map(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_status_code(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_tunneling_npdu_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint8_t length);
static unsigned dissect_zbee_tlv_key_neg_method(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbee_tlv_mac_tag(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset, uint8_t mac_tag_size);
static unsigned dissect_zbee_tlv_nwk_key_seq_num(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);

//Dissectors for ZB Direct
static unsigned dissect_zbd_msg_status_local_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbd_msg_tunneling_local_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbd_msg_manage_joiners_local_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbd_msg_join_local_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbd_msg_formation_local_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);
static unsigned dissect_zbd_msg_secur_local_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset);

void proto_register_zbee_tlv(void);

/* Initialize Protocol and Registered fields */
static int proto_zbee_tlv;
static dissector_handle_t zigbee_aps_handle;
static dissector_handle_t zbee_nwk_handle;

static int hf_zbee_tlv_global_type;
static int hf_zbee_tlv_local_type_key_update_req_rsp;
static int hf_zbee_tlv_local_type_key_negotiation_req_rsp;
static int hf_zbee_tlv_local_type_get_auth_level_rsp;
static int hf_zbee_tlv_local_type_clear_all_bindings_req;
static int hf_zbee_tlv_local_type_req_security_get_auth_token;
static int hf_zbee_tlv_local_type_req_security_get_auth_level;
static int hf_zbee_tlv_local_type_req_security_decommission;
static int hf_zbee_tlv_local_type_req_beacon_survey;
static int hf_zbee_tlv_local_type_rsp_beacon_survey;
static int hf_zbee_tlv_local_type_req_challenge;
static int hf_zbee_tlv_local_type_rsp_challenge;
static int hf_zbee_tlv_local_type_rsp_set_configuration;

static int hf_zbee_tlv_length;
static int hf_zbee_tlv_type;
static int hf_zbee_tlv_value;
static int hf_zbee_tlv_count;
static int hf_zbee_tlv_manufacturer_specific;

static int hf_zbee_tlv_local_status_count;
static int hf_zbee_tlv_local_type_id;
static int hf_zbee_tlv_local_proc_status;

static int hf_zbee_tlv_local_comm_ext_pan_id;
static int hf_zbee_tlv_local_comm_short_pan_id;
static int hf_zbee_tlv_local_comm_channel_mask;
static int hf_zbee_tlv_local_comm_channel_page;
static int hf_zbee_tlv_local_comm_channel_page_count;
static int hf_zbee_tlv_local_comm_nwk_key;
static int hf_zbee_tlv_local_comm_link_key;
static int hf_zbee_tlv_local_comm_link_key_flags;
static int hf_zbee_tlv_local_comm_link_key_flags_unique;
static int hf_zbee_tlv_local_comm_link_key_flags_provisional;
static int hf_zbee_tlv_local_comm_dev_type;
static int hf_zbee_tlv_local_comm_nwk_addr;
static int hf_zbee_tlv_local_comm_join_method;
static int hf_zbee_tlv_local_comm_tc_addr;
static int hf_zbee_tlv_local_comm_network_status_map;
static int hf_zbee_tlv_local_comm_network_status_map_joined_status;
static int hf_zbee_tlv_local_comm_network_status_map_open_status;
static int hf_zbee_tlv_network_status_map_network_type;
static int hf_zbee_tlv_local_comm_nwk_upd_id;
static int hf_zbee_tlv_local_comm_key_seq_num;
static int hf_zbee_tlv_local_comm_adm_key;
static int hf_zbee_tlv_local_comm_status_code_domain;
static int hf_zbee_tlv_local_comm_status_code_value;
static int hf_zbee_tlv_local_comm_mj_prov_lnk_key;
static int hf_zbee_tlv_local_comm_mj_ieee_addr;
static int hf_zbee_tlv_local_comm_mj_cmd;

static int hf_zbee_tlv_local_tunneling_npdu;
static int hf_zbee_tlv_local_tunneling_npdu_flags;
static int hf_zbee_tlv_local_tunneling_npdu_flags_security;
static int hf_zbee_tlv_local_tunneling_npdu_flags_reserved;
static int hf_zbee_tlv_local_tunneling_npdu_length;

static int hf_zbee_tlv_local_selected_key_method;
static int hf_zbee_tlv_local_selected_psk_secret;
static int hf_zbee_tlv_local_nwk_key_seq_num;
static int hf_zbee_tlv_local_mac_tag;

static int hf_zbee_tlv_zbd_comm_tlv;
static int hf_zbee_tlv_zbd_comm_mj_cmd_tlv;
static int hf_zbee_tlv_zbd_secur_tlv;
static int hf_zbee_tlv_zbd_tunneling_npdu_msg_tlv;

static int hf_zbee_tlv_next_pan_id;
static int hf_zbee_tlv_next_channel_change;
static int hf_zbee_tlv_passphrase;
static int hf_zbee_tlv_configuration_param;
static int hf_zbee_tlv_configuration_param_restricted_mode;
static int hf_zbee_tlv_configuration_param_link_key_enc;
static int hf_zbee_tlv_configuration_param_leave_req_allowed;

static int hf_zbee_tlv_dev_cap_ext_capability_information;
static int hf_zbee_tlv_dev_cap_ext_zbdirect_virt_device;

static int hf_zbee_tlv_challenge_value;
static int hf_zbee_tlv_aps_frame_counter;
static int hf_zbee_tlv_challenge_counter;
static int hf_zbee_tlv_mic64;

static int hf_zbee_tlv_lqa;

static int hf_zbee_tlv_router_information;
static int hf_zbee_tlv_router_information_hub_connectivity;
static int hf_zbee_tlv_router_information_uptime;
static int hf_zbee_tlv_router_information_pref_parent;
static int hf_zbee_tlv_router_information_battery_backup;
static int hf_zbee_tlv_router_information_enhanced_beacon_request_support;
static int hf_zbee_tlv_router_information_mac_data_poll_keepalive_support;
static int hf_zbee_tlv_router_information_end_device_keepalive_support;
static int hf_zbee_tlv_router_information_power_negotiation_support;

static int hf_zbee_tlv_node_id;
static int hf_zbee_tlv_frag_opt;
static int hf_zbee_tlv_max_reassembled_buf_size;

static int hf_zbee_tlv_supported_key_negotiation_methods;
static int hf_zbee_tlv_supported_key_negotiation_methods_key_request;
static int hf_zbee_tlv_supported_key_negotiation_methods_ecdhe_using_curve25519_aes_mmo128;
static int hf_zbee_tlv_supported_key_negotiation_methods_ecdhe_using_curve25519_sha256;
static int hf_zbee_tlv_supported_secrets;
static int hf_zbee_tlv_supported_preshared_secrets_auth_token;
static int hf_zbee_tlv_supported_preshared_secrets_ic;
static int hf_zbee_tlv_supported_preshared_secrets_passcode_pake;
static int hf_zbee_tlv_supported_preshared_secrets_basic_access_key;
static int hf_zbee_tlv_supported_preshared_secrets_admin_access_key;

static int hf_zbee_tlv_panid_conflict_cnt;

static int hf_zbee_tlv_selected_key_negotiation_method;
static int hf_zbee_tlv_selected_pre_shared_secret;
static int hf_zbee_tlv_device_eui64;
static int hf_zbee_tlv_public_point;
static int hf_zbee_tlv_global_tlv_id;
static int hf_zbee_tlv_local_ieee_addr;
static int hf_zbee_tlv_local_initial_join_method;
static int hf_zbee_tlv_local_active_lk_type;

static int hf_zbee_tlv_relay_msg_type;
static int hf_zbee_tlv_relay_msg_length;
static int hf_zbee_tlv_relay_msg_joiner_ieee;

static int ett_zbee_aps_tlv;
static int ett_zbee_aps_relay;
static int ett_zbee_tlv;
static int ett_zbee_tlv_supported_key_negotiation_methods;
static int ett_zbee_tlv_supported_secrets;
static int ett_zbee_tlv_router_information;
static int ett_zbee_tlv_configuration_param;
static int ett_zbee_tlv_capability_information;

static int ett_zbee_tlv_zbd_tunneling_npdu;
static int ett_zbee_tlv_zbd_tunneling_npdu_flags;

static int ett_zbee_tlv_link_key_flags;
static int ett_zbee_tlv_network_status_map;

static expert_field ei_zbee_tlv_max_recursion_depth_reached;

static const value_string zbee_tlv_local_types_key_method_str[] =
{
    { ZBEE_TLV_TYPE_KEY_ECDHE_CURVE_25519_HASH_AESMMO128, "Curve 25519 / AESMMO-128" },
    { ZBEE_TLV_TYPE_KEY_ECDHE_CURVE_25519_HASH_SHA256,    "Curve 25519 / SHA-256" },
    { ZBEE_TLV_TYPE_KEY_ECDHE_CURVE_P256_HASH_SHA256,     "P-256 / SHA-256" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_psk_secret_str[] =
{
    { ZBEE_TLV_TYPE_PSK_WELL_KNOWN_KEY,                   "Well known key" },
    { ZBEE_TLV_TYPE_PSK_SECRET_AUTH_TOKEN,                "Authorization token" },
    { ZBEE_TLV_TYPE_PSK_SECRET_INSTALL_CODE,              "Pre-configured link-ley derived from installation code" },
    { ZBEE_TLV_TYPE_PSK_SECRET_PAKE_PASSCODE,             "PAKE passcode" },
    { ZBEE_TLV_TYPE_PSK_SECRET_BASIC_ACCESS_KEY,          "Basic Access Key" },
    { ZBEE_TLV_TYPE_PSK_SECRET_ADMINISTRATIVE_ACCESS_KEY, "Administrative Access Key" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_dev_type_str[] =
{
    { ZBEE_TLV_TYPE_DEV_TYPE_ZC, "ZigBee Coordinator" },
    { ZBEE_TLV_TYPE_DEV_TYPE_ZR, "ZigBee Router" },
    { ZBEE_TLV_TYPE_DEV_TYPE_ED, "ZigBee End Device" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_join_method_str[] =
{
    { ZBEE_TLV_TYPE_JOIN_METHOD_MAC_ASS,           "MAC association" },
    { ZBEE_TLV_TYPE_JOIN_METHOD_NWK_REJ,           "NWK rejoin" },
    { ZBEE_TLV_TYPE_JOIN_METHOD_OOB_WITH_CHECK,    "Out-of-band commissioning (with check for nearby IEEE 802.15.4 beacons)" },
    { ZBEE_TLV_TYPE_JOIN_METHOD_OOB_WITHOUT_CHECK, "Out-of-band commissioning (without check for nearby IEEE 802.15.4 beacons)" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_status_code_domain_str[] =
{
    { ZBEE_TLV_TYPE_ZBD_STATUS_DOMAIN_GENERAL,         "General domain or unspecific operation" },
    { ZBEE_TLV_TYPE_ZBD_STATUS_DOMAIN_FORM,            "Form Network Operation" },
    { ZBEE_TLV_TYPE_ZBD_STATUS_DOMAIN_JOIN,            "Join Network Operation" },
    { ZBEE_TLV_TYPE_ZBD_STATUS_DOMAIN_PERMIT_JOIN,     "Permit Joining Operation" },
    { ZBEE_TLV_TYPE_ZBD_STATUS_DOMAIN_LEAVE,           "Leave Network Operation" },
    { ZBEE_TLV_TYPE_ZBD_STATUS_DOMAIN_MANAGE_JOINERS,  "Manage Joiners Domain" },
    { ZBEE_TLV_TYPE_ZBD_STATUS_DOMAIN_IDENTIFY,        "Identify Operation" },
    { ZBEE_TLV_TYPE_ZBD_STATUS_DOMAIN_FINDING_BINDING, "Finding & Binding Domain" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_joined_status_str[] =
{
    { ZBEE_TLV_TYPE_JOINED_STATUS_NO_NWK,           "No network" },
    { ZBEE_TLV_TYPE_JOINED_STATUS_JOINING,          "Joining" },
    { ZBEE_TLV_TYPE_JOINED_STATUS_JOINED,           "Joined" },
    { ZBEE_TLV_TYPE_JOINED_STATUS_JOINED_NO_PARENT, "Joined (no parent)" },
    { ZBEE_TLV_TYPE_JOINED_STATUS_LEAVING,          "Leaving" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_nwk_type_str[] =
{
    { ZBEE_TLV_NWK_TYPE_DISTRIBUTED, "Distributed" },
    { ZBEE_TLV_NWK_TYPE_CENTRALIZED, "Centralized" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_nwk_state_str[] =
{
    { ZBEE_TLV_TYPE_NWK_STATE_CLOSED, "Closed" },
    { ZBEE_TLV_TYPE_NWK_STATE_OPENED, "Opened" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_mj_cmd_str[] =
{
    { ZBEE_TLV_TYPE_MANAGE_JOINERS_CMD_DROP,   "Drop all joiners' Provisional Link Keys" },
    { ZBEE_TLV_TYPE_MANAGE_JOINERS_CMD_ADD,    "Add a joiner's Provisional Link Key" },
    { ZBEE_TLV_TYPE_MANAGE_JOINERS_CMD_REMOVE, "Remove a joiner's Provisional Link Key" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_lnk_key_unique_str[] =
{
    { ZBEE_TLV_TYPE_LINK_KEY_FLAG_GLOBAL, "Global" },
    { ZBEE_TLV_TYPE_LINK_KEY_FLAG_UNIQUE, "Unique" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_lnk_key_provisional_str[] =
{
    { ZBEE_TLV_TYPE_LINK_KEY_FLAG_PERMANENT,   "Permanent" },
    { ZBEE_TLV_TYPE_LINK_KEY_FLAG_PROVISIONAL, "Provisional" },
    { 0, NULL }
};

static const value_string zbee_tlv_zbd_comm_types[] = {
    { ZBEE_TLV_TYPE_COMM_EXT_PAN_ID,      "Extended PAN ID" },
    { ZBEE_TLV_TYPE_COMM_SHORT_PAN_ID,    "Short PAN ID" },
    { ZBEE_TLV_TYPE_COMM_NWK_CH,          "Network Channel" },
    { ZBEE_TLV_TYPE_COMM_NWK_KEY,         "Network Key" },
    { ZBEE_TLV_TYPE_COMM_LNK_KEY,         "Link Key" },
    { ZBEE_TLV_TYPE_COMM_DEV_TYPE,        "Device Type" },
    { ZBEE_TLV_TYPE_COMM_NWK_ADDR,        "NWK Address" },
    { ZBEE_TLV_TYPE_COMM_JOIN_METHOD,     "Joining Method" },
    { ZBEE_TLV_TYPE_COMM_IEEE_ADDR,       "IEEE Address" },
    { ZBEE_TLV_TYPE_COMM_TC_ADDR,         "Trust Center Address" },
    { ZBEE_TLV_TYPE_COMM_NWK_STATUS_MAP,  "Network Status Map" },
    { ZBEE_TLV_TYPE_COMM_NWK_UPD_ID,      "NWK Update ID" },
    { ZBEE_TLV_TYPE_COMM_KEY_SEQ_NUM,     "NWK Active Key Seq Number" },
    { ZBEE_TLV_TYPE_COMM_ADMIN_KEY,       "Admin Key" },
    { ZBEE_TLV_TYPE_COMM_STATUS_CODE,     "Status Code" },

    // TODO: Not implemented yet
    // { 0x0f,                                      "Extended Status Code" },
    { 0, NULL }
};

static const value_string zbee_tlv_zbd_comm_mj_types[] = {
    { ZBEE_TLV_TYPE_COMM_MJ_PROVISIONAL_LINK_KEY,  "Provisional Link" },
    { ZBEE_TLV_TYPE_COMM_MJ_IEEE_ADDR,             "IEEE Address" },
    { ZBEE_TLV_TYPE_COMM_MJ_CMD,                   "Manage Joiners Command" },

    // 0x03-0xff - Reserved
    { 0, NULL }
};

static const value_string zbee_tlv_zbd_secur_types[] = {
    { ZBEE_TLV_TYPE_KEY_METHOD,        "ZBD Key Negotiation Method TLV" },
    { ZBEE_TLV_TYPE_PUB_POINT_P256,    "ZBD Key Negotiation P-256 Public Point TLV" },
    { ZBEE_TLV_TYPE_PUB_POINT_C25519,  "ZBD Key Negotiation Curve25519 Public Point TLV" },
    { ZBEE_TLV_TYPE_NWK_KEY_SEQ_NUM,   "Network KeySequence Number TLV" },
    { ZBEE_TLV_TYPE_MAC_TAG,           "MacTag Tlv" },
    { 0, NULL }
};

static const value_string zbee_aps_relay_tlvs[] = {
    { 0,          "Relay Message TLV" },
    { 0, NULL }
};

static const value_string zbee_tlv_global_types[] = {
    { ZBEE_TLV_TYPE_MANUFACTURER_SPECIFIC,                "Manufacturer Specific Global TLV" },
    { ZBEE_TLV_TYPE_SUPPORTED_KEY_NEGOTIATION_METHODS,    "Supported Key Negotiation Methods Global TLV" },
    { ZBEE_TLV_TYPE_PANID_CONFLICT_REPORT,                "PAN ID Conflict Report Global TLV"},
    { ZBEE_TLV_TYPE_NEXT_PAN_ID,                          "Next PAN ID Global TLV" },
    { ZBEE_TLV_TYPE_NEXT_CHANNEL_CHANGE,                  "Next Channel Change Global TLV" },
    { ZBEE_TLV_TYPE_PASSPHRASE,                           "Passphrase Global TLV" },
    { ZBEE_TLV_TYPE_ROUTER_INFORMATION,                   "Router Information Global TLV" },
    { ZBEE_TLV_TYPE_FRAGMENTATION_PARAMETERS,             "Fragmentation Parameters Global TLV" },
    { ZBEE_TLV_TYPE_JOINER_ENCAPSULATION_GLOBAL,          "Joiner Encapsulation Global TLV" },
    { ZBEE_TLV_TYPE_BEACON_APPENDIX_ENCAPSULATION_GLOBAL, "Beacon Appendix Encapsulation Global TLV" },
    { ZBEE_TLV_TYPE_CONFIGURATION_MODE_PARAMETERS,        "Configuration Mode Parameters Global TLV" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_key_update_req_rsp[] = {
    { ZBEE_TLV_TYPE_KEY_UPD_REQ_SELECTED_KEY_NEGOTIATION_METHOD,   "Selected Key Negotiations Method Local TLV" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_key_negotiation_req_rsp[] = {
    { ZBEE_TLV_TYPE_KEY_NEG_REQ_CURVE25519_PUBLIC_POINT,           "Curve25519 Public Point Local TLV" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_get_auth_level_rsp[] = {
    { ZBEE_TLV_TYPE_GET_AUTH_LEVEL,                    "Device Authentication Level TLV" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_clear_all_bindings_req[] = {
    { ZBEE_TLV_TYPE_CLEAR_ALL_BINDIGS_REQ_EUI64,       "Clear All Bindings Req EUI64 TLV" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_req_security_get_auth_token[] = {
    { ZBEE_TLV_TYPE_REQUESTED_AUTH_TOKEN_ID,           "Requested Authentication Token ID TLV" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_req_security_get_auth_level[] = {
    { ZBEE_TLV_TYPE_TARGET_IEEE_ADDRESS,               "Target IEEE Address TLV" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_req_security_decommission[] = {
    { ZBEE_TLV_TYPE_EUI64,                             "EUI64 TLV" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_req_beacon_survey[] = {
    { ZBEE_TLV_TYPE_BEACON_SURVEY_CONFIGURATION,       "Beacon Survey Configuration TLV" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_req_challenge[] = {
    { 0,       "APS Frame Counter Challenge Request TLV" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_rsp_challenge[] = {
    { 0,       "APS Frame Counter Challenge Response TLV" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_rsp_set_configuration[] = {
    { 0,       "Processing status TLV" },
    { 0, NULL }
};

static const value_string zbee_tlv_local_types_rsp_beacon_survey[] = {
    { ZBEE_TLV_TYPE_BEACON_SURVEY_CONFIGURATION,       "Beacon Survey Configuration TLV" },
    { ZBEE_TLV_TYPE_BEACON_SURVEY_RESULTS,             "Beacon Survey Results TLV" },
    { ZBEE_TLV_TYPE_BEACON_SURVEY_POTENTIAL_PARENTS,   "Beacon Survey Potential Parents TLV"},
    { 0, NULL }
};

static const value_string zbee_tlv_selected_key_negotiation_method[] = {
    { ZBEE_TLV_SELECTED_KEY_NEGOTIATION_METHODS_ZB_30,                             "Zigbee 3.0" },
    { ZBEE_TLV_SELECTED_KEY_NEGOTIATION_METHODS_ECDHE_USING_CURVE25519_AES_MMO128, "ECDHE using Curve25519 with Hash AES-MMO-128" },
    { ZBEE_TLV_SELECTED_KEY_NEGOTIATION_METHODS_ECDHE_USING_CURVE25519_SHA256,     "ECDHE using Curve25519 with Hash SHA-256" },
    { 0, NULL }
};

static const value_string zbee_tlv_selected_pre_shared_secret[] = {
    { ZBEE_TLV_SELECTED_PRE_SHARED_WELL_KNOWN_KEY,            "Well Known Key" },
    { ZBEE_TLV_SELECTED_PRE_SHARED_SECRET_AUTH_TOKEN,         "Symmetric Authentication Token" },
    { ZBEE_TLV_SELECTED_PRE_SHARED_SECRET_LINK_KEY_IC,        "Pre-configured link-ley derived from installation code" },
    { ZBEE_TLV_SELECTED_PRE_SHARED_SECRET_VLEN_PASSCODE,      "Variable-length pass code" },
    { ZBEE_TLV_SELECTED_PRE_SHARED_SECRET_BASIC_ACCESS_KEY,   "Basic Access Key" },
    { ZBEE_TLV_SELECTED_PRE_SHARED_SECRET_ADMIN_ACCESS_KEY,   "Administrative Access Key" },
    { 0, NULL }
};

static const value_string zbee_initial_join_methods[] = {
    { 0x00, "No authentication" },
    { 0x01, "Install Code Key" },
    { 0x02, "Anonymous key negotiation" },
    { 0x03, "Authentication Key Negotiation" },
    { 0, NULL }
};

static const value_string zbee_active_lk_types[] = {
    { 0x00, "Not Updated" },
    { 0x01, "Key Request Method" },
    { 0x02, "Unauthentication Key Negotiation" },
    { 0x03, "Authentication Key Negotiation" },
    { 0x04, "Application Defined Certificate Based Mutual" },
    { 0, NULL }
};

static unsigned
dissect_aps_relay_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset, void *data)
{
  tvbuff_t    *relay_tvb;
  proto_item  *relayed_frame_root;
  proto_tree  *relayed_frame_tree;
  uint8_t     length;
  zbee_nwk_hints_t *nwk_hints;

  zigbee_aps_handle = find_dissector("zbee_aps");

  proto_tree_add_item(tree, hf_zbee_tlv_relay_msg_type, tvb, offset, 1, ENC_NA);
  offset += 1;

  length = tvb_get_uint8(tvb, offset) + 1;
  proto_tree_add_item(tree, hf_zbee_tlv_relay_msg_length, tvb, offset, 1, ENC_NA);
  offset += 1;

  proto_tree_add_item(tree, hf_zbee_tlv_relay_msg_joiner_ieee, tvb, offset, 8, ENC_LITTLE_ENDIAN);
  nwk_hints = (zbee_nwk_hints_t *)p_get_proto_data(wmem_file_scope(), pinfo,
                                                   proto_get_id_by_filter_name(ZBEE_PROTOABBREV_NWK), 0);
  nwk_hints->joiner_addr64 = tvb_get_letoh64(tvb, offset);
  offset += 8;

  /* The remainder is a relayed APS frame. */
  relay_tvb = tvb_new_subset_remaining(tvb, offset);
  relayed_frame_tree = proto_tree_add_subtree_format(tree, tvb, offset, length - 8, ett_zbee_aps_relay, &relayed_frame_root,
          "Relayed APS Frame");
  call_dissector_with_data(zigbee_aps_handle, relay_tvb, pinfo, relayed_frame_tree, data);

  /* Add column info */
  col_append_str(pinfo->cinfo, COL_INFO, ", Relay");

  return tvb_captured_length(tvb);
}


static unsigned
dissect_aps_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset, void *data, unsigned cmd_id)
{
    switch (cmd_id) {
        case ZBEE_APS_CMD_RELAY_MSG_UPSTREAM:
        case ZBEE_APS_CMD_RELAY_MSG_DOWNSTREAM:
        {
            zbee_nwk_hints_t *nwk_hints  = (zbee_nwk_hints_t *)p_get_proto_data(wmem_file_scope(), pinfo,
                      proto_get_id_by_filter_name(ZBEE_PROTOABBREV_NWK), 0);
            nwk_hints->relay_type = (cmd_id == ZBEE_APS_CMD_RELAY_MSG_DOWNSTREAM ? ZBEE_APS_RELAY_DOWNSTREAM : ZBEE_APS_RELAY_UPSTREAM);
        }
            offset = dissect_aps_relay_local_tlv(tvb, pinfo, tree, offset, data);
            break;

        default:
        {
            offset = dissect_unknown_tlv(tvb, pinfo, tree, offset);
            break;
        }
    }

    return offset;
}

/*
 *Helper dissector for the Security Decommission Request.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zdp_req_security_decommission_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    uint8_t type;
    uint8_t length;

    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_local_type_req_security_decommission, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    length += 1;
    switch (type) {
        case ZBEE_TLV_TYPE_EUI64:
            offset = dissect_zbee_tlv_eui64(tvb, pinfo, tree, offset);
            break;

        default:
            proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
            offset += length;
            break;
    }

    return offset;
}

/*
 *Helper dissector for the Security Get Authentication Level Request.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zdp_req_security_get_auth_level_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    uint8_t type;
    uint8_t length;

    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_local_type_req_security_get_auth_level, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    length += 1;
    switch (type) {
        case ZBEE_TLV_TYPE_TARGET_IEEE_ADDRESS:
            offset = dissect_zbee_tlv_target_ieee_address(tvb, pinfo, tree, offset);
            break;

        default:
            proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
            offset += length;
            break;
    }

    return offset;
}
/*
 *Helper dissector for the Security Get Authentication Token Request.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zdp_req_security_get_auth_token_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    uint8_t type;
    uint8_t length;

    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_local_type_req_security_get_auth_token, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    length += 1;
    switch (type) {
        case ZBEE_TLV_TYPE_REQUESTED_AUTH_TOKEN_ID:
            offset = dissect_zbee_tlv_requested_auth_token_id(tvb, pinfo, tree, offset);
            break;

        default:
            proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
            offset += length;
            break;
    }

    return offset;
}

/*
 *Helper dissector for the Clear All Bindings Request.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zdp_req_clear_all_bindings_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    uint8_t type;
    uint8_t length;

    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_local_type_clear_all_bindings_req, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    length += 1;
    switch (type) {
        case ZBEE_TLV_TYPE_CLEAR_ALL_BINDIGS_REQ_EUI64:
            offset = dissect_zbee_tlv_clear_all_bindigs_eui64(tvb, pinfo, tree, offset);
            break;

        default:
            proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
            offset += length;
            break;
    }

    return offset;
}

/*
 *Helper dissector for the Beacon Survey Request.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zdp_req_beacon_survey_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    uint8_t type;
    uint8_t length;

    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_local_type_req_beacon_survey, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    length += 1;
    switch (type) {
        case ZBEE_TLV_TYPE_BEACON_SURVEY_CONFIGURATION:
        {
            uint8_t cnt;
            uint8_t i;

            cnt = tvb_get_uint8(tvb, offset);
            proto_tree_add_item(tree, hf_zbee_zdp_beacon_survey_scan_mask_cnt, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            for (i = 0; i < cnt; i++)
            {
              proto_tree_add_item(tree, hf_zbee_zdp_beacon_survey_scan_mask, tvb, offset, 4, ENC_LITTLE_ENDIAN);
              offset += 4;
            }

            proto_tree_add_item(tree, hf_zbee_zdp_beacon_survey_conf_mask, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            break;
        }
        default:
            proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
            offset += length;
            break;
    }

    return offset;
}

/*
 *Helper dissector for the Beacon Survey Response.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zdp_rsp_beacon_survey_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    uint8_t type;
    uint8_t length;

    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_local_type_rsp_beacon_survey, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    length += 1;
    switch (type) {
        case ZBEE_TLV_TYPE_BEACON_SURVEY_CONFIGURATION:
        {
            uint8_t cnt;
            uint8_t i;

            proto_tree_add_item(tree, hf_zbee_zdp_beacon_survey_conf_mask, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            cnt = tvb_get_uint8(tvb, offset);
            proto_tree_add_item(tree, hf_zbee_zdp_beacon_survey_scan_mask_cnt, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            for (i = 0; i < cnt; i++)
            {
              proto_tree_add_item(tree, hf_zbee_zdp_beacon_survey_scan_mask, tvb, offset, 4, ENC_LITTLE_ENDIAN);
              offset += 4;
            }

            break;
        }

        case ZBEE_TLV_TYPE_BEACON_SURVEY_RESULTS:
        {
            proto_tree_add_item(tree, hf_zbee_zdp_beacon_survey_total, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            proto_tree_add_item(tree, hf_zbee_zdp_beacon_survey_cur_zbn, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            proto_tree_add_item(tree, hf_zbee_zdp_beacon_survey_cur_zbn_potent_parents, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            proto_tree_add_item(tree, hf_zbee_zdp_beacon_survey_other_zbn, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            break;
        }

        case ZBEE_TLV_TYPE_BEACON_SURVEY_POTENTIAL_PARENTS:
            offset = dissect_zbee_tlv_potential_parents(tvb, pinfo, tree, offset);
            break;

        default:
            proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
            offset += length;
            break;
    }

    return offset;
}

/*
 *Helper dissector for the Security Challenge Request.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zdp_req_security_challenge_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    uint8_t type;
    uint8_t length;

    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_local_type_req_challenge, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    length += 1;
    switch (type) {
       case 0:
       {
           proto_tree_add_item(tree, hf_zbee_tlv_local_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
           offset += 8;

           proto_tree_add_item(tree, hf_zbee_tlv_challenge_value, tvb, offset, 8, ENC_NA);
           offset += 8;
           break;
       }
       default:
           proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
           offset += length;
           break;
    }

    return offset;
}

/*
 *Helper dissector for the Security Challenge Response.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zdp_rsp_security_challenge_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    uint8_t type;
    uint8_t length;

    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_local_type_rsp_challenge, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    length += 1;
    switch (type) {
       case 0:
       {
           proto_tree_add_item(tree, hf_zbee_tlv_local_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
           offset += 8;

           proto_tree_add_item(tree, hf_zbee_tlv_challenge_value, tvb, offset, 8, ENC_NA);
           offset += 8;

           proto_tree_add_item(tree, hf_zbee_tlv_aps_frame_counter, tvb, offset, 4, ENC_LITTLE_ENDIAN);
           offset += 4;

           proto_tree_add_item(tree, hf_zbee_tlv_challenge_counter, tvb, offset, 4, ENC_LITTLE_ENDIAN);
           offset += 4;

           proto_tree_add_item(tree, hf_zbee_tlv_mic64, tvb, offset, 8, ENC_NA);
           offset += 8;
           break;
       }
       default:
           proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
           offset += length;
           break;
    }

    return offset;
}


/*
 *Helper dissector for the Security Challenge Response.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zdp_rsp_security_set_configuration_local_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
  uint8_t type;
  uint8_t length;

  type = tvb_get_uint8(tvb, offset);
  proto_tree_add_item(tree, hf_zbee_tlv_local_type_rsp_set_configuration, tvb, offset, 1, ENC_NA);
  offset += 1;

  length = tvb_get_uint8(tvb, offset);
  proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
  offset += 1;

  length += 1;
  switch (type) {
     case 0:
     {
         uint8_t     count;
         uint8_t     i;

         count = tvb_get_uint8(tvb, offset);
         proto_tree_add_item(tree, hf_zbee_tlv_local_status_count, tvb, offset, 1, ENC_NA);
         offset += 1;

         for (i = 0; i < count; i++)
         {
             proto_tree_add_item(tree, hf_zbee_tlv_local_type_id, tvb, offset, 1, ENC_NA);
             offset += 1;
             proto_tree_add_item(tree, hf_zbee_tlv_local_proc_status, tvb, offset, 1, ENC_NA);
             offset += 1;
         }
         break;
     }
     default:
         proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
         offset += length;
         break;
  }

  return offset;
}


/*
 *Helper dissector for the Security Start Key Negotiation req/rsp
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zdp_security_start_key_neg_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    uint8_t type;
    uint8_t length;

    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_local_type_key_negotiation_req_rsp, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    length += 1; /* actual length */

    switch (type) {

       case ZBEE_TLV_TYPE_KEY_NEG_REQ_CURVE25519_PUBLIC_POINT:
           offset = dissect_zbee_tlv_public_point(tvb, pinfo, tree, offset, length);
           break;

       default:
           proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
           offset += length;
           break;
    }

    return offset;
}

/*
 *Helper dissector for the Security Start Key Update req/rsp
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zdp_security_key_upd_local_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
  uint8_t type;
      uint8_t length;

      type = tvb_get_uint8(tvb, offset);
      proto_tree_add_item(tree, hf_zbee_tlv_local_type_key_update_req_rsp, tvb, offset, 1, ENC_NA);
      offset += 1;

      length = tvb_get_uint8(tvb, offset);
      proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
      offset += 1;

      length += 1; /* actual length */

      switch (type) {

         case ZBEE_TLV_TYPE_KEY_UPD_REQ_SELECTED_KEY_NEGOTIATION_METHOD:
             offset = dissect_zbee_tlv_selected_key_negotiation_method(tvb, pinfo, tree, offset);
             break;

         default:
             proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
             offset += length;
             break;
      }

      return offset;
}
/*
 *Helper dissector for the Security Get Auth Level Response.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zdp_rsp_security_get_auth_level_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    uint8_t type;
    uint8_t length;

    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_local_type_get_auth_level_rsp, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    length += 1;
    switch (type) {
       case ZBEE_TLV_TYPE_GET_AUTH_LEVEL:
           offset = dissect_zbee_tlv_device_auth_level(tvb, pinfo, tree, offset);
           break;

       default:
           proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
           offset += length;
           break;
    }

    return offset;
}


/*
 *Helper dissector for the ZDP commands.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@param  cmd_id - ZDP command id .
 *@return offset after command dissection.
*/
static unsigned
dissect_zdp_local_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset, unsigned cmd_id)
{
    uint8_t total_tlv_length = 2 /*type + len fields*/ + tvb_get_uint8(tvb, offset + 1) + 1;
    uint8_t tmp_offset = offset;

    switch (cmd_id) {
        case ZBEE_ZDP_REQ_CLEAR_ALL_BINDINGS:
            offset = dissect_zdp_req_clear_all_bindings_local_tlv(tvb, pinfo, tree, offset);
            break;

        case ZBEE_ZDP_REQ_SECURITY_START_KEY_UPDATE:
        case ZBEE_ZDP_RSP_SECURITY_START_KEY_UPDATE:
        case ZBEE_ZDP_RSP_NODE_DESC:
            offset = dissect_zdp_security_key_upd_local_tlv(tvb, pinfo, tree, offset);
            break;

        case ZBEE_ZDP_REQ_SECURITY_START_KEY_NEGOTIATION:
        case ZBEE_ZDP_RSP_SECURITY_START_KEY_NEGOTIATION:
            offset = dissect_zdp_security_start_key_neg_local_tlv(tvb, pinfo, tree, offset);
            break;

        case ZBEE_ZDP_REQ_SECURITY_GET_AUTH_TOKEN:
            offset = dissect_zdp_req_security_get_auth_token_local_tlv(tvb, pinfo, tree, offset);
            break;

        case ZBEE_ZDP_REQ_SECURITY_GET_AUTH_LEVEL:
            offset = dissect_zdp_req_security_get_auth_level_local_tlv(tvb, pinfo, tree, offset);
            break;

        case ZBEE_ZDP_REQ_SECURITY_DECOMMISSION:
            offset = dissect_zdp_req_security_decommission_local_tlv(tvb, pinfo, tree, offset);
            break;

        case ZBEE_ZDP_RSP_SECURITY_GET_AUTH_LEVEL:
            offset = dissect_zdp_rsp_security_get_auth_level_local_tlv(tvb, pinfo, tree, offset);
            break;

        case ZBEE_ZDP_REQ_MGMT_NWK_BEACON_SURVEY:
            offset = dissect_zdp_req_beacon_survey_local_tlv(tvb, pinfo, tree, offset);
            break;

        case ZBEE_ZDP_RSP_MGMT_NWK_BEACON_SURVEY:
            offset = dissect_zdp_rsp_beacon_survey_local_tlv(tvb, pinfo, tree, offset);
            break;

        case ZBEE_ZDP_REQ_SECURITY_CHALLENGE:
            offset = dissect_zdp_req_security_challenge_local_tlv(tvb, pinfo, tree, offset);
            break;

        case ZBEE_ZDP_RSP_SECURITY_CHALLENGE:
            offset = dissect_zdp_rsp_security_challenge_local_tlv(tvb, pinfo, tree, offset);
            break;

        case ZBEE_ZDP_RSP_SECURITY_SET_CONFIGURATION:
            offset = dissect_zdp_rsp_security_set_configuration_local_tlv(tvb, pinfo, tree, offset);
            break;
        default:
        {
            offset = dissect_unknown_tlv(tvb, pinfo, tree, offset);
            break;
        }
    }

    /* check extra bytes */
    if ((offset - tmp_offset) < total_tlv_length)
    {
      proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, total_tlv_length - 2, ENC_NA);
      offset = tmp_offset + total_tlv_length;
    }

    return offset;
}

/**
 * Helper dissector for a channel mask.
 *
 * @param  tree        pointer to data tree Wireshark uses to display packet.
 * @param  tvb         pointer to buffer containing raw packet.
 * @param  offset      offset into the tvb to find the status value.
 * @param  hf_page     page field index
 * @param  hf_channel  channel field index
 * @return mask
 */
static unsigned
dissect_zbee_tlv_chanmask(proto_tree *tree, tvbuff_t *tvb, unsigned offset, int hf_page, int hf_channel)
{
    int         i;
    uint32_t    mask;
    uint8_t     page;
    proto_item *ti;

    /* Get and display the channel mask. */
    mask = tvb_get_letohl(tvb, offset);

    page = (uint8_t)((mask >> 27) & 0x07);
    mask &= 0x07FFFFFFUL;

    proto_tree_add_uint(tree, hf_page, tvb, offset, 4, page);
    ti = proto_tree_add_uint_format(tree, hf_channel, tvb, offset, 4, mask, "Channels: ");

    /* Check if there are any channels to display. */
    if (mask == 0)
    {
        proto_item_append_text(ti, "None");
    }

    /* Display the first channel #. */
    for (i = 0; i < 32; i++)
    {
        if ((1 << i) & mask)
        {
            proto_item_append_text(ti, "%d", i++);
            break;
        }
    }

    /* Display the rest of the channels. */
    for (; i < 32; i++)
    {
        if (!((1 << i) & mask))
        {
            /* This channel isn't selected. */
            continue;
        }

        /* If the previous channel wasn't selected,
         * then display the channel number.
         */
        if (!((1 << (i - 1)) & mask))
        {
            proto_item_append_text(ti, ", %d", i);
        }

        /* If the next channel is selected too,
         * skip past it and display a range of values instead.
         */
        if ((2 << i) & mask)
        {
            while ((2 << i) & mask) i++;
            proto_item_append_text(ti, "-%d", i);
        }
    }

    offset += sizeof(uint32_t);

    return offset;
}

/**
 * Dissector Extended PAN ID TLV.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to subtree
 * @param  offset  offset into the tvb to begin dissection
 * @return offset after dissection
 */

static unsigned
dissect_zbee_tlv_ext_pan_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_local_comm_ext_pan_id, tvb, offset, 8, ENC_NA);
    offset += 8;

    return offset;
};

/**
 * Dissector Short PAN ID TLV.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to subtree
 * @param  offset  offset into the tvb to begin dissection
 * @return offset after dissection
 */

static unsigned
dissect_zbee_tlv_short_pan_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_local_comm_short_pan_id, tvb, offset, 2, ENC_NA);
    offset += 2;

    return offset;
};

/**
 * Dissector NWK Key TLV.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to subtree
 * @param  offset  offset into the tvb to begin dissection
 * @return offset after dissection
 */

static unsigned dissect_zbee_tlv_nwk_key(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_local_comm_nwk_key, tvb, offset, 16, ENC_NA);
    offset += 16;

    return offset;
};

/**
 * Dissector Device Type TLV.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to subtree
 * @param  offset  offset into the tvb to begin dissection
 * @return offset after dissection
 */

static unsigned dissect_zbee_tlv_dev_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_local_comm_dev_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
};

/**
 * Dissector NWK Address TLV.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to subtree
 * @param  offset  offset into the tvb to begin dissection
 * @return offset after dissection
 */

static unsigned dissect_zbee_tlv_nwk_addr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_local_comm_nwk_addr, tvb, offset, 2, ENC_NA);
    offset += 2;

    return offset;
};

/**
 * Dissector Joining Method TLV.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to subtree
 * @param  offset  offset into the tvb to begin dissection
 * @return offset after dissection
 */

static unsigned dissect_zbee_tlv_join_method(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_local_comm_join_method, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
};

/**
 * Dissector IEEE Address TLV.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to subtree
 * @param  offset  offset into the tvb to begin dissection
 * @return offset after dissection
 */

static unsigned dissect_zbee_tlv_ieee_addr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_local_ieee_addr, tvb, offset, 8, ENC_NA);
    offset += 8;

    return offset;
};

/**
 * Dissector Trust Center Address TLV.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to subtree
 * @param  offset  offset into the tvb to begin dissection
 * @return offset after dissection
 */

static unsigned dissect_zbee_tlv_tc_addr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_local_comm_tc_addr, tvb, offset, 8, ENC_NA);
    offset += 8;

    return offset;
};

/**
 * Dissector NWK Update ID TLV.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to subtree
 * @param  offset  offset into the tvb to begin dissection
 * @return offset after dissection
 */

static unsigned dissect_zbee_tlv_nwk_upd_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_local_comm_nwk_upd_id, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
};

/**
 * Dissector NWK Active Key Seq Number TLV.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to subtree
 * @param  offset  offset into the tvb to begin dissection
 * @return offset after dissection
 */

static unsigned dissect_zbee_tlv_key_seq_num(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_local_comm_key_seq_num, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
};

/**
 * Dissector Admin Key TLV.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to subtree
 * @param  offset  offset into the tvb to begin dissection
 * @return offset after dissection
 */

static unsigned dissect_zbee_tlv_adm_key(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_local_comm_adm_key, tvb, offset, 16, ENC_NA);
    offset += 16;

    return offset;
};

/**
 * Dissector (Manager Joiners) Provisional Link Key TLV.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to subtree
 * @param  offset  offset into the tvb to begin dissection
 * @return offset after dissection
 */

static unsigned dissect_zbee_tlv_mj_prov_lnk_key(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_local_comm_mj_prov_lnk_key, tvb, offset, 16, ENC_NA);
    offset += 16;

    return offset;
};

/**
 * Dissector (Manager Joiners) IEEE Address TLV.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to subtree
 * @param  offset  offset into the tvb to begin dissection
 * @return offset after dissection
 */

static unsigned dissect_zbee_tlv_mj_ieee_addr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_local_comm_mj_ieee_addr, tvb, offset, 8, ENC_NA);
    offset += 8;

    return offset;
};

/**
 * Dissector (Manager Joiners) Command TLV.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to subtree
 * @param  offset  offset into the tvb to begin dissection
 * @return offset after dissection
 */

static unsigned dissect_zbee_tlv_mj_cmd(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_local_comm_mj_cmd, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
};

/**
 * Dissector Channel List TLV.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to subtree
 * @param  offset  offset into the tvb to begin dissection
 * @return offset after dissection
 */
static unsigned
dissect_zbee_tlv_nwk_channel_list(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    uint32_t count = 0;

    proto_tree_add_item_ret_uint(tree, hf_zbee_tlv_local_comm_channel_page_count, tvb, offset, 1, ENC_LITTLE_ENDIAN, &count);
    offset += 1;

    for (unsigned i = 0; i < count; i++)
    {
        offset = dissect_zbee_tlv_chanmask(tree, tvb, offset, hf_zbee_tlv_local_comm_channel_page, hf_zbee_tlv_local_comm_channel_mask);
    }

    return offset;
}

/**
 * Dissector Link Key TLV.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to subtree
 * @param  offset  offset into the tvb to begin dissection
 * @return offset after dissection
 */
static unsigned
dissect_zbee_tlv_link_key(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    static int * const link_key_flags[] = {
        &hf_zbee_tlv_local_comm_link_key_flags_unique,
        &hf_zbee_tlv_local_comm_link_key_flags_provisional,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_tlv_local_comm_link_key_flags, ett_zbee_tlv_link_key_flags, link_key_flags, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_zbee_tlv_local_comm_link_key, tvb, offset, 16, ENC_NA);
    offset += 16;

    return offset;
}

/**
 * Dissector NWK Status Map TLV.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to subtree
 * @param  offset  offset into the tvb to begin dissection
 * @return offset after dissection
 */
static unsigned
dissect_zbee_tlv_nwk_status_map(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    uint8_t mask;
    unsigned   joined, opened, centralized;

    static int * const network_status_map[] = {
        &hf_zbee_tlv_local_comm_network_status_map_joined_status,
        &hf_zbee_tlv_local_comm_network_status_map_open_status,
        &hf_zbee_tlv_network_status_map_network_type,
        NULL
    };

    mask = tvb_get_uint8(tvb, offset);
    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_tlv_local_comm_network_status_map, ett_zbee_tlv_network_status_map, network_status_map, ENC_LITTLE_ENDIAN);

    offset += 1;

    joined      = (mask & ZBEE_TLV_STATUS_MAP_JOINED_STATUS) >> 0;
    opened      = (mask & ZBEE_TLV_STATUS_MAP_OPEN_STATUS)   >> 3;
    centralized = (mask & ZBEE_TLV_STATUS_MAP_NETWORK_TYPE)  >> 4;


    if (joined == ZB_DIRECT_JOINED_STATUS_JOINED || joined == ZB_DIRECT_JOINED_STATUS_JOINED_NO_PARENT)
    {
        col_append_fstr(pinfo->cinfo,
                        COL_INFO,
                        " (%s, %s, %s)",
                        zbee_tlv_local_types_joined_status_str[joined].strptr,
                        opened ? "Opened" : "Closed",
                        centralized ? "Centralized" : "Distributed");
    }
    else
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", zbee_tlv_local_types_joined_status_str[joined].strptr);
    }

    return offset;
}

/**
 * Dissector Status Code TLV.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to subtree
 * @param  offset  offset into the tvb to begin dissection
 * @return offset after dissection
 */
static unsigned
dissect_zbee_tlv_status_code(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    uint32_t code;
    proto_item *code_item;

    proto_tree_add_item(tree, hf_zbee_tlv_local_comm_status_code_domain, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    code_item = proto_tree_add_item_ret_uint(tree, hf_zbee_tlv_local_comm_status_code_value, tvb, offset, 1, ENC_LITTLE_ENDIAN, &code);
    offset += 1;

    proto_item_append_text(code_item, " (%s)", (code == 0) ? "Success" : "Failure");

    return offset;
}

/**
 * Helper dissector for Tunneling.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to subtree
 * @return offset after dissection
 */
static unsigned
dissect_zbee_tlv_tunneling_npdu_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset,
                                               uint8_t      length)
{
    uint32_t npdu_len = 0;

    /* Parse NPDU Message TLV */
    {
        proto_item *npdu_flags_item = proto_tree_add_item(tree, hf_zbee_tlv_local_tunneling_npdu_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree *npdu_flags_tree = proto_item_add_subtree(npdu_flags_item, ett_zbee_tlv_zbd_tunneling_npdu_flags);
        bool secur;

        proto_tree_add_item_ret_boolean(npdu_flags_tree, hf_zbee_tlv_local_tunneling_npdu_flags_security, tvb, offset, 1, ENC_LITTLE_ENDIAN, &secur);
        proto_tree_add_item_ret_uint(tree, hf_zbee_tlv_local_tunneling_npdu_length, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN, &npdu_len);

        proto_item_append_text(npdu_flags_item, ", Security: %s", secur ? "True" : "False");
        proto_tree_add_item(npdu_flags_tree, hf_zbee_tlv_local_tunneling_npdu_flags_reserved, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    }

    /* Proceed with NPDU that holds a Zigbee NWK frame */
    {
        proto_item *npdu_item = proto_tree_add_item(tree, hf_zbee_tlv_local_tunneling_npdu, tvb, offset + 2, npdu_len, ENC_NA);
        proto_tree *npdu_tree = proto_item_add_subtree(npdu_item, ett_zbee_tlv_zbd_tunneling_npdu);

        ieee802154_packet packet;
        memset(&packet, 0, sizeof(packet));

        call_dissector_with_data(zbee_nwk_handle,
                                 tvb_new_subset_length(tvb, offset + 2, npdu_len),
                                 pinfo,
                                 npdu_tree,
                                 &packet);
    }

    offset += length;

    return offset;
}

/**
 * Checks a curve, that was selected in the method.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to the command subtree
 * @param  offset  offset into the tvb to begin dissection
 * @return offset after command dissection
 */
static unsigned
dissect_zbee_tlv_key_neg_method(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_local_selected_key_method, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_zbee_tlv_local_selected_psk_secret, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    return offset;
}

/**
 * Helper dissector for the MAC tag.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to the command subtree
 * @param  offset  offset into the tvb to begin dissection
 * @return offset after command dissection
 */
static unsigned
dissect_zbee_tlv_mac_tag(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset, uint8_t mac_tag_size)
{
    proto_tree_add_item(tree, hf_zbee_tlv_local_mac_tag, tvb, offset, mac_tag_size, ENC_NA);
    offset += mac_tag_size;

    return offset;
}

/**
 * Helper dissector for the NWK key sequence number.
 *
 * @param  tvb     pointer to buffer containing raw packet
 * @param  pinfo   pointer to packet information fields
 * @param  tree    pointer to the command subtree
 * @param  offset  offset into the tvb to begin dissection
 * @return offset after command dissection
 */
static unsigned
dissect_zbee_tlv_nwk_key_seq_num(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_local_nwk_key_seq_num, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    return offset;
}

/*
 *Helper dissector for the ZB Direct Status.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zbd_msg_status_local_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    uint8_t type;
    uint8_t length;

    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_zbd_comm_tlv, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    length += 1;

    switch (type)
    {
        case ZBEE_TLV_TYPE_COMM_IEEE_ADDR:
            offset = dissect_zbee_tlv_ieee_addr(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_NWK_STATUS_MAP:
            offset = dissect_zbee_tlv_nwk_status_map(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_TC_ADDR:
            offset = dissect_zbee_tlv_tc_addr(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_EXT_PAN_ID:
            offset = dissect_zbee_tlv_ext_pan_id(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_SHORT_PAN_ID:
            offset = dissect_zbee_tlv_short_pan_id(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_NWK_CH:
            offset = dissect_zbee_tlv_nwk_channel_list(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_NWK_KEY:
            offset = dissect_zbee_tlv_nwk_key(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_NWK_ADDR:
            offset = dissect_zbee_tlv_nwk_addr(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_NWK_UPD_ID:
            offset = dissect_zbee_tlv_nwk_upd_id(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_KEY_SEQ_NUM:
            offset = dissect_zbee_tlv_key_seq_num(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_DEV_TYPE:
            offset = dissect_zbee_tlv_dev_type(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_STATUS_CODE:
            offset = dissect_zbee_tlv_status_code(tvb, pinfo, tree, offset);
            break;

        default:
            proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
            offset += length;
            break;
    }

    return offset;
}

/*
 *Helper dissector for the ZB Direct Tunneling.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zbd_msg_tunneling_local_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    uint8_t opcode = tvb_get_uint8(tvb, offset);
    uint8_t length;

    proto_tree_add_item(tree, hf_zbee_tlv_zbd_tunneling_npdu_msg_tlv, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    length += 1;

    switch (opcode)
    {
        case ZBEE_TLV_TYPE_TUNNELING_NPDU_MESSAGE:
        {
            col_set_fence(pinfo->cinfo, COL_PROTOCOL);
            offset = dissect_zbee_tlv_tunneling_npdu_msg(tvb, pinfo, tree, offset, length);
            break;
        }

        default:
            proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
            offset += length;
            break;
    }

    return offset;
}

/*
 *Helper dissector for the ZB Direct Manage Joiners.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zbd_msg_manage_joiners_local_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    uint8_t type;
    uint8_t length;

    type = tvb_get_uint8(tvb, offset);

    proto_tree_add_item(tree, hf_zbee_tlv_zbd_comm_mj_cmd_tlv, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    length += 1;

    switch (type)
    {
        case ZBEE_TLV_TYPE_COMM_MJ_CMD:
            offset = dissect_zbee_tlv_mj_cmd(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_MJ_IEEE_ADDR:
            offset = dissect_zbee_tlv_mj_ieee_addr(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_MJ_PROVISIONAL_LINK_KEY:
            offset = dissect_zbee_tlv_mj_prov_lnk_key(tvb, pinfo, tree, offset);
            break;

        default:
            proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
            offset += length;
            break;
    }

    return offset;
}

/*
 *Helper dissector for the ZB Direct Direct Join.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zbd_msg_join_local_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    uint8_t type;
    uint8_t length;

    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_zbd_comm_tlv, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    length += 1;

    switch (type)
    {
        case ZBEE_TLV_TYPE_COMM_JOIN_METHOD:
            offset = dissect_zbee_tlv_join_method(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_ADMIN_KEY:
            offset = dissect_zbee_tlv_adm_key(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_TC_ADDR:
            offset = dissect_zbee_tlv_tc_addr(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_EXT_PAN_ID:
            offset = dissect_zbee_tlv_ext_pan_id(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_SHORT_PAN_ID:
            offset = dissect_zbee_tlv_short_pan_id(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_NWK_CH:
            offset = dissect_zbee_tlv_nwk_channel_list(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_NWK_KEY:
            offset = dissect_zbee_tlv_nwk_key(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_LNK_KEY:
            offset = dissect_zbee_tlv_link_key(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_NWK_ADDR:
            offset = dissect_zbee_tlv_nwk_addr(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_NWK_UPD_ID:
            offset = dissect_zbee_tlv_nwk_upd_id(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_KEY_SEQ_NUM:
            offset = dissect_zbee_tlv_key_seq_num(tvb, pinfo, tree, offset);
            break;

        default:
            proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
            offset += length;
            break;
    }

    return offset;
}

/*
 *Helper dissector for the ZB Direct Formation.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zbd_msg_formation_local_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    uint8_t type;
    uint8_t length;

    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_zbd_comm_tlv, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    length += 1;

    switch (type)
    {
        case ZBEE_TLV_TYPE_COMM_ADMIN_KEY:
            offset = dissect_zbee_tlv_adm_key(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_TC_ADDR:
            offset = dissect_zbee_tlv_tc_addr(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_EXT_PAN_ID:
            offset = dissect_zbee_tlv_ext_pan_id(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_SHORT_PAN_ID:
            offset = dissect_zbee_tlv_short_pan_id(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_NWK_CH:
            offset = dissect_zbee_tlv_nwk_channel_list(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_NWK_KEY:
            offset = dissect_zbee_tlv_nwk_key(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_LNK_KEY:
            offset = dissect_zbee_tlv_link_key(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_NWK_ADDR:
            offset = dissect_zbee_tlv_nwk_addr(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_NWK_UPD_ID:
            offset = dissect_zbee_tlv_nwk_upd_id(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_COMM_KEY_SEQ_NUM:
            offset = dissect_zbee_tlv_key_seq_num(tvb, pinfo, tree, offset);
            break;

        default:
            proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
            offset += length;
            break;
    }

    return offset;
}

/*
 *Helper dissector for the ZB Direct Security Messages.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to the command subtree.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
*/
static unsigned
dissect_zbd_msg_secur_local_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    uint8_t type;
    uint8_t length;

    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_zbd_secur_tlv, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    length += 1;

    switch (type)
    {
        case ZBEE_TLV_TYPE_KEY_METHOD:
            offset = dissect_zbee_tlv_key_neg_method(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_PUB_POINT_P256:
        case ZBEE_TLV_TYPE_PUB_POINT_C25519:
            offset = dissect_zbee_tlv_public_point(tvb, pinfo, tree, offset, length);
            break;

        case ZBEE_TLV_TYPE_NWK_KEY_SEQ_NUM:
            offset = dissect_zbee_tlv_nwk_key_seq_num(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_MAC_TAG:
            offset = dissect_zbee_tlv_mac_tag(tvb, pinfo, tree, offset, length);
            break;

        default:
            proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
            offset += length;
            break;
    }

    return offset;
}

/*
 *Helper dissector for the ZD Direct messages.
 *
 *@param  tvb pointer to buffer containing raw packet
 *@param  pinfo pointer to packet information fields
 *@param  tree pointer to the command subtree
 *@param  offset into the tvb to begin dissection
 *@param  cmd_id - ZB Direct local Message ID
 *@return offset after command dissection
*/
static unsigned
dissect_zbd_local_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, void* data _U_, unsigned cmd_id)
{
    uint8_t total_tlv_length = 2 /*type + len fields*/ + tvb_get_uint8(tvb, offset + 1) + 1;
    uint8_t tmp_offset = offset;

    switch (cmd_id)
    {
        case ZB_DIRECT_MSG_ID_STATUS:
            offset = dissect_zbd_msg_status_local_tlv(tvb, pinfo, tree, offset);
            break;

        case ZB_DIRECT_MSG_ID_TUNNELING:
            offset = dissect_zbd_msg_tunneling_local_tlv(tvb, pinfo, tree, offset);
            break;

        case ZB_DIRECT_MSG_ID_MANAGE_JOINERS:
            offset = dissect_zbd_msg_manage_joiners_local_tlv(tvb, pinfo, tree, offset);
            break;

        case ZB_DIRECT_MSG_ID_JOIN:
            offset = dissect_zbd_msg_join_local_tlv(tvb, pinfo, tree, offset);
            break;

        case ZB_DIRECT_MSG_ID_FORMATION:
            offset = dissect_zbd_msg_formation_local_tlv(tvb, pinfo, tree, offset);
            break;

        case ZB_DIRECT_MSG_ID_SECUR_C25519_AESMMO:
        case ZB_DIRECT_MSG_ID_SECUR_C25519_SHA256:
        case ZB_DIRECT_MSG_ID_SECUR_P256:
            offset = dissect_zbd_msg_secur_local_tlv(tvb, pinfo, tree, offset);
            break;

        default:
            offset = dissect_unknown_tlv(tvb, pinfo, tree, offset);
            break;
    }

    /* check extra bytes */
    if ((offset - tmp_offset) < total_tlv_length)
    {
        proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, total_tlv_length - 2, ENC_NA);
        offset = tmp_offset + total_tlv_length;
    }

    return offset;
}

/**
 * *Dissector for Zigbee Manufacturer Specific Global TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@param  length of TLV data
 *@return offset after command dissection.
 */
static unsigned
dissect_zbee_tlv_manufacturer_specific(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset, uint8_t length)
{
    proto_tree_add_item(tree, hf_zbee_tlv_manufacturer_specific, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length - 2, ENC_NA);
    offset += length - 2;

    return offset;
} /* dissect_zbee_tlv_manufacturer_specific */

/**
 *Dissector for Zigbee Supported Key Negotiation Methods Global TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static unsigned
dissect_zbee_tlv_supported_key_negotiation_methods(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    static int * const supported_key_negotiation_methods[] = {
        &hf_zbee_tlv_supported_key_negotiation_methods_key_request,
        &hf_zbee_tlv_supported_key_negotiation_methods_ecdhe_using_curve25519_aes_mmo128,
        &hf_zbee_tlv_supported_key_negotiation_methods_ecdhe_using_curve25519_sha256,
        NULL
    };

    static int * const supported_secrets[] = {
        &hf_zbee_tlv_supported_preshared_secrets_auth_token,
        &hf_zbee_tlv_supported_preshared_secrets_ic,
        &hf_zbee_tlv_supported_preshared_secrets_passcode_pake,
        &hf_zbee_tlv_supported_preshared_secrets_basic_access_key,
        &hf_zbee_tlv_supported_preshared_secrets_admin_access_key,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_tlv_supported_key_negotiation_methods, ett_zbee_tlv_supported_key_negotiation_methods, supported_key_negotiation_methods, ENC_NA);
    offset += 1;

    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_tlv_supported_secrets, ett_zbee_tlv_supported_secrets, supported_secrets, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_zbee_tlv_device_eui64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
} /* dissect_zbee_tlv_supported_key_negotiation_methods */

/**
 *Dissector for Zigbee PAN ID conflict report Global TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static unsigned
dissect_zbee_tlv_panid_conflict_report(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_panid_conflict_cnt, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}


/**
 * *Dissector for Zigbee Configuration Parameters Global TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static unsigned
dissect_zbee_tlv_configuration_parameters(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    static int * const bitmask[] = {
        &hf_zbee_tlv_configuration_param_restricted_mode,
        &hf_zbee_tlv_configuration_param_link_key_enc,
        &hf_zbee_tlv_configuration_param_leave_req_allowed,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_tlv_configuration_param, ett_zbee_tlv_configuration_param, bitmask, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
} /* dissect_zbee_tlv_configuration_parameters */


/**
 * *Dissector for Zigbee Configuration Parameters Global TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static unsigned
dissect_zbee_tlv_dev_cap_ext(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    static int * const bitmask[] = {
        &hf_zbee_tlv_dev_cap_ext_zbdirect_virt_device,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_tlv_dev_cap_ext_capability_information, ett_zbee_tlv_capability_information, bitmask, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
} /* dissect_zbee_tlv_configuration_parameters */

/**
 * *Dissector for Zigbee CPotential Parents Global TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static unsigned
dissect_zbee_tlv_potential_parents(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
  uint8_t count, i;

  proto_tree_add_item(tree, hf_zbee_zdp_beacon_survey_current_parent, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_zbee_tlv_lqa, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;

  count = tvb_get_uint8(tvb, offset);
  proto_tree_add_item(tree, hf_zbee_zdp_beacon_survey_cnt_parents, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;

  for (i = 0; i < count; i++)
  {
    proto_tree_add_item(tree, hf_zbee_zdp_beacon_survey_parent, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_zbee_tlv_lqa, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
  }

  return offset;
}

/**
 * *Dissector for Zigbee Next PAN ID Change Global TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static unsigned
dissect_zbee_tlv_next_pan_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_next_pan_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
} /* dissect_zbee_tlv_next_pan_id */

/**
 * *Dissector for Zigbee Next Channel Change Global TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static unsigned
dissect_zbee_tlv_next_channel_change(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    /* todo: fix this (do channel mask) */
    proto_tree_add_item(tree, hf_zbee_tlv_next_channel_change, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    return offset;
} /* dissect_zbee_tlv_next_channel_change */

/**
 * *Dissector for Zigbee Passphrase Global TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static unsigned
dissect_zbee_tlv_passphrase(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_passphrase, tvb, offset, 16, ENC_NA);
    offset += 16;

    return offset;
} /* dissect_zbee_tlv_passphrase */


/**
 * *Dissector for Zigbee Router Information Global TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static unsigned
dissect_zbee_tlv_router_information(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    static int * const router_information[] = {
        &hf_zbee_tlv_router_information_hub_connectivity,
        &hf_zbee_tlv_router_information_uptime,
        &hf_zbee_tlv_router_information_pref_parent,
        &hf_zbee_tlv_router_information_battery_backup,
        &hf_zbee_tlv_router_information_enhanced_beacon_request_support,
        &hf_zbee_tlv_router_information_mac_data_poll_keepalive_support,
        &hf_zbee_tlv_router_information_end_device_keepalive_support,
        &hf_zbee_tlv_router_information_power_negotiation_support,
        NULL
    };

    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_tlv_router_information, ett_zbee_tlv_router_information, router_information, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
} /* dissect_zbee_tlv_router_information */

/**
 * *Dissector for Zigbee Fragmentation Parameters Global TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static unsigned
dissect_zbee_tlv_fragmentation_parameters(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_node_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_zbee_tlv_frag_opt, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_zbee_tlv_max_reassembled_buf_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
} /* dissect_zbee_tlv_fragmentation_parameters */

/**
 *Dissector for Zigbee Selected Key Negotiation Methods TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static unsigned
dissect_zbee_tlv_selected_key_negotiation_method(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_selected_key_negotiation_method, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_zbee_tlv_selected_pre_shared_secret, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_zbee_tlv_device_eui64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
} /* dissect_zbee_tlv_selected_key_negotiation_methods */


/**
 *Dissector for Public Point TLVs
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static unsigned
dissect_zbee_tlv_public_point(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset, uint8_t length)
{
    uint8_t public_point_length = length - 8;

    proto_tree_add_item(tree, hf_zbee_tlv_device_eui64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_zbee_tlv_public_point, tvb, offset, public_point_length, ENC_NA);
    offset += public_point_length;

    return offset;
} /* dissect_zbee_tlv_curve25519_public_point */

/*
 *Dissector for Security Decommission Req EUI64 TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static unsigned
dissect_zbee_tlv_eui64(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    uint8_t eui64_count;
    uint8_t i;

    eui64_count = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_count, tvb, offset, 1, ENC_NA);
    offset += 1;

    for (i = 0; i < eui64_count; i++)
    {
        proto_tree_add_item(tree, hf_zbee_tlv_device_eui64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
    }

    return offset;
}

/*
 *Dissector for Clear All Bindings Req EUI64 TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static unsigned
dissect_zbee_tlv_clear_all_bindigs_eui64(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    return dissect_zbee_tlv_eui64(tvb, pinfo, tree, offset);
}

/*
 *Dissector for Requested Authentication Token ID TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static unsigned
dissect_zbee_tlv_requested_auth_token_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_global_tlv_id, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}

/*
 *Dissector for Target IEEE Address TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static unsigned
dissect_zbee_tlv_target_ieee_address(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_zbee_tlv_local_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    return offset;
}

/**
 * *Dissector for Device Authentication Level TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static unsigned
dissect_zbee_tlv_device_auth_level(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{

    proto_tree_add_item(tree, hf_zbee_tlv_local_ieee_addr, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item(tree, hf_zbee_tlv_local_initial_join_method, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_zbee_tlv_local_active_lk_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
} /* dissect_zbee_tlv_device_auth_level */

/*
 * ToDo: descr
 */
static unsigned
// NOLINTNEXTLINE(misc-no-recursion)
dissect_global_tlv (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    uint8_t type;
    uint8_t length;
    unsigned   tmp_offset;

    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_global_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    length = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    length += 1;
    tmp_offset = offset;
    switch (type) {
        case ZBEE_TLV_TYPE_MANUFACTURER_SPECIFIC:
            offset = dissect_zbee_tlv_manufacturer_specific(tvb, pinfo, tree, offset, length);
            break;

        case ZBEE_TLV_TYPE_SUPPORTED_KEY_NEGOTIATION_METHODS:
            offset = dissect_zbee_tlv_supported_key_negotiation_methods(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_PANID_CONFLICT_REPORT:
            offset = dissect_zbee_tlv_panid_conflict_report(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_NEXT_PAN_ID:
            offset = dissect_zbee_tlv_next_pan_id(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_NEXT_CHANNEL_CHANGE:
            offset = dissect_zbee_tlv_next_channel_change(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_PASSPHRASE:
            offset = dissect_zbee_tlv_passphrase(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_ROUTER_INFORMATION:
            offset = dissect_zbee_tlv_router_information(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_FRAGMENTATION_PARAMETERS:
            offset = dissect_zbee_tlv_fragmentation_parameters(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_JOINER_ENCAPSULATION_GLOBAL:
            offset = dissect_zbee_tlvs(tvb, pinfo, tree, offset, NULL, ZBEE_TLV_SRC_TYPE_DEFAULT, 0);
            break;

        case ZBEE_TLV_TYPE_BEACON_APPENDIX_ENCAPSULATION_GLOBAL:
            offset = dissect_zbee_tlvs(tvb, pinfo, tree, offset, NULL, ZBEE_TLV_SRC_TYPE_DEFAULT, 0);
            break;

        case ZBEE_TLV_TYPE_CONFIGURATION_MODE_PARAMETERS:
            offset = dissect_zbee_tlv_configuration_parameters(tvb, pinfo, tree, offset);
            break;

        case ZBEE_TLV_TYPE_DEVICE_CAPABILITY_EXTENSION:
            offset = dissect_zbee_tlv_dev_cap_ext(tvb, pinfo, tree, offset);
            break;

        default:
            proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
            offset += length;
            break;
    }

    /* check extra bytes */
    if ((offset - tmp_offset) < length)
    {
      proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
      offset = tmp_offset + length;
    }

    return offset;
}

/**
 *Dissector for Unknown Zigbee TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static unsigned
dissect_unknown_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
  uint8_t      length;

  proto_tree_add_item(tree, hf_zbee_tlv_type, tvb, offset, 1, ENC_NA);
  offset += 1;

  length = tvb_get_uint8(tvb, offset);
  proto_tree_add_item(tree, hf_zbee_tlv_length, tvb, offset, 1, ENC_NA);
  offset += 1;

  length += 1; /* length of tlv_val == tlv_len + 1 */
  proto_tree_add_item(tree, hf_zbee_tlv_value, tvb, offset, length, ENC_NA);
  offset += length;

  return offset;
}

/**
 *Dissector for Zigbee TLV
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@return offset after command dissection.
 */
static unsigned
// NOLINTNEXTLINE(misc-no-recursion)
dissect_zbee_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset, void *data, uint8_t source_type, unsigned cmd_id)
{
    uint8_t      type;

    type = tvb_get_uint8(tvb, offset);

    if (type >= ZBEE_TLV_GLOBAL_START_NUMBER)
    {
        offset = dissect_global_tlv (tvb, pinfo, tree, offset);
    }
    else
    {
        switch (source_type)
        {
            case ZBEE_TLV_SRC_TYPE_ZBEE_ZDP:
                offset = dissect_zdp_local_tlv(tvb, pinfo, tree, offset, cmd_id);
                break;

            case ZBEE_TLV_SRC_TYPE_ZBEE_APS:
                offset = dissect_aps_local_tlv(tvb, pinfo, tree, offset, data, cmd_id);
                break;

            case ZBEE_TLV_SRC_TYPE_ZB_DIRECT:
                offset = dissect_zbd_local_tlv(tvb, pinfo, tree, offset, data, cmd_id);
                break;

            default:
                offset = dissect_unknown_tlv(tvb, pinfo, tree, offset);
                break;
        }
    }

    return offset;
} /* dissect_zbee_tlv */

/**
 *Dissector for Zigbee TLVs
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param  offset into the tvb to begin dissection.
 *@param  source_type ToDo:
 *@param  cmd_id ToDo:
 *@return offset after command dissection.
 */

#define ZBEE_TLV_MAX_RECURSION_DEPTH 5 // Arbitrarily chosen

unsigned
// NOLINTNEXTLINE(misc-no-recursion)
dissect_zbee_tlvs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset, void *data, uint8_t source_type, unsigned cmd_id)
{
    proto_tree  *subtree;
    uint8_t      length;
    unsigned     recursion_depth = p_get_proto_depth(pinfo, proto_zbee_tlv);

    if (++recursion_depth >= ZBEE_TLV_MAX_RECURSION_DEPTH) {
        proto_tree_add_expert(tree, pinfo, &ei_zbee_tlv_max_recursion_depth_reached, tvb, 0, 0);
        return offset;
    }

    p_set_proto_depth(pinfo, proto_zbee_tlv, recursion_depth);

    while (tvb_bytes_exist(tvb, offset, ZBEE_TLV_HEADER_LENGTH)) {
        length = tvb_get_uint8(tvb, offset + 1) + 1;
        subtree = proto_tree_add_subtree(tree, tvb, offset, ZBEE_TLV_HEADER_LENGTH + length, ett_zbee_tlv, NULL, "TLV");
        offset = dissect_zbee_tlv(tvb, pinfo, subtree, offset, data, source_type, cmd_id);
    }

    recursion_depth = p_get_proto_depth(pinfo, proto_zbee_tlv);
    p_set_proto_depth(pinfo, proto_zbee_tlv, recursion_depth - 1);

    return offset;
} /* dissect_zbee_tlvs */

/**
 * Dissector for ZBEE TLV.
 *
 * @param tvb pointer to buffer containing raw packet.
 * @param pinfo pointer to packet information fields.
 * @param tree pointer to data tree wireshark uses to display packet.
 */
static int
dissect_zbee_tlv_default(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  unsigned offset = 0;

  offset = dissect_zbee_tlvs(tvb, pinfo, tree, offset, data, ZBEE_TLV_SRC_TYPE_DEFAULT, 0);

  /* Check for leftover bytes. */
  if (offset < tvb_captured_length(tvb)) {
      /* Bytes leftover! */
      tvbuff_t    *leftover_tvb   = tvb_new_subset_remaining(tvb, offset);
      /* Dump the leftover to the data dissector. */
      call_data_dissector(leftover_tvb, pinfo, tree);
  }

  return tvb_captured_length(tvb);
}

/**
 * Proto ZBOSS Network Coprocessor product registration routine
 */
void proto_register_zbee_tlv(void)
{
    /* NCP protocol headers */
    static hf_register_info hf[] = {
        { &hf_zbee_tlv_relay_msg_type,
        { "Type", "zbee_tlv.relay.type", FT_UINT8, BASE_HEX, VALS(zbee_aps_relay_tlvs), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_relay_msg_length,
        { "Length", "zbee_tlv.relay.length", FT_UINT8, BASE_DEC, NULL, 0x0,  NULL, HFILL }},

        { &hf_zbee_tlv_relay_msg_joiner_ieee,
        { "Joiner IEEE",        "zbee_tlv.relay.joiner_ieee", FT_EUI64, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_tlv_global_type,
          { "Type",        "zbee_tlv.type_global", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_global_types), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_local_type_key_update_req_rsp,
          { "Type",        "zbee_tlv.type_local", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_local_types_key_update_req_rsp), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_local_type_key_negotiation_req_rsp,
          { "Type",        "zbee_tlv.type_local", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_local_types_key_negotiation_req_rsp), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_local_type_get_auth_level_rsp,
          { "Type",        "zbee_tlv.type_local", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_local_types_get_auth_level_rsp), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_local_type_clear_all_bindings_req,
          { "Type",        "zbee_tlv.type_local", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_local_types_clear_all_bindings_req), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_local_type_req_security_get_auth_token,
          { "Type",        "zbee_tlv.type_local", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_local_types_req_security_get_auth_token), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_local_type_req_security_get_auth_level,
          { "Type",        "zbee_tlv.type_local", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_local_types_req_security_get_auth_level), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_local_type_req_security_decommission,
          { "Type",        "zbee_tlv.type_local", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_local_types_req_security_decommission), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_local_type_req_beacon_survey,
          { "Type",        "zbee_tlv.type_local", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_local_types_req_beacon_survey), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_local_type_rsp_beacon_survey,
          { "Type",        "zbee_tlv.type_local", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_local_types_rsp_beacon_survey), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_local_type_req_challenge,
          { "Type",        "zbee_tlv.type_local", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_local_types_req_challenge), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_local_type_rsp_challenge,
          { "Type",        "zbee_tlv.type_local", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_local_types_rsp_challenge), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_local_type_rsp_set_configuration,
          { "Type",        "zbee_tlv.type_local", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_local_types_rsp_set_configuration), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_type,
          { "Unknown Type", "zbee_tlv.type", FT_UINT8, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_length,
          { "Length",      "zbee_tlv.length", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_tlv_value,
          { "Value",       "zbee_tlv.value", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_tlv_count,
          { "Count",       "zbee_tlv.count", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_tlv_local_status_count,
            { "TLV Status Count",           "zbee_tlv.tlv_status_count", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_tlv_local_type_id,
            { "TLV Type ID",                "zbee_tlv.tlv_type_id", FT_UINT8, BASE_HEX, VALS(zbee_tlv_global_types), 0x0,
            NULL, HFILL }},

        { &hf_zbee_tlv_local_proc_status,
            { "TLV Processing Status",      "zbee_tlv.tlv_proc_status", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_tlv_manufacturer_specific,
          { "ZigBee Manufacturer ID", "zbee_tlv.manufacturer_specific", FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_supported_key_negotiation_methods,
          { "Supported Key Negotiation Methods", "zbee_tlv.supported_key_negotiation_methods", FT_UINT8, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_supported_key_negotiation_methods_key_request,
          { "Key Request (ZigBee 3.0)",             "zbee_tlv.supported_key_negotiation_methods.key_request", FT_BOOLEAN, 8, NULL,
            ZBEE_TLV_SUPPORTED_KEY_NEGOTIATION_METHODS_KEY_REQUEST, NULL, HFILL }},

        { &hf_zbee_tlv_supported_key_negotiation_methods_ecdhe_using_curve25519_aes_mmo128,
          { "ECDHE using Curve25519 with Hash AES-MMO-128", "zbee_tlv.supported_key_negotiation_methods.ecdhe_using_curve25519_aes_mmo128", FT_BOOLEAN, 8, NULL,
            ZBEE_TLV_SUPPORTED_KEY_NEGOTIATION_METHODS_ANONYMOUS_ECDHE_USING_CURVE25519_AES_MMO128, NULL, HFILL }},

        { &hf_zbee_tlv_supported_key_negotiation_methods_ecdhe_using_curve25519_sha256,
          { "ECDHE using Curve25519 with Hash SHA-256", "zbee_tlv.supported_key_negotiation_methods.ecdhe_using_curve25519_sha256", FT_BOOLEAN, 8, NULL,
            ZBEE_TLV_SUPPORTED_KEY_NEGOTIATION_METHODS_ANONYMOUS_ECDHE_USING_CURVE25519_SHA256, NULL, HFILL }},

        { &hf_zbee_tlv_supported_secrets,
          { "Supported Pre-shared Secrets Bitmask", "zbee_tlv.supported_secrets", FT_UINT8, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_supported_preshared_secrets_auth_token,
          { "Symmetric Authentication Token", "zbee_tlv.supported_secrets.auth_token", FT_BOOLEAN, 8, NULL,
            0x1, NULL, HFILL }},

        { &hf_zbee_tlv_supported_preshared_secrets_ic,
          { "128-bit pre-configured link-key from install code", "zbee_tlv.supported_secrets.ic", FT_BOOLEAN, 8, NULL,
            0x2, NULL, HFILL }},

        { &hf_zbee_tlv_supported_preshared_secrets_passcode_pake,
          { "Variable-length pass code for PAKE protocols", "zbee_tlv.supported_secrets.passcode_pake", FT_BOOLEAN, 8, NULL,
            0x4, NULL, HFILL }},

        { &hf_zbee_tlv_supported_preshared_secrets_basic_access_key,
          { "Basic Access Key", "zbee_tlv.supported_secrets.basic_key", FT_BOOLEAN, 8, NULL,
            0x8, NULL, HFILL }},

        { &hf_zbee_tlv_supported_preshared_secrets_admin_access_key,
          { "Administrative Access Key", "zbee_tlv.supported_secrets.admin_key", FT_BOOLEAN, 8, NULL,
            0x10, NULL, HFILL }},

        { &hf_zbee_tlv_panid_conflict_cnt,
          { "PAN ID Conflict Count", "zbee_tlv.panid_conflict_cnt", FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_next_pan_id,
          { "Next PAN ID Change", "zbee_tlv.next_pan_id", FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_next_channel_change,
          { "Next Channel Change", "zbee_tlv.next_channel", FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_passphrase,
          { "128-bit Symmetric Passphrase", "zbee_tlv.passphrase", FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_challenge_value,
          { "Challenge Value", "zbee_tlv.challenge_val", FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_aps_frame_counter,
          { "APS Frame Counter", "zbee_tlv.aps_frame_cnt", FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_challenge_counter,
          { "Challenge Counter", "zbee_tlv.challenge_cnt", FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_configuration_param,
          { "Configuration Parameters", "zbee_tlv.configuration_parameters", FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_configuration_param_restricted_mode,
          { "apsZdoRestrictedMode", "zbee_tlv.conf_param.restricted_mode", FT_UINT16, BASE_DEC, NULL,
            0x1, NULL, HFILL }},

        { &hf_zbee_tlv_configuration_param_link_key_enc,
          { "requireLinkKeyEncryptionForApsTransportKey", "zbee_tlv.conf_param.req_link_key_enc", FT_UINT16, BASE_DEC, NULL,
            0x2, NULL, HFILL }},

        { &hf_zbee_tlv_configuration_param_leave_req_allowed,
          { "nwkLeaveRequestAllowed", "zbee_tlv.conf_param.leave_req_allowed", FT_UINT16, BASE_DEC, NULL,
            0x4, NULL, HFILL }},

        { &hf_zbee_tlv_dev_cap_ext_capability_information,
          { "Capability Information", "zbee_tlv.dev_cap_ext_cap_info", FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_dev_cap_ext_zbdirect_virt_device,
          { "Zigbee Direct Virtual Device", "zbee_tlv.dev_cap_ext.zbdirect_virt_dev", FT_UINT16, BASE_DEC, NULL,
            0x1, NULL, HFILL }},

        { &hf_zbee_tlv_lqa,
          { "LQA", "zbee_tlv.lqa", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_router_information,
          { "Router Information", "zbee_tlv.router_information", FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_router_information_hub_connectivity,
          { "Hub Connectivity",   "zbee_tlv.router_information.hub_connectivity", FT_BOOLEAN, 16, NULL,
              ZBEE_TLV_ROUTER_INFORMATION_HUB_CONNECTIVITY, NULL, HFILL }},

        { &hf_zbee_tlv_router_information_uptime,
          { "Uptime",             "zbee_tlv.router_information.uptime", FT_BOOLEAN, 16, NULL,
              ZBEE_TLV_ROUTER_INFORMATION_UPTIME, NULL, HFILL }},

        { &hf_zbee_tlv_router_information_pref_parent,
          { "Preferred parent",        "zbee_tlv.router_information.pref_parent", FT_BOOLEAN, 16, NULL,
              ZBEE_TLV_ROUTER_INFORMATION_PREF_PARENT, NULL, HFILL }},

        { &hf_zbee_tlv_router_information_battery_backup,
          { "Battery Backup",     "zbee_tlv.router_information.battery", FT_BOOLEAN, 16, NULL,
              ZBEE_TLV_ROUTER_INFORMATION_BATTERY_BACKUP, NULL, HFILL }},

        { &hf_zbee_tlv_router_information_enhanced_beacon_request_support,
          { "Enhanced Beacon Request Support", "zbee_tlv.router_information.enhanced_beacon", FT_BOOLEAN, 16, NULL,
              ZBEE_TLV_ROUTER_INFORMATION_ENHANCED_BEACON_REQUEST_SUPPORT, NULL, HFILL }},

        { &hf_zbee_tlv_router_information_mac_data_poll_keepalive_support,
          { "MAC Data Poll Keepalive Support", "zbee_tlv.router_information.mac_data_poll_keepalive", FT_BOOLEAN, 16, NULL,
              ZBEE_TLV_ROUTER_INFORMATION_MAC_DATA_POLL_KEEPALIVE_SUPPORT, NULL, HFILL }},

        { &hf_zbee_tlv_router_information_end_device_keepalive_support,
          { "End Device Keepalive Support", "zbee_tlv.router_information.end_dev_keepalive", FT_BOOLEAN, 16, NULL,
              ZBEE_TLV_ROUTER_INFORMATION_END_DEVICE_KEEPALIVE_SUPPORT, NULL, HFILL }},

        { &hf_zbee_tlv_router_information_power_negotiation_support,
          { "Power Negotiation Support", "zbee_tlv.router_information.power_negotiation", FT_BOOLEAN, 16, NULL,
              ZBEE_TLV_ROUTER_INFORMATION_POWER_NEGOTIATION_SUPPORT, NULL, HFILL }},

        { &hf_zbee_tlv_node_id,
          { "Node ID", "zbee_tlv.node_id", FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_frag_opt,
          { "Fragmentation Options", "zbee_tlv.frag_opt", FT_UINT8, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_max_reassembled_buf_size,
          { "Maximum Reassembled Input Buffer Size", "zbee_tlv.max_buf_size", FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_selected_key_negotiation_method,
          { "Selected Key Negotiation Method", "zbee_tlv.selected_key_negotiation_method", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_selected_key_negotiation_method), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_selected_pre_shared_secret,
          { "Selected Pre Shared Secret", "zbee_tlv.selected_pre_shared_secret", FT_UINT8, BASE_HEX,
            VALS(zbee_tlv_selected_pre_shared_secret), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_device_eui64,
          { "Device EUI64", "zbee_tlv.device_eui64", FT_EUI64, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_tlv_public_point,
          { "Public Point", "zbee_tlv.public_point", FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_tlv_global_tlv_id,
          { "TLV Type ID", "zbee_tlv.global_tlv_id", FT_UINT8, BASE_HEX, VALS(zbee_tlv_global_types), 0x0,
            NULL, HFILL }},

        { &hf_zbee_tlv_local_ieee_addr,
          { "IEEE Addr", "zbee_tlv.ieee_addr", FT_EUI64, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_tlv_mic64,
          { "MIC", "zbee_tlv.mic64", FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_tlv_local_initial_join_method,
          { "Initial Join Method",        "zbee_tlv.init_method", FT_UINT8, BASE_HEX,
            VALS(zbee_initial_join_methods), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_local_active_lk_type,
          { "Active link key type",        "zbee_tlv.lk_type", FT_UINT8, BASE_HEX,
            VALS(zbee_active_lk_types), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_zbd_comm_tlv,
            { "ZBD Commissioning Service TLV Type ID", "zbee_tlv.zbd.comm_tlv_id", FT_UINT8, BASE_HEX,
              VALS(zbee_tlv_zbd_comm_types), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_zbd_comm_mj_cmd_tlv,
            { "ZBD Manage Joiners TLV Type ID", "zbee_tlv.zbd.comm_mj_tlv_id", FT_UINT8, BASE_HEX,
              VALS(zbee_tlv_zbd_comm_mj_types), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_zbd_secur_tlv,
            { "ZBD Manage Joiners TLV Type ID", "zbee_tlv.zbd.comm_mj_tlv_id", FT_UINT8, BASE_HEX,
              VALS(zbee_tlv_zbd_secur_types), 0x0, NULL, HFILL }},

        { &hf_zbee_tlv_local_tunneling_npdu,
            { "NPDU", "zbee_tlv.zbd.npdu", FT_NONE, BASE_NONE,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_zbd_tunneling_npdu_msg_tlv,
            { "NPDU Message TLV", "zbee_tlv.zbd.tlv.tunneling.npdu_msg", FT_NONE, BASE_NONE,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_comm_ext_pan_id,
            { "Extended PAN ID", "zbee_tlv.zbd.comm.ext_pan_id", FT_BYTES, SEP_COLON,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_comm_short_pan_id,
            { "Short PAN ID", "zbee_tlv.zbd.comm.short_pan_id", FT_UINT16, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_comm_channel_mask,
            { "Network Channels", "zbee_tlv.zbd.comm.nwk_channel_mask", FT_UINT32, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_comm_channel_page,
            { "Channel Page", "zbee_tlv.zbd.comm.nwk_channel_page", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_comm_channel_page_count,
            { "Channel Page Count", "zbee_tlv.zbd.comm.nwk_channel_page_count", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_comm_nwk_key,
            { "Network key", "zbee_tlv.zbd.comm.nwk_key", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_comm_link_key,
            { "Link key", "zbee_tlv.zbd.comm.link_key", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_comm_dev_type,
            { "Device type", "zbee_tlv.zbd.comm.dev_type", FT_UINT8, BASE_HEX,
                VALS(zbee_tlv_local_types_dev_type_str), 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_comm_nwk_addr,
            { "Network address", "zbee_tlv.zbd.comm.nwk_addr", FT_UINT16, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_comm_join_method,
            { "Join method", "zbee_tlv.zbd.comm.join_method", FT_UINT8, BASE_HEX,
                VALS(zbee_tlv_local_types_join_method_str), 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_comm_tc_addr,
            { "TC address", "zbee_tlv.zbd.comm.tc_addr", FT_UINT64, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_comm_nwk_upd_id,
            { "Network update ID", "zbee_tlv.zbd.comm.nwk_upd_id", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_comm_key_seq_num,
            { "Network active key sequence number", "zbee_tlv.zbd.comm.nwk_key_seq_num", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_comm_adm_key,
            { "Admin key", "zbee_tlv.zbd.comm.admin_key", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_comm_status_code_domain,
            { "Domain", "zbee_tlv.zbd.comm.status_code_domain", FT_UINT8, BASE_HEX,
                VALS(zbee_tlv_local_types_status_code_domain_str), 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_comm_status_code_value,
            { "Code", "zbee_tlv.zbd.comm.status_code_value", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_comm_mj_prov_lnk_key,
            { "Manage Joiners Provisional Link key", "zbee_tlv.zbd.comm.manage_joiners_prov_lnk_key", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_comm_mj_ieee_addr,
            { "Manage Joiners IEEE Address", "zbee_tlv.zbd.comm.manage_joiners_ieee_addr", FT_UINT64, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_comm_mj_cmd,
            { "Manage Joiners command", "zbee_tlv.zbd.comm.manage_joiners_cmd", FT_UINT8, BASE_HEX,
                VALS(zbee_tlv_local_types_mj_cmd_str), 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_tunneling_npdu_flags,
            { "NPDU Flags", "zbee_tlv.zbd.tunneling.npdu_flags", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_tunneling_npdu_flags_security,
            { "Security Enabled", "zbee_tlv.zbd.tunneling.npdu_flags.security", FT_BOOLEAN, 8,
                NULL, 0b00000001, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_tunneling_npdu_flags_reserved,
            { "Reserved", "zbee_tlv.zbd.tunneling.npdu_flags.reserved", FT_UINT8, BASE_DEC,
                NULL, 0b11111110, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_tunneling_npdu_length,
            { "NPDU Length", "zbee_tlv.zbd.tunneling.npdu_length", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_selected_key_method,
            { "Selected Key Negotiation Method", "zbee_tlv.zbd.secur.key_method", FT_UINT8, BASE_HEX,
                VALS(zbee_tlv_local_types_key_method_str), 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_selected_psk_secret,
            { "Selected PSK Secret", "zbee_tlv.zbd.secur.psk_secret", FT_UINT8, BASE_HEX,
                VALS(zbee_tlv_local_types_psk_secret_str), 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_nwk_key_seq_num,
            { "Network Key Sequence Number", "zbee_tlv.zbd.secur.nwk_key_seq_num", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_mac_tag,
            { "MAC Tag", "zbee_tlv.zbd.secur.mac_tag", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_comm_link_key_flags,
            { "Link Key", "zbee_tlv.zbd.comm.join.link_key", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_comm_link_key_flags_unique,
            { "Unique", "zbee_tlv.zbd.comm.join.link_key.unique", FT_UINT8, BASE_DEC,
                VALS(zbee_tlv_local_types_lnk_key_unique_str), ZBEE_TLV_LINK_KEY_UNIQUE, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_comm_link_key_flags_provisional,
            { "Provisional", "zbee_tlv.zbd.comm.join.link_key.provisional", FT_UINT8, BASE_DEC,
                VALS(zbee_tlv_local_types_lnk_key_provisional_str), ZBEE_TLV_LINK_KEY_PROVISIONAL, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_comm_network_status_map,
            { "Network Status Map", "zbee_tlv.zbd.comm.status_map", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_comm_network_status_map_joined_status,
            { "Joined", "zbee_tlv.zbd.comm.status_map.joined_status", FT_UINT8, BASE_HEX,
                VALS(zbee_tlv_local_types_joined_status_str), ZBEE_TLV_STATUS_MAP_JOINED_STATUS, NULL, HFILL }
        },
        { &hf_zbee_tlv_local_comm_network_status_map_open_status,
            { "Open/Closed", "zbee_tlv.zbd.comm.status_map.open_status", FT_UINT8, BASE_DEC,
                VALS(zbee_tlv_local_types_nwk_state_str), ZBEE_TLV_STATUS_MAP_OPEN_STATUS, NULL, HFILL }
        },
        { &hf_zbee_tlv_network_status_map_network_type,
            { "Network Type", "zbee_tlv.zbd.comm.status_map.network_type", FT_UINT8, BASE_DEC,
                VALS(zbee_tlv_local_types_nwk_type_str), ZBEE_TLV_STATUS_MAP_NETWORK_TYPE, NULL, HFILL }
        },
    };

    /* Protocol subtrees */
    static int *ett[] =
        {
            &ett_zbee_aps_tlv,
            &ett_zbee_aps_relay,
            &ett_zbee_tlv,
            &ett_zbee_tlv_supported_key_negotiation_methods,
            &ett_zbee_tlv_supported_secrets,
            &ett_zbee_tlv_router_information,
            &ett_zbee_tlv_configuration_param,
            &ett_zbee_tlv_capability_information,
            &ett_zbee_tlv_zbd_tunneling_npdu,
            &ett_zbee_tlv_zbd_tunneling_npdu_flags,
            &ett_zbee_tlv_link_key_flags,
            &ett_zbee_tlv_network_status_map
        };

    static ei_register_info ei[] = {
        { &ei_zbee_tlv_max_recursion_depth_reached, { "zbee_tlv.max_recursion_depth_reached",
            PI_PROTOCOL, PI_WARN, "Maximum allowed recursion depth reached - stop decoding", EXPFILL }}
    };

    proto_zbee_tlv = proto_register_protocol("Zigbee TLV", "ZB TLV", "zbee_tlv");

    proto_register_field_array(proto_zbee_tlv, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module_t* expert_zbee_tlv = expert_register_protocol(proto_zbee_tlv);
    expert_register_field_array(expert_zbee_tlv, ei, array_length(ei));

    register_dissector("zbee_tlv", dissect_zbee_tlv_default, proto_zbee_tlv);
    zbee_nwk_handle = find_dissector("zbee_nwk");
} /* proto_register_zbee_tlv */
