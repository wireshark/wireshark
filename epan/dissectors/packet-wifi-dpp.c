/* packet-wifi-dpp.c
 *
 * Wi-Fi Device Provisioning Protocol (DPP)
 *
 * Copyright 2017-2020 Richard Sharpe <realrichardsharpe@gmail.com>
 * Copyright 2017-2020 The WiFi Alliance
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Code and constants based on Device_Provisioning_Protocol_Specification_v1.2.9
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-tcp.h"
#include <epan/to_str.h>
#include <epan/expert.h>

#include "packet-wifi-dpp.h"
#include "packet-ieee80211.h"

extern const value_string wfa_subtype_vals[];

void proto_register_wifi_dpp(void);
void proto_reg_handoff_wifi_dpp(void);

#define WIFI_DPP_TCP_PORT (7871)
static guint wifi_dpp_tcp_port = WIFI_DPP_TCP_PORT;

enum {
  DPP_STATUS_OK =                0,
  DPP_STATUS_NOT_COMPATIBLE =    1,
  DPP_STATUS_AUTH_FAILURE =      2,
  DPP_STATUS_UNWRAP_FAILURE =    3,
  DPP_STATUS_BAD_GROUP =         4,
  DPP_STATUS_CONFIGURE_FAILURE = 5,
  DPP_STATUS_RESPONSE_PENDING =  6,
  DPP_STATUS_INVALID_CONNECTOR = 7,
  DPP_STATUS_NO_MATCH =          8,
  DPP_STATUS_CONFIG_REJECTED   = 9,
  DPP_STATUS_NO_AP =             10,
  DPP_STATUS_CONFIGURE_PENDING = 11,
  DPP_STATUS_CSR_NEEDED =        12,
  DPP_STATUS_CSR_BAD =           13
};

static const value_string dpp_status_codes[] = {
  { DPP_STATUS_OK,                 "OK" },
  { DPP_STATUS_NOT_COMPATIBLE,     "Not Compatible" },
  { DPP_STATUS_AUTH_FAILURE,       "Auth Failure" },
  { DPP_STATUS_UNWRAP_FAILURE,     "Unwrap Failure" },
  { DPP_STATUS_BAD_GROUP,          "Bad Group" },
  { DPP_STATUS_CONFIGURE_FAILURE,  "Configure Failure" },
  { DPP_STATUS_RESPONSE_PENDING,   "Response Pending" },
  { DPP_STATUS_INVALID_CONNECTOR,  "Invalid Connector" },
  { DPP_STATUS_NO_MATCH,           "No Match" },
  { DPP_STATUS_CONFIG_REJECTED,    "Enrollee rejected the config" },
  { DPP_STATUS_NO_AP,              "Enrollee failed to discover an AP" },
  { DPP_STATUS_CONFIGURE_PENDING,  "Configuration response is not ready yet. The enrollee needs to request again." },
  { DPP_STATUS_CSR_NEEDED,         "Configuration requires a Certificate Signing Request. Enrollee needs to request again." },
  { DPP_STATUS_CSR_BAD,            "The Certificate Signing Request was invalid." },
  { DPP_STATUS_OK,                "OK" },
  { DPP_STATUS_NOT_COMPATIBLE,    "Not Compatible" },
  { DPP_STATUS_AUTH_FAILURE,      "Auth Failure" },
  { DPP_STATUS_UNWRAP_FAILURE,    "Unwrap Failure" },
  { DPP_STATUS_BAD_GROUP,         "Bad Group" },
  { DPP_STATUS_CONFIGURE_FAILURE, "Configure Failure" },
  { DPP_STATUS_RESPONSE_PENDING,  "Response Pending" },
  { 0, NULL }
};

enum {
  DPP_STATUS                           = 0x1000,
  DPP_INITIATOR_BOOTSTRAPPING_KEY_HASH = 0x1001,
  DPP_RESPONDER_BOOTSTRAPPING_KEY_HASH = 0x1002,
  DPP_INITIATOR_PROTOCOL_KEY           = 0x1003,
  DPP_WRAPPED_DATA                     = 0x1004,
  DPP_INITIATOR_NONCE                  = 0x1005,
  DPP_INITIATOR_CAPABILITIES           = 0x1006,
  DPP_RESPONDER_NONCE                  = 0x1007,
  DPP_RESPONDER_CAPABILITIES           = 0x1008,
  DPP_RESPONDER_PROTOCOL_KEY           = 0x1009,
  DPP_INITIATOR_AUTHENTICATING_TAG     = 0x100A,
  DPP_RESPONDER_AUTHENTICATING_TAG     = 0x100B,
  DPP_CONFIGURATION_OBJECT             = 0x100C,
  DPP_CONNECTOR                        = 0x100D,
  DPP_CONFIGURATION_ATTRIBUTES_OBJECT  = 0x100E,
  DPP_BOOTSTRAPPING_KEY                = 0x100F,
  DPP_FINITE_CYCLIC_GROUP              = 0x1012,
  DPP_ENCRYPTED_KEY                    = 0x1013,
  DPP_ENROLLEE_NONCE                   = 0x1014,
  DPP_CODE_IDENTIFIER                  = 0x1015,
  DPP_TRANSACTION_ID                   = 0x1016,
  DPP_BOOTSTRAPPING_INFO               = 0x1017,
  DPP_CHANNEL                          = 0x1018,
  DPP_PROTOCOL_VERSION                 = 0x1019,
  DPP_ENVELOPEDATA                     = 0x101A,
  DPP_SENDCONNSTATUS                   = 0x101B,
  DPP_CONNSTATUS                       = 0x101C,
  DPP_RECONFIG_FLAGS                   = 0x101D,
  DPP_C_SIGN_KEY_HASH                  = 0x101E,
  DPP_CSR_ATTRIBUTES_REQUEST           = 0x101F,
  DPP_A_NONCE                          = 0x1020,
  DPP_E_PRIME_ID                       = 0x1021
};

static const value_string dpp_ie_attr_ids[] = {
  { DPP_STATUS,                           "DPP Status" },
  { DPP_INITIATOR_BOOTSTRAPPING_KEY_HASH, "DPP Initiator Bootstrapping Key Hash" },
  { DPP_RESPONDER_BOOTSTRAPPING_KEY_HASH, "DPP Responder Bootstrapping Key Hash" },
  { DPP_INITIATOR_PROTOCOL_KEY,           "DPP Initiator Protocol Key" },
  { DPP_WRAPPED_DATA,                     "DPP Primary Wrapped Data" },
  { DPP_INITIATOR_NONCE,                  "DPP Initiator Nonce" },
  { DPP_INITIATOR_CAPABILITIES,           "DPP Initiator Capabilities" },
  { DPP_RESPONDER_NONCE,                  "DPP Responder Nonce" },
  { DPP_RESPONDER_CAPABILITIES,           "DPP Responder Capabilities" },
  { DPP_RESPONDER_PROTOCOL_KEY,           "DPP Responder Protocol Key" },
  { DPP_INITIATOR_AUTHENTICATING_TAG,     "DPP Initiator Authenticating Tag" },
  { DPP_RESPONDER_AUTHENTICATING_TAG,     "DPP Responder Authenticating Tag" },
  { DPP_CONFIGURATION_OBJECT,             "DPP Configuration Object" },
  { DPP_CONNECTOR,                        "DPP Connector" },
  { DPP_CONFIGURATION_ATTRIBUTES_OBJECT,  "DPP Configuration Attributes Object" },
  { DPP_BOOTSTRAPPING_KEY,                "DPP Bootstrapping Key" },
  { DPP_FINITE_CYCLIC_GROUP,              "DPP Finite Cyclic Group" },
  { DPP_ENCRYPTED_KEY,                    "DPP Encrypted Key" },
  { DPP_CODE_IDENTIFIER,                  "DPP Code Identifier" },
  { DPP_TRANSACTION_ID,                   "DPP Transaction ID" },
  { DPP_BOOTSTRAPPING_INFO,               "DPP Bootstrapping Info" },
  { DPP_CHANNEL,                          "DPP Channel" },
  { DPP_PROTOCOL_VERSION,                 "DPP Protocol Version" },
  { DPP_ENVELOPEDATA,                     "DPP Enveloped Data" },
  { DPP_SENDCONNSTATUS,                   "DPP Send Conn Status" },
  { DPP_CONNSTATUS,                       "DPP Conn Status" },
  { DPP_RECONFIG_FLAGS,                   "DPP Reconfig Flags" },
  { DPP_C_SIGN_KEY_HASH,                  "DPP C-sign key Hash" },
  { DPP_CSR_ATTRIBUTES_REQUEST,           "DPP CSR Attributes Request" },
  { DPP_A_NONCE,                          "DPP A-NONCE" },
  { DPP_E_PRIME_ID,                       "DPP E'-id" },
  { 0, NULL }
};

enum {
  DPP_AUTHENTICATION_REQUEST          = 0,
  DPP_AUTHENTICATION_RESPONSE         = 1,
  DPP_AUTHENTICATION_CONFIRM          = 2,
  DPP_PEER_DISCOVERY_REQUEST          = 5,
  DPP_PEER_DISCOVERY_RESPONSE         = 6,
  DPP_PKEX_EXCHANGE_REQUEST           = 7,
  DPP_PKEX_EXCHANGE_RESPONSE          = 8,
  DPP_PKEX_COMMIT_REVEAL_REQUEST      = 9,
  DPP_PKEX_COMMIT_REVEAL_RESPONSE     = 10,
  DPP_CONFIGURATION_RESULT            = 11,
  DPP_CONNECTION_STATUS_RESULT        = 12,
  DPP_PRESENCE_ANNOUNCEMENT           = 13,
  DPP_RECONFIG_ANNOUNCEMENT           = 14,
  DPP_RECONFIG_AUTH_REQUEST           = 15,
  DPP_RECONFIG_AUTH_RESPONSE          = 16,
  DPP_RECONFIG_AUTH_CONFIRM           = 17
};

static const value_string dpp_public_action_subtypes[] = {
  { DPP_AUTHENTICATION_REQUEST,           "Authentication Request" },
  { DPP_AUTHENTICATION_RESPONSE,          "Authentication Response" },
  { DPP_AUTHENTICATION_CONFIRM,           "Authentication Confirm" },
  { DPP_PEER_DISCOVERY_REQUEST,           "Peer Discovery Request" },
  { DPP_PEER_DISCOVERY_RESPONSE,          "Peer Discovery Response" },
  { DPP_PKEX_EXCHANGE_REQUEST,            "PKEX Exchange Request" },
  { DPP_PKEX_EXCHANGE_RESPONSE,           "PKEX Exchange Response" },
  { DPP_PKEX_COMMIT_REVEAL_REQUEST,       "PKEX Commit-Reveal Request" },
  { DPP_PKEX_COMMIT_REVEAL_RESPONSE,      "PKEX Commit-Reveal Response" },
  { DPP_CONFIGURATION_RESULT,             "Configuration Result" },
  { DPP_CONNECTION_STATUS_RESULT,         "Connection Status Result" },
  { DPP_PRESENCE_ANNOUNCEMENT,            "Presence Announcement" },
  { DPP_RECONFIG_ANNOUNCEMENT,            "Reconfig Announcement" },
  { DPP_RECONFIG_AUTH_REQUEST,            "Reconfig Authentication Request" },
  { DPP_RECONFIG_AUTH_RESPONSE,           "Reconfig Authentication Response" },
  { DPP_RECONFIG_AUTH_CONFIRM,            "Reconfig Authentication Confirm" },
  { 0, NULL }
};

/*
 * This table and the one above share values ... but this one is truncated.
 */
static const value_string dpp_action_subtypes[] = {
  { DPP_AUTHENTICATION_REQUEST, "Authentication Request" },
  { DPP_AUTHENTICATION_RESPONSE, "Authentication Response" },
  { DPP_AUTHENTICATION_CONFIRM, "Authentication Confirm" },
  { DPP_PEER_DISCOVERY_REQUEST, "Peer Discovery Request" },
  { DPP_PEER_DISCOVERY_RESPONSE, "Peer Discovery Response" },
  { 0, NULL }
};

static const range_string dpp_protocol_version_rvals[] = {
  { 0, 0,   "Reserved" },
  { 1, 1,   "1.0" },
  { 2, 255, "Reserved" },
  { 0, 0, NULL }
};

static int proto_wifi_dpp = -1;

static gint ett_wifi_dpp_ie_generic = -1;
static gint ett_wifi_dpp_attributes = -1;
static gint ett_wifi_dpp_pa = -1;
static gint ett_wifi_dpp_attribute = -1;
static gint ett_wifi_dpp_attr_header = -1;
static gint ett_wifi_dpp_attr_value = -1;

static int hf_wifi_dpp_ie_attr_id = -1;
static int hf_wifi_dpp_ie_attr_len = -1;
static int hf_wifi_dpp_ie_generic = -1;  /* Remove eventually */
static int hf_wifi_dpp_action_dialog_token = -1;
static int hf_wifi_dpp_action_subtype = -1;
static int hf_wifi_dpp_crypto_suite = -1;
static int hf_wifi_dpp_public_action_subtype = -1;
static int hf_wifi_dpp_init_hash = -1;
static int hf_wifi_dpp_resp_hash = -1;
static int hf_wifi_dpp_status = -1;
static int hf_wifi_dpp_key_x = -1;
static int hf_wifi_dpp_key_y = -1;
static int hf_wifi_dpp_trans_id = -1;
static int hf_wifi_dpp_finite_cyclic_group = -1;
static int hf_wifi_dpp_capabilities = -1;
static int hf_wifi_dpp_code_identifier = -1;
static int hf_wifi_dpp_enc_key_attribute = -1;
static int hf_wifi_dpp_primary_wrapped_data = -1;
static int hf_wifi_dpp_connector_attr = -1;
static int hf_wifi_dpp_initiator_nonce = -1;
static int hf_wifi_dpp_operating_class = -1;
static int hf_wifi_dpp_channel = -1;
static int hf_wifi_dpp_protocol_version = -1;
static int hf_wifi_dpp_a_nonce = -1;
static int hf_wifi_dpp_e_prime_id = -1;
static int hf_wifi_dpp_unknown_anqp_item = -1;

static int hf_wifi_dpp_tcp_pdu_length = -1;
static int hf_wifi_dpp_tcp_pdu_action_field = -1;
static int hf_wifi_dpp_tcp_oui = -1;
static int hf_wifi_dpp_tcp_oui_type = -1;
static int hf_wifi_dpp_tcp_dialog_token = -1;
static int hf_wifi_dpp_tcp_adv_proto_elt = -1;
static int hf_wifi_dpp_tcp_vendor_specific = -1;
static int hf_wifi_dpp_tcp_vendor_spec_len = -1;
static int hf_wifi_dpp_tcp_config = -1;
static int hf_wifi_dpp_tcp_query_req_len = -1;
static int hf_wifi_dpp_tcp_status_code = -1;
static int hf_wifi_dpp_gas_query_resp_frag_id = -1;
static int hf_wifi_dpp_tcp_comeback_delay = -1;
static int hf_wifi_dpp_tcp_query_resp_len = -1;

static int
dissect_wifi_dpp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  int offset = 0;

  proto_tree_add_item(tree, hf_wifi_dpp_unknown_anqp_item, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
  return tvb_captured_length(tvb);
}

static int
dissect_wifi_dpp_ie(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ie;
  guint remaining_len = tvb_reported_length(tvb);

  ie = proto_tree_add_subtree(tree, tvb, 0, remaining_len, ett_wifi_dpp_ie_generic, NULL, "Generic DPP IE");
  proto_tree_add_item(ie, hf_wifi_dpp_ie_generic, tvb, 0, remaining_len,
                      ENC_NA);
  return tvb_captured_length(tvb);
}

static int
dissect_wifi_dpp_attributes(packet_info *pinfo _U_, proto_tree *tree,
                            tvbuff_t *tvb, int offset _U_)
{
  proto_item *si = NULL;
  guint8 status;
  proto_tree *attr, *specific_attr, *attr_hdr;
  guint16 attribute_id;
  guint16 attribute_len;
  guint attributes_len = 0;
  guint remaining_len = tvb_reported_length_remaining(tvb, offset);

  while (remaining_len) {
    attribute_id = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    attribute_len = tvb_get_guint16(tvb, offset + 2, ENC_LITTLE_ENDIAN);
    attr = proto_tree_add_subtree_format(tree, tvb, offset,
                                attribute_len + 4, ett_wifi_dpp_attribute,
                                &si, "%s Attribute",
                                val_to_str(attribute_id,
                                        dpp_ie_attr_ids,
                                        "Unknown (%u)"));
    attr_hdr = proto_tree_add_subtree(attr, tvb, offset, 4,
                                        ett_wifi_dpp_attr_header, NULL,
                                        "Attribute Header");

    proto_tree_add_item(attr_hdr, hf_wifi_dpp_ie_attr_id, tvb, offset, 2,
                        ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(attr_hdr, hf_wifi_dpp_ie_attr_len, tvb, offset, 2,
                        ENC_LITTLE_ENDIAN);
    offset += 2;

    specific_attr = proto_tree_add_subtree(attr, tvb, offset, attribute_len,
                                        ett_wifi_dpp_attr_value,
                                        NULL, "Attribute Value");

    switch (attribute_id) {
    case DPP_STATUS:
      status = tvb_get_guint8(tvb, offset);
      proto_item_append_text(si, ": %s", val_to_str(status,
                                         dpp_status_codes,
                                         "Unknown (%u)"));
      proto_tree_add_item(specific_attr, hf_wifi_dpp_status, tvb, offset, attribute_len, ENC_LITTLE_ENDIAN);
      break;

    case DPP_INITIATOR_BOOTSTRAPPING_KEY_HASH:
      proto_tree_add_item(specific_attr, hf_wifi_dpp_init_hash, tvb, offset, attribute_len, ENC_NA);
      break;

    case DPP_RESPONDER_BOOTSTRAPPING_KEY_HASH:
      proto_tree_add_item(specific_attr, hf_wifi_dpp_resp_hash, tvb, offset, attribute_len, ENC_NA);
      break;

    case DPP_RESPONDER_PROTOCOL_KEY:
    case DPP_INITIATOR_PROTOCOL_KEY:
      // This is two protocol keys of equal length, X then Y.
      proto_tree_add_item(specific_attr, hf_wifi_dpp_key_x, tvb, offset, attribute_len/2, ENC_NA);
      proto_tree_add_item(specific_attr, hf_wifi_dpp_key_y, tvb, offset + attribute_len/2, attribute_len/2, ENC_NA);
      break;

    case DPP_TRANSACTION_ID:
      proto_tree_add_item(specific_attr, hf_wifi_dpp_trans_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      break;

    case DPP_FINITE_CYCLIC_GROUP:
    case DPP_RESPONDER_CAPABILITIES:
      proto_tree_add_item(specific_attr, hf_wifi_dpp_finite_cyclic_group, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      break;

    case DPP_INITIATOR_CAPABILITIES:
      proto_tree_add_item(specific_attr, hf_wifi_dpp_capabilities, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      break;

    case DPP_CODE_IDENTIFIER:
      proto_tree_add_item(specific_attr, hf_wifi_dpp_code_identifier, tvb, offset, attribute_len, ENC_UTF_8|ENC_NA);
      break;

    case DPP_ENCRYPTED_KEY:
      proto_tree_add_item(specific_attr, hf_wifi_dpp_enc_key_attribute, tvb, offset, attribute_len, ENC_NA);
      break;

    case DPP_WRAPPED_DATA:
      proto_tree_add_item(specific_attr, hf_wifi_dpp_primary_wrapped_data, tvb, offset, attribute_len, ENC_NA);
      break;

    case DPP_CONNECTOR:
      proto_tree_add_item(specific_attr, hf_wifi_dpp_connector_attr, tvb,
                          offset, attribute_len, ENC_NA);
      break;

    case DPP_INITIATOR_NONCE:
      proto_tree_add_item(specific_attr, hf_wifi_dpp_initiator_nonce, tvb,
                          offset, attribute_len, ENC_NA);
      break;

    case DPP_CHANNEL:
      proto_tree_add_item(specific_attr, hf_wifi_dpp_operating_class, tvb,
                          offset, 1, ENC_NA);
      proto_tree_add_item(specific_attr, hf_wifi_dpp_channel, tvb, offset + 1,
                          1, ENC_NA);
      break;

    case DPP_PROTOCOL_VERSION:
      proto_tree_add_item(specific_attr, hf_wifi_dpp_protocol_version, tvb,
                          offset, 1, ENC_NA);
      break;

    case DPP_A_NONCE:
      proto_tree_add_item(specific_attr, hf_wifi_dpp_a_nonce, tvb, offset,
                          attribute_len, ENC_NA);
      break;

    case DPP_E_PRIME_ID:
      proto_tree_add_item(specific_attr, hf_wifi_dpp_e_prime_id, tvb, offset,
                          attribute_len, ENC_NA);
       break;

    case DPP_INITIATOR_AUTHENTICATING_TAG:

    case DPP_RESPONDER_AUTHENTICATING_TAG:

    case DPP_CONFIGURATION_OBJECT:

    case DPP_CONFIGURATION_ATTRIBUTES_OBJECT:

    case DPP_BOOTSTRAPPING_KEY:

    case DPP_ENROLLEE_NONCE:

    default:
      proto_tree_add_item(specific_attr, hf_wifi_dpp_ie_generic, tvb, offset, attribute_len, ENC_NA);
      break;
    }

    offset += attribute_len;
    attributes_len += attribute_len + 4;
    remaining_len -= (attribute_len + 4);

  }

  return attributes_len; // We return the attribute length plus hdr!
}

int
dissect_wifi_dpp_config_proto(packet_info *pinfo _U_, proto_tree *tree,
                             tvbuff_t *tvb, int offset _U_)
{
  proto_item *dpp_item;
  proto_tree *dpp_tree, *attr_tree;
  guint remaining_len = tvb_reported_length_remaining(tvb, offset);

  dpp_item = proto_tree_add_item(tree, proto_wifi_dpp, tvb, offset, -1, ENC_NA);
  dpp_tree = proto_item_add_subtree(dpp_item, ett_wifi_dpp_pa);
  proto_item_append_text(dpp_item, " Configuration");

  attr_tree = proto_tree_add_subtree_format(dpp_tree, tvb, offset,
                                            remaining_len,
                                            ett_wifi_dpp_attributes, NULL,
                                            "DPP Attributes");

  offset = dissect_wifi_dpp_attributes(pinfo, attr_tree, tvb, offset);

  return offset;
}

int
dissect_wifi_dpp_public_action(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, void *data _U_)
{
  guint8 subtype;
  guint remaining_len;
  proto_item *dpp_item;
  proto_tree *dpp_tree, *attr_tree;
  guint16 attributes_len;
  int offset = 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "wifi_dpp");

  /* The Crypto suite comes before the DPP frame type */
  subtype = tvb_get_guint8(tvb, offset + 1);
  col_append_fstr(pinfo->cinfo, COL_INFO, ", DPP - %s",
                  val_to_str(subtype, dpp_public_action_subtypes,
                             "Unknown (%u)"));

  remaining_len = tvb_reported_length_remaining(tvb, offset);

  dpp_item = proto_tree_add_item(tree, proto_wifi_dpp, tvb, offset, -1, ENC_NA);
  dpp_tree = proto_item_add_subtree(dpp_item, ett_wifi_dpp_pa);
  proto_item_append_text(dpp_item, ": %s", val_to_str(subtype,
                                                 dpp_public_action_subtypes,
                                                 "Unknown (%u)"));
  proto_tree_add_item(dpp_tree, hf_wifi_dpp_crypto_suite, tvb, offset, 1,
                      ENC_LITTLE_ENDIAN);
  offset++;
  remaining_len--;

  proto_tree_add_item(dpp_tree, hf_wifi_dpp_public_action_subtype, tvb, offset,
                      1, ENC_LITTLE_ENDIAN);
  offset++;  /* Skip the OUI Subtype/DPP Request type */
  remaining_len--;
  if (remaining_len) {
    attr_tree = proto_tree_add_subtree_format(dpp_tree, tvb, offset,
                       remaining_len,
                       ett_wifi_dpp_attributes, NULL, "DPP Attributes");

    attributes_len = dissect_wifi_dpp_attributes(pinfo, attr_tree, tvb, offset);
    offset += attributes_len;
  }

  return offset;
}

static int
dissect_wifi_dpp_action(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  int offset = 0;
  proto_tree_add_item(tree, hf_wifi_dpp_action_subtype, tvb, offset, 1, ENC_NA);
  offset++;

  proto_tree_add_item(tree, hf_wifi_dpp_action_dialog_token, tvb, offset, 1,
                      ENC_NA);
  offset++;

  return offset;
}

static int
dissect_wifi_dpp_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo _U_,
  proto_tree *tree, void *data _U_)
{
  int offset = 0;
  guint8 action;
  tvbuff_t *newtvb;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "dpp");

  /*
   * We get a length, followed by Action field, OUI, OUI type and then a
   * DPP public action
   */
  proto_tree_add_item(tree, hf_wifi_dpp_tcp_pdu_length, tvb, offset, 4,
                      ENC_BIG_ENDIAN);
  offset += 4;

  action = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_wifi_dpp_tcp_pdu_action_field, tvb, offset, 1,
                      ENC_NA);
  offset += 1;

  if (action == 0x09) {
    proto_tree_add_item(tree, hf_wifi_dpp_tcp_oui, tvb, offset, 3, ENC_NA);
    offset += 3;

    proto_tree_add_item(tree, hf_wifi_dpp_tcp_oui_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    newtvb = tvb_new_subset_remaining(tvb, offset);

    offset += dissect_wifi_dpp_public_action(newtvb, pinfo, tree, NULL);
  } else if (action == 0x0a) {
    col_append_str(pinfo->cinfo, COL_INFO, ", DPP - Configuration Request");

    proto_tree_add_item(tree, hf_wifi_dpp_tcp_dialog_token, tvb, offset, 1,
                        ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_wifi_dpp_tcp_adv_proto_elt, tvb, offset, 3,
                        ENC_NA);
    offset += 3;

    proto_tree_add_item(tree, hf_wifi_dpp_tcp_vendor_specific, tvb, offset, 1,
                        ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_wifi_dpp_tcp_vendor_spec_len, tvb, offset, 1,
                        ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_wifi_dpp_tcp_oui, tvb, offset, 3, ENC_NA);
    offset += 3;

    proto_tree_add_item(tree, hf_wifi_dpp_tcp_oui_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_wifi_dpp_tcp_config, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_wifi_dpp_tcp_query_req_len, tvb, offset, 2,
                        ENC_LITTLE_ENDIAN);
    offset += 2;

    offset += dissect_wifi_dpp_config_proto(pinfo, tree, tvb, offset);
  } else if (action == 0x0b || action == 0x0d) {
    guint16 qr_len;

    col_append_str(pinfo->cinfo, COL_INFO, ", DPP - Configuration Response");

    proto_tree_add_item(tree, hf_wifi_dpp_tcp_dialog_token, tvb, offset, 1,
                        ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_wifi_dpp_tcp_status_code, tvb, offset, 2,
                        ENC_LITTLE_ENDIAN);
    offset += 2;

    if (action == 0x0d) {
      proto_tree_add_item(tree, hf_wifi_dpp_gas_query_resp_frag_id, tvb, offset,
                          1, ENC_NA);
      offset += 1;
    }

    proto_tree_add_item(tree, hf_wifi_dpp_tcp_comeback_delay, tvb, offset, 2,
                        ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_wifi_dpp_tcp_adv_proto_elt, tvb, offset, 3,
                        ENC_NA);
    offset += 3;

    proto_tree_add_item(tree, hf_wifi_dpp_tcp_vendor_specific, tvb, offset, 1,
                        ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_wifi_dpp_tcp_vendor_spec_len, tvb, offset, 1,
                        ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_wifi_dpp_tcp_oui, tvb, offset, 3, ENC_NA);
    offset += 3;

    proto_tree_add_item(tree, hf_wifi_dpp_tcp_oui_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_wifi_dpp_tcp_config, tvb, offset, 1, ENC_NA);
    offset += 1;

    qr_len = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_wifi_dpp_tcp_query_resp_len, tvb, offset, 2,
                        ENC_LITTLE_ENDIAN);
    offset += 2;

    if (qr_len) {
      offset += dissect_wifi_dpp_config_proto(pinfo, tree, tvb, offset);
    }
  }

  return offset;
}

static guint
get_wifi_dpp_tcp_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset,
  void *data _U_)
{
  guint pkt_len;

  pkt_len = tvb_get_ntohl(tvb, offset);

  return pkt_len + 4;
}

/*
 * We need 4 bytes for the length ...
 */
#define DPP_TCP_HEADER_LEN 4
static int
dissect_wifi_dpp_tcp_pdus(tvbuff_t *tvb, packet_info *pinfo _U_,
  proto_tree *tree, void *data _U_)
{
  if (!tvb_bytes_exist(tvb, 0, DPP_TCP_HEADER_LEN))
    return 0;

  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, DPP_TCP_HEADER_LEN,
                   get_wifi_dpp_tcp_len, dissect_wifi_dpp_tcp_pdu, data);
  return tvb_reported_length(tvb);
}

void
proto_register_wifi_dpp(void)
{
  static module_t *wifi_dpp_module;
  static hf_register_info hf[] = {
    { &hf_wifi_dpp_status,
      { "Wi-Fi DPP Status", "dpp.status",
        FT_UINT8, BASE_HEX, VALS(dpp_status_codes), 0x0, NULL, HFILL }},
    { &hf_wifi_dpp_init_hash,
      { "Wi-Fi DPP Initiator Hash", "dpp.init.hash",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_wifi_dpp_resp_hash,
      { "Wi-Fi DPP Responder Hash", "dpp.resp.hash",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_wifi_dpp_key_x,
      { "Wi-Fi DPP Key X value", "dpp.key.x",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_wifi_dpp_key_y,
      { "Wi-Fi DPP Key Y value", "dpp.key.y",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_wifi_dpp_trans_id,
      { "Wi-Fi DPP Transaction ID", "dpp.trans_id",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_wifi_dpp_finite_cyclic_group,
      { "Wi-Fi DPP Finite Cyclic Group", "dpp.finite_cyclic_group",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_wifi_dpp_capabilities,
      { "Wi-Fi DPP Capabilities", "dpp.capabilities",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_wifi_dpp_code_identifier,
      { "Wi-Fi DPP Code Identifier", "dpp.code_identifier",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_wifi_dpp_enc_key_attribute,
      { "Wi-Fi DPP Encrypted Key Attribute", "dpp.pkex.enckey",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_wifi_dpp_primary_wrapped_data,
      { "Wi-Fi DPP Primary Wrapped Data", "dpp.primary.wrapped_data",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_wifi_dpp_connector_attr,
      { "Wi-Fi DPP Connector Attribute", "dpp.connector_data",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_wifi_dpp_initiator_nonce,
      { "Wi-Fi DPP Initiator Nonce", "dpp.initiator_nonce",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_wifi_dpp_operating_class,
      { "Operating Class", "dpp.operating_class",
       FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_wifi_dpp_channel,
      { "Channel", "dpp.channel",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_wifi_dpp_protocol_version,
      { "Protocol Version", "dpp.protocol_version",
        FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(dpp_protocol_version_rvals),
        0x0, NULL, HFILL }},
    { &hf_wifi_dpp_a_nonce,
      { "A-NONCE", "dpp.a_nonce",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_wifi_dpp_e_prime_id,
      { "E'-id", "dpp.e_prime_id",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_wifi_dpp_ie_attr_id,
      { "Wi-Fi DPP IE Attribute ID", "dpp.ie.attr_id",
        FT_UINT16, BASE_HEX, VALS(dpp_ie_attr_ids), 0x0, NULL, HFILL }},
    { &hf_wifi_dpp_ie_attr_len,
      { "Wi-Fi DPP IE Attribute Len", "dpp.ie.attr_len",
       FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_wifi_dpp_ie_generic,
      { "Wi-Fi DPP IE generic", "dpp.ie.generic",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_wifi_dpp_action_subtype,
      { "Wi-Fi DPP Action Subtype", "dpp.action.subtype",
        FT_UINT8, BASE_DEC, VALS(dpp_action_subtypes), 0x0, NULL, HFILL }},
    { &hf_wifi_dpp_action_dialog_token,
      { "Wi-Fi DPP Action Dialog Token", "dpp.action.dialog_token",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_wifi_dpp_crypto_suite,
      { "Wi-Fi DPP Cryptographic Suite", "dpp.public_action.crypto_suite",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_wifi_dpp_public_action_subtype,
      { "Wi-Fi DPP Public Action Subtype", "dpp.public_action.subtype",
        FT_UINT8, BASE_DEC, VALS(dpp_public_action_subtypes), 0x0, NULL, HFILL }},
    { &hf_wifi_dpp_unknown_anqp_item,
      { "Wi-fi DPP Unknown ANQP Item", "dpp.unknown_anqp_item",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_wifi_dpp_tcp_pdu_length,
      { "DPP TCP PDU length", "dpp.tcp.length",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_wifi_dpp_tcp_pdu_action_field,
      { "DPP TCP PDU Action type", "dpp.tcp.action_type",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_wifi_dpp_tcp_oui,
      { "DPP TCP PDU OUI", "dpp.tcp.oui",
        FT_UINT24, BASE_OUI, NULL, 0x0, NULL, HFILL }},

    { &hf_wifi_dpp_tcp_oui_type,
      { "DPP TCP PDU OUI type", "dpp.tcp.oui_type",
        FT_UINT8, BASE_DEC, VALS(wfa_subtype_vals), 0, NULL, HFILL }},

    { &hf_wifi_dpp_tcp_dialog_token,
      { "DPP TCP PDU Dialog Token", "dpp.tcp.dialog_token",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_wifi_dpp_tcp_adv_proto_elt,
      { "DPP TCP PDU Advertisement Protocol Element",
        "dpp.tcp.adv_proto_elt",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_wifi_dpp_tcp_vendor_specific,
      { "DPP TCP PDU Vendor Specific tag", "dpp.tcp.vendor_spec_tag",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

    { &hf_wifi_dpp_tcp_vendor_spec_len,
      { "DPP TCP PDU Vendor Specific len", "dpp.tcp.vendor_spec_len",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_wifi_dpp_tcp_config,
      { "DPP TCP PDU Configuration", "dpp.tcp.config",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_wifi_dpp_tcp_query_req_len,
      { "DPP TCP PDU Query Req len", "dpp.tcp.query_req_len",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_wifi_dpp_gas_query_resp_frag_id,
      { "DPP TCP PDU GAS Query Response Fragment ID",
        "dpp.tp.query_resp_frag_id",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_wifi_dpp_tcp_status_code,
      { "DPP TCP PDU Status Code", "dpp.tcp.status_code",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_wifi_dpp_tcp_comeback_delay,
      { "DPP TCP PDU Comeback Delay", "dpp.tcp.comeback_delay",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_wifi_dpp_tcp_query_resp_len,
      { "DPP TCP PDU Query Resp Len", "dpp.tcp.query_resp_len",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
  };
  static gint *ett[] = {
    &ett_wifi_dpp_ie_generic,
    &ett_wifi_dpp_attributes,
    &ett_wifi_dpp_pa,
    &ett_wifi_dpp_attribute,
    &ett_wifi_dpp_attr_header,
    &ett_wifi_dpp_attr_value,
  };

  proto_wifi_dpp = proto_register_protocol("Wi-Fi Device Provisioning Protocol", "Wi-Fi DPP", "dpp");
  proto_register_field_array(proto_wifi_dpp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register the preferred TCP port? Is there one? */
  wifi_dpp_module = prefs_register_protocol(proto_wifi_dpp, NULL);
  prefs_register_uint_preference(wifi_dpp_module, "tcp.port", "DPP TCP Port",
                                 "The TCP port DPP over TCP uses",
                                 10, &wifi_dpp_tcp_port);
}

void
proto_reg_handoff_wifi_dpp(void)
{
  static gboolean initialized = FALSE;
  static dissector_handle_t wifi_dpp_tcp_handle;
  static int current_port;

  dissector_add_uint("wlan.action.wifi_alliance.subtype", WFA_SUBTYPE_DPP, create_dissector_handle(dissect_wifi_dpp_action, proto_wifi_dpp));
  dissector_add_uint("wlan.anqp.wifi_alliance.subtype", WFA_SUBTYPE_DPP, create_dissector_handle(dissect_wifi_dpp, proto_wifi_dpp));
  dissector_add_uint("wlan.ie.wifi_alliance.subtype", WFA_SUBTYPE_DPP, create_dissector_handle(dissect_wifi_dpp_ie, proto_wifi_dpp));
  dissector_add_uint("wlan.pa.wifi_alliance.subtype", WFA_SUBTYPE_DPP, create_dissector_handle(dissect_wifi_dpp_public_action, proto_wifi_dpp));

  /*
   * Register the TCP port
   */
  if (!initialized) {
    wifi_dpp_tcp_handle = create_dissector_handle(dissect_wifi_dpp_tcp_pdus,
                                                  proto_wifi_dpp);
    initialized = TRUE;
  } else {
    dissector_delete_uint("tcp.port", current_port, wifi_dpp_tcp_handle);
  }

  current_port = wifi_dpp_tcp_port;
  dissector_add_uint("tcp.port", current_port, wifi_dpp_tcp_handle);
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
