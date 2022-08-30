/* packet-teap.c
 * Routines for TEAP (Tunnel Extensible Authentication Protocol)
 * RFC 7170
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
#include <epan/proto_data.h>

void proto_register_teap(void);
void proto_reg_handoff_teap(void);

static int proto_teap = -1;

static gint ett_teap = -1;
static gint ett_teap_tlv = -1;
static gint ett_pac_attr_tlv = -1;

static expert_field ei_teap_bad_length = EI_INIT;

static dissector_handle_t teap_handle;

static dissector_handle_t eap_handle;

/*
  From RFC7170, pg 27

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |M|R|            TLV Type       |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                              Value...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#define TEAP_TLV_MANDATORY 0x8000
#define TEAP_TLV_RESERVED  0x4000
#define TEAP_TLV_TYPE      0x3FFF

#define TEAP_CRYPTO_FLAGS    0xF0
#define TEAP_CRYPTO_SUBTYPE  0x0F

#define TEAP_UNASSIGNED              0
#define TEAP_AUTHORITY_ID            1
#define TEAP_IDENTITY                2
#define TEAP_RESULT                  3
#define TEAP_NAK                     4
#define TEAP_ERROR                   5
#define TEAP_CHANNEL_BINDING         6
#define TEAP_VENDOR_SPECIFIC         7
#define TEAP_REQUEST_ACTION          8
#define TEAP_EAP_PAYLOAD             9
#define TEAP_INTERMEDIATE_RESULT     10
#define TEAP_PAC                     11
#define TEAP_CRYPTO_BINDING          12
#define TEAP_BASIC_PWD_AUTH_REQUEST  13
#define TEAP_BASIC_PWD_AUTH_RESPONSE 14
#define TEAP_PKCS7                   15
#define TEAP_PKCS10                  16
#define TEAP_TRUSTED_SERVER_ROOT     17

static const value_string teap_tlv_type_vals[] = {
   { TEAP_UNASSIGNED,              "Unassigned" },
   { TEAP_AUTHORITY_ID,            "Authority-ID" },
   { TEAP_IDENTITY,                "Identity-Type" },
   { TEAP_RESULT,                  "Result" },
   { TEAP_NAK,                     "NAK" },
   { TEAP_ERROR,                   "Error" },
   { TEAP_CHANNEL_BINDING,         "Channel-Binding" },
   { TEAP_VENDOR_SPECIFIC,         "Vendor-Specific" },
   { TEAP_REQUEST_ACTION,          "Request-Action" },
   { TEAP_EAP_PAYLOAD,             "EAP-Payload" },
   { TEAP_INTERMEDIATE_RESULT,     "Intermediate-Result" },
   { TEAP_PAC,                     "PAC" },
   { TEAP_CRYPTO_BINDING,          "Crypto-Binding" },
   { TEAP_BASIC_PWD_AUTH_REQUEST,  "Basic-Password-Auth-Req" },
   { TEAP_BASIC_PWD_AUTH_RESPONSE, "Basic-Password-Auth-Resp" },
   { TEAP_PKCS7,                   "PKCS#7" },
   { TEAP_PKCS10,                  "PKCS#10" },
   { TEAP_TRUSTED_SERVER_ROOT,     "Trusted-Server-Root" },
   { 0,                            NULL }
 };

static const value_string teap_identity_vals[] = {
   { 1, "User" },
   { 2, "Machine" },
   { 0, NULL }
 };

static const value_string teap_status_vals[] = {
   { 1, "Success" },
   { 2, "Failure" },
   { 0, NULL }
 };

static const value_string teap_request_action_status_vals[] = {
   { 1, "Success" },
   { 2, "Failure" },
   { 0, NULL }
 };

static const value_string teap_request_action_action_vals[] = {
   { 1, "Process-TLV" },
   { 2, "Negotiate-EAP" },
   { 0, NULL }
 };

 #define FLAG_EMSK_PRESENT 1
 #define FLAG_MSK_PRESENT  2
 #define FLAG_BOTH_PRESENT 3

static const value_string teap_crypto_flags_vals[] = {
   { FLAG_EMSK_PRESENT, "EMSK Compound MAC is present" },
   { FLAG_MSK_PRESENT,  "MSK Compound MAC is present" },
   { FLAG_BOTH_PRESENT, "Both EMSK and MSK Compound MAC are present" },
   { 0, NULL }
};

static const value_string teap_crypto_subtype_vals[] = {
   { 0, "Binding Request" },
   { 1, "Binding Response" },
   { 0, NULL }
};

static const value_string teap_error_code_vals[] = {
   { 1,    "User account expires soon" },
   { 2,    "User account credential expires soon" },
   { 3,    "User account authorizations change soon" },
   { 4,    "Clock skew detected" },
   { 5,    "Contact administrator" },
   { 6,    "User account credentials change required" },
   { 1001, "Inner Method Error" },
   { 1002, "Unspecified authentication infrastructure problem" },
   { 1003, "Unspecified authentication failure" },
   { 1004, "Unspecified authorization failure" },
   { 1005, "User account credentials unavailable" },
   { 1006, "User account expired" },
   { 1007, "User account locked: try again later" },
   { 1008, "User account locked: admin intervention required" },
   { 1009, "Authentication infrastructure unavailable" },
   { 1010, "Authentication infrastructure not trusted" },
   { 1011, "Clock skew too great" },
   { 1012, "Invalid inner realm" },
   { 1013, "Token out of sync: administrator intervention required" },
   { 1014, "Token out of sync: PIN change required" },
   { 1015, "Token revoked" },
   { 1016, "Tokens exhausted" },
   { 1017, "Challenge expired" },
   { 1018, "Challenge algorithm mismatch" },
   { 1019, "Client certificate not supplied" },
   { 1020, "Client certificate rejected" },
   { 1021, "Realm mismatch between inner and outer identity" },
   { 1022, "Unsupported Algorithm In Certificate Signing Request" },
   { 1023, "Unsupported Extension In Certificate Signing Request" },
   { 1024, "Bad Identity In Certificate Signing Request" },
   { 1025, "Bad Certificate Signing Request" },
   { 1026, "Internal CA Error" },
   { 1027, "General PKI Error" },
   { 1028, "Inner method's channel-binding data required but not supplied" },
   { 1029, "Inner method's channel-binding data did not include required information" },
   { 1030, "Inner method's channel binding failed" },
   { 1031, "User account credentials incorrect [USAGE NOT RECOMMENDED]" },
   { 2001, "Tunnel Compromise Error" },
   { 2002, "Unexpected TLVs Exchanged" },
   { 0, NULL }
};

#define PAC_KEY       1
#define PAC_OPAQUE    2
#define PAC_LIFETIME  3
#define PAC_A_ID      4
#define PAC_I_ID      5
#define PAC_RESERVED  6
#define PAC_A_ID_INFO 7
#define PAC_ACK       8
#define PAC_INFO      9
#define PAC_TYPE      10

static const value_string pac_attr_type_vals[] = {
   { PAC_KEY,       "PAC-Key" },
   { PAC_OPAQUE,    "PAC-Opaque" },
   { PAC_LIFETIME,  "PAC-Lifetime" },
   { PAC_A_ID,      "A-ID" },
   { PAC_I_ID,      "I-ID" },
   { PAC_RESERVED,  "Reserved" },
   { PAC_A_ID_INFO, "A-ID-Info" },
   { PAC_ACK,       "PAC-Acknowledgement" },
   { PAC_INFO,      "PAC-Info" },
   { PAC_TYPE,      "PAC-Type" },
   { 0,             NULL }
};

static const value_string pac_result_vals[] = {
   { 1, "Success" },
   { 2, "Failure" },
   { 0, NULL }
 };

static const value_string pac_type_vals[] = {
   { 1, "Tunnel PAC" },
   { 0, NULL }
 };

static int hf_teap_tlv_mandatory = -1;
static int hf_teap_tlv_reserved = -1;
static int hf_teap_tlv_type = -1;
static int hf_teap_tlv_len = -1;
static int hf_teap_tlv_val = -1;
static int hf_teap_auth_id = -1;
static int hf_teap_identity = -1;
static int hf_teap_status = -1;
static int hf_teap_vendor_id = -1;
static int hf_teap_request_action_status = -1;
static int hf_teap_request_action_action = -1;
static int hf_teap_crypto_reserved = -1;
static int hf_teap_crypto_version = -1;
static int hf_teap_crypto_rcv_version = -1;
static int hf_teap_crypto_flags = -1;
static int hf_teap_crypto_subtype = -1;
static int hf_teap_crypto_nonce = -1;
static int hf_teap_crypto_emsk = -1;
static int hf_teap_crypto_msk = -1;
static int hf_teap_nak_type = -1;
static int hf_teap_error_code = -1;
static int hf_teap_prompt = -1;
static int hf_teap_user_len = -1;
static int hf_teap_username = -1;
static int hf_teap_pass_len = -1;
static int hf_teap_password = -1;

static int hf_pac_attr_type = -1;
static int hf_pac_attr_pac_key = -1;
static int hf_pac_attr_pac_opaque = -1;
static int hf_pac_attr_pac_lifetime = -1;
static int hf_pac_attr_pac_a_id = -1;
static int hf_pac_attr_pac_i_id = -1;
static int hf_pac_attr_pac_reserved = -1;
static int hf_pac_attr_pac_a_id_info = -1;
static int hf_pac_attr_pac_result = -1;
static int hf_pac_attr_pac_type = -1;
static int hf_pac_attr_val = -1;

static int
dissect_teap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);

static int
dissect_teap_tlv_pac(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint16 len);

static int
dissect_pac_attr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  guint16 type;
  guint16 len;
  int start_offset = offset;

  type = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
  len = tvb_get_guint16(tvb, offset + 2, ENC_BIG_ENDIAN);

  proto_tree_add_item(tree, hf_pac_attr_type, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_teap_tlv_len, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  switch (type) {
    case PAC_KEY:
      proto_tree_add_item(tree, hf_pac_attr_pac_key, tvb, offset, len, ENC_NA);
      offset += len;
      break;

    case PAC_OPAQUE:
      proto_tree_add_item(tree, hf_pac_attr_pac_opaque, tvb, offset, len, ENC_NA);
      offset += len;
      break;

    case PAC_LIFETIME:
      proto_tree_add_item(tree, hf_pac_attr_pac_lifetime, tvb, offset, 4, ENC_NA);
      offset += 4;
      break;

    case PAC_A_ID:
      proto_tree_add_item(tree, hf_pac_attr_pac_a_id, tvb, offset, len, ENC_ASCII | ENC_NA);
      offset += len;
      break;

    case PAC_I_ID:
      proto_tree_add_item(tree, hf_pac_attr_pac_i_id, tvb, offset, len, ENC_ASCII | ENC_NA);
      offset += len;
      break;

    case PAC_RESERVED:
      proto_tree_add_item(tree, hf_pac_attr_pac_reserved, tvb, offset, len, ENC_NA);
      offset += len;
      break;

    case PAC_A_ID_INFO:
      proto_tree_add_item(tree, hf_pac_attr_pac_a_id_info, tvb, offset, len, ENC_ASCII | ENC_NA);
      offset += len;
      break;

    case PAC_ACK:
      proto_tree_add_item(tree, hf_pac_attr_pac_result, tvb, offset, len, ENC_NA);
      offset += len;
      break;

    case PAC_INFO:
      offset += dissect_teap_tlv_pac(tvb, pinfo, tree, offset, len);
      break;

    case PAC_TYPE:
      proto_tree_add_item(tree, hf_pac_attr_pac_type, tvb, offset, len, ENC_NA);
      offset += len;
      break;

    default:
      proto_tree_add_item(tree, hf_pac_attr_val, tvb, offset, len, ENC_NA);
      offset += len;
      break;
  }
  return offset - start_offset;
}

static int
dissect_teap_tlv_pac(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint16 len)
{
  int start_offset = offset;

  while (offset - start_offset < len) {
    offset += dissect_pac_attr(tvb, pinfo, tree, offset);
  }
  return offset - start_offset;
}

static int
dissect_teap_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, gboolean top)
{
  int start_offset = offset;
  guint16 type;
  guint16 len;
  proto_tree *tlv_tree;
  proto_tree *ti_len;
  tvbuff_t *next_tvb;

  type = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN) & TEAP_TLV_TYPE;
  len = tvb_get_guint16(tvb, offset + 2, ENC_BIG_ENDIAN);

  tlv_tree = proto_tree_add_subtree_format(tree, tvb, offset, 4 + len,
      ett_teap_tlv, NULL, "TLV %s (%u): ",
      val_to_str_const(type, teap_tlv_type_vals, "Unknown"), type);

  proto_tree_add_item(tlv_tree, hf_teap_tlv_mandatory, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_tree, hf_teap_tlv_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tlv_tree, hf_teap_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tlv_tree, hf_teap_tlv_len, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  if (top) {
    col_add_str(pinfo->cinfo, COL_INFO,
        val_to_str(type, teap_tlv_type_vals, "Unknown TLV (0x%02X)"));
  }
  switch (type) {
    case TEAP_AUTHORITY_ID:
      proto_tree_add_item(tlv_tree, hf_teap_auth_id, tvb, offset, len, ENC_NA);
      offset += len;
      break;

    case TEAP_IDENTITY:
      proto_tree_add_item(tlv_tree, hf_teap_identity, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += len;
      break;

    case TEAP_RESULT:
      proto_tree_add_item(tlv_tree, hf_teap_status, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += len;
      break;

    case TEAP_NAK:
      proto_tree_add_item(tlv_tree, hf_teap_vendor_id, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(tlv_tree, hf_teap_nak_type, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;

      if (len > 6) {
        next_tvb = tvb_new_subset_length(tvb, offset, len - 6);
        offset += dissect_teap(next_tvb, pinfo, tlv_tree, NULL);
      }

      break;

    case TEAP_ERROR:
      proto_tree_add_item(tlv_tree, hf_teap_error_code, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += len;
      break;

    case TEAP_VENDOR_SPECIFIC:
      proto_tree_add_item(tlv_tree, hf_teap_vendor_id, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += len;
      break;

    case TEAP_REQUEST_ACTION:
      proto_tree_add_item(tlv_tree, hf_teap_request_action_status, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
      proto_tree_add_item(tlv_tree, hf_teap_request_action_action, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;

      if (len > 2) {
        next_tvb = tvb_new_subset_length(tvb, offset, len - 2);
        offset += dissect_teap(next_tvb, pinfo, tlv_tree, NULL);
      }

      break;

    case TEAP_EAP_PAYLOAD:
    {
      guint16 eaplen = tvb_get_guint16(tvb, offset + 2, ENC_BIG_ENDIAN);

      next_tvb = tvb_new_subset_length(tvb, offset, eaplen);
      call_dissector(eap_handle, next_tvb, pinfo, tlv_tree);
      offset += eaplen;

      if (len > eaplen) {
        next_tvb = tvb_new_subset_length(tvb, offset, len - eaplen);
        offset += dissect_teap(next_tvb, pinfo, tlv_tree, NULL);
      }
    }
    break;

    case TEAP_INTERMEDIATE_RESULT:
      proto_tree_add_item(tlv_tree, hf_teap_status, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;

      if (len > 2) {
        next_tvb = tvb_new_subset_length(tvb, offset, len - 2);
        offset += dissect_teap(next_tvb, pinfo, tlv_tree, NULL);
      }

      break;

    case TEAP_PAC:
      offset += dissect_teap_tlv_pac(tvb, pinfo, tlv_tree, offset, len);
      break;

    case TEAP_CRYPTO_BINDING:
    {
      guint8 flags;
      proto_tree_add_item(tlv_tree, hf_teap_crypto_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
      proto_tree_add_item(tlv_tree, hf_teap_crypto_version, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
      proto_tree_add_item(tlv_tree, hf_teap_crypto_rcv_version, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
      flags = (tvb_get_guint8(tvb, offset) & TEAP_CRYPTO_FLAGS) >> 4;
      proto_tree_add_item(tlv_tree, hf_teap_crypto_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tlv_tree, hf_teap_crypto_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
      proto_tree_add_item(tlv_tree, hf_teap_crypto_nonce, tvb, offset, 32, ENC_NA);
      offset += 32;
      if (flags == FLAG_EMSK_PRESENT || flags == FLAG_BOTH_PRESENT) {
        proto_tree_add_item(tlv_tree, hf_teap_crypto_emsk, tvb, offset, 20, ENC_NA);
      }
      offset += 20;
      if (flags == FLAG_MSK_PRESENT || flags == FLAG_BOTH_PRESENT) {
        proto_tree_add_item(tlv_tree, hf_teap_crypto_msk, tvb, offset, 20, ENC_NA);
      }
      offset += 20;
    }
    break;

    case TEAP_BASIC_PWD_AUTH_REQUEST:
      if (len > 0) {
        proto_tree_add_item(tlv_tree, hf_teap_prompt, tvb, offset, len, ENC_ASCII | ENC_NA);
        offset += len;
      }
      break;

    case TEAP_BASIC_PWD_AUTH_RESPONSE:
    {
      guint8 auth_len;
      auth_len = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(tlv_tree, hf_teap_user_len, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
      proto_tree_add_item(tlv_tree, hf_teap_username, tvb, offset, auth_len, ENC_ASCII | ENC_NA);
      offset += auth_len;

      auth_len = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(tlv_tree, hf_teap_pass_len, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
      proto_tree_add_item(tlv_tree, hf_teap_password, tvb, offset, auth_len, ENC_ASCII | ENC_NA);
      offset += auth_len;
    }
    break;

    case TEAP_CHANNEL_BINDING:
    case TEAP_TRUSTED_SERVER_ROOT:
    case TEAP_PKCS7:
    case TEAP_PKCS10:
    default:
      ti_len = proto_tree_add_item(tlv_tree, hf_teap_tlv_val, tvb, offset, len, ENC_NA);
      if ((guint)len + 4 > tvb_reported_length(tvb)) {
        expert_add_info(pinfo, ti_len, &ei_teap_bad_length);
      }
      offset += len;
      break;
  }

  return offset - start_offset;
}

static int
dissect_teap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_tree *ti;
  proto_tree *teap_tree;
  int offset = 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "TEAP");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_teap, tvb, 0, tvb_captured_length(tvb), ENC_NA);
  teap_tree = proto_item_add_subtree(ti, ett_teap);

  while (offset < (int)tvb_captured_length(tvb)) {
    offset += dissect_teap_tlv(tvb, pinfo, teap_tree, offset, offset == 0);
  }

  return tvb_captured_length(tvb);
}

void
proto_register_teap(void)
{
  static hf_register_info hf[] = {
    { &hf_teap_tlv_mandatory, {
      "Mandatory", "teap.tlv.mandatory",
      FT_BOOLEAN, 16, NULL, TEAP_TLV_MANDATORY,
      NULL, HFILL }},

    { &hf_teap_tlv_reserved, {
      "Reserved", "teap.tlv.reserved",
      FT_UINT16, BASE_DEC, NULL, TEAP_TLV_RESERVED,
      NULL, HFILL }},

     { &hf_teap_tlv_type, {
      "Type", "teap.tlv.type",
      FT_UINT16, BASE_DEC, VALS(teap_tlv_type_vals), TEAP_TLV_TYPE,
      NULL, HFILL }},

     { &hf_teap_tlv_len, {
      "Length", "teap.tlv.len",
      FT_UINT16, BASE_DEC, NULL, 0x00,
      NULL, HFILL }},

     { &hf_teap_auth_id, {
      "ID", "teap.authority-id",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

     { &hf_teap_identity, {
      "Identity", "teap.identity",
      FT_UINT16, BASE_DEC, VALS(teap_identity_vals), 0x0,
      NULL, HFILL }},

     { &hf_teap_status, {
      "Status", "teap.status",
      FT_UINT16, BASE_DEC, VALS(teap_status_vals), 0x0,
      NULL, HFILL }},

     { &hf_teap_vendor_id, {
      "Vendor-Id", "teap.vendor-id",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      NULL, HFILL }},

     { &hf_teap_crypto_reserved, {
      "Reserved", "teap.crypto.reserved",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

     { &hf_teap_crypto_version, {
      "Version", "teap.crypto.version",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

     { &hf_teap_crypto_rcv_version, {
      "Received Version", "teap.crypto.received-version",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

     { &hf_teap_crypto_flags, {
      "Flags", "teap.crypto.flags",
      FT_UINT8, BASE_DEC, VALS(teap_crypto_flags_vals), TEAP_CRYPTO_FLAGS,
      NULL, HFILL }},

     { &hf_teap_crypto_subtype, {
      "Subtype", "teap.crypto.subtype",
      FT_UINT8, BASE_DEC, VALS(teap_crypto_subtype_vals), TEAP_CRYPTO_SUBTYPE,
      NULL, HFILL }},

     { &hf_teap_crypto_nonce, {
      "Nonce", "teap.crypto.nonce",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

     { &hf_teap_crypto_emsk, {
      "EMSK Compound MAC", "teap.crypto.emsk",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

     { &hf_teap_crypto_msk, {
      "MSK Compound MAC", "teap.crypto.msk",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

     { &hf_teap_nak_type, {
      "NAK-Type", "teap.nak-type",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL }},

     { &hf_teap_error_code, {
      "Error-Code", "teap.error-code",
      FT_UINT32, BASE_DEC, VALS(teap_error_code_vals), 0x0,
      NULL, HFILL }},

     { &hf_teap_request_action_action, {
      "Action", "teap.request-action.action",
      FT_UINT8, BASE_DEC, VALS(teap_request_action_action_vals), 0x0,
      NULL, HFILL }},

     { &hf_teap_request_action_status, {
      "Status", "teap.request-action.status",
      FT_UINT8, BASE_DEC, VALS(teap_request_action_status_vals), 0x0,
      NULL, HFILL }},

     { &hf_teap_prompt, {
      "Prompt", "teap.prompt",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

     { &hf_teap_user_len, {
      "Userlen", "teap.user_len",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

     { &hf_teap_username, {
      "Username", "teap.username",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

     { &hf_teap_pass_len, {
      "Passlen", "teap.pass_len",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

     { &hf_teap_password, {
      "Password", "teap.password",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

     { &hf_teap_tlv_val, {
      "Value", "teap.tlv.val",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

     { &hf_pac_attr_type, {
      "Type", "teap.pac.type",
      FT_UINT16, BASE_DEC, VALS(pac_attr_type_vals), 0x0,
      NULL, HFILL }},

     { &hf_pac_attr_pac_key, {
      "Key", "teap.pac.key",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

     { &hf_pac_attr_pac_opaque, {
      "Opaque", "teap.pac.opaque",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

     { &hf_pac_attr_pac_lifetime, {
      "Lifetime", "teap.pac.lifetime",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

     { &hf_pac_attr_pac_a_id, {
      "A-ID", "teap.pac.a-id",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

     { &hf_pac_attr_pac_i_id, {
      "I-ID", "teap.pac.i-id",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

     { &hf_pac_attr_pac_reserved, {
      "Reserved", "teap.pac.reserved",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

     { &hf_pac_attr_pac_a_id_info, {
      "A-ID-Info", "teap.pac.a-id-info",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

     { &hf_pac_attr_pac_result, {
      "Type", "teap.pac.result",
      FT_UINT16, BASE_DEC, VALS(pac_result_vals), 0x0,
      NULL, HFILL }},

     { &hf_pac_attr_pac_type, {
      "Type", "teap.pac.pac-type",
      FT_UINT16, BASE_DEC, VALS(pac_type_vals), 0x0,
      NULL, HFILL }},

     { &hf_pac_attr_val, {
      "Value", "teap.pac.val",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},
  };

  static gint *ett[] = {
    &ett_teap,
    &ett_teap_tlv,
    &ett_pac_attr_tlv,
  };
  static ei_register_info ei[] = {
     { &ei_teap_bad_length, { "teap.bad_length", PI_PROTOCOL, PI_WARN, "Bad length (too large)", EXPFILL }},
  };

  expert_module_t* expert_teap;

  proto_teap = proto_register_protocol("Tunnel Extensible Authentication Protocol",
                                       "TEAP", "teap");
  proto_register_field_array(proto_teap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_teap = expert_register_protocol(proto_teap);
  expert_register_field_array(expert_teap, ei, array_length(ei));

  teap_handle = register_dissector("teap", dissect_teap, proto_teap);
}

void
proto_reg_handoff_teap(void)
{
  eap_handle = find_dissector_add_dependency("eap", proto_teap);
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
