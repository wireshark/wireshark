/* packet-eap.c
 * Routines for EAP Extensible Authentication Protocol dissection
 * RFC 2284, RFC 3748
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/ppptypes.h>
#include <epan/reassemble.h>
#include <epan/eap.h>
#include <epan/expert.h>
#include <epan/proto_data.h>

#include "packet-eapol.h"
#include "packet-wps.h"
#include "packet-e212.h"
#include "packet-tls-utils.h"

void proto_register_eap(void);
void proto_reg_handoff_eap(void);

static int proto_eap = -1;
static int hf_eap_code = -1;
static int hf_eap_identifier = -1;
static int hf_eap_len = -1;
static int hf_eap_type = -1;
static int hf_eap_type_nak = -1;

static int hf_eap_identity = -1;
static int hf_eap_identity_full = -1;
static int hf_eap_identity_actual_len = -1;
static int hf_eap_identity_prefix = -1;
static int hf_eap_identity_type = -1;
static int hf_eap_identity_mcc = -1;
static int hf_eap_identity_mcc_mnc_2digits = -1;
static int hf_eap_identity_mcc_mnc_3digits = -1;
static int hf_eap_identity_padding = -1;

static int hf_eap_notification = -1;

static int hf_eap_md5_value_size = -1;
static int hf_eap_md5_value = -1;
static int hf_eap_md5_extra_data = -1;

static int hf_eap_sim_subtype = -1;
static int hf_eap_sim_reserved = -1;
static int hf_eap_sim_subtype_attribute = -1;
static int hf_eap_sim_subtype_type = -1;
static int hf_eap_sim_subtype_length = -1;
static int hf_eap_sim_notification_type = -1;
static int hf_eap_sim_error_code_type = -1;
static int hf_eap_sim_subtype_value = -1;

static int hf_eap_aka_subtype = -1;
static int hf_eap_aka_reserved = -1;
static int hf_eap_aka_subtype_attribute = -1;
static int hf_eap_aka_subtype_type = -1;
static int hf_eap_aka_subtype_length = -1;
static int hf_eap_aka_notification_type = -1;
static int hf_eap_aka_error_code_type = -1;
static int hf_eap_aka_subtype_value = -1;

static int hf_eap_leap_version = -1;
static int hf_eap_leap_reserved = -1;
static int hf_eap_leap_count = -1;
static int hf_eap_leap_peer_challenge = -1;
static int hf_eap_leap_peer_response = -1;
static int hf_eap_leap_ap_challenge = -1;
static int hf_eap_leap_ap_response = -1;
static int hf_eap_leap_data = -1;
static int hf_eap_leap_name = -1;

static int hf_eap_ms_chap_v2_opcode = -1;
static int hf_eap_ms_chap_v2_id = -1;
static int hf_eap_ms_chap_v2_length = -1;
static int hf_eap_ms_chap_v2_value_size = -1;
static int hf_eap_ms_chap_v2_challenge = -1;
static int hf_eap_ms_chap_v2_name = -1;
static int hf_eap_ms_chap_v2_peer_challenge = -1;
static int hf_eap_ms_chap_v2_reserved = -1;
static int hf_eap_ms_chap_v2_nt_response = -1;
static int hf_eap_ms_chap_v2_flags = -1;
static int hf_eap_ms_chap_v2_response = -1;
static int hf_eap_ms_chap_v2_message = -1;
static int hf_eap_ms_chap_v2_failure_request = -1;
static int hf_eap_ms_chap_v2_data = -1;
static int hf_eap_data = -1;

static gint ett_eap = -1;

static expert_field ei_eap_ms_chap_v2_length = EI_INIT;
static expert_field ei_eap_mitm_attacks = EI_INIT;
static expert_field ei_eap_md5_value_size_overflow = EI_INIT;
static expert_field ei_eap_dictionary_attacks = EI_INIT;
static expert_field ei_eap_identity_invalid = EI_INIT;
static expert_field ei_eap_retransmission = EI_INIT;
static expert_field ei_eap_bad_length = EI_INIT;

static dissector_table_t eap_expanded_type_dissector_table;

static dissector_handle_t eap_handle;

static dissector_handle_t tls_handle;
static dissector_handle_t diameter_avps_handle;
static dissector_handle_t teap_handle;

const value_string eap_code_vals[] = {
  { EAP_REQUEST,  "Request" },
  { EAP_RESPONSE, "Response" },
  { EAP_SUCCESS,  "Success" },
  { EAP_FAILURE,  "Failure" },
  { EAP_INITIATE, "Initiate" }, /* [RFC5296] */
  { EAP_FINISH,   "Finish" },   /* [RFC5296] */
  { 0,            NULL }
};

/*
References:
  1) https://www.iana.org/assignments/ppp-numbers PPP EAP REQUEST/RESPONSE TYPES
  2) https://tools.ietf.org/html/draft-ietf-pppext-rfc2284bis-02
  3) RFC2284
  4) RFC3748
  5) https://www.iana.org/assignments/eap-numbers EAP registry (updated 2011-02-22)
  6) https://tools.ietf.org/html/draft-bersani-eap-synthesis-sharedkeymethods-00
*/

static const value_string eap_type_vals[] = {
    {   1,         "Identity" },
    {   2,         "Notification" },
    {   3,         "Legacy Nak (Response Only)" },
    {   4,         "MD5-Challenge EAP (EAP-MD5-CHALLENGE)" },
    {   5,         "One-Time Password EAP (EAP-OTP)" },
    {   6,         "Generic Token Card EAP (EAP-GTC)" },
    {   7,         "Allocated" },
    {   8,         "Allocated" },
    {   9,         "RSA Public Key Authentication EAP (EAP-RSA-PKA)" },
    {  10,         "DSS Unilateral EAP (EAP-DSS)" },
    {  11,         "KEA EAP (EAP-KEA)" },
    {  12,         "KEA Validate EAP (EAP-KEA-VALIDATE)" },
    {  13,         "TLS EAP (EAP-TLS)" },
    {  14,         "Defender Token EAP (EAP-AXENT)" },
    {  15,         "RSA Security SecurID EAP (EAP-RSA-SECURID)" },
    {  16,         "Arcot Systems EAP (EAP-ARCOT-SYSTEMS)" },
    {  17,         "Cisco Wireless EAP / Lightweight EAP (EAP-LEAP)" },
    {  18,         "GSM Subscriber Identity Modules EAP (EAP-SIM)" },
    {  19,         "Secure Remote Password SHA1 Part 1 EAP (EAP-SRP-SHA1-PART1)" },
    {  20,         "Secure Remote Password SHA1 Part 2 EAP (EAP-SRP-SHA1-PART2)" },
    {  21,         "Tunneled TLS EAP (EAP-TTLS)" },
    {  22,         "Remote Access Service EAP (EAP-RAS)" },
    {  23,         "UMTS Authentication and Key Agreement EAP (EAP-AKA)" },
    {  24,         "3Com Wireless EAP (EAP-3COM-WIRELESS)" },
    {  25,         "Protected EAP (EAP-PEAP)" },
    {  26,         "MS-Authentication EAP (EAP-MS-AUTH)" },
    {  27,         "Mutual Authentication w/Key Exchange EAP (EAP-MAKE)" },
    {  28,         "CRYPTOCard EAP (EAP-CRYPTOCARD)" },
    {  29,         "MS-CHAP-v2 EAP (EAP-MS-CHAP-V2)" },
    {  30,         "DynamID EAP (EAP-DYNAMID)" },
    {  31,         "Rob EAP (EAP-ROB)" },
    {  32,         "Protected One-Time Password EAP (EAP-POTP)" },
    {  33,         "MS-Authentication TLV EAP (EAP-MS-AUTH-TLV)" },
    {  34,         "SentriNET (EAP-SENTRINET)" },
    {  35,         "Actiontec Wireless EAP (EAP-ACTIONTEC-WIRELESS)" },
    {  36,         "Cogent Systems Biometrics Authentication EAP (EAP-COGENT-BIOMETRIC)" },
    {  37,         "AirFortress EAP (EAP-AIRFORTRESS)" },
    {  38,         "HTTP Digest EAP (EAP-HTTP-DIGEST)" },
    {  39,         "SecureSuite EAP (EAP-SECURESUITE)" },
    {  40,         "DeviceConnect EAP (EAP-DEVICECONNECT)" },
    {  41,         "Simple Password Exponential Key Exchange EAP (EAP-SPEKE)" },
    {  42,         "MOBAC EAP (EAP-MOBAC)" },
    {  43,         "Flexible Authentication via Secure Tunneling EAP (EAP-FAST)" },
    {  44,         "ZoneLabs EAP (EAP-ZLXEAP)" },
    {  45,         "Link EAP (EAP-LINK)" },
    {  46,         "Password Authenticated eXchange EAP (EAP-PAX)" },
    {  47,         "Pre-Shared Key EAP (EAP-PSK)" },
    {  48,         "Shared-secret Authentication and Key Establishment EAP (EAP-SAKE)" },
    {  49,         "Internet Key Exchange v2 EAP (EAP-IKEv2)" },
    {  50,         "UMTS Authentication and Key Agreement' EAP (EAP-AKA')" },
    {  51,         "Generalized Pre-Shared Key EAP (EAP-GPSK)" },
    {  52,         "Password EAP (EAP-pwd)" },
    {  53,         "Encrypted Key Exchange v1 EAP (EAP-EKEv1)" },
    {  55,         "Tunneled EAP protocol" },
    { 254,         "Expanded Type" },
    { 255,         "Experimental" },
    { 0,           NULL }
};
value_string_ext eap_type_vals_ext = VALUE_STRING_EXT_INIT(eap_type_vals);

const value_string eap_identity_prefix_vals[] = {
  { 0x00, "Encrypted IMSI" },
  {  '0', "EAP-AKA Permanent" },
  {  '1', "EAP-SIM Permanent" },
  {  '2', "EAP-AKA Pseudonym" },
  {  '3', "EAP-SIM Pseudonym" },
  {  '4', "EAP-AKA Reauth ID" },
  {  '5', "EAP-SIM Reauth ID" },
  {  '6', "EAP-AKA Prime Permanent" },
  {  '7', "EAP-AKA Prime Pseudonym" },
  {  '8', "EAP-AKA Prime Reauth ID" },
  {  'C', "Conservative Peer" },
  {  'a', "Anonymous Identity" },
  { 0, NULL }
};

const value_string eap_sim_subtype_vals[] = {
  { SIM_START,             "Start" },
  { SIM_CHALLENGE,         "Challenge" },
  { SIM_NOTIFICATION,      "Notification" },
  { SIM_RE_AUTHENTICATION, "Re-authentication" },
  { SIM_CLIENT_ERROR,      "Client-Error" },
  { 0, NULL }
};

const value_string eap_aka_subtype_vals[] = {
  { AKA_CHALLENGE,               "AKA-Challenge" },
  { AKA_AUTHENTICATION_REJECT,   "AKA-Authentication-Reject" },
  { AKA_SYNCHRONIZATION_FAILURE, "AKA-Synchronization-Failure" },
  { AKA_IDENTITY,                "AKA-Identity" },
  { AKA_NOTIFICATION,            "Notification" },
  { AKA_REAUTHENTICATION,        "Re-authentication" },
  { AKA_CLIENT_ERROR,            "Client-Error" },
  { 0, NULL }
};

/*
References:
  1) http://www.iana.org/assignments/eapsimaka-numbers/eapsimaka-numbers.xml
  3) RFC4186
  3) RFC4187
  4) RFC5448
  5) 3GPP TS 24.302
*/

#define AT_NOTIFICATION 12
#define AT_IDENTITY 14
#define AT_CLIENT_ERROR_CODE 22

static const value_string eap_sim_aka_attribute_vals[] = {
  {   1, "AT_RAND" },
  {   2, "AT_AUTN" },
  {   3, "AT_RES" },
  {   4, "AT_AUTS" },
  {   6, "AT_PADDING" },
  {   7, "AT_NONCE_MT" },
  {  10, "AT_PERMANENT_ID_REQ" },
  {  11, "AT_MAC" },
  {  12, "AT_NOTIFICATION" },
  {  13, "AT_ANY_ID_REQ" },
  {  14, "AT_IDENTITY" },
  {  15, "AT_VERSION_LIST" },
  {  16, "AT_SELECTED_VERSION" },
  {  17, "AT_FULLAUTH_ID_REQ" },
  {  19, "AT_COUNTER" },
  {  20, "AT_COUNTER_TOO_SMALL" },
  {  21, "AT_NONCE_S" },
  {  22, "AT_CLIENT_ERROR_CODE" },
  {  23, "AT_KDF_INPUT"},
  {  24, "AT_KDF"},
  { 128, "Unassigned" },
  { 129, "AT_IV" },
  { 130, "AT_ENCR_DATA" },
  { 131, "Unassigned" },
  { 132, "AT_NEXT_PSEUDONYM" },
  { 133, "AT_NEXT_REAUTH_ID" },
  { 134, "AT_CHECKCODE" },
  { 135, "AT_RESULT_IND" },
  { 136, "AT_BIDDING" },
  { 137, "AT_IPMS_IND" },
  { 138, "AT_IPMS_RES" },
  { 139, "AT_TRUST_IND" },
  { 140, "AT_SHORT_NAME_FOR_NETWORK" },
  { 141, "AT_FULL_NAME_FOR_NETWORK" },
  { 142, "AT_RQSI_IND" },
  { 143, "AT_RQSI_RES" },
  { 144, "AT_TWAN_CONN_MODE" },
  { 145, "AT_VIRTUAL_NETWORK_ID" },
  { 146, "AT_VIRTUAL_NETWORK_REQ" },
  { 147, "AT_CONNECTIVITY_TYPE" },
  { 148, "AT_HANDOVER_INDICATION" },
  { 149, "AT_HANDOVER_SESSION_ID" },
  { 150, "AT_MN_SERIAL_ID" },
  { 151, "AT_DEVICE_IDENTITY" },
  { 0, NULL }
};
value_string_ext eap_sim_aka_attribute_vals_ext = VALUE_STRING_EXT_INIT(eap_sim_aka_attribute_vals);

static const value_string eap_sim_aka_notification_vals[] = {
  {    0, "General Failure after Authentication" },
  { 1026, "User has been temporarily denied access" },
  { 1031, "User has not subscribed to the requested service" },
  { 8192, "Failure to Terminate the Authentication Exchange" },
  {16384, "General Failure" },
  {32768, "Success" },
  {0, NULL }
};

static const value_string eap_sim_aka_client_error_codes[] = {
  { 0, "Unable to process packet" },
  { 1, "Unsupported version" },
  { 2, "Insufficient number of challenges" },
  { 3, "RANDs are not fresh" },
  { 0, NULL }
};

const value_string eap_ms_chap_v2_opcode_vals[] = {
  { MS_CHAP_V2_CHALLENGE,       "Challenge" },
  { MS_CHAP_V2_RESPONSE,        "Response" },
  { MS_CHAP_V2_SUCCESS,         "Success" },
  { MS_CHAP_V2_FAILURE,         "Failure" },
  { MS_CHAP_V2_CHANGE_PASSWORD, "Change-Password" },
  { 0, NULL }
};

/*
 * State information for EAP-TLS (RFC2716) and Lightweight EAP:
 *
 *  http://www.missl.cs.umd.edu/wireless/ethereal/leap.txt
 *
 * Attach to all conversations:
 *
 *  a sequence number to be handed to "fragment_add_seq()" as
 *  the fragment sequence number - if it's -1, no reassembly
 *  is in progress, but if it's not, it's the sequence number
 *  to use for the current fragment;
 *
 *  a value to be handed to "fragment_add_seq()" as the
 *  reassembly ID - when a reassembly is started, it's set to
 *  the frame number of the current frame, i.e. the frame
 *  that starts the reassembly;
 *
 *  an indication of the current state of LEAP negotiation,
 *  with -1 meaning no LEAP negotiation is in progress.
 *
 * Attach to frames containing fragments of EAP-TLS messages the
 * reassembly ID for those fragments, so we can find the reassembled
 * data after the first pass through the packets.
 *
 * Attach to LEAP frames the state of the LEAP negotiation when the
 * frame was processed, so we can properly dissect
 * the LEAP message after the first pass through the packets.
 *
 * Attach to all conversations both pieces of information, to keep
 * track of EAP-TLS reassembly and the LEAP state machine.
 */

typedef struct {
  int     eap_tls_seq;
  guint32 eap_reass_cookie;
  int     leap_state;
  gint16  last_eap_id_req;  /* Last ID of the request from the authenticator. */
  gint16  last_eap_id_resp; /* Last ID of the response from the peer. */
} conv_state_t;

typedef struct {
  int     info;  /* interpretation depends on EAP message type */
} frame_state_t;

/*********************************************************************
                           EAP-TLS
RFC2716
**********************************************************************/

/*
from RFC2716, pg 17

   Flags

      0 1 2 3 4 5 6 7 8
      +-+-+-+-+-+-+-+-+
      |L M S R R Vers |
      +-+-+-+-+-+-+-+-+

      L = Length included
      M = More fragments
      S = EAP-TLS start
      R = Reserved
      Vers = PEAP version (Reserved for TLS and TTLS)
*/

#define EAP_TLS_FLAG_L 0x80 /* Length included */
#define EAP_TLS_FLAG_M 0x40 /* More fragments  */
#define EAP_TLS_FLAG_S 0x20 /* EAP-TLS start   */

#define EAP_TLS_FLAGS_VERSION 0x07 /* Version mask for PEAP, TTLS, FAST */

/*
 * reassembly of EAP-TLS
 */
static reassembly_table eap_tls_reassembly_table;

static int hf_eap_tls_flags = -1;
static int hf_eap_tls_flag_l = -1;
static int hf_eap_tls_flag_m = -1;
static int hf_eap_tls_flag_s = -1;
static int hf_eap_tls_flags_version = -1;
static int hf_eap_tls_len = -1;
static int hf_eap_tls_fragment  = -1;
static int hf_eap_tls_fragments = -1;
static int hf_eap_tls_fragment_overlap = -1;
static int hf_eap_tls_fragment_overlap_conflict = -1;
static int hf_eap_tls_fragment_multiple_tails = -1;
static int hf_eap_tls_fragment_too_long_fragment = -1;
static int hf_eap_tls_fragment_error = -1;
static int hf_eap_tls_fragment_count = -1;
static int hf_eap_tls_reassembled_length = -1;
static gint ett_eap_tls_fragment  = -1;
static gint ett_eap_tls_fragments = -1;
static gint ett_eap_sim_attr = -1;
static gint ett_eap_aka_attr = -1;
static gint ett_eap_exp_attr = -1;
static gint ett_eap_tls_flags = -1;
static gint ett_identity = -1;

static const fragment_items eap_tls_frag_items = {
  &ett_eap_tls_fragment,
  &ett_eap_tls_fragments,
  &hf_eap_tls_fragments,
  &hf_eap_tls_fragment,
  &hf_eap_tls_fragment_overlap,
  &hf_eap_tls_fragment_overlap_conflict,
  &hf_eap_tls_fragment_multiple_tails,
  &hf_eap_tls_fragment_too_long_fragment,
  &hf_eap_tls_fragment_error,
  &hf_eap_tls_fragment_count,
  NULL,
  &hf_eap_tls_reassembled_length,
  /* Reassembled data field */
  NULL,
  "fragments"
};

/**********************************************************************
 Support for EAP Expanded Type.

 Currently this is limited to WifiProtectedSetup. Maybe we need
 a generic method to support EAP extended types ?
*********************************************************************/
static int   hf_eap_ext_vendor_id   = -1;
static int   hf_eap_ext_vendor_type = -1;

static const value_string eap_ext_vendor_id_vals[] = {
  { WFA_VENDOR_ID, "WFA" },
  { 0, NULL }
};

static const value_string eap_ext_vendor_type_vals[] = {
  { WFA_SIMPLECONFIG_TYPE, "SimpleConfig" },
  { 0, NULL }
};

static void
dissect_exteap(proto_tree *eap_tree, tvbuff_t *tvb, int offset,
               gint size _U_, packet_info* pinfo, guint8 eap_code, guint8 eap_identifier)
{
  tvbuff_t   *next_tvb;
  guint32    vendor_id;
  guint32    vendor_type;
  eap_vendor_context *vendor_context;

  vendor_context = wmem_new(wmem_packet_scope(), eap_vendor_context);

  proto_tree_add_item_ret_uint(eap_tree, hf_eap_ext_vendor_id, tvb, offset, 3, ENC_BIG_ENDIAN, &vendor_id);
  offset += 3;

  proto_tree_add_item_ret_uint(eap_tree, hf_eap_ext_vendor_type, tvb, offset, 4, ENC_BIG_ENDIAN, &vendor_type);
  offset += 4;

  vendor_context->eap_code = eap_code;
  vendor_context->eap_identifier = eap_identifier;
  vendor_context->vendor_id = vendor_id;
  vendor_context->vendor_type = vendor_type;

  next_tvb = tvb_new_subset_remaining(tvb, offset);
  if (!dissector_try_uint_new(eap_expanded_type_dissector_table,
    vendor_id, next_tvb, pinfo, eap_tree,
    FALSE, vendor_context)) {
    call_data_dissector(next_tvb, pinfo, eap_tree);
  }
}
/* *********************************************************************
********************************************************************* */

static gboolean
test_flag(unsigned char flag, unsigned char mask)
{
  return ( ( flag & mask ) != 0 );
}

static void
dissect_eap_mschapv2(proto_tree *eap_tree, tvbuff_t *tvb, packet_info *pinfo, int offset,
                     gint size)
{
  proto_item *item;
  gint        left = size;
  gint        ms_len;
  guint8      value_size;
  guint8      opcode;

  /* OpCode (1 byte), MS-CHAPv2-ID (1 byte), MS-Length (2 bytes), Data */
  opcode = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(eap_tree, hf_eap_ms_chap_v2_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  left   -= 1;
  if (left <= 0)
    return;

  proto_tree_add_item(eap_tree, hf_eap_ms_chap_v2_id, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  left   -= 1;
  if (left <= 0)
    return;

  item = proto_tree_add_item(eap_tree, hf_eap_ms_chap_v2_length, tvb, offset, 2, ENC_BIG_ENDIAN);
  ms_len = tvb_get_ntohs(tvb, offset);
  if (ms_len != size)
    expert_add_info(pinfo, item, &ei_eap_ms_chap_v2_length);
  offset += 2;
  left   -= 2;

  switch (opcode) {
  case MS_CHAP_V2_CHALLENGE:
    if (left <= 0)
      break;
    value_size = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(eap_tree, hf_eap_ms_chap_v2_value_size,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    left   -= 1;
    proto_tree_add_item(eap_tree, hf_eap_ms_chap_v2_challenge,
                        tvb, offset, value_size, ENC_NA);
    offset += value_size;
    left   -= value_size;
    if (left <= 0)
      break;
    proto_tree_add_item(eap_tree, hf_eap_ms_chap_v2_name,
                        tvb, offset, left, ENC_ASCII|ENC_NA);
    break;
  case MS_CHAP_V2_RESPONSE:
    if (left <= 0)
      break;
    value_size = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(eap_tree, hf_eap_ms_chap_v2_value_size,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    left   -= 1;
    if (value_size == 49) {
      proto_tree_add_item(eap_tree, hf_eap_ms_chap_v2_peer_challenge,
                          tvb, offset, 16, ENC_NA);
      offset += 16;
      proto_tree_add_item(eap_tree, hf_eap_ms_chap_v2_reserved,
                          tvb, offset, 8, ENC_NA);
      offset += 8;
      proto_tree_add_item(eap_tree, hf_eap_ms_chap_v2_nt_response,
                         tvb, offset, 24, ENC_NA);
      offset += 24;
      proto_tree_add_item(eap_tree, hf_eap_ms_chap_v2_flags,
                          tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
      left   -= value_size;
    } else {
      proto_tree_add_item(eap_tree, hf_eap_ms_chap_v2_response, tvb, offset, value_size, ENC_NA);
      offset += value_size;
      left   -= value_size;
    }
    if (left <= 0)
      break;
    proto_tree_add_item(eap_tree, hf_eap_ms_chap_v2_name, tvb, offset, left, ENC_ASCII|ENC_NA);
    break;
  case MS_CHAP_V2_SUCCESS:
    if (left <= 0)
      break;
    proto_tree_add_item(eap_tree, hf_eap_ms_chap_v2_message,
                            tvb, offset, left, ENC_ASCII|ENC_NA);
    break;
  case MS_CHAP_V2_FAILURE:
    if (left <= 0)
      break;
    proto_tree_add_item(eap_tree, hf_eap_ms_chap_v2_failure_request,
                            tvb, offset, left, ENC_ASCII|ENC_NA);
    break;
  default:
    proto_tree_add_item(eap_tree, hf_eap_ms_chap_v2_data, tvb, offset, left, ENC_NA);
    break;
  }
}

/* Dissect the WLAN identity */
static gboolean
dissect_eap_identity_wlan(tvbuff_t *tvb, packet_info* pinfo, proto_tree* tree, int offset, gint size)
{
  guint       mnc = 0;
  guint       mcc = 0;
  guint       mcc_mnc = 0;
  proto_tree* eap_identity_tree = NULL;
  guint8      eap_identity_prefix = 0;
  const gchar* eap_identity_value;
  guint8*     identity = NULL;
  gchar**     tokens = NULL;
  gchar**     realm_tokens = NULL;
  guint       ntokens = 0;
  guint       nrealm_tokens = 0;
  gboolean    ret = TRUE;
  int         hf_eap_identity_mcc_mnc;
  proto_item* item;

  identity = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, size, ENC_ASCII);

  /* Split the Identity and the NAI Realm first */
  tokens = g_strsplit_set(identity, "@", -1);

  while(tokens[ntokens])
    ntokens++;

  /* tokens[0] is the identity, tokens[1] is the NAI Realm */
  if (ntokens != 2) {
    ret = FALSE;
    proto_tree_add_item(tree, hf_eap_identity, tvb, offset, size, ENC_ASCII|ENC_NA);
    goto end;
  }

  realm_tokens = g_strsplit_set(tokens[1], ".", -1);

  while(realm_tokens[nrealm_tokens])
    nrealm_tokens++;

  /* The WLAN identity must have the form of
     <imsi>@wlan.mnc<mnc>.mcc<mcc>.3gppnetwork.org
     If not, we don't have a wlan identity
  */
  if (ntokens != 2 || nrealm_tokens != 5 || g_ascii_strncasecmp(realm_tokens[0], "wlan", 4) ||
      g_ascii_strncasecmp(realm_tokens[3], "3gppnetwork", 11) ||
      g_ascii_strncasecmp(realm_tokens[4], "org", 3)) {
    ret = FALSE;
    goto end;
  }

  /* It is very likely that we have a WLAN identity (EAP-AKA/EAP-SIM) */
  /* Go on with the dissection */
  eap_identity_tree = proto_item_add_subtree(tree, ett_identity);
  proto_tree_add_item(eap_identity_tree, hf_eap_identity_prefix, tvb, offset, 1, ENC_NA);
  eap_identity_prefix = tvb_get_guint8(tvb, offset);
  eap_identity_value = try_val_to_str(eap_identity_prefix, eap_identity_prefix_vals);
  item = proto_tree_add_string(eap_identity_tree, hf_eap_identity_type,
    tvb, offset, 1, eap_identity_value ? eap_identity_value : "Unknown");

  switch(eap_identity_prefix) {
    case 0x00: /* Encrypted IMSI */
      proto_tree_add_item(eap_identity_tree, hf_eap_identity_full, tvb, offset + 1, size - 1, ENC_ASCII || ENC_NA);
      proto_tree_add_item(eap_identity_tree, hf_eap_identity, tvb, offset + 1, (guint)strlen(tokens[0]), ENC_ASCII || ENC_NA);
      break;
    case '0': /* EAP-AKA Permanent */
    case '1': /* EAP-SIM Permanent */
    case '6': /* EAP-AKA' Permanent */
      proto_tree_add_item(eap_identity_tree, hf_eap_identity_full, tvb, offset + 1, size - 1, ENC_ASCII || ENC_NA);
      dissect_e212_utf8_imsi(tvb, pinfo, eap_identity_tree, offset + 1, (guint)strlen(tokens[0]) - 1);
      break;
    case '2': /* EAP-AKA Pseudonym */
    case '3': /* EAP-SIM Pseudonym */
    case '7': /* EAP-AKA' Pseudonym */
      proto_tree_add_item(eap_identity_tree, hf_eap_identity_full, tvb, offset + 1, size - 1, ENC_ASCII || ENC_NA);
      proto_tree_add_item(eap_identity_tree, hf_eap_identity, tvb, offset + 1, (guint)strlen(tokens[0]) - 1, ENC_ASCII|ENC_NA);
      break;
    case '4': /* EAP-AKA Reauth ID */
    case '5': /* EAP-SIM Reauth ID */
    case '8': /* EAP-AKA' Reauth ID */
      proto_tree_add_item(eap_identity_tree, hf_eap_identity_full, tvb, offset + 1, size - 1, ENC_ASCII || ENC_NA);
      proto_tree_add_item(eap_identity_tree, hf_eap_identity, tvb, offset + 1, (guint)strlen(tokens[0]) - 1, ENC_ASCII|ENC_NA);
      break;
    case 'C': /* Conservative Peer */
      proto_tree_add_item(eap_identity_tree, hf_eap_identity_full, tvb, offset + 1, size - 1, ENC_ASCII || ENC_NA);
      proto_tree_add_item(eap_identity_tree, hf_eap_identity, tvb, offset + 1, (guint)strlen(tokens[0]) - 1, ENC_ASCII|ENC_NA);
      break;
    case 'a': /* Anonymous User */
      proto_tree_add_item(eap_identity_tree, hf_eap_identity_full, tvb, offset, size, ENC_ASCII || ENC_NA);
      proto_tree_add_item(eap_identity_tree, hf_eap_identity, tvb, offset, (guint)strlen(tokens[0]), ENC_ASCII|ENC_NA);
      break;
    case 'G': /* TODO: 'G' Unknown */
    case 'I': /* TODO: 'I' Unknown */
    default:
      proto_tree_add_item(eap_identity_tree, hf_eap_identity_full, tvb, offset + 1, size - 1, ENC_ASCII || ENC_NA);
      proto_tree_add_item(eap_identity_tree, hf_eap_identity, tvb, offset + 1, (guint)strlen(tokens[0]) - 1, ENC_ASCII|ENC_NA);
      expert_add_info(pinfo, item, &ei_eap_identity_invalid);
  }

  /* EAP identities do not always equate to IMSIs.  We should
   * still add the MCC and MNC values for non-permanent EAP
   * identities. */
  if (!sscanf(realm_tokens[1] + 3, "%u", &mnc) || !sscanf(realm_tokens[2] + 3, "%u", &mcc)) {
    ret = FALSE;
    goto end;
  }

  if (!try_val_to_str_ext(mcc * 100 + mnc, &mcc_mnc_2digits_codes_ext)) {
    /* May have
     * (1) an invalid 2-digit MNC so it won't resolve,
     * (2) an invalid 3-digit MNC so it won't resolve, or
     * (3) a valid 3-digit MNC.
     * For all cases we treat as 3-digit MNC and continue. */
    mcc_mnc = 1000 * mcc + mnc;
    hf_eap_identity_mcc_mnc = hf_eap_identity_mcc_mnc_3digits;
  } else {
    /* We got a 2-digit MNC match */
    mcc_mnc = 100 * mcc + mnc;
    hf_eap_identity_mcc_mnc = hf_eap_identity_mcc_mnc_2digits;
  }

  proto_tree_add_uint(eap_identity_tree, hf_eap_identity_mcc_mnc,
    tvb, offset + (guint)strlen(tokens[0]) + (guint)strlen("@wlan.") +
    (guint)strlen("mnc"), (guint)strlen(realm_tokens[1]) - (guint)strlen("mnc"),
    mcc_mnc);

  proto_tree_add_uint(eap_identity_tree, hf_eap_identity_mcc,
    tvb, offset + (guint)(strlen(tokens[0]) + strlen("@wlan.") +
    strlen(realm_tokens[1]) + 1 + strlen("mcc")),
    (guint)(strlen(realm_tokens[2]) - strlen("mcc")), mcc);
end:
  g_strfreev(tokens);

  return ret;
}

static void
dissect_eap_identity(tvbuff_t *tvb, packet_info* pinfo, proto_tree* tree, int offset, gint size)
{
  /* Try to dissect as WLAN identity */
  if (dissect_eap_identity_wlan(tvb, pinfo, tree, offset, size))
    return;
}

static void
dissect_eap_sim(proto_tree *eap_tree, tvbuff_t *tvb, packet_info* pinfo, int offset, gint size)
{
  gint left = size;

  proto_tree_add_item(eap_tree, hf_eap_sim_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);

  offset += 1;
  left   -= 1;

  if (left < 2)
    return;
  proto_tree_add_item(eap_tree, hf_eap_sim_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  left   -= 2;

  /* Rest of EAP-SIM data is in Type-Len-Value format. */
  while (left >= 2) {
    guint8      type, length;
    gint        padding;
    proto_item *pi;
    proto_tree *attr_tree;
    int         aoffset;
    gint        aleft;

    aoffset = offset;
    type    = tvb_get_guint8(tvb, aoffset);
    length  = tvb_get_guint8(tvb, aoffset + 1);
    aleft   = 4 * length;

    pi = proto_tree_add_none_format(eap_tree, hf_eap_sim_subtype_attribute, tvb,
                                    aoffset, aleft, "EAP-SIM Attribute: %s (%d)",
                                    val_to_str_ext_const(type,
                                                         &eap_sim_aka_attribute_vals_ext,
                                                         "Unknown"),
                                    type);
    attr_tree = proto_item_add_subtree(pi, ett_eap_sim_attr);
    proto_tree_add_uint(attr_tree, hf_eap_sim_subtype_type, tvb, aoffset, 1, type);
    aoffset += 1;
    aleft   -= 1;

    if (aleft <= 0)
      break;
    proto_tree_add_item(attr_tree, hf_eap_sim_subtype_length, tvb, aoffset, 1, ENC_BIG_ENDIAN);
    aoffset += 1;
    aleft   -= 1;

    switch(type){
      case AT_IDENTITY:
        proto_tree_add_item(attr_tree, hf_eap_identity_actual_len, tvb, aoffset, 2, ENC_BIG_ENDIAN);
        dissect_eap_identity(tvb, pinfo, attr_tree, aoffset + 2, tvb_get_ntohs(tvb, aoffset));
        /* If we have a disparity between the EAP-SIM length (minus the
         * first 4 bytes of header fields) * 4 and the Identity Actual
         * Length then it's padding and we need to adjust for that
         * accurately before looking at the next EAP-SIM attribute. */
        padding = ((length - 1) * 4) - tvb_get_ntohs(tvb, aoffset);
        if (padding != 0) {
          proto_tree_add_item(attr_tree, hf_eap_identity_padding, tvb,
            aoffset + 2 + tvb_get_ntohs(tvb, aoffset), padding, ENC_NA);
        }
        break;
      case AT_NOTIFICATION:
        proto_tree_add_item(attr_tree, hf_eap_sim_notification_type, tvb, aoffset, 2, ENC_BIG_ENDIAN);
        break;
      case AT_CLIENT_ERROR_CODE:
        proto_tree_add_item(attr_tree, hf_eap_sim_error_code_type, tvb, aoffset, 2, ENC_BIG_ENDIAN);
        break;
      default:
        proto_tree_add_item(attr_tree, hf_eap_sim_subtype_value, tvb, aoffset, aleft, ENC_NA);
    }

    offset += 4 * length;
    left   -= 4 * length;
  }
}

static void
dissect_eap_aka(proto_tree *eap_tree, tvbuff_t *tvb, packet_info* pinfo, int offset, gint size)
{
  gint left = size;

  proto_tree_add_item(eap_tree, hf_eap_aka_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);

  offset += 1;
  left   -= 1;

  if (left < 2)
    return;
  proto_tree_add_item(eap_tree, hf_eap_aka_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  left   -= 2;

  /* Rest of EAP-AKA data is in Type-Len-Value format. */
  while (left >= 2) {
    guint8       type, length;
    gint         padding;
    proto_item  *pi;
    proto_tree  *attr_tree;
    int          aoffset;
    gint         aleft;

    aoffset = offset;
    type    = tvb_get_guint8(tvb, aoffset);
    length  = tvb_get_guint8(tvb, aoffset + 1);
    aleft   = 4 *  length;

    pi = proto_tree_add_none_format(eap_tree, hf_eap_aka_subtype_attribute, tvb,
                                    aoffset, aleft, "EAP-AKA Attribute: %s (%d)",
                                    val_to_str_ext_const(type,
                                                         &eap_sim_aka_attribute_vals_ext,
                                                         "Unknown"),
                                    type);
    attr_tree = proto_item_add_subtree(pi, ett_eap_aka_attr);
    proto_tree_add_uint(attr_tree, hf_eap_aka_subtype_type, tvb, aoffset, 1, type);
    aoffset += 1;
    aleft   -= 1;

    if (aleft <= 0)
      break;
    proto_tree_add_item(attr_tree, hf_eap_aka_subtype_length, tvb, aoffset, 1, ENC_BIG_ENDIAN);
    aoffset += 1;
    aleft   -= 1;

    switch(type){
      case AT_IDENTITY:
        proto_tree_add_item(attr_tree, hf_eap_identity_actual_len, tvb, aoffset, 2, ENC_BIG_ENDIAN);
        dissect_eap_identity(tvb, pinfo, attr_tree, aoffset + 2, tvb_get_ntohs(tvb, aoffset));
        /* If we have a disparity between the EAP-AKA length (minus the
         * first 4 bytes of header fields) * 4 and the Identity Actual
         * Length then it's padding and we need to adjust for that
         * accurately before looking at the next EAP-AKA attribute. */
        padding = ((length - 1) * 4) - tvb_get_ntohs(tvb, aoffset);
        if (padding != 0) {
          proto_tree_add_item(attr_tree, hf_eap_identity_padding, tvb,
            aoffset + 2 + tvb_get_ntohs(tvb, aoffset), padding, ENC_NA);
        }
        break;
      case AT_NOTIFICATION:
        proto_tree_add_item(attr_tree, hf_eap_aka_notification_type, tvb, aoffset, 2, ENC_BIG_ENDIAN);
        break;
      case AT_CLIENT_ERROR_CODE:
        proto_tree_add_item(attr_tree, hf_eap_aka_error_code_type, tvb, aoffset, 2, ENC_BIG_ENDIAN);
        break;
      default:
        proto_tree_add_item(attr_tree, hf_eap_aka_subtype_value, tvb, aoffset, aleft, ENC_NA);
    }

    offset += 4 * length;
    left   -= 4 * length;
  }
}

static int
dissect_eap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  guint8          eap_code;
  guint8          eap_identifier;
  guint16         eap_len;
  guint8          eap_type;
  gint            len;
  conversation_t *conversation       = NULL;
  conv_state_t   *conversation_state = NULL;
  frame_state_t  *packet_state;
  int             leap_state;
  proto_tree     *ti, *ti_id, *ti_len;
  proto_tree     *eap_tree;
  proto_tree     *eap_tls_flags_tree;
  proto_item     *eap_type_item;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "EAP");
  col_clear(pinfo->cinfo, COL_INFO);

  eap_code = tvb_get_guint8(tvb, 0);
  eap_identifier = tvb_get_guint8(tvb, 1);

  col_add_str(pinfo->cinfo, COL_INFO,
                val_to_str(eap_code, eap_code_vals, "Unknown code (0x%02X)"));

  /*
   * Find a conversation to which we belong; create one if we don't find it.
   *
   * If this is an EAP-Message (RFC 2869) encapsulated in Tunneled TLS EAP
   * (EAP-TTLS), then we should not attempt to create a conversation to detect
   * retransmitted messages, try TLS reassembly and so on.
   *
   * EAP runs over RADIUS (which runs over UDP), EAPOL (802.1X Authentication)
   * or other transports. In case of RADIUS, a single "session" can have consist
   * of two UDP associations (one for authorization, one for accounting) which
   * results in two separate conversations. This wastes memory, but won't affect
   * the use cases below. In case of EAPOL, there are no ports. In any case,
   * force a new conversation when the EAP-Request/Identity message is found.
   *
   * Conversation tracking is required for 1) EAP-TLS reassembly and 2) tracking
   * the stage in the LEAP protocol. In both cases, the protocol starts with an
   * EAP-Request/Identity message which cannot be found in the middle of the
   * session. Use it as a signal to start a new conversation. This ensures that
   * the TLS dissector associates new TLS messages with a unique TLS session.
   */
  if (!proto_is_frame_protocol(pinfo->layers, "tls")) {
    if (PINFO_FD_VISITED(pinfo) || !(eap_code == EAP_REQUEST && tvb_get_guint8(tvb, 4) == EAP_TYPE_ID)) {
      conversation = find_conversation_pinfo(pinfo, 0);
    }
    if (conversation == NULL) {
      conversation = conversation_new(pinfo->num, &pinfo->src,
                                      &pinfo->dst, conversation_pt_to_endpoint_type(pinfo->ptype),
                                      pinfo->srcport, pinfo->destport, 0);
    }

    /*
     * Get the state information for the conversation; attach some if
     * we don't find it.
     */
    conversation_state = (conv_state_t *)conversation_get_proto_data(conversation, proto_eap);
    if (conversation_state == NULL) {
      /*
       * Attach state information to the conversation.
       */
      conversation_state = wmem_new(wmem_file_scope(), conv_state_t);
      conversation_state->eap_tls_seq      = -1;
      conversation_state->eap_reass_cookie =  0;
      conversation_state->leap_state       = -1;
      conversation_state->last_eap_id_req  = -1;
      conversation_state->last_eap_id_resp = -1;
      conversation_add_proto_data(conversation, proto_eap, conversation_state);
    }

    /*
     * Set this now, so that it gets remembered even if we throw an exception
     * later.
     */
    if (eap_code == EAP_FAILURE)
      conversation_state->leap_state = -1;
  }

  eap_len = tvb_get_ntohs(tvb, 2);
  len     = eap_len;

  ti = proto_tree_add_item(tree, proto_eap, tvb, 0, len, ENC_NA);
  eap_tree = proto_item_add_subtree(ti, ett_eap);

  proto_tree_add_item(eap_tree, hf_eap_code, tvb, 0, 1, ENC_BIG_ENDIAN);
  ti_id = proto_tree_add_item(eap_tree, hf_eap_identifier, tvb, 1, 1, ENC_BIG_ENDIAN);
  ti_len = proto_tree_add_item(eap_tree, hf_eap_len, tvb, 2, 2, ENC_BIG_ENDIAN);
  if (len < 4 || (guint)len > tvb_reported_length(tvb)) {
    expert_add_info(pinfo, ti_len, &ei_eap_bad_length);
  }

  /* Detect message retransmissions. Since the protocol proceeds in lock-step,
   * reordering is not expected. If retransmissions somehow occur, we would have
   * to detect retransmissions via a bitmap. */
  gboolean is_duplicate_id = FALSE;
  if (conversation_state) {
    if (eap_code == EAP_REQUEST || eap_code == EAP_RESPONSE ||
        eap_code == EAP_INITIATE || eap_code == EAP_FINISH) {
      if (!PINFO_FD_VISITED(pinfo)) {
        gint16 *last_eap_id = eap_code == EAP_REQUEST || eap_code == EAP_INITIATE ?
          &conversation_state->last_eap_id_req :
          &conversation_state->last_eap_id_resp;
        is_duplicate_id = *last_eap_id == eap_identifier;
        *last_eap_id = eap_identifier;
        if (is_duplicate_id) {
          // Use a dummy value to remember that this packet is a duplicate.
          p_add_proto_data(wmem_file_scope(), pinfo, proto_eap, 1, GINT_TO_POINTER(1));
        }
      } else {
        is_duplicate_id = !!p_get_proto_data(wmem_file_scope(), pinfo, proto_eap, 1);
      }
      if (is_duplicate_id) {
        expert_add_info(pinfo, ti_id, &ei_eap_retransmission);
      }
    }
  }

  switch (eap_code) {

  case EAP_SUCCESS:
  case EAP_FAILURE:
    break;

  case EAP_REQUEST:
  case EAP_RESPONSE:
    eap_type = tvb_get_guint8(tvb, 4);

    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
                      val_to_str_ext(eap_type, &eap_type_vals_ext,
                                     "Unknown type (0x%02x)"));
    eap_type_item = proto_tree_add_item(eap_tree, hf_eap_type, tvb, 4, 1, ENC_BIG_ENDIAN);

    if ((len > 5) || ((len == 5) && (eap_type == EAP_TYPE_ID))) {
      int     offset = 5;
      gint    size   = len - offset;

      switch (eap_type) {
        /*********************************************************************
        **********************************************************************/
      case EAP_TYPE_ID:
        if (size > 0) {
          dissect_eap_identity(tvb, pinfo, eap_tree, offset, size);
        }
        if (conversation_state && !PINFO_FD_VISITED(pinfo)) {
          conversation_state->leap_state  =  0;
          conversation_state->eap_tls_seq = -1;
        }
        break;

        /*********************************************************************
        **********************************************************************/
      case EAP_TYPE_NOTIFY:
        proto_tree_add_item(eap_tree, hf_eap_notification, tvb,
            offset, size, ENC_ASCII|ENC_NA);
        break;

        /*********************************************************************
        **********************************************************************/
      case EAP_TYPE_NAK:
        proto_tree_add_item(eap_tree, hf_eap_type_nak, tvb,
            offset, 1, ENC_BIG_ENDIAN);
        break;
        /*********************************************************************
        **********************************************************************/
      case EAP_TYPE_MD5:
      {
        guint8      value_size = tvb_get_guint8(tvb, offset);
        gint        extra_len  = size - 1 - value_size;
        proto_item *item;

        /* Warn that this is an insecure EAP type. */
        expert_add_info(pinfo, eap_type_item, &ei_eap_mitm_attacks);

        item = proto_tree_add_item(eap_tree, hf_eap_md5_value_size, tvb, offset, 1, ENC_BIG_ENDIAN);
        if (value_size > (size - 1))
        {
          expert_add_info(pinfo, item, &ei_eap_md5_value_size_overflow);
          value_size = size - 1;
        }

        offset += 1;
        proto_tree_add_item(eap_tree, hf_eap_md5_value, tvb, offset, value_size, ENC_NA);
        offset += value_size;
        if (extra_len > 0) {
          proto_tree_add_item(eap_tree, hf_eap_md5_extra_data, tvb, offset, extra_len, ENC_NA);
        }
      }
      break;

      /*********************************************************************
                                EAP-TLS
      **********************************************************************/
      case EAP_TYPE_FAST:
      case EAP_TYPE_PEAP:
      case EAP_TYPE_TTLS:
      case EAP_TYPE_TLS:
      case EAP_TYPE_TEAP:
      {
        guint8   flags            = tvb_get_guint8(tvb, offset);
        gboolean more_fragments;
        gboolean has_length;
        gboolean is_start;
        int      eap_tls_seq      = -1;
        guint32  eap_reass_cookie =  0;
        gboolean needs_reassembly =  FALSE;

        if (!conversation_state) {
          // XXX expert info? There cannot be another EAP-TTLS message within
          // the EAP-Message inside EAP-TTLS.
          break;
        }

        more_fragments = test_flag(flags,EAP_TLS_FLAG_M);
        has_length     = test_flag(flags,EAP_TLS_FLAG_L);
        is_start       = test_flag(flags,EAP_TLS_FLAG_S);

        if (is_start)
          conversation_state->eap_tls_seq = -1;

        /* Flags field, 1 byte */
        ti = proto_tree_add_item(eap_tree, hf_eap_tls_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
        eap_tls_flags_tree = proto_item_add_subtree(ti, ett_eap_tls_flags);
        proto_tree_add_item(eap_tls_flags_tree, hf_eap_tls_flag_l, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(eap_tls_flags_tree, hf_eap_tls_flag_m, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(eap_tls_flags_tree, hf_eap_tls_flag_s, tvb, offset, 1, ENC_BIG_ENDIAN);

        if ((eap_type == EAP_TYPE_PEAP) || (eap_type == EAP_TYPE_TTLS) ||
            (eap_type == EAP_TYPE_FAST) || (eap_type == EAP_TYPE_TEAP)) {
          proto_tree_add_item(eap_tls_flags_tree, hf_eap_tls_flags_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        }
        size   -= 1;
        offset += 1;

        /* Length field, 4 bytes, OPTIONAL. */
        if (has_length) {
          proto_tree_add_item(eap_tree, hf_eap_tls_len, tvb, offset, 4, ENC_BIG_ENDIAN);
          size   -= 4;
          offset += 4;
        }

        if (size > 0) {

          tvbuff_t *next_tvb = NULL;
          gint      tvb_len;
          gboolean  save_fragmented;

          tvb_len = tvb_captured_length_remaining(tvb, offset);
          if (size < tvb_len)
            tvb_len = size;

          /* If this is a retransmission, do not save the fragment. */
          if (is_duplicate_id) {
            next_tvb = tvb_new_subset_length_caplen(tvb, offset, tvb_len, size);
            call_data_dissector(next_tvb, pinfo, eap_tree);
            break;
          }

          /*
            EAP/TLS is weird protocol (it comes from
            Microsoft after all).

            If we have series of fragmented packets,
            then there's no way of knowing that from
            the packet itself, if it is the last packet
            in series, that is that the packet part of
            bigger fragmented set of data.

            The only way to know is, by knowing
            that we are already in defragmentation
            "mode" and we are expecing packet
            carrying fragment of data. (either
            because we have not received expected
            amount of data, or because the packet before
            had "F"ragment flag set.)

            The situation is alleviated by fact that it
            is simple ack/nack protcol so there's no
            place for out-of-order packets like it is
            possible with IP.

            Anyway, point of this lengthy essay is that
            we have to keep state information in the
            conversation, so that we can put ourselves in
            defragmenting mode and wait for the last packet,
            and have to attach state to frames as well, so
            that we can handle defragmentation after the
            first pass through the capture.
          */
          /* See if we have a remembered defragmentation EAP ID. */
          packet_state = (frame_state_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_eap, 0);
          if (packet_state == NULL) {
            /*
             * We haven't - does this message require reassembly?
             */
            if (!pinfo->fd->visited) {
              /*
               * This is the first time we've looked at this frame,
               * so it wouldn't have any remembered information.
               *
               * Therefore, we check whether this conversation has
               * a reassembly operation in progress, or whether
               * this frame has the Fragment flag set.
               */
              if (conversation_state->eap_tls_seq != -1) {
                /*
                 * There's a reassembly in progress; the sequence number
                 * of the previous fragment is
                 * "conversation_state->eap_tls_seq", and the reassembly
                 * ID is "conversation_state->eap_reass_cookie".
                 *
                 * We must include this frame in the reassembly.
                 * We advance the sequence number, giving us the
                 * sequence number for this fragment.
                 */
                needs_reassembly = TRUE;
                conversation_state->eap_tls_seq++;

                eap_reass_cookie = conversation_state->eap_reass_cookie;
                eap_tls_seq = conversation_state->eap_tls_seq;
              } else if (more_fragments && has_length) {
                /*
                 * This message has the Fragment flag set, so it requires
                 * reassembly.  It's the message containing the first
                 * fragment (if it's a later fragment, the sequence
                 * number in the conversation state would not be -1).
                 *
                 * If it doesn't include a length, however, we can't
                 * do reassembly (either the message is in error, as
                 * the first fragment *must* contain a length, or we
                 * didn't capture the first fragment, and this just
                 * happens to be the first fragment we saw), so we
                 * also check that we have a length;
                 */
                needs_reassembly = TRUE;
                conversation_state->eap_reass_cookie = pinfo->num;

                /*
                 * Start the reassembly sequence number at 0.
                 */
                conversation_state->eap_tls_seq = 0;

                eap_tls_seq = conversation_state->eap_tls_seq;
                eap_reass_cookie = conversation_state->eap_reass_cookie;
              }

              if (needs_reassembly) {
                /*
                 * This frame requires reassembly; remember the reassembly
                 * ID for subsequent accesses to it.
                 */
                packet_state = wmem_new(wmem_file_scope(), frame_state_t);
                packet_state->info = eap_reass_cookie;
                p_add_proto_data(wmem_file_scope(), pinfo, proto_eap, 0, packet_state);
              }
            }
          } else {
            /*
             * This frame has a reassembly cookie associated with it, so
             * it requires reassembly.  We've already done the
             * reassembly in the first pass, so "fragment_add_seq()"
             * won't look at the sequence number; set it to 0.
             *
             * XXX - a frame isn't supposed to have more than one
             * EAP message in it, but if it includes both an EAP-TLS
             * message and a LEAP message, we might be mistakenly
             * concluding it requires reassembly because the "info"
             * field isn't -1.  We could, I guess, pack both EAP-TLS
             * ID and LEAP state into the structure, but that doesn't
             * work if you have multiple EAP-TLS or LEAP messages in
             * the frame.
             *
             * But it's not clear how much work we should do to handle
             * a bogus message such as that; as long as we don't crash
             * or do something else equally horrible, we may not
             * have to worry about this at all.
             */
            needs_reassembly = TRUE;
            eap_reass_cookie = packet_state->info;
            eap_tls_seq = 0;
          }

          /*
            We test here to see whether EAP-TLS packet
            carry fragmented of TLS data.

            If this is the case, we do reasembly below,
            otherwise we just call dissector.
          */
          if (needs_reassembly) {
            fragment_head   *fd_head;

            /*
             * Yes, this frame contains a fragment that requires
             * reassembly.
             */
            save_fragmented   = pinfo->fragmented;
            pinfo->fragmented = TRUE;
            fd_head = fragment_add_seq(&eap_tls_reassembly_table,
                                       tvb, offset,
                                       pinfo, eap_reass_cookie, NULL,
                                       eap_tls_seq,
                                       size,
                                       more_fragments, 0);

            if (fd_head != NULL && fd_head->reassembled_in == pinfo->num) {
              /* Reassembled  */
              proto_item *frag_tree_item;

              next_tvb = tvb_new_chain(tvb, fd_head->tvb_data);
              add_new_data_source(pinfo, next_tvb, "Reassembled EAP-TLS");

              show_fragment_seq_tree(fd_head, &eap_tls_frag_items,
                                     eap_tree, pinfo, next_tvb, &frag_tree_item);

              /*
               * We're finished reassembing this frame.
               * Reinitialize the reassembly state.
               */
              if (!pinfo->fd->visited)
                conversation_state->eap_tls_seq = -1;
            }

            pinfo->fragmented = save_fragmented;

          } else { /* this data is NOT fragmented */
            next_tvb = tvb_new_subset_length_caplen(tvb, offset, tvb_len, size);
          }

          if (next_tvb) {
            switch (eap_type) {
              case EAP_TYPE_TTLS:
                tls_set_appdata_dissector(tls_handle, pinfo, diameter_avps_handle);
                break;
              case EAP_TYPE_PEAP:
                tls_set_appdata_dissector(tls_handle, pinfo, eap_handle);
                break;
              case EAP_TYPE_TEAP:
                tls_set_appdata_dissector(tls_handle, pinfo, teap_handle);
                break;
            }
            call_dissector(tls_handle, next_tvb, pinfo, eap_tree);
          }
        }
      }
      break; /*  EAP_TYPE_TLS */

      /*********************************************************************
        Cisco's Lightweight EAP (LEAP)
        https://web.archive.org/web/20070623090417if_/http://www.missl.cs.umd.edu/wireless/ethereal/leap.txt
      **********************************************************************/
      case EAP_TYPE_LEAP:
      {
        guint8 count, namesize;

        /* Warn that this is an insecure EAP type. */
        expert_add_info(pinfo, eap_type_item, &ei_eap_dictionary_attacks);

        /* Version (byte) */
        proto_tree_add_item(eap_tree, hf_eap_leap_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        /* Unused  (byte) */
        proto_tree_add_item(eap_tree, hf_eap_leap_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        /* Count   (byte) */
        count = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(eap_tree, hf_eap_leap_count, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        /* Data    (byte*Count) */
        /* This part is state-dependent. */

        if (!conversation_state) {
          // XXX expert info? LEAP is not expected within the EAP-Message within EAP-TTLS.
          break;
        }
        /* XXX - are duplicates possible (is_duplicate_id)?
         * If so, should we stop here to avoid modifying conversation_state? */

        /* See if we've already remembered the state. */
        packet_state = (frame_state_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_eap, 0);
        if (packet_state == NULL) {
          /*
           * We haven't - compute the state based on the current
           * state in the conversation.
           */
          leap_state = conversation_state->leap_state;

          /* Advance the state machine. */
          if (leap_state==0) leap_state =  1; else
            if (leap_state==1) leap_state =  2; else
              if (leap_state==2) leap_state =  3; else
                if (leap_state==3) leap_state =  4; else
                  if (leap_state==4) leap_state = -1;

          /*
           * Remember the state for subsequent accesses to this
           * frame.
           */
          packet_state = wmem_new(wmem_file_scope(), frame_state_t);
          packet_state->info = leap_state;
          p_add_proto_data(wmem_file_scope(), pinfo, proto_eap, 0, packet_state);

          /*
           * Update the conversation's state.
           */
          conversation_state->leap_state = leap_state;
        }

        /* Get the remembered state. */
        leap_state = packet_state->info;

        switch (leap_state) {
          case 1:
            proto_tree_add_item(eap_tree, hf_eap_leap_peer_challenge, tvb, offset, count, ENC_NA);
            break;

          case 2:
            proto_tree_add_item(eap_tree, hf_eap_leap_peer_response, tvb, offset, count, ENC_NA);
            break;

          case 3:
            proto_tree_add_item(eap_tree, hf_eap_leap_ap_challenge, tvb, offset, count, ENC_NA);
            break;

          case 4:
            proto_tree_add_item(eap_tree, hf_eap_leap_ap_response, tvb, offset, count, ENC_NA);
            break;

          default:
            proto_tree_add_item(eap_tree, hf_eap_leap_data, tvb, offset, count, ENC_NA);
            break;
        }

        offset += count;

        /* Name    (Length-(8+Count)) */
        namesize = eap_len - (8+count);
        proto_tree_add_item(eap_tree, hf_eap_leap_name, tvb, offset, namesize, ENC_ASCII|ENC_NA);
      }

      break; /* EAP_TYPE_LEAP */

      /*********************************************************************
            EAP-MSCHAPv2 - draft-kamath-pppext-eap-mschapv2-00.txt
      **********************************************************************/
      case EAP_TYPE_MSCHAPV2:
        dissect_eap_mschapv2(eap_tree, tvb, pinfo, offset, size);
        break; /* EAP_TYPE_MSCHAPV2 */

        /*********************************************************************
           EAP-SIM - draft-haverinen-pppext-eap-sim-13.txt
        **********************************************************************/
      case EAP_TYPE_SIM:
        dissect_eap_sim(eap_tree, tvb, pinfo, offset, size);
        break; /* EAP_TYPE_SIM */

        /*********************************************************************
            EAP-AKA - draft-arkko-pppext-eap-aka-12.txt
        **********************************************************************/
      case EAP_TYPE_AKA:
      case EAP_TYPE_AKA_PRIME:
        dissect_eap_aka(eap_tree, tvb, pinfo, offset, size);
        break; /* EAP_TYPE_AKA */

        /*********************************************************************
            EAP Expanded Type
        **********************************************************************/
      case EAP_TYPE_EXT:
      {
        proto_tree *exptree;

        exptree   = proto_tree_add_subtree(eap_tree, tvb, offset, size, ett_eap_exp_attr, NULL, "Expanded Type");
        dissect_exteap(exptree, tvb, offset, size, pinfo, eap_code, eap_identifier);
      }
      break;

      /*********************************************************************
      **********************************************************************/
      default:
        proto_tree_add_item(eap_tree, hf_eap_data, tvb, offset, size, ENC_NA);
        break;
        /*********************************************************************
        **********************************************************************/
      } /* switch (eap_type) */

    }

  } /* switch (eap_code) */

  return tvb_captured_length(tvb);
}

void
proto_register_eap(void)
{
  static hf_register_info hf[] = {
     { &hf_eap_code, {
      "Code", "eap.code",
      FT_UINT8, BASE_DEC, VALS(eap_code_vals), 0x0,
      NULL, HFILL }},

    { &hf_eap_identifier, {
      "Id", "eap.id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_len, {
      "Length", "eap.len",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_type, {
      "Type", "eap.type",
      FT_UINT8, BASE_DEC|BASE_EXT_STRING, &eap_type_vals_ext, 0x0,
      NULL, HFILL }},

    { &hf_eap_type_nak, {
      "Desired Auth Type", "eap.desired_type",
      FT_UINT8, BASE_DEC|BASE_EXT_STRING, &eap_type_vals_ext, 0x0,
      NULL, HFILL }},

    { &hf_eap_identity, {
      "Identity", "eap.identity",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_identity_prefix, {
      "Identity Prefix", "eap.identity.prefix",
      FT_CHAR, BASE_HEX, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_identity_type, {
      "Identity Type", "eap.identity.type",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_identity_full, {
      "Identity (Full)", "eap.identity.full",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_identity_mcc, {
      "Identity Mobile Country Code", "eap.identity.mcc",
      FT_UINT16, BASE_DEC|BASE_EXT_STRING, &E212_codes_ext, 0x0, NULL, HFILL }},

    { &hf_eap_identity_mcc_mnc_2digits, {
      "Identity Mobile Network Code", "eap.identity.mnc",
      FT_UINT16, BASE_DEC|BASE_EXT_STRING, &mcc_mnc_2digits_codes_ext, 0x0, NULL, HFILL }},

    { &hf_eap_identity_mcc_mnc_3digits, {
      "Identity Mobile Network Code", "eap.identity.mnc",
      FT_UINT16, BASE_DEC|BASE_EXT_STRING, &mcc_mnc_3digits_codes_ext, 0x0, NULL, HFILL }},

    { &hf_eap_identity_padding, {
      "Padding", "eap.identity.padding",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_identity_actual_len, {
      "Identity Actual Length", "eap.identity.actual_len",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_notification, {
      "Notification", "eap.notification",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_md5_value_size, {
      "EAP-MD5 Value-Size", "eap.md5.value_size",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_md5_value, {
      "EAP-MD5 Value", "eap.md5.value",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_md5_extra_data, {
      "EAP-MD5 Extra Data", "eap.md5.extra_data",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_tls_flags, {
      "EAP-TLS Flags", "eap.tls.flags",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_tls_flag_l, {
      "Length Included", "eap.tls.flags.len_included",
      FT_BOOLEAN, 8, NULL, EAP_TLS_FLAG_L,
      NULL, HFILL }},

    { &hf_eap_tls_flag_m, {
      "More Fragments", "eap.tls.flags.more_fragments",
      FT_BOOLEAN, 8, NULL, EAP_TLS_FLAG_M,
      NULL, HFILL }},

    { &hf_eap_tls_flag_s, {
      "Start", "eap.tls.flags.start",
      FT_BOOLEAN, 8, NULL, EAP_TLS_FLAG_S,
      NULL, HFILL }},

    { &hf_eap_tls_flags_version, {
      "Version", "eap.tls.flags.version",
      FT_UINT8, BASE_DEC, NULL, EAP_TLS_FLAGS_VERSION,
      NULL, HFILL }},

    { &hf_eap_tls_len, {
      "EAP-TLS Length", "eap.tls.len",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_tls_fragment, {
      "EAP-TLS Fragment", "eap.tls.fragment",
      FT_FRAMENUM, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_tls_fragments, {
      "EAP-TLS Fragments", "eap.tls.fragments",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_tls_fragment_overlap, {
      "Fragment Overlap", "eap.tls.fragment.overlap",
      FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      "Fragment overlaps with other fragments", HFILL }},

    { &hf_eap_tls_fragment_overlap_conflict, {
      "Conflicting Data In Fragment Overlap", "eap.tls.fragment.overlap_conflict",
      FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      "Overlapping fragments contained conflicting data", HFILL }},

    { &hf_eap_tls_fragment_multiple_tails, {
      "Multiple Tail Fragments Found", "eap.tls.fragment.multiple_tails",
      FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      "Several tails were found when defragmenting the packet", HFILL }},

    { &hf_eap_tls_fragment_too_long_fragment,{
      "Fragment Too Long", "eap.tls.fragment.fragment.too_long",
      FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      "Fragment contained data past end of packet", HFILL }},

    { &hf_eap_tls_fragment_error, {
      "Defragmentation Error", "eap.tls.fragment.error",
      FT_FRAMENUM, BASE_NONE, NULL, 0x0,
      "Defragmentation error due to illegal fragments", HFILL }},

    { &hf_eap_tls_fragment_count, {
      "Fragment Count", "eap.tls.fragment.count",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Total length of the reassembled payload", HFILL }},

    { &hf_eap_tls_reassembled_length, {
      "Reassembled EAP-TLS Length", "eap.tls.reassembled.len",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Total length of the reassembled payload", HFILL }},

    { &hf_eap_sim_subtype, {
      "EAP-SIM Subtype", "eap.sim.subtype",
      FT_UINT8, BASE_DEC, VALS(eap_sim_subtype_vals), 0x0,
      NULL, HFILL }},

    { &hf_eap_sim_reserved, {
      "EAP-SIM Reserved", "eap.sim.reserved",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_sim_subtype_attribute, {
      "EAP-SIM Attribute", "eap.sim.subtype.attribute",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_sim_subtype_type, {
      "EAP-SIM Type", "eap.sim.subtype.type",
      FT_UINT8, BASE_DEC|BASE_EXT_STRING, &eap_sim_aka_attribute_vals_ext, 0x0,
      NULL, HFILL }},

    { &hf_eap_sim_subtype_length, {
      "EAP-SIM Length", "eap.sim.subtype.len",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_sim_notification_type, {
      "EAP-SIM Notification Type", "eap.sim.notification_type",
      FT_UINT16, BASE_DEC, VALS(eap_sim_aka_notification_vals), 0x0,
      NULL, HFILL }},

    { &hf_eap_sim_error_code_type, {
      "EAP-SIM Error Code", "eap.sim.error_code",
      FT_UINT16, BASE_DEC, VALS(eap_sim_aka_client_error_codes), 0x0,
      NULL, HFILL }},

    { &hf_eap_sim_subtype_value, {
      "EAP-SIM Value", "eap.sim.subtype.value",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_aka_subtype, {
      "EAP-AKA Subtype", "eap.aka.subtype",
      FT_UINT8, BASE_DEC, VALS(eap_aka_subtype_vals), 0x0,
      NULL, HFILL }},

    { &hf_eap_aka_reserved, {
      "EAP-AKA Reserved", "eap.aka.reserved",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_aka_subtype_attribute, {
      "EAP-AKA Attribute", "eap.aka.subtype.attribute",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_aka_subtype_type, {
      "EAP-AKA Type", "eap.aka.subtype.type",
      FT_UINT8, BASE_DEC|BASE_EXT_STRING, &eap_sim_aka_attribute_vals_ext, 0x0,
      NULL, HFILL }},

    { &hf_eap_aka_subtype_length, {
      "EAP-AKA Length", "eap.aka.subtype.len",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_aka_notification_type, {
      "EAP-AKA Notification Type", "eap.aka.notification_type",
      FT_UINT16, BASE_DEC, VALS(eap_sim_aka_notification_vals), 0x0,
      NULL, HFILL }},

    { &hf_eap_aka_error_code_type, {
      "EAP-AKA Error Code", "eap.aka.error_code",
      FT_UINT16, BASE_DEC, VALS(eap_sim_aka_client_error_codes), 0x0,
      NULL, HFILL }},

    { &hf_eap_aka_subtype_value, {
      "EAP-AKA Value", "eap.aka.subtype.value",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_leap_version, {
      "EAP-LEAP Version", "eap.leap.version",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_leap_reserved, {
      "EAP-LEAP Reserved", "eap.leap.reserved",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_leap_count, {
      "EAP-LEAP Count", "eap.leap.count",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_leap_peer_challenge, {
      "EAP-LEAP Peer-Challenge", "eap.leap.peer_challenge",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_leap_peer_response, {
      "EAP-LEAP Peer-Response", "eap.leap.peer_response",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_leap_ap_challenge, {
      "EAP-LEAP AP-Challenge", "eap.leap.ap_challenge",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_leap_ap_response, {
      "EAP-LEAP AP-Response", "eap.leap.ap_response",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_leap_data, {
      "EAP-LEAP Data", "eap.leap.data",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_leap_name, {
      "EAP-LEAP Name", "eap.leap.name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_ms_chap_v2_opcode, {
      "EAP-MS-CHAP-v2 OpCode", "eap.ms_chap_v2.opcode",
      FT_UINT8, BASE_DEC, VALS(eap_ms_chap_v2_opcode_vals), 0x0,
      NULL, HFILL }},

    { &hf_eap_ms_chap_v2_id, {
      "EAP-MS-CHAP-v2 Id", "eap.ms_chap_v2.id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_ms_chap_v2_length, {
      "EAP-MS-CHAP-v2 Length", "eap.ms_chap_v2.length",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_ms_chap_v2_value_size, {
      "EAP-MS-CHAP-v2 Value-Size", "eap.ms_chap_v2.value_size",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_ms_chap_v2_challenge, {
      "EAP-MS-CHAP-v2 Challenge", "eap.ms_chap_v2.challenge",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_ms_chap_v2_name, {
      "EAP-MS-CHAP-v2 Name", "eap.ms_chap_v2.name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_ms_chap_v2_peer_challenge, {
      "EAP-MS-CHAP-v2 Peer-Challenge", "eap.ms_chap_v2.peer_challenge",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_ms_chap_v2_reserved, {
      "EAP-MS-CHAP-v2 Reserved", "eap.ms_chap_v2.reserved",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_ms_chap_v2_nt_response, {
      "EAP-MS-CHAP-v2 NT-Response", "eap.ms_chap_v2.nt_response",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_ms_chap_v2_flags, {
      "EAP-MS-CHAP-v2 Flags", "eap.ms_chap_v2.flags",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_ms_chap_v2_response, {
      "EAP-MS-CHAP-v2 Response (Unknown Length)", "eap.ms_chap_v2.response",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_ms_chap_v2_message, {
      "EAP-MS-CHAP-v2 Message", "eap.ms_chap_v2.message",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_ms_chap_v2_failure_request, {
      "EAP-MS-CHAP-v2 Failure-Request", "eap.ms_chap_v2.failure_request",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_ms_chap_v2_data, {
      "EAP-MS-CHAP-v2 Data", "eap.ms_chap_v2.data",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    { &hf_eap_data, {
      "EAP Data", "eap.data",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }},

    /* Expanded type fields */
    { &hf_eap_ext_vendor_id, {
      "EAP-EXT Vendor Id", "eap.ext.vendor_id",
      FT_UINT16, BASE_HEX, VALS(eap_ext_vendor_id_vals), 0x0,
      NULL, HFILL }},

    { &hf_eap_ext_vendor_type, {
      "EAP-EXT Vendor Type", "eap.ext.vendor_type",
      FT_UINT8, BASE_HEX, VALS(eap_ext_vendor_type_vals), 0x0,
      NULL, HFILL }}
  };
  static gint *ett[] = {
    &ett_eap,
    &ett_eap_tls_fragment,
    &ett_eap_tls_fragments,
    &ett_eap_sim_attr,
    &ett_eap_aka_attr,
    &ett_eap_exp_attr,
    &ett_eap_tls_flags,
    &ett_identity
  };
  static ei_register_info ei[] = {
     { &ei_eap_ms_chap_v2_length, { "eap.ms_chap_v2.length.invalid", PI_PROTOCOL, PI_WARN, "Invalid Length", EXPFILL }},
     { &ei_eap_mitm_attacks, { "eap.mitm_attacks", PI_SECURITY, PI_WARN, "Vulnerable to MITM attacks. If possible, change EAP type.", EXPFILL }},
     { &ei_eap_md5_value_size_overflow, { "eap.md5.value_size.overflow", PI_PROTOCOL, PI_WARN, "Overflow", EXPFILL }},
     { &ei_eap_dictionary_attacks, { "eap.dictionary_attacks", PI_SECURITY, PI_WARN,
                               "Vulnerable to dictionary attacks. If possible, change EAP type."
                               " See http://www.cisco.com/warp/public/cc/pd/witc/ao350ap/prodlit/2331_pp.pdf", EXPFILL }},
     { &ei_eap_identity_invalid, { "eap.identity.invalid", PI_PROTOCOL, PI_WARN, "Invalid identity code", EXPFILL }},
     { &ei_eap_retransmission, { "eap.retransmission", PI_SEQUENCE, PI_NOTE, "This packet is a retransmission", EXPFILL }},
     { &ei_eap_bad_length, { "eap.bad_length", PI_PROTOCOL, PI_WARN, "Bad length (too small or too large)", EXPFILL }},
  };

  expert_module_t* expert_eap;

  proto_eap = proto_register_protocol("Extensible Authentication Protocol",
                                      "EAP", "eap");
  proto_register_field_array(proto_eap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_eap = expert_register_protocol(proto_eap);
  expert_register_field_array(expert_eap, ei, array_length(ei));

  eap_handle = register_dissector("eap", dissect_eap, proto_eap);

  reassembly_table_register(&eap_tls_reassembly_table,
                        &addresses_reassembly_table_functions);

  eap_expanded_type_dissector_table = register_dissector_table("eap.ext.vendor_id",
    "EAP-EXT Vendor Id",
    proto_eap, FT_UINT24,
    BASE_HEX);

}

void
proto_reg_handoff_eap(void)
{
  /*
   * Get a handle for the SSL/TLS dissector.
   */
  tls_handle = find_dissector_add_dependency("tls", proto_eap);
  diameter_avps_handle = find_dissector_add_dependency("diameter_avps", proto_eap);
  teap_handle = find_dissector_add_dependency("teap", proto_eap);

  dissector_add_uint("ppp.protocol", PPP_EAP, eap_handle);
  dissector_add_uint("eapol.type", EAPOL_EAP, eap_handle);
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
