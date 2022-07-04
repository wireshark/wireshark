/* packet-stun.c
 * Routines for Session Traversal Utilities for NAT (STUN) dissection
 * Copyright 2003, Shiang-Ming Huang <smhuang@pcs.csie.nctu.edu.tw>
 * Copyright 2006, Marc Petit-Huguenin <marc@petit-huguenin.org>
 * Copyright 2007-2008, 8x8 Inc. <petithug@8x8.com>
 * Copyright 2008, Gael Breard <gael@breard.org>
 * Copyright 2013, Media5 Corporation, David Bergeron <dbergeron@media5corp.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Please refer to the following specs for protocol detail:
 * - RFC 3489 (Addition of deprecated attributes for diagnostics purpose)
 *             STUN - Simple Traversal of User Datagram Protocol (UDP)
 *             Through Network Address Translators (NATs) (superseeded by RFC 5389)
 * - RFC 5389, formerly draft-ietf-behave-rfc3489bis-18
 *             Session Traversal Utilities for NAT (STUN) (superseeded by RFC 8489)
 * - RFC 8489  Session Traversal Utilities for NAT (STUN)
 * - RFC 5780, formerly draft-ietf-behave-nat-behavior-discovery-08
 *             NAT Behavior Discovery Using Session Traversal Utilities for NAT (STUN)
 * - RFC 5766, formerly draft-ietf-behave-turn-16
 *             Traversal Using Relays around NAT (TURN) (superseeded by RFC 8656)
 * - RFC 8656  Traversal Using Relays around NAT (TURN)
 * - RFC 6062  Traversal Using Relays around NAT (TURN) Extensions for TCP Allocations
 * - RFC 6156, formerly draft-ietf-behave-turn-ipv6-11
 *             Traversal Using Relays around NAT (TURN) Extension for IPv6
 * - RFC 5245, formerly draft-ietf-mmusic-ice-19
 *             Interactive Connectivity Establishment (ICE)
 * - RFC 6544  TCP Candidates with Interactive Connectivity Establishment (ICE)
 *
 * Iana registered values:
 * https://www.iana.org/assignments/stun-parameters/stun-parameters.xhtml
 *
 * From MS
 * MS-TURN: Traversal Using Relay NAT (TURN) Extensions https://docs.microsoft.com/en-us/openspecs/office_protocols/ms-turn
 * MS-TURNBWM:  Traversal using Relay NAT (TURN) Bandwidth Management Extensions https://docs.microsoft.com/en-us/openspecs/office_protocols/ms-turnbwm
 * MS-ICE: Interactive Connectivity Establishment (ICE) Extensions https://docs.microsoft.com/en-us/openspecs/office_protocols/ms-ice
 * MS-ICE2:  Interactive Connectivity Establishment ICE Extensions 2.0 https://docs.microsoft.com/en-us/openspecs/office_protocols/ms-ice2
 * MS-ICE2BWN: Interactive Connectivity Establishment (ICE) 2.0 Bandwidth Management Extensions https://docs.microsoft.com/en-us/openspecs/office_protocols/ms-ice2bwm
 */

/* TODO
 * Add information about different versions to table as we find it
 * Add/Implement missing attributes
 * Add/Implement missing message classes/methods
 * Add missing error codes
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/to_str.h>
#include <epan/crc32-tvb.h>
#include <wsutil/ws_roundup.h>
#include "packet-tcp.h"

void proto_register_stun(void);
void proto_reg_handoff_stun(void);

/* Dissection relevant differences between STUN/TURN specification documents
 *
 *  Aspect   | MS-TURN 18.0       | RFC 3489           | RFC 5389           | RFC 8489 (*1)      |
 * ===============================================================================================
 *  Message  | 0b00+14-bit        | 16-bit             | 0b00+14-bit, type= |                    |
 *  Type     | No class or method | No class or method | class+method       |                    |
 *           | 0x0115: Data Ind   |                    | Method: 0x000-0xFFF| Method: 0x000-0x0FF|
 * -----------------------------------------------------------------------------------------------
 *  Transac- | 128 bits, seen     | 128 bits           | 32 bit Magic +     |                    |
 *  tion ID  | with MAGIC as well |                    | 96 bit Trans ID    |                    |
 * -----------------------------------------------------------------------------------------------
 *  Padding  | No Attribute Pad   | No Attribute Pad   | Pad to 32 bits     |                    |
 *           |                    |                    | Att. Len excl. Pad |                    |
 *           |                    |                    | Msg. Len incl. Pad |                    |
 *           |                    |                    |  -> MLen & 3 == 0  |                    |
 *           |                    |                    | Pad value: any     | Pad value: MBZ     |
 * -----------------------------------------------------------------------------------------------
 *  (XOR-)   | Write: Any value   | Write: Any value   | Write: MBZ         |                    |
 *  MAP-ADDR | Read : Ignored     | Read : Ignored     | Read : Ignored     |                    |
 *  1st byte |                    |                    |                    |                    |
 * -----------------------------------------------------------------------------------------------
 *  Username | Opaque             | Opaque             | UTF-8 String       |                    |
 * -----------------------------------------------------------------------------------------------
 *  Password | Opaque             | Deprecated         | Deprecated         |                    |
 * -----------------------------------------------------------------------------------------------
 *  NONCE &  | 0x0014             | 0x0015 (*2)        | 0x0015             |                    |
 *  REALM    | 0x0015             | 0x0014             | 0x0014             |                    |
 * -----------------------------------------------------------------------------------------------
 *  TURN     | RFC 5766/8656 or   | N/A                | RFC 5766:          | RFC 8656:          |
 *  Channels | Multiplexed TURN   |                    | 0x4000-0x7FFF used | 0x4000-0x4FFF used |
 *           | Channels (0xFF10)  |                    | 0x8000-0xFFFF res. | 0x5000-0xFFFF res. |
 *           |                    |                    | Reserved MUST NOT  | Reserved MUST be   |
 *           |                    |                    | be rejected        | dropped (collision)|
 * -----------------------------------------------------------------------------------------------
 * *1: Only where different from RFC 5389
 * *2: NONCE & REALM were first defined in Internet-Drafts after RFC 3489 was
 * published. Early drafts, up to draft-ietf-behave-rfc3489bis-02 and
 * draft-rosenberg-midcom-turn-08, used 0x0014 for NONCE and 0x0015 for REALM.
 * The attribute numbers were swapped in draft-ietf-behave-rfc3489bis-03 (when
 * moved from the TURN spec to the STUN spec), the same version that added the
 * fixed 32-bit magic. Since this dissector only handles packets with the magic
 * (others are rejected and processed by the classicstun dissector instead),
 * the swapped values are used for RFC 3489 mode here.
 */

enum {
        NET_VER_AUTO,
        NET_VER_MS_TURN,
        NET_VER_3489,
        NET_VER_5389
};

/* Auto-tuning. Default: NET_VER_5389; NET_VER_MS_TURN if MAGIC_COOKIE is found */
/* NET_VER_3489 is only useful for packets that conform specifically to
 * draft-ietf-behave-rfc3849bis-03; i.e. that have the 32 bit magic so that they
 * are not handled by classicstun instead, have the current (swapped) NONE and
 * REALM attribute numbers, but do not have the attribute padding that was
 * introduced in draft-ietf-behave-rfc3849bis-04.
 */

static gint stun_network_version = NET_VER_5389;

static const enum_val_t stun_network_version_vals[] = {
        { "Auto", "Auto",     NET_VER_AUTO},
        { "MS-TURN",  "MS-TURN", NET_VER_MS_TURN },
        { "RFC3489 and earlier", "RFC3489 and earlier",     NET_VER_3489},
        { "RFC5389 and later",  "RFC5389 and later", NET_VER_5389 },
        { NULL, NULL, 0 }
};

static const value_string network_versions_vals[] = {
        {NET_VER_MS_TURN,  "MS-TURN"},
        {NET_VER_3489,     "RFC-3489 and earlier"},
        {NET_VER_5389,     "RFC-5389/8489"},
        {0,   NULL}
};

/* heuristic subdissectors */
static heur_dissector_list_t heur_subdissector_list;

/* stun dissector handles */
static dissector_handle_t data_handle;
static dissector_handle_t stun_tcp_handle;
static dissector_handle_t stun_udp_handle;

/* Initialize the protocol and registered fields */
static int proto_stun = -1;

static int hf_stun_channel = -1;


static int hf_stun_tcp_frame_length = -1;
static int hf_stun_type = -1;
static int hf_stun_type_class = -1;
static int hf_stun_type_method = -1;
static int hf_stun_type_method_assignment = -1;
static int hf_stun_length = -1;
static int hf_stun_cookie = -1;
static int hf_stun_id = -1;
static int hf_stun_attributes = -1;
static int hf_stun_response_in = -1;
static int hf_stun_response_to = -1;
static int hf_stun_time = -1;
static int hf_stun_duplicate = -1;
static int hf_stun_attr = -1;

static int hf_stun_att_type = -1; /* STUN attribute fields */
static int hf_stun_att_length = -1;
static int hf_stun_att_family = -1;
static int hf_stun_att_type_comprehension = -1;
static int hf_stun_att_type_assignment = -1;
static int hf_stun_att_ipv4 = -1;
static int hf_stun_att_ipv6 = -1;
static int hf_stun_att_port = -1;
static int hf_stun_att_username = -1;
static int hf_stun_att_username_opaque = -1;
static int hf_stun_att_password = -1;
static int hf_stun_att_padding = -1;
static int hf_stun_att_hmac = -1;
static int hf_stun_att_crc32 = -1;
static int hf_stun_att_crc32_status = -1;
static int hf_stun_att_error_class = -1;
static int hf_stun_att_error_number = -1;
static int hf_stun_att_error_reason = -1;
static int hf_stun_att_realm = -1;
static int hf_stun_att_nonce = -1;
static int hf_stun_att_unknown = -1;
static int hf_stun_att_xor_ipv4 = -1;
static int hf_stun_att_xor_ipv6 = -1;
static int hf_stun_att_xor_port = -1;
static int hf_stun_att_icmp_type = -1;
static int hf_stun_att_icmp_code = -1;
static int hf_stun_att_ms_turn_unknown_8006 = -1;
static int hf_stun_att_software = -1;
static int hf_stun_att_priority = -1;
static int hf_stun_att_tie_breaker = -1;
static int hf_stun_att_change_ip = -1;
static int hf_stun_att_change_port = -1;
static int hf_stun_att_cache_timeout = -1;
static int hf_stun_att_token = -1;
static int hf_stun_att_pw_alg = -1;
static int hf_stun_att_pw_alg_param_len = -1;
static int hf_stun_att_pw_alg_param_data = -1;
static int hf_stun_att_reserve_next = -1;
static int hf_stun_att_reserved = -1;
static int hf_stun_att_value = -1;
static int hf_stun_att_transp = -1;
static int hf_stun_att_magic_cookie = -1;
static int hf_stun_att_bandwidth = -1;
static int hf_stun_att_lifetime = -1;
static int hf_stun_att_channelnum = -1;
static int hf_stun_att_ms_version = -1;
static int hf_stun_att_ms_version_ice = -1;
static int hf_stun_att_ms_connection_id = -1;
static int hf_stun_att_ms_sequence_number = -1;
static int hf_stun_att_ms_stream_type = -1;
static int hf_stun_att_ms_service_quality = -1;
static int hf_stun_att_ms_foundation = -1;
static int hf_stun_att_ms_multiplexed_turn_session_id = -1;
static int hf_stun_att_ms_turn_session_id = -1;
static int hf_stun_att_bandwidth_acm_type = -1;
static int hf_stun_att_bandwidth_rsv_id = -1;
static int hf_stun_att_bandwidth_rsv_amount_misb = -1;
static int hf_stun_att_bandwidth_rsv_amount_masb = -1;
static int hf_stun_att_bandwidth_rsv_amount_mirb = -1;
static int hf_stun_att_bandwidth_rsv_amount_marb = -1;
static int hf_stun_att_address_rp_a = -1;
static int hf_stun_att_address_rp_b = -1;
static int hf_stun_att_address_rp_rsv1 = -1;
static int hf_stun_att_address_rp_rsv2 = -1;
static int hf_stun_att_address_rp_masb = -1;
static int hf_stun_att_address_rp_marb = -1;
static int hf_stun_att_sip_dialog_id = -1;
static int hf_stun_att_sip_call_id = -1;
static int hf_stun_att_lp_peer_location = -1;
static int hf_stun_att_lp_self_location = -1;
static int hf_stun_att_lp_federation = -1;
static int hf_stun_att_google_network_id = -1;
static int hf_stun_att_google_network_cost = -1;
static int hf_stun_network_version = -1;

/* Expert items */
static expert_field ei_stun_short_packet = EI_INIT;
static expert_field ei_stun_wrong_msglen = EI_INIT;
static expert_field ei_stun_long_attribute = EI_INIT;
static expert_field ei_stun_unknown_attribute = EI_INIT;
static expert_field ei_stun_fingerprint_bad = EI_INIT;

/* Structure containing transaction specific information */
typedef struct _stun_transaction_t {
    guint32 req_frame;
    guint32 rep_frame;
    nstime_t req_time;
} stun_transaction_t;

/* Structure containing conversation specific information */
typedef struct _stun_conv_info_t {
    wmem_tree_t *transaction_pdus;
} stun_conv_info_t;

/* STUN versions RFC5389 and newer split off the leading 32 bits of the
 * transaction ID into a magic cookie (called message cookie in this
 * dissector to avoid confusion with the MAGIC_COOKIE attribute) and
 * shortens the real transaction ID to 96 bits.
 * This allows to differentiate between the legacy version of RFC3489
 * and all newer versions.
 */
#define MESSAGE_COOKIE 0x2112A442
#define TURN_MAGIC_COOKIE 0x72C64BC6

/* Message classes (2 bit) */
#define REQUEST          0
#define INDICATION       1
#define SUCCESS_RESPONSE 2
#define ERROR_RESPONSE   3


/* Methods */
/* 0x000-0x07F IETF Review */
#define BINDING                 0x0001 /* RFC8489 */
#define SHARED_SECRET           0x0002 /* RFC3489 */
#define ALLOCATE                0x0003 /* RFC8489 */
#define REFRESH                 0x0004 /* RFC8489 */
/* 0x0005 is Unassigned.
 * 0x1115 was used for DATA_INDICATION in draft-rosenberg-midcom-turn-08,
 * but this did not fit the later class+indication scheme (it would
 * indicate an error response, which it is not) and was unassigned and
 * replaced with 0x0007 before RFC5389. The MS-TURN specification lists
 * it, however, and some MS-TURN captures use it.
 */
#define SEND                    0x0006 /* RFC8656 */
#define DATA_IND                0x0007 /* RFC8656 */
#define CREATE_PERMISSION       0x0008 /* RFC8656 */
#define CHANNELBIND             0x0009 /* RFC8656 */
/* TCP specific */
#define CONNECT                 0x000a /* RFC6062 */
#define CONNECTION_BIND         0x000b /* RFC6062 */
#define CONNECTION_ATTEMPT      0x000c /* RFC6062 */
#define GOOG_PING               0x0080 /* Google undocumented */

/* 0x080-0x0FF Expert Review */
/* 0x100-0xFFF Reserved (for DTLS-SRTP multiplexing collision avoidance,
 * see RFC7983.  Cannot be made available for assignment without IETF Review.)
 */

/* Attribute Types */
/* 0x0000-0x3FFF IETF Review comprehension-required range */
#define MAPPED_ADDRESS          0x0001 /* RFC8489, MS-TURN */
#define RESPONSE_ADDRESS        0x0002 /* Deprecated, RFC3489 */
#define CHANGE_REQUEST          0x0003 /* Deprecated, RFC3489 */
#define SOURCE_ADDRESS          0x0004 /* Deprecated, RFC3489 */
#define CHANGED_ADDRESS         0x0005 /* Deprecated, RFC3489 */
#define USERNAME                0x0006 /* RFC8489, MS-TURN */
#define PASSWORD                0x0007 /* Deprecated, RFC3489 */
#define MESSAGE_INTEGRITY       0x0008 /* RFC8489, MS-TURN */
#define ERROR_CODE              0x0009 /* RFC8489, MS-TURN */
#define UNKNOWN_ATTRIBUTES      0x000a /* RFC8489, MS-TURN */
#define REFLECTED_FROM          0x000b /* Deprecated, RFC3489 */
#define CHANNEL_NUMBER          0x000c /* RFC8656 */
#define LIFETIME                0x000d /* RFC8656, MS-TURN */
#define MS_ALTERNATE_SERVER     0x000e /* MS-TURN */
/* 0x000f reserved collision */
#define MAGIC_COOKIE            0x000f /* MS-TURN */
/* 0x0010 fix reference */
#define BANDWIDTH               0x0010 /* MS-TURN */
/* 0x0011 reserved collision */
#define DESTINATION_ADDRESS     0x0011 /* MS-TURN */
#define XOR_PEER_ADDRESS        0x0012 /* RFC8656, MS-TURN */
#define DATA                    0x0013 /* RFC8656, MS-TURN */
/* Note: REALM and NONCE have swapped attribute numbers in MS-TURN */
#define REALM                   0x0014 /* RFC8489, MS-TURN uses 0x0015 */
#define NONCE                   0x0015 /* RFC8489, MS-TURN uses 0x0014 */
#define XOR_RELAYED_ADDRESS     0x0016 /* RFC8656 */
#define REQUESTED_ADDRESS_FAMILY 0x0017 /* RFC8656, MS-TURN */
#define EVEN_PORT               0x0018 /* RFC8656 */
#define REQUESTED_TRANSPORT     0x0019 /* RFC8656 */
#define DONT_FRAGMENT           0x001a /* RFC8656 */
#define ACCESS_TOKEN            0x001b /* RFC7635 */
#define MESSAGE_INTEGRITY_SHA256 0x001c /* RFC8489 */
#define PASSWORD_ALGORITHM      0x001d /* RFC8489 */
#define USERHASH                0x001e /* RFC8489 */
/* 0x001f Reserved */
#define XOR_MAPPED_ADDRESS      0x0020 /* RFC8489 */
/* 0x0021 add deprecated TIMER-VAL */
#define RESERVATION_TOKEN       0x0022 /* RFC8656 */
/* 0x0023 Reserved */
#define PRIORITY                0x0024 /* RFC8445 */
#define USE_CANDIDATE           0x0025 /* RFC8445 */
#define PADDING                 0x0026 /* RFC5780 */
/* 0x0027 collision RESPONSE-PORT RFC5780 */
#define XOR_RESPONSE_TARGET     0x0027 /* draft-ietf-behave-nat-behavior-discovery-03 */
/* 0x0028 Reserved collision */
#define XOR_REFLECTED_FROM      0x0028 /* draft-ietf-behave-nat-behavior-discovery-03 */
/* 0x0029 Reserved */
#define CONNECTION_ID           0x002a /* rfc6062 */
/* 0x002b-0x002f unassigned */
/* 0x0030 collision reserved */
#define LEGACY_ICMP             0x0030 /* Moved from TURN to 0x8004 */
/* 0x0031-0x3fff Unassigned */

/* 0x4000-0x7FFF Expert Review comprehension-required range */
/* 0x4000-0x7fff Unassigned */

/* 0x8000-0xBFFF IETF Review comprehension-optional range */
#define ADDITIONAL_ADDRESS_FAMILY 0x8000 /* RFC8656 */
#define ADDRESS_ERROR_CODE      0x8001 /* RFC8656 */
#define PASSWORD_ALGORITHMS     0x8002 /* RFC8489 */
#define ALTERNATE_DOMAIN        0x8003 /* RFC8489 */
#define ICMP                    0x8004 /* RFC8656 */
/* Unknown attribute in MS-TURN packets */
#define MS_TURN_UNKNOWN_8006	0x8006
/* 0x8005-0x8021 Unassigned collision */
#define MS_VERSION              0x8008 /* MS-TURN */
/* collision */
#define MS_XOR_MAPPED_ADDRESS   0x8020 /* MS-TURN */
#define SOFTWARE                0x8022 /* RFC8489 */
#define ALTERNATE_SERVER        0x8023 /* RFC8489 */
/* 0x8024 Reserved */
#define TRANSACTION_TRANSMIT_COUNTER 0x8025 /* RFC7982 */
/* 0x8026 Reserved */
#define CACHE_TIMEOUT           0x8027 /* RFC5780 */
#define FINGERPRINT             0x8028 /* RFC8489 */
#define ICE_CONTROLLED          0x8029 /* RFC8445 */
#define ICE_CONTROLLING         0x802a /* RFC8445 */
#define RESPONSE_ORIGIN         0x802b /* RFC5780 */
#define OTHER_ADDRESS           0x802c /* RFC5780 */
#define ECN_CHECK_STUN          0x802d /* RFC6679 */
#define THIRD_PARTY_AUTHORIZATION 0x802e /* RFC7635 */
/* 0x802f Unassigned */
#define MOBILITY_TICKET         0x8030 /* RFC8016 */
/* 0x8031-0xBFFF Unassigned collision */
#define MS_ALTERNATE_HOST_NAME  0x8032 /* MS-TURN */
#define MS_APP_ID               0x8037 /* MS-TURN */
#define MS_SECURE_TAG           0x8039 /* MS-TURN */
#define MS_SEQUENCE_NUMBER      0x8050 /* MS-TURN */
#define MS_CANDIDATE_IDENTIFIER 0x8054 /* MS-ICE2 */
#define MS_SERVICE_QUALITY      0x8055 /* MS-TURN */
#define BANDWIDTH_ACM           0x8056 /* MS-TURNBWM */
#define BANDWIDTH_RSV_ID        0x8057 /* MS-TURNBWM */
#define BANDWIDTH_RSV_AMOUNT    0x8058 /* MS-TURNBWM */
#define REMOTE_SITE_ADDR        0x8059 /* MS-TURNBWM */
#define REMOTE_RELAY_SITE       0x805A /* MS-TURNBWM */
#define LOCAL_SITE_ADDR         0x805B /* MS-TURNBWM */
#define LOCAL_RELAY_SITE        0x805C /* MS-TURNBWM */
#define REMOTE_SITE_ADDR_RP     0x805D /* MS-TURNBWM */
#define REMOTE_RELAY_SITE_RP    0x805E /* MS-TURNBWM */
#define LOCAL_SITE_ADDR_RP      0x805F /* MS-TURNBWM */
#define LOCAL_RELAY_SITE_RP     0x8060 /* MS-TURNBWM */
#define SIP_DIALOG_ID           0x8061 /* MS-TURNBWM */
#define SIP_CALL_ID             0x8062 /* MS-TURNBWM */
#define LOCATION_PROFILE        0x8068 /* MS-TURNBWM */
#define MS_IMPLEMENTATION_VER   0x8070 /* MS-ICE2 */
#define MS_ALT_MAPPED_ADDRESS   0x8090 /* MS-TURN */
#define MS_MULTIPLEXED_TURN_SESSION_ID 0x8095 /* MS_TURN */

/* 0xC000-0xFFFF Expert Review comprehension-optional range */
#define CISCO_STUN_FLOWDATA     0xc000 /* Cisco undocumented */
#define ENF_FLOW_DESCRIPTION    0xc001 /* Cisco undocumented */
#define ENF_NETWORK_STATUS      0xc002 /* Cisco undocumented */
/* 0xc003-0xc056 Unassigned */
/* https://webrtc.googlesource.com/src/+/refs/heads/master/api/transport/stun.h */
#define GOOG_NETWORK_INFO       0xc057
#define GOOG_LAST_ICE_CHECK_RECEIVED 0xc058
#define GOOG_MISC_INFO          0xc059
/* Various IANA-registered but undocumented Google attributes follow */
#define GOOG_OBSOLETE_1         0xc05a
#define GOOG_CONNECTION_ID      0xc05b
#define GOOG_DELTA              0xc05c
#define GOOG_DELTA_ACK          0xc05d
/* 0xc05e-0xc05f Unassigned */
#define GOOG_MESSAGE_INTEGRITY_32 0xc060
/* 0xc061-0xff03 Unassigned */
/* https://webrtc.googlesource.com/src/+/refs/heads/master/p2p/base/turn_port.cc */
#define GOOG_MULTI_MAPPING      0xff04
#define GOOG_LOGGING_ID         0xff05
/* 0xff06-0xffff Unassigned */

#define MS_MULTIPLEX_TURN 0xFF10

/* Initialize the subtree pointers */
static gint ett_stun = -1;
static gint ett_stun_type = -1;
static gint ett_stun_att_all= -1;
static gint ett_stun_att = -1;
static gint ett_stun_att_type = -1;

#define UDP_PORT_STUN   3478
#define TCP_PORT_STUN   3478

#define STUN_HDR_LEN                   20 /* STUN message header length */
#define ATTR_HDR_LEN                    4 /* STUN attribute header length */
#define CHANNEL_DATA_HDR_LEN            4 /* TURN CHANNEL-DATA Message hdr length */
#define MIN_HDR_LEN                     4
#define TCP_FRAME_COOKIE_LEN           10 /* min length for cookie with TCP framing */

static const value_string transportnames[] = {
    { 17, "UDP" },
    {  6, "TCP" },
    {  0, NULL }
};

static const value_string classes[] = {
    {REQUEST         , "Request"},
    {INDICATION      , "Indication"},
    {SUCCESS_RESPONSE, "Success Response"},
    {ERROR_RESPONSE  , "Error Response"},
    {0x00            , NULL}
};

static const value_string methods[] = {
    {BINDING           , "Binding"},
    {SHARED_SECRET     , "SharedSecret"},
    {ALLOCATE          , "Allocate"},
    {REFRESH           , "Refresh"},
    {SEND              , "Send"},
    {DATA_IND          , "Data"},
    {CREATE_PERMISSION , "CreatePermission"},
    {CHANNELBIND       , "Channel-Bind"},
    {CONNECT           , "Connect"},
    {CONNECTION_BIND   , "ConnectionBind"},
    {CONNECTION_ATTEMPT, "ConnectionAttempt"},
    {GOOG_PING         , "GooglePing"},
    {0x00              , NULL}
};


static const value_string attributes[] = {
  /* 0x0000-0x3FFF IETF Review comprehension-required range */
    {MAPPED_ADDRESS        , "MAPPED-ADDRESS"},
    {RESPONSE_ADDRESS      , "RESPONSE_ADDRESS"},
    {CHANGE_REQUEST        , "CHANGE_REQUEST"},
    {SOURCE_ADDRESS        , "SOURCE_ADDRESS"},
    {CHANGED_ADDRESS       , "CHANGED_ADDRESS"},
    {USERNAME              , "USERNAME"},
    {PASSWORD              , "PASSWORD"},
    {MESSAGE_INTEGRITY     , "MESSAGE-INTEGRITY"},
    {ERROR_CODE            , "ERROR-CODE"},
    {UNKNOWN_ATTRIBUTES    , "UNKNOWN-ATTRIBUTES"},
    {REFLECTED_FROM        , "REFLECTED-FROM"},
    {CHANNEL_NUMBER        , "CHANNEL-NUMBER"},
    {LIFETIME              , "LIFETIME"},
    {MS_ALTERNATE_SERVER   , "MS-ALTERNATE-SERVER"},
    {MAGIC_COOKIE          , "MAGIC-COOKIE"},
    {BANDWIDTH             , "BANDWIDTH"},
    {DESTINATION_ADDRESS   , "DESTINATION-ADDRESS"},
    {XOR_PEER_ADDRESS      , "XOR-PEER-ADDRESS"},
    {DATA                  , "DATA"},
    {REALM                 , "REALM"},
    {NONCE                 , "NONCE"},
    {XOR_RELAYED_ADDRESS   , "XOR-RELAYED-ADDRESS"},
    {REQUESTED_ADDRESS_FAMILY, "REQUESTED-ADDRESS-FAMILY"},
    {EVEN_PORT             , "EVEN-PORT"},
    {REQUESTED_TRANSPORT   , "REQUESTED-TRANSPORT"},
    {DONT_FRAGMENT         , "DONT-FRAGMENT"},
    {ACCESS_TOKEN          , "ACCESS-TOKEN"},
    {MESSAGE_INTEGRITY_SHA256, "MESSAGE-INTEGRITY-SHA256"},
    {PASSWORD_ALGORITHM    , "PASSWORD-ALGORITHM"},
    {USERHASH              , "USERHASH"},
    {XOR_MAPPED_ADDRESS    , "XOR-MAPPED-ADDRESS"},
    {RESERVATION_TOKEN     , "RESERVATION-TOKEN"},
    {PRIORITY              , "PRIORITY"},
    {USE_CANDIDATE         , "USE-CANDIDATE"},
    {PADDING               , "PADDING"},
    {XOR_RESPONSE_TARGET   , "XOR-RESPONSE-TARGET"},
    {XOR_REFLECTED_FROM    , "XOR-REFELECTED-FROM"},
    {CONNECTION_ID         , "CONNECTION-ID"},
    {LEGACY_ICMP           , "LEGACY-ICMP"},

  /* 0x4000-0x7FFF Expert Review comprehension-required range */

  /* 0x8000-0xBFFF IETF Review comprehension-optional range */
    {ADDITIONAL_ADDRESS_FAMILY, "ADDITIONAL-ADDRESS-FAMILY"},
    {ADDRESS_ERROR_CODE    , "ADDRESS-ERROR-CODE"},
    {PASSWORD_ALGORITHMS   , "PASSWORD-ALGORITHMS"},
    {ALTERNATE_DOMAIN      , "ALTERNATE-DOMAIN"},
    {ICMP                  , "ICMP"},
    {MS_TURN_UNKNOWN_8006  , "MS-TURN UNKNOWN 8006"},
    {MS_VERSION            , "MS-VERSION"},
    {MS_XOR_MAPPED_ADDRESS , "XOR-MAPPED-ADDRESS"},
    {SOFTWARE              , "SOFTWARE"},
    {ALTERNATE_SERVER      , "ALTERNATE-SERVER"},
    {TRANSACTION_TRANSMIT_COUNTER, "TRANSACTION-TRANSMIT-COUNTER"},
    {CACHE_TIMEOUT         , "CACHE-TIMEOUT"},
    {FINGERPRINT           , "FINGERPRINT"},
    {ICE_CONTROLLED        , "ICE-CONTROLLED"},
    {ICE_CONTROLLING       , "ICE-CONTROLLING"},
    {RESPONSE_ORIGIN       , "RESPONSE-ORIGIN"},
    {OTHER_ADDRESS         , "OTHER-ADDRESS"},
    {ECN_CHECK_STUN        , "ECN-CHECK-STUN"},
    {THIRD_PARTY_AUTHORIZATION, "THIRD-PARTY-AUTHORIZATION"},
    {MOBILITY_TICKET       , "MOBILITY-TICKET"},
    {MS_ALTERNATE_HOST_NAME, "MS-ALTERNATE-HOST-NAME"},
    {MS_APP_ID             , "MS-APP-ID"},
    {MS_SECURE_TAG         , "MS-SECURE-TAG"},
    {MS_SEQUENCE_NUMBER    , "MS-SEQUENCE-NUMBER"},
    {MS_CANDIDATE_IDENTIFIER, "MS-CANDIDATE-IDENTIFIER"},
    {MS_SERVICE_QUALITY    , "MS-SERVICE-QUALITY"},
    {BANDWIDTH_ACM         , "Bandwidth Admission Control Message"},
    {BANDWIDTH_RSV_ID      , "Bandwidth Reservation Identifier"},
    {BANDWIDTH_RSV_AMOUNT  , "Bandwidth Reservation Amount"},
    {REMOTE_SITE_ADDR      , "Remote Site Address"},
    {REMOTE_RELAY_SITE     , "Remote Relay Site Address"},
    {LOCAL_SITE_ADDR       , "Local Site Address"},
    {LOCAL_RELAY_SITE      , "Local Relay Site Address"},
    {REMOTE_SITE_ADDR_RP   , "Remote Site Address Response"},
    {REMOTE_RELAY_SITE_RP  , "Remote Relay Site Address Response"},
    {LOCAL_SITE_ADDR_RP    , "Local Site Address Response"},
    {LOCAL_RELAY_SITE_RP   , "Local Relay Site Address Response"},
    {SIP_DIALOG_ID         , "SIP Dialog Identifier"},
    {SIP_CALL_ID           , "SIP Call Identifier"},
    {LOCATION_PROFILE      , "Location Profile"},
    {MS_IMPLEMENTATION_VER , "MS-IMPLEMENTATION-VERSION"},
    {MS_ALT_MAPPED_ADDRESS , "MS-ALT-MAPPED-ADDRESS"},
    {MS_MULTIPLEXED_TURN_SESSION_ID, "MS-MULTIPLEXED-TURN-SESSION-ID"},

  /* 0xC000-0xFFFF Expert Review comprehension-optional range */
    {CISCO_STUN_FLOWDATA   , "CISCO-STUN-FLOWDATA"},
    {ENF_FLOW_DESCRIPTION   , "ENF-FLOW-DESCRIPTION"},
    {ENF_NETWORK_STATUS    , "ENF-NETWORK-STATUS"},
    {GOOG_NETWORK_INFO     , "GOOG-NETWORK-INFO"},
    {GOOG_LAST_ICE_CHECK_RECEIVED, "GOOG-LAST-ICE-CHECK-RECEIVED"},
    {GOOG_MISC_INFO        , "GOOG-MISC-INFO"},
    {GOOG_OBSOLETE_1       , "GOOG-OBSOLETE-1"},
    {GOOG_CONNECTION_ID    , "GOOG-CONNECTION-ID"},
    {GOOG_DELTA            , "GOOG-DELTA"},
    {GOOG_DELTA_ACK        , "GOOG-DELTA-ACK"},
    {GOOG_MESSAGE_INTEGRITY_32, "GOOG-MESSAGE_INTEGRITY-32"},
    {GOOG_MULTI_MAPPING    , "GOOG-MULTI-MAPPING"},
    {GOOG_LOGGING_ID       , "GOOG-LOGGING-ID"},

    {0x00                  , NULL}
};
static value_string_ext attributes_ext = VALUE_STRING_EXT_INIT(attributes);

static const value_string assignments[] = {
    {0x0000, "IETF Review"},
    {0x0001, "Designated Expert"},
    {0x00, NULL}
};

static const value_string comprehensions[] = {
    {0x0000, "Required"},
    {0x0001, "Optional"},
    {0x00  , NULL}
};

static const value_string attributes_reserve_next[] = {
    {0, "No reservation"},
    {1, "Reserve next port number"},
    {0x00, NULL}
};

static const value_string attributes_family[] = {
    {0x0001, "IPv4"},
    {0x0002, "IPv6"},
    {0x00, NULL}
};
/* https://www.iana.org/assignments/stun-parameters/stun-parameters.xhtml#stun-parameters-6 (2020-08-05)*/

static const value_string error_code[] = {
    {274, "Disable Candidate"},               /* MS-ICE2BWN */
    {275, "Disable Candidate Pair"},          /* MS-ICE2BWN */
    {300, "Try Alternate"},                   /* RFC8489 */
    {400, "Bad Request"},                     /* RFC8489 */
    {401, "Unauthenticated"},                 /* RFC8489, RFC3489+MS-TURN: Unauthorized */
    {403, "Forbidden"},                       /* RFC8656 */
    {405, "Mobility Forbidden"},              /* RFC8016 */
    {420, "Unknown Attribute"},               /* RFC8489 */
    {430, "Stale Credentials (legacy)"},      /* RFC3489 */
    {431, "Integrity Check Failure (legacy)"}, /* RFC3489 */
    {432, "Missing Username (legacy)"},       /* RFC3489 */
    {433, "Use TLS (legacy)"},                /* RFC3489 */
    {434, "Missing Realm (legacy)"},          /* MS-TURN */
    {435, "Missing Nonce (legacy)"},          /* MS-TURN */
    {436, "Unknown User (legacy)"},           /* MS-TURN */
    {437, "Allocation Mismatch"},             /* RFC8656 */
    {438, "Stale Nonce"},                     /* RFC8489 */
    {439, "Wrong Credentials (legacy)"},      /* turn-07 */
    {440, "Address Family not Supported"},    /* RFC8656 */
    {441, "Wrong Credentials"},               /* RFC8656 */
    {442, "Unsupported Transport Protocol"},  /* RFC8656 */
    {443, "Peer Address Family Mismatch"},    /* RFC8656 */
    {446, "Connection Already Exists"},       /* RFC6062 */
    {447, "Connection Timeout or Failure"},   /* RFC6062 */
    {481, "Connection does not exist (legacy)"}, /* nat-behavior-discovery-03 */
    {486, "Allocation Quota Reached"},        /* RFC8656 */
    {487, "Role Conflict"},                   /* RFC8445 */
    {500, "Server Error"},                    /* RFC8489 */
    {503, "Service Unavailable (legacy)"},    /* nat-behavior-discovery-03 */
    {507, "Insufficient Bandwidth Capacity (legacy)"}, /* turn-07 */
    {508, "Insufficient Port Capacity"},      /* RFC8656 */
    {600, "Global Failure"},                  /* RFC8656 */
    {0x00, NULL}
};
static value_string_ext error_code_ext = VALUE_STRING_EXT_INIT(error_code);

static const value_string ms_version_vals[] = {
    {0x00000001, "ICE"},
    {0x00000002, "MS-ICE2"},
    {0x00000003, "MS-ICE2 with SHA256"},
    {0x00000004, "MS-ICE2 with SHA256 and IPv6"},
    {0x00000005, "MULTIPLEXED TURN over UDP only"},
    {0x00000006, "MULTIPLEXED TURN over UDP and TCP"},
    {0x00, NULL}
};

static const range_string ms_version_ice_rvals[] = {
    {0x00000000, 0x00000002, "Supports only RFC3489bis-02 message formats"},
    {0x00000003, 0xFFFFFFFF, "Supports RFC5389 message formats"},
    {0x00, 0x00, NULL}
};

static const value_string ms_stream_type_vals[] = {
    {0x0001, "Audio"},
    {0x0002, "Video"},
    {0x0003, "Supplemental Video"},
    {0x0004, "Data"},
    {0x00, NULL}
};

static const value_string ms_service_quality_vals[] = {
    {0x0000, "Best effort delivery"},
    {0x0001, "Reliable delivery"},
    {0x00, NULL}
};

static const value_string bandwidth_acm_type_vals[] = {
    {0x0000, "Reservation Check"},
    {0x0001, "Reservation Commit"},
    {0x0002, "Reservation Update"},
    {0x00, NULL}
};

static const value_string location_vals[] = {
    {0x00, "Unknown"},
    {0x01, "Internet"},
    {0x02, "Intranet"},
    {0x00, NULL}
};

static const value_string federation_vals[] = {
    {0x00, "No Federation"},
    {0x01, "Enterprise Federation"},
    {0x02, "Public Cloud Federation"},
    {0x00, NULL}
};

static const value_string password_algorithm_vals[] = {
    {0x0000, "Reserved"},
    {0x0001, "MD5"},
    {0x0002, "SHA-256"},
    {0x0000, NULL}
};

/* https://webrtc.googlesource.com/src/+/refs/heads/master/rtc_base/network_constants.h */
static const value_string google_network_cost_vals[] = {
    {0,   "Min"},
    {10,  "Low"},
    {50,  "Unknown"},
    {250, "Cellular5G"},
    {500, "Cellular4G"},
    {900, "Cellular"},
    {910, "Cellular3G"},
    {980, "Cellular2G"},
    {999, "Max"},
    {0,   NULL}
};


static guint
get_stun_message_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                     int offset, void *data _U_)
{
    guint16 type;
    guint   length;
    guint   captured_length = tvb_captured_length(tvb);

    if ((captured_length >= TCP_FRAME_COOKIE_LEN) &&
        (tvb_get_ntohl(tvb, 6) == MESSAGE_COOKIE)) {
        /*
         * The magic cookie is off by two, so this appears to be
         * RFC 4571 framing, as per RFC 6544; use the length
         * field from that framing, rather than the STUN/TURN
         * ChannelData length field.
         */
        return (tvb_get_ntohs(tvb, offset) + 2);
    }

    type   = tvb_get_ntohs(tvb, offset);
    length = tvb_get_ntohs(tvb, offset+2);

    if (type & 0xC000)
    {
        /* two first bits not NULL => should be a channel-data message */
        /* Note: For TCP the message is padded to a 4 byte boundary    */
        return (length + CHANNEL_DATA_HDR_LEN +3) & ~0x3;
    }
    else
    {
        /* Normal STUN message */
        return length + STUN_HDR_LEN;
    }
}

/*
 * XXX: why is this done in this file by the STUN dissector? Why don't we
 * re-use the packet-turnchannel.c's dissect_turnchannel_message() function?
 */
static int
dissect_stun_message_channel_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 msg_type, guint msg_length)
{
    tvbuff_t *next_tvb;
    heur_dtbl_entry_t *hdtbl_entry;
    gint offset = CHANNEL_DATA_HDR_LEN;

    /* XXX: a TURN ChannelData message is not actually a STUN message. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "STUN");
    col_set_str(pinfo->cinfo, COL_INFO, "ChannelData TURN Message");

    if (tree) {
        proto_item *ti;
        proto_tree *stun_tree;
        ti = proto_tree_add_item(
            tree, proto_stun, tvb, 0,
            CHANNEL_DATA_HDR_LEN,
            ENC_NA);
        proto_item_append_text(ti, ", TURN ChannelData Message");
        stun_tree = proto_item_add_subtree(ti, ett_stun);
        proto_tree_add_item(stun_tree, hf_stun_channel, tvb, 0, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(stun_tree, hf_stun_length,  tvb, 2, 2, ENC_BIG_ENDIAN);
        /* MS-TURN Multiplexed TURN Channel */
        if (msg_type == MS_MULTIPLEX_TURN && msg_length >= 8) {
            proto_tree_add_item(stun_tree, hf_stun_att_ms_turn_session_id, tvb, 4, 8, ENC_NA);
        }
    }
    if (msg_type == MS_MULTIPLEX_TURN && msg_length >= 8) {
        msg_length -= 8;
        offset += 8;
    }

    next_tvb = tvb_new_subset_length(tvb, offset, msg_length);

    if (!dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree, &hdtbl_entry, NULL)) {
        call_dissector_only(data_handle, next_tvb, pinfo, tree, NULL);
    }

    return tvb_reported_length(tvb);
}


static int
dissect_stun_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean heur_check, gboolean is_udp)
{
    guint       captured_length;
    guint16     msg_type;
    guint       msg_length;
    proto_item *ti;
    proto_tree *stun_tree;
    proto_tree *stun_type_tree;
    proto_tree *att_all_tree;
    proto_tree *att_type_tree;
    proto_tree *att_tree = NULL;
    guint16     msg_type_method;
    guint16     msg_type_class;
    const char *msg_class_str;
    const char *msg_method_str;
    guint16     att_type, att_type_display;
    guint16     att_length, att_length_pad, clear_port;
    guint32     clear_ip[4];
    address     addr;
    guint       i;
    guint       offset;
    guint       magic_cookie_first_word;
    guint       tcp_framing_offset;
    conversation_t     *conversation=NULL;
    stun_conv_info_t   *stun_info;
    stun_transaction_t *stun_trans;
    wmem_tree_key_t     transaction_id_key[2];
    guint32             transaction_id[3];
    heur_dtbl_entry_t  *hdtbl_entry;
    guint               reported_length;
    gboolean            is_turn = FALSE;
    gboolean            found_turn_attributes = FALSE;
    int                 network_version; /* STUN flavour of the current message */

    /*
     * Check if the frame is really meant for us.
     */

    /* First, make sure we have enough data to do the check. */
    captured_length = tvb_captured_length(tvb);
    if (captured_length < MIN_HDR_LEN)
        return 0;
    reported_length = tvb_reported_length(tvb);

    tcp_framing_offset = 0;
    if ((!is_udp) && (captured_length >= TCP_FRAME_COOKIE_LEN) &&
       (tvb_get_ntohl(tvb, 6) == MESSAGE_COOKIE)) {
        /*
         * The magic cookie is off by two, so this appears to be
         * RFC 4571 framing, as per RFC 6544; the STUN/TURN
         * ChannelData header begins after the 2-octet
         * RFC 4571 length field.
         */
        tcp_framing_offset = 2;
    }

    msg_type     = tvb_get_ntohs(tvb, tcp_framing_offset + 0);
    msg_length   = tvb_get_ntohs(tvb, tcp_framing_offset + 2);

    /* TURN ChannelData message ? */
    if (msg_type & 0xC000) {
        /* two first bits not NULL => should be a channel-data message */

        /*
         * If the packet is being dissected through heuristics, we never match
         * TURN ChannelData because the heuristics are otherwise rather weak.
         * Instead we have to have seen another STUN message type on the same
         * 5-tuple, and then set that conversation for non-heuristic STUN
         * dissection.
         */
        if (heur_check)
            return 0;

        /* RFC 5764 defined a demultiplexing scheme to allow STUN to co-exist
         * on the same 5-tuple as DTLS-SRTP (and ZRTP) by rejecting previously
         * reserved channel numbers and method types, implicitly restricting
         * channel numbers to 0x4000-0x7FFF.  RFC 5766 did not incorporate this
         * restriction, instead indicating that reserved numbers MUST NOT be
         * dropped.
         * RFCs 7983, 8489, and 8656 reconciled this and formally indicated
         * that channel numbers in the reserved range MUST be dropped, while
         * further restricting the channel numbers to 0x4000-0x4FFF.
         * Reject the range 0x8000-0xFFFF, except for the special
         * MS-TURN multiplex channel number, since no implementation has
         * used any other value in that range.
         */
        if (msg_type & 0x8000 && msg_type != MS_MULTIPLEX_TURN) {
            /* XXX: If this packet is not being dissected through heuristics,
             * then the range 0x8000-0xBFFF is quite likely to be RTP/RTCP,
             * and according to RFC 7983 should be forwarded to the RTP
             * dissector. However, similar to TURN ChannelData, the heuristics
             * for RTP are fairly weak and turned off by default over UDP.
             * It would be nice to be able to ensure that for this packet
             * the RTP over UDP heuristic dissector is called while still
             * rejecting the packet and removing STUN from the list of layers.
             */
            return 0;
        }

        /* note that padding is only mandatory over streaming
           protocols */
        if (is_udp) {
            if (reported_length != msg_length + CHANNEL_DATA_HDR_LEN &&
                reported_length != ((msg_length + CHANNEL_DATA_HDR_LEN + 3) & ~0x3))
                return 0;
        } else { /* TCP */
            if (reported_length != ((msg_length + CHANNEL_DATA_HDR_LEN + 3) & ~0x3))
                return 0;
        }

        /* XXX: why don't we invoke the turnchannel dissector instead? */
        return dissect_stun_message_channel_data(tvb, pinfo, tree, msg_type, msg_length);
    }

    /* Normal STUN message */
    if (captured_length < STUN_HDR_LEN)
        return 0;

    msg_type_class = ((msg_type & 0x0010) >> 4) | ((msg_type & 0x0100) >> 7) ;
    msg_type_method = (msg_type & 0x000F) | ((msg_type & 0x00E0) >> 1) | ((msg_type & 0x3E00) >> 2);

    if (msg_type_method > 0xFF) {
        /* "Reserved for DTLS-SRTP multiplexing collision avoidance, see RFC
         * 7983. Cannot be made available for assignment without IETF Review."
         * Even though not reserved until RFC 7983, these have never been
         * assigned or used, including by MS-TURN.
         */
        return 0;
    }

    /* Check if it is really a STUN message - reject messages without the
     * RFC 5389 Magic and let the classicstun dissector handle those.
     */
    if ( tvb_get_ntohl(tvb, tcp_framing_offset + 4) != MESSAGE_COOKIE)
        return 0;

    /* check if payload enough */
    if (reported_length != (msg_length + STUN_HDR_LEN + tcp_framing_offset))
        return 0;

    /* The message seems to be a valid STUN message! */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "STUN");

    /* Create the transaction key which may be used
       to track the conversation */
    transaction_id[0] = tvb_get_ntohl(tvb, tcp_framing_offset + 8);
    transaction_id[1] = tvb_get_ntohl(tvb, tcp_framing_offset + 12);
    transaction_id[2] = tvb_get_ntohl(tvb, tcp_framing_offset + 16);

    transaction_id_key[0].length = 3;
    transaction_id_key[0].key =  transaction_id;
    transaction_id_key[1].length = 0;
    transaction_id_key[1].key = NULL;

    switch (msg_type_method) {
        /* if it's a TURN method, remember that */
        case ALLOCATE:
        case REFRESH:
        case SEND:
        case DATA_IND:
        case CREATE_PERMISSION:
        case CHANNELBIND:
        case CONNECT:
        case CONNECTION_BIND:
        case CONNECTION_ATTEMPT:
            is_turn = TRUE;
            break;
    }

    conversation = find_or_create_conversation(pinfo);

    /*
     * Do we already have a state structure for this conv
     */
    stun_info = (stun_conv_info_t *)conversation_get_proto_data(conversation, proto_stun);
    if (!stun_info) {
        /* No.  Attach that information to the conversation, and add
         * it to the list of information structures.
         */
        stun_info = wmem_new(wmem_file_scope(), stun_conv_info_t);
        stun_info->transaction_pdus=wmem_tree_new(wmem_file_scope());
        conversation_add_proto_data(conversation, proto_stun, stun_info);
    }

    if (!pinfo->fd->visited) {
        if ((stun_trans = (stun_transaction_t *)
             wmem_tree_lookup32_array(stun_info->transaction_pdus,
                                      transaction_id_key)) == NULL) {

            transaction_id_key[0].length = 3;
            transaction_id_key[0].key =  transaction_id;
            transaction_id_key[1].length = 0;
            transaction_id_key[1].key = NULL;

            stun_trans=wmem_new(wmem_file_scope(), stun_transaction_t);
            stun_trans->req_frame=0;
            stun_trans->rep_frame=0;
            stun_trans->req_time=pinfo->abs_ts;
            wmem_tree_insert32_array(stun_info->transaction_pdus,
                                     transaction_id_key,
                                     (void *)stun_trans);
        }

        if (msg_type_class == REQUEST) {
            /* This is a request */
            if (stun_trans->req_frame == 0) {
                stun_trans->req_frame=pinfo->num;
            }

        } else {
            /* This is a catch-all for all non-request messages */
            if (stun_trans->rep_frame == 0) {
                stun_trans->rep_frame=pinfo->num;
            }

        }
    } else {
        stun_trans=(stun_transaction_t *)wmem_tree_lookup32_array(stun_info->transaction_pdus,
                                                                  transaction_id_key);
    }

    if (!stun_trans) {
        /* create a "fake" pana_trans structure */
        stun_trans=wmem_new(pinfo->pool, stun_transaction_t);
        stun_trans->req_frame=0;
        stun_trans->rep_frame=0;
        stun_trans->req_time=pinfo->abs_ts;
    }


    msg_class_str  = val_to_str_const(msg_type_class, classes, "Unknown");
    msg_method_str = val_to_str_const(msg_type_method, methods, "Unknown");

    col_add_lstr(pinfo->cinfo, COL_INFO,
                 msg_method_str,
                 " ",
                 msg_class_str,
                 COL_ADD_LSTR_TERMINATOR);

    offset = 0;
    ti = proto_tree_add_item(tree, proto_stun, tvb, offset, -1, ENC_NA);

    stun_tree = proto_item_add_subtree(ti, ett_stun);

    if (msg_type_class == REQUEST) {
        if (stun_trans->req_frame != pinfo->num) {
            proto_item *it;
            it=proto_tree_add_uint(stun_tree, hf_stun_duplicate,
                                   tvb, offset, 0,
                                   stun_trans->req_frame);
            proto_item_set_generated(it);
        }
        if (stun_trans->rep_frame) {
            proto_item *it;
            it=proto_tree_add_uint(stun_tree, hf_stun_response_in,
                                   tvb, offset, 0,
                                   stun_trans->rep_frame);
            proto_item_set_generated(it);
        }
    }
    else {
        /* Retransmission control */
        if (stun_trans->rep_frame != pinfo->num) {
            proto_item *it;
            it=proto_tree_add_uint(stun_tree, hf_stun_duplicate,
                                   tvb, offset, 0,
                                   stun_trans->rep_frame);
            proto_item_set_generated(it);
        }
        if (msg_type_class == SUCCESS_RESPONSE || msg_type_class == ERROR_RESPONSE) {
            /* This is a response */
            if (stun_trans->req_frame) {
                proto_item *it;
                nstime_t ns;

                it=proto_tree_add_uint(stun_tree, hf_stun_response_to, tvb,
                                       offset, 0,
                                       stun_trans->req_frame);
                proto_item_set_generated(it);

                nstime_delta(&ns, &pinfo->abs_ts, &stun_trans->req_time);
                it=proto_tree_add_time(stun_tree, hf_stun_time, tvb,
                                       offset, 0, &ns);
                proto_item_set_generated(it);
            }

        }
    }

    if (tcp_framing_offset) {
        proto_tree_add_item(stun_tree, hf_stun_tcp_frame_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }
    ti = proto_tree_add_uint_format_value(stun_tree, hf_stun_type, tvb, offset, 2,
                                          msg_type, "0x%04x (%s %s)", msg_type, msg_method_str, msg_class_str);
    stun_type_tree = proto_item_add_subtree(ti, ett_stun_type);
    ti = proto_tree_add_uint(stun_type_tree, hf_stun_type_class, tvb, offset, 2, msg_type);
    proto_item_append_text(ti, " %s (%d)", msg_class_str, msg_type_class);
    ti = proto_tree_add_uint(stun_type_tree, hf_stun_type_method, tvb, offset, 2, msg_type);
    proto_item_append_text(ti, " %s (0x%03x)", msg_method_str, msg_type_method);
    proto_tree_add_uint(stun_type_tree, hf_stun_type_method_assignment, tvb, offset, 2, msg_type);
    offset += 2;

    proto_tree_add_item(stun_tree, hf_stun_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(stun_tree, hf_stun_cookie, tvb, offset, 4, ENC_NA);
    offset += 4;
    proto_tree_add_item(stun_tree, hf_stun_id, tvb, offset, 12, ENC_NA);
    offset += 12;

    /* Remember this (in host order) so we can show clear xor'd addresses */
    magic_cookie_first_word = tvb_get_ntohl(tvb, tcp_framing_offset + 4);

    network_version = stun_network_version != NET_VER_AUTO ? stun_network_version : NET_VER_5389;

    if (msg_length != 0) {
        const gchar       *attribute_name_str;

        /* According to [MS-TURN] section 2.2.2.8: "This attribute MUST be the
           first attribute following the TURN message header in all TURN messages" */
        if (stun_network_version == NET_VER_AUTO &&
            offset < (STUN_HDR_LEN + msg_length) &&
            tvb_get_ntohs(tvb, offset) == MAGIC_COOKIE) {
          network_version = NET_VER_MS_TURN;
        }

        ti = proto_tree_add_uint(stun_tree, hf_stun_network_version, tvb, offset, 0, network_version);
        proto_item_set_generated(ti);

        /* Starting with RFC 5389 msg_length MUST be multiple of 4 bytes */
        if ((network_version >= NET_VER_5389 && msg_length & 3) != 0)
            stun_tree = proto_tree_add_expert(stun_tree, pinfo, &ei_stun_wrong_msglen, tvb, offset-18, 2);

        ti = proto_tree_add_item(stun_tree, hf_stun_attributes, tvb, offset, msg_length, ENC_NA);
        att_all_tree = proto_item_add_subtree(ti, ett_stun_att_all);

        while (offset < (STUN_HDR_LEN + msg_length)) {
            att_type = tvb_get_ntohs(tvb, offset);     /* Attribute type field in attribute header */
            att_length = tvb_get_ntohs(tvb, offset+2); /* Attribute length field in attribute header */
            if (network_version >= NET_VER_5389)
                att_length_pad = WS_ROUNDUP_4(att_length); /* Attribute length including padding */
            else
                att_length_pad = att_length;
            att_type_display = att_type;
            /* Early drafts and MS-TURN use swapped numbers to later versions */
            if ((network_version < NET_VER_3489) && (att_type == 0x0014 || att_type == 0x0015)) {
                att_type_display ^= 1;
            }
            attribute_name_str = try_val_to_str_ext(att_type_display, &attributes_ext);
            if (attribute_name_str){
                ti = proto_tree_add_uint_format(att_all_tree, hf_stun_attr,
                                                tvb, offset, ATTR_HDR_LEN+att_length_pad,
                                                att_type, "%s", attribute_name_str);
                att_tree = proto_item_add_subtree(ti, ett_stun_att);
                ti = proto_tree_add_uint_format_value(att_tree, hf_stun_att_type, tvb,
                                         offset, 2, att_type, "%s", attribute_name_str);
                att_type_tree = proto_item_add_subtree(ti, ett_stun_att_type);
                proto_tree_add_uint(att_type_tree, hf_stun_att_type_comprehension, tvb, offset, 2, att_type);
                proto_tree_add_uint(att_type_tree, hf_stun_att_type_assignment, tvb, offset, 2, att_type);

                if ((offset+ATTR_HDR_LEN+att_length_pad) > (STUN_HDR_LEN+msg_length+tcp_framing_offset)) {
                    proto_tree_add_uint_format_value(att_tree,
                                                     hf_stun_att_length, tvb, offset+2, 2,
                                                     att_length_pad,
                                                     "%u (bogus, goes past the end of the message)",
                                                     att_length_pad);
                    break;
                }
            } else {
                att_tree = proto_tree_add_expert_format(att_all_tree, pinfo, &ei_stun_unknown_attribute, tvb,
                                                        offset, 2, "Unknown attribute 0x%04x", att_type);
            }
            offset += 2;

            proto_tree_add_uint(att_tree, hf_stun_att_length, tvb,
                                offset, 2, att_length);
            offset += 2;

            /* Zero out address */
            clear_address(&addr);

            switch (att_type_display) {

                /* Deprecated STUN RFC3489 attributes */
            case RESPONSE_ADDRESS:
            case SOURCE_ADDRESS:
            case CHANGED_ADDRESS:
            case REFLECTED_FROM:
            case DESTINATION_ADDRESS:
                if (att_length < 1)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_reserved, tvb, offset, 1, ENC_NA);
                if (att_length < 2)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_family, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                if (att_length < 4)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_port, tvb, offset+2, 2, ENC_BIG_ENDIAN);
                switch (tvb_get_guint8(tvb, offset+1))
                {
                case 1:
                    if (att_length < 8)
                        break;
                    proto_tree_add_item(att_tree, hf_stun_att_ipv4, tvb, offset+4, 4, ENC_BIG_ENDIAN);
                    proto_item_append_text(att_tree, " (Deprecated): %s:%d", tvb_ip_to_str(pinfo->pool, tvb, offset+4),tvb_get_ntohs(tvb,offset+2));

                    break;

                case 2:
                    if (att_length < 20)
                        break;
                    proto_tree_add_item(att_tree, hf_stun_att_ipv6, tvb, offset+4, 16, ENC_NA);
                    break;
                }
                break;

                /* Deprecated STUN RFC3489 attributes */
            case PASSWORD:
                {
                proto_tree_add_item(att_tree, hf_stun_att_password, tvb, offset, att_length, ENC_NA);
                }
                break;

            case MAPPED_ADDRESS:
            case ALTERNATE_SERVER:
            case RESPONSE_ORIGIN:
            case OTHER_ADDRESS:
            case MS_ALT_MAPPED_ADDRESS:
            case MS_ALTERNATE_SERVER:
            {
                const gchar       *addr_str = NULL;
                guint16            att_port;

                if (att_length < 1)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_reserved, tvb, offset, 1, ENC_NA);
                if (att_length < 2)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_family, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                if (att_length < 4)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_port, tvb, offset+2, 2, ENC_BIG_ENDIAN);
                att_port = tvb_get_ntohs(tvb, offset + 2);

                switch (tvb_get_guint8(tvb, offset+1)) {
                case 1:
                    if (att_length < 8)
                        break;
                    addr_str = tvb_ip_to_str(pinfo->pool, tvb, offset + 4);
                    proto_tree_add_item(att_tree, hf_stun_att_ipv4, tvb, offset+4, 4, ENC_BIG_ENDIAN);
                    break;

                case 2:
                    if (att_length < 20)
                        break;
                    addr_str = tvb_ip6_to_str(pinfo->pool, tvb, offset + 4);
                    proto_tree_add_item(att_tree, hf_stun_att_ipv6, tvb, offset+4, 16, ENC_NA);
                    break;
                }

                if (addr_str != NULL) {
                    proto_item_append_text(att_tree, ": %s:%d", addr_str, att_port);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " %s: %s:%d",
                                    attribute_name_str, addr_str, att_port);
                }

                break;
            }
            case CHANGE_REQUEST:
                if (att_length < 4)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_change_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(att_tree, hf_stun_att_change_port, tvb, offset, 4, ENC_BIG_ENDIAN);
                break;

            case USERNAME:
            {
                if (network_version >  NET_VER_3489) {
                    const guint8 *user_name_str;

                    proto_tree_add_item_ret_string(att_tree, hf_stun_att_username, tvb, offset, att_length, ENC_UTF_8|ENC_NA, pinfo->pool, &user_name_str);
                    proto_item_append_text(att_tree, ": %s", user_name_str);
                    col_append_fstr( pinfo->cinfo, COL_INFO, " user: %s", user_name_str);
                } else {
                    proto_tree_add_item(att_tree, hf_stun_att_username_opaque, tvb, offset, att_length, ENC_NA);
                }
                break;
            }
            case MESSAGE_INTEGRITY:
                if (att_length < 20)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_hmac, tvb, offset, att_length, ENC_NA);
                break;

            case ERROR_CODE:
                if (att_length < 2)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_reserved, tvb, offset, 2, ENC_NA);
                if (att_length < 3)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_error_class, tvb, offset+2, 1, ENC_BIG_ENDIAN);
                if (att_length < 4)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_error_number, tvb, offset+3, 1, ENC_BIG_ENDIAN);
                {
                    int           human_error_num = tvb_get_guint8(tvb, offset+2) * 100 + tvb_get_guint8(tvb, offset+3);
                    const gchar  *error_str = val_to_str_ext_const(human_error_num, &error_code_ext, "*Unknown error code*");
                    proto_item_append_text(
                        att_tree,
                        " %d (%s)",
                        human_error_num, /* human readable error code */
                        error_str
                        );
                    col_append_fstr(
                        pinfo->cinfo, COL_INFO,
                        " error-code: %d (%s)",
                        human_error_num,
                        error_str
                        );
                }
                if (att_length < 5)
                    break;
                {
                const guint8 *error_reas_str;
                proto_tree_add_item_ret_string(att_tree, hf_stun_att_error_reason, tvb, offset + 4, att_length - 4, ENC_UTF_8 | ENC_NA, pinfo->pool, &error_reas_str);

                proto_item_append_text(att_tree, ": %s", error_reas_str);
                col_append_fstr(pinfo->cinfo, COL_INFO, " %s", error_reas_str);
                }
                break;

            case UNKNOWN_ATTRIBUTES:
                for (i = 0; i < att_length; i += 2)
                    proto_tree_add_item(att_tree, hf_stun_att_unknown, tvb, offset+i, 2, ENC_BIG_ENDIAN);
                break;

            case REALM:
            {
                const guint8 *realm_str;
                proto_tree_add_item_ret_string(att_tree, hf_stun_att_realm, tvb, offset, att_length, ENC_UTF_8|ENC_NA, pinfo->pool, &realm_str);
                proto_item_append_text(att_tree, ": %s", realm_str);
                col_append_fstr(pinfo->cinfo, COL_INFO, " realm: %s", realm_str);
                break;
            }
            case NONCE:
            {
                const guint8 *nonce_str;
                proto_tree_add_item_ret_string(att_tree, hf_stun_att_nonce, tvb, offset, att_length, ENC_UTF_8|ENC_NA, pinfo->pool, &nonce_str);
                proto_item_append_text(att_tree, ": %s", nonce_str);
                col_append_str(pinfo->cinfo, COL_INFO, " with nonce");
                break;
            }
            case PASSWORD_ALGORITHM:
            case PASSWORD_ALGORITHMS:
            {
                guint alg, alg_param_len, alg_param_len_pad;
                guint remaining = att_length;
                while (remaining > 0) {
                   guint loopoffset = offset + att_length - remaining;
                   if (remaining < 4) {
                       proto_tree_add_expert_format(att_tree, pinfo, &ei_stun_short_packet, tvb,
                           loopoffset, remaining, "Too few bytes left for TLV header (%d < 4)", remaining);
                       break;
                   }
                   proto_tree_add_item_ret_uint(att_tree, hf_stun_att_pw_alg, tvb, loopoffset, 2, ENC_BIG_ENDIAN, &alg);
                   proto_tree_add_item_ret_uint(att_tree, hf_stun_att_pw_alg_param_len, tvb, loopoffset+2, 2, ENC_BIG_ENDIAN, &alg_param_len);
                   if (alg_param_len > 0) {
                       if (alg_param_len+4 >= remaining)
                           proto_tree_add_item(att_tree, hf_stun_att_pw_alg_param_data, tvb, loopoffset+4, alg_param_len, ENC_NA);
                       else {
                           proto_tree_add_expert_format(att_tree, pinfo, &ei_stun_short_packet, tvb,
                                loopoffset, remaining, "Too few bytes left for parameter data (%u < %u)", remaining-4, alg_param_len);
                           break;
                       }
                   }
                   /* Hopefully, in case MS-TURN ever gets PASSWORD-ALGORITHM(S) support they will add it with padding */
                   alg_param_len_pad = WS_ROUNDUP_4(alg_param_len);

                   if (alg_param_len < alg_param_len_pad)
                       proto_tree_add_uint(att_tree, hf_stun_att_padding, tvb, loopoffset+alg_param_len, alg_param_len_pad-alg_param_len, alg_param_len_pad-alg_param_len);
                   remaining -= (alg_param_len_pad + 4);
                   if ((att_type_display == PASSWORD_ALGORITHM) && (remaining > 0)) {
                       proto_tree_add_expert_format(att_tree, pinfo, &ei_stun_long_attribute, tvb,
                           loopoffset, remaining, " (PASSWORD-ALGORITHM)");
                       /* Continue anyway */
                   }
                }
                break;
            }
            case XOR_PEER_ADDRESS:
            case XOR_RELAYED_ADDRESS:
                found_turn_attributes = TRUE;
                /* Fallthrough */
            case XOR_MAPPED_ADDRESS:
            case XOR_RESPONSE_TARGET:
            case XOR_REFLECTED_FROM:
            case MS_XOR_MAPPED_ADDRESS:
            case REMOTE_SITE_ADDR:
            case REMOTE_RELAY_SITE:
            case LOCAL_SITE_ADDR:
            case LOCAL_RELAY_SITE:
                if (att_length < 1)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_reserved, tvb, offset, 1, ENC_NA);
                if (att_length < 2)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_family, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                if (att_length < 4)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_xor_port, tvb, offset+2, 2, ENC_NA);

                /* Show the port 'in the clear'
                   XOR (host order) transid with (host order) xor-port.
                   Add host-order port into tree. */
                clear_port = tvb_get_ntohs(tvb, offset+2) ^ (magic_cookie_first_word >> 16);
                ti = proto_tree_add_uint(att_tree, hf_stun_att_port, tvb, offset+2, 2, clear_port);
                proto_item_set_generated(ti);

                if (att_length < 8)
                    break;

                switch (tvb_get_guint8(tvb, offset+1)) {
                case 1:
                    proto_tree_add_item(att_tree, hf_stun_att_xor_ipv4, tvb, offset+4, 4, ENC_NA);

                    /* Show the address 'in the clear'.
                       XOR (host order) transid with (host order) xor-address.
                       Add in network order tree. */
                    clear_ip[0] = tvb_get_ipv4(tvb, offset+4) ^ g_htonl(magic_cookie_first_word);
                    ti = proto_tree_add_ipv4(att_tree, hf_stun_att_ipv4, tvb, offset+4, 4, clear_ip[0]);
                    proto_item_set_generated(ti);

                    set_address(&addr, AT_IPv4, 4, clear_ip);
                    break;

                case 2:
                    if (att_length < 20)
                        break;

                    proto_tree_add_item(att_tree, hf_stun_att_xor_ipv6, tvb, offset+4, 16, ENC_NA);

                    tvb_get_ipv6(tvb, offset+4, (ws_in6_addr *)clear_ip);
                    clear_ip[0] ^= g_htonl(magic_cookie_first_word);
                    clear_ip[1] ^= g_htonl(transaction_id[0]);
                    clear_ip[2] ^= g_htonl(transaction_id[1]);
                    clear_ip[3] ^= g_htonl(transaction_id[2]);
                    ti = proto_tree_add_ipv6(att_tree, hf_stun_att_ipv6, tvb, offset+4, 16,
                                             (const ws_in6_addr *)clear_ip);
                    proto_item_set_generated(ti);

                    set_address(&addr, AT_IPv6, 16, &clear_ip);
                    break;

                default:
                    clear_address(&addr);
                    break;
                }

                if (addr.type != AT_NONE) {
                    const gchar *ipstr = address_to_str(pinfo->pool, &addr);
                    proto_item_append_text(att_tree, ": %s:%d", ipstr, clear_port);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " %s: %s:%d",
                                    attribute_name_str, ipstr, clear_port);
                }

                break;

            case REQUESTED_ADDRESS_FAMILY:
                if (att_length < 1)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_family, tvb, offset, 1, ENC_BIG_ENDIAN);
                if (att_length < 4)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_reserved, tvb, offset+1, 3, ENC_NA);
                break;
            case EVEN_PORT:
                if (att_length < 1)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_reserve_next, tvb, offset, 1, ENC_BIG_ENDIAN);
                found_turn_attributes = TRUE;
                break;

            case RESERVATION_TOKEN:
                if (att_length < 8)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_token, tvb, offset, 8, ENC_NA);
                found_turn_attributes = TRUE;
                break;

            case PRIORITY:
                if (att_length < 4)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_priority, tvb, offset, 4, ENC_BIG_ENDIAN);
                break;

            case PADDING:
                proto_tree_add_uint(att_tree, hf_stun_att_padding, tvb, offset, att_length, att_length);
                break;

            case LEGACY_ICMP:
            case ICMP:
                if (att_length < 4)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_icmp_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(att_tree, hf_stun_att_icmp_code, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                break;

            case MS_TURN_UNKNOWN_8006:
                proto_tree_add_item(att_tree, hf_stun_att_ms_turn_unknown_8006, tvb, offset, att_length, ENC_NA);
                break;

            case SOFTWARE:
                proto_tree_add_item(att_tree, hf_stun_att_software, tvb, offset, att_length, ENC_UTF_8);
                break;

            case CACHE_TIMEOUT:
                if (att_length < 4)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_cache_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
                break;

            case FINGERPRINT:
                if (att_length < 4)
                    break;
                proto_tree_add_checksum(att_tree, tvb, offset, hf_stun_att_crc32, hf_stun_att_crc32_status, &ei_stun_fingerprint_bad, pinfo, crc32_ccitt_tvb(tvb, offset-4) ^ 0x5354554e, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
                break;

            case ICE_CONTROLLED:
            case ICE_CONTROLLING:
                if (att_length < 8)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_tie_breaker, tvb, offset, 8, ENC_NA);
                break;

            case DATA:
                if (att_length > 0) {
                    tvbuff_t *next_tvb;
                    proto_tree_add_item(att_tree, hf_stun_att_value, tvb, offset, att_length, ENC_NA);

                    next_tvb = tvb_new_subset_length(tvb, offset, att_length);

                    if (!dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, att_tree, &hdtbl_entry, NULL)) {
                        call_dissector_only(data_handle, next_tvb, pinfo, att_tree, NULL);
                    }

                }
                found_turn_attributes = TRUE;
                break;

            case REQUESTED_TRANSPORT:
                if (att_length < 1)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_transp, tvb, offset, 1, ENC_BIG_ENDIAN);
                if (att_length < 4)
                    break;

                {
                    guint8  protoCode = tvb_get_guint8(tvb, offset);
                    const gchar *protoCode_str = val_to_str(protoCode, transportnames, "Unknown (0x%8x)");

                    proto_item_append_text(att_tree, ": %s", protoCode_str);
                    col_append_fstr(
                        pinfo->cinfo, COL_INFO,
                        " %s",
                        protoCode_str
                        );
                }
                proto_tree_add_item(att_tree, hf_stun_att_reserved, tvb, offset+1, 3, ENC_NA);
                found_turn_attributes = TRUE;
                break;

            case CHANNEL_NUMBER:
                if (att_length < 4)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_channelnum, tvb, offset, 2, ENC_BIG_ENDIAN);
                {
                    guint16 chan = tvb_get_ntohs(tvb, offset);
                    proto_item_append_text(att_tree, ": 0x%x", chan);
                    col_append_fstr(
                        pinfo->cinfo, COL_INFO,
                        " ChannelNumber=0x%x",
                        chan
                        );
                }
                proto_tree_add_item(att_tree, hf_stun_att_reserved, tvb, offset+2, 2, ENC_NA);
                found_turn_attributes = TRUE;
                break;

            case MAGIC_COOKIE:
                if (att_length < 4)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_magic_cookie, tvb, offset, 4, ENC_BIG_ENDIAN);
                break;

            case BANDWIDTH:
                if (att_length < 4)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_bandwidth, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_item_append_text(att_tree, " %d", tvb_get_ntohl(tvb, offset));
                col_append_fstr(
                    pinfo->cinfo, COL_INFO,
                    " bandwidth: %d",
                    tvb_get_ntohl(tvb, offset)
                    );
                found_turn_attributes = TRUE;
                break;
            case LIFETIME:
                if (att_length < 4)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_lifetime, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_item_append_text(att_tree, " %d", tvb_get_ntohl(tvb, offset));
                col_append_fstr(
                    pinfo->cinfo, COL_INFO,
                    " lifetime: %d",
                    tvb_get_ntohl(tvb, offset)
                    );
                found_turn_attributes = TRUE;
                break;

            case MS_VERSION:
                proto_tree_add_item(att_tree, hf_stun_att_ms_version, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_item_append_text(att_tree, ": %s", val_to_str(tvb_get_ntohl(tvb, offset), ms_version_vals, "Unknown (0x%u)"));
                break;
            case MS_IMPLEMENTATION_VER:
                proto_tree_add_item(att_tree, hf_stun_att_ms_version_ice, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_item_append_text(att_tree, ": %s", rval_to_str(tvb_get_ntohl(tvb, offset), ms_version_ice_rvals, "Unknown (0x%u)"));
                break;
            case MS_SEQUENCE_NUMBER:
                proto_tree_add_item(att_tree, hf_stun_att_ms_connection_id, tvb, offset, 20, ENC_NA);
                proto_tree_add_item(att_tree, hf_stun_att_ms_sequence_number, tvb, offset+20, 4, ENC_BIG_ENDIAN);
                break;
            case MS_SERVICE_QUALITY:
                proto_tree_add_item(att_tree, hf_stun_att_ms_stream_type, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(att_tree, hf_stun_att_ms_service_quality, tvb, offset+2, 2, ENC_BIG_ENDIAN);
                break;
            case BANDWIDTH_ACM:
                proto_tree_add_item(att_tree, hf_stun_att_reserved, tvb, offset, 2, ENC_NA);
                proto_tree_add_item(att_tree, hf_stun_att_bandwidth_acm_type, tvb, offset+2, 2, ENC_BIG_ENDIAN);
                break;
            case BANDWIDTH_RSV_ID:
                proto_tree_add_item(att_tree, hf_stun_att_bandwidth_rsv_id, tvb, offset, 16, ENC_NA);
                break;
            case BANDWIDTH_RSV_AMOUNT:
                proto_tree_add_item(att_tree, hf_stun_att_bandwidth_rsv_amount_masb, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(att_tree, hf_stun_att_bandwidth_rsv_amount_misb, tvb, offset+4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(att_tree, hf_stun_att_bandwidth_rsv_amount_marb, tvb, offset+8, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(att_tree, hf_stun_att_bandwidth_rsv_amount_mirb, tvb, offset+12, 4, ENC_BIG_ENDIAN);
                break;
            case REMOTE_SITE_ADDR_RP:
            case LOCAL_SITE_ADDR_RP:
                proto_tree_add_item(att_tree, hf_stun_att_address_rp_a, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(att_tree, hf_stun_att_address_rp_b, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(att_tree, hf_stun_att_address_rp_rsv1, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(att_tree, hf_stun_att_address_rp_masb, tvb, offset+4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(att_tree, hf_stun_att_address_rp_marb, tvb, offset+8, 4, ENC_BIG_ENDIAN);
                break;
            case REMOTE_RELAY_SITE_RP:
            case LOCAL_RELAY_SITE_RP:
                proto_tree_add_item(att_tree, hf_stun_att_address_rp_a, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(att_tree, hf_stun_att_address_rp_rsv2, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(att_tree, hf_stun_att_address_rp_masb, tvb, offset+4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(att_tree, hf_stun_att_address_rp_marb, tvb, offset+8, 4, ENC_BIG_ENDIAN);
                break;
            case SIP_DIALOG_ID:
                proto_tree_add_item(att_tree, hf_stun_att_sip_dialog_id, tvb, offset, att_length, ENC_NA);
                break;
            case SIP_CALL_ID:
                proto_tree_add_item(att_tree, hf_stun_att_sip_call_id, tvb, offset, att_length, ENC_NA);
                break;
            case LOCATION_PROFILE:
                proto_tree_add_item(att_tree, hf_stun_att_lp_peer_location, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(att_tree, hf_stun_att_lp_self_location, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(att_tree, hf_stun_att_lp_federation, tvb, offset+2, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(att_tree, hf_stun_att_reserved, tvb, offset+3, 1, ENC_NA);
                break;
            case MS_CANDIDATE_IDENTIFIER:
                proto_tree_add_item(att_tree, hf_stun_att_ms_foundation, tvb, offset, 4, ENC_ASCII);
                break;
            case MS_MULTIPLEXED_TURN_SESSION_ID:
                proto_tree_add_item(att_tree, hf_stun_att_ms_multiplexed_turn_session_id, tvb, offset, 8, ENC_NA);
                /* Trick to force decoding of MS-TURN Multiplexed TURN channels */
                found_turn_attributes = TRUE;
                break;

            case GOOG_NETWORK_INFO:
                proto_tree_add_item(att_tree, hf_stun_att_google_network_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(att_tree, hf_stun_att_google_network_cost, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                break;

            default:
                if (att_length > 0)
                    proto_tree_add_item(att_tree, hf_stun_att_value, tvb, offset, att_length, ENC_NA);
                break;
            }

            if ((network_version >= NET_VER_5389) && (att_length < att_length_pad))
                proto_tree_add_uint(att_tree, hf_stun_att_padding, tvb, offset+att_length, att_length_pad-att_length, att_length_pad-att_length);
            offset += att_length_pad;
        }
    }

    if (found_turn_attributes) {
        /* At least one STUN/TURN implementation (Facetime) uses unknown/custom
         * TURN methods to setup a Channel Data, so the previous check to set
         * "is_turn" variable fails. Fortunately, standard TURN attributes are still
         * used in the replies */
        is_turn = TRUE;
    }
    if (heur_check && conversation) {
        /*
         * When in heuristic dissector mode, if this is a STUN message, set
         * the 5-tuple conversation to always decode as non-heuristic. The
         * odds of incorrectly identifying a random packet as a STUN message
         * (other than TURN ChannelData) is small, especially with RFC 7983
         * implemented. A ChannelData message won't be matched when in heuristic
         * mode, so heur_check can't be true in that case and get to this part
         * of the code.
         *
         * XXX: If we ever support STUN over [D]TLS (or MS-TURN's Pseudo-TLS)
         * as a heuristic dissector (instead of through ALPN), make sure to
         * set the TLS app_handle instead of changing the conversation
         * dissector from TLS. As it is, heur_check is FALSE over [D]TLS so
         * we won't get here.
         */
        if (pinfo->ptype == PT_TCP) {
            conversation_set_dissector(conversation, stun_tcp_handle);
        } else if (pinfo->ptype == PT_UDP) {
            conversation_set_dissector(conversation, stun_udp_handle);
        }
    }

    if (!PINFO_FD_VISITED(pinfo) && is_turn && (pinfo->ptype == PT_TCP)
        && (msg_type_method == CONNECTION_BIND) && (msg_type_class == SUCCESS_RESPONSE)) {
        /* RFC 6062: after the ConnectionBind exchange, the connection is no longer framed as TURN;
           instead, it is an unframed pass-through.
           Starting from next frame set conversation dissector to data */
        conversation_set_dissector_from_frame_number(conversation, pinfo->num+1, data_handle);
    }
    return reported_length;
}

static int
dissect_stun_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return dissect_stun_message(tvb, pinfo, tree, FALSE, TRUE);
}

static int
dissect_stun_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return dissect_stun_message(tvb, pinfo, tree, FALSE, FALSE);
}

static int
dissect_stun_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, MIN_HDR_LEN,
        get_stun_message_len, dissect_stun_tcp_pdu, data);
    return tvb_reported_length(tvb);
}

static gboolean
dissect_stun_heur_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    conversation_t *conversation;
    guint captured_length;
    guint16 msg_type;
    guint msg_length;
    guint tcp_framing_offset;
    guint reported_length;

    /* There might be multiple STUN messages in a TCP payload: try finding a valid
       message and then switch to non-heuristic TCP dissector which will handle
       multiple messages and reassembler stuff correctly */

    captured_length = tvb_captured_length(tvb);
    if (captured_length < MIN_HDR_LEN)
        return FALSE;
    reported_length = tvb_reported_length(tvb);

    tcp_framing_offset = 0;
    if ((captured_length >= TCP_FRAME_COOKIE_LEN) &&
        (tvb_get_ntohl(tvb, 6) == MESSAGE_COOKIE)) {
        /*
         * The magic cookie is off by two, so this appears to be
         * RFC 4571 framing, as per RFC 6544; the STUN/TURN
         * ChannelData header begins after the 2-octet
         * RFC 4571 length field.
         */
        tcp_framing_offset = 2;
    }

    msg_type = tvb_get_ntohs(tvb, tcp_framing_offset + 0);
    msg_length = tvb_get_ntohs(tvb, tcp_framing_offset + 2);

    /* TURN ChannelData message ? */
    if (msg_type & 0xC000) {
        /* We don't want to handle TURN ChannelData message in heuristic function
           See comment in dissect_stun_message() */
        return FALSE;
    }

    /* Normal STUN message */
    if (captured_length < STUN_HDR_LEN)
        return FALSE;

    /* Check if it is really a STUN message */
    if (tvb_get_ntohl(tvb, tcp_framing_offset + 4) != MESSAGE_COOKIE)
        return FALSE;

    /* We may have more than one STUN message in the TCP payload */
    if (reported_length < (msg_length + STUN_HDR_LEN + tcp_framing_offset))
        return FALSE;

    conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, stun_tcp_handle);

    dissect_stun_tcp(tvb, pinfo, tree, data);
    return TRUE;
}
static gboolean
dissect_stun_heur_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    if (dissect_stun_message(tvb, pinfo, tree, TRUE, TRUE) == 0)
        return FALSE;
    return TRUE;
}

void
proto_register_stun(void)
{
    static hf_register_info hf[] = {

        { &hf_stun_channel,
          { "Channel Number", "stun.channel", FT_UINT16,
            BASE_HEX, NULL,  0x0, NULL, HFILL }
        },

        /* ////////////////////////////////////// */
        { &hf_stun_tcp_frame_length,
          { "TCP Frame Length", "stun.tcp_frame_length", FT_UINT16,
            BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_stun_type,
          { "Message Type", "stun.type", FT_UINT16,
            BASE_HEX, NULL,0, NULL, HFILL }
        },
        { &hf_stun_type_class,
          { "Message Class", "stun.type.class", FT_UINT16,
            BASE_HEX, NULL, 0x0110, NULL, HFILL }
        },
        { &hf_stun_type_method,
          { "Message Method", "stun.type.method", FT_UINT16,
            BASE_HEX, NULL, 0x3EEF, NULL, HFILL }
        },
        { &hf_stun_type_method_assignment,
          { "Message Method Assignment", "stun.type.method-assignment", FT_UINT16,
            BASE_HEX, VALS(assignments), 0x2000, NULL, HFILL }
        },
        { &hf_stun_length,
          { "Message Length", "stun.length", FT_UINT16,
            BASE_DEC, NULL, 0x0, "Payload (attributes) length", HFILL }
        },
        { &hf_stun_cookie,
          { "Message Cookie", "stun.cookie", FT_BYTES,
            BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_stun_id,
          { "Message Transaction ID", "stun.id", FT_BYTES,
            BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_stun_attributes,
          { "Attributes", "stun.attributes", FT_NONE,
            BASE_NONE, NULL,  0x0, NULL, HFILL }
        },
        { &hf_stun_attr,
          { "Attribute Type", "stun.attribute", FT_UINT16,
            BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_stun_response_in,
          { "Response In", "stun.response-in", FT_FRAMENUM,
            BASE_NONE, NULL, 0x0, "The response to this STUN query is in this frame", HFILL }
        },
        { &hf_stun_response_to,
          { "Request In", "stun.response-to", FT_FRAMENUM,
            BASE_NONE, NULL, 0x0, "This is a response to the STUN Request in this frame", HFILL }
        },
        { &hf_stun_time,
          { "Time", "stun.time", FT_RELATIVE_TIME,
            BASE_NONE, NULL, 0x0, "The time between the Request and the Response", HFILL }
        },
        { &hf_stun_duplicate,
          { "Duplicated original message in", "stun.reqduplicate", FT_FRAMENUM,
            BASE_NONE, NULL, 0x0, "This is a duplicate of STUN message in this frame", HFILL }
        },
        /* ////////////////////////////////////// */
        { &hf_stun_att_type,
          { "Attribute Type", "stun.att.type", FT_UINT16,
            BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_stun_att_type_comprehension,
          { "Attribute Type Comprehension", "stun.att.type.comprehension", FT_UINT16,
            BASE_HEX, VALS(comprehensions), 0x8000, NULL, HFILL }
        },
        { &hf_stun_att_type_assignment,
          { "Attribute Type Assignment", "stun.att.type.assignment", FT_UINT16,
            BASE_HEX, VALS(assignments), 0x4000, NULL, HFILL }
        },
        { &hf_stun_att_length,
          { "Attribute Length", "stun.att.length", FT_UINT16,
            BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_stun_att_family,
          { "Protocol Family", "stun.att.family", FT_UINT8,
            BASE_HEX, VALS(attributes_family), 0x0, NULL, HFILL }
        },
        { &hf_stun_att_ipv4,
          { "IP", "stun.att.ipv4", FT_IPv4,
            BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_stun_att_ipv6,
          { "IP", "stun.att.ipv6", FT_IPv6,
            BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_stun_att_port,
          { "Port", "stun.att.port", FT_UINT16,
            BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_stun_att_username,
          { "Username", "stun.att.username", FT_STRING,
            BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_stun_att_username_opaque,
          { "Username", "stun.att.username.opaque", FT_BYTES,
            BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_stun_att_password,
          { "Password", "stun.att.password", FT_BYTES,
            BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_stun_att_padding,
          { "Padding", "stun.att.padding", FT_UINT16,
            BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_stun_att_hmac,
          { "HMAC-SHA1", "stun.att.hmac", FT_BYTES,
            BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_stun_att_crc32,
          { "CRC-32", "stun.att.crc32", FT_UINT32,
            BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_stun_att_crc32_status,
          { "CRC-32 Status", "stun.att.crc32.status", FT_UINT8,
            BASE_NONE, VALS(proto_checksum_vals), 0x0, NULL, HFILL }
        },
        { &hf_stun_att_error_class,
          { "Error Class","stun.att.error.class", FT_UINT8,
            BASE_DEC, NULL, 0x07, NULL, HFILL}
        },
        { &hf_stun_att_error_number,
          { "Error Code","stun.att.error", FT_UINT8,
            BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        { &hf_stun_att_error_reason,
          { "Error Reason Phrase","stun.att.error.reason", FT_STRING,
            BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_stun_att_realm,
          { "Realm", "stun.att.realm", FT_STRING,
            BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_stun_att_nonce,
          { "Nonce", "stun.att.nonce", FT_STRING,
            BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_stun_att_unknown,
          { "Unknown Attribute","stun.att.unknown", FT_UINT16,
            BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        { &hf_stun_att_xor_ipv4,
          { "IP (XOR-d)", "stun.att.ipv4-xord", FT_BYTES,
            BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_stun_att_xor_ipv6,
          { "IP (XOR-d)", "stun.att.ipv6-xord", FT_BYTES,
            BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_stun_att_xor_port,
          { "Port (XOR-d)", "stun.att.port-xord", FT_BYTES,
            BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_stun_att_icmp_type,
          { "ICMP type", "stun.att.icmp.type", FT_UINT8,
            BASE_DEC, NULL, 0x0, NULL, HFILL}
         },
        { &hf_stun_att_icmp_code,
          { "ICMP code", "stun.att.icmp.code", FT_UINT8,
            BASE_DEC, NULL, 0x0, NULL, HFILL}
         },
        { &hf_stun_att_ms_turn_unknown_8006,
          { "Unknown8006", "stun.att.unknown8006", FT_BYTES,
            BASE_NONE, NULL, 0x0, "MS-TURN Unknown Attribute 0x8006", HFILL }
        },
        { &hf_stun_att_software,
          { "Software","stun.att.software", FT_STRING,
            BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_stun_att_priority,
          { "Priority", "stun.att.priority", FT_UINT32,
            BASE_DEC, NULL, 0x0, NULL, HFILL}
         },
        { &hf_stun_att_tie_breaker,
          { "Tie breaker", "stun.att.tie-breaker", FT_BYTES,
            BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_stun_att_lifetime,
          { "Lifetime", "stun.att.lifetime", FT_UINT32,
            BASE_DEC, NULL, 0x0, "Session idle time remaining (seconds)", HFILL}
         },
        { &hf_stun_att_change_ip,
          { "Change IP","stun.att.change-ip", FT_BOOLEAN,
            16, TFS(&tfs_set_notset), 0x0004, NULL, HFILL}
        },
        { &hf_stun_att_change_port,
          { "Change Port","stun.att.change-port", FT_BOOLEAN,
            16, TFS(&tfs_set_notset), 0x0002, NULL, HFILL}
        },
        { &hf_stun_att_pw_alg,
          { "Password Algorithm", "stun.att.pw_alg", FT_UINT16,
            BASE_DEC, VALS(password_algorithm_vals), 0x0, NULL, HFILL }
        },
        { &hf_stun_att_pw_alg_param_len,
          { "Password Algorithm Length", "stun.att.pw_alg_len", FT_UINT16,
            BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_stun_att_pw_alg_param_data,
          { "Password Algorithm Data", "stun.att.pw_alg_data", FT_BYTES,
            BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_stun_att_reserve_next,
          { "Reserve next","stun.att.even-port.reserve-next", FT_UINT8,
            BASE_DEC, VALS(attributes_reserve_next), 0x80, NULL, HFILL}
        },
        { &hf_stun_att_cache_timeout,
          { "Cache timeout", "stun.att.cache-timeout", FT_UINT32,
            BASE_DEC, NULL, 0x0, NULL, HFILL}
         },
        { &hf_stun_att_token,
          { "Token", "stun.att.token", FT_BYTES,
            BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_stun_att_value,
          { "Value", "stun.value", FT_BYTES,
            BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_stun_att_reserved,
          { "Reserved", "stun.att.reserved", FT_BYTES,
            BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_stun_att_transp,
          { "Transport", "stun.att.transp", FT_UINT8,
            BASE_HEX, VALS(transportnames), 0x0, NULL, HFILL }
        },
        { &hf_stun_att_channelnum,
          { "Channel-Number", "stun.att.channelnum", FT_UINT16,
            BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_stun_att_magic_cookie,
          { "Magic Cookie", "stun.att.magic_cookie", FT_UINT32,
            BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_stun_att_bandwidth,
          { "Bandwidth", "stun.port.bandwidth", FT_UINT32,
            BASE_DEC, NULL, 0x0, "Peak Bandwidth (kBit/s)", HFILL }
        },

        { &hf_stun_att_ms_version,
          { "MS Version", "stun.att.ms.version", FT_UINT32,
            BASE_DEC, VALS(ms_version_vals), 0x0, NULL, HFILL}
         },
        { &hf_stun_att_ms_version_ice,
          { "MS ICE Version", "stun.att.ms.version.ice", FT_UINT32,
            BASE_DEC|BASE_RANGE_STRING, RVALS(ms_version_ice_rvals),
            0x0, NULL, HFILL}
         },
        { &hf_stun_att_ms_connection_id,
          { "Connection ID", "stun.att.ms.connection_id", FT_BYTES,
            BASE_NONE, NULL, 0x0, NULL, HFILL}
         },
        { &hf_stun_att_ms_sequence_number,
          { "Sequence Number", "stun.att.ms.sequence_number", FT_UINT32,
            BASE_DEC, NULL, 0x0, NULL, HFILL}
         },
        { &hf_stun_att_ms_stream_type,
          { "Stream Type", "stun.att.ms.stream_type", FT_UINT16,
            BASE_DEC, VALS(ms_stream_type_vals), 0x0, NULL, HFILL}
         },
        { &hf_stun_att_ms_service_quality,
          { "Service Quality", "stun.att.ms.service_quality", FT_UINT16,
            BASE_DEC, VALS(ms_service_quality_vals), 0x0, NULL, HFILL}
         },
         { &hf_stun_att_ms_foundation,
           { "Foundation", "stun.att.ms.foundation", FT_STRING,
             BASE_NONE, NULL, 0x0, NULL, HFILL}
          },
        { &hf_stun_att_ms_multiplexed_turn_session_id,
          { "MS Multiplexed TURN Session Id", "stun.att.ms.multiplexed_turn_session_id", FT_UINT64,
            BASE_HEX, NULL, 0x0, NULL, HFILL}
         },
        { &hf_stun_att_ms_turn_session_id,
          { "MS TURN Session Id", "stun.att.ms.turn_session_id", FT_UINT64,
            BASE_HEX, NULL, 0x0, NULL, HFILL}
         },
        { &hf_stun_att_bandwidth_acm_type,
          { "Message Type", "stun.att.bandwidth_acm.type", FT_UINT16,
            BASE_DEC, VALS(bandwidth_acm_type_vals), 0x0, NULL, HFILL}
         },
        { &hf_stun_att_bandwidth_rsv_id,
          { "Reservation ID", "stun.att.bandwidth_rsv_id", FT_BYTES,
            BASE_NONE, NULL, 0x0, NULL, HFILL}
         },
        { &hf_stun_att_bandwidth_rsv_amount_misb,
          { "Minimum Send Bandwidth", "stun.att.bandwidth_rsv_amount.misb", FT_UINT32,
            BASE_DEC, NULL, 0x0, "In kilobits per second", HFILL}
         },
        { &hf_stun_att_bandwidth_rsv_amount_masb,
          { "Maximum Send Bandwidth", "stun.att.bandwidth_rsv_amount.masb", FT_UINT32,
            BASE_DEC, NULL, 0x0, "In kilobits per second", HFILL}
         },
        { &hf_stun_att_bandwidth_rsv_amount_mirb,
          { "Minimum Receive Bandwidth", "stun.att.bandwidth_rsv_amount.mirb", FT_UINT32,
            BASE_DEC, NULL, 0x0, "In kilobits per second", HFILL}
         },
        { &hf_stun_att_bandwidth_rsv_amount_marb,
          { "Maximum Receive Bandwidth", "stun.att.bandwidth_rsv_amount.marb", FT_UINT32,
            BASE_DEC, NULL, 0x0, "In kilobits per second", HFILL}
         },
        { &hf_stun_att_address_rp_a,
          { "Valid", "stun.att.address_rp.valid", FT_BOOLEAN,
            32, TFS(&tfs_yes_no), 0x80000000, NULL, HFILL}
         },
        { &hf_stun_att_address_rp_b,
          { "PSTN", "stun.att.address_rp.pstn", FT_BOOLEAN,
            32, TFS(&tfs_yes_no), 0x40000000, NULL, HFILL}
         },
        { &hf_stun_att_address_rp_rsv1,
          { "Reserved", "stun.att.address_rp.reserved", FT_UINT32,
            BASE_HEX, NULL, 0x3FFFFFFF, NULL, HFILL}
         },
        { &hf_stun_att_address_rp_rsv2,
          { "Reserved", "stun.att.address_rp.reserved", FT_UINT32,
            BASE_HEX, NULL, 0x7FFFFFFF, NULL, HFILL}
         },
        { &hf_stun_att_address_rp_masb,
          { "Maximum Send Bandwidth", "stun.att.address_rp.masb", FT_UINT32,
            BASE_DEC, NULL, 0x0, "In kilobits per second", HFILL}
         },
        { &hf_stun_att_address_rp_marb,
          { "Maximum Receive Bandwidth", "stun.att.address_rp.marb", FT_UINT32,
            BASE_DEC, NULL, 0x0, "In kilobits per second", HFILL}
         },
        { &hf_stun_att_sip_dialog_id,
          { "SIP Dialog ID", "stun.att.sip_dialog_id", FT_BYTES,
            BASE_NONE, NULL, 0x0, NULL, HFILL}
         },
        { &hf_stun_att_sip_call_id,
          { "SIP Call ID", "stun.att.sip_call_id", FT_BYTES,
            BASE_NONE, NULL, 0x0, NULL, HFILL}
         },
        { &hf_stun_att_lp_peer_location,
          { "Peer Location", "stun.att.lp.peer_location", FT_UINT8,
            BASE_DEC, VALS(location_vals), 0x0, NULL, HFILL}
         },
        { &hf_stun_att_lp_self_location,
          { "Self Location", "stun.att.lp.seft_location", FT_UINT8,
            BASE_DEC, VALS(location_vals), 0x0, NULL, HFILL}
         },
        { &hf_stun_att_lp_federation,
          { "Federation", "stun.att.lp.federation", FT_UINT8,
            BASE_DEC, VALS(federation_vals), 0x0, NULL, HFILL}
         },
        { &hf_stun_att_google_network_id,
          { "Google Network ID", "stun.att.google.network_id", FT_UINT16,
            BASE_DEC, NULL, 0x0, NULL, HFILL}
         },
        { &hf_stun_att_google_network_cost,
          { "Google Network Cost", "stun.att.google.network_cost", FT_UINT16,
            BASE_DEC, VALS(google_network_cost_vals), 0x0, NULL, HFILL}
         },
        { &hf_stun_network_version,
          { "STUN Network Version", "stun.network_version", FT_UINT8,
            BASE_DEC, VALS(network_versions_vals), 0x0, NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_stun,
        &ett_stun_type,
        &ett_stun_att_all,
        &ett_stun_att,
        &ett_stun_att_type,
    };

    static ei_register_info ei[] = {
        { &ei_stun_short_packet,
        { "stun.short_packet", PI_MALFORMED, PI_ERROR, "Packet is too short", EXPFILL }},

        { &ei_stun_wrong_msglen,
        { "stun.wrong_msglen", PI_MALFORMED, PI_ERROR, "Packet length is not multiple of 4 bytes", EXPFILL }},

        { &ei_stun_long_attribute,
        { "stun.long_attribute", PI_MALFORMED, PI_WARN, "Attribute has trailing data", EXPFILL }},

        { &ei_stun_unknown_attribute,
        { "stun.unknown_attribute", PI_UNDECODED, PI_WARN, "Attribute unknown", EXPFILL }},

        { &ei_stun_fingerprint_bad,
        { "stun.att.crc32.bad", PI_CHECKSUM, PI_WARN, "Bad Fingerprint", EXPFILL }},
    };

    module_t *stun_module;
    expert_module_t* expert_stun;

    /* Register the protocol name and description */
    proto_stun = proto_register_protocol("Session Traversal Utilities for NAT", "STUN", "stun");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_stun, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* heuristic subdissectors (used for the DATA field) */
    heur_subdissector_list = register_heur_dissector_list("stun", proto_stun);

    register_dissector("stun-tcp", dissect_stun_tcp, proto_stun);
    register_dissector("stun-udp", dissect_stun_udp, proto_stun);
    register_dissector("stun-heur", dissect_stun_heur_udp, proto_stun);

    /* Register preferences */
    stun_module = prefs_register_protocol(proto_stun, NULL);
    prefs_register_enum_preference(stun_module,
        "stunversion", "Stun Version", "Stun Version on the Network",
                                       &stun_network_version,
                                       stun_network_version_vals,
                                       FALSE);

    expert_stun = expert_register_protocol(proto_stun);
    expert_register_field_array(expert_stun, ei, array_length(ei));
}

void
proto_reg_handoff_stun(void)
{
    stun_tcp_handle = find_dissector("stun-tcp");
    stun_udp_handle = find_dissector("stun-udp");

    dissector_add_uint_with_preference("tcp.port", TCP_PORT_STUN, stun_tcp_handle);
    dissector_add_uint_with_preference("udp.port", UDP_PORT_STUN, stun_udp_handle);

    /*
     * SSL/TLS and DTLS Application-Layer Protocol Negotiation (ALPN)
     * protocol ID.
     */
    dissector_add_string("tls.alpn", "stun.nat-discovery", stun_tcp_handle);
    dissector_add_string("dtls.alpn", "stun.nat-discovery", stun_udp_handle);

    heur_dissector_add("udp", dissect_stun_heur_udp, "STUN over UDP", "stun_udp", proto_stun, HEURISTIC_ENABLE);
    heur_dissector_add("tcp", dissect_stun_heur_tcp, "STUN over TCP", "stun_tcp", proto_stun, HEURISTIC_ENABLE);
    /* STUN messages may be encapsulated in Send Indication or Channel Data message as DATA payload
     * (in TURN and CLASSICSTUN, both)  */
    heur_dissector_add("stun", dissect_stun_heur_udp, "STUN over TURN", "stun_turn", proto_stun, HEURISTIC_DISABLE);
    heur_dissector_add("classicstun", dissect_stun_heur_udp, "STUN over CLASSICSTUN", "stun_classicstun", proto_stun, HEURISTIC_DISABLE);

    data_handle = find_dissector("data");
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
