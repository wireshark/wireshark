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
 *
 * Please refer to the following specs for protocol detail:
 * - RFC 5389, formerly draft-ietf-behave-rfc3489bis-18
 * - RFC 5245, formerly draft-ietf-mmusic-ice-19
 * - RFC 5780, formerly draft-ietf-behave-nat-behavior-discovery-08
 * - RFC 5766, formerly draft-ietf-behave-turn-16
 * - draft-ietf-behave-turn-ipv6-11
 * - RFC 3489, http://www.faqs.org/rfcs/rfc3489.html  (Addition of deprecated attributes for diagnostics purpose)
 * - RFC 6062
 *
 * From MS (Lync)
 * MS-TURN: Traversal Using Relay NAT (TURN) Extensions http://msdn.microsoft.com/en-us/library/cc431507.aspx
 * MS-ICE2BWN: Interactive Connectivity Establishment (ICE) 2.0 Bandwidth Management Extensions http://msdn.microsoft.com/en-us/library/ff595756.aspx
 * MS-TURNBWM:  Traversal using Relay NAT (TURN) Bandwidth Management Extensions http://msdn.microsoft.com/en-us/library/ff595670.aspx
 * MS-ICE2:  Interactive Connectivity Establishment ICE Extensions 2.0 http://msdn.microsoft.com/en-us/library/office/cc431504.aspx
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>
#include "packet-tcp.h"

void proto_register_stun(void);
void proto_reg_handoff_stun(void);

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
static int hf_stun_att_password = -1;
static int hf_stun_att_padding = -1;
static int hf_stun_att_hmac = -1;
static int hf_stun_att_crc32 = -1;
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
static int hf_stun_att_software = -1;
static int hf_stun_att_priority = -1;
static int hf_stun_att_tie_breaker = -1;
static int hf_stun_att_change_ip = -1;
static int hf_stun_att_change_port = -1;
static int hf_stun_att_cache_timeout = -1;
static int hf_stun_att_token = -1;
static int hf_stun_att_reserve_next = -1;
static int hf_stun_att_reserved = -1;
static int hf_stun_att_value = -1;
static int hf_stun_att_transp = -1;
static int hf_stun_att_magic_cookie = -1;
static int hf_stun_att_bandwidth = -1;
static int hf_stun_att_lifetime = -1;
static int hf_stun_att_channelnum = -1;
static int hf_stun_att_ms_version = -1;
static int hf_stun_att_ms_connection_id = -1;
static int hf_stun_att_ms_sequence_number = -1;
static int hf_stun_att_ms_stream_type = -1;
static int hf_stun_att_ms_service_quality = -1;
static int hf_stun_att_ms_foundation = -1;
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


/* Message classes */
#define REQUEST         0x0000
#define INDICATION      0x0001
#define RESPONSE        0x0002
#define ERROR_RESPONSE  0x0003


/* Methods */
#define BINDING                 0x0001 /* draft-ietf-behave-rfc3489bis-17 */
#define ALLOCATE                0x0003 /* draft-ietf-behave-turn-10*/
#define REFRESH                 0x0004 /* draft-ietf-behave-turn-10*/
#define CHANNELBIND             0x0009 /* draft-ietf-behave-turn-10*/
#define CREATE_PERMISSION       0x0008 /* draft-ietf-behave-turn-10 */
/* Indications */
#define SEND                    0x0006 /* draft-ietf-behave-turn-10*/
#define DATA_IND                0x0007 /* draft-ietf-behave-turn-10*/
/* TCP specific */
#define CONNECT                 0x000a /* rfc6062 */
#define CONNECTION_BIND         0x000b /* rfc6062 */
#define CONNECTION_ATTEMPT      0x000c /* rfc6062 */


/* Attribute Types */
/* Comprehension-required range (0x0000-0x7FFF) */
#define MAPPED_ADDRESS          0x0001 /* draft-ietf-behave-rfc3489bis-17 */
#define RESPONSE_ADDRESS        0x0002 /* Deprecated */
#define CHANGE_REQUEST          0x0003 /* draft-ietf-behave-nat-behavior-discovery-03 */
#define SOURCE_ADDRESS          0x0004 /* Deprecated */
#define CHANGED_ADDRESS         0x0005 /* Deprecated */
#define USERNAME                0x0006 /* draft-ietf-behave-rfc3489bis-17 */
#define PASSWORD                0x0007 /* Deprecated */
#define MESSAGE_INTEGRITY       0x0008 /* draft-ietf-behave-rfc3489bis-17 */
#define ERROR_CODE              0x0009 /* draft-ietf-behave-rfc3489bis-17 */
#define UNKNOWN_ATTRIBUTES      0x000a /* draft-ietf-behave-rfc3489bis-17 */
#define REFLECTED_FROM          0x000b /* Deprecated */
#define CHANNEL_NUMBER          0x000c /* draft-ietf-behave-turn-10 */
#define LIFETIME                0x000d /* draft-ietf-behave-turn-10 */
#define MAGIC_COOKIE            0x000f /* MS-TURN / turn-08 */
#define BANDWIDTH               0x0010 /* turn-07 */
#define DESTINATION_ADDRESS     0x0011 /* MS-TURN / turn-08 */
#define XOR_PEER_ADDRESS        0x0012 /* draft-ietf-behave-turn-10 */
#define DATA                    0x0013 /* draft-ietf-behave-turn-10 */
#define REALM                   0x0014 /* draft-ietf-behave-rfc3489bis-17 */
#define NONCE                   0x0015 /* draft-ietf-behave-rfc3489bis-17 */
#define XOR_RELAYED_ADDRESS     0x0016 /* draft-ietf-behave-turn-10 */
#define REQUESTED_ADDRESS_TYPE  0x0017 /* draft-ietf-behave-turn-ipv6-03 */
#define EVEN_PORT               0x0018 /* draft-ietf-behave-turn-10 */
#define REQUESTED_TRANSPORT     0x0019 /* draft-ietf-behave-turn-10 */
#define DONT_FRAGMENT           0x001a /* draft-ietf-behave-turn-10 */
#define XOR_MAPPED_ADDRESS      0x0020 /* draft-ietf-behave-rfc3489bis-17 */
#define RESERVATION_TOKEN       0x0022 /* draft-ietf-behave-turn-10 */
#define PRIORITY                0x0024 /* draft-ietf-mmusic-ice-19 */
#define USE_CANDIDATE           0x0025 /* draft-ietf-mmusic-ice-19 */
#define PADDING                 0x0026 /* draft-ietf-behave-nat-behavior-discovery-03 */
#define XOR_RESPONSE_TARGET     0x0027 /* draft-ietf-behave-nat-behavior-discovery-03 */
#define XOR_REFLECTED_FROM      0x0028 /* draft-ietf-behave-nat-behavior-discovery-03 */
#define CONNECTION_ID           0x002a /* rfc6062 */
#define ICMP                    0x0030 /* Moved from TURN to a future I-D */
/* Comprehension-optional range (0x8000-0xFFFF) */
#define MS_VERSION              0x8008 /* MS-TURN */
#define MS_XOR_MAPPED_ADDRESS   0x8020 /* MS-TURN */
#define SOFTWARE                0x8022 /* draft-ietf-behave-rfc3489bis-17 */
#define ALTERNATE_SERVER        0x8023 /* draft-ietf-behave-rfc3489bis-17 */
#define CACHE_TIMEOUT           0x8027 /* draft-ietf-behave-nat-behavior-discovery-03 */
#define FINGERPRINT             0x8028 /* draft-ietf-behave-rfc3489bis-17 */
#define ICE_CONTROLLED          0x8029 /* draft-ietf-mmusic-ice-19 */
#define ICE_CONTROLLING         0x802a /* draft-ietf-mmusic-ice-19 */
#define RESPONSE_ORIGIN         0x802b /* draft-ietf-behave-nat-behavior-discovery-03 */
#define OTHER_ADDRESS           0x802c /* draft-ietf-behave-nat-behavior-discovery-03 */
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
    {REQUEST       , "Request"},
    {INDICATION    , "Indication"},
    {RESPONSE      , "Success Response"},
    {ERROR_RESPONSE, "Error Response"},
    {0x00          , NULL}
};

static const value_string methods[] = {
    {BINDING           , "Binding"},
    {ALLOCATE          , "Allocate"},
    {REFRESH           , "Refresh"},
    {SEND              , "Send"},
    {DATA_IND          , "Data"},
    {CREATE_PERMISSION , "CreatePermission"},
    {CHANNELBIND       , "Channel-Bind"},
    {CONNECT           , "Connect"},
    {CONNECTION_BIND   , "ConnectionBind"},
    {CONNECTION_ATTEMPT, "ConnectionAttempt"},
    {0x00              , NULL}
};


static const value_string attributes[] = {
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
    {MAGIC_COOKIE          , "MAGIC-COOKIE"},
    {BANDWIDTH             , "BANDWIDTH"},
    {DESTINATION_ADDRESS   , "DESTINATION-ADDRESS"},
    {XOR_PEER_ADDRESS      , "XOR-PEER-ADDRESS"},
    {DATA                  , "DATA"},
    {REALM                 , "REALM"},
    {NONCE                 , "NONCE"},
    {XOR_RELAYED_ADDRESS   , "XOR-RELAYED-ADDRESS"},
    {REQUESTED_ADDRESS_TYPE, "REQUESTED-ADDRESS-TYPE"},
    {EVEN_PORT             , "EVEN-PORT"},
    {REQUESTED_TRANSPORT   , "REQUESTED-TRANSPORT"},
    {DONT_FRAGMENT         , "DONT-FRAGMENT"},
    {XOR_MAPPED_ADDRESS    , "XOR-MAPPED-ADDRESS"},
    {RESERVATION_TOKEN     , "RESERVATION-TOKEN"},
    {PRIORITY              , "PRIORITY"},
    {USE_CANDIDATE         , "USE-CANDIDATE"},
    {PADDING               , "PADDING"},
    {XOR_RESPONSE_TARGET   , "XOR-RESPONSE-TARGET"},
    {XOR_REFLECTED_FROM    , "XOR-REFELECTED-FROM"},
    {CONNECTION_ID         , "CONNECTION-ID"},
    {ICMP                  , "ICMP"},

    {MS_VERSION            , "MS-VERSION"},
    {MS_XOR_MAPPED_ADDRESS , "XOR-MAPPED-ADDRESS"},
    {SOFTWARE              , "SOFTWARE"},
    {ALTERNATE_SERVER      , "ALTERNATE-SERVER"},
    {CACHE_TIMEOUT         , "CACHE-TIMEOUT"},
    {FINGERPRINT           , "FINGERPRINT"},
    {ICE_CONTROLLED        , "ICE-CONTROLLED"},
    {ICE_CONTROLLING       , "ICE-CONTROLLING"},
    {RESPONSE_ORIGIN       , "RESPONSE-ORIGIN"},
    {OTHER_ADDRESS         , "OTHER-ADDRESS"},
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

#if 0
static const value_string attributes_properties_p[] = {
    {0, "All allocation"},
    {1, "Preserving allocation"},
    {0x00, NULL}
};
#endif

static const value_string attributes_family[] = {
    {0x0001, "IPv4"},
    {0x0002, "IPv6"},
    {0x00, NULL}
};
/* http://www.iana.org/assignments/stun-parameters/stun-parameters.xhtml#stun-parameters-6 (2015-06-12)*/

static const value_string error_code[] = {
    {274, "Disable Candidate"},               /* MS-ICE2BWN */
    {275, "Disable Candidate Pair"},          /* MS-ICE2BWN */
    {300, "Try Alternate"},                   /* rfc3489bis-15 */
    {400, "Bad Request"},                     /* rfc3489bis-15 */
    {401, "Unauthorized"},                    /* rfc3489bis-15 */
    {403, "Forbidden"},                       /* rfc5766 */
    {420, "Unknown Attribute"},               /* rfc3489bis-15 */
    {437, "Allocation Mismatch"},             /* turn-07 */
    {438, "Stale Nonce"},                     /* rfc3489bis-15 */
    {439, "Wrong Credentials"},               /* turn-07 - collision 38=>39 */
    {440, "Address Family not Supported"},    /* turn-ipv6-04 */
    {441, "Wrong Credentials"},               /* rfc5766 */
    {442, "Unsupported Transport Protocol"},  /* turn-07 */
    {443, "Peer Address Family Mismatch"},    /* rfc6156 */
    {446, "Connection Already Exists"},       /* rfc6062 */
    {447, "Connection Timeout or Failure"},   /* rfc6062 */
    {481, "Connection does not exist"},       /* nat-behavior-discovery-03 */
    {486, "Allocation Quota Reached"},        /* turn-07 */
    {487, "Role Conflict"},                   /* rfc5245 */
    {500, "Server Error"},                    /* rfc3489bis-15 */
    {503, "Service Unavailable"},             /* nat-behavior-discovery-03 */
    {507, "Insufficient Bandwidth Capacity"}, /* turn-07 */
    {508, "Insufficient Port Capacity"},      /* turn-07 */
    {600, "Global Failure"},
    {0x00, NULL}
};
static value_string_ext error_code_ext = VALUE_STRING_EXT_INIT(error_code);

static const value_string ms_version_vals[] = {
    {0x00000001, "ICE"},
    {0x00000002, "MS-ICE2"},
    {0x00000003, "MS-ICE2 with SHA256"},
    {0x00000004, "MS-ICE2 with SHA256 and IPv6"},
    {0x00, NULL}
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

static guint
get_stun_message_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                     int offset, void *data _U_)
{
    guint16 type;
    guint   length;
    guint   captured_length = tvb_captured_length(tvb);

    if ((captured_length >= TCP_FRAME_COOKIE_LEN) &&
        (tvb_get_ntohl(tvb, 6) == 0x2112a442)) {
        /* The magic cookie is off by two, this appears
           to be RFC4751 framing */
        return (tvb_get_ntohs(tvb, 0) + 2);
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
dissect_stun_message_channel_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 msg_type _U_, guint msg_length _U_)
{
    tvbuff_t *next_tvb;
    heur_dtbl_entry_t *hdtbl_entry;

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
    }

    next_tvb = tvb_new_subset_remaining(tvb, CHANNEL_DATA_HDR_LEN);

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
    guint16     att_type;
    guint16     att_length;
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

    /*
     * Check if the frame is really meant for us.
     */

    /* First, make sure we have enough data to do the check. */
    captured_length = tvb_captured_length(tvb);
    reported_length = tvb_reported_length(tvb);
    if (captured_length < MIN_HDR_LEN)
        return 0;

    tcp_framing_offset = 0;
    if ((!is_udp) && (captured_length >= TCP_FRAME_COOKIE_LEN) &&
       (tvb_get_ntohl(tvb, 6) == 0x2112a442)) {
        /* we found ICE TCP framing according to RFC 4571 */
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
         * Instead we have to have seen another TURN message type on the same
         * 5-tuple, and then set that conversation for non-heuristic STUN dissection.
         */
        if (heur_check)
            return 0;

        if (msg_type == 0xFFFF)
            return 0;

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

    /* Check if it is really a STUN message */
    if ( tvb_get_ntohl(tvb, tcp_framing_offset + 4) != 0x2112a442)
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

    msg_type_class = ((msg_type & 0x0010) >> 4) | ((msg_type & 0x0100) >> 7) ;
    msg_type_method = (msg_type & 0x000F) | ((msg_type & 0x00E0) >> 1) | ((msg_type & 0x3E00) >> 2);

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

    if (!pinfo->fd->flags.visited) {
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
        stun_trans=wmem_new(wmem_packet_scope(), stun_transaction_t);
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
            PROTO_ITEM_SET_GENERATED(it);
        }
        if (stun_trans->rep_frame) {
            proto_item *it;
            it=proto_tree_add_uint(stun_tree, hf_stun_response_in,
                                   tvb, offset, 0,
                                   stun_trans->rep_frame);
            PROTO_ITEM_SET_GENERATED(it);
        }
    }
    else {
        /* Retransmission control */
        if (stun_trans->rep_frame != pinfo->num) {
            proto_item *it;
            it=proto_tree_add_uint(stun_tree, hf_stun_duplicate,
                                   tvb, offset, 0,
                                   stun_trans->rep_frame);
            PROTO_ITEM_SET_GENERATED(it);
        }
        if (msg_type_class == RESPONSE || msg_type_class == ERROR_RESPONSE) {
            /* This is a response */
            if (stun_trans->req_frame) {
                proto_item *it;
                nstime_t ns;

                it=proto_tree_add_uint(stun_tree, hf_stun_response_to, tvb,
                                       offset, 0,
                                       stun_trans->req_frame);
                PROTO_ITEM_SET_GENERATED(it);

                nstime_delta(&ns, &pinfo->abs_ts, &stun_trans->req_time);
                it=proto_tree_add_time(stun_tree, hf_stun_time, tvb,
                                       offset, 0, &ns);
                PROTO_ITEM_SET_GENERATED(it);
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

    if (msg_length != 0) {
        const gchar       *attribute_name_str;

        ti = proto_tree_add_item(stun_tree, hf_stun_attributes, tvb, offset, msg_length, ENC_NA);
        att_all_tree = proto_item_add_subtree(ti, ett_stun_att_all);

        while (offset < (STUN_HDR_LEN + msg_length)) {
            att_type = tvb_get_ntohs(tvb, offset);     /* Type field in attribute header */
            att_length = tvb_get_ntohs(tvb, offset+2); /* Length field in attribute header */
            attribute_name_str = val_to_str_ext_const(att_type, &attributes_ext, "Unknown");
            if(att_all_tree){
                ti = proto_tree_add_uint_format(att_all_tree, hf_stun_attr,
                                                tvb, offset, ATTR_HDR_LEN+att_length,
                                                att_type, "%s", attribute_name_str);
                att_tree = proto_item_add_subtree(ti, ett_stun_att);
                ti = proto_tree_add_uint(att_tree, hf_stun_att_type, tvb,
                                         offset, 2, att_type);
                att_type_tree = proto_item_add_subtree(ti, ett_stun_att_type);
                proto_tree_add_uint(att_type_tree, hf_stun_att_type_comprehension, tvb, offset, 2, att_type);
                proto_tree_add_uint(att_type_tree, hf_stun_att_type_assignment, tvb, offset, 2, att_type);

                if ((offset+ATTR_HDR_LEN+att_length) > (STUN_HDR_LEN+msg_length+tcp_framing_offset)) {
                    proto_tree_add_uint_format_value(att_tree,
                                                     hf_stun_att_length, tvb, offset+2, 2,
                                                     att_length,
                                                     "%u (bogus, goes past the end of the message)",
                                                     att_length);
                    break;
                }
            }
            offset += 2;

            proto_tree_add_uint(att_tree, hf_stun_att_length, tvb,
                                offset, 2, att_length);
            offset += 2;

            switch (att_type) {

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
                    proto_item_append_text(att_tree, " (Deprecated): %s:%d", tvb_ip_to_str(tvb, offset+4),tvb_get_ntohs(tvb,offset+2));

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
                const guint8* dep_password;
                proto_tree_add_item_ret_string(att_tree, hf_stun_att_password, tvb, offset, att_length, ENC_UTF_8|ENC_NA, wmem_packet_scope(), &dep_password);
                proto_item_append_text(att_tree, " (Deprecated): %s", dep_password);
                if (att_length % 4 != 0)
                    proto_tree_add_uint(att_tree, hf_stun_att_padding,
                                        tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
                }
                break;

            case MAPPED_ADDRESS:
            case ALTERNATE_SERVER:
            case RESPONSE_ORIGIN:
            case OTHER_ADDRESS:
            case MS_ALT_MAPPED_ADDRESS:
            {
                const gchar       *addr_str;
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
                    addr_str = tvb_ip_to_str(tvb, offset + 4);
                    proto_tree_add_item(att_tree, hf_stun_att_ipv4, tvb, offset+4, 4, ENC_BIG_ENDIAN);
                    proto_item_append_text(att_tree, ": %s:%d", addr_str, att_port);
                    col_append_fstr(
                        pinfo->cinfo, COL_INFO,
                        " %s: %s:%d",
                        attribute_name_str,
                        addr_str,
                        att_port
                        );
                    break;

                case 2:
                    if (att_length < 20)
                        break;
                    proto_tree_add_item(att_tree, hf_stun_att_ipv6, tvb, offset+4, 16, ENC_NA);
                    break;
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
                const guint8 *user_name_str;

                proto_tree_add_item_ret_string(att_tree, hf_stun_att_username, tvb, offset, att_length, ENC_UTF_8|ENC_NA, wmem_packet_scope(), &user_name_str);
                proto_item_append_text(att_tree, ": %s", user_name_str);
                col_append_fstr(
                    pinfo->cinfo, COL_INFO,
                    " user: %s",
                    user_name_str);

                if (att_length % 4 != 0)
                    proto_tree_add_uint(att_tree, hf_stun_att_padding,
                                        tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
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
                proto_tree_add_item_ret_string(att_tree, hf_stun_att_error_reason, tvb, offset + 4, att_length - 4, ENC_UTF_8 | ENC_NA, wmem_packet_scope(), &error_reas_str);

                proto_item_append_text(att_tree, ": %s", error_reas_str);
                col_append_fstr(pinfo->cinfo, COL_INFO, " %s", error_reas_str);
                }

                if (att_length % 4 != 0)
                    proto_tree_add_uint(att_tree, hf_stun_att_padding, tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
                break;

            case UNKNOWN_ATTRIBUTES:
                for (i = 0; i < att_length; i += 2)
                    proto_tree_add_item(att_tree, hf_stun_att_unknown, tvb, offset+i, 2, ENC_BIG_ENDIAN);
                if (att_length % 4 != 0)
                    proto_tree_add_uint(att_tree, hf_stun_att_padding, tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
                break;

            case REALM:
            {
                const guint8 *realm_str;
                proto_tree_add_item_ret_string(att_tree, hf_stun_att_realm, tvb, offset, att_length, ENC_UTF_8|ENC_NA, wmem_packet_scope(), &realm_str);
                proto_item_append_text(att_tree, ": %s", realm_str);
                col_append_fstr(pinfo->cinfo, COL_INFO, " realm: %s", realm_str);
                if (att_length % 4 != 0)
                    proto_tree_add_uint(att_tree, hf_stun_att_padding, tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
                break;
            }
            case NONCE:
            {
                const guint8 *nonce_str;
                proto_tree_add_item_ret_string(att_tree, hf_stun_att_nonce, tvb, offset, att_length, ENC_UTF_8|ENC_NA, wmem_packet_scope(), &nonce_str);
                proto_item_append_text(att_tree, ": %s", nonce_str);
                col_append_str(pinfo->cinfo, COL_INFO, " with nonce");
                if (att_length % 4 != 0)
                    proto_tree_add_uint(att_tree, hf_stun_att_padding, tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
                break;
            }

            case XOR_MAPPED_ADDRESS:
            case XOR_PEER_ADDRESS:
            case XOR_RELAYED_ADDRESS:
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
                ti = proto_tree_add_uint(att_tree, hf_stun_att_port, tvb, offset+2, 2,
                                         tvb_get_ntohs(tvb, offset+2) ^ (magic_cookie_first_word >> 16));
                PROTO_ITEM_SET_GENERATED(ti);

                if (att_length < 8)
                    break;
                switch (tvb_get_guint8(tvb, offset+1)) {
                case 1:
                    proto_tree_add_item(att_tree, hf_stun_att_xor_ipv4, tvb, offset+4, 4, ENC_NA);

                    /* Show the address 'in the clear'.
                       XOR (host order) transid with (host order) xor-address.
                       Add in network order tree. */
                    ti = proto_tree_add_ipv4(att_tree, hf_stun_att_ipv4, tvb, offset+4, 4,
                                             tvb_get_ipv4(tvb, offset+4) ^ g_htonl(magic_cookie_first_word));
                    PROTO_ITEM_SET_GENERATED(ti);

                    {
                        const gchar *ipstr;
                        address addr;
                        guint32 ip;
                        guint16 port;
                        ip = tvb_get_ipv4(tvb, offset+4) ^ g_htonl(magic_cookie_first_word);
                        set_address(&addr, AT_IPv4, 4, &ip);
                        ipstr = address_to_str(wmem_packet_scope(), &addr);
                        port = tvb_get_ntohs(tvb, offset+2) ^ (magic_cookie_first_word >> 16);
                        proto_item_append_text(att_tree, ": %s:%d", ipstr, port);
                        col_append_fstr(
                            pinfo->cinfo, COL_INFO,
                            " %s: %s:%d",
                            attribute_name_str,
                            ipstr,
                            port
                            );
                    }
                    break;

                case 2:
                    if (att_length < 20)
                        break;
                    proto_tree_add_item(att_tree, hf_stun_att_xor_ipv6, tvb, offset+4, 16, ENC_NA);
                    {
                        guint32 IPv6[4];
                        tvb_get_ipv6(tvb, offset+4, (struct e_in6_addr *)IPv6);
                        IPv6[0] = IPv6[0] ^ g_htonl(magic_cookie_first_word);
                        IPv6[1] = IPv6[1] ^ g_htonl(transaction_id[0]);
                        IPv6[2] = IPv6[2] ^ g_htonl(transaction_id[1]);
                        IPv6[3] = IPv6[3] ^ g_htonl(transaction_id[2]);
                        ti = proto_tree_add_ipv6(att_tree, hf_stun_att_ipv6, tvb, offset+4, 16,
                                                 (const struct e_in6_addr *)IPv6);
                        PROTO_ITEM_SET_GENERATED(ti);
                    }

                    break;
                }
                break;

            case REQUESTED_ADDRESS_TYPE:
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
                break;

            case RESERVATION_TOKEN:
                if (att_length < 8)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_token, tvb, offset, 8, ENC_NA);
                break;

            case PRIORITY:
                if (att_length < 4)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_priority, tvb, offset, 4, ENC_BIG_ENDIAN);
                break;

            case PADDING:
                proto_tree_add_uint(att_tree, hf_stun_att_padding, tvb, offset, att_length, att_length);
                break;

            case ICMP:
                if (att_length < 4)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_icmp_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(att_tree, hf_stun_att_icmp_code, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                break;

            case SOFTWARE:
                proto_tree_add_item(att_tree, hf_stun_att_software, tvb, offset, att_length, ENC_UTF_8|ENC_NA);
                if (att_length % 4 != 0)
                    proto_tree_add_uint(att_tree, hf_stun_att_padding, tvb, offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
                break;

            case CACHE_TIMEOUT:
                if (att_length < 4)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_cache_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
                break;

            case FINGERPRINT:
                if (att_length < 4)
                    break;
                proto_tree_add_item(att_tree, hf_stun_att_crc32, tvb, offset, att_length, ENC_BIG_ENDIAN);
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
                    if (att_length % 4 != 0) {
                        guint pad;
                        pad = 4-(att_length % 4);
                        proto_tree_add_uint(att_tree, hf_stun_att_padding, tvb, offset+att_length, pad, pad);
                    }

                    next_tvb = tvb_new_subset_length(tvb, offset, att_length);

                    if (!dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, att_tree, &hdtbl_entry, NULL)) {
                        call_dissector_only(data_handle, next_tvb, pinfo, att_tree, NULL);
                    }

                }
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
                break;

            case MS_VERSION:
            case MS_IMPLEMENTATION_VER:
                proto_tree_add_item(att_tree, hf_stun_att_ms_version, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_item_append_text(att_tree, ": %s", val_to_str(tvb_get_ntohl(tvb, offset), ms_version_vals, "Unknown (0x%u)"));
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
                proto_tree_add_item(att_tree, hf_stun_att_ms_foundation, tvb, offset, 4, ENC_ASCII|ENC_NA);
                break;

            default:
                if (att_length > 0)
                    proto_tree_add_item(att_tree, hf_stun_att_value, tvb, offset, att_length, ENC_NA);
                if (att_length % 4 != 0)
                    proto_tree_add_uint(att_tree, hf_stun_att_padding, tvb,
                                        offset+att_length, 4-(att_length % 4), 4-(att_length % 4));
                break;
            }
            offset += (att_length+3) & ~0x3;
        }
    }

    if (heur_check && is_turn && conversation) {
        /*
         * When in heuristic dissector mode, if this is a TURN message, set
         * the 5-tuple conversation to always decode as non-heuristic. The
         * odds of incorrectly identifying a random packet as a TURN message
         * (other than ChannelData) is incredibly small. A ChannelData message
         * won't be matched when in heuristic mode, so heur_check can't be true
         * in that case and get to this part of the code.
         */
        if (pinfo->ptype == PT_TCP) {
            conversation_set_dissector(conversation, stun_tcp_handle);
        } else if (pinfo->ptype == PT_UDP) {
            conversation_set_dissector(conversation, stun_udp_handle);
        }
    }

    if (!PINFO_FD_VISITED(pinfo) && is_turn && (pinfo->ptype == PT_TCP)
        && (msg_type_method == CONNECTION_BIND) && (msg_type_class == RESPONSE)) {
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
dissect_stun_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    if (dissect_stun_message(tvb, pinfo, tree, TRUE, TRUE) == 0) {
        /*
         * It wasn't a valid STUN message, and wasn't
         * dissected as such.
         */
        return FALSE;
    }
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
            BASE_DEC, NULL, 0x0, NULL, HFILL }
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
            BASE_HEX | BASE_EXT_STRING, &attributes_ext, 0x0, NULL, HFILL }
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
        { &hf_stun_att_password,
          { "Password", "stun.att.password", FT_STRING,
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
            BASE_DEC, NULL, 0x0, NULL, HFILL}
         },
        { &hf_stun_att_change_ip,
          { "Change IP","stun.att.change-ip", FT_BOOLEAN,
            16, TFS(&tfs_set_notset), 0x0004, NULL, HFILL}
        },
        { &hf_stun_att_change_port,
          { "Change Port","stun.att.change-port", FT_BOOLEAN,
            16, TFS(&tfs_set_notset), 0x0002, NULL, HFILL}
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
            BASE_DEC, NULL, 0x0, NULL, HFILL }
        },

        { &hf_stun_att_ms_version,
          { "MS Version", "stun.att.ms.version", FT_UINT32,
            BASE_DEC, VALS(ms_version_vals), 0x0, NULL, HFILL}
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
          { "PSTN", "stun.att.address_rp.valid", FT_BOOLEAN,
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
          { "Maximum Send Bandwidth", "stun.att.adress_rp.masb", FT_UINT32,
            BASE_DEC, NULL, 0x0, "In kilobits per second", HFILL}
         },
        { &hf_stun_att_address_rp_marb,
          { "Maximum Receive Bandwidth", "stun.att.adress_rp.marb", FT_UINT32,
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
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_stun,
        &ett_stun_type,
        &ett_stun_att_all,
        &ett_stun_att,
        &ett_stun_att_type,
    };

    /* Register the protocol name and description */
    proto_stun = proto_register_protocol("Session Traversal Utilities for NAT", "STUN", "stun");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_stun, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* heuristic subdissectors (used for the DATA field) */
    heur_subdissector_list = register_heur_dissector_list("stun", proto_stun);

    register_dissector("stun-udp", dissect_stun_udp, proto_stun);
    register_dissector("stun-heur", dissect_stun_heur, proto_stun);
}

void
proto_reg_handoff_stun(void)
{
    stun_tcp_handle = create_dissector_handle(dissect_stun_tcp, proto_stun);
    stun_udp_handle = create_dissector_handle(dissect_stun_udp, proto_stun);

    dissector_add_uint("tcp.port", TCP_PORT_STUN, stun_tcp_handle);
    dissector_add_uint("udp.port", UDP_PORT_STUN, stun_udp_handle);

    /* Used for "Decode As" in case STUN negotiation isn't captured */
    dissector_add_for_decode_as("tcp.port", stun_tcp_handle);
    dissector_add_for_decode_as("udp.port", stun_udp_handle);

    heur_dissector_add("udp", dissect_stun_heur, "STUN over UDP", "stun_udp", proto_stun, HEURISTIC_ENABLE);

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
