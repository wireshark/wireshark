/* packet-sdp.c
 * Routines for SDP packet disassembly (RFC 2327)
 *
 * Jason Lango <jal@netapp.com>
 * Liberally copied from packet-http.c, by Guy Harris <guy@alum.mit.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Ref https://www.ietf.org/rfc/rfc4566
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/tap.h>
#include <epan/rtp_pt.h>
#include <epan/show_exception.h>
#include <epan/addr_resolv.h>
#include <epan/conversation.h>
#include <epan/proto_data.h>
#include <epan/strutil.h>

#include <wsutil/strtoi.h>
#include <wsutil/str_util.h>

#include "packet-media-type.h"
#include "packet-sdp.h"

/* un-comment the following as well as this line in conversation.c, to enable debug printing */
/* #define DEBUG_CONVERSATION */
#include "conversation_debug.h"

#include "packet-rtp.h"

#include "packet-rtcp.h"
#include "packet-t38.h"
#include "packet-msrp.h"
#include "packet-sprt.h"
#include "packet-bfcp.h"
#include "packet-h245.h"
#include "packet-h264.h"
#include "packet-h265.h"
#include "packet-mp4ves.h"

void proto_register_sdp(void);
void proto_reg_handoff_sdp(void);

static dissector_handle_t sdp_handle;
static dissector_handle_t rtcp_handle;
static dissector_handle_t sprt_handle;
static dissector_handle_t msrp_handle;
static dissector_handle_t bfcp_handle;
static dissector_handle_t h264_handle;
static dissector_handle_t h265_handle;
static dissector_handle_t mp4ves_config_handle;

static int sdp_tap;

static int proto_sdp;
static int proto_sprt;

static const char* UNKNOWN_ENCODING = "Unknown";
static wmem_tree_t *sdp_transport_reqs;
static wmem_tree_t *sdp_transport_rsps;

/* preference globals */
static bool global_sdp_establish_conversation = true;

/* Top level fields */
static int hf_protocol_version;
static int hf_owner;
static int hf_session_name;
static int hf_session_info;
static int hf_uri;
static int hf_email;
static int hf_phone;
static int hf_connection_info;
static int hf_bandwidth;
static int hf_timezone;
static int hf_encryption_key;
static int hf_session_attribute;
static int hf_media_attribute;
static int hf_time;
static int hf_repeat_time;
static int hf_media;
static int hf_media_title;
static int hf_unknown;
static int hf_invalid;
static int hf_ipbcp_version;
static int hf_ipbcp_type;

/* hf_owner subfields*/
static int hf_owner_username;
static int hf_owner_sessionid;
static int hf_owner_version;
static int hf_owner_network_type;
static int hf_owner_address_type;
static int hf_owner_address;

/* hf_connection_info subfields */
static int hf_connection_info_network_type;
static int hf_connection_info_address_type;
static int hf_connection_info_connection_address;
static int hf_connection_info_ttl;
static int hf_connection_info_num_addr;

/* hf_bandwidth subfields */
static int hf_bandwidth_modifier;
static int hf_bandwidth_value;

/* hf_time subfields */
static int hf_time_start;
static int hf_time_stop;

/* hf_repeat_time subfield */
static int hf_repeat_time_interval;
static int hf_repeat_time_duration;
static int hf_repeat_time_offset;

/* hf_timezone subfields */
static int hf_timezone_time;
static int hf_timezone_offset;

/* hf_encryption_key subfields */
static int hf_encryption_key_type;
static int hf_encryption_key_data;

/* hf_session_attribute subfields */
static int hf_session_attribute_field;
static int hf_session_attribute_value;

/* hf_media subfields */
static int hf_media_media;
static int hf_media_port;
static int hf_media_port_string;
static int hf_media_portcount;
static int hf_media_proto;
static int hf_media_format;

/* hf_session_attribute subfields */
static int hf_media_attribute_field;
static int hf_media_attribute_value;
static int hf_media_encoding_name;
static int hf_media_sample_rate;
static int hf_media_channels;
static int hf_media_format_specific_parameter;
static int hf_sdp_fmtp_mpeg4_profile_level_id;
static int hf_sdp_fmtp_h263_profile;
static int hf_sdp_fmtp_h263_level;
static int hf_sdp_h264_packetization_mode;
static int hf_SDPh223LogicalChannelParameters;

/* hf_session_attribute hf_media_attribute subfields */
static int hf_key_mgmt_att_value;
static int hf_key_mgmt_prtcl_id;
static int hf_key_mgmt_data;

static int hf_sdp_crypto_tag;
static int hf_sdp_crypto_crypto_suite;
static int hf_sdp_crypto_master_key;
static int hf_sdp_crypto_master_salt;
static int hf_sdp_crypto_lifetime;
static int hf_sdp_crypto_mki;
static int hf_sdp_crypto_mki_length;

/* a=candidate subfields */
static int hf_ice_candidate_foundation;
static int hf_ice_candidate_componentid;
static int hf_ice_candidate_transport;
static int hf_ice_candidate_priority;
static int hf_ice_candidate_address;
static int hf_ice_candidate_port;
static int hf_ice_candidate_type;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_sdp_nal_unit_2_string;
static int hf_sdp_key_and_salt;
static int hf_sdp_nal_unit_1_string;
static int hf_sdp_data;

/* trees */
static int ett_sdp;
static int ett_sdp_owner;
static int ett_sdp_connection_info;
static int ett_sdp_bandwidth;
static int ett_sdp_time;
static int ett_sdp_repeat_time;
static int ett_sdp_timezone;
static int ett_sdp_encryption_key;
static int ett_sdp_session_attribute;
static int ett_sdp_media;
static int ett_sdp_media_attribute;
static int ett_sdp_fmtp;
static int ett_sdp_key_mgmt;
static int ett_sdp_crypto_key_parameters;

static expert_field ei_sdp_invalid_key_param;
static expert_field ei_sdp_invalid_line_equal;
static expert_field ei_sdp_invalid_line_fields;
static expert_field ei_sdp_invalid_line_space;
static expert_field ei_sdp_invalid_conversion;
static expert_field ei_sdp_invalid_media_port;
static expert_field ei_sdp_invalid_sample_rate;
static expert_field ei_sdp_invalid_channels;
static expert_field ei_sdp_invalid_media_format;
static expert_field ei_sdp_invalid_crypto_tag;
static expert_field ei_sdp_invalid_crypto_mki_length;

/* patterns used for tvb_ws_mempbrk_pattern_guint8 */
static ws_mempbrk_pattern pbrk_digits;
static ws_mempbrk_pattern pbrk_alpha;

typedef enum {
    SDP_PROTO_UNKNOWN = 0,
    SDP_PROTO_RTP,
    SDP_PROTO_SRTP,
    SDP_PROTO_T38,
    SDP_PROTO_MSRP,
    SDP_PROTO_SPRT,
    SDP_PROTO_BFCP,
} transport_proto_t;


#define SDP_MAX_RTP_CHANNELS 4
#define SDP_MAX_RTP_PAYLOAD_TYPES 20
#define SDP_NO_OF_PT 128
/*
 * All parameters specific to one media description ("m=").
 */
typedef struct {
    int32_t pt[SDP_MAX_RTP_PAYLOAD_TYPES];
    int8_t pt_count;
    rtp_dyn_payload_t *rtp_dyn_payload;
    bool set_rtp;
} transport_media_pt_t;

/*
 * Store data extracted from one Media Description section of a SDP. Memory is
 * allocated in wmem_file_scope().
 */
typedef struct {
    transport_proto_t proto;    /**< Protocol, parsed from "m=" line. */
    uint32_t media_types;        /**< Whether "m=video" or others */
    bool bundled;           /**< "m=" lines are "bundled", that is, all on same port */
    uint16_t media_port;         /**< Port number, parsed from "m=" line. */
    uint16_t control_port;       /**< Port number, parsed from "a=rtcp" or "a=rtcp-mux" line. */
    address conn_addr;          /**< The address from the "c=" line (default
                                     from session level, possibly overridden at
                                     the media level). */
    transport_media_pt_t media; /**< Information about payload numbers for this media. */

    /*
     * Media-level only attributes.
     */
    union {
        struct {
            address ipaddr;
            uint16_t port_number;
        } msrp;                 /**< MSRP transport info, parsed from "a=label:" */
    } media_attr;
} media_description_t;

/*
 * Information parsed from one or two (offer/answer) SDPs that is stored in the
 * conversation. The contents are allocated within wmem_file_scope().
 */
typedef struct {
    enum sdp_exchange_type sdp_status;
    char  *encoding_name[SDP_NO_OF_PT];
    int    sample_rate[SDP_NO_OF_PT];
    unsigned channels[SDP_NO_OF_PT];

    /* Data parsed from "m=" */
    wmem_array_t *media_descriptions;   /* array of media_description_t */

    wmem_array_t *sdp_setup_info_list;  /* array of sdp_setup_info_t that refer
                                         * to the same RTP conversation */

    /* SRTP related info XXX note currently we only handle one crypto line in the SDP
    * We should probably handle offer/answer and session updates etc(SIP) quite possibly the whole handling of
    * seting up the RTP conversations should be done by the signaling protocol(s) calling the SDP dissector
    * and the SDP dissector just provide the relevant data.
    * YES! packet-sdp.c should be about SDP parsing... SDP *state* needs to be maintained by upper
    * protocols, because each one has different rules/semantics.
    */
    unsigned  encryption_algorithm;
    unsigned  auth_algorithm;
    unsigned  mki_len;                /* number of octets used for the MKI in the RTP payload */
    unsigned  auth_tag_len;           /* number of octets used for the Auth Tag in the RTP payload */
} transport_info_t;

/*
 * Information about the session description. These are accumulated while
 * parsing the session description and will be applied to the media description.
 * Memory scope can be pinfo->pool since the contents are no longer
 * needed once they are processed into transport_info_t (via
 * complete_descriptions).
 */
typedef struct {
    address conn_addr;         /**< Parsed from "c=" line. */
    rtp_dyn_payload_t *rtp_dyn_payload; /**< Parsed from "a=rtpmap:" line.
                                             Note: wmem_file_scope, needs manual dealloc. */
} session_info_t;

/* Structure for private data to hold ED137 related values */
typedef struct sdp_data_t {
  char *ed137_type;           /* Radio session type */
  char *ed137_txrxmode;       /* Tx/Rx mode */
  char *ed137_fid;            /* Frequency ID */
} sdp_data_t;


/* here lie the debugging dumper functions */
#ifdef DEBUG_CONVERSATION
static void sdp_dump_transport_media(const transport_media_pt_t* media) {
    int i;
    int count;
    DPRINT2(("transport_media contents:"));
    DINDENT();
        if (!media) {
            DPRINT2(("null transport_media_pt_t*"));
            DENDENT();
            return;
        }
        count = (int)media->pt_count;
        DPRINT2(("pt_count=%d",count));
        DINDENT();
            for (i=0; i < count; i++) {
                DPRINT2(("pt=%d", media->pt[i]));
            }
        DENDENT();
        DPRINT2(("rtp_dyn_payload hashtable=%s", media->rtp_dyn_payload ? "YES" : "NO"));
        if (media->rtp_dyn_payload) {
            rtp_dump_dyn_payload(media->rtp_dyn_payload);
        }
        DPRINT2(("set_rtp=%s", media->set_rtp ? "TRUE" : "FALSE"));
    DENDENT();
}

static const value_string sdp_exchange_type_vs[] = {
    { SDP_EXCHANGE_OFFER,         "SDP_EXCHANGE_OFFER" },
    { SDP_EXCHANGE_ANSWER_ACCEPT, "SDP_EXCHANGE_ANSWER_ACCEPT" },
    { SDP_EXCHANGE_ANSWER_REJECT, "SDP_EXCHANGE_ANSWER_REJECT" },
    { 0, NULL }
};

static void sdp_dump_transport_info(const transport_info_t* info) {
    int i;
    int count;
    DPRINT2(("transport_info contents:"));
    DINDENT();
        if (!info) {
            DPRINT2(("null transport_info_t*"));
            DENDENT();
            return;
        }
        DPRINT2(("sdp_status=%s",
                 val_to_str_const(info->sdp_status, sdp_exchange_type_vs, "SDP_EXCHANGE_UNKNOWN")));
        DPRINT2(("payload type contents:"));
        DINDENT();
            for (i=0; i < SDP_NO_OF_PT; i++) {
                /* don't print out unknown encodings */
                if (info->encoding_name[i] &&
                    strcmp(UNKNOWN_ENCODING,info->encoding_name[i]) != 0) {
                    DPRINT2(("payload type #%d:",i));
                    DINDENT();
                        DPRINT2(("encoding_name=%s", info->encoding_name[i]));
                        DPRINT2(("sample_rate=%d", info->sample_rate[i]));
                    DENDENT();
                }
            }
        DENDENT();
        count = wmem_array_get_count(info->media_descriptions);
        DPRINT2(("media_count=%d", count));
        DPRINT2(("rtp channels:"));
        DINDENT();
            for (i=0; i < count; i++) {
                media_description_t *media_desc = (media_description_t *)wmem_array_index(info->media_descriptions, i);
                DPRINT2(("channel #%d:",i));
                DINDENT();
                    DPRINT2(("conn_addr=%s", address_to_str(pinfo->pool, &(media_desc->conn_addr))));
                    DPRINT2(("media_port=%d", media_desc->media_port));
                    DPRINT2(("proto=%d", media_desc->proto));
                    sdp_dump_transport_media(&(media_desc->media));
                DENDENT();
            }
        DENDENT();
        DPRINT2(("encryption_algorithm=%u", info->encryption_algorithm));
        DPRINT2(("auth_algorithm=%u", info->auth_algorithm));
        if (info->encryption_algorithm || info->auth_algorithm) {
            DPRINT2(("mki_len=%u", info->mki_len));
            if (info->auth_algorithm) {
                DPRINT2(("auth_tag_len=%u", info->auth_tag_len));
            }
        }
    DENDENT();
}

#endif /* DEBUG_CONVERSATION */


/* key-mgmt dissector
 * IANA registry:
 * http://www.iana.org/assignments/sdp-parameters
 */
static dissector_table_t key_mgmt_dissector_table;

/* Finds next token (sequence of non-space chars) in tvb from given offset.
 * The returned value is the token length, or 0 if none found.
 * The offset is changed to be the starting offset, in case there were one or more
 * spaces at the beginning. (this will also add expert info in such a case)
 * The next_offset is set to the next found space after the token, or -1 if the
 * end of line is hit or no token found.
 * If this is the last token in the line, tokenlen will not be 0, but next_offset
 * will be -1.
 *
 * The optional param, if true, means no expert error will be issued if no token
 * is found; if false then a expert error will be issued if no token is found.
 *
 * This function expects to be given a tvb of only one line, and does no error
 * checking of its given arguments.
 */
static inline int
find_next_optional_token_in_line(tvbuff_t *tvb, proto_tree *tree,
                                 int *offset, int *next_offset,
                                 const bool optional)
{
    int tokenlen = 0;
    int next_off = -1;
    int off      = *offset;

    if (tvb_offset_exists(tvb, off)) {
        while (tokenlen == 0) {
            next_off = tvb_find_guint8(tvb, off, -1, ' ');
            if (next_off == -1) {
                tokenlen = tvb_captured_length_remaining(tvb, off);
                break; /* Nothing more left */
            }

            tokenlen = next_off - off;

            if (tokenlen == 0) {
                /* two spaces in a row - illegal, but we'll keep dissecting */
                proto_tree_add_expert(tree, NULL, &ei_sdp_invalid_line_space, tvb, off-1, 2);
                off = next_off + 1;
            }
        }
    }

    if (!optional && tokenlen == 0) {
        proto_tree_add_expert(tree, NULL, &ei_sdp_invalid_line_fields, tvb, 0, -1);
    }

    *next_offset = next_off;
    *offset      = off;
    return tokenlen;
}

/* Same as above, but always issues an expert error if a token is not found. */
static inline int
find_next_token_in_line(tvbuff_t *tvb, proto_tree *tree, int *offset, int *next_offset)
{
    return find_next_optional_token_in_line(tvb, tree, offset, next_offset, false);
}

/* Convert the protocol from the "m=" line to something we understand. */
static transport_proto_t
parse_sdp_media_protocol(const char *media_proto)
{
    /* Sorted according to the "proto" registry at
     * https://www.iana.org/assignments/sdp-parameters/sdp-parameters.xhtml#sdp-parameters-2 */
    const struct {
        const char *proto_name;
        transport_proto_t proto;
    } protocols[] = {
        { "RTP/AVP",            SDP_PROTO_RTP }, /* RFC 4566 */
        { "udptl",              SDP_PROTO_T38 }, /* ITU-T T.38, example in Annex E */
        { "UDPTL",              SDP_PROTO_T38 }, /* Note: IANA registry contains lower case */
        { "RTP/AVPF",           SDP_PROTO_RTP }, /* RFC 4585 */
        { "RTP/SAVP",           SDP_PROTO_SRTP }, /* RFC 3711 */
        { "RTP/SAVPF",          SDP_PROTO_SRTP }, /* RFC 5124 */
        { "UDP/TLS/RTP/SAVP",   SDP_PROTO_SRTP }, /* RFC 5764 */
        { "UDP/TLS/RTP/SAVPF",  SDP_PROTO_SRTP }, /* RFC 5764 */
        { "msrp/tcp",           SDP_PROTO_MSRP }, /* Not in IANA, where is this from? */
        { "UDPSPRT",            SDP_PROTO_SPRT }, /* Not in IANA, but draft-rajeshkumar-avt-v150-registration-00 */
        { "udpsprt",            SDP_PROTO_SPRT }, /* lowercase per section E.1.1 of ITU-T V.150.1 */
        { "udpsprt",            SDP_PROTO_SPRT }, /* lowercase per section E.1.1 of ITU-T V.150.1 */
        { "UDP/BFCP",           SDP_PROTO_BFCP }, /* RFC 8856 */
    };

    for (unsigned i = 0; i < G_N_ELEMENTS(protocols); i++) {
        if (!strcmp(protocols[i].proto_name, media_proto)) {
            return protocols[i].proto;
        }
    }

    return SDP_PROTO_UNKNOWN;
}

/* Parses the parts from "c=" into address structures. */
static void
parse_sdp_connection_address(const uint8_t *connection_type, const char *connection_address,
        wmem_allocator_t *allocator, address *conn_addr)
{
    if (strcmp(connection_type, "IP4") == 0) {
        uint32_t ip4_addr;

        if (str_to_ip(connection_address, &ip4_addr)) {
            /* connection_address could be converted to a valid ipv4 address*/
            alloc_address_wmem(allocator, conn_addr, AT_IPv4, 4, &ip4_addr);
        }
    } else if (strcmp(connection_type, "IP6") == 0) {
        ws_in6_addr ip6_addr;

        if (str_to_ip6(connection_address, &ip6_addr)) {
            /* connection_address could be converted to a valid ipv6 address*/
            alloc_address_wmem(allocator, conn_addr, AT_IPv6, 16, &ip6_addr);
        }
    }
}

/**
 * Starts a new media description. If there are too many media descriptions,
 * no new media description is started and NULL is returned.
 */
static media_description_t *
sdp_new_media_description(wmem_array_t *media_descriptions, session_info_t *session_info)
{
    media_description_t empty_desc;
    media_description_t *media_desc;

    /* Limit number to avoid consuming excess memory. */
    if (wmem_array_get_count(media_descriptions) >= SDP_MAX_RTP_CHANNELS) {
        DPRINT(("Too many media descriptions (more than %d), returning NULL!",
                wmem_array_get_count(media_descriptions)));
        return NULL;
    }

    memset(&empty_desc, 0, sizeof(media_description_t));
    wmem_array_append_one(media_descriptions, empty_desc);
    media_desc = (media_description_t *) wmem_array_index(media_descriptions,
            wmem_array_get_count(media_descriptions) - 1);

    /* XXX does it make sense making media_desc->media.pt a wmem array? */

    /* If "c=" is given at the session level, copy it to the media description.
     * It will be overridden as needed. */
    if (session_info->conn_addr.type != AT_NONE) {
        copy_address_wmem(wmem_file_scope(), &media_desc->conn_addr, &session_info->conn_addr);
    }

    /* If "a=rtpmap:" was set on the session level, copy them to media level. */
    media_desc->media.rtp_dyn_payload =
        rtp_dyn_payload_dup(session_info->rtp_dyn_payload);

    return media_desc;
}

/* Remove information about media descriptions which are unused. These appeared
 * in the "a=rtpmap:" (and maybe even in the payload types part of "m="?), but
 * are not used (port is zero or it was not assigned to RTP dissector). */
static void
clean_unused_media_descriptions(wmem_array_t *descs)
{
    for (unsigned i = 0; i < wmem_array_get_count(descs); i++) {
        media_description_t *media_desc = (media_description_t *)wmem_array_index(descs, i);

        /* If not assigned to subdissector, clear the unused information. */
        if (!media_desc->media.set_rtp) {
            rtp_dyn_payload_free(media_desc->media.rtp_dyn_payload);
            media_desc->media.rtp_dyn_payload = NULL;
        }
    }
}


/* Subdissector functions */
static void
dissect_sdp_owner(tvbuff_t *tvb, proto_item *ti) {
    proto_tree *sdp_owner_tree;
    int         offset, next_offset, tokenlen;

    offset = 0;

    sdp_owner_tree = proto_item_add_subtree(ti, ett_sdp_owner);

    /* Find the username */
    tokenlen = find_next_token_in_line(tvb, sdp_owner_tree, &offset, &next_offset);
    if (tokenlen == 0)
        return;

    proto_tree_add_item(sdp_owner_tree, hf_owner_username, tvb, offset, tokenlen,
                        ENC_UTF_8);
    offset = next_offset  + 1;

    /* Find the session id */
    tokenlen = find_next_token_in_line(tvb, sdp_owner_tree, &offset, &next_offset);
    if (tokenlen == 0)
        return;

    proto_tree_add_item(sdp_owner_tree, hf_owner_sessionid, tvb, offset,
                        tokenlen, ENC_UTF_8);
    offset = next_offset + 1;

    /* Find the version */
    tokenlen = find_next_token_in_line(tvb, sdp_owner_tree, &offset, &next_offset);
    if (tokenlen == 0)
        return;

    proto_tree_add_item(sdp_owner_tree, hf_owner_version, tvb, offset, tokenlen,
                        ENC_UTF_8);
    offset = next_offset + 1;

    /* Find the network type */
    tokenlen = find_next_token_in_line(tvb, sdp_owner_tree, &offset, &next_offset);
    if (tokenlen == 0)
        return;

    proto_tree_add_item(sdp_owner_tree, hf_owner_network_type, tvb, offset,
                        tokenlen, ENC_UTF_8);
    offset = next_offset + 1;

    /* Find the address type */
    tokenlen = find_next_token_in_line(tvb, sdp_owner_tree, &offset, &next_offset);
    if (tokenlen == 0)
        return;

    proto_tree_add_item(sdp_owner_tree, hf_owner_address_type, tvb, offset,
                        tokenlen, ENC_UTF_8);
    offset = next_offset + 1;

    /* Find the address */
    proto_tree_add_item(sdp_owner_tree, hf_owner_address, tvb, offset, -1, ENC_UTF_8);
}

/*
 * XXX - this can leak memory if an exception is thrown after we've fetched
 * a string.
 */
static void
dissect_sdp_connection_info(packet_info *pinfo, tvbuff_t *tvb, proto_item* ti, session_info_t *session_info, media_description_t *media_desc)
{
    proto_tree *sdp_connection_info_tree;
    int         offset, next_offset, tokenlen;
    const uint8_t *connection_type, *connection_address;

    offset = 0;

    sdp_connection_info_tree = proto_item_add_subtree(ti,
                                                      ett_sdp_connection_info);

    /* Find the network type */
    tokenlen = find_next_token_in_line(tvb, sdp_connection_info_tree, &offset, &next_offset);
    if (tokenlen == 0)
        return;

    proto_tree_add_item(sdp_connection_info_tree,
                        hf_connection_info_network_type, tvb, offset, tokenlen,
                        ENC_UTF_8);
    offset = next_offset + 1;

    /* Find the address type */
    tokenlen = find_next_token_in_line(tvb, sdp_connection_info_tree, &offset, &next_offset);
    if (tokenlen == 0)
        return;

    /* Save connection address type */
    proto_tree_add_item_ret_string(sdp_connection_info_tree,
                        hf_connection_info_address_type, tvb, offset, tokenlen,
                        ENC_UTF_8|ENC_NA, pinfo->pool, &connection_type);
    DPRINT(("parsed connection line type=%s", connection_type));
    offset = next_offset + 1;

    /* Find the connection address */
    /* XXX - what if there's a <number of addresses> value? */
    next_offset = tvb_find_guint8(tvb, offset, -1, '/');
    if (next_offset == -1) {
        tokenlen = -1; /* end of tvbuff */
        /* Save connection address */
        connection_address = tvb_get_string_enc(pinfo->pool, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_UTF_8|ENC_NA);
    } else {
        tokenlen = next_offset - offset;
        /* Save connection address */
        connection_address = tvb_get_string_enc(pinfo->pool, tvb, offset, tokenlen, ENC_UTF_8|ENC_NA);
    }

    DPRINT(("parsed connection line address=%s", connection_address));
    /* Parse and store connection address. Session-level addresses are
     * packet-scoped since they will be cloned in file-scope when needed. */
    if (session_info) {
        parse_sdp_connection_address(connection_type, connection_address,
                pinfo->pool,
                &session_info->conn_addr);
    } else if (media_desc) {
        /* Clear possibly inherited address from session level. */
        free_address_wmem(wmem_file_scope(), &media_desc->conn_addr);

        parse_sdp_connection_address(connection_type, connection_address,
                wmem_file_scope(),
                &media_desc->conn_addr);
    }

    proto_tree_add_item(sdp_connection_info_tree,
                        hf_connection_info_connection_address, tvb, offset,
                        tokenlen, ENC_UTF_8);
    if (next_offset != -1) {
        offset = next_offset + 1;
        next_offset = tvb_find_guint8(tvb, offset, -1, '/');
        if (next_offset == -1) {
            tokenlen = -1; /* end of tvbuff */
        } else {
            tokenlen = next_offset - offset;
        }
        proto_tree_add_item(sdp_connection_info_tree,
                            hf_connection_info_ttl, tvb, offset, tokenlen, ENC_UTF_8);
        if (next_offset != -1) {
            offset = next_offset + 1;
            proto_tree_add_item(sdp_connection_info_tree,
                                hf_connection_info_num_addr, tvb, offset, -1, ENC_UTF_8);
        }
    }
}

static void
dissect_sdp_bandwidth(tvbuff_t *tvb, proto_item *ti) {
    proto_tree *sdp_bandwidth_tree;
    int         offset, next_offset, tokenlen;
    proto_item *item;
    bool        unit_is_kbs = false;
    bool        unit_is_bps = false;

    offset = 0;

    sdp_bandwidth_tree = proto_item_add_subtree(ti, ett_sdp_bandwidth);

    /* find the modifier */
    next_offset = tvb_find_guint8(tvb, offset, -1, ':');

    if (next_offset == -1)
        return;

    tokenlen = next_offset - offset;

    item = proto_tree_add_item(sdp_bandwidth_tree, hf_bandwidth_modifier, tvb, offset,
                               tokenlen, ENC_UTF_8);
    if (tvb_strneql(tvb, offset, "CT", 2) == 0) {
        proto_item_append_text(item, " [Conference Total(total bandwidth of all RTP sessions)]");
        unit_is_kbs = true;
    } else if (tvb_strneql(tvb, offset, "AS", 2) == 0) {
        proto_item_append_text(item, " [Application Specific (RTP session bandwidth)]");
        unit_is_kbs = true;
    } else if (tvb_strneql(tvb, offset, "TIAS", 4) == 0) {
        proto_item_append_text(item, " [Transport Independent Application Specific maximum]");
        unit_is_bps = true;
    }


    offset = next_offset + 1;

    item = proto_tree_add_item(sdp_bandwidth_tree, hf_bandwidth_value, tvb, offset, -1,
                               ENC_UTF_8);
    if (unit_is_kbs == true)
        proto_item_append_text(item, " kb/s");
    if (unit_is_bps == true)
        proto_item_append_text(item, " b/s");
}

static void dissect_sdp_time(tvbuff_t *tvb, proto_item* ti) {
    proto_tree *sdp_time_tree;
    int         offset, next_offset, tokenlen;

    offset = 0;

    sdp_time_tree = proto_item_add_subtree(ti, ett_sdp_time);

    /* get start time */
    tokenlen = find_next_token_in_line(tvb, sdp_time_tree, &offset, &next_offset);
    if (tokenlen == 0)
        return;

    proto_tree_add_item(sdp_time_tree, hf_time_start, tvb, offset, tokenlen,
                        ENC_UTF_8);

    /* get stop time */
    offset = next_offset + 1;
    proto_tree_add_item(sdp_time_tree, hf_time_stop, tvb, offset, -1, ENC_UTF_8);
}

static void dissect_sdp_repeat_time(tvbuff_t *tvb, proto_item* ti) {
    proto_tree *sdp_repeat_time_tree;
    int         offset, next_offset, tokenlen;
    bool        optional = false;

    offset = 0;

    sdp_repeat_time_tree = proto_item_add_subtree(ti, ett_sdp_time);

    /* get interval */
    tokenlen = find_next_token_in_line(tvb, sdp_repeat_time_tree, &offset, &next_offset);
    if (tokenlen == 0)
        return;

    proto_tree_add_item(sdp_repeat_time_tree, hf_repeat_time_interval, tvb,
                        offset, tokenlen, ENC_UTF_8);

    /* get duration */
    offset = next_offset + 1;
    tokenlen = find_next_token_in_line(tvb, sdp_repeat_time_tree, &offset, &next_offset);
    if (tokenlen == 0)
        return;

    proto_tree_add_item(sdp_repeat_time_tree, hf_repeat_time_duration, tvb,
                        offset, tokenlen, ENC_UTF_8);

    /* get offsets */
    do {
        offset = next_offset +1;
        tokenlen = find_next_optional_token_in_line(tvb, sdp_repeat_time_tree,
                                                    &offset, &next_offset, optional);
        if (tokenlen == 0)
            break;
        proto_tree_add_item(sdp_repeat_time_tree, hf_repeat_time_offset,
                            tvb, offset, tokenlen, ENC_UTF_8);
        optional = true;
    } while (next_offset != -1);

}

static void
dissect_sdp_timezone(tvbuff_t *tvb, proto_item* ti) {
    proto_tree* sdp_timezone_tree;
    int         offset, next_offset, tokenlen;
    bool        optional = false;

    offset = 0;

    sdp_timezone_tree = proto_item_add_subtree(ti, ett_sdp_timezone);

    do {
        tokenlen = find_next_optional_token_in_line(tvb, sdp_timezone_tree,
                                                    &offset, &next_offset, optional);
        if (tokenlen == 0)
            break;

        proto_tree_add_item(sdp_timezone_tree, hf_timezone_time, tvb, offset,
                            tokenlen, ENC_UTF_8);
        offset = next_offset + 1;
        tokenlen = find_next_optional_token_in_line(tvb, sdp_timezone_tree,
                                                    &offset, &next_offset, optional);
        if (tokenlen == 0)
            break;
        proto_tree_add_item(sdp_timezone_tree, hf_timezone_offset, tvb, offset,
                            tokenlen, ENC_UTF_8);
        offset = next_offset + 1;
        optional = true;
    } while (next_offset != -1);

}


static void dissect_sdp_encryption_key(tvbuff_t *tvb, proto_item * ti) {
    proto_tree *sdp_encryption_key_tree;
    int         offset, next_offset, tokenlen;

    offset = 0;

    sdp_encryption_key_tree = proto_item_add_subtree(ti, ett_sdp_encryption_key);

    next_offset = tvb_find_guint8(tvb, offset, -1, ':');

    if (next_offset == -1)
        return;

    tokenlen = next_offset - offset;

    proto_tree_add_item(sdp_encryption_key_tree, hf_encryption_key_type,
                        tvb, offset, tokenlen, ENC_UTF_8);

    offset = next_offset + 1;
    proto_tree_add_item(sdp_encryption_key_tree, hf_encryption_key_data,
                        tvb, offset, -1, ENC_UTF_8);
}

static void dissect_key_mgmt(tvbuff_t *tvb, packet_info * pinfo, proto_item * ti) {
    char         *data_p      = NULL;
    const uint8_t *prtcl_id    = NULL;
    int           len;
    tvbuff_t     *keymgmt_tvb;
    int           found_match = 0;
    proto_tree   *key_tree;
    int           next_offset;
    int           offset      = 0;
    int           tokenlen;

    key_tree = proto_item_add_subtree(ti, ett_sdp_key_mgmt);

    tokenlen = find_next_token_in_line(tvb, key_tree, &offset, &next_offset);
    if (tokenlen == 0)
        return;

    proto_tree_add_item_ret_string(key_tree, hf_key_mgmt_prtcl_id, tvb, offset, tokenlen, ENC_UTF_8|ENC_NA, pinfo->pool, &prtcl_id);

    offset = next_offset + 1;

    len = tvb_captured_length_remaining(tvb, offset);
    if (len < 0)
        return;

    data_p = (char *)tvb_get_string_enc(pinfo->pool, tvb, offset, len, ENC_UTF_8|ENC_NA);
    keymgmt_tvb = base64_to_tvb(tvb, data_p);
    add_new_data_source(pinfo, keymgmt_tvb, "Key Management Data");

    if ((prtcl_id != NULL) && (key_mgmt_dissector_table != NULL)) {
        found_match = dissector_try_string(key_mgmt_dissector_table,
                                           (const char *)prtcl_id,
                                           keymgmt_tvb, pinfo,
                                           key_tree, NULL);
    }

    if (found_match) {
        proto_item *ti2 = proto_tree_add_item(key_tree, hf_key_mgmt_data,
                                              keymgmt_tvb, 0, -1, ENC_NA);
        proto_item_set_hidden(ti2);
    } else {
        proto_tree_add_item(key_tree, hf_key_mgmt_data,
                            keymgmt_tvb, 0, -1, ENC_NA);
    }

}


static void dissect_sdp_session_attribute(tvbuff_t *tvb, packet_info * pinfo, proto_item * ti) {
    proto_tree   *sdp_session_attribute_tree;
    int           offset, next_offset, tokenlen;
    const uint8_t *field_name;

    offset = 0;

    sdp_session_attribute_tree = proto_item_add_subtree(ti,
                                                        ett_sdp_session_attribute);

    next_offset = tvb_find_guint8(tvb, offset, -1, ':');

    if (next_offset == -1)
        return;

    tokenlen = next_offset - offset;

    proto_tree_add_item_ret_string(sdp_session_attribute_tree, hf_session_attribute_field,
                        tvb, offset, tokenlen, ENC_UTF_8|ENC_NA, pinfo->pool, &field_name);

    offset = next_offset + 1;

    if (tvb_captured_length_remaining(tvb, offset) == 0) {
        expert_add_info(pinfo, ti, &ei_sdp_invalid_line_fields);
        return;
    }

    if (strcmp((const char *)field_name, "ipbcp") == 0) {
        offset = tvb_ws_mempbrk_pattern_guint8(tvb, offset, -1,&pbrk_digits, NULL);

        if (offset == -1)
            return;

        tokenlen = find_next_token_in_line(tvb, sdp_session_attribute_tree, &offset, &next_offset);
        if (tokenlen == 0)
            return;

        proto_tree_add_item(sdp_session_attribute_tree, hf_ipbcp_version, tvb, offset, tokenlen, ENC_UTF_8);

        offset = tvb_ws_mempbrk_pattern_guint8(tvb, offset, -1,&pbrk_alpha, NULL);

        if (offset == -1)
            return;

        tokenlen = tvb_find_line_end(tvb, offset, -1, &next_offset, false);

        if (tokenlen == -1)
            return;

        proto_tree_add_item(sdp_session_attribute_tree, hf_ipbcp_type, tvb, offset, tokenlen, ENC_UTF_8);
    } else if (strcmp((const char *)field_name, "key-mgmt") == 0) {
        tvbuff_t   *key_tvb;
        proto_item *key_ti;

        key_tvb = tvb_new_subset_remaining(tvb, offset);
        key_ti = proto_tree_add_item(sdp_session_attribute_tree, hf_key_mgmt_att_value, key_tvb, 0, -1, ENC_UTF_8);

        dissect_key_mgmt(key_tvb, pinfo, key_ti);
    } else {
        proto_tree_add_item(sdp_session_attribute_tree, hf_session_attribute_value,
                            tvb, offset, -1, ENC_UTF_8);
    }
}


/* Dissect media description - this is passed the line starting after 'm=', so like one of these:
 *    audio 29156 RTP/AVP 18 0
 *    video 49170/2 RTP/AVP 31 99
 */
static void
dissect_sdp_media(tvbuff_t *tvb, packet_info* pinfo, proto_item *ti,
                  media_description_t *media_desc) {
    proto_tree *sdp_media_tree;
    int         offset, next_offset, tokenlen, idx;
    uint8_t    *media_format;
    bool        optional = false;
    proto_item *it;
    const uint8_t *media_type_str;
    const uint8_t *media_port_str;
    const uint8_t *media_proto_str;
    transport_proto_t transport_proto;
    uint16_t    media_port;
    bool        media_port_valid;
    proto_item *pi;

    offset = 0;

    /* Create tree for media session */
    sdp_media_tree = proto_item_add_subtree(ti, ett_sdp_media);

    tokenlen = find_next_token_in_line(tvb, sdp_media_tree, &offset, &next_offset);
    if (tokenlen == 0)
        return;

    /* Type of media session */
    proto_tree_add_item_ret_string(sdp_media_tree, hf_media_media, tvb, offset, tokenlen,
                        ENC_UTF_8|ENC_NA, pinfo->pool, &media_type_str);
    if (media_desc) {
        /* for RTP statistics (supposedly?) */
        if (strcmp((const char*)media_type_str, "audio") == 0)
            media_desc->media_types |= RTP_MEDIA_AUDIO;
        else if (strcmp((const char*)media_type_str, "video") == 0)
            media_desc->media_types |= RTP_MEDIA_VIDEO;
        else
            media_desc->media_types |= RTP_MEDIA_OTHER;
    }
    DPRINT(("parsed media_type=%s", media_type_str));

    offset = next_offset + 1;

    tokenlen = find_next_token_in_line(tvb, sdp_media_tree, &offset, &next_offset);
    if (tokenlen == 0)
        return;

    next_offset = tvb_find_guint8(tvb, offset, tokenlen, '/');

    if (next_offset != -1) {
        tokenlen = next_offset - offset;
        /* Save port info */
        it = proto_tree_add_item_ret_string(sdp_media_tree, hf_media_port_string, tvb, offset, tokenlen,
                                   ENC_UTF_8|ENC_NA, pinfo->pool, &media_port_str);
        DPRINT(("parsed media_port=%s", media_port_str));
        if (g_ascii_isdigit(media_port_str[0])) {
            proto_item_set_hidden(it);
            media_port_valid = ws_strtou16(media_port_str, NULL, &media_port);
            pi = proto_tree_add_uint(sdp_media_tree, hf_media_port, tvb, offset, tokenlen,
                                media_port);
            if (!media_port_valid)
                expert_add_info(pinfo, pi, &ei_sdp_invalid_media_port);
            if (media_desc) {
                media_desc->media_port = media_port;
            }
        }

        offset = next_offset + 1;
        tokenlen = find_next_token_in_line(tvb, sdp_media_tree, &offset, &next_offset);
        if (tokenlen == 0)
            return;

        /* TODO: this puts the (optional) number of ports in the tree, but we don't
           actually use it for building the extra RTP flows, which we should. */
        proto_tree_add_item(sdp_media_tree, hf_media_portcount, tvb, offset,
                            tokenlen, ENC_UTF_8);
        offset = next_offset + 1;
    } else {
        tokenlen = find_next_token_in_line(tvb, sdp_media_tree, &offset, &next_offset);
        if (tokenlen == 0)
            return;

        /* Save port info */
        it = proto_tree_add_item_ret_string(sdp_media_tree, hf_media_port_string, tvb, offset, tokenlen,
                                   ENC_UTF_8|ENC_NA, pinfo->pool, &media_port_str);
        DPRINT(("parsed media_port=%s", media_port_str));
        if (g_ascii_isdigit(media_port_str[0])) {
            proto_item_set_hidden(it);
            media_port_valid = ws_strtou16(media_port_str, NULL, &media_port);
            pi = proto_tree_add_uint(sdp_media_tree, hf_media_port, tvb, offset, tokenlen,
                                media_port);
            if (!media_port_valid)
                expert_add_info(pinfo, pi, &ei_sdp_invalid_media_port);
            if (media_desc) {
                media_desc->media_port = media_port;
            }
        }
        offset = next_offset + 1;
    }

    tokenlen = find_next_token_in_line(tvb, sdp_media_tree, &offset, &next_offset);
    if (tokenlen == 0)
        return;

    /* Save port protocol */
    proto_tree_add_item_ret_string(sdp_media_tree, hf_media_proto, tvb, offset, tokenlen,
                        ENC_UTF_8|ENC_NA, pinfo->pool, &media_proto_str);
    DPRINT(("parsed media_proto=%s", media_proto_str));
    /* Detect protocol for registering with other dissectors like RTP. */
    transport_proto = parse_sdp_media_protocol(media_proto_str);
    if (media_desc) {
        media_desc->proto = transport_proto;
    }

    do {
        offset = next_offset + 1;
        tokenlen = find_next_optional_token_in_line(tvb, sdp_media_tree,
                                                    &offset, &next_offset, optional);
        if (tokenlen == 0)
            break;

        /* RFC 4566: If the <proto> sub-field is "RTP/AVP" or "RTP/SAVP" the
         * <fmt> sub-fields contain RTP payload type numbers. */
        if (transport_proto == SDP_PROTO_RTP || transport_proto == SDP_PROTO_SRTP) {
            media_format = tvb_get_string_enc(pinfo->pool, tvb, offset, tokenlen, ENC_UTF_8|ENC_NA);
            if (g_ascii_isdigit(media_format[0])) {
                proto_tree_add_string(sdp_media_tree, hf_media_format, tvb, offset,
                                      tokenlen, val_to_str_ext((uint32_t)strtoul((char*)media_format, NULL, 10), &rtp_payload_type_vals_ext, "%u"));

                if (media_desc) {
                    idx = media_desc->media.pt_count;
                    media_desc->media.pt[idx] = (int32_t)strtol((char*)media_format, NULL, 10);
                    DPRINT(("parsed media codec pt=%d", media_desc->media.pt[idx]));
                    if (idx < (SDP_MAX_RTP_PAYLOAD_TYPES-1))
                        media_desc->media.pt_count++;
                }
            } else {
                proto_tree_add_item(sdp_media_tree, hf_media_format, tvb, offset,
                                    tokenlen, ENC_UTF_8);
            }
        } else {
            proto_tree_add_item(sdp_media_tree, hf_media_format, tvb, offset,
                                tokenlen, ENC_UTF_8);
        }
        optional = true;
    } while (next_offset != -1);

    /* XXX Dissect traffic to "Port" as "Protocol"
     *     Remember this Port/Protocol pair so we can tear it down again later
     *     Actually, it's harder than that:
     *         We need to find out the address of the other side first and it
     *         looks like that info can be found in SIP headers only.
     */

}

static tvbuff_t *
ascii_bytes_to_tvb(tvbuff_t *tvb, packet_info *pinfo, char *msg)
{
    size_t nbytes;
    uint8_t *buf = convert_string_to_hex(msg, &nbytes);
    if (buf) {
        tvbuff_t *bytes_tvb;

        bytes_tvb = tvb_new_child_real_data(tvb, buf, (unsigned)nbytes, (unsigned)nbytes);
        tvb_set_free_cb(bytes_tvb, g_free);
        add_new_data_source(pinfo, bytes_tvb, "ASCII bytes to tvb");
        return bytes_tvb;
    }
    return NULL;
}

/* Annex X Profiles and levels definition */
static const value_string h263_profile_vals[] =
{
    { 0,    "Baseline Profile" },
    { 1,    "H.320 Coding Efficiency Version 2 Backward-Compatibility Profile" },
    { 2,    "Version 1 Backward-Compatibility Profile" },
    { 3,    "Version 2 Interactive and Streaming Wireless Profile" },
    { 4,    "Version 3 Interactive and Streaming Wireless Profile" },
    { 5,    "Conversational High Compression Profile" },
    { 6,    "Conversational Internet Profile" },
    { 7,    "Conversational Interlace Profile" },
    { 8,    "High Latency Profile" },
    { 0, NULL },
};


/* RFC 4629 The level are described in table X.2 of H.263 annex X */
static const value_string h263_level_vals[] =
{
    { 10,    "QCIF (176 x 144), 1 x 64Kb/s" },
    { 20,    "CIF (352 x 288), 2 x 64Kb/s" },
    { 30,    "CIF (352 x 288), 6 x 64Kb/s" },
    { 40,    "CIF (352 x 288), 32 x 64Kb/s" },
    { 45,    "QCIF (176 x144) support of CPFMT, 2 x 64Kb/s" },
    { 50,    "CIF (352 x 288) support of CPFMT, 64 x 64Kb/s" },
    { 60,    "CPFMT: 720 x 288 support of CPFMT, 128 x 64Kb/s" },
    { 70,    "CPFMT: 720 x 576 support of CPFMT, 256 x 64Kb/s" },
    { 0, NULL },
};


static const value_string h264_packetization_mode_vals[] =
{
    { 0,    "Single NAL mode" },
    { 1,    "Non-interleaved mode" },
    { 2,    "Interleaved mode" },
    { 0, NULL },
};

/*
 * TODO: Make this a more generic routine to dissect fmtp parameters depending on media types
 */
static void
decode_sdp_fmtp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, int tokenlen, uint8_t pt, transport_info_t *transport_info, rtp_dyn_payload_t *rtp_dyn_payload) {
  int                  next_offset;
  int                  end_offset;
  uint8_t             *field_name;
  char                *format_specific_parameter;
  proto_item          *item;
  tvbuff_t * volatile  data_tvb;

  const char *mime_type = transport_info->encoding_name[pt];
  end_offset = offset + tokenlen;

#if 0
    proto_tree_add_debug(tree, tvb, offset, tokenlen, "Debug; Analysed string: '%s'",
    tvb_get_string_enc(pinfo->pool, tvb, offset, tokenlen, ENC_ASCII));
#endif

    /* Look for an '=' within this string - RFC 4855 suggets that parameters
       be "parameter=value" pairs. We'll store them in a hash map from the
       parameter name to the value, as well as dissect some of them here,
       depending on the media type.
     */
    next_offset = tvb_find_guint8(tvb, offset, tokenlen, '=');
    if (next_offset == -1)
    {
        /* Some media types, like telephone-event and RED, don't have the
         * "parameter=value" syntax:
         * https://datatracker.ietf.org/doc/html/rfc4733
         * 2.4.1. "Relationship to SDP"
         * "The "events" media type parameter deviates from the convention
         * suggested in RFC 3555 because it omits the string "events=" before
         * the list of supported events."
         * https://www.iana.org/assignments/media-types/audio/RED
         * We'll handle them with the empty string as the parameter name.
         * The media types should know how to deal with that, if necessary.
         */
        field_name = wmem_strdup(pinfo->pool, "");
    } else {
        /* Find the name of the parameter */
        tokenlen = next_offset - offset;
        field_name = tvb_get_string_enc(pinfo->pool, tvb, offset, tokenlen, ENC_UTF_8);

#if 0
        proto_tree_add_debug(tree, tvb, offset, tokenlen, "Debug; MIMEtype '%s'Parameter name: '%s'", mime_type, field_name); */
#endif

        /* Move past the '=' */
        offset = next_offset + 1;
    }

    /* Get the value */
    tokenlen = end_offset - offset;
    format_specific_parameter = tvb_get_string_enc(pinfo->pool, tvb, offset, tokenlen, ENC_UTF_8);

    if (rtp_dyn_payload) {
        rtp_dyn_payload_add_fmtp(rtp_dyn_payload, pt,
                                 field_name,
                                 format_specific_parameter);
    }

    /* Dissect the MPEG4 profile-level-id parameter if present */
    if ((mime_type != NULL) && (g_ascii_strcasecmp(mime_type, "MP4V-ES") == 0)) {
        if (strcmp((char*)field_name, "profile-level-id") == 0) {
            item = proto_tree_add_uint(tree, hf_sdp_fmtp_mpeg4_profile_level_id, tvb, offset, tokenlen,
                                       (uint32_t)strtol((char*)format_specific_parameter, NULL, 10));
            proto_item_set_generated(item);
        } else if (strcmp((char*)field_name, "config") == 0) {
            data_tvb = ascii_bytes_to_tvb(tvb, pinfo, format_specific_parameter);
            if (mp4ves_config_handle && data_tvb) {
                call_dissector(mp4ves_config_handle, data_tvb, pinfo, tree);
            }
        }
    }

    /* Dissect the H263-2000 profile parameter if present */
    if (((mime_type != NULL) && (g_ascii_strcasecmp(mime_type, "H263-2000") == 0)) ||
        ((mime_type != NULL) && (g_ascii_strcasecmp(mime_type, "H263-1998") == 0))) {
        if (strcmp((char*)field_name, "profile") == 0) {
            item = proto_tree_add_uint(tree, hf_sdp_fmtp_h263_profile, tvb, offset, tokenlen,
                                       (uint32_t)strtol((char*)format_specific_parameter, NULL, 10));
            proto_item_set_generated(item);
        } else if (strcmp((char*)field_name, "level") == 0) {
            item = proto_tree_add_uint(tree, hf_sdp_fmtp_h263_level, tvb, offset, tokenlen,
                                       (uint32_t)strtol((char*)format_specific_parameter, NULL, 10));
            proto_item_set_generated(item);
        }
    }


    /* Dissect the H264 profile-level-id parameter
     * RFC 3984:
     * A base16 [6] (hexadecimal) representation of
     * the following three bytes in the sequence
     * parameter set NAL unit specified in [1]: 1)
     * profile_idc, 2) a byte herein referred to as
     * profile-iop, composed of the values of
     * constraint_set0_flag, constraint_set1_flag,
     * constraint_set2_flag, and reserved_zero_5bits
     * in bit-significance order, starting from the
     * most significant bit, and 3) level_idc.
     */
    if ((mime_type != NULL) && ((g_ascii_strcasecmp(mime_type, "H264") == 0) || (g_ascii_strcasecmp(mime_type, "H264-SVC") == 0))) {
        if (strcmp(field_name, "profile-level-id") == 0) {
            int length = 0;

            data_tvb = ascii_bytes_to_tvb(tvb, pinfo, format_specific_parameter);
            if (!data_tvb) {
                proto_tree_add_expert_format(tree, pinfo, &ei_sdp_invalid_conversion, tvb, offset, tokenlen, "Could not convert '%s' to 3 bytes", format_specific_parameter);
                return;
            }
            length = tvb_reported_length(data_tvb);
            if (length == 3) {
                if (h264_handle && data_tvb) {
                    dissect_h264_profile(data_tvb, pinfo, tree);
                }
            } else {
                item = proto_tree_add_expert_format(tree, pinfo, &ei_sdp_invalid_conversion, tvb, offset, tokenlen, "Incorrectly coded, must be three bytes");
                proto_item_set_generated(item);
            }
        } else if (strcmp(field_name, "packetization-mode") == 0) {
            item = proto_tree_add_uint(tree, hf_sdp_h264_packetization_mode, tvb, offset, tokenlen,
                                       (uint32_t)strtol((char*)format_specific_parameter, NULL, 10));
            proto_item_set_generated(item);
        } else if (strcmp(field_name, "sprop-parameter-sets") == 0) {
            /* The value of the parameter is the
               base64 [6] representation of the initial
               parameter set NAL units as specified in
               sections 7.3.2.1 and 7.3.2.2 of [1].  The
               parameter sets are conveyed in decoding order,
               and no framing of the parameter set NAL units
               takes place.  A comma is used to separate any
               pair of parameter sets in the list.
            */
            const uint8_t *data_p = NULL;
            int    comma_offset;

            comma_offset = tvb_find_guint8(tvb, offset, -1, ',');
            if (comma_offset != -1) {
                tokenlen = comma_offset - offset;
            } else {
                tokenlen = end_offset - offset;
            }

            proto_tree_add_item_ret_string(tree, hf_sdp_nal_unit_1_string, tvb, offset, tokenlen, ENC_UTF_8|ENC_NA, pinfo->pool, &data_p);

            data_tvb = base64_to_tvb(tvb, data_p);
            add_new_data_source(pinfo, data_tvb, "h264 prop-parameter-sets");

            if (h264_handle && data_tvb) {
                TRY {
                    dissect_h264_nal_unit(data_tvb, pinfo, tree);
                }
                CATCH_NONFATAL_ERRORS {
                    show_exception(tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
                }
                ENDTRY;
                if (comma_offset != -1) {
                    /* Second NAL unit */
                    offset   = comma_offset +1;
                    tokenlen = end_offset - offset;
                    proto_tree_add_item_ret_string(tree, hf_sdp_nal_unit_2_string, tvb, offset, tokenlen, ENC_UTF_8|ENC_NA, pinfo->pool, &data_p);
                    data_tvb = base64_to_tvb(tvb, data_p);
                    add_new_data_source(pinfo, data_tvb, "h264 prop-parameter-sets 2");
                    dissect_h264_nal_unit(data_tvb, pinfo, tree);
                }
            }
        }
    }

    /* Dissect the H265
    * RFC 7798:
    */
    else if ((mime_type != NULL) && (g_ascii_strcasecmp(mime_type, "H265") == 0)) {
        if (strcmp(field_name, "sprop-vps") == 0 || strcmp(field_name, "sprop-sps") == 0 || strcmp(field_name, "sprop-pps") == 0) {

            data_tvb = base64_to_tvb(tvb, format_specific_parameter);
            add_new_data_source(pinfo, data_tvb, field_name);
            if (h265_handle && data_tvb) {
                dissect_h265_format_specific_parameter(tree, data_tvb, pinfo);
            }
        }
    }

}

static const string_string ice_candidate_types[] = {
    { "host",       "Host candidate" },
    { "srflx",      "Server reflexive candidate" },
    { "prflx",      "Peer reflexive candidate" },
    { "relay",      "Relayed candidate" },
    { NULL, NULL }
};

static void
dissect_sdp_media_attribute_candidate(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset)
{
    /* RFC 5245 (ICE): "The candidate attribute is a media-level attribute
     * only. It contains a transport address for a candidate that can be
     * used for connectivity checks."
     * https://tools.ietf.org/html/rfc5245#section-15.1
     *
     *   candidate-attribute   = "candidate" ":" foundation SP component-id SP
     *                           transport SP
     *                           priority SP
     *                           connection-address SP     ;from RFC 4566
     *                           port         ;port from RFC 4566
     *                           SP cand-type
     *                           [SP rel-addr]
     *                           [SP rel-port]
     *                           *(SP extension-att-name SP
     *                                extension-att-value)
     *
     * Example: "candidate:0 1 UDP 2122252543 10.9.0.2 60299 typ host"
     */
    proto_item   *pi;
    int           next_offset, tokenlen;
    const uint8_t *candidate_type;

    /* foundation: between 1 and 32 "ICE chars" (ALPHA / DIGIT / "+" / "/") */
    tokenlen = find_next_token_in_line(tvb, tree, &offset, &next_offset);
    if (tokenlen == 0)
        return;
    proto_tree_add_item(tree, hf_ice_candidate_foundation,
            tvb, offset, tokenlen, ENC_ASCII);
    offset = next_offset + 1;

    /* component-id: integer between 1 and 256.
     * For RTP, 1 MUST be RTP and 2 MUST be RTCP (RFC 5245) */
    tokenlen = find_next_token_in_line(tvb, tree, &offset, &next_offset);
    if (tokenlen == 0)
        return;
    proto_tree_add_item(tree, hf_ice_candidate_componentid,
            tvb, offset, tokenlen, ENC_ASCII);
    offset = next_offset + 1;

    /* transport: "UDP", etc. */
    tokenlen = find_next_token_in_line(tvb, tree, &offset, &next_offset);
    if (tokenlen == 0)
        return;
    proto_tree_add_item(tree, hf_ice_candidate_transport,
            tvb, offset, tokenlen, ENC_ASCII);
    offset = next_offset + 1;

    /* priority: integer between 1 and 2^31-1 */
    tokenlen = find_next_token_in_line(tvb, tree, &offset, &next_offset);
    if (tokenlen == 0)
        return;
    proto_tree_add_item(tree, hf_ice_candidate_priority,
            tvb, offset, tokenlen, ENC_ASCII);
    offset = next_offset + 1;

    /* connection-address: IPv4, IPv6 address or FQDN. */
    tokenlen = find_next_token_in_line(tvb, tree, &offset, &next_offset);
    if (tokenlen == 0)
        return;
    proto_tree_add_item(tree, hf_ice_candidate_address,
            tvb, offset, tokenlen, ENC_ASCII);
    offset = next_offset + 1;

    /* port */
    tokenlen = find_next_token_in_line(tvb, tree, &offset, &next_offset);
    if (tokenlen == 0)
        return;
    proto_tree_add_item(tree, hf_ice_candidate_port,
            tvb, offset, tokenlen, ENC_ASCII);
    offset = next_offset + 1;

    /* cand-type: type of candidate (where it learned the candidate)
     * Check for "typ " in "typ host" and skip it. */
    if (tvb_strneql(tvb, offset, "typ ", 4))
        return;
    offset += 4;
    tokenlen = find_next_token_in_line(tvb, tree, &offset, &next_offset);
    if (tokenlen == 0)
        return;
    pi = proto_tree_add_item_ret_string(tree, hf_ice_candidate_type,
            tvb, offset, tokenlen, ENC_ASCII|ENC_NA,
            pinfo->pool, &candidate_type);
    if ((candidate_type = try_str_to_str(candidate_type, ice_candidate_types))) {
        proto_item_append_text(pi, " (%s)", candidate_type);
    }
    /* offset = next_offset + 1; */

    /* Ignored: [rel-addr] [rel-port] *(extension-att-name extension-att-value) */
}

typedef struct {
  const char *name;
} sdp_names_t;

#define SDP_RTPMAP              1
#define SDP_FMTP                2
#define SDP_PATH                3
#define SDP_H248_ITEM           4
#define SDP_CRYPTO              5
#define SDP_SPRTMAP             6
#define SDP_CANDIDATE           7
#define SDP_ED137_TYPE          8
#define SDP_ED137_TXRXMODE      9
#define SDP_ED137_FID           10
#define SDP_RTCP                11
#define SDP_RTCP_MUX            12

static const sdp_names_t sdp_media_attribute_names[] = {
    { "Unknown-name"},    /* 0 Pad so that the real headers start at index 1 */
    { "rtpmap"},          /* 1 */
    { "fmtp"},            /* 2 */
    { "path"},            /* 3 */
    { "h248item"},        /* 4 */
    { "crypto"},          /* 5 */
    { "sprt"},            /* 6 */
    { "candidate" },      /* 7 */
    { "type" },           /* 8 */
    { "txrxmode" },       /* 9 */
    { "fid" },            /* 10 */
    { "rtcp" },           /* 11 */
    { "rtcp-mux" },       /* 12 */
};

static int find_sdp_media_attribute_names(tvbuff_t *tvb, int offset, unsigned len)
{
    unsigned i;

    for (i = 1; i < array_length(sdp_media_attribute_names); i++) {
        if ((len == strlen(sdp_media_attribute_names[i].name)) &&
            (tvb_strncaseeql(tvb, offset, sdp_media_attribute_names[i].name, len) == 0))
            return i;
    }

    return -1;
}

/* A few protocols give the fmtp parameter as a string instead of a
 * numeric payload type, list them here (lower case for comparison).
 */
static const string_string media_format_str_types[] = {
    /* ETSI TS 102 472, ETSI TS 102 592 */
    { "ipdc-kmm", "IP Datacast Key Management Message"},
    { "ipdc-ksm", "IP Datacast Key Stream Message"},
    /* ETSI TS 124 380 */
    { "mcptt",    "Mission Critical Push To Talk"},
    /* ETSI TS 124 581 */
    { "mcvideo",  "Mission Critical Video"},
    /* OMA PoC Control Plane */
    { "tbcp",     "Talk Burst Control Protocol"},
    { NULL, NULL }
};

static void
dissect_sdp_media_attribute_rtpmap(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int length,
                                   transport_info_t *transport_info, session_info_t *session_info,
                                   media_description_t *media_desc, int offset)
{
    int           next_offset, tokenlen;
    const uint8_t *payload_type;
    proto_item   *pi;
    uint8_t       pt;

    /* RFC 8866 6.6 rtpmap
       Syntax:
          rtpmap-value = payload-type SP encoding-name
          "/" clock-rate [ "/" encoding-params ]
          payload-type = zero-based-integer
          encoding-name = token
          clock-rate = integer
          encoding-params = channels
          channels = integer
     */
    next_offset = tvb_find_guint8(tvb, offset, -1, ' ');

    if (next_offset == -1)
        return;

    tokenlen = next_offset - offset;

    proto_tree_add_item_ret_string(tree, hf_media_format, tvb,
                                   offset, tokenlen, ENC_UTF_8|ENC_NA, pinfo->pool, &payload_type);

    offset = next_offset + 1;

    next_offset = tvb_find_guint8(tvb, offset, -1, '/');

    if (next_offset == -1) {
        return;
    }

    tokenlen = next_offset - offset;

    proto_tree_add_item(tree, hf_media_encoding_name, tvb,
                        offset, tokenlen, ENC_UTF_8);

    if (!ws_strtou8(payload_type, NULL, &pt) || pt >= SDP_NO_OF_PT) {
        return;   /* Invalid */
    }

    /* String is file scope allocated because transport_info is connection related */
    transport_info->encoding_name[pt] = (char*)tvb_get_string_enc(wmem_file_scope(), tvb, offset, tokenlen, ENC_UTF_8|ENC_NA);

    offset = next_offset + 1;

    next_offset = tvb_find_guint8(tvb, offset, length - offset, '/');
    if (next_offset == -1) {
        next_offset = length;
    }

    tokenlen = next_offset - offset;
    pi = proto_tree_add_item(tree, hf_media_sample_rate, tvb,
                             offset, tokenlen, ENC_UTF_8);
    transport_info->sample_rate[pt] = 0;
    if (!ws_strtou32(tvb_get_string_enc(pinfo->pool, tvb, offset, tokenlen, ENC_UTF_8|ENC_NA),
                     NULL, &transport_info->sample_rate[pt])) {
        expert_add_info(pinfo, pi, &ei_sdp_invalid_sample_rate);
    } else if (!strcmp(transport_info->encoding_name[pt], "G722")) {
        // The reported sampling rate is 8000, but the actual value is
        // 16kHz. https://tools.ietf.org/html/rfc3551#section-4.5.2
        proto_item_append_text(pi, " (RTP clock rate is 8kHz, actual sampling rate is 16kHz)");
    }

    transport_info->channels[pt] = 1;
    if (media_desc && media_desc->media_types & RTP_MEDIA_AUDIO) {
        if (next_offset < length) {
            offset = next_offset + 1;
            tokenlen = length - offset;
            pi = proto_tree_add_item(tree, hf_media_channels, tvb,
                                     offset, tokenlen, ENC_UTF_8);
            if (!ws_strtou32(tvb_get_string_enc(pinfo->pool, tvb, offset, tokenlen, ENC_UTF_8|ENC_NA),
                             NULL, &transport_info->channels[pt])) {
                expert_add_info(pinfo, pi, &ei_sdp_invalid_channels);
            }
        }
    }
    /* As per RFC2327 it is possible to have multiple Media Descriptions ("m=").
       For example:

       a=rtpmap:101 G726-32/8000
       m=audio 49170 RTP/AVP 0 97
       a=rtpmap:97 telephone-event/8000
       m=audio 49172 RTP/AVP 97 101
       a=rtpmap:97 G726-24/8000

       The Media attributes ("a="s) after the "m=" only apply for that "m=".
       If there is an "a=" before the first "m=", that attribute applies for
       all the session (all the "m="s).
    */

    if (session_info) {
        /* If this "a=" appear before any "m=", we add it to the session
         * info, these will be added later to all media (via
         * sdp_new_media_description).
         *
         * NOTE: This should not happen, because rtpmap is Usage Level: media
         * (RFC 8866 6.6, also RFC 4566 6, and heavily implied by RFC 2327)
         */
        rtp_dyn_payload_insert(session_info->rtp_dyn_payload,
                               pt,
                               transport_info->encoding_name[pt],
                               transport_info->sample_rate[pt],
                               transport_info->channels[pt]);
    } else if (media_desc) {
        /* if the "a=" is after an "m=", only apply to this "m=" */
        rtp_dyn_payload_insert(media_desc->media.rtp_dyn_payload,
                               pt,
                               transport_info->encoding_name[pt],
                               transport_info->sample_rate[pt],
                               transport_info->channels[pt]);
    }
}

static void
dissect_sdp_media_attribute_fmtp(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                                 transport_info_t *transport_info, session_info_t *session_info,
                                 media_description_t *media_desc, int offset)
{
    int           next_offset, tokenlen;
    proto_item   *fmtp_item, *media_format_item;
    const uint8_t *payload_type;
    const uint8_t *media_format_str;
    proto_tree   *fmtp_tree;
    bool          has_more_pars      = true;
    /* Reading the Format parameter(fmtp) */
    uint8_t       media_format;

    /* Skip leading space, if any */
    offset = tvb_skip_wsp(tvb, offset, tvb_captured_length_remaining(tvb, offset));
    /* Media format extends to the next space */
    next_offset = tvb_find_guint8(tvb, offset, -1, ' ');

    if (next_offset == -1)
        return;

    tokenlen = next_offset - offset;

    media_format_item = proto_tree_add_item_ret_string(tree, hf_media_format, tvb,
                                                       offset, tokenlen, ENC_UTF_8 | ENC_NA, pinfo->pool, &payload_type);

    /* Append encoding name to format if known */
    payload_type = wmem_ascii_strdown(pinfo->pool, payload_type, -1);
    media_format = 0;
    if ((media_format_str = try_str_to_str(payload_type, media_format_str_types))) {

        proto_item_append_text(media_format_item, " [%s]",
                               media_format_str);
    } else if (ws_strtou8(payload_type, NULL, &media_format) && media_format < SDP_NO_OF_PT) {
        if (media_format) {
            proto_item_append_text(media_format_item, " [%s]",
                                   transport_info->encoding_name[media_format]);
        }
    } else {
        expert_add_info(pinfo, media_format_item, &ei_sdp_invalid_media_format);
        return;
    }


#if 0 /* XXX:  ?? */
    payload_type = tvb_get_string_enc(pinfo->pool, tvb, offset, tokenlen, ENC_ASCII);
#endif
    /* Move offset past the payload type */
    offset = next_offset + 1;

    while (has_more_pars == true) {
        next_offset = tvb_find_guint8(tvb, offset, -1, ';');
        offset = tvb_skip_wsp(tvb, offset, tvb_captured_length_remaining(tvb, offset));

        if (next_offset == -1) {
            has_more_pars = false;
            next_offset= tvb_captured_length(tvb);
        }

        /* There are at least 2 - add the first parameter */
        tokenlen = next_offset - offset;
        fmtp_item = proto_tree_add_item(tree, hf_media_format_specific_parameter, tvb,
                                        offset, tokenlen, ENC_UTF_8);

        fmtp_tree = proto_item_add_subtree(fmtp_item, ett_sdp_fmtp);

        rtp_dyn_payload_t *rtp_dyn_payload = NULL;
        if (session_info) {
            rtp_dyn_payload = session_info->rtp_dyn_payload;
        } else if (media_desc) {
            rtp_dyn_payload = media_desc->media.rtp_dyn_payload;
        }
        decode_sdp_fmtp(fmtp_tree, tvb, pinfo, offset, tokenlen,
                        media_format, transport_info, rtp_dyn_payload);

        /* Move offset past "; " and onto first char */
        offset = next_offset + 1;
    }
}

static void
dissect_sdp_media_attribute_path(packet_info *pinfo, tvbuff_t *tvb, uint8_t *attribute_value,
                                 media_description_t *media_desc, const char *msrp_res, int offset)
{
    /* msrp attributes that contain address needed for conversation */
    /*    RFC 4975
     *    path = path-label ":" path-list
     *    path-label = "path"
     *    path-list= MSRP-URI *(SP MSRP-URI)
     *    MSRP-URI = msrp-scheme "://" authority
     *       ["/" session-id] ";" transport *( ";" URI-parameter)
     *                        ; authority as defined in RFC3986
     *
     *    msrp-scheme = "msrp" / "msrps"
     * RFC 3986
     * The authority component is preceded by a double slash ("//") and is terminated by
     * the next slash ("/"), question mark ("?"), or number sign ("#") character, or by
     * the end of the URI.
     */

    /* Check for "msrp://" */
    if (strncmp((char*)attribute_value, msrp_res, strlen(msrp_res)) == 0 && msrp_handle &&
        media_desc && media_desc->proto == SDP_PROTO_MSRP) {
        int address_offset, port_offset, port_end_offset;

        /* Address starts here */
        address_offset = offset + (int)strlen(msrp_res);

        /* Port is after next ':' */
        port_offset = tvb_find_guint8(tvb, address_offset, -1, ':');
        /* Check if port is present if not skipp */
        if (port_offset!= -1) {
            /* Port ends with '/' */
            port_end_offset = tvb_find_guint8(tvb, port_offset, -1, '/');
            if (port_end_offset == -1) {
                /* No "/" look for the ";" */
                port_end_offset = tvb_find_guint8(tvb, port_offset, -1, ';');
            }
            /* Attempt to convert address */
            uint32_t msrp_ipaddr;
            uint16_t msrp_port_number;
            if (str_to_ip((char*)tvb_get_string_enc(pinfo->pool, tvb, address_offset, port_offset-address_offset, ENC_UTF_8|ENC_NA),
                          &msrp_ipaddr)) {
                /* Get port number */
                if (ws_strtou16(tvb_get_string_enc(pinfo->pool, tvb, port_offset + 1,
                                                   port_end_offset - port_offset - 1, ENC_UTF_8|ENC_NA), NULL, &msrp_port_number)) {
                    /* Port and address are usable, store for later use in
                     * complete_descriptions (overrides the "c=" address). */
                    alloc_address_wmem(wmem_file_scope(), &media_desc->media_attr.msrp.ipaddr, AT_IPv4, 4, &msrp_ipaddr);
                    media_desc->media_attr.msrp.port_number = msrp_port_number;
                }
            }
        }
    }
}

static void
dissect_sdp_media_attribute_h248_item(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                                      uint8_t *attribute_value, const char *msrp_res)
{
    const char   *h324ext_h223lcparm = "h324ext/h223lcparm";
    tvbuff_t     *h245_tvb;

    if (strncmp((char*)attribute_value, h324ext_h223lcparm, strlen(msrp_res)) == 0) {
        /* A.5.1.3 H.223 Logical channel parameters
         * This property indicates the H.245
         * H223LogicalChannelsParameters structure encoded by applying the PER specified in
         * ITU-T Rec. X.691. Value encoded as per A.5.1.2. For text encoding the mechanism defined
         * in ITU-T Rec. H.248.15 is used.
         *
         * H.248.15 6 IANA considerations
         * The format of the Package attribute is as below:
         *     a=h248item:<package name>/<property name> = <value>
         */
        asn1_ctx_t actx;

        attribute_value = strchr(attribute_value, '=');
        if (!attribute_value) {
            return;
        }

        h245_tvb = ascii_bytes_to_tvb(tvb, pinfo, ++attribute_value);
        /* should go through a handle, however,  the two h245 entry
           points are different, one is over tpkt and the other is raw
        */
        if (h245_tvb) {
            asn1_ctx_init(&actx, ASN1_ENC_PER, true, pinfo);
            dissect_h245_H223LogicalChannelParameters(h245_tvb, 0, &actx,
                                                      tree,hf_SDPh223LogicalChannelParameters);
        }
    }
}

static void
dissect_sdp_media_attribute_crypto(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                                   transport_info_t *transport_info, int offset)
{
    /* https://tools.ietf.org/html/rfc4568
    * 9.1.  Generic "Crypto" Attribute Grammar
    *
    *   The ABNF grammar for the crypto attribute is defined below:
    *
    *   "a=crypto:" tag 1*WSP crypto-suite 1*WSP key-params
    *                                           *(1*WSP session-param)
    *
    *   tag              = 1*9DIGIT
    *   crypto-suite     = 1*(ALPHA / DIGIT / "_")
    *
    *   key-params       = key-param *(";" key-param)
    *   key-param        = key-method ":" key-info
    *   key-method       = "inline" / key-method-ext
    *   key-method-ext   = 1*(ALPHA / DIGIT / "_")
    *   key-info         = 1*(%x21-3A / %x3C-7E) ; visible (printing) chars
    *                                        ; except semi-colon
    *  session-param    = 1*(VCHAR)         ; visible (printing) characters
    *
    *   where WSP, ALPHA, DIGIT, and VCHAR are defined in [RFC4234].
    *
    */
    int           next_offset, tokenlen;
    proto_tree   *parameter_item;
    proto_item   *parameter_tree;
    uint32_t      crypto_tag;
    bool          crypto_tag_valid;
    bool          has_more_pars      = true;
    uint8_t       master_key_length  = 0, master_salt_length = 0;
    bool          mki_len_valid;
    proto_item   *pi;

    /* We are at the first colon */
    /* tag */
    tokenlen = find_next_token_in_line(tvb, tree, &offset, &next_offset);
    if (tokenlen == 0)
        return;
    crypto_tag_valid = ws_strtou32(tvb_get_string_enc(pinfo->pool, tvb, offset,
                                                      tokenlen, ENC_UTF_8|ENC_NA), NULL, &crypto_tag);
    pi = proto_tree_add_uint(tree, hf_sdp_crypto_tag, tvb, offset, tokenlen, crypto_tag);
    if (!crypto_tag_valid)
        expert_add_info(pinfo, pi, &ei_sdp_invalid_crypto_tag);
    offset = next_offset + 1;

    /* crypto-suite */
    tokenlen = find_next_token_in_line(tvb, tree, &offset, &next_offset);
    if (tokenlen == 0)
        return;
    parameter_item = proto_tree_add_item(tree, hf_sdp_crypto_crypto_suite, tvb, offset, tokenlen, ENC_UTF_8);
    if (tvb_strncaseeql(tvb, offset, "AES_CM_128_HMAC_SHA1_80", tokenlen) == 0) {

        /* XXX This may only work in simple cases */
        if (transport_info->encryption_algorithm == SRTP_ENC_ALG_NOT_SET) {
            transport_info->encryption_algorithm = SRTP_ENC_ALG_AES_CM;
            transport_info->auth_algorithm       = SRTP_AUTH_ALG_HMAC_SHA1;
            /* number of octets used for the Auth Tag in the RTP payload */
            transport_info->auth_tag_len         = 10;
        }
        master_key_length  = 16; /* 128 bits = 16 octets */
        master_salt_length = 14; /* 112 bits = 14 octets */
    } else if (tvb_strncaseeql(tvb, offset, "AES_CM_128_HMAC_SHA1_32", tokenlen) == 0) {
        /* XXX This may only work in simple cases */
        if (transport_info->encryption_algorithm == SRTP_ENC_ALG_NOT_SET) {
            transport_info->encryption_algorithm = SRTP_ENC_ALG_AES_CM;
            transport_info->auth_algorithm       = SRTP_AUTH_ALG_HMAC_SHA1;
            /* number of octets used for the Auth Tag in the RTP payload */
            transport_info->auth_tag_len         = 4;
        }
        master_key_length  = 16; /* 128 bits = 16 octets */
        master_salt_length = 14; /* 112 bits = 14 octets */
    } else if (tvb_strncaseeql(tvb, offset, "F8_128_HMAC_SHA1_80", tokenlen) == 0) {
        if (transport_info->encryption_algorithm == SRTP_ENC_ALG_NOT_SET) {
            /* XXX This may only work in simple cases */
            transport_info->encryption_algorithm = SRTP_ENC_ALG_AES_F8;
            transport_info->auth_algorithm       = SRTP_AUTH_ALG_HMAC_SHA1;
            /* number of octets used for the Auth Tag in the RTP payload */
            transport_info->auth_tag_len         = 10;
        }
        master_key_length  = 16; /* 128 bits = 16 octets */
        master_salt_length = 14; /* 112 bits = 14 octets */
    }
    offset = next_offset + 1;

    /* key-params */
    while (has_more_pars == true) {
        int       param_end_offset;
        tvbuff_t *key_salt_tvb;
        char     *data_p = NULL;

        param_end_offset = tvb_find_guint8(tvb, offset, -1, ';');
        if (param_end_offset == -1) {
            has_more_pars = false;
            param_end_offset = tvb_captured_length(tvb);
        }
        /* key-method or key-method-ext */
        next_offset = tvb_find_guint8(tvb, offset, -1, ':');
        if (next_offset == -1) {
            expert_add_info(pinfo, parameter_item, &ei_sdp_invalid_key_param);
            break;
        }

        if (tvb_strncaseeql(tvb, offset, "inline", next_offset-offset) == 0) {
            parameter_tree = proto_tree_add_subtree(tree, tvb, offset,param_end_offset-offset,
                                                    ett_sdp_crypto_key_parameters, NULL, "Key parameters");
            /* XXX only for SRTP? */
            /* srtp-key-info       = key-salt ["|" lifetime] ["|" mki] */
            offset      = next_offset +1;
            next_offset = tvb_find_guint8(tvb, offset, -1, '|');
            if (next_offset == -1) {
                tokenlen = param_end_offset - offset;
            } else {
                tokenlen = next_offset - offset;
            }
            data_p = tvb_get_string_enc(pinfo->pool, tvb, offset, tokenlen, ENC_UTF_8|ENC_NA);
            key_salt_tvb = base64_to_tvb(tvb, data_p);
            add_new_data_source(pinfo, key_salt_tvb, "Key_Salt_tvb");
            if (master_key_length != 0) {
                proto_tree_add_item(parameter_tree, hf_sdp_key_and_salt, tvb, offset, tokenlen, ENC_NA);
                proto_tree_add_item(parameter_tree, hf_sdp_crypto_master_key,
                                    key_salt_tvb, 0, master_key_length, ENC_NA);
                proto_tree_add_item(parameter_tree, hf_sdp_crypto_master_salt,
                                    key_salt_tvb, master_key_length, master_salt_length, ENC_NA);
            } else {
                proto_tree_add_item(parameter_tree, hf_sdp_key_and_salt, key_salt_tvb, 0, -1, ENC_NA);
            }

            /*  ["|" lifetime] ["|" mki] are optional */
            if (next_offset != -1) {
                offset = next_offset + 1;
                next_offset = tvb_find_guint8(tvb, offset, -1, '|');
                if (next_offset == -1) {
                    if (next_offset < param_end_offset){
                        next_offset = param_end_offset;
                    }
                }
                if (next_offset != -1) {
                    /*lifetime           = ["2^"] 1*(DIGIT)   ; see section 6.1 for "2^" */
                    tokenlen = next_offset - offset;
                    proto_tree_add_item(parameter_tree, hf_sdp_crypto_lifetime,
                                        tvb, offset, tokenlen, ENC_UTF_8);
                    offset   = next_offset + 1;
                }
                /* mki                 = mki-value ":" mki-length
                *
                * mki-value           = 1*DIGIT
                */
                if (offset>param_end_offset) {
                    next_offset = -1;
                } else {
                    next_offset = tvb_find_guint8(tvb, offset, -1, ':');
                }
                if (next_offset != -1) {
                    tokenlen    = next_offset - offset;
                    proto_tree_add_item(parameter_tree, hf_sdp_crypto_mki, tvb, offset, tokenlen, ENC_UTF_8);
                    offset      = next_offset + 1;

                    /* mki-length          = 1*3DIGIT   ; range 1..128. */
                    next_offset = param_end_offset;
                    tokenlen    = next_offset - offset;

                    /* This will not work if more than one parameter */
                    /* number of octets used for the MKI in the RTP payload */
                    mki_len_valid = ws_strtou32(tvb_get_string_enc(pinfo->pool, tvb, offset, tokenlen,
                                                                   ENC_UTF_8|ENC_NA), NULL, &transport_info->mki_len);
                    pi = proto_tree_add_item(parameter_tree, hf_sdp_crypto_mki_length,
                                             tvb, offset, tokenlen, ENC_UTF_8);
                    if (!mki_len_valid)
                        expert_add_info(pinfo, pi, &ei_sdp_invalid_crypto_mki_length);
                }
            }
            offset = param_end_offset;
        } else {
            break;
        }
    }
}

static void dissect_sdp_media_attribute(tvbuff_t *tvb, packet_info *pinfo, proto_item * ti, int length,
                                        transport_info_t *transport_info,
                                        session_info_t *session_info,
                                        media_description_t *media_desc,
                                        sdp_data_t *sdp_data)
{
    proto_tree   *sdp_media_attribute_tree;
    proto_item   *pi;
    int           offset, tokenlen, colon_offset;
    uint8_t      *attribute_value;
    int           sdp_media_attrbute_code;
    const char   *msrp_res           = "msrp://";

    offset = 0;

    /* Create attribute tree */
    sdp_media_attribute_tree = proto_item_add_subtree(ti,
                                                      ett_sdp_media_attribute);
    /* Find end of field */
    colon_offset = tvb_find_guint8(tvb, offset, -1, ':');

    if (colon_offset == -1)
      return;

    /* Attribute field name is token before ':' */
    tokenlen = colon_offset - offset;
    pi = proto_tree_add_item(sdp_media_attribute_tree,
                             hf_media_attribute_field,
                             tvb, offset, tokenlen, ENC_UTF_8);
    /*??field_name = tvb_get_string_enc(pinfo->pool, tvb, offset, tokenlen, ENC_ASCII);*/
    sdp_media_attrbute_code = find_sdp_media_attribute_names(tvb, offset, tokenlen);

    /* Skip colon */
    offset = colon_offset + 1;
    /* skip leading wsp */
    offset = tvb_skip_wsp(tvb, offset, tvb_captured_length_remaining(tvb, offset));

    /* Value is the remainder of the line */
    if (tvb_captured_length_remaining(tvb, offset) > 0)
        attribute_value = tvb_get_string_enc(pinfo->pool, tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_UTF_8|ENC_NA);
    else
    {
        expert_add_info(pinfo, pi, &ei_sdp_invalid_line_fields);
        return;
    }

    /*********************************************/
    /* Special parsing for some field name types */

    switch (sdp_media_attrbute_code) {
        case SDP_RTPMAP:
            /* decode the rtpmap to see if it is DynamicPayload to dissect them automatic */
            dissect_sdp_media_attribute_rtpmap(sdp_media_attribute_tree, pinfo, tvb, length, transport_info,
                                               session_info, media_desc, offset);
            break;
        case SDP_FMTP:
            dissect_sdp_media_attribute_fmtp(sdp_media_attribute_tree, pinfo, tvb, transport_info,
                                               session_info, media_desc, offset);
            break;
        case SDP_PATH:
            dissect_sdp_media_attribute_path(pinfo, tvb, attribute_value, media_desc, msrp_res, offset);
            break;
        case SDP_H248_ITEM:
            /* Decode h248 item ITU-T Rec. H.248.12 (2001)/Amd.1 (11/2002)*/
            dissect_sdp_media_attribute_h248_item(sdp_media_attribute_tree, pinfo, tvb, attribute_value, msrp_res);
            break;
        case SDP_CRYPTO:
            dissect_sdp_media_attribute_crypto(sdp_media_attribute_tree, pinfo, tvb, transport_info, offset);
            break;
        case SDP_CANDIDATE:
            dissect_sdp_media_attribute_candidate(sdp_media_attribute_tree, pinfo, tvb, offset);
            break;
        case SDP_ED137_TYPE:
            /* Remember the value and add it to tree */
            sdp_data->ed137_type = attribute_value;
            proto_tree_add_item(sdp_media_attribute_tree, hf_media_attribute_value,
                                tvb, offset, -1, ENC_UTF_8);
            break;
        case SDP_ED137_TXRXMODE:
            /* Remember the value and add it to tree */
            sdp_data->ed137_txrxmode = attribute_value;
            proto_tree_add_item(sdp_media_attribute_tree, hf_media_attribute_value,
                                tvb, offset, -1, ENC_UTF_8);
            break;
        case SDP_ED137_FID:
            /* Remember the value and add it to tree */
            sdp_data->ed137_fid = attribute_value;
            proto_tree_add_item(sdp_media_attribute_tree, hf_media_attribute_value,
                                tvb, offset, -1, ENC_UTF_8);
            break;
        case SDP_RTCP :
            if (media_desc) {
                if (!ws_strtou16(attribute_value, NULL, &media_desc->control_port))
                    media_desc->control_port = 0; /* Just use default, if not legal port */
            }
            proto_tree_add_item(sdp_media_attribute_tree, hf_media_attribute_value,
                                tvb, offset, -1, ENC_UTF_8);
            break;
        case SDP_RTCP_MUX :
            if (media_desc) {
                media_desc->control_port = media_desc->media_port;
            }
            proto_tree_add_item(sdp_media_attribute_tree, hf_media_attribute_value,
                                tvb, offset, -1, ENC_UTF_8);
            break;
        default:
            /* No special treatment for values of this attribute type, just add as one item. */
            proto_tree_add_item(sdp_media_attribute_tree, hf_media_attribute_value,
                                tvb, offset, -1, ENC_UTF_8);
            break;
    }
}

static void
call_sdp_subdissector(tvbuff_t *tvb, packet_info *pinfo, int hf, proto_tree* ti, int length,
                      transport_info_t *transport_info,
                      session_info_t *session_info,
                      media_description_t *media_desc,
                      sdp_data_t *sdp_data)
{
    if (hf == hf_owner) {
        dissect_sdp_owner(tvb, ti);
    } else if (hf == hf_connection_info) {
        dissect_sdp_connection_info(pinfo, tvb, ti, session_info, media_desc);
    } else if (hf == hf_bandwidth) {
        dissect_sdp_bandwidth(tvb, ti);
    } else if (hf == hf_time) {
        dissect_sdp_time(tvb, ti);
    } else if (hf == hf_repeat_time) {
        dissect_sdp_repeat_time(tvb, ti);
    } else if (hf == hf_timezone) {
        dissect_sdp_timezone(tvb, ti);
    } else if (hf == hf_encryption_key) {
        dissect_sdp_encryption_key(tvb, ti);
    } else if (hf == hf_session_attribute) {
        dissect_sdp_session_attribute(tvb, pinfo, ti);
    } else if (hf == hf_media) {
        dissect_sdp_media(tvb, pinfo, ti, media_desc);
    } else if (hf == hf_media_attribute) {
        dissect_sdp_media_attribute(tvb, pinfo, ti, length, transport_info, session_info, media_desc, sdp_data);
    }
}

/**
 * Post-processes the media descriptions after parsing it from the tvb. This
 * performs processing that can only be done when the full media description is
 * parsed (since otherwise the order of attributes could influence the result).
 * Must be called before applying the SDP with apply_sdp_transport.
 * It will remove media streams when the port number in the answer is zero.
 *
 * If the currently processed SDP is an Answer to a known previous Offer, then
 * answer_offset is non-zero.
 */
static void
complete_descriptions(transport_info_t *transport_info, unsigned answer_offset)
{
    unsigned media_count = wmem_array_get_count(transport_info->media_descriptions);
    media_description_t *media_descs = (media_description_t *)wmem_array_get_raw(transport_info->media_descriptions);
    media_description_t *bundle_media_desc = NULL;

    DPRINT(("complete_descriptions called with answer_offset=%d media_count=%d",
            answer_offset, media_count));

    for (unsigned i = answer_offset; i < media_count && !bundle_media_desc; i++) {
        for (unsigned j = i+1; j < media_count && !bundle_media_desc; j++) {
            if (media_descs[i].media_port == media_descs[j].media_port)
                bundle_media_desc = &media_descs[i];
        }
    }

    if (bundle_media_desc) {
        /* We have "bundling" of media, so now combine all the media bit masks
           and merge the rtp_dyn_payload so that the first media description
           has all the data for every media desciption. */
        for (unsigned i = answer_offset; i < media_count; i++) {
            media_description_t *media_desc = &media_descs[i];

            if (bundle_media_desc->media_port == media_desc->media_port) {
                media_desc->bundled = true;

                if (media_desc != bundle_media_desc) {
                    bundle_media_desc->media_types |= media_desc->media_types;
                    for (unsigned pt = 0; pt < 128; ++pt) {
                        const char * encoding_name;
                        int sample_rate;
                        unsigned channels;
                        wmem_map_t *fmtp_map;
                        if (rtp_dyn_payload_get_full(media_desc->media.rtp_dyn_payload,
                                                     pt, &encoding_name, &sample_rate, &channels, &fmtp_map))
                            rtp_dyn_payload_insert_full(bundle_media_desc->media.rtp_dyn_payload,
                                                        pt, encoding_name, sample_rate, channels, fmtp_map);
                    }
                }
            }
        }
    }

    for (unsigned i = answer_offset; i < media_count; i++) {
        media_description_t *media_desc = &media_descs[i];

        if (media_desc->control_port == 0)
            media_desc->control_port = media_desc->media_port + 1;

        if (media_desc->control_port == 0)
            media_desc->control_port = media_desc->media_port + 1;

        /* If this is an answer to a previous offer... */
        if (answer_offset > 0) {
            /* A zero port removes the media stream (RFC 3264, Section 8.2) */
            if (media_desc->media_port == 0) {
                DPRINT(("disabling media_port=%d, for index=%d",
                        media_descs[i - answer_offset].media_port,
                        i - answer_offset));
                media_descs[i - answer_offset].media_port = 0;
            }
        }

        /* MSRP uses addresses discovered in attribute
           rather than connection information of media session line */
        if (media_desc->proto == SDP_PROTO_MSRP && msrp_handle &&
            media_desc->media_attr.msrp.ipaddr.type != AT_NONE) {
            /* clear old address and set new address and port. */
            free_address_wmem(wmem_file_scope(), &media_desc->conn_addr);
            copy_address_shallow(&media_desc->conn_addr,
                                 &media_desc->media_attr.msrp.ipaddr);
            media_desc->media_port = media_desc->media_attr.msrp.port_number;
        }
    }
}

/**
 * Given is a structure containing the parsed result from the SDP (including
 * protocol type (RTP, SRTP, T38, etc.), media info (payload type, etc.) and
 * connection info (address, port). Register the addresss+port such that the
 * protocol will be invoked for this tuple with the media information.
 *
 * For use with SDP using the Offer/Answer model (such as SIP with INVITE and
 * 200 OK).
 * XXX what about RTSP where the SDP merely provides media info, without
 * actually establishing connections (Bug 5208).
 *
 * The passed transport information is modified: 'set_rtp' is set when the media
 * is assigned to a conversation. Note that the unassigned media (payload types)
 * are not freed, this is the responsibility of the caller.
 */
static void
apply_sdp_transport(packet_info *pinfo, transport_info_t *transport_info, int request_frame, sdp_setup_info_t *setup_info)
{
    int establish_frame = 0;
    wmem_array_t *setup_info_list;

    struct srtp_info *srtp_info = NULL;

    if (!global_sdp_establish_conversation) {
        /* Do not register with other dissectors when this pref is disabled. */
        return;
    }

    /* If no request_frame number has been found use this frame's number */
    if (request_frame == 0) {
        establish_frame = pinfo->num;
    } else {
        establish_frame = request_frame;
    }

    bool bundled_media_set = false;

    for (unsigned i = 0; i < wmem_array_get_count(transport_info->media_descriptions); i++) {
        media_description_t *media_desc =
            (media_description_t *)wmem_array_index(transport_info->media_descriptions, i);
        uint32_t current_rtp_port = 0;

        /* Add (s)rtp and (s)rtcp conversation, if available (overrides t38 if conversation already set) */
        if ((media_desc->media_port != 0) &&
            !media_desc->media.set_rtp &&
            (media_desc->proto == SDP_PROTO_RTP ||
             media_desc->proto == SDP_PROTO_SRTP) &&
            (media_desc->conn_addr.type == AT_IPv4 ||
             media_desc->conn_addr.type == AT_IPv6)) {

            media_desc->media.set_rtp = true;

            if (media_desc->bundled) {
                if (bundled_media_set)
                    continue;
                bundled_media_set = true;
            }

            if (media_desc->proto == SDP_PROTO_SRTP) {
                srtp_info = wmem_new0(wmem_file_scope(), struct srtp_info);
                if (transport_info->encryption_algorithm != SRTP_ENC_ALG_NOT_SET) {
                    srtp_info->encryption_algorithm = transport_info->encryption_algorithm;
                    srtp_info->auth_algorithm       = transport_info->auth_algorithm;
                    srtp_info->mki_len              = transport_info->mki_len;
                    srtp_info->auth_tag_len         = transport_info->auth_tag_len;

                }
                DPRINT(("calling srtp_add_address, channel=%d, media_port=%d",
                        i, media_desc->media_port));
                DINDENT();
                /* srtp_add_address and rtp_add_address are given the request_frame's not this frame's number,
                   because that's where the RTP flow started, and thus conversation needs to check against */
                srtp_add_address(pinfo, PT_UDP, &media_desc->conn_addr, media_desc->media_port, 0, "SDP", establish_frame,
                                 media_desc->media_types,
                                 media_desc->media.rtp_dyn_payload, srtp_info,
                                 setup_info);
                DENDENT();
            } else if (!setup_info || !setup_info->is_osmux) {
                DPRINT(("calling rtp_add_address, channel=%d, media_port=%d",
                        i, media_desc->media_port));
                DINDENT();
                srtp_add_address(pinfo, PT_UDP, &media_desc->conn_addr, media_desc->media_port, 0, "SDP", establish_frame,
                                 media_desc->media_types,
                                 media_desc->media.rtp_dyn_payload, NULL, setup_info);
                DENDENT();
            }
            /* SPRT might use the same port... */
            current_rtp_port = media_desc->media_port;

            if (rtcp_handle && media_desc->media_port != media_desc->control_port) {
                if (media_desc->proto == SDP_PROTO_SRTP) {
                    DPRINT(("calling rtcp_add_address, channel=%d, control_port=%d",
                            i, media_desc->control_port));
                    DINDENT();
                    srtcp_add_address(pinfo, &media_desc->conn_addr, media_desc->control_port, 0, "SDP", establish_frame, srtp_info);
                    DENDENT();
                 } else if (!setup_info || !setup_info->is_osmux) {
                    DPRINT(("calling rtcp_add_address, channel=%d, control_port=%d",
                            i, media_desc->control_port));
                    DINDENT();
                    rtcp_add_address(pinfo, &media_desc->conn_addr, media_desc->control_port, 0, "SDP", establish_frame);
                    DENDENT();
                 }
            }
        }

        /* add SPRT conversation */
        if (media_desc->proto == SDP_PROTO_SPRT &&
            (media_desc->conn_addr.type == AT_IPv4 ||
             media_desc->conn_addr.type == AT_IPv6) &&
            (sprt_handle)) {

            if (media_desc->media_port == 0 && current_rtp_port) {
                sprt_add_address(pinfo, &media_desc->conn_addr, current_rtp_port,
                                 0, "SDP", pinfo->num); /* will use same port as RTP */
            } else {
                sprt_add_address(pinfo, &media_desc->conn_addr, media_desc->media_port, 0, "SDP", pinfo->num);
            }
        }

        /* Add t38 conversation, if available and only if no rtp */
        if ((media_desc->media_port != 0) &&
            !media_desc->media.set_rtp &&
            media_desc->proto == SDP_PROTO_T38 &&
            media_desc->conn_addr.type == AT_IPv4) {
            t38_add_address(pinfo, &media_desc->conn_addr, media_desc->media_port, 0, "SDP", pinfo->num);
        }

        /* Add MSRP conversation.  Uses addresses discovered in attribute
           rather than connection information of media session line
           (already handled in media conversion) */
        if (media_desc->proto == SDP_PROTO_MSRP && msrp_handle) {
            msrp_add_address(pinfo, &media_desc->conn_addr, media_desc->media_port, "SDP", pinfo->num);
        }

        /* Add BFCP conversation.  Uses addresses discovered in attribute
           rather than connection information of media session line
           (already handled in media conversion) */
        if (media_desc->proto == SDP_PROTO_BFCP && bfcp_handle) {
            bfcp_add_address(pinfo, PT_UDP, &media_desc->conn_addr, media_desc->media_port, "SDP", establish_frame);
        }
    } /* end of loop through all media descriptions. */

    /* Copy the list of setup info of calls with the same RTP information
     * to the transport info, so that we have it when dissecting the
     * request as well.
     * XXX - There can be multiple media descriptions, and while this SDP's
     * setup info is on all of them, some other SDP might have some but not
     * all media descriptions, so the arrays of setup infos might be different.
     * They should be consolidated as with rtp_add_setup_info_if_no_duplicate()
     * in packet-rtp.c, or stored with each media descriptor.
     */
    setup_info_list = p_get_proto_data(pinfo->pool, pinfo, proto_sdp, 0);
    if (setup_info_list) {
        transport_info->sdp_setup_info_list = setup_info_list;
    }
}

void
setup_sdp_transport(tvbuff_t *tvb, packet_info *pinfo, enum sdp_exchange_type exchange_type,
    int request_frame, const bool delay, sdp_setup_info_t *setup_info)
{
    int         offset = 0, next_offset, n;
    int         linelen;
    bool        in_media_description = false;
    unsigned char      type, delim;
    const int   tokenoffset = 2;
    int         hf     = -1;
    int         start_transport_info_count = 0;
    transport_info_t* transport_info = NULL;
    media_description_t *media_desc = NULL;
    session_info_t session_info;
    sdp_data_t  sdp_data;

    DPRINT2(("-------------------- setup_sdp_transport -------------------"));

    /* Only do this once during first pass */
    if (pinfo->fd->visited) {
        DPRINT(("already visited"));
        return;
    }

    memset(&sdp_data, 0, sizeof(sdp_data));

    if (request_frame != 0)
        transport_info = (transport_info_t*)wmem_tree_lookup32( sdp_transport_reqs, request_frame );
    if (transport_info == NULL) {
        transport_info = wmem_new0(wmem_file_scope(), transport_info_t);
        transport_info->media_descriptions = wmem_array_new(wmem_file_scope(), sizeof(media_description_t));

        for (n = 0; n < SDP_NO_OF_PT; n++) {
            /* String is file scope allocated because transport_info is connection related */
            transport_info->encoding_name[n] = wmem_strdup(wmem_file_scope(), UNKNOWN_ENCODING);
        }

        if (request_frame != 0)
            wmem_tree_insert32(sdp_transport_reqs, request_frame, (void *)transport_info);
    }
#ifdef DEBUG_CONVERSATION
    else {
        DPRINT(("found previous transport_info:"));
        sdp_dump_transport_info(pinfo, transport_info);
    }
#endif

    if (exchange_type != SDP_EXCHANGE_OFFER)
        wmem_tree_insert32(sdp_transport_rsps, pinfo->num, (void *)transport_info);

    /* Offer has already been answered or rejected and hash tables freed, so
     * don't try to add to it
     * XXX - Need to support "modified offers" */
    if ((transport_info->sdp_status == SDP_EXCHANGE_ANSWER_REJECT) ||
        (transport_info->sdp_status == SDP_EXCHANGE_ANSWER_ACCEPT))
        return;

    /* Initialize the session description before parsing the media descriptions. */
    memset(&session_info, 0, sizeof(session_info_t));
    session_info.rtp_dyn_payload = rtp_dyn_payload_new();

    /* Remember where the answer should start (it will be zero if there was no
     * previous offer with media descriptions). */
    start_transport_info_count = wmem_array_get_count(transport_info->media_descriptions);

    DPRINT(("start_transport_info_count=%d", start_transport_info_count));

    /*
     * Show the SDP message a line at a time.
     */
    while (tvb_offset_exists(tvb, offset)) {
        /*
         * Find the end of the line.
         */
        linelen = tvb_find_line_end_unquoted(tvb, offset, -1, &next_offset);

        /*
         * Line must contain at least e.g. "v=".
         */
        if (linelen < 2)
            break;

        type  = tvb_get_uint8(tvb, offset);
        delim = tvb_get_uint8(tvb, offset + 1);
        if (delim != '=') {
            offset = next_offset;
            continue;
        }

        /*
         * Attributes.  Only care about ones that affect the transport.  Ignore others.
         */
        switch (type) {
            case 'c':
                hf = hf_connection_info;
                break;
            case 'm':
                hf = hf_media;

                /* Try to create a new media description (it will return NULL if
                 * there are too many). */
                media_desc = sdp_new_media_description(transport_info->media_descriptions, &session_info);

                in_media_description = true;
                DPRINT(("in media description, media descriptions count=%d",
                        wmem_array_get_count(transport_info->media_descriptions)));
                break;
            case 'a':
                if (in_media_description) {
                    hf = hf_media_attribute;
                } else {
                    hf = hf_session_attribute;
                }
                break;
            default:
                hf = hf_unknown;
                break;
        }

        if (hf != hf_unknown)
        {
            DINDENT();
            call_sdp_subdissector(tvb_new_subset_length(tvb, offset + tokenoffset,
                                                   linelen - tokenoffset),
                                    pinfo,
                                    hf, NULL, linelen-tokenoffset,
                                    transport_info,
                                    in_media_description ? NULL : &session_info,
                                    media_desc,
                                    &sdp_data);
            DENDENT();
        }

        offset = next_offset;
    }

    /* Done parsing media description, no more need for the session-level details. */
    rtp_dyn_payload_free(session_info.rtp_dyn_payload);
    session_info.rtp_dyn_payload = NULL;

    /* Post-processing, close media streams, apply attributes, etc. */
    complete_descriptions(transport_info, start_transport_info_count);

#ifdef DEBUG_CONVERSATION
    sdp_dump_transport_info(pinfo, transport_info);
#endif

    /* We have a successful negotiation, apply data to their respective protocols */
    if (!delay || ((exchange_type == SDP_EXCHANGE_ANSWER_ACCEPT) &&
        (transport_info->sdp_status == SDP_EXCHANGE_OFFER))) {
        /* Accepting answer to a previous offer (or delay pref is false). */
        apply_sdp_transport(pinfo, transport_info, request_frame, setup_info);

        /* Free all media hash tables that were not assigned to a conversation
         * ('set_rtp' is false) */
        clean_unused_media_descriptions(transport_info->media_descriptions);

        transport_info->sdp_status = exchange_type;

    } else if ((exchange_type == SDP_EXCHANGE_ANSWER_REJECT) &&
               (transport_info->sdp_status != SDP_EXCHANGE_ANSWER_REJECT)) {
        /* Rejecting answer */
        clean_unused_media_descriptions(transport_info->media_descriptions);

        transport_info->sdp_status = SDP_EXCHANGE_ANSWER_REJECT;
    } /* else attempt to accept an unknown offer. */
}

void setup_sdp_transport_resend(int current_frame, int request_frame)
{
    transport_info_t* transport_info = NULL;

    if (request_frame != 0) {
        transport_info = (transport_info_t*)wmem_tree_lookup32( sdp_transport_reqs, request_frame );
        if (transport_info != NULL) {
            wmem_tree_insert32(sdp_transport_reqs, current_frame, (void *)transport_info);
        }
    }
}

static int
dissect_sdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_tree *sdp_tree;
    proto_item *ti, *sub_ti;
    int         offset = 0, next_offset, n;
    int         linelen;
    bool        in_media_description;
    unsigned char      type, delim;
    int         datalen, tokenoffset, hf = -1;
    char       *string;
    sdp_data_t  sdp_data;

    transport_info_t  local_transport_info;
    transport_info_t* transport_info = NULL;
    media_description_t *media_desc = NULL;
    session_info_t session_info;
    sdp_packet_info  *sdp_pi;
    sdp_setup_info_t *setup_info = NULL;

    if (data) {
        media_content_info_t *content_info = (media_content_info_t *)data;
        if (content_info->type == MEDIA_CONTAINER_SIP_DATA) {
            setup_info = (sdp_setup_info_t *)content_info->data;
        }
    }

    DPRINT2(("----------------------- dissect_sdp ------------------------"));

    /* Initialise packet info for passing to tap */
    sdp_pi = wmem_new(pinfo->pool, sdp_packet_info);
    sdp_pi->summary_str[0] = '\0';

    memset(&sdp_data, 0, sizeof(sdp_data));

    transport_info = (transport_info_t*)wmem_tree_lookup32( sdp_transport_reqs, pinfo->num );

    if (transport_info == NULL) {
      /* Can't find it in the requests, make sure it's not a response */
      transport_info = (transport_info_t*)wmem_tree_lookup32( sdp_transport_rsps, pinfo->num );
    }

    if (transport_info == NULL) {
      transport_info = &local_transport_info;
    }
#ifdef DEBUG_CONVERSATION
    else {
        DPRINT(("found previous transport_info:"));
        sdp_dump_transport_info(pinfo, transport_info);
    }
#endif

    /* Initialize local transport info */
    memset(&local_transport_info, 0, sizeof(local_transport_info));
    /* Note: packet-scoped since it is only needed while parsing this packet. */
    local_transport_info.media_descriptions = wmem_array_new(pinfo->pool, sizeof(media_description_t));

    for (n = 0; n < SDP_NO_OF_PT; n++) {
        local_transport_info.encoding_name[n] = wmem_strdup(pinfo->pool, UNKNOWN_ENCODING);
    }

    /*
     * As RFC 2327 says, "SDP is purely a format for session
     * description - it does not incorporate a transport protocol,
     * and is intended to use different transport protocols as
     * appropriate including the Session Announcement Protocol,
     * Session Initiation Protocol, Real-Time Streaming Protocol,
     * electronic mail using the MIME extensions, and the
     * Hypertext Transport Protocol."
     *
     * We therefore don't set the protocol or info columns;
     * instead, we append to them, so that we don't erase
     * what the protocol inside which the SDP stuff resides
     * put there.
     */
    col_append_str(pinfo->cinfo, COL_PROTOCOL, "/SDP");

    ti = proto_tree_add_item(tree, proto_sdp, tvb, offset, -1, ENC_NA);
    sdp_tree = proto_item_add_subtree(ti, ett_sdp);

    /*
     * Show the SDP message a line at a time.
     */
    in_media_description = false;

    /* Initialize the session description before parsing the media level. */
    memset(&session_info, 0, sizeof(session_info_t));
    session_info.rtp_dyn_payload = rtp_dyn_payload_new();

    while (tvb_offset_exists(tvb, offset)) {
        /*
         * Find the end of the line.
         */
        linelen = tvb_find_line_end_unquoted(tvb, offset, -1, &next_offset);

        /*
         * Line must contain at least e.g. "v=".
         */
        if (linelen < 2)
            break;

        type  = tvb_get_uint8(tvb, offset);
        delim = tvb_get_uint8(tvb, offset + 1);
        if (delim != '=') {
            proto_item *ti2 = proto_tree_add_item(sdp_tree, hf_invalid, tvb, offset, linelen, ENC_UTF_8);
            expert_add_info(pinfo, ti2, &ei_sdp_invalid_line_equal);
            offset = next_offset;
            continue;
        }

        /*
         * Attributes.
         */
        switch (type) {
            case 'v':
                hf = hf_protocol_version;
                break;
            case 'o':
                hf = hf_owner;
                break;
            case 's':
                hf = hf_session_name;
                break;
            case 'i':
                if (in_media_description) {
                  hf = hf_media_title;
                } else {
                  hf = hf_session_info;
                }
                break;
            case 'u':
                hf = hf_uri;
                break;
            case 'e':
                hf = hf_email;
                break;
            case 'p':
                hf = hf_phone;
                break;
            case 'c':
                hf = hf_connection_info;
                break;
            case 'b':
                hf = hf_bandwidth;
                break;
            case 't':
                hf = hf_time;
                break;
            case 'r':
                hf = hf_repeat_time;
                break;
            case 'm':
                hf = hf_media;

                /* Try to create a new media description (it will return NULL if
                 * there are too many). Pass local_transport_info since we do
                 * not want to modify the transport_info that was created by
                 * setup_sdp_transport. */
                media_desc = sdp_new_media_description(local_transport_info.media_descriptions, &session_info);

                in_media_description = true;
                break;
            case 'k':
                hf = hf_encryption_key;
                break;
            case 'a':
                if (in_media_description) {
                    hf = hf_media_attribute;
                } else {
                    hf = hf_session_attribute;
                }
                break;
            case 'z':
                hf = hf_timezone;
                break;
            default:
                hf = hf_unknown;
                break;
        }
        tokenoffset = 2;
        if (hf == hf_unknown)
            tokenoffset = 0;
        string = (char*)tvb_get_string_enc(pinfo->pool, tvb, offset + tokenoffset,
                                                 linelen - tokenoffset, ENC_ASCII);
        sub_ti = proto_tree_add_string(sdp_tree, hf, tvb, offset, linelen,
                                       string);

        call_sdp_subdissector(tvb_new_subset_length(tvb, offset + tokenoffset,
                                             linelen - tokenoffset),
                              pinfo,
                              hf, sub_ti, linelen-tokenoffset,
                              &local_transport_info,
                              in_media_description ? NULL : &session_info,
                              in_media_description ? media_desc : NULL,
                              &sdp_data);

        offset = next_offset;
    }

    if (NULL != sdp_data.ed137_fid) {
      col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", sdp_data.ed137_fid);
      (void) g_strlcat(sdp_pi->summary_str, sdp_data.ed137_fid, 50);
    }
    if (NULL != sdp_data.ed137_txrxmode) {
      col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", sdp_data.ed137_txrxmode);
      if (strlen(sdp_pi->summary_str))
          (void) g_strlcat(sdp_pi->summary_str, " ", 50);
      (void) g_strlcat(sdp_pi->summary_str, sdp_data.ed137_txrxmode, 50);
    }
    if (NULL != sdp_data.ed137_type) {
      col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", sdp_data.ed137_type);
      if (strlen(sdp_pi->summary_str))
          (void) g_strlcat(sdp_pi->summary_str, " ", 50);
      (void) g_strlcat(sdp_pi->summary_str, sdp_data.ed137_type, 50);
    }

    /* Done parsing media description, no more need for the session-level details. */
    rtp_dyn_payload_free(session_info.rtp_dyn_payload);
    session_info.rtp_dyn_payload = NULL;

    /* Post-processing, close media streams, apply attributes, etc. */
    if (transport_info == &local_transport_info) {
        DPRINT(("no previous transport_info saved, calling complete_descriptions()"));
        DINDENT();
        complete_descriptions(transport_info, 0);
        DENDENT();
#ifdef DEBUG_CONVERSATION
        sdp_dump_transport_info(pinfo, transport_info);
#endif
    }
#ifdef DEBUG_CONVERSATION
    else {
        DPRINT(("not overwriting previous transport_info, local_transport_info contents:"));
        sdp_dump_transport_info(pinfo, &local_transport_info);
    }
#endif

    /* For messages not part of the Offer/Answer model, assume that the SDP is
     * immediately effective (apply it now). */
    if ((!pinfo->fd->visited) && (transport_info == &local_transport_info)) {
        /* XXX - This is a placeholder for higher layer protocols that haven't implemented the proper
         * OFFER/ANSWER functionality using setup_sdp_transport().  Once all of the higher layers
         * use setup_sdp_transport(), this should be removed
         * Note that transport_info contains the SDP info from this frame (and
         * not an earlier request (transport_info == &local_transport_info).
         * Use 0 as request_frame since there is no (known) request.
         */
        apply_sdp_transport(pinfo, transport_info, 0, setup_info);
        /* Save the list of setup info of calls with the same RTP information
         * to the packet in file scope, since transport_info is local and
         * we won't do this on future passes.
         */
        p_add_proto_data(wmem_file_scope(), pinfo, proto_sdp, 0, transport_info->sdp_setup_info_list);
    }

    /* Add information to the VoIP Calls dialog. */
    for (unsigned i = 0; i < wmem_array_get_count(local_transport_info.media_descriptions); i++)
    {
        media_desc = (media_description_t *)wmem_array_index(local_transport_info.media_descriptions, i);

        if (media_desc->media_port != 0) {
            /* Create the RTP summary str for the Voip Call analysis.
             * XXX - Currently this is based only on the current packet
             */
            for (int j = 0; j < media_desc->media.pt_count; j++)
            {
                DPRINT(("in for-loop for voip call analysis setting for media #%d, pt=%d",
                        j, media_desc->media. pt[j]));
                /* if the payload type is dynamic (96 to 127), check the hash table to add the desc in the SDP summary */
                if ((media_desc->media.pt[j] >= 96) && (media_desc->media.pt[j] <= 127)) {
                    const char *payload_type_str = rtp_dyn_payload_get_name(
                        media_desc->media.rtp_dyn_payload,
                        media_desc->media.pt[j]);
                    if (payload_type_str) {
                        if (strlen(sdp_pi->summary_str))
                            (void) g_strlcat(sdp_pi->summary_str, " ", 50);
                        (void) g_strlcat(sdp_pi->summary_str, payload_type_str, 50);
                    } else {
                        char num_pt[10];
                        snprintf(num_pt, 10, "%u", media_desc->media.pt[j]);
                        if (strlen(sdp_pi->summary_str))
                            (void) g_strlcat(sdp_pi->summary_str, " ", 50);
                        (void) g_strlcat(sdp_pi->summary_str, num_pt, 50);
                      }
                } else {
                    if (strlen(sdp_pi->summary_str))
                        (void) g_strlcat(sdp_pi->summary_str, " ", 50);
                    (void) g_strlcat(sdp_pi->summary_str,
                              val_to_str_ext(media_desc->media.pt[j], &rtp_payload_type_short_vals_ext, "%u"),
                              50);
                }
            }
        }

        /* Create the T38 summary str for the Voip Call analysis
         * XXX - Currently this is based only on the current packet
         */
        if ((media_desc->media_port != 0) && media_desc->proto == SDP_PROTO_T38) {
            if (strlen(sdp_pi->summary_str))
                (void) g_strlcat(sdp_pi->summary_str, " ", 50);
            (void) g_strlcat(sdp_pi->summary_str, "t38", 50);
        }
    }

    /* Free all media hash tables that were not assigned to a conversation
     * ('set_rtp' is false) */
    if (transport_info == &local_transport_info) {
        clean_unused_media_descriptions(transport_info->media_descriptions);
    }

    datalen = tvb_captured_length_remaining(tvb, offset);
    if (datalen > 0) {
        proto_tree_add_item(sdp_tree, hf_sdp_data, tvb, offset, datalen, ENC_NA);
    }
    /* Add Trace info */
    wmem_array_t *setup_info_list = transport_info->sdp_setup_info_list;
    if (!setup_info_list) {
        setup_info_list = (wmem_array_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_sdp, 0);
    }
    if (setup_info_list) {
        unsigned i;
        sdp_setup_info_t *stored_setup_info;
        proto_item *item;
        for (i = 0; i < wmem_array_get_count(setup_info_list); i++) {
            stored_setup_info = (sdp_setup_info_t *)wmem_array_index(setup_info_list, i);
            if (stored_setup_info->hf_id) {
                if (stored_setup_info->hf_type == SDP_TRACE_ID_HF_TYPE_STR) {
                    item = proto_tree_add_string(sdp_tree, stored_setup_info->hf_id, tvb, 0, 0, stored_setup_info->trace_id.str);
                    proto_item_set_generated(item);
                    if (stored_setup_info->add_hidden == true) {
                        proto_item_set_hidden(item);
                    }
                } else if (stored_setup_info->hf_type == SDP_TRACE_ID_HF_TYPE_GUINT32) {
                    item = proto_tree_add_uint(sdp_tree, stored_setup_info->hf_id, tvb, 0, 0, stored_setup_info->trace_id.num);
                    proto_item_set_generated(item);
                    if (stored_setup_info->add_hidden == true) {
                        proto_item_set_hidden(item);
                    }
                }
            }
        }
    }
    /* Report this packet to the tap */
    tap_queue_packet(sdp_tap, pinfo, sdp_pi);

    return tvb_captured_length(tvb);
}

void
proto_register_sdp(void)
{
    static hf_register_info hf[] = {
        { &hf_protocol_version,
            { "Session Description Protocol Version (v)", "sdp.version",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_owner,
            { "Owner/Creator, Session Id (o)",
              "sdp.owner", FT_STRING, BASE_NONE, NULL,
              0x0, NULL, HFILL}
        },
        { &hf_session_name,
            { "Session Name (s)", "sdp.session_name",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_session_info,
            { "Session Information (i)", "sdp.session_info",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_uri,
            { "URI of Description (u)", "sdp.uri",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_email,
            { "E-mail Address (e)", "sdp.email",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_phone,
            { "Phone Number (p)", "sdp.phone",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_connection_info,
            { "Connection Information (c)", "sdp.connection_info",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_bandwidth,
            { "Bandwidth Information (b)", "sdp.bandwidth",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_timezone,
            { "Time Zone Adjustments (z)", "sdp.timezone",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_encryption_key,
            { "Encryption Key (k)", "sdp.encryption_key",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_session_attribute,
            { "Session Attribute (a)", "sdp.session_attr",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_media_attribute,
            { "Media Attribute (a)", "sdp.media_attr",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_time,
            { "Time Description, active time (t)",
              "sdp.time", FT_STRING, BASE_NONE, NULL,
              0x0, NULL, HFILL }
        },
        { &hf_repeat_time,
            { "Repeat Time (r)", "sdp.repeat_time",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_media,
            { "Media Description, name and address (m)",
              "sdp.media", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_media_title,
            { "Media Title (i)", "sdp.media_title",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_unknown,
            { "Unknown", "sdp.unknown",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_invalid,
            { "Invalid line", "sdp.invalid",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_owner_username,
            { "Owner Username", "sdp.owner.username",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_owner_sessionid,
            { "Session ID", "sdp.owner.sessionid",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_owner_version,
            { "Session Version", "sdp.owner.version",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_owner_network_type,
            { "Owner Network Type", "sdp.owner.network_type",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_owner_address_type,
            { "Owner Address Type", "sdp.owner.address_type",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_owner_address,
            { "Owner Address", "sdp.owner.address",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_connection_info_network_type,
            { "Connection Network Type", "sdp.connection_info.network_type",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_connection_info_address_type,
            { "Connection Address Type", "sdp.connection_info.address_type",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_connection_info_connection_address,
            { "Connection Address", "sdp.connection_info.address",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_connection_info_ttl,
            { "Connection TTL", "sdp.connection_info.ttl",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_connection_info_num_addr,
            { "Connection Number of Addresses", "sdp.connection_info.num_addr",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_bandwidth_modifier,
            { "Bandwidth Modifier", "sdp.bandwidth.modifier",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_bandwidth_value,
            { "Bandwidth Value", "sdp.bandwidth.value",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "Bandwidth Value (in kbits/s)", HFILL }
        },
        { &hf_time_start,
            { "Session Start Time", "sdp.time.start",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_time_stop,
            { "Session Stop Time", "sdp.time.stop",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_repeat_time_interval,
            { "Repeat Interval", "sdp.repeat_time.interval",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_repeat_time_duration,
            { "Repeat Duration", "sdp.repeat_time.duration",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_repeat_time_offset,
            { "Repeat Offset", "sdp.repeat_time.offset",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_timezone_time,
            { "Timezone Time", "sdp.timezone.time",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_timezone_offset,
            { "Timezone Offset", "sdp.timezone.offset",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_encryption_key_type,
            { "Key Type", "sdp.encryption_key.type",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_encryption_key_data,
            { "Key Data", "sdp.encryption_key.data",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_session_attribute_field,
            { "Session Attribute Fieldname", "sdp.session_attr.field",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_session_attribute_value,
            { "Session Attribute Value", "sdp.session_attr.value",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_media_media,
            { "Media Type", "sdp.media.media",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_media_port,
            { "Media Port", "sdp.media.port",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_media_port_string,
            { "Media Port", "sdp.media.port_string",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_media_portcount,
            { "Media Port Count", "sdp.media.portcount",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_media_proto,
            { "Media Protocol", "sdp.media.proto",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_media_format,
            { "Media Format", "sdp.media.format",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_media_attribute_field,
            { "Media Attribute Fieldname", "sdp.media_attribute.field",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_media_attribute_value,
            { "Media Attribute Value", "sdp.media_attribute.value",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_media_encoding_name,
            { "MIME Type", "sdp.mime.type",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "SDP MIME Type", HFILL }
        },
        { &hf_media_sample_rate,
            { "Sample Rate", "sdp.sample_rate",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_media_channels,
            { "Audio Channels", "sdp.channels",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_media_format_specific_parameter,
            { "Media format specific parameters", "sdp.fmtp.parameter",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "Format specific parameter(fmtp)", HFILL }
        },
        { &hf_ipbcp_version,
            { "IPBCP Protocol Version", "sdp.ipbcp.version",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_ipbcp_type,
            { "IPBCP Command Type", "sdp.ipbcp.command",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        {&hf_sdp_fmtp_mpeg4_profile_level_id,
           { "Level Code", "sdp.fmtp.profile_level_id",
             FT_UINT32, BASE_DEC, VALS(mp4ves_level_indication_vals), 0x0,
             NULL, HFILL }
        },
        { &hf_sdp_fmtp_h263_profile,
            { "Profile", "sdp.fmtp.h263profile",
              FT_UINT32, BASE_DEC, VALS(h263_profile_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_sdp_fmtp_h263_level,
            { "Level", "sdp.fmtp.h263level",
              FT_UINT32, BASE_DEC, VALS(h263_level_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_sdp_h264_packetization_mode,
            { "Packetization mode", "sdp.fmtp.h264_packetization_mode",
              FT_UINT32, BASE_DEC, VALS(h264_packetization_mode_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_SDPh223LogicalChannelParameters,
            { "h223LogicalChannelParameters", "sdp.h223LogicalChannelParameters",
              FT_NONE, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_key_mgmt_att_value,
            { "Key Management", "sdp.key_mgmt",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_key_mgmt_prtcl_id,
            { "Key Management Protocol (kmpid)", "sdp.key_mgmt.kmpid",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_key_mgmt_data,
            { "Key Management Data", "sdp.key_mgmt.data",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_sdp_crypto_tag,
            { "tag", "sdp.crypto.tag",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_sdp_crypto_crypto_suite,
            { "Crypto suite", "sdp.crypto.crypto_suite",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_sdp_crypto_master_key,
            { "Master Key", "sdp.crypto.master_key",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_sdp_crypto_master_salt,
            { "Master salt", "sdp.crypto.master_salt",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_sdp_crypto_lifetime,
            { "Lifetime", "sdp.crypto.lifetime",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_sdp_crypto_mki,
            { "mki-value", "sdp.crypto.mki-valu",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_sdp_crypto_mki_length,
            { "mki_length", "sdp.crypto.mki_length",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_ice_candidate_foundation,
            { "Foundation", "sdp.ice_candidate.foundation",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "Identifier, same for two candidates with same type, base address, protocol and STUN server", HFILL }
        },
        { &hf_ice_candidate_componentid,
            { "Component ID", "sdp.ice_candidate.componentid",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "Media component identifier (For RTP media, 1 is RTP, 2 is RTCP)", HFILL }
        },
        { &hf_ice_candidate_transport,
            { "Transport", "sdp.ice_candidate.transport",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "Transport protocol", HFILL }
        },
        { &hf_ice_candidate_priority,
            { "Priority", "sdp.ice_candidate.priority",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_ice_candidate_address,
            { "Connection Address", "sdp.ice_candidate.address",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "IP address or FQDN of the candidate", HFILL }
        },
        { &hf_ice_candidate_port,
            { "Candidate Port", "sdp.ice_candidate.port",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "Port of the candidate", HFILL }
        },
        { &hf_ice_candidate_type,
            { "Candidate Type", "sdp.ice_candidate.type",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "The origin of the address and port, i.e. where it was learned", HFILL }
        },
      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_sdp_nal_unit_1_string, { "NAL unit 1 string", "sdp.nal_unit_1_string", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_sdp_nal_unit_2_string, { "NAL unit 2 string", "sdp.nal_unit_2_string", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_sdp_key_and_salt, { "Key and Salt", "sdp.key_and_salt", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_sdp_data, { "Data", "sdp.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };
    static int *ett[] = {
        &ett_sdp,
        &ett_sdp_owner,
        &ett_sdp_connection_info,
        &ett_sdp_bandwidth,
        &ett_sdp_time,
        &ett_sdp_repeat_time,
        &ett_sdp_timezone,
        &ett_sdp_encryption_key,
        &ett_sdp_session_attribute,
        &ett_sdp_media,
        &ett_sdp_media_attribute,
        &ett_sdp_fmtp,
        &ett_sdp_key_mgmt,
        &ett_sdp_crypto_key_parameters,
    };

    static ei_register_info ei[] = {
        { &ei_sdp_invalid_key_param,
            { "sdp.invalid_key_param",
              PI_MALFORMED, PI_NOTE,
              "Invalid key-param (no ':' delimiter)",
              EXPFILL
            }
        },
        { &ei_sdp_invalid_line_equal,
            { "sdp.invalid_line.no_equal",
              PI_MALFORMED, PI_NOTE,
              "Invalid SDP line (no '=' delimiter)",
              EXPFILL
            }
        },
        { &ei_sdp_invalid_line_fields,
            { "sdp.invalid_line.missing_fields",
              PI_MALFORMED, PI_ERROR,
              "Invalid SDP line (missing required fields)",
              EXPFILL
            }
        },
        { &ei_sdp_invalid_line_space,
            { "sdp.invalid_line.extra_space",
              PI_MALFORMED, PI_ERROR,
              "Invalid SDP whitespace (extra space character)",
              EXPFILL
            }
        },
        { &ei_sdp_invalid_conversion,
            { "sdp.invalid_conversion",
              PI_PROTOCOL, PI_WARN,
              "Invalid conversion",
              EXPFILL
            }
        },
        { &ei_sdp_invalid_media_port,
            { "sdp.invalid_media_port",
              PI_MALFORMED, PI_ERROR,
              "Invalid media port",
              EXPFILL
            }
        },
        { &ei_sdp_invalid_sample_rate,
            { "sdp.invalid_sample_rate",
              PI_MALFORMED, PI_ERROR,
              "Invalid sample rate",
              EXPFILL
            }
        },
        { &ei_sdp_invalid_channels,
            { "sdp.invalid_channels",
              PI_MALFORMED, PI_WARN,
              "Invalid number of audio channels",
              EXPFILL
            }
        },
        { &ei_sdp_invalid_media_format,
            { "sdp.invalid_media_format",
              PI_MALFORMED, PI_ERROR,
              "Invalid media format",
              EXPFILL
            }
        },
        { &ei_sdp_invalid_crypto_tag,
            { "sdp.invalid_crypto_tag",
              PI_MALFORMED, PI_ERROR,
              "Invalid crypto tag",
              EXPFILL
            }
        },
        { &ei_sdp_invalid_crypto_mki_length,
            { "sdp.invalid_crypto_mki_length",
              PI_MALFORMED, PI_ERROR,
              "Invalid crypto mki length",
              EXPFILL
            }
        }
    };

    module_t *sdp_module;
    expert_module_t* expert_sdp;

    proto_sdp = proto_register_protocol("Session Description Protocol",
                                        "SDP", "sdp");
    proto_register_field_array(proto_sdp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_sdp = expert_register_protocol(proto_sdp);
    expert_register_field_array(expert_sdp, ei, array_length(ei));

    key_mgmt_dissector_table = register_dissector_table("key_mgmt",
                                                        "Key Management", proto_sdp, FT_STRING, STRING_CASE_SENSITIVE);
    /*
     * Preferences registration
     */
    sdp_module = prefs_register_protocol(proto_sdp, NULL);
    prefs_register_bool_preference(sdp_module, "establish_conversation",
                                   "Establish Media Conversation",
                                   "Specifies that RTP/RTCP/T.38/MSRP/etc streams are decoded based "
                                   "upon port numbers found in SDP payload",
                                   &global_sdp_establish_conversation);

    sdp_transport_reqs = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    sdp_transport_rsps = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    /*
     * Register the dissector by name, so other dissectors can
     * grab it by name rather than just referring to it directly.
     */
    sdp_handle = register_dissector("sdp", dissect_sdp, proto_sdp);

    /* Register for tapping */
    sdp_tap = register_tap("sdp");

    /* compile patterns */
    ws_mempbrk_compile(&pbrk_digits, "0123456789");
    ws_mempbrk_compile(&pbrk_alpha, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
}

void
proto_reg_handoff_sdp(void)
{
    rtcp_handle   = find_dissector_add_dependency("rtcp", proto_sdp);
    msrp_handle   = find_dissector_add_dependency("msrp", proto_sdp);
    sprt_handle   = find_dissector_add_dependency("sprt", proto_sdp);
    bfcp_handle   = find_dissector_add_dependency("bfcp", proto_sdp);
    h264_handle   = find_dissector_add_dependency("h264", proto_sdp);
    h265_handle   = find_dissector_add_dependency("h265", proto_sdp);
    mp4ves_config_handle = find_dissector_add_dependency("mp4ves_config", proto_sdp);

    proto_sprt    = dissector_handle_get_protocol_index(find_dissector("sprt"));

    dissector_add_string("media_type", "application/sdp", sdp_handle);
    dissector_add_uint("bctp.tpi", 0x20, sdp_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
