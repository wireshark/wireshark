/* packet-rtp.c
 *
 * Routines for RTP dissection
 * RTP = Real time Transport Protocol
 *
 * Copyright 2000, Philips Electronics N.V.
 * Written by Andreas Sikkema <h323@ramdyne.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * This dissector tries to dissect the RTP protocol according to Annex A
 * of ITU-T Recommendation H.225.0 (02/98) or RFC 3550 (obsoleting 1889).
 *
 * RTP traffic is traditionally handled by an even UDP portnumber. This can
 * be any port number, but there is a registered port available, port 5004
 * See Annex B of ITU-T Recommendation H.225.0, section B.7
 *
 * Note that nowadays RTP and RTCP are often multiplexed onto a single port,
 * per RFC 5671.
 *
 * This doesn't dissect older versions of RTP, such as:
 *
 *    the vat protocol ("version 0") - see
 *
 *  ftp://ftp.ee.lbl.gov/conferencing/vat/alpha-test/vatsrc-4.0b2.tar.gz
 *
 *    and look in "session-vat.cc" if you want to write a dissector
 *    (have fun - there aren't any nice header files showing the packet
 *    format);
 *
 *    version 1, as documented in
 *
 *  ftp://gaia.cs.umass.edu/pub/hgschulz/rtp/draft-ietf-avt-rtp-04.txt
 *
 * It also dissects PacketCable CCC-encapsulated RTP data, as described in
 * chapter 5 of the PacketCable Electronic Surveillance Specification:
 *
 *   http://www.packetcable.com/downloads/specs/PKT-SP-ESP1.5-I01-050128.pdf
 */


#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/decode_as.h>

#include "packet-rtp.h"
#include "packet-rtcp.h"
#include "packet-tcp.h"

#include <epan/rtp_pt.h>
#include <epan/tap.h>
#include <epan/prefs.h>

/* un-comment the following as well as this line in conversation.c, to enable debug printing */
/* #define DEBUG_CONVERSATION */
#include "conversation_debug.h"

/* uncomment this to enable debugging of fragment reassembly */
/* #define DEBUG   1 */
/* #define DEBUG_FRAGMENTS   1 */

typedef struct _rfc2198_hdr {
    unsigned int pt;
    int offset;
    int len;
    const char* payload_type_str;
    int payload_rate;
    unsigned payload_channels;
    wmem_map_t *payload_fmtp_map;
    struct _rfc2198_hdr *next;
} rfc2198_hdr;

/* we have one of these for each pdu which spans more than one segment
 */
typedef struct _rtp_multisegment_pdu {
    /* the seqno of the segment where the pdu starts */
    uint32_t startseq;

    /* the seqno of the segment where the pdu ends */
    uint32_t endseq;
} rtp_multisegment_pdu;

typedef struct  _rtp_private_conv_info {
    /* This tree is indexed by sequence number and keeps track of all
     * all pdus spanning multiple segments for this flow.
     */
    wmem_tree_t *multisegment_pdus;
} rtp_private_conv_info;

typedef struct _rtp_number_space {

    uint32_t extended_seqno;
    uint64_t extended_timestamp;
} rtp_number_space;

/** Info to save in RTP conversation */
struct _rtp_conversation_info
{
    char     method[MAX_RTP_SETUP_METHOD_SIZE + 1];
    uint32_t frame_number;                          /**> the frame where this conversation is started */
    uint32_t media_types;
    rtp_dyn_payload_t* rtp_dyn_payload;             /**> the dynamic RTP payload info - see comments above */

    wmem_map_t* ssrc_number_space;                  /**> maps the SSRCs to the last seen seqno and timestamp
                                                     * for that SSRC in the conversation */
    struct _rtp_private_conv_info* rtp_conv_info;   /**> conversation info private
                                                     * to the rtp dissector
                                                     */
    struct srtp_info* srtp_info;                    /* SRTP context */
    bta2dp_codec_info_t* bta2dp_info;
    btvdp_codec_info_t* btvdp_info;
    wmem_array_t* rtp_sdp_setup_info_list;           /**> List with data from all SDP occurrences for this stream holding a call ID)*/
};

typedef struct {
    char *encoding_name;
    int   sample_rate;
    unsigned channels;
    wmem_map_t *fmtp_map;
} encoding_name_and_rate_t;

struct _rtp_dyn_payload_t
{
    GHashTable *table;
    size_t ref_count;
};

static reassembly_table rtp_reassembly_table;

static int hf_rtp_fragments;
static int hf_rtp_fragment;
static int hf_rtp_fragment_overlap;
static int hf_rtp_fragment_overlap_conflict;
static int hf_rtp_fragment_multiple_tails;
static int hf_rtp_fragment_too_long_fragment;
static int hf_rtp_fragment_error;
static int hf_rtp_fragment_count;
static int hf_rtp_reassembled_in;
static int hf_rtp_reassembled_length;

static int ett_rtp_fragment;
static int ett_rtp_fragments;

static const fragment_items rtp_fragment_items = {
    &ett_rtp_fragment,
    &ett_rtp_fragments,
    &hf_rtp_fragments,
    &hf_rtp_fragment,
    &hf_rtp_fragment_overlap,
    &hf_rtp_fragment_overlap_conflict,
    &hf_rtp_fragment_multiple_tails,
    &hf_rtp_fragment_too_long_fragment,
    &hf_rtp_fragment_error,
    &hf_rtp_fragment_count,
    &hf_rtp_reassembled_in,
    &hf_rtp_reassembled_length,
    /* Reassembled data field */
    NULL,
    "RTP fragments"
};

static dissector_handle_t rtp_handle;
static dissector_handle_t rtp_rfc4571_handle;
static dissector_handle_t rtcp_handle;
static dissector_handle_t classicstun_handle;
static dissector_handle_t stun_handle;
static dissector_handle_t t38_handle;
static dissector_handle_t zrtp_handle;
static dissector_handle_t dtls_handle;
static dissector_handle_t rtp_rfc2198_handle;

static dissector_handle_t sprt_handle;
static dissector_handle_t v150fw_handle;

static dissector_handle_t bta2dp_content_protection_header_scms_t;
static dissector_handle_t btvdp_content_protection_header_scms_t;
static dissector_handle_t bta2dp_handle;
static dissector_handle_t btvdp_handle;
static dissector_handle_t sbc_handle;

static int rtp_tap;

static dissector_table_t rtp_pt_dissector_table;
static dissector_table_t rtp_dyn_pt_dissector_table;

static dissector_table_t rtp_hdr_ext_dissector_table;
static dissector_table_t rtp_hdr_ext_rfc5285_dissector_table;

/* Used for storing data to be retrieved by the SDP dissector*/
static int proto_sdp;

/* RTP header fields             */
static int proto_rtp;
static int proto_rtp_rfc2198;
static int hf_rtp_version;
static int hf_rtp_padding;
static int hf_rtp_extension;
static int hf_rtp_csrc_count;
static int hf_rtp_marker;
static int hf_rtp_payload_type;
static int hf_rtp_seq_nr;
static int hf_rtp_ext_seq_nr;
static int hf_rtp_timestamp;
static int hf_rtp_ext_timestamp;
static int hf_rtp_ssrc;
static int hf_rtp_csrc_items;
static int hf_rtp_csrc_item;
static int hf_rtp_data;
static int hf_rtp_padding_data;
static int hf_rtp_padding_count;
static int hf_rtp_rfc2198_follow;
static int hf_rtp_rfc2198_tm_off;
static int hf_rtp_rfc2198_bl_len;

/* RTP header extension fields   */
static int hf_rtp_prof_define;
static int hf_rtp_length;
static int hf_rtp_hdr_exts;
static int hf_rtp_hdr_ext;

/* RTP setup fields */
static int hf_rtp_setup;
static int hf_rtp_setup_frame;
static int hf_rtp_setup_method;

/* RTP fields defining a sub tree */
static int ett_rtp;
static int ett_csrc_list;
static int ett_hdr_ext;
static int ett_hdr_ext_rfc5285;
static int ett_rtp_setup;
static int ett_rtp_rfc2198;
static int ett_rtp_rfc2198_hdr;

/* SRTP fields */
static int hf_srtp_encrypted_payload;
/* static int hf_srtp_null_encrypted_payload; */
static int hf_srtp_mki;
static int hf_srtp_auth_tag;

/* PacketCable CCC header fields */
static int proto_pkt_ccc;
static int hf_pkt_ccc_id;
static int hf_pkt_ccc_ts;

/* PacketCable CCC field defining a sub tree */
static int ett_pkt_ccc;

static expert_field ei_rtp_fragment_unfinished;
static expert_field ei_rtp_padding_missing;
static expert_field ei_rtp_padding_bogus;

/* RFC 5285 Header extensions */
static int hf_rtp_ext_rfc5285_id;
static int hf_rtp_ext_rfc5285_length;
static int hf_rtp_ext_rfc5285_appbits;
static int hf_rtp_ext_rfc5285_data;

/* RFC 4571 Header extension */
static int hf_rfc4571_header_len;

#define RTP0_INVALID 0
#define RTP0_STUN    1
#define RTP0_CLASSICSTUN    2
#define RTP0_T38     3
#define RTP0_SPRT    4
#define RTP0_RFC7983 5

static const enum_val_t rtp_version0_types[] = {
    { "invalid", "Invalid or ZRTP packets", RTP0_INVALID },
    { "stun", "STUN packets", RTP0_STUN },
    { "classicstun", "CLASSIC-STUN packets", RTP0_CLASSICSTUN },
    { "t38", "T.38 packets", RTP0_T38 },
    { "sprt", "SPRT packets", RTP0_SPRT },
    { "rfc7983", "Multiplexed as in RFC 7983", RTP0_RFC7983 },
    { NULL, NULL, 0 }
};
static int global_rtp_version0_type = 5;

/* Forward declaration we need below */
void proto_register_rtp(void);
void proto_reg_handoff_rtp(void);
void proto_register_pkt_ccc(void);
void proto_reg_handoff_pkt_ccc(void);

static int dissect_rtp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static void show_setup_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static struct _rtp_packet_info *get_rtp_packet_info(packet_info *pinfo, struct _rtp_info *rtp_info);

/* Preferences bool to control whether or not setup info should be shown */
static bool global_rtp_show_setup_info = true;

/* desegment RTP streams */
static bool desegment_rtp = true;

/* RFC2198 Redundant Audio Data */
#define RFC2198_DEFAULT_PT_RANGE "99"

static bool rfc2198_deencapsulate = true;



/*
 * Fields in the first octet of the RTP header.
 */

/* Version is the first 2 bits of the first octet*/
#define RTP_VERSION(octet)  ((octet) >> 6)

/* Padding is the third bit; No need to shift, because true is any value
   other than 0! */
#define RTP_PADDING(octet)  ((octet) & 0x20)

/* Extension bit is the fourth bit */
#define RTP_EXTENSION(octet)    ((octet) & 0x10)

/* ED137 signature */
#define RTP_ED137_SIG    0x0067

/* ED137A signature */
#define RTP_ED137A_SIG   0x0167

/* RFC 5285 one byte header signature */
#define RTP_RFC5285_ONE_BYTE_SIG        0xBEDE

/* RFC 5285 two byte header mask and signature */
#define RTP_RFC5285_TWO_BYTE_MASK       0xFFF0
#define RTP_RFC5285_TWO_BYTE_SIG        0x1000

/* CSRC count is the last four bits */
#define RTP_CSRC_COUNT(octet)   ((octet) & 0xF)

static const value_string rtp_version_vals[] =
{
    { 2, "RFC 1889 Version" }, /* First for speed */
    { 0, "Old VAT Version" },
    { 1, "First Draft Version" },
    { 0, NULL },
};

static const range_string rtp_ext_profile_rvals[] =
{
    { RTP_ED137_SIG, RTP_ED137_SIG, "ED137" },
    { RTP_ED137A_SIG, RTP_ED137A_SIG, "ED137A" },
    { RTP_RFC5285_TWO_BYTE_SIG, RTP_RFC5285_TWO_BYTE_SIG + 0xF, "RFC 5285 Two-Byte Header Extensions" },
    { RTP_RFC5285_ONE_BYTE_SIG, RTP_RFC5285_ONE_BYTE_SIG, "RFC 5285 One-Byte Header Extensions" },
    { 0, 0, NULL },
};

/*
 * Fields in the second octet of the RTP header.
 */

/* Marker is the first bit of the second octet */
#define RTP_MARKER(octet)   ((octet) & 0x80)

/* Payload type is the last 7 bits */
#define RTP_PAYLOAD_TYPE(octet) ((octet) & 0x7F)
/* https://www.iana.org/assignments/rtp-parameters/ */

#define FIRST_RTCP_CONFLICT_PAYLOAD_TYPE 64
#define LAST_RTCP_CONFLICT_PAYLOAD_TYPE  95

static const value_string rtp_payload_type_vals[] =
{
/*  0 */    { PT_PCMU,          "ITU-T G.711 PCMU" },
/*  1 */    { PT_1016,          "USA Federal Standard FS-1016" },
/*  2 */    { PT_G721,          "ITU-T G.721" },
/*  3 */    { PT_GSM,           "GSM 06.10" },
/*  4 */    { PT_G723,          "ITU-T G.723" },
/*  5 */    { PT_DVI4_8000,     "DVI4 8000 samples/s" },
/*  6 */    { PT_DVI4_16000,    "DVI4 16000 samples/s" },
/*  7 */    { PT_LPC,           "Experimental linear predictive encoding from Xerox PARC" },
/*  8 */    { PT_PCMA,          "ITU-T G.711 PCMA" },
/*  9 */    { PT_G722,          "ITU-T G.722" },
/* 10 */    { PT_L16_STEREO,    "16-bit uncompressed audio, stereo" },
/* 11 */    { PT_L16_MONO,      "16-bit uncompressed audio, monaural" },
/* 12 */    { PT_QCELP,         "Qualcomm Code Excited Linear Predictive coding" },
/* 13 */    { PT_CN,            "Comfort noise" },
/* 14 */    { PT_MPA,           "MPEG-I/II Audio"},
/* 15 */    { PT_G728,          "ITU-T G.728" },
/* 16 */    { PT_DVI4_11025,    "DVI4 11025 samples/s" },
/* 17 */    { PT_DVI4_22050,    "DVI4 22050 samples/s" },
/* 18 */    { PT_G729,          "ITU-T G.729" },
/* 19 */    { PT_CN_OLD,        "Comfort noise (old)" },
/* 20 */    { 20,               "Unassigned" },
/* 21 */    { 21,               "Unassigned" },
/* 22 */    { 22,               "Unassigned" },
/* 23 */    { 23,               "Unassigned" },
/* 24 */    { 24,               "Unassigned" },
/* 25 */    { PT_CELB,          "Sun CellB video encoding" },
/* 26 */    { PT_JPEG,          "JPEG-compressed video" },
/* 27 */    { 27,               "Unassigned" },
/* 28 */    { PT_NV,            "'nv' program" },
/* 29 */    { 29,               "Unassigned" },
/* 30 */    { 30,               "Unassigned" },
/* 31 */    { PT_H261,          "ITU-T H.261" },
/* 32 */    { PT_MPV,           "MPEG-I/II Video"},
/* 33 */    { PT_MP2T,          "MPEG-II transport streams"},
/* 34 */    { PT_H263,          "ITU-T H.263" },
/* 35-71     Unassigned  */
/* 35 */    { 35,               "Unassigned" },
/* 36 */    { 36,               "Unassigned" },
/* 37 */    { 37,               "Unassigned" },
/* 38 */    { 38,               "Unassigned" },
/* 39 */    { 39,               "Unassigned" },
/* 40 */    { 40,               "Unassigned" },
/* 41 */    { 41,               "Unassigned" },
/* 42 */    { 42,               "Unassigned" },
/* 43 */    { 43,               "Unassigned" },
/* 44 */    { 44,               "Unassigned" },
/* 45 */    { 45,               "Unassigned" },
/* 46 */    { 46,               "Unassigned" },
/* 47 */    { 47,               "Unassigned" },
/* 48 */    { 48,               "Unassigned" },
/* 49 */    { 49,               "Unassigned" },
/* 50 */    { 50,               "Unassigned" },
/* 51 */    { 51,               "Unassigned" },
/* 52 */    { 52,               "Unassigned" },
/* 53 */    { 53,               "Unassigned" },
/* 54 */    { 54,               "Unassigned" },
/* 55 */    { 55,               "Unassigned" },
/* 56 */    { 56,               "Unassigned" },
/* 57 */    { 57,               "Unassigned" },
/* 58 */    { 58,               "Unassigned" },
/* 59 */    { 59,               "Unassigned" },
/* 60 */    { 60,               "Unassigned" },
/* 61 */    { 61,               "Unassigned" },
/* 62 */    { 62,               "Unassigned" },
/* 63 */    { 63,               "Unassigned" },
/* 64 */    { 64,               "Unassigned" },
/* 65 */    { 65,               "Unassigned" },
/* 66 */    { 66,               "Unassigned" },
/* 67 */    { 67,               "Unassigned" },
/* 68 */    { 68,               "Unassigned" },
/* 69 */    { 69,               "Unassigned" },
/* 70 */    { 70,               "Unassigned" },
/* 71 */    { 71,               "Unassigned" },
/* 72-76     Reserved for RTCP conflict avoidance                                  [RFC3551] */
/* 72 */    { 72,               "Reserved for RTCP conflict avoidance" },
/* 73 */    { 73,               "Reserved for RTCP conflict avoidance" },
/* 74 */    { 74,               "Reserved for RTCP conflict avoidance" },
/* 75 */    { 75,               "Reserved for RTCP conflict avoidance" },
/* 76 */    { 76,               "Reserved for RTCP conflict avoidance" },
/* 77-95     Unassigned, MAY be used if > 32 PT are used */
/* 77 */    { 77,               "Unassigned" },
/* 78 */    { 78,               "Unassigned" },
/* 79 */    { 79,               "Unassigned" },
/* 80 */    { 80,               "Unassigned" },
/* 81 */    { 81,               "Unassigned" },
/* 82 */    { 82,               "Unassigned" },
/* 83 */    { 83,               "Unassigned" },
/* 84 */    { 84,               "Unassigned" },
/* 85 */    { 85,               "Unassigned" },
/* 86 */    { 86,               "Unassigned" },
/* 87 */    { 87,               "Unassigned" },
/* 88 */    { 88,               "Unassigned" },
/* 89 */    { 89,               "Unassigned" },
/* 90 */    { 90,               "Unassigned" },
/* 91 */    { 91,               "Unassigned" },
/* 92 */    { 92,               "Unassigned" },
/* 93 */    { 93,               "Unassigned" },
/* 94 */    { 94,               "Unassigned" },
/* 95 */    { 95,               "Unassigned" },
        /* Added to support additional RTP payload types
         * See epan/rtp_pt.h */
        { PT_UNDF_96,   "DynamicRTP-Type-96" },
        { PT_UNDF_97,   "DynamicRTP-Type-97" },
        { PT_UNDF_98,   "DynamicRTP-Type-98" },
        { PT_UNDF_99,   "DynamicRTP-Type-99" },
        { PT_UNDF_100,  "DynamicRTP-Type-100" },
        { PT_UNDF_101,  "DynamicRTP-Type-101" },
        { PT_UNDF_102,  "DynamicRTP-Type-102" },
        { PT_UNDF_103,  "DynamicRTP-Type-103" },
        { PT_UNDF_104,  "DynamicRTP-Type-104" },
        { PT_UNDF_105,  "DynamicRTP-Type-105" },
        { PT_UNDF_106,  "DynamicRTP-Type-106" },
        { PT_UNDF_107,  "DynamicRTP-Type-107" },
        { PT_UNDF_108,  "DynamicRTP-Type-108" },
        { PT_UNDF_109,  "DynamicRTP-Type-109" },
        { PT_UNDF_110,  "DynamicRTP-Type-110" },
        { PT_UNDF_111,  "DynamicRTP-Type-111" },
        { PT_UNDF_112,  "DynamicRTP-Type-112" },
        { PT_UNDF_113,  "DynamicRTP-Type-113" },
        { PT_UNDF_114,  "DynamicRTP-Type-114" },
        { PT_UNDF_115,  "DynamicRTP-Type-115" },
        { PT_UNDF_116,  "DynamicRTP-Type-116" },
        { PT_UNDF_117,  "DynamicRTP-Type-117" },
        { PT_UNDF_118,  "DynamicRTP-Type-118" },
        { PT_UNDF_119,  "DynamicRTP-Type-119" },
        { PT_UNDF_120,  "DynamicRTP-Type-120" },
        { PT_UNDF_121,  "DynamicRTP-Type-121" },
        { PT_UNDF_122,  "DynamicRTP-Type-122" },
        { PT_UNDF_123,  "DynamicRTP-Type-123" },
        { PT_UNDF_124,  "DynamicRTP-Type-124" },
        { PT_UNDF_125,  "DynamicRTP-Type-125" },
        { PT_UNDF_126,  "DynamicRTP-Type-126" },
        { PT_UNDF_127,  "DynamicRTP-Type-127" },

        { 0,        NULL },
};

value_string_ext rtp_payload_type_vals_ext = VALUE_STRING_EXT_INIT(rtp_payload_type_vals);

static const value_string rtp_payload_type_short_vals[] =
{
    { PT_PCMU,      "g711U" },
    { PT_1016,      "fs-1016" },
    { PT_G721,      "g721" },
    { PT_GSM,       "GSM" },
    { PT_G723,      "g723" },
    { PT_DVI4_8000, "DVI4 8k" },
    { PT_DVI4_16000, "DVI4 16k" },
    { PT_LPC,       "Exp. from Xerox PARC" },
    { PT_PCMA,      "g711A" },
    { PT_G722,      "g722" },
    { PT_L16_STEREO, "16-bit audio, stereo" },
    { PT_L16_MONO,  "16-bit audio, monaural" },
    { PT_QCELP,     "Qualcomm" },
    { PT_CN,        "CN" },
    { PT_MPA,       "MPEG-I/II Audio"},
    { PT_G728,      "g728" },
    { PT_DVI4_11025, "DVI4 11k" },
    { PT_DVI4_22050, "DVI4 22k" },
    { PT_G729,      "g729" },
    { PT_CN_OLD,    "CN(old)" },
    { 20,               "Unassigned" },
    { 21,               "Unassigned" },
    { 22,               "Unassigned" },
    { 23,               "Unassigned" },
    { 24,               "Unassigned" },
    { PT_CELB,      "CellB" },
    { PT_JPEG,      "JPEG" },
    { 27,               "Unassigned" },
    { PT_NV,        "NV" },
    { 29,               "Unassigned" },
    { 30,               "Unassigned" },
    { PT_H261,      "h261" },
    { PT_MPV,       "MPEG-I/II Video"},
    { PT_MP2T,      "MPEG-II streams"},
    { PT_H263,      "h263" },
/* 35-71     Unassigned  */
    { 35,               "Unassigned" },
    { 36,               "Unassigned" },
    { 37,               "Unassigned" },
    { 38,               "Unassigned" },
    { 39,               "Unassigned" },
    { 40,               "Unassigned" },
    { 41,               "Unassigned" },
    { 42,               "Unassigned" },
    { 43,               "Unassigned" },
    { 44,               "Unassigned" },
    { 45,               "Unassigned" },
    { 46,               "Unassigned" },
    { 47,               "Unassigned" },
    { 48,               "Unassigned" },
    { 49,               "Unassigned" },
    { 50,               "Unassigned" },
    { 51,               "Unassigned" },
    { 52,               "Unassigned" },
    { 53,               "Unassigned" },
    { 54,               "Unassigned" },
    { 55,               "Unassigned" },
    { 56,               "Unassigned" },
    { 57,               "Unassigned" },
    { 58,               "Unassigned" },
    { 59,               "Unassigned" },
    { 60,               "Unassigned" },
    { 61,               "Unassigned" },
    { 62,               "Unassigned" },
    { 63,               "Unassigned" },
    { 64,               "Unassigned" },
    { 65,               "Unassigned" },
    { 66,               "Unassigned" },
    { 67,               "Unassigned" },
    { 68,               "Unassigned" },
    { 69,               "Unassigned" },
    { 70,               "Unassigned" },
    { 71,               "Unassigned" },
/* 72-76     Reserved for RTCP conflict avoidance  - [RFC3551] */
    { 72,               "Reserved for RTCP conflict avoidance" },
    { 73,               "Reserved for RTCP conflict avoidance" },
    { 74,               "Reserved for RTCP conflict avoidance" },
    { 75,               "Reserved for RTCP conflict avoidance" },
    { 76,               "Reserved for RTCP conflict avoidance" },
/* 77-95     Unassigned, MAY be used if > 32 PT are used */
    { 77,               "Unassigned" },
    { 78,               "Unassigned" },
    { 79,               "Unassigned" },
    { 80,               "Unassigned" },
    { 81,               "Unassigned" },
    { 82,               "Unassigned" },
    { 83,               "Unassigned" },
    { 84,               "Unassigned" },
    { 85,               "Unassigned" },
    { 86,               "Unassigned" },
    { 87,               "Unassigned" },
    { 88,               "Unassigned" },
    { 89,               "Unassigned" },
    { 90,               "Unassigned" },
    { 91,               "Unassigned" },
    { 92,               "Unassigned" },
    { 93,               "Unassigned" },
    { 94,               "Unassigned" },
    { 95,               "Unassigned" },
    /* Short RTP types */
    { PT_UNDF_96,   "RTPType-96" },
    { PT_UNDF_97,   "RTPType-97" },
    { PT_UNDF_98,   "RTPType-98" },
    { PT_UNDF_99,   "RTPType-99" },
    { PT_UNDF_100,  "RTPType-100" },
    { PT_UNDF_101,  "RTPType-101" },
    { PT_UNDF_102,  "RTPType-102" },
    { PT_UNDF_103,  "RTPType-103" },
    { PT_UNDF_104,  "RTPType-104" },
    { PT_UNDF_105,  "RTPType-105" },
    { PT_UNDF_106,  "RTPType-106" },
    { PT_UNDF_107,  "RTPType-107" },
    { PT_UNDF_108,  "RTPType-108" },
    { PT_UNDF_109,  "RTPType-109" },
    { PT_UNDF_110,  "RTPType-110" },
    { PT_UNDF_111,  "RTPType-111" },
    { PT_UNDF_112,  "RTPType-112" },
    { PT_UNDF_113,  "RTPType-113" },
    { PT_UNDF_114,  "RTPType-114" },
    { PT_UNDF_115,  "RTPType-115" },
    { PT_UNDF_116,  "RTPType-116" },
    { PT_UNDF_117,  "RTPType-117" },
    { PT_UNDF_118,  "RTPType-118" },
    { PT_UNDF_119,  "RTPType-119" },
    { PT_UNDF_120,  "RTPType-120" },
    { PT_UNDF_121,  "RTPType-121" },
    { PT_UNDF_122,  "RTPType-122" },
    { PT_UNDF_123,  "RTPType-123" },
    { PT_UNDF_124,  "RTPType-124" },
    { PT_UNDF_125,  "RTPType-125" },
    { PT_UNDF_126,  "RTPType-126" },
    { PT_UNDF_127,  "RTPType-127" },

    { 0,            NULL },
};
value_string_ext rtp_payload_type_short_vals_ext = VALUE_STRING_EXT_INIT(rtp_payload_type_short_vals);

#if 0
static const value_string srtp_encryption_alg_vals[] =
{
    { SRTP_ENC_ALG_NULL,    "Null Encryption" },
    { SRTP_ENC_ALG_AES_CM,  "AES-128 Counter Mode" },
    { SRTP_ENC_ALG_AES_F8,  "AES-128 F8 Mode" },
    { 0, NULL },
};

static const value_string srtp_auth_alg_vals[] =
{
    { SRTP_AUTH_ALG_NONE,       "No Authentication" },
    { SRTP_AUTH_ALG_HMAC_SHA1,  "HMAC-SHA1" },
    { 0, NULL },
};
#endif

static void rtp_prompt(packet_info *pinfo _U_, char* result)
{
    unsigned payload_type = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_rtp, RTP_DECODE_AS_PROTO_DATA));

    /* Dynamic payload range, don't expose value as it may change within conversation */
    if (payload_type > 95)
    {
        snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "RTP payload type as");
    }
    else
    {
        snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "RTP payload type %d as", payload_type);
    }
}

static void *rtp_value(packet_info *pinfo)
{
    unsigned payload_type = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_rtp, RTP_DECODE_AS_PROTO_DATA));

    return GUINT_TO_POINTER(payload_type);
}

#ifdef DEBUG_CONVERSATION
/* Called for each entry in the rtp_dyn_payload hash table. */
static void
rtp_dyn_payload_table_foreach_func(void *key, void *value, void *user_data _U_) {
    unsigned pt = GPOINTER_TO_UINT(key);
    encoding_name_and_rate_t *encoding = (encoding_name_and_rate_t*) value;

    DPRINT2(("pt=%d", pt));
    if (encoding) {
        DPRINT2(("encoding_name=%s",
                encoding->encoding_name ? encoding->encoding_name : "NULL"));
        DPRINT2(("sample_rate=%d", encoding->sample_rate));
        DPRINT2(("channels=%u", encoding->channels));
    } else {
        DPRINT2(("encoding=NULL"));
    }
}

void
rtp_dump_dyn_payload(rtp_dyn_payload_t *rtp_dyn_payload) {
    DPRINT2(("rtp_dyn_payload hash table contents:"));
    DINDENT();
        if (!rtp_dyn_payload) {
            DPRINT2(("null pointer to rtp_dyn_payload"));
            DENDENT();
            return;
        }
        DPRINT2(("ref_count=%zu", rtp_dyn_payload->ref_count));
        if (!rtp_dyn_payload->table) {
            DPRINT2(("null rtp_dyn_payload table"));
            DENDENT();
            return;
        }
        if (g_hash_table_size(rtp_dyn_payload->table) == 0) {
            DPRINT2(("rtp_dyn_payload has no entries"));
        } else {
            g_hash_table_foreach(rtp_dyn_payload->table, rtp_dyn_payload_table_foreach_func, NULL);
        }
    DENDENT();
}
#endif /* DEBUG_CONVERSATION */

/* A single hash table to hold pointers to all the rtp_dyn_payload_t's we create/destroy.
   This is necessary because we need to g_hash_table_destroy() them, either individually or
   all at once at the end of the wmem file scope. Since rtp_dyn_payload_free() removes them
   individually, we need to remove those then; and when the file scope is over, we have a
   single registered callback walk this GHashTable and destroy each member as well as this
   GHashTable.
 */
static GHashTable *rtp_dyn_payloads;

static gboolean
fmtp_free(void *key, void *value, void *user_data)
{
    wmem_allocator_t *scope = (wmem_allocator_t*)user_data;

    wmem_free(scope, key);
    wmem_free(scope, value);

    return true;
}

/* the following is the GDestroyNotify function used when the individual rtp_dyn_payload_t
   GHashTables are destroyed */
static void
rtp_dyn_payload_value_destroy(void *data)
{
    encoding_name_and_rate_t *encoding_name_and_rate_pt = (encoding_name_and_rate_t*) data;
    wmem_free(wmem_file_scope(), encoding_name_and_rate_pt->encoding_name);
    wmem_map_foreach_remove(encoding_name_and_rate_pt->fmtp_map, fmtp_free, wmem_file_scope());
    wmem_free(wmem_file_scope(), encoding_name_and_rate_pt->fmtp_map);
    wmem_free(wmem_file_scope(), encoding_name_and_rate_pt);
}

/* this gets called by wmem_rtp_dyn_payload_destroy_cb */
static gboolean
rtp_dyn_payloads_table_steal_func(void *key _U_, void *value, void *user_data _U_)
{
    rtp_dyn_payload_t *rtp_dyn_payload = (rtp_dyn_payload_t *)value;

#ifdef DEBUG_CONVERSATION
    DPRINT(("about to steal_all and destroy the following:"));
    DINDENT();
    rtp_dump_dyn_payload(rtp_dyn_payload);
    DENDENT();
#endif

    if (rtp_dyn_payload->ref_count == 0) {
        /* this shouldn't happen */
        DPRINT(("rtp_dyn_payload cannot be free'd because it should already have been!\n"));
    }
    else if (rtp_dyn_payload->table) {
        /* each member was created with a wmem file scope, so there's no point in calling the
           destroy functions for the GHashTable entries, so we steal them instead */
        g_hash_table_steal_all(rtp_dyn_payload->table);
        g_hash_table_destroy(rtp_dyn_payload->table);
    }

    return true;
}

/* the following is used as the wmem callback to destroy *all* alive rtp_dyn_payload_t's,
   which are pointed to by the single rtp_dyn_payloads GHashTable above.
 */
static bool
wmem_rtp_dyn_payload_destroy_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_,
        void *user_data _U_)
{
    DPRINT(("destroying %u remaining rtp_dyn_payload_t's", g_hash_table_size(rtp_dyn_payloads)));

    /* each member was created with a wmem file scope, so there's no point in calling the
       destroy functions for the GHashTable entries, so we steal them instead */
    g_hash_table_foreach_steal(rtp_dyn_payloads, rtp_dyn_payloads_table_steal_func, NULL);
    g_hash_table_destroy(rtp_dyn_payloads);
    rtp_dyn_payloads = NULL;

    /* remove this callback? */
    return false;
}

/* the following initializes the single GHashTable - this is invoked as an init_routine,
   but those are called both at init and cleanup times, and the cleanup time is before
   wmem scope is exited, so we ignore this if rtp_dyn_payloads is not NULL.
 */
static void
rtp_dyn_payloads_init(void)
{
    if (rtp_dyn_payloads == NULL) {
        rtp_dyn_payloads = g_hash_table_new(NULL, NULL);
        wmem_register_callback(wmem_file_scope(), wmem_rtp_dyn_payload_destroy_cb, NULL);
    }
}

/* creates a new hashtable and sets ref_count to 1, returning the newly created object */
rtp_dyn_payload_t* rtp_dyn_payload_new(void)
{
    /* create the new entry */
    rtp_dyn_payload_t * rtp_dyn_payload = wmem_new(wmem_file_scope(), rtp_dyn_payload_t);
    rtp_dyn_payload->table = g_hash_table_new_full(NULL, NULL, NULL, rtp_dyn_payload_value_destroy);
    rtp_dyn_payload->ref_count = 1;

    /* now put it in our single rtp_dyn_payloads GHashTable */
    g_hash_table_insert(rtp_dyn_payloads, rtp_dyn_payload, rtp_dyn_payload);

    return rtp_dyn_payload;
}

/* Creates a copy of the given dynamic payload information. */
rtp_dyn_payload_t* rtp_dyn_payload_dup(rtp_dyn_payload_t *rtp_dyn_payload)
{
    rtp_dyn_payload_t *rtp_dyn_payload2 = rtp_dyn_payload_new();
    GHashTableIter iter;
    void *key, *value;

    g_hash_table_iter_init(&iter, rtp_dyn_payload->table);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        const unsigned pt = GPOINTER_TO_UINT(key);
        encoding_name_and_rate_t *encoding_name_and_rate_pt =
            (encoding_name_and_rate_t *)value;

        rtp_dyn_payload_insert_full(rtp_dyn_payload2, pt,
                encoding_name_and_rate_pt->encoding_name,
                encoding_name_and_rate_pt->sample_rate,
                encoding_name_and_rate_pt->channels,
                encoding_name_and_rate_pt->fmtp_map);

    }

    return rtp_dyn_payload2;
}

static rtp_dyn_payload_t*
rtp_dyn_payload_ref(rtp_dyn_payload_t *rtp_dyn_payload)
{
    if (rtp_dyn_payload) {
        rtp_dyn_payload->ref_count++;
    }
    return rtp_dyn_payload;
}

static void
rtp_dyn_payload_add_fmtp_int(void *key, void *value, void *user_data)
{
    wmem_map_t *fmtp_map = (wmem_map_t*)user_data;
    const char *k = (const char*)key;
    const char *v = (const char*)value;

    wmem_map_insert(fmtp_map, wmem_strdup(wmem_file_scope(), k), wmem_strdup(wmem_file_scope(), v));
}

/* Inserts the given payload type key, for the encoding name and sample rate,
   into the hash table. Copy all the format parameters in the map given into
   the format parameter map for the new entry.
   This makes copies of the encoding name and the format parameters, scoped to
   the life of the capture file or sooner if rtp_dyn_payload_free is called.
 */
void
rtp_dyn_payload_insert_full(rtp_dyn_payload_t *rtp_dyn_payload,
                       const unsigned pt,
                       const char* encoding_name,
                       const int sample_rate,
                       const unsigned channels,
                       wmem_map_t *fmtp_map)
{
    if (rtp_dyn_payload && rtp_dyn_payload->table) {
        encoding_name_and_rate_t *encoding_name_and_rate_pt = (encoding_name_and_rate_t*)g_hash_table_lookup(rtp_dyn_payload->table,
                             GUINT_TO_POINTER(pt));
        if (!encoding_name_and_rate_pt) {
            encoding_name_and_rate_pt = wmem_new(wmem_file_scope(), encoding_name_and_rate_t);
            encoding_name_and_rate_pt->fmtp_map = wmem_map_new(wmem_file_scope(), wmem_str_hash, g_str_equal);
            g_hash_table_insert(rtp_dyn_payload->table, GUINT_TO_POINTER(pt), encoding_name_and_rate_pt);
        }
        encoding_name_and_rate_pt->encoding_name = wmem_strdup(wmem_file_scope(), encoding_name);
        encoding_name_and_rate_pt->sample_rate = sample_rate;
        encoding_name_and_rate_pt->channels = channels;
        if (fmtp_map) {
            wmem_map_foreach(fmtp_map, rtp_dyn_payload_add_fmtp_int, encoding_name_and_rate_pt->fmtp_map);
        }
    }
}

/* Inserts the given payload type key, for the encoding name and sample rate,
   into the hash table.
   This makes copies of the encoding name, scoped to the life of the capture
   file or sooner if rtp_dyn_payload_free is called. */
void
rtp_dyn_payload_insert(rtp_dyn_payload_t *rtp_dyn_payload,
                       const unsigned pt,
                       const char* encoding_name,
                       const int sample_rate,
                       const unsigned channels)
{
    rtp_dyn_payload_insert_full(rtp_dyn_payload, pt, encoding_name, sample_rate, channels, NULL);
}

/* Adds the given format parameter to the fmtp_map for the given payload type
   in the RTP dynamic payload hashtable, if that payload type has been
   inserted with rtp_dyn_payload_insert. The format parameter name and value
   are copied, with scope the lifetime of the capture file.
 */
void
rtp_dyn_payload_add_fmtp(rtp_dyn_payload_t *rtp_dyn_payload,
                         const unsigned pt,
                         const char *key, const char *value)
{
    if (rtp_dyn_payload && rtp_dyn_payload->table) {
        encoding_name_and_rate_t *encoding_name_and_rate_pt = (encoding_name_and_rate_t*)g_hash_table_lookup(rtp_dyn_payload->table,
                             GUINT_TO_POINTER(pt));

        if (!encoding_name_and_rate_pt) {
            rtp_dyn_payload_insert(rtp_dyn_payload, pt, "Unknown", 0, 1);
            encoding_name_and_rate_pt = (encoding_name_and_rate_t*)g_hash_table_lookup(rtp_dyn_payload->table, GUINT_TO_POINTER(pt));
        }

        rtp_dyn_payload_add_fmtp_int((void*)key, (void*)value, encoding_name_and_rate_pt->fmtp_map);
    }
}

/* Replaces the given payload type key in the hash table, with the encoding name and sample rate.
   This makes copies of the encoding name, scoped to the life of the capture file or sooner if
   rtp_dyn_payload_free is called. */
/* Not used anymore
void
rtp_dyn_payload_replace(rtp_dyn_payload_t *rtp_dyn_payload,
                        const unsigned pt,
                        const char* encoding_name,
                        const int sample_rate)
{
    if (rtp_dyn_payload && rtp_dyn_payload->table) {
        encoding_name_and_rate_t *encoding_name_and_rate_pt =
                    wmem_new(wmem_file_scope(), encoding_name_and_rate_t);
        encoding_name_and_rate_pt->encoding_name = wmem_strdup(wmem_file_scope(), encoding_name);
        encoding_name_and_rate_pt->sample_rate = sample_rate;
        g_hash_table_replace(rtp_dyn_payload->table, GUINT_TO_POINTER(pt), encoding_name_and_rate_pt);
    }
}
*/

/* removes the given payload type */
/* Not used anymore
bool
rtp_dyn_payload_remove(rtp_dyn_payload_t *rtp_dyn_payload, const unsigned pt)
{
    return (rtp_dyn_payload && rtp_dyn_payload->table &&
            g_hash_table_remove(rtp_dyn_payload->table, GUINT_TO_POINTER(pt)));
}
*/

/* retrieves the encoding name for the given payload type */
const char*
rtp_dyn_payload_get_name(rtp_dyn_payload_t *rtp_dyn_payload, const unsigned pt)
{
    encoding_name_and_rate_t *encoding_name_and_rate_pt;

    if (!rtp_dyn_payload || !rtp_dyn_payload->table) return NULL;

    encoding_name_and_rate_pt = (encoding_name_and_rate_t*)g_hash_table_lookup(rtp_dyn_payload->table,
                                                                               GUINT_TO_POINTER(pt));

    return (encoding_name_and_rate_pt ? encoding_name_and_rate_pt->encoding_name : NULL);
}

/*
   Retrieves the encoding name, sample rate, and format parameters map for the
   given payload type. The encoding string pointed to is only valid until
   the entry is replaced, removed, or the hash table is destroyed, so duplicate
   it if you need it long. Each of the three output parameters are optional and
   can be NULL.
 */
bool
rtp_dyn_payload_get_full(rtp_dyn_payload_t *rtp_dyn_payload, const unsigned pt,
                         const char **encoding_name, int *sample_rate,
                         unsigned *channels, wmem_map_t **fmtp_map)
{
    encoding_name_and_rate_t *encoding_name_and_rate_pt;
    if (encoding_name) {
        *encoding_name = NULL;
    }
    if (sample_rate) {
        *sample_rate = 0;
    }
    if (channels) {
        *channels = 0;
    }
    if (fmtp_map) {
        *fmtp_map = NULL;
    }

    if (!rtp_dyn_payload || !rtp_dyn_payload->table) return false;

    encoding_name_and_rate_pt = (encoding_name_and_rate_t*)g_hash_table_lookup(rtp_dyn_payload->table,
                                                                               GUINT_TO_POINTER(pt));

    if (encoding_name_and_rate_pt) {
        if (encoding_name) {
            *encoding_name = encoding_name_and_rate_pt->encoding_name;
        }
        if (sample_rate) {
            *sample_rate = encoding_name_and_rate_pt->sample_rate;
        }
        if (channels) {
            *channels = encoding_name_and_rate_pt->channels;
        }
        if (fmtp_map) {
            *fmtp_map = encoding_name_and_rate_pt->fmtp_map;
        }
    }

    return (encoding_name_and_rate_pt != NULL);
}

/* Free's and destroys the dyn_payload hash table; internally this decrements the ref_count
   and only free's it if the ref_count == 0. */
void
rtp_dyn_payload_free(rtp_dyn_payload_t *rtp_dyn_payload)
{
    if (!rtp_dyn_payload) return;

    if (rtp_dyn_payload->ref_count > 0)
        --(rtp_dyn_payload->ref_count);

    if (rtp_dyn_payload->ref_count == 0) {

#ifdef DEBUG_CONVERSATION
        DPRINT(("free'ing the following rtp_dyn_payload:"));
        DINDENT();
        rtp_dump_dyn_payload(rtp_dyn_payload);
        DENDENT();
#endif

        /* remove it from the single rtp_dyn_payloads GHashTable */
        if (!g_hash_table_remove(rtp_dyn_payloads, rtp_dyn_payload)) {
            DPRINT(("rtp_dyn_payload not found in rtp_dyn_payloads table to remove!"));
        }

        /* destroy the table GHashTable in it - this automatically deletes the
           members too, because we used destroy function callbacks */
        if (rtp_dyn_payload->table)
            g_hash_table_destroy(rtp_dyn_payload->table);

        /* free the object itself */
        wmem_free(wmem_file_scope(), rtp_dyn_payload);
    }
}

void
bluetooth_add_address(packet_info *pinfo, address *addr, uint32_t stream_number,
         const char *setup_method, uint32_t setup_frame_number,
         uint32_t media_types, void *data)
{
    address null_addr;
    conversation_t* p_conv;
    struct _rtp_conversation_info *p_conv_data = NULL;
    /*
     * If this isn't the first time this packet has been processed,
     * we've already done this work, so we don't need to do it
     * again.
     */
    if ((pinfo->fd->visited) || (rtp_handle == NULL))
    {
        return;
    }

    clear_address(&null_addr);

    /*
     * Check if the ip address and port combination is not
     * already registered as a conversation.
     */
    p_conv = find_conversation(setup_frame_number, addr, &null_addr, CONVERSATION_BLUETOOTH, stream_number, stream_number,
                   NO_ADDR_B | NO_PORT_B);

    /*
     * If not, create a new conversation.
     */
    if (!p_conv || p_conv->setup_frame != setup_frame_number) {
        p_conv = conversation_new(setup_frame_number, addr, &null_addr, CONVERSATION_BLUETOOTH, stream_number, stream_number,
                   NO_ADDR2 | NO_PORT2);
    }

    /* Set dissector */
    conversation_set_dissector(p_conv, rtp_handle);

    /*
     * Check if the conversation has data associated with it.
     */
    p_conv_data = (struct _rtp_conversation_info *)conversation_get_proto_data(p_conv, proto_rtp);

    /*
     * If not, add a new data item.
     */
    if (! p_conv_data) {
        /* Create conversation data */
        p_conv_data = wmem_new0(wmem_file_scope(), struct _rtp_conversation_info);

        p_conv_data->ssrc_number_space = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
        p_conv_data->rtp_conv_info = wmem_new(wmem_file_scope(), rtp_private_conv_info);
        p_conv_data->rtp_conv_info->multisegment_pdus = wmem_tree_new(wmem_file_scope());
        conversation_add_proto_data(p_conv, proto_rtp, p_conv_data);

        if (media_types == RTP_MEDIA_AUDIO) {
            p_conv_data->bta2dp_info = (bta2dp_codec_info_t *) wmem_memdup(wmem_file_scope(), data, sizeof(bta2dp_codec_info_t));
        } else if (media_types == RTP_MEDIA_VIDEO) {
            p_conv_data->btvdp_info = (btvdp_codec_info_t *) wmem_memdup(wmem_file_scope(), data, sizeof(btvdp_codec_info_t));
        }
    }

    /*
     * Update the conversation data.
     */
    /* Free the hash if already exists */
    rtp_dyn_payload_free(p_conv_data->rtp_dyn_payload);

    (void) g_strlcpy(p_conv_data->method, setup_method, MAX_RTP_SETUP_METHOD_SIZE+1);
    p_conv_data->frame_number = setup_frame_number;
    p_conv_data->media_types = media_types;
    p_conv_data->rtp_dyn_payload = NULL;
    p_conv_data->srtp_info = NULL;
}
static void
rtp_add_setup_info_if_no_duplicate(sdp_setup_info_t *setup_info, wmem_array_t *sdp_conv_info_list)
{
    sdp_setup_info_t *stored_setup_info;
    unsigned i;

    for (i = 0; i < wmem_array_get_count(sdp_conv_info_list); i++) {
        stored_setup_info = (sdp_setup_info_t *)wmem_array_index(sdp_conv_info_list, i);

        /* Check if we have the call id already */
        if ((stored_setup_info->hf_type == SDP_TRACE_ID_HF_TYPE_STR) && (setup_info->hf_type == SDP_TRACE_ID_HF_TYPE_STR)) {
            if (strcmp(stored_setup_info->trace_id.str, setup_info->trace_id.str) == 0) {
                return; /* Do not store the call id */
            }
        } else if ((stored_setup_info->hf_type == SDP_TRACE_ID_HF_TYPE_GUINT32) && (setup_info->hf_type == SDP_TRACE_ID_HF_TYPE_GUINT32)) {
            if (stored_setup_info->trace_id.num == setup_info->trace_id.num) {
                return; /* Do not store the call id */
            }
        }
    }

    wmem_array_append(sdp_conv_info_list, setup_info, 1);

}
/* Set up an SRTP conversation */
void
srtp_add_address(packet_info *pinfo, const port_type ptype, address *addr, int port, int other_port,
         const char *setup_method, uint32_t setup_frame_number,
         uint32_t media_types _U_, rtp_dyn_payload_t *rtp_dyn_payload,
         struct srtp_info *srtp_info, sdp_setup_info_t *setup_info)
{
    address null_addr;
    conversation_t* p_conv;
    struct _rtp_conversation_info *p_conv_data;
    wmem_array_t *rtp_conv_info_list = NULL;
    wmem_map_t *ssrc_number_space = NULL;

    /*
     * If this isn't the first time this packet has been processed,
     * we've already done this work, so we don't need to do it
     * again.
     */
    if ((pinfo->fd->visited) || (rtp_handle == NULL) || (rtp_rfc4571_handle == NULL))
    {
        return;
    }

    DPRINT(("#%u: %srtp_add_address(%d, %s, %u, %u, %s, %u)",
            pinfo->num, (srtp_info)?"s":"", ptype, address_to_str(pinfo->pool, addr), port,
            other_port, setup_method, setup_frame_number));
    DINDENT();

    clear_address(&null_addr);

    /*
     * Check if the ip address and port combination is not
     * already registered as a conversation.
     */
    p_conv = find_conversation(setup_frame_number, addr, &null_addr, conversation_pt_to_conversation_type(ptype), port, other_port,
                   NO_ADDR_B | (!other_port ? NO_PORT_B : 0));

    if (p_conv) {
        /*
         * Check if the conversation has data associated with it.
         * Sometimes there are multiple setup messages for the same
         * conversation, and it's worth copying over some of our
         * internal data to the new conversation. The extended sequence
         * number and timestamp cycle information is per-SSRC, and it
         * doesn't hurt (and can definitely help) to ensure that the
         * new conversation uses the same extended cycles as the old one.
         * XXX: It's not actually clear that we really need to create
         * extra conversations for each setup frame, because we save the
         * relevant information to per-packet data for the subsequent passes.
         */
        p_conv_data = (struct _rtp_conversation_info *)conversation_get_proto_data(p_conv, proto_rtp);
        if (p_conv_data) {
            rtp_conv_info_list = p_conv_data->rtp_sdp_setup_info_list;
            ssrc_number_space = p_conv_data->ssrc_number_space;
        }
    }

    DENDENT();
    DPRINT(("did %sfind conversation", p_conv?"":"NOT "));

    /*
     * If not, create a new conversation.
     */
    if (!p_conv || p_conv->setup_frame != setup_frame_number) {
        /* XXX - If setup_frame_number < pinfo->num, creating this conversation
         * can mean that the dissection is different on later passes.
         */
        p_conv = conversation_new(setup_frame_number, addr, &null_addr, conversation_pt_to_conversation_type(ptype),
                                  (uint32_t)port, (uint32_t)other_port,
                      NO_ADDR2 | (!other_port ? NO_PORT2 : 0));
    }

    /* Set dissector */
    if (ptype == PT_UDP) {
        /* For RFC 5761 multiplexing, go ahead and create/update [S]RTCP
         * info for the conversation, since this dissector will pass RTCP PTs
         * to the RTCP dissector anyway.
         * XXX: We only do this on UDP, as RFC 4571 specifies RTP and RTCP on
         * different ports, but the RTCP dissector (like SDP) doesn't support
         * RFC 4571 currently anyway.
         */
        srtcp_add_address(pinfo, addr, port, other_port, setup_method, setup_frame_number, srtp_info);
        /* Set the dissector afterwards, since RTCP will set the conversation
         * to its dissector, but packets should go to RTP first.
         */
        conversation_set_dissector(p_conv, rtp_handle);
    } else if (ptype == PT_TCP) {
        conversation_set_dissector(p_conv, rtp_rfc4571_handle);
    } else {
        DISSECTOR_ASSERT(false);
    }

    /*
     * Check if the conversation has data associated with it.
     */
    p_conv_data = (struct _rtp_conversation_info *)conversation_get_proto_data(p_conv, proto_rtp);

    /*
     * If not, add a new data item.
     */
    if (! p_conv_data) {
        DPRINT(("creating new conversation data"));

        /* Create conversation data */
        p_conv_data = wmem_new0(wmem_file_scope(), struct _rtp_conversation_info);

        p_conv_data->ssrc_number_space = ssrc_number_space ? ssrc_number_space : wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
        p_conv_data->rtp_conv_info = wmem_new(wmem_file_scope(), rtp_private_conv_info);
        p_conv_data->rtp_conv_info->multisegment_pdus = wmem_tree_new(wmem_file_scope());
        DINDENT();
        conversation_add_proto_data(p_conv, proto_rtp, p_conv_data);
        DENDENT();
    }
#ifdef DEBUG_CONVERSATION
    else {
        DPRINT(("conversation already exists"));
    }
#endif

    /*
     * Update the conversation data.
     */
    /* Free the hash if a different one already exists */
    if (p_conv_data->rtp_dyn_payload != rtp_dyn_payload) {
        rtp_dyn_payload_free(p_conv_data->rtp_dyn_payload);
        p_conv_data->rtp_dyn_payload = rtp_dyn_payload_ref(rtp_dyn_payload);
    } else {
        DPRINT(("passed-in rtp_dyn_payload is the same as in the conversation"));
    }

    (void) g_strlcpy(p_conv_data->method, setup_method, MAX_RTP_SETUP_METHOD_SIZE+1);
    p_conv_data->frame_number = setup_frame_number;
    p_conv_data->media_types = media_types;
    p_conv_data->srtp_info = srtp_info;
    p_conv_data->bta2dp_info = NULL;
    p_conv_data->btvdp_info = NULL;

    /* If we had a sdp setup info list put it back in the potentially new conversation*/
    p_conv_data->rtp_sdp_setup_info_list = rtp_conv_info_list;
    if (setup_info) {
        /* If we have new setup info add it to the list*/
        if (p_conv_data->rtp_sdp_setup_info_list) {
            /* Add info to the SDP conversation */
            rtp_add_setup_info_if_no_duplicate(setup_info, p_conv_data->rtp_sdp_setup_info_list);
        } else {
            p_conv_data->rtp_sdp_setup_info_list = wmem_array_new(wmem_file_scope(), sizeof(sdp_setup_info_t));
            wmem_array_append(p_conv_data->rtp_sdp_setup_info_list, setup_info, 1);
        }
    }
    if (p_conv_data->rtp_sdp_setup_info_list) {
        /* Convey the collected information to SDP */
        /* This is pinfo->pool because this function might not have been called
         * by SDP, in which case we don't need to save it, and SDP might have
         * a file scoped transport info to store it in (using the Offer/Answer
         * model, e.g. with SIP.)
         */
        p_add_proto_data(pinfo->pool, pinfo, proto_sdp, 0, p_conv_data->rtp_sdp_setup_info_list);
    }

}

/* Set up an RTP conversation */
void
rtp_add_address(packet_info *pinfo, const port_type ptype, address *addr, int port, int other_port,
        const char *setup_method, uint32_t setup_frame_number,
        uint32_t media_types, rtp_dyn_payload_t *rtp_dyn_payload)
{
    srtp_add_address(pinfo, ptype, addr, port, other_port, setup_method, setup_frame_number, media_types, rtp_dyn_payload, NULL, NULL);
}

static bool
dissect_rtp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    uint8_t      octet1, octet2;
    unsigned int version, payload_type;
    unsigned int offset = 0;
    int          padding_count;

    if (tvb_captured_length_remaining(tvb, offset) < 2) {
        return false;
    }

    /* Get the fields in the first octet */
    octet1 = tvb_get_uint8( tvb, offset );
    version = RTP_VERSION( octet1 );

    /* XXX: Why are we calling these dissectors from the *heuristic*
     * RTP dissector? These almost all have their own heuristic dissector,
     * enabled by default (unlike RTP, which has a much less accurate
     * heuristic.) We should just reject and let the protocols' own heuristic
     * dissectors handle this.
     */
    if (version == 0) {
        if (!(tvb_memeql(tvb, 4, (const uint8_t*)"ZRTP", 4)))
        {
            call_dissector_only(zrtp_handle, tvb, pinfo, tree, NULL);
            return true;
        } else {
            switch (global_rtp_version0_type) {

            /*
             * The two STUN dissectors return 0 if the packet doesn't appear
             * to be a STUN packet and the number of bytes dissected if
             * it does.  Just call that and test whether the return value
             * is != 0 or not.
             */
            case RTP0_STUN:
                return call_dissector_only(stun_handle, tvb, pinfo, tree, NULL) != 0;
            case RTP0_CLASSICSTUN:
                return call_dissector_only(classicstun_handle, tvb, pinfo, tree, NULL) != 0;

            case RTP0_T38:
                /* XXX: Should really be calling a heuristic dissector for T38 ??? */
                call_dissector_only(t38_handle, tvb, pinfo, tree, NULL);
                return true;

            case RTP0_SPRT:
                /* XXX: Should really be calling a heuristic dissector for SPRT ??? */
                call_dissector_only(sprt_handle, tvb, pinfo, tree, NULL);
                return true;

            case RTP0_INVALID:
            case RTP0_RFC7983:
            default:
                return false; /* Unknown or unsupported version */
            }
        }
    } else if (version != 2) {
        /* Unknown or unsupported version */
        return false;
    }

    octet2 = tvb_get_uint8( tvb, offset + 1 );
    payload_type = RTP_PAYLOAD_TYPE( octet2 );

    if (payload_type >= 72 && payload_type <= 76) {
        /* XXX: This range is definitely excluded by RFCs 3550, 3551.
         * There's an argument, per RFC 5761, for expanding the
         * excluded range to [FIRST_RTCP_CONFLICT_PAYLOAD_TYPE,
         * LAST_RTCP_CONFLICT_PAYLOAD_TYPE] in the heuristic dissector,
         * leaving those values only when specificed by other means
         * (SDP, Decode As, etc.)
         */
        return false;
    }

    /* Skip fixed header */
    offset += 12;

    offset += 4 * RTP_CSRC_COUNT( octet1 );
    if (RTP_EXTENSION( octet1 )) {
        if (tvb_captured_length_remaining(tvb, offset) < 4) {
            return false;
        }
        offset += 4 + 4*tvb_get_uint16(tvb, offset+2, ENC_BIG_ENDIAN);
    }
    if (tvb_reported_length(tvb) < offset) {
        return false;
    }
    if (RTP_PADDING( octet1 )) {
        if (tvb_captured_length(tvb) == tvb_reported_length(tvb)) {
            /* We can test the padding if the last octet is present. */
            padding_count = tvb_get_uint8(tvb, tvb_reported_length(tvb) - 1);
            if (tvb_reported_length_remaining(tvb, offset) < padding_count ||
                    padding_count == 0) {
                return false;
            }
        }
    }

    /* Create a conversation in case none exists so as to allow reassembly code to work */
    if (!find_conversation(pinfo->num, &pinfo->net_dst, &pinfo->net_src, conversation_pt_to_conversation_type(pinfo->ptype),
                           pinfo->destport, pinfo->srcport, NO_ADDR_B)) {
        conversation_t *p_conv;
        struct _rtp_conversation_info *p_conv_data;
        p_conv = conversation_new(pinfo->num, &pinfo->net_dst, &pinfo->net_src, conversation_pt_to_conversation_type(pinfo->ptype),
                                  pinfo->destport, pinfo->srcport, NO_ADDR2);
        p_conv_data = (struct _rtp_conversation_info *)conversation_get_proto_data(p_conv, proto_rtp);
        if (! p_conv_data) {
            /* Create conversation data */
            p_conv_data = wmem_new0(wmem_file_scope(), struct _rtp_conversation_info);
            p_conv_data->ssrc_number_space = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
            p_conv_data->rtp_conv_info = wmem_new(wmem_file_scope(), rtp_private_conv_info);
            p_conv_data->rtp_conv_info->multisegment_pdus = wmem_tree_new(wmem_file_scope());
            conversation_add_proto_data(p_conv, proto_rtp, p_conv_data);
        }
        (void) g_strlcpy(p_conv_data->method, "HEUR RTP", MAX_RTP_SETUP_METHOD_SIZE+1);
        p_conv_data->frame_number = pinfo->num;
        p_conv_data->media_types = 0;
        p_conv_data->srtp_info = NULL;
        p_conv_data->bta2dp_info = NULL;
        p_conv_data->btvdp_info = NULL;
    }
    dissect_rtp( tvb, pinfo, tree, data );
    return true;
}

/*
 * Process the payload of the RTP packet, hand it to the subdissector
 */
static void
process_rtp_payload(tvbuff_t *newtvb, packet_info *pinfo, proto_tree *tree,
            proto_tree *rtp_tree, unsigned int payload_type,
            struct _rtp_info *rtp_info)
{
    struct _rtp_packet_info *p_packet_data;
    int payload_len;
    struct srtp_info *srtp_info;
    int offset = 0;
    proto_item *rtp_data;

    payload_len = tvb_captured_length_remaining(newtvb, offset);

    /* first check if this is added as an SRTP stream - if so, don't try to dissector the payload data for now */
    p_packet_data = (struct _rtp_packet_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_rtp, RTP_CONVERSATION_PROTO_DATA);
    if (p_packet_data && p_packet_data->srtp_info) {
        srtp_info = p_packet_data->srtp_info;
        payload_len -= srtp_info->mki_len + srtp_info->auth_tag_len;
#if 0
#error Currently the srtp_info structure contains no cipher data, see packet-sdp.c adding dummy_srtp_info structure
        if (p_conv_data->srtp_info->encryption_algorithm == SRTP_ENC_ALG_NULL) {
            if (rtp_tree)
                proto_tree_add_item(rtp_tree, hf_srtp_null_encrypted_payload, newtvb, offset, payload_len, ENC_NA);
        }
        else
#endif
        {
            if (rtp_tree)
                proto_tree_add_item(rtp_tree, hf_srtp_encrypted_payload, newtvb, offset, payload_len, ENC_NA);
        }
        offset += payload_len;

        if (srtp_info->mki_len) {
            proto_tree_add_item(rtp_tree, hf_srtp_mki, newtvb, offset, srtp_info->mki_len, ENC_NA);
            offset += srtp_info->mki_len;
        }

        if (srtp_info->auth_tag_len) {
            proto_tree_add_item(rtp_tree, hf_srtp_auth_tag, newtvb, offset, srtp_info->auth_tag_len, ENC_NA);
            /*offset += srtp_info->auth_tag_len;*/
        }
        return;

    } if (p_packet_data && p_packet_data->bta2dp_info) {
        tvbuff_t  *nexttvb;
        int        suboffset = 0;

        if (p_packet_data->bta2dp_info->content_protection_type == BTAVDTP_CONTENT_PROTECTION_TYPE_SCMS_T) {
            nexttvb = tvb_new_subset_length(newtvb, 0, 1);
             call_dissector(bta2dp_content_protection_header_scms_t, nexttvb, pinfo, tree);
            suboffset = 1;
        }

        nexttvb = tvb_new_subset_remaining(newtvb, suboffset);
        if (p_packet_data->bta2dp_info->codec_dissector)
            call_dissector_with_data(p_packet_data->bta2dp_info->codec_dissector, nexttvb, pinfo, tree, p_packet_data->bta2dp_info);
        else
            call_data_dissector(nexttvb, pinfo, tree);

        return;

    } if (p_packet_data && p_packet_data->btvdp_info) {
        tvbuff_t  *nexttvb;
        int        suboffset = 0;

        if (p_packet_data->btvdp_info->content_protection_type == BTAVDTP_CONTENT_PROTECTION_TYPE_SCMS_T) {
            nexttvb = tvb_new_subset_length(newtvb, 0, 1);
            call_dissector(btvdp_content_protection_header_scms_t, nexttvb, pinfo, tree);
            suboffset = 1;
        }

        nexttvb = tvb_new_subset_remaining(newtvb, suboffset);
        if (p_packet_data->btvdp_info->codec_dissector)
            call_dissector_with_data(p_packet_data->btvdp_info->codec_dissector, nexttvb, pinfo, tree, p_packet_data->btvdp_info);
        else
            call_data_dissector(nexttvb, pinfo, tree);

        return;
    }

    rtp_data = proto_tree_add_item(rtp_tree, hf_rtp_data, newtvb, 0, -1, ENC_NA);

    /* We have checked for !p_conv_data->bta2dp_info && !p_conv_data->btvdp_info above*/
    if (p_packet_data && payload_type >= PT_UNDF_96 && payload_type <= PT_UNDF_127) {
        /* if the payload type is dynamic, we check if the conv is set and we look for the pt definition */
        if (p_packet_data->rtp_dyn_payload) {
            const char *payload_type_str = rtp_dyn_payload_get_name(p_packet_data->rtp_dyn_payload, payload_type);
            if (payload_type_str) {
                int len;
                len = dissector_try_string(rtp_dyn_pt_dissector_table,
                    payload_type_str, newtvb, pinfo, tree, rtp_info);
                /* If payload type string set from conversation and
                * no matching dissector found it's probably because no subdissector
                * exists. Don't call the dissectors based on payload number
                * as that'd probably be the wrong dissector in this case.
                * Just add it as data.
                */
                if (len > 0)
                    proto_item_set_hidden(rtp_data);
                return;
            }
        }
    }

    /* if we don't found, it is static OR could be set static from the preferences */
    if (dissector_try_uint_new(rtp_pt_dissector_table, payload_type, newtvb, pinfo, tree, true, rtp_info))
        proto_item_set_hidden(rtp_data);
}

/* Rtp payload reassembly
 *
 * This handles the reassembly of PDUs for higher-level protocols.
 *
 * We're a bit limited on how we can cope with out-of-order packets, because
 * we don't have any idea of where the datagram boundaries are. So if we see
 * packets A, C, B (all of which comprise a single datagram), we cannot know
 * that C should be added to the same datagram as A, until we come to B (which
 * may or may not actually be present...).
 *
 * What we end up doing in this case is passing A+B to the subdissector as one
 * datagram, and make out that a new one starts on C.
 */
static void
dissect_rtp_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
         proto_tree *rtp_tree, int offset, unsigned int data_len,
         unsigned int data_reported_len, unsigned int payload_type,
         struct _rtp_info *rtp_info)
{
    tvbuff_t *newtvb;
    struct _rtp_packet_info *p_packet_data;
    bool must_desegment = false;
    rtp_private_conv_info *finfo = NULL;
    rtp_multisegment_pdu *msp;
    uint32_t seqno;
    uint16_t save_can_desegment;

    /* Retrieve RTPs idea of a conversation */
    p_packet_data = (struct _rtp_packet_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_rtp, RTP_CONVERSATION_PROTO_DATA);

    if(p_packet_data != NULL)
        finfo = p_packet_data->rtp_conv_info;

    if(finfo == NULL || !desegment_rtp) {
        /* Hand the whole lot off to the subdissector */
        newtvb = tvb_new_subset_length_caplen(tvb, offset, data_len, data_reported_len);
        process_rtp_payload(newtvb, pinfo, tree, rtp_tree, payload_type, rtp_info);
        return;
    }

    seqno = p_packet_data->extended_seqno;

    /* Preserve the current desegmentation ability in case this is
     * RTP encapsulated in TCP (RFC 4571).
     */
    save_can_desegment = pinfo->can_desegment;
    pinfo->can_desegment = 2;
    pinfo->desegment_offset = 0;
    pinfo->desegment_len = 0;

#ifdef DEBUG_FRAGMENTS
    ws_debug("%d: RTP Part of convo %d(%p); seqno %d",
        pinfo->num,
        p_packet_data->frame_number, p_packet_data,
        seqno
        );
#endif

    /* look for a pdu which we might be extending */
    msp = (rtp_multisegment_pdu *)wmem_tree_lookup32_le(finfo->multisegment_pdus, seqno-1);

    if(msp && msp->startseq < seqno && msp->endseq >= seqno) {
        uint32_t fid = msp->startseq;
        fragment_head *fd_head;

#ifdef DEBUG_FRAGMENTS
        ws_debug("\tContinues fragment %d", fid);
#endif

        /* we always assume the datagram is complete; if this is the
         * first pass, that's our best guess, and if it's not, what we
         * say gets ignored anyway.
         */
        fd_head = fragment_add_seq(&rtp_reassembly_table,
                       tvb, offset, pinfo, fid, NULL,
                       seqno-msp->startseq, data_len,
                       false, 0);

        newtvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled RTP", fd_head,
                          &rtp_fragment_items, NULL, tree);

#ifdef DEBUG_FRAGMENTS
        ws_debug("\tFragment Coalesced; fd_head=%p, newtvb=%p (len %d)", fd_head, newtvb,
            newtvb?tvb_reported_length(newtvb):0);
#endif

        if(newtvb != NULL) {
            /* Hand off to the subdissector */
            process_rtp_payload(newtvb, pinfo, tree, rtp_tree, payload_type, rtp_info);

            /*
             * Check to see if there were any complete fragments within the chunk
             */
            if( pinfo->desegment_len )
            {
                if (pinfo->desegment_offset == 0) {
#ifdef DEBUG_FRAGMENTS
                    ws_debug("\tNo complete pdus in payload" );
#endif
                    /* Mark the fragments as not complete yet */
                    fragment_set_partial_reassembly(&rtp_reassembly_table,
                                    pinfo, fid, NULL);

                    /* we must need another segment */
                    msp->endseq = MIN(msp->endseq, seqno) + 1;

                }

                /* the higher-level dissector has asked for some more data - ie,
                   the end of this segment does not coincide with the end of a
                   higher-level PDU. */
                must_desegment = true;
            }

        }

    }
    else
    {
        /*
         * The segment is not the continuation of a fragmented segment
         * so process it as normal
         */
#ifdef DEBUG_FRAGMENTS
        ws_debug("\tRTP non-fragment payload");
#endif
        newtvb = tvb_new_subset_length_caplen( tvb, offset, data_len, data_reported_len );

        /* Hand off to the subdissector */
        process_rtp_payload(newtvb, pinfo, tree, rtp_tree, payload_type, rtp_info);

        if(pinfo->desegment_len) {
            /* the higher-level dissector has asked for some more data - ie,
               the end of this segment does not coincide with the end of a
               higher-level PDU. */
            must_desegment = true;
        }
    }

    /*
     * There were bytes left over that the higher protocol couldn't dissect so save them
     */
    if(must_desegment)
    {
        uint32_t deseg_offset = pinfo->desegment_offset;
        uint32_t frag_len = tvb_reported_length_remaining(newtvb, deseg_offset);
        fragment_head *fd_head;

#ifdef DEBUG_FRAGMENTS
        ws_debug("\tRTP Must Desegment: tvb_len=%d ds_len=%d %d frag_len=%d ds_off=%d",
            tvb_reported_length(newtvb),
            pinfo->desegment_len,
            pinfo->fd->visited,
            frag_len,
            deseg_offset);
#endif
        /* allocate a new msp for this pdu */
        if (!PINFO_FD_VISITED(pinfo)) {
            msp = wmem_new(wmem_file_scope(), rtp_multisegment_pdu);
            msp->startseq = seqno;
            msp->endseq = seqno+1;
            wmem_tree_insert32(finfo->multisegment_pdus, seqno, msp);
        }

        /*
         * Add the fragment to the fragment table
         */
        fd_head = fragment_add_seq(&rtp_reassembly_table,
                       newtvb, deseg_offset, pinfo, seqno, NULL, 0, frag_len,
                       true, 0);

        if(fd_head != NULL)
        {
            if( fd_head->reassembled_in != 0 && !(fd_head->flags & FD_PARTIAL_REASSEMBLY) )
            {
                proto_item *rtp_tree_item;
                rtp_tree_item = proto_tree_add_uint( tree, hf_rtp_reassembled_in,
                                     newtvb, deseg_offset, tvb_reported_length_remaining(newtvb, deseg_offset),
                                     fd_head->reassembled_in);
                proto_item_set_generated(rtp_tree_item);
#ifdef DEBUG_FRAGMENTS
                ws_debug("\tReassembled in %d", fd_head->reassembled_in);
#endif
            }
            else if (fd_head->reassembled_in == 0)
            {
#ifdef DEBUG_FRAGMENTS
                ws_debug("\tUnfinished fragment");
#endif
                /* this fragment is never reassembled */
                proto_tree_add_expert(tree, pinfo, &ei_rtp_fragment_unfinished, tvb, deseg_offset, -1);
            }
        }
        else
        {
            /*
             * This fragment was the first fragment in a new entry in the
             * frag_table; we don't yet know where it is reassembled
             */
#ifdef DEBUG_FRAGMENTS
            ws_debug("\tnew pdu");
#endif
        }

        if( pinfo->desegment_offset == 0 )
        {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTP");
            col_set_str(pinfo->cinfo, COL_INFO, "[RTP segment of a reassembled PDU]");
        }
    }

    /* Restore desegmentation ability */
    pinfo->can_desegment = save_can_desegment;
    pinfo->desegment_offset = 0;
    pinfo->desegment_len = 0;
}

static int
dissect_rtp_rfc2198(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    volatile int offset = 0;
    int cnt;
    bool hdr_follow = true;
    proto_tree *rfc2198_tree;
    rfc2198_hdr *hdr_last;
    rfc2198_hdr *hdr_chain = NULL;
    struct _rtp_packet_info *p_packet_data;
    struct _rtp_info* rtp_info = NULL;
    struct _rtp_info rfc2198_rtp_info;
    volatile unsigned rtp_info_offset = 0;

    if (data) {
        rtp_info = (struct _rtp_info*)data;
        rfc2198_rtp_info = *rtp_info;
        rtp_info_offset = rtp_info->info_payload_offset;
    }

    /* Retrieve RTPs idea of a conversation */
    p_packet_data = (struct _rtp_packet_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_rtp, RTP_CONVERSATION_PROTO_DATA);

    /* Add try to RFC 2198 data */
    rfc2198_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_rtp_rfc2198, NULL, "RFC 2198: Redundant Audio Data");

    hdr_last = NULL;
    cnt = 0;
    while (hdr_follow) {
        proto_item *ti;
        proto_tree *rfc2198_hdr_tree;
        const char *payload_type_str;
        rfc2198_hdr *hdr_new;
        uint8_t octet1;

        cnt++;
        payload_type_str = NULL;

        /* Allocate and fill in header */
        hdr_new = wmem_new0(pinfo->pool, rfc2198_hdr);
        hdr_new->next = NULL;
        octet1 = tvb_get_uint8(tvb, offset);
        hdr_new->pt = RTP_PAYLOAD_TYPE(octet1);
        hdr_follow = (octet1 & 0x80);

        /* Save the payload type for Decode As */
        p_add_proto_data(pinfo->pool, pinfo, proto_rtp, RTP_DECODE_AS_PROTO_DATA, GUINT_TO_POINTER(hdr_new->pt));

        /* if it is dynamic payload, let use the conv data to see if it is defined */
        if ((hdr_new->pt > 95) && (hdr_new->pt < 128)) {
            if (p_packet_data && p_packet_data->rtp_dyn_payload){
                rtp_dyn_payload_get_full(p_packet_data->rtp_dyn_payload, hdr_new->pt, &payload_type_str, &hdr_new->payload_rate, &hdr_new->payload_channels, &hdr_new->payload_fmtp_map);
                hdr_new->payload_type_str = payload_type_str;
            } else {
                /* See if we have a dissector tied to the dynamic payload
                 * through preferences / Decode As */
                dissector_handle_t pt_dissector_handle;

                pt_dissector_handle = dissector_get_uint_handle(rtp_pt_dissector_table, hdr_new->pt);
                if (pt_dissector_handle) {
                    hdr_new->payload_type_str = dissector_handle_get_dissector_name(pt_dissector_handle);
                }
            }
        }
        /* Add a subtree for this header and add items */
        rfc2198_hdr_tree = proto_tree_add_subtree_format(rfc2198_tree, tvb, offset, (hdr_follow)?4:1,
                                    ett_rtp_rfc2198_hdr, &ti, "Header %u", cnt);
        proto_tree_add_item(rfc2198_hdr_tree, hf_rtp_rfc2198_follow, tvb, offset, 1, ENC_BIG_ENDIAN );
        proto_tree_add_uint_format_value(rfc2198_hdr_tree, hf_rtp_payload_type, tvb,
            offset, 1, octet1, "%s (%u)",
            payload_type_str ? payload_type_str : val_to_str_ext_const(hdr_new->pt, &rtp_payload_type_vals_ext, "Unknown"),
            hdr_new->pt);
        proto_item_append_text(ti, ": PT=%s",
                       payload_type_str ? payload_type_str :
                                          val_to_str_ext(hdr_new->pt, &rtp_payload_type_vals_ext, "Unknown (%u)"));
        offset += 1;

        /* Timestamp offset and block length don't apply to last header */
        if (hdr_follow) {
            proto_tree_add_item(rfc2198_hdr_tree, hf_rtp_rfc2198_tm_off, tvb, offset, 2, ENC_BIG_ENDIAN );
            proto_tree_add_item(rfc2198_hdr_tree, hf_rtp_rfc2198_bl_len, tvb, offset + 1, 2, ENC_BIG_ENDIAN );
            hdr_new->len = tvb_get_ntohs(tvb, offset + 1) & 0x03FF;
            proto_item_append_text(ti, ", len=%u", hdr_new->len);
            offset += 3;
        } else {
            hdr_new->len = -1;
            hdr_follow = false;
        }

        if (hdr_last) {
            hdr_last->next = hdr_new;
        } else {
            hdr_chain = hdr_new;
        }
        hdr_last = hdr_new;
    }

    /* Dissect each data block according to the header info */
    hdr_last = hdr_chain;
    while (hdr_last) {
        hdr_last->offset = offset;
        if (!hdr_last->next) {
            hdr_last->len = tvb_reported_length_remaining(tvb, offset);
        }
        if (rtp_info) {
            rfc2198_rtp_info.info_payload_offset = rtp_info_offset + hdr_last->offset;
            rfc2198_rtp_info.info_payload_len = hdr_last->len;
            rfc2198_rtp_info.info_payload_type = hdr_last->pt;
            rfc2198_rtp_info.info_payload_type_str = hdr_last->payload_type_str;
            rfc2198_rtp_info.info_payload_rate = hdr_last->payload_rate;
            rfc2198_rtp_info.info_payload_channels = hdr_last->payload_channels;
            rfc2198_rtp_info.info_payload_fmtp_map = hdr_last->payload_fmtp_map;
        }
        const char *saved_proto = pinfo->current_proto;
        TRY {
            dissect_rtp_data(tvb, pinfo, tree, rfc2198_tree, hdr_last->offset, hdr_last->len, hdr_last->len, hdr_last->pt, &rfc2198_rtp_info);
        }
        CATCH_NONFATAL_ERRORS {
            show_exception(tvb, pinfo, rfc2198_tree, EXCEPT_CODE, GET_MESSAGE);
            pinfo->current_proto = saved_proto;
        }
        ENDTRY;
        if (rtp_info && rfc2198_deencapsulate && !hdr_last->next) {
            /* Set the payload for the tap to that of the primary encoding
             * to remove the RFC 2198 encapsulation. (Since this is the
             * last encoding in the packet, the calculated length includes
             * the padding and padding stays the same.)
             * Ideally we should process the redundant encoding or FEC,
             * but just treating the primary encoding as the only payload
             * for the tap is closer than doing nothing, and at least has
             * some chance of playing or saving the primary media payload.
             *
             * XXX: WebRTC/Chromium, when using RED with ULPFEC (RFC 5109),
             * violates the RFCs by having the FEC set in separate packets
             * as a different primary encoding (using duplicate sequence
             * numbers already used by the video.) This is done because of
             * a concern that the combined payload size of FEC plus video
             * encodings like VP8 could push a packet over the MTU size,
             * also a problem.
             * See RFC 8872 3.2.4 "RTP Payload Type" and Appendix A
             * "Dismissing Payload Type Multiplexing," also
             * https://bugs.chromium.org/p/webrtc/issues/detail?id=9188
             * https://bugs.chromium.org/p/webrtc/issues/detail?id=12530
             * https://bugs.chromium.org/p/webrtc/issues/detail?id=1467
             * However, since duplicate sequence numbers as used, a user
             * Ignoring all the FEC packets could be a workaround.
             * RFC 2198 in WebRTC/Chromium with actual redundant audio is
             * RFC-compliant, though:
             * https://bugs.chromium.org/p/webrtc/issues/detail?id=11640
             */
            *rtp_info = rfc2198_rtp_info;
        }
        offset += hdr_last->len;
        hdr_last = hdr_last->next;
    }
    return tvb_captured_length(tvb);
}

static int
dissect_full_rfc4571(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    /* rfc4571 packet frame
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      ---------------------------------------------------------------
     |             LENGTH            |  RTP or RTCP packet ...       |
      ---------------------------------------------------------------
     */
    int offset = 0;
    uint32_t length = 0;
    proto_tree_add_item_ret_uint(tree, hf_rfc4571_header_len, tvb, offset, 2, ENC_NA, &length);
    if (length == 0) {
        return 2;
    }

    offset += 2;
    tvbuff_t *tvb_sub;
    tvb_sub = tvb_new_subset_remaining(tvb, offset);

    dissect_rtp(tvb_sub, pinfo, tree, data);
    return tvb_reported_length(tvb);
}

static unsigned
get_rtp_rfc4571_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    uint16_t rtp_length = tvb_get_ntohs(tvb, offset); /* length field is at the beginning, 2 bytes */
    return (unsigned)rtp_length + 2; /* plus the length field */
}

#define RTP_RFC4571_HEADER_LEN    2

static int
dissect_rtp_rfc4571(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, true, RTP_RFC4571_HEADER_LEN,
                     get_rtp_rfc4571_len, dissect_full_rfc4571, data);
    return tvb_captured_length(tvb);
}

static void
dissect_rtp_hext_rfc5285_onebyte( tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *rtp_hext_tree )
{
    proto_tree *rtp_hext_rfc5285_tree = NULL;
    unsigned ext_offset = 0;

    while (ext_offset < tvb_captured_length (tvb)) {
        uint8_t   ext_hdr_hdr;
        uint8_t   ext_id;
        uint8_t   ext_length;
        unsigned  start_ext_offset;
        tvbuff_t *subtvb;

        /* Skip bytes with the value 0, they are padding */
        start_ext_offset = ext_offset;
        while (tvb_get_uint8 (tvb, ext_offset) == 0) {
            ext_offset ++;
            if (ext_offset >= tvb_captured_length (tvb))
                return;
        }

        /* Add padding */
        if (ext_offset > start_ext_offset)
            proto_tree_add_item(rtp_hext_tree, hf_rtp_padding_data, tvb, start_ext_offset, ext_offset-start_ext_offset, ENC_NA );

        ext_hdr_hdr = tvb_get_uint8 (tvb, ext_offset);
        ext_id = ext_hdr_hdr >> 4;

        /* 15 is for future extensibility, ignore length, etc and stop processing packet if it shows up */
        if (ext_id == 15)
            return;

        ext_length = (ext_hdr_hdr & 0x0F) + 1;

        /* Exit on malformed extension headers */
        if (ext_offset + ext_length + 1 > tvb_captured_length (tvb)) {
            return;
        }

        if (rtp_hext_tree) {
            rtp_hext_rfc5285_tree = proto_tree_add_subtree(rtp_hext_tree, tvb, ext_offset, ext_length + 1,
                                            ett_hdr_ext_rfc5285, NULL, "RFC 5285 Header Extension (One-Byte Header)");

            proto_tree_add_uint( rtp_hext_rfc5285_tree, hf_rtp_ext_rfc5285_id, tvb, ext_offset, 1, ext_id);
            proto_tree_add_uint( rtp_hext_rfc5285_tree, hf_rtp_ext_rfc5285_length, tvb, ext_offset, 1, ext_length);
        }
        ext_offset ++;

        subtvb = tvb_new_subset_length(tvb, ext_offset, ext_length);
        if (!dissector_try_uint (rtp_hdr_ext_rfc5285_dissector_table, ext_id, subtvb, pinfo, rtp_hext_rfc5285_tree)) {
            if (rtp_hext_tree)
                proto_tree_add_item(rtp_hext_rfc5285_tree, hf_rtp_ext_rfc5285_data, subtvb, 0, ext_length, ENC_NA );
        }

        ext_offset += ext_length;
    }
}


static void
dissect_rtp_hext_rfc5285_twobytes(tvbuff_t *parent_tvb, unsigned id_offset,
        uint8_t id, tvbuff_t *tvb, packet_info *pinfo, proto_tree *rtp_hext_tree)
{
    proto_tree *rtp_hext_rfc5285_tree = NULL;
    unsigned ext_offset = 0, start_ext_offset;

    while (ext_offset + 2 < tvb_captured_length (tvb)) {
        uint8_t   ext_id;
        uint8_t   ext_length;
        tvbuff_t *subtvb;

        /* Skip bytes with the value 0, they are padding */
        start_ext_offset = ext_offset;
        while (tvb_get_uint8 (tvb, ext_offset) == 0) {
            if (ext_offset + 2 >= tvb_captured_length (tvb))
                return;
            ext_offset ++;
        }
        /* Add padding */
        if (ext_offset > start_ext_offset)
            proto_tree_add_item(rtp_hext_tree, hf_rtp_padding_data, tvb, start_ext_offset, ext_offset-start_ext_offset, ENC_NA );

        ext_id = tvb_get_uint8 (tvb, ext_offset);
        ext_length = tvb_get_uint8 (tvb, ext_offset + 1);

        if (rtp_hext_tree) {
            rtp_hext_rfc5285_tree = proto_tree_add_subtree(rtp_hext_tree, tvb, ext_offset, ext_length + 2,
                                    ett_hdr_ext_rfc5285, NULL, "RFC 5285 Header Extension (Two-Byte Header)");

            proto_tree_add_uint( rtp_hext_rfc5285_tree, hf_rtp_ext_rfc5285_appbits, parent_tvb, id_offset + 1, 1, id & 0x000F);
            proto_tree_add_uint( rtp_hext_rfc5285_tree, hf_rtp_ext_rfc5285_id, tvb, ext_offset, 1, ext_id);
            proto_tree_add_uint( rtp_hext_rfc5285_tree, hf_rtp_ext_rfc5285_length, tvb, ext_offset + 1, 1, ext_length);
        }

        ext_offset += 2;

        subtvb = tvb_new_subset_length(tvb, ext_offset, ext_length);
        if (ext_length && !dissector_try_uint (rtp_hdr_ext_rfc5285_dissector_table, ext_id, subtvb, pinfo, rtp_hext_rfc5285_tree)) {
            proto_tree_add_item(rtp_hext_rfc5285_tree, hf_rtp_ext_rfc5285_data, subtvb, 0, ext_length, ENC_NA );
        }

        ext_offset += ext_length;
    }
}

static int
dissect_rtp( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti            = NULL;
    proto_tree *volatile rtp_tree = NULL;
    uint8_t     octet1, octet2;
    unsigned int version;
    bool        padding_set;
    bool        extension_set;
    unsigned int csrc_count;
    bool        marker_set;
    unsigned int payload_type;
    const char *payload_type_str = NULL;
    bool        is_srtp = false;
    unsigned int i;
    int         length, reported_length;
    int         data_len;
    volatile unsigned int offset = 0;
    uint16_t    seq_num;
    uint32_t    timestamp;
    uint32_t    sync_src;
    struct _rtp_packet_info *p_packet_data;
    /*struct srtp_info *srtp_info = NULL;*/
    /*unsigned int srtp_offset;*/
    const char   *pt = NULL;
    struct _rtp_info *rtp_info;
    static int * const octet1_fields[] = {
        &hf_rtp_version,
        &hf_rtp_padding,
        &hf_rtp_extension,
        &hf_rtp_csrc_count,
        NULL
    };

    /* Get the fields in the first octet */
    octet1 = tvb_get_uint8( tvb, offset );
    version = RTP_VERSION( octet1 );

    /* RFC 7983 gives current best practice in demultiplexing RTP packets:
     * Examine the first byte of the packet:
     *              +----------------+
     *              |        [0..3] -+--> forward to STUN
     *              |                |
     *              |      [16..19] -+--> forward to ZRTP
     *              |                |
     *  packet -->  |      [20..63] -+--> forward to DTLS
     *              |                |
     *              |      [64..79] -+--> forward to TURN Channel
     *              |                |
     *              |    [128..191] -+--> forward to RTP/RTCP
     *              +----------------+
     *
     * DTLS-SRTP MUST support multiplexing of DTLS and RTP over the same
     * port pair (RFCs 5764, 8835), and this frequently occurs after SDP
     * has been used to set up a RTP conversation and set the conversation
     * dissector RTP. In addition, STUN packets sharing one port are common
     * as well.
     *
     * In practice, RTP0_INVALID rejects packets and lets heuristic dissectors
     * take a look. The STUN, ZRTP, and DTLS heuristic dissectors are all
     * enabled by default so out of the box it more or less looks correct - at
     * least on the second pass, on tshark there's incorrect RTP information in
     * the tree. However, the STUN heuristic dissector can change the
     * dissector for the conversation to itself (the non-heuristic dissector
     * does not), see #18832, and TURN ChannelData messages are impossible to
     * heuristically detect.
     */
    if (global_rtp_version0_type == RTP0_RFC7983) {
        switch (version) {
        case 0:
            if (octet1 < 4) {
                call_dissector(stun_handle, tvb, pinfo, tree);
                return tvb_captured_length(tvb);
            } else if ((octet1 & 0xfc) == 0x10) {
                call_dissector(zrtp_handle, tvb,pinfo, tree);
                return tvb_captured_length(tvb);
            } else if (octet1 > 19) {
                call_dissector(dtls_handle, tvb,pinfo, tree);
                return tvb_captured_length(tvb);
            }
            break;
        case 1:
            if (octet1 < 80) {
                /* The STUN dissector will dissect TURN ChannelData
                 * XXX: Maybe we should call the turnchannel dissector?
                 *
                 * Should we be assuming we have TURN ChannelData for
                 * the RTP0_STUN and option too?
                 */
                call_dissector(stun_handle, tvb, pinfo, tree);
                return tvb_captured_length(tvb);
            }
            break;
        case 3:
            if (octet1 == 0xFF) {
                if (tvb_get_uint8( tvb, offset + 1 ) == 0x10) {
                    /* Special MS-TURN Multiplexed TURN Channel */
                    call_dissector(stun_handle, tvb, pinfo, tree);
                    return tvb_captured_length(tvb);
                }
            }
        /* FALLTHROUGH */
        case 2:
        default:
            break;
        }
    } else if (version == 0) {
        switch (global_rtp_version0_type) {
        case RTP0_STUN:
            call_dissector(stun_handle, tvb, pinfo, tree);
            return tvb_captured_length(tvb);
        case RTP0_CLASSICSTUN:
            call_dissector(classicstun_handle, tvb, pinfo, tree);
            return tvb_captured_length(tvb);

        case RTP0_T38:
            call_dissector(t38_handle, tvb, pinfo, tree);
            return tvb_captured_length(tvb);

        case RTP0_SPRT:
            call_dissector(sprt_handle, tvb, pinfo, tree);
            return tvb_captured_length(tvb);

        case RTP0_INVALID:
            if (!(tvb_memeql(tvb, 4, (const uint8_t*)"ZRTP", 4)))
            {
                call_dissector(zrtp_handle, tvb,pinfo, tree);
                return tvb_captured_length(tvb);
            }
        default:
            ; /* Unknown or unsupported version (let it fall through) */
        }
    }

    /* fill in the rtp_info structure */
    rtp_info = wmem_new0(pinfo->pool, struct _rtp_info);
    rtp_info->info_version = version;
    if (version != 2) {
        /*
         * Unknown or unsupported version.
         */
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTP");

        col_add_fstr( pinfo->cinfo, COL_INFO,
            "Unknown RTP version %u", version);

        if ( tree ) {
            ti = proto_tree_add_item( tree, proto_rtp, tvb, offset, -1, ENC_NA );
            rtp_tree = proto_item_add_subtree( ti, ett_rtp );

            proto_tree_add_uint( rtp_tree, hf_rtp_version, tvb,
                offset, 1, octet1);
        }
        /* XXX: Offset is zero here, so in practice this rejects the packet
         * and lets heuristic dissectors make an attempt, though after
         * adding entries to the tree (at least on a first pass in tshark.)
         */
        return offset;
    }

    padding_set = RTP_PADDING( octet1 );
    extension_set = RTP_EXTENSION( octet1 );
    csrc_count = RTP_CSRC_COUNT( octet1 );

    /* Get the fields in the second octet */
    octet2 = tvb_get_uint8( tvb, offset + 1 );
    marker_set = RTP_MARKER( octet2 );
    payload_type = RTP_PAYLOAD_TYPE( octet2 );

    /* Save the payload type for Decode As */
    p_add_proto_data(pinfo->pool, pinfo, proto_rtp, RTP_DECODE_AS_PROTO_DATA, GUINT_TO_POINTER(payload_type));

    if (marker_set && payload_type >= FIRST_RTCP_CONFLICT_PAYLOAD_TYPE && payload_type <=  LAST_RTCP_CONFLICT_PAYLOAD_TYPE) {
        call_dissector(rtcp_handle, tvb, pinfo, tree);
        return tvb_captured_length(tvb);
    }

    /* Get the subsequent fields */
    seq_num = tvb_get_ntohs( tvb, offset + 2 );
    timestamp = tvb_get_ntohl( tvb, offset + 4 );
    sync_src = tvb_get_ntohl( tvb, offset + 8 );

    /* fill in the rtp_info structure */
    rtp_info->info_padding_set = padding_set;
    rtp_info->info_marker_set = marker_set;
    rtp_info->info_media_types = 0;
    rtp_info->info_payload_type = payload_type;
    rtp_info->info_seq_num = seq_num;
    rtp_info->info_extended_seq_num = seq_num; /* initial with seq_number */
    rtp_info->info_timestamp = timestamp;
    rtp_info->info_extended_timestamp = timestamp; /* initial with timestamp */
    rtp_info->info_sync_src = sync_src;
    rtp_info->info_is_srtp = false;
    rtp_info->info_setup_frame_num = 0;
    rtp_info->info_payload_type_str = NULL;
    rtp_info->info_payload_rate = 0;
    rtp_info->info_payload_fmtp_map = NULL;
    rtp_info->info_is_ed137 = false;
    rtp_info->info_ed137_info = NULL;

    /*
     * Do we have all the data?
     */
    length = tvb_captured_length_remaining(tvb, offset);
    reported_length = tvb_reported_length_remaining(tvb, offset);
    if (reported_length >= 0 && length >= reported_length) {
        /*
         * Yes.
         */
        rtp_info->info_all_data_present = true;
        rtp_info->info_data_len = reported_length;

        /*
         * Save the pointer to raw rtp data (header + payload incl.
         * padding).
         * That should be safe because the "epan_dissect_t"
         * constructed for the packet has not yet been freed when
         * the taps are called.
         * (Destroying the "epan_dissect_t" will end up freeing
         * all the tvbuffs and hence invalidating pointers to
         * their data.)
         * See "add_packet_to_packet_list()" for details.
         */
        rtp_info->info_data = tvb_get_ptr(tvb, 0, -1);
    } else {
        /*
         * No - packet was cut short at capture time.
         */
        rtp_info->info_all_data_present = false;
        rtp_info->info_data_len = 0;
        rtp_info->info_data = NULL;
    }

    /* Look for conv and add to the frame if found */

    p_packet_data = get_rtp_packet_info(pinfo, rtp_info);

    if (p_packet_data && p_packet_data->srtp_info) is_srtp = true;
    rtp_info->info_is_srtp = is_srtp;

    col_set_str( pinfo->cinfo, COL_PROTOCOL, (is_srtp) ? "SRTP" : "RTP" );

#if 0 /* XXX: srtp_offset never actually used ?? */
    /* check if this is added as an SRTP stream - if so, don't try to dissect the payload data for now */
    if (p_conv_data && p_conv_data->srtp_info) {
        srtp_info = p_conv_data->srtp_info;
        if (rtp_info->info_all_data_present) {
            srtp_offset = rtp_info->info_data_len - srtp_info->mki_len - srtp_info->auth_tag_len;
        }
    }
#endif

    if (p_packet_data && p_packet_data->bta2dp_info && p_packet_data->bta2dp_info->codec_dissector) {
        rtp_info->info_payload_type_str = (const char *) dissector_handle_get_protocol_short_name(p_packet_data->bta2dp_info->codec_dissector);
    } else if (p_packet_data && p_packet_data->btvdp_info && p_packet_data->btvdp_info->codec_dissector) {
        rtp_info->info_payload_type_str = (const char *) dissector_handle_get_protocol_short_name(p_packet_data->btvdp_info->codec_dissector);
    }

    /* if it is dynamic payload, let use the conv data to see if it is defined */
    if ( (payload_type>95) && (payload_type<128) ) {
        if (p_packet_data && p_packet_data->rtp_dyn_payload) {
            int sample_rate = 0;
            unsigned channels = 1;
            wmem_map_t *fmtp_map;

#ifdef DEBUG_CONVERSATION
            rtp_dump_dyn_payload(p_conv_data->rtp_dyn_payload);
#endif
            DPRINT(("looking up conversation data for dyn_pt=%d", payload_type));

            if (rtp_dyn_payload_get_full(p_packet_data->rtp_dyn_payload, payload_type,
                                        &payload_type_str, &sample_rate,
                                        &channels, &fmtp_map)) {
                DPRINT(("found conversation data for dyn_pt=%d, enc_name=%s",
                        payload_type, payload_type_str));
                rtp_info->info_payload_type_str = payload_type_str;
                rtp_info->info_payload_rate     = sample_rate;
                rtp_info->info_payload_channels = channels;
                rtp_info->info_payload_fmtp_map = fmtp_map;
            }
        } else {
            /* See if we have a dissector tied to the dynamic payload trough preferences*/
            dissector_handle_t pt_dissector_handle;
            const char *name;

            pt_dissector_handle = dissector_get_uint_handle(rtp_pt_dissector_table, payload_type);
            if (pt_dissector_handle) {
                name = dissector_handle_get_dissector_name(pt_dissector_handle);
                if (name) {
                    rtp_info->info_payload_type_str = name;
                }
            }
        }
    }

    if (p_packet_data && p_packet_data->bta2dp_info) {
        pt = (p_packet_data->bta2dp_info->codec_dissector) ? dissector_handle_get_protocol_short_name(p_packet_data->bta2dp_info->codec_dissector) : "Unknown";
    } else if (p_packet_data && p_packet_data->btvdp_info) {
        pt = (p_packet_data->btvdp_info->codec_dissector) ? dissector_handle_get_protocol_short_name(p_packet_data->btvdp_info->codec_dissector) : "Unknown";
    } else {
        pt = (payload_type_str ? payload_type_str : val_to_str_ext(payload_type, &rtp_payload_type_vals_ext, "Unknown (%u)"));
    }

    col_add_fstr( pinfo->cinfo, COL_INFO,
        "PT=%s, SSRC=0x%X, Seq=%u, Time=%u%s",
        pt,
        sync_src,
        seq_num,
        timestamp,
        marker_set ? ", Mark" : "");

    if ( tree ) {
        proto_tree *item;
        /* Create RTP protocol tree */
        ti = proto_tree_add_item(tree, proto_rtp, tvb, offset, -1, ENC_NA );
        rtp_tree = proto_item_add_subtree(ti, ett_rtp );

        /* Conversation setup info */
        if (global_rtp_show_setup_info)
        {
            show_setup_info(tvb, pinfo, rtp_tree);
        }

        proto_tree_add_bitmask_list(rtp_tree, tvb, offset, 1, octet1_fields, ENC_NA);
        offset++;

        proto_tree_add_boolean( rtp_tree, hf_rtp_marker, tvb, offset,
            1, octet2 );

        proto_tree_add_uint_format( rtp_tree, hf_rtp_payload_type, tvb,
            offset, 1, octet2, "Payload type: %s (%u)", pt, payload_type);

        offset++;

        /* Sequence number 16 bits (2 octets) */
        proto_tree_add_uint( rtp_tree, hf_rtp_seq_nr, tvb, offset, 2, seq_num );
        if(p_packet_data != NULL) {
            item = proto_tree_add_uint(rtp_tree, hf_rtp_ext_seq_nr, tvb, offset, 2, p_packet_data->extended_seqno);
            proto_item_set_generated(item);
        }
        offset += 2;

        /* Timestamp 32 bits (4 octets) */
        proto_tree_add_uint( rtp_tree, hf_rtp_timestamp, tvb, offset, 4, timestamp );
        if(p_packet_data != NULL) {
            item = proto_tree_add_uint64(rtp_tree, hf_rtp_ext_timestamp, tvb, offset, 4, p_packet_data->extended_timestamp);
            proto_item_set_generated(item);
        }
        offset += 4;

        /* Synchronization source identifier 32 bits (4 octets) */
        proto_tree_add_uint( rtp_tree, hf_rtp_ssrc, tvb, offset, 4, sync_src );
        offset += 4;
    } else {
        offset += 12;
    }
    /* CSRC list*/
    if ( csrc_count > 0 ) {
        proto_tree *rtp_csrc_tree;
        uint32_t csrc_item;
        ti = proto_tree_add_item(rtp_tree, hf_rtp_csrc_items, tvb, offset,
                                     csrc_count * 4, ENC_NA);
        proto_item_append_text(ti, " (%u items)", csrc_count);
        rtp_csrc_tree = proto_item_add_subtree( ti, ett_csrc_list );

        for (i = 0; i < csrc_count; i++ ) {
            csrc_item = tvb_get_ntohl( tvb, offset );
            proto_tree_add_uint_format( rtp_csrc_tree,
                hf_rtp_csrc_item, tvb, offset, 4,
                csrc_item,
                "CSRC item %d: 0x%X",
                i, csrc_item );
            offset += 4;
        }
    }

    /* Optional RTP header extension */
    if ( extension_set ) {
        unsigned int hdr_extension_len;
        unsigned int hdr_extension_id;

        /* Defined by profile field is 16 bits (2 octets) */
        hdr_extension_id = tvb_get_ntohs( tvb, offset );
        proto_tree_add_uint( rtp_tree, hf_rtp_prof_define, tvb, offset, 2, hdr_extension_id );
        offset += 2;

        hdr_extension_len = tvb_get_ntohs( tvb, offset );
        proto_tree_add_uint( rtp_tree, hf_rtp_length, tvb, offset, 2, hdr_extension_len);
        offset += 2;
        if ( hdr_extension_len > 0 ) {
            proto_tree *rtp_hext_tree = NULL;
            tvbuff_t   *newtvb;

            ti = proto_tree_add_item(rtp_tree, hf_rtp_hdr_exts, tvb, offset, hdr_extension_len * 4, ENC_NA);
            rtp_hext_tree = proto_item_add_subtree( ti, ett_hdr_ext );

            /* pass interpretation of header extension to a registered subdissector */
            newtvb = tvb_new_subset_length(tvb, offset, hdr_extension_len * 4);

            if (hdr_extension_id == RTP_RFC5285_ONE_BYTE_SIG) {
                dissect_rtp_hext_rfc5285_onebyte (newtvb, pinfo, rtp_hext_tree);
            }
            else if ((hdr_extension_id & RTP_RFC5285_TWO_BYTE_MASK) == RTP_RFC5285_TWO_BYTE_SIG) {
                dissect_rtp_hext_rfc5285_twobytes(tvb,
                    offset - 4, hdr_extension_id, newtvb,
                    pinfo, rtp_hext_tree);
            }
            else {
                if ( !(dissector_try_uint_new(rtp_hdr_ext_dissector_table, hdr_extension_id, newtvb, pinfo, rtp_hext_tree, false, rtp_info)) ) {
                    unsigned int hdrext_offset;

                    hdrext_offset = offset;
                    for ( i = 0; i < hdr_extension_len; i++ ) {
                        proto_tree_add_item( rtp_hext_tree, hf_rtp_hdr_ext, tvb, hdrext_offset, 4, ENC_BIG_ENDIAN );
                        hdrext_offset += 4;
                    }
                }
            }
        }
        offset += hdr_extension_len * 4;
    }

    if ( padding_set ) {
        /*
         * This RTP frame has padding - find it.
         *
         * The padding count is found in the LAST octet of
         * the packet; it contains the number of octets
         * that can be ignored at the end of the packet.
         */
        volatile unsigned int padding_count;
        volatile bool padding_bogus = false;
        if (tvb_captured_length(tvb) < tvb_reported_length(tvb)) {
            /*
             * We don't *have* the last octet of the
             * packet, so we can't get the padding
             * count.
             *
             * Put an indication of that into the
             * tree, and just put in a raw data
             * item.
             */
            proto_tree_add_expert(rtp_tree, pinfo, &ei_rtp_padding_missing, tvb, 0, 0);
            call_data_dissector(tvb_new_subset_remaining(tvb, offset),
                pinfo, rtp_tree);
            return tvb_captured_length(tvb);
        }

        padding_count = tvb_get_uint8( tvb,
            tvb_reported_length( tvb ) - 1 );
        data_len =
            tvb_reported_length_remaining( tvb, offset ) - padding_count;

        rtp_info->info_payload_offset = offset;

        if (p_packet_data && p_packet_data->bta2dp_info) {
            if (p_packet_data->bta2dp_info->codec_dissector == sbc_handle) {
                rtp_info->info_payload_offset += 1;
            }

            if (p_packet_data->bta2dp_info->content_protection_type == BTAVDTP_CONTENT_PROTECTION_TYPE_SCMS_T) {
                rtp_info->info_payload_offset += 1;
            }
        }

        if (p_packet_data && p_packet_data->btvdp_info &&
                p_packet_data->btvdp_info->content_protection_type == BTAVDTP_CONTENT_PROTECTION_TYPE_SCMS_T) {
            rtp_info->info_payload_offset += 1;
        }

        rtp_info->info_payload_len = tvb_reported_length_remaining(tvb, rtp_info->info_payload_offset);

        if (rtp_info->info_payload_len > padding_count) {
            rtp_info->info_payload_len -= padding_count;
        } else {
            rtp_info->info_payload_len = 0;
        }

        if (data_len > 0) {
            /*
             * There's data left over when you take out
             * the padding; dissect it.
             */
            struct _rtp_pkt_info *rtp_pkt_info = wmem_new(pinfo->pool, struct _rtp_pkt_info);

            rtp_pkt_info->payload_len = data_len;
            rtp_pkt_info->padding_len = padding_count - 1;
            p_add_proto_data(pinfo->pool, pinfo, proto_rtp, pinfo->curr_layer_num, rtp_pkt_info);

            /* Ensure that tap is called after packet dissection, even in case of exception */
            TRY {
                dissect_rtp_data( tvb, pinfo, tree, rtp_tree,
                    offset,
                    data_len,
                    data_len,
                    payload_type,
                    rtp_info);
            } CATCH_ALL {
                if (!pinfo->flags.in_error_pkt)
                    tap_queue_packet(rtp_tap, pinfo, rtp_info);
                RETHROW;
            }
            ENDTRY;
            offset += data_len;
        } else if (data_len < 0) {
            /*
             * The padding count is bigger than the
             * amount of RTP payload in the packet!
             * Clip the padding count.
             */
            padding_count =
                tvb_reported_length_remaining(tvb, offset);
            padding_bogus = true;
        }
        if (padding_count) {
            if (padding_count > 1) {
                /*
                 * There's more than one byte of padding;
                 * show all but the last byte as padding
                 * data.
                 */
                proto_tree_add_item( rtp_tree, hf_rtp_padding_data,
                    tvb, offset, padding_count - 1, ENC_NA );
                offset += padding_count - 1;
            }
            /*
             * Show the last byte in the PDU as the padding
             * count.
             */
            ti = proto_tree_add_item( rtp_tree, hf_rtp_padding_count,
                tvb, offset, 1, ENC_BIG_ENDIAN );
            if (padding_bogus) {
                expert_add_info(pinfo, ti, &ei_rtp_padding_bogus);
            }
        } else {
            /* The padding length includes itself, so zero is an illegal
             * value. Trying to add it to the tree at this point would
             * create a malformed error by running off the end of the tvb.
             */
            proto_tree_add_expert_format(rtp_tree, pinfo, &ei_rtp_padding_bogus, tvb, tvb_reported_length(tvb) - 1, 1, "Frame has padding, but of illegal length zero");
        }
    }
    else {
        /*
         * No padding.
         */
        rtp_info->info_payload_offset = offset;
        rtp_info->info_payload_len = tvb_captured_length_remaining(tvb, offset);

        if (p_packet_data && p_packet_data->bta2dp_info) {
            if (p_packet_data->bta2dp_info->codec_dissector == sbc_handle) {
                rtp_info->info_payload_offset += 1;
                rtp_info->info_payload_len -= 1;
            }

            if (p_packet_data->bta2dp_info->content_protection_type == BTAVDTP_CONTENT_PROTECTION_TYPE_SCMS_T) {
                rtp_info->info_payload_offset += 1;
                rtp_info->info_payload_len -= 1;
            }
        }

        if (p_packet_data && p_packet_data->btvdp_info &&
                p_packet_data->btvdp_info->content_protection_type == BTAVDTP_CONTENT_PROTECTION_TYPE_SCMS_T) {
            rtp_info->info_payload_offset += 1;
            rtp_info->info_payload_len -= 1;
        }

        if (tvb_reported_length_remaining(tvb, offset) > 0) {
            struct _rtp_pkt_info *rtp_pkt_info = wmem_new(pinfo->pool, struct _rtp_pkt_info);

            rtp_pkt_info->payload_len = tvb_captured_length_remaining(tvb, offset);
            rtp_pkt_info->padding_len = 0;
            p_set_proto_data(pinfo->pool, pinfo, proto_rtp, pinfo->curr_layer_num, rtp_pkt_info);

            /* Ensure that tap is called after packet dissection, even in case of exception */
            TRY {
                dissect_rtp_data( tvb, pinfo, tree, rtp_tree, offset,
                          tvb_captured_length_remaining( tvb, offset ),
                          tvb_reported_length_remaining( tvb, offset ),
                          payload_type, rtp_info);
            } CATCH_ALL {
                if (!pinfo->flags.in_error_pkt)
                    tap_queue_packet(rtp_tap, pinfo, rtp_info);
                RETHROW;
            }
            ENDTRY;
        }
    }
    if (!pinfo->flags.in_error_pkt)
        tap_queue_packet(rtp_tap, pinfo, rtp_info);

    return offset;
}

int
dissect_rtp_shim_header(tvbuff_t *tvb, int start, packet_info *pinfo _U_, proto_tree *tree, struct _rtp_info *rtp_info)
{
    proto_item *rtp_ti = NULL;
    proto_tree *rtp_tree = NULL;
    proto_item *ti;
    uint8_t     octet1, octet2;
    unsigned int version;
    bool        padding_set;
    bool        extension_set;
    unsigned int csrc_count;
    bool        marker_set;
    unsigned int payload_type;
    unsigned int i;
    int         offset = start;
    uint16_t    seq_num;
    uint32_t    timestamp;
    uint32_t    sync_src;
    const char *pt = NULL;
    static int * const octet1_fields[] = {
        &hf_rtp_version,
        &hf_rtp_padding,
        &hf_rtp_extension,
        &hf_rtp_csrc_count,
        NULL
    };

    /* Get the fields in the first octet */
    octet1 = tvb_get_uint8( tvb, offset );
    version = RTP_VERSION( octet1 );

    /* fill in the rtp_info structure */
    if (rtp_info) rtp_info->info_version = version;
    if (version != 2) {
        /*
         * Unknown or unsupported version.
         */
        if ( tree ) {
            ti = proto_tree_add_item( tree, proto_rtp, tvb, offset, 1, ENC_NA );
            rtp_tree = proto_item_add_subtree( ti, ett_rtp );

            proto_tree_add_uint( rtp_tree, hf_rtp_version, tvb,
                offset, 1, octet1);
        }
        return offset;
    }

    padding_set = RTP_PADDING( octet1 );
    extension_set = RTP_EXTENSION( octet1 );
    csrc_count = RTP_CSRC_COUNT( octet1 );

    /* Get the fields in the second octet */
    octet2 = tvb_get_uint8( tvb, offset + 1 );
    marker_set = RTP_MARKER( octet2 );
    payload_type = RTP_PAYLOAD_TYPE( octet2 );

    /* Get the subsequent fields */
    seq_num = tvb_get_ntohs( tvb, offset + 2 );
    timestamp = tvb_get_ntohl( tvb, offset + 4 );
    sync_src = tvb_get_ntohl( tvb, offset + 8 );

    /* fill in the rtp_info structure */
    if (rtp_info) {
        rtp_info->info_padding_set = padding_set;
        rtp_info->info_marker_set = marker_set;
        rtp_info->info_media_types = 0;
        rtp_info->info_payload_type = payload_type;
        rtp_info->info_seq_num = seq_num;
        rtp_info->info_timestamp = timestamp;
        rtp_info->info_sync_src = sync_src;
        rtp_info->info_data_len = 0;
        rtp_info->info_all_data_present = false;
        rtp_info->info_payload_offset = 0;
        rtp_info->info_payload_len = 0;
        rtp_info->info_is_srtp = false;
        rtp_info->info_setup_frame_num = 0;
        rtp_info->info_data = NULL;
        rtp_info->info_payload_type_str = NULL;
        rtp_info->info_payload_rate = 0;
        rtp_info->info_payload_fmtp_map = NULL;
        rtp_info->info_is_ed137 = false;
        rtp_info->info_ed137_info = NULL;
    }

    if ( tree ) {
        /* Create RTP protocol tree */
        rtp_ti = proto_tree_add_item(tree, proto_rtp, tvb, offset, 0, ENC_NA );
        rtp_tree = proto_item_add_subtree(rtp_ti, ett_rtp );

        proto_tree_add_bitmask_list(rtp_tree, tvb, offset, 1, octet1_fields, ENC_NA);
        offset++;

        proto_tree_add_boolean( rtp_tree, hf_rtp_marker, tvb, offset,
            1, octet2 );

        pt = val_to_str_ext(payload_type, &rtp_payload_type_vals_ext, "Unknown (%u)");

        proto_tree_add_uint_format( rtp_tree, hf_rtp_payload_type, tvb,
            offset, 1, octet2, "Payload type: %s (%u)", pt, payload_type);

        offset++;

        /* Sequence number 16 bits (2 octets) */
        proto_tree_add_uint( rtp_tree, hf_rtp_seq_nr, tvb, offset, 2, seq_num );
        offset += 2;

        /* Timestamp 32 bits (4 octets) */
        proto_tree_add_uint( rtp_tree, hf_rtp_timestamp, tvb, offset, 4, timestamp );
        offset += 4;

        /* Synchronization source identifier 32 bits (4 octets) */
        proto_tree_add_uint( rtp_tree, hf_rtp_ssrc, tvb, offset, 4, sync_src );
        offset += 4;
    } else {
        offset += 12;
    }
    /* CSRC list*/
    if ( csrc_count > 0 ) {
        proto_tree *rtp_csrc_tree;
        uint32_t csrc_item;
        ti = proto_tree_add_item(rtp_tree, hf_rtp_csrc_items, tvb, offset,
                                     csrc_count * 4, ENC_NA);
        proto_item_append_text(ti, " (%u items)", csrc_count);
        rtp_csrc_tree = proto_item_add_subtree( ti, ett_csrc_list );

        for (i = 0; i < csrc_count; i++ ) {
            csrc_item = tvb_get_ntohl( tvb, offset );
            proto_tree_add_uint_format( rtp_csrc_tree,
                hf_rtp_csrc_item, tvb, offset, 4,
                csrc_item,
                "CSRC item %d: 0x%X",
                i, csrc_item );
            offset += 4;
        }
    }

    /* Optional RTP header extension */
    if ( extension_set ) {
        unsigned int hdr_extension_len;
        unsigned int hdr_extension_id;

        /* Defined by profile field is 16 bits (2 octets) */
        hdr_extension_id = tvb_get_ntohs( tvb, offset );
        proto_tree_add_uint( rtp_tree, hf_rtp_prof_define, tvb, offset, 2, hdr_extension_id );
        offset += 2;

        hdr_extension_len = tvb_get_ntohs( tvb, offset );
        proto_tree_add_uint( rtp_tree, hf_rtp_length, tvb, offset, 2, hdr_extension_len);
        offset += 2;
        if ( hdr_extension_len > 0 ) {
            proto_tree *rtp_hext_tree = NULL;

            ti = proto_tree_add_item(rtp_tree, hf_rtp_hdr_exts, tvb, offset, hdr_extension_len * 4, ENC_NA);
            rtp_hext_tree = proto_item_add_subtree( ti, ett_hdr_ext );

            for ( i = 0; i < hdr_extension_len; i++ ) {
                proto_tree_add_item( rtp_hext_tree, hf_rtp_hdr_ext, tvb, offset, 4, ENC_BIG_ENDIAN );
                offset += 4;
            }
        }
    }

    proto_item_set_len(rtp_ti, offset - start);

    return (offset - start);
}

/* calculate the extended sequence number - top 16 bits of the previous sequence number,
 * plus our own; then correct for wrapping */
static uint32_t
calculate_extended_seqno(uint32_t previous_seqno, uint16_t raw_seqno)
{
    uint32_t seqno = (previous_seqno & 0xffff0000) | raw_seqno;
    if (seqno + 0x8000 < previous_seqno) {
        seqno += 0x10000;
    } else if (previous_seqno + 0x8000 < seqno) {
        /* we got an out-of-order packet which happened to go backwards over the
         * wrap boundary */
        seqno -= 0x10000;
    }
    return seqno;
}

/* calculate the extended sequence number - top 16 bits of the previous sequence number,
 * plus our own; then correct for wrapping */
static uint64_t
calculate_extended_timestamp(uint64_t previous_timestamp, uint32_t raw_timestamp)
{
    uint64_t timestamp = (previous_timestamp & 0xffffffff00000000) | raw_timestamp;
    if (timestamp + 0x80000000 < previous_timestamp) {
        timestamp += 0x100000000;
    } else if (previous_timestamp + 0x80000000 < timestamp) {
        /* we got an out-of-order packet which happened to go backwards over the
         * wrap boundary */
        timestamp -= 0x100000000;
    }
    return timestamp;
}

/* Look for conversation info */
static struct _rtp_packet_info *
get_rtp_packet_info(packet_info *pinfo, struct _rtp_info *rtp_info)
{
    /* Conversation and current data */
    struct _rtp_packet_info *p_packet_data;

    /* Use existing packet info if available */
    p_packet_data = (struct _rtp_packet_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_rtp, RTP_CONVERSATION_PROTO_DATA);

    if (!p_packet_data)
    {
        conversation_t *p_conv;

        /* First time, get info from conversation */
        p_conv = find_conversation(pinfo->num, &pinfo->net_dst, &pinfo->net_src,
                                   conversation_pt_to_conversation_type(pinfo->ptype),
                                   pinfo->destport, pinfo->srcport, NO_ADDR_B);
        if (!p_conv) {
            /* Create a conversation in case none exists (decode as is used for marking the packet as RTP) */
            p_conv = conversation_new(pinfo->num, &pinfo->net_dst, &pinfo->net_src,
                conversation_pt_to_conversation_type(pinfo->ptype),
                pinfo->destport, pinfo->srcport, NO_ADDR2);
        }

        /* Create space for packet info */
        struct _rtp_conversation_info *p_conv_data;
        p_conv_data = (struct _rtp_conversation_info *)conversation_get_proto_data(p_conv, proto_rtp);

        if (!p_conv_data) {
            /* Create conversation data. If RTP was set up by an SDP or by
             * the heuristic dissector, conversation data should already
             * have been created. Therefore, we should only reach this
             * case if Decode As is being used (See Issue #18829).
             */
            p_conv_data = wmem_new0(wmem_file_scope(), struct _rtp_conversation_info);
            p_conv_data->ssrc_number_space = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
            p_conv_data->rtp_conv_info = wmem_new(wmem_file_scope(), rtp_private_conv_info);
            p_conv_data->rtp_conv_info->multisegment_pdus = wmem_tree_new(wmem_file_scope());
            (void)g_strlcpy(p_conv_data->method, "DECODE AS", MAX_RTP_SETUP_METHOD_SIZE + 1);
            p_conv_data->frame_number = pinfo->num;
            p_conv_data->media_types = 0;
            p_conv_data->srtp_info = NULL;
            p_conv_data->bta2dp_info = NULL;
            p_conv_data->btvdp_info = NULL;
            conversation_add_proto_data(p_conv, proto_rtp, p_conv_data);
        }

        uint32_t seqno;
        uint64_t timestamp;

        /* Save this conversation info into packet info */
        /* This is file scoped because we only do this on the first pass.
         * On nonsequential passes, the conversation data has the values
         * from the last dissected frame, which is not necessarily the
         * immediately previous frame.
         */
        p_packet_data = wmem_new(wmem_file_scope(), struct _rtp_packet_info);
        (void)g_strlcpy(p_packet_data->method, p_conv_data->method, MAX_RTP_SETUP_METHOD_SIZE + 1);
        p_packet_data->frame_number = p_conv_data->frame_number;
        p_packet_data->media_types = p_conv_data->media_types;
        /* do not increment ref count for the rtp_dyn_payload */
        p_packet_data->rtp_dyn_payload = p_conv_data->rtp_dyn_payload;
        p_packet_data->rtp_conv_info = p_conv_data->rtp_conv_info;
        p_packet_data->srtp_info = p_conv_data->srtp_info;
        p_packet_data->rtp_sdp_setup_info_list = p_conv_data->rtp_sdp_setup_info_list;
        p_packet_data->bta2dp_info = p_conv_data->bta2dp_info;
        p_packet_data->btvdp_info = p_conv_data->btvdp_info;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_rtp, RTP_CONVERSATION_PROTO_DATA, p_packet_data);

        rtp_number_space* number_space = wmem_map_lookup(p_conv_data->ssrc_number_space, GUINT_TO_POINTER(rtp_info->info_sync_src));
        if (number_space == NULL) {
            /* Start the extended numbers up one cycle, to cope gracefully
                with the first few packets being out of order. */
            number_space = wmem_new0(wmem_file_scope(), rtp_number_space);
            number_space->extended_seqno = 0x10000;
            number_space->extended_timestamp = 0x100000000;
            wmem_map_insert(p_conv_data->ssrc_number_space, GUINT_TO_POINTER(rtp_info->info_sync_src), number_space);
        }
        /* calculate extended sequence number */
        seqno = calculate_extended_seqno(number_space->extended_seqno,
            rtp_info->info_seq_num);

        p_packet_data->extended_seqno = seqno;
        number_space->extended_seqno = seqno;

        /* calculate extended timestamp */
        timestamp = calculate_extended_timestamp(number_space->extended_timestamp,
            rtp_info->info_timestamp);

        p_packet_data->extended_timestamp = timestamp;
        number_space->extended_timestamp = timestamp;
    }
    rtp_info->info_setup_frame_num = p_packet_data->frame_number;
    rtp_info->info_media_types = p_packet_data->media_types;
    rtp_info->info_extended_seq_num = p_packet_data->extended_seqno;
    rtp_info->info_extended_timestamp = p_packet_data->extended_timestamp;
    return p_packet_data;
}


/* Display setup info */
static void
show_setup_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Conversation and current data */
    struct _rtp_packet_info *p_packet_data;
    proto_tree *rtp_setup_tree;
    proto_item *ti;

    /* Use existing packet info if available */
    p_packet_data = (struct _rtp_packet_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_rtp, RTP_CONVERSATION_PROTO_DATA);

    if (!p_packet_data) return;

    /* Create setup info subtree with summary info. */
    ti =  proto_tree_add_string_format(tree, hf_rtp_setup, tvb, 0, 0,
                       "", "Stream setup by %s (frame %u)",
                       p_packet_data->method,
                       p_packet_data->frame_number);
        proto_item_set_generated(ti);
        rtp_setup_tree = proto_item_add_subtree(ti, ett_rtp_setup);
        if (rtp_setup_tree)
        {
            /* Add details into subtree */
            proto_item* item = proto_tree_add_uint(rtp_setup_tree, hf_rtp_setup_frame,
                tvb, 0, 0, p_packet_data->frame_number);
            proto_item_set_generated(item);
            item = proto_tree_add_string(rtp_setup_tree, hf_rtp_setup_method,
                tvb, 0, 0, p_packet_data->method);
            proto_item_set_generated(item);

            if (p_packet_data->rtp_sdp_setup_info_list){
                unsigned i;
                sdp_setup_info_t *stored_setup_info;
                for (i = 0; i < wmem_array_get_count(p_packet_data->rtp_sdp_setup_info_list); i++) {
                    stored_setup_info = (sdp_setup_info_t *)wmem_array_index(p_packet_data->rtp_sdp_setup_info_list, i);
                    if (stored_setup_info->hf_id) {
                        if (stored_setup_info->hf_type == SDP_TRACE_ID_HF_TYPE_STR) {
                            item = proto_tree_add_string(rtp_setup_tree, stored_setup_info->hf_id, tvb, 0, 0, stored_setup_info->trace_id.str);
                            proto_item_set_generated(item);
                            if (stored_setup_info->add_hidden == true) {
                                proto_item_set_hidden(item);
                            }
                        } else if (stored_setup_info->hf_type == SDP_TRACE_ID_HF_TYPE_GUINT32) {
                            item = proto_tree_add_uint(rtp_setup_tree, stored_setup_info->hf_id, tvb, 0, 0, stored_setup_info->trace_id.num);
                            proto_item_set_generated(item);
                            if (stored_setup_info->add_hidden == true) {
                                proto_item_set_hidden(item);
                            }
                        }
                    }
                }
            }
        }
}

/* Dissect PacketCable CCC header */

static int
dissect_pkt_ccc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{

    if ( tree ) {
        proto_item *ti;
        proto_tree *pkt_ccc_tree;

        ti = proto_tree_add_item(tree, proto_pkt_ccc, tvb, 0, 12, ENC_NA);
        pkt_ccc_tree = proto_item_add_subtree(ti, ett_pkt_ccc);

        proto_tree_add_item(pkt_ccc_tree, hf_pkt_ccc_id, tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(pkt_ccc_tree, hf_pkt_ccc_ts, tvb, 4, 8,
                    ENC_TIME_NTP|ENC_BIG_ENDIAN);
    }

    return dissect_rtp(tvb, pinfo, tree, data);
}


/* Register PacketCable CCC */

void
proto_register_pkt_ccc(void)
{
    static hf_register_info hf[] =
    {
        {
            &hf_pkt_ccc_id,
            {
                "PacketCable CCC Identifier",
                "pkt_ccc.ccc_id",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_pkt_ccc_ts,
            {
                "PacketCable CCC Timestamp",
                "pkt_ccc.ts",
                FT_ABSOLUTE_TIME,
                ABSOLUTE_TIME_UTC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },

    };

    static int *ett[] =
    {
        &ett_pkt_ccc,
    };

    proto_pkt_ccc = proto_register_protocol("PacketCable Call Content Connection", "PKT CCC", "pkt_ccc");
    proto_register_field_array(proto_pkt_ccc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("pkt_ccc", dissect_pkt_ccc, proto_pkt_ccc);
}

void
proto_reg_handoff_pkt_ccc(void)
{
    /*
     * Register this dissector as one that can be selected by a
     * UDP port number.
     */
    dissector_handle_t pkt_ccc_handle;

    pkt_ccc_handle = find_dissector("pkt_ccc");
    dissector_add_for_decode_as_with_preference("udp.port", pkt_ccc_handle);
}

/* Register RTP */

void
proto_register_rtp(void)
{
    static hf_register_info hf[] =
    {
        {
            &hf_rtp_version,
            {
                "Version",
                "rtp.version",
                FT_UINT8,
                BASE_DEC,
                VALS(rtp_version_vals),
                0xC0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_padding,
            {
                "Padding",
                "rtp.padding",
                FT_BOOLEAN,
                8,
                NULL,
                0x20,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_extension,
            {
                "Extension",
                "rtp.ext",
                FT_BOOLEAN,
                8,
                NULL,
                0x10,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_csrc_count,
            {
                "Contributing source identifiers count",
                "rtp.cc",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0F,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_marker,
            {
                "Marker",
                "rtp.marker",
                FT_BOOLEAN,
                8,
                NULL,
                0x80,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_payload_type,
            {
                "Payload type",
                "rtp.p_type",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x7F,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_seq_nr,
            {
                "Sequence number",
                "rtp.seq",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_ext_seq_nr,
            {
                "Extended sequence number",
                "rtp.extseq",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_timestamp,
            {
                "Timestamp",
                "rtp.timestamp",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_ext_timestamp,
            {
                "Extended timestamp",
                "rtp.timestamp_ext",
                FT_UINT64,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_ssrc,
            {
                "Synchronization Source identifier",
                "rtp.ssrc",
                FT_UINT32,
                BASE_HEX_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_prof_define,
            {
                "Defined by profile",
                "rtp.ext.profile",
                FT_UINT16,
                BASE_HEX_DEC | BASE_RANGE_STRING,
                RVALS(rtp_ext_profile_rvals),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_length,
            {
                "Extension length",
                "rtp.ext.len",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_csrc_items,
            {
                "Contributing Source identifiers",
                "rtp.csrc.items",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_csrc_item,
            {
                "CSRC item",
                "rtp.csrc.item",
                FT_UINT32,
                BASE_HEX_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_hdr_exts,
            {
                "Header extensions",
                "rtp.hdr_exts",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
/* Other RTP structures */
        {
            &hf_rtp_hdr_ext,
            {
                "Header extension",
                "rtp.hdr_ext",
                FT_UINT32,
                BASE_HEX_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_data,
            {
                "Payload",
                "rtp.payload",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_padding_data,
            {
                "Padding data",
                "rtp.padding.data",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_padding_count,
            {
                "Padding count",
                "rtp.padding.count",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_setup,
            {
                "Stream setup",
                "rtp.setup",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                "Stream setup, method and frame number", HFILL
            }
        },
        {
            &hf_rtp_setup_frame,
            {
                "Setup frame",
                "rtp.setup-frame",
                FT_FRAMENUM,
                BASE_NONE,
                NULL,
                0x0,
                "Frame that set up this stream", HFILL
            }
        },
        {
            &hf_rtp_setup_method,
            {
                "Setup Method",
                "rtp.setup-method",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                "Method used to set up this stream", HFILL
            }
        },
        {
            &hf_rtp_rfc2198_follow,
            {
                "Follow",
                "rtp.follow",
                FT_BOOLEAN,
                8,
                TFS(&tfs_set_notset),
                0x80,
                "Next header follows", HFILL
            }
        },
        {
            &hf_rtp_rfc2198_tm_off,
            {
                "Timestamp offset",
                "rtp.timestamp-offset",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0xFFFC,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_rfc2198_bl_len,
            {
                "Block length",
                "rtp.block-length",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x03FF,
                NULL, HFILL
            }
        },
        {
            &hf_rtp_ext_rfc5285_id,
            {
                "Identifier",
                "rtp.ext.rfc5285.id",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "RFC 5285 Header Extension Identifier",
                HFILL
            }
        },
        {
            &hf_rtp_ext_rfc5285_length,
            {
                "Length",
                "rtp.ext.rfc5285.len",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "RFC 5285 Header Extension length",
                HFILL
            }
        },
        {
            &hf_rtp_ext_rfc5285_appbits,
            {
                "Application Bits",
                "rtp.ext.rfc5285.appbits",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "RFC 5285 2-bytes header application bits",
                HFILL
            }
        },
        {
            &hf_rtp_ext_rfc5285_data,
            {
                "Extension Data",
                "rtp.ext.rfc5285.data",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0x0,
                "RFC 5285 Extension Data",
                HFILL
            }
        },
        {
            &hf_rfc4571_header_len,
            {
                "RFC 4571 packet len",
                "rtp.rfc4571.len",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },

        /* reassembly stuff */
        {&hf_rtp_fragments,
         {"RTP Fragments", "rtp.fragments", FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL }
        },

        {&hf_rtp_fragment,
         {"RTP Fragment data", "rtp.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
          NULL, HFILL }
        },

        {&hf_rtp_fragment_overlap,
         {"Fragment overlap", "rtp.fragment.overlap", FT_BOOLEAN, BASE_NONE,
          NULL, 0x0, "Fragment overlaps with other fragments", HFILL }
        },

        {&hf_rtp_fragment_overlap_conflict,
         {"Conflicting data in fragment overlap", "rtp.fragment.overlap.conflict",
          FT_BOOLEAN, BASE_NONE, NULL, 0x0,
          "Overlapping fragments contained conflicting data", HFILL }
        },

        {&hf_rtp_fragment_multiple_tails,
         {"Multiple tail fragments found", "rtp.fragment.multipletails",
          FT_BOOLEAN, BASE_NONE, NULL, 0x0,
          "Several tails were found when defragmenting the packet", HFILL }
        },

        {&hf_rtp_fragment_too_long_fragment,
         {"Fragment too long", "rtp.fragment.toolongfragment",
          FT_BOOLEAN, BASE_NONE, NULL, 0x0,
          "Fragment contained data past end of packet", HFILL }
        },

        {&hf_rtp_fragment_error,
         {"Defragmentation error", "rtp.fragment.error",
          FT_FRAMENUM, BASE_NONE, NULL, 0x0,
          "Defragmentation error due to illegal fragments", HFILL }
        },

        {&hf_rtp_fragment_count,
         {"Fragment count", "rtp.fragment.count",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
        },

        {&hf_rtp_reassembled_in,
         {"RTP fragment, reassembled in frame", "rtp.reassembled_in",
          FT_FRAMENUM, BASE_NONE, NULL, 0x0,
          "This RTP packet is reassembled in this frame", HFILL }
        },
        {&hf_rtp_reassembled_length,
         {"Reassembled RTP length", "rtp.reassembled.length",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "The total length of the reassembled payload", HFILL }
        },
        {&hf_srtp_encrypted_payload,
         {"SRTP Encrypted Payload", "srtp.enc_payload",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }
        },
#if 0
        {&hf_srtp_null_encrypted_payload,
         {"SRTP Payload with NULL encryption", "srtp.null_enc_payload",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }
        },
#endif
        {&hf_srtp_mki,
         {"SRTP MKI", "srtp.mki",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          "SRTP Master Key Index", HFILL }
        },
        {&hf_srtp_auth_tag,
         {"SRTP Auth Tag", "srtp.auth_tag",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          "SRTP Authentication Tag", HFILL }
        }

    };

    static int *ett[] =
    {
        &ett_rtp,
        &ett_csrc_list,
        &ett_hdr_ext,
        &ett_hdr_ext_rfc5285,
        &ett_rtp_setup,
        &ett_rtp_rfc2198,
        &ett_rtp_rfc2198_hdr,
        &ett_rtp_fragment,
        &ett_rtp_fragments
    };

    static ei_register_info ei[] = {
        { &ei_rtp_fragment_unfinished, { "rtp.fragment_unfinished", PI_REASSEMBLE, PI_CHAT, "RTP fragment, unfinished", EXPFILL }},
        { &ei_rtp_padding_missing, { "rtp.padding_missing", PI_UNDECODED, PI_WARN, "Frame has padding, but not all the frame data was captured", EXPFILL }},
        { &ei_rtp_padding_bogus, { "rtp.padding_bogus", PI_PROTOCOL, PI_WARN, "Frame has padding length value greater than payload length", EXPFILL }},
    };

    /* Decode As handling */
    static build_valid_func rtp_da_build_value[1] = {rtp_value};
    static decode_as_value_t rtp_da_values = {rtp_prompt, 1, rtp_da_build_value};
    static decode_as_t rtp_da = {"rtp", "rtp.pt", 1, 0, &rtp_da_values, NULL, NULL,
                                decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    module_t *rtp_module;
    expert_module_t *expert_rtp;

    proto_rtp = proto_register_protocol("Real-Time Transport Protocol", "RTP", "rtp");
    proto_rtp_rfc2198 = proto_register_protocol_in_name_only("RTP Payload for Redundant Audio Data (RFC 2198)",
                                    "RAD (RFC2198)", "rtp_rfc2198", proto_rtp, FT_PROTOCOL);

    proto_register_field_array(proto_rtp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_rtp = expert_register_protocol(proto_rtp);
    expert_register_field_array(expert_rtp, ei, array_length(ei));

    rtp_handle = register_dissector("rtp", dissect_rtp, proto_rtp);
    rtp_rfc2198_handle = register_dissector("rtp.rfc2198", dissect_rtp_rfc2198, proto_rtp_rfc2198);
    rtp_rfc4571_handle = register_dissector("rtp.rfc4571", dissect_rtp_rfc4571, proto_rtp);

    rtp_tap = register_tap("rtp");

    rtp_pt_dissector_table = register_dissector_table("rtp.pt",
                                    "RTP payload type", proto_rtp, FT_UINT8, BASE_DEC);
    rtp_dyn_pt_dissector_table = register_dissector_table("rtp_dyn_payload_type",
                                    "Dynamic RTP payload type", proto_rtp, FT_STRING, STRING_CASE_INSENSITIVE);


    rtp_hdr_ext_dissector_table = register_dissector_table("rtp.hdr_ext",
                                    "RTP header extension", proto_rtp, FT_UINT32, BASE_HEX);
    rtp_hdr_ext_rfc5285_dissector_table = register_dissector_table("rtp.ext.rfc5285.id",
                                    "RTP Generic header extension (RFC 5285)", proto_rtp, FT_UINT8, BASE_DEC);

    rtp_module = prefs_register_protocol(proto_rtp, NULL);

    prefs_register_bool_preference(rtp_module, "show_setup_info",
                                    "Show stream setup information",
                                    "Where available, show which protocol and frame caused "
                                    "this RTP stream to be created",
                                    &global_rtp_show_setup_info);

    prefs_register_obsolete_preference(rtp_module, "heuristic_rtp");

    prefs_register_bool_preference(rtp_module, "desegment_rtp_streams",
                                    "Allow subdissector to reassemble RTP streams",
                                    "Whether subdissector can request RTP streams to be reassembled",
                                    &desegment_rtp);

    prefs_register_enum_preference(rtp_module, "version0_type",
                                    "Treat RTP version 0 packets as",
                                    "If an RTP version 0 packet is encountered, it can be treated as "
                                    "an invalid or ZRTP packet, a CLASSIC-STUN packet, or a T.38 packet",
                                    &global_rtp_version0_type,
                                    rtp_version0_types, false);
    prefs_register_obsolete_preference(rtp_module, "rfc2198_payload_type");

    prefs_register_bool_preference(rtp_module, "rfc2198_deencapsulate",
                                    "De-encapsulate RFC 2198 primary encoding",
                                    "De-encapsulate the primary encoding from "
                                    "the RAD header for RTP analysis and "
                                    "playback",
                                    &rfc2198_deencapsulate);

    reassembly_table_register(&rtp_reassembly_table,
                  &addresses_reassembly_table_functions);

    register_init_routine(rtp_dyn_payloads_init);
    register_decode_as(&rtp_da);
}

void
proto_reg_handoff_rtp(void)
{
    dissector_add_for_decode_as("udp.port", rtp_handle);
    dissector_add_for_decode_as("tcp.port", rtp_rfc4571_handle);
    dissector_add_string("rtp_dyn_payload_type", "red", rtp_rfc2198_handle);
    heur_dissector_add( "udp", dissect_rtp_heur,  "RTP over UDP", "rtp_udp", proto_rtp, HEURISTIC_DISABLE);
    heur_dissector_add("stun", dissect_rtp_heur, "RTP over TURN", "rtp_stun", proto_rtp, HEURISTIC_DISABLE);
    heur_dissector_add("classicstun", dissect_rtp_heur, "RTP over CLASSICSTUN", "rtp_classicstun", proto_rtp, HEURISTIC_DISABLE);
    heur_dissector_add("rtsp", dissect_rtp_heur, "RTP over RTSP", "rtp_rtsp", proto_rtp, HEURISTIC_DISABLE);

    dissector_add_for_decode_as("flip.payload", rtp_handle );


    rtcp_handle = find_dissector_add_dependency("rtcp", proto_rtp);
    stun_handle = find_dissector_add_dependency("stun-udp", proto_rtp);
    classicstun_handle = find_dissector_add_dependency("classicstun", proto_rtp);
    t38_handle = find_dissector_add_dependency("t38_udp", proto_rtp);
    zrtp_handle = find_dissector_add_dependency("zrtp", proto_rtp);
    dtls_handle = find_dissector_add_dependency("dtls", proto_rtp);

    sprt_handle = find_dissector_add_dependency("sprt", proto_rtp);
    v150fw_handle = find_dissector("v150fw");

    bta2dp_content_protection_header_scms_t = find_dissector_add_dependency("bta2dp_content_protection_header_scms_t", proto_rtp);
    btvdp_content_protection_header_scms_t = find_dissector_add_dependency("btvdp_content_protection_header_scms_t", proto_rtp);
    bta2dp_handle = find_dissector_add_dependency("bta2dp", proto_rtp);
    btvdp_handle = find_dissector_add_dependency("btvdp", proto_rtp);
    sbc_handle = find_dissector_add_dependency("sbc", proto_rtp);

    dissector_add_string("rtp_dyn_payload_type", "v150fw", v150fw_handle);
    dissector_add_for_decode_as("rtp.pt", v150fw_handle);

    dissector_add_for_decode_as("btl2cap.cid", rtp_handle);

    dissector_add_uint_range_with_preference("rtp.pt", RFC2198_DEFAULT_PT_RANGE, rtp_rfc2198_handle);
    proto_sdp = proto_get_id_by_filter_name("sdp");
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
