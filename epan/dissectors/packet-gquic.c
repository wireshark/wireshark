/* packet-gquic.c
 * Routines for (Google) Quick UDP Internet Connections dissection
 * Copyright 2013, Alexis La Goutte <alexis.lagoutte at gmail dot com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
QUIC Wire Layout Specification : https://docs.google.com/document/d/1WJvyZflAO2pq77yOLbp9NsGjC1CHetAXV8I0fQe-B_U/

QUIC Crypto : https://docs.google.com/document/d/1g5nIXAIkN_Y-7XJW5K45IblHd_L2f5LTaDUDwvZ5L6g/

QUIC source code in Chromium : https://code.google.com/p/chromium/codesearch#chromium/src/net/quic/quic_utils.h&sq=package:chromium

*/
#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/conversation.h>
#include <epan/tfs.h>
#include "packet-http2.h"
#include "packet-quic.h"
#include <wsutil/strtoi.h>

void proto_register_gquic(void);
void proto_reg_handoff_gquic(void);

static dissector_handle_t gquic_handle;
static dissector_handle_t tls13_handshake_handle;
static dissector_handle_t quic_handle;

static int proto_gquic;
static int hf_gquic_header_form;
static int hf_gquic_fixed_bit;
static int hf_gquic_long_packet_type;
static int hf_gquic_long_reserved;
static int hf_gquic_packet_number_length;
static int hf_gquic_dcil;
static int hf_gquic_scil;
static int hf_gquic_puflags;
static int hf_gquic_puflags_vrsn;
static int hf_gquic_puflags_rst;
static int hf_gquic_puflags_dnonce;
static int hf_gquic_puflags_cid;
static int hf_gquic_puflags_cid_old;
static int hf_gquic_puflags_pkn;
static int hf_gquic_puflags_mpth;
static int hf_gquic_puflags_rsv;
static int hf_gquic_cid;
static int hf_gquic_version;
static int hf_gquic_diversification_nonce;
static int hf_gquic_packet_number;
static int hf_gquic_prflags;
static int hf_gquic_prflags_entropy;
static int hf_gquic_prflags_fecg;
static int hf_gquic_prflags_fec;
static int hf_gquic_prflags_rsv;
static int hf_gquic_message_authentication_hash;
static int hf_gquic_frame;
static int hf_gquic_frame_type;
static int hf_gquic_frame_type_padding_length;
static int hf_gquic_frame_type_padding;
static int hf_gquic_frame_type_rsts_stream_id;
static int hf_gquic_frame_type_rsts_byte_offset;
static int hf_gquic_frame_type_rsts_error_code;
static int hf_gquic_frame_type_cc_error_code;
static int hf_gquic_frame_type_cc_reason_phrase_length;
static int hf_gquic_frame_type_cc_reason_phrase;
static int hf_gquic_frame_type_goaway_error_code;
static int hf_gquic_frame_type_goaway_last_good_stream_id;
static int hf_gquic_frame_type_goaway_reason_phrase_length;
static int hf_gquic_frame_type_goaway_reason_phrase;
static int hf_gquic_frame_type_wu_stream_id;
static int hf_gquic_frame_type_wu_byte_offset;
static int hf_gquic_frame_type_blocked_stream_id;
static int hf_gquic_frame_type_sw_send_entropy;
static int hf_gquic_frame_type_sw_least_unacked_delta;
static int hf_gquic_crypto_offset;
static int hf_gquic_crypto_length;
static int hf_gquic_crypto_crypto_data;
static int hf_gquic_frame_type_stream;
static int hf_gquic_frame_type_stream_f;
static int hf_gquic_frame_type_stream_d;
static int hf_gquic_frame_type_stream_ooo;
static int hf_gquic_frame_type_stream_ss;
/* ACK */
static int hf_gquic_frame_type_ack;
static int hf_gquic_frame_type_ack_n;
static int hf_gquic_frame_type_ack_u;
static int hf_gquic_frame_type_ack_t;
static int hf_gquic_frame_type_ack_ll;
static int hf_gquic_frame_type_ack_mm;
/* ACK Before Q034 */
static int hf_gquic_frame_type_ack_received_entropy;
static int hf_gquic_frame_type_ack_largest_observed;
static int hf_gquic_frame_type_ack_ack_delay_time;
static int hf_gquic_frame_type_ack_num_timestamp;
static int hf_gquic_frame_type_ack_delta_largest_observed;
static int hf_gquic_frame_type_ack_first_timestamp;
static int hf_gquic_frame_type_ack_time_since_previous_timestamp;
static int hf_gquic_frame_type_ack_num_ranges;
static int hf_gquic_frame_type_ack_missing_packet;
static int hf_gquic_frame_type_ack_range_length;
static int hf_gquic_frame_type_ack_num_revived;
static int hf_gquic_frame_type_ack_revived_packet;
/* ACK After Q034 */
static int hf_gquic_frame_type_ack_largest_acked;
static int hf_gquic_frame_type_ack_largest_acked_delta_time;
static int hf_gquic_frame_type_ack_num_blocks;
static int hf_gquic_frame_type_ack_first_ack_block_length;
static int hf_gquic_frame_type_ack_gap_to_next_block;
static int hf_gquic_frame_type_ack_ack_block_length;
static int hf_gquic_frame_type_ack_delta_largest_acked;
static int hf_gquic_frame_type_ack_time_since_largest_acked;
static int hf_gquic_stream_id;
static int hf_gquic_offset;
static int hf_gquic_data_len;
static int hf_gquic_tag;
static int hf_gquic_tags;
static int hf_gquic_tag_number;
static int hf_gquic_tag_value;
static int hf_gquic_tag_type;
static int hf_gquic_tag_offset_end;
static int hf_gquic_tag_length;
static int hf_gquic_tag_sni;
static int hf_gquic_tag_pad;
static int hf_gquic_tag_ver;
static int hf_gquic_tag_ccs;
static int hf_gquic_tag_pdmd;
static int hf_gquic_tag_uaid;
static int hf_gquic_tag_stk;
static int hf_gquic_tag_sno;
static int hf_gquic_tag_prof;
static int hf_gquic_tag_scfg;
static int hf_gquic_tag_scfg_number;
static int hf_gquic_tag_rrej;
static int hf_gquic_tag_crt;
static int hf_gquic_tag_aead;
static int hf_gquic_tag_scid;
static int hf_gquic_tag_pubs;
static int hf_gquic_tag_kexs;
static int hf_gquic_tag_obit;
static int hf_gquic_tag_expy;
static int hf_gquic_tag_nonc;
static int hf_gquic_tag_mspc;
static int hf_gquic_tag_tcid;
static int hf_gquic_tag_srbf;
static int hf_gquic_tag_icsl;
static int hf_gquic_tag_scls;
static int hf_gquic_tag_copt;
static int hf_gquic_tag_ccrt;
static int hf_gquic_tag_irtt;
static int hf_gquic_tag_cfcw;
static int hf_gquic_tag_sfcw;
static int hf_gquic_tag_cetv;
static int hf_gquic_tag_xlct;
static int hf_gquic_tag_nonp;
static int hf_gquic_tag_csct;
static int hf_gquic_tag_ctim;
static int hf_gquic_tag_mids;
static int hf_gquic_tag_fhol;
static int hf_gquic_tag_sttl;
static int hf_gquic_tag_smhl;
static int hf_gquic_tag_tbkp;
static int hf_gquic_tag_mad0;
static int hf_gquic_tag_qlve;
static int hf_gquic_tag_cgst;
static int hf_gquic_tag_epid;
static int hf_gquic_tag_srst;

/* Public Reset Tags */
static int hf_gquic_tag_rnon;
static int hf_gquic_tag_rseq;
static int hf_gquic_tag_cadr_addr_type;
static int hf_gquic_tag_cadr_addr_ipv4;
static int hf_gquic_tag_cadr_addr_ipv6;
static int hf_gquic_tag_cadr_addr;
static int hf_gquic_tag_cadr_port;

static int hf_gquic_tag_unknown;

static int hf_gquic_padding;
static int hf_gquic_stream_data;
static int hf_gquic_payload;

#define QUIC_PORT_RANGE "80,443"
static bool g_gquic_debug;

static int ett_gquic;
static int ett_gquic_puflags;
static int ett_gquic_prflags;
static int ett_gquic_ft;
static int ett_gquic_ftflags;
static int ett_gquic_tag_value;

static expert_field ei_gquic_tag_undecoded;
static expert_field ei_gquic_tag_length;
static expert_field ei_gquic_tag_unknown;
static expert_field ei_gquic_version_invalid;
static expert_field ei_gquic_invalid_parameter;
static expert_field ei_gquic_length_invalid;
static expert_field ei_gquic_data_invalid;

static const value_string gquic_short_long_header_vals[] = {
    { 0, "Short Header" },
    { 1, "Long Header" },
    { 0, NULL }
};
static const value_string gquic_long_packet_type_vals[] = {
    { 0, "Initial" },
    { 2, "Handshake" },
    { 1, "0-RTT" },
    { 0, NULL }
};
static const value_string gquic_packet_number_lengths[] = {
    { 0, "1 bytes" },
    { 1, "2 bytes" },
    { 2, "3 bytes" },
    { 3, "4 bytes" },
    { 0, NULL }
};
static const value_string quic_cid_lengths[] = {
    { 0, "0 bytes" },
    { 5, "8 bytes" },
    { 0, NULL }
};

#define GQUIC_MIN_LENGTH 3
#define GQUIC_MAGIC2 0x513032
#define GQUIC_MAGIC3 0x513033
#define GQUIC_MAGIC4 0x513034

#define GQUIC_VERSION_Q046 0x51303436

/**************************************************************************/
/*                      Public Flags                                      */
/**************************************************************************/
#define PUFLAGS_VRSN    0x01
#define PUFLAGS_RST     0x02
#define PUFLAGS_DNONCE  0x04
#define PUFLAGS_CID     0x08
#define PUFLAGS_CID_OLD 0x0C
#define PUFLAGS_PKN     0x30
#define PUFLAGS_MPTH    0x40
#define PUFLAGS_RSV     0x80

static const true_false_string puflags_cid_tfs = {
    "8 Bytes",
    "0 Byte"
};

static const value_string puflags_cid_old_vals[] = {
    { 0, "0 Byte" },
    { 1, "1 Bytes" },
    { 2, "4 Bytes" },
    { 3, "8 Bytes" },
    { 0, NULL }
};

static const value_string puflags_pkn_vals[] = {
    { 0, "1 Byte" },
    { 1, "2 Bytes" },
    { 2, "4 Bytes" },
    { 3, "6 Bytes" },
    { 0, NULL }
};

/**************************************************************************/
/*                      Private Flags                                     */
/**************************************************************************/
#define PRFLAGS_ENTROPY 0x01
#define PRFLAGS_FECG    0x02
#define PRFLAGS_FEC     0x04
#define PRFLAGS_RSV     0xF8


/**************************************************************************/
/*                      Frame Type Regular                                */
/**************************************************************************/
#define FT_PADDING          0x00
#define FT_RST_STREAM       0x01
#define FT_CONNECTION_CLOSE 0x02
#define FT_GOAWAY           0x03
#define FT_WINDOW_UPDATE    0x04
#define FT_BLOCKED          0x05
#define FT_STOP_WAITING     0x06
#define FT_PING             0x07
/* CRYPTO is not a real GQUIC frame, but a QUIC one. Since some GQUIC flows
 * have this kind of frame, try handling it like all the others */
#define FT_CRYPTO           0x08

/**************************************************************************/
/*                      Frame Type Special                                */
/**************************************************************************/
#define FTFLAGS_SPECIAL     0xE0

#define FTFLAGS_STREAM      0x80
#define FTFLAGS_STREAM_F    0x40
#define FTFLAGS_STREAM_D    0x20
#define FTFLAGS_STREAM_OOO  0x1C
#define FTFLAGS_STREAM_SS   0x03

#define FTFLAGS_ACK         0x40
#define FTFLAGS_ACK_N       0x20
#define FTFLAGS_ACK_U       0x10
#define FTFLAGS_ACK_T       0x10
#define FTFLAGS_ACK_LL      0x0C
#define FTFLAGS_ACK_MM      0x03

static const range_string frame_type_vals[] = {
  { 0,0,         "PADDING" },
  { 1,1,         "RST_STREAM" },
  { 2,2,         "CONNECTION_CLOSE" },
  { 3,3,         "GOAWAY" },
  { 4,4,         "WINDOW_UPDATE" },
  { 5,5,         "BLOCKED" },
  { 6,6,         "STOP_WAITING" },
  { 7,7,         "PING" },
  { 8,8,         "CRYPTO" },
  { 9,31,        "Unknown" },
  { 32,63,       "CONGESTION_FEEDBACK (Special Frame Type)" },
  { 64,127,      "ACK (Special Frame Type)" },
  { 128,256,     "STREAM (Special Frame Type)" },
  { 0,0, NULL }
};

static const value_string len_offset_vals[] = {
    { 0, "0 Byte" },
    { 1, "2 Bytes" },
    { 2, "3 Bytes" },
    { 3, "4 Bytes" },
    { 4, "5 Bytes" },
    { 5, "6 Bytes" },
    { 6, "7 Bytes" },
    { 7, "8 Bytes" },
    { 0, NULL }
};

static const value_string len_stream_vals[] = {
    { 0, "1 Byte" },
    { 1, "2 Bytes" },
    { 2, "3 Bytes" },
    { 3, "4 Bytes" },
    { 0, NULL }
};

static const true_false_string len_data_vals = {
    "2 Bytes",
    "0 Byte"
};

static const value_string len_largest_observed_vals[] = {
    { 0, "1 Byte" },
    { 1, "2 Bytes" },
    { 2, "4 Bytes" },
    { 3, "6 Bytes" },
    { 0, NULL }
};

static const value_string len_missing_packet_vals[] = {
    { 0, "1 Byte" },
    { 1, "2 Bytes" },
    { 2, "4 Bytes" },
    { 3, "6 Bytes" },
    { 0, NULL }
};


/**************************************************************************/
/*                      Message tag                                       */
/**************************************************************************/

#define MTAG_CHLO 0x43484C4F
#define MTAG_SHLO 0x53484C4F
#define MTAG_REJ  0x52454A00
#define MTAG_PRST 0x50525354

static const value_string message_tag_vals[] = {
    { MTAG_CHLO, "Client Hello" },
    { MTAG_SHLO, "Server Hello" },
    { MTAG_REJ, "Rejection" },
    { MTAG_PRST, "Public Reset" },
    { 0, NULL }
};

/**************************************************************************/
/*                      Tag                                               */
/**************************************************************************/
/* See https://chromium.googlesource.com/chromium/src.git/+/master/net/third_party/quic/core/crypto/crypto_protocol.h */

#define TAG_PAD  0x50414400
#define TAG_SNI  0x534E4900
#define TAG_VER  0x56455200
#define TAG_CCS  0x43435300
#define TAG_UAID 0x55414944
#define TAG_PDMD 0x50444d44
#define TAG_STK  0x53544b00
#define TAG_SNO  0x534E4F00
#define TAG_PROF 0x50524F46
#define TAG_SCFG 0x53434647
#define TAG_RREJ 0x5252454A
#define TAG_CRT  0x435254FF
#define TAG_AEAD 0x41454144
#define TAG_SCID 0x53434944
#define TAG_PUBS 0x50554253
#define TAG_KEXS 0x4B455853
#define TAG_OBIT 0x4F424954
#define TAG_EXPY 0x45585059
#define TAG_NONC 0x4E4F4E43
#define TAG_MSPC 0x4D535043
#define TAG_TCID 0x54434944
#define TAG_SRBF 0x53524246
#define TAG_ICSL 0x4943534C
#define TAG_SCLS 0x53434C53
#define TAG_COPT 0x434F5054
#define TAG_CCRT 0x43435254
#define TAG_IRTT 0x49525454
#define TAG_CFCW 0x43464357
#define TAG_SFCW 0x53464357
#define TAG_CETV 0x43455456
#define TAG_XLCT 0x584C4354
#define TAG_NONP 0x4E4F4E50
#define TAG_CSCT 0x43534354
#define TAG_CTIM 0x4354494D
#define TAG_MIDS 0x4D494453
#define TAG_FHOL 0x46484F4C
#define TAG_STTL 0x5354544C
#define TAG_SMHL 0x534D484C
#define TAG_TBKP 0x54424B50
#define TAG_MAD0 0x4d414400
#define TAG_QLVE 0x514C5645
#define TAG_CGST 0x43475354
#define TAG_EPID 0x45504944
#define TAG_SRST 0x53525354

/* Public Reset Tag */
#define TAG_RNON 0x524E4F4E
#define TAG_RSEQ 0x52534551
#define TAG_CADR 0x43414452

static const value_string tag_vals[] = {
    { TAG_PAD, "Padding" },
    { TAG_SNI, "Server Name Indication" },
    { TAG_VER, "Version" },
    { TAG_CCS, "Common Certificate Sets" },
    { TAG_UAID, "Client's User Agent ID" },
    { TAG_PDMD, "Proof Demand" },
    { TAG_STK, "Source Address Token" },
    { TAG_SNO, "Server nonce" },
    { TAG_PROF, "Proof (Signature)" },
    { TAG_SCFG, "Server Config" },
    { TAG_RREJ, "Reasons for server sending" },
    { TAG_CRT, "Certificate chain" },
    { TAG_AEAD, "Authenticated encryption algorithms" },
    { TAG_SCID, "Server config ID" },
    { TAG_PUBS, "Public value" },
    { TAG_KEXS, "Key exchange algorithms" },
    { TAG_OBIT, "Server Orbit" },
    { TAG_EXPY, "Expiry" },
    { TAG_NONC, "Client Nonce" },
    { TAG_MSPC, "Max streams per connection" },
    { TAG_TCID, "Connection ID truncation" },
    { TAG_SRBF, "Socket receive buffer" },
    { TAG_ICSL, "Idle connection state" },
    { TAG_SCLS, "Silently close on timeout" },
    { TAG_COPT, "Connection options" },
    { TAG_CCRT, "Cached certificates" },
    { TAG_IRTT, "Estimated initial RTT" },
    { TAG_CFCW, "Initial session/connection" },
    { TAG_SFCW, "Initial stream flow control" },
    { TAG_CETV, "Client encrypted tag-value" },
    { TAG_XLCT, "Expected leaf certificate" },
    { TAG_NONP, "Client Proof Nonce" },
    { TAG_CSCT, "Signed cert timestamp (RFC6962) of leaf cert" },
    { TAG_CTIM, "Client Timestamp" },
    { TAG_MIDS, "Max incoming dynamic streams" },
    { TAG_FHOL, "Force Head Of Line blocking" },
    { TAG_STTL, "Server Config TTL" },
    { TAG_SMHL, "Support Max Header List (size)" },
    { TAG_TBKP, "Token Binding Key Params" },
    { TAG_MAD0, "Max Ack Delay (IETF QUIC)" },
    { TAG_QLVE, "Legacy Version Encapsulation" },
    { TAG_CGST, "Congestion Control Feedback Type" },
    { TAG_EPID, "Endpoint Identifier" },
    { TAG_SRST, "Stateless Reset Token" },

    { TAG_RNON, "Public Reset Nonce Proof" },
    { TAG_RSEQ, "Rejected Packet Number" },
    { TAG_CADR, "Client Address" },
    { 0, NULL }
};


/**************************************************************************/
/*                      AEAD Tag                                          */
/**************************************************************************/

#define AEAD_AESG  0x41455347
#define AEAD_S20P  0x53323050
#define AEAD_CC12  0x43433132

static const value_string tag_aead_vals[] = {
    { AEAD_AESG, "AES-GCM with a 12-byte tag and IV" },
    { AEAD_S20P, "Salsa20 with Poly1305" },
    { AEAD_CC12, "ChaCha12 with Poly1305" },
    { 0, NULL }
};

/**************************************************************************/
/*                      KEXS Tag                                          */
/**************************************************************************/

#define KEXS_C255  0x43323535
#define KEXS_P256  0x50323536

static const value_string tag_kexs_vals[] = {
    { KEXS_C255, "Curve25519" },
    { KEXS_P256, "P-256" },
    { 0, NULL }
};

/**************************************************************************/
/*                      Client Address Type                               */
/**************************************************************************/

static const value_string cadr_type_vals[] = {
    { 2, "IPv4" },
    { 10, "IPv6" },
    { 0, NULL }
};

/**************************************************************************/
/*                      Error Code                                        */
/**************************************************************************/
/* See https://chromium.googlesource.com/chromium/src.git/+/master/net/third_party/quic/core/quic_error_codes.h */

enum QuicErrorCode {
    QUIC_NO_ERROR = 0,
    /* Connection has reached an invalid state. */
    QUIC_INTERNAL_ERROR = 1,
    /* There were data frames after the a fin or reset. */
    QUIC_STREAM_DATA_AFTER_TERMINATION = 2,
    /* Control frame is malformed. */
    QUIC_INVALID_PACKET_HEADER = 3,
    /* Frame data is malformed. */
    QUIC_INVALID_FRAME_DATA = 4,
    /* The packet contained no payload. */
    QUIC_MISSING_PAYLOAD = 48,
    /* FEC data is malformed. */
    QUIC_INVALID_FEC_DATA = 5,
    /* STREAM frame data is malformed. */
    QUIC_INVALID_STREAM_DATA = 46,
    /* STREAM frame data overlaps with buffered data. */
    QUIC_OVERLAPPING_STREAM_DATA = 87,
    /* STREAM frame data is not encrypted. */
    QUIC_UNENCRYPTED_STREAM_DATA = 61,
    /* Attempt to send unencrypted STREAM frame. */
    QUIC_ATTEMPT_TO_SEND_UNENCRYPTED_STREAM_DATA = 88,
    /* Received a frame which is likely the result of memory corruption. */
    QUIC_MAYBE_CORRUPTED_MEMORY = 89,
    /* FEC frame data is not encrypted. */
    QUIC_UNENCRYPTED_FEC_DATA = 77,
    /* RST_STREAM frame data is malformed. */
    QUIC_INVALID_RST_STREAM_DATA = 6,
    /* CONNECTION_CLOSE frame data is malformed. */
    QUIC_INVALID_CONNECTION_CLOSE_DATA = 7,
    /* GOAWAY frame data is malformed. */
    QUIC_INVALID_GOAWAY_DATA = 8,
    /* WINDOW_UPDATE frame data is malformed. */
    QUIC_INVALID_WINDOW_UPDATE_DATA = 57,
    /* BLOCKED frame data is malformed. */
    QUIC_INVALID_BLOCKED_DATA = 58,
    /* STOP_WAITING frame data is malformed. */
    QUIC_INVALID_STOP_WAITING_DATA = 60,
    /* PATH_CLOSE frame data is malformed. */
    QUIC_INVALID_PATH_CLOSE_DATA = 78,
    /* ACK frame data is malformed. */
    QUIC_INVALID_ACK_DATA = 9,
    /* deprecated: */
    QUIC_INVALID_CONGESTION_FEEDBACK_DATA = 47,
    /* Version negotiation packet is malformed. */
    QUIC_INVALID_VERSION_NEGOTIATION_PACKET = 10,
    /* Public RST packet is malformed. */
    QUIC_INVALID_PUBLIC_RST_PACKET = 11,
    /* There was an error decrypting. */
    QUIC_DECRYPTION_FAILURE = 12,
    /* There was an error encrypting. */
    QUIC_ENCRYPTION_FAILURE = 13,
    /* The packet exceeded kMaxPacketSize. */
    QUIC_PACKET_TOO_LARGE = 14,
    /* Data was sent for a stream which did not exist. */
    QUIC_PACKET_FOR_NONEXISTENT_STREAM = 15,
    /* The peer is going away.   May be a client or server. */
    QUIC_PEER_GOING_AWAY = 16,
    /* A stream ID was invalid. */
    QUIC_INVALID_STREAM_ID = 17,
    /* A priority was invalid. */
    QUIC_INVALID_PRIORITY = 49,
    /* Too many streams already open. */
    QUIC_TOO_MANY_OPEN_STREAMS = 18,
    /* The peer created too many available streams. */
    QUIC_TOO_MANY_AVAILABLE_STREAMS = 76,
    /* The peer must send a FIN/RST for each stream, and has not been doing so. */
    QUIC_TOO_MANY_UNFINISHED_STREAMS = 66,
    /* Received public reset for this connection. */
    QUIC_PUBLIC_RESET = 19,
    /* Invalid protocol version. */
    QUIC_INVALID_VERSION = 20,
    /* deprecated: */
    QUIC_STREAM_RST_BEFORE_HEADERS_DECOMPRESSED = 21,
    /* The Header ID for a stream was too far from the previous. */
    QUIC_INVALID_HEADER_ID = 22,
    /* Negotiable parameter received during handshake had invalid value. */
    QUIC_INVALID_NEGOTIATED_VALUE = 23,
    /* There was an error decompressing data. */
    QUIC_DECOMPRESSION_FAILURE = 24,
    /* We hit our prenegotiated (or default) timeout */
    QUIC_CONNECTION_TIMED_OUT = 25,
    /* We hit our overall connection timeout */
    QUIC_CONNECTION_OVERALL_TIMED_OUT = 67,
    /* There was an error encountered migrating addresses */
    QUIC_ERROR_MIGRATING_ADDRESS = 26,
    /* There was an error encountered migrating port only. */
    QUIC_ERROR_MIGRATING_PORT = 86,
    /* There was an error while writing to the socket. */
    QUIC_PACKET_WRITE_ERROR = 27,
    /* There was an error while reading from the socket. */
    QUIC_PACKET_READ_ERROR = 51,
    /* We received a STREAM_FRAME with no data and no fin flag set. */
    QUIC_INVALID_STREAM_FRAME = 50,
    /* We received invalid data on the headers stream. */
    QUIC_INVALID_HEADERS_STREAM_DATA = 56,
    /* Invalid data on the headers stream received because of decompression failure. */
    QUIC_HEADERS_STREAM_DATA_DECOMPRESS_FAILURE = 97,
    /* The peer received too much data, violating flow control. */
    QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA = 59,
    /* The peer sent too much data, violating flow control. */
    QUIC_FLOW_CONTROL_SENT_TOO_MUCH_DATA = 63,
    /* The peer received an invalid flow control window. */
    QUIC_FLOW_CONTROL_INVALID_WINDOW = 64,
    /* The connection has been IP pooled into an existing connection. */
    QUIC_CONNECTION_IP_POOLED = 62,
    /* The connection has too many outstanding sent packets. */
    QUIC_TOO_MANY_OUTSTANDING_SENT_PACKETS = 68,
    /* The connection has too many outstanding received packets. */
    QUIC_TOO_MANY_OUTSTANDING_RECEIVED_PACKETS = 69,
    /* The quic connection job to load server config is cancelled. */
    QUIC_CONNECTION_CANCELLED = 70,
    /* Disabled QUIC because of high packet loss rate. */
    QUIC_BAD_PACKET_LOSS_RATE = 71,
    /* Disabled QUIC because of too many PUBLIC_RESETs post handshake. */
    QUIC_PUBLIC_RESETS_POST_HANDSHAKE = 73,
    /* Disabled QUIC because of too many timeouts with streams open. */
    QUIC_TIMEOUTS_WITH_OPEN_STREAMS = 74,
    /* Closed because we failed to serialize a packet. */
    QUIC_FAILED_TO_SERIALIZE_PACKET = 75,
    /* QUIC timed out after too many RTOs. */
    QUIC_TOO_MANY_RTOS = 85,

    /* Crypto errors. */
    /* Handshake failed. */
    QUIC_HANDSHAKE_FAILED = 28,
    /* Handshake message contained out of order tags. */
    QUIC_CRYPTO_TAGS_OUT_OF_ORDER = 29,
    /* Handshake message contained too many entries. */
    QUIC_CRYPTO_TOO_MANY_ENTRIES = 30,
    /* Handshake message contained an invalid value length. */
    QUIC_CRYPTO_INVALID_VALUE_LENGTH = 31,
    /* A crypto message was received after the handshake was complete. */
    QUIC_CRYPTO_MESSAGE_AFTER_HANDSHAKE_COMPLETE = 32,
    /* A crypto message was received with an illegal message tag. */
    QUIC_INVALID_CRYPTO_MESSAGE_TYPE = 33,
    /* A crypto message was received with an illegal parameter. */
    QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER = 34,
    /* An invalid channel id signature was supplied. */
    QUIC_INVALID_CHANNEL_ID_SIGNATURE = 52,
    /* A crypto message was received with a mandatory parameter missing. */
    QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND = 35,
    /* A crypto message was received with a parameter that has no overlap
       with the local parameter. */
    QUIC_CRYPTO_MESSAGE_PARAMETER_NO_OVERLAP = 36,
    /* A crypto message was received that contained a parameter with too few
       values. */
    QUIC_CRYPTO_MESSAGE_INDEX_NOT_FOUND = 37,
    /* A demand for an unsupport proof type was received. */
    QUIC_UNSUPPORTED_PROOF_DEMAND = 94,
    /* An internal error occurred in crypto processing. */
    QUIC_CRYPTO_INTERNAL_ERROR = 38,
    /* A crypto handshake message specified an unsupported version. */
    QUIC_CRYPTO_VERSION_NOT_SUPPORTED = 39,
    /* A crypto handshake message resulted in a stateless reject. */
    QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT = 72,
    /* There was no intersection between the crypto primitives supported by the
       peer and ourselves. */
    QUIC_CRYPTO_NO_SUPPORT = 40,
    /* The server rejected our client hello messages too many times. */
    QUIC_CRYPTO_TOO_MANY_REJECTS = 41,
    /* The client rejected the server's certificate chain or signature. */
    QUIC_PROOF_INVALID = 42,
    /* A crypto message was received with a duplicate tag. */
    QUIC_CRYPTO_DUPLICATE_TAG = 43,
    /* A crypto message was received with the wrong encryption level (i.e. it
       should have been encrypted but was not. ) */
    QUIC_CRYPTO_ENCRYPTION_LEVEL_INCORRECT = 44,
    /* The server config for a server has expired. */
    QUIC_CRYPTO_SERVER_CONFIG_EXPIRED = 45,
    /* We failed to setup the symmetric keys for a connection. */
    QUIC_CRYPTO_SYMMETRIC_KEY_SETUP_FAILED = 53,
    /* A handshake message arrived, but we are still validating the
       previous handshake message. */
    QUIC_CRYPTO_MESSAGE_WHILE_VALIDATING_CLIENT_HELLO = 54,
    /* A server config update arrived before the handshake is complete. */
    QUIC_CRYPTO_UPDATE_BEFORE_HANDSHAKE_COMPLETE = 65,
    /* CHLO cannot fit in one packet. */
    QUIC_CRYPTO_CHLO_TOO_LARGE = 90,
    /* This connection involved a version negotiation which appears to have been
       tampered with. */
    QUIC_VERSION_NEGOTIATION_MISMATCH = 55,

    /* Multipath is not enabled, but a packet with multipath flag on is received. */
    QUIC_BAD_MULTIPATH_FLAG = 79,
    /* A path is supposed to exist but does not. */
    QUIC_MULTIPATH_PATH_DOES_NOT_EXIST = 91,
    /* A path is supposed to be active but is not. */
    QUIC_MULTIPATH_PATH_NOT_ACTIVE = 92,

    /* IP address changed causing connection close. */
    QUIC_IP_ADDRESS_CHANGED = 80,

    /* Connection migration errors. */
    /* Network changed, but connection had no migratable streams. */
    QUIC_CONNECTION_MIGRATION_NO_MIGRATABLE_STREAMS = 81,
    /* Connection changed networks too many times. */
    QUIC_CONNECTION_MIGRATION_TOO_MANY_CHANGES = 82,
    /* Connection migration was attempted, but there was no new network to migrate to. */
    QUIC_CONNECTION_MIGRATION_NO_NEW_NETWORK = 83,
    /* Network changed, but connection had one or more non-migratable streams. */
    QUIC_CONNECTION_MIGRATION_NON_MIGRATABLE_STREAM = 84,
    /* Network changed, but connection migration was disabled by config. */
    QUIC_CONNECTION_MIGRATION_DISABLED_BY_CONFIG = 99,
    /* Network changed, but error was encountered on the alternative network. */
    QUIC_CONNECTION_MIGRATION_INTERNAL_ERROR = 100,

    /* Stream frames arrived too discontiguously so that stream sequencer buffer maintains too many gaps. */
    QUIC_TOO_MANY_FRAME_GAPS = 93,

    /* Sequencer buffer get into weird state where continuing read/write will lead
       to crash. */
    QUIC_STREAM_SEQUENCER_INVALID_STATE = 95,
    /* Connection closed because of server hits max number of sessions allowed. */
    QUIC_TOO_MANY_SESSIONS_ON_SERVER = 96,

    /* Receive a RST_STREAM with offset larger than kMaxStreamLength. */
    QUIC_STREAM_LENGTH_OVERFLOW = 98,

    /* No error. Used as bound while iterating. */
    QUIC_LAST_ERROR = 101
};


static const value_string error_code_vals[] = {
    { QUIC_NO_ERROR, "There was no error" },
    { QUIC_INTERNAL_ERROR, "Connection has reached an invalid state" },
    { QUIC_STREAM_DATA_AFTER_TERMINATION, "There were data frames after the a fin or reset" },
    { QUIC_INVALID_PACKET_HEADER, "Control frame is malformed" },
    { QUIC_INVALID_FRAME_DATA, "Frame data is malformed" },
    { QUIC_INVALID_FEC_DATA, "FEC data is malformed" },
    { QUIC_INVALID_RST_STREAM_DATA, "RST_STREAM frame data is malformed" },
    { QUIC_INVALID_CONNECTION_CLOSE_DATA, "CONNECTION_CLOSE frame data is malformed" },
    { QUIC_INVALID_GOAWAY_DATA, "GOAWAY frame data is malformed" },
    { QUIC_INVALID_ACK_DATA, "ACK frame data is malformed" },
    { QUIC_INVALID_VERSION_NEGOTIATION_PACKET, "Version negotiation packet is malformed" },
    { QUIC_INVALID_PUBLIC_RST_PACKET, "Public RST packet is malformed" },
    { QUIC_DECRYPTION_FAILURE, "There was an error decrypting" },
    { QUIC_ENCRYPTION_FAILURE, "There was an error encrypting" },
    { QUIC_PACKET_TOO_LARGE, "The packet exceeded kMaxPacketSize" },
    { QUIC_PACKET_FOR_NONEXISTENT_STREAM, "Data was sent for a stream which did not exist" },
    { QUIC_PEER_GOING_AWAY, "The peer is going away. May be a client or server" },
    { QUIC_INVALID_STREAM_ID, "A stream ID was invalid" },
    { QUIC_TOO_MANY_OPEN_STREAMS, "Too many streams already open" },
    { QUIC_PUBLIC_RESET, "Received public reset for this connection" },
    { QUIC_INVALID_VERSION, "Invalid protocol version" },
    { QUIC_STREAM_RST_BEFORE_HEADERS_DECOMPRESSED, "Stream RST before Headers decompressed (Deprecated)" },
    { QUIC_INVALID_HEADER_ID, "The Header ID for a stream was too far from the previous" },
    { QUIC_INVALID_NEGOTIATED_VALUE, "Negotiable parameter received during handshake had invalid value" },
    { QUIC_DECOMPRESSION_FAILURE, "There was an error decompressing data" },
    { QUIC_CONNECTION_TIMED_OUT, "We hit our prenegotiated (or default) timeout" },
    { QUIC_ERROR_MIGRATING_ADDRESS, "There was an error encountered migrating addresses" },
    { QUIC_PACKET_WRITE_ERROR, "There was an error while writing to the socket" },
    { QUIC_HANDSHAKE_FAILED, "Handshake failed" },
    { QUIC_CRYPTO_TAGS_OUT_OF_ORDER, "Handshake message contained out of order tags" },
    { QUIC_CRYPTO_TOO_MANY_ENTRIES, "Handshake message contained too many entries" },
    { QUIC_CRYPTO_INVALID_VALUE_LENGTH, "Handshake message contained an invalid value length" },
    { QUIC_CRYPTO_MESSAGE_AFTER_HANDSHAKE_COMPLETE, "A crypto message was received after the handshake was complete" },
    { QUIC_INVALID_CRYPTO_MESSAGE_TYPE, "A crypto message was received with an illegal message tag" },
    { QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER, "A crypto message was received with an illegal parameter" },
    { QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND, "A crypto message was received with a mandatory parameter missing" },
    { QUIC_CRYPTO_MESSAGE_PARAMETER_NO_OVERLAP, "A crypto message was received with a parameter that has no overlap with the local parameter" },
    { QUIC_CRYPTO_MESSAGE_INDEX_NOT_FOUND, "A crypto message was received that contained a parameter with too few values" },
    { QUIC_CRYPTO_INTERNAL_ERROR, "An internal error occurred in crypto processing" },
    { QUIC_CRYPTO_VERSION_NOT_SUPPORTED, "A crypto handshake message specified an unsupported version" },

    { QUIC_CRYPTO_NO_SUPPORT, "There was no intersection between the crypto primitives supported by the peer and ourselves" },
    { QUIC_CRYPTO_TOO_MANY_REJECTS, "The server rejected our client hello messages too many times" },
    { QUIC_PROOF_INVALID, "The client rejected the server's certificate chain or signature" },
    { QUIC_CRYPTO_DUPLICATE_TAG, "A crypto message was received with a duplicate tag" },
    { QUIC_CRYPTO_ENCRYPTION_LEVEL_INCORRECT, "A crypto message was received with the wrong encryption level (i.e. it should have been encrypted but was not" },
    { QUIC_CRYPTO_SERVER_CONFIG_EXPIRED, "The server config for a server has expired" },
    { QUIC_INVALID_STREAM_DATA, "STREAM frame data is malformed" },
    { QUIC_INVALID_CONGESTION_FEEDBACK_DATA, "Invalid congestion Feedback data (Deprecated)" },
    { QUIC_MISSING_PAYLOAD, "The packet contained no payload" },
    { QUIC_INVALID_PRIORITY, "A priority was invalid" },
    { QUIC_INVALID_STREAM_FRAME, "We received a STREAM_FRAME with no data and no fin flag set" },
    { QUIC_PACKET_READ_ERROR, "There was an error while reading from the socket" },
    { QUIC_INVALID_CHANNEL_ID_SIGNATURE, "An invalid channel id signature was supplied" },
    { QUIC_CRYPTO_SYMMETRIC_KEY_SETUP_FAILED, "We failed to setup the symmetric keys for a connection" },
    { QUIC_CRYPTO_MESSAGE_WHILE_VALIDATING_CLIENT_HELLO, "A handshake message arrived, but we are still validating the previous handshake message" },
    { QUIC_VERSION_NEGOTIATION_MISMATCH, "This connection involved a version negotiation which appears to have been tampered with" },
    { QUIC_INVALID_HEADERS_STREAM_DATA, "We received invalid data on the headers stream" },
    { QUIC_INVALID_WINDOW_UPDATE_DATA, "WINDOW_UPDATE frame data is malformed" },
    { QUIC_INVALID_BLOCKED_DATA, "BLOCKED frame data is malformed" },

    { QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA, "The peer received too much data, violating flow control" },
    { QUIC_INVALID_STOP_WAITING_DATA, "STOP_WAITING frame data is malformed" },
    { QUIC_UNENCRYPTED_STREAM_DATA, "STREAM frame data is not encrypted" },
    { QUIC_CONNECTION_IP_POOLED, "The connection has been IP pooled into an existing connection" },
    { QUIC_FLOW_CONTROL_SENT_TOO_MUCH_DATA, "The peer sent too much data, violating flow control" },
    { QUIC_FLOW_CONTROL_INVALID_WINDOW, "The peer received an invalid flow control window" },
    { QUIC_CRYPTO_UPDATE_BEFORE_HANDSHAKE_COMPLETE, "A server config update arrived before the handshake is complete" },
    { QUIC_TOO_MANY_UNFINISHED_STREAMS, "The peer must send a FIN/RST for each stream, and has not been doing so" },
    { QUIC_CONNECTION_OVERALL_TIMED_OUT, "We hit our overall connection timeout" },
    { QUIC_TOO_MANY_OUTSTANDING_SENT_PACKETS, "The connection has too many outstanding sent packets" },
    { QUIC_TOO_MANY_OUTSTANDING_RECEIVED_PACKETS, "The connection has too many outstanding received packets" },
    { QUIC_CONNECTION_CANCELLED, "The quic connection job to load server config is cancelled" },
    { QUIC_BAD_PACKET_LOSS_RATE, "Disabled QUIC because of high packet loss rate" },
    { QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT, "A crypto handshake message resulted in a stateless reject" },
    { QUIC_PUBLIC_RESETS_POST_HANDSHAKE, "Disabled QUIC because of too many PUBLIC_RESETs post handshake" },
    { QUIC_TIMEOUTS_WITH_OPEN_STREAMS, "Disabled QUIC because of too many timeouts with streams open" },
    { QUIC_FAILED_TO_SERIALIZE_PACKET, "Closed because we failed to serialize a packet" },
    { QUIC_TOO_MANY_AVAILABLE_STREAMS, "The peer created too many available streams" },
    { QUIC_UNENCRYPTED_FEC_DATA, "FEC frame data is not encrypted" },
    { QUIC_INVALID_PATH_CLOSE_DATA, "PATH_CLOSE frame data is malformed" },
    { QUIC_BAD_MULTIPATH_FLAG, "Multipath is not enabled, but a packet with multipath flag on is received" },
    { QUIC_IP_ADDRESS_CHANGED, "IP address changed causing connection close" },
    { QUIC_CONNECTION_MIGRATION_NO_MIGRATABLE_STREAMS, "Network changed, but connection had no migratable stream" },
    { QUIC_CONNECTION_MIGRATION_TOO_MANY_CHANGES, "Connection changed networks too many times" },
    { QUIC_CONNECTION_MIGRATION_NO_NEW_NETWORK, "Connection migration was attempted, but there was no new network to migrate to" },
    { QUIC_CONNECTION_MIGRATION_NON_MIGRATABLE_STREAM, "Network changed, but connection had one or more non-migratable streams" },
    { QUIC_TOO_MANY_RTOS, "QUIC timed out after too many RTOs" },
    { QUIC_ERROR_MIGRATING_PORT, "There was an error encountered migrating port only" },
    { QUIC_OVERLAPPING_STREAM_DATA, "STREAM frame data overlaps with buffered data" },
    { QUIC_ATTEMPT_TO_SEND_UNENCRYPTED_STREAM_DATA, "Attempt to send unencrypted STREAM frame" },
    { QUIC_MAYBE_CORRUPTED_MEMORY, "Received a frame which is likely the result of memory corruption" },
    { QUIC_CRYPTO_CHLO_TOO_LARGE, "CHLO cannot fit in one packet" },
    { QUIC_MULTIPATH_PATH_DOES_NOT_EXIST, "A path is supposed to exist but does not" },
    { QUIC_MULTIPATH_PATH_NOT_ACTIVE, "A path is supposed to be active but is not" },
    { QUIC_TOO_MANY_FRAME_GAPS, "Stream frames arrived too discontiguously so that stream sequencer buffer maintains too many gaps" },
    { QUIC_UNSUPPORTED_PROOF_DEMAND, "A demand for an unsupport proof type was received" },
    { QUIC_STREAM_SEQUENCER_INVALID_STATE, "Sequencer buffer get into weird state where continuing read/write will lead to crash" },
    { QUIC_TOO_MANY_SESSIONS_ON_SERVER, "Connection closed because of server hits max number of sessions allowed" },
    { QUIC_HEADERS_STREAM_DATA_DECOMPRESS_FAILURE, "Invalid data on the headers stream received because of decompression failure" },
    { QUIC_STREAM_LENGTH_OVERFLOW, "Receive a RST_STREAM with offset larger than kMaxStreamLength" },
    { QUIC_CONNECTION_MIGRATION_DISABLED_BY_CONFIG, "Network changed, but connection migration was disabled by config" },
    { QUIC_CONNECTION_MIGRATION_INTERNAL_ERROR, "Network changed, but error was encountered on the alternative network" },
    { QUIC_LAST_ERROR, "No error. Used as bound while iterating" },
    { 0, NULL }
};

static value_string_ext error_code_vals_ext = VALUE_STRING_EXT_INIT(error_code_vals);

/**************************************************************************/
/*                      RST Stream Error Code                             */
/**************************************************************************/
/* See https://chromium.googlesource.com/chromium/src.git/+/master/net/third_party/quic/core/quic_error_codes.h (enum QuicRstStreamErrorCode) */

enum QuicRstStreamErrorCode {
  /* Complete response has been sent, sending a RST to ask the other endpoint to stop sending request data without discarding the response. */

  QUIC_STREAM_NO_ERROR = 0,
  /* There was some error which halted stream processing.*/
  QUIC_ERROR_PROCESSING_STREAM,
  /* We got two fin or reset offsets which did not match.*/
  QUIC_MULTIPLE_TERMINATION_OFFSETS,
  /* We got bad payload and can not respond to it at the protocol level. */
  QUIC_BAD_APPLICATION_PAYLOAD,
  /* Stream closed due to connection error. No reset frame is sent when this happens. */
  QUIC_STREAM_CONNECTION_ERROR,
  /* GoAway frame sent. No more stream can be created. */
  QUIC_STREAM_PEER_GOING_AWAY,
  /* The stream has been cancelled. */
  QUIC_STREAM_CANCELLED,
  /* Closing stream locally, sending a RST to allow for proper flow control accounting. Sent in response to a RST from the peer. */
  QUIC_RST_ACKNOWLEDGEMENT,
  /* Receiver refused to create the stream (because its limit on open streams has been reached).  The sender should retry the request later (using another stream). */
  QUIC_REFUSED_STREAM,
  /* Invalid URL in PUSH_PROMISE request header. */
  QUIC_INVALID_PROMISE_URL,
  /* Server is not authoritative for this URL. */
  QUIC_UNAUTHORIZED_PROMISE_URL,
  /* Can't have more than one active PUSH_PROMISE per URL. */
  QUIC_DUPLICATE_PROMISE_URL,
  /* Vary check failed. */
  QUIC_PROMISE_VARY_MISMATCH,
  /* Only GET and HEAD methods allowed. */
  QUIC_INVALID_PROMISE_METHOD,
  /* The push stream is unclaimed and timed out. */
  QUIC_PUSH_STREAM_TIMED_OUT,
  /* Received headers were too large. */
  QUIC_HEADERS_TOO_LARGE,
  /* The data is not likely arrive in time. */
  QUIC_STREAM_TTL_EXPIRED,
  /* No error. Used as bound while iterating. */
  QUIC_STREAM_LAST_ERROR,
};

static const value_string rststream_error_code_vals[] = {
    { QUIC_STREAM_NO_ERROR, "Complete response has been sent, sending a RST to ask the other endpoint to stop sending request data without discarding the response." },
    { QUIC_ERROR_PROCESSING_STREAM, "There was some error which halted stream processing" },
    { QUIC_MULTIPLE_TERMINATION_OFFSETS, "We got two fin or reset offsets which did not match" },
    { QUIC_BAD_APPLICATION_PAYLOAD, "We got bad payload and can not respond to it at the protocol level" },
    { QUIC_STREAM_CONNECTION_ERROR, "Stream closed due to connection error. No reset frame is sent when this happens" },
    { QUIC_STREAM_PEER_GOING_AWAY, "GoAway frame sent. No more stream can be created" },
    { QUIC_STREAM_CANCELLED, "The stream has been cancelled" },
    { QUIC_RST_ACKNOWLEDGEMENT, "Closing stream locally, sending a RST to allow for proper flow control accounting. Sent in response to a RST from the peer" },
    { QUIC_REFUSED_STREAM, "Receiver refused to create the stream (because its limit on open streams has been reached). The sender should retry the request later (using another stream)" },
    { QUIC_INVALID_PROMISE_URL, "Invalid URL in PUSH_PROMISE request header" },
    { QUIC_UNAUTHORIZED_PROMISE_URL, "Server is not authoritative for this URL" },
    { QUIC_DUPLICATE_PROMISE_URL, "Can't have more than one active PUSH_PROMISE per URL" },
    { QUIC_PROMISE_VARY_MISMATCH, "Vary check failed" },
    { QUIC_INVALID_PROMISE_METHOD, "Only GET and HEAD methods allowed" },
    { QUIC_PUSH_STREAM_TIMED_OUT, "The push stream is unclaimed and timed out" },
    { QUIC_HEADERS_TOO_LARGE, "Received headers were too large" },
    { QUIC_STREAM_TTL_EXPIRED, "The data is not likely arrive in time" },
    { QUIC_STREAM_LAST_ERROR, "No error. Used as bound while iterating" },
    { 0, NULL }
};
static value_string_ext rststream_error_code_vals_ext = VALUE_STRING_EXT_INIT(rststream_error_code_vals);

/**************************************************************************/
/*                      Handshake Failure Reason                          */
/**************************************************************************/
/* See https://chromium.googlesource.com/chromium/src.git/+/master/net/third_party/quic/core/crypto/crypto_handshake.h */

enum HandshakeFailureReason {
    HANDSHAKE_OK = 0,

    /* Failure reasons for an invalid client nonce in CHLO. */

    /* The default error value for nonce verification failures from strike register (covers old strike registers and unknown failures). */
    CLIENT_NONCE_UNKNOWN_FAILURE = 1,
    /* Client nonce had incorrect length. */
    CLIENT_NONCE_INVALID_FAILURE = 2,
    /* Client nonce is not unique. */
    CLIENT_NONCE_NOT_UNIQUE_FAILURE = 3,
    /* Client orbit is invalid or incorrect. */
    CLIENT_NONCE_INVALID_ORBIT_FAILURE = 4,
    /* Client nonce's timestamp is not in the strike register's valid time range. */
    CLIENT_NONCE_INVALID_TIME_FAILURE = 5,
    /* Strike register's RPC call timed out, client nonce couldn't be verified. */
    CLIENT_NONCE_STRIKE_REGISTER_TIMEOUT = 6,
    /* Strike register is down, client nonce couldn't be verified. */
    CLIENT_NONCE_STRIKE_REGISTER_FAILURE = 7,

    /* Failure reasons for an invalid server nonce in CHLO. */

    /* Unbox of server nonce failed. */
    SERVER_NONCE_DECRYPTION_FAILURE = 8,
    /* Decrypted server nonce had incorrect length. */
    SERVER_NONCE_INVALID_FAILURE = 9,
    /* Server nonce is not unique. */
    SERVER_NONCE_NOT_UNIQUE_FAILURE = 10,
    /* Server nonce's timestamp is not in the strike register's valid time range. */
    SERVER_NONCE_INVALID_TIME_FAILURE = 11,
    /* The server requires handshake confirmation. */
    SERVER_NONCE_REQUIRED_FAILURE = 20,

    /* Failure reasons for an invalid server config in CHLO. */

    /* Missing Server config id (kSCID) tag. */
    SERVER_CONFIG_INCHOATE_HELLO_FAILURE = 12,
    /* Couldn't find the Server config id (kSCID). */
    SERVER_CONFIG_UNKNOWN_CONFIG_FAILURE = 13,

    /* Failure reasons for an invalid source-address token. */

    /* Missing Source-address token (kSourceAddressTokenTag) tag. */
    SOURCE_ADDRESS_TOKEN_INVALID_FAILURE = 14,
    /* Unbox of Source-address token failed. */
    SOURCE_ADDRESS_TOKEN_DECRYPTION_FAILURE = 15,
    /* Couldn't parse the unbox'ed Source-address token. */
    SOURCE_ADDRESS_TOKEN_PARSE_FAILURE = 16,
    /* Source-address token is for a different IP address. */
    SOURCE_ADDRESS_TOKEN_DIFFERENT_IP_ADDRESS_FAILURE = 17,
    /* The source-address token has a timestamp in the future. */
    SOURCE_ADDRESS_TOKEN_CLOCK_SKEW_FAILURE = 18,
    /* The source-address token has expired. */
    SOURCE_ADDRESS_TOKEN_EXPIRED_FAILURE = 19,

    /* The expected leaf certificate hash could not be validated. */
    INVALID_EXPECTED_LEAF_CERTIFICATE = 21,

    MAX_FAILURE_REASON = 22
};

static const value_string handshake_failure_reason_vals[] = {
    { HANDSHAKE_OK, "Handshake OK" },
    { CLIENT_NONCE_UNKNOWN_FAILURE, "The default error value for nonce verification failures from strike register (covers old strike registers and unknown failures)" },
    { CLIENT_NONCE_INVALID_FAILURE, "Client nonce had incorrect length" },
    { CLIENT_NONCE_NOT_UNIQUE_FAILURE, "Client nonce is not unique" },
    { CLIENT_NONCE_INVALID_ORBIT_FAILURE, "Client orbit is invalid or incorrect" },
    { CLIENT_NONCE_INVALID_TIME_FAILURE, "Client nonce's timestamp is not in the strike register's valid time range" },
    { CLIENT_NONCE_STRIKE_REGISTER_TIMEOUT, "Strike register's RPC call timed out, client nonce couldn't be verified" },
    { CLIENT_NONCE_STRIKE_REGISTER_FAILURE, "Strike register is down, client nonce couldn't be verified" },
    { SERVER_NONCE_DECRYPTION_FAILURE, "Unbox of server nonce failed" },
    { SERVER_NONCE_INVALID_FAILURE, "Decrypted server nonce had incorrect length" },
    { SERVER_NONCE_NOT_UNIQUE_FAILURE, "Server nonce is not unique" },
    { SERVER_NONCE_INVALID_TIME_FAILURE, "Server nonce's timestamp is not in the strike register's valid time range" },
    { SERVER_CONFIG_INCHOATE_HELLO_FAILURE, "Missing Server config id (kSCID) tag" },
    { SERVER_CONFIG_UNKNOWN_CONFIG_FAILURE, "Couldn't find the Server config id (kSCID)" },
    { SOURCE_ADDRESS_TOKEN_INVALID_FAILURE, "Missing Source-address token (kSourceAddressTokenTag) tag" },
    { SOURCE_ADDRESS_TOKEN_DECRYPTION_FAILURE, "Unbox of Source-address token failed" },
    { SOURCE_ADDRESS_TOKEN_PARSE_FAILURE, "Couldn't parse the unbox'ed Source-address token" },
    { SOURCE_ADDRESS_TOKEN_DIFFERENT_IP_ADDRESS_FAILURE, "Source-address token is for a different IP address" },
    { SOURCE_ADDRESS_TOKEN_CLOCK_SKEW_FAILURE, "The source-address token has a timestamp in the future" },
    { SOURCE_ADDRESS_TOKEN_EXPIRED_FAILURE, "The source-address token has expired" },
    { SERVER_NONCE_REQUIRED_FAILURE, "The server requires handshake confirmation" },
    { INVALID_EXPECTED_LEAF_CERTIFICATE, "The expected leaf certificate hash could not be validated" },
    { 0, NULL }
};
static value_string_ext handshake_failure_reason_vals_ext = VALUE_STRING_EXT_INIT(handshake_failure_reason_vals);


static uint32_t get_len_offset(uint8_t frame_type){

    switch((frame_type & FTFLAGS_STREAM_OOO) >> 2){
        case 0:
            return 0;
        break;
        case 1:
            return 2;
        break;
        case 2:
            return 3;
        break;
        case 3:
            return 4;
        break;
        case 4:
            return 5;
        break;
        case 5:
            return 6;
        break;
        case 6:
            return 7;
        break;
        case 7:
            return 8;
        break;
        default:
        break;
    }
    return 0;
}
static uint32_t get_len_stream(uint8_t frame_type){

    switch(frame_type & FTFLAGS_STREAM_SS){
        case 0:
            return 1;
        break;
        case 1:
            return 2;
        break;
        case 2:
            return 3;
        break;
        case 3:
            return 4;
        break;
        default:
        break;
    }
    return 1;
}

static uint32_t get_len_largest_observed(uint8_t frame_type){

    switch((frame_type & FTFLAGS_ACK_LL) >> 2){
        case 0:
            return 1;
        break;
        case 1:
            return 2;
        break;
        case 2:
            return 4;
        break;
        case 3:
            return 6;
        break;
        default:
        break;
    }
    return 1;
}
static uint32_t get_len_missing_packet(uint8_t frame_type){

    switch(frame_type & FTFLAGS_ACK_MM){
        case 0:
            return 1;
        break;
        case 1:
            return 2;
        break;
        case 2:
            return 4;
        break;
        case 3:
            return 6;
        break;
        default:
        break;
    }
    return 1;
}

static uint32_t get_len_packet_number(uint8_t puflags){

    switch((puflags & PUFLAGS_PKN) >> 4){
        case 0:
            return 1;
        break;
        case 1:
            return 2;
        break;
        case 2:
            return 4;
        break;
        case 3:
            return 6;
        break;
        default:
        break;
    }
    return 6;
}

static
bool is_gquic_unencrypt(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, uint16_t len_pkn, gquic_info_data_t *gquic_info){
    uint8_t frame_type;
    uint8_t num_ranges, num_revived, num_blocks = 0, num_timestamp;
    uint32_t len_stream = 0, len_offset = 0, len_data = 0, len_largest_observed = 1, len_missing_packet = 1;
    uint32_t message_tag;


    if(tvb_captured_length_remaining(tvb, offset) <= 13){
        return false;
    }
    /* Message Authentication Hash */
    offset += 12;

    if(gquic_info->version_valid && gquic_info->version < 34){ /* No longer Private Flags after Q034 */
        /* Private Flags */
        offset += 1;
    }

    while(tvb_reported_length_remaining(tvb, offset) > 0){

        if (tvb_captured_length_remaining(tvb, offset) <= 1){
            return false;
        }
        /* Frame type */
        frame_type = tvb_get_uint8(tvb, offset);
        if((frame_type & FTFLAGS_SPECIAL) == 0){
            offset += 1;
            switch(frame_type){
                case FT_PADDING:
                    return false; /* Pad on rest of packet.. */
                break;
                case FT_RST_STREAM:
                    /* Stream ID */
                    offset += 4;
                    /* Byte Offset */
                    offset += 8;
                    /* Error Code */
                    offset += 4;
                break;
                case FT_CONNECTION_CLOSE:{
                    uint16_t len_reason;

                    /* Error Code */
                    offset += 4;
                    /* Reason Phrase Length */
                    if (tvb_captured_length_remaining(tvb, offset) <= 2){
                        return false;
                    }
                    len_reason = tvb_get_uint16(tvb, offset, gquic_info->encoding);
                    offset += 2;
                    /* Reason Phrase */
                    /* If length remaining == len_reason, it is Connection Close */
                    if (tvb_captured_length_remaining(tvb, offset) == len_reason){
                        return true;
                    }
                    }
                break;
                case FT_GOAWAY:{
                    uint16_t len_reason;

                    /* Error Code */
                    offset += 4;
                    /* Last Good Stream ID */
                    offset += 4;
                    /* Reason Phrase Length */
                    if (tvb_captured_length_remaining(tvb, offset) <= 2){
                        return false;
                    }
                    len_reason = tvb_get_uint16(tvb, offset, gquic_info->encoding);
                    offset += 2;
                    /* Reason Phrase */
                    offset += len_reason;
                    }
                break;
                case FT_WINDOW_UPDATE:
                    /* Stream ID */
                    offset += 4;
                    /* Byte Offset */
                    offset += 8;
                break;
                case FT_BLOCKED:
                    /* Stream ID */
                    offset += 4;
                break;
                case FT_STOP_WAITING:
                    if(gquic_info->version_valid && gquic_info->version < 34){ /* No longer Entropy after Q034 */
                        /* Send Entropy */
                        offset += 1;
                    }
                    /* Least Unacked Delta */
                    offset += len_pkn;
                break;
                case FT_PING: /* No Payload */
                default: /* No default */
                break;
            }
        } else {
            /* Special Frame Type */
            if(frame_type & FTFLAGS_STREAM){ /* Stream */

                if(frame_type & FTFLAGS_STREAM_D){
                    len_data = 2;
                }
                len_offset = get_len_offset(frame_type);
                len_stream = get_len_stream(frame_type);

                /* Frame Type */
                offset += 1;

                /* Stream */
                offset += len_stream;

                /* Offset */
                offset += len_offset;

                /* Data length */
                offset += len_data;

                if (tvb_captured_length_remaining(tvb, offset) <= 4){
                    return false;
                }

                /* Check if the Message Tag is CHLO (Client Hello) or SHLO (Server Hello) or REJ (Rejection) */
                message_tag = tvb_get_ntohl(tvb, offset);
                if (message_tag == MTAG_CHLO|| message_tag == MTAG_SHLO || message_tag == MTAG_REJ) {
                    if(message_tag == MTAG_CHLO && pinfo->srcport != 443) { /* Found */
                        gquic_info->server_port = pinfo->destport;
                    }
                    return true;
                }


            } else if (frame_type & FTFLAGS_ACK) {
            /* ACK Flags */

                len_largest_observed = get_len_largest_observed(frame_type);
                len_missing_packet = get_len_missing_packet(frame_type);

                /* Frame Type */
                offset += 1;

                if(gquic_info->version_valid && gquic_info->version < 34){ /* No longer Entropy after Q034 */
                    /* Received Entropy */
                    offset += 1;

                    /* Largest Observed */
                    offset += len_largest_observed;

                    /* Ack Delay Time */
                    offset += 2;

                    /* Num Timestamp */
                    if (tvb_captured_length_remaining(tvb, offset) <= 1){
                        return false;
                    }
                    num_timestamp = tvb_get_uint8(tvb, offset);
                    offset += 1;

                    if(num_timestamp > 0){
                        /* Delta Largest Observed */
                        offset += 1;

                        /* First Timestamp */
                        offset += 4;

                        /* Num Timestamp (-1)x (Delta Largest Observed + Time Since Previous Timestamp) */
                        offset += (num_timestamp - 1)*(1+2);
                    }

                    if(frame_type & FTFLAGS_ACK_N){
                        /* Num Ranges */
                        if (tvb_captured_length_remaining(tvb, offset) <= 1){
                            return false;
                        }
                        num_ranges = tvb_get_uint8(tvb, offset);
                        offset += 1;

                        /* Num Range x (Missing Packet + Range Length) */
                        offset += num_ranges*(len_missing_packet+1);

                        /* Num Revived */
                        if (tvb_captured_length_remaining(tvb, offset) <= 1){
                            return false;
                        }
                        num_revived = tvb_get_uint8(tvb, offset);
                        offset += 1;

                        /* Num Revived x Length Largest Observed */
                        offset += num_revived*len_largest_observed;

                    }
                } else {

                    /* Largest Acked */
                    offset += len_largest_observed;

                    /* Largest Acked Delta Time*/
                    offset += 2;

                    /* Ack Block */
                    if(frame_type & FTFLAGS_ACK_N){
                        if (tvb_captured_length_remaining(tvb, offset) <= 1){
                            return false;
                        }
                        num_blocks = tvb_get_uint8(tvb, offset);
                        offset += 1;
                    }

                    /* First Ack Block Length */
                    offset += len_missing_packet;
                    if(num_blocks){
                        offset += (num_blocks)*(1 + len_missing_packet);
                    }

                    /* Timestamp */
                    if (tvb_captured_length_remaining(tvb, offset) <= 1){
                        return false;
                    }
                    num_timestamp = tvb_get_uint8(tvb, offset);
                    offset += 1;

                    if(num_timestamp > 0){

                        /* Delta Largest Acked */
                        offset += 1;

                        /* Time Since Largest Acked */
                        offset += 4;

                        /* Num Timestamp x (Delta Largest Acked + Time Since Previous Timestamp) */
                        offset += (num_timestamp - 1)*(1+2);
                    }

                }
            } else { /* Other Special Frame type */
                offset += 1;
            }
        }
    }

    return false;

}

static uint32_t
// NOLINTNEXTLINE(misc-no-recursion)
dissect_gquic_tag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *gquic_tree, unsigned offset, uint32_t tag_number){
    uint32_t tag_offset_start = offset + tag_number*4*2;
    uint32_t tag_offset = 0, total_tag_len = 0;
    int32_t tag_len;

    while(tag_number){
        proto_tree *tag_tree, *ti_len, *ti_tag, *ti_type;
        uint32_t offset_end, tag, num_iter;
        const uint8_t* tag_str;

        ti_tag = proto_tree_add_item(gquic_tree, hf_gquic_tags, tvb, offset, 8, ENC_NA);
        tag_tree = proto_item_add_subtree(ti_tag, ett_gquic_tag_value);
        ti_type = proto_tree_add_item_ret_string(tag_tree, hf_gquic_tag_type, tvb, offset, 4, ENC_ASCII|ENC_NA, pinfo->pool, &tag_str);
        tag = tvb_get_ntohl(tvb, offset);
        proto_item_append_text(ti_type, " (%s)", val_to_str_const(tag, tag_vals, "Unknown"));
        proto_item_append_text(ti_tag, ": %s (%s)", tag_str, val_to_str_const(tag, tag_vals, "Unknown"));
        offset += 4;

        proto_tree_add_item(tag_tree, hf_gquic_tag_offset_end, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset_end = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);

        tag_len = offset_end - tag_offset;
        ti_len = proto_tree_add_uint(tag_tree, hf_gquic_tag_length, tvb, offset, 4, tag_len);
        proto_item_append_text(ti_tag, " (l=%u)", tag_len);
        proto_item_set_generated(ti_len);
        offset += 4;

        /* Fix issue with CRT.. (Fragmentation ?) */
        if( tag_len > tvb_reported_length_remaining(tvb, tag_offset_start + tag_offset)){
            tag_len = tvb_reported_length_remaining(tvb, tag_offset_start + tag_offset);
            offset_end = tag_offset + tag_len;
            expert_add_info(pinfo, ti_len, &ei_gquic_tag_length);
        }

        total_tag_len += tag_len;

        proto_tree_add_item(tag_tree, hf_gquic_tag_value, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);

        increment_dissection_depth(pinfo);
        switch(tag){
            case TAG_PAD:
                proto_tree_add_item(tag_tree, hf_gquic_tag_pad, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);
                tag_offset += tag_len;
            break;
            case TAG_SNI:
                proto_tree_add_item_ret_string(tag_tree, hf_gquic_tag_sni, tvb, tag_offset_start + tag_offset, tag_len, ENC_ASCII|ENC_NA, pinfo->pool, &tag_str);
                proto_item_append_text(ti_tag, ": %s", tag_str);
                tag_offset += tag_len;
            break;
            case TAG_VER:
                num_iter = 1;
                while(offset_end - tag_offset >= 4){
                    proto_tree_add_item_ret_string(tag_tree, hf_gquic_tag_ver, tvb, tag_offset_start + tag_offset, 4, ENC_ASCII|ENC_NA, pinfo->pool, &tag_str);
                    proto_item_append_text(ti_tag, "%s %s", num_iter == 1 ? ":" : ",", tag_str);
                    tag_offset += 4;
                    num_iter++;
                }
            break;
            case TAG_CCS:
                while(offset_end - tag_offset >= 8){
                    proto_tree_add_item(tag_tree, hf_gquic_tag_ccs, tvb, tag_offset_start + tag_offset, 8, ENC_NA);
                    tag_offset += 8;
                }
            break;
            case TAG_PDMD:
                proto_tree_add_item_ret_string(tag_tree, hf_gquic_tag_pdmd, tvb, tag_offset_start + tag_offset, tag_len, ENC_ASCII|ENC_NA, pinfo->pool, &tag_str);
                proto_item_append_text(ti_tag, ": %s", tag_str);
                tag_offset += tag_len;
            break;
            case TAG_UAID:
                proto_tree_add_item_ret_string(tag_tree, hf_gquic_tag_uaid, tvb, tag_offset_start + tag_offset, tag_len, ENC_ASCII|ENC_NA, pinfo->pool, &tag_str);
                proto_item_append_text(ti_tag, ": %s", tag_str);
                tag_offset += tag_len;
            break;
            case TAG_STK:
                proto_tree_add_item(tag_tree, hf_gquic_tag_stk, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);
                tag_offset += tag_len;
            break;
            case TAG_SNO:
                proto_tree_add_item(tag_tree, hf_gquic_tag_sno, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);
                tag_offset += tag_len;
            break;
            case TAG_PROF:
                proto_tree_add_item(tag_tree, hf_gquic_tag_prof, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);
                tag_offset += tag_len;
            break;
            case TAG_SCFG:{
                uint32_t scfg_tag_number;

                proto_tree_add_item(tag_tree, hf_gquic_tag_scfg, tvb, tag_offset_start + tag_offset, 4, ENC_ASCII);
                tag_offset += 4;
                proto_tree_add_item(tag_tree, hf_gquic_tag_scfg_number, tvb, tag_offset_start + tag_offset, 4, ENC_LITTLE_ENDIAN);
                scfg_tag_number = tvb_get_uint32(tvb, tag_offset_start + tag_offset, ENC_LITTLE_ENDIAN);
                tag_offset += 4;

                dissect_gquic_tag(tvb, pinfo, tag_tree, tag_offset_start + tag_offset, scfg_tag_number);
                tag_offset += tag_len - 4 - 4;
                }
            break;
            case TAG_RREJ:
                while(offset_end - tag_offset >= 4){
                    proto_tree_add_item(tag_tree, hf_gquic_tag_rrej, tvb, tag_offset_start + tag_offset, 4,  ENC_LITTLE_ENDIAN);
                    proto_item_append_text(ti_tag, ", Code %s", val_to_str_ext_const(tvb_get_uint32(tvb, tag_offset_start + tag_offset, ENC_LITTLE_ENDIAN),
                                                                                     &handshake_failure_reason_vals_ext,
                                                                                     "Unknown"));
                    tag_offset += 4;
                }
            break;
            case TAG_CRT:
                proto_tree_add_item(tag_tree, hf_gquic_tag_crt, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);
                tag_offset += tag_len;
            break;
            case TAG_AEAD:
                while(offset_end - tag_offset >= 4){
                    proto_tree *ti_aead;
                    ti_aead = proto_tree_add_item(tag_tree, hf_gquic_tag_aead, tvb, tag_offset_start + tag_offset, 4, ENC_ASCII);
                    proto_item_append_text(ti_aead, " (%s)", val_to_str_const(tvb_get_ntohl(tvb, tag_offset_start + tag_offset), tag_aead_vals, "Unknown"));
                    proto_item_append_text(ti_tag, ", %s", val_to_str_const(tvb_get_ntohl(tvb, tag_offset_start + tag_offset), tag_aead_vals, "Unknown"));
                    tag_offset += 4;
                }
            break;
            case TAG_SCID:
                proto_tree_add_item(tag_tree, hf_gquic_tag_scid, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);
                tag_offset += tag_len;
            break;
            case TAG_PUBS:
                /*TODO FIX: 24 Length + Pubs key?.. ! */
                proto_tree_add_item(tag_tree, hf_gquic_tag_pubs, tvb, tag_offset_start + tag_offset, 2, ENC_LITTLE_ENDIAN);
                tag_offset += 2;
                while(offset_end - tag_offset >= 3){
                    proto_tree_add_item(tag_tree, hf_gquic_tag_pubs, tvb, tag_offset_start + tag_offset, 3, ENC_LITTLE_ENDIAN);
                    tag_offset += 3;
                }
            break;
            case TAG_KEXS:
                while(offset_end - tag_offset >= 4){
                    proto_tree *ti_kexs;
                    ti_kexs = proto_tree_add_item(tag_tree, hf_gquic_tag_kexs, tvb, tag_offset_start + tag_offset, 4, ENC_ASCII);
                    proto_item_append_text(ti_kexs, " (%s)", val_to_str_const(tvb_get_ntohl(tvb, tag_offset_start + tag_offset), tag_kexs_vals, "Unknown"));
                    proto_item_append_text(ti_tag, ", %s", val_to_str_const(tvb_get_ntohl(tvb, tag_offset_start + tag_offset), tag_kexs_vals, "Unknown"));
                    tag_offset += 4;
                }
            break;
            case TAG_OBIT:
                proto_tree_add_item(tag_tree, hf_gquic_tag_obit, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);
                tag_offset += tag_len;
            break;
            case TAG_EXPY:
                proto_tree_add_item(tag_tree, hf_gquic_tag_expy, tvb, tag_offset_start + tag_offset, 8, ENC_LITTLE_ENDIAN);
                tag_offset += 8;
            break;
            case TAG_NONC:
                /*TODO: Enhance display: 32 bytes consisting of 4 bytes of timestamp (big-endian, UNIX epoch seconds), 8 bytes of server orbit and 20 bytes of random data. */
                proto_tree_add_item(tag_tree, hf_gquic_tag_nonc, tvb, tag_offset_start + tag_offset, 32, ENC_NA);
                tag_offset += 32;
            break;
            case TAG_MSPC:
                proto_tree_add_item(tag_tree, hf_gquic_tag_mspc, tvb, tag_offset_start + tag_offset, 4, ENC_LITTLE_ENDIAN);
                proto_item_append_text(ti_tag, ": %u", tvb_get_uint32(tvb, tag_offset_start + tag_offset, ENC_LITTLE_ENDIAN));
                tag_offset += 4;
            break;
            case TAG_TCID:
                proto_tree_add_item(tag_tree, hf_gquic_tag_tcid, tvb, tag_offset_start + tag_offset, 4, ENC_LITTLE_ENDIAN);
                tag_offset += 4;
            break;
            case TAG_SRBF:
                proto_tree_add_item(tag_tree, hf_gquic_tag_srbf, tvb, tag_offset_start + tag_offset, 4, ENC_LITTLE_ENDIAN);
                tag_offset += 4;
            break;
            case TAG_ICSL:
                proto_tree_add_item(tag_tree, hf_gquic_tag_icsl, tvb, tag_offset_start + tag_offset, 4, ENC_LITTLE_ENDIAN);
                tag_offset += 4;
            break;
            case TAG_SCLS:
                proto_tree_add_item(tag_tree, hf_gquic_tag_scls, tvb, tag_offset_start + tag_offset, 4, ENC_LITTLE_ENDIAN);
                tag_offset += 4;
            break;
            case TAG_COPT:
                while(offset_end - tag_offset >= 4){
                    proto_tree_add_item(tag_tree, hf_gquic_tag_copt, tvb, tag_offset_start + tag_offset, 4, ENC_ASCII);
                    tag_offset += 4;
                }
            break;
            case TAG_CCRT:
                proto_tree_add_item(tag_tree, hf_gquic_tag_ccrt, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);
                tag_offset += tag_len;
            break;
            case TAG_IRTT:
                proto_tree_add_item(tag_tree, hf_gquic_tag_irtt, tvb, tag_offset_start + tag_offset, 4, ENC_LITTLE_ENDIAN);
                proto_item_append_text(ti_tag, ": %u", tvb_get_uint32(tvb, tag_offset_start + tag_offset, ENC_LITTLE_ENDIAN));
                tag_offset += 4;
            break;
            case TAG_CFCW:
                proto_tree_add_item(tag_tree, hf_gquic_tag_cfcw, tvb, tag_offset_start + tag_offset, 4, ENC_LITTLE_ENDIAN);
                proto_item_append_text(ti_tag, ": %u", tvb_get_uint32(tvb, tag_offset_start + tag_offset, ENC_LITTLE_ENDIAN));
                tag_offset += 4;
            break;
            case TAG_SFCW:
                proto_tree_add_item(tag_tree, hf_gquic_tag_sfcw, tvb, tag_offset_start + tag_offset, 4, ENC_LITTLE_ENDIAN);
                proto_item_append_text(ti_tag, ": %u", tvb_get_uint32(tvb, tag_offset_start + tag_offset, ENC_LITTLE_ENDIAN));
                tag_offset += 4;
            break;
            case TAG_CETV:
                proto_tree_add_item(tag_tree, hf_gquic_tag_cetv, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);
                tag_offset += tag_len;
            break;
            case TAG_XLCT:
                proto_tree_add_item(tag_tree, hf_gquic_tag_xlct, tvb, tag_offset_start + tag_offset, 8, ENC_NA);
                tag_offset += 8;
            break;
            case TAG_NONP:
                proto_tree_add_item(tag_tree, hf_gquic_tag_nonp, tvb, tag_offset_start + tag_offset, 32, ENC_NA);
                tag_offset += 32;
            break;
            case TAG_CSCT:
                proto_tree_add_item(tag_tree, hf_gquic_tag_csct, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);
                tag_offset += tag_len;
            break;
            case TAG_CTIM:
                proto_tree_add_item(tag_tree, hf_gquic_tag_ctim, tvb, tag_offset_start + tag_offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_SECS_NSECS);
                tag_offset += 8;
            break;
            case TAG_RNON: /* Public Reset Tag */
                proto_tree_add_item(tag_tree, hf_gquic_tag_rnon, tvb, tag_offset_start + tag_offset, 8, ENC_LITTLE_ENDIAN);
                tag_offset += 8;
            break;
            case TAG_RSEQ: /* Public Reset Tag */
                proto_tree_add_item(tag_tree, hf_gquic_tag_rseq, tvb, tag_offset_start + tag_offset, 8, ENC_LITTLE_ENDIAN);
                tag_offset += 8;
            break;
            case TAG_CADR: /* Public Reset Tag */{
                uint32_t addr_type;
                proto_tree_add_item_ret_uint(tag_tree, hf_gquic_tag_cadr_addr_type, tvb, tag_offset_start + tag_offset, 2, ENC_LITTLE_ENDIAN, &addr_type);
                tag_offset += 2;
                switch(addr_type){
                    case 2: /* IPv4 */
                    proto_tree_add_item(tag_tree, hf_gquic_tag_cadr_addr_ipv4, tvb, tag_offset_start + tag_offset, 4, ENC_NA);
                    tag_offset += 4;
                    break;
                    case 10: /* IPv6 */
                    proto_tree_add_item(tag_tree, hf_gquic_tag_cadr_addr_ipv6, tvb, tag_offset_start + tag_offset, 16, ENC_NA);
                    tag_offset += 16;
                    break;
                    default: /* Unknown */
                    proto_tree_add_item(tag_tree, hf_gquic_tag_cadr_addr, tvb, tag_offset_start + tag_offset, tag_len - 2 - 2, ENC_NA);
                    tag_offset += tag_len + 2 + 2 ;
                    break;
                }
                proto_tree_add_item(tag_tree, hf_gquic_tag_cadr_port, tvb, tag_offset_start + tag_offset, 2, ENC_LITTLE_ENDIAN);
                tag_offset += 2;
            }
            break;
            case TAG_MIDS:
                proto_tree_add_item(tag_tree, hf_gquic_tag_mids, tvb, tag_offset_start + tag_offset, 4, ENC_LITTLE_ENDIAN);
                proto_item_append_text(ti_tag, ": %u", tvb_get_uint32(tvb, tag_offset_start + tag_offset, ENC_LITTLE_ENDIAN));
                tag_offset += 4;
            break;
            case TAG_FHOL:
                proto_tree_add_item(tag_tree, hf_gquic_tag_fhol, tvb, tag_offset_start + tag_offset, 4, ENC_LITTLE_ENDIAN);
                proto_item_append_text(ti_tag, ": %u", tvb_get_uint32(tvb, tag_offset_start + tag_offset, ENC_LITTLE_ENDIAN));
                tag_offset += 4;
            break;
            case TAG_STTL:
                proto_tree_add_item(tag_tree, hf_gquic_tag_sttl, tvb, tag_offset_start + tag_offset, 8, ENC_LITTLE_ENDIAN);
                tag_offset += 8;
            break;
            case TAG_SMHL:
                proto_tree_add_item(tag_tree, hf_gquic_tag_smhl, tvb, tag_offset_start + tag_offset, 4, ENC_LITTLE_ENDIAN);
                proto_item_append_text(ti_tag, ": %u", tvb_get_uint32(tvb, tag_offset_start + tag_offset, ENC_LITTLE_ENDIAN));
                tag_offset += 4;
            break;
            case TAG_TBKP:
                proto_tree_add_item_ret_string(tag_tree, hf_gquic_tag_tbkp, tvb, tag_offset_start + tag_offset, 4, ENC_ASCII|ENC_NA, pinfo->pool, &tag_str);
                proto_item_append_text(ti_tag, ": %s", tag_str);
                tag_offset += 4;
            break;
            case TAG_MAD0:
                proto_tree_add_item(tag_tree, hf_gquic_tag_mad0, tvb, tag_offset_start + tag_offset, 4, ENC_LITTLE_ENDIAN);
                proto_item_append_text(ti_tag, ": %u", tvb_get_uint32(tvb, tag_offset_start + tag_offset, ENC_LITTLE_ENDIAN));
                tag_offset += 4;
            break;
            case TAG_QLVE:
            {
                proto_tree_add_item(tag_tree, hf_gquic_tag_qlve, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);

                /* Newest GQUIC versions (usually Q050) encapsulate their first flight in Q043 packets.
		 * (Q050 is handled by QUIC dissector) */
                tvbuff_t *next_tvb = tvb_new_subset_length(tvb, tag_offset_start + tag_offset, tag_len);
                call_dissector_with_data(quic_handle, next_tvb, pinfo, tag_tree, NULL);

                tag_offset += tag_len;
            }
            break;
            case TAG_CGST:
                proto_tree_add_item(tag_tree, hf_gquic_tag_cgst, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);
                tag_offset += tag_len;
            break;
            case TAG_EPID:
                proto_tree_add_item_ret_string(tag_tree, hf_gquic_tag_epid, tvb, tag_offset_start + tag_offset, tag_len, ENC_ASCII|ENC_NA, pinfo->pool, &tag_str);
                proto_item_append_text(ti_tag, ": %s", tag_str);
                tag_offset += tag_len;
            break;
            case TAG_SRST:
                proto_tree_add_item(tag_tree, hf_gquic_tag_srst, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);
                tag_offset += tag_len;
            break;
            default:
                proto_tree_add_item(tag_tree, hf_gquic_tag_unknown, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);
                expert_add_info_format(pinfo, ti_tag, &ei_gquic_tag_undecoded,
                                 "Dissector for (Google) QUIC Tag"
                                 " %s (%s) code not implemented, Contact"
                                 " Wireshark developers if you want this supported",
                                 tvb_get_string_enc(pinfo->pool, tvb, offset-8, 4, ENC_ASCII|ENC_NA),
                                 val_to_str_const(tag, tag_vals, "Unknown"));
                tag_offset += tag_len;
            break;
        }
        decrement_dissection_depth(pinfo);

        if(tag_offset != offset_end){
            /* Wrong Tag len... */
            proto_tree_add_expert(tag_tree, pinfo, &ei_gquic_tag_unknown, tvb, tag_offset_start + tag_offset, tag_len);
            tag_offset = offset_end;
        }

        tag_number--;
    }

    if (offset + total_tag_len <= offset) {
        expert_add_info_format(pinfo, gquic_tree, &ei_gquic_length_invalid,
                                "Invalid total tag length: %u", total_tag_len);
        return offset + tvb_reported_length_remaining(tvb, offset);
    }
    return offset + total_tag_len;

}

uint32_t
dissect_gquic_tags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ft_tree, unsigned offset){
    uint32_t tag_number;

    proto_tree_add_item(ft_tree, hf_gquic_tag_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    tag_number = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(ft_tree, hf_gquic_padding, tvb, offset, 2, ENC_NA);
    offset += 2;

    offset = dissect_gquic_tag(tvb, pinfo, ft_tree, offset, tag_number);

    return offset;
}

int
dissect_gquic_frame_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *gquic_tree, unsigned offset, uint8_t len_pkn, gquic_info_data_t *gquic_info){
    if (!gquic_info) {
        expert_add_info(pinfo, gquic_tree, &ei_gquic_data_invalid);
        return offset + tvb_reported_length_remaining(tvb, offset);
    }

    proto_item *ti, *ti_ft, *ti_ftflags /*, *expert_ti*/;
    proto_tree *ft_tree, *ftflags_tree;
    uint8_t frame_type;
    uint8_t num_ranges, num_revived, num_blocks = 0, num_timestamp;
    uint32_t len_stream = 0, len_offset = 0, len_data = 0, len_largest_observed = 1, len_missing_packet = 1;

    ti_ft = proto_tree_add_item(gquic_tree, hf_gquic_frame, tvb, offset, 1, ENC_NA);
    ft_tree = proto_item_add_subtree(ti_ft, ett_gquic_ft);

    /* Frame type */
    ti_ftflags = proto_tree_add_item(ft_tree, hf_gquic_frame_type, tvb, offset, 1, ENC_NA);
    frame_type = tvb_get_uint8(tvb, offset);
    proto_item_set_text(ti_ft, "%s", rval_to_str_const(frame_type, frame_type_vals, "Unknown"));

    if((frame_type & FTFLAGS_SPECIAL) == 0 && frame_type != FT_CRYPTO){ /* Regular Stream Flags */
        offset += 1;
        switch(frame_type){
            case FT_PADDING:{
                proto_item *ti_pad_len;
                uint32_t pad_len = tvb_reported_length_remaining(tvb, offset);

                ti_pad_len = proto_tree_add_uint(ft_tree, hf_gquic_frame_type_padding_length, tvb, offset, 0, pad_len);
                proto_item_set_generated(ti_pad_len);
                proto_item_append_text(ti_ft, " Length: %u", pad_len);
                if(pad_len > 0) /* Avoid Malformed Exception with pad_len == 0 */
		    proto_tree_add_item(ft_tree, hf_gquic_frame_type_padding, tvb, offset, -1, ENC_NA);
                offset += pad_len;
                }
            break;
            case FT_RST_STREAM:{
                uint32_t stream_id, error_code;
                proto_tree_add_item_ret_uint(ft_tree, hf_gquic_frame_type_rsts_stream_id, tvb, offset, 4, gquic_info->encoding, &stream_id);
                offset += 4;
                proto_tree_add_item(ft_tree, hf_gquic_frame_type_rsts_byte_offset, tvb, offset, 8, gquic_info->encoding);
                offset += 8;
                proto_tree_add_item_ret_uint(ft_tree, hf_gquic_frame_type_rsts_error_code, tvb, offset, 4, gquic_info->encoding, &error_code);
                offset += 4;
                proto_item_append_text(ti_ft, " Stream ID: %u, Error code: %s", stream_id, val_to_str_ext(error_code, &rststream_error_code_vals_ext, "Unknown (%d)"));
                col_set_str(pinfo->cinfo, COL_INFO, "RST STREAM");
                }
            break;
            case FT_CONNECTION_CLOSE:{
                uint16_t len_reason;
                uint32_t error_code;

                proto_tree_add_item_ret_uint(ft_tree, hf_gquic_frame_type_cc_error_code, tvb, offset, 4, gquic_info->encoding, &error_code);
                offset += 4;
                proto_tree_add_item(ft_tree, hf_gquic_frame_type_cc_reason_phrase_length, tvb, offset, 2, gquic_info->encoding);
                len_reason = tvb_get_uint16(tvb, offset, gquic_info->encoding);
                offset += 2;
                proto_tree_add_item(ft_tree, hf_gquic_frame_type_cc_reason_phrase, tvb, offset, len_reason, ENC_ASCII);
                offset += len_reason;
                proto_item_append_text(ti_ft, " Error code: %s", val_to_str_ext(error_code, &error_code_vals_ext, "Unknown (%d)"));
                col_set_str(pinfo->cinfo, COL_INFO, "Connection Close");
                }
            break;
            case FT_GOAWAY:{
                uint16_t len_reason;
                uint32_t error_code, last_good_stream_id;

                proto_tree_add_item_ret_uint(ft_tree, hf_gquic_frame_type_goaway_error_code, tvb, offset, 4, gquic_info->encoding, &error_code);
                offset += 4;
                proto_tree_add_item_ret_uint(ft_tree, hf_gquic_frame_type_goaway_last_good_stream_id, tvb, offset, 4, gquic_info->encoding, &last_good_stream_id);
                offset += 4;
                proto_tree_add_item(ft_tree, hf_gquic_frame_type_goaway_reason_phrase_length, tvb, offset, 2, gquic_info->encoding);
                len_reason = tvb_get_uint16(tvb, offset, gquic_info->encoding);
                offset += 2;
                proto_tree_add_item(ft_tree, hf_gquic_frame_type_goaway_reason_phrase, tvb, offset, len_reason, ENC_ASCII);
                offset += len_reason;
                proto_item_append_text(ti_ft, " Stream ID: %u, Error code: %s", last_good_stream_id, val_to_str_ext(error_code, &error_code_vals_ext, "Unknown (%d)"));
                col_set_str(pinfo->cinfo, COL_INFO, "GOAWAY");
                }
            break;
            case FT_WINDOW_UPDATE:{
                uint32_t stream_id;

                proto_tree_add_item_ret_uint(ft_tree, hf_gquic_frame_type_wu_stream_id, tvb, offset, 4, gquic_info->encoding, &stream_id);
                offset += 4;
                proto_tree_add_item(ft_tree, hf_gquic_frame_type_wu_byte_offset, tvb, offset, 8, gquic_info->encoding);
                offset += 8;
                proto_item_append_text(ti_ft, " Stream ID: %u", stream_id);
                }
            break;
            case FT_BLOCKED:{
                uint32_t stream_id;

                proto_tree_add_item_ret_uint(ft_tree, hf_gquic_frame_type_blocked_stream_id, tvb, offset, 4, gquic_info->encoding, &stream_id);
                offset += 4;
                proto_item_append_text(ti_ft, " Stream ID: %u", stream_id);
                }
            break;
            case FT_STOP_WAITING:{
                uint8_t send_entropy;
                if(gquic_info->version_valid && gquic_info->version < 34){ /* No longer Entropy after Q034 */
                    proto_tree_add_item(ft_tree, hf_gquic_frame_type_sw_send_entropy, tvb, offset, 1, ENC_NA);
                    send_entropy = tvb_get_uint8(tvb, offset);
                    proto_item_append_text(ti_ft, " Send Entropy: %u", send_entropy);
                    offset += 1;
                }
                proto_tree_add_item(ft_tree, hf_gquic_frame_type_sw_least_unacked_delta, tvb, offset, len_pkn, gquic_info->encoding);
                offset += len_pkn;

                }
            break;
            case FT_PING: /* No Payload */
            default: /* No default */
            break;
        }
    }
    else { /* Special Frame Types */
        uint32_t stream_id, message_tag;
        const uint8_t* message_tag_str;
        proto_item *ti_stream;

        ftflags_tree = proto_item_add_subtree(ti_ftflags, ett_gquic_ftflags);
        proto_tree_add_item(ftflags_tree, hf_gquic_frame_type_stream , tvb, offset, 1, ENC_NA);

        if(frame_type == FT_CRYPTO) {
            uint64_t crypto_offset, crypto_length;
            int32_t lenvar;

            DISSECTOR_ASSERT(gquic_info->version_valid && gquic_info->version >= 50);

            col_append_str(pinfo->cinfo, COL_INFO, ", CRYPTO");
            offset += 1;
            proto_tree_add_item_ret_varint(ft_tree, hf_gquic_crypto_offset, tvb, offset, -1, ENC_VARINT_QUIC, &crypto_offset, &lenvar);
            offset += lenvar;
            proto_tree_add_item_ret_varint(ft_tree, hf_gquic_crypto_length, tvb, offset, -1, ENC_VARINT_QUIC, &crypto_length, &lenvar);
            offset += lenvar;
            proto_tree_add_item(ft_tree, hf_gquic_crypto_crypto_data, tvb, offset, (uint32_t)crypto_length, ENC_NA);

            if (gquic_info->version == 50) {
                message_tag = tvb_get_ntohl(tvb, offset);
                ti = proto_tree_add_item_ret_string(ft_tree, hf_gquic_tag, tvb, offset, 4, ENC_ASCII|ENC_NA, pinfo->pool, &message_tag_str);
                proto_item_append_text(ti, " (%s)", val_to_str_const(message_tag, message_tag_vals, "Unknown Tag"));
                col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(message_tag, message_tag_vals, "Unknown"));
                offset += 4;

                offset = dissect_gquic_tags(tvb, pinfo, ft_tree, offset);
	    } else { /* T050 and T051 */
                tvbuff_t *next_tvb = tvb_new_subset_length(tvb, offset, (int)crypto_length);
                col_set_writable(pinfo->cinfo, -1, false);
                call_dissector_with_data(tls13_handshake_handle, next_tvb, pinfo, ft_tree, GUINT_TO_POINTER(crypto_offset));
                col_set_writable(pinfo->cinfo, -1, true);
                offset += (uint32_t)crypto_length;
	    }

	} else if(frame_type & FTFLAGS_STREAM){ /* Stream Flags */
            proto_tree_add_item(ftflags_tree, hf_gquic_frame_type_stream_f, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(ftflags_tree, hf_gquic_frame_type_stream_d, tvb, offset, 1, ENC_NA);
            if(frame_type & FTFLAGS_STREAM_D){
                len_data = 2;
            }
            proto_tree_add_item(ftflags_tree, hf_gquic_frame_type_stream_ooo, tvb, offset, 1, ENC_NA);

            len_offset = get_len_offset(frame_type);

            proto_tree_add_item(ftflags_tree, hf_gquic_frame_type_stream_ss, tvb, offset, 1, ENC_NA);
            len_stream = get_len_stream(frame_type);
            offset += 1;

            ti_stream = proto_tree_add_item_ret_uint(ft_tree, hf_gquic_stream_id, tvb, offset, len_stream, gquic_info->encoding, &stream_id);
            offset += len_stream;

            proto_item_append_text(ti_ft, " Stream ID: %u", stream_id);

            if(len_offset) {
                proto_tree_add_item(ft_tree, hf_gquic_offset, tvb, offset, len_offset, gquic_info->encoding);
                offset += len_offset;
            }

            if(len_data) {
                proto_tree_add_item(ft_tree, hf_gquic_data_len, tvb, offset, len_data, gquic_info->encoding);
                offset += len_data;
            }

            /* Check if there is some reserved streams (Chapiter 6.1 of draft-shade-gquic-http2-mapping-00) */

            switch(stream_id) {
                case 1: { /* Reserved (G)QUIC (handshake, crypto, config updates...) */
                    message_tag = tvb_get_ntohl(tvb, offset);
                    ti = proto_tree_add_item_ret_string(ft_tree, hf_gquic_tag, tvb, offset, 4, ENC_ASCII|ENC_NA, pinfo->pool, &message_tag_str);

                    proto_item_append_text(ti_stream, " (Reserved for (G)QUIC handshake, crypto, config updates...)");
                    proto_item_append_text(ti, " (%s)", val_to_str_const(message_tag, message_tag_vals, "Unknown Tag"));
                    proto_item_append_text(ti_ft, ", Type: %s (%s)", message_tag_str, val_to_str_const(message_tag, message_tag_vals, "Unknown Tag"));
                    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(message_tag, message_tag_vals, "Unknown"));
                    offset += 4;

                    offset = dissect_gquic_tags(tvb, pinfo, ft_tree, offset);
                break;
                }
                case 3: { /* Reserved H2 HEADERS (or PUSH_PROMISE..) */
                    tvbuff_t* tvb_h2;

                    proto_item_append_text(ti_stream, " (Reserved for H2 HEADERS)");

                    col_set_str(pinfo->cinfo, COL_INFO, "H2");

                    tvb_h2 = tvb_new_subset_remaining(tvb, offset);

                    offset += dissect_http2_pdu(tvb_h2, pinfo, ft_tree, NULL);
                }
                break;
                default: { /* Data... */
                    int data_len = tvb_reported_length_remaining(tvb, offset);

                    col_set_str(pinfo->cinfo, COL_INFO, "DATA");

                    proto_tree_add_item(ft_tree, hf_gquic_stream_data, tvb, offset, data_len, ENC_NA);
                    offset += data_len;
                }
                break;
            }
        } else if (frame_type & FTFLAGS_ACK) {     /* ACK Flags */

            proto_tree_add_item(ftflags_tree, hf_gquic_frame_type_ack, tvb, offset, 1, ENC_NA);

            proto_tree_add_item(ftflags_tree, hf_gquic_frame_type_ack_n, tvb, offset, 1, ENC_NA);

            if(gquic_info->version_valid && gquic_info->version < 34){ /* No longer NACK after Q034 */
                proto_tree_add_item(ftflags_tree, hf_gquic_frame_type_ack_t, tvb, offset, 1, ENC_NA);
            } else {
                proto_tree_add_item(ftflags_tree, hf_gquic_frame_type_ack_u, tvb, offset, 1, ENC_NA);
            }
            proto_tree_add_item(ftflags_tree, hf_gquic_frame_type_ack_ll, tvb, offset, 1, ENC_NA);

            len_largest_observed = get_len_largest_observed(frame_type);

            proto_tree_add_item(ftflags_tree, hf_gquic_frame_type_ack_mm, tvb, offset, 1, ENC_NA);
            len_missing_packet = get_len_missing_packet(frame_type);
            offset += 1;

            if(gquic_info->version_valid && gquic_info->version < 34){ /* Big change after Q034 */
                proto_tree_add_item(ft_tree, hf_gquic_frame_type_ack_received_entropy, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(ft_tree, hf_gquic_frame_type_ack_largest_observed, tvb, offset, len_largest_observed, gquic_info->encoding);
                offset += len_largest_observed;

                proto_tree_add_item(ft_tree, hf_gquic_frame_type_ack_ack_delay_time, tvb, offset, 2, gquic_info->encoding);
                offset += 2;

                proto_tree_add_item(ft_tree, hf_gquic_frame_type_ack_num_timestamp, tvb, offset, 1, ENC_NA);
                num_timestamp = tvb_get_uint8(tvb, offset);
                offset += 1;

                if(num_timestamp){

                    /* Delta Largest Observed */
                    proto_tree_add_item(ft_tree, hf_gquic_frame_type_ack_delta_largest_observed, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    /* First Timestamp */
                    proto_tree_add_item(ft_tree, hf_gquic_frame_type_ack_first_timestamp, tvb, offset, 4, gquic_info->encoding);
                    offset += 4;

                    num_timestamp -= 1;
                    /* Num Timestamp (-1) x (Delta Largest Observed + Time Since Previous Timestamp) */
                    while(num_timestamp){
                        proto_tree_add_item(ft_tree, hf_gquic_frame_type_ack_delta_largest_observed, tvb, offset, 1, ENC_NA);
                        offset += 1;

                        proto_tree_add_item(ft_tree, hf_gquic_frame_type_ack_time_since_previous_timestamp, tvb, offset, 2, gquic_info->encoding);
                        offset += 2;

                        num_timestamp--;
                    }
                }

                if(frame_type & FTFLAGS_ACK_N){
                    proto_tree_add_item(ft_tree, hf_gquic_frame_type_ack_num_ranges, tvb, offset, 1, ENC_NA);
                    num_ranges = tvb_get_uint8(tvb, offset);
                    offset += 1;
                    while(num_ranges){

                        proto_tree_add_item(ft_tree, hf_gquic_frame_type_ack_missing_packet, tvb, offset, len_missing_packet, gquic_info->encoding);
                        offset += len_missing_packet;

                        proto_tree_add_item(ft_tree, hf_gquic_frame_type_ack_range_length, tvb, offset, 1, ENC_NA);
                        offset += 1;
                        num_ranges--;
                    }

                    proto_tree_add_item(ft_tree, hf_gquic_frame_type_ack_num_revived, tvb, offset, 1, ENC_NA);
                    num_revived = tvb_get_uint8(tvb, offset);
                    offset += 1;
                    while(num_revived){

                        proto_tree_add_item(ft_tree, hf_gquic_frame_type_ack_revived_packet, tvb, offset, len_largest_observed, gquic_info->encoding);
                        offset += len_largest_observed;
                        num_revived--;

                    }

                }

            } else {

                /* Largest Acked */
                proto_tree_add_item(ft_tree, hf_gquic_frame_type_ack_largest_acked, tvb, offset, len_largest_observed, gquic_info->encoding);
                offset += len_largest_observed;

                /* Largest Acked Delta Time*/
                proto_tree_add_item(ft_tree, hf_gquic_frame_type_ack_largest_acked_delta_time, tvb, offset, 2, gquic_info->encoding);
                offset += 2;

                /* Ack Block */
                if(frame_type & FTFLAGS_ACK_N){
                    proto_tree_add_item(ft_tree, hf_gquic_frame_type_ack_num_blocks, tvb, offset, 1, ENC_NA);
                    num_blocks = tvb_get_uint8(tvb, offset);
                    offset += 1;
                }

                /* First Ack Block Length */
                proto_tree_add_item(ft_tree, hf_gquic_frame_type_ack_first_ack_block_length, tvb, offset, len_missing_packet, gquic_info->encoding);
                offset += len_missing_packet;

                while(num_blocks){
                    /* Gap to next block */
                    proto_tree_add_item(ft_tree, hf_gquic_frame_type_ack_gap_to_next_block, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    /* Ack Block Length */
                    proto_tree_add_item(ft_tree, hf_gquic_frame_type_ack_ack_block_length, tvb, offset, len_missing_packet, gquic_info->encoding);
                    offset += len_missing_packet;

                    num_blocks--;
                }

                /* Timestamp */
                proto_tree_add_item(ft_tree, hf_gquic_frame_type_ack_num_timestamp, tvb, offset, 1, ENC_NA);
                num_timestamp = tvb_get_uint8(tvb, offset);
                offset += 1;

                if(num_timestamp){

                    /* Delta Largest Acked */
                    proto_tree_add_item(ft_tree, hf_gquic_frame_type_ack_delta_largest_acked, tvb, offset, 1, ENC_NA);
                    offset += 1;

                    /* Time Since Largest Acked */
                    proto_tree_add_item(ft_tree, hf_gquic_frame_type_ack_time_since_largest_acked, tvb, offset, 4, gquic_info->encoding);
                    offset += 4;

                    num_timestamp -= 1;
                    /* Num Timestamp x (Delta Largest Acked + Time Since Previous Timestamp) */
                    while(num_timestamp){
                        proto_tree_add_item(ft_tree, hf_gquic_frame_type_ack_delta_largest_acked, tvb, offset, 1, ENC_NA);
                        offset += 1;

                        proto_tree_add_item(ft_tree, hf_gquic_frame_type_ack_time_since_previous_timestamp, tvb, offset, 2, gquic_info->encoding);
                        offset += 2;

                        num_timestamp--;
                    }
                }

            }

        } else { /* Other ...*/
            offset += 1;
        }
    }
    return offset;

}

static int
dissect_gquic_unencrypt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *gquic_tree, unsigned offset, uint8_t len_pkn, gquic_info_data_t *gquic_info){
    proto_item *ti_prflags;
    proto_tree *prflags_tree;

    /* Message Authentication Hash */
    proto_tree_add_item(gquic_tree, hf_gquic_message_authentication_hash, tvb, offset, 12, ENC_NA);
    offset += 12;

    if(gquic_info->version_valid && gquic_info->version < 34){ /* No longer Private Flags after Q034 */
        /* Private Flags */
        ti_prflags = proto_tree_add_item(gquic_tree, hf_gquic_prflags, tvb, offset, 1, ENC_NA);
        prflags_tree = proto_item_add_subtree(ti_prflags, ett_gquic_prflags);
        proto_tree_add_item(prflags_tree, hf_gquic_prflags_entropy, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(prflags_tree, hf_gquic_prflags_fecg, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(prflags_tree, hf_gquic_prflags_fec, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(prflags_tree, hf_gquic_prflags_rsv, tvb, offset, 1, ENC_NA);
        offset += 1;
    }

    while(tvb_reported_length_remaining(tvb, offset) > 0){
        offset = dissect_gquic_frame_type(tvb, pinfo, gquic_tree, offset, len_pkn, gquic_info);
    }

    return offset;

}

static int
dissect_gquic_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_item *ti, *ti_puflags; /*, *expert_ti*/
    proto_tree *gquic_tree, *puflags_tree;
    unsigned offset = 0;
    uint8_t puflags, len_cid = 0, len_pkn;
    uint64_t cid = 0, pkn;
    conversation_t  *conv;
    gquic_info_data_t  *gquic_info;

    if (tvb_captured_length(tvb) < GQUIC_MIN_LENGTH)
        return 0;


    /* get conversation, create if necessary*/
    conv = find_or_create_conversation(pinfo);

    /* get associated state information, create if necessary */
    gquic_info = (gquic_info_data_t *)conversation_get_proto_data(conv, proto_gquic);

    if (!gquic_info) {
        gquic_info = wmem_new(wmem_file_scope(), gquic_info_data_t);
        gquic_info->version = 0;
        gquic_info->encoding = ENC_LITTLE_ENDIAN;
        gquic_info->version_valid = true;
        gquic_info->server_port = 443;
        conversation_add_proto_data(conv, proto_gquic, gquic_info);
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GQUIC");

    ti = proto_tree_add_item(tree, proto_gquic, tvb, 0, -1, ENC_NA);
    gquic_tree = proto_item_add_subtree(ti, ett_gquic);

    /* Public Flags */
    puflags = tvb_get_uint8(tvb, offset);

    /* Get len of CID */
    if(puflags & PUFLAGS_CID){
        len_cid = 8;
    }
    /* check and get (and store) version */
    if(puflags & PUFLAGS_VRSN){
        gquic_info->version_valid = ws_strtou8(tvb_get_string_enc(pinfo->pool, tvb,
            offset + 1 + len_cid + 1, 3, ENC_ASCII), NULL, &gquic_info->version);
        if (!gquic_info->version_valid)
            expert_add_info(pinfo, gquic_tree, &ei_gquic_version_invalid);
    }

    if(gquic_info->version >= 39){ /* After Q039, Integers and floating numbers are written in big endian*/
        gquic_info->encoding = ENC_BIG_ENDIAN;
    }
    ti_puflags = proto_tree_add_item(gquic_tree, hf_gquic_puflags, tvb, offset, 1, ENC_NA);
    puflags_tree = proto_item_add_subtree(ti_puflags, ett_gquic_puflags);
    proto_tree_add_item(puflags_tree, hf_gquic_puflags_vrsn, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(puflags_tree, hf_gquic_puflags_rst, tvb, offset, 1, ENC_NA);
    if (gquic_info->version_valid) {
        if(gquic_info->version < 33){
            proto_tree_add_item(puflags_tree, hf_gquic_puflags_cid_old, tvb, offset, 1, ENC_NA);
        } else {
            proto_tree_add_item(puflags_tree, hf_gquic_puflags_dnonce, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(puflags_tree, hf_gquic_puflags_cid, tvb, offset, 1, ENC_NA);
        }
    }
    proto_tree_add_item(puflags_tree, hf_gquic_puflags_pkn, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(puflags_tree, hf_gquic_puflags_mpth, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(puflags_tree, hf_gquic_puflags_rsv, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* CID */
    if (len_cid) {
        cid = tvb_get_uint64(tvb, offset, gquic_info->encoding);
        proto_tree_add_item(gquic_tree, hf_gquic_cid, tvb, offset, len_cid, gquic_info->encoding);
        offset += len_cid;
    }

    /* Version */
    if(puflags & PUFLAGS_VRSN){
        if(pinfo->srcport == gquic_info->server_port){ /* Version Negotiation Packet */
            while(tvb_reported_length_remaining(tvb, offset) > 0){
                proto_tree_add_item(gquic_tree, hf_gquic_version, tvb, offset, 4, ENC_ASCII);
                offset += 4;
            }
            col_add_fstr(pinfo->cinfo, COL_INFO, "Version Negotiation, CID: %" PRIu64, cid);
            return offset;
        }
        else{
            proto_tree_add_item(gquic_tree, hf_gquic_version, tvb, offset, 4, ENC_ASCII);
            offset += 4;
        }
    }

    /* Public Reset Packet */
    if(puflags & PUFLAGS_RST){
        uint32_t tag_number, message_tag;

        ti = proto_tree_add_item(gquic_tree, hf_gquic_tag, tvb, offset, 4, ENC_ASCII);
        message_tag = tvb_get_ntohl(tvb, offset);
        proto_item_append_text(ti, " (%s)", val_to_str_const(message_tag, message_tag_vals, "Unknown Tag"));
        offset += 4;

        proto_tree_add_item(gquic_tree, hf_gquic_tag_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        tag_number = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(gquic_tree, hf_gquic_padding, tvb, offset, 2, ENC_NA);
        offset += 2;

        offset = dissect_gquic_tag(tvb, pinfo, gquic_tree, offset, tag_number);

        col_add_fstr(pinfo->cinfo, COL_INFO, "Public Reset, CID: %" PRIu64, cid);

        return offset;
    }

    /* Diversification Nonce */
    if(gquic_info->version_valid && (puflags & PUFLAGS_DNONCE) && (gquic_info->version >= 33)){
        if(pinfo->srcport == gquic_info->server_port){ /* Diversification nonce is only present from server to client */
            proto_tree_add_item(gquic_tree, hf_gquic_diversification_nonce, tvb, offset, 32, ENC_NA);
            offset += 32;
        }
    }

    /* Packet Number */

    /* Get len of packet number */
    len_pkn = get_len_packet_number(puflags);
    proto_tree_add_item_ret_uint64(gquic_tree, hf_gquic_packet_number, tvb, offset, len_pkn, gquic_info->encoding, &pkn);
    offset += len_pkn;

    /* Unencrypt Message (Handshake or Connection Close...) */
    if (is_gquic_unencrypt(tvb, pinfo, offset, len_pkn, gquic_info) || g_gquic_debug){
        offset = dissect_gquic_unencrypt(tvb, pinfo, gquic_tree, offset, len_pkn, gquic_info);
    }else {     /* Payload... (encrypted... TODO FIX !) */
        col_set_str(pinfo->cinfo, COL_INFO, "Payload (Encrypted)");
        proto_tree_add_item(gquic_tree, hf_gquic_payload, tvb, offset, -1, ENC_NA);

    }

    col_append_fstr(pinfo->cinfo, COL_INFO, ", PKN: %" PRIu64, pkn);

    if(cid){
        col_append_fstr(pinfo->cinfo, COL_INFO, ", CID: %" PRIu64, cid);
    }


    return offset;
}

static int
dissect_gquic_q046(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_item *ti, *ti_firstbyte; /*, *expert_ti*/
    proto_tree *gquic_tree, *firstbyte_tree;
    unsigned offset = 0;
    uint8_t first_byte, len_cid, cil, len_pkn;
    uint64_t cid = 0, pkn = 0;
    conversation_t  *conv;
    gquic_info_data_t  *gquic_info;

    /* get conversation, create if necessary*/
    conv = find_or_create_conversation(pinfo);

    /* get associated state information, create if necessary */
    gquic_info = (gquic_info_data_t *)conversation_get_proto_data(conv, proto_gquic);

    if (!gquic_info) {
        gquic_info = wmem_new(wmem_file_scope(), gquic_info_data_t);
        gquic_info->version = 0;
        gquic_info->encoding = ENC_BIG_ENDIAN;
        gquic_info->version_valid = true;
        gquic_info->server_port = 443;
        conversation_add_proto_data(conv, proto_gquic, gquic_info);
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GQUIC");

    ti = proto_tree_add_item(tree, proto_gquic, tvb, 0, -1, ENC_NA);
    gquic_tree = proto_item_add_subtree(ti, ett_gquic);

    /* First byte */
    first_byte = tvb_get_uint8(tvb, offset);
    len_pkn = (first_byte & 0x03) + 1;

    ti_firstbyte = proto_tree_add_item(gquic_tree, hf_gquic_puflags, tvb, offset, 1, ENC_NA);
    firstbyte_tree = proto_item_add_subtree(ti_firstbyte, ett_gquic_puflags);
    proto_tree_add_item(firstbyte_tree, hf_gquic_header_form, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(firstbyte_tree, hf_gquic_fixed_bit, tvb, offset, 1, ENC_NA);

    if((first_byte & PUFLAGS_MPTH) && (first_byte & PUFLAGS_RSV)) {
        /* Long Header. We handle only Q046 */

	gquic_info->version_valid = ws_strtou8(tvb_get_string_enc(pinfo->pool, tvb,
            offset + 2, 3, ENC_ASCII), NULL, &gquic_info->version);
        if (!gquic_info->version_valid) {
            expert_add_info(pinfo, gquic_tree, &ei_gquic_version_invalid);
        }

	cil = tvb_get_uint8(tvb, offset + 5);
	if(pinfo->srcport == gquic_info->server_port) { /* Server to client */
	    len_cid = (cil & 0x0F) + 3;
	} else {
	    len_cid = ((cil & 0xF0) >> 4) + 3;
	}
	if (len_cid != 8) {
            expert_add_info(pinfo, gquic_tree, &ei_gquic_invalid_parameter);
        }

        proto_tree_add_item(firstbyte_tree, hf_gquic_long_packet_type, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(firstbyte_tree, hf_gquic_long_reserved, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(firstbyte_tree, hf_gquic_packet_number_length, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(gquic_tree, hf_gquic_version, tvb, offset, 4, ENC_ASCII);
        offset += 4;

        proto_tree_add_item(gquic_tree, hf_gquic_dcil, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(gquic_tree, hf_gquic_scil, tvb, offset, 1, ENC_NA);
        offset += 1;

        /* CID */
        if (len_cid > 0) {
            cid = tvb_get_uint64(tvb, offset, gquic_info->encoding);
            proto_tree_add_item(gquic_tree, hf_gquic_cid, tvb, offset, len_cid, gquic_info->encoding);
        }
        offset += len_cid;

    } else {
        /* Short Header. We handle only Q046 */

        proto_tree_add_uint(firstbyte_tree, hf_gquic_packet_number_length, tvb, offset, 1, first_byte);

        offset += 1;

        if(pinfo->srcport == gquic_info->server_port) { /* Server to client */
            len_cid = 0;
        } else {
            len_cid = 8;
            cid = tvb_get_uint64(tvb, offset, gquic_info->encoding);
            proto_tree_add_item(gquic_tree, hf_gquic_cid, tvb, offset, len_cid, gquic_info->encoding);
        }
        offset += len_cid;
    }

    /* Packet Number */
    proto_tree_add_item_ret_uint64(gquic_tree, hf_gquic_packet_number, tvb, offset, len_pkn, gquic_info->encoding, &pkn);
    offset += len_pkn;

    /* Unencrypt Message (Handshake or Connection Close...) */
    if (is_gquic_unencrypt(tvb, pinfo, offset, len_pkn, gquic_info) || g_gquic_debug){
        offset = dissect_gquic_unencrypt(tvb, pinfo, gquic_tree, offset, len_pkn, gquic_info);
    }else {     /* Payload... (encrypted... TODO FIX !) */
        col_set_str(pinfo->cinfo, COL_INFO, "Payload (Encrypted)");
        proto_tree_add_item(gquic_tree, hf_gquic_payload, tvb, offset, -1, ENC_NA);

    }

    col_append_fstr(pinfo->cinfo, COL_INFO, ", PKN: %" PRIu64, pkn);

    if(cid){
        col_append_fstr(pinfo->cinfo, COL_INFO, ", CID: %" PRIu64, cid);
    }

    return offset;
}

static int
dissect_gquic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
              void *data _U_)
{
    uint8_t flags;

    flags = tvb_get_uint8(tvb, 0);
    if((flags & PUFLAGS_RSV) == 0 && (flags & PUFLAGS_MPTH) == 0)
        return dissect_gquic_common(tvb, pinfo, tree, NULL);
    return dissect_gquic_q046(tvb, pinfo, tree, NULL);
}

static bool dissect_gquic_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{

    conversation_t *conversation = NULL;
    int offset = 0;
    uint8_t flags;
    uint32_t version;

    if (tvb_captured_length(tvb) < 1) {
        return false;
    }
    flags = tvb_get_uint8(tvb, offset);
    offset += 1;

    if((flags & PUFLAGS_RSV) == 0 && (flags & PUFLAGS_MPTH) == 0) {
        /* It may be <= Q043 */

        /* Verify packet size  (Flag (1 byte) + Connection ID (8 bytes) + Version (4 bytes)) */
        if (tvb_captured_length(tvb) < 13) {
            return false;
        }

        /* Check if flags version is set */
        if((flags & PUFLAGS_VRSN) == 0) {
            return false;
        }

        /* Connection ID is always set to "long" (8bytes) too */
        if((flags & PUFLAGS_CID) == 0){
            return false;
        }
        offset += 8;

        /* Check if version start with Q02... (0x51 0x30 0x32), Q03... (0x51 0x30 0x33) or Q04... (0x51 0x30 0x34) */
        version = tvb_get_ntoh24(tvb, offset);
        if ( version == GQUIC_MAGIC2 || version == GQUIC_MAGIC3 || version == GQUIC_MAGIC4) {
            conversation = find_or_create_conversation(pinfo);
            conversation_set_dissector(conversation, gquic_handle);
            dissect_gquic(tvb, pinfo, tree, data);
            return true;
        }
    } else if((flags & PUFLAGS_MPTH) && (flags & PUFLAGS_RSV)) {
        /* It may be > Q043, Long Header. We handle only Q046 */

        /* Verify packet size  (Flag (1 byte) + Version (4) + DCIL/SCIL (1) + Dest Connection ID (8 bytes)) */
        if (tvb_captured_length(tvb) < 14) {
            return false;
        }

        version = tvb_get_ntohl(tvb, offset);
        if (version != GQUIC_VERSION_Q046) {
            return false;
        }

        conversation = find_or_create_conversation(pinfo);
        conversation_set_dissector(conversation, gquic_handle);
        dissect_gquic(tvb, pinfo, tree, data);
        return true;
    }

    return false;
}

void
proto_register_gquic(void)
{
    module_t *gquic_module;

    static hf_register_info hf[] = {
        /* Long/Short header for Q046 */
        { &hf_gquic_header_form,
          { "Header Form", "gquic.header_form",
            FT_UINT8, BASE_DEC, VALS(gquic_short_long_header_vals), 0x80,
            "The most significant bit (0x80) of the first octet is set to 1 for long headers and 0 for short headers.", HFILL }
        },
        { &hf_gquic_fixed_bit,
          { "Fixed Bit", "gquic.fixed_bit",
            FT_BOOLEAN, 8, NULL, 0x40,
            "Must be 1", HFILL }
        },
        { &hf_gquic_long_packet_type,
          { "Packet Type", "gquic.long.packet_type",
            FT_UINT8, BASE_DEC, VALS(gquic_long_packet_type_vals), 0x30,
            "Long Header Packet Type", HFILL }
        },
        { &hf_gquic_long_reserved,
          { "Reserved", "gquic.long.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x0c,
            "Reserved bits", HFILL }
        },
        { &hf_gquic_packet_number_length,
          { "Packet Number Length", "gquic.packet_number_length",
            FT_UINT8, BASE_DEC, VALS(gquic_packet_number_lengths), 0x03,
            "Packet Number field length", HFILL }
	},
        { &hf_gquic_dcil,
          { "Destination Connection ID Length", "gquic.dcil",
            FT_UINT8, BASE_DEC, VALS(quic_cid_lengths), 0xF0,
            NULL, HFILL }
        },
        { &hf_gquic_scil,
          { "Source Connection ID Length", "gquic.scil",
            FT_UINT8, BASE_DEC, VALS(quic_cid_lengths), 0x0F,
            NULL, HFILL }
        },

        /* Public header for < Q046 */
        { &hf_gquic_puflags,
            { "Public Flags", "gquic.puflags",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              "Specifying per-packet public flags", HFILL }
        },
        { &hf_gquic_puflags_vrsn,
            { "Version", "gquic.puflags.version",
              FT_BOOLEAN, 8, TFS(&tfs_yes_no), PUFLAGS_VRSN,
              "Signifies that this packet also contains the version of the (Google)QUIC protocol", HFILL }
        },
        { &hf_gquic_puflags_rst,
            { "Reset", "gquic.puflags.reset",
              FT_BOOLEAN, 8, TFS(&tfs_yes_no), PUFLAGS_RST,
              "Signifies that this packet is a public reset packet", HFILL }
        },
        { &hf_gquic_puflags_dnonce,
            { "Diversification nonce", "gquic.puflags.nonce",
              FT_BOOLEAN, 8, TFS(&tfs_yes_no), PUFLAGS_DNONCE,
              "Indicates the presence of a 32 byte diversification nonce", HFILL }
        },
        { &hf_gquic_puflags_cid,
            { "CID Length", "gquic.puflags.cid",
              FT_BOOLEAN, 8, TFS(&puflags_cid_tfs), PUFLAGS_CID,
              "Indicates the full 8 byte Connection ID is present", HFILL }
        },
        { &hf_gquic_puflags_cid_old,
            { "CID Length", "gquic.puflags.cid.old",
              FT_UINT8, BASE_HEX, VALS(puflags_cid_old_vals), PUFLAGS_CID_OLD,
              "Signifies the Length of CID", HFILL }
        },
        { &hf_gquic_puflags_pkn,
            { "Packet Number Length", "gquic.puflags.pkn",
              FT_UINT8, BASE_HEX, VALS(puflags_pkn_vals), PUFLAGS_PKN,
              "Signifies the Length of packet number", HFILL }
        },
        { &hf_gquic_puflags_mpth,
            { "Multipath", "gquic.puflags.mpth",
              FT_BOOLEAN, 8, TFS(&tfs_yes_no), PUFLAGS_MPTH,
              "Reserved for multipath use", HFILL }
        },
        { &hf_gquic_puflags_rsv,
            { "Reserved", "gquic.puflags.rsv",
              FT_UINT8, BASE_HEX, NULL, PUFLAGS_RSV,
              "Must be Zero", HFILL }
        },
        { &hf_gquic_cid,
            { "CID", "gquic.cid",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Connection ID 64 bit pseudo random number", HFILL }
        },
        { &hf_gquic_version,
            { "Version", "gquic.version",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "32 bit opaque tag that represents the version of the (Google)QUIC", HFILL }
        },
        { &hf_gquic_diversification_nonce,
            { "Diversification nonce", "gquic.diversification_nonce",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_packet_number,
            { "Packet Number", "gquic.packet_number",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "The lower 8, 16, 32, or 48 bits of the packet number", HFILL }
        },

        { &hf_gquic_prflags,
            { "Private Flags", "gquic.prflags",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              "Specifying per-packet Private flags", HFILL }
        },

        { &hf_gquic_prflags_entropy,
            { "Entropy", "gquic.prflags.entropy",
              FT_BOOLEAN, 8, TFS(&tfs_yes_no), PRFLAGS_ENTROPY,
              "For data packets, signifies that this packet contains the 1 bit of entropy, for fec packets, contains the xor of the entropy of protected packets", HFILL }
        },
        { &hf_gquic_prflags_fecg,
            { "FEC Group", "gquic.prflags.fecg",
              FT_BOOLEAN, 8, TFS(&tfs_yes_no), PRFLAGS_FECG,
              "Indicates whether the fec byte is present.", HFILL }
        },
        { &hf_gquic_prflags_fec,
            { "FEC", "gquic.prflags.fec",
              FT_BOOLEAN, 8, TFS(&tfs_yes_no), PRFLAGS_FEC,
              "Signifies that this packet represents an FEC packet", HFILL }
        },
        { &hf_gquic_prflags_rsv,
            { "Reserved", "gquic.prflags.rsv",
              FT_UINT8, BASE_HEX, NULL, PRFLAGS_RSV,
              "Must be Zero", HFILL }
        },

        { &hf_gquic_message_authentication_hash,
            { "Message Authentication Hash", "gquic.message_authentication_hash",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "The hash is an FNV1a-128 hash, serialized in little endian order", HFILL }
        },
        { &hf_gquic_frame,
            { "Frame", "gquic.frame",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_frame_type,
            { "Frame Type", "gquic.frame_type",
              FT_UINT8 ,BASE_RANGE_STRING | BASE_HEX, RVALS(frame_type_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_frame_type_padding_length,
            { "Padding Length", "gquic.frame_type.padding.length",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_frame_type_padding,
            { "Padding", "gquic.frame_type.padding",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "Must be zero", HFILL }
        },
        { &hf_gquic_frame_type_rsts_stream_id,
            { "Stream ID", "gquic.frame_type.rsts.stream_id",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              "Stream ID of the stream being terminated", HFILL }
        },
        { &hf_gquic_frame_type_rsts_byte_offset,
            { "Byte offset", "gquic.frame_type.rsts.byte_offset",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Indicating the absolute byte offset of the end of data for this stream", HFILL }
        },
        { &hf_gquic_frame_type_rsts_error_code,
            { "Error code", "gquic.frame_type.rsts.error_code",
              FT_UINT32, BASE_DEC|BASE_EXT_STRING, &rststream_error_code_vals_ext, 0x0,
              "Indicates why the stream is being closed", HFILL }
        },
        { &hf_gquic_frame_type_cc_error_code,
            { "Error code", "gquic.frame_type.cc.error_code",
              FT_UINT32, BASE_DEC|BASE_EXT_STRING, &error_code_vals_ext, 0x0,
              "Indicates the reason for closing this connection", HFILL }
        },
        { &hf_gquic_frame_type_cc_reason_phrase_length,
            { "Reason phrase Length", "gquic.frame_type.cc.reason_phrase.length",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "Specifying the length of the reason phrase", HFILL }
        },
        { &hf_gquic_frame_type_cc_reason_phrase,
            { "Reason phrase", "gquic.frame_type.cc.reason_phrase",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "An optional human-readable explanation for why the connection was closed", HFILL }
        },
        { &hf_gquic_frame_type_goaway_error_code,
            { "Error code", "gquic.frame_type.goaway.error_code",
              FT_UINT32, BASE_DEC|BASE_EXT_STRING, &error_code_vals_ext, 0x0,
              "Indicates the reason for closing this connection", HFILL }
        },
        { &hf_gquic_frame_type_goaway_last_good_stream_id,
            { "Last Good Stream ID", "gquic.frame_type.goaway.last_good_stream_id",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              "last Stream ID which was accepted by the sender of the GOAWAY message", HFILL }
        },
        { &hf_gquic_frame_type_goaway_reason_phrase_length,
            { "Reason phrase Length", "gquic.frame_type.goaway.reason_phrase.length",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "Specifying the length of the reason phrase", HFILL }
        },
        { &hf_gquic_frame_type_goaway_reason_phrase,
            { "Reason phrase", "gquic.frame_type.goaway.reason_phrase",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "An optional human-readable explanation for why the connection was closed", HFILL }
        },
        { &hf_gquic_frame_type_wu_stream_id,
            { "Stream ID", "gquic.frame_type.wu.stream_id",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              "ID of the stream whose flow control windows is begin updated, or 0 to specify the connection-level flow control window", HFILL }
        },
        { &hf_gquic_frame_type_wu_byte_offset,
            { "Byte offset", "gquic.frame_type.wu.byte_offset",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Indicating the absolute byte offset of data which can be sent on the given stream", HFILL }
        },
        { &hf_gquic_frame_type_blocked_stream_id,
            { "Stream ID", "gquic.frame_type.blocked.stream_id",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              "Indicating the stream which is flow control blocked", HFILL }
        },
        { &hf_gquic_frame_type_sw_send_entropy,
            { "Send Entropy", "gquic.frame_type.sw.send_entropy",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "Specifying the cumulative hash of entropy in all sent packets up to the packet with packet number one less than the least unacked packet", HFILL }
        },
        { &hf_gquic_frame_type_sw_least_unacked_delta,
            { "Least unacked delta", "gquic.frame_type.sw.least_unacked_delta",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "A variable length packet number delta with the same length as the packet header's packet number", HFILL }
        },
        { &hf_gquic_crypto_offset,
            { "Offset", "gquic.crypto.offset",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Byte offset into the stream", HFILL }
        },
        { &hf_gquic_crypto_length,
            { "Length", "gquic.crypto.length",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Length of the Crypto Data field", HFILL }
        },
        { &hf_gquic_crypto_crypto_data,
            { "Crypto Data", "gquic.crypto.crypto_data",
              FT_NONE, BASE_NONE, NULL, 0x0,
              "The cryptographic message data", HFILL }
        },
        { &hf_gquic_frame_type_stream,
            { "Stream", "gquic.frame_type.stream",
              FT_BOOLEAN, 8, NULL, FTFLAGS_STREAM,
              NULL, HFILL }
        },
        { &hf_gquic_frame_type_stream_f,
            { "FIN", "gquic.frame_type.stream.f",
              FT_BOOLEAN, 8, NULL, FTFLAGS_STREAM_F,
              NULL, HFILL }
        },
        { &hf_gquic_frame_type_stream_d,
            { "Data Length", "gquic.frame_type.stream.d",
              FT_BOOLEAN, 8, TFS(&len_data_vals), FTFLAGS_STREAM_D,
              NULL, HFILL }
        },
        { &hf_gquic_frame_type_stream_ooo,
            { "Offset Length", "gquic.frame_type.stream.ooo",
              FT_UINT8, BASE_DEC, VALS(len_offset_vals), FTFLAGS_STREAM_OOO,
              NULL, HFILL }
        },
        { &hf_gquic_frame_type_stream_ss,
            { "Stream Length", "gquic.frame_type.stream.ss",
              FT_UINT8, BASE_DEC, VALS(len_stream_vals), FTFLAGS_STREAM_SS,
              NULL, HFILL }
        },
        { &hf_gquic_frame_type_ack,
            { "ACK", "gquic.frame_type.ack",
              FT_BOOLEAN, 8, NULL, FTFLAGS_ACK,
              NULL, HFILL }
        },
        { &hf_gquic_frame_type_ack_n,
            { "NACK", "gquic.frame_type.ack.n",
              FT_BOOLEAN, 8, NULL, FTFLAGS_ACK_N,
              NULL, HFILL }
        },
        { &hf_gquic_frame_type_ack_u,
            { "Unused", "gquic.frame_type.ack.u",
              FT_BOOLEAN, 8, NULL, FTFLAGS_ACK_U,
              NULL, HFILL }
        },
        { &hf_gquic_frame_type_ack_t,
            { "Truncated", "gquic.frame_type.ack.t",
              FT_BOOLEAN, 8, NULL, FTFLAGS_ACK_T,
              NULL, HFILL }
        },
        { &hf_gquic_frame_type_ack_ll,
            { "Largest Observed Length", "gquic.frame_type.ack.ll",
              FT_UINT8, BASE_DEC, VALS(len_largest_observed_vals), FTFLAGS_ACK_LL,
              "Length of the Largest Observed field as 1, 2, 4, or 6 bytes long", HFILL }
        },
        { &hf_gquic_frame_type_ack_mm,
            { "Missing Packet Length", "gquic.frame_type.ack.mm",
              FT_UINT8, BASE_DEC, VALS(len_missing_packet_vals), FTFLAGS_ACK_MM,
              "Length of the Missing Packet Number Delta field as 1, 2, 4, or 6 bytes long", HFILL }
        },
        /* ACK before Q034 */
        { &hf_gquic_frame_type_ack_received_entropy,
            { "Received Entropy", "gquic.frame_type.ack.received_entropy",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "Specifying the cumulative hash of entropy in all received packets up to the largest observed packet", HFILL }
        },
        { &hf_gquic_frame_type_ack_largest_observed,
            { "Largest Observed", "gquic.frame_type.ack.largest_observed",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Representing the largest packet number the peer has observed", HFILL }
        },
        { &hf_gquic_frame_type_ack_ack_delay_time,
            { "Ack Delay time", "gquic.frame_type.ack.ack_delay_time",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "Specifying the time elapsed in microseconds from when largest observed was received until this Ack frame was sent", HFILL }
        },
        { &hf_gquic_frame_type_ack_num_timestamp,
            { "Num Timestamp", "gquic.frame_type.ack.num_timestamp",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "Specifying the number of TCP timestamps that are included in this frame", HFILL }
        },
        { &hf_gquic_frame_type_ack_delta_largest_observed,
            { "Delta Largest Observed", "gquic.frame_type.ack.delta_largest_observed",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "Specifying the packet number delta from the first timestamp to the largest observed", HFILL }
        },
        { &hf_gquic_frame_type_ack_first_timestamp,
            { "First Timestamp", "gquic.frame_type.ack.first_timestamp",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              "Specifying the time delta in microseconds, from the beginning of the connection of the arrival of the packet specified by Largest Observed minus Delta Largest Observed", HFILL }
        },
        { &hf_gquic_frame_type_ack_time_since_previous_timestamp,
            { "Time since Previous timestamp", "gquic.frame_type.ack.time_since_previous_timestamp",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "This is the time delta from the previous timestamp", HFILL }
        },
        { &hf_gquic_frame_type_ack_num_ranges,
            { "Num Ranges", "gquic.frame_type.ack.num_ranges",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "Specifying the number of missing packet ranges between largest observed and least unacked", HFILL }
        },
        { &hf_gquic_frame_type_ack_missing_packet,
            { "Missing Packet Number Delta", "gquic.frame_type.ack.missing_packet",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_frame_type_ack_range_length,
            { "Range Length", "gquic.frame_type.ack.range_length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "Specifying one less than the number of sequential nacks in the range", HFILL }
        },
        { &hf_gquic_frame_type_ack_num_revived,
            { "Num Revived", "gquic.frame_type.ack.num_revived",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "Specifying the number of revived packets, recovered via FEC", HFILL }
        },
        { &hf_gquic_frame_type_ack_revived_packet,
            { "Revived Packet Number", "gquic.frame_type.ack.revived_packet",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Representing a packet the peer has revived via FEC", HFILL }
        },
        /* ACK after Q034 */
        { &hf_gquic_frame_type_ack_largest_acked,
            { "Largest Acked", "gquic.frame_type.ack.largest_acked",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Representing the largest packet number the peer has observed", HFILL }
        },
        { &hf_gquic_frame_type_ack_largest_acked_delta_time,
            { "Largest Acked Delta Time", "gquic.frame_type.ack.largest_acked_delta_time",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "Specifying the time elapsed in microseconds from when largest acked was received until this Ack frame was sent", HFILL }
        },
        { &hf_gquic_frame_type_ack_num_blocks,
            { "Num blocks", "gquic.frame_type.ack.num_blocks",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "Specifying one less than the number of ack blocks", HFILL }
        },
        { &hf_gquic_frame_type_ack_first_ack_block_length,
            { "First Ack block length", "gquic.frame_type.ack.first_ack_block_length",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_frame_type_ack_gap_to_next_block,
            { "Gap to next block", "gquic.frame_type.ack.gap_to_next_block",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "Specifying the number of packets between ack blocks", HFILL }
        },
        { &hf_gquic_frame_type_ack_ack_block_length,
            { "Ack block length", "gquic.frame_type.ack.ack_block_length",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_frame_type_ack_delta_largest_acked,
            { "Delta Largest Observed", "gquic.frame_type.ack.delta_largest_acked",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "Specifying the packet number delta from the first timestamp to the largest observed", HFILL }
        },
        { &hf_gquic_frame_type_ack_time_since_largest_acked,
            { "Time Since Largest Acked", "gquic.frame_type.ack.time_since_largest_acked",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              "Specifying the time delta in microseconds, from the beginning of the connection of the arrival of the packet specified by Largest Observed minus Delta Largest Observed", HFILL }
        },



        { &hf_gquic_stream_id,
            { "Stream ID", "gquic.stream_id",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_offset,
            { "Offset", "gquic.offset",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_data_len,
            { "Data Length", "gquic.data_len",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag,
            { "Tag", "gquic.tag",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_number,
            { "Tag Number", "gquic.tag_number",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tags,
            { "Tag/value", "gquic.tags",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_type,
            { "Tag Type", "gquic.tag_type",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_offset_end,
            { "Tag offset end", "gquic.tag_offset_end",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_length,
            { "Tag length", "gquic.tag_offset_length",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_value,
            { "Tag/value", "gquic.tag_value",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_sni,
            { "Server Name Indication", "gquic.tag.sni",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "The fully qualified DNS name of the server, canonicalised to lowercase with no trailing period", HFILL }
        },
        { &hf_gquic_tag_pad,
            { "Padding", "gquic.tag.pad",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "Pad.....", HFILL }
        },
        { &hf_gquic_tag_ver,
            { "Version", "gquic.tag.version",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "Version of gquic supported", HFILL }
        },
        { &hf_gquic_tag_pdmd,
            { "Proof demand", "gquic.tag.pdmd",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "a list of tags describing the types of proof acceptable to the client, in preference order", HFILL }
        },
        { &hf_gquic_tag_ccs,
            { "Common certificate sets", "gquic.tag.ccs",
              FT_UINT64, BASE_HEX, NULL, 0x0,
              "A series of 64-bit, FNV-1a hashes of sets of common certificates that the client possesses", HFILL }
        },
        { &hf_gquic_tag_uaid,
            { "Client's User Agent ID", "gquic.tag.uaid",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_stk,
            { "Source-address token", "gquic.tag.stk",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_sno,
            { "Server nonce", "gquic.tag.sno",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_prof,
            { "Proof (Signature)", "gquic.tag.prof",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_scfg,
            { "Server Config Tag", "gquic.tag.scfg",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_scfg_number,
            { "Number Server Config Tag", "gquic.tag.scfg.number",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_rrej,
            { "Reasons for server sending", "gquic.tag.rrej",
              FT_UINT32, BASE_DEC|BASE_EXT_STRING, &handshake_failure_reason_vals_ext, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_crt,
            { "Certificate chain", "gquic.tag.crt",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_aead,
            { "Authenticated encryption algorithms", "gquic.tag.aead",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "A list of tags, in preference order, specifying the AEAD primitives supported by the server", HFILL }
        },
        { &hf_gquic_tag_scid,
            { "Server Config ID", "gquic.tag.scid",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "An opaque, 16-byte identifier for this server config", HFILL }
        },
        { &hf_gquic_tag_pubs,
            { "Public value", "gquic.tag.pubs",
              FT_UINT24, BASE_DEC_HEX, NULL, 0x0,
              "A list of public values, 24-bit, little-endian length prefixed", HFILL }
        },
        { &hf_gquic_tag_kexs,
            { "Key exchange algorithms", "gquic.tag.kexs",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "A list of tags, in preference order, specifying the key exchange algorithms that the server supports", HFILL }
        },
        { &hf_gquic_tag_obit,
            { "Server orbit", "gquic.tag.obit",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_expy,
            { "Expiry", "gquic.tag.expy",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "a 64-bit expiry time for the server config in UNIX epoch seconds", HFILL }
        },
        { &hf_gquic_tag_nonc,
            { "Client nonce", "gquic.tag.nonc",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "32 bytes consisting of 4 bytes of timestamp (big-endian, UNIX epoch seconds), 8 bytes of server orbit and 20 bytes of random data", HFILL }
        },
        { &hf_gquic_tag_mspc,
            { "Max streams per connection", "gquic.tag.mspc",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_tcid,
            { "Connection ID truncation", "gquic.tag.tcid",
              FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_srbf,
            { "Socket receive buffer", "gquic.tag.srbf",
              FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_icsl,
            { "Idle connection state", "gquic.tag.icsl",
              FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_scls,
            { "Silently close on timeout", "gquic.tag.scls",
              FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_copt,
            { "Connection options", "gquic.tag.copt",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_ccrt,
            { "Cached certificates", "gquic.tag.ccrt",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_irtt,
            { "Estimated initial RTT", "gquic.tag.irtt",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              "in us", HFILL }
        },
        { &hf_gquic_tag_cfcw,
            { "Initial session/connection", "gquic.tag.cfcw",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_sfcw,
            { "Initial stream flow control", "gquic.tag.sfcw",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_cetv,
            { "Client encrypted tag-value", "gquic.tag.cetv",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_xlct,
            { "Expected leaf certificate", "gquic.tag.xlct",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_nonp,
            { "Client Proof nonce", "gquic.tag.nonp",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_csct,
            { "Signed cert timestamp", "gquic.tag.csct",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_ctim,
            { "Client Timestamp", "gquic.tag.ctim",
              FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_rnon,
            { "Public reset nonce proof", "gquic.tag.rnon",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_rseq,
            { "Rejected Packet Number", "gquic.tag.rseq",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "a 64-bit packet number", HFILL }
        },
        { &hf_gquic_tag_cadr_addr_type,
            { "Client IP Address Type", "gquic.tag.caddr.addr.type",
              FT_UINT16, BASE_DEC, VALS(cadr_type_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_cadr_addr_ipv4,
            { "Client IP Address", "gquic.tag.caddr.addr.ipv4",
              FT_IPv4, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_cadr_addr_ipv6,
            { "Client IP Address", "gquic.tag.caddr.addr.ipv6",
              FT_IPv6, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_cadr_addr,
            { "Client IP Address", "gquic.tag.caddr.addr",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_cadr_port,
            { "Client Port (Source)", "gquic.tag.caddr.port",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_mids,
            { "Max incoming dynamic streams", "gquic.tag.mids",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_fhol,
            { "Force Head Of Line blocking", "gquic.tag.fhol",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_sttl,
            { "Server Config TTL", "gquic.tag.sttl",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_smhl,
            { "Support Max Header List (size)", "gquic.tag.smhl",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_tbkp,
            { "Token Binding Key Params.", "gquic.tag.tbkp",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_mad0,
            { "Max Ack Delay", "gquic.tag.mad0",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_qlve,
            { "Legacy Version Encapsulation", "gquic.tag.qlve",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_cgst,
            { "Congestion Control Feedback Type", "gquic.tag.cgst",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_epid,
            { "Endpoint identifier", "gquic.tag.epid",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_tag_srst,
            { "Stateless Reset Token", "gquic.tag.srst",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_gquic_tag_unknown,
            { "Unknown tag", "gquic.tag.unknown",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_padding,
            { "Padding", "gquic.padding",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_stream_data,
            { "Stream Data", "gquic.stream_data",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_gquic_payload,
            { "Payload", "gquic.payload",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "(Google) QUIC Payload..", HFILL }
        },
    };


    static int *ett[] = {
        &ett_gquic,
        &ett_gquic_puflags,
        &ett_gquic_prflags,
        &ett_gquic_ft,
        &ett_gquic_ftflags,
        &ett_gquic_tag_value
    };

    static ei_register_info ei[] = {
        { &ei_gquic_tag_undecoded, { "gquic.tag.undecoded", PI_UNDECODED, PI_NOTE, "Dissector for (Google)QUIC Tag code not implemented, Contact Wireshark developers if you want this supported", EXPFILL }},
        { &ei_gquic_tag_length, { "gquic.tag.length.truncated", PI_MALFORMED, PI_NOTE, "Truncated Tag Length...", EXPFILL }},
        { &ei_gquic_tag_unknown, { "gquic.tag.unknown.data", PI_UNDECODED, PI_NOTE, "Unknown Data", EXPFILL }},
        { &ei_gquic_version_invalid, { "gquic.version.invalid", PI_MALFORMED, PI_ERROR, "Invalid Version", EXPFILL }},
        { &ei_gquic_invalid_parameter, { "gquic.invalid.parameter", PI_MALFORMED, PI_ERROR, "Invalid Parameter", EXPFILL }},
        { &ei_gquic_length_invalid, { "gquic.length.invalid", PI_PROTOCOL, PI_WARN, "Invalid Length", EXPFILL }},
        { &ei_gquic_data_invalid, { "gquic.data.invalid", PI_PROTOCOL, PI_WARN, "Invalid Data", EXPFILL }},
    };

    expert_module_t *expert_gquic;

    proto_gquic = proto_register_protocol("GQUIC (Google Quick UDP Internet Connections)", "GQUIC", "gquic");

    proto_register_field_array(proto_gquic, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    gquic_module = prefs_register_protocol(proto_gquic, NULL);

    prefs_register_bool_preference(gquic_module, "debug.quic",
                       "Force decode of all (Google) QUIC Payload",
                       "Help for debug...",
                       &g_gquic_debug);

    expert_gquic = expert_register_protocol(proto_gquic);
    expert_register_field_array(expert_gquic, ei, array_length(ei));

    gquic_handle = register_dissector("gquic", dissect_gquic, proto_gquic);
}

void
proto_reg_handoff_gquic(void)
{
    tls13_handshake_handle = find_dissector("tls13-handshake");
    quic_handle = find_dissector("quic");
    dissector_add_uint_range_with_preference("udp.port", "", gquic_handle);
    heur_dissector_add("udp", dissect_gquic_heur, "Google QUIC", "gquic", proto_gquic, HEURISTIC_ENABLE);
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
