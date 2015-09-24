/* packet-quic.c
 * Routines for Quick UDP Internet Connections dissection
 * Copyright 2013, Alexis La Goutte <alexis.lagoutte at gmail dot com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

void proto_register_quic(void);
void proto_reg_handoff_quic(void);

static int proto_quic = -1;
static int hf_quic_puflags = -1;
static int hf_quic_puflags_vrsn = -1;
static int hf_quic_puflags_rst = -1;
static int hf_quic_puflags_cid = -1;
static int hf_quic_puflags_seq = -1;
static int hf_quic_puflags_rsv = -1;
static int hf_quic_cid = -1;
static int hf_quic_version = -1;
static int hf_quic_sequence = -1;
static int hf_quic_prflags = -1;
static int hf_quic_prflags_entropy = -1;
static int hf_quic_prflags_fecg = -1;
static int hf_quic_prflags_fec = -1;
static int hf_quic_prflags_rsv = -1;
static int hf_quic_message_authentication_hash = -1;
static int hf_quic_frame = -1;
static int hf_quic_frame_type = -1;
static int hf_quic_frame_type_padding_length = -1;
static int hf_quic_frame_type_padding = -1;
static int hf_quic_frame_type_rsts_stream_id = -1;
static int hf_quic_frame_type_rsts_byte_offset = -1;
static int hf_quic_frame_type_rsts_error_code = -1;
static int hf_quic_frame_type_cc_error_code = -1;
static int hf_quic_frame_type_cc_reason_phrase_length = -1;
static int hf_quic_frame_type_cc_reason_phrase = -1;
static int hf_quic_frame_type_goaway_error_code = -1;
static int hf_quic_frame_type_goaway_last_good_stream_id = -1;
static int hf_quic_frame_type_goaway_reason_phrase_length = -1;
static int hf_quic_frame_type_goaway_reason_phrase = -1;
static int hf_quic_frame_type_wu_stream_id = -1;
static int hf_quic_frame_type_wu_byte_offset = -1;
static int hf_quic_frame_type_blocked_stream_id = -1;
static int hf_quic_frame_type_sw_send_entropy = -1;
static int hf_quic_frame_type_sw_least_unacked_delta = -1;
static int hf_quic_frame_type_stream = -1;
static int hf_quic_frame_type_stream_f = -1;
static int hf_quic_frame_type_stream_d = -1;
static int hf_quic_frame_type_stream_ooo = -1;
static int hf_quic_frame_type_stream_ss = -1;
static int hf_quic_frame_type_ack = -1;
static int hf_quic_frame_type_ack_n = -1;
static int hf_quic_frame_type_ack_t = -1;
static int hf_quic_frame_type_ack_ll = -1;
static int hf_quic_frame_type_ack_mm = -1;
static int hf_quic_frame_type_ack_received_entropy = -1;
static int hf_quic_frame_type_ack_largest_observed = -1;
static int hf_quic_frame_type_ack_largest_observed_delta_time = -1;
static int hf_quic_frame_type_ack_num_timestamp = -1;
static int hf_quic_frame_type_ack_delta_largest_observed = -1;
static int hf_quic_frame_type_ack_time_since_largest_observed = -1;
static int hf_quic_frame_type_ack_time_since_previous_timestamp = -1;
static int hf_quic_frame_type_ack_num_ranges = -1;
static int hf_quic_frame_type_ack_missing_packet = -1;
static int hf_quic_frame_type_ack_range_length = -1;
static int hf_quic_frame_type_ack_num_revived = -1;
static int hf_quic_frame_type_ack_revived_packet = -1;
static int hf_quic_stream_id = -1;
static int hf_quic_offset_len = -1;
static int hf_quic_data_len = -1;
static int hf_quic_tag = -1;
static int hf_quic_tags = -1;
static int hf_quic_tag_number = -1;
static int hf_quic_tag_value = -1;
static int hf_quic_tag_type = -1;
static int hf_quic_tag_offset_end = -1;
static int hf_quic_tag_length = -1;
static int hf_quic_tag_sni = -1;
static int hf_quic_tag_pad = -1;
static int hf_quic_tag_ver = -1;
static int hf_quic_tag_ccs = -1;
static int hf_quic_tag_pdmd = -1;
static int hf_quic_tag_uaid = -1;
static int hf_quic_tag_stk = -1;
static int hf_quic_tag_sno = -1;
static int hf_quic_tag_prof = -1;
static int hf_quic_tag_scfg = -1;
static int hf_quic_tag_scfg_number = -1;
static int hf_quic_tag_rrej = -1;
static int hf_quic_tag_crt = -1;
static int hf_quic_tag_aead = -1;
static int hf_quic_tag_scid = -1;
static int hf_quic_tag_pubs = -1;
static int hf_quic_tag_kexs = -1;
static int hf_quic_tag_obit = -1;
static int hf_quic_tag_expy = -1;
static int hf_quic_tag_nonc = -1;
static int hf_quic_tag_mspc = -1;
static int hf_quic_tag_tcid = -1;
static int hf_quic_tag_srbf = -1;
static int hf_quic_tag_icsl = -1;
static int hf_quic_tag_scls = -1;
static int hf_quic_tag_copt = -1;
static int hf_quic_tag_ccrt = -1;
static int hf_quic_tag_irtt = -1;
static int hf_quic_tag_cfcw = -1;
static int hf_quic_tag_sfcw = -1;
static int hf_quic_tag_cetv = -1;
static int hf_quic_tag_unknown = -1;

static int hf_quic_padding = -1;
static int hf_quic_payload = -1;

static guint g_quic_port = 80;
static guint g_quics_port = 443;

static gint ett_quic = -1;
static gint ett_quic_puflags = -1;
static gint ett_quic_prflags = -1;
static gint ett_quic_ft = -1;
static gint ett_quic_ftflags = -1;
static gint ett_quic_tag_value = -1;

static expert_field ei_quic_tag_undecoded = EI_INIT;
static expert_field ei_quic_tag_length = EI_INIT;
static expert_field ei_quic_tag_unknown = EI_INIT;

#define QUIC_MIN_LENGTH 3

/**************************************************************************/
/*                      Public Flags                                      */
/**************************************************************************/
#define PUFLAGS_VRSN    0x01
#define PUFLAGS_RST     0x02
#define PUFLAGS_CID     0x0C
#define PUFLAGS_SEQ     0x30
#define PUFLAGS_RSV     0xC0

static const value_string puflags_cid_vals[] = {
    { 0, "0 Byte" },
    { 1, "1 Bytes" },
    { 2, "4 Bytes" },
    { 3, "8 Bytes" },
    { 0, NULL }
};

static const value_string puflags_seq_vals[] = {
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
  { 8,31,        "Unknown" },
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
#define MTAG_REJ  0X52454A00

static const value_string message_tag_vals[] = {
    { MTAG_CHLO, "Client Hello" },
    { MTAG_SHLO, "Server Hello" },
    { MTAG_REJ, "Rejection" },
    { 0, NULL }
};

/**************************************************************************/
/*                      Tag                                               */
/**************************************************************************/
/* See https://chromium.googlesource.com/chromium/src.git/+/master/net/quic/crypto/crypto_protocol.h */

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
    { AEAD_CC12, "Salsa20 with Poly1305" },
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
/*                      Error Code                                        */
/* See src/net/quic/quic_protocol.h from Chromium Source                  */
/**************************************************************************/

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
    /* STREAM frame data is not encrypted. */
    QUIC_UNENCRYPTED_STREAM_DATA = 61,
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
    /* There was an error while writing to the socket. */
    QUIC_PACKET_WRITE_ERROR = 27,
    /* There was an error while reading from the socket. */
    QUIC_PACKET_READ_ERROR = 51,
    /* We received a STREAM_FRAME with no data and no fin flag set. */
    QUIC_INVALID_STREAM_FRAME = 50,
    /* We received invalid data on the headers stream. */
    QUIC_INVALID_HEADERS_STREAM_DATA = 56,
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

    /* Crypto errors. */
    /* Hanshake failed. */
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
    /* An internal error occured in crypto processing. */
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
    /* This connection involved a version negotiation which appears to have been
       tampered with. */
    QUIC_VERSION_NEGOTIATION_MISMATCH = 55,
    /* No error.  Used as bound while iterating. */
    QUIC_LAST_ERROR = 76
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
    { QUIC_HANDSHAKE_FAILED, "Hanshake failed" },
    { QUIC_CRYPTO_TAGS_OUT_OF_ORDER, "Handshake message contained out of order tags" },
    { QUIC_CRYPTO_TOO_MANY_ENTRIES, "Handshake message contained too many entries" },
    { QUIC_CRYPTO_INVALID_VALUE_LENGTH, "Handshake message contained an invalid value length" },
    { QUIC_CRYPTO_MESSAGE_AFTER_HANDSHAKE_COMPLETE, "A crypto message was received after the handshake was complete" },
    { QUIC_INVALID_CRYPTO_MESSAGE_TYPE, "A crypto message was received with an illegal message tag" },
    { QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER, "A crypto message was received with an illegal parameter" },
    { QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND, "A crypto message was received with a mandatory parameter missing" },
    { QUIC_CRYPTO_MESSAGE_PARAMETER_NO_OVERLAP, "A crypto message was received with a parameter that has no overlap with the local parameter" },
    { QUIC_CRYPTO_MESSAGE_INDEX_NOT_FOUND, "A crypto message was received that contained a parameter with too few values" },
    { QUIC_CRYPTO_INTERNAL_ERROR, "An internal error occured in crypto processing" },
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
    { QUIC_LAST_ERROR, "No error. Used as bound while iterating" },
    { 0, NULL }
};

static value_string_ext error_code_vals_ext = VALUE_STRING_EXT_INIT(error_code_vals);

static guint32 get_len_offset(guint8 frame_type){
    guint32 len;

    switch((frame_type & FTFLAGS_STREAM_OOO) >> 2){
        case 0:
            len = 0;
        break;
        case 1:
            len = 2;
        break;
        case 2:
            len = 3;
        break;
        case 3:
            len = 4;
        break;
        case 4:
            len = 5;
        break;
        case 5:
            len = 5;
        break;
        case 6:
            len = 7;
        break;
        case 7:
            len = 8;
        break;
        default: /* No possible but always return value... */
            len = 0;
        break;
    }
    return len;
}
static guint32 get_len_stream(guint8 frame_type){
    guint32 len;

    switch(frame_type & FTFLAGS_STREAM_SS){
        case 0:
            len = 1;
        break;
        case 1:
            len  = 2;
        break;
        case 2:
            len = 3;
        break;
        case 3:
            len = 4;
        break;
        default: /* No possible but always return value... */
            len = 1;
        break;
    }
    return len;
}

static guint32 get_len_largest_observed(guint8 frame_type){
    guint32 len;

    switch((frame_type & FTFLAGS_ACK_LL) >> 2){
        case 0:
            len = 1;
        break;
        case 1:
            len = 2;
        break;
        case 2:
            len = 4;
        break;
        case 3:
            len = 6;
        break;
        default: /* No possible but always return value... */
            len = 1;
        break;
    }
    return len;
}
static guint32 get_len_missing_packet(guint8 frame_type){
    guint32 len;

    switch(frame_type & FTFLAGS_ACK_MM){
        case 0:
            len = 1;
        break;
        case 1:
            len = 2;
        break;
        case 2:
            len = 4;
        break;
        case 3:
            len = 6;
        break;
        default: /* No possible but always return value... */
            len = 1;
        break;
    }
    return len;
}


static gboolean is_quic_handshake(tvbuff_t *tvb, guint offset, guint16 len_seq){
    guint8 frame_type;
    guint8 num_ranges, num_revived, num_timestamp;
    guint32 len_stream = 0, len_offset = 0, len_data = 0, len_largest_observed = 1, len_missing_packet = 1;
    guint32 message_tag;


    if(tvb_captured_length_remaining(tvb, offset) <= 13){
        return FALSE;
    }
    /* Message Authentication Hash */
    offset += 12;

    /* Private Flags */
    offset += 1;


    while(tvb_reported_length_remaining(tvb, offset) > 0){

        if (tvb_captured_length_remaining(tvb, offset) <= 1){
            return FALSE;
        }
        /* Frame type */
        frame_type = tvb_get_guint8(tvb, offset);
        if((frame_type & FTFLAGS_SPECIAL) == 0){
            offset += 1;
            switch(frame_type){
                case FT_PADDING:
                    return FALSE; /* Pad on rest of packet.. */
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
                    guint16 len_reason;

                    /* Error Code */
                    offset += 4;
                    /* Reason Phrase Length */
                    if (tvb_captured_length_remaining(tvb, offset) <= 2){
                        return FALSE;
                    }
                    len_reason = tvb_get_ntohs(tvb, offset);
                    offset += 2;
                    /* Reason Phrase */
                    offset += len_reason;
                    }
                break;
                case FT_GOAWAY:{
                    guint16 len_reason;

                    /* Error Code */
                    offset += 4;
                    /* Last Good Stream ID */
                    offset += 4;
                    /* Reason Phrase Length */
                    if (tvb_captured_length_remaining(tvb, offset) <= 2){
                        return FALSE;
                    }
                    len_reason = tvb_get_ntohs(tvb, offset);
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
                    /* Send Entropy */
                    offset += 1;
                    /* Least Unacked Delta */
                    offset += len_seq;
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
                    return FALSE;
                }

                /* Check if the Message Tag is CHLO (Client Hello) or SHLO (Server Hello) or REJ (Rejection) */
                message_tag = tvb_get_ntohl(tvb, offset);
                if (message_tag == MTAG_CHLO|| message_tag == MTAG_SHLO || message_tag == MTAG_REJ) {
                    return TRUE;
                }


            } else if (frame_type & FTFLAGS_ACK) {
            /* ACK Flags */

                len_largest_observed = get_len_largest_observed(frame_type);
                len_missing_packet = get_len_missing_packet(frame_type);

                /* Frame Type */
                offset += 1;

                /* Received Entropy */
                offset += 1;

                /* Largest Observed */
                offset += len_largest_observed;

                /* Largest Observed Delta Time */
                offset += 2;

                /* Num Timestamp */
                if (tvb_captured_length_remaining(tvb, offset) <= 1){
                    return FALSE;
                }
                num_timestamp = tvb_get_guint8(tvb, offset);
                offset += 1;

                if(num_timestamp > 0){
                    /* Delta Largest Observed */
                    offset += 1;

                    /* Time Since Previous Timestamp */
                    offset += 4;

                    /* Num Timestamp (-1)x (Delta Largest Observed + Time Since Largest Observed) */
                    offset += (num_timestamp - 1)*(1+2);
                }

                if(frame_type & FTFLAGS_ACK_N){
                    /* Num Ranges */
                    if (tvb_captured_length_remaining(tvb, offset) <= 1){
                        return FALSE;
                    }
                    num_ranges = tvb_get_guint8(tvb, offset);
                    offset += 1;

                    /* Num Range x (Missing Packet + Range Length) */
                    offset += num_ranges*(len_missing_packet+1);

                    /* Num Revived */
                    if (tvb_captured_length_remaining(tvb, offset) <= 1){
                        return FALSE;
                    }
                    num_revived = tvb_get_guint8(tvb, offset);
                    offset += 1;

                    /* Num Revived x Length Largest Observed */
                    offset += num_revived*len_largest_observed;

                }

            } else { /* Other Special Frame type */
                offset += 1;
            }
        }
    }

    return FALSE;

}

static guint32
dissect_quic_tag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree, guint offset, guint32 tag_number){
    guint32 tag_offset_start = offset + tag_number*4*2;
    guint32 tag_offset = 0, total_tag_len = 0;
    gint32 tag_len;

    while(tag_number){
        proto_tree *tag_tree, *ti_len, *ti_tag, *ti_type;
        guint32 offset_end, tag;

        ti_tag = proto_tree_add_item(quic_tree, hf_quic_tags, tvb, offset, 8, ENC_NA);
        tag_tree = proto_item_add_subtree(ti_tag, ett_quic_tag_value);
        ti_type = proto_tree_add_item(tag_tree, hf_quic_tag_type, tvb, offset, 4, ENC_ASCII|ENC_NA);
        tag = tvb_get_ntohl(tvb, offset);
        proto_item_append_text(ti_type, " (%s)", val_to_str(tag, tag_vals, "Unknown"));
        proto_item_append_text(ti_tag, ": %s (%s)", tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 4, ENC_ASCII|ENC_NA), val_to_str(tag, tag_vals, "Unknown"));
        offset += 4;

        proto_tree_add_item(tag_tree, hf_quic_tag_offset_end, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset_end = tvb_get_letohl(tvb, offset);

        tag_len = offset_end - tag_offset;
        total_tag_len += tag_len;
        ti_len = proto_tree_add_uint(tag_tree, hf_quic_tag_length, tvb, offset, 4, tag_len);
        proto_item_append_text(ti_tag, " (l=%u)", tag_len);
        PROTO_ITEM_SET_GENERATED(ti_len);
        offset += 4;

        /* Fix issue with CRT.. (Fragmentation ?) */
        if( tag_len >= tvb_reported_length_remaining(tvb, tag_offset_start + tag_offset)){
            tag_len = tvb_reported_length_remaining(tvb, tag_offset_start + tag_offset);
             expert_add_info(pinfo, ti_len, &ei_quic_tag_length);
        }

        proto_tree_add_item(tag_tree, hf_quic_tag_value, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);

        switch(tag){
            case TAG_PAD:
                proto_tree_add_item(tag_tree, hf_quic_tag_pad, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);
                tag_offset += tag_len;
                tag_len -= tag_len;
            break;
            case TAG_SNI:
                proto_tree_add_item(tag_tree, hf_quic_tag_sni, tvb, tag_offset_start + tag_offset, tag_len, ENC_ASCII|ENC_NA);
                proto_item_append_text(ti_tag, ": %s", tvb_get_string_enc(wmem_packet_scope(), tvb, tag_offset_start + tag_offset, tag_len, ENC_ASCII|ENC_NA));
                tag_offset += tag_len;
                tag_len -= tag_len;
            break;
            case TAG_VER:
                proto_tree_add_item(tag_tree, hf_quic_tag_ver, tvb, tag_offset_start + tag_offset, 4, ENC_ASCII|ENC_NA);
                proto_item_append_text(ti_tag, " %s", tvb_get_string_enc(wmem_packet_scope(), tvb, tag_offset_start + tag_offset, 4, ENC_ASCII|ENC_NA));
                tag_offset += 4;
                tag_len -= 4;
            break;
            case TAG_CCS:
                proto_tree_add_item(tag_tree, hf_quic_tag_ccs, tvb, tag_offset_start + tag_offset, 8, ENC_NA);
                tag_offset += 8;
                tag_len -= 8;
            break;
            case TAG_PDMD:
                proto_tree_add_item(tag_tree, hf_quic_tag_pdmd, tvb, tag_offset_start + tag_offset, tag_len, ENC_ASCII|ENC_NA);
                proto_item_append_text(ti_tag, ": %s", tvb_get_string_enc(wmem_packet_scope(), tvb, tag_offset_start + tag_offset, tag_len, ENC_ASCII|ENC_NA));
                tag_offset += tag_len;
                tag_len -= tag_len;
            break;
            case TAG_UAID:
                proto_tree_add_item(tag_tree, hf_quic_tag_uaid, tvb, tag_offset_start + tag_offset, tag_len, ENC_ASCII|ENC_NA);
                proto_item_append_text(ti_tag, ": %s", tvb_get_string_enc(wmem_packet_scope(), tvb, tag_offset_start + tag_offset, tag_len, ENC_ASCII|ENC_NA));
                tag_offset += tag_len;
                tag_len -= tag_len;
            break;
            case TAG_STK:
                proto_tree_add_item(tag_tree, hf_quic_tag_stk, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);
                tag_offset += tag_len;
                tag_len -= tag_len;
            break;
            case TAG_SNO:
                proto_tree_add_item(tag_tree, hf_quic_tag_sno, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);
                tag_offset += tag_len;
                tag_len -= tag_len;
            break;
            case TAG_PROF:
                proto_tree_add_item(tag_tree, hf_quic_tag_prof, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);
                tag_offset += tag_len;
                tag_len -= tag_len;
            break;
            case TAG_SCFG:{
                guint32 scfg_tag_number;

                proto_tree_add_item(tag_tree, hf_quic_tag_scfg, tvb, tag_offset_start + tag_offset, 4, ENC_ASCII|ENC_NA);
                tag_offset += 4;
                tag_len -= 4;
                proto_tree_add_item(tag_tree, hf_quic_tag_scfg_number, tvb, tag_offset_start + tag_offset, 4, ENC_LITTLE_ENDIAN);
                scfg_tag_number = tvb_get_letohl(tvb, tag_offset_start + tag_offset);
                tag_offset += 4;
                tag_len -= 4;

                dissect_quic_tag(tvb, pinfo, tag_tree, tag_offset_start + tag_offset, scfg_tag_number);
                tag_offset += tag_len;
                tag_len -= tag_len;
                }
            break;
            case TAG_RREJ:
                proto_tree_add_item(tag_tree, hf_quic_tag_rrej, tvb, tag_offset_start + tag_offset, 4,  ENC_LITTLE_ENDIAN);
                proto_item_append_text(ti_tag, ": Code %u", tvb_get_letohl(tvb, tag_offset_start + tag_offset));
                tag_offset += 4;
                tag_len -= 4;
            break;
            case TAG_CRT:
                proto_tree_add_item(tag_tree, hf_quic_tag_crt, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);
                tag_offset += tag_len;
                tag_len -= tag_len;
            break;
            case TAG_AEAD:
                while(tag_len > 0){
                    proto_tree *ti_aead;
                    ti_aead = proto_tree_add_item(tag_tree, hf_quic_tag_aead, tvb, tag_offset_start + tag_offset, 4, ENC_ASCII|ENC_NA);
                    proto_item_append_text(ti_aead, " (%s)", val_to_str(tvb_get_ntohl(tvb, tag_offset_start + tag_offset), tag_aead_vals, "Unknown"));
                    proto_item_append_text(ti_tag, ", %s", val_to_str(tvb_get_ntohl(tvb, tag_offset_start + tag_offset), tag_aead_vals, "Unknown"));
                    tag_offset += 4;
                    tag_len -= 4;
                }
            break;
            case TAG_SCID:
                proto_tree_add_item(tag_tree, hf_quic_tag_scid, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);
                tag_offset += tag_len;
                tag_len -= tag_len;
            break;
            case TAG_PUBS:
                    /*TODO FIX: 24 Length + Pubs key?.. ! */
                    proto_tree_add_item(tag_tree, hf_quic_tag_pubs, tvb, tag_offset_start + tag_offset, 2, ENC_LITTLE_ENDIAN);
                    tag_offset +=2;
                    tag_len -= 2;
                while(tag_len > 0){
                    proto_tree_add_item(tag_tree, hf_quic_tag_pubs, tvb, tag_offset_start + tag_offset, 3, ENC_LITTLE_ENDIAN);
                    tag_offset += 3;
                    tag_len -= 3;
                }
            break;
            case TAG_KEXS:
                while(tag_len > 0){
                    proto_tree *ti_kexs;
                    ti_kexs = proto_tree_add_item(tag_tree, hf_quic_tag_kexs, tvb, tag_offset_start + tag_offset, 4, ENC_ASCII|ENC_NA);
                    proto_item_append_text(ti_kexs, " (%s)", val_to_str(tvb_get_ntohl(tvb, tag_offset_start + tag_offset), tag_kexs_vals, "Unknown"));
                    proto_item_append_text(ti_tag, ", %s", val_to_str(tvb_get_ntohl(tvb, tag_offset_start + tag_offset), tag_kexs_vals, "Unknown"));
                    tag_offset += 4;
                    tag_len -= 4;
                }
            break;
            case TAG_OBIT:
                proto_tree_add_item(tag_tree, hf_quic_tag_obit, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);
                tag_offset += tag_len;
                tag_len -= tag_len;
            break;
            case TAG_EXPY:
                proto_tree_add_item(tag_tree, hf_quic_tag_expy, tvb, tag_offset_start + tag_offset, 8, ENC_LITTLE_ENDIAN);
                tag_offset += 8;
                tag_len -= 8;
            break;
            case TAG_NONC:
                /*TODO: Enhance display: 32 bytes consisting of 4 bytes of timestamp (big-endian, UNIX epoch seconds), 8 bytes of server orbit and 20 bytes of random data. */
                proto_tree_add_item(tag_tree, hf_quic_tag_nonc, tvb, tag_offset_start + tag_offset, 32, ENC_NA);
                tag_offset += 32;
                tag_len -= 32;
            break;
            case TAG_MSPC:
                proto_tree_add_item(tag_tree, hf_quic_tag_mspc, tvb, tag_offset_start + tag_offset, 4, ENC_LITTLE_ENDIAN);
                proto_item_append_text(ti_tag, ": %u", tvb_get_letohl(tvb, tag_offset_start + tag_offset));
                tag_offset += 4;
                tag_len -= 4;
            break;
            case TAG_TCID:
                proto_tree_add_item(tag_tree, hf_quic_tag_tcid, tvb, tag_offset_start + tag_offset, 4, ENC_LITTLE_ENDIAN);
                tag_offset += 4;
                tag_len -= 4;
            break;
            case TAG_SRBF:
                proto_tree_add_item(tag_tree, hf_quic_tag_srbf, tvb, tag_offset_start + tag_offset, 4, ENC_LITTLE_ENDIAN);
                tag_offset += 4;
                tag_len -= 4;
            break;
            case TAG_ICSL:
                proto_tree_add_item(tag_tree, hf_quic_tag_icsl, tvb, tag_offset_start + tag_offset, 4, ENC_LITTLE_ENDIAN);
                tag_offset += 4;
                tag_len -= 4;
            break;
            case TAG_SCLS:
                proto_tree_add_item(tag_tree, hf_quic_tag_scls, tvb, tag_offset_start + tag_offset, 4, ENC_LITTLE_ENDIAN);
                tag_offset += 4;
                tag_len -= 4;
            break;
            case TAG_COPT:
                if(tag_len){
                    proto_tree_add_item(tag_tree, hf_quic_tag_copt, tvb, tag_offset_start + tag_offset, 4, ENC_LITTLE_ENDIAN);
                    tag_offset += 4;
                    tag_len -= 4;
                }
            break;
            case TAG_CCRT:
                proto_tree_add_item(tag_tree, hf_quic_tag_ccrt, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);
                tag_offset += tag_len;
                tag_len -= tag_len;
            break;
            case TAG_IRTT:
                proto_tree_add_item(tag_tree, hf_quic_tag_irtt, tvb, tag_offset_start + tag_offset, 4, ENC_LITTLE_ENDIAN);
                proto_item_append_text(ti_tag, ": %u", tvb_get_letohl(tvb, tag_offset_start + tag_offset));
                tag_offset += 4;
                tag_len -= 4;
            break;
            case TAG_CFCW:
                proto_tree_add_item(tag_tree, hf_quic_tag_cfcw, tvb, tag_offset_start + tag_offset, 4, ENC_LITTLE_ENDIAN);
                proto_item_append_text(ti_tag, ": %u", tvb_get_letohl(tvb, tag_offset_start + tag_offset));
                tag_offset += 4;
                tag_len -= 4;
            break;
            case TAG_SFCW:
                proto_tree_add_item(tag_tree, hf_quic_tag_sfcw, tvb, tag_offset_start + tag_offset, 4, ENC_LITTLE_ENDIAN);
                proto_item_append_text(ti_tag, ": %u", tvb_get_letohl(tvb, tag_offset_start + tag_offset));
                tag_offset += 4;
                tag_len -= 4;
            break;
            case TAG_CETV:
                proto_tree_add_item(tag_tree, hf_quic_tag_cetv, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);
                tag_offset += tag_len;
                tag_len -= tag_len;
            break;
            default:
                proto_tree_add_item(tag_tree, hf_quic_tag_unknown, tvb, tag_offset_start + tag_offset, tag_len, ENC_NA);
                expert_add_info_format(pinfo, ti_tag, &ei_quic_tag_undecoded,
                                 "Dissector for QUIC Tag"
                                 " %s (%s) code not implemented, Contact"
                                 " Wireshark developers if you want this supported", tvb_get_string_enc(wmem_packet_scope(), tvb, offset-8, 4, ENC_ASCII|ENC_NA), val_to_str(tag, tag_vals, "Unknown"));
                tag_offset += tag_len;
                tag_len -= tag_len;
            break;
            }
        if(tag_len){
            /* Wrong Tag len... */
            proto_tree_add_expert(tag_tree, pinfo, &ei_quic_tag_unknown, tvb, tag_offset_start + tag_offset, tag_len);
            tag_len  -= tag_len;
        }

        tag_number--;
    }
    return offset + total_tag_len;

}

static int
dissect_quic_frame_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree, guint offset, guint8 len_seq){
    proto_item *ti, *ti_ft, *ti_ftflags /*, *expert_ti*/;
    proto_tree *ft_tree, *ftflags_tree;
    guint8 frame_type;
    guint8 num_ranges, num_revived, num_timestamp;
    guint32 tag_number;
    guint32 len_stream = 0, len_offset = 0, len_data = 0, len_largest_observed = 1, len_missing_packet = 1;

    ti_ft = proto_tree_add_item(quic_tree, hf_quic_frame, tvb, offset, 1, ENC_NA);
    ft_tree = proto_item_add_subtree(ti_ft, ett_quic_ft);

    /* Frame type */
    ti_ftflags = proto_tree_add_item(ft_tree, hf_quic_frame_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    frame_type = tvb_get_guint8(tvb, offset);
    proto_item_set_text(ti_ft, "%s", rval_to_str(frame_type, frame_type_vals, "Unknown"));

    if((frame_type & FTFLAGS_SPECIAL) == 0){ /* Regular Stream Flags */
        offset += 1;
        switch(frame_type){
            case FT_PADDING:{
                proto_item *ti_pad_len;
                guint32 pad_len = tvb_reported_length_remaining(tvb, offset);

                ti_pad_len = proto_tree_add_uint(ft_tree, hf_quic_frame_type_padding_length, tvb, offset, 0, pad_len);
                PROTO_ITEM_SET_GENERATED(ti_pad_len);
                proto_item_append_text(ti_ft, " Length: %u", pad_len);
                proto_tree_add_item(ft_tree, hf_quic_frame_type_padding, tvb, offset, -1, ENC_NA);
                offset += pad_len;
                }
            break;
            case FT_RST_STREAM:{
                guint32 stream_id, error_code;
                proto_tree_add_item_ret_uint(ft_tree, hf_quic_frame_type_rsts_stream_id, tvb, offset, 4, ENC_LITTLE_ENDIAN, &stream_id);
                offset += 4;
                proto_tree_add_item(ft_tree, hf_quic_frame_type_rsts_byte_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
                offset += 8;
                proto_tree_add_item_ret_uint(ft_tree, hf_quic_frame_type_rsts_error_code, tvb, offset, 4, ENC_LITTLE_ENDIAN, &error_code);
                offset += 4;
                proto_item_append_text(ti_ft, " Stream ID: %u, Error code: %s", stream_id, val_to_str_ext(error_code, &error_code_vals_ext, "Unknown (%d)"));
                }
            break;
            case FT_CONNECTION_CLOSE:{
                guint16 len_reason;
                guint32 error_code;

                proto_tree_add_item_ret_uint(ft_tree, hf_quic_frame_type_cc_error_code, tvb, offset, 4, ENC_LITTLE_ENDIAN, &error_code);
                offset += 4;
                proto_tree_add_item(ft_tree, hf_quic_frame_type_cc_reason_phrase_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                len_reason = tvb_get_ntohs(tvb, offset);
                offset += 2;
                proto_tree_add_item(ft_tree, hf_quic_frame_type_cc_reason_phrase, tvb, offset, len_reason, ENC_ASCII|ENC_NA);
                offset += len_reason;
                proto_item_append_text(ti_ft, " Error code: %s", val_to_str_ext(error_code, &error_code_vals_ext, "Unknown (%d)"));
                }
            break;
            case FT_GOAWAY:{
                guint16 len_reason;
                guint32 error_code, last_good_stream_id;

                proto_tree_add_item_ret_uint(ft_tree, hf_quic_frame_type_goaway_error_code, tvb, offset, 4, ENC_LITTLE_ENDIAN, &error_code);
                offset += 4;
                proto_tree_add_item_ret_uint(ft_tree, hf_quic_frame_type_goaway_last_good_stream_id, tvb, offset, 4, ENC_LITTLE_ENDIAN, &last_good_stream_id);
                offset += 4;
                proto_tree_add_item(ft_tree, hf_quic_frame_type_goaway_reason_phrase_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                len_reason = tvb_get_ntohs(tvb, offset);
                offset += 2;
                proto_tree_add_item(ft_tree, hf_quic_frame_type_goaway_reason_phrase, tvb, offset, len_reason, ENC_ASCII|ENC_NA);
                offset += len_reason;
                proto_item_append_text(ti_ft, " Stream ID: %u, Error code: %s", last_good_stream_id, val_to_str_ext(error_code, &error_code_vals_ext, "Unknown (%d)"));
                }
            break;
            case FT_WINDOW_UPDATE:{
                guint32 stream_id;

                proto_tree_add_item_ret_uint(ft_tree, hf_quic_frame_type_wu_stream_id, tvb, offset, 4, ENC_LITTLE_ENDIAN, &stream_id);
                offset += 4;
                proto_tree_add_item(ft_tree, hf_quic_frame_type_wu_byte_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
                offset += 8;
                proto_item_append_text(ti_ft, " Stream ID: %u", stream_id);
                }
            break;
            case FT_BLOCKED:{
                guint32 stream_id;

                proto_tree_add_item_ret_uint(ft_tree, hf_quic_frame_type_blocked_stream_id, tvb, offset, 4, ENC_LITTLE_ENDIAN, &stream_id);
                offset += 4;
                proto_item_append_text(ti_ft, " Stream ID: %u", stream_id);
                }
            break;
            case FT_STOP_WAITING:{
                guint8 send_entropy;

                proto_tree_add_item(ft_tree, hf_quic_frame_type_sw_send_entropy, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                send_entropy = tvb_get_guint8(tvb, offset);
                offset += 1;
                proto_tree_add_item(ft_tree, hf_quic_frame_type_sw_least_unacked_delta, tvb, offset, len_seq, ENC_LITTLE_ENDIAN);
                offset += len_seq;
                proto_item_append_text(ti_ft, " Send Entropy: %u", send_entropy);
                }
            break;
            case FT_PING: /* No Payload */
            default: /* No default */
            break;
        }
    }
    else { /* Special Frame Types */
        guint32 stream_id = 0, message_tag;
        ftflags_tree = proto_item_add_subtree(ti_ftflags, ett_quic_ftflags);
        proto_tree_add_item(ftflags_tree, hf_quic_frame_type_stream , tvb, offset, 1, ENC_LITTLE_ENDIAN);

        if(frame_type & FTFLAGS_STREAM){ /* Stream Flags */
            proto_tree_add_item(ftflags_tree, hf_quic_frame_type_stream_f, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ftflags_tree, hf_quic_frame_type_stream_d, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            if(frame_type & FTFLAGS_STREAM_D){
                len_data = 2;
            }
            proto_tree_add_item(ftflags_tree, hf_quic_frame_type_stream_ooo, tvb, offset, 1, ENC_LITTLE_ENDIAN);

            len_offset = get_len_offset(frame_type);

            proto_tree_add_item(ftflags_tree, hf_quic_frame_type_stream_ss, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            len_stream = get_len_stream(frame_type);
            offset += 1;

            if(len_stream) {
                proto_tree_add_item_ret_uint(ft_tree, hf_quic_stream_id, tvb, offset, len_stream, ENC_LITTLE_ENDIAN, &stream_id);
                offset += len_stream;
            }

            if(len_offset) {
                proto_tree_add_item(ft_tree, hf_quic_offset_len, tvb, offset, len_offset, ENC_LITTLE_ENDIAN);
                offset += len_offset;
            }

            if(len_data) {
                proto_tree_add_item(ft_tree, hf_quic_data_len, tvb, offset, len_data, ENC_LITTLE_ENDIAN);
                offset += len_data;
            }

            ti = proto_tree_add_item(ft_tree, hf_quic_tag, tvb, offset, 4, ENC_ASCII|ENC_NA);
            message_tag = tvb_get_ntohl(tvb, offset);
            proto_item_append_text(ti, " (%s)", val_to_str(message_tag, message_tag_vals, "Unknown Tag"));
            proto_item_append_text(ti_ft, " Stream ID:%u, Type: %s (%s)", stream_id, tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 4, ENC_ASCII|ENC_NA), val_to_str(message_tag, message_tag_vals, "Unknown Tag"));
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(message_tag, message_tag_vals, "Unknown"));
            offset += 4;

            proto_tree_add_item(ft_tree, hf_quic_tag_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            tag_number = tvb_get_letohs(tvb, offset);
            offset += 2;

            proto_tree_add_item(ft_tree, hf_quic_padding, tvb, offset, 2, ENC_NA);
            offset += 2;

            offset = dissect_quic_tag(tvb, pinfo, ft_tree, offset, tag_number);

        } else if (frame_type & FTFLAGS_ACK) {     /* ACK Flags */

            proto_tree_add_item(ftflags_tree, hf_quic_frame_type_ack, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ftflags_tree, hf_quic_frame_type_ack_n, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ftflags_tree, hf_quic_frame_type_ack_t, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ftflags_tree, hf_quic_frame_type_ack_ll, tvb, offset, 1, ENC_LITTLE_ENDIAN);

            len_largest_observed = get_len_largest_observed(frame_type);

            proto_tree_add_item(ftflags_tree, hf_quic_frame_type_ack_mm, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            len_missing_packet = get_len_missing_packet(frame_type);
            offset += 1;

            proto_tree_add_item(ft_tree, hf_quic_frame_type_ack_received_entropy, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            proto_tree_add_item(ft_tree, hf_quic_frame_type_ack_largest_observed, tvb, offset, len_largest_observed, ENC_LITTLE_ENDIAN);
            offset += len_largest_observed;

            proto_tree_add_item(ft_tree, hf_quic_frame_type_ack_largest_observed_delta_time, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            proto_tree_add_item(ft_tree, hf_quic_frame_type_ack_num_timestamp, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            num_timestamp = tvb_get_guint8(tvb, offset);
            offset += 1;

            /* Delta Largest Observed */
            proto_tree_add_item(ft_tree, hf_quic_frame_type_ack_delta_largest_observed, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            /* Time Since Previous Timestamp */
            proto_tree_add_item(ft_tree, hf_quic_frame_type_ack_time_since_largest_observed, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            num_timestamp -= 1;

            /* Num Timestamp (-1) x (Delta Largest Observed + Time Since Largest Observed) */
            while(num_timestamp){
                proto_tree_add_item(ft_tree, hf_quic_frame_type_ack_delta_largest_observed, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;

                proto_tree_add_item(ft_tree, hf_quic_frame_type_ack_time_since_previous_timestamp, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                num_timestamp--;
            }

            if(frame_type & FTFLAGS_ACK_N){
                proto_tree_add_item(ft_tree, hf_quic_frame_type_ack_num_ranges, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                num_ranges = tvb_get_guint8(tvb, offset);
                offset += 1;
                while(num_ranges){

                    proto_tree_add_item(ft_tree, hf_quic_frame_type_ack_missing_packet, tvb, offset, len_missing_packet, ENC_LITTLE_ENDIAN);
                    offset += len_missing_packet;

                    proto_tree_add_item(ft_tree, hf_quic_frame_type_ack_range_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset += 1;
                    num_ranges--;
                }

                proto_tree_add_item(ft_tree, hf_quic_frame_type_ack_num_revived, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                num_revived = tvb_get_guint8(tvb, offset);
                offset += 1;
                while(num_revived){

                    proto_tree_add_item(ft_tree, hf_quic_frame_type_ack_revived_packet, tvb, offset, len_largest_observed, ENC_LITTLE_ENDIAN);
                    offset += len_largest_observed;
                    num_revived--;

                }

            }
        } else { /* Other ...*/
            offset += 1;
        }
    }
    return offset;

}


static int
dissect_quic_handshake(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree, guint offset, guint8 len_seq){
    proto_item *ti_prflags;
    proto_tree *prflags_tree;

    /* Message Authentication Hash */
    proto_tree_add_item(quic_tree, hf_quic_message_authentication_hash, tvb, offset, 12, ENC_NA);
    offset += 12;

    /* Private Flags */
    ti_prflags = proto_tree_add_item(quic_tree, hf_quic_prflags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    prflags_tree = proto_item_add_subtree(ti_prflags, ett_quic_prflags);
    proto_tree_add_item(prflags_tree, hf_quic_prflags_entropy, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(prflags_tree, hf_quic_prflags_fecg, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(prflags_tree, hf_quic_prflags_fec, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(prflags_tree, hf_quic_prflags_rsv, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset +=1;

    while(tvb_reported_length_remaining(tvb, offset) > 0){
        offset = dissect_quic_frame_type(tvb, pinfo, quic_tree, offset, len_seq);
    }

    return offset;

}

static int
dissect_quic_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_item *ti, *ti_puflags; /*, *expert_ti*/
    proto_tree *quic_tree, *puflags_tree;
    guint offset = 0;
    guint8 puflags, len_cid, len_seq;
    guint64 cid, seq;

    if (tvb_captured_length(tvb) < QUIC_MIN_LENGTH)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "QUIC");

    ti = proto_tree_add_item(tree, proto_quic, tvb, 0, -1, ENC_NA);
    quic_tree = proto_item_add_subtree(ti, ett_quic);

    /* Public Flags */
    ti_puflags = proto_tree_add_item(quic_tree, hf_quic_puflags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    puflags_tree = proto_item_add_subtree(ti_puflags, ett_quic_puflags);
    proto_tree_add_item(puflags_tree, hf_quic_puflags_vrsn, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(puflags_tree, hf_quic_puflags_rst, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(puflags_tree, hf_quic_puflags_cid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(puflags_tree, hf_quic_puflags_seq, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(puflags_tree, hf_quic_puflags_rsv, tvb, offset, 1, ENC_LITTLE_ENDIAN);

    puflags = tvb_get_guint8(tvb, offset);

    offset += 1;

    /* CID */

    /* Get len of CID (and CID), may be a more easy function to get the length... */
    switch((puflags & PUFLAGS_CID) >> 2){
        case 0:
            len_cid = 0;
            cid = 0;
        break;
        case 1:
            len_cid = 1;
            cid = tvb_get_guint8(tvb, offset);
        break;
        case 2:
            len_cid = 4;
            cid = tvb_get_letohl(tvb, offset);
        break;
        case 3:
            len_cid = 8;
            cid = tvb_get_letoh64(tvb, offset);
        break;
        default: /* It is only between 0..3 but Clang(Analyser) i don't like this... ;-) */
            len_cid = 8;
            cid = tvb_get_letoh64(tvb, offset);
        break;
    }

    if (len_cid) {
        proto_tree_add_item(quic_tree, hf_quic_cid, tvb, offset, len_cid, ENC_LITTLE_ENDIAN);
        offset += len_cid;
    }

    /* Version */
    if(puflags & PUFLAGS_VRSN){
        proto_tree_add_item(quic_tree, hf_quic_version, tvb, offset, 4, ENC_ASCII|ENC_NA);
        offset += 4;
    }

    /* Sequence */

    /* Get len of sequence (and sequence), may be a more easy function to get the length... */
    switch((puflags & PUFLAGS_SEQ) >> 4){
        case 0:
            len_seq = 1;
            seq = tvb_get_guint8(tvb, offset);
        break;
        case 1:
            len_seq = 2;
            seq = tvb_get_letohs(tvb, offset);
        break;
        case 2:
            len_seq = 4;
            seq = tvb_get_letohl(tvb, offset);
        break;
        case 3:
            len_seq = 6;
            seq = tvb_get_letoh48(tvb, offset);
        break;
        default: /* It is only between 0..3 but Clang(Analyser) i don't like this... ;-) */
            len_seq = 6;
            seq = tvb_get_letoh48(tvb, offset);
        break;
    }
    proto_tree_add_item(quic_tree, hf_quic_sequence, tvb, offset, len_seq, ENC_LITTLE_ENDIAN);
    offset += len_seq;

    /* Handshake Message */
    if (is_quic_handshake(tvb, offset, len_seq)){
        offset = dissect_quic_handshake(tvb, pinfo, quic_tree, offset, len_seq);
    }else {     /* Payload... (encrypted... TODO FIX !) */
        col_add_str(pinfo->cinfo, COL_INFO, "Payload (Encrypted)");
        proto_tree_add_item(quic_tree, hf_quic_payload, tvb, offset, -1, ENC_NA);

    }

    if(cid){
        col_append_fstr(pinfo->cinfo, COL_INFO, ", CID: %" G_GINT64_MODIFIER "u", cid);
    }
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Seq: %" G_GINT64_MODIFIER "u", seq);

    return offset;
}

static int
dissect_quic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
              void *data _U_)
{
    return dissect_quic_common(tvb, pinfo, tree, NULL);
}

static int
dissect_quics(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
              void *data _U_)
{
    return dissect_quic_common(tvb, pinfo, tree, NULL);
}

void
proto_register_quic(void)
{
    module_t *quic_module;

    static hf_register_info hf[] = {
        { &hf_quic_puflags,
            { "Public Flags", "quic.puflags",
               FT_UINT8, BASE_HEX, NULL, 0x0,
              "Specifying per-packet public flags", HFILL }
        },
        { &hf_quic_puflags_vrsn,
            { "Version", "quic.puflags.version",
               FT_BOOLEAN, 8, TFS(&tfs_yes_no), PUFLAGS_VRSN,
              "Signifies that this packet also contains the version of the QUIC protocol", HFILL }
        },
        { &hf_quic_puflags_rst,
            { "Reset", "quic.puflags.reset",
               FT_BOOLEAN, 8, TFS(&tfs_yes_no), PUFLAGS_RST,
              "Signifies that this packet is a public reset packet", HFILL }
        },
        { &hf_quic_puflags_cid,
            { "CID Length", "quic.puflags.cid",
               FT_UINT8, BASE_HEX, VALS(puflags_cid_vals), PUFLAGS_CID,
              "Signifies the Length of CID", HFILL }
        },
        { &hf_quic_puflags_seq,
            { "Sequence Length", "quic.puflags.seq",
               FT_UINT8, BASE_HEX, VALS(puflags_seq_vals), PUFLAGS_SEQ,
              "Signifies the Length of Sequence", HFILL }
        },
        { &hf_quic_puflags_rsv,
            { "Reserved", "quic.puflags.rsv",
               FT_UINT8, BASE_HEX, NULL, PUFLAGS_RSV,
              "Must be Zero", HFILL }
        },
        { &hf_quic_cid,
            { "CID", "quic.cid",
               FT_UINT64, BASE_DEC, NULL, 0x0,
              "Connection ID 64 bit pseudo random number", HFILL }
        },
        { &hf_quic_version,
            { "Version", "quic.version",
               FT_STRING, BASE_NONE, NULL, 0x0,
              "32 bit opaque tag that represents the version of the QUIC", HFILL }
        },
        { &hf_quic_sequence,
            { "Sequence", "quic.sequence",
               FT_UINT64, BASE_DEC, NULL, 0x0,
              "The lower 8, 16, 32, or 48 bits of the sequence number", HFILL }
        },

        { &hf_quic_prflags,
            { "Private Flags", "quic.prflags",
               FT_UINT8, BASE_HEX, NULL, 0x0,
              "Specifying per-packet Private flags", HFILL }
        },

        { &hf_quic_prflags_entropy,
            { "Entropy", "quic.prflags.entropy",
               FT_BOOLEAN, 8, TFS(&tfs_yes_no), PRFLAGS_ENTROPY,
              "For data packets, signifies that this packet contains the 1 bit of entropy, for fec packets, contains the xor of the entropy of protected packets", HFILL }
        },
        { &hf_quic_prflags_fecg,
            { "FEC Group", "quic.prflags.fecg",
               FT_BOOLEAN, 8, TFS(&tfs_yes_no), PRFLAGS_FECG,
              "Indicates whether the fec byte is present.", HFILL }
        },
        { &hf_quic_prflags_fec,
            { "FEC", "quic.prflags.fec",
               FT_BOOLEAN, 8, TFS(&tfs_yes_no), PRFLAGS_FEC,
              "Signifies that this packet represents an FEC packet", HFILL }
        },
        { &hf_quic_prflags_rsv,
            { "Reserved", "quic.prflags.rsv",
               FT_UINT8, BASE_HEX, NULL, PRFLAGS_RSV,
              "Must be Zero", HFILL }
        },

        { &hf_quic_message_authentication_hash,
            { "Message Authentication Hash", "quic.message_authentication_hash",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              "The hash is an FNV1a-128 hash, serialized in little endian order", HFILL }
        },
        { &hf_quic_frame,
            { "Frame", "quic.frame_type",
               FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_frame_type,
            { "Frame Type", "quic.frame_type",
               FT_UINT8 ,BASE_RANGE_STRING | BASE_HEX, RVALS(frame_type_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_quic_frame_type_padding_length,
            { "Padding Length", "quic.frame_type.padding.length",
               FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_frame_type_padding,
            { "Padding", "quic.frame_type.padding",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              "Must be zero", HFILL }
        },
        { &hf_quic_frame_type_rsts_stream_id,
            { "Stream ID", "quic.frame_type.rsts.stream_id",
               FT_UINT32, BASE_DEC, NULL, 0x0,
              "Stream ID of the stream being terminated", HFILL }
        },
        { &hf_quic_frame_type_rsts_byte_offset,
            { "Byte offset", "quic.frame_type.rsts.byte_offset",
               FT_UINT64, BASE_DEC, NULL, 0x0,
              "Indicating the absolute byte offset of the end of data for this stream", HFILL }
        },
        { &hf_quic_frame_type_rsts_error_code,
            { "Error code", "quic.frame_type.rsts.error_code",
               FT_UINT32, BASE_DEC|BASE_EXT_STRING, &error_code_vals_ext, 0x0,
              "Indicates why the stream is being closed", HFILL }
        },
        { &hf_quic_frame_type_cc_error_code,
            { "Error code", "quic.frame_type.cc.error_code",
               FT_UINT32, BASE_DEC|BASE_EXT_STRING, &error_code_vals_ext, 0x0,
              "Stream ID of the stream being terminated", HFILL }
        },
        { &hf_quic_frame_type_cc_reason_phrase_length,
            { "Reason phrase Length", "quic.frame_type.cc.reason_phrase.length",
               FT_UINT16, BASE_DEC, NULL, 0x0,
              "Specifying the length of the reason phrase", HFILL }
        },
        { &hf_quic_frame_type_cc_reason_phrase,
            { "Reason phrase", "quic.frame_type.cc.reason_phrase",
               FT_STRING, BASE_NONE, NULL, 0x0,
              "An optional human-readable explanation for why the connection was closed", HFILL }
        },
        { &hf_quic_frame_type_goaway_error_code,
            { "Error code", "quic.frame_type.goaway.error_code",
               FT_UINT32, BASE_DEC|BASE_EXT_STRING, &error_code_vals_ext, 0x0,
              "Stream ID of the stream being terminated", HFILL }
        },
        { &hf_quic_frame_type_goaway_last_good_stream_id,
            { "Error code", "quic.frame_type.goaway.error_code",
               FT_UINT32, BASE_DEC|BASE_EXT_STRING, &error_code_vals_ext, 0x0,
              "Stream ID of the stream being terminated", HFILL }
        },
        { &hf_quic_frame_type_goaway_reason_phrase_length,
            { "Reason phrase Length", "quic.frame_type.goaway.reason_phrase.length",
               FT_UINT16, BASE_DEC, NULL, 0x0,
              "Specifying the length of the reason phrase", HFILL }
        },
        { &hf_quic_frame_type_goaway_reason_phrase,
            { "Reason phrase", "quic.frame_type.goaway.reason_phrase",
               FT_STRING, BASE_NONE, NULL, 0x0,
              "An optional human-readable explanation for why the connection was closed", HFILL }
        },
        { &hf_quic_frame_type_wu_stream_id,
            { "Stream ID", "quic.frame_type.wu.stream_id",
               FT_UINT32, BASE_DEC, NULL, 0x0,
              "ID of the stream whose flow control windows is begin updated, or 0 to specify the connection-level flow control window", HFILL }
        },
        { &hf_quic_frame_type_wu_byte_offset,
            { "Byte offset", "quic.frame_type.wu.byte_offset",
               FT_UINT64, BASE_DEC, NULL, 0x0,
              "Indicating the absolute byte offset of data which can be sent on the given stream", HFILL }
        },
        { &hf_quic_frame_type_blocked_stream_id,
            { "Stream ID", "quic.frame_type.blocked.stream_id",
               FT_UINT32, BASE_DEC, NULL, 0x0,
              "Indicating the stream which is flow control blocked", HFILL }
        },
        { &hf_quic_frame_type_sw_send_entropy,
            { "Send Entropy", "quic.frame_type.sw.send_entropy",
               FT_UINT8, BASE_DEC, NULL, 0x0,
              "Specifying the cumulative hash of entropy in all sent packets up to the packet with sequence number one less than the least unacked packet", HFILL }
        },
        { &hf_quic_frame_type_sw_least_unacked_delta,
            { "Least unacked delta", "quic.frame_type.sw.least_unacked_delta",
               FT_UINT64, BASE_DEC, NULL, 0x0,
              "A variable length sequence number delta withthe same length as the packet header's sequence number", HFILL }
        },
        { &hf_quic_frame_type_stream,
            { "Stream", "quic.frame_type.stream",
               FT_BOOLEAN, 8, NULL, FTFLAGS_STREAM,
              NULL, HFILL }
        },
        { &hf_quic_frame_type_stream_f,
            { "FIN", "quic.frame_type.stream.f",
               FT_BOOLEAN, 8, NULL, FTFLAGS_STREAM_F,
              NULL, HFILL }
        },
        { &hf_quic_frame_type_stream_d,
            { "Data Length", "quic.frame_type.stream.d",
               FT_BOOLEAN, 8, TFS(&len_data_vals), FTFLAGS_STREAM_D,
              NULL, HFILL }
        },
        { &hf_quic_frame_type_stream_ooo,
            { "Offset Length", "quic.frame_type.stream.ooo",
               FT_UINT8, BASE_DEC, VALS(len_offset_vals), FTFLAGS_STREAM_OOO,
              NULL, HFILL }
        },
        { &hf_quic_frame_type_stream_ss,
            { "Stream Length", "quic.frame_type.stream.ss",
               FT_UINT8, BASE_DEC, VALS(len_stream_vals), FTFLAGS_STREAM_SS,
              NULL, HFILL }
        },
        { &hf_quic_frame_type_ack,
            { "ACK", "quic.frame_type.ack",
               FT_BOOLEAN, 8, NULL, FTFLAGS_ACK,
              NULL, HFILL }
        },
        { &hf_quic_frame_type_ack_n,
            { "NACK", "quic.frame_type.ack.n",
               FT_BOOLEAN, 8, NULL, FTFLAGS_ACK_N,
              NULL, HFILL }
        },
        { &hf_quic_frame_type_ack_t,
            { "Truncated", "quic.frame_type.ack.t",
               FT_BOOLEAN, 8, NULL, FTFLAGS_ACK_T,
              NULL, HFILL }
        },
        { &hf_quic_frame_type_ack_ll,
            { "Largest Observed Length", "quic.frame_type.ack.ll",
               FT_UINT8, BASE_DEC, VALS(len_largest_observed_vals), FTFLAGS_ACK_LL,
              "Length of the Largest Observed field as 1, 2, 4, or 6 bytes long", HFILL }
        },
        { &hf_quic_frame_type_ack_mm,
            { "Missing Packet Length", "quic.frame_type.ack.mm",
               FT_UINT8, BASE_DEC, VALS(len_missing_packet_vals), FTFLAGS_ACK_MM,
              "Length of the Missing Packet Sequence Number Delta field as 1, 2, 4, or 6 bytes long", HFILL }
        },
        { &hf_quic_frame_type_ack_received_entropy,
            { "Received Entropy", "quic.frame_type.ack.received_entropy",
               FT_UINT8, BASE_DEC, NULL, 0x0,
              "Specifying the cumulative hash of entropy in all received packets up to the largest observed packet", HFILL }
        },
        { &hf_quic_frame_type_ack_largest_observed,
            { "Largest Observed", "quic.frame_type.ack.largest_observed",
               FT_UINT64, BASE_DEC, NULL, 0x0,
              "Representing the largest sequence number the peer has observed", HFILL }
        },
        { &hf_quic_frame_type_ack_largest_observed_delta_time,
            { "Largest Observed Delta time", "quic.frame_type.ack.largest_observed_delta_time",
               FT_UINT16, BASE_DEC, NULL, 0x0,
              "Specifying the time elapsed in microseconds from when largest observed was received until this Ack frame was sent", HFILL }
        },
        { &hf_quic_frame_type_ack_num_timestamp,
            { "Num Timestamp", "quic.frame_type.ack.num_timestamp",
               FT_UINT8, BASE_DEC, NULL, 0x0,
              "Specifying the number of TCP timestamps that are included in this frame", HFILL }
        },
        { &hf_quic_frame_type_ack_delta_largest_observed,
            { "Delta Largest Observed", "quic.frame_type.ack.delta_largest_observed",
               FT_UINT16, BASE_DEC, NULL, 0x0,
              "Specifying the sequence number delta from the first timestamp to the largest observed", HFILL }
        },
        { &hf_quic_frame_type_ack_time_since_largest_observed,
            { "Time since Largest Observed", "quic.frame_type.ack.time_since_largest_observed",
               FT_UINT32, BASE_DEC, NULL, 0x0,
              "This is the time delta in microseconds from the time the receiver's packet framer was created", HFILL }
        },
        { &hf_quic_frame_type_ack_time_since_previous_timestamp,
            { "Time since Previous timestamp", "quic.frame_type.ack.time_since_previous_timestamp",
               FT_UINT16, BASE_DEC, NULL, 0x0,
              "This is the time delta from the previous timestamp", HFILL }
        },
        { &hf_quic_frame_type_ack_num_ranges,
            { "Num Ranges", "quic.frame_type.ack.num_ranges",
               FT_UINT8, BASE_DEC, NULL, 0x0,
              "Specifying the number of missing packet ranges between largest observed and least unacked", HFILL }
        },
        { &hf_quic_frame_type_ack_missing_packet,
            { "Missing Packet Sequence Number Delta", "quic.frame_type.ack.missing_packet",
               FT_UINT64, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_frame_type_ack_range_length,
            { "Range Length", "quic.frame_type.ack.range_length",
               FT_UINT8, BASE_DEC, NULL, 0x0,
              "Specifying one less than the number of sequential nacks in the range", HFILL }
        },
        { &hf_quic_frame_type_ack_num_revived,
            { "Num Ranges", "quic.frame_type.ack.num_revived",
               FT_UINT8, BASE_DEC, NULL, 0x0,
              "Specifying the number of revived packets, recovered via FEC", HFILL }
        },
        { &hf_quic_frame_type_ack_revived_packet,
            { "Revived Packet Sequence Number", "quic.frame_type.ack.revived_packet",
               FT_UINT64, BASE_DEC, NULL, 0x0,
              "Representing a packet the peer has revived via FEC", HFILL }
        },
        { &hf_quic_stream_id,
            { "Stream ID", "quic.stream_id",
               FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_offset_len,
            { "Offset Length", "quic.offset_len",
               FT_UINT64, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_data_len,
            { "Data Length", "quic.offset_len",
               FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_tag,
            { "Tag", "quic.tag",
               FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_tag_number,
            { "Tag Number", "quic.tag_number",
               FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_tags,
            { "Tag/value", "quic.tags",
               FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_tag_type,
            { "Tag Type", "quic.tag_type",
               FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_tag_offset_end,
            { "Tag offset end", "quic.tag_offset_end",
               FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_tag_length,
            { "Tag length", "quic.tag_offset_length",
               FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_tag_value,
            { "Tag/value", "quic.tag_value",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_tag_sni,
            { "Server Name Indication", "quic.tag.sni",
               FT_STRING, BASE_NONE, NULL, 0x0,
              "The fully qualified DNS name of the server, canonicalised to lowercase with no trailing period", HFILL }
        },
        { &hf_quic_tag_pad,
            { "Padding", "quic.tag.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              "Pad.....", HFILL }
        },
        { &hf_quic_tag_ver,
            { "Version", "quic.tag.version",
               FT_STRING, BASE_NONE, NULL, 0x0,
              "Version of QUIC supported", HFILL }
        },
        { &hf_quic_tag_pdmd,
            { "Proof demand", "quic.tag.pdmd",
               FT_STRING, BASE_NONE, NULL, 0x0,
              "a list of tags describing the types of proof acceptable to the client, in preference order", HFILL }
        },
        { &hf_quic_tag_ccs,
            { "Common certificate sets", "quic.tag.ccs",
               FT_UINT64, BASE_HEX, NULL, 0x0,
              "A series of 64-bit, FNV-1a hashes of sets of common certificates that the client possesses", HFILL }
        },
        { &hf_quic_tag_uaid,
            { "Client's User Agent ID", "quic.tag.uaid",
               FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_tag_stk,
            { "Source-address token", "quic.tag.stk",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_tag_sno,
            { "Server nonce", "quic.tag.sno",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_tag_prof,
            { "Proof (Signature)", "quic.tag.prof",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_tag_scfg,
            { "Server Config Tag", "quic.tag.scfg",
               FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_tag_scfg_number,
            { "Number Server Config Tag", "quic.tag.scfg.number",
               FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_tag_rrej,
            { "Reasons for server sending", "quic.tag.rrej",
               FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_tag_crt,
            { "Certificate chain", "quic.tag.crt",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_tag_aead,
            { "Authenticated encryption algorithms", "quic.tag.aead",
               FT_STRING, BASE_NONE, NULL, 0x0,
              "A list of tags, in preference order, specifying the AEAD primitives supported by the server", HFILL }
        },
        { &hf_quic_tag_scid,
            { "Server Config ID", "quic.tag.scid",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              "An opaque, 16-byte identifier for this server config", HFILL }
        },
        { &hf_quic_tag_pubs,
            { "Public value", "quic.tag.pubs",
               FT_UINT24, BASE_DEC_HEX, NULL, 0x0,
              "A list of public values, 24-bit, little-endian length prefixed", HFILL }
        },
        { &hf_quic_tag_kexs,
            { "Key exchange algorithms", "quic.tag.kexs",
               FT_STRING, BASE_NONE, NULL, 0x0,
              "A list of tags, in preference order, specifying the key exchange algorithms that the server supports", HFILL }
        },
        { &hf_quic_tag_obit,
            { "Server orbit", "quic.tag.obit",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_tag_expy,
            { "Expiry", "quic.tag.expy",
               FT_UINT64, BASE_DEC, NULL, 0x0,
              "a 64-bit expiry time for the server config in UNIX epoch seconds", HFILL }
        },
        { &hf_quic_tag_nonc,
            { "Client nonce", "quic.tag.nonc",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              "32 bytes consisting of 4 bytes of timestamp (big-endian, UNIX epoch seconds), 8 bytes of server orbit and 20 bytes of random data", HFILL }
        },
        { &hf_quic_tag_mspc,
            { "Max streams per connection", "quic.tag.mspc",
               FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_tag_tcid,
            { "Connection ID truncation", "quic.tag.tcid",
               FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_tag_srbf,
            { "Socket receive buffer", "quic.tag.srbf",
               FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_tag_icsl,
            { "Idle connection state", "quic.tag.icsl",
               FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_tag_scls,
            { "Silently close on timeout", "quic.tag.scls",
               FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_tag_copt,
            { "Connection options", "quic.tag.copt",
               FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_tag_ccrt,
            { "Cached certificates", "quic.tag.ccrt",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_tag_irtt,
            { "Estimated initial RTT", "quic.tag.irtt",
               FT_UINT32, BASE_DEC, NULL, 0x0,
              "in us", HFILL }
        },
        { &hf_quic_tag_cfcw,
            { "Initial session/connection", "quic.tag.cfcw",
               FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_tag_sfcw,
            { "Initial stream flow control", "quic.tag.sfcw",
               FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_tag_cetv,
            { "Client encrypted tag-value", "quic.tag.cetv",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_tag_unknown,
            { "Unknown tag", "quic.tag.unknown",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_padding,
            { "Padding", "quic.padding",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_payload,
            { "Payload", "quic.payload",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              "Quic Payload..", HFILL }
        },
    };


    static gint *ett[] = {
        &ett_quic,
        &ett_quic_puflags,
        &ett_quic_prflags,
        &ett_quic_ft,
        &ett_quic_ftflags,
        &ett_quic_tag_value
    };

    static ei_register_info ei[] = {
        { &ei_quic_tag_undecoded, { "quic.tag.undecoded", PI_UNDECODED, PI_NOTE, "Dissector for QUIC Tag code not implemented, Contact Wireshark developers if you want this supported", EXPFILL }},
        { &ei_quic_tag_length, { "quic.tag.length.truncated", PI_MALFORMED, PI_NOTE, "Truncated Tag Length...", EXPFILL }},
        { &ei_quic_tag_unknown, { "quic.tag.unknown", PI_UNDECODED, PI_NOTE, "Unknown Data", EXPFILL }}

    };

    expert_module_t *expert_quic;

    proto_quic = proto_register_protocol("QUIC (Quick UDP Internet Connections)",
            "QUIC", "quic");

    proto_register_field_array(proto_quic, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    quic_module = prefs_register_protocol(proto_quic, proto_reg_handoff_quic);


    prefs_register_uint_preference(quic_module, "udp.quic.port", "QUIC UDP Port",
            "QUIC UDP port if other than the default",
            10, &g_quic_port);

    prefs_register_uint_preference(quic_module, "udp.quics.port", "QUICS UDP Port",
            "QUICS (Secure) UDP port if other than the default",
            10, &g_quics_port);

    expert_quic = expert_register_protocol(proto_quic);
    expert_register_field_array(expert_quic, ei, array_length(ei));
}

void
proto_reg_handoff_quic(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t quic_handle;
    static dissector_handle_t quics_handle;
    static int current_quic_port;
    static int current_quics_port;

    if (!initialized) {
        quic_handle = new_create_dissector_handle(dissect_quic,
                proto_quic);
        quics_handle = new_create_dissector_handle(dissect_quics,
                proto_quic);
        initialized = TRUE;

    } else {
        dissector_delete_uint("udp.port", current_quic_port, quic_handle);
        dissector_delete_uint("udp.port", current_quics_port, quics_handle);
    }

    current_quic_port = g_quic_port;
    current_quics_port = g_quics_port;


    dissector_add_uint("udp.port", current_quic_port, quic_handle);
    dissector_add_uint("udp.port", current_quics_port, quics_handle);
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
