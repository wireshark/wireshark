/* packet-quic.c
 * Routines for Quick UDP Internet Connections (IETF) dissection
 * Copyright 2017, Alexis La Goutte <alexis.lagoutte at gmail dot com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * See https://quicwg.github.io/
 * https://tools.ietf.org/html/draft-ietf-quic-transport-09
 * https://tools.ietf.org/html/draft-ietf-quic-tls-09
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include "packet-ssl-utils.h"
#include <epan/prefs.h>
#include <wsutil/pint.h>

#if GCRYPT_VERSION_NUMBER >= 0x010600 /* 1.6.0 */
/* Whether to provide support for authentication in addition to decryption. */
#define HAVE_LIBGCRYPT_AEAD
#endif

/* Prototypes */
void proto_reg_handoff_quic(void);
void proto_register_quic(void);

/* Initialize the protocol and registered fields */
static int proto_quic = -1;
static int hf_quic_header_form = -1;
static int hf_quic_long_packet_type = -1;
static int hf_quic_connection_id = -1;
static int hf_quic_packet_number = -1;
static int hf_quic_version = -1;
static int hf_quic_supported_version = -1;
static int hf_quic_vn_unused = -1;
static int hf_quic_short_ocid_flag = -1;
static int hf_quic_short_kp_flag = -1;
static int hf_quic_short_packet_type = -1;
static int hf_quic_initial_payload = -1;
static int hf_quic_handshake_payload = -1;
static int hf_quic_protected_payload = -1;

static int hf_quic_frame = -1;
static int hf_quic_frame_type = -1;
static int hf_quic_frame_type_stream_fin = -1;
static int hf_quic_frame_type_stream_len = -1;
static int hf_quic_frame_type_stream_off = -1;
static int hf_quic_stream_stream_id = -1;
static int hf_quic_stream_offset = -1;
static int hf_quic_stream_length = -1;
static int hf_quic_stream_data = -1;

static int hf_quic_frame_type_ack_largest_acknowledged = -1;
static int hf_quic_frame_type_ack_ack_delay = -1;
static int hf_quic_frame_type_ack_ack_block_count = -1;
static int hf_quic_frame_type_ack_fab = -1;
static int hf_quic_frame_type_ack_gap = -1;
static int hf_quic_frame_type_ack_ack_block = -1;

static int hf_quic_frame_type_padding_length = -1;
static int hf_quic_frame_type_padding = -1;
static int hf_quic_frame_type_rsts_stream_id = -1;
static int hf_quic_frame_type_rsts_application_error_code = -1;
static int hf_quic_frame_type_rsts_final_offset = -1;
static int hf_quic_frame_type_cc_error_code = -1;
static int hf_quic_frame_type_cc_reason_phrase_length = -1;
static int hf_quic_frame_type_cc_reason_phrase = -1;
static int hf_quic_frame_type_ac_error_code = -1;
static int hf_quic_frame_type_ac_reason_phrase_length = -1;
static int hf_quic_frame_type_ac_reason_phrase = -1;
static int hf_quic_frame_type_md_maximum_data = -1;
static int hf_quic_frame_type_msd_stream_id = -1;
static int hf_quic_frame_type_msd_maximum_stream_data = -1;
static int hf_quic_frame_type_msi_stream_id = -1;
static int hf_quic_frame_type_ping_length = -1;
static int hf_quic_frame_type_ping_data = -1;
static int hf_quic_frame_type_blocked_offset = -1;
static int hf_quic_frame_type_sb_stream_id = -1;
static int hf_quic_frame_type_sb_offset = -1;
static int hf_quic_frame_type_sib_stream_id = -1;
static int hf_quic_frame_type_nci_sequence = -1;
static int hf_quic_frame_type_nci_connection_id = -1;
static int hf_quic_frame_type_nci_stateless_reset_token = -1;
static int hf_quic_frame_type_ss_stream_id = -1;
static int hf_quic_frame_type_ss_application_error_code = -1;
static int hf_quic_frame_type_pong_length = -1;
static int hf_quic_frame_type_pong_data = -1;

static expert_field ei_quic_ft_unknown = EI_INIT;
static expert_field ei_quic_decryption_failed = EI_INIT;

static gint ett_quic = -1;
static gint ett_quic_ft = -1;
static gint ett_quic_ftflags = -1;

static dissector_handle_t quic_handle;
static dissector_handle_t ssl_handle;

typedef struct quic_info_data {
    guint32 version;
    guint16 server_port;
    tls13_cipher *client_cleartext_cipher;
    tls13_cipher *server_cleartext_cipher;
} quic_info_data_t;

const value_string quic_version_vals[] = {
    { 0x00000000, "Version Negotiation" },
    { 0xff000004, "draft-04" },
    { 0xff000005, "draft-05" },
    { 0xff000006, "draft-06" },
    { 0xff000007, "draft-07" },
    { 0xff000008, "draft-08" },
    { 0xff000009, "draft-09" },
    { 0, NULL }
};

static const value_string quic_short_long_header_vals[] = {
    { 0, "Short Header" },
    { 1, "Long Header" },
    { 0, NULL }
};

#define SH_OCID 0x40
#define SH_KP   0x20
#define SH_PT   0x1F

static const value_string quic_short_packet_type_vals[] = {
    { 0x01, "1 octet" },
    { 0x02, "2 octet" },
    { 0x03, "4 octet" },
    { 0x1F, "1 octet" },
    { 0x1E, "2 octet" },
    { 0x1D, "4 octet" },
    { 0, NULL }
};
#define QUIC_LPT_INITIAL    0x7F
#define QUIC_LPT_RETRY      0x7E
#define QUIC_LPT_HANDSHAKE  0x7D

static const value_string quic_long_packet_type_vals[] = {
    { 0x01, "Version Negotiation" }, /* Removed in draft-08 by a check of Version (=0x00000000)*/
    { 0x02, "Client Initial" }, /* Replaced in draft-08 by 0x7F (Initial) */
    { 0x03, "Server Stateless Retry" }, /* Replaced in draft-08 by 0x7E (Retry) */
    { 0x04, "Server Cleartext" }, /* Replaced in draft-08 by 0x7D (Handshake) */
    { 0x05, "Client Cleartext" }, /* Replaced in draft-08 by 0x7D (Handshake) */
    { 0x06, "0-RTT Protected" },  /* Replaced in draft-08 by 0x7C (0-RTT Protected) */
    { QUIC_LPT_INITIAL, "Initial" },
    { QUIC_LPT_RETRY, "Retry" },
    { QUIC_LPT_HANDSHAKE, "Handshake" },
    { 0x7C, "0-RTT Protected" },
    { 0, NULL }
};

#define FT_PADDING          0x00
#define FT_RST_STREAM       0x01
#define FT_CONNECTION_CLOSE 0x02
#define FT_APPLICATION_CLOSE 0x03 /* Add in draft07 */
#define FT_MAX_DATA         0x04
#define FT_MAX_STREAM_DATA  0x05
#define FT_MAX_STREAM_ID    0x06
#define FT_PING             0x07
#define FT_BLOCKED          0x08
#define FT_STREAM_BLOCKED   0x09
#define FT_STREAM_ID_BLOCKED 0x0a
#define FT_NEW_CONNECTION_ID 0x0b
#define FT_STOP_SENDING     0x0c
#define FT_PONG             0x0d
#define FT_ACK              0x0e
#define FT_STREAM_10        0x10
#define FT_STREAM_11        0x11
#define FT_STREAM_12        0x12
#define FT_STREAM_13        0x13
#define FT_STREAM_14        0x14
#define FT_STREAM_15        0x15
#define FT_STREAM_16        0x16
#define FT_STREAM_17        0x17

static const range_string quic_frame_type_vals[] = {
    { 0x00, 0x00,   "PADDING" },
    { 0x01, 0x01,   "RST_STREAM" },
    { 0x02, 0x02,   "CONNECTION_CLOSE" },
    { 0x03, 0x03,   "APPLICATION_CLOSE" },
    { 0x04, 0x04,   "MAX_DATA" },
    { 0x05, 0x05,   "MAX_STREAM_DATA" },
    { 0x06, 0x06,   "MAX_STREAM_ID" },
    { 0x07, 0x07,   "PING" },
    { 0x08, 0x08,   "BLOCKED" },
    { 0x09, 0x09,   "STREAM_BLOCKED" },
    { 0x0a, 0x0a,   "STREAM_ID_BLOCKED" },
    { 0x0b, 0x0b,   "NEW_CONNECTION_ID" },
    { 0x0c, 0x0c,   "STOP_SENDING" },
    { 0x0d, 0x0d,   "PONG" },
    { 0x0e, 0x0e,   "ACK" },
    { 0x10, 0x17,   "STREAM" },
    { 0,    0,        NULL },
};


/* >= draft-08 */
#define FTFLAGS_STREAM_FIN 0x01
#define FTFLAGS_STREAM_LEN 0x02
#define FTFLAGS_STREAM_OFF 0x04

/* > draft 07 */
#define QUIC_NO_ERROR                   0x0000
#define QUIC_INTERNAL_ERROR             0x0001
#define QUIC_FLOW_CONTROL_ERROR         0x0003
#define QUIC_STREAM_ID_ERROR            0x0004
#define QUIC_STREAM_STATE_ERROR         0x0005
#define QUIC_FINAL_OFFSET_ERROR         0x0006
#define QUIC_FRAME_FORMAT_ERROR         0x0007
#define QUIC_TRANSPORT_PARAMETER_ERROR  0x0008
#define QUIC_VERSION_NEGOTIATION_ERROR  0x0009
#define QUIC_PROTOCOL_VIOLATION         0x000A
#define QUIC_UNSOLICITED_PONG           0x000B
#define TLS_HANDSHAKE_FAILED            0x0201
#define TLS_FATAL_ALERT_GENERATED       0x0202
#define TLS_FATAL_ALERT_RECEIVED        0x0203

static const value_string quic_error_code_vals[] = {
    { QUIC_NO_ERROR, "NO_ERROR (An endpoint uses this with CONNECTION_CLOSE to signal that the connection is being closed abruptly in the absence of any error.)" },
    { QUIC_INTERNAL_ERROR, "INTERNAL_ERROR (The endpoint encountered an internal error and cannot continue with the connection)" },
    { QUIC_FLOW_CONTROL_ERROR, "FLOW_CONTROL_ERROR (An endpoint received more data than An endpoint received more data tha)" },
    { QUIC_STREAM_ID_ERROR, "STREAM_ID_ERROR (An endpoint received a frame for a stream identifier that exceeded its advertised maximum stream ID)" },
    { QUIC_STREAM_STATE_ERROR, "STREAM_STATE_ERROR (An endpoint received a frame for a stream that was not in a state that permitted that frame)" },
    { QUIC_FINAL_OFFSET_ERROR, "FINAL_OFFSET_ERROR (An endpoint received a STREAM frame containing data that exceeded the previously established final offset)" },
    { QUIC_FRAME_FORMAT_ERROR, "FRAME_FORMAT_ERROR (An endpoint received a frame that was badly formatted)" },
    { QUIC_TRANSPORT_PARAMETER_ERROR, "TRANSPORT_PARAMETER_ERROR (An endpoint received transport parameters that were badly formatted)" },
    { QUIC_VERSION_NEGOTIATION_ERROR, "VERSION_NEGOTIATION_ERROR (An endpoint received transport parameters that contained version negotiation parameters that disagreed with the version negotiation that it performed)" },
    { QUIC_PROTOCOL_VIOLATION, "PROTOCOL_VIOLATION (An endpoint detected an error with protocol compliance that was not covered by more specific error codes)" },
    { QUIC_UNSOLICITED_PONG, "An endpoint received a PONG frame that did not correspond to any PING frame that it previously sent" },
    /* TLS */
    { TLS_HANDSHAKE_FAILED, "TLS_HANDSHAKE_FAILED (The TLS handshake failed)" },
    { TLS_FATAL_ALERT_GENERATED, "TLS_FATAL_ALERT_GENERATED (A TLS fatal alert was sent causing the TLS connection to end prematurely)" },
    { TLS_FATAL_ALERT_RECEIVED, "TLS_FATAL_ALERT_RECEIVED (A TLS fatal alert was sent received the TLS connection to end prematurely)" },
    { 0, NULL }
};
static value_string_ext quic_error_code_vals_ext = VALUE_STRING_EXT_INIT(quic_error_code_vals);

static guint32 get_len_packet_number(guint8 short_packet_type){

    switch(short_packet_type & SH_PT){
        case 1:
        case 0x1F:
            return 1;
        break;
        case 2:
        case 0x1E:
            return 2;
        break;
        case 3:
        case 0x1D:
            return 4;
        break;
        default:
        break;
    }
    return 1;
}

#ifdef HAVE_LIBGCRYPT_AEAD
static int
dissect_quic_frame_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *quic_tree, guint offset, quic_info_data_t *quic_info _U_){
    proto_item *ti_ft, *ti_ftflags;
    proto_tree *ft_tree, *ftflags_tree;
    guint32 frame_type;

    ti_ft = proto_tree_add_item(quic_tree, hf_quic_frame, tvb, offset, 1, ENC_NA);
    ft_tree = proto_item_add_subtree(ti_ft, ett_quic_ft);

    ti_ftflags = proto_tree_add_item_ret_uint(ft_tree, hf_quic_frame_type, tvb, offset, 1, ENC_NA, &frame_type);
    proto_item_set_text(ti_ft, "%s", rval_to_str(frame_type, quic_frame_type_vals, "Unknown"));
    offset += 1;

    switch(frame_type){
        case FT_PADDING:{
            proto_item *ti_pad_len;
            guint32 padding_offset = offset, pad_len;

            /* get length of padding (with check if it is always a 0) */
            while ( tvb_reported_length_remaining(tvb, padding_offset) > 0) {
                if(tvb_get_guint8(tvb, padding_offset) != 0){
                    break;
                }
                padding_offset ++;
            }
            pad_len = padding_offset - offset;

            ti_pad_len = proto_tree_add_uint(ft_tree, hf_quic_frame_type_padding_length, tvb, offset, 0, pad_len);
            PROTO_ITEM_SET_GENERATED(ti_pad_len);
            proto_item_append_text(ti_ft, " Length: %u", pad_len);
            proto_tree_add_item(ft_tree, hf_quic_frame_type_padding, tvb, offset, pad_len, ENC_NA);
            offset += pad_len;
            proto_item_set_len(ti_ft, 1+pad_len);
        }
        break;
        case FT_RST_STREAM:{
            guint64 stream_id;
            guint32 error_code, len_streamid = 0, len_finaloffset = 0;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_rsts_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, &stream_id, &len_streamid);
            offset += len_streamid;

            proto_tree_add_item_ret_uint(ft_tree, hf_quic_frame_type_rsts_application_error_code, tvb, offset, 2, ENC_BIG_ENDIAN, &error_code);
            offset += 2;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_rsts_final_offset, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_finaloffset);
            offset += len_finaloffset;

            proto_item_append_text(ti_ft, " Stream ID: %" G_GINT64_MODIFIER "u, Error code: %s", stream_id, val_to_str_ext(error_code, &quic_error_code_vals_ext, "Unknown (%d)"));

            proto_item_set_len(ti_ft, 1 + len_streamid + 2 + len_finaloffset);

            col_prepend_fstr(pinfo->cinfo, COL_INFO, "RST STREAM, ");

        }
        break;
        case FT_CONNECTION_CLOSE:{
            guint32 len_reasonphrase, error_code;
            guint64 len_reason = 0;

            proto_tree_add_item_ret_uint(ft_tree, hf_quic_frame_type_cc_error_code, tvb, offset, 2, ENC_BIG_ENDIAN, &error_code);
            offset += 2;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_cc_reason_phrase_length, tvb, offset, -1, ENC_VARINT_QUIC, &len_reason, &len_reasonphrase);
            offset += len_reasonphrase;

            proto_tree_add_item(ft_tree, hf_quic_frame_type_cc_reason_phrase, tvb, offset, (guint32)len_reason, ENC_ASCII|ENC_NA);
            offset += (guint32)len_reason;

            proto_item_append_text(ti_ft, " Error code: %s", val_to_str_ext(error_code, &quic_error_code_vals_ext, "Unknown (%d)"));
            proto_item_set_len(ti_ft, 1 + 2 + len_reasonphrase + (guint32)len_reason);
            col_prepend_fstr(pinfo->cinfo, COL_INFO, "Connection Close");

        }
        break;
        case FT_APPLICATION_CLOSE:{
            guint32 len_reasonphrase, error_code;
            guint64 len_reason;

            proto_tree_add_item_ret_uint(ft_tree, hf_quic_frame_type_ac_error_code, tvb, offset, 2, ENC_BIG_ENDIAN, &error_code);
            offset += 2;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ac_reason_phrase_length, tvb, offset, -1, ENC_VARINT_QUIC, &len_reason, &len_reasonphrase);
            offset += len_reasonphrase;
            proto_tree_add_item(ft_tree, hf_quic_frame_type_ac_reason_phrase, tvb, offset, (guint32)len_reason, ENC_ASCII|ENC_NA);
            offset += (guint32)len_reason;

            proto_item_append_text(ti_ft, " Error code: %s", val_to_str_ext(error_code, &quic_error_code_vals_ext, "Unknown (%d)"));
            proto_item_set_len(ti_ft, 1 + 2+ len_reasonphrase + (guint32)len_reason);

            col_prepend_fstr(pinfo->cinfo, COL_INFO, "Application Close");

        }
        break;
        case FT_MAX_DATA:{
            guint32 len_maximumdata;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_md_maximum_data, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_maximumdata);
            offset += len_maximumdata;

            proto_item_set_len(ti_ft, 1 + len_maximumdata);

            col_prepend_fstr(pinfo->cinfo, COL_INFO, "Max Data");

        }
        break;
        case FT_MAX_STREAM_DATA:{
            guint32 len_streamid, len_maximumstreamdata;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_msd_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_streamid);
            offset += len_streamid;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_msd_maximum_stream_data, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_maximumstreamdata);
            offset += len_maximumstreamdata;

            proto_item_set_len(ti_ft, 1 + len_streamid + len_maximumstreamdata);

            col_prepend_fstr(pinfo->cinfo, COL_INFO, "Max Stream Data");

        }
        break;
        case FT_MAX_STREAM_ID:{
            guint32 len_streamid;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_msi_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_streamid);
            offset += len_streamid;

            proto_item_set_len(ti_ft, 1 + len_streamid);

            col_prepend_fstr(pinfo->cinfo, COL_INFO, "Max Stream ID");

        }
        break;
        case FT_PING:{
            guint len_ping;

            proto_tree_add_item_ret_uint(ft_tree, hf_quic_frame_type_ping_length, tvb, offset, 1, ENC_BIG_ENDIAN, &len_ping);
            offset += 1;
            proto_tree_add_item(ft_tree, hf_quic_frame_type_ping_data, tvb, offset, len_ping, ENC_NA);
            offset += len_ping;

            proto_item_set_len(ti_ft, 1 + 1 + len_ping);

            col_prepend_fstr(pinfo->cinfo, COL_INFO, "PING");
        }
        break;
        case FT_BLOCKED:{
            guint32 len_offset;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_blocked_offset, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_offset);
            offset += len_offset;

            proto_item_set_len(ti_ft, 1 + len_offset);

            col_prepend_fstr(pinfo->cinfo, COL_INFO, "Blocked");
        }
        break;
        case FT_STREAM_BLOCKED:{
            guint32 len_streamid, len_offset;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_sb_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_streamid);
            offset += len_streamid;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_sb_offset, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_offset);
            offset += len_offset;

            proto_item_set_len(ti_ft, 1 + len_streamid + len_offset);

            col_prepend_fstr(pinfo->cinfo, COL_INFO, "Stream Blocked");

        }
        break;
        case FT_STREAM_ID_BLOCKED:{
            guint32 len_streamid;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_sib_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_streamid);
            offset += len_streamid;

            proto_item_set_len(ti_ft, 1 + len_streamid);

            col_prepend_fstr(pinfo->cinfo, COL_INFO, "Stream ID Blocked");
        }
        break;
        case FT_NEW_CONNECTION_ID:{
            guint32 len_sequence;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_nci_sequence, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_sequence);
            offset += len_sequence;

            proto_tree_add_item(ft_tree, hf_quic_frame_type_nci_connection_id, tvb, offset, 8, ENC_BIG_ENDIAN);
            offset += 8;

            proto_tree_add_item(ft_tree, hf_quic_frame_type_nci_stateless_reset_token, tvb, offset, 16, ENC_NA);
            offset += 16;

            proto_item_set_len(ti_ft, 1 + len_sequence + 8 + 16);

            col_prepend_fstr(pinfo->cinfo, COL_INFO, "New Connection ID");

        }
        break;
        case FT_STOP_SENDING:{
            guint32 len_streamid;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ss_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len_streamid);
            offset += len_streamid;


            proto_tree_add_item(ft_tree, hf_quic_frame_type_ss_application_error_code, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            proto_item_set_len(ti_ft, 1 + len_streamid + 2);
            col_prepend_fstr(pinfo->cinfo, COL_INFO, "Stop Sending");

        }
        break;
        case FT_PONG:{
            guint len_pong;

            proto_tree_add_item_ret_uint(ft_tree, hf_quic_frame_type_pong_length, tvb, offset, 1, ENC_BIG_ENDIAN, &len_pong);
            offset += 1;
            proto_tree_add_item(ft_tree, hf_quic_frame_type_pong_data, tvb, offset, len_pong, ENC_NA);
            offset += len_pong;

            proto_item_set_len(ti_ft, 1 + 1 + len_pong);

            col_prepend_fstr(pinfo->cinfo, COL_INFO, "PONG");
        }
        break;
        case FT_ACK: {
            guint64 ack_block_count;
            guint32 lenvar;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ack_largest_acknowledged, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
            offset += lenvar;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ack_ack_delay, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
            offset += lenvar;

            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ack_ack_block_count, tvb, offset, -1, ENC_VARINT_QUIC, &ack_block_count, &lenvar);
            offset += lenvar;

            /* ACK Block */
            /* First ACK Block Length */
            proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ack_fab, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
            offset += lenvar;

            /* Repeated "Ack Block Count" */
            while(ack_block_count){

                /* Gap To Next Block */
                proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ack_gap, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
                offset += lenvar;

                proto_tree_add_item_ret_varint(ft_tree, hf_quic_frame_type_ack_ack_block, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
                offset += lenvar;

                ack_block_count--;
            }
        }
        break;
        case FT_STREAM_10:
        case FT_STREAM_11:
        case FT_STREAM_12:
        case FT_STREAM_13:
        case FT_STREAM_14:
        case FT_STREAM_15:
        case FT_STREAM_16:
        case FT_STREAM_17: {
            guint64 stream_id, length;
            guint32 lenvar;
            proto_item *ti_stream;

            offset -= 1;

            ftflags_tree = proto_item_add_subtree(ti_ftflags, ett_quic_ftflags);
            proto_tree_add_item(ftflags_tree, hf_quic_frame_type_stream_fin, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(ftflags_tree, hf_quic_frame_type_stream_len, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(ftflags_tree, hf_quic_frame_type_stream_off, tvb, offset, 1, ENC_NA);
            offset += 1;

            ti_stream = proto_tree_add_item_ret_varint(ft_tree, hf_quic_stream_stream_id, tvb, offset, -1, ENC_VARINT_QUIC, &stream_id, &lenvar);
            offset += lenvar;

            proto_item_append_text(ti_ft, " Stream ID: %" G_GINT64_MODIFIER "u", stream_id);

            if (frame_type & FTFLAGS_STREAM_OFF) {
                proto_tree_add_item_ret_varint(ft_tree, hf_quic_stream_offset, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
                offset += lenvar;
            }

            if (frame_type & FTFLAGS_STREAM_LEN) {
                proto_tree_add_item_ret_varint(ft_tree, hf_quic_stream_length, tvb, offset, -1, ENC_VARINT_QUIC, &length, &lenvar);
                offset += lenvar;
            } else {
               length = tvb_reported_length_remaining(tvb, offset);
            }

            proto_tree_add_item(ft_tree, hf_quic_stream_data, tvb, offset, (int)length, ENC_NA);

            if (stream_id == 0) { /* Special Stream */
                tvbuff_t *next_tvb;

                proto_item_append_text(ti_stream, " (Cryptographic handshake)");
                col_set_writable(pinfo->cinfo, -1, FALSE);
                next_tvb = tvb_new_subset_length(tvb, offset, (int)length);
                call_dissector(ssl_handle, next_tvb, pinfo, ft_tree);
                col_set_writable(pinfo->cinfo, -1, TRUE);
            }
            offset += (int)length;
        }
        break;
        default:
            expert_add_info_format(pinfo, ti_ft, &ei_quic_ft_unknown, "Unknown Frame Type %u", frame_type);
        break;
    }

    return offset;
}
#endif /* HAVE_LIBGCRYPT_AEAD */

/* TLS 1.3 draft used by the draft-ietf-quic-tls-07 */
#define QUIC_TLS13_VERSION          21
#define QUIC_LONG_HEADER_LENGTH     17

#ifdef HAVE_LIBGCRYPT_AEAD
/**
 * Given a QUIC message (header + non-empty payload), the actual packet number,
 * try to decrypt it using the cipher.
 *
 * The actual packet number must be constructed according to
 * https://tools.ietf.org/html/draft-ietf-quic-transport-07#section-5.7
 *
 * If decryption succeeds, the decrypted buffer is added as data source and
 * returned. Otherwise NULL is returned and an error message is set.
 */
static tvbuff_t *
quic_decrypt_message(tls13_cipher *cipher, tvbuff_t *head, packet_info *pinfo, guint header_length, guint64 packet_number, const gchar **error)
{
    gcry_error_t    err;
    guint8          header[QUIC_LONG_HEADER_LENGTH];
    guint8          nonce[TLS13_AEAD_NONCE_LENGTH];
    guint8         *buffer;
    guint8         *atag[16];
    guint           buffer_length;
    tvbuff_t       *decrypted;

    DISSECTOR_ASSERT(cipher != NULL);
    DISSECTOR_ASSERT(header_length <= sizeof(header));
    tvb_memcpy(head, header, 0, header_length);

    /* Input is "header || ciphertext (buffer) || auth tag (16 bytes)" */
    buffer_length = tvb_captured_length_remaining(head, header_length + 16);
    if (buffer_length == 0) {
        *error = "Decryption not possible, ciphertext is too short";
        return NULL;
    }
    buffer = (guint8 *)tvb_memdup(pinfo->pool, head, header_length, buffer_length);
    tvb_memcpy(head, atag, header_length + buffer_length, 16);

    memcpy(nonce, cipher->iv, TLS13_AEAD_NONCE_LENGTH);
    /* Packet number is left-padded with zeroes and XORed with write_iv */
    phton64(nonce + sizeof(nonce) - 8, pntoh64(nonce + sizeof(nonce) - 8) ^ packet_number);

    gcry_cipher_reset(cipher->hd);
    err = gcry_cipher_setiv(cipher->hd, nonce, TLS13_AEAD_NONCE_LENGTH);
    if (err) {
        *error = wmem_strdup_printf(wmem_packet_scope(), "Decryption (setiv) failed: %s", gcry_strerror(err));
        return NULL;
    }

    /* associated data (A) is the contents of QUIC header */
    err = gcry_cipher_authenticate(cipher->hd, header, header_length);
    if (err) {
        *error = wmem_strdup_printf(wmem_packet_scope(), "Decryption (authenticate) failed: %s", gcry_strerror(err));
        return NULL;
    }

    /* Output ciphertext (C) */
    err = gcry_cipher_decrypt(cipher->hd, buffer, buffer_length, NULL, 0);
    if (err) {
        *error = wmem_strdup_printf(wmem_packet_scope(), "Decryption (decrypt) failed: %s", gcry_strerror(err));
        return NULL;
    }

    err = gcry_cipher_checktag(cipher->hd, atag, 16);
    if (err) {
        *error = wmem_strdup_printf(wmem_packet_scope(), "Decryption (checktag) failed: %s", gcry_strerror(err));
        return NULL;
    }

    decrypted = tvb_new_child_real_data(head, buffer, buffer_length, buffer_length);
    add_new_data_source(pinfo, decrypted, "Decrypted QUIC");

    *error = NULL;
    return decrypted;
}

/**
 * Compute the client and server cleartext secrets given Connection ID "cid".
 *
 * On success TRUE is returned and the two cleartext secrets are returned (these
 * must be freed with wmem_free(NULL, ...)). FALSE is returned on error.
 */
static gboolean
quic_derive_cleartext_secrets(guint64 cid,
                              guint8 **client_cleartext_secret,
                              guint8 **server_cleartext_secret,
                              quic_info_data_t *quic_info _U_,
                              const gchar **error)
{

    /*
     * https://tools.ietf.org/html/draft-ietf-quic-tls-08#section-5.2.1
     *
     * quic_version_1_salt = afc824ec5fc77eca1e9d36f37fb2d46518c36639
     *
     * cleartext_secret = HKDF-Extract(quic_version_1_salt,
     *                                 client_connection_id)
     *
     * client_cleartext_secret =
     *                    HKDF-Expand-Label(cleartext_secret,
     *                                      "QUIC client handshake secret",
     *                                      "", Hash.length)
     * server_cleartext_secret =
     *                    HKDF-Expand-Label(cleartext_secret,
     *                                      "QUIC server handshake secret",
     *                                      "", Hash.length)
     * Hash for cleartext packets is SHA-256 (output size 32).
     */
    static const guint8 quic_version_1_salt[20] = {
        0xaf, 0xc8, 0x24, 0xec, 0x5f, 0xc7, 0x7e, 0xca, 0x1e, 0x9d,
        0x36, 0xf3, 0x7f, 0xb2, 0xd4, 0x65, 0x18, 0xc3, 0x66, 0x39
    };
    const char     *label_prefix;
    gcry_error_t    err;
    guint8          secret_bytes[HASH_SHA2_256_LENGTH];
    StringInfo      secret = { (guchar *) &secret_bytes, HASH_SHA2_256_LENGTH };
    guint8          cid_bytes[8];
    const gchar     *client_label = "QUIC client handshake secret";
    const gchar     *server_label = "QUIC server handshake secret";

    phton64(cid_bytes, cid);
    err = hkdf_extract(GCRY_MD_SHA256, quic_version_1_salt, sizeof(quic_version_1_salt),
                       cid_bytes, sizeof(cid_bytes), secret.data);
    if (err) {
        *error = wmem_strdup_printf(wmem_packet_scope(), "Failed to extract secrets: %s", gcry_strerror(err));
        return FALSE;
    }

    label_prefix = "tls13 ";

    if (!tls13_hkdf_expand_label_common(GCRY_MD_SHA256, &secret, label_prefix, client_label,
                                 HASH_SHA2_256_LENGTH, client_cleartext_secret)) {
        *error = "Key expansion (client) failed";
        return FALSE;
    }

    if (!tls13_hkdf_expand_label_common(GCRY_MD_SHA256, &secret, label_prefix, server_label,
                                 HASH_SHA2_256_LENGTH, server_cleartext_secret)) {
        wmem_free(NULL, *client_cleartext_secret);
        *client_cleartext_secret = NULL;
        *error = "Key expansion (server) failed";
        return FALSE;
    }

    *error = NULL;
    return TRUE;
}

static gboolean
quic_create_cleartext_decoders(guint64 cid, const gchar **error, quic_info_data_t *quic_info)
{
    tls13_cipher   *client_cipher, *server_cipher;
    StringInfo      client_secret = { NULL, HASH_SHA2_256_LENGTH };
    StringInfo      server_secret = { NULL, HASH_SHA2_256_LENGTH };

    /* TODO extract from packet/conversation */
    if (!quic_derive_cleartext_secrets(cid, &client_secret.data, &server_secret.data, quic_info, error)) {
        /* TODO handle error (expert info) */
        return FALSE;
    }

    /* Cleartext packets are protected with AEAD_AES_128_GCM */
    client_cipher = tls13_cipher_create(QUIC_TLS13_VERSION, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, GCRY_MD_SHA256, &client_secret, error);
    server_cipher = tls13_cipher_create(QUIC_TLS13_VERSION, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, GCRY_MD_SHA256, &server_secret, error);

    wmem_free(NULL, client_secret.data);
    wmem_free(NULL, server_secret.data);

    if (!client_cipher || !server_cipher) {
        return FALSE;
    }

    quic_info->client_cleartext_cipher = client_cipher;
    quic_info->server_cleartext_cipher = server_cipher;

    return TRUE;
}
#endif /* HAVE_LIBGCRYPT_AEAD */


static int
dissect_quic_long_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree, guint offset, quic_info_data_t *quic_info){
    guint32 long_packet_type, pkn;
    guint64 cid;

    proto_tree_add_item_ret_uint(quic_tree, hf_quic_long_packet_type, tvb, offset, 1, ENC_NA, &long_packet_type);
    offset += 1;

    proto_tree_add_item_ret_uint64(quic_tree, hf_quic_connection_id, tvb, offset, 8, ENC_BIG_ENDIAN, &cid);
    offset += 8;

    proto_tree_add_item_ret_uint(quic_tree, hf_quic_version, tvb, offset, 4, ENC_BIG_ENDIAN, &quic_info->version);
    offset += 4;

    proto_tree_add_item_ret_uint(quic_tree, hf_quic_packet_number, tvb, offset, 4, ENC_BIG_ENDIAN, &pkn);
    offset += 4;

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s, PKN: %u, CID: 0x%" G_GINT64_MODIFIER "x", val_to_str(long_packet_type, quic_long_packet_type_vals, "Unknown Packet Type"), pkn, cid);

    /* Payload */
    if (long_packet_type == QUIC_LPT_INITIAL) {
        proto_item *ti;

        ti = proto_tree_add_item(quic_tree, hf_quic_initial_payload, tvb, offset, -1, ENC_NA);

        /* Initial Packet is always send by client */
        if(pinfo->destport != 443) {
            quic_info->server_port = pinfo->destport;
        }

#ifdef HAVE_LIBGCRYPT_AEAD
        tls13_cipher *cipher = NULL;
        const gchar *error = NULL;
        tvbuff_t *decrypted_tvb;

        cipher = quic_info->client_cleartext_cipher;

        /* Create new decryption context based on the Client Connection
         * ID from the Client Initial packet. */
        if (!quic_create_cleartext_decoders(cid, &error, quic_info)) {
            expert_add_info_format(pinfo, ti, &ei_quic_decryption_failed, "Failed to create decryption context: %s", error);
             return offset;
        }

        if (cipher) {
            /* quic_decrypt_message expects exactly one header + ciphertext as tvb. */
            DISSECTOR_ASSERT(offset == QUIC_LONG_HEADER_LENGTH);

            decrypted_tvb = quic_decrypt_message(cipher, tvb, pinfo, QUIC_LONG_HEADER_LENGTH, pkn, &error);
            if (decrypted_tvb) {
                guint decrypted_offset = 0;
                while (tvb_reported_length_remaining(decrypted_tvb, decrypted_offset) > 0){
                    decrypted_offset = dissect_quic_frame_type(decrypted_tvb, pinfo, quic_tree, decrypted_offset, quic_info);
                }
            } else {
                expert_add_info_format(pinfo, ti, &ei_quic_decryption_failed, "Failed to decrypt handshake: %s", error);
            }
        }
#else /* !HAVE_LIBGCRYPT_AEAD */
            expert_add_info_format(pinfo, ti, &ei_quic_decryption_failed, "Libgcrypt >= 1.6.0 is required for QUIC decryption");
#endif /* !HAVE_LIBGCRYPT_AEAD */
        offset += tvb_reported_length_remaining(tvb, offset);

    /* Handshake (>= draft-08) */
    } else if  (long_packet_type == QUIC_LPT_HANDSHAKE ) {
        proto_item *ti;

        ti = proto_tree_add_item(quic_tree, hf_quic_handshake_payload, tvb, offset, -1, ENC_NA);

#ifdef HAVE_LIBGCRYPT_AEAD
        tls13_cipher *cipher = NULL;
        const gchar *error = NULL;
        tvbuff_t *decrypted_tvb;

        if(pinfo->destport == quic_info->server_port) {
            cipher = quic_info->client_cleartext_cipher;
        } else {
            cipher = quic_info->server_cleartext_cipher;
        }

        if (cipher) {
            /* quic_decrypt_message expects exactly one header + ciphertext as tvb. */
            DISSECTOR_ASSERT(offset == QUIC_LONG_HEADER_LENGTH);

            decrypted_tvb = quic_decrypt_message(cipher, tvb, pinfo, QUIC_LONG_HEADER_LENGTH, pkn, &error);
            if (decrypted_tvb) {
                guint decrypted_offset = 0;
                while (tvb_reported_length_remaining(decrypted_tvb, decrypted_offset) > 0){
                    decrypted_offset = dissect_quic_frame_type(decrypted_tvb, pinfo, quic_tree, decrypted_offset, quic_info);
                }
            } else {
                expert_add_info_format(pinfo, ti, &ei_quic_decryption_failed, "Failed to decrypt handshake: %s", error);
            }
        }
#else /* !HAVE_LIBGCRYPT_AEAD */
        expert_add_info_format(pinfo, ti, &ei_quic_decryption_failed, "Libgcrypt >= 1.6.0 is required for QUIC decryption");
#endif /* !HAVE_LIBGCRYPT_AEAD */
        offset += tvb_reported_length_remaining(tvb, offset);

    } else {
        /* Protected (Encrypted) Payload */
        proto_tree_add_item(quic_tree, hf_quic_protected_payload, tvb, offset, -1, ENC_NA);
        offset += tvb_reported_length_remaining(tvb, offset);

    }

    return offset;
}

static int
dissect_quic_short_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree, guint offset, quic_info_data_t *quic_info _U_){
    guint8 short_flags;
    guint64 cid = 0;
    guint32 pkn_len, pkn;

    short_flags = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(quic_tree, hf_quic_short_ocid_flag, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(quic_tree, hf_quic_short_kp_flag, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(quic_tree, hf_quic_short_packet_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* Connection ID */
    if ((short_flags & SH_OCID) == 0){
        proto_tree_add_item_ret_uint64(quic_tree, hf_quic_connection_id, tvb, offset, 8, ENC_BIG_ENDIAN, &cid);
        offset += 8;
    }
    /* Packet Number */
    pkn_len = get_len_packet_number(short_flags);
    proto_tree_add_item_ret_uint(quic_tree, hf_quic_packet_number, tvb, offset, pkn_len, ENC_BIG_ENDIAN, &pkn);
    offset += pkn_len;

    /* Protected Payload */
    proto_tree_add_item(quic_tree, hf_quic_protected_payload, tvb, offset, -1, ENC_NA);
    offset += tvb_reported_length_remaining(tvb, offset);

    col_append_fstr(pinfo->cinfo, COL_INFO, "Protected Payload (KP%u), PKN: %u", short_flags & SH_KP, pkn);

    if(cid){
        col_append_fstr(pinfo->cinfo, COL_INFO, ", CID: 0x%" G_GINT64_MODIFIER "x", cid);
    }

    return offset;
}

static int
dissect_quic_version_negotiation(tvbuff_t *tvb, packet_info *pinfo, proto_tree *quic_tree, guint offset, quic_info_data_t *quic_info _U_){
    guint64 cid;

    proto_tree_add_item(quic_tree, hf_quic_vn_unused, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* Connection ID */
    proto_tree_add_item_ret_uint64(quic_tree, hf_quic_connection_id, tvb, offset, 8, ENC_BIG_ENDIAN, &cid);
    col_append_fstr(pinfo->cinfo, COL_INFO, "CID: 0x%" G_GINT64_MODIFIER "x", cid);
    offset += 8;

    /* Version */
    proto_tree_add_item(quic_tree, hf_quic_version, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* Supported Version */
    while(tvb_reported_length_remaining(tvb, offset) > 0){
        proto_tree_add_item(quic_tree, hf_quic_supported_version, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    return offset;
}


static int
dissect_quic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_item *ti;
    proto_tree *quic_tree;
    guint       offset = 0;
    guint32     header_form, version;
    conversation_t  *conv;
    quic_info_data_t  *quic_info;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "QUIC");

    /* get conversation, create if necessary*/
    conv = find_or_create_conversation(pinfo);

    /* get associated state information, create if necessary */
    quic_info = (quic_info_data_t *)conversation_get_proto_data(conv, proto_quic);

    if (!quic_info) {
        quic_info = wmem_new0(wmem_file_scope(), quic_info_data_t);
        quic_info->version = 0;
        quic_info->server_port = 443;
        conversation_add_proto_data(conv, proto_quic, quic_info);
    }

    ti = proto_tree_add_item(tree, proto_quic, tvb, 0, -1, ENC_NA);

    quic_tree = proto_item_add_subtree(ti, ett_quic);

    proto_tree_add_item_ret_uint(quic_tree, hf_quic_header_form, tvb, offset, 1, ENC_NA, &header_form);
    if(header_form) {
        version = tvb_get_ntohl(tvb, offset + 1 + 8);
        if (version == 0x00000000) { /* Version Negotiation ? */
                col_set_str(pinfo->cinfo, COL_INFO, "VN, ");
                offset = dissect_quic_version_negotiation(tvb, pinfo, quic_tree, offset, quic_info);
            return offset;
        }
        col_set_str(pinfo->cinfo, COL_INFO, "LH, ");
        offset = dissect_quic_long_header(tvb, pinfo, quic_tree, offset, quic_info);
    } else {
        col_set_str(pinfo->cinfo, COL_INFO, "SH, ");
        offset = dissect_quic_short_header(tvb, pinfo, quic_tree, offset, quic_info);
    }

    return offset;
}


void
proto_register_quic(void)
{
    expert_module_t *expert_quic;

    static hf_register_info hf[] = {
        { &hf_quic_header_form,
          { "Header Form", "quic.header_form",
            FT_UINT8, BASE_DEC, VALS(quic_short_long_header_vals), 0x80,
            "The most significant bit (0x80) of the first octet is set to 1 for long headers and 0 for short headers.", HFILL }
        },

        { &hf_quic_long_packet_type,
          { "Packet Type", "quic.long.packet_type",
            FT_UINT8, BASE_DEC, VALS(quic_long_packet_type_vals), 0x7F,
            "Long Header Packet Type", HFILL }
        },
        { &hf_quic_connection_id,
          { "Connection ID", "quic.connection_id",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_packet_number,
          { "Packet Number", "quic.packet_number",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_version,
          { "Version", "quic.version",
            FT_UINT32, BASE_HEX, VALS(quic_version_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_quic_supported_version,
          { "Supported Version", "quic.supported_version",
            FT_UINT32, BASE_HEX, VALS(quic_version_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_quic_vn_unused, /* <= draft-07 */
          { "Unused", "quic.vn.unused",
            FT_UINT8, BASE_HEX, NULL, 0x7F,
            NULL, HFILL }
        },
        { &hf_quic_short_ocid_flag,
          { "Omit Connection ID Flag", "quic.short.ocid_flag",
            FT_BOOLEAN, 8, NULL, SH_OCID,
            NULL, HFILL }
        },
        { &hf_quic_short_kp_flag,
          { "Key Phase Bit", "quic.short.kp_flag",
            FT_BOOLEAN, 8, NULL, SH_KP,
            NULL, HFILL }
        },
        { &hf_quic_short_packet_type,
          { "Packet Type", "quic.short.packet_type",
            FT_UINT8, BASE_DEC, VALS(quic_short_packet_type_vals), SH_PT,
            "Short Header Packet Type", HFILL }
        },
        { &hf_quic_initial_payload,
          { "Initial Payload", "quic.initial_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_handshake_payload,
          { "Handshake Payload", "quic.handshake_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_quic_protected_payload,
          { "Protected Payload", "quic.protected_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_quic_frame,
          { "Frame", "quic.frame",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_frame_type,
          { "Frame Type", "quic.frame_type",
            FT_UINT8, BASE_RANGE_STRING | BASE_HEX, RVALS(quic_frame_type_vals), 0x0,
            NULL, HFILL }
        },

        /* >= draft-08*/
        { &hf_quic_frame_type_stream_fin,
          { "Fin", "quic.frame_type.stream.fin",
            FT_BOOLEAN, 8, NULL, FTFLAGS_STREAM_FIN,
            NULL, HFILL }
        },
        { &hf_quic_frame_type_stream_len,
          { "Len(gth)", "quic.frame_type.stream.len",
            FT_BOOLEAN, 8, NULL, FTFLAGS_STREAM_LEN,
            NULL, HFILL }
        },
        { &hf_quic_frame_type_stream_off,
          { "Off(set)", "quic.frame_type.stream.off",
            FT_BOOLEAN, 8, NULL, FTFLAGS_STREAM_OFF,
            NULL, HFILL }
        },

        { &hf_quic_stream_stream_id,
          { "Stream ID", "quic.stream.stream_id",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_stream_offset,
          { "Offset", "quic.stream.offset",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_stream_length,
          { "Length", "quic.stream.length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_quic_stream_data,
          { "Stream Data", "quic.stream_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_quic_frame_type_ack_largest_acknowledged,
          { "Largest Acknowledged", "quic.frame_type.ack.largest_acknowledged",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Representing the largest packet number the peer is acknowledging in this packet", HFILL }
        },
        { &hf_quic_frame_type_ack_ack_delay,
          { "ACK Delay", "quic.frame_type.ack.ack_delay",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "The time from when the largest acknowledged packet, as indicated in the Largest Acknowledged field, was received by this peer to when this ACK was sent", HFILL }
        },
        { &hf_quic_frame_type_ack_ack_block_count,
          { "ACK Block Count", "quic.frame_type.ack.ack_block_count",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "The number of Additional ACK Block (and Gap) fields after the First ACK Block", HFILL }
        },
        { &hf_quic_frame_type_ack_fab,
          { "First ACK Block", "quic.frame_type.ack.fab",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Indicates the number of contiguous additional packets being acknowledged starting at the Largest Acknowledged", HFILL }
        },
        { &hf_quic_frame_type_ack_gap,
          { "Gap", "quic.frame_type.ack.gap",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Indicating the number of contiguous unacknowledged packets preceding the packet number one lower than the smallest in the preceding ACK Block", HFILL }
        },
        { &hf_quic_frame_type_ack_ack_block,
          { "ACK Block", "quic.frame_type.ack.ack_block",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Indicating the number of contiguous acknowledged packets preceding the largest packet number, as determined by the preceding Gap", HFILL }
        },
        /* PADDING */
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
        /* RST_STREAM */
        { &hf_quic_frame_type_rsts_stream_id,
            { "Stream ID", "quic.frame_type.rsts.stream_id",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Stream ID of the stream being terminated", HFILL }
        },
        { &hf_quic_frame_type_rsts_application_error_code,
            { "Application Error code", "quic.frame_type.rsts.application_error_code",
              FT_UINT16, BASE_DEC|BASE_EXT_STRING, &quic_error_code_vals_ext, 0x0,
              "Indicates why the stream is being closed", HFILL }
        },
        { &hf_quic_frame_type_rsts_final_offset,
            { "Final offset", "quic.frame_type.rsts.byte_offset",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Indicating the absolute byte offset of the end of data written on this stream", HFILL }
        },
        /* CONNECTION_CLOSE */
        { &hf_quic_frame_type_cc_error_code, /* >= draft07 */
            { "Error code", "quic.frame_type.cc.error_code",
              FT_UINT16, BASE_DEC|BASE_EXT_STRING, &quic_error_code_vals_ext, 0x0,
              "Indicates the reason for closing this connection", HFILL }
        },
        { &hf_quic_frame_type_cc_reason_phrase_length,
            { "Reason phrase Length", "quic.frame_type.cc.reason_phrase.length",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Specifying the length of the reason phrase", HFILL }
        },
        { &hf_quic_frame_type_cc_reason_phrase,
            { "Reason phrase", "quic.frame_type.cc.reason_phrase",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "A human-readable explanation for why the connection was closed", HFILL }
        },
        /* APPLICATION_CLOSE */
        { &hf_quic_frame_type_ac_error_code,
            { "Application Error code", "quic.frame_type.ac.error_code",
              FT_UINT16, BASE_DEC|BASE_EXT_STRING, &quic_error_code_vals_ext, 0x0,
              "Indicates the reason for closing this application", HFILL }
        },
        { &hf_quic_frame_type_ac_reason_phrase_length,
            { "Reason phrase Length", "quic.frame_type.ac.reason_phrase.length",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Specifying the length of the reason phrase", HFILL }
        },
        { &hf_quic_frame_type_ac_reason_phrase,
            { "Reason phrase", "quic.frame_type.ac.reason_phrase",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "A human-readable explanation for why the application was closed", HFILL }
        },
        /* MAX_DATA */
        { &hf_quic_frame_type_md_maximum_data,
            { "Maximum Data", "quic.frame_type.md.maximum_data",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Indicating the maximum amount of data that can be sent on the entire connection, in units of 1024 octets", HFILL }
        },
        /* MAX_STREAM_DATA */
        { &hf_quic_frame_type_msd_stream_id,
            { "Stream ID", "quic.frame_type.msd.stream_id",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "The stream ID of the stream that is affected", HFILL }
        },
        { &hf_quic_frame_type_msd_maximum_stream_data,
            { "Maximum Stream Data", "quic.frame_type.msd.maximum_stream_data",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Indicating the maximum amount of data that can be sent on the identified stream, in units of octets", HFILL }
        },
        /* MAX_STREAM_ID */
        { &hf_quic_frame_type_msi_stream_id,
            { "Stream ID", "quic.frame_type.msi.stream_id",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "ID of the maximum peer-initiated stream ID for the connection", HFILL }
        },
        /* PING */
        { &hf_quic_frame_type_ping_length,
            { "Length", "quic.frame_type.ping.length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "Describes the length of the Data field", HFILL }
        },
        { &hf_quic_frame_type_ping_data,
            { "Data", "quic.frame_type.ping.data",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "Contains arbitrary data", HFILL }
        },
        /* BLOCKED */
        { &hf_quic_frame_type_blocked_offset,
            { "Offset", "quic.frame_type.sb.offset",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Indicating the connection-level offset at which the blocking occurred", HFILL }
        },
        /* STREAM_BLOCKED */
        { &hf_quic_frame_type_sb_stream_id,
            { "Stream ID", "quic.frame_type.sb.stream_id",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Indicating the stream which is flow control blocked", HFILL }
        },
        { &hf_quic_frame_type_sb_offset,
            { "Offset", "quic.frame_type.sb.offset",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Indicating the offset of the stream at which the blocking occurred", HFILL }
        },
        /* STREAM_ID_BLOCKED */
        { &hf_quic_frame_type_sib_stream_id,
            { "Stream ID", "quic.frame_type.sib.stream_id",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Indicating the highest stream ID that the sender was permitted to open", HFILL }
        },
        /* NEW_CONNECTION_ID */
        { &hf_quic_frame_type_nci_sequence,
            { "Sequence", "quic.frame_type.nci.sequence",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Increases by 1 for each connection ID that is provided by the server", HFILL }
        },
        { &hf_quic_frame_type_nci_connection_id,
            { "Connection ID", "quic.frame_type.nci.connection_id",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_quic_frame_type_nci_stateless_reset_token,
            { "Stateless Reset Token", "quic.frame_type.stateless_reset_token",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        /* STOP_SENDING */
        { &hf_quic_frame_type_ss_stream_id,
            { "Stream ID", "quic.frame_type.ss.stream_id",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Stream ID of the stream being ignored", HFILL }
        },
        { &hf_quic_frame_type_ss_application_error_code,
            { "Application Error code", "quic.frame_type.ss.application_error_code",
              FT_UINT16, BASE_DEC|BASE_EXT_STRING, &quic_error_code_vals_ext, 0x0,
              "Indicates why the sender is ignoring the stream", HFILL }
        },
        /* PONG */
        { &hf_quic_frame_type_pong_length,
            { "Length", "quic.frame_type.pong.length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "Describes the length of the Data field", HFILL }
        },
        { &hf_quic_frame_type_pong_data,
            { "Data", "quic.frame_type.pong.data",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "Contains arbitrary data", HFILL }
        },

    };

    static gint *ett[] = {
        &ett_quic,
        &ett_quic_ft,
        &ett_quic_ftflags
    };

    static ei_register_info ei[] = {
        { &ei_quic_ft_unknown,
          { "quic.ft.unknown", PI_UNDECODED, PI_NOTE,
            "Unknown Frame Type", EXPFILL }
        },
        { &ei_quic_decryption_failed,
          { "quic.decryption_failed", PI_DECRYPTION, PI_WARN,
            "Failed to decrypt handshake", EXPFILL }
        },
    };

    proto_quic = proto_register_protocol("QUIC IETF", "QUIC", "quic");

    proto_register_field_array(proto_quic, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_quic = expert_register_protocol(proto_quic);
    expert_register_field_array(expert_quic, ei, array_length(ei));

    quic_handle = register_dissector("quic", dissect_quic, proto_quic);

}

void
proto_reg_handoff_quic(void)
{
    ssl_handle = find_dissector("ssl");
    dissector_add_uint_with_preference("udp.port", 443, quic_handle);
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
