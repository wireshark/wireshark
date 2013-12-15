/* packet-http2.c
 * Routines for HTTP2 dissection
 * Copyright 2013, Alexis La Goutte <alexis.lagoutte@gmail.com>
 * Copyright 2013, Stephen Ludin <sludin@ludin.org>
 *
 * $Id$
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
 * The information used comes from:
 * Hypertext Transfer Protocol version 2.0 draft-ietf-httpbis-http2-09
 * HTTP Header Compression draft-ietf-httpbis-header-compression-05
 *
 * TODO
* Support HTTP Header Compression (draft-ietf-httpbis-header-compression)
* Enhance display of Data
* Reassembling of continuation frame (and other frame)
* Add same tap and ping/pong time response
*/

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

#include "packet-tcp.h"

/* Packet Header */
static int proto_http2 = -1;
static int hf_http2 = -1;
static int hf_http2_length = -1;
static int hf_http2_len_rsv = -1;
static int hf_http2_type = -1;
static int hf_http2_r = -1;
static int hf_http2_streamid = -1;
static int hf_http2_magic    = -1;
static int hf_http2_unknown = -1;
/* Flags */
static int hf_http2_flags = -1;
static int hf_http2_flags_end_stream = -1;
static int hf_http2_flags_end_headers = -1;
static int hf_http2_flags_priority = -1;
static int hf_http2_flags_end_push_promise = -1;
static int hf_http2_flags_settings_ack = -1;
static int hf_http2_flags_ping_ack = -1;
static int hf_http2_flags_reserved = -1;
static int hf_http2_flags_reserved1 = -1;
#if 0
static int hf_http2_flags_reserved2 = -1;
#endif
static int hf_http2_flags_reserved3 = -1;
static int hf_http2_flags_reserved4 = -1;
/* Headers */
static int hf_http2_headers_r = -1;
static int hf_http2_headers_priority = -1;
static int hf_http2_headers    = -1;
/* Priority */
static int hf_http2_priority_r = -1;
static int hf_http2_priority = -1;
/* RST Stream */
static int hf_http2_rst_stream_error = -1;
/* Settings */
static int hf_http2_settings = -1;
static int hf_http2_settings_r = -1;
static int hf_http2_settings_identifier = -1;
static int hf_http2_settings_header_table_size = -1;
static int hf_http2_settings_enable_push = -1;
static int hf_http2_settings_max_concurrent_streams = -1;
static int hf_http2_settings_initial_window_size = -1;
static int hf_http2_settings_flow_control_options = -1;
static int hf_http2_settings_unknown = -1;
/* Push Promise */
static int hf_http2_push_promise_r = -1;
static int hf_http2_push_promise_promised_stream_id = -1;
static int hf_http2_push_promise_header = -1;
/* Ping */
static int hf_http2_ping = -1;
static int hf_http2_pong = -1;
/* Priority */
static int hf_http2_goaway_r = -1;
static int hf_http2_goaway_last_stream_id = -1;
static int hf_http2_goaway_error = -1;
static int hf_http2_goaway_addata = -1;
/* Window Update */
static int hf_http2_window_update_r = -1;
static int hf_http2_window_update_window_size_increment = -1;
/* Continuation */
static int hf_http2_continuation_header = -1;

static gint ett_http2 = -1;
static gint ett_http2_header = -1;
static gint ett_http2_flags = -1;
static gint ett_http2_settings = -1;

static expert_field ei_http2_flags_epp_old = EI_INIT;

static dissector_handle_t data_handle;
static dissector_handle_t http2_handle;

#define FRAME_HEADER_LENGTH     8
#define MAGIC_FRAME_LENGTH      24
#define MASK_HTTP2_LENGTH       0X1FFF
#define MASK_HTTP2_LEN_RSV      0XE000
#define MASK_HTTP2_RESERVED     0x80000000
#define MASK_HTTP2_STREAMID     0X7FFFFFFF
#define MASK_HTTP2_PRIORITY     0X7FFFFFFF

/* Header Type Code */
#define HTTP2_DATA          0
#define HTTP2_HEADERS       1
#define HTTP2_PRIORITY      2
#define HTTP2_RST_STREAM    3
#define HTTP2_SETTINGS      4
#define HTTP2_PUSH_PROMISE  5
#define HTTP2_PING          6
#define HTTP2_GOAWAY        7
#define HTTP2_WINDOW_UPDATE 9
#define HTTP2_CONTINUATION  10

static const value_string http2_type_vals[] = {
    { HTTP2_DATA,           "DATA" },
    { HTTP2_HEADERS,        "HEADERS" },
    { HTTP2_PRIORITY,       "PRIORITY" },
    { HTTP2_RST_STREAM,     "RST_STREAM" },
    { HTTP2_SETTINGS,       "SETTINGS" },
    { HTTP2_PUSH_PROMISE,   "PUSH_PROMISE" },
    { HTTP2_PING,           "PING" },
    { HTTP2_GOAWAY,         "GOAWAY" },
    { HTTP2_WINDOW_UPDATE,  "WINDOW_UPDATE" },
    { HTTP2_CONTINUATION,   "CONTINUATION" },
    { 0, NULL }
};

/* Flags */
#define HTTP2_FLAGS_ES          0x01
#define HTTP2_FLAGS_EH          0x04
#define HTTP2_FLAGS_PR          0x08
#define HTTP2_FLAGS_EPP_OLD     0x01 /* from draft-04 */
#define HTTP2_FLAGS_EPP         0x04
#define HTTP2_FLAGS_ACK         0x01
#define HTTP2_FLAGS_R           0xFF
#define HTTP2_FLAGS_R1          0xFE
#define HTTP2_FLAGS_R2          0xFA
#define HTTP2_FLAGS_R3          0xF2
#define HTTP2_FLAGS_R4          0xFB

/* Magic Header : PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n */
static    guint8 kMagicHello[] = {
        0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54,
        0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a,
        0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a
};

/* Error Codes */
#define EC_NO_ERROR             0
#define EC_PROTOCOL_ERROR       1
#define EC_INTERNAL_ERROR       2
#define EC_FLOW_CONTROL_ERROR   3
#define EC_SETTINGS_TIMEOUT     4
#define EC_STREAM_CLOSED        5
#define EC_FRAME_SIZE_ERROR     6
#define EC_REFUSED_STREAM       7
#define EC_CANCEL               8
#define EC_COMPRESSION_ERROR    9
#define EC_CONNECT_ERROR        10
#define EC_ENHANCE_YOUR_CALM    420

static const value_string http2_error_codes_vals[] = {
    { EC_NO_ERROR,              "NO8ERROR" },
    { EC_PROTOCOL_ERROR,        "PROTOCOL_ERROR" },
    { EC_INTERNAL_ERROR,        "INTERNAL_ERROR" },
    { EC_FLOW_CONTROL_ERROR,    "FLOW_CONTROL_ERROR" },
    { EC_SETTINGS_TIMEOUT,      "SETTINGS_TIMEOUT" },
    { EC_STREAM_CLOSED,         "STREAM_CLOSED" },
    { EC_FRAME_SIZE_ERROR,      "FRAME_SIZE_ERROR" },
    { EC_REFUSED_STREAM,        "REFUSED_STREAM" },
    { EC_CANCEL,                "CANCEL" },
    { EC_COMPRESSION_ERROR,     "COMPRESSION_ERROR" },
    { EC_CONNECT_ERROR,         "CONNECT_ERROR" },
    { EC_ENHANCE_YOUR_CALM,     "ENHANCE_YOUR_CALM" },
    { 0, NULL }
};

/* Settings */
#define HTTP2_SETTINGS_HEADER_TABLE_SIZE        1
#define HTTP2_SETTINGS_ENABLE_PUSH              2
#define HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS   4
#define HTTP2_SETTINGS_INITIAL_WINDOW_SIZE      7
#define HTTP2_SETTINGS_FLOW_CONTROL_OPTIONS     10

static const value_string http2_settings_vals[] = {
    { HTTP2_SETTINGS_HEADER_TABLE_SIZE,      "Header table size" },
    { HTTP2_SETTINGS_ENABLE_PUSH,            "Enable PUSH" },
    { HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, "Max concurrent streams" },
    { HTTP2_SETTINGS_INITIAL_WINDOW_SIZE,    "Initial Windows size" },
    { HTTP2_SETTINGS_FLOW_CONTROL_OPTIONS,   "Flow Control Options" },
    { 0, NULL }
};

/* Flags
   +--------+---------------+---------------------------+--------------+
   | Frame  | Name          | Flags                     | Section      |
   | Type   |               |                           |              |
   +--------+---------------+---------------------------+--------------+
   | 0      | DATA          | END_STREAM(1)             | Section 6.1  |
   | 1      | HEADERS       | END_STREAM(1),            | Section 6.2  |
   |        |               | END_HEADERS(4),           |              |
   |        |               | PRIORITY(8)               |              |
   | 2      | PRIORITY      | -                         | Section 6.3  |
   | 3      | RST_STREAM    | -                         | Section 6.4  |
   | 4      | SETTINGS      | ACK(1)                    | Section 6.5  |
   | 5      | PUSH_PROMISE  | END_PUSH_PROMISE(4)       | Section 6.6  |
   | 6      | PING          | ACK(1)                    | Section 6.7  |
   | 7      | GOAWAY        | -                         | Section 6.8  |
   | 9      | WINDOW_UPDATE | -                         | Section 6.9  |
   | 10     | CONTINUATION  | END_HEADERS(4)            | Section 6.10 |
   +--------+---------------+---------------------------+--------------+
*/
static guint8
dissect_http2_header_flags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *http2_tree, guint offset, guint8 type)
{
    proto_item *ti_flags;
    proto_tree *flags_tree;
    guint8 flags;

    ti_flags = proto_tree_add_item(http2_tree, hf_http2_flags, tvb, offset, 1, ENC_NA);
    flags_tree = proto_item_add_subtree(ti_flags, ett_http2_flags);
    flags = tvb_get_guint8(tvb, offset);

    switch(type){
        case HTTP2_DATA:
            proto_tree_add_item(flags_tree, hf_http2_flags_end_stream, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_reserved1, tvb, offset, 1, ENC_NA);
        break;
        case HTTP2_HEADERS:
            proto_tree_add_item(flags_tree, hf_http2_flags_end_stream, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_end_headers, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_priority, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_reserved3, tvb, offset, 1, ENC_NA);
        break;
        case HTTP2_PUSH_PROMISE:
            if(flags & HTTP2_FLAGS_EPP_OLD)
            {
                expert_add_info(pinfo, ti_flags, &ei_http2_flags_epp_old );
            }
            proto_tree_add_item(flags_tree, hf_http2_flags_end_push_promise, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_reserved4, tvb, offset, 1, ENC_NA);
        break;
        case HTTP2_PING:
            proto_tree_add_item(flags_tree, hf_http2_flags_ping_ack, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_reserved1, tvb, offset, 1, ENC_NA);
        break;
        case HTTP2_CONTINUATION:
            proto_tree_add_item(flags_tree, hf_http2_flags_end_headers, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_reserved4, tvb, offset, 1, ENC_NA);
        break;
        case HTTP2_PRIORITY:
        case HTTP2_RST_STREAM:
        case HTTP2_SETTINGS:
            proto_tree_add_item(flags_tree, hf_http2_flags_settings_ack, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_reserved1, tvb, offset, 1, ENC_NA);
        case HTTP2_GOAWAY:
        case HTTP2_WINDOW_UPDATE:
        default:
            /* No flags !*/
            proto_tree_add_item(flags_tree, hf_http2_flags_reserved, tvb, offset, 1, ENC_NA);
        break;
    }


    return flags;
}

/* Headers */
static int
dissect_http2_headers(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *http2_tree, guint offset, guint8 flags)
{

    if(flags & HTTP2_FLAGS_PR)
    {
            proto_tree_add_item(http2_tree, hf_http2_headers_r, tvb, offset, 4, ENC_NA);
            proto_tree_add_item(http2_tree, hf_http2_headers_priority, tvb, offset, 4, ENC_NA);
            offset += 4;
    }
    /* TODO : Support header decompression */
    proto_tree_add_item(http2_tree, hf_http2_headers, tvb, offset, -1, ENC_ASCII|ENC_NA);
    offset +=  tvb_reported_length_remaining(tvb, offset);

    return offset;
}

/* Priority */
static int
dissect_http2_priority(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *http2_tree, guint offset, guint8 flags _U_)
{

    proto_tree_add_item(http2_tree, hf_http2_priority_r, tvb, offset, 4, ENC_NA);
    proto_tree_add_item(http2_tree, hf_http2_priority, tvb, offset, 4, ENC_NA);
    offset += 4;

    return offset;
}

/* RST Stream */
static int
dissect_http2_rst_stream(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *http2_tree, guint offset, guint8 flags _U_)
{

    proto_tree_add_item(http2_tree, hf_http2_rst_stream_error, tvb, offset, 4, ENC_NA);
    offset += 4;

    return offset;
}

/* Settings */
static int
dissect_http2_settings(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *http2_tree, guint offset, guint8 flags _U_)
{
    guint32 settingsid;
    proto_item *ti_settings;
    proto_tree *settings_tree;

    while(tvb_reported_length_remaining(tvb, offset) > 0){

        ti_settings = proto_tree_add_item(http2_tree, hf_http2_settings, tvb, offset, 8, ENC_NA);
        settings_tree = proto_item_add_subtree(ti_settings, ett_http2_settings);
        proto_tree_add_item(settings_tree, hf_http2_settings_r, tvb, offset, 1, ENC_NA);
        offset +=1;
        proto_tree_add_item(settings_tree, hf_http2_settings_identifier, tvb, offset, 3, ENC_NA);
        settingsid = tvb_get_ntoh24(tvb, offset);
        proto_item_append_text(ti_settings, " - %s", val_to_str( settingsid, http2_settings_vals, "Unknown (%u)") );
        offset +=3;


        switch(settingsid){
            case HTTP2_SETTINGS_HEADER_TABLE_SIZE:
                proto_tree_add_item(settings_tree, hf_http2_settings_header_table_size, tvb, offset, 4, ENC_NA);
            break;
            case HTTP2_SETTINGS_ENABLE_PUSH:
                proto_tree_add_item(settings_tree, hf_http2_settings_enable_push, tvb, offset, 4, ENC_NA);
            break;
            case HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
                proto_tree_add_item(settings_tree, hf_http2_settings_max_concurrent_streams, tvb, offset, 4, ENC_NA);
            break;
            case HTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
                proto_tree_add_item(settings_tree, hf_http2_settings_initial_window_size, tvb, offset, 4, ENC_NA);
            break;
            case HTTP2_SETTINGS_FLOW_CONTROL_OPTIONS:
                proto_tree_add_item(settings_tree, hf_http2_settings_flow_control_options, tvb, offset, 4, ENC_NA);
            break;
            default:
                proto_tree_add_item(settings_tree, hf_http2_settings_unknown, tvb, offset, 4, ENC_NA);
            break;
        }
        proto_item_append_text(ti_settings, " : %u", tvb_get_ntohl(tvb, offset));
        offset += 4;
    }

    return offset;
}

/* Push Promise */
static int
dissect_http2_push_promise(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *http2_tree, guint offset, guint8 flags _U_)
{

    proto_tree_add_item(http2_tree, hf_http2_push_promise_r, tvb, offset, 4, ENC_NA);
    proto_tree_add_item(http2_tree, hf_http2_push_promise_promised_stream_id, tvb, offset, 4, ENC_NA);
    offset += 4;

    /* TODO : Support header decompression */
    proto_tree_add_item(http2_tree, hf_http2_push_promise_header, tvb, offset, -1, ENC_ASCII|ENC_NA);
    offset +=  tvb_reported_length_remaining(tvb, offset);

    return offset;
}

/* Ping */
static int
dissect_http2_ping(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *http2_tree, guint offset, guint8 flags)
{
    /* TODO : Add Response time */
    if(flags & HTTP2_FLAGS_ACK)
    {
            proto_tree_add_item(http2_tree, hf_http2_pong, tvb, offset, 8, ENC_NA);
    }else{
            proto_tree_add_item(http2_tree, hf_http2_ping, tvb, offset, 8, ENC_NA);
    }
    offset += 8;

    return offset;
}

/* Goaway */
static int
dissect_http2_goaway(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *http2_tree, guint offset, guint8 flags _U_)
{

    proto_tree_add_item(http2_tree, hf_http2_goaway_r, tvb, offset, 4, ENC_NA);
    proto_tree_add_item(http2_tree, hf_http2_goaway_last_stream_id, tvb, offset, 4, ENC_NA);
    offset += 4;

    proto_tree_add_item(http2_tree, hf_http2_goaway_error, tvb, offset, 4, ENC_NA);
    offset += 4;
    if(tvb_reported_length_remaining(tvb, offset) > 0)
    {
        proto_tree_add_item(http2_tree, hf_http2_goaway_addata , tvb, offset, -1, ENC_NA);
        offset += tvb_reported_length_remaining(tvb, offset);
    }
    return offset;
}

/* Window Update */
static int
dissect_http2_window_update(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *http2_tree, guint offset, guint8 flags _U_)
{

    proto_tree_add_item(http2_tree, hf_http2_window_update_r, tvb, offset, 4, ENC_NA);
    proto_tree_add_item(http2_tree, hf_http2_window_update_window_size_increment, tvb, offset, 4, ENC_NA);
    offset += 4;

    return offset;
}

static int
dissect_http2_continuation(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *http2_tree, guint offset, guint8 flags _U_)
{

    /* TODO : Support "Reassemble Header" and header decompression */
    proto_tree_add_item(http2_tree, hf_http2_continuation_header, tvb, offset, -1, ENC_ASCII|ENC_NA);
    offset +=  tvb_reported_length_remaining(tvb, offset);

    return offset;
}

static int
dissect_http2_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_ )
{
    proto_item *ti;
    proto_tree *http2_tree;
    tvbuff_t *next_tvb;
    guint offset = 0;
    guint8 type, flags;
    guint16 length;
    guint32 streamid;

    /* 4.1 Frame Format
         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |         Length (16)           |   Type (8)    |   Flags (8)   |
        +-+-------------+---------------+-------------------------------+
        |R|                 Stream Identifier (31)                      |
        +-+-------------------------------------------------------------+
        |                   Frame Payload (0...)                      ...
        +---------------------------------------------------------------+
    */
    ti = proto_tree_add_item(tree, hf_http2, tvb, 0, -1, ENC_NA);

    http2_tree = proto_item_add_subtree(ti, ett_http2_header);

    /* 3.5 Connection Header
       Upon establishment of a TCP connection and determination that
       HTTP/2.0 will be used by both peers, each endpoint MUST send a
       connection header as a final confirmation and to establish the
       initial settings for the HTTP/2.0 connection.
     */
    /* tvb_memeql makes certain there are enough bytes in the buffer.
     * returns -1 if there are not enough bytes or if there is not a
     * match.  Returns 0 on a match
     */
    if (tvb_memeql(tvb, offset, kMagicHello, MAGIC_FRAME_LENGTH) == 0 )
    {
        col_append_sep_str( pinfo->cinfo, COL_INFO, ", ", "Magic" );

        proto_item_set_len(ti, MAGIC_FRAME_LENGTH);
        proto_item_append_text(ti, ": Magic");

        proto_tree_add_item(http2_tree, hf_http2_magic, tvb, offset, MAGIC_FRAME_LENGTH, ENC_ASCII|ENC_NA);
        return MAGIC_FRAME_LENGTH;
    }

    proto_tree_add_item(http2_tree, hf_http2_length, tvb, offset, 2, ENC_NA);
    proto_tree_add_item(http2_tree, hf_http2_len_rsv, tvb, offset, 2, ENC_NA);
    length = tvb_get_ntohs(tvb, offset) & MASK_HTTP2_LENGTH;
    offset += 2;

    proto_tree_add_item(http2_tree, hf_http2_type, tvb, offset, 1, ENC_NA);
    type = tvb_get_guint8(tvb, offset);
    col_append_sep_fstr( pinfo->cinfo, COL_INFO, ", ", "%s", val_to_str(type, http2_type_vals, "Unknown type (%d)"));

    offset += 1;

    flags = dissect_http2_header_flags(tvb, pinfo, http2_tree, offset, type);
    offset += 1;

    proto_tree_add_item(http2_tree, hf_http2_r, tvb, offset, 4, ENC_NA);
    proto_tree_add_item(http2_tree, hf_http2_streamid, tvb, offset, 4, ENC_NA);
    streamid = tvb_get_ntohl(tvb, offset) & MASK_HTTP2_STREAMID;
    proto_item_append_text(ti, ": %s, Stream ID: %u, Length %u", val_to_str(type, http2_type_vals, "Unknown type (%d)"), streamid, length);
    offset += 4;

    switch(type){
        case HTTP2_DATA: /* Data (0) */
            /* TODO: Enhance dissect (Display in text ?) */
            next_tvb = tvb_new_subset_remaining(tvb, offset);
            call_dissector(data_handle, next_tvb, pinfo, http2_tree);
        break;

        case HTTP2_HEADERS: /* Headers (1) */
            dissect_http2_headers(tvb, pinfo, http2_tree, offset, flags);
        break;

        case HTTP2_PRIORITY: /* Priority (2) */
            dissect_http2_priority(tvb, pinfo, http2_tree, offset, flags);
        break;

        case HTTP2_RST_STREAM: /* RST Stream (3) */
            dissect_http2_rst_stream(tvb, pinfo, http2_tree, offset, flags);
        break;

        case HTTP2_SETTINGS: /* Settings (4) */
            dissect_http2_settings(tvb, pinfo, http2_tree, offset, flags);
        break;

        case HTTP2_PUSH_PROMISE: /* PUSH Promise (5) */
            dissect_http2_push_promise(tvb, pinfo, http2_tree, offset, flags);
        break;

        case HTTP2_PING: /* Ping (6) */
            dissect_http2_ping(tvb, pinfo, http2_tree, offset, flags);
        break;

        case HTTP2_GOAWAY: /* Goaway (7) */
            dissect_http2_goaway(tvb, pinfo, http2_tree, offset, flags);
        break;

        case HTTP2_WINDOW_UPDATE: /* Window Update (9) */
            dissect_http2_window_update(tvb, pinfo, http2_tree, offset, flags);
        break;

        case HTTP2_CONTINUATION: /* Continuation (10) */
            dissect_http2_continuation(tvb, pinfo, http2_tree, offset, flags);
        break;

        default:
            proto_tree_add_item(http2_tree, hf_http2_unknown, tvb, offset, -1, ENC_NA);
        break;
    }
    return tvb_length(tvb);
}

static guint get_http2_message_len( packet_info *pinfo _U_, tvbuff_t *tvb, int offset )
{
        if ( tvb_memeql( tvb, offset, kMagicHello, MAGIC_FRAME_LENGTH ) == 0 ) {
                return MAGIC_FRAME_LENGTH;
        }

        return (guint)tvb_get_ntohs(tvb, offset) + FRAME_HEADER_LENGTH;
}


static int
dissect_http2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
              void *data)
{
    proto_item *ti;
    proto_tree *http2_tree;

    /* Check that there's enough data */
    if (tvb_length(tvb) < FRAME_HEADER_LENGTH)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HTTP2");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_http2, tvb, 0, -1, ENC_NA);
    proto_item_append_text(ti, " (draft-09)");

    http2_tree = proto_item_add_subtree(ti, ett_http2);

    tcp_dissect_pdus(tvb, pinfo, http2_tree, TRUE, FRAME_HEADER_LENGTH,
                     get_http2_message_len, dissect_http2_pdu, data);

    return tvb_length(tvb);
}

static gboolean
dissect_http2_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    /* Check there is Magic Hello ( PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n ) or type is > 10 (May be leak) */
    if (tvb_memeql(tvb, 0, kMagicHello, MAGIC_FRAME_LENGTH) != 0 && tvb_get_guint8(tvb, 2) > 10)
        return (FALSE);

    dissect_http2(tvb, pinfo, tree, data);

    return (TRUE);
}

void
proto_register_http2(void)
{

    static hf_register_info hf[] = {
        /* Packet Header */
        { &hf_http2,
            { "Stream", "http2",
               FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http2_length,
            { "Length", "http2.length",
               FT_UINT16, BASE_DEC, NULL, MASK_HTTP2_LENGTH,
              "The length (14 bits) of the frame payload (The 8 octets of the frame header are not included)", HFILL }
        },
        { &hf_http2_len_rsv,
            { "Reserved", "http2.len.rsv",
               FT_UINT16, BASE_DEC, NULL, MASK_HTTP2_LEN_RSV,
              "Must be zero", HFILL }
        },
        { &hf_http2_type,
            { "Type", "http2.type",
               FT_UINT8, BASE_DEC, VALS(http2_type_vals), 0x0,
              "The frame type determines how the remainder of the frame header and payload are interpreted", HFILL }
        },
        { &hf_http2_r,
            { "Reserved", "http2.r",
               FT_UINT32, BASE_HEX, NULL, MASK_HTTP2_RESERVED,
              "The semantics of this bit are undefined and the bit MUST remain unset (0) when sending and MUST be ignored when receiving", HFILL }
        },
        { &hf_http2_streamid,
            { "Stream Identifier", "http2.streamid",
               FT_UINT32, BASE_DEC, NULL, MASK_HTTP2_STREAMID,
              "A 31-bit stream identifier", HFILL }
        },
        { &hf_http2_magic,
            { "Magic", "http2.magic",
               FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http2_unknown,
            { "Unknown", "http2.unknown",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        /* Flags */
        { &hf_http2_flags,
            { "Flags", "http2.flags",
               FT_UINT8, BASE_HEX, NULL, 0x0,
              "Flags are assigned semantics specific to the indicated frame type", HFILL }
        },
        { &hf_http2_flags_end_stream,
            { "End Stream", "http2.flags.es",
               FT_BOOLEAN, 8, NULL, HTTP2_FLAGS_ES,
              "Indicates that this frame is the last that the endpoint will send for the identified stream", HFILL }
        },
        { &hf_http2_flags_end_headers,
            { "End Headers", "http2.flags.eh",
               FT_BOOLEAN, 8, NULL, HTTP2_FLAGS_EH,
              "Indicates that this frame contains an entire header block  and is not followed by any CONTINUATION frames.", HFILL }
        },
        { &hf_http2_flags_priority,
            { "Priority", "http2.flags.pr",
               FT_BOOLEAN, 8, NULL, HTTP2_FLAGS_PR,
              "Set indicates that the first four octets of this frame contain a single reserved bit and a 31-bit priority", HFILL }
        },
        { &hf_http2_flags_end_push_promise,
            { "End Push Promise", "http2.flags.epp",
               FT_BOOLEAN, 8, NULL, HTTP2_FLAGS_EPP,
              "Set indicates that this frame ends the sequence of header block fragments necessary to provide a complete set of headers", HFILL }
        },
        { &hf_http2_flags_ping_ack,
            { "ACK", "http2.flags.ack.ping",
               FT_BOOLEAN, 8, NULL, HTTP2_FLAGS_ACK,
              "Set indicates that this PING frame is a PING response", HFILL }
        },
        { &hf_http2_flags_settings_ack,
            { "ACK", "http2.flags.ack.settings",
               FT_BOOLEAN, 8, NULL, HTTP2_FLAGS_ACK,
              "Indicates that this frame acknowledges receipt and application of the peer's SETTINGS frame", HFILL }
        },
        { &hf_http2_flags_reserved,
            { "Reserved", "http2.flags.r",
               FT_UINT8, BASE_HEX, NULL, HTTP2_FLAGS_R,
              "(Must be zero)", HFILL }
        },
        { &hf_http2_flags_reserved1,
            { "Reserved", "http2.flags.r1",
               FT_UINT8, BASE_HEX, NULL, HTTP2_FLAGS_R1,
              "(Must be zero)", HFILL }
        },
#if 0
        { &hf_http2_flags_reserved2,
            { "Reserved", "http2.flags.r2",
               FT_UINT8, BASE_HEX, NULL, HTTP2_FLAGS_R2,
              "(Must be zero)", HFILL }
        },
#endif
        { &hf_http2_flags_reserved3,
            { "Reserved", "http2.flags.r3",
               FT_UINT8, BASE_HEX, NULL, HTTP2_FLAGS_R3,
              "(Must be zero)", HFILL }
        },
        { &hf_http2_flags_reserved4,
            { "Reserved", "http2.flags.r4",
               FT_UINT8, BASE_HEX, NULL, HTTP2_FLAGS_R4,
              "(Must be zero)", HFILL }
        },
        /* Headers */
        { &hf_http2_headers_r,
            { "Reserved", "http2.headers.r",
               FT_UINT32, BASE_HEX, NULL, MASK_HTTP2_RESERVED,
              "Must be zero", HFILL }
        },
        { &hf_http2_headers_priority,
            { "Priority", "http2.headers.priority",
               FT_UINT32, BASE_DEC, NULL, MASK_HTTP2_PRIORITY,
              "Priority for the stream (0 is the highest priority)", HFILL }
        },
        { &hf_http2_headers,
            { "Headers", "http2.headers",
               FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        /* Priority */
        { &hf_http2_priority_r,
            { "Reserved", "http2.priority.r",
               FT_UINT32, BASE_HEX, NULL, MASK_HTTP2_RESERVED,
              "Must be zero", HFILL }
        },
        { &hf_http2_priority,
            { "Priority", "http2.priority",
               FT_UINT32, BASE_DEC, NULL, MASK_HTTP2_PRIORITY,
              "Priority for the stream (0 is the highest priority)", HFILL }
        },

        /* RST Stream */
        { &hf_http2_rst_stream_error,
            { "Error", "http2.rst_stream.error",
               FT_UINT32, BASE_DEC, VALS(http2_error_codes_vals), 0x0,
              "The error code indicates why the stream is being terminated", HFILL }
        },

        /* Settings */
        { &hf_http2_settings,
            { "Settings", "http2.settings",
               FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http2_settings_r,
            { "Reserved", "http2.settings.r",
               FT_UINT8, BASE_HEX, NULL, 0x0,
              "Must be zero", HFILL }
        },
        { &hf_http2_settings_identifier,
            { "Settings Identifier", "http2.settings.id",
               FT_UINT24, BASE_DEC, VALS(http2_settings_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_http2_settings_header_table_size,
            { "Header table size", "http2.settings.header_table_size",
               FT_UINT32, BASE_DEC, NULL, 0x0,
              "Allows the sender to inform the remote endpoint of the size of the header compression table used to decode header blocks. The initial value is 4096 byte", HFILL }
        },
        { &hf_http2_settings_enable_push,
            { "Enable PUSH", "http2.settings.enable_push",
               FT_UINT32, BASE_DEC, NULL, 0x0,
              "The initial value is 1, which indicates that push is permitted", HFILL }
        },
        { &hf_http2_settings_max_concurrent_streams,
            { "Max concurrent streams", "http2.settings.max_concurrent_streams",
               FT_UINT32, BASE_DEC, NULL, 0x0,
              "Indicates the maximum number of concurrent streams that the sender will allow", HFILL }
        },
        { &hf_http2_settings_initial_window_size,
            { "Initial Windows Size", "http2.settings.initial_window_size",
               FT_UINT32, BASE_DEC, NULL, 0x0,
              "Indicates the sender's initial window size (in bytes) for stream level flow control", HFILL }
        },
        { &hf_http2_settings_flow_control_options,
            { "Flow Control Options", "http2.settings.flow_control_options",
               FT_UINT32, BASE_DEC, NULL, 0x0,
              "Indicates flow control options", HFILL }
        },
        { &hf_http2_settings_unknown,
            { "Unknown Settings", "http2.settings.unknown",
               FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },

        /* Push Promise */
        { &hf_http2_push_promise_r,
            { "Reserved", "http2.push_promise.r",
               FT_UINT32, BASE_HEX, NULL, MASK_HTTP2_RESERVED,
              "Must be zero", HFILL }
        },
        { &hf_http2_push_promise_promised_stream_id,
            { "Promised-Stream-ID", "http2.push_promise.promised_stream_id",
               FT_UINT32, BASE_DEC, NULL, MASK_HTTP2_PRIORITY,
              "Identifies the stream the endpoint intends to start sending frames for", HFILL }
        },
        { &hf_http2_push_promise_header,
            { "Header", "http2.push_promise.header",
               FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        /* Ping / Pong */
        { &hf_http2_ping,
            { "Ping", "http2.ping",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http2_pong,
            { "Pong", "http2.pong",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        /* Goaway */
        { &hf_http2_goaway_r,
            { "Reserved", "http2.goway.r",
               FT_UINT32, BASE_HEX, NULL, MASK_HTTP2_RESERVED,
              "Must be zero", HFILL }
        },
        { &hf_http2_goaway_last_stream_id,
            { "Promised-Stream-ID", "http2.goaway.last_stream_id",
               FT_UINT32, BASE_DEC, NULL, MASK_HTTP2_PRIORITY,
              "Contains the highest numbered stream identifier for which the sender of the GOAWAY frame has received frames on and might have taken some action on", HFILL }
        },
        { &hf_http2_goaway_error,
            { "Error", "http2.goaway.error",
               FT_UINT32, BASE_DEC, VALS(http2_error_codes_vals), 0x0,
              "The error code indicates the reason for closing the connection", HFILL }
        },
        { &hf_http2_goaway_addata,
            { "Additional Debug Data", "http2.goaway.addata",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        /* Window Update */
        { &hf_http2_window_update_r,
            { "Reserved", "http2.window_update.r",
               FT_UINT32, BASE_HEX, NULL, MASK_HTTP2_RESERVED,
              "Must be zero", HFILL }
        },
        { &hf_http2_window_update_window_size_increment,
            { "Window Size Increment", "http2.window_update.window_size_increment",
               FT_UINT32, BASE_DEC, NULL, MASK_HTTP2_PRIORITY,
              "Indicating the number of bytes that the sender can transmit in addition to the existing flow control window", HFILL }
        },

        /* Continuation */
        { &hf_http2_continuation_header,
            { "Continuation Header", "http2.continuation.header",
               FT_STRING, BASE_NONE, NULL, 0x0,
              "Contains a header block fragment", HFILL }
        },

    };

  static ei_register_info ei[] = {
     { &ei_http2_flags_epp_old, { "http2.flags.epp_old", PI_PROTOCOL, PI_WARN, "Deprecated End Push Promise flags (Now need to use 0x04)", EXPFILL }},
  };

    static gint *ett[] = {
        &ett_http2,
        &ett_http2_header,
        &ett_http2_flags,
        &ett_http2_settings
    };

    expert_module_t* expert_http2;

    proto_http2 = proto_register_protocol("HyperText Transfer Protocol 2", "HTTP2", "http2");

    proto_register_field_array(proto_http2, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_http2 = expert_register_protocol(proto_http2);
    expert_register_field_array(expert_http2, ei, array_length(ei));

    new_register_dissector("http2", dissect_http2, proto_http2);
}

void
proto_reg_handoff_http2(void)
{
    data_handle = find_dissector("data");

    http2_handle = new_create_dissector_handle(dissect_http2, proto_http2);
    dissector_add_handle("tcp.port", http2_handle);

    heur_dissector_add("ssl", dissect_http2_heur, proto_http2);
    heur_dissector_add("http", dissect_http2_heur, proto_http2);
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
