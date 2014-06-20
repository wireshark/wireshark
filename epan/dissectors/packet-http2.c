/* packet-http2.c
 * Routines for HTTP2 dissection
 * Copyright 2013, Alexis La Goutte <alexis.lagoutte@gmail.com>
 * Copyright 2013, Stephen Ludin <sludin@ludin.org>
 * Copyright 2014, Daniel Stenberg <daniel@haxx.se>
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
 * Hypertext Transfer Protocol version 2.0 draft-ietf-httpbis-http2-12
 * HTTP Header Compression draft-ietf-httpbis-header-compression-07
 *
 * TODO
* Support HTTP Header Compression (draft-ietf-httpbis-header-compression)
* Enhance display of Data
* Reassembling of continuation frame (and other frame)
* Add same tap and ping/pong time response
*/

#include "config.h"

#include <stdio.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/conversation.h>
#include <epan/follow.h>

#include <wsutil/nghttp2/nghttp2/nghttp2.h>

#include "packet-tcp.h"

/* struct to hold data per HTTP/2 session */
typedef struct {
    /* We need 2 inflater object for both client and server.  Since
       inflater object is symmetrical, we just want to know which
       inflater is used for each TCP flow.  The hd_inflater_first_flow
       is used to select which one to use.  Basically, we first record
       fwd of tcp_analysis in hd_inflater_first_flow and if processing
       packet_info has fwd of tcp_analysis equal to
       hd_inflater_first_flow, we use hd_inflater[0], otherwise 2nd
       one.
     */
    nghttp2_hd_inflater *hd_inflater[2];
    tcp_flow_t *hd_inflater_first_flow;
} http2_session_t;

typedef struct {
    /* Hash table, associates TCP stream index to http2_session_t object */
    wmem_map_t *sessions;
} http2_data_t;

void proto_register_http2(void);
void proto_reg_handoff_http2(void);

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
static int hf_http2_flags_end_segment = -1;
static int hf_http2_flags_end_headers = -1;
static int hf_http2_flags_pad_low = -1;
static int hf_http2_flags_pad_high = -1;
static int hf_http2_flags_priority = -1;
static int hf_http2_flags_compressed = -1;
static int hf_http2_flags_settings_ack = -1;
static int hf_http2_flags_ping_ack = -1;
static int hf_http2_flags_unused = -1;
static int hf_http2_flags_unused1 = -1;
static int hf_http2_flags_unused3 = -1;
static int hf_http2_flags_unused_data = -1;
static int hf_http2_flags_unused6 = -1;

/* generic */
static int hf_http2_pad_high = -1;
static int hf_http2_pad_low = -1;
static int hf_http2_pad_length = -1;

static int hf_http2_weight = -1;
static int hf_http2_weight_real = -1;
static int hf_http2_stream_dependency = -1;
static int hf_http2_excl_dependency = -1;
/* Data */
static int hf_http2_data_data = -1;
static int hf_http2_data_padding = -1;
/* Headers */
static int hf_http2_headers = -1;
static int hf_http2_headers_padding = -1;
static int hf_http2_header = -1;
static int hf_http2_header_length = -1;
static int hf_http2_header_name_length = -1;
static int hf_http2_header_name = -1;
static int hf_http2_header_value_length = -1;
static int hf_http2_header_value = -1;
/* RST Stream */
static int hf_http2_rst_stream_error = -1;
/* Settings */
static int hf_http2_settings = -1;
static int hf_http2_settings_identifier = -1;
static int hf_http2_settings_header_table_size = -1;
static int hf_http2_settings_enable_push = -1;
static int hf_http2_settings_max_concurrent_streams = -1;
static int hf_http2_settings_initial_window_size = -1;
static int hf_http2_settings_compress_data = -1;
static int hf_http2_settings_unknown = -1;
/* Push Promise */
static int hf_http2_push_promise_r = -1;
static int hf_http2_push_promise_promised_stream_id = -1;
static int hf_http2_push_promise_header = -1;
static int hf_http2_push_promise_padding = -1;
/* Ping */
static int hf_http2_ping = -1;
static int hf_http2_pong = -1;
/* Goaway */
static int hf_http2_goaway_r = -1;
static int hf_http2_goaway_last_stream_id = -1;
static int hf_http2_goaway_error = -1;
static int hf_http2_goaway_addata = -1;
/* Window Update */
static int hf_http2_window_update_r = -1;
static int hf_http2_window_update_window_size_increment = -1;
/* Continuation */
static int hf_http2_continuation_header = -1;
static int hf_http2_continuation_padding = -1;
/* Altsvc */
static int hf_http2_altsvc_maxage = -1;
static int hf_http2_altsvc_port = -1;
static int hf_http2_altsvc_res = -1;
static int hf_http2_altsvc_proto_len = -1;
static int hf_http2_altsvc_protocol = -1;
static int hf_http2_altsvc_host_len = -1;
static int hf_http2_altsvc_host = -1;
static int hf_http2_altsvc_origin = -1;
/* Blocked */


static gint ett_http2 = -1;
static gint ett_http2_header = -1;
static gint ett_http2_headers = -1;
static gint ett_http2_flags = -1;
static gint ett_http2_settings = -1;

static dissector_handle_t data_handle;
static dissector_handle_t http2_handle;

#define FRAME_HEADER_LENGTH     8
#define MAGIC_FRAME_LENGTH      24
#define MASK_HTTP2_LENGTH       0X3FFF
#define MASK_HTTP2_LEN_RSV      0XC000
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
#define HTTP2_WINDOW_UPDATE 8
#define HTTP2_CONTINUATION  9
#define HTTP2_ALTSVC        0xA
#define HTTP2_BLOCKED       0xB

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
    { HTTP2_ALTSVC,         "ALTSVC" },
    { HTTP2_BLOCKED,        "BLOCKED" },
    { 0, NULL }
};

/* Flags */
#define HTTP2_FLAGS_ACK         0x01 /* for PING and SETTINGS */

#define HTTP2_FLAGS_END_STREAM  0x01
#define HTTP2_FLAGS_END_SEGMENT 0x02
#define HTTP2_FLAGS_END_HEADERS 0x04
#define HTTP2_FLAGS_PAD_LOW     0x08
#define HTTP2_FLAGS_PAD_HIGH    0x10
#define HTTP2_FLAGS_PRIORITY    0x20
#define HTTP2_FLAGS_COMPRESSED  0x20

#define HTTP2_FLAGS_R           0xFF
#define HTTP2_FLAGS_R1          0xFE
#define HTTP2_FLAGS_R2          0xFA
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
    { EC_NO_ERROR,              "NO_ERROR" },
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
#define HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS   3
#define HTTP2_SETTINGS_INITIAL_WINDOW_SIZE      4
#define HTTP2_SETTINGS_COMPRESS_DATA            5

static const value_string http2_settings_vals[] = {
    { HTTP2_SETTINGS_HEADER_TABLE_SIZE,      "Header table size" },
    { HTTP2_SETTINGS_ENABLE_PUSH,            "Enable PUSH" },
    { HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, "Max concurrent streams" },
    { HTTP2_SETTINGS_INITIAL_WINDOW_SIZE,    "Initial Windows size" },
    { HTTP2_SETTINGS_COMPRESS_DATA,          "Compress data" },
    { 0, NULL }
};

static http2_session_t*
create_http2_session(packet_info *pinfo)
{
    conversation_t *conversation;
    http2_data_t *http2;
    http2_session_t *h2session;
    struct tcp_analysis *tcpd;

    conversation = find_or_create_conversation(pinfo);

    http2 = (http2_data_t*)conversation_get_proto_data(conversation,
                                                       proto_http2);

    if(http2 == NULL) {
        http2 = wmem_new(wmem_file_scope(), http2_data_t);

        http2->sessions = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);

        conversation_add_proto_data(conversation, proto_http2, http2);
    }

    tcpd = get_tcp_conversation_data(NULL, pinfo);

    h2session = wmem_new(wmem_file_scope(), http2_session_t);
    nghttp2_hd_inflate_new(&h2session->hd_inflater[0]);
    nghttp2_hd_inflate_new(&h2session->hd_inflater[1]);
    h2session->hd_inflater_first_flow = tcpd->fwd;

    wmem_map_insert(http2->sessions, GUINT_TO_POINTER(tcpd->stream), h2session);

    return h2session;
}

static http2_session_t*
get_http2_session(packet_info *pinfo)
{
    conversation_t *conversation;
    http2_data_t *http2;
    http2_session_t *h2session;
    struct tcp_analysis *tcpd;

    conversation = find_or_create_conversation(pinfo);

    http2 = (http2_data_t*)conversation_get_proto_data(conversation,
                                                       proto_http2);

    if(!http2) {
        return NULL;
    }

    tcpd = get_tcp_conversation_data(NULL, pinfo);

    h2session = (http2_session_t*)wmem_map_lookup(http2->sessions, GUINT_TO_POINTER(tcpd->stream));

    return h2session;
}

static nghttp2_hd_inflater*
select_http2_hd_inflater(packet_info *pinfo, http2_session_t *h2session)
{
    struct tcp_analysis *tcpd;

    tcpd = get_tcp_conversation_data(NULL, pinfo);

    if(tcpd->fwd == h2session->hd_inflater_first_flow) {
        return h2session->hd_inflater[0];
    } else {
        return h2session->hd_inflater[1];
    }
}

static void
inflate_http2_header_block(tvbuff_t *tvb, packet_info *pinfo, guint offset,
                           proto_tree *tree, size_t headlen,
                           http2_session_t *h2session, guint8 flags)
{
    guint8 *headbuf;
    proto_tree *header_tree;
    proto_item *header, *ti;
    int header_name_length;
    int header_value_length;
    const gchar *header_name;
    const gchar *header_value;
    int hoffset = 0;
    nghttp2_hd_inflater *hd_inflater;
    tvbuff_t *header_tvb = tvb_new_composite();
    int rv;
    int header_len = 0, len;
    int final;
    if(!h2session) {
        /* We may not be able to track all HTTP/2 session if we miss
           first magic (connection preface) */
        return;
    }

    headbuf = (guint8*)wmem_alloc(wmem_packet_scope(), headlen);
    tvb_memcpy(tvb, headbuf, offset, headlen);

    hd_inflater = select_http2_hd_inflater(pinfo, h2session);

    final = flags & HTTP2_FLAGS_END_HEADERS;

    for(;;) {
        nghttp2_nv nv;
        int inflate_flags = 0;

        rv = (int)nghttp2_hd_inflate_hd(hd_inflater, &nv,
                                        &inflate_flags, headbuf, headlen, final);

        if(rv < 0) {
            break;
        }

        headbuf += rv;
        headlen -= rv;

        if(inflate_flags & NGHTTP2_HD_INFLATE_EMIT) {
            tvbuff_t *next_tvb;
            char *str = (char *)g_malloc(4 + nv.namelen + 4  + nv.valuelen);
            /* Prepare tvb buffer... with the following format
               name length (uint32)
               name (string)
               value length (uint32)
               value (string)

            */
            memcpy(&str[0], (char *)&nv.namelen, 4);
            memcpy(&str[4], nv.name, nv.namelen);
            memcpy(&str[4+nv.namelen], (char *)&nv.valuelen, 4);
            memcpy(&str[4+nv.namelen+4], nv.value, nv.valuelen);

            len = (int)(4 + nv.namelen + 4 + nv.valuelen);
            header_len += len;

            /* Now setup the tvb buffer to have the new data */
            next_tvb = tvb_new_child_real_data(tvb, str, len, len);
            tvb_set_free_cb(next_tvb, g_free);
            tvb_composite_append(header_tvb, next_tvb);
        }
        if(inflate_flags & NGHTTP2_HD_INFLATE_FINAL) {
            nghttp2_hd_inflate_end_headers(hd_inflater);
            break;
        }
        if((inflate_flags & NGHTTP2_HD_INFLATE_EMIT) == 0 &&
           headlen == 0) {
            break;
        }
    }
    tvb_composite_finalize(header_tvb);
    add_new_data_source(pinfo, header_tvb, "Decompressed Header");

    ti = proto_tree_add_uint(tree, hf_http2_header_length, header_tvb, hoffset, 1, header_len);
    PROTO_ITEM_SET_GENERATED(ti);

    while (tvb_reported_length_remaining(header_tvb, hoffset) > 0) {
        /* Populate tree with header name/value details. */
        /* Add 'Header' subtree with description. */
        header = proto_tree_add_item(tree, hf_http2_header, header_tvb, hoffset, -1, ENC_NA);
        header_tree = proto_item_add_subtree(header, ett_http2_headers);

        /* header value length */
        proto_tree_add_item(header_tree, hf_http2_header_name_length, header_tvb, hoffset, 4, ENC_LITTLE_ENDIAN);
        header_name_length = tvb_get_letohl(header_tvb, hoffset);
        hoffset += 4;

        /* Add header name. */
        proto_tree_add_item(header_tree, hf_http2_header_name, header_tvb, hoffset, header_name_length, ENC_ASCII|ENC_NA);
        header_name = (gchar *)tvb_get_string_enc(wmem_packet_scope(), header_tvb, hoffset, header_name_length, ENC_ASCII|ENC_NA);
        hoffset += header_name_length;

        /* header value length */
        proto_tree_add_item(header_tree, hf_http2_header_value_length, header_tvb, hoffset, 4, ENC_LITTLE_ENDIAN);
        header_value_length = tvb_get_letohl(header_tvb, hoffset);
        hoffset += 4;

        /* Add header value. */
        proto_tree_add_item(header_tree, hf_http2_header_value, header_tvb, hoffset, header_value_length, ENC_ASCII|ENC_NA);
        header_value = (gchar *)tvb_get_string_enc(wmem_packet_scope(),header_tvb, hoffset, header_value_length, ENC_ASCII|ENC_NA);
        hoffset += header_value_length;

        proto_item_append_text(header, ": %s: %s", header_name, header_value);
        proto_item_set_len(header, 4 + header_name_length + 4 + header_value_length);
    }
}

static guint8
dissect_http2_header_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *http2_tree, guint offset, guint8 type)
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
            proto_tree_add_item(flags_tree, hf_http2_flags_end_segment, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_pad_low, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_pad_high, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_compressed, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_unused_data, tvb, offset, 1, ENC_NA);
            break;
        case HTTP2_HEADERS:
            proto_tree_add_item(flags_tree, hf_http2_flags_end_stream, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_end_segment, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_end_headers, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_pad_low, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_pad_high, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_priority, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_unused6, tvb, offset, 1, ENC_NA);
            break;
        case HTTP2_SETTINGS:
            proto_tree_add_item(flags_tree, hf_http2_flags_settings_ack, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_unused1, tvb, offset, 1, ENC_NA);
            break;
        case HTTP2_PUSH_PROMISE:
        case HTTP2_CONTINUATION:
            proto_tree_add_item(flags_tree, hf_http2_flags_end_headers, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_pad_low, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_pad_high, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_unused3, tvb, offset, 1, ENC_NA);
            break;
        case HTTP2_PING:
            proto_tree_add_item(flags_tree, hf_http2_flags_ping_ack, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_unused1, tvb, offset, 1, ENC_NA);
            break;
        case HTTP2_PRIORITY:
        case HTTP2_RST_STREAM:
        case HTTP2_GOAWAY:
        case HTTP2_WINDOW_UPDATE:
        case HTTP2_ALTSVC:
        case HTTP2_BLOCKED:
        default:
            /* Does not define any flags */
            proto_tree_add_item(flags_tree, hf_http2_flags_unused, tvb, offset, 1, ENC_NA);
            break;
    }


    return flags;
}

/* helper function to get the padding data for the frames that feature them */
static guint
dissect_frame_padding(tvbuff_t *tvb, guint16 *padding, proto_tree *http2_tree,
                      guint offset, guint8 flags)
{
    proto_item *ti;
    guint pad_len = 0;

    *padding = 0;
    if(flags & HTTP2_FLAGS_PAD_HIGH)
    {
        *padding = tvb_get_guint8(tvb, offset) << 8; /* read a single octet */
        proto_tree_add_item(http2_tree, hf_http2_pad_high, tvb, offset, 1, ENC_NA);
        offset++;
        pad_len ++;
    }

    if(flags & HTTP2_FLAGS_PAD_LOW)
    {
        *padding |= tvb_get_guint8(tvb, offset); /* read a single octet */
        proto_tree_add_item(http2_tree, hf_http2_pad_low, tvb, offset, 1, ENC_NA);
        offset++;
        pad_len ++;
    }
    ti = proto_tree_add_uint(http2_tree, hf_http2_pad_length, tvb, offset-pad_len, pad_len, *padding);
    PROTO_ITEM_SET_GENERATED(ti);

    return offset;
}

/* helper function to get the priority dependence for the frames that feature them:
   HEADERS and PRIORITY */
static guint
dissect_frame_prio(tvbuff_t *tvb, proto_tree *http2_tree, guint offset, guint8 flags)
{
    proto_tree *ti;
    guint8 weight;

    if(flags & HTTP2_FLAGS_PRIORITY)
    {
        proto_tree_add_item(http2_tree, hf_http2_excl_dependency, tvb, offset, 4, ENC_NA);
        proto_tree_add_item(http2_tree, hf_http2_stream_dependency, tvb, offset, 4, ENC_NA);
        offset += 4;
        proto_tree_add_item(http2_tree, hf_http2_weight, tvb, offset, 1, ENC_NA);
        weight = tvb_get_guint8(tvb, offset);
        /* 6.2: Weight:  An 8-bit weight for the stream; Add one to the value to obtain a weight between 1 and 256 */
        ti = proto_tree_add_uint(http2_tree, hf_http2_weight_real, tvb, offset, 1, weight+1);
        PROTO_ITEM_SET_GENERATED(ti);
        offset++;
    }

    return offset;
}


/* Data (0) */
static int
dissect_http2_data(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *http2_tree,
                   guint offset, guint8 flags)
{
    guint16 padding;
    gint datalen;

    offset = dissect_frame_padding(tvb, &padding, http2_tree, offset, flags);
    datalen = tvb_reported_length_remaining(tvb, offset) - padding;
    proto_tree_add_item(http2_tree, hf_http2_data_data, tvb, offset, datalen, ENC_ASCII|ENC_NA);
    offset += datalen;

    proto_tree_add_item(http2_tree, hf_http2_data_padding, tvb, offset, padding, ENC_NA);
    offset += padding;

    return offset;
}

/* Headers */
static int
dissect_http2_headers(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *http2_tree,
                      guint offset, guint8 flags)
{
    guint16 padding;
    gint headlen;
    http2_session_t *h2session;

    h2session = get_http2_session(pinfo);

    offset = dissect_frame_padding(tvb, &padding, http2_tree, offset, flags);
    offset = dissect_frame_prio(tvb, http2_tree, offset, flags);

    headlen = tvb_reported_length_remaining(tvb, offset) - padding;
    proto_tree_add_item(http2_tree, hf_http2_headers, tvb, offset, headlen, ENC_ASCII|ENC_NA);

    /* decompress the header block */
    inflate_http2_header_block(tvb, pinfo, offset, http2_tree, headlen, h2session, flags);

    offset += headlen;

    proto_tree_add_item(http2_tree, hf_http2_headers_padding, tvb, offset, padding, ENC_NA);
    offset += padding;
    return offset;
}

/* Priority */
static int
dissect_http2_priority(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *http2_tree,
                       guint offset, guint8 flags)
{
    /* we pretend the HTTP2_FLAGS_PRIORITY flag is set to share the dissect
       function */
    offset = dissect_frame_prio(tvb, http2_tree, offset,
                                flags | HTTP2_FLAGS_PRIORITY);
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

    /* FIXME: If we send SETTINGS_HEADER_TABLE_SIZE, after receiving
       ACK from peer, we have to apply its value to HPACK decoder
       using nghttp2_hd_inflate_change_table_size() */

    while(tvb_reported_length_remaining(tvb, offset) > 0){

        ti_settings = proto_tree_add_item(http2_tree, hf_http2_settings, tvb, offset, 5, ENC_NA);
        settings_tree = proto_item_add_subtree(ti_settings, ett_http2_settings);
        proto_tree_add_item(settings_tree, hf_http2_settings_identifier, tvb, offset, 1, ENC_NA);
        settingsid = tvb_get_guint8(tvb, offset);
        proto_item_append_text(ti_settings, " - %s",
                               val_to_str( settingsid, http2_settings_vals, "Unknown (%u)") );
        offset++;


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
            case HTTP2_SETTINGS_COMPRESS_DATA:
                proto_tree_add_item(settings_tree, hf_http2_settings_compress_data, tvb, offset, 4, ENC_NA);
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
dissect_http2_push_promise(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *http2_tree,
                           guint offset, guint8 flags _U_)
{
    guint16 padding;
    gint headlen;
    http2_session_t *h2session;

    h2session = get_http2_session(pinfo);

    offset = dissect_frame_padding(tvb, &padding, http2_tree, offset, flags);

    proto_tree_add_item(http2_tree, hf_http2_push_promise_r, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(http2_tree, hf_http2_push_promise_promised_stream_id, tvb,
                        offset, 4, ENC_NA);
    offset += 4;

    headlen = tvb_reported_length_remaining(tvb, offset) - padding;
    proto_tree_add_item(http2_tree, hf_http2_push_promise_header, tvb, offset, headlen,
                        ENC_ASCII|ENC_NA);

    inflate_http2_header_block(tvb, pinfo, offset, http2_tree, headlen, h2session, flags);

    offset += headlen;

    proto_tree_add_item(http2_tree, hf_http2_push_promise_padding, tvb,
                        offset, padding, ENC_NA);

    offset +=  tvb_reported_length_remaining(tvb, offset);

    return offset;
}

/* Ping */
static int
dissect_http2_ping(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *http2_tree,
                   guint offset, guint8 flags)
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
dissect_http2_continuation(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *http2_tree, guint offset, guint8 flags)
{
    guint16 padding;
    gint headlen;
    http2_session_t *h2session;

    h2session = get_http2_session(pinfo);

    offset = dissect_frame_padding(tvb, &padding, http2_tree, offset, flags);

    headlen = tvb_reported_length_remaining(tvb, offset) - padding;
    proto_tree_add_item(http2_tree, hf_http2_continuation_header, tvb, offset, headlen, ENC_ASCII|ENC_NA);

    inflate_http2_header_block(tvb, pinfo, offset, http2_tree, headlen, h2session, flags);

    offset +=  headlen;

    proto_tree_add_item(http2_tree, hf_http2_continuation_padding, tvb, offset, padding, ENC_NA);

    offset += padding;

    return offset;
}


/* Altsvc */
static int
dissect_http2_altsvc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *http2_tree,
                     guint offset, guint8 flags _U_, guint16 length)
{
    guint8 pidlen;
    guint8 hostlen;
    int remain;

    proto_tree_add_item(http2_tree, hf_http2_altsvc_maxage, tvb, offset, 4, ENC_NA);
    offset+=4;

    proto_tree_add_item(http2_tree, hf_http2_altsvc_port, tvb, offset, 2, ENC_NA);
    offset += 2;

    proto_tree_add_item(http2_tree, hf_http2_altsvc_res, tvb, offset, 1, ENC_NA);
    offset ++;

    proto_tree_add_item(http2_tree, hf_http2_altsvc_proto_len, tvb, offset, 1, ENC_NA);
    pidlen = tvb_get_guint8(tvb, offset);
    offset ++;

    proto_tree_add_item(http2_tree, hf_http2_altsvc_protocol, tvb, offset, pidlen, ENC_ASCII|ENC_NA);
    offset += pidlen;

    proto_tree_add_item(http2_tree, hf_http2_altsvc_host_len, tvb, offset, 1, ENC_NA);
    hostlen = tvb_get_guint8(tvb, offset);
    offset ++;

    proto_tree_add_item(http2_tree, hf_http2_altsvc_host, tvb, offset, hostlen, ENC_ASCII|ENC_NA);
    offset += hostlen;

    remain = length - offset;
    if(remain > -8) {
        /* 8 is the fixed size of the http2 frame header */
        proto_tree_add_item(http2_tree, hf_http2_altsvc_origin, tvb,
                            offset, remain + 8, ENC_ASCII|ENC_NA);
        offset += remain;
    }

    return offset;
}


static int
dissect_http2_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_ )
{
    proto_item *ti;
    proto_tree *http2_tree;
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

        create_http2_session(pinfo);

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
            dissect_http2_data(tvb, pinfo, http2_tree, offset, flags);
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

        case HTTP2_WINDOW_UPDATE: /* Window Update (8) */
            dissect_http2_window_update(tvb, pinfo, http2_tree, offset, flags);
        break;

        case HTTP2_CONTINUATION: /* Continuation (9) */
            dissect_http2_continuation(tvb, pinfo, http2_tree, offset, flags);
        break;

        case HTTP2_ALTSVC: /* ALTSVC (10) */
            dissect_http2_altsvc(tvb, pinfo, http2_tree, offset, flags, length);
        break;

        case HTTP2_BLOCKED: /* BLOCKED (11) */
            /* no payload! */
        break;

        default:
            proto_tree_add_item(http2_tree, hf_http2_unknown, tvb, offset, -1, ENC_NA);
        break;
    }
    return tvb_captured_length(tvb);
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
    if (tvb_captured_length(tvb) < FRAME_HEADER_LENGTH)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HTTP2");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_http2, tvb, 0, -1, ENC_NA);
    proto_item_append_text(ti, " (draft-12)");

    http2_tree = proto_item_add_subtree(ti, ett_http2);

    tcp_dissect_pdus(tvb, pinfo, http2_tree, TRUE, FRAME_HEADER_LENGTH,
                     get_http2_message_len, dissect_http2_pdu, data);

    return tvb_captured_length(tvb);
}

static gboolean
dissect_http2_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (tvb_memeql(tvb, 0, kMagicHello, MAGIC_FRAME_LENGTH) != 0) {
        /* we couldn't find the Magic Hello (PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n)
           see if there's a valid frame type (0-11 are defined at the moment) */
        if (tvb_reported_length(tvb)<2 || tvb_get_guint8(tvb, 2)>=HTTP2_BLOCKED)
            return (FALSE);
    }

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

        { &hf_http2_weight,
            { "Weight", "http2.headers.weight",
               FT_UINT8, BASE_DEC, NULL, 0x0,
              "An 8-bit weight for the identified priority", HFILL }
        },
        { &hf_http2_weight_real,
            { "Weight real", "http2.headers.weight_real",
               FT_UINT8, BASE_DEC, NULL, 0x0,
              "Real Weight value (Add one to value)", HFILL }
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
            { "End Stream", "http2.flags.end_stream",
              FT_BOOLEAN, 8, NULL, HTTP2_FLAGS_END_STREAM,
              "Indicates that this frame is the last that the endpoint will send for the identified stream", HFILL }
        },
        { &hf_http2_flags_end_segment,
            { "End Segment", "http2.flags.end_segment",
              FT_BOOLEAN, 8, NULL, HTTP2_FLAGS_END_SEGMENT,
              "Indicates that this frame is the last for the current segment", HFILL }
        },
        { &hf_http2_flags_end_headers,
            { "End Headers", "http2.flags.eh",
              FT_BOOLEAN, 8, NULL, HTTP2_FLAGS_END_HEADERS,
              "Indicates that this frame contains an entire header block  and is not followed by any CONTINUATION frames.", HFILL }
        },
        { &hf_http2_flags_pad_low,
            { "Pad Low", "http2.flags.pad_low",
              FT_BOOLEAN, 8, NULL, HTTP2_FLAGS_PAD_LOW,
              "Indicates that the Pad Low field is present", HFILL }
        },
        { &hf_http2_flags_pad_high,
            { "Pad High", "http2.flags.pad_high",
              FT_BOOLEAN, 8, NULL, HTTP2_FLAGS_PAD_HIGH,
              "Indicates that the Pad High field is present", HFILL }
        },
        { &hf_http2_flags_priority,
            { "Priority", "http2.flags.priority",
               FT_BOOLEAN, 8, NULL, HTTP2_FLAGS_PRIORITY,
              "Indicates that the Exclusive Flag (E), Stream Dependency, and Weight fields are present", HFILL }
        },
        { &hf_http2_flags_compressed,
            { "Compressed", "http2.flags.compressed",
              FT_BOOLEAN, 8, NULL, HTTP2_FLAGS_COMPRESSED,
              "Indicates that the data in the frame has been compressed with GZIP compression", HFILL }
        },

        { &hf_http2_flags_ping_ack,
            { "ACK", "http2.flags.ack.ping",
               FT_BOOLEAN, 8, NULL, HTTP2_FLAGS_ACK,
              "Set indicates that this PING frame is a PING response", HFILL }
        },
        { &hf_http2_flags_unused,
            { "Unused", "http2.flags.unused",
               FT_UINT8, BASE_HEX, NULL, 0xFF,
              "Must be zero", HFILL }
        },
        { &hf_http2_flags_unused1,
            { "Unused", "http2.flags.unused1",
               FT_UINT8, BASE_HEX, NULL, 0xFE,
              "Must be zero", HFILL }
        },
        { &hf_http2_flags_unused3,
            { "Unused", "http2.flags.unused3",
               FT_UINT8, BASE_HEX, NULL, 0xF8,
              "Must be zero", HFILL }
        },
        { &hf_http2_flags_unused_data,
            { "Unused", "http2.flags.unused_data",
               FT_UINT8, BASE_HEX, NULL, 0xC4,
              "Must be zero", HFILL }
        },
        { &hf_http2_flags_unused6,
            { "Unused", "http2.flags.unused6",
               FT_UINT8, BASE_HEX, NULL, 0xC0,
              "Must be zero", HFILL }
        },
        { &hf_http2_flags_settings_ack,
            { "ACK", "http2.flags.ack.settings",
               FT_BOOLEAN, 8, NULL, HTTP2_FLAGS_ACK,
              "Indicates that this frame acknowledges receipt and application of the peer's SETTINGS frame", HFILL }
        },
        { &hf_http2_pad_high,
            { "Pad High", "http2.pad_high",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              "Padding size high bits", HFILL }
        },
        { &hf_http2_pad_low,
            { "Pad Low", "http2.pad_low",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              "Padding size low bits", HFILL }
        },
        { &hf_http2_pad_length,
            { "Pad Length", "http2.pad_length",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http2_excl_dependency,
            { "Exclusive", "http2.exclusive",
              FT_BOOLEAN, 32, NULL, 0x80000000,
              "A single bit flag indicates that the stream dependency is exclusive", HFILL }
        },
        { &hf_http2_stream_dependency,
            { "Stream Dependency", "http2.stream_dependency",
              FT_UINT32, BASE_DEC, NULL, 0x7FFFFFFF,
              "An identifier for the stream that this stream depends on", HFILL }
        },

        /* Data */
        { &hf_http2_data_data,
            { "Data", "http2.data.data",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "Application data", HFILL }
        },
        { &hf_http2_data_padding,
            { "Padding", "http2.data.padding",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "Padding octets", HFILL }
        },

        /* Headers */
        { &hf_http2_headers,
            { "Header Block Fragment", "http2.headers",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              "A header block fragment", HFILL }
        },
        { &hf_http2_headers_padding,
            { "Padding", "http2.headers.padding",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              "Padding octets", HFILL }
        },
        { &hf_http2_header,
            { "Header", "http2.header",
               FT_NONE, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_http2_header_length,
            { "Header Length", "http2.header.length",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_http2_header_name_length,
            { "Name Length", "http2.header.name.length",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http2_header_name,
            { "Name", "http2.header.name",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http2_header_value_length,
            { "Value Length", "http2.header.value.length",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http2_header_value,
            { "Value", "http2.header.value",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
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
        { &hf_http2_settings_identifier,
            { "Settings Identifier", "http2.settings.id",
               FT_UINT8, BASE_DEC, VALS(http2_settings_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_http2_settings_header_table_size,
            { "Header table size", "http2.settings.header_table_size",
               FT_UINT32, BASE_DEC, NULL, 0x0,
              "Allows the sender to inform the remote endpoint of the size of the header compression table used to decode header blocks. The initial value is 4096 bytes", HFILL }
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
        { &hf_http2_settings_compress_data,
            { "Compress Data", "http2.settings.compress_data",
               FT_UINT32, BASE_DEC, NULL, 0x0,
              "Enables GZip compression of DATA frames. Values other than 0 or 1 are invalid", HFILL }
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
        { &hf_http2_push_promise_padding,
            { "Padding", "http2.push_promise.padding",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              "Padding octets", HFILL }
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
        { &hf_http2_continuation_padding,
            { "Padding", "http2.continuation.padding",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              "Padding octets", HFILL }
        },

        /* Altsvc */
        { &hf_http2_altsvc_maxage,
            { "Max-Age", "http2.altsvc.max-age",
               FT_UINT32, BASE_DEC, NULL, 0x0,
              "An unsigned, 32-bit integer indicating the freshness lifetime of the alternative service association", HFILL }
        },
        { &hf_http2_altsvc_port,
            { "Port", "http2.altsvc.port",
               FT_UINT16, BASE_DEC, NULL, 0x0,
              "An unsigned, 16-bit integer indicating the port that the alternative service is available upon", HFILL }
        },
        { &hf_http2_altsvc_res,
            { "Reserved", "http2.altsvc.reserved",
               FT_UINT8, BASE_DEC, NULL, 0x0,
              "For future use.", HFILL }
        },
        { &hf_http2_altsvc_proto_len,
            { "Proto-Len", "http2.altsvc.proto_len",
               FT_UINT8, BASE_DEC, NULL, 0x0,
              "An unsigned, 8-bit integer indicating the length, in octets, of the PROTOCOL-ID field", HFILL }
        },
        { &hf_http2_altsvc_protocol,
            { "Protocol-ID", "http2.altsvc.protocol",
               FT_STRING, BASE_NONE, NULL, 0x0,
              "A sequence of bytes containing the ALPN protocol identifier", HFILL }
        },
        { &hf_http2_altsvc_host_len,
            { "Host-Len", "http2.altsvc.host_len",
               FT_UINT8, BASE_DEC, NULL, 0x0,
              "An unsigned, 8-bit integer indicating the length, in octets, of the Host field", HFILL }
        },
        { &hf_http2_altsvc_host,
            { "Host", "http2.altsvc.host",
               FT_STRING, BASE_NONE, NULL, 0x0,
              "ASCII string indicating the host that the alternative service is available upon", HFILL }
        },
        { &hf_http2_altsvc_origin,
            { "Origin", "http2.altsvc.origin",
               FT_STRING, BASE_NONE, NULL, 0x0,
              "A sequence of characters containing ASCII serialisation of an "
              "origin that the alternate service is applicable to.", HFILL }
        },


    };

    static gint *ett[] = {
        &ett_http2,
        &ett_http2_header,
        &ett_http2_headers,
        &ett_http2_flags,
        &ett_http2_settings
    };

    proto_http2 = proto_register_protocol("HyperText Transfer Protocol 2", "HTTP2", "http2");

    proto_register_field_array(proto_http2, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    new_register_dissector("http2", dissect_http2, proto_http2);
}

void
proto_reg_handoff_http2(void)
{
    data_handle = find_dissector("data");

    http2_handle = new_create_dissector_handle(dissect_http2, proto_http2);
    dissector_add_for_decode_as("tcp.port", http2_handle);

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
