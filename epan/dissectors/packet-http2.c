/* packet-http2.c
 * Routines for HTTP2 dissection
 * Copyright 2013, Alexis La Goutte <alexis.lagoutte@gmail.com>
 * Copyright 2013, Stephen Ludin <sludin@ludin.org>
 * Copyright 2014, Daniel Stenberg <daniel@haxx.se>
 * Copyright 2014, Tatsuhiro Tsujikawa <tatsuhiro.t@gmail.com>
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
 * RFC7540: Hypertext Transfer Protocol version 2 (HTTP/2)
 * RFC7541: HTTP Header Compression for HTTP/2
 * RFC7838: HTTP Alternative Services
 *
 * TODO
* Enhance display of Data
* Reassembling of continuation frame (and other frame)
* Add same tap and ping/pong time response
*/

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>

#include <epan/nghttp2/nghttp2.h>

#include "packet-tcp.h"
#include <epan/tap.h>
#include <epan/stats_tree.h>

#include "wsutil/pint.h"

#define http2_header_repr_type_VALUE_STRING_LIST(XXX)                   \
    XXX(HTTP2_HD_NONE, 0x00, "")                                        \
    XXX(HTTP2_HD_INDEXED, 0x01, "Indexed Header Field")                 \
    XXX(HTTP2_HD_LITERAL_INDEXING_INDEXED_NAME, 0x02, "Literal Header Field with Incremental Indexing - Indexed Name") \
    XXX(HTTP2_HD_LITERAL_INDEXING_NEW_NAME, 0x03, "Literal Header Field with Incremental Indexing - New Name") \
    XXX(HTTP2_HD_LITERAL_INDEXED_NAME, 0x04, "Literal Header Field without Indexing - Indexed Name") \
    XXX(HTTP2_HD_LITERAL_NEW_NAME, 0x05, "Literal Header Field without Indexing - New Name") \
    XXX(HTTP2_HD_LITERAL_NEVER_INDEXING_INDEXED_NAME, 0x06, "Literal Header Field never Indexed - Indexed Name") \
    XXX(HTTP2_HD_LITERAL_NEVER_INDEXING_NEW_NAME, 0x07, "Literal Header Field never Indexed - New Name") \
    XXX(HTTP2_HD_HEADER_TABLE_SIZE_UPDATE, 0x08, "Maximum Header Table Size Change")

VALUE_STRING_ENUM(http2_header_repr_type);
VALUE_STRING_ARRAY(http2_header_repr_type);

/* Decompressed header field */
typedef struct {
    /* one of http2_header_repr_type */
    gint type;
    /* encoded (compressed) length */
    gint length;
    union {
        struct {
            /* header data */
            char *data;
            /* length of data */
            guint datalen;
            /* name index or name/value index if type is one of
               HTTP2_HD_INDEXED and HTTP2_HD_*_INDEXED_NAMEs */
            guint idx;
        } data;
        /* header table size if type == HTTP2_HD_HEADER_TABLE_SIZE_UPDATE */
        guint header_table_size;
    } table;
} http2_header_t;

/* Context to decode header representation */
typedef struct {
    /* one of http2_header_repr_type */
    gint type;
    /* final or temporal result of decoding integer */
    guint integer;
    /* next bit shift to made when decoding integer */
    guint next_shift;
    /* TRUE if integer decoding was completed */
    gboolean complete;
} http2_header_repr_info_t;

/* Cached decompressed header data in one packet_info */
typedef struct {
    /* list of pointer to wmem_array_t, which is array of
       http2_header_t */
    wmem_list_t *header_list;
    /* This points to the list frame containing current decompressed
       header for dissecting later. */
    wmem_list_frame_t *current;
    /* Bytes decompressed if we exceeded MAX_HTTP2_HEADER_SIZE */
    guint header_size_reached;
    /* Bytes decompressed if we had not exceeded MAX_HTTP2_HEADER_SIZE */
    guint header_size_attempted;
    /* TRUE if we found >= MAX_HTTP2_HEADER_LINES */
    gboolean header_lines_exceeded;
} http2_header_data_t;

/* In-flight SETTINGS data. */
typedef struct {
    /* header table size last seen in SETTINGS */
    guint32 header_table_size;
    /* minimum header table size in SETTINGS */
    guint32 min_header_table_size;
    /* nonzero if header_table_size has effective value. */
    int has_header_table_size;
} http2_settings_t;

/* struct to hold data per HTTP/2 session */
typedef struct {
    /* We need to distinguish the direction of the flow to keep track
       of in-flight SETTINGS and HPACK inflater objects.  To achieve
       this, we use fwd member of tcp_analysis.  In the first packet,
       we record fwd of tcp_analysis.  Later, if processing
       packet_info has fwd of tcp_analysis equal to the recorded fwd,
       we use index 0 of settings_queue and hd_inflater.  We keep
       track of SETTINGS frame sent in this direction in
       settings_queue[0] and inflate header block using
       hd_inflater[0].  Otherwise, we use settings_queue[1] and
       hd_inflater[1]. */
    wmem_queue_t *settings_queue[2];
    nghttp2_hd_inflater *hd_inflater[2];
    http2_header_repr_info_t header_repr_info[2];
    tcp_flow_t *fwd_flow;
} http2_session_t;

void proto_register_http2(void);
void proto_reg_handoff_http2(void);

struct HTTP2Tap {
    guint8 type;
};

static int http2_tap = -1;

static const guint8* st_str_http2 = "HTTP2";
static const guint8* st_str_http2_type = "Type";

static int st_node_http2 = -1;
static int st_node_http2_type = -1;

/* Packet Header */
static int proto_http2 = -1;
static int hf_http2_stream = -1;
static int hf_http2_length = -1;
static int hf_http2_type = -1;
static int hf_http2_r = -1;
static int hf_http2_streamid = -1;
static int hf_http2_magic    = -1;
static int hf_http2_unknown = -1;
/* Flags */
static int hf_http2_flags = -1;
static int hf_http2_flags_end_stream = -1;
static int hf_http2_flags_end_headers = -1;
static int hf_http2_flags_padded = -1;
static int hf_http2_flags_priority = -1;
static int hf_http2_flags_settings_ack = -1;
static int hf_http2_flags_ping_ack = -1;
static int hf_http2_flags_unused = -1;
static int hf_http2_flags_unused_settings = -1;
static int hf_http2_flags_unused_ping = -1;
static int hf_http2_flags_unused_continuation = -1;
static int hf_http2_flags_unused_push_promise = -1;
static int hf_http2_flags_unused_data = -1;
static int hf_http2_flags_unused_headers = -1;

/* generic */
static int hf_http2_padding = -1;
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
static int hf_http2_header_count = -1;
static int hf_http2_header_name_length = -1;
static int hf_http2_header_name = -1;
static int hf_http2_header_value_length = -1;
static int hf_http2_header_value = -1;
static int hf_http2_header_repr = -1;
static int hf_http2_header_index = -1;
static int hf_http2_header_table_size_update = -1;
static int hf_http2_header_table_size = -1;
/* RST Stream */
static int hf_http2_rst_stream_error = -1;
/* Settings */
static int hf_http2_settings = -1;
static int hf_http2_settings_identifier = -1;
static int hf_http2_settings_header_table_size = -1;
static int hf_http2_settings_enable_push = -1;
static int hf_http2_settings_max_concurrent_streams = -1;
static int hf_http2_settings_initial_window_size = -1;
static int hf_http2_settings_max_frame_size = -1;
static int hf_http2_settings_max_header_list_size = -1;
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
static int hf_http2_altsvc_origin_len = -1;
static int hf_http2_altsvc_origin = -1;
static int hf_http2_altsvc_field_value = -1;
/* Blocked */

/*
 * These values *should* be large enough to handle most use cases while
 * keeping hostile traffic from consuming too many resources. If that's
 * not the case we can convert them to preferences. Current (Feb 2016)
 * client and server limits:
 *
 * Apache: 8K (LimitRequestFieldSize), 100 lines (LimitRequestFields)
 * Chrome: 256K?
 * Firefox: Unknown
 * IIS: 16K (MaxRequestBytes)
 * Nginx: 8K (large_client_header_buffers)
 * Safari: Unknown
 * Tomcat: 8K (maxHttpHeaderSize)
 */
#define MAX_HTTP2_HEADER_SIZE (256 * 1024)
#define MAX_HTTP2_HEADER_LINES 200
static expert_field ei_http2_header_size = EI_INIT;
static expert_field ei_http2_header_lines = EI_INIT;

static gint ett_http2 = -1;
static gint ett_http2_header = -1;
static gint ett_http2_headers = -1;
static gint ett_http2_flags = -1;
static gint ett_http2_settings = -1;

/* Due to HPACK compression, we may get lots of relatively large
   header fields (e.g., 4KiB).  Allocating each of them requires lots
   of memory.  The maximum compression is achieved in HPACK by
   referencing header field stored in dynamic table by one or two
   bytes.  We reduce memory usage by caching header field in this
   wmem_map_t to reuse its memory region when we see the same header
   field next time. */
static wmem_map_t *http2_hdrcache_map = NULL;
/* Header name_length + name + value_length + value */
static char *http2_header_pstr = NULL;

static dissector_handle_t http2_handle;

#define FRAME_HEADER_LENGTH     9
#define MAGIC_FRAME_LENGTH      24
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
#define HTTP2_FLAGS_END_HEADERS 0x04
#define HTTP2_FLAGS_PADDED      0x08
#define HTTP2_FLAGS_PRIORITY    0x20

#define HTTP2_FLAGS_UNUSED 0xFF
#define HTTP2_FLAGS_UNUSED_SETTINGS (~HTTP2_FLAGS_ACK & 0xFF)
#define HTTP2_FLAGS_UNUSED_PING (~HTTP2_FLAGS_ACK & 0xFF)
#define HTTP2_FLAGS_UNUSED_CONTINUATION (~HTTP2_FLAGS_END_HEADERS & 0xFF)
#define HTTP2_FLAGS_UNUSED_PUSH_PROMISE \
    (~(HTTP2_FLAGS_END_HEADERS | HTTP2_FLAGS_PADDED) & 0xFF)
#define HTTP2_FLAGS_UNUSED_DATA \
    (~(HTTP2_FLAGS_END_STREAM | HTTP2_FLAGS_PADDED) & 0xFF)
#define HTTP2_FLAGS_UNUSED_HEADERS \
    (~(HTTP2_FLAGS_END_STREAM | HTTP2_FLAGS_END_HEADERS | \
       HTTP2_FLAGS_PADDED | HTTP2_FLAGS_PRIORITY) & 0xFF)

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
#define EC_NO_ERROR             0x0
#define EC_PROTOCOL_ERROR       0x1
#define EC_INTERNAL_ERROR       0x2
#define EC_FLOW_CONTROL_ERROR   0x3
#define EC_SETTINGS_TIMEOUT     0x4
#define EC_STREAM_CLOSED        0x5
#define EC_FRAME_SIZE_ERROR     0x6
#define EC_REFUSED_STREAM       0x7
#define EC_CANCEL               0x8
#define EC_COMPRESSION_ERROR    0x9
#define EC_CONNECT_ERROR        0xa
#define EC_ENHANCE_YOUR_CALM    0xb
#define EC_INADEQUATE_SECURITY  0xc
#define EC_HTTP_1_1_REQUIRED    0xd


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
    { EC_INADEQUATE_SECURITY,   "INADEQUATE_SECURITY" },
    { EC_HTTP_1_1_REQUIRED,     "HTTP_1_1_REQUIRED" },
    { 0, NULL }
};

/* Settings */
#define HTTP2_SETTINGS_HEADER_TABLE_SIZE        1
#define HTTP2_SETTINGS_ENABLE_PUSH              2
#define HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS   3
#define HTTP2_SETTINGS_INITIAL_WINDOW_SIZE      4
#define HTTP2_SETTINGS_MAX_FRAME_SIZE           5
#define HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE     6

static const value_string http2_settings_vals[] = {
    { HTTP2_SETTINGS_HEADER_TABLE_SIZE,      "Header table size" },
    { HTTP2_SETTINGS_ENABLE_PUSH,            "Enable PUSH" },
    { HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, "Max concurrent streams" },
    { HTTP2_SETTINGS_INITIAL_WINDOW_SIZE,    "Initial Windows size" },
    { HTTP2_SETTINGS_MAX_FRAME_SIZE,         "Max frame size" },
    { HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE,   "Max header list size" },
    { 0, NULL }
};

static gboolean
hd_inflate_del_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_, void *user_data)
{
    nghttp2_hd_inflate_del((nghttp2_hd_inflater*)user_data);
    http2_hdrcache_map = NULL;
    http2_header_pstr = NULL;

    return FALSE;
}

static http2_session_t*
get_http2_session(packet_info *pinfo)
{
    conversation_t *conversation;
    http2_session_t *h2session;

    conversation = find_or_create_conversation(pinfo);

    h2session = (http2_session_t*)conversation_get_proto_data(conversation,
                                                              proto_http2);

    if(!h2session) {
        struct tcp_analysis *tcpd;

        tcpd = get_tcp_conversation_data(NULL, pinfo);

        h2session = wmem_new0(wmem_file_scope(), http2_session_t);

        nghttp2_hd_inflate_new(&h2session->hd_inflater[0]);
        nghttp2_hd_inflate_new(&h2session->hd_inflater[1]);

        wmem_register_callback(wmem_file_scope(), hd_inflate_del_cb,
                               h2session->hd_inflater[0]);
        wmem_register_callback(wmem_file_scope(), hd_inflate_del_cb,
                               h2session->hd_inflater[1]);

        h2session->fwd_flow = tcpd->fwd;
        h2session->settings_queue[0] = wmem_queue_new(wmem_file_scope());
        h2session->settings_queue[1] = wmem_queue_new(wmem_file_scope());

        conversation_add_proto_data(conversation, proto_http2, h2session);
    }

    return h2session;
}

static int
select_http2_flow_index(packet_info *pinfo, http2_session_t *h2session)
{
    struct tcp_analysis *tcpd;

    tcpd = get_tcp_conversation_data(NULL, pinfo);

    if(tcpd->fwd == h2session->fwd_flow) {
        return 0;
    } else {
        return 1;
    }
}

static void
push_settings(packet_info *pinfo, http2_session_t *h2session,
              http2_settings_t *settings)
{
    wmem_queue_t *queue;
    int flow_index;

    flow_index = select_http2_flow_index(pinfo, h2session);

    queue = h2session->settings_queue[flow_index];

    wmem_queue_push(queue, settings);
}

static void
apply_and_pop_settings(packet_info *pinfo, http2_session_t *h2session)
{
    wmem_queue_t *queue;
    http2_settings_t *settings;
    nghttp2_hd_inflater *inflater;
    int flow_index;

    /* When header table size is applied, it affects the inflater of
       opposite side. */

    flow_index = select_http2_flow_index(pinfo, h2session);

    inflater = h2session->hd_inflater[flow_index];

    queue = h2session->settings_queue[flow_index ^ 1];

    if(wmem_queue_count(queue) == 0) {
        return;
    }

    settings = (http2_settings_t*)wmem_queue_pop(queue);

    if(settings->has_header_table_size) {
        if(settings->min_header_table_size < settings->header_table_size) {
            nghttp2_hd_inflate_change_table_size
                (inflater, settings->min_header_table_size);
        }

        nghttp2_hd_inflate_change_table_size(inflater,
                                             settings->header_table_size);
    }
}

/* Decode integer from buf at position p, using prefix bits.  This
   function can be called several times if buf does not contain whole
   integer.  header_repr_info remembers the result of previous call.
   Returns the number bytes processed. */
static guint read_integer(http2_header_repr_info_t *header_repr_info,
                          const guint8 *buf, guint len, guint p, guint prefix)
{
    guint k = (1 << prefix) - 1;
    guint n = header_repr_info->integer;
    guint shift = header_repr_info->next_shift;

    if(n == 0) {
        DISSECTOR_ASSERT(p < len);

        if((buf[p] & k) != k) {
            header_repr_info->integer = buf[p] & k;
            header_repr_info->complete = TRUE;
            return p + 1;
        }

        n = k;

        ++p;
    }

    for(; p < len; ++p, shift += 7) {
        DISSECTOR_ASSERT(p < len);

        n += (buf[p] & 0x7F) << shift;

        if((buf[p] & 0x80) == 0) {
            header_repr_info->complete = TRUE;
            ++p;
            break;
        }
    }

    header_repr_info->integer = n;
    header_repr_info->next_shift = shift;
    return p;
}

static void
reset_http2_header_repr_info(http2_header_repr_info_t *header_repr_info)
{
    header_repr_info->type = HTTP2_HD_NONE;
    header_repr_info->integer = 0;
    header_repr_info->next_shift = 0;
    header_repr_info->complete = FALSE;
}

/* Reads zero or more header table size update and optionally header
   representation information.  This function returns when first
   header representation is decoded or buf is processed completely.
   This function returns the number bytes processed for header table
   size update. */
static guint
process_http2_header_repr_info(wmem_array_t *headers,
                               http2_header_repr_info_t *header_repr_info,
                               const guint8 *buf, guint len)
{
    guint i;
    guint start;

    if(header_repr_info->type != HTTP2_HD_NONE &&
       header_repr_info->type != HTTP2_HD_HEADER_TABLE_SIZE_UPDATE &&
       header_repr_info->complete) {
        return 0;
    }

    start = 0;

    for(i = 0; i < len;) {
        if(header_repr_info->type == HTTP2_HD_NONE) {
            guchar c = buf[i];
            if((c & 0xE0) == 0x20) {
                header_repr_info->type = HTTP2_HD_HEADER_TABLE_SIZE_UPDATE;

                i = read_integer(header_repr_info, buf, len, i, 5);
            } else if(c & 0x80) {
                header_repr_info->type = HTTP2_HD_INDEXED;
                i = read_integer(header_repr_info, buf, len, i, 7);
            } else if(c == 0x40 || c == 0 || c == 0x10) {
                /* New name */
                header_repr_info->complete = TRUE;
                if(c & 0x40) {
                    header_repr_info->type = HTTP2_HD_LITERAL_INDEXING_NEW_NAME;
                } else if((c & 0xF0) == 0x10) {
                    header_repr_info->type = HTTP2_HD_LITERAL_NEVER_INDEXING_NEW_NAME;
                } else {
                    header_repr_info->type = HTTP2_HD_LITERAL_NEW_NAME;
                }
            } else {
                /* indexed name */
                if(c & 0x40) {
                    header_repr_info->type = HTTP2_HD_LITERAL_INDEXING_INDEXED_NAME;
                    i = read_integer(header_repr_info, buf, len, i, 6);
                } else if((c & 0xF0) == 0x10) {
                    header_repr_info->type = HTTP2_HD_LITERAL_NEVER_INDEXING_INDEXED_NAME;
                    i = read_integer(header_repr_info, buf, len, i, 4);
                } else {
                    header_repr_info->type = HTTP2_HD_LITERAL_INDEXED_NAME;
                    i = read_integer(header_repr_info, buf, len, i, 4);
                }
            }
        } else {
            i = read_integer(header_repr_info, buf, len, i, 8);
        }

        if(header_repr_info->complete) {
            if(header_repr_info->type == HTTP2_HD_HEADER_TABLE_SIZE_UPDATE) {
                http2_header_t *out;

                out = wmem_new(wmem_file_scope(), http2_header_t);

                out->type = header_repr_info->type;
                out->length = i - start;
                out->table.header_table_size = header_repr_info->integer;

                wmem_array_append(headers, out, 1);

                reset_http2_header_repr_info(header_repr_info);
                /* continue to decode header table size update or
                   first header encoding is encountered. */
                start = i;
            } else {
                /* Break on first header encoding */
                break;
            }
        }
    }

    return start;
}

static size_t http2_hdrcache_length(gconstpointer vv)
{
    const guint8 *v = (const guint8 *)vv;
    guint32 namelen, valuelen;

    namelen = pntoh32(v);
    valuelen = pntoh32(v + sizeof(namelen) + namelen);

    return namelen + valuelen + sizeof(namelen) + sizeof(valuelen);
}

static guint http2_hdrcache_hash(gconstpointer key)
{
    return wmem_strong_hash((const guint8 *)key, http2_hdrcache_length(key));
}

static gboolean http2_hdrcache_equal(gconstpointer lhs, gconstpointer rhs)
{
    const guint8 *a = (const guint8 *)lhs;
    const guint8 *b = (const guint8 *)rhs;
    size_t alen = http2_hdrcache_length(a);
    size_t blen = http2_hdrcache_length(b);

    return alen == blen && memcmp(a, b, alen) == 0;
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
    int header_len = 0;
    int final;
    int flow_index;
    http2_header_data_t *header_data;
    http2_header_repr_info_t *header_repr_info;
    wmem_list_t *header_list;
    wmem_array_t *headers;
    guint i;

    if (!http2_hdrcache_map) {
        http2_hdrcache_map = wmem_map_new(wmem_file_scope(), http2_hdrcache_hash, http2_hdrcache_equal);
    }

    header_data = (http2_header_data_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_http2, 0);
    header_list = header_data->header_list;

    if(!PINFO_FD_VISITED(pinfo)) {
        /* This packet has not been processed yet, which means this is
           the first linear scan.  We do header decompression only
           once in linear scan and cache the result.  If we don't
           cache, already processed data will be fed into decompressor
           again and again since dissector will be called randomly.
           This makes context out-of-sync. */
        int decompressed_bytes = 0;

        headbuf = (guint8*)wmem_alloc(wmem_packet_scope(), headlen);
        tvb_memcpy(tvb, headbuf, offset, headlen);

        flow_index = select_http2_flow_index(pinfo, h2session);
        hd_inflater = h2session->hd_inflater[flow_index];
        header_repr_info = &h2session->header_repr_info[flow_index];

        final = flags & HTTP2_FLAGS_END_HEADERS;

        headers = wmem_array_sized_new(wmem_file_scope(), sizeof(http2_header_t), 16);

        for(;;) {
            nghttp2_nv nv;
            int inflate_flags = 0;

            if (wmem_array_get_count(headers) >= MAX_HTTP2_HEADER_LINES) {
                header_data->header_lines_exceeded = TRUE;
                break;
            }

            rv = (int)nghttp2_hd_inflate_hd(hd_inflater, &nv,
                                            &inflate_flags, headbuf, headlen, final);

            if(rv < 0) {
                break;
            }

            headbuf += rv;
            headlen -= rv;

            rv -= process_http2_header_repr_info(headers, header_repr_info, headbuf - rv, rv);

            if(inflate_flags & NGHTTP2_HD_INFLATE_EMIT) {
                char *cached_pstr;
                guint32 len;
                guint datalen = (guint)(4 + nv.namelen + 4 + nv.valuelen);
                http2_header_t *out;

                if (decompressed_bytes + datalen >= MAX_HTTP2_HEADER_SIZE) {
                    header_data->header_size_reached = decompressed_bytes;
                    header_data->header_size_attempted = decompressed_bytes + datalen;
                    break;
                }

                out = wmem_new(wmem_file_scope(), http2_header_t);

                out->type = header_repr_info->type;
                out->length = rv;
                out->table.data.idx = header_repr_info->integer;

                out->table.data.datalen = datalen;
                decompressed_bytes += datalen;

                /* Prepare buffer... with the following format
                   name length (uint32)
                   name (string)
                   value length (uint32)
                   value (string)
                */
                http2_header_pstr = (char *)wmem_realloc(wmem_file_scope(), http2_header_pstr, out->table.data.datalen);

                /* nv.namelen and nv.valuelen are of size_t.  In order
                   to get length in 4 bytes, we have to copy it to
                   guint32. */
                len = (guint32)nv.namelen;
                phton32(&http2_header_pstr[0], len);
                memcpy(&http2_header_pstr[4], nv.name, nv.namelen);

                len = (guint32)nv.valuelen;
                phton32(&http2_header_pstr[4 + nv.namelen], len);
                memcpy(&http2_header_pstr[4 + nv.namelen + 4], nv.value, nv.valuelen);

                cached_pstr = (char *)wmem_map_lookup(http2_hdrcache_map, http2_header_pstr);
                if (cached_pstr) {
                    out->table.data.data = cached_pstr;
                } else {
                    wmem_map_insert(http2_hdrcache_map, http2_header_pstr, http2_header_pstr);
                    out->table.data.data = http2_header_pstr;
                    http2_header_pstr = NULL;
                }

                wmem_array_append(headers, out, 1);

                reset_http2_header_repr_info(header_repr_info);
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

        wmem_list_append(header_list, headers);

        if(!header_data->current) {
            header_data->current = wmem_list_head(header_list);
        }

    } else {
        headers = (wmem_array_t*)wmem_list_frame_data(header_data->current);

        header_data->current = wmem_list_frame_next(header_data->current);

        if(!header_data->current) {
            header_data->current = wmem_list_head(header_list);
        }
    }

    if(wmem_array_get_count(headers) == 0) {
        return;
    }

    for(i = 0; i < wmem_array_get_count(headers); ++i) {
        http2_header_t *in;
        tvbuff_t *next_tvb;

        in = (http2_header_t*)wmem_array_index(headers, i);

        if(in->type == HTTP2_HD_HEADER_TABLE_SIZE_UPDATE) {
            continue;
        }

        header_len += in->table.data.datalen;

        /* Now setup the tvb buffer to have the new data */
        next_tvb = tvb_new_child_real_data(tvb, in->table.data.data, in->table.data.datalen, in->table.data.datalen);
        tvb_composite_append(header_tvb, next_tvb);
    }

    tvb_composite_finalize(header_tvb);
    add_new_data_source(pinfo, header_tvb, "Decompressed Header");

    ti = proto_tree_add_uint(tree, hf_http2_header_length, header_tvb, hoffset, 1, header_len);
    PROTO_ITEM_SET_GENERATED(ti);

    if (header_data->header_size_attempted > 0) {
        expert_add_info_format(pinfo, ti, &ei_http2_header_size,
                               "Decompression stopped after %u bytes (%u attempted).",
                               header_data->header_size_reached,
                               header_data->header_size_attempted);
    }

    ti = proto_tree_add_uint(tree, hf_http2_header_count, header_tvb, hoffset, 1, wmem_array_get_count(headers));
    PROTO_ITEM_SET_GENERATED(ti);

    if (header_data->header_lines_exceeded) {
        expert_add_info(pinfo, ti, &ei_http2_header_lines);
    }

    for(i = 0; i < wmem_array_get_count(headers); ++i) {
        http2_header_t *in = (http2_header_t*)wmem_array_index(headers, i);

        if(in->type == HTTP2_HD_HEADER_TABLE_SIZE_UPDATE) {
            header = proto_tree_add_item(tree, hf_http2_header_table_size_update, tvb, offset, in->length, ENC_NA);

            header_tree = proto_item_add_subtree(header, ett_http2_headers);

            proto_tree_add_uint(header_tree, hf_http2_header_table_size, tvb, offset, in->length, in->table.header_table_size);

            offset += in->length;
            continue;
        }

        /* Populate tree with header name/value details. */
        /* Add 'Header' subtree with description. */

        header = proto_tree_add_item(tree, hf_http2_header, tvb, offset, in->length, ENC_NA);

        header_tree = proto_item_add_subtree(header, ett_http2_headers);

        /* header value length */
        header_name_length = tvb_get_ntohl(header_tvb, hoffset);
        proto_tree_add_uint(header_tree, hf_http2_header_name_length, tvb, offset, in->length, header_name_length);
        hoffset += 4;

        /* Add header name. */
        header_name = (gchar *)tvb_get_string_enc(wmem_packet_scope(), header_tvb, hoffset, header_name_length, ENC_ASCII|ENC_NA);
        proto_tree_add_string(header_tree, hf_http2_header_name, tvb, offset, in->length, header_name);
        hoffset += header_name_length;

        /* header value length */
        header_value_length = tvb_get_ntohl(header_tvb, hoffset);
        proto_tree_add_uint(header_tree, hf_http2_header_value_length, tvb, offset, in->length, header_value_length);
        hoffset += 4;

        /* Add header value. */
        header_value = (gchar *)tvb_get_string_enc(wmem_packet_scope(),header_tvb, hoffset, header_value_length, ENC_ASCII|ENC_NA);
        proto_tree_add_string(header_tree, hf_http2_header_value, tvb, offset, in->length, header_value);
        hoffset += header_value_length;

        /* Add encoding representation */
        proto_tree_add_string(header_tree, hf_http2_header_repr, tvb, offset, in->length, http2_header_repr_type[in->type].strptr);

        if(in->type == HTTP2_HD_INDEXED ||
           in->type == HTTP2_HD_LITERAL_INDEXING_INDEXED_NAME ||
           in->type == HTTP2_HD_LITERAL_INDEXED_NAME ||
           in->type == HTTP2_HD_LITERAL_NEVER_INDEXING_INDEXED_NAME) {
            proto_tree_add_uint(header_tree, hf_http2_header_index, tvb, offset, in->length, in->table.data.idx);
        }

        proto_item_append_text(header, ": %s: %s", header_name, header_value);

        offset += in->length;
    }
}

static guint8
dissect_http2_header_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *http2_tree, guint offset, guint8 type)
{
    proto_item *ti_flags;
    proto_tree *flags_tree;
    guint8 flags;

    ti_flags = proto_tree_add_item(http2_tree, hf_http2_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
    flags_tree = proto_item_add_subtree(ti_flags, ett_http2_flags);
    flags = tvb_get_guint8(tvb, offset);

    switch(type){
        case HTTP2_DATA:
            proto_tree_add_item(flags_tree, hf_http2_flags_end_stream, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_padded, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_unused_data, tvb, offset, 1, ENC_BIG_ENDIAN);
            break;
        case HTTP2_HEADERS:
            proto_tree_add_item(flags_tree, hf_http2_flags_end_stream, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_end_headers, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_padded, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_priority, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_unused_headers, tvb, offset, 1, ENC_BIG_ENDIAN);
            break;
        case HTTP2_SETTINGS:
            proto_tree_add_item(flags_tree, hf_http2_flags_settings_ack, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_unused_settings, tvb, offset, 1, ENC_BIG_ENDIAN);
            break;
        case HTTP2_PUSH_PROMISE:
            proto_tree_add_item(flags_tree, hf_http2_flags_end_headers, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_padded, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_unused_push_promise, tvb, offset, 1, ENC_BIG_ENDIAN);
            break;
        case HTTP2_CONTINUATION:
            proto_tree_add_item(flags_tree, hf_http2_flags_end_headers, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_unused_continuation, tvb, offset, 1, ENC_BIG_ENDIAN);
            break;
        case HTTP2_PING:
            proto_tree_add_item(flags_tree, hf_http2_flags_ping_ack, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(flags_tree, hf_http2_flags_unused_ping, tvb, offset, 1, ENC_BIG_ENDIAN);
            break;
        case HTTP2_PRIORITY:
        case HTTP2_RST_STREAM:
        case HTTP2_GOAWAY:
        case HTTP2_WINDOW_UPDATE:
        case HTTP2_ALTSVC:
        case HTTP2_BLOCKED:
        default:
            /* Does not define any flags */
            proto_tree_add_item(flags_tree, hf_http2_flags_unused, tvb, offset, 1, ENC_BIG_ENDIAN);
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

    if(flags & HTTP2_FLAGS_PADDED)
    {
        *padding = tvb_get_guint8(tvb, offset); /* read a single octet */
        proto_tree_add_item(http2_tree, hf_http2_padding, tvb, offset, 1, ENC_BIG_ENDIAN);
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
        proto_tree_add_item(http2_tree, hf_http2_stream_dependency, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(http2_tree, hf_http2_weight, tvb, offset, 1, ENC_BIG_ENDIAN);
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
    proto_tree_add_item(http2_tree, hf_http2_data_data, tvb, offset, datalen, ENC_NA);
    offset += datalen;

    proto_tree_add_item(http2_tree, hf_http2_data_padding, tvb, offset, padding, ENC_NA);
    offset += padding;

    return offset;
}

/* Headers */
static int
dissect_http2_headers(tvbuff_t *tvb, packet_info *pinfo, proto_tree *http2_tree,
                      guint offset, guint8 flags)
{
    guint16 padding;
    gint headlen;
    http2_session_t *h2session;

    h2session = get_http2_session(pinfo);

    offset = dissect_frame_padding(tvb, &padding, http2_tree, offset, flags);
    offset = dissect_frame_prio(tvb, http2_tree, offset, flags);

    headlen = tvb_reported_length_remaining(tvb, offset) - padding;
    proto_tree_add_item(http2_tree, hf_http2_headers, tvb, offset, headlen, ENC_NA);

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

    proto_tree_add_item(http2_tree, hf_http2_rst_stream_error, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

/* Settings */
static int
dissect_http2_settings(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *http2_tree, guint offset, guint8 flags)
{
    guint32 settingsid;
    proto_item *ti_settings;
    proto_tree *settings_tree;
    guint32 header_table_size;
    guint32 min_header_table_size;
    int header_table_size_found;
    http2_session_t *h2session;

    header_table_size_found = 0;
    header_table_size = 0;
    min_header_table_size = 0xFFFFFFFFu;

    while(tvb_reported_length_remaining(tvb, offset) > 0){

        ti_settings = proto_tree_add_item(http2_tree, hf_http2_settings, tvb, offset, 5, ENC_NA);
        settings_tree = proto_item_add_subtree(ti_settings, ett_http2_settings);
        proto_tree_add_item(settings_tree, hf_http2_settings_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
        settingsid = tvb_get_ntohs(tvb, offset);
        proto_item_append_text(ti_settings, " - %s",
                               val_to_str( settingsid, http2_settings_vals, "Unknown (%u)") );
        offset += 2;


        switch(settingsid){
            case HTTP2_SETTINGS_HEADER_TABLE_SIZE:
                proto_tree_add_item(settings_tree, hf_http2_settings_header_table_size, tvb, offset, 4, ENC_BIG_ENDIAN);

                /* We only care the last header table size in SETTINGS */
                header_table_size_found = 1;
                header_table_size = tvb_get_ntohl(tvb, offset);
                if(min_header_table_size > header_table_size) {
                    min_header_table_size = header_table_size;
                }
            break;
            case HTTP2_SETTINGS_ENABLE_PUSH:
                proto_tree_add_item(settings_tree, hf_http2_settings_enable_push, tvb, offset, 4, ENC_BIG_ENDIAN);
            break;
            case HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
                proto_tree_add_item(settings_tree, hf_http2_settings_max_concurrent_streams, tvb, offset, 4, ENC_BIG_ENDIAN);
            break;
            case HTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
                proto_tree_add_item(settings_tree, hf_http2_settings_initial_window_size, tvb, offset, 4, ENC_BIG_ENDIAN);
            break;
            case HTTP2_SETTINGS_MAX_FRAME_SIZE:
                proto_tree_add_item(settings_tree, hf_http2_settings_max_frame_size, tvb, offset, 4, ENC_BIG_ENDIAN);
            break;
            case HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
                proto_tree_add_item(settings_tree, hf_http2_settings_max_header_list_size, tvb, offset, 4, ENC_BIG_ENDIAN);
            break;
            default:
                proto_tree_add_item(settings_tree, hf_http2_settings_unknown, tvb, offset, 4, ENC_BIG_ENDIAN);
            break;
        }
        proto_item_append_text(ti_settings, " : %u", tvb_get_ntohl(tvb, offset));
        offset += 4;
    }


    if(!PINFO_FD_VISITED(pinfo)) {
        h2session = get_http2_session(pinfo);

        if(flags & HTTP2_FLAGS_ACK) {
            apply_and_pop_settings(pinfo, h2session);
        } else {
            http2_settings_t *settings;

            settings = wmem_new(wmem_file_scope(), http2_settings_t);

            settings->min_header_table_size = min_header_table_size;
            settings->header_table_size = header_table_size;
            settings->has_header_table_size = header_table_size_found;

            push_settings(pinfo, h2session, settings);
        }
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

    proto_tree_add_item(http2_tree, hf_http2_push_promise_r, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(http2_tree, hf_http2_push_promise_promised_stream_id, tvb,
                        offset, 4, ENC_BIG_ENDIAN);
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

    proto_tree_add_item(http2_tree, hf_http2_goaway_r, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(http2_tree, hf_http2_goaway_last_stream_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(http2_tree, hf_http2_goaway_error, tvb, offset, 4, ENC_BIG_ENDIAN);
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

    proto_tree_add_item(http2_tree, hf_http2_window_update_r, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(http2_tree, hf_http2_window_update_window_size_increment, tvb, offset, 4, ENC_BIG_ENDIAN);
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
    guint32 origin_len;
    int remain = length;

    proto_tree_add_item_ret_uint(http2_tree, hf_http2_altsvc_origin_len, tvb, offset, 2, ENC_BIG_ENDIAN, &origin_len);
    offset += 2;
    remain -= 2;

    proto_tree_add_item(http2_tree, hf_http2_altsvc_origin, tvb, offset, origin_len, ENC_ASCII|ENC_NA);
    offset += origin_len;
    remain -= origin_len;

    if(remain) {
        proto_tree_add_item(http2_tree, hf_http2_altsvc_field_value, tvb, offset, remain, ENC_ASCII|ENC_NA);
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
    struct HTTP2Tap *http2_stats;

    if(!p_get_proto_data(wmem_file_scope(), pinfo, proto_http2, 0)) {
        http2_header_data_t *header_data;

        header_data = wmem_new0(wmem_file_scope(), http2_header_data_t);
        header_data->header_list = wmem_list_new(wmem_file_scope());

        p_add_proto_data(wmem_file_scope(), pinfo, proto_http2, 0, header_data);
    }


    /* 4.1 Frame Format
         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                 Length (24)                   |
        +---------------+---------------+---------------+
        |   Type (8)    |   Flags (8)   |
        +-+-+-----------+---------------+-------------------------------+
        |R|                 Stream Identifier (31)                      |
        +=+=============================================================+
        |                   Frame Payload (0...)                      ...
        +---------------------------------------------------------------+
    */
    ti = proto_tree_add_item(tree, hf_http2_stream, tvb, 0, -1, ENC_NA);

    http2_tree = proto_item_add_subtree(ti, ett_http2_header);

    /* 3.5 Connection Header
       Upon establishment of a TCP connection and determination that
       HTTP/2 will be used by both peers, each endpoint MUST send a
       connection preface as a final confirmation and to establish the
       initial SETTINGS parameters for the HTTP/2 connection.
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

    proto_tree_add_item(http2_tree, hf_http2_length, tvb, offset, 3, ENC_BIG_ENDIAN);
    length = tvb_get_ntoh24(tvb, offset);
    offset += 3;

    proto_tree_add_item(http2_tree, hf_http2_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    type = tvb_get_guint8(tvb, offset);
    col_append_sep_fstr( pinfo->cinfo, COL_INFO, ", ", "%s", val_to_str(type, http2_type_vals, "Unknown type (%d)"));

    offset += 1;

    flags = dissect_http2_header_flags(tvb, pinfo, http2_tree, offset, type);
    offset += 1;

    proto_tree_add_item(http2_tree, hf_http2_r, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(http2_tree, hf_http2_streamid, tvb, offset, 4, ENC_BIG_ENDIAN);
    streamid = tvb_get_ntohl(tvb, offset) & MASK_HTTP2_STREAMID;
    proto_item_append_text(ti, ": %s, Stream ID: %u, Length %u", val_to_str(type, http2_type_vals, "Unknown type (%d)"), streamid, length);
    offset += 4;

    /* Collect stats */
    http2_stats = wmem_new0(wmem_packet_scope(), struct HTTP2Tap);
    http2_stats->type = type;

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

    tap_queue_packet(http2_tap, pinfo, http2_stats);


    return tvb_captured_length(tvb);
}

static guint get_http2_message_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                                   int offset, void *data _U_)
{
        if ( tvb_memeql( tvb, offset, kMagicHello, MAGIC_FRAME_LENGTH ) == 0 ) {
                return MAGIC_FRAME_LENGTH;
        }

        return (guint)tvb_get_ntoh24(tvb, offset) + FRAME_HEADER_LENGTH;
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

    http2_tree = proto_item_add_subtree(ti, ett_http2);

    tcp_dissect_pdus(tvb, pinfo, http2_tree, TRUE, FRAME_HEADER_LENGTH,
                     get_http2_message_len, dissect_http2_pdu, data);

    return tvb_captured_length(tvb);
}

static gboolean
dissect_http2_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    conversation_t *conversation;
    http2_session_t *session;

    conversation = find_or_create_conversation(pinfo);
    session = (http2_session_t *)conversation_get_proto_data(conversation,
                                                             proto_http2);
    /* A http2 conversation was previously started, assume it is still active */
    if (session) {
      dissect_http2(tvb, pinfo, tree, data);
      return TRUE;
    }

    if (tvb_memeql(tvb, 0, kMagicHello, MAGIC_FRAME_LENGTH) != 0) {
        /* we couldn't find the Magic Hello (PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n). */
        return FALSE;
    }

    /* Remember http2 conversation. */
    get_http2_session(pinfo);
    dissect_http2(tvb, pinfo, tree, data);

    return (TRUE);
}

static gboolean
dissect_http2_heur_ssl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    dissector_handle_t *app_handle = (dissector_handle_t *) data;
    if (dissect_http2_heur(tvb, pinfo, tree, NULL)) {
        *app_handle = http2_handle;
        return TRUE;
    }
    return FALSE;
}

void
proto_register_http2(void)
{

    static hf_register_info hf[] = {
        /* Packet Header */
        { &hf_http2_stream,
            { "Stream", "http2.stream",
               FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http2_length,
            { "Length", "http2.length",
              FT_UINT24, BASE_DEC, NULL, 0x0,
              "The length (24 bits) of the frame payload (The 9 octets of the frame header are not included)", HFILL }
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
        { &hf_http2_flags_end_headers,
            { "End Headers", "http2.flags.eh",
              FT_BOOLEAN, 8, NULL, HTTP2_FLAGS_END_HEADERS,
              "Indicates that this frame contains an entire header block  and is not followed by any CONTINUATION frames.", HFILL }
        },
        { &hf_http2_flags_padded,
            { "Padded", "http2.flags.padded",
              FT_BOOLEAN, 8, NULL, HTTP2_FLAGS_PADDED,
              "Indicates that the Pad Length field is present", HFILL }
        },
        { &hf_http2_flags_priority,
            { "Priority", "http2.flags.priority",
               FT_BOOLEAN, 8, NULL, HTTP2_FLAGS_PRIORITY,
              "Indicates that the Exclusive Flag (E), Stream Dependency, and Weight fields are present", HFILL }
        },

        { &hf_http2_flags_ping_ack,
            { "ACK", "http2.flags.ack.ping",
               FT_BOOLEAN, 8, NULL, HTTP2_FLAGS_ACK,
              "Set indicates that this PING frame is a PING response", HFILL }
        },
        { &hf_http2_flags_unused,
            { "Unused", "http2.flags.unused",
               FT_UINT8, BASE_HEX, NULL, HTTP2_FLAGS_UNUSED,
              "Must be zero", HFILL }
        },
        { &hf_http2_flags_unused_settings,
            { "Unused", "http2.flags.unused_settings",
               FT_UINT8, BASE_HEX, NULL, HTTP2_FLAGS_UNUSED_SETTINGS,
              "Must be zero", HFILL }
        },
        { &hf_http2_flags_unused_ping,
            { "Unused", "http2.flags.unused_ping",
               FT_UINT8, BASE_HEX, NULL, HTTP2_FLAGS_UNUSED_PING,
              "Must be zero", HFILL }
        },
        { &hf_http2_flags_unused_continuation,
            { "Unused", "http2.flags.unused_continuation",
               FT_UINT8, BASE_HEX, NULL, HTTP2_FLAGS_UNUSED_CONTINUATION,
              "Must be zero", HFILL }
        },
        { &hf_http2_flags_unused_push_promise,
            { "Unused", "http2.flags.unused_push_promise",
               FT_UINT8, BASE_HEX, NULL, HTTP2_FLAGS_UNUSED_PUSH_PROMISE,
              "Must be zero", HFILL }
        },
        { &hf_http2_flags_unused_data,
            { "Unused", "http2.flags.unused_data",
               FT_UINT8, BASE_HEX, NULL, HTTP2_FLAGS_UNUSED_DATA,
              "Must be zero", HFILL }
        },
        { &hf_http2_flags_unused_headers,
            { "Unused", "http2.flags.unused_headers",
               FT_UINT8, BASE_HEX, NULL, HTTP2_FLAGS_UNUSED_HEADERS,
              "Must be zero", HFILL }
        },
        { &hf_http2_flags_settings_ack,
            { "ACK", "http2.flags.ack.settings",
               FT_BOOLEAN, 8, NULL, HTTP2_FLAGS_ACK,
              "Indicates that this frame acknowledges receipt and application of the peer's SETTINGS frame", HFILL }
        },
        { &hf_http2_padding,
            { "Pad Length", "http2.padding",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              "Padding size", HFILL }
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
        { &hf_http2_header_count,
            { "Header Count", "http2.header.count",
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
        { &hf_http2_header_repr,
            { "Representation", "http2.header.repr",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http2_header_index,
            { "Index", "http2.header.index",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http2_header_table_size_update,
            { "Header table size update", "http2.header_table_size_update",
               FT_NONE, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_http2_header_table_size,
            { "Header table size", "http2.header_table_size_update.header_table_size",
               FT_UINT32, BASE_DEC, NULL, 0x0,
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
               FT_UINT16, BASE_DEC, VALS(http2_settings_vals), 0x0,
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
        { &hf_http2_settings_max_frame_size,
            { "Max frame size", "http2.settings.max_frame_size",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              "Indicates the size of the largest frame payload that the sender will allow", HFILL }
        },
        { &hf_http2_settings_max_header_list_size,
            { "Max header list size", "http2.settings.max_header_list_size",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              "This advisory setting informs a peer of the maximum size of header list that the sender is prepared to accept.", HFILL }
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

        /* ALTSVC */
        { &hf_http2_altsvc_origin_len,
            { "Origin Length", "http2.altsvc.origin.len",
               FT_UINT16, BASE_DEC, NULL, 0x0,
              "indicating the length, in octets, of the Origin field.", HFILL }
        },
        { &hf_http2_altsvc_origin,
            { "Origin", "http2.altsvc.origin",
               FT_STRING, BASE_NONE, NULL, 0x0,
              "A sequence of characters containing ASCII serialisation of an "
              "origin that the alternate service is applicable to.", HFILL }
        },
        { &hf_http2_altsvc_field_value,
            { "Field/Value", "http2.altsvc.field_value",
               FT_STRING, BASE_NONE, NULL, 0x0,
              "A sequence of octets containing a value identical to the Alt-Svc field value", HFILL }
        },

    };

    static gint *ett[] = {
        &ett_http2,
        &ett_http2_header,
        &ett_http2_headers,
        &ett_http2_flags,
        &ett_http2_settings
    };

    /* Setup protocol expert items */
    /*
     * Excessive header size or lines could mean a decompression bomb. Should
     * these be PI_SECURITY instead?
     */
    static ei_register_info ei[] = {
        { &ei_http2_header_size,
          { "http2.header_size_exceeded", PI_UNDECODED, PI_ERROR,
            "Decompression stopped.", EXPFILL }
        },
        { &ei_http2_header_lines,
          { "http2.header_lines_exceeded", PI_UNDECODED, PI_ERROR,
            "Decompression stopped after " G_STRINGIFY(MAX_HTTP2_HEADER_LINES) " header lines.", EXPFILL }
        }
    };

    module_t *http2_module;
    expert_module_t *expert_http2;

    proto_http2 = proto_register_protocol("HyperText Transfer Protocol 2", "HTTP2", "http2");

    proto_register_field_array(proto_http2, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    http2_module = prefs_register_protocol(proto_http2, NULL);

    expert_http2 = expert_register_protocol(proto_http2);
    expert_register_field_array(expert_http2, ei, array_length(ei));

    prefs_register_obsolete_preference(http2_module, "heuristic_http2");

    http2_handle = register_dissector("http2", dissect_http2, proto_http2);

    http2_tap = register_tap("http2");
}

static void http2_stats_tree_init(stats_tree* st)
{
    st_node_http2 = stats_tree_create_node(st, st_str_http2, 0, TRUE);
    st_node_http2_type = stats_tree_create_pivot(st, st_str_http2_type, st_node_http2);

}

static int http2_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_, epan_dissect_t* edt _U_, const void* p)
{
    const struct HTTP2Tap *pi = (const struct HTTP2Tap *)p;
    tick_stat_node(st, st_str_http2, 0, FALSE);
    stats_tree_tick_pivot(st, st_node_http2_type,
            val_to_str(pi->type, http2_type_vals, "Unknown type (%d)"));

    return 1;
}

void
proto_reg_handoff_http2(void)
{
    dissector_add_for_decode_as("tcp.port", http2_handle);

    heur_dissector_add("ssl", dissect_http2_heur_ssl, "HTTP2 over SSL", "http2_ssl", proto_http2, HEURISTIC_ENABLE);
    heur_dissector_add("http", dissect_http2_heur, "HTTP2 over TCP", "http2_tcp", proto_http2, HEURISTIC_ENABLE);

    stats_tree_register("http2", "http2", "HTTP2", 0, http2_stats_tree_packet, http2_stats_tree_init, NULL);
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
