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
 * SPDX-License-Identifier: GPL-2.0-or-later
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
#define WS_LOG_DOMAIN "packet-http2"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/exceptions.h>
#include "packet-http.h" /* for getting status reason-phrase */
#include "packet-http2.h"
#include "packet-media-type.h"

#ifdef HAVE_NGHTTP2
#include <epan/uat.h>
#include <epan/charsets.h>
#include <epan/decode_as.h>
#include <nghttp2/nghttp2.h>
#include <epan/export_object.h>
#endif

#include <epan/tap.h>
#include <epan/stats_tree.h>
#include <epan/reassemble.h>
#include <epan/follow.h>
#include <epan/addr_resolv.h>

#include "packet-tcp.h"
#include "packet-tls.h"
#include "wsutil/pint.h"
#include "wsutil/strtoi.h"
#include "wsutil/str_util.h"
#include <wsutil/unicode-utils.h>
#include <wsutil/wsjson.h>

#ifdef HAVE_NGHTTP2
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

/*
 * Decompression of zlib or brotli encoded entities.
 */
#if defined(HAVE_ZLIB) || defined(HAVE_ZLIBNG)|| defined(HAVE_BROTLI)
static bool http2_decompress_body = true;
#else
static bool http2_decompress_body;
#endif

/* Try to dissect reassembled http2.data.data according to content-type later */
static dissector_table_t media_type_dissector_table;

static int http_eo_tap;
#endif

/* Some protocols on top of http2 require http2 streams to remain open. For example, the stream
 * mode gRPC method (like ETCD watch stream). These kinds of subdissectors need http2 dissector
 * to reassemble http2.data.data according to the desegment_offset and desegment_len fields of the
 * pinfo returned from them. Subdissectors can register its content-type in this table.
 * Note: Subdissector can set pinfo->desegment_len to DESEGMENT_ONE_MORE_SEGMENT or
 * to missing nbytes of the head length if entire length of message is undetermined. */
static dissector_table_t streaming_content_type_dissector_table;

static dissector_table_t stream_id_content_type_dissector_table;

#ifdef HAVE_NGHTTP2
/* The type of reassembly mode contains:
 *  - HTTP2_DATA_REASSEMBLY_MODE_END_STREAM   Complete reassembly at the end of stream. (default)
 *  - HTTP2_DATA_REASSEMBLY_MODE_STREAMING    Determined by the desegment_offset and desegment_len fields returned from subdissector.
 */
enum http2_data_reassembly_mode_t {
    HTTP2_DATA_REASSEMBLY_MODE_END_STREAM  = 0, /* default */
    HTTP2_DATA_REASSEMBLY_MODE_STREAMING   = 1
};

static enum http2_data_reassembly_mode_t
http2_get_data_reassembly_mode(const char* content_type)
{
    return dissector_get_string_handle(streaming_content_type_dissector_table, content_type) ?
            HTTP2_DATA_REASSEMBLY_MODE_STREAMING : HTTP2_DATA_REASSEMBLY_MODE_END_STREAM;
}
#endif

/* Decompressed header field */
typedef struct {
    /* one of http2_header_repr_type */
    int type;
    /* encoded (compressed) length */
    int length;
    union {
        struct {
            /* header data */
            char *data;
            /* length of data */
            unsigned datalen;
            /* name index or name/value index if type is one of
               HTTP2_HD_INDEXED and HTTP2_HD_*_INDEXED_NAMEs */
            unsigned idx;
        } data;
        /* header table size if type == HTTP2_HD_HEADER_TABLE_SIZE_UPDATE */
        unsigned header_table_size;
    } table;
} http2_header_t;

/* Context to decode header representation */
typedef struct {
    /* one of http2_header_repr_type */
    int type;
    /* final or temporal result of decoding integer */
    unsigned integer;
    /* next bit shift to made when decoding integer */
    unsigned next_shift;
    /* true if integer decoding was completed */
    bool complete;
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
    unsigned header_size_reached;
    /* Bytes decompressed if we had not exceeded MAX_HTTP2_HEADER_SIZE */
    unsigned header_size_attempted;
    /* true if we found >= MAX_HTTP2_HEADER_LINES */
    bool header_lines_exceeded;
} http2_header_data_t;

/* In-flight SETTINGS data. */
typedef struct {
    /* header table size last seen in SETTINGS */
    uint32_t header_table_size;
    /* minimum header table size in SETTINGS */
    uint32_t min_header_table_size;
    /* nonzero if header_table_size has effective value. */
    int has_header_table_size;
} http2_settings_t;

#ifdef HAVE_NGHTTP2
typedef uint64_t http2_frame_num_t;

/* struct for per-stream, per-direction DATA frame reassembly */
typedef struct {
    http2_frame_num_t data_initiated_in;
    bool has_transfer_encoded_body;
    /* streaming_reassembly_info only used for STREAMING reassembly mode */
    streaming_reassembly_info_t* streaming_reassembly_info;
} http2_data_stream_reassembly_info_t;

/* struct for per-stream, per-direction entity body info */
typedef struct {
    char *content_type;
    char *content_type_parameters;
    char *content_encoding;
    bool is_partial_content;
} http2_data_stream_body_info_t;

/* struct to track header state, so we know if continuation frames are part
 * of a HEADERS frame or a PUSH_PROMISE.
 */
typedef struct {
    /* Only track the latest received because we only use this on the first
     * pass. We could keep all the data in a wmem_list_t if we needed it on
     * later passes. */
    http2_frame_num_t header_start_in;
    http2_frame_num_t header_end_in;
    uint32_t stream_id; /* Normally the same as the parent http2_stream_info_t
                        * During a PUSH_PROMISE, this is the promised stream. */
    /* list of pointer to wmem_array_t, which is array of http2_header_t
    * that come from all HEADERS and CONTINUATION frames. */
    wmem_list_t *stream_header_list;
    /* fake header info */
    http2_frame_num_t fake_headers_initiated_fn;
    wmem_array_t* fake_headers;
} http2_header_stream_info_t;

/* struct to reference uni-directional per-stream info */
typedef struct {
    http2_data_stream_body_info_t data_stream_body_info;
    http2_data_stream_reassembly_info_t data_stream_reassembly_info;
    http2_header_stream_info_t header_stream_info;
    bool is_window_initialized;
    /* Current window size of the one-way session */
    int32_t current_window_size;
} http2_oneway_stream_info_t;

/* struct to hold per-stream information for both directions */
typedef struct {
    /* index into http2_oneway_stream_info_t struct is based off
     * http2_session_t.fwd_flow, available by calling select_http2_flow_index().
     * The index could be for either client or server, depending on when
     * the capture is started but the index will be consistent for the lifetime
     * of the http2_session_t */
    http2_oneway_stream_info_t oneway_stream_info[2];
    bool is_stream_http_connect;
    uint32_t stream_id;
    uint32_t request_in_frame_num;
    uint32_t response_in_frame_num;
    nstime_t request_ts;
    enum http2_data_reassembly_mode_t reassembly_mode;
    char *authority;
    char *path;
} http2_stream_info_t;
#endif
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
#ifdef HAVE_NGHTTP2
    nghttp2_hd_inflater *hd_inflater[2];
    http2_header_repr_info_t header_repr_info[2];
    wmem_map_t *per_stream_info;
    bool        fix_dynamic_table[2];
#endif
    uint32_t current_stream_id;
    tcp_flow_t *fwd_flow;
    /* Initial window size of new streams (in both directions) */
    uint32_t initial_new_stream_window_size[2];
    /* Current window size of the connection (in both directions) */
    int32_t current_connection_window_size[2];
} http2_session_t;

typedef struct http2_follow_tap_data {
    tvbuff_t *tvb;
    uint64_t stream_id;
} http2_follow_tap_data_t;

typedef struct http2_adjust_window {
    int32_t windowSizeDiff;
    uint32_t flow_index;
} http2_adjust_window_t;

#ifdef HAVE_NGHTTP2
/* Decode as functions */
static void *
http2_current_stream_id_value(packet_info* pinfo)
{
    return GUINT_TO_POINTER(http2_get_stream_id(pinfo));
}

static void
http2_streamid_prompt(packet_info* pinfo, char* result)
{

    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "stream (%u)", http2_get_stream_id(pinfo));
}

static void
decode_as_http2_populate_list(const char* table_name _U_, decode_as_add_to_list_func add_to_list, void *ui_element)
{
    decode_as_default_populate_list("media_type", add_to_list, ui_element);
}

#endif /*HAVE_NGHTTP2*/

static GHashTable* streamid_hash;

void proto_register_http2(void);
void proto_reg_handoff_http2(void);

struct HTTP2Tap {
    uint8_t type;
};

static int http2_tap;
static int http2_follow_tap;

static const uint8_t* st_str_http2 = "HTTP2";
static const uint8_t* st_str_http2_type = "Type";

static int st_node_http2 = -1;
static int st_node_http2_type = -1;

#define PROTO_DATA_KEY_HEADER 0
#define PROTO_DATA_KEY_WINDOW_SIZE_CONNECTION_BEFORE 1
#define PROTO_DATA_KEY_WINDOW_SIZE_STREAM_BEFORE 2

/* Packet Header */
static int proto_http2;
static int hf_http2_stream;
static int hf_http2_length;
static int hf_http2_type;
static int hf_http2_r;
static int hf_http2_streamid;
static int hf_http2_magic;
static int hf_http2_unknown;
/* Flags */
static int hf_http2_flags;
static int hf_http2_flags_end_stream;
static int hf_http2_flags_end_headers;
static int hf_http2_flags_padded;
static int hf_http2_flags_priority;
static int hf_http2_flags_settings_ack;
static int hf_http2_flags_ping_ack;
static int hf_http2_flags_unused;
static int hf_http2_flags_unused_settings;
static int hf_http2_flags_unused_ping;
static int hf_http2_flags_unused_continuation;
static int hf_http2_flags_unused_push_promise;
static int hf_http2_flags_unused_data;
static int hf_http2_flags_unused_headers;

/* generic */
static int hf_http2_padding;
static int hf_http2_pad_length;

static int hf_http2_weight;
static int hf_http2_weight_real;
static int hf_http2_stream_dependency;
static int hf_http2_excl_dependency;
/* Data */
static int hf_http2_data_segment;
static int hf_http2_data_data;
static int hf_http2_data_padding;
static int hf_http2_body_fragments;
static int hf_http2_body_fragment;
static int hf_http2_body_fragment_overlap;
static int hf_http2_body_fragment_overlap_conflicts;
static int hf_http2_body_fragment_multiple_tails;
static int hf_http2_body_fragment_too_long_fragment;
static int hf_http2_body_fragment_error;
static int hf_http2_body_fragment_count;
static int hf_http2_body_reassembled_in;
static int hf_http2_body_reassembled_length;
static int hf_http2_body_reassembled_data;
/* Headers */
static int hf_http2_headers;
static int hf_http2_headers_padding;
static int hf_http2_header;
static int hf_http2_header_length;
static int hf_http2_header_count;
static int hf_http2_header_name_length;
static int hf_http2_header_name;
static int hf_http2_header_value_length;
static int hf_http2_header_value;
static int hf_http2_header_unescaped;
static int hf_http2_header_repr;
static int hf_http2_header_index;
static int hf_http2_header_table_size_update;
static int hf_http2_header_table_size;
static int hf_http2_fake_header_count;
static int hf_http2_fake_header;
static int hf_http2_header_request_full_uri;
/* RST Stream */
static int hf_http2_rst_stream_error;
/* Settings */
static int hf_http2_settings;
static int hf_http2_settings_identifier;
static int hf_http2_settings_header_table_size;
static int hf_http2_settings_enable_push;
static int hf_http2_settings_max_concurrent_streams;
static int hf_http2_settings_initial_window_size;
static int hf_http2_settings_max_frame_size;
static int hf_http2_settings_max_header_list_size;
static int hf_http2_settings_extended_connect;
static int hf_http2_settings_no_rfc7540_priorities;
static int hf_http2_settings_unknown;
/* Push Promise */
static int hf_http2_push_promise_r;
static int hf_http2_push_promise_promised_stream_id;
static int hf_http2_push_promise_header;
static int hf_http2_push_promise_padding;
/* Ping */
static int hf_http2_ping;
static int hf_http2_pong;
/* Goaway */
static int hf_http2_goaway_r;
static int hf_http2_goaway_last_stream_id;
static int hf_http2_goaway_error;
static int hf_http2_goaway_addata;
/* Window Update */
static int hf_http2_window_update_r;
static int hf_http2_window_update_window_size_increment;
/* Continuation */
static int hf_http2_continuation_header;
static int hf_http2_continuation_padding;
/* Altsvc */
static int hf_http2_altsvc_origin_len;
static int hf_http2_altsvc_origin;
static int hf_http2_altsvc_field_value;
/* Calculated */
static int hf_http2_calculated_window_size_connection_before;
static int hf_http2_calculated_window_size_connection_after;
static int hf_http2_calculated_window_size_stream_before;
static int hf_http2_calculated_window_size_stream_after;
#if HAVE_NGHTTP2
/* HTTP2 header static fields */
static int hf_http2_headers_status;
static int hf_http2_headers_path;
static int hf_http2_headers_method;
static int hf_http2_headers_scheme;
static int hf_http2_headers_accept;
static int hf_http2_headers_accept_charset;
static int hf_http2_headers_accept_encoding;
static int hf_http2_headers_accept_language;
static int hf_http2_headers_accept_ranges;
static int hf_http2_headers_access_control_allow_origin;
static int hf_http2_headers_age;
static int hf_http2_headers_allow;
static int hf_http2_headers_authorization;
static int hf_http2_headers_authority;
static int hf_http2_headers_cache_control;
static int hf_http2_headers_content_disposition;
static int hf_http2_headers_content_encoding;
static int hf_http2_headers_content_language;
static int hf_http2_headers_content_length;
static int hf_http2_headers_content_location;
static int hf_http2_headers_content_range;
static int hf_http2_headers_content_type;
static int hf_http2_headers_cookie;
static int hf_http2_headers_date;
static int hf_http2_headers_etag;
static int hf_http2_headers_expect;
static int hf_http2_headers_expires;
static int hf_http2_headers_from;
static int hf_http2_headers_if_match;
static int hf_http2_headers_if_modified_since;
static int hf_http2_headers_if_none_match;
static int hf_http2_headers_if_range;
static int hf_http2_headers_if_unmodified_since;
static int hf_http2_headers_last_modified;
static int hf_http2_headers_link;
static int hf_http2_headers_location;
static int hf_http2_headers_max_forwards;
static int hf_http2_headers_proxy_authenticate;
static int hf_http2_headers_proxy_authorization;
static int hf_http2_headers_range;
static int hf_http2_headers_referer;
static int hf_http2_headers_refresh;
static int hf_http2_headers_retry_after;
static int hf_http2_headers_server;
static int hf_http2_headers_set_cookie;
static int hf_http2_headers_strict_transport_security;
static int hf_http2_headers_user_agent;
static int hf_http2_headers_vary;
static int hf_http2_headers_via;
static int hf_http2_headers_www_authenticate;
#endif
/* Blocked */
/* Origin */
static int hf_http2_origin;
static int hf_http2_origin_origin_len;
static int hf_http2_origin_origin;
/* Priority Update */
static int hf_http2_priority_update_stream_id;
static int hf_http2_priority_update_field_value;
/* Generated fields */
static int hf_http2_time;
static int hf_http2_request_in;
static int hf_http2_response_in;

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
static expert_field ei_http2_header_size;
static expert_field ei_http2_header_lines;
static expert_field ei_http2_body_decompression_failed;
static expert_field ei_http2_reassembly_error;

static int ett_http2;
static int ett_http2_header;
static int ett_http2_headers;
static int ett_http2_flags;
static int ett_http2_settings;
static int ett_http2_encoded_entity;
static int ett_http2_body_fragment;
static int ett_http2_body_fragments;
static int ett_http2_origin;

#ifdef HAVE_NGHTTP2
static const fragment_items http2_body_fragment_items = {
    /* Fragment subtrees */
    &ett_http2_body_fragment,
    &ett_http2_body_fragments,
    /* Fragment fields */
    &hf_http2_body_fragments,
    &hf_http2_body_fragment,
    &hf_http2_body_fragment_overlap,
    &hf_http2_body_fragment_overlap_conflicts,
    &hf_http2_body_fragment_multiple_tails,
    &hf_http2_body_fragment_too_long_fragment,
    &hf_http2_body_fragment_error,
    &hf_http2_body_fragment_count,
    &hf_http2_body_reassembled_in,
    &hf_http2_body_reassembled_length,
    &hf_http2_body_reassembled_data,
    "Body fragments"
};

/* Due to HPACK compression, we may get lots of relatively large
   header fields (e.g., 4KiB).  Allocating each of them requires lots
   of memory.  The maximum compression is achieved in HPACK by
   referencing header field stored in dynamic table by one or two
   bytes.  We reduce memory usage by caching header field in this
   wmem_map_t to reuse its memory region when we see the same header
   field next time. */
static wmem_map_t *http2_hdrcache_map;
/* Header name_length + name + value_length + value */
static char *http2_header_pstr;
#endif

#ifdef HAVE_NGHTTP2
/* Stuff for generation/handling of fields for HTTP2 headers */

enum header_field_type {
    val_string,
    val_uint64
};

typedef struct _header_field_t {
    char* header_name;
    enum header_field_type header_type;
    char* header_desc;
} header_field_t;

static header_field_t* header_fields;
static unsigned num_header_fields;
static unsigned num_header_fields_cleanup;

static GHashTable* header_fields_hash;

static bool
header_fields_update_cb(void *r, char **err)
{
    header_field_t *rec = (header_field_t *)r;
    char c;

    if (rec->header_name == NULL) {
        *err = g_strdup("Header name can't be empty");
        return false;
    }

    g_strstrip(rec->header_name);
    if (rec->header_name[0] == 0) {
        *err = g_strdup("Header name can't be empty");
        return false;
    }

    /* Check for invalid characters (to avoid asserting out when
     * registering the field).
     */
    c = proto_check_field_name(rec->header_name);
    if (c) {
        *err = ws_strdup_printf("Header name can't contain '%c'", c);
        return false;
    }

    /* If the hash table is empty(e.g. on startup), do not try to check a value */
    if (header_fields_hash != NULL) {
        const int *entry = (const int *) g_hash_table_lookup(header_fields_hash, rec->header_name);
        if (entry != NULL) {
            *err = ws_strdup_printf("This header field is already defined in UAT or it is a static header field");
            return false;
        }
    }

    *err = NULL;
    return true;
}

static void *
header_fields_copy_cb(void* n, const void* o, size_t siz _U_)
{
    header_field_t* new_rec = (header_field_t*)n;
    const header_field_t* old_rec = (const header_field_t*)o;

    new_rec->header_name = g_strdup(old_rec->header_name);
    new_rec->header_type = old_rec->header_type;
    new_rec->header_desc = g_strdup(old_rec->header_desc);

    return new_rec;
}

static void
header_fields_free_cb(void*r)
{
    header_field_t* rec = (header_field_t*)r;

    g_hash_table_remove(header_fields_hash, rec->header_name);

    g_free(rec->header_name);
    g_free(rec->header_desc);

}

static hf_register_info* hf_uat;

static void
deregister_header_fields(void)
{
    if (hf_uat) {
        for (unsigned i = 0; i < num_header_fields_cleanup; ++i) {
            proto_deregister_field(proto_http2, *(hf_uat[i].p_id));
            g_free(hf_uat[i].p_id);
        }
        proto_add_deregistered_data(hf_uat);
        hf_uat = NULL;
        num_header_fields_cleanup = 0;
    }

    /* header_fields_hash also contains the static header list (used for
     * look ups to avoid duplicate entries, so we don't destroy it here.
     * The dynamic entries are removed from the hash table in
     * header_fields_free_cb().
     */
}

static void
header_fields_post_update_cb(void)
{
    int* hf_id;
    char* header_name;
    char* header_name_key;

    deregister_header_fields();

    /* Add to hash table headers from UAT */
    if (num_header_fields) {
        hf_uat = g_new0(hf_register_info, num_header_fields);
        num_header_fields_cleanup = num_header_fields;

        for (unsigned i = 0; i < num_header_fields; i++) {
            hf_id = g_new(int,1);
            *hf_id = 0;
            header_name = g_strdup(header_fields[i].header_name);
            header_name_key = g_ascii_strdown(header_name, -1);

            hf_uat[i].p_id = hf_id;
            hf_uat[i].hfinfo.name = header_name;
            hf_uat[i].hfinfo.abbrev = ws_strdup_printf("http2.headers.%s", header_name);
            switch(header_fields[i].header_type) {
                case val_uint64:
                    hf_uat[i].hfinfo.type = FT_UINT64;
                    hf_uat[i].hfinfo.display = BASE_DEC;
                    break;
                default: // string
                    hf_uat[i].hfinfo.type = FT_STRING;
                    hf_uat[i].hfinfo.display = BASE_NONE;
                    break;
            }
            hf_uat[i].hfinfo.strings = NULL;
            hf_uat[i].hfinfo.bitmask = 0;
            hf_uat[i].hfinfo.blurb = g_strdup(header_fields[i].header_desc);
            HFILL_INIT(hf_uat[i]);

            g_hash_table_insert(header_fields_hash, header_name_key, hf_id);
        }

        proto_register_field_array(proto_http2, hf_uat, num_header_fields);
    }
}

static void
header_fields_reset_cb(void)
{
    deregister_header_fields();
}

static void
register_static_headers(void) {
    header_fields_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
                                               g_free, NULL);

    /* Here hf[x].hfinfo.name is a header method which is used as key
     * for matching ids while processing HTTP2 packets */
    static hf_register_info hf[] = {
        {
            &hf_http2_headers_authority,
            {":authority", "http2.headers.authority",
                FT_STRING, BASE_NONE, NULL, 0x0,
                "Authority portion of the target URI", HFILL}
        },
        {
            &hf_http2_headers_status,
                {":status", "http2.headers.status",
                 FT_UINT16, BASE_DEC, NULL, 0x0,
                 NULL, HFILL}
        },
        {
            &hf_http2_headers_path,
                {":path", "http2.headers.path",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 NULL, HFILL}
        },
        {
            &hf_http2_headers_method,
                {":method", "http2.headers.method",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 NULL, HFILL}
        },
        {
            &hf_http2_headers_scheme,
                {":scheme", "http2.headers.scheme",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 NULL, HFILL}
        },
        {
            &hf_http2_headers_accept,
                {"accept", "http2.headers.accept",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Media types that are acceptable to the user agent", HFILL}
        },
        {
            &hf_http2_headers_accept_charset,
                {"accept-charset", "http2.headers.accept_charset",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Acceptable charsets in textual responses for the user agent", HFILL}
        },
        {
            &hf_http2_headers_accept_encoding,
                {"accept-encoding", "http2.headers.accept_encoding",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Acceptable content codings (like compression) in responses for the user agent", HFILL}
        },
        {
            &hf_http2_headers_accept_language,
                {"accept-language", "http2.headers.accept_language",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Preferred natural languages for the user agent", HFILL}
        },
        {
            &hf_http2_headers_accept_ranges,
                {"accept-ranges", "http2.headers.accept_ranges",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Bytes range which server may use for partial data transfer", HFILL}
        },
        {
            &hf_http2_headers_access_control_allow_origin,
                {"access-control-allow-origin", "http2.headers.access_control_allow_origin",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Origin control for cross-origin resource sharing", HFILL}
        },
        {
            &hf_http2_headers_age,
                {"age", "http2.headers.age",
                 FT_UINT64, BASE_DEC, NULL, 0x0,
                 "Time in seconds which was spent for transferring data through proxy", HFILL}
        },
        {
            &hf_http2_headers_allow,
                {"allow", "http2.headers.allow",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "List of allowed methods for request", HFILL}
        },
        {
            &hf_http2_headers_authorization,
                {"authorization", "http2.headers.authorization",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Credentials for a server-side authorization", HFILL}
        },
        {
            &hf_http2_headers_cache_control,
                {"cache-control", "http2.headers.cache_control",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Request or response directives for a cache control", HFILL}
        },
        {
            &hf_http2_headers_content_disposition,
                {"content-disposition", "http2.headers.content_disposition",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Indicates that response will be displayed as page or downloaded with dialog box", HFILL}
        },
        {
            &hf_http2_headers_content_encoding,
                {"content-encoding", "http2.headers.content_encoding",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 NULL, HFILL}
        },
        {
            &hf_http2_headers_content_language,
                {"content-language", "http2.headers.content_language",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 NULL, HFILL}
        },
        {
            &hf_http2_headers_content_length,
                {"content-length", "http2.headers.content_length",
                 FT_UINT64, BASE_DEC, NULL, 0x0,
                 "Size of body in bytes", HFILL}
        },
        {
            &hf_http2_headers_content_location,
                {"content-location", "http2.headers.content_location",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Alternative URL for a response data", HFILL}
        },
        {
            &hf_http2_headers_content_range,
                {"content-range", "http2.headers.content_range",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Range of bytes which was sent by server for partial data transfer", HFILL}
        },
        {
            &hf_http2_headers_content_type,
                {"content-type", "http2.headers.content_type",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "MIME type of response", HFILL}
        },
        {
            &hf_http2_headers_cookie,
                {"cookie", "http2.headers.cookie",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Stored cookies", HFILL}
        },
        {
            &hf_http2_headers_date,
                {"date", "http2.headers.date",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Date and time at which the data was originated", HFILL}
        },
        {
            &hf_http2_headers_etag,
                {"etag", "http2.headers.etag",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Directive for version indication of resource", HFILL}
        },
        {
            &hf_http2_headers_expect,
                {"expect", "http2.headers.expect",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Expectations that need to be fulfilled for correct request", HFILL}
        },
        {
            &hf_http2_headers_expires,
                {"expires", "http2.headers.expires",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Data after which resource will be stale", HFILL}
        },
        {
            &hf_http2_headers_from,
                {"from", "http2.headers.from",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Email of a person who responsible for a requesting data", HFILL}
        },
        {
            &hf_http2_headers_if_match,
                {"if-match", "http2.headers.if_match",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Mechanism for requesting data matched by a list of ETags", HFILL}
        },
        {
            &hf_http2_headers_if_modified_since,
                {"if-modified-since", "http2.headers.if_modified_since",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Resource will be sent with status code 200 if it was modified otherwise with status code 304", HFILL}
        },
        {
            &hf_http2_headers_if_none_match,
                {"if-none-match", "http2.headers.if_none_match",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Mechanism for requesting data not matched by a list of ETags", HFILL}
        },
        {
            &hf_http2_headers_if_range,
                {"if-range", "http2.headers.if_range",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Mechanism for a range request which is used to check if a resource was modified", HFILL}
        },
        {
            &hf_http2_headers_if_unmodified_since,
                {"if-unmodified-since", "http2.headers.if_unmodified_since",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Resource will be processed if it was not modified otherwise 412 error will be returned", HFILL}
        },
        {
            &hf_http2_headers_last_modified,
                {"last-modified", "http2.headers.last_modified",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Date and time at which the origin server believes the resource was last modified", HFILL}
        },
        {
            &hf_http2_headers_link,
                {"link", "http2.headers.link",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Mechanism for indicating that resource will be preloaded", HFILL}
        },
        {
            &hf_http2_headers_location,
                {"location", "http2.headers.location",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Mechanism for indicating that client will be redirected", HFILL}
        },
        {
            &hf_http2_headers_max_forwards,
                {"max-forwards", "http2.headers.max_forwards",
                 FT_UINT64, BASE_DEC, NULL, 0x0,
                 "Mechanism for limiting the number of proxies", HFILL}
        },
        {
            &hf_http2_headers_proxy_authenticate,
                {"proxy-authenticate", "http2.headers.proxy_authenticate",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Authentication method that should be used to gain access to a resource behind a proxy server", HFILL}
        },
        {
            &hf_http2_headers_proxy_authorization,
                {"proxy-authorization", "http2.headers.proxy_authorization",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Credentials for a proxy-side authorization", HFILL}
        },
        {
            &hf_http2_headers_range,
                {"range", "http2.headers.range",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Range of resource bytes that server should return", HFILL}
        },
        {
            &hf_http2_headers_referer,
                {"referer", "http2.headers.referer",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Address of the previous web page", HFILL}
        },
        {
            &hf_http2_headers_refresh,
                {"refresh", "http2.headers.refresh",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Time in seconds after which client will be redirected by given url", HFILL}
        },
        {
            &hf_http2_headers_retry_after,
                {"retry-after", "http2.headers.retry_after",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Mechanism to indicate when resource expected to be available", HFILL}
        },
        {
            &hf_http2_headers_server,
                {"server", "http2.headers.server",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Information about server software", HFILL}
        },
        {
            &hf_http2_headers_set_cookie,
                {"set-cookie", "http2.headers.set_cookie",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Send a cookie to the client", HFILL}
        },
        {
            &hf_http2_headers_strict_transport_security,
                {"strict-transport-security", "http2.headers.strict_transport_security",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "HSTS indicates that resource should be accessed only using HTTPS", HFILL}
        },
        {
            &hf_http2_headers_user_agent,
                {"user-agent", "http2.headers.user_agent",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Information about client software", HFILL}
        },
        {
            &hf_http2_headers_vary,
                {"vary", "http2.headers.vary",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Mechanism for selecting which header will be used for content negotiation algorithm", HFILL}
        },
        {
            &hf_http2_headers_via,
                {"via", "http2.headers.via",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Additional information for loop detection and protocol capabilities in proxy requests", HFILL}
        },
        {
            &hf_http2_headers_www_authenticate,
                {"www-authenticate", "http2.headers.www_authenticate",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Authentication method that should be used to gain access to a resource", HFILL}
        }
    };
    char* header_name;
    for (unsigned i = 0; i < G_N_ELEMENTS(hf); ++i) {
        header_name = g_strdup(hf[i].hfinfo.name);

        g_hash_table_insert(header_fields_hash, header_name, &hf[i].hfinfo.id);
    }
    proto_register_field_array(proto_http2, hf, G_N_ELEMENTS(hf));
}

UAT_CSTRING_CB_DEF(header_fields, header_name, header_field_t)
UAT_VS_DEF(header_fields, header_type, header_field_t, enum header_field_type, val_string, "string")
UAT_CSTRING_CB_DEF(header_fields, header_desc, header_field_t)

/* message/stream direction (to or from server) vals */
#define http2_direction_type_vals_VALUE_STRING_LIST(XXX)    \
    XXX(DIRECTION_IN, 0, "IN")  \
    XXX(DIRECTION_OUT, 1, "OUT")

typedef VALUE_STRING_ENUM(http2_direction_type_vals) http2_direction_type;
VALUE_STRING_ARRAY(http2_direction_type_vals);

/* The fake headers will be used if the HEADERS frame before the first DATA is missing. */
typedef struct {
    range_t* server_port_range;
    uint32_t stream_id; /* 0 means applicable to all streams */
    http2_direction_type direction;
    char* header_name;
    char* header_value;
    bool override; /* override existing header */
    bool enable; /* enable or disable this rule */
} http2_fake_header_t;

static http2_fake_header_t* http2_fake_headers;
static unsigned num_http2_fake_headers;

static void*
http2_fake_headers_copy_cb(void* n, const void* o, size_t siz _U_)
{
    http2_fake_header_t* new_rec = (http2_fake_header_t*)n;
    const http2_fake_header_t* old_rec = (const http2_fake_header_t*)o;

    /* copy values like uint32_t */
    memcpy(new_rec, old_rec, sizeof(http2_fake_header_t));

    if (old_rec->server_port_range)
        new_rec->server_port_range = range_copy(NULL, old_rec->server_port_range);

    new_rec->header_name = g_strdup(old_rec->header_name);
    new_rec->header_value = g_strdup(old_rec->header_value);

    return new_rec;
}

static bool
http2_fake_headers_update_cb(void* r, char** err)
{
    http2_fake_header_t* rec = (http2_fake_header_t*)r;
    static range_t* empty;

    empty = range_empty(NULL);
    if (ranges_are_equal(rec->server_port_range, empty)) {
        *err = g_strdup("Must specify server port(s) (like 50051 or 50051,60051-60054)");
        wmem_free(NULL, empty);
        return false;
    }

    wmem_free(NULL, empty);

    /* Check header_name */
    if (rec->header_name == NULL) {
        *err = g_strdup("Header name can't be empty");
        return false;
    }

    g_strstrip(rec->header_name);
    if (rec->header_name[0] == 0) {
        *err = g_strdup("Header name can't be empty");
        return false;
    }

    /* check value */
    if (rec->header_value == NULL) {
        *err = g_strdup("Header value can't be empty");
        return false;
    }

    g_strstrip(rec->header_value);
    if (rec->header_name[0] == 0) {
        *err = g_strdup("Header value can't be empty");
        return false;
    }

    *err = NULL;
    return true;
}

static void
http2_fake_headers_free_cb(void* r)
{
    http2_fake_header_t* rec = (http2_fake_header_t*)r;

    wmem_free(NULL, rec->server_port_range);
    g_free(rec->header_name);
    g_free(rec->header_value);
}

UAT_RANGE_CB_DEF(http2_fake_headers, server_port_range, http2_fake_header_t)
UAT_DEC_CB_DEF(http2_fake_headers, stream_id, http2_fake_header_t)
UAT_VS_DEF(http2_fake_headers, direction, http2_fake_header_t, http2_direction_type,
    DIRECTION_IN, try_val_to_str(DIRECTION_IN, http2_direction_type_vals))
UAT_CSTRING_CB_DEF(http2_fake_headers, header_name, http2_fake_header_t)
UAT_CSTRING_CB_DEF(http2_fake_headers, header_value, http2_fake_header_t)
UAT_BOOL_CB_DEF(http2_fake_headers, override, http2_fake_header_t)
UAT_BOOL_CB_DEF(http2_fake_headers, enable, http2_fake_header_t)

static const char*
get_fake_header_value(packet_info* pinfo, const char* name, bool the_other_direction, bool* override)
{
    if (num_http2_fake_headers == 0) {
        return NULL;
    }

    http2_direction_type direction;
    range_t* server_port_range;
    uint32_t stream_id = http2_get_stream_id(pinfo);

    for (unsigned i = 0; i < num_http2_fake_headers; i++) {
        http2_fake_header_t* fake_header = http2_fake_headers + i;

        if (fake_header->enable == false ||
            (fake_header->stream_id > 0 && fake_header->stream_id != stream_id)) {
            continue;
        }

        server_port_range = fake_header->server_port_range;
        if (value_is_in_range(server_port_range, pinfo->destport)) {
            direction = the_other_direction ? DIRECTION_OUT : DIRECTION_IN;
        } else if (value_is_in_range(server_port_range, pinfo->srcport)) {
            direction = the_other_direction ? DIRECTION_IN : DIRECTION_OUT;
        } else {
            continue;
        }

        if (fake_header->direction == direction && strcmp(fake_header->header_name, name) == 0) {
            if(override) {
                *override = fake_header->override;
            }
            return wmem_strdup(pinfo->pool, fake_header->header_value);
        }
    }

    return NULL;
}
#endif

static void
http2_init_protocol(void)
{
    /* Init hash table with mapping of stream id -> frames count for Follow HTTP2 */
    streamid_hash = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)g_hash_table_destroy);
}

static void
http2_cleanup_protocol(void) {
    g_hash_table_destroy(streamid_hash);
}

static dissector_handle_t http2_handle;
static dissector_handle_t data_handle;

static reassembly_table http2_body_reassembly_table;
static reassembly_table http2_streaming_reassembly_table;

#define FRAME_HEADER_LENGTH     9
#define MAGIC_FRAME_LENGTH      24
#define MASK_HTTP2_RESERVED     0x80000000
#define MASK_HTTP2_STREAMID     0X7FFFFFFF
#define MASK_HTTP2_PRIORITY     0X7FFFFFFF

/* Header Type Code */
#define HTTP2_DATA              0
#define HTTP2_HEADERS           1
#define HTTP2_PRIORITY          2
#define HTTP2_RST_STREAM        3
#define HTTP2_SETTINGS          4
#define HTTP2_PUSH_PROMISE      5
#define HTTP2_PING              6
#define HTTP2_GOAWAY            7
#define HTTP2_WINDOW_UPDATE     8
#define HTTP2_CONTINUATION      9
#define HTTP2_ALTSVC            0xA
#define HTTP2_BLOCKED           0xB
#define HTTP2_ORIGIN            0xC
#define HTTP2_PRIORITY_UPDATE   0x10

static const value_string http2_type_vals[] = {
    { HTTP2_DATA,            "DATA" },
    { HTTP2_HEADERS,         "HEADERS" },
    { HTTP2_PRIORITY,        "PRIORITY" },
    { HTTP2_RST_STREAM,      "RST_STREAM" },
    { HTTP2_SETTINGS,        "SETTINGS" },
    { HTTP2_PUSH_PROMISE,    "PUSH_PROMISE" },
    { HTTP2_PING,            "PING" },
    { HTTP2_GOAWAY,          "GOAWAY" },
    { HTTP2_WINDOW_UPDATE,   "WINDOW_UPDATE" },
    { HTTP2_CONTINUATION,    "CONTINUATION" },
    { HTTP2_ALTSVC,          "ALTSVC" },
    { HTTP2_BLOCKED,         "BLOCKED" },
    { HTTP2_ORIGIN,          "ORIGIN" },
    { HTTP2_PRIORITY_UPDATE, "PRIORITY_UPDATE" },
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

/* header matching helpers */
#define IS_HTTP2_END_STREAM(flags)   (flags & HTTP2_FLAGS_END_STREAM)

/* Magic Header : PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n */
static    uint8_t kMagicHello[] = {
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
#define HTTP2_SETTINGS_EXTENDED_CONNECT         8 /* RFC 8441 */
#define HTTP2_SETTINGS_NO_RFC7540_PRIORITIES    9 /* RFC 9218 */

static const value_string http2_settings_vals[] = {
    { HTTP2_SETTINGS_HEADER_TABLE_SIZE,      "Header table size" },
    { HTTP2_SETTINGS_ENABLE_PUSH,            "Enable PUSH" },
    { HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, "Max concurrent streams" },
    { HTTP2_SETTINGS_INITIAL_WINDOW_SIZE,    "Initial Windows size" },
    { HTTP2_SETTINGS_MAX_FRAME_SIZE,         "Max frame size" },
    { HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE,   "Max header list size" },
    { HTTP2_SETTINGS_EXTENDED_CONNECT,       "Extended CONNECT" },
    { HTTP2_SETTINGS_NO_RFC7540_PRIORITIES,  "No RFC7540 Priorities" },
    { 0, NULL }
};

/*
 * "When an HTTP/2 connection is first established, new streams
 *  are created with an initial flow-control window size of 65,535
 *  octets. The connection flow-control window is also 65,535
 *  octets. Both endpoints can adjust the initial window size for
 *  new streams by including a value for SETTINGS_INITIAL_WINDOW_SIZE
 *  in the SETTINGS frame. The connection flow-control window can
 *  only be changed using WINDOW_UPDATE frames."
 * https://www.ietf.org/rfc/rfc9113.html#section-6.9.2-1
 */
#define INITIAL_WINDOW_SIZE 65535

static uint32_t
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

#ifdef HAVE_NGHTTP2
static bool
hd_inflate_del_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_, void *user_data)
{
    nghttp2_hd_inflate_del((nghttp2_hd_inflater*)user_data);
    http2_hdrcache_map = NULL;
    http2_header_pstr = NULL;

    return false;
}

static http2_stream_info_t*
get_stream_info_for_id(packet_info *pinfo, http2_session_t *http2_session, bool initializeOppositeDirection, uint32_t stream_id)
{
    wmem_map_t *stream_map = http2_session->per_stream_info;
    uint32_t flow_index = select_http2_flow_index(pinfo, http2_session);

    http2_stream_info_t *stream_info = (http2_stream_info_t *)wmem_map_lookup(stream_map, GINT_TO_POINTER(stream_id));
    if (stream_info == NULL) {
        stream_info = wmem_new0(wmem_file_scope(), http2_stream_info_t);
        stream_info->oneway_stream_info[0].header_stream_info.stream_header_list = wmem_list_new(wmem_file_scope());
        stream_info->oneway_stream_info[1].header_stream_info.stream_header_list = wmem_list_new(wmem_file_scope());
        stream_info->stream_id = stream_id;
        stream_info->oneway_stream_info[0].header_stream_info.stream_id = stream_id;
        stream_info->oneway_stream_info[1].header_stream_info.stream_id = stream_id;
        stream_info->reassembly_mode = HTTP2_DATA_REASSEMBLY_MODE_END_STREAM;
        stream_info->oneway_stream_info[0].is_window_initialized = false;
        stream_info->oneway_stream_info[0].current_window_size = INITIAL_WINDOW_SIZE;
        stream_info->oneway_stream_info[1].is_window_initialized = false;
        stream_info->oneway_stream_info[1].current_window_size = INITIAL_WINDOW_SIZE;
        nstime_set_unset(&(stream_info->request_ts));
        wmem_map_insert(stream_map, GINT_TO_POINTER(stream_id), stream_info);
    }

    /* The first time the stream info is requested for a
     * particular direction, initialize the window size
     * in that direction to the current initial window size for
     * that direction. Flip what we're checking around if
     * initializeOppositeDirection is true.
     */
    if (initializeOppositeDirection) {
        flow_index ^= 1;
    }
    if (!stream_info->oneway_stream_info[flow_index].is_window_initialized) {
        stream_info->oneway_stream_info[flow_index].current_window_size = http2_session->initial_new_stream_window_size[flow_index];
        stream_info->oneway_stream_info[flow_index].is_window_initialized = true;
    }

    return stream_info;
}

static http2_stream_info_t*
get_stream_info(packet_info *pinfo, http2_session_t *http2_session, bool initializeOppositeDirection)
{
    uint32_t stream_id = http2_session->current_stream_id;

    return get_stream_info_for_id(pinfo, http2_session, initializeOppositeDirection, stream_id);
}
#endif

static http2_session_t*
get_http2_session(packet_info *pinfo, conversation_t* conversation)
{
    http2_session_t *h2session;

    h2session = (http2_session_t*)conversation_get_proto_data(conversation,
                                                              proto_http2);

    if(!h2session) {
        struct tcp_analysis *tcpd;

        tcpd = get_tcp_conversation_data(conversation, pinfo);

        h2session = wmem_new0(wmem_file_scope(), http2_session_t);

#ifdef HAVE_NGHTTP2
        nghttp2_hd_inflate_new(&h2session->hd_inflater[0]);
        nghttp2_hd_inflate_new(&h2session->hd_inflater[1]);

        wmem_register_callback(wmem_file_scope(), hd_inflate_del_cb,
                               h2session->hd_inflater[0]);
        wmem_register_callback(wmem_file_scope(), hd_inflate_del_cb,
                               h2session->hd_inflater[1]);
        h2session->per_stream_info = wmem_map_new(wmem_file_scope(),
                                                  g_direct_hash,
                                                  g_direct_equal);
        /* Unless found otherwise, assume that some earlier Header Block
         * Fragments were missing and that recovery should be attempted. */
        h2session->fix_dynamic_table[0] = true;
        h2session->fix_dynamic_table[1] = true;
#endif

        h2session->fwd_flow = tcpd->fwd;
        h2session->settings_queue[0] = wmem_queue_new(wmem_file_scope());
        h2session->settings_queue[1] = wmem_queue_new(wmem_file_scope());
        h2session->initial_new_stream_window_size[0] = INITIAL_WINDOW_SIZE;
        h2session->initial_new_stream_window_size[1] = INITIAL_WINDOW_SIZE;
        h2session->current_connection_window_size[0] = INITIAL_WINDOW_SIZE;
        h2session->current_connection_window_size[1] = INITIAL_WINDOW_SIZE;

        conversation_add_proto_data(conversation, proto_http2, h2session);
    }

    return h2session;
}

#ifdef HAVE_NGHTTP2
uint32_t
http2_get_stream_id(packet_info *pinfo)
{
    conversation_t *conversation;
    http2_session_t *h2session;

    conversation = find_conversation_pinfo(pinfo, 0);
    if (!conversation) {
        return 0;
    }

    h2session = (http2_session_t*)conversation_get_proto_data(conversation, proto_http2);
    if (!h2session) {
        return 0;
    }

    return h2session->current_stream_id;
}
#else /* ! HAVE_NGHTTP2 */
uint32_t
http2_get_stream_id(packet_info *pinfo _U_)
{
    return 0;
}
#endif /* ! HAVE_NGHTTP2 */

#ifdef HAVE_NGHTTP2
static const char*
get_real_header_value(packet_info* pinfo, const char* name, bool the_other_direction);

static http2_frame_num_t
get_http2_frame_num(tvbuff_t *tvb, packet_info *pinfo)
{
    /* HTTP2 frames are identified as follows:
     *
     * +--- 32 bits ---+--------- 8 bits -------+----- 24 bits -----+
     * |  pinfo->num   | pinfo->curr_layer_num  |  tvb->raw_offset  |
     * +------------------------------------------------------------+
     *
     * This allows for a single HTTP2 frame to be uniquely identified across a capture with the
     * added benefit that the number will always be increasing from the previous HTTP2 frame so
     * we can use "<" and ">" comparisons to determine before and after in time.
     *
     * pinfo->curr_layer_num is used to deliberate when we have multiple TLS records in a
     * single (non-http2) frame. This ends up being dissected using two separate TVBs
     * (so tvb->raw_offset isn't useful) and then end up being the same pinfo->num.
     *
     * I have seen instances where the pinfo->curr_layer_num can change between the first and second
     * pass of a packet so this needs to be taken into account when this is used as an identifier.
     */
    return (((uint64_t)pinfo->num) << 32) + (((uint64_t)pinfo->curr_layer_num) << 24) + ((uint64_t)tvb_raw_offset(tvb));
}

static http2_oneway_stream_info_t*
get_oneway_stream_info_for_id(packet_info *pinfo, http2_session_t* http2_session, bool the_other_direction, uint32_t stream_id)
{
    http2_stream_info_t *http2_stream_info = get_stream_info_for_id(pinfo, http2_session, false, stream_id);
    uint32_t flow_index = select_http2_flow_index(pinfo, http2_session);
    if (the_other_direction) {
        /* need stream info of the other direction,
        so set index from 0 to 1, or from 1 to 0 */
        flow_index ^= 1;
    }

    return &http2_stream_info->oneway_stream_info[flow_index];
}

static http2_oneway_stream_info_t*
get_oneway_stream_info(packet_info *pinfo, http2_session_t* http2_session, bool the_other_direction)
{
    return get_oneway_stream_info_for_id(pinfo, http2_session, the_other_direction, http2_session->current_stream_id);
}

static http2_data_stream_body_info_t*
get_data_stream_body_info_for_id(packet_info *pinfo, http2_session_t* http2_session, uint32_t stream_id)
{
    return &(get_oneway_stream_info_for_id(pinfo, http2_session, false, stream_id)->data_stream_body_info);
}

static http2_data_stream_body_info_t*
get_data_stream_body_info(packet_info *pinfo, http2_session_t* http2_session)
{
    return &(get_oneway_stream_info(pinfo, http2_session, false)->data_stream_body_info);
}

static http2_data_stream_reassembly_info_t*
get_data_reassembly_info_for_id(packet_info *pinfo, http2_session_t* http2_session, uint32_t stream_id)
{
    return &(get_oneway_stream_info_for_id(pinfo, http2_session, false, stream_id)->data_stream_reassembly_info);
}

static http2_data_stream_reassembly_info_t*
get_data_reassembly_info(packet_info *pinfo, http2_session_t* http2_session)
{
    return &(get_oneway_stream_info(pinfo, http2_session, false)->data_stream_reassembly_info);
}

static http2_header_stream_info_t*
get_header_stream_info_for_id(packet_info *pinfo, http2_session_t* http2_session,bool the_other_direction, uint32_t stream_id)
{
    return &(get_oneway_stream_info_for_id(pinfo, http2_session, the_other_direction, stream_id)->header_stream_info);
}

static http2_header_stream_info_t*
get_header_stream_info(packet_info *pinfo, http2_session_t* http2_session,bool the_other_direction)
{
    return &(get_oneway_stream_info(pinfo, http2_session, the_other_direction)->header_stream_info);
}

static void
push_settings(packet_info *pinfo, http2_session_t *h2session,
              http2_settings_t *settings)
{
    wmem_queue_t *queue;
    uint32_t flow_index;

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
    uint32_t flow_index;

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
static unsigned read_integer(http2_header_repr_info_t *header_repr_info,
                          const uint8_t *buf, unsigned len, unsigned p, unsigned prefix)
{
    unsigned k = (1 << prefix) - 1;
    unsigned n = header_repr_info->integer;
    unsigned shift = header_repr_info->next_shift;

    if(n == 0) {
        DISSECTOR_ASSERT(p < len);

        if((buf[p] & k) != k) {
            header_repr_info->integer = buf[p] & k;
            header_repr_info->complete = true;
            return p + 1;
        }

        n = k;

        ++p;
    }

    for(; p < len; ++p, shift += 7) {
        n += (buf[p] & 0x7F) << shift;

        if((buf[p] & 0x80) == 0) {
            header_repr_info->complete = true;
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
    header_repr_info->complete = false;
}

/* Reads zero or more header table size update and optionally header
   representation information.  This function returns when first
   header representation is decoded or buf is processed completely.
   This function returns the number bytes processed for header table
   size update. */
static unsigned
process_http2_header_repr_info(wmem_array_t *headers,
                               http2_header_repr_info_t *header_repr_info,
                               const uint8_t *buf, unsigned len)
{
    unsigned i;
    unsigned start;

    if(header_repr_info->type != HTTP2_HD_NONE &&
       header_repr_info->type != HTTP2_HD_HEADER_TABLE_SIZE_UPDATE &&
       header_repr_info->complete) {
        return 0;
    }

    start = 0;

    for(i = 0; i < len;) {
        if(header_repr_info->type == HTTP2_HD_NONE) {
            unsigned char c = buf[i];
            if((c & 0xE0) == 0x20) {
                header_repr_info->type = HTTP2_HD_HEADER_TABLE_SIZE_UPDATE;

                i = read_integer(header_repr_info, buf, len, i, 5);
            } else if(c & 0x80) {
                header_repr_info->type = HTTP2_HD_INDEXED;
                i = read_integer(header_repr_info, buf, len, i, 7);
            } else if(c == 0x40 || c == 0 || c == 0x10) {
                /* New name */
                header_repr_info->complete = true;
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

static size_t http2_hdrcache_length(const void *vv)
{
    const uint8_t *v = (const uint8_t *)vv;
    uint32_t namelen, valuelen;

    namelen = pntoh32(v);
    valuelen = pntoh32(v + sizeof(namelen) + namelen);

    return namelen + valuelen + sizeof(namelen) + sizeof(valuelen);
}

static unsigned http2_hdrcache_hash(const void *key)
{
    return wmem_strong_hash((const uint8_t *)key, http2_hdrcache_length(key));
}

static gboolean http2_hdrcache_equal(const void *lhs, const void *rhs)
{
    const uint8_t *a = (const uint8_t *)lhs;
    const uint8_t *b = (const uint8_t *)rhs;
    size_t alen = http2_hdrcache_length(a);
    size_t blen = http2_hdrcache_length(b);

    return alen == blen && memcmp(a, b, alen) == 0;
}

/* If we are in a HEADERS or PUSH_PROMISE context, return the stream id
 * the headers describe. (For PUSH_PROMISE or CONTIUATIONs thereof, this
 * is the promised stream id.) Otherwise return 0.
 */
static uint32_t
is_in_header_context(tvbuff_t *tvb, packet_info *pinfo, http2_session_t* h2session)
{
    http2_header_stream_info_t *stream_info = get_header_stream_info(pinfo, h2session, false);
    if (get_http2_frame_num(tvb, pinfo) >= stream_info->header_start_in) {
        /* We either haven't established the frame that the headers end in so we are currently in the HEADERS context,
         * or if we have, it should be equal or less that the current frame number */
        if (stream_info->header_end_in == 0 || get_http2_frame_num(tvb, pinfo) <= stream_info->header_end_in) {
            return stream_info->stream_id;
        }
    }
    return 0;
}

/* Extracts only the media-type from a content-type header. EG:
   "text/html"                  returns "text/html"
   "text/html; charset=utf-8"   returns "text/html"

   Allocates file-scoped string when called as its only called when the header population is done.
*/
static char*
get_content_type_only(const char *content_type, int content_type_str_len) {
    char *cp = wmem_strndup(wmem_file_scope(), content_type, content_type_str_len);
    char *start = cp;

    while (*cp != '\0' && *cp != ';' && !g_ascii_isspace(*cp)) {
        *cp = g_ascii_tolower(*cp);
        ++cp;
    }
    *cp = '\0';

    return start;
}

/* Extracts the parameters from a content-type or returns NULL. EG:

   "text/html; charset=utf-8"   returns "charset=utf-8"
   "text/html"                  returns NULL
   "text/html; "                returns NULL

   Allocates file-scoped string when called as its only called when the header population is done.
*/
static char*
get_content_type_parameters_only(const char *content_type, int content_type_str_len) {
    char *cp = wmem_strndup(wmem_file_scope(), content_type, content_type_str_len);

    /* Get past the first part of the content type EG: "text/html" */
    while (*cp != '\0' && *cp != ';' && !g_ascii_isspace(*cp)) {
        ++cp;
    }

    /* No parameters */
    if(*cp == '\0') {
        return NULL;
    }

    /* Move past the first ";" or any whitespace */
    while (*cp == ';' || g_ascii_isspace(*cp)) {
        ++cp;
    }

    /* Didn't end up getting any parameters, we just had trailing whitespace or a semicolon after the content-type */
    if (*cp == '\0') {
        return NULL;
    }

    return cp;
}

/* Populates HTTP/2 header information for the given stream. For frames
 * associated with HEADERS this is the current frame, but for PUSH_PROMISE
 * populate information for the promised stream id.
 */
static void
populate_http_header_tracking(tvbuff_t *tvb, packet_info *pinfo, http2_session_t *h2session, int header_value_length,
                                   const char *header_name, const char *header_value, uint32_t stream_id, const bool override)
{
    http2_stream_info_t *stream_info = get_stream_info_for_id(pinfo, h2session, false, stream_id);
    http2_data_stream_body_info_t *body_info = get_data_stream_body_info_for_id(pinfo, h2session, stream_id);
    http2_data_stream_reassembly_info_t *reassembly_info = get_data_reassembly_info_for_id(pinfo, h2session, stream_id);

    /* Populate the content encoding used so we can uncompress the body later if required */
    if (strcmp(header_name, HTTP2_HEADER_CONTENT_ENCODING) == 0) {
        if (body_info->content_encoding == NULL || override == true) {
            body_info->content_encoding = wmem_strndup(wmem_file_scope(), header_value, header_value_length);
        }
    }

    /* Store the frame number so we can enhance the display of request/response */
    if (strcmp(header_name, HTTP2_HEADER_METHOD) == 0) {
        stream_info->request_in_frame_num = pinfo->num;
        stream_info->request_ts = pinfo->abs_ts;
    }
    if (strcmp(header_name, HTTP2_HEADER_STATUS) == 0) {
        stream_info->response_in_frame_num = pinfo->num;
    }

    /* Is this a partial content? */
    if (strcmp(header_name, HTTP2_HEADER_STATUS) == 0 &&
                strcmp(header_value, HTTP2_HEADER_STATUS_PARTIAL_CONTENT) == 0) {
        body_info->is_partial_content = true;
    }

    /* Was this header used to initiate transfer of data frames? We'll use this later for reassembly */
    if (strcmp(header_name, HTTP2_HEADER_STATUS) == 0 ||
                strcmp(header_name, HTTP2_HEADER_METHOD) == 0 ||
                /* If we are in the middle of a stream assume there might be data transfer */
                strcmp(header_name, HTTP2_HEADER_UNKNOWN) == 0){
        if (reassembly_info->data_initiated_in == 0) {
            reassembly_info->data_initiated_in = get_http2_frame_num(tvb, pinfo);
        }
    }

    /* Do we have transfer encoding of bodies? We don't support reassembling these so mark it as such. */
    if (strcmp(header_name, HTTP2_HEADER_TRANSFER_ENCODING) == 0) {
        reassembly_info->has_transfer_encoded_body = true;
    }

    /* Store away if the stream is associated with a CONNECT request */
    if (strcmp(header_name, HTTP2_HEADER_METHOD) == 0 &&
                strcmp(header_value, HTTP2_HEADER_METHOD_CONNECT) == 0) {
        stream_info->is_stream_http_connect = true;
    }

    /* Populate the content type so we can dissect the body later */
    if (strcmp(header_name, HTTP2_HEADER_CONTENT_TYPE) == 0) {
        if (body_info->content_type == NULL || override == true) {
            body_info->content_type = get_content_type_only(header_value, header_value_length);
            body_info->content_type_parameters = get_content_type_parameters_only(header_value, header_value_length);
            stream_info->reassembly_mode = http2_get_data_reassembly_mode(body_info->content_type);
            dissector_handle_t handle = dissector_get_string_handle(media_type_dissector_table, body_info->content_type);
            if (handle) {
                dissector_add_uint("http2.streamid", stream_info->stream_id, handle);
            }
        }
    }

    if (strcmp(header_name, HTTP2_HEADER_PATH) == 0) {
        stream_info->path = wmem_strndup(wmem_file_scope(), header_value, header_value_length);
    }

    if (strcmp(header_name, HTTP2_HEADER_AUTHORITY) == 0) {
        stream_info->authority = wmem_strndup(wmem_file_scope(), header_value, header_value_length);
    }
}

static void
try_append_method_path_info(packet_info *pinfo, proto_tree *tree,
                        const char *method_header_value, const char *path_header_value)
{
    if (method_header_value != NULL && path_header_value != NULL) {
        /* append request information to info column (for example, HEADERS: GET /demo/1.jpg) */
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ", "%s %s", method_header_value, path_header_value);
        /* append request information to Stream node */
        proto_item_append_text(tree, ", %s %s", method_header_value, path_header_value);
    }
}

static proto_item*
try_add_named_header_field(proto_tree *tree, tvbuff_t *tvb, int offset, uint32_t length, const char *header_name, const char *header_value)
{
    int hf_id;
    header_field_info *hfi;
    proto_item* ti = NULL;

    const int *entry = (const int*) g_hash_table_lookup(header_fields_hash, header_name);
    if (entry == NULL) {
        return NULL;
    }

    hf_id = *entry;

    hfi = proto_registrar_get_nth(hf_id);
    DISSECTOR_ASSERT(hfi != NULL);

    if (FT_IS_UINT32(hfi->type)) {
        uint32_t value;
        if (ws_strtou32(header_value, NULL, &value)) {
            ti = proto_tree_add_uint(tree, hf_id, tvb, offset, length, value);
        }
    } else if (FT_IS_UINT(hfi->type)) {
        uint64_t value;
        if (ws_strtou64(header_value, NULL, &value)) {
            ti = proto_tree_add_uint64(tree, hf_id, tvb, offset, length, value);
        }
    } else {
        ti = proto_tree_add_item(tree, hf_id, tvb, offset, length, ENC_BIG_ENDIAN);
    }
    return ti;
}

static void
fix_partial_header_dissection_support(nghttp2_hd_inflater *hd_inflater, bool *fix_it)
{
    /* Workaround is not necessary or has already been applied, skip. */
    if (!*fix_it) {
        return;
    }
    *fix_it = false;

    /* Sanity-check: the workaround should fill an empty dynamic table only and
     * not evict existing entries. It is expected to be empty given that this is
     * the first time processing headers, but double-check just to be sure.
     */
    if (nghttp2_hd_inflate_get_dynamic_table_size(hd_inflater) != 0) {
        // Dynamic table is non-empty, do not touch it!
        return;
    }

    /* Support dissection of headers where the capture starts in the middle of a
     * TCP stream. In that case, the Headers Block Fragment might reference
     * earlier dynamic table entries unknown to the decompressor. To avoid a
     * fatal error that breaks all future header dissection in this connection,
     * populate the dynamic table with some dummy entries.
     * See also https://github.com/nghttp2/nghttp2/issues/1389
     *
     * The number of entries in the dynamic table is dependent on the maximum
     * table size (SETTINGS_HEADER_TABLE_SIZE, defaults to 4096 bytes) and the
     * size of individual entries (32 + name length + value length where 32 is
     * the overhead from RFC 7541, Section 4.1). Since earlier header fields in
     * the dynamic table are unknown, we will try to use a small dummy header
     * field to maximize the number of entries: "<unknown>" with no value.
     *
     * The binary instruction to insert this is defined in Figure 7 of RFC 7541.
     */
    static const uint8_t dummy_header[] = "\x40"
                                         "\x09"      /* Name String Length */
                                         HTTP2_HEADER_UNKNOWN /* Name String */
                                         "\0";       /* Value Length */
    const int dummy_header_size = sizeof(dummy_header) - 1;
    const int dummy_entries_to_add = (int)(nghttp2_hd_inflate_get_max_dynamic_table_size(hd_inflater) / (32 + dummy_header_size - 3));
    for (int i = dummy_entries_to_add - 1; i >= 0; --i) {
        nghttp2_nv nv;
        int inflate_flags = 0;
        int rv = (int)nghttp2_hd_inflate_hd2(hd_inflater, &nv, &inflate_flags,
                                             dummy_header, dummy_header_size,
                                             i == 0);
        if (rv != dummy_header_size) {
            ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
                  "unexpected decompression state: %d != %d", rv,
                  dummy_header_size);
            break;
        }
    }
    nghttp2_hd_inflate_end_headers(hd_inflater);
}

static void
inflate_http2_header_block(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree,
                           unsigned headlen, http2_session_t *h2session, uint8_t flags)
{
    uint8_t *headbuf;
    proto_tree *header_tree;
    proto_item *header, *ti, *ti_named_field;
    uint32_t header_name_length;
    uint32_t header_value_length;
    const uint8_t *header_name;
    const uint8_t *header_value;
    int hoffset = 0;
    nghttp2_hd_inflater *hd_inflater;
    tvbuff_t *header_tvb = NULL;
    int rv;
    int header_len = 0;
    int final;
    uint32_t flow_index;
    http2_header_data_t *header_data;
    http2_header_repr_info_t *header_repr_info;
    wmem_list_t *header_list;
    wmem_array_t *headers;
    unsigned i;
    const char *method_header_value = NULL;
    const char *path_header_value = NULL;
    const char *scheme_header_value = NULL;
    const char *authority_header_value = NULL;
    http2_header_stream_info_t* header_stream_info;
    char *header_unescaped = NULL;

    if (!http2_hdrcache_map) {
        http2_hdrcache_map = wmem_map_new(wmem_file_scope(), http2_hdrcache_hash, http2_hdrcache_equal);
    }

    header_data = (http2_header_data_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_http2, PROTO_DATA_KEY_HEADER);
    header_list = header_data->header_list;

    if(!PINFO_FD_VISITED(pinfo)) {
        /* This packet has not been processed yet, which means this is
           the first linear scan.  We do header decompression only
           once in linear scan and cache the result.  If we don't
           cache, already processed data will be fed into decompressor
           again and again since dissector will be called randomly.
           This makes context out-of-sync. */
        int decompressed_bytes = 0;

        /* Make sure the length isn't too large. */
        tvb_ensure_bytes_exist(tvb, offset, headlen);
        headbuf = (uint8_t*)wmem_alloc(pinfo->pool, headlen);
        tvb_memcpy(tvb, headbuf, offset, headlen);

        flow_index = select_http2_flow_index(pinfo, h2session);
        hd_inflater = h2session->hd_inflater[flow_index];
        header_repr_info = &h2session->header_repr_info[flow_index];

        fix_partial_header_dissection_support(hd_inflater, &h2session->fix_dynamic_table[flow_index]);

        final = flags & HTTP2_FLAGS_END_HEADERS;

        headers = wmem_array_sized_new(wmem_file_scope(), sizeof(http2_header_t), 16);

        for(;;) {
            nghttp2_nv nv;
            int inflate_flags = 0;

            if (wmem_array_get_count(headers) >= MAX_HTTP2_HEADER_LINES) {
                header_data->header_lines_exceeded = true;
                break;
            }

            rv = (int)nghttp2_hd_inflate_hd2(hd_inflater, &nv,
                                             &inflate_flags, headbuf, headlen, final);

            if(rv < 0) {
                break;
            }

            headbuf += rv;
            headlen -= rv;

            rv -= process_http2_header_repr_info(headers, header_repr_info, headbuf - rv, rv);

            if(inflate_flags & NGHTTP2_HD_INFLATE_EMIT) {
                char *cached_pstr;
                uint32_t len;
                unsigned datalen = (unsigned)(4 + nv.namelen + 4 + nv.valuelen);
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
                   uint32_t. */
                len = (uint32_t)nv.namelen;
                phton32(&http2_header_pstr[0], len);
                memcpy(&http2_header_pstr[4], nv.name, nv.namelen);

                len = (uint32_t)nv.valuelen;
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

        /* add this packet headers to stream header list */
        /* If this is a PUSH_PROMISE frame (or a CONTINUATION of a PUSH_PROMISE
         * field block), we don't want to add it to this list, but to the list
         * for the promised stream.
         */
        uint32_t header_stream_id = is_in_header_context(tvb, pinfo, h2session);
        if (header_stream_id == 0) {
            header_stream_id = h2session->current_stream_id;
        }
        header_stream_info = get_header_stream_info_for_id(pinfo, h2session, false, header_stream_id);
        if (header_stream_info) {
            wmem_list_append(header_stream_info->stream_header_list, headers);
        }

    } else if (header_data->current) {
        headers = (wmem_array_t*)wmem_list_frame_data(header_data->current);

        header_data->current = wmem_list_frame_next(header_data->current);

        if(!header_data->current) {
            header_data->current = wmem_list_head(header_list);
        }
    } else {
        return;
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
        if (!header_tvb) {
            header_tvb = tvb_new_composite();
        }
        tvb_composite_append(header_tvb, next_tvb);
    }


    if (!header_tvb) {
        return;
    }

    tvb_composite_finalize(header_tvb);
    add_new_data_source(pinfo, header_tvb, "Decompressed Header");

    ti = proto_tree_add_uint(tree, hf_http2_header_length, header_tvb, hoffset, 1, header_len);
    proto_item_set_generated(ti);

    if (header_data->header_size_attempted > 0) {
        expert_add_info_format(pinfo, ti, &ei_http2_header_size,
                               "Decompression stopped after %u bytes (%u attempted).",
                               header_data->header_size_reached,
                               header_data->header_size_attempted);
    }

    ti = proto_tree_add_uint(tree, hf_http2_header_count, header_tvb, hoffset, 1, wmem_array_get_count(headers));
    proto_item_set_generated(ti);

    if (header_data->header_lines_exceeded) {
        expert_add_info(pinfo, ti, &ei_http2_header_lines);
    }

    wmem_strbuf_t* headers_buf = wmem_strbuf_create(pinfo->pool);
    wmem_strbuf_t* header_buf;

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
        proto_tree_add_item_ret_uint(header_tree, hf_http2_header_name_length, header_tvb, hoffset, 4, ENC_BIG_ENDIAN, &header_name_length);
        hoffset += 4;

        /* Add header name. */
        proto_tree_add_item_ret_string(header_tree, hf_http2_header_name, header_tvb, hoffset, header_name_length, ENC_ASCII|ENC_NA, pinfo->pool, &header_name);
        hoffset += header_name_length;

        /* header value length */
        proto_tree_add_item_ret_uint(header_tree, hf_http2_header_value_length, header_tvb, hoffset, 4, ENC_BIG_ENDIAN, &header_value_length);
        hoffset += 4;

        /* Add header value. */
        proto_tree_add_item_ret_string(header_tree, hf_http2_header_value, header_tvb, hoffset, header_value_length, ENC_ASCII|ENC_NA, pinfo->pool, &header_value);
        // check if field is http2 header https://tools.ietf.org/html/rfc7541#appendix-A
        ti_named_field = try_add_named_header_field(header_tree, header_tvb, hoffset, header_value_length, header_name, header_value);

        /* Add header unescaped. */
        header_unescaped = g_uri_unescape_string(header_value, NULL);
        if (header_unescaped != NULL) {
            char *header_unescaped_valid = ws_utf8_make_valid(pinfo->pool, header_unescaped, strlen(header_unescaped));
            ti = proto_tree_add_string(header_tree, hf_http2_header_unescaped, header_tvb, hoffset, header_value_length, header_unescaped_valid);
            proto_item_set_generated(ti);
            g_free(header_unescaped);
        }
        hoffset += header_value_length;

        /* Track HEADER and CONTINUATION frames part thereof for this stream id.
         * For PUSH_PROMISE and CONTINUATION frames thereof, add to the promised stream id.
         * Only do it for the first pass in case the current layer changes, altering where the headers frame number,
         * http2_frame_num_t points to. */
        uint32_t header_stream_id;
        if (!PINFO_FD_VISITED(pinfo) && (header_stream_id = is_in_header_context(tvb, pinfo, h2session))) {
            populate_http_header_tracking(tvb, pinfo, h2session, header_value_length, header_name, header_value, header_stream_id, false);
        }

        /* Add encoding representation */
        // This should probably be a bitmask for the first bits, see https://tools.ietf.org/html/rfc7541#section-6
        proto_tree_add_string(header_tree, hf_http2_header_repr, tvb, offset, 1, http2_header_repr_type[in->type].strptr);

        if(in->type == HTTP2_HD_INDEXED ||
           in->type == HTTP2_HD_LITERAL_INDEXING_INDEXED_NAME ||
           in->type == HTTP2_HD_LITERAL_INDEXED_NAME ||
           in->type == HTTP2_HD_LITERAL_NEVER_INDEXING_INDEXED_NAME) {
            /* Only for HTTP2_HD_INDEXED, the index value covers the full
             * "in->length". In other cases, it is a subset. For simplicity,
             * just select 1 octet (this might not be accurate though). */
            unsigned index_length = in->length;
            if (in->type != HTTP2_HD_INDEXED) {
                index_length = 1;
            }
            proto_tree_add_uint(header_tree, hf_http2_header_index, tvb, offset, index_length, in->table.data.idx);
        }

        header_buf = wmem_strbuf_new(pinfo->pool, header_name);
        wmem_strbuf_append_printf(header_buf, ": %s", header_value);
        proto_item_append_text(header, ": %s", wmem_strbuf_get_str(header_buf));
        wmem_strbuf_append_printf(headers_buf, "%s\n", wmem_strbuf_finalize(header_buf));

        /* Display :method, :path and :status in info column (just like http1.1 dissector does)*/
        if (strcmp(header_name, HTTP2_HEADER_METHOD) == 0) {
            method_header_value = header_value;
            try_append_method_path_info(pinfo, tree, method_header_value, path_header_value);
        }
        else if (strcmp(header_name, HTTP2_HEADER_PATH) == 0) {
            path_header_value = header_value;
            try_append_method_path_info(pinfo, tree, method_header_value, path_header_value);
            http_add_path_components_to_tree(header_tvb, pinfo, ti_named_field, hoffset - header_value_length, header_value_length);
        }
        else if (strcmp(header_name, HTTP2_HEADER_STATUS) == 0) {
            const char* reason_phase = val_to_str_const((unsigned)strtoul(header_value, NULL, 10), vals_http_status_code, "Unknown");
            /* append response status and reason phrase to info column (for example, HEADERS: 200 OK) */
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ", "%s %s", header_value, reason_phase);
            /* append response status and reason phrase to header_tree and Stream node */
            proto_item_append_text(header_tree, " %s", reason_phase);
            proto_item_append_text(tree, ", %s %s", header_value, reason_phase);
        }
        else if (strcmp(header_name, HTTP2_HEADER_AUTHORITY) == 0) {
            authority_header_value = header_value;
	}
        else if (strcmp(header_name, HTTP2_HEADER_SCHEME) == 0) {
            scheme_header_value = header_value;
	}

        offset += in->length;
    }

    if (have_tap_listener(http2_follow_tap)) {
        http2_follow_tap_data_t* follow_data = wmem_new0(pinfo->pool, http2_follow_tap_data_t);

        wmem_strbuf_append(headers_buf, "\n");
        follow_data->tvb = tvb_new_child_real_data(header_tvb,
            wmem_strbuf_get_str(headers_buf), (unsigned)wmem_strbuf_get_len(headers_buf),
            (int)wmem_strbuf_get_len(headers_buf));
        follow_data->stream_id = h2session->current_stream_id;

        tap_queue_packet(http2_follow_tap, pinfo, follow_data);
    }

    /* Use the Authority Header as an indication that this packet is a request */
    if (authority_header_value) {
        proto_item *e_ti;
        char *uri;

        /* RFC9113 8.3.1:
           "All HTTP/2 requests MUST include exactly one valid value for the
           ":method", ":scheme", and ":path" pseudo-header fields, unless they
           are CONNECT requests"
        */
        if (method_header_value &&
            strcmp(method_header_value, HTTP2_HEADER_METHOD_CONNECT) == 0) {
            uri = wmem_strdup(pinfo->pool, authority_header_value);
        } else {
            uri = wmem_strdup_printf(pinfo->pool, "%s://%s%s", scheme_header_value, authority_header_value, path_header_value);
        }
        e_ti = proto_tree_add_string(tree, hf_http2_header_request_full_uri, tvb, 0, 0, uri);
        proto_item_set_url(e_ti);
        proto_item_set_generated(e_ti);
    }
}

/* If the initial/first HEADERS frame (containing ":method" or ":status" header) of this direction is not received
 * (normally because of starting capturing after a long-lived HTTP2 stream like gRPC streaming call has been establied),
 * we initialize the information in direction of the stream with the fake headers of wireshark http2 preferences.
 * In an other situation, some http2 headers are unable to be parse in current HEADERS frame because previous HEADERS
 * frames were not captured that causing HPACK index table not completed. Fake headers can also be used in this situation.
 */
static void
try_init_stream_with_fake_headers(tvbuff_t* tvb, packet_info* pinfo, http2_session_t* h2session, proto_tree* tree, unsigned offset)
{
    if (num_http2_fake_headers == 0) {
        return;
    }

    http2_direction_type direction;
    range_t* server_port_range;
    uint32_t stream_id = h2session->current_stream_id;
    wmem_array_t* indexes = NULL; /* the indexes of fake headers matching this stream and direction */
    proto_item* ti, * ti_header;
    proto_tree* header_tree;
    http2_frame_num_t http2_frame_num = get_http2_frame_num(tvb, pinfo);

    http2_header_stream_info_t* header_stream_info = get_header_stream_info(pinfo, h2session, false);
    http2_data_stream_reassembly_info_t* reassembly_info = get_data_reassembly_info(pinfo, h2session);

    if (!PINFO_FD_VISITED(pinfo) && header_stream_info->fake_headers_initiated_fn == 0) {
        header_stream_info->fake_headers_initiated_fn = http2_frame_num;
        if (reassembly_info->data_initiated_in == 0) {
            /* At this time, the data_initiated_in has not been set,
             * indicating that the previous initial HEADERS frame has been lost.
             * We try to use fake headers to initialize stream reassembly info. */
            reassembly_info->data_initiated_in = http2_frame_num;
        }

        /* Initialize with fake headers in this frame.
         * Use only those fake headers that do not appear. */
        header_stream_info->fake_headers = wmem_array_sized_new(wmem_file_scope(), sizeof(http2_fake_header_t*), 16);

        for (unsigned i = 0; i < num_http2_fake_headers; ++i) {
            http2_fake_header_t* fake_header = http2_fake_headers + i;
            if (fake_header->enable == false ||
                (fake_header->stream_id > 0 && fake_header->stream_id != stream_id)) {
                continue;
            }

            server_port_range = fake_header->server_port_range;
            if (value_is_in_range(server_port_range, pinfo->destport)) {
                direction = DIRECTION_IN;
            } else if (value_is_in_range(server_port_range, pinfo->srcport)) {
                direction = DIRECTION_OUT;
            } else {
                continue;
            }

            if (fake_header->direction != direction) {
                continue;
            }

            /* now match one */
            if (get_real_header_value(pinfo, fake_header->header_name, false) && fake_header->override == false) {
                /* If this header already appears, the fake header is ignored, unless we want to override. */
                continue;
            }

            populate_http_header_tracking(tvb, pinfo, h2session, (int)strlen(fake_header->header_value),
                fake_header->header_name, fake_header->header_value, h2session->current_stream_id, fake_header->override);

            wmem_array_append(header_stream_info->fake_headers, &fake_header, 1);
        }
    }

    if (header_stream_info->fake_headers_initiated_fn == http2_frame_num) {
        indexes = header_stream_info->fake_headers;
        /* Try to add the tree item of fake headers. */
        if (indexes) {
            unsigned total_matching_fake_headers = wmem_array_get_count(indexes);

            ti = proto_tree_add_uint(tree, hf_http2_fake_header_count, tvb, offset, 0, total_matching_fake_headers);
            proto_item_append_text(ti, " (Using fake headers because previous initial HEADERS frame is missing)");
            proto_item_set_generated(ti);

            for (unsigned i = 0; i < total_matching_fake_headers; ++i) {
                http2_fake_header_t* header = *(http2_fake_header_t**)wmem_array_index(indexes, i);

                ti_header = proto_tree_add_item(tree, hf_http2_fake_header, tvb, offset, 0, ENC_NA);
                header_tree = proto_item_add_subtree(ti_header, ett_http2_header);
                proto_item_append_text(ti_header, ": %s: %s", header->header_name, header->header_value);
                proto_item_set_generated(ti_header);

                ti = proto_tree_add_string(header_tree, hf_http2_header_name, tvb, offset, 0, header->header_name);
                proto_item_set_generated(ti);
                ti = proto_tree_add_string(header_tree, hf_http2_header_value, tvb, offset, 0, header->header_value);
                proto_item_set_generated(ti);
            }
        }
    }
}
#endif

static char*
http2_follow_conv_filter(epan_dissect_t *edt _U_, packet_info *pinfo, unsigned *stream, unsigned *sub_stream)
{
    http2_session_t *h2session;
    struct tcp_analysis *tcpd;
    conversation_t* conversation;

    /* XXX: Since TCP doesn't use the endpoint API (and HTTP2 is
     * over TCP), we can only look up using the current pinfo addresses
     * and ports. We don't want to create a new conversion or stream.
     * Eventually the endpoint API should support storing multiple
     * endpoints and TCP should be changed to use the endpoint API.
     */
    if (((pinfo->net_src.type == AT_IPv4 && pinfo->net_dst.type == AT_IPv4) ||
        (pinfo->net_src.type == AT_IPv6 && pinfo->net_dst.type == AT_IPv6))
        && (pinfo->ptype == PT_TCP) &&
        (conversation=find_conversation(pinfo->num, &pinfo->net_src, &pinfo->net_dst, CONVERSATION_TCP, pinfo->srcport, pinfo->destport, 0)) != NULL)
    {
        h2session = get_http2_session(pinfo, conversation);
        tcpd = get_tcp_conversation_data(conversation, pinfo);

        if (tcpd == NULL)
            return NULL;
        if (h2session == NULL)
            return NULL;

        *stream = tcpd->stream;
        *sub_stream = h2session->current_stream_id;
        return ws_strdup_printf("tcp.stream eq %u and http2.streamid eq %u", tcpd->stream, h2session->current_stream_id);
    }

    return NULL;
}

static uint32_t
get_http2_stream_count(unsigned streamid)
{
    uint32_t result = 0;
    uint32_t key;
    GHashTable *entry;
    GList *entry_set, *it;

    entry = (GHashTable*)g_hash_table_lookup(streamid_hash, GUINT_TO_POINTER(streamid));
    if (entry != NULL) {
        entry_set = g_hash_table_get_keys(entry);

        /* this is a doubly-linked list, g_list_sort has the same time complexity */
        for (it = entry_set; it != NULL; it = it->next) {
            key = GPOINTER_TO_UINT(it->data);
            result = key > result ? key : result;
        }
        g_list_free(entry_set);
    }

    return result;
}

static bool
is_http2_stream_contains(unsigned streamid, int sub_stream_id)
{
    GHashTable *entry;

    entry = (GHashTable*)g_hash_table_lookup(streamid_hash, GUINT_TO_POINTER(streamid));
    if (entry == NULL) {
        return false;
    }

    if (!g_hash_table_contains(entry, GINT_TO_POINTER(sub_stream_id))) {
        return false;
    }

    return true;
}

bool
http2_get_stream_id_le(unsigned streamid, unsigned sub_stream_id, unsigned *sub_stream_id_out)
{
    // HTTP/2 Stream IDs are always 31 bit.
    int max_id = (int)get_http2_stream_count(streamid);
    int id = (int)(sub_stream_id & MASK_HTTP2_STREAMID);
    if (id > max_id) {
        id = max_id;
    }
    for (; id >= 0; id--) {
        if (is_http2_stream_contains(streamid, id)) {
            *sub_stream_id_out = (unsigned)id;
            return true;
        }
    }
    return false;
}

bool
http2_get_stream_id_ge(unsigned streamid, unsigned sub_stream_id, unsigned *sub_stream_id_out)
{
    // HTTP/2 Stream IDs are always 31 bit.
    int max_id = (int)get_http2_stream_count(streamid);
    for (int id = (int)(sub_stream_id & MASK_HTTP2_STREAMID); id <= max_id; id++) {
        if (is_http2_stream_contains(streamid, id)) {
            *sub_stream_id_out = (unsigned)id;
            return true;
        }
    }
    return false;
}

static bool
http2_get_sub_stream_id(unsigned streamid, unsigned sub_stream_id, bool le, unsigned *sub_stream_id_out)
{
    if (le) {
        return http2_get_stream_id_le(streamid, sub_stream_id, sub_stream_id_out);
    } else {
        return http2_get_stream_id_ge(streamid, sub_stream_id, sub_stream_id_out);
    }
}

static char*
http2_follow_index_filter(unsigned stream, unsigned sub_stream)
{
    return ws_strdup_printf("tcp.stream eq %u and http2.streamid eq %u", stream, sub_stream);
}

static tap_packet_status
follow_http2_tap_listener(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *data, tap_flags_t flags)
{
    follow_info_t *follow_info = (follow_info_t *)tapdata;
    const http2_follow_tap_data_t *follow_data = (const http2_follow_tap_data_t *)data;

    if (follow_info->substream_id != SUBSTREAM_UNUSED &&
        follow_info->substream_id != follow_data->stream_id) {
        return TAP_PACKET_DONT_REDRAW;
    }

    return follow_tvb_tap_listener(tapdata, pinfo, NULL, follow_data->tvb, flags);
}

static uint8_t
dissect_http2_header_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *http2_tree, unsigned offset, uint8_t type)
{

    uint64_t flags_val;
    int* const * fields;

    static int* const http2_hdr_flags[] = {
        &hf_http2_flags_unused_headers,
        &hf_http2_flags_priority,
        &hf_http2_flags_padded,
        &hf_http2_flags_end_headers,
        &hf_http2_flags_end_stream,
        NULL
    };

    static int* const http2_data_flags[] = {
        &hf_http2_flags_unused_data,
        &hf_http2_flags_padded,
        &hf_http2_flags_end_stream,
        NULL
    };

    static int* const http2_settings_flags[] = {
        &hf_http2_flags_unused_settings,
        &hf_http2_flags_settings_ack,
        NULL
    };

    static int* const http2_push_promise_flags[] = {
        &hf_http2_flags_unused_push_promise,
        &hf_http2_flags_padded,
        &hf_http2_flags_end_headers,
        NULL
    };

    static int* const http2_continuation_flags[] = {
        &hf_http2_flags_unused_continuation,
        &hf_http2_flags_padded,
        &hf_http2_flags_end_headers,
        NULL
    };

    static int* const http2_ping_flags[] = {
        &hf_http2_flags_unused_ping,
        &hf_http2_flags_ping_ack,
        NULL
    };

    static int* const http2_unused_flags[] = {
        &hf_http2_flags_unused,
        NULL
    };



    switch(type){
        case HTTP2_DATA:
            fields = http2_data_flags;
            break;
        case HTTP2_HEADERS:
            fields = http2_hdr_flags;
            break;
        case HTTP2_SETTINGS:
            fields = http2_settings_flags;
            break;
        case HTTP2_PUSH_PROMISE:
            fields = http2_push_promise_flags;
            break;
        case HTTP2_CONTINUATION:
            fields = http2_continuation_flags;
            break;
        case HTTP2_PING:
            fields = http2_ping_flags;
            break;
        case HTTP2_PRIORITY:
        case HTTP2_RST_STREAM:
        case HTTP2_GOAWAY:
        case HTTP2_WINDOW_UPDATE:
        case HTTP2_ALTSVC:
        case HTTP2_BLOCKED:
        case HTTP2_ORIGIN:
        case HTTP2_PRIORITY_UPDATE:
        default:
            /* Does not define any flags */
            fields = http2_unused_flags;
            break;
    }

    proto_tree_add_bitmask_with_flags_ret_uint64(http2_tree, tvb, offset, hf_http2_flags,
        ett_http2_flags, fields, ENC_BIG_ENDIAN, BMT_NO_FALSE | BMT_NO_INT, &flags_val);
    return (uint8_t)flags_val;

}

/* helper function to get the padding data for the frames that feature them */
static unsigned
dissect_frame_padding(tvbuff_t *tvb, uint16_t *padding, proto_tree *http2_tree,
                      unsigned offset, uint8_t flags)
{
    proto_item *ti;
    unsigned pad_len = 0;

    *padding = 0;

    if(flags & HTTP2_FLAGS_PADDED)
    {
        *padding = tvb_get_uint8(tvb, offset); /* read a single octet */
        proto_tree_add_item(http2_tree, hf_http2_padding, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        pad_len ++;
    }
    ti = proto_tree_add_uint(http2_tree, hf_http2_pad_length, tvb, offset-pad_len, pad_len, *padding);
    proto_item_set_generated(ti);

    return offset;
}

/* helper function to get the priority dependence for the frames that feature them:
   HEADERS and PRIORITY */
static unsigned
dissect_frame_prio(tvbuff_t *tvb, proto_tree *http2_tree, unsigned offset, uint8_t flags)
{
    proto_tree *ti;
    uint8_t weight;

    if(flags & HTTP2_FLAGS_PRIORITY)
    {
        proto_tree_add_item(http2_tree, hf_http2_excl_dependency, tvb, offset, 4, ENC_NA);
        proto_tree_add_item(http2_tree, hf_http2_stream_dependency, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(http2_tree, hf_http2_weight, tvb, offset, 1, ENC_BIG_ENDIAN);
        weight = tvb_get_uint8(tvb, offset);
        /* 6.2: Weight:  An 8-bit weight for the stream; Add one to the value to obtain a weight between 1 and 256 */
        ti = proto_tree_add_uint(http2_tree, hf_http2_weight_real, tvb, offset, 1, weight+1);
        proto_item_set_generated(ti);
        offset++;
    }

    return offset;
}

#ifdef HAVE_NGHTTP2

static streaming_reassembly_info_t*
get_streaming_reassembly_info(packet_info* pinfo, http2_session_t* http2_session)
{
    http2_data_stream_reassembly_info_t* data_reassembly_info =
        &get_oneway_stream_info(pinfo, http2_session, false)->data_stream_reassembly_info;

    if (data_reassembly_info->streaming_reassembly_info == NULL) {
        data_reassembly_info->streaming_reassembly_info = streaming_reassembly_info_new();
    }

    return data_reassembly_info->streaming_reassembly_info;
}

enum body_uncompression {
    BODY_UNCOMPRESSION_NONE,
    BODY_UNCOMPRESSION_ZLIB,
    BODY_UNCOMPRESSION_BROTLI
};

static enum body_uncompression
get_body_uncompression_info(packet_info *pinfo, http2_session_t* h2session)
{
    http2_data_stream_body_info_t *body_info = get_data_stream_body_info(pinfo, h2session);
    char *content_encoding = body_info->content_encoding;

    /* Check we have a content-encoding header appropriate as well as checking if this is partial content.
     * We can't decompress part of a gzip encoded entity */
    if (!http2_decompress_body || body_info->is_partial_content == true || content_encoding == NULL) {
        return BODY_UNCOMPRESSION_NONE;
    }
#ifdef HAVE_ZLIBNG
    if (strncmp(content_encoding, "gzip", 4) == 0 || strncmp(content_encoding, "deflate", 7) == 0) {
        return BODY_UNCOMPRESSION_ZLIB;
    }
#endif
#ifdef HAVE_ZLIB
    if (strncmp(content_encoding, "gzip", 4) == 0 || strncmp(content_encoding, "deflate", 7) == 0) {
        return BODY_UNCOMPRESSION_ZLIB;
    }
#endif
#ifdef HAVE_BROTLI
    if (strncmp(content_encoding, "br", 2) == 0) {
        return BODY_UNCOMPRESSION_BROTLI;
    }
#endif

    return BODY_UNCOMPRESSION_NONE;
}

/* Try to dissect reassembled http2.data.data according to content_type. */
static void
dissect_body_data(proto_tree *tree, packet_info *pinfo, http2_session_t* h2session, tvbuff_t *tvb,
                  const int start, int length, const unsigned encoding, bool streaming_mode)
{
    http2_data_stream_body_info_t *body_info = get_data_stream_body_info(pinfo, h2session);
    http2_stream_info_t *stream_info = get_stream_info(pinfo, h2session, false);
    char *content_type = body_info->content_type;
    media_content_info_t metadata_used_for_media_type_handle = { MEDIA_CONTAINER_HTTP_OTHERS, body_info->content_type_parameters, NULL, NULL };
    http_eo_t *eo_info;
    uint32_t stream_id;

    stream_id = http2_get_stream_id(pinfo);
    if (!streaming_mode)
        proto_tree_add_item(tree, hf_http2_data_data, tvb, start, length, encoding);

    if (have_tap_listener(http2_follow_tap)) {
        http2_follow_tap_data_t *follow_data = wmem_new0(pinfo->pool, http2_follow_tap_data_t);

        follow_data->tvb = tvb_new_subset_length(tvb, start, length);
        follow_data->stream_id = stream_id;

        tap_queue_packet(http2_follow_tap, pinfo, follow_data);
    }

    if (have_tap_listener(http_eo_tap)) {
        eo_info = wmem_new0(pinfo->pool, http_eo_t);

        eo_info->filename = stream_info->path;
        eo_info->hostname = stream_info->authority;
        eo_info->content_type = content_type;
        eo_info->payload = tvb_new_subset_length(tvb, start, length);

        tap_queue_packet(http_eo_tap, pinfo, eo_info);
    }

    tvbuff_t *data_tvb = tvb_new_subset_length(tvb, start, length);
    if (content_type != NULL) {
        /* add it to STREAM level */
        proto_tree* ptree = proto_tree_get_parent_tree(tree);
        dissector_try_string((streaming_mode ? streaming_content_type_dissector_table : media_type_dissector_table),
            content_type, data_tvb, pinfo,
            ptree, &metadata_used_for_media_type_handle);
    } else {
        if (!dissector_try_uint_new(stream_id_content_type_dissector_table, stream_id,
            data_tvb, pinfo, proto_tree_get_parent_tree(tree), true, &metadata_used_for_media_type_handle))
        {
            /* Try heuristics */
            /* Check for possible boundary string */
            if (tvb_strneql(data_tvb, 0, "--", 2) == 0) {
                int next_offset;
                int boundary_len = tvb_find_line_end(data_tvb, 0, -1, &next_offset, true);
                if ((boundary_len > 4) && (boundary_len < 70)){
                    boundary_len = boundary_len - 2; /* ignore ending CRLF*/
                    /* We have a potential boundary string */
                    uint8_t *boundary = tvb_get_string_enc(wmem_packet_scope(), data_tvb, 2, boundary_len, ENC_ASCII | ENC_NA);
                    if (tvb_strneql(data_tvb, (length - 4) - boundary_len, boundary, boundary_len) == 0) {
                        /* We have multipart/mixed */
                        /* Populate the content type so we can dissect the body later */
                        body_info->content_type = wmem_strndup(wmem_file_scope(), "multipart/mixed", 15);
                        body_info->content_type_parameters = wmem_strdup_printf(wmem_file_scope(), "boundary=\"%s\"", boundary);
                        metadata_used_for_media_type_handle.media_str = body_info->content_type_parameters;
                        dissector_try_uint_new(stream_id_content_type_dissector_table, stream_id,
                            data_tvb, pinfo, proto_tree_get_parent_tree(tree), true, &metadata_used_for_media_type_handle);
                    }
                }
                return;
            } /* Not multipart/mixed*/
            /* check for json, from RFC 4627
             * A JSON text is a serialized object or array.
             * JSON-text = object / array
             * These are the six structural characters:
             * begin-array     = ws %x5B ws  ; [ left square bracket
             * begin-object    = ws %x7B ws  ; { left curly bracket
             * :
             * Insignificant whitespace is allowed before or after any of the six
             * structural characters.
             * ws = *(
             *  %x20 /              ; Space
             *  %x09 /              ; Horizontal tab
             *  %x0A /              ; Line feed or New line
             *  %x0D                ; Carriage return
             * )
             */
            int offset = 0;
            offset = tvb_skip_wsp(data_tvb, 0, length);
            uint8_t oct = tvb_get_uint8(data_tvb, offset);
            if ((oct == 0x5b) || (oct == 0x7b)) {
                /* Potential json */
                const uint8_t* buf = tvb_get_string_enc(pinfo->pool, tvb, 0, length, ENC_ASCII);

                if (json_validate(buf, length) == true) {
                    body_info->content_type = wmem_strndup(wmem_file_scope(), "application/json", 16);
                    dissector_handle_t handle = dissector_get_string_handle(media_type_dissector_table, body_info->content_type);
                    metadata_used_for_media_type_handle.media_str = body_info->content_type_parameters;
                    if (handle) {
                        dissector_add_uint("http2.streamid", stream_info->stream_id, handle);
                    }
                    dissector_try_uint_new(stream_id_content_type_dissector_table, stream_id,
                        data_tvb, pinfo, proto_tree_get_parent_tree(tree), true, &metadata_used_for_media_type_handle);
                }
                return;
            }
        }
    }
}

static void
dissect_http2_data_full_body(tvbuff_t *tvb, packet_info *pinfo, http2_session_t* h2session, proto_tree *http2_tree)
{
    if (!tvb) {
        return;
    }

    int datalen = tvb_reported_length(tvb);

    enum body_uncompression uncompression = get_body_uncompression_info(pinfo, h2session);
    if (uncompression != BODY_UNCOMPRESSION_NONE) {
        proto_item *compressed_proto_item = NULL;

        tvbuff_t *uncompressed_tvb = NULL;
        if (uncompression == BODY_UNCOMPRESSION_ZLIB) {
            uncompressed_tvb = tvb_child_uncompress_zlib(tvb, tvb, 0, datalen);
        } else if (uncompression == BODY_UNCOMPRESSION_BROTLI) {
            uncompressed_tvb = tvb_child_uncompress_brotli(tvb, tvb, 0, datalen);
        }

        http2_data_stream_body_info_t *body_info = get_data_stream_body_info(pinfo, h2session);
        char *compression_method = body_info->content_encoding;

        proto_tree *compressed_entity_tree = proto_tree_add_subtree_format(http2_tree, tvb, 0, datalen, ett_http2_encoded_entity,
            &compressed_proto_item, "Content-encoded entity body (%s): %u bytes",
            compression_method == NULL ? "unknown" : compression_method, datalen
        );

        if (uncompressed_tvb != NULL) {
            unsigned uncompressed_length = tvb_captured_length(uncompressed_tvb);
            add_new_data_source(pinfo, uncompressed_tvb, "Uncompressed entity body");
            proto_item_append_text(compressed_proto_item, " -> %u bytes", uncompressed_length);
            dissect_body_data(compressed_entity_tree, pinfo, h2session, uncompressed_tvb, 0, uncompressed_length, ENC_NA, false);

        } else {
            proto_tree_add_expert(compressed_entity_tree, pinfo, &ei_http2_body_decompression_failed, tvb, 0, datalen);
            dissect_body_data(compressed_entity_tree, pinfo, h2session, tvb, 0, datalen, ENC_NA, false);
        }
    } else {
        dissect_body_data(http2_tree, pinfo, h2session, tvb, 0, datalen, ENC_NA, false);
    }

}

static int
should_attempt_to_reassemble_data_frame(http2_data_stream_reassembly_info_t *reassembly, packet_info *pinfo _U_,
   http2_session_t* http2_session)
{
    /* If we haven't captured the header frame with the request/response we don't know how many data
     * frames we might have lost before processing */
    if (reassembly->data_initiated_in == 0) {
        return false;
    }

    /* For now, do not reassemble transfer encoded bodies. Chunked encoding is explicitly disallowed by RFC7540,
     * section 8.1. Additionally, section 8.1.2.2 specifies that the only valid value for the TE header (indicating
     * which transfer-encoding is allowed) is trailers, suggesting transfer coding other than chunked (gzip,
     * deflate, etc) are not allowed */
    if (reassembly->has_transfer_encoded_body) {
        return false;
    }

    /* Is this data frame part of an established tunnel? Don't try to reassemble the data if that is the case */
    http2_stream_info_t *stream_info = get_stream_info(pinfo, http2_session, false);
    if (stream_info->is_stream_http_connect) {
        return false;
    }

    return true;
}

static uint32_t
get_reassembly_id_from_stream(packet_info *pinfo, http2_session_t* session)
{
    http2_stream_info_t *stream_info = get_stream_info(pinfo, session, false);
    uint32_t flow_index = select_http2_flow_index(pinfo, session);

    /* With a stream ID being 31 bits, use the most significant bit to determine the flow direction of the
     * stream. We use this for the ID in the body reassembly using the reassemble API */
    return stream_info->stream_id | (flow_index << 31);
}

/*
 * Like process_reassembled_data() in reassemble.[ch], but ignores the layer
 * number, which is not always stable in HTTP/2, if multiple TLS records are
 * in the same frame.
 */
static tvbuff_t*
http2_process_reassembled_data(tvbuff_t *tvb, const int offset, packet_info *pinfo,
	const char *name, fragment_head *fd_head, const fragment_items *fit,
	bool *update_col_infop, proto_tree *tree)
{
    tvbuff_t* next_tvb;
    bool update_col_info;
    proto_item* frag_tree_item;

    if (fd_head != NULL) {
        /*
         * OK, we've reassembled this.
         * Is this something that's been reassembled from more
         * than one fragment?
         */
        if (fd_head->next != NULL) {
            /*
             * Yes.
             * Allocate a new tvbuff, referring to the
             * reassembled payload, and set
             * the tvbuff to the list of tvbuffs to which
             * the tvbuff we were handed refers, so it'll get
             * cleaned up when that tvbuff is cleaned up.
             */
            next_tvb = tvb_new_chain(tvb, fd_head->tvb_data);

            /* Add the defragmented data to the data source list. */
            add_new_data_source(pinfo, next_tvb, name);

            /* show all fragments */
            if (fd_head->flags & FD_BLOCKSEQUENCE) {
                update_col_info = !show_fragment_seq_tree(
                    fd_head, fit, tree, pinfo, next_tvb, &frag_tree_item);
            }
            else {
                update_col_info = !show_fragment_tree(fd_head,
                    fit, tree, pinfo, next_tvb, &frag_tree_item);
            }
        }
        else {
            /*
             * No.
             * Return a tvbuff with the payload. next_tvb ist from offset until end
             */
            next_tvb = tvb_new_subset_remaining(tvb, offset);
            pinfo->fragmented = false;	/* one-fragment packet */
            update_col_info = true;
        }
        if (update_col_infop != NULL)
            *update_col_infop = update_col_info;
    } else {
        /*
         * We don't have the complete reassembled payload, or this
         * isn't the final frame of that payload.
         */
        next_tvb = NULL;
        /* process_reassembled_data() in reassemble.[ch] adds reassembled_in
         * here, but the reas_in_layer_num is often unstable in HTTP/2 now so
         * we rely on the stream end flag (that's why we have this function).
         *
         * Perhaps we could DISSECTOR_ASSERT() in this path, we shouldn't
         * get here.
         */
    }
    return next_tvb;
}

static tvbuff_t*
reassemble_http2_data_into_full_frame(tvbuff_t *tvb, packet_info *pinfo, http2_session_t* http2_session, proto_tree *http2_tree, unsigned offset,
                                      uint8_t flags, unsigned datalen)
{
    http2_data_stream_reassembly_info_t *reassembly = get_data_reassembly_info(pinfo, http2_session);

    /* There are a number of conditions as to why we may not want to reassemble DATA frames */
    if (!should_attempt_to_reassemble_data_frame(reassembly, pinfo, http2_session)) {
        return NULL;
    }

    /* Continue to add fragments, checking if we have any more fragments */
    uint32_t reassembly_id = get_reassembly_id_from_stream(pinfo, http2_session);
    fragment_head *head = NULL;
    if (IS_HTTP2_END_STREAM(flags) && datalen == 0) {
        /* Workaround displaying "[Frame: N (no data)]" for a HTTP2 frame that contains no data but ends the stream */
        head = fragment_end_seq_next(&http2_body_reassembly_table, pinfo, reassembly_id, NULL);
    } else {
        head = fragment_add_seq_next(&http2_body_reassembly_table, tvb, offset, pinfo, reassembly_id, NULL,
                                     datalen, !IS_HTTP2_END_STREAM(flags));
    }

    /* Only call this if its the last DATA frame (END_STREAM) as the check in process_reassembled_data() will
     * incorrectly match for frames that exist in the same packet as the final DATA frame and incorrectly add
     * reassembly information to those dissection trees */
    if (head && IS_HTTP2_END_STREAM(flags)) {
        return http2_process_reassembled_data(tvb, offset, pinfo, "Reassembled body", head,
                                              &http2_body_fragment_items, NULL, http2_tree);
    }

    /* Add frame where reassembly happened. process_reassembled_data() does this automatically if the reassembled
     * packet matches the packet that is calling the function, but makes some incorrect assumptions for multiple
     * fragments contained in the same packet */
    if (head) {
        proto_tree_add_uint(http2_tree, hf_http2_body_reassembled_in, tvb, 0, 0,
                            head->reassembled_in);
    }

    /* Reassembly not complete yet*/
    return NULL;
}

static void
dissect_http2_data_partial_body(tvbuff_t *tvb, packet_info *pinfo, http2_session_t* http2_session, proto_tree *http2_tree, unsigned offset, int length,
                                uint8_t flags)
{
    http2_data_stream_reassembly_info_t *reassembly = get_data_reassembly_info(pinfo, http2_session);

    /* Is the frame part of a body that is going to be reassembled? */
    if(!IS_HTTP2_END_STREAM(flags)) {
        proto_item_append_text(http2_tree, " (partial entity body)");
    }

    /* If we somehow got a transfer-encoded body, display it here */
    if (reassembly->has_transfer_encoded_body) {
        proto_item_append_text(http2_tree, " (transfer-encoded body)");
    }

    /* Is this part of a tunneled connection? */
    http2_stream_info_t *stream_info = get_stream_info(pinfo, http2_session, false);
    if (stream_info->is_stream_http_connect) {
        proto_item_append_text(http2_tree, " (tunneled data)");
    }

    proto_tree_add_item(http2_tree, hf_http2_data_data, tvb, offset, length, ENC_NA);
}

static void
check_reassembly_completion_status(tvbuff_t* tvb, packet_info* pinfo, proto_tree* http2_tree,
    unsigned offset, uint8_t flags, int length, streaming_reassembly_info_t* reassembly_info)
{
    int more_bytes_expected = additional_bytes_expected_to_complete_reassembly(reassembly_info);

    if (IS_HTTP2_END_STREAM(flags) && more_bytes_expected) {
        if (more_bytes_expected == DESEGMENT_ONE_MORE_SEGMENT) {
            proto_tree_add_expert_format(http2_tree, pinfo, &ei_http2_reassembly_error, tvb, offset, length,
                "Reassembling HTTP2 body for subdissector failed, more bytes are missing before END_STREAM.");
        } else {
            proto_tree_add_expert_format(http2_tree, pinfo, &ei_http2_reassembly_error, tvb, offset, length,
                "Reassembling HTTP2 body for subdissector failed, %d bytes are missing before END_STREAM.",
                more_bytes_expected);
        }
    }
}

/* Streaming reassembly of HTTP2 DATA will handle many cases. The most complicated one is:
 *
 * +--------------------------------------------- HTTP2 DATA payload ---------------------------------------------+
 * | Part1: end of a multisegment PDU | Part2: one or more non-fragment PDUs | Part3: begin of a multisegment PDU |
 * +----------------------------------+--------------------------------------+------------------------------------+
 * Note: we use short name 'MSP' for 'Multisegment PDU', and 'NFP' for 'Non-fragment PDU'.
 *
 * In this case, one HTTP2 DATA payload contains:
 *   Part1: At the begin of the DATA, there is the last part of a multisegment PDU.
 *   Part2: The middle part of DATA payload contains one or more non-fragment PDUs.
 *   Part3: At the tail of the DATA, there is the begin of a new multisegment PDU.
 * All of three parts are optional. For example, one DATA could contain only Part1, Part2 or Part3; or contain
 * Part1 and Part2 without Part3; or contain Part1 and Part3 without Part2; or contain Part2 and Part3 without
 * Part1.
 *
 * And another case is the entire DATA is one of middle parts of a multisegment PDU. We call it MoMSP. Following
 * case shows a multisegment PDU composed of Part3 + MoMSP + MoMSP + MoMSP + Part1:
 *
 *                 +-------------------------------- One Multisegment PDU ---------------------------------+
 *                 |                                                                                       |
 * +----- HTTP2 DATA1 -----+   +------------- HTTP2 DATA2 -----------+  +- DATA3 -+  +- DATA4 -+   +- HTTP2 DATA5 -+
 * | Part1 | Part2 | Part3 |   | MoMSP: middle of a multisegment PDU |  |  MoMSP  |  |  MoMSP  |   | Part1 | Part3 |
 * +-------+-------+-------+   +-------------------------------------+  +---------+  +---------+   +---------------+
 *                 |                                                                                       |
 *                 +---------------------------------------------------------------------------------------+
 *
 * Subdissector behave: The pinfo->desegment_len should contain the estimated number of additional bytes required
 * for completing the PDU. and set pinfo->desegment_offset to the offset in the tvbuff at which the dissector will
 * continue processing when next called. Next time the subdissector is called, it will be passed a tvbuff composed
 * of the end of the data from the previous tvbuff together with desegment_len more bytes. If the dissector cannot
 * tell how many more bytes it will need, it should set pinfo->desegment_len to additional bytes required for parsing
 * message head or just DESEGMENT_ONE_MORE_SEGMENT. It will then be called again as soon as more data becomes available.
 * Please refer to comments of the declaration of reassemble_streaming_data_and_call_subdissector() function in
 * 'epan/reassemble.h' for more requirments about subdissectors.
 */
static void
reassemble_http2_data_according_to_subdissector(tvbuff_t* tvb, packet_info* pinfo, http2_session_t* http2_session,
                                                proto_tree* http2_tree, unsigned offset, uint8_t flags, int length)
{
    const char* saved_match_string = pinfo->match_string;
    http2_frame_num_t cur_frame_num = get_http2_frame_num(tvb, pinfo);

    proto_tree_add_bytes_format(http2_tree, hf_http2_data_data, tvb, offset,
        length, NULL, "DATA payload (%u byte%s)", length, plurality(length, "", "s"));

    http2_data_stream_body_info_t* body_info = get_data_stream_body_info(pinfo, http2_session);
    char* content_type = body_info->content_type;
    media_content_info_t metadata_used_for_media_type_handle = {
        MEDIA_CONTAINER_HTTP_OTHERS, body_info->content_type_parameters, NULL, NULL
    };
    streaming_reassembly_info_t* reassembly_info = get_streaming_reassembly_info(pinfo, http2_session);

    dissector_handle_t subdissector_handle = dissector_get_string_handle(streaming_content_type_dissector_table, content_type);
    if (subdissector_handle == NULL) {
        /* We didn't get the content type, possibly because of byte errors.
         * Note that the content type is per direction (as it should be)
         * but reassembly_mode is set the same for *both* directions.
         *
         * We could try to set it to the content type used in the other
         * direction, but among other things, if this is the request,
         * we might be getting here for the first time on the second pass,
         * and reassemble_streaming_data_and_call_subdissector() asserts in
         *
         * Just set it to data for now to avoid an assert from a NULL handle.
         */
        subdissector_handle = data_handle;
    }
    /* XXX - Do we still need to set this? */
    pinfo->match_string = content_type;

    reassemble_streaming_data_and_call_subdissector(
        tvb, pinfo, offset, length, http2_tree, proto_tree_get_parent_tree(http2_tree),
        http2_streaming_reassembly_table, reassembly_info, (uint64_t)cur_frame_num,
        subdissector_handle, proto_tree_get_parent_tree(http2_tree), &metadata_used_for_media_type_handle,
        "HTTP2 body", &http2_body_fragment_items, hf_http2_data_segment);

    pinfo->match_string = saved_match_string;

    if (IS_HTTP2_END_STREAM(flags)) {
        check_reassembly_completion_status(tvb, pinfo, http2_tree, offset, flags, length, reassembly_info);
    }
}

static void
dissect_http2_data_body(tvbuff_t *tvb, packet_info *pinfo, http2_session_t* h2session, proto_tree *http2_tree, unsigned offset, uint8_t flags, int length)
{
    try_init_stream_with_fake_headers(tvb, pinfo, h2session, http2_tree, offset);

    http2_stream_info_t *stream_info = get_stream_info(pinfo, h2session, false);
    if (stream_info->reassembly_mode == HTTP2_DATA_REASSEMBLY_MODE_STREAMING) {
        reassemble_http2_data_according_to_subdissector(tvb, pinfo, h2session, http2_tree, offset, flags, length);
        return;
    }

    tvbuff_t *data_tvb = reassemble_http2_data_into_full_frame(tvb, pinfo, h2session, http2_tree, offset, flags, length);

    if (data_tvb != NULL) {
        dissect_http2_data_full_body(data_tvb, pinfo, h2session, http2_tree);
    } else {
        dissect_http2_data_partial_body(tvb, pinfo, h2session, http2_tree, offset, length, flags);
    }
}

/* Get real header value from current or the other direction stream_header_list */
static const char*
get_real_header_value(packet_info* pinfo, const char* name, bool the_other_direction)
{
    http2_header_stream_info_t* header_stream_info;
    wmem_list_frame_t* frame;
    wmem_array_t* headers;
    unsigned i;
    uint32_t name_len;
    uint32_t value_len;
    http2_header_t *hdr;
    char* data;

    conversation_t* conversation = find_or_create_conversation(pinfo);
    header_stream_info = get_header_stream_info(pinfo, get_http2_session(pinfo, conversation), the_other_direction);
    if (!header_stream_info) {
        return NULL;
    }

    for (frame = wmem_list_head(header_stream_info->stream_header_list);
        frame;
        frame = wmem_list_frame_next(frame))
    {   /* each frame contains one HEADERS or CONTINUATION frame's headers */
        headers = (wmem_array_t*)wmem_list_frame_data(frame);
        if (!headers) {
            continue;
        }

        for (i = 0; i < wmem_array_get_count(headers); ++i) {
            hdr = (http2_header_t*)wmem_array_index(headers, i);
            if (hdr->type == HTTP2_HD_HEADER_TABLE_SIZE_UPDATE) {
                continue;
            }

            /* parsing data as format:
                   name length (uint32)
                   name (string)
                   value length (uint32)
                   value (string)
            */
            data = (char*) hdr->table.data.data;
            name_len = pntoh32(data);
            if (strlen(name) == name_len && strncmp(data + 4, name, name_len) == 0) {
                value_len = pntoh32(data + 4 + name_len);
                if (4 + name_len + 4 + value_len == hdr->table.data.datalen) {
                    /* return value */
                    return get_ascii_string(pinfo->pool, data + 4 + name_len + 4, value_len);
                }
                else {
                    return NULL; /* unexpected error */
                }
            }
        }
    }

    return NULL;
}

/* Get header value from current or the other direction stream_header_list */
const char*
http2_get_header_value(packet_info *pinfo, const char* name, bool the_other_direction)
{
    bool override = false;
    const char* real_value = get_real_header_value(pinfo, name, the_other_direction);
    const char* fake_value = get_fake_header_value(pinfo, name, the_other_direction, &override);
    if (real_value && override == false) {
        return real_value;
    } else if (fake_value) {
        return fake_value;
    }
    return NULL;
}
#else
static void
dissect_http2_data_body(tvbuff_t *tvb, packet_info *pinfo _U_, http2_session_t* http2_session _U_, proto_tree *http2_tree, unsigned offset, uint8_t flags _U_, int datalen)
{
    proto_tree_add_item(http2_tree, hf_http2_data_data, tvb, offset, datalen, ENC_NA);
}

const char*
http2_get_header_value(packet_info *pinfo _U_, const char* name _U_, bool the_other_direction _U_)
{
    return NULL;
}
#endif

/* Increment or decrement the accumulated connection and/or stream window
 * sizes based on the flow direction, stream ID and increaseWindow parameter.
 * In other words, if increaseWindow is true, then we're processing a
 * WINDOW_UPDATE frame; otherwise, we're processing a DATA frame.
 */
static void
adjust_window_size(tvbuff_t *tvb, packet_info *pinfo, http2_session_t* http2_session, proto_tree *http2_tree, int32_t adjustment, bool increaseWindow)
{
    uint32_t flow_index = select_http2_flow_index(pinfo, http2_session);
    int32_t finalAdjustment = ((increaseWindow ? 1 : -1) * adjustment);

    if (increaseWindow) {
        /* The WINDOW_UPDATE comes in for the other direction */
        flow_index ^= 1;
    }

    /* Always decrease the connection window after sending data,
     * but only increase the connection window for a WINDOW_UPDATE on stream 0 (the connection). */
    if (!increaseWindow || http2_session->current_stream_id == 0) {
        int32_t* window_size_connection_before = p_get_proto_data(wmem_file_scope(), pinfo, proto_http2, PROTO_DATA_KEY_WINDOW_SIZE_CONNECTION_BEFORE);
        int32_t window_size_connection_after;

        if (!window_size_connection_before) {
            /* There may be multiple passes, so we must use proto_data to keep state */
            window_size_connection_before = wmem_new0(wmem_file_scope(), int32_t);
            (*window_size_connection_before) = http2_session->current_connection_window_size[flow_index];
            http2_session->current_connection_window_size[flow_index] += finalAdjustment;
            p_add_proto_data(wmem_file_scope(), pinfo, proto_http2, PROTO_DATA_KEY_WINDOW_SIZE_CONNECTION_BEFORE, window_size_connection_before);
        }

        proto_item_set_generated(proto_tree_add_int(http2_tree, hf_http2_calculated_window_size_connection_before,
                                                    tvb, 0, 0, (*window_size_connection_before)));

        window_size_connection_after = (*window_size_connection_before) + finalAdjustment;

        proto_item_set_generated(proto_tree_add_int(http2_tree, hf_http2_calculated_window_size_connection_after,
                                                    tvb, 0, 0, window_size_connection_after));
    }

#ifdef HAVE_NGHTTP2
    /* Always decrease the stream window after sending data,
     * but only increase the stream window for a WINDOW_UPDATE on stream > 0 (not the connection). */
    if (!increaseWindow || http2_session->current_stream_id > 0) {
        http2_stream_info_t *http2_stream_info = get_stream_info(pinfo, http2_session, increaseWindow);
        int32_t* window_size_stream_before = p_get_proto_data(wmem_file_scope(), pinfo, proto_http2, PROTO_DATA_KEY_WINDOW_SIZE_STREAM_BEFORE);
        int32_t window_size_stream_after;

        if (!window_size_stream_before) {
            /* There may be multiple passes, so we must use proto_data to keep state */
            window_size_stream_before = wmem_new0(wmem_file_scope(), int32_t);
            (*window_size_stream_before) = http2_stream_info->oneway_stream_info[flow_index].current_window_size;
            http2_stream_info->oneway_stream_info[flow_index].current_window_size += finalAdjustment;
            p_add_proto_data(wmem_file_scope(), pinfo, proto_http2, PROTO_DATA_KEY_WINDOW_SIZE_STREAM_BEFORE, window_size_stream_before);
        }

        proto_item_set_generated(proto_tree_add_int(http2_tree, hf_http2_calculated_window_size_stream_before, tvb, 0, 0,
                                                    (*window_size_stream_before)));

        window_size_stream_after = (*window_size_stream_before) + finalAdjustment;

        proto_item_set_generated(proto_tree_add_int(http2_tree, hf_http2_calculated_window_size_stream_after, tvb, 0, 0,
                                                    window_size_stream_after));
    }
#endif
}

/* Data (0) */
static int
dissect_http2_data(tvbuff_t *tvb, packet_info *pinfo, http2_session_t* http2_session, proto_tree *http2_tree,
                   unsigned offset, uint8_t flags)
{
    uint16_t padding;
    int datalen;

    offset = dissect_frame_padding(tvb, &padding, http2_tree, offset, flags);
    datalen = tvb_reported_length_remaining(tvb, offset) - padding;

    dissect_http2_data_body(tvb, pinfo, http2_session, http2_tree, offset, flags, datalen);

    offset += datalen;

    if (padding) {
        proto_tree_add_item(http2_tree, hf_http2_data_padding, tvb, offset, padding, ENC_NA);
        offset += padding;
    }

    adjust_window_size(tvb, pinfo, http2_session, http2_tree, (int32_t)datalen, false);

    return offset;
}

/* Headers */
static int
#ifdef HAVE_NGHTTP2
dissect_http2_headers(tvbuff_t *tvb, packet_info *pinfo, http2_session_t* h2session, proto_tree *http2_tree,
                      unsigned offset, uint8_t flags)
#else
dissect_http2_headers(tvbuff_t *tvb, packet_info *pinfo, http2_session_t* h2session _U_, proto_tree *http2_tree,
                      unsigned offset, uint8_t flags)
#endif
{
    uint16_t padding;
    int headlen;
#ifdef HAVE_NGHTTP2
    fragment_head *head;
    http2_stream_info_t *info;
    streaming_reassembly_info_t *reassembly_info;

    /* Trailing headers coming after a DATA stream should have END_STREAM set. DATA should be complete
     * so try to reassemble DATA fragments if that is the case */
    if(IS_HTTP2_END_STREAM(flags)) {
        info = get_stream_info(pinfo, h2session, false);
        switch (info->reassembly_mode) {
        case HTTP2_DATA_REASSEMBLY_MODE_END_STREAM:
            head = fragment_end_seq_next(&http2_body_reassembly_table, pinfo, get_reassembly_id_from_stream(pinfo, h2session), NULL);
            if(head) {
                tvbuff_t *reassembled_data = process_reassembled_data(tvb, 0, pinfo, "Reassembled body", head,
                                                                      &http2_body_fragment_items, NULL, http2_tree);
                dissect_http2_data_full_body(reassembled_data, pinfo, h2session, http2_tree);
            }
            break;

        case HTTP2_DATA_REASSEMBLY_MODE_STREAMING:
            reassembly_info = get_streaming_reassembly_info(pinfo, h2session);
            check_reassembly_completion_status(tvb, pinfo, http2_tree, offset, flags, tvb_reported_length(tvb), reassembly_info);
            break;

        default:
            /* do nothing */
            break;
        }
    }

    /* Mark this frame as the first header frame seen and last if the END_HEADERS flag
     * is set. We use this to ensure when we read header values, we are not reading ones
     * that have come from a PUSH_PROMISE header (and associated CONTINUATION frames) */
    if (!PINFO_FD_VISITED(pinfo)) {
        http2_header_stream_info_t *header_stream_info = get_header_stream_info(pinfo, h2session, false);
        header_stream_info->header_start_in = get_http2_frame_num(tvb, pinfo);
        if (flags & HTTP2_FLAGS_END_HEADERS) {
            header_stream_info->header_end_in = get_http2_frame_num(tvb, pinfo);
        } else {
            header_stream_info->header_end_in = 0;
        }
        header_stream_info->stream_id = h2session->current_stream_id;
    }
#endif

    offset = dissect_frame_padding(tvb, &padding, http2_tree, offset, flags);
    offset = dissect_frame_prio(tvb, http2_tree, offset, flags);

    headlen = tvb_reported_length_remaining(tvb, offset);
    if (headlen < padding) {
        /* XXX - what error *should* be reported here? */
        THROW(ReportedBoundsError);
    }
    headlen -= padding;
    proto_tree_add_item(http2_tree, hf_http2_headers, tvb, offset, headlen, ENC_NA);

#ifdef HAVE_NGHTTP2
    /* decompress the header block */
    inflate_http2_header_block(tvb, pinfo, offset, http2_tree, headlen, h2session, flags);
    http2_stream_info_t *stream_info = get_stream_info(pinfo, h2session, false);

    /* Display request/response links */
    if (pinfo->num > stream_info->request_in_frame_num && stream_info->request_in_frame_num > 0) {
        /* Response frame */
        if (! nstime_is_unset(&(stream_info->request_ts))) {
            nstime_t delta;

            nstime_delta(&delta, &pinfo->abs_ts, &(stream_info->request_ts));
            proto_item_set_generated(proto_tree_add_time(http2_tree, hf_http2_time, tvb, 0, 0, &delta));
        }
        proto_item_set_generated(proto_tree_add_uint(http2_tree, hf_http2_request_in, tvb, 0, 0, stream_info->request_in_frame_num));
    }
    if (pinfo->num == stream_info->request_in_frame_num && stream_info->response_in_frame_num > 0) {
        /* Request frame */
        proto_item_set_generated(proto_tree_add_uint(http2_tree, hf_http2_response_in, tvb, 0, 0, stream_info->response_in_frame_num));
    }

#else
    proto_tree_add_expert_format(http2_tree, pinfo, &ei_http2_header_size, tvb, offset, headlen,
            "Wireshark must be built with nghttp2 for HTTP/2 HEADERS support");
#endif

    offset += headlen;

    if (padding) {
        proto_tree_add_item(http2_tree, hf_http2_headers_padding, tvb, offset, padding, ENC_NA);
        offset += padding;
    }

    return offset;
}

/* Priority */
static int
dissect_http2_priority(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *http2_tree,
                       unsigned offset, uint8_t flags)
{
    /* we pretend the HTTP2_FLAGS_PRIORITY flag is set to share the dissect
       function */
    offset = dissect_frame_prio(tvb, http2_tree, offset,
                                flags | HTTP2_FLAGS_PRIORITY);
    return offset;
}

/* RST Stream */
static int
dissect_http2_rst_stream(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *http2_tree, unsigned offset, uint8_t flags _U_)
{

    proto_tree_add_item(http2_tree, hf_http2_rst_stream_error, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

#ifdef HAVE_NGHTTP2
static void
adjust_existing_window(void *key _U_, void *value, void *userData _U_)
{
    http2_stream_info_t *stream_info = (http2_stream_info_t *)value;
    http2_adjust_window_t *adjustWindow = (http2_adjust_window_t *)userData;
    stream_info->oneway_stream_info[adjustWindow->flow_index].current_window_size += adjustWindow->windowSizeDiff;
}
#endif

/* Settings */
static int
#ifdef HAVE_NGHTTP2
dissect_http2_settings(tvbuff_t* tvb, packet_info* pinfo _U_, http2_session_t* h2session, proto_tree* http2_tree, unsigned offset, uint8_t flags)
#else
dissect_http2_settings(tvbuff_t* tvb, packet_info* pinfo _U_, http2_session_t* h2session _U_, proto_tree* http2_tree, unsigned offset, uint8_t flags _U_)
#endif
{
    uint32_t settingsid;
    proto_item *ti_settings;
    proto_tree *settings_tree;
#ifdef HAVE_NGHTTP2
    uint32_t header_table_size;
    uint32_t min_header_table_size;
    int header_table_size_found;

    header_table_size_found = 0;
    header_table_size = 0;
    min_header_table_size = 0xFFFFFFFFu;
#endif

    while(tvb_reported_length_remaining(tvb, offset) > 0){

        ti_settings = proto_tree_add_item(http2_tree, hf_http2_settings, tvb, offset, 6, ENC_NA);
        settings_tree = proto_item_add_subtree(ti_settings, ett_http2_settings);
        proto_tree_add_item(settings_tree, hf_http2_settings_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
        settingsid = tvb_get_ntohs(tvb, offset);
        proto_item_append_text(ti_settings, " - %s",
                               val_to_str( settingsid, http2_settings_vals, "Unknown (%u)") );
        offset += 2;


        switch(settingsid){
            case HTTP2_SETTINGS_HEADER_TABLE_SIZE:
                proto_tree_add_item(settings_tree, hf_http2_settings_header_table_size, tvb, offset, 4, ENC_BIG_ENDIAN);

#ifdef HAVE_NGHTTP2
                /* We only care the last header table size in SETTINGS */
                header_table_size_found = 1;
                header_table_size = tvb_get_ntohl(tvb, offset);
                if(min_header_table_size > header_table_size) {
                    min_header_table_size = header_table_size;
                }
#endif
            break;
            case HTTP2_SETTINGS_ENABLE_PUSH:
                proto_tree_add_item(settings_tree, hf_http2_settings_enable_push, tvb, offset, 4, ENC_BIG_ENDIAN);
            break;
            case HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
                proto_tree_add_item(settings_tree, hf_http2_settings_max_concurrent_streams, tvb, offset, 4, ENC_BIG_ENDIAN);
            break;
            case HTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
                {
                    uint32_t newInitialWindowSize;

                    proto_tree_add_item_ret_uint(settings_tree, hf_http2_settings_initial_window_size, tvb, offset, 4, ENC_BIG_ENDIAN, &newInitialWindowSize);

                    if (h2session) {
                        uint32_t flow_index = select_http2_flow_index(pinfo, h2session);

                        /* This new initial window size will be applied to
                         * any new future streams going in the other direction.
                         * Note that this setting does not apply to the connection:
                         * https://lists.w3.org/Archives/Public/ietf-http-wg/2023JanMar/0003.html
                         */
                        flow_index ^= 1;

                        h2session->initial_new_stream_window_size[flow_index] = newInitialWindowSize;

#ifdef HAVE_NGHTTP2
                        {
                            uint32_t previousInitialWindowSize = h2session->initial_new_stream_window_size[flow_index];
                            int32_t windowSizeDiff = newInitialWindowSize - previousInitialWindowSize;

                            /* "When the value of SETTINGS_INITIAL_WINDOW_SIZE changes,
                            *  a receiver MUST adjust the size of all stream flow-control
                            *  windows that it maintains by the difference between the
                            *  new value and the old value."
                            * https://www.ietf.org/rfc/rfc9113.html#section-6.9.2-3
                            */
                            if (windowSizeDiff != 0) {
                                http2_adjust_window_t userData;

                                userData.windowSizeDiff = windowSizeDiff;
                                userData.flow_index = flow_index;

                                wmem_map_foreach(h2session->per_stream_info, adjust_existing_window, &userData);
                            }
                        }
#endif
                    }
                }
            break;
            case HTTP2_SETTINGS_MAX_FRAME_SIZE:
                proto_tree_add_item(settings_tree, hf_http2_settings_max_frame_size, tvb, offset, 4, ENC_BIG_ENDIAN);
            break;
            case HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
                proto_tree_add_item(settings_tree, hf_http2_settings_max_header_list_size, tvb, offset, 4, ENC_BIG_ENDIAN);
            break;
            case HTTP2_SETTINGS_EXTENDED_CONNECT:
                proto_tree_add_item(settings_tree, hf_http2_settings_extended_connect, tvb, offset, 4, ENC_BIG_ENDIAN);
            break;
            case HTTP2_SETTINGS_NO_RFC7540_PRIORITIES:
                proto_tree_add_item(settings_tree, hf_http2_settings_no_rfc7540_priorities, tvb, offset, 4, ENC_BIG_ENDIAN);
            break;
            default:
                proto_tree_add_item(settings_tree, hf_http2_settings_unknown, tvb, offset, 4, ENC_BIG_ENDIAN);
            break;
        }
        proto_item_append_text(ti_settings, " : %u", tvb_get_ntohl(tvb, offset));
        offset += 4;
    }

#ifdef HAVE_NGHTTP2
    if(!PINFO_FD_VISITED(pinfo)&&(h2session != NULL)) {

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
#endif

    return offset;
}

void
dissect_http2_settings_ext(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* http2_tree, unsigned offset) {
    dissect_http2_settings(tvb, pinfo, NULL, http2_tree, offset, 0);
}

/* Push Promise */
static int
#ifdef HAVE_NGHTTP2
dissect_http2_push_promise(tvbuff_t *tvb, packet_info *pinfo _U_, http2_session_t* h2session, proto_tree *http2_tree,
                           unsigned offset, uint8_t flags _U_)
#else
dissect_http2_push_promise(tvbuff_t *tvb, packet_info *pinfo _U_, http2_session_t* h2session _U_, proto_tree *http2_tree,
                           unsigned offset, uint8_t flags _U_)
#endif
{
    uint16_t padding;
    int headlen;
    uint32_t promised_stream_id;

    offset = dissect_frame_padding(tvb, &padding, http2_tree, offset, flags);

    proto_tree_add_item(http2_tree, hf_http2_push_promise_r, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(http2_tree, hf_http2_push_promise_promised_stream_id, tvb,
                        offset, 4, ENC_BIG_ENDIAN, &promised_stream_id);
#ifdef HAVE_NGHTTP2
    if (!PINFO_FD_VISITED(pinfo)) {
        http2_header_stream_info_t *header_stream_info = get_header_stream_info(pinfo, h2session, false);
        header_stream_info->header_start_in = get_http2_frame_num(tvb, pinfo);
        if (flags & HTTP2_FLAGS_END_HEADERS) {
            header_stream_info->header_end_in = get_http2_frame_num(tvb, pinfo);
        } else {
            header_stream_info->header_end_in = 0;
        }
        header_stream_info->stream_id = promised_stream_id;
    }
#endif
    offset += 4;

    headlen = tvb_reported_length_remaining(tvb, offset);
    if (headlen < padding) {
        /* XXX - what error *should* be reported here? */
        THROW(ReportedBoundsError);
    }
    headlen -= padding;
    proto_tree_add_item(http2_tree, hf_http2_push_promise_header, tvb, offset, headlen,
                        ENC_NA);

#ifdef HAVE_NGHTTP2
    inflate_http2_header_block(tvb, pinfo, offset, http2_tree, headlen, h2session, flags);

    /* Display request/response links */
    /* For PUSH_PROMISE, the response is on the promised stream ID. The
     * response is also in the same direction as the request.
     */
    http2_stream_info_t *stream_info = get_stream_info_for_id(pinfo, h2session, false, promised_stream_id);
    if (pinfo->num == stream_info->request_in_frame_num && stream_info->response_in_frame_num > 0) {
        /* Request frame */
        proto_item_set_generated(proto_tree_add_uint(http2_tree, hf_http2_response_in, tvb, 0, 0, stream_info->response_in_frame_num));
    }

#endif

    offset += headlen;

    if (padding) {
        proto_tree_add_item(http2_tree, hf_http2_push_promise_padding, tvb,
                            offset, padding, ENC_NA);
    }

    offset +=  tvb_reported_length_remaining(tvb, offset);

    return offset;
}

/* Ping */
static int
dissect_http2_ping(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *http2_tree,
                   unsigned offset, uint8_t flags)
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
dissect_http2_goaway(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *http2_tree, unsigned offset, uint8_t flags _U_)
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
dissect_http2_window_update(tvbuff_t *tvb, packet_info *pinfo _U_, http2_session_t* http2_session, proto_tree *http2_tree, unsigned offset, uint8_t flags _U_)
{
    int32_t wsi;

    proto_tree_add_item(http2_tree, hf_http2_window_update_r, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(http2_tree, hf_http2_window_update_window_size_increment, tvb, offset, 4, ENC_BIG_ENDIAN, &wsi);
    offset += 4;

    adjust_window_size(tvb, pinfo, http2_session, http2_tree, wsi, true);

    return offset;
}

static int
#ifdef HAVE_NGHTTP2
dissect_http2_continuation(tvbuff_t *tvb, packet_info *pinfo _U_, http2_session_t* h2session, proto_tree *http2_tree, unsigned offset, uint8_t flags)
#else
dissect_http2_continuation(tvbuff_t *tvb, packet_info *pinfo _U_, http2_session_t* h2session _U_, proto_tree *http2_tree, unsigned offset, uint8_t flags)
#endif
{
    uint16_t padding;
    int headlen;
#ifdef HAVE_NGHTTP2
    /* Mark this as the last CONTINUATION frame for a HEADERS frame. This is used to know the context when we read
     * header (is the source a HEADER frame or a PUSH_PROMISE frame?) */
    if (!PINFO_FD_VISITED(pinfo) && flags & HTTP2_FLAGS_END_HEADERS) {
        http2_header_stream_info_t *stream_info = get_header_stream_info(pinfo, h2session, false);
        if (stream_info->header_start_in != 0 && stream_info->header_end_in == 0) {
            stream_info->header_end_in = get_http2_frame_num(tvb, pinfo);
        }
    }

#endif

    offset = dissect_frame_padding(tvb, &padding, http2_tree, offset, flags);

    headlen = tvb_reported_length_remaining(tvb, offset);
    if (headlen < padding) {
        /* XXX - what error *should* be reported here? */
        THROW(ReportedBoundsError);
    }
    headlen -= padding;
    proto_tree_add_item(http2_tree, hf_http2_continuation_header, tvb, offset, headlen, ENC_NA);

#ifdef HAVE_NGHTTP2
    inflate_http2_header_block(tvb, pinfo, offset, http2_tree, headlen, h2session, flags);
#endif

    offset +=  headlen;

    if (padding) {
        proto_tree_add_item(http2_tree, hf_http2_continuation_padding, tvb, offset, padding, ENC_NA);
        offset += padding;
    }

    return offset;
}


/* Altsvc */
static int
dissect_http2_altsvc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *http2_tree,
                     unsigned offset, uint8_t flags _U_, uint16_t length)
{
    uint32_t origin_len;
    int remain = length;

    proto_tree_add_item_ret_uint(http2_tree, hf_http2_altsvc_origin_len, tvb, offset, 2, ENC_BIG_ENDIAN, &origin_len);
    offset += 2;
    remain -= 2;

    proto_tree_add_item(http2_tree, hf_http2_altsvc_origin, tvb, offset, origin_len, ENC_ASCII);
    offset += origin_len;
    remain -= origin_len;

    if(remain) {
        proto_tree_add_item(http2_tree, hf_http2_altsvc_field_value, tvb, offset, remain, ENC_ASCII);
        offset += remain;
    }

    return offset;
}

/* Origin */
static int
dissect_http2_origin(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *http2_tree,
                     unsigned offset, uint8_t flags _U_)
{
    uint32_t origin_len;

    proto_item *ti_origin_entry;
    proto_tree *origin_entry_tree;

    while(tvb_reported_length_remaining(tvb, offset) > 0){

        ti_origin_entry = proto_tree_add_item(http2_tree, hf_http2_origin, tvb, offset, 6, ENC_NA);
        origin_entry_tree = proto_item_add_subtree(ti_origin_entry, ett_http2_origin);

        proto_tree_add_item_ret_uint(origin_entry_tree, hf_http2_origin_origin_len, tvb, offset, 2, ENC_BIG_ENDIAN, &origin_len);
        offset += 2;

        proto_tree_add_item(origin_entry_tree, hf_http2_origin_origin, tvb, offset, origin_len, ENC_ASCII);
        offset += origin_len;
    }

    return offset;
}

/* Priority Update */
static int
dissect_http2_priority_update(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *http2_tree,
                              unsigned offset, uint8_t flags _U_, uint16_t length)
{
    int remain = length;

    proto_tree_add_item(http2_tree, hf_http2_priority_update_stream_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    remain -= 4;

    proto_tree_add_item(http2_tree, hf_http2_priority_update_field_value, tvb, offset, remain, ENC_ASCII);
    offset += remain;

    return offset;
}


int
dissect_http2_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_ )
{
    proto_item *ti;
    proto_tree *http2_tree;
    unsigned offset = 0;
    uint8_t type, flags;
    uint16_t length;
    uint32_t streamid;
    struct HTTP2Tap *http2_stats;
    GHashTable* entry;
    struct tcp_analysis* tcpd;
    conversation_t* conversation = find_or_create_conversation(pinfo);
    bool use_follow_tap = true;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HTTP2");

    ti = proto_tree_add_item(tree, proto_http2, tvb, 0, -1, ENC_NA);

    http2_tree = proto_item_add_subtree(ti, ett_http2);

    if(!p_get_proto_data(wmem_file_scope(), pinfo, proto_http2, PROTO_DATA_KEY_HEADER)) {
        http2_header_data_t *header_data;

        header_data = wmem_new0(wmem_file_scope(), http2_header_data_t);
        header_data->header_list = wmem_list_new(wmem_file_scope());

        p_add_proto_data(wmem_file_scope(), pinfo, proto_http2, PROTO_DATA_KEY_HEADER, header_data);
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
    ti = proto_tree_add_item(http2_tree, hf_http2_stream, tvb, 0, -1, ENC_NA);

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

        proto_tree_add_item(http2_tree, hf_http2_magic, tvb, offset, MAGIC_FRAME_LENGTH, ENC_ASCII);

        return MAGIC_FRAME_LENGTH;
    }

    proto_tree_add_item(http2_tree, hf_http2_length, tvb, offset, 3, ENC_BIG_ENDIAN);
    length = tvb_get_ntoh24(tvb, offset);
    offset += 3;

    proto_tree_add_item(http2_tree, hf_http2_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    type = tvb_get_uint8(tvb, offset);

    int type_idx;
    const char *type_str = try_val_to_str_idx(type, http2_type_vals, &type_idx);
    if (type_str == NULL) {
        type_str = wmem_strdup_printf(pinfo->pool, "Unknown type (%d)", type);
    }

    offset += 1;

    flags = dissect_http2_header_flags(tvb, pinfo, http2_tree, offset, type);
    offset += 1;

    proto_tree_add_item(http2_tree, hf_http2_r, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(http2_tree, hf_http2_streamid, tvb, offset, 4, ENC_BIG_ENDIAN);
    streamid = tvb_get_ntohl(tvb, offset) & MASK_HTTP2_STREAMID;
    proto_item_append_text(ti, ": %s, Stream ID: %u, Length %u", type_str, streamid, length);
    offset += 4;

    /* append stream id after frame type on info column, like: HEADERS[1], DATA[1], HEADERS[3], DATA[3] */
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%s[%u]", type_str, streamid);

    /* fill hash table with stream ids and skip all unknown frames */
    tcpd = get_tcp_conversation_data(conversation, pinfo);
    if (tcpd != NULL && type_idx != -1) {
        entry = (GHashTable*)g_hash_table_lookup(streamid_hash, GUINT_TO_POINTER(tcpd->stream));
        if (entry == NULL) {
            entry = g_hash_table_new(NULL, NULL);
            g_hash_table_insert(streamid_hash, GUINT_TO_POINTER(tcpd->stream), entry);
        }

        g_hash_table_add(entry, GUINT_TO_POINTER(streamid));
    }

    /* Mark the current stream, used for per-stream processing later in the dissection */
    http2_session_t *http2_session = get_http2_session(pinfo, conversation);
    http2_session->current_stream_id = streamid;

    /* Collect stats */
    http2_stats = wmem_new0(pinfo->pool, struct HTTP2Tap);
    http2_stats->type = type;

    switch(type){
        case HTTP2_DATA: /* Data (0) */
            dissect_http2_data(tvb, pinfo, http2_session, http2_tree, offset, flags);
#ifdef HAVE_NGHTTP2
            use_follow_tap = false;
#endif
        break;

        case HTTP2_HEADERS: /* Headers (1) */
            dissect_http2_headers(tvb, pinfo, http2_session, http2_tree, offset, flags);
#ifdef HAVE_NGHTTP2
            use_follow_tap = false;
#endif
        break;

        case HTTP2_PRIORITY: /* Priority (2) */
            dissect_http2_priority(tvb, pinfo, http2_tree, offset, flags);
        break;

        case HTTP2_RST_STREAM: /* RST Stream (3) */
            dissect_http2_rst_stream(tvb, pinfo, http2_tree, offset, flags);
        break;

        case HTTP2_SETTINGS: /* Settings (4) */
            dissect_http2_settings(tvb, pinfo, http2_session, http2_tree, offset, flags);
        break;

        case HTTP2_PUSH_PROMISE: /* PUSH Promise (5) */
            dissect_http2_push_promise(tvb, pinfo, http2_session, http2_tree, offset, flags);
#ifdef HAVE_NGHTTP2
            use_follow_tap = false;
#endif
        break;

        case HTTP2_PING: /* Ping (6) */
            dissect_http2_ping(tvb, pinfo, http2_tree, offset, flags);
        break;

        case HTTP2_GOAWAY: /* Goaway (7) */
            dissect_http2_goaway(tvb, pinfo, http2_tree, offset, flags);
        break;

        case HTTP2_WINDOW_UPDATE: /* Window Update (8) */
            dissect_http2_window_update(tvb, pinfo, http2_session, http2_tree, offset, flags);
        break;

        case HTTP2_CONTINUATION: /* Continuation (9) */
            dissect_http2_continuation(tvb, pinfo, http2_session, http2_tree, offset, flags);
#ifdef HAVE_NGHTTP2
            use_follow_tap = false;
#endif
        break;

        case HTTP2_ALTSVC: /* ALTSVC (10) */
            dissect_http2_altsvc(tvb, pinfo, http2_tree, offset, flags, length);
        break;

        case HTTP2_BLOCKED: /* BLOCKED (11) */
            /* no payload! */
        break;

        case HTTP2_ORIGIN: /* ORIGIN (12) */
            dissect_http2_origin(tvb, pinfo, http2_tree, offset, flags);
        break;

        case HTTP2_PRIORITY_UPDATE: /* Priority Update (16) */
            dissect_http2_priority_update(tvb, pinfo, http2_tree, offset, flags, length);
        break;

        default:
            proto_tree_add_item(http2_tree, hf_http2_unknown, tvb, offset, -1, ENC_NA);
        break;
    }
    tap_queue_packet(http2_tap, pinfo, http2_stats);

    /* HEADERS, CONTINUATION, and PUSH_PROMISE frames are compressed,
     * and sent to the follow tap inside inflate_http2_header_block.
     */
    if (have_tap_listener(http2_follow_tap) && use_follow_tap) {
        http2_follow_tap_data_t *follow_data = wmem_new0(pinfo->pool, http2_follow_tap_data_t);

        follow_data->tvb = tvb;
        follow_data->stream_id = streamid;

        tap_queue_packet(http2_follow_tap, pinfo, follow_data);
    }

    return tvb_captured_length(tvb);
}

static unsigned get_http2_message_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                                   int offset, void *data _U_)
{
        if ( tvb_memeql( tvb, offset, kMagicHello, MAGIC_FRAME_LENGTH ) == 0 ) {
                return MAGIC_FRAME_LENGTH;
        }

        return (unsigned)tvb_get_ntoh24(tvb, offset) + FRAME_HEADER_LENGTH;
}


static int
dissect_http2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
              void *data)
{
    /* XXX: Should tcp_dissect_pdus() set a fence after each PDU?
     * If so the col_clear could be moved inside dissect_http2_pdu.
     */
    col_clear(pinfo->cinfo, COL_INFO);

    tcp_dissect_pdus(tvb, pinfo, tree, true, FRAME_HEADER_LENGTH,
                     get_http2_message_len, dissect_http2_pdu, data);

    return tvb_captured_length(tvb);
}

static bool
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
      return true;
    }

    if (tvb_memeql(tvb, 0, kMagicHello, MAGIC_FRAME_LENGTH) != 0) {
        /* we couldn't find the Magic Hello (PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n). */
        return false;
    }

    /* Remember http2 conversation. */
    get_http2_session(pinfo, conversation);
    dissect_http2(tvb, pinfo, tree, data);

    return true;
}

static bool
dissect_http2_heur_ssl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    struct tlsinfo *tlsinfo = (struct tlsinfo *) data;
    if (dissect_http2_heur(tvb, pinfo, tree, NULL)) {
        *(tlsinfo->app_handle) = http2_handle;
        return true;
    }
    return false;
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
        { &hf_http2_data_segment,
          { "DATA segment", "http2.data.segment",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "A data segment used in reassembly", HFILL}
        },
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
        /* Body fragments */
        { &hf_http2_body_fragments,
            { "Body fragments", "http2.body.fragments",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http2_body_fragment,
            { "Body fragment", "http2.body.fragment",
              FT_FRAMENUM, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http2_body_fragment_overlap,
            { "Body fragment overlap", "http2.body.fragment.overlap",
              FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http2_body_fragment_overlap_conflicts,
            { "Body fragment overlapping with conflicting data", "http2.body.fragment.overlap.conflicts",
              FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http2_body_fragment_multiple_tails,
            { "Body has multiple tail fragments", "http2.body.fragment.multiple_tails",
              FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http2_body_fragment_too_long_fragment,
            { "Body fragment too long", "http2.body.fragment.too_long_fragment",
              FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http2_body_fragment_error,
            { "Body defragment error", "http2.body.fragment.error",
              FT_FRAMENUM, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http2_body_fragment_count,
            { "Body fragment count", "http2.body.fragment.count",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http2_body_reassembled_in,
            { "Reassembled body in frame", "http2.body.reassembled.in",
              FT_FRAMENUM, BASE_NONE, NULL, 0x0,
              "Reassembled body in frame number", HFILL }
        },
        { &hf_http2_body_reassembled_length,
            { "Reassembled body length", "http2.body.reassembled.length",
               FT_UINT32, BASE_DEC, NULL, 0x0,
              "Reassembled body in frame number", HFILL }
        },
        { &hf_http2_body_reassembled_data,
            { "Reassembled body data", "http2.body.reassembled.data",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              "Reassembled body data for multisegment PDU spanning across DATAs", HFILL }
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
        { &hf_http2_header_unescaped,
            { "Unescaped", "http2.header.unescaped",
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
        { &hf_http2_fake_header_count,
            { "Fake Header Count", "http2.fake.header.count",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_http2_fake_header,
            { "Fake Header", "http2.fake.header",
               FT_NONE, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_http2_header_request_full_uri,
            { "Full request URI", "http2.request.full_uri",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "The full requested URI (including host name)", HFILL }
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
            { "Initial Window Size", "http2.settings.initial_window_size",
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
        { &hf_http2_settings_extended_connect,
            { "Extended CONNECT", "http2.settings.extended_connect",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              "Indicates support for the extended CONNECT method extension defined RFC 8441.", HFILL }
        },
        { &hf_http2_settings_no_rfc7540_priorities,
            { "No RFC7540 Priorities", "http2.settings.no_rfc7540_priorities",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
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
            { "Header Block Fragment", "http2.push_promise.header",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              "Containing request header fields", HFILL }
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
            { "Reserved", "http2.goaway.r",
               FT_UINT32, BASE_HEX, NULL, MASK_HTTP2_RESERVED,
              "Must be zero", HFILL }
        },
        { &hf_http2_goaway_last_stream_id,
            { "Last-Stream-ID", "http2.goaway.last_stream_id",
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
            { "Header Block Fragment", "http2.continuation.header",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              "Continues a HEADERS or PUSH_PROMISE field block", HFILL }
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

        /* Origin */
        { &hf_http2_origin,
            { "Origin", "http2.origin",
               FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http2_origin_origin_len,
            { "Origin Length", "http2.origin.origin_len",
               FT_UINT16, BASE_DEC, NULL, 0x0,
              "indicating the length, in octets, of the Origin field.", HFILL }
        },
        { &hf_http2_origin_origin,
            { "Origin", "http2.origin.origin",
               FT_STRING, BASE_NONE, NULL, 0x0,
              "A sequence of characters containing ASCII serialisation of an "
              "origin that server is authoritative for.", HFILL }
        },

        /* Priority Update */
        { &hf_http2_priority_update_stream_id,
            { "Priority Update Stream ID", "http2.priority_update_stream_id",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http2_priority_update_field_value,
            { "Priority Update Field Value", "http2.priority_update_field_value",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http2_time,
          { "Time since request", "http2.time",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0,
            "Time since the request was sent", HFILL }
        },
        { &hf_http2_request_in,
            { "Request in frame", "http2.request_in",
              FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
              "This frame is a response to a HTTP2 request contained in frame with this number", HFILL }
        },
        { &hf_http2_response_in,
            { "Response in frame", "http2.response_in",
              FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
              "This request will be responded in the frame with this number", HFILL }
        },

        /* Calculated */
        { &hf_http2_calculated_window_size_connection_before,
            { "Connection window size (before)", "http2.calculated.connection.window_size.before",
              FT_INT32, BASE_DEC, NULL, 0x0,
              "The sender's current window size (in bytes) for this connection (before sending)", HFILL }
        },
        { &hf_http2_calculated_window_size_connection_after,
            { "Connection window size (after)", "http2.calculated.connection.window_size.after",
              FT_INT32, BASE_DEC, NULL, 0x0,
              "The sender's current window size (in bytes) for this connection (after sending)", HFILL }
        },
        { &hf_http2_calculated_window_size_stream_before,
            { "Stream window size (before)", "http2.calculated.stream.window_size.before",
              FT_INT32, BASE_DEC, NULL, 0x0,
              "The sender's current window size (in bytes) for this stream (before sending)", HFILL }
        },
        { &hf_http2_calculated_window_size_stream_after,
            { "Stream window size (after)", "http2.calculated.stream.window_size.after",
              FT_INT32, BASE_DEC, NULL, 0x0,
              "The sender's current window size (in bytes) for this stream (after sending)", HFILL }
        },
    };

    static int *ett[] = {
        &ett_http2,
        &ett_http2_header,
        &ett_http2_headers,
        &ett_http2_flags,
        &ett_http2_settings,
        &ett_http2_encoded_entity,
        &ett_http2_body_fragment,
        &ett_http2_body_fragments,
        &ett_http2_origin
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
        },
        { &ei_http2_body_decompression_failed,
          { "http2.body_decompression_failed", PI_UNDECODED, PI_WARN,
            "Body decompression failed", EXPFILL }
        },
        { &ei_http2_reassembly_error,
          { "http2.reassembly_error", PI_UNDECODED, PI_WARN,
            "Reassembly failed", EXPFILL }
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

#ifdef HAVE_NGHTTP2
    uat_t* headers_uat;

    static const value_string http2_custom_type_vals[] = {
        { val_string,   "string" },
        { val_uint64,   "unsigned 64-bit integer" },
        { 0x00, NULL }
    };

    static uat_field_t custom_header_uat_fields[] = {
        UAT_FLD_CSTRING(header_fields, header_name, "Header name", "HTTP2 header name"),
        UAT_FLD_VS(header_fields, header_type, "Header type", http2_custom_type_vals, "Field type"),
        UAT_FLD_CSTRING(header_fields, header_desc, "Field desc", "Description of the value contained in the header"),
        UAT_END_FIELDS
    };

    headers_uat = uat_new("Custom HTTP2 Header Fields",
                          sizeof(header_field_t),
                          "custom_http2_header_fields",
                          true,
                          &header_fields,
                          &num_header_fields,
                          /* specifies named fields, so affects dissection
                             and the set of named fields */
                          UAT_AFFECTS_DISSECTION|UAT_AFFECTS_FIELDS,
                          NULL,
                          header_fields_copy_cb,
                          header_fields_update_cb,
                          header_fields_free_cb,
                          header_fields_post_update_cb,
                          header_fields_reset_cb,
                          custom_header_uat_fields
    );

    prefs_register_uat_preference(http2_module, "custom_http2_header_fields", "Custom HTTP2 header fields",
        "A table to define custom HTTP2 header for which fields can be setup and used for filtering/data extraction etc.",
        headers_uat);

    uat_t* fake_headers_uat;

    static uat_field_t http2_fake_header_uat_fields[] = {
        UAT_FLD_RANGE(http2_fake_headers, server_port_range, "Server ports", 0xFFFF,
                      "Server ports providing HTTP2 service"),
        UAT_FLD_DEC(http2_fake_headers, stream_id, "Stream ID",
                    "The HTTP2 Stream ID this rule will apply to. The 0 means applicable to all streams."),
        UAT_FLD_VS(http2_fake_headers, direction, "Direction", http2_direction_type_vals,
                   "This rule applies to the message sent to (IN) or from (OUT) server."),
        UAT_FLD_CSTRING(http2_fake_headers, header_name, "Header name", "HTTP2 header name"),
        UAT_FLD_CSTRING(http2_fake_headers, header_value, "Header value", "HTTP2 header value"),
        UAT_FLD_BOOL(http2_fake_headers, override, "Override", "Override existing header"),
        UAT_FLD_BOOL(http2_fake_headers, enable, "Enable", "Enable this rule"),
        UAT_END_FIELDS
    };

    fake_headers_uat = uat_new("HTTP2 Fake Headers",
        sizeof(http2_fake_header_t),
        "http2_fake_headers",
        true,
        &http2_fake_headers,
        &num_http2_fake_headers,
        UAT_AFFECTS_DISSECTION | UAT_AFFECTS_FIELDS,
        NULL,
        http2_fake_headers_copy_cb,
        http2_fake_headers_update_cb,
        http2_fake_headers_free_cb,
        NULL,
        NULL,
        http2_fake_header_uat_fields
    );

    prefs_register_uat_preference(http2_module, "fake_headers", "HTTP2 Fake Headers",
        "A table to define HTTP2 fake headers for parsing a HTTP2 stream conversation that first HEADERS frame is missing.",
        fake_headers_uat);

    /* Fill hash table with static headers */
    register_static_headers();

    /* Decode As handling */
    static build_valid_func http2_current_stream_values[1] = { http2_current_stream_id_value };
    static decode_as_value_t http2_da_stream_id_values[1] = { {http2_streamid_prompt, 1, http2_current_stream_values} };
    static decode_as_t http2_da_stream_id = { "http2", "http2.streamid", 1, 0, http2_da_stream_id_values, "HTTP2", "Stream ID as",
                                       decode_as_http2_populate_list, decode_as_default_reset, decode_as_default_change, NULL };
    register_decode_as(&http2_da_stream_id);
#endif

    register_init_routine(&http2_init_protocol);
    register_cleanup_routine(&http2_cleanup_protocol);

    http2_handle = register_dissector("http2", dissect_http2, proto_http2);

    reassembly_table_register(&http2_body_reassembly_table,
                              &addresses_ports_reassembly_table_functions);
    reassembly_table_register(&http2_streaming_reassembly_table,
                              &addresses_ports_reassembly_table_functions);

    streaming_content_type_dissector_table =
        register_dissector_table("streaming_content_type",
            "Data Transmitted over HTTP2 in Streaming Mode", proto_http2, FT_STRING, STRING_CASE_SENSITIVE);

    stream_id_content_type_dissector_table =
        register_dissector_table("http2.streamid", "HTTP2 content type in stream", proto_http2, FT_UINT32, BASE_DEC);

    http2_tap = register_tap("http2");
    http2_follow_tap = register_tap("http2_follow");

    register_follow_stream(proto_http2, "http2_follow", http2_follow_conv_filter, http2_follow_index_filter, tcp_follow_address_filter,
                           tcp_port_to_display, follow_http2_tap_listener, get_tcp_stream_count,
                           http2_get_sub_stream_id);
}

static void http2_stats_tree_init(stats_tree* st)
{
    st_node_http2 = stats_tree_create_node(st, st_str_http2, 0, STAT_DT_INT, true);
    st_node_http2_type = stats_tree_create_pivot(st, st_str_http2_type, st_node_http2);

}

static tap_packet_status http2_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_, epan_dissect_t* edt _U_, const void* p, tap_flags_t flags _U_)
{
    const struct HTTP2Tap *pi = (const struct HTTP2Tap *)p;
    tick_stat_node(st, st_str_http2, 0, false);
    stats_tree_tick_pivot(st, st_node_http2_type,
            val_to_str(pi->type, http2_type_vals, "Unknown type (%d)"));

    return TAP_PACKET_REDRAW;
}

void
proto_reg_handoff_http2(void)
{
#ifdef HAVE_NGHTTP2
    media_type_dissector_table = find_dissector_table("media_type");
#endif

    data_handle = find_dissector("data");

    dissector_add_uint_range_with_preference("tcp.port", "", http2_handle);
    dissector_add_for_decode_as("tcp.port", http2_handle);

    /*
     * SSL/TLS Application-Layer Protocol Negotiation (ALPN) protocol ID.
     */
    dissector_add_string("tls.alpn", "h2", http2_handle);
    dissector_add_string("http.upgrade", "h2", http2_handle);
    dissector_add_string("http.upgrade", "h2c", http2_handle);

    heur_dissector_add("tls", dissect_http2_heur_ssl, "HTTP2 over TLS", "http2_tls", proto_http2, HEURISTIC_ENABLE);
    heur_dissector_add("tcp", dissect_http2_heur, "HTTP2 over TCP", "http2_tcp", proto_http2, HEURISTIC_ENABLE);
    heur_dissector_add("http", dissect_http2_heur, "HTTP2 on an HTTP port", "http2_http", proto_http2, HEURISTIC_ENABLE);

    stats_tree_register("http2", "http2", "HTTP2", 0, http2_stats_tree_packet, http2_stats_tree_init, NULL);

#ifdef HAVE_NGHTTP2
    register_eo_t *http_eo = get_eo_by_name("http");
    if (http_eo) {
        http_eo_tap = find_tap_id(get_eo_tap_listener_name(http_eo));
    }
#endif
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
