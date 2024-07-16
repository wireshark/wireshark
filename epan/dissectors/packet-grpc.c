/* packet-grpc.c
 * Routines for GRPC dissection
 * Copyright 2017,2022 Huang Qiangxiong <qiangxiong.huang@qq.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
* The information used comes from:
* https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md
* https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-WEB.md
*
* This GRPC dissector must be invoked by HTTP2 or HTTP dissector.
* The native GRPC is always over HTTP2, the GRPC-Web is over either HTTP2 or HTTP.
*
* The main task of GRPC dissector for native GRPC includes:
*
* 1. Parse grpc message header first, if header shows message is compressed,
*    it will find grpc-encoding http2 header by invoking http2_get_header_value()
*    and uncompress the following message body according to the value of
*    grpc-encoding header. After that grpc dissector call subdissector
*    to dissect the (uncompressed) data of message body.
*
* 2. GRPC dissector will create and maintain a new dissector table named
*    'grpc_message_type'. It allows dissection of a grpc message body.
*    The pattern format used by this table has two levels:
*
*    1) Request/Response level pattern, which includes request
*       grpc-method-path (equals to http2 ':path' header value) and
*       direction (request or response), the format:
*           http2-content-type "," http2-path "," direction
*       direction = "request" / "response",    for example:
*           "application/grpc,/helloworld.Greeter/SayHello,request"
*       The "helloworld.Greeter" is  grpc_package "." grpc_service
*
*    2) Content-type level pattern, which just takes http2-content-type
*       as pattern (for example, "application/grpc",
*       "application/grpc+proto" and "application/grpc+json").
*
*    GRPC dissector will try to call request/response message level
*    subdissector first. If not found, then try content-type level
*    dissectors. grpc dissector will always transmit grpc message
*    information - (http2-content-type "," http2-path "," direction ) to
*    subdissector in (void *data) parameter of dissect handler.
*    Content-type level subdissector can use this information to locate
*    the request/response message type.
*
* For GRPC-WEB, the ways to get information like content-type, path (request uri)
* are different. And for GRPC-WEB-TEXT, the dissector will first decode the base64
* payload and then dissect the data as GRPC-WEB.
*/

#include "config.h"

#include <epan/conversation.h>
#include <epan/proto_data.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/strutil.h>
#include <epan/proto_data.h>
#include "packet-http.h"
#include "packet-http2.h"
#include "packet-media-type.h"

#include "wsutil/pint.h"

#define GRPC_MESSAGE_HEAD_LEN 5

/* calculate the size of a bytes after decoding as base64 */
#define BASE64_ENCODE_SIZE(len)  ((len) / 3 * 4 + ((len) % 3 == 0 ? 0 : 4))

/*
* Decompression of zlib encoded entities.
*/
#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
static bool grpc_decompress_body = true;
#else
static bool grpc_decompress_body;
#endif

/* detect json automatically */
static bool grpc_detect_json_automatically = true;
/* whether embed GRPC messages under HTTP2 (or other) protocol tree items */
static bool grpc_embedded_under_http2;

void proto_register_grpc(void);
void proto_reg_handoff_grpc(void);

static int proto_grpc;
static int proto_http;

/* message header */
static int hf_grpc_frame_type;
static int hf_grpc_compressed_flag;
static int hf_grpc_message_length;
/* message body */
static int hf_grpc_message_data;

/* grpc protocol type */
#define grpc_protocol_type_vals_VALUE_STRING_LIST(XXX)    \
    XXX(GRPC_PTYPE_GRPC, 0, "GRPC")  \
    XXX(GRPC_PTYPE_GRPC_WEB, 1, "GRPC-Web") \
    XXX(GRPC_PTYPE_GRPC_WEB_TEXT, 2, "GRPC-Web-Text")

typedef VALUE_STRING_ENUM(grpc_protocol_type_vals) grpc_protocol_type_t;
VALUE_STRING_ARRAY(grpc_protocol_type_vals);

/* grpc frame type (grpc-web extension) */
#define grpc_frame_type_vals_VALUE_STRING_LIST(XXX)    \
    XXX(GRPC_FRAME_TYPE_DATA, 0, "Data")  \
    XXX(GRPC_FRAME_TYPE_TRAILER, 1, "Trailer")

VALUE_STRING_ENUM(grpc_frame_type_vals);
VALUE_STRING_ARRAY(grpc_frame_type_vals);

/* compressed flag vals */
#define grpc_compressed_flag_vals_VALUE_STRING_LIST(XXX)    \
    XXX(GRPC_NOT_COMPRESSED, 0, "Not Compressed")  \
    XXX(GRPC_COMPRESSED, 1, "Compressed")

VALUE_STRING_ENUM(grpc_compressed_flag_vals);
VALUE_STRING_ARRAY(grpc_compressed_flag_vals);

/* expert */
static expert_field ei_grpc_body_decompression_failed;
static expert_field ei_grpc_body_malformed;

/* trees */
static int ett_grpc;
static int ett_grpc_message;
static int ett_grpc_encoded_entity;

static dissector_handle_t grpc_handle;
static dissector_handle_t grpc_web_handle;
static dissector_handle_t grpc_web_text_handle;
static dissector_handle_t data_text_lines_handle;

/* the information used during dissecting a grpc message */
typedef struct {
    bool is_request; /* is request or response message */
    grpc_protocol_type_t proto_type;
    const char* path; /* is http2 ":path" or http request_uri, format: "/" Service-Name "/" {method name} */
    const char* content_type; /* is http2 or http content-type, like: application/grpc */
    const char* encoding; /* is grpc-encoding header containing compressed method, for example "gzip" */
} grpc_context_info_t;

/* GRPC message type dissector table list.
* Dissectors can register themselves in this table as grpc message data dissectors.
* Dissectors registered in this table may use pattern that
* contains content-type,grpc-method-path(http2_path),request/response info, like:
*     application/grpc,/helloworld.Greeter/SayHello,request
* or just contains content-type:
*     application/grpc
*     application/grpc+proto
*     application/grpc+json
*/
static dissector_table_t grpc_message_type_subdissector_table;

/* Try to dissect grpc message according to grpc message info or http2 content_type. */
static void
dissect_body_data(proto_tree *grpc_tree, packet_info *pinfo, tvbuff_t *tvb, const int offset,
    int length, bool continue_dissect,
    uint32_t frame_type, grpc_context_info_t *grpc_ctx)
{
    const char *http2_content_type = grpc_ctx->content_type;
    char *grpc_message_info;
    tvbuff_t *next_tvb;
    int dissected;
    proto_tree *parent_tree;

    proto_tree_add_bytes_format_value(grpc_tree, hf_grpc_message_data, tvb, offset, length, NULL, "%u bytes", length);

    if (frame_type == GRPC_FRAME_TYPE_TRAILER) {
        call_dissector(data_text_lines_handle, tvb_new_subset_length(tvb, offset, length), pinfo, grpc_tree);
        return;
    }

    if (!continue_dissect) {
        return; /* if uncompress failed, we don't continue dissecting. */
    }

    if (http2_content_type == NULL || grpc_ctx->path == NULL) {
        return; /* not continue if there is not enough grpc information */
    }

    next_tvb = tvb_new_subset_length(tvb, offset, length);

    /* Try to detect body as json first.
    * Current grpc-java version sends json on grpc with content-type = application/grpc
    * insteadof application/grpc+json, so we may detect to dissect message with default
    * content-type application/grpc by json dissector insteadof protobuf dissector.
    */
    if (grpc_detect_json_automatically && length > 3
        && tvb_get_guint8(next_tvb, 0) == '{')  /* start with '{' */
    {
        uint8_t end_bytes[3];
        tvb_memcpy(next_tvb, end_bytes, length - 3, 3);
        if (end_bytes[2] == '}'     /* end with '}' */
            || end_bytes[1] == '}'  /* or "}\n" */
            || end_bytes[0] == '}') /* or "}\n\r" or " }\r\n" */
        {
            /* We just replace content-type with "application/grpc+json" insteadof calling
            JSON dissector directly. Because someone may want to use his own dissector to
            parse json insteadof default json dissector. */
            http2_content_type = "application/grpc+json";
        }
    }

    /* Since message data (like protobuf) may be not a self-describing protocol, we need
    * provide grpc service-name, method-name and request or response type to subdissector.
    * According to these information, subdissector may find correct message definition
    * from IDL file like ".proto".
    *
    * We define a string format to carry these information. The benefit using string is
    * the grpc message information might be used by the other Lua dissector in the future.
    * The grpc message information format is:
    *   http2_content_type "," http2_path "," ("request" / "response")
    * According to grpc wire format guide, it will be:
    *   "application/grpc" [("+proto" / "+json" / {custom})] "," "/" service-name "/" method-name "/" "," ("request" / "response")
    * For example:
    *   application/grpc,/helloworld.Greeter/SayHello,request
    */
    grpc_message_info = wmem_strconcat(pinfo->pool, http2_content_type, ",",
        grpc_ctx->path, ",", (grpc_ctx->is_request ? "request" : "response"), NULL);

    parent_tree = proto_tree_get_parent_tree(grpc_tree);

    /* Protobuf dissector may be implemented that each request or response message
    * of a method is defined as an individual dissector, so we try dissect using
    * grpc_message_info first.
    */
    dissected = dissector_try_string(grpc_message_type_subdissector_table, grpc_message_info,
        next_tvb, pinfo, parent_tree, grpc_message_info);

    if (dissected == 0) {
        /* not dissected yet, we try common subdissector again. */
        dissector_try_string(grpc_message_type_subdissector_table, http2_content_type,
            next_tvb, pinfo, parent_tree, grpc_message_info);
    }
}

static bool
can_uncompress_body(const char *grpc_encoding)
{
    /* check http2 have a grpc-encoding header appropriate */
    return grpc_decompress_body
        && grpc_encoding != NULL
        && (strcmp(grpc_encoding, "gzip") == 0 || strcmp(grpc_encoding, "deflate") == 0);
}

/* Dissect a grpc message. The caller needs to guarantee that the length is equal
to 5 + message_length according to grpc wire format definition. */
static unsigned
dissect_grpc_message(tvbuff_t *tvb, unsigned offset, unsigned length, packet_info *pinfo, proto_tree *grpc_tree,
                     grpc_context_info_t* grpc_ctx)
{
    uint32_t frame_type, compressed_flag, message_length;
    const char *compression_method = grpc_ctx->encoding;

    /* GRPC message format:
    Delimited-Message -> Compressed-Flag Message-Length Message
    Compressed-Flag -> 0 / 1 # encoded as 1 byte unsigned integer
    Message-Length -> {length of Message} # encoded as 4 byte unsigned integer
    Message -> *{binary octet} (may be protobuf or json)

    Note: GRPC-WEB extend the MSB of Compressed-Flag as frame type (0-data, 1-trailer)
    */
    proto_tree_add_item_ret_uint(grpc_tree, hf_grpc_frame_type, tvb, offset, 1, ENC_BIG_ENDIAN, &frame_type);
    proto_tree_add_item_ret_uint(grpc_tree, hf_grpc_compressed_flag, tvb, offset, 1, ENC_BIG_ENDIAN, &compressed_flag);
    offset += 1;

    if (frame_type == GRPC_FRAME_TYPE_TRAILER) {
        proto_item_append_text(proto_tree_get_parent(grpc_tree), " (Trailer)");
    }

    proto_tree_add_item(grpc_tree, hf_grpc_message_length, tvb, offset, 4, ENC_BIG_ENDIAN);
    message_length = length - 5;  /* should be equal to tvb_get_ntohl(tvb, offset) */
    offset += 4;

    if (message_length == 0) {
        return offset;
    }

    /* uncompressed message data if compressed_flag is set */
    if (compressed_flag & GRPC_COMPRESSED) {
        if (can_uncompress_body(compression_method)) {
            proto_item *compressed_proto_item = NULL;
            tvbuff_t *uncompressed_tvb = tvb_child_uncompress_zlib(tvb, tvb, offset, message_length);

            proto_tree *compressed_entity_tree = proto_tree_add_subtree_format(
                grpc_tree, tvb, offset, message_length, ett_grpc_encoded_entity,
                &compressed_proto_item, "Message-encoded entity body (%s): %u bytes",
                compression_method == NULL ? "unknown" : compression_method, message_length
            );

            if (uncompressed_tvb != NULL) {
                unsigned uncompressed_length = tvb_captured_length(uncompressed_tvb);
                add_new_data_source(pinfo, uncompressed_tvb, "Uncompressed entity body");
                proto_item_append_text(compressed_proto_item, " -> %u bytes", uncompressed_length);
                dissect_body_data(grpc_tree, pinfo, uncompressed_tvb, 0, uncompressed_length, true, frame_type, grpc_ctx);
            } else {
                proto_tree_add_expert(compressed_entity_tree, pinfo, &ei_grpc_body_decompression_failed,
                    tvb, offset, message_length);
                dissect_body_data(grpc_tree, pinfo, tvb, offset, message_length, false, frame_type, grpc_ctx);
            }
        } else { /* compressed flag is set, but we can not uncompressed */
            dissect_body_data(grpc_tree, pinfo, tvb, offset, message_length, false, frame_type, grpc_ctx);
        }
    } else {
        dissect_body_data(grpc_tree, pinfo, tvb, offset, message_length, true, frame_type, grpc_ctx);
    }

    return offset + message_length;
}

static int
dissect_grpc_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, grpc_context_info_t *grpc_ctx)
{
    proto_item *ti;
    proto_tree *grpc_tree;
    uint32_t message_length;
    unsigned offset = 0;
    unsigned tvb_len = tvb_reported_length(tvb);
    const char* proto_name;

    DISSECTOR_ASSERT(grpc_ctx != NULL);

    proto_name = val_to_str_const(grpc_ctx->proto_type, grpc_protocol_type_vals, "GRPC");

    if (!grpc_embedded_under_http2 && proto_tree_get_parent_tree(tree)) {
        tree = proto_tree_get_parent_tree(tree);
    }

    /* http2 had reassembled the http2.data.data, so we need not reassemble again.
    reassembled http2.data.data may contain one or more grpc messages. */
    while (offset < tvb_len)
    {
        if (tvb_len - offset < GRPC_MESSAGE_HEAD_LEN) {
            /* need at least 5 bytes for dissecting a grpc message */
            if (pinfo->can_desegment) {
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = GRPC_MESSAGE_HEAD_LEN - (tvb_len - offset);
                return offset;
            }
            proto_tree_add_expert_format(tree, pinfo, &ei_grpc_body_malformed, tvb, offset, -1,
                     "GRPC Malformed message data: only %u bytes left, need at least %u bytes.", tvb_len - offset, GRPC_MESSAGE_HEAD_LEN);
            break;
        }

        message_length = tvb_get_ntohl(tvb, offset + 1);
        if (tvb_len - offset < GRPC_MESSAGE_HEAD_LEN + message_length) {
            /* remaining bytes are not enough for dissecting the message body */
            if (pinfo->can_desegment) {
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = GRPC_MESSAGE_HEAD_LEN + message_length - (tvb_len - offset);
                return offset;
            }
            proto_tree_add_expert_format(tree, pinfo, &ei_grpc_body_malformed, tvb, offset, -1,
                     "GRPC Malformed message data: only %u bytes left, need at least %u bytes.", tvb_len - offset, GRPC_MESSAGE_HEAD_LEN + message_length);
            break;
        }
        /* ready to add information into protocol columns and tree */
        if (offset == 0) { /* change columns only when there is at least one grpc message will be parsed */
            col_set_str(pinfo->cinfo, COL_PROTOCOL, proto_name);
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", proto_name);
            col_set_fence(pinfo->cinfo, COL_PROTOCOL);
        }
        ti = proto_tree_add_item(tree, proto_grpc, tvb, offset, message_length + GRPC_MESSAGE_HEAD_LEN, ENC_NA);
        grpc_tree = proto_item_add_subtree(ti, ett_grpc_message);
        proto_item_set_text(ti, "%s Message", proto_name);

        if (grpc_ctx->path) {
            proto_item_append_text(ti, ": %s, %s", grpc_ctx->path, (grpc_ctx->is_request ? "Request" : "Response"));
        }

        offset = dissect_grpc_message(tvb, offset, GRPC_MESSAGE_HEAD_LEN + message_length, pinfo, grpc_tree, grpc_ctx);
    }

    return tvb_captured_length(tvb);
}

static grpc_context_info_t*
get_grpc_context(packet_info *pinfo, const media_content_info_t *content_info)
{
    http_req_res_t* curr_req_res;
    grpc_context_info_t* grpc_ctx = wmem_new0(pinfo->pool, grpc_context_info_t);

    if (proto_is_frame_protocol(pinfo->layers, "http2")) {
        grpc_ctx->path = http2_get_header_value(pinfo, HTTP2_HEADER_PATH, false);
        grpc_ctx->is_request = (grpc_ctx->path != NULL);
        if (grpc_ctx->path == NULL) {
            /* this must be response, so we get it from http2 request stream */
            /* XXX - Not necessarily true if the data has errors. */
            grpc_ctx->path = http2_get_header_value(pinfo, HTTP2_HEADER_PATH, true);
        }
        grpc_ctx->content_type = http2_get_header_value(pinfo, HTTP2_HEADER_CONTENT_TYPE, false);
        grpc_ctx->encoding = http2_get_header_value(pinfo, HTTP2_HEADER_GRPC_ENCODING, false);
    }
    else if (proto_is_frame_protocol(pinfo->layers, "http")) {
        curr_req_res = (http_req_res_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_http, HTTP_PROTO_DATA_REQRES);
        DISSECTOR_ASSERT_HINT(curr_req_res && content_info, "Unexpected error: HTTP request/reply or HTTP message info not available.");
        grpc_ctx->is_request = (content_info->type == MEDIA_CONTAINER_HTTP_REQUEST);
        grpc_ctx->path = curr_req_res->request_uri;
        grpc_ctx->content_type = pinfo->match_string; /* only for grpc-web(-text) over http1.1 */
        if (content_info->data) {
            grpc_ctx->encoding = (const char*)wmem_map_lookup((wmem_map_t *)content_info->data, HTTP2_HEADER_GRPC_ENCODING);
        }
    }
    else {
        /* unexpected protocol error */
        DISSECTOR_ASSERT_NOT_REACHED();
    }

    return grpc_ctx;
}

static int
dissect_grpc(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
    grpc_context_info_t* grpc_ctx;
    media_content_info_t* content_info = (media_content_info_t*)data;

    grpc_ctx = get_grpc_context(pinfo, content_info);
    grpc_ctx->proto_type = GRPC_PTYPE_GRPC;

    return dissect_grpc_common(tvb, pinfo, tree, grpc_ctx);
}

static int
dissect_grpc_web(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
    grpc_context_info_t* grpc_ctx;
    media_content_info_t* content_info = (media_content_info_t*)data;

    grpc_ctx = get_grpc_context(pinfo, content_info);
    grpc_ctx->proto_type = GRPC_PTYPE_GRPC_WEB;

    return dissect_grpc_common(tvb, pinfo, tree, grpc_ctx);
}

static int
dissect_grpc_web_text(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
    int ret;
    tvbuff_t* real_data_tvb;
    grpc_context_info_t* grpc_ctx;
    media_content_info_t* content_info = (media_content_info_t*)data;

    real_data_tvb = base64_tvb_to_new_tvb(tvb, 0, tvb_reported_length(tvb));
    add_new_data_source(pinfo, real_data_tvb, "Decoded base64 body");

    grpc_ctx = get_grpc_context(pinfo, content_info);
    grpc_ctx->proto_type = GRPC_PTYPE_GRPC_WEB_TEXT;

    ret = dissect_grpc_common(real_data_tvb, pinfo, tree, grpc_ctx);

    /* convert reassembly the lengths of offset and remaining bytes back to the base64 lengths */
    pinfo->desegment_offset = BASE64_ENCODE_SIZE(pinfo->desegment_offset);
    pinfo->desegment_len = BASE64_ENCODE_SIZE(pinfo->desegment_len);

    return ret;
}

void
proto_register_grpc(void)
{

    static hf_register_info hf[] = {
        { &hf_grpc_frame_type,
          { "Frame Type", "grpc.frame_type",
            FT_UINT8, BASE_DEC, VALS(grpc_frame_type_vals), 0x80,
            "The frame type of this grpc message (GRPC-WEB extension)", HFILL }
        },
        { &hf_grpc_compressed_flag,
          { "Compressed Flag", "grpc.compressed_flag",
            FT_UINT8, BASE_DEC, VALS(grpc_compressed_flag_vals), 0x01,
            "Compressed-Flag value of 1 indicates that the binary octet sequence of Message is compressed", HFILL }
        },
        { &hf_grpc_message_length,
          { "Message Length", "grpc.message_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "The length (32 bits) of message payload (not include itself)", HFILL }
        },
        { &hf_grpc_message_data,
          { "Message Data", "grpc.message_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        }
    };

    static int *ett[] = {
        &ett_grpc,
        &ett_grpc_message,
        &ett_grpc_encoded_entity
    };

    /* Setup protocol expert items */
    static ei_register_info ei[] = {
        { &ei_grpc_body_decompression_failed,
        { "grpc.body_decompression_failed", PI_UNDECODED, PI_WARN,
        "Body decompression failed", EXPFILL }
        },
        { &ei_grpc_body_malformed,
        { "grpc.body_malformed", PI_UNDECODED, PI_WARN,
        "Malformed message data", EXPFILL }
        }
    };

    module_t *grpc_module;
    expert_module_t *expert_grpc;

    proto_grpc = proto_register_protocol("GRPC Message", "GRPC", "grpc");

    proto_register_field_array(proto_grpc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    grpc_module = prefs_register_protocol(proto_grpc, NULL);

    prefs_register_bool_preference(grpc_module, "detect_json_automatically",
        "Always check whether the message is JSON regardless of content-type.",
        "Normally application/grpc message is protobuf, "
        "but sometime the true message is json. "
        "If this option in on, we always check whether the message is JSON "
        "(body starts with '{' and ends with '}') regardless of "
        "grpc_message_type_subdissector_table settings (which dissect grpc "
        "message according to content-type).",
        &grpc_detect_json_automatically);

    prefs_register_bool_preference(grpc_module, "embedded_under_http2",
        "Embed gRPC messages under HTTP2 (or other) protocol tree items.",
        "Embed gRPC messages under HTTP2 (or other) protocol tree items.",
        &grpc_embedded_under_http2);

    prefs_register_static_text_preference(grpc_module, "service_definition",
        "Please refer to preferences of Protobuf for specifying gRPC Service Definitions (*.proto).",
        "Including specifying .proto files search paths, etc.");

    expert_grpc = expert_register_protocol(proto_grpc);
    expert_register_field_array(expert_grpc, ei, array_length(ei));

    grpc_handle = register_dissector_with_description("grpc", "gRPC", dissect_grpc, proto_grpc);
    grpc_web_handle = register_dissector_with_description("grpc_web", "gRPC Web", dissect_grpc_web, proto_grpc);
    grpc_web_text_handle = register_dissector_with_description("grpc_web_text", "gRPC Web Text", dissect_grpc_web_text, proto_grpc);

    /*
    * Dissectors can register themselves in this table as grpc message
    * subdissector. Default it support json, protobuf.
    */
    grpc_message_type_subdissector_table =
        register_dissector_table("grpc_message_type",
            "GRPC message type", proto_grpc, FT_STRING, STRING_CASE_SENSITIVE);
}

void
proto_reg_handoff_grpc(void)
{
    int i;

    char *content_types[] = {
        "application/grpc",
        "application/grpc+proto",
        "application/grpc+json",
        NULL /* end flag */
    };

    char *content_types_web[] = {
        "application/grpc-web",
        "application/grpc-web+proto",
        NULL /* end flag */
    };

    char *content_types_web_text[] = {
        "application/grpc-web-text",
        "application/grpc-web-text+proto",
        NULL /* end flag */
    };

    /* register native grpc handler */
    for (i = 0; content_types[i]; i++) {
        dissector_add_string("streaming_content_type", content_types[i], grpc_handle);
        dissector_add_string("media_type", content_types[i], grpc_handle);
    }

    /* register gRPC Web handler */
    for (i = 0; content_types_web[i]; i++) {
        dissector_add_string("streaming_content_type", content_types_web[i], grpc_web_handle);
        dissector_add_string("media_type", content_types_web[i], grpc_web_handle);
    }

    /* register gRPC Web Text handler */
    for (i = 0; content_types_web_text[i]; i++) {
        dissector_add_string("streaming_content_type", content_types_web_text[i], grpc_web_text_handle);
        dissector_add_string("media_type", content_types_web_text[i], grpc_web_text_handle);
    }

    proto_http = proto_get_id_by_filter_name("http");
    data_text_lines_handle = find_dissector_add_dependency("data-text-lines", proto_grpc);
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
