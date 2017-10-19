/* packet-grpc.c
 * Routines for GRPC dissection
 * Copyright 2017, Huang Qiangxiong <qiangxiong.huang@qq.com>
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
*
* This GRPC dissector must be invoked by HTTP2 dissector.
*
* The main task of grpc dissector includes:
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
*
* TODO
*   Support tap.
*   Support statistics.
*/

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/dissectors/packet-http2.h>

#include "wsutil/pint.h"

#define GRPC_MESSAGE_HEAD_LEN 5

/* http2 standard headers */
#define HTTP2_HEADER_PATH ":path"
#define HTTP2_HEADER_CONTENT_TYPE "content-type"
/* http2 for grpc */
#define HTTP2_HEADER_GRPC_ENCODING "grpc-encoding"

/*
* Decompression of zlib encoded entities.
*/
#ifdef HAVE_ZLIB
static gboolean grpc_decompress_body = TRUE;
#else
static gboolean grpc_decompress_body = FALSE;
#endif

/* detect json automaticlly */
static gboolean grpc_detect_json_automatically = TRUE;
/* tell http2 to use streaming mode reassembly for grpc dissector */
static gboolean grpc_enable_streaming_reassembly_mode = TRUE;
/* whether embed GRPC messages under HTTP2 protocol tree items */
static gboolean grpc_embedded_under_http2 = FALSE;

void proto_register_grpc(void);
void proto_reg_handoff_grpc(void);

static int proto_grpc = -1;

/* message header */
static int hf_grpc_compressed_flag = -1;
static int hf_grpc_message_length = -1;
/* message body */
static int hf_grpc_message_data = -1;

/* compressed flag vals */
#define grpc_compressed_flag_vals_VALUE_STRING_LIST(XXX)    \
    XXX(GRPC_NOT_COMPRESSED, 0, "Not Compressed")  \
    XXX(GRPC_COMPRESSED, 1, "Compressed")

VALUE_STRING_ENUM(grpc_compressed_flag_vals);
VALUE_STRING_ARRAY(grpc_compressed_flag_vals);

/* expert */
static expert_field ei_grpc_body_decompression_failed = EI_INIT;
static expert_field ei_grpc_body_malformed = EI_INIT;

/* trees */
static int ett_grpc = -1;
static int ett_grpc_message = -1;
static int ett_grpc_encoded_entity = -1;

static dissector_handle_t grpc_handle;

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
dissect_body_data(proto_tree *grpc_tree, packet_info *pinfo, tvbuff_t *tvb, const gint offset,
    gint length, gboolean continue_dissect,
    const gchar* http2_path, gboolean is_request)
{
    const gchar *http2_content_type;
    gchar *grpc_message_info;
    tvbuff_t *next_tvb;
    int dissected;
    proto_tree *parent_tree;

    proto_tree_add_bytes_format_value(grpc_tree, hf_grpc_message_data, tvb, offset, length, NULL, "%u bytes", length);

    if (!continue_dissect) {
        return; /* if uncompress failed, we don't continue dissecting. */
    }

    http2_content_type = http2_get_header_value(pinfo, HTTP2_HEADER_CONTENT_TYPE, FALSE);
    if (http2_content_type == NULL || http2_path == NULL) {
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
        guint8 end_bytes[3];
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
    * Acording to grpc wire format guide, it will be:
    *   "application/grpc" [("+proto" / "+json" / {custom})] "," "/" service-name "/" method-name "/" "," ("request" / "response")
    * For example:
    *   application/grpc,/helloworld.Greeter/SayHello,request
    */
    grpc_message_info = wmem_strconcat(wmem_packet_scope(), http2_content_type, ",",
        http2_path, ",", (is_request ? "request" : "response"), NULL);

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

static gboolean
can_uncompress_body(packet_info *pinfo, const gchar **compression_method)
{
    const gchar *grpc_encoding = http2_get_header_value(pinfo, HTTP2_HEADER_GRPC_ENCODING, FALSE);
    *compression_method = grpc_encoding;

    /* check http2 have a grpc-encoding header appropriate */
    return grpc_decompress_body
        && grpc_encoding != NULL
        && (strcmp(grpc_encoding, "gzip") == 0 || strcmp(grpc_encoding, "deflate") == 0);
}

/* Dissect a grpc message. The caller needs to guarantee that the length is equal
to 5 + message_length according to grpc wire format definition. */
static guint
dissect_grpc_message(tvbuff_t *tvb, guint offset, guint length, packet_info *pinfo, proto_tree *grpc_tree,
                     const gchar* http2_path, gboolean is_request)
{
    guint32 compressed_flag, message_length;
    const gchar *compression_method;

    /* GRPC message format:
    Delimited-Message -> Compressed-Flag Message-Length Message
    Compressed-Flag -> 0 / 1 # encoded as 1 byte unsigned integer
    Message-Length -> {length of Message} # encoded as 4 byte unsigned integer
    Message -> *{binary octet} (may be protobuf or json)
    */
    proto_tree_add_item_ret_uint(grpc_tree, hf_grpc_compressed_flag, tvb, offset, 1, ENC_BIG_ENDIAN, &compressed_flag);
    offset += 1;

    proto_tree_add_item(grpc_tree, hf_grpc_message_length, tvb, offset, 4, ENC_BIG_ENDIAN);
    message_length = length - 5;  /* should be equal to tvb_get_ntohl(tvb, offset) */
    offset += 4;

    /* uncompressed message data if compressed_flag is set */
    if (compressed_flag & GRPC_COMPRESSED) {
        if (can_uncompress_body(pinfo, &compression_method)) {
            proto_item *compressed_proto_item = NULL;
            tvbuff_t *uncompressed_tvb = tvb_child_uncompress(tvb, tvb, offset, message_length);

            proto_tree *compressed_entity_tree = proto_tree_add_subtree_format(
                grpc_tree, tvb, offset, message_length, ett_grpc_encoded_entity,
                &compressed_proto_item, "Message-encoded entity body (%s): %u bytes",
                compression_method == NULL ? "unknown" : compression_method, message_length
            );

            if (uncompressed_tvb != NULL) {
                guint uncompressed_length = tvb_captured_length(uncompressed_tvb);
                add_new_data_source(pinfo, uncompressed_tvb, "Uncompressed entity body");
                proto_item_append_text(compressed_proto_item, " -> %u bytes", uncompressed_length);
                dissect_body_data(grpc_tree, pinfo, uncompressed_tvb, 0, uncompressed_length, TRUE,
                    http2_path, is_request);
            } else {
                proto_tree_add_expert(compressed_entity_tree, pinfo, &ei_grpc_body_decompression_failed,
                    tvb, offset, message_length);
                dissect_body_data(grpc_tree, pinfo, tvb, offset, message_length, FALSE, http2_path, is_request);
            }
        } else { /* compressed flag is set, but we can not uncompressed */
            dissect_body_data(grpc_tree, pinfo, tvb, offset, message_length, FALSE, http2_path, is_request);
        }
    } else {
        dissect_body_data(grpc_tree, pinfo, tvb, offset, message_length, TRUE, http2_path, is_request);
    }

    return offset + message_length;
}

static int
dissect_grpc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *grpc_tree;
    guint32 message_length;
    guint offset = 0;
    const gchar* http2_path;
    gboolean is_request;
    guint tvb_len = tvb_reported_length(tvb);

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
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "GRPC");
            col_append_str(pinfo->cinfo, COL_INFO, " (GRPC)");
            col_set_fence(pinfo->cinfo, COL_PROTOCOL);
        }
        ti = proto_tree_add_item(tree, proto_grpc, tvb, offset, message_length + GRPC_MESSAGE_HEAD_LEN, ENC_NA);
        grpc_tree = proto_item_add_subtree(ti, ett_grpc_message);

        /* http2_path contains: "/" Service-Name "/" {method name} */
        http2_path = http2_get_header_value(pinfo, HTTP2_HEADER_PATH, FALSE);
        is_request = (http2_path != NULL);

        if (http2_path == NULL) { /* this response, so we get it from http2 request stream */
            http2_path = http2_get_header_value(pinfo, HTTP2_HEADER_PATH, TRUE);
        }

        if (http2_path) {
            proto_item_append_text(ti, ": %s, %s", http2_path, (is_request ? "Request" : "Response"));
        }

        offset = dissect_grpc_message(tvb, offset, GRPC_MESSAGE_HEAD_LEN + message_length, pinfo, grpc_tree, http2_path, is_request);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_grpc(void)
{

    static hf_register_info hf[] = {
        { &hf_grpc_compressed_flag,
        { "Compressed Flag", "grpc.compressed_flag",
        FT_UINT8, BASE_DEC, VALS(grpc_compressed_flag_vals), 0x0,
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

    static gint *ett[] = {
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

    grpc_module = prefs_register_protocol(proto_grpc, proto_reg_handoff_grpc);

    prefs_register_bool_preference(grpc_module, "detect_json_automaticlly",
        "Always check whether the message is JSON regardless of content-type.",
        "Normally application/grpc message is protobuf, "
        "but sometime the true message is json. "
        "If this option in on, we always check whether the message is JSON "
        "(body starts with '{' and ends with '}') regardless of "
        "grpc_message_type_subdissector_table settings (which dissect grpc "
        "message according to content-type).",
        &grpc_detect_json_automatically);

    prefs_register_bool_preference(grpc_module, "streaming_reassembly_mode",
        "Turn on streaming reassembly mode. Required for parsing streaming RPCs.",
        "If turned on, http2 will reassemble gRPC message as soon as possible. "
        "Or else the gRPC message will be reassembled at the end of each HTTP2 "
        "STREAM. If your .proto files contains streaming RPCs (declaring RPC "
        "operation input/output message type with 'stream' label), you need "
        "to keep this option on.",
        &grpc_enable_streaming_reassembly_mode);

    prefs_register_bool_preference(grpc_module, "embeded_under_http2",
        "Embed gRPC messages under HTTP2 protocol tree items.",
        "Embed gRPC messages under HTTP2 protocol tree items.",
        &grpc_embedded_under_http2);

    prefs_register_static_text_preference(grpc_module, "service_definition",
        "Please refer to preferences of Protobuf for specifying gRPC Service Definitions (*.proto).",
        "Including specifying .proto files search paths, etc.");

    expert_grpc = expert_register_protocol(proto_grpc);
    expert_register_field_array(expert_grpc, ei, array_length(ei));

    grpc_handle = register_dissector("grpc", dissect_grpc, proto_grpc);

    /*
    * Dissectors can register themselves in this table as grpc message
    * subdissector. Default it support json, protobuf.
    */
    grpc_message_type_subdissector_table =
        register_dissector_table("grpc_message_type",
            "GRPC message type", proto_grpc, FT_STRING, BASE_NONE);
}

void
proto_reg_handoff_grpc(void)
{
    static gboolean initialized = FALSE;
    char *del_table, *add_table;
    char *content_types[] = {
        "application/grpc",
        "application/grpc+proto",
        "application/grpc+json",
        NULL /* end flag */
    };
    int i;

    add_table = grpc_enable_streaming_reassembly_mode ? "streaming_content_type" : "media_type";
    del_table = grpc_enable_streaming_reassembly_mode ? "media_type" : "streaming_content_type";

    /* register/deregister grpc_handle to/from tables */
    for (i = 0; content_types[i]; i++) {
        if (initialized) {
            dissector_delete_string(del_table, content_types[i], grpc_handle);
        }
        dissector_add_string(add_table, content_types[i], grpc_handle);
    }

    if (!initialized) {
        initialized = TRUE;
    }
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
