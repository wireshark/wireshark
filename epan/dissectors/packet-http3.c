/* packet-http3.c
 * Routines for HTTP/3 dissection
 * Copyright 2019, Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * https://tools.ietf.org/html/draft-ietf-quic-http-29
 * https://tools.ietf.org/html/draft-ietf-quic-qpack-16
 *
 * Depends on the QUIC dissector for providing a reassembled stream of data, see
 * packet-quic.c for details about supported QUIC draft versions.
 * Currently supported HTTP/3 versions: h3-23 up to and including h3-29.
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/expert.h>

#include "packet-quic.h"

void proto_reg_handoff_http3(void);
void proto_register_http3(void);

static int proto_http3 = -1;
static int hf_http3_stream_type = -1;
static int hf_http3_push_id = -1;
static int hf_http3_frame_type = -1;
static int hf_http3_frame_length = -1;
static int hf_http3_frame_payload = -1;
static int hf_http3_settings = -1;
static int hf_http3_settings_identifier = -1;
static int hf_http3_settings_value = -1;
static int hf_http3_settings_qpack_max_table_capacity = -1;
static int hf_http3_settings_max_field_section_size = -1;
static int hf_http3_settings_qpack_blocked_streams = -1;
static int hf_http3_settings_extended_connect = -1;
static int hf_http3_priority_update_element_id = -1;
static int hf_http3_priority_update_field_value = -1;

static expert_field ei_http3_unknown_stream_type = EI_INIT;

/* Initialize the subtree pointers */
static gint ett_http3 = -1;
static gint ett_http3_settings = -1;

/**
 * Unidirectional stream types.
 * https://tools.ietf.org/html/draft-ietf-quic-http-29#section-6.2
 * https://tools.ietf.org/html/draft-ietf-quic-qpack-16#section-4.2
 */
enum http3_stream_type {
    HTTP3_STREAM_TYPE_CONTROL,
    HTTP3_STREAM_TYPE_PUSH,
    HTTP3_STREAM_TYPE_QPACK_ENCODER,
    HTTP3_STREAM_TYPE_QPACK_DECODER,
};

/*
 * Unidirectional stream types (62-bit code space).
 * https://tools.ietf.org/html/draft-ietf-quic-http-29#section-11.2.4
 */
static const val64_string http3_stream_types[] = {
    /* 0x00 - 0x3f Assigned via Standards Action or IESG Approval. */
    { 0x00, "Control Stream" },
    { 0x01, "Push Stream" },
    { 0x02, "QPACK Encoder Stream" },
    { 0x03, "QPACK Decoder Stream" },
    /* 0x40 - 0x3FFFFFFFFFFFFFFF Assigned via Specification Required policy */
    { 0, NULL }
};

/*
 * Frame type codes (62-bit code space).
 * https://tools.ietf.org/html/draft-ietf-quic-http-29#section-11.2.1
 */
#define HTTP3_DATA                              0x0
#define HTTP3_HEADERS                           0x1
#define HTTP3_CANCEL_PUSH                       0x3
#define HTTP3_SETTINGS                          0x4
#define HTTP3_PUSH_PROMISE                      0x5
#define HTTP3_GOAWAY                            0x7
#define HTTP3_MAX_PUSH_ID                       0xD
#define HTTP3_PRIORITY_UPDATE_REQUEST_STREAM    0xF0700
#define HTTP3_PRIORITY_UPDATE_PUSH_STREAM       0xF0701

static const val64_string http3_frame_types[] = {
    /* 0x00 - 0x3f Assigned via Standards Action or IESG Approval. */
    { HTTP3_DATA, "DATA" },
    { HTTP3_HEADERS, "HEADERS" },
    { 0x02, "Reserved" },       // "PRIORITY" in draft-22 and before
    { HTTP3_CANCEL_PUSH, "CANCEL_PUSH" },
    { HTTP3_SETTINGS, "SETTINGS" },
    { HTTP3_PUSH_PROMISE, "PUSH_PROMISE" },
    { 0x06, "Reserved" },
    { HTTP3_GOAWAY, "GOAWAY" },
    { 0x08, "Reserved" },
    { 0x09, "Reserved" },
    { HTTP3_MAX_PUSH_ID, "MAX_PUSH_ID" },
    { 0x0e, "Reserved" }, // "DUPLICATE_PUSH" in draft-26 and before
    { HTTP3_PRIORITY_UPDATE_REQUEST_STREAM, "PRIORITY_UPDATE" }, // draft-ietf-httpbis-priority-03
    { HTTP3_PRIORITY_UPDATE_PUSH_STREAM, "PRIORITY_UPDATE" }, // draft-ietf-httpbis-priority-03
    /* 0x40 - 0x3FFFFFFFFFFFFFFF Assigned via Specification Required policy */
    { 0, NULL }
};

/*
 * Settings parameter type codes (62-bit code space).
 * https://tools.ietf.org/html/draft-ietf-quic-http-29#name-http-2-settings-parameters
 */

#define HTTP3_QPACK_MAX_TABLE_CAPACITY          0x01
#define HTTP3_SETTINGS_MAX_FIELD_SECTION_SIZE   0x06
#define HTTP3_QPACK_BLOCKED_STREAMS             0x07
#define HTTP3_EXTENDED_CONNECT                  0x08 /* https://datatracker.ietf.org/doc/draft-ietf-httpbis-h3-websockets */

static const val64_string http3_settings_vals[] = {
    { HTTP3_QPACK_MAX_TABLE_CAPACITY, "Max Table Capacity" },
    { HTTP3_SETTINGS_MAX_FIELD_SECTION_SIZE, "Max Field Section Size" },
    { HTTP3_QPACK_BLOCKED_STREAMS, "Blocked Streams" },
    { HTTP3_QPACK_BLOCKED_STREAMS, "Extended CONNECT" },
    { 0, NULL }
};

typedef struct _http3_stream_info {
    guint64 uni_stream_type;
    guint64 broken_from_offset;     /**< Unrecognized stream starting at offset (if non-zero). */
} http3_stream_info;

/**
 * Whether this is a reserved code point for Stream Type, Frame Type, Error
 * Code, etc.
 */
static inline gboolean
http3_is_reserved_code(guint64 stream_type)
{
    return (stream_type - 0x21) % 0x1f == 0;
}

static gboolean
try_get_quic_varint(tvbuff_t *tvb, int offset, guint64 *value, int *lenvar)
{
    if (tvb_reported_length_remaining(tvb, offset) == 0) {
        return FALSE;
    }
    gint len = 1 << (tvb_get_guint8(tvb, offset) >> 6);
    if (tvb_reported_length_remaining(tvb, offset) < len) {
        return FALSE;
    }
    *lenvar = len;
    if (value) {
        gint n = (gint)tvb_get_varint(tvb, offset, -1, value, ENC_VARINT_QUIC);
        DISSECTOR_ASSERT_CMPINT(n, ==, len);
    }
    return TRUE;
}

/** Returns the size of the whole HTTP/3 frame. */
static int
get_http3_frame_size(tvbuff_t *tvb, int offset)
{
    int type_size, length_size;
    guint64 frame_length;

    if (!try_get_quic_varint(tvb, offset, NULL, &type_size)) {
        return 0;
    }
    offset += type_size;

    if (!try_get_quic_varint(tvb, offset, &frame_length, &length_size)) {
        return 0;
    }

    guint64 frame_size = type_size + length_size + frame_length;
    if (frame_size > G_MAXINT32) {
        // We do not support such large frames.
        return 0;
    }
    return (int)frame_size;
}

static gboolean
http3_check_frame_size(tvbuff_t *tvb, packet_info *pinfo, int offset)
{
    int frame_size = get_http3_frame_size(tvb, offset);
    int remaining = tvb_reported_length_remaining(tvb, offset);
    if (frame_size && frame_size <= remaining) {
        return TRUE;
    }

    pinfo->desegment_offset = offset;
    pinfo->desegment_len = frame_size ? (frame_size - remaining) : DESEGMENT_ONE_MORE_SEGMENT;
    return FALSE;
}

/* Settings */
static int
dissect_http3_settings(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* http3_tree, guint offset)
{
    guint64 settingsid, value;
    proto_item *ti_settings, *pi;
    int lenvar;
    proto_tree *settings_tree;
    while(tvb_reported_length_remaining(tvb, offset) > 0){

        ti_settings = proto_tree_add_item(http3_tree, hf_http3_settings, tvb, offset, 2, ENC_NA);
        settings_tree = proto_item_add_subtree(ti_settings, ett_http3_settings);
        pi = proto_tree_add_item_ret_varint(settings_tree, hf_http3_settings_identifier, tvb, offset, -1, ENC_VARINT_QUIC, &settingsid, &lenvar);
        /* Check if it is a GREASE Settings ID */
        if (http3_is_reserved_code(settingsid)) {
            proto_item_set_text(pi, "Type: GREASE (%#" PRIx64 ")", settingsid);
            proto_item_append_text(ti_settings, " - GREASE" );
        } else {
            proto_item_append_text(ti_settings, " - %s",
                                   val64_to_str_const(settingsid, http3_settings_vals, "Unknown") );
        }
        offset += lenvar;


        proto_tree_add_item_ret_varint(settings_tree, hf_http3_settings_value, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
        switch(settingsid){
            case HTTP3_QPACK_MAX_TABLE_CAPACITY:
                proto_tree_add_item_ret_varint(settings_tree, hf_http3_settings_qpack_max_table_capacity, tvb, offset, -1, ENC_VARINT_QUIC, &value, &lenvar);
                proto_item_append_text(ti_settings, ": %" PRIu64, value );
            break;
            case HTTP3_SETTINGS_MAX_FIELD_SECTION_SIZE:
                proto_tree_add_item_ret_varint(settings_tree, hf_http3_settings_max_field_section_size, tvb, offset, -1, ENC_VARINT_QUIC, &value, &lenvar);
                proto_item_append_text(ti_settings, ": %" PRIu64, value );
            break;
            case HTTP3_QPACK_BLOCKED_STREAMS:
                proto_tree_add_item_ret_varint(settings_tree, hf_http3_settings_qpack_blocked_streams, tvb, offset, -1, ENC_VARINT_QUIC, &value, &lenvar);
                proto_item_append_text(ti_settings, ": %" PRIu64, value );
            break;
            case HTTP3_EXTENDED_CONNECT:
                proto_tree_add_item_ret_varint(settings_tree, hf_http3_settings_extended_connect, tvb, offset, -1, ENC_VARINT_QUIC, &value, &lenvar);
                proto_item_append_text(ti_settings, ": %" PRIu64, value );
            break;
            default:
                /* No Default */
            break;
        }
        offset += lenvar;
    }

    return offset;
}
/* Priority Update */
static int
dissect_http3_priority_update(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* http3_tree, guint offset, guint64 frame_length)
{
    guint64 priority_field_value_len;
    int lenvar;

    proto_tree_add_item_ret_varint(http3_tree, hf_http3_priority_update_element_id, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
    offset += lenvar;
    priority_field_value_len = frame_length - lenvar;

    proto_tree_add_item(http3_tree, hf_http3_priority_update_field_value, tvb, offset, (int)priority_field_value_len, ENC_ASCII);
    offset += (int)priority_field_value_len;

    return offset;
}

static int
dissect_http3_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    guint64 frame_type, frame_length;
    int lenvar;
    proto_item *pi;

    pi = proto_tree_add_item_ret_varint(tree, hf_http3_frame_type, tvb, offset, -1, ENC_VARINT_QUIC, &frame_type, &lenvar);
    offset += lenvar;
    if (http3_is_reserved_code(frame_type)) {
        proto_item_set_text(pi, "Type: Reserved (%#" PRIx64 ")", frame_type);
    } else {
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val64_to_str_const(frame_type, http3_frame_types, "Unknown"));
    }

    proto_tree_add_item_ret_varint(tree, hf_http3_frame_length, tvb, offset, -1, ENC_VARINT_QUIC, &frame_length, &lenvar);
    offset += lenvar;

    if (frame_length) {
        proto_tree_add_item(tree, hf_http3_frame_payload, tvb, offset, (int)frame_length, ENC_NA);

        switch (frame_type) {
            case HTTP3_SETTINGS: { /* Settings Frame */
                tvbuff_t *next_tvb = tvb_new_subset_length(tvb, offset, (int)frame_length);
                dissect_http3_settings(next_tvb, pinfo,tree, 0);
            }
            break;
            case HTTP3_PRIORITY_UPDATE_REQUEST_STREAM:
            case HTTP3_PRIORITY_UPDATE_PUSH_STREAM: { /* Priority_Update Frame */
                tvbuff_t *next_tvb = tvb_new_subset_length(tvb, offset, (int)frame_length);
                dissect_http3_priority_update(next_tvb, pinfo,tree, 0, frame_length);
            }
            break;
        }

        offset += (int)frame_length;
    }


    return offset;
}

static void
report_unknown_stream_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, quic_stream_info *stream_info, http3_stream_info *h3_stream)
{
    /*
     * "If the stream header indicates a stream type which is not supported by
     * the recipient, the remainder of the stream cannot be consumed as the
     * semantics are unknown."
     * https://tools.ietf.org/html/draft-ietf-quic-http-29#page-28
     */
    proto_tree_add_expert_format(tree, pinfo, &ei_http3_unknown_stream_type, tvb, offset, 0,
                                 "Unknown stream type %#" PRIx64 " on Stream ID %#" PRIx64,
                                 h3_stream->uni_stream_type, stream_info->stream_id);
}

static int
dissect_http3_uni_stream(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, quic_stream_info *stream_info, http3_stream_info *h3_stream)
{
    guint64 stream_type;
    int lenvar;
    proto_item *pi;

    if (stream_info->offset == 0) {
        pi = proto_tree_add_item_ret_varint(tree, hf_http3_stream_type, tvb, offset, -1, ENC_VARINT_QUIC, &stream_type, &lenvar);
        offset += lenvar;
        if (http3_is_reserved_code(stream_type)) {
            // Reserved to exercise requirement that unknown types are ignored.
            proto_item_set_text(pi, "Stream Type: Reserved (%#" PRIx64 ")", stream_type);
        }
        h3_stream->uni_stream_type = stream_type;
    } else {
        stream_type = h3_stream->uni_stream_type;
    }

    switch (stream_type) {
        case HTTP3_STREAM_TYPE_CONTROL:
            break;
        case HTTP3_STREAM_TYPE_PUSH:
            // The remaining data of this stream consists of HTTP/3 frames.
            if (stream_info->offset == 0) {
                proto_tree_add_item_ret_varint(tree, hf_http3_push_id, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
                offset += lenvar;
            }
            break;
        case HTTP3_STREAM_TYPE_QPACK_ENCODER:
            // TODO
            offset = tvb_captured_length(tvb);
            break;
        case HTTP3_STREAM_TYPE_QPACK_DECODER:
            // TODO
            offset = tvb_captured_length(tvb);
            break;
        default:
            // Unknown or reserved stream type, consume everything.
            if (!http3_is_reserved_code(stream_type)) {
                if (!PINFO_FD_VISITED(pinfo)) {
                    h3_stream->broken_from_offset = stream_info->offset + offset;
                }
                report_unknown_stream_type(tvb, pinfo, tree, offset, stream_info, h3_stream);
            }
            offset = tvb_captured_length(tvb);
            break;
    }

    return offset;
}

static int
dissect_http3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    quic_stream_info *stream_info = (quic_stream_info *)data;
    proto_item *ti;
    proto_tree *http3_tree;
    int offset = 0;
    http3_stream_info *h3_stream;

    if (!stream_info) {
        return 0;
    }

    switch (QUIC_STREAM_TYPE(stream_info->stream_id)) {
        case QUIC_STREAM_CLIENT_BIDI:
            /* Used for HTTP requests and responses. */
            if (!http3_check_frame_size(tvb, pinfo, offset)) {
                return tvb_captured_length(tvb);
            }
            break;
        case QUIC_STREAM_SERVER_BIDI:
            /* "HTTP/3 does not use server-initiated bidirectional streams,
             * though an extension could define a use for these streams." */
            break;
        case QUIC_STREAM_CLIENT_UNI:
        case QUIC_STREAM_SERVER_UNI:
            break;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HTTP3");
    // Only clear the columns if this is the first HTTP/3 STREAM in the packet.
    if (!proto_is_frame_protocol(pinfo->layers, "http3")) {
        col_clear(pinfo->cinfo, COL_INFO);
    }

    ti = proto_tree_add_item(tree, proto_http3, tvb, 0, -1, ENC_NA);
    http3_tree = proto_item_add_subtree(ti, ett_http3);

    h3_stream = (http3_stream_info *)quic_stream_get_proto_data(pinfo, stream_info);
    if (!h3_stream) {
        h3_stream = wmem_new0(wmem_file_scope(), http3_stream_info);
        quic_stream_add_proto_data(pinfo, stream_info, h3_stream);
    }

    // If a STREAM has unknown data, everything afterwards cannot be dissected.
    if (h3_stream->broken_from_offset && h3_stream->broken_from_offset <= stream_info->offset + offset) {
        report_unknown_stream_type(tvb, pinfo, tree, offset, stream_info, h3_stream);
        return tvb_captured_length(tvb);
    }

    switch (QUIC_STREAM_TYPE(stream_info->stream_id)) {
        case QUIC_STREAM_CLIENT_BIDI:
            /* Used for HTTP requests and responses. */
            break;

        case QUIC_STREAM_SERVER_BIDI:
            /* "HTTP/3 does not use server-initiated bidirectional streams,
             * though an extension could define a use for these streams." */
            // XXX expert info?
            return tvb_captured_length(tvb);

        case QUIC_STREAM_CLIENT_UNI:
        case QUIC_STREAM_SERVER_UNI:
            offset = dissect_http3_uni_stream(tvb, pinfo, http3_tree, offset, stream_info, h3_stream);
            break;
    }

    while (tvb_reported_length_remaining(tvb, offset)) {
        if (!http3_check_frame_size(tvb, pinfo, offset)) {
            return tvb_captured_length(tvb);
        }
        offset = dissect_http3_frame(tvb, pinfo, http3_tree, offset);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_http3(void)
{
    expert_module_t *expert_http3;

    static hf_register_info hf[] = {
        { &hf_http3_stream_type,
          { "Stream Type", "http3.stream_type",
            FT_UINT64, BASE_HEX|BASE_VAL64_STRING, VALS64(http3_stream_types), 0x0,
            NULL, HFILL }
        },
        { &hf_http3_push_id,
          { "Push ID", "http3.push_id",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_http3_frame_type,
          { "Type", "http3.frame_type",
            FT_UINT64, BASE_HEX|BASE_VAL64_STRING, VALS64(http3_frame_types), 0x0,
            "Frame Type", HFILL }
        },
        { &hf_http3_frame_length,
          { "Length", "http3.frame_length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Length of the Frame Payload", HFILL }
        },
        { &hf_http3_frame_payload,
          { "Frame Payload", "http3.frame_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        /* Settings */
        { &hf_http3_settings,
            { "Settings", "http3.settings",
               FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http3_settings_identifier,
            { "Settings Identifier", "http3.settings.id",
               FT_UINT64, BASE_HEX|BASE_VAL64_STRING, VALS64(http3_settings_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_http3_settings_value,
            { "Settings Value", "http3.settings.value",
               FT_UINT64, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http3_settings_qpack_max_table_capacity,
            { "Max Table Capacity", "http3.settings.qpack.max_table_capacity",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http3_settings_max_field_section_size,
            { "Max header list size", "http3.settings.max_field_section_size",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "The default value is unlimited.", HFILL }
        },
        { &hf_http3_settings_qpack_blocked_streams,
            { "Blocked Streams", "http3.settings.qpack.blocked_streams",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http3_settings_extended_connect,
            { "Extended CONNECT", "http3.settings.extended_connect",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },

        /* Priority Update */
        { &hf_http3_priority_update_element_id,
            { "Priority Update Element ID", "http3.priority_update_element_id",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http3_priority_update_field_value,
            { "Priority Update Field Value", "http3.priority_update_field_value",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

    };

    static gint *ett[] = {
        &ett_http3,
        &ett_http3_settings,
    };

    static ei_register_info ei[] = {
        { &ei_http3_unknown_stream_type,
          { "http3.unknown_stream_type", PI_UNDECODED, PI_WARN,
            "An unknown stream type was encountered", EXPFILL }
        },
    };

    proto_http3 = proto_register_protocol("Hypertext Transfer Protocol Version 3", "HTTP3", "http3");

    proto_register_field_array(proto_http3, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_http3 = expert_register_protocol(proto_http3);
    expert_register_field_array(expert_http3, ei, array_length(ei));
}

void
proto_reg_handoff_http3(void)
{
    dissector_handle_t http3_handle;

    http3_handle = create_dissector_handle(dissect_http3, proto_http3);
    dissector_add_string("quic.proto", "h3", http3_handle);
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
