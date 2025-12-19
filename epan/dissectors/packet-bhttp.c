/* packet-bhttp.c
 * Routines for dissecting the binary format representation of HTTP messages.
 * Copyright 2023, Lucas Pardue <lucaspardue.24.7@gmail.com>
  *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * The information used comes from:
 * RFC9292: Binary Representation of HTTP Messages
 */

#include "config.h"

#include <epan/packet.h>

#include "packet-http.h"

/* Prototypes */
void proto_register_bhttp(void);
void proto_reg_handoff_bhttp(void);

/* Initialize the protocol */
static int proto_bhttp;
static int hf_bhttp_frame;
static int hf_bhttp_framing_indicator;
static int hf_bhttp_request_control_data;
static int hf_bhttp_request_method_len;
static int hf_bhttp_request_method;
static int hf_bhttp_request_scheme_len;
static int hf_bhttp_request_scheme;
static int hf_bhttp_request_authority_len;
static int hf_bhttp_request_authority;
static int hf_bhttp_request_path_len;
static int hf_bhttp_request_path;
static int hf_bhttp_info_response_control_data;
static int hf_bhttp_final_response_control_data;
static int hf_bhttp_final_response_status;
static int hf_bhttp_info_response_status;
static int hf_bhttp_known_length_field_section;
static int hf_bhttp_known_length_field_section_length;
static int hf_bhttp_indeterminate_length_field_section;
static int hf_bhttp_indeterminate_content_terminator;
static int hf_bhttp_name_len;
static int hf_bhttp_name;
static int hf_bhttp_value_len;
static int hf_bhttp_value;
static int hf_bhttp_known_length_content;
static int hf_bhttp_known_length_content_length;
static int hf_bhttp_known_length_content_content;
static int hf_bhttp_indeterminate_length_content;
static int hf_bhttp_indeterminate_length_content_chunk_length;
static int hf_bhttp_padding_length;

/* Initialize the subtree pointers */
static int ett_bhttp;
static int ett_bhttp_ft;
static int ett_bhttp_request_control_data;
static int ett_bhttp_info_response_control_data;
static int ett_bhttp_final_response_control_data;
static int ett_bhttp_known_length_field_section;
static int ett_bhttp_indeterminate_length_field_section;
static int ett_bhttp_response_control_data;
static int ett_bhttp_known_length_informational_response;
static int ett_bhttp_known_length_content;
static int ett_bhttp_indeterminate_length_content;

static dissector_handle_t bhttp_handle;

/* Framing indicator types https://www.rfc-editor.org/rfc/rfc9292.html#section-3.3 */
#define BHTTP_KNOWN_LENGTH_REQUEST             0x0
#define BHTTP_KNOWN_LENGTH_RESPONSE            0x1
#define BHTTP_INDETERMINATE_LENGTH_REQUEST     0x2
#define BHTTP_INDETERMINATE_LENGTH_RESPONSE    0x3

static const val64_string bhttp_frame_indicators[] = {
    { BHTTP_KNOWN_LENGTH_REQUEST, "Known-Length Request"},
    { BHTTP_KNOWN_LENGTH_RESPONSE, "Known-Length Response"},
    { BHTTP_INDETERMINATE_LENGTH_REQUEST, "Indeterminate-Length Request"},
    { BHTTP_INDETERMINATE_LENGTH_RESPONSE, "Indeterminate-Length Response"},
    { 0, NULL }
};

static bool
try_get_quic_varint(tvbuff_t *tvb, int offset, uint64_t *value, int *lenvar)
{
    if (tvb_reported_length_remaining(tvb, offset) == 0) {
        return false;
    }
    unsigned len = 1 << (tvb_get_uint8(tvb, offset) >> 6);
    if (tvb_reported_length_remaining(tvb, offset) < len) {
        return false;
    }
    *lenvar = (int)len;
    if (value) {
        unsigned n = tvb_get_varint(tvb, offset, -1, value, ENC_VARINT_QUIC);
        DISSECTOR_ASSERT_CMPINT(n, ==, len);
    }
    return true;
}

static int
dissect_bhttp_request_control_data(tvbuff_t *tvb, packet_info *pinfo, proto_item *pi, int offset)
{
    uint64_t method_len, scheme_len, authority_len, path_len;
    int32_t lenvar;
    proto_tree *cd_tree;
    const uint8_t *method, *path;

    cd_tree = proto_item_add_subtree(pi, ett_bhttp_request_control_data);

    proto_tree_add_item_ret_varint(cd_tree, hf_bhttp_request_method_len, tvb, offset, -1, ENC_VARINT_QUIC, &method_len, &lenvar);
    offset += lenvar;

    proto_tree_add_item_ret_string(cd_tree, hf_bhttp_request_method, tvb, offset, (uint32_t)method_len, ENC_ASCII, pinfo->pool, &method);
    offset += (uint32_t)method_len;

    proto_tree_add_item_ret_varint(cd_tree, hf_bhttp_request_scheme_len, tvb, offset, -1, ENC_VARINT_QUIC, &scheme_len, &lenvar);
    offset += lenvar;

    proto_tree_add_item(cd_tree, hf_bhttp_request_scheme, tvb, offset, (uint32_t)scheme_len, ENC_ASCII);
    offset += (uint32_t)scheme_len;

    proto_tree_add_item_ret_varint(cd_tree, hf_bhttp_request_authority_len, tvb, offset, -1, ENC_VARINT_QUIC, &authority_len, &lenvar);
    offset += lenvar;

    proto_tree_add_item(cd_tree, hf_bhttp_request_authority, tvb, offset, (uint32_t)authority_len, ENC_ASCII);
    offset += (uint32_t)authority_len;

    proto_tree_add_item_ret_varint(cd_tree, hf_bhttp_request_path_len, tvb, offset, -1, ENC_VARINT_QUIC, &path_len, &lenvar);
    offset += lenvar;

    proto_tree_add_item_ret_string(cd_tree, hf_bhttp_request_path, tvb, offset, (uint32_t)path_len, ENC_ASCII|ENC_NA, pinfo->pool, &path);
    offset += (uint32_t)path_len;

    proto_item_append_text(cd_tree, ": %s: %s", method, path);
    proto_tree* ptree = proto_tree_get_parent_tree(pi);
    proto_item_append_text(ptree, ": %s: %s", method, path);

    return offset;
}

static int
dissect_bhttp_known_field_section(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    uint64_t fs_length, length;
    int32_t lenvar;
    proto_tree *fs_tree;
    proto_item *pi;
    int target_offset, total_fields;

    pi = proto_tree_add_item(tree, hf_bhttp_known_length_field_section, tvb, offset, 1, ENC_NA);
    fs_tree = proto_item_add_subtree(pi, ett_bhttp_known_length_field_section);

    proto_tree_add_item_ret_varint(fs_tree, hf_bhttp_known_length_field_section_length, tvb, offset, -1, ENC_VARINT_QUIC, &fs_length, &lenvar);
    offset += lenvar;
    target_offset = offset + (uint32_t)fs_length;

    total_fields = 0;

    while(offset < target_offset){
        proto_tree_add_item_ret_varint(fs_tree, hf_bhttp_name_len, tvb, offset, -1, ENC_VARINT_QUIC, &length, &lenvar);
        offset += lenvar;

        proto_tree_add_item(fs_tree, hf_bhttp_name, tvb, offset, (uint32_t)length, ENC_ASCII);
        offset += (uint32_t)length;

        proto_tree_add_item_ret_varint(fs_tree, hf_bhttp_value_len, tvb, offset, -1, ENC_VARINT_QUIC, &length, &lenvar);
        offset += lenvar;

        proto_tree_add_item(fs_tree, hf_bhttp_value, tvb, offset, (uint32_t)length, ENC_ASCII);
        offset += (uint32_t)length;

        total_fields +=1;
    }

    proto_item_append_text(fs_tree, ": Length: %" PRIu64 ", Total Field lines : %" PRIu32, fs_length, total_fields);

    return offset;
}

static int
dissect_bhttp_indeterminate_field_section(tvbuff_t *tvb, proto_tree *tree, int offset, bool is_trailing)
{
    uint64_t length, content_terminator;
    int32_t lenvar;
    proto_tree *fs_tree;
    proto_item *pi;
    int original_offset, total_fields;

    pi = proto_tree_add_item(tree, hf_bhttp_indeterminate_length_field_section, tvb, offset, 1, ENC_NA);
    fs_tree = proto_item_add_subtree(pi, ett_bhttp_indeterminate_length_field_section);

    original_offset = offset;
    total_fields = 0;
    content_terminator = 1;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_tree_add_item_ret_varint(fs_tree, hf_bhttp_name_len, tvb, offset, -1, ENC_VARINT_QUIC, &length, &lenvar);
        offset += lenvar;

        /* Trailing section with 0 name length is end of message*/
        if (is_trailing && length == 0) {
            proto_item_append_text(fs_tree, ": End of message");
            break;
        }

        proto_tree_add_item(fs_tree, hf_bhttp_name, tvb, offset, (uint32_t)length, ENC_ASCII);
        offset += (uint32_t)length;

        proto_tree_add_item_ret_varint(fs_tree, hf_bhttp_value_len, tvb, offset, -1, ENC_VARINT_QUIC, &length, &lenvar);
        offset += lenvar;

        proto_tree_add_item(fs_tree, hf_bhttp_value, tvb, offset, (uint32_t)length, ENC_ASCII);
        offset += (uint32_t)length;

        total_fields +=1;

        if (!try_get_quic_varint(tvb, offset, &content_terminator, &lenvar)) {
            return offset;
        } else if (content_terminator == 0) {
            proto_tree_add_item_ret_varint(fs_tree, hf_bhttp_indeterminate_content_terminator, tvb, offset, -1, ENC_VARINT_QUIC, &content_terminator, &lenvar);
            offset += lenvar;
            break;
        }
    }

    proto_item_append_text(fs_tree, ": Length: %u, Total Field lines: %u", offset - original_offset, total_fields);
    proto_item_set_len(fs_tree, offset - original_offset);

    return offset;
}

static int
dissect_bhttp_indeterminate_content(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    uint64_t chunk_length, content_terminator;
    int32_t lenvar;
    proto_tree *c_tree;
    proto_item *pi;
    int original_offset = offset;

    content_terminator = 1;

    pi = proto_tree_add_item(tree, hf_bhttp_indeterminate_length_content, tvb, offset, 1, ENC_NA);
    c_tree = proto_item_add_subtree(pi, ett_bhttp_indeterminate_length_content);

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_tree_add_item_ret_varint(c_tree, hf_bhttp_indeterminate_length_content_chunk_length, tvb, offset, -1, ENC_VARINT_QUIC, &chunk_length, &lenvar);
        offset += lenvar;

        if (chunk_length > 0) {
            proto_tree_add_item(c_tree, hf_bhttp_known_length_content_content, tvb, offset, (uint32_t)chunk_length, ENC_NA);
            offset += (uint32_t)chunk_length;
        }

        if (!try_get_quic_varint(tvb, offset, &content_terminator, &lenvar)) {
            return offset;
        } else if (content_terminator == 0) {
            proto_tree_add_item_ret_varint(c_tree, hf_bhttp_indeterminate_content_terminator, tvb, offset, -1, ENC_VARINT_QUIC, &content_terminator, &lenvar);
            offset += lenvar;
            break;
        }
    }

    proto_item_append_text(c_tree, ": Length: %u", offset - original_offset);
    proto_item_set_len(c_tree, offset - original_offset);

    return offset;
}

static int
dissect_bhttp_known_content(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    uint64_t length;
    int32_t lenvar;
    proto_tree *c_tree;
    proto_item *pi;

    pi = proto_tree_add_item(tree, hf_bhttp_known_length_content, tvb, offset, 1, ENC_NA);
    c_tree = proto_item_add_subtree(pi, ett_bhttp_known_length_content);

    proto_tree_add_item_ret_varint(c_tree, hf_bhttp_known_length_content_length, tvb, offset, -1, ENC_VARINT_QUIC, &length, &lenvar);
    offset += lenvar;

    if (length > 0) {
        proto_tree_add_item(c_tree, hf_bhttp_known_length_content_content, tvb, offset, (uint32_t)length, ENC_NA);
        offset += (uint32_t)length;
    }

    proto_item_append_text(c_tree, ": Length: %" PRIu64, length);

    return offset;
}

static int
dissect_bhttp_padding(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    uint32_t pad_len;
    proto_item *pi;

    pad_len = 1 + tvb_skip_uint8(tvb, offset, tvb_reported_length_remaining(tvb, offset), '\0') - offset;
    pi = proto_tree_add_uint(tree, hf_bhttp_padding_length, tvb, offset, 0, pad_len);
    proto_item_set_generated(pi);
    proto_item_append_text(pi, ": Length: %u", pad_len);
    offset += pad_len - 1;
    return offset;
}

static int
dissect_bhttp_informational_response_control_data(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    uint64_t status;
    int32_t lenvar;
    proto_item *pi;
    proto_tree *cd_tree;

    pi = proto_tree_add_item(tree, hf_bhttp_info_response_control_data, tvb, offset, 1, ENC_NA);
    cd_tree = proto_item_add_subtree(pi, ett_bhttp_info_response_control_data);

    proto_tree_add_item_ret_varint(cd_tree, hf_bhttp_info_response_status, tvb, offset, -1, ENC_VARINT_QUIC, &status, &lenvar);
    proto_item_append_text(cd_tree, ": Status: %" PRIu64, status);
    proto_item_append_text(tree, ": Status: %" PRIu64, status);
    offset += lenvar;

    return offset;
}

static int
dissect_bhttp_final_response_control_data(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    uint64_t status;
    int32_t lenvar;
    proto_item *pi;
    proto_tree *cd_tree;

    pi = proto_tree_add_item(tree, hf_bhttp_final_response_control_data, tvb, offset, 1, ENC_NA);
    cd_tree = proto_item_add_subtree(pi, ett_bhttp_final_response_control_data);

    proto_tree_add_item_ret_varint(cd_tree, hf_bhttp_final_response_status, tvb, offset, -1, ENC_VARINT_QUIC, &status, &lenvar);
    proto_item_append_text(cd_tree, ": Status: %" PRIu64, status);
    proto_item_append_text(tree, ": Status: %" PRIu64, status);
    offset += lenvar;

    return offset;
}

static int
dissect_bhttp_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_item *ti_cd;

    ti_cd = proto_tree_add_item(tree, hf_bhttp_request_control_data, tvb, offset, 1, ENC_NA);
    offset = dissect_bhttp_request_control_data(tvb, pinfo, ti_cd, offset);

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        offset = dissect_bhttp_known_field_section(tvb, tree, offset);
    }

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        offset = dissect_bhttp_known_content(tvb, tree, offset);
    }

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        offset = dissect_bhttp_known_field_section(tvb, tree, offset);
    }

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        offset = dissect_bhttp_padding(tvb, tree, offset);
    }

    return offset;
}

static int
dissect_bhttp_response(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    uint64_t status;
    int32_t lenvar;
    bool final_response = false;

    while (tvb_reported_length_remaining(tvb, offset) > 0 && !final_response) {
        if (!try_get_quic_varint(tvb, offset, &status, &lenvar)) {
            return offset;
        }

        if (status >=100 && status <= 199) {
            offset = dissect_bhttp_informational_response_control_data(tvb, tree, offset);
            if (tvb_reported_length_remaining(tvb, offset) > 0) {
                offset = dissect_bhttp_known_field_section(tvb, tree, offset);
            }
        } else if (status >= 200 && status <= 599) {

            offset = dissect_bhttp_final_response_control_data(tvb, tree, offset);

            if (tvb_reported_length_remaining(tvb, offset) > 0) {
                offset = dissect_bhttp_known_field_section(tvb, tree, offset);
            }

            if (tvb_reported_length_remaining(tvb, offset) > 0) {
                offset = dissect_bhttp_known_content(tvb, tree, offset);
            }

            if (tvb_reported_length_remaining(tvb, offset) > 0) {
                offset = dissect_bhttp_known_field_section(tvb, tree, offset);
            }

            final_response = true;
        } else {
            break;
        }
    }


    return offset;
}

static int
dissect_bhttp_indeterminate_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_item *ti_cd;

    ti_cd = proto_tree_add_item(tree, hf_bhttp_request_control_data, tvb, offset, 1, ENC_NA);
    offset = dissect_bhttp_request_control_data(tvb, pinfo, ti_cd, offset);

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        offset = dissect_bhttp_indeterminate_field_section(tvb, tree, offset, false);
    }

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        offset = dissect_bhttp_indeterminate_content(tvb, tree, offset);
    }

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        offset = dissect_bhttp_indeterminate_field_section(tvb, tree, offset, true);
    }

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        offset = dissect_bhttp_padding(tvb, tree, offset);
    }

    return offset;
}

static int
dissect_bhttp_indeterminate_response(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    uint64_t status;
    int32_t lenvar;
    bool final_response = false;

    while (tvb_reported_length_remaining(tvb, offset) > 0 && !final_response) {
        if (!try_get_quic_varint(tvb, offset, &status, &lenvar)) {
            return offset;
        }

        if (status >=100 && status <= 199) {
            offset = dissect_bhttp_informational_response_control_data(tvb, tree, offset);
            if (tvb_reported_length_remaining(tvb, offset) > 0) {
                offset = dissect_bhttp_indeterminate_field_section(tvb, tree, offset, false);
            }
        } else if (status >= 200 && status <= 599) {
            offset = dissect_bhttp_final_response_control_data(tvb, tree, offset);

            if (tvb_reported_length_remaining(tvb, offset) > 0) {
                offset = dissect_bhttp_indeterminate_field_section(tvb, tree, offset, false);
            }

            if (tvb_reported_length_remaining(tvb, offset) > 0) {
                offset = dissect_bhttp_indeterminate_content(tvb, tree, offset);
            }

            if (tvb_reported_length_remaining(tvb, offset) > 0) {
                offset = dissect_bhttp_indeterminate_field_section(tvb, tree, offset, true);
            }

            final_response = true;
        } else {
            break;
        }
    }


    return offset;
}

static int
dissect_bhttp_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    uint64_t framing_indicator;
    int32_t lenvar;
    proto_item *ti_ft;
    proto_tree *ft_tree;

    unsigned   orig_offset = offset;

    ti_ft = proto_tree_add_item(tree, hf_bhttp_frame, tvb, offset, 1, ENC_BIG_ENDIAN);
    ft_tree = proto_item_add_subtree(ti_ft, ett_bhttp_ft);

    proto_tree_add_item_ret_varint(ft_tree, hf_bhttp_framing_indicator, tvb, offset, -1, ENC_VARINT_QUIC, &framing_indicator, &lenvar);
    proto_item_set_text(ti_ft, "%s", val64_to_str_const(framing_indicator, bhttp_frame_indicators, "Unknown"));

    offset += lenvar;

    switch (framing_indicator)
    {
    case BHTTP_KNOWN_LENGTH_REQUEST:
        offset = dissect_bhttp_request(tvb, pinfo, ft_tree, offset);
        break;
    case BHTTP_KNOWN_LENGTH_RESPONSE:
        offset = dissect_bhttp_response(tvb, ft_tree, offset);
        break;
    case BHTTP_INDETERMINATE_LENGTH_REQUEST:
        offset = dissect_bhttp_indeterminate_request(tvb, pinfo, ft_tree, offset);
        break;
    case BHTTP_INDETERMINATE_LENGTH_RESPONSE:
        offset = dissect_bhttp_indeterminate_response(tvb, ft_tree, offset);
        break;
    default:
        break;
    }

    col_append_sep_str(pinfo->cinfo, COL_INFO, "", val64_to_str_const(framing_indicator, bhttp_frame_indicators, "Unknown"));

    proto_item_set_len(ti_ft, offset - orig_offset);

    return offset;
}

static int
dissect_bhttp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *bhttp_tree;
    int offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "bHTTP");

    ti = proto_tree_add_item(tree, proto_bhttp, tvb, 0, -1, ENC_NA);
    bhttp_tree = proto_item_add_subtree(ti, ett_bhttp);

    dissect_bhttp_frame(tvb, pinfo, bhttp_tree, offset);
    return tvb_captured_length(tvb);
}

void
proto_register_bhttp(void)
{
    static hf_register_info hf[] = {
        { &hf_bhttp_frame,
          { "Frame", "bhttp.frame",
            FT_UINT64, BASE_HEX|BASE_VAL64_STRING, VALS64(bhttp_frame_indicators), 0x0,
            NULL, HFILL }
        },

        { &hf_bhttp_framing_indicator,
          { "Framing indicator", "bhttp.framing_indicator",
            FT_UINT64, BASE_HEX|BASE_VAL64_STRING, VALS64(bhttp_frame_indicators), 0x0,
            NULL, HFILL }
        },

        { &hf_bhttp_request_control_data,
          { "Request control data", "bhttp.request",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_bhttp_request_method_len,
          { "Request method length", "bhttp.request.method_len",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_bhttp_request_method,
          { "Request method", "bhttp.request.method",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_bhttp_request_scheme_len,
          { "Request scheme length", "bhttp.request.scheme_len",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_bhttp_request_scheme,
          { "Request scheme", "bhttp.request.scheme",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_bhttp_request_authority_len,
          { "Request authority length", "bhttp.request.authority_len",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_bhttp_request_authority,
          { "Request authority", "bhttp.request.authority",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_bhttp_request_path_len,
          { "Request path length", "bhttp.request.path_len",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_bhttp_request_path,
          { "Request path", "bhttp.request.path",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_bhttp_info_response_control_data,
          { "Known-length informational response control data", "bhttp.response.informational",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_bhttp_final_response_control_data,
          { "Final response control data", "bhttp.response.final",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_bhttp_final_response_status,
          { "Status code", "bhttp.response.final.status",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_bhttp_info_response_status,
          { "Status code", "bhttp.response.informational.status",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_bhttp_known_length_field_section,
          { "Known-length field section", "bhttp.known_length_field_section",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_bhttp_known_length_field_section_length,
          { "Known-length field section length", "bhttp.known_length_field_section.len",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_bhttp_indeterminate_length_field_section,
          { "Indeterminate-length field section", "bhttp.indeterminate_length_field_section",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_bhttp_indeterminate_content_terminator,
          { "Indeterminate-length content terminator", "bhttp.indeterminate_content_terminator",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_bhttp_name_len,
          { "Name length", "bhttp.name_len",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_bhttp_name,
          { "Name", "bhttp.name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_bhttp_value_len,
          { "Value length", "bhttp.value_len",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_bhttp_value,
          { "Value", "bhttp.value",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_bhttp_known_length_content,
          { "Known-length content", "bhttp.known_length_content",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_bhttp_known_length_content_length,
          { "Content length", "bhttp.known_length_content.len",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_bhttp_known_length_content_content,
          { "Content", "bhttp.known_length_content.content",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_bhttp_indeterminate_length_content,
          { "Indeterminate-length content", "bhttp.indeterminate_length_content",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_bhttp_indeterminate_length_content_chunk_length,
          { "Chunk length", "bhttp.indeterminate_length_content.chunk_len",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_bhttp_padding_length,
          { "Padding Length", "bhttp.padding_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

    };

    static int *ett[] = {
        &ett_bhttp,
        &ett_bhttp_ft,
        &ett_bhttp_request_control_data,
        &ett_bhttp_known_length_informational_response,
        &ett_bhttp_info_response_control_data,
        &ett_bhttp_final_response_control_data,
        &ett_bhttp_known_length_field_section,
        &ett_bhttp_indeterminate_length_field_section,
        &ett_bhttp_response_control_data,
        &ett_bhttp_known_length_content,
        &ett_bhttp_indeterminate_length_content,
    };

    proto_bhttp = proto_register_protocol("Binary representation of HTTP Messages", "Binary HTTP", "bhttp");

    proto_register_field_array(proto_bhttp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    bhttp_handle = register_dissector("bhttp", dissect_bhttp, proto_bhttp);
}

void
proto_reg_handoff_bhttp(void)
{
    dissector_add_string("media_type", "message/bhttp", bhttp_handle);
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
