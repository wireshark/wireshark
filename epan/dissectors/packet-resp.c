/* packet-resp.c
 * Routines for Redis Client/Server RESP (REdis Serialization Protocol) v2 as
 * documented by https://redis.io/topics/protocol
 * and RESP v3 as documented by:
 * https://github.com/redis/redis-specifications/blob/master/protocol/RESP3.md
 * https://redis.io/docs/latest/develop/reference/protocol-spec/
 *
 * Copyright 2022 Ryan Doyle <ryan <AT> doylenet dot net>
 * Modifications for RESP3 support by Corentin B <corentinb.pro@pm.me> in 2025
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"
#include "packet-tcp.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/prefs.h>

#define RESP_PORT 6379
#define CRLF_LENGTH 2
#define RESP_TOKEN_PREFIX_LENGTH 1
#define MAX_ARRAY_DEPTH_TO_RECURSE 30 //also used for maps and other similar types
#define BULK_STRING_MAX_DISPLAY 100 //also used for similar types such as Verbatim String and Bulk Error
#define VERBATIM_STRING_ENCODING_LENGTH 3
#define RESP_NULL_STRING (-1)
#define RESP_NULL_ARRAY (-1)
#define RESP_REQUEST(pinfo) ((pinfo)->match_uint == (pinfo)->destport)
#define RESP_RESPONSE(pinfo) ((pinfo)->match_uint == (pinfo)->srcport)
#define DESEGMENT_ENABLED(pinfo) ((pinfo)->can_desegment && resp_desegment)

static dissector_handle_t resp_handle;
static bool resp_desegment = true;

static int proto_resp;

static int ett_resp;
static int ett_resp_bulk_string;
static int ett_resp_bulk_error;
static int ett_resp_array;
static int ett_resp_verbatim_string;
static int ett_resp_set;
static int ett_resp_push;
static int ett_resp_map;
static int ett_resp_map_entry;
static int ett_resp_attribute;
static int ett_resp_attribute_entry;

static expert_field ei_resp_partial;
static expert_field ei_resp_malformed_length;
static expert_field ei_resp_array_recursion_too_deep;
static expert_field ei_resp_reassembled_in_next_frame;
static expert_field ei_resp_invalid_boolean_value;
static expert_field ei_resp_invalid_big_number_value;

static int hf_resp_string;
static int hf_resp_error;
static int hf_resp_bulk_string;
static int hf_resp_bulk_string_length;
static int hf_resp_bulk_string_value;
static int hf_resp_integer;
static int hf_resp_array;
static int hf_resp_array_length;
static int hf_resp_fragment;

// RESP3 types
static int hf_resp_null;
static int hf_resp_boolean;
static int hf_resp_double;
static int hf_resp_verbatim_string;
static int hf_resp_verbatim_string_length;
static int hf_resp_verbatim_string_value;
static int hf_resp_verbatim_string_encoding;
static int hf_resp_bulk_error;
static int hf_resp_bulk_error_length;
static int hf_resp_bulk_error_value;
static int hf_resp_big_number;
static int hf_resp_set;
static int hf_resp_set_length;
static int hf_resp_push;
static int hf_resp_push_length;
static int hf_resp_map;
static int hf_resp_map_length;
static int hf_resp_attribute;
static int hf_resp_attribute_length;

static int dissect_resp_loop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int array_depth, int64_t expected_elements);
static int dissect_resp_entries(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int array_depth, int64_t expected_entries, int ett_entry_type);
static void resp_bulk_string_enhance_display(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree, int array_depth, int bulk_string_length, const char *bulk_string_as_str, const char data_type);
void proto_reg_handoff_resp(void);
void proto_register_resp(void);

static bool prefs_try_json_on_string = TRUE;

static dissector_handle_t json_handle;

static int dissect_resp_string(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int string_length, int array_depth) {
    const char *string_value;

    string_value = (char*)tvb_get_string_enc(pinfo->pool, tvb, offset + RESP_TOKEN_PREFIX_LENGTH,
                                      string_length - RESP_TOKEN_PREFIX_LENGTH, ENC_ASCII);
    proto_tree_add_string(tree, hf_resp_string, tvb, offset, string_length + CRLF_LENGTH, string_value);

    /* Simple strings can be used as a response for commands */
    if (RESP_RESPONSE(pinfo) && array_depth == 0) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, " ", string_value);
    }

    return string_length + CRLF_LENGTH;
}

static int dissect_resp_null(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int string_length, int array_depth) {
    if (string_length != RESP_TOKEN_PREFIX_LENGTH) {
        expert_add_info(pinfo, tree, &ei_resp_malformed_length);
        return string_length + CRLF_LENGTH;
    }

    proto_tree_add_item(tree, hf_resp_null, tvb, offset,CRLF_LENGTH, ENC_NA);
    if (RESP_RESPONSE(pinfo) && array_depth == 0) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "Null");
    }
    return string_length + CRLF_LENGTH;
}

static int dissect_resp_boolean(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int string_length, int array_depth) {
    const char value = tvb_get_uint8(tvb, offset + 1);
    bool bool_value;
    switch (value) {
        case 't':
            bool_value = true;
            break;
        case 'f':
            bool_value = false;
            break;
        default:
            expert_add_info(pinfo, tree, &ei_resp_invalid_boolean_value);
            return string_length + CRLF_LENGTH;
    }

    proto_tree_add_boolean(tree, hf_resp_boolean, tvb, offset + 1, 1, bool_value);

    if (RESP_RESPONSE(pinfo) && array_depth == 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " Boolean(%s)", bool_value ? "True" : "False");
    }

    return string_length + CRLF_LENGTH;
}

static int dissect_resp_double(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int string_length, int array_depth) {
    const char *string_value = (char*)tvb_get_string_enc(pinfo->pool, tvb, offset + RESP_TOKEN_PREFIX_LENGTH,
                                      string_length - RESP_TOKEN_PREFIX_LENGTH, ENC_ASCII);
    char *endptr = 0;
    /* Should probably do some error checking in case the packet is malformed */
    const double decimal = g_ascii_strtod(string_value, &endptr);

    proto_tree_add_double(tree, hf_resp_double, tvb, offset, string_length + CRLF_LENGTH, decimal);

    if (RESP_RESPONSE(pinfo) && array_depth == 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " Double(%f)", decimal);
    }

    return string_length + CRLF_LENGTH;
}

static int dissect_resp_error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int string_length) {
    const char *error_value;

    error_value = (char*)tvb_get_string_enc(pinfo->pool, tvb, offset + RESP_TOKEN_PREFIX_LENGTH,
                                     string_length - RESP_TOKEN_PREFIX_LENGTH, ENC_ASCII);
    proto_tree_add_string(tree, hf_resp_error, tvb, offset, string_length + CRLF_LENGTH, error_value);
    col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", error_value);
    return string_length + CRLF_LENGTH;
}

static int dissect_resp_big_number(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int string_length, int array_depth) {
    const char *string_value;

    if (string_length < 1) {
        return string_length + CRLF_LENGTH;
    }

    string_value = (char*)tvb_get_string_enc(pinfo->pool, tvb, offset + RESP_TOKEN_PREFIX_LENGTH,
                                      string_length - RESP_TOKEN_PREFIX_LENGTH, ENC_ASCII);

    proto_item *resp_big_number_item = proto_tree_add_string(tree, hf_resp_big_number, tvb, offset, string_length + CRLF_LENGTH, string_value);

    if (!g_ascii_isdigit(string_value[0]) && string_value[0] != '+' && string_value[0] != '-') {
        expert_add_info(pinfo, resp_big_number_item, &ei_resp_invalid_big_number_value);
        return string_length + CRLF_LENGTH;
    }

    for (int i = 1; i<string_length - 1; i++) {
        if (!g_ascii_isdigit(string_value[i])){
            expert_add_info(pinfo, resp_big_number_item, &ei_resp_invalid_big_number_value);
            return string_length + CRLF_LENGTH;
        }
    }

    if (RESP_RESPONSE(pinfo) && array_depth == 0) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, " ", string_value);
    }

    return string_length + CRLF_LENGTH;
}

static int dissect_resp_bulk_string(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int bulk_string_string_length, int array_depth, const char data_type) {
    const char *bulk_string_length_as_str;
    int bulk_string_length;
    int bulk_string_captured_length;
    int bulk_string_captured_length_with_crlf;
    proto_item *resp_string_item;
    proto_tree *resp_string_tree;
    int hf_resp_bulk_x;
    int hf_resp_bulk_x_value;
    int hf_resp_bulk_x_length;
    int ett_resp_bulk_x;

    switch (data_type) {
        case '$':
            hf_resp_bulk_x = hf_resp_bulk_string;
            hf_resp_bulk_x_value = hf_resp_bulk_string_value;
            hf_resp_bulk_x_length = hf_resp_bulk_string_length;
            ett_resp_bulk_x = ett_resp_bulk_string;
            break;
        case '!':
            hf_resp_bulk_x = hf_resp_bulk_string;
            hf_resp_bulk_x_value = hf_resp_bulk_string_value;
            hf_resp_bulk_x_length = hf_resp_bulk_string_length;
            ett_resp_bulk_x = ett_resp_bulk_error;
            break;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
    }

    bulk_string_length_as_str = (char*)tvb_get_string_enc(pinfo->pool, tvb, offset + RESP_TOKEN_PREFIX_LENGTH,
                                                   bulk_string_string_length - RESP_TOKEN_PREFIX_LENGTH, ENC_ASCII);
    bulk_string_length = (int)g_ascii_strtoll(bulk_string_length_as_str, NULL, 10);
    /* Negative string lengths */
    if (bulk_string_length < 0) {
        /* NULL string */
        resp_string_item = proto_tree_add_item(tree, hf_resp_bulk_x, tvb, offset,bulk_string_string_length + CRLF_LENGTH, ENC_NA);
        resp_string_tree = proto_item_add_subtree(resp_string_item, ett_resp_bulk_x);
        proto_tree_add_int(resp_string_tree, hf_resp_bulk_x_length, tvb, offset, bulk_string_string_length + CRLF_LENGTH, bulk_string_length);
        if (bulk_string_length == RESP_NULL_STRING) {
            proto_item_append_text(resp_string_item, ": [NULL]");
        } else {
            expert_add_info(pinfo, resp_string_item, &ei_resp_malformed_length);
        }
        return bulk_string_string_length + CRLF_LENGTH;
    }

    /* We have either a bulk string or an empty string */
    int remaining_bytes_for_bulkstring = tvb_captured_length_remaining(tvb, offset + bulk_string_string_length + CRLF_LENGTH);
    /* Do we have enough bytes in the tvb for what was reported in the string length? */
    int is_fragmented = remaining_bytes_for_bulkstring < bulk_string_length + CRLF_LENGTH;
    if (is_fragmented) {
        if (DESEGMENT_ENABLED(pinfo)) {
            /* Desegment at the start of the bulk string instead of part way through */
            pinfo->desegment_offset = offset;
            /* We know how many bytes we will need */
            pinfo->desegment_len = bulk_string_length + CRLF_LENGTH - remaining_bytes_for_bulkstring;
            return -1;
        }
        /* There's no CRLF, we didn't get all the bytes needed */
        bulk_string_captured_length = remaining_bytes_for_bulkstring;
        bulk_string_captured_length_with_crlf = remaining_bytes_for_bulkstring;
        col_append_str(pinfo->cinfo, COL_INFO, " [partial]");
    } else {
        bulk_string_captured_length = bulk_string_length;
        bulk_string_captured_length_with_crlf = bulk_string_length + CRLF_LENGTH;
    }

    /* Add protocol items */
    resp_string_item = proto_tree_add_item(tree, hf_resp_bulk_x, tvb, offset,
                                           bulk_string_string_length + CRLF_LENGTH + bulk_string_captured_length_with_crlf,ENC_NA);
    if (is_fragmented) {
        expert_add_info(pinfo, resp_string_item, &ei_resp_partial);
    }
    resp_string_tree = proto_item_add_subtree(resp_string_item, ett_resp_bulk_x);
    proto_tree_add_int(resp_string_tree, hf_resp_bulk_x_length, tvb, offset, bulk_string_string_length + CRLF_LENGTH, bulk_string_length);
    offset += bulk_string_string_length + CRLF_LENGTH;
    if (bulk_string_captured_length > 0) {
        proto_tree_add_item(resp_string_tree, hf_resp_bulk_x_value, tvb, offset, bulk_string_captured_length, ENC_NA);
    }

    /* Enhance display */
    const char *bulk_string_as_str = (char*)tvb_get_string_enc(pinfo->pool, tvb, offset, bulk_string_captured_length, ENC_NA);
    if (g_str_is_ascii(bulk_string_as_str)) {
        proto_item_append_text(resp_string_item, ": %s", bulk_string_as_str);
        resp_bulk_string_enhance_display(pinfo, tvb, resp_string_tree, array_depth, bulk_string_length, bulk_string_as_str, '$');
    } else if(array_depth == 0) {
        /* Otherwise, just append that we captured bulk strings (and only do so if they aren't part of an array */
        col_append_fstr(pinfo->cinfo, COL_INFO, " BulkString(%d)", bulk_string_length);
    }

    return bulk_string_string_length + CRLF_LENGTH + bulk_string_captured_length_with_crlf;
}

/* Maybe rename? also used for Verbatim String and Bulk Error */
static void resp_bulk_string_enhance_display(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree, int array_depth, int bulk_string_length, const char *bulk_string_as_str, const char data_type) {
    char *data_type_format_string;
        switch (data_type) {
            case '$':
                data_type_format_string = " BulkString(%d)";
                break;
            case '=':
                data_type_format_string = " VerbatimString(%d)";
                break;
            default:
                return;
        }
    /* Request commands are arrays */
    if (RESP_REQUEST(pinfo) && array_depth == 1) {
        if (bulk_string_length < BULK_STRING_MAX_DISPLAY) {
            col_append_sep_str(pinfo->cinfo, COL_INFO, " ", bulk_string_as_str);
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, data_type_format_string, bulk_string_length);
        }

        /* Is it worth trying the JSON dissector? */
        if (prefs_try_json_on_string &&                 /* preference enabled */
            bulk_string_length >= 2 &&                  /* at least 2 chars long */
            /* and has format {..} or [..] */
            ((bulk_string_as_str[0] == '{' && bulk_string_as_str[bulk_string_length-1] == '}') ||
             (bulk_string_as_str[0] == '[' && bulk_string_as_str[bulk_string_length-1] == ']'))) {

            /* Create TVB just with string */
            tvbuff_t *json_tvb = tvb_new_child_real_data(tvb, (const uint8_t*)bulk_string_as_str, bulk_string_length, bulk_string_length);
            add_new_data_source(pinfo, json_tvb, "JSON string");

            /* Call JSON dissector on this TVB */
            TRY {
                call_dissector_only(json_handle, json_tvb, pinfo, tree, NULL);
            }
            CATCH_ALL {
            }
            ENDTRY
        }
        return;
    }
    /* Print responses with zero depth */
    if (RESP_RESPONSE(pinfo) && array_depth == 0 && bulk_string_length < BULK_STRING_MAX_DISPLAY) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, " ", bulk_string_as_str);
        return;
    }
    /* Otherwise, just display that there is a bulk string in the response (for top-level) */
    if (array_depth == 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, data_type_format_string, bulk_string_length);
    }
}

static int dissect_resp_verbatim_string(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int verbatim_string_string_length, int array_depth) {
    const char *verbatim_string_length_as_str;
    int verbatim_string_length;
    int verbatim_string_captured_length;
    int verbatim_string_captured_length_with_crlf;
    proto_item *resp_string_item;
    proto_tree *resp_string_tree;

    verbatim_string_length_as_str = (char*)tvb_get_string_enc(pinfo->pool, tvb, offset + RESP_TOKEN_PREFIX_LENGTH,
                                                   verbatim_string_string_length - RESP_TOKEN_PREFIX_LENGTH, ENC_ASCII);
    verbatim_string_length = (int)g_ascii_strtoll(verbatim_string_length_as_str, NULL, 10);
    /* Negative string lengths */
    if (verbatim_string_length < 0) {
        /* NULL string */
        resp_string_item = proto_tree_add_item(tree, hf_resp_verbatim_string, tvb, offset,verbatim_string_string_length + CRLF_LENGTH, ENC_NA);
        resp_string_tree = proto_item_add_subtree(resp_string_item, ett_resp_verbatim_string);
        proto_tree_add_int(resp_string_tree, hf_resp_bulk_string_length, tvb, offset, verbatim_string_string_length + CRLF_LENGTH, verbatim_string_length);
        expert_add_info(pinfo, resp_string_item, &ei_resp_malformed_length);
        return verbatim_string_string_length + CRLF_LENGTH;
    }

    /* We have either a verbatim string or an empty string */
    int remaining_bytes_for_verbatimstring = tvb_captured_length_remaining(tvb, offset + verbatim_string_string_length + CRLF_LENGTH);
    /* Do we have enough bytes in the tvb for what was reported in the string length? */
    int is_fragmented = remaining_bytes_for_verbatimstring < verbatim_string_length + CRLF_LENGTH;
    if (is_fragmented) {
        if (DESEGMENT_ENABLED(pinfo)) {
            /* Desegment at the start of the bulk string instead of part way through */
            pinfo->desegment_offset = offset;
            /* We know how many bytes we will need */
            pinfo->desegment_len = verbatim_string_length + CRLF_LENGTH - remaining_bytes_for_verbatimstring;
            return -1;
        }
        /* There's no CRLF, we didn't get all the bytes needed */
        verbatim_string_captured_length = remaining_bytes_for_verbatimstring;
        verbatim_string_captured_length_with_crlf = remaining_bytes_for_verbatimstring;
        col_append_str(pinfo->cinfo, COL_INFO, " [partial]");
    } else {
        verbatim_string_captured_length = verbatim_string_length;
        verbatim_string_captured_length_with_crlf = verbatim_string_length + CRLF_LENGTH;
    }

    /* Add protocol items */
    resp_string_item = proto_tree_add_item(tree, hf_resp_verbatim_string, tvb, offset,
                                           verbatim_string_string_length + CRLF_LENGTH + verbatim_string_captured_length_with_crlf,ENC_NA);
    if (is_fragmented) {
        expert_add_info(pinfo, resp_string_item, &ei_resp_partial);
    }
    resp_string_tree = proto_item_add_subtree(resp_string_item, ett_resp_verbatim_string);
    proto_tree_add_int(resp_string_tree, hf_resp_verbatim_string_length, tvb, offset, verbatim_string_string_length + CRLF_LENGTH, verbatim_string_length);
    offset += verbatim_string_string_length + CRLF_LENGTH;
    if (verbatim_string_captured_length > 0) {
        const char *enc_value = (char*)tvb_get_string_enc(pinfo->pool, tvb, offset,VERBATIM_STRING_ENCODING_LENGTH, ENC_ASCII);
        proto_tree_add_string(resp_string_tree, hf_resp_verbatim_string_encoding, tvb, offset, VERBATIM_STRING_ENCODING_LENGTH, enc_value);
        offset += VERBATIM_STRING_ENCODING_LENGTH + 1; // skip the ':' that separates encoding from the actual value
        proto_tree_add_item(resp_string_tree, hf_resp_verbatim_string_value, tvb, offset, verbatim_string_captured_length - VERBATIM_STRING_ENCODING_LENGTH, ENC_NA);
    }

    /* Enhance display */
    const char *verbatim_string_as_str = (char*)tvb_get_string_enc(pinfo->pool, tvb, offset, verbatim_string_captured_length - VERBATIM_STRING_ENCODING_LENGTH, ENC_NA);
    // printf("verbatim_string_as_str: %s", verbatim_string_as_str);
    if (g_str_is_ascii(verbatim_string_as_str)) {
        proto_item_append_text(resp_string_item, ": %s", verbatim_string_as_str);
        resp_bulk_string_enhance_display(pinfo, tvb, resp_string_tree, array_depth, verbatim_string_length, verbatim_string_as_str, '=');
    } else if(array_depth == 0) {
        /* Otherwise, just append that we captured bulk strings (and only do so if they aren't part of an array */
        col_append_fstr(pinfo->cinfo, COL_INFO, " VerbatimString(%d)", verbatim_string_length);
    }

    return verbatim_string_string_length + CRLF_LENGTH + verbatim_string_captured_length_with_crlf;
}

static int dissect_resp_integer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int bulk_string_string_length, int array_depth) {
    const char *integer_as_string;
    int64_t integer;
    integer_as_string = (char*)tvb_get_string_enc(pinfo->pool, tvb, offset + RESP_TOKEN_PREFIX_LENGTH,
                                                   bulk_string_string_length - RESP_TOKEN_PREFIX_LENGTH, ENC_ASCII);
    integer = g_ascii_strtoll(integer_as_string, NULL, 10);
    proto_tree_add_int64(tree, hf_resp_integer, tvb, offset, bulk_string_string_length + CRLF_LENGTH, integer);
    /* Simple integers can be used as a response for commands */
    if (RESP_RESPONSE(pinfo) && array_depth == 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " %" PRId64, integer);
    }
    return bulk_string_string_length + CRLF_LENGTH;
}

// NOLINTNEXTLINE(misc-no-recursion)
static int dissect_resp_array(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int string_length, int array_depth, char data_type) {
    int hf_resp_x;
    int hf_resp_x_length;
    int ett_resp_x;
    char *data_type_format;

    switch (data_type) {
        case '*':
            hf_resp_x = hf_resp_array;
            hf_resp_x_length = hf_resp_array_length;
            ett_resp_x = ett_resp_array;
            data_type_format = " Array(%" PRId64 ")";
            break;
        case '~':
            hf_resp_x = hf_resp_set;
            hf_resp_x_length = hf_resp_set_length;
            ett_resp_x = ett_resp_set;
            data_type_format = " Set(%" PRId64 ")";
            break;
        case '>':
            hf_resp_x = hf_resp_push;
            hf_resp_x_length = hf_resp_push_length;
            ett_resp_x = ett_resp_push;
            data_type_format = " Push(%" PRId64 ")";
            break;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
    }

    const char *array_length_as_string = (char*)tvb_get_string_enc(pinfo->pool, tvb, offset + RESP_TOKEN_PREFIX_LENGTH,
                                                        string_length - RESP_TOKEN_PREFIX_LENGTH, ENC_ASCII);
    int64_t array_length = g_ascii_strtoll(array_length_as_string, NULL, 10);

    /* We'll fix up the length later when we know how long it actually was */
    proto_item *array_item = proto_tree_add_item(tree, hf_resp_x, tvb, offset, string_length + CRLF_LENGTH, ENC_NA);

    proto_tree *array_tree = proto_item_add_subtree(array_item, ett_resp_x);
    proto_tree_add_int64(array_tree, hf_resp_x_length, tvb, offset, string_length + CRLF_LENGTH, array_length);

    /* Null array, no elements */
    if (array_length <= 0) {
        switch (array_length) {
            case RESP_NULL_ARRAY:
                proto_item_append_text(array_item, ": NULL");
                break;
            case 0:
                proto_item_append_text(array_item, ": Empty");
                break;
            default:
                expert_add_info(pinfo, array_item, &ei_resp_malformed_length);
                break;
        }
        return string_length + CRLF_LENGTH;
    }

    proto_item_append_text(array_item, ": Length %" PRId64, array_length);

    /* Bail out if we're recursing too much */
    if (array_depth > MAX_ARRAY_DEPTH_TO_RECURSE) {
        expert_add_info(pinfo, array_item, &ei_resp_array_recursion_too_deep);
        return string_length + CRLF_LENGTH;
    }

    /* Non-empty array, but we've ran out of bytes in the tvb */
    if (!tvb_offset_exists(tvb, offset + string_length + CRLF_LENGTH) && array_length > 0) {
        if (DESEGMENT_ENABLED(pinfo)) {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            return -1;
        }
        expert_add_info(pinfo, array_item, &ei_resp_partial);
    }

    /* Add to the info column for responses. Don't do this for requests which are typically commands.
     * These are extracted in the bulk string dissector  */
    if (RESP_RESPONSE(pinfo) && array_depth == 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, data_type_format , array_length);
    }


    int dissected_offset = dissect_resp_loop(tvb, pinfo, array_tree, offset + string_length + CRLF_LENGTH,array_depth + 1, array_length);
    if (dissected_offset == -1) {
        /* Override any desegment lengths previously set as we want to start from the beginning of the array */
        pinfo->desegment_offset = offset;
        pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
        /* We've partially decoded some of the array, but we've asked for all. It will still show in the proto tree so give an
         * indication as to why it's only partially there*/
        expert_add_info(pinfo, array_item, &ei_resp_reassembled_in_next_frame);
        return -1;
    }
    proto_item_set_len(array_item, dissected_offset - offset);
    return dissected_offset - offset;
}

// NOLINTNEXTLINE(misc-no-recursion)
static int dissect_resp_map(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int string_length, int array_depth, char data_type) {
    int hf_resp_x;
    int hf_resp_x_length;
    int ett_resp_x;
    int ett_resp_x_entry;
    char *data_type_format;

    switch (data_type) {
        case '%':
            hf_resp_x = hf_resp_map;
            hf_resp_x_length = hf_resp_map_length;
            ett_resp_x = ett_resp_map;
            ett_resp_x_entry = ett_resp_map_entry;
            data_type_format = " Map(%" PRId64 ")";
            break;
        case '|':
            hf_resp_x = hf_resp_attribute;
            hf_resp_x_length = hf_resp_attribute_length;
            ett_resp_x = ett_resp_attribute;
            ett_resp_x_entry = ett_resp_attribute_entry;
            data_type_format = " Attribute(%" PRId64 ")";
            break;
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
    }

    const char *nb_entries_as_string = (char*)tvb_get_string_enc(pinfo->pool, tvb, offset + RESP_TOKEN_PREFIX_LENGTH,
                                                        string_length - RESP_TOKEN_PREFIX_LENGTH, ENC_ASCII);
    int64_t nb_entries = g_ascii_strtoll(nb_entries_as_string, NULL, 10);

    /* We'll fix up the length later when we know how long it actually was */
    proto_item *map_item = proto_tree_add_item(tree, hf_resp_x, tvb, offset, string_length + CRLF_LENGTH, ENC_NA);

    proto_tree *map_tree = proto_item_add_subtree(map_item, ett_resp_x);
    proto_tree_add_int64(map_tree, hf_resp_x_length, tvb, offset, string_length + CRLF_LENGTH, nb_entries);


    if (nb_entries == 0) {
        proto_item_append_text(map_item, ": Empty");
        return string_length + CRLF_LENGTH;
    } else if (nb_entries < 0) {
        expert_add_info(pinfo, map_item, &ei_resp_malformed_length);
        return string_length + CRLF_LENGTH;
    }

    proto_item_append_text(map_item, ": Length %" PRId64, nb_entries);

    /* Bail out if we're recursing too much */
    if (array_depth > MAX_ARRAY_DEPTH_TO_RECURSE) {
        expert_add_info(pinfo, map_item, &ei_resp_array_recursion_too_deep);
        return string_length + CRLF_LENGTH;
    }

    /* Non-empty map, but we've ran out of bytes in the tvb */
    if (!tvb_offset_exists(tvb, offset + string_length + CRLF_LENGTH) && nb_entries > 0) {
        if (DESEGMENT_ENABLED(pinfo)) {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            return -1;
        }
        expert_add_info(pinfo, map_item, &ei_resp_partial);
    }

    /* Add to the info column for responses. Don't do this for requests which are typically commands.
     * These are extracted in the bulk string dissector  */
    if (RESP_RESPONSE(pinfo) && array_depth == 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, data_type_format, nb_entries);
    }

    int dissected_offset = dissect_resp_entries(tvb, pinfo, map_tree, offset + string_length + CRLF_LENGTH,array_depth + 1, nb_entries, ett_resp_x_entry);
    if (dissected_offset == -1) {
        /* Override any desegment lengths previously set as we want to start from the beginning of the array */
        pinfo->desegment_offset = offset;
        pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
        /* We've partially decoded some of the array, but we've asked for all. It will still show in the proto tree so give an
         * indication as to why it's only partially there*/
        expert_add_info(pinfo, map_item, &ei_resp_reassembled_in_next_frame);
        return -1;
    }
    proto_item_set_len(map_item, dissected_offset - offset);
    return dissected_offset - offset;
}

// NOLINTNEXTLINE(misc-no-recursion)
static int dissect_resp_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int string_length, int array_depth) {
    const char data_type = tvb_get_uint8(tvb, offset);
    switch (data_type) {
        case '+':
            return dissect_resp_string(tvb, pinfo, tree, offset, string_length, array_depth);
        case '-':
            return dissect_resp_error(tvb, pinfo, tree, offset, string_length);
        case ':':
            return dissect_resp_integer(tvb, pinfo, tree, offset, string_length, array_depth);
        case ',':
            return dissect_resp_double(tvb, pinfo, tree, offset, string_length, array_depth);
        case '(':
            return dissect_resp_big_number(tvb, pinfo, tree, offset, string_length, array_depth);
        case '$':
        case '!':
            return dissect_resp_bulk_string(tvb, pinfo, tree, offset, string_length, array_depth, data_type);
        case '=':
            return dissect_resp_verbatim_string(tvb, pinfo, tree, offset, string_length, array_depth);
        case '*':
        case '~':
        case '>':
            return dissect_resp_array(tvb, pinfo, tree, offset, string_length, array_depth, data_type);
        case '_':
            return dissect_resp_null(tvb, pinfo, tree, offset, string_length, array_depth);
        case '#':
            return dissect_resp_boolean(tvb, pinfo, tree, offset, string_length, array_depth);
        case '%':
        case '|':
            return dissect_resp_map(tvb, pinfo, tree, offset, string_length, array_depth, data_type);
        default:
            /* We have an erroneous \r\n if the string length is 0. */
            if (string_length == 0) {
                return CRLF_LENGTH;
            }
            /* Otherwise, its:
             * - A command we don't support yet (RESPv4 if/when it comes out?)
             * - Reassembly is disabled and data is between packet boundaries
             * - It's the first frame in a partial capture
             * */
            col_append_str(pinfo->cinfo, COL_INFO, " [fragment]");
            proto_tree_add_item(tree, hf_resp_fragment, tvb, offset, string_length + CRLF_LENGTH,ENC_NA);
            return string_length + CRLF_LENGTH;
    }
}

// NOLINTNEXTLINE(misc-no-recursion)
static int dissect_resp_loop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int array_depth, int64_t expected_elements) {
    int error_or_offset;
    int crlf_string_line_length;
    int done_elements = 0;

    while (tvb_offset_exists(tvb, offset)) {
        /* If we ended up in here from a recursive call when traversing an array, don't drain the tvb to empty.
         * Only do the amount of elements that are expected in the array */
        if (expected_elements >= 0 && done_elements == expected_elements) {
            return offset;
        }
        crlf_string_line_length = tvb_find_line_end(tvb, offset, -1, NULL, DESEGMENT_ENABLED(pinfo));
        /* If desegment is disabled, tvb_find_line_end() will return a positive length, regardless if it finds a CRLF */
        if (crlf_string_line_length == -1) {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            return -1;
        }
        increment_dissection_depth(pinfo);
        error_or_offset = dissect_resp_message(tvb, pinfo, tree, offset, crlf_string_line_length, array_depth);
        decrement_dissection_depth(pinfo);
        if (error_or_offset == -1) {
            return -1;
        }
        done_elements++;
        offset += error_or_offset;
    }

    return offset;
}

// NOLINTNEXTLINE(misc-no-recursion)
static int dissect_resp_entries(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int array_depth, int64_t expected_entries, int ett_entry_type) {
    int error_or_offset;
    int crlf_string_line_length;
    int done_entries = 0;
    proto_tree *entry_tree;
    proto_item *ti;

    while (tvb_offset_exists(tvb, offset)) {
        /* If we ended up in here from a recursive call when traversing a map, don't drain the tvb to empty.
         * Only do the amount of elements that are expected in the array */
        if (expected_entries >= 0 && done_entries == expected_entries) {
            return offset;
        }
        crlf_string_line_length = tvb_find_line_end(tvb, offset, -1, NULL, DESEGMENT_ENABLED(pinfo));
        /* If desegment is disabled, tvb_find_line_end() will return a positive length, regardless if it finds a CRLF */
        if (crlf_string_line_length == -1) {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            return -1;
        }

        entry_tree = proto_tree_add_subtree_format(tree, tvb, offset, 1, ett_entry_type, &ti, "Entry[%d]", done_entries);

        increment_dissection_depth(pinfo);
        error_or_offset = dissect_resp_message(tvb, pinfo, entry_tree, offset, crlf_string_line_length, array_depth);
        decrement_dissection_depth(pinfo);
        if (error_or_offset == -1) {
            return -1;
        }
        offset += error_or_offset;

        crlf_string_line_length = tvb_find_line_end(tvb, offset, -1, NULL, DESEGMENT_ENABLED(pinfo));
        /* If desegment is disabled, tvb_find_line_end() will return a positive length, regardless if it finds a CRLF */
        if (crlf_string_line_length == -1) {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            return -1;
        }
        increment_dissection_depth(pinfo);
        error_or_offset = dissect_resp_message(tvb, pinfo, entry_tree, offset, crlf_string_line_length, array_depth);
        decrement_dissection_depth(pinfo);
        if (error_or_offset == -1) {
            return -1;
        }
        done_entries++;
        offset += error_or_offset;
    }

    return offset;
}

static int dissect_resp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_) {
    int offset = 0;
    proto_item *root_resp_item;
    proto_tree *resp_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RESP");
    col_clear(pinfo->cinfo, COL_INFO);
    col_append_str(pinfo->cinfo, COL_INFO, RESP_RESPONSE(pinfo) ? "Response:" : "Request:");
    root_resp_item = proto_tree_add_item(tree, proto_resp, tvb, 0, -1, ENC_NA);
    resp_tree = proto_item_add_subtree(root_resp_item, ett_resp);

    int dissected_length = dissect_resp_loop(tvb, pinfo, resp_tree, offset, 0, -1);
    if (dissected_length == -1) {
        col_append_str(pinfo->cinfo, COL_INFO, " [continuation]");
        return tvb_captured_length(tvb);
    }
    return dissected_length;
}


void proto_register_resp(void) {

    static hf_register_info hf[] = {
            { &hf_resp_string,
                    { "String", "resp.string",
                            FT_STRING, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            { &hf_resp_error,
                    { "Error", "resp.error",
                            FT_STRING, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            { &hf_resp_bulk_string,
                    { "Bulk String", "resp.bulk_string",
                            FT_NONE, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            { &hf_resp_bulk_string_value,
                    { "Value", "resp.bulk_string.value",
                            FT_BYTES, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            { &hf_resp_bulk_string_length,
                    { "Length", "resp.bulk_string.length",
                            FT_INT32, BASE_DEC,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            { &hf_resp_integer,
                    { "Integer", "resp.integer",
                            FT_INT64, BASE_DEC,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            { &hf_resp_array,
                    { "Array", "resp.array",
                            FT_NONE, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            { &hf_resp_array_length,
                    { "Length", "resp.array.length",
                            FT_INT64, BASE_DEC,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            { &hf_resp_set,
                    { "Set", "resp.set",
                            FT_NONE, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            { &hf_resp_set_length,
                    { "Length", "resp.set.length",
                            FT_INT64, BASE_DEC,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            { &hf_resp_push,
                    { "Push", "resp.push",
                            FT_NONE, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            { &hf_resp_push_length,
                    { "Length", "resp.push.length",
                            FT_INT64, BASE_DEC,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            { &hf_resp_fragment,
                    { "Fragment", "resp.fragment",
                            FT_NONE, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            { &hf_resp_null,
                    { "Null", "resp.null",
                            FT_NONE, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            { &hf_resp_verbatim_string,
                    { "Verbatim String", "resp.verbatim_string",
                            FT_NONE, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            { &hf_resp_verbatim_string_value,
                    { "Value", "resp.verbatim_string.value",
                            FT_BYTES, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            { &hf_resp_verbatim_string_length,
                    { "Length", "resp.verbatim_string.length",
                            FT_INT32, BASE_DEC,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            { &hf_resp_verbatim_string_encoding,
                    { "Encoding", "resp.verbatim_string.encoding",
                            FT_STRING, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            { &hf_resp_bulk_error,
                    { "Bulk Error", "resp.bulk_error",
                            FT_NONE, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            { &hf_resp_bulk_error_value,
                    { "Value", "resp.bulk_error.value",
                            FT_BYTES, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            { &hf_resp_bulk_error_length,
                    { "Length", "resp.bulk_error.length",
                            FT_INT32, BASE_DEC,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            { &hf_resp_boolean,
                    { "Boolean", "resp.boolean",
                            FT_BOOLEAN, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            { &hf_resp_double,
                    { "Double", "resp.double",
                            FT_DOUBLE, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            { &hf_resp_big_number,
                    { "Big Number", "resp.big_number",
                            FT_STRING, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            { &hf_resp_map,
                    { "Map", "resp.map",
                            FT_NONE, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            { &hf_resp_map_length,
                    { "Length", "resp.map.length",
                            FT_INT64, BASE_DEC,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            { &hf_resp_attribute,
                    { "Attribute", "resp.attribute",
                            FT_NONE, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },
            { &hf_resp_attribute_length,
                    { "Length", "resp.attribute.length",
                            FT_INT64, BASE_DEC,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            }
    };


    static int *ett[] = {
            &ett_resp,
            &ett_resp_bulk_string,
            &ett_resp_bulk_error,
            &ett_resp_array,
            &ett_resp_set,
            &ett_resp_push,
            &ett_resp_map,
            &ett_resp_map_entry,
            &ett_resp_attribute,
            &ett_resp_attribute_entry,
    };

    static ei_register_info ei[] = {
            { &ei_resp_partial, { "resp.partial", PI_UNDECODED, PI_NOTE, "Field is only partially decoded", EXPFILL }},
            { &ei_resp_malformed_length, { "resp.malformed_length", PI_UNDECODED, PI_ERROR, "Malformed length specified", EXPFILL }},
            { &ei_resp_reassembled_in_next_frame, {"resp.reassembled_in_next_frame", PI_UNDECODED, PI_NOTE,
                                                         "Array is partially decoded. Re-assembled array is in the next frame", EXPFILL }},
            { &ei_resp_array_recursion_too_deep, { "resp.array_recursion_too_deep", PI_UNDECODED, PI_NOTE,
                                                   "Array is too deep to recurse any further. Subsequent elements attached to the protocol "
                                                   "tree may not reflect their actual location in the array", EXPFILL }},
            { &ei_resp_invalid_boolean_value, { "resp.invalid_boolean_value",PI_MALFORMED, PI_ERROR,
                                                "Invalid value received for a boolean field", EXPFILL }},
            { &ei_resp_invalid_big_number_value, { "resp.invalid_big_number_value",PI_MALFORMED, PI_ERROR,
                                                "Invalid value received for a big number field", EXPFILL }}
    };

    proto_resp = proto_register_protocol("REdis Serialization Protocol", "RESP", "resp");

    /* Preferences */
    module_t *resp_module = prefs_register_protocol(proto_resp, NULL);
    prefs_register_bool_preference(resp_module, "desegment_data",
                                   "Reassemble RESP data spanning multiple TCP segments",
                                   "Whether the RESP dissector should reassemble command and response lines"
                                   " spanning multiple TCP segments. To use this option, you must also enable "
                                   "\"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                   &resp_desegment);
    prefs_register_bool_preference(resp_module, "attempt_json_on_string",
                                   "Try JSON on string data",
                                   "For bulk string values that look like they might be JSON, try the dissector",
                                   &prefs_try_json_on_string);


    expert_module_t *expert_pcp = expert_register_protocol(proto_resp);
    expert_register_field_array(expert_pcp, ei, array_length(ei));

    resp_handle = register_dissector("resp", dissect_resp, proto_resp);

    proto_register_field_array(proto_resp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void proto_reg_handoff_resp(void) {
    dissector_add_uint_with_preference("tcp.port", RESP_PORT, resp_handle);
    json_handle = find_dissector("json");

}
