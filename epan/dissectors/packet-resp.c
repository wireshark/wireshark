/* packet-resp.c
 * Routines for Redis Client/Server RESP (REdis Serialization Protocol) v2 as
 * documented by https://redis.io/topics/protocol
 *
 * Copyright 2022 Ryan Doyle <ryan <AT> doylenet dot net>
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
#include <epan/expert.h>

#define RESP_PORT 6379
#define CRLF_LENGTH 2
#define RESP_TOKEN_PREFIX_LENGTH 1
#define MAX_ARRAY_DEPTH_TO_RECURSE 30
#define BULK_STRING_MAX_DISPLAY 100
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
static int ett_resp_array;

static expert_field ei_resp_partial;
static expert_field ei_resp_malformed_length;
static expert_field ei_resp_array_recursion_too_deep;
static expert_field ei_resp_reassembled_in_next_frame;

static int hf_resp_string;
static int hf_resp_error;
static int hf_resp_bulk_string;
static int hf_resp_bulk_string_length;
static int hf_resp_bulk_string_value;
static int hf_resp_integer;
static int hf_resp_array;
static int hf_resp_array_length;
static int hf_resp_fragment;

static int dissect_resp_loop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int array_depth, int64_t expected_elements);
static void resp_bulk_string_enhance_colinfo_ascii(packet_info *pinfo, int array_depth, int bulk_string_length, const uint8_t *bulk_string_as_str);
void proto_reg_handoff_resp(void);
void proto_register_resp(void);

static int dissect_resp_string(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int string_lenth, int array_depth) {
    uint8_t *string_value;

    string_value = tvb_get_string_enc(pinfo->pool, tvb, offset + RESP_TOKEN_PREFIX_LENGTH,
                                      string_lenth - RESP_TOKEN_PREFIX_LENGTH, ENC_ASCII);
    proto_tree_add_string(tree, hf_resp_string, tvb, offset, string_lenth + CRLF_LENGTH, string_value);

    /* Simple strings can be used as a response for commands */
    if (RESP_RESPONSE(pinfo) && array_depth == 0) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, " ", string_value);
    }

    return string_lenth + CRLF_LENGTH;
}

static int dissect_resp_error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int string_lenth) {
    uint8_t *error_value;

    error_value = tvb_get_string_enc(pinfo->pool, tvb, offset + RESP_TOKEN_PREFIX_LENGTH,
                                     string_lenth - RESP_TOKEN_PREFIX_LENGTH, ENC_ASCII);
    proto_tree_add_string(tree, hf_resp_error, tvb, offset, string_lenth + CRLF_LENGTH, error_value);
    col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", error_value);
    return string_lenth + CRLF_LENGTH;
}

static int dissect_resp_bulk_string(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int bulk_string_string_length, int array_depth) {
    uint8_t *bulk_string_length_as_str;
    int bulk_string_length;
    int bulk_string_captured_length;
    int bulk_string_captured_length_with_crlf;
    proto_item *resp_string_item;
    proto_tree *resp_string_tree;

    bulk_string_length_as_str = tvb_get_string_enc(pinfo->pool, tvb, offset + RESP_TOKEN_PREFIX_LENGTH,
                                                   bulk_string_string_length - RESP_TOKEN_PREFIX_LENGTH, ENC_ASCII);
    bulk_string_length = (int)g_ascii_strtoll(bulk_string_length_as_str, NULL, 10);
    /* Negative string lengths */
    if (bulk_string_length < 0) {
        /* NULL string */
        resp_string_item = proto_tree_add_item(tree, hf_resp_bulk_string, tvb, offset,bulk_string_string_length + CRLF_LENGTH, ENC_NA);
        resp_string_tree = proto_item_add_subtree(resp_string_item, ett_resp_bulk_string);
        proto_tree_add_int(resp_string_tree, hf_resp_bulk_string_length, tvb, offset, bulk_string_string_length + CRLF_LENGTH, bulk_string_length);
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
    resp_string_item = proto_tree_add_item(tree, hf_resp_bulk_string, tvb, offset,
                                           bulk_string_string_length + CRLF_LENGTH + bulk_string_captured_length_with_crlf,ENC_NA);
    if (is_fragmented) {
        expert_add_info(pinfo, resp_string_item, &ei_resp_partial);
    }
    resp_string_tree = proto_item_add_subtree(resp_string_item, ett_resp_bulk_string);
    proto_tree_add_int(resp_string_tree, hf_resp_bulk_string_length, tvb, offset, bulk_string_string_length + CRLF_LENGTH, bulk_string_length);
    offset += bulk_string_string_length + CRLF_LENGTH;
    if (bulk_string_captured_length > 0) {
        proto_tree_add_item(resp_string_tree, hf_resp_bulk_string_value, tvb, offset, bulk_string_captured_length, ENC_NA);
    }

    /* Enhance display */
    uint8_t *bulk_string_as_str = tvb_get_string_enc(pinfo->pool, tvb, offset, bulk_string_captured_length, ENC_NA);
    if (g_str_is_ascii(bulk_string_as_str)) {
        proto_item_append_text(resp_string_item, ": %s", bulk_string_as_str);
        resp_bulk_string_enhance_colinfo_ascii(pinfo, array_depth, bulk_string_length, bulk_string_as_str);
    } else if(array_depth == 0) {
        /* Otherwise, just append that we captured bulk strings (and only do so if they aren't part of an array */
        col_append_fstr(pinfo->cinfo, COL_INFO, " BulkString(%d)", bulk_string_length);
    }

    return bulk_string_string_length + CRLF_LENGTH + bulk_string_captured_length_with_crlf;
}

static void resp_bulk_string_enhance_colinfo_ascii(packet_info *pinfo, int array_depth, int bulk_string_length, const uint8_t *bulk_string_as_str) {
    /* Request commands are arrays */
    if (RESP_REQUEST(pinfo) && array_depth == 1) {
        if (bulk_string_length < BULK_STRING_MAX_DISPLAY) {
            col_append_sep_str(pinfo->cinfo, COL_INFO, " ", bulk_string_as_str);
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, " BulkString(%d)", bulk_string_length);
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
        col_append_fstr(pinfo->cinfo, COL_INFO, " BulkString(%d)", bulk_string_length);
    }
}

static int dissect_resp_integer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int bulk_string_string_length, int array_depth) {
    uint8_t *integer_as_string;
    int64_t integer;
    integer_as_string = tvb_get_string_enc(pinfo->pool, tvb, offset + RESP_TOKEN_PREFIX_LENGTH,
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
static int dissect_resp_array(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int string_length, int array_depth) {
    uint8_t *array_length_as_string = tvb_get_string_enc(pinfo->pool, tvb, offset + RESP_TOKEN_PREFIX_LENGTH,
                                                        string_length - RESP_TOKEN_PREFIX_LENGTH, ENC_ASCII);
    int64_t array_length = g_ascii_strtoll(array_length_as_string, NULL, 10);

    /* We'll fix up the length later when we know how long it actually was */
    proto_item *array_item = proto_tree_add_item(tree, hf_resp_array, tvb, offset, string_length + CRLF_LENGTH, ENC_NA);

    proto_tree *array_tree = proto_item_add_subtree(array_item, ett_resp_array);
    proto_tree_add_int64(array_tree, hf_resp_array_length, tvb, offset, string_length + CRLF_LENGTH, array_length);

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
        col_append_fstr(pinfo->cinfo, COL_INFO, " Array(%" PRId64 ")" , array_length);
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
static int dissect_resp_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int string_length, int array_depth) {
    switch (tvb_get_uint8(tvb, offset)) {
        case '+':
            return dissect_resp_string(tvb, pinfo, tree, offset, string_length, array_depth);
        case '-':
            return dissect_resp_error(tvb, pinfo, tree, offset, string_length);
        case ':':
            return dissect_resp_integer(tvb, pinfo, tree, offset, string_length, array_depth);
        case '$':
            return dissect_resp_bulk_string(tvb, pinfo, tree, offset, string_length, array_depth);
        case '*':
            return dissect_resp_array(tvb, pinfo, tree, offset, string_length, array_depth);
        default:
            /* We have an erroneous \r\n if the string length is 0. */
            if (string_length == 0) {
                return CRLF_LENGTH;
            }
            /* Otherwise, its:
             * - A command we don't support yet (RESPv3 commands that aren't implemented yet)
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
            { &hf_resp_fragment,
                    { "Fragment", "resp.fragment",
                            FT_NONE, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL
                    }
            },

    };

    static int *ett[] = {
            &ett_resp,
            &ett_resp_bulk_string,
            &ett_resp_array,
    };

    static ei_register_info ei[] = {
            { &ei_resp_partial, { "resp.partial", PI_UNDECODED, PI_NOTE, "Field is only partially decoded", EXPFILL }},
            { &ei_resp_malformed_length, { "resp.malformed_length", PI_UNDECODED, PI_ERROR, "Malformed length specified", EXPFILL }},
            { &ei_resp_reassembled_in_next_frame, {"resp.reassembled_in_next_frame", PI_UNDECODED, PI_NOTE,
                                                         "Array is partially decoded. Re-assembled array is in the next frame", EXPFILL }},
            { &ei_resp_array_recursion_too_deep, { "resp.array_recursion_too_deep", PI_UNDECODED, PI_NOTE,
                                                   "Array is too deep to recurse any further. Subsequent elements attached to the protocol "
                                                   "tree may not reflect their actual location in the array", EXPFILL }},
    };

    proto_resp = proto_register_protocol("REdis Serialization Protocol", "RESP", "resp");
    module_t *resp_module = prefs_register_protocol(proto_resp, NULL);
    prefs_register_bool_preference(resp_module, "desegment_data",
                                   "Reassemble RESP data spanning multiple TCP segments",
                                   "Whether the RESP dissector should reassemble command and response lines"
                                   " spanning multiple TCP segments. To use this option, you must also enable "
                                   "\"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                   &resp_desegment);

    expert_module_t *expert_pcp = expert_register_protocol(proto_resp);
    expert_register_field_array(expert_pcp, ei, array_length(ei));

    resp_handle = register_dissector("resp", dissect_resp, proto_resp);

    proto_register_field_array(proto_resp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void proto_reg_handoff_resp(void) {
    dissector_add_uint_with_preference("tcp.port", RESP_PORT, resp_handle);
}
