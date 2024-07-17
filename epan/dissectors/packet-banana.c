/* packet-bananna.c
 * Routines for the Twisted Banana serialization protocol dissection
 * Copyright 2009, Gerald Combs <gerald@wireshark.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Based on "Banana Protocol Specifications"
 * https://twisted.org/documents/16.1.1/core/specifications/banana.html
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

void proto_register_banana(void);
void proto_reg_handoff_banana(void);

/* Initialize the protocol and registered fields */
static int proto_banana;
static int hf_banana_list;
static int hf_banana_int;
static int hf_banana_string;
static int hf_banana_neg_int;
static int hf_banana_float;
static int hf_banana_lg_int;
static int hf_banana_lg_neg_int;
static int hf_banana_pb;

/* Initialize the subtree pointers */
static int ett_banana;
static int ett_list;

static expert_field ei_banana_unknown_type;
static expert_field ei_banana_too_many_value_bytes;
static expert_field ei_banana_length_too_long;
static expert_field ei_banana_value_too_large;
static expert_field ei_banana_pb_error;

static dissector_handle_t banana_handle;

#define BE_LIST         0x80
#define BE_INT          0x81
#define BE_STRING       0x82
#define BE_NEG_INT      0x83
#define BE_FLOAT        0x84
#define BE_LG_INT       0x85
#define BE_LG_NEG_INT   0x86
#define BE_PB           0x87

#define is_element(b) (b >= BE_LIST && b <= BE_PB)

static const value_string type_vals[] = {
    { BE_LIST,          "List" },
    { BE_INT,           "Integer" },
    { BE_STRING,        "String" },
    { BE_NEG_INT,       "Negative Integer" },
    { BE_FLOAT,         "Float" },
    { BE_LG_INT,        "Large Integer" },
    { BE_LG_NEG_INT,    "Large Negative Integer" },
    { BE_PB,            "pb Profile"},
    { 0, NULL }
};

static const value_string pb_vals[] = {
    { 0x01, "None" },
    { 0x02, "class" },
    { 0x03, "dereference" },
    { 0x04, "reference" },
    { 0x05, "dictionary" },
    { 0x06, "function" },
    { 0x07, "instance" },
    { 0x08, "list" },
    { 0x09, "module" },
    { 0x0a, "persistent" },
    { 0x0b, "tuple" },
    { 0x0c, "unpersistable" },
    { 0x0d, "copy" },
    { 0x0e, "cache" },
    { 0x0f, "cached" },
    { 0x10, "remote" },
    { 0x11, "local" },
    { 0x12, "lcache" },
    { 0x13, "version" },
    { 0x14, "login" },
    { 0x15, "password" },
    { 0x16, "challenge" },
    { 0x17, "logged_in" },
    { 0x18, "not_logged_in" },
    { 0x19, "cachemessage" },
    { 0x1a, "message" },
    { 0x1b, "answer" },
    { 0x1c, "error" },
    { 0x1d, "decref" },
    { 0x1e, "decache" },
    { 0x1f, "uncache" },
    { 0,    NULL }
};

#define MAX_ELEMENT_VAL 2147483647 /* Max TE value */
#define MAX_ELEMENT_INT_LEN 4
#define MAX_ELEMENT_VAL_LEN 8

/* Dissect the packets */

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_banana_element(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset) {
    proto_item *ti;
    proto_tree *list_tree;
    uint8_t byte = 0;
    int64_t val = 0;
    int val_len = 0;
    int start_offset = offset;
    int old_offset;
    int i;

    /* Accumulate our value/length 'til we hit a valid type */
    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        byte = tvb_get_uint8(tvb, offset);
        offset++;

        if (byte & 0x80) {
            if (is_element(byte)) {
                break;
            } else {
                expert_add_info_format(pinfo, NULL, &ei_banana_unknown_type, "Unknown type %u", byte);
            }
        } else {
            val_len++;
            if (val_len > MAX_ELEMENT_VAL_LEN) {
                expert_add_info(pinfo, NULL, &ei_banana_too_many_value_bytes);
            }
            val += byte + (val << 7);
        }
    }

    /* Type */
    switch (byte) {
        case BE_LIST:
            if (val > MAX_ELEMENT_VAL) {
                expert_add_info_format(pinfo, NULL, &ei_banana_length_too_long, "List length %" PRId64 " longer than we can handle", val);
            }
            ti = proto_tree_add_uint_format_value(tree, hf_banana_list, tvb, start_offset, offset - start_offset - 1, (uint32_t) val, "(%d items)", (int) val);
            list_tree = proto_item_add_subtree(ti, ett_list);
            for (i = 0; i < val; i++) {
                old_offset = offset;
                increment_dissection_depth(pinfo);
                offset += dissect_banana_element(tvb, pinfo, list_tree, offset);
                decrement_dissection_depth(pinfo);
                if (offset <= old_offset) {
                    return offset - start_offset;
                }
            }
            break;
        case BE_INT:
            if (val > MAX_ELEMENT_VAL) {
                expert_add_info_format(pinfo, NULL, &ei_banana_value_too_large, "Integer value %" PRId64 " too large", val);
            }
            proto_tree_add_uint(tree, hf_banana_int, tvb, start_offset, offset - start_offset, (uint32_t) val);
            break;
        case BE_STRING:
            if (val > MAX_ELEMENT_VAL) {
                expert_add_info_format(pinfo, NULL, &ei_banana_length_too_long, "String length %" PRId64 " longer than we can handle", val);
            }
            proto_tree_add_item(tree, hf_banana_string, tvb, offset, (uint32_t) val, ENC_ASCII);
            offset += (int) val;
            break;
        case BE_NEG_INT:
            if (val > MAX_ELEMENT_VAL) {
                expert_add_info_format(pinfo, NULL, &ei_banana_value_too_large, "Integer value -%" PRId64 " too large", val);
            }
            proto_tree_add_int(tree, hf_banana_neg_int, tvb, start_offset, offset - start_offset, (int32_t) val * -1);
            break;
        case BE_FLOAT:
            proto_tree_add_item(tree, hf_banana_float, tvb, offset, 8, ENC_BIG_ENDIAN);
            offset += 8;
            break;
        case BE_LG_INT:
            proto_tree_add_item(tree, hf_banana_lg_int, tvb, start_offset, offset - start_offset, ENC_NA);
            break;
        case BE_LG_NEG_INT:
            proto_tree_add_item(tree, hf_banana_lg_neg_int, tvb, start_offset, offset - start_offset, ENC_NA);
            break;
        case BE_PB:
            if (val_len > 1) {
                expert_add_info(pinfo, NULL, &ei_banana_pb_error);
            }
            /*
             * The spec says the pb dictionary value comes after the tag.
             * In real-world captures it comes before.
             */
            proto_tree_add_item(tree, hf_banana_pb, tvb, offset - 2, 1, ENC_BIG_ENDIAN);
            break;
        default:
            return 0;
    }
    return offset - start_offset;
}

static int
dissect_banana(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    uint8_t byte = 0;
    int offset = 0, old_offset;
    proto_item *ti;
    proto_tree *banana_tree;

    /* Check that there's enough data */
    if (tvb_reported_length(tvb) < 2)
        return 0;

    /* Fill in our protocol and info columns */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Banana");

    while (tvb_reported_length_remaining(tvb, offset) > 0 && offset < MAX_ELEMENT_VAL_LEN) {
        byte = tvb_get_uint8(tvb, offset);
        if (is_element(byte))
            break;
        offset++;
    }
    col_add_fstr(pinfo->cinfo, COL_INFO, "First element: %s",
        val_to_str(byte, type_vals, "Unknown type: %u"));

    /* Create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_banana, tvb, 0, -1, ENC_NA);
    banana_tree = proto_item_add_subtree(ti, ett_banana);

    offset = 0;
    old_offset = -1;
    while (offset > old_offset) {
        old_offset = offset;
        offset += dissect_banana_element(tvb, pinfo, banana_tree, offset);
    }

    /* Return the amount of data this dissector was able to dissect */
    return tvb_reported_length(tvb);
}

/* Register the protocol with Wireshark */

void
proto_register_banana(void)
{
    static hf_register_info hf[] = {
        { &hf_banana_list,
            { "List Length", "banana.list",
                FT_UINT32, BASE_DEC, NULL, 0,
                "Banana list", HFILL }
        },
        { &hf_banana_int,
            { "Integer", "banana.int",
                FT_UINT32, BASE_DEC, NULL, 0,
                "Banana integer", HFILL }
        },
        { &hf_banana_string,
            { "String", "banana.string",
                FT_STRING, BASE_NONE, NULL, 0,
                "Banana string", HFILL }
        },
        { &hf_banana_neg_int,
            { "Negative Integer", "banana.neg_int",
                FT_INT32, BASE_DEC, NULL, 0,
                "Banana negative integer", HFILL }
        },
        { &hf_banana_float,
            { "Float", "banana.float",
                FT_DOUBLE, BASE_NONE, NULL, 0,
                "Banana float", HFILL }
        },
        { &hf_banana_lg_int,
            { "Float", "banana.lg_int",
                FT_BYTES, BASE_NONE, NULL, 0,
                "Banana large integer", HFILL }
        },
        { &hf_banana_lg_neg_int,
            { "Float", "banana.lg_neg_int",
                FT_BYTES, BASE_NONE, NULL, 0,
                "Banana large negative integer", HFILL }
        },
        { &hf_banana_pb,
            { "pb Profile Value", "banana.pb",
                FT_UINT8, BASE_HEX, VALS(pb_vals), 0,
                "Banana Perspective Broker Profile Value", HFILL }
        }
    };

    expert_module_t* expert_banana;

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_banana,
        &ett_list
    };

    static ei_register_info ei[] = {
        { &ei_banana_unknown_type, { "banana.unknown_type", PI_UNDECODED, PI_ERROR, "Unknown type", EXPFILL }},
        { &ei_banana_too_many_value_bytes, { "banana.too_many_value_bytes", PI_UNDECODED, PI_ERROR, "Too many value/length bytes", EXPFILL }},
        { &ei_banana_length_too_long, { "banana.length_too_long", PI_UNDECODED, PI_ERROR, "Length too long", EXPFILL }},
        { &ei_banana_value_too_large, { "banana.value_too_large", PI_MALFORMED, PI_ERROR, "Value too large", EXPFILL }},
        { &ei_banana_pb_error, { "banana.pb_error", PI_MALFORMED, PI_ERROR, "More than 1 byte before pb", EXPFILL }},
    };

    /* Register the protocol name and description */
    proto_banana = proto_register_protocol("Twisted Banana", "Banana", "banana");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_banana, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_banana = expert_register_protocol(proto_banana);
    expert_register_field_array(expert_banana, ei, array_length(ei));

    banana_handle = register_dissector("banana", dissect_banana, proto_banana);
}

void
proto_reg_handoff_banana(void)
{
    dissector_add_uint_range_with_preference("tcp.port", "", banana_handle);
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
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */


