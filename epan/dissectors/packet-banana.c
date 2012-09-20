/* packet-bananna.c
 * Routines for the Twisted Banana serialization protocol dissection
 * Copyright 2009, Gerald Combs <gerald@wireshark.org>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/*
 * Based on "Banana Protocol Specifications"
 * http://twistedmatrix.com/projects/core/documentation/specifications/banana.html
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

/* Initialize the protocol and registered fields */
static int proto_banana = -1;
static int hf_banana_list = -1;
static int hf_banana_int = -1;
static int hf_banana_string = -1;
static int hf_banana_neg_int = -1;
static int hf_banana_float = -1;
static int hf_banana_lg_int = -1;
static int hf_banana_lg_neg_int = -1;
static int hf_banana_pb = -1;

/* Initialize the subtree pointers */
static gint ett_banana = -1;
static gint ett_list = -1;

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

static range_t *global_banana_tcp_range = NULL;
static range_t *banana_tcp_range = NULL;

/* Dissect the packets */

static int
dissect_banana_element(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset) {
    proto_item *ti;
    proto_tree *list_tree;
    guint8 byte = 0;
    gint64 val = 0;
    gint val_len = 0;
    int start_offset = offset;
    int old_offset;
    int i;

    /* Accumulate our value/length 'til we hit a valid type */
    while (tvb_length_remaining(tvb, offset) > 0) {
        byte = tvb_get_guint8(tvb, offset);
        offset++;

        if (byte & 0x80) {
            if (is_element(byte)) {
                break;
            } else {
                expert_add_info_format(pinfo, NULL, PI_UNDECODED, PI_ERROR, "Unknown type %u", byte);
            }
        } else {
            val_len++;
            if (val_len > MAX_ELEMENT_VAL_LEN) {
                expert_add_info_format(pinfo, NULL, PI_UNDECODED, PI_ERROR, "Too many value/length bytes");
            }
            val += byte + (val << 7);
        }
    }

    /* Type */
    switch (byte) {
        case BE_LIST:
            if (val > MAX_ELEMENT_VAL) {
                expert_add_info_format(pinfo, NULL, PI_UNDECODED, PI_ERROR, "List length %" G_GINT64_MODIFIER "d longer than we can handle", val);
            }
            ti = proto_tree_add_uint_format_value(tree, hf_banana_list, tvb, start_offset, offset - start_offset - 1, (guint32) val, "(%d items)", (gint) val);
            list_tree = proto_item_add_subtree(ti, ett_list);
            for (i = 0; i < val; i++) {
                old_offset = offset;
                offset += dissect_banana_element(tvb, pinfo, list_tree, offset);
                if (offset <= old_offset) {
                    return offset - start_offset;
                }
            }
            break;
        case BE_INT:
            if (val > MAX_ELEMENT_VAL) {
                expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR, "Integer value %" G_GINT64_MODIFIER "d too large", val);
            }
            proto_tree_add_uint(tree, hf_banana_int, tvb, start_offset, offset - start_offset, (guint32) val);
            break;
        case BE_STRING:
            if (val > MAX_ELEMENT_VAL) {
                expert_add_info_format(pinfo, NULL, PI_UNDECODED, PI_ERROR, "String length %" G_GINT64_MODIFIER "d longer than we can handle", val);
            }
            proto_tree_add_item(tree, hf_banana_string, tvb, offset, (guint32) val, ENC_ASCII|ENC_NA);
            offset += (gint) val;
            break;
        case BE_NEG_INT:
            if (val > MAX_ELEMENT_VAL) {
                expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR, "Integer value -%" G_GINT64_MODIFIER "d too large", val);
            }
            proto_tree_add_int(tree, hf_banana_neg_int, tvb, start_offset, offset - start_offset, (gint32) val * -1);
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
                expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR, "More than 1 byte before pb");
            }
            /*
             * The spec says the pb dictionary value comes after the tag.
             * In real-world captures it comes before.
             */
            proto_tree_add_item(tree, hf_banana_pb, tvb, offset - 2, 1, ENC_BIG_ENDIAN);
            break;
        default:
            return 0;
            break;
    }
    return offset - start_offset;
}

static int
dissect_banana(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    guint8 byte = 0;
    gint offset = 0, old_offset;
    proto_item *ti;
    proto_tree *banana_tree;

    /* Check that there's enough data */
    if (tvb_length(tvb) < 2)
        return 0;

    /* Fill in our protocol and info columns */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Banana");

    while (tvb_length_remaining(tvb, offset) > 0 && offset < MAX_ELEMENT_VAL_LEN) {
        byte = tvb_get_guint8(tvb, offset);
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
    return tvb_length(tvb);
}

static void
range_delete_banana_tcp_callback(guint32 port) {
      dissector_delete_uint("tcp.port", port, banana_handle);
}

static void
range_add_banana_tcp_callback(guint32 port) {
    dissector_add_uint("tcp.port", port, banana_handle);
}

static void
banana_prefs(void) {
    range_foreach(banana_tcp_range, range_delete_banana_tcp_callback);
    g_free(banana_tcp_range);
    banana_tcp_range = range_copy(global_banana_tcp_range);
    range_foreach(banana_tcp_range, range_add_banana_tcp_callback);
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

    module_t *banana_module;

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_banana,
        &ett_list
    };

    /* Register the protocol name and description */
    proto_banana = proto_register_protocol("Twisted Banana",
        "Banana", "banana");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_banana, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Initialize dissector preferences */
    banana_module = prefs_register_protocol(proto_banana, banana_prefs);
    banana_tcp_range = range_empty();
    prefs_register_range_preference(banana_module, "tcp.port", "TCP Ports", "Banana TCP Port range", &global_banana_tcp_range, 65535);
}

void
proto_reg_handoff_banana(void)
{
    banana_handle = new_create_dissector_handle(dissect_banana, proto_banana);
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
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */


