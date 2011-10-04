/* packet-bmc.c
 * Routines for Broadcast/Multicast Control dissection
 * Copyright 2011, Neil Piercy <Neil.Piercy@ipaccess.com>
 *
 * $Id$
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <string.h>

#include <epan/bitswap.h>
#include <epan/packet.h>

static int dissect_bmc_cbs_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_bmc_schedule_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_bmc_cbs41_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static int proto_bmc = -1;
static int hf_bmc_message_type = -1;
static int hf_bmc_message_id = -1;
static int hf_bmc_serial_number = -1;
static int hf_bmc_data_coding_scheme = -1;
static int hf_bmc_cb_data = -1;
static int hf_bmc_offset_to_begin_ctch_bs_index = -1;
static int hf_bmc_length_of_cbs_schedule_period = -1;
static int hf_bmc_new_message_bitmap = -1;
static int hf_bmc_message_description_type = -1;
static int hf_bmc_offset_to_ctch_bs_index_of_first_transmission = -1;
static int hf_bmc_broadcast_address = -1;
static int hf_bmc_cb_data41 = -1;
static int hf_bmc_future_extension_bitmap = -1;
static int hf_bmc_length_of_serial_number_list = -1;
static int hf_bmc_ctch_bs_index = -1;

#define MESSAGE_TYPE_CBS_MESSAGE        1
#define MESSAGE_TYPE_SCHEDULE_MESSAGE   2
#define MESSAGE_TYPE_CBS41_MESSAGE      3

static const value_string message_type_vals[] = {
    {MESSAGE_TYPE_CBS_MESSAGE, "CBS Message"},
    {MESSAGE_TYPE_SCHEDULE_MESSAGE, "Schedule Message"},
    {MESSAGE_TYPE_CBS41_MESSAGE, "CBS41 Message"},
    {0, NULL}
};

static const value_string message_description_type_vals[] = {
    {0, "Repetition of new BMC CBS message within schedule period"},
    {1, "New BMC CBS message (a BMC CBS message never previously sent)"},
    {2, "Reading advised"},
    {3, "Reading optional"},
    {4, "Repetition of old BMC CBS message within schedule period"},
    {5, "Old BMC CBS message (repetition of a BMC CBS message sent in a previous schedule period)"},
    {6, "Schedule message"},
    {7, "CBS41 message"},
    {8, "no message"},
    {0, NULL}
};

static gint ett_bmc = -1;
static gint ett_bmc_message_description = -1;

static int
dissect_bmc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8 message_type;
    guint8 *p_rev, *reversing_buffer;
    gint offset = 0;
    gint i, len;
    proto_item *ti;
    proto_tree *bmc_tree;
    tvbuff_t *bit_reversed_tvb;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BMC");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_bmc, tvb, 0, -1, ENC_NA);
    bmc_tree = proto_item_add_subtree(ti, ett_bmc);

    /* Needs bit-reversing. Create a new buffer, copy the message to it and bit-reverse */
    len = tvb_length(tvb);
    reversing_buffer = se_alloc(len);
    memcpy(reversing_buffer, tvb_get_ptr(tvb, offset, -1), len);

    p_rev = reversing_buffer;
    /* Entire message is bit reversed */
    for (i=0; i<len; i++, p_rev++)
        *p_rev = BIT_SWAP(*p_rev);

    /* Make this new buffer part of the display and provide a way to dispose of it */
    bit_reversed_tvb = tvb_new_real_data(reversing_buffer, len, len);
    tvb_set_child_real_data_tvbuff(tvb, bit_reversed_tvb);
    add_new_data_source(pinfo, bit_reversed_tvb, "Bit-reversed Data");

    message_type = tvb_get_guint8(bit_reversed_tvb, offset);
    proto_tree_add_item(bmc_tree, hf_bmc_message_type, bit_reversed_tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(message_type, message_type_vals,"Reserved 0x%02x"));

    switch (message_type) {
        case MESSAGE_TYPE_CBS_MESSAGE:
            offset = dissect_bmc_cbs_message(bit_reversed_tvb, pinfo, bmc_tree);
            break;

        case MESSAGE_TYPE_SCHEDULE_MESSAGE:
            offset = dissect_bmc_schedule_message(bit_reversed_tvb, pinfo, bmc_tree);
            break;

        case MESSAGE_TYPE_CBS41_MESSAGE:
            offset = dissect_bmc_cbs41_message(bit_reversed_tvb, pinfo, bmc_tree);
            break;

        default:
            break;
    }

    return offset;
}

static int
dissect_bmc_cbs_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    gint offset=1;

    proto_tree_add_item(tree, hf_bmc_message_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_bmc_serial_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_bmc_data_coding_scheme, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_bmc_cb_data, tvb, offset, tvb_length_remaining(tvb,offset), ENC_NA);
    offset = tvb_length(tvb);

    return offset;
}

static int
dissect_bmc_schedule_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    gint offset=1, i, saved_offset;
    guint8 new_message_bitmap_len;
    guint8 length_of_cbs_schedule_period;
    guint8 message_description_type;
    guint8 future_extension_bitmap;
    guint8 length_of_serial_number_list;
    guint8 entry;
    guint8 mask, bit;
    proto_tree *message_description_tree;
    proto_item *ti;

    proto_tree_add_item(tree, hf_bmc_offset_to_begin_ctch_bs_index, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    length_of_cbs_schedule_period = tvb_get_guint8(tvb,offset);
    proto_tree_add_item(tree, hf_bmc_length_of_cbs_schedule_period, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    new_message_bitmap_len = length_of_cbs_schedule_period>>3;
    if (length_of_cbs_schedule_period & 0x7)
        new_message_bitmap_len += 1;

    proto_tree_add_item(tree, hf_bmc_new_message_bitmap, tvb, offset, new_message_bitmap_len, ENC_NA);
    offset += new_message_bitmap_len;

    ti = proto_tree_add_text(tree, tvb, offset, 0, "Message Description" );
    message_description_tree = proto_item_add_subtree(ti, ett_bmc_message_description);
    saved_offset = offset;

    bit=1;
    for (i=0; i<new_message_bitmap_len; i++) {
        for(mask=1; bit<=length_of_cbs_schedule_period; mask<<=1, bit++) {
            message_description_type = tvb_get_guint8(tvb,offset);
            proto_tree_add_uint_format(message_description_tree, hf_bmc_message_description_type, tvb, offset, 1, message_description_type, "Message %d Message Description Type: %s (%d)", bit, val_to_str(message_description_type, message_description_type_vals,"Unknown"), message_description_type);
            offset += 1;

            if ((message_description_type==1) || (message_description_type==5)) {
                proto_tree_add_item(message_description_tree, hf_bmc_message_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
            }
            else if ((message_description_type==0) || (message_description_type==4)) {
                proto_tree_add_item(message_description_tree, hf_bmc_offset_to_ctch_bs_index_of_first_transmission, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
            }
        }
    }
    proto_item_set_len(ti, offset-saved_offset);

    if (tvb_length_remaining(tvb,offset)) {
        future_extension_bitmap = tvb_get_guint8(tvb,offset);
        proto_tree_add_item(tree, hf_bmc_future_extension_bitmap, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        if (future_extension_bitmap & 0x01) {
            length_of_serial_number_list = tvb_get_guint8(tvb,offset);
            proto_tree_add_item(tree, hf_bmc_length_of_serial_number_list, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            for (entry=0; entry<length_of_serial_number_list; entry++) {
                proto_tree_add_item(tree, hf_bmc_serial_number, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                proto_tree_add_item(tree, hf_bmc_ctch_bs_index, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
            }
        }
    }

    return offset;
}

static int
dissect_bmc_cbs41_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    gint offset=1;

    proto_tree_add_item(tree, hf_bmc_broadcast_address, tvb, offset, 5, ENC_NA);
    offset += 5;

    proto_tree_add_item(tree, hf_bmc_cb_data41, tvb, offset, tvb_length_remaining(tvb,offset), ENC_NA);
    offset = tvb_length(tvb);

    return offset;
}

void
proto_register_bmc(void)
{
    static hf_register_info hf[] = {
        { &hf_bmc_message_type,
            { "Message Type", "bmc.message_type",
            FT_UINT8, BASE_DEC, message_type_vals, 0,
            NULL, HFILL }
        },
        { &hf_bmc_message_id,
            { "Message ID", "bmc.message_id",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bmc_serial_number,
            { "Serial Number", "bmc.serial_number",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bmc_data_coding_scheme,
            { "Data Coding Scheme", "bmc.data_coding_scheme",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bmc_cb_data,
            { "CB Data", "bmc.cb_data",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bmc_offset_to_begin_ctch_bs_index,
            { "Offset to Begin CTCH Block Set Index", "bmc.offset_to_begin_ctch_bs_index",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bmc_length_of_cbs_schedule_period,
            { "Length of CBS Schedule Period", "bmc.length_of_cbs_schedule_period",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bmc_new_message_bitmap,
            { "New Message Bitmap", "bmc.new_message_bitmap",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bmc_message_description_type,
            { "Message Description Type", "bmc.message_description_type",
            FT_UINT8, BASE_DEC, message_description_type_vals, 0,
            NULL, HFILL }
        },
        { &hf_bmc_offset_to_ctch_bs_index_of_first_transmission,
            { "Offset to CTCH BS index of first transmission", "bmc.offset_to_ctch_bs_index_of_first_transmission",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bmc_broadcast_address,
            { "Broadcast Address", "bmc.broadcast_address",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bmc_cb_data41,
            { "CB Data41", "bmc.cb_data41",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bmc_future_extension_bitmap,
            { "Future Extension Bitmap", "bmc.future_extension_bitmap",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bmc_length_of_serial_number_list,
            { "Length of Serial Number List", "bmc.length_of_serial_number_list",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_bmc_ctch_bs_index,
            { "CTCH BS Index", "bmc.ctch_bs_index",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_bmc,
        &ett_bmc_message_description
    };

    proto_bmc = proto_register_protocol("Broadcast/Multicast Control", "BMC", "bmc");
    new_register_dissector("bmc", dissect_bmc, proto_bmc);

    proto_register_field_array(proto_bmc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}
