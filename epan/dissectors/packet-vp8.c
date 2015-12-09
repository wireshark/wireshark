/* packet-vp8.c
 * Routines for VP8 dissection
 * Copyright 2014, Owen Williams williams.owen@gmail.com
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

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

void proto_reg_handoff_vp8(void);
void proto_register_vp8(void);

#define BIT_1_MASK              0x80
#define BIT_2_MASK              0x40
#define BIT_3_MASK              0x20
#define BIT_4_MASK              0x10
#define BIT_5_MASK              0x08
#define BIT_6_MASK              0x04
#define BIT_7_MASK              0x02
#define BIT_8_MASK              0x01
#define BIT_123_MASK            0xE0
#define BIT_234_MASK            0x70
#define BIT_5678_MASK           0x0F
#define BIT_567_MASK            0x0E
#define BIT_45678_MASK          0x1F
#define BIT_12_MASK             0xC0
#define BIT_NO_MASK             0xFF

#define BIT_2BYTE_NO_MASK       0xFFFF
#define BIT_3BYTE_NO_MASK       0xFFFFFF
#define BIT_EXT_PICTURE_MASK    0x7FFF
#define BIT_PARTITION_SIZE_MASK 0xE0FFFF

static range_t *temp_dynamic_payload_type_range = NULL;

static dissector_handle_t vp8_handle;

/* Initialize the protocol and registered fields */
static int proto_vp8 = -1;
static int hf_vp8_pld_x_bit = -1;
static int hf_vp8_pld_r_bit = -1;
static int hf_vp8_pld_n_bit = -1;
static int hf_vp8_pld_s_bit = -1;
static int hf_vp8_pld_part_id = -1;
static int hf_vp8_pld_i_bit = -1;
static int hf_vp8_pld_l_bit = -1;
static int hf_vp8_pld_t_bit = -1;
static int hf_vp8_pld_k_bit = -1;
static int hf_vp8_pld_rsv_a = -1;
static int hf_vp8_pld_picture_id = -1;
static int hf_vp8_pld_extended_picture_id = -1;
static int hf_vp8_pld_tl0picidx = -1;
static int hf_vp8_pld_tid = -1;
static int hf_vp8_pld_y_bit = -1;
static int hf_vp8_pld_keyidx = -1;

/* payload header fields */
static int hf_vp8_hdr_frametype = -1;
static int hf_vp8_hdr_version = -1;
static int hf_vp8_hdr_show_bit = -1;
static int hf_vp8_hdr_first_partition_size = -1;

/* keyframe fields */
static int hf_vp8_keyframe_start_code = -1;
static int hf_vp8_keyframe_width = -1;
static int hf_vp8_keyframe_horizontal_scale = -1;
static int hf_vp8_keyframe_height = -1;
static int hf_vp8_keyframe_vertical_scale = -1;

/* Initialize the subtree pointers */
static int ett_vp8 = -1;
static int ett_vp8_payload_descriptor = -1;
static int ett_vp8_payload_header = -1;
static int ett_vp8_payload = -1;
static int ett_vp8_keyframe = -1;

static expert_field ei_vp8_startcode = EI_INIT;
static expert_field ei_vp8_undecoded = EI_INIT;
static expert_field ei_vp8_continuation = EI_INIT;
static expert_field ei_vp8_first_partition_split = EI_INIT;
static expert_field ei_vp8_first_partition_plus = EI_INIT;

static void
dissect_vp8_payload_descriptor(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *vp8_tree, gint *offset, gboolean *hasHeader);

static void
dissect_vp8_payload_header(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *vp8_tree, gint *offset, gint *frametype, gint *partition1_size);

static void
dissect_vp8_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *vp8_tree, gint *offset, gint *frametype, gint *partition1_size);

static gint *ett[] = {
    &ett_vp8,
    &ett_vp8_payload_descriptor,
    &ett_vp8_payload_header,
    &ett_vp8_payload,
    &ett_vp8_keyframe
};

static const value_string vp8_type_values[] = {
    {  0,   "Keyframe" },
    {  1,   "Interframe" },
    {  2,   "Continuation" },
    {  0, NULL }
};

static const true_false_string vp8_x_bit_vals = {
    "Extended control bits present (I L T K)",
    "Extended control bits not present"
};

static const true_false_string vp8_r_bit_vals = {
    "Reserved for future use (Error should be zero)",
    "Reserved for future use"
};

static const true_false_string vp8_n_bit_vals = {
    "Non referenced frame",
    "Reference frame"
};

static const true_false_string vp8_s_bit_vals = {
    "Start of VP8 partition",
    "Continuation of VP8 partition"
};

static const true_false_string vp8_i_bit_vals = {
    "Picture ID byte present",
    "No Picture byte ID"
};

static const true_false_string vp8_l_bit_vals = {
    "TL0PICIDX byte present",
    "TL0PICIDX byte not present"
};

static const true_false_string vp8_t_bit_vals = {
    "TID (temporal layer index) byte present",
    "TID (temporal layer index) byte not present"
};

static const true_false_string vp8_k_bit_vals = {
    "TID/KEYIDX byte present",
    "TID/KEYIDX byte not present"
};

static const true_false_string vp8_hdr_frametype_vals = {
    "interframe",
    "keyframe"
};

static int
dissect_vp8(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{

    proto_item *item;
    gint offset = 0, frametype = 0, partition1_size = -1;
    proto_tree *vp8_tree;
    gboolean hasHeader = FALSE;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VP8");
    col_clear(pinfo->cinfo, COL_INFO);

    item = proto_tree_add_item(tree, proto_vp8, tvb, 0, -1, ENC_NA);
    vp8_tree = proto_item_add_subtree(item, ett_vp8);

    frametype = 2; /*continuation, will get overridden if there is a payload header*/

    dissect_vp8_payload_descriptor(tvb, pinfo, vp8_tree, &offset, &hasHeader);
    if (hasHeader)
    {
        dissect_vp8_payload_header(tvb, pinfo, vp8_tree, &offset, &frametype, &partition1_size);
    }

    dissect_vp8_payload(tvb, pinfo, vp8_tree, &offset, &frametype, &partition1_size);

    col_append_fstr(pinfo->cinfo, COL_INFO, " - %s",
        val_to_str(frametype, vp8_type_values, "Unknown Type (%u)"));

    return tvb_captured_length(tvb);
}

static void
dissect_vp8_payload_descriptor(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *vp8_tree, gint *offset, gboolean *hasHeader)
{
    proto_item *item_descriptor;
    guint8      extended_bit, s_bit, partId;
    proto_tree *vp8_payload_descriptor_tree;

/*
The first octets after the RTP header are the VP8 payload descriptor,
   with the following structure.

         0 1 2 3 4 5 6 7
        +-+-+-+-+-+-+-+-+
        |X|R|N|S|PartID | (REQUIRED)
        +-+-+-+-+-+-+-+-+
   X:   |I|L|T|K| RSV   | (OPTIONAL)
        +-+-+-+-+-+-+-+-+
   I:   |   PictureID   | (OPTIONAL)
        +-+-+-+-+-+-+-+-+
   L:   |   TL0PICIDX   | (OPTIONAL)
        +-+-+-+-+-+-+-+-+
   T/K: |TID|Y| KEYIDX  | (OPTIONAL)
        +-+-+-+-+-+-+-+-+
*/

    vp8_payload_descriptor_tree = proto_tree_add_subtree(vp8_tree, tvb, *offset, -1, ett_vp8_payload_descriptor,
                                                         &item_descriptor, "Payload descriptor");

    proto_tree_add_item(vp8_payload_descriptor_tree, hf_vp8_pld_x_bit,   tvb, *offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(vp8_payload_descriptor_tree, hf_vp8_pld_r_bit,   tvb, *offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(vp8_payload_descriptor_tree, hf_vp8_pld_n_bit,   tvb, *offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(vp8_payload_descriptor_tree, hf_vp8_pld_s_bit,   tvb, *offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(vp8_payload_descriptor_tree, hf_vp8_pld_part_id, tvb, *offset, 1, ENC_BIG_ENDIAN);
    extended_bit = tvb_get_guint8(tvb, *offset) & BIT_1_MASK;
    s_bit  = tvb_get_guint8(tvb, *offset) & BIT_4_MASK;
    partId = tvb_get_guint8(tvb, *offset) & BIT_5678_MASK;

    if ((s_bit > 0) && (partId == 0)) {
        *hasHeader=TRUE;
    }

    if (extended_bit)
    {
        guint8 i_bit, l_bit, t_bit, k_bit;
        (*offset)++;
        proto_tree_add_item(vp8_payload_descriptor_tree, hf_vp8_pld_i_bit, tvb, *offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(vp8_payload_descriptor_tree, hf_vp8_pld_l_bit, tvb, *offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(vp8_payload_descriptor_tree, hf_vp8_pld_t_bit, tvb, *offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(vp8_payload_descriptor_tree, hf_vp8_pld_k_bit, tvb, *offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(vp8_payload_descriptor_tree, hf_vp8_pld_rsv_a, tvb, *offset, 1, ENC_BIG_ENDIAN);

        i_bit = tvb_get_guint8(tvb, *offset) & BIT_1_MASK;
        l_bit = tvb_get_guint8(tvb, *offset) & BIT_2_MASK;
        t_bit = tvb_get_guint8(tvb, *offset) & BIT_3_MASK;
        k_bit = tvb_get_guint8(tvb, *offset) & BIT_4_MASK;
        if (i_bit)
        {
            (*offset)++;
            if(tvb_get_guint8(tvb, *offset) & BIT_1_MASK)
            {
                proto_tree_add_item(vp8_payload_descriptor_tree, hf_vp8_pld_extended_picture_id, tvb, *offset, 2, ENC_BIG_ENDIAN);
                (*offset)++;
            }
            else
            {
                proto_tree_add_item(vp8_payload_descriptor_tree, hf_vp8_pld_picture_id, tvb, *offset, 1, ENC_BIG_ENDIAN);
            }

        }
        if (l_bit)
        {
            (*offset)++;
            proto_tree_add_item(vp8_payload_descriptor_tree, hf_vp8_pld_tl0picidx, tvb, *offset, 1, ENC_BIG_ENDIAN);
        }
        if (t_bit || k_bit)
        {
             (*offset)++;
             proto_tree_add_item(vp8_payload_descriptor_tree, hf_vp8_pld_tid, tvb, *offset, 1, ENC_BIG_ENDIAN);
             proto_tree_add_item(vp8_payload_descriptor_tree, hf_vp8_pld_y_bit, tvb, *offset, 1, ENC_BIG_ENDIAN);
             proto_tree_add_item(vp8_payload_descriptor_tree, hf_vp8_pld_keyidx, tvb, *offset, 1, ENC_BIG_ENDIAN);
        }
    }
    (*offset)++;
    /* now we know the length of payload descriptor */
    proto_item_set_len(item_descriptor, *offset);
}

static void
dissect_vp8_payload_header(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *vp8_tree, gint *offset, gint *frametype, gint *partition1_size)
{
    proto_item *item_header;
    proto_tree *vp8_payload_header_tree;
    gint size0, size1, size2;

/*
The first three octets of an encoded VP8 frame are referred to as an
   "uncompressed data chunk" in [RFC6386], and co-serve as payload
   header in this RTP format.  The codec bitstream format specifies two
   different variants of the uncompressed data chunk: a 3 octet version
   for interframes and a 10 octet version for key frames.  The first 3
   octets are common to both variants.  In the case of a key frame the
   remaining 7 octets are considered to be part of the remaining payload
   in this RTP format.  Note that the header is present only in packets
   which have the S bit equal to one and the PartID equal to zero in the
   payload descriptor.  Subsequent packets for the same frame do not
   carry the payload header.


      0 1 2 3 4 5 6 7
     +-+-+-+-+-+-+-+-+
     |Size0|H| VER |P|
     +-+-+-+-+-+-+-+-+
     |     Size1     |
     +-+-+-+-+-+-+-+-+
     |     Size2     |
     +-+-+-+-+-+-+-+-+
     | Bytes 4..N of |
     | VP8 payload   |
     :               :
     +-+-+-+-+-+-+-+-+
     | OPTIONAL RTP  |
     | padding       |
     :               :
     +-+-+-+-+-+-+-+-+

*/

    vp8_payload_header_tree = proto_tree_add_subtree(vp8_tree, tvb, *offset, 3, ett_vp8_payload_header, &item_header, "Payload header");
    proto_tree_add_item(vp8_payload_header_tree, hf_vp8_hdr_frametype, tvb, *offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(vp8_payload_header_tree, hf_vp8_hdr_version,   tvb, *offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(vp8_payload_header_tree, hf_vp8_hdr_show_bit,  tvb, *offset, 1, ENC_BIG_ENDIAN);

    *frametype = tvb_get_guint8(tvb, *offset) & BIT_8_MASK;

    size0 = (tvb_get_guint8(tvb, *offset) & BIT_123_MASK) >> 5;
    size1 = tvb_get_guint8(tvb, *offset + 1);
    size2 = tvb_get_guint8(tvb, *offset + 2);
    (*partition1_size) = size0 + (size1*8) + (size2*2048);
    proto_tree_add_uint(vp8_payload_header_tree, hf_vp8_hdr_first_partition_size, tvb, *offset, 3, *partition1_size);
    (*offset)++;
    (*offset)++;
    (*offset)++;

}

static void
dissect_vp8_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *vp8_tree, gint *offset, gint *frametype, gint *partition1_size)
{
    proto_tree *vp8_payload_tree;
    proto_item *payload_item;
    gint remainder;

    vp8_payload_tree = proto_tree_add_subtree(vp8_tree, tvb, *offset, -1, ett_vp8_payload, &payload_item, "Payload");

    if (*frametype == 0)
    {
        guint16 width, height;
        gint start1, start2, start3, horizontal_scale, vertical_scale;
        proto_tree *vp8_keyframe_tree;

        vp8_keyframe_tree = proto_tree_add_subtree(vp8_payload_tree, tvb, *offset, -1, ett_vp8_keyframe, NULL, "Keyframe header");

        proto_tree_add_item(vp8_keyframe_tree, hf_vp8_keyframe_start_code, tvb, *offset, 3, ENC_BIG_ENDIAN);
        start1 = tvb_get_guint8(tvb, *offset);
        start2 = tvb_get_guint8(tvb, *offset + 1);
        start3 = tvb_get_guint8(tvb, *offset + 2);

        /* check start code is correct */
        if ((start1 != 0x9d) || (start2 != 0x01) || (start3 != 0x2a))
        {
            expert_add_info(pinfo, vp8_keyframe_tree, &ei_vp8_startcode);
        }

        (*offset)++;
        (*offset)++;
        (*offset)++;
        width = tvb_get_letohs(tvb, *offset) & 0x3FFF;
        horizontal_scale = tvb_get_letohs(tvb, *offset)>>14;

        proto_tree_add_uint(vp8_keyframe_tree, hf_vp8_keyframe_horizontal_scale, tvb, *offset, 2, horizontal_scale);
        proto_tree_add_uint(vp8_keyframe_tree, hf_vp8_keyframe_width, tvb, *offset, 2, width);
        (*offset)++;
        (*offset)++;

        height = tvb_get_letohs(tvb, *offset) & 0x3FFF;
        vertical_scale = tvb_get_letohs(tvb, *offset)>>14;
        proto_tree_add_uint(vp8_keyframe_tree, hf_vp8_keyframe_vertical_scale, tvb, *offset, 2, vertical_scale);
        proto_tree_add_uint(vp8_keyframe_tree, hf_vp8_keyframe_height, tvb, *offset, 2, height);
        (*offset)++;
        (*offset)++;
    }

    remainder = tvb_reported_length_remaining(tvb, (*offset));
    if ((*partition1_size) == -1)
    {
        /*no header, continuation?*/
        proto_tree_add_expert_format(vp8_payload_tree, pinfo, &ei_vp8_continuation, tvb, *offset, -1, "Continuation of partition fragment (%d bytes)", remainder);
    }
    else
    {
        if (remainder < *partition1_size)
        {
            /* partition size has already been added to vp8 header tree, but it would be useful to provide additional explanation */
            proto_tree_add_expert_format(vp8_payload_tree, pinfo, &ei_vp8_first_partition_split, tvb, *offset, -1,
                "First partition is split with %d bytes in this packet and %d bytes in subsequent frames", remainder, ((*partition1_size)-remainder));
        }
        else
        {
            (*offset)= (*offset) + (*partition1_size);
            proto_tree_add_expert_format(vp8_payload_tree, pinfo, &ei_vp8_first_partition_plus, tvb, *offset, -1,
                                "This frame contains all of first partition (%d bytes) and also %d bytes from other partitions",
                                *partition1_size, remainder);
        }
    }
    expert_add_info(pinfo, payload_item, &ei_vp8_undecoded);
}

void
proto_register_vp8(void)
{
    module_t *vp8_module;
    expert_module_t* expert_vp8;

    static hf_register_info hf[] = {
        { &hf_vp8_pld_x_bit,
            { "X bit",           "vp8.pld.x",
            FT_BOOLEAN, 8, TFS(&vp8_x_bit_vals), BIT_1_MASK,
            NULL, HFILL }
        },
        { &hf_vp8_pld_r_bit,
            { "R bit",           "vp8.pld.r",
            FT_BOOLEAN, 8, TFS(&vp8_r_bit_vals), BIT_2_MASK,
            NULL, HFILL }
        },
        { &hf_vp8_pld_n_bit,
            { "N bit",           "vp8.pld.n",
            FT_BOOLEAN, 8, TFS(&vp8_n_bit_vals), BIT_3_MASK,
            NULL, HFILL }
        },
        { &hf_vp8_pld_s_bit,
            { "S bit",           "vp8.pld.s",
            FT_BOOLEAN, 8, TFS(&vp8_s_bit_vals), BIT_4_MASK,
            NULL, HFILL }
        },
        { &hf_vp8_pld_part_id,
            { "Part Id",           "vp8.pld.partid",
            FT_UINT8, BASE_DEC, NULL, BIT_5678_MASK,
            NULL, HFILL }
        },
        { &hf_vp8_pld_i_bit,
            { "I bit",           "vp8.pld.i",
            FT_BOOLEAN, 8, TFS(&vp8_i_bit_vals), BIT_1_MASK,
            NULL, HFILL }
        },
        { &hf_vp8_pld_l_bit,
            { "L bit",           "vp8.pld.l",
            FT_BOOLEAN, 8, TFS(&vp8_l_bit_vals), BIT_2_MASK,
            NULL, HFILL }
        },
        { &hf_vp8_pld_t_bit,
            { "T bit",           "vp8.pld.t",
            FT_BOOLEAN, 8, TFS(&vp8_t_bit_vals), BIT_3_MASK,
            NULL, HFILL }
        },
        { &hf_vp8_pld_k_bit,
            { "K bit",           "vp8.pld.k",
            FT_BOOLEAN, 8, TFS(&vp8_k_bit_vals), BIT_4_MASK,
            NULL, HFILL }
        },
        { &hf_vp8_pld_rsv_a,
            { "Reserved A",           "vp8.pld.rsva",
            FT_UINT8, BASE_DEC, NULL, BIT_5678_MASK,
            NULL, HFILL }
        },
        { &hf_vp8_pld_picture_id,
            { "Picture Id",           "vp8.pld.pictureid",
            FT_UINT8, BASE_DEC, NULL, BIT_NO_MASK,
            NULL, HFILL }
        },
        { &hf_vp8_pld_extended_picture_id,
            { "Extended Picture Id",           "vp8.pld.pictureid",
            FT_UINT8, BASE_DEC, NULL, BIT_EXT_PICTURE_MASK,
            NULL, HFILL }
        },
        { &hf_vp8_pld_tl0picidx,
            { "Temporal layer zero Picture Index (TL0PICIDX)",           "vp8.pld.tl0picidx",
            FT_UINT8, BASE_DEC, NULL, BIT_NO_MASK,
            NULL, HFILL }
        },
        { &hf_vp8_pld_tid,
            { "Temporal layer Index (TID)",           "vp8.pld.tid",
            FT_UINT8, BASE_DEC, NULL, BIT_12_MASK,
            NULL, HFILL }
        },
        { &hf_vp8_pld_y_bit,
            { "1 Lay Sync Bit (Y)",           "vp8.pld.y",
            FT_BOOLEAN, 8, NULL, BIT_3_MASK,
            NULL, HFILL }
        },
        { &hf_vp8_pld_keyidx,
            { "Temporal Key Frame Index (KEYIDX)",           "vp8.pld.keyidx",
            FT_UINT8, BASE_DEC, NULL, BIT_45678_MASK,
            NULL, HFILL }
        },
        { &hf_vp8_hdr_frametype,
            { "frametype",           "vp8.hdr.frametype",
            FT_BOOLEAN, 8, TFS(&vp8_hdr_frametype_vals), BIT_8_MASK,
            NULL, HFILL }
        },
        { &hf_vp8_hdr_version,
            { "version",           "vp8.hdr.version",
            FT_UINT8, BASE_DEC, NULL, BIT_567_MASK,
            NULL, HFILL }
        },
        { &hf_vp8_hdr_show_bit,
            { "Show bit",           "vp8.hdr.show",
            FT_BOOLEAN, 8, NULL, BIT_5_MASK,
            NULL, HFILL }
        },
        { &hf_vp8_hdr_first_partition_size,
            { "First partition size",           "vp8.hdr.partition_size",
            FT_UINT8, BASE_DEC, NULL, BIT_PARTITION_SIZE_MASK,
            NULL, HFILL }
        },
        { &hf_vp8_keyframe_start_code,
            { "VP8 Start code",           "vp8.keyframe.start_code",
            FT_UINT24, BASE_HEX, NULL, BIT_3BYTE_NO_MASK,
            NULL, HFILL }
        },
        { &hf_vp8_keyframe_width,
            { "Width",           "vp8.keyframe.width",
            FT_UINT16, BASE_DEC, NULL, BIT_2BYTE_NO_MASK,
            NULL, HFILL }
        },
        { &hf_vp8_keyframe_height,
            { "Height",           "vp8.keyframe.height",
            FT_UINT16, BASE_DEC, NULL, BIT_2BYTE_NO_MASK,
            NULL, HFILL }
        },
        { &hf_vp8_keyframe_horizontal_scale,
            { "Horizontal Scale",           "vp8.keyframe.horizontal_scale",
            FT_UINT8, BASE_DEC, NULL, BIT_12_MASK,
            NULL, HFILL }
        },
        { &hf_vp8_keyframe_vertical_scale,
            { "Vertical Scale",           "vp8.keyframe.vertical_scale",
            FT_UINT8, BASE_DEC, NULL, BIT_12_MASK,
            NULL, HFILL }
        }

    };

    static ei_register_info ei[] = {
        { &ei_vp8_startcode, { "vp8.keyframe.startcode", PI_PROTOCOL, PI_ERROR, "Startcode is incorrect", EXPFILL }},
        { &ei_vp8_undecoded, { "vp8.undecoded", PI_UNDECODED, PI_NOTE, "Payload not fully decoded", EXPFILL }},
        { &ei_vp8_continuation, { "vp8.continuation", PI_REASSEMBLE, PI_CHAT, "Continuation of partition fragment", EXPFILL }},
        { &ei_vp8_first_partition_split, { "vp8.first_partition_split", PI_REASSEMBLE, PI_CHAT, "First partition is split", EXPFILL }},
        { &ei_vp8_first_partition_plus, { "vp8.first_partition_plus", PI_REASSEMBLE, PI_CHAT, "This frame contains all of first partition and also bytes from other partitions", EXPFILL }},
    };

    proto_vp8 = proto_register_protocol (
        "VP8", /* name       */
        "VP8",      /* short name */
        "vp8"       /* abbrev     */
        );

    proto_register_field_array(proto_vp8, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    vp8_module = prefs_register_protocol(proto_vp8, proto_reg_handoff_vp8);

    expert_vp8 = expert_register_protocol(proto_vp8);
    expert_register_field_array(expert_vp8, ei, array_length(ei));

    prefs_register_range_preference(vp8_module, "dynamic.payload.type",
                            "vp8 dynamic payload types",
                            "Dynamic payload types which will be interpreted as vp8"
                            "; Values must be in the range 96 - 127",
                            &temp_dynamic_payload_type_range, 127);

    register_dissector("vp8", dissect_vp8, proto_vp8);
}

static void
range_delete_vp8_rtp_pt_callback(guint32 rtp_pt) {
    if ((rtp_pt >= 96) && (rtp_pt <= 127))
        dissector_delete_uint("rtp.pt", rtp_pt, vp8_handle);
}

static void
range_add_vp8_rtp_pt_callback(guint32 rtp_pt) {
    if ((rtp_pt >= 96) && (rtp_pt <= 127))
        dissector_add_uint("rtp.pt", rtp_pt, vp8_handle);
}

void
proto_reg_handoff_vp8(void)
{
    static range_t  *dynamic_payload_type_range = NULL;
    static gboolean  vp8_prefs_initialized      = FALSE;

    if (!vp8_prefs_initialized) {
        vp8_handle = find_dissector("vp8");
        dissector_add_string("rtp_dyn_payload_type" , "VP8", vp8_handle);
        vp8_prefs_initialized = TRUE;
    } else {
        range_foreach(dynamic_payload_type_range, range_delete_vp8_rtp_pt_callback);
        g_free(dynamic_payload_type_range);
    }

    dynamic_payload_type_range = range_copy(temp_dynamic_payload_type_range);
    range_foreach(dynamic_payload_type_range, range_add_vp8_rtp_pt_callback);
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
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
