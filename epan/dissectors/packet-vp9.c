/* packet-vp9.c
 * Routines for VP9 dissection
 * Copyright 2023, Noan Perrot <noan.perrot@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * vp9-bitstream-specification-v0.6-20160331-draft - VP9 Bitstream & Decoding Process Specification
 * draft-ietf-payload-vp9-16 - RTP Payload Format for VP9 Video
 */

#include "config.h"
/* Define the name for the logging domain (try to avoid collisions with existing domains) */
#define WS_LOG_DOMAIN "vp9"

/* Global header providing a minimum base set of required macros and APIs */
#include <wireshark.h>

#include <epan/packet.h> /* Required dissection API header */
#include <epan/expert.h> /* Include only as needed */
#include <epan/prefs.h>  /* Include only as needed */

#define STRING_SIZE 50
#define VP9_1_BIT_MASK 0x80
#define VP9_2_BIT_MASK 0x40
#define VP9_3_BIT_MASK 0x20
#define VP9_4_BIT_MASK 0x10
#define VP9_5_BIT_MASK 0x08
#define VP9_6_BIT_MASK 0x04
#define VP9_7_BIT_MASK 0x02
#define VP9_8_BIT_MASK 0x01
#define VP9_2_BITS_MASK 0xC0
#define VP9_3_BITS_MASK 0xE0
#define VP9_7_BITS_MASK 0xFE
#define VP9_8_BITS_MASK 0xFF
#define VP9_16_BITS_MASK 0xFFFF
#define VP9_EXTENDED_PID 0x7FFF

static int proto_vp9;

static int hf_vp9_pld_i_bit;
static int hf_vp9_pld_p_bit;
static int hf_vp9_pld_l_bit;
static int hf_vp9_pld_f_bit;
static int hf_vp9_pld_b_bit;
static int hf_vp9_pld_e_bit;
static int hf_vp9_pld_v_bit;
static int hf_vp9_pld_z_bit;
static int hf_vp9_pld_u_bit;
static int hf_vp9_pld_m_bit;
static int hf_vp9_pld_d_bit;
static int hf_vp9_pld_n_bit;
static int hf_vp9_pld_y_bit;
static int hf_vp9_pld_g_bit;
static int hf_vp9_pld_pg_bits;
static int hf_vp9_pld_n_s_bits;
static int hf_vp9_pld_n_g_bits;
static int hf_vp9_pld_sid_bits;
static int hf_vp9_pld_pid_bits;
static int hf_vp9_pld_tid_bits;
static int hf_vp9_pld_width_bits;
static int hf_vp9_pld_height_bits;
static int hf_vp9_pld_n_s_numbers;
static int hf_vp9_pld_p_diff_bits;
static int hf_vp9_pld_tl0picidx_bits;
static int hf_vp9_pld_pg_extended_bits;
static int hf_vp9_pld_pid_extended_bits;

static int ett_vp9;
static int ett_vp9_descriptor;

static int *ett[] = {
    &ett_vp9,
    &ett_vp9_descriptor
};

static int
dissect_vp9(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VP9");

    proto_item *vp9_item = proto_tree_add_item(tree, proto_vp9, tvb, 0, -1, ENC_NA);
    proto_tree *vp9_tree = proto_item_add_subtree(vp9_item, ett_vp9);

    proto_item *vp9_descriptor_item;
    proto_tree *vp9_descriptor_tree = proto_tree_add_subtree(vp9_tree, tvb, 0, 1, ett_vp9_descriptor, &vp9_descriptor_item, "Payload Descriptor");

    int offset = 0;

    /*
          0 1 2 3 4 5 6 7
         +-+-+-+-+-+-+-+-+
         |I|P|L|F|B|E|V|Z| (REQUIRED)
         +-+-+-+-+-+-+-+-+
    */
    uint8_t i = tvb_get_uint8(tvb, offset) & VP9_1_BIT_MASK;
    uint8_t p = tvb_get_uint8(tvb, offset) & VP9_2_BIT_MASK;
    uint8_t l = tvb_get_uint8(tvb, offset) & VP9_3_BIT_MASK;
    uint8_t f = tvb_get_uint8(tvb, offset) & VP9_4_BIT_MASK;
    uint8_t v = tvb_get_uint8(tvb, offset) & VP9_7_BIT_MASK;
    proto_tree_add_item(vp9_descriptor_tree, hf_vp9_pld_i_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(vp9_descriptor_tree, hf_vp9_pld_p_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(vp9_descriptor_tree, hf_vp9_pld_l_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(vp9_descriptor_tree, hf_vp9_pld_f_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(vp9_descriptor_tree, hf_vp9_pld_b_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(vp9_descriptor_tree, hf_vp9_pld_e_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(vp9_descriptor_tree, hf_vp9_pld_v_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(vp9_descriptor_tree, hf_vp9_pld_z_bit, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    /*
         +-+-+-+-+-+-+-+-+
    I:   |M| PICTURE ID  | (REQUIRED)
         +-+-+-+-+-+-+-+-+
    M:   | EXTENDED PID  | (RECOMMENDED)
         +-+-+-+-+-+-+-+-+
    */
    uint8_t m = tvb_get_uint8(tvb, offset) & VP9_1_BIT_MASK;
    proto_tree_add_item(vp9_descriptor_tree, hf_vp9_pld_m_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (f)
    {
        //  Flexible mode
        if (m == i)
        {
            if (m)
            {
                //  Extended PID
                proto_tree_add_item(vp9_descriptor_tree, hf_vp9_pld_pid_extended_bits, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
            }
            else
            {
                //  PID
                proto_tree_add_item(vp9_descriptor_tree, hf_vp9_pld_pid_bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
            }
        }
        else
        {
            //  Malformed packet
        }
    }
    else
    {
        //  Non-flexible mode
        if (m == i)
        {
            if (m)
            {
                //  Extended PID
                proto_tree_add_item(vp9_descriptor_tree, hf_vp9_pld_pg_extended_bits, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
            }
            else
            {
                //  PID
                proto_tree_add_item(vp9_descriptor_tree, hf_vp9_pld_pg_bits, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
            }
        }
        else
        {
            //  Malformed packet
        }
    }

    /*
         +-+-+-+-+-+-+-+-+
    L:   | TID |U| SID |D| (Conditionally RECOMMENDED)
         +-+-+-+-+-+-+-+-+
    */
    if (l)
    {
        //  Layer indices present
        proto_tree_add_item(vp9_descriptor_tree, hf_vp9_pld_tid_bits, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(vp9_descriptor_tree, hf_vp9_pld_u_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(vp9_descriptor_tree, hf_vp9_pld_sid_bits, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(vp9_descriptor_tree, hf_vp9_pld_d_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        if (f)
        {
            //  1 octet is present for the layer indices
            proto_item_set_len(vp9_descriptor_item, 4);
        }
        else
        {
            //  2 octets are present for the layer indices
            proto_tree_add_item(vp9_descriptor_tree, hf_vp9_pld_tl0picidx_bits, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_item_set_len(vp9_descriptor_item, 5);
            offset++;
        }
    }

    /*
          +-+-+-+-+-+-+-+-+                             -\
     P,F: | P_DIFF      |N| (Conditionally REQUIRED)    - up to 3 times
          +-+-+-+-+-+-+-+-+                             -/
    */
    if (p && f)
    {
        uint8_t n = tvb_get_uint8(tvb, offset) & (VP9_1_BIT_MASK >> 7);
        int idx = 0;
        int max_p_diff = 3;
        while (n && idx < max_p_diff)
        {
            proto_tree_add_item(vp9_descriptor_tree, hf_vp9_pld_p_diff_bits, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(vp9_descriptor_tree, hf_vp9_pld_n_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_item_set_len(vp9_descriptor_item, 6);
            offset++;
            n = tvb_get_uint8(tvb, offset) & (VP9_1_BIT_MASK >> 7);
            idx++;
            if (n && idx == max_p_diff)
            {
                //  Malformed packet
            }
        }
    }

    /*
           +-+-+-+-+-+-+-+-+
      V:   | SS            |
           | ..            |
           +-+-+-+-+-+-+-+-+
    */
    if (v)
    {
        /*
             +-+-+-+-+-+-+-+-+
        V:   | N_S |Y|G|-|-|-|
             +-+-+-+-+-+-+-+-+
        */
        proto_item* n_s_numbers_field;
        uint8_t n_s = (tvb_get_uint8(tvb, offset) & (VP9_3_BITS_MASK)) >> 5;
        uint8_t y = tvb_get_uint8(tvb, offset) & (VP9_1_BIT_MASK >> 3);
        uint8_t g = tvb_get_uint8(tvb, offset) & (VP9_1_BIT_MASK >> 4);
        uint8_t number_of_spatial_layers = n_s + 1;

        proto_tree_add_item(vp9_descriptor_tree, hf_vp9_pld_n_s_bits, tvb, offset, 1, ENC_BIG_ENDIAN);
        n_s_numbers_field = proto_tree_add_uint(vp9_descriptor_tree, hf_vp9_pld_n_s_numbers, tvb, offset, 1, number_of_spatial_layers);
        proto_tree_add_item(vp9_descriptor_tree, hf_vp9_pld_y_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(vp9_descriptor_tree, hf_vp9_pld_g_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_item_set_generated(n_s_numbers_field);

        offset++;

        /*
             +-+-+-+-+-+-+-+-+              -\
        Y:   |     WIDTH     | (OPTIONAL)    .
             +               +               .
             |               | (OPTIONAL)    .
             +-+-+-+-+-+-+-+-+               . - N_S + 1 times
             |     HEIGHT    | (OPTIONAL)    .
             +               +               .
             |               | (OPTIONAL)    .
             +-+-+-+-+-+-+-+-+              -/
        */
        uint8_t spatial_layer = 0;
        while (spatial_layer < number_of_spatial_layers)
        {
            if (y)
            {
                //  TODO: Add subtree for spatial layers
                proto_tree_add_item(vp9_descriptor_tree, hf_vp9_pld_width_bits, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(vp9_descriptor_tree, hf_vp9_pld_height_bits, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
            }
            spatial_layer++;
        }

        /*
             +-+-+-+-+-+-+-+-+
        G:   |      N_G      | (OPTIONAL)
             +-+-+-+-+-+-+-+-+
        */
        if (g)
        {
            /*
                     +-+-+-+-+-+-+-+-+                            -\
            N_G:     | TID |U| R |-|-| (OPTIONAL)                 .
                     +-+-+-+-+-+-+-+-+              -\            . - N_G times
                     |    P_DIFF     | (OPTIONAL)    . - R times  .
                     +-+-+-+-+-+-+-+-+              -/            -/
            */
            proto_tree_add_item(vp9_descriptor_tree, hf_vp9_pld_n_g_bits, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            //  TODO: handle N_G
        }
    }

    return tvb_captured_length(tvb);
}

void proto_register_vp9(void)
{
    static hf_register_info hf[] = {
        {&hf_vp9_pld_i_bit,
         {"Picture ID present (I)", "vp9.pld.i",
          FT_BOOLEAN, 8,
          NULL, VP9_1_BIT_MASK,
          NULL, HFILL}},
        {&hf_vp9_pld_p_bit,
         {"Inter-picture predicted frame (P)", "vp9.pld.p",
          FT_BOOLEAN, 8,
          NULL, VP9_2_BIT_MASK,
          NULL, HFILL}},
        {&hf_vp9_pld_l_bit,
         {"Layer indices present (L)", "vp9.pld.l",
          FT_BOOLEAN, 8,
          NULL, VP9_3_BIT_MASK,
          NULL, HFILL}},
        {&hf_vp9_pld_f_bit,
         {"Flexible mode (F)", "vp9.pld.f",
          FT_BOOLEAN, 8,
          NULL, VP9_4_BIT_MASK,
          NULL, HFILL}},
        {&hf_vp9_pld_b_bit,
         {"Start of a frame (B)", "vp9.pld.b",
          FT_BOOLEAN, 8,
          NULL, VP9_5_BIT_MASK,
          NULL, HFILL}},
        {&hf_vp9_pld_e_bit,
         {"End of a frame (E)", "vp9.pld.e",
          FT_BOOLEAN, 8,
          NULL, VP9_6_BIT_MASK,
          NULL, HFILL}},
        {&hf_vp9_pld_v_bit,
         {"Scalability structure (SS) data present (V)", "vp9.pld.v",
          FT_BOOLEAN, 8,
          NULL, VP9_7_BIT_MASK,
          NULL, HFILL}},
        {&hf_vp9_pld_z_bit,
         {"Not a reference frame for upper spatial layers (Z)", "vp9.pld.z",
          FT_BOOLEAN, 8,
          NULL, VP9_8_BIT_MASK,
          NULL, HFILL}},
        {&hf_vp9_pld_m_bit,
         {"Extension flag (M)", "vp9.pld.m",
          FT_BOOLEAN, 8,
          NULL, VP9_1_BIT_MASK,
          NULL, HFILL}},
        {&hf_vp9_pld_pid_bits,
         {"Picture ID (PID)", "vp9.pld.pid",
          FT_UINT8, BASE_DEC,
          NULL, VP9_7_BITS_MASK >> 1,
          NULL, HFILL}},
        {&hf_vp9_pld_pid_extended_bits,
         {"Picture ID (PID) Extended", "vp9.pld.pid_ext",
          FT_UINT16, BASE_DEC,
          NULL, VP9_EXTENDED_PID,
          NULL, HFILL}},
        {&hf_vp9_pld_pg_bits,
         {"Picture Group Index (PG)", "vp9.pld.pg",
          FT_UINT8, BASE_DEC,
          NULL, VP9_7_BITS_MASK >> 1,
          NULL, HFILL}},
        {&hf_vp9_pld_pg_extended_bits,
         {"Picture Group Index (PG) Extended", "vp9.pld.pg_ext",
          FT_UINT16, BASE_DEC,
          NULL, VP9_EXTENDED_PID,
          NULL, HFILL}},
        {&hf_vp9_pld_tid_bits,
         {"Temporal layer ID", "vp9.pld.tid",
          FT_UINT8, BASE_DEC,
          NULL, VP9_3_BITS_MASK,
          NULL, HFILL}},
        {&hf_vp9_pld_u_bit,
         {"Switching up point (U)", "vp9.pld.u",
          FT_BOOLEAN, 8,
          NULL, VP9_1_BIT_MASK >> 3,
          NULL, HFILL}},
        {&hf_vp9_pld_sid_bits,
         {"Spatial Layer ID", "vp9.pld.sid",
          FT_UINT8, BASE_DEC,
          NULL, VP9_3_BITS_MASK >> 4,
          NULL, HFILL}},
        {&hf_vp9_pld_d_bit,
         {"Inter-layer dependency used (D)", "vp9.pld.d",
          FT_BOOLEAN, 8,
          NULL, VP9_1_BIT_MASK >> 7,
          NULL, HFILL}},
        {&hf_vp9_pld_tl0picidx_bits,
         {"Temporal layer zero index", "vp9.pld.tl0picidx",
          FT_UINT8, BASE_DEC,
          NULL, 0,
          NULL, HFILL}},
        {&hf_vp9_pld_p_diff_bits,
         {"Reference index (P_DIFF)", "vp9.pld.p_diff",
          FT_UINT8, BASE_DEC,
          NULL, VP9_7_BITS_MASK,
          NULL, HFILL}},
        {&hf_vp9_pld_n_bit,
         {"Additional reference index (N)", "vp9.pld.n",
          FT_BOOLEAN, 8,
          NULL, VP9_1_BIT_MASK >> 7,
          NULL, HFILL}},
        {&hf_vp9_pld_n_s_bits,
         {"Spatial layers minus 1 (N_S)", "vp9.pld.n_s",
          FT_UINT8, BASE_DEC,
          NULL, VP9_3_BITS_MASK,
          NULL, HFILL}},
        {&hf_vp9_pld_n_s_numbers,
         {"Number of spatial layers", "vp9.pld.spatial_layers_number",
          FT_UINT8, BASE_DEC,
          NULL, 0,
          NULL, HFILL}},
        {&hf_vp9_pld_y_bit,
         {"Spatial layer's frame resolution present (Y)", "vp9.pld.y",
          FT_BOOLEAN, 8,
          NULL, VP9_1_BIT_MASK >> 3,
          NULL, HFILL}},
        {&hf_vp9_pld_g_bit,
         {"PG description flag (G)", "vp9.pld.g",
          FT_BOOLEAN, 8,
          NULL, VP9_1_BIT_MASK >> 4,
          NULL, HFILL}},
        {&hf_vp9_pld_height_bits,
         {"Height", "vp9.pld.height",
          FT_UINT16, BASE_DEC,
          NULL, 0,
          NULL, HFILL}},
        {&hf_vp9_pld_width_bits,
         {"Width", "vp9.pld.width",
          FT_UINT16, BASE_DEC,
          NULL, 0,
          NULL, HFILL}},
        {&hf_vp9_pld_n_g_bits,
         {"Number of pictures (N_G)", "vp9.pld.n_g",
          FT_UINT8, BASE_DEC,
          NULL, 0,
          NULL, HFILL}}};

    proto_vp9 = proto_register_protocol("VP9", "VP9", "vp9");

    proto_register_field_array(proto_vp9, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_vp9(void)
{
    static dissector_handle_t vp9_handle;

    vp9_handle = register_dissector("vp9", dissect_vp9, proto_vp9);

    dissector_add_string("rtp_dyn_payload_type", "vp9", vp9_handle);
    dissector_add_uint_range_with_preference("rtp.pt", "", vp9_handle);
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
