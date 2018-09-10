/* packet-evc.c
 * Routines for AMR dissection
 * Copyright 2005-2008, Anders Broman <anders.broman[at]ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References:
 * 3GPP TS 26.445 A.2 EVS RTP Payload Format
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>


void proto_register_evs(void);
void proto_reg_handoff_evs(void);

static dissector_handle_t evs_handle;

/* Initialize the protocol and registered fields */
static int proto_evs = -1;

static int hf_evs_packet_length = -1;
static int hf_evs_voice_data = -1;
static int hf_evs_h_bit = -1;
static int hf_evs_cmr_t = -1;
static int hf_evs_cmr_t0_d = -1;
static int hf_evs_cmr_t1_d = -1;
static int hf_evs_cmr_t2_d = -1;
static int hf_evs_cmr_t3_d = -1;
static int hf_evs_cmr_t4_d = -1;
static int hf_evs_cmr_t5_d = -1;
static int hf_evs_cmr_t6_d = -1;
static int hf_evs_cmr_t7_d = -1;
static int hf_evs_f_bit = -1;
static int hf_evs_mode_bit = -1;
static int hf_evs_toc_spare = -1;
static int hf_evs_amr_wb_q_bit = -1;
static int hf_evs_bit_rate_mode_0 = -1;
static int hf_evs_bit_rate_mode_1 = -1;
static int hf_evs_cmr_amr_io = -1;

static int ett_evs = -1;
static int ett_evs_header = -1;

/* The dynamic payload type which will be dissected as EVS */
static guint temp_dynamic_payload_type = 0;

static const value_string evs_protected_payload_sizes_value[] = {
{    48, "EVS Primary 2.4" },
{    56, "Special case" },
{   136, "EVS AMR-WB IO" },
{   144, "EVS Primary 7.2" },
{   160, "EVS Primary 8.0" },
{   184, "EVS AMR-WB IO" },
{   192, "EVS Primary 9.6" },
{   256, "EVS AMR-WB IO" },
{   264, "EVS Primary 13.2" },
{   288, "EVS AMR-WB IO" },
{   320, "EVS AMR-WB IO" },
{   328, "EVS Primary 16.4" },
{   368, "EVS AMR-WB IO" },
{   400, "EVS AMR-WB IO" },
{   464, "EVS AMR-WB IO" },
{   480, "EVS Primary 24.0" },
{   488, "EVS Primary 24.4" },
{   640, "EVS Primary 32.0" },
{   960, "EVS Primary 48.0" },
{  1280, "EVS Primary 64.0" },
{  1920, "EVS Primary 96.0" },
{  2560, "EVS Primary 128.0" },
{ 0, NULL }
};

static const value_string evs_d_bits_t0_values[] = {
    { 0x0, "NB 5.9 (VBR)" },
    { 0x1, "NB 7.2" },
    { 0x2, "NB 8.0" },
    { 0x3, "NB 9.6" },
    { 0x4, "NB 13.2" },
    { 0x5, "NB 16.4" },
    { 0x6, "Not used" },
    { 0x7, "Not used" },
    { 0x8, "Not used" },
    { 0x9, "Not used" },
    { 0xa, "Not used" },
    { 0xb, "Not used" },
    { 0xc, "Not used" },
    { 0xd, "Not used" },
    { 0xe, "Not used" },
    { 0xf, "Not used" },
    { 0, NULL }
};

static const value_string evs_d_bits_t1_values[] = {
    { 0x0, "IO 6.6" },
    { 0x1, "IO 8.8" },
    { 0x2, "IO 12.65" },
    { 0x3, "IO 14.25" },
    { 0x4, "IO 15.85" },
    { 0x5, "IO 18.25" },
    { 0x6, "IO 19.85" },
    { 0x7, "IO 23.05" },
    { 0x8, "IO 23.85" },
    { 0x9, "Not used" },
    { 0xa, "Not used" },
    { 0xb, "Not used" },
    { 0xc, "Not used" },
    { 0xd, "Not used" },
    { 0xe, "Not used" },
    { 0xf, "Not used" },
    { 0, NULL }
};


static const value_string evs_d_bits_t2_values[] = {
    { 0x0, "WB 5.9 (VBR)" },
    { 0x1, "WB 7.2" },
    { 0x2, "WB 8" },
    { 0x3, "WB 9.6" },
    { 0x4,"WB 13.2" },
    { 0x5,"WB 16.4" },
    { 0x6,"WB 24.4" },
    { 0x7,"WB 32" },
    { 0x8,"WB 48" },
    { 0x9,"WB 64" },
    { 0xa,"WB 96" },
    { 0xb,"WB 128" },
    { 0xc, "Not used" },
    { 0xd, "Not used" },
    { 0xe, "Not used" },
    { 0xf, "Not used" },
    { 0, NULL }
};

static const value_string evs_d_bits_t3_values[] = {
    { 0x0, "Not used" },
    { 0x1, "Not used" },
    { 0x2, "Not used" },
    { 0x3, "SWB 9.6" },
    { 0x4, "SWB 13.2" },
    { 0x5, "SWB 16.4" },
    { 0x6, "SWB 24.4" },
    { 0x7, "SWB 32" },
    { 0x8, "SWB 48" },
    { 0x9, "SWB 64" },
    { 0xa, "SWB 96" },
    { 0xb, "SWB 128" },
    { 0xc, "Not used" },
    { 0xd, "Not used" },
    { 0xe, "Not used" },
    { 0xf, "Not used" },
    { 0, NULL }
};

static const value_string evs_d_bits_t4_values[] = {
    { 0x0, "Not used" },
    { 0x1, "Not used" },
    { 0x2, "Not used" },
    { 0x3, "Not used" },
    { 0x4, "Not used" },
    { 0x5, "FB 16.4" },
    { 0x6, "FB 24.4" },
    { 0x7, "FB 32" },
    { 0x8, "FB 48" },
    { 0x9, "FB 64" },
    { 0xa, "FB 96" },
    { 0xb, "FB 128" },
    { 0xc, "Not used" },
    { 0xd, "Not used" },
    { 0xe, "Not used" },
    { 0xf, "Not used" },
    { 0, NULL }
};

static const value_string evs_d_bits_t5_values[] = {
    { 0x0, "WB 13.2 CA-L-O2" },
    { 0x1, "WB 13.2 CA-L-O2" },
    { 0x2, "WB 13.2 CA-L-O5" },
    { 0x3, "WB 13.2 CA-L-O7" },
    { 0x4, "WB 13.2 CA-H-O2" },
    { 0x5, "WB 13.2 CA-H-O3" },
    { 0x6, "WB 13.2 CA-H-O5" },
    { 0x7, "WB 13.2 CA-H-O7" },
    { 0x8, "Not used" },
    { 0x9, "Not used" },
    { 0xa, "Not used" },
    { 0xb, "Not used" },
    { 0xc, "Not used" },
    { 0xd, "Not used" },
    { 0xe, "Not used" },
    { 0xf, "Not used" },
    { 0, NULL }
};

static const value_string evs_d_bits_t6_values[] = {
    { 0x0, "SWB 13.2 CA-L-O2" },
    { 0x1, "SWB 13.2 CA-L-O2" },
    { 0x2, "SWB 13.2 CA-L-O5" },
    { 0x3, "SWB 13.2 CA-L-O7" },
    { 0x4, "SWB 13.2 CA-H-O2" },
    { 0x5, "SWB 13.2 CA-H-O3" },
    { 0x6, "SWB 13.2 CA-H-O5" },
    { 0x7, "SWB 13.2 CA-H-O7" },
    { 0x8, "Not used" },
    { 0x9, "Not used" },
    { 0xa, "Not used" },
    { 0xb, "Not used" },
    { 0xc, "Not used" },
    { 0xd, "Not used" },
    { 0xe, "Not used" },
    { 0xf, "Not used" },
    { 0, NULL }
};

static const value_string evs_d_bits_t7_values[] = {
    { 0x0, "Reserved" },
    { 0x1, "Reserved" },
    { 0x2, "Reserved" },
    { 0x3, "Reserved" },
    { 0x4, "Reserved" },
    { 0x5, "Reserved" },
    { 0x6, "Reserved" },
    { 0x7, "Reserved" },
    { 0x8, "Reserved" },
    { 0x9, "Reserved" },
    { 0xa, "Reserved" },
    { 0xb, "Reserved" },
    { 0xc, "Reserved" },
    { 0xd, "Reserved" },
    { 0xe, "Reserved" },
    { 0xf, "NO_REQ" },
    { 0, NULL }
};

static const value_string evs_bit_rate_mode_0_values[] = {
    { 0x0, "Primary 2.8 kbps" },
    { 0x1, "Primary 7.2 kbps" },
    { 0x2, "Primary 8.0 kbps" },
    { 0x3, "Primary 9.6 kbps" },
    { 0x4, "Primary 13.2 kbps" },
    { 0x5, "Primary 16.4 kbps" },
    { 0x6, "Primary 24.4 kbps" },
    { 0x7, "Primary 32.0 kbps" },
    { 0x8, "Primary 48.0 kbps" },
    { 0x9, "Primary 64.0 kbps" },
    { 0xa, "Primary 96.0 kbps" },
    { 0xb, "Primary 128.0 kbps" },
    { 0xc, "Primary 2.4kbps SID" },
    { 0xd, "For future use" },
    { 0xe, "SPEECH_LOST" },
    { 0xf, "NO_DATA" },
    { 0, NULL }
};

static const value_string evs_bit_rate_mode_1_values[] = {
    { 0x0, "AMR-WB IO 6.6 kbps" },
    { 0x1, "AMR-WB IO 8.85 kbps" },
    { 0x2, "AMR-WB IO 12.65 kbps" },
    { 0x3, "AMR-WB IO 14.24 kbps" },
    { 0x4, "AMR-WB IO 15.85 kbps" },
    { 0x5, "AMR-WB IO 18.25 kbps" },
    { 0x6, "AMR-WB IO 19.85 kbps" },
    { 0x7, "AMR-WB IO 23.05 kbps" },
    { 0x8, "AMR-WB IO 23.85 kbps" },
    { 0x9, "AMR-WB IO 2.0 kbps SID" },
    { 0xa, "For future use" },
    { 0xb, "For future use" },
    { 0xc, "For future use" },
    { 0xd, "For future use" },
    { 0xe, "SPEECH_LOST" },
    { 0xf, "NO_DATA" },
    { 0, NULL }
};


static const value_string evs_cmr_amr_io_values[] = {
    { 0x0, "AMR-WB IO 6.6 kbps" },
    { 0x1, "AMR-WB IO 8.85 kbps" },
    { 0x2, "AMR-WB IO 12.65 kbps" },
    { 0x3, "AMR-WB IO 15.85 kbps" },
    { 0x4, "AMR-WB IO 18.25 kbps" },
    { 0x5, "AMR-WB IO 23.05 kbps" },
    { 0x6, "AMR-WB IO 23.85 kbps" },
    { 0x7, "none" },
    { 0, NULL }
};

static const true_false_string tfs_evs_h_bit = {
    "CMR",
    "ToC"
};

static const true_false_string tfs_evs_f_bit = {
    "Speech frame follows",
    "Last frame in payload"
};

static const true_false_string toc_evs_q_bit_vals = {
    "Ok",
    "Severely damaged frame"
};

static void
dissect_evs_cmr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *evs_tree, int offset, guint8 t_bits)
{
    proto_tree *tree;
    /* CMR */
    tree = proto_tree_add_subtree(evs_tree, tvb, offset, 1, ett_evs_header, NULL, "CMR");

    switch (t_bits) {
    case 0:
    {
        static const int * flags_t0[] = {
            &hf_evs_h_bit,
            &hf_evs_cmr_t,
            &hf_evs_cmr_t0_d,
            NULL
        };

        proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags_t0, ENC_BIG_ENDIAN);
    }
    break;
    case 1:
    {
        static const int * flags_t1[] = {
            &hf_evs_h_bit,
            &hf_evs_cmr_t,
            &hf_evs_cmr_t1_d,
            NULL
        };

        proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags_t1, ENC_BIG_ENDIAN);
    }
    break;
    case 2:
    {
        static const int * flags_t2[] = {
            &hf_evs_h_bit,
            &hf_evs_cmr_t,
            &hf_evs_cmr_t2_d,
            NULL
        };

        proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags_t2, ENC_BIG_ENDIAN);
    }
    break;
    case 3:
    {
        static const int * flags_t3[] = {
            &hf_evs_h_bit,
            &hf_evs_cmr_t,
            &hf_evs_cmr_t3_d,
            NULL
        };

        proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags_t3, ENC_BIG_ENDIAN);
    }
    break;
    case 4:
    {
        static const int * flags_t4[] = {
            &hf_evs_h_bit,
            &hf_evs_cmr_t,
            &hf_evs_cmr_t4_d,
            NULL
        };

        proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags_t4, ENC_BIG_ENDIAN);
    }
    break;
    case 5:
    {
        static const int * flags_t5[] = {
            &hf_evs_h_bit,
            &hf_evs_cmr_t,
            &hf_evs_cmr_t5_d,
            NULL
        };

        proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags_t5, ENC_BIG_ENDIAN);
    }
    break;
    case 6:
    {
        static const int * flags_t6[] = {
            &hf_evs_h_bit,
            &hf_evs_cmr_t,
            &hf_evs_cmr_t6_d,
            NULL
        };

        proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags_t6, ENC_BIG_ENDIAN);
    }
    break;
    case 7:
    {
        static const int * flags_t7[] = {
            &hf_evs_h_bit,
            &hf_evs_cmr_t,
            &hf_evs_cmr_t7_d,
            NULL
        };

        proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags_t7, ENC_BIG_ENDIAN);
    }
    break;
    default:
        break;

    }

}

/* Code to actually dissect the packets */
static int
dissect_evs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_tree *evs_tree, *sub_tree;
    int offset = 0;
    int packet_len, idx;
    guint32 num_bits;
    const gchar *str;
    guint8 oct, h_bit, t_bits, toc_f_bit, evs_mode_b;
    int num_toc;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "EVS");


    /* Find out if we have one of the reserved packet sizes*/
    packet_len = tvb_reported_length(tvb);
    num_bits = packet_len * 8;
    str = try_val_to_str_idx(num_bits, evs_protected_payload_sizes_value, &idx);
    ti = proto_tree_add_item(tree, proto_evs, tvb, 0, -1, ENC_NA);
    evs_tree = proto_item_add_subtree(ti, ett_evs);
    if (str) {
        /* A.2.1 EVS codec Compact Format */
        /* One of the protected payload sizes, no further dissection currently. XXX add handling of "Special case"*/
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s ", str);
        proto_tree_add_int_format(evs_tree, hf_evs_packet_length, tvb, offset, 1, packet_len * 8, " %s, packet_len %i bits", str, packet_len * 8);
        if (strcmp(str, "EVS A") == 0) {
            /* A.2.1.2	Compact format for EVS AMR-WB IO mode */
            /* CMR */
            proto_tree_add_item(evs_tree, hf_evs_cmr_amr_io, tvb, offset, 1, ENC_BIG_ENDIAN);
        }

        proto_tree_add_item(evs_tree, hf_evs_voice_data, tvb, offset, -1, ENC_NA);
        return packet_len;
    }

    /* A.2.2 EVS codec Header-Full format */

    /*proto_tree_add_int_format(evs_tree, hf_evs_packet_length, tvb, offset, 1, packet_len * 8, "packet_len %i bits", packet_len * 8);*/
    oct = tvb_get_guint8(tvb, offset);
    h_bit = oct >> 7;
    t_bits = (oct & 0x70) >> 4;

    if (h_bit == 1) {
        /* `CMR */
        dissect_evs_cmr(tvb, pinfo, evs_tree, offset, t_bits);
        offset++;
    }
    /* ToC */
    num_toc = 0;
    do {
        oct = tvb_get_guint8(tvb, offset);
        toc_f_bit = (oct & 0x40) >> 6;
        evs_mode_b = (oct & 0x20) >> 5;
        num_toc++;

        sub_tree = proto_tree_add_subtree_format(evs_tree, tvb, offset, 1, ett_evs_header, NULL, "TOC %u",
            num_toc);

        if (evs_mode_b == 0) {
            static const int * flags_toc_mode_0[] = {
                &hf_evs_h_bit,
                &hf_evs_f_bit,
                &hf_evs_mode_bit,
                &hf_evs_toc_spare,
                &hf_evs_bit_rate_mode_0,
                NULL
            };

            proto_tree_add_bitmask_list(sub_tree, tvb, offset, 1, flags_toc_mode_0, ENC_BIG_ENDIAN);
        } else {
            static const int * flags_toc_mode_1[] = {
            &hf_evs_h_bit,
            &hf_evs_f_bit,
            &hf_evs_mode_bit,
            &hf_evs_amr_wb_q_bit,
            &hf_evs_bit_rate_mode_1,
            NULL
            };

            proto_tree_add_bitmask_list(sub_tree, tvb, offset, 1, flags_toc_mode_1, ENC_BIG_ENDIAN);
        }
        offset++;
    } while (toc_f_bit == 1);

    return packet_len;
}

void
proto_register_evs(void)
{
    module_t *evs_module;
    /*expert_module_t* expert_evs;*/

    static hf_register_info hf[] = {
        { &hf_evs_packet_length,
        { "Packet length", "evs.packet_length",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_evs_voice_data,
        { "Voice data", "evs.voice_data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_evs_h_bit,
        { "Header Type identification bit (H)", "evs.h_bit",
        FT_BOOLEAN, 8, TFS(&tfs_evs_h_bit), 0x80,
        NULL, HFILL }
        },
        { &hf_evs_cmr_t,
        { "Type of Request(T)", "evs.cmr_t",
        FT_UINT8, BASE_DEC, NULL, 0x70,
        NULL, HFILL }
        },
        { &hf_evs_cmr_t0_d,
        { "D", "evs.cmr_t0_d",
        FT_UINT8, BASE_DEC, VALS(evs_d_bits_t0_values), 0x0f,
        NULL, HFILL }
        },
        { &hf_evs_cmr_t1_d,
        { "D", "evs.cmr_t1_d",
        FT_UINT8, BASE_DEC, VALS(evs_d_bits_t1_values), 0x0f,
        NULL, HFILL }
        },
        { &hf_evs_cmr_t2_d,
        { "D", "evs.cmr_t3_d",
        FT_UINT8, BASE_DEC, VALS(evs_d_bits_t2_values), 0x0f,
        NULL, HFILL }
        },
        { &hf_evs_cmr_t3_d,
        { "D", "evs.cmr_t3_d",
        FT_UINT8, BASE_DEC, VALS(evs_d_bits_t3_values), 0x0f,
        NULL, HFILL }
        },
        { &hf_evs_cmr_t4_d,
        { "D", "evs.cmr_t4_d",
        FT_UINT8, BASE_DEC, VALS(evs_d_bits_t4_values), 0x0f,
        NULL, HFILL }
        },
        { &hf_evs_cmr_t5_d,
        { "D", "evs.cmr_t5_d",
        FT_UINT8, BASE_DEC, VALS(evs_d_bits_t5_values), 0x0f,
        NULL, HFILL }
        },
        { &hf_evs_cmr_t6_d,
        { "D", "evs.cmr_t6_d",
        FT_UINT8, BASE_DEC, VALS(evs_d_bits_t6_values), 0x0f,
        NULL, HFILL }
        },
        { &hf_evs_cmr_t7_d,
        { "D", "evs.cmr_t7_d",
        FT_UINT8, BASE_DEC, VALS(evs_d_bits_t7_values), 0x0f,
        NULL, HFILL }
        },
        { &hf_evs_mode_bit,
        { "EVS Mode", "evs.mode_bit",
        FT_UINT8, BASE_DEC, NULL, 0x20,
        NULL, HFILL }
        },
        { &hf_evs_toc_spare,
        { "Unused", "evs.toc_spare",
        FT_UINT8, BASE_DEC, NULL, 0x10,
        NULL, HFILL }
        },
        { &hf_evs_amr_wb_q_bit,
        { "AMR WB Q bit", "evs.amr_wb_q_bit",
        FT_BOOLEAN, 8, TFS(&toc_evs_q_bit_vals), 0x10,
        NULL, HFILL }
        },

        { &hf_evs_bit_rate_mode_0,
        { "EVS mode and bit rate", "evs.bit_rate_mode_0",
        FT_UINT8, BASE_DEC, VALS(evs_bit_rate_mode_0_values), 0x0f,
        NULL, HFILL }
        },
        { &hf_evs_bit_rate_mode_1,
        { "EVS mode and bit rate", "evs.bit_rate_mode_1",
        FT_UINT8, BASE_DEC, VALS(evs_bit_rate_mode_1_values), 0x0f,
        NULL, HFILL }
        },
        { &hf_evs_f_bit,
        { "F", "evs.f_bit",
        FT_BOOLEAN, 8, TFS(&tfs_evs_f_bit), 0x40,
        NULL, HFILL }
        },
    { &hf_evs_cmr_amr_io,
    { "CMR", "evs.cmr_amr_io",
        FT_UINT8, BASE_DEC, VALS(evs_cmr_amr_io_values), 0xe0,
        NULL, HFILL }
    },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_evs,
        &ett_evs_header,
    };


    /* Register the protocol name and description */
    proto_evs = proto_register_protocol("Enhanced Voice Services", "EVS", "evs");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_evs, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    evs_module = prefs_register_protocol(proto_evs, proto_reg_handoff_evs);

    prefs_register_uint_preference(evs_module, "dynamic.payload.type",
        "EVS dynamic payload type",
        "The dynamic payload type which will be interpreted as EVS"
        "; The value must be greater than 95",
        10,
        &temp_dynamic_payload_type);

    evs_handle = register_dissector("evs", dissect_evs, proto_evs);

}

void
proto_reg_handoff_evs(void)
{
    static guint              dynamic_payload_type;
    static gboolean           evs_prefs_initialized = FALSE;

    if (!evs_prefs_initialized) {
        dissector_add_string("rtp_dyn_payload_type", "EVS", evs_handle);
        evs_prefs_initialized = TRUE;
    }
    else {
        if (dynamic_payload_type > 95)
            dissector_delete_uint("rtp.pt", dynamic_payload_type, evs_handle);
    }

    dynamic_payload_type = temp_dynamic_payload_type;

    if (dynamic_payload_type > 95) {
        dissector_add_uint("rtp.pt", dynamic_payload_type, evs_handle);
    }
}
