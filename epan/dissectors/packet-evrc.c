/* packet-evrc.c
 * Routines for EVRC/EVRC-B/EVRC-WB/EVRC-NW RTP RTP payload header dissection
 * (I.e. RFC 3558)
 * (I.e. RFC 3558 and as of draft-zfang-avt-rtp-evrc-nw-02)
 *
 * Copyright 2008, Michael Lum <michael.lum [AT] shaw.ca>
 * In association with Star Solutions
 *
 * Title                3GPP2                   Other
 *
 *   Enhanced Variable Rate Codec, Speech Service Options 3, 68, 70, and 73
 *   for Wideband Spread Spectrum Digital Systems
 *                      3GPP2 C.S0014-D v2.0      TIA-127-?
 *
 * RFC 3558  http://www.ietf.org/rfc/rfc3558.txt?number=3558
 * RFC 4788  http://www.ietf.org/rfc/rfc4788.txt?number=4788
 * RFC 5188  http://www.ietf.org/rfc/rfc5188.txt?number=5188
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/strutil.h>


/* PROTOTYPES/FORWARDS */

void proto_reg_handoff_evrc(void);

static const value_string evrc_frame_type_vals[] = {
    { 0,        "Blank (0 bits)" },
    { 1,        "1/8 Rate (16 bits)" },
    { 2,        "Not valid (1/4 Rate : 40 bits)" },
    { 3,        "1/2 Rate (80 bits)" },
    { 4,        "Full Rate (171 bits; + 5 bits padding)" },
    { 5,        "Erasure (0 bits)" },
    { 0,        NULL }
};

static const value_string evrc_b_frame_type_vals[] = {
    { 0,        "Blank (0 bits)" },
    { 1,        "1/8 Rate (16 bits)" },
    { 2,        "1/4 Rate (40 bits)" },
    { 3,        "1/2 Rate (80 bits)" },
    { 4,        "Full Rate (171 bits; + 5 bits padding)" },
    { 5,        "Erasure (0 bits)" },
    { 0,        NULL }
};

static const value_string evrc_legacy_frame_type_vals[] = {
    { 0,        "Blank (0 bits)" },
    { 1,        "1/8 Rate (16 bits)" },
    { 3,        "1/2 Rate (80 bits)" },
    { 4,        "Full Rate (171 bits; + 5 bits padding)" },
    { 14,       "Erasure (0 bits)" },
    { 0,        NULL }
};

static const value_string evrc_mode_request_vals[] = {
    { 0,        "Rate Reduction 0 (Full Rate)" },
    { 1,        "Rate Reduction 1" },
    { 2,        "Rate Reduction 2" },
    { 3,        "Rate Reduction 3" },
    { 4,        "Rate Reduction 4" },
    { 0,        NULL }
};

static const value_string evrc_b_mode_request_vals[] = {
    { 0,        "Encoder Operating Point 0 (Full Rate)" },
    { 1,        "Encoder Operating Point 1" },
    { 2,        "Encoder Operating Point 2" },
    { 3,        "Encoder Operating Point 3" },
    { 4,        "Encoder Operating Point 4" },
    { 5,        "Encoder Operating Point 5" },
    { 6,        "Encoder Operating Point 6" },
    { 7,        "Encoder Operating Point 7 (1/2 rate max)" },
    { 0,        NULL }
};

static const value_string evrc_wb_mode_request_vals[] = {
    { 0,        "Encoder Operating Point 0 (Full Rate)" },
    { 1,        "Reserved" },
    { 2,        "Reserved" },
    { 3,        "Reserved" },
    { 4,        "Encoder Operating Point 4" },
    { 5,        "Reserved" },
    { 6,        "Reserved" },
    { 7,        "Encoder Operating Point 7 (1/2 rate max)" },
    { 0,        NULL }
};

static const value_string evrc_nw_mode_request_vals[] = {
    { 0,        "Encoder Operating Point 0 (EVRC-WB COP0)" },
    { 1,        "Encoder Operating Point 1 (EVRC-B COP0/EVRC-WB COP4)" },
    { 2,        "Encoder Operating Point 2 (EVRC-B COP2)" },
    { 3,        "Encoder Operating Point 3 (EVRC-B COP3)" },
    { 4,        "Encoder Operating Point 4 (EVRC-B COP4)" },
    { 5,        "Encoder Operating Point 5 (EVRC-B COP5)" },
    { 6,        "Encoder Operating Point 6 (EVRC-B COP6)" },
    { 7,        "Encoder Operating Point 7 (EVRC-B COP7/EVRC-WB COP7)" },
    { 0,        NULL }
};

static const true_false_string toc_further_entries_bit_vals = {
  "More ToC entries follow",
  "End of ToC entries"
};

typedef enum
{
    EVRC_VARIANT_EVRC,
    EVRC_VARIANT_EVRC_B,
    EVRC_VARIANT_EVRC_WB,
    EVRC_VARIANT_EVRC_NW,
    EVRC_VARIANT_EVRC_LEGACY
}
evrc_variant_t;


/* Initialize the protocol and registered fields */
static int proto_evrc = -1;

static int hf_evrc_reserved = -1;
static int hf_evrc_interleave_length = -1;
static int hf_evrc_interleave_index = -1;
static int hf_evrc_mode_request = -1;
static int hf_evrc_b_mode_request = -1;
static int hf_evrc_wb_mode_request = -1;
static int hf_evrc_nw_mode_request = -1;
static int hf_evrc_frame_count = -1;
static int hf_evrc_toc_frame_type_high = -1;
static int hf_evrc_toc_frame_type_low = -1;
static int hf_evrc_b_toc_frame_type_high = -1;
static int hf_evrc_b_toc_frame_type_low = -1;
static int hf_evrc_padding = -1;
static int hf_evrc_legacy_toc_fe_ind = -1;
static int hf_evrc_legacy_toc_reduc_rate = -1;
static int hf_evrc_legacy_toc_frame_type = -1;

/* Initialize the subtree pointers */
static gint ett_evrc = -1;
static gint ett_toc = -1;

static packet_info *g_pinfo;
static proto_tree *g_tree;

/*
 * Variables to allow for proper deletion of dissector registration when
 * the user changes values
 */
static gboolean legacy_pt_60 = FALSE;


static guint8
evrc_frame_type_to_octs(guint8 frame_type)
{
    switch (frame_type)
    {
    default:
        break;

    case 1:     /* 1/8 rate */
        return(2);

    case 2:     /* 1/4 rate */
        return(5);

    case 3:     /* 1/2 rate */
        return(10);

    case 4:     /* full rate */
        return(22);
    }

    return(0);
}

/* GENERIC EVRC DISSECTOR FUNCTIONS */

static void
dissect_evrc_aux(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, evrc_variant_t evrc_variant)
{
    guint8                      oct;
    guint8                      frame_count;
    guint8                      i;
    guint32                     offset, saved_offset;
    gboolean                    further_entries;
    guint32                     len;
    proto_item                  *item = NULL;
    proto_tree                  *evrc_tree = NULL;
    proto_tree                  *toc_tree = NULL;
    int                         hf_mode_request;
    int                         hf_toc_frame_type_high;
    int                         hf_toc_frame_type_low;

    /*
     * assumed max number of speech frames based on
     * frame count being 5 bits + 1
     */
    guint8                      speech_data_len[0x20];


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "EVRC");

    if (!tree) return;

    offset = 0;
    g_pinfo = pinfo;
    g_tree = tree;
    memset(speech_data_len, 0, sizeof(speech_data_len));

    if (NULL == tree) return;

    len = tvb_reported_length(tvb);

    item = proto_tree_add_item(tree, proto_evrc, tvb, 0, -1, ENC_NA);

    evrc_tree = proto_item_add_subtree(item, ett_evrc);

    proto_tree_add_item(evrc_tree, hf_evrc_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(evrc_tree, hf_evrc_interleave_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(evrc_tree, hf_evrc_interleave_index, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    if (evrc_variant == EVRC_VARIANT_EVRC_LEGACY)
    {
        /* legacy 'payload type 60' draft-ietf-avt-evrc-07.txt header format */

        frame_count = 0;
        further_entries = TRUE;
        while (further_entries && (frame_count < sizeof(speech_data_len)) &&
            ((len - offset) > 0))
        {
            item =
                proto_tree_add_text(evrc_tree, tvb, offset, 1, "ToC [%u]", frame_count+1);

            toc_tree = proto_item_add_subtree(item, ett_toc);

            proto_tree_add_item(toc_tree, hf_evrc_legacy_toc_fe_ind, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(toc_tree, hf_evrc_legacy_toc_reduc_rate, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(toc_tree, hf_evrc_legacy_toc_frame_type, tvb, offset, 1, ENC_BIG_ENDIAN);

            oct = tvb_get_guint8(tvb, offset);
            further_entries = (oct & 0x80) ? TRUE : FALSE;

            speech_data_len[frame_count] = evrc_frame_type_to_octs((guint8)(oct & 0x7f));

            frame_count++;
            offset++;
        }
    }
    else
    {
        /* RFC 3558 header format */

        switch (evrc_variant)
        {
        case EVRC_VARIANT_EVRC:
            hf_mode_request = hf_evrc_mode_request;
            hf_toc_frame_type_high = hf_evrc_toc_frame_type_high;
            hf_toc_frame_type_low = hf_evrc_toc_frame_type_low;
            break;

        case EVRC_VARIANT_EVRC_B:
            hf_mode_request = hf_evrc_b_mode_request;
            hf_toc_frame_type_high = hf_evrc_b_toc_frame_type_high;
            hf_toc_frame_type_low = hf_evrc_b_toc_frame_type_low;
            break;

        case EVRC_VARIANT_EVRC_WB:
            hf_mode_request = hf_evrc_wb_mode_request;
            hf_toc_frame_type_high = hf_evrc_b_toc_frame_type_high;
            hf_toc_frame_type_low = hf_evrc_b_toc_frame_type_low;
            break;

        case EVRC_VARIANT_EVRC_NW:
            hf_mode_request = hf_evrc_nw_mode_request;
            hf_toc_frame_type_high = hf_evrc_b_toc_frame_type_high;
            hf_toc_frame_type_low = hf_evrc_b_toc_frame_type_low;
            break;

        default:
            return;
        }

        proto_tree_add_item(evrc_tree, hf_mode_request, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(evrc_tree, hf_evrc_frame_count, tvb, offset, 1, ENC_BIG_ENDIAN);

        /*
         * number of frames in PACKET is frame_count + 1
         */
        frame_count = (tvb_get_guint8(tvb, offset) & 0x1f) + 1;

        offset++;
        saved_offset = offset;

        item =
            proto_tree_add_text(evrc_tree, tvb, offset, -1, "ToC - %u frame%s",
                frame_count, plurality(frame_count, "", "s"));

        toc_tree = proto_item_add_subtree(item, ett_toc);

        i = 0;
        while ((i < frame_count) &&
            ((len - offset) > 0))
        {
            oct = tvb_get_guint8(tvb, offset);

            proto_tree_add_item(toc_tree, hf_toc_frame_type_high, tvb, offset, 1, ENC_BIG_ENDIAN);

            speech_data_len[i] = evrc_frame_type_to_octs((guint8)((oct & 0xf0) >> 4));

            i++;

	    if (i < frame_count)
            {
                /* even number of frames */
                proto_tree_add_item(toc_tree, hf_toc_frame_type_low, tvb, offset, 1, ENC_BIG_ENDIAN);

                speech_data_len[i] = evrc_frame_type_to_octs((guint8)(oct & 0x0f));

                i++;
            }

            offset++;
        }

        if (frame_count & 0x01)
        {
            /* odd number of frames */
            proto_tree_add_item(toc_tree, hf_evrc_padding, tvb, offset-1, 1, ENC_BIG_ENDIAN);
        }

        proto_item_set_len(item, offset - saved_offset);
    }

    i = 0;
    while ((i < frame_count) &&
        ((len - offset) >= speech_data_len[i]))
    {
        proto_tree_add_text(evrc_tree, tvb, offset, speech_data_len[i], "Speech Data [%u]", i+1);

        offset += speech_data_len[i];
        i++;
    }
}

static void
dissect_evrc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    dissect_evrc_aux(tvb, pinfo, tree, EVRC_VARIANT_EVRC);
}

static void
dissect_evrcb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    dissect_evrc_aux(tvb, pinfo, tree, EVRC_VARIANT_EVRC_B);
}

static void
dissect_evrcwb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    dissect_evrc_aux(tvb, pinfo, tree, EVRC_VARIANT_EVRC_WB);
}

static void
dissect_evrcnw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    dissect_evrc_aux(tvb, pinfo, tree, EVRC_VARIANT_EVRC_NW);
}

static void
dissect_evrc_legacy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    dissect_evrc_aux(tvb, pinfo, tree, EVRC_VARIANT_EVRC_LEGACY);
}


/* Register the protocol with Wireshark */
void
proto_register_evrc(void)
{
    module_t            *evrc_module;

    /* Setup list of header fields */

    static hf_register_info hf[] =
    {
        { &hf_evrc_reserved,
            { "Reserved",               "evrc.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xc0,
            "Reserved bits", HFILL }
        },
        { &hf_evrc_interleave_length,
            { "Interleave Length",      "evrc.interleave_len",
            FT_UINT8, BASE_DEC, NULL, 0x38,
            "Interleave length bits", HFILL }
        },
        { &hf_evrc_interleave_index,
            { "Interleave Index",       "evrc.interleave_idx",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            "Interleave index bits", HFILL }
        },
        { &hf_evrc_mode_request,
            { "Mode Request",           "evrc.mode_request",
            FT_UINT8, BASE_DEC, VALS(evrc_mode_request_vals), 0xe0,
            "Mode Request bits", HFILL }
        },
        { &hf_evrc_b_mode_request,
            { "Mode Request",           "evrc.b.mode_request",
            FT_UINT8, BASE_DEC, VALS(evrc_b_mode_request_vals), 0xe0,
            "Mode Request bits", HFILL }
        },
        { &hf_evrc_wb_mode_request,
            { "Mode Request",           "evrc.wb.mode_request",
            FT_UINT8, BASE_DEC, VALS(evrc_wb_mode_request_vals), 0xe0,
            "Mode Request bits", HFILL }
        },
        { &hf_evrc_nw_mode_request,
            { "Mode Request",           "evrc.nw.mode_request",
            FT_UINT8, BASE_DEC, VALS(evrc_nw_mode_request_vals), 0xe0,
            "Mode Request bits", HFILL }
        },
        { &hf_evrc_frame_count,
            { "Frame Count (0 means 1 frame)",  "evrc.frame_count",
            FT_UINT8, BASE_DEC, NULL, 0x1f,
            "Frame Count bits, a value of 0 means 1 frame", HFILL }
        },
        { &hf_evrc_toc_frame_type_high,
            { "ToC Frame Type",         "evrc.toc.frame_type_hi",
            FT_UINT8, BASE_DEC, VALS(evrc_frame_type_vals), 0xf0,
            "ToC Frame Type bits", HFILL }
        },
        { &hf_evrc_toc_frame_type_low,
            { "ToC Frame Type",         "evrc.toc.frame_type_lo",
            FT_UINT8, BASE_DEC, VALS(evrc_frame_type_vals), 0x0f,
            "ToC Frame Type bits", HFILL }
        },
        { &hf_evrc_b_toc_frame_type_high,
            { "ToC Frame Type",         "evrc.b.toc.frame_type_hi",
            FT_UINT8, BASE_DEC, VALS(evrc_b_frame_type_vals), 0xf0,
            "ToC Frame Type bits", HFILL }
        },
        { &hf_evrc_b_toc_frame_type_low,
            { "ToC Frame Type",         "evrc.b.toc.frame_type_lo",
            FT_UINT8, BASE_DEC, VALS(evrc_b_frame_type_vals), 0x0f,
            "ToC Frame Type bits", HFILL }
        },
        { &hf_evrc_padding,
            { "Padding",                "evrc.padding",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            "Padding bits", HFILL }
        },
        { &hf_evrc_legacy_toc_fe_ind,
            { "ToC Further Entries Indicator",  "evrc.legacy.toc.further_entries_ind",
            FT_BOOLEAN, 8, TFS(&toc_further_entries_bit_vals), 0x80,
            "ToC Further Entries Indicator bit", HFILL }
        },
        { &hf_evrc_legacy_toc_reduc_rate,
            { "ToC Reduced Rate",       "evrc.legacy.toc.reduced_rate",
            FT_UINT8, BASE_DEC, NULL, 0x40,
            "ToC Reduced Rate bits", HFILL }
        },
        { &hf_evrc_legacy_toc_frame_type,
            { "ToC Frame Type",         "evrc.legacy.toc.frame_type",
            FT_UINT8, BASE_DEC, VALS(evrc_legacy_frame_type_vals), 0x3f,
            "ToC Frame Type bits", HFILL }
        }
    };

    /* Setup protocol subtree array */

    static gint *ett[] =
    {
        &ett_evrc,
        &ett_toc
    };

    /* Register the protocol name and description */

    proto_evrc =
        proto_register_protocol("Enhanced Variable Rate Codec", "EVRC", "evrc");

    proto_register_field_array(proto_evrc, hf, array_length(hf));

    proto_register_subtree_array(ett, array_length(ett));

    /*
     * setup for preferences
     */
    evrc_module = prefs_register_protocol(proto_evrc, proto_reg_handoff_evrc);

    prefs_register_bool_preference(evrc_module,
        "legacy_pt_60",
        "Add dissector for static payload type 60 as legacy EVRC (non-RFC3558)",
        "Whether the EVRC dissector should process payload type 60 as legacy EVRC packets",
        &legacy_pt_60);
}


void
proto_reg_handoff_evrc(void)
{
    static gboolean             evrc_prefs_initialized = FALSE;
    static dissector_handle_t   evrc_legacy_handle;

    if (!evrc_prefs_initialized)
    {
        dissector_handle_t evrc_handle;
        dissector_handle_t evrcb_handle;
        dissector_handle_t evrcwb_handle;
        dissector_handle_t evrcnw_handle;

        evrc_handle        = create_dissector_handle(dissect_evrc, proto_evrc);
        evrcb_handle       = create_dissector_handle(dissect_evrcb, proto_evrc);
        evrcwb_handle      = create_dissector_handle(dissect_evrcwb, proto_evrc);
        evrcnw_handle      = create_dissector_handle(dissect_evrcnw, proto_evrc);
        evrc_legacy_handle = create_dissector_handle(dissect_evrc_legacy, proto_evrc);

        /* header-full mime types */
        dissector_add_string("rtp_dyn_payload_type",  "EVRC", evrc_handle);
        dissector_add_string("rtp_dyn_payload_type",  "EVRCB", evrcb_handle);
        dissector_add_string("rtp_dyn_payload_type",  "EVRCWB", evrcwb_handle);
        dissector_add_string("rtp_dyn_payload_type",  "EVRCNW", evrcnw_handle);

        evrc_prefs_initialized = TRUE;
    }
    else
    {
        dissector_delete_uint("rtp.pt", 60, evrc_legacy_handle);
    }

    if (legacy_pt_60)
    {
        dissector_add_uint("rtp.pt", 60, evrc_legacy_handle);
    }
}
