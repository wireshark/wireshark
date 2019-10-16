/* packet-prp.c
 * Routines for PRP (Parallel Redundancy Protocol; IEC62439 Part 3) dissection
 * Copyright 2007, Sven Meier <msv[AT]zhwin.ch>
 * Copyright 2011, Martin Renold <reld[AT]zhaw.ch>
 * Copyright 2011, Florian Reichert <refl [AT] zhaw.ch>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald[AT]wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/prefs.h>

#define    PRP_LAN_A                               10
#define    PRP_LAN_B                               11

static const value_string prp_lan_vals[] = {
    {PRP_LAN_A, "LAN A"},
    {PRP_LAN_B, "LAN B"},
    {0, NULL}
};

/**********************************************************/
/* Initialize the protocol and registered fields      */
/**********************************************************/

void proto_register_prp(void);

static int proto_prp = -1;


/* Initialize trailer fields */
static int hf_prp_redundancy_control_trailer_sequence_nr = -1;
static int hf_prp_redundancy_control_trailer_lan = -1;
static int hf_prp_redundancy_control_trailer_size = -1;
static int hf_prp_redundancy_control_trailer_suffix = -1;
static int hf_prp_redundancy_control_trailer_version = -1;


/* Initialize the subtree pointers */
static gint ett_prp_redundancy_control_trailer = -1;


/* Code to actually dissect the packets */
static int
dissect_prp_redundancy_control_trailer(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_tree *prp_tree;
    guint       i;
    guint       length;
    guint       offset;
    guint16     lan_id;
    guint16     lsdu_size;
    guint16     prp1_suffix;
    guint       trailer_start;
    guint       trailer_length;

    trailer_start = 0;
    trailer_length = 0;
    length = tvb_reported_length(tvb);

    if(length < 14)
        return 0;

    /*
     * This is horribly broken.  It assumes the frame is an Ethernet
     * frame, with a type field at an offset of 12 bytes from the header.
     * That is not guaranteed to be true.
     *
     * Ideally, this should be a heuristic dissector registered in
     * the "eth.trailer" heuristic dissector table (and it can
     * be registered as "disabled by default" there); unfortunately,
     * it needs to know the length of the entire frame for the
     * PRP-0 heuristic, so it'd have to be passed that length
     * out of band.
     */
    if (!tvb_bytes_exist(tvb, 12, 2))
        return 0;
    if(ETHERTYPE_VLAN == tvb_get_ntohs(tvb, 12)) /* tagged frame */
    {
        offset = 18;
    }
    else /* untagged */
    {
        offset = 14;
    }

    if (!tree)
        return tvb_captured_length(tvb);

    /*
     * Is there enough data in the packet to every try to search for a
     * trailer?
     */
    if (!tvb_bytes_exist(tvb, (length-4)+2, 2))
        return 0;  /* no */

    /* search for PRP-0 trailer */
    /* If the frame is >  64 bytes, the PRP-0 trailer is always at the end. */
    /* If the frame is <= 64 bytes, the PRP-0 trailer may be anywhere (before the padding) */
    for(i=length-4; i>=offset; i--)
    {
        lan_id    = tvb_get_ntohs(tvb, (i+2)) >> 12;
        lsdu_size = tvb_get_ntohs(tvb, (i+2)) & 0x0fff;
        if(lsdu_size == i+4-offset && (lan_id == 0xa || lan_id == 0xb))
        {
            trailer_start  = i;
            trailer_length = 4;
            break;
        }

        if (length > 64) {
            break; /* don't search, just check the last position */
        }
    }

    /* check for PRP-1 trailer */
    /* PRP-1 trailer is always at the end of the frame, after any padding. */
    {
        lan_id      = tvb_get_ntohs(tvb, length-4) >> 12;
        lsdu_size   = tvb_get_ntohs(tvb, length-4) & 0x0fff;
        prp1_suffix = tvb_get_ntohs(tvb, length-2);

        if(prp1_suffix == ETHERTYPE_PRP && (lan_id == 0xa || lan_id == 0xb))
        {
            /* We don't check the lsdu_size, we just display whether
               it's correct. Helpful for testing, because different
               definitions of the lsdu_size did exist. */
            trailer_start  = length-6;
            trailer_length = 6;
        }
    }

    if(trailer_length != 0)
    {
        /* create display subtree for the protocol */
        ti = proto_tree_add_item(tree, proto_prp, tvb, trailer_start,
                                 trailer_length, ENC_NA);

        prp_tree = proto_item_add_subtree(ti, ett_prp_redundancy_control_trailer);

        if (trailer_length == 4) {
            ti = proto_tree_add_string(prp_tree, hf_prp_redundancy_control_trailer_version,
                                       tvb, trailer_start, trailer_length, "PRP-0");
        } else {
            ti = proto_tree_add_string(prp_tree, hf_prp_redundancy_control_trailer_version,
                                       tvb, trailer_start, trailer_length, "PRP-1");
        }
        proto_item_set_generated(ti);

        proto_tree_add_item(prp_tree, hf_prp_redundancy_control_trailer_sequence_nr,
                            tvb, trailer_start, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(prp_tree, hf_prp_redundancy_control_trailer_lan,
                            tvb, trailer_start+2, 2, ENC_BIG_ENDIAN);

        if (trailer_length == 4) {
            /* PRP-0 */
            proto_tree_add_item(prp_tree, hf_prp_redundancy_control_trailer_size,
                                tvb, trailer_start+2, 2, ENC_BIG_ENDIAN);
        } else {
            /* PRP-1 */
            int lsdu_size_correct = length-offset;
            if (lsdu_size == lsdu_size_correct) {
                proto_tree_add_uint_format(prp_tree, hf_prp_redundancy_control_trailer_size,
                                           tvb, trailer_start+2, 2, lsdu_size,
                                           "LSDU size: %d [correct]", lsdu_size);
            } else {
                proto_tree_add_uint_format(prp_tree, hf_prp_redundancy_control_trailer_size,
                                           tvb, trailer_start+2, 2, lsdu_size,
                                           "LSDU size: %d [WRONG, should be %d]", lsdu_size, lsdu_size_correct);
            }
            /* suffix */
            proto_tree_add_item(prp_tree, hf_prp_redundancy_control_trailer_suffix,
                                tvb, trailer_start+4, 2, ENC_BIG_ENDIAN);
        }
    }
    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */
void proto_register_prp(void)
{
    static hf_register_info hf[] = {
        /*trailer*/
        { &hf_prp_redundancy_control_trailer_sequence_nr,
            { "Sequence number", "prp.trailer.prp_sequence_nr",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },

        { &hf_prp_redundancy_control_trailer_lan,
            { "LAN", "prp.trailer.prp_lan",
            FT_UINT16, BASE_DEC, VALS(prp_lan_vals), 0xf000,
            NULL, HFILL }
        },

        { &hf_prp_redundancy_control_trailer_size,
            { "Size", "prp.trailer.prp_size",
            FT_UINT16, BASE_DEC, NULL, 0x0fff,
            NULL, HFILL }
        },

        { &hf_prp_redundancy_control_trailer_suffix,
            { "Suffix", "prp.trailer.prp1_suffix",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },

        { &hf_prp_redundancy_control_trailer_version,
            { "PRP Version", "prp.trailer.version",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_prp_redundancy_control_trailer,
    };

    module_t *prp_module;
    dissector_handle_t prp_handle;

    /* Register the protocol name and description */
    proto_prp = proto_register_protocol("Parallel Redundancy Protocol (IEC62439 Part 3)", "PRP", "prp");

    /*  Post dissectors (such as the trailer dissector for this protocol)
     *  get called for every single frame anyone loads into Wireshark.
     *  Since this protocol is not of general interest we disable this
     *  protocol by default.
     */
    proto_disable_by_default(proto_prp);

    prp_module = prefs_register_protocol(proto_prp, NULL);

    prefs_register_obsolete_preference(prp_module, "enable");

    /* Required function calls to register the header fields and subtree used */
    proto_register_field_array(proto_prp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    prp_handle = register_dissector("prp", dissect_prp_redundancy_control_trailer, proto_prp);

    register_postdissector(prp_handle);
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
