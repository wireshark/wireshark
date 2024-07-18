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

static int proto_prp;


/* Initialize trailer fields */
static int hf_prp_redundancy_control_trailer_sequence_nr;
static int hf_prp_redundancy_control_trailer_lan;
static int hf_prp_redundancy_control_trailer_size;
static int hf_prp_redundancy_control_trailer_suffix;
static int hf_prp_redundancy_control_trailer_version;


/* Initialize the subtree pointers */
static int ett_prp_redundancy_control_trailer;


/* Code to actually dissect the packets */
static int
dissect_prp_redundancy_control_trailer(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data)
{
    proto_item *ti;
    proto_tree *prp_tree;
    int         i;
    int         length;
    uint16_t    lan_id;
    uint16_t    lsdu_size;
    uint16_t    prp1_suffix;
    unsigned    trailer_start;
    unsigned    trailer_length;

    trailer_start = 0;
    trailer_length = 0;
    length = tvb_reported_length(tvb);

    /*
     * Is there enough data in the packet to every try to search for a
     * trailer?
     */
    if (!tvb_bytes_exist(tvb, (length-4)+2, 2))
        return 0;  /* no */

    if (data == NULL) {
        return 0;
    }

    int lsdu_size_correct = *(int*)data;

    /* search for PRP-0 trailer */
    /* If the frame is >  64 bytes, the PRP-0 trailer is always at the end. */
    /* If the frame is <= 64 bytes, the PRP-0 trailer may be anywhere (before the padding) */
    for(i = 0; i <= length - 4; i++)
    {
        lan_id    = tvb_get_ntohs(tvb, length - 2 - i) >> 12;
        lsdu_size = tvb_get_ntohs(tvb, length - 2 - i) & 0x0fff;
        if(lsdu_size == (lsdu_size_correct - i) && (lan_id == 0xa || lan_id == 0xb))
        {
            trailer_start  = length - 4 - i;
            trailer_length = 4;
            break;
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
    return trailer_length;
}

static bool dissect_prp_redundancy_control_trailer_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
	return dissect_prp_redundancy_control_trailer(tvb, pinfo, parent_tree, data) > 0;
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

    static int *ett[] = {
        &ett_prp_redundancy_control_trailer,
    };

    module_t *prp_module;

    /* Register the protocol name and description */
    proto_prp = proto_register_protocol("Parallel Redundancy Protocol (IEC62439 Part 3)", "PRP", "prp");

    prp_module = prefs_register_protocol_obsolete(proto_prp);

    prefs_register_obsolete_preference(prp_module, "enable");

    /* Required function calls to register the header fields and subtree used */
    proto_register_field_array(proto_prp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    heur_dissector_add("eth.trailer", dissect_prp_redundancy_control_trailer_heur,
        "PRP Trailer", "prp_eth", proto_prp, HEURISTIC_ENABLE);
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
