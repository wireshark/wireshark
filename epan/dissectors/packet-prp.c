/* packet-prp.c
 * Routines for PRP (Parallel Redundancy Protocol; IEC62439 Part 3) dissection
 * Copyright 2007, Sven Meier <msv[AT]zhwin.ch>
 * Copyright 2011, Martin Renold <reld[AT]zhaw.ch>
 * Copyright 2011, Florian Reichert <refl [AT] zhaw.ch>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald[AT]wireshark.org>
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

#include <glib.h>
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

void proto_reg_handoff_prp(void);
static int proto_prp = -1;
static module_t *prp_module;


/* Initialize trailer fields */
static int hf_prp_redundancy_control_trailer_sequence_nr = -1;
static int hf_prp_redundancy_control_trailer_lan = -1;
static int hf_prp_redundancy_control_trailer_size = -1;
static int hf_prp_redundancy_control_trailer_suffix = -1;
static int hf_prp_redundancy_control_trailer_version = -1;


/* Initialize the subtree pointers */
static gint ett_prp_redundancy_control_trailer = -1;


/*  Post dissectors (such as the trailer dissector for this protocol)
 *  get called for every single frame anyone loads into Wireshark.
 *  Since this protocol is not of general interest we disable this
 *  protocol by default.
 *
 *  This is done separately from the disabled protocols list mainly so
 *  we can disable it by default.  XXX Maybe there's a better way.
 */
static gboolean prp_enable_dissector = FALSE;


/* Code to actually dissect the packets */
static void
dissect_prp_redundancy_control_trailer(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *prp_tree;
    guint i;
    guint length;
    guint offset;
    guint16 lan_id;
    guint16 lsdu_size;
    guint16 prp1_suffix;
    guint trailer_start;
    guint trailer_length;

    if (!tree)
        return;

    trailer_start = 0;
    trailer_length = 0;
    length = tvb_reported_length(tvb);

    if(length < 14)
    {
        return;
    }

    if(ETHERTYPE_VLAN == tvb_get_ntohs(tvb, 12)) /* tagged frame */
    {
        offset = 18;
    }
    else /* untagged */
    {
        offset = 14;
    }

    /* search for PRP-0 trailer */
    /* If the frame is >  64 bytes, the PRP-0 trailer is always at the end. */
    /* If the frame is <= 64 bytes, the PRP-0 trailer may be anywhere (before the padding) */
    for(i=length-4; i>=offset; i--)
    {
        lan_id    = tvb_get_ntohs(tvb, (i+2)) >> 12;
        lsdu_size = tvb_get_ntohs(tvb, (i+2)) & 0x0fff;
        if(lsdu_size == i+4-offset && (lan_id == 0xa || lan_id == 0xb))
        {
            trailer_start = i;
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
            trailer_start = length-6;
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
        PROTO_ITEM_SET_GENERATED(ti);

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


    /* Register the protocol name and description */
    proto_prp = proto_register_protocol("Parallel Redundancy Protocol (IEC62439 Part 3)",
                        "PRP", "prp");
    prp_module = prefs_register_protocol(proto_prp, proto_reg_handoff_prp);

    prefs_register_bool_preference(prp_module, "enable", "Enable dissector",
                       "Enable this dissector (default is false)",
                       &prp_enable_dissector);

    /* Required function calls to register the header fields and subtree used */
    proto_register_field_array(proto_prp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

}

void proto_reg_handoff_prp(void)
{
    static gboolean prefs_initialized = FALSE;

    if (!prefs_initialized) {
        dissector_handle_t prp_redundancy_control_trailer_handle;

        prp_redundancy_control_trailer_handle = create_dissector_handle(dissect_prp_redundancy_control_trailer, proto_prp);
        register_postdissector(prp_redundancy_control_trailer_handle);

        prefs_initialized = TRUE;
    }

      proto_set_decoding(proto_prp, prp_enable_dissector);
}
