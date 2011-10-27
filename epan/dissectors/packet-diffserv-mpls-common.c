/* packet-diffserv-mpls-common.c
 * Routines for the common part of Diffserv MPLS signaling protocols
 * Author: Endoh Akira (endoh@netmarks.co.jp)
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

/*
 * This module defines routines only for the common part of LDP
 * and RSVP to support for Diffserv MPLS as described in RFC 3270
 * and RFC 3140. Protocol specific routines of each signaling
 * protocol are defined in each dissector.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include "packet-diffserv-mpls-common.h"

#define hf_map         *hfindexes[0]
#define hf_exp         *hfindexes[1]
#define hf_phbid       *hfindexes[2]
#define hf_phbid_dscp  *hfindexes[3]
#define hf_phbid_code  *hfindexes[4]
#define hf_phbid_bit14 *hfindexes[5]
#define hf_phbid_bit15 *hfindexes[6]
#define ett_map        *etts[0]
#define ett_map_phbid  *etts[1]

const value_string phbid_bit14_vals[] = {
    {0, "Single PHB"},
    {1, "Set of PHBs"},
    {0, NULL}
};

const value_string phbid_bit15_vals[] = {
    {0, "PHBs defined by standards action"},
    {1, "PHBs not defined by standards action"},
    {0, NULL}
};

void
dissect_diffserv_mpls_common(tvbuff_t *tvb, proto_tree *tree, int type,
                             int offset, int **hfindexes, gint **etts)
{
    proto_item  *ti = NULL, *sub_ti;
    proto_tree  *tree2 = NULL, *phbid_subtree;
    int exp;
    guint16 phbid;

    switch (type) {
    case 1:  /* E-LSP */
        ti = proto_tree_add_item(tree, hf_map, tvb, offset, 4, ENC_NA);
        tree2 = proto_item_add_subtree(ti, ett_map);
        proto_item_set_text(ti, "MAP: ");
        offset ++;
        exp = tvb_get_guint8(tvb, offset) & 7;
        proto_tree_add_uint(tree2, hf_exp, tvb, offset, 1, exp);
        proto_item_append_text(ti, "EXP %u, ", exp);
        offset ++;
        break;
    case 2:  /* L-LSP */
        tree2 = tree;
        break;
    default:
        return;
    }

    /* PHBID subtree */
    sub_ti = proto_tree_add_item(tree2, hf_phbid, tvb, offset, 2, ENC_NA);
    phbid_subtree = proto_item_add_subtree(sub_ti, ett_map_phbid);
    proto_item_set_text(sub_ti, "%s: ", (type == 1) ? PHBID_DESCRIPTION : "PSC");
    phbid = tvb_get_ntohs(tvb, offset);

    if ((phbid & 1) == 0) {
        /* Case 1 of RFC 3140 */
        proto_tree_add_uint(phbid_subtree, hf_phbid_dscp,
                            tvb, offset, 2, phbid);
        if (type == 1)
            proto_item_append_text(ti, "DSCP %u", phbid >> 10);
        proto_item_append_text(sub_ti, "DSCP %u", phbid >> 10);
    }
    else {
        /* Case 2 of RFC 3140 */
        proto_tree_add_uint(phbid_subtree, hf_phbid_code,
                            tvb, offset, 2, phbid);
        if (type == 1)
            proto_item_append_text(ti, "PHB id code %u", phbid >> 4);
        proto_item_append_text(sub_ti, "PHB id code %u", phbid >> 4);
    }
    proto_tree_add_uint(phbid_subtree, hf_phbid_bit14, tvb, offset, 2, phbid);
    proto_tree_add_uint(phbid_subtree, hf_phbid_bit15, tvb, offset, 2, phbid);
}
