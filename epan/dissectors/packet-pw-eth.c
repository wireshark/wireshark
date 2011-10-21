/* packet-pw-eth.c
 * Routines for ethernet PW dissection: it should be conform to RFC 4448.
 *
 * Copyright 2008 _FF_
 *
 * Francesco Fondelli <francesco dot fondelli, gmail dot com>
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

#include <stdlib.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>

#include "packet-mpls.h"

static gint proto_pw_eth_cw = -1;
static gint proto_pw_eth_nocw = -1;
static gint proto_pw_eth_heuristic = -1;

static gint ett_pw_eth = -1;

static int hf_pw_eth = -1;
static int hf_pw_eth_cw = -1;
static int hf_pw_eth_cw_sequence_number = -1;

static dissector_handle_t eth_withoutfcs_handle;
static dissector_handle_t pw_eth_handle_cw;
static dissector_handle_t pw_eth_handle_nocw;

static void
dissect_pw_eth_cw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        proto_tree *pw_eth_tree = NULL;
        proto_item *ti = NULL;
        tvbuff_t *next_tvb = NULL;
        guint16 sequence_number = 0;

        if (tvb_reported_length_remaining(tvb, 0) < 4) {
                if (tree)
                        proto_tree_add_text(tree, tvb, 0, -1,
                                            "Error processing Message");
                return;
        }

        if (dissect_try_cw_first_nibble(tvb, pinfo, tree))
                return;

        sequence_number = tvb_get_ntohs(tvb, 2);
        if (tree) {
                ti = proto_tree_add_boolean(tree, hf_pw_eth_cw,
                                            tvb, 0, 0, TRUE);
                PROTO_ITEM_SET_HIDDEN(ti);
                ti = proto_tree_add_item(tree, proto_pw_eth_cw,
                                         tvb, 0, 4, ENC_NA);
                pw_eth_tree = proto_item_add_subtree(ti, ett_pw_eth);
                if (pw_eth_tree == NULL)
                        return;
                proto_tree_add_uint_format(pw_eth_tree,
                                           hf_pw_eth_cw_sequence_number,
                                           tvb, 2, 2, sequence_number,
                                           "Sequence Number: %d",
                                           sequence_number);
        }
        next_tvb = tvb_new_subset_remaining(tvb, 4);
        {
                /*
                 * When Ethernet frames being decoded, pinfo->ethertype is extracted
                 * from the top-level Ethernet frame. Dissection of Ethernet PW payload
                 * overwrites this value as the same dissector is invoked again.
                 * This may lead to undesired behavior (like disappearance of "Link"
                 * tab from the "Decode as" menu).
                 *
                 * Let's save/restore ethertype. --ATA
                 *
                 * XXX it looks that more pinfo members (or even the whole pinfo)
                 * XXX should be saved/restored in PW cases. Multilayer encapsulations,
                 * XXX like ethernet/mpls/ethernet-pw/ip/vlan, may lead to undesired
                 * XXX changes if pinfo->ipproto, ptype etc.
                 */
                guint32 etype_save = pinfo->ethertype;
                call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, tree);
                pinfo->ethertype = etype_save;
        }
}

static void
dissect_pw_eth_nocw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        tvbuff_t *next_tvb = NULL;
        proto_item *ti = NULL;

        if (tree) {
                ti = proto_tree_add_boolean(tree, hf_pw_eth, tvb, 0, 0, TRUE);
                PROTO_ITEM_SET_HIDDEN(ti);
        }
        next_tvb = tvb_new_subset_remaining(tvb, 0);
        {
                guint32 etype_save = pinfo->ethertype;
                call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, tree);
                pinfo->ethertype = etype_save;
        }
}

/*
 * FF: this function returns TRUE if the first 12 bytes in tvb looks like
 *     two valid ethernet addresses.  FALSE otherwise.
 */
static gboolean
looks_like_plain_eth(tvbuff_t *tvb _U_)
{
        const gchar *manuf_name_da = NULL;
        const gchar *manuf_name_sa = NULL;

        if (tvb_reported_length_remaining(tvb, 0) < 14) {
                return FALSE;
        }

        manuf_name_da = tvb_get_manuf_name_if_known(tvb, 0);
        manuf_name_sa = tvb_get_manuf_name_if_known(tvb, 6);

        if (manuf_name_da && manuf_name_sa) {
                return TRUE;
        }

        return FALSE;
}

static void
dissect_pw_eth_heuristic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        if (looks_like_plain_eth(tvb)) {
                call_dissector(pw_eth_handle_nocw, tvb, pinfo, tree);
        } else {
                call_dissector(pw_eth_handle_cw, tvb, pinfo, tree);
        }
}

void
proto_register_pw_eth(void)
{
        static hf_register_info hf[] = {
                {
                        &hf_pw_eth,
                        {
                                "PW (ethernet)",
                                "pweth", FT_BOOLEAN,
                                BASE_NONE, NULL, 0x0, NULL, HFILL
                        }
                },
                {
                        &hf_pw_eth_cw,
                        {
                                "PW Control Word (ethernet)",
                                "pweth.cw", FT_BOOLEAN,
                                BASE_NONE, NULL, 0x0, NULL, HFILL
                        }
                },
                {
                        &hf_pw_eth_cw_sequence_number,
                        {
                                "PW sequence number (ethernet)",
                                "pweth.cw.sequence_number", FT_UINT16,
                                BASE_DEC, NULL, 0x0, NULL, HFILL
                        }
                }
        };

        static gint *ett[] = {
                &ett_pw_eth
        };

        proto_pw_eth_cw =
          proto_register_protocol("PW Ethernet Control Word",
                                  "Ethernet PW (with CW)",
                                  "pwethcw");
        proto_pw_eth_nocw =
          proto_register_protocol("Ethernet PW (no CW)", /* not displayed */
                                  "Ethernet PW (no CW)",
                                  "pwethnocw");
        proto_pw_eth_heuristic =
          proto_register_protocol("Ethernet PW (CW heuristic)", /* not disp. */
                                  "Ethernet PW (CW heuristic)",
                                  "pwethheuristic");
        proto_register_field_array(proto_pw_eth_cw, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
        register_dissector("pw_eth_cw", dissect_pw_eth_cw, proto_pw_eth_cw);
        register_dissector("pw_eth_nocw", dissect_pw_eth_nocw,
                           proto_pw_eth_nocw);
        register_dissector("pw_eth_heuristic", dissect_pw_eth_heuristic,
                           proto_pw_eth_heuristic);
}

void
proto_reg_handoff_pw_eth(void)
{
        dissector_handle_t pw_eth_handle_heuristic;

        eth_withoutfcs_handle = find_dissector("eth_withoutfcs");

        pw_eth_handle_cw = find_dissector("pw_eth_cw");
        dissector_add_uint("mpls.label", LABEL_INVALID, pw_eth_handle_cw);

        pw_eth_handle_nocw = find_dissector("pw_eth_nocw");
        dissector_add_uint("mpls.label", LABEL_INVALID, pw_eth_handle_nocw);

        pw_eth_handle_heuristic = find_dissector("pw_eth_heuristic");
        dissector_add_uint("mpls.label", LABEL_INVALID, pw_eth_handle_heuristic);
}
