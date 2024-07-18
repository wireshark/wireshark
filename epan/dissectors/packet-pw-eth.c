/* packet-pw-eth.c
 * Routines for ethernet PW dissection: it should conform to RFC 4448.
 *
 * Copyright 2008 _FF_
 *
 * Francesco Fondelli <francesco dot fondelli, gmail dot com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/etypes.h>
#include <epan/dissectors/packet-llc.h>

#include "packet-mpls.h"

void proto_register_pw_eth(void);
void proto_reg_handoff_pw_eth(void);

static int proto_pw_eth_cw;
static int proto_pw_eth_nocw;
static int proto_pw_eth_heuristic;

static int ett_pw_eth;

static int hf_pw_eth;
static int hf_pw_eth_cw;
static int hf_pw_eth_cw_sequence_number;

static dissector_handle_t eth_withoutfcs_handle;
static dissector_handle_t pw_eth_handle_cw;
static dissector_handle_t pw_eth_handle_nocw;
static dissector_handle_t pw_eth_handle_heuristic;

static int
dissect_pw_eth_cw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    tvbuff_t *next_tvb;
    uint16_t  sequence_number;

    if (tvb_reported_length_remaining(tvb, 0) < 4) {
        return 0;
    }

    if (dissect_try_cw_first_nibble(tvb, pinfo, tree))
        return tvb_captured_length(tvb);

    sequence_number = tvb_get_ntohs(tvb, 2);

    if (tree) {
        proto_tree *pw_eth_tree;
        proto_item *ti;

        ti = proto_tree_add_boolean(tree, hf_pw_eth_cw,
                                    tvb, 0, 0, true);
        proto_item_set_hidden(ti);
        ti = proto_tree_add_item(tree, proto_pw_eth_cw,
                                 tvb, 0, 4, ENC_NA);
        pw_eth_tree = proto_item_add_subtree(ti, ett_pw_eth);

        proto_tree_add_uint_format(pw_eth_tree,
                                   hf_pw_eth_cw_sequence_number,
                                   tvb, 2, 2, sequence_number,
                                   "Sequence Number: %d",
                                   sequence_number);
    }

    next_tvb = tvb_new_subset_remaining(tvb, 4);
    {
        call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}

static int
dissect_pw_eth_nocw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    tvbuff_t *next_tvb;

    if (tree) {
        proto_item *ti;
        ti = proto_tree_add_boolean(tree, hf_pw_eth, tvb, 0, 0, true);
        proto_item_set_hidden(ti);
    }

    next_tvb = tvb_new_subset_remaining(tvb, 0);
    call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}

/*
 * FF: this function returns true if the first 12 bytes in tvb looks like
 *     two valid ethernet addresses.  false otherwise.
 */
static int
looks_like_plain_eth(tvbuff_t *tvb, int offset)
{
    const char *manuf_name_da;
    const char *manuf_name_sa;
    uint16_t etype;
    int ret = 2;

    /* Don't throw an exception. If the packet is truncated, you lose. */
    if (tvb_captured_length_remaining(tvb, offset) < 14) {
        return 0;
    }

    /* Copy the source and destination addresses, as tvb_get_manuf_name_if_known
     * only uses the first three bytes (it's for an OUI in, e.g., IEEE 802.11),
     * and returns NULL for MA-M and MA-S.
     */
    uint8_t da[6], sa[6];
    tvb_memcpy(tvb, da, offset, 6);
    /* da[0] & 0x2 is the U/L bit; if it's set, none of this helps. (#13039) */
    if (da[0] & 0x2) {
        // U/L bit; locally assigned addresses are a less solid heuristic
        ret = 1;
    } else {
        manuf_name_da = get_manuf_name_if_known(da, 6);
        if (!manuf_name_da) {
            /* Try looking for an exact match in the ethers file. */
            manuf_name_da = get_ether_name_if_known(da);
            if (!manuf_name_da) {
                return 0;
            }
        }
    }
    offset += 6;

    tvb_memcpy(tvb, sa, offset, 6);
    if (sa[0] & 0x1) {
        // Group bit should not be set on source
        return 0;
    }
    if (sa[0] & 0x2) {
        // U/L bit; locally assigned addresses are a less solid heuristic
        ret = 1;
    } else {
        manuf_name_sa = get_manuf_name_if_known(sa, 6);
        if (!manuf_name_sa) {
            manuf_name_sa = get_ether_name_if_known(sa);
            if (!manuf_name_sa) {
                return 0;
            }
        }
    }
    offset += 6;
    etype = tvb_get_ntohs(tvb, offset);

    if (etype > IEEE_802_3_MAX_LEN) {
        if (etype < ETHERNET_II_MIN_LEN) {
            return 0;
        }

        if (!try_val_to_str(etype, etype_vals)) {
            return 0;
        }
    } else {
        offset += 2;
        /* XXX - There are unusual cases like Cisco ISL, Novell raw 802.3
         * for IPX/SPX, etc. See packet-eth capture_eth()
         */
        if (tvb_reported_length_remaining(tvb, offset) < etype) {
            return 0;
        }

        if (tvb_captured_length_remaining(tvb, offset) < 3) {
            return 0;
        }
        uint8_t sap;
        sap = tvb_get_uint8(tvb, offset);
        if (!try_val_to_str(sap, sap_vals)) {
            return 0;
        }
        offset += 1;
        sap = tvb_get_uint8(tvb, offset);
        if (!try_val_to_str(sap, sap_vals)) {
            return 0;
        }
        /* We could go deeper, and see if this looks like SNAP if the dsap
         * and ssap are both 0xAA (the common case).
         */
    }

    return ret;
}

static int
dissect_pw_eth_heuristic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    /*
     * RFC 8469 states that that both ingress and egress SHOULD support the PW
     * CW, and if they do, the CW MUST be used. So it looks equally likely to
     * have the CW as not, assume CW.
     */
    uint8_t first_nibble = (tvb_get_uint8(tvb, 0) >> 4) & 0x0F;

    if (first_nibble == 0) {
        if (looks_like_plain_eth(tvb, 4) >= looks_like_plain_eth(tvb, 0)) {
            call_dissector(pw_eth_handle_cw, tvb, pinfo, tree);
        } else {
            call_dissector(pw_eth_handle_nocw, tvb, pinfo, tree);
        }
    } else {
        call_dissector(pw_eth_handle_nocw, tvb, pinfo, tree);
    }
    return tvb_captured_length(tvb);
}

static bool
dissect_pw_eth_nocw_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (!looks_like_plain_eth(tvb, 0)) {
        return false;
    }
    dissect_pw_eth_nocw(tvb, pinfo, tree, data);
    return true;
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

    static int *ett[] = {
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
    pw_eth_handle_cw = register_dissector("pw_eth_cw", dissect_pw_eth_cw, proto_pw_eth_cw);
    pw_eth_handle_nocw = register_dissector("pw_eth_nocw", dissect_pw_eth_nocw, proto_pw_eth_nocw);
    pw_eth_handle_heuristic = register_dissector("pw_eth_heuristic", dissect_pw_eth_heuristic,
                       proto_pw_eth_heuristic);
}

void
proto_reg_handoff_pw_eth(void)
{
    heur_dissector_add("mpls", dissect_pw_eth_nocw_heur,
        "Ethernet PW (no CW)", "pwethnocw", proto_pw_eth_nocw,
        HEURISTIC_ENABLE);
    eth_withoutfcs_handle = find_dissector_add_dependency("eth_withoutfcs", proto_pw_eth_cw);

    dissector_add_for_decode_as("mpls.label", pw_eth_handle_cw);
    dissector_add_for_decode_as("mpls.label", pw_eth_handle_nocw);

    dissector_add_for_decode_as("mpls.label", pw_eth_handle_heuristic);

    dissector_add_for_decode_as("mpls.pfn", pw_eth_handle_cw);
    dissector_add_for_decode_as("mpls.pfn", pw_eth_handle_nocw);
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
