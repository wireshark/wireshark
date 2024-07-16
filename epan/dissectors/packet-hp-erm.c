/* packet-hp-erm.c
 * Routines for the disassembly of  HP ProCurve encapsulated remote mirroring frames
 * (Adapted from packet-cisco-erspan.c and packet-vlan.c)
 *
 * Copyright 2010 2012 William Meier <wmeier [AT] newsguy.com>,
 *                     Zdravko Velinov <z.velinov [AT] vkv5.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * For some information on HP Procurve encapsulated remote mirroring see
 *  "Traffic Mirroring" in Appendix B of the HP manual
 *   "Management and Configuration Guide for the ProCurve Series
 *    3500, 3500yl, 5400zl, 6200yl, 6600, and 8200zl Switches (September 2009)"
 *
 * Format:
 *  The above manual indicates that the encapsulatedmirrored frame is transmitted
 *  on the network as a [UDP] packet which has 54 bytes preceding the mirrored frame.
 *  Examining a sample capture shows that this means that the data payload
 *  of the UDP packet consists of a 12 byte "header" followed by the
 *  bytes of the mirrored frame.
 *
 *  After some additional tests, which involved injecting 802.1Q frames with
 *  different priorities and VLAN identifiers. It was determined that the HP
 *  ERM header has a part inside its header that closely resembles the 802.1Q
 *  header. The only difference is the priority numbering.
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_hp_erm(void);
void proto_reg_handoff_hp_erm(void);

static dissector_handle_t hp_erm_handle;

#define PROTO_SHORT_NAME "HP_ERM"
#define PROTO_LONG_NAME  "HP encapsulated remote mirroring"

static int  proto_hp_erm;
static int ett_hp_erm;
static int  hf_hp_erm_unknown1;
static int  hf_hp_erm_unknown2;
static int  hf_hp_erm_unknown3;
static int  hf_hp_erm_priority;
static int  hf_hp_erm_cfi;
static int  hf_hp_erm_vlan;
static int  hf_hp_erm_is_tagged;

static const value_string hp_erm_pri_vals[] = {
  { 0, "Background"                        },
  { 1, "Spare"                             },
  { 2, "Best Effort (default)"             },
  { 3, "Excellent Effort"                  },
  { 4, "Controlled Load"                   },
  { 5, "Video, < 100ms latency and jitter" },
  { 6, "Voice, < 10ms latency and jitter"  },
  { 7, "Network Control"                   },
  { 0, NULL                                }
};

static const true_false_string hp_erm_canonical = { "Non-canonical", "Canonical" };

static dissector_handle_t eth_withoutfcs_handle;

static int
dissect_hp_erm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_tree *hp_erm_tree;
    tvbuff_t   *eth_tvb;
    int        offset = 0;
    static int * const flags[] = {
        &hf_hp_erm_unknown2,
        &hf_hp_erm_priority,
        &hf_hp_erm_cfi,
        &hf_hp_erm_vlan,
        &hf_hp_erm_is_tagged,
        &hf_hp_erm_unknown3,
        NULL
    };

    col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_SHORT_NAME);
    col_set_str(pinfo->cinfo, COL_INFO, PROTO_SHORT_NAME ":");

    ti = proto_tree_add_item(tree, proto_hp_erm, tvb, 0, -1, ENC_NA);
    hp_erm_tree = proto_item_add_subtree(ti, ett_hp_erm);

    proto_tree_add_item(hp_erm_tree, hf_hp_erm_unknown1, tvb, offset, 8, ENC_NA);
    offset += 8;

    proto_tree_add_bitmask_list(hp_erm_tree, tvb, offset, 4, flags, ENC_BIG_ENDIAN);
    offset += 4;

    eth_tvb = tvb_new_subset_remaining(tvb, offset);
    call_dissector(eth_withoutfcs_handle, eth_tvb, pinfo, tree);
    return tvb_captured_length(tvb);
}

void
proto_register_hp_erm(void)
{
    static hf_register_info hf[] = {

        { &hf_hp_erm_unknown1,
          { "Unknown1", "hp_erm.unknown1", FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }},

        { &hf_hp_erm_unknown2,
          { "Unknown2", "hp_erm.unknown2", FT_UINT32, BASE_DEC, NULL,
            0xFF000000, NULL, HFILL }},

        { &hf_hp_erm_priority,
          { "Priority", "hp_erm.priority", FT_UINT32, BASE_DEC, VALS(hp_erm_pri_vals),
            0x00E00000, NULL, HFILL }},

        { &hf_hp_erm_cfi,
          { "CFI", "hp_erm.cfi", FT_BOOLEAN, 32, TFS(&hp_erm_canonical),
            0x00100000, NULL, HFILL }},

        { &hf_hp_erm_vlan,
          { "Vlan", "hp_erm.vlan", FT_UINT32, BASE_DEC, NULL,
            0x000FFF00, NULL, HFILL }},

        { &hf_hp_erm_is_tagged,
          { "Is_Tagged", "hp_erm.is_tagged", FT_BOOLEAN, 32, TFS(&tfs_yes_no),
            0x00000080, NULL, HFILL }},

        { &hf_hp_erm_unknown3,
          { "Unknown3", "hp_erm.unknown3", FT_UINT32, BASE_DEC, NULL,
            0x0000007F, NULL, HFILL }}
    };

    static int *ett[] = {
        &ett_hp_erm,
    };

    proto_hp_erm = proto_register_protocol(PROTO_LONG_NAME, PROTO_SHORT_NAME, "hp_erm");

    proto_register_field_array(proto_hp_erm, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    hp_erm_handle = register_dissector("hp_erm", dissect_hp_erm, proto_hp_erm);
}

void
proto_reg_handoff_hp_erm(void)
{
    eth_withoutfcs_handle = find_dissector_add_dependency("eth_withoutfcs", proto_hp_erm);
    dissector_add_for_decode_as_with_preference("udp.port", hp_erm_handle);
}
/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
