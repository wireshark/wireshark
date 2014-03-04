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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>

void proto_register_hp_erm(void);
void proto_reg_handoff_hp_erm(void);

#define PROTO_SHORT_NAME "HP_ERM"
#define PROTO_LONG_NAME  "HP encapsulated remote mirroring"

static guint global_hp_erm_udp_port = 0;

static int  proto_hp_erm       = -1;
static gint ett_hp_erm         = -1;
static int  hf_hp_erm_unknown1 = -1;
static int  hf_hp_erm_unknown2 = -1;
static int  hf_hp_erm_unknown3 = -1;
static int  hf_hp_erm_priority = -1;
static int  hf_hp_erm_cfi      = -1;
static int  hf_hp_erm_vlan     = -1;

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

static const value_string hp_erm_cfi_vals[] = {
  { 0, "Canonical"     },
  { 1, "Non-canonical" },
  { 0, NULL            }
};

static dissector_handle_t eth_withoutfcs_handle;

static void
dissect_hp_erm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *hp_erm_tree = NULL;
    tvbuff_t   *eth_tvb;
    int        offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_SHORT_NAME);
    col_set_str(pinfo->cinfo, COL_INFO, PROTO_SHORT_NAME ":");

    if (tree) {
        ti = proto_tree_add_item(tree, proto_hp_erm, tvb, 0, -1, ENC_NA);
        hp_erm_tree = proto_item_add_subtree(ti, ett_hp_erm);
    }

    proto_tree_add_item(hp_erm_tree, hf_hp_erm_unknown1, tvb, offset, 8, ENC_NA);
    offset += 8;

    proto_tree_add_item(hp_erm_tree, hf_hp_erm_unknown2, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(hp_erm_tree, hf_hp_erm_priority, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(hp_erm_tree, hf_hp_erm_cfi, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(hp_erm_tree, hf_hp_erm_vlan, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(hp_erm_tree, hf_hp_erm_unknown3, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;


    eth_tvb = tvb_new_subset_remaining(tvb, offset);
    call_dissector(eth_withoutfcs_handle, eth_tvb, pinfo, tree);
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
          { "CFI", "hp_erm.cfi", FT_UINT32, BASE_DEC, VALS(hp_erm_cfi_vals),
            0x00100000, NULL, HFILL }},

        { &hf_hp_erm_vlan,
          { "Vlan", "hp_erm.vlan", FT_UINT32, BASE_DEC, NULL,
            0x000FFF00, NULL, HFILL }},

        { &hf_hp_erm_unknown3,
          { "Unknown3", "hp_erm.unknown3", FT_UINT32, BASE_DEC, NULL,
            0x000000FF, NULL, HFILL }}
    };

    static gint *ett[] = {
        &ett_hp_erm,
    };

    module_t *hp_erm_module;

    proto_hp_erm = proto_register_protocol(PROTO_LONG_NAME, PROTO_SHORT_NAME, "hp_erm");

    hp_erm_module = prefs_register_protocol(proto_hp_erm, proto_reg_handoff_hp_erm);
    prefs_register_uint_preference(hp_erm_module, "udp.port", "HP_ERM UDP Port",
                                   "Set the UDP port (source or destination) used for HP"
                                   " encapsulated remote mirroring frames;\n"
                                   "0 (default) means that the HP_ERM dissector is not active",
                                   10, &global_hp_erm_udp_port);

    proto_register_field_array(proto_hp_erm, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_hp_erm(void)
{
    static dissector_handle_t hp_erm_handle;
    static guint hp_erm_udp_port;
    static gboolean initialized = FALSE;

    if (!initialized) {
        eth_withoutfcs_handle = find_dissector("eth_withoutfcs");
        hp_erm_handle = create_dissector_handle(dissect_hp_erm, proto_hp_erm);
        initialized = TRUE;
    } else {
        if (hp_erm_udp_port != 0)
            dissector_delete_uint("udp.port", hp_erm_udp_port, hp_erm_handle);
    }

    hp_erm_udp_port = global_hp_erm_udp_port;

    if (hp_erm_udp_port != 0)
        dissector_add_uint("udp.port", hp_erm_udp_port, hp_erm_handle);
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
