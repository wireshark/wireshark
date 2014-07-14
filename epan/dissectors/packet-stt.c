/* packet-stt.c
 *
 * Routines for Stateless Transport Tunneling (STT) packet dissection
 * Remi Vichery <remi.vichery@gmail.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Protocol ref:
 * http://tools.ietf.org/html/draft-davie-stt-06
 */


#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

/* IANA  ref:
 * http://www.iana.org/assignments/service-names-port-numbers/service-
 * names-port-numbers.xml
 */
#define TCP_PORT_STT  7471

#define STT_PCP_MASK    0xE000
#define STT_V_MASK      0x1000
#define STT_VLANID_MASK 0x0FFF
#define NO_MASK         0x0000
#define FLAG_B0_MASK    0x0001
#define FLAG_B1_MASK    0x0002
#define FLAG_B2_MASK    0x0004
#define FLAG_B3_MASK    0x0008
#define FLAG_B4_MASK    0x0010
#define FLAG_B5_MASK    0x0020
#define FLAG_B6_MASK    0x0040
#define FLAG_B7_MASK    0x0080

void proto_register_stt(void);
void proto_reg_handoff_stt(void);

static int proto_stt = -1;

static int hf_stt_version = -1;
static int hf_stt_flags = -1;
static int hf_stt_flag_b7 = -1;
static int hf_stt_flag_b6 = -1;
static int hf_stt_flag_b5 = -1;
static int hf_stt_flag_b4 = -1;
static int hf_stt_flag_b3 = -1;
static int hf_stt_flag_b2 = -1;
static int hf_stt_flag_b1 = -1;
static int hf_stt_flag_b0 = -1;
static int hf_stt_l4_offset = -1;
static int hf_stt_reserved_8 = -1;
static int hf_stt_mss = -1;
static int hf_stt_pcp = -1;
static int hf_stt_v = -1;
static int hf_stt_vlan_id= -1;
static int hf_stt_context_id = -1;
static int hf_stt_padding = -1;

static int ett_stt = -1;
static int ett_stt_flgs = -1;

static expert_field ei_stt_l4_offset = EI_INIT;

static dissector_handle_t eth_handle;

/* From Table G-2 of IEEE standard 802.1Q-2005 */
static const value_string pri_vals[] = {
  { 1, "Background"                        },
  { 0, "Best Effort (default)"             },
  { 2, "Excellent Effort"                  },
  { 3, "Critical Applications"             },
  { 4, "Video, < 100ms latency and jitter" },
  { 5, "Voice, < 10ms latency and jitter"  },
  { 6, "Internetwork Control"              },
  { 7, "Network Control"                   },
  { 0, NULL                                }
};

static void
dissect_stt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *stt_tree, *flg_tree;
    proto_item *ti, *flg_item, *l4_offset_item;
    tvbuff_t *next_tvb;
    guint8 flags, l4_offset;
    guint16 attributes;
    guint64 context_id;
    int offset = 0;

    /* Make entry in Protocol column on summary display. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "STT");

    /* Clean previous TCP information because STT frames are encapsulated
    in a TCP-like header (to avoid DUP Ack, TCP Out-of-order, ...). */
    col_clear_fence(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_stt, tvb, offset, -1, ENC_NA);
    stt_tree = proto_item_add_subtree(ti, ett_stt);

    /*
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |  Version      | Flags         |  L4 Offset    |  Reserved     |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |    Max. Segment Size          | PCP |V|     VLAN ID           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               |
       +                     Context ID (64 bits)                      +
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |     Padding                   |    Data                       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
       |                                                               |
    */

    /* Protocol version */
    proto_tree_add_item(stt_tree, hf_stt_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Flags tree */
    flg_item = proto_tree_add_item(stt_tree, hf_stt_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
    flg_tree = proto_item_add_subtree(flg_item, ett_stt_flgs);

    /* Flags */
    flags = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(flg_tree, hf_stt_flag_b7, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flg_tree, hf_stt_flag_b6, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flg_tree, hf_stt_flag_b5, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flg_tree, hf_stt_flag_b4, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flg_tree, hf_stt_flag_b3, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flg_tree, hf_stt_flag_b2, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flg_tree, hf_stt_flag_b1, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flg_tree, hf_stt_flag_b0, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Layer 4 offset */
    l4_offset = tvb_get_guint8(tvb, offset);
    l4_offset_item = proto_tree_add_item(stt_tree, hf_stt_l4_offset, tvb, offset, 1, ENC_BIG_ENDIAN);
    /* Display an error if offset is != 0 when encapsulated packet is NOT TCP */
    if ( !(flags & FLAG_B3_MASK) && (l4_offset != 0) ) {
        expert_add_info_format(pinfo, l4_offset_item, &ei_stt_l4_offset, "Incorrect offset, should be equals to zero");
    }
    /* Display an error if offset equals 0 when encapsulated packet is TCP */
    if ( (flags & FLAG_B3_MASK) && (l4_offset == 0) ) {
        expert_add_info_format(pinfo, l4_offset_item, &ei_stt_l4_offset, "Incorrect offset, should be greater than zero");
    }
    offset ++;

    /* Reserved field (1 byte). MUST be 0 on transmission,
    ignored on receipt. */
    proto_tree_add_item(stt_tree, hf_stt_reserved_8, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset ++;

    /* Maximum Segment Size. MUST be 0 if segmentation offload
    is not in use. */
    proto_tree_add_item(stt_tree, hf_stt_mss, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* Tag Control Information like header */
    attributes = tvb_get_ntohs(tvb, offset);
    /* if V flag is set, it indicates the presence of a valid
    VLAN ID in the following field and valid PCP in the preceding
    field. */
    if (attributes & STT_V_MASK) {
        /* Display priority code point and VLAN ID when V flag is set */
        proto_item_append_text(ti, ", Priority: %u, VLAN ID: %u", (attributes >> 13), (attributes & STT_VLANID_MASK));
        proto_tree_add_item(stt_tree, hf_stt_pcp, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(stt_tree, hf_stt_v, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(stt_tree, hf_stt_vlan_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    }
    offset += 2;

    /* Context ID */
    context_id = tvb_get_ntoh64(tvb, offset);
    proto_tree_add_item(stt_tree, hf_stt_context_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    proto_item_append_text(ti, ", Context ID: 0x%" G_GINT64_MODIFIER "x",context_id);
    offset += 8;

    /* Padding */
    proto_tree_add_item(stt_tree, hf_stt_padding, tvb, offset, 2, ENC_NA);
    offset += 2;

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    call_dissector(eth_handle, next_tvb, pinfo, tree);
}


/* Register STT with Wireshark */
void
proto_register_stt(void)
{
    expert_module_t* expert_stt;

    static hf_register_info hf[] = {
        { &hf_stt_version,
          { "Version", "stt.version",
            FT_UINT8, BASE_DEC, NULL, NO_MASK,
            NULL, HFILL
          },
        },
        { &hf_stt_flags,
          { "Flags", "stt.flags",
            FT_UINT8, BASE_HEX, NULL, NO_MASK,
            NULL, HFILL,
          },
        },
        { &hf_stt_flag_b7,
          { "Unused flag", "stt.flags.b7",
            FT_BOOLEAN, 8, NULL, FLAG_B7_MASK,
            NULL, HFILL,
          },
        },
        { &hf_stt_flag_b6,
          { "Unused flag", "stt.flags.b6",
            FT_BOOLEAN, 8, NULL, FLAG_B6_MASK,
            NULL, HFILL,
          },
        },
        { &hf_stt_flag_b5,
          { "Unused flag", "stt.flags.b5",
            FT_BOOLEAN, 8, NULL, FLAG_B5_MASK,
            NULL, HFILL,
          },
        },
        { &hf_stt_flag_b4,
          { "Unused flag", "stt.flags.b4",
            FT_BOOLEAN, 8, NULL, FLAG_B4_MASK,
            NULL, HFILL,
          },
        },
        { &hf_stt_flag_b3,
          { "TCP payload", "stt.flags.b3",
            FT_BOOLEAN, 8, NULL, FLAG_B3_MASK,
            NULL, HFILL,
          },
        },
        { &hf_stt_flag_b2,
          { "IPv4 packet", "stt.flags.b2",
            FT_BOOLEAN, 8, NULL, FLAG_B2_MASK,
            NULL, HFILL,
          },
        },
        { &hf_stt_flag_b1,
          { "Checksum partial", "stt.flags.b1",
            FT_BOOLEAN, 8, NULL, FLAG_B1_MASK,
            NULL, HFILL,
          },
        },
        { &hf_stt_flag_b0,
          { "Checksum verified", "stt.flags.b0",
            FT_BOOLEAN, 8, NULL, FLAG_B0_MASK,
            NULL, HFILL,
          },
        },
        { &hf_stt_l4_offset,
          { "L4 Offset", "stt.l4offset",
            FT_UINT8, BASE_DEC, NULL, NO_MASK,
            NULL, HFILL,
          },
        },
        { &hf_stt_reserved_8,
          { "Reserved", "stt.reserved",
            FT_UINT8, BASE_DEC, NULL, NO_MASK,
            NULL, HFILL,
          },
        },
        { &hf_stt_mss,
          { "Max Segment Size", "stt.mss",
            FT_UINT16, BASE_DEC, NULL, NO_MASK,
            NULL, HFILL,
          },
        },
        { &hf_stt_pcp,
          { "PCP", "stt.pcp",
            FT_UINT16, BASE_DEC, VALS(pri_vals), STT_PCP_MASK,
            NULL, HFILL,
          },
        },
        { &hf_stt_v,
          { "V flag", "stt.v",
            FT_UINT16, BASE_DEC, NULL, STT_V_MASK,
            NULL, HFILL,
          },
        },
        { &hf_stt_vlan_id,
          { "VLAN ID", "stt.vlan_id",
            FT_UINT16, BASE_DEC, NULL, STT_VLANID_MASK,
            NULL, HFILL,
          },
        },
        { &hf_stt_context_id,
          { "Context ID", "stt.context_id",
            FT_UINT64, BASE_HEX, NULL, NO_MASK,
            NULL, HFILL,
          },
        },
        { &hf_stt_padding,
          { "Padding", "stt.padding",
            FT_BYTES, BASE_NONE, NULL, NO_MASK,
            NULL, HFILL,
          },
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_stt,
        &ett_stt_flgs,
    };

    static ei_register_info ei[] = {
        { &ei_stt_l4_offset,
          { "stt.l4_offset_bad.expert", PI_PROTOCOL,
            PI_WARN, "Bad L4 Offset", EXPFILL
          }
        },
    };

    /* Register the protocol name and description */
    proto_stt = proto_register_protocol("Stateless Transport Tunneling",
                                          "STT", "stt");

    expert_stt = expert_register_protocol(proto_stt);
    expert_register_field_array(expert_stt, ei, array_length(ei));

    /* Required function calls to register the header fields and
    subtrees used */
    proto_register_field_array(proto_stt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_stt(void)
{
    dissector_handle_t stt_handle;

    eth_handle = find_dissector("eth");

    /* Need to be modified with a special hack in the TCP dissector. */
    stt_handle = create_dissector_handle(dissect_stt, proto_stt);
    dissector_add_uint("tcp.port", TCP_PORT_STT, stt_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
