/* packet-trel.c
 * Routines for TREL packet dissection
 * Copyright 2004, Pranay Nagpure  - <pranay.dilip@graniteriverlabs.in>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "config.h"
#include <epan/packet.h>
#include "packet-ieee802154.h"
#include <epan/wmem_scopes.h>
#include <epan/packet_info.h>
#include <epan/proto_data.h>
#include <epan/proto.h>
#include <packet-mle.h>
#include <packet-6lowpan.h>
#include <epan/expert.h>
#include<wsutil/wsgcrypt.h>

#define TREL_PORT 38196

#define  TREL_TYPE_BROADCAST 0
#define TREL_TYPE_UNICAST    1
#define TREL_TYPE_ACK        2

static dissector_handle_t trel_handle;
static int hf_trel_version;
static int hf_trel_rsv;
static int hf_trel_ack;
static int hf_trel_type;
static int hf_trel_channel;
static int hf_802154_dest_panid;
static int hf_trel_source_addr;
static int hf_trel_destination_addr;
static int hf_trel_packetno;

static int proto_trel;

static int ett_trel;
static int ett_trel_hdr;

void proto_register_trel(void);

static const value_string trel_command_vals[] = {
    { TREL_TYPE_BROADCAST,                "TREL Advertisement" },
    { TREL_TYPE_UNICAST,                  "TREL Unicast Response" },
    { TREL_TYPE_ACK,                      "TREL Acknowledgement"},
    { 0, NULL}
};

static int
dissect_trel(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    proto_tree* volatile trel_tree = NULL, * volatile trel_hdr_tree;
    proto_item* volatile proto_root = NULL;

    unsigned                offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TREL");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_root = proto_tree_add_item(tree, proto_trel, tvb, 0, tvb_reported_length(tvb), ENC_NA);
    trel_tree = proto_item_add_subtree(proto_root, ett_trel);

    //add header subtree
    trel_hdr_tree = proto_tree_add_subtree(trel_tree, tvb, 0, 4, ett_trel_hdr, NULL, "Header");

    proto_tree_add_item(trel_hdr_tree, hf_trel_version, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(trel_hdr_tree, hf_trel_rsv, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(trel_hdr_tree, hf_trel_ack, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(trel_hdr_tree, hf_trel_type, tvb, offset, 1, ENC_NA);

    uint8_t type = tvb_get_uint8(tvb, offset);
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str(type, trel_command_vals, "Unknown (%x)"));
    ++offset;
    proto_tree_add_item(trel_hdr_tree, hf_trel_channel, tvb, offset, 1, ENC_NA);
    ++offset;

    proto_tree_add_item(trel_hdr_tree, hf_802154_dest_panid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(trel_hdr_tree, hf_trel_packetno, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(trel_hdr_tree, hf_trel_source_addr, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    if (type)
    {
        proto_tree_add_item(trel_hdr_tree, hf_trel_destination_addr, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    dissector_handle_t frame_handle = find_dissector("wpan_nofcs");
    tvbuff_t* payload = tvb_new_subset_remaining(tvb, offset);

    if (tvb_reported_length(payload))
        call_dissector(frame_handle, payload, pinfo, trel_tree);

    return tvb_captured_length(tvb);
}
// below code is added to replace mdns dissector registration
static bool
dissect_trel_heur(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
    if ((tvb_captured_length(tvb)) < 16 ) {
        return false;
    }

    uint8_t first = tvb_get_uint8(tvb, 0);
    if ((first & 0xE0) != 0)
        return false;

    if (pinfo->srcport == pinfo->destport)      return false;

    dissect_trel(tvb, pinfo, tree, data);
    return true;
}
void
proto_register_trel(void)
{

    static hf_register_info hf[] = {

        { &hf_trel_version,
          { "TREL version",
            "trel.ver",
            FT_UINT8, BASE_DEC, NULL, 0xE0,
            "The TREL protocol version",
            HFILL
          }
        },
        { &hf_trel_rsv,
          { "TREL reserved bit",
            "trel.rsv",
            FT_UINT8, BASE_DEC, NULL, 0x18,
            "The TREL reserved bit",
            HFILL
          }
        },
        { &hf_trel_ack,
          { "TREL acknowledgement",
            "trel.ack",
            FT_UINT8, BASE_DEC, NULL, 0x4,
            "The TREL acknowledgement",
            HFILL
          }
        },
        { &hf_trel_type,
          { "TREL type",
            "trel.type",
            FT_UINT8, BASE_DEC, NULL, 0x3,
            "The TREL type",
            HFILL
          }
        },
        { &hf_trel_channel,
          { "TREL channel",
            "trel.channel",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "The TREL channel",
            HFILL
          }
        },
        { &hf_802154_dest_panid,
          { "TREL 802.15.4 Dest Pan ID",
            "trel.panID",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "The TREL  802.15.4 Dest Pan ID",
            HFILL
          }
        },
        { &hf_trel_packetno,
          { "TREL packet number",
            "trel.packetno",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "The TREL  packet number",
            HFILL
          }
        },
        { &hf_trel_source_addr,
          { "TREL Src Address",
             "trel.source_addr",
             FT_EUI64, BASE_NONE, NULL, 0x0,
             "Source address",
             HFILL
          }
        },
        { &hf_trel_destination_addr,
          { "TREL Dest Address",
            "trel.destination_addr",
            FT_EUI64, BASE_NONE, NULL, 0x0,
            "Destination address",
            HFILL
          }
        }
    };

    static int* ett[] = {
      &ett_trel,
      &ett_trel_hdr
    };

    proto_trel = proto_register_protocol("TREL Protocol", "TREL", "trel");

    proto_register_field_array(proto_trel, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    trel_handle = register_dissector("trel", dissect_trel, proto_trel);

}
void
proto_reg_handoff_trel(void)
{
    //heur dissector is disabled as it not strong enough
    //dissector_add_uint("udp.port", TREL_PORT, trel_handle);
    dissector_add_uint_with_preference("udp.port", 0, trel_handle);
    heur_dissector_add("udp", dissect_trel_heur, "TREL over UDP", "trel_udp", proto_trel, HEURISTIC_DISABLE);
}
