/* packet-pktgen.c
 * Routines for "Linux pktgen" dissection
 * Copyright 2006 _FF_
 * Francesco Fondelli <francesco dot fondelli, gmail dot com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* FF:
 * The linux packet generator is a tool to generate packets at very high speed in the kernel.
 * See linux/net/core/pktgen.c and linux/Documentation/networking/pktgen.txt for more info.
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_pktgen(void);
void proto_reg_handoff_pktgen(void);

/* magic num used for heuristic */
#define PKTGEN_MAGIC 0xbe9be955

/* Initialize the protocol and registered fields */
static int proto_pktgen;

/* pktgen header */
static int hf_pktgen_magic;
static int hf_pktgen_seqnum;
static int hf_pktgen_tvsec;
static int hf_pktgen_tvusec;
static int hf_pktgen_timestamp;

/* Initialize the subtree pointer */
static int ett_pktgen;

/* entry point */
static bool dissect_pktgen(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti          = NULL;
    proto_item *tmp         = NULL;
    proto_tree *pktgen_tree = NULL;
    uint32_t    offset      = 0;
    nstime_t    tstamp;
    uint32_t    magic;

    /* check for min size */
    if (tvb_reported_length(tvb) < 16) {  /* Not a PKTGEN packet. */
        return false;
    }

    /* check for magic number */
    magic = tvb_get_ntohl(tvb,0);
    if (magic != PKTGEN_MAGIC) {
        /* Not a PKTGEN packet. */
        return false;
    }


    /* Make entries in Protocol column and Info column on summary display */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PKTGEN");

    col_add_fstr(pinfo->cinfo, COL_INFO, "Seq: %u", tvb_get_ntohl(tvb, 4));

    if (tree) {

        /* create display subtree for the protocol */

        ti = proto_tree_add_item(tree, proto_pktgen, tvb, 0, -1, ENC_NA);

        pktgen_tree = proto_item_add_subtree(ti, ett_pktgen);

        /* add items to the subtree */

        proto_tree_add_item(pktgen_tree, hf_pktgen_magic, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(pktgen_tree, hf_pktgen_seqnum, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        tstamp.secs = tvb_get_ntohl(tvb, offset);
        tmp = proto_tree_add_item(pktgen_tree, hf_pktgen_tvsec, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_item_set_generated(tmp);
        offset += 4;

        tstamp.nsecs = tvb_get_ntohl(tvb, offset) /* microsecond on the wire so... */ * 1000;
        tmp = proto_tree_add_item(pktgen_tree, hf_pktgen_tvusec, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_item_set_generated(tmp);
        offset += 4;

        proto_tree_add_time(pktgen_tree, hf_pktgen_timestamp, tvb, offset - 8, 8, &tstamp);

        if (tvb_reported_length_remaining(tvb, offset)) /* random data */
            call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo,
            pktgen_tree);
    }

    return true;
}


/* Register the protocol with Wireshark */
void proto_register_pktgen(void)
{
    /* Setup list of header fields */

    static hf_register_info hf[] = {

        { &hf_pktgen_magic,
          {
              "Magic number", "pktgen.magic",
              FT_UINT32, BASE_HEX, NULL, 0x0,
              "The pktgen magic number", HFILL
          }
        },

        { &hf_pktgen_seqnum,
          {
              "Sequence number", "pktgen.seqnum",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL
          }
        },

        { &hf_pktgen_tvsec,
          {
              "Timestamp tvsec", "pktgen.tvsec",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              "Timestamp tvsec part", HFILL
          }
        },

        { &hf_pktgen_tvusec,
          {
              "Timestamp tvusec", "pktgen.tvusec",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              "Timestamp tvusec part", HFILL
          }
        },

        { &hf_pktgen_timestamp,
          {
              "Timestamp", "pktgen.timestamp",
              FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
              NULL, HFILL
          }
        }
    };

    /* Setup protocol subtree array */

    static int *ett[] = {
        &ett_pktgen
    };

    /* Register the protocol name and description */

    proto_pktgen = proto_register_protocol("Linux Kernel Packet Generator", "PKTGEN", "pktgen");

    /* Required function calls to register the header fields and subtrees used */

    proto_register_field_array(proto_pktgen, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void proto_reg_handoff_pktgen(void)
{
    /* Register as a heuristic UDP dissector */
    heur_dissector_add("udp", dissect_pktgen, "Linux Kernel Packet Generator over UDP", "pktgen_udp", proto_pktgen, HEURISTIC_ENABLE);
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
