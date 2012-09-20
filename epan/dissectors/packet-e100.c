/* packet-e100.c
 * Routines for Arbor Networks E100 packet encapsulation disassembly
 *
 * $Id$
 *
 * Copyright (c) 2009 by Bradley Higgins <bhiggins@arbor.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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
 */

#include "config.h"

#include <epan/packet.h>

static int proto_e100 = -1;

static dissector_handle_t eth_handle;

/* Dissector tree globals */
static int hf_e100_header = -1;
static int hf_e100_port = -1;
static int hf_e100_seq = -1;
static int hf_e100_ip = -1;
static int hf_e100_mon_pkt_id = -1;
static int hf_e100_pkt_ts = -1;
static int hf_e100_bytes_cap = -1;
static int hf_e100_bytes_orig = -1;

static gint ett_e100 = -1;

/* E100 encapsulated packet offsets */
typedef struct _e100_encap
{
    guint offset;
    guint len;
} e100_encap;

static e100_encap e100_header_ver = {0, 1};
static e100_encap e100_port_recv  = {1, 1};
static e100_encap e100_seq        = {2, 2};
static e100_encap e100_ip         = {4, 4};
static e100_encap e100_mon_pkt_id = {8, 4};
static e100_encap e100_ts         = {12, 8};
static e100_encap e100_bytes_cap  = {20, 4};
static e100_encap e100_bytes_orig = {24, 4};
static guint e100_encap_len = 28;


static int
dissect_e100(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int ret_val = 0;
    tvbuff_t *next_tvb = NULL;

        /* heuristic testing:
         * (1) tvb packet is larger than e100 packet
         * (2) e100 header is 1
         * (3) e100 capture size matches tvb packet size
         */
        if (tvb_length(tvb) >= e100_encap_len &&
            tvb_get_guint8(tvb, e100_header_ver.offset) == 1 &&
            tvb_get_ntohl(tvb, e100_bytes_cap.offset) == tvb_length(tvb)-e100_encap_len)
        {
            guint32 bytes_captured=0;
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "e100");
            col_set_str(pinfo->cinfo, COL_INFO, "E100 Encapsulated Packet");
            if (tree)
            {
                /* pick apart protocol for display */
                proto_item *ti = NULL;
                proto_tree *e100_tree = NULL;

                ti = proto_tree_add_item(tree, proto_e100, tvb, 0, e100_encap_len, ENC_NA);
                e100_tree = proto_item_add_subtree(ti, ett_e100);

                proto_tree_add_item(e100_tree, hf_e100_header, tvb,
                        e100_header_ver.offset, e100_header_ver.len, ENC_BIG_ENDIAN);
                proto_tree_add_item(e100_tree, hf_e100_port, tvb,
                        e100_port_recv.offset, e100_port_recv.len, ENC_BIG_ENDIAN);
                proto_tree_add_item(e100_tree, hf_e100_seq, tvb,
                        e100_seq.offset, e100_seq.len, ENC_BIG_ENDIAN);
                proto_tree_add_item(e100_tree, hf_e100_ip, tvb,
                        e100_ip.offset, e100_ip.len, ENC_BIG_ENDIAN);
                proto_tree_add_item(e100_tree, hf_e100_mon_pkt_id, tvb,
                        e100_mon_pkt_id.offset, e100_mon_pkt_id.len, ENC_BIG_ENDIAN);
                {
                  nstime_t ts;
                  ts.secs = tvb_get_ntohl(tvb, e100_ts.offset);
                  ts.nsecs = tvb_get_ntohl(tvb, e100_ts.offset+4)*1000;
                  proto_tree_add_time(e100_tree, hf_e100_pkt_ts, tvb,
                          e100_ts.offset, e100_ts.len, &ts);
                }
                proto_tree_add_item(e100_tree, hf_e100_bytes_cap, tvb,
                        e100_bytes_cap.offset, e100_bytes_cap.len, ENC_BIG_ENDIAN);
                proto_tree_add_item(e100_tree, hf_e100_bytes_orig, tvb,
                        e100_bytes_orig.offset, e100_bytes_orig.len, ENC_BIG_ENDIAN);

            } /* if(tree) */
            bytes_captured = tvb_get_ntohl(tvb, e100_bytes_cap.offset);
            next_tvb = tvb_new_subset(tvb, e100_encap_len, -1, bytes_captured);
            call_dissector(eth_handle, next_tvb, pinfo, tree);

            ret_val = tvb_length(tvb);
        } /* heuristic testing */

    return ret_val;
}

void
proto_register_e100(void)
{
    static hf_register_info hf[] =
    {
    { &hf_e100_header,
        { "Header Version",
            "e100.version",
            FT_UINT8,
            BASE_DEC,
            NULL, 0x0, NULL, HFILL
        }
    },
    { &hf_e100_port,
        { "E100 Port Received",
            "e100.port_recv",
            FT_UINT8,
            BASE_DEC,
            NULL, 0x0, NULL, HFILL
        }
    },
    { &hf_e100_seq,
        { "Sequence Number",
            "e100.seq_num",
            FT_UINT16,
            BASE_DEC,
            NULL, 0x0, NULL, HFILL
        }
    },
    {  &hf_e100_ip,
        { "E100 IP Address",
            "e100.ip",
            FT_IPv4,
            BASE_NONE,
            NULL, 0x0, NULL, HFILL
        }
    },
    { &hf_e100_mon_pkt_id,
        { "Monitor Packet ID",
            "e100.mon_pkt_id",
            FT_UINT32,
            BASE_DEC,
            NULL, 0x0, NULL, HFILL
        }
    },
    { &hf_e100_pkt_ts,
        { "Packet Capture Timestamp",
            "e100.pkt_ts",
            FT_ABSOLUTE_TIME,
            ABSOLUTE_TIME_LOCAL,
            NULL, 0x0, NULL, HFILL
        }
    },
    { &hf_e100_bytes_cap,
        { "Bytes Captured",
            "e100.bytes_cap",
            FT_UINT32,
            BASE_DEC,
            NULL, 0x0, NULL, HFILL
        }
    },
    { &hf_e100_bytes_orig,
        { "Bytes in Original Packet",
            "e100.bytes_orig",
            FT_UINT32,
            BASE_DEC,
            NULL, 0x0, NULL, HFILL
        }
    }
    };

    /* Setup protocol subtree array */
    static gint *ett[] =
    {
        &ett_e100
    };

    proto_e100 = proto_register_protocol("E100 Encapsulation", "E100", "e100");
    proto_register_field_array(proto_e100, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_e100(void)
{
    /* Check all UDP traffic, as the specific UDP port is configurable */
    heur_dissector_add("udp", dissect_e100, proto_e100);
    /* e100 traffic encapsulates traffic from the ethernet frame on */
    eth_handle = find_dissector("eth");
}
