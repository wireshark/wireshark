/* packet-lanforge.c
 * Routines for "LANforge traffic generator IP protocol" dissection
 * Copyright 2008
 * Ben Greear <greearb@candelatech.com>
 *
 * Based on pktgen dissectory by:
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

/* LANforge generates network traffic for load & performance testing.
 * See http://www.candelatech.com for more info.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>

/* magic num used for heuristic */
static const guint8 lanforge_magic[] = { 0x1a, 0x2b, 0x3c, 0x4d };

/* Initialize the protocol and registered fields */
static int proto_lanforge = -1;

/* lanforge header */
static int hf_lanforge_crc = -1;
static int hf_lanforge_magic = -1;
static int hf_lanforge_src_session = -1;
static int hf_lanforge_dst_session = -1;
static int hf_lanforge_pld_len_l = -1;
static int hf_lanforge_pld_len_h = -1;
static int hf_lanforge_pld_len = -1;
static int hf_lanforge_pld_pattern = -1;
static int hf_lanforge_seq = -1;
static int hf_lanforge_tx_time_s = -1;
static int hf_lanforge_tx_time_ns = -1;
static int hf_lanforge_timestamp = -1;

/* Initialize the subtree pointer */
static gint ett_lanforge = -1;

/* data dissector handle */
static dissector_handle_t data_handle;

/* entry point */
static gboolean dissect_lanforge(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    proto_item *tmp;
    proto_tree *lanforge_tree;
    guint32 offset = 0;
    nstime_t tstamp;
    guint32 tss;
    guint32 tmpi;
    guint32 pld_len;

    /* check for min size */
    if(tvb_length(tvb) < 28) {  /* Not a LANforge packet. */
        return FALSE;
    }

    /* check for magic number */
    if(tvb_memeql(tvb, 4, lanforge_magic, 4) == -1) { /* Not a LANforge packet. */
       return FALSE;
    }

    /* Make entries in Protocol column and Info column on summary display */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LANforge");

    if(check_col(pinfo->cinfo, COL_INFO)) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Seq: %u", tvb_get_ntohl(tvb, 16));
    }

    if(tree) {

        /* create display subtree for the protocol */

        ti = proto_tree_add_item(tree, proto_lanforge, tvb, 0, -1, FALSE);

        lanforge_tree = proto_item_add_subtree(ti, ett_lanforge);

        /* add items to the subtree */

        proto_tree_add_item(lanforge_tree, hf_lanforge_crc, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;

        proto_tree_add_item(lanforge_tree, hf_lanforge_magic, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;

        proto_tree_add_item(lanforge_tree, hf_lanforge_src_session, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;

        proto_tree_add_item(lanforge_tree, hf_lanforge_dst_session, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;

        pld_len = tvb_get_ntohs(tvb, offset);
        tmp = proto_tree_add_item(lanforge_tree, hf_lanforge_pld_len_l, tvb, offset, 2, ENC_BIG_ENDIAN);
        PROTO_ITEM_SET_GENERATED(tmp);
        offset+=2;

        tmpi = tvb_get_guint8(tvb, offset);
        tmp = proto_tree_add_item(lanforge_tree, hf_lanforge_pld_len_h, tvb, offset, 1, ENC_BIG_ENDIAN);
        PROTO_ITEM_SET_GENERATED(tmp);
        offset+=1;
        pld_len |= (tmpi << 16);

        proto_tree_add_uint(lanforge_tree, hf_lanforge_pld_len, tvb, offset-3, 3, pld_len);

        proto_tree_add_item(lanforge_tree, hf_lanforge_pld_pattern, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset+=1;

        proto_tree_add_item(lanforge_tree, hf_lanforge_seq, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;

        tss = tvb_get_ntohl(tvb, offset);
        tstamp.secs = tss;
        tmp = proto_tree_add_item(lanforge_tree, hf_lanforge_tx_time_s, tvb, offset, 4, ENC_BIG_ENDIAN);
        PROTO_ITEM_SET_GENERATED(tmp);
        offset+=4;

        tss = tvb_get_ntohl(tvb, offset);
        tstamp.nsecs = tss;
        tmp = proto_tree_add_item(lanforge_tree, hf_lanforge_tx_time_ns, tvb, offset, 4, ENC_BIG_ENDIAN);
        PROTO_ITEM_SET_GENERATED(tmp);
        offset+=4;

        proto_tree_add_time(lanforge_tree, hf_lanforge_timestamp, tvb, offset - 8, 8, &tstamp);

#if 0
        if(tvb_reported_length_remaining(tvb, offset) > 0) /* random data */
            proto_tree_add_text(lanforge_tree, tvb, offset, -1, "Data (%u bytes)",
                                tvb_length_remaining(tvb, offset));
#else
        if(tvb_reported_length_remaining(tvb, offset) > 0) /* random data */
            call_dissector(data_handle, tvb_new_subset_remaining(tvb, offset), pinfo,
                lanforge_tree);
#endif
    }

    return TRUE;
}


/* Register the protocol with Wireshark */
void proto_register_lanforge(void)
{
    /* Setup list of header fields */

    static hf_register_info hf[] = {

        { &hf_lanforge_crc,
          {
              "CRC", "lanforge.CRC",
              FT_UINT32, BASE_HEX, NULL, 0x0,
              "The LANforge CRC number", HFILL
          }
        },

        { &hf_lanforge_magic,
          {
              "Magic number", "lanforge.magic",
              FT_UINT32, BASE_HEX, NULL, 0x0,
              "The LANforge magic number", HFILL
          }
        },

        { &hf_lanforge_src_session,
          {
              "Source session ID", "lanforge.source-session-id",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "The LANforge source session ID", HFILL
          }
        },

        { &hf_lanforge_dst_session,
          {
              "Dest session ID", "lanforge.dest-session-id",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "The LANforge dest session ID", HFILL
          }
        },

        { &hf_lanforge_pld_len_l,
          {
              "Payload Length(L)", "lanforge.pld-len-L",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "The LANforge payload length (low bytes)", HFILL
          }
        },

        { &hf_lanforge_pld_len_h,
          {
              "Payload Length(H)", "lanforge.pld-len-H",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "The LANforge payload length (high byte)", HFILL
          }
        },

        { &hf_lanforge_pld_len,
          {
              "Payload Length", "lanforge.pld-length",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              "The LANforge payload length", HFILL
          }
        },

        { &hf_lanforge_pld_pattern,
          {
              "Payload Pattern", "lanforge.pld-pattern",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "The LANforge payload pattern", HFILL
          }
        },

        { &hf_lanforge_seq,
          {
              "Sequence Number", "lanforge.seqno",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              "The LANforge Sequence Number", HFILL
          }
        },

        { &hf_lanforge_tx_time_s,
          {
              "Timestamp Secs", "lanforge.ts-secs",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL
          }
        },

        { &hf_lanforge_tx_time_ns,
          {
              "Timestamp nsecs", "lanforge.ts-nsecs",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL
          }
        },

        { &hf_lanforge_timestamp,
          {
              "Timestamp", "lanforge.timestamp",
              FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
              NULL, HFILL
          }
        }
    };

    /* Setup protocol subtree array */

    static gint *ett[] = {
        &ett_lanforge
    };

    /* Register the protocol name and description */

    proto_lanforge = proto_register_protocol("LANforge Traffic Generator", "LANforge", "lanforge");

    /* Required function calls to register the header fields and subtrees used */

    proto_register_field_array(proto_lanforge, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void proto_reg_handoff_lanforge(void)
{
    /* Register as a heuristic UDP dissector */
    heur_dissector_add("udp", dissect_lanforge, proto_lanforge);
    heur_dissector_add("tcp", dissect_lanforge, proto_lanforge);

    /* Find data dissector handle */
    data_handle = find_dissector("data");
}
