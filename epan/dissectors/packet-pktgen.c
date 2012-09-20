/* packet-pktgen.c
 * Routines for "Linux pktgen" dissection
 * Copyright 2006 _FF_
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* FF:
 * The linux packet generator is a tool to generate packets at very high speed in the kernel.
 * See linux/net/core/pktgen.c and linux/Documentation/networking/pktgen.txt for more info.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>

/* magic num used for heuristic */
static const guint8 pktgen_magic[] = { 0xbe, 0x9b, 0xe9, 0x55 };

/* Initialize the protocol and registered fields */
static int proto_pktgen = -1;

/* pktgen header */
static int hf_pktgen_magic = -1;
static int hf_pktgen_seqnum = -1;
static int hf_pktgen_tvsec = -1;
static int hf_pktgen_tvusec = -1;
static int hf_pktgen_timestamp = -1;

/* Initialize the subtree pointer */
static gint ett_pktgen = -1;

/* data dissector handle */
static dissector_handle_t data_handle;

/* entry point */
static gboolean dissect_pktgen(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti = NULL;
    proto_item *tmp = NULL;
    proto_tree *pktgen_tree = NULL;
    guint32 offset = 0;
    nstime_t tstamp;

    /* check for min size */
    if(tvb_length(tvb) < 16) { 	/* Not a PKTGEN packet. */
	return FALSE;
    }

    /* check for magic number */
    if(tvb_memeql(tvb, 0, pktgen_magic, 4) == -1) { /* Not a PKTGEN packet. */
	return FALSE;
    }

    /* Make entries in Protocol column and Info column on summary display */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PKTGEN");

    if(check_col(pinfo->cinfo, COL_INFO)) {
	col_add_fstr(pinfo->cinfo, COL_INFO, "Seq: %u", tvb_get_ntohl(tvb, 4));
    }

    if(tree) {

	/* create display subtree for the protocol */

	ti = proto_tree_add_item(tree, proto_pktgen, tvb, 0, -1, ENC_NA);

	pktgen_tree = proto_item_add_subtree(ti, ett_pktgen);

	/* add items to the subtree */

	proto_tree_add_item(pktgen_tree, hf_pktgen_magic, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset+=4;

	proto_tree_add_item(pktgen_tree, hf_pktgen_seqnum, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset+=4;

	tstamp.secs = tvb_get_ntohl(tvb, offset);
	tmp = proto_tree_add_item(pktgen_tree, hf_pktgen_tvsec, tvb, offset, 4, ENC_BIG_ENDIAN);
	PROTO_ITEM_SET_GENERATED(tmp);
	offset+=4;

	tstamp.nsecs = tvb_get_ntohl(tvb, offset) /* microsecond on the wire so... */ * 1000;
	tmp = proto_tree_add_item(pktgen_tree, hf_pktgen_tvusec, tvb, offset, 4, ENC_BIG_ENDIAN);
	PROTO_ITEM_SET_GENERATED(tmp);
	offset+=4;

	proto_tree_add_time(pktgen_tree, hf_pktgen_timestamp, tvb, offset - 8, 8, &tstamp);

#if 0
	if(tvb_length_remaining(tvb, offset)) /* random data */
	    proto_tree_add_text(pktgen_tree, tvb, offset, -1, "Data (%u bytes)",
				tvb_length_remaining(tvb, offset));
#else
	if(tvb_length_remaining(tvb, offset)) /* random data */
	    call_dissector(data_handle, tvb_new_subset_remaining(tvb, offset), pinfo,
		pktgen_tree);
#endif
    }

    return TRUE;
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

    static gint *ett[] = {
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
    heur_dissector_add("udp", dissect_pktgen, proto_pktgen);

    /* Find data dissector handle */
    data_handle = find_dissector("data");
}
