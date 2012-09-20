/* packet-roofnet.c
 * Routines for roofnet dissection
 * Copyright 2006, Sebastien Tandel (sebastien@tandel.be)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/expert.h>
#include <epan/ptvcursor.h>


/* roofnet packet type constants */
#define ROOFNET_PT_QUERY 0x01
#define ROOFNET_PT_REPLY 0x02
#define ROOFNET_PT_DATA 0x04
#define ROOFNET_PT_GATEWAY 0x08
static const value_string roofnet_pt_vals[] = {
  { ROOFNET_PT_QUERY, "Query" },
  { ROOFNET_PT_REPLY, "Reply" },
  { ROOFNET_PT_DATA, "Data" },
  { ROOFNET_PT_GATEWAY, "Gateway" },
  { 0, NULL }
};

/* roofnet flag bit masks */
#define ROOFNET_FLAG_ERROR 0x01
#define ROOFNET_FLAG_UPDATE 0x02
static const value_string roofnet_flags_vals[] = {
  { ROOFNET_FLAG_ERROR, "Error" },
  { ROOFNET_FLAG_UPDATE, "Update" },
  { 0, NULL }
};

/* header length */
#define ROOFNET_HEADER_LENGTH 160
/* roofnet max length */
/* may change with time */
#define ROOFNET_MAX_LENGTH 400
/* Roofnet Link Description Length
 * which is 6 fields of 4 bytes */
#define ROOFNET_LINK_DESCRIPTION_LENGTH 6*4

/* offset constants */
#define ROOFNET_OFFSET_TYPE 1
#define ROOFNET_OFFSET_NLINKS 2
#define ROOFNET_OFFSET_DATA_LENGTH 10

/* offset relative to a link section of roofnet */
#define ROOFNET_LINK_OFFSET_SRC 0
#define ROOFNET_LINK_OFFSET_DST 20
/* roofnet link fields length */
#define ROOFNET_LINK_LEN 24

/* forward reference */
void proto_reg_handoff_roofnet(void);

static dissector_handle_t ip_handle;
static int proto_roofnet = -1;

/* hf fields for the header of roofnet */
static int hf_roofnet_version = -1;
static int hf_roofnet_type = -1;
static int hf_roofnet_nlinks = -1;
static int hf_roofnet_next = -1;
static int hf_roofnet_ttl = -1;
static int hf_roofnet_cksum = -1;
static int hf_roofnet_flags = -1;
static int hf_roofnet_data_length = -1;
static int hf_roofnet_query_dst = -1;
static int hf_roofnet_seq = -1;
static int hf_roofnet_links = -1;
static int hf_roofnet_link_src = -1;
static int hf_roofnet_link_forward = -1;
static int hf_roofnet_link_rev = -1;
static int hf_roofnet_link_seq = -1;
static int hf_roofnet_link_age = -1;
static int hf_roofnet_link_dst = -1;


static gint ett_roofnet = -1;
static gint ett_roofnet_link = -1;

/*
 * dissect the header of roofnet
 */
static void dissect_roofnet_header(proto_tree *tree, tvbuff_t *tvb, guint *offset)
{
  ptvcursor_t *cursor = ptvcursor_new(tree, tvb, *offset);

  ptvcursor_add(cursor, hf_roofnet_version, 1, ENC_BIG_ENDIAN);
  ptvcursor_add(cursor, hf_roofnet_type, 1, ENC_BIG_ENDIAN);
  ptvcursor_add(cursor, hf_roofnet_nlinks, 1, ENC_BIG_ENDIAN);
  ptvcursor_add(cursor, hf_roofnet_next, 1, ENC_BIG_ENDIAN);
  ptvcursor_add(cursor, hf_roofnet_ttl, 2, ENC_BIG_ENDIAN);
  ptvcursor_add(cursor, hf_roofnet_cksum, 2, ENC_BIG_ENDIAN);
  ptvcursor_add(cursor, hf_roofnet_flags, 2, ENC_BIG_ENDIAN);
  ptvcursor_add(cursor, hf_roofnet_data_length, 2, ENC_BIG_ENDIAN);
  ptvcursor_add(cursor, hf_roofnet_query_dst, 4, ENC_BIG_ENDIAN);
  ptvcursor_add(cursor, hf_roofnet_seq, 4, ENC_BIG_ENDIAN);

  *offset = ptvcursor_current_offset(cursor);
  ptvcursor_free(cursor);
}

/*
 * dissect the description of link in roofnet
 */
static void dissect_roofnet_link(proto_tree *tree, tvbuff_t *tvb, guint *offset, guint link)
{
  proto_item *it= NULL;
  proto_tree *subtree= NULL;

  ptvcursor_t *cursor= NULL;

  guint32 addr_src= 0;
  guint32 addr_dst= 0;

  addr_src= tvb_get_ipv4(tvb, *offset + ROOFNET_LINK_OFFSET_SRC);
  addr_dst= tvb_get_ipv4(tvb, *offset + ROOFNET_LINK_OFFSET_DST);

  it = proto_tree_add_text(tree, tvb, *offset, ROOFNET_LINK_LEN,
			    "link: %u, src: %s, dst: %s",
			    link,
			    get_hostname(addr_src),
			    get_hostname(addr_dst));
  subtree= proto_item_add_subtree(it, ett_roofnet_link);

  proto_tree_add_ipv4(subtree, hf_roofnet_link_src, tvb, *offset, 4, addr_src);
  *offset += 4;

  cursor = ptvcursor_new(subtree, tvb, *offset);

  ptvcursor_add(cursor, hf_roofnet_link_forward, 4, ENC_BIG_ENDIAN);
  ptvcursor_add(cursor, hf_roofnet_link_rev, 4, ENC_BIG_ENDIAN);
  ptvcursor_add(cursor, hf_roofnet_link_seq, 4, ENC_BIG_ENDIAN);
  ptvcursor_add(cursor, hf_roofnet_link_age, 4, ENC_BIG_ENDIAN);

  ptvcursor_free(cursor);

  *offset = ptvcursor_current_offset(cursor);
  proto_tree_add_ipv4(subtree, hf_roofnet_link_dst, tvb, *offset, 4, addr_dst);
  /* don't increment offset here because the dst of this link is the src of the next one */
}

/*
 * dissect the data in roofnet
 */
static void dissect_roofnet_data(proto_tree *tree, tvbuff_t *tvb, packet_info * pinfo, gint offset)
{
  guint16 roofnet_datalen= 0;
  guint16 remaining_datalen= 0;

  roofnet_datalen = tvb_get_ntohs(tvb, ROOFNET_OFFSET_DATA_LENGTH);
  remaining_datalen= tvb_reported_length_remaining(tvb, offset);


  /* dissect on remaining_datalen */
   if (roofnet_datalen < remaining_datalen)
     proto_tree_add_text(tree, tvb, offset, roofnet_datalen,
	 "[More payload data (%u) than told by Roofnet (%u)]",
	 remaining_datalen, roofnet_datalen);

  if (roofnet_datalen == 0)
    return;

  /* dissect ip payload */
  call_dissector(ip_handle, tvb_new_subset_remaining(tvb, offset), pinfo, tree);

}

/*
 * entry point of the roofnet dissector
 */
static void dissect_roofnet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item * it= NULL;
  proto_tree * roofnet_tree= NULL;
  guint offset= 0;

  guint8 roofnet_msg_type= 0;
  guint8 roofnet_nlinks= 0;
  guint8 nlink= 1;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Roofnet");

  roofnet_msg_type = tvb_get_guint8(tvb, ROOFNET_OFFSET_TYPE);
  /* Clear out stuff in the info column */
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "Message Type: %s",
	val_to_str(roofnet_msg_type, roofnet_pt_vals, "Unknown (%d)"));
  }

  if (tree) {
    it = proto_tree_add_item(tree, proto_roofnet, tvb, offset, -1, ENC_NA);
    roofnet_tree = proto_item_add_subtree(it, ett_roofnet);
  }

  dissect_roofnet_header(roofnet_tree, tvb, &offset);

  roofnet_nlinks= tvb_get_guint8(tvb, ROOFNET_OFFSET_NLINKS);
  /* Check that we do not have a malformed roofnet packet */
  if ((roofnet_nlinks*6*4)+ROOFNET_HEADER_LENGTH > ROOFNET_MAX_LENGTH) {
    if (tree) {
      expert_add_info_format(pinfo, it, PI_MALFORMED, PI_ERROR, "Too many links (%u)\n", roofnet_nlinks);
    }
    return;
  }

  for (; roofnet_nlinks > 0; roofnet_nlinks--) {
    /* Do we have enough buffer to decode the next link ? */
    if (tvb_reported_length_remaining(tvb, offset) < ROOFNET_LINK_DESCRIPTION_LENGTH)
      return;
    dissect_roofnet_link(roofnet_tree, tvb, &offset, nlink++);
  }

  dissect_roofnet_data(tree, tvb, pinfo, offset+4);
}

void proto_register_roofnet(void)
{
  static hf_register_info hf[] = {
    /* Roofnet Header */
    { &hf_roofnet_version,
      { "Version", "roofnet.version",
      FT_UINT8, BASE_DEC, NULL, 0x0, "Roofnet Version", HFILL }
    },

    { &hf_roofnet_type,
      { "Type", "roofnet.type",
	FT_UINT8, BASE_DEC, VALS(roofnet_pt_vals), 0x0, "Roofnet Message Type", HFILL }
    },

    { &hf_roofnet_nlinks,
      { "Number of Links", "roofnet.nlinks",
	FT_UINT8, BASE_DEC, NULL, 0x0, "Roofnet Number of Links", HFILL }
    },

    { &hf_roofnet_next,
      { "Next Link", "roofnet.next",
	FT_UINT8, BASE_DEC, NULL, 0x0, "Roofnet Next Link to Use", HFILL }
    },

    { &hf_roofnet_ttl,
      { "Time To Live", "roofnet.ttl",
	FT_UINT16, BASE_DEC, NULL, 0x0, "Roofnet Time to Live", HFILL }
    },

    { &hf_roofnet_cksum,
      { "Checksum", "roofnet.cksum",
	FT_UINT16, BASE_DEC, NULL, 0x0, "Roofnet Header Checksum", HFILL }
    },

    { &hf_roofnet_flags,
      { "Flags", "roofnet.flags",
	FT_UINT16, BASE_DEC, VALS(roofnet_flags_vals), 0x0, "Roofnet Flags", HFILL }
    },

    { &hf_roofnet_data_length,
      { "Data Length", "roofnet.datalength",
	FT_UINT16, BASE_DEC, NULL, 0x0, "Data Payload Length", HFILL }
    },

    { &hf_roofnet_query_dst,
      { "Query Dst", "roofnet.querydst",
	FT_IPv4, BASE_NONE, NULL, 0x0, "Roofnet Query Destination", HFILL }
    },

    { &hf_roofnet_seq,
      { "Seq", "roofnet.seq",
	FT_UINT32, BASE_DEC, NULL, 0x0, "Roofnet Sequential Number", HFILL }
    },

    { &hf_roofnet_links,
      { "Links", "roofnet.links",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_roofnet_link_src,
      { "Source IP", "roofnet.link.src",
      FT_IPv4, BASE_NONE, NULL, 0x0, "Roofnet Message Source", HFILL }
    },

    { &hf_roofnet_link_forward,
      { "Forward", "roofnet.link.forward",
	FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_roofnet_link_rev,
      { "Rev", "roofnet.link.rev",
	FT_UINT32, BASE_DEC, NULL, 0x0, "Revision Number", HFILL }
    },

    { &hf_roofnet_link_seq,
      { "Seq", "roofnet.link.seq",
	FT_UINT32, BASE_DEC, NULL, 0x0, "Link Sequential Number", HFILL }
    },

    { &hf_roofnet_link_age,
      { "Age", "roofnet.link.age",
	FT_UINT32, BASE_DEC, NULL, 0x0, "Information Age", HFILL }
    },

    { &hf_roofnet_link_dst,
      { "Dst IP", "roofnet.link.dst",
	FT_IPv4, BASE_NONE, NULL, 0x0, "Roofnet Message Destination", HFILL }
    }
  };

  /* setup protocol subtree array */
  static gint *ett[] = {
    &ett_roofnet,
    &ett_roofnet_link
  };

  proto_roofnet = proto_register_protocol(
				"Roofnet Protocol", /* Name */
				"Roofnet",	    /* Short Name */
				"roofnet"	    /* Abbrev */
				);

  proto_register_field_array(proto_roofnet, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}


void proto_reg_handoff_roofnet(void)
{
  dissector_handle_t roofnet_handle;

  /* Until now there is no other option than having an IPv4 payload (maybe
   * extended one day to IPv6 or other?) */
  ip_handle = find_dissector("ip");
  roofnet_handle = create_dissector_handle(dissect_roofnet, proto_roofnet);
  /* I did not put the type numbers in the ethertypes.h as they only are
   * experimental and not official */
  dissector_add_uint("ethertype", 0x0641, roofnet_handle);
  dissector_add_uint("ethertype", 0x0643, roofnet_handle);
  dissector_add_uint("ethertype", 0x0644, roofnet_handle);
  dissector_add_uint("ethertype", 0x0645, roofnet_handle);
}
