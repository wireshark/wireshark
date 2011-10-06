/* Copyright 2002, Anand V. Narwani <anand[AT]narwani.org>
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>

#define IUC_REQUEST 1
#define IUC_REQ_DATA 2
#define IUC_INIT_MAINT 3
#define IUC_STATION_MAINT 4
#define IUC_SHORT_DATA_GRANT 5
#define IUC_LONG_DATA_GRANT 6
#define IUC_NULL_IE 7
#define IUC_DATA_ACK 8
#define IUC_RESERVED9 9
#define IUC_RESERVED10 10
#define IUC_RESERVED11 11
#define IUC_RESERVED12 12
#define IUC_RESERVED13 13
#define IUC_RESERVED14 14
#define IUC_EXPANSION 15

/* Initialize the protocol and registered fields */
static int proto_docsis_map = -1;
static int hf_docsis_map_upstream_chid = -1;
static int hf_docsis_map_ucd_count = -1;
static int hf_docsis_map_numie = -1;
static int hf_docsis_map_alloc_start = -1;
static int hf_docsis_map_ack_time = -1;
static int hf_docsis_map_rng_start = -1;
static int hf_docsis_map_rng_end = -1;
static int hf_docsis_map_data_start = -1;
static int hf_docsis_map_data_end = -1;
static int hf_docsis_map_ie = -1;
static int hf_docsis_map_rsvd = -1;

static int hf_docsis_map_sid = -1;
static int hf_docsis_map_iuc = -1;
static int hf_docsis_map_offset = -1;

/* Initialize the subtree pointers */
static gint ett_docsis_map = -1;

/* Defined in packet-ucd.c */
extern value_string iuc_vals[];

/* Code to actually dissect the packets */
static void
dissect_map (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  guint8 i, numie;
  int pos;
  guint16 sid;
  guint8 iuc;
  guint16 offset;
  guint32 ie, temp, mask;
  proto_item *it, *item;
  proto_tree *map_tree;
  guint8 upchid, ucd_count;


  numie = tvb_get_guint8 (tvb, 2);
  upchid = tvb_get_guint8 (tvb, 0);
  ucd_count = tvb_get_guint8 (tvb, 1);

  col_clear (pinfo->cinfo, COL_INFO);
  if (upchid > 0)
	col_add_fstr (pinfo->cinfo, COL_INFO,
		      "Map Message:  Channel ID = %u (U%u), UCD Count = %u,  # IE's = %u",
		      upchid, upchid - 1, ucd_count, numie);
  else
	col_add_fstr (pinfo->cinfo, COL_INFO,
		      "Map Message:  Channel ID = %u (Telephony Return), UCD Count = %u, # IE's = %u",
		      upchid, ucd_count, numie);

  if (tree)
    {
      it =
	proto_tree_add_protocol_format (tree, proto_docsis_map, tvb, 0, -1,
					"MAP Message");
      map_tree = proto_item_add_subtree (it, ett_docsis_map);

      proto_tree_add_item (map_tree, hf_docsis_map_upstream_chid, tvb, 0, 1,
			   ENC_BIG_ENDIAN);
      proto_tree_add_item (map_tree, hf_docsis_map_ucd_count, tvb, 1, 1,
			   ENC_BIG_ENDIAN);
      proto_tree_add_item (map_tree, hf_docsis_map_numie, tvb, 2, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item (map_tree, hf_docsis_map_rsvd, tvb, 3, 1, FALSE);
      proto_tree_add_item (map_tree, hf_docsis_map_alloc_start, tvb, 4, 4,
			   ENC_BIG_ENDIAN);
      proto_tree_add_item (map_tree, hf_docsis_map_ack_time, tvb, 8, 4,
			   ENC_BIG_ENDIAN);
      proto_tree_add_item (map_tree, hf_docsis_map_rng_start, tvb, 12, 1,
			   ENC_BIG_ENDIAN);
      proto_tree_add_item (map_tree, hf_docsis_map_rng_end, tvb, 13, 1,
			   ENC_BIG_ENDIAN);
      proto_tree_add_item (map_tree, hf_docsis_map_data_start, tvb, 14, 1,
			   ENC_BIG_ENDIAN);
      proto_tree_add_item (map_tree, hf_docsis_map_data_end, tvb, 15, 1,
			   ENC_BIG_ENDIAN);

      pos = 16;
      for (i = 0; i < numie; i++)
	{
	  ie = tvb_get_ntohl (tvb, pos);
	  mask = 0xFFFC0000;
	  temp = (ie & mask);
	  temp = temp >> 18;
	  sid = (guint16) (temp & 0x3FFF);
	  mask = 0x3C000;
	  temp = (ie & mask);
	  temp = temp >> 14;
	  iuc = (guint8) (temp & 0x0F);
	  mask = 0x3FFF;
	  offset = (guint16) (ie & mask);
	  item = proto_tree_add_item(map_tree, hf_docsis_map_sid, tvb, pos, 4, ENC_BIG_ENDIAN);
	  PROTO_ITEM_SET_HIDDEN(item);
	  item = proto_tree_add_item(map_tree, hf_docsis_map_iuc, tvb, pos, 4, ENC_BIG_ENDIAN);
	  PROTO_ITEM_SET_HIDDEN(item);
	  item = proto_tree_add_item(map_tree, hf_docsis_map_offset, tvb, pos, 4, ENC_BIG_ENDIAN);
	  PROTO_ITEM_SET_HIDDEN(item);
	  if (sid == 0x3FFF)
	    proto_tree_add_uint_format (map_tree, hf_docsis_map_ie, tvb, pos, 4,
				      ie, "SID = 0x%x (All CM's), IUC = %s, Offset = %u",
				      sid, val_to_str (iuc, iuc_vals, "%d"),
				      offset);
	  else
	    proto_tree_add_uint_format (map_tree, hf_docsis_map_ie, tvb, pos, 4,
				      ie, "SID = %u, IUC = %s, Offset = %u",
				      sid, val_to_str (iuc, iuc_vals, "%d"),
				      offset);
	  pos = pos + 4;
	}			/* for... */
    }				/* if(tree) */


}




/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/


void
proto_register_docsis_map (void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    {&hf_docsis_map_ucd_count,
     {"UCD Count", "docsis_map.ucdcount",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Map UCD Count", HFILL}
     },
    {&hf_docsis_map_upstream_chid,
     {"Upstream Channel ID", "docsis_map.upchid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_map_numie,
     {"Number of IE's", "docsis_map.numie",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Number of Information Elements", HFILL}
     },
    {&hf_docsis_map_alloc_start,
     {"Alloc Start Time (minislots)", "docsis_map.allocstart",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_map_ack_time,
     {"ACK Time (minislots)", "docsis_map.acktime",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_map_rng_start,
     {"Ranging Backoff Start", "docsis_map.rng_start",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_map_rng_end,
     {"Ranging Backoff End", "docsis_map.rng_end",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_map_data_start,
     {"Data Backoff Start", "docsis_map.data_start",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_map_data_end,
     {"Data Backoff End", "docsis_map.data_end",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_map_ie,
     {"Information Element", "docsis_map.ie",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_map_rsvd,
     {"Reserved [0x00]", "docsis_map.rsvd",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "Reserved Byte", HFILL}
     },
    {&hf_docsis_map_sid,
     {"Service Identifier", "docsis_map.sid",
      FT_UINT32, BASE_DEC, NULL, 0xFFFC0000,
      NULL, HFILL}
     },
    {&hf_docsis_map_iuc,
     {"Interval Usage Code", "docsis_map.iuc",
      FT_UINT32, BASE_DEC, VALS(iuc_vals), 0x0003c000,
      NULL, HFILL}
     },
    {&hf_docsis_map_offset,
     {"Offset", "docsis_map.offset",
      FT_UINT32, BASE_DEC, NULL, 0x00003fff,
      NULL, HFILL}
     },

  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_docsis_map,
  };

/* Register the protocol name and description */
  proto_docsis_map =
    proto_register_protocol ("DOCSIS Upstream Bandwidth Allocation",
			     "DOCSIS MAP", "docsis_map");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array (proto_docsis_map, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("docsis_map", dissect_map, proto_docsis_map);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_docsis_map (void)
{
  dissector_handle_t docsis_map_handle;

  docsis_map_handle = find_dissector ("docsis_map");
  dissector_add_uint ("docsis_mgmt", 0x03, docsis_map_handle);

}
