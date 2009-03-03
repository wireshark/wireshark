/* packet-miop.c
 * Routines for CORBA MIOP packet disassembly
 * Significantly based on packet-giop.c
 * Copyright 2009 Alvaro Vega Garcia <avega at tid dot es>
 *
 * According with Unreliable Multicast Draft Adopted Specification 
 * 2001 October (OMG)
 * Chapter 29: Unreliable Multicast Inter-ORB Protocol (MIOP)
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <glib.h>
#include <math.h>
#ifdef NEED_STRERROR_H
#include "strerror.h"
#endif

#include "isprint.h"

#include <epan/packet.h>
#include <epan/emem.h>

#include "packet-miop.h"
#include "packet-giop.h"
#include "packet-tcp.h"

#ifdef NEED_G_ASCII_STRCASECMP_H
#include "g_ascii_strcasecmp.h"
#endif

/*
 * Set to 1 for DEBUG output - TODO make this a runtime option
 */

#define DEBUG   0

/*
 * ------------------------------------------------------------------------------------------+
 *                                 Data/Variables/Structs
 * ------------------------------------------------------------------------------------------+
 */


static int proto_miop = -1;

/*
 * (sub)Tree declares
 */


static gint hf_miop_magic = -1;
static gint hf_miop_hdr_version = -1;
static gint hf_miop_flags = -1;
static gint hf_miop_packet_length = -1;
static gint hf_miop_packet_number = -1;
static gint hf_miop_number_of_packets = -1;
static gint hf_miop_unique_id_len = -1;
static gint hf_miop_unique_id = -1;


static gint ett_miop_magic = -1;
static gint ett_miop_hdr_version = -1;
static gint ett_miop_flags = -1;
static gint ett_miop_packet_length = -1;
static gint ett_miop_packet_number = -1;
static gint ett_miop_number_of_packets = -1;
static gint ett_miop_unique_id_len = -1;
static gint ett_miop_unique_id = -1;


static dissector_handle_t miop_handle;

#define MIOP_MAGIC 	 "MIOP"


static gboolean
dissect_miop_heur (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree) {

  guint tot_len;

  /* check magic number and version */


  tot_len = tvb_length(tvb);

  if (tot_len < MIOP_HEADER_SIZE) /* tot_len < 16 */
    {
      /* Not enough data captured to hold the GIOP header; don't try
         to interpret it as GIOP. */
      return FALSE;
    }

  if ( tvb_memeql(tvb, 0, MIOP_MAGIC ,4) != 0)
    return FALSE;

  if (pinfo->ptype != PT_UDP)
    return FALSE;
  
  dissect_miop (tvb, pinfo, tree);

  /* TODO: make reasembly */

  return TRUE;

}


/* Main entry point */
static void dissect_miop (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree) {
  guint offset = 0;
  PacketHeader header;
  UniqueId unique_id;

  tvbuff_t *miop_header_tvb;
  tvbuff_t *unique_id_len_tvb;
  tvbuff_t *unique_id_tvb;
  tvbuff_t *payload_tvb;

  proto_tree *clnp_tree = NULL;
  proto_item *ti;

  guint version_major;
  guint version_minor;

  guint16 packet_length;
  guint packet_number;
  guint number_of_packets;
  gboolean stream_is_big_endian;

  miop_header_tvb = tvb_new_subset (tvb, 0, MIOP_HEADER_SIZE, -1);
  tvb_memcpy (miop_header_tvb, (guint8 *)&header, 0, MIOP_HEADER_SIZE );

  unique_id_len_tvb = tvb_new_subset (tvb, MIOP_HEADER_SIZE, 4, -1);
  tvb_memcpy (unique_id_len_tvb, (guint32 *)&(unique_id.id_len), 0, 4);

  unique_id_tvb = tvb_new_subset (tvb, MIOP_HEADER_SIZE + 4, unique_id.id_len, -1);
  /*unique_id.id = g_malloc(unique_id.id_len);*/
  unique_id.id = ep_alloc(unique_id.id_len);
  tvb_memcpy (unique_id_tvb, (guint8 *)(unique_id.id), 0, unique_id.id_len);

  payload_tvb = tvb_new_subset (tvb, MIOP_HEADER_SIZE + 4 + unique_id.id_len, -1, -1);


  if (check_col (pinfo->cinfo, COL_PROTOCOL)) {
    col_set_str (pinfo->cinfo, COL_PROTOCOL, MIOP_MAGIC);
  }

  /* Clear out stuff in the info column */
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_clear(pinfo->cinfo, COL_INFO);
  }

  /* Extract major and minor version numbers */ 
  version_major = ((header.hdr_version & 0xf0) >> 4);
  version_minor =  (header.hdr_version & 0x0f);

  if (header.hdr_version != 16)
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	{
	  col_add_fstr (pinfo->cinfo, COL_INFO, "Version %u.%u",
			version_major, version_minor);
	}
      if (tree)
	{
	  ti = proto_tree_add_item (tree, proto_miop, tvb, 0, -1, FALSE);
	  clnp_tree = proto_item_add_subtree (ti, ett_miop_hdr_version);
	  proto_tree_add_text (clnp_tree, miop_header_tvb, 0, -1,
			       "Version %u.%u not supported",
			       version_major, version_minor);
	}
      return;
    }

  stream_is_big_endian = ((header.flags & 0x01) == 0);

  if (stream_is_big_endian) {
    packet_length = pntohs (&header.packet_length);
    packet_number = pntohl (&header.packet_number);
    number_of_packets = pntohl (&header.number_of_packets);
  } 
  else {
    packet_length = pletohs (&header.packet_length);
    packet_number = pletohl (&header.packet_number);
    number_of_packets = pletohl (&header.number_of_packets);
  }



  if (check_col (pinfo->cinfo, COL_INFO))
  {
      col_add_fstr (pinfo->cinfo, COL_INFO, "MIOP %u.%u Packet s=%d (%u of %u)",
                    version_major, version_minor, header.packet_length, 
                    header.packet_number + 1, 
                    header.number_of_packets);
  }

  if (tree)
    {
      ti = proto_tree_add_item (tree, proto_miop, tvb, 0, -1, FALSE);
      clnp_tree = proto_item_add_subtree (ti, ett_miop_magic);
      proto_tree_add_text (clnp_tree, miop_header_tvb, offset, 4,
			   "Magic number: %s", MIOP_MAGIC);
      offset += 4;
      clnp_tree = proto_item_add_subtree (ti, ett_miop_hdr_version);
      proto_tree_add_text (clnp_tree, miop_header_tvb, offset, 1,
			   "Version: %u.%u", version_major, version_minor);
      offset++;
      clnp_tree = proto_item_add_subtree (ti, ett_miop_flags);
      proto_tree_add_text (clnp_tree, miop_header_tvb, offset, 1,
			   "Flags: 0x%02x (%s)", header.flags,
                           (stream_is_big_endian) ? "big-endian" : "little-endian");
      offset++;
      clnp_tree = proto_item_add_subtree (ti, ett_miop_packet_length);
      proto_tree_add_text (clnp_tree, miop_header_tvb, offset, 2,
			   "Packet length: %d", packet_length);
      offset += 2;
      clnp_tree = proto_item_add_subtree (ti, ett_miop_packet_number);
      proto_tree_add_text (clnp_tree, miop_header_tvb, offset, 4,
			   "Packet number: %d", packet_number);
      offset += 4;
      clnp_tree = proto_item_add_subtree (ti, ett_miop_number_of_packets);
      proto_tree_add_text (clnp_tree, miop_header_tvb, offset, 4,
			   "Number of packets: %d", number_of_packets);

      offset = 0;
      clnp_tree = proto_item_add_subtree (ti, ett_miop_unique_id_len);
      proto_tree_add_text (clnp_tree, unique_id_len_tvb, offset, 4,
			   "Unique Id length:  %d", unique_id.id_len);

      clnp_tree = proto_item_add_subtree (ti, ett_miop_unique_id);
      proto_tree_add_text (clnp_tree, unique_id_tvb, offset, unique_id.id_len,
			   "Unique Id: (string) %s",
                           make_printable_string(unique_id.id, unique_id.id_len));

      if (header.packet_number == 0) 
        /*  It is the first packet of the collection
            We can call to GIOP dissector to show more about this first 
            uncompleted GIOP message 
        */
        dissect_giop(payload_tvb, pinfo, tree);
    }


}


void proto_register_miop (void) {


  /* A header field is something you can search/filter on.
   * 
   * We create a structure to register our fields. It consists of an
   * array of hf_register_info structures, each of which are of the format
   * {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
   */
  static hf_register_info hf[] = {
    { &hf_miop_magic,
      { "Magic", "miop.magic", FT_UINT32, BASE_DEC, NULL, 0x0,
        "PacketHeader magic", HFILL }},
    { &hf_miop_hdr_version,
      { "Version", "miop.hdr_version", FT_UINT8, BASE_HEX, NULL, 0x0,
        "PacketHeader hdr_version", HFILL }},
    { &hf_miop_flags,
      { "Flags", "miop.flags", FT_UINT8, BASE_OCT, NULL, 0x0,
        "PacketHeader flags", HFILL }},
    { &hf_miop_packet_length,
      { "Length", "miop.packet_length", FT_UINT16, BASE_DEC, NULL, 0x0,
        "PacketHeader packet_length", HFILL }},
    { &hf_miop_packet_number,
      { "PacketNumber", "miop.packet_number",  FT_UINT32, BASE_DEC, NULL, 0x0,
        "PacketHeader packet_number", HFILL }},
    { &hf_miop_number_of_packets,
      { "NumberOfPackets", "miop.number_of_packets", FT_UINT32, BASE_DEC, NULL, 0x0,
        "PacketHeader number_of_packets", HFILL }},
    { &hf_miop_unique_id_len,
      { "UniqueIdLength", "miop.unique_id_len", FT_UINT32, BASE_DEC, NULL, 0x0,
        "UniqueId length", HFILL }},
    { &hf_miop_unique_id,
      { "UniqueId", "miop.unique_id", FT_STRING, BASE_NONE, NULL, 0x0,
        "UniqueId id", HFILL }},
  };


  static gint *ett[] = {
    &ett_miop_magic,
    &ett_miop_hdr_version,
    &ett_miop_flags,
    &ett_miop_packet_length,
    &ett_miop_packet_number,
    &ett_miop_number_of_packets,
    &ett_miop_unique_id_len,
    &ett_miop_unique_id,
  };

  proto_miop = proto_register_protocol("Unreliable Multicast Inter-ORB Protocol", "MIOP",
				       "miop");
  proto_register_field_array (proto_miop, hf, array_length (ett));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector("miop", dissect_miop, proto_miop);

}


void proto_reg_handoff_miop (void) {

  static gboolean initialized = FALSE;
  
  miop_handle = create_dissector_handle(dissect_miop, proto_miop);
  heur_dissector_add("udp", dissect_miop_heur, proto_miop);
    
  dissector_add_handle("udp.port", miop_handle); 
  initialized = TRUE;

  
}
