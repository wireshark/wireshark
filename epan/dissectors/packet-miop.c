/* packet-miop.c
 * Routines for CORBA MIOP packet disassembly
 * Significantly based on packet-giop.c
 * Copyright 2009 Alvaro Vega Garcia <avega at tid dot es>
 *
 * According with Unreliable Multicast Draft Adopted Specification
 * 2001 October (OMG)
 * Chapter 29: Unreliable Multicast Inter-ORB Protocol (MIOP)
 * http://www.omg.org/technology/documents/specialized_corba.htm
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

#include <errno.h>
#include <glib.h>
#include <math.h>

#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/expert.h>

#include "packet-giop.h"
#include "packet-tcp.h"

/*
 * Useful visible data/structs
 */

#define MIOP_MAX_UNIQUE_ID_LENGTH   252

#define MIOP_HEADER_SIZE 16

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

static gint ett_miop = -1;

#define MIOP_MAGIC   "MIOP"

static void dissect_miop (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree);

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

  proto_tree *miop_tree = NULL;
  proto_item *ti;

  guint8 hdr_version;
  guint version_major;
  guint version_minor;

  guint8 flags;

  guint16 packet_length;
  guint packet_number;
  guint number_of_packets;
  gboolean little_endian;

  guint32 unique_id_len;

  emem_strbuf_t *flags_strbuf = ep_strbuf_new_label("none");

  col_set_str (pinfo->cinfo, COL_PROTOCOL, MIOP_MAGIC);
  /* Clear out stuff in the info column */
  col_clear(pinfo->cinfo, COL_INFO);

  /* Extract major and minor version numbers */
  hdr_version = tvb_get_guint8(tvb, 4);
  version_major = ((hdr_version & 0xf0) >> 4);
  version_minor =  (hdr_version & 0x0f);

  if (hdr_version != 16)
    {
      col_add_fstr (pinfo->cinfo, COL_INFO, "Version %u.%u",
                    version_major, version_minor);
      if (tree)
        {
          ti = proto_tree_add_item (tree, proto_miop, tvb, 0, -1, FALSE);
          miop_tree = proto_item_add_subtree (ti, ett_miop);
          proto_tree_add_text (miop_tree, tvb, 0, -1,
                               "Version %u.%u",
                               version_major, version_minor);
          expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_WARN,
                               "MIOP version %u.%u not supported",
                               version_major, version_minor);
        }
      return;
    }

  flags = tvb_get_guint8(tvb, 5);
  little_endian = flags & 0x01;

  if (little_endian) {
    packet_length = tvb_get_letohs(tvb, 6);
    packet_number = tvb_get_letohl(tvb, 8);
    number_of_packets = tvb_get_letohl(tvb, 12);
    unique_id_len = tvb_get_letohl(tvb, 16);
  }
  else {
    packet_length = tvb_get_ntohs(tvb, 6);
    packet_number = tvb_get_ntohl(tvb, 8);
    number_of_packets = tvb_get_ntohl(tvb, 12);
    unique_id_len = tvb_get_ntohl(tvb, 16);
  }

  col_add_fstr (pinfo->cinfo, COL_INFO, "MIOP %u.%u Packet s=%d (%u of %u)",
                version_major, version_minor, packet_length,
                packet_number + 1,
                number_of_packets);

  if (tree)
    {

      ti = proto_tree_add_item (tree, proto_miop, tvb, 0, -1, FALSE);
      miop_tree = proto_item_add_subtree (ti, ett_miop);

      /* XXX - Should we bail out if we don't have the right magic number? */
      proto_tree_add_item(miop_tree, hf_miop_magic, tvb, offset, 4, FALSE);
      offset += 4;
      proto_tree_add_uint_format(miop_tree, hf_miop_hdr_version, tvb, offset, 1, hdr_version,
                                 "Version: %u.%u", version_major, version_minor);
      offset++;
      if (flags & 0x01) {
        ep_strbuf_printf(flags_strbuf, "little-endian");
      }
      if (flags & 0x02) {
        ep_strbuf_append_printf(flags_strbuf, "%s%s",
                                flags_strbuf->len ? ", " : "", "last message");
      }
      ti = proto_tree_add_uint_format_value(miop_tree, hf_miop_flags, tvb, offset, 1,
                                            flags, "0x%02x (%s)", flags, flags_strbuf->str);
      offset++;
      proto_tree_add_item(miop_tree, hf_miop_packet_length, tvb, offset, 2, little_endian);
      offset += 2;
      proto_tree_add_item(miop_tree, hf_miop_packet_number, tvb, offset, 4, little_endian);
      offset += 4;
      proto_tree_add_item(miop_tree, hf_miop_number_of_packets, tvb, offset, 4, little_endian);

      offset += 4;
      ti = proto_tree_add_item(miop_tree, hf_miop_unique_id_len, tvb, offset, 4, little_endian);

      if (unique_id_len >= MIOP_MAX_UNIQUE_ID_LENGTH) {
        expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_WARN,
                       "Unique Id length (%u) exceeds max value (%u)",
                       unique_id_len, MIOP_MAX_UNIQUE_ID_LENGTH);
        return;
      }

      offset += 4;
      proto_tree_add_item(miop_tree, hf_miop_unique_id, tvb, offset, unique_id_len,
                          little_endian);

      if (packet_number == 0) {
        /*  It is the first packet of the collection
            We can call to GIOP dissector to show more about this first
            uncompleted GIOP message
        */
        tvbuff_t *payload_tvb;

        offset += unique_id_len;
        payload_tvb = tvb_new_subset_remaining (tvb, offset);
        dissect_giop(payload_tvb, pinfo, tree);
      }
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
      { "Magic", "miop.magic", FT_STRING, BASE_NONE, NULL, 0x0,
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
      { "UniqueId", "miop.unique_id", FT_BYTES, BASE_NONE, NULL, 0x0,
        "UniqueId id", HFILL }},
  };


  static gint *ett[] = {
    &ett_miop
  };

  proto_miop = proto_register_protocol("Unreliable Multicast Inter-ORB Protocol", "MIOP",
                                       "miop");
  proto_register_field_array (proto_miop, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector("miop", dissect_miop, proto_miop);

}


void proto_reg_handoff_miop (void) {

  dissector_handle_t miop_handle;

  miop_handle = find_dissector("miop");
  dissector_add_handle("udp.port", miop_handle);    /* for 'Decode As' */

  heur_dissector_add("udp", dissect_miop_heur, proto_miop);

}
