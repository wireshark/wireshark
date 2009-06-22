/* packet-ziop.c
 * Routines for CORBA ZIOP packet disassembly
 * Significantly based on packet-giop.c
 * Copyright 2009 Alvaro Vega Garcia <avega at tid dot es>
 *
 * According with GIOP Compression RFP revised submission
 * OMG mars/2008-12-20
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
#include <epan/conversation.h>

#include "packet-ziop.h"
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

static int proto_ziop = -1;

/*
 * (sub)Tree declares
 */

static gint hf_ziop_magic = -1;
static gint hf_ziop_giop_version_major = -1;
static gint hf_ziop_giop_version_minor = -1;
static gint hf_ziop_flags = -1;
static gint hf_ziop_message_type = -1;
static gint hf_ziop_message_size = -1;
static gint hf_ziop_compressor_id = -1;
static gint hf_ziop_original_length = -1;

static gint ett_ziop_magic = -1;
static gint ett_ziop_giop_version_major = -1;
static gint ett_ziop_giop_version_minor = -1;
static gint ett_ziop_flags = -1;
static gint ett_ziop_message_type = -1;
static gint ett_ziop_message_size = -1;
static gint ett_ziop_compressor_id = -1;
static gint ett_ziop_original_length = -1;


static dissector_handle_t data_handle;
static dissector_handle_t ziop_tcp_handle;


static const value_string ziop_compressor_ids[] = {                              
  { 0, "None" },
  { 1, "GZIP"},
  { 2, "PKZIP"},
  { 3, "BZIP2"},
  { 4, "ZLIB"},
  { 5, "LZMA"},
  { 6, "LZOP"},
  { 7, "RZIP"},
  { 8, "7X"},
  { 9, "XAR"},
  { 0, NULL}
};


static const value_string giop_message_types[] = {
	{ 0x0, "Request" },
	{ 0x1, "Reply"},
	{ 0x2, "CancelRequest"},
	{ 0x3, "LocateRequest"},
	{ 0x4, "LocateReply"},
	{ 0x5, "CloseConnection"},
	{ 0x6, "MessageError"},
	{ 0x7, "Fragment"},
	{ 0, NULL}
};


gboolean ziop_desegment = TRUE;

static void dissect_ziop (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree);

static guint
get_ziop_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{

  ZIOPHeader header;
  guint message_size;
  gboolean stream_is_big_endian;

  if ( tvb_memeql(tvb, 0, ZIOP_MAGIC, 4) != 0)
    return 0;

  tvb_memcpy (tvb, (guint8 *)&header, offset, ZIOP_HEADER_SIZE);
  
  stream_is_big_endian =  ((header.flags & 0x1) == 0);
  
  if (stream_is_big_endian)
    message_size = pntohl (&header.message_size);
  else
    message_size = pletohl (&header.message_size);
  
  return message_size + ZIOP_HEADER_SIZE;
}


static void
dissect_ziop_tcp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree) {
  
  if ( tvb_memeql(tvb, 0, ZIOP_MAGIC ,4) != 0) {

    if ( tvb_memeql(tvb, 0, GIOP_MAGIC ,4) == 0)
      dissect_giop(tvb, pinfo, tree);

    return;
  }

  tcp_dissect_pdus(tvb, pinfo, tree, ziop_desegment, ZIOP_HEADER_SIZE,
                   get_ziop_pdu_len, dissect_ziop);
}


gboolean
dissect_ziop_heur (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree) {

  guint tot_len;

  conversation_t *conversation;
  /* check magic number and version */


  tot_len = tvb_length(tvb);


  if (tot_len < ZIOP_HEADER_SIZE) /* tot_len < 12 */
    {
      /* Not enough data captured to hold the ZIOP header; don't try
         to interpret it as GIOP. */
      return FALSE;
    }
  if ( tvb_memeql(tvb, 0, ZIOP_MAGIC, 4) != 0) {
    return FALSE;
  }

  if ( pinfo->ptype == PT_TCP )
    {
      /*
       * Make the ZIOP dissector the dissector for this conversation.
       *
       * If this isn't the first time this packet has been processed,
       * we've already done this work, so we don't need to do it
       * again.
       */
      if (!pinfo->fd->flags.visited)
        {
          conversation = find_conversation(pinfo->fd->num, &pinfo->src,
              &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
          if (conversation == NULL)
            {
              conversation = conversation_new(pinfo->fd->num, &pinfo->src,
                  &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
            }
          /* Set dissector */
          conversation_set_dissector(conversation, ziop_tcp_handle);
	}
      dissect_ziop_tcp (tvb, pinfo, tree);
    }
  else
    {
      dissect_ziop (tvb, pinfo, tree);
    }
  return TRUE;

}


/* Main entry point */
static void 
dissect_ziop (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree) {
  guint offset = 0;
  ZIOPHeader header;
  CompressionData compression_data;
  tvbuff_t *ziop_header_tvb;
  tvbuff_t *compression_data_tvb;
  tvbuff_t *payload_tvb;

  proto_tree *clnp_tree = NULL;
  proto_item *ti;

  gboolean stream_is_big_endian;
  guint32 message_size;
  guint32 original_len;
  guint16 compressor_id;

  ziop_header_tvb = tvb_new_subset (tvb, 0, ZIOP_HEADER_SIZE, -1);
  tvb_memcpy (ziop_header_tvb, (guint8 *)&header, 0, ZIOP_HEADER_SIZE );


  compression_data_tvb = tvb_new_subset (tvb, ZIOP_HEADER_SIZE, 8 , -1);
  tvb_memcpy (compression_data_tvb, (guint8 *)&compression_data, 0, 8 );

  payload_tvb = tvb_new_subset (tvb, ZIOP_HEADER_SIZE + 8, -1, -1);


  if (check_col (pinfo->cinfo, COL_PROTOCOL)) {
    col_set_str (pinfo->cinfo, COL_PROTOCOL, ZIOP_MAGIC);
  }

  /* Clear out stuff in the info column */
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_clear(pinfo->cinfo, COL_INFO);
  }



  if ( (header.giop_version_major != 1) || 
       (header.giop_version_minor != 2) ) /* > 2?? */
    {
      if (check_col (pinfo->cinfo, COL_INFO))
	{
	  col_add_fstr (pinfo->cinfo, COL_INFO, "Version %u.%u",
			header.giop_version_major, header.giop_version_minor);
	}
      if (tree)
	{
	  ti = proto_tree_add_item (tree, proto_ziop, tvb, 0, -1, FALSE);
	  clnp_tree = proto_item_add_subtree (ti, ett_ziop_giop_version_major);
	  proto_tree_add_text (clnp_tree, ziop_header_tvb, 0, -1,
			       "Version %u.%u not supported",
			       header.giop_version_major,
			       header.giop_version_minor);
	}
      call_dissector(data_handle, tvb, pinfo, tree);
      return;
    }

  stream_is_big_endian = ((header.flags & 0x01) == 0);

  if (stream_is_big_endian) {
    message_size = pntohl (&header.message_size);
    compressor_id = pntohs (&compression_data.compressor_id);
    original_len = pntohl (&compression_data.original_length);
  }
  else {
    message_size = pletohl (&header.message_size);
    compressor_id = pletohs (&compression_data.compressor_id);
    original_len = pletohl (&compression_data.original_length);
  }



  if (check_col (pinfo->cinfo, COL_INFO))
  {
      col_add_fstr (pinfo->cinfo, COL_INFO, "ZIOP %u.%u %s", 
                    header.giop_version_major, 
                    header.giop_version_minor,
                    val_to_str(header.message_type, giop_message_types,
                    	       "Unknown message type (0x%02x)")
                    );
  }

  if (tree)
    {
      ti = proto_tree_add_item (tree, proto_ziop, tvb, 0, -1, FALSE);

      clnp_tree = proto_item_add_subtree (ti, ett_ziop_magic);
      proto_tree_add_text (clnp_tree, ziop_header_tvb, offset, 4,
			   "Magic number: %s", ZIOP_MAGIC);
      offset += 4;
      clnp_tree = proto_item_add_subtree (ti, ett_ziop_giop_version_major);
      proto_tree_add_text (clnp_tree, ziop_header_tvb, offset, 1,
			   "Version major: %u", header.giop_version_major);
      offset++;
      clnp_tree = proto_item_add_subtree (ti, ett_ziop_giop_version_minor);
      proto_tree_add_text (clnp_tree, ziop_header_tvb, offset, 1,
			   "Version minor: %u", header.giop_version_minor);
      offset++;
      clnp_tree = proto_item_add_subtree (ti, ett_ziop_flags);
      proto_tree_add_text (clnp_tree, ziop_header_tvb, offset, 1,
			   "Flags: 0x%02x (%s)", header.flags, 
                           (stream_is_big_endian) ? "big-endian" : "little-endian");
      offset++;
      clnp_tree = proto_item_add_subtree (ti, ett_ziop_message_type);
      proto_tree_add_text (clnp_tree, ziop_header_tvb, offset, 1,
			   "Type: %s", 
                           val_to_str(header.message_type, giop_message_types, 
                                      "(0x%x)")
                           );
      offset++;
      clnp_tree = proto_item_add_subtree (ti, ett_ziop_message_size);
      proto_tree_add_text (clnp_tree, ziop_header_tvb, offset, 4,
			   "Size: %d", message_size);
      offset = 0;
      clnp_tree = proto_item_add_subtree (ti, ett_ziop_compressor_id);
      proto_tree_add_text (clnp_tree, compression_data_tvb, offset, 2,
			   "Compressor Id: %s" , 
                           val_to_str(compressor_id, ziop_compressor_ids, 
                                      "(0x%x)")
                           );
      offset += 4;
      clnp_tree = proto_item_add_subtree (ti, ett_ziop_original_length);
      proto_tree_add_text (clnp_tree, compression_data_tvb, offset, 4,
			   "Original length:  %d", original_len);


    }


}


void proto_register_ziop (void) {


  /* A header field is something you can search/filter on.
   * 
   * We create a structure to register our fields. It consists of an
   * array of hf_register_info structures, each of which are of the format
   * {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
   */
  static hf_register_info hf[] = {
    { &hf_ziop_magic,
      { "Header magic", "ziop.magic", FT_UINT32, BASE_DEC, NULL, 0x0,
        "ZIOPHeader magic", HFILL }},
    { &hf_ziop_giop_version_major,
      { "Header major version", "ziop.giop_version_major", FT_UINT8, BASE_OCT, NULL, 0x0,
        "ZIOPHeader giop_major_version", HFILL }},
    { &hf_ziop_giop_version_minor,
      { "Header minor version", "ziop.giop_version_minor", FT_UINT8, BASE_OCT, NULL, 0x0,
        "ZIOPHeader giop_minor_version", HFILL }},
    { &hf_ziop_flags,
      { "Header flags", "ziop.flags", FT_UINT8, BASE_OCT, NULL, 0x0,
        "ZIOPHeader flags", HFILL }},
    { &hf_ziop_message_type,
      { "Header type", "ziop.message_type", FT_UINT8, BASE_OCT, NULL, 0x0,
        "ZIOPHeader message_type", HFILL }},
    { &hf_ziop_message_size,
      { "Header size", "ziop.message_size",  FT_UINT32, BASE_DEC, NULL, 0x0,
        "ZIOPHeader message_size", HFILL }},
    { &hf_ziop_compressor_id,
      { "Header compressor id", "ziop.compressor_id", FT_UINT16, BASE_DEC, NULL, 0x0,
        "ZIOPHeader compressor_id", HFILL }},
    { &hf_ziop_original_length,
      { "Header original length", "ziop.original_length", FT_UINT32, BASE_DEC, NULL, 0x0,
        "ZIOP original_length", HFILL }},
  };


  static gint *ett[] = {
    &ett_ziop_magic,
    &ett_ziop_giop_version_major,
    &ett_ziop_giop_version_minor,
    &ett_ziop_flags,
    &ett_ziop_message_type,
    &ett_ziop_message_size,
    &ett_ziop_compressor_id,
    &ett_ziop_original_length
  };

  proto_ziop = proto_register_protocol("Zipped Inter-ORB Protocol", "ZIOP",
				       "ziop");
  proto_register_field_array (proto_ziop, hf, array_length (ett));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector("ziop", dissect_ziop, proto_ziop);

}


void proto_reg_handoff_ziop (void) {

  ziop_tcp_handle = create_dissector_handle(dissect_ziop_tcp, proto_ziop);
  dissector_add_handle("udp.port", ziop_tcp_handle);  /* For 'Decode As' */
  
  heur_dissector_add("tcp", dissect_ziop_heur, proto_ziop);

  data_handle = find_dissector("data");
}
