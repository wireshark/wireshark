/* packet-postgresql.c
 * Routines for postgresql packet disassembly
 *
 * Copyright 2004, Edwin Calo <calo@fusemail.com>
 *
 * $Id: packet-postgresql.c,v 1.2 2004/02/17 10:03:47 jmayer Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

static int proto_postgresql = -1;
static int hf_postgresql_response = -1;
static int hf_postgresql_request = -1;
static int hf_postgresql_length = -1;
static int hf_postgresql_string_size = -1;
static int hf_postgresql_string = -1;
static int hf_postgresql_total_length = -1;
static int hf_postgresql_bitone = -1;
static int hf_postgresql_buff_remaining = -1;
static int hf_postgresql_opcode = -1;
static int hf_postgresql_idone = -1;
static gint ett_postgresql = -1;

#define TCP_PORT_POSTGRESQL	5432


static void
dissect_postgresql (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  proto_tree *postgresql_tree;
  proto_item *ti;
  gint offset = 0;
  gint buff_remaining = 0;

  guint8 *string;
  guint8 bitone;
  gint flag = 0;
  gint counter = 0;




  if (check_col (pinfo->cinfo, COL_PROTOCOL))
    col_set_str (pinfo->cinfo, COL_PROTOCOL, "POSTGRESQL");

  ti = proto_tree_add_item (tree, proto_postgresql, tvb, offset, -1, FALSE);
  postgresql_tree = proto_item_add_subtree (ti, ett_postgresql);

  buff_remaining = tvb_length_remaining (tvb, offset);

  if (check_col (pinfo->cinfo, COL_INFO))
    {
      col_add_str (pinfo->cinfo, COL_INFO,
		   (pinfo->match_port ==
		    pinfo->destport) ? " Request" : " Response");
    }

    counter=0;
    flag=0;
    while ( buff_remaining > 1 )
    {
         bitone = tvb_get_guint8 (tvb, offset);
         offset += 1;

         if(bitone > 0x7f || (bitone > 0x0 && bitone < 0x20) ) 
         {
	    if(counter > 3)
	    {
	      if(offset > counter)
	      {
                   offset -= counter;

                    /* Reading the string from the packet */
		    string = g_malloc( counter+1 );
		    tvb_memcpy(tvb,string,offset,counter);
                    string[counter]='\0';   /* Forcing end of string */
                    /* Printing the data */
                    proto_tree_add_string (tree,hf_postgresql_string,tvb, offset,counter, string );
                    if (check_col (pinfo->cinfo, COL_INFO)) { col_append_fstr (pinfo->cinfo, COL_INFO, " %s", string ); }
		    g_free(string);  /* Freeing up string */
                    string=NULL;

                   offset += counter;
	           counter=0;
	      }
	      else
	      {
	       counter=0;
	       offset+=1;
	      }
	    }
	    else
	    {
	     counter=0;
	     offset+=1;
	    }
         }

         if( bitone == 0 )
         {
                if(counter != 0)
                { 
                  if(offset > counter)
                  {
                   offset -= counter;
		   if( counter > 1)
		   {
                    /* Reading the string from the packet */
		    string = g_malloc( counter+1 );
		    tvb_memcpy(tvb,string,offset,counter);
                    string[counter]='\0';   /* Forcing end of string */
                    /* Printing the data */
                    proto_tree_add_string (tree,hf_postgresql_string,tvb, offset,counter, string );
                    if (check_col (pinfo->cinfo, COL_INFO)) { col_append_fstr (pinfo->cinfo, COL_INFO, " %s", string ); }
		    g_free(string);  /* Freeing up string */
                    string=NULL;

                   }
		   offset += counter;
                  }
                  counter = 0;
                }
                counter=0;
         }
         else
         {
             counter += 1;
         }

         buff_remaining = tvb_length_remaining (tvb, offset);
     }
} 


void proto_register_postgresql (void)
{

  static hf_register_info hf[] = {
    {&hf_postgresql_response,
     {"Response", "postgresql.response",
      FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      "TRUE if postgresql response", HFILL}},
    {&hf_postgresql_request,
     {"Request", "postgresql.request",
      FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      "TRUE if postgresql request", HFILL}},
    {&hf_postgresql_string, {"String", "hf_postgresql_string", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL}},
    {&hf_postgresql_length, {"Length", "hf_postgresql_length", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL}},
    {&hf_postgresql_string_size, {"Size", "hf_postgresql_string_size", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL}},
    {&hf_postgresql_total_length, {"TotalLength", "hf_postgresql_total_length", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL}},
    {&hf_postgresql_buff_remaining, {"Buffer Remaining", "hf_postgresql_buff_remaining", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL}},
    {&hf_postgresql_opcode, {"Op Code", "hf_postgresql_opcode", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL}},
    {&hf_postgresql_bitone, {"Bitone", "hf_postgresql_bitone", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL}},
    {&hf_postgresql_idone, {"idone", "hf_postgresql_idone", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL}},
 


  };

  static gint *ett[] = {
    &ett_postgresql,
  };

  proto_postgresql =
    proto_register_protocol ("POSTGRESQL", "POSTGRESQL", "postgresql");
  proto_register_field_array (proto_postgresql, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_postgresql (void)
{
  dissector_handle_t postgresql_handle;

  postgresql_handle =
    create_dissector_handle (dissect_postgresql, proto_postgresql);
  dissector_add ("tcp.port", TCP_PORT_POSTGRESQL, postgresql_handle);
}
