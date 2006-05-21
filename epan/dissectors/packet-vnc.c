/* packet-vnc.c
 * Routines for VNC dissection (Virtual Network Computing)
 * Copyright 2005, Ulf Lamping <ulf.lamping@web.de>
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

/* Dissection of the VNC (Virtual Network Computing) network traffic.
 *
 * Several VNC implementations available, see:
 * http://www.realvnc.com/
 * http://www.tightvnc.com/
 * http://ultravnc.sourceforge.net/
 * ...
 * 
 * The protocol itself is known as RFB - Remote Frame Buffer Protocol.
 *
 * Protocol specification:
 * http://www.realvnc.com/docs/rfbproto.pdf
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>

void proto_reg_handoff_vnc(void);

/* IF PROTO exposes code to other dissectors, then it must be exported
   in a header file. If not, a header file is not needed at all. */
/*#include "packet-PROTOABBREV.h"*/

static dissector_handle_t data_handle;

/* Initialize the protocol and registered fields */
static int proto_vnc = -1;
static int hf_vnc = -1;
static int hf_vnc_protocol_version = -1;

/* Global sample preference ("controls" display of numbers) */
/*static gboolean gPREF_HEX = FALSE;*/

/* Initialize the subtree pointers */
static gint ett_vnc = -1;

/* Code to actually dissect the packets */
static void
dissect_vnc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint offset = 0;
    gint length;
    guint8 *version;


/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *vnc_tree;

/* Make entries in Protocol column and Info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "VNC");
    
	if (check_col(pinfo->cinfo, COL_INFO)) 
		col_set_str(pinfo->cinfo, COL_INFO, "VNC");

/* A protocol dissector can be called in 2 different ways:

	(a) Operational dissection

		In this mode, Wireshark is only interested in the way protocols
		interact, protocol conversations are created, packets are reassembled
		and handed over to higher-level protocol dissectors.
		In this mode Wireshark does not build a so-called "protocol tree".

	(b) Detailed dissection

		In this mode, Wireshark is also interested in all details of a given
		protocol, so a "protocol tree" is created.

   Wireshark distinguishes between the 2 modes with the proto_tree pointer:
	(a) <=> tree == NULL
	(b) <=> tree != NULL

   In the interest of speed, if "tree" is NULL, avoid building a
   protocol tree and adding stuff to it, or even looking at any packet
   data needed only if you're building the protocol tree, if possible.

   Note, however, that you must fill in column information, create
   conversations, reassemble packets, build any other persistent state
   needed for dissection, and call subdissectors regardless of whether
   "tree" is NULL or not.  This might be inconvenient to do without
   doing most of the dissection work; the routines for adding items to
   the protocol tree can be passed a null protocol tree pointer, in
   which case they'll return a null item pointer, and
   "proto_item_add_subtree()" returns a null tree pointer if passed a
   null item pointer, so, if you're careful not to dereference any null
   tree or item pointers, you can accomplish this by doing all the
   dissection work.  This might not be as efficient as skipping that
   work if you're not building a protocol tree, but if the code would
   have a lot of tests whether "tree" is null if you skipped that work,
   you might still be better off just doing all that work regardless of
   whether "tree" is null or not. */
	if (tree) {

/* NOTE: The offset and length values in the call to
   "proto_tree_add_item()" define what data bytes to highlight in the hex
   display window when the line in the protocol tree display
   corresponding to that item is selected.

   Supplying a length of -1 is the way to highlight all data from the
   offset to the end of the packet. */

/* create display subtree for the protocol */
	ti = proto_tree_add_item(tree, proto_vnc, tvb, 0, -1, FALSE);
	vnc_tree = proto_item_add_subtree(ti, ett_vnc);

   /* this is a hideous first hack!!! */
   if(tvb_length_remaining(tvb, offset) == 12) {
        length = 12;
        version = tvb_get_ephemeral_string(tvb, offset, length);
        if(version[0] == 'R' && version[1] == 'F' && version[2] == 'B') {
            /* remove trailing \n */
            version[11] = '\0';
            proto_tree_add_string(vnc_tree, hf_vnc_protocol_version, tvb, offset,
	            length, version);
	        if (check_col(pinfo->cinfo, COL_INFO)) 
		        col_add_str(pinfo->cinfo, COL_INFO, version);
            offset += length;
        }
   }


/* Continue adding tree items to process the packet here */

		call_dissector(data_handle, tvb_new_subset(tvb, offset, -1, -1),
		    pinfo, vnc_tree);

	}

/* If this protocol has a sub-dissector call it here, see section 1.8 */
}


/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_vnc(void)
{                 
/*  module_t *vnc_module;*/

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
	{ &hf_vnc,
		{ "VNC", "vnc", FT_NONE, BASE_NONE, NULL, 0x0, "Virtual Network Computing", HFILL }},
    { &hf_vnc_protocol_version,
		{ "ProtocolVersion", "vnc.protocol_version", FT_STRING, BASE_NONE, NULL, 0x0, "Protocol Version", HFILL }
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_vnc,
	};

/* Register the protocol name and description */
	proto_vnc = proto_register_protocol("Virtual Network Computing",
	    "VNC", "vnc");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_vnc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
        
/* Register preferences module (See Section 2.6 for more on preferences) */       
/*        vnc_module = prefs_register_protocol(proto_vnc, proto_reg_handoff_vnc);*/
     
/* Register a sample preference */        
/*        prefs_register_bool_preference(vnc_module, "showHex", 
             "Display numbers in Hex",
	     "Enable to display numerical values in hexadecimal.",
	     &gPREF_HEX );        */
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This exact format is required because a script is used to find these routines 
   and create the code that calls these routines.
   
   This function is also called by preferences whenever "Apply" is pressed 
   (see prefs_register_protocol above) so it should accommodate being called 
   more than once.
*/
void
proto_reg_handoff_vnc(void)
{
        static gboolean inited = FALSE;
        
        if( !inited ) {

	dissector_handle_t vnc_handle;

	data_handle = find_dissector("data");

	vnc_handle = create_dissector_handle(dissect_vnc,
	    proto_vnc);

    /* XXX - we need a heuristic or at least a preference setting for this port */
	dissector_add("tcp.port", 5901, vnc_handle);
        
        inited = TRUE;
        }
        
        /* 
          If you perform registration functions which are dependant upon
          prefs the you should de-register everything which was associated
          with the previous settings and re-register using the new prefs settings
          here. In general this means you need to keep track of what value the
          preference had at the time you registered using a local static in this
          function. ie.

          static int currentPort = -1;

          if( -1 != currentPort ) {
              dissector_delete( "tcp.port", currentPort, PROTOABBREV_handle);
          }

          currentPort = gPortPref;

          dissector_add("tcp.port", currentPort, PROTOABBREV_handle);
            
        */
}

