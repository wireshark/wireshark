/* packet-megaco.c
 * Routines for megaco packet disassembly
 * RFC 3015
 *
 * $Id: packet-megaco.c,v 1.4 2003/01/24 21:07:43 jmayer Exp $
 *
 * Christian Falckenberg, 2002/10/17
 * Copyright (c) 2002 by Christian Falckenberg
 *                       <christian.falckenberg@nortelnetworks.com>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "plugins/plugin_api.h"

#include "moduleinfo.h"

#include <stdio.h>
#include <stdlib.h>
#include <gmodule.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <epan/packet.h>
#include <epan/resolv.h>
#include "prefs.h"
#include <epan/strutil.h>
#include "sctpppids.h"

#include "plugins/plugin_api_defs.h"

#ifndef __ETHEREAL_STATIC__
G_MODULE_EXPORT const gchar version[] = VERSION;
#endif

#define PORT_MEGACO_TXT 2944
#define PORT_MEGACO_BIN 2945

void proto_reg_handoff_megaco(void);

/* Define the megaco proto */
static int proto_megaco = -1;

/* Define headers for megaco */
static int hf_megaco_version     = -1;
static int hf_megaco_mid         = -1;
static int hf_megaco_transaction = -1;
static int hf_megaco_transid     = -1;

/* Define the tree for megaco */
static int ett_megaco = -1;

/*
 * Here are the global variables associated with
 * the various user definable characteristics of the dissection
 *
 * MEGACO has two kinds of message formats: text and binary
 *
 * global_megaco_raw_text determines whether we are going to display
 * the raw text of the megaco message, much like the HTTP dissector does.
 *
 * global_megaco_dissect_tree determines whether we are going to display
 * a detailed tree that expresses a somewhat more semantically meaningful
 * decode.
 */
static int global_megaco_txt_tcp_port = PORT_MEGACO_TXT;
static int global_megaco_txt_udp_port = PORT_MEGACO_TXT;
#if 0
static int global_megaco_bin_tcp_port = PORT_MEGACO_BIN;
static int global_megaco_bin_udp_port = PORT_MEGACO_BIN;
#endif
static gboolean global_megaco_raw_text = TRUE;
static gboolean global_megaco_dissect_tree = TRUE;

/*
 * Variables to allow for proper deletion of dissector registration when
 * the user changes port from the gui.
 */
static int txt_tcp_port = 0;
static int txt_udp_port = 0;
#if 0
static int bin_tcp_port = 0;
static int bin_udp_port = 0;
#endif

/* Some basic utility functions that are specific to this dissector */
static gint tvb_skip_wsp(tvbuff_t* tvb, gint offset, gint maxlength);

/*
 * The various functions that either dissect some
 * subpart of MEGACO.  These aren't really proto dissectors but they
 * are written in the same style.
 */

/*
 * dissect_megaco_text - The dissector for the MEGACO Protocol, using
 * text encoding.
 */

static void
dissect_megaco_text(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint        tvb_len, len;
    gint        tvb_offset,tvb_current_offset,tvb_previous_offset, tokenlen;
    proto_tree  *megaco_tree, *ti;
    proto_item* (*my_proto_tree_add_string)(proto_tree*, int, tvbuff_t*, gint,
					  gint, const char*);
    guint8      word[7];
    gint        tvb_linebegin,tvb_lineend,linelen;

    /* Initialize variables */
    tvb_len             = tvb_length(tvb);
    megaco_tree         = NULL;
    ti                  = NULL;
    tvb_previous_offset = 0;
    tvb_current_offset  = 0;

    /*
     * Check to see whether we're really dealing with MEGACO by looking
     * for the MEGACO string.  This needs to be improved when supporting
     * binary encodings.
     */
    if(!tvb_get_nstringz0(tvb,0,6,word)) return;
    if (strncasecmp(word, "MEGACO", 6) != 0) return;

    /* Display MEGACO in protocol column */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
	col_add_str(pinfo->cinfo, COL_PROTOCOL, "MEGACO");
    
    /* Display transaction in info column */
    tvb_offset = tvb_find_guint8(tvb, 0, tvb_len, ' ');
    tvb_offset = tvb_find_guint8(tvb, tvb_offset, tvb_len, ' ');
    len = tvb_find_guint8(tvb, tvb_offset, tvb_len, '=') - tvb_offset;
    
    if (check_col(pinfo->cinfo, COL_INFO) )
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
		     tvb_format_text(tvb,tvb_offset,len));
	
    /* Build the info tree if we've been given a root */
    if (tree)
    {
	/* Create megaco subtree */
	ti = proto_tree_add_item(tree,proto_megaco,tvb,0,0, FALSE);
	megaco_tree = proto_item_add_subtree(ti, ett_megaco);

	if(global_megaco_dissect_tree)
	    my_proto_tree_add_string = proto_tree_add_string;
	else 
	    my_proto_tree_add_string = proto_tree_add_string_hidden;

	/* Find version */

	tvb_previous_offset = tvb_find_guint8(tvb, tvb_previous_offset,
					 tvb_len, '/') + 1;
	tvb_current_offset  = tvb_find_guint8(tvb, tvb_previous_offset,
					  tvb_len, ' ');

	tokenlen = tvb_current_offset - tvb_previous_offset;
	
	if (tree)
	    my_proto_tree_add_string(megaco_tree, hf_megaco_version, tvb,
				     tvb_previous_offset, tokenlen,
				     tvb_format_text(tvb, tvb_previous_offset,
						     tokenlen));
    

	/* Find mId (message originator identifier) */
	tvb_previous_offset = tvb_skip_wsp(tvb, tvb_current_offset,
					   tvb_len);
	tvb_current_offset  = tvb_find_guint8(tvb, tvb_previous_offset,
					      tvb_len, ' ');
	
	tokenlen = tvb_current_offset - tvb_previous_offset;

	my_proto_tree_add_string(megaco_tree, hf_megaco_mid, tvb,
				 tvb_previous_offset, tokenlen,
				 tvb_format_text(tvb, tvb_previous_offset,
						 tokenlen));
	/* Find transaction */
	tvb_previous_offset = tvb_skip_wsp(tvb, tvb_current_offset,
					   tvb_len);
	tvb_current_offset  = tvb_find_guint8(tvb, tvb_previous_offset,
					      tvb_len, '=');
    
	tokenlen = tvb_current_offset - tvb_previous_offset;

	my_proto_tree_add_string(megaco_tree, hf_megaco_transaction, tvb,
				 tvb_previous_offset, tokenlen,
				 tvb_format_text(tvb, tvb_previous_offset,
						 tokenlen));
	if (check_col(pinfo->cinfo, COL_INFO) )
	    col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
			 tvb_format_text(tvb,tvb_previous_offset,tokenlen));
	
	/* Find transaction id */
	tvb_previous_offset = tvb_skip_wsp(tvb, tvb_current_offset,
					   tvb_len) + 1;
	tvb_current_offset  = tvb_find_guint8(tvb, tvb_previous_offset,
					      tvb_len, '{');
	
	tokenlen = tvb_current_offset - tvb_previous_offset;

	my_proto_tree_add_string(megaco_tree, hf_megaco_transid, tvb,
				 tvb_previous_offset, tokenlen,
				 tvb_format_text(tvb, tvb_previous_offset,
						 tokenlen));
	
	/* and finally the whole message as raw text */

	if(global_megaco_raw_text){
	    tvb_linebegin = 0;

	    do {
		tvb_find_line_end(tvb,tvb_linebegin,-1,&tvb_lineend,FALSE);
		linelen = tvb_lineend - tvb_linebegin;
		proto_tree_add_text(tree, tvb, tvb_linebegin, linelen,
				    "%s", tvb_format_text(tvb,tvb_linebegin,
							  linelen));
		tvb_linebegin = tvb_lineend;
	    } while ( tvb_lineend < tvb_len );
	}
    }
}

/* Register all the bits needed with the filtering engine */

void
proto_register_megaco(void)
{
    static hf_register_info hf[] = {
	{ &hf_megaco_version,
	  { "Version", "megaco.version", FT_STRING, BASE_DEC, NULL, 0x0,
	    "MEGACO Version", HFILL }},
	{ &hf_megaco_mid,
	  { "mID", "megaco.mid", FT_STRING, BASE_DEC, NULL, 0x0,
	    "Message Originator", HFILL }},
	{ &hf_megaco_transaction,
	  { "Transaction", "megaco.transaction", FT_STRING, BASE_DEC, NULL, 0x0,
	    "Transaction type of this message", HFILL }},
	{ &hf_megaco_transid,
	  { "Transaction ID", "megaco.transid", FT_STRING, BASE_DEC, NULL, 0x0,
	    "Transaction ID of this message", HFILL }},
	/* Add more fields here */
    };
    static gint *ett[] = {
	&ett_megaco,
    };
    module_t *megaco_module;

    proto_megaco = proto_register_protocol("MEGACO",
					   "MEGACO", "megaco");

    proto_register_field_array(proto_megaco, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register our configuration options, particularly our ports */

    megaco_module = prefs_register_protocol(proto_megaco, proto_reg_handoff_megaco);

    prefs_register_uint_preference(megaco_module, "tcp.txt_port",
				   "MEGACO Text TCP Port",
				   "Set the TCP port for MEGACO text messages",
				   10, &global_megaco_txt_tcp_port);

    prefs_register_uint_preference(megaco_module, "udp.txt_port",
				   "MEGACO Text UDP Port",
				   "Set the UDP port for MEGACO text messages",
				   10, &global_megaco_txt_udp_port);

#if 0
    prefs_register_uint_preference(megaco_module, "tcp.bin_port",
				   "MEGACO Binary TCP Port",
				   "Set the TCP port for MEGACO binary messages",
				   10, &global_megaco_bin_tcp_port);

    prefs_register_uint_preference(megaco_module, "udp.bin_port",
				   "MEGACO Binary UDP Port",
				   "Set the UDP port for MEGACO binary messages",
				   10, &global_megaco_bin_udp_port);
#endif

    prefs_register_bool_preference(megaco_module, "display_raw_text",
				   "Display raw text for MEGACO message",
				   "Specifies that the raw text of the "
				   "MEGACO message should be displayed "
				   "instead of (or in addition to) the "
				   "dissection tree",
				   &global_megaco_raw_text);

    prefs_register_bool_preference(megaco_module, "display_dissect_tree",
				   "Display tree dissection for MEGACO message",
				   "Specifies that the dissection tree of the "
				   "MEGACO message should be displayed "
				   "instead of (or in addition to) the "
				   "raw text",
				   &global_megaco_dissect_tree);
}

/* The registration hand-off routine */
void
proto_reg_handoff_megaco(void)
{
    static int megaco_prefs_initialized = FALSE;
    static dissector_handle_t megaco_text_handle;

    /*
     * Get a handle for the SDP dissector.
     */
    if (!megaco_prefs_initialized) {
	megaco_text_handle = create_dissector_handle(dissect_megaco_text,
						     proto_megaco);
	megaco_prefs_initialized = TRUE;
    }
    else {
	dissector_delete("tcp.port", txt_tcp_port, megaco_text_handle);
	dissector_delete("udp.port", txt_udp_port, megaco_text_handle);
#if 0
	dissector_delete("tcp.port", bin_tcp_port, megaco_bin_handle);
	dissector_delete("udp.port", bin_udp_port, megaco_bin_handle);
#endif
    }

    /* Set our port number for future use */

    txt_tcp_port = global_megaco_txt_tcp_port;
    txt_udp_port = global_megaco_txt_udp_port;

#if 0
    bin_tcp_port = global_megaco_bin_tcp_port;
    bin_udp_port = global_megaco_bin_udp_port;
#endif

    dissector_add("tcp.port", global_megaco_txt_tcp_port, megaco_text_handle);
    dissector_add("udp.port", global_megaco_txt_udp_port, megaco_text_handle);
#if 0
    dissector_add("tcp.port", global_megaco_bin_tcp_port, megaco_bin_handle);
    dissector_add("udp.port", global_megaco_bin_udp_port, megaco_bin_handle);
#endif
    /* XXX - text or binary?  Does that depend on the port number? */
    dissector_add("sctp.ppi", H248_PAYLOAD_PROTOCOL_ID,   megaco_text_handle);
}

/*
 * tvb_skip_wsp - Returns the position in tvb of the first non-whitespace
 *                character following offset or offset + maxlength -1 whichever
 *                is smaller.
 *
 * Parameters:
 * tvb - The tvbuff in which we are skipping whitespace.
 * offset - The offset in tvb from which we begin trying to skip whitespace.
 * maxlength - The maximum distance from offset that we may try to skip
 * whitespace.
 *
 * Returns: The position in tvb of the first non-whitespace
 *          character following offset or offset + maxlength -1 whichever
 *          is smaller.
 */
static gint tvb_skip_wsp(tvbuff_t* tvb, gint offset, gint maxlength){
  gint counter = offset;
  gint end,tvb_len;
  guint8 tempchar;
  tvb_len = tvb_length(tvb);
  end = offset + maxlength;
  if(end >= tvb_len){
    end = tvb_len;
  }
  for(counter = offset; counter < end &&
	((tempchar = tvb_get_guint8(tvb,counter)) == ' ' ||
	tempchar == '\t');counter++);
  return (counter);
}


/* Start the functions we need for the plugin stuff */

#ifndef __ETHEREAL_STATIC__

G_MODULE_EXPORT void
plugin_reg_handoff(void){
    proto_reg_handoff_megaco();
}

G_MODULE_EXPORT void
plugin_init(plugin_address_table_t *pat
#ifndef PLUGINS_NEED_ADDRESS_TABLE
	    _U_
#endif
	    ){
/* initialise the table of pointers needed in Win32 DLLs */
    plugin_address_table_init(pat);
/* register the new protocol, protocol fields, and subtrees */
    if (proto_megaco == -1) { /* execute protocol initialization only once */
	proto_register_megaco();
    }
}

#endif

/* End the functions we need for plugin stuff */
