/* packet-megaco.c
* Routines for megaco packet disassembly
* RFC 3015
*
* $Id: packet-megaco.c,v 1.7 2003/07/08 17:42:24 guy Exp $
*
* Christian Falckenberg, 2002/10/17
* Copyright (c) 2002 by Christian Falckenberg
*                       <christian.falckenberg@nortelnetworks.com>
*
* Christoph Wiest,		2003/06/28
* Modified 2003 by		Christoph Wiest
*						<ch.wiest@tesionmail.de>
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
static int proto_megaco				= -1;

/* Define headers for megaco */
static int hf_megaco_version    	= -1;
static int hf_megaco_transaction   	= -1;
static int hf_megaco_transid    	= -1;
static int hf_megaco_Context		= -1;
static int hf_megaco_command_line	= -1;
static int hf_megaco_command		= -1;
static int hf_megaco_termid			= -1;



/* Define headers in subtree for megaco */
static int hf_megaco_modem_descriptor           = -1;
static int hf_megaco_multiplex_descriptor       = -1;
static int hf_megaco_media_descriptor			= -1;
static int hf_megaco_events_descriptor          = -1;
static int hf_megaco_signal_descriptor          = -1;
static int hf_megaco_audit_descriptor           = -1;
static int hf_megaco_servicechange_descriptor	= -1;
static int hf_megaco_digitmap_descriptor		= -1;
static int hf_megaco_statistics_descriptor		= -1;
static int hf_megaco_observedevents_descriptor	= -1;
static int hf_megaco_topology_descriptor		= -1;
static int hf_megaco_error_descriptor			= -1;
static int hf_megaco_TerminationState_descriptor= -1;
static int hf_megaco_Remote_descriptor 			= -1;
static int hf_megaco_Local_descriptor 			= -1;
static int hf_megaco_LocalControl_descriptor 	= -1;
static int hf_megaco_packages_descriptor		= -1;
static int hf_megaco_error_Frame				= -1;
static int hf_megaco_Service_State				= -1;
static int hf_megaco_Event_Buffer_Control		= -1;
static int hf_megaco_mode						= -1;
static int hf_megaco_reserve_group				= -1;
static int hf_megaco_reserve_value				= -1;
static int hf_megaco_streamid 					= -1;
static int hf_megaco_requestid 					= -1;
static int hf_megaco_pkgdname					= -1;

/* Define the trees for megaco */
static int ett_megaco 							= -1;
static int ett_megaco_command_line 				= -1;
static int ett_megaco_mediadescriptor			= -1;
static int ett_megaco_descriptors 				= -1;
static int ett_megaco_TerminationState			= -1;
static int ett_megaco_Localdescriptor			= -1;
static int ett_megaco_Remotedescriptor			= -1;
static int ett_megaco_LocalControldescriptor	= -1;
static int ett_megaco_auditdescriptor			= -1;
static int ett_megaco_eventsdescriptor			= -1;
static int ett_megaco_observedeventsdescriptor	= -1;
static int ett_megaco_observedevent				= -1;
static int ett_megaco_packagesdescriptor		= -1;
static int ett_megaco_requestedevent			= -1;
static int ett_megaco_signalsdescriptor			= -1;
static int ett_megaco_requestedsignal			= -1;

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
static gint tvb_skip_wsp(tvbuff_t* tvb, gint offset);
static gint tvb_skip_wsp_return(tvbuff_t* tvb, gint offset);
/*
* The various functions that either dissect some
* subpart of MEGACO.  These aren't really proto dissectors but they
* are written in the same style.
*
*/
static void
dissect_megaco_descriptors(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, gint tvb_descriptors_start_offset, gint tvb_descriptors_end_offset);
static void
dissect_megaco_modemdescriptor(tvbuff_t *tvb, proto_tree *tree, gint tvb_RBRKT, gint tvb_previous_offset);
static void
dissect_megaco_multiplexdescriptor(tvbuff_t *tvb, proto_tree *tree, gint tvb_RBRKT, gint tvb_previous_offset);
static void
dissect_megaco_mediadescriptor(tvbuff_t *tvb, proto_tree *tree,packet_info *pinfo, gint tvb_RBRKT, gint tvb_previous_offset);
static void
dissect_megaco_eventsdescriptor(tvbuff_t *tvb, proto_tree *tree, gint tvb_RBRKT, gint tvb_previous_offset);
static void
dissect_megaco_signaldescriptor(tvbuff_t *tvb, proto_tree *tree, gint tvb_RBRKT, gint tvb_previous_offset);
static void
dissect_megaco_auditdescriptor(tvbuff_t *tvb, proto_tree *tree,packet_info *pinfo, gint tvb_RBRKT, gint tvb_previous_offset);
static void
dissect_megaco_servicechangedescriptor(tvbuff_t *tvb, proto_tree *tree, gint tvb_RBRKT, gint tvb_previous_offset);
static void
dissect_megaco_digitmapdescriptor(tvbuff_t *tvb, proto_tree *tree, gint tvb_RBRKT, gint tvb_previous_offset);
static void
dissect_megaco_statisticsdescriptor(tvbuff_t *tvb, proto_tree *tree, gint tvb_RBRKT, gint tvb_previous_offset);
static void
dissect_megaco_observedeventsdescriptor(tvbuff_t *tvb, proto_tree *tree, gint tvb_RBRKT, gint tvb_previous_offset);
static void
dissect_megaco_topologydescriptor(tvbuff_t *tvb, proto_tree *tree, gint tvb_RBRKT, gint tvb_previous_offset);
static void
dissect_megaco_errordescriptor(tvbuff_t *tvb, proto_tree *tree, gint tvb_RBRKT, gint tvb_previous_offset);
static void
dissect_megaco_TerminationStatedescriptor(tvbuff_t *tvb, proto_tree *tree, gint tvb_next_offset, gint tvb_current_offset);
static void
dissect_megaco_Localdescriptor(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, gint tvb_next_offset, gint tvb_current_offset);
static void
dissect_megaco_Remotedescriptor(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, gint tvb_next_offset, gint tvb_current_offset);
static void
dissect_megaco_LocalControldescriptor(tvbuff_t *tvb, proto_tree *tree, gint tvb_next_offset, gint tvb_current_offset);
static void
dissect_megaco_Packagesdescriptor(tvbuff_t *tvb, proto_tree *tree, gint tvb_next_offset, gint tvb_current_offset);

static dissector_handle_t sdp_handle;

/*
* dissect_megaco_text - The dissector for the MEGACO Protocol, using
* text encoding.
*/

static void
dissect_megaco_text(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint		tvb_len, len;
	gint		tvb_offset,tvb_current_offset,tvb_previous_offset,tvb_next_offset,tokenlen;
	gint		tvb_command_start_offset, tvb_command_end_offset;
	gint		tvb_descriptors_start_offset, tvb_descriptors_end_offset;
	proto_tree  *megaco_tree, *megaco_tree_command_line, *ti, *sub_ti;
	proto_item* (*my_proto_tree_add_string)(proto_tree*, int, tvbuff_t*, gint, gint, const char*);
	
	guint8		word[7];
	guint8		transaction[30];
	guint8		TermID[30];
	guint8		tempchar;
	gint		tvb_RBRKT, tvb_LBRKT,  RBRKT_counter, LBRKT_counter;
	
	
	
	/* Initialize variables */
	tvb_len						= tvb_length(tvb);
	megaco_tree					= NULL;
	ti							= NULL;
	tvb_previous_offset			= 0;
	tvb_current_offset			= 0;
	tvb_next_offset				= 0;
	tvb_command_start_offset	= 0;
	tvb_command_end_offset		= 0;
	tvb_RBRKT					= 0;
	tvb_LBRKT					= 0;
	RBRKT_counter				= 0;
	LBRKT_counter				= 0;
	
	/*
	* Check to see whether we're really dealing with MEGACO by looking
	* for the "MEGACO" string or a "!".This needs to be improved when supporting
	* binary encodings.
	*/
	if(!tvb_get_nstringz0(tvb,0,sizeof(word),word)) return;
	if (strncasecmp(word, "MEGACO", 6) != 0 && tvb_get_guint8(tvb, 0 ) != '!') return;
	
	
	/* Display MEGACO in protocol column */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_add_str(pinfo->cinfo, COL_PROTOCOL, "MEGACO");
	
	
	/* Display transaction in info column
	* tvb_previous_offset ll be on the of the action */
	
	tvb_offset = tvb_find_guint8(tvb, 0, tvb_len, ':');
	tvb_current_offset = tvb_find_guint8(tvb, 0, tvb_len, '=');
	
	/* Transaction / TransactionResponseAck */
	if (tvb_find_guint8(tvb, 0, tvb_len, 'T') != -1 && tvb_find_guint8(tvb, 0, tvb_len, 'T') < tvb_current_offset)
		tvb_previous_offset = tvb_find_guint8(tvb, 0, tvb_len, 'T');
	
	/* Reply */
	if (tvb_find_guint8(tvb, 0, tvb_len, 'R') != -1 && tvb_find_guint8(tvb, 0, tvb_len, 'R') < tvb_current_offset) 
		tvb_previous_offset = tvb_find_guint8(tvb, 0, tvb_len, 'R');
	
	/* Pending */
	if (tvb_find_guint8(tvb, 0, tvb_len, 'P') != -1 && tvb_find_guint8(tvb, 0, tvb_len, 'P') < tvb_current_offset) 
		tvb_previous_offset = tvb_find_guint8(tvb, 0, tvb_len, 'P');
	
	/* ERROR */
	if (tvb_find_guint8(tvb, tvb_offset, tvb_len, 'E') != -1 && tvb_find_guint8(tvb, tvb_offset, tvb_len, 'E') < tvb_current_offset) 
		tvb_previous_offset = tvb_find_guint8(tvb, tvb_offset, tvb_len, 'E');
	
	len = tvb_current_offset - tvb_previous_offset;
	
	tvb_get_nstringz0(tvb,tvb_previous_offset,len+1,transaction);	
	
	tvb_offset = tvb_skip_wsp(tvb, tvb_current_offset +1);
	
	tvb_current_offset  = tvb_find_guint8(tvb, tvb_offset,
		tvb_len, '{');
	
	len = tvb_current_offset - tvb_offset;
	
	if (tvb_get_guint8(tvb, tvb_current_offset-1 ) == ' ')
		len--;
	
	
	if ( transaction[0] == 'T'){ 
		if (check_col(pinfo->cinfo, COL_INFO) )
			col_add_fstr(pinfo->cinfo, COL_INFO, "%s Request",
			tvb_format_text(tvb,tvb_offset,len));
	}
	if ( (transaction[0] == 'P' && transaction[1] != 'e') || transaction[0] == 'R'){ 
		if (check_col(pinfo->cinfo, COL_INFO) )
			col_add_fstr(pinfo->cinfo, COL_INFO, "%s Reply",
			tvb_format_text(tvb,tvb_offset,len));
	}
	if (  transaction[1] == 'N' || ( transaction[0] == 'P' && transaction[1] == 'e')){ 
		if (check_col(pinfo->cinfo, COL_INFO) )
			col_add_fstr(pinfo->cinfo, COL_INFO, "%s Pending",
			tvb_format_text(tvb,tvb_offset,len)); 
	}
	if ( transaction[0] == 'E'){ 
		if (check_col(pinfo->cinfo, COL_INFO) )
			col_add_fstr(pinfo->cinfo, COL_INFO, "Error"
			);
	}
	
	
	/* Build the info tree if we've been given a root */
	if (tree){
		/* Create megaco subtree */
		ti = proto_tree_add_item(tree,proto_megaco,tvb, 0, -1, FALSE);
		megaco_tree = proto_item_add_subtree(ti, ett_megaco);
		
		if(global_megaco_dissect_tree)
			my_proto_tree_add_string = proto_tree_add_string;
		else 
			my_proto_tree_add_string = proto_tree_add_string_hidden;
		
		/* Find version */
		tvb_previous_offset = tvb_find_guint8(tvb, 0,
			tvb_len, '/') + 1;
		
		tvb_current_offset  = tvb_find_guint8(tvb, tvb_previous_offset,
			tvb_len, ' ');
		
		tokenlen = tvb_current_offset - tvb_previous_offset;
		
		if (tree)
			my_proto_tree_add_string(megaco_tree, hf_megaco_version, tvb,
			tvb_previous_offset, tokenlen,
			tvb_format_text(tvb, tvb_previous_offset,
			tokenlen));
		
		/* Find transaction */
		tvb_offset = tvb_find_guint8(tvb, 0,
			tvb_len, ':');
		tvb_current_offset = tvb_find_guint8(tvb, 0,
			tvb_len, '=');
		
		/* Transaction / TransactionResponseAck */
		
		tvb_current_offset = tvb_find_guint8(tvb, 0,
			tvb_len, '=');
		
		tvb_previous_offset = tvb_find_guint8(tvb, tvb_offset, tvb_len, transaction[0]);
		
		tokenlen = tvb_current_offset - tvb_previous_offset;
		
		if (tvb_get_guint8(tvb, tvb_current_offset-1 ) == ' ')
			tokenlen--;
		
		if ( transaction[0] == 'T'){ 
			my_proto_tree_add_string(megaco_tree, hf_megaco_transaction, tvb,
				tvb_previous_offset, tokenlen,
				"Request" );
		}
		if (  (transaction[0] == 'P' && transaction[1] != 'e') || transaction[0] == 'R'){
			my_proto_tree_add_string(megaco_tree, hf_megaco_transaction, tvb,
				tvb_previous_offset, tokenlen,
				"Reply" );
		}
		if (  transaction[1] == 'N' || ( transaction[0] == 'P' && transaction[2] == 'n')){ 
			my_proto_tree_add_string(megaco_tree, hf_megaco_transaction, tvb,
				tvb_previous_offset, tokenlen,
				"Pending" );
		}
		
		
		if ( transaction[0] == 'E'){
			my_proto_tree_add_string(megaco_tree, hf_megaco_transaction, tvb,
				tvb_previous_offset, tokenlen,
				"Error" );
			
			tvb_offset = tvb_find_guint8(tvb, 0, tvb_len, '/');
			tvb_command_start_offset = tvb_find_guint8(tvb, tvb_offset, tvb_len, 'E');
			dissect_megaco_errordescriptor(tvb, megaco_tree, tvb_len-1, tvb_command_start_offset);
			return;
		}
		
		/* Find transaction id */
		
		tvb_previous_offset = tvb_skip_wsp(tvb, tvb_current_offset +1);
		
		tvb_current_offset  = tvb_find_guint8(tvb, tvb_previous_offset,
							  tvb_len, '{');
		
		tokenlen = tvb_current_offset - tvb_previous_offset;
		
		if (tvb_get_guint8(tvb, tvb_current_offset-1 ) == ' '){
			tokenlen--;
		}
		
		my_proto_tree_add_string(megaco_tree, hf_megaco_transid, tvb,
			tvb_previous_offset, tokenlen,
			tvb_format_text(tvb, tvb_previous_offset,
			tokenlen));
		
		/* Return if transaction = Pending */
		if ( transaction[0] == 'P' && ( transaction[1] == 'e' || transaction[1] == 'N')){
			return;
		}
		
		
		/* Return if there is an error */
		tvb_current_offset = tvb_skip_wsp(tvb, tvb_current_offset+1);
		tempchar = tvb_get_guint8(tvb, tvb_current_offset );
		
		if ( tempchar == 'E'){
			tvb_previous_offset = tvb_current_offset;
			
			tvb_current_offset = tvb_find_guint8(tvb, tvb_current_offset,
				tvb_len, '}');
			tvb_current_offset = tvb_find_guint8(tvb, tvb_current_offset+1,
				tvb_len, '}');
			
			tvb_current_offset = tvb_skip_wsp(tvb, tvb_current_offset-1);
			
			dissect_megaco_errordescriptor(tvb, megaco_tree, tvb_current_offset , tvb_previous_offset);
			
			return;
		}
		
		
		
		
		/* Find Context */
nextcontext:
		tvb_previous_offset = tvb_find_guint8(tvb, tvb_current_offset,
			tvb_len, '=')+1;
		tvb_previous_offset = tvb_skip_wsp(tvb, tvb_previous_offset);
		tvb_current_offset = tvb_find_guint8(tvb, tvb_previous_offset,
			tvb_len, '{');
		
		
		tokenlen = tvb_current_offset - tvb_previous_offset;
		tempchar = tvb_get_guint8(tvb, tvb_previous_offset );
		
		if (tvb_get_guint8(tvb, tvb_current_offset-1 ) == ' '){
			tokenlen--;
		}
		
		switch ( tempchar ){
		case '$':
			my_proto_tree_add_string(megaco_tree, hf_megaco_Context, tvb,
				tvb_previous_offset, 1,
				"Choose one");
			break;
		case '*':
			my_proto_tree_add_string(megaco_tree, hf_megaco_Context, tvb,
				tvb_previous_offset, 1,
				"All");
			break;
		case '-':
			proto_tree_add_text(megaco_tree, tvb, tvb_previous_offset, tokenlen, "Context: NULL" );
			break;
		default:		
			my_proto_tree_add_string(megaco_tree, hf_megaco_Context, tvb,
				tvb_previous_offset, tokenlen,
				tvb_format_text(tvb, tvb_previous_offset,
				tokenlen));
		}
		
		/* Find Commands */
		
		
		/* If transaction is ERROR the plugin will call the ERROR subroutine */
		if ( transaction[0] == 'E'){
			tvb_offset = tvb_find_guint8(tvb, 0, tvb_len, '/');
			tvb_command_start_offset = tvb_find_guint8(tvb, tvb_offset, tvb_len, 'E');
			dissect_megaco_errordescriptor(tvb, megaco_tree, tvb_len-1, tvb_command_start_offset);
			return;
		}
		
		else{
			
			/* If Transaction is is Request, Reply or Pending */
			
			tvb_command_start_offset = tvb_skip_wsp(tvb, tvb_current_offset +1);
			tvb_command_end_offset = tvb_command_start_offset;
			
			tvb_LBRKT = tvb_command_start_offset;
			tvb_RBRKT = tvb_command_start_offset;	
		}
		
		
		/* The following loop find the individual contexts, commands and call the for every Descriptor a subroutine */
		
		do {
			tvb_command_end_offset = tvb_find_guint8(tvb, tvb_command_end_offset +1,
				tvb_len, ',');
			
			if ( tvb_command_end_offset == -1 ){
				tvb_command_end_offset = tvb_len;
				
			} 
			
			/* checking how many left brackets are before the next comma */
			
			while ( tvb_find_guint8(tvb, tvb_LBRKT+1,tvb_len, '{') != -1 
				&& (tvb_find_guint8(tvb, tvb_LBRKT+1,tvb_len, '{') < tvb_command_end_offset)){
				
				tvb_LBRKT = tvb_find_guint8(tvb, tvb_LBRKT+1,
					tvb_len, '{');
				
				LBRKT_counter++;
			}
			
			/* checking how many right brackets are before the next comma */
			
			while ( (tvb_find_guint8(tvb, tvb_RBRKT+1,tvb_len, '}') != -1 )
				&& (tvb_find_guint8(tvb, tvb_RBRKT+1,tvb_len, '}') < tvb_command_end_offset)
				&& LBRKT_counter != 0){
				
				tvb_RBRKT = tvb_find_guint8(tvb, tvb_RBRKT+1,
					tvb_len, '}');
				RBRKT_counter++; 
				
				
			} 
			
			/* If equal or more right brackets before the comma, one command is complete */
			
			if ( LBRKT_counter <= RBRKT_counter ){
				
				tvb_current_offset  = tvb_find_guint8(tvb, tvb_command_start_offset,
					tvb_len, '{');
				
				
				/* includes no descriptors */
				
				if ( LBRKT_counter == 0 ){
					
					tvb_current_offset = tvb_command_end_offset;
					
					/* the last command in a context */
					
					if ( tvb_find_guint8(tvb, tvb_command_start_offset, tvb_len, '}') < tvb_current_offset
						&& tvb_find_guint8(tvb, tvb_command_start_offset, tvb_len, '}') != -1){
						
						tvb_previous_offset  = tvb_find_guint8(tvb, tvb_command_start_offset,
							tvb_len, '}');
						
						
						tvb_previous_offset = tvb_skip_wsp_return(tvb, tvb_previous_offset -1);
						
						tokenlen =  tvb_previous_offset - tvb_command_start_offset;
						
					}
					
					/* not the last command in a context*/
					
					else{
						tvb_current_offset = tvb_skip_wsp_return(tvb, tvb_current_offset -1);
						
						tokenlen =  tvb_current_offset - tvb_command_start_offset;
					}
				}
				
				/* command includes descriptors */
				
				else{
					tvb_current_offset = tvb_skip_wsp_return(tvb, tvb_current_offset -1);
					
					tokenlen =  tvb_current_offset - tvb_command_start_offset;
				}		
				
				/* if a next context is specified */
				
				if ( tvb_get_guint8(tvb, tvb_command_start_offset ) == 'C'){
					tvb_current_offset = tvb_command_start_offset;
					LBRKT_counter = 0;
					RBRKT_counter = 0;
					goto nextcontext;
				}
				
				/* creation of the megaco_tree_command_line additionally Command and Transaction ID will be printed in this line */
				
				sub_ti = proto_tree_add_item(megaco_tree,hf_megaco_command_line,tvb,tvb_command_start_offset,tokenlen, FALSE);
				megaco_tree_command_line = proto_item_add_subtree(sub_ti, ett_megaco_command_line);
				
				tvb_next_offset = tvb_command_start_offset + tokenlen;
				
				/* Additional value */
				
				if ( tvb_get_guint8(tvb, tvb_command_start_offset ) == 'O'){
					
					proto_tree_add_text(megaco_tree_command_line, tvb, tvb_command_start_offset, 2, "O- indicates an optional command" );
					tvb_command_start_offset = tvb_command_start_offset+2;
					
				}
				
				/* Additional value */
				
				if ( tvb_get_guint8(tvb, tvb_command_start_offset ) == 'W'){
					
					proto_tree_add_text(megaco_tree_command_line, tvb, tvb_command_start_offset, 2, "W- indicates a wildcarded response to a command" );
					tvb_command_start_offset = tvb_command_start_offset+2;
					
				}
				
				
				
				tvb_offset  = tvb_find_guint8(tvb, tvb_command_start_offset,
					tvb_len, '=');
				tvb_offset = tvb_skip_wsp_return(tvb, tvb_offset -1);
				tokenlen = tvb_offset - tvb_command_start_offset;
				
				tempchar = tvb_get_guint8(tvb, tvb_command_start_offset);
				
				
				if ( tempchar != 'E' ){
					
					if ( tvb_get_guint8(tvb, 0 ) == '!'){
						
						switch ( tempchar ){
							
						case 'A':
							
							tempchar = tvb_get_guint8(tvb, tvb_command_start_offset+1);
							
							switch ( tempchar ){
								
							case 'V':
								my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
									tvb_command_start_offset, tokenlen,
									"AuditValue");
								break;
								
							case 'C':
								my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
									tvb_command_start_offset, tokenlen,
									"AuditCapability");
								break;
								
							default:
								my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
									tvb_command_start_offset, tokenlen,
									"Add");
								break;
							}
							break;
							
							case 'N':
								my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
									tvb_command_start_offset, tokenlen,
									"Notify");
								break;
								
							case 'M':
								
								tempchar = tvb_get_guint8(tvb, tvb_command_start_offset+1);
								
								switch ( tempchar ){
								case 'F':
									my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
										tvb_command_start_offset, tokenlen,
										"Modify");
									break;
									
								case 'V':
									my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
										tvb_command_start_offset, tokenlen,
										"Move");
									break;
								}
								break;
								
								case 'S':
									
									tempchar = tvb_get_guint8(tvb, tvb_command_start_offset+1);
									
									switch ( tempchar ){
										
									case 'C':
										my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
											tvb_command_start_offset, tokenlen,
											"ServiceChange");
										break;
										
									default:
										my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
											tvb_command_start_offset, tokenlen,
											"Subtract");
										break;
									}			
									break;
									
									default:
										tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;
										proto_tree_add_string(megaco_tree, hf_megaco_error_Frame, tvb,
											tvb_previous_offset, tokenlen,
											"No Command detectable !");
										return;
										
										break;
						}
					}
					else{
						my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_command, tvb,
							tvb_command_start_offset, tokenlen,
							tvb_format_text(tvb, tvb_command_start_offset,
							tokenlen));
					}
					
					
					tvb_offset  = tvb_find_guint8(tvb, tvb_command_start_offset,
						tvb_len, '=');			
					tvb_offset = tvb_skip_wsp(tvb, tvb_offset+1);
					tokenlen = tvb_next_offset - tvb_offset;
					
					tempchar = tvb_get_guint8(tvb, tvb_offset);
					
					switch ( tempchar ){
						
					case 'E':
						tvb_get_nstringz0(tvb,tvb_offset,tokenlen+1,TermID);
						TermID[0] = 'e';
						my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_termid, tvb,
							tvb_offset, tokenlen,
							TermID);
						break;
						
					case '*':
						my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_termid, tvb,
							tvb_offset, tokenlen,
							"WildCard all");
						break;
						
					case '$':
						my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_termid, tvb,
							tvb_offset, tokenlen,
							"WildCard any");
						break;
						
					default:
						my_proto_tree_add_string(megaco_tree_command_line, hf_megaco_termid, tvb,
							tvb_offset, tokenlen,
							tvb_format_text(tvb, tvb_offset,
							tokenlen));
						break;
					}
					
			}
			/* Dissect the Descriptors */
			
			
			if ( LBRKT_counter != 0 && tvb_current_offset != tvb_command_end_offset){
				
				tvb_descriptors_start_offset  = tvb_find_guint8(tvb, tvb_command_start_offset,
					tvb_len, '{');
				
				tvb_descriptors_end_offset = tvb_descriptors_start_offset;
				
				
				while ( LBRKT_counter > 0 ){
					
					tvb_descriptors_end_offset = tvb_find_guint8(tvb, tvb_descriptors_end_offset+1,
						tvb_len, '}');
					
					LBRKT_counter--;
					
				}
				
				tempchar = tvb_get_guint8(tvb, tvb_command_start_offset);
				
				if ( tempchar == 'E'){
					dissect_megaco_descriptors(tvb, megaco_tree_command_line, pinfo, tvb_command_start_offset-1,tvb_descriptors_end_offset);
				}
				else {
					dissect_megaco_descriptors(tvb, megaco_tree_command_line, pinfo, tvb_descriptors_start_offset,tvb_descriptors_end_offset);	
				}	
			}
			RBRKT_counter = 0;
			LBRKT_counter = 0;
			tvb_command_start_offset = tvb_skip_wsp(tvb, tvb_command_end_offset +1);
			tvb_LBRKT = tvb_command_start_offset;
			tvb_RBRKT = tvb_command_start_offset;
			
			}
		} while ( tvb_command_end_offset < tvb_len );
	}
}

static void
dissect_megaco_descriptors(tvbuff_t *tvb, proto_tree *megaco_tree_command_line, packet_info *pinfo, gint tvb_descriptors_start_offset, gint tvb_descriptors_end_offset)
{
	gint		tvb_len, len;
	gint		tvb_current_offset,tvb_previous_offset,tokenlen;
	gint		tvb_RBRKT, tvb_LBRKT,  RBRKT_counter, LBRKT_counter;
	guint8	  tempchar;
	tvb_len  	= tvb_length(tvb);


	len				= 0;
	tvb_RBRKT		= 0;
	tvb_LBRKT		= 0;
	RBRKT_counter	= 0;
	LBRKT_counter	= 0;

	
	tokenlen = tvb_descriptors_end_offset - tvb_descriptors_start_offset;
	
	
	tvb_LBRKT = tvb_skip_wsp(tvb, tvb_descriptors_start_offset +1);
	
	tvb_previous_offset = tvb_LBRKT;
	tvb_RBRKT = tvb_descriptors_start_offset;
	
	
	
	do {
		
		
		tvb_RBRKT = tvb_find_guint8(tvb, tvb_RBRKT+1,
			tvb_len, '}');
		tvb_LBRKT = tvb_find_guint8(tvb, tvb_LBRKT,
			tvb_len, '{');
		
		tvb_current_offset 	= tvb_find_guint8(tvb, tvb_previous_offset,
			tvb_len, ',');
		
		if (tvb_current_offset == -1 ){
			tvb_current_offset = tvb_descriptors_end_offset;
			
		}
		
		
		
		/* Descriptor includes no parameters */
		
		if ( tvb_LBRKT > tvb_current_offset || tvb_LBRKT == -1 ){
			
			if ( tvb_current_offset > tvb_RBRKT ){
				tvb_current_offset = tvb_RBRKT;
			}
			
			tvb_RBRKT = tvb_skip_wsp_return(tvb, tvb_current_offset-1)-1;
		}
		
		/* Descriptor includes Parameters */
		if ( (tvb_current_offset > tvb_LBRKT && tvb_LBRKT != -1)){
			
			while ( tvb_LBRKT != -1 && tvb_RBRKT > tvb_LBRKT ){
				
				
				tvb_LBRKT  = tvb_find_guint8(tvb, tvb_LBRKT+1,
					tvb_len, '{');
				if ( tvb_LBRKT < tvb_RBRKT && tvb_LBRKT != -1)
					tvb_RBRKT  = tvb_find_guint8(tvb, tvb_RBRKT+1,
					tvb_len, '}');
				
				
			}
			
		}
		
		
		tempchar = tvb_get_guint8(tvb, tvb_previous_offset );
		
		switch ( tempchar ){
			
		case 'M':
			tempchar = tvb_get_guint8(tvb, tvb_previous_offset+1 );
			switch ( tempchar ){
				
			case 'o':
				dissect_megaco_modemdescriptor(tvb, megaco_tree_command_line, tvb_RBRKT, tvb_previous_offset);
				break;
				
			case 'D':
				dissect_megaco_modemdescriptor(tvb, megaco_tree_command_line, tvb_RBRKT, tvb_previous_offset);
				break;
				
			case 'u':
				dissect_megaco_multiplexdescriptor(tvb, megaco_tree_command_line, tvb_RBRKT, tvb_previous_offset);
				break;
				
			case 'X':
				dissect_megaco_multiplexdescriptor(tvb, megaco_tree_command_line, tvb_RBRKT, tvb_previous_offset);
				break;
				
			case 'e':
				dissect_megaco_mediadescriptor(tvb, megaco_tree_command_line, pinfo, tvb_RBRKT, tvb_previous_offset);
				break;
				
			default: 
				dissect_megaco_mediadescriptor(tvb, megaco_tree_command_line, pinfo, tvb_RBRKT, tvb_previous_offset);
				break;
			}
			break;
			
			case 'S':
				tempchar = tvb_get_guint8(tvb, tvb_previous_offset+1 );
				switch ( tempchar ){
					
				case 'i':
					dissect_megaco_signaldescriptor(tvb, megaco_tree_command_line, tvb_RBRKT, tvb_previous_offset);
					break;
					
				case 'G':
					dissect_megaco_signaldescriptor(tvb, megaco_tree_command_line, tvb_RBRKT, tvb_previous_offset);
					break;
					
				case 'e':
					dissect_megaco_servicechangedescriptor(tvb, megaco_tree_command_line, tvb_RBRKT, tvb_previous_offset);
					break;
					
				case 'C':
					dissect_megaco_servicechangedescriptor(tvb, megaco_tree_command_line, tvb_RBRKT, tvb_previous_offset);
					break;
					
				case 't':
					dissect_megaco_statisticsdescriptor(tvb, megaco_tree_command_line, tvb_RBRKT, tvb_previous_offset);
					break;
					
				case 'A':
					dissect_megaco_statisticsdescriptor(tvb, megaco_tree_command_line, tvb_RBRKT, tvb_previous_offset);
					break;
				default:
					tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;
					proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_Frame, tvb,
						tvb_previous_offset, tokenlen,
						"No Descriptor detectable !");
					break;	
				}
				break;
				
				case 'E':
					tempchar = tvb_get_guint8(tvb, tvb_previous_offset+1 );
					if ( tempchar == 'r' || tempchar == 'R'){
						
						if (  tvb_get_guint8(tvb, tvb_skip_wsp(tvb, tvb_RBRKT +1)) == ';'){
							tvb_RBRKT = tvb_find_guint8(tvb, tvb_RBRKT+1, tvb_len, '}');
							tvb_RBRKT = tvb_skip_wsp_return(tvb, tvb_RBRKT -1)-1;
						}
						
						dissect_megaco_errordescriptor(tvb, megaco_tree_command_line, tvb_RBRKT, tvb_previous_offset);
					}
					else{
						dissect_megaco_eventsdescriptor(tvb, megaco_tree_command_line, tvb_RBRKT, tvb_previous_offset);
					}
					break;
					
				case 'A':
					dissect_megaco_auditdescriptor(tvb, megaco_tree_command_line, pinfo, tvb_RBRKT, tvb_previous_offset);
					break;
					
				case 'D':
					dissect_megaco_digitmapdescriptor(tvb, megaco_tree_command_line, tvb_RBRKT, tvb_previous_offset);
					break;
					
				case 'O':
					dissect_megaco_observedeventsdescriptor(tvb, megaco_tree_command_line, tvb_RBRKT, tvb_previous_offset);
					break;
					
				case 'T':
					dissect_megaco_topologydescriptor(tvb, megaco_tree_command_line, tvb_RBRKT, tvb_previous_offset);
					break;
				case 'P':
					dissect_megaco_Packagesdescriptor(tvb, megaco_tree_command_line, tvb_RBRKT, tvb_previous_offset);
					break;
					
				default:
					tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;
					proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_Frame, tvb,
						tvb_previous_offset, tokenlen,
						"No Descriptor detectable !");
					break;	
					
	}
	
	
	tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;    	
	
	tvb_current_offset  	= tvb_find_guint8(tvb, tvb_RBRKT,
		tvb_len, ',');
	if (tvb_current_offset == -1 ){
		tvb_current_offset = tvb_descriptors_end_offset;
	}
	tvb_previous_offset = tvb_skip_wsp(tvb, tvb_current_offset+1);
	tvb_LBRKT = tvb_previous_offset;	
	tvb_RBRKT = tvb_previous_offset;
	
	
	} while ( tvb_current_offset < tvb_descriptors_end_offset );
	
}

static void
dissect_megaco_modemdescriptor(tvbuff_t *tvb, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset)
{
	
	gint 	tokenlen;

	tokenlen = 0;

	
	
	tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;
	proto_tree_add_string(megaco_tree_command_line, hf_megaco_modem_descriptor, tvb,
					 		tvb_previous_offset, tokenlen,
							tvb_format_text(tvb, tvb_previous_offset,
							tokenlen));
	
}
static void
dissect_megaco_multiplexdescriptor(tvbuff_t *tvb, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset)
{
	
	gint 	tokenlen;

	tokenlen = 0;
	
	tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;
	proto_tree_add_string(megaco_tree_command_line, hf_megaco_multiplex_descriptor, tvb,
					 		tvb_previous_offset, tokenlen,
							tvb_format_text(tvb, tvb_previous_offset,
							tokenlen));
	
}
static void
dissect_megaco_mediadescriptor(tvbuff_t *tvb, proto_tree *megaco_tree_command_line,packet_info *pinfo,  gint tvb_RBRKT, gint tvb_previous_offset)
{
	
	gint 	tokenlen;
	gint	tvb_next_offset, tvb_current_offset, tvb_offset, tvb_help_offset;
	guint8	tempchar;
	

	proto_tree  *megaco_mediadescriptor_tree, *megaco_mediadescriptor_ti;

	tokenlen			= 0;
	tvb_next_offset		= 0;
	tvb_current_offset	= 0;
	tvb_offset			= 0;
	tvb_help_offset		= 0;
	
	tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;	
	
	
	megaco_mediadescriptor_ti = proto_tree_add_item(megaco_tree_command_line,hf_megaco_media_descriptor,tvb,tvb_previous_offset,tokenlen, FALSE);
	megaco_mediadescriptor_tree = proto_item_add_subtree(megaco_mediadescriptor_ti, ett_megaco_mediadescriptor);
	
	tvb_current_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_RBRKT, '=');
	tvb_next_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_RBRKT, '{');
	
	/* If a StreamID is present */
	
	if ( tvb_find_guint8(tvb, tvb_next_offset+1, tvb_RBRKT, '{') > tvb_current_offset && tvb_current_offset > tvb_previous_offset ){
		tvb_next_offset = tvb_find_guint8(tvb, tvb_next_offset+1, tvb_RBRKT, '{');
		tvb_current_offset = tvb_skip_wsp(tvb, tvb_current_offset +1);
		
		tvb_offset = tvb_skip_wsp_return(tvb, tvb_next_offset-2);
		tokenlen =  tvb_offset - tvb_current_offset;
		
		proto_tree_add_string(megaco_mediadescriptor_tree, hf_megaco_streamid, tvb,
			tvb_current_offset, tokenlen,
			tvb_format_text(tvb, tvb_current_offset,
			tokenlen));
	} 
	tvb_current_offset = tvb_next_offset ;
	
	
	
	while ( tvb_find_guint8(tvb, tvb_current_offset+1 , tvb_RBRKT, '{') != -1 && tvb_find_guint8(tvb, tvb_current_offset+1 , tvb_RBRKT, '{') < tvb_RBRKT && tvb_next_offset != -1){
		
		tvb_help_offset = tvb_next_offset;
		tvb_current_offset = tvb_find_guint8(tvb, tvb_current_offset+1 , tvb_RBRKT, '{');
		tvb_next_offset = tvb_find_guint8(tvb, tvb_current_offset+1 , tvb_RBRKT, '}');
		tvb_offset = tvb_skip_wsp_return(tvb, tvb_current_offset-1)-1;
		
		tvb_next_offset = tvb_skip_wsp_return(tvb, tvb_next_offset-1);
		tvb_current_offset = tvb_skip_wsp(tvb, tvb_current_offset +1);
		
		
		
		tempchar = tvb_get_guint8(tvb, tvb_offset);
		
		switch ( tempchar ){
			
		case 'R':
			/* Remote Descriptor in short message encoding */
			dissect_megaco_Remotedescriptor(tvb,megaco_mediadescriptor_tree, pinfo, tvb_next_offset, tvb_current_offset);
			break;
			
		case 'L':
			/* Local Descriptor in short message encoding */
			dissect_megaco_Localdescriptor(tvb,megaco_mediadescriptor_tree , pinfo, tvb_next_offset, tvb_current_offset);
			break;
			
		case 'O':
			/* Local Control Descriptor in short message encoding */
			dissect_megaco_LocalControldescriptor(tvb,megaco_mediadescriptor_tree , tvb_next_offset, tvb_current_offset);
			break;
			
		case 'S':
			/* Termination State Descriptor in short message encoding */
			dissect_megaco_TerminationStatedescriptor(tvb,megaco_mediadescriptor_tree , tvb_next_offset, tvb_current_offset);
			break;
			
		case 'l':
			/* Local or Local Control Descriptor in long message encoding */
			if (tvb_get_guint8(tvb, tvb_offset-1) == 'a'){
				dissect_megaco_Localdescriptor(tvb,megaco_mediadescriptor_tree , pinfo, tvb_next_offset, tvb_current_offset);
			}
			else{
				dissect_megaco_LocalControldescriptor(tvb,megaco_mediadescriptor_tree , tvb_next_offset, tvb_current_offset);
			}
			break;
			
		case 'e':
			/* Remote or Termination State Descriptor in long message encoding */
			
			if (tvb_get_guint8(tvb, tvb_offset-2) == 'a'){
				dissect_megaco_TerminationStatedescriptor(tvb,megaco_mediadescriptor_tree , tvb_next_offset, tvb_current_offset);
			}
			else {
				dissect_megaco_Remotedescriptor(tvb,megaco_mediadescriptor_tree , pinfo, tvb_next_offset, tvb_current_offset);
			}
			
			break;
			
		default:
			
			if ( tvb_find_guint8(tvb, tvb_help_offset, tvb_RBRKT, '{') > tvb_find_guint8(tvb, tvb_help_offset, tvb_RBRKT, '=')){
				
				tvb_help_offset = tvb_find_guint8(tvb, tvb_help_offset, tvb_RBRKT, '=');
				tvb_help_offset = tvb_skip_wsp(tvb, tvb_help_offset +1);
				
				tokenlen = tvb_offset - tvb_help_offset + 1;
				
				proto_tree_add_string(megaco_mediadescriptor_tree, hf_megaco_streamid, tvb,
					tvb_help_offset, tokenlen,
					tvb_format_text(tvb, tvb_help_offset,
					tokenlen));
				
			}
			else {
				tokenlen =  (tvb_RBRKT+1) - tvb_offset;
				proto_tree_add_string(megaco_mediadescriptor_tree, hf_megaco_error_Frame, tvb,
					tvb_offset, tokenlen,
					"No Descriptor detectable !");
			}
			break;	
			
		}	
	}
	
}
static void
dissect_megaco_eventsdescriptor(tvbuff_t *tvb, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset)
{
	
	gint tokenlen, tvb_current_offset, tvb_next_offset, tvb_help_offset;
	gint tvb_events_end_offset, tvb_events_start_offset, tvb_LBRKT;
	proto_tree  *megaco_eventsdescriptor_tree, *megaco_eventsdescriptor_ti;
	
	guint8 tempchar;
	gint requested_event_start_offset, requested_event_end_offset;
	proto_tree	*megaco_requestedevent_tree, *megaco_requestedevent_ti;
	
	tokenlen						= 0;
	tvb_current_offset				= 0;
	tvb_next_offset					= 0;
	tvb_help_offset					= 0;
	tvb_events_end_offset			= 0;
	tvb_events_start_offset			= 0;	
	tvb_help_offset					= 0;
	requested_event_start_offset	= 0;
	requested_event_end_offset		= 0;
	
	tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;
	
	megaco_eventsdescriptor_ti = proto_tree_add_item(megaco_tree_command_line,hf_megaco_events_descriptor,tvb,tvb_previous_offset,tokenlen, FALSE);
	megaco_eventsdescriptor_tree = proto_item_add_subtree(megaco_eventsdescriptor_ti, ett_megaco_eventsdescriptor);
	
	
	
	tvb_current_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_RBRKT, '=');
	tvb_next_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_RBRKT, '{');
	
	if ( tvb_current_offset < tvb_RBRKT && tvb_current_offset != -1 ){
		
		tvb_current_offset = tvb_skip_wsp(tvb, tvb_current_offset +1);
		tvb_help_offset = tvb_skip_wsp_return(tvb, tvb_next_offset-1);
		
		tokenlen =  tvb_help_offset - tvb_current_offset;
		
		proto_tree_add_string(megaco_eventsdescriptor_tree, hf_megaco_requestid, tvb,
			tvb_current_offset, tokenlen,
			tvb_format_text(tvb, tvb_current_offset,
			tokenlen));
		
		tvb_events_end_offset   = tvb_RBRKT;
		tvb_events_start_offset = tvb_previous_offset;
		
		tvb_RBRKT = tvb_next_offset+1;
		tvb_LBRKT = tvb_next_offset+1;
		tvb_previous_offset = tvb_skip_wsp(tvb, tvb_next_offset+1);
		
		
		do {
			
			tvb_RBRKT = tvb_find_guint8(tvb, tvb_RBRKT+1,
				tvb_events_end_offset, '}');
			tvb_LBRKT = tvb_find_guint8(tvb, tvb_LBRKT,
				tvb_events_end_offset, '{');
			
			tvb_current_offset 	= tvb_find_guint8(tvb, tvb_previous_offset,
				tvb_events_end_offset, ',');
			
			if (tvb_current_offset == -1 || tvb_current_offset > tvb_events_end_offset){
				tvb_current_offset = tvb_events_end_offset;
			}
			
			
			/* Descriptor includes no parameters */
			
			if ( tvb_LBRKT > tvb_current_offset || tvb_LBRKT == -1 ){
				
				tvb_RBRKT = tvb_skip_wsp_return(tvb, tvb_current_offset-1)-1;
			}
			
			/* Descriptor includes Parameters */
			
			if ( (tvb_current_offset > tvb_LBRKT && tvb_LBRKT != -1)){
				
				while ( tvb_LBRKT != -1 && tvb_RBRKT > tvb_LBRKT ){
					
					tvb_LBRKT  = tvb_find_guint8(tvb, tvb_LBRKT+1,
						tvb_events_end_offset, '{');
					if ( tvb_LBRKT < tvb_RBRKT && tvb_LBRKT != -1)
						tvb_RBRKT  = tvb_find_guint8(tvb, tvb_RBRKT+1,
						tvb_events_end_offset, '}');
				}
				
			}
			
			tvb_help_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_events_end_offset, '{');
			
			/* if there are eventparameter  */
			
			if ( tvb_help_offset < tvb_RBRKT && tvb_help_offset != -1 ){
				
				requested_event_start_offset = tvb_help_offset;
				requested_event_end_offset	 = tvb_RBRKT;
				tvb_help_offset = tvb_skip_wsp_return(tvb, tvb_help_offset-1);
				tokenlen = tvb_help_offset - tvb_previous_offset;
			}
			/* no parameters */
			else {
				tokenlen = tvb_RBRKT+1 - tvb_previous_offset;
			}
			
			megaco_requestedevent_ti = proto_tree_add_item(megaco_eventsdescriptor_tree,hf_megaco_pkgdname,tvb,tvb_previous_offset,tokenlen, FALSE);
			megaco_requestedevent_tree = proto_item_add_subtree(megaco_requestedevent_ti, ett_megaco_requestedevent);	
			
			if ( tvb_help_offset < tvb_RBRKT && tvb_help_offset != -1 ){
				
				tvb_help_offset = tvb_skip_wsp(tvb, requested_event_start_offset +1);
				tempchar = tvb_get_guint8(tvb, tvb_help_offset);
				
				requested_event_start_offset = tvb_skip_wsp(tvb, requested_event_start_offset +1);
				requested_event_end_offset = tvb_skip_wsp_return(tvb, requested_event_end_offset-1);
				
				if ( tempchar == 'D' ){
					dissect_megaco_digitmapdescriptor(tvb, megaco_requestedevent_tree, requested_event_end_offset, requested_event_start_offset);
				}
				else{
					tokenlen = 	requested_event_end_offset - requested_event_start_offset
						;
					proto_tree_add_text(megaco_requestedevent_tree, tvb, requested_event_start_offset, tokenlen,
						"%s", tvb_format_text(tvb,requested_event_start_offset, tokenlen));	
				}	
				
			}
			
			tvb_current_offset  = tvb_find_guint8(tvb, tvb_RBRKT,
				tvb_events_end_offset, ',');
			
			if (tvb_current_offset == -1 || tvb_current_offset > tvb_events_end_offset ){
				tvb_current_offset = tvb_events_end_offset;
			}
			
			tvb_previous_offset = tvb_skip_wsp(tvb, tvb_current_offset+1);
			
			tvb_LBRKT = tvb_previous_offset;	
			tvb_RBRKT = tvb_previous_offset;
			
		} while ( tvb_current_offset < tvb_events_end_offset );
	}	
}

static void
dissect_megaco_signaldescriptor(tvbuff_t *tvb, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset)
{
	
	gint tokenlen, tvb_current_offset, tvb_next_offset, tvb_help_offset;
	gint tvb_signals_end_offset, tvb_signals_start_offset, tvb_LBRKT;
	proto_tree  *megaco_signalsdescriptor_tree, *megaco_signalsdescriptor_ti;
	
	gint requested_signal_start_offset, requested_signal_end_offset;
	proto_tree	*megaco_requestedsignal_tree, *megaco_requestedsignal_ti;
	
	tokenlen						= 0;
	tvb_current_offset				= 0;
	tvb_next_offset					= 0;
	tvb_help_offset					= 0;
	tvb_signals_end_offset			= 0;
	tvb_signals_start_offset		= 0;	
	tvb_LBRKT						= 0;
	requested_signal_start_offset	= 0;
	requested_signal_end_offset		= 0;
	
	tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;
	
	megaco_signalsdescriptor_ti = proto_tree_add_item(megaco_tree_command_line,hf_megaco_signal_descriptor,tvb,tvb_previous_offset,tokenlen, FALSE);
	megaco_signalsdescriptor_tree = proto_item_add_subtree(megaco_signalsdescriptor_ti, ett_megaco_signalsdescriptor);
	
	tvb_current_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_RBRKT, '{');
	tvb_next_offset = tvb_skip_wsp(tvb, tvb_current_offset+1);
	
	tvb_signals_end_offset   = tvb_RBRKT;
	tvb_signals_start_offset = tvb_previous_offset;
	
	if ( tvb_current_offset < tvb_RBRKT && tvb_current_offset != -1 && tvb_next_offset != tvb_signals_end_offset){
		
		
		tvb_RBRKT = tvb_next_offset+1;
		tvb_LBRKT = tvb_next_offset+1;
		tvb_previous_offset = tvb_next_offset;
		
		
		do {
			
			tvb_RBRKT = tvb_find_guint8(tvb, tvb_RBRKT+1,
				tvb_signals_end_offset, '}');
			tvb_LBRKT = tvb_find_guint8(tvb, tvb_LBRKT,
				tvb_signals_end_offset, '{');
			
			tvb_current_offset 	= tvb_find_guint8(tvb, tvb_previous_offset,
				tvb_signals_end_offset, ',');
			
			if (tvb_current_offset == -1 || tvb_current_offset > tvb_signals_end_offset){
				tvb_current_offset = tvb_signals_end_offset;
			}
			
			
			/* Descriptor includes no parameters */
			
			if ( tvb_LBRKT > tvb_current_offset || tvb_LBRKT == -1 ){
				
				tvb_RBRKT = tvb_skip_wsp_return(tvb, tvb_current_offset-1)-1;
			}
			
			/* Descriptor includes Parameters */
			
			if ( (tvb_current_offset > tvb_LBRKT && tvb_LBRKT != -1)){
				
				while ( tvb_LBRKT != -1 && tvb_RBRKT > tvb_LBRKT ){
					
					tvb_LBRKT  = tvb_find_guint8(tvb, tvb_LBRKT+1,
						tvb_signals_end_offset, '{');
					if ( tvb_LBRKT < tvb_RBRKT && tvb_LBRKT != -1)
						tvb_RBRKT  = tvb_find_guint8(tvb, tvb_RBRKT+1,
						tvb_signals_end_offset, '}');
				}
				
			}
			
			tvb_help_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_signals_end_offset, '{');
			
			/* if there are signalparameter  */
			
			if ( tvb_help_offset < tvb_RBRKT && tvb_help_offset != -1 ){
				
				requested_signal_start_offset = tvb_help_offset;
				requested_signal_end_offset	 = tvb_RBRKT;
				tvb_help_offset = tvb_skip_wsp_return(tvb, tvb_help_offset-1);
				tokenlen = tvb_help_offset - tvb_previous_offset;
			}
			/* no parameters */
			else {
				tokenlen = tvb_RBRKT+1 - tvb_previous_offset;
			}
			
			
			megaco_requestedsignal_ti = proto_tree_add_item(megaco_signalsdescriptor_tree,hf_megaco_pkgdname,tvb,tvb_previous_offset,tokenlen, FALSE);
			megaco_requestedsignal_tree = proto_item_add_subtree(megaco_requestedsignal_ti, ett_megaco_requestedsignal);	
			
			if ( tvb_help_offset < tvb_RBRKT && tvb_help_offset != -1 ){
				
				
				requested_signal_start_offset = tvb_skip_wsp(tvb, requested_signal_start_offset +1);
				requested_signal_end_offset = tvb_skip_wsp_return(tvb, requested_signal_end_offset-1);
				
				tokenlen = 	requested_signal_end_offset - requested_signal_start_offset;
				
				proto_tree_add_text(megaco_requestedsignal_tree, tvb, requested_signal_start_offset, tokenlen,
					"%s", tvb_format_text(tvb,requested_signal_start_offset, tokenlen+1));	
				
			}
			
			tvb_current_offset  = tvb_find_guint8(tvb, tvb_RBRKT,
				tvb_signals_end_offset, ',');
			
			if (tvb_current_offset == -1 || tvb_current_offset > tvb_signals_end_offset ){
				tvb_current_offset = tvb_signals_end_offset;
			}
			
			tvb_previous_offset = tvb_skip_wsp(tvb, tvb_current_offset+1);
			
			tvb_LBRKT = tvb_previous_offset;	
			tvb_RBRKT = tvb_previous_offset;
			
		} while ( tvb_current_offset < tvb_signals_end_offset );
	}
	
	
}
static void
dissect_megaco_auditdescriptor(tvbuff_t *tvb, proto_tree *megaco_tree_command_line, packet_info *pinfo,  gint tvb_RBRKT, gint tvb_previous_offset)
{
	
	gint 	tokenlen;
	proto_tree  *megaco_auditdescriptor_tree, *megaco_auditdescriptor_ti;
	
	tokenlen = 0;

	tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;
	
	megaco_auditdescriptor_ti = proto_tree_add_item(megaco_tree_command_line,hf_megaco_audit_descriptor,tvb,tvb_previous_offset,tokenlen, FALSE);
	megaco_auditdescriptor_tree = proto_item_add_subtree(megaco_auditdescriptor_ti, ett_megaco_auditdescriptor);
	
	
	tvb_previous_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_RBRKT, '{');
	
	if ( tvb_skip_wsp(tvb, tvb_previous_offset +1) != tvb_RBRKT ){
		dissect_megaco_descriptors(tvb, megaco_auditdescriptor_tree, pinfo, tvb_previous_offset,tvb_RBRKT);
	}
}
static void
dissect_megaco_servicechangedescriptor(tvbuff_t *tvb, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset)
{
	
	gint 	tokenlen;
	
	tokenlen = 0;

	tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;
	proto_tree_add_string(megaco_tree_command_line, hf_megaco_servicechange_descriptor, tvb,
					 		tvb_previous_offset, tokenlen,
							tvb_format_text(tvb, tvb_previous_offset,
							tokenlen));
	
}
static void
dissect_megaco_digitmapdescriptor(tvbuff_t *tvb, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset)
{
	
	gint 	tokenlen;
	
	tokenlen = 0;

	tokenlen =  tvb_RBRKT - tvb_previous_offset;
	proto_tree_add_string(megaco_tree_command_line, hf_megaco_digitmap_descriptor, tvb,
					 		tvb_previous_offset, tokenlen,
							tvb_format_text(tvb, tvb_previous_offset,
							tokenlen));
	
}
static void
dissect_megaco_statisticsdescriptor(tvbuff_t *tvb, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset)
{
	
	gint 	tokenlen;

	tokenlen = 0;
		
	tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;
	proto_tree_add_string(megaco_tree_command_line, hf_megaco_statistics_descriptor, tvb,
					 		tvb_previous_offset, tokenlen,
							tvb_format_text(tvb, tvb_previous_offset,
							tokenlen));
	
}
static void
dissect_megaco_observedeventsdescriptor(tvbuff_t *tvb, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset)
{
	
	gint tokenlen, tvb_current_offset, tvb_next_offset, tvb_help_offset;
	gint tvb_observedevents_end_offset, tvb_observedevents_start_offset, tvb_LBRKT;
	proto_tree  *megaco_observedeventsdescriptor_tree, *megaco_observedeventsdescriptor_ti;
	
	guint8 tempchar;
	gint requested_event_start_offset, requested_event_end_offset, param_start_offset, param_end_offset;
	proto_tree	*megaco_observedevent_tree, *megaco_observedevent_ti;

	tokenlen						= 0;
	tvb_current_offset				= 0;
	tvb_next_offset					= 0;
	tvb_help_offset					= 0;
	tvb_observedevents_end_offset	= 0;
	tvb_observedevents_start_offset	= 0;	
	tvb_LBRKT						= 0;
	requested_event_start_offset	= 0;
	requested_event_end_offset	= 0;

	
	
	tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;
	
	megaco_observedeventsdescriptor_ti = proto_tree_add_item(megaco_tree_command_line,hf_megaco_observedevents_descriptor,tvb,tvb_previous_offset,tokenlen, FALSE);
	megaco_observedeventsdescriptor_tree = proto_item_add_subtree(megaco_observedeventsdescriptor_ti, ett_megaco_observedeventsdescriptor);
	
	
	
	tvb_current_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_RBRKT, '=');
	tvb_next_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_RBRKT, '{');
	
	if ( tvb_current_offset < tvb_RBRKT && tvb_current_offset != -1 ){
		
		tvb_current_offset = tvb_skip_wsp(tvb, tvb_current_offset +1);
		tvb_help_offset = tvb_skip_wsp_return(tvb, tvb_next_offset-1);
		
		tokenlen =  tvb_help_offset - tvb_current_offset;
		
		proto_tree_add_string(megaco_observedeventsdescriptor_tree, hf_megaco_requestid, tvb,
			tvb_current_offset, tokenlen,
			tvb_format_text(tvb, tvb_current_offset,
			tokenlen));
		
		tvb_observedevents_end_offset   = tvb_RBRKT;
		tvb_observedevents_start_offset = tvb_previous_offset;
		
		tvb_RBRKT = tvb_next_offset+1;
		tvb_LBRKT = tvb_next_offset+1;
		tvb_previous_offset = tvb_skip_wsp(tvb, tvb_next_offset+1);
		
		
		do {
			
			tvb_RBRKT = tvb_find_guint8(tvb, tvb_RBRKT+1,
				tvb_observedevents_end_offset, '}');
			tvb_LBRKT = tvb_find_guint8(tvb, tvb_LBRKT,
				tvb_observedevents_end_offset, '{');
			
			tvb_current_offset 	= tvb_find_guint8(tvb, tvb_previous_offset,
				tvb_observedevents_end_offset, ',');
			
			if (tvb_current_offset == -1 || tvb_current_offset > tvb_observedevents_end_offset){
				tvb_current_offset = tvb_observedevents_end_offset;
			}
			
			
			/* Descriptor includes no parameters */
			
			if ( tvb_LBRKT > tvb_current_offset || tvb_LBRKT == -1 ){
				
				tvb_RBRKT = tvb_skip_wsp_return(tvb, tvb_current_offset-1)-1;
			}
			
			/* Descriptor includes Parameters */
			
			if ( (tvb_current_offset > tvb_LBRKT && tvb_LBRKT != -1)){
				
				while ( tvb_LBRKT != -1 && tvb_RBRKT > tvb_LBRKT ){
					
					tvb_LBRKT  = tvb_find_guint8(tvb, tvb_LBRKT+1,
						tvb_observedevents_end_offset, '{');
					if ( tvb_LBRKT < tvb_RBRKT && tvb_LBRKT != -1){
						tvb_RBRKT  = tvb_find_guint8(tvb, tvb_RBRKT+1,
							tvb_observedevents_end_offset, '}');
					}
				}
				
			}
			
			tvb_help_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_observedevents_end_offset, '{');
			
			/* if there are eventparameter  */
			
			if ( tvb_help_offset < tvb_RBRKT && tvb_help_offset != -1 ){
				
				requested_event_start_offset = tvb_help_offset;
				requested_event_end_offset	 = tvb_RBRKT;
				tvb_help_offset = tvb_skip_wsp_return(tvb, tvb_help_offset-1);
				tokenlen = tvb_help_offset - tvb_previous_offset;
			}
			/* no parameters */
			else {
				tokenlen = tvb_RBRKT+1 - tvb_previous_offset;
			}
			
			megaco_observedevent_ti = proto_tree_add_item(megaco_observedeventsdescriptor_tree,hf_megaco_pkgdname,tvb,tvb_previous_offset,tokenlen, FALSE);
			megaco_observedevent_tree = proto_item_add_subtree(megaco_observedevent_ti, ett_megaco_observedevent);	
			
			if ( tvb_help_offset < tvb_RBRKT && tvb_help_offset != -1 ){
				
				tvb_help_offset = tvb_skip_wsp(tvb, requested_event_start_offset +1);
				tempchar = tvb_get_guint8(tvb, tvb_help_offset);
				
				requested_event_start_offset = tvb_skip_wsp(tvb, requested_event_start_offset +1)-1;
				requested_event_end_offset = tvb_skip_wsp_return(tvb, requested_event_end_offset-1);
				
				tvb_help_offset = requested_event_start_offset;
				
				do {
					
					param_start_offset = tvb_skip_wsp(tvb, tvb_help_offset+1);
					
					tvb_help_offset = tvb_find_guint8(tvb, tvb_help_offset+1,requested_event_end_offset, ',');
					
					if ( tvb_help_offset > requested_event_end_offset || tvb_help_offset == -1){
						tvb_help_offset = requested_event_end_offset;
					}
					
					param_end_offset = tvb_skip_wsp(tvb, tvb_help_offset-1);
					
					tokenlen = 	param_end_offset - param_start_offset+1;
					
					proto_tree_add_text(megaco_observedevent_tree, tvb, param_start_offset, tokenlen,
						"%s", tvb_format_text(tvb,param_start_offset, tokenlen));
					
					
				} while ( tvb_help_offset < requested_event_end_offset );
			}
			
			tvb_current_offset  = tvb_find_guint8(tvb, tvb_RBRKT,
				tvb_observedevents_end_offset, ',');
			
			if (tvb_current_offset == -1 || tvb_current_offset > tvb_observedevents_end_offset ){
				tvb_current_offset = tvb_observedevents_end_offset;
			}
			
			tvb_previous_offset = tvb_skip_wsp(tvb, tvb_current_offset+1);
			
			tvb_LBRKT = tvb_previous_offset;	
			tvb_RBRKT = tvb_previous_offset;
			
		} while ( tvb_current_offset < tvb_observedevents_end_offset );
	}	
}
static void
dissect_megaco_topologydescriptor(tvbuff_t *tvb, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset)
{
	
	gint 	tokenlen;
	
	tokenlen = 0;

	tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;
	proto_tree_add_string(megaco_tree_command_line, hf_megaco_topology_descriptor, tvb,
					 		tvb_previous_offset, tokenlen,
							tvb_format_text(tvb, tvb_previous_offset,
							tokenlen));
	
}
static void
dissect_megaco_Packagesdescriptor(tvbuff_t *tvb, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset)
{
	
	gint tokenlen, tvb_current_offset, tvb_next_offset, tvb_help_offset;
	gint tvb_packages_end_offset, tvb_packages_start_offset, tvb_LBRKT;
	proto_tree  *megaco_packagesdescriptor_tree, *megaco_packagesdescriptor_ti;
	
	tokenlen					= 0;
	tvb_current_offset			= 0;
	tvb_next_offset				= 0;
	tvb_help_offset				= 0;
	tvb_packages_end_offset		= 0;
	tvb_packages_start_offset	= 0;	
	tvb_LBRKT					= 0;
	
	tokenlen =  (tvb_RBRKT+1) - tvb_previous_offset;
	
	megaco_packagesdescriptor_ti = proto_tree_add_item(megaco_tree_command_line,hf_megaco_packages_descriptor,tvb,tvb_previous_offset,tokenlen, FALSE);
	megaco_packagesdescriptor_tree = proto_item_add_subtree(megaco_packagesdescriptor_ti, ett_megaco_packagesdescriptor);
	
	
	
	tvb_current_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_RBRKT, '=');
	tvb_next_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_RBRKT, '{');
	
	if ( tvb_current_offset < tvb_RBRKT && tvb_current_offset != -1 ){
		
		tvb_current_offset = tvb_skip_wsp(tvb, tvb_current_offset +1);
		tvb_help_offset = tvb_skip_wsp_return(tvb, tvb_next_offset-1);
		
		tokenlen =  tvb_help_offset - tvb_current_offset;
		
		proto_tree_add_string(megaco_packagesdescriptor_tree, hf_megaco_requestid, tvb,
			tvb_current_offset, tokenlen,
			tvb_format_text(tvb, tvb_current_offset,
			tokenlen));
		
		tvb_packages_end_offset   = tvb_RBRKT;
		tvb_packages_start_offset = tvb_previous_offset;
		
		tvb_RBRKT = tvb_next_offset+1;
		tvb_LBRKT = tvb_next_offset+1;
		tvb_previous_offset = tvb_skip_wsp(tvb, tvb_next_offset+1);
		
		
		do {
			
			tvb_RBRKT = tvb_find_guint8(tvb, tvb_RBRKT+1,
				tvb_packages_end_offset, '}');
			tvb_LBRKT = tvb_find_guint8(tvb, tvb_LBRKT,
				tvb_packages_end_offset, '{');
			
			tvb_current_offset 	= tvb_find_guint8(tvb, tvb_previous_offset,
				tvb_packages_end_offset, ',');
			
			if (tvb_current_offset == -1 || tvb_current_offset > tvb_packages_end_offset){
				tvb_current_offset = tvb_packages_end_offset;
			}
			
			
			/* Descriptor includes no parameters */
			
			if ( tvb_LBRKT > tvb_current_offset || tvb_LBRKT == -1 ){
				
				tvb_RBRKT = tvb_skip_wsp_return(tvb, tvb_current_offset-1)-1;
			}
			
			/* Descriptor includes Parameters */
			
			if ( (tvb_current_offset > tvb_LBRKT && tvb_LBRKT != -1)){
				
				while ( tvb_LBRKT != -1 && tvb_RBRKT > tvb_LBRKT ){
					
					tvb_LBRKT  = tvb_find_guint8(tvb, tvb_LBRKT+1,
						tvb_packages_end_offset, '{');
					if ( tvb_LBRKT < tvb_RBRKT && tvb_LBRKT != -1)
						tvb_RBRKT  = tvb_find_guint8(tvb, tvb_RBRKT+1,
						tvb_packages_end_offset, '}');
				}
				
			}
			
			tokenlen = tvb_RBRKT+1 - tvb_previous_offset;
			
			proto_tree_add_text(megaco_packagesdescriptor_tree, tvb, tvb_previous_offset, tokenlen,
				"%s", tvb_format_text(tvb,tvb_previous_offset,
				tokenlen));	
			
			
			tvb_current_offset  	= tvb_find_guint8(tvb, tvb_RBRKT,
				tvb_packages_end_offset, ',');
			
			if (tvb_current_offset == -1 || tvb_current_offset > tvb_packages_end_offset ){
				tvb_current_offset = tvb_packages_end_offset;
			}
			
			tvb_previous_offset = tvb_skip_wsp(tvb, tvb_current_offset+1);
			
			tvb_LBRKT = tvb_previous_offset;	
			tvb_RBRKT = tvb_previous_offset;
			
		} while ( tvb_current_offset < tvb_packages_end_offset );
	}
	
}
static void
dissect_megaco_errordescriptor(tvbuff_t *tvb, proto_tree *megaco_tree_command_line,  gint tvb_RBRKT, gint tvb_previous_offset)
{
	
	gint 	tokenlen;
	guint8	error[4];
	gint 	tvb_next_offset, tvb_current_offset,tvb_len;
	
	tvb_len				= tvb_length(tvb);
	tokenlen			= 0;
	tvb_next_offset		= 0;
	tvb_current_offset	= 0;
	tvb_len				= 0;

	
	tvb_current_offset = tvb_find_guint8(tvb, tvb_previous_offset , tvb_RBRKT, '=');
	tvb_current_offset = tvb_skip_wsp(tvb, tvb_current_offset +1);
	tvb_get_nstringz0(tvb,tvb_current_offset,4,error);
	
	proto_tree_add_string_hidden(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
					 		tvb_current_offset, 3,
							tvb_format_text(tvb, tvb_current_offset,
							3));
	
	tokenlen =  (tvb_RBRKT) - tvb_previous_offset+1;
	
	
	proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
					 		tvb_previous_offset, tokenlen,
							tvb_format_text(tvb, tvb_previous_offset,
							tokenlen));
	
	
	switch ( error[0] ){
		
	case '4':
		
		switch ( error[1] ){
			
		case '0':
			
			switch ( error[2] ){			
				
			case '0':
				proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
					tvb_current_offset, 3,
					"Bad Request");
				break;
				
			case '1':
				proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
					tvb_current_offset, 3,
					"Protocol Error");
				break;
				
			case '2':
				proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
					tvb_current_offset, 3,
					"Unauthorized");
				break;
				
			case '3':
				proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
					tvb_current_offset, 3,
					"Syntax Error in Transaction");
				break;
				
			case '6':
				proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
					tvb_current_offset, 3,
					"Version Not Supported");
				break;
				
			}
			
			break;
			
			case '1':
				
				switch ( error[2] ){
					
				case '0':
					proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
						tvb_current_offset, 3,
						"Incorrect identifier");
					break;
					
				case '1':
					proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
						tvb_current_offset, 3,
						"The Transaction refers to an unkown ContextID");
					break;
					
				case '2':
					proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
						tvb_current_offset, 3,
						"No ContextIDs available");
					break;
					
				}			
				
				break;
				
				case '2':
					
					switch ( error[2] ){	
						
					case '1':
						proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
							tvb_current_offset, 3,
							"Unkown action or illegal combination of actions");
						break;
						
					case '2':
						proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
							tvb_current_offset, 3,
							"Syntax Error in Action");
						
						break;
						
					}
					
					break;
					
					case '3':
						
						switch ( error[2] ){	
							
						case '0':
							proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
								tvb_current_offset, 3,
								"Unknown TerminationID");
							break;
							
						case '1':
							proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
								tvb_current_offset, 3,
								"No TertminationID matched a Wildcard");
							break;
							
						case '2':
							proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
								tvb_current_offset, 3,
								"Out of TerminationIDs or no TerminationID available");
							break;
							
						case '3':
							proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
								tvb_current_offset, 3,
								"TerminationID is already in Context");
							break;
							
						}
						
						break;
						
						case '4':
							
							switch ( error[2] ){	
								
							case '0':
								proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
									tvb_current_offset, 3,
									"Unsupported or unknown Package");
								break;
								
							case '1':
								proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
									tvb_current_offset, 3,
									"Missing RemoteDascriptor");
								break;
								
							case '2':
								proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
									tvb_current_offset, 3,
									"Syntax Error in Command");
								break;
								
							case '3':
								proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
									tvb_current_offset, 3,
									"Unsupported or Unknown Command");
								break;
								
							case '4':
								proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
									tvb_current_offset, 3,
									"Unsupported or Unknown Descriptor");
								break;
								
							case '5':
								proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
									tvb_current_offset, 3,
									"Unsupported or Unknown Property");
								break;
								
							case '6':
								proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
									tvb_current_offset, 3,
									"Unsupported or Unknown Parameter");
								break;
								
							case '7':
								proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
									tvb_current_offset, 3,
									"Descriptor not legal in this command");
								break;
								
							case '8':
								proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
									tvb_current_offset, 3,
									"Descriptor appears twice in this command");
								break;
								
							}
							
							break;
							
							case '5':
								switch ( error[2] ){	
									
								case '0':
									proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
										tvb_current_offset, 3,
										"No such property in this package");
									break;
									
								case '1':
									proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
										tvb_current_offset, 3,
										"No such event in this package");
									break;
									
								case '2':
									proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
										tvb_current_offset, 3,
										"No such signal in this package");
									break;
									
								case '3':
									proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
										tvb_current_offset, 3,
										"No such statistic in this package");
									break;
									
								case '4':
									proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
										tvb_current_offset, 3,
										"No such parameter value in this package");
									break;
									
								case '5':	
									proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
										tvb_current_offset, 3,
										"Parameter illegal in this Descriptor");
									break;
									
								case '6':
									proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
										tvb_current_offset, 3,
										"Parameter or Property appears twice in this Descriptor");
									break;
									
								}
								
								break;
								
								case '7':
									
									switch ( error[2] ){	
										
									case '1':
										proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
											tvb_current_offset, 3,
											"Implied Add for Multiplex failure");
										break;
										
									}
									
									break;
									
		}		
		
		break;
		
		
	case '5':
		
		switch ( error[1] ){
			
		case '0':
			
			switch ( error[2] ){
				
			case '0':
				proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
					tvb_current_offset, 3,
					"Internal Gateway Error");		
				break;
				
			case '1':
				proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
					tvb_current_offset, 3,
					"Not Implemented");		
				break;
				
			case '2':
				proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
					tvb_current_offset, 3,
					"Not ready");		
				break;
				
			case '3':
				proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
					tvb_current_offset, 3,
					"Service Unavailable");		
				break;
				
			case '4':
				proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
					tvb_current_offset, 3,
					"Command Received from unauthorized entity");		
				break;
				
			case '5':
				proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
					tvb_current_offset, 3,
					"Command Received before Restart response");		
				break;
				
			}
			
			break;
			
			case '1':
				
				switch ( error[2] ){
					
				case '0':
					proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
						tvb_current_offset, 3,
						"Insufficient resources");		
					break;
					
				case '2':
					proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
						tvb_current_offset, 3,
						"Media Gateway unequipped to detect request Event");		
					break;
					
				case '3':
					proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
						tvb_current_offset, 3,
						"Media Gateway unequipped to generate requested Signals");		
					break;
					
				case '4':
					proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
						tvb_current_offset, 3,
						"Media Gateway cannot send the specified announcement");		
					break;
					
				case '5':
					proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
						tvb_current_offset, 3,
						"Unsupported Media Type");		
					break;
					
				case '7':
					proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
						tvb_current_offset, 3,
						"Unsupported or invalid mode");		
					break;
					
				case '8':
					proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
						tvb_current_offset, 3,
						"Event buffer full");		
					break;
					
				case '9':
					proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
						tvb_current_offset, 3,
						"Out of space to store digit map");		
					break;
					
				}
				
				break;
				
				case '2':
					
					switch ( error[2] ){
						
						
					case '0':
						proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
							tvb_current_offset, 3,
							"Media Gateway does not have a digit map");		
						break;
						
					case '1':
						proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
							tvb_current_offset, 3,
							"Termination is ServiceChanging");		
						break;
						
					case '6':
						proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
							tvb_current_offset, 3,
							"insufficient bandwidth");		
						break;
						
					case '9':
						proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
							tvb_current_offset, 3,
							"Internal hardeware failure");		
						break;
						
					}
					
					break;
					
					case '3':
						
						switch ( error[2] ){
							
						case '0':
							proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
								tvb_current_offset, 3,
								"Temporary Network failure");		
							break;
							
						case '1':
							proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
								tvb_current_offset, 3,
								"Permanent Network failure");		
							break;
							
							
						}
						
						break;
						
						case '8':
							
							switch ( error[2] ){
								
							case '1':
								proto_tree_add_string(megaco_tree_command_line, hf_megaco_error_descriptor, tvb,
									tvb_current_offset, 3,
									"Does Not Exist");		
								break;
								
								
							}
							
							break;
			}
		
		break;
		
	}
	
	
	
}
static void
dissect_megaco_TerminationStatedescriptor(tvbuff_t *tvb, proto_tree *megaco_mediadescriptor_tree,  gint tvb_next_offset, gint tvb_current_offset)
{
	gint tokenlen;
	gint tvb_offset, tvb_help_offset;
	guint8 tempchar;
	
	proto_tree  *megaco_TerminationState_tree, *megaco_TerminationState_ti;
	
	tokenlen		= 0;
	tvb_offset		= 0;
	tvb_help_offset = 0;

	tvb_offset = tvb_find_guint8(tvb, tvb_current_offset , tvb_next_offset, '=');
	
	tokenlen = tvb_next_offset - tvb_current_offset;
	
	megaco_TerminationState_ti = proto_tree_add_item(megaco_mediadescriptor_tree,hf_megaco_TerminationState_descriptor,tvb,tvb_current_offset,tokenlen, FALSE);
	megaco_TerminationState_tree = proto_item_add_subtree(megaco_TerminationState_ti, ett_megaco_TerminationState);
	
	while ( tvb_offset < tvb_next_offset && tvb_offset != -1 ){
		
		tempchar = tvb_get_guint8(tvb, tvb_current_offset);
		tvb_help_offset = tvb_current_offset;
		
		tvb_current_offset = tvb_skip_wsp(tvb, tvb_offset +1);
		
		switch ( tempchar ){
			
		case 'S':
			tvb_offset = tvb_find_guint8(tvb, tvb_current_offset , tvb_offset, ',');
			if ( tvb_offset == -1 || tvb_offset > tvb_next_offset ){
				tvb_offset = tvb_next_offset;
			}
			
			tempchar = tvb_get_guint8(tvb, tvb_current_offset);
			tokenlen = tvb_offset - tvb_current_offset;
			
			proto_tree_add_string(megaco_TerminationState_tree, hf_megaco_Service_State, tvb,
				tvb_current_offset, tokenlen,
				tvb_format_text(tvb, tvb_current_offset,
				tokenlen));
			
			break;	
			
		case 'B':	
			
			tvb_offset = tvb_find_guint8(tvb, tvb_current_offset , tvb_offset, ',');
			if ( tvb_offset == -1 || tvb_offset > tvb_next_offset ){
				tvb_offset = tvb_next_offset;
			}
			
			tempchar = tvb_get_guint8(tvb, tvb_current_offset);
			tokenlen = tvb_offset - tvb_current_offset;
			
			proto_tree_add_string(megaco_TerminationState_tree, hf_megaco_Event_Buffer_Control, tvb,
				tvb_current_offset, tokenlen,
				tvb_format_text(tvb, tvb_current_offset,
				tokenlen));
			
			break;
			
		case 'E':
			tvb_offset = tvb_find_guint8(tvb, tvb_current_offset , tvb_offset, ',');
			if ( tvb_offset == -1 || tvb_offset > tvb_next_offset ){
				tvb_offset = tvb_next_offset;
			}
			
			tempchar = tvb_get_guint8(tvb, tvb_current_offset);
			tokenlen = tvb_offset - tvb_current_offset;
			
			proto_tree_add_string(megaco_TerminationState_tree, hf_megaco_Event_Buffer_Control, tvb,
				tvb_current_offset, tokenlen,
				tvb_format_text(tvb, tvb_current_offset,
				tokenlen));
			
			break;
			
		default:
			tvb_offset = tvb_find_guint8(tvb, tvb_current_offset , tvb_offset, ',');
			if ( tvb_offset == -1 || tvb_offset > tvb_next_offset ){
				tvb_offset = tvb_next_offset;
			}
			
			tempchar = tvb_get_guint8(tvb, tvb_help_offset);
			tokenlen = tvb_offset - tvb_help_offset;
			
			proto_tree_add_text(megaco_TerminationState_tree, tvb, tvb_help_offset, tokenlen,
				"%s", tvb_format_text(tvb,tvb_help_offset,
				tokenlen));	
			break;
		}
		
		
		tvb_current_offset = tvb_skip_wsp(tvb, tvb_offset +1);
		tvb_offset = tvb_find_guint8(tvb, tvb_current_offset , tvb_next_offset, '=');
	}	
}

static void
dissect_megaco_Localdescriptor(tvbuff_t *tvb, proto_tree *megaco_mediadescriptor_tree,packet_info *pinfo, gint tvb_next_offset, gint tvb_current_offset)
{
	gint tokenlen;
	tvbuff_t *next_tvb;
	
	proto_tree  *megaco_localdescriptor_tree, *megaco_localdescriptor_ti;

	tokenlen = 0;

	tokenlen = tvb_next_offset - tvb_current_offset;
	
	
	
	megaco_localdescriptor_ti = proto_tree_add_item(megaco_mediadescriptor_tree,hf_megaco_Local_descriptor,tvb,tvb_current_offset,tokenlen, FALSE);
	megaco_localdescriptor_tree = proto_item_add_subtree(megaco_localdescriptor_ti, ett_megaco_Localdescriptor);
	
	tokenlen = tvb_next_offset - tvb_current_offset;
	
	next_tvb = tvb_new_subset(tvb, tvb_current_offset, tokenlen, tokenlen);
	call_dissector(sdp_handle, next_tvb, pinfo, megaco_localdescriptor_tree);
	
}
static void
dissect_megaco_Remotedescriptor(tvbuff_t *tvb, proto_tree *megaco_mediadescriptor_tree,packet_info *pinfo, gint tvb_next_offset, gint tvb_current_offset)
{
	gint tokenlen;
	tvbuff_t *next_tvb;

		
	proto_tree  *megaco_Remotedescriptor_tree, *megaco_Remotedescriptor_ti;

	tokenlen = 0;	
	
	tokenlen = tvb_next_offset - tvb_current_offset;
	
	megaco_Remotedescriptor_ti = proto_tree_add_item(megaco_mediadescriptor_tree,hf_megaco_Remote_descriptor,tvb,tvb_current_offset,tokenlen, FALSE);
	megaco_Remotedescriptor_tree = proto_item_add_subtree(megaco_Remotedescriptor_ti, ett_megaco_Remotedescriptor);
	
	
	next_tvb = tvb_new_subset(tvb, tvb_current_offset, tokenlen, tokenlen);
	call_dissector(sdp_handle, next_tvb, pinfo, megaco_Remotedescriptor_tree);
	
}
static void
dissect_megaco_LocalControldescriptor(tvbuff_t *tvb, proto_tree *megaco_mediadescriptor_tree,  gint tvb_next_offset, gint tvb_current_offset)
{
	gint tokenlen;
	gint tvb_offset,tvb_help_offset;
	guint8 tempchar;


	proto_tree  *megaco_LocalControl_tree, *megaco_LocalControl_ti;

	tokenlen		= 0;
	tvb_offset		= 0;
	tvb_help_offset = 0;
	
	tvb_offset = tvb_find_guint8(tvb, tvb_current_offset , tvb_next_offset, '=');
	
	tokenlen = tvb_next_offset - tvb_current_offset;
	
	megaco_LocalControl_ti = proto_tree_add_item(megaco_mediadescriptor_tree,hf_megaco_LocalControl_descriptor,tvb,tvb_current_offset,tokenlen, FALSE);
	megaco_LocalControl_tree = proto_item_add_subtree(megaco_LocalControl_ti, ett_megaco_LocalControldescriptor);
	
	while ( tvb_offset < tvb_next_offset && tvb_offset != -1 ){
		
		tempchar = tvb_get_guint8(tvb, tvb_current_offset);
		tvb_help_offset	= tvb_current_offset;
		tvb_current_offset = tvb_skip_wsp(tvb, tvb_offset +1);
		
		
		switch ( tempchar ){
			
		case 'M':
			tvb_offset = tvb_find_guint8(tvb, tvb_current_offset , tvb_offset, ',');
			if ( tvb_offset == -1 || tvb_offset > tvb_next_offset ){
				tvb_offset = tvb_next_offset;
			}
			
			tokenlen = tvb_offset - tvb_current_offset;
			
			proto_tree_add_string(megaco_LocalControl_tree, hf_megaco_mode, tvb,
				tvb_current_offset, tokenlen,
				tvb_format_text(tvb, tvb_current_offset,
				tokenlen));
			tvb_current_offset = tvb_skip_wsp(tvb, tvb_offset +1);
			break;
			
		case 'R':
			if ( tvb_get_guint8(tvb, tvb_help_offset+1) == 'V' || tvb_get_guint8(tvb, tvb_help_offset+8)  == 'V'){
				
				tvb_offset = tvb_find_guint8(tvb, tvb_current_offset , tvb_offset, ',');
				if ( tvb_offset == -1 || tvb_offset > tvb_next_offset ){
					tvb_offset = tvb_next_offset;
				}
				
				tokenlen = tvb_offset - tvb_current_offset;
				
				proto_tree_add_string(megaco_LocalControl_tree, hf_megaco_reserve_value, tvb,
					tvb_current_offset, tokenlen,
					tvb_format_text(tvb, tvb_current_offset,
					tokenlen));
				
				tvb_current_offset = tvb_skip_wsp(tvb, tvb_offset +1);
			}
			else {
				tvb_offset = tvb_find_guint8(tvb, tvb_current_offset , tvb_offset, ',');
				if ( tvb_offset == -1 || tvb_offset > tvb_next_offset ){
					tvb_offset = tvb_next_offset;
				}
				
				tokenlen = tvb_offset - tvb_current_offset;
				
				proto_tree_add_string(megaco_LocalControl_tree, hf_megaco_reserve_group, tvb,
					tvb_current_offset, tokenlen,
					tvb_format_text(tvb, tvb_current_offset,
					tokenlen));
				tvb_current_offset = tvb_skip_wsp(tvb, tvb_offset +1);
			}
			break;
			
		default: 
			tvb_offset = tvb_find_guint8(tvb, tvb_current_offset , tvb_offset, ',');
			if ( tvb_offset == -1 || tvb_offset > tvb_next_offset ){
				tvb_offset = tvb_next_offset;
			}
			
			tokenlen = tvb_offset - tvb_help_offset;
			
			proto_tree_add_text(megaco_LocalControl_tree, tvb, tvb_help_offset, tokenlen,
				"%s", tvb_format_text(tvb,tvb_help_offset,
				tokenlen));
			tvb_current_offset = tvb_skip_wsp(tvb, tvb_offset +1);
			
			break;
		}
		tvb_offset = tvb_find_guint8(tvb, tvb_current_offset , tvb_next_offset, '=');
	}
}
/* Register all the bits needed with the filtering engine */

void
proto_register_megaco(void)
{
	static hf_register_info hf[] = {
		{ &hf_megaco_audit_descriptor,
		{ "Audit Descriptor", "megaco.audit", FT_STRING, BASE_DEC, NULL, 0x0,
		"Audit Descriptor of the megaco Command ", HFILL }},
		{ &hf_megaco_command_line,
		{ "Command line", "megaco.command_line", FT_STRING, BASE_DEC, NULL, 0x0,
		"Commands of this message ", HFILL }},
		{ &hf_megaco_command,
		{ "Command", "megaco.command", FT_STRING, BASE_DEC, NULL, 0x0,
		"Command of this message ", HFILL }},
		{ &hf_megaco_Context,
		{ "Context", "megaco.context", FT_STRING, BASE_DEC, NULL, 0x0,
		"Context ID of this massage ", HFILL }},
		{ &hf_megaco_digitmap_descriptor,
		{ "DigitMap Descriptor", "megaco.digitmap", FT_STRING, BASE_DEC, NULL, 0x0,
		"DigitMap Descriptor of the megaco Command ", HFILL }},
		{ &hf_megaco_error_descriptor,
		{ "ERROR Descriptor", "megaco.error", FT_STRING, BASE_DEC, NULL, 0x0,
		"Error Descriptor of the megaco Command ", HFILL }},
		{ &hf_megaco_error_Frame,
		{ "ERROR frame", "megaco.error_frame", FT_STRING, BASE_DEC, NULL, 0x0,
		"Syntax error ", HFILL }},
		{ &hf_megaco_Event_Buffer_Control,
		{ "Event Buffer Control", "megaco.eventbuffercontrol", FT_STRING, BASE_DEC, NULL, 0x0,
		"Event Buffer Control in Termination State Descriptor", HFILL }},
		{ &hf_megaco_events_descriptor,
		{ "Events Descriptor", "megaco.events", FT_STRING, BASE_DEC, NULL, 0x0,
		"Events Descriptor of the megaco Command ", HFILL }},
		{ &hf_megaco_Local_descriptor,
		{ "Local Descriptor", "megaco.localdescriptor", FT_STRING, BASE_DEC, NULL, 0x0,
		"Local Descriptor in Media Descriptor ", HFILL }},
		{ &hf_megaco_LocalControl_descriptor,
		{ "Local Control Descriptor", "megaco.localcontroldescriptor", FT_STRING, BASE_DEC, NULL, 0x0,
		"Local Control Descriptor in Media Descriptor ", HFILL }},
		{ &hf_megaco_media_descriptor,
		{ "Media Descriptor", "megaco.media", FT_STRING, BASE_DEC, NULL, 0x0,
		"Media Descriptor of the megaco Command ", HFILL }},
		{ &hf_megaco_modem_descriptor,
		{ "Modem Descriptor", "megaco.modem", FT_STRING, BASE_DEC, NULL, 0x0,
		"Modem Descriptor of the megaco Command ", HFILL }},
		{ &hf_megaco_mode,
		{ "Mode", "megaco.mode", FT_STRING, BASE_DEC, NULL, 0x0,
		"Mode  sendonly/receiveonly/inactive/loopback", HFILL }},
		{ &hf_megaco_multiplex_descriptor,
		{ "Multiplex Descriptor", "megaco.multiplex", FT_STRING, BASE_DEC, NULL, 0x0,
		"Multiplex Descriptor of the megaco Command ", HFILL }},
		{ &hf_megaco_observedevents_descriptor,
		{ "Observed Events Descriptor", "megaco.observedevents", FT_STRING, BASE_DEC, NULL, 0x0,
		"Observed Events Descriptor of the megaco Command ", HFILL }},
		{ &hf_megaco_packages_descriptor,
		{ "Packages Descriptor", "megaco.packagesdescriptor", FT_STRING, BASE_DEC, NULL, 0x0,
		"Packages Descriptor", HFILL }},
		{ &hf_megaco_pkgdname,
		{ "pkgdName", "megaco.pkgdname", FT_STRING, BASE_DEC, NULL, 0x0,
		"PackageName SLASH ItemID", HFILL }},
		{ &hf_megaco_Remote_descriptor,
		{ "Remote Descriptor", "megaco.remotedescriptor", FT_STRING, BASE_DEC, NULL, 0x0,
		"Remote Descriptor in Media Descriptor ", HFILL }},
		{ &hf_megaco_reserve_group,
		{ "Reserve Group", "megaco.reservegroup", FT_STRING, BASE_DEC, NULL, 0x0,
		"Reserve Group on or off", HFILL }},
		{ &hf_megaco_reserve_value,
		{ "Reserve Value", "megaco.reservevalue", FT_STRING, BASE_DEC, NULL, 0x0,
		"Reserve Value on or off", HFILL }},
		{ &hf_megaco_requestid,
		{ "RequestID", "megaco.requestid", FT_STRING, BASE_DEC, NULL, 0x0,
		"RequestID in Events or Observedevents Descriptor ", HFILL }},
		{ &hf_megaco_servicechange_descriptor,
		{ "Service Chnage Descriptor", "megaco.servicechange", FT_STRING, BASE_DEC, NULL, 0x0,
		"Service Change Descriptor of the megaco Command ", HFILL }},
		{ &hf_megaco_Service_State,
		{ "Service State", "megaco.servicestates", FT_STRING, BASE_DEC, NULL, 0x0,
		"Service States in Termination State Descriptor", HFILL }},
		{ &hf_megaco_signal_descriptor,
		{ "Signal Descriptor", "megaco.signal", FT_STRING, BASE_DEC, NULL, 0x0,
		"Signal Descriptor of the megaco Command ", HFILL }},
		{ &hf_megaco_statistics_descriptor,
		{ "Statistics Descriptor", "megaco.statistics", FT_STRING, BASE_DEC, NULL, 0x0,
		"Statistics Descriptor of the megaco Command ", HFILL }},
		{ &hf_megaco_streamid,
		{ "StreamID", "megaco.streamid", FT_STRING, BASE_DEC, NULL, 0x0,
		"StreamID in the Media Descriptor ", HFILL }},
		{ &hf_megaco_termid,
		{ "Termination ID", "megaco.termid", FT_STRING, BASE_DEC, NULL, 0x0,
		"Termination ID of this Command ", HFILL }},
		{ &hf_megaco_TerminationState_descriptor,
		{ "Termination State Descriptor", "megaco.terminationstate", FT_STRING, BASE_DEC, NULL, 0x0,
		"Termination State Descriptor in Media Descriptor ", HFILL }},
		{ &hf_megaco_topology_descriptor,
		{ "Topology Descriptor", "megaco.topology", FT_STRING, BASE_DEC, NULL, 0x0,
		"Topology Descriptor of the megaco Command ", HFILL }},
		{ &hf_megaco_transaction,
		{ "Transaction", "megaco.transaction", FT_STRING, BASE_DEC, NULL, 0x0,
		"Message Originator", HFILL }},
		{ &hf_megaco_transid,
		{ "Transaction ID", "megaco.transid", FT_STRING, BASE_DEC, NULL, 0x0,
		"Transaction ID of this message", HFILL }},
		{ &hf_megaco_version,
		{ "Version", "megaco.version", FT_STRING, BASE_DEC, NULL, 0x0,
		"Version", HFILL }},	
		
		
		/* Add more fields here */
	};
	static gint *ett[] = {
		&ett_megaco,
			&ett_megaco_command_line,
			&ett_megaco_descriptors,
			&ett_megaco_mediadescriptor,
			&ett_megaco_TerminationState,
			&ett_megaco_Remotedescriptor,
			&ett_megaco_Localdescriptor,
			&ett_megaco_LocalControldescriptor,
			&ett_megaco_auditdescriptor,
			&ett_megaco_eventsdescriptor,
			&ett_megaco_observedeventsdescriptor,
			&ett_megaco_observedevent,
			&ett_megaco_packagesdescriptor,
			&ett_megaco_requestedevent,
			&ett_megaco_signalsdescriptor,
			&ett_megaco_requestedsignal,
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
	
	sdp_handle = find_dissector("sdp");
	
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
*		 character following offset or offset + maxlength -1 whichever
*		 is smaller.
*
* Parameters:
* tvb - The tvbuff in which we are skipping whitespaces, tab and end_of_line characters.
* offset - The offset in tvb from which we begin trying to skip whitespace.
*
* Returns: The position in tvb of the first non-whitespace
*/
static gint tvb_skip_wsp(tvbuff_t* tvb, gint offset ){
	gint counter = offset;
	gint end,tvb_len;
	guint8 tempchar;
	tvb_len = tvb_length(tvb);
	end = tvb_len;
	
	for(counter = offset; counter < end &&
		((tempchar = tvb_get_guint8(tvb,counter)) == ' ' ||
		tempchar == '\t'|| tempchar == '\n');counter++);
	return (counter);
}
static gint tvb_skip_wsp_return(tvbuff_t* tvb, gint offset){
	gint counter = offset;
	gint end;
	guint8 tempchar;
	end = 0;
	
	for(counter = offset; counter > end &&
		((tempchar = tvb_get_guint8(tvb,counter)) == ' ' ||
		tempchar == '\t'|| tempchar == '\n');counter--);
	counter++;
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

