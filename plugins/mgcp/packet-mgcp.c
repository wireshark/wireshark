/* packet-mgcp.c
 * Routines for mgcp packet disassembly
 * RFC 2705
 *
 * $Id: packet-mgcp.c,v 1.42 2003/09/05 07:44:49 jmayer Exp $
 *
 * Copyright (c) 2000 by Ed Warnicke <hagbard@physics.rutgers.edu>
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
#include <epan/conversation.h>
#include "packet-mgcp.h"

#include "plugins/plugin_api_defs.h"

#ifndef ENABLE_STATIC
G_MODULE_EXPORT const gchar version[] = VERSION;
#endif

#define TCP_PORT_MGCP_GATEWAY 2427
#define UDP_PORT_MGCP_GATEWAY 2427
#define TCP_PORT_MGCP_CALLAGENT 2727
#define UDP_PORT_MGCP_CALLAGENT 2727

void proto_reg_handoff_mgcp(void);


/* Define the mgcp proto */
static int proto_mgcp = -1;

/* Define many many headers for mgcp */
static int hf_mgcp_req = -1;
static int hf_mgcp_req_verb = -1;
static int hf_mgcp_req_endpoint = -1;
static int hf_mgcp_req_frame = -1;
static int hf_mgcp_rsp = -1;
static int hf_mgcp_rsp_frame = -1;
static int hf_mgcp_time = -1;
static int hf_mgcp_transid = -1;
static int hf_mgcp_version = -1;
static int hf_mgcp_rsp_rspcode = -1;
static int hf_mgcp_rsp_rspstring = -1;
static int hf_mgcp_param_rspack = -1;
static int hf_mgcp_param_bearerinfo = -1;
static int hf_mgcp_param_callid = -1;
static int hf_mgcp_param_connectionid = -1;
static int hf_mgcp_param_secondconnectionid = -1;
static int hf_mgcp_param_notifiedentity = -1;
static int hf_mgcp_param_requestid = -1;
static int hf_mgcp_param_localconnoptions = -1;
static int hf_mgcp_param_connectionmode = -1;
static int hf_mgcp_param_reqevents = -1;
static int hf_mgcp_param_restartmethod = -1;
static int hf_mgcp_param_restartdelay = -1;
static int hf_mgcp_param_signalreq  = -1;
static int hf_mgcp_param_digitmap = -1;
static int hf_mgcp_param_observedevent = -1;
static int hf_mgcp_param_connectionparam = -1;
static int hf_mgcp_param_reasoncode = -1;
static int hf_mgcp_param_eventstates = -1;
static int hf_mgcp_param_specificendpoint = -1;
static int hf_mgcp_param_secondendpointid = -1;
static int hf_mgcp_param_reqinfo = -1;
static int hf_mgcp_param_quarantinehandling = -1;
static int hf_mgcp_param_detectedevents = -1;
static int hf_mgcp_param_capabilities = -1;
static int hf_mgcp_param_extention = -1;
static int hf_mgcp_param_invalid = -1;
static int hf_mgcp_messagecount = -1;
static int hf_mgcp_dup = -1;
static int hf_mgcp_req_dup = -1;
static int hf_mgcp_rsp_dup = -1;

/*
 * Define the trees for mgcp
 * We need one for MGCP itself and one for the MGCP paramters
 */
static int ett_mgcp = -1;
static int ett_mgcp_param = -1;

/*
 * Define the tap for mgcp
 */
static int mgcp_tap = -1;

/*
 * Here are the global variables associated with
 * the various user definable characteristics of the dissection
 *
 * MGCP has two kinds of "agents", gateways and callagents.  Callagents
 * control gateways in a master/slave sort of arrangement.  Since gateways
 * and callagents have different well known ports and could both
 * operate under either udp or tcp we have rather a lot of port info to
 * specify.
 *
 * global_mgcp_raw_text determines whether we are going to display
 * the raw text of the mgcp message, much like the HTTP dissector does.
 *
 * global_mgcp_dissect_tree determines whether we are going to display
 * a detailed tree that expresses a somewhat more semantically meaningful
 * decode.
 */
static int global_mgcp_gateway_tcp_port = TCP_PORT_MGCP_GATEWAY;
static int global_mgcp_gateway_udp_port = UDP_PORT_MGCP_GATEWAY;
static int global_mgcp_callagent_tcp_port = TCP_PORT_MGCP_CALLAGENT;
static int global_mgcp_callagent_udp_port = UDP_PORT_MGCP_CALLAGENT;
static gboolean global_mgcp_raw_text = FALSE;
static gboolean global_mgcp_dissect_tree = TRUE;
static gboolean global_mgcp_message_count = FALSE;

/*
 * Variables to allow for proper deletion of dissector registration when
 * the user changes port from the gui.
 */
static int gateway_tcp_port = 0;
static int gateway_udp_port = 0;
static int callagent_tcp_port = 0;
static int callagent_udp_port = 0;

/* Some basic utility functions that are specific to this dissector */
static gboolean is_mgcp_verb(tvbuff_t *tvb, gint offset, gint maxlength);
static gboolean is_mgcp_rspcode(tvbuff_t *tvb, gint offset, gint maxlength);
static gint tvb_parse_param(tvbuff_t *tvb, gint offset, gint maxlength,
			    int** hf);

/*
 * The various functions that either dissect some
 * subpart of MGCP.  These aren't really proto dissectors but they
 * are written in the same style.
 */
static void dissect_mgcp_message(tvbuff_t *tvb, packet_info *pinfo,
				 proto_tree *tree,proto_tree *mgcp_tree, proto_tree *ti);
static void dissect_mgcp_firstline(tvbuff_t *tvb, packet_info *pinfo,
				   proto_tree *tree, mgcp_info_t *mi);
static void dissect_mgcp_params(tvbuff_t *tvb,
				proto_tree *tree);
static void mgcp_raw_text_add(tvbuff_t *tvb,
			      proto_tree *tree);

/*
 * Some functions which should be moved to a library
 * as I think that people may find them of general usefulness.
 */
static gint tvb_skip_wsp(tvbuff_t* tvb, gint offset, gint maxlength);
static gint tvb_find_null_line(tvbuff_t* tvb, gint offset, gint len,
			       gint* next_offset);
static gint tvb_find_dot_line(tvbuff_t* tvb, gint offset,
			      gint len, gint* next_offset);
static gboolean is_rfc2234_alpha(guint8 c);

static dissector_handle_t sdp_handle;


/*
 * Init Hash table stuff
 */

typedef struct _mgcp_call_info_key {
	guint32	transid;
	conversation_t *conversation;
} mgcp_call_info_key;

static GMemChunk *mgcp_call_info_key_chunk;

static GMemChunk *mgcp_call_info_value_chunk;

static GHashTable *mgcp_calls;

/* compare 2 keys */
static gint
mgcp_call_equal(gconstpointer k1, gconstpointer k2)
{
	const mgcp_call_info_key* key1 = (const mgcp_call_info_key*) k1;
	const mgcp_call_info_key* key2 = (const mgcp_call_info_key*) k2;

	return (key1->transid == key2->transid &&
	    key1->conversation == key2->conversation);
}


/* calculate a hash key */
static guint
mgcp_call_hash(gconstpointer k)
{
	const mgcp_call_info_key* key = (const mgcp_call_info_key*) k;

	return key->transid  + (guint32)(key->conversation);
}

/*
 * dissect_mgcp - The dissector for the Media Gateway Control Protocol
 */

static void
dissect_mgcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  gint sectionlen;
  guint32 num_messages;
  gint tvb_sectionend,tvb_sectionbegin, tvb_len, tvb_current_len;
  proto_tree *mgcp_tree, *ti;

  /* Initialize variables */
  tvb_sectionend = 0;
  tvb_sectionbegin = tvb_sectionend;
  sectionlen = 0;
  tvb_len = tvb_length(tvb);
  tvb_current_len  = tvb_len;
  num_messages = 0;
  mgcp_tree = NULL;
  ti = NULL;

  /*
   * Set the columns now, so that they'll be set correctly if we throw
   * an exception.  We can set them later as well....
   */
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_add_str(pinfo->cinfo, COL_PROTOCOL, "MGCP");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  /*
   * Check to see whether we're really dealing with MGCP by looking
   * for a valid MGCP verb or response code.  This isn't infallible,
   * but its cheap and its better than nothing.
   */
  if(is_mgcp_verb(tvb,0,tvb_len) || is_mgcp_rspcode(tvb,0,tvb_len)){

    /* Build the info tree if we've been given a root */
    if (tree || global_mgcp_message_count == TRUE) {
      /*
       * Loop through however many mgcp messages may be stuck in
       * this packet using piggybacking
       */
      do{
	num_messages++;
	if(tree){
	  /* Create out mgcp subtree */
	  ti = proto_tree_add_item(tree,proto_mgcp,tvb,0,0, FALSE);
	  mgcp_tree = proto_item_add_subtree(ti, ett_mgcp);
	}

	sectionlen = tvb_find_dot_line(tvb, tvb_sectionbegin, -1,
				       &tvb_sectionend);
	if( sectionlen != -1){
	  dissect_mgcp_message(tvb_new_subset(tvb, tvb_sectionbegin,
					      sectionlen, -1),
			       pinfo, tree, mgcp_tree,ti);
	  tvb_sectionbegin = tvb_sectionend;
	}
	else {
	  break;
	}
      } while(tvb_sectionend < tvb_len );
      if(mgcp_tree){
	proto_tree_add_uint_hidden(mgcp_tree, hf_mgcp_messagecount, tvb,
				   0 ,0 , num_messages);
      }
    }

    /*
     * Add our column information we do this after dissecting SDP
     * in order to prevent the column info changing to reflect the SDP.
     */
    tvb_sectionbegin = 0;
    if (check_col(pinfo->cinfo, COL_PROTOCOL)){
      if( global_mgcp_message_count == TRUE ){
	if(num_messages > 1){
	  col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "MGCP (%i messages)",num_messages);
	}
	else {
	  col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "MGCP (%i message)",num_messages);
	}
      }
      else {
	  col_add_str(pinfo->cinfo, COL_PROTOCOL, "MGCP");
      }
    }

    if (check_col(pinfo->cinfo, COL_INFO) ){
      sectionlen = tvb_find_line_end(tvb, tvb_sectionbegin,-1,
				     &tvb_sectionend,FALSE);
      col_prepend_fstr(pinfo->cinfo, COL_INFO, "%s",
		   tvb_format_text(tvb,tvb_sectionbegin,sectionlen));
    }
  }
}

static void
dissect_mgcp_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		     proto_tree *mgcp_tree, proto_tree *ti){

  /* Declare variables */
  gint sectionlen;
  gint tvb_sectionend,tvb_sectionbegin, tvb_len, tvb_current_len;
  tvbuff_t *next_tvb;
  static mgcp_info_t mi;

  /* Initialize variables */
  tvb_sectionend = 0;
  tvb_sectionbegin = tvb_sectionend;
  sectionlen = 0;
  tvb_len = tvb_length(tvb);
  tvb_current_len  = tvb_len;

  /*
   * Check to see whether we're really dealing with MGCP by looking
   * for a valid MGCP verb or response code.  This isn't infallible,
   * but its cheap and its better than nothing.
   */
  if(is_mgcp_verb(tvb,0,tvb_len) || is_mgcp_rspcode(tvb,0,tvb_len)){

    /* Build the info tree if we've been given a root */
    if (tree && mgcp_tree) {

      /* dissect first line */
      tvb_sectionbegin = 0;
      tvb_current_len = tvb_len;
      tvb_sectionend = tvb_sectionbegin;
      sectionlen = tvb_find_line_end(tvb,0,-1,&tvb_sectionend,FALSE);
      if( sectionlen > 0){
	dissect_mgcp_firstline(tvb_new_subset(tvb, tvb_sectionbegin,
					      sectionlen,-1), pinfo,
			       mgcp_tree, &mi);
      }
      tvb_sectionbegin = tvb_sectionend;

      /* dissect params */
      if(tvb_sectionbegin < tvb_len){
	sectionlen = tvb_find_null_line(tvb, tvb_sectionbegin, -1,
					&tvb_sectionend);
	dissect_mgcp_params(tvb_new_subset(tvb, tvb_sectionbegin,
					   sectionlen, -1),
			    mgcp_tree);
	tvb_sectionbegin = tvb_sectionend;
      }

      /* set the mgcp payload length correctly so we don't include the
       * encapsulated SDP
       */
      sectionlen = tvb_sectionend;
      proto_item_set_len(ti,sectionlen);

      /* Display the raw text of the mgcp message if desired */

      /* Do we want to display the raw text of our MGCP packet? */
      if(global_mgcp_raw_text)
	mgcp_raw_text_add(tvb, mgcp_tree);

      /* dissect sdp payload */
      if( tvb_sectionend < tvb_len && global_mgcp_dissect_tree == TRUE){
	next_tvb = tvb_new_subset(tvb, tvb_sectionend, -1, -1);
	call_dissector(sdp_handle, next_tvb, pinfo, tree);
      }
    }
  }
}


/*
 * Add the raw text of the message to the dissect tree if appropriate
 * preferences are specified.
 */

static void mgcp_raw_text_add(tvbuff_t *tvb, proto_tree *tree){

  gint tvb_linebegin,tvb_lineend,tvb_len,linelen;

  tvb_linebegin = 0;
  tvb_len = tvb_length(tvb);

  do {
    tvb_find_line_end(tvb,tvb_linebegin,-1,&tvb_lineend,FALSE);
    linelen = tvb_lineend - tvb_linebegin;
    proto_tree_add_text(tree, tvb, tvb_linebegin, linelen,
			"%s", tvb_format_text(tvb,tvb_linebegin,
					      linelen));
    tvb_linebegin = tvb_lineend;
  } while ( tvb_lineend < tvb_len );
}

/* Discard and init any state we've saved */

static void
mgcp_init_protocol(void)
{
	if (mgcp_calls != NULL) {
		g_hash_table_destroy(mgcp_calls);
		mgcp_calls = NULL;
	}
	if (mgcp_call_info_key_chunk != NULL) {
		g_mem_chunk_destroy(mgcp_call_info_key_chunk);
		mgcp_call_info_key_chunk = NULL;
	}
	if (mgcp_call_info_value_chunk != NULL) {
		g_mem_chunk_destroy(mgcp_call_info_value_chunk);
		mgcp_call_info_value_chunk = NULL;
	}

	mgcp_calls = g_hash_table_new(mgcp_call_hash, mgcp_call_equal);
	mgcp_call_info_key_chunk = g_mem_chunk_new("call_info_key_chunk",
	    sizeof(mgcp_call_info_key),
	    200 * sizeof(mgcp_call_info_key),
	    G_ALLOC_ONLY);
	mgcp_call_info_value_chunk = g_mem_chunk_new("call_info_value_chunk",
	    sizeof(mgcp_call_t),
	    200 * sizeof(mgcp_call_t),
	    G_ALLOC_ONLY);
}

/* Register all the bits needed with the filtering engine */

void
proto_register_mgcp(void)
{
  static hf_register_info hf[] = {
    { &hf_mgcp_req,
      { "Request", "mgcp.req", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"True if MGCP request", HFILL }},
    { &hf_mgcp_rsp,
      { "Response", "mgcp.rsp", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"TRUE if MGCP response", HFILL }},
    { &hf_mgcp_req_frame,
      {	"Request Frame", "mgcp.reqframe", FT_FRAMENUM, BASE_NONE, NULL, 0,
        "Request Frame", HFILL }},
    { &hf_mgcp_rsp_frame,
      {	"Response Frame", "mgcp.rspframe", FT_FRAMENUM, BASE_NONE, NULL, 0,
        "Response Frame", HFILL }},
    { &hf_mgcp_time,
      {	"Time from request", "mgcp.time", FT_RELATIVE_TIME, BASE_NONE, NULL, 0,
        "Timedelta between Request and Response", HFILL }},
    { &hf_mgcp_req_verb,
      { "Verb", "mgcp.req.verb", FT_STRING, BASE_DEC, NULL, 0x0,
	"Name of the verb", HFILL }},
    { &hf_mgcp_req_endpoint,
      { "Endpoint", "mgcp.req.endpoint", FT_STRING, BASE_DEC, NULL, 0x0,
	"Endpoint referenced by the message", HFILL }},
    { &hf_mgcp_transid,
      { "Transaction ID", "mgcp.transid", FT_STRING, BASE_DEC, NULL, 0x0,
	"Transaction ID of this message", HFILL }},
    { &hf_mgcp_version,
      { "Version", "mgcp.version", FT_STRING, BASE_DEC, NULL, 0x0,
	"MGCP Version", HFILL }},
    { &hf_mgcp_rsp_rspcode,
      { "Response Code", "mgcp.rsp.rspcode", FT_STRING, BASE_DEC, NULL, 0x0,
	"Response Code", HFILL }},
    { &hf_mgcp_rsp_rspstring,
      { "Response String", "mgcp.rsp.rspstring", FT_STRING, BASE_DEC, NULL,
	0x0, "Response String", HFILL }},
    { &hf_mgcp_param_rspack,
      { "ResponseAck (K)", "mgcp.param.rspack", FT_STRING, BASE_DEC, NULL,
	0x0, "Response Ack", HFILL }},
    { &hf_mgcp_param_bearerinfo,
      { "BearerInformation (B)", "mgcp.param.bearerinfo", FT_STRING, BASE_DEC,
	NULL, 0x0, "Bearer Information", HFILL }},
    { &hf_mgcp_param_callid,
      { "CallId (C)", "mgcp.param.callid", FT_STRING, BASE_DEC, NULL, 0x0,
	"Call Id", HFILL }},
    { &hf_mgcp_param_connectionid,
      {"ConnectionIdentifier (I)", "mgcp.param.connectionid", FT_STRING,
       BASE_DEC, NULL, 0x0, "Connection Identifier", HFILL }},
    { &hf_mgcp_param_secondconnectionid,
      { "SecondConnectionID (I2)", "mgcp.param.secondconnectionid", FT_STRING,
       BASE_DEC, NULL, 0x0, "Second Connection Identifier", HFILL }},
    { &hf_mgcp_param_notifiedentity,
      { "NotifiedEntity (N)", "mgcp.param.notifiedentity", FT_STRING, BASE_DEC,
	NULL, 0x0, "Notified Entity", HFILL }},
    { &hf_mgcp_param_requestid,
      { "RequestIdentifier (X)", "mgcp.param.requestid", FT_STRING, BASE_DEC,
	NULL, 0x0, "Request Identifier", HFILL }},
    { &hf_mgcp_param_localconnoptions,
      { "LocalConnectionOptions (L)", "mgcp.param.localconnectionoptions",
	FT_STRING, BASE_DEC, NULL, 0x0, "Local Connection Options", HFILL }},
    { &hf_mgcp_param_connectionmode,
      { "ConnectionMode (M)", "mgcp.param.connectionmode", FT_STRING, BASE_DEC,
	NULL, 0x0, "Connection Mode", HFILL }},
    { &hf_mgcp_param_reqevents,
      { "RequestedEvents (R)", "mgcp.param.reqevents", FT_STRING, BASE_DEC,
	NULL, 0x0, "Requested Events", HFILL }},
    { &hf_mgcp_param_signalreq,
      { "SignalRequests (S)", "mgcp.param.signalreq", FT_STRING, BASE_DEC,
	NULL, 0x0, "Signal Request", HFILL }},
    { &hf_mgcp_param_restartmethod,
      { "RestartMethod (RM)", "mgcp.param.restartmethod", FT_STRING, BASE_DEC,
	NULL, 0x0, "Restart Method", HFILL }},
    { &hf_mgcp_param_restartdelay,
      { "RestartDelay (RD)", "mgcp.param.restartdelay", FT_STRING, BASE_DEC,
	NULL, 0x0, "Restart Delay", HFILL }},
    { &hf_mgcp_param_digitmap,
      { "DigitMap (D)", "mgcp.param.digitmap", FT_STRING, BASE_DEC, NULL, 0x0,
	"Digit Map", HFILL }},
    { &hf_mgcp_param_observedevent,
      { "ObservedEvents (O)", "mgcp.param.observedevents", FT_STRING,
	BASE_DEC, NULL, 0x0, "Observed Events", HFILL }},
    { &hf_mgcp_param_connectionparam,
      { "ConnectionParameters (P)", "mgcp.param.connectionparam", FT_STRING,
	BASE_DEC, NULL, 0x0, "Connection Parameters", HFILL }},
    { &hf_mgcp_param_reasoncode,
      { "ReasonCode (E)", "mgcp.param.reasoncode", FT_STRING, BASE_DEC,
	NULL, 0x0, "Reason Code", HFILL }},
    { &hf_mgcp_param_eventstates,
      { "EventStates (ES)", "mgcp.param.eventstates", FT_STRING, BASE_DEC,
	NULL, 0x0, "Event States", HFILL }},
    { &hf_mgcp_param_specificendpoint,
      { "SpecificEndpointID (Z)", "mgcp.param.specificendpointid", FT_STRING,
	BASE_DEC, NULL, 0x0, "Specific Endpoint ID", HFILL }},
    { &hf_mgcp_param_secondendpointid,
      { "SecondEndpointID (Z2)", "mgcp.param.secondendpointid", FT_STRING,
	BASE_DEC, NULL, 0x0, "Second Endpoing ID", HFILL }},
    { &hf_mgcp_param_reqinfo,
      { "RequestedInfo (F)", "mgcp.param.reqinfo", FT_STRING, BASE_DEC,
	NULL, 0x0,"Requested Info", HFILL }},
    { &hf_mgcp_param_quarantinehandling,
      { "QuarantineHandling (Q)", "mgcp.param.quarantinehandling", FT_STRING,
	BASE_DEC, NULL, 0x0, "Quarantine Handling", HFILL }},
    { &hf_mgcp_param_detectedevents,
      { "DetectedEvents (T)", "mgcp.param.detectedevents", FT_STRING, BASE_DEC,
	NULL, 0x0, "Detected Events", HFILL }},
    { &hf_mgcp_param_capabilities,
      { "Capabilities (A)", "mgcp.param.capabilities", FT_STRING, BASE_DEC,
	NULL, 0x0, "Capabilities", HFILL }},
    { &hf_mgcp_param_extention,
      { "Extention Parameter (X-*)", "mgcp.param.extention", FT_STRING,
	BASE_DEC, NULL, 0x0, "Extension Parameter", HFILL }},
    { &hf_mgcp_param_invalid,
      { "Invalid Parameter", "mgcp.param.invalid", FT_STRING,
	BASE_DEC, NULL, 0x0, "Invalid Parameter", HFILL }},
    { &hf_mgcp_messagecount,
      { "MGCP Message Count", "mgcp.messagecount", FT_UINT32,
	BASE_DEC, NULL, 0x0, "Number of MGCP message in a packet", HFILL }},
    { &hf_mgcp_dup,
      {	"Duplicate Message", "mgcp.dup", FT_UINT32, BASE_DEC,
	NULL, 0, "Duplicate Message", HFILL }},
    { &hf_mgcp_req_dup,
      {	"Duplicate Request", "mgcp.req.dup", FT_UINT32, BASE_DEC,
	NULL, 0, "Duplicate Request", HFILL }},
    { &hf_mgcp_rsp_dup,
      {	"Duplicate Response", "mgcp.rsp.dup", FT_UINT32, BASE_DEC,
	NULL, 0, "Duplicate Response", HFILL }},
    /* Add more fields here */
  };
  static gint *ett[] = {
    &ett_mgcp,
    &ett_mgcp_param,
  };
  module_t *mgcp_module;

  proto_mgcp = proto_register_protocol("Media Gateway Control Protocol",
				       "MGCP", "mgcp");

  proto_register_field_array(proto_mgcp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_init_routine(&mgcp_init_protocol);

  /* Register our configuration options for , particularly our ports */

  mgcp_module = prefs_register_protocol(proto_mgcp, proto_reg_handoff_mgcp);

  prefs_register_uint_preference(mgcp_module, "tcp.gateway_port",
				 "MGCP Gateway TCP Port",
				 "Set the UDP port for gateway messages "
				 "(if other than the default of 2427)",
				 10, &global_mgcp_gateway_tcp_port);

  prefs_register_uint_preference(mgcp_module, "udp.gateway_port",
				 "MGCP Gateway UDP Port",
				 "Set the TCP port for gateway messages "
				 "(if other than the default of 2427)",
				 10, &global_mgcp_gateway_udp_port);

  prefs_register_uint_preference(mgcp_module, "tcp.callagent_port",
				 "MGCP Callagent TCP Port",
				 "Set the TCP port for callagent messages "
				 "(if other than the default of 2727)",
				 10, &global_mgcp_callagent_tcp_port);

  prefs_register_uint_preference(mgcp_module, "udp.callagent_port",
				 "MGCP Callagent UDP Port",
				 "Set the UDP port for callagent messages "
				 "(if other than the default of 2727)",
				 10, &global_mgcp_callagent_udp_port);


  prefs_register_bool_preference(mgcp_module, "display_raw_text",
                                 "Display raw text for MGCP message",
                                 "Specifies that the raw text of the "
                                 "MGCP message should be displayed "
				 "instead of (or in addition to) the "
				 "dissection tree",
                                 &global_mgcp_raw_text);

  prefs_register_bool_preference(mgcp_module, "display_dissect_tree",
                                 "Display tree dissection for MGCP message",
                                 "Specifies that the dissection tree of the "
                                 "MGCP message should be displayed "
				 "instead of (or in addition to) the "
				 "raw text",
                                 &global_mgcp_dissect_tree);

  prefs_register_bool_preference(mgcp_module, "display_mgcp_message_count",
                                 "Display the number of MGCP messages",
                                 "Display the number of MGCP messages "
                                 "found in a packet in the protocol column.",
                                 &global_mgcp_message_count);

  mgcp_tap = register_tap("mgcp");
}

/* The registration hand-off routine */
void
proto_reg_handoff_mgcp(void)
{
  static int mgcp_prefs_initialized = FALSE;
  static dissector_handle_t mgcp_handle;

  /*
   * Get a handle for the SDP dissector.
   */
  sdp_handle = find_dissector("sdp");

  if (!mgcp_prefs_initialized) {
    mgcp_handle = create_dissector_handle(dissect_mgcp, proto_mgcp);
    mgcp_prefs_initialized = TRUE;
  }
  else {
    dissector_delete("tcp.port", gateway_tcp_port, mgcp_handle);
    dissector_delete("udp.port", gateway_udp_port, mgcp_handle);
    dissector_delete("tcp.port", callagent_tcp_port, mgcp_handle);
    dissector_delete("udp.port", callagent_udp_port, mgcp_handle);
  }

  /* Set our port number for future use */

  gateway_tcp_port = global_mgcp_gateway_tcp_port;
  gateway_udp_port = global_mgcp_gateway_udp_port;

  callagent_tcp_port = global_mgcp_callagent_tcp_port;
  callagent_udp_port = global_mgcp_callagent_udp_port;

  dissector_add("tcp.port", global_mgcp_gateway_tcp_port, mgcp_handle);
  dissector_add("udp.port", global_mgcp_gateway_udp_port, mgcp_handle);
  dissector_add("tcp.port", global_mgcp_callagent_tcp_port, mgcp_handle);
  dissector_add("udp.port", global_mgcp_callagent_udp_port, mgcp_handle);

}

/*
 * is_mgcp_verb - A function for determining whether there is a
 *                MGCP verb at offset in tvb
 *
 * Parameter:
 * tvb - The tvbuff in which we are looking for an MGCP verb
 * offset - The offset in tvb at which we are looking for a MGCP verb
 * maxlength - The maximum distance from offset we may look for the
 *             characters that make up a MGCP verb.
 *
 * Return: TRUE if there is an MGCP verb at offset in tvb, otherwise FALSE
 */

static gboolean is_mgcp_verb(tvbuff_t *tvb, gint offset, gint maxlength){
  int returnvalue = FALSE;
  guint8 word[5];

  if(( maxlength >= 4) && tvb_get_nstringz0(tvb,offset,sizeof(word),word)){
    if (strncasecmp(word, "EPCF", 4) == 0 ||
	strncasecmp(word, "CRCX", 4) == 0 ||
	strncasecmp(word, "MDCX", 4) == 0 ||
	strncasecmp(word, "DLCX", 4) == 0 ||
	strncasecmp(word, "RQNT", 4) == 0 ||
	strncasecmp(word, "NTFY", 4) == 0 ||
	strncasecmp(word, "AUEP", 4) == 0 ||
	strncasecmp(word, "AUCX", 4) == 0 ||
	strncasecmp(word, "RSIP", 4) == 0 ||
	(word[0] == 'X' && is_rfc2234_alpha(word[1]) && is_rfc2234_alpha(word[2]) &&
	 is_rfc2234_alpha(word[3]))
	){
      returnvalue = TRUE;
    }
  }
  if( returnvalue && maxlength >= 5 &&
      (word[0] = tvb_get_guint8(tvb,4)) != ' ' && word[0] != '\t'){
    returnvalue = FALSE;
  }
  return returnvalue;
}

/*
 * is_mgcp_rspcode - A function for determining whether something which
 *                   looks roughly like a MGCP response code is at
 *                   offset in tvb
 *
 * Parameters:
 * tvb - The tvbuff in which we are looking for an MGCP response code
 * offset - The offset in tvb at which we are looking for a MGCP response code
 * maxlength - The maximum distance from offset we may look for the
 *             characters that make up a MGCP response code.
 *
 * Return: TRUE if there is an MGCP response code at offset in tvb,
 *         otherwise FALSE
 */

static gboolean is_mgcp_rspcode(tvbuff_t *tvb, gint offset, gint maxlength){
  int returnvalue = FALSE;
  guint8 word[4];
  if(maxlength >= 3){
    tvb_get_nstringz0(tvb,offset,sizeof(word),word);
    if( isdigit(word[0]) &&
	isdigit(word[1]) &&
	isdigit(word[2])){
      returnvalue = TRUE;
    }
  }
  if( returnvalue && maxlength >= 4 &&
      (word[0] = tvb_get_guint8(tvb,3)) != ' ' && word[0] != '\t'){
    returnvalue = FALSE;
  }
  return returnvalue;
}

/*
 * is_rfc2234_alpha - Indicates whether the character c is an alphabetical
 *                    character.  This function is used instead of
 *                    isalpha because isalpha may deviate from the rfc2234
 *                    definition of ALPHA in some locales.
 *
 * Parameter:
 * c - The character being checked for being an alphabetical character.
 *
 * Return: TRUE if c is an upper or lower case alphabetical character,
 *         FALSE otherwise.
 */

static gboolean is_rfc2234_alpha(guint8 c){
  int returnvalue = FALSE;
  if(( c <= 'Z' && c >= 'A' ) || (c <= 'z' && c >= 'a')){
    returnvalue = TRUE;
  }
  return returnvalue;
}

/*
 * tvb_parse_param - Parse the MGCP param into a type and a value.
 *
 * Parameters:
 * tvb - The tvbuff containing the MGCP param we are to parse.
 * offset - The offset in tvb at which we will begin looking for a
 *          MGCP parameter to parse.
 * len - The maximum distance from offset in tvb that we can look for
 *       an MGCP parameter to parse.
 * hf - The place to write a pointer to the integer representing the
 *      header field associated with the MGCP parameter parsed.
 *
 * Returns: The offset in tvb where the value of the MGCP parameter
 *          begins.
 */
static gint tvb_parse_param(tvbuff_t* tvb, gint offset, gint len, int** hf){
  gint returnvalue, tvb_current_offset,counter;
  guint8 tempchar;
  tvb_current_offset = offset;
  returnvalue = -1;
  *hf = NULL;
  if(len > 0){
    tempchar = tvb_get_guint8(tvb,tvb_current_offset);
    switch(tempchar){
    case 'K':
      *hf = &hf_mgcp_param_rspack;
      break;
    case 'B':
      *hf = &hf_mgcp_param_bearerinfo;
      break;
    case 'C':
      *hf = &hf_mgcp_param_callid;
      break;
    case 'I':
      tvb_current_offset++;
      if(len > (tvb_current_offset - offset) &&
	 (tempchar = tvb_get_guint8(tvb,tvb_current_offset)) == ':'){
	*hf = &hf_mgcp_param_connectionid;
	tvb_current_offset--;
      }
      else if ( tempchar == '2'){
	*hf = &hf_mgcp_param_secondconnectionid;
      }
      break;
    case 'N':
      *hf = &hf_mgcp_param_notifiedentity;
      break;
    case 'X':
      tvb_current_offset++;
      if(len > (tvb_current_offset - offset) &&
	 (tempchar = tvb_get_guint8(tvb,tvb_current_offset)) == ':'){
	*hf = &hf_mgcp_param_requestid;
      }
      else if(len > (tvb_current_offset - offset) && (
	 (tempchar = tvb_get_guint8(tvb,tvb_current_offset)) == '-' ||
	 tempchar == '+')){
	tvb_current_offset++;
	for(counter = 1;(counter <= 6) && (len > (counter + tvb_current_offset
						  - offset))
	      && ( is_rfc2234_alpha(tempchar =
				    tvb_get_guint8(tvb,
						   tvb_current_offset+counter))
		   || isdigit(tempchar));counter++);
	if(tempchar == ':'){
	  tvb_current_offset += counter;
	  *hf = &hf_mgcp_param_extention;
	}
      }
      tvb_current_offset--;
      break;
    case 'L':
      *hf = &hf_mgcp_param_localconnoptions;
      break;
    case 'M':
      *hf = &hf_mgcp_param_connectionmode;
      break;
    case 'R':
      tvb_current_offset++;
      if(len > (tvb_current_offset - offset) &&
	 (tempchar = tvb_get_guint8(tvb,tvb_current_offset)) == ':'){
	*hf = &hf_mgcp_param_reqevents;
	tvb_current_offset--;
      }
      else if ( tempchar == 'M'){
	*hf = &hf_mgcp_param_restartmethod;
      }
      else if ( tempchar == 'D'){
	*hf = &hf_mgcp_param_restartdelay;
      }
      break;
    case 'S':
      *hf = &hf_mgcp_param_signalreq;
      break;
    case 'D':
      *hf = &hf_mgcp_param_digitmap;
      break;
    case 'O':
      *hf = &hf_mgcp_param_observedevent;
      break;
    case 'P':
      *hf = &hf_mgcp_param_connectionparam;
      break;
    case 'E':
      tvb_current_offset++;
      if(len > (tvb_current_offset - offset) &&
	 (tempchar = tvb_get_guint8(tvb,tvb_current_offset)) == ':'){
	*hf = &hf_mgcp_param_reasoncode;
	tvb_current_offset--;
      }
      else if ( tempchar == 'S'){
	*hf = &hf_mgcp_param_eventstates;
      }
      break;
    case 'Z':
      tvb_current_offset++;
      if(len > (tvb_current_offset - offset) &&
	 (tempchar = tvb_get_guint8(tvb,tvb_current_offset)) == ':'){
	*hf = &hf_mgcp_param_specificendpoint;
	tvb_current_offset--;
      }
      else if ( tempchar == '2'){
	*hf = &hf_mgcp_param_secondendpointid;
      }
      break;
    case 'F':
      *hf = &hf_mgcp_param_reqinfo;
      break;

    case 'Q':
      *hf = &hf_mgcp_param_quarantinehandling;
      break;

    case 'T':
      *hf = &hf_mgcp_param_detectedevents;
      break;

    case 'A':
      *hf = &hf_mgcp_param_capabilities;
      break;
    default:
      *hf = &hf_mgcp_param_invalid;
      break;
    }

    tvb_current_offset++;
    if(*hf != NULL && len > (tvb_current_offset - offset) &&
       (tempchar = tvb_get_guint8(tvb,tvb_current_offset)) == ':'){
      tvb_current_offset++;
      tvb_current_offset = tvb_skip_wsp(tvb,tvb_current_offset,
					(len - tvb_current_offset + offset));
      returnvalue = tvb_current_offset;
    }
    else {
      *hf = &hf_mgcp_param_invalid;
    }
  }
  else{
    *hf = &hf_mgcp_param_invalid;
  }
  if(*hf == &hf_mgcp_param_invalid){
    returnvalue = offset;
  }
  return returnvalue;
}


/*
 * dissect_mgcp_firstline - Dissects the firstline of an MGCP message.
 *                          Adds the appropriate headers fields to
 *                          tree for the dissection of the first line
 *                          of an MGCP message.
 *
 * Parameters:
 * tvb - The tvb containing the first line of an MGCP message.  This
 *       tvb is presumed to ONLY contain the first line of the MGCP
 *       message.
 * pinfo - The packet info for the packet.  This is not really used
 *         by this function but is passed through so as to retain the
 *         style of a dissector.
 * tree - The tree from which to hang the structured information parsed
 *        from the first line of the MGCP message.
 */
static void dissect_mgcp_firstline(tvbuff_t *tvb, packet_info *pinfo,
				   proto_tree *tree, mgcp_info_t *mi){
  gint tvb_current_offset,tvb_previous_offset,tvb_len,tvb_current_len;
  gint tokennum, tokenlen;
  char *transid = NULL;
  char *code = NULL;
  mgcp_type_t mgcp_type = MGCP_OTHERS;
  conversation_t* conversation;
  mgcp_call_info_key mgcp_call_key;
  mgcp_call_info_key *new_mgcp_call_key = NULL;
  mgcp_call_t *mgcp_call = NULL;
  nstime_t delta;

  static address null_address = { AT_NONE, 0, NULL };
  proto_item* (*my_proto_tree_add_string)(proto_tree*, int, tvbuff_t*, gint,
					  gint, const char*);
  tvb_previous_offset = 0;
  tvb_len = tvb_length(tvb);
  tvb_current_len = tvb_len;
  tvb_current_offset = tvb_previous_offset;
  mi->is_duplicate = FALSE;
  mi->request_available = FALSE;

  if(tree){
    tokennum = 0;

    if(global_mgcp_dissect_tree){
      my_proto_tree_add_string = proto_tree_add_string;
    }
    else{
      my_proto_tree_add_string = proto_tree_add_string_hidden;
    }

    do {
      tvb_current_len = tvb_length_remaining(tvb,tvb_previous_offset);
      tvb_current_offset = tvb_find_guint8(tvb, tvb_previous_offset,
					   tvb_current_len, ' ');
      if(tvb_current_offset == -1){
	tvb_current_offset = tvb_len;
	tokenlen = tvb_current_len;
      }
      else{
	tokenlen = tvb_current_offset - tvb_previous_offset;
      }
      if(tokennum == 0){
        code = tvb_format_text(tvb,tvb_previous_offset,tokenlen);
        strncpy(mi->code,code,4);
        mi->code[4] = '\0';
	if(is_mgcp_verb(tvb,tvb_previous_offset,tvb_current_len)){
	  mgcp_type = MGCP_REQUEST;
	  my_proto_tree_add_string(tree,hf_mgcp_req_verb, tvb,
				   tvb_previous_offset, tokenlen,
				   code);
	}
	else if (is_mgcp_rspcode(tvb,tvb_previous_offset,tvb_current_len)){
	  mgcp_type = MGCP_RESPONSE;
	  my_proto_tree_add_string(tree,hf_mgcp_rsp_rspcode, tvb,
				   tvb_previous_offset, tokenlen,
				   code);
	}
	else {
	  break;
	}
      }
      if(tokennum == 1){
        transid = tvb_format_text(tvb,tvb_previous_offset,tokenlen);
        /* XXX - what if this isn't a valid text string? */
        mi->transid = atol(transid);
	my_proto_tree_add_string(tree,hf_mgcp_transid, tvb,
				 tvb_previous_offset, tokenlen,
				 transid);
      }
      if(tokennum == 2){
	if(mgcp_type == MGCP_REQUEST){
	  my_proto_tree_add_string(tree,hf_mgcp_req_endpoint, tvb,
				   tvb_previous_offset, tokenlen,
				   tvb_format_text(tvb, tvb_previous_offset,
						   tokenlen));
	}
	else if(mgcp_type == MGCP_RESPONSE){
	  if(tvb_current_offset < tvb_len){
	    tokenlen = tvb_find_line_end(tvb, tvb_previous_offset,
					 -1,&tvb_current_offset,FALSE);
	  }
	  else{
	    tokenlen = tvb_current_len;
	  }
	  my_proto_tree_add_string(tree, hf_mgcp_rsp_rspstring, tvb,
				   tvb_previous_offset, tokenlen,
				   tvb_format_text(tvb, tvb_previous_offset,
						   tokenlen));
	  break;
	}
      }
      if( (tokennum == 3 && mgcp_type == MGCP_REQUEST) ){
	if(tvb_current_offset < tvb_len ){
	  tokenlen = tvb_find_line_end(tvb, tvb_previous_offset,
				       -1,&tvb_current_offset,FALSE);
	}
	else{
	  tokenlen = tvb_current_len;
	}
	my_proto_tree_add_string(tree,hf_mgcp_version, tvb,
				 tvb_previous_offset, tokenlen,
				 tvb_format_text(tvb,tvb_previous_offset,
						 tokenlen));
	break;
      }
      if(tvb_current_offset < tvb_len){
	tvb_previous_offset = tvb_skip_wsp(tvb, tvb_current_offset,
					   tvb_current_len);
      }
      tokennum++;
    } while( tvb_current_offset < tvb_len && tvb_previous_offset < tvb_len
	     && tokennum <= 3);

    switch (mgcp_type){
    case MGCP_RESPONSE:
	proto_tree_add_boolean_hidden(tree, hf_mgcp_rsp, tvb, 0, 0, TRUE);
	/* Check for MGCP response.  A response must match a call that
	   we've seen, and the response must be sent to the same
	   port and address that the call came from, and must
	   come from the port to which the call was sent.

	   If the transport is connection-oriented (we check, for
	   now, only for "pinfo->ptype" of PT_TCP), we take
	   into account the address from which the call was sent
	   and the address to which the call was sent, because
	   the addresses of the two endpoints should be the same
	   for all calls and replies.

	   If the transport is connectionless, we don't worry
	   about the address to which the call was sent and from
	   which the reply was sent, because there's no
	   guarantee that the reply will come from the address
	   to which the call was sent. */
	if (pinfo->ptype == PT_TCP) {
		conversation = find_conversation(&pinfo->src,
		    &pinfo->dst, pinfo->ptype, pinfo->srcport,
		    pinfo->destport, 0);
	} else {
		/*
		 * XXX - can we just use NO_ADDR_B?  Unfortunately,
		 * you currently still have to pass a non-null
		 * pointer for the second address argument even
		 * if you do that.
		 */
		conversation = find_conversation(&null_address,
		    &pinfo->dst, pinfo->ptype, pinfo->srcport,
		    pinfo->destport, 0);
	}
	if (conversation != NULL) {
		/* look only for matching request, if
		   matching conversation is available. */
		mgcp_call_key.transid = mi->transid;
		mgcp_call_key.conversation = conversation;
		mgcp_call = g_hash_table_lookup(mgcp_calls, &mgcp_call_key);
		if(mgcp_call) {
			/* Indicate the frame to which this is a reply. */
			if(mgcp_call->req_num){
				mi->request_available = TRUE;
				mgcp_call->responded = TRUE;
				strcpy(mi->code,mgcp_call->code);
				proto_tree_add_uint_format(tree, hf_mgcp_req_frame,
				    tvb, 0, 0, mgcp_call->req_num,
				    "This is a response to a request in frame %u",
				    mgcp_call->req_num);
				delta.secs= pinfo->fd->abs_secs-mgcp_call->req_time.secs;
				delta.nsecs=pinfo->fd->abs_usecs*1000-mgcp_call->req_time.nsecs;
				if(delta.nsecs<0){
					delta.nsecs+=1000000000;
					delta.secs--;
				}
				proto_tree_add_time(tree, hf_mgcp_time, tvb, 0, 0,
					&delta);
			}

			if (mgcp_call->rsp_num == 0) {
				/* We have not yet seen a response to that call, so
				   this must be the first response; remember its
				   frame number. */
				mgcp_call->rsp_num = pinfo->fd->num;
			} else {
				/* We have seen a response to this call - but was it
				   *this* response? */
				if (mgcp_call->rsp_num != pinfo->fd->num) {
					/* No, so it's a duplicate response.
					   Mark it as such. */
					mi->is_duplicate = TRUE;
					if (check_col(pinfo->cinfo, COL_INFO)) {
						col_append_fstr(pinfo->cinfo, COL_INFO,
							", Duplicate Response %u",mi->transid);
						if (tree) {
							proto_tree_add_uint_hidden(tree,
								hf_mgcp_dup, tvb, 0,0, mi->transid);
							proto_tree_add_uint_hidden(tree,
								hf_mgcp_rsp_dup, tvb, 0,0, mi->transid);
						}
					}
				}
			}
		}
	}
      break;
    case MGCP_REQUEST:
	proto_tree_add_boolean_hidden(tree, hf_mgcp_req, tvb, 0, 0, TRUE);
	/* Keep track of the address and port whence the call came,
	   and the port to which the call is being sent, so that
	   we can match up calls with replies.

	   If the transport is connection-oriented (we check, for
	   now, only for "pinfo->ptype" of PT_TCP), we take
	   into account the address from which the call was sent
	   and the address to which the call was sent, because
	   the addresses of the two endpoints should be the same
	   for all calls and replies.

	   If the transport is connectionless, we don't worry
	   about the address to which the call was sent and from
	   which the reply was sent, because there's no
	   guarantee that the reply will come from the address
	   to which the call was sent. */
	if (pinfo->ptype == PT_TCP) {
		conversation = find_conversation(&pinfo->src,
		    &pinfo->dst, pinfo->ptype, pinfo->srcport,
		    pinfo->destport, 0);
	} else {
		/*
		 * XXX - can we just use NO_ADDR_B?  Unfortunately,
		 * you currently still have to pass a non-null
		 * pointer for the second address argument even
		 * if you do that.
		 */
		conversation = find_conversation(&pinfo->src,
		    &null_address, pinfo->ptype, pinfo->srcport,
		    pinfo->destport, 0);
	}
	if (conversation == NULL) {
		/* It's not part of any conversation - create a new
		   one. */
		if (pinfo->ptype == PT_TCP) {
			conversation = conversation_new(&pinfo->src,
			    &pinfo->dst, pinfo->ptype, pinfo->srcport,
			    pinfo->destport, 0);
		} else {
			conversation = conversation_new(&pinfo->src,
			    &null_address, pinfo->ptype, pinfo->srcport,
			    pinfo->destport, 0);
		}
	}

	/* prepare the key data */
	mgcp_call_key.transid = mi->transid;
	mgcp_call_key.conversation = conversation;

	/* look up the request */
	mgcp_call = g_hash_table_lookup(mgcp_calls, &mgcp_call_key);
	if (mgcp_call != NULL) {
		/* We've seen a request with this TRANSID, with the same
		   source and destination, before - but was it
		   *this* request? */
		if (pinfo->fd->num != mgcp_call->req_num) {
			/* No, so it's a duplicate request.
			   Mark it as such. */
			mi->is_duplicate = TRUE;
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO,
					", Duplicate Request %u",mi->transid);
				if (tree) {
					proto_tree_add_uint_hidden(tree,
						hf_mgcp_dup, tvb, 0,0, mi->transid);
					proto_tree_add_uint_hidden(tree,
						hf_mgcp_req_dup, tvb, 0,0, mi->transid);
				}
			}
		}
	}
	else {
		/* Prepare the value data.
		   "req_num" and "rsp_num" are frame numbers;
		   frame numbers are 1-origin, so we use 0
		   to mean "we don't yet know in which frame
		   the reply for this call appears". */
		new_mgcp_call_key = g_mem_chunk_alloc(mgcp_call_info_key_chunk);
		*new_mgcp_call_key = mgcp_call_key;
		mgcp_call = g_mem_chunk_alloc(mgcp_call_info_value_chunk);
		mgcp_call->req_num = pinfo->fd->num;
		mgcp_call->rsp_num = 0;
		mgcp_call->transid = mi->transid;
		mgcp_call->responded = FALSE;
		mgcp_call->req_time.secs=pinfo->fd->abs_secs;
		mgcp_call->req_time.nsecs=pinfo->fd->abs_usecs*1000;
		strcpy(mgcp_call->code,mi->code);

		/* store it */
		g_hash_table_insert(mgcp_calls, new_mgcp_call_key, mgcp_call);
	}
	if(mgcp_call && mgcp_call->rsp_num){
		proto_tree_add_uint_format(tree, hf_mgcp_rsp_frame,
		    tvb, 0, 0, mgcp_call->rsp_num,
		    "The response to this request is in frame %u",
		    mgcp_call->rsp_num);
	}
      break;
    default:
      break;
    }
    mi->mgcp_type = mgcp_type;
    if(mgcp_call) {
    	mi->req_time.secs=mgcp_call->req_time.secs;
    	mi->req_time.nsecs=mgcp_call->req_time.nsecs;
    }
  }
  tap_queue_packet(mgcp_tap, pinfo, mi);
}

/*
 * dissect_mgcp_params - Dissects the parameters of an MGCP message.
 *                       Adds the appropriate headers fields to
 *                       tree for the dissection of the parameters
 *                       of an MGCP message.
 *
 * Parameters:
 * tvb - The tvb containing the parameters of an MGCP message.  This
 *       tvb is presumed to ONLY contain the part of the MGCP
 *       message which contains the MGCP parameters.
 * pinfo - The packet info for the packet.  This is not really used
 *         by this function but is passed through so as to retain the
 *         style of a dissector.
 * tree - The tree from which to hang the structured information parsed
 *        from the parameters of the MGCP message.
 */
static void dissect_mgcp_params(tvbuff_t *tvb, proto_tree *tree){
  int linelen, tokenlen, *my_param;
  gint tvb_lineend,tvb_current_len, tvb_linebegin,tvb_len;
  gint tvb_tokenbegin;
  proto_tree *mgcp_param_ti, *mgcp_param_tree;
  proto_item* (*my_proto_tree_add_string)(proto_tree*, int, tvbuff_t*, gint,
					  gint, const char*);

  tvb_len = tvb_length(tvb);
  tvb_linebegin = 0;
  tvb_current_len = tvb_length_remaining(tvb,tvb_linebegin);
  tvb_lineend = tvb_linebegin;

  if(tree){
    if(global_mgcp_dissect_tree){
      my_proto_tree_add_string = proto_tree_add_string;
      mgcp_param_ti = proto_tree_add_item(tree, proto_mgcp, tvb,
					  tvb_linebegin, tvb_len, FALSE);
      proto_item_set_text(mgcp_param_ti, "Parameters");
      mgcp_param_tree = proto_item_add_subtree(mgcp_param_ti, ett_mgcp_param);
    }
    else{
      my_proto_tree_add_string = proto_tree_add_string_hidden;
      mgcp_param_tree = tree;
      mgcp_param_ti = NULL;
    }

    /* Parse the parameters */
    while(tvb_lineend < tvb_len){
      linelen = tvb_find_line_end(tvb, tvb_linebegin, -1,&tvb_lineend,FALSE);
      tvb_tokenbegin = tvb_parse_param(tvb, tvb_linebegin, linelen,
				       &my_param);
      if( my_param != NULL ){
	tokenlen = tvb_find_line_end(tvb,tvb_tokenbegin,-1,&tvb_lineend,FALSE);
	my_proto_tree_add_string(mgcp_param_tree,*my_param, tvb,
				 tvb_linebegin, linelen,
				 tvb_format_text(tvb,tvb_tokenbegin,
						 tokenlen));
      }
      tvb_linebegin = tvb_lineend;
    }
  }
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
  gint end = offset + maxlength,tvb_len;
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

/*
 * tvb_find_null_line - Returns the length from offset to the first null
 *                      line found (a null line is a line that begins
 *                      with a CR or LF.  The offset to the first character
 *                      after the null line is written into the gint pointed
 *                      to by next_offset.
 *
 * Parameters:
 * tvb - The tvbuff in which we are looking for a null line.
 * offset - The offset in tvb at which we will begin looking for
 *          a null line.
 * len - The maximum distance from offset in tvb that we will look for
 *       a null line.  If it is -1 we will look to the end of the buffer.
 *
 * next_offset - The location to write the offset of first character
 *               FOLLOWING the null line.
 *
 * Returns: The length from offset to the first character BEFORE
 *          the null line..
 */
static gint tvb_find_null_line(tvbuff_t* tvb, gint offset,
			       gint len, gint* next_offset){
  gint tvb_lineend,tvb_current_len,tvb_linebegin,maxoffset;
  guint tempchar;

  tvb_linebegin = offset;
  tvb_lineend = tvb_linebegin;

  /* Simple setup to allow for the traditional -1 search to the end
   * of the tvbuff
   */
  if(len != -1){
    tvb_current_len = len;
  }
  else{
    tvb_current_len = tvb_length_remaining(tvb,offset);
  }
  maxoffset = (tvb_current_len - 1) + offset;

  /*
   * Loop around until we either find a line begining with a carriage return
   * or newline character or until we hit the end of the tvbuff.
   */
  do {
    tvb_linebegin = tvb_lineend;
    tvb_current_len = tvb_length_remaining(tvb,tvb_linebegin);
    tvb_find_line_end(tvb, tvb_linebegin, tvb_current_len, &tvb_lineend,FALSE);
    tempchar = tvb_get_guint8(tvb,tvb_linebegin);
  }
  while( tempchar != '\r' && tempchar != '\n' &&
	 tvb_lineend <= maxoffset);

  *next_offset = tvb_lineend;

  if( tvb_lineend <= maxoffset ) {
    tvb_current_len = tvb_linebegin - offset;
  }
  else {
    tvb_current_len = tvb_length_remaining(tvb,offset);
  }

  return (tvb_current_len);
}

/*
 * tvb_find_dot_line -  Returns the length from offset to the first line
 *                      containing only a dot (.) character.  A line
 *                      containing only a dot is used to indicate a
 *                      separation between multiple MGCP messages
 *                      piggybacked in the same UDP packet.
 *
 * Parameters:
 * tvb - The tvbuff in which we are looking for a dot line.
 * offset - The offset in tvb at which we will begin looking for
 *          a dot line.
 * len - The maximum distance from offset in tvb that we will look for
 *       a dot line.  If it is -1 we will look to the end of the buffer.
 *
 * next_offset - The location to write the offset of first character
 *               FOLLOWING the dot line.
 *
 * Returns: The length from offset to the first character BEFORE
 *          the dot line or -1 if the character at offset is a .
 *          followed by a newline or a carriage return.
 */
static gint tvb_find_dot_line(tvbuff_t* tvb, gint offset,
			       gint len, gint* next_offset){
  gint tvb_current_offset, tvb_current_len, maxoffset,tvb_len;
  guint8 tempchar;

  tvb_current_offset = offset;
  tvb_current_len = len;
  tvb_len = tvb_length(tvb);

  if(len == -1){
    maxoffset = ( tvb_len - 1 );
  }
  else {
    maxoffset = (len - 1 ) + offset;
  }
  tvb_current_offset = offset -1;
  do {
    tvb_current_offset = tvb_find_guint8(tvb, tvb_current_offset+1,
					 tvb_current_len, '.');
    tvb_current_len = maxoffset - tvb_current_offset + 1;
    /*
     * if we didn't find a . then break out of the loop
     */
    if(tvb_current_offset == -1){
      break;
    }
    /* do we have and characters following the . ? */
    if( tvb_current_offset < maxoffset ) {
      tempchar = tvb_get_guint8(tvb,tvb_current_offset+1);
      /*
       * are the characters that follow the dot a newline or carriage return ?
       */
      if(tempchar == '\r' || tempchar == '\n'){
	/*
	 * do we have any charaters that proceed the . ?
	 */
	if( tvb_current_offset == 0 ){
	  break;
	}
	else {
	  tempchar = tvb_get_guint8(tvb,tvb_current_offset-1);
	  /*
	   * are the characters that follow the dot a newline or a carriage
	   * return ?
	   */
	  if(tempchar == '\r' || tempchar == '\n'){
	    break;
	  }
	}
      }
    }
    else if ( tvb_current_offset == maxoffset ) {
      if( tvb_current_offset == 0 ){
	break;
      }
      else {
	tempchar = tvb_get_guint8(tvb,tvb_current_offset-1);
	if(tempchar == '\r' || tempchar == '\n'){
	  break;
	}
      }
    }
  } while (tvb_current_offset < maxoffset);
  /*
   * so now we either have the tvb_current_offset of a . in a dot line
   * or a tvb_current_offset of -1
   */
  if(tvb_current_offset == -1){
    tvb_current_offset = maxoffset +1;
    *next_offset = maxoffset + 1;
  }
  else {
    tvb_find_line_end(tvb,tvb_current_offset,tvb_current_len,next_offset,FALSE);
  }

  if( tvb_current_offset == offset ){
    tvb_current_len = -1;
  }
  else {
    tvb_current_len = tvb_current_offset - offset;
  }
  return tvb_current_len;
}

/* Start the functions we need for the plugin stuff */

#ifndef ENABLE_STATIC

G_MODULE_EXPORT void
plugin_reg_handoff(void){
  proto_reg_handoff_mgcp();
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
  if (proto_mgcp == -1) { /* execute protocol initialization only once */
    proto_register_mgcp();
  }
}

#endif

/* End the functions we need for plugin stuff */
