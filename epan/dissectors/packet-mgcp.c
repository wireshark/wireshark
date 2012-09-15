/* packet-mgcp.c
 * Routines for mgcp packet disassembly
 * RFC 2705
 * RFC 3435 (obsoletes 2705): Media Gateway Control Protocol (MGCP) Version 1.0
 * RFC 3660: Basic MGCP Packages
 * RFC 3661: MGCP Return Code Usage
 * NCS 1.0: PacketCable Network-Based Call Signaling Protocol Specification,
 *          PKT-SP-EC-MGCP-I09-040113, January 13, 2004, Cable Television
 *          Laboratories, Inc., http://www.PacketCable.com/
 * www.iana.org/assignments/mgcp-localconnectionoptions
 *
 * $Id$
 *
 * Copyright (c) 2000 by Ed Warnicke <hagbard@physics.rutgers.edu>
 * Copyright (c) 2004 by Thomas Anders <thomas.anders [AT] blue-cable.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/tap.h>
#include <epan/strutil.h>
#include "packet-mgcp.h"


#define TCP_PORT_MGCP_GATEWAY 2427
#define UDP_PORT_MGCP_GATEWAY 2427
#define TCP_PORT_MGCP_CALLAGENT 2727
#define UDP_PORT_MGCP_CALLAGENT 2727


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
static int hf_mgcp_params = -1;
static int hf_mgcp_param_rspack = -1;
static int hf_mgcp_param_bearerinfo = -1;
static int hf_mgcp_param_callid = -1;
static int hf_mgcp_param_connectionid = -1;
static int hf_mgcp_param_secondconnectionid = -1;
static int hf_mgcp_param_notifiedentity = -1;
static int hf_mgcp_param_requestid = -1;
static int hf_mgcp_param_localconnoptions = -1;
static int hf_mgcp_param_localconnoptions_p = -1;
static int hf_mgcp_param_localconnoptions_a = -1;
static int hf_mgcp_param_localconnoptions_s = -1;
static int hf_mgcp_param_localconnoptions_e = -1;
static int hf_mgcp_param_localconnoptions_scrtp = -1;
static int hf_mgcp_param_localconnoptions_scrtcp = -1;
static int hf_mgcp_param_localconnoptions_b = -1;
static int hf_mgcp_param_localconnoptions_esccd = -1;
static int hf_mgcp_param_localconnoptions_escci = -1;
static int hf_mgcp_param_localconnoptions_dqgi = -1;
static int hf_mgcp_param_localconnoptions_dqrd = -1;
static int hf_mgcp_param_localconnoptions_dqri = -1;
static int hf_mgcp_param_localconnoptions_dqrr = -1;
static int hf_mgcp_param_localconnoptions_k = -1;
static int hf_mgcp_param_localconnoptions_gc = -1;
static int hf_mgcp_param_localconnoptions_fmtp = -1;
static int hf_mgcp_param_localconnoptions_nt = -1;
static int hf_mgcp_param_localconnoptions_ofmtp = -1;
static int hf_mgcp_param_localconnoptions_r = -1;
static int hf_mgcp_param_localconnoptions_t = -1;
static int hf_mgcp_param_localconnoptions_rcnf = -1;
static int hf_mgcp_param_localconnoptions_rdir = -1;
static int hf_mgcp_param_localconnoptions_rsh = -1;
static int hf_mgcp_param_connectionmode = -1;
static int hf_mgcp_param_reqevents = -1;
static int hf_mgcp_param_restartmethod = -1;
static int hf_mgcp_param_restartdelay = -1;
static int hf_mgcp_param_signalreq  = -1;
static int hf_mgcp_param_digitmap = -1;
static int hf_mgcp_param_observedevent = -1;
static int hf_mgcp_param_connectionparam = -1;
static int hf_mgcp_param_connectionparam_ps = -1;
static int hf_mgcp_param_connectionparam_os = -1;
static int hf_mgcp_param_connectionparam_pr = -1;
static int hf_mgcp_param_connectionparam_or = -1;
static int hf_mgcp_param_connectionparam_pl = -1;
static int hf_mgcp_param_connectionparam_ji = -1;
static int hf_mgcp_param_connectionparam_la = -1;
static int hf_mgcp_param_connectionparam_pcrps = -1;
static int hf_mgcp_param_connectionparam_pcros = -1;
static int hf_mgcp_param_connectionparam_pcrpl = -1;
static int hf_mgcp_param_connectionparam_pcrji = -1;
static int hf_mgcp_param_connectionparam_x = -1;
static int hf_mgcp_param_reasoncode = -1;
static int hf_mgcp_param_eventstates = -1;
static int hf_mgcp_param_specificendpoint = -1;
static int hf_mgcp_param_secondendpointid = -1;
static int hf_mgcp_param_reqinfo = -1;
static int hf_mgcp_param_quarantinehandling = -1;
static int hf_mgcp_param_detectedevents = -1;
static int hf_mgcp_param_capabilities = -1;
static int hf_mgcp_param_maxmgcpdatagram = -1;
static int hf_mgcp_param_packagelist = -1;
static int hf_mgcp_param_extension = -1;
static int hf_mgcp_param_extension_critical = -1;
static int hf_mgcp_param_invalid = -1;
static int hf_mgcp_messagecount = -1;
static int hf_mgcp_dup = -1;
static int hf_mgcp_req_dup = -1;
static int hf_mgcp_req_dup_frame = -1;
static int hf_mgcp_rsp_dup = -1;
static int hf_mgcp_rsp_dup_frame = -1;

static const value_string mgcp_return_code_vals[] = {
	{000, "Response Acknowledgement"},
	{100, "The transaction is currently being executed.  An actual completion message will follow on later."},
	{101, "The transaction has been queued for execution.  An actual completion message will follow later."},
	{200, "The requested transaction was executed normally."},
	{250, "The connection was deleted."},
	{400, "The transaction could not be executed, due to a transient error."},
	{401, "The phone is already off hook"},
	{402, "The phone is already on hook"},
	{403, "The transaction could not be executed, because the endpoint does not have sufficient resources at this time"},
	{404, "Insufficient bandwidth at this time"},
	{405, "The transaction could not be executed, because the endpoint is \"restarting\"."},
	{406, "Transaction time-out.  The transaction did not complete in a reasonable period of time and has been aborted."},
	{407, "Transaction aborted.  The transaction was aborted by some external action, e.g., a ModifyConnection command aborted by a DeleteConnection command."},
	{409, "The transaction could not be executed because of internal overload."},
	{410, "No endpoint available.  A valid \"any of\" wildcard was used, however there was no endpoint available to satisfy the request."},
	{500, "The transaction could not be executed, because the endpoint is unknown."},
	{501, "The transaction could not be executed, because the endpoint is not ready."},
	{502, "The transaction could not be executed, because the endpoint does not have sufficient resources"},
	{503, "\"All of\" wildcard too complicated."},
	{504, "Unknown or unsupported command."},
	{505, "Unsupported RemoteConnectionDescriptor."},
	{506, "Unable to satisfy both LocalConnectionOptions and RemoteConnectionDescriptor."},
	{507, "Unsupported functionality."},
	{508, "Unknown or unsupported quarantine handling."},
	{509, "Error in RemoteConnectionDescriptor."},
	{510, "The transaction could not be executed, because a protocol error was detected."},
	{511, "The transaction could not be executed, because the command contained an unrecognized extension."},
	{512, "The transaction could not be executed, because the gateway is not equipped to detect one of the requested events."},
	{513, "The transaction could not be executed, because the gateway is not equipped to generate one of the requested signals."},
	{514, "The transaction could not be executed, because the gateway cannot send the specified announcement."},
	{515, "The transaction refers to an incorrect connection-id (may have been already deleted)"},
	{516, "The transaction refers to an unknown call-id."},
	{517, "Unsupported or invalid mode."},
	{518, "Unsupported or unknown package."},
	{519, "Endpoint does not have a digit map."},
	{520, "The transaction could not be executed, because the endpoint is 'restarting'."},
	{521, "Endpoint redirected to another Call Agent."},
	{522, "No such event or signal."},
	{523, "Unknown action or illegal combination of actions"},
	{524, "Internal inconsistency in LocalConnectionOptions"},
	{525, "Unknown extension in LocalConnectionOptions"},
	{526, "Insufficient bandwidth"},
	{527, "Missing RemoteConnectionDescriptor"},
	{528, "Incompatible protocol version"},
	{529, "Internal hardware failure"},
	{530, "CAS signaling protocol error."},
	{531, "failure of a grouping of trunks (e.g. facility failure)."},
	{532, "Unsupported value(s) in LocalConnectionOptions."},
	{533, "Response too large."},
	{534, "Codec negotiation failure."},
	{535, "Packetization period not supported"},
	{536, "Unknown or unsupported RestartMethod"},
	{537, "Unknown or unsupported digit map extension"},
	{538, "Event/signal parameter error (e.g., missing, erroneous, unsupported, unknown, etc.)"},
	{539, "Invalid or unsupported command parameter."},
	{540, "Per endpoint connection limit exceeded."},
	{541, "Invalid or unsupported LocalConnectionOptions"},
	{0,   NULL }
};

/* TODO: add/use when tested/have capture to test with */
/*
static const value_string mgcp_reason_code_vals[] = {
	{0,   "Endpoint state is normal"},
	{900, "Endpoint malfunctioning."},
	{901, "Endpoint taken out-of-service."},
	{902, "Loss of lower layer connectivity (e.g., downstream sync)."},
	{903, "QoS resource reservation was lost."},
	{904, "Manual intervention."},
	{905, "Facility failure (e.g., DS-0 failure)."},
	{0,   NULL }
};
*/


/*
 * Define the trees for mgcp
 * We need one for MGCP itself, one for the MGCP paramters and one
 * for each of the dissected parameters
 */
static int ett_mgcp = -1;
static int ett_mgcp_param = -1;
static int ett_mgcp_param_connectionparam = -1;
static int ett_mgcp_param_localconnectionoptions = -1;

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
 */
static guint global_mgcp_gateway_tcp_port = TCP_PORT_MGCP_GATEWAY;
static guint global_mgcp_gateway_udp_port = UDP_PORT_MGCP_GATEWAY;
static guint global_mgcp_callagent_tcp_port = TCP_PORT_MGCP_CALLAGENT;
static guint global_mgcp_callagent_udp_port = UDP_PORT_MGCP_CALLAGENT;
static gboolean global_mgcp_raw_text = FALSE;
static gboolean global_mgcp_message_count = FALSE;

/* Some basic utility functions that are specific to this dissector */
static gboolean is_mgcp_verb(tvbuff_t *tvb, gint offset, gint maxlength, const gchar **verb_name);
static gboolean is_mgcp_rspcode(tvbuff_t *tvb, gint offset, gint maxlength);
static gint tvb_parse_param(tvbuff_t *tvb, gint offset, gint maxlength, int** hf);

/*
 * The various functions that either dissect some
 * subpart of MGCP.  These aren't really proto dissectors but they
 * are written in the same style.
 */
static void dissect_mgcp_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                 proto_tree *mgcp_tree, proto_tree *ti);
static void dissect_mgcp_firstline(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_mgcp_params(tvbuff_t *tvb, proto_tree *tree);
static void dissect_mgcp_connectionparams(proto_tree *parent_tree, tvbuff_t *tvb,
                                          gint offset, gint param_type_len,
                                          gint param_val_len);
static void dissect_mgcp_localconnectionoptions(proto_tree *parent_tree, tvbuff_t *tvb,
                                                gint offset, gint param_type_len,
                                                gint param_val_len);


static void mgcp_raw_text_add(tvbuff_t *tvb, proto_tree *tree);

/*
 * Some functions which should be moved to a library
 * as I think that people may find them of general usefulness.
 */
static gint tvb_find_null_line(tvbuff_t* tvb, gint offset, gint len, gint* next_offset);
static gint tvb_find_dot_line(tvbuff_t* tvb, gint offset, gint len, gint* next_offset);
static gboolean is_rfc2234_alpha(guint8 c);

static dissector_handle_t sdp_handle;
static dissector_handle_t mgcp_handle;
extern void
dissect_asciitpkt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
     dissector_handle_t subdissector_handle);
extern guint16 is_asciitpkt(tvbuff_t *tvb);

/*
 * Init Hash table stuff
 */

typedef struct _mgcp_call_info_key
{
	guint32 transid;
	conversation_t *conversation;
} mgcp_call_info_key;

static GHashTable *mgcp_calls;

/* Compare 2 keys */
static gint mgcp_call_equal(gconstpointer k1, gconstpointer k2)
{
	const mgcp_call_info_key* key1 = (const mgcp_call_info_key*) k1;
	const mgcp_call_info_key* key2 = (const mgcp_call_info_key*) k2;

	return (key1->transid == key2->transid &&
	        key1->conversation == key2->conversation);
}

/* Calculate a hash key */
static guint mgcp_call_hash(gconstpointer k)
{
	const mgcp_call_info_key* key = (const mgcp_call_info_key*) k;

	return key->transid  + key->conversation->index;
}


/************************************************************************
 * dissect_mgcp - The dissector for the Media Gateway Control Protocol
 ************************************************************************/
static int dissect_mgcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	gint sectionlen;
	guint32 num_messages;
	gint tvb_sectionend,tvb_sectionbegin, tvb_len;
	proto_tree *mgcp_tree, *ti;
	const gchar *verb_name = "";

	/* Initialize variables */
	tvb_sectionend = 0;
	tvb_sectionbegin = tvb_sectionend;
	sectionlen = 0;
	tvb_len = tvb_length(tvb);
	num_messages = 0;
	mgcp_tree = NULL;
	ti = NULL;

	/*
	 * Check to see whether we're really dealing with MGCP by looking
	 * for a valid MGCP verb or response code.  This isn't infallible,
	 * but its cheap and its better than nothing.
	 */
	if (is_mgcp_verb(tvb,0,tvb_len, &verb_name) || is_mgcp_rspcode(tvb,0,tvb_len))
	{
		/*
		 * Set the columns now, so that they'll be set correctly if we throw
		 * an exception.  We can set them later as well....
		 */
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "MGCP");
		col_clear(pinfo->cinfo, COL_INFO);

		/*
		 * Loop through however many mgcp messages may be stuck in
		 * this packet using piggybacking
		 */
		do
		{
			num_messages++;
			if (tree)
			{
				/* Create our mgcp subtree */
				ti = proto_tree_add_item(tree,proto_mgcp,tvb,0,0, ENC_NA);
				mgcp_tree = proto_item_add_subtree(ti, ett_mgcp);
			}

			sectionlen = tvb_find_dot_line(tvb, tvb_sectionbegin, -1, &tvb_sectionend);
			if (sectionlen != -1)
			{
				dissect_mgcp_message(tvb_new_subset(tvb, tvb_sectionbegin,
				                                    sectionlen, -1),
				                                    pinfo, tree, mgcp_tree,ti);
				tvb_sectionbegin = tvb_sectionend;
			}
			else
			{
				break;
			}
		} while (tvb_sectionend < tvb_len);

		if (mgcp_tree)
		{
			proto_item *tii = proto_tree_add_uint(mgcp_tree, hf_mgcp_messagecount, tvb,
			                                     0 ,0 , num_messages);
			PROTO_ITEM_SET_HIDDEN(tii);
		}

		/*
		 * Add our column information after dissecting SDP
		 * in order to prevent the column info changing to reflect the SDP
		 * (when showing message count)
		 */
		tvb_sectionbegin = 0;
		if (global_mgcp_message_count == TRUE )
		{
			if (num_messages > 1)
			{
				col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "MGCP (%i messages)",num_messages);
			}
			else
			{
				col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "MGCP (%i message)",num_messages);
			}
		}

		sectionlen = tvb_find_line_end(tvb, tvb_sectionbegin,-1,
		                               &tvb_sectionend,FALSE);
		col_prepend_fstr(pinfo->cinfo, COL_INFO, "%s",
		                 tvb_format_text(tvb, tvb_sectionbegin, sectionlen));

		return tvb_len;
	}

	return 0;
}
/************************************************************************
 * dissect_tpkt_mgcp - The dissector for the ASCII TPKT Media Gateway Control Protocol
 ************************************************************************/
static int dissect_tpkt_mgcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	guint16 ascii_tpkt;
	int     offset = 0;

	/* Check whether this looks like a ASCII TPKT-encapsulated
	 *  MGCP packet.
	 */
	ascii_tpkt = is_asciitpkt(tvb);

	if (ascii_tpkt != 1 )
	{
		/*
		 * It's not a ASCII TPKT packet
		 * in MGCP
		 */
		offset = dissect_mgcp(tvb, pinfo, tree, NULL);
	}
	else
	{
		/*
		 * Dissect ASCII TPKT header
		 */
		dissect_asciitpkt(tvb, pinfo, tree, mgcp_handle);
		offset = tvb_length(tvb);
	}

	return offset;
}

#define MAX_MGCP_MESSAGES_IN_PACKET 5
static mgcp_info_t pi_arr[MAX_MGCP_MESSAGES_IN_PACKET];
static int pi_current = 0;
static mgcp_info_t *mi;

/* Dissect an individual MGCP message */
static void dissect_mgcp_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                 proto_tree *mgcp_tree, proto_tree *ti)
{
	/* Declare variables */
	gint sectionlen;
	gint tvb_sectionend,tvb_sectionbegin, tvb_len;
	tvbuff_t *next_tvb;
	const gchar *verb_name = "";

	/* Initialise stat info for passing to tap */
	pi_current++;
	if (pi_current == MAX_MGCP_MESSAGES_IN_PACKET)
	{
		/* Overwrite info in first struct if run out of space... */
		pi_current = 0;
	}
	mi = &pi_arr[pi_current];


	mi->mgcp_type = MGCP_OTHERS;
	mi->code[0] = '\0';
	mi->transid = 0;
	mi->req_time.secs = 0;
	mi->req_time.nsecs = 0;
	mi->is_duplicate = FALSE;
	mi->request_available = FALSE;
	mi->req_num = 0;
	mi->endpointId = NULL;
	mi->observedEvents = NULL;
	mi->rspcode = 0;
	mi->signalReq = NULL;
	mi->hasDigitMap = FALSE;

	/* Initialize variables */
	tvb_sectionend = 0;
	tvb_sectionbegin = tvb_sectionend;
	sectionlen = 0;
	tvb_len = tvb_length(tvb);

	/*
	 * Check to see whether we're really dealing with MGCP by looking
	 * for a valid MGCP verb or response code.  This isn't infallible,
	 * but its cheap and its better than nothing.
	 */
	if (is_mgcp_verb(tvb,0,tvb_len,&verb_name) || is_mgcp_rspcode(tvb,0,tvb_len))
	{
		/* dissect first line */
		tvb_sectionbegin = 0;
		tvb_sectionend = tvb_sectionbegin;
		sectionlen = tvb_find_line_end(tvb,0,-1,&tvb_sectionend,FALSE);
		if (sectionlen > 0)
		{
			dissect_mgcp_firstline(tvb_new_subset(tvb, tvb_sectionbegin,
			                       sectionlen,-1), pinfo,
			                       mgcp_tree);
		}
		tvb_sectionbegin = tvb_sectionend;

		/* Dissect params */
		if (tvb_sectionbegin < tvb_len)
		{
			sectionlen = tvb_find_null_line(tvb, tvb_sectionbegin, -1,
			                                &tvb_sectionend);
			if (sectionlen > 0)
			{
				dissect_mgcp_params(tvb_new_subset(tvb, tvb_sectionbegin, sectionlen, -1),
				                                   mgcp_tree);
				tvb_sectionbegin = tvb_sectionend;
			}
		}

		/* Set the mgcp payload length correctly so we don't include any
		   encapsulated SDP */
		sectionlen = tvb_sectionend;
		proto_item_set_len(ti,sectionlen);

		/* Display the raw text of the mgcp message if desired */

		/* Do we want to display the raw text of our MGCP packet? */
		if (global_mgcp_raw_text)
		{
			if (tree)
				mgcp_raw_text_add(tvb, mgcp_tree);
		}

		/* Dissect sdp payload */
		if (tvb_sectionend < tvb_len)
		{
			next_tvb = tvb_new_subset_remaining(tvb, tvb_sectionend);
			call_dissector(sdp_handle, next_tvb, pinfo, tree);
		}
	}
}


/*
 * Add the raw text of the message to the dissect tree if appropriate
 * preferences are specified.
 */
static void mgcp_raw_text_add(tvbuff_t *tvb, proto_tree *tree)
{
	gint tvb_linebegin,tvb_lineend,tvb_len,linelen;

	tvb_linebegin = 0;
	tvb_len = tvb_length(tvb);

	do
	{
		tvb_find_line_end(tvb,tvb_linebegin,-1,&tvb_lineend,FALSE);
		linelen = tvb_lineend - tvb_linebegin;
		proto_tree_add_text(tree, tvb, tvb_linebegin, linelen, "%s",
		                    tvb_format_text(tvb, tvb_linebegin, linelen));
		tvb_linebegin = tvb_lineend;
	} while (tvb_lineend < tvb_len);
}

/* Discard and init any state we've saved */
static void mgcp_init_protocol(void)
{
	if (mgcp_calls != NULL)
	{
		g_hash_table_destroy(mgcp_calls);
		mgcp_calls = NULL;
	}

	mgcp_calls = g_hash_table_new(mgcp_call_hash, mgcp_call_equal);
}

/* Register all the bits needed with the filtering engine */
void proto_register_mgcp(void)
{
    static hf_register_info hf[] =
    {
        { &hf_mgcp_req,
          { "Request", "mgcp.req", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "True if MGCP request", HFILL }},
        { &hf_mgcp_rsp,
          { "Response", "mgcp.rsp", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "TRUE if MGCP response", HFILL }},
        { &hf_mgcp_req_frame,
          { "Request Frame", "mgcp.reqframe", FT_FRAMENUM, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_mgcp_rsp_frame,
          { "Response Frame", "mgcp.rspframe", FT_FRAMENUM, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_mgcp_time,
          { "Time from request", "mgcp.time", FT_RELATIVE_TIME, BASE_NONE, NULL, 0,
            "Timedelta between Request and Response", HFILL }},
        { &hf_mgcp_req_verb,
          { "Verb", "mgcp.req.verb", FT_STRING, BASE_NONE, NULL, 0x0,
            "Name of the verb", HFILL }},
        { &hf_mgcp_req_endpoint,
          { "Endpoint", "mgcp.req.endpoint", FT_STRING, BASE_NONE, NULL, 0x0,
            "Endpoint referenced by the message", HFILL }},
        { &hf_mgcp_transid,
          { "Transaction ID", "mgcp.transid", FT_STRING, BASE_NONE, NULL, 0x0,
            "Transaction ID of this message", HFILL }},
        { &hf_mgcp_version,
          { "Version", "mgcp.version", FT_STRING, BASE_NONE, NULL, 0x0,
            "MGCP Version", HFILL }},
        { &hf_mgcp_rsp_rspcode,
          { "Response Code", "mgcp.rsp.rspcode", FT_UINT32, BASE_DEC, VALS(mgcp_return_code_vals), 0x0,
            NULL, HFILL }},
        { &hf_mgcp_rsp_rspstring,
          { "Response String", "mgcp.rsp.rspstring", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_mgcp_params,
          { "Parameters", "mgcp.params", FT_NONE, BASE_NONE, NULL, 0x0,
            "MGCP parameters", HFILL }},
        { &hf_mgcp_param_rspack,
          { "ResponseAck (K)", "mgcp.param.rspack", FT_STRING, BASE_NONE, NULL, 0x0,
            "Response Ack", HFILL }},
        { &hf_mgcp_param_bearerinfo,
          { "BearerInformation (B)", "mgcp.param.bearerinfo", FT_STRING, BASE_NONE, NULL, 0x0,
            "Bearer Information", HFILL }},
        { &hf_mgcp_param_callid,
          { "CallId (C)", "mgcp.param.callid", FT_STRING, BASE_NONE, NULL, 0x0,
            "Call Id", HFILL }},
        { &hf_mgcp_param_connectionid,
          {"ConnectionIdentifier (I)", "mgcp.param.connectionid", FT_STRING, BASE_NONE, NULL, 0x0,
            "Connection Identifier", HFILL }},
        { &hf_mgcp_param_secondconnectionid,
          { "SecondConnectionID (I2)", "mgcp.param.secondconnectionid", FT_STRING, BASE_NONE, NULL, 0x0,
            "Second Connection Identifier", HFILL }},
        { &hf_mgcp_param_notifiedentity,
          { "NotifiedEntity (N)", "mgcp.param.notifiedentity", FT_STRING, BASE_NONE, NULL, 0x0,
            "Notified Entity", HFILL }},
        { &hf_mgcp_param_requestid,
          { "RequestIdentifier (X)", "mgcp.param.requestid", FT_STRING, BASE_NONE, NULL, 0x0,
            "Request Identifier", HFILL }},
        { &hf_mgcp_param_localconnoptions,
          { "LocalConnectionOptions (L)", "mgcp.param.localconnectionoptions", FT_STRING, BASE_NONE, NULL, 0x0,
            "Local Connection Options", HFILL }},
        { &hf_mgcp_param_localconnoptions_p,
          { "Packetization period (p)", "mgcp.param.localconnectionoptions.p", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Packetization period", HFILL }},
        { &hf_mgcp_param_localconnoptions_a,
          { "Codecs (a)", "mgcp.param.localconnectionoptions.a", FT_STRING, BASE_NONE, NULL, 0x0,
            "Codecs", HFILL }},
        { &hf_mgcp_param_localconnoptions_s,
          { "Silence Suppression (s)", "mgcp.param.localconnectionoptions.s", FT_STRING, BASE_NONE, NULL, 0x0,
            "Silence Suppression", HFILL }},
        { &hf_mgcp_param_localconnoptions_e,
          { "Echo Cancellation (e)", "mgcp.param.localconnectionoptions.e", FT_STRING, BASE_NONE, NULL, 0x0,
            "Echo Cancellation", HFILL }},
        { &hf_mgcp_param_localconnoptions_scrtp,
          { "RTP ciphersuite (sc-rtp)", "mgcp.param.localconnectionoptions.scrtp", FT_STRING, BASE_NONE, NULL, 0x0,
            "RTP ciphersuite", HFILL }},
        { &hf_mgcp_param_localconnoptions_scrtcp,
          { "RTCP ciphersuite (sc-rtcp)", "mgcp.param.localconnectionoptions.scrtcp", FT_STRING, BASE_NONE, NULL, 0x0,
            "RTCP ciphersuite", HFILL }},
        { &hf_mgcp_param_localconnoptions_b,
          { "Bandwidth (b)", "mgcp.param.localconnectionoptions.b", FT_STRING, BASE_NONE, NULL, 0x0,
            "Bandwidth", HFILL }},
        { &hf_mgcp_param_localconnoptions_esccd,
          { "Content Destination (es-ccd)", "mgcp.param.localconnectionoptions.esccd", FT_STRING, BASE_NONE, NULL, 0x0,
            "Content Destination", HFILL }},
        { &hf_mgcp_param_localconnoptions_escci,
          { "Content Identifier (es-cci)", "mgcp.param.localconnectionoptions.escci", FT_STRING, BASE_NONE, NULL, 0x0,
            "Content Identifier", HFILL }},
        { &hf_mgcp_param_localconnoptions_dqgi,
          { "D-QoS GateID (dq-gi)", "mgcp.param.localconnectionoptions.dqgi", FT_STRING, BASE_NONE, NULL, 0x0,
            "D-QoS GateID", HFILL }},
        { &hf_mgcp_param_localconnoptions_dqrd,
          { "D-QoS Reserve Destination (dq-rd)", "mgcp.param.localconnectionoptions.dqrd", FT_STRING, BASE_NONE, NULL, 0x0,
            "D-QoS Reserve Destination", HFILL }},
        { &hf_mgcp_param_localconnoptions_dqri,
          { "D-QoS Resource ID (dq-ri)", "mgcp.param.localconnectionoptions.dqri", FT_STRING, BASE_NONE, NULL, 0x0,
            "D-QoS Resource ID", HFILL }},
        { &hf_mgcp_param_localconnoptions_dqrr,
          { "D-QoS Resource Reservation (dq-rr)", "mgcp.param.localconnectionoptions.dqrr", FT_STRING, BASE_NONE, NULL, 0x0,
            "D-QoS Resource Reservation", HFILL }},
        { &hf_mgcp_param_localconnoptions_k,
          { "Encryption Key (k)", "mgcp.param.localconnectionoptions.k", FT_STRING, BASE_NONE, NULL, 0x0,
            "Encryption Key", HFILL }},
        { &hf_mgcp_param_localconnoptions_gc,
          { "Gain Control (gc)", "mgcp.param.localconnectionoptions.gc", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Gain Control", HFILL }},
        { &hf_mgcp_param_localconnoptions_fmtp,
          { "Media Format (fmtp)", "mgcp.param.localconnectionoptions.fmtp", FT_STRING, BASE_NONE, NULL, 0x0,
            "Media Format", HFILL }},
        { &hf_mgcp_param_localconnoptions_nt,
          { "Network Type (nt)", "mgcp.param.localconnectionoptions.nt", FT_STRING, BASE_NONE, NULL, 0x0,
            "Network Type", HFILL }},
        { &hf_mgcp_param_localconnoptions_ofmtp,
          { "Optional Media Format (o-fmtp)", "mgcp.param.localconnectionoptions.ofmtp", FT_STRING, BASE_NONE, NULL, 0x0,
            "Optional Media Format", HFILL }},
        { &hf_mgcp_param_localconnoptions_r,
          { "Resource Reservation (r)", "mgcp.param.localconnectionoptions.r", FT_STRING, BASE_NONE, NULL, 0x0,
            "Resource Reservation", HFILL }},
        { &hf_mgcp_param_localconnoptions_t,
          { "Type of Service (r)", "mgcp.param.localconnectionoptions.t", FT_STRING, BASE_NONE, NULL, 0x0,
            "Type of Service", HFILL }},
        { &hf_mgcp_param_localconnoptions_rcnf,
          { "Reservation Confirmation (r-cnf)", "mgcp.param.localconnectionoptions.rcnf", FT_STRING, BASE_NONE, NULL, 0x0,
            "Reservation Confirmation", HFILL }},
        { &hf_mgcp_param_localconnoptions_rdir,
          { "Reservation Direction (r-dir)", "mgcp.param.localconnectionoptions.rdir", FT_STRING, BASE_NONE, NULL, 0x0,
            "Reservation Direction", HFILL }},
        { &hf_mgcp_param_localconnoptions_rsh,
          { "Resource Sharing (r-sh)", "mgcp.param.localconnectionoptions.rsh", FT_STRING, BASE_NONE, NULL, 0x0,
            "Resource Sharing", HFILL }},
        { &hf_mgcp_param_connectionmode,
          { "ConnectionMode (M)", "mgcp.param.connectionmode", FT_STRING, BASE_NONE, NULL, 0x0,
            "Connection Mode", HFILL }},
        { &hf_mgcp_param_reqevents,
          { "RequestedEvents (R)", "mgcp.param.reqevents", FT_STRING, BASE_NONE, NULL, 0x0,
            "Requested Events", HFILL }},
        { &hf_mgcp_param_signalreq,
          { "SignalRequests (S)", "mgcp.param.signalreq", FT_STRING, BASE_NONE, NULL, 0x0,
            "Signal Request", HFILL }},
        { &hf_mgcp_param_restartmethod,
          { "RestartMethod (RM)", "mgcp.param.restartmethod", FT_STRING, BASE_NONE, NULL, 0x0,
            "Restart Method", HFILL }},
        { &hf_mgcp_param_restartdelay,
          { "RestartDelay (RD)", "mgcp.param.restartdelay", FT_STRING, BASE_NONE, NULL, 0x0,
            "Restart Delay", HFILL }},
        { &hf_mgcp_param_digitmap,
          { "DigitMap (D)", "mgcp.param.digitmap", FT_STRING, BASE_NONE, NULL, 0x0,
            "Digit Map", HFILL }},
        { &hf_mgcp_param_observedevent,
          { "ObservedEvents (O)", "mgcp.param.observedevents", FT_STRING, BASE_NONE, NULL, 0x0,
            "Observed Events", HFILL }},
        { &hf_mgcp_param_connectionparam,
          { "ConnectionParameters (P)", "mgcp.param.connectionparam", FT_STRING, BASE_NONE, NULL, 0x0,
            "Connection Parameters", HFILL }},
        { &hf_mgcp_param_connectionparam_ps,
          { "Packets sent (PS)", "mgcp.param.connectionparam.ps", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Packets sent (P:PS)", HFILL }},
        { &hf_mgcp_param_connectionparam_os,
          { "Octets sent (OS)", "mgcp.param.connectionparam.os", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Octets sent (P:OS)", HFILL }},
        { &hf_mgcp_param_connectionparam_pr,
          { "Packets received (PR)", "mgcp.param.connectionparam.pr", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Packets received (P:PR)", HFILL }},
        { &hf_mgcp_param_connectionparam_or,
          { "Octets received (OR)", "mgcp.param.connectionparam.or", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Octets received (P:OR)", HFILL }},
        { &hf_mgcp_param_connectionparam_pl,
          { "Packets lost (PL)", "mgcp.param.connectionparam.pl", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Packets lost (P:PL)", HFILL }},
        { &hf_mgcp_param_connectionparam_ji,
          { "Jitter (JI)", "mgcp.param.connectionparam.ji", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Average inter-packet arrival jitter in milliseconds (P:JI)", HFILL }},
        { &hf_mgcp_param_connectionparam_la,
          { "Latency (LA)", "mgcp.param.connectionparam.la", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Average latency in milliseconds (P:LA)", HFILL }},
        { &hf_mgcp_param_connectionparam_pcrps,
          { "Remote Packets sent (PC/RPS)", "mgcp.param.connectionparam.pcrps", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Remote Packets sent (P:PC/RPS)", HFILL }},
        { &hf_mgcp_param_connectionparam_pcros,
          { "Remote Octets sent (PC/ROS)", "mgcp.param.connectionparam.pcros", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Remote Octets sent (P:PC/ROS)", HFILL }},
        { &hf_mgcp_param_connectionparam_pcrpl,
          { "Remote Packets lost (PC/RPL)", "mgcp.param.connectionparam.pcrpl", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Remote Packets lost (P:PC/RPL)", HFILL }},
        { &hf_mgcp_param_connectionparam_pcrji,
          { "Remote Jitter (PC/RJI)", "mgcp.param.connectionparam.pcrji", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Remote Jitter (P:PC/RJI)", HFILL }},
        { &hf_mgcp_param_connectionparam_x,
          { "Vendor Extension", "mgcp.param.connectionparam.x", FT_STRING, BASE_NONE, NULL, 0x0,
            "Vendor Extension (P:X-*)", HFILL }},
        { &hf_mgcp_param_reasoncode,
          { "ReasonCode (E)", "mgcp.param.reasoncode", FT_STRING, BASE_NONE, NULL, 0x0,
            "Reason Code", HFILL }},
        { &hf_mgcp_param_eventstates,
          { "EventStates (ES)", "mgcp.param.eventstates", FT_STRING, BASE_NONE, NULL, 0x0,
            "Event States", HFILL }},
        { &hf_mgcp_param_specificendpoint,
          { "SpecificEndpointID (Z)", "mgcp.param.specificendpointid", FT_STRING, BASE_NONE, NULL, 0x0,
            "Specific Endpoint ID", HFILL }},
        { &hf_mgcp_param_secondendpointid,
          { "SecondEndpointID (Z2)", "mgcp.param.secondendpointid", FT_STRING, BASE_NONE, NULL, 0x0,
            "Second Endpoint ID", HFILL }},
        { &hf_mgcp_param_reqinfo,
          { "RequestedInfo (F)", "mgcp.param.reqinfo", FT_STRING, BASE_NONE, NULL, 0x0,
            "Requested Info", HFILL }},
        { &hf_mgcp_param_quarantinehandling,
          { "QuarantineHandling (Q)", "mgcp.param.quarantinehandling", FT_STRING, BASE_NONE, NULL, 0x0,
            "Quarantine Handling", HFILL }},
        { &hf_mgcp_param_detectedevents,
          { "DetectedEvents (T)", "mgcp.param.detectedevents", FT_STRING, BASE_NONE, NULL, 0x0,
            "Detected Events", HFILL }},
        { &hf_mgcp_param_capabilities,
          { "Capabilities (A)", "mgcp.param.capabilities", FT_STRING, BASE_NONE, NULL, 0x0,
            "Capabilities", HFILL }},
        { &hf_mgcp_param_maxmgcpdatagram,
          {"MaxMGCPDatagram (MD)", "mgcp.param.maxmgcpdatagram", FT_STRING, BASE_NONE, NULL, 0x0,
           "Maximum MGCP Datagram size", HFILL }},
        { &hf_mgcp_param_packagelist,
          {"PackageList (PL)", "mgcp.param.packagelist", FT_STRING, BASE_NONE, NULL, 0x0,
           "Package List", HFILL }},
        { &hf_mgcp_param_extension,
          { "Extension Parameter (non-critical)", "mgcp.param.extension", FT_STRING, BASE_NONE, NULL, 0x0,
            "Extension Parameter", HFILL }},
        { &hf_mgcp_param_extension_critical,
          { "Extension Parameter (critical)", "mgcp.param.extensioncritical", FT_STRING, BASE_NONE, NULL, 0x0,
            "Critical Extension Parameter", HFILL }},
        { &hf_mgcp_param_invalid,
          { "Invalid Parameter", "mgcp.param.invalid", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_mgcp_messagecount,
          { "MGCP Message Count", "mgcp.messagecount", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Number of MGCP message in a packet", HFILL }},
        { &hf_mgcp_dup,
          { "Duplicate Message", "mgcp.dup", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_mgcp_req_dup,
          { "Duplicate Request", "mgcp.req.dup", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_mgcp_req_dup_frame,
          { "Original Request Frame", "mgcp.req.dup.frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Frame containing original request", HFILL }},
        { &hf_mgcp_rsp_dup,
          { "Duplicate Response", "mgcp.rsp.dup", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_mgcp_rsp_dup_frame,
          { "Original Response Frame", "mgcp.rsp.dup.frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Frame containing original response", HFILL }},
    };

    static gint *ett[] =
    {
        &ett_mgcp,
        &ett_mgcp_param,
        &ett_mgcp_param_connectionparam,
        &ett_mgcp_param_localconnectionoptions
    };

    module_t *mgcp_module;

    /* Register protocol */
    proto_mgcp = proto_register_protocol("Media Gateway Control Protocol", "MGCP", "mgcp");
    proto_register_field_array(proto_mgcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_init_routine(&mgcp_init_protocol);

    new_register_dissector("mgcp", dissect_mgcp, proto_mgcp);

    /* Register our configuration options */
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

    prefs_register_obsolete_preference(mgcp_module, "display_dissect_tree");

    prefs_register_bool_preference(mgcp_module, "display_mgcp_message_count",
                                   "Display the number of MGCP messages",
                                   "Display the number of MGCP messages "
                                   "found in a packet in the protocol column.",
                                   &global_mgcp_message_count);

    mgcp_tap = register_tap("mgcp");
}

/* The registration hand-off routine */
void proto_reg_handoff_mgcp(void)
{
	static gboolean mgcp_prefs_initialized = FALSE;
	static dissector_handle_t mgcp_tpkt_handle;
	/*
	 * Variables to allow for proper deletion of dissector registration when
	 * the user changes port from the gui.
	 */
	static guint gateway_tcp_port;
	static guint gateway_udp_port;
	static guint callagent_tcp_port;
	static guint callagent_udp_port;

	if (!mgcp_prefs_initialized)
	{
		/* Get a handle for the SDP dissector. */
		sdp_handle = find_dissector("sdp");
		mgcp_handle = new_create_dissector_handle(dissect_mgcp, proto_mgcp);
		mgcp_tpkt_handle = new_create_dissector_handle(dissect_tpkt_mgcp, proto_mgcp);
		mgcp_prefs_initialized = TRUE;
	}
	else
	{
		dissector_delete_uint("tcp.port", gateway_tcp_port, mgcp_tpkt_handle);
		dissector_delete_uint("udp.port", gateway_udp_port, mgcp_handle);
		dissector_delete_uint("tcp.port", callagent_tcp_port, mgcp_tpkt_handle);
		dissector_delete_uint("udp.port", callagent_udp_port, mgcp_handle);
	}

	/* Set our port number for future use */
	gateway_tcp_port = global_mgcp_gateway_tcp_port;
	gateway_udp_port = global_mgcp_gateway_udp_port;

	callagent_tcp_port = global_mgcp_callagent_tcp_port;
	callagent_udp_port = global_mgcp_callagent_udp_port;

	dissector_add_uint("tcp.port", global_mgcp_gateway_tcp_port, mgcp_tpkt_handle);
	dissector_add_uint("udp.port", global_mgcp_gateway_udp_port, mgcp_handle);
	dissector_add_uint("tcp.port", global_mgcp_callagent_tcp_port, mgcp_tpkt_handle);
	dissector_add_uint("udp.port", global_mgcp_callagent_udp_port, mgcp_handle);
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
 * verb_name - The name for the verb code found (output)
 *
 * Return: TRUE if there is an MGCP verb at offset in tvb, otherwise FALSE
 */
static gboolean is_mgcp_verb(tvbuff_t *tvb, gint offset, gint maxlength, const gchar **verb_name)
{
	int returnvalue = FALSE;
	gchar word[5];

	/* Read the string into 'word' and see if it looks like the start of a verb */
	if ((maxlength >= 4) && tvb_get_nstringz0(tvb, offset, sizeof(word), word))
	{
		if (((g_ascii_strncasecmp(word, "EPCF", 4) == 0) && (*verb_name = "EndpointConfiguration")) ||
		    ((g_ascii_strncasecmp(word, "CRCX", 4) == 0) && (*verb_name = "CreateConnection")) ||
		    ((g_ascii_strncasecmp(word, "MDCX", 4) == 0) && (*verb_name = "ModifyConnection")) ||
		    ((g_ascii_strncasecmp(word, "DLCX", 4) == 0) && (*verb_name = "DeleteConnection")) ||
		    ((g_ascii_strncasecmp(word, "RQNT", 4) == 0) && (*verb_name = "NotificationRequest")) ||
		    ((g_ascii_strncasecmp(word, "NTFY", 4) == 0) && (*verb_name = "Notify")) ||
		    ((g_ascii_strncasecmp(word, "AUEP", 4) == 0) && (*verb_name = "AuditEndpoint")) ||
		    ((g_ascii_strncasecmp(word, "AUCX", 4) == 0) && (*verb_name = "AuditConnection")) ||
		    ((g_ascii_strncasecmp(word, "RSIP", 4) == 0) && (*verb_name = "RestartInProgress")) ||
		    ((g_ascii_strncasecmp(word, "MESG", 4) == 0) && (*verb_name = "Message")) ||
		    (word[0] == 'X' && is_rfc2234_alpha(word[1]) && is_rfc2234_alpha(word[2]) &&
		                       is_rfc2234_alpha(word[3]) && (*verb_name = "*Experimental*")))
		{
			returnvalue = TRUE;
		}
	}

	/* May be whitespace after verb code - anything else is an error.. */
	if (returnvalue && maxlength >= 5)
	{
		char next = tvb_get_guint8(tvb,4);
		if ((next != ' ') && (next != '\t'))
		{
			returnvalue = FALSE;
		}
	}

	return returnvalue;
}

/*
 * is_mgcp_rspcode - A function for determining whether something which
 *                   looks roughly like a MGCP response code (3-digit number)
 *                   is at 'offset' in tvb
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
static gboolean is_mgcp_rspcode(tvbuff_t *tvb, gint offset, gint maxlength)
{
	int returnvalue = FALSE;
	guint8 word[4];

	/* Do 1st 3 characters look like digits? */
	if (maxlength >= 3)
	{
		tvb_get_nstringz0(tvb, offset, sizeof(word), word);
		if (isdigit(word[0]) && isdigit(word[1]) && isdigit(word[2]))
		{
			returnvalue = TRUE;
		}
	}

	/* Maybe some white space after the 3rd digit - anything else is an error */
	if (returnvalue && maxlength >= 4)
	{
		char next = tvb_get_guint8(tvb, 3);
		if ((next != ' ') && (next != '\t'))
		{
			returnvalue = FALSE;
		}
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
static gboolean is_rfc2234_alpha(guint8 c)
{
	return ((c <= 'Z' && c >= 'A' ) || (c <= 'z' && c >= 'a'));
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
static gint tvb_parse_param(tvbuff_t* tvb, gint offset, gint len, int** hf)
{
	gint returnvalue = -1, tvb_current_offset,counter;
	guint8 tempchar, plus_minus;
	gchar **buf;

	tvb_current_offset = offset;
	*hf = NULL;
	buf=NULL;

	if (len > 0)
	{
		tempchar = tvb_get_guint8(tvb,tvb_current_offset);

		switch (tempchar)
		{
			case 'K':
				if (tvb_get_guint8(tvb,tvb_current_offset+1) != ':')
				{
					*hf = &hf_mgcp_param_invalid;
					break;
				}
				*hf = &hf_mgcp_param_rspack;
				break;
			case 'B':
				if (tvb_get_guint8(tvb,tvb_current_offset+1) != ':')
				{
					*hf = &hf_mgcp_param_invalid;
					break;
				}
				*hf = &hf_mgcp_param_bearerinfo;
				break;
			case 'C':
				if (tvb_get_guint8(tvb,tvb_current_offset+1) != ':')
				{
					*hf = &hf_mgcp_param_invalid;
					break;
				}
				*hf = &hf_mgcp_param_callid;
				break;
			case 'I':
				tvb_current_offset++;
				if (len > (tvb_current_offset - offset) &&
				   (tempchar = tvb_get_guint8(tvb,tvb_current_offset)) == ':')
				{
					*hf = &hf_mgcp_param_connectionid;
					tvb_current_offset--;
				}
				else
					if (tempchar == '2')
				{
					*hf = &hf_mgcp_param_secondconnectionid;
				}
				break;
			case 'N':
				if (tvb_get_guint8(tvb,tvb_current_offset+1) != ':')
				{
					*hf = &hf_mgcp_param_invalid;
					break;
				}
				*hf = &hf_mgcp_param_notifiedentity;
				break;
			case 'X':
				/* Move past 'X' */
				tvb_current_offset++;

				/* X: is RequestIdentifier */
				if (len > (tvb_current_offset - offset) &&
				   (tempchar = tvb_get_guint8(tvb,tvb_current_offset)) == ':')
				{
					*hf = &hf_mgcp_param_requestid;
					tvb_current_offset--;
				}

				/* X+...: or X-....: are vendor extension parameters */
				else
				if (len > (tvb_current_offset - offset) &&
				    ((plus_minus = tvb_get_guint8(tvb,tvb_current_offset)) == '-' ||
				     (plus_minus == '+')))
				{
					/* Move past + or - */
					tvb_current_offset++;

					/* Keep going, through possible vendor param name */
					for (counter = 1;
					    ((len > (counter + tvb_current_offset-offset)) &&
					    (is_rfc2234_alpha(tempchar = tvb_get_guint8(tvb, tvb_current_offset+counter)) ||
					     isdigit(tempchar))) ;
					     counter++);

					if (tempchar == ':')
					{
						/* Looks like a valid vendor param name */
						tvb_current_offset += counter;
						switch (plus_minus)
						{
							case '+':
								*hf = &hf_mgcp_param_extension_critical;
								break;
							case '-':
								*hf = &hf_mgcp_param_extension;
								break;
						}
					}
				}
				break;
			case 'L':
				if (tvb_get_guint8(tvb,tvb_current_offset+1) != ':')
				{
					*hf = &hf_mgcp_param_invalid;
					break;
				}
				*hf = &hf_mgcp_param_localconnoptions;
				break;
			case 'M':
				tvb_current_offset++;
				if (len > (tvb_current_offset - offset) &&
				   (tempchar = tvb_get_guint8(tvb,tvb_current_offset)) == ':')
				{
					*hf = &hf_mgcp_param_connectionmode;
					tvb_current_offset--;
				}
				else
				if (tempchar == 'D')
				{
					*hf = &hf_mgcp_param_maxmgcpdatagram;
				}
				break;
			case 'R':
				tvb_current_offset++;
				if (len > (tvb_current_offset - offset) &&
				    (tempchar = tvb_get_guint8(tvb,tvb_current_offset)) == ':')
				{
					*hf = &hf_mgcp_param_reqevents;
					tvb_current_offset--;
				}
				else
				if ( tempchar == 'M')
				{
					*hf = &hf_mgcp_param_restartmethod;
				}
				else
				if (tempchar == 'D')
				{
					*hf = &hf_mgcp_param_restartdelay;
				}
				break;
			case 'S':
				if (tvb_get_guint8(tvb,tvb_current_offset+1) != ':')
				{
					*hf = &hf_mgcp_param_invalid;
					break;
				}
				*hf = &hf_mgcp_param_signalreq;
				buf = &(mi->signalReq);
				break;
			case 'D':
				if (tvb_get_guint8(tvb,tvb_current_offset+1) != ':')
				{
					*hf = &hf_mgcp_param_invalid;
					break;
				}
				*hf = &hf_mgcp_param_digitmap;
				mi->hasDigitMap = TRUE;
				break;
			case 'O':
				if (tvb_get_guint8(tvb,tvb_current_offset+1) != ':')
				{
					*hf = &hf_mgcp_param_invalid;
					break;
				}
				*hf = &hf_mgcp_param_observedevent;
				buf = &(mi->observedEvents);
				break;
			case 'P':
				tvb_current_offset++;
				if (len > (tvb_current_offset - offset) &&
				    (tempchar = tvb_get_guint8(tvb,tvb_current_offset)) == ':')
				{
					*hf = &hf_mgcp_param_connectionparam;
					tvb_current_offset--;
				}
				else
				if ( tempchar == 'L')
				{
					*hf = &hf_mgcp_param_packagelist;
				}
				break;
			case 'E':
				tvb_current_offset++;
				if (len > (tvb_current_offset - offset) &&
				    (tempchar = tvb_get_guint8(tvb,tvb_current_offset)) == ':')
				{
					*hf = &hf_mgcp_param_reasoncode;
					tvb_current_offset--;
				}
				else
				if ( tempchar == 'S')
				{
					*hf = &hf_mgcp_param_eventstates;
				}
				break;
			case 'Z':
				tvb_current_offset++;
				if (len > (tvb_current_offset - offset) &&
				    (tempchar = tvb_get_guint8(tvb,tvb_current_offset)) == ':')
				{
					*hf = &hf_mgcp_param_specificendpoint;
					tvb_current_offset--;
				}
				else
				if (tempchar == '2')
				{
					*hf = &hf_mgcp_param_secondendpointid;
				}
				break;
			case 'F':
				if (tvb_get_guint8(tvb,tvb_current_offset+1) != ':')
				{
					*hf = &hf_mgcp_param_invalid;
					break;
				}
				*hf = &hf_mgcp_param_reqinfo;
				break;
			case 'Q':
				if (tvb_get_guint8(tvb,tvb_current_offset+1) != ':')
				{
					*hf = &hf_mgcp_param_invalid;
					break;
				}
				*hf = &hf_mgcp_param_quarantinehandling;
				break;
			case 'T':
				if (tvb_get_guint8(tvb,tvb_current_offset+1) != ':')
				{
					*hf = &hf_mgcp_param_invalid;
					break;
				}
				*hf = &hf_mgcp_param_detectedevents;
				break;
			case 'A':
				if (tvb_get_guint8(tvb,tvb_current_offset+1) != ':')
				{
					*hf = &hf_mgcp_param_invalid;
					break;
				}
				*hf = &hf_mgcp_param_capabilities;
				break;

			default:
				*hf = &hf_mgcp_param_invalid;
				break;
		}

		/* Move to (hopefully) the colon */
		tvb_current_offset++;

		/* Add a recognised parameter type if we have one */
		if (*hf != NULL && len > (tvb_current_offset - offset) &&
		    tvb_get_guint8(tvb,tvb_current_offset) == ':')
		{
			tvb_current_offset++;
			tvb_current_offset = tvb_skip_wsp(tvb,tvb_current_offset, (len - tvb_current_offset + offset));
			returnvalue = tvb_current_offset;

                       /* set the observedEvents or signalReq used in Voip Calls analysis */
                       if (buf != NULL) {
                               *buf = tvb_get_ephemeral_string(tvb, tvb_current_offset, (len - tvb_current_offset + offset));
                       }
		}
	}
	else
	{
		/* Was an empty line */
		*hf = &hf_mgcp_param_invalid;
	}

	/* For these types, show the whole line */
	if ((*hf == &hf_mgcp_param_invalid) ||
	    (*hf == &hf_mgcp_param_extension) || (*hf == &hf_mgcp_param_extension_critical))
	{
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
static void dissect_mgcp_firstline(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint tvb_current_offset,tvb_previous_offset,tvb_len,tvb_current_len;
	gint tokennum, tokenlen;
	proto_item* hidden_item;
	char *transid = NULL;
	char *code = NULL;
	char *endpointId = NULL;
	mgcp_type_t mgcp_type = MGCP_OTHERS;
	conversation_t* conversation;
	mgcp_call_info_key mgcp_call_key;
	mgcp_call_info_key *new_mgcp_call_key = NULL;
	mgcp_call_t *mgcp_call = NULL;
	nstime_t delta;
	gint rspcode = 0;
	const gchar *verb_description = "";
	char code_with_verb[64] = "";  /* To fit "<4-letter-code> (<longest-verb>)" */

	static address null_address = { AT_NONE, AT_SUB_NONE, 0, NULL };
	tvb_previous_offset = 0;
	tvb_len = tvb_length(tvb);
	tvb_current_len = tvb_len;
	tvb_current_offset = tvb_previous_offset;
	mi->is_duplicate = FALSE;
	mi->request_available = FALSE;

	if (tree)
	{
		tokennum = 0;

		do
		{
			tvb_current_len = tvb_length_remaining(tvb,tvb_previous_offset);
			tvb_current_offset = tvb_find_guint8(tvb, tvb_previous_offset, tvb_current_len, ' ');
			if (tvb_current_offset == -1)
			{
				tvb_current_offset = tvb_len;
				tokenlen = tvb_current_len;
			}
			else
			{
				tokenlen = tvb_current_offset - tvb_previous_offset;
			}
			if (tokennum == 0)
			{
				if (tokenlen > 4)
					THROW(ReportedBoundsError);
				code = tvb_format_text(tvb,tvb_previous_offset,tokenlen);
				g_strlcpy(mi->code,code,5);
				if (is_mgcp_verb(tvb,tvb_previous_offset,tvb_current_len,&verb_description))
				{
					mgcp_type = MGCP_REQUEST;
					if (verb_description != NULL)
					{
						/* Can show verb along with code if known */
						g_snprintf(code_with_verb, 64, "%s (%s)", code, verb_description);
					}

					proto_tree_add_string_format(tree, hf_mgcp_req_verb, tvb,
					                             tvb_previous_offset, tokenlen,
					                             code, "%s",
					                             strlen(code_with_verb) ? code_with_verb : code);
				}
				else
				if (is_mgcp_rspcode(tvb,tvb_previous_offset,tvb_current_len))
				{
					mgcp_type = MGCP_RESPONSE;
					rspcode = atoi(code);
					mi->rspcode = rspcode;
					proto_tree_add_uint(tree,hf_mgcp_rsp_rspcode, tvb,
					                    tvb_previous_offset, tokenlen, rspcode);
				}
				else
				{
					break;
				}
			}
			if (tokennum == 1)
			{
				transid = tvb_format_text(tvb,tvb_previous_offset,tokenlen);
				/* XXX - what if this isn't a valid text string? */
				mi->transid = atol(transid);
				proto_tree_add_string(tree, hf_mgcp_transid, tvb,
				                      tvb_previous_offset, tokenlen, transid);
			}
			if (tokennum == 2)
			{
				if (mgcp_type == MGCP_REQUEST)
				{
					endpointId = tvb_format_text(tvb, tvb_previous_offset,tokenlen);
					mi->endpointId = ep_strdup(endpointId);
					proto_tree_add_string(tree,hf_mgcp_req_endpoint, tvb,
					                      tvb_previous_offset, tokenlen, endpointId);
				}
				else
				if (mgcp_type == MGCP_RESPONSE)
				{
					if (tvb_current_offset < tvb_len)
					{
						tokenlen = tvb_find_line_end(tvb, tvb_previous_offset,
						                             -1, &tvb_current_offset, FALSE);
					}
					else
					{
						tokenlen = tvb_current_len;
					}
					proto_tree_add_string(tree, hf_mgcp_rsp_rspstring, tvb,
					                      tvb_previous_offset, tokenlen,
					                      tvb_format_text(tvb, tvb_previous_offset,
					                      tokenlen));
					break;
				}
			}

			if ((tokennum == 3 && mgcp_type == MGCP_REQUEST))
			{
				if (tvb_current_offset < tvb_len )
				{
					tokenlen = tvb_find_line_end(tvb, tvb_previous_offset,
					                             -1, &tvb_current_offset,FALSE);
				}
				else
				{
					tokenlen = tvb_current_len;
				}
				proto_tree_add_string(tree,hf_mgcp_version, tvb,
				                      tvb_previous_offset, tokenlen,
				                      tvb_format_text(tvb,tvb_previous_offset,
				                      tokenlen));
				break;
			}
			if (tvb_current_offset < tvb_len)
			{
				tvb_previous_offset = tvb_skip_wsp(tvb, tvb_current_offset,
				                                   tvb_current_len);
			}
			tokennum++;
		} while (tvb_current_offset < tvb_len && tvb_previous_offset < tvb_len && tokennum <= 3);

		switch (mgcp_type)
		{
			case MGCP_RESPONSE:
				hidden_item = proto_tree_add_boolean(tree, hf_mgcp_rsp, tvb, 0, 0, TRUE);
				PROTO_ITEM_SET_HIDDEN(hidden_item);
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
				if (pinfo->ptype == PT_TCP)
				{
					conversation = find_conversation(pinfo->fd->num, &pinfo->src,
					                                 &pinfo->dst, pinfo->ptype, pinfo->srcport,
					                                 pinfo->destport, 0);
				}
				else
				{
					/* XXX - can we just use NO_ADDR_B?  Unfortunately,
					 * you currently still have to pass a non-null
					 * pointer for the second address argument even
					 * if you do that.
					 */
					conversation = find_conversation(pinfo->fd->num, &null_address,
					                                 &pinfo->dst, pinfo->ptype, pinfo->srcport,
					                                 pinfo->destport, 0);
				}
				if (conversation != NULL)
				{
					/* Look only for matching request, if
					   matching conversation is available. */
					mgcp_call_key.transid = mi->transid;
					mgcp_call_key.conversation = conversation;
					mgcp_call = g_hash_table_lookup(mgcp_calls, &mgcp_call_key);
					if (mgcp_call)
					{
						/* Indicate the frame to which this is a reply. */
						if (mgcp_call->req_num)
						{
							proto_item* item;
							mi->request_available = TRUE;
							mgcp_call->responded = TRUE;
							mi->req_num = mgcp_call->req_num;
							g_strlcpy(mi->code,mgcp_call->code,5);
							item = proto_tree_add_uint_format(tree, hf_mgcp_req_frame,
							                                  tvb, 0, 0, mgcp_call->req_num,
							                                  "This is a response to a request in frame %u",
							                                  mgcp_call->req_num);
							PROTO_ITEM_SET_GENERATED(item);
							nstime_delta(&delta, &pinfo->fd->abs_ts, &mgcp_call->req_time);
							item = proto_tree_add_time(tree, hf_mgcp_time, tvb, 0, 0, &delta);
							PROTO_ITEM_SET_GENERATED(item);
						}

						if (mgcp_call->rsp_num == 0)
						{
							/* We have not yet seen a response to that call, so
							   this must be the first response; remember its
							   frame number. */
							mgcp_call->rsp_num = pinfo->fd->num;
						}
						else
						{
							/* We have seen a response to this call - but was it
							   *this* response? (disregard provisional responses) */
							if ((mgcp_call->rsp_num != pinfo->fd->num) &&
							    (mi->rspcode >= 200) &&
							    (mi->rspcode == mgcp_call->rspcode))
							{
								/* No, so it's a duplicate response. Mark it as such. */
								mi->is_duplicate = TRUE;
								col_append_fstr(pinfo->cinfo, COL_INFO,
								                ", Duplicate Response %u",
								                mi->transid);
								if (tree)
								{
									proto_item* item;
									item = proto_tree_add_uint(tree, hf_mgcp_dup, tvb, 0,0, mi->transid);
									PROTO_ITEM_SET_HIDDEN(item);
									item = proto_tree_add_uint(tree, hf_mgcp_rsp_dup,
									                           tvb, 0, 0, mi->transid);
									PROTO_ITEM_SET_GENERATED(item);
									item = proto_tree_add_uint(tree, hf_mgcp_rsp_dup_frame,
									                           tvb, 0, 0, mgcp_call->rsp_num);
									PROTO_ITEM_SET_GENERATED(item);
								}
							}
						}
						/* Now store the response code (after comparison above) */
						mgcp_call->rspcode = mi->rspcode;
					}
				}
				break;
			case MGCP_REQUEST:
				hidden_item = proto_tree_add_boolean(tree, hf_mgcp_req, tvb, 0, 0, TRUE);
				PROTO_ITEM_SET_HIDDEN(hidden_item);
				/* Keep track of the address and port whence the call came,
				 * and the port to which the call is being sent, so that
				 * we can match up calls with replies.
				 *
				 * If the transport is connection-oriented (we check, for
				 * now, only for "pinfo->ptype" of PT_TCP), we take
				 * into account the address from which the call was sent
				 * and the address to which the call was sent, because
				 * the addresses of the two endpoints should be the same
				 * for all calls and replies.
				 *
				 * If the transport is connectionless, we don't worry
				 * about the address to which the call was sent and from
				 * which the reply was sent, because there's no
				 * guarantee that the reply will come from the address
				 * to which the call was sent.
				 */
				if (pinfo->ptype == PT_TCP)
				{
					conversation = find_conversation(pinfo->fd->num, &pinfo->src,
					                                 &pinfo->dst, pinfo->ptype, pinfo->srcport,
					                                 pinfo->destport, 0);
				}
				else
				{
					/*
					 * XXX - can we just use NO_ADDR_B?  Unfortunately,
					 * you currently still have to pass a non-null
					 * pointer for the second address argument even
					 * if you do that.
					 */
					conversation = find_conversation(pinfo->fd->num, &pinfo->src,
					                                 &null_address, pinfo->ptype, pinfo->srcport,
					                                 pinfo->destport, 0);
				}
				if (conversation == NULL)
				{
					/* It's not part of any conversation - create a new one. */
					if (pinfo->ptype == PT_TCP)
					{
						conversation = conversation_new(pinfo->fd->num, &pinfo->src,
						                                &pinfo->dst, pinfo->ptype, pinfo->srcport,
						                                pinfo->destport, 0);
					}
					else
					{
						conversation = conversation_new(pinfo->fd->num, &pinfo->src,
						                                &null_address, pinfo->ptype, pinfo->srcport,
						                                pinfo->destport, 0);
					}
				}

				/* Prepare the key data */
				mgcp_call_key.transid = mi->transid;
				mgcp_call_key.conversation = conversation;

				/* Look up the request */
				mgcp_call = g_hash_table_lookup(mgcp_calls, &mgcp_call_key);
				if (mgcp_call != NULL)
				{
					/* We've seen a request with this TRANSID, with the same
					   source and destination, before - but was it
					   *this* request? */
					if (pinfo->fd->num != mgcp_call->req_num)
					{
						/* No, so it's a duplicate request. Mark it as such. */
						mi->is_duplicate = TRUE;
						mi->req_num = mgcp_call->req_num;
						col_append_fstr(pinfo->cinfo, COL_INFO,
						                ", Duplicate Request %u",
						                mi->transid);
						if (tree)
						{
							proto_item* item;
							item = proto_tree_add_uint(tree, hf_mgcp_dup, tvb, 0,0, mi->transid);
							PROTO_ITEM_SET_HIDDEN(item);
							item = proto_tree_add_uint(tree, hf_mgcp_req_dup, tvb, 0,0, mi->transid);
							PROTO_ITEM_SET_GENERATED(item);
							item = proto_tree_add_uint(tree, hf_mgcp_req_dup_frame, tvb, 0,0, mi->req_num);
							PROTO_ITEM_SET_GENERATED(item);
						}
					}
				}
				else
				{
					/* Prepare the value data.
					   "req_num" and "rsp_num" are frame numbers;
					   frame numbers are 1-origin, so we use 0
					   to mean "we don't yet know in which frame
					   the reply for this call appears". */
					new_mgcp_call_key = se_alloc(sizeof(*new_mgcp_call_key));
					*new_mgcp_call_key = mgcp_call_key;
					mgcp_call = se_alloc(sizeof(*mgcp_call));
					mgcp_call->req_num = pinfo->fd->num;
					mgcp_call->rsp_num = 0;
					mgcp_call->transid = mi->transid;
					mgcp_call->responded = FALSE;
					mgcp_call->req_time=pinfo->fd->abs_ts;
					g_strlcpy(mgcp_call->code,mi->code,5);

					/* Store it */
					g_hash_table_insert(mgcp_calls, new_mgcp_call_key, mgcp_call);
				}
				if (mgcp_call->rsp_num)
				{
					proto_item* item = proto_tree_add_uint_format(tree, hf_mgcp_rsp_frame,
					                                              tvb, 0, 0, mgcp_call->rsp_num,
					                                              "The response to this request is in frame %u",
					                                              mgcp_call->rsp_num);
					PROTO_ITEM_SET_GENERATED(item);
				}
				break;
			default:
				break;
		}

		mi->mgcp_type = mgcp_type;
		if (mgcp_call)
		{
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
 * tree - The tree from which to hang the structured information parsed
 *        from the parameters of the MGCP message.
 */
static void dissect_mgcp_params(tvbuff_t *tvb, proto_tree *tree)
{
	int linelen, tokenlen, *my_param;
	gint tvb_lineend, tvb_linebegin, tvb_len, old_lineend;
	gint tvb_tokenbegin;
	proto_tree *mgcp_param_ti, *mgcp_param_tree;

	tvb_len = tvb_length(tvb);
	tvb_linebegin = 0;
	tvb_lineend = tvb_linebegin;

	if (tree)
	{
		mgcp_param_ti = proto_tree_add_item(tree, hf_mgcp_params, tvb,
		                                    tvb_linebegin, tvb_len, ENC_NA);
		proto_item_set_text(mgcp_param_ti, "Parameters");
		mgcp_param_tree = proto_item_add_subtree(mgcp_param_ti, ett_mgcp_param);

		/* Parse the parameters */
		while (tvb_lineend < tvb_len)
		{
			old_lineend = tvb_lineend;
			linelen = tvb_find_line_end(tvb, tvb_linebegin, -1,&tvb_lineend,FALSE);
			tvb_tokenbegin = tvb_parse_param(tvb, tvb_linebegin, linelen, &my_param);

			if (my_param)
			{
				if (*my_param == hf_mgcp_param_connectionparam)
				{
					tokenlen = tvb_find_line_end(tvb,tvb_tokenbegin,-1,&tvb_lineend,FALSE);
					dissect_mgcp_connectionparams(mgcp_param_tree, tvb, tvb_linebegin,
					                              tvb_tokenbegin - tvb_linebegin, tokenlen);
				}
				else
				if (*my_param == hf_mgcp_param_localconnoptions)
				{
					tokenlen = tvb_find_line_end(tvb,tvb_tokenbegin,-1,&tvb_lineend,FALSE);
					dissect_mgcp_localconnectionoptions(mgcp_param_tree, tvb, tvb_linebegin,
					                                    tvb_tokenbegin - tvb_linebegin, tokenlen);
				}
				else
				{
					tokenlen = tvb_find_line_end(tvb,tvb_tokenbegin,-1,&tvb_lineend,FALSE);
					proto_tree_add_string(mgcp_param_tree,*my_param, tvb,
					                      tvb_linebegin, linelen,
					                      tvb_format_text(tvb,tvb_tokenbegin, tokenlen));
				}
			}

			tvb_linebegin = tvb_lineend;
			/* Its a infinite loop if we didn't advance (or went backwards) */
			if (old_lineend >= tvb_lineend)
			{
				THROW(ReportedBoundsError);
			}
		}
	}
}

/* Dissect the connection params */
static void
dissect_mgcp_connectionparams(proto_tree *parent_tree, tvbuff_t *tvb, gint offset, gint param_type_len, gint param_val_len)
{
	proto_tree *tree = parent_tree;
	proto_item *item = NULL;

	gchar *tokenline = NULL;
	gchar **tokens = NULL;
	gchar **typval = NULL;
	guint i = 0;
	guint tokenlen = 0;
	int hf_uint = -1;
	int hf_string = -1;

	if (parent_tree)
	{
		item = proto_tree_add_item(parent_tree, hf_mgcp_param_connectionparam, tvb, offset, param_type_len+param_val_len, ENC_ASCII|ENC_NA);
		tree = proto_item_add_subtree(item, ett_mgcp_param_connectionparam);
	}

	/* The P: line */
	offset += param_type_len; /* skip the P: */
	tokenline = tvb_get_ephemeral_string(tvb, offset, param_val_len);

	/* Split into type=value pairs separated by comma */
	tokens = ep_strsplit(tokenline, ",", -1);

	for (i = 0; tokens[i] != NULL; i++)
	{
		tokenlen = (int)strlen(tokens[i]);
		typval = ep_strsplit(tokens[i], "=", 2);
		if ((typval[0] != NULL) && (typval[1] != NULL))
		{
			if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "PS"))
			{
				hf_uint = hf_mgcp_param_connectionparam_ps;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "OS"))
			{
				hf_uint = hf_mgcp_param_connectionparam_os;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "PR"))
			{
				hf_uint = hf_mgcp_param_connectionparam_pr;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "OR"))
			{
				hf_uint = hf_mgcp_param_connectionparam_or;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "PL"))
			{
				hf_uint = hf_mgcp_param_connectionparam_pl;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "JI"))
			{
				hf_uint = hf_mgcp_param_connectionparam_ji;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "LA"))
			{
				hf_uint = hf_mgcp_param_connectionparam_la;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "PC/RPS"))
			{
				hf_uint = hf_mgcp_param_connectionparam_pcrps;
			} else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "PC/ROS"))
			{
				hf_uint = hf_mgcp_param_connectionparam_pcros;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "PC/RPL"))
			{
				hf_uint = hf_mgcp_param_connectionparam_pcrpl;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "PC/RJI"))
			{
				hf_uint = hf_mgcp_param_connectionparam_pcrji;
			}
			else if (!g_ascii_strncasecmp(g_strstrip(typval[0]), "X-", 2))
			{
				hf_string = hf_mgcp_param_connectionparam_x;
			}
			else
			{
				hf_uint = -1;
				hf_string = -1;
			}

			if (tree)
			{
				if (hf_uint != -1)
				{
					proto_tree_add_uint(tree, hf_uint, tvb, offset, tokenlen, atol(typval[1]));
				}
				else if (hf_string != -1)
				{
					proto_tree_add_string(tree, hf_string, tvb, offset, tokenlen, g_strstrip(typval[1]));
				}
				else
				{
					proto_tree_add_text(tree, tvb, offset, tokenlen, "Unknown parameter: %s", tokens[i]);
				}
			}
		}
		else if (tree)
		{
			proto_tree_add_text(tree, tvb, offset, tokenlen, "Malformed parameter: %s", tokens[i]);
		}
		offset += tokenlen + 1; /* 1 extra for the delimiter */
	}

}

/* Dissect the local connection option */
static void
dissect_mgcp_localconnectionoptions(proto_tree *parent_tree, tvbuff_t *tvb, gint offset, gint param_type_len, gint param_val_len)
{
	proto_tree *tree = parent_tree;
	proto_item *item = NULL;

	gchar *tokenline = NULL;
	gchar **tokens = NULL;
	gchar **typval = NULL;
	guint i = 0;
	guint tokenlen = 0;
	int hf_uint = -1;
	int hf_string = -1;

	if (parent_tree)
	{
		item = proto_tree_add_item(parent_tree, hf_mgcp_param_localconnoptions, tvb, offset, param_type_len+param_val_len, ENC_ASCII|ENC_NA);
		tree = proto_item_add_subtree(item, ett_mgcp_param_localconnectionoptions);
	}

	/* The L: line */
	offset += param_type_len; /* skip the L: */
	tokenline = tvb_get_ephemeral_string(tvb, offset, param_val_len);

	/* Split into type=value pairs separated by comma */
	tokens = ep_strsplit(tokenline, ",", -1);
	for (i = 0; tokens[i] != NULL; i++)
	{
		hf_uint = -1;
		hf_string = -1;

		tokenlen = (int)strlen(tokens[i]);
		typval = ep_strsplit(tokens[i], ":", 2);
		if ((typval[0] != NULL) && (typval[1] != NULL))
		{
			if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "p"))
			{
				hf_uint = hf_mgcp_param_localconnoptions_p;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "a"))
			{
				hf_string = hf_mgcp_param_localconnoptions_a;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "s"))
			{
				hf_string = hf_mgcp_param_localconnoptions_s;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "e"))
			{
				hf_string = hf_mgcp_param_localconnoptions_e;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "sc-rtp"))
			{
				hf_string = hf_mgcp_param_localconnoptions_scrtp;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "sc-rtcp"))
			{
				hf_string = hf_mgcp_param_localconnoptions_scrtcp;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "b"))
			{
				hf_string = hf_mgcp_param_localconnoptions_b;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "es-ccd"))
			{
				hf_string = hf_mgcp_param_localconnoptions_esccd;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "es-cci"))
			{
				hf_string = hf_mgcp_param_localconnoptions_escci;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "dq-gi"))
			{
				hf_string = hf_mgcp_param_localconnoptions_dqgi;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "dq-rd"))
			{
				hf_string = hf_mgcp_param_localconnoptions_dqrd;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "dq-ri"))
			{
				hf_string = hf_mgcp_param_localconnoptions_dqri;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "dq-rr"))
			{
				hf_string = hf_mgcp_param_localconnoptions_dqrr;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "k"))
			{
				hf_string = hf_mgcp_param_localconnoptions_k;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "gc"))
			{
				hf_uint = hf_mgcp_param_localconnoptions_gc;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "fmtp"))
			{
				hf_string = hf_mgcp_param_localconnoptions_fmtp;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "nt"))
			{
				hf_string = hf_mgcp_param_localconnoptions_nt;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "o-fmtp"))
			{
				hf_string = hf_mgcp_param_localconnoptions_ofmtp;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "r"))
			{
				hf_string = hf_mgcp_param_localconnoptions_r;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "t"))
			{
				hf_string = hf_mgcp_param_localconnoptions_t;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "r-cnf"))
			{
				hf_string = hf_mgcp_param_localconnoptions_rcnf;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "r-dir"))
			{
				hf_string = hf_mgcp_param_localconnoptions_rdir;
			}
			else if (!g_ascii_strcasecmp(g_strstrip(typval[0]), "r-sh"))
			{
				hf_string = hf_mgcp_param_localconnoptions_rsh;
			}
			else
			{
				hf_uint = -1;
				hf_string = -1;
			}

			/* Add item */
			if (tree)
			{
				if (hf_uint != -1)
				{
					proto_tree_add_uint(tree, hf_uint, tvb, offset, tokenlen, atol(typval[1]));
				}
				else if (hf_string != -1)
				{
					proto_tree_add_string(tree, hf_string, tvb, offset, tokenlen, g_strstrip(typval[1]));
				}
				else
				{
					proto_tree_add_text(tree, tvb, offset, tokenlen, "Unknown parameter: %s", tokens[i]);
				}
			}
		}
		else if (tree)
		{
			proto_tree_add_text(tree, tvb, offset, tokenlen, "Malformed parameter: %s", tokens[i]);
		}
		offset += tokenlen + 1; /* 1 extra for the delimiter */
	}
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
static gint tvb_find_null_line(tvbuff_t* tvb, gint offset, gint len, gint* next_offset)
{
	gint tvb_lineend,tvb_current_len,tvb_linebegin,maxoffset;
	guint tempchar;

	tvb_linebegin = offset;
	tvb_lineend = tvb_linebegin;

	/* Simple setup to allow for the traditional -1 search to the end of the tvbuff */
	if (len != -1)
	{
		tvb_current_len = len;
	}
	else
	{
		tvb_current_len = tvb_length_remaining(tvb,offset);
	}

	maxoffset = (tvb_current_len - 1) + offset;

	/* Loop around until we either find a line begining with a carriage return
	   or newline character or until we hit the end of the tvbuff. */
	do
	{
		tvb_linebegin = tvb_lineend;
		tvb_current_len = tvb_length_remaining(tvb,tvb_linebegin);
		tvb_find_line_end(tvb, tvb_linebegin, tvb_current_len, &tvb_lineend,FALSE);
		tempchar = tvb_get_guint8(tvb,tvb_linebegin);
	} while (tempchar != '\r' && tempchar != '\n' && tvb_lineend <= maxoffset);


	*next_offset = tvb_lineend;

	if (tvb_lineend <= maxoffset)
	{
		tvb_current_len = tvb_linebegin - offset;
	}
	else
	{
		tvb_current_len = tvb_length_remaining(tvb,offset);
	}

	return tvb_current_len;
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
static gint tvb_find_dot_line(tvbuff_t* tvb, gint offset, gint len, gint* next_offset)
{
	gint tvb_current_offset, tvb_current_len, maxoffset,tvb_len;
	guint8 tempchar;
	tvb_current_offset = offset;
	tvb_current_len = len;
	tvb_len = tvb_length(tvb);

	if (len == -1)
	{
		maxoffset = tvb_len - 1;
	}
	else
	{
		maxoffset = (len - 1) + offset;
	}
	tvb_current_offset = offset -1;

	do
	{
		tvb_current_offset = tvb_find_guint8(tvb, tvb_current_offset+1,
		                                     tvb_current_len, '.');
		tvb_current_len = maxoffset - tvb_current_offset + 1;

		/* If we didn't find a . then break out of the loop */
		if (tvb_current_offset == -1)
		{
			break;
		}

		/* Do we have and characters following the . ? */
		if (tvb_current_offset < maxoffset)
		{
			tempchar = tvb_get_guint8(tvb,tvb_current_offset+1);
			/* Are the characters that follow the dot a newline or carriage return ? */
			if (tempchar == '\r' || tempchar == '\n')
			{
				/* Do we have any charaters that proceed the . ? */
				if (tvb_current_offset == 0)
				{
					break;
				}
				else
				{
					tempchar = tvb_get_guint8(tvb,tvb_current_offset-1);

					/* Are the characters that follow the dot a newline or a
					   carriage return ? */
					if (tempchar == '\r' || tempchar == '\n')
					{
						break;
					}
				}
			}
		}
		else
		if (tvb_current_offset == maxoffset)
		{
			if (tvb_current_offset == 0)
			{
				break;
			}
			else
			{
				tempchar = tvb_get_guint8(tvb,tvb_current_offset-1);
				if (tempchar == '\r' || tempchar == '\n')
				{
					break;
				}
			}
		}
	} while (tvb_current_offset < maxoffset);


	/*
	 * So now we either have the tvb_current_offset of a . in a dot line
	 * or a tvb_current_offset of -1
	 */
	if (tvb_current_offset == -1)
	{
		tvb_current_offset = maxoffset +1;
		*next_offset = maxoffset + 1;
	}
	else
	{
		tvb_find_line_end(tvb,tvb_current_offset,tvb_current_len,next_offset,FALSE);
	}

	if (tvb_current_offset == offset)
	{
		tvb_current_len = -1;
	}
	else
	{
		tvb_current_len = tvb_current_offset - offset;
	}

	return tvb_current_len;
}

