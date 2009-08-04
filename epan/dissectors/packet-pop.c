/* packet-pop.c
 * Routines for pop packet dissection
 * RFC 1939
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-tftp.c
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

#include <stdio.h>

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include "packet-ssl.h"

static int proto_pop = -1;

static int hf_pop_response = -1;
static int hf_pop_response_indicator = -1;
static int hf_pop_response_description = -1;
static int hf_pop_response_data = -1;

static int hf_pop_request = -1;
static int hf_pop_request_command = -1;
static int hf_pop_request_parameter = -1;
static int hf_pop_request_data = -1;

static int hf_pop_data_fragments = -1;
static int hf_pop_data_fragment = -1;
static int hf_pop_data_fragment_overlap = -1;
static int hf_pop_data_fragment_overlap_conflicts = -1;
static int hf_pop_data_fragment_multiple_tails = -1;
static int hf_pop_data_fragment_too_long_fragment = -1;
static int hf_pop_data_fragment_error = -1;
static int hf_pop_data_reassembled_in = -1;

static gint ett_pop = -1;
static gint ett_pop_reqresp = -1;

static gint ett_pop_data_fragment = -1;
static gint ett_pop_data_fragments = -1;

static dissector_handle_t data_handle;
static dissector_handle_t imf_handle = NULL;

#define TCP_PORT_POP			110
#define TCP_PORT_SSL_POP		995

/* desegmentation of POP command and response lines */
static gboolean pop_data_desegment = TRUE;

static GHashTable *pop_data_segment_table = NULL;
static GHashTable *pop_data_reassembled_table = NULL;

static const fragment_items pop_data_frag_items = {
	/* Fragment subtrees */
	&ett_pop_data_fragment,
	&ett_pop_data_fragments,
	/* Fragment fields */
	&hf_pop_data_fragments,
	&hf_pop_data_fragment,
	&hf_pop_data_fragment_overlap,
	&hf_pop_data_fragment_overlap_conflicts,
	&hf_pop_data_fragment_multiple_tails,
	&hf_pop_data_fragment_too_long_fragment,
	&hf_pop_data_fragment_error,
	/* Reassembled in field */
	&hf_pop_data_reassembled_in,
	/* Tag */
	"DATA fragments"
};

struct pop_proto_data {
  guint16 conversation_id;
  gboolean more_frags;
};

struct pop_data_val {
  gboolean msg_request;
  guint32 msg_read_len;  /* Length of RETR message read so far */
  guint32 msg_tot_len;   /* Total length of RETR message */
};



static gboolean response_is_continuation(const guchar *data);

static void
dissect_pop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        struct pop_proto_data  *frame_data;
	gboolean     is_request;
	gboolean     is_continuation;
	proto_tree   *pop_tree, *reqresp_tree;
	proto_item   *ti;
	gint         offset = 0;
	const guchar *line;
	gint         next_offset;
	int          linelen;
	int          tokenlen;
	const guchar *next_token;
	fragment_data  *frag_msg = NULL;
	tvbuff_t     *next_tvb = NULL;
	conversation_t          *conversation = NULL;
	struct pop_data_val *data_val = NULL;
	gint         length_remaining;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "POP");

	/*
	 * Find the end of the first line.
	 *
	 * Note that "tvb_find_line_end()" will return a value that is
	 * not longer than what's in the buffer, so the "tvb_get_ptr()"
	 * call won't throw an exception.
	 */
	linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
	line = tvb_get_ptr(tvb, offset, linelen);

	if (pinfo->match_port == pinfo->destport) {
		is_request = TRUE;
		is_continuation = FALSE;
	} else {
		is_request = FALSE;
		is_continuation = response_is_continuation(line);
	}

	frame_data = p_get_proto_data(pinfo->fd, proto_pop);

	if (!frame_data) {

	  conversation = find_conversation(pinfo->fd->num, 
					   &pinfo->src, &pinfo->dst, 
					   pinfo->ptype,
					   pinfo->srcport, pinfo->destport, 0);

	  if (conversation == NULL) { /* No conversation, create one */
	    conversation = conversation_new(pinfo->fd->num, 
					    &pinfo->src, &pinfo->dst, pinfo->ptype,
					    pinfo->srcport, pinfo->destport, 0);
	  }

	  data_val = conversation_get_proto_data(conversation, proto_pop);

	  if (!data_val) {

	    /*
	     * No - create one and attach it.
	     */
	    data_val = se_alloc(sizeof(struct pop_data_val));
	    data_val->msg_request = FALSE;
	    data_val->msg_read_len = 0;
	    data_val->msg_tot_len = 0;
	    
	    conversation_add_proto_data(conversation, proto_pop, data_val);
	  }
	}

	if (check_col(pinfo->cinfo, COL_INFO)) {
		/*
		 * Put the first line from the buffer into the summary
		 * if it's a POP request or reply (but leave out the
		 * line terminator).
		 * Otherwise, just call it a continuation.
		 */
		if (is_continuation) {
			length_remaining = tvb_length_remaining(tvb, offset);
			col_set_str(pinfo->cinfo, COL_INFO, "S: DATA fragment");
		        col_append_fstr(pinfo->cinfo, COL_INFO, ", %d byte%s", 
					length_remaining,  
					plurality (length_remaining, "", "s"));
		}
		else
			col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s",
			    is_request ? "C" : "S",
			    format_text(line, linelen));
	}

	if (tree) { 
		ti = proto_tree_add_item(tree, proto_pop, tvb, offset, -1,
		    FALSE);
		pop_tree = proto_item_add_subtree(ti, ett_pop);

		if (is_continuation) {

		  if(pop_data_desegment) {

		    if(!frame_data) {

   		      data_val->msg_read_len += tvb_length(tvb);

		      frame_data = se_alloc(sizeof(struct pop_proto_data));

		      frame_data->conversation_id = conversation->index;
		      frame_data->more_frags = data_val->msg_read_len < data_val->msg_tot_len;

		      p_add_proto_data(pinfo->fd, proto_pop, frame_data);	
		    }

		    frag_msg = fragment_add_seq_next (tvb, 0, pinfo, 
						      frame_data->conversation_id, 
						      pop_data_segment_table, 
						      pop_data_reassembled_table, 
						      tvb_length(tvb), 
						      frame_data->more_frags);

		    next_tvb = process_reassembled_data (tvb, offset, pinfo, 
							 "Reassembled DATA",
							 frag_msg, &pop_data_frag_items, 
							 NULL, pop_tree);

		    if(next_tvb) {

		      if(imf_handle)
                call_dissector(imf_handle, next_tvb, pinfo, tree);

		      if(data_val) {
			      /* we have read everything - reset */
			      
			      data_val->msg_read_len = 0;
			      data_val->msg_tot_len = 0; 
		      }
		      pinfo->fragmented = FALSE;
		    } else {
		      pinfo->fragmented = TRUE;
		    }

		  } else {

		    /*
		     * Put the whole packet into the tree as data.
		     */
		    call_dissector(data_handle,tvb, pinfo, pop_tree);
		  
		  }
		  return;
		}

		/*
		 * Put the line into the protocol tree.
		 */
		ti = proto_tree_add_string_format(pop_tree,
		                                  (is_request) ?
		                                      hf_pop_request :
		                                      hf_pop_response,
		                                  tvb, offset,
		                                  next_offset - offset,
		                                  "", "%s",
		                                  tvb_format_text(tvb, offset, next_offset - offset));
		reqresp_tree = proto_item_add_subtree(ti, ett_pop_reqresp);

		/*
		 * Extract the first token, and, if there is a first
		 * token, add it as the request or reply code.
		 */
		tokenlen = get_token_len(line, line + linelen, &next_token);
		if (tokenlen != 0) {
			proto_tree_add_item(reqresp_tree,
			                    (is_request) ?
			                        hf_pop_request_command :
			                        hf_pop_response_indicator,
			                    tvb, offset, tokenlen, FALSE);

			if(is_request) {
			  /* see if this is RETR or TOP command */
			  if(data_val && ((g_ascii_strncasecmp(line, "RETR", 4) == 0) ||
			     (g_ascii_strncasecmp(line, "TOP", 3) == 0)))
			    /* the next response will tell us how many bytes */
			    data_val->msg_request = TRUE;
			} else {
			  if(data_val && data_val->msg_request) {
			    /* this is a response to a RETR or TOP command */

			    if(g_ascii_strncasecmp(line, "+OK ", 4) == 0) {
			      /* the message will be sent - work out how many bytes */
			      data_val->msg_read_len = 0;
			      data_val->msg_tot_len = atoi(line + 4);
			    }
			    data_val->msg_request = FALSE;
			  }
			}

			offset += (gint) (next_token - line);
			linelen -= (int) (next_token - line);
		}

		/*
		 * Add the rest of the first line as request or
		 * reply param/description.
		 */
		if (linelen != 0) {
			proto_tree_add_item(reqresp_tree,
			                    (is_request) ?
			                        hf_pop_request_parameter :
			                        hf_pop_response_description,
			                    tvb, offset, linelen, FALSE);
		}
		offset = next_offset;

		/*
		 * Show the rest of the request or response as text,
		 * a line at a time.
		 */
		while (tvb_offset_exists(tvb, offset)) {
			/*
			 * Find the end of the line.
			 */
			tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);

			/*
			 * Put this line.
			 */
			proto_tree_add_string_format(pop_tree,
			                             (is_request) ?
			                                 hf_pop_request_data :
			                                 hf_pop_response_data,
			                             tvb, offset,
			                             next_offset - offset,
			                             "", "%s",
			                             tvb_format_text(tvb, offset, next_offset - offset));
			offset = next_offset;
		}
	} 
}

static gboolean response_is_continuation(const guchar *data)
{
  if (strncmp(data, "+OK", strlen("+OK")) == 0)
    return FALSE;

  if (strncmp(data, "-ERR", strlen("-ERR")) == 0)
    return FALSE;

  return TRUE;
}

static void pop_data_reassemble_init (void)
{
  fragment_table_init (&pop_data_segment_table);
  reassembled_table_init (&pop_data_reassembled_table);
}

void
proto_register_pop(void)
{
  static hf_register_info hf[] = {
    { &hf_pop_response,
      { "Response",           "pop.response",
	    FT_STRING, BASE_NONE, NULL, 0x0,
      	NULL, HFILL }},
    { &hf_pop_response_indicator,
      { "Response indicator",           "pop.response.indicator",
	    FT_STRING, BASE_NONE, NULL, 0x0,
      	NULL, HFILL }},
    { &hf_pop_response_description,
      { "Response description",           "pop.response.description",
	     FT_STRING, BASE_NONE, NULL, 0x0,
	     NULL, HFILL }},
    { &hf_pop_response_data,
      { "Data",           "pop.response.data",
	     FT_STRING, BASE_NONE, NULL, 0x0,
	     "Response Data", HFILL }},
    { &hf_pop_request,
      { "Request",           "pop.request",
	    FT_STRING, BASE_NONE, NULL, 0x0,
      	NULL, HFILL }},
    { &hf_pop_request_command,
      { "Request command",            "pop.request.command",
	    FT_STRING, BASE_NONE, NULL, 0x0,
      	NULL, HFILL }},
    { &hf_pop_request_parameter,
      { "Request parameter",            "pop.request.parameter",
	    FT_STRING, BASE_NONE, NULL, 0x0,
      	NULL, HFILL }},
    { &hf_pop_request_data,
      { "Data",           "pop.request.data",
	     FT_STRING, BASE_NONE, NULL, 0x0,
	     "Request data", HFILL }},
    /* Fragment entries */
    { &hf_pop_data_fragments,
      { "DATA fragments", "pop.data.fragments", FT_NONE, BASE_NONE,
	NULL, 0x00, "Message fragments", HFILL } },
    { &hf_pop_data_fragment,
      { "DATA fragment", "pop.data.fragment", FT_FRAMENUM, BASE_NONE,
	NULL, 0x00, "Message fragment", HFILL } },
    { &hf_pop_data_fragment_overlap,
      { "DATA fragment overlap", "pop.data.fragment.overlap", FT_BOOLEAN,
	BASE_NONE, NULL, 0x0, "Message fragment overlap", HFILL } },
    { &hf_pop_data_fragment_overlap_conflicts,
      { "DATA fragment overlapping with conflicting data",
	"pop.data.fragment.overlap.conflicts", FT_BOOLEAN, BASE_NONE, NULL,
	0x0, "Message fragment overlapping with conflicting data", HFILL } },
    { &hf_pop_data_fragment_multiple_tails,
      { "DATA has multiple tail fragments",
	"pop.data.fragment.multiple_tails", FT_BOOLEAN, BASE_NONE,
	NULL, 0x0, "Message has multiple tail fragments", HFILL } },
    { &hf_pop_data_fragment_too_long_fragment,
      { "DATA fragment too long", "pop.data.fragment.too_long_fragment",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0, "Message fragment too long",
	HFILL } },
    { &hf_pop_data_fragment_error,
      { "DATA defragmentation error", "pop.data.fragment.error", FT_FRAMENUM,
	BASE_NONE, NULL, 0x00, "Message defragmentation error", HFILL } },
    { &hf_pop_data_reassembled_in,
      { "Reassembled DATA in frame", "pop.data.reassembled.in", FT_FRAMENUM, BASE_NONE,
	NULL, 0x00, "This DATA fragment is reassembled in this frame", HFILL } },
  };

  static gint *ett[] = {
    &ett_pop,
    &ett_pop_reqresp,
    &ett_pop_data_fragment,
    &ett_pop_data_fragments
  };
  module_t *pop_module;


  proto_pop = proto_register_protocol("Post Office Protocol", "POP", "pop");
  register_dissector("pop", dissect_pop, proto_pop);
  proto_register_field_array(proto_pop, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_init_routine (&pop_data_reassemble_init);

  /* Preferences */
  pop_module = prefs_register_protocol(proto_pop, NULL);

  prefs_register_bool_preference(pop_module, "desegment_data",
    "Reassemble POP RETR and TOP responses spanning multiple TCP segments",
    "Whether the POP dissector should reassemble RETR and TOP responses and spanning multiple TCP segments."
    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &pop_data_desegment);
}

void
proto_reg_handoff_pop(void)
{
  dissector_handle_t pop_handle;

  pop_handle = find_dissector("pop");
  dissector_add("tcp.port", TCP_PORT_POP, pop_handle);
  ssl_dissector_add(TCP_PORT_SSL_POP, "pop", TRUE);
  data_handle = find_dissector("data");

  /* find the IMF dissector */
  imf_handle = find_dissector("imf");

}
