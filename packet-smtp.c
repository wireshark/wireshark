/* packet-smtp.c
 * Routines for SMTP packet disassembly
 *
 * $Id: packet-smtp.c,v 1.13 2001/01/03 06:55:32 guy Exp $
 *
 * Copyright (c) 2000 by Richard Sharpe <rsharpe@ns.aus.com>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs
 * Copyright 1999 Gerald Combs
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <glib.h>
#include <string.h>
#include "packet.h"
#include "conversation.h"
#include "resolv.h"
#include "prefs.h"
#include "strutil.h"

#define TCP_PORT_SMTP 25

void proto_reg_handoff_smtp(void);

static int proto_smtp = -1;

static int hf_smtp_req = -1;
static int hf_smtp_rsp = -1;

static int ett_smtp = -1;

static int global_smtp_tcp_port = TCP_PORT_SMTP;

/*
 * A CMD is an SMTP command, MESSAGE is the message portion, and EOM is the
 * last part of a message
 */

#define SMTP_PDU_CMD     0   
#define SMTP_PDU_MESSAGE 1
#define SMTP_PDU_EOM     2

struct smtp_proto_data {
  guint16 pdu_type;
};

static int smtp_packet_init_count = 100;

struct smtp_request_key {
  guint32 conversation;
};

/*
 * State information stored with a conversation.
 */
struct smtp_request_val {
  gboolean reading_data; /* Reading message data, not commands */
  guint16 crlf_seen;     /* Have we seen a CRLF on the end of a packet */
};

GHashTable *smtp_request_hash = NULL;
GMemChunk  *smtp_request_keys = NULL;
GMemChunk  *smtp_request_vals = NULL;
GMemChunk  *smtp_packet_infos = NULL;

/* Hash Functions */
gint
smtp_equal(gconstpointer v, gconstpointer w)
{
  struct smtp_request_key *v1 = (struct smtp_request_key *)v;
  struct smtp_request_key *v2 = (struct smtp_request_key *)w;

#if defined(DEBUG_SMTP_HASH)
  printf("Comparing %08X\n      and %08X\n",
	 v1->conversation, v2->conversation);
#endif

  if (v1->conversation == v2->conversation)
    return 1;

  return 0;

}

static guint
smtp_hash(gconstpointer v)
{
  struct smtp_request_key *key = (struct smtp_request_key *)v;
  guint val;

  val = key->conversation;

#if defined(DEBUG_SMTP_HASH)
  printf("SMTP Hash calculated as %u\n", val);
#endif

  return val;

}

static void
smtp_init_protocol(void)
{
#if defined(DEBUG_SMTP_HASH)
  printf("Initializing SMTP hashtable area\n");
#endif

  if (smtp_request_hash)
    g_hash_table_destroy(smtp_request_hash);
  if (smtp_request_keys)
    g_mem_chunk_destroy(smtp_request_keys);
  if (smtp_request_vals)
    g_mem_chunk_destroy(smtp_request_vals);
  if (smtp_packet_infos)
    g_mem_chunk_destroy(smtp_packet_infos);

  smtp_request_hash = g_hash_table_new(smtp_hash, smtp_equal);
  smtp_request_keys = g_mem_chunk_new("smtp_request_keys",
				       sizeof(struct smtp_request_key),
				       smtp_packet_init_count * sizeof(struct smtp_request_key), G_ALLOC_AND_FREE);
  smtp_request_vals = g_mem_chunk_new("smtp_request_vals", 
				      sizeof(struct smtp_request_val),
				      smtp_packet_init_count * sizeof(struct smtp_request_val), G_ALLOC_AND_FREE);
  smtp_packet_infos = g_mem_chunk_new("smtp_packet_infos",
				      sizeof(struct smtp_proto_data),
				      smtp_packet_init_count * sizeof(struct smtp_proto_data), G_ALLOC_AND_FREE);

}

static void
dissect_smtp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    struct smtp_proto_data  *frame_data;
    proto_tree              *smtp_tree;
    proto_item              *ti;
    int                     offset = 0;
    int                     request = 0;
    conversation_t          *conversation;
    struct smtp_request_key request_key, *new_request_key;
    struct smtp_request_val *request_val;
    char                    *line;
    int                     linelen;
    gboolean                eom_seen = FALSE;
    gint                    next_offset;
    gboolean                is_continuation_line;
    int                     cmdlen;

    CHECK_DISPLAY_AS_DATA(proto_smtp, tvb, pinfo, tree);

    pinfo->current_proto = "SMTP";

    /* As there is no guarantee that we will only see frames in the
     * the SMTP conversation once, and that we will see them in
     * order - in Ethereal, the user could randomly click on frames
     * in the conversation in any order in which they choose - we
     * have to store information with each frame indicating whether
     * it contains commands or data or an EOM indication.
     *
     * XXX - what about frames that contain *both*?  TCP is a
     * byte-stream protocol, and there are no guarantees that
     * TCP segment boundaries will correspond to SMTP commands
     * or EOM indications.
     *
     * We only need that for the client->server stream; responses
     * are easy to manage.
     *
     * If we have per frame data, use that, else, we must be on the first 
     * pass, so we figure it out on the first pass.
     */

    /* Find out what conversation this packet is part of ... but only
     * if we have no information on this packet, so find the per-frame 
     * info first.
     */

    /* SMTP messages have a simple format ... */

    request = pinfo -> destport == TCP_PORT_SMTP;

    /*
     * Get the first line from the buffer.
     */
    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset);
    line = tvb_get_ptr(tvb, offset, linelen);

    frame_data = p_get_proto_data(pinfo->fd, proto_smtp);

    if (!frame_data) {

      conversation = find_conversation(&pinfo->src, &pinfo->dst, pi.ptype,
				       pinfo->srcport, pinfo->destport, 0);
      if (conversation == NULL) { /* No conversation, create one */
	conversation = conversation_new(&pinfo->src, &pinfo->dst, pinfo->ptype,
					pinfo->srcport, pinfo->destport, NULL,
					0);

      }

      /* 
       * Check for and insert an entry in the request table if does not exist
       */
      request_key.conversation = conversation->index;

      request_val = (struct smtp_request_val *)g_hash_table_lookup(smtp_request_hash, &request_key);
      
      if (!request_val) { /* Create one */

	new_request_key = g_mem_chunk_alloc(smtp_request_keys);
	new_request_key->conversation = conversation->index;

	request_val = g_mem_chunk_alloc(smtp_request_vals);
	request_val->reading_data = FALSE;
	request_val->crlf_seen = 0;

	g_hash_table_insert(smtp_request_hash, new_request_key, request_val);

      }

      /* 
       * Check whether or not this packet is an end of message packet
       * We should look for CRLF.CRLF and they may be split.
       * We have to keep in mind that we may see what we want on
       * two passes through here ...
       */

      if (request_val->reading_data) {

	/*
	 * The order of these is important ... We want to avoid
	 * cases where there is a CRLF at the end of a packet and a 
	 * .CRLF at the begining of the same packet.
	 */

	if ((request_val->crlf_seen && tvb_strneql(tvb, offset, ".\r\n", 3) == 0) ||
	    tvb_strneql(tvb, offset, "\r\n.\r\n", 5) == 0) {

	  eom_seen = TRUE;

	}

	if (tvb_strneql(tvb, offset + tvb_length_remaining(tvb, offset) - 2, "\r\n", 2) == 0) {

	  request_val->crlf_seen = 1;

	}
	else {

	  request_val->crlf_seen = 0;

	}
      }

    /*
     * OK, Check if we have seen a DATA request. We do it here for 
     * simplicity, but we have to be careful below.
     */

      if (request) {

	frame_data = g_mem_chunk_alloc(smtp_packet_infos);

	if (request_val->reading_data) {
	  /*
	   * This is message data.
	   */
	  if (eom_seen) { /* Seen the EOM */
	    /*
	     * EOM.
	     * Everything that comes after it is commands.
	     *
	     * XXX - what if the EOM isn't at the beginning of
	     * the TCP segment?  It can occur anywhere....
	     */
	    frame_data->pdu_type = SMTP_PDU_EOM;
	    request_val->reading_data = FALSE;
	  } else {
	    /*
	     * Message data with no EOM.
	     */
	    frame_data->pdu_type = SMTP_PDU_MESSAGE;
	  }
	} else {
	  /*
	   * This is commands - unless the capture started in the
	   * middle of a session, and we're in the middle of data.
	   * To quote RFC 821, "Command codes are four alphabetic
	   * characters"; if we don't see four alphabetic characters
	   * and, if there's anything else in the line, a space, we
	   * assume it's not a command.
	   * (We treat only A-Z and a-z as alphabetic.)
	   */
#define	ISALPHA(c)	(((c) >= 'A' && (c) <= 'Z') || \
			 ((c) >= 'a' && (c) <= 'z'))
	  if (linelen >= 4 && ISALPHA(line[0]) && ISALPHA(line[1]) &&
	      ISALPHA(line[2]) && ISALPHA(line[3]) &&
	      (linelen == 4 || line[4] == ' ')) {
	    if (strncasecmp(line, "DATA", 4) == 0) {

	      /*
	       * DATA command.
	       * This is a command, but everything that comes after it,
	       * until an EOM, is data.
	       */
	      frame_data->pdu_type = SMTP_PDU_CMD;
	      request_val->reading_data = TRUE;

	    } else {

	      /*
	       * Regular command.
	       */
	      frame_data->pdu_type = SMTP_PDU_CMD;

	    }
	  } else {

	    /*
	     * Assume it's message data.
	     */

	    frame_data->pdu_type = SMTP_PDU_MESSAGE;

	  }

	}

	p_add_proto_data(pinfo->fd, proto_smtp, frame_data);

      }
    }

    /* 
     * From here, we simply add items to the tree and info to the info 
     * fields ...
     */

    if (check_col(pinfo->fd, COL_PROTOCOL))
      col_set_str(pinfo->fd, COL_PROTOCOL, "SMTP");

    if (check_col(pinfo->fd, COL_INFO)) {  /* Add the appropriate type here */

      /*
       * If it is a request, we have to look things up, otherwise, just
       * display the right things 
       */

      if (request) {

	/* We must have frame_data here ... */

	switch (frame_data->pdu_type) {
	case SMTP_PDU_MESSAGE:

	  col_set_str(pinfo->fd, COL_INFO, "Message Body");
	  break;

	case SMTP_PDU_EOM:

	  col_add_fstr(pinfo->fd, COL_INFO, "EOM: %s",
	      format_text(line, linelen));
	  break;

	case SMTP_PDU_CMD:

	  col_add_fstr(pinfo->fd, COL_INFO, "Command: %s",
	      format_text(line, linelen));
	  break;

	}

      }
      else {

	col_add_fstr(pinfo->fd, COL_INFO, "Response: %s",
	    format_text(line, linelen));

      }
    }

    if (tree) { /* Build the tree info ... */

      ti = proto_tree_add_item(tree, proto_smtp, tvb, offset, END_OF_FRAME, FALSE);
      smtp_tree = proto_item_add_subtree(ti, ett_smtp);
      proto_tree_add_boolean_hidden(smtp_tree, (request ? hf_smtp_req : hf_smtp_rsp),
				    tvb, offset, 4, TRUE);
      if (request) {

	/* 
	 * Check out whether or not we can see a command in there ...
	 * What we are looking for is not data_seen and the word DATA
	 * and not eom_seen.
	 *
	 * We will see DATA and request_val->data_seen when we process the
	 * tree view after we have seen a DATA packet when processing
	 * the packet list pane.
	 *
	 * On the first pass, we will not have any info on the packets
	 * On second and subsequent passes, we will.
	 */

	switch (frame_data->pdu_type) {

	case SMTP_PDU_MESSAGE:

	  /*
	   * Message body.
	   * Put its lines into the protocol tree, a line at a time.
	   */
	  while (tvb_offset_exists(tvb, offset)) {

	    /*
	     * Find the end of the line.
	     */
	    tvb_find_line_end(tvb, offset, -1, &next_offset);

	    /*
	     * Put this line.
	     */
	    proto_tree_add_text(smtp_tree, tvb, offset, next_offset - offset,
	        "Message: %s",
		tvb_format_text(tvb, offset, next_offset - offset));

	    /*
	     * Step to the next line.
	     */
	    offset = next_offset;

	  }

	  break;

	case SMTP_PDU_EOM:

	  /*
	   * End-of-message-body indicator.
	   *
	   * XXX - what about stuff after the first line?
	   * Unlikely, as the client should wait for a response to the
	   * DATA command this terminates before sending another
	   * request, but we should probably handle it.
	   */
	  proto_tree_add_text(smtp_tree, tvb, offset, linelen,
	      "EOM: %s", format_text(line, linelen));

	  break;

	case SMTP_PDU_CMD:

	  /*
	   * Command.
	   *
	   * XXX - what about stuff after the first line?
	   * Unlikely, as the client should wait for a response to the
	   * previous command before sending another request, but we
	   * should probably handle it.
	   */
	  if (linelen >= 4)
	    cmdlen = 4;
	  else
	    cmdlen = linelen;
	  proto_tree_add_text(smtp_tree, tvb, offset, cmdlen,
	      "Command: %s", format_text(line, cmdlen));
	  if (linelen > 5) {
	    proto_tree_add_text(smtp_tree, tvb, offset + 5, linelen - 5,
	        "Parameter: %s", format_text(line + 5, linelen - 5));
	  }

	}

      }
      else {

        /*
	 * Process the response, a line at a time, until we hit a line
	 * that doesn't have a continuation indication on it.
	 */

	while (tvb_offset_exists(tvb, offset)) {

	  /*
	   * Find the end of the line.
	   */
	  linelen = tvb_find_line_end(tvb, offset, -1, &next_offset);

	  /*
	   * Is it a continuation line?
	   */
	  is_continuation_line =
	      (linelen >= 4 && tvb_get_guint8(tvb, offset + 3) == '-');

	  /*
	   * Put it into the protocol tree.
	   */
	  proto_tree_add_text(smtp_tree, tvb, offset, 3,
	      "Response: %s", tvb_format_text(tvb, offset, 3));
	  if (linelen >= 4) {
	    proto_tree_add_text(smtp_tree, tvb, offset + 4, linelen - 4,
	        "Parameter: %s", tvb_format_text(tvb, offset + 4, linelen - 4));
	  }

	  /*
	   * Step past this line.
	   */
	  offset = next_offset;

	  /*
	   * If it's not a continuation line, quit.
	   */
	  if (!is_continuation_line)
	    break;

	}
	
      }
    }
}

/* Register all the bits needed by the filtering engine */

void
proto_register_smtp(void)
{
  static hf_register_info hf[] = {
    { &hf_smtp_req,
      { "Request", "smtp.req", FT_BOOLEAN, BASE_NONE, NULL, 0x0, ""}},

    { &hf_smtp_rsp,
      { "Response", "smtp.rsp", FT_BOOLEAN, BASE_NONE, NULL, 0x0, ""}},
  };
  static gint *ett[] = {
    &ett_smtp
  };
  /*module_t *smtp_module = NULL; */  /* Not yet used */

  /* No Configuration options to register? */

  proto_smtp = proto_register_protocol("Simple Mail Transfer Protocol",
				       "SMTP", "smtp");

  proto_register_field_array(proto_smtp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_init_routine(&smtp_init_protocol);

}

/* The registration hand-off routine */
void
proto_reg_handoff_smtp(void)
{
  static int smtp_prefs_initialized = FALSE;
  static int tcp_port = 0;

  if (smtp_prefs_initialized) {

    dissector_delete("tcp.port", tcp_port, dissect_smtp);

  }
  else {

    smtp_prefs_initialized = TRUE;

  }

  tcp_port = global_smtp_tcp_port;

  dissector_add("tcp.port", global_smtp_tcp_port, dissect_smtp);

}
