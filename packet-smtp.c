/* packet-smtp.c
 * Routines for SMTP packet disassembly
 *
 * $Id: packet-smtp.c,v 1.6 2000/09/11 16:16:07 gram Exp $
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

struct smtp_request_val {
  guint16 processed;     /* Have we processed this conversation? */
  guint16 data_seen;     /* Have we seen the data packet */
  guint16 eom_seen;      /* Have we seen the end of message */
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

static
int find_smtp_resp_end(const u_char *pd, int offset)
{
  int cntr = 0;

  /* Look for the CRLF ... but keep in mind the END_OF_FRAME */

  while (END_OF_FRAME >= cntr) {

    if (pd[offset + cntr] == 0x0A) { /* Found it */

      if (END_OF_FRAME >= cntr + 1) cntr++;

      return cntr;

    }

    cntr++;

  }

  return cntr;

}

#if 0
static void
dissect_smtp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
#else
static void
dissect_smtp(const u_char *pd, int offset, frame_data *fd,
	     proto_tree *tree)
{
  /*    tvbuff_t *tvb = tvb_create_from_top(offset);*/
    packet_info *pinfo = &pi;
#endif
    struct smtp_proto_data  *frame_data;
    proto_tree              *smtp_tree, *ti;
    int                     request = 0;
    const u_char            *cmd = NULL;
    conversation_t          *conversation;
    struct smtp_request_key request_key, *new_request_key;
    struct smtp_request_val *request_val;

#if 0
    CHECK_DISPLAY_AS_DATA(proto_smtp, tvb, pinfo, tree);
#else
    OLD_CHECK_DISPLAY_AS_DATA(proto_smtp, pd, offset, fd, tree);
#endif

    /* If we have per frame data, use that, else, we must be on the first 
     * pass, so we figure it out on the first pass.
     * 
     * Since we can't stash info away in a conversation (as they are 
     * removed during a filter operation, and we can't rely on the visited
     * flag, as that is set to 0 during a filter, we must save per-frame
     * data for each frame. However, we only need it for requests. Responses
     * are easy to manage.
     */

    /* Find out what conversation this packet is part of ... but only
     * if we have no information on this packet, so find the per-frame 
     * info first.
     */

    /* SMTP messages have a simple format ... */

    request = pinfo -> destport == TCP_PORT_SMTP;
    cmd = pd + offset;   /* FIXME: What about tvb */

    frame_data = p_get_proto_data(pinfo->fd, proto_smtp);

    if (!frame_data) {

      conversation = find_conversation(&pinfo->src, &pinfo->dst, pi.ptype,
				       pinfo->srcport, pinfo->destport);
      if (conversation == NULL) { /* No conversation, create one */
	conversation = conversation_new(&pinfo->src, &pinfo->dst, pinfo->ptype,
					pinfo->srcport, pinfo->destport, NULL);

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
	request_val->processed = 0;
	request_val->data_seen = 0;
	request_val->eom_seen = 0;
	request_val->crlf_seen = 0;

	g_hash_table_insert(smtp_request_hash, new_request_key, request_val);

      }

      /* 
       * Check whether or not this packet is an end of message packet
       * We should look for CRLF.CRLF and they may be split.
       * We have to keep in mind that we may see what we want on
       * two passes through here ...
       */

      if (request_val->data_seen && !request_val->processed) {

	/*
	 * The order of these is important ... We want to avoid
	 * cases where there is a CRLF at the end of a packet and a 
	 * .CRLF at the begining of the same packet.
	 */

	if ((request_val->crlf_seen && strncmp(pd + offset, ".\r\n", 3) == 0) ||
	    (strncmp(pd + offset, "\r\n.\r\n", 5) == 0)) {

	  request_val->eom_seen = 1;

	}

	if (strncmp(pd + offset + END_OF_FRAME - 2, "\r\n", 2) == 0) {

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

	if (!request_val->processed) { 
	  if (strncmp(pd + offset, "DATA", 4)==0) {

	  request_val->data_seen = 1;
	  frame_data->pdu_type = SMTP_PDU_CMD;
	  p_add_proto_data(pinfo->fd, proto_smtp, frame_data);

	  } else if ((!request_val->eom_seen) &&
		     (request_val->data_seen)) {
	 
	    /* Now, create the frame data for this frame ... */

	    frame_data->pdu_type = SMTP_PDU_MESSAGE;
	    p_add_proto_data(pinfo->fd, proto_smtp, frame_data);

	  } else if (request_val->eom_seen) { /* Seen the EOM */

	    /* Now, we clear the eom_seen and data_seen bits */

	    request_val->eom_seen = request_val->data_seen = 0;
	    request_val->processed = 1;   /* We have seen all the packets */

	    /* And add the packet data */

	    frame_data->pdu_type = SMTP_PDU_EOM;
	    p_add_proto_data(pinfo->fd, proto_smtp, frame_data);

	  } else {

	    frame_data->pdu_type = SMTP_PDU_CMD;
	    p_add_proto_data(pinfo->fd, proto_smtp, frame_data);

	  }
	}
      }
    }

    /* 
     * From here, we simply add items to the tree and info to the info 
     * fields ...
     */

    if (check_col(fd, COL_PROTOCOL))
      col_add_str(fd, COL_PROTOCOL, "SMTP");

    if (check_col(fd, COL_INFO)) {  /* Add the appropriate type here */

      /*
       * If it is a request, we have to look things up, otherwise, just
       * display the right things 
       */

      if (request) {

	/* We must have frame_data here ... */

	switch (frame_data->pdu_type) {
	case SMTP_PDU_MESSAGE:

	  col_add_fstr(pinfo->fd, COL_INFO, "Message: %s", format_text(cmd, END_OF_FRAME));
	  break;

	case SMTP_PDU_EOM:

	  col_add_fstr(pinfo->fd, COL_INFO, "EOM: %s", format_text(cmd, END_OF_FRAME));
	  break;

	case SMTP_PDU_CMD:

	  col_add_fstr(pinfo->fd, COL_INFO, "%s", format_text(cmd, END_OF_FRAME));

	}

      }
      else {

	col_add_fstr(pinfo->fd, COL_INFO, "%s", format_text(cmd, END_OF_FRAME));

      }
    }

    if (tree) { /* Build the tree info ... */

      ti = proto_tree_add_item(tree, proto_smtp, NullTVB, offset, END_OF_FRAME, FALSE);
      smtp_tree = proto_item_add_subtree(ti, ett_smtp);
      proto_tree_add_boolean_hidden(smtp_tree, (request ? hf_smtp_req : hf_smtp_rsp),
				    NullTVB, offset, 4, TRUE);
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

	  proto_tree_add_protocol_format(smtp_tree, proto_smtp, NullTVB, offset, END_OF_FRAME, "Message: %s", format_text(cmd, END_OF_FRAME));

	  break;

	case SMTP_PDU_EOM:

	  proto_tree_add_protocol_format(smtp_tree, proto_smtp, NullTVB, offset, END_OF_FRAME, "EOM: %s", format_text(cmd, END_OF_FRAME));

	  break;

	case SMTP_PDU_CMD:
	  proto_tree_add_protocol_format(smtp_tree, proto_smtp, NullTVB, offset, 4, "Command: %s", format_text(cmd, 4));
	  proto_tree_add_protocol_format(smtp_tree, proto_smtp, NullTVB, offset + 5, END_OF_FRAME, "Parameter: %s", format_text(cmd + 5, END_OF_FRAME - 5));

	}

      }
      else {

	/* Must consider a multi-line response here ... */

	while (END_OF_FRAME >= 4 && pd[offset + 3] == '-') {
	  int resp_len = find_smtp_resp_end(pd, offset);

	  proto_tree_add_protocol_format(smtp_tree, proto_smtp, NullTVB, offset, 3, "Response: %s", format_text(pd + offset, 3));
	  proto_tree_add_protocol_format(smtp_tree, proto_smtp, NullTVB, offset + 4, resp_len, "Parameter: %s", format_text(pd + offset + 4, resp_len - 4));

	  offset += resp_len;
	}

	proto_tree_add_protocol_format(smtp_tree, proto_smtp, NullTVB, offset, 3, "Response: %s", format_text(pd + offset, 3));
	proto_tree_add_protocol_format(smtp_tree, proto_smtp, NullTVB, offset + 4, END_OF_FRAME, "Parameter: %s", format_text(pd + offset + 4, END_OF_FRAME - 4));
	
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

  proto_smtp = proto_register_protocol("Simple Mail Transfer Protocol", "smtp");

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

    old_dissector_delete("tcp.port", tcp_port, dissect_smtp);

  }
  else {

    smtp_prefs_initialized = TRUE;

  }

  tcp_port = global_smtp_tcp_port;

  old_dissector_add("tcp.port", global_smtp_tcp_port, dissect_smtp);

}
