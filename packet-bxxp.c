/* packet-bxxp.c
 * Routines for BXXP packet disassembly
 *
 * $Id: packet-bxxp.c,v 1.3 2000/09/12 02:24:19 sharpe Exp $
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
#include "resolv.h"
#include "prefs.h"
#include "conversation.h"

#define TCP_PORT_BXXP 10288
void proto_reg_handoff_bxxp(void);

static int proto_bxxp = -1;

static int hf_bxxp_req = -1;
static int hf_bxxp_rsp = -1;
static int hf_bxxp_seq = -1;
static int hf_bxxp_end = -1;    /* Do we need this one?        */
static int hf_bxxp_complete = -1;   /* More data follows */
static int hf_bxxp_intermediate = -1; /* No More data follows */
static int hf_bxxp_serial = -1;
static int hf_bxxp_seqno = -1;
static int hf_bxxp_size = -1;
static int hf_bxxp_channel = -1;
static int hf_bxxp_positive = -1;
static int hf_bxxp_negative = -1;
static int hf_bxxp_ackno = -1;
static int hf_bxxp_window = -1;

static int ett_bxxp = -1;
static int ett_mime_header = -1;
static int ett_header = -1;
static int ett_trailer = -1;

static int tcp_port = 0;

/* Get the state of the more flag ... */

#define BXXP_VIOL         0
#define BXXP_INTERMEDIATE 1
#define BXXP_COMPLETE     2

/*
 * Per-frame data
 *
 * pl_left is the amount of data in this packet that belongs to another
 * frame ...
 * 
 * It relies on TCP segments not being re-ordered too much ...
 */
struct bxxp_proto_data {
  int pl_left;   /* Payload at beginning of frame */
  int pl_size;   /* Payload in current message ...*/
};

/*
 * Conversation stuff
 */
static int bxxp_packet_init_count = 100;

struct bxxp_request_key {
  guint32 conversation;
};

struct bxxp_request_val {
  guint16 processed;     /* Have we processed this conversation? */
  int size;              /* Size of the message                  */
};

GHashTable *bxxp_request_hash = NULL;
GMemChunk  *bxxp_request_keys = NULL;
GMemChunk  *bxxp_request_vals = NULL;
GMemChunk  *bxxp_packet_infos = NULL;

/* Hash Functions */
gint
bxxp_equal(gconstpointer v, gconstpointer w)
{
  struct bxxp_request_key *v1 = (struct bxxp_request_key *)v;
  struct bxxp_request_key *v2 = (struct bxxp_request_key *)w;

#if defined(DEBUG_BXXP_HASH)
  printf("Comparing %08X\n      and %08X\n",
	 v1->conversation, v2->conversation);
#endif

  if (v1->conversation == v2->conversation)
    return 1;

  return 0;

}

static guint
bxxp_hash(gconstpointer v)
{
  struct bxxp_request_key *key = (struct bxxp_request_key *)v;
  guint val;

  val = key->conversation;

#if defined(DEBUG_BXXP_HASH)
  printf("BXXP Hash calculated as %u\n", val);
#endif

  return val;

}

static void
bxxp_init_protocol(void)
{
#if defined(DEBUG_BXXP_HASH)
  fprintf(stderr, "Initializing BXXP hashtable area\n");
#endif

  if (bxxp_request_hash)
    g_hash_table_destroy(bxxp_request_hash);
  if (bxxp_request_keys)
    g_mem_chunk_destroy(bxxp_request_keys);
  if (bxxp_request_vals)
    g_mem_chunk_destroy(bxxp_request_vals);
  if (bxxp_packet_infos)
    g_mem_chunk_destroy(bxxp_packet_infos);

  bxxp_request_hash = g_hash_table_new(bxxp_hash, bxxp_equal);
  bxxp_request_keys = g_mem_chunk_new("bxxp_request_keys",
				       sizeof(struct bxxp_request_key),
				       bxxp_packet_init_count * sizeof(struct bxxp_request_key), G_ALLOC_AND_FREE);
  bxxp_request_vals = g_mem_chunk_new("bxxp_request_vals", 
				      sizeof(struct bxxp_request_val),
				      bxxp_packet_init_count * sizeof(struct bxxp_request_val), G_ALLOC_AND_FREE);
  bxxp_packet_infos = g_mem_chunk_new("bxxp_packet_infos",
				      sizeof(struct bxxp_proto_data),
				      bxxp_packet_init_count * sizeof(struct bxxp_proto_data), G_ALLOC_AND_FREE);
}

/*
 * BXXP routines
 */

int bxxp_get_more(char more)
{

  if (more == '.')
    return BXXP_COMPLETE;
  else if (more == '*')
    return BXXP_INTERMEDIATE;

  return BXXP_VIOL;
}

void
dissect_bxxp_more(tvbuff_t *tvb, int offset, frame_data *fd, 
		  proto_tree *tree)
{

  switch (bxxp_get_more(tvb_get_guint8(tvb, offset))) {

  case BXXP_COMPLETE:

    proto_tree_add_boolean_hidden(tree, hf_bxxp_complete, tvb, offset, 1, TRUE);
    proto_tree_add_text(tree, tvb, offset, 1, "More: Complete");

    break;

  case BXXP_INTERMEDIATE:
	
    proto_tree_add_boolean_hidden(tree, hf_bxxp_intermediate, tvb, offset, 1, TRUE);
    proto_tree_add_text(tree, tvb, offset, 1, "More: Intermediate");

    break;

  default:  /* FIXME: Add code for this case ... */

    fprintf(stderr, "Error from bxxp_get_more ...\n");
    break;
  }

}

void dissect_bxxp_status(tvbuff_t *tvb, int offset, frame_data *fd,
			 proto_tree *tree)
{
  
  switch(tvb_get_guint8(tvb, offset)) {

  case '+':
  
    proto_tree_add_boolean_hidden(tree, hf_bxxp_positive, tvb, offset, 1, TRUE);
    proto_tree_add_text(tree, tvb, offset, 1, "Status: Positive");

    break;

  case '-':

    proto_tree_add_boolean_hidden(tree, hf_bxxp_negative, tvb, offset, 1, TRUE);
    proto_tree_add_text(tree, tvb, offset, 1, "Status: Negative");

    break;

  default:  /* Proto violation: FIXME */

    break;

  }

}

int num_len(tvbuff_t *tvb, int offset)
{
  int i = 0;

  while (isdigit(tvb_get_guint8(tvb, offset + i))) i++;

  return i;

}

/* Get the MIME header length */
int header_len(tvbuff_t *tvb, int offset)
{
  int i = 0;

  while (tvb_get_guint8(tvb, offset + i) != 0x0d 
	 && tvb_get_guint8(tvb, offset + i + 1) != 0x0a) i++;

  return i;

}

int
dissect_bxxp_mime_header(tvbuff_t *tvb, int offset, frame_data *fd,
			 proto_tree *tree)
{
  proto_tree    *ti, *mime_tree;
  int           mime_length = header_len(tvb, offset);

  ti = proto_tree_add_text(tree, tvb, offset, mime_length + 2, "Mime header: %s", tvb_format_text(tvb, offset, mime_length + 2));
  mime_tree = proto_item_add_subtree(ti, ett_mime_header);

  if (mime_length == 0) { /* Default header */

    proto_tree_add_text(mime_tree, tvb, offset, 2, "Default values");

  }
  else {  /* FIXME: Process the headers */


  }

  return mime_length + 2;  /* FIXME: Check that the CRLF is there */

}

int
dissect_bxxp_int(tvbuff_t *tvb, int offset, frame_data *fd,
		    proto_tree *tree, int hf, int *val)
{
  int ival, i = num_len(tvb, offset);
  guint8 int_buff[100];

  memset(int_buff, '\0', sizeof(int_buff));

  tvb_memcpy(tvb, int_buff, offset, MIN(sizeof(int_buff), i));

  sscanf(int_buff, "%d", &ival);  /* FIXME: Dangerous */

  proto_tree_add_uint(tree, hf, tvb, offset, i, ival);

  *val = ival;  /* Return the value */

  return i;

}

int 
check_crlf(tvbuff_t *tvb, int offset)
{

  return (tvb_get_guint8(tvb, offset) == 0x0d
	  && tvb_get_guint8(tvb, offset + 1) == 0x0a);

}

static int global_bxxp_tcp_port = TCP_PORT_BXXP;

/* Build the tree */

int
dissect_bxxp_tree(tvbuff_t *tvb, int offset, packet_info *pinfo, 
		  proto_tree *tree, struct bxxp_request_val *request_val, 
		  struct bxxp_proto_data *frame_data)
{
  proto_tree     *ti, *hdr;
  int            st_offset, serial, seqno, size, channel, ackno, window;

  st_offset = offset;

  if (tvb_strneql(tvb, offset, "REQ ", 4) == 0) {

    ti = proto_tree_add_text(tree, tvb, offset, header_len(tvb, offset) + 2, "Header");

    hdr = proto_item_add_subtree(ti, ett_header);

    proto_tree_add_boolean_hidden(hdr, hf_bxxp_req, tvb, offset, 3, TRUE);
    proto_tree_add_text(hdr, NullTVB, offset, 3, "Command: REQ");

    offset += 3;

#if 0
    if (tvb_get_guint8(tvb, offset) != ' ') { /* Protocol violation */

      /* Hmm, FIXME ... Add some code here ... */

    }
#endif

    offset += 1;  /* Skip the space */

    /* Insert the more elements ... */

    dissect_bxxp_more(tvb, offset, pinfo->fd, hdr);
    offset += 1;
      
    /* Check the space ... */

    offset += 1;

    /* Dissect the serial */

    offset += dissect_bxxp_int(tvb, offset, pinfo->fd, hdr, hf_bxxp_serial, &serial);
    /* skip the space */

    offset += 1;

    /* now for the seqno */

    offset += dissect_bxxp_int(tvb, offset, pinfo->fd, hdr, hf_bxxp_seqno, &seqno);

    /* skip the space */

    offset += 1;

    offset += dissect_bxxp_int(tvb, offset, pinfo->fd, hdr, hf_bxxp_size, &size);
    if (request_val)
      request_val -> size = size;  /* Stash this away */
    else {
      frame_data->pl_size = size;
      if (frame_data->pl_size < 0) frame_data->pl_size = 0;
    }

    /* Check the space */

    offset += 1;

    /* Get the channel */

    offset += dissect_bxxp_int(tvb, offset, pinfo->fd, hdr, hf_bxxp_channel, &channel);
      
    if (check_crlf(tvb, offset)) {

      proto_tree_add_text(hdr, tvb, offset, 2, "Terminator: CRLF");

    }
    else {  /* Protocol violation */

      /* FIXME: implement */

    }

    offset += 2;
    
    /* Insert MIME header ... */

    offset += dissect_bxxp_mime_header(tvb, offset, pinfo->fd, hdr);

    /* Now for the payload, if any */

    if (tvb_length_remaining(tvb, offset) > 0) { /* Dissect what is left as payload */

      int pl_size = MIN(size, tvb_length_remaining(tvb, offset));

      /* Except, check the payload length, and only dissect that much */

      /* We need to keep track, in the conversation, of how much is left 
       * so in the next packet, we can figure out what is part of the payload
       * and what is the next message
       */

      proto_tree_add_text(tree, tvb, offset, pl_size, "Payload: %s", tvb_format_text(tvb, offset, pl_size));

      offset += pl_size;

      if (request_val) {
	request_val->size -= pl_size;
	if (request_val->size < 0) request_val->size = 0;
      }
      else {
	frame_data->pl_size -= pl_size;
	if (frame_data->pl_size < 0) frame_data->pl_size = 0;
      }
    }
      
    /* If anything else left, dissect it ... As what? */

    if (tvb_length_remaining(tvb, offset) > 0)
      offset += dissect_bxxp_tree(tvb, offset, pinfo, tree, request_val, frame_data);

  } else if (tvb_strneql(tvb, offset, "RSP ", 4) == 0) {

    /* FIXME: Fix the header length */

    ti = proto_tree_add_text(tree, tvb, offset, header_len(tvb, offset) + 2, "Header");

    hdr = proto_item_add_subtree(ti, ett_header);

    proto_tree_add_boolean_hidden(hdr, hf_bxxp_rsp, NullTVB, offset, 3, TRUE);
    proto_tree_add_text(hdr, tvb, offset, 3, "Command: RSP");

    offset += 3;

    /* Now check the space: FIXME */

    offset += 1;

    /* Next, the 'more' flag ... */

    dissect_bxxp_more(tvb, offset, pinfo->fd, hdr);
    offset += 1;

    /* Check the space */

    offset += 1;

    offset += dissect_bxxp_int(tvb, offset, pinfo->fd, hdr, hf_bxxp_serial, &serial);
    /* skip the space */

    offset += 1;

    /* now for the seqno */

    offset += dissect_bxxp_int(tvb, offset, pinfo->fd, hdr, hf_bxxp_seqno, &seqno);

    /* skip the space */

    offset += 1;

    offset += dissect_bxxp_int(tvb, offset, pinfo->fd, hdr, hf_bxxp_size, &size);
    if (request_val)
      request_val->size = size;
    else
      frame_data->pl_size = size;

    /* Check the space ... */

    offset += 1;

    dissect_bxxp_status(tvb, offset, pinfo->fd, hdr);

    offset += 1;

    if (check_crlf(tvb, offset)) {

      proto_tree_add_text(hdr, tvb, offset, 2, "Terminator: CRLF");

    }
    else {  /* Protocol violation */

      /* FIXME: implement */

    }

    offset += 2;
    
    /* Insert MIME header ... */

    offset += dissect_bxxp_mime_header(tvb, offset, pinfo->fd, hdr);

    /* Now for the payload, if any */

    if (tvb_length_remaining(tvb, offset) > 0) { /* Dissect what is left as payload */

      int pl_size = MIN(size, tvb_length_remaining(tvb, offset));
      
      /* Except, check the payload length, and only dissect that much */

      proto_tree_add_text(tree, tvb, offset, pl_size, "Payload: %s", tvb_format_text(tvb, offset, pl_size));

      offset += pl_size;

      if (request_val) {
	request_val->size -= pl_size;
	if (request_val->size < 0) request_val->size = 0;
      }
      else {
	frame_data->pl_size -= pl_size;
	if (frame_data->pl_size < 0) frame_data->pl_size = 0;
      }
    }

    /* If anything else left, dissect it ... As what? */

    if (tvb_length_remaining(tvb, offset) > 0)
      offset += dissect_bxxp_tree(tvb, offset, pinfo, tree, request_val, frame_data);

  } else if (tvb_strneql(tvb, offset, "SEQ ", 4) == 0) {

    proto_tree_add_boolean_hidden(tree, hf_bxxp_seq, NullTVB, offset, 3, TRUE);
    proto_tree_add_text(tree, tvb, offset, 3, "Command: SEQ");
      
    offset += 3;

    /* Now check the space: FIXME */

    offset += 1;

    offset += dissect_bxxp_int(tvb, offset, pinfo->fd, tree, hf_bxxp_channel, &channel);

    /* Check the space: FIXME */

    offset += 1;

    offset += dissect_bxxp_int(tvb, offset, pinfo->fd, tree, hf_bxxp_ackno, &ackno);

    /* Check the space: FIXME */

    offset += 1;

    offset += dissect_bxxp_int(tvb, offset, pinfo->fd, tree, hf_bxxp_window, &window);

    if (check_crlf(tvb, offset)) {

      proto_tree_add_text(tree, tvb, offset, 2, "Terminator: CRLF");

    }
    else {  /* Protocol violation */

      /* FIXME: implement */

    }

    offset += 2;

  } else if (tvb_strneql(tvb, offset, "END", 3) == 0) {

    proto_tree *tr;

    ti = proto_tree_add_text(tree, tvb, offset, MIN(5, tvb_length_remaining(tvb, offset)), "Trailer");

    tr = proto_item_add_subtree(ti, ett_trailer);

    proto_tree_add_boolean_hidden(tr, hf_bxxp_end, NullTVB, offset, 3, TRUE);
    proto_tree_add_text(tr, tvb, offset, 3, "Command: END");

    offset += 3;

    if (check_crlf(tvb, offset)) {

      proto_tree_add_text(tr, tvb, offset, 2, "Terminator: CRLF");

    }
    else {  /* Protocol violation */

      /* FIXME: implement */

    }

    offset += 2;

  }

  if (tvb_length_remaining(tvb, offset) > 0) { /* Dissect anything left over */

    int pl_size = 0;

    if (request_val) {

      pl_size = MIN(request_val->size, tvb_length_remaining(tvb, offset));

      if (pl_size == 0) { /* The whole of the rest must be payload */
      
	pl_size = tvb_length_remaining(tvb, offset); /* Right place ? */
      
      }

    } else if (frame_data) {
      pl_size = MIN(frame_data->pl_size, tvb_length_remaining(tvb, offset));
    } else { /* Just in case */
      pl_size = tvb_length_remaining(tvb, offset);
    }

    /* Take care here to handle the payload correctly, and if there is 
     * another message here, then handle it correctly as well.
     */

    /* If the pl_size == 0 and the offset == 0, then we have not processed
     * anything in this frame above, so we better treat all this data as 
     * payload to avoid recursion loops
     */

    if (pl_size == 0 && offset == 0)
      pl_size = tvb_length_remaining(tvb, offset);

    if (pl_size > 0) {

      proto_tree_add_text(tree, tvb, offset, pl_size, "Payload: %s",
			  tvb_format_text(tvb, offset, pl_size));

      offset += pl_size;            /* Advance past the payload */

      if (request_val){
	request_val->size -= pl_size; /* Reduce payload by what we added */
	if (request_val->size < 0) request_val->size = 0;
      }
      else {
	frame_data->pl_size -= pl_size;
	if (frame_data->pl_size < 0) frame_data->pl_size = 0;
      }
    }

    if (tvb_length_remaining(tvb, offset) > 0) {
      offset += dissect_bxxp_tree(tvb, offset, pinfo, tree, request_val, frame_data);
    }
  }

  return offset - st_offset;

}

static void
dissect_bxxp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  int offset;
  struct bxxp_proto_data  *frame_data = NULL;
  proto_tree              *bxxp_tree, *ti;
  conversation_t          *conversation = NULL;
  struct bxxp_request_key request_key, *new_request_key;
  struct bxxp_request_val *request_val = NULL;

  CHECK_DISPLAY_AS_DATA(proto_bxxp, tvb, pinfo, tree);

  offset = 0;

  /* If we have per frame data, use that, else, we must have lost the per-
   * frame data, and we have to do a full dissect pass again.
   *
   * The per-frame data tells us how much of this frame is left over from a
   * previous frame, so we dissect it as payload and then try to dissect the
   * rest.
   * 
   * We use the conversation to build up info on the first pass over the
   * packets of type BXXP, and record anything that is needed if the user
   * does random dissects of packets in per packet data.
   *
   * Once we have per-packet data, we don't need the conversation stuff 
   * anymore, but if per-packet data and conversation stuff gets deleted, as 
   * it does under some circumstances when a rescan is done, it all gets 
   * rebuilt.
   */

  /* Find out what conversation this packet is part of ... but only
   * if we have no information on this packet, so find the per-frame 
   * info first.
   */

  frame_data = p_get_proto_data(pinfo->fd, proto_bxxp);

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

      request_val = (struct bxxp_request_val *)g_hash_table_lookup(bxxp_request_hash, &request_key);
      
      if (!request_val) { /* Create one */

	new_request_key = g_mem_chunk_alloc(bxxp_request_keys);
	new_request_key->conversation = conversation->index;

	request_val = g_mem_chunk_alloc(bxxp_request_vals);
	request_val->processed = 0;
	request_val->size = 0;

	g_hash_table_insert(bxxp_request_hash, new_request_key, request_val);

      }
    }

  if (check_col(pinfo->fd, COL_PROTOCOL))
    col_add_str(pinfo->fd, COL_PROTOCOL, "BXXP");

  if (check_col(pinfo->fd, COL_INFO)) {  /* Check the type ... */

    col_add_fstr(pinfo->fd, COL_INFO, "%s", tvb_format_text(tvb, offset, tvb_length_remaining(tvb, offset)));

  }

  if (tree) {  /* Build the tree info ... */

    /* Check the per-frame data and the conversation for any left-over 
     * payload from the previous frame 
     */

    ti = proto_tree_add_item(tree, proto_bxxp, tvb, offset, tvb_length(tvb), FALSE);

    bxxp_tree = proto_item_add_subtree(ti, ett_bxxp);

    /* FIXME: This conditional is not correct */
    if ((frame_data && frame_data->pl_left > 0) ||
	(request_val && request_val->size > 0)) {
      int pl_left = 0;

      if (frame_data) {
	pl_left = frame_data->pl_left;
      }
      else {
	pl_left = request_val->size;

	request_val->size = 0;

	/* We create the frame data here for this case, and 
	 * elsewhere for other frames
	 */

	frame_data = g_mem_chunk_alloc(bxxp_packet_infos);

	frame_data->pl_left = pl_left;
	frame_data->pl_size = 0;

	p_add_proto_data(pinfo->fd, proto_bxxp, frame_data);

      }

      pl_left = MIN(pl_left, tvb_length_remaining(tvb, offset));

      /* Add the payload bit */
      proto_tree_add_text(bxxp_tree, tvb, offset, pl_left, "Payload: %s",
			  tvb_format_text(tvb, offset, pl_left));
      offset += pl_left;
    }

    if (tvb_length_remaining(tvb, offset) > 0) {

      offset += dissect_bxxp_tree(tvb, offset, pinfo, bxxp_tree, request_val, frame_data);

    }

    /* Set up the per-frame data here if not already done so */

    if (frame_data == NULL) { 

      frame_data = g_mem_chunk_alloc(bxxp_packet_infos);

      frame_data->pl_left = 0;
      frame_data->pl_size = 0;

      p_add_proto_data(pinfo->fd, proto_bxxp, frame_data);
	
    }

  }

}

/* Register all the bits needed with the filtering engine */

void 
proto_register_bxxp(void)
{
  static hf_register_info hf[] = {
    { &hf_bxxp_req,
      { "Request", "bxxp.req", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "" }},

    { &hf_bxxp_rsp,
      { "Response", "bxxp.rsp", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "" }},

    { &hf_bxxp_seq,
      { "Sequence", "bxxp.seq", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "" }},

    { &hf_bxxp_end,
      { "End", "bxxp.end", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "" }},

    { &hf_bxxp_complete,
      { "Complete", "bxxp.more.complete", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "" }},

    { &hf_bxxp_intermediate,
      { "Intermediate", "bxxp.more.intermediate", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "" }},

    { &hf_bxxp_serial,
      { "Serial", "bxxp.serial", FT_UINT32, BASE_DEC, NULL, 0x0, "" }},

    { &hf_bxxp_seqno,
      { "Seqno", "bxxp.seqno", FT_UINT32, BASE_DEC, NULL, 0x0, "" }},

    { &hf_bxxp_size,
      { "Size", "bxxp.size", FT_UINT32, BASE_DEC, NULL, 0x0, "" }},

    { &hf_bxxp_channel,
      { "Channel", "bxxp.channel", FT_UINT32, BASE_DEC, NULL, 0x0, "" }},

    { &hf_bxxp_negative,
      { "Negative", "bxxp.status.negative", FT_BOOLEAN, BASE_NONE, NULL, 0x0, ""}},

    { &hf_bxxp_positive,
      { "Positive", "bxxp.status.positive", FT_BOOLEAN, BASE_NONE, NULL, 0x0, ""}},

    { &hf_bxxp_ackno,
      { "Ackno", "bxxp.seq.ackno", FT_UINT32, BASE_DEC, NULL, 0x0, ""}},

    { &hf_bxxp_window,
      { "Window", "bxxp.seq.window", FT_UINT32, BASE_DEC, NULL, 0x0, ""}},

  };
  static gint *ett[] = {
    &ett_bxxp,
    &ett_mime_header,
    &ett_header,
    &ett_trailer,
  };
  module_t *bxxp_module; 

  /* Register our configuration options for BXXP, particularly out port */

  bxxp_module = prefs_register_module("bxxp", "BXXP", proto_reg_handoff_bxxp);

  prefs_register_uint_preference(bxxp_module, "tcp.port", "BXXP TCP Port",
				 "Set the port for BXXP messages (if other"
				 " than the default of 10288)",
				 10, &global_bxxp_tcp_port);

  proto_bxxp = proto_register_protocol("Blocks eXtensible eXchange Protocol",
				       "bxxp");

  proto_register_field_array(proto_bxxp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_init_routine(&bxxp_init_protocol);

}

/* The registration hand-off routine */
void
proto_reg_handoff_bxxp(void)
{
  static int bxxp_prefs_initialized = FALSE;

  if (bxxp_prefs_initialized) {

    dissector_delete("tcp.port", tcp_port, dissect_bxxp);

  }
  else {

    bxxp_prefs_initialized = TRUE;

  }

  /* Set our port number for future use */

  tcp_port = global_bxxp_tcp_port;

  dissector_add("tcp.port", global_bxxp_tcp_port, dissect_bxxp);

}
