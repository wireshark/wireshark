/* packet-bxxp.c
 * Routines for BXXP packet disassembly
 *
 * $Id: packet-bxxp.c,v 1.7 2000/10/07 04:48:40 sharpe Exp $
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


static int global_bxxp_tcp_port = TCP_PORT_BXXP;
static int global_bxxp_strict_term = TRUE;

static int proto_bxxp = -1;

static int hf_bxxp_req = -1;
static int hf_bxxp_req_chan = -1;
static int hf_bxxp_rsp_chan = -1;
static int hf_bxxp_seq_chan = -1;
static int hf_bxxp_rsp = -1;
static int hf_bxxp_seq = -1;
static int hf_bxxp_end = -1;
static int hf_bxxp_proto_viol = -1;
static int hf_bxxp_complete = -1;   /* No More data follows */
static int hf_bxxp_intermediate = -1; /* More data follows */
static int hf_bxxp_serial = -1;
static int hf_bxxp_seqno = -1;
static int hf_bxxp_size = -1;
static int hf_bxxp_channel = -1;
static int hf_bxxp_positive = -1;
static int hf_bxxp_negative = -1;
static int hf_bxxp_ackno = -1;
static int hf_bxxp_window = -1;

/* Arrays of hf entry pointers for some routines to use. If you want more
 * hidden items added for a field, add them to the list before the NULL, 
 * and the various routines that these are passed to will add them.
 */

static int *req_serial_hfa[] = { &hf_bxxp_serial, NULL };
static int *req_seqno_hfa[]  = { &hf_bxxp_seqno, NULL };
static int *req_size_hfa[]   = { &hf_bxxp_size, NULL };
static int *req_chan_hfa[]   = { &hf_bxxp_channel, &hf_bxxp_req_chan, NULL };
static int *rsp_serial_hfa[] = { &hf_bxxp_serial, NULL };
static int *rsp_seqno_hfa[]  = { &hf_bxxp_seqno, NULL };
static int *rsp_size_hfa[]   = { &hf_bxxp_size, NULL };
static int *seq_chan_hfa[]   = { &hf_bxxp_channel, &hf_bxxp_seq_chan, NULL };
static int *seq_ackno_hfa[]  = { &hf_bxxp_ackno, NULL };
static int *seq_window_hfa[] = { &hf_bxxp_window, NULL };

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
  int mime_hdr;  /* Whether we expect a mime header. 1 on first, 0 on rest 
		  * in a message
		  */
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
                         /* We need an indication in each dirn of
			  * whether on not a mime header is expected 
			  */
  int c_mime_hdr, s_mime_hdr;
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

/* dissect the more flag, and return a value of:
 *  1 -> more
 *  0 -> no more
 *  -1 -> Proto violation
 */

int
dissect_bxxp_more(tvbuff_t *tvb, int offset, frame_data *fd, 
		  proto_tree *tree)
{


  switch (bxxp_get_more(tvb_get_guint8(tvb, offset))) {

  case BXXP_COMPLETE:

    if (tree) {
      proto_tree_add_boolean_hidden(tree, hf_bxxp_complete, tvb, offset, 1, TRUE);
      proto_tree_add_text(tree, tvb, offset, 1, "More: Complete");
    }

    return 0;

    break;

  case BXXP_INTERMEDIATE:

    if (tree) {
      proto_tree_add_boolean_hidden(tree, hf_bxxp_intermediate, tvb, offset, 1, TRUE);
      proto_tree_add_text(tree, tvb, offset, 1, "More: Intermediate");
    }

    return 1;

    break;

  default:  

    if (tree) {
      proto_tree_add_boolean_hidden(tree, hf_bxxp_proto_viol, tvb, offset, 1, TRUE);
      proto_tree_add_text(tree, tvb, offset, 1, "PROTOCOL VIOLATION: Expected More Flag (* or .)");
    }

    return -1;

    break;
  }

}

void dissect_bxxp_status(tvbuff_t *tvb, int offset, frame_data *fd,
			 proto_tree *tree)
{

  /* FIXME: We should return a value to indicate all OK. */
  
  switch(tvb_get_guint8(tvb, offset)) {

  case '+':

    if (tree) {
      proto_tree_add_boolean_hidden(tree, hf_bxxp_positive, tvb, offset, 1, TRUE);
      proto_tree_add_text(tree, tvb, offset, 1, "Status: Positive");
    }

    break;

  case '-':

    if (tree) {
      proto_tree_add_boolean_hidden(tree, hf_bxxp_negative, tvb, offset, 1, TRUE);
      proto_tree_add_text(tree, tvb, offset, 1, "Status: Negative");
    }

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

/*
 * We check for a terminator. This can be CRLF, which will be recorded
 * as a terminator, or CR or LF by itself, which will be redorded as
 * an incorrect terminator ... We build the tree at this point
 * However, we depend on the variable bxxp_strict_term
 */ 

int 
check_term(tvbuff_t *tvb, int offset, proto_tree *tree)
{

  /* First, check for CRLF, or, if global_bxxp_strict_term is false, 
   * one of CR or LF ... If neither of these hold, we add an element
   * that complains of a protocol violation, and return -1, else
   * we add a terminator to the tree (possibly non-standard) and return
   * the count of characters we saw ... This may throw off the rest of the 
   * dissection ... so-be-it!
   */

  if ((tvb_get_guint8(tvb, offset) == 0x0d && 
       tvb_get_guint8(tvb, offset + 1) == 0x0a)){ /* Correct terminator */

    if (tree) {
      proto_tree_add_text(tree, tvb, offset, 2, "Terminator: CRLF");
    }
    return 2;

  }
  else if ((tvb_get_guint8(tvb, offset) == 0x0d) && !global_bxxp_strict_term) {

    if (tree) {
      proto_tree_add_text(tree, tvb, offset, 1, "Nonstandard Terminator: CR");
      proto_tree_add_boolean_hidden(tree, hf_bxxp_proto_viol, tvb, offset, 1, TRUE);
    }
    return 1;

  }
  else if ((tvb_get_guint8(tvb, offset) == 0x0a) && !global_bxxp_strict_term) {

    if (tree) {
      proto_tree_add_text(tree, tvb, offset, 1, "Nonstandard Terminator: LF");
      proto_tree_add_boolean_hidden(tree, hf_bxxp_proto_viol, tvb, offset, 1, TRUE);
    }
    return 1;

  }
  else {    

    if (tree) {
      proto_tree_add_text(tree, tvb, offset, 2, "PROTOCOL VIOLATION, Invalid Terminator: %s", tvb_format_text(tvb, offset, 2));
      proto_tree_add_boolean_hidden(tree, hf_bxxp_proto_viol, tvb, offset, 2, TRUE);
    }
    return -1;

  }

}

/* Get the header length, up to CRLF or CR or LF */
int header_len(tvbuff_t *tvb, int offset)
{
  int i = 0;
  guint8 sc;

  /* FIXME: Have to make sure we stop looking at the end of the tvb ... */

  /* We look for CRLF, or CR or LF if global_bxxp_strict_term is 
   * not set.
   */

  while (1) {

    if (tvb_length_remaining(tvb, offset + i) < 1)
      return i;   /* Not enough characters left ... */

    if ((sc = tvb_get_guint8(tvb, offset + i)) == 0x0d 
	&& tvb_get_guint8(tvb, offset + i + 1) == 0x0a)
      return i;   /* Done here ... */

    if (!global_bxxp_strict_term && (sc == 0x0d || sc == 0x0a))
      return i;   /* Done here also ... */
	  
    i++;

  }
}

int
dissect_bxxp_mime_header(tvbuff_t *tvb, int offset, 
			 struct bxxp_proto_data *frame_data,
			 proto_tree *tree)
{
  proto_tree    *ti = NULL, *mime_tree = NULL;
  int           mime_length = header_len(tvb, offset), cc = 0;

  if (frame_data && !frame_data->mime_hdr) return 0;

  if (tree) {

    /* FIXME: Should calculate the whole length of the mime headers */

    ti = proto_tree_add_text(tree, tvb, offset, mime_length, "Mime header: %s", tvb_format_text(tvb, offset, mime_length));
    mime_tree = proto_item_add_subtree(ti, ett_mime_header);
  }

  if (mime_length == 0) { /* Default header */

    if (tree) {
      proto_tree_add_text(mime_tree, tvb, offset, 0, "Default values");
    }

    if ((cc = check_term(tvb, offset, mime_tree)) <= 0) {

      /* Ignore it, it will cause funnies in the rest of the dissect */

    }

  }
  else {  /* FIXME: Process the headers */

    if (tree) {
      proto_tree_add_text(mime_tree, tvb, offset, mime_length, "Header: %s", 
			  tvb_format_text(tvb, offset, mime_length));
    }

    if ((cc = check_term(tvb, offset + mime_length, mime_tree)) <= 0) {

      /* Ignore it, it will cause funnies in the rest of the dissect */

    }

  }

  return mime_length + cc;  /* FIXME: Check that the CRLF is there */

}

int
dissect_bxxp_int(tvbuff_t *tvb, int offset, frame_data *fd,
		    proto_tree *tree, int hf, int *val, int *hfa[])
{
  int ival, ind = 0, i = num_len(tvb, offset);
  guint8 int_buff[100];

  memset(int_buff, '\0', sizeof(int_buff));

  tvb_memcpy(tvb, int_buff, offset, MIN(sizeof(int_buff), i));

  sscanf(int_buff, "%d", &ival);  /* FIXME: Dangerous */

  if (tree) {
    proto_tree_add_uint(tree, hf, tvb, offset, i, ival);
  }

  while (hfa[ind]) {

    proto_tree_add_uint_hidden(tree, *hfa[ind], tvb, offset, i, ival);
    ind++;

  }

  *val = ival;  /* Return the value */

  return i;

}

void
set_mime_hdr_flags(int more, struct bxxp_request_val *request_val, 
		   struct bxxp_proto_data *frame_data)
{

  if (!request_val) return; /* Nothing to do ??? */

  if (pi.destport == tcp_port) { /* Going to the server ... client */

    if (request_val->c_mime_hdr) {

      frame_data->mime_hdr = 0;

      if (!more) request_val->c_mime_hdr = 0; 

    }
    else {

      frame_data->mime_hdr = 1;

      if (more) request_val->c_mime_hdr = 1;

    }

  }
  else {

    if (request_val->s_mime_hdr) {

      frame_data->mime_hdr = 0;

      if (!more) request_val->s_mime_hdr = 0; 

    }
    else {

      frame_data->mime_hdr = 1;

      if (more) request_val->s_mime_hdr = 1;

    }

  }

}

/* Build the tree
 *
 * A return value of <= 0 says we bailed out, skip the rest of this message,
 * if any.
 *
 * A return value > 0 is the count of bytes we consumed ...
 */

int
dissect_bxxp_tree(tvbuff_t *tvb, int offset, packet_info *pinfo, 
		  proto_tree *tree, struct bxxp_request_val *request_val, 
		  struct bxxp_proto_data *frame_data)
{
  proto_tree     *ti = NULL, *hdr = NULL;
  int            st_offset, serial, seqno, size, channel, ackno, window, cc,
                 more;

  st_offset = offset;

  if (tvb_strneql(tvb, offset, "REQ ", 4) == 0) {

    if (tree) {
      ti = proto_tree_add_text(tree, tvb, offset, header_len(tvb, offset) + 2, "Header");

      hdr = proto_item_add_subtree(ti, ett_header);

      proto_tree_add_boolean_hidden(hdr, hf_bxxp_req, tvb, offset, 3, TRUE);
      proto_tree_add_text(hdr, NullTVB, offset, 3, "Command: REQ");
    }

    offset += 3;

#if 0
    if (tvb_get_guint8(tvb, offset) != ' ') { /* Protocol violation */

      /* Hmm, FIXME ... Add some code here ... */

    }
#endif

    offset += 1;  /* Skip the space */

    /* Insert the more elements ... */

    if ((more = dissect_bxxp_more(tvb, offset, pinfo->fd, hdr)) >= 0) {

      /* Figure out which direction this is in and what mime_hdr flag to 
       * add to the frame_data. If there are missing segments, this code
       * will get it wrong!
       */

      set_mime_hdr_flags(more, request_val, frame_data);

    }
    else {  /* Protocol violation, so dissect rest as undisectable */

      if (tree) {

	proto_tree_add_text(hdr, tvb, offset, 
			    tvb_length_remaining(tvb, offset),
			    "Undissected Payload: %s",
			    tvb_format_text(tvb, offset,
					    tvb_length_remaining(tvb, offset)
					    )
			    );

      }

      return -1;

    }

    offset += 1;
      
    /* Check the space ... */

    offset += 1;

    /* Dissect the serial */

    offset += dissect_bxxp_int(tvb, offset, pinfo->fd, hdr, hf_bxxp_serial, &serial, req_serial_hfa);
    /* skip the space */

    offset += 1;

    /* now for the seqno */

    offset += dissect_bxxp_int(tvb, offset, pinfo->fd, hdr, hf_bxxp_seqno, &seqno, req_seqno_hfa);

    /* skip the space */

    offset += 1;

    offset += dissect_bxxp_int(tvb, offset, pinfo->fd, hdr, hf_bxxp_size, &size, req_size_hfa);
    if (request_val)   /* FIXME, is this the right order ... */
      request_val -> size = size;  /* Stash this away */
    else {
      frame_data->pl_size = size;
      if (frame_data->pl_size < 0) frame_data->pl_size = 0; /* FIXME: OK? */
    }

    /* Check the space */

    offset += 1;

    /* Get the channel */

    offset += dissect_bxxp_int(tvb, offset, pinfo->fd, hdr, hf_bxxp_channel, &channel, req_chan_hfa);
      
    if ((cc = check_term(tvb, offset, hdr)) <= 0) {

      /* We dissect the rest as data and bail ... */

      if (tree) {
	proto_tree_add_text(hdr, tvb, offset, 
			    tvb_length_remaining(tvb, offset),
			    "Undissected Payload: %s", 
			    tvb_format_text(tvb, offset, 
					    tvb_length_remaining(tvb, offset)
					    )
			    );
      }

      return -1;

    }

    offset += cc;
    
    /* Insert MIME header ... */

    if (frame_data && frame_data->mime_hdr)
      offset += dissect_bxxp_mime_header(tvb, offset, frame_data, hdr);

    /* Now for the payload, if any */

    if (tvb_length_remaining(tvb, offset) > 0) { /* Dissect what is left as payload */

      int pl_size = MIN(size, tvb_length_remaining(tvb, offset));

      /* Except, check the payload length, and only dissect that much */

      /* We need to keep track, in the conversation, of how much is left 
       * so in the next packet, we can figure out what is part of the payload
       * and what is the next message
       */

      if (tree) {
	proto_tree_add_text(tree, tvb, offset, pl_size, "Payload: %s", tvb_format_text(tvb, offset, pl_size));

      }

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
      
    /* If anything else left, dissect it ... */

    if (tvb_length_remaining(tvb, offset) > 0)
      offset += dissect_bxxp_tree(tvb, offset, pinfo, tree, request_val, frame_data);

  } else if (tvb_strneql(tvb, offset, "RSP ", 4) == 0) {

    if (tree) {

      ti = proto_tree_add_text(tree, tvb, offset, header_len(tvb, offset) + 2, "Header");

      hdr = proto_item_add_subtree(ti, ett_header);

      proto_tree_add_boolean_hidden(hdr, hf_bxxp_rsp, NullTVB, offset, 3, TRUE);
      proto_tree_add_text(hdr, tvb, offset, 3, "Command: RSP");

    }

    offset += 3;

    /* Now check the space: FIXME */

    offset += 1;

    /* Next, the 'more' flag ... */

    if ((more = dissect_bxxp_more(tvb, offset, pinfo->fd, hdr)) >= 0) {

      set_mime_hdr_flags(more, request_val, frame_data);

    }
    else { 

      if (tree) {

	proto_tree_add_text(hdr, tvb, offset, 
			    tvb_length_remaining(tvb, offset),
			    "Undissected Payload: %s",
			    tvb_format_text(tvb, offset,
					    tvb_length_remaining(tvb, offset)
					    )
			    );

      }

      return -1;

    }

    offset += 1;

    /* Check the space */

    offset += 1;

    offset += dissect_bxxp_int(tvb, offset, pinfo->fd, hdr, hf_bxxp_serial, &serial, rsp_serial_hfa);
    /* skip the space */

    offset += 1;

    /* now for the seqno */

    offset += dissect_bxxp_int(tvb, offset, pinfo->fd, hdr, hf_bxxp_seqno, &seqno, rsp_seqno_hfa);

    /* skip the space */

    offset += 1;

    offset += dissect_bxxp_int(tvb, offset, pinfo->fd, hdr, hf_bxxp_size, &size, rsp_size_hfa);
    if (request_val)
      request_val->size = size;
    else
      frame_data->pl_size = size;

    /* Check the space ... */

    offset += 1;

    dissect_bxxp_status(tvb, offset, pinfo->fd, hdr);

    offset += 1;

    if ((cc = check_term(tvb, offset, hdr)) <= 0) {

      /* We dissect the rest as data and bail ... */

      if (tree) {
	proto_tree_add_text(hdr, tvb, offset, 
			    tvb_length_remaining(tvb, offset),
			    "Undissected Payload: %s", 
			    tvb_format_text(tvb, offset, 
					    tvb_length_remaining(tvb, offset)
					    )
			    );
      }

      return -1;

    }

    offset += cc;
    
    /* Insert MIME header ... */

    if (frame_data && frame_data->mime_hdr)
      offset += dissect_bxxp_mime_header(tvb, offset, pinfo->fd, hdr);

    /* Now for the payload, if any */

    if (tvb_length_remaining(tvb, offset) > 0) { /* Dissect what is left as payload */

      int pl_size = MIN(size, tvb_length_remaining(tvb, offset));
      
      /* Except, check the payload length, and only dissect that much */

      if (tree) {
	proto_tree_add_text(tree, tvb, offset, pl_size, "Payload: %s", tvb_format_text(tvb, offset, pl_size));
      }

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

    if (tree) {
      proto_tree_add_boolean_hidden(tree, hf_bxxp_seq, NullTVB, offset, 3, TRUE);
      proto_tree_add_text(tree, tvb, offset, 3, "Command: SEQ");
    }

    offset += 3;

    /* Now check the space: FIXME */

    offset += 1;

    offset += dissect_bxxp_int(tvb, offset, pinfo->fd, tree, hf_bxxp_channel, &channel, seq_chan_hfa);

    /* Check the space: FIXME */

    offset += 1;

    offset += dissect_bxxp_int(tvb, offset, pinfo->fd, tree, hf_bxxp_ackno, &ackno, seq_ackno_hfa);

    /* Check the space: FIXME */

    offset += 1;

    offset += dissect_bxxp_int(tvb, offset, pinfo->fd, tree, hf_bxxp_window, &window, seq_window_hfa);

    if ((cc = check_term(tvb, offset, tree)) <= 0) {

      /* We dissect the rest as data and bail ... */

      if (tree) {
	proto_tree_add_text(tree, tvb, offset, 
			    tvb_length_remaining(tvb, offset),
			    "Undissected Payload: %s", 
			    tvb_format_text(tvb, offset, 
					    tvb_length_remaining(tvb, offset)
					    )
			    );
      }

      return -1;

    }

    offset += cc;

  } else if (tvb_strneql(tvb, offset, "END", 3) == 0) {

    proto_tree *tr = NULL;

    if (tree) {
      ti = proto_tree_add_text(tree, tvb, offset, MIN(5, tvb_length_remaining(tvb, offset)), "Trailer");

      tr = proto_item_add_subtree(ti, ett_trailer);

      proto_tree_add_boolean_hidden(tr, hf_bxxp_end, NullTVB, offset, 3, TRUE);
      proto_tree_add_text(tr, tvb, offset, 3, "Command: END");

    }

    offset += 3;

    if ((cc = check_term(tvb, offset, tr)) <= 0) {

      /* We dissect the rest as data and bail ... */

      if (tree) { 
	proto_tree_add_text(tr, tvb, offset, tvb_length_remaining(tvb, offset),
			    "Undissected Payload: %s", 
			    tvb_format_text(tvb, offset, 
					    tvb_length_remaining(tvb, offset)
					    )
			    );
      }

      return -1;

    }

    offset += cc;

  }

  if (tvb_length_remaining(tvb, offset) > 0) { /* Dissect anything left over */

    int pl_size = 0;

    if (request_val) {

      pl_size = MIN(request_val->size, tvb_length_remaining(tvb, offset));

      /* FIXME: May be redundent ... */

      if (pl_size == 0 && offset == st_offset) { /* The whole of the rest must be payload */
      
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

    /* If the pl_size == 0 and the offset == st_offset, then we have not 
     * processed anything in this frame above, so we better treat all this
     * data as payload to avoid recursion loops
     */

    if (pl_size == 0 && offset == st_offset) 
      pl_size = tvb_length_remaining(tvb, offset);

    if (pl_size > 0) {

      if (tree) {
	proto_tree_add_text(tree, tvb, offset, pl_size, "Payload: %s",
			    tvb_format_text(tvb, offset, pl_size));
      }

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
  proto_tree              *bxxp_tree = NULL, *ti = NULL;
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

  /* Here, we parse the message so we can retrieve the info we need, which 
   * is that there is some payload left from a previous segment on the 
   * front of this segment ... This all depends on TCP segments not getting
   * out of order ... 
   *
   * As a huge kludge, we push the checking for the tree down into the code
   * and process as if we were given a tree but not call the routines that
   * adorn the protocol tree if they were NULL.
   */

  if (tree) {  /* Build the tree info ... */

    ti = proto_tree_add_item(tree, proto_bxxp, tvb, offset, tvb_length(tvb), FALSE);

    bxxp_tree = proto_item_add_subtree(ti, ett_bxxp);

  }
  
  /* Check the per-frame data and the conversation for any left-over 
   * payload from the previous frame 
   *
   * We check that per-frame data exists first, and if so, use it,
   * else we use the conversation data.
   *
   * We create per-frame data here as well, but we must ensure we create it
   * after we have done the check for per-frame or conversation data.
   *
   * We also depend on the first frame in a group having a pl_size of 0.
   */

  if (frame_data && frame_data->pl_left > 0) {

    int pl_left = frame_data->pl_left;

    pl_left = MIN(pl_left, tvb_length_remaining(tvb, offset));

    /* Add the payload bit, only if we have a tree */
    if (tree) {
      proto_tree_add_text(bxxp_tree, tvb, offset, pl_left, "Payload: %s",
			  tvb_format_text(tvb, offset, pl_left));
    }
    offset += pl_left;
  }
  else if (request_val && request_val->size > 0) {

    int pl_left = request_val->size;

    request_val->size = 0;

    /* We create the frame data here for this case, and 
     * elsewhere for other frames
     */

    frame_data = g_mem_chunk_alloc(bxxp_packet_infos);

    frame_data->pl_left = pl_left;
    frame_data->pl_size = 0;
    frame_data->mime_hdr = 0;
      
    p_add_proto_data(pinfo->fd, proto_bxxp, frame_data);

  }

  /* Set up the per-frame data here if not already done so
   * This _must_ come after the checks above ...
   */

  if (frame_data == NULL) { 

    frame_data = g_mem_chunk_alloc(bxxp_packet_infos);

    frame_data->pl_left = 0;
    frame_data->pl_size = 0;
    frame_data->mime_hdr = 0;

    p_add_proto_data(pinfo->fd, proto_bxxp, frame_data);
	
  }

  if (tvb_length_remaining(tvb, offset) > 0) {

    offset += dissect_bxxp_tree(tvb, offset, pinfo, bxxp_tree, request_val, frame_data);

  }

}

/* Register all the bits needed with the filtering engine */

void 
proto_register_bxxp(void)
{
  static hf_register_info hf[] = {
    { &hf_bxxp_proto_viol,
      { "Protocol Violation", "bxxp.violation", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "" }},

    { &hf_bxxp_req,
      { "Request", "bxxp.req", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "" }},

    { &hf_bxxp_req_chan,
      { "Request Channel Number", "bxxp.req.channel", FT_UINT32, BASE_DEC, NULL, 0x0, ""}},

    { &hf_bxxp_rsp,
      { "Response", "bxxp.rsp", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "" }},

    { &hf_bxxp_rsp_chan,
      { "Response Channel Number", "bxxp.rsp.channel", FT_UINT32, BASE_DEC, NULL, 0x0, ""}},

    { &hf_bxxp_seq,
      { "Sequence", "bxxp.seq", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "" }},

    { &hf_bxxp_seq_chan,
      { "Sequence Channel Number", "bxxp.seq.channel", FT_UINT32, BASE_DEC, NULL, 0x0, ""}},

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

  /* Register our configuration options for BXXP, particularly our port */

  bxxp_module = prefs_register_module("bxxp", "BXXP", proto_reg_handoff_bxxp);

  prefs_register_uint_preference(bxxp_module, "tcp.port", "BXXP TCP Port",
				 "Set the port for BXXP messages (if other"
				 " than the default of 10288)",
				 10, &global_bxxp_tcp_port);

  prefs_register_bool_preference(bxxp_module, "strict_header_terminator", 
				 "BXXP Header Requires CRLF", 
				 "Specifies that BXXP requires CRLF as a "
				 "terminator, and not just CR or LF",
				 &global_bxxp_strict_term);

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
