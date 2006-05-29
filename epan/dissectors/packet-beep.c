/* packet-beep.c
 * Routines for BEEP packet disassembly
 *
 * $Id$
 *
 * Copyright (c) 2000 by Richard Sharpe <rsharpe@ns.aus.com>
 * Modified 2001 Darren New <dnew@invisible.net> for BEEP.
 *
 * Original BXXP dissector developed with funding from InvisibleWorlds
 * (www.invisibleworlds.com) via Collab.Net.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs
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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <glib.h>
#include <string.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/emem.h>

#define TCP_PORT_BEEP 10288
void proto_reg_handoff_beep(void);


static guint global_beep_tcp_port = TCP_PORT_BEEP;
static int global_beep_strict_term = TRUE;

static int proto_beep = -1;

static int hf_beep_req = -1;
static int hf_beep_req_chan = -1;
static int hf_beep_rsp_chan = -1;
static int hf_beep_seq_chan = -1;
static int hf_beep_rsp = -1;
static int hf_beep_seq = -1;
static int hf_beep_end = -1;
static int hf_beep_proto_viol = -1;
static int hf_beep_complete = -1;   /* No More data follows */
static int hf_beep_intermediate = -1; /* More data follows */
static int hf_beep_msgno = -1;
static int hf_beep_ansno = -1;
static int hf_beep_seqno = -1;
static int hf_beep_size = -1;
static int hf_beep_channel = -1;
static int hf_beep_positive = -1;
static int hf_beep_negative = -1;
static int hf_beep_ackno = -1;
static int hf_beep_window = -1;

/* Arrays of hf entry pointers for some routines to use. If you want more
 * hidden items added for a field, add them to the list before the NULL,
 * and the various routines that these are passed to will add them.
 */

static int *req_msgno_hfa[] = { &hf_beep_msgno, NULL };
static int *req_ansno_hfa[] = { &hf_beep_ansno, NULL };
static int *req_seqno_hfa[]  = { &hf_beep_seqno, NULL };
static int *req_size_hfa[]   = { &hf_beep_size, NULL };
static int *req_chan_hfa[]   = { &hf_beep_channel, &hf_beep_req_chan, NULL };
/*
static int *rsp_msgno_hfa[] = { &hf_beep_msgno, NULL };
static int *rsp_seqno_hfa[]  = { &hf_beep_seqno, NULL };
static int *rsp_size_hfa[]   = { &hf_beep_size, NULL };
*/
static int *seq_chan_hfa[]   = { &hf_beep_channel, &hf_beep_seq_chan, NULL };
static int *seq_ackno_hfa[]  = { &hf_beep_ackno, NULL };
static int *seq_window_hfa[] = { &hf_beep_window, NULL };

static int ett_beep = -1;
static int ett_mime_header = -1;
static int ett_header = -1;
static int ett_trailer = -1;

static guint tcp_port = 0;

/* Get the state of the more flag ... */

#define BEEP_VIOL         0
#define BEEP_INTERMEDIATE 1
#define BEEP_COMPLETE     2

/*
 * Per-frame data
 *
 * pl_left is the amount of data in this packet that belongs to another
 * frame ...
 *
 * It relies on TCP segments not being re-ordered too much ...
 */
struct beep_proto_data {
  int pl_left;   /* Payload at beginning of frame */
  int pl_size;   /* Payload in current message ...*/
  int mime_hdr;  /* Whether we expect a mime header. 1 on first, 0 on rest
		  * in a message
		  */
};

/*
 * Conversation stuff
 */

struct beep_request_key {
  guint32 conversation;
};

struct beep_request_val {
  guint16 processed;     /* Have we processed this conversation? */
  int size;              /* Size of the message                  */
                         /* We need an indication in each dirn of
			  * whether on not a mime header is expected
			  */
  int c_mime_hdr, s_mime_hdr;
};

static GHashTable *beep_request_hash = NULL;

/* Hash Functions */
static gint
beep_equal(gconstpointer v, gconstpointer w)
{
  const struct beep_request_key *v1 = (const struct beep_request_key *)v;
  const struct beep_request_key *v2 = (const struct beep_request_key *)w;

#if defined(DEBUG_BEEP_HASH)
  printf("Comparing %08X\n      and %08X\n",
	 v1->conversation, v2->conversation);
#endif

  if (v1->conversation == v2->conversation)
    return 1;

  return 0;

}

static guint
beep_hash(gconstpointer v)
{
  const struct beep_request_key *key = (const struct beep_request_key *)v;
  guint val;

  val = key->conversation;

#if defined(DEBUG_BEEP_HASH)
  printf("BEEP Hash calculated as %u\n", val);
#endif

  return val;

}

static void
beep_init_protocol(void)
{
#if defined(DEBUG_BEEP_HASH)
  fprintf(stderr, "Initializing BEEP hashtable area\n");
#endif

  if (beep_request_hash)
    g_hash_table_destroy(beep_request_hash);

  beep_request_hash = g_hash_table_new(beep_hash, beep_equal);
}

/*
 * BEEP routines
 */

static int beep_get_more(char more)
{

  if (more == '.')
    return BEEP_COMPLETE;
  else if (more == '*')
    return BEEP_INTERMEDIATE;

  return BEEP_VIOL;
}

/* dissect the more flag, and return a value of:
 *  1 -> more
 *  0 -> no more
 *  -1 -> Proto violation
 */

static int
dissect_beep_more(tvbuff_t *tvb, int offset,
		  proto_tree *tree)
{


  switch (beep_get_more(tvb_get_guint8(tvb, offset))) {

  case BEEP_COMPLETE:

    if (tree) {
      proto_tree_add_boolean_hidden(tree, hf_beep_complete, tvb, offset, 1, TRUE);
      proto_tree_add_text(tree, tvb, offset, 1, "More: Complete");
    }

    return 0;

    break;

  case BEEP_INTERMEDIATE:

    if (tree) {
      proto_tree_add_boolean_hidden(tree, hf_beep_intermediate, tvb, offset, 1, TRUE);
      proto_tree_add_text(tree, tvb, offset, 1, "More: Intermediate");
    }

    return 1;

    break;

  default:

    if (tree) {
      proto_tree_add_boolean_hidden(tree, hf_beep_proto_viol, tvb, offset, 1, TRUE);
      proto_tree_add_text(tree, tvb, offset, 1, "PROTOCOL VIOLATION: Expected More Flag (* or .)");
    }

    return -1;

    break;
  }

}

#if 0
static void dissect_beep_status(tvbuff_t *tvb, int offset,
				proto_tree *tree)
{

  /* FIXME: We should return a value to indicate all OK. */

  switch(tvb_get_guint8(tvb, offset)) {

  case '+':

    if (tree) {
      proto_tree_add_boolean_hidden(tree, hf_beep_positive, tvb, offset, 1, TRUE);
      proto_tree_add_text(tree, tvb, offset, 1, "Status: Positive");
    }

    break;

  case '-':

    if (tree) {
      proto_tree_add_boolean_hidden(tree, hf_beep_negative, tvb, offset, 1, TRUE);
      proto_tree_add_text(tree, tvb, offset, 1, "Status: Negative");
    }

    break;

  default:  /* Proto violation: FIXME */

    break;

  }

}
#endif

static int num_len(tvbuff_t *tvb, int offset)
{
  unsigned int i = 0;

  while (isdigit(tvb_get_guint8(tvb, offset + i))) i++;

  return i;

}

/*
 * We check for a terminator. This can be CRLF, which will be recorded
 * as a terminator, or CR or LF by itself, which will be redorded as
 * an incorrect terminator ... We build the tree at this point
 * However, we depend on the variable beep_strict_term
 */

static int
check_term(tvbuff_t *tvb, int offset, proto_tree *tree)
{

  /* First, check for CRLF, or, if global_beep_strict_term is false,
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
  else if ((tvb_get_guint8(tvb, offset) == 0x0d) && !global_beep_strict_term) {

    if (tree) {
      proto_tree_add_text(tree, tvb, offset, 1, "Nonstandard Terminator: CR");
      proto_tree_add_boolean_hidden(tree, hf_beep_proto_viol, tvb, offset, 1, TRUE);
    }
    return 1;

  }
  else if ((tvb_get_guint8(tvb, offset) == 0x0a) && !global_beep_strict_term) {

    if (tree) {
      proto_tree_add_text(tree, tvb, offset, 1, "Nonstandard Terminator: LF");
      proto_tree_add_boolean_hidden(tree, hf_beep_proto_viol, tvb, offset, 1, TRUE);
    }
    return 1;

  }
  else {

    if (tree) {
      proto_tree_add_text(tree, tvb, offset, 2, "PROTOCOL VIOLATION, Invalid Terminator: %s", tvb_format_text(tvb, offset, 2));
      proto_tree_add_boolean_hidden(tree, hf_beep_proto_viol, tvb, offset, 2, TRUE);
    }
    return -1;

  }

}

/* Get the header length, up to CRLF or CR or LF */
static int header_len(tvbuff_t *tvb, int offset)
{
  int i = 0;
  guint8 sc;

  /* FIXME: Have to make sure we stop looking at the end of the tvb ... */

  /* We look for CRLF, or CR or LF if global_beep_strict_term is
   * not set.
   */

  while (1) {

    if ((sc = tvb_get_guint8(tvb, offset + i)) == 0x0d
	&& tvb_get_guint8(tvb, offset + i + 1) == 0x0a)
      return i;   /* Done here ... */

    if (!global_beep_strict_term && (sc == 0x0d || sc == 0x0a))
      return i;   /* Done here also ... */

    i++;

  }
}

static int
dissect_beep_mime_header(tvbuff_t *tvb, int offset,
			 struct beep_proto_data *frame_data,
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

static int
dissect_beep_int(tvbuff_t *tvb, int offset,
		    proto_tree *tree, int hf, int *val, int *hfa[])
{
  int ival, ind = 0;
  unsigned int i = num_len(tvb, offset);
  guint8 int_buff[100];

  memset(int_buff, '\0', sizeof(int_buff));

  tvb_memcpy(tvb, int_buff, offset, MIN(sizeof(int_buff) - 1, i));

  /* XXX - is this still "Dangerous" now that we don't copy to the
     last byte of "int_buff[]"? */
  sscanf(int_buff, "%d", &ival);

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

static void
set_mime_hdr_flags(int more, struct beep_request_val *request_val,
		   struct beep_proto_data *frame_data, packet_info *pinfo)
{

  if (!request_val) return; /* Nothing to do ??? */

  if (pinfo->destport == tcp_port) { /* Going to the server ... client */

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

static int
dissect_beep_tree(tvbuff_t *tvb, int offset, packet_info *pinfo,
		  proto_tree *tree, struct beep_request_val *request_val,
		  struct beep_proto_data *frame_data)
{
  proto_tree     *ti = NULL, *hdr = NULL;
  int            st_offset, msgno, ansno, seqno, size, channel, ackno, window, cc,
                 more;

  const char * cmd_temp = NULL;
  int is_ANS = 0;
  st_offset = offset;

  if (tvb_strneql(tvb, offset, "MSG ", 4) == 0)
    cmd_temp = "Command: MSG";
  if (tvb_strneql(tvb, offset, "RPY ", 4) == 0)
    cmd_temp = "Command: RPY";
  if (tvb_strneql(tvb, offset, "ERR ", 4) == 0)
    cmd_temp = "Command: ERR";
  if (tvb_strneql(tvb, offset, "NUL ", 4) == 0)
    cmd_temp = "Command: NUL";
  if (tvb_strneql(tvb, offset, "ANS ", 4) == 0) {
    cmd_temp = "Command: ANS";
    is_ANS = 1;
  }

  if (cmd_temp != NULL) {

    if (tree) {
      ti = proto_tree_add_text(tree, tvb, offset, header_len(tvb, offset) + 2, "Header");

      hdr = proto_item_add_subtree(ti, ett_header);

      proto_tree_add_boolean_hidden(hdr, hf_beep_req, tvb, offset, 3, TRUE);
      proto_tree_add_text(hdr, tvb, offset, 3, cmd_temp);
    }

    offset += 4;

    /* Get the channel */
    offset += dissect_beep_int(tvb, offset, hdr, hf_beep_channel, &channel, req_chan_hfa);
    offset += 1; /* Skip the space */

    /* Dissect the message number */
    offset += dissect_beep_int(tvb, offset, hdr, hf_beep_msgno, &msgno, req_msgno_hfa);
    offset += 1; /* skip the space */

    /* Insert the more elements ... */
    if ((more = dissect_beep_more(tvb, offset, hdr)) >= 0) {
      /* Figure out which direction this is in and what mime_hdr flag to
       * add to the frame_data. If there are missing segments, this code
       * will get it wrong!
       */
      set_mime_hdr_flags(more, request_val, frame_data, pinfo);
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

    offset += 2; /* Skip the flag and the space ... */

    /* now for the seqno */
    offset += dissect_beep_int(tvb, offset, hdr, hf_beep_seqno, &seqno, req_seqno_hfa);
    offset += 1; /* skip the space */

    offset += dissect_beep_int(tvb, offset, hdr, hf_beep_size, &size, req_size_hfa);
    if (request_val)   /* FIXME, is this the right order ... */
      request_val -> size = size;  /* Stash this away */
    else {
      frame_data->pl_size = size;
      if (frame_data->pl_size < 0) frame_data->pl_size = 0; /* FIXME: OK? */
    }
    /* offset += 1; skip the space */

    if (is_ANS) { /* We need to put in the ansno */
        offset += 1; /* skip the space */
        /* Dissect the message number */
        offset += dissect_beep_int(tvb, offset, hdr, hf_beep_ansno, &ansno, req_ansno_hfa);
    }

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
      offset += dissect_beep_mime_header(tvb, offset, frame_data, hdr);

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
      offset += dissect_beep_tree(tvb, offset, pinfo, tree, request_val, frame_data);

  } else if (tvb_strneql(tvb, offset, "SEQ ", 4) == 0) {

    if (tree) {
      proto_tree_add_boolean_hidden(tree, hf_beep_seq, tvb, offset, 3, TRUE);
      proto_tree_add_text(tree, tvb, offset, 3, "Command: SEQ");
    }

    offset += 3;

    /* Now check the space: FIXME */

    offset += 1;

    offset += dissect_beep_int(tvb, offset, tree, hf_beep_channel, &channel, seq_chan_hfa);

    /* Check the space: FIXME */

    offset += 1;

    offset += dissect_beep_int(tvb, offset, tree, hf_beep_ackno, &ackno, seq_ackno_hfa);

    /* Check the space: FIXME */

    offset += 1;

    offset += dissect_beep_int(tvb, offset, tree, hf_beep_window, &window, seq_window_hfa);

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

      proto_tree_add_boolean_hidden(tr, hf_beep_end, tvb, offset, 3, TRUE);
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

    /* If the pl_size == 0 and the offset == 0?, then we have not processed
     * anything in this frame above, so we better treat all this data as
     * payload to avoid recursion loops
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
      offset += dissect_beep_tree(tvb, offset, pinfo, tree, request_val, frame_data);
    }
  }

  return offset - st_offset;

}

static void
dissect_beep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  int offset;
  struct beep_proto_data  *frame_data = NULL;
  proto_tree              *beep_tree = NULL, *ti = NULL;
  conversation_t          *conversation = NULL;
  struct beep_request_key request_key, *new_request_key;
  struct beep_request_val *request_val = NULL;

  offset = 0;

  /* If we have per frame data, use that, else, we must have lost the per-
   * frame data, and we have to do a full dissect pass again.
   *
   * The per-frame data tells us how much of this frame is left over from a
   * previous frame, so we dissect it as payload and then try to dissect the
   * rest.
   *
   * We use the conversation to build up info on the first pass over the
   * packets of type BEEP, and record anything that is needed if the user
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

  frame_data = p_get_proto_data(pinfo->fd, proto_beep);

  if (!frame_data) {

    conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,
				       pinfo->srcport, pinfo->destport, 0);
    if (conversation == NULL) { /* No conversation, create one */
	conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,
					pinfo->srcport, pinfo->destport, 0);

      }

      /*
       * Check for and insert an entry in the request table if does not exist
       */
      request_key.conversation = conversation->index;

      request_val = (struct beep_request_val *)g_hash_table_lookup(beep_request_hash, &request_key);

      if (!request_val) { /* Create one */

	new_request_key = se_alloc(sizeof(struct beep_request_key));
	new_request_key->conversation = conversation->index;

	request_val = se_alloc(sizeof(struct beep_request_val));
	request_val->processed = 0;
	request_val->size = 0;

	g_hash_table_insert(beep_request_hash, new_request_key, request_val);

      }
    }

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BEEP");

  if (check_col(pinfo->cinfo, COL_INFO)) {  /* Check the type ... */

    /* "tvb_format_text()" is passed a value that won't go past the end
     * of the packet, so it won't throw an exception. */
    col_add_str(pinfo->cinfo, COL_INFO, tvb_format_text(tvb, offset, tvb_length_remaining(tvb, offset)));

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

    ti = proto_tree_add_item(tree, proto_beep, tvb, offset, -1, FALSE);

    beep_tree = proto_item_add_subtree(ti, ett_beep);

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
      proto_tree_add_text(beep_tree, tvb, offset, pl_left, "Payload: %s",
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

    frame_data = se_alloc(sizeof(struct beep_proto_data));

    frame_data->pl_left = pl_left;
    frame_data->pl_size = 0;
    frame_data->mime_hdr = 0;

    p_add_proto_data(pinfo->fd, proto_beep, frame_data);

  }

  /* Set up the per-frame data here if not already done so
   * This _must_ come after the checks above ...
   */

  if (frame_data == NULL) {

    frame_data = se_alloc(sizeof(struct beep_proto_data));

    frame_data->pl_left = 0;
    frame_data->pl_size = 0;
    frame_data->mime_hdr = 0;

    p_add_proto_data(pinfo->fd, proto_beep, frame_data);

  }

  if (tvb_length_remaining(tvb, offset) > 0) {

    offset += dissect_beep_tree(tvb, offset, pinfo, beep_tree, request_val, frame_data);

  }

}

/* Register all the bits needed with the filtering engine */

void
proto_register_beep(void)
{
  static hf_register_info hf[] = {
    { &hf_beep_proto_viol,
      { "Protocol Violation", "beep.violation", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_beep_req,
      { "Request", "beep.req", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_beep_req_chan,
      { "Request Channel Number", "beep.req.channel", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_beep_rsp,
      { "Response", "beep.rsp", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_beep_rsp_chan,
      { "Response Channel Number", "beep.rsp.channel", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_beep_seq,
      { "Sequence", "beep.seq", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_beep_seq_chan,
      { "Sequence Channel Number", "beep.seq.channel", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_beep_end,
      { "End", "beep.end", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_beep_complete,
      { "Complete", "beep.more.complete", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_beep_intermediate,
      { "Intermediate", "beep.more.intermediate", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_beep_msgno,
      { "Msgno", "beep.msgno", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_beep_ansno,
      { "Ansno", "beep.ansno", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_beep_seqno,
      { "Seqno", "beep.seqno", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_beep_size,
      { "Size", "beep.size", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_beep_channel,
      { "Channel", "beep.channel", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_beep_negative,
      { "Negative", "beep.status.negative", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_beep_positive,
      { "Positive", "beep.status.positive", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_beep_ackno,
      { "Ackno", "beep.seq.ackno", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

    { &hf_beep_window,
      { "Window", "beep.seq.window", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},

  };
  static gint *ett[] = {
    &ett_beep,
    &ett_mime_header,
    &ett_header,
    &ett_trailer,
  };
  module_t *beep_module;

  proto_beep = proto_register_protocol("Blocks Extensible Exchange Protocol",
				       "BEEP", "beep");

  proto_register_field_array(proto_beep, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_init_routine(&beep_init_protocol);

  /* Register our configuration options for BEEP, particularly our port */

  beep_module = prefs_register_protocol(proto_beep, proto_reg_handoff_beep);

  prefs_register_uint_preference(beep_module, "tcp.port", "BEEP TCP Port",
				 "Set the port for BEEP messages (if other"
				 " than the default of 10288)",
				 10, &global_beep_tcp_port);

  prefs_register_bool_preference(beep_module, "strict_header_terminator",
				 "BEEP Header Requires CRLF",
				 "Specifies that BEEP requires CRLF as a "
				 "terminator, and not just CR or LF",
				 &global_beep_strict_term);
}

/* The registration hand-off routine */
void
proto_reg_handoff_beep(void)
{
  static int beep_prefs_initialized = FALSE;
  static dissector_handle_t beep_handle;

  if (!beep_prefs_initialized) {

    beep_handle = create_dissector_handle(dissect_beep, proto_beep);

    beep_prefs_initialized = TRUE;

  }
  else {

    dissector_delete("tcp.port", tcp_port, beep_handle);

  }

  /* Set our port number for future use */

  tcp_port = global_beep_tcp_port;

  dissector_add("tcp.port", global_beep_tcp_port, beep_handle);

}
