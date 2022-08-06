/* packet-beep.c
 * Routines for BEEP packet disassembly
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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#if defined(DEBUG_BEEP_HASH)
#include <epan/ws_printf.h>
#endif

#define TCP_PORT_BEEP 10288 /* Don't think this is IANA registered */

void proto_register_beep(void);
void proto_reg_handoff_beep(void);

static range_t *global_beep_tcp_ports = NULL;
static int global_beep_strict_term = TRUE;

static int proto_beep = -1;

static int hf_beep_req = -1;
static int hf_beep_cmd = -1;
static int hf_beep_req_chan = -1;
/* static int hf_beep_rsp_chan = -1; */
static int hf_beep_seq_chan = -1;
/* static int hf_beep_rsp = -1; */
static int hf_beep_more = -1;
static int hf_beep_msgno = -1;
static int hf_beep_ansno = -1;
static int hf_beep_seqno = -1;
static int hf_beep_size = -1;
static int hf_beep_channel = -1;
static int hf_beep_mime_header = -1;
static int hf_beep_header = -1;
#if 0
static int hf_beep_status = -1;
#endif
static int hf_beep_ackno = -1;
static int hf_beep_window = -1;
static int hf_beep_payload = -1;
static int hf_beep_payload_undissected = -1;
static int hf_beep_crlf_terminator = -1;

#if 0
static const value_string beep_status_vals[] = {
   { '+',        "Positive" },
   { '-',        "Negative"  },

   { 0,        NULL   }
};
#endif

static const value_string beep_more_vals[] = {
   { '.',        "Complete" },
   { '*',        "Intermediate"  },

   { 0,        NULL   }
};



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

static expert_field ei_beep_more = EI_INIT;
static expert_field ei_beep_cr_terminator = EI_INIT;
static expert_field ei_beep_lf_terminator = EI_INIT;
static expert_field ei_beep_invalid_terminator = EI_INIT;

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

static wmem_map_t *beep_request_hash = NULL;

/* Hash Functions */
static gint
beep_equal(gconstpointer v, gconstpointer w)
{
  const struct beep_request_key *v1 = (const struct beep_request_key *)v;
  const struct beep_request_key *v2 = (const struct beep_request_key *)w;

#if defined(DEBUG_BEEP_HASH)
  ws_debug_printf("Comparing %08X\n      and %08X\n",
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
  ws_debug_printf("BEEP Hash calculated as %u\n", val);
#endif

  return val;

}


/* dissect the more flag, and return a value of:
 *  1 -> more
 *  0 -> no more
 *  -1 -> Proto violation
 */

static int
dissect_beep_more(tvbuff_t *tvb, packet_info *pinfo, int offset,
                  proto_tree *tree)
{
  proto_item *hidden_item;
  int ret = 0;
  guint8 more = tvb_get_guint8(tvb, offset);

  hidden_item = proto_tree_add_item(tree, hf_beep_more, tvb, offset, 1, ENC_ASCII|ENC_NA);
  proto_item_set_hidden(hidden_item);

  switch(more) {
  case '.':
     ret = 0;
     break;
  case '*':
     ret = 1;
     break;
  default:
    expert_add_info(pinfo, hidden_item, &ei_beep_more);
    ret = -1;
    break;
  }

  return ret;
}

#if 0
static void dissect_beep_status(tvbuff_t *tvb, int offset,
                                proto_tree *tree)
{

  /* FIXME: We should return a value to indicate all OK. */

  proto_tree_add_item(item_tree, hf_beep_status, tvb, offset, 1, ENC_BIG_ENDIAN);
}
#endif

static int num_len(tvbuff_t *tvb, int offset)
{
  unsigned int i = 0;

  while (g_ascii_isdigit(tvb_get_guint8(tvb, offset + i))) i++;

  return i;

}

/*
 * We check for a terminator. This can be CRLF, which will be recorded
 * as a terminator, or CR or LF by itself, which will be redorded as
 * an incorrect terminator ... We build the tree at this point
 * However, we depend on the variable beep_strict_term
 */

static int
check_term(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree)
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

    proto_tree_add_item(tree, hf_beep_crlf_terminator, tvb, offset, 2, ENC_NA);
    return 2;

  }

  if ((tvb_get_guint8(tvb, offset) == 0x0d) && !global_beep_strict_term) {

    proto_tree_add_expert(tree, pinfo, &ei_beep_cr_terminator, tvb, offset, 1);
    return 1;

  }

  if ((tvb_get_guint8(tvb, offset) == 0x0a) && !global_beep_strict_term) {

    proto_tree_add_expert(tree, pinfo, &ei_beep_lf_terminator, tvb, offset, 1);
    return 1;
  }

  proto_tree_add_expert_format(tree, pinfo, &ei_beep_invalid_terminator, tvb,
                                offset, 1, "Terminator: %s", tvb_format_text(pinfo->pool, tvb, offset, 2));
  return -1;
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
dissect_beep_mime_header(tvbuff_t *tvb, packet_info *pinfo, int offset,
                         struct beep_proto_data *beep_frame_data,
                         proto_tree *tree)
{
  proto_tree    *ti = NULL, *mime_tree = NULL;
  int           mime_length = header_len(tvb, offset), cc = 0;

  if (beep_frame_data && !beep_frame_data->mime_hdr) return 0;

  if (tree) {

    /* FIXME: Should calculate the whole length of the mime headers */
    ti = proto_tree_add_item(tree, hf_beep_mime_header, tvb, offset, mime_length, ENC_NA|ENC_ASCII);
    mime_tree = proto_item_add_subtree(ti, ett_mime_header);
  }

  if (mime_length == 0) { /* Default header */

    if (tree) {
      proto_tree_add_string_format(mime_tree, hf_beep_header, tvb, offset, 0, "", "Default values");
    }

    if ((cc = check_term(tvb, pinfo, offset, mime_tree)) <= 0) {

      /* Ignore it, it will cause funnies in the rest of the dissect */

    }

  }
  else {  /* FIXME: Process the headers */

    if (tree) {
      proto_tree_add_item(mime_tree, hf_beep_header, tvb, offset, mime_length, ENC_NA|ENC_ASCII);
    }

    if ((cc = check_term(tvb, pinfo, offset + mime_length, mime_tree)) <= 0) {

      /* Ignore it, it will cause funnies in the rest of the dissect */

    }

  }

  return mime_length + cc;  /* FIXME: Check that the CRLF is there */

}

static int
dissect_beep_int(tvbuff_t *tvb, packet_info *pinfo, int offset,
                    proto_tree *tree, int hf, int *val, int *hfa[])
{
  proto_item  *hidden_item;
  int ival, ind = 0;
  unsigned int len = num_len(tvb, offset);

  ival = (int)strtol(tvb_get_string_enc(pinfo->pool, tvb, offset, len, ENC_ASCII), NULL, 10);
  proto_tree_add_uint(tree, hf, tvb, offset, len, ival);

  while (hfa[ind]) {

    hidden_item = proto_tree_add_uint(tree, *hfa[ind], tvb, offset, len, ival);
        proto_item_set_hidden(hidden_item);
    ind++;

  }

  *val = ival;  /* Return the value */

  return len;

}

static void
set_mime_hdr_flags(int more, struct beep_request_val *request_val,
                   struct beep_proto_data *beep_frame_data, packet_info *pinfo)
{

  if (!request_val) return; /* Nothing to do ??? */

  if (value_is_in_range(global_beep_tcp_ports, pinfo->destport)) { /* Going to the server ... client */

    if (request_val->c_mime_hdr) {

      beep_frame_data->mime_hdr = 0;

      if (!more) request_val->c_mime_hdr = 0;

    }
    else {

      beep_frame_data->mime_hdr = 1;

      if (more) request_val->c_mime_hdr = 1;

    }

  }
  else {

    if (request_val->s_mime_hdr) {

      beep_frame_data->mime_hdr = 0;

      if (!more) request_val->s_mime_hdr = 0;

    }
    else {

      beep_frame_data->mime_hdr = 1;

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
                  struct beep_proto_data *beep_frame_data)
{
  proto_tree     *ti = NULL, *hdr = NULL;
  /*proto_item     *hidden_item;*/
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
      hdr = proto_tree_add_subtree(tree, tvb, offset, header_len(tvb, offset) + 2,
            ett_header, NULL, "Header");

      ti = proto_tree_add_item(hdr, hf_beep_cmd, tvb, offset, 3, ENC_NA|ENC_ASCII);
      /* Include space */
      proto_item_set_len(ti, 4);

      proto_tree_add_boolean(hdr, hf_beep_req, tvb, offset, 3, TRUE);
    }

    offset += 4;

    /* Get the channel */
    offset += dissect_beep_int(tvb, pinfo, offset, hdr, hf_beep_channel, &channel, req_chan_hfa);
    offset += 1; /* Skip the space */

    /* Dissect the message number */
    offset += dissect_beep_int(tvb, pinfo, offset, hdr, hf_beep_msgno, &msgno, req_msgno_hfa);
    offset += 1; /* skip the space */

    /* Insert the more elements ... */
    if ((more = dissect_beep_more(tvb, pinfo, offset, hdr)) >= 0) {
      /* Figure out which direction this is in and what mime_hdr flag to
       * add to the beep_frame_data. If there are missing segments, this code
       * will get it wrong!
       */
      set_mime_hdr_flags(more, request_val, beep_frame_data, pinfo);
    }
    else {  /* Protocol violation, so dissect rest as undisectable */
      if (tree && (tvb_reported_length_remaining(tvb, offset) > 0)) {
        proto_tree_add_item(tree, hf_beep_payload_undissected, tvb, offset,
                            tvb_reported_length_remaining(tvb, offset), ENC_NA|ENC_ASCII);
      }
      return -1;
    }

    offset += 2; /* Skip the flag and the space ... */

    /* now for the seqno */
    offset += dissect_beep_int(tvb, pinfo, offset, hdr, hf_beep_seqno, &seqno, req_seqno_hfa);
    offset += 1; /* skip the space */

    offset += dissect_beep_int(tvb, pinfo, offset, hdr, hf_beep_size, &size, req_size_hfa);
    if (request_val)   /* FIXME, is this the right order ... */
      request_val -> size = size;  /* Stash this away */
    else if (beep_frame_data) {
      beep_frame_data->pl_size = size;
      if (beep_frame_data->pl_size < 0) beep_frame_data->pl_size = 0; /* FIXME: OK? */
    }
    /* offset += 1; skip the space */

    if (is_ANS) { /* We need to put in the ansno */
        offset += 1; /* skip the space */
        /* Dissect the message number */
        offset += dissect_beep_int(tvb, pinfo, offset, hdr, hf_beep_ansno, &ansno, req_ansno_hfa);
    }

    if ((cc = check_term(tvb, pinfo, offset, hdr)) <= 0) {

      /* We dissect the rest as data and bail ... */

      if (tree && (tvb_reported_length_remaining(tvb, offset) > 0)) {
        proto_tree_add_item(tree, hf_beep_payload_undissected, tvb, offset,
                            tvb_reported_length_remaining(tvb, offset), ENC_NA|ENC_ASCII);
      }

      return -1;

    }

    offset += cc;

    /* Insert MIME header ... */

    if (beep_frame_data && beep_frame_data->mime_hdr)
      offset += dissect_beep_mime_header(tvb, pinfo, offset, beep_frame_data, hdr);

    /* Now for the payload, if any */

    if (tvb_reported_length_remaining(tvb, offset) > 0) { /* Dissect what is left as payload */

      int pl_size = MIN(size, tvb_reported_length_remaining(tvb, offset));

      /* Except, check the payload length, and only dissect that much */

      /* We need to keep track, in the conversation, of how much is left
       * so in the next packet, we can figure out what is part of the payload
       * and what is the next message
       */

      if (tree) {
        proto_tree_add_item(tree, hf_beep_payload, tvb, offset, pl_size, ENC_NA|ENC_ASCII);
      }

      offset += pl_size;

      if (request_val) {
        request_val->size -= pl_size;
        if (request_val->size < 0) request_val->size = 0;
      }
      else if (beep_frame_data) {
        beep_frame_data->pl_size -= pl_size;
        if (beep_frame_data->pl_size < 0) beep_frame_data->pl_size = 0;
      }
    }

    /* If anything else left, dissect it ... */

    if (tvb_reported_length_remaining(tvb, offset) > 0)
      offset += dissect_beep_tree(tvb, offset, pinfo, tree, request_val, beep_frame_data);

  } else if (tvb_strneql(tvb, offset, "SEQ ", 4) == 0) {

    if (tree) {
      ti = proto_tree_add_item(hdr, hf_beep_cmd, tvb, offset, 3, ENC_NA|ENC_ASCII);
      /* Include space */
      proto_item_set_len(ti, 4);
    }

    offset += 3;

    /* Now check the space: FIXME */

    offset += 1;

    offset += dissect_beep_int(tvb, pinfo, offset, tree, hf_beep_channel, &channel, seq_chan_hfa);

    /* Check the space: FIXME */

    offset += 1;

    offset += dissect_beep_int(tvb, pinfo, offset, tree, hf_beep_ackno, &ackno, seq_ackno_hfa);

    /* Check the space: FIXME */

    offset += 1;

    offset += dissect_beep_int(tvb, pinfo, offset, tree, hf_beep_window, &window, seq_window_hfa);

    if ((cc = check_term(tvb, pinfo, offset, tree)) <= 0) {

      /* We dissect the rest as data and bail ... */

      if (tree && (tvb_reported_length_remaining(tvb, offset) > 0)) {
        proto_tree_add_item(tree, hf_beep_payload_undissected, tvb, offset,
                            tvb_reported_length_remaining(tvb, offset), ENC_NA|ENC_ASCII);
      }

      return -1;

    }

    offset += cc;

  } else if (tvb_strneql(tvb, offset, "END", 3) == 0) {

    proto_tree *tr = NULL;

    if (tree) {
      tr = proto_tree_add_subtree(tree, tvb, offset, MIN(5, MAX(0, tvb_reported_length_remaining(tvb, offset))),
                                    ett_trailer, NULL, "Trailer");

      proto_tree_add_item(hdr, hf_beep_cmd, tvb, offset, 3, ENC_NA|ENC_ASCII);
    }

    offset += 3;

    if ((cc = check_term(tvb, pinfo, offset, tr)) <= 0) {

      /* We dissect the rest as data and bail ... */

      if (tree && (tvb_reported_length_remaining(tvb, offset) > 0)) {
        proto_tree_add_item(tree, hf_beep_payload_undissected, tvb, offset,
                            tvb_reported_length_remaining(tvb, offset), ENC_NA|ENC_ASCII);
      }

      return -1;

    }

    offset += cc;

  }

  if (tvb_reported_length_remaining(tvb, offset) > 0) { /* Dissect anything left over */

    int pl_size = 0;

    if (request_val) {

      pl_size = MIN(request_val->size, tvb_reported_length_remaining(tvb, offset));

      if (pl_size == 0) { /* The whole of the rest must be payload */

        pl_size = tvb_reported_length_remaining(tvb, offset); /* Right place ? */

      }

    } else if (beep_frame_data) {
      pl_size = MIN(beep_frame_data->pl_size, tvb_reported_length_remaining(tvb, offset));
    } else { /* Just in case */
      pl_size = tvb_reported_length_remaining(tvb, offset);
    }

    /* Take care here to handle the payload correctly, and if there is
     * another message here, then handle it correctly as well.
     */

    /* If the pl_size == 0 and the offset == 0?, then we have not processed
     * anything in this frame above, so we better treat all this data as
     * payload to avoid recursion loops
     */

    if (pl_size == 0 && offset == st_offset)
      pl_size = tvb_reported_length_remaining(tvb, offset);

    if (pl_size > 0) {

      if (tree) {
        proto_tree_add_item(tree, hf_beep_payload, tvb, offset, pl_size, ENC_NA|ENC_ASCII);
      }

      offset += pl_size;            /* Advance past the payload */

      if (request_val){
        request_val->size -= pl_size; /* Reduce payload by what we added */
        if (request_val->size < 0) request_val->size = 0;
      }
      else if (beep_frame_data) {
        beep_frame_data->pl_size -= pl_size;
        if (beep_frame_data->pl_size < 0) beep_frame_data->pl_size = 0;
      }
    }

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
      offset += dissect_beep_tree(tvb, offset, pinfo, tree, request_val, beep_frame_data);
    }
  }

  return offset - st_offset;

}

static int
dissect_beep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  int offset;
  struct beep_proto_data  *beep_frame_data;
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

  beep_frame_data = (struct beep_proto_data *)p_get_proto_data(wmem_file_scope(), pinfo, proto_beep, 0);

  if (!beep_frame_data) {

      conversation = find_or_create_conversation(pinfo);

      /*
       * Check for and insert an entry in the request table if does not exist
       */
      request_key.conversation = conversation->conv_index;

      request_val = (struct beep_request_val *)wmem_map_lookup(beep_request_hash, &request_key);

      if (!request_val) { /* Create one */

        new_request_key = wmem_new(wmem_file_scope(), struct beep_request_key);
        new_request_key->conversation = conversation->conv_index;

        request_val = wmem_new(wmem_file_scope(), struct beep_request_val);
        request_val->processed = 0;
        request_val->size = 0;

        wmem_map_insert(beep_request_hash, new_request_key, request_val);

      }
    }

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "BEEP");


  /* "tvb_format_text()" is passed a value that won't go past the end
   * of the packet, so it won't throw an exception.
   */
  if (tvb_reported_length_remaining(tvb, offset) > 0)
    col_add_str(pinfo->cinfo, COL_INFO, tvb_format_text(pinfo->pool, tvb, offset, tvb_reported_length_remaining(tvb, offset)));

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

    ti = proto_tree_add_item(tree, proto_beep, tvb, offset, -1, ENC_NA);

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

  if (beep_frame_data != NULL && beep_frame_data->pl_left > 0) {

    int pl_left = beep_frame_data->pl_left;

    pl_left = MIN(pl_left, MAX(0, tvb_reported_length_remaining(tvb, offset)));

    /* Add the payload bit, only if we have a tree */
    if (tree && (pl_left > 0)) {
      proto_tree_add_item(tree, hf_beep_payload, tvb, offset, pl_left, ENC_NA|ENC_ASCII);
    }
    offset += pl_left;
  }
  else if (request_val && request_val->size > 0) {

    int pl_left = request_val->size;

    request_val->size = 0;

    /* We create the frame data here for this case, and
     * elsewhere for other frames
     */

    beep_frame_data = wmem_new(wmem_file_scope(), struct beep_proto_data);

    beep_frame_data->pl_left = pl_left;
    beep_frame_data->pl_size = 0;
    beep_frame_data->mime_hdr = 0;

    p_add_proto_data(wmem_file_scope(), pinfo, proto_beep, 0, beep_frame_data);

  }

  /* Set up the per-frame data here if not already done so
   * This _must_ come after the checks above ...
   */

  if (beep_frame_data == NULL) {

    beep_frame_data = wmem_new(wmem_file_scope(), struct beep_proto_data);

    beep_frame_data->pl_left = 0;
    beep_frame_data->pl_size = 0;
    beep_frame_data->mime_hdr = 0;

    p_add_proto_data(wmem_file_scope(), pinfo, proto_beep, 0, beep_frame_data);

  }

  if (tvb_reported_length_remaining(tvb, offset) > 0) {

    /*offset += */dissect_beep_tree(tvb, offset, pinfo, beep_tree, request_val, beep_frame_data);

  }

  return tvb_captured_length(tvb);
}

static void
apply_beep_prefs(void)
{
  /* Beep uses the port preference to determine client/server */
  global_beep_tcp_ports = prefs_get_range_value("beep", "tcp.port");
}

/* Register all the bits needed with the filtering engine */

void
proto_register_beep(void)
{
  static hf_register_info hf[] = {
    { &hf_beep_req,
      { "Request", "beep.req", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_beep_cmd,
      { "Command", "beep.command", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_beep_req_chan,
      { "Request Channel Number", "beep.req.channel", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

#if 0
    { &hf_beep_rsp,
      { "Response", "beep.rsp", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_beep_rsp_chan,
      { "Response Channel Number", "beep.rsp.channel", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
#endif

    { &hf_beep_seq_chan,
      { "Sequence Channel Number", "beep.seq.channel", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_beep_more,
      { "More", "beep.more", FT_CHAR, BASE_HEX, VALS(beep_more_vals), 0x0, NULL, HFILL }},

    { &hf_beep_msgno,
      { "Msgno", "beep.msgno", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_beep_ansno,
      { "Ansno", "beep.ansno", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_beep_seqno,
      { "Seqno", "beep.seqno", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_beep_size,
      { "Size", "beep.size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_beep_channel,
      { "Channel", "beep.channel", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_beep_mime_header,
      { "Mime header", "beep.mime_header", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_beep_header,
      { "Header", "beep.header", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

#if 0
    { &hf_beep_status,
      { "Status", "beep.status", FT_UINT8, BASE_HEX, VALS(beep_status_vals), 0x0, NULL, HFILL }},
#endif

    { &hf_beep_ackno,
      { "Ackno", "beep.seq.ackno", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_beep_window,
      { "Window", "beep.seq.window", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_beep_payload,
      { "Payload", "beep.payload", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_beep_payload_undissected,
      { "Undissected Payload", "beep.payload_undissected", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_beep_crlf_terminator,
      { "Terminator: CRLF", "beep.crlf_terminator", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
  };
  static gint *ett[] = {
    &ett_beep,
    &ett_mime_header,
    &ett_header,
    &ett_trailer,
  };
  static ei_register_info ei[] = {
     { &ei_beep_more, { "beep.more.expected", PI_PROTOCOL, PI_WARN, "Expected More Flag (* or .)", EXPFILL }},
     { &ei_beep_cr_terminator, { "beep.cr_terminator", PI_PROTOCOL, PI_WARN, "Nonstandard Terminator: CR", EXPFILL }},
     { &ei_beep_lf_terminator, { "beep.lf_terminator", PI_PROTOCOL, PI_WARN, "Nonstandard Terminator: LF", EXPFILL }},
     { &ei_beep_invalid_terminator, { "beep.invalid_terminator", PI_PROTOCOL, PI_WARN, "Invalid Terminator", EXPFILL }},
  };

  module_t *beep_module;
  expert_module_t* expert_beep;

  proto_beep = proto_register_protocol("Blocks Extensible Exchange Protocol",
                                       "BEEP", "beep");

  proto_register_field_array(proto_beep, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_beep = expert_register_protocol(proto_beep);
  expert_register_field_array(expert_beep, ei, array_length(ei));

  beep_request_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), beep_hash, beep_equal);

  /* Register our configuration options for BEEP, particularly our port */

  beep_module = prefs_register_protocol(proto_beep, apply_beep_prefs);
  /* For reading older preference files with "bxxp." preferences */
  prefs_register_module_alias("bxxp", beep_module);

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
  dissector_handle_t beep_handle;

  beep_handle = create_dissector_handle(dissect_beep, proto_beep);

  dissector_add_uint_with_preference("tcp.port", TCP_PORT_BEEP, beep_handle);

  apply_beep_prefs();
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
