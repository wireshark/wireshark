/* packet-bxxp.c
 * Routines for BXXP packet disassembly
 *
 * $Id: packet-bxxp.c,v 1.1 2000/08/30 12:42:31 sharpe Exp $
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
static int hf_bxxp_status = -1;
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

int bxxp_get_more(char more)
{

  if (more == '.')
    return BXXP_COMPLETE;
  else if (more == '*')
    return BXXP_INTERMEDIATE;

  return BXXP_VIOL;
}

void
dissect_bxxp_more(const u_char *pd, int offset, frame_data *fd, 
		  proto_tree *tree)
{

  switch (bxxp_get_more(pd[offset])) {

  case BXXP_COMPLETE:

    proto_tree_add_boolean_hidden(tree, hf_bxxp_complete, NullTVB, offset, 1, TRUE);
    proto_tree_add_text(tree, NullTVB, offset, 1, "More: Complete");

    break;

  case BXXP_INTERMEDIATE:
	
    proto_tree_add_boolean_hidden(tree, hf_bxxp_intermediate, NullTVB, offset, 1, TRUE);
    proto_tree_add_text(tree, NullTVB, offset, 1, "More: Intermediate");

    break;

  default:

    fprintf(stderr, "Error from bxxp_get_more ...\n");
    break;
  }

}

void dissect_bxxp_status(const u_char *pd, int offset, frame_data *fd,
			 proto_tree *tree)
{
  
  switch(pd[offset]) {

  case '+':
  
    proto_tree_add_boolean_hidden(tree, hf_bxxp_positive, NullTVB, offset, 1, TRUE);
    proto_tree_add_text(tree, NullTVB, offset, 1, "Status: Positive");

    break;

  case '-':

    proto_tree_add_boolean_hidden(tree, hf_bxxp_negative, NullTVB, offset, 1, TRUE);
    proto_tree_add_text(tree, NullTVB, offset, 1, "Status: Negative");

    break;

  default:  /* Proto violation: FIXME */

    break;

  }

}

int num_len(const u_char *pd, int offset)
{
  int i = 0;

  /* FIXME: END_OF_FRAME needed here ... */
  while (isdigit(pd[offset + i])) i++;

  return i;

}

/* Get a MIME header ... FIXME: END_OF_DATA */
int header_len(const u_char *pd, int offset)
{
  int i = 0;

  while (pd[offset + i] != 0x0d && pd[offset + i + 1] != 0x0a) i++;

  return i;

}

int
dissect_bxxp_mime_header(const u_char *pd, int offset, frame_data *fd,
			 proto_tree *tree)
{
  proto_tree    *ti, *mime_tree;
  int           mime_length = header_len(pd, offset);

  ti = proto_tree_add_text(tree, NullTVB, offset, mime_length + 2, "Mime header: %s", format_text(pd + offset, mime_length + 2));
  mime_tree = proto_item_add_subtree(ti, ett_mime_header);

  if (mime_length == 0) { /* Default header */

    proto_tree_add_text(mime_tree, NullTVB, offset, 2, "Default values");

  }
  else {  /* FIXME: Process the headers */


  }

  return mime_length + 2;  /* FIXME: Check that the CRLF is there */

}

int
dissect_bxxp_int(const u_char *pd, int offset, frame_data *fd,
		    proto_tree *tree, int hf, int *val)
{
  int ival, i = num_len(pd, offset);

  sscanf(pd + offset, "%d", &ival);  /* FIXME: Dangerous */

  proto_tree_add_uint(tree, hf, NullTVB, offset, i, ival);

  *val = ival;  /* Return the value */

  return i;

}

int 
check_crlf(const u_char *pd, int offset)
{

  /* FIXME: Check END_OF_FRAME */
  return(pd[offset] == 0x0d && pd[offset + 1] == 0x0a);

}

static int global_bxxp_tcp_port = TCP_PORT_BXXP;

/* Build the tree */

int
dissect_bxxp_tree(const u_char *pd, int offset, packet_info *pinfo, 
		  proto_tree *tree)
{
  proto_tree     *bxxp_tree, *ti, *hdr;
  int            st_offset, serial, seqno, size, channel, ackno, window;
  char           *cmd = pd + offset;

  st_offset = offset;

  if (strncmp(pd+offset, "REQ ", 4) == 0) {

    /* FIXME: Fix the header length */
    ti = proto_tree_add_text(tree, NullTVB, offset, header_len(pd, offset) + 2, "Header");

    hdr = proto_item_add_subtree(ti, ett_header);

    proto_tree_add_boolean_hidden(hdr, hf_bxxp_req, NullTVB, offset, 3, TRUE);
    proto_tree_add_text(hdr, NullTVB, offset, 3, "Command: REQ");

    offset += 3;

    if (pd[offset] != ' ') { /* Protocol violation */

      /* Hmm, FIXME ... Add some code here ... */

    }

    offset += 1;

    /* Insert the more elements ... */

    dissect_bxxp_more(pd, offset, pinfo->fd, hdr);
    offset += 1;
      
    /* Check the space ... */

    offset += 1;

    /* Dissect the serial */

    offset += dissect_bxxp_int(pd, offset, pinfo->fd, hdr, hf_bxxp_serial, &serial);
    /* skip the space */

    offset += 1;

    /* now for the seqno */

    offset += dissect_bxxp_int(pd, offset, pinfo->fd, hdr, hf_bxxp_seqno, &seqno);

    /* skip the space */

    offset += 1;

    offset += dissect_bxxp_int(pd, offset, pinfo->fd, hdr, hf_bxxp_size, &size);

    /* Check the space */

    offset += 1;

    /* Get the channel */

    offset += dissect_bxxp_int(pd, offset, pinfo->fd, hdr, hf_bxxp_channel, &channel);
      
    if (check_crlf(pd, offset)) {

      proto_tree_add_text(hdr, NullTVB, offset, 2, "Terminator: CRLF");

    }
    else {  /* Protocol violation */

      /* FIXME: implement */

    }

    offset += 2;
    
    /* Insert MIME header ... */

    offset += dissect_bxxp_mime_header(pd, offset, pinfo->fd, hdr);

    /* Now for the payload, if any */

    if (END_OF_FRAME > 0) { /* Dissect what is left as payload */

      int pl_size = MIN(size, END_OF_FRAME);

      /* Except, check the payload length, and only dissect that much */

      proto_tree_add_text(tree, NullTVB, offset, pl_size, "Payload: %s", format_text(pd + offset, pl_size));

      offset += pl_size;

    }
      
    /* If anything else left, dissect it ... As what? */

    if (END_OF_FRAME > 0)
      offset += dissect_bxxp_tree(pd, offset, pinfo->fd, tree);

  } else if (strncmp(pd+offset, "RSP ", 4) == 0) {

    /* FIXME: Fix the header length */

    ti = proto_tree_add_text(tree, NullTVB, offset, header_len(pd, offset) + 2, "Header");

    hdr = proto_item_add_subtree(ti, ett_header);

    proto_tree_add_boolean_hidden(hdr, hf_bxxp_rsp, NullTVB, offset, 3, TRUE);
    proto_tree_add_text(hdr, NullTVB, offset, 3, "Command: RSP");

    offset += 3;

    /* Now check the space: FIXME */

    offset += 1;

    /* Next, the 'more' flag ... */

    dissect_bxxp_more(pd, offset, pinfo->fd, hdr);
    offset += 1;

    /* Check the space */

    offset += 1;

    offset += dissect_bxxp_int(pd, offset, pinfo->fd, hdr, hf_bxxp_serial, &serial);
    /* skip the space */

    offset += 1;

    /* now for the seqno */

    offset += dissect_bxxp_int(pd, offset, pinfo->fd, hdr, hf_bxxp_seqno, &seqno);

    /* skip the space */

    offset += 1;

    offset += dissect_bxxp_int(pd, offset, pinfo->fd, hdr, hf_bxxp_size, &size);

    /* Check the space ... */

    offset += 1;

    dissect_bxxp_status(pd, offset, pinfo->fd, hdr);

    offset += 1;

    if (check_crlf(pd, offset)) {

      proto_tree_add_text(hdr, NullTVB, offset, 2, "Terminator: CRLF");

    }
    else {  /* Protocol violation */

      /* FIXME: implement */

    }

    offset += 2;
    
    /* Insert MIME header ... */

    offset += dissect_bxxp_mime_header(pd, offset, pinfo->fd, hdr);

    /* Now for the payload, if any */

    if (END_OF_FRAME > 0) { /* Dissect what is left as payload */

      int pl_size = MIN(size, END_OF_FRAME);
      
      /* Except, check the payload length, and only dissect that much */

      proto_tree_add_text(tree, NullTVB, offset, pl_size, "Payload: %s", format_text(pd + offset, pl_size));

      offset += pl_size;

    }

    /* If anything else left, dissect it ... As what? */

    if (END_OF_FRAME > 0)
      offset += dissect_bxxp_tree(pd, offset, pinfo->fd, tree);

  } else if (strncmp(pd+offset, "SEQ ", 4) == 0) {

    proto_tree_add_boolean_hidden(tree, hf_bxxp_seq, NullTVB, offset, 3, TRUE);
    proto_tree_add_text(tree, NullTVB, offset, 3, "Command: SEQ");
      
    offset += 3;

    /* Now check the space: FIXME */

    offset += 1;

    offset += dissect_bxxp_int(pd, offset, pinfo->fd, tree, hf_bxxp_channel, &channel);

    /* Check the space: FIXME */

    offset += 1;

    offset += dissect_bxxp_int(pd, offset, pinfo->fd, tree, hf_bxxp_ackno, &ackno);

    /* Check the space: FIXME */

    offset += 1;

    offset += dissect_bxxp_int(pd, offset, pinfo->fd, tree, hf_bxxp_window, &window);

    if (check_crlf(pd, offset)) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Terminator: CRLF");

    }
    else {  /* Protocol violation */

      /* FIXME: implement */

    }

    offset += 2;

  } else if (strncmp(pd+offset, "END", 3) == 0) {

    proto_tree *tr;

    ti = proto_tree_add_text(tree, NullTVB, offset, MIN(5, END_OF_FRAME), "Trailer");

    tr = proto_item_add_subtree(ti, ett_trailer);

    proto_tree_add_boolean_hidden(tr, hf_bxxp_end, NullTVB, offset, 3, TRUE);
    proto_tree_add_text(tr, NullTVB, offset, 3, "Command: END");

    offset += 3;

    if (check_crlf(pd, offset)) {

      proto_tree_add_text(tr, NullTVB, offset, 2, "Terminator: CRLF");

    }
    else {  /* Protocol violation */

      /* FIXME: implement */

    }

    offset += 2;

  }

  if (END_OF_FRAME > 0) { /* Dissect anything left over as payload */

    proto_tree_add_text(tree, NullTVB, offset, END_OF_FRAME, "Payload: %s",
			format_text(pd + offset, END_OF_FRAME));

  }

  return offset - st_offset;

}

#if 0
static void
dissect_bxxp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
#else
static void
dissect_bxxp(const u_char *pd, int offset, frame_data *fd,
		  proto_tree *tree)

{
  tvbuff_t       *tvb = tvb_create_from_top(offset);
  packet_info    *pinfo = &pi;
#endif
  proto_tree     *bxxp_tree, *ti;
  int            request, serial, seqno, size, channel, ackno, window;
  char           *cmd = pd + offset;

#if 0
  CHECK_DISPLAY_AS_DATA(proto_bxxp, tvb, pinfo, tree);
#else
  OLD_CHECK_DISPLAY_AS_DATA(proto_bxxp, pd, offset, fd, tree);
#endif

  /* Dissect this frame a bit ? */

  request = pinfo->destport == tcp_port;

  if (check_col(pinfo->fd, COL_PROTOCOL))
    col_add_str(pinfo->fd, COL_PROTOCOL, "BXXP");

  if (check_col(pinfo->fd, COL_INFO)) {  /* Check the type ... */

    col_add_fstr(pinfo->fd, COL_INFO, "%s", format_text(cmd, END_OF_FRAME));

  }

  if (tree) {  /* Build the tree info ... */

    ti = proto_tree_add_item(tree, proto_bxxp, NullTVB, offset, END_OF_FRAME, FALSE);

    bxxp_tree = proto_item_add_subtree(ti, ett_bxxp);

    dissect_bxxp_tree(pd, offset, pinfo, bxxp_tree);

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

}

/* The registration hand-off routine */
void
proto_reg_handoff_bxxp(void)
{
  static int bxxp_prefs_initialized = FALSE;

  if (bxxp_prefs_initialized) {

    old_dissector_delete("tcp.port", tcp_port, dissect_bxxp);

  }
  else {

    bxxp_prefs_initialized = TRUE;

  }

  /* Set our port number for future use */

  tcp_port = global_bxxp_tcp_port;

  old_dissector_add("tcp.port", global_bxxp_tcp_port, dissect_bxxp);

}
