/* packet-eap.c
 * Routines for EAP Extensible Authentication Protocol dissection
 * RFC 2284
 *
 * $Id: packet-eap.c,v 1.23 2002/03/27 19:38:37 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include "ppptypes.h"
#include "reassemble.h"

static int proto_eap = -1;
static int hf_eap_code = -1;
static int hf_eap_identifier = -1;
static int hf_eap_len = -1;
static int hf_eap_type = -1;
static int hf_eap_type_nak = -1;

static gint ett_eap = -1;

static dissector_handle_t ssl_handle;

#define EAP_REQUEST	1
#define EAP_RESPONSE	2
#define EAP_SUCCESS	3
#define EAP_FAILURE	4

static const value_string eap_code_vals[] = { 
    { EAP_REQUEST,  "Request" },
    { EAP_RESPONSE, "Response" },
    { EAP_SUCCESS,  "Success" },
    { EAP_FAILURE,  "Failure" },
    { 0,            NULL }
};

/*
References:
  1) http://www.iana.org/assignments/ppp-numbers	
			PPP EAP REQUEST/RESPONSE TYPES
  2) http://www.ietf.org/internet-drafts/draft-ietf-pppext-rfc2284bis-02.txt
  3) RFC2284
*/

#define EAP_TYPE_ID     1
#define EAP_TYPE_NOTIFY 2
#define EAP_TYPE_NAK    3
#define EAP_TYPE_TLS	13
#define EAP_TYPE_LEAP	17

static const value_string eap_type_vals[] = { 
  {EAP_TYPE_ID,  "Identity [RFC2284]" },
  {EAP_TYPE_NOTIFY,"Notification [RFC2284]" },
  {EAP_TYPE_NAK, "Nak (Response only) [RFC2284]" },
  {  4,          "MD5-Challenge [RFC2284]" },
  {  5,          "One Time Password (OTP) [RFC2289]" },
  {  6,          "Generic Token Card [RFC2284]" },
  {  7,          "?? RESERVED ?? " }, /* ??? */
  {  8,          "?? RESERVED ?? " }, /* ??? */
  {  9,          "RSA Public Key Authentication [Whelan]" },
  { 10,          "DSS Unilateral [Nace]" },
  { 11,          "KEA [Nace]" },
  { 12,          "KEA-VALIDATE [Nace]" },
  {EAP_TYPE_TLS, "EAP-TLS [RFC2716] [Aboba]" },
  { 14,          "Defender Token (AXENT) [Rosselli]" },
  { 15,          "Windows 2000 EAP [Asnes]" },
  { 16,          "Arcot Systems EAP [Jerdonek]" },
  {EAP_TYPE_LEAP,"EAP-Cisco Wireless (LEAP) [Norman]" }, 
  { 18,          "Nokia IP smart card authentication [Haverinen]" },  
  { 19,          "SRP-SHA1 Part 1 [Carlson]" },
  { 20,          "SRP-SHA1 Part 2 [Carlson]" },
  { 21,          "EAP-TTLS [Funk]" },
  { 22,          "Remote Access Service [Fields]" },
  { 23,          "UMTS Authentication and Key Argreement [Haverinen]" }, 
  { 24,          "EAP-3Com Wireless [Young]" }, 
  { 25,          "PEAP [Palekar]" },
  { 26,          "MS-EAP-Authentication [Palekar]" },
  { 27,          "Mutual Authentication w/Key Exchange (MAKE)[Berrendonner]" },
  { 28,          "CRYPTOCard [Webb]" },
  { 29,          "EAP-MSCHAP-V2 [Potter]" },
  { 30,          "DynamID [Merlin]" },
  { 31,          "Rob EAP [Ullah]" },
  { 32,          "SecurID EAP [Josefsson]" },
  { 255,         "Vendor-specific [draft-ietf-pppext-rfc2284bis-02.txt]" },
  { 0,          NULL }

};

/*
 * State information for EAP-TLS (RFC2716) and Lightweight EAP:
 *
 *	http://www.missl.cs.umd.edu/wireless/ethereal/leap.txt
 *
 * Attach to all frames containing fragments of EAP-TLS messages the
 * EAP ID value of the first fragment, so we can determine which
 * message is getting reassembled after the first pass through
 * the packets.  We also attach a sequence number for fragments,
 * which starts with 0 for the first fragment.
 *
 * Attach to all frames containing LEAP messages an indication of
 * the state of the LEAP negotiation, so we can properly dissect
 * the LEAP message after the first pass through the packets.
 *
 * Attach to all conversations both pieces of information, to keep
 * track of EAP-TLS reassembly and the LEAP state machine.
 */
static GMemChunk *conv_state_chunk = NULL;

typedef struct {
	int	init_eap_id;
	int	eap_tls_seq;
	int	leap_state;
} conv_state_t;

static GMemChunk *frame_state_chunk = NULL;

typedef struct {
	int	info;	/* interpretation depends on EAP message type */
} frame_state_t;

/*********************************************************************
                           EAP-TLS 
RFC2716
**********************************************************************/

/*
from RFC2716, pg 17

   Flags

      0 1 2 3 4 5 6 7 8
      +-+-+-+-+-+-+-+-+
      |L M S R R R R R|
      +-+-+-+-+-+-+-+-+

      L = Length included
      M = More fragments
      S = EAP-TLS start
      R = Reserved
*/

#define EAP_TLS_FLAG_L 0x80 /* Length included */
#define EAP_TLS_FLAG_M 0x40 /* More fragments  */
#define EAP_TLS_FLAG_S 0x20 /* EAP-TLS start   */

/*
 * reassembly of EAP-TLS
 */
static GHashTable *eaptls_fragment_table = NULL;

static int   hf_eaptls_fragment  = -1;
static int   hf_eaptls_fragments = -1;
static gint ett_eaptls_fragment  = -1;
static gint ett_eaptls_fragments = -1;

/*********************************************************************
**********************************************************************/

static gboolean
test_flag(unsigned char flag, unsigned char mask) 
{
  return ( ( flag & mask ) != 0 );
}

static void
eaptls_defragment_init(void)
{
  fragment_table_init(&eaptls_fragment_table);
}

static void
eap_init_protocol(void)
{
  if (conv_state_chunk != NULL)
    g_mem_chunk_destroy(conv_state_chunk);
  if (frame_state_chunk != NULL)
    g_mem_chunk_destroy(frame_state_chunk);

  conv_state_chunk = g_mem_chunk_new("conv_state_chunk",
				     sizeof (conv_state_t),
				     10 * sizeof (conv_state_t),
				     G_ALLOC_ONLY);

  frame_state_chunk = g_mem_chunk_new("frame_state_chunk",
				      sizeof (frame_state_t),
				     100 * sizeof (frame_state_t),
				     G_ALLOC_ONLY);
}

static int
dissect_eap_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		 gboolean fragmented)
{
  guint8      eap_code;
  guint8      eap_id;
  guint16     eap_len;
  guint8      eap_type;
  gint        len;
  conversation_t *conversation;
  conv_state_t *conversation_state;
  frame_state_t *packet_state;
  int leap_state;
  proto_tree *ti;
  proto_tree *eap_tree = NULL;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "EAP");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  eap_code = tvb_get_guint8(tvb, 0);

  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_str(pinfo->cinfo, COL_INFO,
		val_to_str(eap_code, eap_code_vals, "Unknown code (0x%02X)"));

  /*
   * Find a conversation to which we belong; create one if we don't find
   * it.
   *
   * We use the source and destination addresses, and the *matched* port
   * number, because if this is running over RADIUS, there's no guarantee
   * that the source port number for request and the destination port
   * number for replies will be the same in all messages - the client
   * may use different port numbers for each request.
   *
   * We have to pair up the matched port number with the corresponding
   * address; we determine which that is by comparing it with the
   * destination port - if it matches, we matched on the destination
   * port (this is a request), otherwise we matched on the source port
   * (this is a reply).
   *
   * XXX - what if we're running over a TCP or UDP protocol with a
   * heuristic dissector, meaning the matched port number won't be set?
   *
   * XXX - what if we have a capture file with captures on multiple
   * PPP interfaces, with LEAP traffic on all of them?  How can we
   * keep them separate?  (Or is that not going to happen?)
   */
  if (pinfo->destport == pinfo->match_port) {
    conversation = find_conversation(&pinfo->dst, &pinfo->src,
				     pinfo->ptype, pinfo->destport,
				     0, NO_PORT_B);
  } else {
    conversation = find_conversation(&pinfo->src, &pinfo->dst,
				     pinfo->ptype, pinfo->srcport,
				     0, NO_PORT_B);
  }
  if (conversation == NULL) {
    if (pinfo->destport == pinfo->match_port) {
      conversation = conversation_new(&pinfo->dst, &pinfo->src,
				      pinfo->ptype, pinfo->destport,
				      0, NO_PORT2);
    } else {
      conversation = conversation_new(&pinfo->src, &pinfo->dst,
				      pinfo->ptype, pinfo->srcport,
				      0, NO_PORT2);
    }
  }

  /*
   * Get the LEAP state information for the conversation; attach some if
   * we don't find it.
   */
  conversation_state = conversation_get_proto_data(conversation, proto_eap);
  if (conversation_state == NULL) {
    /*
     * Attach LEAP state information to the conversation.
     */
    conversation_state = g_mem_chunk_alloc(conv_state_chunk);
    conversation_state->init_eap_id = -1;
    conversation_state->eap_tls_seq = -1;
    conversation_state->leap_state = -1;
    conversation_add_proto_data(conversation, proto_eap, conversation_state);
  }

  /*
   * Set this now, so that it gets remembered even if we throw an exception
   * later.
   */
  if (eap_code == EAP_FAILURE)
    conversation_state->leap_state = -1;

  eap_id = tvb_get_guint8(tvb, 1);

  eap_len = tvb_get_ntohs(tvb, 2);
  len = eap_len;

  if (fragmented) {
    /*
     * This is an EAP fragment inside, for example, RADIUS.  If we don't
     * have all of the packet data, return the negative of the amount of
     * additional data we need.
     */
    int reported_len = tvb_reported_length_remaining(tvb, 0);

    if (reported_len < len)
      return -(len - reported_len);
  }

  if (tree) {
    ti = proto_tree_add_item(tree, proto_eap, tvb, 0, len, FALSE);
    eap_tree = proto_item_add_subtree(ti, ett_eap);

    proto_tree_add_uint(eap_tree, hf_eap_code, tvb, 0, 1, eap_code);
  }

  if (tree)
    proto_tree_add_item(eap_tree, hf_eap_identifier, tvb, 1, 1, FALSE);

  if (tree)
    proto_tree_add_uint(eap_tree, hf_eap_len, tvb, 2, 2, eap_len);

  switch (eap_code) {

  case EAP_SUCCESS:
  case EAP_FAILURE:
    break;

  case EAP_REQUEST:
  case EAP_RESPONSE:
    eap_type = tvb_get_guint8(tvb, 4);

    if (check_col(pinfo->cinfo, COL_INFO))
      col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
		      val_to_str(eap_type, eap_type_vals,
				 "Unknown type (0x%02X)"));
    if (tree)
      proto_tree_add_uint(eap_tree, hf_eap_type, tvb, 4, 1, eap_type);

    if (len > 5) {
      int     offset = 5;
      gint    size   = len - offset;

      switch (eap_type) {
      /*********************************************************************
      **********************************************************************/
      case EAP_TYPE_ID:
	if (tree) {
	  proto_tree_add_text(eap_tree, tvb, offset, size, 
			      "Identity (%d byte%s): %s",
			      size, plurality(size, "", "s"),
			      tvb_format_text(tvb, offset, size));
         }
	if(!pinfo->fd->flags.visited)
	  conversation_state->leap_state = 0;
	break;

      /*********************************************************************
      **********************************************************************/
      case EAP_TYPE_NOTIFY:
	if (tree) {
	  proto_tree_add_text(eap_tree, tvb, offset, size, 
			      "Notification (%d byte%s): %s",
			      size, plurality(size, "", "s"),
			      tvb_format_text(tvb, offset, size));
	}
	break;
      /*********************************************************************
      **********************************************************************/
      case EAP_TYPE_NAK:
	if (tree) {
	  proto_tree_add_uint(eap_tree, hf_eap_type_nak, tvb,
			      offset, size, eap_type);
	}
	break;
      /*********************************************************************
                                  EAP-TLS
      **********************************************************************/
      case EAP_TYPE_TLS:
	{
	guint8 flags   = tvb_get_guint8(tvb, offset);
	gboolean more_fragments;
	gboolean has_length;
	guint32 length;
	int init_eap_id = -1;
	int eap_tls_seq = -1;

	more_fragments = test_flag(flags,EAP_TLS_FLAG_M);
	has_length = test_flag(flags,EAP_TLS_FLAG_L);

	/* Flags field, 1 byte */
	if (tree)
	  proto_tree_add_text(eap_tree, tvb, offset, 1, "Flags(0x%X): %s%s%s",
			      flags,
			      has_length                      ? "Length ":"",
			      more_fragments                  ? "More "  :"",
			      test_flag(flags,EAP_TLS_FLAG_S) ? "Start " :"");
	size--;
	offset++;

	/* Length field, 4 bytes, OPTIONAL. */
	if ( has_length ) {
	  length = tvb_get_ntohl(tvb, offset);
	  if (tree)
	    proto_tree_add_text(eap_tree, tvb, offset, 4, "Length: %i",length);
	  size   -= 4;
	  offset += 4;
	}

	if (size>0) {

	  tvbuff_t *next_tvb;
	  gint tvb_len; 
	  gboolean save_fragmented;

	  tvb_len = tvb_length_remaining(tvb, offset);
	  if (size < tvb_len)
	    tvb_len = size;
	  
	    /* 
	       EAP/TLS is weird protocol (it comes from 
	       Microsoft after all). 

	       If we have series of fragmented packets,
	       then there's no way of knowing that from
	       the packet itself, if it is the last packet
	       in series, that is that the packet part of 
	       bigger fragmented set of data.

	       The only way to know is, by knowing
	       that we are already in defragmentation
	       "mode" and we are expecing packet
	       carrying fragment of data. (either 
	       because we have not received expected
	       amount of data, or because the packet before
	       had "F"ragment flag set.)

	       The situation is alleviated by fact that it 
	       is simple ack/nack protcol so there's no 
	       place for out-of-order packets like it is 
	       possible with IP. 

	       Anyway, point of this lengthy essay is that
	       we have to keep state information in the
	       conversation, so that we can put ourselves in 
	       defragmenting mode and wait for the last packet,
	       and have to attach state to frames as well, so
	       that we can handle defragmentation after the
	       first pass through the capture.
	    */
	  /* See if we have a remembered defragmentation EAP ID. */
	  packet_state = p_get_proto_data(pinfo->fd, proto_eap);
	  if (packet_state == NULL) {
	    /*
	     * We haven't - does this message require reassembly?
	     */
	    if (!pinfo->fd->flags.visited) {
	      /*
	       * This is the first time we've looked at this frame,
	       * so it wouldn't have any remembered information.
	       *
	       * Therefore, we check whether this conversation has
	       * a reassembly operation in progress, or whether
	       * this frame has the Fragment flag set.
	       */
	      if (conversation_state->eap_tls_seq != -1) {
		/*
		 * There's a reassembly in progress; the EAP ID of
		 * the message containing the first fragment
		 * is "conversation_state->init_eap_id", and
		 * the sequence number of the previous fragment
		 * is "conversation_state->eap_tls_seq".
		 *
		 * We must include this frame in the reassembly.
		 * We advance the sequence number, giving us the
		 * sequence number for this fragment.
		 */
		init_eap_id = conversation_state->init_eap_id;
		conversation_state->eap_tls_seq++;
		eap_tls_seq = conversation_state->eap_tls_seq;
	      } else if (more_fragments && has_length) {
		/*
		 * This message has the Fragment flag set, so it requires
		 * reassembly.  It's the message containing the first
		 * fragment (if it's a later fragment, the EAP ID
		 * in the conversation state would not be -1, it'd
		 * be the EAP ID of the first fragment), so remember its
		 * EAP ID.
		 *
		 * If it doesn't include a length, however, we can't
		 * do reassembly (either the message is in error, as
		 * the first fragment *must* contain a length, or we
		 * didn't capture the first fragment, and this just
		 * happens to be the first fragment we saw), so we
		 * also check that we have a length;
		 */
		init_eap_id = eap_id;
		conversation_state->init_eap_id = eap_id;

		/*
		 * Start the sequence number at 0.
		 */
		conversation_state->eap_tls_seq = 0;
		eap_tls_seq = conversation_state->eap_tls_seq;
	      }

	      if (init_eap_id != -1) {
		/*
		 * This frame requires reassembly; remember the initial
		 * EAP ID for subsequent accesses to it.
		 */
		packet_state = g_mem_chunk_alloc(frame_state_chunk);
		packet_state->info = init_eap_id;
		p_add_proto_data(pinfo->fd, proto_eap, packet_state);
	      }
	    }
	  } else {
	    /*
	     * This frame has an initial EAP ID associated with it, so
	     * it requires reassembly.  We've already done the
	     * reassembly in the first pass, so "fragment_add_seq()"
	     * won't look at the sequence number; set it to 0.
	     *
	     * XXX - a frame isn't supposed to have more than one
	     * EAP message in it, but if it includes both an EAP-TLS
	     * message and a LEAP message, we might be mistakenly
	     * concluding it requires reassembly because the "info"
	     * field isn't -1.  We could, I guess, pack both EAP-TLS
	     * ID and LEAP state into the structure, but that doesn't
	     * work if you have multiple EAP-TLS or LEAP messages in
	     * the frame.
	     *
	     * But it's not clear how much work we should do to handle
	     * a bogus message such as that; as long as we don't crash
	     * or do something else equally horrible, we may not
	     * have to worry about this at all.
	     */
	    init_eap_id = packet_state->info;
	    eap_tls_seq = 0;
	  }

	  /* 
	     We test here to see whether EAP-TLS packet 
	     carry fragmented of TLS data. 

	     If is his case, we do reasembly below,
	     otherwise we just call dissector.
	  */
	  if (init_eap_id != -1) {
	    fragment_data   *fd_head = NULL;

	    /*
	     * Yes, this frame contains a fragment that requires
	     * reassembly.
	     */
	    save_fragmented = pinfo->fragmented;
	    pinfo->fragmented = TRUE;
	    fd_head = fragment_add_seq(tvb, offset, pinfo, 
				   init_eap_id,
				   eaptls_fragment_table,
				   eap_tls_seq, 
				   size,
				   more_fragments);

	    if (fd_head != NULL)            /* Reassembled  */
	      {

		fragment_data *ffd; /* fragment file descriptor */
		proto_tree *ft=NULL;
		proto_item *fi=NULL;
		guint32 frag_offset;

		next_tvb = tvb_new_real_data(fd_head->data,
					     fd_head->len,
					     fd_head->len);
		tvb_set_child_real_data_tvbuff(tvb, next_tvb);
		add_new_data_source(pinfo->fd, next_tvb,
				    "Reassembled EAP-TLS");
		pinfo->fragmented = FALSE;
		
		fi = proto_tree_add_item(eap_tree, hf_eaptls_fragments,
					 next_tvb, 0, -1, FALSE);
		ft = proto_item_add_subtree(fi, ett_eaptls_fragments);
		frag_offset = 0;
		for (ffd=fd_head->next; ffd; ffd=ffd->next){
		  proto_tree_add_none_format(ft, hf_eaptls_fragment,
					     next_tvb, frag_offset, ffd->len,
					     "Frame:%u payload:%u-%u",
					     ffd->frame,
					     frag_offset,
					     frag_offset+ffd->len-1
					     );
		  frag_offset += ffd->len;
		}
		call_dissector(ssl_handle, next_tvb, pinfo, eap_tree);

		/*
		 * We're finished reassembing this frame.
		 * Reinitialize the reassembly state.
		 */
		if (!pinfo->fd->flags.visited) {
		  conversation_state->init_eap_id = -1;
		  conversation_state->eap_tls_seq = -1;
		}
	      }

	    pinfo->fragmented = save_fragmented;
			
	  } else { /* this data is NOT fragmented */
	    next_tvb = tvb_new_subset(tvb, offset, tvb_len, size);
	    call_dissector(ssl_handle, next_tvb, pinfo, eap_tree);
	  }
	}
	}
	break; /*  EAP_TYPE_TLS */
      /*********************************************************************
                                  Cisco's Lightweight EAP (LEAP)
      http://www.missl.cs.umd.edu/wireless/ethereal/leap.txt
      **********************************************************************/
      case EAP_TYPE_LEAP:
	{
	  guint8  field,count,namesize;

	  /* Version (byte) */
	  if (tree) {
	    field = tvb_get_guint8(tvb, offset);
	    proto_tree_add_text(eap_tree, tvb, offset, 1, 
				"Version: %i",field);
	  }
	  size--;
	  offset++;

	  /* Unused  (byte) */
	  if (tree) {
	    field = tvb_get_guint8(tvb, offset);
	    proto_tree_add_text(eap_tree, tvb, offset, 1, 
				"Reserved: %i",field);
	  }
	  size--;
	  offset++;

	  /* Count   (byte) */
	  count = tvb_get_guint8(tvb, offset);
	  if (tree) {
	    proto_tree_add_text(eap_tree, tvb, offset, 1, 
				"Count: %i",count);
	  }
	  size--;
	  offset++;

	  /* Data    (byte*Count) */
	  /* This part is state-dependent. */

	  /* See if we've already remembered the state. */
	  packet_state = p_get_proto_data(pinfo->fd, proto_eap);
	  if (packet_state == NULL) {
	    /*
	     * We haven't - compute the state based on the current
	     * state in the conversation.
	     */
	    leap_state = conversation_state->leap_state;
	    
	    /* Advance the state machine. */
	    if (leap_state==0) leap_state =  1; else
	    if (leap_state==1) leap_state =  2; else
	    if (leap_state==2) leap_state =  3; else
	    if (leap_state==3) leap_state =  4; else
	    if (leap_state==4) leap_state = -1;

	    /*
	     * Remember the state for subsequent accesses to this
	     * frame.
	     */
	    packet_state = g_mem_chunk_alloc(frame_state_chunk);
	    packet_state->info = leap_state;
	    p_add_proto_data(pinfo->fd, proto_eap, packet_state);

	    /*
	     * Update the conversation's state.
	     */
	    conversation_state->leap_state = leap_state;
	  }

	  /* Get the remembered state. */
	  leap_state = packet_state->info;

	  if (tree) { 

	    if        (leap_state==1) {
	      proto_tree_add_text(eap_tree, tvb, offset, count, 
				  "Peer Challenge [8] Random Value:\"%s\"",
				  tvb_bytes_to_str(tvb, offset, count));
	    } else if (leap_state==2) {
	      proto_tree_add_text(eap_tree, tvb, offset, count, 
				  "Peer Response [24] NtChallengeResponse(%s)",
				  tvb_bytes_to_str(tvb, offset, count));
	    } else if (leap_state==3) {
	      proto_tree_add_text(eap_tree, tvb, offset, count, 
				  "AP Challenge [8] Random Value:\"%s\"",
				  tvb_bytes_to_str(tvb, offset, count));
	    } else if (leap_state==4) {
	      proto_tree_add_text(eap_tree, tvb, offset, count, 
				  "AP Response [24] ChallengeResponse(%s)",
				  tvb_bytes_to_str(tvb, offset, count));
	    } else {
	      proto_tree_add_text(eap_tree, tvb, offset, count, 
				"Data (%d byte%s): \"%s\"",
				count, plurality(count, "", "s"),
				tvb_bytes_to_str(tvb, offset, count));
	    }

	  } /* END: if (tree) */


	  size   -= count;
	  offset += count;

	  /* Name    (Length-(8+Count)) */
	  namesize = eap_len - (8+count);
	  if (tree) {
	    proto_tree_add_text(eap_tree, tvb, offset, namesize, 
				"Name (%d byte%s): %s",
				namesize, plurality(count, "", "s"),
				tvb_format_text(tvb, offset, namesize));
	  }
	  size   -= namesize;
	  offset += namesize;
	}

	break; /* EAP_TYPE_LEAP */
      /*********************************************************************
      **********************************************************************/
      default:
        if (tree) {
	  proto_tree_add_text(eap_tree, tvb, offset, size, 
			      "Type-Data (%d byte%s) Value: %s",
			      size, plurality(size, "", "s"),
			      tvb_bytes_to_str(tvb, offset, size));
	}
	break;
      /*********************************************************************
      **********************************************************************/
      } /* switch (eap_type) */

    }

  } /* switch (eap_code) */

  return tvb_length(tvb);
}

static int
dissect_eap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return dissect_eap_data(tvb, pinfo, tree, FALSE);
}

static int
dissect_eap_fragment(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return dissect_eap_data(tvb, pinfo, tree, TRUE);
}

void
proto_register_eap(void)
{
  static hf_register_info hf[] = {
	{ &hf_eap_code, { 
		"Code", "eap.code", FT_UINT8, BASE_DEC, 
		VALS(eap_code_vals), 0x0, "", HFILL }},
	{ &hf_eap_identifier, {
		"Id", "eap.id", FT_UINT8, BASE_DEC,
		NULL, 0x0, "", HFILL }},
	{ &hf_eap_len, {
		"Length", "eap.len", FT_UINT16, BASE_DEC,
		NULL, 0x0, "", HFILL }},
	{ &hf_eap_type, { 
		"Type", "eap.type", FT_UINT8, BASE_DEC, 
		VALS(eap_type_vals), 0x0, "", HFILL }},
	{ &hf_eap_type_nak, { 
		"Desired Auth Type", "eap.type", FT_UINT8, BASE_DEC, 
		VALS(eap_type_vals), 0x0, "", HFILL }},
	{ &hf_eaptls_fragment,
	  { "EAP-TLS Fragment", "eaptls.fragment", 
	        FT_NONE, BASE_NONE, NULL, 0x0,
	        "EAP-TLS Fragment", HFILL }},
	{ &hf_eaptls_fragments,
	  { "EAP-TLS Fragments", "eaptls.fragments", 
	        FT_NONE, BASE_NONE, NULL, 0x0,
	        "EAP-TLS Fragments", HFILL }},


  };
  static gint *ett[] = {
	&ett_eap,
	&ett_eaptls_fragment,
	&ett_eaptls_fragments,
  };

  proto_eap = proto_register_protocol("Extensible Authentication Protocol", 
				      "EAP", "eap");
  proto_register_field_array(proto_eap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_init_routine(&eap_init_protocol);

  new_register_dissector("eap", dissect_eap, proto_eap);
  new_register_dissector("eap_fragment", dissect_eap_fragment, proto_eap);
  register_init_routine(eaptls_defragment_init);
}

void
proto_reg_handoff_eap(void)
{
  dissector_handle_t eap_handle;

  /*
   * Get a handle for the SSL/TLS dissector.
   */
  ssl_handle = find_dissector("ssl");

  eap_handle = find_dissector("eap");
  dissector_add("ppp.protocol", PPP_EAP, eap_handle);
}
