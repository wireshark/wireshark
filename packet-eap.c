/* packet-eap.c
 * Routines for EAP Extensible Authentication Protocol dissection
 * RFC 2284
 *
 * $Id: packet-eap.c,v 1.21 2002/03/23 21:24:38 guy Exp $
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
 * Attach to all frames containing LEAP messages an indication of
 * the state of the LEAP negotiation, so we can properly dissect
 * the LEAP message after the first pass through the packets.
 */
static GMemChunk *leap_state_chunk = NULL;

typedef struct {
	int	state;
} leap_state_t;

static void
eap_init_protocol(void)
{
  if (leap_state_chunk != NULL)
    g_mem_chunk_destroy(leap_state_chunk);

  leap_state_chunk = g_mem_chunk_new("leap_state_chunk",
				     sizeof (leap_state_t),
				     100 * sizeof (leap_state_t),
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
  leap_state_t *conversation_state, *packet_state;
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
    conversation_state = g_mem_chunk_alloc(leap_state_chunk);
    conversation_state->state = -1;
    conversation_add_proto_data(conversation, proto_eap, conversation_state);
  }

  /*
   * Set this now, so that it gets remembered even if we throw an exception
   * later.
   */
  if (eap_code == EAP_FAILURE)
    conversation_state->state = -1;

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

      case EAP_TYPE_ID:
	if (tree) {
	  proto_tree_add_text(eap_tree, tvb, offset, size, 
			      "Identity (%d byte%s): %s",
			      size, plurality(size, "", "s"),
			      tvb_format_text(tvb, offset, size));
         }
	conversation_state->state = 0;
	break;
	
      case EAP_TYPE_NOTIFY:
	if (tree) {
	  proto_tree_add_text(eap_tree, tvb, offset, size, 
			      "Notification (%d byte%s): %s",
			      size, plurality(size, "", "s"),
			      tvb_format_text(tvb, offset, size));
	}
	break;

      case EAP_TYPE_NAK:
	if (tree) {
	  proto_tree_add_uint(eap_tree, hf_eap_type_nak, tvb,
			      offset, size, eap_type);
	}
	break;

      case EAP_TYPE_TLS:
	{
	guint8 flags = tvb_get_guint8(tvb, offset);

	if (tree) {
	  proto_tree_add_text(eap_tree, tvb, offset, 1, "Flags(%i): %s%s%s",
			      flags,
			      flags & 128 ? "Length " : "",
			      flags &  64 ? "More " : "",
			      flags &  32 ? "Start " : "");
	}
	size--;
	offset++;

	if (flags >> 7) {
	  guint32 length = tvb_get_ntohl(tvb, offset);
	  if (tree) {
	    proto_tree_add_text(eap_tree, tvb, offset, 4, "Length: %i",
				length);
	  }
	  size   -= 4;
	  offset += 4;
	}

	if (size>0) {
	  tvbuff_t *next_tvb;
	  gint tvb_len; 

	  tvb_len = tvb_length_remaining(tvb, offset);
	  if (size < tvb_len)
	    tvb_len = size;
	  next_tvb = tvb_new_subset(tvb, offset, tvb_len, size);
	  call_dissector(ssl_handle, next_tvb, pinfo, eap_tree);
	}
	}
	break; /*  EAP_TYPE_TLS */

	/*
	  Cisco's LEAP
	  http://www.missl.cs.umd.edu/wireless/ethereal/leap.txt
	*/

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
	    leap_state = conversation_state->state;
	    
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
	    packet_state = g_mem_chunk_alloc(leap_state_chunk);
	    packet_state->state = leap_state;
	    p_add_proto_data(pinfo->fd, proto_eap, packet_state);

	    /*
	     * Update the conversation's state.
	     */
	    conversation_state->state = leap_state;
	  }

	  /* Get the remembered state. */
	  leap_state = packet_state->state;

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

      default:
        if (tree) {
	  proto_tree_add_text(eap_tree, tvb, offset, size, 
			      "Type-Data (%d byte%s) Value: %s",
			      size, plurality(size, "", "s"),
			      tvb_bytes_to_str(tvb, offset, size));
	}
	break;
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
  };
  static gint *ett[] = {
	&ett_eap,
  };

  proto_eap = proto_register_protocol("Extensible Authentication Protocol", 
				      "EAP", "eap");
  proto_register_field_array(proto_eap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_init_routine(&eap_init_protocol);

  new_register_dissector("eap", dissect_eap, proto_eap);
  new_register_dissector("eap_fragment", dissect_eap_fragment, proto_eap);
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
