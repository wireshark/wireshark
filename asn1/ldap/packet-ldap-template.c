/* packet-ldap.c
 * Routines for ldap packet dissection
 *
 * See RFC 1777 (LDAP v2), RFC 2251 (LDAP v3), and RFC 2222 (SASL).
 *
 * $Id$
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

/*
 * This is not a complete implementation. It doesn't handle the full version 3, more specifically,
 * it handles only the commands of version 2, but any additional characteristics of the ver3 command are supported.
 * It's also missing extensible search filters.
 *
 * There should probably be alot more error checking, I simply assume that if we have a full packet, it will be a complete
 * and correct packet.
 *
 * AFAIK, it will handle all messages used by the OpenLDAP 1.2.9 server and libraries which was my goal. I do plan to add
 * the remaining commands as time permits but this is not a priority to me. Send me an email if you need it and I'll see what
 * I can do.
 *
 * Doug Nazar
 * nazard@dragoninc.on.ca
 */

/*
 * 11/11/2002 - Fixed problem when decoding LDAP with desegmentation enabled and the
 *              ASN.1 BER Universal Class Tag: "Sequence Of" header is encapsulated across 2
 *              TCP segments.
 *
 * Ronald W. Henderson
 * ronald.henderson@cognicaseusa.com
 */

/*
 * 20-JAN-2004 - added decoding of MS-CLDAP netlogon RPC
 *               using information from the SNIA 2003 conference paper :
 *               Active Directory Domain Controller Location Service
 *                    by Anthony Liguori
 * ronnie sahlberg
 */

/*
 * 17-DEC-2004 - added basic decoding for LDAP Controls
 * 20-DEC-2004 - added handling for GSS-API encrypted blobs
 *
 * Stefan Metzmacher <metze@samba.org>
 *
 * 15-NOV-2005 - Changed to use the asn2eth compiler
 * Anders Broman <anders.broman@ericsson.com>
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/emem.h>
#include <epan/oid_resolv.h>

#include "packet-frame.h"
#include "packet-ldap.h"

#include "packet-ber.h"
#include "packet-per.h"

#define PNAME  "Lightweight-Directory-Access-Protocol"
#define PSNAME "LDAP"
#define PFNAME "ldap"

static dissector_handle_t ldap_handle=NULL;

/* Initialize the protocol and registered fields */
static int ldap_tap = -1;
static int proto_ldap = -1;
static int proto_cldap = -1;

static int hf_ldap_sasl_buffer_length = -1;
static int hf_ldap_response_in = -1;
static int hf_ldap_response_to = -1;
static int hf_ldap_time = -1;

#include "packet-ldap-hf.c"

/* Initialize the subtree pointers */
static gint ett_ldap = -1;
static gint ett_ldap_msg = -1;
static gint ett_ldap_sasl_blob = -1;
static guint ett_ldap_payload = -1;

#include "packet-ldap-ett.c"

/* desegmentation of LDAP */
static gboolean ldap_desegment = TRUE;
static guint    ldap_tcp_port = 389;
static gboolean do_protocolop = FALSE;

#define TCP_PORT_LDAP			389
#define UDP_PORT_CLDAP			389
#define TCP_PORT_GLOBALCAT_LDAP         3268 /* Windows 2000 Global Catalog */

static dissector_handle_t gssapi_handle;
static dissector_handle_t gssapi_wrap_handle;


/* different types of rpc calls ontop of ms cldap */
#define	MSCLDAP_RPC_NETLOGON 	1

/* Message type Choice values */
static const value_string ldap_ProtocolOp_choice_vals[] = {
  {   0, "bindRequest" },
  {   1, "bindResponse" },
  {   2, "unbindRequest" },
  {   3, "searchRequest" },
  {   4, "searchResEntry" },
  {   5, "searchResDone" },
  {	  6, "searchResRef" },
  {   7, "modifyRequest" },
  {   8, "modifyResponse" },
  {   9, "addRequest" },
  {  10, "addResponse" },
  {  11, "delRequest" },
  {  12, "delResponse" },
  {  13, "modDNRequest" },
  {  14, "modDNResponse" },
  {  15, "compareRequest" },
  {  16, "compareResponse" },
  {  17, "abandonRequest" },
  {  18, "extendedReq" },
  {  19, "extendedResp" },
  { 0, NULL }
};
/*
 * Data structure attached to a conversation, giving authentication
 * information from a bind request.
 * We keep a linked list of them, so that we can free up all the
 * authentication mechanism strings.
 */
typedef struct ldap_conv_info_t {
  struct ldap_conv_info_t *next;
  guint auth_type;		/* authentication type */
  char *auth_mech;		/* authentication mechanism */
  guint32 first_auth_frame;	/* first frame that would use a security layer */
  GHashTable *unmatched;
  GHashTable *matched;
  gboolean is_mscldap;
  gboolean first_time;
  guint32  num_results;
} ldap_conv_info_t;
static ldap_conv_info_t *ldap_info_items;

static guint
ldap_info_hash_matched(gconstpointer k)
{
  const ldap_call_response_t *key = k;

  return key->messageId;
}

static gint
ldap_info_equal_matched(gconstpointer k1, gconstpointer k2)
{
  const ldap_call_response_t *key1 = k1;
  const ldap_call_response_t *key2 = k2;

  if( key1->req_frame && key2->req_frame && (key1->req_frame!=key2->req_frame) ){
    return 0;
  }
  /* a response may span multiple frames
  if( key1->rep_frame && key2->rep_frame && (key1->rep_frame!=key2->rep_frame) ){
    return 0;
  }
  */

  return key1->messageId==key2->messageId;
}

static guint
ldap_info_hash_unmatched(gconstpointer k)
{
  const ldap_call_response_t *key = k;

  return key->messageId;
}

static gint
ldap_info_equal_unmatched(gconstpointer k1, gconstpointer k2)
{
  const ldap_call_response_t *key1 = k1;
  const ldap_call_response_t *key2 = k2;

  return key1->messageId==key2->messageId;
}

/* Global variables */
char *mechanism = NULL;
static gint MessageID =-1;
static gint ProtocolOp = -1;
static gint result = 0;
static proto_item *ldm_tree = NULL; /* item to add text to */

static void ldap_do_protocolop(packet_info *pinfo)
{
  const gchar* valstr;

  if (do_protocolop)  {

    valstr = val_to_str(ProtocolOp, ldap_ProtocolOp_choice_vals, "Unknown (%%u)");

    if(check_col(pinfo->cinfo, COL_INFO))
      col_append_fstr(pinfo->cinfo, COL_INFO, "%s(%u) ", valstr, MessageID);

    if(ldm_tree)
      proto_item_append_text(ldm_tree, " %s(%d)", valstr, MessageID); 

    do_protocolop = FALSE;

  }
}

static ldap_call_response_t *
ldap_match_call_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint messageId, guint protocolOpTag)
{
  ldap_call_response_t lcr, *lcrp=NULL;
  ldap_conv_info_t *ldap_info = (ldap_conv_info_t *)pinfo->private_data;

  /* first see if we have already matched this */

      lcr.messageId=messageId;
      switch(protocolOpTag){
        case LDAP_REQ_BIND:
        case LDAP_REQ_SEARCH:
        case LDAP_REQ_MODIFY:
        case LDAP_REQ_ADD:
        case LDAP_REQ_DELETE:
        case LDAP_REQ_MODRDN:
        case LDAP_REQ_COMPARE:
          lcr.is_request=TRUE;
          lcr.req_frame=pinfo->fd->num;
          lcr.rep_frame=0;
          break;
        case LDAP_RES_BIND:
        case LDAP_RES_SEARCH_ENTRY:
        case LDAP_RES_SEARCH_REF:
        case LDAP_RES_SEARCH_RESULT:
        case LDAP_RES_MODIFY:
        case LDAP_RES_ADD:
        case LDAP_RES_DELETE:
        case LDAP_RES_MODRDN:
        case LDAP_RES_COMPARE:
          lcr.is_request=FALSE;
          lcr.req_frame=0;
          lcr.rep_frame=pinfo->fd->num;
          break;
      }
      lcrp=g_hash_table_lookup(ldap_info->matched, &lcr);

      if(lcrp){

        lcrp->is_request=lcr.is_request;

      } else {

		  /* we haven't found a match - try and match it up */

  switch(protocolOpTag){
      case LDAP_REQ_BIND:
      case LDAP_REQ_SEARCH:
      case LDAP_REQ_MODIFY:
      case LDAP_REQ_ADD:
      case LDAP_REQ_DELETE:
      case LDAP_REQ_MODRDN:
      case LDAP_REQ_COMPARE:

		/* this a a request - add it to the unmatched list */

        /* check that we dont already have one of those in the
           unmatched list and if so remove it */

        lcr.messageId=messageId;
        lcrp=g_hash_table_lookup(ldap_info->unmatched, &lcr);
        if(lcrp){
          g_hash_table_remove(ldap_info->unmatched, lcrp);
        }
        /* if we cant reuse the old one, grab a new chunk */
        if(!lcrp){
          lcrp=se_alloc(sizeof(ldap_call_response_t));
        }
        lcrp->messageId=messageId;
        lcrp->req_frame=pinfo->fd->num;
        lcrp->req_time=pinfo->fd->abs_ts;
        lcrp->rep_frame=0;
        lcrp->protocolOpTag=protocolOpTag;
        lcrp->is_request=TRUE;
        g_hash_table_insert(ldap_info->unmatched, lcrp, lcrp);
        return NULL;
        break;
      case LDAP_RES_BIND:
      case LDAP_RES_SEARCH_ENTRY:
      case LDAP_RES_SEARCH_REF:
      case LDAP_RES_SEARCH_RESULT:
      case LDAP_RES_MODIFY:
      case LDAP_RES_ADD:
      case LDAP_RES_DELETE:
      case LDAP_RES_MODRDN:
      case LDAP_RES_COMPARE:

		/* this is a result - it should be in our unmatched list */

        lcr.messageId=messageId;
        lcrp=g_hash_table_lookup(ldap_info->unmatched, &lcr);

        if(lcrp){

          if(!lcrp->rep_frame){
            g_hash_table_remove(ldap_info->unmatched, lcrp);
            lcrp->rep_frame=pinfo->fd->num;
            lcrp->is_request=FALSE;
            g_hash_table_insert(ldap_info->matched, lcrp, lcrp);
          }
        }

        break;
	  }

	}
    /* we have found a match */

    if(lcrp){
      if(lcrp->is_request){
        proto_tree_add_uint(tree, hf_ldap_response_in, tvb, 0, 0, lcrp->rep_frame);
      } else {
        nstime_t ns;
        proto_tree_add_uint(tree, hf_ldap_response_to, tvb, 0, 0, lcrp->req_frame);
        nstime_delta(&ns, &pinfo->fd->abs_ts, &lcrp->req_time);
        proto_tree_add_time(tree, hf_ldap_time, tvb, 0, 0, &ns);
      }
    }

    return lcrp;
}

#include "packet-ldap-fn.c"

static void
dissect_ldap_payload(tvbuff_t *tvb, packet_info *pinfo,
		     proto_tree *tree, ldap_conv_info_t *ldap_info,
		     gboolean rest_is_pad, gboolean is_mscldap)
{
  int offset = 0;
  gboolean first_time = TRUE;
  guint length_remaining;
  guint msg_len = 0;
  int messageOffset = 0;
  guint headerLength = 0;
  guint length = 0;
  tvbuff_t *msg_tvb = NULL;
  gint8 class;
  gboolean pc, ind = 0;
  gint32 ber_tag;

  while (tvb_reported_length_remaining(tvb, offset) > 0) {
    /*
     * This will throw an exception if we don't have any data left.
     * That's what we want.  (See "tcp_dissect_pdus()", which is
     * similar)
     */
    length_remaining = tvb_ensure_length_remaining(tvb, offset);

    if (rest_is_pad && length_remaining < 6) return;

    /*
     * The frame begins
     * with a "Sequence Of" header.
     * Can we do reassembly?
     */
    if (ldap_desegment && pinfo->can_desegment) {
        /*
         * Yes - is the "Sequence Of" header split across segment
         * boundaries?  We require at least 6 bytes for the header
         * which allows for a 4 byte length (ASN.1 BER).
         */
        if (length_remaining < 6) {
	  /* stop if the caller says that we are given all data and the rest is padding
	   * this is for the SASL GSSAPI case when the data is only signed and not sealed
	   */
          pinfo->desegment_offset = offset;
          pinfo->desegment_len = 6 - length_remaining;
          return;
        }
    }

    /*
     * OK, try to read the "Sequence Of" header; this gets the total
     * length of the LDAP message.
     */
	messageOffset = get_ber_identifier(tvb, offset, &class, &pc, &ber_tag);
	messageOffset = get_ber_length(tree, tvb, messageOffset, &msg_len, &ind);

    if (ber_tag == BER_UNI_TAG_SEQUENCE) {
      	/*
      	 * Add the length of the "Sequence Of" header to the message
      	 * length.
      	 */
      	headerLength = messageOffset - offset;
      	msg_len += headerLength;
        if (msg_len < headerLength) {
    	    /*
    	     * The message length was probably so large that the total length
    	     * overflowed.
    	     *
    	     * Report this as an error.
    	     */
    	    show_reported_bounds_error(tvb, pinfo, tree);
    	    return;
        }
    } else {
      	/*
      	 * We couldn't parse the header; just make it the amount of data
      	 * remaining in the tvbuff, so we'll give up on this segment
      	 * after attempting to parse the message - there's nothing more
      	 * we can do.  "dissect_ldap_message()" will display the error.
      	 */
      	msg_len = length_remaining;
    }

    /*
     * Is the message split across segment boundaries?
     */
    if (length_remaining < msg_len) {
        /* provide a hint to TCP where the next PDU starts */
        pinfo->want_pdu_tracking=2;
        pinfo->bytes_until_next_pdu= msg_len - length_remaining;
        /*
         * Can we do reassembly?
         */
        if (ldap_desegment && pinfo->can_desegment) {
	    /*
	     * Yes.  Tell the TCP dissector where the data for this message
	     * starts in the data it handed us, and how many more bytes
	     * we need, and return.
	     */
	    pinfo->desegment_offset = offset;
	    pinfo->desegment_len = msg_len - length_remaining;

	    return;
        }
    }

    /*
     * Construct a tvbuff containing the amount of the payload we have
     * available.  Make its reported length the amount of data in the
     * LDAP message.
     *
     * XXX - if reassembly isn't enabled. the subdissector will throw a
     * BoundsError exception, rather than a ReportedBoundsError exception.
     * We really want a tvbuff where the length is "length", the reported
     * length is "plen", and the "if the snapshot length were infinite"
     * length is the minimum of the reported length of the tvbuff handed
     * to us and "plen", with a new type of exception thrown if the offset
     * is within the reported length but beyond that third length, with
     * that exception getting the "Unreassembled Packet" error.
     */
    length = length_remaining;
    if (length > msg_len) length = msg_len;
    msg_tvb = tvb_new_subset(tvb, offset, length, msg_len);

    /*
     * Now dissect the LDAP message.
     */

    /*dissect_ldap_message(msg_tvb, 0, pinfo, msg_tree, msg_item, first_time, ldap_info, is_mscldap);*/
	ldap_info->first_time= first_time;
	ldap_info->is_mscldap = is_mscldap;
	pinfo->private_data = ldap_info;
	dissect_LDAPMessage_PDU(msg_tvb, pinfo, tree);


    offset += msg_len;

    first_time = FALSE;
  }
}

static void
dissect_ldap_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean is_mscldap)
{
  int offset = 0;
  conversation_t *conversation;
  gboolean doing_sasl_security = FALSE;
  guint length_remaining;
  ldap_conv_info_t *ldap_info = NULL;
  proto_item *ldap_item = NULL;
  proto_tree *ldap_tree = NULL;

  /*
   * Do we have a conversation for this connection?
   */
  conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                   pinfo->ptype, pinfo->srcport,
                                   pinfo->destport, 0);
  if (conversation == NULL) {
    /* We don't yet have a conversation, so create one. */
    conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst,
    	                    	    pinfo->ptype, pinfo->srcport,
                                    pinfo->destport, 0);

  }

  /*
   * Do we already have a type and mechanism?
   */
  ldap_info = conversation_get_proto_data(conversation, proto_ldap);
  if (ldap_info == NULL) {
    /* No.  Attach that information to the conversation, and add
     * it to the list of information structures.
     */
    ldap_info = se_alloc(sizeof(ldap_conv_info_t));
    ldap_info->auth_type = 0;
    ldap_info->auth_mech = 0;
    ldap_info->first_auth_frame = 0;
    ldap_info->matched=g_hash_table_new(ldap_info_hash_matched, ldap_info_equal_matched);
    ldap_info->unmatched=g_hash_table_new(ldap_info_hash_unmatched, ldap_info_equal_unmatched);
    ldap_info->num_results = 0;

    conversation_add_proto_data(conversation, proto_ldap, ldap_info);

    ldap_info->next = ldap_info_items;
    ldap_info_items = ldap_info;

  }

  switch (ldap_info->auth_type) {
    case LDAP_AUTH_SASL:
    /*
     * It's SASL; are we using a security layer?
     */
    if (ldap_info->first_auth_frame != 0 &&
       pinfo->fd->num >= ldap_info->first_auth_frame) {
	doing_sasl_security = TRUE;	/* yes */
    }
  }

  while (tvb_reported_length_remaining(tvb, offset) > 0) {

    /*
     * This will throw an exception if we don't have any data left.
     * That's what we want.  (See "tcp_dissect_pdus()", which is
     * similar, but doesn't have to deal with the SASL issues.
     * XXX - can we make "tcp_dissect_pdus()" provide enough information
     * to the "get_pdu_len" routine so that we could have one dealing
     * with the SASL issues, have that routine deal with SASL and
     * ASN.1, and just use "tcp_dissect_pdus()"?)
     */
    length_remaining = tvb_ensure_length_remaining(tvb, offset);

    /*
     * Try to find out if we have a plain LDAP buffer
     * with a "Sequence Of" header or a SASL buffer with
     * Can we do reassembly?
     */
    if (ldap_desegment && pinfo->can_desegment) {
        /*
         * Yes - is the "Sequence Of" header split across segment
         * boundaries?  We require at least 6 bytes for the header
         * which allows for a 4 byte length (ASN.1 BER).
	 * For the SASL case we need at least 4 bytes, so this is
	 * no problem here because we check for 6 bytes ans sasl buffers
	 * with less than 2 bytes should not exist...
         */
        if (length_remaining < 6) {
    	    pinfo->desegment_offset = offset;
    	    pinfo->desegment_len = 6 - length_remaining;
    	    return;
        }
    }

    /* It might still be a packet containing a SASL security layer
     * but its just that we never saw the BIND packet.
     * check if it looks like it could be a SASL blob here
     * and in that case just assume it is GSS-SPNEGO
     */
    if(!doing_sasl_security && (tvb_bytes_exist(tvb, offset, 5))
      &&(tvb_get_ntohl(tvb, offset)<=(guint)(tvb_reported_length_remaining(tvb, offset)-4))
      &&(tvb_get_guint8(tvb, offset+4)==0x60) ){
        ldap_info->auth_type=LDAP_AUTH_SASL;
        ldap_info->first_auth_frame=pinfo->fd->num;
        ldap_info->auth_mech=g_strdup("GSS-SPNEGO");
        doing_sasl_security=TRUE;
    }

    /*
     * This is the first PDU, set the Protocol column and clear the
     * Info column.
     */
    if (check_col(pinfo->cinfo, COL_PROTOCOL)) col_set_str(pinfo->cinfo, COL_PROTOCOL, pinfo->current_proto);
    if (check_col(pinfo->cinfo, COL_INFO)) col_clear(pinfo->cinfo, COL_INFO);

    ldap_item = proto_tree_add_item(tree, proto_ldap, tvb, 0, -1, FALSE);
    ldap_tree = proto_item_add_subtree(ldap_item, ett_ldap);

    /*
     * Might we be doing a SASL security layer and, if so, *are* we doing
     * one?
     *
     * Just because we've seen a bind reply for SASL, that doesn't mean
     * that we're using a SASL security layer; I've seen captures in
     * which some SASL negotiations lead to a security layer being used
     * and other negotiations don't, and it's not obvious what's different
     * in the two negotiations.  Therefore, we assume that if the first
     * byte is 0, it's a length for a SASL security layer (that way, we
     * never reassemble more than 16 megabytes, protecting us from
     * chewing up *too* much memory), and otherwise that it's an LDAP
     * message (actually, if it's an LDAP message it should begin with 0x30,
     * but we want to parse garbage as LDAP messages rather than really
     * huge lengths).
     */

    if (doing_sasl_security && tvb_get_guint8(tvb, offset) == 0) {
      proto_item *sasl_item = NULL;
      proto_tree *sasl_tree = NULL;
      tvbuff_t *sasl_tvb;
      guint sasl_len, sasl_msg_len, length;
      /*
       * Yes.  The frame begins with a 4-byte big-endian length.
       * And we know we have at least 6 bytes
       */

      /*
       * Get the SASL length, which is the length of data in the buffer
       * following the length (i.e., it's 4 less than the total length).
       *
       * XXX - do we need to reassemble buffers?  For now, we
       * assume that each LDAP message is entirely contained within
       * a buffer.
       */
      sasl_len = tvb_get_ntohl(tvb, offset);
      sasl_msg_len = sasl_len + 4;
      if (sasl_msg_len < 4) {
        /*
         * The message length was probably so large that the total length
	 * overflowed.
         *
         * Report this as an error.
         */
        show_reported_bounds_error(tvb, pinfo, tree);
        return;
      }

      /*
       * Is the buffer split across segment boundaries?
       */
      if (length_remaining < sasl_msg_len) {
        /* provide a hint to TCP where the next PDU starts */
        pinfo->want_pdu_tracking = 2;
        pinfo->bytes_until_next_pdu= sasl_msg_len - length_remaining;
        /*
         * Can we do reassembly?
         */
        if (ldap_desegment && pinfo->can_desegment) {
          /*
           * Yes.  Tell the TCP dissector where the data for this message
           * starts in the data it handed us, and how many more bytes we
           * need, and return.
           */
          pinfo->desegment_offset = offset;
          pinfo->desegment_len = sasl_msg_len - length_remaining;
          return;
        }
      }

      /*
       * Construct a tvbuff containing the amount of the payload we have
       * available.  Make its reported length the amount of data in the PDU.
       *
       * XXX - if reassembly isn't enabled. the subdissector will throw a
       * BoundsError exception, rather than a ReportedBoundsError exception.
       * We really want a tvbuff where the length is "length", the reported
       * length is "plen", and the "if the snapshot length were infinite"
       * length is the minimum of the reported length of the tvbuff handed
       * to us and "plen", with a new type of exception thrown if the offset
       * is within the reported length but beyond that third length, with
       * that exception getting the "Unreassembled Packet" error.
       */
      length = length_remaining;
      if (length > sasl_msg_len) length = sasl_msg_len;
      sasl_tvb = tvb_new_subset(tvb, offset, length, sasl_msg_len);

      if (ldap_tree) {
        proto_tree_add_uint(ldap_tree, hf_ldap_sasl_buffer_length, sasl_tvb, 0, 4,
                            sasl_len);

        sasl_item = proto_tree_add_text(ldap_tree, sasl_tvb, 0,  sasl_msg_len, "SASL buffer");
        sasl_tree = proto_item_add_subtree(sasl_item, ett_ldap_sasl_blob);
      }

      if (ldap_info->auth_mech != NULL &&
          strcmp(ldap_info->auth_mech, "GSS-SPNEGO") == 0) {
	  tvbuff_t *gssapi_tvb, *plain_tvb = NULL, *decr_tvb= NULL;
	  int ver_len;
	  int length;

          /*
           * This is GSS-API (using SPNEGO, but we should be done with
           * the negotiation by now).
           *
           * Dissect the GSS_Wrap() token; it'll return the length of
           * the token, from which we compute the offset in the tvbuff at
           * which the plaintext data, i.e. the LDAP message, begins.
           */
          length = tvb_length_remaining(sasl_tvb, 4);
          if ((guint)length > sasl_len)
              length = sasl_len;
	  gssapi_tvb = tvb_new_subset(sasl_tvb, 4, length, sasl_len);

	  /* Attempt decryption of the GSSAPI wrapped data if possible */
	  pinfo->decrypt_gssapi_tvb=DECRYPT_GSSAPI_NORMAL;
	  pinfo->gssapi_wrap_tvb=NULL;
	  pinfo->gssapi_encrypted_tvb=NULL;
	  pinfo->gssapi_decrypted_tvb=NULL;
          ver_len = call_dissector(gssapi_wrap_handle, gssapi_tvb, pinfo, sasl_tree);
	  /* if we could unwrap, do a tvb shuffle */
	  if(pinfo->gssapi_decrypted_tvb){
		decr_tvb=pinfo->gssapi_decrypted_tvb;
	  }
	  /* tidy up */
	  pinfo->decrypt_gssapi_tvb=0;
	  pinfo->gssapi_wrap_tvb=NULL;
	  pinfo->gssapi_encrypted_tvb=NULL;
	  pinfo->gssapi_decrypted_tvb=NULL;

          /*
           * if len is 0 it probably mean that we got a PDU that is not
           * aligned to the start of the segment.
           */
          if(ver_len==0){
             return;
          }

	  /*
	   * if we don't have unwrapped data,
	   * see if the wrapping involved encryption of the
	   * data; if not, just use the plaintext data.
	   */
	  if (!decr_tvb) {
	    if(!pinfo->gssapi_data_encrypted){
	      plain_tvb = tvb_new_subset(gssapi_tvb,  ver_len, -1, -1);
	    }
	  }

          if (decr_tvb) {
	    proto_item *enc_item = NULL;
	    proto_tree *enc_tree = NULL;

            /*
             * The LDAP message was encrypted in the packet, and has
             * been decrypted; dissect the decrypted LDAP message.
             */
            if (sasl_tree) {
	      enc_item = proto_tree_add_text(sasl_tree, gssapi_tvb, ver_len, -1,
                                "GSS-API Encrypted payload (%d byte%s)",
                                sasl_len - ver_len,
                                plurality(sasl_len - ver_len, "", "s"));
	      enc_tree = proto_item_add_subtree(enc_item, ett_ldap_payload);
            }
	    dissect_ldap_payload(decr_tvb, pinfo, enc_tree, ldap_info, TRUE, is_mscldap);
          } else if (plain_tvb) {
	    proto_item *plain_item = NULL;
	    proto_tree *plain_tree = NULL;

	    /*
	     * The LDAP message wasn't encrypted in the packet;
	     * dissect the plain LDAP message.
             */
	    if (sasl_tree) {
              plain_item = proto_tree_add_text(sasl_tree, gssapi_tvb, ver_len, -1,
                                "GSS-API payload (%d byte%s)",
                                sasl_len - ver_len,
                                plurality(sasl_len - ver_len, "", "s"));
	      plain_tree = proto_item_add_subtree(plain_item, ett_ldap_payload);
            }

           dissect_ldap_payload(plain_tvb, pinfo, plain_tree, ldap_info, TRUE, is_mscldap);
	  } else {
            /*
             * The LDAP message was encrypted in the packet, and was
             * not decrypted; just show it as encrypted data.
             */
            if (check_col(pinfo->cinfo, COL_INFO)) {
        	    col_add_fstr(pinfo->cinfo, COL_INFO, "LDAP GSS-API Encrypted payload (%d byte%s)",
                                 sasl_len - ver_len,
                                 plurality(sasl_len - ver_len, "", "s"));
            }
	    if (sasl_tree) {
              proto_tree_add_text(sasl_tree, gssapi_tvb, ver_len, -1,
                                "GSS-API Encrypted payload (%d byte%s)",
                                sasl_len - ver_len,
                                plurality(sasl_len - ver_len, "", "s"));
	    }
          }
      }
      offset += sasl_msg_len;
    } else {
	/* plain LDAP, so dissect the payload */
	dissect_ldap_payload(tvb, pinfo, ldap_tree, ldap_info, FALSE, is_mscldap);
	/* dissect_ldap_payload() has it's own loop so go out here */
	break;
    }
  }
}
static void
dissect_ldap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_ldap_pdu(tvb, pinfo, tree, FALSE);
	return;
}

static void
dissect_mscldap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_ldap_pdu(tvb, pinfo, tree, TRUE);
	return;
}


static void
ldap_reinit(void)
{
  ldap_conv_info_t *ldap_info;

  /* Free up state attached to the ldap_info structures */
  for (ldap_info = ldap_info_items; ldap_info != NULL; ldap_info = ldap_info->next) {
    if (ldap_info->auth_mech != NULL) {
      g_free(ldap_info->auth_mech);
      ldap_info->auth_mech=NULL;
    }
    g_hash_table_destroy(ldap_info->matched);
    ldap_info->matched=NULL;
    g_hash_table_destroy(ldap_info->unmatched);
    ldap_info->unmatched=NULL;
  }

  ldap_info_items = NULL;

}
/*--- proto_register_ldap -------------------------------------------*/
void proto_register_ldap(void) {

  /* List of fields */

  static hf_register_info hf[] = {

	  	{ &hf_ldap_sasl_buffer_length,
		  { "SASL Buffer Length",	"ldap.sasl_buffer_length",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"SASL Buffer Length", HFILL }},
	    { &hf_ldap_response_in,
	      { "Response In", "ldap.response_in",
	        FT_FRAMENUM, BASE_DEC, NULL, 0x0,
	        "The response to this LDAP request is in this frame", HFILL }},
	    { &hf_ldap_response_to,
	      { "Response To", "ldap.response_to",
	        FT_FRAMENUM, BASE_DEC, NULL, 0x0,
	        "This is a response to the LDAP request in this frame", HFILL }},
	    { &hf_ldap_time,
	      { "Time", "ldap.time",
	        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
	        "The time between the Call and the Reply", HFILL }},

#include "packet-ldap-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_ldap,
	&ett_ldap_payload,
    &ett_ldap_sasl_blob,
	&ett_ldap_msg,

#include "packet-ldap-ettarr.c"
  };

    module_t *ldap_module;

  /* Register protocol */
  proto_ldap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_ldap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));


  register_dissector("ldap", dissect_ldap, proto_ldap);

  ldap_module = prefs_register_protocol(proto_ldap, NULL);
  prefs_register_bool_preference(ldap_module, "desegment_ldap_messages",
    "Reassemble LDAP messages spanning multiple TCP segments",
    "Whether the LDAP dissector should reassemble messages spanning multiple TCP segments."
    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings, and disable \"Verify length\" in the BER protocol settings",
    &ldap_desegment);

  prefs_register_uint_preference(ldap_module, "tcp.port", "LDAP TCP Port",
				 "Set the port for LDAP operations",
				 10, &ldap_tcp_port);

  proto_cldap = proto_register_protocol(
	  "Connectionless Lightweight Directory Access Protocol",
	  "CLDAP", "cldap");

  register_init_routine(ldap_reinit);
  ldap_tap=register_tap("ldap");

}


/*--- proto_reg_handoff_ldap ---------------------------------------*/
void
proto_reg_handoff_ldap(void)
{
	dissector_handle_t ldap_handle, cldap_handle;
	ldap_handle = create_dissector_handle(dissect_ldap, proto_ldap);

	dissector_add("tcp.port", ldap_tcp_port, ldap_handle);
	dissector_add("tcp.port", TCP_PORT_GLOBALCAT_LDAP, ldap_handle);

	cldap_handle = create_dissector_handle(dissect_mscldap, proto_cldap);
	dissector_add("udp.port", UDP_PORT_CLDAP, cldap_handle);

	gssapi_handle = find_dissector("gssapi");
	gssapi_wrap_handle = find_dissector("gssapi_verf");

/*  http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dsml/dsml/ldap_controls_and_session_support.asp */
	register_ber_oid_name("1.2.840.113556.1.4.319","LDAP_PAGED_RESULT_OID_STRING");
	register_ber_oid_name("1.2.840.113556.1.4.417","LDAP_SERVER_SHOW_DELETED_OID");
	register_ber_oid_name("1.2.840.113556.1.4.473","LDAP_SERVER_SORT_OID");
	register_ber_oid_name("1.2.840.113556.1.4.521","LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID");
	register_ber_oid_name("1.2.840.113556.1.4.528","LDAP_SERVER_NOTIFICATION_OID");
	register_ber_oid_name("1.2.840.113556.1.4.529","LDAP_SERVER_EXTENDED_DN_OID");
	register_ber_oid_name("1.2.840.113556.1.4.619","LDAP_SERVER_LAZY_COMMIT_OID");
	register_ber_oid_name("1.2.840.113556.1.4.801","LDAP_SERVER_SD_FLAGS_OID");
	register_ber_oid_name("1.2.840.113556.1.4.805","LDAP_SERVER_TREE_DELETE_OID");
	register_ber_oid_name("1.2.840.113556.1.4.841","LDAP_SERVER_DIRSYNC_OID");
	register_ber_oid_name("1.2.840.113556.1.4.970 ","None");
	register_ber_oid_name("1.2.840.113556.1.4.1338","LDAP_SERVER_VERIFY_NAME_OID");
	register_ber_oid_name("1.2.840.113556.1.4.1339","LDAP_SERVER_DOMAIN_SCOPE_OID");
	register_ber_oid_name("1.2.840.113556.1.4.1340","LDAP_SERVER_SEARCH_OPTIONS_OID");
	register_ber_oid_name("1.2.840.113556.1.4.1413","LDAP_SERVER_PERMISSIVE_MODIFY_OID");
	register_ber_oid_name("1.2.840.113556.1.4.1504","LDAP_SERVER_ASQ_OID");
	register_ber_oid_name("1.2.840.113556.1.4.1781","LDAP_SERVER_FAST_BIND_OID");
	register_ber_oid_name("1.3.6.1.4.1.1466.101.119.1","None");
	register_ber_oid_name("1.3.6.1.4.1.1466.20037","LDAP_START_TLS_OID");
	register_ber_oid_name("2.16.840.1.113730.3.4.9","LDAP_CONTROL_VLVREQUEST VLV");


}


