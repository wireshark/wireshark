/* packet-spnego.c
 * Routines for the simple and protected GSS-API negotiation mechanism
 * as described in RFC 2478.
 * Copyright 2002, Tim Potter <tpot@samba.org>
 * Copyright 2002, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id: packet-spnego.c,v 1.43 2003/05/23 17:46:06 sharpe Exp $
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

#include <glib.h>
#include <epan/packet.h>

#include "asn1.h"
#include "format-oid.h"
#include "packet-gssapi.h"
#include "packet-kerberos.h"
#include <epan/conversation.h>

#define SPNEGO_negTokenInit 0
#define SPNEGO_negTokenTarg 1
#define SPNEGO_mechTypes 0
#define SPNEGO_reqFlags 1
#define SPNEGO_mechToken 2
#define SPNEGO_mechListMIC 3
#define SPNEGO_negResult 0
#define SPNEGO_supportedMech 1
#define SPNEGO_responseToken 2
#define SPNEGO_negResult_accept_completed 0
#define SPNEGO_negResult_accept_incomplete 1
#define SPNEGO_negResult_accept_reject 2

static int proto_spnego = -1;
static int proto_spnego_krb5 = -1;

static int hf_spnego = -1;
static int hf_spnego_negtokeninit = -1;
static int hf_spnego_negtokentarg = -1;
static int hf_spnego_mechtype = -1;
static int hf_spnego_mechtoken = -1;
static int hf_spnego_negtokentarg_negresult = -1;
static int hf_spnego_mechlistmic = -1;
static int hf_spnego_responsetoken = -1;
static int hf_spnego_reqflags = -1;
static int hf_spnego_wraptoken = -1;
static int hf_spnego_krb5 = -1;
static int hf_spnego_krb5_tok_id = -1;
static int hf_spnego_krb5_sgn_alg = -1;
static int hf_spnego_krb5_seal_alg = -1;
static int hf_spnego_krb5_snd_seq = -1;
static int hf_spnego_krb5_sgn_cksum = -1;
static int hf_spnego_krb5_confounder = -1;

static gint ett_spnego = -1;
static gint ett_spnego_negtokeninit = -1;
static gint ett_spnego_negtokentarg = -1;
static gint ett_spnego_mechtype = -1;
static gint ett_spnego_mechtoken = -1;
static gint ett_spnego_mechlistmic = -1;
static gint ett_spnego_responsetoken = -1;
static gint ett_spnego_wraptoken = -1;
static gint ett_spnego_krb5 = -1;

static const value_string spnego_negResult_vals[] = {
  { SPNEGO_negResult_accept_completed,   "Accept Completed" },
  { SPNEGO_negResult_accept_incomplete,  "Accept Incomplete" },
  { SPNEGO_negResult_accept_reject,      "Accept Reject"},
  { 0, NULL}
};

/* Display an ASN1 parse error.  Taken from packet-snmp.c */

static dissector_handle_t data_handle;

static void
dissect_parse_error(tvbuff_t *tvb, int offset, packet_info *pinfo,
		    proto_tree *tree, const char *field_name, int ret)
{
	char *errstr;

	errstr = asn1_err_to_str(ret);

	if (tree != NULL) {
		proto_tree_add_text(tree, tvb, offset, 0,
		    "ERROR: Couldn't parse %s: %s", field_name, errstr);
		call_dissector(data_handle,
		    tvb_new_subset(tvb, offset, -1, -1), pinfo, tree);
	}
}

/*
 * This is the SPNEGO KRB5 dissector. It is not true KRB5, but some ASN.1
 * wrapped blob with an OID, USHORT token ID, and a Ticket, that is also 
 * ASN.1 wrapped by the looks of it. It conforms to RFC1964.
 */ 

#define KRB_TOKEN_AP_REQ		0x0001
#define KRB_TOKEN_AP_REP		0x0002
#define KRB_TOKEN_AP_ERR		0x0003
#define KRB_TOKEN_GETMIC		0x0101
#define KRB_TOKEN_WRAP			0x0102
#define KRB_TOKEN_DELETE_SEC_CONTEXT	0x0201

static const value_string spnego_krb5_tok_id_vals[] = {
  { KRB_TOKEN_AP_REQ,             "KRB5_AP_REQ"},
  { KRB_TOKEN_AP_REP,             "KRB5_AP_REP"},
  { KRB_TOKEN_AP_ERR,             "KRB5_ERROR"},
  { KRB_TOKEN_GETMIC,             "KRB5_GSS_GetMIC" },
  { KRB_TOKEN_WRAP,               "KRB5_GSS_Wrap" },
  { KRB_TOKEN_DELETE_SEC_CONTEXT, "KRB5_GSS_Delete_sec_context" },
  { 0, NULL}
};

#define KRB_SGN_ALG_DES_MAC_MD5	0x0000
#define KRB_SGN_ALG_MD2_5	0x0001
#define KRB_SGN_ALG_DES_MAC	0x0002
#define KRB_SGN_ALG_HMAC	0x0011

static const value_string spnego_krb5_sgn_alg_vals[] = {
  { KRB_SGN_ALG_DES_MAC_MD5, "DES MAC MD5"},
  { KRB_SGN_ALG_MD2_5,       "MD2.5"},
  { KRB_SGN_ALG_DES_MAC,     "DES MAC"},
  { KRB_SGN_ALG_HMAC,        "HMAC"},
  { 0, NULL}
};

#define KRB_SEAL_ALG_DES_CBC	0x0000
#define KRB_SEAL_ALG_RC4	0x0010
#define KRB_SEAL_ALG_NONE	0xffff

static const value_string spnego_krb5_seal_alg_vals[] = {
  { KRB_SEAL_ALG_DES_CBC, "DES CBC"},
  { KRB_SEAL_ALG_RC4,     "RC4"},
  { KRB_SEAL_ALG_NONE,    "None"},
  { 0, NULL}
};

/*
 * XXX - is this for SPNEGO or just GSS-API?
 * RFC 1964 is "The Kerberos Version 5 GSS-API Mechanism"; presumably one
 * can directly designate Kerberos V5 as a mechanism in GSS-API, rather
 * than designating SPNEGO as the mechanism, offering Kerberos V5, and
 * getting it accepted.
 */
static void
dissect_spnego_krb5(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *item;
	proto_tree *subtree;
	int ret, offset = 0;
	ASN1_SCK hnd;
	gboolean def;
	guint len1, cls, con, tag, oid_len, nbytes;
	guint16 token_id = 0;
	subid_t *oid;
	gchar *oid_string;
	gssapi_oid_value *value;
	tvbuff_t *krb5_tvb;

	item = proto_tree_add_item(tree, hf_spnego_krb5, tvb, offset, 
				   -1, FALSE);

	subtree = proto_item_add_subtree(item, ett_spnego_krb5);

	/*
	 * The KRB5 blob conforms to RFC1964:
	 * [APPLICATION 0] {
	 *   OID,
	 *   USHORT (0x0001 == AP-REQ, 0x0002 == AP-REP, 0x0003 == ERROR),
	 *   OCTET STRING } 
         *
         * However, for some protocols, the KRB5 blob starts at the SHORT
	 * and has no DER encoded header etc.
	 *
	 * It appears that for some other protocols the KRB5 blob is just
	 * a Kerberos message, with no [APPLICATION 0] header, no OID,
	 * and no USHORT.
	 *
	 * So:
	 *
	 *	If we see an [APPLICATION 0] HEADER, we show the OID and
	 *	the USHORT, and then dissect the rest as a Kerberos message.
	 *
	 *	If we see an [APPLICATION 14] or [APPLICATION 15] header,
	 *	we assume it's an AP-REQ or AP-REP message, and dissect
	 *	it all as a Kerberos message.
	 *
	 *	Otherwise, we show the USHORT, and then dissect the rest
	 *	as a Kerberos message.
	 */

	asn1_open(&hnd, tvb, offset);

	/*
	 * Get the first header ...
	 */

	ret = asn1_header_decode(&hnd, &cls, &con, &tag, &def, &len1);

	if (ret != ASN1_ERR_NOERROR) {
		dissect_parse_error(tvb, offset, pinfo, subtree,
				    "SPNEGO KRB5 Header", ret);
		goto done;
	}

	if (cls == ASN1_APL && con == ASN1_CON) {
	    /*
	     * [APPLICATION <tag>]
	     */
	    switch (tag) {

	    case 0:
		/*
		 * [APPLICATION 0]
		 */

		offset = hnd.offset;

		/* Next, the OID */

		ret = asn1_oid_decode(&hnd, &oid, &oid_len, &nbytes);

		if (ret != ASN1_ERR_NOERROR) {
		    dissect_parse_error(tvb, offset, pinfo, subtree,
			 	        "SPNEGO supportedMech token", ret);
		    goto done;
		}

		oid_string = format_oid(oid, oid_len);

		value = gssapi_lookup_oid(oid, oid_len);

		if (value) 
		    proto_tree_add_text(subtree, tvb, offset, nbytes, 
					"OID: %s (%s)",
					oid_string, value->comment);
		else
		    proto_tree_add_text(subtree, tvb, offset, nbytes,
					"OID: %s",
					oid_string);
	  
		g_free(oid_string);

		offset += nbytes;

		/* Next, the token ID ... */

		token_id = tvb_get_letohs(tvb, offset);
		proto_tree_add_item(subtree, hf_spnego_krb5_tok_id, tvb, offset, 2,
				    TRUE);

		hnd.offset += 2;

		offset += 2;

		break;

	    case 14:	/* [APPLICATION 14] */
	    case 15:	/* [APPLICATION 15] */
		break;

	    default:
		proto_tree_add_text(subtree, tvb, offset, 0,
			"Unknown header (cls=%d, con=%d, tag=%d)",
			cls, con, tag);
		goto done;
	    }
	} else {
	    /* Next, the token ID ... */

	    token_id = tvb_get_letohs(tvb, offset);
	    proto_tree_add_item(subtree, hf_spnego_krb5_tok_id, tvb, offset, 2,
				TRUE);

	    hnd.offset += 2;

	    offset += 2;
	}

	switch (token_id) {

	case KRB_TOKEN_AP_REQ:
	case KRB_TOKEN_AP_REP:
	case KRB_TOKEN_AP_ERR:
	  krb5_tvb = tvb_new_subset(tvb, offset, -1, -1); 
	  offset = dissect_kerberos_main(krb5_tvb, pinfo, subtree, FALSE);
	  break;

	case KRB_TOKEN_GETMIC:

	  break;

	case KRB_TOKEN_WRAP:

	  break;

	case KRB_TOKEN_DELETE_SEC_CONTEXT:

	  break;

	default:

	  break;
	}

 done:
	return;
}

/*
 * XXX - is this for SPNEGO or just GSS-API?
 * RFC 1964 is "The Kerberos Version 5 GSS-API Mechanism"; presumably one
 * can directly designate Kerberos V5 as a mechanism in GSS-API, rather
 * than designating SPNEGO as the mechanism, offering Kerberos V5, and
 * getting it accepted.
 */
static int
dissect_spnego_krb5_wrap(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item *item;
	proto_tree *subtree;
	int offset = 0;
	guint16 sgn_alg;

	item = proto_tree_add_item(tree, hf_spnego_krb5, tvb, 0, -1, FALSE);

	subtree = proto_item_add_subtree(item, ett_spnego_krb5);

	/*
	 * The KRB5 blob conforms to RFC1964:
	 *   USHORT (0x0102 == GSS_Wrap)
	 *   and so on } 
	 */

	/* First, the token ID ... */

	proto_tree_add_item(subtree, hf_spnego_krb5_tok_id, tvb, offset, 2,
			    TRUE);

	offset += 2;

	/* Now, the sign and seal algorithms ... */

	sgn_alg = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(subtree, hf_spnego_krb5_sgn_alg, tvb, offset, 2,
			    sgn_alg);

	offset += 2;

	proto_tree_add_item(subtree, hf_spnego_krb5_seal_alg, tvb, offset, 2,
			    TRUE);

	offset += 2;

	/* Skip the filler */

	offset += 2;

	/* Encrypted sequence number */

	proto_tree_add_item(subtree, hf_spnego_krb5_snd_seq, tvb, offset, 8,
			    TRUE);

	offset += 8;

	/* Checksum of plaintext padded data */

	proto_tree_add_item(subtree, hf_spnego_krb5_sgn_cksum, tvb, offset, 8,
			    TRUE);

	offset += 8;

	/*
	 * At least according to draft-brezak-win2k-krb-rc4-hmac-04,
	 * if the signing algorithm is KRB_SGN_ALG_HMAC, there's an
	 * extra 8 bytes of "Random confounder" after the checksum.
	 * It certainly confounds code expecting all Kerberos 5
	 * GSS_Wrap() tokens to look the same....
	 */
	if (sgn_alg == KRB_SGN_ALG_HMAC) {
	  proto_tree_add_item(subtree, hf_spnego_krb5_confounder, tvb, offset, 8,
			      TRUE);

	  offset += 8;
	}

	/*
	 * Return the offset past the checksum, so that we know where
	 * the data we're wrapped around starts.  Also, set the length
	 * of our top-level item to that offset, so it doesn't cover
	 * the data we're wrapped around.
	 */
	proto_item_set_len(item, offset);
	return offset;
}

/* Spnego stuff from here */

static int
dissect_spnego_mechTypes(tvbuff_t *tvb, int offset, packet_info *pinfo,
			 proto_tree *tree, ASN1_SCK *hnd,
			 gssapi_oid_value **next_level_value_p)
{
	proto_item *item = NULL;
	proto_tree *subtree = NULL;
	gboolean def;
	guint len1, len, cls, con, tag, nbytes;
	subid_t *oid;
	gchar *oid_string;
	int ret;
	gboolean saw_mechanism = FALSE;

	/*
	 * MechTypeList ::= SEQUENCE OF MechType
	 */

	ret = asn1_header_decode(hnd, &cls, &con, &tag, &def, &len1);

	if (ret != ASN1_ERR_NOERROR) {
	  dissect_parse_error(tvb, offset, pinfo, subtree,
			      "SPNEGO last sequence header", ret);
	  goto done;
	}

	if (!(cls == ASN1_UNI && con == ASN1_CON && tag == ASN1_SEQ)) {
	  proto_tree_add_text(
			      subtree, tvb, offset, 0,
			      "Unknown header (cls=%d, con=%d, tag=%d)",
			      cls, con, tag);
	  goto done;
	}

	offset = hnd->offset;

	item = proto_tree_add_item(tree, hf_spnego_mechtype, tvb, offset, 
				   len1, FALSE);
	subtree = proto_item_add_subtree(item, ett_spnego_mechtype);

	/*
	 * Now, the object IDs ... We should translate them: FIXME
	 */

	while (len1) {
	  gssapi_oid_value *value;

	  ret = asn1_oid_decode(hnd, &oid, &len, &nbytes);

	  if (ret != ASN1_ERR_NOERROR) {
	    dissect_parse_error(tvb, offset, pinfo, subtree,
				"SPNEGO mechTypes token", ret);
	    goto done;
	  }

	  oid_string = format_oid(oid, len);
	  value = gssapi_lookup_oid(oid, len);
	  if (value)
	    proto_tree_add_text(subtree, tvb, offset, nbytes, "OID: %s (%s)",
				oid_string, value->comment);
	  else
	    proto_tree_add_text(subtree, tvb, offset, nbytes, "OID: %s",
				oid_string);

	  g_free(oid_string);

	  /*
	   * Tell our caller the first mechanism we see, so that if
	   * this is a negTokenInit with a mechToken, it can interpret
	   * the mechToken according to the first mechType.  (There
	   * might not have been any indication of the mechType
	   * in prior frames, so we can't necessarily use the
	   * mechanism from the conversation; i.e., a negTokenInit
	   * can contain the initial security token for the desired
	   * mechanism of the initiator - that's the first mechanism
	   * in the list.)
	   */
	  if (!saw_mechanism) {
	    if (value)
	      *next_level_value_p = value;
	    saw_mechanism = TRUE;
	  }

	  offset += nbytes;
	  len1 -= nbytes;

	}

 done:

	return offset;

}

static int
dissect_spnego_reqFlags(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			proto_tree *tree, ASN1_SCK *hnd)
{
	gboolean def;
	guint len1, cls, con, tag;
	int ret;

 	ret = asn1_header_decode(hnd, &cls, &con, &tag, &def, &len1);

	if (ret != ASN1_ERR_NOERROR) {
		dissect_parse_error(tvb, offset, pinfo, tree,
				    "SPNEGO reqFlags header", ret);
		goto done;
	}

	if (!(cls == ASN1_UNI && con == ASN1_PRI && tag == ASN1_BTS)) {
		proto_tree_add_text(
			tree, tvb, offset, 0,
			"Unknown header (cls=%d, con=%d, tag=%d)",
			cls, con, tag);
		goto done;
	}

	/* We must have a Bit String ... insert it */ 

	offset = hnd->offset;

	proto_tree_add_item(tree, hf_spnego_reqflags, tvb, offset, len1,
			    FALSE);

	hnd->offset += len1;

 done:
	return offset + len1;

}

static int
dissect_spnego_mechToken(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			 proto_tree *tree, ASN1_SCK *hnd,
			 dissector_handle_t next_level_dissector)
{
        proto_item *item;
	proto_tree *subtree;
	gboolean def;
	int ret;
	guint cls, con, tag, nbytes;
	tvbuff_t *token_tvb;

	/*
	 * This appears to be a simple octet string ...
	 */

 	ret = asn1_header_decode(hnd, &cls, &con, &tag, &def, &nbytes);

	if (ret != ASN1_ERR_NOERROR) {
		dissect_parse_error(tvb, offset, pinfo, tree,
				    "SPNEGO sequence header", ret);
		goto done;
	}

	if (!(cls == ASN1_UNI && con == ASN1_PRI && tag == ASN1_OTS)) {
		proto_tree_add_text(
			tree, tvb, offset, 0,
			"Unknown header (cls=%d, con=%d, tag=%d)",
			cls, con, tag);
		goto done;
	}

	offset = hnd->offset;

	item = proto_tree_add_item(tree, hf_spnego_mechtoken, tvb, offset, 
				   nbytes, FALSE);
	subtree = proto_item_add_subtree(item, ett_spnego_mechtoken);

	/*
	 * Now, we should be able to dispatch after creating a new TVB.
	 */

	token_tvb = tvb_new_subset(tvb, offset, nbytes, -1);
	if (next_level_dissector)
	  call_dissector(next_level_dissector, token_tvb, pinfo, subtree);

	hnd->offset += nbytes; /* Update this ... */

 done:

  return offset + nbytes;

}

static int
dissect_spnego_mechListMIC(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			   proto_tree *tree, ASN1_SCK *hnd,
			   dissector_handle_t next_level_dissector)
{
	guint len1, cls, con, tag;
	int ret;
	gboolean def;
	proto_tree *subtree = NULL;

	/*
	 * Add the mechListMIC [3] Octet String or General String ...
	 */
 	ret = asn1_header_decode(hnd, &cls, &con, &tag, &def, &len1);

	if (ret != ASN1_ERR_NOERROR) {
		dissect_parse_error(tvb, offset, pinfo, subtree,
				    "SPNEGO sequence header", ret);
		goto done;
	}

	offset = hnd->offset;

	if (cls == ASN1_UNI && con == ASN1_CON && tag == ASN1_SEQ) {

	  /*
	   * There seems to be two different forms this can take
	   * One as an Octet string, and one as a general string in a 
	   * sequence ... We will have to dissect this later
	   */
	 
	  proto_tree_add_text(tree, tvb, offset + 4, len1 - 4,
			      "mechListMIC: %s",
			      tvb_format_text(tvb, offset + 4, len1 - 4));

	  /* Naughty ... but we have to adjust for what we never took */

	  hnd->offset += len1;
	  offset += len1;

	}
	else if (cls == ASN1_UNI && con == ASN1_PRI && tag == ASN1_OTS) {
	  tvbuff_t *token_tvb;
	  proto_item *item;
	  proto_tree *subtree;

	  item = proto_tree_add_item(tree, hf_spnego_mechlistmic, tvb, offset, 
			      len1, FALSE); 
	  subtree = proto_item_add_subtree(item, ett_spnego_mechlistmic);
	  
	/*
	 * Now, we should be able to dispatch after creating a new TVB.
	 */

	  token_tvb = tvb_new_subset(tvb, offset, len1, -1);
	  if (next_level_dissector)
	    call_dissector(next_level_dissector, token_tvb, pinfo, subtree);

	  hnd->offset += len1; /* Update this ... */
	  offset += len1;

	}
	else {

	  proto_tree_add_text(subtree, tvb, offset, 0,
			      "Unknown header (cls=%d, con=%d, tag=%d)",
			      cls, con, tag);
	  goto done;
	}

 done:

	return offset;

}

static int
dissect_spnego_negTokenInit(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			    proto_tree *tree, ASN1_SCK *hnd,
			    gssapi_oid_value **next_level_value_p)
{
	proto_item *item;
	proto_tree *subtree;
	gboolean def;
	guint len1, len, cls, con, tag;
	int ret;

	item = proto_tree_add_item( tree, hf_spnego_negtokeninit, tvb, offset,
				    -1, FALSE);
	subtree = proto_item_add_subtree(item, ett_spnego_negtokeninit);

	/*
	 * Here is what we need to get ...
	 * NegTokenInit ::= SEQUENCE {
	 *          mechTypes [0] MechTypeList OPTIONAL,
	 *          reqFlags [1] ContextFlags OPTIONAL,
	 *          mechToken [2] OCTET STRING OPTIONAL,
	 *          mechListMIC [3] OCTET STRING OPTIONAL }

	 */

 	ret = asn1_header_decode(hnd, &cls, &con, &tag, &def, &len1);

	if (ret != ASN1_ERR_NOERROR) {
		dissect_parse_error(tvb, offset, pinfo, subtree,
				    "SPNEGO sequence header", ret);
		goto done;
	}

	if (!(cls == ASN1_UNI && con == ASN1_CON && tag == ASN1_SEQ)) {
		proto_tree_add_text(
			subtree, tvb, offset, 0,
			"Unknown header (cls=%d, con=%d, tag=%d)",
			cls, con, tag);
		goto done;
	}

	offset = hnd->offset;

	while (len1) {
	  int hdr_ofs;

	  hdr_ofs = hnd->offset;

	  ret = asn1_header_decode(hnd, &cls, &con, &tag, &def, &len);

	  if (ret != ASN1_ERR_NOERROR) {
	    dissect_parse_error(tvb, offset, pinfo, subtree,
				"SPNEGO context header", ret);
	    goto done;
	  }

	  if (!(cls == ASN1_CTX && con == ASN1_CON)) {
	    proto_tree_add_text(subtree, tvb, offset, 0,
				"Unknown header (cls=%d, con=%d, tag=%d)",
				cls, con, tag);
	    goto done;
	  }

	  /* Adjust for the length of the header */

	  len1 -= (hnd->offset - hdr_ofs);

	  /* Should be one of the fields */

	  switch (tag) {

	  case SPNEGO_mechTypes:

	    offset = dissect_spnego_mechTypes(tvb, offset, pinfo,
					      subtree, hnd,
					      next_level_value_p);

	    break;

	  case SPNEGO_reqFlags:

	    offset = dissect_spnego_reqFlags(tvb, offset, pinfo, subtree, hnd);

	    break;

	  case SPNEGO_mechToken:

	    offset = dissect_spnego_mechToken(tvb, offset, pinfo, subtree, 
					      hnd, (*next_level_value_p)->handle);
	    break;

	  case SPNEGO_mechListMIC:

	    offset = dissect_spnego_mechListMIC(tvb, offset, pinfo, subtree,
						hnd, (*next_level_value_p)->handle);
	    break;

	  default:

	    break;
	  }

	  len1 -= len;

	}

 done:

	return offset; /* Not sure this is right */
}

static int
dissect_spnego_negResult(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			    proto_tree *tree, ASN1_SCK *hnd)
{
        gboolean def;
	int ret;
	guint len, cls, con, tag, val;

	ret = asn1_header_decode(hnd, &cls, &con, &tag, &def, &len);

	if (ret != ASN1_ERR_NOERROR) {
	  dissect_parse_error(tvb, offset, pinfo, tree,
			      "SPNEGO context header", ret);
	  goto done;
	}

	if (!(cls == ASN1_UNI && con == ASN1_PRI && tag == ASN1_ENUM)) {
	  proto_tree_add_text(
			      tree, tvb, offset, 0,
			      "Unknown header (cls=%d, con=%d, tag=%d) xxx",
			      cls, con, tag);
	  goto done;
	}

	offset = hnd->offset;

	/* Now, get the value */

	ret = asn1_uint32_value_decode(hnd, len, &val);

	if (ret != ASN1_ERR_NOERROR) {
	  dissect_parse_error(tvb, offset, pinfo, tree,
			      "SPNEGO negResult value", ret);
	  goto done;
	}
	
	proto_tree_add_item(tree, hf_spnego_negtokentarg_negresult, tvb, 
			    offset, 1, FALSE);

	offset = hnd->offset;

 done:
	return offset;
}

static int
dissect_spnego_supportedMech(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			     proto_tree *tree, ASN1_SCK *hnd,
			     gssapi_oid_value **next_level_value_p)
{
	int ret;
	guint oid_len, nbytes;
	subid_t *oid;
	gchar *oid_string;
	gssapi_oid_value *value;
	conversation_t *conversation;

	/*
	 * Now, get the OID, and find the handle, if any
	 */

	offset = hnd->offset;

	ret = asn1_oid_decode(hnd, &oid, &oid_len, &nbytes);

	if (ret != ASN1_ERR_NOERROR) {
		dissect_parse_error(tvb, offset, pinfo, tree,
				    "SPNEGO supportedMech token", ret);
		goto done;
	}

	oid_string = format_oid(oid, oid_len);
	value = gssapi_lookup_oid(oid, oid_len);

	if (value)
	  proto_tree_add_text(tree, tvb, offset, nbytes, 
			      "supportedMech: %s (%s)",
			      oid_string, value->comment);
	else
	  proto_tree_add_text(tree, tvb, offset, nbytes, "supportedMech: %s",
			      oid_string);

	g_free(oid_string);

	offset += nbytes;

	/* Should check for an unrecognized OID ... */

	if (value)
	  *next_level_value_p = value;

	/*
	 * Now, we need to save this in per proto info in the
	 * conversation if it exists. We also should create a 
	 * conversation if one does not exist. FIXME!
	 * Hmmm, might need to be smarter, because there can be
	 * multiple mechTypes in a negTokenInit with one being the
	 * default used in the Token if present. Then the negTokenTarg
	 * could override that. :-(
	 */

	if ((conversation = find_conversation(&pinfo->src, &pinfo->dst,
					     pinfo->ptype, pinfo->srcport,
					     pinfo->destport, 0))) {


	  conversation_add_proto_data(conversation, proto_spnego, 
				      *next_level_value_p);
	}
	else {

	}

 done:
	return offset;
}

static int
dissect_spnego_responseToken(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			     proto_tree *tree, ASN1_SCK *hnd,
			     dissector_handle_t next_level_dissector)
{
	gboolean def;
	int ret;
	guint cls, con, tag, nbytes;
	tvbuff_t *token_tvb;
	proto_item *item;
	proto_tree *subtree;

 	ret = asn1_header_decode(hnd, &cls, &con, &tag, &def, &nbytes);

	if (ret != ASN1_ERR_NOERROR) {
		dissect_parse_error(tvb, offset, pinfo, tree,
				    "SPNEGO sequence header", ret);
		goto done;
	}

	if (!(cls == ASN1_UNI && con == ASN1_PRI && tag == ASN1_OTS)) {
		proto_tree_add_text(
			tree, tvb, offset, 0,
			"Unknown header (cls=%d, con=%d, tag=%d)",
			cls, con, tag);
		goto done;
	}

	offset = hnd->offset;

	item = proto_tree_add_item(tree, hf_spnego_responsetoken, tvb, offset, 
				   nbytes, FALSE); 

	subtree = proto_item_add_subtree(item, ett_spnego_responsetoken);

	/*
	 * Now, we should be able to dispatch after creating a new TVB.
	 */

	token_tvb = tvb_new_subset(tvb, offset, nbytes, -1);
	if (next_level_dissector)
	  call_dissector(next_level_dissector, token_tvb, pinfo, subtree);

	hnd->offset += nbytes; /* Update this ... */

 done:
	return offset + nbytes;
}

static int
dissect_spnego_negTokenTarg(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			    proto_tree *tree, ASN1_SCK *hnd,
			    gssapi_oid_value **next_level_value_p)

{
	proto_item *item;
	proto_tree *subtree;
	gboolean def;
	int ret;
	guint len1, len, cls, con, tag;

	item = proto_tree_add_item( tree, hf_spnego_negtokentarg, tvb, offset,
				    -1, FALSE);
	subtree = proto_item_add_subtree(item, ett_spnego_negtokentarg);

	/* 
	 * Here is what we need to get ...
         * NegTokenTarg ::= SEQUENCE {
	 *          negResult [0] ENUMERATED {
	 *              accept_completed (0),
	 *              accept_incomplete (1),
	 *              reject (2) } OPTIONAL,
         *          supportedMech [1] MechType OPTIONAL,
         *          responseToken [2] OCTET STRING OPTIONAL,
         *          mechListMIC [3] OCTET STRING OPTIONAL }
	 */

 	ret = asn1_header_decode(hnd, &cls, &con, &tag, &def, &len1);

	if (ret != ASN1_ERR_NOERROR) {
		dissect_parse_error(tvb, offset, pinfo, subtree,
				    "SPNEGO sequence header", ret);
		goto done;
	}

	if (!(cls == ASN1_UNI && con == ASN1_CON && tag == ASN1_SEQ)) {
		proto_tree_add_text(
			subtree, tvb, offset, 0,
			"Unknown header (cls=%d, con=%d, tag=%d)",
			cls, con, tag);
		goto done;
	}

	offset = hnd->offset;

	while (len1) {
	  int hdr_ofs;

	  hdr_ofs = hnd->offset; 

	  ret = asn1_header_decode(hnd, &cls, &con, &tag, &def, &len);

	  if (ret != ASN1_ERR_NOERROR) {
	    dissect_parse_error(tvb, offset, pinfo, subtree,
				"SPNEGO context header", ret);
	    goto done;
	  }

	  if (!(cls == ASN1_CTX && con == ASN1_CON)) {
	    proto_tree_add_text(
				subtree, tvb, offset, 0,
				"Unknown header (cls=%d, con=%d, tag=%d)",
				cls, con, tag);
	    goto done;
	  }

	  /* Adjust for the length of the header */

	  len1 -= (hnd->offset - hdr_ofs);

	  /* Should be one of the fields */

	  switch (tag) {

	  case SPNEGO_negResult:

	    offset = dissect_spnego_negResult(tvb, offset, pinfo, subtree, 
					      hnd);
	    break;

	  case SPNEGO_supportedMech:

	    offset = dissect_spnego_supportedMech(tvb, offset, pinfo, subtree,
						  hnd, next_level_value_p);

	    break;

	  case SPNEGO_responseToken:

	    offset = dissect_spnego_responseToken(tvb, offset, pinfo, subtree,
						  hnd,
						  (*next_level_value_p != NULL) ?
						      (*next_level_value_p)->handle :
						      NULL);
	    break;

	  case SPNEGO_mechListMIC:

	    offset = dissect_spnego_mechListMIC(tvb, offset, pinfo, subtree, 
						hnd,
						(*next_level_value_p != NULL) ?
						    (*next_level_value_p)->handle :
						    NULL);
	    break;

	  default:

	    break;
	  }

	  len1 -= len;

	}

 done:
	return offset;

}

static void
dissect_spnego(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *item;
	proto_tree *subtree;
	int ret, offset = 0;
	ASN1_SCK hnd;
	gboolean def;
	guint len1, cls, con, tag;
	conversation_t *conversation;
	gssapi_oid_value *next_level_value;

	/*
	 * We need this later, so lets get it now ...
	 * It has to be per-frame as there can be more than one GSS-API
	 * negotiation in a conversation.
	 */

	next_level_value = p_get_proto_data(pinfo->fd, proto_spnego);
	if (!next_level_value && !pinfo->fd->flags.visited) {
	    /*
	     * No handle attached to this frame, but it's the first
	     * pass, so it'd be attached to the conversation.
	     * If we have a conversation, try to get the handle,
	     * and if we get one, attach it to the frame.
	     */
	    conversation = find_conversation(&pinfo->src, &pinfo->dst,
					     pinfo->ptype, pinfo->srcport,
					     pinfo->destport, 0);

	    if (conversation) {
		next_level_value = conversation_get_proto_data(conversation, 
							       proto_spnego);
		if (next_level_value)
		    p_add_proto_data(pinfo->fd, proto_spnego, next_level_value);
	    }
	}

	item = proto_tree_add_item(tree, hf_spnego, tvb, offset, 
				   -1, FALSE);

	subtree = proto_item_add_subtree(item, ett_spnego);

	/*
	 * The TVB contains a [0] header and a sequence that consists of an
	 * object ID and a blob containing the data ...
	 * Actually, it contains, according to RFC2478:
         * NegotiationToken ::= CHOICE {
	 *          negTokenInit [0] NegTokenInit,
	 *          negTokenTarg [1] NegTokenTarg }
	 * NegTokenInit ::= SEQUENCE {
	 *          mechTypes [0] MechTypeList OPTIONAL,
	 *          reqFlags [1] ContextFlags OPTIONAL,
	 *          mechToken [2] OCTET STRING OPTIONAL,
	 *          mechListMIC [3] OCTET STRING OPTIONAL }
         * NegTokenTarg ::= SEQUENCE {
	 *          negResult [0] ENUMERATED {
	 *              accept_completed (0),
	 *              accept_incomplete (1),
	 *              reject (2) } OPTIONAL,
         *          supportedMech [1] MechType OPTIONAL,
         *          responseToken [2] OCTET STRING OPTIONAL,
         *          mechListMIC [3] OCTET STRING OPTIONAL }
         *
	 * Windows typically includes mechTypes and mechListMic ('NONE'
	 * in the case of NTLMSSP only).
         * It seems to duplicate the responseToken into the mechListMic field
         * as well. Naughty, naughty.
         *
	 */

	asn1_open(&hnd, tvb, offset);

	/*
	 * Get the first header ...
	 */

	ret = asn1_header_decode(&hnd, &cls, &con, &tag, &def, &len1);

	if (ret != ASN1_ERR_NOERROR) {
		dissect_parse_error(tvb, offset, pinfo, subtree,
				    "SPNEGO context header", ret);
		goto done;
	}

	if (!(cls == ASN1_CTX && con == ASN1_CON)) {
		proto_tree_add_text(
			subtree, tvb, offset, 0,
			"Unknown header (cls=%d, con=%d, tag=%d)",
			cls, con, tag);
		goto done;
	}

	offset = hnd.offset;

	/*
	 * The Tag is one of negTokenInit or negTokenTarg
	 */

	switch (tag) {

	case SPNEGO_negTokenInit:

	  offset = dissect_spnego_negTokenInit(tvb, offset, pinfo,
					       subtree, &hnd,
					       &next_level_value);

	  break;

	case SPNEGO_negTokenTarg:

	  offset = dissect_spnego_negTokenTarg(tvb, offset, pinfo,
					       subtree, &hnd,
					       &next_level_value);
	  break;

	default: /* Broken, what to do? */

	  break;
	}


 done:
	asn1_close(&hnd, &offset);

}

static int
dissect_spnego_wrap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *item;
	proto_tree *subtree;
	int ret, offset = 0;
	int return_offset;
	ASN1_SCK hnd;
	gboolean def;
	guint len1, cls, con, tag, nbytes;
	guint oid_len;
	subid_t *oid;
	gchar *oid_string;
	conversation_t *conversation;
	gssapi_oid_value *next_level_value;
	tvbuff_t *token_tvb;
	int len;

	/*
	 * We need this later, so lets get it now ...
	 * It has to be per-frame as there can be more than one GSS-API
	 * negotiation in a conversation.
	 */

	next_level_value = p_get_proto_data(pinfo->fd, proto_spnego);
	if (!next_level_value && !pinfo->fd->flags.visited) {
	    /*
	     * No handle attached to this frame, but it's the first
	     * pass, so it'd be attached to the conversation.
	     * If we have a conversation, try to get the handle,
	     * and if we get one, attach it to the frame.
	     */
	    conversation = find_conversation(&pinfo->src, &pinfo->dst,
					     pinfo->ptype, pinfo->srcport,
					     pinfo->destport, 0);

	    if (conversation) {
		next_level_value = conversation_get_proto_data(conversation, 
							       proto_spnego);
		if (next_level_value)
		    p_add_proto_data(pinfo->fd, proto_spnego, next_level_value);
	    }
	}

	item = proto_tree_add_item(tree, hf_spnego, tvb, offset, 
				   -1, FALSE);

	subtree = proto_item_add_subtree(item, ett_spnego);

	/*
	 * The TVB contains a [0] header and a sequence that consists of an
	 * object ID and a blob containing the data ...
	 * XXX - is this RFC 2743's "Mechanism-Independent Token Format",
	 * with the "optional" "use in non-initial tokens" being chosen.
	 */

	asn1_open(&hnd, tvb, offset);

	/*
	 * Get the first header ...
	 */

	ret = asn1_header_decode(&hnd, &cls, &con, &tag, &def, &len1);

	if (ret != ASN1_ERR_NOERROR) {
		dissect_parse_error(tvb, offset, pinfo, subtree,
				    "SPNEGO context header", ret);
		return_offset = tvb_length(tvb);
		goto done;
	}

	if (!(cls == ASN1_APL && con == ASN1_CON && tag == 0)) {
		proto_tree_add_text(
			subtree, tvb, offset, 0,
			"Unknown header (cls=%d, con=%d, tag=%d)",
			cls, con, tag);
		return_offset = tvb_length(tvb);
		goto done;
	}

	offset = hnd.offset;

	/*
	 * Get the OID, and find the handle, if any
	 */

	ret = asn1_oid_decode(&hnd, &oid, &oid_len, &nbytes);

	if (ret != ASN1_ERR_NOERROR) {
		dissect_parse_error(tvb, offset, pinfo, tree,
				    "SPNEGO wrap token", ret);
		return_offset = tvb_length(tvb);
		goto done;
	}

	oid_string = format_oid(oid, oid_len);
	next_level_value = gssapi_lookup_oid(oid, oid_len);

	/*
	 * XXX - what should we do if this doesn't match the value
	 * attached to the frame or conversation?  (That would be
	 * bogus, but that's not impossible - some broken implementation
	 * might negotiate some security mechanism but put the OID
	 * for some other security mechanism in GSS_Wrap tokens.)
	 */
	if (next_level_value)
	  proto_tree_add_text(tree, tvb, offset, nbytes, 
			      "thisMech: %s (%s)",
			      oid_string, next_level_value->comment);
	else
	  proto_tree_add_text(tree, tvb, offset, nbytes, "thisMech: %s",
			      oid_string);

	g_free(oid_string);

	offset += nbytes;

	/*
	 * Now dissect the GSS_Wrap token; it's assumed to be in the
	 * rest of the tvbuff.
	 */
	item = proto_tree_add_item(tree, hf_spnego_wraptoken, tvb, offset, 
				   -1, FALSE); 

	subtree = proto_item_add_subtree(item, ett_spnego_wraptoken);

	/*
	 * Now, we should be able to dispatch after creating a new TVB.
	 * The subdissector must return the length of the part of the
	 * token it dissected, so we can return the length of the part
	 * we (and it) dissected.
	 */

	token_tvb = tvb_new_subset(tvb, offset, -1, -1);
	if (next_level_value->wrap_handle) {
	  len = call_dissector(next_level_value->wrap_handle, token_tvb, pinfo, subtree);
	  if (len == 0)
	    return_offset = tvb_length(tvb);
	  else
	    return_offset = offset + len;
	} else
	  return_offset = tvb_length(tvb);
 done:
	asn1_close(&hnd, &offset);

	return return_offset;
}

void
proto_register_spnego(void)
{
	static hf_register_info hf[] = {
		{ &hf_spnego,
		  { "SPNEGO", "spnego", FT_NONE, BASE_NONE, NULL, 0x0,
		    "SPNEGO", HFILL }},
		{ &hf_spnego_negtokeninit,
		  { "negTokenInit", "spnego.negtokeninit", FT_NONE, BASE_NONE,
		    NULL, 0x0, "SPNEGO negTokenInit", HFILL}},
		{ &hf_spnego_negtokentarg,
		  { "negTokenTarg", "spnego.negtokentarg", FT_NONE, BASE_NONE,
		    NULL, 0x0, "SPNEGO negTokenTarg", HFILL}},
		{ &hf_spnego_mechtype,
		  { "mechType", "spnego.negtokeninit.mechtype", FT_NONE,
		    BASE_NONE, NULL, 0x0, "SPNEGO negTokenInit mechTypes", HFILL}},
		{ &hf_spnego_mechtoken,
		  { "mechToken", "spnego.negtokeninit.mechtoken", FT_NONE,
		    BASE_NONE, NULL, 0x0, "SPNEGO negTokenInit mechToken", HFILL}},
		{ &hf_spnego_mechlistmic,
		  { "mechListMIC", "spnego.mechlistmic", FT_NONE,
		    BASE_NONE, NULL, 0x0, "SPNEGO mechListMIC", HFILL}}, 
		{ &hf_spnego_responsetoken,
		  { "responseToken", "spnego.negtokentarg.responsetoken",
		    FT_NONE, BASE_NONE, NULL, 0x0, "SPNEGO responseToken",
		    HFILL}},
		{ &hf_spnego_negtokentarg_negresult,
		  { "negResult", "spnego.negtokeninit.negresult", FT_UINT16,
		    BASE_HEX, VALS(spnego_negResult_vals), 0, "negResult", HFILL}},
		{ &hf_spnego_reqflags, 
		  { "reqFlags", "spnego.negtokeninit.reqflags", FT_BYTES,
		    BASE_HEX, NULL, 0, "reqFlags", HFILL }},
		{ &hf_spnego_wraptoken,
		  { "wrapToken", "spnego.wraptoken",
		    FT_NONE, BASE_NONE, NULL, 0x0, "SPNEGO wrapToken",
		    HFILL}},
		{ &hf_spnego_krb5,
		  { "krb5_blob", "spnego.krb5.blob", FT_BYTES,
		    BASE_NONE, NULL, 0, "krb5_blob", HFILL }},
		{ &hf_spnego_krb5_tok_id,
		  { "krb5_tok_id", "spnego.krb5.tok_id", FT_UINT16, BASE_HEX,
		    VALS(spnego_krb5_tok_id_vals), 0, "KRB5 Token Id", HFILL}},
		{ &hf_spnego_krb5_sgn_alg,
		  { "krb5_sgn_alg", "spnego.krb5.sgn_alg", FT_UINT16, BASE_HEX,
		    VALS(spnego_krb5_sgn_alg_vals), 0, "KRB5 Signing Algorithm", HFILL}},
		{ &hf_spnego_krb5_seal_alg,
		  { "krb5_seal_alg", "spnego.krb5.seal_alg", FT_UINT16, BASE_HEX,
		    VALS(spnego_krb5_seal_alg_vals), 0, "KRB5 Sealing Algorithm", HFILL}},
		{ &hf_spnego_krb5_snd_seq,
		  { "krb5_snd_seq", "spnego.krb5.snd_seq", FT_BYTES, BASE_NONE,
		    NULL, 0, "KRB5 Encrypted Sequence Number", HFILL}},
		{ &hf_spnego_krb5_sgn_cksum,
		  { "krb5_sgn_cksum", "spnego.krb5.sgn_cksum", FT_BYTES, BASE_NONE,
		    NULL, 0, "KRB5 Data Checksum", HFILL}},
		{ &hf_spnego_krb5_confounder,
		  { "krb5_confounder", "spnego.krb5.confounder", FT_BYTES, BASE_NONE,
		    NULL, 0, "KRB5 Confounder", HFILL}},
	};

	static gint *ett[] = {
		&ett_spnego,
		&ett_spnego_negtokeninit,
		&ett_spnego_negtokentarg,
		&ett_spnego_mechtype,
		&ett_spnego_mechtoken,
		&ett_spnego_mechlistmic,
		&ett_spnego_responsetoken,
		&ett_spnego_wraptoken,
		&ett_spnego_krb5,
	};

	proto_spnego = proto_register_protocol(
		"Spnego", "Spnego", "spnego");
	proto_spnego_krb5 = proto_register_protocol("SPNEGO-KRB5",
						    "SPNEGO-KRB5",
						    "spnego-krb5");

	proto_register_field_array(proto_spnego, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_spnego(void)
{
	dissector_handle_t spnego_handle, spnego_wrap_handle;
	dissector_handle_t spnego_krb5_handle, spnego_krb5_wrap_handle;

	/* Register protocol with GSS-API module */

	spnego_handle = create_dissector_handle(dissect_spnego, proto_spnego);
	spnego_wrap_handle = new_create_dissector_handle(dissect_spnego_wrap,
							 proto_spnego);
	gssapi_init_oid("1.3.6.1.5.5.2", proto_spnego, ett_spnego,
	    spnego_handle, spnego_wrap_handle,
	    "SPNEGO - Simple Protected Negotiation");

	/* Register both the one MS created and the real one */
	/*
	 * Thanks to Jean-Baptiste Marchand and Richard B Ward, the
	 * mystery of the MS KRB5 OID is cleared up. It was due to a library
	 * that did not handle OID components greater than 16 bits, and was
	 * fixed in Win2K SP2 as well as WinXP.
	 * See the archive of <ietf-krb-wg@anl.gov> for the thread topic
	 * SPNEGO implementation issues. 3-Dec-2002.
	 */
	spnego_krb5_handle = create_dissector_handle(dissect_spnego_krb5,
						     proto_spnego_krb5);
	spnego_krb5_wrap_handle = new_create_dissector_handle(dissect_spnego_krb5_wrap,
							      proto_spnego_krb5);
	gssapi_init_oid("1.2.840.48018.1.2.2", proto_spnego_krb5, ett_spnego_krb5,
			spnego_krb5_handle, spnego_krb5_wrap_handle,
			"MS KRB5 - Microsoft Kerberos 5");
	gssapi_init_oid("1.2.840.113554.1.2.2", proto_spnego_krb5, ett_spnego_krb5,
			spnego_krb5_handle, spnego_krb5_wrap_handle,
			"KRB5 - Kerberos 5");
}
