/* packet-spnego.c
 * Routines for the simple and protected GSS-API negotiation mechanism
 * as described in rfc2478.
 * Copyright 2002, Tim Potter <tpot@samba.org>
 * Copyright 2002, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id: packet-spnego.c,v 1.20 2002/08/31 17:09:45 sharpe Exp $
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
#include "epan/conversation.h"

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

static int hf_spnego = -1;
static int hf_spnego_negtokeninit = -1;
static int hf_spnego_negtokentarg = -1;
static int hf_spnego_mechtype = -1;
static int hf_spnego_mechtoken = -1;
static int hf_spnego_negtokentarg_negresult = -1;
static int hf_spnego_mechlistmic = -1;
static int hf_spnego_responsetoken = -1;

static gint ett_spnego = -1;
static gint ett_spnego_negtokeninit = -1;
static gint ett_spnego_negtokentarg = -1;
static gint ett_spnego_mechtype = -1;
static gint ett_spnego_mechtoken = -1;
static gint ett_spnego_mechlistmic = -1;
static gint ett_spnego_responsetoken = -1;

/*
 * XXX: Fixme. This thould be made global ...
 */

static const value_string spnego_negResult_vals[] = {
  { SPNEGO_negResult_accept_completed,   "Accept Completed" },
  { SPNEGO_negResult_accept_incomplete,  "Accept Incomplete" },
  { SPNEGO_negResult_accept_reject,      "Accept Reject"},
  { 0, NULL}
};

/*
 * We need to keep this around for other routines to use.
 * We store it in the per-protocol conversation data and 
 * retrieve it in the main dissector.
 */

static dissector_handle_t next_level_dissector = NULL;

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

static int
dissect_spnego_mechTypes(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			 proto_tree *tree, ASN1_SCK *hnd)
{
	proto_item *item = NULL;
	proto_tree *subtree = NULL;
	gboolean def;
	guint len1, len, cls, con, tag, nbytes;
	subid_t *oid;
	gchar *oid_string;
	int ret;


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

	  ret = asn1_oid_decode(hnd, &oid, &len, &nbytes);

	  if (ret != ASN1_ERR_NOERROR) {
	    dissect_parse_error(tvb, offset, pinfo, subtree,
				"GSS-API token", ret);
	    goto done;
	  }

	  oid_string = format_oid(oid, len);

	  proto_tree_add_text(subtree, tvb, offset, nbytes, "OID: %s",
			      oid_string);

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


  return offset;

}

static int
dissect_spnego_mechToken(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			 proto_tree *tree, ASN1_SCK *hnd)
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
			   proto_tree *tree, ASN1_SCK *hnd)
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
			      "mechListMIC: %s\n",
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
			    proto_tree *tree, ASN1_SCK *hnd)
{
	proto_item *item;
	proto_tree *subtree;
	gboolean def;
	guint len1, len, cls, con, tag;
	int ret;
	int length = tvb_length_remaining(tvb, offset);

	item = proto_tree_add_item( tree, hf_spnego_negtokeninit, tvb, offset,
				    length, FALSE);
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
					      subtree, hnd);

	    break;

	  case SPNEGO_reqFlags:

	    break;

	  case SPNEGO_mechToken:

	    offset = dissect_spnego_mechToken(tvb, offset, pinfo, subtree, 
					      hnd);
	    break;

	  case SPNEGO_mechListMIC:

	    offset = dissect_spnego_mechListMIC(tvb, offset, pinfo, subtree,
						hnd);
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
			     proto_tree *tree, ASN1_SCK *hnd)
{
	int ret;
	guint oid_len, len, nbytes;
	subid_t *oid;
	gchar *p, *oid_string;
	unsigned int i;
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

	proto_tree_add_text(tree, tvb, offset, nbytes, "supportedMech: %s",
			    oid_string);

	offset += nbytes;

	g_free(oid_string);

	oid_string = g_malloc(oid_len * 22 + 1);
	p = oid_string;
	len = sprintf(p, "%lu", (unsigned long)oid[0]);
	p += len;
	for (i = 1; i < oid_len;i++) {
		len = sprintf(p, ".%lu", (unsigned long)oid[i]);
		p += len;
	}

	value = g_hash_table_lookup(gssapi_oids, oid_string);

	/* Should check for an unrecognized OID ... */

	next_level_dissector = NULL; /* FIXME: Is this right? */

	if (value) next_level_dissector = find_dissector(value->name);

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
				      next_level_dissector);
	}
	else {

	}

 done:
	return offset;
}

static int
dissect_spnego_responseToken(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			     proto_tree *tree, ASN1_SCK *hnd)
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
			    proto_tree *tree, ASN1_SCK *hnd)

{
	proto_item *item;
	proto_tree *subtree;
	gboolean def;
	int ret;
	guint len1, len, cls, con, tag;
	int length = tvb_length_remaining(tvb, offset);

	item = proto_tree_add_item( tree, hf_spnego_negtokentarg, tvb, offset,
				    length, FALSE);
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
						  hnd);

	    break;

	  case SPNEGO_responseToken:

	    offset = dissect_spnego_responseToken(tvb, offset, pinfo, subtree,
						  hnd);
	    break;

	  case SPNEGO_mechListMIC:

	    offset = dissect_spnego_mechListMIC(tvb, offset, pinfo, subtree, 
						hnd);
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
dissect_spnego(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item *item;
	proto_tree *subtree;
	int length = tvb_length_remaining(tvb, 0);
	int ret, offset = 0;
	ASN1_SCK hnd;
	gboolean def;
	guint len1, cls, con, tag;
	conversation_t *conversation;
	dissector_handle_t handle;

	/*
	 * We need this later, so lets get it now ...
	 */

	conversation = find_conversation(&pinfo->src, &pinfo->dst,
					 pinfo->ptype, pinfo->srcport,
					 pinfo->destport, 0);

	if (conversation && 
	    (handle = conversation_get_proto_data(conversation, 
						 proto_spnego))) {
	  next_level_dissector = handle;

	}
	item = proto_tree_add_item(tree, hf_spnego, tvb, offset, 
				   length, FALSE);

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
         * FIXME, the following code is broken so far.
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
					       subtree, &hnd);

	  break;

	case SPNEGO_negTokenTarg:

	  offset = dissect_spnego_negTokenTarg(tvb, offset, pinfo,
					       subtree, &hnd);
	  break;

	default: /* Broken, what to do? */

	  break;
	}


 done:
	asn1_close(&hnd, &offset);

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
	};

	static gint *ett[] = {
		&ett_spnego,
		&ett_spnego_negtokeninit,
		&ett_spnego_negtokentarg,
		&ett_spnego_mechtype,
		&ett_spnego_mechtoken,
		&ett_spnego_mechlistmic,
		&ett_spnego_responsetoken,
	};

	proto_spnego = proto_register_protocol(
		"Spnego", "Spnego", "spnego");

	proto_register_field_array(proto_spnego, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("spnego", dissect_spnego, proto_spnego);
}

void
proto_reg_handoff_spnego(void)
{
	/* Register protocol with GSS-API module */

	gssapi_init_oid("1.3.6.1.5.5.2", proto_spnego, ett_spnego, "spnego");
}
