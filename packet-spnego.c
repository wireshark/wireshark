/* packet-spnego.c
 * Routines for the simple and protected GSS-API negotiation mechanism
 * as described in rfc2478.
 * Copyright 2002, Tim Potter <tpot@samba.org>
 * Copyright 2002, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id: packet-spnego.c,v 1.3 2002/08/28 00:19:10 sharpe Exp $
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

#define SPNEGO_negTokenInit 0
#define SPNEGO_negTokenTarg 1
#define SPNEGO_mechTypes 0
#define SPNEGO_reqFlags 1
#define SPNEGO_mechToken 2
#define SPNEGO_mechListMIC 3
#define SPNEGO_negResult 0
#define SPNEGO_accept_completed 0
#define SPNEGO_accept_incomplete 1
#define SPNEGO_reject 2
#define SPNEGO_supportedMech 1
#define SPNEGO_responseToken 2
#define SPNEGO_mechListMIC 3

static int proto_spnego = -1;

static int hf_spnego = -1;
static int hf_spnego_neg_token_init = -1;
static int hf_spnego_neg_token_targ = -1; 

static gint ett_spnego = -1;

/*
 * XXX: Fixme. This thould be made global ...
 */

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

static void
dissect_spnego_negTokenInit(tvbuff_t *tvb, packet_info *pinfo _U_, 
			    proto_tree *tree, ASN1_SCK *hnd)
{
	proto_item *item;
	proto_tree *subtree;
	gboolean def;
	guint len1, len, cls, con, tag, nbytes;
	subid_t *oid;
	gssapi_oid_value *value;
	dissector_handle_t handle;
	gchar *oid_string;
	proto_item *sub_item;
	proto_tree *oid_subtree;
	int ret, offset = 0;

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

	while (len1) {

	  /*
	   * Another context header ... It could be MechTypeList, but that
	   * is optional, Hmmm ... what if it was empty?
	   */

	  ret = asn1_header_decode(hnd, &cls, &con, &tag, &def, &len);

	  if (ret != ASN1_ERR_NOERROR) {
	    dissect_parse_error(tvb, offset, pinfo, subtree,
				"SPNEGO context header", ret);
	    goto done;
	  }

	  if (!(cls == ASN1_CTX && con == ASN1_CON && tag == 0)) {
	    proto_tree_add_text(
				subtree, tvb, offset, 0,
				"Unknown header (cls=%d, con=%d, tag=%d)",
				cls, con, tag);
	    goto done;
	  }

	  /* Should be one of the fields */

	  switch (tag) {

	  case SPNEGO_mechTypes:

	    break;

	  case SPNEGO_reqFlags:

	    break;

	  case SPNEGO_mechToken:

	    break;

	  case SPNEGO_mechListMIC:

	    break;

	  default:

	    break;
	  }

	  len1 -= len;

	}

	/* 
	 * Last sequence header and then the ObjID.
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

	/*
	 * Now, the object ID ... 
	 */

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

	/* Now get the offset. Assume 4 btyes to go ... */

	/* Hand off to subdissector */

	if (((value = g_hash_table_lookup(gssapi_oids, oid_string)) == NULL) ||
	    !proto_is_protocol_enabled(value->proto)) {

		/* No dissector for this oid */

		proto_tree_add_text(
			subtree, tvb, offset, 
			tvb_length_remaining(tvb, offset), "Token object");

		goto done;
	}

	sub_item = proto_tree_add_item(subtree, value->proto, tvb, offset,
				       -1, FALSE);

	oid_subtree = proto_item_add_subtree(sub_item, value->ett);

	handle = find_dissector(value->name);

	if (handle) {
		tvbuff_t *oid_tvb;

		oid_tvb = tvb_new_subset(tvb, offset + 4, -1, -1);
		call_dissector(handle, oid_tvb, pinfo, oid_subtree);
	}

 done:
} 

static void
dissect_spnego_negTokenTarg(tvbuff_t *tvb, packet_info *pinfo _U_, 
			    proto_tree *tree)

{
	proto_item *item;
	proto_tree *subtree;

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
	guint len1, len, cls, con, tag, nbytes;

	item = proto_tree_add_item(
		tree, hf_spnego, tvb, offset, length, FALSE);

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

	if (!(cls == ASN1_CTX && con == ASN1_CON && tag == 0)) {
		proto_tree_add_text(
			subtree, tvb, offset, 0,
			"Unknown header (cls=%d, con=%d, tag=%d)",
			cls, con, tag);
		goto done;
	}

	/* 
	 * The Tag is one of negTokenInit or negTokenTarg
	 */

	switch (tag) {

	case SPNEGO_negTokenInit:

	  break;

	case SPNEGO_negTokenTarg:

	  break;

	default: /* Broken, what to do? */

	  break;
	}


 done:
	asn1_close(&hnd, &offset);

}

void
proto_register_snego(void)
{
	static hf_register_info hf[] = {
		{ &hf_spnego,
		  { "SPNEGO", "Spnego", FT_NONE, BASE_NONE, NULL, 0x0, 
		    "SPNEGO", HFILL }},
	};
  
	static gint *ett[] = {
		&ett_spnego,
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
