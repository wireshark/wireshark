/* packet-gssapi.c
 * Dissector for GSS-API tokens as described in rfc2078, section 3.1
 * Copyright 2002, Tim Potter <tpot@samba.org>
 * Copyright 2002, Richard Sharpe <rsharpe@samba.org> Added a few 
 *		   bits and pieces ...
 *
 * $Id: packet-gssapi.c,v 1.19 2002/09/08 01:43:44 guy Exp $
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
#include "packet-frame.h"
#include "epan/conversation.h"

static int proto_gssapi = -1;

static int hf_gssapi = -1;

static gint ett_gssapi = -1;

/*
 * Subdissectors
 */

static GHashTable *gssapi_oids;

static gint gssapi_oid_equal(gconstpointer k1, gconstpointer k2)
{
	char *key1 = (char *)k1;
	char *key2 = (char *)k2;

	return strcmp(key1, key2) == 0;
}

static guint
gssapi_oid_hash(gconstpointer k)
{
	char *key = (char *)k;
	guint hash = 0, i;

	for (i = 0; i < strlen(key); i++)
		hash += key[i];

	return hash;
}

void
gssapi_init_oid(char *oid, int proto, int ett, dissector_handle_t handle,
		gchar *comment)
{
	char *key = g_strdup(oid);
	gssapi_oid_value *value = g_malloc(sizeof(*value));

	value->proto = proto;
	value->ett = ett;
	value->handle = handle;
	value->comment = comment;

	g_hash_table_insert(gssapi_oids, key, value);
}

/*
 * This takes an OID in binary form, not an OID as a text string, as
 * an argument.
 */
gssapi_oid_value *
gssapi_lookup_oid(subid_t *oid, guint oid_len)
{
	gchar *oid_key;
	gchar *p;
	unsigned int i;
	int len;
	gssapi_oid_value *value;

	/*
	 * Convert the OID to a string, as text strings are used as
	 * keys in the OID hash table.
	 */
	oid_key = g_malloc(oid_len * 22 + 1);
	p = oid_key;
	len = sprintf(p, "%lu", (unsigned long)oid[0]);
	p += len;
	for (i = 1; i < oid_len;i++) {
		len = sprintf(p, ".%lu", (unsigned long)oid[i]);
		p += len;
	}

	value = g_hash_table_lookup(gssapi_oids, oid_key);
	g_free(oid_key);
	return value;
}

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
dissect_gssapi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *item;
	proto_tree *subtree;
	ASN1_SCK hnd;
	int ret, offset = 0;
	gboolean def;
	guint len1, oid_len, cls, con, tag, nbytes;
	subid_t *oid;
	gchar *oid_string;
	gssapi_oid_value *value;
	volatile dissector_handle_t handle = NULL;
	conversation_t *volatile conversation;

	/*
	 * We need this later, so lets get it now ...
	 */

	conversation = find_conversation(&pinfo->src, &pinfo->dst,
					 pinfo->ptype, pinfo->srcport,
					 pinfo->destport, 0);

	item = proto_tree_add_item(
		tree, hf_gssapi, tvb, offset, -1, FALSE);

	subtree = proto_item_add_subtree(item, ett_gssapi);

	/*
	 * Catch the ReportedBoundsError exception; the stuff we've been
	 * handed doesn't necessarily run to the end of the packet, it's
	 * an item inside a packet, so if it happens to be malformed (or
	 * we, or a dissector we call, has a bug), so that an exception
	 * is thrown, we want to report the error, but return and let
	 * our caller dissect the rest of the packet.
	 *
	 * If it gets a BoundsError, we can stop, as there's nothing more
	 * in the packet after our blob to see, so we just re-throw the
	 * exception.
	 */
	TRY {
		/* Read header */

		asn1_open(&hnd, tvb, offset);

		ret = asn1_header_decode(&hnd, &cls, &con, &tag, &def, &len1);

		if (ret != ASN1_ERR_NOERROR) {
			dissect_parse_error(tvb, offset, pinfo, subtree,
				    "GSS-API header", ret);
			goto done;
		}

		if (!(cls == ASN1_APL && con == ASN1_CON && tag == 0)) {
		  /* 
		   * If we do not recognise an Application class,
		   * then we are probably dealing with an inner context
		   * token, and we should retrieve the dissector from
		   * the conversation that exists or we created from pinfo
		   *
		   * Note! We cheat. Since we only need the dissector handle,
		   * We store that as the conversation data ... 
		   */

		  if (conversation && 
		      !(handle = conversation_get_proto_data(conversation, 
							     proto_gssapi))){
			proto_tree_add_text(
				subtree, tvb, offset, 0,
				"Unknown header (cls=%d, con=%d, tag=%d)",
				cls, con, tag);
			goto done;
		  }
		  else 
		  {
		    tvbuff_t *oid_tvb;

		    /* Naughty ... no way to reset the offset */
		    /* Account for the fact we have consumed part of the */
		    /* ASN.1 and we want to get it back */

		    hnd.offset = offset;
		    oid_tvb = tvb_new_subset(tvb, offset, -1, -1);
		    call_dissector(handle, oid_tvb, pinfo, subtree);
		    goto done; /* We are finished here */
		  }
		}

		offset = hnd.offset;

		/* Read oid */

		ret = asn1_oid_decode(&hnd, &oid, &oid_len, &nbytes);

		if (ret != ASN1_ERR_NOERROR) {
			dissect_parse_error(tvb, offset, pinfo, subtree,
					    "GSS-API token", ret);
			goto done;
		}

		oid_string = format_oid(oid, oid_len);

		/*
		 * Hand off to subdissector.
		 */

		if (((value = gssapi_lookup_oid(oid, oid_len)) == NULL) ||
		    !proto_is_protocol_enabled(value->proto)) {

		        proto_tree_add_text(subtree, tvb, offset, nbytes, 
					    "OID: %s",
					    oid_string);

			offset += nbytes;

			g_free(oid_string);

			/* No dissector for this oid */

			proto_tree_add_text(subtree, tvb, offset, -1,
					    "Token object");

			goto done;
		}

		if (value)
		  proto_tree_add_text(subtree, tvb, offset, nbytes, 
				      "OID: %s (%s)",
				      oid_string, value->comment);
		else
		  proto_tree_add_text(subtree, tvb, offset, nbytes, "OID: %s",
				      oid_string);

		offset += nbytes;

		g_free(oid_string);

		/*
		 * This is not needed, as the sub-dissector adds a tree
		sub_item = proto_tree_add_item(subtree, value->proto, tvb,
					       offset, -1, FALSE);

		oid_subtree = proto_item_add_subtree(sub_item, value->ett);
		*/

		handle = value->handle;

		if (handle) {
			tvbuff_t *oid_tvb;

			/* 
			 * Here we should create a conversation if needed and 
			 * save the OID and dissector handle in it for the 
			 * GSSAPI protocol.
			 */

			if (!conversation) { /* Create one */
			  conversation = conversation_new(&pinfo->src,
							  &pinfo->dst, 
							  pinfo->ptype, 
							  pinfo->srcport, 
							  pinfo->destport, 0);
			}

			/*
			 * Now add the proto data ... 
			 * but only if it is not already there.
			 */

			if (!conversation_get_proto_data(conversation,
							 proto_gssapi)) {
			  conversation_add_proto_data(conversation,
						      proto_gssapi, handle);
			}

			oid_tvb = tvb_new_subset(tvb, offset, -1, -1);
			call_dissector(handle, oid_tvb, pinfo, subtree);
		}
		else { /* FIXME, do something if handle not found */

		}

	 done:
		asn1_close(&hnd, &offset);
	} CATCH(BoundsError) {
		RETHROW;
	} CATCH(ReportedBoundsError) {
		show_reported_bounds_error(tvb, pinfo, tree);
	} ENDTRY;
}

void
proto_register_gssapi(void)
{
	static hf_register_info hf[] = {
		{ &hf_gssapi,
		  { "GSS-API", "gss-api", FT_NONE, BASE_NONE, NULL, 0x0,
		    "GSS-API", HFILL }},
	};

	static gint *ett[] = {
		&ett_gssapi,
	};

	proto_gssapi = proto_register_protocol(
		"Generic Security Service Application Program Interface",
		"GSS-API", "gss-api");

	proto_register_field_array(proto_gssapi, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("gssapi", dissect_gssapi, proto_gssapi);

	gssapi_oids = g_hash_table_new(gssapi_oid_hash, gssapi_oid_equal);
}

void
proto_reg_handoff_gssapi(void)
{
	data_handle = find_dissector("data");
}
