/* packet-gssapi.c
 * Dissector for GSS-API tokens as described in rfc2078, section 3.1
 * Copyright 2002, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-gssapi.c,v 1.3 2002/08/25 19:22:20 sharpe Exp $
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

static int proto_gssapi = -1;

static int hf_gssapi = -1;

static gint ett_gssapi = -1;

/* 
 * Subdissectors
 */

static GHashTable *gssapi_oids;

typedef struct _gssapi_oid_value {
	int proto;
	int ett;
	gchar *name;
} gssapi_oid_value;

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
gssapi_init_oid(char *oid, int proto, int ett, char *name)
{
	char *key = g_strdup(oid);
	gssapi_oid_value *value = g_malloc(sizeof(*value));

	value->proto = proto;
	value->ett = ett;
	value->name = g_strdup(name);

	g_hash_table_insert(gssapi_oids, key, value);
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
	int length = tvb_length_remaining(tvb, 0);
	ASN1_SCK hnd;
	int ret, offset = 0;
	gboolean def;
	guint len1, len, cls, con, tag, nbytes;
	subid_t *oid;
	gchar *oid_string;
	gssapi_oid_value *value;
	dissector_handle_t handle;
	proto_item *sub_item;
	proto_tree *oid_subtree;

	item = proto_tree_add_item(
		tree, hf_gssapi, tvb, offset, length, FALSE);

	subtree = proto_item_add_subtree(item, ett_gssapi);

	/* Read header */

	asn1_open(&hnd, tvb, offset);
 
	ret = asn1_header_decode(&hnd, &cls, &con, &tag, &def, &len1);

	if (ret != ASN1_ERR_NOERROR) {
		dissect_parse_error(tvb, offset, pinfo, subtree,
				    "GSS-API header", ret);
		goto done;
	}

	if (!(cls == ASN1_APL && con == ASN1_CON && tag == 0)) {
		proto_tree_add_text(
			subtree, tvb, offset, 0,
			"Unknown header (cls=%d, con=%d, tag=%d)",
			cls, con, tag);
		goto done;
	}

	offset = hnd.offset;

	/* Read oid */

	ret = asn1_oid_decode(&hnd, &oid, &len, &nbytes);

	if (ret != ASN1_ERR_NOERROR) {
		dissect_parse_error(tvb, offset, pinfo, subtree,
				    "GSS-API token", ret);
		goto done;
	}

	oid_string = format_oid(oid, len);

	proto_tree_add_text(subtree, tvb, offset, nbytes, "OID: %s", 
			    oid_string);

	offset += nbytes;

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

		oid_tvb = tvb_new_subset(tvb, offset, -1, -1);
		call_dissector(handle, oid_tvb, pinfo, oid_subtree);
	}

 done:
	asn1_close(&hnd, &offset);
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
