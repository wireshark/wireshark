/*#define DEBUG_BER 1*/
/* TODO: change #.REGISTER signature to new_dissector_t and
 * update call_ber_oid_callback() accordingly.
 *
 * Since we don't pass the TAG/LENGTH from the CHOICE/SEQUENCE/SEQUENCE OF/
 * SET OF helpers through the callbacks to the next pabket-ber helper
 * when the tags are IMPLICIT, this causes a problem when we also have
 * indefinite length at the same time as the tags are implicit.
 *
 * While the proper fix is to change the signatures for packet-ber.c helpers
 * as well as the signatures for the callbacks to include the indefinite length
 * indication that would be a major job.
 *
 * Originally we used a kludge - we set a global variable in the
 * CHOICE/SEQUENCE [OF]/SET [OF] helpers to indicate to the next helper
 * whether the length is indefinite or not.
 * That had currently only been implemented for {SEQUENCE|SET} [OF] but not
 * CHOICE.
 *
 * This version attacks the problem(s) in a different way.  If we see
 * indefinite length the get_ber_length traverses the tags within the
 * compound value and then we return the true length of the compound value
 * including the EOC. Thus the tvb length is now always correct even for
 * indefinite length, then if we get implicit tags they can be handled as
 * if they were definite length.
 */

/* packet-ber.c
 * Helpers for ASN.1/BER dissection
 * Ronnie Sahlberg (C) 2004
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * ITU-T Recommendation X.690 (07/2002),
 *   Information technology ASN.1 encoding rules:
 *     Specification of Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/to_str.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/oids.h>
#include <epan/expert.h>
#include <epan/uat.h>
#include <epan/asn1.h>

#include "packet-ber.h"

static gint proto_ber = -1;
static gint hf_ber_id_class = -1;
static gint hf_ber_id_pc = -1;
static gint hf_ber_id_uni_tag = -1;
static gint hf_ber_id_uni_tag_ext = -1;
static gint hf_ber_id_tag = -1;
static gint hf_ber_id_tag_ext = -1;
static gint hf_ber_length = -1;
static gint hf_ber_bitstring_padding = -1;
static gint hf_ber_bitstring_empty = -1;
static gint hf_ber_unknown_OID = -1;
static gint hf_ber_unknown_BOOLEAN = -1;
static gint hf_ber_unknown_OCTETSTRING = -1;
static gint hf_ber_unknown_BER_OCTETSTRING = -1;
static gint hf_ber_unknown_BER_primitive = -1;
static gint hf_ber_unknown_GraphicString = -1;
static gint hf_ber_unknown_NumericString = -1;
static gint hf_ber_unknown_PrintableString = -1;
static gint hf_ber_unknown_TeletexString = -1;
static gint hf_ber_unknown_VisibleString = -1;
static gint hf_ber_unknown_GeneralString = -1;
static gint hf_ber_unknown_UniversalString = -1;
static gint hf_ber_unknown_BMPString = -1;
static gint hf_ber_unknown_IA5String = -1;
static gint hf_ber_unknown_UTCTime = -1;
static gint hf_ber_unknown_UTF8String = -1;
static gint hf_ber_unknown_GeneralizedTime = -1;
static gint hf_ber_unknown_INTEGER = -1;
static gint hf_ber_unknown_BITSTRING = -1;
static gint hf_ber_unknown_ENUMERATED = -1;
static gint hf_ber_error = -1;
static gint hf_ber_no_oid = -1;
static gint hf_ber_no_syntax = -1;
static gint hf_ber_oid_not_implemented = -1;
static gint hf_ber_syntax_not_implemented = -1;
static gint hf_ber_direct_reference = -1;         /* OBJECT_IDENTIFIER */
static gint hf_ber_indirect_reference = -1;       /* INTEGER */
static gint hf_ber_data_value_descriptor = -1;    /* ObjectDescriptor */
static gint hf_ber_encoding = -1;                 /* T_encoding */
static gint hf_ber_single_ASN1_type = -1;         /* T_single_ASN1_type */
static gint hf_ber_octet_aligned = -1;            /* OCTET_STRING */
static gint hf_ber_arbitrary = -1;                /* BIT_STRING */

static int hf_ber_fragments = -1;
static int hf_ber_fragment = -1;
static int hf_ber_fragment_overlap = -1;
static int hf_ber_fragment_overlap_conflicts = -1;
static int hf_ber_fragment_multiple_tails = -1;
static int hf_ber_fragment_too_long_fragment = -1;
static int hf_ber_fragment_error = -1;
static int hf_ber_fragment_count = -1;
static int hf_ber_reassembled_in = -1;
static int hf_ber_reassembled_length = -1;

static gint ett_ber_octet_string = -1;
static gint ett_ber_reassembled_octet_string = -1;
static gint ett_ber_primitive = -1;
static gint ett_ber_unknown = -1;
static gint ett_ber_SEQUENCE = -1;
static gint ett_ber_EXTERNAL = -1;
static gint ett_ber_T_encoding = -1;
static gint ett_ber_fragment = -1;
static gint ett_ber_fragments = -1;

static gboolean show_internal_ber_fields = FALSE;
static gboolean decode_octetstring_as_ber = FALSE;
static gboolean decode_primitive_as_ber = FALSE;
static gboolean decode_unexpected = FALSE;

static gchar *decode_as_syntax = NULL;
static gchar *ber_filename = NULL;

static dissector_table_t ber_oid_dissector_table=NULL;
static dissector_table_t ber_syntax_dissector_table=NULL;
static GHashTable *syntax_table=NULL;

static gint8 last_class;
static gboolean last_pc;
static gint32 last_tag;
static guint32 last_length;
static gboolean last_ind;

static const value_string ber_class_codes[] = {
	{ BER_CLASS_UNI,	"UNIVERSAL" },
	{ BER_CLASS_APP,	"APPLICATION" },
	{ BER_CLASS_CON,	"CONTEXT" },
	{ BER_CLASS_PRI,	"PRIVATE" },
	{ 0, NULL }
};

static const true_false_string ber_pc_codes = {
	"Constructed Encoding",
	"Primitive Encoding"
};

static const true_false_string ber_pc_codes_short = {
	"constructed",
	"primitive"
};

static const value_string ber_uni_tag_codes[] = {
	{ BER_UNI_TAG_EOC, 				"'end-of-content'" },
	{ BER_UNI_TAG_BOOLEAN, 			"BOOLEAN" },
	{ BER_UNI_TAG_INTEGER,			"INTEGER" },
	{ BER_UNI_TAG_BITSTRING,		"BIT STRING" },
	{ BER_UNI_TAG_OCTETSTRING,		"OCTET STRING" },
	{ BER_UNI_TAG_NULL,				"NULL" },
	{ BER_UNI_TAG_OID,				"OBJECT IDENTIFIER" },
	{ BER_UNI_TAG_ObjectDescriptor, "ObjectDescriptor" },
	{ BER_UNI_TAG_EXTERNAL,			"EXTERNAL" },
	{ BER_UNI_TAG_REAL,				"REAL" },
	{ BER_UNI_TAG_ENUMERATED,		"ENUMERATED" },
	{ BER_UNI_TAG_EMBEDDED_PDV,		"EMBEDDED PDV" },
	{ BER_UNI_TAG_UTF8String,		"UTF8String" },
	{ BER_UNI_TAG_RELATIVE_OID,		"RELATIVE-OID" },
	/* UNIVERSAL 14-15
	 * Reserved for future editions of this
	 * Recommendation | International Standard
	 */
	{  14,		"Reserved for future editions" },
	{  15 ,		"Reserved for future editions" },

	{ BER_UNI_TAG_SEQUENCE,			"SEQUENCE" },
	{ BER_UNI_TAG_SET,				"SET" },
	{ BER_UNI_TAG_NumericString,	"NumericString" },
	{ BER_UNI_TAG_PrintableString,	"PrintableString" },
	{ BER_UNI_TAG_TeletexString,	"TeletexString, T61String" },
	{ BER_UNI_TAG_VideotexString,	"VideotexString" },
	{ BER_UNI_TAG_IA5String,		"IA5String" },
	{ BER_UNI_TAG_UTCTime,			"UTCTime" },
	{ BER_UNI_TAG_GeneralizedTime,	"GeneralizedTime" },
	{ BER_UNI_TAG_GraphicString,	"GraphicString" },
	{ BER_UNI_TAG_VisibleString,	"VisibleString, ISO64String" },
	{ BER_UNI_TAG_GeneralString,	"GeneralString" },
	{ BER_UNI_TAG_UniversalString,	"UniversalString" },
	{ BER_UNI_TAG_CHARACTERSTRING,	"CHARACTER STRING" },
	{ BER_UNI_TAG_BMPString,		"BMPString" },
	{ 31,							"Continued" },
	{ 0, NULL }
};
static value_string_ext ber_uni_tag_codes_ext = VALUE_STRING_EXT_INIT(ber_uni_tag_codes);

static const true_false_string ber_real_binary_vals = {
	"Binary encoding",
	"Decimal encoding"
};

static const true_false_string ber_real_decimal_vals = {
	"SpecialRealValue",
	"Decimal encoding "
};

typedef struct _da_data {
  GHFunc   func;
  gpointer user_data;
} da_data;

typedef struct _oid_user_t {
  char *oid;
  char *name;
  char *syntax;
} oid_user_t;

UAT_CSTRING_CB_DEF(oid_users, oid, oid_user_t);
UAT_CSTRING_CB_DEF(oid_users, name, oid_user_t);
UAT_VS_CSTRING_DEF(oid_users, syntax, oid_user_t, 0, "");

static oid_user_t *oid_users;
static guint num_oid_users;

#define MAX_SYNTAX_NAMES 128
/* Define non_const_value_string as a hack to prevent chackAPIs.pl from complaining */
#define non_const_value_string value_string
static non_const_value_string syntax_names[MAX_SYNTAX_NAMES+1] = {
  {0, ""},
  {0, NULL}
};

/*
 * Set a limit on recursion so we don't blow away the stack. Another approach
 * would be to remove recursion completely but then we'd exhaust CPU+memory
 * trying to read a hellabyte of nested indefinite lengths.
 * XXX - Max nesting in the ASN.1 plugin is 32. Should they match?
 */
#define BER_MAX_NESTING 500

static const fragment_items octet_string_frag_items = {
	/* Fragment subtrees */
	&ett_ber_fragment,
	&ett_ber_fragments,
	/* Fragment fields */
	&hf_ber_fragments,
	&hf_ber_fragment,
	&hf_ber_fragment_overlap,
	&hf_ber_fragment_overlap_conflicts,
	&hf_ber_fragment_multiple_tails,
	&hf_ber_fragment_too_long_fragment,
	&hf_ber_fragment_error,
	&hf_ber_fragment_count,
	/* Reassembled in field */
	&hf_ber_reassembled_in,
	/* Reassembled length field */
	&hf_ber_reassembled_length,
	/* Tag */
	"OCTET STRING fragments"
};

static void *
oid_copy_cb(void *dest, const void *orig, size_t len _U_)
{
	oid_user_t *u = dest;
	const oid_user_t *o = orig;

	u->oid = g_strdup(o->oid);
	u->name = g_strdup(o->name);
	u->syntax = o->syntax;

	return dest;
}

static void
oid_free_cb(void *r)
{
	oid_user_t *u = r;

	g_free(u->oid);
	g_free(u->name);
}

static int
cmp_value_string(const void *v1, const void *v2)
{
  value_string *vs1 = (value_string *)v1;
  value_string *vs2 = (value_string *)v2;

  return strcmp(vs1->strptr, vs2->strptr);
}

static uat_field_t users_flds[] = {
  UAT_FLD_OID(oid_users, oid, "OID", "Object Identifier"),
  UAT_FLD_CSTRING(oid_users, name, "Name", "Human readable name for the OID"),
  UAT_FLD_VS(oid_users, syntax, "Syntax", syntax_names, "Syntax of values associated with the OID"),
  UAT_END_FIELDS
};

void
dissect_ber_oid_NULL_callback(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_)
{
	return;
}


void
register_ber_oid_dissector_handle(const char *oid, dissector_handle_t dissector, int proto _U_, const char *name)
{
	dissector_add_string("ber.oid", oid, dissector);
	oid_add_from_string(name, oid);
}

void
register_ber_oid_dissector(const char *oid, dissector_t dissector, int proto, const char *name)
{
	dissector_handle_t dissector_handle;

	dissector_handle=create_dissector_handle(dissector, proto);
	dissector_add_string("ber.oid", oid, dissector_handle);
	oid_add_from_string(name, oid);
}

void
register_ber_syntax_dissector(const char *syntax, int proto, dissector_t dissector)
{
  dissector_handle_t dissector_handle;

  dissector_handle=create_dissector_handle(dissector, proto);
  dissector_add_string("ber.syntax", syntax, dissector_handle);

}

void
register_ber_oid_syntax(const char *oid, const char *name, const char *syntax)
{

  if(syntax && *syntax)
    g_hash_table_insert(syntax_table, (gpointer)g_strdup(oid), (gpointer)g_strdup(syntax));

  if(name && *name)
    register_ber_oid_name(oid, name);
}

/* Register the oid name to get translation in proto dissection */
void
register_ber_oid_name(const char *oid, const char *name)
{
	oid_add_from_string(name, oid);
}

static void
ber_add_syntax_name(gpointer key, gpointer value _U_, gpointer user_data)
{
  guint *i = (guint*)user_data;

  if(*i < MAX_SYNTAX_NAMES) {
    syntax_names[*i].value = *i;
    syntax_names[*i].strptr = (const gchar*)key;

    (*i)++;
  }

}

static void ber_decode_as_dt(const gchar *table_name _U_, ftenum_t selector_type _U_, gpointer key, gpointer value, gpointer user_data)
{
  da_data *decode_as_data;

  decode_as_data = (da_data *)user_data;

  decode_as_data->func(key, value, decode_as_data->user_data);
}

void ber_decode_as_foreach(GHFunc func, gpointer user_data)
{
  da_data decode_as_data;

  decode_as_data.func = func;
  decode_as_data.user_data = user_data;

  dissector_table_foreach("ber.syntax",  ber_decode_as_dt, &decode_as_data);

}

void ber_decode_as(const gchar *syntax)
{

  if(decode_as_syntax) {
    g_free(decode_as_syntax);
    decode_as_syntax = NULL;
  }

  if(syntax)
    decode_as_syntax = g_strdup(syntax);
}

/* Get oid syntax from hash table to get translation in proto dissection(packet-per.c) */
static const gchar *
get_ber_oid_syntax(const char *oid)
{
       return g_hash_table_lookup(syntax_table, oid);
}

void ber_set_filename(gchar *filename)
{
  gchar      *ptr;

  if(ber_filename) {
    g_free(ber_filename);
    ber_filename = NULL;
  }

  if(filename) {

    ber_filename = g_strdup(filename);

    if((ptr = strrchr(ber_filename, '.')) != NULL) {

      ber_decode_as(get_ber_oid_syntax(ptr));

    }
  }
}


static void
ber_update_oids(void)
{
  guint i;

  for(i = 0; i < num_oid_users; i++)
    register_ber_oid_syntax(oid_users[i].oid, oid_users[i].name, oid_users[i].syntax);
}

static void
ber_check_length (guint32 length, gint32 min_len, gint32 max_len, asn1_ctx_t *actx, proto_item *item, gboolean bit)
{
  if (min_len != -1 && length < (guint32)min_len) {
    expert_add_info_format(actx->pinfo, item, PI_PROTOCOL, PI_WARN, "Size constraint: %sstring too short: %d (%d .. %d)", bit ? "bit " : "", length, min_len, max_len);
  } else if (max_len != -1 && length > (guint32)max_len) {
    expert_add_info_format(actx->pinfo, item, PI_PROTOCOL, PI_WARN, "Size constraint: %sstring too long: %d (%d .. %d)", bit ? "bit " : "", length, min_len, max_len);
  }
}

static void
ber_check_value64 (gint64 value, gint64 min_len, gint64 max_len, asn1_ctx_t *actx, proto_item *item)
{
  if (min_len != -1 && value < min_len) {
    expert_add_info_format(actx->pinfo, item, PI_PROTOCOL, PI_WARN, "Size constraint: value too small: %" G_GINT64_MODIFIER "d (%" G_GINT64_MODIFIER "d .. %" G_GINT64_MODIFIER "d)", value, min_len, max_len);
  } else if (max_len != -1 && value > max_len) {
    expert_add_info_format(actx->pinfo, item, PI_PROTOCOL, PI_WARN, "Size constraint: value too big: %" G_GINT64_MODIFIER "d (%" G_GINT64_MODIFIER "d .. %" G_GINT64_MODIFIER "d)", value, min_len, max_len);
  }
}

static void
ber_check_value (guint32 value, gint32 min_len, gint32 max_len, asn1_ctx_t *actx, proto_item *item)
{
  if (min_len != -1 && value < (guint32)min_len) {
    expert_add_info_format(actx->pinfo, item, PI_PROTOCOL, PI_WARN, "Size constraint: value too small: %d (%d .. %d)", value, min_len, max_len);
  } else if (max_len != -1 && value > (guint32)max_len) {
    expert_add_info_format(actx->pinfo, item, PI_PROTOCOL, PI_WARN, "Size constraint: value too big: %d (%d .. %d)", value, min_len, max_len);
  }
}

static void
ber_check_items (int cnt, gint32 min_len, gint32 max_len, asn1_ctx_t *actx, proto_item *item)
{
  if (min_len != -1 && cnt < min_len) {
    expert_add_info_format(actx->pinfo, item, PI_PROTOCOL, PI_WARN, "Size constraint: too few items: %d (%d .. %d)", cnt, min_len, max_len);
  } else if (max_len != -1 && cnt > max_len) {
    expert_add_info_format(actx->pinfo, item, PI_PROTOCOL, PI_WARN, "Size constraint: too many items: %d (%d .. %d)", cnt, min_len, max_len);
  }
}

int dissect_ber_tagged_type(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, gint8 tag_cls, gint32 tag_tag, gboolean tag_impl, ber_type_fn type)
{
 gint8 tmp_cls;
 gint32 tmp_tag;
 guint32 tmp_len;
 tvbuff_t *next_tvb = tvb;
 proto_item *cause;

#ifdef DEBUG_BER
{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("dissect_ber_tagged_type(%s) entered implicit_tag:%d offset:%d len:%d %02x:%02x:%02x\n",name,implicit_tag,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("dissect_ber_tagged_type(%s) entered\n",name);
}
}
#endif

 if (implicit_tag) {
	offset = type(tag_impl, tvb, offset, actx, tree, hf_id);
	return offset;
 }

 offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &tmp_cls, NULL, &tmp_tag);
 offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &tmp_len, NULL);

 if ((tmp_cls != tag_cls) || (tmp_tag != tag_tag)) {
   cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, tmp_len, "wrong_tag",
		"BER Error: Wrong tag in tagged type - expected class:%s(%d) tag:%d (%s) but found class:%s(%d) tag:%d",
		val_to_str(tag_cls, ber_class_codes, "Unknown"), tag_cls, tag_tag, val_to_str_ext(tag_tag, &ber_uni_tag_codes_ext,"Unknown"),
		val_to_str(tmp_cls, ber_class_codes, "Unknown"), tmp_cls, tmp_tag);
   expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Wrong tag in tagged type");
 }

 if (tag_impl) {
	next_tvb = tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset), tmp_len);
	type(tag_impl, next_tvb, 0, actx, tree, hf_id);
	offset += tmp_len;
 } else {
	offset = type(tag_impl, tvb, offset, actx, tree, hf_id);
 }

 return offset;
}

/*
 * Add a "length bogus" error.
 */
static proto_item *
ber_add_bad_length_error(packet_info *pinfo, proto_tree *tree,
                         const char *name, tvbuff_t *tvb, const gint start,
                         gint length)
{
	proto_item *ti;

	ti = proto_tree_add_string_format(tree, hf_ber_error, tvb, start, length, "illegal_length",
	    "%s: length of item (%d) is not valid", name, length);
	expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_WARN,
	    "Length of item (%d) is not valid", length);
	return ti;
}

/*
 * Like proto_tree_add_item(), but checks whether the length of the item
 * being added is appropriate for the type of the item being added, so
 * if it's not, we report an error rather than a dissector bug.
 *
 * This is for use when a field that's nominally an OCTET STRING but
 * where we want the string further interpreted, e.g. as a number or
 * a network address or a UN*X-style time stamp.
 *
 * XXX - this duplicates the length checking in proto_tree_add_item()
 * and the routines it calls; that should really be done in one
 * place.  We *do* want to report a dissector bug in proto_tree_add_item()
 * if the dissector explicitly says, for example, "this IPv4 address is
 * 7 bytes long", but we don't want to report a dissector bug if the
 * *packet* says "this IPv4 address is 7 bytes long", we want to report
 * a malformed packet.
 */
static proto_item *
ber_proto_tree_add_item(packet_info *pinfo, proto_tree *tree,
                        const int hfindex, tvbuff_t *tvb, const gint start,
                        gint length, const guint encoding)
{
	header_field_info *hfinfo;

	hfinfo = proto_registrar_get_nth((guint)hfindex);
	if (hfinfo != NULL) {
		switch (hfinfo->type) {

		case FT_BOOLEAN:
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			if (length != 1 && length != 2 && length != 3 &&
			    length != 4)
				return ber_add_bad_length_error(pinfo, tree,
				    hfinfo->name, tvb, start, length);
			break;

		case FT_IPv4:
			if (length != FT_IPv4_LEN)
				return ber_add_bad_length_error(pinfo, tree,
				    hfinfo->name, tvb, start, length);
			break;

		case FT_IPXNET:
			if (length != FT_IPXNET_LEN)
				return ber_add_bad_length_error(pinfo, tree,
				    hfinfo->name, tvb, start, length);
			break;

		case FT_IPv6:
			if (length < 0 || length > FT_IPv6_LEN)
				return ber_add_bad_length_error(pinfo, tree,
				    hfinfo->name, tvb, start, length);
			break;

		case FT_ETHER:
			if (length != FT_ETHER_LEN)
				return ber_add_bad_length_error(pinfo, tree,
				    hfinfo->name, tvb, start, length);
			break;

		case FT_GUID:
			if (length != FT_GUID_LEN)
				return ber_add_bad_length_error(pinfo, tree,
				    hfinfo->name, tvb, start, length);
			break;

		case FT_FLOAT:
			if (length != 4)
				return ber_add_bad_length_error(pinfo, tree,
				    hfinfo->name, tvb, start, length);
			break;

		case FT_DOUBLE:
			if (length != 8)
				return ber_add_bad_length_error(pinfo, tree,
				    hfinfo->name, tvb, start, length);
			break;

		case FT_ABSOLUTE_TIME:
		case FT_RELATIVE_TIME:
			if (length != 4 && length != 8)
				return ber_add_bad_length_error(pinfo, tree,
				    hfinfo->name, tvb, start, length);
			break;

		default:
			break;
		}
	}
	return proto_tree_add_item(tree, hfindex, tvb, start, length, encoding);
}

static int
try_dissect_unknown_ber(packet_info *pinfo, tvbuff_t *tvb, volatile int offset, proto_tree *tree, gint nest_level)
{
	int start_offset;
	gint8 class;
	gboolean pc, ind;
	gint32 tag;
	guint32 len;
	int hdr_len;
	proto_item *item=NULL;
	proto_tree *next_tree=NULL;
	guint8 c;
	guint32 i;
	gboolean is_printable;
	volatile gboolean is_decoded_as;
	proto_item *pi, *cause;
	asn1_ctx_t asn1_ctx;

	if (nest_level > BER_MAX_NESTING) {
		/* Assume that we have a malformed packet. */
		THROW(ReportedBoundsError);
	}

	start_offset=offset;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	offset=get_ber_identifier(tvb, offset, &class, &pc, &tag);
	offset=get_ber_length(tvb, offset, &len, &ind);

	if(len>(guint32)tvb_length_remaining(tvb, offset)){
		/* hmm   maybe something bad happened or the frame is short,
		   since these are not vital outputs just return instead of
		   throwing an exception.
		 */

	        if(show_internal_ber_fields) {
		  offset=dissect_ber_identifier(pinfo, tree, tvb, start_offset, &class, &pc, &tag);
		  offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, NULL);
	        }
		cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "illegal_length", "BER Error: length:%u longer than tvb_length_remaining:%d",len, tvb_length_remaining(tvb, offset));
		expert_add_info_format(pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error length");
		return tvb_length(tvb);
	}
/* we dont care about the class only on the constructor flag */
	switch(pc){

	case FALSE: /* this is not constructed */

	  switch(class) { /* we do care about the class */
	  case BER_CLASS_UNI: /* it a Universal tag - we can decode it */
		switch(tag){
		case BER_UNI_TAG_EOC:
		  /* XXX: shouldn't really get here */
		  break;
		case BER_UNI_TAG_INTEGER:
			offset = dissect_ber_integer(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_INTEGER, NULL);
			break;
		case BER_UNI_TAG_BITSTRING:
			offset = dissect_ber_bitstring(FALSE, &asn1_ctx, tree, tvb, start_offset, NULL, hf_ber_unknown_BITSTRING, -1, NULL);
			break;
		case BER_UNI_TAG_ENUMERATED:
			offset = dissect_ber_integer(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_ENUMERATED, NULL);
			break;
		case BER_UNI_TAG_GraphicString:
			offset = dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_GraphicString, NULL);
			break;
		case BER_UNI_TAG_OCTETSTRING:
			is_decoded_as = FALSE;
			if (decode_octetstring_as_ber && len >= 2) {
				volatile int ber_offset = 0;
				guint32 ber_len = 0;
				TRY {
					ber_offset = get_ber_identifier(tvb, offset, NULL, &pc, NULL);
					ber_offset = get_ber_length(tvb, ber_offset, &ber_len, NULL);
				} CATCH_ALL {
				}
				ENDTRY;
				if (pc && (ber_len > 0) && (ber_len + (ber_offset - offset) == len)) {
					/* Decoded a constructed ASN.1 tag with a length indicating this
					 * could be BER encoded data.  Try dissecting as unknown BER.
					 */
					is_decoded_as = TRUE;
					if (show_internal_ber_fields) {
						offset = dissect_ber_identifier(pinfo, tree, tvb, start_offset, NULL, NULL, NULL);
						offset = dissect_ber_length(pinfo, tree, tvb, offset, NULL, NULL);
					}
					item = ber_proto_tree_add_item(pinfo, tree, hf_ber_unknown_BER_OCTETSTRING, tvb, offset, len, ENC_NA);
					next_tree = proto_item_add_subtree(item, ett_ber_octet_string);
					offset = try_dissect_unknown_ber(pinfo, tvb, offset, next_tree, nest_level+1);
				}
			}
			if (!is_decoded_as) {
				offset = dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_OCTETSTRING, NULL);
			}
			break;
		case BER_UNI_TAG_OID:
			offset=dissect_ber_object_identifier_str(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_OID, NULL);
			break;
		case BER_UNI_TAG_NumericString:
			offset = dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_NumericString, NULL);
			break;
		case BER_UNI_TAG_PrintableString:
			offset = dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_PrintableString, NULL);
			break;
		case BER_UNI_TAG_TeletexString:
			offset = dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_TeletexString, NULL);
			break;
		case BER_UNI_TAG_VisibleString:
			offset = dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_VisibleString, NULL);
			break;
		case BER_UNI_TAG_GeneralString:
			offset = dissect_ber_GeneralString(&asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_GeneralString, NULL, 0);
			break;
		case BER_UNI_TAG_BMPString:
			offset = dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_BMPString, NULL);
			break;
		case BER_UNI_TAG_UniversalString:
			offset = dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_UniversalString, NULL);
			break;
		case BER_UNI_TAG_IA5String:
			offset = dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_IA5String, NULL);
			break;
		case BER_UNI_TAG_UTCTime:
			offset = dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_UTCTime, NULL);
			break;
		case BER_UNI_TAG_NULL:
			proto_tree_add_text(tree, tvb, offset, len, "NULL tag");
			break;
		case BER_UNI_TAG_UTF8String:
			offset = dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_UTF8String, NULL);
			break;
		case BER_UNI_TAG_GeneralizedTime:
			offset = dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_GeneralizedTime, NULL);
			break;
		case BER_UNI_TAG_BOOLEAN:
			offset = dissect_ber_boolean(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_BOOLEAN, NULL);
			break;
		default:
			offset=dissect_ber_identifier(pinfo, tree, tvb, start_offset, &class, &pc, &tag);
			offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, NULL);
			cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "unknown_universal_tag", "BER Error: can not handle universal tag:%d",tag);
			expert_add_info_format(pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: can not handle universal");
			offset += len;
		}
		break;
	  case BER_CLASS_APP:
	  case BER_CLASS_CON:
	  case BER_CLASS_PRI:
	  default:
	    /* we dissect again if show_internal_ber_fields is set */
	    if(show_internal_ber_fields) {
	      offset=dissect_ber_identifier(pinfo, tree, tvb, start_offset, &class, &pc, &tag);
	      offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, NULL);
	    }

	    /* we can't dissect this directly as it is specific */
	    pi = proto_tree_add_none_format(tree, hf_ber_unknown_BER_primitive, tvb, offset, len,
					    "[%s %d] ", val_to_str(class,ber_class_codes,"Unknown"), tag);

	    is_decoded_as = FALSE;
	    if (decode_primitive_as_ber && len >= 2) {
	      volatile int ber_offset = 0;
	      guint32 ber_len = 0;
	      TRY {
		ber_offset = get_ber_identifier(tvb, offset, NULL, &pc, NULL);
		ber_offset = get_ber_length(tvb, ber_offset, &ber_len, NULL);
	      } CATCH_ALL {
	      }
	      ENDTRY;
	      if (pc && (ber_len > 0) && (ber_len + (ber_offset - offset) == len)) {
		/* Decoded a constructed ASN.1 tag with a length indicating this
		 * could be BER encoded data.  Try dissecting as unknown BER.
		 */
		is_decoded_as = TRUE;
		proto_item_append_text (pi, "[BER encoded]");
		next_tree = proto_item_add_subtree(pi, ett_ber_primitive);
		offset = try_dissect_unknown_ber(pinfo, tvb, offset, next_tree, nest_level+1);
	      }
	    }

	    if (!is_decoded_as && len) {
	      /* we may want to do better and show the bytes */
	      is_printable = TRUE;
	      for(i=0;i<len;i++){
		c = tvb_get_guint8(tvb, offset+i);

		if(is_printable && !g_ascii_isprint(c))
		  is_printable=FALSE;

		proto_item_append_text(pi,"%02x",c);
	      }

	      if(is_printable) { /* give a nicer representation if it looks like a string */
		proto_item_append_text(pi," (");
		for(i=0;i<len;i++){
		  proto_item_append_text(pi,"%c",tvb_get_guint8(tvb, offset+i));
		}
		proto_item_append_text(pi,")");
	      }
	      offset += len;
	    }

	    break;
	  }
	  break;

	case TRUE: /* this is constructed */

	  /* we dissect again if show_internal_ber_fields is set */
	  if(show_internal_ber_fields) {
	    offset=dissect_ber_identifier(pinfo, tree, tvb, start_offset, &class, &pc, &tag);
	    offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, NULL);
	  }

	  hdr_len=offset-start_offset;

	  switch(class) {
	  case BER_CLASS_UNI:
       	    item=proto_tree_add_text(tree, tvb, offset, len, "%s", val_to_str_ext(tag,&ber_uni_tag_codes_ext,"Unknown"));
		if(item){
			next_tree=proto_item_add_subtree(item, ett_ber_SEQUENCE);
		}
		while(offset < (int)(start_offset + len + hdr_len))
		  offset=try_dissect_unknown_ber(pinfo, tvb, offset, next_tree, nest_level+1);
		break;
	  case BER_CLASS_APP:
	  case BER_CLASS_CON:
	  case BER_CLASS_PRI:
	  default:
       	    item=proto_tree_add_text(tree, tvb, offset, len, "[%s %d]", val_to_str(class,ber_class_codes,"Unknown"), tag);
		if(item){
			next_tree=proto_item_add_subtree(item, ett_ber_SEQUENCE);
		}
		while(offset < (int)(start_offset + len + hdr_len))
		  offset=try_dissect_unknown_ber(pinfo, tvb, offset, next_tree, nest_level+1);
		break;

	  }
	  break;

	}

	return offset;
}

int
dissect_unknown_ber(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree)
{
	return try_dissect_unknown_ber(pinfo, tvb, offset, tree, 1);
}

int
call_ber_oid_callback(const char *oid, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	tvbuff_t *next_tvb;
	const char *syntax = NULL;

	if (!tvb) {
		return offset;
	}

	next_tvb = tvb_new_subset_remaining(tvb, offset);
	if(oid == NULL ||
	   ((((syntax = get_ber_oid_syntax(oid)) == NULL) ||
	     /* First see if a syntax has been registered for this oid (user defined) */
	     !dissector_try_string(ber_syntax_dissector_table, syntax, next_tvb, pinfo, tree)) &&
	    /* Then try registered oid's */
	    (!dissector_try_string(ber_oid_dissector_table, oid, next_tvb, pinfo, tree)))) {
		proto_item *item=NULL;
		proto_tree *next_tree=NULL;
		gint length_remaining;

		length_remaining = tvb_length_remaining(tvb, offset);

		if (oid == NULL) {
		  item=proto_tree_add_none_format(tree, hf_ber_no_oid, next_tvb, 0, length_remaining, "BER: No OID supplied to call_ber_oid_callback");
		  expert_add_info_format(pinfo, item, PI_MALFORMED, PI_WARN, "BER Error: No OID supplied");
		} else if (tvb_get_ntohs (tvb, offset) != 0x0500) { /* Not NULL tag */
		  if(syntax)
		    item=proto_tree_add_none_format(tree, hf_ber_syntax_not_implemented, next_tvb, 0, length_remaining, "BER: Dissector for syntax:%s not implemented. Contact Wireshark developers if you want this supported", syntax);
		  else
		    item=proto_tree_add_none_format(tree, hf_ber_oid_not_implemented, next_tvb, 0, length_remaining, "BER: Dissector for OID:%s not implemented. Contact Wireshark developers if you want this supported", oid);
		  expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN, "BER: Dissector for OID %s not implemented", oid);
		} else {
		  next_tree=tree;
		}
	        if (decode_unexpected) {
		  int ber_offset;
		  gint32 ber_len;

		  if(item){
			next_tree=proto_item_add_subtree(item, ett_ber_unknown);
		  }
		  ber_offset = get_ber_identifier(next_tvb, 0, NULL, NULL, NULL);
		  ber_offset = get_ber_length(next_tvb, ber_offset, &ber_len, NULL);
		  if ((ber_len + ber_offset) == length_remaining) {
		    /* Decoded an ASN.1 tag with a length indicating this
		     * could be BER encoded data.  Try dissecting as unknown BER.
		     */
		    dissect_unknown_ber(pinfo, next_tvb, 0, next_tree);
		  } else {
		    proto_tree_add_text(next_tree, next_tvb, 0, length_remaining,
				    "Unknown Data (%d byte%s)", length_remaining,
				    plurality(length_remaining, "", "s"));
		  }
		}

	}

	/*XXX until we change the #.REGISTER signature for _PDU()s
	 * into new_dissector_t   we have to do this kludge with
	 * manually step past the content in the ANY type.
	 */
	offset+=tvb_length_remaining(tvb, offset);

	return offset;
}

static int
call_ber_syntax_callback(const char *syntax, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	tvbuff_t *next_tvb;

	next_tvb = tvb_new_subset_remaining(tvb, offset);
	if(syntax == NULL ||
	    !dissector_try_string(ber_syntax_dissector_table, syntax, next_tvb, pinfo, tree)){
	  proto_item *item=NULL;
	  proto_tree *next_tree=NULL;

	  if (syntax == NULL)
	    item=proto_tree_add_none_format(tree, hf_ber_no_syntax, next_tvb, 0, tvb_length_remaining(tvb, offset), "BER: No syntax supplied to call_ber_syntax_callback");
	  else
	    item=proto_tree_add_none_format(tree, hf_ber_syntax_not_implemented, next_tvb, 0, tvb_length_remaining(tvb, offset), "BER: Dissector for syntax: %s not implemented. Contact Wireshark developers if you want this supported", syntax);
	  if(item){
	    next_tree=proto_item_add_subtree(item, ett_ber_unknown);
	  }
	  dissect_unknown_ber(pinfo, next_tvb, 0, next_tree);
	}

	/*XXX until we change the #.REGISTER signature for _PDU()s
	 * into new_dissector_t   we have to do this kludge with
	 * manually step past the content in the ANY type.
	 */
	offset+=tvb_length_remaining(tvb, offset);

	return offset;
}


/* 8.1 General rules for encoding */

/*  8.1.2 Identifier octets */
int get_ber_identifier(tvbuff_t *tvb, int offset, gint8 *class, gboolean *pc, gint32 *tag) {
	guint8 id, t;
	gint8 tmp_class;
	gboolean tmp_pc;
	gint32 tmp_tag;

	id = tvb_get_guint8(tvb, offset);
	offset += 1;
#ifdef DEBUG_BER
printf ("BER ID=%02x", id);
#endif
	/* 8.1.2.2 */
	tmp_class = (id>>6) & 0x03;
	tmp_pc = (id>>5) & 0x01;
	tmp_tag = id&0x1F;
	/* 8.1.2.4 */
	if (tmp_tag == 0x1F) {
		tmp_tag = 0;
		while (tvb_length_remaining(tvb, offset) > 0) {
			t = tvb_get_guint8(tvb, offset);
#ifdef DEBUG_BER
printf (" %02x", t);
#endif
			offset += 1;
			tmp_tag <<= 7;
			tmp_tag |= t & 0x7F;
			if (!(t & 0x80)) break;
		}
	}

#ifdef DEBUG_BER
printf ("\n");
#endif
	if (class)
		*class = tmp_class;
	if (pc)
		*pc = tmp_pc;
	if (tag)
		*tag = tmp_tag;

	last_class = tmp_class;
	last_pc = tmp_pc;
	last_tag = tmp_tag;

	return offset;
}

static void get_last_ber_identifier(gint8 *class, gboolean *pc, gint32 *tag)
{
	if (class)
		*class = last_class;
	if (pc)
		*pc = last_pc;
	if (tag)
		*tag = last_tag;

}

int dissect_ber_identifier(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, gint8 *class, gboolean *pc, gint32 *tag)
{
	int old_offset = offset;
	gint8 tmp_class;
	gboolean tmp_pc;
	gint32 tmp_tag;

	offset = get_ber_identifier(tvb, offset, &tmp_class, &tmp_pc, &tmp_tag);

	if(show_internal_ber_fields){
		proto_tree_add_uint(tree, hf_ber_id_class, tvb, old_offset, 1, tmp_class<<6);
		proto_tree_add_boolean(tree, hf_ber_id_pc, tvb, old_offset, 1, (tmp_pc)?0x20:0x00);
		if(tmp_tag>0x1F){
			if(tmp_class==BER_CLASS_UNI){
				proto_tree_add_uint(tree, hf_ber_id_uni_tag_ext, tvb, old_offset + 1, offset - (old_offset + 1), tmp_tag);
			} else {
				proto_tree_add_uint(tree, hf_ber_id_tag_ext, tvb, old_offset + 1, offset - (old_offset + 1), tmp_tag);
			}
		} else {
			if(tmp_class==BER_CLASS_UNI){
				proto_tree_add_uint(tree, hf_ber_id_uni_tag, tvb, old_offset, 1, tmp_tag);
			} else {
				proto_tree_add_uint(tree, hf_ber_id_tag, tvb, old_offset, 1, tmp_tag);
			}
		}
	}

	if(class)
		*class = tmp_class;
	if(pc)
		*pc = tmp_pc;
	if(tag)
		*tag = tmp_tag;

	return offset;
}

/** Try to get the length octets of the BER TLV.
 * Only (TAGs and) LENGTHs that fit inside 32 bit integers are supported.
 *
 * @return TRUE if we have the entire length, FALSE if we're in the middle of
 * an indefinite length and haven't reached EOC.
 */
/* 8.1.3 Length octets */

static int
try_get_ber_length(tvbuff_t *tvb, int offset, guint32 *length, gboolean *ind, gint nest_level) {
	guint8 oct, len;
	guint32 indef_len;
	guint32 tmp_length;
	gboolean tmp_ind;
	int tmp_offset,s_offset;
	gint8 tclass;
	gboolean tpc;
	gint32 ttag;
	tmp_length = 0;
	tmp_ind = FALSE;

	if (nest_level > BER_MAX_NESTING) {
		/* Assume that we have a malformed packet. */
		THROW(ReportedBoundsError);
	}

	oct = tvb_get_guint8(tvb, offset);
	offset += 1;

	if(!(oct&0x80)) {
		/* 8.1.3.4 */
		tmp_length = oct;
	} else {
		len = oct & 0x7F;
		if(len) {
			/* 8.1.3.5 */
			while (len--) {
				oct = tvb_get_guint8(tvb, offset);
				offset++;
				tmp_length = (tmp_length<<8) + oct;
			}
		} else {
			/* 8.1.3.6 */

			tmp_offset = offset;
			/* ok in here we can traverse the BER to find the length, this will fix most indefinite length issues */
			/* Assumption here is that indefinite length is always used on constructed types*/
			/* check for EOC */
			while (tvb_get_guint8(tvb, offset) || tvb_get_guint8(tvb, offset+1)) {
				/* not an EOC at offset */
				s_offset=offset;
				offset= get_ber_identifier(tvb, offset, &tclass, &tpc, &ttag);
				offset= try_get_ber_length(tvb,offset, &indef_len, NULL, nest_level+1);
				tmp_length += indef_len+(offset-s_offset); /* length + tag and length */
				offset += indef_len;
                                /* Make sure we've moved forward in the packet */
				if (offset <= s_offset)
					THROW(ReportedBoundsError);
			}
			tmp_length += 2;
			tmp_ind = TRUE;
			offset = tmp_offset;
		}
	}

	if (length)
		*length = tmp_length;
	if (ind)
		*ind = tmp_ind;

#ifdef DEBUG_BER
printf("get BER length %d, offset %d (remaining %d)\n", tmp_length, offset, tvb_length_remaining(tvb, offset));
#endif

	return offset;
}

int
get_ber_length(tvbuff_t *tvb, int offset, guint32 *length, gboolean *ind)
{
	return try_get_ber_length(tvb, offset, length, ind, 1);
}

static void get_last_ber_length(guint32 *length, gboolean *ind)
{
	if (length)
		*length = last_length;
	if (ind)
		*ind = last_ind;
}

/* this function dissects the length octets of the BER TLV.
 * We only handle (TAGs and) LENGTHs that fit inside 32 bit integers.
 */
int
dissect_ber_length(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, guint32 *length, gboolean *ind)
{
	int old_offset = offset;
	guint32 tmp_length;
	gboolean tmp_ind;

	offset = get_ber_length(tvb, offset, &tmp_length, &tmp_ind);

	if(show_internal_ber_fields){
		if(tmp_ind){
			proto_tree_add_text(tree, tvb, old_offset, 1, "Length: Indefinite length %d", tmp_length);
		} else {
			proto_tree_add_uint(tree, hf_ber_length, tvb, old_offset, offset - old_offset, tmp_length);
		}
	}
	if(length)
		*length = tmp_length;
	if(ind)
		*ind = tmp_ind;

#ifdef DEBUG_BER
printf("dissect BER length %d, offset %d (remaining %d)\n", tmp_length, offset, tvb_length_remaining(tvb, offset));
#endif

 last_length = tmp_length;
 last_ind = tmp_ind;

	return offset;
}

static GHashTable *octet_segment_table = NULL;
static GHashTable *octet_reassembled_table = NULL;

static void ber_defragment_init(void) {
  fragment_table_init(&octet_segment_table);
  reassembled_table_init(&octet_reassembled_table);
}

static int
reassemble_octet_string(asn1_ctx_t *actx, proto_tree *tree, gint hf_id, tvbuff_t *tvb, int offset, guint32 con_len, gboolean ind, tvbuff_t **out_tvb)
{
  fragment_data *fd_head = NULL;
  tvbuff_t *next_tvb = NULL;
  tvbuff_t *reassembled_tvb = NULL;
  guint16 dst_ref = 0;
  int start_offset = offset;
  gboolean fragment = TRUE;
  gboolean firstFragment = TRUE;

  /* so we need to consume octet strings for the given length */

  if(out_tvb)
    *out_tvb=NULL;

  if (con_len == 0) /* Zero encodings (8.7.3) */
    return offset;

  /* not sure we need this */
  actx->pinfo->fragmented = TRUE;

  while(!fd_head) {

    offset = dissect_ber_octet_string(FALSE, actx, NULL, tvb, offset, hf_id, &next_tvb);

    if (next_tvb == NULL) {
      /* Assume that we have a malformed packet. */
      THROW(ReportedBoundsError);
    }

    if(ind) {
      /* this was indefinite length - so check for EOC */

      if((tvb_get_guint8(tvb, offset)==0)&&(tvb_get_guint8(tvb, offset+1)==0)) {
	fragment = FALSE;
	/* skip past EOC */
	offset +=2;
      }
    } else {

    if((guint32)(offset - start_offset) >= con_len)
	fragment = FALSE;
    }

    if(!fragment && firstFragment) {
      /* there is only one fragment (I'm sure there's a reason it was constructed) */
      /* anyway, we can get out of here */
      gboolean pc;
      get_ber_identifier(tvb, start_offset, NULL, &pc, NULL);
      if (!pc && tree) {
	/* Only display here if not constructed */
	dissect_ber_octet_string(FALSE, actx, tree, tvb, start_offset, hf_id, NULL);
      }
      reassembled_tvb = next_tvb;
      break;
    }


    if (tvb_length(next_tvb) < 1) {
      /* Don't cause an assertion in the reassembly code. */
      THROW(ReportedBoundsError);
    }
    fd_head = fragment_add_seq_next(next_tvb, 0, actx->pinfo, dst_ref,
				    octet_segment_table,
				    octet_reassembled_table,
				    tvb_length(next_tvb),
				    fragment);

    firstFragment = FALSE;
  }

  if(fd_head) {
    if(fd_head->next) {
      /* not sure I really want to do this here - should be nearer the application where we can give it a better name*/
      proto_tree *next_tree;
      proto_item *frag_tree_item;

      reassembled_tvb = tvb_new_child_real_data(next_tvb, fd_head->data, fd_head->len, fd_head->len);

      actx->created_item = proto_tree_add_item(tree, hf_id, reassembled_tvb, 0, -1, ENC_BIG_ENDIAN);
      next_tree = proto_item_add_subtree (actx->created_item, ett_ber_reassembled_octet_string);

      add_new_data_source(actx->pinfo, reassembled_tvb, "Reassembled OCTET STRING");
      show_fragment_seq_tree(fd_head, &octet_string_frag_items, next_tree, actx->pinfo, reassembled_tvb, &frag_tree_item);
    }
  }

  if(out_tvb)
    *out_tvb = reassembled_tvb;

  /* again - not sure we need this */
  actx->pinfo->fragmented = FALSE;

  return offset;

}

/* 8.7 Encoding of an octetstring value */
int
dissect_ber_constrained_octet_string(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint32 min_len, gint32 max_len, gint hf_id, tvbuff_t **out_tvb) {
	gint8 class;
	gboolean pc, ind;
	gint32 tag;
	guint32 len;
	int hoffset;
	int end_offset;
	proto_item *it, *cause;
  guint32 i;
  guint32 len_remain;

#ifdef DEBUG_BER
{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("OCTET STRING dissect_ber_octet string(%s) entered implicit_tag:%d offset:%d len:%d %02x:%02x:%02x\n",name,implicit_tag,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("OCTET STRING dissect_ber_octet_string(%s) entered\n",name);
}
}
#endif

	if(out_tvb)
		*out_tvb=NULL;

	if (!implicit_tag) {
		hoffset = offset;
		/* read header and len for the octet string */
		offset=dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &class, &pc, &tag);
		offset=dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, &ind);
		end_offset=offset+len;

		/* sanity check: we only handle Constructed Universal Sequences */
		if ((class!=BER_CLASS_APP)&&(class!=BER_CLASS_PRI))

		if( (class!=BER_CLASS_UNI)
		  ||((tag<BER_UNI_TAG_NumericString)&&(tag!=BER_UNI_TAG_OCTETSTRING)&&(tag!=BER_UNI_TAG_UTF8String)) ){
		    tvb_ensure_bytes_exist(tvb, hoffset, 2);
		    cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "octetstring_expected", "BER Error: OctetString expected but class:%s(%d) %s tag:%d was unexpected", val_to_str(class,ber_class_codes,"Unknown"), class, pc ? ber_pc_codes_short.true_string : ber_pc_codes_short.false_string, tag);
		    expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: OctetString expected");
			if (decode_unexpected) {
			  proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
			  dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
			}
			return end_offset;
		}
	} else {
	  /* implicit tag so get from last tag/length */

	  get_last_ber_identifier(&class, &pc, &tag);
	  get_last_ber_length(&len, &ind);

	  end_offset=offset+len;

	  /* caller may have created new buffer for indefinite length data Verify via length */
	  len_remain = (guint32)tvb_length_remaining(tvb, offset);
	  if((ind) && (len_remain == len - 2)) {
			/* new buffer received so adjust length and indefinite flag */
			len -=2;
			end_offset -= 2;
			ind = FALSE;
	  } else if (len_remain < len) {
			/*
			 * error - short frame, or this item runs past the
			 * end of the item containing it
			 */
	    cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "illegal_length", "BER Error: length:%u longer than tvb_length_remaining:%d", len, len_remain);
		  expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error length");
		  return end_offset;
	  }

	}

	actx->created_item = NULL;

	if (pc) {
		/* constructed */
		end_offset = reassemble_octet_string(actx, tree, hf_id, tvb, offset, len, ind, out_tvb);
	} else {
		/* primitive */
		gint length_remaining;

		length_remaining = tvb_length_remaining(tvb, offset);
#if 0
		if(length_remaining<1){
			return end_offset;
		}
#endif

		if(len<=(guint32)length_remaining){
			length_remaining=len;
		}
		if(hf_id >= 0) {
			it = ber_proto_tree_add_item(actx->pinfo, tree, hf_id, tvb, offset, length_remaining, ENC_BIG_ENDIAN);
			actx->created_item = it;
			ber_check_length(length_remaining, min_len, max_len, actx, it, ENC_BIG_ENDIAN);
		} else {
			proto_item *pi;

			pi=proto_tree_add_text(tree, tvb, offset, len, "Unknown OctetString: Length: 0x%02x, Value: 0x", len);
			if(pi){
				for(i=0;i<len;i++){
					proto_item_append_text(pi,"%02x",tvb_get_guint8(tvb, offset));
					offset++;
				}
			}
		}

		if(out_tvb) {
			*out_tvb = tvb_new_subset(tvb, offset, length_remaining, len);
		}
	}
	return end_offset;
}

int
dissect_ber_octet_string(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, tvbuff_t **out_tvb) {
  return dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset, NO_BOUND, NO_BOUND, hf_id, out_tvb);
}

int dissect_ber_octet_string_wcb(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, ber_callback func)
{
	tvbuff_t *out_tvb = NULL;

	offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_id, (func)?&out_tvb:NULL);
	if (func && out_tvb && (tvb_length(out_tvb)>0)) {
		if (hf_id >= 0)
			tree = proto_item_add_subtree(actx->created_item, ett_ber_octet_string);
		/* TODO Should hf_id2 be pased as last parameter???*/
		func(FALSE, out_tvb, 0, actx, tree, -1);
	}
	return offset;
}

int dissect_ber_old_octet_string_wcb(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, ber_old_callback func)
{
	tvbuff_t *out_tvb = NULL;

	offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_id, (func)?&out_tvb:NULL);
	if (func && out_tvb && (tvb_length(out_tvb)>0)) {
		if (hf_id >= 0)
			tree = proto_item_add_subtree(actx->created_item, ett_ber_octet_string);
		/* TODO Should hf_id2 be pased as last parameter???*/
		func(tree, out_tvb, 0, actx);
	}
	return offset;
}
/* 8.8 Encoding of a null value */
int
dissect_ber_null(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id) {
  gint8 class;
  gboolean pc;
  gint32 tag;
  guint32 len;
  int offset_old;
  proto_item* cause;

if (!implicit_tag)
{
  offset_old = offset;
  offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &class, &pc, &tag);
  if((pc) ||
      (!implicit_tag && ((class != BER_CLASS_UNI) || (tag != BER_UNI_TAG_NULL)))) {
    cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset_old, offset - offset_old, "null_expected", "BER Error: NULL expected but class:%s(%d) %s tag:%d was unexpected", val_to_str(class,ber_class_codes,"Unknown"), class, pc ? ber_pc_codes_short.true_string : ber_pc_codes_short.false_string, tag);
    expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: NULL expected");
  }

  offset_old = offset;
  offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, NULL);
  if(len) {
    proto_tree_add_string_format(tree, hf_ber_error, tvb, offset_old, offset - offset_old, "illegal_length", "BER Error: NULL expect zero length but Length=%d", len);
    cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "unexpected_data", "BER Error: unexpected data in NULL type");
    expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: NULL expect zero length");
    offset += len;
  }
}
  if (hf_id >= 0)
	  proto_tree_add_item(tree, hf_id, tvb, offset, 0, ENC_BIG_ENDIAN);
  return offset;
}

int
dissect_ber_integer64(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, gint64 *value)
{
	gint8 class;
	gboolean pc;
	gint32 tag;
	guint32 len;
	gint64 val;
	guint32 i;
	gboolean used_too_many_bytes = FALSE;

#ifdef DEBUG_BER
{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("INTEGERnew dissect_ber_integer(%s) entered implicit_tag:%d offset:%d len:%d %02x:%02x:%02x\n",name,implicit_tag,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("INTEGERnew dissect_ber_integer(%s) entered implicit_tag:%d \n",name,implicit_tag);
}
}
#endif


	if(value){
		*value=0;
	}

	if(!implicit_tag){
	  offset=dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &class, &pc, &tag);
	  offset=dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, NULL);
	} else {
	  gint32 remaining=tvb_length_remaining(tvb, offset);
	  len=remaining>0 ? remaining : 0;
	}

	/* we cant handle integers > 64 bits */
	if(len>8){
		header_field_info *hfinfo;
		proto_item *pi = NULL;

		if (hf_id >= 0) {
			hfinfo = proto_registrar_get_nth(hf_id);
			pi=proto_tree_add_text(tree, tvb, offset, len, "%s : 0x", hfinfo->name);
		}
		if(pi){
			for(i=0;i<len;i++){
				proto_item_append_text(pi,"%02x",tvb_get_guint8(tvb, offset));
				offset++;
			}
		} else {
			offset += len;
		}
		return offset;
	}

	val=0;
	if(len > 0) {
		/* extend sign bit */
		guint8 first = tvb_get_guint8(tvb, offset);
		if(first & 0x80){
			val=-1;
		}
		if(len > 1) {
			guint8 second = tvb_get_guint8(tvb, offset+1);
			if((first == 0x00 && (second & 0x80) == 0) ||
			   (first == 0xff && (second & 0x80)))
			{
				used_too_many_bytes = TRUE;
			}
		}
		for(i=0;i<len;i++){
			val=(val<<8)|tvb_get_guint8(tvb, offset);
			offset++;
		}
	}

	actx->created_item=NULL;

	if(hf_id >= 0){
		/*  */
		if(len < 1 || len > 8) {
		  proto_item *pi = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset-len, len, "invalid length", "BER Error: Can't handle integer length: %u", len);
			expert_add_info_format(actx->pinfo, pi, PI_MALFORMED, PI_WARN, "BER Error: Illegal integer length: %u", len);
		} else {
			header_field_info* hfi;

			hfi = proto_registrar_get_nth(hf_id);
			switch(hfi->type){
			case FT_UINT8:
			case FT_UINT16:
			case FT_UINT24:
			case FT_UINT32:
				actx->created_item=proto_tree_add_uint(tree, hf_id, tvb, offset-len, len, (guint32)val);
				break;
			case FT_INT8:
			case FT_INT16:
			case FT_INT24:
			case FT_INT32:
				actx->created_item=proto_tree_add_int(tree, hf_id, tvb, offset-len, len, (gint32)val);
				break;
			case FT_INT64:
				actx->created_item=proto_tree_add_int64(tree, hf_id, tvb, offset-len, len, val);
				break;
			case FT_UINT64:
				actx->created_item=proto_tree_add_uint64(tree, hf_id, tvb, offset-len, len, (guint64)val);
				break;
			default:
				DISSECTOR_ASSERT_NOT_REACHED();
			}

			if (used_too_many_bytes) {
				expert_add_info_format(actx->pinfo, actx->created_item, PI_PROTOCOL, PI_WARN, 
						       "Value is encoded with too many bytes");
			}
		}
	}

	if(value){
		*value=val;
	}

	return offset;
}

int
dissect_ber_constrained_integer64(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint64 min_len, gint64 max_len, gint hf_id, gint64 *value)
{
	gint64 val;

	offset=dissect_ber_integer64(implicit_tag, actx, tree, tvb, offset, hf_id, &val);
	if(value){
		*value=val;
	}

	ber_check_value64 (val, min_len, max_len, actx, actx->created_item);

	return offset;
}

int
dissect_ber_integer(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, guint32 *value)
{
	gint64 val;

	offset=dissect_ber_integer64(implicit_tag, actx, tree, tvb, offset, hf_id, &val);
	if(value){
		*value=(guint32)val;
	}

	return offset;
}

int
dissect_ber_constrained_integer(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint32 min_len, gint32 max_len, gint hf_id, guint32 *value)
{
	gint64 val;

	offset=dissect_ber_integer64(implicit_tag, actx, tree, tvb, offset, hf_id, &val);
	if(value){
		*value=(guint32)val;
	}

	ber_check_value ((guint32)val, min_len, max_len, actx, actx->created_item);

	return offset;
}

int
dissect_ber_boolean(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, gboolean *value)
{
	gint8 class;
	gboolean pc;
	gint32 tag;
	guint32 len;
	guint8 val;
	header_field_info *hfi;

	if(!implicit_tag){
		offset=dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &class, &pc, &tag);
		offset=dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, NULL);
		/*if(class!=BER_CLASS_UNI)*/
	} else {
		/* nothing to do here, yet */
	}

	val=tvb_get_guint8(tvb, offset);
	offset+=1;

	actx->created_item=NULL;

	if(hf_id >= 0){
		hfi = proto_registrar_get_nth(hf_id);
		if(hfi->type == FT_BOOLEAN)
			actx->created_item=proto_tree_add_boolean(tree, hf_id, tvb, offset-1, 1, val);
		else
			actx->created_item=proto_tree_add_uint(tree, hf_id, tvb, offset-1, 1, val?1:0);
	}

	if(value){
		*value=(val?TRUE:ENC_BIG_ENDIAN);
	}

	return offset;
}


/* 8.5	Encoding of a real value */
/* NOT Tested*/
int
dissect_ber_real(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id _U_, double *value)
{
	gint8 class;
	gboolean pc;
	gint32 tag;
	guint32 val_length = 0, end_offset;
	double val = 0;

	if(!implicit_tag){
		offset=dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &class, &pc, &tag);
		offset=dissect_ber_length(actx->pinfo, tree, tvb, offset, &val_length, NULL);
	} else {
		/* 8.5.1	The encoding of a real value shall be primitive. */
		DISSECTOR_ASSERT_NOT_REACHED();
	}
	/* 8.5.2	If the real value is the value zero,
	 *			there shall be no contents octets in the encoding.
	 */
	if (val_length==0){
		if (value)
			*value = 0;
		return offset;
	}
	end_offset = offset + val_length;

	val = asn1_get_real(tvb_get_ptr(tvb, offset, val_length), val_length);
	actx->created_item = proto_tree_add_double(tree, hf_id, tvb, offset, val_length, val);

	if (value) *value = val;

	return end_offset;

}
/* this function dissects a BER sequence
 */
int dissect_ber_sequence(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_sequence_t *seq, gint hf_id, gint ett_id) {
	gint8 classx;
	gboolean pcx, ind = 0, ind_field, imp_tag=FALSE;
	gint32 tagx;
	guint32 lenx;
	proto_tree *tree = parent_tree;
	proto_item *item = NULL;
	proto_item *cause;
	int end_offset = 0;
	int hoffset;
	gint length_remaining;
	tvbuff_t *next_tvb;

#ifdef DEBUG_BER
{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("SEQUENCE dissect_ber_sequence(%s) entered offset:%d len:%d %02x:%02x:%02x\n",name,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("SEQUENCE dissect_ber_sequence(%s) entered\n",name);
}
}
#endif
	hoffset = offset;
	if(!implicit_tag) {
		offset = get_ber_identifier(tvb, offset, NULL, NULL, NULL);
		offset = get_ber_length(tvb, offset, &lenx, NULL);
	} else {
		/* was implicit tag so just use the length of the tvb */
		lenx=tvb_length_remaining(tvb,offset);
		end_offset=offset+lenx;
	}
	/* create subtree */
	if(hf_id >= 0) {
		if(parent_tree){
			item = proto_tree_add_item(parent_tree, hf_id, tvb, hoffset, lenx + offset - hoffset, ENC_BIG_ENDIAN);
			tree = proto_item_add_subtree(item, ett_id);
		}
	}
	offset = hoffset;

	if(!implicit_tag){
		/* first we must read the sequence header */
		offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &classx, &pcx, &tagx);
		offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &lenx, &ind);
		if(ind){
		/*  Fixed the length is correctly returned from dissect ber_length
		  end_offset = tvb_length(tvb);*/
		  end_offset = offset + lenx -2;
		} else {
		  end_offset = offset + lenx;
		}

		/* sanity check: we only handle Constructed Universal Sequences */
		if((classx!=BER_CLASS_APP)&&(classx!=BER_CLASS_PRI))
		if((!pcx)
		||(!implicit_tag&&((classx!=BER_CLASS_UNI)
					||(tagx!=BER_UNI_TAG_SEQUENCE)))) {
			tvb_ensure_bytes_exist(tvb, hoffset, 2);
			cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, lenx, "sequence_expected", "BER Error: Sequence expected but class:%s(%d) %s tag:%d was unexpected", val_to_str(classx,ber_class_codes,"Unknown"), classx, pcx ? ber_pc_codes_short.true_string : ber_pc_codes_short.false_string, tagx);
			expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Sequence expected");
			if (decode_unexpected) {
			  proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
			  dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
			}
			return end_offset;
		}
	}
	/* loop over all entries until we reach the end of the sequence */
	while (offset < end_offset){
		gint8 class;
		gboolean pc;
		gint32 tag;
		guint32 len;
		int eoffset, count;

		/*if(ind){  this sequence was of indefinite length, if this is implicit indefinite impossible maybe
					but ber dissector uses this to eat the tag length then pass into here... EOC still on there...*/
			if((tvb_get_guint8(tvb, offset)==0)&&(tvb_get_guint8(tvb, offset+1)==0)){
				/* If the first bytes is 00 00 of a indefenert length field it's a zero length field*/
				offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &class, &pc, &tag);
				offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, &ind);
				proto_item_append_text(item," 0 items");
				return end_offset;
				/*
				if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, s_offset, offset+2, "ERROR WRONG SEQ EOC");
				}
				return end_offset;
				*/
			}
		/*}*/
		hoffset = offset;
		/* read header and len for next field */
		offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
		offset = get_ber_length(tvb, offset, &len, &ind_field);
		eoffset = offset + len;
                /* Make sure we move forward */
		if (eoffset <= hoffset)
			THROW(ReportedBoundsError);

		/*if(ind_field && (len == 2)){
    			/ disgusting indefinite length zero length field, what are these people doing /
			offset = eoffset;
			continue;
		}
		*/

ber_sequence_try_again:
		/* have we run out of known entries in the sequence ?*/
		if(!seq->func) {
			/* it was not,  move to the next one and try again */
			offset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, NULL, NULL);
			cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "unknown_field", "BER Error: This field lies beyond the end of the known sequence definition.");
			expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Unknown field in Sequence");
			if (decode_unexpected) {
			  proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
			  dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
			}
			offset = eoffset;
			continue;
		}

		/* Verify that this one is the one we want.
		 * Skip check completely if class==ANY
		 * of if NOCHKTAG is set
		 */
/* XXX Bug in asn2eth,
 * for   scope            [7]  Scope OPTIONAL,
 * it generates
 *   { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_scope },
 * and there should not be a NOTCHKTAG here
 */
		if( ((seq->class==BER_CLASS_CON)||(seq->class==BER_CLASS_APP)||(seq->class==BER_CLASS_PRI)) && (!(seq->flags&BER_FLAGS_NOOWNTAG)) ){
		  if( (seq->class!=BER_CLASS_ANY)
		  &&  (seq->tag!=-1)
		  &&( (seq->class!=class)
		    ||(seq->tag!=tag) ) ){
			/* it was not,  move to the next one and try again */
			if(seq->flags&BER_FLAGS_OPTIONAL){
				/* well this one was optional so just skip to the next one and try again. */
				seq++;
				goto ber_sequence_try_again;
			}
			offset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, NULL, NULL);
			if( seq->class == BER_CLASS_UNI){
			  cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "wrong_field",
				    "BER Error: Wrong field in SEQUENCE  expected class:%s(%d) tag:%d (%s) but found class:%s(%d) tag:%d",
				    val_to_str(seq->class,ber_class_codes,"Unknown"),seq->class,
				    seq->tag,val_to_str_ext(seq->tag,&ber_uni_tag_codes_ext,"Unknown"),
				    val_to_str(class,ber_class_codes,"Unknown"),class,tag);
				expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Wrong field in SEQUENCE");
			}else{
			  cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "wrong_field",
				    "BER Error: Wrong field in SEQUENCE  expected class:%s(%d) tag:%d but found class:%s(%d) tag:%d",
				    val_to_str(seq->class,ber_class_codes,"Unknown"),seq->class,
				    seq->tag,val_to_str(class,ber_class_codes,"Unknown"),class,tag);
				expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Wrong field in SEQUENCE");
			}
			if (decode_unexpected) {
			  proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
			  dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
			}
			seq++;
			offset=eoffset;
			continue;
		  }
	        } else if(!(seq->flags & BER_FLAGS_NOTCHKTAG)) {
		  if( (seq->class!=BER_CLASS_ANY)
		  &&  (seq->tag!=-1)
		  &&( (seq->class!=class)
		    ||(seq->tag!=tag) ) ){
			/* it was not,  move to the next one and try again */
			if(seq->flags&BER_FLAGS_OPTIONAL){
				/* well this one was optional so just skip to the next one and try again. */
				seq++;
				goto ber_sequence_try_again;
			}

			offset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, NULL, NULL);
			if( seq->class == BER_CLASS_UNI){
			  cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "wrong_field", "BER Error: Wrong field in sequence  expected class:%s(%d) tag:%d(%s) but found class:%s(%d) tag:%d",
				  val_to_str(seq->class,ber_class_codes,"Unknown"),seq->class,seq->tag,val_to_str_ext(seq->tag,&ber_uni_tag_codes_ext,"Unknown"),val_to_str(class,ber_class_codes,"Unknown"),class,tag);
				expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Wrong field in sequence");
			}else{
			  cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "wrong_field", "BER Error: Wrong field in sequence  expected class:%s(%d) tag:%d but found class:%s(%d) tag:%d",val_to_str(seq->class,ber_class_codes,"Unknown"),seq->class,seq->tag,val_to_str(class,ber_class_codes,"Unknown"),class,tag);
				expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Wrong field in sequence");
			}
			if (decode_unexpected) {
			  proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
			  dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
			}
			seq++;
			offset=eoffset;
			continue;
		  }
		}

		if(!(seq->flags & BER_FLAGS_NOOWNTAG) ) {
			/* dissect header and len for field */
			if(ind_field && (len == 2)){
				/* This is a Zero length field */
				next_tvb = tvb_new_subset(tvb, offset, len, len);
				hoffset = eoffset;
			}else{
				hoffset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
				hoffset = dissect_ber_length(actx->pinfo, tree, tvb, hoffset, NULL, NULL);
				length_remaining=tvb_length_remaining(tvb, hoffset);
				if (length_remaining>eoffset-hoffset-(2*ind_field))
					length_remaining=eoffset-hoffset-(2*ind_field);
				next_tvb = tvb_new_subset(tvb, hoffset, length_remaining, eoffset-hoffset-(2*ind_field));
			}
		}
		else {
			length_remaining=tvb_length_remaining(tvb, hoffset);
			if (length_remaining>eoffset-hoffset)
				length_remaining=eoffset-hoffset;
			next_tvb = tvb_new_subset(tvb, hoffset, length_remaining, eoffset-hoffset);
		}

		/* call the dissector for this field */
		/*if 	((eoffset-hoffset)>length_remaining) {*/
			/* If the field is indefinite (i.e. we dont know the
			 * length) of if the tvb is short, then just
			 * give it all of the tvb and hope for the best.
			 */
			/*next_tvb = tvb_new_subset_remaining(tvb, hoffset);*/
		/*} else {*/

		/*}*/

#ifdef DEBUG_BER
{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(next_tvb,0)>3){
printf("SEQUENCE dissect_ber_sequence(%s) calling subdissector offset:%d len:%d %02x:%02x:%02x\n",name,offset,tvb_length_remaining(next_tvb,0),tvb_get_guint8(next_tvb,0),tvb_get_guint8(next_tvb,1),tvb_get_guint8(next_tvb,2));
}else{
printf("SEQUENCE dissect_ber_sequence(%s) calling subdissector\n",name);
}
}
#endif
		if (next_tvb == NULL) {
			/* Assume that we have a malformed packet. */
			THROW(ReportedBoundsError);
		}
		imp_tag=FALSE;
		if (seq->flags & BER_FLAGS_IMPLTAG){
			imp_tag = TRUE;
		}

		count=seq->func(imp_tag, next_tvb, 0, actx, tree, *seq->p_id);

#ifdef DEBUG_BER
{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
printf("SEQUENCE dissect_ber_sequence(%s) subdissector ate %d bytes\n",name,count);
}
#endif
		/* if it was optional and no bytes were eaten and it was */
		/* supposed to (len<>0), just try again. */
		if((len!=0)&&(count==0)&&(seq->flags&BER_FLAGS_OPTIONAL)){
			seq++;
			goto ber_sequence_try_again;
		/* move the offset to the beginning of the next sequenced item */
		}
		offset = eoffset;
		if(!(seq->flags & BER_FLAGS_NOOWNTAG) ) {
			/* if we stripped the tag and length we should also strip the EOC is ind_len
			 * Unless its a zero length field (len = 2)
			 */
			if((ind_field == 1)&&(len>2))
			{
				/* skip over EOC */
				if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, offset, count, "SEQ FIELD EOC");
				}
			}
		}
		seq++;
	}

	/* if we didnt end up at exactly offset, then we ate too many bytes */
	if(offset != end_offset) {
		tvb_ensure_bytes_exist(tvb, offset-2, 2);
		cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset-2, 2, "illegal_length", "BER Error: Sequence ate %d too many bytes", offset-end_offset);
		expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: too many bytes in Sequence");
	}
	if(ind){
		/*  need to eat this EOC
		end_offset = tvb_length(tvb);*/
		end_offset += 2;
		if(show_internal_ber_fields){
			proto_tree_add_text(tree, tvb, end_offset-2,2 , "SEQ EOC");
		}
	}
	return end_offset;
}

int dissect_ber_old_sequence(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_old_sequence_t *seq, gint hf_id, gint ett_id) {
	gint8 classx;
	gboolean pcx, ind = 0, ind_field;
	gint32 tagx;
	guint32 lenx;
	proto_tree *tree = parent_tree;
	proto_item *item = NULL;
	proto_item *cause;
	int end_offset = 0;
	int hoffset;
	gint length_remaining;
	tvbuff_t *next_tvb;

#ifdef DEBUG_BER
{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("SEQUENCE dissect_ber_old_sequence(%s) entered offset:%d len:%d %02x:%02x:%02x\n",name,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("SEQUENCE dissect_ber_old_sequence(%s) entered\n",name);
}
}
#endif
	hoffset = offset;
	if(!implicit_tag) {
		offset = get_ber_identifier(tvb, offset, NULL, NULL, NULL);
		offset = get_ber_length(tvb, offset, &lenx, NULL);
	} else {
		/* was implicit tag so just use the length of the tvb */
		lenx=tvb_length_remaining(tvb,offset);
		end_offset=offset+lenx;
	}
	/* create subtree */
	if(hf_id >= 0) {
		if(parent_tree){
			item = proto_tree_add_item(parent_tree, hf_id, tvb, hoffset, lenx + offset - hoffset, ENC_BIG_ENDIAN);
			tree = proto_item_add_subtree(item, ett_id);
		}
	}
	offset = hoffset;

	if(!implicit_tag){
		/* first we must read the sequence header */
		offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &classx, &pcx, &tagx);
		offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &lenx, &ind);
		if(ind){
		/*  Fixed the length is correctly returned from dissect ber_length
		  end_offset = tvb_length(tvb);*/
		  end_offset = offset + lenx -2;
		} else {
		  end_offset = offset + lenx;
		}

		/* sanity check: we only handle Constructed Universal Sequences */
		if((classx!=BER_CLASS_APP)&&(classx!=BER_CLASS_PRI))
		if((!pcx)
		||(!implicit_tag&&((classx!=BER_CLASS_UNI)
					||(tagx!=BER_UNI_TAG_SEQUENCE)))) {
			tvb_ensure_bytes_exist(tvb, hoffset, 2);
			cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, lenx, "sequence_expected", "BER Error: Sequence expected but class:%s(%d) %s tag:%d was unexpected", val_to_str(classx,ber_class_codes,"Unknown"), classx, pcx ? ber_pc_codes_short.true_string : ber_pc_codes_short.false_string, tagx);
			expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Sequence expected");
			if (decode_unexpected) {
			  proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
			  dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
			}
			return end_offset;
		}
	}
	/* loop over all entries until we reach the end of the sequence */
	while (offset < end_offset){
		gint8 class;
		gboolean pc;
		gint32 tag;
		guint32 len;
		int eoffset, count;

		/*if(ind){  this sequence was of indefinite length, if this is implicit indefinite impossible maybe
					but ber dissector uses this to eat the tag length then pass into here... EOC still on there...*/
			if((tvb_get_guint8(tvb, offset)==0)&&(tvb_get_guint8(tvb, offset+1)==0)){
				/* If the first bytes is 00 00 of a indefenert length field it's a zero length field*/
				offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &class, &pc, &tag);
				offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, &ind);
				proto_item_append_text(item," 0 items");
				return end_offset;
				/*
				if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, s_offset, offset+2, "ERROR WRONG SEQ EOC");
				}
				return end_offset;
				*/
			}
		/*}*/
		hoffset = offset;
		/* read header and len for next field */
		offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
		offset = get_ber_length(tvb, offset, &len, &ind_field);
		eoffset = offset + len;
                /* Make sure we move forward */
		if (eoffset <= hoffset)
			THROW(ReportedBoundsError);

		/*if(ind_field && (len == 2)){
    			/ disgusting indefinite length zero length field, what are these people doing /
			offset = eoffset;
			continue;
		}
		*/

ber_old_sequence_try_again:
		/* have we run out of known entries in the sequence ?*/
		if(!seq->func) {
			/* it was not,  move to the next one and try again */
			offset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, NULL, NULL);
			cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "illegal_length", "BER Error: This field lies beyond the end of the known sequence definition.");
			expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Unknown field in Sequence");
			if (decode_unexpected) {
			  proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
			  dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
			}
			offset = eoffset;
			continue;
		}

		/* Verify that this one is the one we want.
		 * Skip check completely if class==ANY
		 * of if NOCHKTAG is set
		 */
/* XXX Bug in asn2eth,
 * for   scope            [7]  Scope OPTIONAL,
 * it generates
 *   { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_scope },
 * and there should not be a NOTCHKTAG here
 */
		if( ((seq->class==BER_CLASS_CON)||(seq->class==BER_CLASS_APP)||(seq->class==BER_CLASS_PRI)) && (!(seq->flags&BER_FLAGS_NOOWNTAG)) ){
		  if( (seq->class!=BER_CLASS_ANY)
		  &&  (seq->tag!=-1)
		  &&( (seq->class!=class)
		    ||(seq->tag!=tag) ) ){
			/* it was not,  move to the next one and try again */
			if(seq->flags&BER_FLAGS_OPTIONAL){
				/* well this one was optional so just skip to the next one and try again. */
				seq++;
				goto ber_old_sequence_try_again;
			}
			offset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, NULL, NULL);
			if( seq->class == BER_CLASS_UNI){
			  cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "wrong_field",
				    "BER Error: Wrong field in SEQUENCE  expected class:%s(%d) tag:%d (%s) but found class:%s(%d) tag:%d",
				    val_to_str(seq->class,ber_class_codes,"Unknown"),seq->class,
				    seq->tag,val_to_str_ext(seq->tag,&ber_uni_tag_codes_ext,"Unknown"),
				    val_to_str(class,ber_class_codes,"Unknown"),class,tag);
				expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Wrong field in SEQUENCE");
			}else{
			  cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "wrong_field"
				    "BER Error: Wrong field in SEQUENCE  expected class:%s(%d) tag:%d but found class:%s(%d) tag:%d",
				    val_to_str(seq->class,ber_class_codes,"Unknown"),seq->class,
				    seq->tag,val_to_str(class,ber_class_codes,"Unknown"),class,tag);
				expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Wrong field in SEQUENCE");
			}
			if (decode_unexpected) {
			  proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
			  dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
			}
			seq++;
			offset=eoffset;
			continue;
		  }
	        } else if(!(seq->flags & BER_FLAGS_NOTCHKTAG)) {
		  if( (seq->class!=BER_CLASS_ANY)
		  &&  (seq->tag!=-1)
		  &&( (seq->class!=class)
		    ||(seq->tag!=tag) ) ){
			/* it was not,  move to the next one and try again */
			if(seq->flags&BER_FLAGS_OPTIONAL){
				/* well this one was optional so just skip to the next one and try again. */
				seq++;
				goto ber_old_sequence_try_again;
			}

			offset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, NULL, NULL);
			if( seq->class == BER_CLASS_UNI){
			  cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "wrong_field", "BER Error: Wrong field in sequence  expected class:%s(%d) tag:%d(%s) but found class:%s(%d) tag:%d",
				  val_to_str(seq->class,ber_class_codes,"Unknown"),seq->class,seq->tag,val_to_str_ext(seq->tag,&ber_uni_tag_codes_ext,"Unknown"),val_to_str(class,ber_class_codes,"Unknown"),class,tag);
				expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Wrong field in sequence");
			}else{
			  cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "wrong_field", "BER Error: Wrong field in sequence  expected class:%s(%d) tag:%d but found class:%s(%d) tag:%d",val_to_str(seq->class,ber_class_codes,"Unknown"),seq->class,seq->tag,val_to_str(class,ber_class_codes,"Unknown"),class,tag);
				expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Wrong field in sequence");
			}
			if (decode_unexpected) {
			  proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
			  dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
			}
			seq++;
			offset=eoffset;
			continue;
		  }
		}

		if(!(seq->flags & BER_FLAGS_NOOWNTAG) ) {
			/* dissect header and len for field */
			if(ind_field && (len == 2)){
				/* This is a Zero length field */
				next_tvb = tvb_new_subset(tvb, offset, len, len);
				hoffset = eoffset;
			}else{
				hoffset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
				hoffset = dissect_ber_length(actx->pinfo, tree, tvb, hoffset, NULL, NULL);
				length_remaining=tvb_length_remaining(tvb, hoffset);
				if (length_remaining>eoffset-hoffset-(2*ind_field))
					length_remaining=eoffset-hoffset-(2*ind_field);
				next_tvb = tvb_new_subset(tvb, hoffset, length_remaining, eoffset-hoffset-(2*ind_field));
			}
		}
		else {
			length_remaining=tvb_length_remaining(tvb, hoffset);
			if (length_remaining>eoffset-hoffset)
				length_remaining=eoffset-hoffset;
			next_tvb = tvb_new_subset(tvb, hoffset, length_remaining, eoffset-hoffset);
		}

		/* call the dissector for this field */
		/*if 	((eoffset-hoffset)>length_remaining) {*/
			/* If the field is indefinite (i.e. we dont know the
			 * length) of if the tvb is short, then just
			 * give it all of the tvb and hope for the best.
			 */
			/*next_tvb = tvb_new_subset_remaining(tvb, hoffset);*/
		/*} else {*/

		/*}*/

#ifdef DEBUG_BER
{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(next_tvb,0)>3){
printf("SEQUENCE dissect_ber_old_sequence(%s) calling subdissector offset:%d len:%d %02x:%02x:%02x\n",name,offset,tvb_length_remaining(next_tvb,0),tvb_get_guint8(next_tvb,0),tvb_get_guint8(next_tvb,1),tvb_get_guint8(next_tvb,2));
}else{
printf("SEQUENCE dissect_ber_old_sequence(%s) calling subdissector\n",name);
}
}
#endif
		if (next_tvb == NULL) {
			/* Assume that we have a malformed packet. */
			THROW(ReportedBoundsError);
		}
		count=seq->func(tree, next_tvb, 0, actx);

#ifdef DEBUG_BER
{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
printf("SEQUENCE dissect_ber_old_sequence(%s) subdissector ate %d bytes\n",name,count);
}
#endif
		/* if it was optional and no bytes were eaten and it was */
		/* supposed to (len<>0), just try again. */
		if((len!=0)&&(count==0)&&(seq->flags&BER_FLAGS_OPTIONAL)){
			seq++;
			goto ber_old_sequence_try_again;
		/* move the offset to the beginning of the next sequenced item */
		}
		offset = eoffset;
		seq++;
		if(!(seq->flags & BER_FLAGS_NOOWNTAG) ) {
			/* if we stripped the tag and length we should also strip the EOC is ind_len
			 * Unless its a zero length field (len = 2)
			 */
			if((ind_field == 1)&&(len>2))
			{
				/* skip over EOC */
				if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, offset, count, "SEQ FIELD EOC");
				}
			}
		}
	}

	/* if we didnt end up at exactly offset, then we ate too many bytes */
	if(offset != end_offset) {
		tvb_ensure_bytes_exist(tvb, offset-2, 2);
		cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset-2, 2, "illegal_length", "BER Error: Sequence ate %d too many bytes", offset-end_offset);
		expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: too many bytes in Sequence");
	}
	if(ind){
		/*  need to eat this EOC
		end_offset = tvb_length(tvb);*/
		end_offset += 2;
		if(show_internal_ber_fields){
			proto_tree_add_text(tree, tvb, end_offset-2,2 , "SEQ EOC");
		}
	}
	return end_offset;
}

/* This function dissects a BER set
 */
int dissect_ber_set(gboolean implicit_tag,asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_sequence_t *set, gint hf_id, gint ett_id) {
	gint8 classx;
	gboolean pcx, ind = 0, ind_field, imp_tag = FALSE;
	gint32 tagx;
	guint32 lenx;
	proto_tree *tree = parent_tree;
	proto_item *item = NULL;
	proto_item *cause;
	int end_offset, s_offset;
	int hoffset;
	gint length_remaining;
	tvbuff_t *next_tvb;
	const ber_sequence_t *cset = NULL;
# define MAX_SET_ELEMENTS 32
	guint32   mandatory_fields = 0;
	guint8   set_idx;
	gboolean first_pass;
	s_offset = offset;
#ifdef DEBUG_BER
	{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("SET dissect_ber_set(%s) entered offset:%d len:%d %02x:%02x:%02x\n",name,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("SET dissect_ber_set(%s) entered\n",name);
}
}
#endif

	if(!implicit_tag){
		hoffset = offset;
		/* first we must read the sequence header */
		offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &classx, &pcx, &tagx);
		offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &lenx, &ind);
		if(ind){
		/*  Fixed the length is correctly returned from dissect ber_length
		  end_offset = tvb_length(tvb);*/
		  end_offset = offset + lenx -2;
		} else {
		  end_offset = offset + lenx;
		}

		/* sanity check: we only handle Constructed Universal Sets */
		if ((classx!=BER_CLASS_APP)&&(classx!=BER_CLASS_PRI))
		if ((!pcx)
		||(!implicit_tag&&((classx!=BER_CLASS_UNI)
							||(tagx!=BER_UNI_TAG_SET)))) {
		  tvb_ensure_bytes_exist(tvb, hoffset, 2);
		  cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, lenx, "set_expected", "BER Error: SET expected but class:%s(%d) %s tag:%d was found", val_to_str(classx,ber_class_codes,"Unknown"), classx, pcx ? ber_pc_codes_short.true_string : ber_pc_codes_short.false_string, tagx);
		  expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: SET expected");
		  if (decode_unexpected) {
		    proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
		    dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
		  }
		  return end_offset;
		}
	} else {
		/* was implicit tag so just use the length of the tvb */
		lenx=tvb_length_remaining(tvb,offset);
		end_offset=offset+lenx;
	}

	/* create subtree */
	if (hf_id >= 0) {
		if(parent_tree){
			item = proto_tree_add_item(parent_tree, hf_id, tvb, offset, lenx, ENC_BIG_ENDIAN);
			tree = proto_item_add_subtree(item, ett_id);
		}
	}

	/* record the mandatory elements of the set so we can check we found everything at the end
	   we can only record 32 elements for now ... */
	for(set_idx = 0; (cset=&set[set_idx])->func && (set_idx < MAX_SET_ELEMENTS); set_idx++) {

	  if(!(cset->flags & BER_FLAGS_OPTIONAL))
	      mandatory_fields |= 1 << set_idx;

	}

	/* loop over all entries until we reach the end of the set */
	while (offset < end_offset){
		gint8 class;
		gboolean pc;
		gint32 tag;
		guint32 len;
		int eoffset, count;

		/*if(ind){  this sequence was of indefinite length, if this is implicit indefinite impossible maybe
		  but ber dissector uses this to eat the tag length then pass into here... EOC still on there...*/

			if((tvb_get_guint8(tvb, offset)==0)&&(tvb_get_guint8(tvb, offset+1)==0)){
				if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, s_offset, offset+2, "SEQ EOC");
				}
				return end_offset;
			}
			/* } */
		hoffset = offset;
		/* read header and len for next field */
		offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
		offset = get_ber_length(tvb, offset, &len, &ind_field);
		eoffset = offset + len;

		/* Look through the Set to see if this class/id exists and
		 * hasn't been seen before
		 * Skip check completely if class==ANY
		 * of if NOCHKTAG is set
		 */


		for(first_pass=TRUE, cset = set, set_idx = 0; cset->func || first_pass; cset++, set_idx++) {

		  /* we reset for a second pass when we will look for choices */
		  if(!cset->func) {
		    first_pass = FALSE;

		    cset=set; /* reset to the beginning */
		    set_idx = 0;
		  }

		  if((first_pass && ((cset->class==class) && (cset->tag==tag))) ||
		     (!first_pass && ((cset->class== BER_CLASS_ANY) && (cset->tag == -1))) ) /* choices */
		  {

			if (!(cset->flags & BER_FLAGS_NOOWNTAG) ) {
		      /* dissect header and len for field */
				hoffset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
				hoffset = dissect_ber_length(actx->pinfo, tree, tvb, hoffset, NULL, NULL);
				length_remaining=tvb_length_remaining(tvb, hoffset);
				if (length_remaining>eoffset-hoffset-(2*ind_field))
					length_remaining=eoffset-hoffset-(2*ind_field);
				next_tvb = tvb_new_subset(tvb, hoffset, length_remaining, eoffset-hoffset-(2*ind_field));
		    }
			else {
				length_remaining=tvb_length_remaining(tvb, hoffset);
				if (length_remaining>eoffset-hoffset)
					length_remaining=eoffset-hoffset;
				next_tvb = tvb_new_subset(tvb, hoffset, length_remaining, eoffset-hoffset);
			}


			/* call the dissector for this field */
			/*if 	((eoffset-hoffset)>length_remaining) {*/
				/* If the field is indefinite (i.e. we dont know the
				 * length) of if the tvb is short, then just
				 * give it all of the tvb and hope for the best.
				 */
				/*next_tvb = tvb_new_subset_remaining(tvb, hoffset);*/
			/*} else {*/

			/*}*/

#ifdef DEBUG_BER
{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(next_tvb,0)>3){
printf("SET dissect_ber_set(%s) calling subdissector offset:%d len:%d %02x:%02x:%02x\n",name,offset,tvb_length_remaining(next_tvb,0),tvb_get_guint8(next_tvb,0),tvb_get_guint8(next_tvb,1),tvb_get_guint8(next_tvb,2));
}else{
printf("SET dissect_ber_set(%s) calling subdissector\n",name);
}
}
#endif
			if (next_tvb == NULL) {
				/* Assume that we have a malformed packet. */
				THROW(ReportedBoundsError);
			}
			imp_tag = FALSE;
			if ((cset->flags & BER_FLAGS_IMPLTAG))
				imp_tag = TRUE;
			count=cset->func(imp_tag, next_tvb, 0, actx, tree, *cset->p_id);

			/* if we consumed some bytes,
			   or we knew the length was zero (during the first pass only) */
			if(count || (first_pass && (len == 0 || (ind_field == 1 && len == 2)))) {
			    /* we found it! */
			    if(set_idx < MAX_SET_ELEMENTS)
				  mandatory_fields &= ~(1 << set_idx);

				offset = eoffset;

				if(!(cset->flags & BER_FLAGS_NOOWNTAG) ) {
				  /* if we stripped the tag and length we should also strip the EOC is ind_len */
				  if(ind_field == 1){
					  /* skip over EOC */
					  if(show_internal_ber_fields){
						  proto_tree_add_text(tree, tvb, offset, count, "SET FIELD EOC");
					  }
				  }
				}
				break;
			}
		  }
		}

		if(!cset->func) {
		  /* we didn't find a match */
		  cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "unknown_field", "BER Error: Unknown field in SET class:%s(%d) tag:%d",val_to_str(class,ber_class_codes,"Unknown"),class,tag);
		  expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Unknown field in SET");
		  if (decode_unexpected) {
		    proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
		    dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
		  }
		  offset = eoffset;
		}
	}

	if(mandatory_fields) {

	  /* OK - we didn't find some of the elements we expected */

	  for(set_idx = 0;  (cset = &set[set_idx])->func && (set_idx < MAX_SET_ELEMENTS); set_idx++) {

	    if(mandatory_fields & (1 << set_idx)) {

	      /* here is something we should have seen - but didn't! */
	      cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, lenx, "missing_field",
				  "BER Error: Missing field in SET class:%s(%d) tag:%d expected",
				  val_to_str(cset->class,ber_class_codes,"Unknown"),cset->class,
				  cset->tag);
	      expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Missing field in SET");

	    }

	  }
	}

	/* if we didnt end up at exactly offset, then we ate too many bytes */
	if (offset != end_offset) {
		tvb_ensure_bytes_exist(tvb, offset-2, 2);
		cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset-2, 2, "illegal_length", "BER Error: SET ate %d too many bytes", offset-end_offset);
		expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: too many bytes in SET");
	}

	if(ind){
		/*  need to eat this EOC
		  end_offset = tvb_length(tvb);*/
		  end_offset += 2;
		  if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, end_offset-2,2 , "SET EOC");
		  }
	}

	return end_offset;

}

int dissect_ber_old_set(gboolean implicit_tag,asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_old_sequence_t *set, gint hf_id, gint ett_id) {
	gint8 classx;
	gboolean pcx, ind = 0, ind_field;
	gint32 tagx;
	guint32 lenx;
	proto_tree *tree = parent_tree;
	proto_item *item = NULL;
	proto_item *cause;
	int end_offset, s_offset;
	int hoffset;
	gint length_remaining;
	tvbuff_t *next_tvb;
	const ber_old_sequence_t *cset = NULL;
# define MAX_SET_ELEMENTS 32
	guint32   mandatory_fields = 0;
	guint8   set_idx;
	gboolean first_pass;
	s_offset = offset;
#ifdef DEBUG_BER
	{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("SET dissect_old_ber_set(%s) entered offset:%d len:%d %02x:%02x:%02x\n",name,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("SET dissect_old_ber_set(%s) entered\n",name);
}
}
#endif

	if(!implicit_tag){
		hoffset = offset;
		/* first we must read the sequence header */
		offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &classx, &pcx, &tagx);
		offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &lenx, &ind);
		if(ind){
		/*  Fixed the length is correctly returned from dissect ber_length
		  end_offset = tvb_length(tvb);*/
		  end_offset = offset + lenx -2;
		} else {
		  end_offset = offset + lenx;
		}

		/* sanity check: we only handle Constructed Universal Sets */
		if ((classx!=BER_CLASS_APP)&&(classx!=BER_CLASS_PRI))
		if ((!pcx)
		||(!implicit_tag&&((classx!=BER_CLASS_UNI)
							||(tagx!=BER_UNI_TAG_SET)))) {
		  tvb_ensure_bytes_exist(tvb, hoffset, 2);
		  cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, lenx, "set_expected", "BER Error: SET expected but class:%s(%d) %s tag:%d was found", val_to_str(classx,ber_class_codes,"Unknown"), classx, pcx ? ber_pc_codes_short.true_string : ber_pc_codes_short.false_string, tagx);
		  expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: SET expected");
		  if (decode_unexpected) {
		    proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
		    dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
		  }
		  return end_offset;
		}
	} else {
		/* was implicit tag so just use the length of the tvb */
		lenx=tvb_length_remaining(tvb,offset);
		end_offset=offset+lenx;
	}

	/* create subtree */
	if (hf_id >= 0) {
		if(parent_tree){
			item = proto_tree_add_item(parent_tree, hf_id, tvb, offset, lenx, ENC_BIG_ENDIAN);
			tree = proto_item_add_subtree(item, ett_id);
		}
	}

	/* record the mandatory elements of the set so we can check we found everything at the end
	   we can only record 32 elements for now ... */
	for(set_idx = 0; (cset=&set[set_idx])->func && (set_idx < MAX_SET_ELEMENTS); set_idx++) {

	  if(!(cset->flags & BER_FLAGS_OPTIONAL))
	      mandatory_fields |= 1 << set_idx;

	}

	/* loop over all entries until we reach the end of the set */
	while (offset < end_offset){
		gint8 class;
		gboolean pc;
		gint32 tag;
		guint32 len;
		int eoffset, count;

		/*if(ind){  this sequence was of indefinite length, if this is implicit indefinite impossible maybe
		  but ber dissector uses this to eat the tag length then pass into here... EOC still on there...*/

			if((tvb_get_guint8(tvb, offset)==0)&&(tvb_get_guint8(tvb, offset+1)==0)){
				if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, s_offset, offset+2, "SEQ EOC");
				}
				return end_offset;
			}
			/* } */
		hoffset = offset;
		/* read header and len for next field */
		offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
		offset = get_ber_length(tvb, offset, &len, &ind_field);
		eoffset = offset + len;

		/* Look through the Set to see if this class/id exists and
		 * hasn't been seen before
		 * Skip check completely if class==ANY
		 * of if NOCHKTAG is set
		 */


		for(first_pass=TRUE, cset = set, set_idx = 0; cset->func || first_pass; cset++, set_idx++) {

		  /* we reset for a second pass when we will look for choices */
		  if(!cset->func) {
		    first_pass = FALSE;

		    cset=set; /* reset to the beginning */
		    set_idx = 0;
		  }

		  if((first_pass && ((cset->class==class) && (cset->tag==tag))) ||
		     (!first_pass && ((cset->class== BER_CLASS_ANY) && (cset->tag == -1))) ) /* choices */
		  {

			if (!(cset->flags & BER_FLAGS_NOOWNTAG) ) {
		      /* dissect header and len for field */
				hoffset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
				hoffset = dissect_ber_length(actx->pinfo, tree, tvb, hoffset, NULL, NULL);
				length_remaining=tvb_length_remaining(tvb, hoffset);
				if (length_remaining>eoffset-hoffset-(2*ind_field))
					length_remaining=eoffset-hoffset-(2*ind_field);
				next_tvb = tvb_new_subset(tvb, hoffset, length_remaining, eoffset-hoffset-(2*ind_field));
		    }
			else {
				length_remaining=tvb_length_remaining(tvb, hoffset);
				if (length_remaining>eoffset-hoffset)
					length_remaining=eoffset-hoffset;
				next_tvb = tvb_new_subset(tvb, hoffset, length_remaining, eoffset-hoffset);
			}


			/* call the dissector for this field */
			/*if 	((eoffset-hoffset)>length_remaining) {*/
				/* If the field is indefinite (i.e. we dont know the
				 * length) of if the tvb is short, then just
				 * give it all of the tvb and hope for the best.
				 */
				/*next_tvb = tvb_new_subset_remaining(tvb, hoffset);*/
			/*} else {*/

			/*}*/

#ifdef DEBUG_BER
{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(next_tvb,0)>3){
printf("SET dissect_old_ber_set(%s) calling subdissector offset:%d len:%d %02x:%02x:%02x\n",name,offset,tvb_length_remaining(next_tvb,0),tvb_get_guint8(next_tvb,0),tvb_get_guint8(next_tvb,1),tvb_get_guint8(next_tvb,2));
}else{
printf("SET dissect_old_ber_set(%s) calling subdissector\n",name);
}
}
#endif
			if (next_tvb == NULL) {
				/* Assume that we have a malformed packet. */
				THROW(ReportedBoundsError);
			}
			count=cset->func(tree, next_tvb, 0, actx);

			/* if we consumed some bytes,
			   or we knew the length was zero (during the first pass only) */
			if(count || (first_pass && (len == 0 || (ind_field == 1 && len == 2)))) {
			    /* we found it! */
			    if(set_idx < MAX_SET_ELEMENTS)
				  mandatory_fields &= ~(1 << set_idx);

				offset = eoffset;

				if(!(cset->flags & BER_FLAGS_NOOWNTAG) ) {
				  /* if we stripped the tag and length we should also strip the EOC is ind_len */
				  if(ind_field == 1){
					  /* skip over EOC */
					  if(show_internal_ber_fields){
						  proto_tree_add_text(tree, tvb, offset, count, "SET FIELD EOC");
					  }
				  }
				}
				break;
			}
		  }
		}

		if(!cset->func) {
		  /* we didn't find a match */
		  cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "unknown_field", "BER Error: Unknown field in SET class:%s(%d) tag:%d",val_to_str(class,ber_class_codes,"Unknown"),class,tag);
		  expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Unknown field in SET");
		  if (decode_unexpected) {
		    proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
		    dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
		  }
		  offset = eoffset;
		}
	}

	if(mandatory_fields) {

	  /* OK - we didn't find some of the elements we expected */

	  for(set_idx = 0;  (cset = &set[set_idx])->func && (set_idx < MAX_SET_ELEMENTS); set_idx++) {

	    if(mandatory_fields & (1 << set_idx)) {

	      /* here is something we should have seen - but didn't! */
	      cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, lenx, "missing_field",
				  "BER Error: Missing field in SET class:%s(%d) tag:%d expected",
				  val_to_str(cset->class,ber_class_codes,"Unknown"),cset->class,
				  cset->tag);
	      expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Missing field in SET");

	    }

	  }
	}

	/* if we didnt end up at exactly offset, then we ate too many bytes */
	if (offset != end_offset) {
		tvb_ensure_bytes_exist(tvb, offset-2, 2);
		cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset-2, 2, "illegal_length", "BER Error: SET ate %d too many bytes", offset-end_offset);
		expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: too many bytes in SET");
	}

	if(ind){
		/*  need to eat this EOC
		  end_offset = tvb_length(tvb);*/
		  end_offset += 2;
		  if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, end_offset-2,2 , "SET EOC");
		  }
	}

	return end_offset;

}
/* this function dissects a BER choice
 * If we did not find a matching choice,  just return offset unchanged
 * in case it was a CHOICE { } OPTIONAL
 */
#ifdef DEBUG_BER
#define DEBUG_BER_CHOICE
#endif

int
dissect_ber_choice(asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_choice_t *choice, gint hf_id, gint ett_id, gint *branch_taken)
{
	gint8 class;
	gboolean pc, ind, imp_tag = FALSE;
	gint32 tag;
	guint32 len;
	const ber_choice_t *ch;
	proto_tree *tree=parent_tree;
	proto_item *item=NULL;
	int end_offset, start_offset, count;
	int hoffset = offset;
	header_field_info	*hfinfo;
	gint length, length_remaining;
	tvbuff_t *next_tvb;
	gboolean first_pass;

#ifdef DEBUG_BER_CHOICE
{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("CHOICE dissect_ber_choice(%s) entered offset:%d len:%d %02x:%02x:%02x\n",name,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("CHOICE dissect_ber_choice(%s) entered len:%d\n",name,tvb_length_remaining(tvb,offset));
}
}
#endif
	start_offset=offset;

        if(tvb_length_remaining(tvb,offset) == 0) {
                item = proto_tree_add_string_format(parent_tree, hf_ber_error, tvb, offset, 0, "empty_choice", "BER Error: Empty choice was found");
                expert_add_info_format(actx->pinfo, item, PI_MALFORMED, PI_WARN, "BER Error: Empty choice was found");
                return offset;
        }

	/* read header and len for choice field */
	offset=get_ber_identifier(tvb, offset, &class, &pc, &tag);
	offset=get_ber_length(tvb, offset, &len, &ind);
	  end_offset = offset + len ;

	/* Some sanity checks.
	 * The hf field passed to us MUST be an integer type
	 */
	if(hf_id >= 0){
		hfinfo=proto_registrar_get_nth(hf_id);
		switch(hfinfo->type) {
			case FT_UINT8:
			case FT_UINT16:
			case FT_UINT24:
			case FT_UINT32:
				break;
		default:
			proto_tree_add_text(tree, tvb, offset, len,"dissect_ber_choice(): Was passed a HF field that was not integer type : %s",hfinfo->abbrev);
			fprintf(stderr,"dissect_ber_choice(): frame:%u offset:%d Was passed a HF field that was not integer type : %s\n",actx->pinfo->fd->num,offset,hfinfo->abbrev);
			return end_offset;
		}
	}



	/* loop over all entries until we find the right choice or
	   run out of entries */
	ch = choice;
	if(branch_taken){
		*branch_taken=-1;
	}
	first_pass = TRUE;
	while(ch->func || first_pass){
		if(branch_taken){
			(*branch_taken)++;
		}
	  /* we reset for a second pass when we will look for choices */
	  if(!ch->func) {
	    first_pass = FALSE;
	    ch = choice; /* reset to the beginning */
		if(branch_taken){
			*branch_taken=-1;
		}
	  }

choice_try_again:
#ifdef DEBUG_BER_CHOICE
printf("CHOICE testing potential subdissector class[%p]:%d:(expected)%d  tag:%d:(expected)%d flags:%d\n",ch,class,ch->class,tag,ch->tag,ch->flags);
#endif
		if( (first_pass && (((ch->class==class)&&(ch->tag==tag))
		     ||  ((ch->class==class)&&(ch->tag==-1)&&(ch->flags&BER_FLAGS_NOOWNTAG)))) ||
		    (!first_pass && (((ch->class == BER_CLASS_ANY) && (ch->tag == -1)))) /* we failed on the first pass so now try any choices */
		){
			if(!(ch->flags & BER_FLAGS_NOOWNTAG)){
				/* dissect header and len for field */
				hoffset = dissect_ber_identifier(actx->pinfo, tree, tvb, start_offset, NULL, NULL, NULL);
				hoffset = dissect_ber_length(actx->pinfo, tree, tvb, hoffset, NULL, NULL);
				start_offset=hoffset;
				if (ind)
					{
					length = len-2;
					}
				else
					{
					length = len;
					}
			}
			else
				length = end_offset- hoffset;
			/* create subtree */
			if(hf_id >= 0){
				if(parent_tree){
					item = proto_tree_add_uint(parent_tree, hf_id, tvb, hoffset, end_offset - hoffset, ch->value);
					tree = proto_item_add_subtree(item, ett_id);
				}
			}

			length_remaining=tvb_length_remaining(tvb, hoffset);
			if(length_remaining>length)
				length_remaining=length;

#ifdef REMOVED
			/* This is bogus and makes the OID_1.0.9506.1.1.cap file
			 * in Steven J Schaeffer's email of 2005-09-12 fail to dissect
			 * properly.  Maybe we should get rid of 'first_pass'
			 * completely.
			 * It was added as a qad workaround for some problem CMIP
			 * traces anyway.
			 * God, this file is a mess and it is my fault. /ronnie
			 */
			if(first_pass)
			next_tvb=tvb_new_subset(tvb, hoffset, length_remaining, length);
			else
			  next_tvb = tvb; /* we didn't make selection on this class/tag so pass it on */
#endif
			next_tvb=tvb_new_subset(tvb, hoffset, length_remaining, length);


#ifdef DEBUG_BER_CHOICE
{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(next_tvb,0)>3){
printf("CHOICE dissect_ber_choice(%s) calling subdissector start_offset:%d offset:%d len:%d %02x:%02x:%02x\n",name,start_offset,offset,tvb_length_remaining(next_tvb,0),tvb_get_guint8(next_tvb,0),tvb_get_guint8(next_tvb,1),tvb_get_guint8(next_tvb,2));
}else{
printf("CHOICE dissect_ber_choice(%s) calling subdissector len:%d\n",name,tvb_length(next_tvb));
}
}
#endif
			if (next_tvb == NULL) {
				/* Assume that we have a malformed packet. */
				THROW(ReportedBoundsError);
			}
			imp_tag = FALSE;
			if ((ch->flags & BER_FLAGS_IMPLTAG))
				imp_tag = TRUE;
			count=ch->func(imp_tag, next_tvb, 0, actx, tree, *ch->p_id);
#ifdef DEBUG_BER_CHOICE
{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
printf("CHOICE dissect_ber_choice(%s) subdissector ate %d bytes\n",name,count);
}
#endif
			if((count==0)&&(((ch->class==class)&&(ch->tag==-1)&&(ch->flags&BER_FLAGS_NOOWNTAG)) || !first_pass)){
				/* wrong one, break and try again */
				ch++;
#ifdef DEBUG_BER_CHOICE
{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
printf("CHOICE dissect_ber_choice(%s) trying again\n",name);
}
#endif
				goto choice_try_again;
			}
			if(!(ch->flags & BER_FLAGS_NOOWNTAG)){
			 if(ind)
			 	{
			 	/* we are traversing a indfinite length choice where we did not pass the tag length */
			 	/* we need to eat the EOC */
			 	if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, start_offset, count+2, "CHOICE EOC");
				}
			 }
			}
			return end_offset;
		}
		ch++;
	}
	if(branch_taken){
		/* none of the branches were taken so set the param
		   back to -1 */
		*branch_taken=-1;
	}

#ifdef REMOVED
	/*XXX here we should have another flag to the CHOICE to distinguish
	 * between the case when we know it is a mandatory   or if the CHOICE is optional == no arm matched */

	/* oops no more entries and we still havent found
	 * our guy :-(
	 */
	item = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "missing_choice_field", "BER Error: This choice field was not found.");
	expert_add_info_format(actx->pinfo, item, PI_MALFORMED, PI_WARN, "BER Error: This choice field was not found");
	return end_offset;
#endif

	return start_offset;
}

int
dissect_ber_old_choice(asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_old_choice_t *choice, gint hf_id, gint ett_id, gint *branch_taken)
{
	gint8 class;
	gboolean pc, ind;
	gint32 tag;
	guint32 len;
	const ber_old_choice_t *ch;
	proto_tree *tree=parent_tree;
	proto_item *item=NULL;
	int end_offset, start_offset, count;
	int hoffset = offset;
	header_field_info	*hfinfo;
	gint length, length_remaining;
	tvbuff_t *next_tvb;
	gboolean first_pass;

#ifdef DEBUG_BER_CHOICE
{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("CHOICE dissect_ber_old_choice(%s) entered offset:%d len:%d %02x:%02x:%02x\n",name,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("CHOICE dissect_ber_old_choice(%s) entered len:%d\n",name,tvb_length_remaining(tvb,offset));
}
}
#endif
	start_offset=offset;

        if(tvb_length_remaining(tvb,offset) == 0) {
                item = proto_tree_add_string_format(parent_tree, hf_ber_error, tvb, offset, 0, "empty_choice", "BER Error: Empty choice was found");
                expert_add_info_format(actx->pinfo, item, PI_MALFORMED, PI_WARN, "BER Error: Empty choice was found");
                return offset;
        }

	/* read header and len for choice field */
	offset=get_ber_identifier(tvb, offset, &class, &pc, &tag);
	offset=get_ber_length(tvb, offset, &len, &ind);
	  end_offset = offset + len ;

	/* Some sanity checks.
	 * The hf field passed to us MUST be an integer type
	 */
	if(hf_id >= 0){
		hfinfo=proto_registrar_get_nth(hf_id);
		switch(hfinfo->type) {
			case FT_UINT8:
			case FT_UINT16:
			case FT_UINT24:
			case FT_UINT32:
				break;
		default:
			proto_tree_add_text(tree, tvb, offset, len,"dissect_ber_old_choice(): Was passed a HF field that was not integer type : %s",hfinfo->abbrev);
			fprintf(stderr,"dissect_ber_old_choice(): frame:%u offset:%d Was passed a HF field that was not integer type : %s\n",actx->pinfo->fd->num,offset,hfinfo->abbrev);
			return end_offset;
		}
	}



	/* loop over all entries until we find the right choice or
	   run out of entries */
	ch = choice;
	if(branch_taken){
		*branch_taken=-1;
	}
	first_pass = TRUE;
	while(ch->func || first_pass){
		if(branch_taken){
			(*branch_taken)++;
		}
	  /* we reset for a second pass when we will look for choices */
	  if(!ch->func) {
	    first_pass = FALSE;
	    ch = choice; /* reset to the beginning */
		if(branch_taken){
			*branch_taken=-1;
		}
	  }

choice_try_again:
#ifdef DEBUG_BER_CHOICE
printf("CHOICE testing potential subdissector class[%p]:%d:(expected)%d  tag:%d:(expected)%d flags:%d\n",ch,class,ch->class,tag,ch->tag,ch->flags);
#endif
		if( (first_pass && (((ch->class==class)&&(ch->tag==tag))
		     ||  ((ch->class==class)&&(ch->tag==-1)&&(ch->flags&BER_FLAGS_NOOWNTAG)))) ||
		    (!first_pass && (((ch->class == BER_CLASS_ANY) && (ch->tag == -1)))) /* we failed on the first pass so now try any choices */
		){
			if(!(ch->flags & BER_FLAGS_NOOWNTAG)){
				/* dissect header and len for field */
				hoffset = dissect_ber_identifier(actx->pinfo, tree, tvb, start_offset, NULL, NULL, NULL);
				hoffset = dissect_ber_length(actx->pinfo, tree, tvb, hoffset, NULL, NULL);
				start_offset=hoffset;
				if (ind)
					{
					length = len-2;
					}
				else
					{
					length = len;
					}
			}
			else
				length = end_offset- hoffset;
			/* create subtree */
			if(hf_id >= 0){
				if(parent_tree){
					item = proto_tree_add_uint(parent_tree, hf_id, tvb, hoffset, end_offset - hoffset, ch->value);
					tree = proto_item_add_subtree(item, ett_id);
				}
			}

			length_remaining=tvb_length_remaining(tvb, hoffset);
			if(length_remaining>length)
				length_remaining=length;

#ifdef REMOVED
			/* This is bogus and makes the OID_1.0.9506.1.1.cap file
			 * in Steven J Schaeffer's email of 2005-09-12 fail to dissect
			 * properly.  Maybe we should get rid of 'first_pass'
			 * completely.
			 * It was added as a qad workaround for some problem CMIP
			 * traces anyway.
			 * God, this file is a mess and it is my fault. /ronnie
			 */
			if(first_pass)
			next_tvb=tvb_new_subset(tvb, hoffset, length_remaining, length);
			else
			  next_tvb = tvb; /* we didn't make selection on this class/tag so pass it on */
#endif
			next_tvb=tvb_new_subset(tvb, hoffset, length_remaining, length);


#ifdef DEBUG_BER_CHOICE
{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(next_tvb,0)>3){
printf("CHOICE dissect_ber_old_choice(%s) calling subdissector start_offset:%d offset:%d len:%d %02x:%02x:%02x\n",name,start_offset,offset,tvb_length_remaining(next_tvb,0),tvb_get_guint8(next_tvb,0),tvb_get_guint8(next_tvb,1),tvb_get_guint8(next_tvb,2));
}else{
printf("CHOICE dissect_ber_old_choice(%s) calling subdissector len:%d\n",name,tvb_length(next_tvb));
}
}
#endif
			if (next_tvb == NULL) {
				/* Assume that we have a malformed packet. */
				THROW(ReportedBoundsError);
			}
			count=ch->func(tree, next_tvb, 0, actx);
#ifdef DEBUG_BER_CHOICE
{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
printf("CHOICE dissect_ber_old_choice(%s) subdissector ate %d bytes\n",name,count);
}
#endif
			if((count==0)&&(((ch->class==class)&&(ch->tag==-1)&&(ch->flags&BER_FLAGS_NOOWNTAG)) || !first_pass)){
				/* wrong one, break and try again */
				ch++;
#ifdef DEBUG_BER_CHOICE
{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
printf("CHOICE dissect_ber_old_choice(%s) trying again\n",name);
}
#endif
				goto choice_try_again;
			}
			if(!(ch->flags & BER_FLAGS_NOOWNTAG)){
			 if(ind)
			 	{
			 	/* we are traversing a indfinite length choice where we did not pass the tag length */
			 	/* we need to eat the EOC */
			 	if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, start_offset, count+2, "CHOICE EOC");
				}
			 }
			}
			return end_offset;
		}
		ch++;
	}
	if(branch_taken){
		/* none of the branches were taken so set the param
		   back to -1 */
		*branch_taken=-1;
	}

#ifdef REMOVED
	/*XXX here we should have another flag to the CHOICE to distinguish
	 * between the case when we know it is a mandatory   or if the CHOICE is optional == no arm matched */

	/* oops no more entries and we still havent found
	 * our guy :-(
	 */
	cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "missing_choice_field", "BER Error: This choice field was not found.");
	expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: This choice field was not found");
	return end_offset;
#endif

	return start_offset;
}

#if 0
/* this function dissects a BER GeneralString
 */
int
dissect_ber_GeneralString(asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, char *name_string, int name_len)
{
	gint8 class;
	gboolean pc;
	gint32 tag;
	guint32 len;
	int end_offset;
	int hoffset;
	char str_arr[256];
	guint32 max_len;
	char *str;
	proto_item *cause;

	str=str_arr;
	max_len=255;
	if(name_string){
		str=name_string;
		max_len=name_len;
	}

	hoffset = offset;
	/* first we must read the GeneralString header */
	offset=dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &class, &pc, &tag);
	offset=dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, NULL);
	end_offset=offset+len;

	/* sanity check: we only handle Universal GeneralString*/
	if( (class!=BER_CLASS_UNI)
	  ||(tag!=BER_UNI_TAG_GENSTR) ){
		tvb_ensure_bytes_exist(tvb, hoffset, 2);
		cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "generalstring_expected", "BER Error: GeneralString expected but class:%s(%d) %s tag:%d was unexpected", val_to_str(class,ber_class_codes,"Unknown"), class, pc ? ber_pc_codes_short.true_string : ber_pc_codes_short.false_string, tag);
		expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: GeneralString expected");
		if (decode_unexpected) {
		  proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
		  dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
		}
		return end_offset;
	}

	if(len>=(max_len-1)){
		len=max_len-1;
	}

	tvb_memcpy(tvb, str, offset, len);
	str[len]=0;

	if(hf_id >= 0){
		proto_tree_add_string(tree, hf_id, tvb, offset, len, str);
	}

	return end_offset;
}
#endif

int dissect_ber_constrained_restricted_string(gboolean implicit_tag, gint32 type,  asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint32 min_len, gint32 max_len, gint hf_id, tvbuff_t **out_tvb) {
	gint8 class;
	gboolean pc;
	gint32 tag;
	guint32 len;
	int eoffset;
	int hoffset = offset;
	proto_item *cause;

#ifdef DEBUG_BER
{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("RESTRICTED STRING dissect_ber_octet string(%s) entered implicit_tag:%d offset:%d len:%d %02x:%02x:%02x\n",name,implicit_tag,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("RESTRICTED STRING dissect_ber_octet_string(%s) entered\n",name);
}
}
#endif

	if(!implicit_tag) {
		offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
		offset = get_ber_length(tvb, offset, &len, NULL);
		eoffset = offset + len;

		/* sanity check */
		if( (class!=BER_CLASS_UNI)
		  ||(tag != type) ){
	            tvb_ensure_bytes_exist(tvb, hoffset, 2);
		    cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "string_expected", "BER Error: String with tag=%d expected but class:%s(%d) %s tag:%d was unexpected", type, val_to_str(class,ber_class_codes,"Unknown"), class, pc ? ber_pc_codes_short.true_string : ber_pc_codes_short.false_string, tag);
		    expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: String expected");
		    if (decode_unexpected) {
		      proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
		      dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
		    }
		    return eoffset;
		}
	}

	/* 8.21.3 */
	return dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, hoffset, min_len, max_len, hf_id, out_tvb);
}

int dissect_ber_restricted_string(gboolean implicit_tag, gint32 type, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, tvbuff_t **out_tvb)
{
	return dissect_ber_constrained_restricted_string(implicit_tag, type, actx, tree, tvb, offset, NO_BOUND, NO_BOUND, hf_id, out_tvb);
}

int
dissect_ber_GeneralString(asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, char *name_string, guint name_len)
{
	tvbuff_t *out_tvb = NULL;
	gint tvb_len;

	offset = dissect_ber_restricted_string(FALSE, BER_UNI_TAG_GeneralString, actx, tree, tvb, offset, hf_id, (name_string)?&out_tvb:NULL);

	if(name_string) {
		/*
		 * XXX - do we want to just get what's left in the tvbuff
		 * if the full length isn't available in the tvbuff, or
		 * do we want to throw an exception?
		 */
		if(out_tvb) {
			tvb_len = tvb_length(out_tvb);
			if((guint)tvb_len >= name_len) {
				tvb_memcpy(out_tvb, (guint8*)name_string, 0, name_len-1);
				name_string[name_len-1] = '\0';
			} else {
				tvb_memcpy(out_tvb, (guint8*)name_string, 0, tvb_len);
				name_string[tvb_len] = '\0';
			}
		}
	}

	return offset;
}

/* 8.19 Encoding of an object identifier value.
 */
int dissect_ber_object_identifier(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, tvbuff_t **value_tvb)
{
	gint8 class;
	gboolean pc;
	gint32 tag;
	guint32 len;
	int eoffset;
	int hoffset;
	const char *str;
	proto_item *cause;
	header_field_info *hfi;
	const gchar *name;

#ifdef DEBUG_BER
{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("OBJECT IDENTIFIER dissect_ber_object_identifier(%s) entered implicit_tag:%d offset:%d len:%d %02x:%02x:%02x\n",name,implicit_tag,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("OBJECT IDENTIFIER dissect_ber_object_identifier(%s) entered\n",name);
}
}
#endif

	if(!implicit_tag) {
		hoffset = offset;
		/* sanity check */
		offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &class, &pc, &tag);
		offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, NULL);
		eoffset = offset + len;
		if( (class!=BER_CLASS_UNI)
		  ||(tag != BER_UNI_TAG_OID) ){
	            tvb_ensure_bytes_exist(tvb, hoffset, 2);
		    cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "oid_expected", "BER Error: Object Identifier expected but class:%s(%d) %s tag:%d was unexpected", val_to_str(class,ber_class_codes,"Unknown"), class, pc ? ber_pc_codes_short.true_string : ber_pc_codes_short.false_string, tag);
		    expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Object Identifier expected");
		    if (decode_unexpected) {
		      proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
		      dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
		    }
		    return eoffset;
		}
	} else {
		len=tvb_length_remaining(tvb,offset);
		eoffset=offset+len;
	}

	actx->created_item=NULL;
	hfi = proto_registrar_get_nth(hf_id);
	if (hfi->type == FT_OID) {
		actx->created_item = proto_tree_add_item(tree, hf_id, tvb, offset, len, ENC_BIG_ENDIAN);
	} else if (IS_FT_STRING(hfi->type)) {
		str = oid_encoded2string(tvb_get_ptr(tvb, offset, len), len);
		actx->created_item = proto_tree_add_string(tree, hf_id, tvb, offset, len, str);
		if(actx->created_item){
			/* see if we know the name of this oid */
			name = oid_resolved_from_encoded(tvb_get_ptr(tvb, offset, len), len);
			if(name){
				proto_item_append_text(actx->created_item, " (%s)", name);
			}
		}
	} else {
		DISSECTOR_ASSERT_NOT_REACHED();
	}

	if (value_tvb)
		*value_tvb = tvb_new_subset(tvb, offset, len, len);

	return eoffset;
}

int dissect_ber_object_identifier_str(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, const char **value_stringx)
{
  tvbuff_t *value_tvb = NULL;
  guint length;

  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_id, (value_stringx) ? &value_tvb : NULL);

  if (value_stringx) {
    if (value_tvb && (length = tvb_length(value_tvb))) {
      *value_stringx = oid_encoded2string(tvb_get_ptr(value_tvb, 0, length), length);
    } else {
      *value_stringx = "";
    }
  }

  return offset;
}

#ifdef DEBUG_BER
#define DEBUG_BER_SQ_OF
#endif

static int dissect_ber_sq_of(gboolean implicit_tag, gint32 type, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, gint32 min_len, gint32 max_len, const ber_sequence_t *seq, gint hf_id, gint ett_id) {
	gint8 classx;
	gboolean pcx, ind = FALSE, ind_field;
	gint32 tagx;
	guint32 lenx;

	proto_tree *tree = parent_tree;
	proto_item *item = NULL;
	proto_item *causex;
	int cnt, hoffsetx, end_offset;
	header_field_info *hfi;
	gint length_remaining;
	tvbuff_t *next_tvb;

#ifdef DEBUG_BER_SQ_OF
{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("SQ OF dissect_ber_sq_of(%s) entered implicit_tag:%d offset:%d len:%d %02x:%02x:%02x\n",name,implicit_tag,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("SQ OF dissect_ber_sq_of(%s) entered\n",name);
}
}
#endif

	if(!implicit_tag){
		hoffsetx = offset;
		/* first we must read the sequence header */
		offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &classx, &pcx, &tagx);
		offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &lenx, &ind);
		if(ind){
		  /* if the length is indefinite we dont really know (yet) where the
		   * object ends so assume it spans the rest of the tvb for now.
        	   */
		  end_offset = offset + lenx;
		} else {
		  end_offset = offset + lenx;
		}

		/* sanity check: we only handle Constructed Universal Sequences */
		if((classx!=BER_CLASS_APP)&&(classx!=BER_CLASS_PRI))
		if(!pcx
			||(!implicit_tag&&((classx!=BER_CLASS_UNI)
							||(tagx!=type)))) {
			tvb_ensure_bytes_exist(tvb, hoffsetx, 2);
			causex = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, lenx, (type==BER_UNI_TAG_SEQUENCE)?"set_of_expected":"sequence_of_expected", "BER Error: %s Of expected but class:%s(%d) %s tag:%d was unexpected",
							(type==BER_UNI_TAG_SEQUENCE)?"Set":"Sequence", val_to_str(classx,ber_class_codes,"Unknown"), classx, pcx ? ber_pc_codes_short.true_string : ber_pc_codes_short.false_string, tagx);
			expert_add_info_format(actx->pinfo, causex, PI_MALFORMED, PI_WARN, "BER Error: %s Of expected",(type==BER_UNI_TAG_SEQUENCE)?"Set":"Sequence");
			if (decode_unexpected) {
			  proto_tree *unknown_tree = proto_item_add_subtree(causex, ett_ber_unknown);
			  dissect_unknown_ber(actx->pinfo, tvb, hoffsetx, unknown_tree);
			}
			return end_offset;
		}
	} else {
		/* the tvb length should be correct now nope we could be comming from an implicit choice or sequence, thus we
		read the items we match and return the length*/
		lenx=tvb_length_remaining(tvb,offset);
		end_offset = offset + lenx;
	}

	/* count number of items */
	cnt = 0;
	hoffsetx = offset;
	/* only count the number of items IFF we have the full blob,
	 * else this will just generate a [short frame] before we even start
	 * dissecting a single item.
	 */
	/* XXX Do we really need to count them at all ?  ronnie */
	if(tvb_length_remaining(tvb, offset)==tvb_reported_length_remaining(tvb, offset)){
		while (offset < end_offset){
			guint32 len;
                        gint s_offset;

                        s_offset = offset;

			/*if(ind){  this sequence of was of indefinite length, if this is implicit indefinite impossible maybe
			  but ber dissector uses this to eat the tag length then pass into here... EOC still on there...*/
				if((tvb_get_guint8(tvb, offset)==0)&&(tvb_get_guint8(tvb, offset+1)==0)){
					break;
				}
			/*}*/

			/* read header and len for next field */
			offset = get_ber_identifier(tvb, offset, NULL, NULL, NULL);
			offset = get_ber_length(tvb, offset, &len, &ind);
			/* best place to get real length of implicit sequence of or set of is here... */
			/* adjust end_offset if we find somthing that doesnt match */
			offset += len;
			cnt++;
			if (offset <= s_offset)
				THROW(ReportedBoundsError);
		}
	}
	offset = hoffsetx;

	/* create subtree */
	if(hf_id >= 0) {
		hfi = proto_registrar_get_nth(hf_id);
		if(parent_tree){
			if(hfi->type == FT_NONE) {
				item = proto_tree_add_item(parent_tree, hf_id, tvb, offset, lenx, ENC_BIG_ENDIAN);
				proto_item_append_text(item, ":");
			} else {
				item = proto_tree_add_uint(parent_tree, hf_id, tvb, offset, lenx, cnt);
				proto_item_append_text(item, (cnt==1)?" item":" items");
			}
			tree = proto_item_add_subtree(item, ett_id);
			ber_check_items (cnt, min_len, max_len, actx, item);
		}
	}

	/* loop over all entries until we reach the end of the sequence */
	while (offset < end_offset){
		gint8 class;
		gboolean pc;
		gint32 tag;
		guint32 len;
		int eoffset;
		int hoffset;
		proto_item *cause;
		gboolean imp_tag;

		hoffset = offset;
		/*if(ind){  this sequence was of indefinite length, if this is implicit indefinite impossible maybe
		  but ber dissector uses this to eat the tag length then pass into here... EOC still on there...*/
			if((tvb_get_guint8(tvb, offset)==0)&&(tvb_get_guint8(tvb, offset+1)==0)){
				if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, hoffset, end_offset-hoffset, "SEQ OF EOC");
				}
				return offset+2;
			}
		/*}*/
		/* read header and len for next field */
		offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
		offset = get_ber_length(tvb, offset, &len, &ind_field);
		eoffset = offset + len;
                /* Make sure we move forward */
		if (eoffset <= hoffset)
			THROW(ReportedBoundsError);

		if((class==BER_CLASS_UNI)&&(tag==BER_UNI_TAG_EOC)){
			/* This is a zero length sequence of*/
			hoffset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			hoffset = dissect_ber_length(actx->pinfo, tree, tvb, hoffset, NULL, NULL);
			return eoffset;
		}
		/* verify that this one is the one we want */
		/* ahup if we are implicit then we return to the uper layer how much we have used */
		if(seq->class!=BER_CLASS_ANY){
		  if((seq->class!=class)
			||(seq->tag!=tag) ){
			if(!(seq->flags & BER_FLAGS_NOTCHKTAG)) {
				cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "wrong_field", "BER Error: Wrong field in SQ OF(tag %u expected %u)",tag,seq->tag);
				expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Wrong field in Sequence Of");
				if (decode_unexpected) {
				  proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
				  dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
				}
				offset = eoffset;
				continue;
				/* wrong.... */
			}
		  }
		}

		if(!(seq->flags & BER_FLAGS_NOOWNTAG) && !(seq->flags & BER_FLAGS_IMPLTAG)) {
			/* dissect header and len for field */
			hoffset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			hoffset = dissect_ber_length(actx->pinfo, tree, tvb, hoffset, NULL, NULL);
		}
		if((seq->flags == BER_FLAGS_IMPLTAG)&&(seq->class==BER_CLASS_CON)) {
			/* Constructed sequence of with a tag */
			/* dissect header and len for field */
			hoffset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			hoffset = dissect_ber_length(actx->pinfo, tree, tvb, hoffset, NULL, NULL);
			/* Function has IMPLICIT TAG */
		}

		length_remaining=tvb_length_remaining(tvb, hoffset);
		if (length_remaining>eoffset-hoffset)
			length_remaining=eoffset-hoffset;
		next_tvb = tvb_new_subset(tvb, hoffset, length_remaining, eoffset-hoffset);

		imp_tag = FALSE;
		if(seq->flags == BER_FLAGS_IMPLTAG)
			imp_tag = TRUE;
		/* call the dissector for this field */
		seq->func(imp_tag, next_tvb, 0, actx, tree, *seq->p_id);
				/* hold on if we are implicit and the result is zero, i.e. the item in the sequence of
				doesnt match the next item, thus this implicit sequence is over, return the number of bytes
				we have eaten to allow the possible upper sequence continue... */
		cnt++; /* rubbish*/
		offset = eoffset;
	}

	/* if we didnt end up at exactly offset, then we ate too many bytes */
	if(offset != end_offset) {
		tvb_ensure_bytes_exist(tvb, offset-2, 2);
		causex =proto_tree_add_string_format(tree, hf_ber_error, tvb, offset-2, 2, "illegal_length", "BER Error: %s Of ate %d too many bytes",
							(type==BER_UNI_TAG_SEQUENCE)?"Set":"Sequence", offset-end_offset);
		expert_add_info_format(actx->pinfo, causex, PI_MALFORMED, PI_WARN, "BER Error:too many byte in %s",(type==BER_UNI_TAG_SEQUENCE)?"Set":"Sequence");
	}

	return end_offset;
}

static int dissect_ber_old_sq_of(gboolean implicit_tag, gint32 type, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_old_sequence_t *seq, gint hf_id, gint ett_id) {
	gint8 classx;
	gboolean pcx, ind = FALSE, ind_field;
	gint32 tagx;
	guint32 lenx;

	proto_tree *tree = parent_tree;
	proto_item *item = NULL;
	proto_item *causex;
	int cnt, hoffsetx, end_offset;
	header_field_info *hfi;
	gint length_remaining;

#ifdef DEBUG_BER_SQ_OF
{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("SQ OF dissect_ber_old_sq_of(%s) entered implicit_tag:%d offset:%d len:%d %02x:%02x:%02x\n",name,implicit_tag,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("SQ OF dissect_ber_old_sq_of(%s) entered\n",name);
}
}
#endif

	if(!implicit_tag){
		hoffsetx = offset;
		/* first we must read the sequence header */
		offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &classx, &pcx, &tagx);
		offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &lenx, &ind);
		if(ind){
		  /* if the length is indefinite we dont really know (yet) where the
		   * object ends so assume it spans the rest of the tvb for now.
        	   */
		  end_offset = offset + lenx;
		} else {
		  end_offset = offset + lenx;
		}

		/* sanity check: we only handle Constructed Universal Sequences */
		if((classx!=BER_CLASS_APP)&&(classx!=BER_CLASS_PRI))
		if(!pcx
			||(!implicit_tag&&((classx!=BER_CLASS_UNI)
							||(tagx!=type)))) {
			tvb_ensure_bytes_exist(tvb, hoffsetx, 2);
			causex = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, lenx, (type==BER_UNI_TAG_SEQUENCE)?"set_of_expected":"sequence_of_expected", "BER Error: %s Of expected but class:%s(%d) %s tag:%d was unexpected",
							(type==BER_UNI_TAG_SEQUENCE)?"Set":"Sequence", val_to_str(classx,ber_class_codes,"Unknown"), classx, pcx ? ber_pc_codes_short.true_string : ber_pc_codes_short.false_string, tagx);
			expert_add_info_format(actx->pinfo, causex, PI_MALFORMED, PI_WARN, "BER Error: %s Of expected",(type==BER_UNI_TAG_SEQUENCE)?"Set":"Sequence");
			if (decode_unexpected) {
			  proto_tree *unknown_tree = proto_item_add_subtree(causex, ett_ber_unknown);
			  dissect_unknown_ber(actx->pinfo, tvb, hoffsetx, unknown_tree);
			}
			return end_offset;
		}
	} else {
		/* the tvb length should be correct now nope we could be comming from an implicit choice or sequence, thus we
		read the items we match and return the length*/
		lenx=tvb_length_remaining(tvb,offset);
		end_offset = offset + lenx;
	}

	/* count number of items */
	cnt = 0;
	hoffsetx = offset;
	/* only count the number of items IFF we have the full blob,
	 * else this will just generate a [short frame] before we even start
	 * dissecting a single item.
	 */
	/* XXX Do we really need to count them at all ?  ronnie */
	if(tvb_length_remaining(tvb, offset)==tvb_reported_length_remaining(tvb, offset)){
		while (offset < end_offset){
			guint32 len;
                        gint s_offset;

                        s_offset = offset;

			if(ind){ /* this sequence of was of indefinite length, so check for EOC */
				if((tvb_get_guint8(tvb, offset)==0)&&(tvb_get_guint8(tvb, offset+1)==0)){
					break;
				}
			}

			/* read header and len for next field */
			offset = get_ber_identifier(tvb, offset, NULL, NULL, NULL);
			offset = get_ber_length(tvb, offset, &len, &ind);
			/* best place to get real length of implicit sequence of or set of is here... */
			/* adjust end_offset if we find somthing that doesnt match */
			offset += len;
			cnt++;
			if (offset <= s_offset)
				THROW(ReportedBoundsError);
		}
	}
	offset = hoffsetx;

	/* create subtree */
	if(hf_id >= 0) {
		hfi = proto_registrar_get_nth(hf_id);
		if(parent_tree){
			if(hfi->type == FT_NONE) {
				item = proto_tree_add_item(parent_tree, hf_id, tvb, offset, lenx, ENC_BIG_ENDIAN);
				proto_item_append_text(item, ":");
			} else {
				item = proto_tree_add_uint(parent_tree, hf_id, tvb, offset, lenx, cnt);
				proto_item_append_text(item, (cnt==1)?" item":" items");
			}
			tree = proto_item_add_subtree(item, ett_id);
		}
	}

	/* loop over all entries until we reach the end of the sequence */
	while (offset < end_offset){
		gint8 class;
		gboolean pc;
		gint32 tag;
		guint32 len;
		int eoffset;
		int hoffset;
		proto_item *cause;

		hoffset = offset;
	 	if(ind){ /*this sequence of was of indefinite length, so check for EOC */
			if((tvb_get_guint8(tvb, offset)==0)&&(tvb_get_guint8(tvb, offset+1)==0)){
				if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, hoffset, end_offset-hoffset, "SEQ OF EOC");
				}
				return offset+2;
			}
		}
		/* read header and len for next field */
		offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
		offset = get_ber_length(tvb, offset, &len, &ind_field);
		eoffset = offset + len;
                /* Make sure we move forward */
		if (eoffset <= hoffset)
			THROW(ReportedBoundsError);

		if((class==BER_CLASS_UNI)&&(tag==BER_UNI_TAG_EOC)){
			/* This is a zero length sequence of*/
			hoffset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			hoffset = dissect_ber_length(actx->pinfo, tree, tvb, hoffset, NULL, NULL);
			return eoffset;
		}
		/* verify that this one is the one we want */
		/* ahup if we are implicit then we return to the uper layer how much we have used */
		if(seq->class!=BER_CLASS_ANY){
		  if((seq->class!=class)
			||(seq->tag!=tag) ){
			if(!(seq->flags & BER_FLAGS_NOTCHKTAG)) {
				cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "wrong_field", "BER Error: Wrong field in SQ OF");
				expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Wrong field in Sequence Of");
				if (decode_unexpected) {
				  proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
				  dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
				}
				offset = eoffset;
				continue;
				/* wrong.... */
			}
		  }
		}

		if(!(seq->flags & BER_FLAGS_NOOWNTAG) && !(seq->flags & BER_FLAGS_IMPLTAG)) {
			/* dissect header and len for field */
			hoffset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			hoffset = dissect_ber_length(actx->pinfo, tree, tvb, hoffset, NULL, NULL);
		}
		if((seq->flags == BER_FLAGS_IMPLTAG)&&(seq->class==BER_CLASS_CON)) {
			/* Constructed sequence of with a tag */
			/* dissect header and len for field */
			hoffset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			hoffset = dissect_ber_length(actx->pinfo, tree, tvb, hoffset, NULL, NULL);
		}

		length_remaining=tvb_length_remaining(tvb, hoffset);
		if (length_remaining>eoffset-hoffset)
			length_remaining=eoffset-hoffset;


		/* call the dissector for this field */
		seq->func(tree, tvb, hoffset, actx);
				/* hold on if we are implicit and the result is zero, i.e. the item in the sequence of
				doesnt match the next item, thus this implicit sequence is over, return the number of bytes
				we have eaten to allow the possible upper sequence continue... */
		cnt++; /* rubbish*/
		offset = eoffset;
	}

	/* if we didnt end up at exactly offset, then we ate too many bytes */
	if(offset != end_offset) {
		tvb_ensure_bytes_exist(tvb, offset-2, 2);
		causex =proto_tree_add_string_format(tree, hf_ber_error, tvb, offset-2, 2, "illegal_length", "BER Error: %s Of ate %d too many bytes",
							(type==BER_UNI_TAG_SEQUENCE)?"Set":"Sequence", offset-end_offset);
		expert_add_info_format(actx->pinfo, causex, PI_MALFORMED, PI_WARN, "BER Error:too many byte in %s",(type==BER_UNI_TAG_SEQUENCE)?"Set":"Sequence");
	}

	return end_offset;
}

int dissect_ber_constrained_sequence_of(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, gint32 min_len, gint32 max_len, const ber_sequence_t *seq, gint hf_id, gint ett_id) {
	return dissect_ber_sq_of(implicit_tag, BER_UNI_TAG_SEQUENCE, actx, parent_tree, tvb, offset, min_len, max_len, seq, hf_id, ett_id);
}

int dissect_ber_sequence_of(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_sequence_t *seq, gint hf_id, gint ett_id) {
	return dissect_ber_sq_of(implicit_tag, BER_UNI_TAG_SEQUENCE, actx, parent_tree, tvb, offset, NO_BOUND, NO_BOUND, seq, hf_id, ett_id);
}

int dissect_ber_constrained_set_of(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, gint32 min_len, gint32 max_len, const ber_sequence_t *seq, gint hf_id, gint ett_id) {
	return dissect_ber_sq_of(implicit_tag, BER_UNI_TAG_SET, actx, parent_tree, tvb, offset, min_len, max_len, seq, hf_id, ett_id);
}

int dissect_ber_set_of(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_sequence_t *seq, gint hf_id, gint ett_id) {
	return dissect_ber_sq_of(implicit_tag, BER_UNI_TAG_SET, actx, parent_tree, tvb, offset, NO_BOUND, NO_BOUND, seq, hf_id, ett_id);
}

int dissect_ber_old_sequence_of(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_old_sequence_t *seq, gint hf_id, gint ett_id) {
	return dissect_ber_old_sq_of(implicit_tag, BER_UNI_TAG_SEQUENCE, actx, parent_tree, tvb, offset, seq, hf_id, ett_id);
}

int dissect_ber_old_set_of(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_old_sequence_t *seq, gint hf_id, gint ett_id) {
	return dissect_ber_old_sq_of(implicit_tag, BER_UNI_TAG_SET, actx, parent_tree, tvb, offset, seq, hf_id, ett_id);
}

int
dissect_ber_GeneralizedTime(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id)
{
	char str[35];
	int tmp_int;
	const guint8 *tmpstr;
	char *strptr;
	char first_delim[2];
	int first_digits;
	char second_delim[2];
	int second_digits;
	int ret;
	gint8 class;
	gboolean pc;
	gint32 tag;
	guint32 len;
	int end_offset;
	int hoffset;
	proto_item *cause;

	if(!implicit_tag){
	  hoffset = offset;
	  offset=dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &class, &pc, &tag);
	  offset=dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, NULL);
	  end_offset=offset+len;

	  /* sanity check. we only handle universal/generalized time */
	  if( (class!=BER_CLASS_UNI)
	  ||(tag!=BER_UNI_TAG_GeneralizedTime)){
		tvb_ensure_bytes_exist(tvb, hoffset, 2);
		cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "generalized_time_expected", "BER Error: GeneralizedTime expected but class:%s(%d) %s tag:%d was unexpected", val_to_str(class,ber_class_codes,"Unknown"), class, pc ? ber_pc_codes_short.true_string : ber_pc_codes_short.false_string, tag);
		expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: GeneralizedTime expected");
		if (decode_unexpected) {
		  proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
		  dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
		}
		return end_offset;
	  }
        } else {
	  len=tvb_length_remaining(tvb,offset);
	  end_offset=offset+len;
	}

	if (len < 14 || len > 23) {
		cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "illegal_length", "BER Error: GeneralizedTime invalid length: %u", len);
		expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: GeneralizedTime invalid length");
		if (decode_unexpected) {
			proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
			dissect_unknown_ber(actx->pinfo, tvb, offset, unknown_tree);
		}
		return end_offset;
	}

	tmpstr=tvb_get_ephemeral_string(tvb, offset, len);
	strptr = str;
	/* those fields are allways present */
	strptr += g_snprintf(str, 20, "%.4s-%.2s-%.2s %.2s:%.2s:%.2s",
			tmpstr, tmpstr+4, tmpstr+6, tmpstr+8,
			tmpstr+10, tmpstr+12);

	first_delim[0]=0;
	second_delim[0]=0;
	ret = sscanf( tmpstr, "%14d%1[.,+-Z]%4d%1[+-Z]%4d", &tmp_int, first_delim, &first_digits, second_delim, &second_digits);
	/* tmp_int does not contain valid value bacause of overflow but we use it just for format checking */
	if (ret < 1) {
		cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "invalid_generalized_time", "BER Error: GeneralizedTime invalid format: %s", tmpstr);
		expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: GeneralizedTime invalid format");
		if (decode_unexpected) {
			proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
			dissect_unknown_ber(actx->pinfo, tvb, offset, unknown_tree);
		}
		return end_offset;
	}

	switch (first_delim[0]) {
		case '.':
		case ',':
			strptr += g_snprintf(strptr, 5, "%c%.3d", first_delim[0], first_digits);
			switch (second_delim[0]) {
				case '+':
				case '-':
					g_snprintf(strptr, 12, " (UTC%c%.4d)", second_delim[0], second_digits);
					break;
				case 'Z':
					g_snprintf(strptr, 7, " (UTC)");
					break;
				case 0:
					break;
				default:
					/* handle the malformed field */
					break;
			}
			break;
		case '+':
		case '-':
			g_snprintf(strptr, 12, " (UTC%c%.4d)", first_delim[0], first_digits);
			break;
		case 'Z':
			g_snprintf(strptr, 7, " (UTC)");
			break;
		case 0:
			break;
		default:
			/* handle the malformed field */
			break;
	}

	if(hf_id >= 0){
		proto_tree_add_string(tree, hf_id, tvb, offset, len, str);
	}

	offset+=len;
	return offset;
}


int
dissect_ber_UTCTime(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id)
{
	char outstr[33];
	char *outstrptr = outstr;
	const guint8 *instr;
	gint8 class;
	gboolean pc;
	gint32 tag;
	guint32 len, i, n;
	int hoffset;
	proto_item *cause;
	proto_tree *error_tree;
	gchar *error_str = NULL;

	if(!implicit_tag){
		hoffset = offset;
		offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &class, &pc, &tag);
		offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, NULL);

		/* sanity check: we only handle UTCTime */
		if( (class!=BER_CLASS_UNI) || (tag!=BER_UNI_TAG_UTCTime) ) {
			tvb_ensure_bytes_exist(tvb, hoffset, 2);
			cause = proto_tree_add_string_format(tree, hf_ber_error, tvb, offset, len, "utctime_expected",
					"BER Error: UTCTime expected but class:%s(%d) %s tag:%d was unexpected",
					val_to_str(class,ber_class_codes,"Unknown"), class,
					pc ? ber_pc_codes_short.true_string : ber_pc_codes_short.false_string, tag);
			expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: UTCTime expected");
			if (decode_unexpected) {
				proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
				dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
			}
			return offset+len;
		}
	} else {
		len = tvb_length_remaining(tvb,offset);
	}

	if (len < 10 || len > 19) {
		error_str = g_strdup_printf("BER Error: UTCTime invalid length: %u", len);
		instr = tvb_get_ephemeral_string(tvb, offset, len > 19 ? 19 : len);
		goto malformed;
	}

	instr = tvb_get_ephemeral_string(tvb, offset, len);

	/* YYMMDDhhmm */
	for(i=0;i<10;i++) {
		if(instr[i] < '0' || instr[i] > '9') {
			error_str = g_strdup("BER Error: malformed UTCTime encoding, "
					"first 10 octets have to contain YYMMDDhhmm in digits");
			goto malformed;
		}
	}
	g_snprintf(outstrptr, 15, "%.2s-%.2s-%.2s %.2s:%.2s", instr, instr+2, instr+4, instr+6, instr+8);
	outstrptr+= 14;

	/* (ss)? */
	if(len >= 12) {
		if(instr[i] >= '0' && instr[i] <= '9') {
			i++;
			if(instr[i] >= '0' && instr[i] <= '9') {
				i++;
				g_snprintf(outstrptr, 4, ":%.2s", instr+10);
				outstrptr+=3;
			} else {
				error_str = g_strdup("BER Error: malformed UTCTime encoding, "
						"if 11th octet is a digit for seconds, "
						"the 12th octet has to be a digit, too");
				goto malformed;
			}
		}
	}

	/* Z|([+-]hhmm) */
	switch (instr[i]) {
		case 'Z':
			if(len!=i+1) {
				error_str = g_strdup("BER Error: malformed UTCTime encoding, "
						"there must be no further octets after \'Z\'");
				goto malformed;
			}
			g_snprintf(outstrptr, 7, " (UTC)");
			i++;
			break;
		case '-':
		case '+':
			if(len!=i+5) {
				error_str = g_strdup("BER Error: malformed UTCTime encoding, "
						"4 digits must follow on \'+\' resp. \'-\'");
				goto malformed;
			}
			for(n=i+1;n<i+5;n++) {
				if(instr[n] < '0' || instr[n] > '9') {
					error_str = g_strdup("BER Error: malformed UTCTime encoding, "
							"4 digits must follow on \'+\' resp. \'-\'");
					goto malformed;
				}
			}
			g_snprintf(outstrptr, 12, " (UTC%c%.4s)", instr[i], instr+i+1);
			i+=5;
			break;
		default:
			error_str = g_strdup_printf("BER Error: malformed UTCTime encoding, "
					"unexpected character in %dth octet, "
					"must be \'Z\', \'+\' or \'-\'", i+1);
			goto malformed;
			break;
	}

	if(len!=i) {
		error_str = g_strdup_printf("BER Error: malformed UTCTime encoding, "
				"%d unexpected character%s after %dth octet",
				len-i, (len==i-1?"s":""), i);
		goto malformed;
	}

	if(hf_id >= 0){
		proto_tree_add_string(tree, hf_id, tvb, offset, len, outstr);
	}

	return offset+len;
malformed:
	if(hf_id >= 0){
 		cause = proto_tree_add_string(tree, hf_id, tvb, offset, len, instr);
 		error_tree = proto_item_add_subtree(cause, ett_ber_unknown);
 	} else {
 		error_tree = tree;
 	}
 	
 	cause = proto_tree_add_string_format(error_tree, hf_ber_error, tvb, offset, len, "invalid_utctime", "%s", error_str);
	expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: malformed UTCTime encoding");
	g_free (error_str);

	return offset+len;
}


/* 8.6 Encoding of a bitstring value */
int dissect_ber_constrained_bitstring(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, gint32 min_len, gint32 max_len, const asn_namedbit *named_bits, gint hf_id, gint ett_id, tvbuff_t **out_tvb)
{
	gint8 class;
	gboolean pc, ind;
	gint32 tag;
	guint32 len, byteno;
	guint8 pad=0, b0, b1, val, *bitstring;
	int end_offset;
	int hoffset;
	proto_item *item = NULL;
	proto_item *cause;
	proto_tree *tree = NULL;
	const asn_namedbit *nb;
	const char *sep;
	gboolean term;

	if(!implicit_tag){
	  hoffset = offset;
	  /* read header and len for the octet string */
	  offset = dissect_ber_identifier(actx->pinfo, parent_tree, tvb, offset, &class, &pc, &tag);
	  offset = dissect_ber_length(actx->pinfo, parent_tree, tvb, offset, &len, &ind);
	  end_offset = offset + len;

	  /* sanity check: we only handle Universal BitStrings */

	  /* for an IMPLICIT APPLICATION tag asn2eth seems to call this
	     function with implicit_tag = FALSE. BER_FLAGS_NOOWNTAG was
	     set so the APPLICATION tag was still present.
	     So here we relax it for APPLICATION tags. CONTEXT tags may
	     still cause a problem. */

	  if(!implicit_tag && (class!=BER_CLASS_APP)) {
		if( (class!=BER_CLASS_UNI)
		  ||(tag!=BER_UNI_TAG_BITSTRING) ){
		    tvb_ensure_bytes_exist(tvb, hoffset, 2);
		    cause = proto_tree_add_string_format(parent_tree, hf_ber_error, tvb, offset, len, "bitstring_expected", "BER Error: BitString expected but class:%s(%d) %s tag:%d was unexpected", val_to_str(class,ber_class_codes,"Unknown"), class, pc ? ber_pc_codes_short.true_string : ber_pc_codes_short.false_string, tag);
		    expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: BitString expected");
		    if (decode_unexpected) {
		      proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
		      dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
		    }
		    return end_offset;
		}
	  }
	} else {
	  pc=0;
	  len=tvb_length_remaining(tvb,offset);
	  end_offset=offset+len;
	}

	actx->created_item = NULL;

	if(pc) {
		/* constructed */
		/* TO DO */
	} else {
		/* primitive */
		pad = tvb_get_guint8(tvb, offset);
		if(pad == 0 && len == 1) {
			/* empty */
			proto_tree_add_item(parent_tree, hf_ber_bitstring_empty, tvb, offset, 1, ENC_BIG_ENDIAN);
		} else {
			/* padding */
			proto_item *pad_item = proto_tree_add_item(parent_tree, hf_ber_bitstring_padding, tvb, offset, 1, ENC_BIG_ENDIAN);
			if (pad > 7) {
				expert_add_info_format(actx->pinfo, pad_item, PI_UNDECODED, PI_WARN,
						       "Illegal padding (0 .. 7): %d", pad);
			}
		}
		offset++;
		len--;
		if(hf_id >= 0) {
			item = proto_tree_add_item(parent_tree, hf_id, tvb, offset, len, ENC_BIG_ENDIAN);
			actx->created_item = item;
			if(ett_id != -1) {
				tree = proto_item_add_subtree(item, ett_id);
			}
		}
		if(out_tvb) {
			if(len<=(guint32)tvb_length_remaining(tvb, offset)){
				*out_tvb = tvb_new_subset(tvb, offset, len, len);
			} else {
				*out_tvb = tvb_new_subset_remaining(tvb, offset);
			}
		}
	}

	if(named_bits) {
		sep = " (";
		term = FALSE;
		nb = named_bits;
		bitstring = tvb_get_ephemeral_string(tvb, offset, len);

		while (nb->p_id) {
			if(len > 0 && nb->bit < (8*len-pad)) {
				val = tvb_get_guint8(tvb, offset + nb->bit/8);
				bitstring[(nb->bit/8)] &= ~(0x80 >> (nb->bit%8));
				val &= 0x80 >> (nb->bit%8);
				b0 = (nb->gb0 == -1) ? nb->bit/8 :
						       ((guint32)nb->gb0)/8;
				b1 = (nb->gb1 == -1) ? nb->bit/8 :
						       ((guint32)nb->gb1)/8;
				proto_tree_add_item(tree, *(nb->p_id), tvb, offset + b0, b1 - b0 + 1, ENC_BIG_ENDIAN);
			} else {  /* 8.6.2.4 */
				val = 0;
				proto_tree_add_boolean(tree, *(nb->p_id), tvb, offset + len, 0, 0x00);
			}
			if(val) {
				if(item && nb->tstr) {
					proto_item_append_text(item, "%s%s", sep, nb->tstr);
					sep = ", ";
					term = TRUE;
				}
			} else {
				if(item && nb->fstr) {
					proto_item_append_text(item, "%s%s", sep, nb->fstr);
					sep = ", ";
					term = TRUE;
				}
			}
			nb++;
		}
		if(term)
			proto_item_append_text(item, ")");

		for (byteno = 0; byteno < len; byteno++) {
			if (bitstring[byteno]) {
				expert_add_info_format(actx->pinfo, item, PI_UNDECODED, PI_WARN,
						       "Unknown bit(s): 0x%s", bytes_to_str(bitstring, len));
				break;
			}
		}
	}

	if (pad > 0 && pad < 8 && len > 0) {
		guint8 bits_in_pad = tvb_get_guint8(tvb, offset + len - 1) & (0xFF >> (8-pad));
		if (bits_in_pad) {
			expert_add_info_format(actx->pinfo, item, PI_UNDECODED, PI_WARN,
					       "Bits set in padded area: 0x%02x", bits_in_pad);
		}
	}

	ber_check_length(8*len-pad, min_len, max_len, actx, item, TRUE);

	return end_offset;
}

int dissect_ber_bitstring(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const asn_namedbit *named_bits, gint hf_id, gint ett_id, tvbuff_t **out_tvb)
{
  return dissect_ber_constrained_bitstring(implicit_tag, actx, parent_tree, tvb, offset, -1, -1, named_bits, hf_id, ett_id, out_tvb);
}

int dissect_ber_bitstring32(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, int **bit_fields, gint hf_id, gint ett_id, tvbuff_t **out_tvb)
{
	tvbuff_t *tmp_tvb = NULL;
	proto_tree *tree;
	guint32 val;
	int **bf;
	header_field_info *hfi;
	const char *sep;
	gboolean term;
	unsigned int i, tvb_len;

	offset = dissect_ber_bitstring(implicit_tag, actx, parent_tree, tvb, offset, NULL, hf_id, ett_id, &tmp_tvb);

	tree = proto_item_get_subtree(actx->created_item);
	if(bit_fields && tree && tmp_tvb) {
		/* tmp_tvb points to the actual bitstring (including any pad bits at the end.
		 * note that this bitstring is not neccessarily always encoded as 4 bytes
		 * so we have to read it byte by byte.
		 */
		val=0;
		tvb_len=tvb_length(tmp_tvb);
		for(i=0;i<4;i++){
			val<<=8;
			if(i<tvb_len){
				val|=tvb_get_guint8(tmp_tvb,i);
			}
		}
		bf = bit_fields;
		sep = " (";
		term = FALSE;
		while (*bf) {
			proto_tree_add_boolean(tree, **bf, tmp_tvb, 0, tvb_len, val);
			if (**bf >= 0) {
				hfi = proto_registrar_get_nth(**bf);
				if(val & hfi->bitmask) {
					proto_item_append_text(actx->created_item, "%s%s", sep, hfi->name);
					sep = ", ";
					term = TRUE;
				}
			}
			bf++;
		}
		if(term)
			proto_item_append_text(actx->created_item, ")");
	}

	if(out_tvb)
		*out_tvb = tmp_tvb;

	return offset;
}

/*
 *	8.18	Encoding of a value of the external type
 *	8.18.1	The encoding of a value of the external type shall be the BER encoding of the following
 *			sequence type, assumed to be defined in an environment of EXPLICIT TAGS,
 *			with a value as specified in the subclauses below:
 *
 *	[UNIVERSAL 8] IMPLICIT SEQUENCE {
 *		direct-reference			OBJECT IDENTIFIER OPTIONAL,
 *		indirect-reference		INTEGER OPTIONAL,
 *		data-value-descriptor		ObjectDescriptor OPTIONAL,
 *		encoding				CHOICE {
 *		single-ASN1-type				[0] ABSTRACT-SYNTAX.&Type,
 *		octet-aligned					[1] IMPLICIT OCTET STRING,
 *		arbitrary						[2] IMPLICIT BIT STRING } }
 *
 */

static int
dissect_ber_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  &actx->external.indirect_reference);
  actx->external.indirect_ref_present = TRUE;

  return offset;
}

static int
dissect_ber_T_octet_aligned(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_)
{
  if (actx->external.u.ber.ber_callback) {
    offset = actx->external.u.ber.ber_callback(FALSE, tvb, offset, actx, tree, hf_index);
  } else if (actx->external.direct_ref_present &&
	     dissector_get_string_handle(ber_oid_dissector_table, actx->external.direct_reference)) {
    offset = call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree);
  } else {
    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index, &actx->external.octet_aligned);
  }

  return offset;
}
static int
dissect_ber_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_)
{
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &actx->external.direct_reference);
  actx->external.direct_ref_present = TRUE;

  return offset;
}

static int
dissect_ber_ObjectDescriptor(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_)
{
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_ObjectDescriptor,
					 actx, tree, tvb, offset, hf_index,
					 &actx->external.data_value_descriptor);

  return offset;
}

static int
dissect_ber_T_single_ASN1_type(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_)
{
  if (actx->external.u.ber.ber_callback) {
    offset = actx->external.u.ber.ber_callback(FALSE, tvb, offset, actx, tree, hf_index);
  } else {
    offset = call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree);
  }

  return offset;
}

static int
dissect_ber_T_arbitrary(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_)
{
  if (actx->external.u.ber.ber_callback) {
    offset = actx->external.u.ber.ber_callback(FALSE, tvb, offset, actx, tree, hf_index);
  } else {
    offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
				   NULL, hf_index, -1, &actx->external.arbitrary);
  }

  return offset;
}

static const value_string ber_T_encoding_vals[] = {
  {   0, "single-ASN1-type" },
  {   1, "octet-aligned" },
  {   2, "arbitrary" },
  { 0, NULL }
};

static const ber_choice_t T_encoding_choice[] = {
  {   0, &hf_ber_single_ASN1_type, BER_CLASS_CON, 0, 0, dissect_ber_T_single_ASN1_type },
  {   1, &hf_ber_octet_aligned  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ber_T_octet_aligned },
  {   2, &hf_ber_arbitrary      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ber_T_arbitrary },
  { 0, NULL, 0, 0, 0, NULL }
};


static int
dissect_ber_T_encoding(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_encoding_choice, hf_index, ett_ber_T_encoding,
                                 &actx->external.encoding);

  return offset;
}


static const ber_sequence_t external_U_sequence[] = {
  { &hf_ber_direct_reference, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ber_OBJECT_IDENTIFIER },
  { &hf_ber_indirect_reference, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ber_INTEGER },
  { &hf_ber_data_value_descriptor, BER_CLASS_UNI, BER_UNI_TAG_ObjectDescriptor, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ber_ObjectDescriptor },
  { &hf_ber_encoding       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ber_T_encoding },
  { NULL, 0, 0, 0, NULL }
};
static int
dissect_ber_external_U(gboolean implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_ , proto_tree *tree, int hf_index _U_)
{
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   external_U_sequence, hf_index, ett_ber_EXTERNAL);
  return offset;
}

int
dissect_ber_external_type(gboolean implicit_tag, proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, gint hf_id, ber_callback func){

	actx->external.u.ber.ber_callback =  func;

	offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
					 hf_id, BER_CLASS_UNI, BER_UNI_TAG_EXTERNAL, TRUE, dissect_ber_external_U);

	asn1_ctx_clean_external(actx);

	return offset;
}
/* Experimental */
int
dissect_ber_EmbeddedPDV_Type(gboolean implicit_tag, proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, gint hf_id, ber_callback func _U_){


  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_id, BER_CLASS_UNI, BER_UNI_TAG_EMBEDDED_PDV, TRUE, dissect_ber_external_U);

	return offset;
}

static void
dissect_ber_syntax(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  (void) dissect_unknown_ber(pinfo, tvb, 0, tree);
}

static void
dissect_ber(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  const char *name;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "BER");

  col_set_str(pinfo->cinfo, COL_DEF_SRC, "BER encoded file");

  if(!decode_as_syntax) {

    /* if we got here we couldn't find anything better */
    col_set_str(pinfo->cinfo, COL_INFO, "Unknown BER");

    (void) dissect_unknown_ber(pinfo, tvb, 0, tree);

  } else {

    (void) call_ber_syntax_callback(decode_as_syntax, tvb, 0, pinfo, tree);

	/* see if we have a better name */
    name = get_ber_oid_syntax(decode_as_syntax);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Decoded as %s", name ? name : decode_as_syntax);
  }
}

void
proto_register_ber(void)
{
    static hf_register_info hf[] = {
	{ &hf_ber_id_class, {
	    "Class", "ber.id.class", FT_UINT8, BASE_DEC,
	    VALS(ber_class_codes), 0xc0, "Class of BER TLV Identifier", HFILL }},
	{ &hf_ber_bitstring_padding, {
	    "Padding", "ber.bitstring.padding", FT_UINT8, BASE_DEC,
	    NULL, 0x0, "Number of unused bits in the last octet of the bitstring", HFILL }},
	{ &hf_ber_bitstring_empty, {
	    "Empty", "ber.bitstring.empty", FT_UINT8, BASE_DEC,
	    NULL, 0x0, "This is an empty bitstring", HFILL }},
	{ &hf_ber_id_pc, {
	    "P/C", "ber.id.pc", FT_BOOLEAN, 8,
	    TFS(&ber_pc_codes), 0x20, "Primitive or Constructed BER encoding", HFILL }},
	{ &hf_ber_id_uni_tag, {
	    "Tag", "ber.id.uni_tag", FT_UINT8, BASE_DEC|BASE_EXT_STRING,
	    &ber_uni_tag_codes_ext, 0x1f, "Universal tag type", HFILL }},
	{ &hf_ber_id_uni_tag_ext, {
	    "Tag", "ber.id.uni_tag", FT_UINT32, BASE_DEC,
	    NULL, 0, "Universal tag type", HFILL }},
	{ &hf_ber_id_tag, {
	    "Tag", "ber.id.tag", FT_UINT8, BASE_DEC,
	    NULL, 0x1f, "Tag value for non-Universal classes", HFILL }},
	{ &hf_ber_id_tag_ext, {
	    "Tag", "ber.id.tag", FT_UINT32, BASE_DEC,
	    NULL, 0, "Tag value for non-Universal classes", HFILL }},
	{ &hf_ber_length, {
	    "Length", "ber.length", FT_UINT32, BASE_DEC,
	    NULL, 0, "Length of contents", HFILL }},
	{ &hf_ber_unknown_OCTETSTRING, {
	    "OCTETSTRING", "ber.unknown.OCTETSTRING", FT_BYTES, BASE_NONE,
	    NULL, 0, "This is an unknown OCTETSTRING", HFILL }},
	{ &hf_ber_unknown_BER_OCTETSTRING, {
	    "OCTETSTRING [BER encoded]", "ber.unknown.OCTETSTRING", FT_NONE, BASE_NONE,
	    NULL, 0, "This is an BER encoded OCTETSTRING", HFILL }},
	{ &hf_ber_unknown_BER_primitive, {
	    "Primitive [BER encoded]", "ber.unknown.primitive", FT_NONE, BASE_NONE,
	    NULL, 0, "This is a BER encoded Primitive", HFILL }},
	{ &hf_ber_unknown_OID, {
	    "OID", "ber.unknown.OID", FT_OID, BASE_NONE,
	    NULL, 0, "This is an unknown Object Identifier", HFILL }},
	{ &hf_ber_unknown_GraphicString, {
	    "GRAPHICSTRING", "ber.unknown.GRAPHICSTRING", FT_STRING, BASE_NONE,
	    NULL, 0, "This is an unknown GRAPHICSTRING", HFILL }},
	{ &hf_ber_unknown_NumericString, {
	    "NumericString", "ber.unknown.NumericString", FT_STRING, BASE_NONE,
	    NULL, 0, "This is an unknown NumericString", HFILL }},
	{ &hf_ber_unknown_PrintableString, {
	    "PrintableString", "ber.unknown.PrintableString", FT_STRING, BASE_NONE,
	    NULL, 0, "This is an unknown PrintableString", HFILL }},
	{ &hf_ber_unknown_TeletexString, {
	    "TeletexString", "ber.unknown.TeletexString", FT_STRING, BASE_NONE,
	    NULL, 0, "This is an unknown TeletexString", HFILL }},
	{ &hf_ber_unknown_VisibleString, {
	    "VisibleString", "ber.unknown.VisibleString", FT_STRING, BASE_NONE,
	    NULL, 0, "This is an unknown VisibleString", HFILL }},
	{ &hf_ber_unknown_GeneralString, {
	    "GeneralString", "ber.unknown.GeneralString", FT_STRING, BASE_NONE,
	    NULL, 0, "This is an unknown GeneralString", HFILL }},
	{ &hf_ber_unknown_UniversalString, {
	    "UniversalString", "ber.unknown.UniversalString", FT_STRING, BASE_NONE,
	    NULL, 0, "This is an unknown UniversalString", HFILL }},
	{ &hf_ber_unknown_BMPString, {
	    "BMPString", "ber.unknown.BMPString", FT_STRING, BASE_NONE,
	    NULL, 0, "This is an unknown BMPString", HFILL }},
	{ &hf_ber_unknown_IA5String, {
	    "IA5String", "ber.unknown.IA5String", FT_STRING, BASE_NONE,
	    NULL, 0, "This is an unknown IA5String", HFILL }},
	{ &hf_ber_unknown_UTCTime, {
	    "UTCTime", "ber.unknown.UTCTime", FT_STRING, BASE_NONE,
	    NULL, 0, "This is an unknown UTCTime", HFILL }},
	{ &hf_ber_unknown_UTF8String, {
	    "UTF8String", "ber.unknown.UTF8String", FT_STRING, BASE_NONE,
	    NULL, 0, "This is an unknown UTF8String", HFILL }},
	{ &hf_ber_unknown_GeneralizedTime, {
	    "GeneralizedTime", "ber.unknown.GeneralizedTime", FT_STRING, BASE_NONE,
	    NULL, 0, "This is an unknown GeneralizedTime", HFILL }},
	{ &hf_ber_unknown_INTEGER, {
	    "INTEGER", "ber.unknown.INTEGER", FT_INT64, BASE_DEC,
	    NULL, 0, "This is an unknown INTEGER", HFILL }},
	{ &hf_ber_unknown_BITSTRING, {
	    "BITSTRING", "ber.unknown.BITSTRING", FT_BYTES, BASE_NONE,
	    NULL, 0, "This is an unknown BITSTRING", HFILL }},
	{ &hf_ber_unknown_BOOLEAN, {
	    "BOOLEAN", "ber.unknown.BOOLEAN", FT_UINT8, BASE_HEX,
	    NULL, 0, "This is an unknown BOOLEAN", HFILL }},
	{ &hf_ber_unknown_ENUMERATED, {
	    "ENUMERATED", "ber.unknown.ENUMERATED", FT_UINT32, BASE_DEC,
	    NULL, 0, "This is an unknown ENUMERATED", HFILL }},
	{ &hf_ber_error, {
	    "BER Error", "ber.error", FT_STRING, BASE_NONE,
	    NULL, 0, NULL, HFILL }},
	{ &hf_ber_no_oid, {
	    "No OID", "ber.no_oid", FT_NONE, BASE_NONE,
	    NULL, 0, "No OID supplied to call_ber_oid_callback", HFILL }},
	{ &hf_ber_oid_not_implemented, {
	    "OID not implemented", "ber.oid_not_implemented", FT_NONE, BASE_NONE,
	    NULL, 0, "Dissector for OID not implemented", HFILL }},
	{ &hf_ber_no_syntax, {
	    "No OID", "ber.no_oid", FT_NONE, BASE_NONE,
	    NULL, 0, "No syntax supplied to call_ber_syntax_callback", HFILL }},
	{ &hf_ber_syntax_not_implemented, {
	    "Syntax not implemented", "ber.syntax_not_implemented", FT_NONE, BASE_NONE,
	    NULL, 0, "Dissector for OID not implemented", HFILL }},
    { &hf_ber_direct_reference,
      { "direct-reference", "ber.direct_reference",
        FT_OID, BASE_NONE, NULL, 0,
        "ber.OBJECT_IDENTIFIER", HFILL }},
    { &hf_ber_indirect_reference,
      { "indirect-reference", "ber.indirect_reference",
        FT_INT32, BASE_DEC, NULL, 0,
        "ber.INTEGER", HFILL }},
    { &hf_ber_data_value_descriptor,
      { "data-value-descriptor", "ber.data_value_descriptor",
        FT_STRING, BASE_NONE, NULL, 0,
        "ber.ObjectDescriptor", HFILL }},
    { &hf_ber_encoding,
      { "encoding", "ber.encoding",
        FT_UINT32, BASE_DEC, VALS(ber_T_encoding_vals), 0,
        "ber.T_encoding", HFILL }},
    { &hf_ber_octet_aligned,
      { "octet-aligned", "ber.octet_aligned",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ber.T_octet_aligned", HFILL }},
    { &hf_ber_arbitrary,
      { "arbitrary", "ber.arbitrary",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ber.T_arbitrary", HFILL }},
    { &hf_ber_single_ASN1_type,
      { "single-ASN1-type", "ber.single_ASN1_type",
        FT_NONE, BASE_NONE, NULL, 0,
        "ber.T_single_ASN1_type", HFILL }},

    /* Fragment entries */
    { &hf_ber_fragments,
      { "OCTET STRING fragments", "ber.octet_string.fragments", FT_NONE, BASE_NONE,
        NULL, 0x00, NULL, HFILL } },
    { &hf_ber_fragment,
      { "OCTET STRING fragment", "ber.octet_string.fragment", FT_FRAMENUM, BASE_NONE,
        NULL, 0x00, NULL, HFILL } },
    { &hf_ber_fragment_overlap,
      { "OCTET STRING fragment overlap", "ber.octet_string.fragment.overlap", FT_BOOLEAN,
        BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_ber_fragment_overlap_conflicts,
      { "OCTET STRING fragment overlapping with conflicting data",
        "ber.octet_string.fragment.overlap.conflicts", FT_BOOLEAN, BASE_NONE, NULL,
        0x0, NULL, HFILL } },
    { &hf_ber_fragment_multiple_tails,
      { "OCTET STRING has multiple tail fragments",
        "ber.octet_string.fragment.multiple_tails", FT_BOOLEAN, BASE_NONE,
        NULL, 0x0, NULL, HFILL } },
    { &hf_ber_fragment_too_long_fragment,
      { "OCTET STRING fragment too long", "ber.octet_string.fragment.too_long_fragment",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL,
        HFILL } },
    { &hf_ber_fragment_error,
      { "OCTET STRING defragmentation error", "ber.octet_string.fragment.error", FT_FRAMENUM,
        BASE_NONE, NULL, 0x00, NULL, HFILL } },
    { &hf_ber_fragment_count,
      { "OCTET STRING fragment count", "ber.octet_string.fragment.count", FT_UINT32, BASE_DEC,
        NULL, 0x00, NULL, HFILL } },
    { &hf_ber_reassembled_in,
      { "Reassembled in", "ber.octet_string.reassembled.in", FT_FRAMENUM, BASE_NONE,
        NULL, 0x00, NULL, HFILL } },
    { &hf_ber_reassembled_length,
      { "Reassembled OCTET STRING length", "ber.octet_string.reassembled.length", FT_UINT32, BASE_DEC,
        NULL, 0x00, NULL, HFILL } }
    };


    static gint *ett[] = {
	&ett_ber_octet_string,
	&ett_ber_reassembled_octet_string,
	&ett_ber_primitive,
	&ett_ber_unknown,
	&ett_ber_SEQUENCE,
	&ett_ber_EXTERNAL,
	&ett_ber_T_encoding,
	&ett_ber_fragment,
	&ett_ber_fragments
    };
    module_t *ber_module;
    uat_t* users_uat = uat_new("OID Tables",
			       sizeof(oid_user_t),
			       "oid",
			       FALSE,
			       (void*) &oid_users,
			       &num_oid_users,
			       UAT_CAT_GENERAL,
			       "ChObjectIdentifiers",
			       oid_copy_cb,
			       NULL,
			       oid_free_cb,
			       ber_update_oids,
			       users_flds);

    proto_ber = proto_register_protocol("Basic Encoding Rules (ASN.1 X.690)", "BER", "ber");
    register_dissector ("ber", dissect_ber, proto_ber);
    proto_register_field_array(proto_ber, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    proto_set_cant_toggle(proto_ber);

    /* Register preferences */
    ber_module = prefs_register_protocol(proto_ber, NULL);

    prefs_register_bool_preference(ber_module, "show_internals",
	"Show internal BER encapsulation tokens",
	"Whether the dissector should also display internal"
	" ASN.1 BER details such as Identifier and Length fields", &show_internal_ber_fields);
    prefs_register_bool_preference(ber_module, "decode_unexpected",
	"Decode unexpected tags as BER encoded data",
	"Whether the dissector should decode unexpected tags as"
	" ASN.1 BER encoded data", &decode_unexpected);
    prefs_register_bool_preference(ber_module, "decode_octetstring",
	"Decode OCTET STRING as BER encoded data",
	"Whether the dissector should try decoding OCTET STRINGs as"
	" constructed ASN.1 BER encoded data", &decode_octetstring_as_ber);

    prefs_register_bool_preference(ber_module, "decode_primitive",
	"Decode Primitive as BER encoded data",
	"Whether the dissector should try decoding unknown primitive as"
	" constructed ASN.1 BER encoded data", &decode_primitive_as_ber);

    prefs_register_uat_preference(ber_module, "oid_table", "Object Identifiers",
				  "A table that provides names for object identifiers"
				  " and the syntax of any associated values",
				  users_uat);

    ber_oid_dissector_table = register_dissector_table("ber.oid", "BER OID Dissectors", FT_STRING, BASE_NONE);
    ber_syntax_dissector_table = register_dissector_table("ber.syntax", "BER Syntax Dissectors", FT_STRING, BASE_NONE);
    syntax_table=g_hash_table_new(g_str_hash, g_str_equal); /* oid to syntax */

    register_ber_syntax_dissector("ASN.1", proto_ber, dissect_ber_syntax);

    register_init_routine(ber_defragment_init);
}

void
proto_reg_handoff_ber(void)
{
  guint i = 1;
        dissector_handle_t ber_handle;

	oid_add_from_string("asn1","2.1");
	oid_add_from_string("basic-encoding","2.1.1");

	ber_handle = create_dissector_handle(dissect_ber, proto_ber);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_BER, ber_handle);

	ber_decode_as_foreach(ber_add_syntax_name, &i);

	if(i > 1)
	  qsort(&syntax_names[1], i - 1, sizeof(value_string), cmp_value_string);
	syntax_names[i].value = 0;
	syntax_names[i].strptr = NULL;

	/* allow the dissection of BER/DER carried over a TCP transport 
	   by using "Decode As..." */
	dissector_add_handle("tcp.port", ber_handle);

	ber_update_oids();
}

gboolean oid_has_dissector(const char *oid) {
  return(dissector_get_string_handle(ber_oid_dissector_table, oid) != NULL);
}
