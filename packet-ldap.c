/* packet-ldap.c
 * Routines for ldap packet dissection
 *
 * See RFC 1777 (LDAP v2), RFC 2251 (LDAP v3), and RFC 2222 (SASL).
 *
 * $Id: packet-ldap.c,v 1.54 2003/04/25 21:19:10 guy Exp $
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
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#include <string.h>
#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>

#include "packet-ldap.h"
#include "asn1.h"
#include "prefs.h"
#include <epan/conversation.h>
#include "packet-frame.h"

static int proto_ldap = -1;
static int hf_ldap_sasl_buffer_length = -1;
static int hf_ldap_length = -1;
static int hf_ldap_message_id = -1;
static int hf_ldap_message_type = -1;
static int hf_ldap_message_length = -1;

static int hf_ldap_message_result = -1;
static int hf_ldap_message_result_matcheddn = -1;
static int hf_ldap_message_result_errormsg = -1;
static int hf_ldap_message_result_referral = -1;

static int hf_ldap_message_bind_version = -1;
static int hf_ldap_message_bind_dn = -1;
static int hf_ldap_message_bind_auth = -1;
static int hf_ldap_message_bind_auth_password = -1;
static int hf_ldap_message_bind_auth_mechanism = -1;
static int hf_ldap_message_bind_auth_credentials = -1;
static int hf_ldap_message_bind_server_credentials = -1;

static int hf_ldap_message_search_base = -1;
static int hf_ldap_message_search_scope = -1;
static int hf_ldap_message_search_deref = -1;
static int hf_ldap_message_search_sizeLimit = -1;
static int hf_ldap_message_search_timeLimit = -1;
static int hf_ldap_message_search_typesOnly = -1;
static int hf_ldap_message_search_filter = -1;

static int hf_ldap_message_dn = -1;
static int hf_ldap_message_attribute = -1;
static int hf_ldap_message_value = -1;

static int hf_ldap_message_modrdn_name = -1;
static int hf_ldap_message_modrdn_delete = -1;
static int hf_ldap_message_modrdn_superior = -1;

static int hf_ldap_message_compare = -1;

static int hf_ldap_message_modify_add = -1;
static int hf_ldap_message_modify_replace = -1;
static int hf_ldap_message_modify_delete = -1;

static int hf_ldap_message_abandon_msgid = -1;

static gint ett_ldap = -1;
static gint ett_ldap_message = -1;
static gint ett_ldap_gssapi_token = -1;
static gint ett_ldap_referrals = -1;
static gint ett_ldap_attribute = -1;

/* desegmentation of LDAP */
static gboolean ldap_desegment = TRUE;

#define TCP_PORT_LDAP			389
#define UDP_PORT_CLDAP			389

static dissector_handle_t gssapi_handle;
static dissector_handle_t gssapi_wrap_handle;

/*
 * Data structure attached to a conversation, giving authentication
 * information from a bind request.
 * We keep a linked list of them, so that we can free up all the
 * authentication mechanism strings.
 */
typedef struct ldap_auth_info_t {
  guint auth_type;		/* authentication type */
  char *auth_mech;		/* authentication mechanism */
  guint32 first_auth_frame;	/* first frame that would use a security layer */
  struct ldap_auth_info_t *next;
} ldap_auth_info_t;

static GMemChunk *ldap_auth_info_chunk = NULL;

static guint ldap_auth_info_chunk_count = 200;

static ldap_auth_info_t *auth_info_items;

static value_string msgTypes [] = {
  {LDAP_REQ_BIND, "Bind Request"},
  {LDAP_REQ_UNBIND, "Unbind Request"},
  {LDAP_REQ_SEARCH, "Search Request"},
  {LDAP_REQ_MODIFY, "Modify Request"},
  {LDAP_REQ_ADD, "Add Request"},
  {LDAP_REQ_DELETE, "Delete Request"},
  {LDAP_REQ_MODRDN, "Modify RDN Request"},
  {LDAP_REQ_COMPARE, "Compare Request"},
  {LDAP_REQ_ABANDON, "Abandon Request"},
  {LDAP_REQ_EXTENDED, "Extended Request"},

  {LDAP_RES_BIND, "Bind Result"},
  {LDAP_RES_SEARCH_ENTRY, "Search Entry"},
  {LDAP_RES_SEARCH_RESULT, "Search Result"},
  {LDAP_RES_SEARCH_REF, "Search Result Reference"},
  {LDAP_RES_MODIFY, "Modify Result"},
  {LDAP_RES_ADD, "Add Result"},
  {LDAP_RES_DELETE, "Delete Result"},
  {LDAP_RES_MODRDN, "Modify RDN Result"},
  {LDAP_RES_COMPARE, "Compare Result"},
  {LDAP_REQ_EXTENDED, "Extended Response"},
  {0, NULL},
};

static int read_length(ASN1_SCK *a, proto_tree *tree, int hf_id, guint *len)
{
  guint length = 0;
  gboolean def = FALSE;
  int start = a->offset;
  int ret;

  ret = asn1_length_decode(a, &def, &length);
  if (ret != ASN1_ERR_NOERROR) {
    if (tree) {
      proto_tree_add_text(tree, a->tvb, start, 0,
        "%s: ERROR: Couldn't parse length: %s",
        proto_registrar_get_name(hf_id), asn1_err_to_str(ret));
    }
    return ret;
  }

  if (len)
    *len = length;

  if (tree)
    proto_tree_add_uint(tree, hf_id, a->tvb, start, a->offset-start, length);

  return ASN1_ERR_NOERROR;
}

static int read_sequence(ASN1_SCK *a, guint *len)
{
  guint cls, con, tag;
  gboolean def;
  guint length;
  int ret;

  ret = asn1_header_decode(a, &cls, &con, &tag, &def, &length);
  if (ret != ASN1_ERR_NOERROR)
    return ret;
  if (cls != ASN1_UNI || con != ASN1_CON || tag != ASN1_SEQ)
    return ASN1_ERR_WRONG_TYPE;

  if (len)
    *len = length;

  return ASN1_ERR_NOERROR;
}

static int read_set(ASN1_SCK *a, guint *len)
{
  guint cls, con, tag;
  gboolean def;
  guint length;
  int ret;

  ret = asn1_header_decode(a, &cls, &con, &tag, &def, &length);
  if (ret != ASN1_ERR_NOERROR)
    return ret;
  if (cls != ASN1_UNI || con != ASN1_CON || tag != ASN1_SET)
    return ASN1_ERR_WRONG_TYPE;

  if (len)
    *len = length;

  return ASN1_ERR_NOERROR;
}

static int read_integer_value(ASN1_SCK *a, proto_tree *tree, int hf_id,
	proto_item **new_item, guint *i, int start, guint length)
{
  guint integer = 0;
  proto_item *temp_item = NULL;
  int ret;

  ret = asn1_uint32_value_decode(a, length, &integer);
  if (ret != ASN1_ERR_NOERROR) {
    if (tree) {
      proto_tree_add_text(tree, a->tvb, start, 0,
       "%s: ERROR: Couldn't parse value: %s",
        proto_registrar_get_name(hf_id), asn1_err_to_str(ret));
    }
    return ret;
  }

  if (i)
    *i = integer;

  if (tree)
    temp_item = proto_tree_add_uint(tree, hf_id, a->tvb, start, a->offset-start, integer);

  if (new_item)
    *new_item = temp_item;

  return ASN1_ERR_NOERROR;
}

static int read_integer(ASN1_SCK *a, proto_tree *tree, int hf_id,
	proto_item **new_item, guint *i, guint expected_tag)
{
  guint cls, con, tag;
  gboolean def;
  guint length;
  int start = a->offset;
  int ret;

  ret = asn1_header_decode(a, &cls, &con, &tag, &def, &length);
  if (ret == ASN1_ERR_NOERROR) {
    if (cls != ASN1_UNI || con != ASN1_PRI || tag != expected_tag)
      ret = ASN1_ERR_WRONG_TYPE;
  }
  if (ret != ASN1_ERR_NOERROR) {
    if (tree) {
      proto_tree_add_text(tree, a->tvb, start, 0,
        "%s: ERROR: Couldn't parse header: %s",
        (hf_id != -1) ? proto_registrar_get_name(hf_id) : "LDAP message",
        asn1_err_to_str(ret));
    }
    return ret;
  }

  return read_integer_value(a, tree, hf_id, new_item, i, start, length);
}

static int read_boolean_value(ASN1_SCK *a, proto_tree *tree, int hf_id,
	proto_item **new_item, guint *i, int start, guint length)
{
  guint integer = 0;
  proto_item *temp_item = NULL;
  int ret;

  ret = asn1_uint32_value_decode(a, length, &integer);
  if (ret != ASN1_ERR_NOERROR) {
    if (tree) {
      proto_tree_add_text(tree, a->tvb, start, 0,
        "%s: ERROR: Couldn't parse value: %s",
        proto_registrar_get_name(hf_id), asn1_err_to_str(ret));
    }
    return ret;
  }

  if (i)
    *i = integer;

  if (tree)
    temp_item = proto_tree_add_boolean(tree, hf_id, a->tvb, start, a->offset-start, integer);
  if (new_item)
    *new_item = temp_item;

  return ASN1_ERR_NOERROR;
}

static int read_boolean(ASN1_SCK *a, proto_tree *tree, int hf_id,
	proto_item **new_item, guint *i)
{
  guint cls, con, tag;
  gboolean def;
  guint length;
  int start = a->offset;
  int ret;

  ret = asn1_header_decode(a, &cls, &con, &tag, &def, &length);
  if (ret == ASN1_ERR_NOERROR) {
    if (cls != ASN1_UNI || con != ASN1_PRI || tag != ASN1_BOL)
      ret = ASN1_ERR_WRONG_TYPE;
  }
  if (ret != ASN1_ERR_NOERROR) {
    if (tree) {
      proto_tree_add_text(tree, a->tvb, start, 0,
        "%s: ERROR: Couldn't parse header: %s",
        proto_registrar_get_name(hf_id), asn1_err_to_str(ret));
    }
    return ret;
  }

  return read_boolean_value(a, tree, hf_id, new_item, i, start, length);
}

static int read_string_value(ASN1_SCK *a, proto_tree *tree, int hf_id,
	proto_item **new_item, char **s, int start, guint length)
{
  guchar *string;
  proto_item *temp_item = NULL;
  int ret;

  if (length)
  {
    ret = asn1_string_value_decode(a, length, &string);
    if (ret != ASN1_ERR_NOERROR) {
      if (tree) {
        proto_tree_add_text(tree, a->tvb, start, 0,
          "%s: ERROR: Couldn't parse value: %s",
          proto_registrar_get_name(hf_id), asn1_err_to_str(ret));
      }
      return ret;
    }
    string = g_realloc(string, length + 1);
    string[length] = '\0';
  }
  else
    string = "(null)";

  if (tree)
    temp_item = proto_tree_add_string(tree, hf_id, a->tvb, start, a->offset - start, string);
  if (new_item)
    *new_item = temp_item;

  if (s && length)
    *s = string;
  else if (length)
    g_free(string);

  return ASN1_ERR_NOERROR;
}

static int read_string(ASN1_SCK *a, proto_tree *tree, int hf_id,
	proto_item **new_item, char **s, guint expected_cls, guint expected_tag)
{
  guint cls, con, tag;
  gboolean def;
  guint length;
  int start = a->offset;
  int ret;

  ret = asn1_header_decode(a, &cls, &con, &tag, &def, &length);
  if (ret == ASN1_ERR_NOERROR) {
    if (cls != expected_cls || con != ASN1_PRI || tag != expected_tag)
      ret = ASN1_ERR_WRONG_TYPE;
  }
  if (ret != ASN1_ERR_NOERROR) {
    if (tree) {
      proto_tree_add_text(tree, a->tvb, start, 0,
        "%s: ERROR: Couldn't parse header: %s",
        proto_registrar_get_name(hf_id), asn1_err_to_str(ret));
    }
    return ret;
  }

  return read_string_value(a, tree, hf_id, new_item, s, start, length);
}

static int read_bytestring_value(ASN1_SCK *a, proto_tree *tree, int hf_id,
	proto_item **new_item, char **s, int start, guint length)
{
  guchar *string;
  proto_item *temp_item = NULL;
  int ret;

  if (length)
  {
    ret = asn1_string_value_decode(a, length, &string);
    if (ret != ASN1_ERR_NOERROR) {
      if (tree) {
        proto_tree_add_text(tree, a->tvb, start, 0,
          "%s: ERROR: Couldn't parse value: %s",
          proto_registrar_get_name(hf_id), asn1_err_to_str(ret));
      }
      return ret;
    }
    string = g_realloc(string, length + 1);
    string[length] = '\0';
  }
  else
    string = "(null)";

  if (tree)
    temp_item = proto_tree_add_bytes(tree, hf_id, a->tvb, start, a->offset - start, string);
  if (new_item)
    *new_item = temp_item;

  if (s && length)
    *s = string;
  else if (length)
    g_free(string);

  return ASN1_ERR_NOERROR;
}

static int read_bytestring(ASN1_SCK *a, proto_tree *tree, int hf_id,
	proto_item **new_item, char **s, guint expected_cls, guint expected_tag)
{
  guint cls, con, tag;
  gboolean def;
  guint length;
  int start = a->offset;
  int ret;

  ret = asn1_header_decode(a, &cls, &con, &tag, &def, &length);
  if (ret == ASN1_ERR_NOERROR) {
    if (cls != expected_cls || con != ASN1_PRI || tag != expected_tag)
      ret = ASN1_ERR_WRONG_TYPE;
  }
  if (ret != ASN1_ERR_NOERROR) {
    if (tree) {
      proto_tree_add_text(tree, a->tvb, start, 0,
        "%s: ERROR: Couldn't parse header: %s",
        proto_registrar_get_name(hf_id), asn1_err_to_str(ret));
    }
    return ret;
  }

  return read_bytestring_value(a, tree, hf_id, new_item, s, start, length);
}

static int parse_filter_strings(ASN1_SCK *a, char **filter, guint *filter_length, const guchar *operation)
{
  guchar *string;
  guchar *string2;
  guint string_length;
  guint string2_length;
  guint string_bytes;
  char *filterp;
  int ret;

  ret = asn1_octet_string_decode(a, &string, &string_length, &string_bytes);
  if (ret != ASN1_ERR_NOERROR)
    return ret;
  ret = asn1_octet_string_decode(a, &string2, &string2_length, &string_bytes);
  if (ret != ASN1_ERR_NOERROR)
    return ret;
  *filter_length += 2 + strlen(operation) + string_length + string2_length;
  *filter = g_realloc(*filter, *filter_length);
  filterp = *filter + strlen(*filter);
  *filterp++ = '(';
  if (string_length != 0) {
  	memcpy(filterp, string, string_length);
  	filterp += string_length;
  }
  strcpy(filterp, operation);
  filterp += strlen(operation);
  if (string2_length != 0) {
  	memcpy(filterp, string2, string2_length);
  	filterp += string2_length;
  }
  *filterp++ = ')';
  *filterp = '\0';
  g_free(string);
  g_free(string2);
  return ASN1_ERR_NOERROR;
}

/* Richard Dawe: To parse substring filters, I added this function. */
static int parse_filter_substrings(ASN1_SCK *a, char **filter, guint *filter_length)
{
  int end;
  guchar *string;
  char *filterp;
  guint string_length;
  guint string_bytes;
  guint seq_len;
  guint header_bytes;
  int ret, any_valued;

  /* For ASN.1 parsing of octet strings */
  guint        cls;
  guint        con;
  guint        tag;
  gboolean     def;

  ret = asn1_octet_string_decode(a, &string, &string_length, &string_bytes);
  if (ret != ASN1_ERR_NOERROR)
    return ret;

  ret = asn1_sequence_decode(a, &seq_len, &header_bytes);
  if (ret != ASN1_ERR_NOERROR)
    return ret;

  *filter_length += 2 + 1 + string_length;
  *filter = g_realloc(*filter, *filter_length);

  filterp = *filter + strlen(*filter);
  *filterp++ = '(';
  if (string_length != 0) {
    memcpy(filterp, string, string_length);
    filterp += string_length;
  }
  *filterp++ = '=';
  *filterp = '\0';
  g_free(string);

  /* Now decode seq_len's worth of octet strings. */
  any_valued = 0;
  end = a->offset + seq_len;

  while (a->offset < end) {
    /* Octet strings here are context-specific, which
     * asn1_octet_string_decode() barfs on. Emulate it, but don't barf. */
    ret = asn1_header_decode (a, &cls, &con, &tag, &def, &string_length);
    if (ret != ASN1_ERR_NOERROR)
      return ret;

    /* XXX - check the tag? */
    if (cls != ASN1_CTX || con != ASN1_PRI) {
    	/* XXX - handle the constructed encoding? */
	return ASN1_ERR_WRONG_TYPE;
    }
    if (!def)
    	return ASN1_ERR_LENGTH_NOT_DEFINITE;

    ret = asn1_string_value_decode(a, (int) string_length, &string);
    if (ret != ASN1_ERR_NOERROR)
      return ret;

    /* If we have an 'any' component with a string value, we need to append
     * an extra asterisk before final component. */
    if ((tag == 1) && (string_length != 0))
      any_valued = 1;

    if ( (tag == 1) || ((tag == 2) && any_valued) )
      (*filter_length)++;
    *filter_length += string_length;
    *filter = g_realloc(*filter, *filter_length);

    filterp = *filter + strlen(*filter);
    if ( (tag == 1) || ((tag == 2) && any_valued) )
      *filterp++ = '*';
    if (tag == 2)
      any_valued = 0;
    if (string_length != 0) {
      memcpy(filterp, string, string_length);
      filterp += string_length;
    }
    *filterp = '\0';
    g_free(string);
  }

  if (any_valued)
  {
    (*filter_length)++;
    *filter = g_realloc(*filter, *filter_length);
    filterp = *filter + strlen(*filter);
    *filterp++ = '*';
  }

  /* NB: Allocated byte for this earlier */
  *filterp++ = ')';
  *filterp = '\0';

  return ASN1_ERR_NOERROR;
}

/* Returns -1 if we're at the end, returns an ASN1_ERR value otherwise. */
static int parse_filter(ASN1_SCK *a, char **filter, guint *filter_length,
			int *end)
{
  guint cls, con, tag;
  guint length;
  gboolean def;
  int ret;

  ret = asn1_header_decode(a, &cls, &con, &tag, &def, &length);
  if (ret != ASN1_ERR_NOERROR)
    return ret;

  if (*end == 0)
  {
    *end = a->offset + length;
    *filter_length = 1;
    *filter = g_malloc0(*filter_length);
  }

  if (cls == ASN1_CTX)	/* XXX - handle other types as errors? */
  {
    switch (tag)
    {
     case LDAP_FILTER_AND:
      {
        int add_end;

        if (con != ASN1_CON)
          return ASN1_ERR_WRONG_TYPE;
        add_end = a->offset + length;
        *filter_length += 3;
        *filter = g_realloc(*filter, *filter_length);
        strcat(*filter, "(&");
        while ((ret = parse_filter(a, filter, filter_length, &add_end))
 		== ASN1_ERR_NOERROR)
	  continue;
	if (ret != -1)
	  return ret;
        strcat(*filter, ")");
      }
      break;
     case LDAP_FILTER_OR:
      {
        int or_end;

        if (con != ASN1_CON)
          return ASN1_ERR_WRONG_TYPE;
        or_end = a->offset + length;
        *filter_length += 3;
        *filter = g_realloc(*filter, *filter_length);
        strcat(*filter, "(|");
        while ((ret = parse_filter(a, filter, filter_length, &or_end))
 		== ASN1_ERR_NOERROR)
	  continue;
	if (ret != -1)
	  return ret;
        strcat(*filter, ")");
      }
      break;
     case LDAP_FILTER_NOT:
      {
        int not_end;

        if (con != ASN1_CON)
          return ASN1_ERR_WRONG_TYPE;
        not_end = a->offset + length;
        *filter_length += 3;
        *filter = g_realloc(*filter, *filter_length);
        strcat(*filter, "(!");
        ret = parse_filter(a, filter, filter_length, &not_end);
        if (ret != -1 && ret != ASN1_ERR_NOERROR)
          return ret;
        strcat(*filter, ")");
      }
      break;
     case LDAP_FILTER_EQUALITY:
      if (con != ASN1_CON)
        return ASN1_ERR_WRONG_TYPE;
      ret = parse_filter_strings(a, filter, filter_length, "=");
      if (ret != ASN1_ERR_NOERROR)
        return ret;
      break;
     case LDAP_FILTER_GE:
      if (con != ASN1_CON)
        return ASN1_ERR_WRONG_TYPE;
      ret = parse_filter_strings(a, filter, filter_length, ">=");
      if (ret != ASN1_ERR_NOERROR)
        return ret;
      break;
     case LDAP_FILTER_LE:
      if (con != ASN1_CON)
        return ASN1_ERR_WRONG_TYPE;
      ret = parse_filter_strings(a, filter, filter_length, "<=");
      if (ret != -1 && ret != ASN1_ERR_NOERROR)
        return ret;
      break;
     case LDAP_FILTER_APPROX:
      if (con != ASN1_CON)
        return ASN1_ERR_WRONG_TYPE;
      ret = parse_filter_strings(a, filter, filter_length, "~=");
      if (ret != ASN1_ERR_NOERROR)
        return ret;
      break;
     case LDAP_FILTER_PRESENT:
      {
        guchar *string;
        char *filterp;

        if (con != ASN1_PRI)
          return ASN1_ERR_WRONG_TYPE;
        ret = asn1_string_value_decode(a, length, &string);
        if (ret != ASN1_ERR_NOERROR)
          return ret;
        *filter_length += 4 + length;
        *filter = g_realloc(*filter, *filter_length);
        filterp = *filter + strlen(*filter);
        *filterp++ = '(';
        if (length != 0) {
          memcpy(filterp, string, length);
          filterp += length;
        }
        *filterp++ = '=';
        *filterp++ = '*';
        *filterp++ = ')';
        *filterp = '\0';
        g_free(string);
      }
      break;
     case LDAP_FILTER_SUBSTRINGS:
      if (con != ASN1_CON)
        return ASN1_ERR_WRONG_TYPE;
      /* Richard Dawe: Handle substrings */
      ret = parse_filter_substrings(a, filter, filter_length);
      if (ret != ASN1_ERR_NOERROR)
        return ret;
      break;
     default:
      return ASN1_ERR_WRONG_TYPE;
    }
  }

  if (a->offset == *end)
    return -1;
  else
    return ASN1_ERR_NOERROR;
}

static gboolean read_filter(ASN1_SCK *a, proto_tree *tree, int hf_id)
{
  int start = a->offset;
  char *filter = 0;
  guint filter_length = 0;
  int end = 0;
  int ret;

  while ((ret = parse_filter(a, &filter, &filter_length, &end))
	== ASN1_ERR_NOERROR)
    continue;

  if (tree) {
    if (ret != -1) {
      proto_tree_add_text(tree, a->tvb, start, 0,
        "%s: ERROR: Can't parse filter: %s",
        proto_registrar_get_name(hf_id), asn1_err_to_str(ret));
    } else
      proto_tree_add_string(tree, hf_id, a->tvb, start, a->offset-start, filter);
  }

  g_free(filter);

  return (ret == -1) ? TRUE : FALSE;
}

/********************************************************************************************/

static void dissect_ldap_result(ASN1_SCK *a, proto_tree *tree)
{
  guint resultCode = 0;
  int ret;

  if (read_integer(a, tree, hf_ldap_message_result, 0, &resultCode, ASN1_ENUM) != ASN1_ERR_NOERROR)
    return;
  if (read_string(a, tree, hf_ldap_message_result_matcheddn, 0, 0, ASN1_UNI, ASN1_OTS) != ASN1_ERR_NOERROR)
    return;
  if (read_string(a, tree, hf_ldap_message_result_errormsg, 0, 0, ASN1_UNI, ASN1_OTS) != ASN1_ERR_NOERROR)
    return;

  if (resultCode == 10)		/* Referral */
  {
    int start = a->offset;
    int end;
    guint length;
    proto_item *ti;
    proto_tree *referralTree;

    ret = read_sequence(a, &length);
    if (ret != ASN1_ERR_NOERROR) {
      if (tree) {
        proto_tree_add_text(tree, a->tvb, start, 0,
            "ERROR: Couldn't parse referral URL sequence header: %s",
            asn1_err_to_str(ret));
      }
      return;
    }
    ti = proto_tree_add_text(tree, a->tvb, start, length, "Referral URLs");
    referralTree = proto_item_add_subtree(ti, ett_ldap_referrals);

    end = a->offset + length;
    while (a->offset < end) {
      if (read_string(a, referralTree, hf_ldap_message_result_referral, 0, 0, ASN1_UNI, ASN1_OTS) != ASN1_ERR_NOERROR)
        return;
    }
  }
}

static void dissect_ldap_request_bind(ASN1_SCK *a, proto_tree *tree,
    tvbuff_t *tvb, packet_info *pinfo)
{
  guint cls, con, tag;
  gboolean def;
  guint length;
  int start;
  int end;
  int ret;
  conversation_t *conversation;
  ldap_auth_info_t *auth_info;
  char *mechanism;
  int token_offset;
  gint available_length, reported_length;
  tvbuff_t *new_tvb;
  proto_item *gitem;
  proto_tree *gtree = NULL;

  if (read_integer(a, tree, hf_ldap_message_bind_version, 0, 0, ASN1_INT) != ASN1_ERR_NOERROR)
    return;
  if (read_string(a, tree, hf_ldap_message_bind_dn, 0, 0, ASN1_UNI, ASN1_OTS) != ASN1_ERR_NOERROR)
    return;

  start = a->offset;
  ret = asn1_header_decode(a, &cls, &con, &tag, &def, &length);
  if (ret == ASN1_ERR_NOERROR) {
    if (cls != ASN1_CTX) {
      /* RFCs 1777 and 2251 say these are context-specific types */
      ret = ASN1_ERR_WRONG_TYPE;
    }
  }
  if (ret != ASN1_ERR_NOERROR) {
    proto_tree_add_text(tree, a->tvb, start, 0,
      "%s: ERROR: Couldn't parse header: %s",
      proto_registrar_get_name(hf_ldap_message_bind_auth),
      asn1_err_to_str(ret));
    return;
  }
  proto_tree_add_uint(tree, hf_ldap_message_bind_auth, a->tvb, start,
			a->offset - start, tag);
  end = a->offset + length;
  switch (tag)
  {
   case LDAP_AUTH_SIMPLE:
    if (read_string_value(a, tree, hf_ldap_message_bind_auth_password, NULL,
                          NULL, start, length) != ASN1_ERR_NOERROR)
      return;
    break;

    /* For Kerberos V4, dissect it as a ticket. */

   case LDAP_AUTH_SASL:
    mechanism = NULL;
    if (read_string(a, tree, hf_ldap_message_bind_auth_mechanism, NULL,
                    &mechanism, ASN1_UNI, ASN1_OTS) != ASN1_ERR_NOERROR)
      return;

    /*
     * We need to remember the authentication type and mechanism for this
     * conversation.
     *
     * XXX - actually, we might need to remember more than one
     * type and mechanism, if you can unbind and rebind with a
     * different type and/or mechanism.
     */
    conversation = find_conversation(&pinfo->src, &pinfo->dst,
                                     pinfo->ptype, pinfo->srcport,
                                     pinfo->destport, 0);
    if (conversation == NULL) {
      /* We don't yet have a conversation, so create one. */
      conversation = conversation_new(&pinfo->src, &pinfo->dst,
                                      pinfo->ptype, pinfo->srcport,
                                      pinfo->destport, 0);
    }

    /*
     * Do we already have a type and mechanism?
     */
    auth_info = conversation_get_proto_data(conversation, proto_ldap);
    if (auth_info == NULL) {
      /* No.  Attach that information to the conversation, and add
         it to the list of information structures. */
      auth_info = g_mem_chunk_alloc(ldap_auth_info_chunk);
      auth_info->auth_type = tag;
      auth_info->auth_mech = mechanism;
      auth_info->first_auth_frame = 0;	/* not known until we see the bind reply */
      conversation_add_proto_data(conversation, proto_ldap, auth_info);
      auth_info->next = auth_info_items;
      auth_info_items = auth_info;
    } else {
      /*
       * Yes.
       *
       * If the mechanism in this request is an empty string (which is
       * returned as a null pointer), use the saved mechanism instead.
       * Otherwise, if the saved mechanism is an empty string (null),
       * save this mechanism.
       */
      if (mechanism == NULL)
      	mechanism = auth_info->auth_mech;
      else {
        if (auth_info->auth_mech == NULL)
          auth_info->auth_mech = mechanism;
      }
    }

    if (a->offset < end) {
      if (mechanism != NULL && strcmp(mechanism, "GSS-SPNEGO") == 0) {
        /*
         * This is a GSS-API token.
         * Find out how big it is by parsing the ASN.1 header for the
         * OCTET STREAM that contains it.
         */
        token_offset = a->offset;
        ret = asn1_header_decode(a, &cls, &con, &tag, &def, &length);
        if (ret != ASN1_ERR_NOERROR) {
          proto_tree_add_text(tree, a->tvb, token_offset, 0,
            "%s: ERROR: Couldn't parse header: %s",
            proto_registrar_get_name(hf_ldap_message_bind_auth_credentials),
            asn1_err_to_str(ret));
          return;
        }
        if (tree) {
          gitem = proto_tree_add_text(tree, tvb, token_offset,
            (a->offset + length) - token_offset, "GSS-API Token");
          gtree = proto_item_add_subtree(gitem, ett_ldap_gssapi_token);
        }
        available_length = tvb_length_remaining(tvb, token_offset);
        reported_length = tvb_reported_length_remaining(tvb, token_offset);
        g_assert(available_length >= 0);
        g_assert(reported_length >= 0);
        if (available_length > reported_length)
          available_length = reported_length;
        if ((guint)available_length > length)
          available_length = length;
        if ((guint)reported_length > length)
          reported_length = length;
        new_tvb = tvb_new_subset(tvb, a->offset, available_length, reported_length);
        call_dissector(gssapi_handle, new_tvb, pinfo, gtree);
        a->offset += length;
      } else {
        if (read_bytestring(a, tree, hf_ldap_message_bind_auth_credentials,
                            NULL, NULL, ASN1_UNI, ASN1_OTS) != ASN1_ERR_NOERROR)
          return;
      }
    }
    break;
  }
}

static void dissect_ldap_response_bind(ASN1_SCK *a, proto_tree *tree,
		int start, guint length, tvbuff_t *tvb, packet_info *pinfo)
{
  guint cls, con, tag;
  gboolean def;
  guint cred_length;
  int end;
  int ret;
  conversation_t *conversation;
  ldap_auth_info_t *auth_info;
  int token_offset;
  gint available_length, reported_length;
  tvbuff_t *new_tvb;
  proto_item *gitem;
  proto_tree *gtree = NULL;

  end = start + length;
  dissect_ldap_result(a, tree);
  if (a->offset < end) {
    conversation = find_conversation(&pinfo->src, &pinfo->dst,
                                     pinfo->ptype, pinfo->srcport,
                                     pinfo->destport, 0);
    if (conversation != NULL) {
      auth_info = conversation_get_proto_data(conversation, proto_ldap);
      if (auth_info != NULL) {
        switch (auth_info->auth_type) {

          /* For Kerberos V4, dissect it as a ticket. */
          /* XXX - what about LDAP_AUTH_SIMPLE? */

        case LDAP_AUTH_SASL:
          /*
           * All frames after this are assumed to use a security layer.
           *
           * XXX - won't work if there's another reply, with the security
           * layer, starting in the same TCP segment that ends this
           * reply, but as LDAP is a request/response protocol, and
           * as the client probably can't start using authentication until
           * it gets the bind reply and the server won't send a reply until
           * it gets a request, that probably won't happen.
           *
           * XXX - that assumption is invalid; it's not clear where the
           * hell you find out whether there's any security layer.  In
           * one capture, we have two GSS-SPNEGO negotiations, both of
           * which select MS KRB5, and the only differences in the tokens
           * is in the RC4-HMAC ciphertext.  The various
           * draft-ietf--cat-sasl-gssapi-NN.txt drafts seem to imply
           * that the RFC 2222 spoo with the bitmask and maximum
           * output message size stuff is done - but where does that
           * stuff show up?  Is it in the ciphertext, which means it's
           * presumably encrypted?
           *
           * Grrr.  We have to do a gross heuristic, checking whether the
	   * putative LDAP message begins with 0x00 or not, making the
	   * assumption that we won't have more than 2^24 bytes of
	   * encapsulated stuff.
           */
          auth_info->first_auth_frame = pinfo->fd->num + 1;
          if (auth_info->auth_mech != NULL &&
              strcmp(auth_info->auth_mech, "GSS-SPNEGO") == 0) {
            /*
             * This is a GSS-API token.
             * Find out how big it is by parsing the ASN.1 header for the
             * OCTET STREAM that contains it.
             */
            token_offset = a->offset;
            ret = asn1_header_decode(a, &cls, &con, &tag, &def, &cred_length);
            if (ret != ASN1_ERR_NOERROR) {
              proto_tree_add_text(tree, a->tvb, token_offset, 0,
                "%s: ERROR: Couldn't parse header: %s",
                proto_registrar_get_name(hf_ldap_message_bind_auth_credentials),
                asn1_err_to_str(ret));
              return;
            }
            if (tree) {
              gitem = proto_tree_add_text(tree, tvb, token_offset,
                (a->offset + cred_length) - token_offset, "GSS-API Token");
              gtree = proto_item_add_subtree(gitem, ett_ldap_gssapi_token);
            }
            available_length = tvb_length_remaining(tvb, token_offset);
            reported_length = tvb_reported_length_remaining(tvb, token_offset);
            g_assert(available_length >= 0);
            g_assert(reported_length >= 0);
            if (available_length > reported_length)
              available_length = reported_length;
            if ((guint)available_length > cred_length)
              available_length = cred_length;
            if ((guint)reported_length > cred_length)
              reported_length = cred_length;
            new_tvb = tvb_new_subset(tvb, a->offset, available_length, reported_length);
            call_dissector(gssapi_handle, new_tvb, pinfo, gtree);
            a->offset += cred_length;
          } else {
            if (read_bytestring(a, tree, hf_ldap_message_bind_server_credentials,
                                NULL, NULL, ASN1_UNI, ASN1_OTS) != ASN1_ERR_NOERROR)
              return;
          }
          break;

        default:
          if (read_bytestring(a, tree, hf_ldap_message_bind_server_credentials,
                              NULL, NULL, ASN1_CTX, 7) != ASN1_ERR_NOERROR)
            return;
          break;
        }
      } else {
        if (read_bytestring(a, tree, hf_ldap_message_bind_server_credentials,
                            NULL, NULL, ASN1_CTX, 7) != ASN1_ERR_NOERROR)
          return;
      }
    } else {
      if (read_bytestring(a, tree, hf_ldap_message_bind_server_credentials,
                          NULL, NULL, ASN1_CTX, 7) != ASN1_ERR_NOERROR)
        return;
    }
  }
}

static void dissect_ldap_request_search(ASN1_SCK *a, proto_tree *tree)
{
  guint seq_length;
  int end;
  int ret;

  if (read_string(a, tree, hf_ldap_message_search_base, 0, 0, ASN1_UNI, ASN1_OTS) != ASN1_ERR_NOERROR)
    return;
  if (read_integer(a, tree, hf_ldap_message_search_scope, 0, 0, ASN1_ENUM) != ASN1_ERR_NOERROR)
    return;
  if (read_integer(a, tree, hf_ldap_message_search_deref, 0, 0, ASN1_ENUM) != ASN1_ERR_NOERROR)
    return;
  if (read_integer(a, tree, hf_ldap_message_search_sizeLimit, 0, 0, ASN1_INT) != ASN1_ERR_NOERROR)
    return;
  if (read_integer(a, tree, hf_ldap_message_search_timeLimit, 0, 0, ASN1_INT) != ASN1_ERR_NOERROR)
    return;
  if (read_boolean(a, tree, hf_ldap_message_search_typesOnly, 0, 0) != ASN1_ERR_NOERROR)
    return;
  if (!read_filter(a, tree, hf_ldap_message_search_filter))
    return;
  ret = read_sequence(a, &seq_length);
  if (ret != ASN1_ERR_NOERROR) {
    if (tree) {
      proto_tree_add_text(tree, a->tvb, a->offset, 0,
          "ERROR: Couldn't parse LDAP attribute sequence header: %s",
          asn1_err_to_str(ret));
    }
    return;
  }
  end = a->offset + seq_length;
  while (a->offset < end) {
    if (read_string(a, tree, hf_ldap_message_attribute, 0, 0, ASN1_UNI,
                    ASN1_OTS) != ASN1_ERR_NOERROR)
      return;
  }
}

static void dissect_ldap_response_search_entry(ASN1_SCK *a, proto_tree *tree)
{
  guint seq_length;
  int end_of_sequence;
  int ret;

  if (read_string(a, tree, hf_ldap_message_dn, 0, 0, ASN1_UNI, ASN1_OTS) != ASN1_ERR_NOERROR)
    return;
  ret = read_sequence(a, &seq_length);
  if (ret != ASN1_ERR_NOERROR) {
    if (tree) {
      proto_tree_add_text(tree, a->tvb, a->offset, 0,
          "ERROR: Couldn't parse search entry response sequence header: %s",
          asn1_err_to_str(ret));
    }
    return;
  }

  end_of_sequence = a->offset + seq_length;
  while (a->offset < end_of_sequence)
  {
    proto_item *ti;
    proto_tree *attr_tree;
    guint set_length;
    int end_of_set;

    ret = read_sequence(a, 0);
    if (ret != ASN1_ERR_NOERROR) {
      if (tree) {
        proto_tree_add_text(tree, a->tvb, a->offset, 0,
            "ERROR: Couldn't parse LDAP attribute sequence header: %s",
            asn1_err_to_str(ret));
      }
      return;
    }
    if (read_string(a, tree, hf_ldap_message_attribute, &ti, 0, ASN1_UNI, ASN1_OTS) != ASN1_ERR_NOERROR)
      return;
    attr_tree = proto_item_add_subtree(ti, ett_ldap_attribute);

    ret = read_set(a, &set_length);
    if (ret != ASN1_ERR_NOERROR) {
      if (tree) {
        proto_tree_add_text(attr_tree, a->tvb, a->offset, 0,
            "ERROR: Couldn't parse LDAP value set header: %s",
            asn1_err_to_str(ret));
      }
      return;
    }
    end_of_set = a->offset + set_length;
    while (a->offset < end_of_set) {
      if (read_string(a, attr_tree, hf_ldap_message_value, 0, 0, ASN1_UNI,
                      ASN1_OTS) != ASN1_ERR_NOERROR)
        return;
    }
  }
}

static void dissect_ldap_request_add(ASN1_SCK *a, proto_tree *tree)
{
  guint seq_length;
  int end_of_sequence;
  int ret;

  if (read_string(a, tree, hf_ldap_message_dn, 0, 0, ASN1_UNI, ASN1_OTS) != ASN1_ERR_NOERROR)
    return;

  ret = read_sequence(a, &seq_length);
  if (ret != ASN1_ERR_NOERROR) {
    if (tree) {
      proto_tree_add_text(tree, a->tvb, a->offset, 0,
          "ERROR: Couldn't parse add request sequence header: %s",
          asn1_err_to_str(ret));
    }
    return;
  }

  end_of_sequence = a->offset + seq_length;
  while (a->offset < end_of_sequence)
  {
    proto_item *ti;
    proto_tree *attr_tree;
    guint set_length;
    int end_of_set;

    ret = read_sequence(a, 0);
    if (ret != ASN1_ERR_NOERROR) {
      if (tree) {
        proto_tree_add_text(tree, a->tvb, a->offset, 0,
            "ERROR: Couldn't parse LDAP attribute sequence header: %s",
            asn1_err_to_str(ret));
      }
      return;
    }
    if (read_string(a, tree, hf_ldap_message_attribute, &ti, 0, ASN1_UNI,
                    ASN1_OTS) != ASN1_ERR_NOERROR)
      return;
    attr_tree = proto_item_add_subtree(ti, ett_ldap_attribute);

    ret = read_set(a, &set_length);
    if (ret != ASN1_ERR_NOERROR) {
      if (tree) {
        proto_tree_add_text(attr_tree, a->tvb, a->offset, 0,
            "ERROR: Couldn't parse LDAP value set header: %s",
            asn1_err_to_str(ret));
      }
      return;
    }
    end_of_set = a->offset + set_length;
    while (a->offset < end_of_set) {
      if (read_string(a, attr_tree, hf_ldap_message_value, 0, 0, ASN1_UNI, ASN1_OTS) != ASN1_ERR_NOERROR)
        return;
    }
  }
}

static void dissect_ldap_request_delete(ASN1_SCK *a, proto_tree *tree,
		int start, guint length)
{
  read_string_value(a, tree, hf_ldap_message_dn, NULL, NULL, start, length);
}

static void dissect_ldap_request_modifyrdn(ASN1_SCK *a, proto_tree *tree,
		guint length)
{
  int start = a->offset;

  if (read_string(a, tree, hf_ldap_message_dn, 0, 0, ASN1_UNI, ASN1_OTS) != ASN1_ERR_NOERROR)
    return;
  if (read_string(a, tree, hf_ldap_message_modrdn_name, 0, 0, ASN1_UNI, ASN1_OTS) != ASN1_ERR_NOERROR)
    return;
  if (read_boolean(a, tree, hf_ldap_message_modrdn_delete, 0, 0) != ASN1_ERR_NOERROR)
    return;

  if (a->offset < (int) (start + length)) {
    /* LDAP V3 Modify DN operation, with newSuperior */
    /*      "newSuperior     [0] LDAPDN OPTIONAL" (0x80) */
    if (read_string(a, tree, hf_ldap_message_modrdn_superior, 0, 0, ASN1_CTX, 0) != ASN1_ERR_NOERROR)
      return;
  }
}

static void dissect_ldap_request_compare(ASN1_SCK *a, proto_tree *tree)
{
  int start;
  int length;
  char *string1 = NULL;
  char *string2 = NULL;
  char *s1, *s2;
  char *compare;
  int ret;

  if (read_string(a, tree, hf_ldap_message_dn, 0, 0, ASN1_UNI, ASN1_OTS) != ASN1_ERR_NOERROR)
    return;
  ret = read_sequence(a, 0);
  if (ret != ASN1_ERR_NOERROR) {
    if (tree) {
      proto_tree_add_text(tree, a->tvb, a->offset, 0,
          "ERROR: Couldn't parse compare request sequence header: %s",
          asn1_err_to_str(ret));
    }
    return;
  }

  start = a->offset;
  ret = read_string(a, 0, -1, 0, &string1, ASN1_UNI, ASN1_OTS);
  if (ret != ASN1_ERR_NOERROR) {
    if (tree) {
      proto_tree_add_text(tree, a->tvb, start, 0,
        "ERROR: Couldn't parse compare type: %s", asn1_err_to_str(ret));
    }
    return;
  }
  ret = read_string(a, 0, -1, 0, &string2, ASN1_UNI, ASN1_OTS);
  if (ret != ASN1_ERR_NOERROR) {
    if (tree) {
      proto_tree_add_text(tree, a->tvb, start, 0,
        "ERROR: Couldn't parse compare value: %s", asn1_err_to_str(ret));
    }
    return;
  }

  s1 = (string1 == NULL) ? "(null)" : string1;
  s2 = (string2 == NULL) ? "(null)" : string2;
  length = 2 + strlen(s1) + strlen(s2);
  compare = g_malloc0(length);
  snprintf(compare, length, "%s=%s", s1, s2);
  proto_tree_add_string(tree, hf_ldap_message_compare, a->tvb, start,
      a->offset-start, compare);

  g_free(string1);
  g_free(string2);
  g_free(compare);

  return;
}

static void dissect_ldap_request_modify(ASN1_SCK *a, proto_tree *tree)
{
  guint seq_length;
  int end_of_sequence;
  int ret;

  if (read_string(a, tree, hf_ldap_message_dn, 0, 0, ASN1_UNI, ASN1_OTS) != ASN1_ERR_NOERROR)
    return;
  ret = read_sequence(a, &seq_length);
  if (ret != ASN1_ERR_NOERROR) {
    if (tree) {
      proto_tree_add_text(tree, a->tvb, a->offset, 0,
          "ERROR: Couldn't parse modify request sequence header: %s",
          asn1_err_to_str(ret));
    }
    return;
  }
  end_of_sequence = a->offset + seq_length;
  while (a->offset < end_of_sequence)
  {
    proto_item *ti;
    proto_tree *attr_tree;
    guint set_length;
    int end_of_set;
    guint operation;

    ret = read_sequence(a, 0);
    if (ret != ASN1_ERR_NOERROR) {
      if (tree) {
        proto_tree_add_text(tree, a->tvb, a->offset, 0,
            "ERROR: Couldn't parse modify request item sequence header: %s",
            asn1_err_to_str(ret));
      }
      return;
    }
    ret = read_integer(a, 0, -1, 0, &operation, ASN1_ENUM);
    if (ret != ASN1_ERR_NOERROR) {
      if (tree) {
        proto_tree_add_text(tree, a->tvb, a->offset, 0,
          "ERROR: Couldn't parse modify operation: %s",
          asn1_err_to_str(ret));
        return;
      }
    }
    ret = read_sequence(a, 0);
    if (ret != ASN1_ERR_NOERROR) {
      if (tree) {
        proto_tree_add_text(tree, a->tvb, a->offset, 0,
            "ERROR: Couldn't parse modify request operation sequence header: %s",
            asn1_err_to_str(ret));
      }
      return;
    }

    switch (operation)
    {
     case LDAP_MOD_ADD:
      if (read_string(a, tree, hf_ldap_message_modify_add, &ti, 0, ASN1_UNI,
                      ASN1_OTS) != ASN1_ERR_NOERROR)
        return;
      break;

     case LDAP_MOD_REPLACE:
      if (read_string(a, tree, hf_ldap_message_modify_replace, &ti, 0,
                      ASN1_UNI, ASN1_OTS) != ASN1_ERR_NOERROR)
        return;
      break;

     case LDAP_MOD_DELETE:
      if (read_string(a, tree, hf_ldap_message_modify_delete, &ti, 0,
                      ASN1_UNI, ASN1_OTS) != ASN1_ERR_NOERROR)
        return;
      break;

     default:
       proto_tree_add_text(tree, a->tvb, a->offset, 0,
            "Unknown LDAP modify operation (%u)", operation);
       return;
    }
    attr_tree = proto_item_add_subtree(ti, ett_ldap_attribute);

    ret = read_set(a, &set_length);
    if (ret != ASN1_ERR_NOERROR) {
      if (tree) {
        proto_tree_add_text(attr_tree, a->tvb, a->offset, 0,
            "ERROR: Couldn't parse LDAP value set header: %s",
            asn1_err_to_str(ret));
      }
      return;
    }
    end_of_set = a->offset + set_length;
    while (a->offset < end_of_set) {
      if (read_string(a, attr_tree, hf_ldap_message_value, 0, 0, ASN1_UNI,
                      ASN1_OTS) != ASN1_ERR_NOERROR)
        return;
    }
  }
}

static void dissect_ldap_request_abandon(ASN1_SCK *a, proto_tree *tree,
		int start, guint length)
{
  read_integer_value(a, tree, hf_ldap_message_abandon_msgid, NULL, NULL,
			    start, length);
}

static void
dissect_ldap_message(tvbuff_t *tvb, int offset, packet_info *pinfo,
                     proto_tree *ldap_tree, gboolean first_time)
{
  int message_id_start;
  int message_id_length;
  proto_item *ti;
  proto_tree *msg_tree = NULL;
  guint messageLength;
  guint messageId;
  int next_offset;
  guint protocolOpCls, protocolOpCon, protocolOpTag;
  gchar *typestr;
  guint opLen;
  ASN1_SCK a;
  int start;
  int ret;

  asn1_open(&a, tvb, offset);

  ret = read_sequence(&a, &messageLength);
  if (ret != ASN1_ERR_NOERROR)
  {
    if (first_time)
    {
      if (check_col(pinfo->cinfo, COL_INFO))
      {
        col_add_fstr(pinfo->cinfo, COL_INFO,
                    "Invalid LDAP message (Can't parse sequence header: %s)",
                    asn1_err_to_str(ret));
      }
    }
    if (ldap_tree)
    {
      proto_tree_add_text(ldap_tree, tvb, offset, -1,
			  "Invalid LDAP message (Can't parse sequence header: %s)",
			  asn1_err_to_str(ret));
    }
    return;
  }

  message_id_start = a.offset;
  ret = read_integer(&a, 0, hf_ldap_message_id, 0, &messageId, ASN1_INT);
  if (ret != ASN1_ERR_NOERROR)
  {
    if (first_time && check_col(pinfo->cinfo, COL_INFO))
      col_add_fstr(pinfo->cinfo, COL_INFO, "Invalid LDAP packet (Can't parse Message ID: %s)",
                   asn1_err_to_str(ret));
    if (ldap_tree)
      proto_tree_add_text(ldap_tree, tvb, message_id_start, 1,
                          "Invalid LDAP packet (Can't parse Message ID: %s)",
                          asn1_err_to_str(ret));
      return;
  }
  message_id_length = a.offset - message_id_start;

  start = a.offset;
  asn1_id_decode(&a, &protocolOpCls, &protocolOpCon, &protocolOpTag);
  if (protocolOpCls != ASN1_APL)
    typestr = "Bad message type (not Application)";
  else
    typestr = val_to_str(protocolOpTag, msgTypes, "Unknown message type (%u)");

  if (first_time)
  {
    if (check_col(pinfo->cinfo, COL_INFO))
      col_add_fstr(pinfo->cinfo, COL_INFO, "MsgId=%u MsgType=%s",
		   messageId, typestr);
  }

  if (ldap_tree)
  {
    ti = proto_tree_add_text(ldap_tree, tvb, message_id_start, messageLength, "Message: Id=%u  %s", messageId, typestr);
    msg_tree = proto_item_add_subtree(ti, ett_ldap_message);
    proto_tree_add_uint(msg_tree, hf_ldap_message_id, tvb, message_id_start, message_id_length, messageId);
    proto_tree_add_uint(msg_tree, hf_ldap_message_type, tvb,
			       start, a.offset - start, protocolOpTag);
  }
  start = a.offset;
  if (read_length(&a, msg_tree, hf_ldap_message_length, &opLen) != ASN1_ERR_NOERROR)
    return;

  if (protocolOpCls != ASN1_APL)
  {
    if (ldap_tree)
    {
      proto_tree_add_text(msg_tree, a.tvb, a.offset, opLen,
			  "%s", typestr);
    }
  }
  else
  {
    switch (protocolOpTag)
    {
     case LDAP_REQ_BIND:
      dissect_ldap_request_bind(&a, msg_tree, tvb, pinfo);
      break;
     case LDAP_REQ_UNBIND:
      /* Nothing to dissect */
      break;
     case LDAP_REQ_SEARCH:
      if (ldap_tree)
        dissect_ldap_request_search(&a, msg_tree);
      break;
     case LDAP_REQ_MODIFY:
      if (ldap_tree)
        dissect_ldap_request_modify(&a, msg_tree);
      break;
     case LDAP_REQ_ADD:
      if (ldap_tree)
        dissect_ldap_request_add(&a, msg_tree);
      break;
     case LDAP_REQ_DELETE:
      if (ldap_tree)
        dissect_ldap_request_delete(&a, msg_tree, start, opLen);
      break;
     case LDAP_REQ_MODRDN:
      if (ldap_tree)
        dissect_ldap_request_modifyrdn(&a, msg_tree, opLen);
      break;
     case LDAP_REQ_COMPARE:
      if (ldap_tree)
        dissect_ldap_request_compare(&a, msg_tree);
      break;
     case LDAP_REQ_ABANDON:
      if (ldap_tree)
        dissect_ldap_request_abandon(&a, msg_tree, start, opLen);
      break;
     case LDAP_RES_BIND:
      dissect_ldap_response_bind(&a, msg_tree, start, opLen, tvb, pinfo);
      break;
     case LDAP_RES_SEARCH_ENTRY:
      if (ldap_tree)
        dissect_ldap_response_search_entry(&a, msg_tree);
      break;
     case LDAP_RES_SEARCH_RESULT:
     case LDAP_RES_MODIFY:
     case LDAP_RES_ADD:
     case LDAP_RES_DELETE:
     case LDAP_RES_MODRDN:
     case LDAP_RES_COMPARE:
      if (ldap_tree)
        dissect_ldap_result(&a, msg_tree);
      break;
     default:
      if (ldap_tree)
      {
        proto_tree_add_text(msg_tree, a.tvb, a.offset, opLen,
                            "Unknown LDAP operation (%u)", protocolOpTag);
      }
      break;
    }
  }

  /*
   * XXX - what if "next_offset" is past the offset of the next top-level
   * sequence?  Show that as an error?
   */
  asn1_close(&a, &next_offset);	/* XXX - use the new value of next_offset? */
}

static void
dissect_ldap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  int offset = 0;
  gboolean first_time = TRUE;
  conversation_t *conversation;
  ldap_auth_info_t *auth_info = NULL;
  gboolean doing_sasl_security = FALSE;
  guint length_remaining;
  guint32 sasl_length;
  guint32 message_data_len;
  proto_item *ti;
  proto_tree *ldap_tree = NULL;
  ASN1_SCK a;
  int ret;
  guint messageLength;
  int messageOffset;
  guint headerLength;
  guint length;
  gint available_length, reported_length;
  int len;
  proto_item *gitem = NULL;
  proto_tree *gtree = NULL;
  tvbuff_t *next_tvb;

  /*
   * Do we have a conversation for this connection?
   */
  conversation = find_conversation(&pinfo->src, &pinfo->dst,
                                   pinfo->ptype, pinfo->srcport,
                                   pinfo->destport, 0);
  if (conversation != NULL) {
    /*
     * Yes - do we have any authentication mechanism for it?
     */
    auth_info = conversation_get_proto_data(conversation, proto_ldap);
    if (auth_info != NULL) {
      /*
       * Yes - what's the authentication type?
       */
      switch (auth_info->auth_type) {

      case LDAP_AUTH_SASL:
        /*
         * It's SASL; are we using a security layer?
         */
        if (auth_info->first_auth_frame != 0 &&
            pinfo->fd->num >= auth_info->first_auth_frame)
          doing_sasl_security = TRUE;	/* yes */
      }
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
      /*
       * Yes.  The frame begins with a 4-byte big-endian length.
       * Can we do reassembly?
       */
      if (ldap_desegment && pinfo->can_desegment) {
        /*
         * Yes - is the SASL length split across segment boundaries?
         */
        if (length_remaining < 4) {
          /*
           * Yes.  Tell the TCP dissector where the data for this message
           * starts in the data it handed us, and how many more bytes we
           * need, and return.
           */
          pinfo->desegment_offset = offset;
          pinfo->desegment_len = 4 - length_remaining;
          return;
        }
      }

      /*
       * Get the SASL length, which is the length of data in the buffer
       * following the length (i.e., it's 4 less than the total length).
       *
       * XXX - do we need to reassemble buffers?  For now, we
       * assume that each LDAP message is entirely contained within
       * a buffer.
       */
      sasl_length = tvb_get_ntohl(tvb, offset);
      message_data_len = sasl_length + 4;
      if (message_data_len < 4) {
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
       * Can we do reassembly?
       */
      if (ldap_desegment && pinfo->can_desegment) {
        /*
         * Yes - is the buffer split across segment boundaries?
         */
        if (length_remaining < message_data_len) {
          /*
           * Yes.  Tell the TCP dissector where the data for this message
           * starts in the data it handed us, and how many more bytes we
           * need, and return.
           */
          pinfo->desegment_offset = offset;
          pinfo->desegment_len = message_data_len - length_remaining;
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
      if (length > message_data_len)
        length = message_data_len;
      next_tvb = tvb_new_subset(tvb, offset, length, message_data_len);

      /*
       * If this is the first PDU, set the Protocol column and clear the
       * Info column.
       */
      if (first_time)
      {
        if (check_col(pinfo->cinfo, COL_PROTOCOL))
          col_set_str(pinfo->cinfo, COL_PROTOCOL, "LDAP");
        if (check_col(pinfo->cinfo, COL_INFO))
          col_clear(pinfo->cinfo, COL_INFO);
      }

      if (tree)
      {
        ti = proto_tree_add_item(tree, proto_ldap, next_tvb, 0, -1, FALSE);
        ldap_tree = proto_item_add_subtree(ti, ett_ldap);

        proto_tree_add_uint(ldap_tree, hf_ldap_sasl_buffer_length, tvb, 0, 4,
                            sasl_length);
      }

      if (auth_info->auth_mech != NULL &&
          strcmp(auth_info->auth_mech, "GSS-SPNEGO") == 0) {
          /*
           * This is GSS-API (using SPNEGO, but we should be done with
           * the negotiation by now).
           *
           * Dissect the GSS_Wrap() token; it'll return the length of
           * the token, from which we compute the offset in the tvbuff at
           * which the plaintext data, i.e. the LDAP message, begins.
           */
          available_length = tvb_length_remaining(tvb, 4);
          reported_length = tvb_reported_length_remaining(tvb, 4);
          g_assert(available_length >= 0);
          g_assert(reported_length >= 0);
          if (available_length > reported_length)
            available_length = reported_length;
          if ((guint)available_length > sasl_length - 4)
            available_length = sasl_length - 4;
          if ((guint)reported_length > sasl_length - 4)
            reported_length = sasl_length - 4;
          next_tvb = tvb_new_subset(tvb, 4, available_length, reported_length);
          if (tree)
          {
            gitem = proto_tree_add_text(ldap_tree, next_tvb, 0, -1, "GSS-API Token");
            gtree = proto_item_add_subtree(gitem, ett_ldap_gssapi_token);
          }
          len = call_dissector(gssapi_wrap_handle, next_tvb, pinfo, gtree);
          g_assert(len != 0);	/* GSS_Wrap() dissectors can't reject data */
          if (gitem != NULL)
              proto_item_set_len(gitem, len);

          /*
           * Now dissect the LDAP message.
           */
          dissect_ldap_message(tvb, 4 + len, pinfo, ldap_tree, first_time);
      } else {
        /*
         * We don't know how to handle other authentication mechanisms
         * yet, so just put in an entry for the SASL buffer.
         */
        proto_tree_add_text(ldap_tree, tvb, 4, -1, "SASL buffer");
      }
      offset += message_data_len;
    } else {
      /*
       * No, we're not doing a SASL security layer.  The frame begins
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
          pinfo->desegment_offset = offset;
          pinfo->desegment_len = 6 - length_remaining;
          return;
        }
      }

      /*
       * OK, try to read the "Sequence Of" header; this gets the total
       * length of the LDAP message.
       */
      asn1_open(&a, tvb, offset);
      ret = read_sequence(&a, &messageLength);
      asn1_close(&a, &messageOffset);

      if (ret == ASN1_ERR_NOERROR) {
      	/*
      	 * Add the length of the "Sequence Of" header to the message
      	 * length.
      	 */
      	headerLength = messageOffset - offset;
      	messageLength += headerLength;
        if (messageLength < headerLength) {
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
      	messageLength = length_remaining;
      }

      /*
       * Can we do reassembly?
       */
      if (ldap_desegment && pinfo->can_desegment) {
        /*
         * Yes - is the message split across segment boundaries?
         */
        if (length_remaining < messageLength) {
	  /*
	   * Yes.  Tell the TCP dissector where the data for this message
	   * starts in the data it handed us, and how many more bytes
	   * we need, and return.
	   */
	  pinfo->desegment_offset = offset;
	  pinfo->desegment_len = messageLength - length_remaining;
	  return;
        }
      }

      /*
       * If this is the first PDU, set the Protocol column and clear the
       * Info column.
       */
      if (first_time) {
        if (check_col(pinfo->cinfo, COL_PROTOCOL))
          col_set_str(pinfo->cinfo, COL_PROTOCOL, "LDAP");
        if (check_col(pinfo->cinfo, COL_INFO))
          col_clear(pinfo->cinfo, COL_INFO);
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
      if (length > messageLength)
        length = messageLength;
      next_tvb = tvb_new_subset(tvb, offset, length, messageLength);

      /*
       * Now dissect the LDAP message.
       */
      if (tree) {
        ti = proto_tree_add_item(tree, proto_ldap, next_tvb, 0, -1, FALSE);
        ldap_tree = proto_item_add_subtree(ti, ett_ldap);
      } else
        ldap_tree = NULL;
      dissect_ldap_message(next_tvb, 0, pinfo, ldap_tree, first_time);

      offset += messageLength;
    }

    first_time = FALSE;
  }
}

static void
ldap_reinit(void)
{
  ldap_auth_info_t *auth_info;

  /* Free up saved authentication mechanism strings */
  for (auth_info = auth_info_items; auth_info != NULL;
       auth_info = auth_info->next) {
    if (auth_info->auth_mech != NULL)
      g_free(auth_info->auth_mech);
  }

  if (ldap_auth_info_chunk != NULL)
    g_mem_chunk_destroy(ldap_auth_info_chunk);

  auth_info_items = NULL;

  ldap_auth_info_chunk = g_mem_chunk_new("ldap_auth_info_chunk",
		sizeof(ldap_auth_info_t),
		ldap_auth_info_chunk_count * sizeof(ldap_auth_info_t),
		G_ALLOC_ONLY);
}

void
proto_register_ldap(void)
{
  static value_string result_codes[] = {
    {0, "Success"},
    {1, "Operations error"},
    {2, "Protocol error"},
    {3, "Time limit exceeded"},
    {4, "Size limit exceeded"},
    {5, "Compare false"},
    {6, "Compare true"},
    {7, "Authentication method not supported"},
    {8, "Strong authentication required"},
    {10, "Referral"},
    {11, "Administrative limit exceeded"},
    {12, "Unavailable critical extension"},
    {13, "Confidentiality required"},
    {14, "SASL bind in progress"},
    {16, "No such attribute"},
    {17, "Undefined attribute type"},
    {18, "Inappropriate matching"},
    {19, "Constraint violation"},
    {20, "Attribute or value exists"},
    {21, "Invalid attribute syntax"},
    {32, "No such object"},
    {33, "Alias problem"},
    {34, "Invalid DN syntax"},
    {36, "Alias derefetencing problem"},
    {48, "Inappropriate authentication"},
    {49, "Invalid credentials"},
    {50, "Insufficient access rights"},
    {51, "Busy"},
    {52, "Unavailable"},
    {53, "Unwilling to perform"},
    {54, "Loop detected"},
    {64, "Naming violation"},
    {65, "Objectclass violation"},
    {66, "Not allowed on non-leaf"},
    {67, "Not allowed on RDN"},
    {68, "Entry already exists"},
    {69, "Objectclass modification prohibited"},
    {71, "Affects multiple DSAs"},
    {80, "Other"},
    {0,  NULL},
  };

  static value_string auth_types[] = {
    {LDAP_AUTH_SIMPLE,    "Simple"},
    {LDAP_AUTH_KRBV4LDAP, "Kerberos V4 to the LDAP server"},
    {LDAP_AUTH_KRBV4DSA,  "Kerberos V4 to the DSA"},
    {LDAP_AUTH_SASL,      "SASL"},
    {0, NULL},
  };

  static value_string search_scope[] = {
    {0x00, "Base"},
    {0x01, "Single"},
    {0x02, "Subtree"},
    {0x00, NULL},
  };

  static value_string search_dereference[] = {
    {0x00, "Never"},
    {0x01, "Searching"},
    {0x02, "Base Object"},
    {0x03, "Always"},
    {0x00, NULL},
  };

  static hf_register_info hf[] = {
    { &hf_ldap_sasl_buffer_length,
      { "SASL Buffer Length",	"ldap.sasl_buffer_length",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"SASL Buffer Length", HFILL }},

    { &hf_ldap_length,
      { "Length",		"ldap.length",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"LDAP Length", HFILL }},

    { &hf_ldap_message_id,
      { "Message Id",		"ldap.message_id",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"LDAP Message Id", HFILL }},
    { &hf_ldap_message_type,
      { "Message Type",		"ldap.message_type",
	FT_UINT8, BASE_HEX, &msgTypes, 0x0,
	"LDAP Message Type", HFILL }},
    { &hf_ldap_message_length,
      { "Message Length",		"ldap.message_length",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"LDAP Message Length", HFILL }},

    { &hf_ldap_message_result,
      { "Result Code",		"ldap.result.code",
	FT_UINT8, BASE_HEX, result_codes, 0x0,
	"LDAP Result Code", HFILL }},
    { &hf_ldap_message_result_matcheddn,
      { "Matched DN",		"ldap.result.matcheddn",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Result Matched DN", HFILL }},
    { &hf_ldap_message_result_errormsg,
      { "Error Message",		"ldap.result.errormsg",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Result Error Message", HFILL }},
    { &hf_ldap_message_result_referral,
      { "Referral",		"ldap.result.referral",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Result Referral URL", HFILL }},

    { &hf_ldap_message_bind_version,
      { "Version",		"ldap.bind.version",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"LDAP Bind Version", HFILL }},
    { &hf_ldap_message_bind_dn,
      { "DN",			"ldap.bind.dn",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Bind Distinguished Name", HFILL }},
    { &hf_ldap_message_bind_auth,
      { "Auth Type",		"ldap.bind.auth_type",
	FT_UINT8, BASE_HEX, auth_types, 0x0,
	"LDAP Bind Auth Type", HFILL }},
    { &hf_ldap_message_bind_auth_password,
      { "Password",		"ldap.bind.password",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Bind Password", HFILL }},
    { &hf_ldap_message_bind_auth_mechanism,
      { "Mechanism",		"ldap.bind.mechanism",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Bind Mechanism", HFILL }},
    { &hf_ldap_message_bind_auth_credentials,
      { "Credentials",		"ldap.bind.credentials",
	FT_BYTES, BASE_NONE, NULL, 0x0,
	"LDAP Bind Credentials", HFILL }},
    { &hf_ldap_message_bind_server_credentials,
      { "Server Credentials",	"ldap.bind.server_credentials",
	FT_BYTES, BASE_NONE, NULL, 0x0,
	"LDAP Bind Server Credentials", HFILL }},

    { &hf_ldap_message_search_base,
      { "Base DN",		"ldap.search.basedn",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Search Base Distinguished Name", HFILL }},
    { &hf_ldap_message_search_scope,
      { "Scope",			"ldap.search.scope",
	FT_UINT8, BASE_HEX, search_scope, 0x0,
	"LDAP Search Scope", HFILL }},
    { &hf_ldap_message_search_deref,
      { "Dereference",		"ldap.search.dereference",
	FT_UINT8, BASE_HEX, search_dereference, 0x0,
	"LDAP Search Dereference", HFILL }},
    { &hf_ldap_message_search_sizeLimit,
      { "Size Limit",		"ldap.search.sizelimit",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"LDAP Search Size Limit", HFILL }},
    { &hf_ldap_message_search_timeLimit,
      { "Time Limit",		"ldap.search.timelimit",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"LDAP Search Time Limit", HFILL }},
    { &hf_ldap_message_search_typesOnly,
      { "Attributes Only",	"ldap.search.typesonly",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"LDAP Search Attributes Only", HFILL }},
    { &hf_ldap_message_search_filter,
      { "Filter",		"ldap.search.filter",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Search Filter", HFILL }},
    { &hf_ldap_message_dn,
      { "Distinguished Name",	"ldap.dn",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Distinguished Name", HFILL }},
    { &hf_ldap_message_attribute,
      { "Attribute",		"ldap.attribute",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Attribute", HFILL }},
    /*
     * XXX - not all LDAP values are text strings; we'd need a file
     * describing which values (by name) are text strings and which are
     * binary.
     *
     * Some values that are, at least in Microsoft's schema, binary
     * are:
     *
     *	invocationId
     *	nTSecurityDescriptor
     *	objectGUID
     */
    { &hf_ldap_message_value,
      { "Value",		"ldap.value",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Value", HFILL }},

    { &hf_ldap_message_modrdn_name,
      { "New Name",		"ldap.modrdn.name",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP New Name", HFILL }},
    { &hf_ldap_message_modrdn_delete,
      { "Delete Values",	"ldap.modrdn.delete",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"LDAP Modify RDN - Delete original values", HFILL }},
    { &hf_ldap_message_modrdn_superior,
      { "New Location",		"ldap.modrdn.superior",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Modify RDN - New Location", HFILL }},

    { &hf_ldap_message_compare,
      { "Test",		"ldap.compare.test",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Compare Test", HFILL }},

    { &hf_ldap_message_modify_add,
      { "Add",			"ldap.modify.add",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Add", HFILL }},
    { &hf_ldap_message_modify_replace,
      { "Replace",		"ldap.modify.replace",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Replace", HFILL }},
    { &hf_ldap_message_modify_delete,
      { "Delete",		"ldap.modify.delete",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Delete", HFILL }},

    { &hf_ldap_message_abandon_msgid,
      { "Abandon Msg Id",	"ldap.abandon.msgid",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"LDAP Abandon Msg Id", HFILL }},
  };

  static gint *ett[] = {
    &ett_ldap,
    &ett_ldap_message,
    &ett_ldap_gssapi_token,
    &ett_ldap_referrals,
    &ett_ldap_attribute
  };
  module_t *ldap_module;

  proto_ldap = proto_register_protocol("Lightweight Directory Access Protocol",
				       "LDAP", "ldap");
  proto_register_field_array(proto_ldap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  ldap_module = prefs_register_protocol(proto_ldap, NULL);
  prefs_register_bool_preference(ldap_module, "desegment_ldap_messages",
    "Desegment all LDAP messages spanning multiple TCP segments",
    "Whether the LDAP dissector should desegment all messages spanning multiple TCP segments",
    &ldap_desegment);

  register_init_routine(ldap_reinit);
}

void
proto_reg_handoff_ldap(void)
{
  dissector_handle_t ldap_handle;

  ldap_handle = create_dissector_handle(dissect_ldap, proto_ldap);
  dissector_add("tcp.port", TCP_PORT_LDAP, ldap_handle);
  dissector_add("udp.port", UDP_PORT_CLDAP, ldap_handle);

  gssapi_handle = find_dissector("gssapi");
  gssapi_wrap_handle = find_dissector("gssapi_verf");
}
