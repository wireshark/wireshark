/* packet-ldap.c
 * Routines for ldap packet dissection
 *
 * $Id: packet-ldap.c,v 1.39 2002/03/02 21:51:52 guy Exp $
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>

#include "packet-ldap.h"
#include "asn1.h"
#include "prefs.h"

static int proto_ldap = -1;
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
static gint ett_ldap_referrals = -1;
static gint ett_ldap_attribute = -1;

/* desegmentation of LDAP */
static gboolean ldap_desegment = TRUE;

#define TCP_PORT_LDAP			389

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
  if (ret != ASN1_ERR_NOERROR)
    return ret;

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
  if (ret != ASN1_ERR_NOERROR)
    return ret;

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
  if (ret != ASN1_ERR_NOERROR)
    return ret;
  if (cls != ASN1_UNI || con != ASN1_PRI || tag != expected_tag)
    return ASN1_ERR_WRONG_TYPE;

  return read_integer_value(a, tree, hf_id, new_item, i, start, length);
}

static int read_boolean_value(ASN1_SCK *a, proto_tree *tree, int hf_id,
	proto_item **new_item, guint *i, int start, guint length)
{
  guint integer = 0;
  proto_item *temp_item = NULL;

  asn1_uint32_value_decode(a, length, &integer);

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
  if (ret != ASN1_ERR_NOERROR)
    return ret;
  if (cls != ASN1_UNI || con != ASN1_PRI || tag != ASN1_BOL)
    return ASN1_ERR_WRONG_TYPE;

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
    if (ret != ASN1_ERR_NOERROR)
      return ret;
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
  if (ret != ASN1_ERR_NOERROR)
    return ret;
  if (cls != expected_cls || con != ASN1_PRI || tag != expected_tag)
    return ASN1_ERR_WRONG_TYPE;

  return read_string_value(a, tree, hf_id, new_item, s, start, length);
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
    return ret;
}

static int read_filter(ASN1_SCK *a, proto_tree *tree, int hf_id)
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
        "Error parsing filter: %s", asn1_err_to_str(ret));
    } else
      proto_tree_add_string(tree, hf_id, a->tvb, start, a->offset-start, filter);
  }

  g_free(filter);

  return (ret == -1) ? ASN1_ERR_NOERROR : ret;
}

/********************************************************************************************/

static int dissect_ldap_result(ASN1_SCK *a, proto_tree *tree)
{
  guint resultCode = 0;
  int ret;
  
  ret = read_integer(a, tree, hf_ldap_message_result, 0, &resultCode, ASN1_ENUM);
  if (ret != ASN1_ERR_NOERROR)
    return ret;
  ret = read_string(a, tree, hf_ldap_message_result_matcheddn, 0, 0, ASN1_UNI, ASN1_OTS);
  if (ret != ASN1_ERR_NOERROR)
    return ret;
  ret = read_string(a, tree, hf_ldap_message_result_errormsg, 0, 0, ASN1_UNI, ASN1_OTS);
  if (ret != ASN1_ERR_NOERROR)
    return ret;

  if (resultCode == 10)		/* Referral */
  {
    int start = a->offset;
    int end;
    guint length;
    proto_item *ti;
    proto_tree *referralTree;
    
    ret = read_sequence(a, &length);
    if (ret != ASN1_ERR_NOERROR)
      return ret;
    ti = proto_tree_add_text(tree, a->tvb, start, length, "Referral URLs");
    referralTree = proto_item_add_subtree(ti, ett_ldap_referrals);

    end = a->offset + length;
    while (a->offset < end) {
      ret = read_string(a, referralTree, hf_ldap_message_result_referral, 0, 0, ASN1_UNI, ASN1_OTS);
      if (ret != ASN1_ERR_NOERROR)
        return ret;
    }
  }
    
  return ASN1_ERR_NOERROR;
}

static int dissect_ldap_request_bind(ASN1_SCK *a, proto_tree *tree)
{
  guint cls, con, tag;
  guint def, length;
  int start;
  int ret;

  ret = read_integer(a, tree, hf_ldap_message_bind_version, 0, 0, ASN1_INT);
  if (ret != ASN1_ERR_NOERROR)
    return ret;
  ret = read_string(a, tree, hf_ldap_message_bind_dn, 0, 0, ASN1_UNI, ASN1_OTS);
  if (ret != ASN1_ERR_NOERROR)
    return ret;

  start = a->offset;
  ret = asn1_header_decode(a, &cls, &con, &tag, &def, &length);
  if (ret != ASN1_ERR_NOERROR)
    return ret;
  if (cls != ASN1_CTX)
    return ASN1_ERR_WRONG_TYPE;	/* RFCs 1777 and 2251 say these are context-specific types */
  proto_tree_add_uint(tree, hf_ldap_message_bind_auth, a->tvb, start,
			a->offset - start, tag);
  switch (tag)
  {
   case LDAP_AUTH_SIMPLE:
    ret = read_string_value(a, tree, hf_ldap_message_bind_auth_password, NULL,
			    NULL, start, length);
    if (ret != ASN1_ERR_NOERROR)
      return ret;
    break;

    /* For Kerberos V4, dissect it as a ticket. */
    /* For SASL, dissect it as SaslCredentials. */
  }
  
  return ASN1_ERR_NOERROR;
}

static int dissect_ldap_response_bind(ASN1_SCK *a, proto_tree *tree)
{
  /* FIXME: handle SASL data */
  return dissect_ldap_result(a, tree);
}

static int dissect_ldap_request_search(ASN1_SCK *a, proto_tree *tree)
{
  guint seq_length;
  int end;
  int ret;
  
  ret = read_string(a, tree, hf_ldap_message_search_base, 0, 0, ASN1_UNI, ASN1_OTS);
  if (ret != ASN1_ERR_NOERROR)
    return ret;
  ret = read_integer(a, tree, hf_ldap_message_search_scope, 0, 0, ASN1_ENUM);
  if (ret != ASN1_ERR_NOERROR)
    return ret;
  ret = read_integer(a, tree, hf_ldap_message_search_deref, 0, 0, ASN1_ENUM);
  if (ret != ASN1_ERR_NOERROR)
    return ret;
  ret = read_integer(a, tree, hf_ldap_message_search_sizeLimit, 0, 0, ASN1_INT);
  if (ret != ASN1_ERR_NOERROR)
    return ret;
  ret = read_integer(a, tree, hf_ldap_message_search_timeLimit, 0, 0, ASN1_INT);
  if (ret != ASN1_ERR_NOERROR)
    return ret;
  ret = read_boolean(a, tree, hf_ldap_message_search_typesOnly, 0, 0);
  if (ret != ASN1_ERR_NOERROR)
    return ret;
  ret = read_filter(a, tree, hf_ldap_message_search_filter);
  if (ret != ASN1_ERR_NOERROR)
    return ret;
  ret = read_sequence(a, &seq_length);
  if (ret != ASN1_ERR_NOERROR)
    return ret;
  end = a->offset + seq_length;
  while (a->offset < end) {
    ret = read_string(a, tree, hf_ldap_message_attribute, 0, 0, ASN1_UNI, ASN1_OTS);
    if (ret != ASN1_ERR_NOERROR)
      return ret;
  }
  return ASN1_ERR_NOERROR;
}

static int dissect_ldap_response_search_entry(ASN1_SCK *a, proto_tree *tree)
{
  guint seq_length;
  int end_of_sequence;
  int ret;
 
  ret = read_string(a, tree, hf_ldap_message_dn, 0, 0, ASN1_UNI, ASN1_OTS);
  if (ret != ASN1_ERR_NOERROR)
    return ret;
  ret = read_sequence(a, &seq_length);
  if (ret != ASN1_ERR_NOERROR)
    return ret;

  end_of_sequence = a->offset + seq_length;
  while (a->offset < end_of_sequence)
  {
    proto_item *ti;
    proto_tree *attr_tree;
    guint set_length;
    int end_of_set;

    ret = read_sequence(a, 0);
    if (ret != ASN1_ERR_NOERROR)
      return ret;
    ret = read_string(a, tree, hf_ldap_message_attribute, &ti, 0, ASN1_UNI, ASN1_OTS);
    if (ret != ASN1_ERR_NOERROR)
      return ret;
    attr_tree = proto_item_add_subtree(ti, ett_ldap_attribute);

    ret = read_set(a, &set_length);
    if (ret != ASN1_ERR_NOERROR)
      return ret;
    end_of_set = a->offset + set_length;
    while (a->offset < end_of_set) {
      ret = read_string(a, attr_tree, hf_ldap_message_value, 0, 0, ASN1_UNI, ASN1_OTS);
      if (ret != ASN1_ERR_NOERROR)
        return ret;
    }
  }

  return ASN1_ERR_NOERROR;
}

static int dissect_ldap_request_add(ASN1_SCK *a, proto_tree *tree)
{
  guint seq_length;
  int end_of_sequence;
  int ret;
  
  ret = read_string(a, tree, hf_ldap_message_dn, 0, 0, ASN1_UNI, ASN1_OTS);
  if (ret != ASN1_ERR_NOERROR)
    return ret;

  ret = read_sequence(a, &seq_length);
  if (ret != ASN1_ERR_NOERROR)
    return ret;
  end_of_sequence = a->offset + seq_length;
  while (a->offset < end_of_sequence)
  {
    proto_item *ti;
    proto_tree *attr_tree;
    guint set_length;
    int end_of_set;

    ret = read_sequence(a, 0);
    if (ret != ASN1_ERR_NOERROR)
      return ret;
    ret = read_string(a, tree, hf_ldap_message_attribute, &ti, 0, ASN1_UNI, ASN1_OTS);
    if (ret != ASN1_ERR_NOERROR)
      return ret;
    attr_tree = proto_item_add_subtree(ti, ett_ldap_attribute);

    ret = read_set(a, &set_length);
    if (ret != ASN1_ERR_NOERROR)
      return ret;
    end_of_set = a->offset + set_length;
    while (a->offset < end_of_set) {
      ret = read_string(a, attr_tree, hf_ldap_message_value, 0, 0, ASN1_UNI, ASN1_OTS);
      if (ret != ASN1_ERR_NOERROR)
        return ret;
    }
  }

  return ASN1_ERR_NOERROR;
}

static int dissect_ldap_request_delete(ASN1_SCK *a, proto_tree *tree,
		int start, guint length)
{
  return read_string_value(a, tree, hf_ldap_message_dn, NULL, NULL, start, length);
}

static int dissect_ldap_request_modifyrdn(ASN1_SCK *a, proto_tree *tree,
		guint length)
{
  int start = a->offset;
  int ret;

  ret = read_string(a, tree, hf_ldap_message_dn, 0, 0, ASN1_UNI, ASN1_OTS);
  if (ret != ASN1_ERR_NOERROR)
    return ret;
  ret = read_string(a, tree, hf_ldap_message_modrdn_name, 0, 0, ASN1_UNI, ASN1_OTS);
  if (ret != ASN1_ERR_NOERROR)
    return ret;
  ret = read_boolean(a, tree, hf_ldap_message_modrdn_delete, 0, 0);
  if (ret != ASN1_ERR_NOERROR)
    return ret;
  
  if (a->offset < (int) (start + length)) {
    /* LDAP V3 Modify DN operation, with newSuperior */
    ret = read_string(a, tree, hf_ldap_message_modrdn_superior, 0, 0, ASN1_UNI, ASN1_OTS);
    if (ret != ASN1_ERR_NOERROR)
      return ret;
  }

  return ASN1_ERR_NOERROR;
}

static int dissect_ldap_request_compare(ASN1_SCK *a, proto_tree *tree)
{
  int start;
  int length;
  char *string1 = 0;
  char *string2 = 0;
  char *compare;
  int ret;
  
  ret = read_string(a, tree, hf_ldap_message_dn, 0, 0, ASN1_UNI, ASN1_OTS);
  if (ret != ASN1_ERR_NOERROR)
    return ret;
  ret = read_sequence(a, 0);
  if (ret != ASN1_ERR_NOERROR)
    return ret;

  start = a->offset;
  ret = read_string(a, 0, -1, 0, &string1, ASN1_UNI, ASN1_OTS);
  if (ret != ASN1_ERR_NOERROR)
    return ret;
  ret = read_string(a, 0, -1, 0, &string2, ASN1_UNI, ASN1_OTS);
  if (ret != ASN1_ERR_NOERROR)
    return ret;

  length = 2 + strlen(string1) + strlen(string2);
  compare = g_malloc0(length);
  snprintf(compare, length, "%s=%s", string1, string2);
  proto_tree_add_string(tree, hf_ldap_message_compare, a->tvb, start,
      a->offset-start, compare);
  
  g_free(string1);
  g_free(string2);
  g_free(compare);
  
  return ASN1_ERR_NOERROR;
}

static int dissect_ldap_request_modify(ASN1_SCK *a, proto_tree *tree)
{
  guint seq_length;
  int end_of_sequence;
  int ret;
  
  ret = read_string(a, tree, hf_ldap_message_dn, 0, 0, ASN1_UNI, ASN1_OTS);
  if (ret != ASN1_ERR_NOERROR)
    return ret;
  ret = read_sequence(a, &seq_length);
  if (ret != ASN1_ERR_NOERROR)
    return ret;
  end_of_sequence = a->offset + seq_length;
  while (a->offset < end_of_sequence)
  {
    proto_item *ti;
    proto_tree *attr_tree;
    guint set_length;
    int end_of_set;
    guint operation;

    ret = read_sequence(a, 0);
    if (ret != ASN1_ERR_NOERROR)
      return ret;
    ret = read_integer(a, 0, -1, 0, &operation, ASN1_ENUM);
    if (ret != ASN1_ERR_NOERROR)
      return ret;
    ret = read_sequence(a, 0);
    if (ret != ASN1_ERR_NOERROR)
      return ret;

    switch (operation)
    {
     case LDAP_MOD_ADD:
      ret = read_string(a, tree, hf_ldap_message_modify_add, &ti, 0, ASN1_UNI, ASN1_OTS);
      if (ret != ASN1_ERR_NOERROR)
        return ret;
      break;

     case LDAP_MOD_REPLACE:
      ret = read_string(a, tree, hf_ldap_message_modify_replace, &ti, 0, ASN1_UNI, ASN1_OTS);
      if (ret != ASN1_ERR_NOERROR)
        return ret;
      break;

     case LDAP_MOD_DELETE:
      ret = read_string(a, tree, hf_ldap_message_modify_delete, &ti, 0, ASN1_UNI, ASN1_OTS);
      if (ret != ASN1_ERR_NOERROR)
        return ret;
      break;

     default:
       proto_tree_add_text(tree, a->tvb, a->offset, 0,
            "Unknown LDAP modify operation (%u)", operation);
       return ASN1_ERR_NOERROR;
    }
    attr_tree = proto_item_add_subtree(ti, ett_ldap_attribute);

    ret = read_set(a, &set_length);
    if (ret != ASN1_ERR_NOERROR)
      return ret;
    end_of_set = a->offset + set_length;
    while (a->offset < end_of_set) {
      ret = read_string(a, attr_tree, hf_ldap_message_value, 0, 0, ASN1_UNI, ASN1_OTS);
      if (ret != ASN1_ERR_NOERROR)
        return ret;
    }
  }

  return ASN1_ERR_NOERROR;
}

static int dissect_ldap_request_abandon(ASN1_SCK *a, proto_tree *tree,
		int start, guint length)
{
  return read_integer_value(a, tree, hf_ldap_message_abandon_msgid, NULL, NULL,
			    start, length); 
}

static void
dissect_ldap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *ldap_tree = 0, *ti, *msg_tree;
  guint messageLength;
  guint messageId;
  int next_offset;
  guint protocolOpCls, protocolOpCon, protocolOpTag;
  gchar *typestr;
  guint opLen;
  ASN1_SCK a;
  int start;
  gboolean first_time = TRUE;
  int ret;

  asn1_open(&a, tvb, 0);

  while (tvb_reported_length_remaining(tvb, a.offset) > 0)
  {
    int message_id_start;
    int message_id_length;
    int message_start;
    
    /*
     * XXX - should handle the initial sequence specifier split across
     * segment boundaries.
     */
    message_start = a.offset;
    ret = read_sequence(&a, &messageLength);
    if (ret != ASN1_ERR_NOERROR)
    {
      if (first_time)
      {
        if (check_col(pinfo->cinfo, COL_PROTOCOL))
          col_set_str(pinfo->cinfo, COL_PROTOCOL, "LDAP");
        if (check_col(pinfo->cinfo, COL_INFO))
          col_set_str(pinfo->cinfo, COL_INFO, "Invalid LDAP packet");
      }
      if (tree)
      {
        ti = proto_tree_add_item(tree, proto_ldap, tvb, message_start, -1,
			         FALSE);
        ldap_tree = proto_item_add_subtree(ti, ett_ldap);
        proto_tree_add_text(ldap_tree, tvb, message_start, -1,
			    "Invalid LDAP packet");
      }
      break;
    }

    /*
     * Desegmentation check.
     */
    if (ldap_desegment) {
	if (pinfo->can_desegment
	    && messageLength > (guint)tvb_length_remaining(tvb, a.offset)) {
	    /*
	     * This frame doesn't have all of the data for this message,
	     * but we can do reassembly on it.
	     *
	     * Tell the TCP dissector where the data for this message
	     * starts in the data it handed us, and how many more bytes
	     * we need, and return.
	     */
	    pinfo->desegment_offset = message_start;
	    pinfo->desegment_len = messageLength -
	        tvb_length_remaining(tvb, a.offset);
	    return;
	}
    }
    next_offset = a.offset + messageLength;

    if (first_time)
    {
      if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "LDAP");
      if (check_col(pinfo->cinfo, COL_INFO))
        col_clear(pinfo->cinfo, COL_INFO);
    }

    if (tree) 
    {
      ti = proto_tree_add_item(tree, proto_ldap, tvb, message_start,
			       next_offset - message_start, FALSE);
      ldap_tree = proto_item_add_subtree(ti, ett_ldap);
    }

    message_id_start = a.offset;
    ret = read_integer(&a, 0, -1, 0, &messageId, ASN1_INT);
    if (ret != ASN1_ERR_NOERROR)
    {
      if (first_time && check_col(pinfo->cinfo, COL_INFO))
        col_set_str(pinfo->cinfo, COL_INFO, "Invalid LDAP packet (No Message ID)");
      if (ldap_tree)
        proto_tree_add_text(ldap_tree, tvb, message_id_start, 1,
                            "Invalid LDAP packet (No Message ID)");
      break;
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
      first_time = FALSE;
    }

    if (ldap_tree) 
    {
      proto_tree_add_uint_hidden(ldap_tree, hf_ldap_message_id, tvb, message_id_start, message_id_length, messageId);
      proto_tree_add_uint_hidden(ldap_tree, hf_ldap_message_type, tvb,
			         start, a.offset - start, protocolOpTag);
      ti = proto_tree_add_text(ldap_tree, tvb, message_id_start, messageLength, "Message: Id=%u  %s", messageId, typestr);
      msg_tree = proto_item_add_subtree(ti, ett_ldap_message);
      start = a.offset;
      ret = read_length(&a, msg_tree, hf_ldap_message_length, &opLen);
      if (ret != ASN1_ERR_NOERROR) {
        proto_tree_add_text(msg_tree, a.tvb, start, 0,
          "Error parsing length: %s", asn1_err_to_str(ret));
        return;
      }

      if (protocolOpCls != ASN1_APL)
      {
        proto_tree_add_text(msg_tree, a.tvb, a.offset, opLen,
			    "%s", typestr);
        ret = ASN1_ERR_NOERROR;
      }
      else
      {
        switch (protocolOpTag)
        {
         case LDAP_REQ_BIND:
          ret = dissect_ldap_request_bind(&a, msg_tree);
          break;
         case LDAP_REQ_UNBIND:
          /* Nothing to dissect */
	  ret = ASN1_ERR_NOERROR;
          break;
         case LDAP_REQ_SEARCH:
          ret = dissect_ldap_request_search(&a, msg_tree);
          break;
         case LDAP_REQ_MODIFY:
          ret = dissect_ldap_request_modify(&a, msg_tree);
          break;
         case LDAP_REQ_ADD:
          ret = dissect_ldap_request_add(&a, msg_tree);
          break;
         case LDAP_REQ_DELETE:
          ret = dissect_ldap_request_delete(&a, msg_tree, start, opLen);
          break;
         case LDAP_REQ_MODRDN:
          ret = dissect_ldap_request_modifyrdn(&a, msg_tree, opLen);
          break;
         case LDAP_REQ_COMPARE:
          ret = dissect_ldap_request_compare(&a, msg_tree);
          break;
         case LDAP_REQ_ABANDON:
          ret = dissect_ldap_request_abandon(&a, msg_tree, start, opLen);
          break;
         case LDAP_RES_BIND:
          ret = dissect_ldap_response_bind(&a, msg_tree);
          break;
         case LDAP_RES_SEARCH_ENTRY:
          ret = dissect_ldap_response_search_entry(&a, msg_tree);
          break;
         case LDAP_RES_SEARCH_RESULT:
         case LDAP_RES_MODIFY:
         case LDAP_RES_ADD:
         case LDAP_RES_DELETE:
         case LDAP_RES_MODRDN:
         case LDAP_RES_COMPARE:
          ret = dissect_ldap_result(&a, msg_tree);
          break;
         default:
          proto_tree_add_text(msg_tree, a.tvb, a.offset, opLen,
			      "Unknown LDAP operation (%u)", protocolOpTag);
          ret = ASN1_ERR_NOERROR;
          break;
        }
      }

      if (ret != ASN1_ERR_NOERROR) {
        proto_tree_add_text(msg_tree, a.tvb, start, 0,
          "Error parsing message: %s", asn1_err_to_str(ret));
        return;
      }
    }

    /*
     * XXX - what if "a.offset" is past the offset of the next top-level
     * sequence?  Show that as an error?
     */
    a.offset = next_offset;
  }
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
}

void
proto_reg_handoff_ldap(void)
{
  dissector_handle_t ldap_handle;

  ldap_handle = create_dissector_handle(dissect_ldap, proto_ldap);
  dissector_add("tcp.port", TCP_PORT_LDAP, ldap_handle);
}
