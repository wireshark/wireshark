/* packet-ldap.c
 * Routines for ldap packet dissection
 *
 * $Id: packet-ldap.c,v 1.3 2000/03/28 07:12:23 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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
 * It's also missing the substring and extensible search filters.
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
#include "packet.h"

#include "packet-ldap.h"
#include "asn1.h"

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

static value_string msgTypes [] = {
  {LDAP_REQ_BIND, "Bind Request"},
  {LDAP_REQ_UNBIND, "Unbind Request"},
  {LDAP_REQ_UNBIND_30, "Unbind Request"},
  {LDAP_REQ_SEARCH, "Search Request"},
  {LDAP_REQ_MODIFY, "Modify Request"},
  {LDAP_REQ_ADD, "Add Request"},
  {LDAP_REQ_DELETE, "Delete Request"},
  {LDAP_REQ_DELETE_30, "Delete Request"},
  {LDAP_REQ_MODRDN, "Modify RDN Request"},
  {LDAP_REQ_COMPARE, "Compare Request"},
  {LDAP_REQ_ABANDON, "Abandon Request"},
  {LDAP_REQ_ABANDON_30, "Abandon Request"},
    
  {LDAP_RES_BIND, "Bind Result"},
  {LDAP_RES_SEARCH_ENTRY, "Search Entry"},
  {LDAP_RES_SEARCH_RESULT, "Search Result"},
  {LDAP_RES_MODIFY, "Modify Result"},
  {LDAP_RES_ADD, "Add Result"},
  {LDAP_RES_DELETE, "Delete Result"},
  {LDAP_RES_MODRDN, "Modify RDN Result"},
  {LDAP_RES_COMPARE, "Compare Result"}
};

static const char *message_type_str(long messageType)
{
  int count = sizeof(msgTypes) / sizeof(value_string);
  while (count--)
  {
    if (msgTypes[count].value == messageType)
      return msgTypes[count].strptr;
  }
  
  return "Unknown";
}

static int read_length(ASN1_SCK *a, proto_tree *tree, int hf_id, guint *len)
{
  guint length = 0;
  gboolean def = FALSE;
  const guchar *start = a->pointer;
  
  asn1_length_decode(a, &def, &length);

  if (len)
    *len = length;

  if (tree)
    proto_tree_add_item(tree, hf_id, start-a->begin, a->pointer-start, length);

  return 0;
}

static int read_sequence(ASN1_SCK *a, guint *len)
{
  guchar tag = 0;
  guint length = 0;
  gboolean def = FALSE;
  
  asn1_octet_decode(a, &tag);
  if (tag != LBER_SEQUENCE)
    return 1;
  
  asn1_length_decode(a, &def, &length);

  if (len)
    *len = length;
  
  return 0;
}

static int read_set(ASN1_SCK *a, guint *len)
{
  guchar tag = 0;
  guint length = 0;
  gboolean def = FALSE;
  
  asn1_octet_decode(a, &tag);
  if (tag != LBER_SET)
    return 1;
  
  asn1_length_decode(a, &def, &length);

  if (len)
    *len = length;
  
  return 0;
}

static int read_integer(ASN1_SCK *a, proto_tree *tree, int hf_id, proto_tree **new_tree, guint *i, guchar expected_tag)
{
  guint length = 0;
  guint integer = 0;
  guchar tag = 0;
  gboolean def = FALSE;
  const guchar *start = a->pointer;
  
  asn1_octet_decode(a, &tag);
  if (tag != expected_tag)
    return 1;

  asn1_length_decode(a, &def, &length);
  asn1_uint32_value_decode(a, length, &integer);

  if (i)
    *i = integer;

  if (tree)
  {
    proto_tree *temp_tree = 0;
    temp_tree = proto_tree_add_item(tree, hf_id, start-a->begin, a->pointer-start, integer);
    if (new_tree)
      *new_tree = temp_tree;
  }

  return 0;
}

static int read_string(ASN1_SCK *a, proto_tree *tree, int hf_id, proto_tree **new_tree, char **s, guchar expected_tag)
{
  guchar *string;
  guchar tag = 0;
  guint length = 0;
  gboolean def = FALSE;
  const guchar *start = a->pointer;
  
  asn1_octet_decode(a, &tag);
  if (tag != expected_tag)
    return 1;

  asn1_length_decode(a, &def, &length);

  if (length)
  {
    asn1_octet_string_value_decode(a, length, &string);
    string = g_realloc(string, length + 1);
    string[length] = '\0';
  }
  else
    string = "(null)";
    
  if (tree)
  {
    proto_tree *temp_tree;
    temp_tree = proto_tree_add_item(tree, hf_id, start - a->begin, a->pointer - start, string);
    if (new_tree)
      *new_tree = temp_tree;
  }

  if (s && length)
    *s = string;
  else if (length)
    g_free(string);

  return 0;
}

static void parse_filter_strings(ASN1_SCK *a, char **filter, guint *filter_length, const guchar *operation)
{
  guchar *string;
  guchar *string2;
  gint string_length;
  gint string2_length;
  guint string_bytes;

  asn1_octet_string_decode(a, &string, &string_length, &string_bytes);
  asn1_octet_string_decode(a, &string2, &string2_length, &string_bytes);
  *filter_length += 3 + string_length + string2_length;
  *filter = g_realloc(*filter, *filter_length);
  sprintf(*filter + strlen(*filter), "(%.*s%s%.*s)", string_length, string, operation, string2_length, string2);
  g_free(string);
  g_free(string2);
}

static gboolean parse_filter(ASN1_SCK *a, char **filter, guint *filter_length, const guchar **end)
{
  guchar tag;
  guint length;
  gboolean def;

  asn1_octet_decode(a, &tag);
  asn1_length_decode(a, &def, &length);
  
  if (*end == 0)
  {
    *end = a->pointer + length;
    *filter_length = 1;
    *filter = g_malloc0(*filter_length);
  }

  switch (tag)
  {
   case LDAP_FILTER_AND:
    {
      const guchar *add_end = a->pointer + length;
      *filter_length += 3;
      *filter = g_realloc(*filter, *filter_length);
      strcat(*filter, "(&");
      while (!parse_filter(a, filter, filter_length, &add_end))
	continue;
      strcat(*filter, ")");
    }
    break;
   case LDAP_FILTER_OR:
    {
      const guchar *or_end = a->pointer + length;
      *filter_length += 3;
      *filter = g_realloc(*filter, *filter_length);
      strcat(*filter, "(|");
      while (!parse_filter(a, filter, filter_length, &or_end))
	continue;
      strcat(*filter, ")");
    }
    break;
   case LDAP_FILTER_NOT:
    {
      const guchar *not_end = a->pointer + length;
      *filter_length += 3;
      *filter = g_realloc(*filter, *filter_length);
      strcat(*filter, "(!");
      parse_filter(a, filter, filter_length, &not_end);
      strcat(*filter, ")");
    }
    break;
   case LDAP_FILTER_EQUALITY:
    parse_filter_strings(a, filter, filter_length, "=");
    break;
   case LDAP_FILTER_GE:
    parse_filter_strings(a, filter, filter_length, ">=");
    break;
   case LDAP_FILTER_LE:
    parse_filter_strings(a, filter, filter_length, "<=");
    break;
   case LDAP_FILTER_APPROX:
    parse_filter_strings(a, filter, filter_length, "~=");
    break;
   case LDAP_FILTER_PRESENT:
   case LDAP_FILTER_PRESENT_30:
    {
      guchar *string;
      gint string_length;
      guint string_bytes;
    
      asn1_octet_string_decode(a, &string, &string_length, &string_bytes);
      *filter_length += 3 + string_length;
      *filter = g_realloc(*filter, *filter_length);
      sprintf(*filter + strlen(*filter), "(%.*s=*)", string_length, string);
      g_free(string);
    }
    break;
   case LDAP_FILTER_SUBSTRINGS:
    asn1_null_decode(a, length);
    break;
  }
  
  return a->pointer == *end;
}

static int read_filter(ASN1_SCK *a, proto_tree *tree, int hf_id)
{
  const guchar *start = a->pointer;
  char *filter = 0;
  guint filter_length = 0;
  const guchar *end = 0;
     
  while (!parse_filter(a, &filter, &filter_length, &end))
    continue;
  
  if (tree)
    proto_tree_add_item(tree, hf_id, start-a->begin, a->pointer-start, filter);

  g_free(filter);

  return 0;
}

/********************************************************************************************/

static int dissect_ldap_result(ASN1_SCK *a, proto_tree *tree)
{
  guint resultCode = 0;
  
  read_length(a, tree, hf_ldap_message_length, 0);
  read_integer(a, tree, hf_ldap_message_result, 0, &resultCode, LBER_ENUMERATED);
  read_string(a, tree, hf_ldap_message_result_matcheddn, 0, 0, LBER_OCTETSTRING);
  read_string(a, tree, hf_ldap_message_result_errormsg, 0, 0, LBER_OCTETSTRING);

  if (resultCode == 10)		/* Referral */
  {
    const guchar *start = a->pointer;
    const guchar *end;
    guint length;
    proto_tree *t, *referralTree;
    
    read_sequence(a, &length);
    t = proto_tree_add_text(tree, start-a->begin, length, "Referral URLs");
    referralTree = proto_item_add_subtree(t, ett_ldap_referrals);

    end = a->pointer + length;;
    while (a->pointer < end)
      read_string(a, referralTree, hf_ldap_message_result_referral, 0, 0, LBER_OCTETSTRING);
  }
    
  return 0;
}

static int dissect_ldap_request_bind(ASN1_SCK *a, proto_tree *tree)
{
  read_length(a, tree, hf_ldap_message_length, 0);
  read_integer(a, tree, hf_ldap_message_bind_version, 0, 0, LBER_INTEGER);
  read_string(a, tree, hf_ldap_message_bind_dn, 0, 0, LBER_OCTETSTRING);

  switch (*a->pointer)
  {
   case LDAP_AUTH_SIMPLE:
   case LDAP_AUTH_SIMPLE_30:
    proto_tree_add_item(tree, hf_ldap_message_bind_auth, a->pointer-a->begin, 1, *a->pointer);
    read_string(a, tree, hf_ldap_message_bind_auth_password, 0, 0, *a->pointer);
    break;
  }
  
  return 0;
}

static int dissect_ldap_response_bind(ASN1_SCK *a, proto_tree *tree)
{
  dissect_ldap_result(a, tree);
  /* FIXME: handle SASL data */
  return 0;
}

static int dissect_ldap_request_search(ASN1_SCK *a, proto_tree *tree)
{
  guint seq_length;
  const guchar *end;
  
  read_length(a, tree, hf_ldap_message_length, 0);
  read_string(a, tree, hf_ldap_message_search_base, 0, 0, LBER_OCTETSTRING);
  read_integer(a, tree, hf_ldap_message_search_scope, 0, 0, LBER_ENUMERATED);
  read_integer(a, tree, hf_ldap_message_search_deref, 0, 0, LBER_ENUMERATED);
  read_integer(a, tree, hf_ldap_message_search_sizeLimit, 0, 0, LBER_INTEGER);
  read_integer(a, tree, hf_ldap_message_search_timeLimit, 0, 0, LBER_INTEGER);
  read_integer(a, tree, hf_ldap_message_search_typesOnly, 0, 0, LBER_BOOLEAN);
  read_filter(a, tree, hf_ldap_message_search_filter);
  read_sequence(a, &seq_length);
  end = a->pointer + seq_length;
  while (a->pointer < end)
    read_string(a, tree, hf_ldap_message_attribute, 0, 0, LBER_OCTETSTRING);
  return 0;
}

static int dissect_ldap_response_search_entry(ASN1_SCK *a, proto_tree *tree)
{
  guint seq_length;
  const guchar *end_of_sequence;
 
  read_length(a, tree, hf_ldap_message_length, 0);
  read_string(a, tree, hf_ldap_message_dn, 0, 0, LBER_OCTETSTRING);
  read_sequence(a, &seq_length);

  end_of_sequence = a->pointer + seq_length;
  while (a->pointer < end_of_sequence)
  {
    proto_tree *t, *attr_tree;
    guint set_length;
    const guchar *end_of_set;

    read_sequence(a, 0);
    read_string(a, tree, hf_ldap_message_attribute, &t, 0, LBER_OCTETSTRING);
    attr_tree = proto_item_add_subtree(t, ett_ldap_attribute);

    read_set(a, &set_length);
    end_of_set = a->pointer + set_length;
    while (a->pointer < end_of_set)
      read_string(a, attr_tree, hf_ldap_message_value, 0, 0, LBER_OCTETSTRING);
  }

  return 0;
}

static int dissect_ldap_request_add(ASN1_SCK *a, proto_tree *tree)
{
  guint seq_length;
  const guchar *end_of_sequence;
  
  read_length(a, tree, hf_ldap_message_length, 0);
  read_string(a, tree, hf_ldap_message_dn, 0, 0, LBER_OCTETSTRING);

  read_sequence(a, &seq_length);
  end_of_sequence = a->pointer + seq_length;
  while (a->pointer < end_of_sequence)
  {
    proto_tree *t, *attr_tree;
    guint set_length;
    const guchar *end_of_set;

    read_sequence(a, 0);
    read_string(a, tree, hf_ldap_message_attribute, &t, 0, LBER_OCTETSTRING);
    attr_tree = proto_item_add_subtree(t, ett_ldap_attribute);

    read_set(a, &set_length);
    end_of_set = a->pointer + set_length;
    while (a->pointer < end_of_set)
      read_string(a, attr_tree, hf_ldap_message_value, 0, 0, LBER_OCTETSTRING);
  }

  return 0;
}

static int dissect_ldap_request_delete(ASN1_SCK *a, proto_tree *tree)
{
  read_string(a, tree, hf_ldap_message_dn, 0, 0, LDAP_REQ_DELETE);
  return 0;
}

static int dissect_ldap_request_modifyrdn(ASN1_SCK *a, proto_tree *tree)
{
  guint length;
  const guchar *start;

  start = a->pointer;
  read_length(a, tree, hf_ldap_message_length, &length);
  read_string(a, tree, hf_ldap_message_dn, 0, 0, LBER_OCTETSTRING);
  read_string(a, tree, hf_ldap_message_modrdn_name, 0, 0, LBER_OCTETSTRING);
  read_integer(a, tree, hf_ldap_message_modrdn_delete, 0, 0, LBER_BOOLEAN);
  
  if (a->pointer < (start + length))
    read_string(a, tree, hf_ldap_message_modrdn_superior, 0, 0, LBER_OCTETSTRING);

  return 0;
}

static int dissect_ldap_request_compare(ASN1_SCK *a, proto_tree *tree)
{
  const guchar *start;
  int length;
  char *string1 = 0;
  char *string2 = 0;
  char *compare;
  
  read_length(a, tree, hf_ldap_message_length, 0);
  read_string(a, tree, hf_ldap_message_dn, 0, 0, LBER_OCTETSTRING);
  read_sequence(a, 0);

  start = a->pointer;
  read_string(a, 0, -1, 0, &string1, LBER_OCTETSTRING);
  read_string(a, 0, -1, 0, &string2, LBER_OCTETSTRING);

  length = 2 + strlen(string1) + strlen(string2);
  compare = g_malloc0(length);
  snprintf(compare, length, "%s=%s", string1, string2);
  proto_tree_add_item(tree, hf_ldap_message_compare, start-a->begin, a->pointer-start, compare);
  
  g_free(string1);
  g_free(string2);
  g_free(compare);
  
  return 0;
}

static int dissect_ldap_request_modify(ASN1_SCK *a, proto_tree *tree)
{
  guint seq_length;
  const guchar *end_of_sequence;
  
  read_length(a, tree, hf_ldap_message_length, 0);
  read_string(a, tree, hf_ldap_message_dn, 0, 0, LBER_OCTETSTRING);
  read_sequence(a, &seq_length);
  end_of_sequence = a->pointer + seq_length;
  while (a->pointer < end_of_sequence)
  {
    proto_tree *t = 0, *attr_tree;
    guint set_length;
    const guchar *end_of_set;
    guint operation;

    read_sequence(a, 0);
    read_integer(a, 0, -1, 0, &operation, LBER_ENUMERATED);
    read_sequence(a, 0);

    switch (operation)
    {
     case LDAP_MOD_ADD:
      read_string(a, tree, hf_ldap_message_modify_add, &t, 0, LBER_OCTETSTRING);
      break;
     case LDAP_MOD_REPLACE:
      read_string(a, tree, hf_ldap_message_modify_replace, &t, 0, LBER_OCTETSTRING);
      break;
     case LDAP_MOD_DELETE:
      read_string(a, tree, hf_ldap_message_modify_delete, &t, 0, LBER_OCTETSTRING);
      break;
    }
    attr_tree = proto_item_add_subtree(t, ett_ldap_attribute);

    read_set(a, &set_length);
    end_of_set = a->pointer + set_length;
    while (a->pointer < end_of_set)
      read_string(a, attr_tree, hf_ldap_message_value, 0, 0, LBER_OCTETSTRING);
  }

  return 0;
}

static int dissect_ldap_request_abandon(ASN1_SCK *a, proto_tree *tree)
{
  read_integer(a, tree, hf_ldap_message_abandon_msgid, 0, 0, LDAP_REQ_ABANDON);
  return 0;
}

void
dissect_ldap(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
  proto_tree *ldap_tree = 0, *ti, *msg_tree;
  guint messageLength;
  guint messageId;
  guchar messageType;
  ASN1_SCK a;

  if (tree) 
  {
    ti = proto_tree_add_item(tree, proto_ldap, offset, END_OF_FRAME, NULL);
    ldap_tree = proto_item_add_subtree(ti, ett_ldap);
  }

  asn1_open(&a, pd, pi.captured_len);
  a.pointer += offset;

  if (read_sequence(&a, &messageLength))
  {
    if (tree)
      proto_tree_add_text(tree, offset, 1, "Invalid LDAP packet");
    return;
  }

  if (messageLength > (pi.captured_len - offset))
  {
    if (tree)
      proto_tree_add_text(tree, offset, END_OF_FRAME, "Sequence length: %u, LDAP packet data length = %u\n",
			  messageLength, pi.captured_len - offset);
    return;
  }
  
  read_integer(&a, ldap_tree, hf_ldap_message_id, 0, &messageId, LBER_INTEGER);
  asn1_octet_decode(&a, &messageType);
  
  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "LDAP");

  if (check_col(fd, COL_INFO))
    col_add_fstr(fd, COL_INFO, "MsgId=%u MsgType=%s",
		 messageId, message_type_str(messageType));

  if (tree) 
  {
    ti = proto_tree_add_item(ldap_tree, hf_ldap_message_type, a.pointer - a.begin - 1, 1, messageType);
    msg_tree = proto_item_add_subtree(ti, ett_ldap_message);

    switch (messageType)
    {
     case LDAP_REQ_BIND:
      dissect_ldap_request_bind(&a, msg_tree);
      break;
     case LDAP_REQ_SEARCH:
      dissect_ldap_request_search(&a, msg_tree);
      break;
     case LDAP_REQ_ADD:
      dissect_ldap_request_add(&a, msg_tree);
      break;
     case LDAP_REQ_DELETE:
      dissect_ldap_request_delete(&a, msg_tree);
      break;
     case LDAP_REQ_MODRDN:
      dissect_ldap_request_modifyrdn(&a, msg_tree);
      break;
     case LDAP_REQ_COMPARE:
      dissect_ldap_request_compare(&a, msg_tree);
      break;
     case LDAP_REQ_MODIFY:
      dissect_ldap_request_modify(&a, msg_tree);
      break;
     case LDAP_REQ_ABANDON:
      dissect_ldap_request_abandon(&a, msg_tree);
      break;
     case LDAP_RES_BIND:
      dissect_ldap_response_bind(&a, msg_tree);
      break;
     case LDAP_RES_SEARCH_ENTRY:
      dissect_ldap_response_search_entry(&a, msg_tree);
      break;
     case LDAP_RES_SEARCH_RESULT:
     case LDAP_RES_MODIFY:
     case LDAP_RES_ADD:
     case LDAP_RES_DELETE:
     case LDAP_RES_MODRDN:
     case LDAP_RES_COMPARE:
      dissect_ldap_result(&a, msg_tree);
      break;
    }
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
  };

  static value_string auth_types[] = {
    {LDAP_AUTH_NONE, "None"},
    {LDAP_AUTH_SIMPLE, "Simple"},
    {LDAP_AUTH_SIMPLE_30, "Simple"},
    {LDAP_AUTH_KRBV4, "Kerberos"},
    {LDAP_AUTH_KRBV41, "Kerberos V4.1"},
    {LDAP_AUTH_KRBV41_30, "Kerberos V4.1"},
    {LDAP_AUTH_KRBV42, "Kerberos V4.2"},
    {LDAP_AUTH_KRBV42_30, "Kerberos V4.2"},
  };
  
  static value_string search_scope[] = {
    {0x00, "Base"},
    {0x01, "Single"},
    {0x02, "Subtree"},
  };
    
  static value_string search_dereference[] = {
    {0x00, "Never"},
    {0x01, "Searching"},
    {0x02, "Base Object"},
    {0x03, "Always"},
  };
  
  static hf_register_info hf[] = {
    { &hf_ldap_length,
      { "Length",		"ldap.length",
	FT_INT32, BASE_DEC, NULL, 0x0,
	"LDAP Length" }},
	  
    { &hf_ldap_message_id,
      { "Message Id",		"ldap.message_id",
	FT_INT32, BASE_DEC, NULL, 0x0,
	"LDAP Message Id" }},
    { &hf_ldap_message_type,
      { "Message Type",		"ldap.message_type",
	FT_UINT8, BASE_HEX, &msgTypes, 0x0,
	"LDAP Message Type" }},
    { &hf_ldap_message_length,
      { "Message Length",		"ldap.message_length",
	FT_INT32, BASE_DEC, NULL, 0x0,
	"LDAP Message Length" }},

    { &hf_ldap_message_result,
      { "Result Code",		"ldap.result.code",
	FT_INT8, BASE_HEX, result_codes, 0x0,
	"LDAP Result Code" }},
    { &hf_ldap_message_result_matcheddn,
      { "Matched DN",		"ldap.result.matcheddn",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Result Matched DN" }},
    { &hf_ldap_message_result_errormsg,
      { "Error Message",		"ldap.result.errormsg",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Result Error Message" }},
    { &hf_ldap_message_result_referral,
      { "Referral",		"ldap.result.referral",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Result Referral URL" }},

    { &hf_ldap_message_bind_version,
      { "Version",		"ldap.bind.version",
	FT_INT32, BASE_DEC, NULL, 0x0,
	"LDAP Bind Version" }},
    { &hf_ldap_message_bind_dn,
      { "DN",			"ldap.bind.dn",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Bind Distinguished Name" }},
    { &hf_ldap_message_bind_auth,
      { "Auth Type",		"ldap.bind.auth_type",
	FT_INT8, BASE_HEX, auth_types, 0x0,
	"LDAP Bind Auth Type" }},
    { &hf_ldap_message_bind_auth_password,
      { "Password",		"ldap.bind.password",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Bind Password" }},

    { &hf_ldap_message_search_base,
      { "Base DN",		"ldap.search.basedn",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Search Base Distinguished Name" }},
    { &hf_ldap_message_search_scope,
      { "Scope",			"ldap.search.scope",
	FT_UINT8, BASE_HEX, search_scope, 0x0,
	"LDAP Search Scope" }},
    { &hf_ldap_message_search_deref,
      { "Dereference",		"ldap.search.dereference",
	FT_UINT8, BASE_HEX, search_dereference, 0x0,
	"LDAP Search Dereference" }},
    { &hf_ldap_message_search_sizeLimit,
      { "Size Limit",		"ldap.search.sizelimit",
	FT_INT32, BASE_DEC, NULL, 0x0,
	"LDAP Search Size Limit" }},
    { &hf_ldap_message_search_timeLimit,
      { "Time Limit",		"ldap.search.timelimit",
	FT_INT32, BASE_DEC, NULL, 0x0,
	"LDAP Search Time Limit" }},
    { &hf_ldap_message_search_typesOnly,
      { "Attributes Only",	"ldap.search.typesonly",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"LDAP Search Attributes Only" }},
    { &hf_ldap_message_search_filter,
      { "Filter",		"ldap.search.filter",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Search Filter" }},
    { &hf_ldap_message_dn,
      { "Distinguished Name",	"ldap.dn",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Distinguished Name" }},
    { &hf_ldap_message_attribute,
      { "Attribute",		"ldap.attribute",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Attribute" }},
    { &hf_ldap_message_value,
      { "Value",		"ldap.value",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Value" }},

    { &hf_ldap_message_modrdn_name,
      { "New Name",		"ldap.modrdn.name",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP New Name" }},
    { &hf_ldap_message_modrdn_delete,
      { "Delete Values",	"ldap.modrdn.delete",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"LDAP Modify RDN - Delete original values" }},
    { &hf_ldap_message_modrdn_superior,
      { "New Location",		"ldap.modrdn.superior",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Modify RDN - New Location" }},

    { &hf_ldap_message_compare,
      { "Test",		"ldap.compare.test",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Compare Test" }},

    { &hf_ldap_message_modify_add,
      { "Add",			"ldap.modify.add",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Add" }},
    { &hf_ldap_message_modify_replace,
      { "Replace",		"ldap.modify.replace",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Replace" }},
    { &hf_ldap_message_modify_delete,
      { "Delete",		"ldap.modify.delete",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"LDAP Delete" }},

    { &hf_ldap_message_abandon_msgid,
      { "Abandon Msg Id",	"ldap.abandon.msgid",
	FT_INT32, BASE_DEC, NULL, 0x0,
	"LDAP Abandon Msg Id" }},
  };

  static gint *ett[] = {
    &ett_ldap,
    &ett_ldap_message,
    &ett_ldap_referrals,
    &ett_ldap_attribute
  };

  proto_ldap = proto_register_protocol("Lightweight Directory Access Protocol", "ldap");
  proto_register_field_array(proto_ldap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}
