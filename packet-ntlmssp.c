/* packet-ntlmssp.c
 * Routines for NTLM Secure Service Provider
 * Devin Heitmueller <dheitmueller@netilla.com>
 *
 * $Id: packet-ntlmssp.c,v 1.21 2002/09/11 17:47:32 sharpe Exp $
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

#include <glib.h>
#include <epan/packet.h>

#include "packet-smb-common.h"
#include "asn1.h"		/* XXX - needed for subid_t */
#include "packet-gssapi.h"
#include "packet-frame.h"

/* Message types */

#define NTLMSSP_NEGOTIATE 1
#define NTLMSSP_CHALLENGE 2
#define NTLMSSP_AUTH      3
#define NTLMSSP_UNKNOWN   4

static const value_string ntlmssp_message_types[] = {
  { NTLMSSP_NEGOTIATE, "NTLMSSP_NEGOTIATE" },
  { NTLMSSP_CHALLENGE, "NTLMSSP_CHALLENGE" },
  { NTLMSSP_AUTH, "NTLMSSP_AUTH" },
  { NTLMSSP_UNKNOWN, "NTLMSSP_UNKNOWN" },
  { 0, NULL }
};

/*
 * NTLMSSP negotiation flags
 * Taken from Samba
 */
#define NTLMSSP_NEGOTIATE_UNICODE          0x00000001
#define NTLMSSP_NEGOTIATE_OEM              0x00000002
#define NTLMSSP_REQUEST_TARGET             0x00000004
#define NTLMSSP_NEGOTIATE_00000008         0x00000008
#define NTLMSSP_NEGOTIATE_SIGN             0x00000010
#define NTLMSSP_NEGOTIATE_SEAL             0x00000020
#define NTLMSSP_NEGOTIATE_DATAGRAM_STYLE   0x00000040
#define NTLMSSP_NEGOTIATE_LM_KEY           0x00000080
#define NTLMSSP_NEGOTIATE_NETWARE          0x00000100
#define NTLMSSP_NEGOTIATE_NTLM             0x00000200
#define NTLMSSP_NEGOTIATE_00000400         0x00000400
#define NTLMSSP_NEGOTIATE_00000800         0x00000800
#define NTLMSSP_NEGOTIATE_DOMAIN_SUPPLIED  0x00001000
#define NTLMSSP_NEGOTIATE_WORKSTATION_SUPPLIED 0x00002000
#define NTLMSSP_NEGOTIATE_THIS_IS_LOCAL_CALL  0x00004000
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN      0x00008000
#define NTLMSSP_CHAL_INIT_RESPONSE         0x00010000
#define NTLMSSP_CHAL_ACCEPT_RESPONSE       0x00020000
#define NTLMSSP_CHAL_NON_NT_SESSION_KEY    0x00040000
#define NTLMSSP_NEGOTIATE_NTLM2            0x00080000
#define NTLMSSP_NEGOTIATE_00100000         0x00100000
#define NTLMSSP_NEGOTIATE_00200000         0x00200000
#define NTLMSSP_NEGOTIATE_00400000         0x00400000
#define NTLMSSP_CHAL_TARGET_INFO           0x00800000
#define NTLMSSP_NEGOTIATE_01000000         0x01000000
#define NTLMSSP_NEGOTIATE_02000000         0x02000000
#define NTLMSSP_NEGOTIATE_04000000         0x04000000
#define NTLMSSP_NEGOTIATE_08000000         0x08000000
#define NTLMSSP_NEGOTIATE_10000000         0x10000000
#define NTLMSSP_NEGOTIATE_128              0x20000000
#define NTLMSSP_NEGOTIATE_KEY_EXCH         0x40000000
#define NTLMSSP_NEGOTIATE_80000000         0x80000000


static int proto_ntlmssp = -1;
static int hf_ntlmssp = -1;
static int hf_ntlmssp_auth = -1;
static int hf_ntlmssp_message_type = -1;
static int hf_ntlmssp_negotiate_flags = -1;
static int hf_ntlmssp_negotiate_flags_01 = -1;
static int hf_ntlmssp_negotiate_flags_02 = -1;
static int hf_ntlmssp_negotiate_flags_04 = -1;
static int hf_ntlmssp_negotiate_flags_08 = -1;
static int hf_ntlmssp_negotiate_flags_10 = -1;
static int hf_ntlmssp_negotiate_flags_20 = -1;
static int hf_ntlmssp_negotiate_flags_40 = -1;
static int hf_ntlmssp_negotiate_flags_80 = -1;
static int hf_ntlmssp_negotiate_flags_100 = -1;
static int hf_ntlmssp_negotiate_flags_200 = -1;
static int hf_ntlmssp_negotiate_flags_400 = -1;
static int hf_ntlmssp_negotiate_flags_800 = -1;
static int hf_ntlmssp_negotiate_flags_1000 = -1;
static int hf_ntlmssp_negotiate_flags_2000 = -1;
static int hf_ntlmssp_negotiate_flags_4000 = -1;
static int hf_ntlmssp_negotiate_flags_8000 = -1;
static int hf_ntlmssp_negotiate_flags_10000 = -1;
static int hf_ntlmssp_negotiate_flags_20000 = -1;
static int hf_ntlmssp_negotiate_flags_40000 = -1;
static int hf_ntlmssp_negotiate_flags_80000 = -1;
static int hf_ntlmssp_negotiate_flags_100000 = -1;
static int hf_ntlmssp_negotiate_flags_200000 = -1;
static int hf_ntlmssp_negotiate_flags_400000 = -1;
static int hf_ntlmssp_negotiate_flags_800000 = -1;
static int hf_ntlmssp_negotiate_flags_1000000 = -1;
static int hf_ntlmssp_negotiate_flags_2000000 = -1;
static int hf_ntlmssp_negotiate_flags_4000000 = -1;
static int hf_ntlmssp_negotiate_flags_8000000 = -1;
static int hf_ntlmssp_negotiate_flags_10000000 = -1;
static int hf_ntlmssp_negotiate_flags_20000000 = -1;
static int hf_ntlmssp_negotiate_flags_40000000 = -1;
static int hf_ntlmssp_negotiate_flags_80000000 = -1;
static int hf_ntlmssp_negotiate_workstation_strlen = -1;
static int hf_ntlmssp_negotiate_workstation_maxlen = -1;
static int hf_ntlmssp_negotiate_workstation_buffer = -1;
static int hf_ntlmssp_negotiate_workstation = -1;
static int hf_ntlmssp_negotiate_domain_strlen = -1;
static int hf_ntlmssp_negotiate_domain_maxlen = -1;
static int hf_ntlmssp_negotiate_domain_buffer = -1;
static int hf_ntlmssp_negotiate_domain = -1;
static int hf_ntlmssp_ntlm_challenge = -1;
static int hf_ntlmssp_reserved = -1;
static int hf_ntlmssp_challenge_domain = -1;
static int hf_ntlmssp_auth_username = -1;
static int hf_ntlmssp_auth_domain = -1;
static int hf_ntlmssp_auth_hostname = -1;
static int hf_ntlmssp_auth_lmresponse = -1;
static int hf_ntlmssp_auth_ntresponse = -1;
static int hf_ntlmssp_auth_sesskey = -1;
static int hf_ntlmssp_string_len = -1;
static int hf_ntlmssp_string_maxlen = -1;
static int hf_ntlmssp_string_offset = -1;
static int hf_ntlmssp_blob_len = -1;
static int hf_ntlmssp_blob_maxlen = -1;
static int hf_ntlmssp_blob_offset = -1;
static int hf_ntlmssp_address_list = -1;
static int hf_ntlmssp_address_list_len = -1;
static int hf_ntlmssp_address_list_maxlen = -1;
static int hf_ntlmssp_address_list_offset = -1;
static int hf_ntlmssp_address_list_server_nb = -1;
static int hf_ntlmssp_address_list_domain_nb = -1;
static int hf_ntlmssp_address_list_server_dns = -1;
static int hf_ntlmssp_address_list_domain_dns = -1;

static gint ett_ntlmssp = -1;
static gint ett_ntlmssp_negotiate_flags = -1;
static gint ett_ntlmssp_string = -1;
static gint ett_ntlmssp_blob = -1;
static gint ett_ntlmssp_address_list = -1;

/* dissect a string - header area contains:
     two byte len
     two byte maxlen
     four byte offset of string in data area
  The function returns the offset at the end of the string header,
  but the 'end' parameter returns the offset of the end of the string itself
*/
static int
dissect_ntlmssp_string (tvbuff_t *tvb, int offset,
			proto_tree *ntlmssp_tree, 
			gboolean unicode_strings,
			int string_hf, int *end)
{
  proto_tree *tree = NULL;
  proto_item *tf = NULL;
  gint16 string_length = tvb_get_letohs(tvb, offset);
  gint16 string_maxlen = tvb_get_letohs(tvb, offset+2);
  gint32 string_offset = tvb_get_letohl(tvb, offset+4);
  const char *string_text = NULL;
  int result_length;
  guint16 bc;

  if (0 == string_length) {
    *end = (string_offset > offset+8 ? string_offset : offset+8);
    return offset+8;
  }

  bc = result_length = string_length;
  string_text = get_unicode_or_ascii_string(tvb, &string_offset,
					    unicode_strings, &result_length,
					    FALSE, TRUE, &bc);

  if (ntlmssp_tree) {
    tf = proto_tree_add_string(ntlmssp_tree, string_hf, tvb,
			       string_offset, result_length, string_text);
    tree = proto_item_add_subtree(tf, ett_ntlmssp_string);
  }
  proto_tree_add_uint(tree, hf_ntlmssp_string_len,
		      tvb, offset, 2, string_length);
  offset += 2;
  proto_tree_add_uint(tree, hf_ntlmssp_string_maxlen,
		      tvb, offset, 2, string_maxlen);
  offset += 2;
  proto_tree_add_uint(tree, hf_ntlmssp_string_offset,
		      tvb, offset, 4, string_offset);
  offset += 4;

  *end = string_offset + string_length;
  return offset;
}

/* dissect a generic blowb - header area contains:
     two byte len
     two byte maxlen
     four byte offset of blob in data area
  The function returns the offset at the end of the blob header,
  but the 'end' parameter returns the offset of the end of the blob itself
*/
static int
dissect_ntlmssp_blob (tvbuff_t *tvb, int offset,
		      proto_tree *ntlmssp_tree, 
		      int blob_hf, int *end)
{
  proto_item *tf = NULL;
  proto_tree *tree = NULL;
  gint16 blob_length = tvb_get_letohs(tvb, offset);
  gint16 blob_maxlen = tvb_get_letohs(tvb, offset+2);
  gint32 blob_offset = tvb_get_letohl(tvb, offset+4);

  if (0 == blob_length) {
    *end = (blob_offset > offset+8 ? blob_offset : offset+8);
    return offset+8;
  }

  if (ntlmssp_tree) {
    tf = proto_tree_add_item (ntlmssp_tree, blob_hf, tvb, 
			      blob_offset, blob_length, FALSE);
    tree = proto_item_add_subtree(tf, ett_ntlmssp_blob);
  }
  proto_tree_add_uint(tree, hf_ntlmssp_blob_len,
		      tvb, offset, 2, blob_length);
  offset += 2;
  proto_tree_add_uint(tree, hf_ntlmssp_blob_maxlen,
		      tvb, offset, 2, blob_maxlen);
  offset += 2;
  proto_tree_add_uint(tree, hf_ntlmssp_blob_offset,
		      tvb, offset, 4, blob_offset);
  offset += 4;

  *end = blob_offset + blob_length;
  return offset;
}

static int
dissect_ntlmssp_negotiate_flags (tvbuff_t *tvb, int offset,
				 proto_tree *ntlmssp_tree,
				 guint32 negotiate_flags)
{
  proto_tree *negotiate_flags_tree = NULL;
  proto_item *tf = NULL;

  if (ntlmssp_tree) {
    tf = proto_tree_add_uint (ntlmssp_tree,
			      hf_ntlmssp_negotiate_flags,
			      tvb, offset, 4, negotiate_flags);
    negotiate_flags_tree = proto_item_add_subtree (tf, ett_ntlmssp_negotiate_flags);
  }

  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_80000000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_40000000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_20000000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_10000000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_8000000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_4000000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_2000000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_1000000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_800000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_400000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_200000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_100000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_80000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_40000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_20000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_10000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_8000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_4000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_2000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_1000,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_800,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_400,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_200,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_100,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_80,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_40,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_20,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_10,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_08,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_04,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_02,
			  tvb, offset, 4, negotiate_flags);
  proto_tree_add_boolean (negotiate_flags_tree,
			  hf_ntlmssp_negotiate_flags_01,
			  tvb, offset, 4, negotiate_flags);

  return (offset + 4);
}


static int
dissect_ntlmssp_negotiate (tvbuff_t *tvb, int offset,
			   proto_tree *ntlmssp_tree)
{
  guint32 negotiate_flags;
  int workstation_end;
  int domain_end;

  /* NTLMSSP Negotiate Flags */
  negotiate_flags = tvb_get_letohl (tvb, offset);
  offset = dissect_ntlmssp_negotiate_flags (tvb, offset, ntlmssp_tree,
					    negotiate_flags);

  offset = dissect_ntlmssp_string(tvb, offset, ntlmssp_tree, FALSE, 
				  hf_ntlmssp_negotiate_domain,
				  &workstation_end);
  offset = dissect_ntlmssp_string(tvb, offset, ntlmssp_tree, FALSE, 
				  hf_ntlmssp_negotiate_workstation,
				  &domain_end);

  return MAX(workstation_end, domain_end);
}


static int
dissect_ntlmssp_address_list (tvbuff_t *tvb, int offset, 
			      proto_tree *ntlmssp_tree, 
			      gboolean unicode_strings, int *end)
{
  gint16 list_length = tvb_get_letohs(tvb, offset);
  gint16 list_maxlen = tvb_get_letohs(tvb, offset+2);
  gint32 list_offset = tvb_get_letohl(tvb, offset+4);
  gint16 item_type, item_length;
  int item_offset;
  proto_item *tf = NULL;
  proto_tree *tree = NULL;

  /* the address list is just a blob */
  if (0 == list_length) {
    *end = (list_offset > offset+8 ? list_offset : offset+8);
    return offset+8;
  }

  if (ntlmssp_tree) {
    tf = proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_address_list, tvb, 
			      list_offset, list_length, FALSE);
    tree = proto_item_add_subtree(tf, ett_ntlmssp_address_list);
  }
  proto_tree_add_uint(tree, hf_ntlmssp_address_list_len,
		      tvb, offset, 2, list_length);
  offset += 2;
  proto_tree_add_uint(tree, hf_ntlmssp_address_list_maxlen,
		      tvb, offset, 2, list_maxlen);
  offset += 2;
  proto_tree_add_uint(tree, hf_ntlmssp_address_list_offset,
		      tvb, offset, 4, list_offset);
  offset += 4;

  item_offset = list_offset;
  item_type = tvb_get_letohs(tvb, item_offset);
  item_offset += 2;
  item_length = tvb_get_letohs(tvb, item_offset);
  item_offset += 2;
  while (item_type) {
    guint16 bc;
    int result_length;
    const char *text;
    bc = item_length;
    text = get_unicode_or_ascii_string(tvb, &item_offset,
				       unicode_strings, &result_length,
				       FALSE, FALSE, &bc);

    if (!text) text = ""; /* Make sure we don't blow up below */

    switch(item_type) {
    case 1:
      proto_tree_add_string(tree, hf_ntlmssp_address_list_server_nb,
			    tvb, item_offset, item_length, text);
      break;
    case 2:
      proto_tree_add_string(tree, hf_ntlmssp_address_list_domain_nb,
			    tvb, item_offset, item_length, text);
      break;
    case 3:
      proto_tree_add_string(tree, hf_ntlmssp_address_list_server_dns,
			    tvb, item_offset, item_length, text);
      break;
    case 4:
      proto_tree_add_string(tree, hf_ntlmssp_address_list_domain_dns,
			    tvb, item_offset, item_length, text);
    }

    item_offset += item_length;
    item_type = tvb_get_letohs(tvb, item_offset);
    item_offset += 2;
    item_length = tvb_get_letohs(tvb, item_offset);
    item_offset += 2;
  }

  *end = list_offset + list_length;
  return offset;
}

static int
dissect_ntlmssp_challenge (tvbuff_t *tvb, int offset, proto_tree *ntlmssp_tree)
{
  guint32 negotiate_flags;
  int item_end;
  int data_end = 0;
  gboolean unicode_strings = FALSE;

  /* need to find unicode flag */
  negotiate_flags = tvb_get_letohl (tvb, offset+8);
  if (negotiate_flags && NTLMSSP_NEGOTIATE_UNICODE)
    unicode_strings = TRUE;

  /* Domain name */
  offset = dissect_ntlmssp_string(tvb, offset, ntlmssp_tree, unicode_strings, 
			 hf_ntlmssp_challenge_domain,
			 &item_end);
  data_end = item_end;

  /* NTLMSSP Negotiate Flags */
  offset = dissect_ntlmssp_negotiate_flags (tvb, offset, ntlmssp_tree,
					    negotiate_flags);

  /* NTLMSSP NT Lan Manager Challenge */
  proto_tree_add_item (ntlmssp_tree,
		       hf_ntlmssp_ntlm_challenge,
		       tvb, offset, 8, FALSE);
  offset += 8;

  /* Reserved (function not completely known) */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_reserved,
		       tvb, offset, 8, FALSE);
  offset += 8;

  offset = dissect_ntlmssp_address_list(tvb, offset, ntlmssp_tree, 
					unicode_strings, &item_end);
  data_end = MAX(data_end, item_end);

  return MAX(offset, data_end);
}

static int
dissect_ntlmssp_auth (tvbuff_t *tvb, int offset, proto_tree *ntlmssp_tree)
{
  int item_end;
  int data_end = 0;
  guint32 negotiate_flags;
  gboolean unicode_strings = FALSE;

  negotiate_flags = tvb_get_letohl (tvb, offset+50);
  if (negotiate_flags && NTLMSSP_NEGOTIATE_UNICODE)
    unicode_strings = TRUE;

  /* Lan Manager response */
  offset = dissect_ntlmssp_blob(tvb, offset, ntlmssp_tree,
				hf_ntlmssp_auth_lmresponse,
				&item_end);
  data_end = MAX(data_end, item_end);

  /* NTLM response */
  offset = dissect_ntlmssp_blob(tvb, offset, ntlmssp_tree,
				hf_ntlmssp_auth_ntresponse,
				&item_end);
  data_end = MAX(data_end, item_end);

  /* domain name */
  offset = dissect_ntlmssp_string(tvb, offset, ntlmssp_tree, 
				  unicode_strings, 
				  hf_ntlmssp_auth_domain,
				  &item_end);
  data_end = MAX(data_end, item_end);

  /* user name */
  offset = dissect_ntlmssp_string(tvb, offset, ntlmssp_tree, 
				  unicode_strings, 
				  hf_ntlmssp_auth_username,
				  &item_end);
  data_end = MAX(data_end, item_end);

  /* hostname */
  offset = dissect_ntlmssp_string(tvb, offset, ntlmssp_tree, 
				  unicode_strings, 
				  hf_ntlmssp_auth_hostname,
				  &item_end);
  data_end = MAX(data_end, item_end);

  /* Session Key */
  offset = dissect_ntlmssp_blob(tvb, offset, ntlmssp_tree,
				hf_ntlmssp_auth_sesskey,
				&item_end);
  data_end = MAX(data_end, item_end);

  /* NTLMSSP Negotiate Flags */
  offset = dissect_ntlmssp_negotiate_flags (tvb, offset, ntlmssp_tree,
					    negotiate_flags);

  return MAX(offset, data_end);
}

static void
dissect_ntlmssp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  guint32 ntlmssp_message_type;
  volatile int offset = 0;
  proto_tree *volatile ntlmssp_tree = NULL;
  proto_item *tf = NULL;

  /* Setup a new tree for the NTLMSSP payload */
  if (tree) {
    tf = proto_tree_add_item (tree,
			      hf_ntlmssp,
			      tvb, offset, -1, FALSE);

    ntlmssp_tree = proto_item_add_subtree (tf,
					   ett_ntlmssp);
  }

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
    /* NTLMSSP constant */
    proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_auth,
			 tvb, offset, 8, FALSE);
    offset += 8;

    /* NTLMSSP Message Type */
    proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_message_type,
			 tvb, offset, 4, TRUE);
    ntlmssp_message_type = tvb_get_letohl (tvb, offset);
    offset += 4; 

    /* Call the appropriate dissector based on the Message Type */
    switch (ntlmssp_message_type) {

    case NTLMSSP_NEGOTIATE:
      offset = dissect_ntlmssp_negotiate (tvb, offset, ntlmssp_tree);
      break;

    case NTLMSSP_CHALLENGE:
      offset = dissect_ntlmssp_challenge (tvb, offset, ntlmssp_tree);
      break;

    case NTLMSSP_AUTH:
      offset = dissect_ntlmssp_auth (tvb, offset, ntlmssp_tree);
      break;

    default:
      /* Unrecognized message type */
      proto_tree_add_text (ntlmssp_tree, tvb, offset, -1,
			   "Unrecognized NTLMSSP Message");
      break;
    }
  } CATCH(BoundsError) {
    RETHROW;
  } CATCH(ReportedBoundsError) {
    show_reported_bounds_error(tvb, pinfo, tree);
  } ENDTRY;
}

void
proto_register_ntlmssp(void)
{

  static hf_register_info hf[] = {
    { &hf_ntlmssp,
      { "NTLMSSP", "ntlmssp", FT_NONE, BASE_NONE, NULL, 0x0, "NTLMSSP", HFILL }},

    { &hf_ntlmssp_auth,
      { "NTLMSSP identifier", "ntlmssp.identifier", FT_STRING, BASE_NONE, NULL, 0x0, "NTLMSSP Identifier", HFILL }},

    { &hf_ntlmssp_message_type,
      { "NTLM Message Type", "ntlmssp.messagetype", FT_UINT32, BASE_HEX, VALS(ntlmssp_message_types), 0x0, "", HFILL }},

    { &hf_ntlmssp_negotiate_flags,
      { "Flags", "dcerpc.negotiateflags", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_01,

      { "Negotiate UNICODE", "ntlmssp.negotiateunicode", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_NEGOTIATE_UNICODE, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_02,
      { "Negotiate OEM", "ntlmssp.negotiateoem", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_NEGOTIATE_OEM, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_04,
      { "Request Target", "ntlmssp.requesttarget", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_REQUEST_TARGET, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_08,
      { "Request 0x00000008", "ntlmssp.negotiate00000008", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_NEGOTIATE_00000008, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_10,
      { "Negotiate Sign", "ntlmssp.negotiatesign", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_NEGOTIATE_SIGN, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_20,
      { "Negotiate Seal", "ntlmssp.negotiateseal", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_NEGOTIATE_SEAL, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_40,
      { "Negotiate Datagram Style", "ntlmssp.negotiatedatagramstyle", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_NEGOTIATE_DATAGRAM_STYLE, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_80,
      { "Negotiate Lan Manager Key", "ntlmssp.negotiatelmkey", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_NEGOTIATE_LM_KEY, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_100,
      { "Negotiate Netware", "ntlmssp.negotiatenetware", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_NEGOTIATE_NETWARE, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_200,
      { "Negotiate NTLM key", "ntlmssp.negotiatentlm", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_NEGOTIATE_NTLM, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_400,
      { "Negotiate 0x00000400", "ntlmssp.negotiate00000400", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_NEGOTIATE_00000400, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_800,
      { "Negotiate 0x00000800", "ntlmssp.negotiate00000800", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_NEGOTIATE_00000800, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_1000,
      { "Negotiate Domain Supplied", "ntlmssp.negotiatedomainsupplied", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_NEGOTIATE_DOMAIN_SUPPLIED, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_2000,
      { "Negotiate Workstation Supplied", "ntlmssp.negotiateworkstationsupplied", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_NEGOTIATE_WORKSTATION_SUPPLIED, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_4000,
      { "Negotiate This is Local Call", "ntlmssp.negotiatethisislocalcall", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_NEGOTIATE_THIS_IS_LOCAL_CALL, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_8000,
      { "Negotiate Always Sign", "ntlmssp.negotiatealwayssign", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_NEGOTIATE_ALWAYS_SIGN, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_10000,
      { "Negotiate Challenge Init Response", "ntlmssp.negotiatechallengeinitresponse", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_CHAL_INIT_RESPONSE, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_20000,
      { "Negotiate Challenge Accept Response", "ntlmssp.negotiatechallengeacceptresponse", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_CHAL_ACCEPT_RESPONSE, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_40000,
      { "Negotiate Challenge Non NT Session Key", "ntlmssp.negotiatechallengenonntsessionkey", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_CHAL_NON_NT_SESSION_KEY, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_80000,
      { "Negotiate NTLM2 key", "ntlmssp.negotiatentlm2", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_NEGOTIATE_NTLM2, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_100000,
      { "Negotiate 0x00100000", "ntlmssp.negotiatent00100000", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_NEGOTIATE_00100000, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_200000,
      { "Negotiate 0x00200000", "ntlmssp.negotiatent00200000", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_NEGOTIATE_00200000, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_400000,
      { "Negotiate 0x00400000", "ntlmssp.negotiatent00400000", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_NEGOTIATE_00400000, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_800000,
      { "Negotiate Target Info", "ntlmssp.negotiatetargetinfo", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_CHAL_TARGET_INFO, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_1000000,
      { "Negotiate 0x01000000", "ntlmssp.negotiatent01000000", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_NEGOTIATE_01000000, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_2000000,
      { "Negotiate 0x02000000", "ntlmssp.negotiatent02000000", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_NEGOTIATE_02000000, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_4000000,
      { "Negotiate 0x04000000", "ntlmssp.negotiatent04000000", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_NEGOTIATE_04000000, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_8000000,
      { "Negotiate 0x08000000", "ntlmssp.negotiatent08000000", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_NEGOTIATE_08000000, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_10000000,
      { "Negotiate 0x10000000", "ntlmssp.negotiatent10000000", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_NEGOTIATE_10000000, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_20000000,
      { "Negotiate 128", "ntlmssp.negotiate128", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_NEGOTIATE_128, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_40000000,
      { "Negotiate Key Exchange", "ntlmssp.negotiatekeyexch", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_NEGOTIATE_KEY_EXCH, "", HFILL }},
    { &hf_ntlmssp_negotiate_flags_80000000,
      { "Negotiate 0x80000000", "ntlmssp.negotiatent80000000", FT_BOOLEAN, 32, TFS (&flags_set_truth), NTLMSSP_NEGOTIATE_80000000, "", HFILL }},
    { &hf_ntlmssp_negotiate_workstation_strlen,
      { "Calling workstation name length", "ntlmssp.negotiate.callingworkstation.strlen", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_negotiate_workstation_maxlen,
      { "Calling workstation name max length", "ntlmssp.negotiate.callingworkstation.maxlen", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_negotiate_workstation_buffer,
      { "Calling workstation name buffer", "ntlmssp.negotiate.callingworkstation.buffer", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_negotiate_workstation,
      { "Calling workstation name", "ntlmssp.negotiate.callingworkstation", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_negotiate_domain_strlen,
      { "Calling workstation domain length", "ntlmssp.negotiate.domain.strlen", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_negotiate_domain_maxlen,
      { "Calling workstation domain max length", "ntlmssp.negotiate.domain.maxlen", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_negotiate_domain_buffer,
      { "Calling workstation domain buffer", "ntlmssp.negotiate.domain.buffer", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_negotiate_domain,
      { "Calling workstation domain", "ntlmssp.negotiate.domain", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_ntlm_challenge,
      { "NTLM Challenge", "ntlmssp.ntlmchallenge", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_reserved,
      { "Reserved", "ntlmssp.reserved", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_challenge_domain,
      { "Domain", "ntlmssp.challenge.domain", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_auth_domain,
      { "Domain name", "ntlmssp.auth.domain", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_auth_username,
      { "User name", "ntlmssp.auth.username", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_auth_hostname,
      { "Host name", "ntlmssp.auth.hostname", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_auth_lmresponse,
      { "Lan Manager Response", "ntlmssp.auth.lmresponse", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_auth_ntresponse,
      { "NTLM Response", "ntlmssp.auth.ntresponse", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_auth_sesskey,
      { "Session Key", "ntlmssp.auth.sesskey", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_string_len,
      { "Length", "ntlmssp.string.length", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL}},
    { &hf_ntlmssp_string_maxlen,
      { "Maxlen", "ntlmssp.string.maxlen", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL}},
    { &hf_ntlmssp_string_offset,
      { "Offset", "ntlmssp.string.offset", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL}},
    { &hf_ntlmssp_blob_len,
      { "Length", "ntlmssp.blob.length", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL}},
    { &hf_ntlmssp_blob_maxlen,
      { "Maxlen", "ntlmssp.blob.maxlen", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL}},
    { &hf_ntlmssp_blob_offset,
      { "Offset", "ntlmssp.blob.offset", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL}},
    { &hf_ntlmssp_address_list,
      { "Address List", "ntlmssp.challenge.addresslist", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL}},
    { &hf_ntlmssp_address_list_len,
      { "Length", "ntlmssp.challenge.addresslist.length", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL}},
    { &hf_ntlmssp_address_list_maxlen,
      { "Maxlen", "ntlmssp.challenge.addresslist.maxlen", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL}},
    { &hf_ntlmssp_address_list_offset,
      { "Offset", "ntlmssp.challenge.addresslist.offset", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL}},
    { &hf_ntlmssp_address_list_server_nb,
      { "Server NetBIOS Name", "ntlmssp.challenge.addresslist.servernb", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_address_list_domain_nb,
      { "Domain NetBIOS Name", "ntlmssp.challenge.addresslist.domainnb", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_address_list_server_dns,
      { "Server DNS Name", "ntlmssp.challenge.addresslist.serverdns", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_address_list_domain_dns,
      { "Domain DNS Name", "ntlmssp.challenge.addresslist.domaindns", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }}

  };


  static gint *ett[] = {
    &ett_ntlmssp,
    &ett_ntlmssp_negotiate_flags,
    &ett_ntlmssp_string,
    &ett_ntlmssp_blob,
    &ett_ntlmssp_address_list
  };

  proto_ntlmssp = proto_register_protocol (
					   "NTLM Secure Service Provider", /* name */
					   "NTLMSSP",	/* short name */
					   "ntlmssp"	/* abbrev */
					   );
  proto_register_field_array (proto_ntlmssp, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector("ntlmssp", dissect_ntlmssp, proto_ntlmssp);
}

void
proto_reg_handoff_ntlmssp(void)
{     
  dissector_handle_t ntlmssp_handle;

  /* Register protocol with the GSS-API module */

  ntlmssp_handle = find_dissector("ntlmssp");
  gssapi_init_oid("1.3.6.1.4.1.311.2.2.10", proto_ntlmssp, ett_ntlmssp, 
		  ntlmssp_handle, "NTLMSSP (Microsoft NTLM Security Support Provider)");
}
