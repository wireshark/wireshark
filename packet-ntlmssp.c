/* packet-ntlmssp.c
 * Routines for NTLM Secure Service Provider
 * Devin Heitmueller <dheitmueller@netilla.com>
 *
 * $Id: packet-ntlmssp.c,v 1.8 2002/08/21 21:25:23 tpot Exp $
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
static int hf_ntlmssp_challenge_unknown1 = -1;
static int hf_ntlmssp_challenge_unknown2 = -1;
static int hf_ntlmssp_auth_lmresponse_strlen = -1;
static int hf_ntlmssp_auth_lmresponse_maxlen = -1;
static int hf_ntlmssp_auth_lmresponse_offset = -1;
static int hf_ntlmssp_auth_ntresponse_strlen = -1;
static int hf_ntlmssp_auth_ntresponse_maxlen = -1;
static int hf_ntlmssp_auth_ntresponse_offset = -1;
static int hf_ntlmssp_auth_domain_strlen = -1;
static int hf_ntlmssp_auth_domain_maxlen = -1;
static int hf_ntlmssp_auth_domain_offset = -1;
static int hf_ntlmssp_auth_username_strlen = -1;
static int hf_ntlmssp_auth_username_maxlen = -1;
static int hf_ntlmssp_auth_username_offset = -1;
static int hf_ntlmssp_auth_hostname_strlen = -1;
static int hf_ntlmssp_auth_hostname_maxlen = -1;
static int hf_ntlmssp_auth_hostname_offset = -1;
static int hf_ntlmssp_auth_unknown1_strlen = -1;
static int hf_ntlmssp_auth_unknown1_maxlen = -1;
static int hf_ntlmssp_auth_unknown1_offset = -1;
static int hf_ntlmssp_auth_username = -1;
static int hf_ntlmssp_auth_domain = -1;
static int hf_ntlmssp_auth_hostname = -1;
static int hf_ntlmssp_auth_lmresponse = -1;
static int hf_ntlmssp_auth_ntresponse = -1;
static int hf_ntlmssp_auth_unknown1 = -1;
static gint ett_ntlmssp = -1;
static gint ett_ntlmssp_negotiate_flags = -1;

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
  guint16 workstation_length;
  guint16 domain_length;

  /* NTLMSSP Negotiate Flags */
  negotiate_flags = tvb_get_letohl (tvb, offset);
  offset = dissect_ntlmssp_negotiate_flags (tvb, offset, ntlmssp_tree,
					    negotiate_flags);

  /* Calling workstation domain name length */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_negotiate_domain_strlen,
		       tvb, offset, 2, TRUE);
  domain_length = tvb_get_letohs (tvb, offset);
  offset += 2;

  /* Calling workstation domain name max length */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_negotiate_domain_maxlen,
		       tvb, offset, 2, TRUE);
  offset += 2;


  /* Calling workstation domain name buffer? */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_negotiate_domain_buffer,
		       tvb, offset, 4, TRUE);
  offset += 4;

  /* Calling workstation name length */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_negotiate_workstation_strlen,
		       tvb, offset, 2, TRUE);
  workstation_length = tvb_get_letohs (tvb, offset);
  offset += 2;

  /* Calling workstation name max length */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_negotiate_workstation_maxlen,
		       tvb, offset, 2, TRUE);
  offset += 2;

  /* Calling workstation name buffer? */
  proto_tree_add_item(ntlmssp_tree, hf_ntlmssp_negotiate_workstation_buffer,
		      tvb, offset, 4, TRUE);
  offset += 4;

  /* Calling workstation name */
  if (workstation_length != 0) {
    proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_negotiate_workstation,
			 tvb, offset, workstation_length, FALSE);
    offset += workstation_length;
  }

  /* Calling domain name */
  if (domain_length != 0) {
    proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_negotiate_domain,
			 tvb, offset, domain_length, FALSE);
    offset += domain_length;
  }

  return offset;
}


static int
dissect_ntlmssp_challenge (tvbuff_t *tvb, int offset, proto_tree *ntlmssp_tree)
{
  guint32 negotiate_flags;

  /* Skip over the two unknown fields */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_challenge_unknown1,
		       tvb, offset, 4, TRUE);
  offset += 4;

  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_challenge_unknown2,
		       tvb, offset, 4, TRUE);
  offset += 4;

  /* NTLMSSP Negotiate Flags */
  negotiate_flags = tvb_get_letohl (tvb, offset);
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

  return offset;
}

static int
dissect_ntlmssp_auth (tvbuff_t *tvb, int offset, proto_tree *ntlmssp_tree)
{
  guint16 lmresponse_length;
  guint16 ntresponse_length;
  guint16 domain_length;
  guint16 username_length;
  guint16 hostname_length;
  guint16 unknown1_length;
  guint32 negotiate_flags;
  const gchar *username;
  const gchar *domain;
  const gchar *hostname;
  int result_length;
  guint16 bc;
  gboolean unicode_strings = FALSE;

  /* Lan Manager response length */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_auth_lmresponse_strlen,
		       tvb, offset, 2, TRUE);
  lmresponse_length = tvb_get_letohs (tvb, offset);
  offset += 2;

  /* Lan Manager response max length */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_auth_lmresponse_maxlen,
		       tvb, offset, 2, TRUE);
  offset += 2;

  /* Lan Manager response offset */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_auth_lmresponse_offset,
		       tvb, offset, 4, TRUE);
  offset += 4;

  /* NTLM response length */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_auth_ntresponse_strlen,
		       tvb, offset, 2, TRUE);
  ntresponse_length = tvb_get_letohs (tvb, offset);
  offset += 2;

  /* NTLM response max length */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_auth_ntresponse_maxlen,
		       tvb, offset, 2, TRUE);
  offset += 2;

  /* NTLM response offset */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_auth_ntresponse_offset,
		       tvb, offset, 4, TRUE);
  offset += 4;

  /* Domain name length */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_auth_domain_strlen,
		       tvb, offset, 2, TRUE);
  domain_length = tvb_get_letohs (tvb, offset);
  offset += 2;

  /* Domain name max length */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_auth_domain_maxlen,
		       tvb, offset, 2, TRUE);
  offset += 2;

  /* Domain name offset */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_auth_domain_offset,
		       tvb, offset, 4, TRUE);
  offset += 4;

  /* Username length */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_auth_username_strlen,
		       tvb, offset, 2, TRUE);
  username_length = tvb_get_letohs (tvb, offset);
  offset += 2;

  /* Username max length */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_auth_username_maxlen,
		       tvb, offset, 2, TRUE);
  offset += 2;

  /* Username offset */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_auth_username_offset,
		       tvb, offset, 4, TRUE);
  offset += 4;

  /* Hostname length */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_auth_hostname_strlen,
		       tvb, offset, 2, TRUE);
  hostname_length = tvb_get_letohs (tvb, offset);
  offset += 2;

  /* Hostname max length */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_auth_hostname_maxlen,
		       tvb, offset, 2, TRUE);
  offset += 2;

  /* Hostname offset */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_auth_hostname_offset,
		       tvb, offset, 4, TRUE);
  offset += 4;

  /* Unknown1 length */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_auth_unknown1_strlen,
		       tvb, offset, 2, TRUE);
  unknown1_length = tvb_get_letohs (tvb, offset);
  offset += 2;

  /* Unknown1 max length */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_auth_unknown1_maxlen,
		       tvb, offset, 2, TRUE);
  offset += 2;

  /* Unknown1 offset */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_auth_unknown1_offset,
		       tvb, offset, 4, TRUE);
  offset += 4;

  /* NTLMSSP Negotiate Flags */
  negotiate_flags = tvb_get_letohl (tvb, offset);
  offset = dissect_ntlmssp_negotiate_flags (tvb, offset, ntlmssp_tree,
					    negotiate_flags);

  if (negotiate_flags && NTLMSSP_NEGOTIATE_UNICODE)
    unicode_strings = TRUE;

  /* Domain name */
  if (domain_length != 0) {
    bc = domain_length;
    domain = get_unicode_or_ascii_string(tvb, &offset,
					 unicode_strings, &result_length,
					 FALSE, FALSE, &bc);
    if (domain == NULL) {
      offset += domain_length;
      return offset;
    }

    proto_tree_add_string(ntlmssp_tree, hf_ntlmssp_auth_domain, tvb, 
			  offset, result_length, domain);
    offset += domain_length;
  }

  /* User name */
  if (username_length != 0) {
    bc = username_length;
    username = get_unicode_or_ascii_string(tvb, &offset,
					   unicode_strings, &result_length,
					   FALSE, FALSE, &bc);
    if (username == NULL) {
      offset += username_length;
      return offset;
    }

    proto_tree_add_string(ntlmssp_tree, hf_ntlmssp_auth_username, tvb, 
			  offset, result_length, username);
    offset += username_length;
  }

  /* Host name */
  if (hostname_length != 0) {
    bc = hostname_length;
    hostname = get_unicode_or_ascii_string(tvb, &offset,
					   unicode_strings, &result_length,
					   FALSE, FALSE, &bc);
    if (hostname == NULL) {
      offset += hostname_length;
      return offset;
    }

    proto_tree_add_string(ntlmssp_tree, hf_ntlmssp_auth_hostname, tvb, 
			  offset, result_length, hostname);
    offset += hostname_length;
  }

  /* Lan Manager Response */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_auth_lmresponse,
		       tvb, offset, lmresponse_length, FALSE);
  offset += lmresponse_length;

  /* NTLM Response */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_auth_ntresponse,
		       tvb, offset, ntresponse_length, FALSE);
  offset += ntresponse_length; 

  /* Unknown1 */
  proto_tree_add_item (ntlmssp_tree, hf_ntlmssp_auth_unknown1,
		       tvb, offset, unknown1_length, FALSE);
  offset += unknown1_length; 

  return offset;
}

static void
dissect_ntlmssp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  guint32 ntlmssp_message_type;
  int offset = 0;
  int payloadsize = 0;
  proto_tree *ntlmssp_tree = NULL;
  proto_item *tf = NULL;

  /* Compute the total size of the data to be parsed */
  payloadsize = tvb_length_remaining(tvb, 0);
  
  /* Setup a new tree for the NTLMSSP payload */
  if (tree) {
    tf = proto_tree_add_item (tree, 
			      hf_ntlmssp,
			      tvb, offset, payloadsize, FALSE);
    
    ntlmssp_tree = proto_item_add_subtree (tf, 
					   ett_ntlmssp);
  }
  
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
    proto_tree_add_text (ntlmssp_tree, tvb, offset, 
			 (payloadsize - 12), 
			 "Unrecognized NTLMSSP Message");
    break;
  }
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
    { &hf_ntlmssp_challenge_unknown1,
      { "Unknown1", "ntlmssp.challenge.unknown1", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_challenge_unknown2,
      { "Unknown2", "ntlmssp.challenge.unknown2", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_auth_lmresponse_strlen,
      { "Lan Manager response length", "ntlmssp.auth.lmresponse.strlen", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_auth_lmresponse_maxlen,
      { "Lan Manager response max length", "ntlmssp.auth.lmresponse.maxlen", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_auth_lmresponse_offset,
      { "Lan Manager response offset", "ntlmssp.auth.lmresponse.offset", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_auth_ntresponse_strlen,
      { "NTLM response length", "ntlmssp.auth.ntresponse.strlen", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_auth_ntresponse_maxlen,
      { "NTLM response max length", "ntlmssp.auth.ntresponse.maxlen", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_auth_ntresponse_offset,
      { "NTLM response offset", "ntlmssp.auth.ntresponse.offset", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_auth_domain_strlen,
      { "Domain name length", "ntlmssp.auth.domain.strlen", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_auth_domain_maxlen,
      { "Domain name max length", "ntlmssp.auth.domain.maxlen", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_auth_domain_offset,
      { "Domain name offset", "ntlmssp.auth.domain.offset", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_auth_username_strlen,
      { "Username length", "ntlmssp.auth.username.strlen", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_auth_username_maxlen,
      { "Username max length", "ntlmssp.auth.username.maxlen", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_auth_username_offset,
      { "Username offset", "ntlmssp.auth.username.offset", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_auth_hostname_strlen,
      { "Hostname length", "ntlmssp.auth.hostname.strlen", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_auth_hostname_maxlen,
      { "Hostname max length", "ntlmssp.auth.hostname.maxlen", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_auth_hostname_offset,
      { "Hostname offset", "ntlmssp.auth.hostname.offset", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_auth_unknown1_strlen,
      { "Unknown1 length", "ntlmssp.auth.unknown1.strlen", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_auth_unknown1_maxlen,
      { "Unknown1 max length", "ntlmssp.auth.unknown1.maxlen", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_ntlmssp_auth_unknown1_offset,
      { "Unknown1 offset", "ntlmssp.auth.unknown1.offset", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
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
    { &hf_ntlmssp_auth_unknown1,
      { "Unknown1", "ntlmssp.auth.unknown1", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL }}
  };


  static gint *ett[] = {
    &ett_ntlmssp,
    &ett_ntlmssp_negotiate_flags,
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
