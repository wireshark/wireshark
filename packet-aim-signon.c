/* packet-aim-signon.c
 * Routines for AIM Instant Messenger (OSCAR) dissection, SNAC Signon
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
 * Copyright 2000, Ralf Hoelzer <ralf@well.com>
 *
 * $Id: packet-aim-signon.c,v 1.1 2004/03/23 06:21:17 guy Exp $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>

#include "packet-aim.h"

#define FAMILY_SIGNON     0x0017

/* Family Signon */
#define FAMILY_SIGNON_ERROR          0x0001
#define FAMILY_SIGNON_LOGON          0x0002
#define FAMILY_SIGNON_LOGON_REPLY    0x0003
#define FAMILY_SIGNON_UIN_REQ        0x0004
#define FAMILY_SIGNON_UIN_REPL       0x0005
#define FAMILY_SIGNON_SIGNON         0x0006
#define FAMILY_SIGNON_SIGNON_REPLY   0x0007
#define FAMILY_SIGNON_S_SECUREID_REQ 0x000a
#define FAMILY_SIGNON_C_SECUREID_REP 0x000b

static const value_string aim_fnac_family_signon[] = {
  { FAMILY_SIGNON_LOGON, "Logon" },
  { FAMILY_SIGNON_LOGON_REPLY, "Logon Reply" },
  { FAMILY_SIGNON_UIN_REQ, "Request UIN" },
  { FAMILY_SIGNON_UIN_REPL, "New UIN response" },
  { FAMILY_SIGNON_SIGNON, "Sign-on" },
  { FAMILY_SIGNON_SIGNON_REPLY, "Sign-on Reply" },
  { FAMILY_SIGNON_S_SECUREID_REQ, "Server SecureID Request" },
  { FAMILY_SIGNON_C_SECUREID_REP, "Client SecureID Reply" },
  { 0, NULL }
};

static int dissect_aim_snac_signon(tvbuff_t *tvb, packet_info *pinfo, 
				    proto_tree *tree);
static int dissect_aim_snac_signon_logon(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree);
static int dissect_aim_snac_signon_logon_reply(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree);
static int dissect_aim_snac_signon_signon(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree);
static int dissect_aim_snac_signon_signon_reply(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree);

/* Initialize the protocol and registered fields */
static int proto_aim_signon = -1;
static int hf_aim_infotype = -1;
static int hf_aim_signon_challenge_len = -1;
static int hf_aim_signon_challenge = -1;


/* Initialize the subtree pointers */
static gint ett_aim_signon   = -1;

static int dissect_aim_snac_signon(tvbuff_t *tvb, packet_info *pinfo, 
				    proto_tree *tree)
{
	struct aiminfo *aiminfo = pinfo->private_data;
	int offset = 0;
  switch(aiminfo->subtype)
    {
	case FAMILY_SIGNON_ERROR:
      return dissect_aim_snac_error(tvb, pinfo, offset, tree);
    case FAMILY_SIGNON_LOGON:
      return dissect_aim_snac_signon_logon(tvb, pinfo, offset, tree);
    case FAMILY_SIGNON_LOGON_REPLY:
      return dissect_aim_snac_signon_logon_reply(tvb, pinfo, offset, tree);
    case FAMILY_SIGNON_SIGNON:
      return dissect_aim_snac_signon_signon(tvb, pinfo, offset, tree);
    case FAMILY_SIGNON_SIGNON_REPLY:
      return dissect_aim_snac_signon_signon_reply(tvb, pinfo, offset, tree);
	case FAMILY_SIGNON_UIN_REQ:
	case FAMILY_SIGNON_UIN_REPL:
	case FAMILY_SIGNON_S_SECUREID_REQ:
	case FAMILY_SIGNON_C_SECUREID_REP:
	/*FIXME*/	

	default:
	  return 0;
    }
}

static int dissect_aim_snac_signon_logon(tvbuff_t *tvb, packet_info *pinfo, 
					  int offset, proto_tree *tree)
{
  while (tvb_length_remaining(tvb, offset) > 0) {
    offset = dissect_aim_tlv(tvb, pinfo, offset, tree);
  }
  return offset;
}

static int dissect_aim_snac_signon_logon_reply(tvbuff_t *tvb, 
						packet_info *pinfo, 
						int offset, proto_tree *tree)
{
    if (check_col(pinfo->cinfo, COL_INFO)) 
      col_append_fstr(pinfo->cinfo, COL_INFO, ", Login information reply");

    while (tvb_length_remaining(tvb, offset) > 0) {
      offset = dissect_aim_tlv(tvb, pinfo, offset, tree);
    }
	return offset;
}

static int dissect_aim_snac_signon_signon(tvbuff_t *tvb, packet_info *pinfo, 
					   int offset, proto_tree *tree)
{
  guint8 buddyname_length = 0;
  char buddyname[MAX_BUDDYNAME_LENGTH + 1];

  /* Info Type */
  proto_tree_add_item(tree, hf_aim_infotype, tvb, offset, 2, FALSE);
  offset += 2;

  /* Unknown */
  offset += 1;

  /* Buddy Name */
  buddyname_length = aim_get_buddyname( buddyname, tvb, offset, offset + 1 );
  
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_append_fstr(pinfo->cinfo, COL_INFO, " Username: %s", buddyname);
  }
  
  if(tree) {
    proto_tree_add_text(tree, tvb, offset + 1, buddyname_length, 
			"Screen Name: %s", buddyname);
  }
  
  offset += buddyname_length + 1;
  return offset;
}

static int dissect_aim_snac_signon_signon_reply(tvbuff_t *tvb, 
						 packet_info *pinfo, 
						 int offset, proto_tree *tree)
{
  guint16 challenge_length = 0;

  if (check_col(pinfo->cinfo, COL_INFO)) 
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Sign-on reply");

  /* Logon Challenge Length */
  challenge_length = tvb_get_ntohs(tvb, offset);
  proto_tree_add_item(tree, hf_aim_signon_challenge_len, tvb, offset, 2, FALSE);
  offset += 2;

  /* Challenge */
  proto_tree_add_item(tree, hf_aim_signon_challenge, tvb, offset, challenge_length, FALSE);
  offset += challenge_length;
  return offset;
}

/* Register the protocol with Ethereal */
void
proto_register_aim_signon(void)
{

/* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_aim_signon_challenge_len,
      { "Signon challenge length", "aim.signon.challengelen", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_signon_challenge,
      { "Signon challenge", "aim.signon.challenge", FT_STRING, BASE_HEX, NULL, 0x0, "", HFILL }
    },
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_aim_signon,
  };

/* Register the protocol name and description */
  proto_aim_signon = proto_register_protocol("AIM Signon", "AIM Signon", "aim_signon");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_aim_signon, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aim_signon(void)
{
  dissector_handle_t aim_handle;

  aim_handle = new_create_dissector_handle(dissect_aim_snac_signon, proto_aim_signon);
  dissector_add("aim.family", FAMILY_SIGNON, aim_handle);
  aim_init_family(FAMILY_SIGNON, "Signon", aim_fnac_family_signon);
}
