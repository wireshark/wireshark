/* packet-aim-admin.c
 * Routines for AIM (OSCAR) dissection, Administration Service
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
 *
 * $Id: packet-aim-admin.c,v 1.2 2004/04/20 04:48:31 guy Exp $
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

#define FAMILY_ADMIN      0x0007

/* Family Admin */
#define FAMILY_ADMIN_ERROR            0x0001
#define FAMILY_ADMIN_ACCNT_INFO_REQ   0x0002
#define FAMILY_ADMIN_ACCNT_INFO_REPL  0x0003
#define FAMILY_ADMIN_INFOCHANGEREQ    0x0004
#define FAMILY_ADMIN_INFOCHANGEREPLY  0x0005
#define FAMILY_ADMIN_ACCT_CFRM_REQ    0x0006
#define FAMILY_ADMIN_ACCT_CFRM_REPL   0x0007
#define FAMILY_ADMIN_DEFAULT          0xffff

static const value_string aim_fnac_family_admin[] = {
  { FAMILY_ADMIN_ERROR, "Error" },
  { FAMILY_ADMIN_ACCNT_INFO_REQ, "Request Account Information" },
  { FAMILY_ADMIN_ACCNT_INFO_REPL, "Requested Account Information" },
  { FAMILY_ADMIN_INFOCHANGEREQ, "Infochange Request" },
  { FAMILY_ADMIN_INFOCHANGEREPLY, "Infochange Reply" },
  { FAMILY_ADMIN_ACCT_CFRM_REQ, "Account Confirm Request" },
  { FAMILY_ADMIN_ACCT_CFRM_REPL, "Account Confirm Reply" },
  { FAMILY_ADMIN_DEFAULT, "Adminstrative Default" },
  { 0, NULL }
};

#define CONFIRM_STATUS_EMAIL_SENT 		 0x00
#define CONFIRM_STATUS_ALREADY_CONFIRMED 0x1E
#define CONFIRM_STATUS_SERVER_ERROR	     0x23

static const value_string confirm_statusses[] = {
	{ CONFIRM_STATUS_EMAIL_SENT, "A confirmation email has been sent" },
	{ CONFIRM_STATUS_ALREADY_CONFIRMED, "Account was already confirmed" },
	{ CONFIRM_STATUS_SERVER_ERROR, "Server couldn't start confirmation process" },
	{ 0, NULL }
};

/* Initialize the protocol and registered fields */
static int proto_aim_admin = -1;
static int hf_admin_acctinfo_code = -1;
static int hf_admin_acctinfo_permissions = -1;
static int hf_admin_acctinfo_tlvcount = -1;
static int hf_admin_confirm_status = -1;

/* Initialize the subtree pointers */
static gint ett_aim_admin          = -1;

static int dissect_aim_admin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	struct aiminfo *aiminfo = pinfo->private_data;
    proto_item *ti = NULL;
    proto_tree *admin_tree = NULL;
	int offset = 0;
                                                                                
    if(tree) {
        ti = proto_tree_add_text(tree, tvb, 0, -1,"AIM Administration Service");
        admin_tree = proto_item_add_subtree(ti, ett_aim_admin);
    }
	
	switch(aiminfo->subtype) {
	case FAMILY_ADMIN_ERROR:
		return dissect_aim_snac_error(tvb, pinfo, 0, admin_tree);
	case FAMILY_ADMIN_ACCNT_INFO_REQ:
		proto_tree_add_item(admin_tree, hf_admin_acctinfo_code, tvb, 0, 2, tvb_get_ntohs(tvb, 0)); 
		proto_tree_add_text(admin_tree, tvb, 2, 2, "Unknown");
		return 4;
		
	case FAMILY_ADMIN_INFOCHANGEREPLY:
    case FAMILY_ADMIN_ACCNT_INFO_REPL:
		{
			guint16 numtlvs, i;
			proto_tree_add_uint(admin_tree, hf_admin_acctinfo_permissions, tvb, offset, 2, tvb_get_ntohs(tvb, offset)); offset+=2;
			numtlvs = tvb_get_ntohs(tvb, offset);
			proto_tree_add_uint(admin_tree, hf_admin_acctinfo_tlvcount, tvb, offset, 2, numtlvs); offset+=2;
			for(i = 0; i < numtlvs; i++) {
				offset = dissect_aim_tlv(tvb, pinfo, offset, admin_tree);
			}
		}
		return offset;
	case FAMILY_ADMIN_INFOCHANGEREQ:
		while(tvb_length_remaining(tvb, offset) > 0) {
			offset = dissect_aim_tlv(tvb, pinfo, offset, admin_tree);
		}
		return offset;
	case FAMILY_ADMIN_ACCT_CFRM_REQ:
		/* No data */
		return 0;
	case FAMILY_ADMIN_ACCT_CFRM_REPL:
		proto_tree_add_uint(admin_tree, hf_admin_confirm_status, tvb, offset, 2, tvb_get_ntohs(tvb, offset)); offset+=2;
		while(tvb_length_remaining(tvb, offset) > 0) {
			offset = dissect_aim_tlv(tvb, pinfo, offset, admin_tree);
		}
		return offset;

	default: return 0;
	}
	return 0;
}

/* Register the protocol with Ethereal */
void
proto_register_aim_admin(void)
{

/* Setup list of header fields */
  static hf_register_info hf[] = {
	  { &hf_admin_acctinfo_code,
		  { "Account Information Request Code", "aim.acctinfo.code", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL },
	  },
	  { &hf_admin_acctinfo_permissions,
		  { "Account Permissions", "aim.acctinfo.permissions", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL },
	  }, 
	  { &hf_admin_acctinfo_tlvcount,
		  { "TLV Count", "aim.acctinfo.tlvcount", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL },
	  },
	  { &hf_admin_confirm_status,
		  { "Confirmation status", "admin.confirm_status", FT_UINT16, BASE_HEX, VALS(confirm_statusses), 0x0, "", HFILL },
																					 },
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_aim_admin,
  };

/* Register the protocol name and description */
  proto_aim_admin = proto_register_protocol("AIM Administrative", "AIM Administration", "aim_admin");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_aim_admin, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aim_admin(void)
{
  dissector_handle_t aim_handle;

  aim_handle = new_create_dissector_handle(dissect_aim_admin, proto_aim_admin);
  dissector_add("aim.family", FAMILY_ADMIN, aim_handle);
  aim_init_family(FAMILY_ADMIN, "Administration", aim_fnac_family_admin);
}
