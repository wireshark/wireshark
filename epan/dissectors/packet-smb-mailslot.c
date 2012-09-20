/* packet-smb-mailslot.c
 * Routines for SMB mailslot packet dissection
 * Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/dissectors/packet-smb.h>
#include "packet-smb-mailslot.h"
#include "packet-smb-browse.h"
#include "packet-smb-pipe.h"

static int proto_smb_msp = -1;
static int hf_opcode = -1;
static int hf_priority = -1;
static int hf_class = -1;
static int hf_size = -1;
static int hf_name = -1;

static int ett_smb_msp = -1;

static dissector_handle_t mailslot_browse_handle;
static dissector_handle_t mailslot_lanman_handle;
static dissector_handle_t netlogon_handle;
static dissector_handle_t data_handle;

#define MAILSLOT_UNKNOWN              0
#define MAILSLOT_BROWSE               1
#define MAILSLOT_LANMAN               2
#define MAILSLOT_NET                  3
#define MAILSLOT_TEMP_NETLOGON        4
#define MAILSLOT_MSSP                 5

static const value_string opcode_vals[] = {
	{1,	"Write Mail Slot"},
	{0,	NULL}
};

static const value_string class_vals[] = {
	{1,	"Reliable"},
	{2,	"Unreliable & Broadcast"},
	{0,	NULL}
};

/* decode the SMB mail slot protocol
   for requests
     mailslot is the name of the mailslot, e.g. BROWSE
     si->trans_subcmd is set to the symbolic constant matching the mailslot name.
   for responses
     mailslot is NULL
     si->trans_subcmd gives us which mailslot this response refers to.
*/

gboolean
dissect_mailslot_smb(tvbuff_t *mshdr_tvb, tvbuff_t *setup_tvb,
		     tvbuff_t *tvb, const char *mailslot, packet_info *pinfo,
		     proto_tree *parent_tree)
{
	smb_info_t *smb_info;
	smb_transact_info_t *tri;
	int             trans_subcmd;
	proto_tree      *tree = NULL;
	proto_item      *item = NULL;
	guint16         opcode;
	int             offset = 0;
	int             len;

	if (!proto_is_protocol_enabled(find_protocol_by_id(proto_smb_msp))) {
		return FALSE;
	}
	pinfo->current_proto = "SMB Mailslot";

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMB Mailslot");

	if ((tvb==NULL) || (tvb_reported_length(tvb)==0)) {
		/* Interim reply */
		col_set_str(pinfo->cinfo, COL_INFO, "Interim reply");
		return TRUE;
	}

	col_clear(pinfo->cinfo, COL_INFO);

	smb_info = pinfo->private_data;
	if (smb_info->sip != NULL && smb_info->sip->extra_info_type == SMB_EI_TRI)
		tri = smb_info->sip->extra_info;
	else
		tri = NULL;

	/* check which mailslot this is about */
	trans_subcmd=MAILSLOT_UNKNOWN;
	if(smb_info->request){
		if(strncmp(mailslot,"BROWSE",6) == 0){
	  		trans_subcmd=MAILSLOT_BROWSE;
		} else if(strncmp(mailslot,"LANMAN",6) == 0){
	  		trans_subcmd=MAILSLOT_LANMAN;
		} else if(strncmp(mailslot,"NET",3) == 0){
	  		trans_subcmd=MAILSLOT_NET;
		} else if(strncmp(mailslot,"TEMP\\NETLOGON",13) == 0){
	  		trans_subcmd=MAILSLOT_TEMP_NETLOGON;
		} else if(strncmp(mailslot,"MSSP",4) == 0){
			trans_subcmd=MAILSLOT_MSSP;
		}
		if (!pinfo->fd->flags.visited) {
			if (tri != NULL)
				tri->trans_subcmd = trans_subcmd;
		}
	} else {
		if(!tri){
			return FALSE;
		} else {
			trans_subcmd = tri->trans_subcmd;
		}
	}

	/* Only do these ones if we have them. For fragmented SMB Transactions
	   we may only have the setup area for the first fragment
	*/
	if(mshdr_tvb && setup_tvb){
		if (parent_tree) {
			item = proto_tree_add_item(parent_tree, proto_smb_msp,
						   mshdr_tvb, 0, -1, ENC_NA);
			tree = proto_item_add_subtree(item, ett_smb_msp);
		}

		/* do the opcode field */
		opcode = tvb_get_letohs(setup_tvb, offset);

		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_str(pinfo->cinfo, COL_INFO,
				    val_to_str(opcode, opcode_vals, "Unknown opcode: 0x%04x"));
		}


		/* These are in the setup words; use "setup_tvb". */

		/* opcode */
		proto_tree_add_uint(tree, hf_opcode, setup_tvb, offset, 2,
		    opcode);
		offset += 2;

		/* priority */
		proto_tree_add_item(tree, hf_priority, setup_tvb, offset, 2,
		    ENC_LITTLE_ENDIAN);
		offset += 2;

		/* class */
		proto_tree_add_item(tree, hf_class, setup_tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		/* These are in the rest of the data; use "mshdr_tvb", which
		   starts at the same place "setup_tvb" does. */

		/* size */
		/* this is actually bytecount in the SMB Transaction command */
		proto_tree_add_item(tree, hf_size, mshdr_tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		/* mailslot name */
		len = tvb_strsize(mshdr_tvb, offset);
		proto_tree_add_item(tree, hf_name, mshdr_tvb, offset, len, ENC_ASCII|ENC_NA);
		offset += len;
		proto_item_set_len(item, offset);
	}

	switch(trans_subcmd){
	case MAILSLOT_BROWSE:
		call_dissector(mailslot_browse_handle, tvb, pinfo,
		    parent_tree);
		break;

	case MAILSLOT_LANMAN:
		call_dissector(mailslot_lanman_handle, tvb, pinfo,
		    parent_tree);
		break;

	case MAILSLOT_NET:
	case MAILSLOT_TEMP_NETLOGON:
	case MAILSLOT_MSSP:
		call_dissector(netlogon_handle, tvb, pinfo,
		    parent_tree);
		break;

	default:
		/*
		 * We dissected the mailslot header, but we don't know
		 * how to dissect the message; dissect the latter as data,
		 * but indicate that we successfully dissected the mailslot
		 * stuff.
		 */
		call_dissector(data_handle ,tvb, pinfo, parent_tree);
		break;
	}
	return TRUE;
}

void
proto_register_smb_mailslot(void)
{
	static hf_register_info hf[] = {
		{ &hf_opcode,
			{ "Opcode", "mailslot.opcode", FT_UINT16, BASE_DEC,
			VALS(opcode_vals), 0, "MAILSLOT OpCode", HFILL }},

		{ &hf_priority,
			{ "Priority", "mailslot.priority", FT_UINT16, BASE_DEC,
			NULL, 0, "MAILSLOT Priority of transaction", HFILL }},

		{ &hf_class,
			{ "Class", "mailslot.class", FT_UINT16, BASE_DEC,
			VALS(class_vals), 0, "MAILSLOT Class of transaction", HFILL }},

		{ &hf_size,
			{ "Size", "mailslot.size", FT_UINT16, BASE_DEC,
			NULL, 0, "MAILSLOT Total size of mail data", HFILL }},

		{ &hf_name,
			{ "Mailslot Name", "mailslot.name", FT_STRING, BASE_NONE,
			NULL, 0, "MAILSLOT Name of mailslot", HFILL }},

	};

	static gint *ett[] = {
		&ett_smb_msp
	};

	proto_smb_msp = proto_register_protocol(
		"SMB MailSlot Protocol", "SMB Mailslot", "mailslot");

	proto_register_field_array(proto_smb_msp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_smb_mailslot(void)
{
	mailslot_browse_handle = find_dissector("mailslot_browse");
	mailslot_lanman_handle = find_dissector("mailslot_lanman");
	netlogon_handle = find_dissector("smb_netlogon");
	data_handle = find_dissector("data");
}
