/* packet-smb-mailslot.c
 * Routines for SMB mailslot packet dissection
 * Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
 *
 * $Id: packet-smb-mailslot.c,v 1.19 2001/11/03 00:58:49 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include "packet-smb-common.h"
#include "packet-smb-mailslot.h"
#include "packet-smb-browse.h"
#include "packet-smb-logon.h"
#include "packet-smb-pipe.h"

static int proto_smb_msp = -1;
static int hf_opcode = -1;
static int hf_priority = -1;
static int hf_class = -1;
static int hf_size = -1;
static int hf_name = -1;

static int ett_smb_msp = -1;

static const value_string opcode_vals[] = {
	{1,	"Write Mail Slot"},
	{0,	NULL}
};

static const value_string class_vals[] = {
	{1,	"Reliable"},
	{2,	"Unreliable & Broadcast"},
	{0,	NULL}
};

/* decode the SMB mail slot protocol */
gboolean
dissect_mailslot_smb(tvbuff_t *setup_tvb, tvbuff_t *tvb, packet_info *pinfo,
		     proto_tree *parent_tree)
{
	struct smb_info *smb_info = pinfo->private_data;
	proto_tree      *tree = 0;
	proto_item      *item;
	tvbuff_t        *next_tvb = NULL;
	guint16         opcode;
	int             offset = 0;
	int             len;

	if (!proto_is_protocol_enabled(proto_smb_msp)) {
		return FALSE;
	}
	pinfo->current_proto = "SMB Mailslot";

	if (check_col(pinfo->fd, COL_PROTOCOL)) {
		col_set_str(pinfo->fd, COL_PROTOCOL, "SMB Mailslot");
	}

	if (smb_info->data_offset < 0) {
		/* Interim reply */
		col_set_str(pinfo->fd, COL_INFO, "Interim reply");
		return TRUE;
	}

	/* do the opcode field */
	opcode = tvb_get_letohs(setup_tvb, offset);

	if (check_col(pinfo->fd, COL_INFO)) {
		  col_add_str(pinfo->fd, COL_INFO,
		      val_to_str(opcode, opcode_vals, "Unknown opcode:0x%04x"));
	}

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, proto_smb_msp, setup_tvb,
			offset, tvb_length_remaining(setup_tvb, offset), FALSE);
		tree = proto_item_add_subtree(item, ett_smb_msp);

		/* opcode */
		proto_tree_add_uint(tree, hf_opcode, setup_tvb, offset, 2,
		    opcode);
		offset += 2;

		/* priority */
		proto_tree_add_item(tree, hf_priority, setup_tvb, offset, 2,
		    TRUE);
		offset += 2;

		/* class */
		proto_tree_add_item(tree, hf_class, setup_tvb, offset, 2, TRUE);
		offset += 2;

		/* size */
		proto_tree_add_item(tree, hf_size, setup_tvb, offset, 2, TRUE);
		offset += 2;

		/* mailslot name */
		len = tvb_strsize(setup_tvb, offset);
		proto_tree_add_item(tree, hf_name, setup_tvb, offset, len,
		    TRUE);
		offset += len;
	}

	/* Quit if we don't have the transaction command name (mailslot path) */
	if (smb_info->trans_cmd == NULL) {
		/* Dump it as data */
		dissect_data(tvb, smb_info->data_offset, pinfo, parent_tree);
		return TRUE;
	}

	/* create new tvb for subdissector */
	next_tvb = tvb_new_subset(tvb, smb_info->data_offset, -1, -1);

	/*** Decide what dissector to call based upon the command value ***/
	if (strcmp(smb_info->trans_cmd, "BROWSE") == 0) {
		if (dissect_mailslot_browse(next_tvb, pinfo, parent_tree))
			return TRUE;
	} else if (strcmp(smb_info->trans_cmd, "LANMAN") == 0) {
		/* Decode a LANMAN browse */
		if (dissect_mailslot_lanman(next_tvb, pinfo, parent_tree))
			return TRUE;
	} else if ((strncmp(smb_info->trans_cmd, "NET", strlen("NET")) == 0) ||
		   (strcmp(smb_info->trans_cmd, "TEMP\\NETLOGON") == 0) ||
		   (strcmp(smb_info->trans_cmd, "MSSP") == 0)) {
/* NOTE: use TEMP\\NETLOGON and MSSP because they seems very common,	*/
/* NOTE: may need a look up list to check for the mailslot names passed	*/
/*		by the logon request packet */
		if (dissect_smb_logon(next_tvb, pinfo, parent_tree))
			return TRUE;
	}
	/* Dump it as data */
	dissect_data(next_tvb, 0, pinfo, parent_tree);
	return TRUE;
}

void
register_proto_smb_mailslot(void)
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
