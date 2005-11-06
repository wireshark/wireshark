/* packet-smb2.c
 * Routines for smb2 packet dissection
 *
 * $Id: packet-smb2.c 16113 2005-10-04 10:23:40Z guy $
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

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/tap.h>
#include <epan/emem.h>

#include "packet-dcerpc.h"
#include "packet-ntlmssp.h"



static int proto_smb2 = -1;


static gint ett_smb2 = -1;



static void
dissect_smb2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int offset=0;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)){
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMB2");
	}
	if (check_col(pinfo->cinfo, COL_INFO)){
		col_clear(pinfo->cinfo, COL_INFO);
	}

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, proto_smb2, tvb, offset,
			-1, FALSE);
		tree = proto_item_add_subtree(item, ett_smb2);
	}

	proto_tree_add_text(tree, tvb, offset, 4, "Server Component: SMB2");
	offset += 4;  /* Skip the marker */
}

static gboolean
dissect_smb2_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	/* must check that this really is a smb2 packet */
	if (!tvb_bytes_exist(tvb, 0, 4))
		return FALSE;

	if( (tvb_get_guint8(tvb, 0) != 0xfe)
	    || (tvb_get_guint8(tvb, 1) != 'S')
	    || (tvb_get_guint8(tvb, 2) != 'M')
	    || (tvb_get_guint8(tvb, 3) != 'B') ){
		return FALSE;
	}

	dissect_smb2(tvb, pinfo, parent_tree);
	return TRUE;
}

void
proto_register_smb2(void)
{
	static hf_register_info hf[] = {
	};

	static gint *ett[] = {
		&ett_smb2,
	};

	proto_smb2 = proto_register_protocol("SMB2 (Server Message Block Protocol version 2)",
	    "SMB2", "smb2");
	proto_register_subtree_array(ett, array_length(ett));
	/*proto_register_field_array(proto_smb2, hf, array_length(hf));*/
}

void
proto_reg_handoff_smb2(void)
{
	heur_dissector_add("netbios", dissect_smb2_heur, proto_smb2);
}
