/* packet-ib.c
 * Routines for Interbase dissection
 *
 * Erik Kunze <kunze@philosys.de>
 * Uwe Girlich <Uwe.Girlich@philosys.de>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-x11.c
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

#include <epan/packet.h>

/* Initialize the protocol and registered fields */
static int proto_ib = -1;

static int hf_ib_opcode = -1;

/* Initialize the subtree pointers */
static gint ett_ib = -1;

static dissector_handle_t data_handle;

#define TCP_PORT_IB			3050

/*
 * Round a length to a multiple of 4 bytes.
 */
#define ROUND_LENGTH(n)	((((n) + 3)/4) * 4)


static const value_string names_opcode[] = {
{ 0, "void" },
{ 1, "connect" },
{ 2, "exit" },
{ 3, "accept" },
{ 4, "reject" },
{ 5, "protocol" },
{ 6, "disconnect" },
{ 7, "credit" },
{ 8, "continuation" },
{ 9, "response" },
{ 10, "open file" },
{ 11, "create file" },
{ 12, "close file" },
{ 13, "read page" },
{ 14, "write page" },
{ 15, "lock" },
{ 16, "convert lock" },
{ 17, "release lock" },
{ 18, "blocking" },
{ 19, "attach" },
{ 20, "create" },
{ 21, "detach" },
{ 22, "compile" },
{ 23, "start" },
{ 24, "start and_send" },
{ 25, "send" },
{ 26, "receive" },
{ 27, "unwind" },
{ 28, "release" },
{ 29, "transaction" },
{ 30, "commit" },
{ 31, "rollback" },
{ 32, "prepare" },
{ 33, "reconnect" },
{ 34, "create blob" },
{ 35, "open blob" },
{ 36, "get segment" },
{ 37, "put segment" },
{ 38, "cancel blob" },
{ 39, "close blob" },
{ 40, "info database" },
{ 41, "info request" },
{ 42, "info transaction" },
{ 43, "info blob" },
{ 44, "batch segments" },
{ 45, "mgr set_affinity" },
{ 46, "mgr clear_affinity" },
{ 47, "mgr report" },
{ 48, "que events" },
{ 49, "cancel events" },
{ 50, "commit retaining" },
{ 51, "prepare2" },
{ 52, "event" },
{ 53, "connect request" },
{ 54, "aux connect" },
{ 55, "ddl" },
{ 56, "open blob2" },
{ 57, "create blob2" },
{ 58, "get slice" },
{ 59, "put slice" },
{ 60, "slice" },
{ 61, "seek blob" },
{ 62, "allocate statement" },
{ 63, "execute" },
{ 64, "exec immediate" },
{ 65, "fetch" },
{ 66, "fetch response" },
{ 67, "free statement" },
{ 68, "prepare statement" },
{ 69, "set cursor" },
{ 70, "info sql" },
{ 71, "dummy" },
{ 72, "response piggyback" },
{ 73, "start and_receive" },
{ 74, "start send_and_receive" },
{ 75, "exec immediate2" },
{ 76, "execute2" },
{ 77, "insert" },
{ 78, "sql response" },
{ 79, "transact" },
{ 80, "transact response" },
{ 81, "drop database" },
{ 82, "service attach" },
{ 83, "service detach" },
{ 84, "service info" },
{ 85, "service start" },
{ 86, "rollback retaining" },
{ 0, NULL }
};

static int
dissect_ib(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32		opcode;
	proto_item	*ti = NULL;
	proto_tree	*ib_tree = NULL;
	int		offset;
	tvbuff_t	*next_tvb;

	offset = 0;

	/*
	 * Check that the opcode is one we recognize.
	 */
	if (!tvb_bytes_exist(tvb, offset, 4)) {
		/*
		 * We don't have enough bytes for an opcode.
		 */
		return 0;
	}
	opcode = tvb_get_ntohl(tvb, offset + 0);
	if (match_strval(opcode, names_opcode) == NULL) {
		/*
		 * This isn't an opcode we recognize.
		 */
		return 0;
	}
		
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "IB");
    
	if (check_col(pinfo->cinfo, COL_INFO)) {
		if (pinfo->match_port == pinfo->destport)
			col_set_str(pinfo->cinfo, COL_INFO, "Request");
		else
			col_set_str(pinfo->cinfo, COL_INFO, "Reply");
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_ib, tvb, 0, -1, FALSE);
	}
	if (ti) {
		ib_tree = proto_item_add_subtree(ti, ett_ib);
	}

	if (ib_tree) {
		proto_tree_add_uint(ib_tree,
			hf_ib_opcode, tvb, offset + 0, 4, opcode);
	}
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
				val_to_str(opcode,names_opcode,"%u"));
	}
	offset += 4;

	next_tvb = tvb_new_subset(tvb, offset, -1, -1);

	call_dissector(data_handle, next_tvb, pinfo, ib_tree);
	return tvb_length(tvb);
}

/* Register the protocol with Wireshark */
void proto_register_ib(void)
{                 

/* Setup list of header fields */
      static hf_register_info hf[] = {
		{ &hf_ib_opcode,
		{ "Opcode", "ib.opcode",
		FT_UINT32, BASE_DEC, VALS(names_opcode), 0x0,
		"packet opcode", HFILL }},
      };

/* Setup protocol subtree array */
      static gint *ett[] = {
	    &ett_ib,
      };

/* Register the protocol name and description */
      proto_ib = proto_register_protocol("Interbase", "IB", "ib");

/* Required function calls to register the header fields and subtrees used */
      proto_register_field_array(proto_ib, hf, array_length(hf));
      proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ib(void)
{
  dissector_handle_t ib_handle;

  ib_handle = new_create_dissector_handle(dissect_ib, proto_ib);
  dissector_add("tcp.port", TCP_PORT_IB, ib_handle);
  data_handle = find_dissector("data");
}
