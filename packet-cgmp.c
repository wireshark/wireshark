/* packet-cgmp.c
 * Routines for the disassembly of the Cisco Group Management Protocol
 *
 * $Id: packet-cgmp.c,v 1.3 2000/05/31 05:06:58 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 * 
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
 
#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include "packet.h"

/*
 * See
 *
 * http://www.barnett.sk/software/bbooks/cisco_multicasting_routing/chap04.html
 *
 * for some information on CGMP.
 */

static int proto_cgmp = -1;
static int hf_cgmp_version = -1;
static int hf_cgmp_type = -1;
static int hf_cgmp_count = -1;
static int hf_cgmp_gda = -1;
static int hf_cgmp_usa = -1;

static gint ett_cgmp = -1;

static const value_string type_vals[] = {
	{ 0, "Join" },
	{ 1, "Leave" },
	{ 0, NULL },
};
	
void 
dissect_cgmp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_item *ti; 
	proto_tree *cgmp_tree = NULL;
	guint8 count;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "CGMP");
	if (check_col(fd, COL_INFO))
		col_add_str(fd, COL_INFO, "Cisco Group Management Protocol"); 

	if (tree) {
	        ti = proto_tree_add_item(tree, proto_cgmp, NullTVB, offset, END_OF_FRAME, FALSE);
		cgmp_tree = proto_item_add_subtree(ti, ett_cgmp);
	
		proto_tree_add_uint(cgmp_tree, hf_cgmp_version, NullTVB, offset, 1,
		    pd[offset]);
		proto_tree_add_uint(cgmp_tree, hf_cgmp_type, NullTVB, offset, 1,
		    pd[offset]);
		offset += 1;

		offset += 2;	/* skip reserved field */

		count = pd[offset];
		proto_tree_add_uint(cgmp_tree, hf_cgmp_count, NullTVB, offset, 1,
		    count);
		offset += 1;

		while (count != 0) {
			if (!BYTES_ARE_IN_FRAME(offset, 6))
				break;
			proto_tree_add_ether(cgmp_tree, hf_cgmp_gda, NullTVB, offset, 6,
			    &pd[offset]);
			offset += 6;

			if (!BYTES_ARE_IN_FRAME(offset, 6))
				break;
			proto_tree_add_ether(cgmp_tree, hf_cgmp_usa, NullTVB, offset, 6,
			    &pd[offset]);
			offset += 6;

			count--;
		}
	}
}

void
proto_register_cgmp(void)
{
	static hf_register_info hf[] = {
		{ &hf_cgmp_version,
		{ "Version",	"cgmp.version",	FT_UINT8, BASE_DEC, NULL, 0xF0,
			"" }},

		{ &hf_cgmp_type,
		{ "Type",	"cgmp.type",	FT_UINT8, BASE_DEC, VALS(type_vals), 0x0F,
			"" }},

		{ &hf_cgmp_count,
		{ "Count",	"cgmp.count", FT_UINT8, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_cgmp_gda,
		{ "Group Destination Address",	"cgmp.gda", FT_ETHER, BASE_NONE, NULL, 0x0,
			"Group Destination Address" }},

		{ &hf_cgmp_usa,
		{ "Unicast Source Address",	"cgmp.usa", FT_ETHER, BASE_NONE, NULL, 0x0,
			"Unicast Source Address" }},
        };
	static gint *ett[] = {
		&ett_cgmp,
	};

        proto_cgmp = proto_register_protocol("Cisco Group Management Protocol", "cgmp");
        proto_register_field_array(proto_cgmp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}
