/* packet-lapd.c
 * Routines for LAPD frame disassembly
 * Gilbert Ramirez <gram@xiexie.org>
 *
 * $Id: packet-lapd.c,v 1.1 1999/11/11 05:36:05 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <stdio.h>
#include <glib.h>
#include <string.h>
#include "packet.h"
#include "xdlc.h"

/* ISDN/LAPD references:
 *
 * http://www.cisco.com/univercd/cc/td/doc/cisintwk/ito_doc/isdn.htm
 * http://www.ece.wpi.edu/courses/ee535/hwk11cd95/agrebe/agrebe.html
 * http://www.acacia-net.com/Clarinet/Protocol/q9213o84.htm
 */

int proto_lapd = -1;
int hf_lapd_address = -1;
int hf_lapd_sapi = -1;
int hf_lapd_cr = -1;
int hf_lapd_ea1 = -1;
int hf_lapd_tei = -1;
int hf_lapd_ea2 = -1;
int hf_lapd_control = -1;

static const value_string lapd_sapi_vals[] = {
	{ 0,	"Q.931 Call control procedure" },
	{ 1,	"Packet mode Q.931 Call control procedure" },
	{ 16,	"X.25 Level 3 procedures" },
	{ 63,	"Layer 2 management procedures" },
	{ 0,	NULL }
};

void
dissect_lapd(const u_char *pd, frame_data *fd, proto_tree *tree)
{
	proto_tree	*lapd_tree, *addr_tree;
	proto_item	*ti;

	guint16	address, cr;

	gboolean is_response;

	if (check_col(fd, COL_PROTOCOL))
	col_add_str(fd, COL_PROTOCOL, "LAPD");

	address = pntohs(&pd[0]);
	cr = address  & 0x0200;

	if (fd->pseudo_header.lapd.from_network_to_user) {
		is_response = cr ? FALSE : TRUE;
		if(check_col(fd, COL_RES_DL_DST))
		    col_add_str(fd, COL_RES_DL_DST, "User");
		if(check_col(fd, COL_RES_DL_SRC))
		    col_add_str(fd, COL_RES_DL_SRC, "Network");
	}
	else {
		is_response = cr ? TRUE : FALSE;
		if(check_col(fd, COL_RES_DL_DST))
			col_add_str(fd, COL_RES_DL_DST, "Network");
		if(check_col(fd, COL_RES_DL_SRC))
			col_add_str(fd, COL_RES_DL_SRC, "User");
	}


	if (tree) {
		ti = proto_tree_add_item(tree, proto_lapd, 0, 3, NULL);
		lapd_tree = proto_item_add_subtree(ti, ETT_LAPD);

		ti = proto_tree_add_item(lapd_tree, hf_lapd_address, 0, 2, address);
		addr_tree = proto_item_add_subtree(ti, ETT_LAPD_ADDRESS);

		proto_tree_add_item(addr_tree, hf_lapd_sapi,	0, 1, address);
		proto_tree_add_item(addr_tree, hf_lapd_cr,	0, 1, address);
		proto_tree_add_item(addr_tree, hf_lapd_ea1,	0, 1, address);
		proto_tree_add_item(addr_tree, hf_lapd_tei,	1, 1, address);
		proto_tree_add_item(addr_tree, hf_lapd_ea2,	1, 1, address);
	}
	else {
		lapd_tree = NULL;
	}

	dissect_xdlc_control(pd, 2, fd, lapd_tree, hf_lapd_control, is_response, TRUE);

	/* call next protocol */
}

void
proto_register_lapd(void)
{
    static hf_register_info hf[] = {
	{ &hf_lapd_address,
	  { "Address Field", "lapd.address", FT_UINT16, BASE_HEX, NULL, 0x0, 
	  	"" }},

	{ &hf_lapd_sapi,
	  { "SAPI", "lapd.sapi", FT_UINT16, BASE_DEC, VALS(lapd_sapi_vals), 0xfc00,
	  	"Service Access Point Identifier" }},

	{ &hf_lapd_cr,
	  { "C/R", "lapd.cr", FT_UINT16, BASE_DEC, NULL, 0x0200,
	  	"Command/Response bit" }},

	{ &hf_lapd_ea1,
	  { "EA1", "lapd.ea1", FT_UINT16, BASE_DEC, NULL, 0x0100,
	  	"First Address Extension bit" }},

	{ &hf_lapd_tei,
	  { "TEI", "lapd.tei", FT_UINT16, BASE_DEC, NULL, 0x00fe,
	  	"Terminal Endpoint Identifier" }},

	{ &hf_lapd_ea2,
	  { "EA2", "lapd.ea2", FT_UINT16, BASE_DEC, NULL, 0x0001,
	  	"Second Address Extension bit" }},

	{ &hf_lapd_control,
	  { "Control Field", "lapd.control", FT_UINT16, BASE_HEX, NULL, 0x0,
	  	"" }},
    };

    proto_lapd = proto_register_protocol ("Link Access Procedure, Channel D (LAPD)", "lapd");
    proto_register_field_array (proto_lapd, hf, array_length(hf));
}
