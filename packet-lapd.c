/* packet-lapd.c
 * Routines for LAPD frame disassembly
 * Gilbert Ramirez <gram@xiexie.org>
 *
 * $Id: packet-lapd.c,v 1.21 2001/05/27 07:27:21 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
#include "packet-q931.h"
#include "xdlc.h"

/* ISDN/LAPD references:
 *
 * http://www.cisco.com/univercd/cc/td/doc/cisintwk/ito_doc/isdn.htm
 * http://www.ece.wpi.edu/courses/ee535/hwk11cd95/agrebe/agrebe.html
 * http://www.acacia-net.com/Clarinet/Protocol/q9213o84.htm
 */

static int proto_lapd = -1;
static int hf_lapd_address = -1;
static int hf_lapd_sapi = -1;
static int hf_lapd_cr = -1;
static int hf_lapd_ea1 = -1;
static int hf_lapd_tei = -1;
static int hf_lapd_ea2 = -1;
static int hf_lapd_control = -1;

static gint ett_lapd = -1;
static gint ett_lapd_address = -1;
static gint ett_lapd_control = -1;

static dissector_handle_t q931_handle;

/*
 * Bits in the address field.
 */
#define	LAPD_SAPI	0xfc00	/* Service Access Point Identifier */
#define	LAPD_SAPI_SHIFT	10
#define	LAPD_CR		0x0200	/* Command/Response bit */
#define	LAPD_EA1	0x0100	/* First Address Extension bit */
#define	LAPD_TEI	0x00fe	/* Terminal Endpoint Identifier */
#define	LAPD_EA2	0x0001	/* Second Address Extension bit */

#define	LAPD_SAPI_Q931		0	/* Q.931 call control procedure */
#define	LAPD_SAPI_PM_Q931	1	/* Packet mode Q.931 call control procedure */
#define	LAPD_SAPI_X25		16	/* X.25 Level 3 procedures */
#define	LAPD_SAPI_L2		63	/* Layer 2 management procedures */

static const value_string lapd_sapi_vals[] = {
	{ LAPD_SAPI_Q931,	"Q.931 Call control procedure" },
	{ LAPD_SAPI_PM_Q931,	"Packet mode Q.931 Call control procedure" },
	{ LAPD_SAPI_X25,	"X.25 Level 3 procedures" },
	{ LAPD_SAPI_L2,		"Layer 2 management procedures" },
	{ 0,			NULL }
};

static void
dissect_lapd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*lapd_tree, *addr_tree;
	proto_item	*ti;
	guint16		control;
	int		lapd_header_len;
	guint16		address, cr, sapi;
	gboolean	is_response;
	tvbuff_t	*next_tvb;

	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "LAPD");
	if (check_col(pinfo->fd, COL_INFO))
		col_clear(pinfo->fd, COL_INFO);

	address = tvb_get_ntohs(tvb, 0);
	cr = address & LAPD_CR;
	sapi = (address & LAPD_SAPI) >> LAPD_SAPI_SHIFT;
	lapd_header_len = 2;	/* address */

	if (pinfo->pseudo_header->p2p.sent) {
		is_response = cr ? TRUE : FALSE;
		if(check_col(pinfo->fd, COL_RES_DL_DST))
			col_set_str(pinfo->fd, COL_RES_DL_DST, "Network");
		if(check_col(pinfo->fd, COL_RES_DL_SRC))
			col_set_str(pinfo->fd, COL_RES_DL_SRC, "User");
	}
	else {
		is_response = cr ? FALSE : TRUE;
		if(check_col(pinfo->fd, COL_RES_DL_DST))
		    col_set_str(pinfo->fd, COL_RES_DL_DST, "User");
		if(check_col(pinfo->fd, COL_RES_DL_SRC))
		    col_set_str(pinfo->fd, COL_RES_DL_SRC, "Network");
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_lapd, tvb, 0, 3, FALSE);
		lapd_tree = proto_item_add_subtree(ti, ett_lapd);

		ti = proto_tree_add_uint(lapd_tree, hf_lapd_address, tvb, 0, 2, address);
		addr_tree = proto_item_add_subtree(ti, ett_lapd_address);

		proto_tree_add_uint(addr_tree, hf_lapd_sapi,tvb, 0, 1, address);
		proto_tree_add_uint(addr_tree, hf_lapd_cr,  tvb, 0, 1, address);
		proto_tree_add_uint(addr_tree, hf_lapd_ea1, tvb, 0, 1, address);
		proto_tree_add_uint(addr_tree, hf_lapd_tei, tvb, 1, 1, address);
		proto_tree_add_uint(addr_tree, hf_lapd_ea2, tvb, 1, 1, address);
	}
	else {
		lapd_tree = NULL;
	}

	control = dissect_xdlc_control(tvb, 2, pinfo, lapd_tree, hf_lapd_control,
	    ett_lapd_control, is_response, TRUE);
	lapd_header_len += XDLC_CONTROL_LEN(control, TRUE);

	next_tvb = tvb_new_subset(tvb, lapd_header_len, -1, -1);
	if (XDLC_IS_INFORMATION(control)) {
		/* call next protocol */
		switch (sapi) {

		case LAPD_SAPI_Q931:
			call_dissector(q931_handle, next_tvb, pinfo, tree);
			break;

		default:
			dissect_data(next_tvb, 0, pinfo, tree);
			break;
		}
	} else
		dissect_data(next_tvb, 0, pinfo, tree);
}

void
proto_register_lapd(void)
{
    static hf_register_info hf[] = {
	{ &hf_lapd_address,
	  { "Address Field", "lapd.address", FT_UINT16, BASE_HEX, NULL, 0x0, 
	  	"Address" }},

	{ &hf_lapd_sapi,
	  { "SAPI", "lapd.sapi", FT_UINT16, BASE_DEC, VALS(lapd_sapi_vals), LAPD_SAPI,
	  	"Service Access Point Identifier" }},

	{ &hf_lapd_cr,
	  { "C/R", "lapd.cr", FT_UINT16, BASE_DEC, NULL, LAPD_CR,
	  	"Command/Response bit" }},

	{ &hf_lapd_ea1,
	  { "EA1", "lapd.ea1", FT_UINT16, BASE_DEC, NULL, LAPD_EA1,
	  	"First Address Extension bit" }},

	{ &hf_lapd_tei,
	  { "TEI", "lapd.tei", FT_UINT16, BASE_DEC, NULL, LAPD_TEI,
	  	"Terminal Endpoint Identifier" }},

	{ &hf_lapd_ea2,
	  { "EA2", "lapd.ea2", FT_UINT16, BASE_DEC, NULL, LAPD_EA2,
	  	"Second Address Extension bit" }},

	{ &hf_lapd_control,
	  { "Control Field", "lapd.control", FT_UINT16, BASE_HEX, NULL, 0x0,
	  	"Control field" }},
    };
    static gint *ett[] = {
        &ett_lapd,
        &ett_lapd_address,
        &ett_lapd_control,
    };

    proto_lapd = proto_register_protocol("Link Access Procedure, Channel D (LAPD)",
					 "LAPD", "lapd");
    proto_register_field_array (proto_lapd, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_lapd(void)
{
	/*
	 * Get handle for the Q.931 dissector.
	 */
	q931_handle = find_dissector("q931");

	dissector_add("wtap_encap", WTAP_ENCAP_LAPD, dissect_lapd, proto_lapd);
}
