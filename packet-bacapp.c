/* packet-bacapp.c
 * Routines for BACnet (APDU) dissection
 * Copyright 2001, Hartmut Mueller <hartmut@abmlinux.org>, FH Dortmund
 *
 * $Id: packet-bacapp.c,v 1.5 2001/11/26 01:03:35 hagbard Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer,v 1.23
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include "packet.h"

static const char*
bacapp_type_name (guint8 bacapp_type){
  static const char *type_names[] = {
	"Confirmed-Request-PDU",
	"Unconfirmed-Request-PDU",
	"SimpleACK-PDU",
	"ComplexACK-PDU",
	"SegmentACK-PDU",
	"Error-PDU",
	"Reject-PDU",
	"Abort-PDU"
	};
        return (bacapp_type > 7)? "unknown PDU" : type_names[bacapp_type];
}

static int proto_bacapp = -1;
static int hf_bacapp_type = -1;

static gint ett_bacapp = -1;

static dissector_handle_t data_handle;

static void
dissect_bacapp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *bacapp_tree;
	guint8 offset;
	guint8 bacapp_type;
	tvbuff_t *next_tvb;

	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "BACnet-APDU");
	if (check_col(pinfo->fd, COL_INFO))
		col_add_str(pinfo->fd, COL_INFO, "BACnet APDU ");

	offset  = 0;
	bacapp_type = (tvb_get_guint8(tvb, offset) >> 4) & 0x0f;

	if (check_col(pinfo->fd, COL_INFO))
		col_append_fstr(pinfo->fd, COL_INFO, "(%s)",
		bacapp_type_name(bacapp_type));
	if (tree) {
		ti = proto_tree_add_item(tree, proto_bacapp, tvb, offset, tvb_length(tvb), FALSE);

		bacapp_tree = proto_item_add_subtree(ti, ett_bacapp);

		proto_tree_add_uint_format(bacapp_tree, hf_bacapp_type, tvb, 
			offset, 1, bacapp_type, "APDU Type: %u (%s)", bacapp_type,
				bacapp_type_name(bacapp_type));
		offset ++;

	}
	next_tvb = tvb_new_subset(tvb,offset,-1,-1);
	call_dissector(data_handle,next_tvb, pinfo, tree);
}


void
proto_register_bacapp(void)
{
	static hf_register_info hf[] = {
		{ &hf_bacapp_type,
			{ "APDU Type",           "bacapp.bacapp_type",
			FT_UINT8, BASE_DEC, NULL, 0xf0, "APDU Type", HFILL }
		},
	};
	static gint *ett[] = {
		&ett_bacapp,
	};
	proto_bacapp = proto_register_protocol("Building Automation and Control Network APDU",
	    "BACapp", "bacapp");
	proto_register_field_array(proto_bacapp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}
void
proto_reg_handoff_bacapp(void)
{
	dissector_add("bacnet_control_net", 0, dissect_bacapp, proto_bacapp);
	data_handle = find_dissector("data");
}
