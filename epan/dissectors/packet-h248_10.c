/*
 *  packet-h248_10.c
 *
 *  H.248.10
 *  Gateway control protocol: Media gateway
 *  resource congestion handling package
 *
 *  (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include "config.h"

#include "packet-h248.h"

void proto_register_h248_dot10(void);

#define PNAME  "H.248.10"
#define PSNAME "H248CHP"
#define PFNAME "h248.chp"

static int proto_h248_CHP = -1;

static int hf_h248_CHP_mgcon = -1;
static int hf_h248_CHP_mgcon_reduction = -1;

static gint ett_h248_CHP = -1;
static gint ett_h248_CHP_mgcon = -1;

static const value_string h248_CHP_prop_vals[] = {
	{ 0, "chp (MG Congestion Handling)" },
	{ 0, NULL }
};

static const value_string h248_CHP_events_vals[] = {
	{1, "MGCon"},
	{ 0, NULL }
};

static const value_string h248_CHP_mgcon_params_vals[] = {
	{1, "reduction"},
	{ 0, NULL }
};


static const h248_pkg_param_t h248_CHP_mgcon_params[] = {
	{ 0x0001, &hf_h248_CHP_mgcon_reduction, h248_param_ber_integer, NULL },
	{ 0, NULL, NULL, NULL}
};


static const h248_pkg_evt_t h248_CHP_mgcon_events[] = {
	{ 0x0001, &hf_h248_CHP_mgcon, &ett_h248_CHP_mgcon, h248_CHP_mgcon_params, h248_CHP_mgcon_params_vals},
	{ 0, NULL, NULL, NULL, NULL}
};

static h248_package_t h248_pkg_CHP = {
	0x0029,
	&proto_h248_CHP,
	&ett_h248_CHP,

	h248_CHP_prop_vals,
	NULL,
	h248_CHP_events_vals,
	NULL,

	NULL,
	NULL,
	h248_CHP_mgcon_events,
	NULL
};

void proto_register_h248_dot10(void) {
	static hf_register_info hf[] = {
		/* H.248.1 E.1  Generic Package */
		{ &hf_h248_CHP_mgcon, { "MGCon", "h248.chp.mgcon", FT_BYTES, BASE_NONE, NULL, 0, "This event occurs when the MG requires that the MGC start or finish load reduction.", HFILL }},
		{ &hf_h248_CHP_mgcon_reduction, { "Reduction", "h248.chp.mgcon.reduction", FT_UINT32, BASE_DEC, NULL, 0, "Percentage of the load that the MGC is requested to block", HFILL }},
	};

	static gint *ett[] = {
		&ett_h248_CHP,
		&ett_h248_CHP_mgcon,
	};

	proto_h248_CHP = proto_register_protocol(PNAME, PSNAME, PFNAME);

	proto_register_field_array(proto_h248_CHP, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));

	h248_register_package(&h248_pkg_CHP,REPLACE_PKG);
}


