/*
 *  packet-h248_q1950.c
 *  Q.1950 annex A
 *
 *  (c) 2006, Anders Broman <anders.broman@telia.com>
 *
 * $Id$
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
 *
 * Ref ITU-T Rec. Q.1950 (12/2002)
 */

#include "packet-h248.h"
#include "packet-isup.h"

#define PNAME  "H.248 Q.1950 Annex A"
#define PSNAME "H248Q1950"
#define PFNAME "h248q1950"

static int proto_q1950 = -1;

/* A.3 Bearer characteristics package */
static int hf_h248_pkg_BCP = -1;
static int hf_h248_pkg_BCP_param = -1;
static int hf_h248_pkg_BCP_BNCChar = -1;

static int ett_h248_pkg_BCP = -1;

static const value_string h248_pkg_BCP_parameters[] = {
	{   0x0001, "BNCChar (BNC Characteristics)" },
	{0,     NULL}
};
/* Properties */
h248_pkg_param_t h248_pkg_BCP_props[] = {
	{ 0x0001, &hf_h248_pkg_BCP_BNCChar, h248_param_ber_integer, NULL },
	{ 0, NULL, NULL, NULL}
};

/* Packet defenitions */
static h248_package_t h248_pkg_BCP = {
	0x001e,
	&hf_h248_pkg_BCP,
	&hf_h248_pkg_BCP_param,
	&ett_h248_pkg_BCP,
	h248_pkg_BCP_props,			/* Properties */
	NULL,						/* signals */
	NULL,						/* events */
	NULL						/* statistics */
};

void proto_register_q1950(void) {
	static hf_register_info hf[] = {
		/* A.3 Bearer characteristics package */
		{ &hf_h248_pkg_BCP,
			{ "BCP (Bearer characteristics package)", "h248.pkg.BCP", 
			FT_BYTES, BASE_HEX, NULL, 0, "", HFILL }
		},
		{ &hf_h248_pkg_BCP_param,	
			{ "Parameter", "h248.package_bcp.parameter", 
			FT_UINT16, BASE_HEX, VALS(h248_pkg_BCP_parameters), 0, "Parameter", HFILL }
		},
		{ &hf_h248_pkg_BCP_BNCChar,
			{ "BNCChar (BNC Characteristics)", "h248.pkg.bcp.bncchar", 
			FT_UINT32, BASE_HEX, VALS(bearer_network_connection_characteristics_vals), 0, "BNC Characteristics", HFILL }
		},
	};

	static gint *ett[] = {
		&ett_h248_pkg_BCP
	};
	proto_q1950 = proto_register_protocol(PNAME, PSNAME, PFNAME);

	proto_register_field_array(proto_q1950, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));
	
	h248_register_package(&h248_pkg_BCP);
}

void proto_reg_handoff_q1950(void) {
}
