/*
 *  packet-h248_3gpp.c
 *  3GPP H.248 Packages
 *
 *  (c) 2006, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.com>
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

#include "packet-h248.h"
#define PNAME  "H.248 3GPP"
#define PSNAME "H2483GPP"
#define PFNAME "h2483gpp"


/* 3GPP TS 29.232 v4.1.0 */
static int hf_h248_package_3GUP = -1;
static int hf_h248_package_3GUP_parameters = -1;

static int hf_h248_package_3GUP_Mode = -1;
static int hf_h248_package_3GUP_UPversions = -1;
static int hf_h248_package_3GUP_delerrsdu = -1;
static int hf_h248_package_3GUP_interface = -1;
static int hf_h248_package_3GUP_initdir = -1;

static gint ett_h248_package_3GUP;

static const value_string h248_3GUP_Mode_vals[] = {
	{   0x00000001, "Transparent mode" },
	{   0x00000002, "Support mode for predefined SDU sizes" },
	{0,     NULL}
};

static const value_string h248_3GUP_upversions_vals[] = {
	{   0x01, "Version 1" },
	{   0x02, "Version 2" },
	{   0x03, "Version 3" },
	{   0x04, "Version 4" },
	{   0x05, "Version 5" },
	{   0x06, "Version 6" },
	{   0x07, "Version 7" },
	{   0x08, "Version 8" },
	{   0x09, "Version 9" },
	{   0x0A, "Version 10" },
	{   0x0B, "Version 11" },
	{   0x0C, "Version 12" },
	{   0x0D, "Version 13" },
	{   0x0E, "Version 14" },
	{   0x0F, "Version 15" },
	{   0x10, "Version 16" },
	{0,     NULL}
};

static const value_string h248_3GUP_delerrsdu_vals[] = {
	{   0x0001, "Yes" },
	{   0x0002, "No" },
	{   0x0003, "Not Applicable" },
	{0,     NULL}
};

static const value_string h248_3GUP_interface_vals[] = {
	{   0x0001, "RAN (Iu interface)" },
	{   0x0002, "CN (Nb interfac)" },
	{0,     NULL}
};

static const value_string h248_3GUP_initdir_vals[] = {
	{   0x0001, "Incoming" },
	{   0x0002, "Outgoing" },
	{0,     NULL}
};

static const value_string h248_3GUP_parameters[] = {
	{   0x0001, "Mode" },
	{   0x0002, "UPversions" },
	{   0x0003, "Delivery of erroneous SDUs" },
	{   0x0004, "Interface" },
	{   0x0005, "Initialisation Direction" },
	{0,     NULL}
};

h248_pkg_param_t h248_package_3GUP_properties[] = {
	{ 0x0001, &hf_h248_package_3GUP_Mode, h248_param_ber_boolean, NULL },
	{ 0x0002, &hf_h248_package_3GUP_UPversions, h248_param_ber_integer, NULL },
	{ 0x0003, &hf_h248_package_3GUP_delerrsdu, h248_param_ber_integer, NULL },
	{ 0x0004, &hf_h248_package_3GUP_interface, h248_param_ber_integer, NULL },
	{ 0x0005, &hf_h248_package_3GUP_initdir, h248_param_ber_integer, NULL },
};

static h248_package_t h248_package_3GUP = {
	0x002f,
	&hf_h248_package_3GUP,
	&hf_h248_package_3GUP_parameters,
	&ett_h248_package_3GUP,
	h248_package_3GUP_properties,
	NULL,
	NULL,
	NULL
};

void proto_register_h248_3gpp(void) {
	static hf_register_info hf[] = {
		{ &hf_h248_package_3GUP_Mode,
		{ "Mode", "h248.package_3GUP.Mode",
			FT_UINT32, BASE_DEC, VALS(h248_3GUP_Mode_vals), 0,
			"Mode", HFILL }},
	{ &hf_h248_package_3GUP_parameters,
	{ "Parameter", "h248.package_3GUP.parameter",
		FT_UINT16, BASE_HEX, VALS(h248_3GUP_parameters), 0,
		"Parameter", HFILL }},
		
		
		{ &hf_h248_package_3GUP_UPversions,
		{ "UPversions", "h248.package_3GUP.upversions",
			FT_UINT32, BASE_DEC, VALS(h248_3GUP_upversions_vals), 0,
			"UPversions", HFILL }},
		{ &hf_h248_package_3GUP_delerrsdu,
		{ "Delivery of erroneous SDUs", "h248.package_3GUP.delerrsdu",
			FT_UINT32, BASE_DEC, VALS(h248_3GUP_delerrsdu_vals), 0,
			"Delivery of erroneous SDUs", HFILL }},
		{ &hf_h248_package_3GUP_interface,
		{ "Interface", "h248.package_3GUP.interface",
			FT_UINT32, BASE_DEC, VALS(h248_3GUP_interface_vals), 0,
			"Interface", HFILL }},
		{ &hf_h248_package_3GUP_initdir,
		{ "Initialisation Direction", "h248.package_3GUP.initdir",
			FT_UINT32, BASE_DEC, VALS(h248_3GUP_initdir_vals), 0,
			"Initialisation Direction", HFILL }},
	};
	
	static gint *ett[] = {
		&ett_h248_package_3GUP
	};
	
	hf_h248_package_3GUP = proto_register_protocol(PNAME, PSNAME, PFNAME);
	
	proto_register_field_array(hf_h248_package_3GUP, hf, array_length(hf));
	
	proto_register_subtree_array(ett, array_length(ett));
	
	h248_register_package(&h248_package_3GUP);
}

void proto_reg_handoff_h248_3gpp(void) {
}





