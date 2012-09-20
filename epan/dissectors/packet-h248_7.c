/*
 *  packet-h248_7.c
 *  H.248.7
 *  Gateway control protocol: Generic Announcement package
 *
 *  (c) 2007, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * $Id$
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
 */

#include "config.h"

#include "packet-h248.h"

#define PNAME  "H.248.7"
#define PSNAME "H248AN"
#define PFNAME "h248.an"

static int proto_h248_an = -1;

static int hf_h248_an_apf = -1;
static int hf_h248_an_apf_an = -1;
static int hf_h248_an_apf_noc = -1;
static int hf_h248_an_apf_av = -1;
static int hf_h248_an_apf_di = -1;

static int hf_h248_an_apv = -1;
static int hf_h248_an_apv_an = -1;
static int hf_h248_an_apv_noc = -1;
static int hf_h248_an_apv_av = -1;
static int hf_h248_an_apv_num = -1;
static int hf_h248_an_apv_spi = -1;
static int hf_h248_an_apv_sp = -1;
static int hf_h248_an_apv_di = -1;

static gint ett_h248_an = -1;
static gint ett_h248_an_apf = -1;
static gint ett_h248_an_apv = -1;

static const value_string h248_an_prop_vals[] = {
	{ 0, "Generic Announcment Package (an) (H.248.7)" },
	{ 0, NULL }
};

static const value_string  h248_an_signals_vals[] = {
	{ 0x0001, "Annoumcement Play Fixed (apf)"},
	{ 0x0002, "Announcement Play Variable (apv)"},
	{0,NULL}
};


static const value_string  h248_an_apf_params_vals[] = {
	{ 0x0001, "Name (an)"},
	{ 0x0002, "Number of Cycles (noc)"},
	{ 0x0003, "Variant (av)"},
	{ 0x0004, "Direction (di)"},
	{0,NULL}
};

static const value_string  h248_an_apv_params_vals[] = {
	{ 0x0001, "Name (an)"},
	{ 0x0002, "Number of Cycles (noc)"},
	{ 0x0003, "Variant (av)"},
	{ 0x0004, "Number (num)"},
	{ 0x0005, "Specific Parameters Interpretation (spi)"},
	{ 0x0006, "Specific Parameters (sp)"},
	{ 0x0007, "Direction (di)"},
	{0,NULL}
};

static const value_string  h248_an_di_vals[] = {
	{ 0x0001, "External (ext)"},
	{ 0x0002, "Internal (int)"},
	{ 0x0003, "Both (both)"},
	{0,NULL}
};




static const h248_pkg_param_t  h248_an_apf_params[] = {
	{ 0x0001, &hf_h248_an_apf_an, h248_param_ber_integer, NULL },
	{ 0x0002, &hf_h248_an_apf_noc, h248_param_ber_integer, NULL },
	{ 0x0003, &hf_h248_an_apf_av, h248_param_ber_octetstring, NULL },
	{ 0x0004, &hf_h248_an_apf_di, h248_param_ber_integer, NULL },
	{ 0, NULL, NULL, NULL}
};

static const h248_pkg_param_t  h248_an_apv_params[] = {
	{ 0x0001, &hf_h248_an_apv_an, h248_param_ber_integer, NULL },
	{ 0x0002, &hf_h248_an_apv_noc, h248_param_ber_integer, NULL },
	{ 0x0003, &hf_h248_an_apv_av, h248_param_ber_octetstring, NULL },
	{ 0x0004, &hf_h248_an_apv_num, h248_param_ber_integer, NULL },
	{ 0x0005, &hf_h248_an_apv_spi, h248_param_ber_integer, NULL },
	{ 0x0006, &hf_h248_an_apv_sp, h248_param_ber_integer, NULL },
	{ 0x0007, &hf_h248_an_apv_di, h248_param_ber_integer, NULL },
	{ 0, NULL, NULL, NULL}
};

static const h248_pkg_sig_t h248_an_signals[] = {
	{ 0x0001, &hf_h248_an_apf, &ett_h248_an_apf, h248_an_apf_params, h248_an_apf_params_vals },
	{ 0x0002, &hf_h248_an_apv, &ett_h248_an_apv, h248_an_apv_params, h248_an_apv_params_vals },
	{ 0, NULL, NULL, NULL, NULL}
};

static const h248_package_t h248_pkg_an = {
	0x001d,
	&proto_h248_an,
	&ett_h248_an,
	h248_an_prop_vals,
	h248_an_signals_vals,
	NULL,
	NULL,
	NULL,					/* Properties	*/
	h248_an_signals,			/* signals		*/
	NULL,					/* events		*/
	NULL					/* statistics	*/
};






void proto_register_h248_7(void) {
	static hf_register_info hf[] = {
		{ &hf_h248_an_apf, { "Fixed Announcement Play", "h248.an.apf", FT_BYTES, BASE_NONE, NULL, 0, "Initiates the play of a fixed announcement", HFILL }},
		{ &hf_h248_an_apf_an, { "Announcement name", "h248.an.apf.an", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_h248_an_apf_noc, { "Number of cycles", "h248.an.apf.noc", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }}, 
		{ &hf_h248_an_apf_av, { "Announcement Variant", "h248.an.apf.av", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_an_apf_di, {"Announcement Direction","h248.an.apf.di",FT_UINT32, BASE_HEX, VALS(h248_an_di_vals), 0, NULL, HFILL}},

		{ &hf_h248_an_apv, { "Fixed Announcement Play", "h248.an.apv", FT_BYTES, BASE_NONE, NULL, 0, "Initiates the play of a fixed announcement", HFILL }},
		{ &hf_h248_an_apv_an, { "Announcement name", "h248.an.apv.an", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_h248_an_apv_noc, { "Number of cycles", "h248.an.apv.noc", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }}, 
		{ &hf_h248_an_apv_av, { "Announcement Variant", "h248.an.apv.av", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_an_apv_num, { "Number", "h248.an.apv.num", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }}, 
		{ &hf_h248_an_apv_spi, { "Specific parameters interpretation", "h248.an.apv.spi", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }}, 
		{ &hf_h248_an_apv_sp, { "Specific parameters", "h248.an.apv.sp", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }}, 
		{ &hf_h248_an_apv_di, {"Announcement Direction","h248.an.apv.di",FT_UINT32, BASE_HEX, VALS(h248_an_di_vals), 0, NULL, HFILL}}
		
		};
	
	static gint *ett[] = {
		&ett_h248_an,
		&ett_h248_an_apf,
		&ett_h248_an_apv
	};

	proto_h248_an = proto_register_protocol(PNAME, PSNAME, PFNAME);

	proto_register_field_array(proto_h248_an, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));
	
	h248_register_package(&h248_pkg_an,REPLACE_PKG);
}


