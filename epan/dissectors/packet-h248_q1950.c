/*
 *  packet-h248_q1950.c
 *  Q.1950 annex A
 *
 *  (c) 2006, Anders Broman <anders.broman@telia.com>
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


/* A.8 Basic call progress tones generator with directionality */
static int hf_h248_pkg_bcg = -1;
static int hf_h248_pkg_bcg_sig_bdt_par_btd = -1;
static int hf_h248_pkg_bcg_sig_bdt = -1;
static int hf_h248_pkg_bcg_sig_brt = -1;
static int hf_h248_pkg_bcg_sig_bbt = -1;
static int hf_h248_pkg_bcg_sig_bct = -1;
static int hf_h248_pkg_bcg_sig_bsit = -1;
static int hf_h248_pkg_bcg_sig_bwt = -1;
static int hf_h248_pkg_bcg_sig_bpt = -1;
static int hf_h248_pkg_bcg_sig_bcw = -1;
static int hf_h248_pkg_bcg_sig_bcr = -1;
static int hf_h248_pkg_bcg_sig_bpy = -1;

static int ett_h248_pkg_bcg = -1;
static int ett_h248_pkg_bcg_sig_bdt = -1;

static const value_string h248_pkg_bcg_sig_bdt_par_btd_vals[] = {
	{   0x0001, "ext (External)" },
	{   0x0002, "int (Internal)" },
	{   0x0003, "both (Both)" },
	{0,     NULL},
};

static h248_pkg_param_t  h248_pkg_h248_pkg_bcg_sig_bdt_params[] = {
	{ 0x0001, &hf_h248_pkg_bcg_sig_bdt_par_btd, h248_param_ber_integer, NULL },
	{ 0, NULL, NULL, NULL}
};

static h248_pkg_sig_t h248_pkg_bcg_signals[] = {
	/* All the tones have the same parameters */
	{ 0x0040, &hf_h248_pkg_bcg_sig_bdt, &ett_h248_pkg_bcg_sig_bdt, h248_pkg_h248_pkg_bcg_sig_bdt_params },
	{ 0x0041, &hf_h248_pkg_bcg_sig_brt, &ett_h248_pkg_bcg_sig_bdt, h248_pkg_h248_pkg_bcg_sig_bdt_params },
	{ 0x0042, &hf_h248_pkg_bcg_sig_bbt, &ett_h248_pkg_bcg_sig_bdt, h248_pkg_h248_pkg_bcg_sig_bdt_params },
	{ 0x0043, &hf_h248_pkg_bcg_sig_bct, &ett_h248_pkg_bcg_sig_bdt, h248_pkg_h248_pkg_bcg_sig_bdt_params },
	{ 0x0044, &hf_h248_pkg_bcg_sig_bsit, &ett_h248_pkg_bcg_sig_bdt, h248_pkg_h248_pkg_bcg_sig_bdt_params },
	{ 0x0045, &hf_h248_pkg_bcg_sig_bwt, &ett_h248_pkg_bcg_sig_bdt, h248_pkg_h248_pkg_bcg_sig_bdt_params },
	{ 0x0046, &hf_h248_pkg_bcg_sig_bpt, &ett_h248_pkg_bcg_sig_bdt, h248_pkg_h248_pkg_bcg_sig_bdt_params },
	{ 0x0047, &hf_h248_pkg_bcg_sig_bcw, &ett_h248_pkg_bcg_sig_bdt, h248_pkg_h248_pkg_bcg_sig_bdt_params },
	{ 0x0048, &hf_h248_pkg_bcg_sig_bcr, &ett_h248_pkg_bcg_sig_bdt, h248_pkg_h248_pkg_bcg_sig_bdt_params },
	{ 0x0049, &hf_h248_pkg_bcg_sig_bpy, &ett_h248_pkg_bcg_sig_bdt, h248_pkg_h248_pkg_bcg_sig_bdt_params },
	{ 0, NULL, NULL, NULL}
};

/* Packet defenitions */
static h248_package_t h248_pkg_bcg = {
	0x0023,
	&hf_h248_pkg_bcg,
	NULL,
	&ett_h248_pkg_bcg,
	NULL,						/* Properties */
	h248_pkg_bcg_signals,		/* signals */
	NULL,						/* events */
	NULL						/* statistics */
};

/* Register dissector */
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
		/* A.8 Basic call progress tones generator with directionality */
		{ &hf_h248_pkg_bcg,
			{ "bcg (Basic call progress tones generator with directionality)", "h248.pkg.bcg", 
			FT_BYTES, BASE_HEX, NULL, 0, "", HFILL }
		},
		{ &hf_h248_pkg_bcg_sig_bdt_par_btd,
			{ "btd (Tone Direction)", "h248.pkg.bcp.btd", 
			FT_UINT32, BASE_HEX, VALS(h248_pkg_bcg_sig_bdt_par_btd_vals), 0, "btd (Tone Direction)", HFILL }
		},
		{ &hf_h248_pkg_bcg_sig_bdt,
			{ "bdt (Dial Tone)", "h248.pkg.bcg.bdt", 
			FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }
		},
		{ &hf_h248_pkg_bcg_sig_brt,
			{ "brt (Ringing tone)", "h248.pkg.bcg.brt", 
			FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }
		},
		{ &hf_h248_pkg_bcg_sig_bbt,
			{ "bbt (Busy tone)", "h248.pkg.bcg.bbt", 
			FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }
		},
		{ &hf_h248_pkg_bcg_sig_bct,
			{ "bct (Congestion tone)", "h248.pkg.bcg.bct", 
			FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }
		},
		{ &hf_h248_pkg_bcg_sig_bsit,
			{ "bsit (Special information tone)", "h248.pkg.bcg.bsit", 
			FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }
		},
		{ &hf_h248_pkg_bcg_sig_bwt,
			{ "bwt (Warning tone)", "h248.pkg.bcg.bwt", 
			FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }
		},
		{ &hf_h248_pkg_bcg_sig_bpt,
			{ "bpt (Payphone recognition tone)", "h248.pkg.bcg.bpt", 
			FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }
		},
		{ &hf_h248_pkg_bcg_sig_bcw,
			{ "bcw (Call waiting tone)", "h248.pkg.bcg.bcw", 
			FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }
		},
		{ &hf_h248_pkg_bcg_sig_bpy,
			{ "bpy (Pay tone)", "h248.pkg.bcg.bpy", 
			FT_UINT8, BASE_HEX, NULL, 0, "", HFILL }
		},
	};

	static gint *ett[] = {
		&ett_h248_pkg_BCP
	};
	proto_q1950 = proto_register_protocol(PNAME, PSNAME, PFNAME);

	proto_register_field_array(proto_q1950, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));
	
	/* Register the packages */
	h248_register_package(&h248_pkg_BCP);
	h248_register_package(&h248_pkg_bcg);
}

void proto_reg_handoff_q1950(void) {
}
