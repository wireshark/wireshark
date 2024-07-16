/*
 *  packet-h248_7.c
 *  H.248.7
 *  Gateway control protocol: Generic Announcement package
 *
 *  (c) 2007, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "packet-h248.h"

void proto_register_h248_7(void);

#define PNAME  "H.248.7"
#define PSNAME "H248AN"
#define PFNAME "h248.an"

static int proto_h248_an;

static int hf_h248_an_apf;
static int hf_h248_an_apf_an;
static int hf_h248_an_apf_noc;
static int hf_h248_an_apf_av;
static int hf_h248_an_apf_di;

static int hf_h248_an_apv;
static int hf_h248_an_apv_an;
static int hf_h248_an_apv_noc;
static int hf_h248_an_apv_av;
static int hf_h248_an_apv_num;
static int hf_h248_an_apv_spi;
static int hf_h248_an_apv_sp;
static int hf_h248_an_apv_di;

static int ett_h248_an;
static int ett_h248_an_apf;
static int ett_h248_an_apv;

static const value_string h248_an_prop_vals[] = {
	{ 0, "Generic Announcement Package (an) (H.248.7)" },
	{ 0, NULL }
};

static const value_string  h248_an_signals_vals[] = {
	{ 0x0001, "Announcement Play Fixed (apf)"},
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

static h248_package_t h248_pkg_an = {
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

	static int *ett[] = {
		&ett_h248_an,
		&ett_h248_an_apf,
		&ett_h248_an_apv
	};

	proto_h248_an = proto_register_protocol(PNAME, PSNAME, PFNAME);

	proto_register_field_array(proto_h248_an, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));

	h248_register_package(&h248_pkg_an,REPLACE_PKG);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
