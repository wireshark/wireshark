/*
 *  packet-h248-annex_e.c
 *  H.248 Annex E
 *
 *  (c) 2006, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
 *
 * $Id: packet-h248-template.c 17587 2006-03-11 13:02:41Z sahlberg $
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
 */

#include "packet-h248.h"
#define PNAME  "H.248 Annex E"
#define PSNAME "H248E"
#define PFNAME "h248e"
/*
#include <epan/dissectors/packet-alcap.h>
*/
static int proto_h248_annex_E = -1;

/* H.248.1 E.1  Generic Package */
static int hf_h248_pkg_generic = -1;
static int hf_h248_pkg_generic_params = -1;
static int hf_h248_pkg_generic_cause_evt = -1;
static int hf_h248_pkg_generic_cause_gencause = -1;
static int hf_h248_pkg_generic_cause_failurecause = -1;

static gint ett_h248_pkg_generic_cause_evt = -1;
static gint ett_tdmc = -1;
static gint ett_h248_pkg_generic = -1;


static h248_pkg_param_t h248_pkg_generic_cause_evt_params[] = {
	{ 0x0001, &hf_h248_pkg_generic_cause_gencause, h248_param_ber_integer, NULL },
	{ 0x0002, &hf_h248_pkg_generic_cause_failurecause, h248_param_ber_octetstring, NULL },
	{ 0, NULL, NULL, NULL}
};

static h248_pkg_evt_t h248_pkg_generic_cause_evts[] = {
	{ 0x0001, &hf_h248_pkg_generic_cause_evt, &ett_h248_pkg_generic_cause_evt, h248_pkg_generic_cause_evt_params},
};


static h248_package_t h248_pkg_generic = {
	0x0001,
	&hf_h248_pkg_generic,
	&hf_h248_pkg_generic_params,
	&ett_h248_pkg_generic,
	NULL,
	NULL,
	h248_pkg_generic_cause_evts,
	NULL
};


/* H.248.1 E.2  Base Root Package 
static int hf_h248_pkg_root = -1;
static int hf_h248_pkg_root_params = -1;
static int hf_h248_pkg_root_maxnrofctx = -1;
static int hf_h248_pkg_root_maxtermsperctx = -1;
static int hf_h248_pkg_root_normalmgexectime = -1;
static int hf_h248_pkg_root_normalmgcexecutiontime = -1;
static int hf_h248_pkg_root_provisionalresponsetimervalue = -1;

static gint ett_h248_pkg_root = -1;

static h248_pkg_param_t h248_pkg_root_properties[] = {
	{ 0x0001, &hf_h248_pkg_root_maxnrofctx, h248_param_ber_integer, NULL },
	{ 0x0002, &hf_h248_pkg_root_maxtermsperctx, h248_param_ber_integer, NULL },
	{ 0x0003, &hf_h248_pkg_root_normalmgexectime, h248_param_ber_integer, NULL },
	{ 0x0004, &hf_h248_pkg_root_normalmgcexecutiontime, h248_param_ber_integer, NULL },
	{ 0x0005, &hf_h248_pkg_root_provisionalresponsetimervalue, h248_param_ber_integer, NULL },
	{ 0, NULL, NULL, NULL}
};

static h248_package_t h248_pkg_root = {
	0x0002,
	&hf_h248_pkg_root,
	&hf_h248_pkg_root_params,
	&ett_h248_pkg_root,
	h248_pkg_root_properties,
	NULL,
	NULL,
	NULL,
	NULL
};
*/

/* H.248.1 E.3  Tone Generator Package
static int hf_h248_pkg_tonegen = -1;
static int hf_h248_pkg_tonegen_params = -1;
static int hf_h248_pkg_tonegen_sig_pt = -1;
static int hf_h248_pkg_tonegen_sig_pt_tl = -1;
static int hf_h248_pkg_tonegen_sig_pt_ind = -1;

static gint ett_h248_pkg_tonegen = -1;

static h248_pkg_param_t hf_h248_pkg_tonegen_properties[] = {
	{ 0x0001, &hf_h248_pkg_tonegen_sig_pt_tl, h248_param_ber_integer, NULL },
	{ 0x0002, &hf_h248_pkg_tonegen_sig_pt_ind, h248_param_ber_integer, NULL },
	{ 0, NULL, NULL, NULL}
};

static h248_package_t h248_pkg_tonegen = {
	0x0002,
	&hf_h248_pkg_tonegen,
	&hf_h248_pkg_tonegen_params,
	&ett_h248_pkg_tonegen,
	h248_pkg_root_properties,
	NULL,
	NULL,
	NULL
};
*/


/* H.248.1 E.4  Tone Detector Package 
static int hf_h248_pkg_tonedet = -1;
static int hf_h248_pkg_tonedet_evt_std = -1;
static int hf_h248_pkg_tonedet_evt_etd = -1;
static int hf_h248_pkg_tonedet_evt_ltd = -1;
*/

/* H.248.1 E.13 TDM Circuit Package */
static int hf_h248_pkg_tdmc = -1;
static int hf_h248_pkg_tdmc_param = -1;
static int hf_h248_pkg_tdmc_ec = -1;
static int hf_h248_pkg_tdmc_gain = -1;

static gint ett_h248_pkg_tdmc = -1;

static const true_false_string h248_tdmc_ec_vals = {
	"On",
	"Off"
};


static h248_pkg_param_t h248_pkg_tdmc_props[] = {
	{ 0x0008, &hf_h248_pkg_tdmc_ec, h248_param_ber_boolean, NULL },
	{ 0x000a, &hf_h248_pkg_tdmc_gain, h248_param_ber_integer, NULL },
};

static h248_package_t h248_pkg_tdmc = {
	0x000d,
	&hf_h248_pkg_tdmc,
	&hf_h248_pkg_tdmc_param,
	&ett_h248_pkg_tdmc,
	h248_pkg_tdmc_props,
	NULL,
	NULL,
	NULL
};



void proto_register_h248_annex_e(void) {
	static hf_register_info hf[] = {
		{ &hf_h248_pkg_generic, { "Generic Package", "h248.pkg.generic", FT_BYTES, BASE_HEX, NULL, 0, "", HFILL }},
		{ &hf_h248_pkg_generic_cause_evt, { "Cause Event", "h248.pkg.generic.cause", FT_BYTES, BASE_HEX, NULL, 0, "", HFILL }},
		{ &hf_h248_pkg_generic_cause_gencause, { "Generic Cause", "h248.pkg.generic.cause.gencause", FT_UINT32, BASE_HEX, NULL, 0, "", HFILL }}, 
		{ &hf_h248_pkg_generic_cause_failurecause, { "Generic Cause", "h248.pkg.generic.cause.failurecause", FT_STRING, BASE_HEX, NULL, 0, "", HFILL }},
		
		{ &hf_h248_pkg_tdmc_ec, { "Echo Cancellation", "h248.pkg.tdmc.ec", FT_BOOLEAN, 8, TFS(&h248_tdmc_ec_vals), 0, "Echo Cancellation", HFILL }},
		{ &hf_h248_pkg_tdmc_gain, { "Gain", "h248.pkg.tdmc.gain", FT_UINT32, BASE_HEX, NULL, 0, "Gain", HFILL }},
	};
	
	static gint *ett[] = {
		&ett_h248_pkg_generic_cause_evt,
		&ett_h248_pkg_generic,

		
		&ett_tdmc
	};

	proto_h248_annex_E = proto_register_protocol(PNAME, PSNAME, PFNAME);

	proto_register_field_array(proto_h248_annex_E, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));
	
	h248_register_package(&h248_pkg_generic);
	h248_register_package(&h248_pkg_tdmc);
}

void proto_reg_handoff_h248_annex_e(void) {
}

