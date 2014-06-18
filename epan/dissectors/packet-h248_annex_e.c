/*
 *  packet-h248_annex_e.c
 *  H.248 Annex E
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
 */

#include "config.h"


/*****/
#include <epan/proto.h>
#include <epan/tvbuff.h>
#include <epan/tvbuff-int.h>
#include <epan/tvbparse.h>
/*****/

#include "packet-h248.h"

void proto_register_h248_annex_e(void);

#define PNAME  "H.248 Annex E"
#define PSNAME "H248E"
#define PFNAME "h248e"
/*
#include <epan/dissectors/packet-alcap.h>
*/
static int proto_h248_annex_E = -1;

static gboolean h248_e_implicit = FALSE;
static gboolean implicit = FALSE;

/* H.248.1 E.1  Generic Package */
static int hf_h248_pkg_generic = -1;
static int hf_h248_pkg_generic_cause_evt = -1;
static int hf_h248_pkg_generic_cause_gencause = -1;
static int hf_h248_pkg_generic_cause_failurecause = -1;
static int hf_h248_pkg_generic_sc_evt = -1;
static int hf_h248_pkg_generic_sc_sig_id = -1;
static int hf_h248_pkg_generic_sc_meth = -1;
static int hf_h248_pkg_generic_sc_slid = -1;
static int hf_h248_pkg_generic_sc_rid = -1;

static gint ett_h248_pkg_generic_cause_evt = -1;
static gint ett_h248_pkg_generic = -1;
static gint ett_h248_pkg_generic_sc_evt = -1;

static const value_string h248_pkg_generic_props_vals[] = {
	{ 0,"Generic Package - Annex E (g)" },
	{ 0, NULL }
};

static const value_string h248_pkg_generic_cause_vals[] _U_ = {
	{1, "General Cause (gencause)"},
	{2, "Faiure Cause (failurecause)"},
	{ 0, NULL }
};

static const value_string h248_pkg_generic_cause_gencause_vals[] = {
	{ 1, "Normal Release (NR)"},
	{ 2, "Unavailable Resources (UR)"},
	{ 3, "Failure, Temporary (FT)"},
	{ 4, "Failure, Permanent (FP)"},
	{ 5, "Interworking Error (IW)"},
	{ 6, "Unsupported (UN)"},
	{ 0, NULL }
};

static h248_pkg_param_t h248_pkg_generic_cause_evt_params[] = {
	{ 0x0001, &hf_h248_pkg_generic_cause_gencause, h248_param_ber_integer, &h248_e_implicit },
	{ 0x0002, &hf_h248_pkg_generic_cause_failurecause, h248_param_ber_octetstring, &h248_e_implicit },
	{ 0, NULL, NULL, NULL}
};

static const value_string h248_pkg_generic_sc_meth_vals[] _U_ = {
	{0x0001,"Signal Identity (SigID)"},
	{0x0002,"Termination Method (Meth)"},
	{0x0003,"Signal List ID (SLID)"},
	{0x0004,"Request ID (RID)"},
	{0,NULL}
};

static const value_string h248_pkg_generic_sc_vals[] = {
	{0x0001,"TO - Signal timed out or otherwise completed on its own"},
	{0x0002,"EV - Interrupted by event"},
	{0x0003,"SD - Halted by new Signals Descriptor"},
	{0x0004,"NC - Not completed, other cause"},
	{0x0005,"PI - First to penultimate iteration"},
	{0,NULL}
};

static h248_pkg_param_t h248_pkg_generic_sc_evt_params[] = {
	{ 0x0001, &hf_h248_pkg_generic_sc_sig_id, h248_param_PkgdName, &h248_e_implicit },
	{ 0x0002, &hf_h248_pkg_generic_sc_meth, h248_param_ber_integer, &h248_e_implicit },
	{ 0x0003, &hf_h248_pkg_generic_sc_slid, h248_param_ber_integer, &h248_e_implicit },
	{ 0x0004, &hf_h248_pkg_generic_sc_rid, h248_param_ber_integer, &h248_e_implicit },
	{ 0, NULL, NULL, NULL}
};

static h248_pkg_evt_t h248_pkg_generic_cause_evts[] = {
	{ 0x0001, &hf_h248_pkg_generic_cause_evt, &ett_h248_pkg_generic_cause_evt, h248_pkg_generic_cause_evt_params, h248_pkg_generic_cause_gencause_vals},
	{ 0x0002, &hf_h248_pkg_generic_sc_evt, &ett_h248_pkg_generic_sc_evt, h248_pkg_generic_sc_evt_params, h248_pkg_generic_sc_vals},
	{ 0, NULL, NULL, NULL, NULL}
};

static h248_package_t h248_pkg_generic = {
	0x0001,
	&hf_h248_pkg_generic,
	&ett_h248_pkg_generic,
	h248_pkg_generic_props_vals,
	NULL,
	h248_pkg_generic_cause_vals,
	NULL,
	NULL,
	NULL,
	h248_pkg_generic_cause_evts,
	NULL
};


/* H.248.1 E.2  Base Root Package */
#if 0 /* XXX: All of the following hf_... vars  have no hf[] entry; package commented out */
static int hf_h248_pkg_root = -1;
static int hf_h248_pkg_root_maxnrofctx = -1;
static int hf_h248_pkg_root_maxtermsperctx = -1;
static int hf_h248_pkg_root_normalmgexectime = -1;
static int hf_h248_pkg_root_normalmgcexecutiontime = -1;
static int hf_h248_pkg_root_mg_provisionalresponsetimervalue = -1;
static int hf_h248_pkg_root_mgc_provisionalresponsetimervalue = -1;
static int hf_h248_pkg_root_mgc_orginalpendinglimit = -1;
static int hf_h248_pkg_root_mg_orginalpendinglimit = -1;

static gint ett_h248_pkg_root_params		= -1;

static const value_string h248_pkg_root_props_vals[] = {
	{ 0x0000, "Base Root Package - Annex E (root)" },
	{ 0x0001, "Maximum Number of Contexts" },
	{ 0x0002, "Maximum Terminations Per Context" },
	{ 0x0003, "Normal MG Execution Time" },
	{ 0x0004, "Normal MGC Execution Time" },
	{ 0x0005, "MG Provisional Response Timer Value" },
	{ 0x0006, "MGC Provisional Response Timer Value" },
	{ 0x0007, "MGC Originated Pending Limit" },
	{ 0x0008, "MG Originated Pending Limit" },
	{ 0, NULL }
};

static h248_pkg_param_t h248_pkg_root_properties[] = {
	{ 0x0001, &hf_h248_pkg_root_maxnrofctx, h248_param_ber_integer, &h248_e_implicit },
	{ 0x0002, &hf_h248_pkg_root_maxtermsperctx, h248_param_ber_integer, &h248_e_implicit },
	{ 0x0003, &hf_h248_pkg_root_normalmgexectime, h248_param_ber_integer, &h248_e_implicit },
	{ 0x0004, &hf_h248_pkg_root_normalmgcexecutiontime, h248_param_ber_integer, &h248_e_implicit },
	{ 0x0005, &hf_h248_pkg_root_mg_provisionalresponsetimervalue, h248_param_ber_integer, &implicit },
	{ 0x0006, &hf_h248_pkg_root_mgc_provisionalresponsetimervalue, h248_param_ber_integer, &implicit },
	{ 0x0007, &hf_h248_pkg_root_mgc_orginalpendinglimit, h248_param_ber_integer, &implicit },
	{ 0x0008, &hf_h248_pkg_root_mg_orginalpendinglimit, h248_param_ber_integer, &implicit },
	{ 0, NULL, NULL, NULL}
};

static h248_package_t h248_pkg_root = {
	0x0002,
	&hf_h248_pkg_root,
	&ett_h248_pkg_root_params,
	h248_pkg_root_props_vals,
	NULL,
	NULL,
	NULL,
	h248_pkg_root_properties,
	NULL,
	NULL,
	NULL
};
#endif

/* H.248.1 E.3  Tone Generator Package */
static int hf_h248_pkg_tonegen				= -1;
static int hf_h248_pkg_tonegen_sig_pt		= -1;
static int hf_h248_pkg_tonegen_sig_pt_tl	= -1;
static int hf_h248_pkg_tonegen_sig_pt_ind	= -1;
static int hf_h248_pkg_tonegen_sig_pg_btd	= -1;

static gint ett_h248_pkg_tonegen_params		= -1;
static gint ett_h248_pkg_tonegen_sig_pt		= -1;

static const value_string h248_pkg_tonegen_props_vals[] = {
	{ 0x0000, "Tone Generator - Annex E (tonegen)" },
	{ 0, NULL }
};

static const value_string h248_pkg_tonegen_sigs_vals[] = {
	{ 0x0001, "Play Tone (pt)" },
	{ 0, NULL }
};

static const value_string h248_pkg_tonegen_pt_param_vals[] = {
	{ 0x0001, "Tone ID List (tl)" },
	{ 0x0002, "Inter-signal duration (ind)" },
	{ 0x0003, "Tone Direction (td)" },
	{ 0, NULL }
};

static const value_string h248_pkg_tonegen_pt_btd_param_vals[] = {
	{ 0x0001, "External (EXT)" },
	{ 0x0002, "Internal (INT)" },
	{ 0x0003, "Both (BOTH)" },
	{ 0, NULL }
};

static h248_pkg_param_t h248_pkg_tonegen_sig_params[] = {
	{ 0x0001, &hf_h248_pkg_tonegen_sig_pt_tl, h248_param_ber_integer, &h248_e_implicit },
	{ 0x0002, &hf_h248_pkg_tonegen_sig_pt_ind, h248_param_ber_integer, &h248_e_implicit },
	{ 0x0003, &hf_h248_pkg_tonegen_sig_pg_btd, h248_param_ber_integer, &implicit },
	{ 0, NULL, NULL, NULL}
};

static const h248_pkg_sig_t h248_pkg_tonegen_signals[] = {
	{ 0x0001, &hf_h248_pkg_tonegen_sig_pt, &ett_h248_pkg_tonegen_sig_pt, h248_pkg_tonegen_sig_params, h248_pkg_tonegen_pt_param_vals },
	{ 0, NULL, NULL, NULL, NULL }
};

static h248_package_t h248_pkg_tonegen = {
	0x0003,
	&hf_h248_pkg_tonegen,
	&ett_h248_pkg_tonegen_params,
	h248_pkg_tonegen_props_vals,
	h248_pkg_tonegen_sigs_vals,
	NULL,NULL,NULL,
	h248_pkg_tonegen_signals,
	NULL,
	NULL
};


/*  H.248.1 E.4  Tone Detector Package */
static int hf_h248_pkg_tonedet = -1;
static int hf_h248_pkg_tonedet_evt_std = -1;
static int hf_h248_pkg_tonedet_evt_etd = -1;
static int hf_h248_pkg_tonedet_evt_ltd = -1;

static int hf_h248_pkg_tonedet_evt_tl_param = -1;
static int hf_h248_pkg_tonedet_evt_dur_param = -1;
static int hf_h248_pkg_tonedet_evt_tid_param = -1;

static gint ett_h248_pkg_tonedet = -1;
static gint ett_h248_pkg_tonedet_evt_std = -1;
static gint ett_h248_pkg_tonedet_evt_etd = -1;
static gint ett_h248_pkg_tonedet_evt_ltd = -1;

static const value_string h248_pkg_tonedet_props_vals[] = {
	{ 0x0000, "Tone Detection Package - Annex E  (tonedet)" },
	{ 0, NULL }
};

static const value_string h248_pkg_tonedet_events_vals[] = {
	{ 0x0001, "Start Tone Detected (std)" },
	{ 0x0002, "End Tone Detected (etd)" },
	{ 0x0003, "Long Tone Detected (ltd)" },
	{ 0, NULL }
};

static const value_string h248_pkg_tonedet_evt_param_vals[] = {
	{ 0x0001, "Tone ID List (tl)" },
	{ 0x0002, "Duration (dur)" },
	{ 0x0003, "Tone ID (tid)" },
	{ 0, NULL }
};

static const value_string h248_pkg_tonedet_tl_params_vals[] = {
	{ 0x0000, "Wildcard (*)" },
	{ 0, NULL }
};

static const h248_pkg_param_t h248_pkg_tonedet_event_params[] = {
	{ 0x0001, &hf_h248_pkg_tonedet_evt_tl_param, h248_param_uint_item, &implicit },
	{ 0x0002, &hf_h248_pkg_tonedet_evt_dur_param, h248_param_ber_integer, &implicit },
	{ 0x0003, &hf_h248_pkg_tonedet_evt_tid_param, h248_param_ber_integer, &implicit },
	{ 0, NULL, NULL, NULL }
};

static const h248_pkg_evt_t h248_pkg_tonedet_events[] = {
	{ 0x0001, &hf_h248_pkg_tonedet_evt_std, &ett_h248_pkg_tonedet_evt_std, h248_pkg_tonedet_event_params, h248_pkg_tonedet_evt_param_vals },
	{ 0x0002, &hf_h248_pkg_tonedet_evt_etd, &ett_h248_pkg_tonedet_evt_etd, h248_pkg_tonedet_event_params, h248_pkg_tonedet_evt_param_vals },
	{ 0x0003, &hf_h248_pkg_tonedet_evt_ltd, &ett_h248_pkg_tonedet_evt_ltd, h248_pkg_tonedet_event_params, h248_pkg_tonedet_evt_param_vals },
	{ 0, NULL, NULL, NULL, NULL }
};

static h248_package_t h248_pkg_tonedet = {
	0x0004,
	&hf_h248_pkg_tonedet,
	&ett_h248_pkg_tonedet,
	h248_pkg_tonedet_props_vals,
	NULL,
	h248_pkg_tonedet_events_vals,
	NULL,
	NULL,
	NULL,
	h248_pkg_tonedet_events,
	NULL
};


/* E.5 Basic DTMF Generator Package */
static int hf_h248_pkg_dg			= -1;
static int hf_h248_pkg_dg_sig_pt	= -1;
static int hf_h248_pkg_dg_sig_d0	= -1;
static int hf_h248_pkg_dg_sig_d1	= -1;
static int hf_h248_pkg_dg_sig_d2	= -1;
static int hf_h248_pkg_dg_sig_d3	= -1;
static int hf_h248_pkg_dg_sig_d4	= -1;
static int hf_h248_pkg_dg_sig_d5	= -1;
static int hf_h248_pkg_dg_sig_d6	= -1;
static int hf_h248_pkg_dg_sig_d7	= -1;
static int hf_h248_pkg_dg_sig_d8	= -1;
static int hf_h248_pkg_dg_sig_d9	= -1;
static int hf_h248_pkg_dg_sig_da	= -1;
static int hf_h248_pkg_dg_sig_db	= -1;
static int hf_h248_pkg_dg_sig_dc	= -1;
static int hf_h248_pkg_dg_sig_dd	= -1;
static int hf_h248_pkg_dg_sig_ds	= -1;
static int hf_h248_pkg_dg_sig_do	= -1;
static int hf_h248_pkg_dg_sig_params	= -1;

static gint ett_h248_pkg_dg			= -1;
static gint ett_h248_pkg_dg_sig_pt	= -1;
static gint ett_h248_pkg_dg_sig_d0	= -1;
static gint ett_h248_pkg_dg_sig_d1	= -1;
static gint ett_h248_pkg_dg_sig_d2	= -1;
static gint ett_h248_pkg_dg_sig_d3	= -1;
static gint ett_h248_pkg_dg_sig_d4	= -1;
static gint ett_h248_pkg_dg_sig_d5	= -1;
static gint ett_h248_pkg_dg_sig_d6	= -1;
static gint ett_h248_pkg_dg_sig_d7	= -1;
static gint ett_h248_pkg_dg_sig_d8	= -1;
static gint ett_h248_pkg_dg_sig_d9	= -1;
static gint ett_h248_pkg_dg_sig_da	= -1;
static gint ett_h248_pkg_dg_sig_db	= -1;
static gint ett_h248_pkg_dg_sig_dc	= -1;
static gint ett_h248_pkg_dg_sig_dd	= -1;
static gint ett_h248_pkg_dg_sig_ds	= -1;
static gint ett_h248_pkg_dg_sig_do	= -1;

static const value_string h248_pkg_dg_props_vals[] = {
	{ 0x0000, "Basic DTMF Generator Package - Annex E (dg)" },
	{ 0, NULL }
};

static const value_string  h248_pkg_dg_signals_vals[] = {
	/* from tonegeg */
	{ 0x0001, "Tone ID List (tl)" },
	{ 0x0002, "End Tone Detected (etd)" },
	{ 0x0003, "Long Tone Detected (ltd)" },

	/* from dd */
	{ 0x0010, "0 (d0)"},
	{ 0x0011, "1 (d1)"},
	{ 0x0012, "2 (d2)"},
	{ 0x0013, "3 (d3)"},
	{ 0x0014, "4 (d4)"},
	{ 0x0015, "5 (d5)"},
	{ 0x0016, "6 (d6)"},
	{ 0x0017, "7 (d7)"},
	{ 0x0018, "8 (d8)"},
	{ 0x0019, "9 (d9)"},
	{ 0x001a, "A (dA)"},
	{ 0x001b, "B (dB)"},
	{ 0x001c, "C (dC)"},
	{ 0x001d, "D (dD)"},
	{ 0x0020, "* (ds)"},
	{ 0x0021, "# (do)"},
	{0,NULL}
};

#if 0
static const value_string h248_pkg_dg_sig_params_vals[] = {
	{ 0x0001, "Tone Direction (btd)" },
	{ 0, NULL }
};
#endif

static const value_string h248_pkg_dg_sig_btd_vals[] = {
	{ 0x0001, "External (EXT)" },
	{ 0x0002, "Internal (INT)" },
	{ 0x0003, "Both (BOTH)" },
	{ 0, NULL }
};

static const h248_pkg_param_t h248_pkg_dg_signal_params[] = {
	{ 0x0001, &hf_h248_pkg_dg_sig_params, h248_param_ber_integer, &implicit },
	{ 0x0010, &hf_h248_pkg_dg_sig_params, h248_param_ber_integer, &implicit },
	{ 0x0011, &hf_h248_pkg_dg_sig_params, h248_param_ber_integer, &implicit },
	{ 0x0012, &hf_h248_pkg_dg_sig_params, h248_param_ber_integer, &implicit },
	{ 0x0013, &hf_h248_pkg_dg_sig_params, h248_param_ber_integer, &implicit },
	{ 0x0014, &hf_h248_pkg_dg_sig_params, h248_param_ber_integer, &implicit },
	{ 0x0015, &hf_h248_pkg_dg_sig_params, h248_param_ber_integer, &implicit },
	{ 0x0016, &hf_h248_pkg_dg_sig_params, h248_param_ber_integer, &implicit },
	{ 0x0017, &hf_h248_pkg_dg_sig_params, h248_param_ber_integer, &implicit },
	{ 0x0018, &hf_h248_pkg_dg_sig_params, h248_param_ber_integer, &implicit },
	{ 0x0019, &hf_h248_pkg_dg_sig_params, h248_param_ber_integer, &implicit },
	{ 0x001a, &hf_h248_pkg_dg_sig_params, h248_param_ber_integer, &implicit },
	{ 0x001b, &hf_h248_pkg_dg_sig_params, h248_param_ber_integer, &implicit },
	{ 0x001c, &hf_h248_pkg_dg_sig_params, h248_param_ber_integer, &implicit },
	{ 0x001d, &hf_h248_pkg_dg_sig_params, h248_param_ber_integer, &implicit },
	{ 0x0020, &hf_h248_pkg_dg_sig_params, h248_param_ber_integer, &implicit },
	{ 0x0021, &hf_h248_pkg_dg_sig_params, h248_param_ber_integer, &implicit },
	{ 0, NULL, NULL, NULL }
};

/* Signals definitions */
static h248_pkg_sig_t h248_pkg_dg_signals[] = {
	{ 0X0001, &hf_h248_pkg_dg_sig_pt, &ett_h248_pkg_dg_sig_pt, h248_pkg_dg_signal_params,h248_pkg_dg_signals_vals },
	{ 0x0010, &hf_h248_pkg_dg_sig_d0, &ett_h248_pkg_dg_sig_d0, h248_pkg_dg_signal_params,h248_pkg_dg_signals_vals },
	{ 0x0011, &hf_h248_pkg_dg_sig_d1, &ett_h248_pkg_dg_sig_d1, h248_pkg_dg_signal_params,h248_pkg_dg_signals_vals },
	{ 0x0012, &hf_h248_pkg_dg_sig_d2, &ett_h248_pkg_dg_sig_d2, h248_pkg_dg_signal_params,h248_pkg_dg_signals_vals },
	{ 0x0013, &hf_h248_pkg_dg_sig_d3, &ett_h248_pkg_dg_sig_d3, h248_pkg_dg_signal_params,h248_pkg_dg_signals_vals },
	{ 0x0014, &hf_h248_pkg_dg_sig_d4, &ett_h248_pkg_dg_sig_d4, h248_pkg_dg_signal_params,h248_pkg_dg_signals_vals },
	{ 0x0015, &hf_h248_pkg_dg_sig_d5, &ett_h248_pkg_dg_sig_d5, h248_pkg_dg_signal_params,h248_pkg_dg_signals_vals },
	{ 0x0016, &hf_h248_pkg_dg_sig_d6, &ett_h248_pkg_dg_sig_d6, h248_pkg_dg_signal_params,h248_pkg_dg_signals_vals },
	{ 0x0017, &hf_h248_pkg_dg_sig_d7, &ett_h248_pkg_dg_sig_d7, h248_pkg_dg_signal_params,h248_pkg_dg_signals_vals },
	{ 0x0018, &hf_h248_pkg_dg_sig_d8, &ett_h248_pkg_dg_sig_d8, h248_pkg_dg_signal_params,h248_pkg_dg_signals_vals },
	{ 0x0019, &hf_h248_pkg_dg_sig_d9, &ett_h248_pkg_dg_sig_d9, h248_pkg_dg_signal_params,h248_pkg_dg_signals_vals },
	{ 0x001a, &hf_h248_pkg_dg_sig_da, &ett_h248_pkg_dg_sig_da, h248_pkg_dg_signal_params,h248_pkg_dg_signals_vals },
	{ 0x001b, &hf_h248_pkg_dg_sig_db, &ett_h248_pkg_dg_sig_db, h248_pkg_dg_signal_params,h248_pkg_dg_signals_vals },
	{ 0x001c, &hf_h248_pkg_dg_sig_dc, &ett_h248_pkg_dg_sig_dc, h248_pkg_dg_signal_params,h248_pkg_dg_signals_vals },
	{ 0x001d, &hf_h248_pkg_dg_sig_dd, &ett_h248_pkg_dg_sig_dd, h248_pkg_dg_signal_params,h248_pkg_dg_signals_vals },
	{ 0x0020, &hf_h248_pkg_dg_sig_ds, &ett_h248_pkg_dg_sig_ds, h248_pkg_dg_signal_params,h248_pkg_dg_signals_vals },
	{ 0x0021, &hf_h248_pkg_dg_sig_do, &ett_h248_pkg_dg_sig_do, h248_pkg_dg_signal_params,h248_pkg_dg_signals_vals },
	{ 0, NULL, NULL, NULL, NULL}
};

/* Packet definitions */
static h248_package_t h248_pkg_dg = {
	0x0005,
	&hf_h248_pkg_dg,
	&ett_h248_pkg_dg,
	h248_pkg_dg_props_vals,
	h248_pkg_dg_signals_vals,
	NULL, NULL, NULL,
	h248_pkg_dg_signals,	/* signals		*/
	NULL, NULL
};

/* H248.1 E.6 DTMF Detection Package (dd) */

#if 0 /* XXX: The following 5 hf_... vars have no hf[] entry: package commented out */
static int hf_h248_pkg_dd		= -1;
static int hf_h248_pkg_dd_evt_std	= -1;
static int hf_h248_pkg_dd_evt_etd	= -1;
static int hf_h248_pkg_dd_evt_ltd	= -1;
static int hf_h248_pkg_dd_evt_ce	= -1;
#endif
#if 0
static int hf_h248_pkg_dd_evt_d0	= -1;
static int hf_h248_pkg_dd_evt_d1	= -1;
static int hf_h248_pkg_dd_evt_d2	= -1;
static int hf_h248_pkg_dd_evt_d3	= -1;
static int hf_h248_pkg_dd_evt_d4	= -1;
static int hf_h248_pkg_dd_evt_d5	= -1;
static int hf_h248_pkg_dd_evt_d6	= -1;
static int hf_h248_pkg_dd_evt_d7	= -1;
static int hf_h248_pkg_dd_evt_d8	= -1;
static int hf_h248_pkg_dd_evt_d9	= -1;
static int hf_h248_pkg_dd_evt_da	= -1;
static int hf_h248_pkg_dd_evt_db	= -1;
static int hf_h248_pkg_dd_evt_dc	= -1;
static int hf_h248_pkg_dd_evt_dd	= -1;
static int hf_h248_pkg_dd_evt_ds	= -1;
static int hf_h248_pkg_dd_evt_do	= -1;
static int hf_h248_pkg_dd_evt_ce_ds	= -1;
static int hf_h248_pkg_dd_evt_ce_meth	= -1;
static int hf_h248_pkg_dd_evt_tl_param	= -1;
static int hf_h248_pkg_dd_evt_dur_param	= -1;
static int hf_h248_pkg_dd_evt_tid_param	= -1;
#endif

#if 0
static gint ett_h248_pkg_dd			= -1;
static gint ett_h248_pkg_dd_evt_ce		= -1;
static gint ett_h248_pkg_dd_evt_std		= -1;
static gint ett_h248_pkg_dd_evt_etd		= -1;
static gint ett_h248_pkg_dd_evt_ltd		= -1;

static const value_string h248_pkg_dd_props_vals[] = {
	{ 0x0000, "DTMF Detection Package - Annex E (dd)" },
	{ 0, NULL }
};

static const value_string  h248_pkg_dd_event_vals[] = {
	/* from tonedet */
	{ 0x0000, "Wildcard (*)" },
	{ 0x0001, "Start Tone Detected (std)" },
	{ 0x0002, "End Tone Detected (etd)" },
	{ 0x0003, "Long Tone Detected (ltd)" },
	{ 0x0004, "Digit Completion Map (ce)" },

	/* from dd */
	{ 0x0010, "0 (d0)"},
	{ 0x0011, "1 (d1)"},
	{ 0x0012, "2 (d2)"},
	{ 0x0013, "3 (d3)"},
	{ 0x0014, "4 (d4)"},
	{ 0x0015, "5 (d5)"},
	{ 0x0016, "6 (d6)"},
	{ 0x0017, "7 (d7)"},
	{ 0x0018, "8 (d8)"},
	{ 0x0019, "9 (d9)"},
	{ 0x001a, "A (dA)"},
	{ 0x001b, "B (dB)"},
	{ 0x001c, "C (dC)"},
	{ 0x001d, "D (dD)"},
	{ 0x0020, "* (ds)"},
	{ 0x0021, "# (do)"},
	{0,NULL}
};

static const value_string h248_pkg_dd_event_params_vals[] = {
	{ 0x0001, "Unambiguous Match (UM)" },
	{ 0x0002, "Partial Match (PM)" },
	{ 0x0003, "Full Match (FM)" },
	{ 0, NULL }
};

static const value_string h248_pkg_dd_ce_vals[] = {
	{ 0x0001, "Digit String (ds)" },
	{ 0x0003, "Termination Method (meth)" },
	{ 0, NULL }
};

static h248_pkg_param_t h248_pkg_dd_ds_events[] = {
	{ 0x0001, &hf_h248_pkg_dd_evt_ce_ds, h248_param_ber_octetstring, &implicit },
	{ 0x0003, &hf_h248_pkg_dd_evt_ce_meth, h248_param_ber_integer, &implicit },
	{ 0, NULL, NULL, NULL }
};

static const h248_pkg_param_t h248_pkg_dd_event_params[] = {
	{ 0x0001, &hf_h248_pkg_dd_evt_tl_param, h248_param_ber_integer, &implicit },
	{ 0x0002, &hf_h248_pkg_dd_evt_dur_param, h248_param_ber_integer, &implicit },
	{ 0x0003, &hf_h248_pkg_dd_evt_tid_param, h248_param_ber_integer, &implicit },
	{ 0, NULL, NULL, NULL }
};


static h248_pkg_evt_t h248_pkg_dd_events[] = {
	{ 0x0001, &hf_h248_pkg_dd_evt_std, &ett_h248_pkg_dd_evt_std, h248_pkg_dd_event_params, h248_pkg_dd_event_vals },
	{ 0x0002, &hf_h248_pkg_dd_evt_etd, &ett_h248_pkg_dd_evt_etd, h248_pkg_dd_event_params, h248_pkg_dd_event_vals },
	{ 0x0003, &hf_h248_pkg_dd_evt_ltd, &ett_h248_pkg_dd_evt_ltd, h248_pkg_dd_event_params, h248_pkg_dd_event_vals },
	{ 0x0004, &hf_h248_pkg_dd_evt_ce, &ett_h248_pkg_dd_evt_ce, h248_pkg_dd_ds_events, h248_pkg_dd_ce_vals},
	{ 0, NULL, NULL, NULL, NULL }
};

static h248_package_t h248_pkg_dd = {
	0x0006,
	&hf_h248_pkg_dd,
	&ett_h248_pkg_dd,
	h248_pkg_dd_props_vals,
	NULL,
	h248_pkg_dd_event_vals,
	NULL,
	NULL, NULL,
	h248_pkg_dd_events,
	NULL
};
#endif

/* H.248.1.E.7 Call Progress Tones Generator package */
static int hf_h248_pkg_cg			= -1;
static int hf_h248_pkg_cg_sig_pt		= -1;
static int hf_h248_pkg_cg_sig_pt_tl		= -1;
static int hf_h248_pkg_cg_sig_pt_ind		= -1;
static int hf_h248_pkg_cg_sig_pt_btd		= -1;
static int hf_h248_pkg_cg_sig_dt		= -1;
static int hf_h248_pkg_cg_sig_rt		= -1;
static int hf_h248_pkg_cg_sig_bt		= -1;
static int hf_h248_pkg_cg_sig_ct		= -1;
static int hf_h248_pkg_cg_sig_sit		= -1;
static int hf_h248_pkg_cg_sig_wt		= -1;
static int hf_h248_pkg_cg_sig_prt		= -1;
static int hf_h248_pkg_cg_sig_cw		= -1;
static int hf_h248_pkg_cg_sig_cr		= -1;

static gint ett_h248_pkg_cg_params			= -1;
static gint ett_h248_pkg_cg_sig_pt			= -1;
static gint ett_h248_pkg_cg_sig_dt			= -1;
static gint ett_h248_pkg_cg_sig_rt			= -1;
static gint ett_h248_pkg_cg_sig_bt			= -1;
static gint ett_h248_pkg_cg_sig_ct			= -1;
static gint ett_h248_pkg_cg_sig_sit			= -1;
static gint ett_h248_pkg_cg_sig_wt			= -1;
static gint ett_h248_pkg_cg_sig_prt			= -1;
static gint ett_h248_pkg_cg_sig_cw			= -1;
static gint ett_h248_pkg_cg_sig_cr			= -1;

static const value_string h248_pkg_cg_props_vals[] = {
	{ 0x0000, "Call Progress Tones Generator - Annex E (cg)" },
	{ 0, NULL }
};

static const value_string h248_pkg_cg_sig_cd_evt_vals[] = {
	{ 0x0001, "Play Tone (pt)" },
	{ 0x0030, "Dial Tone"},
	{ 0x0031, "Ring Tone" },
	{ 0x0032, "Busy Tone" },
	{ 0x0033, "Congestion Tone" },
	{ 0x0034, "Special Information Tone" },
	{ 0x0035, "(Recording) Warning Tone" },
	{ 0x0036, "Payphone Recognition Tone" },
	{ 0x0037, "Call Waiting Tone" },
	{ 0x0038, "Caller Waiting Tone" },
	{ 0, NULL }
};

static const value_string h248_pkg_cg_sig_pt_param_vals[] = {
	{ 0x0001, "Tone ID List (tl)"},
	{ 0x0002, "Inter-signal duration (ind)" },
	{ 0x0003, "Tone Direction (td)" },
	{ 0, NULL }
};

static const value_string h248_pkg_cg_pt_btd_param_vals[] = {
	{ 0x0001, "External (EXT)" },
	{ 0x0002, "Internal (INT)" },
	{ 0x0003, "Both (BOTH)" },
	{ 0, NULL }
};

static const h248_pkg_param_t h248_pkg_cg_sig_pt_params[] = {
	{ 0x0001, &hf_h248_pkg_cg_sig_pt_tl, h248_param_ber_integer, &implicit },
	{ 0x0002, &hf_h248_pkg_cg_sig_pt_ind, h248_param_ber_integer, &implicit },
	{ 0x0003, &hf_h248_pkg_cg_sig_pt_btd, h248_param_ber_integer, &implicit },
	{ 0, NULL, NULL, NULL}
};

static const h248_pkg_sig_t h248_pkg_cg_signals_cd_events[] = {
	{ 0x0001, &hf_h248_pkg_cg_sig_pt,	&ett_h248_pkg_cg_sig_pt,	h248_pkg_cg_sig_pt_params, h248_pkg_cg_sig_pt_param_vals },
	{ 0x0030, &hf_h248_pkg_cg_sig_dt,	&ett_h248_pkg_cg_sig_dt,	h248_pkg_cg_sig_pt_params, h248_pkg_cg_sig_pt_param_vals },
	{ 0x0031, &hf_h248_pkg_cg_sig_rt,	&ett_h248_pkg_cg_sig_rt,	h248_pkg_cg_sig_pt_params, h248_pkg_cg_sig_pt_param_vals },
	{ 0x0032, &hf_h248_pkg_cg_sig_bt,	&ett_h248_pkg_cg_sig_bt,	h248_pkg_cg_sig_pt_params, h248_pkg_cg_sig_pt_param_vals },
	{ 0x0033, &hf_h248_pkg_cg_sig_ct,	&ett_h248_pkg_cg_sig_ct,	h248_pkg_cg_sig_pt_params, h248_pkg_cg_sig_pt_param_vals },
	{ 0x0034, &hf_h248_pkg_cg_sig_sit,	&ett_h248_pkg_cg_sig_sit,	h248_pkg_cg_sig_pt_params, h248_pkg_cg_sig_pt_param_vals },
	{ 0x0035, &hf_h248_pkg_cg_sig_wt,	&ett_h248_pkg_cg_sig_wt,	h248_pkg_cg_sig_pt_params, h248_pkg_cg_sig_pt_param_vals },
	{ 0x0036, &hf_h248_pkg_cg_sig_prt,	&ett_h248_pkg_cg_sig_prt,	h248_pkg_cg_sig_pt_params, h248_pkg_cg_sig_pt_param_vals },
	{ 0x0037, &hf_h248_pkg_cg_sig_cw,	&ett_h248_pkg_cg_sig_cw,	h248_pkg_cg_sig_pt_params, h248_pkg_cg_sig_pt_param_vals },
	{ 0x0038, &hf_h248_pkg_cg_sig_cr,	&ett_h248_pkg_cg_sig_cr,	h248_pkg_cg_sig_pt_params, h248_pkg_cg_sig_pt_param_vals },
	{ 0, NULL, NULL, NULL, NULL }
};

static h248_package_t h248_pkg_cg = {
	0x0007,
	&hf_h248_pkg_cg,
	&ett_h248_pkg_cg_params,
	h248_pkg_cg_props_vals,
	h248_pkg_cg_sig_cd_evt_vals,
	NULL,NULL,			/* value_stings:  event, stats */
	NULL,  /* dissectors: prop */
	h248_pkg_cg_signals_cd_events,
	NULL,		/* disectors: events */
	NULL		/* dissectors: stats */
};

/* H.248.1 E.8 - Call Tones Detection Package */
static int hf_h248_pkg_cd		= -1;

static gint ett_h248_pkg_cd		= -1;

static const value_string h248_pkg_cd_params_vals[] = {
	{ 0x0000, "Call Progress Tones Detection Package (cd)" },
	{ 0, NULL }
};

static h248_package_t h248_pkg_cd = {
	0x0008,
	&hf_h248_pkg_cd,
	&ett_h248_pkg_cd,
	h248_pkg_cd_params_vals,
	NULL,
	h248_pkg_cg_sig_cd_evt_vals,
	NULL,
	NULL,NULL,
	(const h248_pkg_evt_t *)(const void*)h248_pkg_cg_signals_cd_events,
	NULL
};

/* H.248.1 E.9 Analog Line Supervision Package */
static int hf_h248_pkg_al = -1;
static int hf_h248_pkg_al_sig_cadence = -1;
static int hf_h248_pkg_al_sig_cadence_on_off = -1;
/* static int hf_h248_pkg_al_sig_freq = -1; */
static int hf_h248_pkg_al_evt_onhook = -1;
static int hf_h248_pkg_al_evt_offhook = -1;
static int hf_h248_pkg_al_evt_flashhook = -1;
static int hf_h248_pkg_al_evt_onhook_par_strict = -1;
static int hf_h248_pkg_al_evt_offhook_par_strict = -1;
static int hf_h248_pkg_al_evt_onhook_par_init = -1;
static int hf_h248_pkg_al_evt_offhook_par_init = -1;
static int hf_h248_pkg_al_evt_flashhook_par_mindur = -1;

static gint ett_h248_pkg_al = -1;
static gint ett_h248_pkg_al_sig_cadence = -1;
static gint ett_h248_pkg_al_sig_freq = -1;
static gint ett_h248_pkg_al_evt_onhook = -1;
static gint ett_h248_pkg_al_evt_offhook = -1;
static gint ett_h248_pkg_al_evt_flashhook = -1;

static const value_string h248_pkg_al_props_vals[] = {
	{ 0x0000, "Analog Line Supervision Package - Annex E (al)" },
	{ 0, NULL }
};

static const value_string h248_pkg_al_sig_params_vals[] = {
	{ 1, "One" },
	{ 2, "Two" },
	{ 0x0006, "Cadence" },
	{ 0x0007, "Frequency (Hz)" },
	{ 0, NULL }
};

static const value_string  h248_pkg_al_evt_onhook_params_vals[] = {
	{ 0x0001, "strict"},
	{ 0x0002, "init"},
	{ 0, NULL}
};

static const value_string  h248_pkg_al_evt_flashhook_params_vals[] = {
	{ 0x0001, "mindur"},
	{ 0, NULL}
};

/* Packet definitions */
static const value_string h248_pkg_al_sig_evts_vals[] _U_ = {
	/* Signals */
	{   0x0002, "ri (Ring)" },
	/* Events */
	{   0x0004, "on (On-hook)" },
	{   0x0005, "off (Off-hook)" },
	{   0x0006, "fl (Flashhook)" },
	{0,     NULL},
};

/* Events definitions */
static const value_string h248_pkg_al_evt_onhook_strict_vals[] = {
	{ 0, "exact"},
	{ 1, "state"},
	{ 2, "failWrong"},
	{ 0, NULL }
};

static const true_false_string h248_pkg_al_evt_onhook_par_init_vals = {
	"already on-hook",
	"actual state transition to on-hook"
};

static const true_false_string h248_pkg_al_evt_offhook_par_init_vals = {
	"already off-hook",
	"actual state transition to off-hook"
};


static h248_pkg_param_t h248_pkg_al_sig_cadence[] = {
	{ 0x0006, &hf_h248_pkg_al_sig_cadence_on_off, h248_param_ber_octetstring, &h248_e_implicit },
	{ 0, NULL, NULL, NULL }
};

static h248_pkg_param_t  h248_pkg_al_evt_onhook_params[] = {
	{ 0x0001, &hf_h248_pkg_al_evt_onhook_par_strict, h248_param_ber_integer, &h248_e_implicit },
	{ 0x0002, &hf_h248_pkg_al_evt_onhook_par_init, h248_param_ber_boolean, &h248_e_implicit },
	{ 0, NULL, NULL, NULL}
};

static h248_pkg_param_t  h248_pkg_al_evt_offhook_params[] = {
	{ 0x0001, &hf_h248_pkg_al_evt_offhook_par_strict, h248_param_ber_integer, &h248_e_implicit },
	{ 0x0002, &hf_h248_pkg_al_evt_offhook_par_init, h248_param_ber_boolean, &h248_e_implicit },
	{ 0, NULL, NULL, NULL}
};

static h248_pkg_param_t  h248_pkg_al_evt_flashhook_params[] = {
	{ 0x0001, &hf_h248_pkg_al_evt_flashhook_par_mindur, h248_param_ber_integer, &h248_e_implicit },
	{ 0, NULL, NULL, NULL}
};

static h248_pkg_sig_t h248_pkg_al_sig[] = {
	{ 0x0002, &hf_h248_pkg_al_sig_cadence, &ett_h248_pkg_al_sig_cadence, h248_pkg_al_sig_cadence, h248_pkg_al_sig_params_vals},
	{ 0, NULL, NULL, NULL, NULL }
};

static h248_pkg_evt_t h248_pkg_al_evts[] = {
	{ 0x0004, &hf_h248_pkg_al_evt_onhook, &ett_h248_pkg_al_evt_onhook, h248_pkg_al_evt_onhook_params, h248_pkg_al_evt_onhook_params_vals},
	{ 0x0005, &hf_h248_pkg_al_evt_offhook, &ett_h248_pkg_al_evt_offhook, h248_pkg_al_evt_offhook_params, h248_pkg_al_evt_onhook_params_vals },
	{ 0x0006, &hf_h248_pkg_al_evt_flashhook, &ett_h248_pkg_al_evt_flashhook, h248_pkg_al_evt_flashhook_params, h248_pkg_al_evt_flashhook_params_vals },

	{ 0, NULL, NULL, NULL, NULL}
};

static h248_package_t h248_pkg_al = {
	0x0009,
	&hf_h248_pkg_al,
	&ett_h248_pkg_al,
	h248_pkg_al_props_vals,
	h248_pkg_al_sig_evts_vals,
	h248_pkg_al_sig_evts_vals,
	NULL,
	NULL,						/* Properties */
	h248_pkg_al_sig,			/* signals */
	h248_pkg_al_evts,			/* events */
	NULL						/* statistics */
};


/* H.248.1 E.10 - Basic Continuity Package */
static int hf_h248_pkg_ct		= -1;
static gint ett_h248_pkg_ct		= -1;

static const value_string h248_pkg_ct_props_vals[] = {
	{ 0x0000, "Basic Continuity Package (ct)" },
	{ 0, NULL }
};

static const value_string h248_pkg_ct_evt_sig_vals[] = {
	{ 0x0003, "Continuity Test (ct)" },
	{ 0x0004, "Respond (rsp)" },
	{ 0x0005, "Completion (cmp)" },
	{ 0, NULL }
};

static h248_package_t h248_pkg_ct = {
	0x000a,
	&hf_h248_pkg_ct,
	&ett_h248_pkg_ct,
	h248_pkg_ct_props_vals,
	h248_pkg_ct_evt_sig_vals,
	h248_pkg_ct_evt_sig_vals,
	NULL,
	NULL, NULL, NULL, NULL
};

/* H.248.1 E.11 Network Package */
static int hf_h248_pkg_nt		= -1;
static gint ett_h248_pkg_nt		= -1;

static const value_string h248_pkg_nt_props_evt_stats_vals[] = {
	{ 0x0000, "Network Package (nt)" },
	{ 0x0001, "Duration (dur)" },
	{ 0x0002, "Octets Sent (os)" },
	{ 0x0003, "Octets Received (or)" },
	{ 0x0005, "Network Failure (netfail)" },
	{ 0x0006, "Quality Alert (qualert)" },
	{ 0x0007, "Maximum Jitter Buffer (jit)" },
	{ 0, NULL }
};

static h248_package_t h248_pkg_nt = {
	0x000b,
	&hf_h248_pkg_nt,
	&ett_h248_pkg_nt,
	h248_pkg_nt_props_evt_stats_vals,
	h248_pkg_nt_props_evt_stats_vals,
	NULL,
	h248_pkg_nt_props_evt_stats_vals,
	NULL, NULL, NULL, NULL
};

/* H.248.1 E.12 RTP package */
static int hf_h248_pkg_rtp = -1;
static int hf_h248_pkg_rtp_stat_ps = -1;

static gint ett_h248_pkg_rtp = -1;

static const value_string h248_pkg_rtp_stat_vals[] _U_ = {
	{ 0x0004, "ps"},
	{ 0, NULL}
};

static const value_string h248_pkg_rtp_props_vals[] = {
	{   0x0000, "RTP Package - Annex E (rtp)" },
	{   0x0001, "pltrans (Payload Transition)" },
	{   0x0004, "ps (Packets Sent)" },
	{   0x0005, "pr (Packets Received)" },
	{   0x0006, "pl (Packet Loss)" },
	{   0x0007, "jit (Jitter)" },
	{   0x0008, "delay (Delay)" },
	{0,     NULL},
};

static h248_pkg_stat_t h248_pkg_rtp_stat[] = {
	{ 0x0004, &hf_h248_pkg_rtp_stat_ps, &ett_h248_pkg_rtp, NULL,NULL},
};

/* Packet definitions */
static h248_package_t h248_pkg_rtp = {
	0x000c,
	&hf_h248_pkg_rtp,
	&ett_h248_pkg_rtp,
	h248_pkg_rtp_props_vals,
	NULL,
	NULL,
	NULL,
	NULL,						/* Properties */
	NULL,						/* signals */
	NULL,						/* events */
	h248_pkg_rtp_stat			/* statistics */
};

/* H.248.1 E.13 TDM Circuit Package */
static int hf_h248_pkg_tdmc = -1;
static int hf_h248_pkg_tdmc_ec = -1;
static int hf_h248_pkg_tdmc_gain = -1;

static gint ett_h248_pkg_tdmc = -1;

static const true_false_string h248_tdmc_ec_vals = {
	"On",
	"Off"
};
static const value_string h248_pkg_tdmc_props_vals[] = {
	{ 0x0000, "TDM Circuit Package - Annex E (tdmc)" },
	{ 0x0008, "Echo Cancellation (ec)"},
	{ 0x000a, "Gain Control (gain)"},
	{ 0, NULL}
};


static h248_pkg_param_t h248_pkg_tdmc_props[] = {
	{ 0x0008, &hf_h248_pkg_tdmc_ec, h248_param_ber_boolean, &h248_e_implicit },
	{ 0x000a, &hf_h248_pkg_tdmc_gain, h248_param_ber_integer, &h248_e_implicit },
	{ 0, NULL, NULL, NULL}
};

static h248_package_t h248_pkg_tdmc = {
	0x000d,
	&hf_h248_pkg_tdmc,
	&ett_h248_pkg_tdmc,
	h248_pkg_tdmc_props_vals,
	NULL,
	NULL,
	NULL,
	h248_pkg_tdmc_props,		/* Properties */
	NULL,						/* signals */
	NULL,						/* events */
	NULL						/* statistics */
};



void proto_register_h248_annex_e(void) {
	static hf_register_info hf[] = {
		/* H.248.1 E.1  Generic Package */
		{ &hf_h248_pkg_generic, { "Generic Package", "h248.generic", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_generic_cause_evt, { "Cause Event", "h248.generic.cause", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_generic_cause_gencause, { "Generic Cause", "h248.generic.cause.gencause", FT_UINT32, BASE_HEX, VALS(h248_pkg_generic_cause_gencause_vals), 0, NULL, HFILL }},
		{ &hf_h248_pkg_generic_cause_failurecause, { "Generic Cause", "h248.generic.cause.failurecause", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_generic_sc_evt, {"Signal Completion2","h248.generic.sc",FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}},
		{ &hf_h248_pkg_generic_sc_sig_id, { "Signal Identity", "h248.generic.sc.sig_id", FT_BYTES, BASE_NONE, NULL , 0, NULL, HFILL }},
		{ &hf_h248_pkg_generic_sc_meth, { "Termination Method", "h248.generic.sc.meth", FT_UINT32, BASE_DEC, VALS(h248_pkg_generic_sc_vals) , 0, NULL, HFILL }},
		{ &hf_h248_pkg_generic_sc_slid, { "Signal List ID", "h248.generic.sc.slid", FT_UINT32, BASE_DEC, NULL , 0, NULL, HFILL }},
		{ &hf_h248_pkg_generic_sc_rid, { "Request ID", "h248.generic.sc.rid", FT_UINT32, BASE_DEC,  NULL, 0, NULL, HFILL }},

		/* H.248.1.E 3 Tone Generator (tonegeg) */
		{ &hf_h248_pkg_tonegen, { "Tone Generator (tonegen)", "h248.tonegen", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_tonegen_sig_pt, { "Play Tone (pt)", "h248.tonegen.pg", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_tonegen_sig_pt_tl, { "Tone List ID (tl)", "h248.tonegen.pt.tl", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_tonegen_sig_pt_ind, { "Inter-signal Duration (ind)", "h248.tonegem.pt.ind", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_tonegen_sig_pg_btd, { "Tone Direction (btd)", "h248.tonegen.pt.btd", FT_UINT32, BASE_HEX, VALS(h248_pkg_tonegen_pt_btd_param_vals), 0, NULL, HFILL }},

		/* H.248.1 E.4 Tone Detection (tonedet) */
		{ &hf_h248_pkg_tonedet, { "Tone Detection Package", "h248.tonedet", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_tonedet_evt_std, { "Start Tone", "h248.tonedet.std", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_tonedet_evt_etd, { "End Tone", "h248.tonedet.etd",  FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_tonedet_evt_ltd, { "Long Tone", "h248.tonedet.ltd", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_tonedet_evt_tl_param, {"Tone Detail", "h248.tonedet.evt.tl", FT_UINT16, BASE_DEC, VALS(h248_pkg_tonedet_tl_params_vals), 0, NULL, HFILL }},
		{ &hf_h248_pkg_tonedet_evt_dur_param, {"Duration (ms)", "h248.tonedet.evt.dur", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_tonedet_evt_tid_param, {"Tone ID", "h248.tonedet.evt.tid", FT_UINT16, BASE_DEC, VALS(h248_pkg_tonedet_tl_params_vals), 0, NULL, HFILL }},


		/* H.248.1 E.5 Basic DTMF Generator Package */
		{ &hf_h248_pkg_dg, { "Basic DTMF Generator Package (dg)", "h248.dg", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_dg_sig_pt, { "Play Tone", "h248.dg.pt", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_dg_sig_d0, { "Digit 0", "h248.dg.d0", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_dg_sig_d1, { "Digit 1", "h248.dg.d1", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_dg_sig_d2, { "Digit 2", "h248.dg.d2", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_dg_sig_d3, { "Digit 3", "h248.dg.d3", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_dg_sig_d4, { "Digit 4", "h248.dg.d4", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_dg_sig_d5, { "Digit 5", "h248.dg.d5", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_dg_sig_d6, { "Digit 6", "h248.dg.d6", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_dg_sig_d7, { "Digit 7", "h248.dg.d7", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_dg_sig_d8, { "Digit 8", "h248.dg.d8", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_dg_sig_d9, { "Digit 9", "h248.dg.d9", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_dg_sig_da, { "Digit A", "h248.dg.da", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_dg_sig_db, { "Digit B", "h248.dg.db", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_dg_sig_dc, { "Digit C", "h248.dg.dc", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_dg_sig_dd, { "Digit D", "h248.dg.dd", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_dg_sig_ds, { "Digit *", "h248.dg.ds", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_dg_sig_do, { "Digit #", "h248.dg.do", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_dg_sig_params, { "Event Parameters", "h248.dg.signal.direction", FT_UINT16, BASE_DEC, VALS(h248_pkg_dg_sig_btd_vals), 0, NULL, HFILL }},

		/* H.248.1 E.6 DTMF Detection Package */
#if 0
		{ &hf_h248_pkg_dd_evt_ce_ds, { "Digit(s) Detected", "h248.dd.ce.ds", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_dd_evt_ce_meth, { "Method Used", "h248.dd.ce.meth", FT_UINT16, BASE_DEC, VALS(h248_pkg_dd_event_params_vals), 0, NULL, HFILL }},
		{ &hf_h248_pkg_dd_evt_tl_param, {"Tone Detail", "h248.dd.evt.tl", FT_UINT16, BASE_DEC, VALS(h248_pkg_dd_event_vals), 0, NULL, HFILL }},
		{ &hf_h248_pkg_dd_evt_dur_param, {"Duration (ms)", "h248.dd.evt.dur", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_dd_evt_tid_param, {"Tone ID", "h248.dd.evt.tid", FT_UINT16, BASE_DEC, VALS(h248_pkg_dd_event_vals), 0, NULL, HFILL }},
#endif

		/* H.248.1.E.7 Call Progress Tones Generator package */
		{ &hf_h248_pkg_cg, { "Call Progress Tones Generator", "h248.cg", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_cg_sig_pt, { "Play Tone (pt)", "h248.cg.pt", FT_UINT16, BASE_HEX, VALS(h248_pkg_cg_sig_cd_evt_vals), 0, NULL, HFILL }},
		{ &hf_h248_pkg_cg_sig_pt_tl, {"Tone List", "h248.cg.pt.tl", FT_UINT16, BASE_DEC_HEX, VALS(h248_pkg_cg_sig_cd_evt_vals), 0, NULL, HFILL }},
		{ &hf_h248_pkg_cg_sig_pt_ind, { "Inter-Signal Duration (ind)", "h248.cg.pt.ind", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_cg_sig_pt_btd, { "Tone Direction (btd)", "h248.cg.pt.btd", FT_UINT8, BASE_DEC, VALS(h248_pkg_cg_pt_btd_param_vals), 0, NULL, HFILL }},

		{ &hf_h248_pkg_cg_sig_dt, { "Dial Tone (dt)", "h248.cg.dt", FT_UINT16, BASE_HEX, VALS(h248_pkg_cg_sig_cd_evt_vals), 0, NULL, HFILL }},
		{ &hf_h248_pkg_cg_sig_rt, { "Ring Tone (rt)", "h248.cg.rt",FT_UINT16, BASE_HEX, VALS(h248_pkg_cg_sig_cd_evt_vals), 0, NULL, HFILL }},
		{ &hf_h248_pkg_cg_sig_bt, { "Buzy Tone (bt)", "h248.cg.bt", FT_UINT16, BASE_HEX, VALS(h248_pkg_cg_sig_cd_evt_vals), 0, NULL, HFILL }},
		{ &hf_h248_pkg_cg_sig_ct, { "Congestion Tone (ct)", "h248.cg.ct", FT_UINT16, BASE_HEX, VALS(h248_pkg_cg_sig_cd_evt_vals), 0, NULL, HFILL }},
		{ &hf_h248_pkg_cg_sig_sit, { "Special Information Tone (sit)", "h248.cg.sit", FT_UINT16, BASE_HEX, VALS(h248_pkg_cg_sig_cd_evt_vals), 0, NULL, HFILL }},
		{ &hf_h248_pkg_cg_sig_wt, { "(Recording) Warning Tone (wt)", "h248.cg.wt", FT_UINT16, BASE_HEX, VALS(h248_pkg_cg_sig_cd_evt_vals), 0, NULL, HFILL }},
		{ &hf_h248_pkg_cg_sig_prt, { "Payphone Recognition Tone (prt)", "h248.cg.prt", FT_UINT16, BASE_HEX, VALS(h248_pkg_cg_sig_cd_evt_vals), 0, NULL, HFILL }},
		{ &hf_h248_pkg_cg_sig_cw, { "Call Waiting Tone (wt)", "h248.cg.cw", FT_UINT16, BASE_HEX, VALS(h248_pkg_cg_sig_cd_evt_vals), 0, NULL, HFILL }},
		{ &hf_h248_pkg_cg_sig_cr, { "Caller Waiting Tone (rt)", "h248.cg.cr", FT_UINT16, BASE_HEX, VALS(h248_pkg_cg_sig_cd_evt_vals), 0, NULL, HFILL }},

		/* H.248.1 E.8 Call Progress Tones Detection Package */
		{ &hf_h248_pkg_cd, { "Call Progress Tones Detection Package", "h248.cd", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		/* H.248.1 E.9 Analog Line Supervision Package */
		{ &hf_h248_pkg_al, { "Analog Line Supervision Package", "h248.al", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_al_sig_cadence, { "Cadence", "h248.al.sig.cadence", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_al_sig_cadence_on_off, { "On/Off Cadence", "h248.al.sig.cadence_on_off", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
#if 0
		{ &hf_h248_pkg_al_sig_freq, { "Ring Frequency", "h248.al.sig.freq", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
#endif
		{ &hf_h248_pkg_al_evt_onhook, { "onhook", "h248.al.onhook", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_al_evt_offhook, { "offhook", "h248.al.offhook", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_al_evt_flashhook, { "flashhook", "h248.al.flashhook", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_al_evt_onhook_par_strict, { "strict", "h248.al.ev.onhook.strict", FT_UINT8, BASE_DEC, VALS(h248_pkg_al_evt_onhook_strict_vals), 0, NULL, HFILL }},
		{ &hf_h248_pkg_al_evt_onhook_par_init, { "init", "h248.al.ev.onhook.init", FT_BOOLEAN, BASE_NONE, TFS(&h248_pkg_al_evt_onhook_par_init_vals), 0x0, NULL, HFILL }},
		{ &hf_h248_pkg_al_evt_offhook_par_strict, { "strict", "h248.al.ev.offhook.strict", FT_UINT8, BASE_DEC, VALS(h248_pkg_al_evt_onhook_strict_vals), 0, NULL, HFILL }},
		{ &hf_h248_pkg_al_evt_offhook_par_init, { "init", "h248.al.ev.onhook.init", FT_BOOLEAN, BASE_NONE, TFS(&h248_pkg_al_evt_offhook_par_init_vals), 0x0, NULL, HFILL }},
		{ &hf_h248_pkg_al_evt_flashhook_par_mindur, { "Minimum duration in ms", "h248.al.ev.flashhook.mindur", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		/* H.248.1 E.10 - Basic Continuity Package */
		{ &hf_h248_pkg_ct, { "Basic Continuity package", "h248.ct", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		/* H.248.1 E.11 Network Package */
		{ &hf_h248_pkg_nt, { "Network package", "h248.nt", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		/* H.248.1 E.12 RTP package */
		{ &hf_h248_pkg_rtp, { "RTP package", "h248.rtp", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_rtp_stat_ps, { "Packets Sent", "h248.rtp.stat.ps", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }},

		/* H.248.1 E.13 TDM Circuit Package */
		{ &hf_h248_pkg_tdmc, { "TDM Circuit Package", "h248.tdmc", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_tdmc_ec, { "Echo Cancellation", "h248.tdmc.ec", FT_BOOLEAN, BASE_NONE, TFS(&h248_tdmc_ec_vals), 0x0, NULL, HFILL }},
		{ &hf_h248_pkg_tdmc_gain, { "Gain", "h248.tdmc.gain", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	};

	static gint *ett[] = {
		/* generic 0x0001 */
		&ett_h248_pkg_generic_cause_evt,
		&ett_h248_pkg_generic,
		&ett_h248_pkg_generic_sc_evt,

#if 0
		&ett_h248_pkg_root_params,
#endif

		&ett_h248_pkg_tonegen_params,

		/* tonegen 0x0003 */
		&ett_h248_pkg_tonedet,
		&ett_h248_pkg_tonedet_evt_std,
		&ett_h248_pkg_tonedet_evt_etd,
		&ett_h248_pkg_tonedet_evt_ltd,

        /* dg 0x0005 */
		&ett_h248_pkg_dg,
		&ett_h248_pkg_dg_sig_pt,
		&ett_h248_pkg_dg_sig_d0,
		&ett_h248_pkg_dg_sig_d1,
		&ett_h248_pkg_dg_sig_d2,
		&ett_h248_pkg_dg_sig_d3,
		&ett_h248_pkg_dg_sig_d4,
		&ett_h248_pkg_dg_sig_d5,
		&ett_h248_pkg_dg_sig_d6,
		&ett_h248_pkg_dg_sig_d7,
		&ett_h248_pkg_dg_sig_d8,
		&ett_h248_pkg_dg_sig_d9,
		&ett_h248_pkg_dg_sig_da,
		&ett_h248_pkg_dg_sig_db,
		&ett_h248_pkg_dg_sig_dc,
		&ett_h248_pkg_dg_sig_dd,
		&ett_h248_pkg_dg_sig_ds,
		&ett_h248_pkg_dg_sig_do,

		/* dd 0x0006 */
#if 0
		&ett_h248_pkg_dd,
		&ett_h248_pkg_dd_evt_std,
		&ett_h248_pkg_dd_evt_ltd,
		&ett_h248_pkg_dd_evt_etd,
		&ett_h248_pkg_dd_evt_ce,
#endif

		/* 0x0007 Package cg */
		&ett_h248_pkg_cg_params,
		&ett_h248_pkg_cg_sig_pt,
		&ett_h248_pkg_tonegen_sig_pt,
		&ett_h248_pkg_cg_sig_dt,
		&ett_h248_pkg_cg_sig_rt,
		&ett_h248_pkg_cg_sig_bt,
		&ett_h248_pkg_cg_sig_ct,
		&ett_h248_pkg_cg_sig_sit,
		&ett_h248_pkg_cg_sig_wt,
		&ett_h248_pkg_cg_sig_prt,
		&ett_h248_pkg_cg_sig_cw,
		&ett_h248_pkg_cg_sig_cr,

		/* cd 0x0008 */
		&ett_h248_pkg_cd,

		/* al 0x0009 */
		&ett_h248_pkg_al,
		&ett_h248_pkg_al_sig_cadence,
		&ett_h248_pkg_al_sig_freq,
		&ett_h248_pkg_al_evt_flashhook,
		&ett_h248_pkg_al_evt_offhook,
		&ett_h248_pkg_al_evt_onhook,

		/* ct 0x000a */
		&ett_h248_pkg_ct,

		/* nt 0x000b */
		&ett_h248_pkg_nt,

		/* rtp 0x000c */
		&ett_h248_pkg_rtp,

		/* tdmc 0x000d */
		&ett_h248_pkg_tdmc
	};

	proto_h248_annex_E = proto_register_protocol(PNAME, PSNAME, PFNAME);

	proto_register_field_array(proto_h248_annex_E, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));

	/* MERGE_PKG_LOW is use to allow other custom version of these
	 *H248 package to take presidence if already loaded */
	h248_register_package(&h248_pkg_generic,MERGE_PKG_LOW);		/* 0x0001 */
/*	h248_register_package(&h248_pkg_root,MERGE_PKG_LOW); */		/* 0x0002 */
	h248_register_package(&h248_pkg_tonegen,MERGE_PKG_LOW);		/* 0x0003 */
	h248_register_package(&h248_pkg_tonedet,MERGE_PKG_LOW);		/* 0x0004 */
	h248_register_package(&h248_pkg_dg,MERGE_PKG_LOW);		/* 0X0005 */
/*	h248_register_package(&h248_pkg_dd,MERGE_PKG_LOW); */		/* 0x0006 */
	h248_register_package(&h248_pkg_cg,MERGE_PKG_LOW);		/* 0x0007 */
	h248_register_package(&h248_pkg_cd, MERGE_PKG_LOW);		/* 0x0008 */
	h248_register_package(&h248_pkg_al,MERGE_PKG_LOW);		/* 0x0009 */
	h248_register_package(&h248_pkg_ct, MERGE_PKG_LOW);		/* 0x000a */
	h248_register_package(&h248_pkg_nt, MERGE_PKG_LOW);		/* 0x000b */
	h248_register_package(&h248_pkg_rtp,MERGE_PKG_LOW);		/* 0x000c */
	h248_register_package(&h248_pkg_tdmc,MERGE_PKG_LOW);		/* 0x000d */
}


