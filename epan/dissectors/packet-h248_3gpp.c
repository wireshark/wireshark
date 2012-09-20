/*
 *  packet-h248_3gpp.c
 *  3GPP H.248 Packages
 *
 *  (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
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
#define PNAME  "H.248 3GPP"
#define PSNAME "H2483GPP"
#define PFNAME "h248.3gpp"

#include "packet-isup.h"

/*
 * 3GUP Package
 * 3GPP TS 29.232 -- 15.1.1
 */
static int hf_h248_package_3GUP = -1;

static int hf_h248_package_3GUP_Mode = -1;
static int hf_h248_package_3GUP_UPversions = -1;
static int hf_h248_package_3GUP_delerrsdu = -1;
static int hf_h248_package_3GUP_interface = -1;
static int hf_h248_package_3GUP_initdir = -1;

static gint ett_h248_package_3GUP = -1;

static gboolean implicit = FALSE;

static const value_string h248_3GUP_properties_vals[] = {
	{ 0x0000, "threegup (3G User Plane)" },
	{ 0x0001, "Mode" },
	{ 0x0002, "Versions" },
	{ 0x0003, "delerrsdu" },
	{ 0x0004, "interface" },
	{ 0x0005, "initdir" },
	{0,     NULL}
};

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
	{   0x0002, "CN (Nb interface)" },
	{0,     NULL}
};

static const value_string h248_3GUP_initdir_vals[] = {
	{   0x0001, "Incoming" },
	{   0x0002, "Outgoing" },
	{0,     NULL}
};

static const value_string h248_3GUP_parameters[] _U_ = {
	{   0x0001, "Mode" },
	{   0x0002, "UPversions" },
	{   0x0003, "Delivery of erroneous SDUs" },
	{   0x0004, "Interface" },
	{   0x0005, "Initialisation Direction" },
	{0,     NULL}
};

static const h248_pkg_param_t h248_package_3GUP_properties[] = {
	{ 0x0001, &hf_h248_package_3GUP_Mode, h248_param_ber_integer, &implicit },
	{ 0x0002, &hf_h248_package_3GUP_UPversions, h248_param_ber_integer, &implicit },
	{ 0x0003, &hf_h248_package_3GUP_delerrsdu, h248_param_ber_integer, &implicit },
	{ 0x0004, &hf_h248_package_3GUP_interface, h248_param_ber_integer, &implicit },
	{ 0x0005, &hf_h248_package_3GUP_initdir, h248_param_ber_integer, &implicit },
	{ 0x0000, NULL, NULL, NULL }
};

static const h248_package_t h248_package_3GUP = {
	0x002f,
	&hf_h248_package_3GUP,
	&ett_h248_package_3GUP,
	h248_3GUP_properties_vals,
	NULL,
	NULL,
	NULL,
	h248_package_3GUP_properties,
	NULL,
	NULL,
	NULL
};


/*
 * Circuit Switched Data package
 * 3GPP TS 29.232 -- 15.2.1
 */

static int hf_h248_package_3GCSD = -1;

static int hf_h248_package_3GCSD_plmnbc = -1;
static int hf_h248_package_3GCSD_gsmchancod = -1;
static int hf_h248_pkg_3GCSD_evt_protres = -1;
static int hf_h248_pkg_3GCSD_evt_protres_result = -1;
static int hf_h248_pkg_3GCSD_evt_protres_cause = -1;
static int hf_h248_pkg_3GCSD_evt_ratechg = -1;
static int hf_h248_pkg_3GCSD_evt_ratechg_rate = -1;
static int hf_h248_pkg_3GCSD_sig_actprot = -1;
static int hf_h248_pkg_3GCSD_actprot_sig_localpeer = -1;

static gint ett_h248_package_3GCSD = -1;
static gint ett_h248_3GCSD_evt_protres = -1;
static gint ett_h248_3GCSD_evt_ratechg = -1;
static gint ett_pkg_3GCSD_sig_actprot = -1;

static const value_string h248_3GCSD_properties_vals[] = {
	{ 0x0001, "plmnbc"},
	{ 0x0002, "gsmchancod"},
	{0,     NULL}
};

static const value_string h248_3GCSD_signals_vals[] _U_ = {
	{ 0x0001, "actprot" },
	{0,     NULL}
};

static const value_string h248_3GCSD_signal_actprot_vals[] = {
	{ 0x0001, "localpeer" },
	{0,     NULL}
};

static const value_string h248_3GCSD_events_vals[] _U_ = {
	{ 0x0001, "protres"},
	{ 0x0002, "ratechg"},
	{0,     NULL}
};

static const value_string h248_3GCSD_event_protres_vals[] = {
	{ 0x0001, "result"},
	{ 0x0002, "cause"},
	{0,     NULL}
};

static const value_string h248_3GCSD_event_ratechg_vals[] = {
	{ 0x0001, "rate"},
	{0,     NULL}
};

static const value_string h248_3GCSD_evt_protres_result_vals[] = {
	{1,"Success"},
	{0,"Failure"},
	{0,NULL}
};

static const value_string h248_3GCSD_evt_protres_cause_vals[] = {
	{1,"Unsp"},
	{2,"V8V34"},
	{0,NULL}
};

static const value_string h248_3GCSD_actprot_sig_localpeer_vals[] = {
	{0,"Orig"},
	{1,"Term"},
	{0,NULL}
};

static const h248_pkg_param_t h248_package_3GCSD_props[] = {
	{ 0x0001, &hf_h248_package_3GCSD_plmnbc, h248_param_ber_octetstring, &implicit},
	{ 0x0002, &hf_h248_package_3GCSD_gsmchancod, h248_param_ber_octetstring, &implicit },
	{ 0x0000, NULL, NULL, NULL }
};

static const h248_pkg_param_t h248_pkg_3GCSD_evt_protres_params[] = {
	{ 0x0001, &hf_h248_pkg_3GCSD_evt_protres_result, h248_param_ber_integer, &implicit },
	{ 0x0002, &hf_h248_pkg_3GCSD_evt_protres_cause, h248_param_ber_integer, &implicit },
	{ 0, NULL, NULL, NULL}
};

static const h248_pkg_param_t h248_pkg_3GCSD_evt_ratechg_params[] = {
	{ 0x0001, &hf_h248_pkg_3GCSD_evt_ratechg_rate, h248_param_ber_integer, &implicit },
	{ 0, NULL, NULL, NULL}
};

static const h248_pkg_evt_t h248_package_3GCSD_evts[] = {
	{ 0x0001, &hf_h248_pkg_3GCSD_evt_protres, &ett_h248_3GCSD_evt_protres, h248_pkg_3GCSD_evt_protres_params, h248_3GCSD_event_protres_vals},
	{ 0x0002, &hf_h248_pkg_3GCSD_evt_ratechg, &ett_h248_3GCSD_evt_ratechg, h248_pkg_3GCSD_evt_ratechg_params, h248_3GCSD_event_ratechg_vals},
	{ 0, NULL, NULL, NULL,NULL}
};

static const h248_pkg_param_t h248_pkg_3GCSD_actprot_sig_params[] = {
	{ 0x0001, &hf_h248_pkg_3GCSD_actprot_sig_localpeer, h248_param_ber_integer, &implicit },
	{ 0, NULL, NULL, NULL}
};

static const h248_pkg_sig_t h248_package_3GCSD_sigs[] = {
	{ 0x0010, &hf_h248_pkg_3GCSD_sig_actprot, &ett_pkg_3GCSD_sig_actprot, h248_pkg_3GCSD_actprot_sig_params, h248_3GCSD_signal_actprot_vals },
	{ 0, NULL, NULL, NULL,NULL}
};

static const h248_package_t h248_package_3GCSD = {
	0x0030,
	&hf_h248_package_3GCSD,
	&ett_h248_package_3GCSD,
	h248_3GCSD_properties_vals,
	NULL,
	NULL,
	NULL,
	h248_package_3GCSD_props,
	h248_package_3GCSD_sigs,
	h248_package_3GCSD_evts,
	NULL
};


/*
 * TFO package
 * 3GPP TS 29.232 -- 15.2.2
 */
static int hf_h248_package_3GTFO = -1;

static int hf_h248_pkg_3GTFO_evt_codec_modify = -1;
static int hf_h248_pkg_3GTFO_evt_distant_codec_list = -1;
static int hf_h248_pkg_3GTFO_evt_status = -1;
static int hf_h248_pkg_3GTFO_enable = -1;
static int hf_h248_pkg_3GTFO_codeclist = -1;
static int hf_h248_pkg_3GTFO_evt_codec_modify_optimalcodec = -1;
static int hf_h248_pkg_3GTFO_evt_distant_codec_list_distlist = -1;
static int hf_h248_pkg_3GTFO_evt_status_tfostatus = -1;

static gint ett_h248_package_3GTFO = -1;
static gint ett_h248_3GTFO_evt_status = -1;
static gint ett_h248_3GTFO_evt_distant_codec_list = -1;
static gint ett_h248_3GTFO_evt_codec_modify = -1;
static gint ett_h248_3GTFO_codec_list = -1;
static gint ett_h248_3GTFO_codec = -1;


static void dissect_3GTFO_codec_mode(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, int hfid, h248_curr_info_t* cu _U_, void* ignored _U_) {
	tvbuff_t* sub_tvb = NULL;
	gint8 class;
	gboolean pc;
	gint32 tag;
	asn1_ctx_t asn1_ctx;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	get_ber_identifier(tvb, 0, &class, &pc, &tag);

	/* XXX: is this enough to guess it? */
	if (tag==BER_UNI_TAG_OCTETSTRING) {
		dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, 0, hfid, &sub_tvb );

		if (sub_tvb) {
			proto_tree* pt = proto_item_add_subtree(asn1_ctx.created_item, ett_h248_3GTFO_codec);
			dissect_codec_mode(pt, sub_tvb, 0, tvb_length(tvb));
		}
	} else {
		proto_tree_add_item(tree,hfid,tvb,0,-1,ENC_NA);
	}

}

static void dissect_3GTFO_codec_list(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, int hfid, h248_curr_info_t* cu _U_, void* ignored _U_) {
	tvbuff_t* sub_tvb = NULL;
	gint8 class;
	gboolean pc;
	gint32 tag;
	asn1_ctx_t asn1_ctx;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	get_ber_identifier(tvb, 0, &class, &pc, &tag);

	if (tag==BER_UNI_TAG_OCTETSTRING) {
		dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, 0, hfid, &sub_tvb );

		if (sub_tvb) {
			proto_tree* pt = proto_item_add_subtree(asn1_ctx.created_item,ett_h248_3GTFO_codec_list);
			int len = tvb_length(sub_tvb);
			int offset = 0;
			do {
				offset = dissect_codec_mode(pt, sub_tvb, offset, len);
			} while(offset < len);
		}
	} else {
		proto_tree_add_item(tree,hfid,tvb,0,-1,ENC_NA);
	}
}


static const value_string h248_package_3GTFO_props_vals[] = {
	{1,"enable"},
	{2,"codeclist"},
	{0,NULL}
};

static const value_string h248_pkg_3GTFO_evt_codec_modify_params_vals[] = {
	{11,"optimalcodec"},
	{0,NULL}
};


static const value_string h248_pkg_3GTFO_evt_distant_codec_list_params_vals[] = {
	{13,"distlist"},
	{0,NULL}
};

static const value_string h248_pkg_3GTFO_evt_status_params_vals[] = {
	{1,"tfostatus"},
	{0,NULL}
};


static const value_string h248_package_3GTFO_evts_vals[] = {
	{10,"codec_modify"},
	{12,"distant_codec_list"},
	{14,"status"},
	{0,NULL}
};

static const value_string tfoenable_vals[] = {
	{1,"On"},
	{2,"Off"},
	{0,NULL}
};

static const h248_pkg_param_t h248_package_3GTFO_props[] = {
	{ 0x0001, &hf_h248_pkg_3GTFO_enable, h248_param_ber_integer, &implicit },
	{ 0x0002, &hf_h248_pkg_3GTFO_codeclist, dissect_3GTFO_codec_list, NULL }, /* Sub-list of Octet string Q.765.5 + TS 26.103 .*/
	{ 0, NULL, NULL, NULL}
};


static const h248_pkg_param_t h248_pkg_3GTFO_evt_codec_modify_params[] = {
	{ 0x0011, &hf_h248_pkg_3GTFO_evt_codec_modify_optimalcodec, dissect_3GTFO_codec_mode, NULL }, /* Q.765.5 + TS 26.103 .*/
	{ 0, NULL, NULL, NULL}
};


static const h248_pkg_param_t h248_pkg_3GTFO_evt_distant_codec_list_params[] = {
	{ 0x0013, &hf_h248_pkg_3GTFO_evt_distant_codec_list_distlist, dissect_3GTFO_codec_list, NULL }, /* Sub-list of Octet string Q.765.5 + TS 26.103 .*/
	{ 0, NULL, NULL, NULL}
};

static const h248_pkg_param_t h248_pkg_3GTFO_evt_status_params[] = {
	{ 0x0001, &hf_h248_pkg_3GTFO_evt_status_tfostatus, h248_param_ber_boolean, &implicit },
	{ 0, NULL, NULL, NULL}
};

static const h248_pkg_evt_t h248_package_3GTFO_evts[] = {
	{ 0x0010, &hf_h248_pkg_3GTFO_evt_codec_modify, &ett_h248_3GTFO_evt_codec_modify, h248_pkg_3GTFO_evt_codec_modify_params, h248_pkg_3GTFO_evt_codec_modify_params_vals},
	{ 0x0012, &hf_h248_pkg_3GTFO_evt_distant_codec_list, &ett_h248_3GTFO_evt_distant_codec_list, h248_pkg_3GTFO_evt_distant_codec_list_params, h248_pkg_3GTFO_evt_distant_codec_list_params_vals},
	{ 0x0014, &hf_h248_pkg_3GTFO_evt_status, &ett_h248_3GTFO_evt_status, h248_pkg_3GTFO_evt_status_params, h248_pkg_3GTFO_evt_status_params_vals},
	{ 0, NULL, NULL, NULL,NULL}
};

static const h248_package_t h248_package_3GTFO = {
	0x0031,
	&hf_h248_package_3GTFO,
	&ett_h248_package_3GTFO,
	h248_package_3GTFO_props_vals,
	NULL,
	h248_package_3GTFO_evts_vals,
	NULL,
	h248_package_3GTFO_props,
	NULL,
	h248_package_3GTFO_evts,
	NULL};

/*
 * 3G Expanded Call Progress Tones Generator Package
 * 3GPP TS 29.232 -- 15.2.3
 */
/*
 * Modification Of Link Characteristics Bearer Capability
 * 3GPP TS 29.232 -- 15.2.4
 */
/*
 * Enhanced Circuit Switched Data package
 * 3GPP TS 29.232 -- 15.2.5
 */
/*
 * Cellular Text telephone Modem Text Transport
 * 3GPP TS 29.232 -- 15.2.6
 */
/*
 * IP transport package
 * 3GPP TS 29.232 -- 15.2.7
 */
/*
 * Flexible Tone Generator Package
 * 3GPP TS 29.232 -- 15.2.8
 */
/*
 * Trace Package
 * 3GPP TS 29.232 -- 15.2.9
 */
/*
 * ASCI Group call package
 * 3GPP TS 29.232 -- 15.2.10
 */


void proto_register_h248_3gpp(void) {
	static hf_register_info hf[] = {
		{ &hf_h248_package_3GUP_Mode,
		{ "Mode", "h248.package_3GUP.Mode",
			FT_UINT32, BASE_DEC, VALS(h248_3GUP_Mode_vals), 0,
			NULL, HFILL }},
		{ &hf_h248_package_3GUP_UPversions,
		{ "UPversions", "h248.package_3GUP.upversions",
			FT_UINT32, BASE_DEC, VALS(h248_3GUP_upversions_vals), 0,
			NULL, HFILL }},
		{ &hf_h248_package_3GUP_delerrsdu,
		{ "Delivery of erroneous SDUs", "h248.package_3GUP.delerrsdu",
			FT_UINT32, BASE_DEC, VALS(h248_3GUP_delerrsdu_vals), 0,
			NULL, HFILL }},
		{ &hf_h248_package_3GUP_interface,
		{ "Interface", "h248.package_3GUP.interface",
			FT_UINT32, BASE_DEC, VALS(h248_3GUP_interface_vals), 0,
			NULL, HFILL }},
		{ &hf_h248_package_3GUP_initdir,
		{ "Initialisation Direction", "h248.package_3GUP.initdir",
			FT_UINT32, BASE_DEC, VALS(h248_3GUP_initdir_vals), 0,
			NULL, HFILL }},


		{ &hf_h248_package_3GCSD,
		{ "CSD Package", "h248.package_3GCSD",
			FT_BYTES, BASE_NONE, NULL, 0,
			"Circuit Switched Data Package", HFILL }},
		{ &hf_h248_package_3GCSD_plmnbc,
		{ "PLMN Bearer Capability", "h248.package_3GCSD.plmnbc",
			FT_BYTES, BASE_NONE, NULL, 0,
			"The PLMN Bearer Capability", HFILL }},
		{ &hf_h248_package_3GCSD_gsmchancod,
		{ "GSM channel coding", "h248.package_3GCSD.gsmchancod",
			FT_BYTES, BASE_NONE, NULL, 0,
			"Channel information needed for GSM", HFILL }},
		{ &hf_h248_pkg_3GCSD_evt_protres,
		{ "Protocol Negotiation Result", "h248.package_3GCSD.protres",
			FT_BYTES, BASE_NONE, NULL, 0,
			"This event is used to report the result of the protocol negotiation", HFILL }},
		{ &hf_h248_pkg_3GCSD_evt_protres_result,
		{ "Negotiation Result", "h248.package_3GCSD.protres.result",
			FT_UINT32, BASE_DEC, VALS(h248_3GCSD_evt_protres_result_vals), 0,
			"reports whether the protocol negotiation has been successful", HFILL }},
		{ &hf_h248_pkg_3GCSD_evt_protres_cause,
		{ "Possible Failure Cause", "h248.package_3GCSD.protres.cause",
			FT_UINT32, BASE_DEC, VALS(h248_3GCSD_evt_protres_cause_vals), 0,
			"indicates the possible failure cause", HFILL }},
		{ &hf_h248_pkg_3GCSD_evt_ratechg,
		{ "Rate Change", "h248.package_3GCSD.ratechg",
			FT_BYTES, BASE_NONE, NULL, 0,
			"This event is used to report a rate change", HFILL }},
		{ &hf_h248_pkg_3GCSD_evt_ratechg_rate,
		{ "New Rate", "h248.package_3GCSD.ratechg.rate",
			FT_UINT32, BASE_DEC, NULL, 0,
			"reports the new rate for the termination", HFILL }},
		{ &hf_h248_pkg_3GCSD_sig_actprot,
		{ "Activate Protocol", "h248.package_3GCSD.actprot",
			FT_BYTES, BASE_NONE, NULL, 0,
			"Activate the higher layer protocol", HFILL }},
		{ &hf_h248_pkg_3GCSD_actprot_sig_localpeer,
		{ "Local Peer Role", "h248.package_3GCSD.actprot.localpeer",
			FT_UINT32, BASE_DEC, VALS(h248_3GCSD_actprot_sig_localpeer_vals), 0,
			"It is used to inform the modem whether it should act as originating or terminating peer", HFILL }},


		{ &hf_h248_package_3GTFO,
		{ "Tandem Free Operation", "h248.package_3GTFO",
			FT_BYTES, BASE_NONE, NULL, 0,
			"This package defines events and properties for Tandem Free Operation (TFO) control", HFILL }},
		{ &hf_h248_pkg_3GTFO_enable,
		{ "TFO Activity Control", "h248.package_3GTFO.tfoenable",
			FT_UINT32, BASE_DEC, VALS(tfoenable_vals), 0,
			"Defines if TFO is enabled or not", HFILL }},
		{ &hf_h248_pkg_3GTFO_codeclist,
		{ "TFO Codec List", "h248.package_3GTFO.codeclist",
			FT_BYTES, BASE_NONE, NULL, 0,
			"List of codecs for use in TFO protocol", HFILL }},

		{ &hf_h248_pkg_3GTFO_evt_codec_modify,
		{ "Optimal Codec Event", "h248.package_3GTFO.codec_modify",
			FT_BYTES, BASE_NONE, NULL, 0,
			"The event is used to notify the MGC that TFO negotiation has resulted in an optimal codec type being proposed", HFILL }},
		{ &hf_h248_pkg_3GTFO_evt_codec_modify_optimalcodec,
		{ "Optimal Codec Type", "h248.package_3GTFO.codec_modify.optimalcodec",
			FT_BYTES, BASE_NONE, NULL, 0,
			"indicates which is the proposed codec type for TFO", HFILL }},

		{ &hf_h248_pkg_3GTFO_evt_distant_codec_list,
		{ "Codec List Event", "h248.package_3GTFO.distant_codec_list",
			FT_BYTES, BASE_NONE, NULL, 0,
			"The event is used to notify the MGC of the distant TFO partner's supported codec list", HFILL }},

		{ &hf_h248_pkg_3GTFO_evt_distant_codec_list_distlist,
		{ "Distant Codec List", "h248.package_3GTFO.distant_codec_list.distlist",
			FT_BYTES, BASE_NONE, NULL, 0,
			"indicates the codec list for TFO", HFILL }},

		{ &hf_h248_pkg_3GTFO_evt_status,
		{ "TFO Status Event", "h248.package_3GTFO.status",
			FT_BYTES, BASE_NONE, NULL, 0,
			"The event is used to notify the MGC that a TFO link has been established or broken", HFILL }},
		{ &hf_h248_pkg_3GTFO_evt_status_tfostatus,
		{ "TFO Status", "h248.package_3GTFO.status.tfostatus",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"reports whether TFO has been established or broken", HFILL }},
	};

	static gint *ett[] = {
		&ett_h248_package_3GUP,
		&ett_h248_package_3GCSD,
		&ett_h248_3GCSD_evt_protres,
		&ett_h248_3GCSD_evt_ratechg,
		&ett_h248_package_3GTFO,
		&ett_h248_3GTFO_evt_status,
		&ett_h248_3GTFO_evt_distant_codec_list,
		&ett_h248_3GTFO_evt_codec_modify,
		&ett_h248_3GTFO_codec_list,
		&ett_h248_3GTFO_codec,
		&ett_pkg_3GCSD_sig_actprot
	};

	hf_h248_package_3GUP = proto_register_protocol(PNAME, PSNAME, PFNAME);

	proto_register_field_array(hf_h248_package_3GUP, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));

	h248_register_package(&h248_package_3GUP,REPLACE_PKG);
	h248_register_package(&h248_package_3GCSD, REPLACE_PKG);
	h248_register_package(&h248_package_3GTFO, REPLACE_PKG);
}

