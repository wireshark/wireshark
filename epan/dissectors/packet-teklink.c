/* packet-teklink.c
 * Routines for TEKLINK dissection
 * Copyright (c)2010 Sven Schnelle <svens@stackframe.org>
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

#include "packet-rpc.h"

#define PROGRAM_TEKLINK 0x20400034

static int proto_teklink = -1;
static int hf_teklink_procedure = -1;
static int hf_teklink_unknown_long = -1;
static int hf_teklink_unknown_string = -1;
static int hf_teklink_cmd = -1;
static int hf_teklink_user = -1;
static int hf_teklink_host = -1;
static int hf_teklink_location = -1;
static int hf_teklink_tla_type = -1;
static int hf_teklink_locked = -1;
static int hf_teklink_vtc_srcnames = -1;
static int hf_teklink_vtc_dstnames = -1;
static int hf_teklink_vtc_sigpol = -1;
static int hf_teklink_vtc_sigen = -1;
static int hf_teklink_vtc_clksource = -1;
static int hf_teklink_vtc_clkmode = -1;
static int hf_teklink_vtc_clkedge = -1;
static int hf_teklink_vtc_mode = -1;
static int hf_teklink_vtc_edge = -1;
static int hf_teklink_vtc_sigfeedback = -1;

static gint ett_teklink = -1;

static const value_string teklink_vtc_srcnames[] = {
	{ 0, "VTC_SRC_APPSIG0" },
	{ 1, "VTC_SRC_APPSIG1" },
	{ 2, "VTC_SRC_APPSIG2" },
	{ 3, "VTC_SRC_APPSIG3" },
	{ 4, "VTC_SRC_APPSIG4" },
	{ 5, "VTC_SRC_APPSIG5" },
	{ 6, "VTC_SRC_APPSIG6" },
	{ 7, "VTC_SRC_APPSIG7" },
	{ 8, "VTC_SRC_APPSIG8" },
	{ 9, "VTC_SRC_APPSIG9" },
	{ 10, "VTC_SRC_APPSIG10" },
	{ 11, "VTC_SRC_APPSIG11" },
	{ 12, "VTC_SRC_TTLTRIG0" },
	{ 13, "VTC_SRC_TTLTRIG1" },
	{ 14, "VTC_SRC_TTLTRIG2" },
	{ 15, "VTC_SRC_TTLTRIG3" },
	{ 16, "VTC_SRC_TTLTRIG4" },
	{ 17, "VTC_SRC_TTLTRIG5" },
	{ 18, "VTC_SRC_TTLTRIG6" },
	{ 19, "VTC_SRC_TTLTRIG7" },
	{ 20, "VTC_SRC_XBAR1" },
	{ 21, "VTC_SRC_XBAR2" },
	{ 22, "VTC_SRC_ECLTRIG0" },
	{ 23, "VTC_SRC_ECLTRIG1" },
	{ 24, "VTC_SRC_ALL" },
	{ 25, "VTC_SRC_XXX" },
	{ 26, "VTC_SRC_XXX" },
	{ 27, "VTC_SRC_VCC" },
	{ 0, NULL },
};

static const value_string teklink_vtc_dstnames[] = {
	{ 0, "VTC_DST_APPSIG0" },
	{ 1, "VTC_DST_APPSIG1" },
	{ 2, "VTC_DST_APPSIG2" },
	{ 3, "VTC_DST_APPSIG3" },
	{ 4, "VTC_DST_APPSIG4" },
	{ 5, "VTC_DST_APPSIG5" },
	{ 6, "VTC_DST_APPSIG6" },
	{ 7, "VTC_DST_APPSIG7" },
	{ 8, "VTC_DST_APPSIG8" },
	{ 9, "VTC_DST_APPSIG9" },
	{ 10, "VTC_DST_APPSIG10" },
	{ 11, "VTC_DST_APPSIG11" },
	{ 12, "VTC_DST_TTLTRIG0" },
	{ 13, "VTC_DST_TTLTRIG1" },
	{ 14, "VTC_DST_TTLTRIG2" },
	{ 15, "VTC_DST_TTLTRIG3" },
	{ 16, "VTC_DST_TTLTRIG4" },
	{ 17, "VTC_DST_TTLTRIG5" },
	{ 18, "VTC_DST_TTLTRIG6" },
	{ 19, "VTC_DST_TTLTRIG7" },
	{ 20, "VTC_DST_XBAR1" },
	{ 21, "VTC_DST_XBAR2" },
	{ 22, "VTC_DST_ECLTRIG0" },
	{ 23, "VTC_DST_ECLTRIG1" },
	{ 24, "VTC_DST_ALL" },
	{ 0, NULL },
};

static const value_string teklink_vtc_sigen[] = {
	{ 0, "VTC_OUT_FORCE_OFF" },
	{ 1, "VTC_OUT_FORCE_ON" },
	{ 0, NULL },
};

static const value_string teklink_vtc_sigfeedback[] = {
	{ 0, "VTC_MODE_FEEDBK_OFF" },
	{ 1, "VTC_MODE_FEEDBK_ON" },
	{ 0, NULL },
};

static const value_string teklink_vtc_edge[] = {
	{ 0, "VTC_MODE_EDGE_FALL" },
	{ 1, "VTC_MODE_EDGE_RISE" },
	{ 0, NULL },
};

static const value_string teklink_vtc_sigpol[] = {
	{ 0, "VTC_OUT_POL_NORM" },
	{ 1, "VTC_OUT_POL_INVERT" },
	{ 0, NULL },
};

static const value_string teklink_vtc_clkmode[] = {
	{ 0, "VTC_CLK_MODE_ASYNCH" },
	{ 1, "VTC_CLK_MODE_SYNCH" },
	{ 0, NULL },
};

static const value_string teklink_vtc_clkedge[] = {
	{ 0, "VTC_CLK_EDGE_SENS_FALL" },
	{ 1, "VTC_CLK_EDGE_SENS_RISE" },
	{ 0, NULL },
};

static const value_string teklink_vtc_clksource[] = {
	{ 0, "VTC_CLK_SRC_GND" },
	{ 1, "VTC_CLK_SRC_1" },
	{ 2, "VTC_CLK_SRC_2" },
	{ 3, "VTC_CLK_SRC_CPUCLK" },
	{ 0, NULL },
};

static const value_string teklink_vtc_modes[] = {
	{ 0, "VTC_MODE_NONE" },
	{ 1, "VTC_MODE_1" },
	{ 2, "VTC_MODE_2" },
	{ 3, "VTC_MODE_3" },
	{ 4, "VTC_MODE_4" },
	{ 5, "VTC_MODE_5" },
	{ 6, "VTC_MODE_6" },
	{ 7, "VTC_MODE_EVENT_CNT_LAT" },
	{ 0, NULL },
};

static int dissect_teklink_tlaframeopen_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_unknown_long, offset);
	offset = dissect_rpc_string(tvb, tree, hf_teklink_unknown_string, offset, NULL);
	offset = dissect_rpc_string(tvb, tree, hf_teklink_unknown_string, offset, NULL);
	offset = dissect_rpc_string(tvb, tree, hf_teklink_unknown_string, offset, NULL);
	return offset;
}

static int dissect_teklink_tlaframeclose_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_unknown_long, offset);
	return offset;
}

static int dissect_teklink_tlaframeclose_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_unknown_long, offset);
	return offset;
}

static int dissect_teklink_tlaframeopen_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_unknown_long, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_unknown_long, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_unknown_long, offset);
	return offset;
}

static int dissect_teklink_get_software_version_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_unknown_long, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_unknown_long, offset);
	offset = dissect_rpc_string(tvb, tree, hf_teklink_unknown_string, offset, NULL);
	offset = dissect_rpc_string(tvb, tree, hf_teklink_unknown_string, offset, NULL);
	return offset;
}

static int dissect_teklink_call65_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_cmd, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_unknown_long, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_unknown_long, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_unknown_long, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_unknown_long, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_unknown_long, offset);
	return offset;
}

static int dissect_teklink_call65_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_unknown_long, offset);
	return offset;
}

static int dissect_teklink_info_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_locked, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_unknown_long, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_tla_type, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_unknown_long, offset);
	offset = dissect_rpc_string(tvb, tree, hf_teklink_unknown_string, offset, NULL);
	offset = dissect_rpc_string(tvb, tree, hf_teklink_location, offset, NULL);
	offset = dissect_rpc_string(tvb, tree, hf_teklink_user, offset, NULL);
	offset = dissect_rpc_string(tvb, tree, hf_teklink_host, offset, NULL);
	offset = dissect_rpc_string(tvb, tree, hf_teklink_unknown_string, offset, NULL);
	return offset;
}

static int dissect_teklink_info_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_unknown_long, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_unknown_long, offset);
	return offset;
}


static int dissect_teklink_vtc_ident(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_unknown_long, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_unknown_long, offset);
	return offset;
}

static int dissect_teklink_vtc_sigstatall(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_unknown_long, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_unknown_long, offset);
	return offset;
}

static int dissect_teklink_vtc_outen(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	guint32 sig = tvb_get_ntohl(tvb, offset);
	guint32 sigon = tvb_get_ntohl(tvb, offset + 4);

	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_vtc_dstnames, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_vtc_sigen, offset);

	col_append_fstr(pinfo->cinfo, COL_INFO," %s, %s ",
			val_to_str(sig, teklink_vtc_dstnames, "Unknown destination %d"),
			sigon ? "VTC_OUT_FORCE_ON" : "VTC_OUT_FORCE_OFF");
	return offset;
}

static int dissect_teklink_vtc_map(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	guint32 src, dst;

	src = tvb_get_ntohl(tvb, offset);
	dst = tvb_get_ntohl(tvb, offset + 4);

	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_vtc_srcnames, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_vtc_dstnames, offset);

	col_append_fstr(pinfo->cinfo, COL_INFO," %s, %s ",
			val_to_str(src, teklink_vtc_srcnames, "Unknown source %d"),
			val_to_str(dst, teklink_vtc_dstnames, "Unknown destination %d"));
	return offset;
}

static int dissect_teklink_vtc_clk(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	guint32 sig, clksource, clkedge, clkmode;

	sig = tvb_get_ntohl(tvb, offset);
	clksource = tvb_get_ntohl(tvb, offset + 4);
	clkedge = tvb_get_ntohl(tvb, offset + 8);
	clkmode = tvb_get_ntohl(tvb, offset + 12);

	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_vtc_dstnames, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_vtc_clksource, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_vtc_clkedge, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_vtc_clkmode, offset);

	col_append_fstr(pinfo->cinfo, COL_INFO,"  %s, %s, %s, %s",
			val_to_str(sig, teklink_vtc_dstnames, "Unknown destination %d"),
			val_to_str(clksource, teklink_vtc_clksource, "Unknown clocksource %d"),
			val_to_str(clkedge, teklink_vtc_clkedge, "Unknown edge setting %d"),
			val_to_str(clkmode, teklink_vtc_clkmode, "Unknown mode setting %d"));
	return offset;
}

static int dissect_teklink_vtc_mode(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	guint32 sig, edge, mode;

	sig = tvb_get_ntohl(tvb, offset);
	edge = tvb_get_ntohl(tvb, offset + 4);
	mode = tvb_get_ntohl(tvb, offset + 12);

	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_vtc_dstnames, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_vtc_edge, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_unknown_long, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_vtc_mode, offset);

	col_append_fstr(pinfo->cinfo, COL_INFO," %s, %s, %s",
			val_to_str(sig, teklink_vtc_dstnames, "Unknown destination %d"),
			val_to_str(edge, teklink_vtc_edge, "Unknown edge setting %d"),
			val_to_str(mode, teklink_vtc_modes, "Unknown mode setting %d"));
	return offset;
}

static int dissect_teklink_vtc_outsetup(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	guint32 sig, en, pol, feedback;

	sig = tvb_get_ntohl(tvb, offset);
	en = tvb_get_ntohl(tvb, offset + 4);
	pol = tvb_get_ntohl(tvb, offset + 8);
	feedback = tvb_get_ntohl(tvb, offset + 12);

	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_vtc_dstnames, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_vtc_sigen, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_vtc_sigpol, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_vtc_sigfeedback, offset);

	col_append_fstr(pinfo->cinfo, COL_INFO," %s, %s, %s, %s",
			val_to_str(sig, teklink_vtc_dstnames, "Unknown destination %d"),
			val_to_str(pol, teklink_vtc_sigpol, "Unknown signal polarity %d"),
			val_to_str(en, teklink_vtc_sigen, "Unknown signal enable %d"),
			val_to_str(feedback, teklink_vtc_sigfeedback, "Unknown signal feedback setting %d"));
	return offset;
}

static int dissect_teklink_vtc_res(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	guint32 sig = tvb_get_ntohl(tvb, offset);

	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_vtc_dstnames, offset);

	col_append_fstr(pinfo->cinfo, COL_INFO," %s",
			val_to_str(sig, teklink_vtc_dstnames, "Unknown destination %d"));
	return offset;
}

static int dissect_teklink_vtl_spinbits(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_unknown_long, offset);
	return offset;
}

static int dissect_teklink_vtl_zmode(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
	proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_teklink_unknown_long, offset);
	return offset;
}

static const vsff teklink_proc[] = {
	{ 1, "TLAFrameOpen", dissect_teklink_tlaframeopen_call, dissect_teklink_tlaframeopen_reply },
	{ 2, "TLAFrameClose", dissect_teklink_tlaframeclose_call, dissect_teklink_tlaframeclose_reply },
	{ 3, "GetSoftwareVersion", NULL, dissect_teklink_get_software_version_reply },
	{ 4, "GetInfo", dissect_teklink_info_call, dissect_teklink_info_reply },
	{ 5, "VtcIdent", NULL, dissect_teklink_vtc_ident },
	{ 7, "VtcOutEn", dissect_teklink_vtc_outen, NULL },
	{ 8, "VtcMap", dissect_teklink_vtc_map, NULL },
	{ 9, "VtcOutSetup", dissect_teklink_vtc_outsetup, NULL },
	{ 10, "VtcClk", dissect_teklink_vtc_clk, NULL },
	{ 11, "VtcMode", dissect_teklink_vtc_mode, NULL },
	{ 12, "VtcRes", dissect_teklink_vtc_res, NULL },
	{ 13, "VtcHardRes", NULL, NULL },
	{ 14, "VtcSigStatAll", NULL, dissect_teklink_vtc_sigstatall },
	{ 20, "VtlZMode", NULL, dissect_teklink_vtl_zmode },
	{ 21, "VtlSpinBits", NULL, dissect_teklink_vtl_spinbits },
	{ 65, "Unknown (65)", dissect_teklink_call65_call, dissect_teklink_call65_reply },
	{ 0, NULL, NULL, NULL }
};

static const value_string teklink_proc_vals[] = {
	{ 1, "TLAFrameOpen" },
	{ 2, "TLAFrameClose" },
	{ 3, "TLAFrameGetStatus" },
	{ 4, "GetInfo" },
	{ 5, "VtcIdent" },
	{ 7, "VtcOutEn" },
	{ 8, "VtcMap" },
	{ 9, "VtcOutSetup" },
	{ 10, "VtcClk" },
	{ 11, "VtcMode" },
	{ 12, "VtcRes" },
	{ 13, "VtcHardRes" },
	{ 14, "VtcSigStatAll" },
	{ 15, "VtcPeek" },
	{ 16, "VtcPoke" },
	{ 20, "VtlZMode" },
	{ 21, "VtlSpinBits" },
	{ 30, "TLAFrameResetVISA" },
	{ 35, "VtcRemoteDiag" },
	{ 36, "TLAFrameRunPostDiag" },
	{ 37, "TLAFrameTigerAccess" },
	{ 40, "XXX" },
	{ 41, "XXX" },
	{ 42, "TLAGetFrameError" },
	{ 50, "TLAFileOpen" },
	{ 51, "TLAReadFile" },
	{ 52, "TLAWriteFile" },
	{ 53, "TLAFileClose" },
	{ 54, "TLAFlashImage" },

	{ 0, NULL }
};

static const value_string teklink_error_vals[] = {
	{ 0, NULL }
};

static const value_string teklink_cmd_vals[] = {
	{ 0, "TLKFreeResources" },
	{ 1, "TLKCreateDeleteEventRoute" },
	{ 2, "TLKDeleteRoutesForSignal" },
	{ 3, "CanRequestBeRouted" },
	{ 4, "TLKIsRouted" },
	{ 5, "TLACreateSysRoutes" },
	{ 6, "TLAStart" },
	{ 7, "TLAGetFrameDelay" },
	{ 8, "TLAFrameRegisterCallBack" },
	{ 10, "TLAGetTrggerDelay" },
	{ 0, NULL }
};

static const value_string teklink_tla_types[] = {
	{ 0x02, "TLA711" },
	{ 0x03, "TLA714" },
	{ 0x04, "TLA720" },
	{ 0x05, "TLA60X" },
	{ 0x06, "TLA6XX" },
	{ 0x13, "TLA714A" },
	{ 0x14, "TLA715" },
	{ 0x15, "TLA721" },
	{ 0x16, "TLA520X" },
	{ 0x17, "TLA7012" },
	{ 0x18, "TLA7016" },
	{ 0x00, NULL }
};

void
proto_register_teklink(void)
{
	static hf_register_info hf_core[] = {
		{ &hf_teklink_procedure, {
				"Procedure", "teklink.procedure", FT_UINT8, BASE_DEC,
				VALS(teklink_proc_vals), 0, NULL, HFILL }},
		{ &hf_teklink_unknown_long, {
				"Unknown long", "teklink.long", FT_UINT32, BASE_HEX,
				NULL, 0, NULL, HFILL }},
		{ &hf_teklink_unknown_string, {
				"Unknown String", "teklink.string", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }},
		{ &hf_teklink_cmd, {
				"Command", "teklink.command", FT_UINT32, BASE_DEC,
				VALS(teklink_cmd_vals), 0, NULL, HFILL }},
		{ &hf_teklink_tla_type, {
				"TLA Type", "teklink.tla_type", FT_UINT32, BASE_DEC,
				VALS(teklink_tla_types), 0, NULL, HFILL }},
		{ &hf_teklink_host, {
				"Host", "teklink.host", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }},
		{ &hf_teklink_user, {
				"User", "teklink.user", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }},
		{ &hf_teklink_location, {
				"Location", "teklink.location", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }},
		{ &hf_teklink_locked, {
				"Locked", "teklink.locked", FT_UINT32, BASE_HEX,
				NULL, 0, NULL, HFILL }},
		{ &hf_teklink_vtc_dstnames, {
				"Destination signal", "teklink.signal.destination", FT_UINT32, BASE_HEX,
				VALS(teklink_vtc_dstnames), 0, NULL, HFILL }},
		{ &hf_teklink_vtc_srcnames, {
				"Source signal", "teklink.signal.source", FT_UINT32, BASE_HEX,
				VALS(teklink_vtc_srcnames), 0, NULL, HFILL }},
		{ &hf_teklink_vtc_sigen, {
				"Signal Enable", "teklink.signal.enable", FT_UINT32, BASE_HEX,
				VALS(teklink_vtc_sigen), 0, NULL, HFILL }},
		{ &hf_teklink_vtc_sigpol, {
				"Signal Polarity", "teklink.signal.polarity", FT_UINT32, BASE_HEX,
				VALS(teklink_vtc_sigpol), 0, NULL, HFILL }},
		{ &hf_teklink_vtc_clkmode, {
				"Clock Mode", "teklink.clock.polarity", FT_UINT32, BASE_HEX,
				VALS(teklink_vtc_clkmode), 0, NULL, HFILL }},
		{ &hf_teklink_vtc_clkedge, {
				"Clock Edge", "teklink.clock.polarity", FT_UINT32, BASE_HEX,
				VALS(teklink_vtc_clkedge), 0, NULL, HFILL }},
		{ &hf_teklink_vtc_clksource, {
				"Clock Source", "teklink.clock.source", FT_UINT32, BASE_HEX,
				VALS(teklink_vtc_clksource), 0, NULL, HFILL }},
		{ &hf_teklink_vtc_mode, {
				"Signal Mode", "teklink.signal.mode", FT_UINT32, BASE_HEX,
				VALS(teklink_vtc_modes), 0, NULL, HFILL }},
		{ &hf_teklink_vtc_edge, {
				"Signal Edge", "teklink.signal.edge", FT_UINT32, BASE_HEX,
				VALS(teklink_vtc_edge), 0, NULL, HFILL }},
		{ &hf_teklink_vtc_sigfeedback, {
				"Signal Feedbmode", "teklink.signal.feedback", FT_UINT32, BASE_HEX,
				VALS(teklink_vtc_sigfeedback), 0, NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_teklink
	};

	proto_teklink = proto_register_protocol("TEKLINK", "TEKLINK", "teklink");
	proto_register_field_array(proto_teklink, hf_core, array_length(hf_core));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_teklink(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_teklink, PROGRAM_TEKLINK, ett_teklink);

	/* Register the procedure tables */
	rpc_init_proc_table(PROGRAM_TEKLINK, 1, teklink_proc, hf_teklink_procedure);
}
