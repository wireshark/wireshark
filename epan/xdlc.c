/* xdlc.c
 * Routines for use by various SDLC-derived protocols, such as HDLC
 * and its derivatives LAPB, IEEE 802.2 LLC, etc..
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/xdlc.h>
#include <epan/emem.h>

const value_string ftype_vals[] = {
    { XDLC_I, "Information frame" },
    { XDLC_S, "Supervisory frame" },
    { XDLC_U, "Unnumbered frame" },
    { 0,      NULL }
};

const value_string stype_vals[] = {
    { XDLC_RR>>2,   "Receiver ready" },
    { XDLC_RNR>>2,  "Receiver not ready" },
    { XDLC_REJ>>2,  "Reject" },
    { XDLC_SREJ>>2, "Selective reject" },
    { 0,            NULL }
};

static const value_string modifier_short_vals_cmd[] = {
    { XDLC_UI,    "UI" },
    { XDLC_UP,    "UP" },
    { XDLC_DISC,  "DISC" },
    { XDLC_UA,    "UA" },
    { XDLC_SNRM,  "SNRM" },
    { XDLC_SNRME, "SNRME" },
    { XDLC_TEST,  "TEST" },
    { XDLC_SIM,   "SIM" },
    { XDLC_FRMR,  "FRMR" },
    { XDLC_CFGR,  "CFGR" },
    { XDLC_SARM,  "SARM" },
    { XDLC_SABM,  "SABM" },
    { XDLC_SARME, "SARME" },
    { XDLC_SABME, "SABME" },
    { XDLC_RESET, "RESET" },
    { XDLC_XID,   "XID" },
    { XDLC_SNRME, "SNRME" },
    { XDLC_BCN,   "BCN" },
    { 0,          NULL }
};

const value_string modifier_vals_cmd[] = {
    { XDLC_UI>>2,    "Unnumbered Information" },
    { XDLC_UP>>2,    "Unnumbered Poll" },
    { XDLC_DISC>>2,  "Disconnect" },
    { XDLC_UA>>2,    "Unnumbered Acknowledge" },
    { XDLC_SNRM>>2,  "Set Normal Response Mode" },
    { XDLC_TEST>>2,  "Test" },
    { XDLC_SIM>>2,   "Set Initialization Mode" },
    { XDLC_FRMR>>2,  "Frame reject" },
    { XDLC_CFGR>>2,  "Configure" },
    { XDLC_SARM>>2,  "Set Asynchronous Response Mode" },
    { XDLC_SABM>>2,  "Set Asynchronous Balanced Mode" },
    { XDLC_SARME>>2, "Set Asynchronous Response Mode Extended" },
    { XDLC_SABME>>2, "Set Asynchronous Balanced Mode Extended" },
    { XDLC_RESET>>2, "Reset" },
    { XDLC_XID>>2,   "Exchange identification" },
    { XDLC_SNRME>>2, "Set Normal Response Mode Extended" },
    { XDLC_BCN>>2,   "Beacon" },
    { 0,             NULL }
};

static const value_string modifier_short_vals_resp[] = {
    { XDLC_UI,    "UI" },
    { XDLC_UP,    "UP" },
    { XDLC_RD,    "RD" },
    { XDLC_UA,    "UA" },
    { XDLC_SNRM,  "SNRM" },
    { XDLC_TEST,  "TEST" },
    { XDLC_RIM,   "RIM" },
    { XDLC_FRMR,  "FRMR" },
    { XDLC_CFGR,  "CFGR" },
    { XDLC_DM,    "DM" },
    { XDLC_SABM,  "SABM" },
    { XDLC_SARME, "SARME" },
    { XDLC_SABME, "SABME" },
    { XDLC_RESET, "RESET" },
    { XDLC_XID,   "XID" },
    { XDLC_SNRME, "SNRME" },
    { XDLC_BCN,   "BCN" },
    { 0,          NULL }
};

const value_string modifier_vals_resp[] = {
    { XDLC_UI>>2,    "Unnumbered Information" },
    { XDLC_UP>>2,    "Unnumbered Poll" },
    { XDLC_RD>>2,    "Request Disconnect" },
    { XDLC_UA>>2,    "Unnumbered Acknowledge" },
    { XDLC_SNRM>>2,  "Set Normal Response Mode" },
    { XDLC_TEST>>2,  "Test" },
    { XDLC_RIM>>2,   "Request Initialization Mode" },
    { XDLC_FRMR>>2,  "Frame reject" },
    { XDLC_CFGR>>2,  "Configure" },
    { XDLC_DM>>2,    "Disconnected mode" },
    { XDLC_SABM>>2,  "Set Asynchronous Balanced Mode" },
    { XDLC_SARME>>2, "Set Asynchronous Response Mode Extended" },
    { XDLC_SABME>>2, "Set Asynchronous Balanced Mode Extended" },
    { XDLC_RESET>>2, "Reset" },
    { XDLC_XID>>2,   "Exchange identification" },
    { XDLC_SNRME>>2, "Set Normal Response Mode Extended" },
    { XDLC_BCN>>2,   "Beacon" },
    { 0,             NULL }
};

int
get_xdlc_control(const guchar *pd, int offset, int is_extended)
{
    guint16 control;

    switch (pd[offset] & 0x03) {

    case XDLC_S:
    default:
        /*
	 * Supervisory or Information frame.
	 */
	if (is_extended)
		control = pletohs(&pd[offset]);
	else
		control = pd[offset];
	break;

    case XDLC_U:
	/*
	 * Unnumbered frame.
	 *
	 * XXX - is this two octets, with a P/F bit, in HDLC extended
	 * operation?  It's one octet in LLC, even though the control
	 * field of I and S frames is a 2-byte extended-operation field
	 * in LLC.  Given that there are no sequence numbers in the
	 * control field of a U frame, there doesn't appear to be any
	 * need for it to be 2 bytes in extended operation.
	 */
	control = pd[offset];
	break;
    }
    return control;
}

int
dissect_xdlc_control(tvbuff_t *tvb, int offset, packet_info *pinfo,
  proto_tree *xdlc_tree, int hf_xdlc_control, gint ett_xdlc_control,
  const xdlc_cf_items *cf_items_nonext, const xdlc_cf_items *cf_items_ext,
  const value_string *u_modifier_short_vals_cmd,
  const value_string *u_modifier_short_vals_resp, int is_response,
  int is_extended, int append_info)
{
    guint16 control;
    int control_len;
    const xdlc_cf_items *cf_items;
    const char *control_format;
    guint16 poll_final;
    char *info;
    proto_tree *tc, *control_tree;
    const gchar *frame_type = NULL;
    const gchar *modifier;

    info=ep_alloc(80);
    switch (tvb_get_guint8(tvb, offset) & 0x03) {

    case XDLC_S:
	if (is_extended) {
	    control = tvb_get_letohs(tvb, offset);
	    control_len = 2;
	    cf_items = cf_items_ext;
	    control_format = "Control field: %s (0x%04X)";
	} else {
	    control = tvb_get_guint8(tvb, offset);
	    control_len = 1;
	    cf_items = cf_items_nonext;
	    control_format = "Control field: %s (0x%02X)";
	}
        /*
	 * Supervisory frame.
	 */
	switch (control & XDLC_S_FTYPE_MASK) {
	case XDLC_RR:
	    frame_type = "RR";
	    break;

	case XDLC_RNR:
	    frame_type = "RNR";
	    break;

	case XDLC_REJ:
	    frame_type = "REJ";
	    break;

	case XDLC_SREJ:
	    frame_type = "SREJ";
	    break;
	}
	if (is_extended) {
	    poll_final = (control & XDLC_P_F_EXT);
	    g_snprintf(info, 80, "S%s, func=%s, N(R)=%u",
		 	(poll_final ?
		 	    (is_response ? " F" : " P") :
		 	    ""),
			frame_type,
			(control & XDLC_N_R_EXT_MASK) >> XDLC_N_R_EXT_SHIFT);
	} else {
	    poll_final = (control & XDLC_P_F);
	    g_snprintf(info, 80, "S%s, func=%s, N(R)=%u",
		 	(poll_final ?
		 	    (is_response ? " F" : " P") :
		 	    ""),
		 	frame_type,
			(control & XDLC_N_R_MASK) >> XDLC_N_R_SHIFT);
	}
	if (check_col(pinfo->cinfo, COL_INFO)) {
	    if (append_info) {
	    	col_append_str(pinfo->cinfo, COL_INFO, ", ");
		col_append_str(pinfo->cinfo, COL_INFO, info);
	    } else
		col_add_str(pinfo->cinfo, COL_INFO, info);
	}
	if (xdlc_tree) {
	    tc = proto_tree_add_uint_format(xdlc_tree, hf_xdlc_control, tvb,
		offset, control_len, control, control_format, info, control);
	    control_tree = proto_item_add_subtree(tc, ett_xdlc_control);
	    proto_tree_add_uint(control_tree, *cf_items->hf_xdlc_n_r,
		tvb, offset, control_len, control);
	    if (poll_final) {
		proto_tree_add_boolean(control_tree,
			(is_response ? *cf_items->hf_xdlc_f :
				       *cf_items->hf_xdlc_p),
			tvb, offset, control_len, control);
	    }
	    proto_tree_add_uint(control_tree, *cf_items->hf_xdlc_s_ftype,
		tvb, offset, control_len, control);
	    /* This will always say it's a supervisory frame */
	    proto_tree_add_uint(control_tree, *cf_items->hf_xdlc_ftype_s_u,
		tvb, offset, control_len, control);
	}
	break;

    case XDLC_U:
	/*
	 * Unnumbered frame.
	 *
	 * XXX - is this two octets, with a P/F bit, in HDLC extended
	 * operation?  It's one octet in LLC, even though the control
	 * field of I and S frames is a 2-byte extended-operation field
	 * in LLC.  Given that there are no sequence numbers in the
	 * control field of a U frame, there doesn't appear to be any
	 * need for it to be 2 bytes in extended operation.
	 */
	if (u_modifier_short_vals_cmd == NULL)
		u_modifier_short_vals_cmd = modifier_short_vals_cmd;
	if (u_modifier_short_vals_resp == NULL)
		u_modifier_short_vals_resp = modifier_short_vals_resp;
	control = tvb_get_guint8(tvb, offset);
	control_len = 1;
	cf_items = cf_items_nonext;
	control_format = "Control field: %s (0x%02X)";
	if (is_response) {
		modifier = val_to_str(control & XDLC_U_MODIFIER_MASK,
			u_modifier_short_vals_resp, "Unknown");
	} else {
		modifier = val_to_str(control & XDLC_U_MODIFIER_MASK,
			u_modifier_short_vals_cmd, "Unknown");
	}
	poll_final = (control & XDLC_P_F);
	g_snprintf(info, 80, "U%s, func=%s",
		(poll_final ?
		    (is_response ? " F" : " P") :
		    ""),
		modifier);
	if (check_col(pinfo->cinfo, COL_INFO)) {
	    if (append_info) {
	    	col_append_str(pinfo->cinfo, COL_INFO, ", ");
		col_append_str(pinfo->cinfo, COL_INFO, info);
	    } else
		col_add_str(pinfo->cinfo, COL_INFO, info);
	}
	if (xdlc_tree) {
	    tc = proto_tree_add_uint_format(xdlc_tree, hf_xdlc_control,	tvb,
		offset, control_len, control, control_format, info, control);
	    control_tree = proto_item_add_subtree(tc, ett_xdlc_control);
	    if (poll_final) {
		proto_tree_add_boolean(control_tree,
			(is_response ? *cf_items->hf_xdlc_f:
				       *cf_items->hf_xdlc_p),
			tvb, offset, control_len, control);
	    }
	    proto_tree_add_uint(control_tree,
		(is_response ? *cf_items->hf_xdlc_u_modifier_resp :
			       *cf_items->hf_xdlc_u_modifier_cmd),
	    	tvb, offset, control_len, control);
	    /* This will always say it's an unnumbered frame */
	    proto_tree_add_uint(control_tree, *cf_items->hf_xdlc_ftype_s_u,
		tvb, offset, control_len, control);
	}
	break;

    default:
	/*
	 * Information frame.
	 */
	if (is_extended) {
	    control = tvb_get_letohs(tvb, offset);
	    control_len = 2;
	    cf_items = cf_items_ext;
	    control_format = "Control field: %s (0x%04X)";
	    poll_final = (control & XDLC_P_F_EXT);
	    g_snprintf(info, 80, "I%s, N(R)=%u, N(S)=%u",
			((control & XDLC_P_F_EXT) ? " P" : ""),
			(control & XDLC_N_R_EXT_MASK) >> XDLC_N_R_EXT_SHIFT,
			(control & XDLC_N_S_EXT_MASK) >> XDLC_N_S_EXT_SHIFT);
	} else {
	    control = tvb_get_guint8(tvb, offset);
	    control_len = 1;
	    cf_items = cf_items_nonext;
	    control_format = "Control field: %s (0x%02X)";
	    poll_final = (control & XDLC_P_F);
	    g_snprintf(info, 80, "I%s, N(R)=%u, N(S)=%u",
			((control & XDLC_P_F) ? " P" : ""),
			(control & XDLC_N_R_MASK) >> XDLC_N_R_SHIFT,
			(control & XDLC_N_S_MASK) >> XDLC_N_S_SHIFT);
	}
	if (check_col(pinfo->cinfo, COL_INFO)) {
	    if (append_info) {
	    	col_append_str(pinfo->cinfo, COL_INFO, ", ");
		col_append_str(pinfo->cinfo, COL_INFO, info);
	    } else
		col_add_str(pinfo->cinfo, COL_INFO, info);
	}
	if (xdlc_tree) {
	    tc = proto_tree_add_uint_format(xdlc_tree, hf_xdlc_control, tvb,
		offset, control_len, control, control_format, info, control);
	    control_tree = proto_item_add_subtree(tc, ett_xdlc_control);
	    proto_tree_add_uint(control_tree, *cf_items->hf_xdlc_n_r,
		tvb, offset, control_len, control);
	    proto_tree_add_uint(control_tree, *cf_items->hf_xdlc_n_s,
		tvb, offset, control_len, control);
	    if (poll_final) {
		proto_tree_add_boolean(control_tree, *cf_items->hf_xdlc_p,
		    	tvb, offset, control_len, control);
	    }
	    /* This will always say it's an information frame */
	    proto_tree_add_uint(control_tree, *cf_items->hf_xdlc_ftype_i,
		tvb, offset, control_len, control);
	}
	break;
    }
    return control;
}
