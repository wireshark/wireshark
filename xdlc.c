/* xdlc.c
 * Routines for use by various SDLC-derived protocols, such as HDLC
 * and its derivatives LAPB, IEEE 802.2 LLC, etc..
 *
 * $Id: xdlc.c,v 1.15 2000/05/31 03:58:55 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <stdio.h>
#include <string.h>

#include <glib.h>
#include "packet.h"
#include "xdlc.h"
	
/*
 * N(S) and N(R) fields, in basic and extended operation.
 */
#define XDLC_N_R_MASK		0xE0	/* basic */
#define XDLC_N_R_SHIFT		5
#define XDLC_N_R_EXT_MASK	0xFE00	/* extended */
#define XDLC_N_R_EXT_SHIFT	9
#define XDLC_N_S_MASK		0x0E	/* basic */
#define XDLC_N_S_SHIFT		1
#define XDLC_N_S_EXT_MASK	0x00FE	/* extended */
#define XDLC_N_S_EXT_SHIFT	1

/*
 * Poll/Final bit, in basic and extended operation.
 */
#define XDLC_P_F	0x10	/* basic */
#define XDLC_P_F_EXT	0x0100	/* extended */

/*
 * S-format frame types.
 */
#define XDLC_S_FTYPE_MASK	0x0C
#define XDLC_RR			0x00	/* Receiver ready */
#define XDLC_RNR		0x04	/* Receiver not ready */
#define XDLC_REJ		0x08	/* Reject */
#define XDLC_SREJ		0x0C	/* Selective reject */

static const value_string stype_vals[] = {
    { XDLC_RR,   "Receiver ready" },
    { XDLC_RNR,  "Receiver not ready" },
    { XDLC_REJ,  "Reject" },
    { XDLC_SREJ, "Selective reject" },
    { 0,         NULL }
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

static const value_string modifier_vals_cmd[] = {
    { XDLC_UI,    "Unnumbered Information" },
    { XDLC_UP,    "Unnumbered Poll" },
    { XDLC_DISC,  "Disconnect" },
    { XDLC_UA,    "Unnumbered Acknowledge" },
    { XDLC_SNRM,  "Set Normal Response Mode" },
    { XDLC_TEST,  "Test" },
    { XDLC_SIM,   "Set Initialization Mode" },
    { XDLC_FRMR,  "Frame reject" },
    { XDLC_CFGR,  "Configure" },
    { XDLC_SARM,  "Set Asynchronous Response Mode" },
    { XDLC_SABM,  "Set Asynchronous Balanced Mode" },
    { XDLC_SARME, "Set Asynchronous Response Mode Extended" },
    { XDLC_SABME, "Set Asynchronous Balanced Mode Extended" },
    { XDLC_RESET, "Reset" },
    { XDLC_XID,   "Exchange identification" },
    { XDLC_SNRME, "Set Normal Response Mode Extended" },
    { XDLC_BCN,   "Beacon" },
    { 0,          NULL }
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

static const value_string modifier_vals_resp[] = {
    { XDLC_UI,    "Unnumbered Information" },
    { XDLC_UP,    "Unnumbered Poll" },
    { XDLC_RD,    "Request Disconnect" },
    { XDLC_UA,    "Unnumbered Acknowledge" },
    { XDLC_SNRM,  "Set Normal Response Mode" },
    { XDLC_TEST,  "Test" },
    { XDLC_RIM,   "Request Initialization Mode" },
    { XDLC_FRMR,  "Frame reject" },
    { XDLC_CFGR,  "Configure" },
    { XDLC_DM,    "Disconnected mode" },
    { XDLC_SABM,  "Set Asynchronous Balanced Mode" },
    { XDLC_SARME, "Set Asynchronous Response Mode Extended" },
    { XDLC_SABME, "Set Asynchronous Balanced Mode Extended" },
    { XDLC_RESET, "Reset" },
    { XDLC_XID,   "Exchange identification" },
    { XDLC_SNRME, "Set Normal Response Mode Extended" },
    { XDLC_BCN,   "Beacon" },
    { 0,          NULL }
};

int
get_xdlc_control(const u_char *pd, int offset, int is_response, int is_extended)
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
  int is_response, int is_extended)
{
    guint16 control;
    char info[80];
    proto_tree *tc, *control_tree;
    gchar *frame_type = NULL;
    gchar *modifier;

    switch (tvb_get_guint8(tvb, offset) & 0x03) {

    case XDLC_S:
        /*
	 * Supervisory frame.
	 */
	if (is_extended)
		control = tvb_get_letohs(tvb, offset);
	else
		control = tvb_get_guint8(tvb, offset);
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
	    sprintf(info, "S%s, %sN(R) = %u", frame_type,
		 	((control & XDLC_P_F_EXT) ?
		 	    (is_response ? "func = F, " : "func = P, ") :
		 	    ""),
			(control & XDLC_N_R_EXT_MASK) >> XDLC_N_R_EXT_SHIFT);
	} else {
	    sprintf(info, "S%s, %sN(R) = %u", frame_type,
		 	((control & XDLC_P_F) ?
		 	    (is_response ? "func = F, " : "func = P, ") :
		 	    ""),
			(control & XDLC_N_R_MASK) >> XDLC_N_R_SHIFT);
	}
	if (check_col(pinfo->fd, COL_INFO))
	    col_add_str(pinfo->fd, COL_INFO, info);
	if (xdlc_tree) {
	    if (is_extended) {
		tc = proto_tree_add_uint_format(xdlc_tree, hf_xdlc_control, tvb,
			offset, 2,
			control,
			"Control field: %s (0x%04X)", info, control);
		control_tree = proto_item_add_subtree(tc, ett_xdlc_control);
		proto_tree_add_text(control_tree, tvb, offset, 2,
		    decode_numeric_bitfield(control, XDLC_N_R_EXT_MASK, 2*8,
			"N(R) = %u"));
		if (control & XDLC_P_F_EXT) {
		    proto_tree_add_text(control_tree, tvb, offset, 2,
			decode_boolean_bitfield(control, XDLC_P_F_EXT, 2*8,
		  	    (is_response ? "Final" : "Poll"), NULL));
		}
		proto_tree_add_text(control_tree, tvb, offset, 2,
		    decode_enumerated_bitfield(control, XDLC_S_FTYPE_MASK, 2*8,
			stype_vals, "Supervisory frame - %s"));
		/* This will always say it's a supervisory frame */
		proto_tree_add_text(control_tree, tvb, offset, 2,
		    decode_boolean_bitfield(control, 0x03, 2*8,
			"Supervisory frame", NULL));
	    } else {
		tc = proto_tree_add_uint_format(xdlc_tree, hf_xdlc_control, tvb,
			offset, 1,
			control,
			"Control field: %s (0x%02X)", info, control);
		control_tree = proto_item_add_subtree(tc, ett_xdlc_control);
		proto_tree_add_text(control_tree, tvb, offset, 1,
		    decode_numeric_bitfield(control, XDLC_N_R_MASK, 1*8,
			"N(R) = %u"));
		if (control & XDLC_P_F) {
		    proto_tree_add_text(control_tree, tvb, offset, 1,
			decode_boolean_bitfield(control, XDLC_P_F, 1*8,
		  	    (is_response ? "Final" : "Poll"), NULL));
		}
		proto_tree_add_text(control_tree, tvb, offset, 1,
		    decode_enumerated_bitfield(control, XDLC_S_FTYPE_MASK, 1*8,
			stype_vals, "%s"));
		/* This will always say it's a supervisory frame */
		proto_tree_add_text(control_tree, tvb, offset, 1,
		    decode_boolean_bitfield(control, 0x03, 1*8,
			"Supervisory frame", NULL));
	    }
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
	control = tvb_get_guint8(tvb, offset);
	if (is_response) {
		modifier = match_strval(control & XDLC_U_MODIFIER_MASK,
			modifier_short_vals_resp);
	} else {
		modifier = match_strval(control & XDLC_U_MODIFIER_MASK,
			modifier_short_vals_cmd);
	}
	if (modifier == NULL)
		modifier = "Unknown";
	sprintf(info, "U%s, func = %s",
		((control & XDLC_P_F) ?
		    (is_response ? " F" : " P") :
		    ""),
		modifier);
	if (check_col(pinfo->fd, COL_INFO))
	    col_add_str(pinfo->fd, COL_INFO, info);
	if (xdlc_tree) {
	    tc = proto_tree_add_uint_format(xdlc_tree, hf_xdlc_control, tvb,
			offset, 1,
			control,
			"Control field: %s (0x%02X)", info, control);
	    control_tree = proto_item_add_subtree(tc, ett_xdlc_control);
	    if (control & XDLC_P_F) {
		proto_tree_add_text(control_tree, tvb, offset, 2,
		    decode_boolean_bitfield(control, XDLC_P_F, 1*8,
			(is_response ? "Final" : "Poll"), NULL));
	    }
	    proto_tree_add_text(control_tree, tvb, offset, 1,
		decode_enumerated_bitfield(control, XDLC_U_MODIFIER_MASK, 1*8,
		    (is_response ? modifier_vals_resp : modifier_vals_cmd),
		    "%s"));
	    /* This will always say it's an unnumbered frame */
	    proto_tree_add_text(control_tree, tvb, offset, 1,
		decode_boolean_bitfield(control, 0x03, 1*8,
		    "Unnumbered frame", NULL));
	}
	break;

    default:
	/*
	 * Information frame.
	 */
	if (is_extended)
		control = tvb_get_letohs(tvb, offset);
	else
		control = tvb_get_guint8(tvb, offset);
	if (is_extended) {
	    sprintf(info, "I%s, N(R) = %u, N(S) = %u",
			((control & XDLC_P_F_EXT) ? " P" : ""),
			(control & XDLC_N_R_EXT_MASK) >> XDLC_N_R_EXT_SHIFT,
			(control & XDLC_N_S_EXT_MASK) >> XDLC_N_S_EXT_SHIFT);
	} else {
	    sprintf(info, "I%s, N(R) = %u, N(S) = %u",
			((control & XDLC_P_F) ? " P" : ""),
			(control & XDLC_N_R_MASK) >> XDLC_N_R_SHIFT,
			(control & XDLC_N_S_MASK) >> XDLC_N_S_SHIFT);
	}
	if (check_col(pinfo->fd, COL_INFO))
	    col_add_str(pinfo->fd, COL_INFO, info);
	if (xdlc_tree) {
	    tc = proto_tree_add_uint_format(xdlc_tree, hf_xdlc_control, tvb,
			offset, (is_extended) ? 2 : 1,
			control,
			(is_extended) ? "Control field: %s (0x%04X)"
			              : "Control field: %s (0x%02X)",
			info, control);
	    control_tree = proto_item_add_subtree(tc, ett_xdlc_control);
	    if (is_extended) {
		proto_tree_add_text(control_tree, tvb, offset, 2,
		    decode_numeric_bitfield(control, XDLC_N_R_EXT_MASK, 2*8,
		  		"N(R) = %u"));
		proto_tree_add_text(control_tree, tvb, offset, 2,
		    decode_numeric_bitfield(control, XDLC_N_S_EXT_MASK, 2*8,
		  		"N(S) = %u"));
		if (control & XDLC_P_F_EXT) {
		    proto_tree_add_text(control_tree, tvb, offset, 2,
			decode_boolean_bitfield(control, XDLC_P_F_EXT, 2*8,
		  		"Poll", NULL));
		}
		/* This will always say it's an information frame */
		proto_tree_add_text(control_tree, tvb, offset, 2,
		    decode_boolean_bitfield(control, 0x01, 2*8,
			NULL, "Information frame"));
	    } else {
		proto_tree_add_text(control_tree, tvb, offset, 1,
		    decode_numeric_bitfield(control, XDLC_N_R_MASK, 1*8,
		  		"N(R) = %u"));
		proto_tree_add_text(control_tree, tvb, offset, 1,
		    decode_numeric_bitfield(control, XDLC_N_S_MASK, 1*8,
		  		"N(S) = %u"));
		if (control & XDLC_P_F) {
		    proto_tree_add_text(control_tree, tvb, offset, 1,
			decode_boolean_bitfield(control, XDLC_P_F, 1*8,
		  		"Poll", NULL));
		}
		/* This will always say it's an information frame */
		proto_tree_add_text(control_tree, tvb, offset, 1,
		    decode_boolean_bitfield(control, 0x01, 1*8,
			NULL, "Information frame"));
	    }
	}
    }
    return control;
}
