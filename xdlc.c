/* xdlc.c
 * Routines for use by various SDLC-derived protocols, such as HDLC
 * and its derivatives LAPB, IEEE 802.2 LLC, etc..
 *
 * $Id: xdlc.c,v 1.6 1999/08/27 18:01:02 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
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

/*
 * U-format modifiers.
 */
#define XDLC_U_MODIFIER_MASK	0xEC
#define XDLC_UI		0x00	/* Unnumbered Information */
#define XDLC_UP		0x20	/* Unnumbered Poll */
#define XDLC_DISC	0x40	/* Disconnect (command) */
#define XDLC_RD		0x40	/* Request Disconnect (response) */
#define XDLC_UA		0x60	/* Unnumbered Acknowledge */
#define XDLC_SNRM	0x80	/* Set Normal Response Mode */
#define XDLC_SNRME	0xC0	/* Set Normal Response Mode Extended */
#define XDLC_TEST	0xE0	/* Test */
#define XDLC_SIM	0x04	/* Set Initialization Mode (command) */
#define XDLC_RIM	0x04	/* Request Initialization Mode (response) */
#define XDLC_FRMR	0x84	/* Frame reject */
#define XDLC_CFGR	0xC4	/* Configure */
#define XDLC_SARM	0x0C	/* Set Asynchronous Response Mode (command) */
#define XDLC_DM		0x0C	/* Disconnected mode (response) */
#define XDLC_SABM	0x2C	/* Set Asynchronous Balanced Mode */
#define XDLC_SARME	0x4C	/* Set Asynchronous Response Mode Extended */
#define XDLC_SABME	0x6C	/* Set Asynchronous Balanced Mode Extended */
#define XDLC_RESET	0x8C	/* Reset */
#define XDLC_XID	0xAC	/* Exchange identification */
#define XDLC_SNRME	0xCC	/* Set Normal Response Mode Extended */
#define XDLC_BCN	0xEC	/* Beacon */

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
        /*
	 * Supervisory frame - no higher-layer payload.
	 */
	return FALSE;

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

	/*
	 * This frame has payload only if it's a UI frame.
	 */
	return (control & XDLC_U_MODIFIER_MASK) == XDLC_UI;

    default:
	/*
	 * Information frame - has higher-layer payload.
	 */
	return TRUE;
    }
}

int
dissect_xdlc_control(const u_char *pd, int offset, frame_data *fd,
  proto_tree *xdlc_tree, int hf_xdlc_control, 
  int is_response, int is_extended)
{
    guint16 control;
    char info[80];
    proto_tree *tc, *control_tree;
    gchar *frame_type = NULL;
    gchar *modifier;

    switch (pd[offset] & 0x03) {

    case XDLC_S:
        /*
	 * Supervisory frame.
	 */
	if (is_extended)
		control = pletohs(&pd[offset]);
	else
		control = pd[offset];
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
	if (check_col(fd, COL_INFO))
	    col_add_str(fd, COL_INFO, info);
	if (xdlc_tree) {
	    if (is_extended) {
		tc = proto_tree_add_item_format(xdlc_tree, hf_xdlc_control,
			offset, 2,
			frame_type,
			"Control field: %s (0x%04X)", info, control);
		control_tree = proto_item_add_subtree(tc, ETT_XDLC_CONTROL);
		proto_tree_add_text(control_tree, offset, 2,
		    decode_numeric_bitfield(control, XDLC_N_R_EXT_MASK, 2*8,
			"N(R) = %u"));
		if (control & XDLC_P_F_EXT) {
		    proto_tree_add_text(control_tree, offset, 2,
			decode_boolean_bitfield(control, XDLC_P_F_EXT, 2*8,
		  	    (is_response ? "Final" : "Poll"), NULL));
		}
		proto_tree_add_text(control_tree, offset, 2,
		    decode_enumerated_bitfield(control, XDLC_S_FTYPE_MASK, 2*8,
			stype_vals, "Supervisory frame - %s"));
		/* This will always say it's a supervisory frame */
		proto_tree_add_text(control_tree, offset, 2,
		    decode_boolean_bitfield(control, 0x03, 2*8,
			"Supervisory frame", NULL));
	    } else {
		tc = proto_tree_add_item_format(xdlc_tree, hf_xdlc_control,
			offset, 1,
			frame_type,
			"Control field: %s (0x%02X)", info, control);
		control_tree = proto_item_add_subtree(tc, ETT_XDLC_CONTROL);
		proto_tree_add_text(control_tree, offset, 1,
		    decode_numeric_bitfield(control, XDLC_N_R_MASK, 1*8,
			"N(R) = %u"));
		if (control & XDLC_P_F) {
		    proto_tree_add_text(control_tree, offset, 1,
			decode_boolean_bitfield(control, XDLC_P_F, 1*8,
		  	    (is_response ? "Final" : "Poll"), NULL));
		}
		proto_tree_add_text(control_tree, offset, 1,
		    decode_enumerated_bitfield(control, XDLC_S_FTYPE_MASK, 1*8,
			stype_vals, "%s"));
		/* This will always say it's a supervisory frame */
		proto_tree_add_text(control_tree, offset, 1,
		    decode_boolean_bitfield(control, 0x03, 1*8,
			"Supervisory frame", NULL));
	    }
	}

	/*
	 * Supervisory frames have no higher-layer payload to be analyzed.
	 */
	return FALSE;

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
	if (check_col(fd, COL_INFO))
	    col_add_str(fd, COL_INFO, info);
	if (xdlc_tree) {
	    tc = proto_tree_add_item_format(xdlc_tree, hf_xdlc_control,
			offset, 1,
			frame_type,
			"Control field: %s (0x%02X)", info, control);
	    control_tree = proto_item_add_subtree(tc, ETT_XDLC_CONTROL);
	    if (control & XDLC_P_F) {
		proto_tree_add_text(control_tree, offset, 2,
		    decode_boolean_bitfield(control, XDLC_P_F, 1*8,
			(is_response ? "Final" : "Poll"), NULL));
	    }
	    proto_tree_add_text(control_tree, offset, 1,
		decode_enumerated_bitfield(control, XDLC_U_MODIFIER_MASK, 1*8,
		    (is_response ? modifier_vals_resp : modifier_vals_cmd),
		    "%s"));
	    /* This will always say it's an unnumbered frame */
	    proto_tree_add_text(control_tree, offset, 1,
		decode_boolean_bitfield(control, 0x03, 1*8,
		    "Unnumbered frame", NULL));
	}

	/*
	 * This frame has payload only if it's a UI frame.
	 */
	return (control & XDLC_U_MODIFIER_MASK) == XDLC_UI;

    default:
	/*
	 * Information frame.
	 */
	control = pd[offset];
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
	if (check_col(fd, COL_INFO))
	    col_add_str(fd, COL_INFO, info);
	if (xdlc_tree) {
	    tc = proto_tree_add_item_format(xdlc_tree, hf_xdlc_control,
			offset, (is_extended) ? 2 : 1,
			frame_type,
			(is_extended) ? "Control field: %s (0x%04X)"
			              : "Control field: %s (0x%02X)",
			info, control);
	    control_tree = proto_item_add_subtree(tc, ETT_XDLC_CONTROL);
	    if (is_extended) {
		proto_tree_add_text(control_tree, offset, 2,
		    decode_numeric_bitfield(control, XDLC_N_R_EXT_MASK, 2*8,
		  		"N(R) = %u"));
		proto_tree_add_text(control_tree, offset, 2,
		    decode_numeric_bitfield(control, XDLC_N_S_EXT_MASK, 2*8,
		  		"N(S) = %u"));
		if (control & XDLC_P_F_EXT) {
		    proto_tree_add_text(control_tree, offset, 2,
			decode_boolean_bitfield(control, XDLC_P_F_EXT, 2*8,
		  		"Poll", NULL));
		}
		/* This will always say it's an information frame */
		proto_tree_add_text(control_tree, offset, 2,
		    decode_boolean_bitfield(control, 0x01, 2*8,
			NULL, "Information frame"));
	    } else {
		proto_tree_add_text(control_tree, offset, 1,
		    decode_numeric_bitfield(control, XDLC_N_R_MASK, 1*8,
		  		"N(R) = %u"));
		proto_tree_add_text(control_tree, offset, 1,
		    decode_numeric_bitfield(control, XDLC_N_S_MASK, 1*8,
		  		"N(S) = %u"));
		if (control & XDLC_P_F) {
		    proto_tree_add_text(control_tree, offset, 1,
			decode_boolean_bitfield(control, XDLC_P_F, 1*8,
		  		"Poll", NULL));
		}
		/* This will always say it's an information frame */
		proto_tree_add_text(control_tree, offset, 1,
		    decode_boolean_bitfield(control, 0x01, 1*8,
			NULL, "Information frame"));
	    }
	}

	/*
	 * Information frames have higher-layer payload to be analyzed.
	 */
	return TRUE;
    }
}
