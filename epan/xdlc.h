/* xdlc.h
 * Define *DLC frame types, and routine to dissect the control field of
 * a *DLC frame.
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

#ifndef __XDLC_H__
#define __XDLC_H__

#include "ws_symbol_export.h"

/** @file
 * Define *DLC frame types, and routine to dissect the control field of
 * a *DLC frame.
 */
/*
 * Low-order bits of first (extended) or only (basic) octet of control
 * field, specifying the frame type.
 */
#define XDLC_I_MASK		0x01	/**< Mask to test for I or not I */
#define XDLC_I			0x00	/**< Information frames */
#define XDLC_S_U_MASK	0x03	/**< Mask to test for S or U */
#define XDLC_S			0x01	/**< Supervisory frames */
#define XDLC_U			0x03	/**< Unnumbered frames */

/*
 * N(S) and N(R) fields, in basic and extended operation.
 */
#define XDLC_N_R_MASK		0xE0	/**< basic */
#define XDLC_N_R_SHIFT		5
#define XDLC_N_R_EXT_MASK	0xFE00	/**< extended */
#define XDLC_N_R_EXT_SHIFT	9
#define XDLC_N_S_MASK		0x0E	/**< basic */
#define XDLC_N_S_SHIFT		1
#define XDLC_N_S_EXT_MASK	0x00FE	/**< extended */
#define XDLC_N_S_EXT_SHIFT	1

/*
 * Poll/Final bit, in basic and extended operation.
 */
#define XDLC_P_F		0x10	/**< basic */
#define XDLC_P_F_EXT	0x0100	/**< extended */

/*
 * S-format frame types.
 */
#define XDLC_S_FTYPE_MASK	0x0C
#define XDLC_RR			0x00	/**< Receiver ready */
#define XDLC_RNR		0x04	/**< Receiver not ready */
#define XDLC_REJ		0x08	/**< Reject */
#define XDLC_SREJ		0x0C	/**< Selective reject */

/*
 * U-format modifiers.
 */
#define XDLC_U_MODIFIER_MASK	0xEC
#define XDLC_UI		0x00	/**< Unnumbered Information */
#define XDLC_UP		0x20	/**< Unnumbered Poll */
#define XDLC_DISC	0x40	/**< Disconnect (command) */
#define XDLC_RD		0x40	/**< Request Disconnect (response) */
#define XDLC_UA		0x60	/**< Unnumbered Acknowledge */
#define XDLC_SNRM	0x80	/**< Set Normal Response Mode */
#define XDLC_TEST	0xE0	/**< Test */
#define XDLC_SIM	0x04	/**< Set Initialization Mode (command) */
#define XDLC_RIM	0x04	/**< Request Initialization Mode (response) */
#define XDLC_FRMR	0x84	/**< Frame reject */
#define XDLC_CFGR	0xC4	/**< Configure */
#define XDLC_SARM	0x0C	/**< Set Asynchronous Response Mode (command) */
#define XDLC_DM		0x0C	/**< Disconnected mode (response) */
#define XDLC_SABM	0x2C	/**< Set Asynchronous Balanced Mode */
#define XDLC_SARME	0x4C	/**< Set Asynchronous Response Mode Extended */
#define XDLC_SABME	0x6C	/**< Set Asynchronous Balanced Mode Extended */
#define XDLC_RESET	0x8C	/**< Reset */
#define XDLC_XID	0xAC	/**< Exchange identification */
#define XDLC_SNRME	0xCC	/**< Set Normal Response Mode Extended */
#define XDLC_BCN	0xEC	/**< Beacon */

/**
 * This macro takes the control field of an xDLC frame, as returned by
 * "get_xdlc_control()" or "dissect_xdlc_control()", and evaluates to
 * TRUE if the frame is an "information" frame and FALSE if it isn't.
 * Note that frames other than information frames can have data in them,
 * e.g. TEST frames.
 */
#define XDLC_IS_INFORMATION(control) \
	(((control) & XDLC_I_MASK) == XDLC_I || (control) == (XDLC_UI|XDLC_U))

/**
 * This macro takes the control field of an xDLC frame, and a flag saying
 * whether we're doing basic or extended operation, and evaluates to
 * the length of that field (if it's an Unnumbered frame, or we're not
 * in extended mode, it's 1 byte long, otherwise it's 2 bytes long).
 */
#define XDLC_CONTROL_LEN(control, is_extended) \
	((((control) & XDLC_S_U_MASK) == XDLC_U || !(is_extended)) ? 1 : 2)

/**
 * Structure containing pointers to hf_ values for various subfields of
 * the control field.
 */
typedef struct {
	int	*hf_xdlc_n_r;
	int	*hf_xdlc_n_s;
	int	*hf_xdlc_p;
	int	*hf_xdlc_f;
	int	*hf_xdlc_s_ftype;
	int	*hf_xdlc_u_modifier_cmd;
	int	*hf_xdlc_u_modifier_resp;
	int	*hf_xdlc_ftype_i;
	int	*hf_xdlc_ftype_s_u;
} xdlc_cf_items;

extern const value_string ftype_vals[];
extern const value_string stype_vals[];
extern const value_string modifier_vals_cmd[];
extern const value_string modifier_vals_resp[];

extern int get_xdlc_control(const guchar *pd, int offset, gboolean is_extended);

/**
 * Check whether the control field of the packet looks valid.
 */
WS_DLL_PUBLIC gboolean check_xdlc_control(tvbuff_t *tvb, int offset,
  const value_string *u_modifier_short_vals_cmd,
  const value_string *u_modifier_short_vals_resp, gboolean is_response,
  gboolean is_extended _U_);

WS_DLL_PUBLIC int dissect_xdlc_control(tvbuff_t *tvb, int offset, packet_info *pinfo,
  proto_tree *xdlc_tree, int hf_xdlc_control, gint ett_xdlc_control,
  const xdlc_cf_items *cf_items_nonext, const xdlc_cf_items *cf_items_ext,
  const value_string *u_modifier_short_vals_cmd,
  const value_string *u_modifier_short_vals_resp, gboolean is_response,
  gboolean is_extended, gboolean append_info);

#endif
