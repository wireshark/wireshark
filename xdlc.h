/* xdlc.h
 * Define *DLC frame types, and routine to dissect the control field of
 * a *DLC frame.
 *
 * $Id: xdlc.h,v 1.9 1999/11/11 08:04:06 guy Exp $
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

/*
 * Low-order bits of first (extended) or only (basic) octet of control
 * field, specifying the frame type.
 */
#define XDLC_I		0x00	/* Information frames */
#define XDLC_S		0x01	/* Supervisory frames */
#define XDLC_U		0x03	/* Unnumbered frames */

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

/*
 * This macro takes the control field of an xDLC frame, as returned by
 * "get_xdlc_control()" or "dissect_xdlc_control()", and evaluates to
 * TRUE if the frame has a payload (i.e., if it's an Information or
 * Unnumbered Information frame) and FALSE if it doesn't.
 */
#define XDLC_HAS_PAYLOAD(control) \
	(((control) & 0x1) == XDLC_I || (control) == (XDLC_UI|XDLC_U))

/*
 * This macro takes the control field of an xDLC frame, and a flag saying
 * whether we're doing basic or extended operation, and evaluates to
 * the length of that field (if it's an Unnumbered frame, or we're not
 * in extended mode, it's 1 byte long, otherwise it's 2 bytes long).
 */
#define XDLC_CONTROL_LEN(control, is_extended) \
	((((control) & 0x3) == XDLC_U || !(is_extended)) ? 1 : 2)

int get_xdlc_control(const u_char *pd, int offset, int is_response,
  int extended);

int dissect_xdlc_control(const u_char *pd, int offset, frame_data *fd,
  proto_tree *xdlc_tree, int hf_xdlc_control, int is_response, int extended);
