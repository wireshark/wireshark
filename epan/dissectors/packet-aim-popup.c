/* packet-aim.c
 * Routines for AIM Instant Messenger (OSCAR) dissection
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
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

#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>

#include "packet-aim.h"

/* SNAC families */
#define FAMILY_POPUP      0x0008


#define AIM_POPUP_TLV_MESSAGE_TEXT		0x001
#define AIM_POPUP_TLV_URL_STRING		0x002
#define AIM_POPUP_TLV_WINDOW_WIDTH		0x003
#define AIM_POPUP_TLV_WINDOW_HEIGHT		0x004
#define AIM_POPUP_TLV_AUTOHIDE_DELAY	0x005

static const aim_tlv aim_popup_tlvs[] = {
	{ AIM_POPUP_TLV_MESSAGE_TEXT, "Message text (html)", dissect_aim_tlv_value_string },
	{ AIM_POPUP_TLV_URL_STRING, "URL string", dissect_aim_tlv_value_string },
	{ AIM_POPUP_TLV_WINDOW_WIDTH, "Window Width (pixels)", dissect_aim_tlv_value_uint16 },
	{ AIM_POPUP_TLV_WINDOW_HEIGHT, "Window Height (pixels)", dissect_aim_tlv_value_uint16 },
	{ AIM_POPUP_TLV_AUTOHIDE_DELAY, "Autohide delay (seconds)", dissect_aim_tlv_value_uint16 },
	{ 0, NULL, NULL }
};

/* Initialize the protocol and registered fields */
static int proto_aim_popup = -1;

/* Initialize the subtree pointers */
static gint ett_aim_popup    = -1;

static int dissect_aim_popup(tvbuff_t *tvb, packet_info *pinfo, proto_tree *popup_tree)
{
	return dissect_aim_tlv(tvb, pinfo, 0, popup_tree, aim_popup_tlvs);
}

static const aim_subtype aim_fnac_family_popup[] = {
	{ 0x0001, "Error", dissect_aim_snac_error },
	{ 0x0002, "Display Popup Message Server Command" , dissect_aim_popup },
	{ 0, NULL, NULL }
};


/* Register the protocol with Wireshark */
void
proto_register_aim_popup(void)
{

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_aim_popup,
	};

/* Register the protocol name and description */
	proto_aim_popup = proto_register_protocol("AIM Popup", "AIM Popup", "aim_popup");

/* Required function calls to register the header fields and subtrees used */
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aim_popup(void)
{
	aim_init_family(proto_aim_popup, ett_aim_popup, FAMILY_POPUP, aim_fnac_family_popup);
}
