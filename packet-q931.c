/* packet-q931.c
 * Routines for Q.931 frame disassembly
 * Guy Harris <guy@alum.mit.edu>
 *
 * $Id: packet-q931.c,v 1.1 1999/11/11 08:35:10 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998
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
#include <glib.h>
#include <string.h>
#include "packet.h"

/* Q.931 references:
 *
 * http://www.acacia-net.com/Clarinet/Protocol/q9313svn.htm
 * http://www.acacia-net.com/Clarinet/Protocol/q9311sc3.htm
 */

int proto_q931 = -1;
int hf_q931_discriminator = -1;
int hf_q931_call_ref_len = -1;
int hf_q931_call_ref = -1;
int hf_q931_message_type = -1;

/*
 * Q.931 message types.
 */
#define	Q931_ALERTING		0x01
#define	Q931_CALL_PROCEEDING	0x02
#define	Q931_CONNECT		0x07
#define	Q931_CONNECT_ACK	0x0F
#define	Q931_PROGRESS		0x03
#define	Q931_SETUP		0x05
#define	Q931_SETUP_ACK		0x0B
#define	Q931_HOLD		0x24
#define	Q931_HOLD_ACK		0x28
#define	Q931_HOLD_REJECT	0x30
#define	Q931_RESUME		0x26
#define	Q931_RESUME_ACK		0x2E
#define	Q931_RESUME_REJECT	0x22
#define	Q931_RETRIEVE		0x31
#define	Q931_RETRIEVE_ACK	0x33
#define	Q931_RETRIEVE_REJECT	0x37
#define	Q931_SUSPEND		0x25
#define	Q931_SUSPEND_ACK	0x2D
#define	Q931_SUSPEND_REJECT	0x21
#define	Q931_USER_INFORMATION	0x20
#define	Q931_DISCONNECT		0x45
#define	Q931_RELEASE		0x4D
#define	Q931_RELEASE_COMPLETE	0x5A
#define	Q931_RESTART		0x46
#define	Q931_RESTART_ACK	0x4E
#define	Q931_CONGESTION_CONTROL	0x79
#define	Q931_FACILITY		0x62
#define	Q931_INFORMATIION	0x7B
#define	Q931_NOTIFY		0x6E
#define	Q931_REGISTER		0x64
#define	Q931_SEGMENT		0x60
#define	Q931_STATUS		0x7D
#define	Q931_STATUS_ENQUIRY	0x75

static const value_string q931_message_type_vals[] = {
	{ Q931_ALERTING,		"ALERTING" },
	{ Q931_CALL_PROCEEDING,		"CALL PROCEEDING" },
	{ Q931_CONNECT,			"CONNECT" },
	{ Q931_CONNECT_ACK,		"CONNECT ACKNOWLEDGE" },
	{ Q931_PROGRESS,		"PROGRESS" },
	{ Q931_SETUP,			"SETUP" },
	{ Q931_SETUP_ACK,		"SETUP ACKNOWLEDGE" },
	{ Q931_HOLD,			"HOLD" },
	{ Q931_HOLD_ACK,		"HOLD_ACKNOWLEDGE" },
	{ Q931_HOLD_REJECT,		"HOLD_REJECT" },
	{ Q931_RESUME,			"RESUME" },
	{ Q931_RESUME_ACK,		"RESUME ACKNOWLEDGE" },
	{ Q931_RESUME_REJECT,		"RESUME REJECT" },
	{ Q931_RETRIEVE,		"RETRIEVE" },
	{ Q931_RETRIEVE_ACK,		"RETRIEVE ACKNOWLEDGE" },
	{ Q931_RETRIEVE_REJECT,		"RETRIEVE REJECT" },
	{ Q931_SUSPEND,			"SUSPEND" },
	{ Q931_SUSPEND_ACK,		"SUSPEND ACKNOWLEDGE" },
	{ Q931_SUSPEND_REJECT,		"SUSPEND REJECT" },
	{ Q931_USER_INFORMATION,	"USER INFORMATION" },
	{ Q931_DISCONNECT,		"DISCONNECT" },
	{ Q931_RELEASE,			"RELEASE" },
	{ Q931_RELEASE_COMPLETE,	"RELEASE COMPLETE" },
	{ Q931_RESTART,			"RESTART" },
	{ Q931_RESTART_ACK,		"RESTART ACKNOWLEDGE" },
	{ Q931_CONGESTION_CONTROL,	"CONGESTION CONTROL" },
	{ Q931_FACILITY,		"FACILITY" },
	{ Q931_INFORMATIION,		"INFORMATIION" },
	{ Q931_NOTIFY,			"NOTIFY" },
	{ Q931_REGISTER,		"REGISTER" },
	{ Q931_SEGMENT,			"SEGMENT" },
	{ Q931_STATUS,			"STATUS" },
	{ Q931_STATUS_ENQUIRY,		"STATUS ENQUIRY" },
	{ 0,				NULL }
};

void
dissect_q931(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_tree	*q931_tree = NULL;
	proto_item	*ti;
	guint8		call_ref_len;
	guint16		call_ref;
	guint8		message_type;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "Q.931");

	if (tree) {
		ti = proto_tree_add_item(tree, proto_q931, offset, 3, NULL);
		q931_tree = proto_item_add_subtree(ti, ETT_Q931);

		proto_tree_add_item(q931_tree, hf_q931_discriminator, offset, 1, pd[offset]);
	}
	offset += 1;
	call_ref_len = pd[offset];
	if (q931_tree != NULL)
		proto_tree_add_item(q931_tree, hf_q931_call_ref_len, offset, 1, call_ref_len);
	offset += 1;
	switch (call_ref_len) {

	case 1:
		call_ref = pd[offset];
		break;

	case 2:
		call_ref = pntohs(&pd[offset]);
		break;

	default:
		if (check_col(fd, COL_INFO))
			col_add_str(fd, COL_INFO, "Bad call reference value length");
		if (q931_tree != NULL) {
			proto_tree_add_text(q931_tree, offset, 0,
			    "<Call reference value length is neither 1 nor 2>");
		}
		return;
	}
	if (q931_tree != NULL)
		proto_tree_add_item(q931_tree, hf_q931_call_ref, offset, call_ref_len, call_ref);
	offset += call_ref_len;
	message_type = pd[offset];
	if (check_col(fd, COL_INFO)) {
		col_add_str(fd, COL_INFO,
		    val_to_str(message_type, q931_message_type_vals,
		      "Unknown message type (0x%02X)"));
	}
	if (q931_tree != NULL)
		proto_tree_add_item(q931_tree, hf_q931_message_type, offset, 1, message_type);
}

void
proto_register_q931(void)
{
    static hf_register_info hf[] = {
	{ &hf_q931_discriminator,
	  { "Protocol discriminator", "q931.disc", FT_UINT8, BASE_HEX, NULL, 0x0, 
	  	"" }},

	{ &hf_q931_call_ref_len,
	  { "Call reference value length", "q931.call_ref_len", FT_UINT8, BASE_DEC, NULL, 0x0,
	  	"" }},

	{ &hf_q931_call_ref,
	  { "Call reference value", "q931.call_ref", FT_UINT16, BASE_HEX, NULL, 0x0,
	  	"" }},

	{ &hf_q931_message_type,
	  { "Message type", "q931.message_type", FT_UINT8, BASE_HEX, VALS(q931_message_type_vals), 0x0,
	  	"" }},

    };

    proto_q931 = proto_register_protocol ("Q.931", "q931");
    proto_register_field_array (proto_q931, hf, array_length(hf));
}


