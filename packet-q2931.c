/* packet-q2931.c
 * Routines for Q.2931 frame disassembly
 * Guy Harris <guy@alum.mit.edu>
 *
 * $Id: packet-q2931.c,v 1.1 1999/11/19 09:55:37 guy Exp $
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

/*
 * See
 *
 *	http://www.protocols.com/pbook/atmsig.htm
 *
 * for some information on Q.2931, although, alas, not the actual message
 * type and information element values - those I got from the FreeBSD 3.2
 * ATM code.
 */

static int proto_q2931 = -1;
static int hf_q2931_discriminator = -1;
static int hf_q2931_call_ref_len = -1;
static int hf_q2931_call_ref = -1;
static int hf_q2931_message_type = -1;
static int hf_q2931_message_type_ext = -1;
static int hf_q2931_message_len = -1;

static gint ett_q2931 = -1;
static gint ett_q2931_ie = -1;

/*
 * Q.2931 message types.
 */
#define	Q2931_ALERTING		0x01
#define	Q2931_CALL_PROCEEDING	0x02
#define	Q2931_CONNECT		0x07
#define	Q2931_CONNECT_ACK	0x0F
#define	Q2931_PROGRESS		0x03
#define	Q2931_SETUP		0x05
#define	Q2931_SETUP_ACK		0x0B
#define	Q2931_RELEASE		0x4D
#define	Q2931_RELEASE_COMPLETE	0x5A
#define	Q2931_RESTART		0x46
#define	Q2931_RESTART_ACK	0x4E
#define	Q2931_INFORMATION	0x7B
#define	Q2931_NOTIFY		0x6E
#define	Q2931_STATUS		0x7D
#define	Q2931_STATUS_ENQUIRY	0x75
#define	Q2931_ADD_PARTY		0x80
#define	Q2931_ADD_PARTY_ACK	0x81
#define	Q2931_ADD_PARTY_REJ	0x82
#define	Q2931_DROP_PARTY	0x83
#define	Q2931_DROP_PARTY_ACK	0x84

static const value_string q2931_message_type_vals[] = {
	{ Q2931_ALERTING,		"ALERTING" },
	{ Q2931_CALL_PROCEEDING,	"CALL PROCEEDING" },
	{ Q2931_CONNECT,		"CONNECT" },
	{ Q2931_CONNECT_ACK,		"CONNECT ACKNOWLEDGE" },
	{ Q2931_PROGRESS,		"PROGRESS" },
	{ Q2931_SETUP,			"SETUP" },
	{ Q2931_SETUP_ACK,		"SETUP ACKNOWLEDGE" },
	{ Q2931_RELEASE,		"RELEASE" },
	{ Q2931_RELEASE_COMPLETE,	"RELEASE COMPLETE" },
	{ Q2931_RESTART,		"RESTART" },
	{ Q2931_RESTART_ACK,		"RESTART ACKNOWLEDGE" },
	{ Q2931_INFORMATION,		"INFORMATION" },
	{ Q2931_NOTIFY,			"NOTIFY" },
	{ Q2931_STATUS,			"STATUS" },
	{ Q2931_STATUS_ENQUIRY,		"STATUS ENQUIRY" },
	{ Q2931_ADD_PARTY,		"ADD PARTY" },
	{ Q2931_ADD_PARTY_ACK,		"ADD PARTY ACKNOWLEDGE" },
	{ Q2931_ADD_PARTY_REJ,		"ADD PARTY REJECT" },
	{ Q2931_DROP_PARTY,		"DROP PARTY" },
	{ Q2931_DROP_PARTY_ACK,		"DROP PARTY ACKNOWLEDGE" },
	{ 0,				NULL }
};

/*
 * Information elements.
 */

#define	Q2931_IE_CAUSE			0x08
#define	Q2931_IE_CALL_STATE		0x14
#define	Q2931_IE_ENDPOINT_REFERENCE	0x54
#define	Q2931_IE_ENDPOINT_STATE		0x55
#define	Q2931_IE_AAL_PARAMETERS		0x58
#define	Q2931_IE_ATM_USER_CELL_RATE	0x59
#define	Q2931_IE_CONNECTION_IDENTIFIER	0x5A
#define	Q2931_IE_QOS_PARAMETER		0x5C	/* Quality of Service parameter */
#define	Q2931_IE_BBAND_HI_LAYER_INFO	0x5D	/* Broadband high-layer information */
#define	Q2931_IE_BBAND_BRER_CAPACITY	0x5E	/* Broadband bearer capacity */
#define	Q2931_IE_BBAND_LOW_LAYER_INFO	0x5F	/* Broadband low-layer information */
#define	Q2931_IE_BBAND_LOCKING_SHIFT	0x60	/* Broadband locking shift */
#define	Q2931_IE_BBAND_NLOCKING_SHIFT	0x61	/* Broadband non-locking shift */
#define	Q2931_IE_BBAND_SENDING_COMPL	0x62	/* Broadband sending complete */
#define	Q2931_IE_BBAND_RPT_INDICATOR	0x63	/* Broadband repeat indicator */
#define	Q2931_IE_CALLING_PARTY_NUMBER	0x6C	/* Calling Party Number */
#define	Q2931_IE_CALLING_PARTY_SUBADDR	0x6D	/* Calling Party Subaddress */
#define	Q2931_IE_CALLED_PARTY_NUMBER	0x70	/* Called Party Number */
#define	Q2931_IE_CALLED_PARTY_SUBADDR	0x71	/* Called Party Subaddress */
#define	Q2931_IE_TRANSIT_NETWORK_SEL	0x78	/* Transit Network Selection */
#define	Q2931_IE_RESTART_INDICATOR	0x79

static const value_string q2931_info_element_vals[] = {
	{ Q2931_IE_CAUSE,			"Cause" },
	{ Q2931_IE_CALL_STATE,			"Call state" },
	{ Q2931_IE_ENDPOINT_REFERENCE,		"Endpoint reference" },
	{ Q2931_IE_ENDPOINT_STATE,		"Endpoint state" },
	{ Q2931_IE_AAL_PARAMETERS,		"AAL parameters" },
	{ Q2931_IE_ATM_USER_CELL_RATE,		"ATM user cell rate" },
	{ Q2931_IE_CONNECTION_IDENTIFIER,	"Connection identifier" },
	{ Q2931_IE_QOS_PARAMETER,		"Quality of service parameter" },
	{ Q2931_IE_BBAND_HI_LAYER_INFO,		"Broadband high-layer information" },
	{ Q2931_IE_BBAND_BRER_CAPACITY,		"Broadband bearer capacity" },
	{ Q2931_IE_BBAND_LOW_LAYER_INFO,	"Broadband low-layer information" },
	{ Q2931_IE_BBAND_LOCKING_SHIFT,		"Broadband locking shift" },
	{ Q2931_IE_BBAND_NLOCKING_SHIFT,	"Broadband non-locking shift" },
	{ Q2931_IE_BBAND_SENDING_COMPL,		"Broadband sending complete" },
	{ Q2931_IE_BBAND_RPT_INDICATOR,		"Broadband repeat indicator" },
	{ Q2931_IE_CALLING_PARTY_NUMBER,	"Calling party number" },
	{ Q2931_IE_CALLING_PARTY_SUBADDR,	"Calling party subaddress" },
	{ Q2931_IE_CALLED_PARTY_NUMBER,		"Called party number" },
	{ Q2931_IE_CALLED_PARTY_SUBADDR,	"Called party subaddress" },
	{ Q2931_IE_TRANSIT_NETWORK_SEL,		"Transit network selection" },
	{ Q2931_IE_RESTART_INDICATOR,		"Restart indicator" },
	{ 0,					NULL }
};

void
dissect_q2931(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_tree	*q2931_tree = NULL;
	proto_item	*ti;
	proto_tree	*ie_tree;
	guint8		call_ref_len;
	guint8		call_ref[15];
	guint8		message_type;
	guint8		message_type_ext;
	guint16		message_len;
	guint8		info_element;
	guint8		info_element_ext;
	guint16		info_element_len;
	int		codeset;
	int		non_locking_shift;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "Q.2931");

	if (tree) {
		ti = proto_tree_add_item(tree, proto_q2931, offset,
		    END_OF_FRAME, NULL);
		q2931_tree = proto_item_add_subtree(ti, ett_q2931);

		proto_tree_add_item(q2931_tree, hf_q2931_discriminator, offset, 1, pd[offset]);
	}
	offset += 1;
	call_ref_len = pd[offset] & 0xF;	/* XXX - do as a bit field? */
	if (q2931_tree != NULL)
		proto_tree_add_item(q2931_tree, hf_q2931_call_ref_len, offset, 1, call_ref_len);
	offset += 1;
	if (call_ref_len != 0) {
		/* XXX - split this into flag and value */
		memcpy(call_ref, &pd[offset], call_ref_len);
		if (q2931_tree != NULL)
			proto_tree_add_item(q2931_tree, hf_q2931_call_ref, offset, call_ref_len, call_ref);
		offset += call_ref_len;
	}
	message_type = pd[offset];
	if (check_col(fd, COL_INFO)) {
		col_add_str(fd, COL_INFO,
		    val_to_str(message_type, q2931_message_type_vals,
		      "Unknown message type (0x%02X)"));
	}
	if (q2931_tree != NULL)
		proto_tree_add_item(q2931_tree, hf_q2931_message_type, offset, 1, message_type);
	offset += 1;

	message_type_ext = pd[offset];
	if (q2931_tree != NULL)
		proto_tree_add_item(q2931_tree, hf_q2931_message_type_ext, offset, 1, message_type_ext);
	offset += 1;

	message_len = pntohs(&pd[offset]);
	if (q2931_tree != NULL)
		proto_tree_add_item(q2931_tree, hf_q2931_message_len, offset, 2, message_len);
	offset += 2;

	/*
	 * And now for the information elements....
	 */
	codeset = 0;	/* start out in codeset 0 */
	non_locking_shift = TRUE;
	while (IS_DATA_IN_FRAME(offset)) {
		info_element = pd[offset];
		if (!BYTES_ARE_IN_FRAME(offset + 1, 1))
			break;	/* ran past end of frame */
		info_element_ext = pd[offset + 1];
		if (!BYTES_ARE_IN_FRAME(offset + 2, 2))
			break;	/* ran past end of frame */
		info_element_len = pntohs(&pd[offset + 2]);
		if (!BYTES_ARE_IN_FRAME(offset + 4, info_element_len))
			break;	/* ran past end of frame */
		if (q2931_tree != NULL) {
			ti = proto_tree_add_text(q2931_tree, offset,
			    1+1+2+info_element_len, "%s",
			    val_to_str(info_element, q2931_info_element_vals,
			      "Unknown information element (0x%02X)"));
			ie_tree = proto_item_add_subtree(ti, ett_q2931_ie);
			proto_tree_add_text(ie_tree, offset, 1,
			    "Information element: %s",
			    val_to_str(info_element, q2931_info_element_vals,
			      "Unknown"));
			proto_tree_add_text(ie_tree, offset + 1, 1,
			    "Information element extension: 0x%02x",
			    info_element_ext);
			proto_tree_add_text(ie_tree, offset + 2, 2,
			    "Length: %u", info_element_len);
		}
		offset += 1 + 1 + 2 + info_element_len;
	}
}

void
proto_register_q2931(void)
{
    static hf_register_info hf[] = {
	{ &hf_q2931_discriminator,
	  { "Protocol discriminator", "q2931.disc", FT_UINT8, BASE_HEX, NULL, 0x0, 
	  	"" }},

	{ &hf_q2931_call_ref_len,
	  { "Call reference value length", "q2931.call_ref_len", FT_UINT8, BASE_DEC, NULL, 0x0,
	  	"" }},

	{ &hf_q2931_call_ref,
	  { "Call reference value", "q2931.call_ref", FT_BYTES, BASE_HEX, NULL, 0x0,
	  	"" }},

	{ &hf_q2931_message_type,
	  { "Message type", "q2931.message_type", FT_UINT8, BASE_HEX, VALS(q2931_message_type_vals), 0x0,
	  	"" }},

	{ &hf_q2931_message_type_ext,
	  { "Message type extension", "q2931.message_type_ext", FT_UINT8, BASE_HEX, NULL, 0x0,
	  	"" }},

	{ &hf_q2931_message_len,
	  { "Message length", "q2931.message_len", FT_UINT16, BASE_DEC, NULL, 0x0,
	  	"" }},

    };
    static gint *ett[] = {
        &ett_q2931,
        &ett_q2931_ie,
    };

    proto_q2931 = proto_register_protocol ("Q.2931", "q2931");
    proto_register_field_array (proto_q2931, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}
