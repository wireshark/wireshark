/* packet-q931.c
 * Routines for Q.931 frame disassembly
 * Guy Harris <guy@alum.mit.edu>
 *
 * $Id: packet-q931.c,v 1.4 1999/11/13 02:07:59 guy Exp $
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
 * http://www.acacia-net.com/Clarinet/Protocol/q9317oz7.htm
 * http://www.protocols.com/pbook/isdn.htm
 * http://freesoft.org/CIE/Topics/126.htm
 * http://noc.comstar.ru/miscdocs/ascend-faq-cause-codes.html
 * http://www.andrews-arnold.co.uk/isdn/q931cause.html
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

/*
 * Information elements.
 */

/*
 * Single-octet IEs.
 */
#define	Q931_IE_SO_IDENTIFIER_MASK	0x70	/* IE identifier mask */
#define	Q931_IE_SO_IDENTIFIER_SHIFT	4	/* IE identifier shift */
#define	Q931_IE_SO_IE_MASK		0x0F	/* IE mask */

#define	Q931_IE_SHIFT			0x90
#define	Q931_IE_MORE_DATA_OR_SEND_COMP	0xA0	/* More Data or Sending Complete */
#define	Q931_IE_MORE_DATA		0xA0
#define	Q931_IE_SENDING_COMPLETE	0xA1
#define	Q931_IE_CONGESTION_LEVEL	0xB0
#define	Q931_IE_REPEAT_INDICATOR	0xD0

/*
 * Variable-length IEs.
 */

/*
 * Codeset 0 (default).
 */
#define	Q931_IE_SEGMENTED_MESSAGE	0x00
#define	Q931_IE_BEARER_CAPABILITY	0x04
#define	Q931_IE_CAUSE			0x08
#define	Q931_IE_CALL_IDENTITY		0x10
#define	Q931_IE_CALL_STATE		0x14
#define	Q931_IE_CHANNEL_IDENTIFICATION	0x18
#define	Q931_IE_FACILITY		0x1C
#define	Q931_IE_PROGRESS_INDICATOR	0x1E
#define	Q931_IE_NETWORK_SPECIFIC_FACIL	0x20	/* Network Specific Facilities */
#define	Q931_IE_NOTIFICATION_INDICATOR	0x27
#define	Q931_IE_DISPLAY			0x28
#define	Q931_IE_DATE_TIME		0x29
#define	Q931_IE_KEYPAD_FACILITY		0x2C
#define	Q931_IE_INFORMATION_REQUEST	0x32
#define	Q931_IE_SIGNAL			0x34
#define	Q931_IE_SWITCHHOOK		0x36
#define	Q931_IE_FEATURE_ACTIVATION	0x38
#define	Q931_IE_FEATURE_INDICATION	0x39
#define	Q931_IE_ENDPOINT_IDENTIFIER	0x3B
#define	Q931_IE_SERVICE_PROFILE_ID	0x3A
#define	Q931_IE_INFORMATION_RATE	0x40
#define	Q931_IE_E2E_TRANSIT_DELAY	0x42	/* End-to-end Transit Delay */
#define	Q931_IE_TD_SELECTION_AND_INT	0x43	/* Transit Delay Selection and Indication */
#define	Q931_IE_PL_BINARY_PARAMETERS	0x44	/* Packet layer binary parameters */
#define	Q931_IE_PL_WINDOW_SIZE		0x45	/* Packet layer Window Size */
#define	Q931_IE_PL_SIZE			0x46	/* Packet layer Size */
#define	Q931_IE_CALLING_PARTY_NUMBER	0x6C	/* Calling Party Number */
#define	Q931_IE_CALLING_PARTY_SUBADDR	0x6D	/* Calling Party Subaddress */
#define	Q931_IE_CALLED_PARTY_NUMBER	0x70	/* Called Party Number */
#define	Q931_IE_CALLED_PARTY_SUBADDR	0x71	/* Called Party Subaddress */
#define	Q931_IE_REDIRECTING_NUMBER	0x74
#define	Q931_IE_REDIRECTION_NUMBER	0x76
#define	Q931_IE_TRANSIT_NETWORK_SEL	0x78	/* Transit Network Selection */
#define	Q931_IE_RESTART_INDICATOR	0x79
#define	Q931_IE_LOW_LAYER_COMPAT	0x7C	/* Low-Layer Compatibility */
#define	Q931_IE_HIGH_LAYER_COMPAT	0x7D	/* High-Layer Compatibility */
#define	Q931_IE_USER_USER		0x7E	/* User-User */
#define	Q931_IE_ESCAPE			0x7F	/* Escape for extension */

/*
 * Codeset 0 ETSI.
 */
#define	Q931_IE_CONNECTED_NUMBER	0x8C
#define	Q931_IE_CONNECTED_SUBADDR	0x8D

/*
 * Codeset 5 (National-specific) Belgium.
 */
#define	Q931_IE_CHARGING_ADVICE		0x1A

/*
 * Codeset 5 (National-specific) Bellcore National ISDN.
 */
#define	Q931_IE_OPERATOR_SYSTEM_ACCESS	0x1D

/*
 * Codeset 6 (Network-specific) Belgium.
 */
/* 0x1A is Charging Advice, as with Codeset 5 */
#define	Q931_IE_REDIRECTING_NUMBER	0x74

/*
 * Codeset 6 (Network-specific) FT-Numeris.
 */
/* 0x1D is User Capability */

/*
 * Codeset 6 (Network-specific) Bellcore National ISDN.
 */
#define	Q931_IE_REDIRECTING_SUBADDR	0x75	/* Redirecting Subaddress */
/* 0x76 is Redirection Number, but that's also Codeset 0 */
#define	Q931_IE_CALL_APPEARANCE		0x7B

static const value_string q931_info_element_vals[] = {
	{ Q931_IE_SEGMENTED_MESSAGE,		"Segmented message" },
	{ Q931_IE_BEARER_CAPABILITY,		"Bearer capability" },
	{ Q931_IE_CAUSE,			"Cause" },
	{ Q931_IE_CALL_IDENTITY,		"Call identity" },
	{ Q931_IE_CALL_STATE,			"Call state" },
	{ Q931_IE_CHANNEL_IDENTIFICATION,	"Channel identification" },
	{ Q931_IE_FACILITY,			"Facility" },
	{ Q931_IE_PROGRESS_INDICATOR,		"Progress indicator" },
	{ Q931_IE_NETWORK_SPECIFIC_FACIL,	"Network specific facilities" },
	{ Q931_IE_NOTIFICATION_INDICATOR,	"Notification indicator" },
	{ Q931_IE_DISPLAY,			"Display" },
	{ Q931_IE_DATE_TIME,			"Date/Time" },
	{ Q931_IE_KEYPAD_FACILITY,		"Keypad facility" },
	{ Q931_IE_INFORMATION_REQUEST,		"Information request" },
	{ Q931_IE_SIGNAL,			"Signal" },
	{ Q931_IE_SWITCHHOOK,			"Switchhook" },
	{ Q931_IE_FEATURE_ACTIVATION,		"Feature activation" },
	{ Q931_IE_FEATURE_INDICATION,		"Feature Indication" },
	{ Q931_IE_ENDPOINT_IDENTIFIER,		"Endpoint identifier" },
	{ Q931_IE_SERVICE_PROFILE_ID,		"Service profile ID" },
	{ Q931_IE_INFORMATION_RATE,		"Information rate" },
	{ Q931_IE_E2E_TRANSIT_DELAY,		"End-to-end transit delay" },
	{ Q931_IE_TD_SELECTION_AND_INT,		"Transit delay selection and indication" },
	{ Q931_IE_PL_BINARY_PARAMETERS,		"Packet layer binary parameters" },
	{ Q931_IE_PL_WINDOW_SIZE,		"Packet layer window size" },
	{ Q931_IE_PL_SIZE,			"Packet layer size" },
	{ Q931_IE_CALLING_PARTY_NUMBER,		"Calling party number" },
	{ Q931_IE_CALLING_PARTY_SUBADDR,	"Calling party subaddress" },
	{ Q931_IE_CALLED_PARTY_NUMBER,		"Called party number" },
	{ Q931_IE_CALLED_PARTY_SUBADDR,		"Called party subaddress" },
	{ Q931_IE_REDIRECTING_NUMBER,		"Redirecting number" },
	{ Q931_IE_REDIRECTION_NUMBER,		"Redirection number" },
	{ Q931_IE_TRANSIT_NETWORK_SEL,		"Transit network selection" },
	{ Q931_IE_RESTART_INDICATOR,		"Restart indicator" },
	{ Q931_IE_LOW_LAYER_COMPAT,		"Low-layer compatibility" },
	{ Q931_IE_HIGH_LAYER_COMPAT,		"High-layer compatibility" },
	{ Q931_IE_USER_USER,			"User-user" },
	{ Q931_IE_ESCAPE,			"Escape" },
	{ Q931_IE_CONNECTED_NUMBER,		"Connected number" },
	{ Q931_IE_CONNECTED_SUBADDR,		"Connected subaddress" },
	{ Q931_IE_CHARGING_ADVICE,		"Charging advice" },
	{ Q931_IE_OPERATOR_SYSTEM_ACCESS,	"Operator system access" },
	{ Q931_IE_REDIRECTING_NUMBER,		"Redirecting number" },
	{ Q931_IE_REDIRECTING_SUBADDR,		"Redirecting subaddress" },
	{ Q931_IE_CALL_APPEARANCE,		"Call appearance" },
	{ 0,					NULL }
};

/*
 * Cause codes for Cause.
 */
static const value_string q931_cause_code_vals[] = {
	{ 0,	"Valid cause code not yet received" },
	{ 1,	"Unallocated (unassigned) number" },
	{ 2,	"No route to specified transit network (WAN)" },
	{ 3,	"No route to destination" },
	{ 4,	"send special information tone" },
	{ 5,	"Misdialled trunk prefix" },
	{ 6,	"Channel unacceptable" },
	{ 7,	"Call awarded and being delivered in an established channel" },
	{ 8,	"Prefix 0 dialed but not allowed" },
	{ 9,	"Prefix 1 dialed but not allowed" },
	{ 10,	"Prefix 1 dialed but not required" },
	{ 11,	"More digits received than allowed, call is proceeding" },
	{ 16,	"Normal call clearing" },
	{ 17,	"User busy" },
	{ 18,	"No user responding" },
	{ 19,	"No answer from user" },
	{ 20,	"Subscriber absent" },
	{ 21,	"Call rejected" },
	{ 22,	"Number changed" },
	{ 23,	"Reverse charging rejected" },
	{ 24,	"Call suspended" },
	{ 25,	"Call resumed" },
	{ 26,	"Non-selected user clearing" },
	{ 27,	"Destination out of order" },
	{ 28,	"Invalid number format (incomplete number)" },
	{ 29,	"Facility rejected" },
	{ 30,	"Response to STATUS ENQUIRY" },
	{ 31,	"Normal, unspecified" },
	{ 33,	"Circuit out of order" },
	{ 34,	"No circuit/channel available" },
	{ 35,	"Destination unattainable" },
	{ 37,	"Degraded service" },
	{ 38,	"Network (WAN) out of order" },
	{ 39,	"Transit delay range cannot be achieved" },
	{ 40,	"Throughput range cannot be achieved" },
	{ 41,	"Temporary failure" },
	{ 42,	"Switching equipment congestion" },
	{ 43,	"Access information discarded" },
	{ 44,	"Requested circuit channel not available" },
	{ 45,	"Pre-empted" },
	{ 46,	"Precedence call blocked" },
	{ 47,	"Resource unavailable - unspecified" },
	{ 49,	"Quality of service unavailable" },
	{ 50,	"Requested facility not subscribed" },
	{ 51,	"Reverse charging not allowed" },
	{ 52,	"Outgoing calls barred" },
	{ 53,	"Outgoing calls barred within CUG" },
	{ 54,	"Incoming calls barred" },
	{ 55,	"Incoming calls barred within CUG" },
	{ 56,	"Call waiting not subscribed" },
	{ 57,	"Bearer capability not authorized" },
	{ 58,	"Bearer capability not presently available" },
	{ 62,	"Inconsistency in designated outgoing access information and subscriber class" },
	{ 63,	"Service or option not available, unspecified" },
	{ 65,	"Bearer service not implemented" },
	{ 66,	"Channel type not implemented" },
	{ 67,	"Transit network selection not implemented" },
	{ 68,	"Message not implemented" },
	{ 69,	"Requested facility not implemented" },
	{ 70,	"Only restricted digital information bearer capability is available" },
	{ 79,	"Service or option not implemented, unspecified" },
	{ 81,	"Invalid call reference value" },
	{ 82,	"Identified channel does not exist" },
	{ 83,	"A suspended call exists, but this call identity does not" },
	{ 84,	"Call identity in use" },
	{ 85,	"No call suspended" },
	{ 86,	"Call having the requested call identity has been cleared" },
	{ 87,	"Called user not member of CUG" },
	{ 88,	"Incompatible destination" },
	{ 89,	"Non-existent abbreviated address entry" },
	{ 90,	"Destination address missing, and direct call not subscribed" },
	{ 91,	"Invalid transit network selection (national use)" },
	{ 92,	"Invalid facility parameter" },
	{ 93,	"Mandatory information element is missing" },
	{ 95,	"Invalid message, unspecified" },
	{ 96,	"Mandatory information element is missing" },
	{ 97,	"Message type non-existent or not implemented" },
	{ 98,	"Message not compatible with call state or message type non-existent or not implemented" },
	{ 99,	"Information element nonexistant or not implemented" },
	{ 100,	"Invalid information element contents" },
	{ 101,	"Message not compatible with call state" },
	{ 102,	"Recovery on timer expiry" },
	{ 103,	"Parameter non-existent or not implemented - passed on" },
	{ 110,	"Message with unrecognized parameter discarded" },
	{ 111,	"Protocol error, unspecified" },
	{ 127,	"Internetworking, unspecified" },
	{ 0,	NULL }
};

/*
 * Call status tones for Signal.
 */
#define	Q931_SIGNAL_DIAL_TONE		0x00
#define	Q931_SIGNAL_RINGING		0x01
#define	Q931_SIGNAL_INTERCEPT		0x02
#define	Q931_SIGNAL_NETWORK_CONGESTION	0x03	/* "fast busy" */
#define	Q931_SIGNAL_BUSY		0x04
#define	Q931_SIGNAL_CONFIRM		0x05
#define	Q931_SIGNAL_ANSWER		0x06
#define	Q931_SIGNAL_CALL_WAITING	0x07
#define	Q931_SIGNAL_OFF_HOOK_WARNING	0x08
#define	Q931_SIGNAL_TONES_OFF		0x3F

void
dissect_q931(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_tree	*q931_tree = NULL;
	proto_item	*ti;
	proto_tree	*ie_tree;
	guint8		call_ref_len;
	guint8		call_ref[15];
	guint8		message_type;
	guint8		info_element;
	guint8		info_element_len;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "Q.931");

	if (tree) {
		ti = proto_tree_add_item(tree, proto_q931, offset, 3, NULL);
		q931_tree = proto_item_add_subtree(ti, ETT_Q931);

		proto_tree_add_item(q931_tree, hf_q931_discriminator, offset, 1, pd[offset]);
	}
	offset += 1;
	call_ref_len = pd[offset] & 0xF;	/* XXX - do as a bit field? */
	if (q931_tree != NULL)
		proto_tree_add_item(q931_tree, hf_q931_call_ref_len, offset, 1, call_ref_len);
	offset += 1;
	if (call_ref_len != 0) {
		/* XXX - split this into flag and value */
		memcpy(call_ref, &pd[offset], call_ref_len);
		if (q931_tree != NULL)
			proto_tree_add_item(q931_tree, hf_q931_call_ref, offset, call_ref_len, call_ref);
		offset += call_ref_len;
	}
	message_type = pd[offset];
	if (check_col(fd, COL_INFO)) {
		col_add_str(fd, COL_INFO,
		    val_to_str(message_type, q931_message_type_vals,
		      "Unknown message type (0x%02X)"));
	}
	if (q931_tree != NULL)
		proto_tree_add_item(q931_tree, hf_q931_message_type, offset, 1, message_type);
	offset += 1;

	/*
	 * And now for the information elements....
	 */
	while (IS_DATA_IN_FRAME(offset)) {
		info_element = pd[offset];
		switch (info_element & Q931_IE_SO_IDENTIFIER_MASK) {

		case Q931_IE_SHIFT:
			if (q931_tree != NULL) {
				proto_tree_add_text(q931_tree, offset, 1,
				    "Shift: %u", info_element & Q931_IE_SO_IE_MASK);
			}
			offset += 1;		
			break;

		case Q931_IE_MORE_DATA_OR_SEND_COMP:
			switch (info_element) {

			case Q931_IE_MORE_DATA:
				if (q931_tree != NULL) {
					proto_tree_add_text(q931_tree, offset, 1,
					    "More data");
				}
				break;

			case Q931_IE_SENDING_COMPLETE:
				if (q931_tree != NULL) {
					proto_tree_add_text(q931_tree, offset, 1,
					    "Sending complete");
				}
				break;

			default:
				if (q931_tree != NULL) {
					proto_tree_add_text(q931_tree, offset, 1,
					    "Unknown information element (0x%02X",
					    info_element);
				}
				break;
			}
			offset += 1;		
			break;

		case Q931_IE_CONGESTION_LEVEL:
			if (q931_tree != NULL) {
				proto_tree_add_text(q931_tree, offset, 1,
				    "Congestion level: %u", info_element & Q931_IE_SO_IE_MASK);
			}		
			offset += 1;		
			break;

		case Q931_IE_REPEAT_INDICATOR:
			if (q931_tree != NULL) {
				proto_tree_add_text(q931_tree, offset, 1,
				    "Repeat indicator: %u", info_element & Q931_IE_SO_IE_MASK);
			}		
			offset += 1;		
			break;

		default:
			/*
			 * Variable-length IE.
			 */
			if (!BYTES_ARE_IN_FRAME(offset + 1, 1))
				break;	/* ran past end of frame */
			info_element_len = pd[offset + 1];
			if (!BYTES_ARE_IN_FRAME(offset + 2, info_element_len))
				break;	/* ran past end of frame */
			if (q931_tree != NULL) {
				ti = proto_tree_add_text(q931_tree, offset,
				    1+1+info_element_len,
				    "%s",
				    val_to_str(info_element,
				      q931_info_element_vals,
				      "Unknown information element (0x%02X)"));
				ie_tree = proto_item_add_subtree(ti,
				    ETT_Q931_IE);
				proto_tree_add_text(ie_tree, offset, 1,
				    "Information element: %s",
				    val_to_str(info_element,
				      q931_info_element_vals,
				      "Unknown"));
				proto_tree_add_text(ie_tree, offset + 1, 1,
				    "Length: %u", info_element_len);
				proto_tree_add_text(ie_tree, offset + 2,
				    info_element_len,
				    "Data: %s",
				    bytes_to_str(&pd[offset + 2],
				      info_element_len));
			}
			offset += 1 + 1 + info_element_len;
			break;
		}
	}
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
	  { "Call reference value", "q931.call_ref", FT_BYTES, BASE_HEX, NULL, 0x0,
	  	"" }},

	{ &hf_q931_message_type,
	  { "Message type", "q931.message_type", FT_UINT8, BASE_HEX, VALS(q931_message_type_vals), 0x0,
	  	"" }},

    };

    proto_q931 = proto_register_protocol ("Q.931", "q931");
    proto_register_field_array (proto_q931, hf, array_length(hf));
}
