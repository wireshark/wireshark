/* packet-q931.c
 * Routines for Q.931 frame disassembly
 * Guy Harris <guy@alum.mit.edu>
 *
 * $Id: packet-q931.c,v 1.13 2000/01/13 05:41:21 guy Exp $
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
#include "nlpid.h"
#include "packet-q931.h"

/* Q.931 references:
 *
 * http://www.acacia-net.com/Clarinet/Protocol/q9313svn.htm
 * http://www.acacia-net.com/Clarinet/Protocol/q9311sc3.htm
 * http://www.acacia-net.com/Clarinet/Protocol/q9317oz7.htm
 * http://www.protocols.com/pbook/isdn.htm
 * http://freesoft.org/CIE/Topics/126.htm
 * http://noc.comstar.ru/miscdocs/ascend-faq-cause-codes.html
 * http://www.andrews-arnold.co.uk/isdn/q931cause.html
 * http://www.tulatelecom.ru/staff/german/DSSHelp/MessList/InfEl/InfElList.html
 */

static int proto_q931 = -1;
static int hf_q931_discriminator = -1;
static int hf_q931_call_ref_len = -1;
static int hf_q931_call_ref = -1;
static int hf_q931_message_type = -1;

static gint ett_q931 = -1;
static gint ett_q931_ie = -1;

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
#define	Q931_INFORMATION	0x7B
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
	{ Q931_INFORMATION,		"INFORMATION" },
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
#define	Q931_IE_SO_IDENTIFIER_MASK	0xf0	/* IE identifier mask */
#define	Q931_IE_SO_IDENTIFIER_SHIFT	4	/* IE identifier shift */
#define	Q931_IE_SO_IE_MASK		0x0F	/* IE mask */

#define	Q931_IE_SHIFT			0x90
#define	Q931_IE_SHIFT_LOCKING		0x08	/* locking shift */
#define	Q931_IE_SHIFT_CODESET		0x0F	/* codeset */

#define	Q931_IE_MORE_DATA_OR_SEND_COMP	0xA0	/* More Data or Sending Complete */
#define	Q931_IE_MORE_DATA		0xA0
#define	Q931_IE_SENDING_COMPLETE	0xA1

#define	Q931_IE_CONGESTION_LEVEL	0xB0
#define	Q931_IE_REPEAT_INDICATOR	0xD0

/*
 * Variable-length IEs.
 */
#define	Q931_IE_VL_EXTENSION		0x80	/* Extension flag */

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
#define	Q931_IE_PL_WINDOW_SIZE		0x45	/* Packet layer window size */
#define	Q931_IE_PACKET_SIZE		0x46	/* Packet size */
#define	Q931_IE_CUG			0x47	/* Closed user group */
#define	Q931_IE_REVERSE_CHARGE_IND	0x4A	/* Reverse charging indication */
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
	{ Q931_IE_PACKET_SIZE,			"Packet size" },
	{ Q931_IE_CUG,				"Closed user group" },
	{ Q931_IE_REVERSE_CHARGE_IND,		"Reverse charging indication" },
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

static const value_string q931_congestion_level_vals[] = {
	{ 0x0, "Receiver ready" },
	{ 0xF, "Receiver not ready" },
	{ 0,   NULL }
};

static const value_string q931_repeat_indication_vals[] = {
	{ 0x2, "Prioritized list" },
	{ 0,   NULL }
};

/*
 * ITU-standardized coding.
 */
#define	Q931_ITU_STANDARDIZED_CODING	0x00

/*
 * Dissect a Segmented message information element.
 */
static void
dissect_q931_segmented_message_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	if (len != 2) {
		proto_tree_add_text(tree, offset, len,
		    "Segmented message: length is %d, should be 2\n", len);
		return;
	}
	if (pd[offset] & 0x80) {
		proto_tree_add_text(tree, offset, 1,
		    "First segment: %u segments remaining",
		    pd[offset] & 0x7F);
	} else {
		proto_tree_add_text(tree, offset, 1,
		    "Not first segment: %u segments remaining",
		    pd[offset] & 0x7F);
	}
	proto_tree_add_text(tree, offset + 1, 1,
	    "Segmented message type: %u\n", pd[offset + 1]);
}

/*
 * Dissect a Bearer capability or Low-layer compatibility information element.
 */
static const value_string q931_bc_coding_standard_vals[] = {
	{ 0x00, "ITU-T standardized coding" },
	{ 0x20, "ISO/IEC standard" },
	{ 0x40, "National standard" },
	{ 0x60, "Standard defined for this particular network" },
	{ 0,    NULL }
};

static const value_string q931_information_transfer_capability_vals[] = {
	{ 0x00, "Speech" },
	{ 0x08, "Unrestricted digital information" },
	{ 0x09, "Restricted digital information" },
	{ 0x10, "3.1 kHz audio" },
	{ 0x11, "Unrestricted digital information with tones/announcements" },
	{ 0x18, "Video" },
	{ 0,    NULL }
};
	
static const value_string q931_transfer_mode_vals[] = {
	{ 0x00, "Circuit mode" },
	{ 0x40, "Packet mode" },
	{ 0,    NULL }
};

#define	Q931_IT_RATE_MULTIRATE	0x18

static const value_string q931_information_transfer_rate_vals[] = {
	{ 0x00,				"Packet mode" },
	{ 0x10,				"64 kbit/s" },
	{ 0x11,				"2 x 64 kbit/s" },
	{ 0x13,				"384 kbit/s" },
	{ 0x15,				"1536 kbit/s" },
	{ 0x17,				"1920 kbit/s" },
	{ Q931_IT_RATE_MULTIRATE,	"Multirate (64 kbit/s base rate)" },
	{ 0,				NULL }
};
	
static const value_string q931_uil1_vals[] = {
	{ 0x01, "V.110/I.460/X.30 rate adaption" },
	{ 0x02, "Recommendation G.711 u-law" },
	{ 0x03, "Recommendation G.711 A-law" },
	{ 0x04, "Recommendation G.721 32 kbit/s ADPCM and Recommendation I.460" },
	{ 0x05, "Recommendation H.221 and H.242" },
	{ 0x06, "Recommendation H.223 and H.245" },
	{ 0x07, "Non-ITU-T-standardized rate adaption" },
	{ 0x08, "V.120 rate adaption" },
	{ 0x09, "X.31 HDLC flag stuffing" },
	{ 0,    NULL },
};

static const value_string q931_l1_user_rate_vals[] = {
	{ 0x00, "Rate indicated by E-bits" },
	{ 0x01, "0.6 kbit/s" },
	{ 0x02, "1.2 kbit/s" },
	{ 0x03, "2.4 kbit/s" },
	{ 0x04, "3.6 kbit/s" },
	{ 0x05, "4.8 kbit/s" },
	{ 0x06, "7.2 kbit/s" },
	{ 0x07, "8 kbit/s" },
	{ 0x08, "9.6 kbit/s" },
	{ 0x09, "14.4 kbit/s" },
	{ 0x0A, "16 kbit/s" },
	{ 0x0B, "19.2 kbit/s" },
	{ 0x0C, "32 kbit/s" },
	{ 0x0E, "48 kbit/s" },
	{ 0x0F, "56 kbit/s" },
	{ 0x10, "64 kbit/s "},
	{ 0x15, "0.1345 kbit/s" },
	{ 0x16, "0.100 kbit/s" },
	{ 0x17, "0.075/1.2 kbit/s" },
	{ 0x18, "1.2/0.075 kbit/s" },
	{ 0x19, "0.050 kbit/s" },
	{ 0x1A, "0.075 kbit/s" },
	{ 0x1B, "0.110 kbit/s" },
	{ 0x1C, "0.150 kbit/s" },
	{ 0x1D, "0.200 kbit/s" },
	{ 0x1E, "0.300 kbit/s" },
	{ 0x1F, "12 kbit/s" },
	{ 0,    NULL }
};

static const value_string q931_l1_intermediate_rate_vals[] = {
	{ 0x20, "8 kbit/s" },
	{ 0x40, "16 kbit/s" },
	{ 0x60, "32 kbit/s" },
	{ 0,    NULL }
};

static const value_string q931_l1_stop_bits_vals[] = {
	{ 0x20, "1" },
	{ 0x40, "1.5" },
	{ 0x60, "2" },
	{ 0,    NULL }
};

static const value_string q931_l1_data_bits_vals[] = {
	{ 0x08, "5" },
	{ 0x10, "7" },
	{ 0x18, "8" },
	{ 0,    NULL }
};

static const value_string q931_l1_parity_vals[] = {
	{ 0x00, "Odd" },
	{ 0x02, "Even" },
	{ 0x03, "None" },
	{ 0x04, "Forced to 0" },
	{ 0x05, "Forced to 1" },
	{ 0,    NULL }
};

static const value_string q931_l1_modem_type_vals[] = {
	{ 0x11, "V.21" },
	{ 0x12, "V.22" },
	{ 0x13, "V.22 bis" },
	{ 0x14, "V.23" },
	{ 0x15, "V.26" },
	{ 0x16, "V.26 bis" },
	{ 0x17, "V.26 ter" },
	{ 0x18, "V.27" },
	{ 0x19, "V.27 bis" },
	{ 0x1A, "V.27 ter" },
	{ 0x1B, "V.29" },
	{ 0x1C, "V.32" },
	{ 0x1E, "V.34" },
	{ 0,    NULL }
};

#define	Q931_UIL2_USER_SPEC	0x10

static const value_string q931_uil2_vals[] = {
	{ 0x01,			"Basic mode ISO 1745" },
	{ 0x02,			"Q.921/I.441" },	/* LAPD */
	{ 0x06,			"X.25, link layer" },	/* LAPB */
	{ 0x07,			"X.25 multilink" },	/* or 0x0F? */
	{ 0x08,			"T.71 Extended LAPB" },
	{ 0x09,			"HDLC ARM" },
	{ 0x0A,			"HDLC NRM" },
	{ 0x0B,			"HDLC ABM" },
	{ 0x0C,			"ISO 8802/2 LLC" },
	{ 0x0D,			"X.75 Single Link Procedure" },
	{ 0x0E,			"Q.922" },
	{ 0x0F,			"Core aspects of Q.922" },
	{ Q931_UIL2_USER_SPEC,	"User-specified" },
	{ 0x11,			"ISO 7776 DTE-DTE operation" },
	{ 0,			NULL }
};

static const value_string q931_mode_vals[] = {
	{ 0x20, "Normal mode" },
	{ 0x40, "Extended mode" },
	{ 0,    NULL }
};

#define	Q931_UIL3_X25_PL	0x06
#define	Q931_UIL3_ISO_8208	0x07	/* X.25-based */
#define	Q931_UIL3_X223		0x08	/* X.25-based */
#define	Q931_UIL3_TR_9577	0x0B
#define	Q931_UIL3_USER_SPEC	0x10

static const value_string q931_uil3_vals[] = {
	{ 0x02,			"Q.931/I.451" },
	{ Q931_UIL3_X25_PL,	"X.25, packet layer" },
	{ Q931_UIL3_ISO_8208,	"ISO/IEC 8208" },
	{ Q931_UIL3_X223,	"X.223/ISO 8878" },
	{ 0x09,			"ISO/IEC 8473" },
	{ 0x0A,			"T.70" },
	{ Q931_UIL3_TR_9577,	"ISO/IEC TR 9577" },
	{ Q931_UIL3_USER_SPEC,	"User-specified" },
	{ 0,			NULL }
};

void
dissect_q931_bearer_capability_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;
	guint8 coding_standard;
	guint8 it_rate;
	guint8 modem_type;
	guint8 uil2_protocol;
	guint8 uil3_protocol;
	guint8 add_l3_info;

	if (len == 0)
		return;
	octet = pd[offset];
	coding_standard = octet & 0x60;
	proto_tree_add_text(tree, offset, 1,
	    "Coding standard: %s",
	    val_to_str(coding_standard, q931_bc_coding_standard_vals, NULL));
	if (coding_standard != Q931_ITU_STANDARDIZED_CODING) {
		/*
		 * We don't know how the bearer capability is encoded,
		 * so just dump it as data and be done with it.
		 */
		proto_tree_add_text(tree, offset,
		    len, "Data: %s", bytes_to_str(&pd[offset], len));
		return;
	}
	proto_tree_add_text(tree, offset, 1,
	    "Information transfer capability: %s",
	    val_to_str(octet & 0x1F, q931_information_transfer_capability_vals,
	      "Unknown (0x%02X)"));
	offset += 1;
	len -= 1;

	/*
	 * XXX - only in Low-layer compatibility information element.
	 */
	if (!(octet & Q931_IE_VL_EXTENSION)) {
		if (len == 0)
			return;
		octet = pd[offset];
		proto_tree_add_text(tree, offset, 1,
		    "Out-band negotiation %spossible",
		    (octet & 0x40) ? "" : "not ");
		offset += 1;
		len -= 1;
	}

	if (len == 0)
		return;
	octet = pd[offset];
	proto_tree_add_text(tree, offset, 1,
	    "Transfer mode: %s",
	    val_to_str(octet & 0x60, q931_transfer_mode_vals,
	      "Unknown (0x%02X)"));
	it_rate = octet & 0x1F;
	proto_tree_add_text(tree, offset, 1,
	    "Information transfer rate: %s",
	    val_to_str(it_rate, q931_information_transfer_rate_vals,
	      "Unknown (0x%02X)"));
	offset += 1;
	len -= 1;

	if (it_rate == Q931_IT_RATE_MULTIRATE) {
		if (len == 0)
			return;
		proto_tree_add_text(tree, offset, 1, "Rate multiplier: %u", pd[offset]);
		offset += 1;
		len -= 1;
	}

	if (len == 0)
		return;
	octet = pd[offset];
	if ((octet & 0x60) == 0x20) {
		/*
		 * Layer 1 information.
		 */
		proto_tree_add_text(tree, offset, 1,
		    "User information layer 1 protocol: %s",
		    val_to_str(octet & 0x1F, q931_uil1_vals,
		      "Unknown (0x%02X)"));
		offset += 1;
		len -= 1;
		
		if (octet & Q931_IE_VL_EXTENSION)
			goto l1_done;
		if (len == 0)
			return;
		octet = pd[offset];
		proto_tree_add_text(tree, offset, 1,
		    "Layer 1 is %s",
		    (octet & 0x40) ? "Asynchronous" : "Synchronous");
		proto_tree_add_text(tree, offset, 1,
		    "Layer 1 in-band negotiation is %spossible",
		    (octet & 0x20) ? "" : "not ");
		proto_tree_add_text(tree, offset, 1,
		    "User rate: %s",
		    val_to_str(octet & 0x1F, q931_l1_user_rate_vals,
		      "Unknown (0x%02X)"));
		offset += 1;
		len -= 1;

		if (octet & Q931_IE_VL_EXTENSION)
			goto l1_done;
		if (len == 0)
			return;
		octet = pd[offset];
		proto_tree_add_text(tree, offset, 1,
		    "Intermediate rate: %s",
		      val_to_str(octet & 0x60, q931_l1_intermediate_rate_vals,
		       "Unknown (0x%X)"));
		proto_tree_add_text(tree, offset, 1,
		    "%s to send data with network independent clock",
		    (octet & 0x10) ? "Required" : "Not required");
		proto_tree_add_text(tree, offset, 1,
		    "%s accept data with network independent clock",
		    (octet & 0x08) ? "Can" : "Cannot");
		proto_tree_add_text(tree, offset, 1,
		    "%s to send data with flow control mechanism",
		    (octet & 0x04) ? "Required" : "Not required");
		proto_tree_add_text(tree, offset, 1,
		    "%s accept data with flow control mechanism",
		    (octet & 0x02) ? "Can" : "Cannot");
		offset += 1;
		len -= 1;

		if (octet & Q931_IE_VL_EXTENSION)
			goto l1_done;
		if (len == 0)
			return;
		octet = pd[offset];
		proto_tree_add_text(tree, offset, 1,
		    "Rate adaption header %sincluded",
		    (octet & 0x40) ? "" : "not ");
		proto_tree_add_text(tree, offset, 1,
		    "Multiple frame establishment %ssupported",
		    (octet & 0x20) ? "" : "not ");
		proto_tree_add_text(tree, offset, 1,
		    "%s mode of operation",
		    (octet & 0x10) ? "Protocol sensitive" : "Bit transparent");
		proto_tree_add_text(tree, offset, 1,
		    (octet & 0x08) ?
		      "Full protocol negotiation" : "LLI = 256 only");
		proto_tree_add_text(tree, offset, 1,
		    "Message originator is %s",
		    (octet & 0x04) ? "Assignor only" : "Default assignee");
		proto_tree_add_text(tree, offset, 1,
		    "Negotiation is done %s",
		    (octet & 0x02) ? "in-band" : "out-of-band");
		offset += 1;
		len -= 1;

		if (octet & Q931_IE_VL_EXTENSION)
			goto l1_done;
		if (len == 0)
			return;
		octet = pd[offset];
		proto_tree_add_text(tree, offset, 1,
		    "Stop bits: %s",
		      val_to_str(octet & 0x60, q931_l1_stop_bits_vals,
		       "Unknown (0x%X)"));
		proto_tree_add_text(tree, offset, 1,
		    "Data bits: %s",
		      val_to_str(octet & 0x18, q931_l1_data_bits_vals,
		       "Unknown (0x%X)"));
		proto_tree_add_text(tree, offset, 1,
		    "Parity: %s",
		      val_to_str(octet & 0x08, q931_l1_parity_vals,
		       "Unknown (0x%X)"));

		if (octet & Q931_IE_VL_EXTENSION)
			goto l1_done;
		if (len == 0)
			return;
		octet = pd[offset];
		proto_tree_add_text(tree, offset, 1,
		    "%s duplex",
		    (octet & 0x40) ? "Full" : "Half");
		modem_type = octet & 0x3F;
		if (modem_type <= 0x5 ||
		    (modem_type >= 0x20 && modem_type <= 0x2F)) {
			proto_tree_add_text(tree, offset, 1,
			    "Modem type: National use 0x%02X", modem_type);
		} else if (modem_type >= 0x30) {
			proto_tree_add_text(tree, offset, 1,
			    "Modem type: User specified 0x%02X", modem_type);
		} else {
			proto_tree_add_text(tree, offset, 1,
			    "Modem type: %s",
			      val_to_str(modem_type, q931_l1_modem_type_vals,
			      NULL));
		}
		offset += 1;
		len -= 1;
	}
l1_done:
	;

	if (len == 0)
		return;
	octet = pd[offset];
	if ((octet & 0x60) == 0x40) {
		/*
		 * Layer 2 information.
		 */
		uil2_protocol = octet & 0x1F;
		proto_tree_add_text(tree, offset, 1,
		    "User information layer 2 protocol: %s",
		    val_to_str(uil2_protocol, q931_uil2_vals,
		      "Unknown (0x%02X)"));
		offset += 1;
		len -= 1;

		/*
		 * XXX - only in Low-layer compatibility information element.
		 */
		if (octet & Q931_IE_VL_EXTENSION)
			goto l2_done;
		if (len == 0)
			return;
		octet = pd[offset];
		if (uil2_protocol == Q931_UIL2_USER_SPEC) {
			proto_tree_add_text(tree, offset, 1,
			    "User-specified layer 2 protocol information: 0x%02X",
			    octet & 0x7F);
		} else {
			proto_tree_add_text(tree, offset, 1,
			    "Mode: %s",
			    val_to_str(octet & 0x60, q931_mode_vals,
			      "Unknown (0x%02X)"));
		}
		offset += 1;
		len -= 1;

		if (octet & Q931_IE_VL_EXTENSION)
			goto l2_done;
		if (len == 0)
			return;
		octet = pd[offset];
		proto_tree_add_text(tree, offset, 1,
		    "Window size: %u k", octet & 0x7F);
		offset += 1;
		len -= 1;
	}
l2_done:
	;

	if (len == 0)
		return;
	octet = pd[offset];
	if ((octet & 0x60) == 0x60) {
		/*
		 * Layer 3 information.
		 */
		uil3_protocol = octet & 0x1F;
		proto_tree_add_text(tree, offset, 1,
		    "User information layer 3 protocol: %s",
		    val_to_str(uil3_protocol, q931_uil3_vals,
		      "Unknown (0x%02X)"));
		offset += 1;
		len -= 1;


		/*
		 * XXX - only in Low-layer compatibility information element.
		 */
		if (octet & Q931_IE_VL_EXTENSION)
			goto l3_done;
		if (len == 0)
			return;
		octet = pd[offset];
		switch (uil3_protocol) {

		case Q931_UIL3_X25_PL:
		case Q931_UIL3_ISO_8208:
		case Q931_UIL3_X223:
			proto_tree_add_text(tree, offset, 1,
			    "Mode: %s",
			    val_to_str(octet & 0x60, q931_mode_vals,
			      "Unknown (0x%02X)"));
			offset += 1;
			len -= 1;

			if (octet & Q931_IE_VL_EXTENSION)
				goto l3_done;
			if (len == 0)
				return;
			octet = pd[offset];
			proto_tree_add_text(tree, offset, 1,
			    "Default packet size: %u", octet & 0x0F);
			offset += 1;
			len -= 1;

			if (octet & Q931_IE_VL_EXTENSION)
				goto l3_done;
			if (len == 0)
				return;
			octet = pd[offset];
			proto_tree_add_text(tree, offset, 1,
			    "Packet window size: %u", octet & 0x7F);
			offset += 1;
			len -= 1;
			break;

		case Q931_UIL3_USER_SPEC:
			proto_tree_add_text(tree, offset, 1,
			    "Default packet size: %u octets",
			    1 << (octet & 0x0F));
			offset += 1;
			len -= 1;
			break;

		case Q931_UIL3_TR_9577:
			add_l3_info = (octet & 0x0F) << 4;
			if (octet & Q931_IE_VL_EXTENSION)
				goto l3_done;
			if (len == 0)
				return;
			octet = pd[offset + 1];
			add_l3_info |= (octet & 0x0F);
			proto_tree_add_text(tree, offset, 2,
			    "Additional layer 3 protocol information: %s",
			    val_to_str(add_l3_info, nlpid_vals,
			      "Unknown (0x%02X)"));
			offset += 2;
			len -= 2;
			break;
		}
	}
l3_done:
	;
}

/*
 * Dissect a Cause information element.
 */
static const value_string q931_cause_coding_standard_vals[] = {
	{ 0x00, "ITU-T standardized coding" },
	{ 0x20, "ISO/IEC standard" },
	{ 0x40, "National standard" },
	{ 0x60, "Standard specific to identified location" },
	{ 0,    NULL }
};
	
static const value_string q931_cause_location_vals[] = {
	{ 0x00, "User (U)" },
	{ 0x01, "Private network serving the local user (LPN)" },
	{ 0x02, "Public network serving the local user (LN)" },
	{ 0x03, "Transit network (TN)" },
	{ 0x04, "Public network serving the remote user (RLN)" },
	{ 0x05, "Private network serving the remote user (RPN)" },
	{ 0x07, "International network (INTL)" },
	{ 0x0A, "Network beyond interworking point (BI)" },
	{ 0,    NULL }
};

static const value_string q931_cause_recommendation_vals[] = {
	{ 0x00, "Q.931" },
	{ 0x03, "X.21" },
	{ 0x04, "X.25" },
	{ 0x05, "Q.1031/Q.1051" },
	{ 0,    NULL }
};

/*
 * Cause codes for Cause.
 */
static const value_string q931_cause_code_vals[] = {
	{ 0x00,	"Valid cause code not yet received" },
	{ 0x01,	"Unallocated (unassigned) number" },
	{ 0x02,	"No route to specified transit network" },
	{ 0x03,	"No route to destination" },
	{ 0x04,	"Send special information tone" },
	{ 0x05,	"Misdialled trunk prefix" },
	{ 0x06,	"Channel unacceptable" },
	{ 0x07,	"Call awarded and being delivered in an established channel" },
	{ 0x08,	"Prefix 0 dialed but not allowed" },
	{ 0x09,	"Prefix 1 dialed but not allowed" },
	{ 0x0A,	"Prefix 1 dialed but not required" },
	{ 0x0B,	"More digits received than allowed, call is proceeding" },
	{ 0x10,	"Normal call clearing" },
	{ 0x11,	"User busy" },
	{ 0x12,	"No user responding" },
	{ 0x13,	"No answer from user (user alerted)" },
	{ 0x14,	"Subscriber absent" },
	{ 0x15,	"Call rejected" },
	{ 0x16,	"Number changed" },
	{ 0x17,	"Reverse charging rejected" },
	{ 0x18,	"Call suspended" },
	{ 0x19,	"Call resumed" },
	{ 0x1A,	"Non-selected user clearing" },
	{ 0x1B,	"Destination out of order" },
	{ 0x1C,	"Invalid number format (incomplete number)" },
	{ 0x1D,	"Facility rejected" },
	{ 0x1E,	"Response to STATUS ENQUIRY" },
	{ 0x1F,	"Normal unspecified" },
	{ 0x21,	"Circuit out of order" },
	{ 0x22,	"No circuit/channel available" },
	{ 0x23,	"Destination unattainable" },
	{ 0x25,	"Degraded service" },
	{ 0x26,	"Network out of order" },
	{ 0x27,	"Transit delay range cannot be achieved" },
	{ 0x28,	"Throughput range cannot be achieved" },
	{ 0x29,	"Temporary failure" },
	{ 0x2A,	"Switching equipment congestion" },
	{ 0x2B,	"Access information discarded" },
	{ 0x2C,	"Requested circuit/channel not available" },
	{ 0x2D,	"Pre-empted" },
	{ 0x2E,	"Precedence call blocked" },
	{ 0x2F,	"Resources unavailable, unspecified" },
	{ 0x31,	"Quality of service unavailable" },
	{ 0x32,	"Requested facility not subscribed" },
	{ 0x33,	"Reverse charging not allowed" },
	{ 0x34,	"Outgoing calls barred" },
	{ 0x35,	"Outgoing calls barred within CUG" },
	{ 0x36,	"Incoming calls barred" },
	{ 0x37,	"Incoming calls barred within CUG" },
	{ 0x38,	"Call waiting not subscribed" },
	{ 0x39,	"Bearer capability not authorized" },
	{ 0x3A,	"Bearer capability not presently available" },
	{ 0x3E,	"Inconsistency in designated outgoing access information and subscriber class" },
	{ 0x3F,	"Service or option not available, unspecified" },
	{ 0x41,	"Bearer capability not implemented" },
	{ 0x42,	"Channel type not implemented" },
	{ 0x43,	"Transit network selection not implemented" },
	{ 0x44,	"Message not implemented" },
	{ 0x45,	"Requested facility not implemented" },
	{ 0x46,	"Only restricted digital information bearer capability is available" },
	{ 0x4F,	"Service or option not implemented, unspecified" },
	{ 0x51,	"Invalid call reference value" },
	{ 0x52,	"Identified channel does not exist" },
	{ 0x53,	"Call identity does not exist for suspended call" },
	{ 0x54,	"Call identity in use" },
	{ 0x55,	"No call suspended" },
	{ 0x56,	"Call having the requested call identity has been cleared" },
	{ 0x57,	"Called user not member of CUG" },
	{ 0x58,	"Incompatible destination" },
	{ 0x59,	"Non-existent abbreviated address entry" },
	{ 0x5A,	"Destination address missing, and direct call not subscribed" },
	{ 0x5B,	"Invalid transit network selection (national use)" },
	{ 0x5C,	"Invalid facility parameter" },
	{ 0x5D,	"Mandatory information element is missing" },
	{ 0x5F,	"Invalid message, unspecified" },
	{ 0x60,	"Mandatory information element is missing" },
	{ 0x61,	"Message type non-existent or not implemented" },
	{ 0x62,	"Message not compatible with call state or message type non-existent or not implemented" },
	{ 0x63,	"Information element nonexistant or not implemented" },
	{ 0x64,	"Invalid information element contents" },
	{ 0x65,	"Message not compatible with call state" },
	{ 0x66,	"Recovery on timer expiry" },
	{ 0x67,	"Parameter non-existent or not implemented - passed on" },
	{ 0x6E,	"Message with unrecognized parameter discarded" },
	{ 0x6F,	"Protocol error, unspecified" },
	{ 0x7F,	"Internetworking, unspecified" },
	{ 0,	NULL }
};

static void
dissect_q931_cause_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;
	guint8 coding_standard;

	if (len == 0)
		return;
	octet = pd[offset];
	coding_standard = octet & 0x60;
	proto_tree_add_text(tree, offset, 1,
	    "Coding standard: %s",
	    val_to_str(coding_standard, q931_cause_coding_standard_vals, NULL));
	if (coding_standard != Q931_ITU_STANDARDIZED_CODING) {
		/*
		 * We don't know how the cause is encoded,
		 * so just dump it as data and be done with it.
		 */
		proto_tree_add_text(tree, offset,
		    len, "Data: %s", bytes_to_str(&pd[offset], len));
		return;
	}
	proto_tree_add_text(tree, offset, 1,
	    "Location: %s",
	    val_to_str(octet & 0x0F, q931_cause_location_vals,
	      "Unknown (0x%X)"));
	offset += 1;
	len -= 1;

	if (!(octet & Q931_IE_VL_EXTENSION)) {
		if (len == 0)
			return;
		octet = pd[offset];
		proto_tree_add_text(tree, offset, 1,
		    "Recommendation: %s",
		    val_to_str(octet & 0x7F, q931_cause_recommendation_vals,
		      "Unknown (0x%X)"));
		offset += 1;
		len -= 1;
	}

	if (len == 0)
		return;
	octet = pd[offset];
	proto_tree_add_text(tree, offset, 1,
	    "Cause value: %s",
	    val_to_str(octet & 0x7F, q931_cause_code_vals,
	      "Unknown (0x%X)"));
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	proto_tree_add_text(tree, offset, len,
	    "Diagnostics: %s",
	    bytes_to_str(&pd[offset], len));
}

/*
 * Dissect a Call state information element.
 */
static const value_string q931_coding_standard_vals[] = {
	{ 0x00, "ITU-T standardized coding" },
	{ 0x20, "ISO/IEC standard" },
	{ 0x40, "National standard" },
	{ 0x60, "Standard defined for the network" },
	{ 0,    NULL }
};
	
static const value_string q931_call_state_vals[] = {
	{ 0x00, "Null" },
	{ 0x01, "Call initiated" },
	{ 0x02, "Overlap sending" },
	{ 0x03, "Outgoing call proceeding" },
	{ 0x04, "Call delivered" },
	{ 0x06, "Call present" },
	{ 0x07, "Call received" },
	{ 0x09, "Connect request" },
	{ 0x0A, "Incoming call proceeding" },
	{ 0x0B, "Active" },
	{ 0x0C, "Disconnect request" },
	{ 0x0F, "Disconnect indication" },
	{ 0x11, "Suspend request" },
	{ 0x13, "Resume request" },
	{ 0x16, "Release request" },
	{ 0x19, "Overlap receiving" },
	{ 0x3D, "Restart request" },
	{ 0x3E, "Restart" },
	{ 0,    NULL }
};

static void
dissect_q931_call_state_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;
	guint8 coding_standard;

	if (len == 0)
		return;
	octet = pd[offset];
	coding_standard = octet & 0x60;
	proto_tree_add_text(tree, offset, 1,
	    "Coding standard: %s",
	    val_to_str(coding_standard, q931_coding_standard_vals, NULL));
	if (coding_standard != Q931_ITU_STANDARDIZED_CODING) {
		/*
		 * We don't know how the call state is encoded,
		 * so just dump it as data and be done with it.
		 */
		proto_tree_add_text(tree, offset,
		    len, "Data: %s", bytes_to_str(&pd[offset], len));
		return;
	}
	proto_tree_add_text(tree, offset, 1,
	    "Call state: %s",
	    val_to_str(octet & 0x3F, q931_call_state_vals,
	      "Unknown (0x%02X)"));
}

/*
 * Dissect a Channel identification information element.
 */
#define	Q931_INTERFACE_IDENTIFIED	0x40
#define	Q931_NOT_BASIC_CHANNEL		0x20

static const value_string q931_basic_channel_selection_vals[] = {
	{ 0x00, "No channel" },
	{ 0x01, "B1 channel" },
	{ 0x02, "B2 channel" },
	{ 0x03, "Any channel" },
	{ 0,    NULL }
};

static const value_string q931_not_basic_channel_selection_vals[] = {
	{ 0x00, "No channel" },
	{ 0x01, "Channel indicated in following octets" },
	{ 0x03, "Any channel" },
	{ 0,    NULL }
};

#define	Q931_IS_SLOT_MAP		0x10
	
static const value_string q931_element_type_vals[] = {
	{ 0x03, "B-channel units" },
	{ 0x06, "H0-channel units" },
	{ 0x08, "H11-channel units" },
	{ 0x09, "H12-channel units" },
	{ 0,    NULL }
};

static void
dissect_q931_channel_identification_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;
	int identifier_offset;
	int identifier_len;
	guint8 coding_standard;

	if (len == 0)
		return;
	octet = pd[offset];
	proto_tree_add_text(tree, offset, 1,
	    "Interface %s identified",
	    (octet & Q931_INTERFACE_IDENTIFIED) ? "explicitly" : "implicitly");
	proto_tree_add_text(tree, offset, 1,
	    "%s interface",
	    (octet & Q931_NOT_BASIC_CHANNEL) ? "Not basic" : "Basic");
	proto_tree_add_text(tree, offset, 1,
	    "Indicated channel is %s",
	    (octet & 0x08) ? "required" : "preferred");
	proto_tree_add_text(tree, offset, 1,
	    "Indicated channel is %sthe D-channel",
	    (octet & 0x04) ? "" : "not ");
	if (octet & Q931_NOT_BASIC_CHANNEL) {
		proto_tree_add_text(tree, offset, 1,
		    "Channel selection: %s",
		    val_to_str(octet & 0x03, q931_not_basic_channel_selection_vals,
		      NULL));
	} else {
		proto_tree_add_text(tree, offset, 1,
		    "Channel selection: %s",
		    val_to_str(octet & 0x03, q931_basic_channel_selection_vals,
		      NULL));
	}
	offset += 1;
	len -= 1;

	if (octet & Q931_INTERFACE_IDENTIFIED) {
		identifier_offset = offset;
		identifier_len = 0;
		do {
			if (len == 0)
				break;
			octet = pd[offset];
			offset += 1;
			len -= 1;
			identifier_len++;
		} while (!(octet & Q931_IE_VL_EXTENSION));

		/*
		 * XXX - do we want to strip off the 8th bit on the
		 * last octet of the interface identifier?
		 */
		if (identifier_len != 0) {
			proto_tree_add_text(tree, identifier_offset,
			    identifier_len, "Interface identifier: %s",
			    bytes_to_str(&pd[identifier_offset],
			      identifier_len));
		}
	}

	if (octet & Q931_NOT_BASIC_CHANNEL) {
		if (len == 0)
			return;
		octet = pd[offset];
		coding_standard = octet & 0x60;
		proto_tree_add_text(tree, offset, 1,
		    "Coding standard: %s",
		    val_to_str(coding_standard, q931_coding_standard_vals,
		      NULL));
		if (coding_standard != Q931_ITU_STANDARDIZED_CODING) {
			/*
			 * We don't know how the channel identifier is
			 * encoded, so just dump it as data and be done
			 * with it.
			 */
			proto_tree_add_text(tree, offset,
			    len, "Data: %s", bytes_to_str(&pd[offset], len));
			return;
		}
		proto_tree_add_text(tree, offset, 1,
		    "Channel is indicated by %s",
		    (octet & Q931_IS_SLOT_MAP) ? "slot map" : "number");
		proto_tree_add_text(tree, offset, 1,
		    "%s type: %s",
		    (octet & Q931_IS_SLOT_MAP) ? "Map element" : "Channel",
		    val_to_str(octet & 0x0F, q931_element_type_vals,
		    "Unknown (0x%02X)"));

		/*
		 * XXX - dump the channel number or slot map.
		 */
	}
}

/*
 * Dissect a Progress indicator information element.
 */
static const value_string q931_progress_description_vals[] = {
	{ 0x01, "Call is not end-to-end ISDN - progress information available in-band" },
	{ 0x02, "Destination address is non-ISDN" },
	{ 0x03, "Origination address is non-ISDN" },
	{ 0x04, "Call has returned to the ISDN" },
	{ 0x05, "Interworking has occurred and has resulted in a telecommunications service change" },
	{ 0x08, "In-band information or an appropriate pattern is now available" },
	{ 0,    NULL }
};

void
dissect_q931_progress_indicator_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;
	guint8 coding_standard;

	if (len == 0)
		return;
	octet = pd[offset];
	coding_standard = octet & 0x60;
	proto_tree_add_text(tree, offset, 1,
	    "Coding standard: %s",
	    val_to_str(coding_standard, q931_cause_coding_standard_vals, NULL));
	if (coding_standard != Q931_ITU_STANDARDIZED_CODING) {
		/*
		 * We don't know how the progress indicator is encoded,
		 * so just dump it as data and be done with it.
		 */
		proto_tree_add_text(tree, offset,
		    len, "Data: %s", bytes_to_str(&pd[offset], len));
		return;
	}
	proto_tree_add_text(tree, offset, 1,
	    "Location: %s",
	    val_to_str(octet & 0x0F, q931_cause_location_vals,
	      "Unknown (0x%X)"));
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	octet = pd[offset];
	proto_tree_add_text(tree, offset, 1,
	    "Progress description: %s",
	    val_to_str(octet & 0x7F, q931_progress_description_vals,
	      "Unknown (0x%02X)"));
}

/*
 * Dissect a Network-specific facilities or Transit network selection
 * information element.
 */
static const value_string q931_netid_type_vals[] = {
	{ 0x00, "User specified" },
	{ 0x20, "National network identification" },
	{ 0x30, "International network identification" },
	{ 0,    NULL }
};

static const value_string q931_netid_plan_vals[] = {
	{ 0x00, "Unknown" },
	{ 0x01, "Carrier Identification Code" },
	{ 0x03, "X.121 data network identification code" },
	{ 0,    NULL }
};

static void
dissect_q931_ns_facilities_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;
	int netid_len;

	if (len == 0)
		return;
	octet = pd[offset];
	netid_len = octet & 0x7F;
	proto_tree_add_text(tree, offset, 1,
	    "Network identification length: %u",
	    netid_len);
	offset += 1;
	len -= 1;
	if (netid_len != 0) {
		if (len == 0)
			return;
		octet = pd[offset];
		proto_tree_add_text(tree, offset, 1,
		    "Type of network identification: %s",
		    val_to_str(octet & 0x70, q931_netid_type_vals,
		      "Unknown (0x%02X)"));
		proto_tree_add_text(tree, offset, 1,
		    "Network identification plan: %s",
		    val_to_str(octet & 0x0F, q931_netid_plan_vals,
		      "Unknown (0x%02X)"));
		offset += 1;
		len -= 1;
		netid_len--;

		if (len == 0)
			return;
		if (netid_len > len)
			netid_len = len;
		if (netid_len != 0) {
			proto_tree_add_text(tree, offset, netid_len,
			    "Network identification: %.*s",
			    netid_len, &pd[offset]);
			offset += netid_len;
			len -= netid_len;
		}
	}

	/*
	 * Whatever is left is the network-specific facility
	 * specification.
	 */
	 if (len == 0)
	 	return;
	proto_tree_add_text(tree, offset,
	    len, "Network-specific facility specification: %s",
	    bytes_to_str(&pd[offset], len));
}

/*
 * Dissect a Notification indicator information element.
 */
static const value_string q931_notification_description_vals[] = {
	{ 0x00, "User suspended" },
	{ 0x01, "User resumed" },
	{ 0x02, "Bearer service change" },
	{ 0,    NULL }
};

static void
dissect_q931_notification_indicator_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;

	if (len == 0)
		return;
	octet = pd[offset];
	proto_tree_add_text(tree, offset, 1,
	    "Notification description: %s",
	    val_to_str(octet & 0x7F, q931_notification_description_vals,
	      "Unknown (0x%02X)"));
}

/*
 * Dissect a Date/time information element.
 */
static void
dissect_q931_date_time_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	if (len != 6) {
		proto_tree_add_text(tree, offset, len,
		    "Date/time: length is %d, should be 6\n", len);
		return;
	}
	/*
	 * XXX - what is "year" relative to?  Is "month" 0-origin or
	 * 1-origin?  Q.931 doesn't say....
	 */
	proto_tree_add_text(tree, offset, 6,
	    "Date/time: %02u-%02u-%02u %02u:%02u:%02u",
	    pd[offset + 0], pd[offset + 1], pd[offset + 2],
	    pd[offset + 3], pd[offset + 4], pd[offset + 5]);
}

/*
 * Dissect a Signal information element.
 */
static const value_string q931_signal_vals[] = {
	{ 0x00, "Dial tone on" },
	{ 0x01, "Ring tone on" },
	{ 0x02, "Intercept tone on" },
	{ 0x03, "Network congestion tone on" },	/* "fast busy" */
	{ 0x04, "Busy tone on" },
	{ 0x05, "Confirm tone on" },
	{ 0x06, "Answer tone on" },
	{ 0x07, "Call waiting tone on" },
	{ 0x08, "Off-hoke warning tone on" },
	{ 0x09, "Preemption tone on" },
	{ 0x3F, "Tones off" },
	{ 0x40, "Alerting on - pattern 0" },
	{ 0x41, "Alerting on - pattern 1" },
	{ 0x42, "Alerting on - pattern 2" },
	{ 0x43, "Alerting on - pattern 3" },
	{ 0x44, "Alerting on - pattern 4" },
	{ 0x45, "Alerting on - pattern 5" },
	{ 0x46, "Alerting on - pattern 6" },
	{ 0x47, "Alerting on - pattern 7" },
	{ 0x4F, "Alerting off" },
	{ 0,    NULL }
};

static void
dissect_q931_signal_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	if (len != 1) {
		proto_tree_add_text(tree, offset, len,
		    "Signal: length is %d, should be 1\n", len);
		return;
	}
	proto_tree_add_text(tree, offset, 1,
	    "Signal: %s",
	    val_to_str(pd[offset], q931_signal_vals, "Unknown (0x%02X)"));
}

/*
 * Dissect an Information rate information element.
 */
static const value_string q931_throughput_class_vals[] = {
	{ 0x03, "75 bit/s" },
	{ 0x04, "150 bit/s" },
	{ 0x05, "300 bit/s" },
	{ 0x06, "600 bit/s" },
	{ 0x07, "1200 bit/s" },
	{ 0x08, "2400 bit/s" },
	{ 0x09, "4800 bit/s" },
	{ 0x0A, "9600 bit/s" },
	{ 0x0B, "19200 bit/s" },
	{ 0x0C, "48000 bit/s" },
	{ 0x0D, "64000 bit/s" },
	{ 0,    NULL }
};

static void
dissect_q931_information_rate_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	if (len != 4) {
		proto_tree_add_text(tree, offset, len,
		    "Information rate: length is %d, should be 4\n", len);
		return;
	}
	proto_tree_add_text(tree, offset + 0, 1,
	    "Incoming information rate: %s",
	    val_to_str(pd[offset + 0] & 0x1F, q931_throughput_class_vals,
	      "Unknown (0x%02X)"));
	proto_tree_add_text(tree, offset + 1, 1,
	    "Outgoing information rate: %s",
	    val_to_str(pd[offset + 1] & 0x1F, q931_throughput_class_vals,
	      "Unknown (0x%02X)"));
	proto_tree_add_text(tree, offset + 2, 1,
	    "Minimum incoming information rate: %s",
	    val_to_str(pd[offset + 2] & 0x1F, q931_throughput_class_vals,
	      "Unknown (0x%02X)"));
	proto_tree_add_text(tree, offset + 3, 1,
	    "Minimum outgoing information rate: %s",
	    val_to_str(pd[offset + 3] & 0x1F, q931_throughput_class_vals,
	      "Unknown (0x%02X)"));
}

static int
dissect_q931_guint16_value(const u_char *pd, int offset, int len,
    proto_tree *tree, char *label)
{
	guint8 octet;
	guint16 value;
	int value_len;

	value_len = 0;

	octet = pd[offset];
	if (octet & Q931_IE_VL_EXTENSION) {
		/*
		 * Only one octet long - error.
		 */
		goto bad_length;
	}
	value = (octet & 0x3) << 14;
	offset += 1;
	len -= 1;
	value_len++;

	if (len == 0) {
		/*
		 * We've reached the end of the information element - error.
		 */
		goto past_end;
	}
	octet = pd[offset];
	if (octet & Q931_IE_VL_EXTENSION) {
		/*
		 * Only two octets long - error.
		 */
		goto bad_length;
	}
	value |= (octet & 0x7F) << 7;
	offset += 1;
	len -= 1;
	value_len++;

	if (len == 0) {
		/*
		 * We've reached the end of the information element - error.
		 */
		goto past_end;
	}
	octet = pd[offset];
	if (!(octet & Q931_IE_VL_EXTENSION)) {
		/*
		 * More than three octets long - error.
		 */
		goto bad_length;
	}
	value |= (octet & 0x7F);
	offset += 1;
	len -= 1;
	value_len++;

	proto_tree_add_text(tree, offset, value_len, "%s: %u ms", label,
	    value);
	return value_len;

past_end:
	proto_tree_add_text(tree, offset, len,
	    "%s goes past end of information element", label);
	return -1;

bad_length:
	proto_tree_add_text(tree, offset, len, "%s isn't 3 octets long",
	    label);
	return -1;
}

/*
 * Dissect an End-to-end transit delay information element.
 */
static void
dissect_q931_e2e_transit_delay_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	int value_len;

	if (len == 0)
		return;
	value_len = dissect_q931_guint16_value(pd, offset, len, tree,
	    "Cumulative transit delay");
	if (value_len < 0)
		return;	/* error */
	offset += value_len;
	len -= value_len;

	if (len == 0)
		return;
	value_len = dissect_q931_guint16_value(pd, offset, len, tree,
	    "Requested end-to-end transit delay");
	if (value_len < 0)
		return;	/* error */
	offset += value_len;
	len -= value_len;

	if (len == 0)
		return;
	value_len = dissect_q931_guint16_value(pd, offset, len, tree,
	    "Maximum end-to-end transit delay");
}

/*
 * Dissect a Transit delay selection and indication information element.
 */
static void
dissect_q931_td_selection_and_int_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	if (len == 0)
		return;
	dissect_q931_guint16_value(pd, offset, len, tree,
	    "Transit delay");
}

/*
 * Dissect a Packet layer binary parameters information element.
 */
static const value_string q931_fast_selected_vals[] = {
	{ 0x00, "Fast select not requested" },
	{ 0x08, "Fast select not requested" },
	{ 0x10, "Fast select requested with no restriction of response" },
	{ 0x18, "Fast select requested with restrictions of response" },
	{ 0x00, NULL }
};

static void
dissect_q931_pl_binary_parameters_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;

	if (len == 0)
		return;
	octet = pd[offset];
	proto_tree_add_text(tree, offset, 1,
	    "Fast select: %s",
	    val_to_str(octet & 0x18, q931_fast_selected_vals,
	      NULL));
	proto_tree_add_text(tree, offset, 1,
	    "%s",
	    (octet & 0x04) ? "No request/request denied" :
	    		     "Request indicated/request accepted");
	proto_tree_add_text(tree, offset, 1,
	    "%s confirmation",
	    (octet & 0x02) ? "Link-by-link" : "End-to-end");
	proto_tree_add_text(tree, offset, 1,
	    "Modulus %u sequencing",
	    (octet & 0x01) ? 8 : 128);
}

/*
 * Dissect a Packet layer window size information element.
 */
static void
dissect_q931_pl_window_size_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	if (len == 0)
		return;
	proto_tree_add_text(tree, offset, 1,
	    "Forward value: %u", pd[offset] & 0x7F);
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	proto_tree_add_text(tree, offset, 1,
	    "Backward value: %u", pd[offset] & 0x7F);
}

/*
 * Dissect a Packet size information element.
 */
static void
dissect_q931_packet_size_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	if (len == 0)
		return;
	proto_tree_add_text(tree, offset, 1,
	    "Forward value: %u", pd[offset] & 0x7F);
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	proto_tree_add_text(tree, offset, 1,
	    "Backward value: %u", pd[offset] & 0x7F);
}

/*
 * Dissect a Closed user group information element.
 */
static const value_string q931_cug_indication_vals[] = {
	{ 0x01, "Closed user group selection" },
	{ 0x02, "Closed user group with outgoing access selection and indication" },
	{ 0,    NULL }
};

static void
dissect_q931_cug_ie(const u_char *pd, int offset, int len, proto_tree *tree)
{
	if (len == 0)
		return;
	proto_tree_add_text(tree, offset, 1,
	    "CUG indication: %s",
	    val_to_str(pd[offset] & 0x07, q931_cug_indication_vals,
	      "Unknown (0x%02X)"));
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	proto_tree_add_text(tree, offset, len, "CUG index code: %.*s", len,
	    &pd[offset]);
}

/*
 * Dissect a Reverse charging indication information element.
 */
static const value_string q931_reverse_charging_indication_vals[] = {
	{ 0x01, "Reverse charging requested" },
	{ 0,    NULL }
};

static void
dissect_q931_reverse_charge_ind_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	if (len == 0)
		return;
	proto_tree_add_text(tree, offset, 1,
	    "Reverse charging indication: %s",
	    val_to_str(pd[offset] & 0x07, q931_reverse_charging_indication_vals,
	      "Unknown (0x%02X)"));
}

/*
 * Dissect a (phone) number information element.
 */
static const value_string q931_number_type_vals[] = {
	{ 0x00, "Unknown" },
	{ 0x10, "International number" },
	{ 0x20, "National number" },
	{ 0x30, "Network specific number" },
	{ 0x40, "Subscriber number" },
	{ 0x60, "Abbreviated number" },
	{ 0,    NULL }
};

static const value_string q931_numbering_plan_vals[] = {
	{ 0x00, "Unknown" },
	{ 0x01, "E.164 ISDN/telephony numbering" },
	{ 0x03, "X.121 data numbering" },
	{ 0x04, "F.69 Telex numbering" },
	{ 0x08, "National standard numbering" },
	{ 0x09, "Private numbering" },
	{ 0,    NULL }
};

static const value_string q931_presentation_indicator_vals[] = {
	{ 0x00, "Presentation allowed" },
	{ 0x20, "Presentation restricted" },
	{ 0x40, "Number not available due to interworking" },
	{ 0,    NULL }
};

static const value_string q931_screening_indicator_vals[] = {
	{ 0x00, "User-provided, not screened" },
	{ 0x01, "User-provided, verified and passed" },
	{ 0x02, "User-provided, verified and failed" },
	{ 0x03, "Network-provided" },
	{ 0,    NULL }
};

static const value_string q931_redirection_reason_vals[] = {
	{ 0x00, "Unknown" },
	{ 0x01, "Call forwarding busy or called DTE busy" },
	{ 0x02, "Call forwarding no reply" },
	{ 0x04, "Call deflection" },
	{ 0x09, "Called DTE out of order" },
	{ 0x0A, "Call forwarding by the called DTE" },
	{ 0x0F, "Call forwarding unconditional or systematic call redirection" },
	{ 0,    NULL }
};

static void
dissect_q931_number_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;

	if (len == 0)
		return;
	octet = pd[offset];
	proto_tree_add_text(tree, offset, 1,
	    "Type of number: %s",
	    val_to_str(octet & 0x70, q931_number_type_vals,
	      "Unknown (0x%02X)"));
	proto_tree_add_text(tree, offset, 1,
	    "Numbering plan: %s",
	    val_to_str(octet & 0x0F, q931_numbering_plan_vals,
	      "Unknown (0x%02X)"));
	offset += 1;
	len -= 1;

	if (!(octet & Q931_IE_VL_EXTENSION)) {
		if (len == 0)
			return;
		octet = pd[offset];
		proto_tree_add_text(tree, offset, 1,
		    "Presentation indicator: %s",
		    val_to_str(octet & 0x60, q931_presentation_indicator_vals,
		      "Unknown (0x%X)"));
		proto_tree_add_text(tree, offset, 1,
		    "Screening indicator: %s",
		    val_to_str(octet & 0x03, q931_screening_indicator_vals,
		      "Unknown (0x%X)"));
		offset += 1;
		len -= 1;
	}

	/*
	 * XXX - only in a Redirecting number information element.
	 */
	if (!(octet & Q931_IE_VL_EXTENSION)) {
		if (len == 0)
			return;
		octet = pd[offset];
		proto_tree_add_text(tree, offset, 1,
		    "Reason for redirection: %s",
		    val_to_str(octet & 0x0F, q931_redirection_reason_vals,
		      "Unknown (0x%X)"));
		offset += 1;
		len -= 1;
	}

	if (len == 0)
		return;
	proto_tree_add_text(tree, offset, len, "Number: %.*s",
	    len, &pd[offset]);
}

/*
 * Dissect a party subaddress information element.
 */
static const value_string q931_subaddress_type_vals[] = {
	{ 0x00, "X.213/ISO 8348 Add.2 NSAP" },
	{ 0x20, "User-specified" },
	{ 0,    NULL }
};

static const value_string q931_odd_even_indicator_vals[] = {
	{ 0x00, "Even number of address signals" },
	{ 0x10, "Odd number of address signals" },
	{ 0,    NULL }
};

static void
dissect_q931_party_subaddr_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;

	if (len == 0)
		return;
	octet = pd[offset];
	proto_tree_add_text(tree, offset, 1,
	    "Type of subaddress: %s",
	    val_to_str(octet & 0x70, q931_subaddress_type_vals,
	      "Unknown (0x%02X)"));
	proto_tree_add_text(tree, offset, 1,
	    "Odd/even indicator: %s",
	    val_to_str(octet & 0x10, q931_odd_even_indicator_vals,
	      NULL));
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	proto_tree_add_text(tree, offset, len, "Subaddress: %s",
	    bytes_to_str(&pd[offset], len));
}

/*
 * Dissect a Restart indicator information element.
 */
static const value_string q931_restart_indicator_class_vals[] = {
	{ 0x00, "Indicated channels" },
	{ 0x06, "Single interface" },
	{ 0x07, "All interfaces" },
	{ 0,    NULL }
};

static void
dissect_q931_restart_indicator_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	if (len != 1) {
		proto_tree_add_text(tree, offset, len,
		    "Restart indicator: length is %d, should be 1\n", len);
		return;
	}
	proto_tree_add_text(tree, offset, 1,
	    "Restart indicator: %s",
	    val_to_str(pd[offset] & 0x07, q931_restart_indicator_class_vals,
	      "Unknown (0x%02X)"));
}

/*
 * Dissect a High-layer compatibility information element.
 */
#define	Q931_AUDIOVISUAL	0x60
static const value_string q931_high_layer_characteristics_vals[] = {
	{ 0x01,             "Telephony" },
	{ 0x04,             "F.182 Facsimile Group 2/3" },
	{ 0x21,             "F.184 Facsimile Group 4 Class I" },
	{ 0x24,             "F.230 Teletex, basic and mixed mode, and F.184 Facsimile Group 4, Classes II and III" },
	{ 0x28,             "F.220 Teletex, basic and processable mode" },
	{ 0x31,             "F.200 Teletex, basic mode" },
	{ 0x32,             "F.300 and T.102 syntax-based Videotex" },
	{ 0x33,             "F.300 and T.101 international Videotex interworking" },
	{ 0x35,             "F.60 Telex" },
	{ 0x38,             "X.400 Message Handling Systems" },
	{ 0x41,             "X.200 OSI application" },
	{ 0x42,             "FTAM application" },
	{ 0x5E,             "Reserved for maintenance" },
	{ 0x5F,             "Reserved for management" },
	{ Q931_AUDIOVISUAL, "F.720/F.821 and F.731 Profile 1a videotelephony" },
	{ 0x61,             "F.702 and F.731 Profile 1b videoconferencing" },
	{ 0x62,             "F.702 and F.731 audiographic conferencing" },
	{ 0,                NULL }
};

static const value_string q931_audiovisual_characteristics_vals[] = {
	{ 0x01, "Capability set of initial channel of H.221" },
	{ 0x02, "Capability set of subsequent channel of H.221" },
	{ 0x21, "Capability set of initial channel of an active 3.1kHz audio or speech call" },
	{ 0x00, NULL }
};

void
dissect_q931_high_layer_compat_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;
	guint8 coding_standard;
	guint8 characteristics;

	if (len == 0)
		return;
	octet = pd[offset];
	coding_standard = octet & 0x60;
	proto_tree_add_text(tree, offset, 1,
	    "Coding standard: %s",
	    val_to_str(coding_standard, q931_coding_standard_vals, NULL));
	if (coding_standard != Q931_ITU_STANDARDIZED_CODING) {
		/*
		 * We don't know how the call state is encoded,
		 * so just dump it as data and be done with it.
		 */
		proto_tree_add_text(tree, offset,
		    len, "Data: %s", bytes_to_str(&pd[offset], len));
		return;
	}

	if (len == 0)
		return;
	octet = pd[offset];
	characteristics = octet & 0x7F;
	proto_tree_add_text(tree, offset, 1,
	    "High layer characteristics identification: %s",
	    val_to_str(characteristics, q931_high_layer_characteristics_vals,
	      NULL));
	offset += 1;
	len -= 1;

	if (!(octet & Q931_IE_VL_EXTENSION)) {
		if (len == 0)
			return;
		octet = pd[offset];
		if (characteristics == Q931_AUDIOVISUAL) {
			proto_tree_add_text(tree, offset, 1,
			    "Extended audiovisual characteristics identification: %s",
			    val_to_str(octet & 0x7F, q931_audiovisual_characteristics_vals,
			      NULL));
		} else {
			proto_tree_add_text(tree, offset, 1,
			    "Extended high layer characteristics identification: %s",
			    val_to_str(octet & 0x7F, q931_high_layer_characteristics_vals,
			      NULL));
		}
	}
}


/*
 * Dissect a User-user information element.
 */
#define	Q931_PROTOCOL_DISCRIMINATOR_IA5	0x04

static const value_string q931_protocol_discriminator_vals[] = {
	{ 0x00,					"User-specific protocol" },
	{ 0x01,					"OSI high layer protocols" },
	{ 0x02,					"X.244" },
	{ Q931_PROTOCOL_DISCRIMINATOR_IA5,	"IA5 characters" },
	{ 0x05,					"X.208 and X.209 coded user information" },
	{ 0x07,					"V.120 rate adaption" },
	{ 0x08,					"Q.931/I.451 user-network call control messages" },
	{ 0,					NULL }
};

static void
dissect_q931_user_user_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;

	if (len == 0)
		return;
	octet = pd[offset];
	proto_tree_add_text(tree, offset, 1,
	    "Protocol discriminator: %s",
	    val_to_str(octet, q931_protocol_discriminator_vals,
	    "Unknown (0x%02x)"));
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	switch (octet) {

	case Q931_PROTOCOL_DISCRIMINATOR_IA5:
		proto_tree_add_text(tree, offset, len, "User information: %.*s",
		    len, &pd[offset]);
		break;

	default:
		proto_tree_add_text(tree, offset, len, "User information: %s",
		    bytes_to_str(&pd[offset], len));
		break;
	}
}

/*
 * Dissect information elements consisting of ASCII^H^H^H^H^HIA5 text.
 */
static void
dissect_q931_ia5_ie(const u_char *pd, int offset, int len, proto_tree *tree,
    char *label)
{
	if (len != 0) {
		proto_tree_add_text(tree, offset, len, "%s: %.*s", label, len,
		    &pd[offset]);
	}
}

static const value_string q931_codeset_vals[] = {
	{ 0x00, "Q.931 information elements" },
	{ 0x04, "Information elements for ISO/IEC use" },
	{ 0x05, "Information elements for national use" },
	{ 0x06, "Information elements specific to the local network" },
	{ 0x07, "User-specific information elements" },
	{ 0x00, NULL },
};

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
	int		codeset;
	gboolean	non_locking_shift;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "Q.931");

	if (tree) {
		ti = proto_tree_add_item(tree, proto_q931, offset,
		    END_OF_FRAME, NULL);
		q931_tree = proto_item_add_subtree(ti, ett_q931);

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
	codeset = 0;	/* start out in codeset 0 */
	non_locking_shift = TRUE;
	while (IS_DATA_IN_FRAME(offset)) {
		info_element = pd[offset];

		/*
		 * Check for the single-octet IEs.
		 */
		switch (info_element & Q931_IE_SO_IDENTIFIER_MASK) {

		case Q931_IE_SHIFT:
			non_locking_shift =
			    !(info_element & Q931_IE_SHIFT_LOCKING);
			codeset = info_element & Q931_IE_SHIFT_CODESET;
			if (q931_tree != NULL) {
				proto_tree_add_text(q931_tree, offset, 1,
				    "%s shift to codeset %u: %s",
				    (non_locking_shift ? "Non-locking" : "Locking"),
				    codeset,
				    val_to_str(codeset, q931_codeset_vals,
				      "Unknown (0x%02X)"));
			}
			offset += 1;
			continue;

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
			if (non_locking_shift)
				codeset = 0;
			continue;

		case Q931_IE_CONGESTION_LEVEL:
			if (q931_tree != NULL) {
				proto_tree_add_text(q931_tree, offset, 1,
				    "Congestion level: %s",
				    val_to_str(info_element & Q931_IE_SO_IE_MASK,
				      q931_congestion_level_vals,
				      "Unknown (0x%X)"));
			}		
			offset += 1;
			if (non_locking_shift)
				codeset = 0;
			continue;

		case Q931_IE_REPEAT_INDICATOR:
			if (q931_tree != NULL) {
				proto_tree_add_text(q931_tree, offset, 1,
				    "Repeat indicator: %s",
				    val_to_str(info_element & Q931_IE_SO_IE_MASK,
				      q931_repeat_indication_vals,
				      "Unknown (0x%X)"));
			}		
			offset += 1;
			if (non_locking_shift)
				codeset = 0;
			continue;

		default:
			break;
		}

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
			    1+1+info_element_len, "%s",
			    val_to_str(info_element, q931_info_element_vals,
			      "Unknown information element (0x%02X)"));
			ie_tree = proto_item_add_subtree(ti, ett_q931_ie);
			proto_tree_add_text(ie_tree, offset, 1,
			    "Information element: %s",
			    val_to_str(info_element, q931_info_element_vals,
			      "Unknown (0x%02X)"));
			proto_tree_add_text(ie_tree, offset + 1, 1,
			    "Length: %u", info_element_len);

			switch (info_element) {

			case Q931_IE_SEGMENTED_MESSAGE:
				dissect_q931_segmented_message_ie(pd,
				    offset + 2, info_element_len, ie_tree);
				break;

			case Q931_IE_BEARER_CAPABILITY:
			case Q931_IE_LOW_LAYER_COMPAT:
				dissect_q931_bearer_capability_ie(pd,
				    offset + 2, info_element_len, ie_tree);
				break;

			case Q931_IE_CAUSE:
				dissect_q931_cause_ie(pd,
				    offset + 2, info_element_len, ie_tree);
				break;

			case Q931_IE_CALL_STATE:
				dissect_q931_call_state_ie(pd,
				    offset + 2, info_element_len, ie_tree);
				break;

			case Q931_IE_CHANNEL_IDENTIFICATION:
				dissect_q931_channel_identification_ie(pd,
				    offset + 2, info_element_len, ie_tree);
				break;

			case Q931_IE_PROGRESS_INDICATOR:
				dissect_q931_progress_indicator_ie(pd,
				    offset + 2, info_element_len, ie_tree);
				break;

			case Q931_IE_NETWORK_SPECIFIC_FACIL:
			case Q931_IE_TRANSIT_NETWORK_SEL:
				dissect_q931_ns_facilities_ie(pd,
				    offset + 2, info_element_len, ie_tree);
				break;

			case Q931_IE_NOTIFICATION_INDICATOR:
				dissect_q931_notification_indicator_ie(pd,
				    offset + 2, info_element_len, ie_tree);
				break;

			case Q931_IE_DISPLAY:
				dissect_q931_ia5_ie(pd, offset + 2,
				    info_element_len, ie_tree,
				    "Display information");
				break;

			case Q931_IE_DATE_TIME:
				dissect_q931_date_time_ie(pd,
				    offset + 2, info_element_len, ie_tree);
				break;

			case Q931_IE_KEYPAD_FACILITY:
				dissect_q931_ia5_ie(pd, offset + 2,
				    info_element_len, ie_tree,
				    "Keypad facility");
				break;

			case Q931_IE_SIGNAL:
				dissect_q931_signal_ie(pd,
				    offset + 2, info_element_len, ie_tree);
				break;

			case Q931_IE_INFORMATION_RATE:
				dissect_q931_information_rate_ie(pd,
				    offset + 2, info_element_len, ie_tree);
				break;

			case Q931_IE_E2E_TRANSIT_DELAY:
				dissect_q931_e2e_transit_delay_ie(pd,
				    offset + 2, info_element_len, ie_tree);
				break;

			case Q931_IE_TD_SELECTION_AND_INT:
				dissect_q931_td_selection_and_int_ie(pd,
				    offset + 2, info_element_len, ie_tree);
				break;

			case Q931_IE_PL_BINARY_PARAMETERS:
				dissect_q931_pl_binary_parameters_ie(pd,
				    offset + 2, info_element_len, ie_tree);
				break;

			case Q931_IE_PL_WINDOW_SIZE:
				dissect_q931_pl_window_size_ie(pd,
				    offset + 2, info_element_len, ie_tree);
				break;

			case Q931_IE_PACKET_SIZE:
				dissect_q931_packet_size_ie(pd,
				    offset + 2, info_element_len, ie_tree);
				break;

			case Q931_IE_CUG:
				dissect_q931_cug_ie(pd,
				    offset + 2, info_element_len, ie_tree);
				break;

			case Q931_IE_REVERSE_CHARGE_IND:
				dissect_q931_reverse_charge_ind_ie(pd,
				    offset + 2, info_element_len, ie_tree);
				break;

			case Q931_IE_CALLING_PARTY_NUMBER:
			case Q931_IE_CALLED_PARTY_NUMBER:
			case Q931_IE_REDIRECTING_NUMBER:
				dissect_q931_number_ie(pd,
				    offset + 2, info_element_len, ie_tree);
				break;

			case Q931_IE_CALLING_PARTY_SUBADDR:
			case Q931_IE_CALLED_PARTY_SUBADDR:
				dissect_q931_party_subaddr_ie(pd,
				    offset + 2, info_element_len, ie_tree);
				break;

			case Q931_IE_RESTART_INDICATOR:
				dissect_q931_restart_indicator_ie(pd,
				    offset + 2, info_element_len, ie_tree);
				break;

			case Q931_IE_HIGH_LAYER_COMPAT:
				dissect_q931_high_layer_compat_ie(pd,
				    offset + 2, info_element_len, ie_tree);
				break;

			case Q931_IE_USER_USER:
				dissect_q931_user_user_ie(pd,
				    offset + 2, info_element_len, ie_tree);
				break;

			default:
				proto_tree_add_text(ie_tree, offset + 2,
				    info_element_len, "Data: %s",
				    bytes_to_str(&pd[offset + 2],
				      info_element_len));
				break;
			}
		}
		offset += 1 + 1 + info_element_len;
		if (non_locking_shift)
			codeset = 0;
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
    static gint *ett[] = {
        &ett_q931,
        &ett_q931_ie,
    };

    proto_q931 = proto_register_protocol ("Q.931", "q931");
    proto_register_field_array (proto_q931, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}
