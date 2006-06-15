/* packet-q931.c
 * Routines for Q.931 frame disassembly
 * Guy Harris <guy@alum.mit.edu>
 *
 * $Id$
 *
 * Modified by Andreas Sikkema for possible use with H.323
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
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
#include <glib.h>
#include <string.h>
#include <epan/packet.h>
#include <epan/tap.h>
#include <epan/strutil.h>
#include <epan/nlpid.h>
#include "packet-q931.h"
#include "packet-e164.h"
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/emem.h>

#include <epan/lapd_sapi.h>
#include "packet-tpkt.h"

#ifndef min
#define min(a,b) (((a)<(b))?(a):(b))
#endif

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
static void reset_q931_packet_info(q931_packet_info *pi);
static gboolean have_valid_q931_pi=FALSE;
static q931_packet_info *q931_pi=NULL;
static int q931_tap = -1;

static int proto_q931 					= -1;
static int hf_q931_discriminator			= -1;
static int hf_q931_coding_standard			= -1;
static int hf_q931_information_transfer_capability	= -1;
static int hf_q931_transfer_mode			= -1;
static int hf_q931_information_transfer_rate		= -1;
static int hf_q931_uil1					= -1;
static int hf_q931_call_ref_len 			= -1;
static int hf_q931_call_ref_flag 			= -1;
static int hf_q931_call_ref 				= -1;
static int hf_q931_message_type 			= -1;
static int hf_q931_segment_type 			= -1;
static int hf_q931_cause_location			= -1;
static int hf_q931_cause_value 				= -1;
static int hf_q931_number_type				= -1;
static int hf_q931_numbering_plan			= -1;
static int hf_q931_extension_ind			= -1;
static int hf_q931_calling_party_number 		= -1;
static int hf_q931_called_party_number 			= -1;
static int hf_q931_connected_number 			= -1;
static int hf_q931_redirecting_number 			= -1;
static int hf_q931_screening_ind				= -1;
static int hf_q931_presentation_ind				= -1;

/* fields for Channel Indentification IE */
static int hf_q931_channel_interface_explicit		= -1;
static int hf_q931_channel_interface_type		= -1;
static int hf_q931_channel_exclusive			= -1;
static int hf_q931_channel_dchan			= -1;
static int hf_q931_channel_selection_bri		= -1;
static int hf_q931_channel_selection_pri		= -1;
static int hf_q931_channel_map				= -1;
static int hf_q931_channel_element_type			= -1;
static int hf_q931_channel_number			= -1;


static int hf_q931_segments = -1;
static int hf_q931_segment = -1;
static int hf_q931_segment_overlap = -1;
static int hf_q931_segment_overlap_conflict = -1;
static int hf_q931_segment_multiple_tails = -1;
static int hf_q931_segment_too_long_segment = -1;
static int hf_q931_segment_error = -1;
static int hf_q931_reassembled_in = -1; 

static gint ett_q931 					= -1;
static gint ett_q931_ie 				= -1;

static gint ett_q931_segments = -1;
static gint ett_q931_segment = -1;

static const fragment_items q931_frag_items = {
	&ett_q931_segment,
	&ett_q931_segments,

	&hf_q931_segments,
	&hf_q931_segment,
	&hf_q931_segment_overlap,
	&hf_q931_segment_overlap_conflict,
	&hf_q931_segment_multiple_tails,
	&hf_q931_segment_too_long_segment,
	&hf_q931_segment_error,
	&hf_q931_reassembled_in,
	"segments"
};

/* Tables for reassembly of fragments. */
static GHashTable *q931_fragment_table = NULL;
static GHashTable *q931_reassembled_table = NULL;

/* Preferences */
static gboolean q931_reassembly = TRUE;

static dissector_table_t codeset_dissector_table;
static dissector_table_t ie_dissector_table;

/* desegmentation of Q.931 over TPKT over TCP */
static gboolean q931_desegment = TRUE;

static dissector_handle_t h225_handle;
static dissector_handle_t q931_tpkt_pdu_handle;

static void
dissect_q931_IEs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *root_tree,
    proto_tree *q931_tree, gboolean is_tpkt, int offset, int initial_codeset);

const value_string q931_message_type_vals[] = {
	{ Q931_ESCAPE,			"ESCAPE" },
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
	{ Q931_VERSION,			"VERSION" },
	{ Q931_GROUIP_SERVICE,		"GROUP SERVICE" },
	{ Q931_GROUIP_SERVICE_ACK,	"GROUP SERVICE ACK" },
	{ Q931_RESYNC_REQ,		"RESYNC REQ" },
	{ Q931_RESYNC_RESP,		"RESYNC RESP" },
	{ 0,				NULL }
};

static const true_false_string tfs_call_ref_flag = {
	"Message sent to originating side",
	"Message sent from originating side"
};

static const true_false_string tfs_interface_type = {
    "Primary rate interface",
    "Basic rate interface"
};

static const true_false_string tfs_channel_exclusive = {
	"Exclusive; only the indicated channel is acceptable",
	"Indicated channel is preferred"
};

static const true_false_string tfs_channel_map = {
	"Channel indicated by slot map",
	"Channel indicated by number"
};

/*
 * Information elements.
 */

/* Shifted codeset values */
#define CS0 0x000
#define CS1 0x100
#define CS2 0x200
#define CS3 0x300
#define CS4 0x400
#define CS5 0x500
#define CS6 0x600
#define CS7 0x700

#define	Q931_IE_SO_MASK	0x80	/* single-octet/variable-length mask */
/*
 * Single-octet IEs.
 */
#define	Q931_IE_SO_IDENTIFIER_MASK	0xf0	/* IE identifier mask */
#define	Q931_IE_SO_IDENTIFIER_SHIFT	4	/* IE identifier shift */
#define	Q931_IE_SO_IE_MASK		0x0F	/* IE mask */

#define	Q931_IE_SHIFT			0x90
#define	Q931_IE_SHIFT_NON_LOCKING	0x08	/* non-locking shift */
#define	Q931_IE_SHIFT_CODESET		0x07	/* codeset */

#define	Q931_IE_MORE_DATA_OR_SEND_COMP	0xA0	/* More Data or Sending Complete */
#define	Q931_IE_MORE_DATA		0xA0
#define	Q931_IE_SENDING_COMPLETE	0xA1

#define	Q931_IE_CONGESTION_LEVEL	0xB0
#define	Q931_IE_REPEAT_INDICATOR	0xD0

/*
 * Variable-length IEs.
 */
#define	Q931_IE_VL_EXTENSION		0x80	/* Extension flag */
/*	extension bit. The bit value "0" indicates that the octet continues through the		*/
/*	next octet. The bit value "1" indicates that this octet is the last octet		*/

static const true_false_string q931_extension_ind_value = {
  "last octet",
  "information continues through the next octet",

};


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
#define	Q931_IE_CONNECTED_NUMBER_DEFAULT        0x4C	/* Connected Number */
#define	Q931_IE_INTERFACE_SERVICE	0x66	/* q931+ Interface Service */
#define	Q931_IE_CHANNEL_STATUS		0x67	/* q931+ Channel Status */
#define	Q931_IE_VERSION_INFO		0x68	/* q931+ Version Info */
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

/* Codeset 0 */
static const value_string q931_info_element_vals0[] = {
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
	{ Q931_IE_CONNECTED_NUMBER_DEFAULT,     "Connected number" },
	{ Q931_IE_INTERFACE_SERVICE,		"Interface Service" },
	{ Q931_IE_CHANNEL_STATUS,		"Channel Status" },
	{ Q931_IE_VERSION_INFO,			"Version Info" },
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
	{ 0,					NULL }
};
/* Codeset 1 */
static const value_string q931_info_element_vals1[] = {
	{ 0,					NULL }
};
/* Codeset 2 */
static const value_string q931_info_element_vals2[] = {
	{ 0,					NULL }
};
/* Codeset 3 */
static const value_string q931_info_element_vals3[] = {
	{ 0,					NULL }
};
/* Codeset 4 */
static const value_string q931_info_element_vals4[] = {
	{ 0,					NULL }
};
/* Codeset 5 */
static const value_string q931_info_element_vals5[] = {
	{ Q931_IE_CHARGING_ADVICE,		"Charging advice" },
	{ Q931_IE_OPERATOR_SYSTEM_ACCESS,	"Operator system access" },
	{ 0,					NULL }
};
/* Codeset 6 */
static const value_string q931_info_element_vals6[] = {
	{ Q931_IE_REDIRECTING_NUMBER,		"Redirecting number" },
	{ Q931_IE_REDIRECTING_SUBADDR,		"Redirecting subaddress" },
	{ Q931_IE_CALL_APPEARANCE,		"Call appearance" },
	{ 0,					NULL }
};
/* Codeset 7 */
static const value_string q931_info_element_vals7[] = {
	{ 0,					NULL }
};

/* Codeset array */
#define NUM_INFO_ELEMENT_VALS	(Q931_IE_SHIFT_CODESET+1)
static const value_string *q931_info_element_vals[NUM_INFO_ELEMENT_VALS] = {
  q931_info_element_vals0,
  q931_info_element_vals1,
  q931_info_element_vals2,
  q931_info_element_vals3,
  q931_info_element_vals4,
  q931_info_element_vals5,
  q931_info_element_vals6,
  q931_info_element_vals7,
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
dissect_q931_segmented_message_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	if (len != 2) {
		proto_tree_add_text(tree, tvb, offset, len,
		    "Segmented message: length is %d, should be 2", len);
		return;
	}
	if (tvb_get_guint8(tvb, offset) & 0x80) {
		proto_tree_add_text(tree, tvb, offset, 1,
		    "First segment: %u segments remaining",
		    tvb_get_guint8(tvb, offset) & 0x7F);
	} else {
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Not first segment: %u segments remaining",
		    tvb_get_guint8(tvb, offset) & 0x7F);
	}
	proto_tree_add_item(tree, hf_q931_segment_type, tvb, offset + 1, 1, FALSE);
}

/*
 * Dissect a Bearer capability or Low-layer compatibility information element.
 */
static const value_string q931_coding_standard_vals[] = {
	{ 0x0, "ITU-T standardized coding" },
	{ 0x1, "ISO/IEC standard" },
	{ 0x2, "National standard" },
	{ 0x3, "Standard defined for this particular network" },
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
	{ 0x02, "Packet mode" },
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
	{ 0,    NULL }
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

static void
dissect_q931_protocol_discriminator(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	unsigned int discriminator = tvb_get_guint8(tvb, offset);

	if (discriminator == NLPID_Q_931) {
		proto_tree_add_uint_format(tree, hf_q931_discriminator,
			 tvb, offset, 1, discriminator,
			 "Protocol discriminator: Q.931");
	} else if (discriminator == NLPID_Q_2931) {
		proto_tree_add_uint_format(tree, hf_q931_discriminator,
			 tvb, offset, 1, discriminator,
			 "Protocol discriminator: Q.2931");
	} else if ((discriminator >= 16 && discriminator < 63)
	    || ((discriminator >= 80) && (discriminator < 254))) {
		proto_tree_add_uint_format(tree, hf_q931_discriminator,
		    tvb, offset, 1, discriminator,
		    "Protocol discriminator: Network layer or layer 3 protocol (0x%02X)",
		    discriminator);
	} else if (discriminator >= 64 && discriminator <= 79) {
		proto_tree_add_uint_format(tree, hf_q931_discriminator,
		    tvb, offset, 1, discriminator,
		    "Protocol discriminator: National use (0x%02X)",
		    discriminator);
	} else {
		proto_tree_add_uint_format(tree, hf_q931_discriminator,
		    tvb, offset, 1, discriminator,
		    "Protocol discriminator: Reserved (0x%02X)",
		    discriminator);
	}
}

void
dissect_q931_bearer_capability_ie(tvbuff_t *tvb, int offset, int len,
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
	octet = tvb_get_guint8(tvb, offset);
	coding_standard = octet & 0x60;
	if (coding_standard != Q931_ITU_STANDARDIZED_CODING) {
		/*
		 * We don't know how the bearer capability is encoded,
		 * so just dump it as data and be done with it.
		 */
		proto_tree_add_text(tree, tvb, offset,
		    len, "Data: %s",
		    tvb_bytes_to_str(tvb, offset, len));
		proto_tree_add_boolean(tree, hf_q931_extension_ind, tvb, offset, 1, octet);
		proto_tree_add_uint(tree, hf_q931_coding_standard, tvb, offset, 1, octet);
		return;
	}
	proto_tree_add_boolean(tree, hf_q931_extension_ind, tvb, offset, 1, octet);
	proto_tree_add_uint(tree, hf_q931_coding_standard, tvb, offset, 1, octet);
	proto_tree_add_uint(tree, hf_q931_information_transfer_capability, tvb, offset, 1, octet);
	offset += 1;
	len -= 1;

	/*
	 * XXX - only in Low-layer compatibility information element.
	 */
	if (!(octet & Q931_IE_VL_EXTENSION)) {
		if (len == 0)
			return;
		octet = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Out-band negotiation %spossible",
		    (octet & 0x40) ? "" : "not ");
		offset += 1;
		len -= 1;
	}

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	proto_tree_add_boolean(tree, hf_q931_extension_ind, tvb, offset, 1, octet);
	proto_tree_add_uint(tree, hf_q931_transfer_mode, tvb, offset, 1, octet);
	proto_tree_add_uint(tree, hf_q931_information_transfer_rate, tvb, offset, 1, octet);
	it_rate = octet & 0x1F;
	offset += 1;
	len -= 1;

	if (it_rate == Q931_IT_RATE_MULTIRATE) {
		if (len == 0)
			return;
		proto_tree_add_text(tree, tvb, offset, 1, "Rate multiplier: %u", tvb_get_guint8(tvb, offset));
		offset += 1;
		len -= 1;
	}

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	if ((octet & 0x60) == 0x20) {
		/*
		 * Layer 1 information.
		 */
		proto_tree_add_boolean(tree, hf_q931_extension_ind, tvb, offset, 1, octet);
		proto_tree_add_uint(tree, hf_q931_uil1, tvb, offset, 1, octet);
		offset += 1;
		len -= 1;

		if (octet & Q931_IE_VL_EXTENSION)
			goto l1_done;
		if (len == 0)
			return;
		octet = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Layer 1 is %s",
		    (octet & 0x40) ? "Asynchronous" : "Synchronous");
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Layer 1 in-band negotiation is %spossible",
		    (octet & 0x20) ? "" : "not ");
		proto_tree_add_text(tree, tvb, offset, 1,
		    "User rate: %s",
		    val_to_str(octet & 0x1F, q931_l1_user_rate_vals,
		      "Unknown (0x%02X)"));
		offset += 1;
		len -= 1;

		if (octet & Q931_IE_VL_EXTENSION)
			goto l1_done;
		if (len == 0)
			return;
		octet = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Intermediate rate: %s",
		      val_to_str(octet & 0x60, q931_l1_intermediate_rate_vals,
		       "Unknown (0x%X)"));
		proto_tree_add_text(tree, tvb, offset, 1,
		    "%s to send data with network independent clock",
		    (octet & 0x10) ? "Required" : "Not required");
		proto_tree_add_text(tree, tvb, offset, 1,
		    "%s accept data with network independent clock",
		    (octet & 0x08) ? "Can" : "Cannot");
		proto_tree_add_text(tree, tvb, offset, 1,
		    "%s to send data with flow control mechanism",
		    (octet & 0x04) ? "Required" : "Not required");
		proto_tree_add_text(tree, tvb, offset, 1,
		    "%s accept data with flow control mechanism",
		    (octet & 0x02) ? "Can" : "Cannot");
		offset += 1;
		len -= 1;

		if (octet & Q931_IE_VL_EXTENSION)
			goto l1_done;
		if (len == 0)
			return;
		octet = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Rate adaption header %sincluded",
		    (octet & 0x40) ? "" : "not ");
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Multiple frame establishment %ssupported",
		    (octet & 0x20) ? "" : "not ");
		proto_tree_add_text(tree, tvb, offset, 1,
		    "%s mode of operation",
		    (octet & 0x10) ? "Protocol sensitive" : "Bit transparent");
		proto_tree_add_text(tree, tvb, offset, 1,
		    (octet & 0x08) ?
		      "Full protocol negotiation" : "LLI = 256 only");
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Message originator is %s",
		    (octet & 0x04) ? "Assignor only" : "Default assignee");
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Negotiation is done %s",
		    (octet & 0x02) ? "in-band" : "out-of-band");
		offset += 1;
		len -= 1;

		if (octet & Q931_IE_VL_EXTENSION)
			goto l1_done;
		if (len == 0)
			return;
		octet = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Stop bits: %s",
		      val_to_str(octet & 0x60, q931_l1_stop_bits_vals,
		       "Unknown (0x%X)"));
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Data bits: %s",
		      val_to_str(octet & 0x18, q931_l1_data_bits_vals,
		       "Unknown (0x%X)"));
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Parity: %s",
		      val_to_str(octet & 0x07, q931_l1_parity_vals,
		       "Unknown (0x%X)"));

		if (octet & Q931_IE_VL_EXTENSION)
			goto l1_done;
		if (len == 0)
			return;
		octet = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(tree, tvb, offset, 1,
		    "%s duplex",
		    (octet & 0x40) ? "Full" : "Half");
		modem_type = octet & 0x3F;
		if (modem_type <= 0x5 ||
		    (modem_type >= 0x20 && modem_type <= 0x2F)) {
			proto_tree_add_text(tree, tvb, offset, 1,
			    "Modem type: National use 0x%02X", modem_type);
		} else if (modem_type >= 0x30) {
			proto_tree_add_text(tree, tvb, offset, 1,
			    "Modem type: User specified 0x%02X", modem_type);
		} else {
			proto_tree_add_text(tree, tvb, offset, 1,
			    "Modem type: %s",
			      val_to_str(modem_type, q931_l1_modem_type_vals,
			      "Unknown (0x%02X)"));
		}
		offset += 1;
		len -= 1;
	}
l1_done:
	;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	if ((octet & 0x60) == 0x40) {
		/*
		 * Layer 2 information.
		 */
		uil2_protocol = octet & 0x1F;
		proto_tree_add_text(tree, tvb, offset, 1,
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
		octet = tvb_get_guint8(tvb, offset);
		if (uil2_protocol == Q931_UIL2_USER_SPEC) {
			proto_tree_add_text(tree, tvb, offset, 1,
			    "User-specified layer 2 protocol information: 0x%02X",
			    octet & 0x7F);
		} else {
			proto_tree_add_text(tree, tvb, offset, 1,
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
		octet = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Window size: %u k", octet & 0x7F);
		offset += 1;
		len -= 1;
	}
l2_done:
	;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	if ((octet & 0x60) == 0x60) {
		/*
		 * Layer 3 information.
		 */
		uil3_protocol = octet & 0x1F;
		proto_tree_add_text(tree, tvb, offset, 1,
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
		octet = tvb_get_guint8(tvb, offset);
		switch (uil3_protocol) {

		case Q931_UIL3_X25_PL:
		case Q931_UIL3_ISO_8208:
		case Q931_UIL3_X223:
			proto_tree_add_text(tree, tvb, offset, 1,
			    "Mode: %s",
			    val_to_str(octet & 0x60, q931_mode_vals,
			      "Unknown (0x%02X)"));
			offset += 1;
			len -= 1;

			if (octet & Q931_IE_VL_EXTENSION)
				goto l3_done;
			if (len == 0)
				return;
			octet = tvb_get_guint8(tvb, offset);
			proto_tree_add_text(tree, tvb, offset, 1,
			    "Default packet size: %u", octet & 0x0F);
			offset += 1;
			len -= 1;

			if (octet & Q931_IE_VL_EXTENSION)
				goto l3_done;
			if (len == 0)
				return;
			octet = tvb_get_guint8(tvb, offset);
			proto_tree_add_text(tree, tvb, offset, 1,
			    "Packet window size: %u", octet & 0x7F);
			offset += 1;
			len -= 1;
			break;

		case Q931_UIL3_USER_SPEC:
			proto_tree_add_text(tree, tvb, offset, 1,
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
			octet = tvb_get_guint8(tvb, offset + 1);
			add_l3_info |= (octet & 0x0F);
			proto_tree_add_text(tree, tvb, offset, 2,
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


const value_string q931_cause_location_vals[] = {
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
#define	Q931_CAUSE_UNALLOC_NUMBER	0x01
#define	Q931_CAUSE_NO_ROUTE_TO_DEST	0x03
#define	Q931_CAUSE_CALL_REJECTED	0x15
#define	Q931_CAUSE_NUMBER_CHANGED	0x16
#define	Q931_CAUSE_ACCESS_INFO_DISC	0x2B
#define	Q931_CAUSE_QOS_UNAVAILABLE	0x31
#define	Q931_CAUSE_CHAN_NONEXISTENT	0x52
#define	Q931_CAUSE_INCOMPATIBLE_DEST	0x58
#define	Q931_CAUSE_MAND_IE_MISSING	0x60
#define	Q931_CAUSE_MT_NONEX_OR_UNIMPL	0x61
#define	Q931_CAUSE_IE_NONEX_OR_UNIMPL	0x63
#define	Q931_CAUSE_INVALID_IE_CONTENTS	0x64
#define	Q931_CAUSE_MSG_INCOMPAT_W_CS	0x65
#define	Q931_CAUSE_REC_TIMER_EXP	0x66

const value_string q931_cause_code_vals[] = {
	{ 0x00,				"Valid cause code not yet received" },
	{ Q931_CAUSE_UNALLOC_NUMBER,	"Unallocated (unassigned) number" },
	{ 0x02,				"No route to specified transit network" },
	{ Q931_CAUSE_NO_ROUTE_TO_DEST,	"No route to destination" },
	{ 0x04,				"Send special information tone" },
	{ 0x05,				"Misdialled trunk prefix" },
	{ 0x06,				"Channel unacceptable" },
	{ 0x07,				"Call awarded and being delivered in an established channel" },
	{ 0x08,				"Prefix 0 dialed but not allowed" },
					/* Q.850 - "Preemption" */
	{ 0x09,				"Prefix 1 dialed but not allowed" },
					/* Q.850 - "Preemption - circuit reserved for reuse" */
	{ 0x0A,				"Prefix 1 dialed but not required" },
	{ 0x0B,				"More digits received than allowed, call is proceeding" },
	{ 0x0E,				"QoR: ported number" },
	{ 0x10,				"Normal call clearing" },
	{ 0x11,				"User busy" },
	{ 0x12,				"No user responding" },
	{ 0x13,				"No answer from user (user alerted)" },
	{ 0x14,				"Subscriber absent" },
	{ Q931_CAUSE_CALL_REJECTED,	"Call rejected" },
	{ Q931_CAUSE_NUMBER_CHANGED,	"Number changed" },
	{ 0x17,				"Reverse charging rejected" },
					/* Q.850 - "Redirection to new destination" */
	{ 0x18,				"Call suspended" },
					/* Q.850 Amendment 1 - "Call rejected due to feature at the destination" */
	{ 0x19,				"Call resumed" },
					/* Q.850 - "Exchange routing error */
	{ 0x1A,				"Non-selected user clearing" },
	{ 0x1B,				"Destination out of order" },
	{ 0x1C,				"Invalid number format (incomplete number)" },
	{ 0x1D,				"Facility rejected" },
	{ 0x1E,				"Response to STATUS ENQUIRY" },
	{ 0x1F,				"Normal unspecified" },
	{ 0x21,				"Circuit out of order" },
	{ 0x22,				"No circuit/channel available" },
	{ 0x23,				"Destination unattainable" },
	{ 0x25,				"Degraded service" },
	{ 0x26,				"Network out of order" },
	{ 0x27,				"Transit delay range cannot be achieved" },
					/* Q.850 - "Permanent frame mode connection out of service" */
	{ 0x28,				"Throughput range cannot be achieved" },
					/* Q.850 - "Permanent frame mode connection operational" */
	{ 0x29,				"Temporary failure" },
	{ 0x2A,				"Switching equipment congestion" },
	{ Q931_CAUSE_ACCESS_INFO_DISC,	"Access information discarded" },
	{ 0x2C,				"Requested circuit/channel not available" },
	{ 0x2D,				"Pre-empted" },
	{ 0x2E,				"Precedence call blocked" },
	{ 0x2F,				"Resources unavailable, unspecified" },
	{ Q931_CAUSE_QOS_UNAVAILABLE,	"Quality of service unavailable" },
	{ 0x32,				"Requested facility not subscribed" },
	{ 0x33,				"Reverse charging not allowed" },
	{ 0x34,				"Outgoing calls barred" },
	{ 0x35,				"Outgoing calls barred within CUG" },
	{ 0x36,				"Incoming calls barred" },
	{ 0x37,				"Incoming calls barred within CUG" },
	{ 0x38,				"Call waiting not subscribed" },
	{ 0x39,				"Bearer capability not authorized" },
	{ 0x3A,				"Bearer capability not presently available" },
	{ 0x3E,				"Inconsistency in designated outgoing access information and subscriber class" },
	{ 0x3F,				"Service or option not available, unspecified" },
	{ 0x41,				"Bearer capability not implemented" },
	{ 0x42,				"Channel type not implemented" },
	{ 0x43,				"Transit network selection not implemented" },
	{ 0x44,				"Message not implemented" },
	{ 0x45,				"Requested facility not implemented" },
	{ 0x46,				"Only restricted digital information bearer capability is available" },
	{ 0x4F,				"Service or option not implemented, unspecified" },
	{ 0x51,				"Invalid call reference value" },
	{ Q931_CAUSE_CHAN_NONEXISTENT,	"Identified channel does not exist" },
	{ 0x53,				"Call identity does not exist for suspended call" },
	{ 0x54,				"Call identity in use" },
	{ 0x55,				"No call suspended" },
	{ 0x56,				"Call having the requested call identity has been cleared" },
	{ 0x57,				"Called user not member of CUG" },
	{ Q931_CAUSE_INCOMPATIBLE_DEST,	"Incompatible destination" },
	{ 0x59,				"Non-existent abbreviated address entry" },
	{ 0x5A,				"Destination address missing, and direct call not subscribed" },
					/* Q.850 - "Non-existent CUG" */
	{ 0x5B,				"Invalid transit network selection (national use)" },
	{ 0x5C,				"Invalid facility parameter" },
	{ 0x5D,				"Mandatory information element is missing" },
	{ 0x5F,				"Invalid message, unspecified" },
	{ Q931_CAUSE_MAND_IE_MISSING,	"Mandatory information element is missing" },
	{ Q931_CAUSE_MT_NONEX_OR_UNIMPL,"Message type non-existent or not implemented" },
	{ 0x62,				"Message not compatible with call state or message type non-existent or not implemented" },
	{ Q931_CAUSE_IE_NONEX_OR_UNIMPL,"Information element nonexistant or not implemented" },
	{ Q931_CAUSE_INVALID_IE_CONTENTS,"Invalid information element contents" },
	{ Q931_CAUSE_MSG_INCOMPAT_W_CS,	"Message not compatible with call state" },
	{ Q931_CAUSE_REC_TIMER_EXP,	"Recovery on timer expiry" },
	{ 0x67,				"Parameter non-existent or not implemented - passed on" },
	{ 0x6E,				"Message with unrecognized parameter discarded" },
	{ 0x6F,				"Protocol error, unspecified" },
	{ 0x7F,				"Internetworking, unspecified" },
	{ 0,				NULL }
};

static const value_string q931_cause_condition_vals[] = {
	{ 0x00, "Unknown" },
	{ 0x01, "Permanent" },
	{ 0x02, "Transient" },
	{ 0x00, NULL }
};

#define	Q931_REJ_USER_SPECIFIC		0x00
#define	Q931_REJ_IE_MISSING		0x04
#define	Q931_REJ_IE_INSUFFICIENT	0x08

static const value_string q931_rejection_reason_vals[] = {
	{ 0x00, "User specific" },
	{ 0x04, "Information element missing" },
	{ 0x08, "Information element contents are not sufficient" },
	{ 0x00, NULL }
};

void
dissect_q931_cause_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree, int hf_cause_value, guint8 *cause_value)
{
	guint8 octet;
	guint8 coding_standard;
	guint8 rejection_reason;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	coding_standard = octet & 0x60;
	if (coding_standard != Q931_ITU_STANDARDIZED_CODING) {
		/*
		 * We don't know how the cause is encoded,
		 * so just dump it as data and be done with it.
		 */
		proto_tree_add_uint(tree, hf_q931_coding_standard, tvb, offset, 1, octet);
		proto_tree_add_text(tree, tvb, offset,
		    len, "Data: %s",
		    tvb_bytes_to_str(tvb, offset, len));
		return;
	}
	proto_tree_add_uint(tree, hf_q931_cause_location, tvb, offset, 1, octet);
	proto_tree_add_uint(tree, hf_q931_coding_standard, tvb, offset, 1, octet);
	proto_tree_add_boolean(tree, hf_q931_extension_ind, tvb, offset, 1, octet);
	offset += 1;
	len -= 1;

	if (!(octet & Q931_IE_VL_EXTENSION)) {
		if (len == 0)
			return;
		octet = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Recommendation: %s",
		    val_to_str(octet & 0x7F, q931_cause_recommendation_vals,
		      "Unknown (0x%02X)"));
		proto_tree_add_boolean(tree, hf_q931_extension_ind, tvb, offset, 1, octet);
		offset += 1;
		len -= 1;
	}

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	*cause_value = octet & 0x7F;

	/* add cause value to packet info for use in tap */
	if(have_valid_q931_pi) {
		q931_pi->cause_value = *cause_value;
	}

	proto_tree_add_uint(tree, hf_cause_value, tvb, offset, 1, *cause_value);
	proto_tree_add_boolean(tree, hf_q931_extension_ind, tvb, offset, 1, octet);
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	switch (*cause_value) {

	case Q931_CAUSE_UNALLOC_NUMBER:
	case Q931_CAUSE_NO_ROUTE_TO_DEST:
	case Q931_CAUSE_QOS_UNAVAILABLE:
		octet = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Network service: %s",
		    (octet & 0x80) ? "User" : "Provider");
		proto_tree_add_text(tree, tvb, offset, 1,
		    "%s",
		    (octet & 0x40) ? "Abnormal" : "Normal");
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Condition: %s",
		    val_to_str(octet & 0x03, q931_cause_condition_vals,
		      "Unknown (0x%X)"));
		break;

	case Q931_CAUSE_CALL_REJECTED:
		rejection_reason = octet & 0x7C;
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Rejection reason: %s",
		    val_to_str(octet & 0x7C, q931_rejection_reason_vals,
		      "Unknown (0x%X)"));
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Condition: %s",
		    val_to_str(octet & 0x03, q931_cause_condition_vals,
		      "Unknown (0x%X)"));
		offset += 1;
		len -= 1;

		if (len == 0)
			return;
		switch (rejection_reason) {

		case Q931_REJ_USER_SPECIFIC:
			proto_tree_add_text(tree, tvb, offset, len,
			    "User specific diagnostic: %s",
			    tvb_bytes_to_str(tvb, offset, len));
			break;

		case Q931_REJ_IE_MISSING:
			proto_tree_add_text(tree, tvb, offset, 1,
			    "Missing information element: %s",
			    val_to_str(tvb_get_guint8(tvb, offset), q931_info_element_vals0,
			      "Unknown (0x%02X)"));
			break;

		case Q931_REJ_IE_INSUFFICIENT:
			proto_tree_add_text(tree, tvb, offset, 1,
			    "Insufficient information element: %s",
			    val_to_str(tvb_get_guint8(tvb, offset), q931_info_element_vals0,
			      "Unknown (0x%02X)"));
			break;

		default:
			proto_tree_add_text(tree, tvb, offset, len,
			    "Diagnostic: %s",
			    tvb_bytes_to_str(tvb, offset, len));
			break;
		}
		break;

	case Q931_CAUSE_ACCESS_INFO_DISC:
	case Q931_CAUSE_INCOMPATIBLE_DEST:
	case Q931_CAUSE_MAND_IE_MISSING:
	case Q931_CAUSE_IE_NONEX_OR_UNIMPL:
	case Q931_CAUSE_INVALID_IE_CONTENTS:
		do {
			proto_tree_add_text(tree, tvb, offset, 1,
			    "Information element: %s",
			    val_to_str(tvb_get_guint8(tvb, offset), q931_info_element_vals0,
			      "Unknown (0x%02X)"));
			offset += 1;
			len -= 1;
		} while (len != 0);
		break;

	case Q931_CAUSE_MT_NONEX_OR_UNIMPL:
	case Q931_CAUSE_MSG_INCOMPAT_W_CS:
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Message type: %s",
		    val_to_str(tvb_get_guint8(tvb, offset), q931_message_type_vals,
		      "Unknown (0x%02X)"));
		break;

	case Q931_CAUSE_REC_TIMER_EXP:
		if (len < 3)
			return;
		proto_tree_add_text(tree, tvb, offset, 3,
		    "Timer: %.3s", tvb_get_ptr(tvb, offset, 3));
		break;

	default:
		proto_tree_add_text(tree, tvb, offset, len,
		    "Diagnostics: %s",
		    tvb_bytes_to_str(tvb, offset, len));
	}
}

/*
 * Dissect a Call state information element.
 */
static const value_string q931_call_state_vals[] = {
	{ 0x00, "Null" },
	{ 0x01, "Call initiated" },
	{ 0x02, "Overlap sending" },
	{ 0x03, "Outgoing call proceeding" },
	{ 0x04, "Call delivered" },
	{ 0x06, "Call present" },
	{ 0x07, "Call received" },
	{ 0x08, "Connect request" },
	{ 0x09, "Incoming call proceeding" },
	{ 0x0A, "Active" },
	{ 0x0B, "Disconnect request" },
	{ 0x0C, "Disconnect indication" },
	{ 0x0F, "Suspend request" },
	{ 0x12, "Resume request" },
	{ 0x13, "Release request" },
	{ 0x16, "Call abort"},
	{ 0x19, "Overlap receiving" },
	{ 0x3D, "Restart request" },
	{ 0x3E, "Restart" },
	{ 0,    NULL }
};

static void
dissect_q931_call_state_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;
	guint8 coding_standard;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	coding_standard = octet & 0x60;
	proto_tree_add_uint(tree, hf_q931_coding_standard, tvb, offset, 1, octet);
	if (coding_standard != Q931_ITU_STANDARDIZED_CODING) {
		/*
		 * We don't know how the call state is encoded,
		 * so just dump it as data and be done with it.
		 */
		proto_tree_add_text(tree, tvb, offset,
		    len, "Data: %s",
		    tvb_bytes_to_str(tvb, offset, len));
		return;
	}
	proto_tree_add_text(tree, tvb, offset, 1,
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
dissect_q931_channel_identification_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;
	guint8 coding_standard;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);

	proto_tree_add_item(tree, hf_q931_extension_ind, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_q931_channel_interface_explicit, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_q931_channel_interface_type, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_q931_channel_exclusive, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_q931_channel_dchan, tvb, offset, 1, FALSE);
	
	if (octet & Q931_NOT_BASIC_CHANNEL) {
		proto_tree_add_item(tree, hf_q931_channel_selection_pri, tvb, offset, 1, FALSE);
	} else {
		proto_tree_add_item(tree, hf_q931_channel_selection_bri, tvb, offset, 1, FALSE);
	}
	offset += 1;
	len -= 1;

	if (octet & Q931_INTERFACE_IDENTIFIED) {
		guint8 octet;
		int identifier_offset = offset;
		int identifier_len = 0;
		do {
			if (len == 0)
				break;
			octet = tvb_get_guint8(tvb, offset);
			offset += 1;
			len -= 1;
			identifier_len++;
		} while (!(octet & Q931_IE_VL_EXTENSION));

		/*
		 * XXX - do we want to strip off the 8th bit on the
		 * last octet of the interface identifier?
		 */
		if (identifier_len != 0) {
			proto_tree_add_text(tree, tvb, identifier_offset,
			    identifier_len, "Interface identifier: %s",
			    bytes_to_str(
			      tvb_get_ptr(tvb, identifier_offset, identifier_len),
			      identifier_len));
		}
	}

	if (octet & Q931_NOT_BASIC_CHANNEL) {
		if (len == 0)
			return;
		octet = tvb_get_guint8(tvb, offset);
		coding_standard = octet & 0x60;
		proto_tree_add_item(tree, hf_q931_extension_ind, tvb, offset, 1, FALSE);
		proto_tree_add_uint(tree, hf_q931_coding_standard, tvb, offset, 1, octet);
		if (coding_standard != Q931_ITU_STANDARDIZED_CODING) {
			/*
			 * We don't know how the channel identifier is
			 * encoded, so just dump it as data and be done
			 * with it.
			 */
			proto_tree_add_text(tree, tvb, offset,
			    len, "Data: %s",
			    tvb_bytes_to_str(tvb, offset, len));
			return;
		}
		proto_tree_add_item(tree, hf_q931_channel_map, tvb, offset, 1, FALSE);
		proto_tree_add_item(tree, hf_q931_channel_element_type, tvb, offset, 1, FALSE);
		
		offset += 1;
		len -= 1;

		if (octet & Q931_IS_SLOT_MAP) {
			guint8 octet;
			while (len) {
				octet = tvb_get_guint8(tvb, offset);
				proto_tree_add_text(tree, tvb, offset, 1,
					"Slot map: 0x%02x", octet);
				offset += 1;
				len -= 1;
			} 
		} else {
			guint8 octet;
			do {
				if (len == 0)
					break;
				octet = tvb_get_guint8(tvb, offset);

				proto_tree_add_item(tree, hf_q931_extension_ind, tvb, offset, 1, FALSE);
				proto_tree_add_item(tree,hf_q931_channel_number,tvb,offset,1,FALSE);

				offset += 1;
				len -= 1;
			} while (!(octet & Q931_IE_VL_EXTENSION));
		}
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
dissect_q931_progress_indicator_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;
	guint8 coding_standard;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	coding_standard = octet & 0x60;
	proto_tree_add_uint(tree, hf_q931_coding_standard, tvb, offset, 1, octet);
	if (coding_standard != Q931_ITU_STANDARDIZED_CODING) {
		/*
		 * We don't know how the progress indicator is encoded,
		 * so just dump it as data and be done with it.
		 */
		proto_tree_add_text(tree, tvb, offset,
		    len, "Data: %s",
		    tvb_bytes_to_str(tvb, offset, len));
		return;
	}
	proto_tree_add_text(tree, tvb, offset, 1,
	    "Location: %s",
	    val_to_str(octet & 0x0F, q931_cause_location_vals,
	      "Unknown (0x%X)"));
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 1,
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
dissect_q931_ns_facilities_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;
	int netid_len;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	netid_len = octet & 0x7F;
	proto_tree_add_text(tree, tvb, offset, 1,
	    "Network identification length: %u",
	    netid_len);
	offset += 1;
	len -= 1;
	if (netid_len != 0) {
		if (len == 0)
			return;
		octet = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Type of network identification: %s",
		    val_to_str(octet & 0x70, q931_netid_type_vals,
		      "Unknown (0x%02X)"));
		proto_tree_add_text(tree, tvb, offset, 1,
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
			proto_tree_add_text(tree, tvb, offset, netid_len,
			    "Network identification: %s",
			    tvb_format_text(tvb, offset, netid_len));
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
	proto_tree_add_text(tree, tvb, offset,
	    len, "Network-specific facility specification: %s",
	    tvb_bytes_to_str(tvb, offset, len));
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
dissect_q931_notification_indicator_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 1,
	    "Notification description: %s",
	    val_to_str(octet & 0x7F, q931_notification_description_vals,
	      "Unknown (0x%02X)"));
}

/*
 * Dissect a Date/time information element.
 */
static void
dissect_q931_date_time_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	if (len == 6) {
		/*
		 * XXX - what is "year" relative to?  Is "month" 0-origin or
		 * 1-origin?  Q.931 doesn't say....
		 */
		proto_tree_add_text(tree, tvb, offset, 6,
		    "Date/time: %02u-%02u-%02u %02u:%02u:%02u",
		    tvb_get_guint8(tvb, offset + 0), tvb_get_guint8(tvb, offset + 1), tvb_get_guint8(tvb, offset + 2),
		    tvb_get_guint8(tvb, offset + 3), tvb_get_guint8(tvb, offset + 4), tvb_get_guint8(tvb, offset + 5));
	} else if (len == 5) {
		proto_tree_add_text(tree, tvb, offset, 5,
		    "Date/time: %02u-%02u-%02u %02u:%02u:00",
		    tvb_get_guint8(tvb, offset + 0), tvb_get_guint8(tvb, offset + 1), tvb_get_guint8(tvb, offset + 2),
		    tvb_get_guint8(tvb, offset + 3), tvb_get_guint8(tvb, offset + 4));
	} else {
		proto_tree_add_text(tree, tvb, offset, len,
		    "Date/time: length is %d, should be 5 or 6", len);
	}
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
	{ 0x08, "Off-hook warning tone on" },
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
dissect_q931_signal_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	if (len != 1) {
		proto_tree_add_text(tree, tvb, offset, len,
		    "Signal: length is %d, should be 1", len);
		return;
	}
	proto_tree_add_text(tree, tvb, offset, 1,
	    "Signal: %s",
	    val_to_str(tvb_get_guint8(tvb, offset), q931_signal_vals,
	        "Unknown (0x%02X)"));
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
dissect_q931_information_rate_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	if (len != 4) {
		proto_tree_add_text(tree, tvb, offset, len,
		    "Information rate: length is %d, should be 4", len);
		return;
	}
	proto_tree_add_text(tree, tvb, offset + 0, 1,
	    "Incoming information rate: %s",
	    val_to_str(tvb_get_guint8(tvb, offset + 0) & 0x1F,
	      q931_throughput_class_vals, "Unknown (0x%02X)"));
	proto_tree_add_text(tree, tvb, offset + 1, 1,
	    "Outgoing information rate: %s",
	    val_to_str(tvb_get_guint8(tvb, offset + 1) & 0x1F,
	      q931_throughput_class_vals, "Unknown (0x%02X)"));
	proto_tree_add_text(tree, tvb, offset + 2, 1,
	    "Minimum incoming information rate: %s",
	    val_to_str(tvb_get_guint8(tvb, offset + 2) & 0x1F,
	      q931_throughput_class_vals, "Unknown (0x%02X)"));
	proto_tree_add_text(tree, tvb, offset + 3, 1,
	    "Minimum outgoing information rate: %s",
	    val_to_str(tvb_get_guint8(tvb, offset + 3) & 0x1F,
	      q931_throughput_class_vals, "Unknown (0x%02X)"));
}

static int
dissect_q931_guint16_value(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree, const char *label)
{
	guint8 octet;
	guint16 value;
	int value_len;

	value_len = 0;

	octet = tvb_get_guint8(tvb, offset);
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
	octet = tvb_get_guint8(tvb, offset);
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
	octet = tvb_get_guint8(tvb, offset);
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

	proto_tree_add_text(tree, tvb, offset, value_len, "%s: %u ms", label,
	    value);
	return value_len;

past_end:
	proto_tree_add_text(tree, tvb, offset, len,
	    "%s goes past end of information element", label);
	return -1;

bad_length:
	proto_tree_add_text(tree, tvb, offset, len, "%s isn't 3 octets long",
	    label);
	return -1;
}

/*
 * Dissect an End-to-end transit delay information element.
 */
static void
dissect_q931_e2e_transit_delay_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	int value_len;

	if (len == 0)
		return;
	value_len = dissect_q931_guint16_value(tvb, offset, len, tree,
	    "Cumulative transit delay");
	if (value_len < 0)
		return;	/* error */
	offset += value_len;
	len -= value_len;

	if (len == 0)
		return;
	value_len = dissect_q931_guint16_value(tvb, offset, len, tree,
	    "Requested end-to-end transit delay");
	if (value_len < 0)
		return;	/* error */
	offset += value_len;
	len -= value_len;

	if (len == 0)
		return;
	value_len = dissect_q931_guint16_value(tvb, offset, len, tree,
	    "Maximum end-to-end transit delay");
}

/*
 * Dissect a Transit delay selection and indication information element.
 */
static void
dissect_q931_td_selection_and_int_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	if (len == 0)
		return;
	dissect_q931_guint16_value(tvb, offset, len, tree,
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
dissect_q931_pl_binary_parameters_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 1,
	    "Fast select: %s",
	    val_to_str(octet & 0x18, q931_fast_selected_vals, "Unknown (0x%02X)"));
	proto_tree_add_text(tree, tvb, offset, 1,
	    "%s",
	    (octet & 0x04) ? "No request/request denied" :
	    		     "Request indicated/request accepted");
	proto_tree_add_text(tree, tvb, offset, 1,
	    "%s confirmation",
	    (octet & 0x02) ? "Link-by-link" : "End-to-end");
	proto_tree_add_text(tree, tvb, offset, 1,
	    "Modulus %u sequencing",
	    (octet & 0x01) ? 8 : 128);
}

/*
 * Dissect a Packet layer window size information element.
 */
static void
dissect_q931_pl_window_size_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	if (len == 0)
		return;
	proto_tree_add_text(tree, tvb, offset, 1,
	    "Forward value: %u", tvb_get_guint8(tvb, offset) & 0x7F);
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	proto_tree_add_text(tree, tvb, offset, 1,
	    "Backward value: %u", tvb_get_guint8(tvb, offset) & 0x7F);
}

/*
 * Dissect a Packet size information element.
 */
static void
dissect_q931_packet_size_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	if (len == 0)
		return;
	proto_tree_add_text(tree, tvb, offset, 1,
	    "Forward value: %u", tvb_get_guint8(tvb, offset) & 0x7F);
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	proto_tree_add_text(tree, tvb, offset, 1,
	    "Backward value: %u", tvb_get_guint8(tvb, offset) & 0x7F);
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
dissect_q931_cug_ie(tvbuff_t *tvb, int offset, int len, proto_tree *tree)
{
	if (len == 0)
		return;
	proto_tree_add_text(tree, tvb, offset, 1,
	    "CUG indication: %s",
	    val_to_str(tvb_get_guint8(tvb, offset) & 0x07,
	      q931_cug_indication_vals, "Unknown (0x%02X)"));
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	proto_tree_add_text(tree, tvb, offset, len, "CUG index code: %s",
	    tvb_format_text(tvb, offset, len));
}

/*
 * Dissect a Reverse charging indication information element.
 */
static const value_string q931_reverse_charging_indication_vals[] = {
	{ 0x01, "Reverse charging requested" },
	{ 0,    NULL }
};

static void
dissect_q931_reverse_charge_ind_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	if (len == 0)
		return;
	proto_tree_add_text(tree, tvb, offset, 1,
	    "Reverse charging indication: %s",
	    val_to_str(tvb_get_guint8(tvb, offset) & 0x07,
	      q931_reverse_charging_indication_vals, "Unknown (0x%02X)"));
}

/*
 * Dissect a (phone) number information element.
 */
static const value_string q931_number_type_vals[] = {
	{ 0x0, "Unknown" },
	{ 0x1, "International number" },
	{ 0x2, "National number" },
	{ 0x3, "Network specific number" },
	{ 0x4, "Subscriber number" },
	{ 0x6, "Abbreviated number" },
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
	{ 0x01, "Presentation restricted" },
	{ 0x02, "Number not available due to interworking" },
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
dissect_q931_number_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree, int hfindex, e164_info_t e164_info)
{
	guint8 octet;
	gint number_plan;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	number_plan = octet & 0x0f;
	e164_info.nature_of_address = ( octet & 0x70 ) >> 4;
	proto_tree_add_uint(tree, hf_q931_numbering_plan, tvb, offset, 1, octet);
	proto_tree_add_uint(tree, hf_q931_number_type, tvb, offset, 1, octet);
	proto_tree_add_boolean(tree, hf_q931_extension_ind, tvb, offset, 1, octet);
	
	offset += 1;
	len -= 1;

	if (!(octet & Q931_IE_VL_EXTENSION)) {
		if (len == 0)
			return;
		octet = tvb_get_guint8(tvb, offset);
		proto_tree_add_uint(tree, hf_q931_screening_ind, tvb, offset, 1, octet);
		proto_tree_add_uint(tree, hf_q931_presentation_ind, tvb, offset, 1, octet);
		proto_tree_add_boolean(tree, hf_q931_extension_ind, tvb, offset, 1, octet);
		offset += 1;
		len -= 1;
	}

	/*
	 * XXX - only in a Redirecting number information element.
	 */
	if (!(octet & Q931_IE_VL_EXTENSION)) {
		if (len == 0)
			return;
		octet = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Reason for redirection: %s",
		    val_to_str(octet & 0x0F, q931_redirection_reason_vals,
		      "Unknown (0x%X)"));
		offset += 1;
		len -= 1;
	}

	if (len == 0)
		return;
	proto_tree_add_item(tree, hfindex, tvb, offset, len, FALSE);
	proto_item_append_text(proto_tree_get_parent(tree), ": '%s'", tvb_format_text(tvb, offset, len));

	if ( number_plan == 1 ) {
		if ( e164_info.e164_number_type != NONE ){

			e164_info.E164_number_str = tvb_get_ephemeral_string(tvb, offset, len);
			e164_info.E164_number_length = len;
			dissect_e164_number(tvb, tree, offset, len, e164_info);
		}
	}

    /* Collect q931_packet_info */
    if ( e164_info.e164_number_type == CALLING_PARTY_NUMBER && have_valid_q931_pi)
          q931_pi->calling_number = tvb_get_ephemeral_string(tvb, offset, len);
    if ( e164_info.e164_number_type == CALLED_PARTY_NUMBER && have_valid_q931_pi)
          q931_pi->called_number = tvb_get_ephemeral_string(tvb, offset, len);
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
dissect_q931_party_subaddr_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 1,
	    "Type of subaddress: %s",
	    val_to_str(octet & 0x70, q931_subaddress_type_vals,
	      "Unknown (0x%02X)"));
	proto_tree_add_text(tree, tvb, offset, 1,
	    "Odd/even indicator: %s",
	    val_to_str(octet & 0x10, q931_odd_even_indicator_vals,
	      "Unknown (0x%02X)"));
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	proto_tree_add_text(tree, tvb, offset, len, "Subaddress: %s",
	    tvb_bytes_to_str(tvb, offset, len));
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
dissect_q931_restart_indicator_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	if (len != 1) {
		proto_tree_add_text(tree, tvb, offset, len,
		    "Restart indicator: length is %d, should be 1", len);
		return;
	}
	proto_tree_add_text(tree, tvb, offset, 1,
	    "Restart indicator: %s",
	    val_to_str(tvb_get_guint8(tvb, offset) & 0x07,
	      q931_restart_indicator_class_vals, "Unknown (0x%02X)"));
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
dissect_q931_high_layer_compat_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;
	guint8 coding_standard;
	guint8 characteristics;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	coding_standard = octet & 0x60;
	proto_tree_add_uint(tree, hf_q931_coding_standard, tvb, offset, 1, octet);
	offset += 1;
	len -= 1;
	if (coding_standard != Q931_ITU_STANDARDIZED_CODING) {
		/*
		 * We don't know how the call state is encoded,
		 * so just dump it as data and be done with it.
		 */
		proto_tree_add_text(tree, tvb, offset,
		    len, "Data: %s",
		    tvb_bytes_to_str(tvb, offset, len));
		return;
	}

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	characteristics = octet & 0x7F;
	proto_tree_add_text(tree, tvb, offset, 1,
	    "High layer characteristics identification: %s",
	    val_to_str(characteristics, q931_high_layer_characteristics_vals,
	     "Unknown (0x%02X)"));
	offset += 1;
	len -= 1;

	if (!(octet & Q931_IE_VL_EXTENSION)) {
		if (len == 0)
			return;
		octet = tvb_get_guint8(tvb, offset);
		if (characteristics == Q931_AUDIOVISUAL) {
			proto_tree_add_text(tree, tvb, offset, 1,
			    "Extended audiovisual characteristics identification: %s",
			    val_to_str(octet & 0x7F,
			      q931_audiovisual_characteristics_vals,
			      "Unknown (0x%02X)"));
		} else {
			proto_tree_add_text(tree, tvb, offset, 1,
			    "Extended high layer characteristics identification: %s",
			    val_to_str(octet & 0x7F,
			      q931_high_layer_characteristics_vals,
			      "Unknown (0x%02X)"));
		}
	}
}


/*
 * Dissect a User-user information element.
 */
#define	Q931_PROTOCOL_DISCRIMINATOR_IA5		0x04
#define Q931_PROTOCOL_DISCRIMINATOR_ASN1	0x05

const value_string q931_protocol_discriminator_vals[] = {
	{ 0x00,					"User-specific protocol" },
	{ 0x01,					"OSI high layer protocols" },
	{ 0x02,					"X.244" },
	{ Q931_PROTOCOL_DISCRIMINATOR_IA5,	"IA5 characters" },
	{ Q931_PROTOCOL_DISCRIMINATOR_ASN1,	"X.208 and X.209 coded user information" },
	{ 0x07,					"V.120 rate adaption" },
	{ 0x08,					"Q.931/I.451 user-network call control messages" },
	{ 0,					NULL }
};

void
dissect_q931_user_user_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 1,
	    "Protocol discriminator: %s",
	    val_to_str(octet, q931_protocol_discriminator_vals,
	    "Unknown (0x%02x)"));
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	switch (octet) {

	case Q931_PROTOCOL_DISCRIMINATOR_IA5:
		proto_tree_add_text(tree, tvb, offset, len, "User information: %s",
		    tvb_format_text(tvb, offset, len));
		break;

	default:
		proto_tree_add_text(tree, tvb, offset, len, "User information: %s",
		    tvb_bytes_to_str(tvb, offset, len));
		break;
	}
}

/*
 * Dissect information elements consisting of ASCII^H^H^H^H^HIA5 text.
 */
static void
dissect_q931_ia5_ie(tvbuff_t *tvb, int offset, int len, proto_tree *tree,
    const char *label)
{
	if (len != 0) {
		proto_tree_add_text(tree, tvb, offset, len, "%s: %s", label,
		    tvb_format_text(tvb, offset, len));
		proto_item_append_text(proto_tree_get_parent(tree), "  '%s'", tvb_format_text(tvb, offset, len));
	}
}

static void
dissect_q931_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    gboolean is_tpkt)
{
	int		offset = 0;
	proto_tree	*q931_tree = NULL;
	proto_tree	*ie_tree = NULL;
	proto_item	*ti, *ti_ie;
	guint8		call_ref_len;
	guint8		call_ref[15];
	guint32		call_ref_val;
	guint8		message_type, segmented_message_type;
	guint8		info_element;
	guint16		info_element_len;
	gboolean	more_frags; 
	guint32		frag_len;
	fragment_data *fd_head;
	tvbuff_t *next_tvb = NULL;

	q931_pi=ep_alloc(sizeof(q931_packet_info));

	/* Init struct for collecting q931_packet_info */
	reset_q931_packet_info(q931_pi);
	have_valid_q931_pi=TRUE;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "Q.931");

	if (tree) {
		ti = proto_tree_add_item(tree, proto_q931, tvb, offset, -1,
		    FALSE);
		q931_tree = proto_item_add_subtree(ti, ett_q931);

		dissect_q931_protocol_discriminator(tvb, offset, q931_tree);
	}
	offset += 1;
	call_ref_len = tvb_get_guint8(tvb, offset) & 0xF;	/* XXX - do as a bit field? */
	if (q931_tree != NULL)
		proto_tree_add_uint(q931_tree, hf_q931_call_ref_len, tvb, offset, 1, call_ref_len);
	offset += 1;
	switch (call_ref_len) {
		case 0: call_ref_val = 0; break;
		case 1:	call_ref_val = tvb_get_guint8(tvb, offset);	break;
		case 2:	call_ref_val = tvb_get_ntohs(tvb, offset); break;
		case 3:	call_ref_val = tvb_get_ntoh24(tvb, offset); break;
		default: call_ref_val = tvb_get_ntohl(tvb, offset);
	} 
	if (call_ref_len != 0) {
		tvb_memcpy(tvb, call_ref, offset, call_ref_len);
		if (q931_tree != NULL) {
			proto_tree_add_boolean(q931_tree, hf_q931_call_ref_flag,
			    tvb, offset, 1, (call_ref[0] & 0x80) != 0);
			call_ref[0] &= 0x7F;
			proto_tree_add_bytes(q931_tree, hf_q931_call_ref,
			    tvb, offset, call_ref_len, call_ref);
		} else
		{       /* info for the tap */
			call_ref[0] &= 0x7F;
		}
		/* XXX - Should crv be something besides a guint32? */
		g_memmove(&(q931_pi->crv), call_ref, call_ref_len > sizeof(q931_pi->crv) ? sizeof(q931_pi->crv) : call_ref_len );
		offset += call_ref_len;
	}
	message_type = tvb_get_guint8(tvb, offset);
	if(have_valid_q931_pi) {
		q931_pi->message_type = message_type;
	}
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_str(pinfo->cinfo, COL_INFO,
		    val_to_str(message_type, q931_message_type_vals,
		      "Unknown message type (0x%02X)"));
	}
	if (q931_tree != NULL)
		proto_tree_add_uint(q931_tree, hf_q931_message_type, tvb, offset, 1, message_type);
	offset += 1;

	/*
	 * And now for the information elements....
	 */
	if ((message_type != Q931_SEGMENT) || !q931_reassembly || 
			(tvb_reported_length_remaining(tvb, offset) <= 4)) {
		dissect_q931_IEs(tvb, pinfo, tree, q931_tree, is_tpkt, offset, 0);
		return;
	}
	info_element = tvb_get_guint8(tvb, offset);
	info_element_len = tvb_get_guint8(tvb, offset + 1);
	if ((info_element != Q931_IE_SEGMENTED_MESSAGE) || (info_element_len < 2)) {
		dissect_q931_IEs(tvb, pinfo, tree, q931_tree, is_tpkt, offset, 0);
		return;
	}
	/* Segmented message IE */
	ti_ie = proto_tree_add_text(q931_tree, tvb, offset, 1+1+info_element_len, "%s",
				    val_to_str(info_element, q931_info_element_vals[0], "Unknown information element (0x%02X)"));
	ie_tree = proto_item_add_subtree(ti_ie, ett_q931_ie);
	proto_tree_add_text(ie_tree, tvb, offset, 1, "Information element: %s",
				    val_to_str(info_element, q931_info_element_vals[0], "Unknown (0x%02X)"));
	proto_tree_add_text(ie_tree, tvb, offset + 1, 1, "Length: %u", info_element_len);
	dissect_q931_segmented_message_ie(tvb, offset + 2, info_element_len, ie_tree);
	more_frags = (tvb_get_guint8(tvb, offset + 2) & 0x7F) != 0;
	segmented_message_type = tvb_get_guint8(tvb, offset + 3);
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " of %s",
		    val_to_str(segmented_message_type, q931_message_type_vals, "Unknown message type (0x%02X)"));
	}
	offset += 1 + 1 + info_element_len;
	/* Reassembly */
	frag_len = tvb_length_remaining(tvb, offset);
	fd_head = fragment_add_seq_next(tvb, offset, pinfo, call_ref_val,
									q931_fragment_table, q931_reassembled_table,
									frag_len, more_frags);
	if (fd_head) {
		if (pinfo->fd->num == fd_head->reassembled_in) {  /* last fragment */
			if (fd_head->next != NULL) {  /* 2 or more segments */
				next_tvb = tvb_new_real_data(fd_head->data, fd_head->len, fd_head->len);
				tvb_set_child_real_data_tvbuff(tvb, next_tvb);
				add_new_data_source(pinfo, next_tvb, "Reassembled Q.931 IEs");
				/* Show all fragments. */
                if (tree) {
                    proto_item *frag_tree_item;
                    show_fragment_seq_tree(fd_head, &q931_frag_items, q931_tree, pinfo, next_tvb, &frag_tree_item);
                }
			} else {  /* only 1 segment */
				next_tvb = tvb_new_subset(tvb, offset, -1, -1);
			}
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_add_fstr(pinfo->cinfo, COL_INFO, "%s [reassembled]",
				    val_to_str(segmented_message_type, q931_message_type_vals, "Unknown message type (0x%02X)"));
			}
		} else {
			if (tree) proto_tree_add_uint(q931_tree, hf_q931_reassembled_in, tvb, offset, frag_len, fd_head->reassembled_in);
		}
	}
	if (next_tvb)
		dissect_q931_IEs(next_tvb, pinfo, tree, q931_tree, is_tpkt, 0, 0);
}

static const value_string q931_codeset_vals[] = {
	{ 0x00, "Q.931 information elements" },
	{ 0x04, "Information elements for ISO/IEC use" },
	{ 0x05, "Information elements for national use" },
	{ 0x06, "Information elements specific to the local network" },
	{ 0x07, "User-specific information elements" },
	{ 0x00, NULL },
};

static void
dissect_q931_IEs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *root_tree,
    proto_tree *q931_tree, gboolean is_tpkt, int offset, int initial_codeset)
{
	proto_item	*ti;
	proto_tree	*ie_tree = NULL;
	guint8		info_element;
	guint8		dummy;
	guint16		info_element_len;
	int		codeset, locked_codeset;
	gboolean	non_locking_shift, first_segment;
	tvbuff_t	*h225_tvb, *next_tvb;
	e164_info_t e164_info;
	e164_info.e164_number_type = NONE;

	codeset = locked_codeset = initial_codeset;
	non_locking_shift = TRUE;
	first_segment = FALSE;
	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		info_element = tvb_get_guint8(tvb, offset);

		/* Check for the codeset shift */
		if ((info_element & Q931_IE_SO_MASK) &&
		    ((info_element & Q931_IE_SO_IDENTIFIER_MASK) == Q931_IE_SHIFT)) {
			non_locking_shift = info_element & Q931_IE_SHIFT_NON_LOCKING;
			codeset = info_element & Q931_IE_SHIFT_CODESET;
			if (!non_locking_shift)
				locked_codeset = codeset;
			if (q931_tree != NULL) {
				proto_tree_add_text(q931_tree, tvb, offset, 1,
				    "%s shift to codeset %u: %s",
				    (non_locking_shift ? "Non-locking" : "Locking"),
				    codeset,
				    val_to_str(codeset, q931_codeset_vals,
				      "Unknown (0x%02X)"));
			}
			offset += 1;
			continue;
		}

		/*
		 * Check for the single-octet IEs.
		 */
		if (info_element & Q931_IE_SO_MASK) {
			/*
			 * Check for subdissectors for this IE or
			 * for all IEs in this codeset.
			 */
			if (dissector_get_port_handle(codeset_dissector_table, codeset) ||
			    dissector_get_port_handle(ie_dissector_table, (codeset << 8) | (info_element & Q931_IE_SO_IDENTIFIER_MASK))) {
				next_tvb = tvb_new_subset (tvb, offset, 1, 1);
				if (dissector_try_port(ie_dissector_table, (codeset << 8) | (info_element & Q931_IE_SO_IDENTIFIER_MASK), next_tvb, pinfo, q931_tree) ||
				    dissector_try_port(codeset_dissector_table, codeset, next_tvb, pinfo, q931_tree)) {
					offset += 1;
					codeset = locked_codeset;
					continue;
				}
			}

			switch ((codeset << 8) | (info_element & Q931_IE_SO_IDENTIFIER_MASK)) {

			case CS0 | Q931_IE_MORE_DATA_OR_SEND_COMP:
				switch (info_element) {	

				case Q931_IE_MORE_DATA:
					if (q931_tree != NULL) {
						proto_tree_add_text(q931_tree, tvb, offset, 1,
						    "More data");
					}
					break;

				case Q931_IE_SENDING_COMPLETE:
					if (q931_tree != NULL) {
						proto_tree_add_text(q931_tree, tvb, offset, 1,
						    "Sending complete");
					}
					break;

				default:
					if (q931_tree != NULL) {
						proto_tree_add_text(q931_tree, tvb, offset, 1,
						    "Unknown information element (0x%02X)",
						    info_element);
					}
					break;
				}
				break;

			case CS0 | Q931_IE_CONGESTION_LEVEL:
				if (q931_tree != NULL) {
					proto_tree_add_text(q931_tree, tvb, offset, 1,
					    "Congestion level: %s",
					    val_to_str(info_element & Q931_IE_SO_IE_MASK,
					      q931_congestion_level_vals,
					      "Unknown (0x%X)"));
				}
				break;

			case CS0 | Q931_IE_REPEAT_INDICATOR:
				if (q931_tree != NULL) {
					proto_tree_add_text(q931_tree, tvb, offset, 1,
					    "Repeat indicator: %s",
					    val_to_str(info_element & Q931_IE_SO_IE_MASK,
				    	  q931_repeat_indication_vals,
					      "Unknown (0x%X)"));
				}
				break;

			default:
				if (q931_tree != NULL) {
					proto_tree_add_text(q931_tree, tvb, offset, 1,
					    "Unknown information element (0x%02X)",
					    info_element);
				}
				break;
			}
			offset += 1;
			codeset = locked_codeset;
			continue;
		}

		/*
		 * Variable-length IE.
		 *
		 * According to page 18 from Recommendation H.225.0 :
		 * " Length of user-user contents contents
		 * - Shall be 2 octets instead of 1 (as in Figure 4-36/Q.931)"
		 *
		 * We assume that if this is Q.931-over-TPKT, it might
		 * be H.225 traffic, and check for the IE being a user-user
		 * IE with ASN.1 encoding of the user information.
		 */
		if (is_tpkt && tvb_bytes_exist(tvb, offset, 4) &&
		    codeset == 0 && tvb_get_guint8(tvb, offset) == Q931_IE_USER_USER &&
		    tvb_get_guint8(tvb, offset + 3) == Q931_PROTOCOL_DISCRIMINATOR_ASN1)  {
			info_element_len = tvb_get_ntohs(tvb, offset + 1);
			if (q931_tree != NULL) {
				ti = proto_tree_add_text(q931_tree, tvb, offset,
				    1+2+info_element_len, "%s",
				    val_to_str(info_element,
				      q931_info_element_vals[codeset],
				      "Unknown information element (0x%02X)"));
				ie_tree = proto_item_add_subtree(ti,
				    ett_q931_ie);
				proto_tree_add_text(ie_tree, tvb, offset, 1,
				    "Information element: %s",
				    val_to_str(info_element,
				      q931_info_element_vals[codeset], "Unknown (0x%02X)"));
				proto_tree_add_text(ie_tree, tvb, offset + 1,
				    2, "Length: %u", info_element_len);
				proto_tree_add_text(ie_tree, tvb, offset + 3,
				    1, "Protocol discriminator: %s",
				    val_to_str(tvb_get_guint8(tvb, offset + 3),
				      q931_protocol_discriminator_vals,
				      "Unknown (0x%02x)"));
			}

			if (info_element_len > 1) {
				/*
				 * If we don't desegment limit the length 
				 * to the actual size in the frame
				 */
				if (!pinfo->can_desegment) {
					info_element_len = min(info_element_len, tvb_length_remaining(tvb, offset + 3));
				}
				/*
				 * Do we have a handle for the H.225
				 * dissector?
				 */
				if (h225_handle != NULL) {
					/*
					 * Yes - call it, regardless of
					 * whether we're building a
					 * protocol tree or not.
					 */
					h225_tvb = tvb_new_subset(tvb,
					    offset + 4, info_element_len - 1,
					    info_element_len - 1);
					call_dissector(h225_handle, h225_tvb,
					    pinfo, root_tree);
				} else {
					/*
					 * No - just show it as "User
					 * information" (if "ie_tree" is
					 * null, this won't add anything).
					 */
					proto_tree_add_text(ie_tree, tvb,
					    offset + 4, info_element_len - 1,
					    "User information: %s",
					    tvb_bytes_to_str(tvb, offset + 4,
					      info_element_len - 1));
				}
			}
			offset += 1 + 2 + info_element_len;
		} else {
			info_element_len = tvb_get_guint8(tvb, offset + 1);

			if (first_segment && (tvb_reported_length_remaining(tvb, offset + 2) < info_element_len)) {  /* incomplete IE at the end of the 1st segment */
				proto_tree_add_text(q931_tree, tvb, offset, tvb_reported_length_remaining(tvb, offset), "Incomplete IE in the 1st segment");
				break;
			}

			/*
			 * Check for subdissectors for this IE or
			 * for all IEs in this codeset.
			 */
			if (dissector_get_port_handle(codeset_dissector_table, codeset) ||
			    dissector_get_port_handle(ie_dissector_table, (codeset << 8) | info_element)) {
				next_tvb = tvb_new_subset (tvb, offset, info_element_len + 2, info_element_len + 2);
				if (dissector_try_port(ie_dissector_table, (codeset << 8) | info_element, next_tvb, pinfo, q931_tree) ||
				    dissector_try_port(codeset_dissector_table, codeset, next_tvb, pinfo, q931_tree)) {
					offset += 2 + info_element_len;
					codeset = locked_codeset;
					continue;
				}
			}

			ti = proto_tree_add_text(q931_tree, tvb, offset, 1+1+info_element_len, "%s",
				    val_to_str(info_element, q931_info_element_vals[codeset], "Unknown information element (0x%02X)"));
			ie_tree = proto_item_add_subtree(ti, ett_q931_ie);
			proto_tree_add_text(ie_tree, tvb, offset, 1, "Information element: %s",
				    val_to_str(info_element, q931_info_element_vals[codeset], "Unknown (0x%02X)"));
			proto_tree_add_text(ie_tree, tvb, offset + 1, 1, "Length: %u", info_element_len);

			if (((codeset << 8) | info_element) == (CS0 | Q931_IE_SEGMENTED_MESSAGE)) {
				dissect_q931_segmented_message_ie(tvb, offset + 2, info_element_len, ie_tree);
				if (check_col(pinfo->cinfo, COL_INFO)) {
					col_append_fstr(pinfo->cinfo, COL_INFO, " of %s",
					    val_to_str(tvb_get_guint8(tvb, offset + 3), q931_message_type_vals, "Unknown message type (0x%02X)"));
				}
				if (tvb_get_guint8(tvb, offset + 2) & 0x80) {  /* the 1st segment */
					first_segment = TRUE;
				} else {  /* not the 1st segment */
					proto_tree_add_text(q931_tree, tvb, offset + 4, tvb_reported_length_remaining(tvb, offset + 4), "Message segment");
					info_element_len += tvb_reported_length_remaining(tvb, offset + 4);
				}
			} else {
				/*
				 * For the calling number, called number,
				 * and release cause IEs, don't check
				 * for the tree being null, as
				 * the dissectors for those IEs also
				 * supply information for the tap used
				 * in VoIP calls.
				 */
				switch ((codeset << 8) | info_element) {

				case CS0 | Q931_IE_BEARER_CAPABILITY:
				case CS0 | Q931_IE_LOW_LAYER_COMPAT:
					if (q931_tree != NULL) {
						dissect_q931_bearer_capability_ie(tvb,
							offset + 2, info_element_len,
							ie_tree);
					}
					break;

				case CS0 | Q931_IE_CAUSE:
					dissect_q931_cause_ie(tvb,
						offset + 2, info_element_len,
						ie_tree,
						hf_q931_cause_value, &dummy);
					break;

				case CS0 | Q931_IE_CALL_STATE:
					if (q931_tree != NULL) {
						dissect_q931_call_state_ie(tvb,
							offset + 2, info_element_len,
							ie_tree);
					}
					break;

				case CS0 | Q931_IE_CHANNEL_IDENTIFICATION:
					if (q931_tree != NULL) {
						dissect_q931_channel_identification_ie(
							tvb, offset + 2, info_element_len,
							ie_tree);
					}
					break;

				case CS0 | Q931_IE_PROGRESS_INDICATOR:
					if (q931_tree != NULL) {
						dissect_q931_progress_indicator_ie(tvb,
							offset + 2, info_element_len,
							ie_tree);
					}
					break;

				case CS0 | Q931_IE_NETWORK_SPECIFIC_FACIL:
				case CS0 | Q931_IE_TRANSIT_NETWORK_SEL:
					if (q931_tree != NULL) {
						dissect_q931_ns_facilities_ie(tvb,
							offset + 2, info_element_len,
							ie_tree);
					}
					break;

				case CS0 | Q931_IE_NOTIFICATION_INDICATOR:
					if (q931_tree != NULL) {
						dissect_q931_notification_indicator_ie(
							tvb, offset + 2, info_element_len,
							ie_tree);
					}
					break;

				case CS0 | Q931_IE_DISPLAY:
					if (q931_tree != NULL) {
						dissect_q931_ia5_ie(tvb, offset + 2,
							info_element_len, ie_tree,
							"Display information");
					}
					break;

				case CS0 | Q931_IE_DATE_TIME:
					if (q931_tree != NULL) {
						dissect_q931_date_time_ie(tvb,
							offset + 2, info_element_len,
							ie_tree);
					}
					break;

				case CS0 | Q931_IE_KEYPAD_FACILITY:
					if (q931_tree != NULL) {
						dissect_q931_ia5_ie(tvb, offset + 2,
							info_element_len, ie_tree,
							"Keypad facility");
					}
					break;

				case CS0 | Q931_IE_SIGNAL:
					if (q931_tree != NULL) {
						dissect_q931_signal_ie(tvb,
							offset + 2, info_element_len,
							ie_tree);
					}
					break;

				case CS0 | Q931_IE_INFORMATION_RATE:
					if (q931_tree != NULL) {
						dissect_q931_information_rate_ie(tvb,
							offset + 2, info_element_len,
							ie_tree);
					}
					break;

				case CS0 | Q931_IE_E2E_TRANSIT_DELAY:
					if (q931_tree != NULL) {
						dissect_q931_e2e_transit_delay_ie(tvb,
							offset + 2, info_element_len,
							ie_tree);
					}
					break;

				case CS0 | Q931_IE_TD_SELECTION_AND_INT:
					if (q931_tree != NULL) {
						dissect_q931_td_selection_and_int_ie(
							tvb, offset + 2, info_element_len,
							ie_tree);
					}
					break;

				case CS0 | Q931_IE_PL_BINARY_PARAMETERS:
					if (q931_tree != NULL) {
						dissect_q931_pl_binary_parameters_ie(
							tvb, offset + 2, info_element_len,
							ie_tree);
					}
					break;

				case CS0 | Q931_IE_PL_WINDOW_SIZE:
					if (q931_tree != NULL) {
						dissect_q931_pl_window_size_ie(tvb,
							offset + 2, info_element_len,
							ie_tree);
					}
					break;

				case CS0 | Q931_IE_PACKET_SIZE:
					if (q931_tree != NULL) {
						dissect_q931_packet_size_ie(tvb,
							offset + 2, info_element_len,
							ie_tree);
					}
					break;

				case CS0 | Q931_IE_CUG:
					if (q931_tree != NULL) {
						dissect_q931_cug_ie(tvb,
							offset + 2, info_element_len,
							ie_tree);
					}
					break;

				case CS0 | Q931_IE_REVERSE_CHARGE_IND:
					if (q931_tree != NULL) {
						dissect_q931_reverse_charge_ind_ie(tvb,
							offset + 2, info_element_len,
							ie_tree);
					}
					break;

				case CS0 | Q931_IE_CONNECTED_NUMBER_DEFAULT:
					if (q931_tree != NULL) {
						dissect_q931_number_ie(tvb,
							offset + 2, info_element_len,
							ie_tree,
							hf_q931_connected_number, e164_info);
					}
					break;


				case CS0 | Q931_IE_CALLING_PARTY_NUMBER:
					e164_info.e164_number_type = CALLING_PARTY_NUMBER;
					dissect_q931_number_ie(tvb,
						offset + 2, info_element_len,
						ie_tree,
						hf_q931_calling_party_number, e164_info);
					break;

				case CS0 | Q931_IE_CALLED_PARTY_NUMBER:
					e164_info.e164_number_type = CALLED_PARTY_NUMBER;
					dissect_q931_number_ie(tvb,
						offset + 2, info_element_len,
						ie_tree,
						hf_q931_called_party_number, e164_info);
					break;

				case CS0 | Q931_IE_CALLING_PARTY_SUBADDR:
				case CS0 | Q931_IE_CALLED_PARTY_SUBADDR:
					if (q931_tree != NULL) {
						dissect_q931_party_subaddr_ie(tvb,
							offset + 2, info_element_len,
							ie_tree);
					}
					break;

				case CS0 | Q931_IE_REDIRECTING_NUMBER:
					if (q931_tree != NULL) {
						dissect_q931_number_ie(tvb,
							offset + 2, info_element_len,
							ie_tree,
							hf_q931_redirecting_number, e164_info);
					}
					break;

				case CS0 | Q931_IE_RESTART_INDICATOR:
					if (q931_tree != NULL) {
						dissect_q931_restart_indicator_ie(tvb,
							offset + 2, info_element_len,
							ie_tree);
					}
					break;

				case CS0 | Q931_IE_HIGH_LAYER_COMPAT:
					if (q931_tree != NULL) {
						dissect_q931_high_layer_compat_ie(tvb,
							offset + 2, info_element_len,
							ie_tree);
					}
					break;

				case CS0 | Q931_IE_USER_USER:
					if (q931_tree != NULL) {
						dissect_q931_user_user_ie(tvb,
							offset + 2, info_element_len,
							ie_tree);
					}
					break;

				default:
					if (q931_tree != NULL) {
						proto_tree_add_text(ie_tree, tvb,
							offset + 2, info_element_len,
							"Data: %s",
							bytes_to_str(
							  tvb_get_ptr(tvb, offset + 2,
								  info_element_len),
							  info_element_len));
					}
					break;
				}
			}
			offset += 1 + 1 + info_element_len;
		}
		codeset = locked_codeset;
	}
	if(have_valid_q931_pi) {
		tap_queue_packet(q931_tap, pinfo, q931_pi);
	}
	have_valid_q931_pi=FALSE;
}

/*
 * Q.931-over-TPKT-over-TCP.
 */
static gboolean
dissect_q931_tpkt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int lv_tpkt_len;

	/*
	 * Check whether this looks like a TPKT-encapsulated
	 * Q.931 packet.
	 *
	 * The minimum length of a Q.931 message is 3:
	 * 1 byte for the protocol discriminator,
	 * 1 for the call_reference length,
	 * and one for the message type.
	 */
	lv_tpkt_len = is_tpkt(tvb, 3);
	if (lv_tpkt_len == -1) {
		/*
		 * It's not a TPKT packet; reject it.
		 */
		return FALSE;
	}

	/*
	 * If this segment is *exactly* the length of a TPKT header,
	 * we assume that, as it looks like a TPKT header, it
	 * is one, and that the code put a TPKT header in one
	 * segment and the rest of the PDU in another.
	 */
	if (tvb_length(tvb) == 4) {
		/*
		 * It is - call the "dissect TPKT over a TCP stream"
		 * routine.
		 */
		dissect_tpkt_encap(tvb, pinfo, tree, q931_desegment,
		    q931_tpkt_pdu_handle);
		return TRUE;
	}

	/*
	 * Well, we have more data than just the TPKT header;
	 * check whether it looks like the beginning of a
	 * Q.931 message.
	 *
	 * The minimum length of a Q.931 message is 3, as per the
	 * above.
	 *
	 * Check that we have that many bytes past the TPKT header in
	 * the tvbuff; we already know that the TPKT header says we
	 * have that many bytes (as we passed 3 as the "min_len" argument
	 * to "is_tpkt()").
	 */
	if (!tvb_bytes_exist(tvb, 4, 3))
		return FALSE;

	/* Check the protocol discriminator */
	if (tvb_get_guint8(tvb, 4) != NLPID_Q_931) {
		/* Doesn't look like Q.931 inside TPKT */
		return FALSE;
	}

	/*
	 * OK, it looks like Q.931-over-TPKT.
	 * Call the "dissect TPKT over a TCP stream" routine.
	 */
	dissect_tpkt_encap(tvb, pinfo, tree, q931_desegment,
	    q931_tpkt_pdu_handle);

	return TRUE;
}

static void
dissect_q931_tpkt_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_q931_pdu(tvb, pinfo, tree, TRUE);
}

static void
dissect_q931(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_q931_pdu(tvb, pinfo, tree, FALSE);
}

static void
dissect_q931_ie_cs0(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_q931_IEs(tvb, pinfo, NULL, tree, FALSE, 0, 0);
}

static void
dissect_q931_ie_cs7(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_q931_IEs(tvb, pinfo, NULL, tree, FALSE, 0, 7);
}

static void 
q931_init(void) {
	/* Initialize the fragment and reassembly tables */
	fragment_table_init(&q931_fragment_table);
	reassembled_table_init(&q931_reassembled_table);
}

void
proto_register_q931(void)
{
	static hf_register_info hf[] = {
		{ &hf_q931_discriminator,
		  { "Protocol discriminator", "q931.disc", FT_UINT8, BASE_HEX, NULL, 0x0,
			"", HFILL }},

		{ &hf_q931_call_ref_len,
		  { "Call reference value length", "q931.call_ref_len", FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_q931_call_ref_flag,
		  { "Call reference flag", "q931.call_ref_flag", FT_BOOLEAN, BASE_NONE, TFS(&tfs_call_ref_flag), 0x0,
			"", HFILL }},

		{ &hf_q931_call_ref,
		  { "Call reference value", "q931.call_ref", FT_BYTES, BASE_HEX, NULL, 0x0,
			"", HFILL }},

		{ &hf_q931_message_type,
		  { "Message type", "q931.message_type", FT_UINT8, BASE_HEX, VALS(q931_message_type_vals), 0x0,
			"", HFILL }},

		{ &hf_q931_segment_type,
		  { "Segmented message type", "q931.segment_type", FT_UINT8, BASE_HEX, VALS(q931_message_type_vals), 0x0,
			"", HFILL }},

		{ &hf_q931_coding_standard,
		  { "Coding standard", "q931.coding_standard", FT_UINT8, BASE_HEX,
			 VALS(q931_coding_standard_vals), 0x60,"", HFILL }},

		{ &hf_q931_information_transfer_capability,
		  { "Information transfer capability", "q931.information_transfer_capability", FT_UINT8, BASE_HEX,
			 VALS(q931_information_transfer_capability_vals), 0x1f,"", HFILL }},

		{ &hf_q931_transfer_mode,
		  { "Transfer mode", "q931.transfer_mode", FT_UINT8, BASE_HEX,
			 VALS(q931_transfer_mode_vals), 0x60,"", HFILL }},

		{ &hf_q931_information_transfer_rate,
		  { "Information transfer rate", "q931.information_transfer_rate", FT_UINT8, BASE_HEX,
			 VALS(q931_information_transfer_rate_vals), 0x1f,"", HFILL }},

		{ &hf_q931_uil1,
		  { "User information layer 1 protocol", "q931.uil1", FT_UINT8, BASE_HEX,
			 VALS(q931_uil1_vals), 0x1f,"", HFILL }},

		{ &hf_q931_cause_location,
		  { "Cause location", "q931.cause_location", FT_UINT8, BASE_DEC, VALS(q931_cause_location_vals), 0x0f,
			"", HFILL }},

		{ &hf_q931_cause_value,
		  { "Cause value", "q931.cause_value", FT_UINT8, BASE_DEC, VALS(q931_cause_code_vals), 0x7f,
			"", HFILL }},

		{ &hf_q931_number_type,
		  { "Number type", "q931.number_type", FT_UINT8, BASE_HEX, VALS(q931_number_type_vals), 0x70,
			"", HFILL }},

		{ &hf_q931_numbering_plan,
		  { "Numbering plan", "q931.numbering_plan", FT_UINT8, BASE_HEX, VALS(q931_numbering_plan_vals), 0x0f,
			"", HFILL }},

		{ &hf_q931_screening_ind,
		  { "Screening indicator", "q931.screening_ind", FT_UINT8, BASE_HEX, VALS(q931_screening_indicator_vals), 0x03,
			"", HFILL }},

		{ &hf_q931_presentation_ind,
		  { "Presentation indicator", "q931.presentation_ind", FT_UINT8, BASE_HEX, VALS(q931_presentation_indicator_vals), 0x60,
			"", HFILL }},

		{ &hf_q931_extension_ind,
		  { "Extension indicator",  "q931.extension_ind",
			FT_BOOLEAN, 8, TFS(&q931_extension_ind_value), 0x80,
			"", HFILL }},

		{ &hf_q931_calling_party_number,
		  { "Calling party number digits", "q931.calling_party_number.digits", FT_STRING, BASE_NONE, NULL, 0x0,
			"", HFILL }},

		{ &hf_q931_called_party_number,
		  { "Called party number digits", "q931.called_party_number.digits", FT_STRING, BASE_NONE, NULL, 0x0,
			"", HFILL }},

		{ &hf_q931_connected_number,
		  { "Connected party number digits", "q931.connected_number.digits", FT_STRING, BASE_NONE, NULL, 0x0,
			"", HFILL }},

		{ &hf_q931_redirecting_number,
		  { "Redirecting party number digits", "q931.redirecting_number.digits", FT_STRING, BASE_NONE, NULL, 0x0,
			"", HFILL }},

    /* fields for channel identification IE */
		/* 0x80 is the extension bit */

		{ &hf_q931_channel_interface_explicit,
		  { "Interface identifier present", "q931.channel.interface_id_present", FT_BOOLEAN, 8, NULL, 0x40,
		    "True if the interface identifier is explicit in the following octets", HFILL }},

		{ &hf_q931_channel_interface_type,
		  { "Interface type", "q931.channel.interface_type", FT_BOOLEAN, 8, &tfs_interface_type, 0x20,
		    "Identifies the ISDN interface type", HFILL }},

		/* 0x10 is spare */
                
		{ &hf_q931_channel_exclusive,
		  { "Indicated channel is exclusive", "q931.channel.exclusive", FT_BOOLEAN, 8, &tfs_channel_exclusive, 0x08,
		    "True if only the indicated channel is acceptable", HFILL }},

		{ &hf_q931_channel_dchan,
		  { "D-channel indicator", "q931.channel.dchan", FT_BOOLEAN, 8, NULL, 0x04,
		    "True if the identified channel is the D-Channel", HFILL }},

		{ &hf_q931_channel_selection_bri,
		  { "Information channel selection", "q931.channel.selection", FT_UINT8, BASE_HEX, q931_basic_channel_selection_vals, 0x03,
		    "Identifies the information channel to be used", HFILL }},

		{ &hf_q931_channel_selection_pri,
		  { "Information channel selection", "q931.channel.selection", FT_UINT8, BASE_HEX, q931_not_basic_channel_selection_vals, 0x03,
		    "Identifies the information channel to be used", HFILL }},

		{ &hf_q931_channel_map,
		  { "Number/map", "q931.channel.map", FT_BOOLEAN, 8, &tfs_channel_map, 0x10,
		    "True if channel is indicates by channel map rather than number", HFILL }},
                
		{ &hf_q931_channel_element_type,
		  { "Element type", "q931.channel.element_type", FT_UINT8, BASE_HEX, q931_element_type_vals, 0xF,
		    "Type of element in the channel number/slot map octets", HFILL }},

		{ &hf_q931_channel_number,
		  { "Channel number", "q931.channel.number", FT_UINT8, BASE_DEC, NULL, 0x7F,
		    "Channel number", HFILL }},
               
    /* desegmentation fields */
		{ &hf_q931_segment_overlap,
		  { "Segment overlap", "q931.segment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"Fragment overlaps with other fragments", HFILL }},

		{ &hf_q931_segment_overlap_conflict,
		  { "Conflicting data in fragment overlap", "q931.segment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"Overlapping fragments contained conflicting data", HFILL }},

		{ &hf_q931_segment_multiple_tails,
		  { "Multiple tail fragments found", "q931.segment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"Several tails were found when defragmenting the packet", HFILL }},

		{ &hf_q931_segment_too_long_segment,
		  { "Segment too long", "q931.segment.toolongfragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"Segment contained data past end of packet", HFILL }},

		{ &hf_q931_segment_error,
		  { "Defragmentation error", "q931.segment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			"Defragmentation error due to illegal fragments", HFILL }},

		{ &hf_q931_segment,
		  { "Q.931 Segment", "q931.segment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			"Q.931 Segment", HFILL }},

		{ &hf_q931_segments,
		  { "Q.931 Segments", "q931.segments", FT_NONE, BASE_NONE, NULL, 0x0,
			"Q.931 Segments", HFILL }},

		{ &hf_q931_reassembled_in,
		  { "Reassembled Q.931 in frame", "q931.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			"This Q.931 message is reassembled in this frame", HFILL}}, 
	};
	static gint *ett[] = {
		&ett_q931,
		&ett_q931_ie,
		&ett_q931_segments,
		&ett_q931_segment,
	};
	module_t *q931_module;

	proto_q931 = proto_register_protocol("Q.931", "Q.931", "q931");
	proto_register_field_array (proto_q931, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_init_routine(q931_init);

	register_dissector("q931", dissect_q931, proto_q931);
	q931_tpkt_pdu_handle = create_dissector_handle(dissect_q931_tpkt_pdu,
	    proto_q931);
	register_dissector("q931.ie", dissect_q931_ie_cs0, proto_q931);
	register_dissector("q931.ie.cs7", dissect_q931_ie_cs7, proto_q931);

 	/* subdissector code */	
 	codeset_dissector_table = register_dissector_table("q931.codeset", "Q.931 Codeset", FT_UINT8, BASE_HEX);
 	ie_dissector_table = register_dissector_table("q931.ie", "Q.931 IE", FT_UINT16, BASE_HEX);

	q931_module = prefs_register_protocol(proto_q931, NULL);
	prefs_register_bool_preference(q931_module, "desegment_h323_messages",
	    "Reassemble Q.931 messages spanning multiple TCP segments",
	    "Whether the Q.931 dissector should reassemble messages spanning multiple TCP segments."
	    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
	    &q931_desegment);
	prefs_register_bool_preference(q931_module, "reassembly",
	    "Reassemble segmented Q.931 messages",
	    "Reassemble segmented Q.931 messages (Q.931 - Annex H)",
	    &q931_reassembly);
       /* Register for tapping */
       q931_tap = register_tap("q931");
}

void
proto_reg_handoff_q931(void)
{
	dissector_handle_t q931_handle;

	q931_handle = find_dissector("q931");
	dissector_add("lapd.sapi", LAPD_SAPI_Q931, q931_handle);

	/*
	 * Attempt to get a handle for the H.225 dissector.
	 * If we can't, the handle we get is null, and we'll just
	 * dissect putatively-H.255 Call Signaling stuff as User
	 * Information.
	 */
	h225_handle = find_dissector("h225");

	/*
	 * For H.323.
	 */
	heur_dissector_add("tcp", dissect_q931_tpkt, proto_q931);
}

static void reset_q931_packet_info(q931_packet_info *pi)
{
    if(pi == NULL) {
        return;
    }

    pi->calling_number = NULL;
    pi->called_number = NULL;
    pi->cause_value = 0xFF;
    pi->crv = -1;
}
