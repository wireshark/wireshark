/* packet-q933.c
 * Routines for Q.933 frame disassembly
 * Guy Harris <guy@alum.mit.edu>
 *
 * $Id$
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/nlpid.h>

static int proto_q933 					= -1;
static int hf_q933_discriminator			= -1;
static int hf_q933_coding_standard			= -1;
static int hf_q933_information_transfer_capability	= -1;
static int hf_q933_transfer_mode			= -1;
static int hf_q933_uil1					= -1;
static int hf_q933_call_ref_len 			= -1;
static int hf_q933_call_ref_flag 			= -1;
static int hf_q933_call_ref 				= -1;
static int hf_q933_message_type 			= -1;
static int hf_q933_cause_location			= -1;
static int hf_q933_cause_value 				= -1;
static int hf_q933_number_type				= -1;
static int hf_q933_numbering_plan			= -1;
static int hf_q933_extension_ind			= -1;
static int hf_q933_calling_party_number 		= -1;
static int hf_q933_called_party_number 			= -1;
static int hf_q933_connected_number 			= -1;
static int hf_q933_redirecting_number 			= -1;
static int hf_q933_screening_ind				= -1;
static int hf_q933_presentation_ind				= -1;
static int hf_q933_report_type				= -1;
static int hf_q933_link_verf_txseq		       	= -1;
static int hf_q933_link_verf_rxseq		       	= -1;

static gint ett_q933 					= -1;
static gint ett_q933_ie 				= -1;

/*
 * Q.933 message types.
 */
#define	Q933_ESCAPE		0x00
#define	Q933_ALERTING		0x01
#define	Q933_CALL_PROCEEDING	0x02
#define	Q933_CONNECT		0x07
#define	Q933_CONNECT_ACK	0x0F
#define	Q933_PROGRESS		0x03
#define	Q933_SETUP		0x05
#define	Q933_DISCONNECT		0x45
#define	Q933_RELEASE		0x4D
#define	Q933_RELEASE_COMPLETE	0x5A
#define	Q933_SEGMENT		0x60
#define	Q933_STATUS		0x7D
#define	Q933_STATUS_ENQUIRY	0x75

static const value_string q933_message_type_vals[] = {
	{ Q933_ESCAPE,			"ESCAPE" },
	{ Q933_ALERTING,		"ALERTING" },
	{ Q933_CALL_PROCEEDING,		"CALL PROCEEDING" },
	{ Q933_CONNECT,			"CONNECT" },
	{ Q933_CONNECT_ACK,		"CONNECT ACKNOWLEDGE" },
	{ Q933_PROGRESS,		"PROGRESS" },
	{ Q933_SETUP,			"SETUP" },
	{ Q933_DISCONNECT,		"DISCONNECT" },
	{ Q933_RELEASE,			"RELEASE" },
	{ Q933_RELEASE_COMPLETE,	"RELEASE COMPLETE" },
	{ Q933_SEGMENT,			"SEGMENT" },
	{ Q933_STATUS,			"STATUS" },
	{ Q933_STATUS_ENQUIRY,		"STATUS ENQUIRY" },
	{ 0,				NULL }
};

static const true_false_string tfs_call_ref_flag = {
	"Message sent to originating side",
	"Message sent from originating side"
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

#define	Q933_IE_SO_MASK	0x80	/* single-octet/variable-length mask */
/*
 * Single-octet IEs.
 */
#define	Q933_IE_SO_IDENTIFIER_MASK	0xf0	/* IE identifier mask */
#define	Q933_IE_SO_IDENTIFIER_SHIFT	4	/* IE identifier shift */
#define	Q933_IE_SO_IE_MASK		0x0F	/* IE mask */

#define	Q933_IE_SHIFT			0x90
#define	Q933_IE_SHIFT_NON_LOCKING	0x08	/* non-locking shift */
#define	Q933_IE_SHIFT_CODESET		0x07	/* codeset */

#define	Q933_IE_REPEAT_INDICATOR	0xD0

/*
 * Variable-length IEs.
 */
#define	Q933_IE_VL_EXTENSION		0x80	/* Extension flag */
/*	extension bit. The bit value "0" indicates that the octet continues through the		*/
/*	next octet. The bit value "1" indicates that this octet is the last octet		*/

static const true_false_string q933_extension_ind_value = {
  "last octet",
  "information continues through the next octet",

};


/*
 * Codeset 0 (default).
 */
#define	Q933_IE_SEGMENTED_MESSAGE	0x00
#define	Q933_IE_BEARER_CAPABILITY	0x04
#define	Q933_IE_CAUSE			0x08
#define	Q933_IE_CALL_STATE		0x14
#define	Q933_IE_CHANNEL_IDENTIFICATION	0x18
#define	Q933_IE_DLCI			0x19
#define	Q933_IE_PROGRESS_INDICATOR	0x1E
#define	Q933_IE_NETWORK_SPECIFIC_FACIL	0x20	/* Network Specific Facilities */
#define	Q933_IE_DISPLAY			0x28
#define	Q933_IE_E2E_TRANSIT_DELAY	0x42	/* End-to-end Transit Delay */
#define	Q933_IE_TD_SELECTION_AND_INT	0x43	/* Transit Delay Selection and Indication */
#define	Q933_IE_PL_BINARY_PARAMETERS	0x44	/* Packet layer binary parameters */
#define	Q933_IE_LL_CORE_PARAMETERS	0x48	/* Link layer core parameters */
#define	Q933_IE_LL_PROTOCOL_PARAMETERS	0x49	/* Link layer protocol parameters */
#define	Q933_IE_REVERSE_CHARGE_IND	0x4A	/* Reverse charging indication */
#define	Q933_IE_CONNECTED_NUMBER	0x4C	/* Connected Number */
#define	Q933_IE_CONNECTED_SUBADDR	0x4D	/* Connected sub-address */
#define	Q933_IE_X_213_PRIORITY		0x50	/* X.213 priority */
#define	Q933_IE_REPORT_TYPE		0x51
#define	Q933_IE_LINK_INTEGRITY_VERF	0x53	/* Link integrity verification */
#define	Q933_IE_PVC_STATUS		0x57
#define	Q933_IE_CALLING_PARTY_NUMBER	0x6C	/* Calling Party Number */
#define	Q933_IE_CALLING_PARTY_SUBADDR	0x6D	/* Calling Party Subaddress */
#define	Q933_IE_CALLED_PARTY_NUMBER	0x70	/* Called Party Number */
#define	Q933_IE_CALLED_PARTY_SUBADDR	0x71	/* Called Party Subaddress */
#define	Q933_IE_TRANSIT_NETWORK_SEL	0x78	/* Transit Network Selection */
#define	Q933_IE_LOW_LAYER_COMPAT	0x7C	/* Low-Layer Compatibility */
#define	Q933_IE_HIGH_LAYER_COMPAT	0x7D	/* High-Layer Compatibility */
#define	Q933_IE_USER_USER		0x7E	/* User-User */
#define	Q933_IE_ESCAPE			0x7F	/* Escape for extension */

/* Codeset 0 */
static const value_string q933_info_element_vals0[] = {
	{ Q933_IE_SEGMENTED_MESSAGE,		"Segmented message" },
	{ Q933_IE_BEARER_CAPABILITY,		"Bearer capability" },
	{ Q933_IE_CAUSE,			"Cause" },
	{ Q933_IE_CALL_STATE,			"Call state" },
	{ Q933_IE_CHANNEL_IDENTIFICATION,	"Channel identification" },
	{ Q933_IE_DLCI,				"Data link connection identifier" },
	{ Q933_IE_PROGRESS_INDICATOR,		"Progress indicator" },
	{ Q933_IE_NETWORK_SPECIFIC_FACIL,	"Network specific facilities" },
	{ Q933_IE_E2E_TRANSIT_DELAY,		"End-to-end transit delay" },
	{ Q933_IE_TD_SELECTION_AND_INT,		"Transit delay selection and indication" },
	{ Q933_IE_PL_BINARY_PARAMETERS,		"Packet layer binary parameters" },
	{ Q933_IE_LL_CORE_PARAMETERS,		"Link layer core parameters" },
	{ Q933_IE_LL_PROTOCOL_PARAMETERS,	"Link layer protocol parameters" },
	{ Q933_IE_REVERSE_CHARGE_IND,		"Reverse charging indication" },
	{ Q933_IE_CONNECTED_NUMBER,		"Connected number" },
	{ Q933_IE_CONNECTED_SUBADDR,		"Connected subaddress" },
	{ Q933_IE_X_213_PRIORITY,		"X.213 priority" },
	{ Q933_IE_REPORT_TYPE,			"Report type" },
	{ Q933_IE_LINK_INTEGRITY_VERF,		"Link integrity verification" },
	{ Q933_IE_PVC_STATUS,			"PVC status" },
	{ Q933_IE_CALLING_PARTY_NUMBER,		"Calling party number" },
	{ Q933_IE_CALLING_PARTY_SUBADDR,	"Calling party subaddress" },
	{ Q933_IE_CALLED_PARTY_NUMBER,		"Called party number" },
	{ Q933_IE_CALLED_PARTY_SUBADDR,		"Called party subaddress" },
	{ Q933_IE_TRANSIT_NETWORK_SEL,		"Transit network selection" },
	{ Q933_IE_LOW_LAYER_COMPAT,		"Low-layer compatibility" },
	{ Q933_IE_HIGH_LAYER_COMPAT,		"High-layer compatibility" },
	{ Q933_IE_USER_USER,			"User-user" },
	{ Q933_IE_ESCAPE,			"Escape" },
	{ 0,					NULL }
};
/* Codeset 1 */
static const value_string q933_info_element_vals1[] = {
	{ 0,					NULL }
};
/* Codeset 2 */
static const value_string q933_info_element_vals2[] = {
	{ 0,					NULL }
};
/* Codeset 3 */
static const value_string q933_info_element_vals3[] = {
	{ 0,					NULL }
};
/* Codeset 4 */
static const value_string q933_info_element_vals4[] = {
	{ 0,					NULL }
};

/* Codeset 5 */
#define Q933_IE_ANSI_REPORT_TYPE         0x01
#define Q933_IE_ANSI_LINK_INTEGRITY_VERF 0x03
#define Q933_IE_ANSI_PVC_STATUS          0x07

/* Codeset 5 */
static const value_string q933_info_element_vals5[] = {
        { Q933_IE_ANSI_REPORT_TYPE,             "Report type (ANSI)" },
        { Q933_IE_REPORT_TYPE,                  "Report type (CCITT)" },
        { Q933_IE_ANSI_LINK_INTEGRITY_VERF,     "Keep Alive (ANSI)" },
        { Q933_IE_LINK_INTEGRITY_VERF,          "Keep Alive (CCITT)" },
        { Q933_IE_ANSI_PVC_STATUS,              "PVC Status (ANSI)" },
        { Q933_IE_PVC_STATUS,                   "PVC Status (CCITT)" },
	{ 0,					NULL }
};
/* Codeset 6 */
static const value_string q933_info_element_vals6[] = {
	{ 0,					NULL }
};
/* Codeset 7 */
static const value_string q933_info_element_vals7[] = {
	{ 0,					NULL }
};

/* Codeset array */
#define NUM_INFO_ELEMENT_VALS	(Q933_IE_SHIFT_CODESET+1)
static const value_string *q933_info_element_vals[NUM_INFO_ELEMENT_VALS] = {
  q933_info_element_vals0,
  q933_info_element_vals1,
  q933_info_element_vals2,
  q933_info_element_vals3,
  q933_info_element_vals4,
  q933_info_element_vals5,
  q933_info_element_vals6,
  q933_info_element_vals7,
};

static const value_string q933_repeat_indication_vals[] = {
	{ 0x2, "Prioritized list" },
	{ 0,   NULL }
};

/*
 * ITU-standardized coding.
 */
#define	Q933_ITU_STANDARDIZED_CODING	0x00

/*
 * Dissect a Segmented message information element.
 */
static void
dissect_q933_segmented_message_ie(tvbuff_t *tvb, int offset, int len,
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
	proto_tree_add_text(tree, tvb, offset + 1, 1,
	    "Segmented message type: %u", tvb_get_guint8(tvb, offset + 1));
}

/*
 * Dissect a Bearer capability or Low-layer compatibility information element.
 */
static const value_string q933_coding_standard_vals[] = {
	{ 0x0, "ITU-T standardized coding" },
	{ 0x1, "ISO/IEC standard" },
	{ 0x2, "National standard" },
	{ 0x3, "Standard defined for this particular network" },
	{ 0,    NULL }
};

static const value_string q933_information_transfer_capability_vals[] = {
	{ 0x08, "Unrestricted digital information" },
	{ 0,    NULL }
};

static const value_string q933_transfer_mode_vals[] = {
	{ 0x01, "Frame mode" },
	{ 0,    NULL }
};

static const value_string q933_uil1_vals[] = {
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

static const value_string q933_l1_user_rate_vals[] = {
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

static const value_string q933_l1_stop_bits_vals[] = {
	{ 0x20, "1" },
	{ 0x40, "1.5" },
	{ 0x60, "2" },
	{ 0,    NULL }
};

static const value_string q933_l1_data_bits_vals[] = {
	{ 0x08, "5" },
	{ 0x10, "7" },
	{ 0x18, "8" },
	{ 0,    NULL }
};

static const value_string q933_l1_parity_vals[] = {
	{ 0x00, "Odd" },
	{ 0x02, "Even" },
	{ 0x03, "None" },
	{ 0x04, "Forced to 0" },
	{ 0x05, "Forced to 1" },
	{ 0,    NULL }
};

#define	Q933_UIL2_USER_SPEC	0x10

static const value_string q933_uil2_vals[] = {
	{ 0x01,			"Basic mode ISO 1745" },
	{ 0x06,			"X.25, link level" },
	{ 0x07,			"X.25 multilink" },
	{ 0x08,			"T.71 Extended LAPB" },
	{ 0x09,			"HDLC ARM" },
	{ 0x0A,			"HDLC NRM" },
	{ 0x0B,			"HDLC ABM" },
	{ 0x0C,			"ISO 8802/2 LLC" },
	{ 0x0D,			"X.75 Single Link Procedure" },
	{ 0x0E,			"Q.922" },
	{ 0x0F,			"Core aspects of Q.922" },
	{ Q933_UIL2_USER_SPEC,	"User-specified" },
	{ 0x11,			"ISO 7776 DTE-DTE operation" },
	{ 0,			NULL }
};

static const value_string q933_address_inclusion_vals[] = {
	{ 0x01,			"Address included" },
	{ 0x02,			"Encapsulation of logical control frame" },
	{ 0,			NULL }
};

static const value_string q933_mode_vals[] = {
	{ 0x20, "Normal mode" },
	{ 0x40, "Extended mode" },
	{ 0,    NULL }
};

#define	Q933_UIL3_X25_PL	0x06
#define	Q933_UIL3_ISO_8208	0x07	/* X.25-based */
#define	Q933_UIL3_X223		0x08	/* X.25-based */
#define	Q933_UIL3_TR_9577	0x0B
#define	Q933_UIL3_USER_SPEC	0x10

static const value_string q933_uil3_vals[] = {
	{ Q933_UIL3_X25_PL,	"X.25, packet layer" },
	{ Q933_UIL3_ISO_8208,	"ISO/IEC 8208" },
	{ Q933_UIL3_X223,	"X.223/ISO 8878" },
	{ 0x09,			"ISO/IEC 8473" },
	{ 0x0A,			"T.70" },
	{ Q933_UIL3_TR_9577,	"ISO/IEC TR 9577" },
	{ Q933_UIL3_USER_SPEC,	"User-specified" },
	{ 0,			NULL }
};

static void
dissect_q933_protocol_discriminator(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	unsigned int discriminator = tvb_get_guint8(tvb, offset);

	if (discriminator == NLPID_Q_933) {
		proto_tree_add_uint_format(tree, hf_q933_discriminator,
			 tvb, offset, 1, discriminator,
			 "Protocol discriminator: Q.933");
	} else if (discriminator == NLPID_Q_2931) {
		proto_tree_add_uint_format(tree, hf_q933_discriminator,
			 tvb, offset, 1, discriminator,
			 "Protocol discriminator: Q.2931");
	} else if ((discriminator >= 16 && discriminator < 63)
	    || ((discriminator >= 80) && (discriminator < 254))) {
		proto_tree_add_uint_format(tree, hf_q933_discriminator,
		    tvb, offset, 1, discriminator,
		    "Protocol discriminator: Network layer or layer 3 protocol (0x%02X)",
		    discriminator);
	} else if (discriminator >= 64 && discriminator <= 79) {
		proto_tree_add_uint_format(tree, hf_q933_discriminator,
		    tvb, offset, 1, discriminator,
		    "Protocol discriminator: National use (0x%02X)",
		    discriminator);
	} else {
		proto_tree_add_uint_format(tree, hf_q933_discriminator,
		    tvb, offset, 1, discriminator,
		    "Protocol discriminator: Reserved (0x%02X)",
		    discriminator);
	}
}

static void
dissect_q933_bearer_capability_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;
	guint8 coding_standard;
	guint8 modem_type;
	guint8 uil2_protocol;
	guint8 uil3_protocol;
	guint8 add_l3_info;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	coding_standard = octet & 0x60;
	if (coding_standard != Q933_ITU_STANDARDIZED_CODING) {
		/*
		 * We don't know how the bearer capability is encoded,
		 * so just dump it as data and be done with it.
		 */
		proto_tree_add_text(tree, tvb, offset,
		    len, "Data: %s",
		    tvb_bytes_to_str(tvb, offset, len));
		proto_tree_add_uint(tree, hf_q933_coding_standard, tvb, offset, 1, octet);
		proto_tree_add_boolean(tree, hf_q933_extension_ind, tvb, offset, 1, octet);
		return;
	}
	proto_tree_add_uint(tree, hf_q933_information_transfer_capability, tvb, offset, 1, octet);
	proto_tree_add_uint(tree, hf_q933_coding_standard, tvb, offset, 1, octet);
	proto_tree_add_boolean(tree, hf_q933_extension_ind, tvb, offset, 1, octet);
	offset += 1;
	len -= 1;

	/*
	 * XXX - only in Low-layer compatibility information element.
	 */
	if (!(octet & Q933_IE_VL_EXTENSION)) {
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
	proto_tree_add_uint(tree, hf_q933_transfer_mode, tvb, offset, 1, octet);
	proto_tree_add_boolean(tree, hf_q933_extension_ind, tvb, offset, 1, octet);
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	if ((octet & 0x60) == 0x20) {
		/*
		 * Layer 1 information.
		 */
		proto_tree_add_uint(tree, hf_q933_uil1, tvb, offset, 1, octet);
		proto_tree_add_boolean(tree, hf_q933_extension_ind, tvb, offset, 1, octet);
		offset += 1;
		len -= 1;

		if (octet & Q933_IE_VL_EXTENSION)
			goto l1_done;
		if (len == 0)
			return;
		octet = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Layer 1 is %s",
		    (octet & 0x40) ? "Asynchronous" : "Synchronous");
		proto_tree_add_text(tree, tvb, offset, 1,
		    "User rate: %s",
		    val_to_str(octet & 0x1F, q933_l1_user_rate_vals,
		      "Unknown (0x%02X)"));
		offset += 1;
		len -= 1;

		if (octet & Q933_IE_VL_EXTENSION)
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
		offset += 1;
		len -= 1;

		if (octet & Q933_IE_VL_EXTENSION)
			goto l1_done;
		if (len == 0)
			return;
		octet = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Stop bits: %s",
		      val_to_str(octet & 0x60, q933_l1_stop_bits_vals,
		       "Unknown (0x%X)"));
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Data bits: %s",
		      val_to_str(octet & 0x18, q933_l1_data_bits_vals,
		       "Unknown (0x%X)"));
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Parity: %s",
		      val_to_str(octet & 0x07, q933_l1_parity_vals,
		       "Unknown (0x%X)"));
		offset += 1;
		len -= 1;

		if (octet & Q933_IE_VL_EXTENSION)
			goto l1_done;
		if (len == 0)
			return;
		octet = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(tree, tvb, offset, 1,
		    "%s duplex",
		    (octet & 0x40) ? "Full" : "Half");
		modem_type = octet & 0x3F;
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Modem type: Network-specific rules 0x%02X", modem_type);
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
		    val_to_str(uil2_protocol, q933_uil2_vals,
		      "Unknown (0x%02X)"));
		offset += 1;
		len -= 1;

		/*
		 * XXX - only in Low-layer compatibility information element.
		 */
		if (octet & Q933_IE_VL_EXTENSION)
			goto l2_done;
		if (len == 0)
			return;
		octet = tvb_get_guint8(tvb, offset);
		if (uil2_protocol == Q933_UIL2_USER_SPEC) {
			proto_tree_add_text(tree, tvb, offset, 1,
			    "User-specified layer 2 protocol information: 0x%02X",
			    octet & 0x7F);
		} else {
			proto_tree_add_text(tree, tvb, offset, 1,
			    "Address inclusion: %s",
			    val_to_str(octet & 0x03, q933_address_inclusion_vals,
			      "Unknown (0x%02X)"));
		}
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
		    val_to_str(uil3_protocol, q933_uil3_vals,
		      "Unknown (0x%02X)"));
		offset += 1;
		len -= 1;


		/*
		 * XXX - only in Low-layer compatibility information element.
		 */
		if (octet & Q933_IE_VL_EXTENSION)
			goto l3_done;
		if (len == 0)
			return;
		octet = tvb_get_guint8(tvb, offset);
		switch (uil3_protocol) {

		case Q933_UIL3_X25_PL:
		case Q933_UIL3_ISO_8208:
		case Q933_UIL3_X223:
			proto_tree_add_text(tree, tvb, offset, 1,
			    "Mode: %s",
			    val_to_str(octet & 0x60, q933_mode_vals,
			      "Unknown (0x%02X)"));
			offset += 1;
			len -= 1;

			if (octet & Q933_IE_VL_EXTENSION)
				goto l3_done;
			if (len == 0)
				return;
			octet = tvb_get_guint8(tvb, offset);
			proto_tree_add_text(tree, tvb, offset, 1,
			    "Default packet size: %u", octet & 0x0F);
			offset += 1;
			len -= 1;

			if (octet & Q933_IE_VL_EXTENSION)
				goto l3_done;
			if (len == 0)
				return;
			octet = tvb_get_guint8(tvb, offset);
			proto_tree_add_text(tree, tvb, offset, 1,
			    "Packet window size: %u", octet & 0x7F);
			offset += 1;
			len -= 1;
			break;

		case Q933_UIL3_USER_SPEC:
			proto_tree_add_text(tree, tvb, offset, 1,
			    "Default packet size: %u octets",
			    1 << (octet & 0x0F));
			offset += 1;
			len -= 1;
			break;

		case Q933_UIL3_TR_9577:
			add_l3_info = (octet & 0x0F) << 4;
			if (octet & Q933_IE_VL_EXTENSION)
				goto l3_done;
#if 0 /* XXX: len is always >0 at this point; is field always 2 bytes (if not Q933_IE_VL_EXTENSION) ? */
			if (len == 0)
				return;
#endif
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


const value_string q933_cause_location_vals[] = {
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

static const value_string q933_cause_recommendation_vals[] = {
	{ 0x00, "Q.933" },
	{ 0x03, "X.21" },
	{ 0x04, "X.25" },
	{ 0x05, "Q.1031/Q.1051" },
	{ 0,    NULL }
};

/*
 * Cause codes for Cause.
 */
#define	Q933_CAUSE_UNALLOC_NUMBER	0x01
#define	Q933_CAUSE_NO_ROUTE_TO_DEST	0x03
#define	Q933_CAUSE_CALL_REJECTED	0x15
#define	Q933_CAUSE_NUMBER_CHANGED	0x16
#define	Q933_CAUSE_ACCESS_INFO_DISC	0x2B
#define	Q933_CAUSE_QOS_UNAVAILABLE	0x31
#define	Q933_CAUSE_CHAN_NONEXISTENT	0x52
#define	Q933_CAUSE_INCOMPATIBLE_DEST	0x58
#define	Q933_CAUSE_MAND_IE_MISSING	0x60
#define	Q933_CAUSE_MT_NONEX_OR_UNIMPL	0x61
#define	Q933_CAUSE_IE_NONEX_OR_UNIMPL	0x63
#define	Q933_CAUSE_INVALID_IE_CONTENTS	0x64
#define	Q933_CAUSE_MSG_INCOMPAT_W_CS	0x65
#define	Q933_CAUSE_REC_TIMER_EXP	0x66

const value_string q933_cause_code_vals[] = {
	{ 0x00,				"Valid cause code not yet received" },
	{ Q933_CAUSE_UNALLOC_NUMBER,	"Unallocated (unassigned) number" },
	{ 0x02,				"No route to specified transit network" },
	{ Q933_CAUSE_NO_ROUTE_TO_DEST,	"No route to destination" },
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
	{ Q933_CAUSE_CALL_REJECTED,	"Call rejected" },
	{ Q933_CAUSE_NUMBER_CHANGED,	"Number changed" },
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
	{ Q933_CAUSE_ACCESS_INFO_DISC,	"Access information discarded" },
	{ 0x2C,				"Requested circuit/channel not available" },
	{ 0x2D,				"Pre-empted" },
	{ 0x2E,				"Precedence call blocked" },
	{ 0x2F,				"Resources unavailable, unspecified" },
	{ Q933_CAUSE_QOS_UNAVAILABLE,	"Quality of service unavailable" },
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
	{ Q933_CAUSE_CHAN_NONEXISTENT,	"Identified channel does not exist" },
	{ 0x53,				"Call identity does not exist for suspended call" },
	{ 0x54,				"Call identity in use" },
	{ 0x55,				"No call suspended" },
	{ 0x56,				"Call having the requested call identity has been cleared" },
	{ 0x57,				"Called user not member of CUG" },
	{ Q933_CAUSE_INCOMPATIBLE_DEST,	"Incompatible destination" },
	{ 0x59,				"Non-existent abbreviated address entry" },
	{ 0x5A,				"Destination address missing, and direct call not subscribed" },
					/* Q.850 - "Non-existent CUG" */
	{ 0x5B,				"Invalid transit network selection (national use)" },
	{ 0x5C,				"Invalid facility parameter" },
	{ 0x5D,				"Mandatory information element is missing" },
	{ 0x5F,				"Invalid message, unspecified" },
	{ Q933_CAUSE_MAND_IE_MISSING,	"Mandatory information element is missing" },
	{ Q933_CAUSE_MT_NONEX_OR_UNIMPL,"Message type non-existent or not implemented" },
	{ 0x62,				"Message not compatible with call state or message type non-existent or not implemented" },
	{ Q933_CAUSE_IE_NONEX_OR_UNIMPL,"Information element non-existent or not implemented" },
	{ Q933_CAUSE_INVALID_IE_CONTENTS,"Invalid information element contents" },
	{ Q933_CAUSE_MSG_INCOMPAT_W_CS,	"Message not compatible with call state" },
	{ Q933_CAUSE_REC_TIMER_EXP,	"Recovery on timer expiry" },
	{ 0x67,				"Parameter non-existent or not implemented - passed on" },
	{ 0x6E,				"Message with unrecognized parameter discarded" },
	{ 0x6F,				"Protocol error, unspecified" },
	{ 0x7F,				"Internetworking, unspecified" },
	{ 0,				NULL }
};

static const value_string q933_cause_condition_vals[] = {
	{ 0x00, "Unknown" },
	{ 0x01, "Permanent" },
	{ 0x02, "Transient" },
	{ 0x00, NULL }
};

#define	Q933_REJ_USER_SPECIFIC		0x00
#define	Q933_REJ_IE_MISSING		0x04
#define	Q933_REJ_IE_INSUFFICIENT	0x08

static const value_string q933_rejection_reason_vals[] = {
	{ 0x00, "User specific" },
	{ 0x04, "Information element missing" },
	{ 0x08, "Information element contents are not sufficient" },
	{ 0x00, NULL }
};

static void
dissect_q933_cause_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree, int hf_cause_value)
{
	guint8 octet;
	guint8 cause_value;
	guint8 coding_standard;
	guint8 rejection_reason;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	coding_standard = octet & 0x60;
	if (coding_standard != Q933_ITU_STANDARDIZED_CODING) {
		/*
		 * We don't know how the cause is encoded,
		 * so just dump it as data and be done with it.
		 */
		proto_tree_add_uint(tree, hf_q933_coding_standard, tvb, offset, 1, octet);
		proto_tree_add_text(tree, tvb, offset,
		    len, "Data: %s",
		    tvb_bytes_to_str(tvb, offset, len));
		return;
	}
	proto_tree_add_uint(tree, hf_q933_cause_location, tvb, offset, 1, octet);
	proto_tree_add_uint(tree, hf_q933_coding_standard, tvb, offset, 1, octet);
	proto_tree_add_boolean(tree, hf_q933_extension_ind, tvb, offset, 1, octet);
	offset += 1;
	len -= 1;

	if (!(octet & Q933_IE_VL_EXTENSION)) {
		if (len == 0)
			return;
		octet = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Recommendation: %s",
		    val_to_str(octet & 0x7F, q933_cause_recommendation_vals,
		      "Unknown (0x%02X)"));
		proto_tree_add_boolean(tree, hf_q933_extension_ind, tvb, offset, 1, octet);
		offset += 1;
		len -= 1;
	}

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	cause_value = octet & 0x7F;
	proto_tree_add_uint(tree, hf_cause_value, tvb, offset, 1, cause_value);
	proto_tree_add_boolean(tree, hf_q933_extension_ind, tvb, offset, 1, octet);
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	switch (cause_value) {

	case Q933_CAUSE_UNALLOC_NUMBER:
	case Q933_CAUSE_NO_ROUTE_TO_DEST:
	case Q933_CAUSE_QOS_UNAVAILABLE:
		octet = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Network service: %s",
		    (octet & 0x80) ? "User" : "Provider");
		proto_tree_add_text(tree, tvb, offset, 1,
		    "%s",
		    (octet & 0x40) ? "Abnormal" : "Normal");
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Condition: %s",
		    val_to_str(octet & 0x03, q933_cause_condition_vals,
		      "Unknown (0x%X)"));
		break;

	case Q933_CAUSE_CALL_REJECTED:
		rejection_reason = octet & 0x7C;
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Rejection reason: %s",
		    val_to_str(octet & 0x7C, q933_rejection_reason_vals,
		      "Unknown (0x%X)"));
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Condition: %s",
		    val_to_str(octet & 0x03, q933_cause_condition_vals,
		      "Unknown (0x%X)"));
		offset += 1;
		len -= 1;

		if (len == 0)
			return;
		switch (rejection_reason) {

		case Q933_REJ_USER_SPECIFIC:
			proto_tree_add_text(tree, tvb, offset, len,
			    "User specific diagnostic: %s",
			    tvb_bytes_to_str(tvb, offset, len));
			break;

		case Q933_REJ_IE_MISSING:
			proto_tree_add_text(tree, tvb, offset, 1,
			    "Missing information element: %s",
			    val_to_str(tvb_get_guint8(tvb, offset), q933_info_element_vals0,
			      "Unknown (0x%02X)"));
			break;

		case Q933_REJ_IE_INSUFFICIENT:
			proto_tree_add_text(tree, tvb, offset, 1,
			    "Insufficient information element: %s",
			    val_to_str(tvb_get_guint8(tvb, offset), q933_info_element_vals0,
			      "Unknown (0x%02X)"));
			break;

		default:
			proto_tree_add_text(tree, tvb, offset, len,
			    "Diagnostic: %s",
			    tvb_bytes_to_str(tvb, offset, len));
			break;
		}
		break;

	case Q933_CAUSE_ACCESS_INFO_DISC:
	case Q933_CAUSE_INCOMPATIBLE_DEST:
	case Q933_CAUSE_MAND_IE_MISSING:
	case Q933_CAUSE_IE_NONEX_OR_UNIMPL:
	case Q933_CAUSE_INVALID_IE_CONTENTS:
		do {
			proto_tree_add_text(tree, tvb, offset, 1,
			    "Information element: %s",
			    val_to_str(tvb_get_guint8(tvb, offset), q933_info_element_vals0,
			      "Unknown (0x%02X)"));
			offset += 1;
			len -= 1;
		} while (len != 0);
		break;

	case Q933_CAUSE_MT_NONEX_OR_UNIMPL:
	case Q933_CAUSE_MSG_INCOMPAT_W_CS:
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Message type: %s",
		    val_to_str(tvb_get_guint8(tvb, offset), q933_message_type_vals,
		      "Unknown (0x%02X)"));
		break;

	case Q933_CAUSE_REC_TIMER_EXP:
		if (len < 3)
			return;
		proto_tree_add_text(tree, tvb, offset, 3,
		    "Timer: %.3s", tvb_get_ephemeral_string(tvb, offset, 3));
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
static const value_string q933_call_state_vals[] = {
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
dissect_q933_call_state_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;
	guint8 coding_standard;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	coding_standard = octet & 0x60;
	proto_tree_add_uint(tree, hf_q933_coding_standard, tvb, offset, 1, octet);
	if (coding_standard != Q933_ITU_STANDARDIZED_CODING) {
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
	    val_to_str(octet & 0x3F, q933_call_state_vals,
	      "Unknown (0x%02X)"));
}

/*
 * Dissect a Report Type information element.
 */
#define Q933_IE_REPORT_TYPE_FULL_STATUS 0x00
#define Q933_IE_REPORT_TYPE_LINK_VERIFY 0x01
#define Q933_IE_REPORT_TYPE_ASYNC_PVC_STATUS 0x02

static const value_string q933_report_type_vals[] = {
        { Q933_IE_REPORT_TYPE_FULL_STATUS, "Full Status" },
        { Q933_IE_REPORT_TYPE_LINK_VERIFY, "Link verify" },
        { Q933_IE_REPORT_TYPE_ASYNC_PVC_STATUS, "Async PVC Status" },
	{ 0,    NULL }
};

static void
dissect_q933_report_type_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint8 report_type;

	if (len == 0)
		return;

	report_type = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_q933_report_type, tvb, offset, 1, report_type);
}

/*
 * Dissect a Link Integrity Verification information element.
 */
static void
dissect_q933_link_integrity_verf_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint8 txseq,rxseq;

	if (len < 2)
		return;

	txseq = tvb_get_guint8(tvb, offset);
	rxseq = tvb_get_guint8(tvb, offset+1);

	proto_tree_add_uint(tree, hf_q933_link_verf_txseq, tvb, offset, 1, txseq);
	proto_tree_add_uint(tree, hf_q933_link_verf_rxseq, tvb, offset+1, 1, rxseq);

}

/*
 * Dissect a PVC status information element.
 */
static const value_string q933_pvc_status_vals[] = {
    {0x00, "Inactive"},
    {0x02, "Active"},
    {0x08, "New"},
    {0x0a, "New, Active"},
    {0, NULL}
};

static void
dissect_q933_pvc_status_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint32 dlci;
        guint8 dlci_status,dlci_len=2;

	if (len < 3)
		return;

        dlci = ((tvb_get_guint8(tvb, offset) & 0x3F) << 4) |
            ((tvb_get_guint8(tvb, offset+1) & 0x78) >> 3);

        /* first determine the DLCI field length */
        if (len == 4) {
            dlci = (dlci << 6) | ((tvb_get_guint8(tvb, offset+2) & 0x7E) >> 1);
            dlci_len++;
        } else if (len == 5) {
            dlci = (dlci << 13) | (tvb_get_guint8(tvb, offset+3) & 0x7F) |
                ((tvb_get_guint8(tvb, offset+4) & 0x7E) >> 1);
            dlci_len+=2;
        }
        dlci_status=tvb_get_guint8(tvb, offset+dlci_len)&0x0a;

	proto_tree_add_text(tree, tvb, offset, dlci_len, "DLCI: %u", dlci);
	proto_tree_add_text(tree, tvb, offset+dlci_len, 1, "Status: %s",
                            val_to_str(dlci_status, q933_pvc_status_vals, "Unknown"));
}

/*
 * Dissect a Channel identification information element.
 */
#define	Q933_INTERFACE_IDENTIFIED	0x40
#define	Q933_NOT_BASIC_CHANNEL		0x20

static const value_string q933_basic_channel_selection_vals[] = {
	{ 0x00, "No channel" },
	{ 0x01, "B1 channel" },
	{ 0x02, "B2 channel" },
	{ 0x03, "Any channel" },
	{ 0,    NULL }
};

static const value_string q933_not_basic_channel_selection_vals[] = {
	{ 0x00, "No channel" },
	{ 0x01, "Channel indicated in following octets" },
	{ 0x03, "Any channel" },
	{ 0,    NULL }
};

#define	Q933_IS_SLOT_MAP		0x10

static const value_string q933_element_type_vals[] = {
	{ 0x03, "B-channel units" },
	{ 0x06, "H0-channel units" },
	{ 0x08, "H11-channel units" },
	{ 0x09, "H12-channel units" },
	{ 0,    NULL }
};

static void
dissect_q933_channel_identification_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;
	int identifier_offset;
	int identifier_len;
	guint8 coding_standard;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 1,
	    "Interface %s identified",
	    (octet & Q933_INTERFACE_IDENTIFIED) ? "explicitly" : "implicitly");
	proto_tree_add_text(tree, tvb, offset, 1,
	    "%s interface",
	    (octet & Q933_NOT_BASIC_CHANNEL) ? "Not basic" : "Basic");
	proto_tree_add_text(tree, tvb, offset, 1,
	    "Indicated channel is %s",
	    (octet & 0x08) ? "required" : "preferred");
	proto_tree_add_text(tree, tvb, offset, 1,
	    "Indicated channel is %sthe D-channel",
	    (octet & 0x04) ? "" : "not ");
	if (octet & Q933_NOT_BASIC_CHANNEL) {
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Channel selection: %s",
		    val_to_str(octet & 0x03, q933_not_basic_channel_selection_vals,
		      "Unknown (0x%X)"));
	} else {
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Channel selection: %s",
		    val_to_str(octet & 0x03, q933_basic_channel_selection_vals,
		      "Unknown (0x%X)"));
	}
	offset += 1;
	len -= 1;

	if (octet & Q933_INTERFACE_IDENTIFIED) {
		identifier_offset = offset;
		identifier_len = 0;
		do {
			if (len == 0)
				break;
			octet = tvb_get_guint8(tvb, offset);
			offset += 1;
			len -= 1;
			identifier_len++;
		} while (!(octet & Q933_IE_VL_EXTENSION));

		/*
		 * XXX - do we want to strip off the 8th bit on the
		 * last octet of the interface identifier?
		 */
		if (identifier_len != 0) {
			proto_tree_add_text(tree, tvb, identifier_offset,
			    identifier_len, "Interface identifier: %s",
			    tvb_bytes_to_str(tvb, identifier_offset, identifier_len));
		}
	}

	if (octet & Q933_NOT_BASIC_CHANNEL) {
		if (len == 0)
			return;
		octet = tvb_get_guint8(tvb, offset);
		coding_standard = octet & 0x60;
		proto_tree_add_uint(tree, hf_q933_coding_standard, tvb, offset, 1, octet);
		if (coding_standard != Q933_ITU_STANDARDIZED_CODING) {
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
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Channel is indicated by %s",
		    (octet & Q933_IS_SLOT_MAP) ? "slot map" : "number");
		proto_tree_add_text(tree, tvb, offset, 1,
		    "%s type: %s",
		    (octet & Q933_IS_SLOT_MAP) ? "Map element" : "Channel",
		    val_to_str(octet & 0x0F, q933_element_type_vals,
		        "Unknown (0x%02X)"));

		/*
		 * XXX - dump the channel number or slot map.
		 */
	}
}

/*
 * Dissect a Progress indicator information element.
 */
static const value_string q933_progress_description_vals[] = {
	{ 0x01, "Call is not end-to-end ISDN - progress information available in-band" },
	{ 0x02, "Destination address is non-ISDN" },
	{ 0x03, "Origination address is non-ISDN" },
	{ 0x04, "Call has returned to the ISDN" },
	{ 0x05, "Interworking has occurred and has resulted in a telecommunications service change" },
	{ 0x08, "In-band information or an appropriate pattern is now available" },
	{ 0,    NULL }
};

static void
dissect_q933_progress_indicator_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;
	guint8 coding_standard;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	coding_standard = octet & 0x60;
	proto_tree_add_uint(tree, hf_q933_coding_standard, tvb, offset, 1, octet);
	if (coding_standard != Q933_ITU_STANDARDIZED_CODING) {
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
	    val_to_str(octet & 0x0F, q933_cause_location_vals,
	      "Unknown (0x%X)"));
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 1,
	    "Progress description: %s",
	    val_to_str(octet & 0x7F, q933_progress_description_vals,
	      "Unknown (0x%02X)"));
}

/*
 * Dissect a Network-specific facilities or Transit network selection
 * information element.
 */
static const value_string q933_netid_type_vals[] = {
	{ 0x00, "User specified" },
	{ 0x20, "National network identification" },
	{ 0x30, "International network identification" },
	{ 0,    NULL }
};

static const value_string q933_netid_plan_vals[] = {
	{ 0x00, "Unknown" },
	{ 0x01, "Carrier Identification Code" },
	{ 0x03, "X.121 data network identification code" },
	{ 0,    NULL }
};

static void
dissect_q933_ns_facilities_ie(tvbuff_t *tvb, int offset, int len,
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
		    val_to_str(octet & 0x70, q933_netid_type_vals,
		      "Unknown (0x%02X)"));
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Network identification plan: %s",
		    val_to_str(octet & 0x0F, q933_netid_plan_vals,
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

static int
dissect_q933_guint16_value(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree, const char *label)
{
	guint8 octet;
	guint16 value;
	int value_len;

	value_len = 0;

	octet = tvb_get_guint8(tvb, offset);
	if (octet & Q933_IE_VL_EXTENSION) {
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
	if (octet & Q933_IE_VL_EXTENSION) {
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
	if (!(octet & Q933_IE_VL_EXTENSION)) {
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
dissect_q933_e2e_transit_delay_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	int value_len;

	if (len == 0)
		return;
	value_len = dissect_q933_guint16_value(tvb, offset, len, tree,
	    "Cumulative transit delay");
	if (value_len < 0)
		return;	/* error */
	offset += value_len;
	len -= value_len;

	if (len == 0)
		return;
	value_len = dissect_q933_guint16_value(tvb, offset, len, tree,
	    "Requested end-to-end transit delay");
	if (value_len < 0)
		return;	/* error */
	offset += value_len;
	len -= value_len;

	if (len == 0)
		return;
	value_len = dissect_q933_guint16_value(tvb, offset, len, tree,
	    "Maximum end-to-end transit delay");
}

/*
 * Dissect a Transit delay selection and indication information element.
 */
static void
dissect_q933_td_selection_and_int_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	if (len == 0)
		return;
	dissect_q933_guint16_value(tvb, offset, len, tree,
	    "Transit delay");
}

static void
dissect_q933_pl_binary_parameters_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 1,
	    "%s",
	    (octet & 0x04) ? "No request/request denied" :
	    		     "Request indicated/request accepted");
	proto_tree_add_text(tree, tvb, offset, 1,
	    "%s confirmation",
	    (octet & 0x02) ? "Link-by-link" : "End-to-end");
}

/*
 * Dissect a Reverse charging indication information element.
 */
static const value_string q933_reverse_charging_indication_vals[] = {
	{ 0x01, "Reverse charging requested" },
	{ 0,    NULL }
};

static void
dissect_q933_reverse_charge_ind_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	if (len == 0)
		return;
	proto_tree_add_text(tree, tvb, offset, 1,
	    "Reverse charging indication: %s",
	    val_to_str(tvb_get_guint8(tvb, offset) & 0x07,
	      q933_reverse_charging_indication_vals, "Unknown (0x%02X)"));
}

/*
 * Dissect a (phone) number information element.
 */
static const value_string q933_number_type_vals[] = {
	{ 0x0, "Unknown" },
	{ 0x1, "International number" },
	{ 0x2, "National number" },
	{ 0x3, "Network specific number" },
	{ 0x4, "Subscriber number" },
	{ 0x6, "Abbreviated number" },
	{ 0,    NULL }
};

static const value_string q933_numbering_plan_vals[] = {
	{ 0x00, "Unknown" },
	{ 0x01, "E.164 ISDN/telephony numbering" },
	{ 0x03, "X.121 data numbering" },
	{ 0x04, "F.69 Telex numbering" },
	{ 0x08, "National standard numbering" },
	{ 0x09, "Private numbering" },
	{ 0,    NULL }
};

static const value_string q933_presentation_indicator_vals[] = {
	{ 0x00, "Presentation allowed" },
	{ 0x01, "Presentation restricted" },
	{ 0x02, "Number not available due to interworking" },
	{ 0,    NULL }
};

static const value_string q933_screening_indicator_vals[] = {
	{ 0x00, "User-provided, not screened" },
	{ 0x01, "User-provided, verified and passed" },
	{ 0x02, "User-provided, verified and failed" },
	{ 0x03, "Network-provided" },
	{ 0,    NULL }
};

static const value_string q933_redirection_reason_vals[] = {
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
dissect_q933_number_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree, int hfindex)
{
	guint8 octet;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_q933_numbering_plan, tvb, offset, 1, octet);
	proto_tree_add_uint(tree, hf_q933_number_type, tvb, offset, 1, octet);
	proto_tree_add_boolean(tree, hf_q933_extension_ind, tvb, offset, 1, octet);

	offset += 1;
	len -= 1;

	if (!(octet & Q933_IE_VL_EXTENSION)) {
		if (len == 0)
			return;
		octet = tvb_get_guint8(tvb, offset);
		proto_tree_add_uint(tree, hf_q933_screening_ind, tvb, offset, 1, octet);
		proto_tree_add_uint(tree, hf_q933_presentation_ind, tvb, offset, 1, octet);
		proto_tree_add_boolean(tree, hf_q933_extension_ind, tvb, offset, 1, octet);
		offset += 1;
		len -= 1;
	}

	/*
	 * XXX - only in a Redirecting number information element.
	 */
	if (!(octet & Q933_IE_VL_EXTENSION)) {
		if (len == 0)
			return;
		octet = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Reason for redirection: %s",
		    val_to_str(octet & 0x0F, q933_redirection_reason_vals,
		      "Unknown (0x%X)"));
		offset += 1;
		len -= 1;
	}

	if (len == 0)
		return;
	proto_tree_add_item(tree, hfindex, tvb, offset, len, FALSE);
}

/*
 * Dissect a party subaddress information element.
 */
static const value_string q933_subaddress_type_vals[] = {
	{ 0x00, "X.213/ISO 8348 Add.2 NSAP" },
	{ 0x20, "User-specified" },
	{ 0,    NULL }
};

static const value_string q933_odd_even_indicator_vals[] = {
	{ 0x00, "Even number of address signals" },
	{ 0x10, "Odd number of address signals" },
	{ 0,    NULL }
};

static void
dissect_q933_party_subaddr_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 1,
	    "Type of subaddress: %s",
	    val_to_str(octet & 0x70, q933_subaddress_type_vals,
	      "Unknown (0x%02X)"));
	proto_tree_add_text(tree, tvb, offset, 1,
	    "Odd/even indicator: %s",
	    val_to_str(octet & 0x10, q933_odd_even_indicator_vals,
	      "Unknown (0x%02X)"));
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	proto_tree_add_text(tree, tvb, offset, len, "Subaddress: %s",
	    tvb_bytes_to_str(tvb, offset, len));
}

/*
 * Dissect a High-layer compatibility information element.
 */
#define	Q933_AUDIOVISUAL	0x60
static const value_string q933_high_layer_characteristics_vals[] = {
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
	{ Q933_AUDIOVISUAL, "F.720/F.821 and F.731 Profile 1a videotelephony" },
	{ 0x61,             "F.702 and F.731 Profile 1b videoconferencing" },
	{ 0x62,             "F.702 and F.731 audiographic conferencing" },
	{ 0,                NULL }
};

static const value_string q933_audiovisual_characteristics_vals[] = {
	{ 0x01, "Capability set of initial channel of H.221" },
	{ 0x02, "Capability set of subsequent channel of H.221" },
	{ 0x21, "Capability set of initial channel of an active 3.1kHz audio or speech call" },
	{ 0x00, NULL }
};

static void
dissect_q933_high_layer_compat_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;
	guint8 coding_standard;
	guint8 characteristics;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	coding_standard = octet & 0x60;
	proto_tree_add_uint(tree, hf_q933_coding_standard, tvb, offset, 1, octet);
	offset += 1;
	len -= 1;
	if (coding_standard != Q933_ITU_STANDARDIZED_CODING) {
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
	    val_to_str(characteristics, q933_high_layer_characteristics_vals,
	     "Unknown (0x%02X)"));
	offset += 1;
	len -= 1;

	if (!(octet & Q933_IE_VL_EXTENSION)) {
		if (len == 0)
			return;
		octet = tvb_get_guint8(tvb, offset);
		if (characteristics == Q933_AUDIOVISUAL) {
			proto_tree_add_text(tree, tvb, offset, 1,
			    "Extended audiovisual characteristics identification: %s",
			    val_to_str(octet & 0x7F,
			      q933_audiovisual_characteristics_vals,
			      "Unknown (0x%02X)"));
		} else {
			proto_tree_add_text(tree, tvb, offset, 1,
			    "Extended high layer characteristics identification: %s",
			    val_to_str(octet & 0x7F,
			      q933_high_layer_characteristics_vals,
			      "Unknown (0x%02X)"));
		}
	}
}


/*
 * Dissect a User-user information element.
 */
#define	Q933_PROTOCOL_DISCRIMINATOR_IA5		0x04
#define Q933_PROTOCOL_DISCRIMINATOR_ASN1	0x05

static const value_string q933_protocol_discriminator_vals[] = {
	{ 0x00,					"User-specific protocol" },
	{ 0x01,					"OSI high layer protocols" },
	{ 0x02,					"X.244" },
	{ Q933_PROTOCOL_DISCRIMINATOR_IA5,	"IA5 characters" },
	{ Q933_PROTOCOL_DISCRIMINATOR_ASN1,	"X.208 and X.209 coded user information" },
	{ 0x07,					"V.120 rate adaption" },
	{ 0x08,					"Q.933/I.451 user-network call control messages" },
	{ 0,					NULL }
};

static void
dissect_q933_user_user_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 1,
	    "Protocol discriminator: %s",
	    val_to_str(octet, q933_protocol_discriminator_vals,
	    "Unknown (0x%02x)"));
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	switch (octet) {

	case Q933_PROTOCOL_DISCRIMINATOR_IA5:
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
dissect_q933_ia5_ie(tvbuff_t *tvb, int offset, int len, proto_tree *tree,
    const char *label)
{
	if (len != 0) {
		proto_tree_add_text(tree, tvb, offset, len, "%s: %s", label,
		    tvb_format_text(tvb, offset, len));
	}
}

static const value_string q933_codeset_vals[] = {
	{ 0x00, "Q.933 information elements" },
	{ 0x04, "Information elements for ISO/IEC use" },
	{ 0x05, "Information elements for national use" },
	{ 0x06, "Information elements specific to the local network" },
	{ 0x07, "User-specific information elements" },
	{ 0x00, NULL },
};

static void
dissect_q933(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int		offset = 0;
	proto_tree	*q933_tree = NULL;
	proto_item	*ti;
	proto_tree	*ie_tree = NULL;
	guint8		call_ref_len;
	guint8		call_ref[15];
	guint8		message_type;
	guint8		info_element;
	guint16		info_element_len;
	int		codeset, locked_codeset;
	gboolean	non_locking_shift;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Q.933");

	if (tree) {
		ti = proto_tree_add_item(tree, proto_q933, tvb, offset, -1,
		    ENC_NA);
		q933_tree = proto_item_add_subtree(ti, ett_q933);

		dissect_q933_protocol_discriminator(tvb, offset, q933_tree);
	}
	offset += 1;
	call_ref_len = tvb_get_guint8(tvb, offset) & 0xF;	/* XXX - do as a bit field? */
	if (q933_tree != NULL)
		proto_tree_add_uint(q933_tree, hf_q933_call_ref_len, tvb, offset, 1, call_ref_len);
	offset += 1;
	if (call_ref_len != 0) {
		tvb_memcpy(tvb, call_ref, offset, call_ref_len);
		if (q933_tree != NULL) {
			proto_tree_add_boolean(q933_tree, hf_q933_call_ref_flag,
			    tvb, offset, 1, (call_ref[0] & 0x80) != 0);
			call_ref[0] &= 0x7F;
			proto_tree_add_bytes(q933_tree, hf_q933_call_ref,
			    tvb, offset, call_ref_len, call_ref);
		}
		offset += call_ref_len;
	}
	message_type = tvb_get_guint8(tvb, offset);
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_str(pinfo->cinfo, COL_INFO,
		    val_to_str(message_type, q933_message_type_vals,
		      "Unknown message type (0x%02X)"));
	}
	if (q933_tree != NULL)
		proto_tree_add_uint(q933_tree, hf_q933_message_type, tvb, offset, 1, message_type);
	offset += 1;

	/*
	 * And now for the information elements....
	 */
	codeset = locked_codeset = 0;	/* start out in codeset 0 */
	non_locking_shift = TRUE;
	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		info_element = tvb_get_guint8(tvb, offset);

		 /* Check for the codeset shift */
		if ((info_element & Q933_IE_SO_MASK) &&
		    ((info_element & Q933_IE_SO_IDENTIFIER_MASK) == Q933_IE_SHIFT)) {
			non_locking_shift = info_element & Q933_IE_SHIFT_NON_LOCKING;
			codeset = info_element & Q933_IE_SHIFT_CODESET;
			if (!non_locking_shift)
				locked_codeset = codeset;
			if (q933_tree != NULL) {
				proto_tree_add_text(q933_tree, tvb, offset, 1,
				    "%s shift to codeset %u: %s",
				    (non_locking_shift ? "Non-locking" : "Locking"),
				    codeset,
				    val_to_str(codeset, q933_codeset_vals,
				      "Unknown (0x%02X)"));
			}
			offset += 1;
			continue;
		}

		/*
		 * Check for the single-octet IEs.
		 */
		if (info_element & Q933_IE_SO_MASK) {
			switch ((codeset << 8) | (info_element & Q933_IE_SO_IDENTIFIER_MASK)) {

			case CS0 | Q933_IE_REPEAT_INDICATOR:
				if (q933_tree != NULL) {
					proto_tree_add_text(q933_tree, tvb, offset, 1,
					    "Repeat indicator: %s",
					    val_to_str(info_element & Q933_IE_SO_IE_MASK,
				    	  q933_repeat_indication_vals,
					      "Unknown (0x%X)"));
				}
				break;

			default:
				if (q933_tree != NULL) {
					proto_tree_add_text(q933_tree, tvb, offset, 1,
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
		 */
		info_element_len = tvb_get_guint8(tvb, offset + 1);
		if (q933_tree != NULL) {
			ti = proto_tree_add_text(q933_tree, tvb, offset,
			    1+1+info_element_len, "%s",
			    val_to_str(info_element, q933_info_element_vals[codeset],
			      "Unknown information element (0x%02X)"));
				ie_tree = proto_item_add_subtree(ti, ett_q933_ie);
			proto_tree_add_text(ie_tree, tvb, offset, 1,
			    "Information element: %s",
			    val_to_str(info_element, q933_info_element_vals[codeset],
			      "Unknown (0x%02X)"));
			proto_tree_add_text(ie_tree, tvb, offset + 1, 1,
			    "Length: %u", info_element_len);

			switch ((codeset << 8) | info_element) {

			case CS0 | Q933_IE_SEGMENTED_MESSAGE:
				dissect_q933_segmented_message_ie(tvb,
				    offset + 2, info_element_len,
				    ie_tree);
				break;

			case CS0 | Q933_IE_BEARER_CAPABILITY:
			case CS0 | Q933_IE_LOW_LAYER_COMPAT:
				dissect_q933_bearer_capability_ie(tvb,
				    offset + 2, info_element_len,
				    ie_tree);
				break;

			case CS0 | Q933_IE_CAUSE:
				dissect_q933_cause_ie(tvb,
				    offset + 2, info_element_len,
				    ie_tree,
				    hf_q933_cause_value);
				break;

			case CS0 | Q933_IE_CALL_STATE:
				dissect_q933_call_state_ie(tvb,
				    offset + 2, info_element_len,
				    ie_tree);
				break;

			case CS0 | Q933_IE_CHANNEL_IDENTIFICATION:
				dissect_q933_channel_identification_ie(
				    tvb, offset + 2, info_element_len,
				    ie_tree);
				break;

			case CS0 | Q933_IE_PROGRESS_INDICATOR:
				dissect_q933_progress_indicator_ie(tvb,
				    offset + 2, info_element_len,
				    ie_tree);
				break;

			case CS0 | Q933_IE_NETWORK_SPECIFIC_FACIL:
			case CS0 | Q933_IE_TRANSIT_NETWORK_SEL:
				dissect_q933_ns_facilities_ie(tvb,
				    offset + 2, info_element_len,
				    ie_tree);
				break;

			case CS0 | Q933_IE_DISPLAY:
				dissect_q933_ia5_ie(tvb, offset + 2,
				    info_element_len, ie_tree,
				    "Display information");
				break;

			case CS0 | Q933_IE_E2E_TRANSIT_DELAY:
				dissect_q933_e2e_transit_delay_ie(tvb,
				    offset + 2, info_element_len,
				    ie_tree);
				break;

			case CS0 | Q933_IE_TD_SELECTION_AND_INT:
				dissect_q933_td_selection_and_int_ie(
				    tvb, offset + 2, info_element_len,
				    ie_tree);
				break;

			case CS0 | Q933_IE_PL_BINARY_PARAMETERS:
				dissect_q933_pl_binary_parameters_ie(
				    tvb, offset + 2, info_element_len,
				    ie_tree);
				break;

			case CS0 | Q933_IE_REVERSE_CHARGE_IND:
				dissect_q933_reverse_charge_ind_ie(tvb,
				    offset + 2, info_element_len,
				    ie_tree);
				break;

			case CS0 | Q933_IE_CALLING_PARTY_NUMBER:
				dissect_q933_number_ie(tvb,
				    offset + 2, info_element_len,
				    ie_tree,
				    hf_q933_calling_party_number);
				break;

			case CS0 | Q933_IE_CONNECTED_NUMBER:
				dissect_q933_number_ie(tvb,
				    offset + 2, info_element_len,
				    ie_tree,
				    hf_q933_connected_number);
				break;

			case CS0 | Q933_IE_CALLED_PARTY_NUMBER:
				dissect_q933_number_ie(tvb,
				    offset + 2, info_element_len,
				    ie_tree,
				    hf_q933_called_party_number);
				break;

			case CS0 | Q933_IE_CALLING_PARTY_SUBADDR:
			case CS0 | Q933_IE_CALLED_PARTY_SUBADDR:
				dissect_q933_party_subaddr_ie(tvb,
				    offset + 2, info_element_len,
				    ie_tree);
				break;

			case CS0 | Q933_IE_HIGH_LAYER_COMPAT:
				dissect_q933_high_layer_compat_ie(tvb,
				    offset + 2, info_element_len,
				    ie_tree);
				break;

			case CS0 | Q933_IE_USER_USER:
				dissect_q933_user_user_ie(tvb,
				    offset + 2, info_element_len,
				    ie_tree);
				break;


			case CS0 | Q933_IE_REPORT_TYPE:
			case CS5 | Q933_IE_REPORT_TYPE:
			case CS5 | Q933_IE_ANSI_REPORT_TYPE:
				dissect_q933_report_type_ie(tvb,
				    offset + 2, info_element_len,
				    ie_tree);
				break;

			case CS5 | Q933_IE_LINK_INTEGRITY_VERF:
			case CS5 | Q933_IE_ANSI_LINK_INTEGRITY_VERF:
                                dissect_q933_link_integrity_verf_ie(tvb,
				    offset + 2, info_element_len,
				    ie_tree);
				break;

			case CS5 | Q933_IE_PVC_STATUS:
			case CS5 | Q933_IE_ANSI_PVC_STATUS:
				dissect_q933_pvc_status_ie(tvb,
				    offset + 2, info_element_len,
				    ie_tree);
				break;

			default:
				proto_tree_add_text(ie_tree, tvb,
				    offset + 2, info_element_len,
				    "Data: %s",
				    tvb_bytes_to_str(tvb, offset + 2,
					  info_element_len));
				break;
			}
		}
		offset += 1 + 1 + info_element_len;
		codeset = locked_codeset;
	}
}

void
proto_register_q933(void)
{
	static hf_register_info hf[] = {
		{ &hf_q933_discriminator,
		  { "Protocol discriminator", "q933.disc", FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_q933_call_ref_flag,
		  { "Call reference flag", "q933.call_ref_flag", FT_BOOLEAN, BASE_NONE, TFS(&tfs_call_ref_flag), 0x0,
			NULL, HFILL }},

		{ &hf_q933_call_ref,
		  { "Call reference value", "q933.call_ref", FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},


		{ &hf_q933_coding_standard,
		  { "Coding standard", "q933.coding_standard", FT_UINT8, BASE_HEX,
			 VALS(q933_coding_standard_vals), 0x60,NULL, HFILL }},

		{ &hf_q933_information_transfer_capability,
		  { "Information transfer capability", "q933.information_transfer_capability", FT_UINT8, BASE_HEX,
			 VALS(q933_information_transfer_capability_vals), 0x1f,NULL, HFILL }},

		{ &hf_q933_transfer_mode,
		  { "Transfer mode", "q933.transfer_mode", FT_UINT8, BASE_HEX,
			 VALS(q933_transfer_mode_vals), 0x60,NULL, HFILL }},

		{ &hf_q933_uil1,
		  { "User information layer 1 protocol", "q933.uil1", FT_UINT8, BASE_HEX,
			 VALS(q933_uil1_vals), 0x1f,NULL, HFILL }},

		{ &hf_q933_call_ref_len,
		  { "Call reference value length", "q933.call_ref_len", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_q933_message_type,
		  { "Message type", "q933.message_type", FT_UINT8, BASE_HEX, VALS(q933_message_type_vals), 0x0,
			NULL, HFILL }},

		{ &hf_q933_cause_location,
		  { "Cause location", "q933.cause_location", FT_UINT8, BASE_DEC, VALS(q933_cause_location_vals), 0x0f,
			NULL, HFILL }},

		{ &hf_q933_cause_value,
		  { "Cause value", "q933.cause_value", FT_UINT8, BASE_DEC, VALS(q933_cause_code_vals), 0x7f,
			NULL, HFILL }},

		{ &hf_q933_number_type,
		  { "Number type", "q933.number_type", FT_UINT8, BASE_HEX, VALS(q933_number_type_vals), 0x70,
			NULL, HFILL }},

		{ &hf_q933_numbering_plan,
		  { "numbering plan", "q933.numbering_plan", FT_UINT8, BASE_HEX, VALS(q933_numbering_plan_vals), 0x0f,
			NULL, HFILL }},

		{ &hf_q933_screening_ind,
		  { "Screening indicator", "q933.screening_ind", FT_UINT8, BASE_HEX, VALS(q933_screening_indicator_vals), 0x03,
			NULL, HFILL }},

		{ &hf_q933_presentation_ind,
		  { "Presentation indicator", "q933.presentation_ind", FT_UINT8, BASE_HEX, VALS(q933_presentation_indicator_vals), 0x60,
			NULL, HFILL }},

		{ &hf_q933_extension_ind,
		  { "Extension indicator",  "q933.extension_ind",
			FT_BOOLEAN, 8, TFS(&q933_extension_ind_value), 0x80,
			NULL, HFILL }},

		{ &hf_q933_calling_party_number,
		  { "Calling party number digits", "q933.calling_party_number.digits", FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_q933_called_party_number,
		  { "Called party number digits", "q933.called_party_number.digits", FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_q933_connected_number,
		  { "Connected party number digits", "q933.connected_number.digits", FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_q933_redirecting_number,
		  { "Redirecting party number digits", "q933.redirecting_number.digits", FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_q933_report_type,
		  { "Report type", "q933.report_type", FT_UINT8, BASE_DEC, VALS(q933_report_type_vals), 0x0,
			NULL, HFILL }},
		{ &hf_q933_link_verf_txseq,
		  { "TX Sequence", "q933.link_verification.txseq", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_q933_link_verf_rxseq,
		  { "RX Sequence", "q933.link_verification.rxseq", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

	};
	static gint *ett[] = {
		&ett_q933,
		&ett_q933_ie,
	};

	proto_q933 = proto_register_protocol("Q.933", "Q.933", "q933");
	proto_register_field_array (proto_q933, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("q933", dissect_q933, proto_q933);
}

void
proto_reg_handoff_q933(void)
{
	dissector_handle_t q933_handle;

	q933_handle = find_dissector("q933");
	dissector_add_uint("fr.osinl", NLPID_Q_933, q933_handle);
}
