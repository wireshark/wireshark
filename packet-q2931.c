/* packet-q2931.c
 * Routines for Q.2931 frame disassembly
 * Guy Harris <guy@alum.mit.edu>
 *
 * $Id: packet-q2931.c,v 1.3 1999/11/25 22:52:20 guy Exp $
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
#include "packet-q931.h"

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
static int hf_q2931_message_flag = -1;
static int hf_q2931_message_action_indicator = -1;
static int hf_q2931_message_len = -1;

static gint ett_q2931 = -1;
static gint ett_q2931_ext = -1;
static gint ett_q2931_ie = -1;
static gint ett_q2931_ie_ext = -1;
static gint ett_q2931_nsap = -1;

static void dissect_q2931_ie(const u_char *pd, int offset, int len,
    proto_tree *tree, guint8 info_element, guint8 info_element_ext);

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
#define	Q2931_LEAF_SETUP_FAIL	0x90
#define	Q2931_LEAF_SETUP_REQ	0x91

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
	{ Q2931_LEAF_SETUP_FAIL,	"LEAF SETUP FAILURE" },
	{ Q2931_LEAF_SETUP_REQ,		"LEAF SETUP REQUEST" },
	{ 0,				NULL }
};

/*
 * Bits in the message type extension.
 */
#define	Q2931_MSG_TYPE_EXT_FOLLOW_INST	0x10	/* follow instructions in action indicator */
#define	Q2931_MSG_TYPE_EXT_ACTION_IND	0x03	/* said instructions */

static const true_false_string tos_msg_flag = {
	"Regular error handling procedures apply",
	"Follow explicit error handling instructions"
};

static const value_string msg_action_ind_vals[] = {
	{ 0x00, "Clear call" },
	{ 0x01, "Discard and ignore" },
	{ 0x02, "Discard and report status" },
	{ 0x00, NULL }
};

/*
 * Bits in the compatibility instruction indicator octet of an
 * information element.
 */
#define	Q2931_IE_COMPAT_CODING_STD	0x60	/* Coding standard */
#define	Q2931_IE_COMPAT_FOLLOW_INST	0x10	/* follow instructions in action indicator */
#define	Q2931_IE_COMPAT_ACTION_IND	0x07

/*
 * ITU-standardized coding.
 */
#define	Q2931_ITU_STANDARDIZED_CODING	0x00

static const value_string coding_std_vals[] = {
	{ 0x00, "ITU-T standardized coding" },
	{ 0x20, "ISO/IEC standard" },
	{ 0x40, "National standard" },
	{ 0x60, "Standard defined for the network" },
	{ 0,    NULL }
};

static const value_string ie_action_ind_vals[] = {
	{ 0x00, "Clear call" },
	{ 0x01, "Discard information element and proceed" },
	{ 0x02, "Discard information element, proceed, and report status" },
	{ 0x05, "Discard message, and ignore" },
	{ 0x06, "Discard message, and report status" },
	{ 0x00, NULL }
};

/*
 * Information elements.
 */
#define	Q2931_IE_EXTENSION		0x80	/* Extension flag */

#define	Q2931_IE_NBAND_BEARER_CAP	0x04	/* Narrowband bearer capability */
#define	Q2931_IE_CAUSE			0x08
#define	Q2931_IE_CALL_STATE		0x14
#define	Q2931_IE_PROGRESS_INDICATOR	0x1E
#define	Q2931_IE_NOTIFICATION_INDICATOR	0x27
#define	Q2931_IE_E2E_TRANSIT_DELAY	0x42	/* End-to-end Transit Delay */
#define	Q2931_IE_ENDPOINT_REFERENCE	0x54
#define	Q2931_IE_ENDPOINT_STATE		0x55
#define	Q2931_IE_AAL_PARAMETERS		0x58	/* ATM adaptation layer parameters */
#define	Q2931_IE_ATM_USER_CELL_RATE	0x59	/* ATM traffic descriptor */
#define	Q2931_IE_CONNECTION_IDENTIFIER	0x5A
#define	Q2931_IE_OAM_TRAFFIC_DESCRIPTOR	0x5B
#define	Q2931_IE_QOS_PARAMETER		0x5C	/* Quality of Service parameter */
#define	Q2931_IE_BBAND_HI_LAYER_INFO	0x5D	/* Broadband high-layer information */
#define	Q2931_IE_BBAND_BEARER_CAP	0x5E	/* Broadband bearer capability */
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
#define	Q2931_IE_NBAND_LOW_LAYER_COMPAT	0x7C	/* Narrowband Low-Layer Compatibility */
#define	Q2931_IE_NBAND_HIGH_LAYER_COMPAT 0x7D	/* Narrowband High-Layer Compatibility */
#define	Q2931_IE_GENERIC_IDENT_TRANSPORT 0x7F	/* Generic identifier transport */

static const value_string q2931_info_element_vals[] = {
	{ Q2931_IE_NBAND_BEARER_CAP,		"Narrowband bearer capability" },
	{ Q2931_IE_CAUSE,			"Cause" },
	{ Q2931_IE_CALL_STATE,			"Call state" },
	{ Q2931_IE_PROGRESS_INDICATOR,		"Progress indicator" },
	{ Q2931_IE_NOTIFICATION_INDICATOR,	"Notification indicator" },
	{ Q2931_IE_E2E_TRANSIT_DELAY,		"End-to-end transit delay" },
	{ Q2931_IE_ENDPOINT_REFERENCE,		"Endpoint reference" },
	{ Q2931_IE_ENDPOINT_STATE,		"Endpoint state" },
	{ Q2931_IE_AAL_PARAMETERS,		"AAL parameters" },
	{ Q2931_IE_ATM_USER_CELL_RATE,		"ATM user cell rate" },
	{ Q2931_IE_CONNECTION_IDENTIFIER,	"Connection identifier" },
	{ Q2931_IE_OAM_TRAFFIC_DESCRIPTOR,	"OAM traffic descriptor" },
	{ Q2931_IE_QOS_PARAMETER,		"Quality of service parameter" },
	{ Q2931_IE_BBAND_HI_LAYER_INFO,		"Broadband high-layer information" },
	{ Q2931_IE_BBAND_BEARER_CAP,		"Broadband bearer capability" },
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
	{ Q2931_IE_NBAND_LOW_LAYER_COMPAT,	"Narrowband low-layer compatibility" },
	{ Q2931_IE_NBAND_HIGH_LAYER_COMPAT,	"Narrowband high-layer compatibility" },
	{ Q2931_IE_GENERIC_IDENT_TRANSPORT,	"Generic identifier transport" },
	{ 0,					NULL }
};

/*
 * Dissect a locking or non-locking shift information element.
 */
static const value_string q2931_codeset_vals[] = {
	{ 0x00, "Q.2931 information elements" },
	{ 0x04, "Information elements for ISO/IEC use" },
	{ 0x05, "Information elements for national use" },
	{ 0x06, "Information elements specific to the local network" },
	{ 0x07, "User-specific information elements" },
	{ 0x00, NULL },
};

static void
dissect_q2931_shift_ie(const u_char *pd, int offset, int len,
    proto_tree *tree, guint8 info_element)
{
	gboolean non_locking_shift;
	guint8 codeset;

	non_locking_shift = (info_element == Q2931_IE_BBAND_NLOCKING_SHIFT);
	codeset = pd[offset] & 0x07;
	proto_tree_add_text(tree, offset, 1, "%s shift to codeset %u: %s",
	    (non_locking_shift ? "Non-locking" : "Locking"),
	    codeset,
	    val_to_str(codeset, q2931_codeset_vals, "Unknown (0x%02X)"));
}

/*
 * Dissect an ATM adaptation layer parameters information element.
 */
#define	Q2931_AAL_VOICE		0x00
#define	Q2931_AAL1		0x01
#define	Q2931_AAL2		0x02
#define	Q2931_AAL3_4		0x03
#define	Q2931_AAL5		0x05
#define	Q2931_USER_DEFINED_AAL	0x10

static const value_string q9231_aal_type_vals[] = {
	{ 0x00, "AAL for voice" },
	{ 0x01, "AAL type 1" },
	{ 0x02, "AAL type 2" },
	{ 0x03, "AAL type 3/4" },
	{ 0x05, "AAL type 5" },
	{ 0x10, "User-defined AAL" },
	{ 0,    NULL }
};

static const value_string q9231_aal1_subtype_vals[] = {
	{ 0x00, "Null" },
	{ 0x01, "64 kbit/s voice-band signal transport (G.711/G.722)" },
	{ 0x02, "Circuit transport (I.363)" },
	{ 0x04, "High-quality audio signal transport (I.363)" },
	{ 0x05, "Video signal transport (I.363)" },
	{ 0x00, NULL }
};

#define	Q2931_AAL1_nx64_KBIT_S	0x40
#define	Q2931_AAL1_nx8_KBIT_S	0x41

static const value_string q9231_aal1_cbr_rate_vals[] = {
	{ 0x01,                   "64 kbit/s" },
	{ 0x04,                   "1544 kbit/s" },
	{ 0x05,                   "6312 kbit/s" },
	{ 0x06,                   "32064 kbit/s" },
	{ 0x07,                   "44736 kbit/s" },
	{ 0x08,                   "97728 kbit/s" },
	{ 0x10,                   "2048 kbit/s" },
	{ 0x11,                   "8448 kibt/s" },
	{ 0x12,                   "34368 kbit/s" },
	{ 0x13,                   "139264 kbit/s" },
	{ Q2931_AAL1_nx64_KBIT_S, "nx64 kbit/s" },
	{ Q2931_AAL1_nx8_KBIT_S,  "nx8 kbit/s" },
	{ 0x00,                   NULL }
};

static const value_string q2931_aal1_src_clk_rec_meth_vals[] = {
	{ 0x00, "Null (synchronous circuit transport)" },
	{ 0x01, "SRTS method (asynchronous circuit transport" },
	{ 0x02, "Adaptive clock method" },
	{ 0x00, NULL }
};

static const value_string q2931_aal1_err_correction_method_vals[] = {
	{ 0x00, "Null" },
	{ 0x01, "FEC method for less sensitive signal transport" },
	{ 0x02, "FEC method for delay-sensigive signal transport" },
	{ 0x00, NULL }
};

static const value_string q2931_sscs_type_vals[] = {
	{ 0x00, "Null" },
	{ 0x01, "Data SSCS based on SSCOP (assured operation)" },
	{ 0x02, "Data SSCS based on SSCOP (non-assured operation)" },
	{ 0x04, "Frame relay SSCS" },
	{ 0x00, NULL }
};

static void
dissect_q2931_aal_parameters_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 aal_type;
	guint8 identifier;
	guint32 value;
	guint32 low_mid, high_mid;

	if (len == 0)
		return;
	aal_type = pd[offset];
	proto_tree_add_text(tree, offset, 1, "AAL type: %s",
	    val_to_str(aal_type, q9231_aal_type_vals, "Unknown (0x%02X)"));
	offset += 1;
	len -= 1;

	/*
	 * Now get the rest of the IE.
	 */
	if (aal_type == 0x40) {
		/*
		 * User-defined AAL.
		 */
		if (len > 4)
			len = 4;
		proto_tree_add_text(tree, offset, len,
		    "User defined AAL information: %s",
		    bytes_to_str(&pd[offset], len));
		return;
	}

	while (len != 0) {
		identifier = pd[offset];
		switch (identifier) {

		case 0x85:	/* Subtype identifier for AAL1 */
			if (len < 2)
				return;
			value = pd[offset + 1];
			proto_tree_add_text(tree, offset, 2,
			    "Subtype: %s",
			    val_to_str(value, q9231_aal1_subtype_vals,
			    "Unknown (0x%02X)"));
			offset += 2;
			len -= 2;
			break;

		case 0x86:	/* CBR identifier for AAL1 */
			if (len < 2)
				return;
			value = pd[offset + 1];
			proto_tree_add_text(tree, offset, 2,
			    "CBR rate: %s",
			    val_to_str(value, q9231_aal1_cbr_rate_vals,
			    "Unknown (0x%02X)"));
			offset += 2;
			len -= 2;
			break;

		case 0x87:	/* Multiplier identifier for AAL1 */
			if (len < 3)
				return;
			value = pntohs(&pd[offset + 1]);
			proto_tree_add_text(tree, offset, 3,
			    "Multiplier: %u", value);
			offset += 3;
			len -= 3;
			break;

		case 0x88:	/* Source clock frequency recovery method identifier for AAL1 */
			if (len < 2)
				return;
			value = pd[offset + 1];
			proto_tree_add_text(tree, offset, 2,
			    "Source clock frequency recovery method: %s",
			    val_to_str(value, q2931_aal1_src_clk_rec_meth_vals,
			    "Unknown (0x%02X)"));
			offset += 2;
			len -= 2;
			break;

		case 0x89:	/* Error correction method identifier for AAL1 */
			if (len < 2)
				return;
			value = pd[offset + 1];
			proto_tree_add_text(tree, offset, 2,
			    "Error correction method: %s",
			    val_to_str(value, q2931_aal1_err_correction_method_vals,
			    "Unknown (0x%02X)"));
			offset += 2;
			len -= 2;
			break;

		case 0x8A:	/* Structured data transfer block size identifier for AAL1 */
			if (len < 3)
				return;
			value = pntohs(&pd[offset + 1]);
			proto_tree_add_text(tree, offset, 3,
			    "Structured data transfer block size: %u", value);
			offset += 3;
			len -= 3;
			break;

		case 0x8B:	/* Partially filled cells identifier for AAL1 */
			if (len < 2)
				return;
			value = pd[offset + 1];
			proto_tree_add_text(tree, offset, 2,
			    "Partially filled cells method: %u octets", value);
			offset += 2;
			len -= 2;
			break;

		case 0x8C:	/* Forward maximum CPCS-SDU size identifier for AAL3/4 and AAL5 */
			if (len < 3)
				return;
			value = pntohs(&pd[offset + 1]);
			proto_tree_add_text(tree, offset, 3,
			    "Forward maximum CPCS-SDU size: %u", value);
			offset += 3;
			len -= 3;
			break;

		case 0x81:	/* Backward maximum CPCS-SDU size identifier for AAL3/4 and AAL5 */
			if (len < 3)
				return;
			value = pntohs(&pd[offset + 1]);
			proto_tree_add_text(tree, offset, 3,
			    "Backward maximum CPCS-SDU size: %u", value);
			offset += 3;
			len -= 3;
			break;

		case 0x82:	/* MID range identifier for AAL3/4 */
			if (len < 5)
				return;
			low_mid = pntohs(&pd[offset + 1]);
			high_mid = pntohs(&pd[offset + 3]);
			proto_tree_add_text(tree, offset, 3,
			    "MID range: %u - %u", low_mid, high_mid);
			offset += 5;
			len -= 5;
			break;

		case 0x84:	/* SSCS type identifier for AAL3/4 and AAL5 */
			if (len < 2)
				return;
			value = pd[offset + 1];
			proto_tree_add_text(tree, offset, 2,
			    "SSCS type: %s",
			    val_to_str(value, q2931_sscs_type_vals,
			    "Unknown (0x%02X)"));
			offset += 2;
			len -= 2;
			break;

		default:	/* unknown AAL parameter */
			proto_tree_add_text(tree, offset, 1,
			    "Unknown AAL parameter (0x%02X)",
			    identifier);
			return;	/* give up */
		}
	}
}

/*
 * Dissect an ATM traffic descriptor information element.
 */
#define	Q2931_ATM_CR_FW_PEAK_CLP_0	0x82	/* Forward peak cell rate (CLP = 0) */
#define	Q2931_ATM_CR_BW_PEAK_CLP_0	0x83	/* Backward peak cell rate (CLP = 0) */
#define	Q2931_ATM_CR_FW_PEAK_CLP_0_1	0x84	/* Forward peak cell rate (CLP = 0 + 1) */
#define	Q2931_ATM_CR_BW_PEAK_CLP_0_1	0x85	/* Backward peak cell rate (CLP = 0 + 1) */
#define	Q2931_ATM_CR_FW_SUST_CLP_0	0x88	/* Forward sustainable cell rate (CLP = 0) */
#define	Q2931_ATM_CR_BW_SUST_CLP_0	0x89	/* Backward sustainable cell rate (CLP = 0) */
#define	Q2931_ATM_CR_FW_SUST_CLP_0_1	0x90	/* Forward sustainable cell rate (CLP = 0 + 1) */
#define	Q2931_ATM_CR_BW_SUST_CLP_0_1	0x91	/* Backward sustainable cell rate (CLP = 0 + 1) */
#define	Q2931_ATM_CR_FW_MAXB_CLP_0	0xA0	/* Forward maximum burst size (CLP = 0) */
#define	Q2931_ATM_CR_BW_MAXB_CLP_0	0xA1	/* Backward maximum burst size (CLP = 0) */
#define	Q2931_ATM_CR_FW_MAXB_CLP_0_1	0xB0	/* Forward maximum burst size (CLP = 0 + 1) */
#define	Q2931_ATM_CR_BW_MAXB_CLP_0_1	0xB1	/* Backward maximum burst size (CLP = 0 + 1) */
#define	Q2931_ATM_CR_BEST_EFFORT_IND	0xBE	/* Best effort indicator */
#define	Q2931_ATM_CR_TRAFFIC_MGMT_OPT	0xBF	/* Traffic management options */

static const value_string q2931_atm_td_subfield_vals[] = {
	{ Q2931_ATM_CR_FW_PEAK_CLP_0,	"Forward peak cell rate (CLP = 0)" },
	{ Q2931_ATM_CR_BW_PEAK_CLP_0,	"Backward peak cell rate (CLP = 0)" },
	{ Q2931_ATM_CR_FW_PEAK_CLP_0_1,	"Forward peak cell rate (CLP = 0 + 1)" },
	{ Q2931_ATM_CR_BW_PEAK_CLP_0_1,	"Backward peak cell rate (CLP = 0 + 1)" },
	{ Q2931_ATM_CR_FW_SUST_CLP_0,	"Forward sustainable cell rate (CLP = 0)" },
	{ Q2931_ATM_CR_BW_SUST_CLP_0,	"Backward sustainable cell rate (CLP = 0)" },
	{ Q2931_ATM_CR_FW_SUST_CLP_0_1,	"Forward sustainable cell rate (CLP = 0 + 1)" },
	{ Q2931_ATM_CR_BW_SUST_CLP_0_1,	"Backward sustainable cell rate (CLP = 0 + 1)" },
	{ Q2931_ATM_CR_FW_MAXB_CLP_0,	"Forward maximum burst size (CLP = 0)" },
	{ Q2931_ATM_CR_BW_MAXB_CLP_0,	"Backward maximum burst size (CLP = 0)" },
	{ Q2931_ATM_CR_FW_MAXB_CLP_0_1,	"Forward maximum burst size (CLP = 0 + 1)" },
	{ Q2931_ATM_CR_BW_MAXB_CLP_0_1,	"Backward maximum burst size (CLP = 0 + 1)" },
	{ Q2931_ATM_CR_BEST_EFFORT_IND,	"Best effort indicator" },
	{ Q2931_ATM_CR_TRAFFIC_MGMT_OPT,"Traffic management options" },
	{ 0x0,				NULL }
};

static void
dissect_q2931_atm_cell_rate_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 identifier;
	guint32 value;

	while (len != 0) {
		identifier = pd[offset];
		switch (identifier) {

		case Q2931_ATM_CR_FW_PEAK_CLP_0:
		case Q2931_ATM_CR_BW_PEAK_CLP_0:
		case Q2931_ATM_CR_FW_PEAK_CLP_0_1:
		case Q2931_ATM_CR_BW_PEAK_CLP_0_1:
		case Q2931_ATM_CR_FW_SUST_CLP_0:
		case Q2931_ATM_CR_BW_SUST_CLP_0:
		case Q2931_ATM_CR_FW_SUST_CLP_0_1:
		case Q2931_ATM_CR_BW_SUST_CLP_0_1:
		case Q2931_ATM_CR_FW_MAXB_CLP_0:
		case Q2931_ATM_CR_BW_MAXB_CLP_0:
		case Q2931_ATM_CR_FW_MAXB_CLP_0_1:
		case Q2931_ATM_CR_BW_MAXB_CLP_0_1:
			if (len < 4)
				return;
			value = (pd[offset + 1] << 16)
			      | (pd[offset + 2] << 8)
			      | (pd[offset + 3] << 0);
			proto_tree_add_text(tree, offset, 4,
			    "%s: %u cell%s/s",
			    val_to_str(identifier, q2931_atm_td_subfield_vals,
			      NULL),
			    value, plurality(value, "", "s"));
			offset += 4;
			len -= 4;
			break;

		case Q2931_ATM_CR_BEST_EFFORT_IND:
			/* Yes, its value *IS* 0xBE.... */
			proto_tree_add_text(tree, offset, 1,
			    "%s",
			    val_to_str(identifier, q2931_atm_td_subfield_vals,
			      NULL));
			offset += 1;
			len -= 1;
			break;

		case Q2931_ATM_CR_TRAFFIC_MGMT_OPT:
			if (len < 2)
				return;
			value = pd[offset + 1];
			proto_tree_add_text(tree, offset, 2,
			    "%s",
			    val_to_str(identifier, q2931_atm_td_subfield_vals,
			      NULL));
			proto_tree_add_text(tree, offset + 1, 1,
			    "%s allowed in forward direction",
			    (value & 0x80) ? "Frame discard" : "No frame discard");
			proto_tree_add_text(tree, offset + 1, 1,
			    "%s allowed in backward direction",
			    (value & 0x40) ? "Frame discard" : "No frame discard");
			proto_tree_add_text(tree, offset + 1, 1,
			    "Tagging %srequested in backward direction",
			    (value & 0x02) ? "" : "not ");
			proto_tree_add_text(tree, offset + 1, 1,
			    "Tagging %srequested in forward direction",
			    (value & 0x01) ? "" : "not ");
			offset += 2;
			len -= 2;
			break;

		default:	/* unknown ATM traffic descriptor element */
			proto_tree_add_text(tree, offset, 1,
			    "Unknown ATM traffic descriptor element (0x%02X)",
			    identifier);
			return;	/* give up */
		}
	}
}

/*
 * Dissect a broadband bearer capability information element.
 */
static const value_string q2931_bearer_class_vals[] = {
	{ 0x01, "BCOB-A" },
	{ 0x03, "BCOB-C" },
	{ 0x10, "BCOB-X" },
	{ 0x18, "Transparent VP Service" },
	{ 0x00, NULL }
};

static const value_string q2931_transfer_capability_vals[] = {
	{ 0x00, "No bit rate indication" },
	{ 0x01, "No bit rate indication, end-to-end timing required" },
	{ 0x02, "No bit rate indication, end-to-end timing not required" },
	{ 0x04, "CBR" },
	{ 0x05, "CBR, end-to-end timing required" },
	{ 0x06, "CBR, end-to-end timing not required" },
	{ 0x07, "CBR with CLR commitment on CLP=0+1" },
	{ 0x08, "VBR, no timing requirements indication" },
	{ 0x09, "Real time VBR" },
	{ 0x0A, "Non-real time VBR" },
	{ 0x0B, "Non-real time VBR with CLR commitment on CLP=0+1" },
	{ 0x0C, "ABR" },
	{ 0x00, NULL }
};

static const value_string q2931_susc_clip_vals[] = {
	{ 0x00, "Not susceptible to clipping" },
	{ 0x20, "Susceptible to clipping" },
	{ 0x00, NULL }
};

static const value_string q2931_up_conn_config_vals[] = {
	{ 0x00, "Point-to-point" },
	{ 0x01, "Point-to-multipoint" },
	{ 0x00, NULL }
};

void
dissect_q2931_bband_bearer_cap_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;

	if (len == 0)
		return;
	octet = pd[offset];
	proto_tree_add_text(tree, offset, 1,
	    "Bearer class: %s",
	    val_to_str(octet & 0x1F, q2931_bearer_class_vals,
	    "Unknown (0x%02X)"));
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	if (!(octet & Q2931_IE_EXTENSION)) {
		octet = pd[offset];
		proto_tree_add_text(tree, offset, 1,
		    "ATM Transfer Capability: %s",
		    val_to_str(octet & 0x1F, q2931_transfer_capability_vals,
		    "Unknown (0x%02X)"));
		offset += 1;
		len -= 1;
	}

	if (len == 0)
		return;
	octet = pd[offset];
	proto_tree_add_text(tree, offset, 1,
	    "Susceptibility to clipping: %s",
	    val_to_str(octet & 0x60, q2931_susc_clip_vals,
	    "Unknown (0x%02X)"));
	proto_tree_add_text(tree, offset, 1,
	    "User-plane connection configuration: %s",
	    val_to_str(octet & 0x03, q2931_up_conn_config_vals,
	    "Unknown (0x%02X)"));
}

/*
 * Dissect a broadband high layer information information element.
 */
static const value_string q2931_hi_layer_info_type_vals[] = {
	{ 0x00, "ISO/IEC" },
	{ 0x01, "User-specific" },
	{ 0x03, "Vendor-specific" },
	{ 0x04, "ITU-T SG 1 B-ISDN teleservice recommendation" },
	{ 0x00, NULL }
};

void
dissect_q2931_bband_hi_layer_info_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;

	if (len == 0)
		return;
	octet = pd[offset];
	proto_tree_add_text(tree, offset, 1,
	    "High layer information type: %s",
	    val_to_str(octet & 0x7F, q2931_hi_layer_info_type_vals,
	    "Unknown (0x%02X)"));
	offset += 1;
	len -= 1;
}

/*
 * Dissect a Bearer capability or Low-layer compatibility information element.
 */
#define	Q2931_UIL2_USER_SPEC	0x10

static const value_string q2931_uil2_vals[] = {
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
	{ Q2931_UIL2_USER_SPEC,	"User-specified" },
	{ 0x11,			"ISO 7776 DTE-DTE operation" },
	{ 0,			NULL }
};

static const value_string q2931_mode_vals[] = {
	{ 0x20, "Normal mode" },
	{ 0x40, "Extended mode" },
	{ 0,    NULL }
};

#define	Q2931_UIL3_X25_PL	0x06
#define	Q2931_UIL3_ISO_8208	0x07	/* X.25-based */
#define	Q2931_UIL3_X223		0x08	/* X.25-based */
#define	Q2931_UIL3_TR_9577	0x0B
#define	Q2931_UIL3_USER_SPEC	0x10

static const value_string q2931_uil3_vals[] = {
	{ Q2931_UIL3_X25_PL,	"X.25, packet layer" },
	{ Q2931_UIL3_ISO_8208,	"ISO/IEC 8208" },
	{ Q2931_UIL3_X223,	"X.223/ISO 8878" },
	{ 0x09,			"ISO/IEC 8473" },
	{ 0x0A,			"T.70" },
	{ Q2931_UIL3_TR_9577,	"ISO/IEC TR 9577" },
	{ Q2931_UIL3_USER_SPEC,	"User-specified" },
	{ 0,			NULL }
};

#define	Q2931_TR_9577_IPI_SNAP	0x80
static const value_string q2931_uil3_tr_9577_vals[] = {
	{ 0xCC,                   "IP" },
	{ 0xCF,                   "PPP" },
	{ Q2931_TR_9577_IPI_SNAP, "SNAP" },
	{ 0x00,                   NULL }
};

/*
 * Dissect a broadband low layer information information element.
 */
void
dissect_q2931_bband_low_layer_info_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;
	guint8 uil2_protocol;
	guint8 uil3_protocol;
	guint8 add_l3_info;
	guint32 organization_code;
	guint16 pid;

	if (len == 0)
		return;
	octet = pd[offset];
	if ((octet & 0x60) == 0x20) {
		/*
		 * Layer 1 information.
		 */
		proto_tree_add_text(tree, offset, 1,
		    "User information layer 1 protocol: 0x%02X",
		    octet & 0x1F);
		offset += 1;
		len -= 1;
	}

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
		    val_to_str(uil2_protocol, q2931_uil2_vals,
		      "Unknown (0x%02X)"));
		offset += 1;
		len -= 1;

		if (octet & Q2931_IE_EXTENSION)
			goto l2_done;
		if (len == 0)
			return;
		octet = pd[offset];
		if (uil2_protocol == Q2931_UIL2_USER_SPEC) {
			proto_tree_add_text(tree, offset, 1,
			    "User-specified layer 2 protocol information: 0x%02X",
			    octet & 0x7F);
		} else {
			proto_tree_add_text(tree, offset, 1,
			    "Mode: %s",
			    val_to_str(octet & 0x60, q2931_mode_vals,
			      "Unknown (0x%02X)"));
		}
		offset += 1;
		len -= 1;

		if (octet & Q2931_IE_EXTENSION)
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
		    val_to_str(uil3_protocol, q2931_uil3_vals,
		      "Unknown (0x%02X)"));
		offset += 1;
		len -= 1;


		/*
		 * XXX - only in Low-layer compatibility information element.
		 */
		if (octet & Q2931_IE_EXTENSION)
			goto l3_done;
		if (len == 0)
			return;
		octet = pd[offset];
		switch (uil3_protocol) {

		case Q2931_UIL3_X25_PL:
		case Q2931_UIL3_ISO_8208:
		case Q2931_UIL3_X223:
			proto_tree_add_text(tree, offset, 1,
			    "Mode: %s",
			    val_to_str(octet & 0x60, q2931_mode_vals,
			      "Unknown (0x%02X)"));
			offset += 1;
			len -= 1;

			if (octet & Q2931_IE_EXTENSION)
				goto l3_done;
			if (len == 0)
				return;
			octet = pd[offset];
			proto_tree_add_text(tree, offset, 1,
			    "Default packet size: %u", octet & 0x0F);
			offset += 1;
			len -= 1;

			if (octet & Q2931_IE_EXTENSION)
				goto l3_done;
			if (len == 0)
				return;
			octet = pd[offset];
			proto_tree_add_text(tree, offset, 1,
			    "Packet window size: %u", octet & 0x7F);
			offset += 1;
			len -= 1;
			break;

		case Q2931_UIL3_USER_SPEC:
			proto_tree_add_text(tree, offset, 1,
			    "Default packet size: %u octets",
			    1 << (octet & 0x0F));
			offset += 1;
			len -= 1;
			break;

		case Q2931_UIL3_TR_9577:
			add_l3_info = (octet & 0x7F) << 1;
			if (octet & Q2931_IE_EXTENSION)
				goto l3_done;
			if (len < 2)
				return;
			add_l3_info |= (pd[offset + 1] & 0x40) >> 6;
			proto_tree_add_text(tree, offset, 2,
			    "Additional layer 3 protocol information: %s",
			    val_to_str(add_l3_info, q2931_uil3_tr_9577_vals,
			      "Unknown (0x%02X)"));
			offset += 2;
			len -= 2;
			if (add_l3_info == Q2931_TR_9577_IPI_SNAP) {
				if (len < 6)
					return;
				offset += 1;
				len -= 1;
				organization_code = 
				    pd[offset] << 16 | pd[offset+1] << 8 | pd[offset+2];
				proto_tree_add_text(tree, offset, 3,
				    "Organization Code: 0x%06X",
				    organization_code);
				offset += 3;
				len -= 3;

				if (len < 2)
					return;
				pid = pntohs(&pd[offset]);
				if (organization_code == 0x000000) {
					proto_tree_add_text(tree, offset, 2,
					    "Ethernet type: %s",
					    val_to_str(pid, etype_vals,
					        "Unknown (0x%04X)"));
				} else {
					proto_tree_add_text(tree, offset, 2,
					    "Protocol ID: 0x%04X", pid);
				}
			}
			break;
		}
	}
l3_done:
	;
}

/*
 * Dissect a Cause information element.
 */
static const value_string q2931_cause_coding_standard_vals[] = {
	{ 0x00, "ITU-T standardized coding" },
	{ 0x20, "ISO/IEC standard" },
	{ 0x40, "National standard" },
	{ 0x60, "Standard defined for the network" },
	{ 0,    NULL }
};
	
static const value_string q2931_cause_location_vals[] = {
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

/*
 * Cause codes for Cause.
 */
#define	Q2931_CAUSE_UNALLOC_NUMBER	0x01
#define	Q2931_CAUSE_NO_ROUTE_TO_DEST	0x03
#define	Q2931_CAUSE_CALL_REJECTED	0x15
#define	Q2931_CAUSE_NUMBER_CHANGED	0x16
#define	Q2931_CAUSE_CELL_RATE_UNAVAIL	0x25
#define	Q2931_CAUSE_ACCESS_INFO_DISC	0x2B
#define	Q2931_CAUSE_QOS_UNAVAILABLE	0x31
#define	Q2931_CAUSE_CHAN_NONEXISTENT	0x52
#define	Q2931_CAUSE_INCOMPATIBLE_DEST	0x58
#define	Q2931_CAUSE_MAND_IE_MISSING	0x60
#define	Q2931_CAUSE_MT_NONEX_OR_UNIMPL	0x61
#define	Q2931_CAUSE_IE_NONEX_OR_UNIMPL	0x63
#define	Q2931_CAUSE_INVALID_IE_CONTENTS	0x64
#define	Q2931_CAUSE_MSG_INCOMPAT_W_CS	0x65
#define	Q2931_CAUSE_REC_TIMER_EXP	0x66

static const value_string q2931_cause_code_vals[] = {
	{ Q2931_CAUSE_UNALLOC_NUMBER,	"Unallocated (unassigned) number" },
	{ 0x02,				"No route to specified transit network" },
	{ Q2931_CAUSE_NO_ROUTE_TO_DEST,	"No route to destination" },
	{ 0x10,				"Normal call clearing" },
	{ 0x11,				"User busy" },
	{ 0x12,				"No user responding" },
	{ Q2931_CAUSE_CALL_REJECTED,	"Call rejected" },
	{ Q2931_CAUSE_NUMBER_CHANGED,	"Number changed" },
	{ 0x17,				"User rejects calls with calling line identification restriction" },
	{ 0x1B,				"Destination out of order" },
	{ 0x1C,				"Invalid number format (incomplete number)" },
	{ 0x1E,				"Response to STATUS ENQUIRY" },
	{ 0x1F,				"Normal unspecified" },
	{ 0x23,				"Requested VPCI/VCI not available" },
	{ 0x24,				"VPCI/VCI assignment failure" },
	{ Q2931_CAUSE_CELL_RATE_UNAVAIL,"User cell rate not available" },
	{ 0x26,				"Network out of order" },
	{ 0x29,				"Temporary failure" },
	{ Q2931_CAUSE_ACCESS_INFO_DISC,	"Access information discarded" },
	{ 0x2D,				"No VPCI/VCI available" },
	{ 0x2F,				"Resources unavailable, unspecified" },
	{ Q2931_CAUSE_QOS_UNAVAILABLE,	"Quality of service unavailable" },
	{ 0x39,				"Bearer capability not authorized" },
	{ 0x3A,				"Bearer capability not presently available" },
	{ 0x3F,				"Service or option not available, unspecified" },
	{ 0x41,				"Bearer capability not implemented" },
	{ 0x49,				"Unsupported combination of traffic parameters" },
	{ 0x4E,				"AAL parameters cannot be supported" },
	{ 0x51,				"Invalid call reference value" },
	{ Q2931_CAUSE_CHAN_NONEXISTENT,	"Identified channel does not exist" },
	{ Q2931_CAUSE_INCOMPATIBLE_DEST,"Incompatible destination" },
	{ 0x59,				"Invalid endpoint reference" },
	{ 0x5B,				"Invalid transit network selection" },
	{ 0x5C,				"Too many pending ADD PARTY requests" },
	{ Q2931_CAUSE_MAND_IE_MISSING,	"Mandatory information element is missing" },
	{ Q2931_CAUSE_MT_NONEX_OR_UNIMPL,"Message type non-existent or not implemented" },
	{ Q2931_CAUSE_IE_NONEX_OR_UNIMPL,"Information element nonexistant or not implemented" },
	{ Q2931_CAUSE_INVALID_IE_CONTENTS,"Invalid information element contents" },
	{ Q2931_CAUSE_MSG_INCOMPAT_W_CS,"Message not compatible with call state" },
	{ Q2931_CAUSE_REC_TIMER_EXP,	"Recovery on timer expiry" },
	{ 0x68,				"Incorrect message length" },
	{ 0x6F,				"Protocol error, unspecified" },
	{ 0,				NULL }
};

static const value_string q2931_cause_condition_vals[] = {
	{ 0x00, "Unknown" },
	{ 0x01, "Permanent" },
	{ 0x02, "Transient" },
	{ 0x00, NULL }
};

#define	Q2931_REJ_USER_SPECIFIC		0x00
#define	Q2931_REJ_IE_MISSING		0x04
#define	Q2931_REJ_IE_INSUFFICIENT	0x08

static const value_string q2931_rejection_reason_vals[] = {
	{ 0x00, "User specific" },
	{ 0x04, "Information element missing" },
	{ 0x08, "Information element contents are not sufficient" },
	{ 0x00, NULL }
};

static void
dissect_q2931_cause_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;
	guint8 cause_value;
	guint8 rejection_reason;
	guint8 info_element;
	guint8 info_element_ext;
	guint16 info_element_len;

	if (len == 0)
		return;
	octet = pd[offset];
	proto_tree_add_text(tree, offset, 1,
	    "Location: %s",
	    val_to_str(octet & 0x0F, q2931_cause_location_vals,
	      "Unknown (0x%X)"));
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	octet = pd[offset];
	cause_value = octet & 0x7F;
	proto_tree_add_text(tree, offset, 1,
	    "Cause value: %s",
	    val_to_str(cause_value, q2931_cause_code_vals,
	      "Unknown (0x%X)"));
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	switch (cause_value) {

	case Q2931_CAUSE_UNALLOC_NUMBER:
	case Q2931_CAUSE_NO_ROUTE_TO_DEST:
	case Q2931_CAUSE_QOS_UNAVAILABLE:
		octet = pd[offset];
		proto_tree_add_text(tree, offset, 1,
		    "Network service: %s",
		    (octet & 0x80) ? "User" : "Provider");
		proto_tree_add_text(tree, offset, 1,
		    "%s",
		    (octet & 0x40) ? "Abnormal" : "Normal");
		proto_tree_add_text(tree, offset, 1,
		    "Condition: %s",
		    val_to_str(octet & 0x03, q2931_cause_condition_vals,
		      "Unknown (0x%X)"));
		break;
		
	case Q2931_CAUSE_CALL_REJECTED:
		rejection_reason = octet & 0x7C;
		proto_tree_add_text(tree, offset, 1,
		    "Rejection reason: %s",
		    val_to_str(octet & 0x7C, q2931_cause_condition_vals,
		      "Unknown (0x%X)"));
		proto_tree_add_text(tree, offset, 1,
		    "Condition: %s",
		    val_to_str(octet & 0x03, q2931_cause_condition_vals,
		      "Unknown (0x%X)"));
		offset += 1;
		len -= 1;

		if (len == 0)
			return;
		switch (rejection_reason) {

		case Q2931_REJ_USER_SPECIFIC:
			proto_tree_add_text(tree, offset, len,
			    "User specific diagnostic: %s",
			    bytes_to_str(&pd[offset], len));
			break;

		case Q2931_REJ_IE_MISSING:
			proto_tree_add_text(tree, offset, 1,
			    "Missing information element: %s",
			    val_to_str(pd[offset], q2931_info_element_vals,
			      "Unknown (0x%02X)"));
			break;

		case Q2931_REJ_IE_INSUFFICIENT:
			proto_tree_add_text(tree, offset, 1,
			    "Insufficient information element: %s",
			    val_to_str(pd[offset], q2931_info_element_vals,
			      "Unknown (0x%02X)"));
			break;

		default:
			proto_tree_add_text(tree, offset, len,
			    "Diagnostic: %s",
			    bytes_to_str(&pd[offset], len));
			break;
		}
		break;

	case Q2931_CAUSE_NUMBER_CHANGED:
		/*
		 * UNI 3.1 claims this "is formatted as the called party
		 * number information element, including information
		 * element identifier.
		 */
		info_element = pd[offset];
		if (!BYTES_ARE_IN_FRAME(offset + 1, 1))
			break;	/* ran past end of frame */
		info_element_ext = pd[offset + 1];
		if (!BYTES_ARE_IN_FRAME(offset + 2, 2))
			break;	/* ran past end of frame */
		info_element_len = pntohs(&pd[offset + 2]);
		if (!BYTES_ARE_IN_FRAME(offset + 4, info_element_len))
			break;	/* ran past end of frame */
		dissect_q2931_ie(pd, offset, info_element_len, tree,
		    info_element, info_element_ext);
		break;

	case Q2931_CAUSE_ACCESS_INFO_DISC:
	case Q2931_CAUSE_INCOMPATIBLE_DEST:
	case Q2931_CAUSE_MAND_IE_MISSING:
	case Q2931_CAUSE_IE_NONEX_OR_UNIMPL:
	case Q2931_CAUSE_INVALID_IE_CONTENTS:
		do {
			proto_tree_add_text(tree, offset, 1,
			    "Information element: %s",
			    val_to_str(pd[offset], q2931_info_element_vals,
			      "Unknown (0x%02X)"));
			offset += 1;
			len -= 1;
		} while (len != 0);
		break;

	case Q2931_CAUSE_CELL_RATE_UNAVAIL:
		do {
			proto_tree_add_text(tree, offset, 1,
			    "Cell rate subfield identifier: %s",
			    val_to_str(pd[offset], q2931_atm_td_subfield_vals,
			      "Unknown (0x%02X)"));
			offset += 1;
			len -= 1;
		} while (len != 0);
		break;

	case Q2931_CAUSE_CHAN_NONEXISTENT:
		if (len < 2)
			return;
		proto_tree_add_text(tree, offset, 2,
		    "VPCI: %u", pntohs(&pd[offset]));
		offset += 2;
		len -= 2;

		if (len < 2)
			return;
		proto_tree_add_text(tree, offset, 2,
		    "VCI: %u", pntohs(&pd[offset]));
		break;

	case Q2931_CAUSE_MT_NONEX_OR_UNIMPL:
	case Q2931_CAUSE_MSG_INCOMPAT_W_CS:
		proto_tree_add_text(tree, offset, 1,
		    "Message type: %s",
		    val_to_str(pd[offset], q2931_message_type_vals,
		      "Unknown (0x%02X)"));
		break;

	case Q2931_CAUSE_REC_TIMER_EXP:
		if (len < 3)
			return;
		proto_tree_add_text(tree, offset, 3,
		    "Timer: %.3s", &pd[offset]);
		break;

	default:
		proto_tree_add_text(tree, offset, len,
		    "Diagnostics: %s",
		    bytes_to_str(&pd[offset], len));
	}
}

/*
 * Dissect a Call state information element.
 */
static const value_string q2931_call_state_vals[] = {
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
dissect_q2931_call_state_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;

	if (len == 0)
		return;
	octet = pd[offset];
	proto_tree_add_text(tree, offset, 1,
	    "Call state: %s",
	    val_to_str(octet & 0x3F, q2931_call_state_vals,
	      "Unknown (0x%02X)"));
}

/*
 * Dissect a (phone) number information element.
 */
static const value_string q2931_number_type_vals[] = {
	{ 0x00, "Unknown" },
	{ 0x10, "International number" },
	{ 0x20, "National number" },
	{ 0x30, "Network specific number" },
	{ 0x40, "Subscriber number" },
	{ 0x60, "Abbreviated number" },
	{ 0,    NULL }
};

#define	Q2931_ISDN_NUMBERING	0x01
#define	Q2931_NSAP_ADDRESSING	0x02

static const value_string q2931_numbering_plan_vals[] = {
	{ 0x00,                  "Unknown" },
	{ Q2931_ISDN_NUMBERING,  "E.164 ISDN/telephony numbering" },
	{ Q2931_NSAP_ADDRESSING, "ISO/IEC 8348 NSAP addressing" },
	{ 0x09,                  "Private numbering" },
	{ 0,                     NULL }
};

static const value_string q2931_presentation_indicator_vals[] = {
	{ 0x00, "Presentation allowed" },
	{ 0x20, "Presentation restricted" },
	{ 0x40, "Number not available" },
	{ 0,    NULL }
};

static const value_string q2931_screening_indicator_vals[] = {
	{ 0x00, "User-provided, not screened" },
	{ 0x01, "User-provided, verified and passed" },
	{ 0x02, "User-provided, verified and failed" },
	{ 0x03, "Network-provided" },
	{ 0,    NULL }
};

static void
dissect_q2931_number_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;
	guint8 numbering_plan;
	proto_item *ti;
	proto_tree *nsap_tree;

	if (len == 0)
		return;
	octet = pd[offset];
	proto_tree_add_text(tree, offset, 1,
	    "Type of number: %s",
	    val_to_str(octet & 0x70, q2931_number_type_vals,
	      "Unknown (0x%02X)"));
	numbering_plan = octet & 0x0F;
	proto_tree_add_text(tree, offset, 1,
	    "Numbering plan: %s",
	    val_to_str(numbering_plan, q2931_numbering_plan_vals,
	      "Unknown (0x%02X)"));
	offset += 1;
	len -= 1;

	if (!(octet & Q2931_IE_EXTENSION)) {
		if (len == 0)
			return;
		octet = pd[offset];
		proto_tree_add_text(tree, offset, 1,
		    "Presentation indicator: %s",
		    val_to_str(octet & 0x60, q2931_presentation_indicator_vals,
		      "Unknown (0x%X)"));
		proto_tree_add_text(tree, offset, 1,
		    "Screening indicator: %s",
		    val_to_str(octet & 0x03, q2931_screening_indicator_vals,
		      "Unknown (0x%X)"));
		offset += 1;
		len -= 1;
	}

	if (len == 0)
		return;
	switch (numbering_plan) {

	case Q2931_ISDN_NUMBERING:
		proto_tree_add_text(tree, offset, len, "Number: %.*s",
		    len, &pd[offset]);
		break;

	case Q2931_NSAP_ADDRESSING:
		if (len < 20) {
			proto_tree_add_text(tree, offset, len,
			    "Number (too short): %s",
			    bytes_to_str(&pd[offset], len));
			return;
		}
		ti = proto_tree_add_text(tree, offset, len, "Number");
		nsap_tree = proto_item_add_subtree(ti, ett_q2931_nsap);
		switch (pd[offset]) {

		case 0x39:	/* DCC ATM format */
		case 0xBD:	/* DCC ATM group format */
			proto_tree_add_text(nsap_tree, offset + 0, 3,
			    "Data Country Code%s: 0x%04X",
			    (pd[offset] == 0xBD) ? " (group)" : "",
			    pntohs(&pd[offset + 1]));
			proto_tree_add_text(nsap_tree, offset + 3, 10,
			    "High Order DSP: %s",
			    bytes_to_str(&pd[offset + 3], 10));
			proto_tree_add_text(nsap_tree, offset + 13, 6,
			    "End System Identifier: %s",
			    bytes_to_str(&pd[offset + 13], 6));
			proto_tree_add_text(nsap_tree, offset + 19, 1,
			    "Selector: 0x%02X", pd[offset + 19]);
			break;

		case 0x47:	/* ICD ATM format */
		case 0xC5:	/* ICD ATM group format */
			proto_tree_add_text(nsap_tree, offset, 1,
			    "International Code Designator%s: 0x%04X",
			    (pd[offset] == 0xC5) ? " (group)" : "",
			    pntohs(&pd[offset + 1]));
			proto_tree_add_text(nsap_tree, offset + 3, 10,
			    "High Order DSP: %s",
			    bytes_to_str(&pd[offset + 3], 10));
			proto_tree_add_text(nsap_tree, offset + 13, 6,
			    "End System Identifier: %s",
			    bytes_to_str(&pd[offset + 13], 6));
			proto_tree_add_text(nsap_tree, offset + 19, 1,
			    "Selector: 0x%02X", pd[offset + 19]);
			break;

		case 0x45:	/* E.164 ATM format */
		case 0xC3:	/* E.164 ATM group format */
			proto_tree_add_text(nsap_tree, offset + 0, 9,
			    "E.164 ISDN%s: %s",
			    (pd[offset] == 0xC3) ? " (group)" : "",
			    bytes_to_str(&pd[offset + 1], 8));
			proto_tree_add_text(nsap_tree, offset + 9, 4,
			    "High Order DSP: %s",
			    bytes_to_str(&pd[offset + 3], 10));
			proto_tree_add_text(nsap_tree, offset + 13, 6,
			    "End System Identifier: %s",
			    bytes_to_str(&pd[offset + 13], 6));
			proto_tree_add_text(nsap_tree, offset + 19, 1,
			    "Selector: 0x%02X", pd[offset + 19]);
			break;

		default:
			proto_tree_add_text(nsap_tree, offset, 1,
			    "Unknown AFI: 0x%02X", pd[offset]);
			proto_tree_add_text(nsap_tree, offset + 1, len - 1,
			    "Rest of address: %s",
			    bytes_to_str(&pd[offset + 1], len - 1));
			break;
		}
		break;

	default:
		proto_tree_add_text(tree, offset, len, "Number: %s",
		    bytes_to_str(&pd[offset], len));
		break;
	}
}

/*
 * Dissect a party subaddress information element.
 */
static const value_string q2931_subaddress_type_vals[] = {
	{ 0x00, "X.213/ISO 8348 NSAP" },
	{ 0x10, "User-specified ATM endsystem address" },
	{ 0x20, "User-specified" },
	{ 0,    NULL }
};

static const value_string q2931_odd_even_indicator_vals[] = {
	{ 0x00, "Even number of address signals" },
	{ 0x10, "Odd number of address signals" },
	{ 0,    NULL }
};

static void
dissect_q2931_party_subaddr_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;

	if (len == 0)
		return;
	octet = pd[offset];
	proto_tree_add_text(tree, offset, 1,
	    "Type of subaddress: %s",
	    val_to_str(octet & 0x70, q2931_subaddress_type_vals,
	      "Unknown (0x%02X)"));
	proto_tree_add_text(tree, offset, 1,
	    "Odd/even indicator: %s",
	    val_to_str(octet & 0x10, q2931_odd_even_indicator_vals,
	      NULL));
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	proto_tree_add_text(tree, offset, len, "Subaddress: %s",
	    bytes_to_str(&pd[offset], len));
}

/*
 * Dissect a connection identifier information element.
 */
static const value_string q2931_vp_associated_signalling_vals[] = {
	{ 0x00, "Yes" },
	{ 0x08, "No - explicit indication of VPCI" },
	{ 0x00, NULL }
};

static const value_string q2931_preferred_exclusive_vals[] = {
	{ 0x00, "Exclusive VPCI; exclusive VCI" },
	{ 0x01, "Exclusive VPCI; any VCI" },
	{ 0x04, "Exclusive VPCI; no VCI" },
	{ 0x00, NULL }
};

static void
dissect_q2931_connection_identifier_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;

	if (len == 0)
		return;
	octet = pd[offset];
	proto_tree_add_text(tree, offset, 1,
	    "VP-associated signalling: %s",
	    val_to_str(octet & 0x18, q2931_vp_associated_signalling_vals,
	      "Unknown (0x%02X)"));
	proto_tree_add_text(tree, offset, 1,
	    "Preferred/exclusive: %s",
	    val_to_str(octet & 0x07, q2931_preferred_exclusive_vals,
	      "Unknown (0x%02X)"));
	offset += 1;
	len -= 1;

	if (len < 2)
		return;
	proto_tree_add_text(tree, offset, 2, "VPCI: %u",
	    pntohs(&pd[offset]));
	offset += 2;
	len -= 2;

	if (len < 2)
		return;
	proto_tree_add_text(tree, offset, 2, "VCI: %u",
	    pntohs(&pd[offset]));
}

/*
 * Dissect an End-to-end transit delay information element.
 */
static void
dissect_q2931_e2e_transit_delay_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 identifier;
	guint16 value;

	while (len >= 3) {
		identifier = pd[offset];
		value = pntohs(&pd[offset + 1]);
		switch (identifier) {

		case 0x01:	/* Cumulative transit delay identifier */
			proto_tree_add_text(tree, offset, 3,
			    "Cumulative transit delay: %u ms", value);
			break;

		case 0x03:	/* Maximum transit delay identifier */
			if (value == 0xFFFF) {
				proto_tree_add_text(tree, offset, 3,
				    "Any end-to-end transit delay value acceptable");
			} else {
				proto_tree_add_text(tree, offset, 3,
				    "Maximum end-to-end transit delay: %u ms",
				    value);
			}
			break;

		default:	/* Unknown transit delay identifier */
			proto_tree_add_text(tree, offset, 1,
			    "Unknown transit delay identifier (0x%02X)",
			    identifier);
			return;	/* give up */
		}
	}
}

/*
 * Dissect a Quality of Service parameter information element.
 */
static const value_string q2931_qos_parameter_vals[] = {
	{ 0x00, "Unspecified QOS class" },
	{ 0x00, NULL }
};

static void
dissect_q2931_qos_parameter_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;

	if (len == 0)
		return;
	octet = pd[offset];
	proto_tree_add_text(tree, offset, 1,
	    "QOS class forward: %s",
	    val_to_str(octet, q2931_qos_parameter_vals,
	      "Unknown (0x%02X)"));
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	octet = pd[offset];
	proto_tree_add_text(tree, offset, 1,
	    "QOS class backward: %s",
	    val_to_str(octet, q2931_qos_parameter_vals,
	      "Unknown (0x%02X)"));
}

/*
 * Dissect a broadband repeat indicator.
 */
static const value_string q2931_bband_rpt_indicator_vals[] = {
	{ 0x02, "Prioritized list for selecting one possibility (descending order)" },
	{ 0x00, NULL }
};

static void
dissect_q2931_bband_rpt_indicator(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;

	if (len == 0)
		return;
	octet = pd[offset];
	proto_tree_add_text(tree, offset, 1,
	    "Broadband repeat indicator: %s",
	    val_to_str(octet & 0x0F, q2931_bband_rpt_indicator_vals,
	      "Unknown (0x%02X)"));
}

/*
 * Dissect a restart indicator.
 */
static const value_string q2931_class_vals[] = {
	{ 0x00, "Indicated VC" },
	{ 0x01, "All VC's in the indicated VPC controlled via this channel" },
	{ 0x02, "All VC's controlled by the L3 entity that sent this message" },
	{ 0x00, NULL }
};

static void
dissect_q2931_restart_indicator(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;

	if (len == 0)
		return;
	octet = pd[offset];
	proto_tree_add_text(tree, offset, 1,
	    "Restart indicator: %s",
	    val_to_str(octet & 0x07, q2931_class_vals,
	      "Unknown (0x%02X)"));
}

/*
 * Dissect an broadband sending complete information element.
 */
static void
dissect_q2931_bband_sending_compl_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 identifier;

	while (len != 0) {
		identifier = pd[offset];
		switch (identifier) {

		case 0xA1:	/* Sending complete indication */
			proto_tree_add_text(tree, offset, 1,
			    "Broadband sending complete indication");
			offset += 1;
			len -= 1;
			break;

		default:	/* unknown broadband sending complete element */
			proto_tree_add_text(tree, offset, 1,
			    "Unknown broadband sending complete element (0x%02X)",
			    identifier);
			return;	/* give up */
		}
	}
}

/*
 * Dissect a Transit network selection information element.
 */
static const value_string q2931_netid_type_vals[] = {
	{ 0x00, "User specified" },
	{ 0x20, "National network identification" },
	{ 0x30, "International network identification" },
	{ 0,    NULL }
};

static const value_string q2931_netid_plan_vals[] = {
	{ 0x00, "Unknown" },
	{ 0x01, "Carrier Identification Code" },
	{ 0x03, "X.121 data network identification code" },
	{ 0,    NULL }
};

static void
dissect_q2931_transit_network_sel_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;

	if (len == 0)
		return;
	octet = pd[offset];
	proto_tree_add_text(tree, offset, 1,
	    "Type of network identification: %s",
	    val_to_str(octet & 0x70, q2931_netid_type_vals,
	      "Unknown (0x%02X)"));
	proto_tree_add_text(tree, offset, 1,
	    "Network identification plan: %s",
	    val_to_str(octet & 0x0F, q2931_netid_plan_vals,
	      "Unknown (0x%02X)"));
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	proto_tree_add_text(tree, offset, len,
	    "Network identification: %.*s", len, &pd[offset]);
}

/*
 * Dissect an OAM traffic descriptor information element.
 */
static const value_string q2931_shaping_indicator_vals[] = {
	{ 0x00, "No user specified requirement" },
	{ 0x20, "Aggregate shaping of user and OAM cells not allowed" },
	{ 0,    NULL }
};

static const value_string q2931_user_net_fault_mgmt_vals[] = {
	{ 0x00, "No user-originated fault managment indications" },
	{ 0x01, "User-originated fault management indications, cell rate 1 cell/s" },
	{ 0,    NULL }
};

static const value_string q2931_fwd_e2e_oam_f5_flow_indicator_vals[] = {
	{ 0x00, "0% of the forward cell rate" },
	{ 0x10, "0.1% of the forward cell rate" },
	{ 0x40, "1% of the forward cell rate" },
	{ 0x0,  NULL }
};

static const value_string q2931_bwd_e2e_oam_f5_flow_indicator_vals[] = {
	{ 0x00, "0% of the backward cell rate" },
	{ 0x01, "0.1% of the backward cell rate" },
	{ 0x04, "1% of the backward cell rate" },
	{ 0x0,  NULL }
};

static void
dissect_q2931_oam_traffic_descriptor_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;

	if (len == 0)
		return;
	octet = pd[offset];
	proto_tree_add_text(tree, offset, 1,
	    "Shaping indicator: %s",
	    val_to_str(octet & 0x60, q2931_shaping_indicator_vals,
	      "Unknown (0x%02X)"));
	proto_tree_add_text(tree, offset, 1,
	    "Use of end-to-end OAM F5 flow is %s",
	    (octet & 0x10) ? "mandatory" : "optional");
	proto_tree_add_text(tree, offset, 1,
	    "User-Network fault management indicator: %s",
	    val_to_str(octet & 0x07, q2931_user_net_fault_mgmt_vals,
	      "Unknown (0x%02X)"));
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	octet = pd[offset];
	proto_tree_add_text(tree, offset, 1,
	    "Forward end-to-end OAM F5 flow indicator: %s",
	    val_to_str(octet & 0x70, q2931_fwd_e2e_oam_f5_flow_indicator_vals,
	      "Unknown (0x%02X)"));
	proto_tree_add_text(tree, offset, 1,
	    "Backward end-to-end OAM F5 flow indicator: %s",
	    val_to_str(octet & 0x07, q2931_bwd_e2e_oam_f5_flow_indicator_vals,
	      "Unknown (0x%02X)"));
}

/*
 * Dissect an Endpoint reference information element.
 */
static const value_string q2931_endpoint_reference_type_vals[] = {
	{ 0x00, "Locally defined integer" },
	{ 0,    NULL }
};

static void
dissect_q2931_endpoint_reference_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;
	guint16 value;

	if (len == 0)
		return;
	octet = pd[offset];
	proto_tree_add_text(tree, offset, 1,
	    "Endpoint reference type: %s",
	    val_to_str(octet, q2931_endpoint_reference_type_vals,
	      "Unknown (0x%02X)"));
	offset += 1;
	len -= 1;

	if (len < 2)
		return;
	value = pntohs(&pd[offset]);
	proto_tree_add_text(tree, offset, 2,
	    "Endpoint reference flag: %s",
	    (value & 0x8000) ? "Message sent to side that originates the endpoint reference" :
		 	       "Message sent from side that originates the endpoint reference");
	proto_tree_add_text(tree, offset, 2,
	    "Endpoint reference identifier value: %u",
	    value & 0x7FFF);
}

/*
 * Dissect an Endpoint state information element.
 */
static const value_string q2931_endpoint_reference_party_state_vals[] = {
	{ 0x00, "Null" },
	{ 0x01, "ADD PARTY initiated" },
	{ 0x06, "ADD PARTY received" },
	{ 0x0B, "DROP PARTY initiated" },
	{ 0x0C, "DROP PARTY received" },
	{ 0x0A, "Active" },
	{ 0,    NULL }
};

static void
dissect_q2931_endpoint_state_ie(const u_char *pd, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;

	if (len == 0)
		return;
	octet = pd[offset];
	proto_tree_add_text(tree, offset, 1,
	    "Endpoint reference party-state: %s",
	    val_to_str(octet & 0x3F, q2931_endpoint_reference_party_state_vals,
	      "Unknown (0x%02X)"));
}

static void
dissect_q2931_ie_contents(const u_char *pd, int offset, int len,
    proto_tree *tree, guint8 info_element)
{
	switch (info_element) {

	case Q2931_IE_BBAND_LOCKING_SHIFT:
	case Q2931_IE_BBAND_NLOCKING_SHIFT:
		dissect_q2931_shift_ie(pd, offset, len, tree, info_element);
		break;

	case Q2931_IE_NBAND_BEARER_CAP:
	case Q2931_IE_NBAND_LOW_LAYER_COMPAT:
		dissect_q931_bearer_capability_ie(pd, offset, len, tree);
		break;

	case Q2931_IE_NBAND_HIGH_LAYER_COMPAT:
		dissect_q931_high_layer_compat_ie(pd, offset, len, tree);
		break;

	case Q2931_IE_PROGRESS_INDICATOR:
		dissect_q931_progress_indicator_ie(pd, offset, len, tree);
		break;

	case Q2931_IE_AAL_PARAMETERS:
		dissect_q2931_aal_parameters_ie(pd, offset, len, tree);
		break;

	case Q2931_IE_ATM_USER_CELL_RATE:
		dissect_q2931_atm_cell_rate_ie(pd, offset, len, tree);
		break;

	case Q2931_IE_BBAND_BEARER_CAP:
		dissect_q2931_bband_bearer_cap_ie(pd, offset, len, tree);
		break;

	case Q2931_IE_BBAND_HI_LAYER_INFO:
		dissect_q2931_bband_hi_layer_info_ie(pd, offset, len, tree);
		break;

	case Q2931_IE_BBAND_LOW_LAYER_INFO:
		dissect_q2931_bband_low_layer_info_ie(pd, offset, len, tree);
		break;

	case Q2931_IE_CALL_STATE:
		dissect_q2931_call_state_ie(pd, offset, len, tree);
		break;

	case Q2931_IE_CALLED_PARTY_NUMBER:
	case Q2931_IE_CALLING_PARTY_NUMBER:
		dissect_q2931_number_ie(pd, offset, len, tree);
		break;

	case Q2931_IE_CALLED_PARTY_SUBADDR:
	case Q2931_IE_CALLING_PARTY_SUBADDR:
		dissect_q2931_party_subaddr_ie(pd, offset, len, tree);
		break;

	case Q2931_IE_CAUSE:
		dissect_q2931_cause_ie(pd, offset, len, tree);
		break;

	case Q2931_IE_CONNECTION_IDENTIFIER:
		dissect_q2931_connection_identifier_ie(pd, offset, len, tree);
		break;

	case Q2931_IE_E2E_TRANSIT_DELAY:
		dissect_q2931_e2e_transit_delay_ie(pd, offset, len, tree);
		break;

	case Q2931_IE_QOS_PARAMETER:
		dissect_q2931_qos_parameter_ie(pd, offset, len, tree);
		break;

	case Q2931_IE_BBAND_RPT_INDICATOR:
		dissect_q2931_bband_rpt_indicator(pd, offset, len, tree);
		break;

	case Q2931_IE_RESTART_INDICATOR:
		dissect_q2931_restart_indicator(pd, offset, len, tree);
		break;

	case Q2931_IE_BBAND_SENDING_COMPL:
		dissect_q2931_bband_sending_compl_ie(pd, offset, len, tree);
		break;

	case Q2931_IE_TRANSIT_NETWORK_SEL:
		dissect_q2931_transit_network_sel_ie(pd, offset, len, tree);
		break;

	case Q2931_IE_OAM_TRAFFIC_DESCRIPTOR:
		dissect_q2931_oam_traffic_descriptor_ie(pd, offset, len, tree);
		break;

	case Q2931_IE_ENDPOINT_REFERENCE:
		dissect_q2931_endpoint_reference_ie(pd, offset, len, tree);
		break;

	case Q2931_IE_ENDPOINT_STATE:
		dissect_q2931_endpoint_state_ie(pd, offset, len, tree);
		break;
	}
}

static void
dissect_q2931_ie(const u_char *pd, int offset, int len, proto_tree *tree,
    guint8 info_element, guint8 info_element_ext)
{
	proto_item	*ti;
	proto_tree	*ie_tree;
	proto_tree	*ie_ext_tree;

	ti = proto_tree_add_text(tree, offset, 1+1+2+len, "%s",
	    val_to_str(info_element, q2931_info_element_vals,
	      "Unknown information element (0x%02X)"));
	ie_tree = proto_item_add_subtree(ti, ett_q2931_ie);
	proto_tree_add_text(ie_tree, offset, 1, "Information element: %s",
	    val_to_str(info_element, q2931_info_element_vals,
	      "Unknown (0x%02X)"));
	ti = proto_tree_add_text(ie_tree, offset + 1, 1,
	    "Information element extension: 0x%02x",
	    info_element_ext);
	ie_ext_tree = proto_item_add_subtree(ti, ett_q2931_ie_ext);
	proto_tree_add_text(ie_ext_tree, offset + 1, 1,
	    decode_enumerated_bitfield(info_element_ext,
	        Q2931_IE_COMPAT_CODING_STD, 8,
		coding_std_vals, "Coding standard: %s"));
	proto_tree_add_text(ie_ext_tree, offset + 1, 1,
	    decode_boolean_bitfield(info_element_ext,
	    Q2931_IE_COMPAT_FOLLOW_INST, 8,
	    "Follow explicit error handling instructions",
  	    "Regular error handling procedures apply"));
	if (info_element_ext & Q2931_IE_COMPAT_FOLLOW_INST) {
		proto_tree_add_text(ie_ext_tree, offset + 1, 1,
		    decode_enumerated_bitfield(info_element_ext,
		        Q2931_IE_COMPAT_ACTION_IND, 8,
			ie_action_ind_vals,
			"Action indicator: %s"));
	}
	proto_tree_add_text(ie_tree, offset + 2, 2, "Length: %u", len);

	if ((info_element_ext & Q2931_IE_COMPAT_CODING_STD)
	    == Q2931_ITU_STANDARDIZED_CODING) {
		dissect_q2931_ie_contents(pd, offset + 4,
		    len, ie_tree, info_element);
	} else {
		/*
		 * We don't know how it's encoded, so just
		 * dump it as data and be done with it.
		 */
		proto_tree_add_text(ie_tree, offset + 4,  len,
		    "Data: %s", bytes_to_str(&pd[offset + 4], len));
	}
}

void
dissect_q2931(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_tree	*q2931_tree = NULL;
	proto_item	*ti;
	proto_tree	*ext_tree;
	guint8		call_ref_len;
	guint8		call_ref[15];
	guint8		message_type;
	guint8		message_type_ext;
	guint16		message_len;
	guint8		info_element;
	guint8		info_element_ext;
	guint16		info_element_len;
	int		codeset;
	gboolean	non_locking_shift;

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
	if (q2931_tree != NULL) {
		ti = proto_tree_add_item(q2931_tree, hf_q2931_message_type_ext,
		    offset, 1, message_type_ext);
		ext_tree = proto_item_add_subtree(ti, ett_q2931_ext);
		proto_tree_add_item(ext_tree, hf_q2931_message_flag,
		    offset, 1, message_type_ext);
		if (message_type_ext & Q2931_MSG_TYPE_EXT_FOLLOW_INST) {
			proto_tree_add_item(ext_tree, hf_q2931_message_action_indicator,
			    offset, 1, message_type_ext);
		}
	}
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
			dissect_q2931_ie(pd, offset, info_element_len,
			    q2931_tree, info_element, info_element_ext);
		}
		if (non_locking_shift)
			codeset = 0;

		/*
		 * Handle shifts.
		 */
		switch (info_element) {

		case Q2931_IE_BBAND_LOCKING_SHIFT:
			if (info_element_len >= 1) {
				non_locking_shift = FALSE;
				codeset = pd[offset + 4] & 0x07;
			}
			break;

		case Q2931_IE_BBAND_NLOCKING_SHIFT:
			if (info_element_len >= 1) {
				non_locking_shift = TRUE;
				codeset = pd[offset + 4] & 0x07;
			}
			break;
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

	{ &hf_q2931_message_flag,
	  { "Flag", "q2931.message_flag", FT_BOOLEAN, 8, TFS(&tos_msg_flag), Q2931_MSG_TYPE_EXT_FOLLOW_INST,
	  	"" }},

	{ &hf_q2931_message_action_indicator,
	  { "Action indicator", "q2931.message_action_indicator", FT_UINT8, BASE_DEC, VALS(msg_action_ind_vals), Q2931_MSG_TYPE_EXT_ACTION_IND,
	  	"" }},

	{ &hf_q2931_message_len,
	  { "Message length", "q2931.message_len", FT_UINT16, BASE_DEC, NULL, 0x0,
	  	"" }},

    };
    static gint *ett[] = {
        &ett_q2931,
        &ett_q2931_ext,
        &ett_q2931_ie,
        &ett_q2931_ie_ext,
        &ett_q2931_nsap,
    };

    proto_q2931 = proto_register_protocol ("Q.2931", "q2931");
    proto_register_field_array (proto_q2931, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}
