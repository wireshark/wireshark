/* packet-q2931.c
 * Routines for Q.2931 frame disassembly
 * Guy Harris <guy@alum.mit.edu>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/oui.h>
#include <epan/nlpid.h>
#include <epan/etypes.h>
#include "packet-q931.h"
#include "packet-arp.h"

/*
 * See
 *
 *	http://www.protocols.com/pbook/atmsig.htm
 *
 * for some information on Q.2931, although, alas, not the actual message
 * type and information element values - those I got from the FreeBSD 3.2
 * ATM code, and from Q.2931 (and Q.931) itself.
 */

void proto_register_q2931(void);

static int proto_q2931 = -1;
static int hf_q2931_discriminator = -1;
static int hf_q2931_call_ref_len = -1;
static int hf_q2931_call_ref_flag = -1;
static int hf_q2931_call_ref = -1;
static int hf_q2931_message_type = -1;
static int hf_q2931_message_type_ext = -1;
static int hf_q2931_message_flag = -1;
static int hf_q2931_message_action_indicator = -1;
static int hf_q2931_message_len = -1;
static int hf_q2931_ie_handling_instructions = -1;
static int hf_q2931_ie_coding_standard = -1;
static int hf_q2931_ie_action_indicator = -1;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_q2931_number_bytes = -1;
static int hf_q2931_conn_id_vci = -1;
static int hf_q2931_restart_indicator = -1;
static int hf_q2931_conn_id_vpci = -1;
static int hf_q2931_bband_low_layer_info_mode = -1;
static int hf_q2931_cause_rejection_insufficient_information_element = -1;
static int hf_q2931_bband_low_layer_info_user_info_l3_proto = -1;
static int hf_q2931_number_string = -1;
static int hf_q2931_aal1_backward_max_cpcs_sdu_size = -1;
static int hf_q2931_user_plane_connection_configuration = -1;
static int hf_q2931_party_subaddr_subaddress = -1;
static int hf_q2931_aal1_mode = -1;
static int hf_q2931_cause_location = -1;
static int hf_q2931_bband_low_layer_info_user_specified_l2_proto = -1;
static int hf_q2931_information_element = -1;
static int hf_q2931_conn_id_preferred_exclusive = -1;
static int hf_q2931_cause_vci = -1;
static int hf_q2931_cause_information_element = -1;
static int hf_q2931_oam_traffic_descriptor_backward_f5_flow_indicator = -1;
static int hf_q2931_cause_rejection_reason = -1;
static int hf_q2931_ethernet_type = -1;
static int hf_q2931_cause_value = -1;
static int hf_q2931_information_element_length = -1;
static int hf_q2931_cause_rejection_user_specific_diagnostic = -1;
static int hf_q2931_transit_network_sel_type = -1;
static int hf_q2931_user_defined_aal_information = -1;
static int hf_q2931_aal1_forward_max_cpcs_sdu_size = -1;
static int hf_q2931_atm_transfer_capability = -1;
static int hf_q2931_aal1_subtype = -1;
static int hf_q2931_information_element_extension = -1;
static int hf_q2931_party_subaddr_type_of_subaddress = -1;
static int hf_q2931_number_plan = -1;
static int hf_q2931_aal1_error_correction_method = -1;
static int hf_q2931_call_state = -1;
static int hf_q2931_bearer_class = -1;
static int hf_q2931_protocol_id = -1;
static int hf_q2931_information_element_data = -1;
static int hf_q2931_aal1_partially_filled_cells_method = -1;
static int hf_q2931_lane_protocol_id = -1;
static int hf_q2931_party_subaddr_odd_even_indicator = -1;
static int hf_q2931_qos_class_backward = -1;
static int hf_q2931_cause_rejection_condition = -1;
static int hf_q2931_aal1_source_clock_frequency_recovery_method = -1;
static int hf_q2931_broadband_repeat_indicator = -1;
static int hf_q2931_cause_rejection_missing_information_element = -1;
static int hf_q2931_e2e_transit_delay_maximum_end_to_end = -1;
static int hf_q2931_endpoint_reference_identifier_value = -1;
static int hf_q2931_cause_vpci = -1;
static int hf_q2931_endpoint_state = -1;
static int hf_q2931_high_layer_information_type = -1;
static int hf_q2931_transit_network_sel_network_id = -1;
static int hf_q2931_aal1_sscs_type = -1;
static int hf_q2931_bband_low_layer_info_packet_window_size = -1;
static int hf_q2931_aal1_structured_data_transfer_block_size = -1;
static int hf_q2931_cause_timer = -1;
static int hf_q2931_cause_message_type = -1;
static int hf_q2931_e2e_transit_delay_cumulative = -1;
static int hf_q2931_oam_traffic_descriptor_shaping_indicator = -1;
static int hf_q2931_oam_traffic_descriptor_forward_f5_flow_indicator = -1;
static int hf_q2931_organization_code = -1;
static int hf_q2931_bband_low_layer_info_additional_l3_proto = -1;
static int hf_q2931_transit_network_sel_plan = -1;
static int hf_q2931_bband_low_layer_info_user_info_l2_proto = -1;
static int hf_q2931_aal1_multiplier = -1;
static int hf_q2931_aal_type = -1;
static int hf_q2931_aal1_cbr_rate = -1;
static int hf_q2931_number_type = -1;
static int hf_q2931_cause_rejection_diagnostic = -1;
static int hf_q2931_bband_low_layer_info_default_packet_size = -1;
static int hf_q2931_susceptibility_to_clipping = -1;
static int hf_q2931_oam_traffic_descriptor_management_indicator = -1;
static int hf_q2931_qos_class_forward = -1;
static int hf_q2931_endpoint_reference_type = -1;
static int hf_q2931_number_presentation_indicator = -1;
static int hf_q2931_bband_low_layer_info_user_info_l1_proto = -1;
static int hf_q2931_number_screening_indicator = -1;
static int hf_q2931_bband_low_layer_info_window_size = -1;
static int hf_q2931_conn_id_vp_associated_signalling = -1;
static int hf_q2931_cause_cell_rate_subfield_identifier = -1;

static gint ett_q2931 = -1;
static gint ett_q2931_ext = -1;
static gint ett_q2931_ie = -1;
static gint ett_q2931_ie_ext = -1;
static gint ett_q2931_nsap = -1;

static void dissect_q2931_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree, guint8 info_element, guint8 info_element_ext);

/*
 * Q.2931 message types.
 */
#define	Q2931_ALERTING		0x01
#define	Q2931_CALL_PROCEEDING	0x02
#define	Q2931_PROGRESS		0x03
#define	Q2931_SETUP		0x05
#define	Q2931_CONNECT		0x07
#define	Q2931_SETUP_ACK		0x0B
#define	Q2931_CONNECT_ACK	0x0F
#define	Q2931_RESTART		0x46
#define	Q2931_RELEASE		0x4D
#define	Q2931_RESTART_ACK	0x4E
#define	Q2931_RELEASE_COMPLETE	0x5A
#define	Q2931_NOTIFY		0x6E
#define	Q2931_STATUS_ENQUIRY	0x75
#define	Q2931_INFORMATION	0x7B
#define	Q2931_STATUS		0x7D
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
	{ Q2931_PROGRESS,		"PROGRESS" },
	{ Q2931_SETUP,			"SETUP" },
	{ Q2931_CONNECT,		"CONNECT" },
	{ Q2931_SETUP_ACK,		"SETUP ACKNOWLEDGE" },
	{ Q2931_CONNECT_ACK,		"CONNECT ACKNOWLEDGE" },
	{ Q2931_RESTART,		"RESTART" },
	{ Q2931_RELEASE,		"RELEASE" },
	{ Q2931_RESTART_ACK,		"RESTART ACKNOWLEDGE" },
	{ Q2931_RELEASE_COMPLETE,	"RELEASE COMPLETE" },
	{ Q2931_NOTIFY,			"NOTIFY" },
	{ Q2931_STATUS_ENQUIRY,		"STATUS ENQUIRY" },
	{ Q2931_INFORMATION,		"INFORMATION" },
	{ Q2931_STATUS,			"STATUS" },
	{ Q2931_ADD_PARTY,		"ADD PARTY" },
	{ Q2931_ADD_PARTY_ACK,		"ADD PARTY ACKNOWLEDGE" },
	{ Q2931_ADD_PARTY_REJ,		"ADD PARTY REJECT" },
	{ Q2931_DROP_PARTY,		"DROP PARTY" },
	{ Q2931_DROP_PARTY_ACK,		"DROP PARTY ACKNOWLEDGE" },
	{ Q2931_LEAF_SETUP_FAIL,	"LEAF SETUP FAILURE" },
	{ Q2931_LEAF_SETUP_REQ,		"LEAF SETUP REQUEST" },
	{ 0,				NULL }
};

static value_string_ext q2931_message_type_vals_ext = VALUE_STRING_EXT_INIT(q2931_message_type_vals);

static const true_false_string tfs_call_ref_flag = {
	"Message sent to originating side",
	"Message sent from originating side"
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

static value_string_ext q2931_info_element_vals_ext = VALUE_STRING_EXT_INIT(q2931_info_element_vals);

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

static const true_false_string tfs_q2931_handling_instructions = { "Follow explicit error handling instructions",
																   "Regular error handling procedures apply" };

static void
dissect_q2931_shift_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree, guint8 info_element)
{
	gboolean non_locking_shift;
	guint8 codeset;

	if (len == 0)
		return;
	non_locking_shift = (info_element == Q2931_IE_BBAND_NLOCKING_SHIFT);
	codeset = tvb_get_guint8(tvb, offset) & 0x07;
	proto_tree_add_text(tree, tvb, offset, 1, "%s shift to codeset %u: %s",
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
	{ 0x03, "Circuit emulation (asynchronous)" },
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
	{ 0x02, "FEC method for delay-sensitive signal transport" },
	{ 0x00, NULL }
};

static const value_string q2931_aal_mode_vals[] = {
	{ 0x01, "Message" },
	{ 0x02, "Streaming" },
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
dissect_q2931_aal_parameters_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint8 aal_type;
	guint8 identifier;
	guint32 value;
	guint32 low_mid, high_mid;

	if (len == 0)
		return;
	aal_type = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_q2931_aal_type, tvb, offset, 1, ENC_NA);
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
		proto_tree_add_item(tree, hf_q2931_user_defined_aal_information, tvb, offset, len, ENC_NA);
		return;
	}

	while (len >= 0) {
		identifier = tvb_get_guint8(tvb, offset);
		switch (identifier) {

		case 0x85:	/* Subtype identifier for AAL1 */
			if (len < 2)
				return;
			value = tvb_get_guint8(tvb, offset + 1);
			proto_tree_add_uint(tree, hf_q2931_aal1_subtype, tvb, offset, 2, value);
			offset += 2;
			len -= 2;
			break;

		case 0x86:	/* CBR identifier for AAL1 */
			if (len < 2)
				return;
			value = tvb_get_guint8(tvb, offset + 1);
			proto_tree_add_uint(tree, hf_q2931_aal1_cbr_rate, tvb, offset, 2, value);
			offset += 2;
			len -= 2;
			break;

		case 0x87:	/* Multiplier identifier for AAL1 */
			if (len < 3)
				return;
			value = tvb_get_ntohs(tvb, offset + 1);
			proto_tree_add_uint(tree, hf_q2931_aal1_multiplier, tvb, offset, 3, value);
			offset += 3;
			len -= 3;
			break;

		case 0x88:	/* Source clock frequency recovery method identifier for AAL1 */
			if (len < 2)
				return;
			value = tvb_get_guint8(tvb, offset + 1);
			proto_tree_add_uint(tree, hf_q2931_aal1_source_clock_frequency_recovery_method, tvb, offset, 2, value);
			offset += 2;
			len -= 2;
			break;

		case 0x89:	/* Error correction method identifier for AAL1 */
			if (len < 2)
				return;
			value = tvb_get_guint8(tvb, offset + 1);
			proto_tree_add_uint(tree, hf_q2931_aal1_error_correction_method, tvb, offset, 2, value);
			offset += 2;
			len -= 2;
			break;

		case 0x8A:	/* Structured data transfer block size identifier for AAL1 */
			if (len < 3)
				return;
			value = tvb_get_ntohs(tvb, offset + 1);
			proto_tree_add_uint(tree, hf_q2931_aal1_structured_data_transfer_block_size, tvb, offset, 3, value);
			offset += 3;
			len -= 3;
			break;

		case 0x8B:	/* Partially filled cells identifier for AAL1 */
			if (len < 2)
				return;
			value = tvb_get_guint8(tvb, offset + 1);
			proto_tree_add_uint_format_value(tree, hf_q2931_aal1_partially_filled_cells_method, tvb, offset, 2,
			    value, "%u octets", value);
			offset += 2;
			len -= 2;
			break;

		case 0x8C:	/* Forward maximum CPCS-SDU size identifier for AAL3/4 and AAL5 */
			if (len < 3)
				return;
			value = tvb_get_ntohs(tvb, offset + 1);
			proto_tree_add_uint(tree, hf_q2931_aal1_forward_max_cpcs_sdu_size, tvb, offset, 3, value);
			offset += 3;
			len -= 3;
			break;

		case 0x81:	/* Backward maximum CPCS-SDU size identifier for AAL3/4 and AAL5 */
			if (len < 3)
				return;
			value = tvb_get_ntohs(tvb, offset + 1);
			proto_tree_add_uint(tree, hf_q2931_aal1_backward_max_cpcs_sdu_size, tvb, offset, 3, value);
			offset += 3;
			len -= 3;
			break;

		case 0x82:	/* MID range identifier for AAL3/4 */
			if (len < 5)
				return;
			low_mid = tvb_get_ntohs(tvb, offset + 1);
			high_mid = tvb_get_ntohs(tvb, offset + 3);
			proto_tree_add_text(tree, tvb, offset, 3,
			    "MID range: %u - %u", low_mid, high_mid);
			offset += 5;
			len -= 5;
			break;

		case 0x83:	/* Mode identifier for AAL3/4 and AAL5 */
			if (len < 2)
				return;
			value = tvb_get_guint8(tvb, offset + 1);
			proto_tree_add_uint(tree, hf_q2931_aal1_mode, tvb, offset, 2, value);
			offset += 2;
			len -= 2;
			break;

		case 0x84:	/* SSCS type identifier for AAL3/4 and AAL5 */
			if (len < 2)
				return;
			value = tvb_get_guint8(tvb, offset + 1);
			proto_tree_add_uint(tree, hf_q2931_aal1_sscs_type, tvb, offset, 2, value);
			offset += 2;
			len -= 2;
			break;

		default:	/* unknown AAL parameter */
			proto_tree_add_text(tree, tvb, offset, 1,
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
dissect_q2931_atm_cell_rate_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint8 identifier;
	guint32 value;

	while (len >= 0) {
		identifier = tvb_get_guint8(tvb, offset);
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
			value = tvb_get_ntoh24(tvb, offset + 1);
			proto_tree_add_text(tree, tvb, offset, 4,
			    "%s: %u cell%s/s",
			    val_to_str(identifier, q2931_atm_td_subfield_vals,
			      "Unknown (0x%02X)"),
			    value, plurality(value, "", "s"));
			offset += 4;
			len -= 4;
			break;

		case Q2931_ATM_CR_BEST_EFFORT_IND:
			/* Yes, its value *IS* 0xBE.... */
			proto_tree_add_text(tree, tvb, offset, 1,
			    "%s",
			    val_to_str(identifier, q2931_atm_td_subfield_vals,
			      "Unknown (0x%02X)"));
			offset += 1;
			len -= 1;
			break;

		case Q2931_ATM_CR_TRAFFIC_MGMT_OPT:
			if (len < 2)
				return;
			value = tvb_get_guint8(tvb, offset + 1);
			proto_tree_add_text(tree, tvb, offset, 2,
			    "%s",
			    val_to_str(identifier, q2931_atm_td_subfield_vals,
			      "Unknown (0x%02X)"));
			proto_tree_add_text(tree, tvb, offset + 1, 1,
			    "%s allowed in forward direction",
			    (value & 0x80) ? "Frame discard" : "No frame discard");
			proto_tree_add_text(tree, tvb, offset + 1, 1,
			    "%s allowed in backward direction",
			    (value & 0x40) ? "Frame discard" : "No frame discard");
			proto_tree_add_text(tree, tvb, offset + 1, 1,
			    "Tagging %srequested in backward direction",
			    (value & 0x02) ? "" : "not ");
			proto_tree_add_text(tree, tvb, offset + 1, 1,
			    "Tagging %srequested in forward direction",
			    (value & 0x01) ? "" : "not ");
			offset += 2;
			len -= 2;
			break;

		default:	/* unknown ATM traffic descriptor element */
			proto_tree_add_text(tree, tvb, offset, 1,
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

static void
dissect_q2931_bband_bearer_cap_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_q2931_bearer_class, tvb, offset, 1, ENC_NA);
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	if (!(octet & Q2931_IE_EXTENSION)) {
		proto_tree_add_item(tree, hf_q2931_atm_transfer_capability, tvb, offset, 1, ENC_NA);
		offset += 1;
		len -= 1;
	}

	if (len == 0)
		return;
	proto_tree_add_item(tree, hf_q2931_susceptibility_to_clipping, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_q2931_user_plane_connection_configuration, tvb, offset, 1, ENC_NA);
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

static void
dissect_q2931_bband_hi_layer_info_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	if (len == 0)
		return;

	proto_tree_add_item(tree, hf_q2931_high_layer_information_type, tvb, offset, 1, ENC_NA);
	/*offset += 1; */
	/* len -= 1; */
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

static const value_string lane_pid_vals[] = {
	{ 0x0001, "LE Configuration Direct/Control Direct/Control Distribute" },
	{ 0x0002, "Ethernet/IEEE 002.3 LE Data Direct" },
	{ 0x0003, "IEEE 802.5 LE Data Direct" },
	{ 0x0004, "Ethernet/IEEE 802.3 LE Multicast Send/Multicast Forward" },
	{ 0x0005, "IEEE 802.5 LE Multicast Send/Multicast Forward" },
	{ 0,      NULL },
};

/*
 * Dissect a broadband low layer information information element.
 */
static void
dissect_q2931_bband_low_layer_info_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;
	guint8 uil2_protocol;
	guint8 uil3_protocol;
	guint8 add_l3_info;
	guint32 organization_code;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	if ((octet & 0x60) == 0x20) {
		/*
		 * Layer 1 information.
		 */
		proto_tree_add_item(tree, hf_q2931_bband_low_layer_info_user_info_l1_proto, tvb, offset, 1, ENC_NA);
		offset += 1;
		len -= 1;
	}

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	if ((octet & 0x60) == 0x40) {
		/*
		 * Layer 2 information.
		 */
		uil2_protocol = octet & 0x1F;
		proto_tree_add_item(tree, hf_q2931_bband_low_layer_info_user_info_l2_proto, tvb, offset, 1, ENC_NA);
		offset += 1;
		len -= 1;

		if (octet & Q2931_IE_EXTENSION)
			goto l2_done;
		if (len == 0)
			return;
		octet = tvb_get_guint8(tvb, offset);
		if (uil2_protocol == Q2931_UIL2_USER_SPEC) {
			proto_tree_add_item(tree, hf_q2931_bband_low_layer_info_user_specified_l2_proto, tvb, offset, 1, ENC_NA);
		} else {
			proto_tree_add_item(tree, hf_q2931_bband_low_layer_info_mode, tvb, offset, 1, ENC_NA);
		}
		offset += 1;
		len -= 1;

		if (octet & Q2931_IE_EXTENSION)
			goto l2_done;
		if (len == 0)
			return;
		octet = tvb_get_guint8(tvb, offset);
		proto_tree_add_uint_format_value(tree, hf_q2931_bband_low_layer_info_window_size, tvb, offset, 1,
		    octet & 0x7F, "%u k", octet & 0x7F);
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
		proto_tree_add_item(tree, hf_q2931_bband_low_layer_info_user_info_l3_proto, tvb, offset, 1, ENC_NA);
		offset += 1;
		len -= 1;


		/*
		 * XXX - only in Low-layer compatibility information element.
		 */
		if (octet & Q2931_IE_EXTENSION)
			goto l3_done;
		if (len == 0)
			return;
		octet = tvb_get_guint8(tvb, offset);
		switch (uil3_protocol) {

		case Q2931_UIL3_X25_PL:
		case Q2931_UIL3_ISO_8208:
		case Q2931_UIL3_X223:
			proto_tree_add_item(tree, hf_q2931_bband_low_layer_info_mode, tvb, offset, 1, ENC_NA);
			offset += 1;
			len -= 1;

			if (octet & Q2931_IE_EXTENSION)
				goto l3_done;
			if (len == 0)
				return;
			octet = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(tree, hf_q2931_bband_low_layer_info_default_packet_size, tvb, offset, 1, ENC_NA);
			offset += 1;
			len -= 1;

			if (octet & Q2931_IE_EXTENSION)
				goto l3_done;
			if (len == 0)
				return;
			proto_tree_add_item(tree, hf_q2931_bband_low_layer_info_packet_window_size, tvb, offset, 1, ENC_NA);
			/*offset += 1;*/
			/*len -= 1;*/
			break;

		case Q2931_UIL3_USER_SPEC:
			proto_tree_add_uint_format_value(tree, hf_q2931_bband_low_layer_info_default_packet_size, tvb, offset, 1,
			    1 << (octet & 0x0F), "%u octets", 1 << (octet & 0x0F));
			/*offset += 1;*/
			/*len -= 1;*/
			break;

		case Q2931_UIL3_TR_9577:
			add_l3_info = (octet & 0x7F) << 1;
			if (octet & Q2931_IE_EXTENSION)
				goto l3_done;
			if (len < 2)
				return;
			add_l3_info |= (tvb_get_guint8(tvb, offset + 1) & 0x40) >> 6;
			proto_tree_add_uint(tree, hf_q2931_bband_low_layer_info_additional_l3_proto, tvb, offset, 2, add_l3_info);
			offset += 2;
			len -= 2;
			if (add_l3_info == NLPID_SNAP) {
				if (len < 6)
					return;
				offset += 1;
				/*len -= 1;*/
				organization_code = tvb_get_ntoh24(tvb, offset);
				proto_tree_add_item(tree, hf_q2931_organization_code, tvb, offset, 3, ENC_BIG_ENDIAN);
				offset += 3;
				/*len -= 3;*/

				switch (organization_code) {

				case OUI_ENCAP_ETHER:
					proto_tree_add_item(tree, hf_q2931_ethernet_type, tvb, offset, 2, ENC_BIG_ENDIAN);
					break;

				case OUI_ATM_FORUM:
					proto_tree_add_item(tree, hf_q2931_lane_protocol_id, tvb, offset, 2, ENC_BIG_ENDIAN);
					break;

				default:
					proto_tree_add_item(tree, hf_q2931_protocol_id, tvb, offset, 2, ENC_BIG_ENDIAN);
					break;
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
	{ 0x04,				"Send special information tone" },
	{ 0x05,				"Misdialled trunk prefix" },
	{ 0x06,				"Channel unacceptable" },
	{ 0x07,				"Call awarded and being delivered in an established channel" },
	{ 0x08,				"Preemption" },
	{ 0x09,				"Preemption - circuit reserved for reuse" },
	{ 0x0E,				"QoR: ported number" },
	{ 0x10,				"Normal call clearing" },
	{ 0x11,				"User busy" },
	{ 0x12,				"No user responding" },
	{ 0x13,				"No answer from user (user alerted)" },
	{ 0x14,				"Subscriber absent" },
	{ Q2931_CAUSE_CALL_REJECTED,	"Call rejected" },
	{ Q2931_CAUSE_NUMBER_CHANGED,	"Number changed" },
	{ 0x17,				"Redirection to new destination" },
	{ 0x18,				"Call rejected due to feature at the destination" },
	{ 0x19,				"Exchange routing error" },
	{ 0x1A,				"Non-selected user clearing" },
	{ 0x1B,				"Destination out of order" },
	{ 0x1C,				"Invalid number format (incomplete number)" },
	{ 0x1E,				"Response to STATUS ENQUIRY" },
	{ 0x1F,				"Normal unspecified" },
	{ 0x20,				"Too many pending add party request" },
	{ 0x23,				"Requested VPCI/VCI not available" },
	{ 0x24,				"VPCI/VCI assignment failure" },
	{ Q2931_CAUSE_CELL_RATE_UNAVAIL,"User cell rate not available" },
	{ 0x26,				"Network out of order" },
	{ 0x27,				"Permanent frame mode connection out of service" },
	{ 0x28,				"Permanent frame mode connection operational" },
	{ 0x29,				"Temporary failure" },
	{ 0x2A,				"Switching equipment congestion" },
	{ Q2931_CAUSE_ACCESS_INFO_DISC,	"Access information discarded" },
	{ 0x2C,				"Requested circuit/channel not available" },
	{ 0x2D,				"No VPCI/VCI available" },
	{ 0x2F,				"Resources unavailable, unspecified" },
	{ Q2931_CAUSE_QOS_UNAVAILABLE,	"Quality of service unavailable" },
	{ 0x32,				"Requested facility not subscribed" },
	{ 0x35,				"Outgoing calls barred within CUG" },
	{ 0x37,				"Incoming calls barred within CUG" },
	{ 0x39,				"Bearer capability not authorized" },
	{ 0x3A,				"Bearer capability not presently available" },
	{ 0x3E,				"Inconsistency in designated outgoing access information and subscriber class" },
	{ 0x3F,				"Service or option not available, unspecified" },
	{ 0x41,				"Bearer capability not implemented" },
	{ 0x42,				"Channel type not implemented" },
	{ 0x45,				"Requested facility not implemented" },
	{ 0x46,				"Only restricted digital information bearer capability is available" },
	{ 0x49,				"Unsupported combination of traffic parameters" },
	{ 0x4E,				"AAL parameters cannot be supported" },
	{ 0x4F,				"Service or option not implemented, unspecified" },
	{ 0x51,				"Invalid call reference value" },
	{ Q2931_CAUSE_CHAN_NONEXISTENT,	"Identified channel does not exist" },
	{ 0x53,				"Call identity does not exist for suspended call" },
	{ 0x54,				"Call identity in use" },
	{ 0x55,				"No call suspended" },
	{ 0x56,				"Call having the requested call identity has been cleared" },
	{ 0x57,				"Called user not member of CUG" },
	{ Q2931_CAUSE_INCOMPATIBLE_DEST,"Incompatible destination" },
	{ 0x59,				"Invalid endpoint reference" },
	{ 0x5A,				"Non-existent CUG" },
	{ 0x5B,				"Invalid transit network selection" },
	{ 0x5C,				"Too many pending ADD PARTY requests" },
	{ 0x5D,				"AAL parameters cannot be supported" },
	{ 0x5F,				"Invalid message, unspecified" },
	{ Q2931_CAUSE_MAND_IE_MISSING,	"Mandatory information element is missing" },
	{ Q2931_CAUSE_MT_NONEX_OR_UNIMPL,"Message type non-existent or not implemented" },
	{ 0x62,				"Message not compatible with call state or message type non-existent or not implemented" },
	{ Q2931_CAUSE_IE_NONEX_OR_UNIMPL,"Information element non-existent or not implemented" },
	{ Q2931_CAUSE_INVALID_IE_CONTENTS,"Invalid information element contents" },
	{ Q2931_CAUSE_MSG_INCOMPAT_W_CS,"Message not compatible with call state" },
	{ Q2931_CAUSE_REC_TIMER_EXP,	"Recovery on timer expiry" },
	{ 0x67,				"Parameter non-existent or not implemented - passed on" },
	{ 0x68,				"Incorrect message length" },
	{ 0x6E,				"Message with unrecognized parameter discarded" },
	{ 0x6F,				"Protocol error, unspecified" },
	{ 0x7F,				"Internetworking, unspecified" },
	{ 0,				NULL }
};

static value_string_ext q2931_cause_code_vals_ext = VALUE_STRING_EXT_INIT(q2931_cause_code_vals);

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
dissect_q2931_cause_ie(tvbuff_t *tvb, int offset, int len,
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
	proto_tree_add_item(tree, hf_q2931_cause_location, tvb, offset, 1, ENC_NA);
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	cause_value = octet & 0x7F;
	proto_tree_add_item(tree, hf_q2931_cause_value, tvb, offset, 1, ENC_NA);
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	switch (cause_value) {

	case Q2931_CAUSE_UNALLOC_NUMBER:
	case Q2931_CAUSE_NO_ROUTE_TO_DEST:
	case Q2931_CAUSE_QOS_UNAVAILABLE:
		octet = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Network service: %s",
		    (octet & 0x80) ? "User" : "Provider");
		proto_tree_add_text(tree, tvb, offset, 1,
		    "%s",
		    (octet & 0x40) ? "Abnormal" : "Normal");
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Condition: %s",
		    val_to_str(octet & 0x03, q2931_cause_condition_vals,
		      "Unknown (0x%X)"));
		break;

	case Q2931_CAUSE_CALL_REJECTED:
		rejection_reason = octet & 0x7C;
		proto_tree_add_item(tree, hf_q2931_cause_rejection_reason, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(tree, hf_q2931_cause_rejection_condition, tvb, offset, 1, ENC_NA);
		offset += 1;
		len -= 1;

		if (len == 0)
			return;
		switch (rejection_reason) {

		case Q2931_REJ_USER_SPECIFIC:
			proto_tree_add_item(tree, hf_q2931_cause_rejection_user_specific_diagnostic, tvb, offset, len, ENC_NA);
			break;

		case Q2931_REJ_IE_MISSING:
			proto_tree_add_item(tree, hf_q2931_cause_rejection_missing_information_element, tvb, offset, 1, ENC_NA);
			break;

		case Q2931_REJ_IE_INSUFFICIENT:
			proto_tree_add_item(tree, hf_q2931_cause_rejection_insufficient_information_element, tvb, offset, 1, ENC_NA);
			break;

		default:
			proto_tree_add_item(tree, hf_q2931_cause_rejection_diagnostic, tvb, offset, len, ENC_NA);
			break;
		}
		break;

	case Q2931_CAUSE_NUMBER_CHANGED:
		/*
		 * UNI 3.1 claims this "is formatted as the called party
		 * number information element, including information
		 * element identifier.
		 */
		info_element = tvb_get_guint8(tvb, offset);
		info_element_ext = tvb_get_guint8(tvb, offset + 1);
		info_element_len = tvb_get_ntohs(tvb, offset + 2);
		dissect_q2931_ie(tvb, offset, info_element_len, tree,
		    info_element, info_element_ext);
		break;

	case Q2931_CAUSE_ACCESS_INFO_DISC:
	case Q2931_CAUSE_INCOMPATIBLE_DEST:
	case Q2931_CAUSE_MAND_IE_MISSING:
	case Q2931_CAUSE_IE_NONEX_OR_UNIMPL:
	case Q2931_CAUSE_INVALID_IE_CONTENTS:
		do {
			proto_tree_add_item(tree, hf_q2931_cause_information_element, tvb, offset, 1, ENC_NA);
			offset += 1;
			len -= 1;
		} while (len >= 0);
		break;

	case Q2931_CAUSE_CELL_RATE_UNAVAIL:
		do {
			proto_tree_add_item(tree, hf_q2931_cause_cell_rate_subfield_identifier, tvb, offset, 1, ENC_NA);
			offset += 1;
			len -= 1;
		} while (len >= 0);
		break;

	case Q2931_CAUSE_CHAN_NONEXISTENT:
		if (len < 2)
			return;
		proto_tree_add_item(tree, hf_q2931_cause_vpci, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		len -= 2;

		if (len < 2)
			return;
		proto_tree_add_item(tree, hf_q2931_cause_vci, tvb, offset, 2, ENC_BIG_ENDIAN);
		break;

	case Q2931_CAUSE_MT_NONEX_OR_UNIMPL:
	case Q2931_CAUSE_MSG_INCOMPAT_W_CS:
		proto_tree_add_item(tree, hf_q2931_cause_message_type, tvb, offset, 1, ENC_NA);
		break;

	case Q2931_CAUSE_REC_TIMER_EXP:
		if (len < 3)
			return;
		proto_tree_add_item(tree, hf_q2931_cause_timer, tvb, offset, 3, ENC_ASCII|ENC_NA);
		break;

	default:
		proto_tree_add_item(tree, hf_q2931_cause_rejection_diagnostic, tvb, offset, len, ENC_NA);
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
dissect_q2931_call_state_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	if (len == 0)
		return;

	proto_tree_add_item(tree, hf_q2931_call_state, tvb, offset, 1, ENC_NA);
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
dissect_q2931_number_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;
	guint8 numbering_plan;
	proto_item *ti;
	proto_tree *nsap_tree;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_q2931_number_type, tvb, offset, 1, ENC_NA);
	numbering_plan = octet & 0x0F;
	proto_tree_add_item(tree, hf_q2931_number_plan, tvb, offset, 1, ENC_NA);
	offset += 1;
	len -= 1;

	if (!(octet & Q2931_IE_EXTENSION)) {
		if (len == 0)
			return;

		proto_tree_add_item(tree, hf_q2931_number_presentation_indicator, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(tree, hf_q2931_number_screening_indicator, tvb, offset, 1, ENC_NA);
		offset += 1;
		len -= 1;
	}

	if (len == 0)
		return;
	switch (numbering_plan) {

	case Q2931_ISDN_NUMBERING:
		proto_tree_add_item(tree, hf_q2931_number_string, tvb, offset, len, ENC_ASCII|ENC_NA);
		break;

	case Q2931_NSAP_ADDRESSING:
		if (len < 20) {
			proto_tree_add_text(tree, tvb, offset, len,
			    "Number (too short): %s",
			    tvb_bytes_to_ep_str(tvb, offset, len));
			return;
		}
		ti = proto_tree_add_text(tree, tvb, offset, len, "Number");
		nsap_tree = proto_item_add_subtree(ti, ett_q2931_nsap);
		dissect_atm_nsap(tvb, offset, len, nsap_tree);
		break;

	default:
		proto_tree_add_item(tree, hf_q2931_number_bytes, tvb, offset, len, ENC_NA);
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
dissect_q2931_party_subaddr_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	if (len == 0)
		return;

	proto_tree_add_item(tree, hf_q2931_party_subaddr_type_of_subaddress, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_q2931_party_subaddr_odd_even_indicator, tvb, offset, 1, ENC_NA);
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	proto_tree_add_item(tree, hf_q2931_party_subaddr_subaddress, tvb, offset, len, ENC_NA);
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
dissect_q2931_connection_identifier_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	if (len == 0)
		return;

	proto_tree_add_item(tree, hf_q2931_conn_id_vp_associated_signalling, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_q2931_conn_id_preferred_exclusive, tvb, offset, 1, ENC_NA);
	offset += 1;
	len -= 1;

	if (len < 2)
		return;
	proto_tree_add_item(tree, hf_q2931_conn_id_vpci, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	len -= 2;

	if (len < 2)
		return;
	proto_tree_add_item(tree, hf_q2931_conn_id_vci, tvb, offset, 2, ENC_BIG_ENDIAN);
}

/*
 * Dissect an End-to-end transit delay information element.
 */
static void
dissect_q2931_e2e_transit_delay_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint8 identifier;
	guint16 value;

	while (len >= 3) {
		identifier = tvb_get_guint8(tvb, offset);
		value = tvb_get_ntohs(tvb, offset + 1);
		len -=3;
		switch (identifier) {

		case 0x01:	/* Cumulative transit delay identifier */
			proto_tree_add_uint_format_value(tree, hf_q2931_e2e_transit_delay_cumulative, tvb, offset, 3,
			    value, "%u ms", value);
			break;

		case 0x03:	/* Maximum transit delay identifier */
			if (value == 0xFFFF) {
				proto_tree_add_uint_format_value(tree, hf_q2931_e2e_transit_delay_maximum_end_to_end, tvb, offset, 3,
				    value, "Any end-to-end transit delay value acceptable");
			} else {
				proto_tree_add_uint_format_value(tree, hf_q2931_e2e_transit_delay_maximum_end_to_end, tvb, offset, 3,
				    value, "%u ms", value);
			}
			break;

		default:	/* Unknown transit delay identifier */
			proto_tree_add_text(tree, tvb, offset, 1,
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
dissect_q2931_qos_parameter_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	if (len == 0)
		return;

	proto_tree_add_item(tree, hf_q2931_qos_class_forward, tvb, offset, 1, ENC_NA);
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	proto_tree_add_item(tree, hf_q2931_qos_class_backward, tvb, offset, 1, ENC_NA);
}

/*
 * Dissect a broadband repeat indicator.
 */
static const value_string q2931_bband_rpt_indicator_vals[] = {
	{ 0x02, "Prioritized list for selecting one possibility (descending order)" },
	{ 0x00, NULL }
};

static void
dissect_q2931_bband_rpt_indicator(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	if (len == 0)
		return;

	proto_tree_add_item(tree, hf_q2931_broadband_repeat_indicator, tvb, offset, 1, ENC_NA);
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
dissect_q2931_restart_indicator(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	if (len == 0)
		return;

	proto_tree_add_item(tree, hf_q2931_restart_indicator, tvb, offset, 1, ENC_NA);
}

/*
 * Dissect an broadband sending complete information element.
 */
static void
dissect_q2931_bband_sending_compl_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint8 identifier;

	while (len >= 0) {
		identifier = tvb_get_guint8(tvb, offset);
		switch (identifier) {

		case 0xA1:	/* Sending complete indication */
			proto_tree_add_text(tree, tvb, offset, 1,
			    "Broadband sending complete indication");
			offset += 1;
			len -= 1;
			break;

		default:	/* unknown broadband sending complete element */
			proto_tree_add_text(tree, tvb, offset, 1,
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
dissect_q2931_transit_network_sel_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	if (len == 0)
		return;

	proto_tree_add_item(tree, hf_q2931_transit_network_sel_type, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_q2931_transit_network_sel_plan, tvb, offset, 1, ENC_NA);
	offset += 1;
	len -= 1;

	if (len == 0)
		return;
	proto_tree_add_item(tree, hf_q2931_transit_network_sel_network_id, tvb, offset, len, ENC_NA|ENC_ASCII);
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
	{ 0x00, "No user-originated fault management indications" },
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
dissect_q2931_oam_traffic_descriptor_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint8 octet;

	if (len == 0)
		return;
	octet = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_q2931_oam_traffic_descriptor_shaping_indicator, tvb, offset, 1, ENC_NA);
	proto_tree_add_text(tree, tvb, offset, 1,
	    "Use of end-to-end OAM F5 flow is %s",
	    (octet & 0x10) ? "mandatory" : "optional");
	proto_tree_add_item(tree, hf_q2931_oam_traffic_descriptor_management_indicator, tvb, offset, 1, ENC_NA);
	offset += 1;
	len -= 1;

	if (len == 0)
		return;

	proto_tree_add_item(tree, hf_q2931_oam_traffic_descriptor_forward_f5_flow_indicator, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_q2931_oam_traffic_descriptor_backward_f5_flow_indicator, tvb, offset, 1, ENC_NA);
}

/*
 * Dissect an Endpoint reference information element.
 */
static const value_string q2931_endpoint_reference_type_vals[] = {
	{ 0x00, "Locally defined integer" },
	{ 0,    NULL }
};

static void
dissect_q2931_endpoint_reference_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	guint16 value;

	if (len == 0)
		return;

	proto_tree_add_item(tree, hf_q2931_endpoint_reference_type, tvb, offset, 1, ENC_NA);
	offset += 1;
	len -= 1;

	if (len < 2)
		return;
	value = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2,
	    "Endpoint reference flag: %s",
	    (value & 0x8000) ? "Message sent to side that originates the endpoint reference" :
			       "Message sent from side that originates the endpoint reference");
	proto_tree_add_item(tree, hf_q2931_endpoint_reference_identifier_value, tvb, offset, 2, ENC_BIG_ENDIAN);
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
dissect_q2931_endpoint_state_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree)
{
	if (len == 0)
		return;

	proto_tree_add_item(tree, hf_q2931_endpoint_state, tvb, offset, 1, ENC_NA);
}

static void
dissect_q2931_ie_contents(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree, guint8 info_element)
{
	switch (info_element) {

	case Q2931_IE_BBAND_LOCKING_SHIFT:
	case Q2931_IE_BBAND_NLOCKING_SHIFT:
		dissect_q2931_shift_ie(tvb, offset, len, tree, info_element);
		break;

	case Q2931_IE_NBAND_BEARER_CAP:
	case Q2931_IE_NBAND_LOW_LAYER_COMPAT:
		dissect_q931_bearer_capability_ie(tvb, offset, len, tree);
		break;

	case Q2931_IE_NBAND_HIGH_LAYER_COMPAT:
		dissect_q931_high_layer_compat_ie(tvb, offset, len, tree);
		break;

	case Q2931_IE_PROGRESS_INDICATOR:
		dissect_q931_progress_indicator_ie(tvb, offset, len, tree);
		break;

	case Q2931_IE_AAL_PARAMETERS:
		dissect_q2931_aal_parameters_ie(tvb, offset, len, tree);
		break;

	case Q2931_IE_ATM_USER_CELL_RATE:
		dissect_q2931_atm_cell_rate_ie(tvb, offset, len, tree);
		break;

	case Q2931_IE_BBAND_BEARER_CAP:
		dissect_q2931_bband_bearer_cap_ie(tvb, offset, len, tree);
		break;

	case Q2931_IE_BBAND_HI_LAYER_INFO:
		dissect_q2931_bband_hi_layer_info_ie(tvb, offset, len, tree);
		break;

	case Q2931_IE_BBAND_LOW_LAYER_INFO:
		dissect_q2931_bband_low_layer_info_ie(tvb, offset, len, tree);
		break;

	case Q2931_IE_CALL_STATE:
		dissect_q2931_call_state_ie(tvb, offset, len, tree);
		break;

	case Q2931_IE_CALLED_PARTY_NUMBER:
	case Q2931_IE_CALLING_PARTY_NUMBER:
		dissect_q2931_number_ie(tvb, offset, len, tree);
		break;

	case Q2931_IE_CALLED_PARTY_SUBADDR:
	case Q2931_IE_CALLING_PARTY_SUBADDR:
		dissect_q2931_party_subaddr_ie(tvb, offset, len, tree);
		break;

	case Q2931_IE_CAUSE:
		dissect_q2931_cause_ie(tvb, offset, len, tree);
		break;

	case Q2931_IE_CONNECTION_IDENTIFIER:
		dissect_q2931_connection_identifier_ie(tvb, offset, len, tree);
		break;

	case Q2931_IE_E2E_TRANSIT_DELAY:
		dissect_q2931_e2e_transit_delay_ie(tvb, offset, len, tree);
		break;

	case Q2931_IE_QOS_PARAMETER:
		dissect_q2931_qos_parameter_ie(tvb, offset, len, tree);
		break;

	case Q2931_IE_BBAND_RPT_INDICATOR:
		dissect_q2931_bband_rpt_indicator(tvb, offset, len, tree);
		break;

	case Q2931_IE_RESTART_INDICATOR:
		dissect_q2931_restart_indicator(tvb, offset, len, tree);
		break;

	case Q2931_IE_BBAND_SENDING_COMPL:
		dissect_q2931_bband_sending_compl_ie(tvb, offset, len, tree);
		break;

	case Q2931_IE_TRANSIT_NETWORK_SEL:
		dissect_q2931_transit_network_sel_ie(tvb, offset, len, tree);
		break;

	case Q2931_IE_OAM_TRAFFIC_DESCRIPTOR:
		dissect_q2931_oam_traffic_descriptor_ie(tvb, offset, len, tree);
		break;

	case Q2931_IE_ENDPOINT_REFERENCE:
		dissect_q2931_endpoint_reference_ie(tvb, offset, len, tree);
		break;

	case Q2931_IE_ENDPOINT_STATE:
		dissect_q2931_endpoint_state_ie(tvb, offset, len, tree);
		break;
	}
}

static void
dissect_q2931_ie(tvbuff_t *tvb, int offset, int len, proto_tree *tree,
    guint8 info_element, guint8 info_element_ext)
{
	proto_item	*ti;
	proto_tree	*ie_tree;
	proto_tree	*ie_ext_tree;

	ti = proto_tree_add_text(tree, tvb, offset, 1+1+2+len, "%s",
	    val_to_str_ext(info_element, &q2931_info_element_vals_ext,
	      "Unknown information element (0x%02X)"));
	ie_tree = proto_item_add_subtree(ti, ett_q2931_ie);
	proto_tree_add_uint(ie_tree, hf_q2931_information_element, tvb, offset, 1, info_element);
	ti = proto_tree_add_uint(ie_tree, hf_q2931_information_element_extension, tvb, offset + 1, 1, info_element_ext);
	ie_ext_tree = proto_item_add_subtree(ti, ett_q2931_ie_ext);
	proto_tree_add_item(ie_ext_tree, hf_q2931_ie_coding_standard, tvb, offset+1, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(ie_ext_tree, hf_q2931_ie_handling_instructions, tvb, offset+1, 1, ENC_BIG_ENDIAN);
	if (info_element_ext & Q2931_IE_COMPAT_FOLLOW_INST) {
	    proto_tree_add_item(ie_ext_tree, hf_q2931_ie_action_indicator, tvb, offset+1, 1, ENC_BIG_ENDIAN);
	}
	proto_tree_add_uint(ie_tree, hf_q2931_information_element_length, tvb, offset + 2, 2, len);

	if ((info_element_ext & Q2931_IE_COMPAT_CODING_STD)
	    == Q2931_ITU_STANDARDIZED_CODING) {
		dissect_q2931_ie_contents(tvb, offset + 4,
		    len, ie_tree, info_element);
	} else {
		/*
		 * We don't know how it's encoded, so just
		 * dump it as data and be done with it.
		 */
		proto_tree_add_item(ie_tree, hf_q2931_information_element_data, tvb, offset + 4, len, ENC_NA);
	}
}

static void
dissect_q2931(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int		offset = 0;
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
#if 0
	int		codeset;
	gboolean	non_locking_shift;
#endif

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Q.2931");

	if (tree) {
		ti = proto_tree_add_item(tree, proto_q2931, tvb, offset, -1,
		    ENC_NA);
		q2931_tree = proto_item_add_subtree(ti, ett_q2931);

		proto_tree_add_uint(q2931_tree, hf_q2931_discriminator, tvb, offset, 1, tvb_get_guint8(tvb, offset));
	}
	offset += 1;
	call_ref_len = tvb_get_guint8(tvb, offset) & 0xF;	/* XXX - do as a bit field? */
	if (q2931_tree != NULL)
		proto_tree_add_uint(q2931_tree, hf_q2931_call_ref_len, tvb, offset, 1, call_ref_len);
	offset += 1;
	if (call_ref_len != 0) {
		tvb_memcpy(tvb, call_ref, offset, call_ref_len);
		if (q2931_tree != NULL) {
			proto_tree_add_boolean(q2931_tree, hf_q2931_call_ref_flag,
			    tvb, offset, 1, (call_ref[0] & 0x80) != 0);
			call_ref[0] &= 0x7F;
			proto_tree_add_bytes(q2931_tree, hf_q2931_call_ref, tvb, offset, call_ref_len, call_ref);
		}
		offset += call_ref_len;
	}
	message_type = tvb_get_guint8(tvb, offset);
	col_add_str(pinfo->cinfo, COL_INFO,
		    val_to_str_ext(message_type, &q2931_message_type_vals_ext,
		      "Unknown message type (0x%02X)"));

	if (q2931_tree != NULL)
		proto_tree_add_uint(q2931_tree, hf_q2931_message_type, tvb, offset, 1, message_type);
	offset += 1;

	message_type_ext = tvb_get_guint8(tvb, offset);
	if (q2931_tree != NULL) {
		ti = proto_tree_add_uint(q2931_tree, hf_q2931_message_type_ext, tvb,
		    offset, 1, message_type_ext);
		ext_tree = proto_item_add_subtree(ti, ett_q2931_ext);
		proto_tree_add_boolean(ext_tree, hf_q2931_message_flag, tvb,
		    offset, 1, message_type_ext);
		if (message_type_ext & Q2931_MSG_TYPE_EXT_FOLLOW_INST) {
			proto_tree_add_uint(ext_tree, hf_q2931_message_action_indicator, tvb,
			    offset, 1, message_type_ext);
		}
	}
	offset += 1;

	message_len = tvb_get_ntohs(tvb, offset);
	if (q2931_tree != NULL)
		proto_tree_add_uint(q2931_tree, hf_q2931_message_len, tvb, offset, 2, message_len);
	offset += 2;

	/*
	 * And now for the information elements....
	 */
#if 0
	codeset = 0;	/* start out in codeset 0 */
	non_locking_shift = TRUE;
#endif
	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		info_element = tvb_get_guint8(tvb, offset);
		info_element_ext = tvb_get_guint8(tvb, offset + 1);
		info_element_len = tvb_get_ntohs(tvb, offset + 2);
		if (q2931_tree != NULL) {
			dissect_q2931_ie(tvb, offset, info_element_len,
			    q2931_tree, info_element, info_element_ext);
		}
#if 0 /* XXX: Is codeset & etc supoosed to be used somehow ? */
		if (non_locking_shift)
			codeset = 0;
		/*
		 * Handle shifts.
		 */
		switch (info_element) {

		case Q2931_IE_BBAND_LOCKING_SHIFT:
			if (info_element_len >= 1) {
				non_locking_shift = FALSE;
				codeset = tvb_get_guint8(tvb, offset + 4) & 0x07;
			}
			break;

		case Q2931_IE_BBAND_NLOCKING_SHIFT:
			if (info_element_len >= 1) {
				non_locking_shift = TRUE;
				codeset = tvb_get_guint8(tvb, offset + 4) & 0x07;
			}
			break;
		}
#endif
		offset += 1 + 1 + 2 + info_element_len;
	}
}

void
proto_register_q2931(void)
{
	static hf_register_info hf[] = {
		{ &hf_q2931_discriminator,
		  { "Protocol discriminator", "q2931.disc", FT_UINT8, BASE_HEX, NULL, 0x0,
		  	NULL, HFILL }},

		{ &hf_q2931_call_ref_len,
		  { "Call reference value length", "q2931.call_ref_len", FT_UINT8, BASE_DEC, NULL, 0x0,
		  	NULL, HFILL }},

		{ &hf_q2931_call_ref_flag,
		  { "Call reference flag", "q2931.call_ref_flag", FT_BOOLEAN, BASE_NONE, TFS(&tfs_call_ref_flag), 0x0,
		  	NULL, HFILL }},

		{ &hf_q2931_call_ref,
		  { "Call reference value", "q2931.call_ref", FT_BYTES, BASE_NONE, NULL, 0x0,
		  	NULL, HFILL }},

		{ &hf_q2931_message_type,
		  { "Message type", "q2931.message_type", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &q2931_message_type_vals_ext, 0x0,
		  	NULL, HFILL }},

		{ &hf_q2931_message_type_ext,
		  { "Message type extension", "q2931.message_type_ext", FT_UINT8, BASE_HEX, NULL, 0x0,
		  	NULL, HFILL }},

		{ &hf_q2931_message_flag,
		  { "Flag", "q2931.message_flag", FT_BOOLEAN, 8, TFS(&tos_msg_flag), Q2931_MSG_TYPE_EXT_FOLLOW_INST,
		  	NULL, HFILL }},

		{ &hf_q2931_message_action_indicator,
		  { "Action indicator", "q2931.message_action_indicator", FT_UINT8, BASE_DEC, VALS(msg_action_ind_vals), Q2931_MSG_TYPE_EXT_ACTION_IND,
		  	NULL, HFILL }},

		{ &hf_q2931_message_len,
		  { "Message length", "q2931.message_len", FT_UINT16, BASE_DEC, NULL, 0x0,
		  	NULL, HFILL }},

		{ &hf_q2931_ie_handling_instructions,
		  { "Handling Instructions", "q2931.ie_handling_instructions", FT_BOOLEAN, 8, TFS(&tfs_q2931_handling_instructions), Q2931_IE_COMPAT_FOLLOW_INST,
		  	NULL, HFILL }},

		{ &hf_q2931_ie_coding_standard,
		  { "Coding standard", "q2931.ie_coding_standard", FT_UINT8, BASE_DEC, VALS(coding_std_vals), Q2931_IE_COMPAT_CODING_STD,
		  	NULL, HFILL }},

		{ &hf_q2931_ie_action_indicator,
		  { "Action indicator", "q2931.ie_action_indicator", FT_UINT8, BASE_DEC, VALS(ie_action_ind_vals), Q2931_IE_COMPAT_ACTION_IND,
		  	NULL, HFILL }},

      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_q2931_aal_type, { "AAL type", "q2931.aal_type", FT_UINT8, BASE_HEX, VALS(q9231_aal_type_vals), 0x0, NULL, HFILL }},
      { &hf_q2931_user_defined_aal_information, { "User defined AAL information", "q2931.user_defined_aal_information", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_q2931_aal1_subtype, { "Subtype", "q2931.aal1.subtype", FT_UINT8, BASE_HEX, VALS(q9231_aal1_subtype_vals), 0x0, NULL, HFILL }},
      { &hf_q2931_aal1_cbr_rate, { "CBR rate", "q2931.aal1.cbr_rate", FT_UINT8, BASE_HEX, VALS(q9231_aal1_cbr_rate_vals), 0x0, NULL, HFILL }},
      { &hf_q2931_aal1_multiplier, { "Multiplier", "q2931.aal1.multiplier", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_q2931_aal1_source_clock_frequency_recovery_method, { "Source clock frequency recovery method", "q2931.aal1.source_clock_frequency_recovery_method", FT_UINT8, BASE_HEX, VALS(q2931_aal1_src_clk_rec_meth_vals), 0x0, NULL, HFILL }},
      { &hf_q2931_aal1_error_correction_method, { "Error correction method", "q2931.aal1.error_correction_method", FT_UINT8, BASE_HEX, VALS(q2931_aal1_err_correction_method_vals), 0x0, NULL, HFILL }},
      { &hf_q2931_aal1_structured_data_transfer_block_size, { "Structured data transfer block size", "q2931.aal1.structured_data_transfer_block_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_q2931_aal1_partially_filled_cells_method, { "Partially filled cells method", "q2931.aal1.partially_filled_cells_method", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_q2931_aal1_forward_max_cpcs_sdu_size, { "Forward maximum CPCS-SDU size", "q2931.aal1.forward_max_cpcs_sdu_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_q2931_aal1_backward_max_cpcs_sdu_size, { "Backward maximum CPCS-SDU size", "q2931.aal1.backward_max_cpcs_sdu_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_q2931_aal1_mode, { "Mode", "q2931.aal1.mode", FT_UINT8, BASE_HEX, VALS(q2931_aal_mode_vals), 0x0, NULL, HFILL }},
      { &hf_q2931_aal1_sscs_type, { "SSCS type", "q2931.aal1.sscs_type", FT_UINT8, BASE_HEX, VALS(q2931_sscs_type_vals), 0x0, NULL, HFILL }},
      { &hf_q2931_bearer_class, { "Bearer class", "q2931.bearer_class", FT_UINT8, BASE_HEX, VALS(q2931_bearer_class_vals), 0x1F, NULL, HFILL }},
      { &hf_q2931_atm_transfer_capability, { "ATM Transfer Capability", "q2931.atm_transfer_capability", FT_UINT8, BASE_HEX, VALS(q2931_transfer_capability_vals), 0x1F, NULL, HFILL }},
      { &hf_q2931_susceptibility_to_clipping, { "Susceptibility to clipping", "q2931.susceptibility_to_clipping", FT_UINT8, BASE_HEX, VALS(q2931_susc_clip_vals), 0x60, NULL, HFILL }},
      { &hf_q2931_user_plane_connection_configuration, { "User-plane connection configuration", "q2931.user_plane_connection_configuration", FT_UINT8, BASE_HEX, VALS(q2931_up_conn_config_vals), 0x03, NULL, HFILL }},
      { &hf_q2931_high_layer_information_type, { "High layer information type", "q2931.high_layer_information_type", FT_UINT8, BASE_HEX, VALS(q2931_hi_layer_info_type_vals), 0x7F, NULL, HFILL }},
      { &hf_q2931_bband_low_layer_info_user_info_l1_proto, { "User information layer 1 protocol", "q2931.bband_low_layer_info.user_info_l1_proto", FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL }},
      { &hf_q2931_bband_low_layer_info_user_info_l2_proto, { "User information layer 2 protocol", "q2931.bband_low_layer_info.user_info_l2_proto", FT_UINT8, BASE_HEX, VALS(q2931_uil2_vals), 0x1F, NULL, HFILL }},
      { &hf_q2931_bband_low_layer_info_user_specified_l2_proto, { "User-specified layer 2 protocol information", "q2931.bband_low_layer_info.user_specified_l2_proto", FT_UINT8, BASE_HEX, NULL, 0x7F, NULL, HFILL }},
      { &hf_q2931_bband_low_layer_info_mode, { "Mode", "q2931.bband_low_layer_info.mode", FT_UINT8, BASE_HEX, VALS(q2931_mode_vals), 0x60, NULL, HFILL }},
      { &hf_q2931_bband_low_layer_info_window_size, { "Window size", "q2931.bband_low_layer_info.window_size", FT_UINT8, BASE_DEC, NULL, 0x7F, NULL, HFILL }},
      { &hf_q2931_bband_low_layer_info_user_info_l3_proto, { "User information layer 3 protocol", "q2931.bband_low_layer_info.user_info_l3_proto", FT_UINT8, BASE_HEX, VALS(q2931_uil3_vals), 0x1F, NULL, HFILL }},
      { &hf_q2931_bband_low_layer_info_default_packet_size, { "Default packet size", "q2931.bband_low_layer_info.default_packet_size", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }},
      { &hf_q2931_bband_low_layer_info_packet_window_size, { "Packet window size", "q2931.bband_low_layer_info.packet_window_size", FT_UINT8, BASE_DEC, NULL, 0x7F, NULL, HFILL }},
      { &hf_q2931_bband_low_layer_info_additional_l3_proto, { "Additional layer 3 protocol information", "q2931.bband_low_layer_info.additional_l3_proto", FT_UINT8, BASE_HEX, VALS(nlpid_vals), 0x0, NULL, HFILL }},
      { &hf_q2931_organization_code, { "Organization Code", "q2931.bband_low_layer_info.organization_code", FT_UINT24, BASE_HEX, VALS(oui_vals), 0x0, NULL, HFILL }},
      { &hf_q2931_ethernet_type, { "Ethernet type", "q2931.bband_low_layer_info.ethernet_type", FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0, NULL, HFILL }},
      { &hf_q2931_lane_protocol_id, { "LANE Protocol ID", "q2931.bband_low_layer_info.lane_protocol_id", FT_UINT16, BASE_HEX, VALS(lane_pid_vals), 0x0, NULL, HFILL }},
      { &hf_q2931_protocol_id, { "Protocol ID", "q2931.bband_low_layer_info.protocol_id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_q2931_cause_location, { "Location", "q2931.cause.location", FT_UINT8, BASE_HEX, VALS(q2931_cause_location_vals), 0x0F, NULL, HFILL }},
      { &hf_q2931_cause_value, { "Cause value", "q2931.cause.value", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &q2931_cause_code_vals_ext, 0x7F, NULL, HFILL }},
      { &hf_q2931_cause_rejection_reason, { "Rejection reason", "q2931.cause.rejection.reason", FT_UINT8, BASE_HEX, VALS(q2931_rejection_reason_vals), 0x7C, NULL, HFILL }},
      { &hf_q2931_cause_rejection_condition, { "Condition", "q2931.cause.rejection.condition", FT_UINT8, BASE_HEX, VALS(q2931_cause_condition_vals), 0x03, NULL, HFILL }},
      { &hf_q2931_cause_rejection_user_specific_diagnostic, { "User specific diagnostic", "q2931.cause.rejection.user_specific_diagnostic", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_q2931_cause_rejection_missing_information_element, { "Missing information element", "q2931.cause.rejection.missing_information_element", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &q2931_info_element_vals_ext, 0x0, NULL, HFILL }},
      { &hf_q2931_cause_rejection_insufficient_information_element, { "Insufficient information element", "q2931.cause.rejection.insufficient_information_element", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &q2931_info_element_vals_ext, 0x0, NULL, HFILL }},
      { &hf_q2931_cause_rejection_diagnostic, { "Diagnostic", "q2931.cause.rejection.diagnostic", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_q2931_cause_information_element, { "Information element", "q2931.cause.information_element", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &q2931_info_element_vals_ext, 0x0, NULL, HFILL }},
      { &hf_q2931_cause_cell_rate_subfield_identifier, { "Cell rate subfield identifier", "q2931.cause.cell_rate_subfield_identifier", FT_UINT8, BASE_HEX, VALS(q2931_atm_td_subfield_vals), 0x0, NULL, HFILL }},
      { &hf_q2931_cause_vpci, { "VPCI", "q2931.cause.vpci", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_q2931_cause_vci, { "VCI", "q2931.cause.vci", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_q2931_cause_message_type, { "Message type", "q2931.cause.message_type", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &q2931_message_type_vals_ext, 0x0, NULL, HFILL }},
      { &hf_q2931_cause_timer, { "Timer", "q2931.cause.timer", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_q2931_call_state, { "Call state", "q2931.call_state", FT_UINT8, BASE_HEX, VALS(q2931_call_state_vals), 0x3F, NULL, HFILL }},
      { &hf_q2931_number_type, { "Type of number", "q2931.number.type", FT_UINT8, BASE_HEX, VALS(q2931_number_type_vals), 0x70, NULL, HFILL }},
      { &hf_q2931_number_plan, { "Numbering plan", "q2931.number.plan", FT_UINT8, BASE_HEX, VALS(q2931_numbering_plan_vals), 0x0F, NULL, HFILL }},
      { &hf_q2931_number_presentation_indicator, { "Presentation indicator", "q2931.number.presentation_indicator", FT_UINT8, BASE_HEX, VALS(q2931_presentation_indicator_vals), 0x60, NULL, HFILL }},
      { &hf_q2931_number_screening_indicator, { "Screening indicator", "q2931.number.screening_indicator", FT_UINT8, BASE_HEX, VALS(q2931_screening_indicator_vals), 0x03, NULL, HFILL }},
      { &hf_q2931_number_string, { "Number", "q2931.number.string", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_q2931_number_bytes, { "Number", "q2931.number.bytes", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_q2931_party_subaddr_type_of_subaddress, { "Type of subaddress", "q2931.party_subaddr.type_of_subaddress", FT_UINT8, BASE_HEX, VALS(q2931_subaddress_type_vals), 0x70, NULL, HFILL }},
      { &hf_q2931_party_subaddr_odd_even_indicator, { "Odd/even indicator", "q2931.party_subaddr.odd_even_indicator", FT_UINT8, BASE_HEX, VALS(q2931_odd_even_indicator_vals), 0x10, NULL, HFILL }},
      { &hf_q2931_party_subaddr_subaddress, { "Subaddress", "q2931.party_subaddr.subaddress", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_q2931_conn_id_vp_associated_signalling, { "VP-associated signalling", "q2931.conn_id.vp_associated_signalling", FT_UINT8, BASE_HEX, VALS(q2931_vp_associated_signalling_vals), 0x18, NULL, HFILL }},
      { &hf_q2931_conn_id_preferred_exclusive, { "Preferred/exclusive", "q2931.conn_id.preferred_exclusive", FT_UINT8, BASE_HEX, VALS(q2931_preferred_exclusive_vals), 0x07, NULL, HFILL }},
      { &hf_q2931_conn_id_vpci, { "VPCI", "q2931.conn_id.vpci", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_q2931_conn_id_vci, { "VCI", "q2931.conn_id.vci", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_q2931_e2e_transit_delay_cumulative, { "Cumulative transit delay", "q2931.e2e_transit_delay.cumulative", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_q2931_e2e_transit_delay_maximum_end_to_end, { "Maximum end-to-end transit delay", "q2931.e2e_transit_delay.maximum_end_to_end", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_q2931_qos_class_forward, { "QOS class forward", "q2931.qos_class_forward", FT_UINT8, BASE_HEX, VALS(q2931_qos_parameter_vals), 0x0, NULL, HFILL }},
      { &hf_q2931_qos_class_backward, { "QOS class backward", "q2931.qos_class_backward", FT_UINT8, BASE_HEX, VALS(q2931_qos_parameter_vals), 0x0, NULL, HFILL }},
      { &hf_q2931_broadband_repeat_indicator, { "Broadband repeat indicator", "q2931.broadband_repeat_indicator", FT_UINT8, BASE_HEX, VALS(q2931_bband_rpt_indicator_vals), 0x0F, NULL, HFILL }},
      { &hf_q2931_restart_indicator, { "Restart indicator", "q2931.restart_indicator", FT_UINT8, BASE_HEX, VALS(q2931_class_vals), 0x07, NULL, HFILL }},
      { &hf_q2931_transit_network_sel_type, { "Type of network identification", "q2931.transit_network_sel.type", FT_UINT8, BASE_HEX, VALS(q2931_netid_type_vals), 0x70, NULL, HFILL }},
      { &hf_q2931_transit_network_sel_plan, { "Network identification plan", "q2931.transit_network_sel.plan", FT_UINT8, BASE_HEX, VALS(q2931_netid_plan_vals), 0x0F, NULL, HFILL }},
      { &hf_q2931_transit_network_sel_network_id, { "Network identification", "q2931.transit_network_sel.network_identification", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_q2931_oam_traffic_descriptor_shaping_indicator, { "Shaping indicator", "q2931.oam_traffic_descriptor.shaping_indicator", FT_UINT8, BASE_HEX, VALS(q2931_shaping_indicator_vals), 0x60, NULL, HFILL }},
      { &hf_q2931_oam_traffic_descriptor_management_indicator, { "User-Network fault management indicator", "q2931.oam_traffic_descriptor.management_indicator", FT_UINT8, BASE_HEX, VALS(q2931_user_net_fault_mgmt_vals), 0x07, NULL, HFILL }},
      { &hf_q2931_oam_traffic_descriptor_forward_f5_flow_indicator, { "Forward end-to-end OAM F5 flow indicator", "q2931.oam_traffic_descriptor.forward_f5_flow_indicator", FT_UINT8, BASE_HEX, VALS(q2931_fwd_e2e_oam_f5_flow_indicator_vals), 0x70, NULL, HFILL }},
      { &hf_q2931_oam_traffic_descriptor_backward_f5_flow_indicator, { "Backward end-to-end OAM F5 flow indicator", "q2931.oam_traffic_descriptor.backward_f5_flow_indicator", FT_UINT8, BASE_HEX, VALS(q2931_bwd_e2e_oam_f5_flow_indicator_vals), 0x07, NULL, HFILL }},
      { &hf_q2931_endpoint_reference_type, { "Endpoint reference type", "q2931.endpoint_reference.type", FT_UINT8, BASE_HEX, VALS(q2931_endpoint_reference_type_vals), 0x0, NULL, HFILL }},
      { &hf_q2931_endpoint_reference_identifier_value, { "Endpoint reference identifier value", "q2931.endpoint_reference.identifier_value", FT_UINT16, BASE_DEC, NULL, 0x7FFF, NULL, HFILL }},
      { &hf_q2931_endpoint_state, { "Endpoint reference party-state", "q2931.endpoint_state", FT_UINT8, BASE_HEX, VALS(q2931_endpoint_reference_party_state_vals), 0x3F, NULL, HFILL }},
      { &hf_q2931_information_element, { "Information element", "q2931.information_element", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &q2931_info_element_vals_ext, 0x0, NULL, HFILL }},
      { &hf_q2931_information_element_extension, { "Information element extension", "q2931.information_element.extension", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_q2931_information_element_length, { "Length", "q2931.information_element.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_q2931_information_element_data, { "Data", "q2931.information_element.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	};
	static gint *ett[] = {
		&ett_q2931,
		&ett_q2931_ext,
		&ett_q2931_ie,
		&ett_q2931_ie_ext,
		&ett_q2931_nsap,
	};

	proto_q2931 = proto_register_protocol("Q.2931", "Q.2931", "q2931");
	proto_register_field_array (proto_q2931, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("q2931", dissect_q2931, proto_q2931);
}
