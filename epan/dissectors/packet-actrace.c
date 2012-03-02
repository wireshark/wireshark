/* packet-actrace.c
 * Routines for AudioCodes Trunk traces packet disassembly
 *
 * Copyright (c) 2005 by Alejandro Vaquero <alejandro.vaquero@verso.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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
#include "config.h"
#endif

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include "packet-actrace.h"
#include <epan/emem.h>

#define UDP_PORT_ACTRACE 2428
#define NOT_ACTRACE 0
#define ACTRACE_CAS 1
#define ACTRACE_ISDN 2


void proto_reg_handoff_actrace(void);


/* Define the actrace proto */
static int proto_actrace = -1;

/* Define many headers for actrace */
/* ISDN headers */
static int hf_actrace_isdn_direction = -1;
static int hf_actrace_isdn_trunk = -1;
static int hf_actrace_isdn_length = -1;


/* CAS headers */
static int hf_actrace_cas_time = -1;
static int hf_actrace_cas_source = -1;
static int hf_actrace_cas_current_state = -1;
static int hf_actrace_cas_event = -1;
static int hf_actrace_cas_next_state = -1;
static int hf_actrace_cas_function = -1;
static int hf_actrace_cas_par0 = -1;
static int hf_actrace_cas_par1 = -1;
static int hf_actrace_cas_par2 = -1;
static int hf_actrace_cas_trunk = -1;
static int hf_actrace_cas_bchannel = -1;
static int hf_actrace_cas_connection_id = -1;



static dissector_handle_t lapd_handle;

#define ACTRACE_CAS_SOURCE_DSP		0
#define ACTRACE_CAS_SOURCE_USER		1
#define ACTRACE_CAS_SOURCE_TABLE	2

static const value_string actrace_cas_source_vals[] = {
	{ACTRACE_CAS_SOURCE_DSP, "DSP"},
	{ACTRACE_CAS_SOURCE_USER, "User"},
	{ACTRACE_CAS_SOURCE_TABLE, "Table"},
	{0,   NULL }
};

static const value_string actrace_cas_source_vals_short[] = {
	{ACTRACE_CAS_SOURCE_DSP, "D"},
	{ACTRACE_CAS_SOURCE_USER, "U"},
	{ACTRACE_CAS_SOURCE_TABLE, "T"},
	{0,   NULL }
};

#define ACTRACE_CAS_EV_11 17
#define ACTRACE_CAS_EV_10 18
#define ACTRACE_CAS_EV_01 19
#define ACTRACE_CAS_EV_00 20

#define ACTRACE_CAS_EV_DTMF 302
#define ACTRACE_CAS_EV_FIRST_DIGIT 63

static const value_string actrace_cas_event_ab_vals[] = {
	{ACTRACE_CAS_EV_11, "11"},
	{ACTRACE_CAS_EV_10, "10"},
	{ACTRACE_CAS_EV_01, "01"},
	{ACTRACE_CAS_EV_00, "00"},
	{0, NULL}
};

static const value_string actrace_cas_mf_vals[] = {
	{32, "1"},
	{33, "2"},
	{34, "3"},
	{35, "4"},
	{36, "5"},
	{37, "6"},
	{38, "7"},
	{39, "8"},
	{40, "9"},
	{41, "0"},
	{42, "A"},
	{43, "B"},
	{44, "C"},
	{45, "*"},
	{46, "#"},
	{0, NULL}
};
static value_string_ext actrace_cas_mf_vals_ext = VALUE_STRING_EXT_INIT(actrace_cas_mf_vals);

static const value_string actrace_cas_event_vals[] = {
	{0, "FUNCTION0"},
	{1, "FUNCTION1"},
	{2, "FUNCTION2"},
	{3, "FUNCTION3"},
	{4, "EV_PLACE_CALL"},
	{5, "EV_TIMER_EXPIRED1"},
	{6, "EV_TIMER_EXPIRED2"},
	{7, "EV_TIMER_EXPIRED3"},
	{8, "EV_TIMER_EXPIRED4"},
	{9, "EV_TIMER_EXPIRED5"},
	{10, "EV_TIMER_EXPIRED6"},
	{11, "EV_TIMER_EXPIRED7"},
	{12, "EV_TIMER_EXPIRED8"},
	{13, "EV_ANSWER"},
	{14, "EV_DIAL_TONE_DETECTED"},
	{15, "EV_DIAL_ENDED"},
	{16, "EV_DISCONNECT"},
	{ACTRACE_CAS_EV_11, "EV_CAS_1_1"},
	{ACTRACE_CAS_EV_10, "EV_CAS_1_0"},
	{ACTRACE_CAS_EV_01, "EV_CAS_0_1"},
	{ACTRACE_CAS_EV_00, "EV_CAS_0_0"},
	{21, "EV_RB_TONE_STARTED"},
	{22, "EV_RB_TONE_STOPPED"},
	{23, "EV_BUSY_TONE"},
	{24, "EV_FAST_BUSY_TONE"},
	{25, "EV_HELLO_DETECTED"},
	{26, "EV_DIAL_TONE_STOPPED"},
	{27, "EV_DISCONNECT_INCOMING"},
	{28, "EV_RELEASE_CALL"},
	{29, "EV_DIALED_NUM_DETECTED"},
	{30, "EV_COUNTER1_EXPIRED"},
	{31, "EV_COUNTER2_EXPIRED"},
	{32, "EV_MFRn_1"},
	{33, "EV_MFRn_2"},
	{34, "EV_MFRn_3"},
	{35, "EV_MFRn_4"},
	{36, "EV_MFRn_5"},
	{37, "EV_MFRn_6"},
	{38, "EV_MFRn_7"},
	{39, "EV_MFRn_8"},
	{40, "EV_MFRn_9"},
	{41, "EV_MFRn_10"},
	{42, "EV_MFRn_11"},
	{43, "EV_MFRn_12"},
	{44, "EV_MFRn_13"},
	{45, "EV_MFRn_14"},
	{46, "EV_MFRn_15"},
	{47, "EV_MFRn_1_STOPPED"},
	{48, "EV_MFRn_2_STOPPED"},
	{49, "EV_MFRn_3_STOPPED"},
	{50, "EV_MFRn_4_STOPPED"},
	{51, "EV_MFRn_5_STOPPED"},
	{52, "EV_MFRn_6_STOPPED"},
	{53, "EV_MFRn_7_STOPPED"},
	{54, "EV_MFRn_8_STOPPED"},
	{55, "EV_MFRn_9_STOPPED"},
	{56, "EV_MFRn_10_STOPPED"},
	{57, "EV_MFRn_11_STOPPED"},
	{58, "EV_MFRn_12_STOPPED"},
	{59, "EV_MFRn_13_STOPPED"},
	{60, "EV_MFRn_14_STOPPED"},
	{61, "EV_MFRn_15_STOPPED"},
	{62, "EV_ANI_NUM_DETECTED"},
	{ACTRACE_CAS_EV_FIRST_DIGIT, "EV_FIRST_DIGIT"},
	{64, "EV_END_OF_MF_DIGIT"},
	{65, "EV_ACCEPT"},
	{66, "EV_REJECT_BUSY"},
	{67, "EV_REJECT_CONGESTION"},
	{68, "EV_REJECT_UNALLOCATED"},
	{69, "EV_REJECT_RESERVE1"},
	{70, "EV_REJECT_RESERVE2"},
	{71, "EV_NO_ANI"},
	{100, "EV_INIT_CHANNEL"},
	{101, "EV_BUSY_TONE_STOPPED"},
	{102, "EV_FAST_BUSY_TONE_STOPPED"},
	{103, "EV_TO_USER"},
	{104, "SEND_FIRST_DIGIT"},
	{110, "EV_CLOSE_CHANNEL"},
	{111, "EV_OPEN_CHANNEL"},
	{112, "EV_FAIL_DIAL"},
	{113, "EV_FAIL_SEND_CAS"},
	{114, "EV_ALARM"},
	{ACTRACE_CAS_EV_DTMF, "EV_DTMF"},
	{1010, "EV_TIMER_EXPIRED10"},
	{1020, "EV_DEBOUNCE_TIMER_EXPIRED"},
	{1030, "EV_INTER_DIGIT_TIMER_EXPIRED"},
	{0, NULL}
};
static value_string_ext actrace_cas_event_vals_ext = VALUE_STRING_EXT_INIT(actrace_cas_event_vals);

#define SEND_CAS 2
#define SEND_EVENT 3
#define CHANGE_COLLECT_TYPE 13
#define SEND_MF 8
#define SEND_DEST_NUM 4

static const value_string actrace_cas_function_vals[] = {
	{0, "NILL"},
	{1, "SET_TIMER"},
	{SEND_CAS, "SEND_CAS"},
	{SEND_EVENT, "SEND_EVENT"},
	{SEND_DEST_NUM, "SEND_DEST_NUM"},
	{5, "DEL_TIMER"},
	{6, "START_COLLECT"},
	{7, "STOP_COLLECT"},
	{SEND_MF, "SEND_MF"},
	{9, "STOP_DIAL_MF"},
	{10, "SET_COUNTER"},
	{11, "DEC_COUNTER"},
	{12, "SEND_PROG_TON"},
	{CHANGE_COLLECT_TYPE, "CHANGE_COLLECT_TYPE"},
	{14, "GENERATE_CAS_EV"},
	{0, NULL}
};
static value_string_ext actrace_cas_function_vals_ext = VALUE_STRING_EXT_INIT(actrace_cas_function_vals);

static const value_string actrace_cas_pstn_event_vals[] = {
	{64, "acEV_PSTN_INTERNAL_ERROR"},
	{65, "acEV_PSTN_CALL_CONNECTED"},
	{66, "acEV_PSTN_INCOMING_CALL_DETECTED"},
	{67, "acEV_PSTN_CALL_DISCONNECTED"},
	{68, "acEV_PSTN_CALL_RELEASED"},
	{69, "acEV_PSTN_REMOTE_ALERTING"},
	{70, "acEV_PSTN_STARTED"},
	{71, "acEV_PSTN_WARNING"},
	{72, "acEV_ISDN_PROGRESS_INDICATION"},
	{73, "acEV_PSTN_PROCEEDING_INDICATION"},
	{74, "acEV_PSTN_ALARM"},
	{75, "acEV_RESERVED"},
	{76, "acEV_PSTN_LINE_INFO"},
	{77, "acEV_PSTN_LOOP_CONFIRM"},
	{78, "acEV_PSTN_RESTART_CONFIRM"},
	{84, "acEV_ISDN_SETUP_ACK_IN"},
	{85, "acEV_PSTN_CALL_INFORMATION"},
	{128, "acEV_CAS_SEIZURE_DETECTED"},
	{129, "acEV_CAS_CHANNEL_BLOCKED"},
	{130, "acEV_CAS_PROTOCOL_STARTED"},
	{131, "acEV_PSTN_CALL_STATE_RESPONSE"},
	{132, "acEV_CAS_SEIZURE_ACK"},
	{0, NULL}
};
static value_string_ext actrace_cas_pstn_event_vals_ext = VALUE_STRING_EXT_INIT(actrace_cas_pstn_event_vals);

static const value_string actrace_cas_collect_type_vals[] = {
	{0, "COLLECT_TYPE_ADDRESS"},
	{1, "COLLECT_TYPE_ANI"},
	{2, "COLLECT_TYPE_SOURCE_CATEGORY"},
	{3, "COLLECT_TYPE_LINE_CATEGORY"},
	{0, NULL}
};

#define SEND_TYPE_ADDRESS 1
#define SEND_TYPE_SPECIFIC 2
#define SEND_TYPE_INTER_EXCHANGE_SWITCH 3
#define SEND_TYPE_ANI 4
#define SEND_TYPE_SOURCE_CATEGORY 5
#define SEND_TYPE_TRANSFER_CAPABILITY 6

static const value_string actrace_cas_send_type_vals[] = {
	{SEND_TYPE_ADDRESS, "ADDRESS"},
	{SEND_TYPE_SPECIFIC, "SPECIFIC"},
	{SEND_TYPE_INTER_EXCHANGE_SWITCH, "INTER_EXCHANGE_SWITCH"},
	{SEND_TYPE_ANI, "ANI"},
	{SEND_TYPE_SOURCE_CATEGORY, "SOURCE_CATEGORY"},
	{SEND_TYPE_TRANSFER_CAPABILITY, "TRANSFER_CAPABILITY"},
	{0, NULL}
};

static const value_string actrace_cas_cause_vals[] = {
	{1, "UNASSIGNED_NUMBER"},
	{2, "NO_ROUTE_TO_TRANSIT_NET"},
	{3, "NO_ROUTE_TO_DESTINATION"},
	{6, "CHANNEL_UNACCEPTABLE"},
	{7, "CALL_AWARDED_AND"},
	{8, "PREEMPTION"},
	{16, "NORMAL_CALL_CLEAR"},
	{17, "USER_BUSY"},
	{18, "NO_USER_RESPONDING"},
	{19, "NO_ANSWER_FROM_USER_ALERTED"},
	{20, "ACCEPT_DONE"},
	{21, "CALL_REJECTED"},
	{22, "NUMBER_CHANGED"},
	{26, "NON_SELECTED_USER_CLEARING"},
	{27, "DEST_OUT_OF_ORDER"},
	{28, "INVALID_NUMBER_FORMAT"},
	{29, "FACILITY_REJECT"},
	{30, "RESPONSE_TO_STATUS_ENQUIRY"},
	{31, "NORMAL_UNSPECIFIED"},
	{32, "CIRCUIT_CONGESTION"},
	{33, "USER_CONGESTION"},
	{34, "NO_CIRCUIT_AVAILABLE"},
	{38, "NETWORK_OUT_OF_ORDER"},
	{39, "PERM_FR_MODE_CONN_OUT_OF_S"},
	{40, "PERM_FR_MODE_CONN_OPERATIONAL"},
	{41, "NETWORK_TEMPORARY_FAILURE"},
	{42, "NETWORK_CONGESTION"},
	{43, "ACCESS_INFORMATION_DISCARDED"},
	{44, "REQUESTED_CIRCUIT_NOT_AVAILABLE"},
	{46, "PRECEDENCE_CALL_BLOCKED"},
	{47, "RESOURCE_UNAVAILABLE_UNSPECIFIED"},
	{49, "QUALITY_OF_SERVICE_UNAVAILABLE"},
	{50, "REQUESTED_FAC_NOT_SUBSCRIBED"},
	{53, "CUG_OUT_CALLS_BARRED"},
	{55, "CUG_INC_CALLS_BARRED"},
	{57, "BC_NOT_AUTHORIZED"},
	{58, "BC_NOT_PRESENTLY_AVAILABLE"},
	{62, "ACCES_INFO_SUBS_CLASS_INCONS"},
	{63, "SERVICE_NOT_AVAILABLE"},
	{65, "BC_NOT_IMPLEMENTED"},
	{66, "CHANNEL_TYPE_NOT_IMPLEMENTED"},
	{69, "REQUESTED_FAC_NOT_IMPLEMENTED"},
	{70, "ONLY_RESTRICTED_INFO_BEARER"},
	{79, "SERVICE_NOT_IMPLEMENTED_UNSPECIFIED"},
	{81, "INVALID_CALL_REF"},
	{82, "IDENTIFIED_CHANNEL_NOT_EXIST"},
	{83, "SUSPENDED_CALL_BUT_CALL_ID_NOT_EXIST"},
	{84, "CALL_ID_IN_USE"},
	{85, "NO_CALL_SUSPENDED"},
	{86, "CALL_HAVING_CALL_ID_CLEARED"},
	{87, "NOT_CUG_MEMBER"},
	{88, "INCOMPATIBLE_DESTINATION"},
	{90, "CUG_NON_EXISTENT"},
	{91, "INVALID_TRANSIT_NETWORK_SELECTION"},
	{95, "INVALID_MESSAGE_UNSPECIFIED"},
	{96, "MANDATORY_IE_MISSING"},
	{97, "MESSAGE_TYPE_NON_EXISTENT"},
	{98, "MESSAGE_STATE_INCONSISTENCY"},
	{99, "NON_EXISTENT_IE"},
	{100, "INVALID_IE_CONTENT"},
	{101, "MESSAGE_NOT_COMPATIBLE"},
	{102, "RECOVERY_ON_TIMER_EXPIRY"},
	{111, "PROTOCOL_ERROR_UNSPECIFIED"},
	{127, "INTERWORKING_UNSPECIFIED"},
	{128, "ACU_CAUSE_ACU_BAD_ADDRESS"},
	{129, "ACU_CAUSE_ACU_BAD_SERVICE"},
	{130, "ACU_CAUSE_ACU_COLLISION"},
	{131, "ACU_CAUSE_ACU_FAC_REJECTED"},
	{200, "C_ALREADY_BLOCKED"},
	{201, "C_CHANNEL_BLOCKED"},
	{202, "C_BLOCKING_DONE"},
	{203, "C_ALREADY_UNBLOCKED"},
	{204, "C_UNBLOCKING_DONE"},
	{255, "ACU_NETWORK_CAUSE_NIL"},
	{260, "CLRN_MFRn_A4"},
	{261, "CLRN_MFRn_B1"},
	{262, "CLRN_MFRn_B2"},
	{263, "CLRN_MFRn_B3"},
	{264, "CLRN_MFRn_B4"},
	{265, "CLRN_MFRn_B5"},
	{266, "CLRN_MFRn_B6"},
	{267, "CLRN_MFRn_B7"},
	{268, "CLRN_MFRn_B8"},
	{269, "CLRN_MFRn_B9"},
	{270, "CLRN_MFRn_B10"},
	{271, "CLRN_MFRn_B11"},
	{272, "CLRN_MFRn_B12"},
	{273, "CLRN_MFRn_B13"},
	{274, "CLRN_MFRn_B14"},
	{275, "CLRN_MFRn_B15"},
	{300, "ACURC_BUSY"},
	{301, "ACURC_NOPROCEED"},
	{302, "ACURC_NOANSWER"},
	{303, "ACURC_NOAUTOANSWER"},
	{304, "ACURC_CONGESTED"},
	{305, "ACURC_INCOMING"},
	{306, "ACURC_NOLINE"},
	{307, "ACURC_ERRNUM"},
	{308, "ACURC_INHNUM"},
	{309, "ACURC_2MNUM"},
	{310, "ACURC_HUNGUP"},
	{311, "ACURC_NETWORK_ERROR"},
	{312, "ACURC_TIMEOUT"},
	{313, "ACURC_BAD_SERVICE"},
	{314, "ACURC_INTERNAL"},
	{315, "ACURC_OK"},
	{316, "ACURC_BL_TIMEOUT"},
	{317, "ACURC_IN_CALL"},
	{318, "ACURC_CLEAR_RQ"},
	{0, NULL}
};
static value_string_ext actrace_cas_cause_vals_ext = VALUE_STRING_EXT_INIT(actrace_cas_cause_vals);

/* ISDN */
#define PSTN_TO_BLADE	0x49446463
#define BLADE_TO_PSTN	0x49644443

static const value_string actrace_isdn_direction_vals[] = {
	{PSTN_TO_BLADE, "Blade <-- PSTN"},
	{BLADE_TO_PSTN, "Blade --> PSTN"},
	{0, NULL}
};

/*
 * Define the tree for actrace
 */
static int ett_actrace = -1;

/*
 * Define the tap for actrace
 */
static int actrace_tap = -1;
static actrace_info_t *actrace_pi;

/*
 * Here are the global variables associated with
 * the user definable characteristics of the dissection
 */
static guint global_actrace_udp_port = UDP_PORT_ACTRACE;

/* Some basic utility functions that are specific to this dissector */
static int is_actrace(tvbuff_t *tvb, gint offset);

/*
 * The dissect functions
 */
static void dissect_actrace_cas(tvbuff_t *tvb, packet_info *pinfo, proto_tree *actrace_tree);
static void dissect_actrace_isdn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
				 proto_tree *actrace_tree);

/************************************************************************
 * dissect_actrace - The dissector for the AudioCodes Trace prtocol
 ************************************************************************/
static int dissect_actrace(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *actrace_tree;
	proto_item *ti;
	int actrace_protocol;

	/* Initialize variables */
	actrace_tree = NULL;

	/*
	 * Check to see whether we're really dealing with AC trace by looking
	 * for a valid "source" and fixed len for CAS, and the direction for ISDN.
	 * This isn't infallible, but its cheap and it's better than nothing.
	 */
	actrace_protocol = is_actrace(tvb, 0);
	if (actrace_protocol != NOT_ACTRACE)
	{
		/*
		 * Set the columns now, so that they'll be set correctly if we throw
		 * an exception.  We can set them later as well....
		 */
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "AC_TRACE");
		col_clear(pinfo->cinfo, COL_INFO);

		if (tree)
		{
			/* Create our actrace subtree */
			ti = proto_tree_add_item(tree,proto_actrace,tvb,0,-1, ENC_NA);
			actrace_tree = proto_item_add_subtree(ti, ett_actrace);
		}

		switch (actrace_protocol)
		{
			case ACTRACE_CAS:
				dissect_actrace_cas(tvb, pinfo, actrace_tree);
				break;
			case ACTRACE_ISDN:
				dissect_actrace_isdn(tvb, pinfo, tree, actrace_tree);
				break;
		}
		return tvb_length(tvb);
	}

	return 0;
}

/* Dissect an individual actrace CAS message */
static void dissect_actrace_cas(tvbuff_t *tvb, packet_info *pinfo, proto_tree *actrace_tree)
{
	/* Declare variables */
	gint32 value, function, trunk, bchannel, source, event, curr_state, next_state;
	gint32 par0, par1, par2;
	gchar *frame_label = NULL;
	int direction = 0;
	int offset = 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "AC_CAS");

	value = tvb_get_ntohl(tvb, offset);
	proto_tree_add_int(actrace_tree, hf_actrace_cas_time, tvb, offset, 4, value);
	offset += 4;

	source = tvb_get_ntohl(tvb, offset);
	proto_tree_add_int(actrace_tree, hf_actrace_cas_source, tvb, offset, 4, source);
	offset += 4;

	curr_state = tvb_get_ntohl(tvb, offset);
	proto_tree_add_int(actrace_tree, hf_actrace_cas_current_state, tvb, offset, 4, curr_state);
	offset += 4;

	event = tvb_get_ntohl(tvb, offset);
	proto_tree_add_int(actrace_tree, hf_actrace_cas_event, tvb, offset, 4, event);
	offset += 4;

	next_state = tvb_get_ntohl(tvb, offset);
	proto_tree_add_int(actrace_tree, hf_actrace_cas_next_state, tvb, offset, 4, next_state);
	offset += 4;

	function = tvb_get_ntohl(tvb, offset);
	proto_tree_add_int(actrace_tree, hf_actrace_cas_function, tvb, offset, 4, function);
	offset += 4;

	col_append_fstr(pinfo->cinfo, COL_INFO, "%s|%d|%s|%d|%s|",
			val_to_str_const(source, actrace_cas_source_vals_short, "ukn"),
			curr_state,
			val_to_str_ext(event, &actrace_cas_event_vals_ext, "%d"),
			next_state,
			val_to_str_ext(function, &actrace_cas_function_vals_ext, "%d"));

	par0 = tvb_get_ntohl(tvb, offset);
	switch (function)
	{
		case SEND_EVENT:
			proto_tree_add_text(actrace_tree, tvb, offset, 4,
				"Parameter 0: %s",  val_to_str_ext(par0,
				&actrace_cas_pstn_event_vals_ext, "Unknown (%d)"));
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s|",
					val_to_str_ext(par0, &actrace_cas_pstn_event_vals_ext, "%d"));
			break;
		case CHANGE_COLLECT_TYPE:
			proto_tree_add_text(actrace_tree, tvb, offset, 4,
				"Parameter 0: %s", val_to_str(par0,
				actrace_cas_collect_type_vals, "Unknown (%d)"));
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s|",
					val_to_str(par0, actrace_cas_collect_type_vals, "%d"));
			break;
		case SEND_MF:
		case SEND_DEST_NUM:
			proto_tree_add_text(actrace_tree, tvb, offset, 4,
				"Parameter 0: %s", val_to_str(par0,
				actrace_cas_send_type_vals, "Unknown (%d)"));
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s|",
					val_to_str(par0, actrace_cas_send_type_vals, "%d"));
			break;
		default:
			proto_tree_add_int(actrace_tree, hf_actrace_cas_par0, tvb, offset, 4, par0);
			col_append_fstr(pinfo->cinfo, COL_INFO, "%d|", par0);
	}
	offset += 4;

	par1 = tvb_get_ntohl(tvb, offset);
	if (function == SEND_EVENT) {
		proto_tree_add_text(actrace_tree, tvb, offset, 4,
			"Parameter 1: %s", val_to_str_ext(par1, &actrace_cas_cause_vals_ext, "Unknown (%d)"));
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s|",
				val_to_str_ext(par1, &actrace_cas_cause_vals_ext, "%d"));
	} else {
		proto_tree_add_int(actrace_tree, hf_actrace_cas_par1, tvb, offset, 4, par1);
		col_append_fstr(pinfo->cinfo, COL_INFO, "%d|", par1);
	}
	offset += 4;

	par2 = tvb_get_ntohl(tvb, offset);
	proto_tree_add_int(actrace_tree, hf_actrace_cas_par2, tvb, offset, 4, par2);
	col_append_fstr(pinfo->cinfo, COL_INFO, "%d|", par2);
	offset += 4;

	trunk = tvb_get_ntohl(tvb, offset);
	proto_tree_add_int(actrace_tree, hf_actrace_cas_trunk, tvb, offset, 4, trunk);
	offset += 4;

	bchannel = tvb_get_ntohl(tvb, offset);
	proto_tree_add_int(actrace_tree, hf_actrace_cas_bchannel, tvb, offset, 4, bchannel);
	offset += 4;

	col_prepend_fstr(pinfo->cinfo, COL_INFO, "t%db%d|", trunk, bchannel);

	value = tvb_get_ntohl(tvb, offset);
	proto_tree_add_int(actrace_tree, hf_actrace_cas_connection_id, tvb, offset, 4, value);

	/* Add tap info for the Voip Graph */
	if (source == ACTRACE_CAS_SOURCE_DSP) {
		direction = 1;
		if ( (event >= ACTRACE_CAS_EV_11) && (event <= ACTRACE_CAS_EV_00 ) ) {
			frame_label = ep_strdup_printf("AB: %s", val_to_str_const(event, actrace_cas_event_ab_vals, "ERROR") );
		} else if ( (event >= 32) && (event <= 46 ) ) { /* is an MF tone */
			frame_label = ep_strdup_printf("MF: %s", val_to_str_ext_const(event, &actrace_cas_mf_vals_ext, "ERROR") );
		} else if ( (event == ACTRACE_CAS_EV_DTMF ) || (event == ACTRACE_CAS_EV_FIRST_DIGIT ) ) { /* DTMF digit */
			frame_label = ep_strdup_printf("DTMF: %u", par0 );
		}
	} else if (source == ACTRACE_CAS_SOURCE_TABLE) {
		direction = 0;
		if (function == SEND_MF) {
			if (par0 == SEND_TYPE_SPECIFIC ) {
				frame_label = ep_strdup_printf("MF: %u", par1);
			} else if (par0 == SEND_TYPE_ADDRESS ) {
				frame_label = ep_strdup("MF: DNIS digit");
			} else if (par0 == SEND_TYPE_ANI  ) {
				frame_label = ep_strdup("MF: ANI digit");
			} else if (par0 == SEND_TYPE_SOURCE_CATEGORY ) {
				frame_label = ep_strdup("MF: src_category");
			} else if (par0 == SEND_TYPE_TRANSFER_CAPABILITY ) {
				frame_label = ep_strdup("MF: trf_capability");
			} else if (par0 == SEND_TYPE_INTER_EXCHANGE_SWITCH ) {
				frame_label = ep_strdup("MF: inter_exch_sw");
			}
		} else if (function == SEND_CAS) {
			frame_label = ep_strdup_printf("AB: %s", val_to_str_const(ACTRACE_CAS_EV_00-par0, actrace_cas_event_ab_vals, "ERROR"));
		} else if (function == SEND_DEST_NUM) {
			if (par0 == SEND_TYPE_ADDRESS ) {
				frame_label = ep_strdup("DTMF/MF: sending DNIS");
			} else if (par0 == SEND_TYPE_ANI ) {
				frame_label = ep_strdup("DTMF/MF: sending ANI");
			}
		}
	}

	if (frame_label != NULL) {
		/* Initialise packet info for passing to tap */
		actrace_pi = ep_alloc(sizeof(actrace_info_t));

		actrace_pi->type = ACTRACE_CAS;
		actrace_pi->direction = direction;
		actrace_pi->trunk = trunk;
		actrace_pi->cas_bchannel = bchannel;
		actrace_pi->cas_frame_label = frame_label;
		/* Report this packet to the tap */
		tap_queue_packet(actrace_tap, pinfo, actrace_pi);
	}
}

/* Dissect an individual actrace ISDN message */
static void dissect_actrace_isdn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
				 proto_tree *actrace_tree)
{
	/* Declare variables */
	gint len;
	gint32 value, trunk;
	tvbuff_t *next_tvb;
	int offset = 0;

	len = tvb_get_ntohs(tvb, 44);

	value = tvb_get_ntohl(tvb, offset+4);
	proto_tree_add_int(actrace_tree, hf_actrace_isdn_direction, tvb, offset+4, 4, value);

	offset += 8;
	trunk = tvb_get_ntohs(tvb, offset);
	proto_tree_add_int(actrace_tree, hf_actrace_isdn_trunk, tvb, offset, 2, trunk);

	offset = 44;
	proto_tree_add_int(actrace_tree, hf_actrace_isdn_length, tvb, offset, 2, len);


	/* if it is a q931 packet (we don't want LAPD packets for Voip Graph) add tap info */
	if (len > 4) {
		/* Initialise packet info for passing to tap */
		actrace_pi = ep_alloc(sizeof(actrace_info_t));

		actrace_pi->type = ACTRACE_ISDN;
		actrace_pi->direction = (value==PSTN_TO_BLADE?1:0);
		actrace_pi->trunk = trunk;

		/* Report this packet to the tap */
		tap_queue_packet(actrace_tap, pinfo, actrace_pi);
	}

	/* Dissect lapd payload */
	offset += 2 ;
	next_tvb = tvb_new_subset(tvb, offset, len, len);
	call_dissector(lapd_handle, next_tvb, pinfo, tree);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "AC_ISDN");
	col_prepend_fstr(pinfo->cinfo, COL_INFO, "Trunk:%d  Blade %s PSTN "
			 , trunk, value==PSTN_TO_BLADE?"<--":"-->");
}

/*
 * is_actrace - A function for determining whether there is a
 *              AudioCodes packet at offset in tvb. The packet could be
 *				a CAS, ISDN or other Trunk protocol. Here we are only
 *				trying to decode CAS or ISDN protocols
 *
 * Parameter:
 * tvb - The tvbuff in which we are looking for
 * offset - The offset in tvb at which we are looking for
 *
 * Return: NOT_ACTRACE if there isn't an AudioCodes trace packet at offset
 * in tvb, ACTRACE_CAS if there's a CAS packet there, ACTRACE_ISDN if
 * there's an ISDN packet there.
 */
static int is_actrace(tvbuff_t *tvb, gint offset)
{
	gint tvb_len;
	gint32 source, isdn_header;

	tvb_len = tvb_reported_length(tvb);

	/* is a CAS packet?
	 * the CAS messages are 48 byte fixed and the source should be 0,1 or 2 (DSP, User or Table)
	 */
	source = tvb_get_ntohl(tvb, offset+4);
	if ( (tvb_len == 48) && ((source > -1) && (source <3)) )
		return ACTRACE_CAS;
	/* is ISDN packet?
	 * the ISDN packets have 0x49446463 for packets from PSTN to the Blade and
	 * 0x49644443 for packets from the Blade to the PSTN at offset 4
	 */
	isdn_header = tvb_get_ntohl(tvb, offset+4);
	if ( (tvb_len >= 50) && ( (isdn_header == PSTN_TO_BLADE) || (isdn_header == BLADE_TO_PSTN)) )
		return ACTRACE_ISDN;
	return NOT_ACTRACE;
}

/* Register all the bits needed with the filtering engine */
void proto_register_actrace(void)
{
	static hf_register_info hf[] =
		{
			/* CAS */
			{ &hf_actrace_cas_time,
			  { "Time", "actrace.cas.time", FT_INT32, BASE_DEC, NULL, 0x0,
			    "Capture Time", HFILL }},
			{ &hf_actrace_cas_source,
			  { "Source", "actrace.cas.source", FT_INT32, BASE_DEC, VALS(actrace_cas_source_vals), 0x0,
			    NULL, HFILL }},
			{ &hf_actrace_cas_current_state,
			  { "Current State", "actrace.cas.curr_state", FT_INT32, BASE_DEC, NULL, 0x0,
			    NULL, HFILL }},
			{ &hf_actrace_cas_event,
			  { "Event", "actrace.cas.event", FT_INT32, BASE_DEC|BASE_EXT_STRING, &actrace_cas_event_vals_ext, 0x0,
			    "New Event", HFILL }},
			{ &hf_actrace_cas_next_state,
			  { "Next State", "actrace.cas.next_state", FT_INT32, BASE_DEC, NULL, 0x0,
			    NULL, HFILL }},
			{ &hf_actrace_cas_function,
			  { "Function", "actrace.cas.function", FT_INT32, BASE_DEC|BASE_EXT_STRING, &actrace_cas_function_vals_ext, 0x0,
			    NULL, HFILL }},
			{ &hf_actrace_cas_par0,
			  { "Parameter 0", "actrace.cas.par0", FT_INT32, BASE_DEC, NULL, 0x0,
			    NULL, HFILL }},
			{ &hf_actrace_cas_par1,
			  { "Parameter 1", "actrace.cas.par1", FT_INT32, BASE_DEC, NULL, 0x0,
			    NULL, HFILL }},
			{ &hf_actrace_cas_par2,
			  { "Parameter 2", "actrace.cas.par2", FT_INT32, BASE_DEC, NULL, 0x0,
			    NULL, HFILL }},
			{ &hf_actrace_cas_trunk,
			  { "Trunk Number", "actrace.cas.trunk", FT_INT32, BASE_DEC, NULL, 0x0,
			    NULL, HFILL }},
			{ &hf_actrace_cas_bchannel,
			  { "BChannel", "actrace.cas.bchannel", FT_INT32, BASE_DEC, NULL, 0x0,
			    NULL, HFILL }},
			{ &hf_actrace_cas_connection_id,
			  { "Connection ID", "actrace.cas.conn_id", FT_INT32, BASE_DEC, NULL, 0x0,
			    NULL, HFILL }},

			/* ISDN */
			{ &hf_actrace_isdn_trunk,
			  { "Trunk Number", "actrace.isdn.trunk", FT_INT16, BASE_DEC, NULL, 0x0,
			    NULL, HFILL }},
			{ &hf_actrace_isdn_direction,
			  { "Direction", "actrace.isdn.dir", FT_INT32, BASE_DEC, VALS(actrace_isdn_direction_vals), 0x0,
			    NULL, HFILL }},
			{ &hf_actrace_isdn_length,
			  { "Length", "actrace.isdn.length", FT_INT16, BASE_DEC, NULL, 0x0,
			    NULL, HFILL }},
		};

	static gint *ett[] =
		{
			&ett_actrace,
		};

	module_t *actrace_module;

	/* Register protocol */
	proto_actrace = proto_register_protocol("AudioCodes Trunk Trace", "ACtrace", "actrace");
	proto_register_field_array(proto_actrace, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register our configuration options */
	actrace_module = prefs_register_protocol(proto_actrace, proto_reg_handoff_actrace);

	prefs_register_uint_preference(actrace_module, "udp_port",
				       "AudioCodes Trunk Trace UDP port",
				       "Set the UDP port for AudioCodes Trunk Traces."
				       "Use http://x.x.x.x/TrunkTraces to enable the traces in the Blade",
				       10, &global_actrace_udp_port);

	prefs_register_obsolete_preference(actrace_module, "display_dissect_tree");

	actrace_tap = register_tap("actrace");
}

/* The registration hand-off routine */
void proto_reg_handoff_actrace(void)
{
	static gboolean actrace_prefs_initialized = FALSE;
	static dissector_handle_t actrace_handle;
	static guint actrace_udp_port;

	if (!actrace_prefs_initialized)
	{
		actrace_handle = new_create_dissector_handle(dissect_actrace, proto_actrace);
		/* Get a handle for the lapd dissector. */
		lapd_handle = find_dissector("lapd");
		actrace_prefs_initialized = TRUE;
	}
	else
	{
		dissector_delete_uint("udp.port", actrace_udp_port, actrace_handle);
	}

	/* Set our port number for future use */
	actrace_udp_port = global_actrace_udp_port;

	dissector_add_uint("udp.port", global_actrace_udp_port, actrace_handle);
}

