/* packet-etheric.c
 * Routines for Etheric dissection a Ericsson propriatary protocol.
 * 
 * Copyright 2004, Anders Broman <anders.broman@ericsson.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <prefs.h>
#include "packet-e164.h"
#include "packet-q931.h"
#include "packet-isup.h"

/* Initialize the protocol and registered fields */
static int proto_etheric				= -1;
static int hf_etheric_protocol_version	= -1;
static int hf_etheric_message_length	= -1;
static int hf_etheric_cic				= -1;
static int hf_etheric_message_type		= -1;
static int hf_etheric_parameter_type	= -1;

static int hf_etheric_calling_partys_category					= -1;
static int hf_etheric_forw_call_isdn_access_indicator			= -1;
	
static int hf_etheric_transmission_medium_requirement			= -1;
static int hf_etheric_odd_even_indicator						= -1;
static int hf_etheric_called_party_nature_of_address_indicator	= -1;

static int hf_etheric_ni_indicator								= -1;
static int hf_etheric_calling_party_nature_of_address_indicator	= -1;

static int hf_etheric_inn_indicator								= -1;

static int hf_etheric_numbering_plan_indicator					= -1;

static int hf_etheric_address_presentation_restricted_indicator	= -1;
static int hf_etheric_screening_indicator						= -1;
static int hf_etheric_called_party_odd_address_signal_digit		= -1;
static int hf_etheric_calling_party_odd_address_signal_digit	= -1;
static int hf_etheric_called_party_even_address_signal_digit	= -1;
static int hf_etheric_calling_party_even_address_signal_digit	= -1;
static int hf_etheric_mandatory_variable_parameter_pointer		= -1;
static int hf_etheric_parameter_length							= -1;
static int hf_etheric_pointer_to_start_of_optional_part			= -1;
static int hf_etheric_inband_information_ind					= -1;
static int hf_etheric_cause_indicator							= -1;
static int hf_etheric_event_ind									= -1;	
static int hf_etheric_event_presentation_restricted_ind			= -1;

/* Initialize the subtree pointers */
static gint ett_etheric						= -1;
static gint ett_etheric_parameter			= -1;
static gint ett_etheric_address_digits		= -1;
static gint ett_etheric_circuit_state_ind	= -1;

/* set the tcp port */
static guint ethericTCPport1 =1806;
static guint ethericTCPport2 =10002;

static dissector_handle_t	q931_ie_handle = NULL;
/* Value strings */
static const value_string protocol_version_vals[] = {
	{ 0x00,	"Etheric 1.0" },
	{ 0x10,	"Etheric 2.0" },
	{ 0x11,	"Etheric 2.1" },
	{ 0,	NULL }
};

/* Copied from packet-isup */
/* since length field is 8 Bit long - used in number dissectors;
 * max. number of address digits is 15 digits, but MAXLENGTH used
 * to avoid runtime errors 
 */
#define MAXLENGTH                            0xFF 
/* Definition of Message Types */
#define ETHERIC_MESSAGE_TYPE_INITIAL_ADDR       1
#define ETHERIC_MESSAGE_TYPE_SUBSEQ_ADDR        2
#define ETHERIC_MESSAGE_TYPE_INFO_REQ           3
#define ETHERIC_MESSAGE_TYPE_INFO               4
#define ETHERIC_MESSAGE_TYPE_CONTINUITY         5
#define ETHERIC_MESSAGE_TYPE_ADDR_CMPL          6
#define ETHERIC_MESSAGE_TYPE_CONNECT            7
#define ETHERIC_MESSAGE_TYPE_FORW_TRANS         8
#define ETHERIC_MESSAGE_TYPE_ANSWER             9
#define ETHERIC_MESSAGE_TYPE_RELEASE           12
#define ETHERIC_MESSAGE_TYPE_SUSPEND           13
#define ETHERIC_MESSAGE_TYPE_RESUME            14
#define ETHERIC_MESSAGE_TYPE_REL_CMPL          16
#define ETHERIC_MESSAGE_TYPE_CONT_CHECK_REQ    17
#define ETHERIC_MESSAGE_TYPE_RESET_CIRCUIT     18
#define ETHERIC_MESSAGE_TYPE_BLOCKING          19
#define ETHERIC_MESSAGE_TYPE_UNBLOCKING        20
#define ETHERIC_MESSAGE_TYPE_BLOCK_ACK         21
#define ETHERIC_MESSAGE_TYPE_UNBLOCK_ACK       22
#define ETHERIC_MESSAGE_TYPE_CIRC_GRP_RST      23
#define ETHERIC_MESSAGE_TYPE_CIRC_GRP_BLCK     24
#define ETHERIC_MESSAGE_TYPE_CIRC_GRP_UNBL     25
#define ETHERIC_MESSAGE_TYPE_CIRC_GRP_BL_ACK   26
#define ETHERIC_MESSAGE_TYPE_CIRC_GRP_UNBL_ACK 27
#define ETHERIC_MESSAGE_TYPE_FACILITY_REQ      31
#define ETHERIC_MESSAGE_TYPE_FACILITY_ACC      32
#define ETHERIC_MESSAGE_TYPE_FACILITY_REJ      33
#define ETHERIC_MESSAGE_TYPE_LOOP_BACK_ACK     36
#define ETHERIC_MESSAGE_TYPE_PASS_ALONG        40
#define ETHERIC_MESSAGE_TYPE_CIRC_GRP_RST_ACK  41
#define ETHERIC_MESSAGE_TYPE_CIRC_GRP_QRY      42
#define ETHERIC_MESSAGE_TYPE_CIRC_GRP_QRY_RSP  43
#define ETHERIC_MESSAGE_TYPE_CALL_PROGRSS      44
#define ETHERIC_MESSAGE_TYPE_USER2USER_INFO    45
#define ETHERIC_MESSAGE_TYPE_UNEQUIPPED_CIC    46
#define ETHERIC_MESSAGE_TYPE_CONFUSION         47
#define ETHERIC_MESSAGE_TYPE_OVERLOAD          48
#define ETHERIC_MESSAGE_TYPE_CHARGE_INFO       49
#define ETHERIC_MESSAGE_TYPE_NETW_RESRC_MGMT   50
#define ETHERIC_MESSAGE_TYPE_FACILITY          51
#define ETHERIC_MESSAGE_TYPE_USER_PART_TEST    52
#define ETHERIC_MESSAGE_TYPE_USER_PART_AVAIL   53
#define ETHERIC_MESSAGE_TYPE_IDENT_REQ         54
#define ETHERIC_MESSAGE_TYPE_IDENT_RSP         55
#define ETHERIC_MESSAGE_TYPE_SEGMENTATION      56
#define ETHERIC_MESSAGE_TYPE_LOOP_PREVENTION   64
#define ETHERIC_MESSAGE_TYPE_APPLICATION_TRANS 65
#define ETHERIC_MESSAGE_TYPE_PRE_RELEASE_INFO  66
#define ETHERIC_MESSAGE_TYPE_SUBSEQUENT_DIR_NUM 67


/* Definition of Parameter Types */
#define ETHERIC_PARAM_TYPE_END_OF_OPT_PARAMS      0
#define ETHERIC_PARAM_TYPE_CALL_REF               1
#define ETHERIC_PARAM_TYPE_TRANSM_MEDIUM_REQU     2
#define ETHERIC_PARAM_TYPE_ACC_TRANSP             3
#define ETHERIC_PARAM_TYPE_CALLED_PARTY_NR        4
#define ETHERIC_PARAM_TYPE_SUBSQT_NR              5
#define ETHERIC_PARAM_TYPE_NATURE_OF_CONN_IND     6
#define ETHERIC_PARAM_TYPE_FORW_CALL_IND          7
#define ETHERIC_PARAM_TYPE_OPT_FORW_CALL_IND      8
#define ETHERIC_PARAM_TYPE_CALLING_PRTY_CATEG     9
#define ETHERIC_PARAM_TYPE_CALLING_PARTY_NR      10
#define ETHERIC_PARAM_TYPE_REDIRECTING_NR        11
#define ETHERIC_PARAM_TYPE_REDIRECTION_NR        12
#define ETHERIC_PARAM_TYPE_CONNECTION_REQ        13
#define ETHERIC_PARAM_TYPE_INFO_REQ_IND          14
#define ETHERIC_PARAM_TYPE_INFO_IND              15
#define ETHERIC_PARAM_TYPE_CONTINUITY_IND        16
#define ETHERIC_PARAM_TYPE_BACKW_CALL_IND        17
#define ETHERIC_PARAM_TYPE_CAUSE_INDICATORS      18
#define ETHERIC_PARAM_TYPE_REDIRECTION_INFO      19
#define ETHERIC_PARAM_TYPE_CIRC_GRP_SV_MSG_TYPE  21
#define ETHERIC_PARAM_TYPE_RANGE_AND_STATUS      22
#define ETHERIC_PARAM_TYPE_FACILITY_IND          24
#define ETHERIC_PARAM_TYPE_CLSD_USR_GRP_ILOCK_CD 26
#define ETHERIC_PARAM_TYPE_USER_SERVICE_INFO     29
#define ETHERIC_PARAM_TYPE_SIGNALLING_POINT_CODE 30
#define ETHERIC_PARAM_TYPE_USER_TO_USER_INFO     32
#define ETHERIC_PARAM_TYPE_CONNECTED_NR          33
#define ETHERIC_PARAM_TYPE_SUSP_RESUME_IND       34
#define ETHERIC_PARAM_TYPE_TRANSIT_NETW_SELECT   35
#define ETHERIC_PARAM_TYPE_EVENT_INFO            36
#define ETHERIC_PARAM_TYPE_CIRC_ASSIGN_MAP       37
#define ETHERIC_PARAM_TYPE_CIRC_STATE_IND        38
#define ETHERIC_PARAM_TYPE_AUTO_CONG_LEVEL       39
#define ETHERIC_PARAM_TYPE_ORIG_CALLED_NR        40
#define ETHERIC_PARAM_TYPE_OPT_BACKW_CALL_IND    41
#define ETHERIC_PARAM_TYPE_USER_TO_USER_IND      42
#define ETHERIC_PARAM_TYPE_ORIG_ISC_POINT_CODE   43
#define ETHERIC_PARAM_TYPE_GENERIC_NOTIF_IND     44
#define ETHERIC_PARAM_TYPE_CALL_HIST_INFO        45
#define ETHERIC_PARAM_TYPE_ACC_DELIV_INFO        46
#define ETHERIC_PARAM_TYPE_NETW_SPECIFIC_FACLTY  47
#define ETHERIC_PARAM_TYPE_USER_SERVICE_INFO_PR  48
#define ETHERIC_PARAM_TYPE_PROPAG_DELAY_COUNTER  49
#define ETHERIC_PARAM_TYPE_REMOTE_OPERATIONS     50
#define ETHERIC_PARAM_TYPE_SERVICE_ACTIVATION    51
#define ETHERIC_PARAM_TYPE_USER_TELESERV_INFO    52
#define ETHERIC_PARAM_TYPE_TRANSM_MEDIUM_USED    53
#define ETHERIC_PARAM_TYPE_CALL_DIV_INFO         54
#define ETHERIC_PARAM_TYPE_ECHO_CTRL_INFO        55
#define ETHERIC_PARAM_TYPE_MSG_COMPAT_INFO       56
#define ETHERIC_PARAM_TYPE_PARAM_COMPAT_INFO     57
#define ETHERIC_PARAM_TYPE_MLPP_PRECEDENCE       58
#define ETHERIC_PARAM_TYPE_MCID_REQ_IND          59
#define ETHERIC_PARAM_TYPE_MCID_RSP_IND          60
#define ETHERIC_PARAM_TYPE_HOP_COUNTER           61
#define ETHERIC_PARAM_TYPE_TRANSM_MEDIUM_RQUR_PR 62
#define ETHERIC_PARAM_TYPE_LOCATION_NR           63
#define ETHERIC_PARAM_TYPE_REDIR_NR_RSTRCT       64
#define ETHERIC_PARAM_TYPE_CALL_TRANS_REF        67
#define ETHERIC_PARAM_TYPE_LOOP_PREV_IND         68
#define ETHERIC_PARAM_TYPE_CALL_TRANS_NR         69
#define ETHERIC_PARAM_TYPE_CCSS                  75
#define ETHERIC_PARAM_TYPE_FORW_GVNS             76
#define ETHERIC_PARAM_TYPE_BACKW_GVNS            77
#define ETHERIC_PARAM_TYPE_REDIRECT_CAPAB        78
#define ETHERIC_PARAM_TYPE_NETW_MGMT_CTRL        91
#define ETHERIC_PARAM_TYPE_CORRELATION_ID       101
#define ETHERIC_PARAM_TYPE_SCF_ID               102
#define ETHERIC_PARAM_TYPE_CALL_DIV_TREAT_IND   110
#define ETHERIC_PARAM_TYPE_CALLED_IN_NR         111
#define ETHERIC_PARAM_TYPE_CALL_OFF_TREAT_IND   112
#define ETHERIC_PARAM_TYPE_CHARGED_PARTY_IDENT  113
#define ETHERIC_PARAM_TYPE_CONF_TREAT_IND       114
#define ETHERIC_PARAM_TYPE_DISPLAY_INFO         115
#define ETHERIC_PARAM_TYPE_UID_ACTION_IND       116
#define ETHERIC_PARAM_TYPE_UID_CAPAB_IND        117
#define ETHERIC_PARAM_TYPE_REDIRECT_COUNTER     119
#define ETHERIC_PARAM_TYPE_APPLICATON_TRANS	120
#define ETHERIC_PARAM_TYPE_COLLECT_CALL_REQ     121
#define ETHERIC_PARAM_TYPE_GENERIC_NR           192
#define ETHERIC_PARAM_TYPE_GENERIC_DIGITS       193

static const value_string isup_parameter_type_value[] = {
{ ETHERIC_PARAM_TYPE_END_OF_OPT_PARAMS,        "End of optional parameters"},
  { ETHERIC_PARAM_TYPE_CALL_REF,               "Call Reference (national use)"},
  { ETHERIC_PARAM_TYPE_TRANSM_MEDIUM_REQU,     "Transmission medium requirement"},
  { ETHERIC_PARAM_TYPE_ACC_TRANSP,             "Access transport"},
  { ETHERIC_PARAM_TYPE_CALLED_PARTY_NR,        "Called party number"},
  { ETHERIC_PARAM_TYPE_SUBSQT_NR,              "Subsequent number"},
  { ETHERIC_PARAM_TYPE_NATURE_OF_CONN_IND,     "Nature of connection indicators"},
  { ETHERIC_PARAM_TYPE_FORW_CALL_IND,          "Forward call indicators"},
  { ETHERIC_PARAM_TYPE_OPT_FORW_CALL_IND,      "Optional forward call indicators"},
  { ETHERIC_PARAM_TYPE_CALLING_PRTY_CATEG,     "Calling party's category"},
  { ETHERIC_PARAM_TYPE_CALLING_PARTY_NR,       "Calling party number"},
  { ETHERIC_PARAM_TYPE_REDIRECTING_NR,         "Redirecting number"},
  { ETHERIC_PARAM_TYPE_REDIRECTION_NR,         "Redirection number"},
  { ETHERIC_PARAM_TYPE_CONNECTION_REQ,         "Connection request"},
  { ETHERIC_PARAM_TYPE_INFO_REQ_IND,           "Information request indicators (national use)"},
  { ETHERIC_PARAM_TYPE_INFO_IND,               "Information indicators (national use)"},
  { ETHERIC_PARAM_TYPE_CONTINUITY_IND,         "Continuity request"},
  { ETHERIC_PARAM_TYPE_BACKW_CALL_IND,         "Backward call indicators"},
  { ETHERIC_PARAM_TYPE_CAUSE_INDICATORS,       "Cause indicators"},
  { ETHERIC_PARAM_TYPE_REDIRECTION_INFO,       "Redirection information"},
  { ETHERIC_PARAM_TYPE_CIRC_GRP_SV_MSG_TYPE,   "Circuit group supervision message type"},
  { ETHERIC_PARAM_TYPE_RANGE_AND_STATUS,       "Range and Status"},
  { ETHERIC_PARAM_TYPE_FACILITY_IND,           "Facility indicator"},
  { ETHERIC_PARAM_TYPE_CLSD_USR_GRP_ILOCK_CD,  "Closed user group interlock code"},
  { ETHERIC_PARAM_TYPE_USER_SERVICE_INFO,      "User service information"},
  { ETHERIC_PARAM_TYPE_SIGNALLING_POINT_CODE,  "Signalling point code (national use)"},
  { ETHERIC_PARAM_TYPE_USER_TO_USER_INFO,      "User-to-user information"},
  { ETHERIC_PARAM_TYPE_CONNECTED_NR,           "Connected number"},
  { ETHERIC_PARAM_TYPE_SUSP_RESUME_IND,        "Suspend/Resume indicators"},
  { ETHERIC_PARAM_TYPE_TRANSIT_NETW_SELECT,    "Transit network selection (national use)"},
  { ETHERIC_PARAM_TYPE_EVENT_INFO,             "Event information"},
  { ETHERIC_PARAM_TYPE_CIRC_ASSIGN_MAP,        "Circuit assignment map"},
  { ETHERIC_PARAM_TYPE_CIRC_STATE_IND,         "Circuit state indicator (national use)"},
  { ETHERIC_PARAM_TYPE_AUTO_CONG_LEVEL,        "Automatic congestion level"},
  { ETHERIC_PARAM_TYPE_ORIG_CALLED_NR,         "Original called number"},
  { ETHERIC_PARAM_TYPE_OPT_BACKW_CALL_IND,     "Backward call indicators"},
  { ETHERIC_PARAM_TYPE_USER_TO_USER_IND,       "User-to-user indicators"},
  { ETHERIC_PARAM_TYPE_ORIG_ISC_POINT_CODE,    "Origination ISC point code"},
  { ETHERIC_PARAM_TYPE_GENERIC_NOTIF_IND,      "Generic notification indicator"},
  { ETHERIC_PARAM_TYPE_CALL_HIST_INFO,         "Call history information"},
  { ETHERIC_PARAM_TYPE_ACC_DELIV_INFO,         "Access delivery information"},
  { ETHERIC_PARAM_TYPE_NETW_SPECIFIC_FACLTY,   "Network specific facility (national use)"},
  { ETHERIC_PARAM_TYPE_USER_SERVICE_INFO_PR,   "User service information prime"},
  { ETHERIC_PARAM_TYPE_PROPAG_DELAY_COUNTER,   "Propagation delay counter"},
  { ETHERIC_PARAM_TYPE_REMOTE_OPERATIONS,      "Remote operations (national use)"},
  { ETHERIC_PARAM_TYPE_SERVICE_ACTIVATION,     "Service activation"},
  { ETHERIC_PARAM_TYPE_USER_TELESERV_INFO,     "User teleservice information"},
  { ETHERIC_PARAM_TYPE_TRANSM_MEDIUM_USED,     "Transmission medium used"},
  { ETHERIC_PARAM_TYPE_CALL_DIV_INFO,          "Call diversion information"},
  { ETHERIC_PARAM_TYPE_ECHO_CTRL_INFO,         "Echo control information"},
  { ETHERIC_PARAM_TYPE_MSG_COMPAT_INFO,        "Message compatibility information"},
  { ETHERIC_PARAM_TYPE_PARAM_COMPAT_INFO,      "Parameter compatibility information"},
  { ETHERIC_PARAM_TYPE_MLPP_PRECEDENCE,        "MLPP precedence"},
  { ETHERIC_PARAM_TYPE_MCID_REQ_IND,           "MCID request indicators"},
  { ETHERIC_PARAM_TYPE_MCID_RSP_IND,           "MCID response indicators"},
  { ETHERIC_PARAM_TYPE_HOP_COUNTER,            "Hop counter"},
  { ETHERIC_PARAM_TYPE_TRANSM_MEDIUM_RQUR_PR,  "Transmission medium requirement prime"},
  { ETHERIC_PARAM_TYPE_LOCATION_NR,            "Location number"},
  { ETHERIC_PARAM_TYPE_REDIR_NR_RSTRCT,        "Redirection number restriction"},
  { ETHERIC_PARAM_TYPE_CALL_TRANS_REF,         "Call transfer reference"},
  { ETHERIC_PARAM_TYPE_LOOP_PREV_IND,          "Loop prevention indicators"},
  { ETHERIC_PARAM_TYPE_CALL_TRANS_NR,          "Call transfer number"},
  { ETHERIC_PARAM_TYPE_CCSS,                   "CCSS"},
  { ETHERIC_PARAM_TYPE_FORW_GVNS,              "Forward GVNS"},
  { ETHERIC_PARAM_TYPE_BACKW_GVNS,             "Backward GVNS"},
  { ETHERIC_PARAM_TYPE_REDIRECT_CAPAB,         "Redirect capability (reserved for national use)"},
  { ETHERIC_PARAM_TYPE_NETW_MGMT_CTRL,         "Network management controls"},
  { ETHERIC_PARAM_TYPE_CORRELATION_ID,         "Correlation id"},
  { ETHERIC_PARAM_TYPE_SCF_ID,                 "SCF id"},
  { ETHERIC_PARAM_TYPE_CALL_DIV_TREAT_IND,     "Call diversion treatment indicators"},
  { ETHERIC_PARAM_TYPE_CALLED_IN_NR,           "Called IN number"},
  { ETHERIC_PARAM_TYPE_CALL_OFF_TREAT_IND,     "Call offering treatment indicators"},
  { ETHERIC_PARAM_TYPE_CHARGED_PARTY_IDENT,    "Charged party identification (national use)"},
  { ETHERIC_PARAM_TYPE_CONF_TREAT_IND,         "Conference treatment indicators"},
  { ETHERIC_PARAM_TYPE_DISPLAY_INFO,           "Display information"},
  { ETHERIC_PARAM_TYPE_UID_ACTION_IND,         "UID action indicators"},
  { ETHERIC_PARAM_TYPE_UID_CAPAB_IND,          "UID capability indicators"},
  { ETHERIC_PARAM_TYPE_REDIRECT_COUNTER,       "Redirect counter (reserved for national use)"},
  { ETHERIC_PARAM_TYPE_COLLECT_CALL_REQ,       "Collect call request"},
  { ETHERIC_PARAM_TYPE_GENERIC_NR,             "Generic number"},
  { ETHERIC_PARAM_TYPE_GENERIC_DIGITS,         "Generic digits (national use)"},
  { ETHERIC_PARAM_TYPE_APPLICATON_TRANS,       "Application transport"},
  { 0,                                 NULL}};

static const true_false_string isup_ISDN_originating_access_ind_value = {
  "originating access ISDN",
  "originating access non-ISDN"
};
static const value_string isup_calling_partys_category_value[] = {
  { 0,	"Reserved"},
  { 1,	"Reserved"},
  { 2,	"Reserved"},
  { 3,	"Reserved"},
  { 4,	"Reserved"},
  { 5,	"Reserved"},
  { 10,	"Ordinary calling subscriber"},
  { 11,	"Reserved"},
  { 12,	"Reserved"},
  { 13,	"Test call"},
  /* q.763-200212Amd2 */
  { 14,	"Reserved"},
  { 15,	"Reserved"},
  { 0,	NULL}};
static const value_string isup_transmission_medium_requirement_value[] = {
  { 0,	"speech"},
  { 1,	"64 kbit/s restricted"},
  { 2,	"64 kbit/s unrestricted"},
  { 3,	"3.1 khz audio"},
  { 0,	NULL}};

static const true_false_string isup_odd_even_ind_value = {
  "odd number of address signals",
  "even number of address signals"
};

static const value_string isup_called_party_nature_of_address_ind_value[] = {
  { 0,	"Spare"},
  { 1,	"Reserved"},
  { 2,	"Reserved"},
  { 3,	"national (significant) number"},
  { 4,	"international number"},
  { 5,	"Reserved"},
  { 0,	NULL}};

static const true_false_string isup_NI_ind_value = {
  "incomplete",
  "complete"
};

  static const value_string etheric_location_number_nature_of_address_ind_value[] = {
  { 0,	"Spare"},
  { 1,	"subscriber number (national use)"},
  { 2,	"unknown (national use)"},
  { 3,	"national (significant) number"},
  { 4,	"international number"},
  { 0,NULL}};

static const value_string isup_address_presentation_restricted_ind_value[] = {
  { 0,	"Presentation allowed"},
  { 1,	"Presentation restricted"},
  { 2,	"Reserved"},
  { 3,	"Spare"},
  { 0,	NULL}};

static const value_string isup_screening_ind_value[] = {
  { 0,     "Not available"},
  { 1,     "User provided, verified and passed"},
  { 2,     "reserved"},
  { 3,     "Network provided"},
  { 0,     NULL}};

static const value_string isup_called_party_address_digit_value[] = {
  { 0,  "0"},
  { 1,  "1"},
  { 2,  "2"},
  { 3,  "3"},
  { 4,  "4"},
  { 5,  "5"},
  { 6,  "6"},
  { 7,  "7"},
  { 8,  "8"},
  { 9,  "9"},
  { 10, "spare"},
  { 11, "code 11 "},
  { 12, "code 12"},
  { 15, "Stop sending"},
  { 0,  NULL}};

static const value_string isup_calling_party_address_digit_value[] = {
  { 0,  "0"},
  { 1,  "1"},
  { 2,  "2"},
  { 3,  "3"},
  { 4,  "4"},
  { 5,  "5"},
  { 6,  "6"},
  { 7,  "7"},
  { 8,  "8"},
  { 9,  "9"},
  { 10, "spare"},
  { 11, "code 11 "},
  { 12, "code 12"},
  { 15, "spare"},
  { 0,  NULL}};
static const true_false_string isup_INN_ind_value = {
  "routing to internal network number not allowed",
  "routing to internal network number allowed "
};
static const value_string isup_numbering_plan_ind_value[] = {
  { 1,	"ISDN (Telephony) numbering plan"},
  { 3,	"Data numbering plan (national use)"},
  { 4,	"Telex numbering plan (national use)"},
  { 5,	"Reserved for national use"},
  { 6,	"Reserved for national use"},
  { 0,	NULL}};

  static const true_false_string isup_inband_information_ind_value = {
  /* according 3.37/Q.763 */
  "in-band information or an appropirate pattern is now available",
  "no indication"
};
static const true_false_string isup_event_presentation_restricted_ind_value = {
  /* according 3.21/Q.763 */
  "presentation restricted",
  "no indication"
};
static const value_string isup_event_ind_value[] = {
  /* according 3.21/Q.763 */
  {  1,	"ALERTING"},
  {  2,	"PROGRESS"},
  {  3,	"in-band information or an appropriate pattern is now available"},
  {  4,	"call forwarded on busy (national use)"},
  {  5,	"call forwarded on no reply (national use)"},
  {  6,	"call forwarded unconditional (national use)"},
  {  0,	NULL}};

static void dissect_etheric_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *etheric_tree, guint8 etheric_version, guint8 message_length);

/* ------------------------------------------------------------------
  Mapping number to ASCII-character
 ------------------------------------------------------------------ */
char number_to_char_2(int number)
{
  if (number < 10)
    return ((char) number + 0x30);
  else
    return ((char) number + 0x37);
}

/* Code to actually dissect the packets */
static int
dissect_etheric(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *etheric_tree;
	gint		offset = 0;
	guint8		message_length; 
	guint16		cic;
	guint8		message_type,etheric_version;
	
	tvbuff_t	*message_tvb;
	
	
	/* Do we have the version number? */
	if (!tvb_bytes_exist(tvb, 0, 1)) {
		/* No - reject this packet. */
		return 0;
	}
	etheric_version = tvb_get_guint8(tvb, 0);
	/* Do we know the version? */
	if (match_strval(etheric_version, protocol_version_vals) == NULL) {
		/* No - reject this packet. */
		return 0;
	}

	/* Make entries in Protocol column and Info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "Etheric");

	if (check_col(pinfo->cinfo, COL_INFO)) 
		col_clear(pinfo->cinfo, COL_INFO);

	message_type = tvb_get_guint8(tvb, 4);
	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(message_type, isup_message_type_value_acro, "reserved"));

	if(tree){


/* create display subtree for the protocol */
		ti = proto_tree_add_item(tree, proto_etheric, tvb, 0, -1, FALSE);

		etheric_tree = proto_item_add_subtree(ti, ett_etheric);
		proto_tree_add_item(etheric_tree, hf_etheric_protocol_version, tvb, offset, 1, FALSE);
		offset++;
		message_length = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(etheric_tree, hf_etheric_message_length, tvb, offset, 1, FALSE);
		offset++;

		cic = tvb_get_letohs(tvb, offset) & 0x0FFF; /*since upper 4 bits spare */
		proto_tree_add_uint_format(etheric_tree, hf_etheric_cic, tvb, offset, 2, cic, "CIC: %u", cic);
		offset = offset + 2;
	
		message_tvb = tvb_new_subset(tvb, offset, -1, -1);
		dissect_etheric_message(message_tvb, pinfo, etheric_tree,etheric_version, message_length);


	}/* end end if tree */
	return tvb_length(tvb);
}

/* ------------------------------------------------------------------
 Dissector Parameter Forward Call Indicators
 */
static void
dissect_etheric_forward_call_indicators_parameter(tvbuff_t *parameter_tvb,proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 forward_call_ind;

  forward_call_ind = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_etheric_forw_call_isdn_access_indicator, 
	  parameter_tvb, 0, 1, forward_call_ind);

  proto_item_set_text(parameter_item, "Forward Call Indicators: 0x%x", forward_call_ind );
}

/* ------------------------------------------------------------------
 Dissector Parameter Calling Party's Category
 */
static void
dissect_etheric_calling_partys_category_parameter(tvbuff_t *parameter_tvb,proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 calling_partys_category;

  calling_partys_category = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_etheric_calling_partys_category, parameter_tvb, 
	  0, 1, calling_partys_category);

  proto_item_set_text(parameter_item, "Calling Party's category: 0x%x (%s)", calling_partys_category,
	  val_to_str(calling_partys_category, isup_calling_partys_category_value, "reserved/spare"));
}
/* ------------------------------------------------------------------
  Dissector Parameter Transmission medium requirement
 */
static void
dissect_etheric_transmission_medium_requirement_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 transmission_medium_requirement;

  transmission_medium_requirement = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_etheric_transmission_medium_requirement, parameter_tvb, 0, 1,transmission_medium_requirement);

  proto_item_set_text(parameter_item, "Transmission medium requirement: %u (%s)",  transmission_medium_requirement, val_to_str(transmission_medium_requirement, isup_transmission_medium_requirement_value, "spare"));
}
/* ------------------------------------------------------------------
  Dissector Parameter Called party number
 */
static void
dissect_etheric_called_party_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_item *address_digits_item;
  proto_tree *address_digits_tree;
  guint8 indicators1;
  guint8 address_digit_pair=0;
  gint offset=0;
  gint i=0;
  gint length;
  char called_number[MAXLENGTH]="";
  e164_info_t e164_info;
 
  indicators1 = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_etheric_odd_even_indicator, parameter_tvb, 0, 1, indicators1);
  proto_tree_add_uint(parameter_tree, hf_etheric_called_party_nature_of_address_indicator, parameter_tvb, 0, 1, indicators1);
  offset = 1;

  address_digits_item = proto_tree_add_text(parameter_tree, parameter_tvb,
					    offset, -1,
					    "Called Party Number");
  address_digits_tree = proto_item_add_subtree(address_digits_item, ett_etheric_address_digits);

  while((length = tvb_reported_length_remaining(parameter_tvb, offset)) > 0){
    address_digit_pair = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(address_digits_tree, hf_etheric_called_party_odd_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
    called_number[i++] = number_to_char_2(address_digit_pair & 0x0F);
    if ((length - 1) > 0 ){
      proto_tree_add_uint(address_digits_tree, hf_etheric_called_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      called_number[i++] = number_to_char_2((address_digit_pair & 0xf0) / 0x10);
    }
    offset++;
  }

  if  (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_etheric_called_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      called_number[i++] = number_to_char_2((address_digit_pair & 0xf0) / 0x10);
  }
  called_number[i++] = '\0';
  e164_info.e164_number_type = CALLED_PARTY_NUMBER;
  e164_info.nature_of_address = indicators1 & 0x7f;
  e164_info.E164_number_str = called_number;
  e164_info.E164_number_length = i - 1;
  dissect_e164_number(parameter_tvb, address_digits_tree, 2,
								  (offset - 2), e164_info);
  proto_item_set_text(address_digits_item, "Called Party Number: %s", called_number);
  proto_item_set_text(parameter_item, "Called Party Number: %s", called_number);

}
/* ------------------------------------------------------------------
  Dissector Parameter calling party number
 */
static void
dissect_etheric_calling_party_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_item *address_digits_item;
  proto_tree *address_digits_tree;
  guint8 indicators1, indicators2;
  guint8 address_digit_pair=0;
  gint offset=0;
  gint i=0;
  gint length;
  char calling_number[MAXLENGTH]="";
  e164_info_t e164_info;

  indicators1 = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_etheric_odd_even_indicator, parameter_tvb, 0, 1, indicators1);
  proto_tree_add_uint(parameter_tree, hf_etheric_called_party_nature_of_address_indicator, parameter_tvb, 0, 1, indicators1);
  indicators2 = tvb_get_guint8(parameter_tvb, 1);
  proto_tree_add_uint(parameter_tree, hf_etheric_address_presentation_restricted_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_etheric_screening_indicator, parameter_tvb, 1, 1, indicators2);
  offset = 2;

  address_digits_item = proto_tree_add_text(parameter_tree, parameter_tvb,
					    offset, -1,
					    "Calling Party Number");
  address_digits_tree = proto_item_add_subtree(address_digits_item, ett_etheric_address_digits);

  length = tvb_length_remaining(parameter_tvb, offset);
  while(length > 0){
    address_digit_pair = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(address_digits_tree, hf_etheric_calling_party_odd_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
    calling_number[i++] = number_to_char_2(address_digit_pair & 0x0F);
    if ((length - 1) > 0 ){
      proto_tree_add_uint(address_digits_tree, hf_etheric_calling_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      calling_number[i++] = number_to_char_2((address_digit_pair & 0xF0) / 0x10);
    }
    offset++;
    length = tvb_length_remaining(parameter_tvb, offset);
  }

  if  (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_etheric_calling_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      calling_number[i++] = number_to_char_2((address_digit_pair & 0xF0) / 0x10);
  }
  calling_number[i++] = '\0';

  proto_item_set_text(address_digits_item, "Calling Party Number: %s", calling_number);
  proto_item_set_text(parameter_item, "Calling Party Number: %s", calling_number);
  
    e164_info.e164_number_type = CALLING_PARTY_NUMBER;
    e164_info.nature_of_address = indicators1 & 0x7f;
    e164_info.E164_number_str = calling_number;
    e164_info.E164_number_length = i - 1;
    dissect_e164_number(parameter_tvb, address_digits_tree, 2, (offset - 2), e164_info);
 
}
/* ------------------------------------------------------------------
  Dissector Parameter location number
 */
static void
dissect_etheric_location_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_item *address_digits_item;
  proto_tree *address_digits_tree;
  guint8 indicators1, indicators2;
  guint8 address_digit_pair=0;
  gint offset=0;
  gint i=0;
  gint length;
  char calling_number[MAXLENGTH]="";

  indicators1 = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_etheric_odd_even_indicator, parameter_tvb, 0, 1, indicators1);
  proto_tree_add_uint(parameter_tree, hf_etheric_calling_party_nature_of_address_indicator, parameter_tvb, 0, 1, indicators1);
  indicators2 = tvb_get_guint8(parameter_tvb, 1);
  proto_tree_add_boolean(parameter_tree, hf_etheric_inn_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_etheric_numbering_plan_indicator, parameter_tvb, 1, 1, indicators2);
  if ((indicators2 & 0x70) == 0x50)
    proto_tree_add_text(parameter_tree, parameter_tvb, 1, 1, "Different meaning for Location Number: Numbering plan indicator = private numbering plan");
  proto_tree_add_uint(parameter_tree, hf_etheric_address_presentation_restricted_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_etheric_screening_indicator, parameter_tvb, 1, 1, indicators2);

   /* NOTE  When the address presentation restricted indicator indicates address not available, the
    * subfields in items a), b), c) and d) are coded with 0's, and the screening indicator is set to 11
    * (network provided).
    */
  if ( indicators2 == 0x0b ){
    proto_tree_add_text(parameter_tree, parameter_tvb, 1, -1, "Location number: address not available");
    proto_item_set_text(parameter_item, "Location number: address not available");
    return;
  }

  offset = 2;

  address_digits_item = proto_tree_add_text(parameter_tree, parameter_tvb,
					    offset, -1,
					    "Location number");
  address_digits_tree = proto_item_add_subtree(address_digits_item, ett_etheric_address_digits);

  length = tvb_length_remaining(parameter_tvb, offset);
  while(length > 0){
    address_digit_pair = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(address_digits_tree, hf_etheric_calling_party_odd_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
    calling_number[i++] = number_to_char_2(address_digit_pair & 0x0f);
    if ((length - 1) > 0 ){
      proto_tree_add_uint(address_digits_tree, hf_etheric_calling_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      calling_number[i++] = number_to_char_2((address_digit_pair & 0xf0) / 0x10);
    }
    offset++;
    length = tvb_length_remaining(parameter_tvb, offset);
  }

  if  (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_etheric_calling_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      calling_number[i++] = number_to_char_2((address_digit_pair & 0xf0) / 0x10);
  }
  calling_number[i++] = '\0';

  proto_item_set_text(address_digits_item, "Location number: %s", calling_number);
  proto_item_set_text(parameter_item, "Location number: %s", calling_number);

}

/* ------------------------------------------------------------------
  Dissector Parameter User service information- no detailed dissection since defined in Rec. Q.931
 */
static void
dissect_etheric_user_service_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, length,
	  "User service information (-> Q.931 Bearer_capability)");
  proto_item_set_text(parameter_item, "User service information, (%u byte%s length)",
	  length , plurality(length, "", "s"));
  dissect_q931_bearer_capability_ie(parameter_tvb,
					    0, length,
					    parameter_tree);
}
/* ------------------------------------------------------------------
  Dissector Parameter Access Transport - no detailed dissection since defined in Rec. Q.931
 */
static void
dissect_etheric_access_transport_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree,
			 proto_item *parameter_item, packet_info *pinfo)
{ guint length = tvb_reported_length(parameter_tvb);

  proto_tree_add_text(parameter_tree, parameter_tvb, 0, -1, 
	  "Access transport parameter field (-> Q.931)");
  
  if (q931_ie_handle)
    call_dissector(q931_ie_handle, parameter_tvb, pinfo, parameter_tree);

  proto_item_set_text(parameter_item, "Access transport (%u byte%s length)",
	  length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
 Dissector Parameter Backward Call Indicators
 */
static void
dissect_etheric_backward_call_indicators_parameter(tvbuff_t *parameter_tvb,proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 backward_call_ind;

  backward_call_ind = tvb_get_guint8(parameter_tvb, 0);


  proto_tree_add_boolean(parameter_tree, hf_etheric_inband_information_ind, parameter_tvb, 0, 1, backward_call_ind);

  proto_item_set_text(parameter_item, "Backward Call Indicators: 0x%x", backward_call_ind);
}
/* ------------------------------------------------------------------
  Dissector Parameter Cause Indicators - no detailed dissection since defined in Rec. Q.850
 */

/*
 * Cause codes for Cause.
 * The decoding of cause indicators parameter field are defined in ITU-T
 * Recommendation Q.850; those are different from the ones in the Q.931
 * dissector, as that has some values not specified by the standard but
 * that appear to be used for purposes other than the ones in Q.850.
 */
static const value_string q850_cause_code_vals[] = {
	{ 0x00,	"Valid cause code not yet received" },
	{ 0x01,	"Unallocated (unassigned) number" },
	{ 0x02,	"No route to specified transit network" },
	{ 0x03,	"No route to destination" },
	{ 0x04,	"Send special information tone" },
	{ 0x05,	"Misdialled trunk prefix" },
	{ 0x06,	"Channel unacceptable" },
	{ 0x07,	"Call awarded and being delivered in an established channel" },
	{ 0x08,	"Preemption" },
	{ 0x09,	"Preemption - circuit reserved for reuse" },
	{ 0x0E,	"QoR: ported number" },
	{ 0x10,	"Normal call clearing" },
	{ 0x11,	"User busy" },
	{ 0x12,	"No user responding" },
	{ 0x13,	"No answer from user (user alerted)" },
	{ 0x14,	"Subscriber absent" },
	{ 0x15,	"Call rejected" },
	{ 0x16,	"Number changed" },
	{ 0x17,	"Redirection to new destination" },
	{ 0x18,	"Call rejected due to feature at the destination" },
	{ 0x19,	"Exchange routing error" },
	{ 0x1A,	"Non-selected user clearing" },
	{ 0x1B,	"Destination out of order" },
	{ 0x1C,	"Invalid number format (address incomplete)" },
	{ 0x1D,	"Facility rejected" },
	{ 0x1E,	"Response to STATUS ENQUIRY" },
	{ 0x1F,	"Normal unspecified" },
	{ 0x21,	"Circuit out of order" },
	{ 0x22,	"No circuit/channel available" },
	{ 0x26,	"Network out of order" },
	{ 0x27,	"Permanent frame mode connection out of service" },
	{ 0x28,	"Permanent frame mode connection operational" },
	{ 0x29,	"Temporary failure" },
	{ 0x2A,	"Switching equipment congestion" },
	{ 0x2B,	"Access information discarded" },
	{ 0x2C,	"Requested circuit/channel not available" },
	{ 0x2E,	"Precedence call blocked" },
	{ 0x2F,	"Resources unavailable, unspecified" },
	{ 0x31,	"Quality of service unavailable" },
	{ 0x32,	"Requested facility not subscribed" },
	{ 0x35,	"Outgoing calls barred within CUG" },
	{ 0x37,	"Incoming calls barred within CUG" },
	{ 0x38,	"Call waiting not subscribed" },
	{ 0x39,	"Bearer capability not authorized" },
	{ 0x3A,	"Bearer capability not presently available" },
	{ 0x3E,	"Inconsistency in designated outgoing access information and subscriber class" },
	{ 0x3F,	"Service or option not available, unspecified" },
	{ 0x41,	"Bearer capability not implemented" },
	{ 0x42,	"Channel type not implemented" },
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
	{ 0x5A,	"Non-existing CUG" },
	{ 0x5B,	"Invalid transit network selection (national use)" },
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

/* ------------------------------------------------------------------
  Dissector Message Type release message
 */
gint
dissect_etheric_release_message(tvbuff_t *message_tvb, proto_tree *etheric_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  gint offset = 0;
  gint parameter_type, parameter_pointer, parameter_length;

  /* Do stuff for mandatory variable parameter Cause indicators */
  parameter_type =  ETHERIC_PARAM_TYPE_CAUSE_INDICATORS;

  parameter_pointer = 0;
  parameter_length = 1;

  parameter_item = proto_tree_add_text(etheric_tree, message_tvb,
				       offset +  parameter_pointer, 1,"Cause indicators, see Q.850");

  parameter_tree = proto_item_add_subtree(parameter_item, ett_etheric_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_etheric_parameter_type, message_tvb, 0, 1, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));
  proto_tree_add_item(parameter_tree, hf_etheric_cause_indicator, message_tvb, 0, 1,FALSE);
  offset += 1;

  return offset;
}
/* ------------------------------------------------------------------
  Dissector Parameter Event information
 */
static void
dissect_etheric_event_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 indicators;

  indicators = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint_format(parameter_tree, hf_etheric_event_ind, parameter_tvb, 0, 1, indicators, "Event indicator: %s (%u)", val_to_str(indicators & 0x7f, isup_event_ind_value, "spare"), indicators & 0x7f);
  proto_tree_add_boolean(parameter_tree, hf_etheric_event_presentation_restricted_ind, parameter_tvb, 0, 1, indicators);

  proto_item_set_text(parameter_item,"Event information: %s (%u)", val_to_str(indicators & 0x7f, isup_event_ind_value, "spare"),indicators );
}

/* ------------------------------------------------------------------ */
static void
dissect_etheric_unknown_parameter(tvbuff_t *parameter_tvb, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_item_set_text(parameter_item, "Parameter Type unknown/reserved (%u Byte%s)", length , plurality(length, "", "s"));
}

/* ------------------------------------------------------------------ */
/* Dissectors for all used message types                              */
/* Called by dissect_etheric_message(),                               */
/* call parameter dissectors in order of mandatory parameters         */
/* (since not labeled)                                                */
/* ------------------------------------------------------------------
  Dissector Message Type Initial address message
 */
gint
dissect_etheric_initial_address_message(tvbuff_t *message_tvb, proto_tree *etheric_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  tvbuff_t *parameter_tvb;
  gint offset = 0;
  gint parameter_type, parameter_pointer, parameter_length, actual_length;

  /* Do stuff for 1nd mandatory fixed parameter: Forward Call Indicators */
  parameter_type =  ETHERIC_PARAM_TYPE_FORW_CALL_IND;
  parameter_item = proto_tree_add_text(etheric_tree, message_tvb, offset,
				       1,
				       "Forward Call Indicators");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_etheric_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_etheric_parameter_type, message_tvb, 0, 0,
	  parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(2, actual_length), 2 );
  dissect_etheric_forward_call_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset +=  1;

  /* Do stuff for 2nd mandatory fixed parameter: Calling party's category */
  parameter_type = ETHERIC_PARAM_TYPE_CALLING_PRTY_CATEG;
  parameter_item = proto_tree_add_text(etheric_tree, message_tvb, offset,
				       1, "Calling Party's category");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_etheric_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_etheric_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(1, actual_length),1 );
  dissect_etheric_calling_partys_category_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += 1;
  /* Do stuff for 3d mandatory fixed parameter: Transmission medium requirement */
  parameter_type = ETHERIC_PARAM_TYPE_TRANSM_MEDIUM_REQU;
  parameter_item = proto_tree_add_text(etheric_tree, message_tvb, offset,
				       1, "Transmission medium requirement");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_etheric_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_etheric_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(1, actual_length), 1);
  dissect_etheric_transmission_medium_requirement_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += 1;


  /* Do stuff for mandatory variable parameter Called party number */
  parameter_type = ETHERIC_PARAM_TYPE_CALLED_PARTY_NR;
  parameter_pointer = tvb_get_guint8(message_tvb, offset);
  parameter_length = tvb_get_guint8(message_tvb, offset + parameter_pointer);

  parameter_item = proto_tree_add_text(etheric_tree, message_tvb,
				       offset +  parameter_pointer,
				       parameter_length + 1,
				       "Called Party Number");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_etheric_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_etheric_parameter_type, message_tvb, 0, 0,
	  parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));
  proto_tree_add_uint_format(parameter_tree, hf_etheric_mandatory_variable_parameter_pointer,
	  message_tvb, offset, 1, parameter_pointer, "Pointer to Parameter: %u", parameter_pointer);
  proto_tree_add_uint_format(parameter_tree, hf_etheric_parameter_length, message_tvb,
	  offset + parameter_pointer, 1, parameter_length, "Parameter length: %u", parameter_length);
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset + parameter_pointer + 1, MIN(parameter_length, actual_length), parameter_length );
  dissect_etheric_called_party_number_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += 1;
  /* Do stuff for mandatory variable parameter Calling party number */
  parameter_type = ETHERIC_PARAM_TYPE_CALLING_PARTY_NR;
  parameter_pointer = tvb_get_guint8(message_tvb, offset);
  parameter_length = tvb_get_guint8(message_tvb, offset + parameter_pointer);

  parameter_item = proto_tree_add_text(etheric_tree, message_tvb,
				       offset +  parameter_pointer,
				       parameter_length + 1,
				       "Calling Party Number");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_etheric_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_etheric_parameter_type, message_tvb, 0, 0,
	  parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));
  proto_tree_add_uint_format(parameter_tree, hf_etheric_mandatory_variable_parameter_pointer,
	  message_tvb, offset, 1, parameter_pointer, "Pointer to Parameter: %u", parameter_pointer);
  proto_tree_add_uint_format(parameter_tree, hf_etheric_parameter_length, message_tvb,
	  offset + parameter_pointer, 1, parameter_length, "Parameter length: %u", parameter_length);
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset + parameter_pointer + 1, MIN(parameter_length, actual_length), parameter_length );
  dissect_etheric_calling_party_number_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += 1;
  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type Address complete
 */
gint
dissect_etheric_address_complete_message(tvbuff_t *message_tvb, proto_tree *etheric_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  tvbuff_t *parameter_tvb;
  gint offset = 0;
  gint parameter_type, actual_length;

  /* Do stuff for first mandatory fixed parameter: backward call indicators*/
  parameter_type = ETHERIC_PARAM_TYPE_BACKW_CALL_IND;
  parameter_item = proto_tree_add_text(etheric_tree, message_tvb, offset,
				       1,
				       "Backward Call Indicators");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_etheric_parameter);
  
  proto_tree_add_uint_format(parameter_tree, hf_etheric_parameter_type, message_tvb, 0, 0,
	  parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));
  
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(1, actual_length), 1);
  dissect_etheric_backward_call_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += 1;
  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type Call Progress
*/
gint
dissect_etheric_call_progress_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  tvbuff_t *parameter_tvb;
  gint offset = 0;
  gint parameter_type, actual_length;

  /* Do stuff for first mandatory fixed parameter: Event information*/
  parameter_type = ETHERIC_PARAM_TYPE_EVENT_INFO;
  parameter_item = proto_tree_add_text(isup_tree, message_tvb, offset,
				       1,
				       "Event information");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_etheric_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_etheric_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(1, actual_length), 1);
  dissect_etheric_event_information_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += 1;
  return offset;
}

/* ------------------------------------------------------------------
  Dissector all optional parameters
*/
static void
dissect_etheric_optional_parameter(tvbuff_t *optional_parameters_tvb,packet_info *pinfo, proto_tree *etheric_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  gint offset = 0;
  guint parameter_type, parameter_length, actual_length;
  tvbuff_t *parameter_tvb;

  /* Dissect all optional parameters while end of message isn't reached */
  parameter_type = 0xFF; /* Start-initializiation since parameter_type is used for while-condition */

  while ((tvb_length_remaining(optional_parameters_tvb, offset)  >= 1) && (parameter_type != ETHERIC_PARAM_TYPE_END_OF_OPT_PARAMS)){
    parameter_type = tvb_get_guint8(optional_parameters_tvb, offset);

    if (parameter_type != ETHERIC_PARAM_TYPE_END_OF_OPT_PARAMS){
      parameter_length = tvb_get_guint8(optional_parameters_tvb, offset + 1);

      parameter_item = proto_tree_add_text(etheric_tree, optional_parameters_tvb,
					   offset,
					   parameter_length  + 1 + 1,
					   "Parameter: type %u",
					   parameter_type);
      parameter_tree = proto_item_add_subtree(parameter_item, ett_etheric_parameter);
      proto_tree_add_uint_format(parameter_tree, hf_etheric_parameter_type, optional_parameters_tvb, offset, 1, parameter_type, "Optional Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));
      offset += 1;

      proto_tree_add_uint_format(parameter_tree, hf_etheric_parameter_length, optional_parameters_tvb, offset, 1, parameter_length, "Parameter length: %u", parameter_length);
      offset += 1;

      actual_length = tvb_length_remaining(optional_parameters_tvb, offset);
      if (actual_length > 0){
	parameter_tvb = tvb_new_subset(optional_parameters_tvb, offset, MIN(parameter_length, actual_length), parameter_length);
	switch (parameter_type) {
	case ETHERIC_PARAM_TYPE_USER_SERVICE_INFO:
	  dissect_etheric_user_service_information_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case ETHERIC_PARAM_TYPE_ACC_TRANSP:
	  dissect_etheric_access_transport_parameter(parameter_tvb, parameter_tree, parameter_item, pinfo);
	  break;
	 
	case ETHERIC_PARAM_TYPE_LOCATION_NR:
	  dissect_etheric_location_number_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;

	default:
	  dissect_etheric_unknown_parameter(parameter_tvb, parameter_item);
	  break;
	}
	offset += MIN(parameter_length, actual_length);
      }

    }
    else {
	/* End of optional parameters is reached */
	proto_tree_add_uint_format(etheric_tree, hf_etheric_message_type, optional_parameters_tvb , offset, 1, parameter_type, "End of optional parameters (%u)", parameter_type);
    }
  }
}
		

static void
dissect_etheric_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *etheric_tree, guint8 etheric_version, guint8 message_length)
{
  tvbuff_t *parameter_tvb;
  tvbuff_t *optional_parameter_tvb;
  gint offset, bufferlength;
  guint8 message_type; 
  guint8 opt_parameter_pointer = 0;
  gint opt_part_possible = FALSE; /* default setting - for message types allowing optional
				     params explicitely set to TRUE in case statement */
  offset = 0;
    /* Extract message type field */
  message_type = tvb_get_guint8(message_tvb,0);
  proto_tree_add_item(etheric_tree, hf_etheric_message_type, message_tvb, 0, 1,FALSE);
  offset ++;
  parameter_tvb = tvb_new_subset(message_tvb, offset, -1, -1);

  switch (message_type) {
    case ETHERIC_MESSAGE_TYPE_ADDR_CMPL:
       offset += dissect_etheric_address_complete_message(parameter_tvb, etheric_tree);
       opt_part_possible = FALSE;
      break;

    case ETHERIC_MESSAGE_TYPE_ANSWER:
      /* no dissector necessary since no mandatory parameters included */
		if (etheric_version > 0x10 ) /* 0x10,	"Etheric 2.0" */
	       opt_part_possible = TRUE;
      break;

    case ETHERIC_MESSAGE_TYPE_BLOCK_ACK:
      /* no dissector necessary since no mandatory parameters included */
      break;

    case ETHERIC_MESSAGE_TYPE_BLOCKING:
      /* no dissector necessary since no mandatory parameters included */
      break;

    case ETHERIC_MESSAGE_TYPE_CONNECT:
		if (etheric_version > 0x10 ) /* 0x10,	"Etheric 2.0" */
			opt_part_possible = TRUE;
      break;

    case ETHERIC_MESSAGE_TYPE_CALL_PROGRSS:
       offset += dissect_etheric_call_progress_message(parameter_tvb, etheric_tree);
       opt_part_possible = TRUE;
      break;

    case ETHERIC_MESSAGE_TYPE_CIRC_GRP_RST:
      /* no dissector necessary since no mandatory parameters included */
      break;

    case ETHERIC_MESSAGE_TYPE_CIRC_GRP_RST_ACK:
      /* no dissector necessary since no mandatory parameters included */
      break;

    case ETHERIC_MESSAGE_TYPE_INITIAL_ADDR:
		offset += dissect_etheric_initial_address_message(parameter_tvb, etheric_tree);
		if (etheric_version > 0 ) /* 0x00,	"Etheric 1.0" */
			opt_part_possible = TRUE;
     break;

    case ETHERIC_MESSAGE_TYPE_RELEASE:
       offset += dissect_etheric_release_message(parameter_tvb, etheric_tree);
       opt_part_possible = FALSE;
      break;

	case ETHERIC_MESSAGE_TYPE_REL_CMPL:
      /* no dissector necessary since no mandatory parameters included */
      break;
    case ETHERIC_MESSAGE_TYPE_RESET_CIRCUIT:
      /* no dissector necessary since no mandatory parameters included */
      break;
 
	case ETHERIC_MESSAGE_TYPE_UNBLOCKING:
      /* no dissector necessary since no mandatory parameters included */
      break;
    case ETHERIC_MESSAGE_TYPE_UNBLOCK_ACK:
      /* no dissector necessary since no mandatory parameters included */
      break;
 default:
     bufferlength = tvb_length_remaining(message_tvb, offset);
     if (bufferlength != 0)
       proto_tree_add_text(etheric_tree, parameter_tvb, 0, bufferlength, 
			"Unknown Message type (possibly reserved/used in former ISUP version)");
     break;
  }

   /* extract pointer to start of optional part (if any) */
   if (opt_part_possible == TRUE){
	   if (message_length > 5 ) {
		   opt_parameter_pointer = tvb_get_guint8(message_tvb, offset);

		   proto_tree_add_uint_format(etheric_tree, hf_etheric_pointer_to_start_of_optional_part,
				message_tvb, offset, 1, opt_parameter_pointer, "Pointer to start of optional part: %u", opt_parameter_pointer);
		   offset += opt_parameter_pointer;
		   if (opt_parameter_pointer > 0){
		     optional_parameter_tvb = tvb_new_subset(message_tvb, offset, -1, -1 );
		     dissect_etheric_optional_parameter(optional_parameter_tvb, pinfo, etheric_tree);
		   }
	   }
   }
   else if (message_type !=ETHERIC_MESSAGE_TYPE_CHARGE_INFO)
     proto_tree_add_text(etheric_tree, message_tvb, 0, 0, 
		"No optional parameters are possible with this message type");

}
/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_etheric(void)
{
	static dissector_handle_t etheric_handle;

	static int tcp_port1 = 1806;
	static int tcp_port2 = 10002;
	static int Initialized=FALSE;


	if (!Initialized) {
		etheric_handle = find_dissector("etheric");
		Initialized=TRUE;
	}else{
		dissector_delete("udp.port", tcp_port1, etheric_handle);
		dissector_delete("udp.port", tcp_port2, etheric_handle);
	}

	tcp_port1 = ethericTCPport1;
	tcp_port2 = ethericTCPport2;

	dissector_add("tcp.port", ethericTCPport1, etheric_handle);
	dissector_add("tcp.port", ethericTCPport2, etheric_handle);
	q931_ie_handle = find_dissector("q931.ie");

}

void
proto_register_etheric(void)
{                 

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_etheric_protocol_version,
			{ "Protocol version",           "etheric.protocol_version",
			FT_UINT8, BASE_HEX, VALS(&protocol_version_vals), 0x0,          
			"Etheric protocol version", HFILL }
		},
		{ &hf_etheric_message_length,
			{ "Message length",           "etheric.message.length",
			FT_UINT8, BASE_DEC, NULL, 0x0,          
			"Etheric Message length", HFILL }
		},
		{ &hf_etheric_cic,
			{ "CIC",           "etheric.cic",
			FT_UINT16, BASE_DEC, NULL, 0x0,          
			"Etheric CIC", HFILL }
		},
		{ &hf_etheric_message_type,
			{ "Message type",           "etheric.message.type",
			FT_UINT8, BASE_HEX, VALS(&isup_message_type_value), 0x0,          
			"Etheric message types", HFILL }
		},
		{ &hf_etheric_parameter_type,
			{ "Parameter Type",  "etheric.parameter_type",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_etheric_forw_call_isdn_access_indicator,
			{ "ISDN access indicator",  "etheric.forw_call_isdn_access_indicator",
			FT_BOOLEAN, 16, TFS(&isup_ISDN_originating_access_ind_value), 0x01,
			"", HFILL }},

		{ &hf_etheric_calling_partys_category,
			{ "Calling Party's category",  "etheric.calling_partys_category",
			FT_UINT8, BASE_HEX, VALS(isup_calling_partys_category_value), 0x0,
			"", HFILL }},

		{ &hf_etheric_mandatory_variable_parameter_pointer,
			{ "Pointer to Parameter",  "etheric.mandatory_variable_parameter_pointer",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_etheric_pointer_to_start_of_optional_part,
			{ "Pointer to optional parameter part",  "etheric.optional_parameter_part_pointer",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_etheric_parameter_length,
			{ "Parameter Length",  "etheric.parameter_length",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_etheric_transmission_medium_requirement,
			{ "Transmission medium requirement",  "etheric.transmission_medium_requirement",
			FT_UINT8, BASE_DEC, VALS(isup_transmission_medium_requirement_value), 0x0,
			"", HFILL }},

		{ &hf_etheric_odd_even_indicator,
			{ "Odd/even indicator",  "etheric.isdn_odd_even_indicator",
			FT_BOOLEAN, 8, TFS(&isup_odd_even_ind_value), 0x80,
			"", HFILL }},

		{ &hf_etheric_called_party_nature_of_address_indicator,
			{ "Nature of address indicator",  "etheric.called_party_nature_of_address_indicator",
			FT_UINT8, BASE_DEC, VALS(isup_called_party_nature_of_address_ind_value), 0x3f,
			"", HFILL }},

		{ &hf_etheric_calling_party_nature_of_address_indicator,
			{ "Nature of address indicator",  "etheric.calling_party_nature_of_address_indicator",
			FT_UINT8, BASE_DEC, VALS(etheric_location_number_nature_of_address_ind_value), 0x7f,
			"", HFILL }},


		{ &hf_etheric_ni_indicator,
			{ "NI indicator",  "etheric.ni_indicator",
			FT_BOOLEAN, 8, TFS(&isup_NI_ind_value), 0x80,
			"", HFILL }},

		{ &hf_etheric_inn_indicator,
			{ "INN indicator",  "etheric.inn_indicator",
			FT_BOOLEAN, 8, TFS(&isup_INN_ind_value), 0x80,
			"", HFILL }},

		{ &hf_etheric_numbering_plan_indicator,
			{ "Numbering plan indicator",  "etheric.numbering_plan_indicator",
			FT_UINT8, BASE_DEC, VALS(isup_numbering_plan_ind_value), 0x70,
			"", HFILL }},

		{ &hf_etheric_address_presentation_restricted_indicator,
			{ "Address presentation restricted indicator",  "etheric.address_presentation_restricted_indicator",
			FT_UINT8, BASE_DEC, VALS(isup_address_presentation_restricted_ind_value), 0x0c,
			"", HFILL }},

		{ &hf_etheric_screening_indicator,
			{ "Screening indicator",  "etheric.screening_indicator",
			FT_UINT8, BASE_DEC, VALS(isup_screening_ind_value), 0x03,
			"", HFILL }},

		{ &hf_etheric_called_party_odd_address_signal_digit,
			{ "Address signal digit",  "etheric.called_party_odd_address_signal_digit",
			FT_UINT8, BASE_DEC, VALS(isup_called_party_address_digit_value), 0x0F,
			"", HFILL }},

		{ &hf_etheric_calling_party_odd_address_signal_digit,
			{ "Address signal digit",  "etheric.calling_party_odd_address_signal_digit",
			FT_UINT8, BASE_DEC, VALS(isup_calling_party_address_digit_value), 0x0F,
			"", HFILL }},

		{ &hf_etheric_called_party_even_address_signal_digit,
			{ "Address signal digit",  "etheric.called_party_even_address_signal_digit",
			FT_UINT8, BASE_DEC, VALS(isup_called_party_address_digit_value), 0xF0,
			"", HFILL }},

		{ &hf_etheric_calling_party_even_address_signal_digit,
			{ "Address signal digit",  "etheric.calling_party_even_address_signal_digit",
			FT_UINT8, BASE_DEC, VALS(isup_calling_party_address_digit_value), 0xF0,
			"", HFILL }},

		{ &hf_etheric_inband_information_ind,
			{ "In-band information indicator",  "etheric.inband_information_ind",
			FT_BOOLEAN, 8, TFS(&isup_inband_information_ind_value), 0x01,
			"", HFILL }},

		{ &hf_etheric_cause_indicator,
			{ "Cause indicator",  "etheric.cause_indicator",
			FT_UINT8, BASE_DEC, VALS(q850_cause_code_vals), 0x7f,
			"", HFILL }},

		{ &hf_etheric_event_ind,
			{ "Event indicator",  "etheric.event_ind",
			  FT_UINT8, 8, VALS(isup_event_ind_value), 0x7f,
			"", HFILL }},

		{ &hf_etheric_event_presentation_restricted_ind,
			{ "Event presentation restricted indicator",  "etheric.event_presentatiation_restr_ind",
			FT_BOOLEAN, 8, TFS(&isup_event_presentation_restricted_ind_value), 0x80,
			"", HFILL }},


	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_etheric,
		&ett_etheric_parameter,
		&ett_etheric_address_digits,
		&ett_etheric_circuit_state_ind,
	};

	module_t *etheric_module;

/* Register the protocol name and description */
	proto_etheric = proto_register_protocol("Etheric",
	    "ETHERIC", "etheric");

	new_register_dissector("etheric", dissect_etheric, proto_etheric);


/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_etheric, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));


	/* Register a configuration option for port */
	etheric_module = prefs_register_protocol(proto_etheric,
											  proto_reg_handoff_etheric);

	prefs_register_uint_preference(etheric_module, "tcp.port1",
								   "etheric TCP Port 1",
								   "Set TCP port 1 for etheric messages",
								   10,
								   &ethericTCPport1);

	prefs_register_uint_preference(etheric_module, "tcp.port2",
								   "etheric TCP Port 2",
								   "Set TCP port 2 for etheric messages",
								   10,
								   &ethericTCPport2);
}
