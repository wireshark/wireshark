/* packet-ISUP.c
 * Routines for ISUP dissection
 * Copyright 2001, Martina Obermeier <martina.obermeier@icn.siemens.de>
 *
 * $Id: packet-isup.c,v 1.5 2001/08/28 08:28:14 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include "packet.h"
#include "packet-ip.h"

#define MTP3_ISUP_SERVICE_INDICATOR     5
#define ASCII_NUMBER_DELTA              0x30
#define ASCII_LETTER_DELTA              0x37

/* Definition of protocol field values und lengths */

/* Definition of Message Types */
#define MESSAGE_TYPE_INITIAL_ADDR       1
#define MESSAGE_TYPE_SUBSEQ_ADDR        2
#define MESSAGE_TYPE_INFO_REQ           3
#define MESSAGE_TYPE_INFO               4
#define MESSAGE_TYPE_CONTINUITY         5
#define MESSAGE_TYPE_ADDR_CMPL          6
#define MESSAGE_TYPE_CONNECT            7
#define MESSAGE_TYPE_FORW_TRANS         8
#define MESSAGE_TYPE_ANSWER             9
#define MESSAGE_TYPE_RELEASE           12 
#define MESSAGE_TYPE_SUSPEND           13
#define MESSAGE_TYPE_RESUME            14 
#define MESSAGE_TYPE_REL_CMPL          16
#define MESSAGE_TYPE_CONT_CHECK_REQ    17
#define MESSAGE_TYPE_RESET_CIRCUIT     18
#define MESSAGE_TYPE_BLOCKING          19
#define MESSAGE_TYPE_UNBLOCKING        20
#define MESSAGE_TYPE_BLOCK_ACK         21
#define MESSAGE_TYPE_UNBLOCK_ACK       22
#define MESSAGE_TYPE_CIRC_GRP_RST      23
#define MESSAGE_TYPE_CIRC_GRP_BLCK     24
#define MESSAGE_TYPE_CIRC_GRP_UNBL     25
#define MESSAGE_TYPE_CIRC_GRP_BL_ACK   26
#define MESSAGE_TYPE_CIRC_GRP_UNBL_ACK 27 
#define MESSAGE_TYPE_FACILITY_REQ      31
#define MESSAGE_TYPE_FACILITY_ACC      32
#define MESSAGE_TYPE_FACILITY_REJ      33
#define MESSAGE_TYPE_LOOP_BACK_ACK     36
#define MESSAGE_TYPE_PASS_ALONG        40
#define MESSAGE_TYPE_CIRC_GRP_RST_ACK  41
#define MESSAGE_TYPE_CIRC_GRP_QRY      42
#define MESSAGE_TYPE_CIRC_GRP_QRY_RSP  43
#define MESSAGE_TYPE_CALL_PROGRSS      44
#define MESSAGE_TYPE_USER2USER_INFO    45
#define MESSAGE_TYPE_UNEQUIPPED_CIC    46
#define MESSAGE_TYPE_CONFUSION         47
#define MESSAGE_TYPE_OVERLOAD          48
#define MESSAGE_TYPE_CHARGE_INFO       49
#define MESSAGE_TYPE_NETW_RESRC_MGMT   50
#define MESSAGE_TYPE_FACILITY          51
#define MESSAGE_TYPE_USER_PART_TEST    52
#define MESSAGE_TYPE_USER_PART_AVAIL   53
#define MESSAGE_TYPE_IDENT_REQ         54
#define MESSAGE_TYPE_IDENT_RSP         55 
#define MESSAGE_TYPE_SEGMENTATION      56
#define MESSAGE_TYPE_LOOP_PREVENTION   64

static const value_string isup_message_type_value[] = {
  { MESSAGE_TYPE_INITIAL_ADDR,          "Initial address"},
  { MESSAGE_TYPE_SUBSEQ_ADDR,           "Subsequent address"},
  { MESSAGE_TYPE_INFO_REQ,              "Information request (national use)"},
  { MESSAGE_TYPE_INFO,                  "Information (national use)"},
  { MESSAGE_TYPE_CONTINUITY,            "Continuity"},
  { MESSAGE_TYPE_ADDR_CMPL,             "Address complete"},
  { MESSAGE_TYPE_CONNECT,               "Connect"},
  { MESSAGE_TYPE_FORW_TRANS,            "Forward transfer"},
  { MESSAGE_TYPE_ANSWER,                "Answer"},
  { MESSAGE_TYPE_RELEASE,               "Release"},
  { MESSAGE_TYPE_SUSPEND,               "Suspend"},
  { MESSAGE_TYPE_RESUME,                "Resume"},
  { MESSAGE_TYPE_REL_CMPL,              "Release complete"},
  { MESSAGE_TYPE_CONT_CHECK_REQ,        "Continuity check request"},
  { MESSAGE_TYPE_RESET_CIRCUIT,         "Reset Circuit"},
  { MESSAGE_TYPE_BLOCKING,              "Blocking"},
  { MESSAGE_TYPE_UNBLOCKING,            "Unblocking"},
  { MESSAGE_TYPE_BLOCK_ACK,             "Blocking acknowledgement"},
  { MESSAGE_TYPE_UNBLOCK_ACK,           "Unblocking acknowledgment"},
  { MESSAGE_TYPE_CIRC_GRP_RST,          "Circuit group reset"},
  { MESSAGE_TYPE_CIRC_GRP_BLCK,         "Circuit group blocking"},
  { MESSAGE_TYPE_CIRC_GRP_UNBL,         "Circuit group unblocking"},
  { MESSAGE_TYPE_CIRC_GRP_BL_ACK,       "Circuit group blocking acknowledgement"},
  { MESSAGE_TYPE_CIRC_GRP_UNBL_ACK,     "Circuit group unblocking acknowledgement"},
  { MESSAGE_TYPE_FACILITY_REQ,          "Facility request"},
  { MESSAGE_TYPE_FACILITY_ACC,          "Facility accepted"},
  { MESSAGE_TYPE_FACILITY_REJ,          "Facility reject"},
  { MESSAGE_TYPE_LOOP_BACK_ACK,         "Loop back acknowledgement (national use)"},
  { MESSAGE_TYPE_PASS_ALONG,            "Pass-along (national use)"},
  { MESSAGE_TYPE_CIRC_GRP_RST_ACK,      "Circuit group reset acknowledgement"},
  { MESSAGE_TYPE_CIRC_GRP_QRY,          "Circuit group query (national use)"},
  { MESSAGE_TYPE_CIRC_GRP_QRY_RSP,      "Circuit group query response (national use)"},
  { MESSAGE_TYPE_CALL_PROGRSS,          "Call progress"},
  { MESSAGE_TYPE_USER2USER_INFO,        "User-to-user information"},
  { MESSAGE_TYPE_UNEQUIPPED_CIC,        "Unequipped CIC (national use)"},
  { MESSAGE_TYPE_CONFUSION,             "Confusion"},
  { MESSAGE_TYPE_OVERLOAD,              "Overload (national use)"},
  { MESSAGE_TYPE_CHARGE_INFO,           "Charge information (national use)"},
  { MESSAGE_TYPE_NETW_RESRC_MGMT,       "Network resource management"},
  { MESSAGE_TYPE_FACILITY,              "Facility"},
  { MESSAGE_TYPE_USER_PART_TEST,        "User part test"},
  { MESSAGE_TYPE_USER_PART_AVAIL,       "User part available"},
  { MESSAGE_TYPE_IDENT_REQ,             "Identification request"},
  { MESSAGE_TYPE_IDENT_RSP,             "Identification response"},
  { MESSAGE_TYPE_SEGMENTATION,          "Segmentation"},
  { MESSAGE_TYPE_LOOP_PREVENTION,       "Loop prevention"},
  { 0,                                  NULL}};

/* Definition of Parameter Types */
#define PARAM_TYPE_END_OF_OPT_PARAMS      0
#define PARAM_TYPE_CALL_REF               1
#define PARAM_TYPE_TRANSM_MEDIUM_REQU     2
#define PARAM_TYPE_ACC_TRANSP             3
#define PARAM_TYPE_CALLED_PARTY_NR        4
#define PARAM_TYPE_SUBSQT_NR              5
#define PARAM_TYPE_NATURE_OF_CONN_IND     6
#define PARAM_TYPE_FORW_CALL_IND          7
#define PARAM_TYPE_OPT_FORW_CALL_IND      8
#define PARAM_TYPE_CALLING_PRTY_CATEG     9
#define PARAM_TYPE_CALLING_PARTY_NR      10
#define PARAM_TYPE_REDIRECTING_NR        11
#define PARAM_TYPE_REDIRECTION_NR        12
#define PARAM_TYPE_CONNECTION_REQ        13
#define PARAM_TYPE_INFO_REQ_IND          14
#define PARAM_TYPE_INFO_IND              15
#define PARAM_TYPE_CONTINUITY_IND        16
#define PARAM_TYPE_BACKW_CALL_IND        17
#define PARAM_TYPE_CAUSE_INDICATORS      18
#define PARAM_TYPE_REDIRECTION_INFO      19
#define PARAM_TYPE_CIRC_GRP_SV_MSG_TYPE  21
#define PARAM_TYPE_RANGE_AND_STATUS      22
#define PARAM_TYPE_FACILITY_IND          24
#define PARAM_TYPE_CLSD_USR_GRP_ILOCK_CD 26
#define PARAM_TYPE_USER_SERVICE_INFO     29
#define PARAM_TYPE_SIGNALLING_POINT_CODE 30
#define PARAM_TYPE_USER_TO_USER_INFO     32
#define PARAM_TYPE_CONNECTED_NR          33
#define PARAM_TYPE_SUSP_RESUME_IND       34
#define PARAM_TYPE_TRANSIT_NETW_SELECT   35
#define PARAM_TYPE_EVENT_INFO            36
#define PARAM_TYPE_CIRC_ASSIGN_MAP       37
#define PARAM_TYPE_CIRC_STATE_IND        38
#define PARAM_TYPE_AUTO_CONG_LEVEL       39
#define PARAM_TYPE_ORIG_CALLED_NR        40
#define PARAM_TYPE_OPT_BACKW_CALL_IND    41
#define PARAM_TYPE_USER_TO_USER_IND      42
#define PARAM_TYPE_ORIG_ISC_POINT_CODE   43
#define PARAM_TYPE_GENERIC_NOTIF_IND     44
#define PARAM_TYPE_CALL_HIST_INFO        45 
#define PARAM_TYPE_ACC_DELIV_INFO        46
#define PARAM_TYPE_NETW_SPECIFIC_FACLTY  47
#define PARAM_TYPE_USER_SERVICE_INFO_PR  48
#define PARAM_TYPE_PROPAG_DELAY_COUNTER  49
#define PARAM_TYPE_REMOTE_OPERATIONS     50
#define PARAM_TYPE_SERVICE_ACTIVATION    51
#define PARAM_TYPE_USER_TELESERV_INFO    52
#define PARAM_TYPE_TRANSM_MEDIUM_USED    53
#define PARAM_TYPE_CALL_DIV_INFO         54
#define PARAM_TYPE_ECHO_CTRL_INFO        55
#define PARAM_TYPE_MSG_COMPAT_INFO       56
#define PARAM_TYPE_PARAM_COMPAT_INFO     57
#define PARAM_TYPE_MLPP_PRECEDENCE       58  
#define PARAM_TYPE_MCID_REQ_IND          59
#define PARAM_TYPE_MCID_RSP_IND          60
#define PARAM_TYPE_HOP_COUNTER           61
#define PARAM_TYPE_TRANSM_MEDIUM_RQUR_PR 62
#define PARAM_TYPE_LOCATION_NR           63
#define PARAM_TYPE_REDIR_NR_RSTRCT       64
#define PARAM_TYPE_CALL_TRANS_REF        67
#define PARAM_TYPE_LOOP_PREV_IND         68
#define PARAM_TYPE_CALL_TRANS_NR         69
#define PARAM_TYPE_CCSS                  75
#define PARAM_TYPE_FORW_GVNS             76
#define PARAM_TYPE_BACKW_GVNS            77
#define PARAM_TYPE_REDIRECT_CAPAB        78
#define PARAM_TYPE_NETW_MGMT_CTRL        91
#define PARAM_TYPE_CORRELATION_ID       101
#define PARAM_TYPE_SCF_ID               102
#define PARAM_TYPE_CALL_DIV_TREAT_IND   110
#define PARAM_TYPE_CALLED_IN_NR         111
#define PARAM_TYPE_CALL_OFF_TREAT_IND   112
#define PARAM_TYPE_CHARGED_PARTY_IDENT  113
#define PARAM_TYPE_CONF_TREAT_IND       114
#define PARAM_TYPE_DISPLAY_INFO         115
#define PARAM_TYPE_UID_ACTION_IND       116
#define PARAM_TYPE_UID_CAPAB_IND        117
#define PARAM_TYPE_REDIRECT_COUNTER     119
#define PARAM_TYPE_COLLECT_CALL_REQ     121
#define PARAM_TYPE_GENERIC_NR           192
#define PARAM_TYPE_GENERIC_DIGITS       193

static const value_string isup_parameter_type_value[] = {
{ PARAM_TYPE_END_OF_OPT_PARAMS,        "End of optional parameters"},
  { PARAM_TYPE_CALL_REF,               "Call Reference (national use)"},
  { PARAM_TYPE_TRANSM_MEDIUM_REQU,     "Transmission medium requirement"},
  { PARAM_TYPE_ACC_TRANSP,             "Access transport"},
  { PARAM_TYPE_CALLED_PARTY_NR,        "Called party number"},
  { PARAM_TYPE_SUBSQT_NR,              "Subsequent number"},
  { PARAM_TYPE_NATURE_OF_CONN_IND,     "Nature of connection indicators"},
  { PARAM_TYPE_FORW_CALL_IND,          "Forward call indicators"},
  { PARAM_TYPE_OPT_FORW_CALL_IND,      "Optional forward call indicators"},
  { PARAM_TYPE_CALLING_PRTY_CATEG,     "Calling party's category"},
  { PARAM_TYPE_CALLING_PARTY_NR,       "Calling party number"},
  { PARAM_TYPE_REDIRECTING_NR,         "Redirecting number"},
  { PARAM_TYPE_REDIRECTION_NR,         "Redirection number"},
  { PARAM_TYPE_CONNECTION_REQ,         "Connection request"},
  { PARAM_TYPE_INFO_REQ_IND,           "Information request indicators (national use)"},
  { PARAM_TYPE_INFO_IND,               "Information indicators (national use)"},
  { PARAM_TYPE_CONTINUITY_IND,         "Continuity request"},
  { PARAM_TYPE_BACKW_CALL_IND,         "Backward call indicators"},
  { PARAM_TYPE_CAUSE_INDICATORS,       "Cause indicators"},
  { PARAM_TYPE_REDIRECTION_INFO,       "Redirection information"},
  { PARAM_TYPE_CIRC_GRP_SV_MSG_TYPE,   "Circuit group supervision message type"},
  { PARAM_TYPE_RANGE_AND_STATUS,       "Range and Status"},
  { PARAM_TYPE_FACILITY_IND,           "Facility indicator"},
  { PARAM_TYPE_CLSD_USR_GRP_ILOCK_CD,  "Closed user group interlock code"},
  { PARAM_TYPE_USER_SERVICE_INFO,      "User service information"},
  { PARAM_TYPE_SIGNALLING_POINT_CODE,  "Signalling point code (national use)"},
  { PARAM_TYPE_USER_TO_USER_INFO,      "User-to-user information"},
  { PARAM_TYPE_CONNECTED_NR,           "Connected number"},
  { PARAM_TYPE_SUSP_RESUME_IND,        "Suspend/Resume indicators"},
  { PARAM_TYPE_TRANSIT_NETW_SELECT,    "Transit network selection (national use)"},
  { PARAM_TYPE_EVENT_INFO,             "Event information"},
  { PARAM_TYPE_CIRC_ASSIGN_MAP,        "Circuit assignment map"},
  { PARAM_TYPE_CIRC_STATE_IND,         "Circuit state indicator (national use)"},
  { PARAM_TYPE_AUTO_CONG_LEVEL,        "Automatic congestion level"},
  { PARAM_TYPE_ORIG_CALLED_NR,         "Original called number"},
  { PARAM_TYPE_OPT_BACKW_CALL_IND,     "Backward call indicators"},
  { PARAM_TYPE_USER_TO_USER_IND,       "User-to-user indicators"},
  { PARAM_TYPE_ORIG_ISC_POINT_CODE,    "Origination ISC point code"},
  { PARAM_TYPE_GENERIC_NOTIF_IND,      "Generic notification indicator"},
  { PARAM_TYPE_CALL_HIST_INFO,         "Call history information"},
  { PARAM_TYPE_ACC_DELIV_INFO,         "Access delivery information"},
  { PARAM_TYPE_NETW_SPECIFIC_FACLTY,   "Network specific facility (national use)"},
  { PARAM_TYPE_USER_SERVICE_INFO_PR,   "User service information prime"},
  { PARAM_TYPE_PROPAG_DELAY_COUNTER,   "Propagation delay counter"},
  { PARAM_TYPE_REMOTE_OPERATIONS,      "Remote operations (national use)"},
  { PARAM_TYPE_SERVICE_ACTIVATION,     "Service activation"},
  { PARAM_TYPE_USER_TELESERV_INFO,     "User teleservice information"},
  { PARAM_TYPE_TRANSM_MEDIUM_USED,     "Transmission medium used"},
  { PARAM_TYPE_CALL_DIV_INFO,          "Call diversion information"},
  { PARAM_TYPE_ECHO_CTRL_INFO,         "Echo control information"},
  { PARAM_TYPE_MSG_COMPAT_INFO,        "Message compatibility information"},
  { PARAM_TYPE_PARAM_COMPAT_INFO,      "Parameter compatibility information"},
  { PARAM_TYPE_MLPP_PRECEDENCE,        "MLPP precedence"},
  { PARAM_TYPE_MCID_REQ_IND,           "MCID request indicators"},
  { PARAM_TYPE_MCID_RSP_IND,           "MCID response indicators"},
  { PARAM_TYPE_HOP_COUNTER,            "Hop counter"},
  { PARAM_TYPE_TRANSM_MEDIUM_RQUR_PR,  "Transmission medium requirement prime"},
  { PARAM_TYPE_LOCATION_NR,            "Location number"},
  { PARAM_TYPE_REDIR_NR_RSTRCT,        "Redirection number restriction"},
  { PARAM_TYPE_CALL_TRANS_REF,         "Call transfer reference"},
  { PARAM_TYPE_LOOP_PREV_IND,          "Loop prevention indicators"},
  { PARAM_TYPE_CALL_TRANS_NR,          "Call transfer number"},
  { PARAM_TYPE_CCSS,                   "CCSS"},
  { PARAM_TYPE_FORW_GVNS,              "Forward GVNS"},
  { PARAM_TYPE_BACKW_GVNS,             "Backward GVNS"},
  { PARAM_TYPE_REDIRECT_CAPAB,         "Redirect capability (reserved for national use)"},
  { PARAM_TYPE_NETW_MGMT_CTRL,         "Network management controls"},
  { PARAM_TYPE_CORRELATION_ID,         "Correlation id"},
  { PARAM_TYPE_SCF_ID,                 "SCF id"},
  { PARAM_TYPE_CALL_DIV_TREAT_IND,     "Call diversion treatment indicators"},
  { PARAM_TYPE_CALLED_IN_NR,           "Called IN number"},
  { PARAM_TYPE_CALL_OFF_TREAT_IND,     "Call offering treatment indicators"},
  { PARAM_TYPE_CHARGED_PARTY_IDENT,    "Charged party identification (national use)"},
  { PARAM_TYPE_CONF_TREAT_IND,         "Conference treatment indicators"},
  { PARAM_TYPE_DISPLAY_INFO,           "Display information"},
  { PARAM_TYPE_UID_ACTION_IND,         "UID action indicators"},
  { PARAM_TYPE_UID_CAPAB_IND,          "UID capability indicators"},
  { PARAM_TYPE_REDIRECT_COUNTER,       "Redirect counter (reserved for national use)"},
  { PARAM_TYPE_COLLECT_CALL_REQ,       "Collect call request"},
  { PARAM_TYPE_GENERIC_NR,             "Generic number"},
  { PARAM_TYPE_GENERIC_DIGITS,         "Generic digits (national use)"},
  { 0,                                 NULL}};


#define CIC_LENGTH                             2
#define MESSAGE_TYPE_LENGTH                    1
#define COMMON_HEADER_LENGTH                   (CIC_LENGTH + MESSAGE_TYPE_LENGTH)

#define MAXLENGTH                            0xFF /* since length field is 8 Bit long - used in number dissectors;
						     max. number of address digits is 15 digits, but MAXLENGTH used 
						     to avoid runtime errors */

#define PARAMETER_TYPE_LENGTH                  1
#define PARAMETER_POINTER_LENGTH               1
#define PARAMETER_LENGTH_IND_LENGTH            1

/* All following parameter length definitions are WITHOUT the parameter type byte and length indicator for optional parameters*/ 
#define PARAMETER_NAME_LENGTH                  1
#define PARAMETER_LENGTH_IND_LENGTH            1
#define ACCESS_DELIVERY_INFO_LENGTH            1
#define AUTO_CONGEST_LEVEL_LENGTH              1
#define BACKWARD_CALL_IND_LENGTH               2
#define BACKWARD_GVNS_LENGTH                   1
#define CALL_DIV_INFO_LENGTH                   1
#define CALL_DIV_TREATMENT_IND_LENGTH          1
#define CALL_HISTORY_INFO_LENGTH               2
#define CALL_OFFERING_TREATMENT_IND_LENGTH     1
#define CALL_REFERENCE_LENGTH                  5
#define CALL_TRANSFER_REF_LENGTH               1
#define CALLING_PRTYS_CATEGORY_LENGTH          1
#define CCSS_LENGTH                            1
#define CIRCUIT_ASSIGNMENT_MAP_LENGTH          5
#define CIRC_GRP_SV_MSG_TYPE_LENGTH            1
#define CLOSED_USR_GRP_INTERLOCK_CODE_LENGTH   4
#define COLLECT_CALL_REQUEST_LENGTH            1
#define CONFERENCE_TREATMENT_IND_LENGTH        1
#define CONNECTION_REQUEST_LENGTH              7
#define CONTINUITY_IND_LENGTH                  1
#define ECHO_CONTROL_INFO_LENGTH               1
#define END_OF_OPT_PART_LENGTH                 1
#define EVENT_INFO_LENGTH                      1
#define FACILITY_IND_LENGTH                    1
#define FORWARD_CALL_IND_LENGTH                2
#define GENERIC_NOTIFICATION_IND_LENGTH        1
#define HOP_COUNTER_LENGTH                     1
#define INFO_IND_LENGTH                        2
#define INFO_REQUEST_IND_LENGTH                2
#define LOOP_PREVENTION_IND_LENGTH             1
#define MCID_REQUEST_IND_LENGTH                1
#define MCID_RESPONSE_IND_LENGTH               1
#define MLPP_PRECEDENCE_LENGTH                 1
#define NATURE_OF_CONNECTION_IND_LENGTH        1
#define NETWORK_MANAGEMENT_CONTROLS_LENGTH     1
#define OPTIONAL_BACKWARD_CALL_IND_LENGTH      1
#define OPTIONAL_FORWARD_CALL_IND_LENGTH       1
#define ORIGINAL_ISC_POINT_CODE_LENGTH         2
#define PROPAGATION_DELAY_COUNT_LENGTH         2
#define REDIRECTION_NUMBER_LENGTH              2
#define REDIRECTION_INFO_LENGTH                2
#define REDIRECTION_NUMBER_RESTRICTION_LENGTH  1
#define SIGNALLING_POINT_CODE_LENGTH           2
#define SUSPEND_RESUME_IND_LENGTH              1
#define TRANSMISSION_MEDIUM_REQUIREMENT_LENGTH 1
#define TRANSMISSION_MEDIUM_RQMT_PRIME_LENGTH  1
#define TRANSMISSION_MEDIUM_USED_LENGTH        1
#define UID_ACTION_IND_LENGTH                  1
#define UID_CAPABILITY_IND_LENGTH              1
#define USER_TELESERVICE_INFO_LENGTH           3
#define USER_TO_USER_IND_LENGTH                1
#define RANGE_LENGTH                           1

#define CALL_ID_LENGTH        3 /* for parameter Call Reference */
#define SPC_LENGTH            2 /* for parameter Call Reference, Connection request */
#define LOCAL_REF_LENGTH      3 /* for parameter Connection request */
#define PROTOCOL_CLASS_LENGTH 1 /* for parameter Connection request */
#define CREDIT_LENGTH         1 /* for parameter Connection request */

#define CIC_OFFSET            0

#define NO_SATELLITE_CIRCUIT_IN_CONNECTION   0
#define ONE_SATELLITE_CIRCUIT_IN_CONNECTION  1
#define TWO_SATELLITE_CIRCUIT_IN_CONNECTION  2
static const value_string isup_satellite_ind_value[] = {
  { NO_SATELLITE_CIRCUIT_IN_CONNECTION,          "No Satellite circuit in connection"},
  { ONE_SATELLITE_CIRCUIT_IN_CONNECTION,         "One Satellite circuit in connection"},  
  { TWO_SATELLITE_CIRCUIT_IN_CONNECTION,         "Two Satellite circuits in connection"},
  { 0,                                 NULL}};

#define CONTINUITY_CHECK_NOT_REQUIRED           0
#define CONTINUITY_CHECK_REQUIRED               1
#define CONTINUITY_CHECK_ON_A_PREVIOUS_CIRCUIT  2
static const value_string isup_continuity_check_ind_value[] = {
  { CONTINUITY_CHECK_NOT_REQUIRED,               "Continuity check not required"},
  { CONTINUITY_CHECK_REQUIRED,                   "Continuity check required on this circuit"},  
  { CONTINUITY_CHECK_ON_A_PREVIOUS_CIRCUIT ,     "Continuity check performed on a previous circuit"},
  { 0,                                 NULL}};

static const true_false_string isup_echo_control_device_ind_value = {
  "Echo control device included",
  "Echo control device not included"
};

static const true_false_string isup_natnl_inatnl_call_ind_value = {
  "Call to be treated as international call",
  "Call to be treated as national call"
};

#define NO_END_TO_END_METHOD_AVAILABLE       0
#define PASS_ALONG_METHOD_AVAILABLE          1
#define SCCP_METHOD_AVAILABLE                2
#define PASS_ALONG_AND_SCCP_METHOD_AVAILABLE 3
static const value_string isup_end_to_end_method_ind_value[] = {
  { NO_END_TO_END_METHOD_AVAILABLE,          "No End-to-end method available (only link-by-link method available)"},
  { PASS_ALONG_METHOD_AVAILABLE,             "Pass-along method available (national use)"},  
  { SCCP_METHOD_AVAILABLE,                   "SCCP method available"},
  { PASS_ALONG_AND_SCCP_METHOD_AVAILABLE,    "pass-along and SCCP method available (national use)"},
  { 0,                                 NULL}};

static const true_false_string isup_interworking_ind_value = {
  "interworking encountered",
  "no interworking encountered (No.7 signalling all the way)"
};

static const true_false_string isup_end_to_end_info_ind_value = {
  "end-to-end information available",
  "no end-to-end information available"
};

static const true_false_string isup_ISDN_user_part_ind_value = {
  "ISDN user part used all the way",
  "ISDN user part not used all the way"
};

#define ISUP_PREFERED_ALL_THE_WAY               0
#define ISUP_NOT_REQUIRED_ALL_THE_WAY           1
#define ISUP_REQUIRED_ALL_WAY                   2
#define ISUP_ISDN_USER_PART_IND_SPARE           3
static const value_string isup_preferences_ind_value[] = {
  { ISUP_PREFERED_ALL_THE_WAY,                   "ISDN user part prefered all the way"},
  { ISUP_NOT_REQUIRED_ALL_THE_WAY,               "ISDN user part not required all the way"},  
  { ISUP_REQUIRED_ALL_WAY,                       "ISDN user part required all the way"},
  { ISUP_ISDN_USER_PART_IND_SPARE,               "spare"},
  { 0,                                 NULL}};

static const true_false_string isup_ISDN_originating_access_ind_value = {
  "originating access ISDN",
  "originating access non-ISDN"
};

#define NO_INDICATION                                0
#define CONNECTIONLESS_METHOD_AVAILABLE              1
#define CONNECITON_ORIENTED_METHOD_AVAILABLE         2
#define CONNECTIONLESS_AND_ORIENTED_METHOD_AVAILABLE 3
static const value_string isup_SCCP_method_ind_value[] = {
  { NO_INDICATION,                                  "No indication"},
  { CONNECTIONLESS_METHOD_AVAILABLE,                "Connectionless method available (national use)"},  
  { CONNECITON_ORIENTED_METHOD_AVAILABLE,           "Connection oriented method available"},
  { CONNECTIONLESS_AND_ORIENTED_METHOD_AVAILABLE,   "Connectionless and -oriented method available (national use)"},
  { 0,                                 NULL}};

#define UNKNOWN_AT_THIS_TIME                 0
#define OPERATOR_FRENCH                      1
#define OPERATOR_ENGLISH                     2
#define OPERATOR_GERMAN                      3
#define OPERATOR_RUSSIAN                     4
#define OPERATOR_SPANISH                     5
#define ORDINARY_CALLING_SUBSCRIBER         10
#define CALLING_SUBSCRIBER_WITH_PRIORITY    11
#define DATA_CALL                           12
#define TEST_CALL                           13
#define PAYPHONE                            15
static const value_string isup_calling_partys_category_value[] = {
  { UNKNOWN_AT_THIS_TIME,               "Category unknown at this time (national use)"},
  { OPERATOR_FRENCH,                    "operator, language French"},  
  { OPERATOR_ENGLISH,                   "operator, language English"},  
  { OPERATOR_GERMAN,                    "operator, language German"},  
  { OPERATOR_RUSSIAN,                   "operator, language Russian"},  
  { OPERATOR_SPANISH,                   "operator, language Spanish"},  
  { ORDINARY_CALLING_SUBSCRIBER,        "ordinary calling subscriber"},
  { CALLING_SUBSCRIBER_WITH_PRIORITY,   "calling subscriber with priority"},
  { DATA_CALL,                          "data call (voice band data)"},
  { TEST_CALL,                          "test call"},
  { PAYPHONE,                           "payphone"},
  { 0,                                 NULL}};

#define MEDIUM_SPEECH                        0
#define MEDIUM_64KBS                         2
#define MEDIUM_3_1_KHZ_AUDIO                 3
#define MEDIUM_RESERVED_SERVICE2_1           4
#define MEDIUM_RESERVED_SERVICE1_2           5
#define MEDIUM_64KBS_PREFERED                6
#define MEDIUM_2_64KBS                       7
#define MEDIUM_384KBS                        8
#define MEDIUM_1536KBS                       9
#define MEDIUM_1920KBS                      10
#define MEDIUM_3_64KBS                      16
#define MEDIUM_4_64KBS                      17
#define MEDIUM_5_64KBS                      18
#define MEDIUM_7_64KBS                      20
#define MEDIUM_8_64KBS                      21
#define MEDIUM_9_64KBS                      22
#define MEDIUM_10_64KBS                     23
#define MEDIUM_11_64KBS                     24
#define MEDIUM_12_64KBS                     25
#define MEDIUM_13_64KBS                     26
#define MEDIUM_14_64KBS                     27
#define MEDIUM_15_64KBS                     28
#define MEDIUM_16_64KBS                     29
#define MEDIUM_17_64KBS                     30
#define MEDIUM_18_64KBS                     31
#define MEDIUM_19_64KBS                     32
#define MEDIUM_20_64KBS                     33
#define MEDIUM_21_64KBS                     34
#define MEDIUM_22_64KBS                     35
#define MEDIUM_23_64KBS                     36
#define MEDIUM_25_64KBS                     38
#define MEDIUM_26_64KBS                     39
#define MEDIUM_27_64KBS                     40
#define MEDIUM_28_64KBS                     41
#define MEDIUM_29_64KBS                     42
static const value_string isup_transmission_medium_requirement_value[] = {
  { MEDIUM_SPEECH,                       "speech"},
  { MEDIUM_64KBS,                        "64 kbit/s unrestricted"},
  { MEDIUM_3_1_KHZ_AUDIO,                "3.1 kHz audio"},
  { MEDIUM_RESERVED_SERVICE2_1,          "reserved for alternate speech (service 2)/64 kbit/s unrestricted (service 1)"},
  { MEDIUM_RESERVED_SERVICE1_2,          "reserved for alternate 64 kbit/s unrestricted (service 1)/speech (service 2)"},
  { MEDIUM_64KBS_PREFERED,               "64 kbit/s prefered"},
  { MEDIUM_2_64KBS,                      "2x64 kbit/s unrestricted"},
  { MEDIUM_384KBS,                       "384 kbit/s unrestricted"},
  { MEDIUM_1536KBS,                      "1536 kbit/s unrestricted"},
  { MEDIUM_1920KBS,                      "1920 kbit/s unrestricted"},
  { MEDIUM_3_64KBS,                      "3x64 kbit/s unrestricted"},
  { MEDIUM_4_64KBS,                      "4x64 kbit/s unrestricted"},
  { MEDIUM_5_64KBS,                      "5x64 kbit/s unrestricted"},
  { MEDIUM_7_64KBS,                      "7x64 kbit/s unrestricted"},
  { MEDIUM_8_64KBS,                      "8x64 kbit/s unrestricted"},
  { MEDIUM_9_64KBS,                      "9x64 kbit/s unrestricted"},
  { MEDIUM_10_64KBS,                     "10x64 kbit/s unrestricted"},
  { MEDIUM_11_64KBS,                     "11x64 kbit/s unrestricted"},
  { MEDIUM_12_64KBS,                     "12x64 kbit/s unrestricted"},
  { MEDIUM_13_64KBS,                     "13x64 kbit/s unrestricted"},
  { MEDIUM_14_64KBS,                     "14x64 kbit/s unrestricted"},
  { MEDIUM_15_64KBS,                     "15x64 kbit/s unrestricted"},
  { MEDIUM_16_64KBS,                     "16x64 kbit/s unrestricted"},
  { MEDIUM_17_64KBS,                     "17x64 kbit/s unrestricted"},
  { MEDIUM_18_64KBS,                     "18x64 kbit/s unrestricted"},
  { MEDIUM_19_64KBS,                     "19x64 kbit/s unrestricted"},
  { MEDIUM_20_64KBS,                     "20x64 kbit/s unrestricted"},
  { MEDIUM_21_64KBS,                     "21x64 kbit/s unrestricted"},
  { MEDIUM_22_64KBS,                     "22x64 kbit/s unrestricted"},
  { MEDIUM_23_64KBS,                     "23x64 kbit/s unrestricted"},
  { MEDIUM_25_64KBS,                     "25x64 kbit/s unrestricted"},
  { MEDIUM_26_64KBS,                     "26x64 kbit/s unrestricted"},
  { MEDIUM_27_64KBS,                     "27x64 kbit/s unrestricted"},
  { MEDIUM_28_64KBS,                     "28x64 kbit/s unrestricted"},
  { MEDIUM_29_64KBS,                     "29x64 kbit/s unrestricted"},
  { 0,                                 NULL}};
static const value_string isup_transmission_medium_requirement_prime_value[] = {
  { MEDIUM_SPEECH,                       "speech"},
  { MEDIUM_64KBS,                        "reserved for 64 kbit/s unrestricted"},
  { MEDIUM_3_1_KHZ_AUDIO,                "3.1 kHz audio"},
  { MEDIUM_RESERVED_SERVICE2_1,          "reserved for alternate speech (service 2)/64 kbit/s unrestricted (service 1)"},
  { MEDIUM_RESERVED_SERVICE1_2,          "reserved for alternate 64 kbit/s unrestricted (service 1)/speech (service 2)"},
  { MEDIUM_64KBS_PREFERED,               "reserved for 64 kbit/s prefered"},
  { MEDIUM_2_64KBS,                      "reserved for 2x64 kbit/s unrestricted"},
  { MEDIUM_384KBS,                       "reserved for 384 kbit/s unrestricted"},
  { MEDIUM_1536KBS,                      "reserved for 1536 kbit/s unrestricted"},
  { MEDIUM_1920KBS,                      "reserved for 1920 kbit/s unrestricted"},
  { 0,                                 NULL}};


/* Definitions for Called and Calling Party number */
#define ISUP_ODD_EVEN_MASK                       0x80
#define ISUP_NATURE_OF_ADDRESS_IND_MASK          0x7F
#define ISUP_INN_MASK                            0x80
#define ISUP_NI_MASK                             0x80
#define ISUP_NUMBERING_PLAN_IND_MASK             0x70
#define ISUP_ADDRESS_PRESENTATION_RESTR_IND_MASK 0x0C
#define ISUP_SCREENING_IND_MASK                  0x03
#define ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK       0x0F
#define ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK      0xF0

static const true_false_string isup_odd_even_ind_value = {
  "odd number of address signals",
  "even number of address signals"
};

#define ISUP_CALLED_PARTY_NATURE_SUBSCRIBER_NR  1
#define ISUP_CALLED_PARTY_NATURE_UNKNOWN        2
#define ISUP_CALLED_PARTY_NATURE_NATIONAL_NR    3
#define ISUP_CALLED_PARTY_NATURE_INTERNATNL_NR  4
#define ISUP_CALLED_PARTY_NATURE_NETW_SPEC_NR   5
static const value_string isup_called_party_nature_of_address_ind_value[] = {
  { ISUP_CALLED_PARTY_NATURE_SUBSCRIBER_NR,     "subscriber number (national use)"},
  { ISUP_CALLED_PARTY_NATURE_UNKNOWN,           "unknown (national use)"},  
  { ISUP_CALLED_PARTY_NATURE_NATIONAL_NR,       "national (significant) number"},
  { ISUP_CALLED_PARTY_NATURE_INTERNATNL_NR,     "international number"},
  { ISUP_CALLED_PARTY_NATURE_NETW_SPEC_NR,      "network-specific number (national use)"},
  { 0,                                 NULL}};

static const value_string isup_calling_party_nature_of_address_ind_value[] = {
  { ISUP_CALLED_PARTY_NATURE_SUBSCRIBER_NR,     "subscriber number (national use)"},
  { ISUP_CALLED_PARTY_NATURE_UNKNOWN,           "unknown (national use)"},  
  { ISUP_CALLED_PARTY_NATURE_NATIONAL_NR,       "national (significant) number"},
  { ISUP_CALLED_PARTY_NATURE_INTERNATNL_NR,     "international number"},
  { 0,                                 NULL}};

static const true_false_string isup_INN_ind_value = {
  "routing to internal network number not allowed",
  "routing to internal network number allowed "
};
static const true_false_string isup_NI_ind_value = {
  "incomplete",
  "complete"
};

#define ISDN_NUMBERING_PLAN                     1
#define DATA_NUMBERING_PLAN                     3
#define TELEX_NUMBERING_PLAN                    4
static const value_string isup_numbering_plan_ind_value[] = {
  { ISDN_NUMBERING_PLAN,     "ISDN (Telephony) numbering plan"},
  { DATA_NUMBERING_PLAN,     "Data numbering plan (national use)"},
  { TELEX_NUMBERING_PLAN,    "Telex numbering plan (national use)"},
  { 5,                       "Reserved for national use"},
  { 6,                       "Reserved for national use"},
  { 0,                                 NULL}};

#define ADDRESS_PRESETATION_ALLOWED      0
#define ADDRESS_PRESETATION_RESTRICTED   1
#define ADDRESS_NOT_AVAILABLE            2
static const value_string isup_address_presentation_restricted_ind_value[] = {
  { ADDRESS_PRESETATION_ALLOWED,     "presentation allowed"},
  { ADDRESS_PRESETATION_RESTRICTED,  "presentation restricted"},
  { ADDRESS_NOT_AVAILABLE,           "address not availabe (national use)"},
  { 3,                                 "spare"},
  { 0,                                 NULL}};

static const value_string isup_screening_ind_value[] = {
  { 0,     "reserved"},
  { 1,     "user provided, verified and passed"},
  { 2,     "reserved"},
  { 3,     "network provided"},
  { 0,     NULL}};

static const value_string isup_screening_ind_enhanced_value[] = {
  { 0,     "user provided, not verified"},
  { 1,     "user provided, verified and passed"},
  { 2,     "user provided, verified and failed"},
  { 3,     "network provided"},
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

/*End of Called/Calling party address definitions */


static const true_false_string isup_calling_party_address_request_ind_value = {
  "calling party address requested",
  "calling party address not requested"
};
static const true_false_string isup_holding_ind_value = {
  "holding requested",
  "holding not requested"
};
static const true_false_string isup_calling_partys_category_request_ind_value = {
  "Calling Party's category requested",
  "Calling Party's category not requested",
};
static const true_false_string isup_charge_information_request_ind_value = {
  "Charge Information requested",
  "Charge Information not requested"
};
static const true_false_string isup_malicious_call_identification_request_ind_value = {
  "Malicious call identification requested",
  "Malicious call identification not requested"
};

#define CALLING_PARTY_ADDRESS_NOT_INCLUDED             0
#define CALLING_PARTY_ADDRESS_NOT_AVAILABLE            1
#define CALLING_PARTY_ADDRESS_INCLUDED                 3
static const value_string isup_calling_party_address_response_ind_value[] = {
  { CALLING_PARTY_ADDRESS_NOT_INCLUDED, "Calling party address not included"},
  { CALLING_PARTY_ADDRESS_NOT_AVAILABLE,"Calling party address not available"},
  { 4,                                  "spare"},
  { CALLING_PARTY_ADDRESS_INCLUDED,     "Calling party address included"},
  { 0,                                 NULL}};

static const true_false_string isup_hold_provided_ind_value = {
  "hold provided",
  "hold not provided"
};
static const true_false_string isup_calling_partys_category_response_ind_value = {
  "Calling Party's category included",
  "Calling Party's category not included",
};
static const true_false_string isup_charge_information_response_ind_value = {
  "Charge Information included",
  "Charge Information not included"
};
static const true_false_string isup_solicited_information_ind_value = {
  "unsolicited",
  "solicited"
};

static const true_false_string isup_continuity_ind_value = {
  "Continuity check successful",
  "Continuity ckec failed"
};

#define CHARGE_NO_IND       0
#define CHARGE_NO_CHARGE    1
#define CHARGE_CHARGE       2
static const value_string isup_charge_ind_value[] = {
  { CHARGE_NO_IND,    "No indication"},
  { CHARGE_NO_CHARGE, "No charge"},
  { CHARGE_CHARGE,    "Charge"},
  { 3,                "spare"},
  { 0,                NULL}};

#define CALLED_PARTYS_STATUS_NO_IND            0
#define CALLED_PARTYS_STATUS_SUBSCR_FREE       1
#define CALLED_PARTYS_STATUS_CONNECT_WHEN_FREE 2      
static const value_string isup_called_partys_status_ind_value[] = {
  { CALLED_PARTYS_STATUS_NO_IND,            "No indication"},
  { CALLED_PARTYS_STATUS_SUBSCR_FREE,       "Subscriber free"},
  { CALLED_PARTYS_STATUS_CONNECT_WHEN_FREE, "Connect when free (national use)"},
  { 3,                                      "spare"},
  { 0,                NULL}};

#define CALLED_PARTYS_CATEGORY_NO_IND            0
#define CALLED_PARTYS_CATEGORY_ORDINARY_SUBSCR   1
#define CALLED_PARTYS_CATEGORY_PAYPHONE          2      
static const value_string isup_called_partys_category_ind_value[] = {
  { CALLED_PARTYS_CATEGORY_NO_IND,             "No indication"},
  { CALLED_PARTYS_CATEGORY_ORDINARY_SUBSCR,    "Ordinary subscriber"},
  { CALLED_PARTYS_CATEGORY_PAYPHONE,           "Payphone"},
  { 3,                                         "spare"},
  { 0,                NULL}};

static const true_false_string isup_ISDN_terminating_access_ind_value = {
  "terminating access ISDN",
  "terminating access non-ISDN"
};

static const true_false_string isup_suspend_resume_ind_value = {
  "network initiated",
  "ISDN subscriber initiated"
};
#define MAINTENANCE            0
#define HARDWARE_FAILURE       1
#define RES_FOR_NATNL_USE      2      
static const value_string isup_cgs_message_type_value[] = {
  { MAINTENANCE,            "maintenance oriented"},
  { HARDWARE_FAILURE,       "hardware failure oriented"},
  { RES_FOR_NATNL_USE,      "reserved for national use (ISUP'84)"},
  { 3,                      "spare"},
  { 0,                NULL}};

#define USER_TO_USER_SERVICE      2      
static const value_string isup_facility_ind_value[] = {
  { USER_TO_USER_SERVICE,     "user-to-user service"},
  { 0,                NULL}};

#define MTC_BLCK_STATE_TRANSIENT  0
#define MTC_BLCK_STATE_UNEQUIPPED 3
static const value_string isup_mtc_blocking_state_DC00_value[] = {
  {  MTC_BLCK_STATE_TRANSIENT,  "transient"},
  { 1,                          "spare"},
  { 2,                          "spare"},
  {  MTC_BLCK_STATE_UNEQUIPPED, "unequipped"},
  { 0,                NULL}};

#define MTC_BLCK_NO_BLOCKING      0
#define MTC_LOCALLY_BLOCKED       1
#define MTC_REMOTELY_BLOCKED      2
#define MTC_LOCAL_REMOTE_BLOCKED  3
static const value_string isup_mtc_blocking_state_DCnot00_value[] = {
  {  MTC_BLCK_NO_BLOCKING,     "no blocking (active)"},
  {  MTC_LOCALLY_BLOCKED,      "locally blocked"},
  {  MTC_REMOTELY_BLOCKED,     "remotely blocked"},
  {  MTC_LOCAL_REMOTE_BLOCKED, "locally and remotely blocked"},
  {  0,                NULL}};

#define CALL_PROC_INCOMING_BUSY 1
#define CALL_PROC_OUTGOING_BUSY 2
#define CALL_PROC_IDLE          3
static const value_string isup_call_processing_state_value[] = {
  {  CALL_PROC_INCOMING_BUSY,     "circuit incoming busy"},
  {  CALL_PROC_OUTGOING_BUSY,     "circuit outgoing busy"},
  {  CALL_PROC_IDLE,              "idle"},
  {  0,                NULL}};

#define HW_BLCK_NO_BLOCKING          0
#define HW_LOCALLY_BLOCKED           1
#define HW_REMOTELY_BLOCKED          2
#define HW_LOCAL_REMOTE_BLOCKED      3
static const value_string isup_HW_blocking_state_value[] = {
  {  HW_BLCK_NO_BLOCKING,     "no blocking (active)"},
  {  HW_LOCALLY_BLOCKED,      "locally blocked"},
  {  HW_REMOTELY_BLOCKED,     "remotely blocked"},
  {  HW_LOCAL_REMOTE_BLOCKED, "locally and remotely blocked"},
  {  0,                NULL}};

#define EVENT_ALERTING      1
#define EVENT_PROGRESS      2
#define EVENT_INBAND_INFO   3
#define EVENT_ON_BUSY       4
#define EVENT_ON_NO_REPLY   5
#define EVENT_UNCONDITIONAL 6
static const value_string isup_event_ind_value[] = {
  /* according 3.21/Q.763 */
  {  EVENT_ALERTING,     "ALERTING"},
  {  EVENT_PROGRESS,     "PROGRESS"},
  {  EVENT_INBAND_INFO,  "in-band information or an appropriate pattern is now available"},
  {  EVENT_ON_BUSY,      "call forwarded on busy (national use)"},
  {  EVENT_ON_NO_REPLY,  "call forwarded on no reply (national use)"},
  {  EVENT_UNCONDITIONAL,"call forwarded unconditional (national use)"},
  {  0,                NULL}};

static const true_false_string isup_event_presentation_restricted_ind_value = {
  /* according 3.21/Q.763 */
  "presentation restricted",
  "no indication"
};
#define CUG_NON_CUG_CALL                      0
#define CUG_CALL_OUTGOING_ACCESS_ALLOWED      2
#define CUG_CALL_OUTGOING_ACCESS_NOT_ALLOWED  3
static const value_string isup_CUG_call_ind_value[] = {
  /* according 3.38/Q.763 */
  {  CUG_NON_CUG_CALL,                     "non-CUG call"},
  {  1,                                    "spare"},
  {  CUG_CALL_OUTGOING_ACCESS_ALLOWED,     "closed user group call, outgoing access allowed"},
  {  CUG_CALL_OUTGOING_ACCESS_NOT_ALLOWED, "closed user group call, outgoing access not allowed"},
  {  0,                NULL}};


static const true_false_string isup_simple_segmentation_ind_value = {
  /* according 3.38/Q.763 */
  "additional information will be sent in a segmentation message",
  "no additional information will be sent"
};

static const true_false_string isup_connected_line_identity_request_ind_value = {
  /* according 3.38/Q.763 */
  "requested",
  "not requested"
};

static const value_string isup_redirecting_ind_value[] = {
  /* according 3.45/Q.763 */
  {  0,        "no redirection (national use)"},
  {  1,        "call rerouted (national use)"},
  {  2,        "call rerouted, all redirection information presentation restricted (national use)"},
  {  3,        "call diverted"},
  {  4,        "call diverted, all redirection information presentation restricted"},
  {  5,        "call rerouted, redirection number presentation restricted (national use)"},
  {  6,        "call diversion, redirection number presentation restricted (national use)"},
  {  7,        "spare"},
  {  0,         NULL}};

static const value_string isup_original_redirection_reason_value[] = {
  /* according 3.45/Q.763 */
  {  0,        "unknown/not available"},
  {  1,        "user busy (national use)"},
  {  2,        "no reply (national use)"},
  {  3,        "unconditional (national use)"},
  {  0,         NULL}};

static const value_string isup_redirection_reason_value[] = {
  /* according 3.45/Q.763 */
  {  0,        "unknown/not available"},
  {  1,        "user busy (national use)"},
  {  2,        "no reply (national use)"},
  {  3,        "unconditional (national use)"},
  {  4,        "deflection during alerting"},
  {  5,        "deflection immediate response"},
  {  6,        "mobile subscriber not reachable"},
  {  0,         NULL}};

static const value_string isup_type_of_network_identification_value[] = {
  /* according 3.53/Q.763 */
  {  0,        "CCITT/ITU-T-standardized identification"},
  {  2,        "national network identification"},
  {  0,         NULL}};

static const value_string isup_network_identification_plan_value[] = {
  /* according 3.53/Q.763 */
  {  0,        "if CCITT/ITU-T id - unknown"},
  {  3,        "if CCITT/ITU-T id - public data network id code (X.121)"},
  {  6,        "if CCITT/ITU-T id - public land Mobile Network id code (E.211)"},
  {  0,         NULL}};

static const value_string isup_map_type_value[] = {
  /* according 3.69/Q.763 */
  {  1,        "1544 kbit/s digital path map format (64 kbit/s base rate"},
  {  2,        "2048 kbit/s digital path map format (64 kbit/s base rate"},
  {  0,         NULL}};

static const value_string isup_auto_congestion_level_value[] = {
  /* according 3.4/Q.763 */
  {  1,        "Congestion level 1 exceeded"},
  {  2,        "Congestion level 2 exceeded"},
  {  0,         NULL}};

static const true_false_string isup_inband_information_ind_value = {
  /* according 3.37/Q.763 */
  "in-band information or an appropirate pattern is now available",
  "no indication"
};
static const true_false_string isup_call_diversion_may_occur_ind_value = {
  /* according 3.37/Q.763 */
  "call diversion may occur",
  "no indication"
};
static const true_false_string isup_MLPP_user_ind_value = {
  /* according 3.37/Q.763 */
  "MLPP user",
  "no indication"
};

static const true_false_string isup_access_delivery_ind_value = {
  /* according 3.2/Q.763 */
  "No set-up message generated",
  "Set-up message generated"
};

static const value_string isup_loop_prevention_response_ind_value[] = {
  /* according 3.67/Q.763 */
  {  0,        "insufficient information"},
  {  1,        "no loop exists"},
  {  2,        "simultaneous transfer"},
  {  0,         NULL}};

static const true_false_string isup_temporary_alternative_routing_ind_value = {
  /* according 3.68/Q.763 */
  "TAR controlled call",
  "no indication"
};
static const true_false_string isup_extension_ind_value = {
  /* according 3.68/Q.763 */
  "last octet",
  "information continues through the next octet"
};

static const value_string isup_call_to_be_diverted_ind_value[] = {
  /* according 3.72/Q.763 */
  {  0,        "no indication"},
  {  1,        "call diversion allowed"},
  {  2,        "call diversion not allowed"},
  {  3,        "spare"},
  {  0,         NULL}};

static const value_string isup_call_to_be_offered_ind_value[] = {
  /* according 3.72/Q.763 */
  {  0,        "no indication"},
  {  1,        "call offering not allowed"},
  {  2,        "call offering allowed"},
  {  3,        "spare"},
  {  0,         NULL}};

static const value_string isup_conference_acceptance_ind_value[] = {
  /* according 3.76/Q.763 */
  {  0,        "no indication"},
  {  1,        "accept conference request"},
  {  2,        "reject conference request"},
  {  3,        "spare"},
  {  0,         NULL}};


/* Generalized bit masks for 8 and 16 bits fields */
#define A_8BIT_MASK  0x01
#define B_8BIT_MASK  0x02
#define C_8BIT_MASK  0x04
#define D_8BIT_MASK  0x08
#define E_8BIT_MASK  0x10
#define F_8BIT_MASK  0x20
#define G_8BIT_MASK  0x40
#define H_8BIT_MASK  0x80

#define BA_8BIT_MASK 0x03
#define CB_8BIT_MASK 0x06
#define DC_8BIT_MASK 0x0C
#define FE_8BIT_MASK 0x30
#define GFE_8BIT_MASK 0x70
#define DCBA_8BIT_MASK 0x0F
#define EDCBA_8BIT_MASK 0x1F
#define HGFE_8BIT_MASK 0xF0
#define GFEDCBA_8BIT_MASK 0x7F
#define FEDCBA_8BIT_MASK 0x3F

#define A_16BIT_MASK  0x0100
#define B_16BIT_MASK  0x0200
#define C_16BIT_MASK  0x0400
#define D_16BIT_MASK  0x0800
#define E_16BIT_MASK  0x1000
#define F_16BIT_MASK  0x2000
#define G_16BIT_MASK  0x4000
#define H_16BIT_MASK  0x8000
#define I_16BIT_MASK  0x0001
#define J_16BIT_MASK  0x0002
#define K_16BIT_MASK  0x0004
#define L_16BIT_MASK  0x0008
#define M_16BIT_MASK  0x0010
#define N_16BIT_MASK  0x0020
#define O_16BIT_MASK  0x0040
#define P_16BIT_MASK  0x0080

#define BA_16BIT_MASK 0x0300 
#define CB_16BIT_MASK 0x0600
#define DC_16BIT_MASK 0x0C00
#define FE_16BIT_MASK 0x3000
#define HG_16BIT_MASK 0xC000
#define KJ_16BIT_MASK 0x0006
#define PO_16BIT_MASK 0x00C0

#define CBA_16BIT_MASK 0x0700
#define KJI_16BIT_MASK 0x0007
#define HGFE_16BIT_MASK 0xF000
#define PONM_16BIT_MASK 0x00F0

/* Initialize the protocol and registered fields */
static int proto_isup = -1;
static int hf_isup_cic = -1;
static int hf_isup_message_type = -1;
static int hf_isup_parameter_type = -1;
static int hf_isup_parameter_length = -1;
static int hf_isup_mandatory_variable_parameter_pointer = -1;
static int hf_isup_pointer_to_start_of_optional_part = -1;

static int hf_isup_satellite_indicator = -1;
static int hf_isup_continuity_check_indicator = -1;
static int hf_isup_echo_control_device_indicator = -1;

static int hf_isup_forw_call_natnl_inatnl_call_indicator = -1;
static int hf_isup_forw_call_end_to_end_method_indicator = -1;
static int hf_isup_forw_call_interworking_indicator = -1;
static int hf_isup_forw_call_end_to_end_info_indicator = -1;
static int hf_isup_forw_call_isdn_user_part_indicator = -1;
static int hf_isup_forw_call_preferences_indicator = -1;
static int hf_isup_forw_call_isdn_access_indicator = -1;
static int hf_isup_forw_call_sccp_method_indicator = -1;

static int hf_isup_calling_partys_category = -1;

static int hf_isup_transmission_medium_requirement = -1;

static int hf_isup_odd_even_indicator = -1;
static int hf_isup_called_party_nature_of_address_indicator = -1;
static int hf_isup_calling_party_nature_of_address_indicator = -1;
static int hf_isup_inn_indicator = -1;
static int hf_isup_ni_indicator = -1;
static int hf_isup_numbering_plan_indicator = -1;
static int hf_isup_address_presentation_restricted_indicator = -1;
static int hf_isup_screening_indicator = -1;
static int hf_isup_screening_indicator_enhanced = -1;
static int hf_isup_called_party_odd_address_signal_digit = -1;
static int hf_isup_calling_party_odd_address_signal_digit = -1;
static int hf_isup_called_party_even_address_signal_digit = -1;
static int hf_isup_calling_party_even_address_signal_digit = -1;

static int hf_isup_calling_party_address_request_indicator = -1;
static int hf_isup_info_req_holding_indicator = -1;
static int hf_isup_calling_partys_category_request_indicator = -1;
static int hf_isup_charge_information_request_indicator = -1;
static int hf_isup_malicious_call_identification_request_indicator = -1;

static int hf_isup_calling_party_address_response_indicator = -1;
static int hf_isup_hold_provided_indicator = -1;
static int hf_isup_calling_partys_category_response_indicator = -1;
static int hf_isup_charge_information_response_indicator = -1;
static int hf_isup_solicited_indicator = -1;

static int hf_isup_continuity_indicator = -1;

static int hf_isup_backw_call_charge_ind = -1 ; 
static int hf_isup_backw_call_called_partys_status_ind = -1;
static int hf_isup_backw_call_called_partys_category_ind = -1;
static int hf_isup_backw_call_end_to_end_method_ind = -1;
static int hf_isup_backw_call_interworking_ind = -1;
static int hf_isup_backw_call_end_to_end_info_ind = -1;
static int hf_isup_backw_call_isdn_user_part_ind = -1;
static int hf_isup_backw_call_holding_ind = -1;
static int hf_isup_backw_call_isdn_access_ind = -1;
static int hf_isup_backw_call_echo_control_device_ind = -1;
static int hf_isup_backw_call_sccp_method_ind = -1;
 
static int hf_isup_suspend_resume_indicator = -1;

static int hf_isup_range_indicator = -1;
static int hf_isup_cgs_message_type = -1;

static int hf_isup_mtc_blocking_state1 = -1;
static int hf_isup_mtc_blocking_state2 = -1;
static int hf_isup_call_proc_state = -1;
static int hf_isup_hw_blocking_state = -1;

static int hf_isup_event_ind = -1;
static int hf_isup_event_presentation_restricted_ind = -1;

static int hf_isup_cug_call_ind = -1;
static int hf_isup_simple_segmentation_ind = -1;
static int hf_isup_connected_line_identity_request_ind = -1;

static int hf_isup_redirecting_ind = -1;
static int hf_isup_original_redirection_reason = -1;
static int hf_isup_redirection_counter = -1;
static int hf_isup_redirection_reason = -1;

static int hf_isup_type_of_network_identification = -1;
static int hf_isup_network_identification_plan = -1;

static int hf_isup_map_type = -1;

static int hf_isup_automatic_congestion_level = -1;

static int hf_isup_inband_information_ind = -1;
static int hf_isup_call_diversion_may_occur_ind = -1;
static int hf_isup_mlpp_user_ind = -1;

static int hf_isup_access_delivery_ind =- -1;

static int hf_isup_transmission_medium_requirement_prime = -1;

static int hf_isup_loop_prevention_response_ind = -1;

static int hf_isup_temporary_alternative_routing_ind = -1;
static int hf_isup_extension_ind = -1;

static int hf_isup_call_to_be_diverted_ind = -1;

static int hf_isup_call_to_be_offered_ind = -1;

static int hf_isup_conference_acceptance_ind = -1;

/* Initialize the subtree pointers */
static gint ett_isup = -1;
static gint ett_isup_parameter = -1;
static gint ett_isup_address_digits = -1;
static gint ett_isup_pass_along_message = -1;
static gint ett_isup_circuit_state_ind = -1;


/* ------------------------------------------------------------------ 
  Mapping number to ASCII-character   
 ------------------------------------------------------------------ */
char number_to_char(int number)
{
  if (number < 10)
    return ((char) number + ASCII_NUMBER_DELTA);
  else
    return ((char) number + ASCII_LETTER_DELTA);
}


/* ------------------------------------------------------------------ */
/* Dissectors for all used parameter types                            */ 
/* ------------------------------------------------------------------ */
/* argument tvbuff_t contains only parameter-specific length          */
/* length indicator is already dissected in dissect_isup_message() or */
/* dissect_isup_optional_parameter()                                  */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ 
 Dissector Parameter nature of connection flags 
 */
void 
dissect_isup_nature_of_connection_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 nature_of_connection_ind;

  nature_of_connection_ind = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_isup_satellite_indicator, parameter_tvb, 0,NATURE_OF_CONNECTION_IND_LENGTH, nature_of_connection_ind);
  proto_tree_add_uint(parameter_tree, hf_isup_continuity_check_indicator, parameter_tvb, 0,NATURE_OF_CONNECTION_IND_LENGTH, nature_of_connection_ind);
  proto_tree_add_boolean(parameter_tree, hf_isup_echo_control_device_indicator, parameter_tvb, 0,  NATURE_OF_CONNECTION_IND_LENGTH, nature_of_connection_ind);

  proto_item_set_text(parameter_item, "Nature of Connection Indicators: 0x%x", nature_of_connection_ind);
}

/* ------------------------------------------------------------------ 
 Dissector Parameter Forward Call Indicators
 */
void 
dissect_isup_forward_call_indicators_parameter(tvbuff_t *parameter_tvb,proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 forward_call_ind;

  forward_call_ind = tvb_get_ntohs(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_isup_forw_call_natnl_inatnl_call_indicator, parameter_tvb, 0, FORWARD_CALL_IND_LENGTH, forward_call_ind);
  proto_tree_add_uint(parameter_tree, hf_isup_forw_call_end_to_end_method_indicator, parameter_tvb, 0, FORWARD_CALL_IND_LENGTH, forward_call_ind);
  proto_tree_add_boolean(parameter_tree, hf_isup_forw_call_interworking_indicator, parameter_tvb, 0, FORWARD_CALL_IND_LENGTH, forward_call_ind);
  proto_tree_add_boolean(parameter_tree, hf_isup_forw_call_end_to_end_info_indicator, parameter_tvb, 0, FORWARD_CALL_IND_LENGTH, forward_call_ind);
  proto_tree_add_boolean(parameter_tree, hf_isup_forw_call_isdn_user_part_indicator, parameter_tvb, 0, FORWARD_CALL_IND_LENGTH, forward_call_ind);
  proto_tree_add_uint(parameter_tree, hf_isup_forw_call_preferences_indicator, parameter_tvb, 0, FORWARD_CALL_IND_LENGTH, forward_call_ind);
  proto_tree_add_boolean(parameter_tree, hf_isup_forw_call_isdn_access_indicator, parameter_tvb, 0, FORWARD_CALL_IND_LENGTH, forward_call_ind);
  proto_tree_add_uint(parameter_tree, hf_isup_forw_call_sccp_method_indicator, parameter_tvb, 0, FORWARD_CALL_IND_LENGTH, forward_call_ind);
 
  proto_item_set_text(parameter_item, "Forward Call Indicators: 0x%x", forward_call_ind );  
}

/* ------------------------------------------------------------------ 
 Dissector Parameter Calling Party's Category 
 */
void 
dissect_isup_calling_partys_category_parameter(tvbuff_t *parameter_tvb,proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 calling_partys_category;
  
  calling_partys_category = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_isup_calling_partys_category, parameter_tvb, 0, CALLING_PRTYS_CATEGORY_LENGTH, calling_partys_category);

  proto_item_set_text(parameter_item, "Calling Party's category: 0x%x (%s)", calling_partys_category, val_to_str(calling_partys_category, isup_calling_partys_category_value, "reserved/spare"));
}


/* ------------------------------------------------------------------
  Dissector Parameter Transmission medium requirement 
 */
void 
dissect_isup_transmission_medium_requirement_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ 
  guint8 transmission_medium_requirement;
  
  transmission_medium_requirement = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_isup_transmission_medium_requirement, parameter_tvb, 0, TRANSMISSION_MEDIUM_REQUIREMENT_LENGTH,transmission_medium_requirement);

  proto_item_set_text(parameter_item, "Transmission medium requirement: %u (%s)",  transmission_medium_requirement, val_to_str(transmission_medium_requirement, isup_transmission_medium_requirement_value, "spare"));
}
/* ------------------------------------------------------------------
  Dissector Parameter Called party number
 */
void dissect_isup_called_party_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_item *address_digits_item;
  proto_tree *address_digits_tree;
  guint8 indicators1, indicators2;
  guint8 address_digit_pair=0;
  gint offset=0; 
  gint i=0;
  gint length;
  char called_number[MAXLENGTH]="";

  indicators1 = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_isup_odd_even_indicator, parameter_tvb, 0, 1, indicators1);
  proto_tree_add_uint(parameter_tree, hf_isup_called_party_nature_of_address_indicator, parameter_tvb, 0, 1, indicators1);
  indicators2 = tvb_get_guint8(parameter_tvb, 1);
  proto_tree_add_boolean(parameter_tree, hf_isup_inn_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_numbering_plan_indicator, parameter_tvb, 1, 1, indicators2);
  offset = 2;

  address_digits_item = proto_tree_add_text(parameter_tree, parameter_tvb,
					    offset,
					    tvb_length_remaining(parameter_tvb, offset),
					    "Called Party Number");
  address_digits_tree = proto_item_add_subtree(address_digits_item, ett_isup_address_digits);

  length = tvb_length_remaining(parameter_tvb, offset);
  while(length > 0){
    address_digit_pair = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(address_digits_tree, hf_isup_called_party_odd_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
    called_number[i++] = number_to_char(address_digit_pair & ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK);
    if ((length - 1) > 0 ){ 
      proto_tree_add_uint(address_digits_tree, hf_isup_called_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      called_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
    } 
    offset++;
    length = tvb_length_remaining(parameter_tvb, offset);   
  }

  if  (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_isup_called_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      called_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
  }
  called_number[i++] = '\0';

  proto_item_set_text(address_digits_item, "Called Party Number: %s", called_number);  
  proto_item_set_text(parameter_item, "Called Party Number: %s", called_number);
  
}
/* ------------------------------------------------------------------
  Dissector Parameter  Subsequent number
 */
void dissect_isup_subsequent_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_item *address_digits_item;
  proto_tree *address_digits_tree;
  guint8 indicators1;
  guint8 address_digit_pair=0;
  gint offset=0; 
  gint i=0;
  gint length;
  char called_number[MAXLENGTH]="";

  indicators1 = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_isup_odd_even_indicator, parameter_tvb, 0, 1, indicators1);
  offset = 1;

  address_digits_item = proto_tree_add_text(parameter_tree, parameter_tvb,
					    offset,
					    tvb_length_remaining(parameter_tvb, offset),
					    "Subsequent Number");
  address_digits_tree = proto_item_add_subtree(address_digits_item, ett_isup_address_digits);

  length = tvb_length_remaining(parameter_tvb, offset);
  while(length > 0){
    address_digit_pair = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(address_digits_tree, hf_isup_called_party_odd_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
    called_number[i++] = number_to_char(address_digit_pair & ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK);
    if ((length - 1) > 0 ){ 
      proto_tree_add_uint(address_digits_tree, hf_isup_called_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      called_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
    } 
    offset++;
    length = tvb_length_remaining(parameter_tvb, offset);   
  }

  if (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_isup_called_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      called_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
  }
  called_number[i++] = '\0';

  proto_item_set_text(address_digits_item, "Subsequent Number: %s", called_number);  
  proto_item_set_text(parameter_item, "Subsequent Number: %s", called_number);
  
}
/* ------------------------------------------------------------------
  Dissector Parameter Information Request Indicators
 */
void 
dissect_isup_information_request_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ 
  guint16 information_request_indicators;
  
  information_request_indicators = tvb_get_ntohs(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_isup_calling_party_address_request_indicator, parameter_tvb, 0, INFO_REQUEST_IND_LENGTH,  information_request_indicators);
  proto_tree_add_boolean(parameter_tree, hf_isup_info_req_holding_indicator, parameter_tvb, 0, INFO_REQUEST_IND_LENGTH,  information_request_indicators);
  proto_tree_add_boolean(parameter_tree, hf_isup_calling_partys_category_request_indicator, parameter_tvb, 0, INFO_REQUEST_IND_LENGTH,  information_request_indicators);
  proto_tree_add_boolean(parameter_tree, hf_isup_charge_information_request_indicator, parameter_tvb, 0, INFO_REQUEST_IND_LENGTH,  information_request_indicators);
  proto_tree_add_boolean(parameter_tree, hf_isup_malicious_call_identification_request_indicator, parameter_tvb, 0, INFO_REQUEST_IND_LENGTH,  information_request_indicators);
  

  proto_item_set_text(parameter_item, "Information request indicators: 0x%x", information_request_indicators);
}
/* ------------------------------------------------------------------
  Dissector Parameter Information Indicators
 */
void 
dissect_isup_information_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ 
  guint16 information_indicators;
  
  information_indicators = tvb_get_ntohs(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_isup_calling_party_address_response_indicator, parameter_tvb, 0, INFO_IND_LENGTH,  information_indicators);
  proto_tree_add_boolean(parameter_tree, hf_isup_hold_provided_indicator, parameter_tvb, 0, INFO_IND_LENGTH,  information_indicators);
  proto_tree_add_boolean(parameter_tree, hf_isup_calling_partys_category_response_indicator, parameter_tvb, 0, INFO_IND_LENGTH,  information_indicators);
  proto_tree_add_boolean(parameter_tree, hf_isup_charge_information_response_indicator, parameter_tvb, 0, INFO_IND_LENGTH,  information_indicators);
  proto_tree_add_boolean(parameter_tree, hf_isup_solicited_indicator, parameter_tvb, 0, INFO_IND_LENGTH,  information_indicators);
  

  proto_item_set_text(parameter_item, "Information indicators: 0x%x", information_indicators);
}
/* ------------------------------------------------------------------
  Dissector Parameter Continuity Indicators 
 */
void 
dissect_isup_continuity_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ 
  guint8 continuity_indicators;
  
  continuity_indicators = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_isup_continuity_indicator, parameter_tvb, 0, CONTINUITY_IND_LENGTH,  continuity_indicators);

  proto_item_set_text(parameter_item, "Continuity indicators: 0x%x", continuity_indicators);
}
/* ------------------------------------------------------------------ 
 Dissector Parameter Backward Call Indicators 
 */
void 
dissect_isup_backward_call_indicators_parameter(tvbuff_t *parameter_tvb,proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 backward_call_ind;

  backward_call_ind = tvb_get_ntohs(parameter_tvb, 0);
  

  proto_tree_add_uint(parameter_tree, hf_isup_backw_call_charge_ind, parameter_tvb, 0, BACKWARD_CALL_IND_LENGTH, backward_call_ind);
  proto_tree_add_uint(parameter_tree, hf_isup_backw_call_called_partys_status_ind, parameter_tvb, 0, BACKWARD_CALL_IND_LENGTH, backward_call_ind);
  proto_tree_add_uint(parameter_tree, hf_isup_backw_call_called_partys_category_ind, parameter_tvb, 0, BACKWARD_CALL_IND_LENGTH, backward_call_ind);
  proto_tree_add_uint(parameter_tree, hf_isup_backw_call_end_to_end_method_ind, parameter_tvb, 0, BACKWARD_CALL_IND_LENGTH, backward_call_ind);
  proto_tree_add_boolean(parameter_tree, hf_isup_backw_call_interworking_ind, parameter_tvb, 0, BACKWARD_CALL_IND_LENGTH, backward_call_ind);
  proto_tree_add_boolean(parameter_tree, hf_isup_backw_call_end_to_end_info_ind, parameter_tvb, 0, BACKWARD_CALL_IND_LENGTH, backward_call_ind);
  proto_tree_add_boolean(parameter_tree, hf_isup_backw_call_isdn_user_part_ind, parameter_tvb, 0, BACKWARD_CALL_IND_LENGTH, backward_call_ind);
  proto_tree_add_boolean(parameter_tree, hf_isup_backw_call_holding_ind, parameter_tvb, 0, BACKWARD_CALL_IND_LENGTH,  backward_call_ind);
  proto_tree_add_boolean(parameter_tree, hf_isup_backw_call_isdn_access_ind, parameter_tvb, 0, BACKWARD_CALL_IND_LENGTH, backward_call_ind);
  proto_tree_add_boolean(parameter_tree, hf_isup_backw_call_echo_control_device_ind, parameter_tvb, 0, BACKWARD_CALL_IND_LENGTH, backward_call_ind);
  proto_tree_add_uint(parameter_tree, hf_isup_backw_call_sccp_method_ind, parameter_tvb, 0, BACKWARD_CALL_IND_LENGTH, backward_call_ind);
 
  proto_item_set_text(parameter_item, "Backward Call Indicators: 0x%x", backward_call_ind);  
}
/* ------------------------------------------------------------------
  Dissector Parameter Cause Indicators - no detailed dissection since defined in Rec. Q.850
 */
void 
dissect_isup_cause_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_item, parameter_tvb,0, length, "Cause indicators (-> Q.850)"); 
  proto_item_set_text(parameter_item, "Cause indicators, see Q.850 (%u byte%s length)", length , plurality(length, "", "s"));
}

/* ------------------------------------------------------------------
  Dissector Parameter Suspend/Resume Indicators 
 */
void 
dissect_isup_suspend_resume_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ 
  guint8 indicators;
  
  indicators = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_isup_suspend_resume_indicator, parameter_tvb, 0, SUSPEND_RESUME_IND_LENGTH,  indicators);

  proto_item_set_text(parameter_item, "Suspend/Resume indicator: 0x%x", indicators);
}
/* ------------------------------------------------------------------
  Dissector Parameter Range and Status Indicators 
 */
void 
dissect_isup_range_and_status_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ 
  guint8 range, actual_status_length;

  range = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint_format(parameter_tree, hf_isup_range_indicator, parameter_tvb, 0, RANGE_LENGTH, range, "Range: %u", range);
  actual_status_length = tvb_length_remaining(parameter_tvb, RANGE_LENGTH);
  if (actual_status_length > 0)
    proto_tree_add_text(parameter_tree, parameter_tvb , RANGE_LENGTH, actual_status_length, "Status subfield");
  else
    proto_tree_add_text(parameter_tree, parameter_tvb , 0, 0, "Status subfield is not present with this message type");


  proto_item_set_text(parameter_item, "Range (%u) and status", range);
}
/* ------------------------------------------------------------------
  Dissector Parameter Circuit group supervision message type
 */
void 
dissect_isup_circuit_group_supervision_message_type_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ 
  guint8 cgs_message_type;
  
  cgs_message_type = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_isup_cgs_message_type, parameter_tvb, 0, CIRC_GRP_SV_MSG_TYPE_LENGTH, cgs_message_type);

  proto_item_set_text(parameter_item, "Circuit group supervision message type: %s (%u)"  ,val_to_str(cgs_message_type, isup_cgs_message_type_value,"unknown"), cgs_message_type);
}
/* ------------------------------------------------------------------
  Dissector Parameter Facility indicator parameter 
 */
void 
dissect_isup_facility_ind_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ 
  guint8 indicator;
  
  indicator = tvb_get_guint8(parameter_tvb, 0);

  proto_item_set_text(parameter_item, "Facility indicator: %s (%u)"  ,val_to_str(indicator, isup_facility_ind_value,"spare"), indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter Circuit state indicator 
 */
void 
dissect_isup_circuit_state_ind_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_item *circuit_state_item;
  proto_tree *circuit_state_tree;
  guint8 circuit_state;
  gint offset=0; 
  gint i=0;
  gint length;

  length = tvb_length_remaining(parameter_tvb, offset);
  while(length > 0){
    circuit_state_item = proto_tree_add_text(parameter_tree, parameter_tvb,
					     offset,
					     tvb_length_remaining(parameter_tvb, offset),
					     "Circuit# CIC+%u state", i);
    circuit_state_tree = proto_item_add_subtree(circuit_state_item, ett_isup_circuit_state_ind);
    circuit_state = tvb_get_guint8(parameter_tvb, offset);
    if ((circuit_state & DC_8BIT_MASK) == 0){ 
      proto_tree_add_uint(circuit_state_tree, hf_isup_mtc_blocking_state1, parameter_tvb, offset, 1, circuit_state);
      proto_item_set_text(circuit_state_item, "Circuit# CIC+%u state: %s", i++, val_to_str(circuit_state&BA_8BIT_MASK, isup_mtc_blocking_state_DC00_value, "unknown"));  
    } 
    else { 
      proto_tree_add_uint(circuit_state_tree, hf_isup_mtc_blocking_state2, parameter_tvb, offset, 1, circuit_state);
      proto_tree_add_uint(circuit_state_tree, hf_isup_call_proc_state, parameter_tvb, offset, 1, circuit_state);
      proto_tree_add_uint(circuit_state_tree, hf_isup_hw_blocking_state, parameter_tvb, offset, 1, circuit_state);
      proto_item_set_text(circuit_state_item, "Circuit# CIC+%u state: %s", i++, val_to_str(circuit_state&BA_8BIT_MASK, isup_mtc_blocking_state_DCnot00_value, "unknown"));     
    } 
    offset++;
    length = tvb_length_remaining(parameter_tvb, offset);
  }
  proto_item_set_text(parameter_item, "Circuit state indicator (national use)");
}
/* ------------------------------------------------------------------
  Dissector Parameter Event information 
 */
void 
dissect_isup_event_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ 
  guint8 indicators;
  
  indicators = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint_format(parameter_tree, hf_isup_event_ind, parameter_tvb, 0, EVENT_INFO_LENGTH, indicators, "Event indicator: %s (%u)", val_to_str(indicators & GFEDCBA_8BIT_MASK, isup_event_ind_value, "spare"), indicators & GFEDCBA_8BIT_MASK);
  proto_tree_add_boolean(parameter_tree, hf_isup_event_presentation_restricted_ind, parameter_tvb, 0, EVENT_INFO_LENGTH, indicators);

  proto_item_set_text(parameter_item,"Event information: %s (%u)", val_to_str(indicators & GFEDCBA_8BIT_MASK, isup_event_ind_value, "spare"),indicators );
}
/* ------------------------------------------------------------------
  Dissector Parameter User-to-user information- no detailed dissection since defined in Rec. Q.931
 */
void 
dissect_isup_user_to_user_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_item, parameter_tvb, 0, length, "User-to-user info (-> Q.931)"); 
  proto_item_set_text(parameter_item, "User-to-user information, see Q.931 (%u byte%s length)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
  Dissector Parameter Call Reference 
 */
void 
dissect_isup_call_reference_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ 
  guint32 call_id;
  guint16 spc;
  
  call_id = tvb_get_ntoh24(parameter_tvb, 0);
  spc = tvb_get_letohs(parameter_tvb, CALL_ID_LENGTH) & 0x3FFF; /*since 1st 2 bits spare */
  proto_tree_add_text(parameter_item, parameter_tvb, 0, CALL_ID_LENGTH, "Call identity: %u", call_id); 
  proto_tree_add_text(parameter_item, parameter_tvb, CALL_ID_LENGTH, SPC_LENGTH, "Signalling Point Code: %u", spc); 

  proto_item_set_text(parameter_item, "Call Reference: Call ID = %u, SPC = %u", call_id, spc);
}
/* ------------------------------------------------------------------
  Dissector Parameter Access Transport - no detailed dissection since defined in Rec. Q.931
 */
void 
dissect_isup_access_transport_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_item, parameter_tvb, 0, length, "Access transport parameter field (-> Q.931)"); 
  proto_item_set_text(parameter_item, "Access transport, see Q.931 (%u byte%s length)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
  Dissector Parameter Optional Forward Call indicators
 */
void 
dissect_isup_optional_forward_call_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ 
  guint8 indicators;
  
  indicators = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_isup_cug_call_ind, parameter_tvb, 0, OPTIONAL_FORWARD_CALL_IND_LENGTH, indicators);
  proto_tree_add_boolean(parameter_tree, hf_isup_simple_segmentation_ind, parameter_tvb, 0, OPTIONAL_FORWARD_CALL_IND_LENGTH, indicators);
  proto_tree_add_boolean(parameter_tree, hf_isup_connected_line_identity_request_ind, parameter_tvb, 0, OPTIONAL_FORWARD_CALL_IND_LENGTH, indicators);


  proto_item_set_text(parameter_item,"Optional forward call indicators: %s (%u)", val_to_str(indicators & BA_8BIT_MASK, isup_CUG_call_ind_value, "spare"),indicators );
}
/* ------------------------------------------------------------------
  Dissector Parameter calling party number
 */
void 
dissect_isup_calling_party_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
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
  proto_tree_add_boolean(parameter_tree, hf_isup_odd_even_indicator, parameter_tvb, 0, 1, indicators1);
  proto_tree_add_uint(parameter_tree, hf_isup_calling_party_nature_of_address_indicator, parameter_tvb, 0, 1, indicators1);
  indicators2 = tvb_get_guint8(parameter_tvb, 1);
  proto_tree_add_boolean(parameter_tree, hf_isup_ni_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_numbering_plan_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_address_presentation_restricted_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_screening_indicator, parameter_tvb, 1, 1, indicators2);
  offset = 2;

  address_digits_item = proto_tree_add_text(parameter_tree, parameter_tvb,
					    offset,
					    tvb_length_remaining(parameter_tvb, offset),
					    "Calling Party Number");
  address_digits_tree = proto_item_add_subtree(address_digits_item, ett_isup_address_digits);

  length = tvb_length_remaining(parameter_tvb, offset);
  while(length > 0){
    address_digit_pair = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_odd_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
    calling_number[i++] = number_to_char(address_digit_pair & ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK);
    if ((length - 1) > 0 ){ 
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
    } 
    offset++;
    length = tvb_length_remaining(parameter_tvb, offset);   
  }

  if  (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
  }
  calling_number[i++] = '\0';

  proto_item_set_text(address_digits_item, "Calling Party Number: %s", calling_number);  
  proto_item_set_text(parameter_item, "Calling Party Number: %s", calling_number);
  
}
/* ------------------------------------------------------------------
  Dissector Parameter Original called  number
 */
void 
dissect_isup_original_called_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
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
  proto_tree_add_boolean(parameter_tree, hf_isup_odd_even_indicator, parameter_tvb, 0, 1, indicators1);
  proto_tree_add_uint(parameter_tree, hf_isup_calling_party_nature_of_address_indicator, parameter_tvb, 0, 1, indicators1);
  indicators2 = tvb_get_guint8(parameter_tvb, 1);
  proto_tree_add_uint(parameter_tree, hf_isup_numbering_plan_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_address_presentation_restricted_indicator, parameter_tvb, 1, 1, indicators2);
  offset = 2;

  address_digits_item = proto_tree_add_text(parameter_tree, parameter_tvb,
					    offset,
					    tvb_length_remaining(parameter_tvb, offset),
					    "Original Called Number");
  address_digits_tree = proto_item_add_subtree(address_digits_item, ett_isup_address_digits);

  length = tvb_length_remaining(parameter_tvb, offset);
  while(length > 0){
    address_digit_pair = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_odd_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
    calling_number[i++] = number_to_char(address_digit_pair & ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK);
    if ((length - 1) > 0 ){ 
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
    } 
    offset++;
    length = tvb_length_remaining(parameter_tvb, offset);   
  }

  if  (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
  }
  calling_number[i++] = '\0';

  proto_item_set_text(address_digits_item, "Original Called Number: %s", calling_number);  
  proto_item_set_text(parameter_item, "Original Called Number: %s", calling_number);
  
}
/* ------------------------------------------------------------------
  Dissector Parameter Redirecting number
 */
void 
dissect_isup_redirecting_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
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
  proto_tree_add_boolean(parameter_tree, hf_isup_odd_even_indicator, parameter_tvb, 0, 1, indicators1);
  proto_tree_add_uint(parameter_tree, hf_isup_calling_party_nature_of_address_indicator, parameter_tvb, 0, 1, indicators1);
  indicators2 = tvb_get_guint8(parameter_tvb, 1);
  proto_tree_add_uint(parameter_tree, hf_isup_numbering_plan_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_address_presentation_restricted_indicator, parameter_tvb, 1, 1, indicators2);
  offset = 2;

  address_digits_item = proto_tree_add_text(parameter_tree, parameter_tvb,
					    offset,
					    tvb_length_remaining(parameter_tvb, offset),
					    "Redirecting Number");
  address_digits_tree = proto_item_add_subtree(address_digits_item, ett_isup_address_digits);

  length = tvb_length_remaining(parameter_tvb, offset);
  while(length > 0){
    address_digit_pair = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_odd_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
    calling_number[i++] = number_to_char(address_digit_pair & ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK);
    if ((length - 1) > 0 ){ 
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
    } 
    offset++;
    length = tvb_length_remaining(parameter_tvb, offset);   
  }

  if  (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
  }
  calling_number[i++] = '\0';

  proto_item_set_text(address_digits_item, "Redirecting Number: %s", calling_number);  
  proto_item_set_text(parameter_item, "Redirecting Number: %s", calling_number);
  
}
/* ------------------------------------------------------------------
  Dissector Parameter Redirection number 
 */
void dissect_isup_redirection_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_item *address_digits_item;
  proto_tree *address_digits_tree;
  guint8 indicators1, indicators2;
  guint8 address_digit_pair=0;
  gint offset=0; 
  gint i=0;
  gint length;
  char called_number[MAXLENGTH]="";

  indicators1 = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_isup_odd_even_indicator, parameter_tvb, 0, 1, indicators1);
  proto_tree_add_uint(parameter_tree, hf_isup_called_party_nature_of_address_indicator, parameter_tvb, 0, 1, indicators1);
  indicators2 = tvb_get_guint8(parameter_tvb, 1);
  proto_tree_add_boolean(parameter_tree, hf_isup_inn_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_numbering_plan_indicator, parameter_tvb, 1, 1, indicators2);
  offset = 2;

  address_digits_item = proto_tree_add_text(parameter_tree, parameter_tvb,
					    offset,
					    tvb_length_remaining(parameter_tvb, offset),
					    "Redirection Number");
  address_digits_tree = proto_item_add_subtree(address_digits_item, ett_isup_address_digits);

  length = tvb_length_remaining(parameter_tvb, offset);
  while(length > 0){
    address_digit_pair = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(address_digits_tree, hf_isup_called_party_odd_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
    called_number[i++] = number_to_char(address_digit_pair & ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK);
    if ((length - 1) > 0 ){ 
      proto_tree_add_uint(address_digits_tree, hf_isup_called_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      called_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
    } 
    offset++;
    length = tvb_length_remaining(parameter_tvb, offset);   
  }

  if  (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_isup_called_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      called_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
  }
  called_number[i++] = '\0';

  proto_item_set_text(address_digits_item, "Redirection Number: %s", called_number);  
  proto_item_set_text(parameter_item, "Redirection Number: %s", called_number); 
}
/* ------------------------------------------------------------------
  Dissector Parameter Connection request 
 */
void 
dissect_isup_connection_request_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ 
  guint32 local_ref;
  guint16 spc;
  guint8 protocol_class, credit, offset=0; 
  
  local_ref = tvb_get_ntoh24(parameter_tvb, 0);
  proto_tree_add_text(parameter_item, parameter_tvb, offset, LOCAL_REF_LENGTH, "Local Reference: %u", local_ref); 
  offset = LOCAL_REF_LENGTH;
  spc = tvb_get_letohs(parameter_tvb,offset) & 0x3FFF; /*since 1st 2 bits spare */
  proto_tree_add_text(parameter_item, parameter_tvb, offset, SPC_LENGTH, "Signalling Point Code: %u", spc); 
  offset += SPC_LENGTH;
  protocol_class = tvb_get_guint8(parameter_tvb, offset);
  proto_tree_add_text(parameter_item, parameter_tvb, offset, PROTOCOL_CLASS_LENGTH, "Protocol Class: %u", protocol_class); 
  offset += PROTOCOL_CLASS_LENGTH;
  credit = tvb_get_guint8(parameter_tvb, offset);
  proto_tree_add_text(parameter_item, parameter_tvb, offset, CREDIT_LENGTH, "Credit: %u", credit); 
  offset += CREDIT_LENGTH;

  proto_item_set_text(parameter_item, "Connection request: Local Reference = %u, SPC = %u, Protocol Class = %u, Credit = %u", local_ref, spc, protocol_class, credit);
}
/* ------------------------------------------------------------------
  Dissector Parameter Redirection information
 */
void 
dissect_isup_redirection_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ 
  if (tvb_length(parameter_tvb) == 2){ 
    guint16 indicators;
    indicators = tvb_get_ntohs(parameter_tvb, 0);
    proto_tree_add_uint(parameter_tree, hf_isup_redirecting_ind, parameter_tvb,0 , REDIRECTION_INFO_LENGTH, indicators);
    proto_tree_add_uint(parameter_tree, hf_isup_original_redirection_reason, parameter_tvb,0 , REDIRECTION_INFO_LENGTH, indicators);
    proto_tree_add_uint(parameter_tree, hf_isup_redirection_counter, parameter_tvb,0 , REDIRECTION_INFO_LENGTH, indicators);
    proto_tree_add_uint(parameter_tree, hf_isup_redirection_reason, parameter_tvb,0 , REDIRECTION_INFO_LENGTH, indicators);
    proto_item_set_text(parameter_item, "Redirection Information");
  }
  else { /* ISUP'88 (blue book) */
    guint16 indicators;
    indicators = tvb_get_guint8(parameter_tvb, 0) * 0x100; /*since 2nd octet isn't present*/ 
    proto_tree_add_uint(parameter_tree, hf_isup_redirecting_ind, parameter_tvb, 0, 1, indicators);
    proto_tree_add_uint(parameter_tree, hf_isup_original_redirection_reason, parameter_tvb,0 , 1, indicators);
    proto_item_set_text(parameter_item, "Redirection Information (2nd octet not present since ISUP '88)");
  }
}
/* ------------------------------------------------------------------
  Dissector Parameter Closed user group interlock code
 */
void dissect_isup_closed_user_group_interlock_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  char NI_digits[5]="";
  guint8 digit_pair;
  guint16 bin_code;

  digit_pair = tvb_get_guint8(parameter_tvb, 0);
  NI_digits[0] = number_to_char((digit_pair & HGFE_8BIT_MASK) / 0x10);
  NI_digits[1] = number_to_char(digit_pair & DCBA_8BIT_MASK);
  digit_pair = tvb_get_guint8(parameter_tvb, 1);
  NI_digits[2] = number_to_char((digit_pair & HGFE_8BIT_MASK) / 0x10);
  NI_digits[3] = number_to_char(digit_pair & DCBA_8BIT_MASK);
  NI_digits[4] = '\0';
  proto_tree_add_text(parameter_item, parameter_tvb, 0, 2, "Network Identity: %s", NI_digits); 
  bin_code = tvb_get_ntohs(parameter_tvb, 2);  
  proto_tree_add_text(parameter_item, parameter_tvb, 3, 2, "Binary Code: 0x%x", bin_code); 
  proto_item_set_text(parameter_item, "Closed user group interlock code: NI = %s, Binary code = 0x%x", NI_digits, bin_code); 
}
/* ------------------------------------------------------------------
  Dissector Parameter User service information- no detailed dissection since defined in Rec. Q.931
 */
void 
dissect_isup_user_service_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_item, parameter_tvb, 0, length, "User service information (-> Q.931)"); 
  proto_item_set_text(parameter_item, "User service information, see Q.931 (%u byte%s length)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
  Dissector Parameter Signalling point code 
 */
void 
dissect_isup_signalling_point_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ 
  guint16 spc;
  
  spc = tvb_get_letohs(parameter_tvb, 0) & 0x3FFF; /*since 1st 2 bits spare */
  proto_tree_add_text(parameter_item, parameter_tvb, 0, SIGNALLING_POINT_CODE_LENGTH, "Signalling Point Code: %u", spc); 

  proto_item_set_text(parameter_item, "Signalling point code: %u", spc);
}
/* ------------------------------------------------------------------
  Dissector Parameter Connected number
 */
void 
dissect_isup_connected_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
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
  proto_tree_add_boolean(parameter_tree, hf_isup_odd_even_indicator, parameter_tvb, 0, 1, indicators1);
  proto_tree_add_uint(parameter_tree, hf_isup_calling_party_nature_of_address_indicator, parameter_tvb, 0, 1, indicators1);
  indicators2 = tvb_get_guint8(parameter_tvb, 1);
  proto_tree_add_uint(parameter_tree, hf_isup_numbering_plan_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_address_presentation_restricted_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_screening_indicator, parameter_tvb, 1, 1, indicators2);
  offset = 2;

  address_digits_item = proto_tree_add_text(parameter_tree, parameter_tvb,
					    offset,
					    tvb_length_remaining(parameter_tvb, offset),
					    "Connected Number");
  address_digits_tree = proto_item_add_subtree(address_digits_item, ett_isup_address_digits);

  length = tvb_length_remaining(parameter_tvb, offset);
  while(length > 0){
    address_digit_pair = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_odd_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
    calling_number[i++] = number_to_char(address_digit_pair & ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK);
    if ((length - 1) > 0 ){ 
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
    } 
    offset++;
    length = tvb_length_remaining(parameter_tvb, offset);   
  }

  if  (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
  }
  calling_number[i++] = '\0';

  proto_item_set_text(address_digits_item, "Connected Number: %s", calling_number);  
  proto_item_set_text(parameter_item, "Connected Number: %s", calling_number);
  
}
/* ------------------------------------------------------------------
  Dissector Transit network selection
 */
void 
dissect_isup_transit_network_selection_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_item *address_digits_item;
  proto_tree *address_digits_tree;
  guint8 indicators;
  guint8 address_digit_pair=0;
  gint offset=0; 
  gint i=0;
  gint length;
  char network_id[MAXLENGTH]="";

  indicators = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_isup_odd_even_indicator, parameter_tvb, 0, 1, indicators);
  proto_tree_add_uint(parameter_tree, hf_isup_type_of_network_identification, parameter_tvb, 0, 1, indicators);
  proto_tree_add_uint(parameter_tree, hf_isup_network_identification_plan, parameter_tvb, 0, 1, indicators);
  offset = 1;

  address_digits_item = proto_tree_add_text(parameter_tree, parameter_tvb,
					    offset,
					    tvb_length_remaining(parameter_tvb, offset),
					    "Network identification");
  address_digits_tree = proto_item_add_subtree(address_digits_item, ett_isup_address_digits);

  length = tvb_length_remaining(parameter_tvb, offset);
  while(length > 0){
    address_digit_pair = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_odd_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
    network_id[i++] = number_to_char(address_digit_pair & ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK);
    if ((length - 1) > 0 ){ 
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      network_id[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
    } 
    offset++;
    length = tvb_length_remaining(parameter_tvb, offset);   
  }

  if  (((indicators & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      network_id[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
  }
  network_id[i++] = '\0';

  proto_item_set_text(address_digits_item, "Network identification: %s", network_id);  
  proto_item_set_text(parameter_item, "Transit network selection: %s", network_id);
  
}
/* ------------------------------------------------------------------
  Dissector Parameter Circuit assignment map
 */
void 
dissect_isup_circuit_assignment_map_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 map_type;

  map_type = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_isup_map_type, parameter_tvb, 0, 1, map_type); 
  proto_tree_add_text(parameter_item, parameter_tvb, 1, 5, "Circuit assignment map (bit position indicates usage of corresponding circuit->3.69/Q.763)"); 
  proto_item_set_text(parameter_item, "Circuit assignment map");
}
/* ------------------------------------------------------------------
  Dissector Parameter Automatic congestion level
 */
void 
dissect_isup_automatic_congestion_level_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 congestion_level;

  congestion_level = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_isup_automatic_congestion_level, parameter_tvb, 0, AUTO_CONGEST_LEVEL_LENGTH, congestion_level); 
  proto_item_set_text(parameter_item, "Automatic congestion level: %s (%u)", val_to_str(congestion_level, isup_auto_congestion_level_value, "spare"), congestion_level);
}
/* ------------------------------------------------------------------
  Dissector Parameter Optional backward Call indicators
 */
void 
dissect_isup_optional_backward_call_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ 
  guint8 indicators;
  
  indicators = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_isup_inband_information_ind, parameter_tvb, 0, OPTIONAL_BACKWARD_CALL_IND_LENGTH, indicators);
  proto_tree_add_boolean(parameter_tree, hf_isup_call_diversion_may_occur_ind, parameter_tvb, 0, OPTIONAL_BACKWARD_CALL_IND_LENGTH, indicators);
  proto_tree_add_boolean(parameter_tree, hf_isup_simple_segmentation_ind, parameter_tvb, 0, OPTIONAL_BACKWARD_CALL_IND_LENGTH, indicators);
  proto_tree_add_boolean(parameter_tree, hf_isup_mlpp_user_ind, parameter_tvb, 0, OPTIONAL_BACKWARD_CALL_IND_LENGTH, indicators);


  proto_item_set_text(parameter_item,"Optional backward call indicators: 0x%x", indicators );
}
/* ------------------------------------------------------------------
  Dissector Parameter User-to-user indicators
 */
void 
dissect_isup_user_to_user_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ 
  guint8 indicators;
  
  indicators = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_text(parameter_item, parameter_tvb, 0, USER_TO_USER_IND_LENGTH, "User-to-user indicators: 0x%x (refer to 3.60/Q.763 for detailed decoding)", indicators );
  proto_item_set_text(parameter_item,"User-to-user indicators: 0x%x", indicators );
}
/* ------------------------------------------------------------------
  Dissector Parameter Original ISC point code 
 */
void 
dissect_isup_original_isc_point_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ 
  guint16 spc;
  
  spc = tvb_get_letohs(parameter_tvb, 0) & 0x3FFF; /*since 1st 2 bits spare */
  proto_tree_add_text(parameter_item, parameter_tvb, 0, ORIGINAL_ISC_POINT_CODE_LENGTH, "Origination ISC Point Code: %u", spc); 

  proto_item_set_text(parameter_item, "Origination ISC point code: %u", spc);
}
/* ------------------------------------------------------------------
  Dissector Parameter Generic notification indicator
 */
void 
dissect_isup_generic_notification_indicator_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ 
  guint8 indicators;
  
  indicators = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_text(parameter_item, parameter_tvb, 0, GENERIC_NOTIFICATION_IND_LENGTH, "Generic notification indicator: 0x%x (refer to 3.25/Q.763 for detailed decoding)", indicators );
  proto_item_set_text(parameter_item,"Generic notification indicator: 0x%x", indicators );
}
/* ------------------------------------------------------------------
  Dissector Parameter Call history information
 */
void 
dissect_isup_call_history_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ 
  guint16 info;
  
  info = tvb_get_ntohs(parameter_tvb, 0);
  proto_tree_add_text(parameter_item, parameter_tvb, 0, CALL_HISTORY_INFO_LENGTH, "Call history info: propagation delay = %u ms", info);
  proto_item_set_text(parameter_item,"Call history info: propagation delay = %u ms", info);
}
/* ------------------------------------------------------------------
  Dissector Parameter Access delivery information
 */
void 
dissect_isup_access_delivery_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_isup_access_delivery_ind, parameter_tvb, 0, ACCESS_DELIVERY_INFO_LENGTH, indicator); 
  proto_item_set_text(parameter_item, "Access delivery information: 0x%x", indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter Network specific facility
 */
void 
dissect_isup_network_specific_facility_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_item, parameter_tvb, 0, length, "Network specific facility (refer to 3.36/Q.763 for detailed decoding)"); 
  proto_item_set_text(parameter_item, "Network specific facility (%u byte%s length)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
  Dissector Parameter User service information prime 
 */
void 
dissect_isup_user_service_information_prime_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_item, parameter_tvb, 0, length, "User service information prime (-> Q.931)"); 
  proto_item_set_text(parameter_item, "User service information prime, see Q.931 (%u byte%s length)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
  Dissector Parameter Propagation delay counter
 */
void 
dissect_isup_propagation_delay_counter_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ 
  guint16 info;
  
  info = tvb_get_ntohs(parameter_tvb, 0);
  proto_tree_add_text(parameter_item, parameter_tvb, 0, PROPAGATION_DELAY_COUNT_LENGTH, "Propagation delay counter = %u ms", info);
  proto_item_set_text(parameter_item,"Propagation delay counter = %u ms", info);
}
/* ------------------------------------------------------------------
  Dissector Parameter Remote operations
 */
void 
dissect_isup_remote_operations_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_item, parameter_tvb, 0, length, "Remote operations"); 
  proto_item_set_text(parameter_item, "Remote operations (%u byte%s length)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
  Dissector Parameter Service activation
 */
void 
dissect_isup_service_activation_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ 
  guint i;
  guint8 feature_code;
  guint length = tvb_length(parameter_tvb);
  for (i=0; i< length; i++){
    feature_code = tvb_get_guint8(parameter_tvb, i);
    proto_tree_add_text(parameter_item, parameter_tvb, i, 1, "Feature Code %u: %u", i+1, feature_code); 
  }
  proto_item_set_text(parameter_item, "Service Activation (%u byte%s length)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
  Dissector Parameter User service information prime - no detailed dissection since defined in Rec. Q.931
 */
void 
dissect_isup_user_teleservice_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ 
  proto_tree_add_text(parameter_item, parameter_tvb, 0, USER_TELESERVICE_INFO_LENGTH, "User teleservice information (-> Q.931)"); 
  proto_item_set_text(parameter_item, "User teleservice information, see Q.931");
}
/* ------------------------------------------------------------------
  Dissector Parameter Transmission medium requirement used
 */
void 
dissect_isup_transmission_medium_used_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ 
  guint8 transmission_medium_requirement;
  
  transmission_medium_requirement = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_isup_transmission_medium_requirement_prime, parameter_tvb, 0, TRANSMISSION_MEDIUM_RQMT_PRIME_LENGTH,transmission_medium_requirement);

  proto_item_set_text(parameter_item, "Transmission medium used: %u (%s)",  transmission_medium_requirement, val_to_str(transmission_medium_requirement, isup_transmission_medium_requirement_prime_value, "spare/reserved"));
}
/* ------------------------------------------------------------------
  Dissector Parameter Call diversion information
 */
void 
dissect_isup_call_diversion_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0); 
  proto_tree_add_text(parameter_item, parameter_tvb, 0, CALL_DIV_INFO_LENGTH, "Call diversion information: 0x%x (refer to 3.6/Q.763 for detailed decoding)", indicator);
  proto_item_set_text(parameter_item, "Call diversion information: 0x%x", indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter Echo control  information
 */
void 
dissect_isup_echo_control_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0); 
  proto_tree_add_text(parameter_item, parameter_tvb, 0, ECHO_CONTROL_INFO_LENGTH, "Echo control information: 0x%x (refer to 3.19/Q.763 for detailed decoding)", indicator);
  proto_item_set_text(parameter_item, "Echo control information: 0x%x", indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter Message compatibility information
 */
void 
dissect_isup_message_compatibility_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_item, parameter_tvb, 0, length, "Message compatibility information (refer to 3.33/Q.763 for detailed decoding)"); 
  proto_item_set_text(parameter_item, "Message compatibility information (%u byte%s length)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
  Dissector Parameter compatibility information
 */
void 
dissect_isup_parameter_compatibility_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ 
  guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_item, parameter_tvb, 0, length, "Parameter compatibility information (refer to 3.41/Q.763 for detailed decoding)"); 
  proto_item_set_text(parameter_item, "Parameter compatibility information (%u byte%s length)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
  Dissector Parameter MLPP precedence
 */
void dissect_isup_mlpp_precedence_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  char NI_digits[5]="";
  guint8 indicators, digit_pair;
  guint32 bin_code;

  indicators = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_text(parameter_item, parameter_tvb, 0, 1, "LFB (Bits 6+7) and precedence level (Bits 1-4): 0x%x",indicators); 
  digit_pair = tvb_get_guint8(parameter_tvb, 1);
  NI_digits[0] = number_to_char((digit_pair & HGFE_8BIT_MASK) / 0x10);
  NI_digits[1] = number_to_char(digit_pair & DCBA_8BIT_MASK);
  digit_pair = tvb_get_guint8(parameter_tvb, 2);
  NI_digits[2] = number_to_char((digit_pair & HGFE_8BIT_MASK) / 0x10);
  NI_digits[3] = number_to_char(digit_pair & DCBA_8BIT_MASK);
  NI_digits[4] = '\0';
  proto_tree_add_text(parameter_item, parameter_tvb, 1, 2, "Network Identity: %s", NI_digits); 
  bin_code = tvb_get_ntoh24(parameter_tvb, 3);  
  proto_tree_add_text(parameter_item, parameter_tvb, 3, 3, "MLPP service domain: 0x%x", bin_code); 
  proto_item_set_text(parameter_item, "MLPP precedence: NI = %s, MLPP service domain = 0x%x", NI_digits, bin_code); 
}
/* ------------------------------------------------------------------
  Dissector Parameter MCID request indicators
 */
void 
dissect_isup_mcid_request_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0); 
  proto_tree_add_text(parameter_item, parameter_tvb, 0,MCID_REQUEST_IND_LENGTH, "MCID request indicators: 0x%x (MCID requested by Bit1=1, Holding requested by Bit2=1 see 3.31/Q.763)", indicator);
  proto_item_set_text(parameter_item, "MCID request indicators: 0x%x", indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter MCID response indicators
 */
void 
dissect_isup_mcid_response_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0); 
  proto_tree_add_text(parameter_item, parameter_tvb, 0,MCID_RESPONSE_IND_LENGTH, "MCID response indicators: 0x%x (MCID included if Bit1=1, Holding provided if Bit2=1 see 3.32/Q.763)", indicator);
  proto_item_set_text(parameter_item, "MCID response indicators: 0x%x", indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter Hop counter
 */
void 
dissect_isup_hop_counter_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 counter;

  counter = tvb_get_guint8(parameter_tvb, 0) & EDCBA_8BIT_MASK; /* since bits H,G and F are spare */ 
  proto_tree_add_text(parameter_item, parameter_tvb, 0, HOP_COUNTER_LENGTH, "Hop counter: %u", counter);
  proto_item_set_text(parameter_item,  "Hop counter: %u", counter);
}
/* ------------------------------------------------------------------
  Dissector Parameter Transmission medium requirement prime
 */
void 
dissect_isup_transmission_medium_requirement_prime_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ 
  guint8 transmission_medium_requirement;
  
  transmission_medium_requirement = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_isup_transmission_medium_requirement_prime, parameter_tvb, 0, TRANSMISSION_MEDIUM_RQMT_PRIME_LENGTH,transmission_medium_requirement);

  proto_item_set_text(parameter_item, "Transmission medium requirement prime: %u (%s)",  transmission_medium_requirement, val_to_str(transmission_medium_requirement, isup_transmission_medium_requirement_prime_value, "spare/reserved"));
}

/* ------------------------------------------------------------------
  Dissector Parameter location number
 */
void 
dissect_isup_location_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
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
  proto_tree_add_boolean(parameter_tree, hf_isup_odd_even_indicator, parameter_tvb, 0, 1, indicators1);
  proto_tree_add_uint(parameter_tree, hf_isup_calling_party_nature_of_address_indicator, parameter_tvb, 0, 1, indicators1);
  indicators2 = tvb_get_guint8(parameter_tvb, 1);
  proto_tree_add_boolean(parameter_tree, hf_isup_inn_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_numbering_plan_indicator, parameter_tvb, 1, 1, indicators2);
  if ((indicators2 & GFE_8BIT_MASK) == 0x50)
    proto_tree_add_text(parameter_item, parameter_tvb, 1, 1, "Different meaning for Location Number: Numbering plan indicator = private numbering plan");
  proto_tree_add_uint(parameter_tree, hf_isup_address_presentation_restricted_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_screening_indicator, parameter_tvb, 1, 1, indicators2);
  offset = 2;

  address_digits_item = proto_tree_add_text(parameter_tree, parameter_tvb,
					    offset,
					    tvb_length_remaining(parameter_tvb, offset),
					    "Location number");
  address_digits_tree = proto_item_add_subtree(address_digits_item, ett_isup_address_digits);

  length = tvb_length_remaining(parameter_tvb, offset);
  while(length > 0){
    address_digit_pair = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_odd_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
    calling_number[i++] = number_to_char(address_digit_pair & ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK);
    if ((length - 1) > 0 ){ 
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
    } 
    offset++;
    length = tvb_length_remaining(parameter_tvb, offset);   
  }

  if  (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
  }
  calling_number[i++] = '\0';

  proto_item_set_text(address_digits_item, "Location number: %s", calling_number);  
  proto_item_set_text(parameter_item, "Location number: %s", calling_number);
  
}
/* ------------------------------------------------------------------
  Dissector Parameter Redirection number restiriction
 */
void 
dissect_isup_redirection_number_restriction_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ 
  guint8 indicator;
  
  indicator = tvb_get_guint8(parameter_tvb, 0);
  switch (indicator & BA_8BIT_MASK) {
  case 0:
    proto_tree_add_text(parameter_item, parameter_tvb, 0, REDIRECTION_NUMBER_RESTRICTION_LENGTH, "Presentation indicator: Presentation allowed");
    break;
  case 1:
    proto_tree_add_text(parameter_item, parameter_tvb, 0, REDIRECTION_NUMBER_RESTRICTION_LENGTH, "Presentation indicator: Presentation restricted");
    break;
  default:
    proto_tree_add_text(parameter_item, parameter_tvb, 0, REDIRECTION_NUMBER_RESTRICTION_LENGTH, "Presentation indicator: spare");
    break;
  }
  proto_item_set_text(parameter_item, "Redirection number restriction: 0x%x ", indicator); 
}
/* ------------------------------------------------------------------
  Dissector Parameter Call transfer identity
 */
void 
dissect_isup_call_transfer_reference_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 id;

  id = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_text(parameter_item, parameter_tvb, 0, CALL_TRANSFER_REF_LENGTH, "Call transfer identity: %u", id);
  proto_item_set_text(parameter_item,  "Call transfer reference: %u", id);
}
/* ------------------------------------------------------------------
  Dissector Parameter Loop prevention
 */
void 
dissect_isup_loop_prevention_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ 
  guint8 indicator;
  
  indicator = tvb_get_guint8(parameter_tvb, 0);
  if ((indicator & A_8BIT_MASK)==0) {
    proto_tree_add_text(parameter_item, parameter_tvb, 0, LOOP_PREVENTION_IND_LENGTH, "Type: Request");
    proto_item_set_text(parameter_item, "Loop prevention indicators: Request (%u)", indicator); 
  }
  else {
    proto_tree_add_text(parameter_item, parameter_tvb, 0, LOOP_PREVENTION_IND_LENGTH, "Type: Response");
    proto_tree_add_uint(parameter_item, hf_isup_loop_prevention_response_ind, parameter_tvb, 0, LOOP_PREVENTION_IND_LENGTH, indicator);
    proto_item_set_text(parameter_item, "Loop prevention indicators: Response (%u)", indicator); 
  }
}
/* ------------------------------------------------------------------
  Dissector Parameter Call transfer number
 */
void 
dissect_isup_call_transfer_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
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
  proto_tree_add_boolean(parameter_tree, hf_isup_odd_even_indicator, parameter_tvb, 0, 1, indicators1);
  proto_tree_add_uint(parameter_tree, hf_isup_calling_party_nature_of_address_indicator, parameter_tvb, 0, 1, indicators1);
  indicators2 = tvb_get_guint8(parameter_tvb, 1);
  proto_tree_add_uint(parameter_tree, hf_isup_numbering_plan_indicator, parameter_tvb, 1, 1, indicators2);
  if ((indicators2 & GFE_8BIT_MASK) == 0x50)
    proto_tree_add_text(parameter_item, parameter_tvb, 1, 1, "Different meaning for Call Transfer Number: Numbering plan indicator = private numbering plan");
  proto_tree_add_uint(parameter_tree, hf_isup_address_presentation_restricted_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_screening_indicator_enhanced, parameter_tvb, 1, 1, indicators2);
  offset = 2;

  address_digits_item = proto_tree_add_text(parameter_tree, parameter_tvb,
					    offset,
					    tvb_length_remaining(parameter_tvb, offset),
					    "Call transfer number");
  address_digits_tree = proto_item_add_subtree(address_digits_item, ett_isup_address_digits);

  length = tvb_length_remaining(parameter_tvb, offset);
  while(length > 0){
    address_digit_pair = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_odd_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
    calling_number[i++] = number_to_char(address_digit_pair & ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK);
    if ((length - 1) > 0 ){ 
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
    } 
    offset++;
    length = tvb_length_remaining(parameter_tvb, offset);   
  }

  if  (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
  }
  calling_number[i++] = '\0';

  proto_item_set_text(address_digits_item, "Call transfer number: %s", calling_number);  
  proto_item_set_text(parameter_item, "Call transfer number: %s", calling_number);
  
}
/* ------------------------------------------------------------------
  Dissector Parameter CCSS
 */
void 
dissect_isup_ccss_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ 
  guint8 indicator;
  
  indicator = tvb_get_guint8(parameter_tvb, 0);
  if ((indicator & A_8BIT_MASK)==0) {
    proto_tree_add_text(parameter_item, parameter_tvb, 0, LOOP_PREVENTION_IND_LENGTH, "CCSS call indicator: no indication");
    proto_item_set_text(parameter_item, "CCSS call indicator: no indication (%u)", indicator); 
  }
  else {
    proto_tree_add_text(parameter_item, parameter_tvb, 0, LOOP_PREVENTION_IND_LENGTH, "CCSS call indicator: CCSS call");
    proto_item_set_text(parameter_item, "CCSS call indicator: CCSS call (%u)", indicator); 
  }
}
/* ------------------------------------------------------------------ 
 Parameter Forward GVNS 
 */
void
dissect_isup_forward_gvns_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_item, parameter_tvb, 0, length, "Forward GVNS (refer to 3.66/Q.763 for detailed decoding)");
  proto_item_set_text(parameter_item, "Forward GVNS (%u Byte%s)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------ 
 Parameter Redirect capability
 */
void
dissect_isup_redirect_capability_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_item, parameter_tvb, 0, length, "Redirect capability (format is a national matter)");
  proto_item_set_text(parameter_item, "Redirect Capability (%u Byte%s)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
  Dissector Parameter Backward GVNS
 */
void 
dissect_isup_backward_gvns_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0); 
  proto_tree_add_text(parameter_item, parameter_tvb, 0, BACKWARD_GVNS_LENGTH, "Backward GVNS: 0x%x (refer to 3.62/Q.763 for detailed decoding)", indicator);
  proto_item_set_text(parameter_item, "Backward GVNS: 0x%x", indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter Network management controls
 */
void 
dissect_isup_network_management_controls_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0); 
  proto_tree_add_boolean(parameter_item, hf_isup_temporary_alternative_routing_ind, parameter_tvb, 0,NETWORK_MANAGEMENT_CONTROLS_LENGTH, indicator);
  proto_tree_add_boolean(parameter_item, hf_isup_extension_ind, parameter_tvb, 0,NETWORK_MANAGEMENT_CONTROLS_LENGTH, indicator);
  proto_item_set_text(parameter_item, "Network management controls: 0x%x", indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter Correlation id - no detailed dissection since defined in Rec. Q.1281
 */
void 
dissect_isup_correlation_id_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_item, parameter_tvb, 0, length, "Correlation ID (-> Q.1281)"); 
  proto_item_set_text(parameter_item, "Correlation ID, see Q.1281 (%u Byte%s)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
  Dissector Parameter SCF id - no detailed dissection since defined in Rec. Q.1281
 */
void 
dissect_isup_scf_id_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_item, parameter_tvb, 0, length, "SCF ID (-> Q.1281)"); 
  proto_item_set_text(parameter_item, "SCF ID, see Q.1281 (%u Byte%s)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
  Dissector Parameter Call diversion treatment indicators
 */
void 
dissect_isup_call_diversion_treatment_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0); 
  proto_tree_add_uint(parameter_item, hf_isup_call_to_be_diverted_ind, parameter_tvb, 0,CALL_DIV_TREATMENT_IND_LENGTH, indicator);
  proto_tree_add_boolean(parameter_item, hf_isup_extension_ind, parameter_tvb, 0, CALL_DIV_TREATMENT_IND_LENGTH, indicator);
  proto_item_set_text(parameter_item, "Call diversion treatment indicators: 0x%x", indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter called IN  number
 */
void 
dissect_isup_called_in_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
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
  proto_tree_add_boolean(parameter_tree, hf_isup_odd_even_indicator, parameter_tvb, 0, 1, indicators1);
  proto_tree_add_uint(parameter_tree, hf_isup_calling_party_nature_of_address_indicator, parameter_tvb, 0, 1, indicators1);
  indicators2 = tvb_get_guint8(parameter_tvb, 1);
  proto_tree_add_uint(parameter_tree, hf_isup_numbering_plan_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_address_presentation_restricted_indicator, parameter_tvb, 1, 1, indicators2);
  offset = 2;

  address_digits_item = proto_tree_add_text(parameter_tree, parameter_tvb,
					    offset,
					    tvb_length_remaining(parameter_tvb, offset),
					    "Called IN Number");
  address_digits_tree = proto_item_add_subtree(address_digits_item, ett_isup_address_digits);

  length = tvb_length_remaining(parameter_tvb, offset);
  while(length > 0){
    address_digit_pair = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_odd_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
    calling_number[i++] = number_to_char(address_digit_pair & ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK);
    if ((length - 1) > 0 ){ 
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
    } 
    offset++;
    length = tvb_length_remaining(parameter_tvb, offset);   
  }

  if  (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
  }
  calling_number[i++] = '\0';

  proto_item_set_text(address_digits_item, "Called IN Number: %s", calling_number);  
  proto_item_set_text(parameter_item, "Called IN Number: %s", calling_number);
  
}
/* ------------------------------------------------------------------
  Dissector Parameter Call offering treatment indicators
 */
void 
dissect_isup_call_offering_treatment_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0); 
  proto_tree_add_uint(parameter_item, hf_isup_call_to_be_offered_ind, parameter_tvb, 0,CALL_OFFERING_TREATMENT_IND_LENGTH, indicator);
  proto_tree_add_boolean(parameter_item, hf_isup_extension_ind, parameter_tvb, 0, CALL_OFFERING_TREATMENT_IND_LENGTH, indicator);
  proto_item_set_text(parameter_item, "Call offering treatment indicators: 0x%x", indicator);
}
/* ------------------------------------------------------------------ 
 Parameter Charged party identification
 */
void
dissect_isup_charged_party_identification_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_item, parameter_tvb, 0, length, "Charged party identification (format is national network specific)");
  proto_item_set_text(parameter_item, "Charged party identification (%u Byte%s)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
  Dissector Parameter Conference treatment indicators
 */
void 
dissect_isup_conference_treatment_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0); 
  proto_tree_add_uint(parameter_item, hf_isup_conference_acceptance_ind, parameter_tvb, 0,CONFERENCE_TREATMENT_IND_LENGTH, indicator);
  proto_tree_add_boolean(parameter_item, hf_isup_extension_ind, parameter_tvb, 0, CONFERENCE_TREATMENT_IND_LENGTH, indicator);
  proto_item_set_text(parameter_item, "Conference treatment indicators: 0x%x", indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter Display information
 */
void 
dissect_isup_display_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_item, parameter_tvb, 0, length, "Display information (-> Q.931)");
  proto_item_set_text(parameter_item, "Display information (%u Byte%s)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------ 
 Parameter UID action indicators
 */
void
dissect_isup_uid_action_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0); 
  proto_tree_add_text(parameter_item, parameter_tvb, 0,UID_ACTION_IND_LENGTH, "UID action indicators: 0x%x (refer to 3.78/Q.763 for detailed decoding)", indicator);
  proto_item_set_text(parameter_item, "UID action indicators: 0x%x", indicator);
}
/* ------------------------------------------------------------------ 
 Parameter UID capability indicators
 */
void
dissect_isup_uid_capability_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0); 
  proto_tree_add_text(parameter_item, parameter_tvb, 0,UID_CAPABILITY_IND_LENGTH, "UID capability indicators: 0x%x (refer to 3.79/Q.763 for detailed decoding)", indicator);
  proto_item_set_text(parameter_item, "UID capability indicators: 0x%x", indicator);
}
/* ------------------------------------------------------------------ 
 Parameter Redirect counter
 */
void
dissect_isup_redirect_counter_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_item, parameter_tvb, 0, length, "Redirect counter (format is a national matter)");
  proto_item_set_text(parameter_item, "Redirect counter (%u Byte%s)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
  Dissector Parameter Collect call request
 */
void 
dissect_isup_collect_call_request_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0); 
  if ((indicator & A_8BIT_MASK) == 0) {
    proto_tree_add_text(parameter_item, parameter_tvb, 0, COLLECT_CALL_REQUEST_LENGTH, "Collect call request indicator: no indication");
    proto_item_set_text(parameter_item, "Collect call reqeust: no indication (0x%x)", indicator);
  }
  else {
    proto_tree_add_text(parameter_item, parameter_tvb, 0, COLLECT_CALL_REQUEST_LENGTH, "Collect call request indicator: collect call requested");
    proto_item_set_text(parameter_item, "Collect call reqeust: collect call requested (0x%x)", indicator);
  }
}
/* ------------------------------------------------------------------
  Dissector Parameter Generic number
 */
void 
dissect_isup_generic_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_item *address_digits_item;
  proto_tree *address_digits_tree;
  guint8 indicators1, indicators2, nr_qualifier_ind;
  guint8 address_digit_pair=0;
  gint offset=0; 
  gint i=0;
  gint length;
  char calling_number[MAXLENGTH]="";

  nr_qualifier_ind = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, 1, "Number qualifier indicator: 0x%x (refer to 3.26/Q.763 for detailed decoding)", nr_qualifier_ind);
  indicators1 = tvb_get_guint8(parameter_tvb, 1);
  proto_tree_add_boolean(parameter_tree, hf_isup_odd_even_indicator, parameter_tvb, 1, 1, indicators1);
  proto_tree_add_uint(parameter_tree, hf_isup_calling_party_nature_of_address_indicator, parameter_tvb, 0, 1, indicators1);
  indicators2 = tvb_get_guint8(parameter_tvb, 2);
  proto_tree_add_boolean(parameter_tree, hf_isup_ni_indicator, parameter_tvb, 2, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_numbering_plan_indicator, parameter_tvb, 2, 1, indicators2);
  if ((indicators2 & GFE_8BIT_MASK) == 0x50)
    proto_tree_add_text(parameter_item, parameter_tvb, 2, 1, "Different meaning for Generic Number: Numbering plan indicator = private numbering plan");
  proto_tree_add_uint(parameter_tree, hf_isup_address_presentation_restricted_indicator, parameter_tvb, 2, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_screening_indicator_enhanced, parameter_tvb, 2, 1, indicators2);
  offset = 3;

  address_digits_item = proto_tree_add_text(parameter_tree, parameter_tvb,
					    offset,
					    tvb_length_remaining(parameter_tvb, offset),
					    "Generic number");
  address_digits_tree = proto_item_add_subtree(address_digits_item, ett_isup_address_digits);

  length = tvb_length_remaining(parameter_tvb, offset);
  while(length > 0){
    address_digit_pair = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_odd_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
    calling_number[i++] = number_to_char(address_digit_pair & ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK);
    if ((length - 1) > 0 ){ 
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
    } 
    offset++;
    length = tvb_length_remaining(parameter_tvb, offset);   
  }

  if  (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
  }
  calling_number[i++] = '\0';

  proto_item_set_text(address_digits_item, "Generic number: %s", calling_number);  
  proto_item_set_text(parameter_item, "Generic number: %s", calling_number);
  
}
/* ------------------------------------------------------------------ 
 Dissector Parameter Generic digits
 */
void
dissect_isup_generic_digits_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_item, parameter_tvb, 0, length, "Generic digits (refer to 3.24/Q.673 for detailed decoding)");
  proto_item_set_text(parameter_item, "Generic digits (%u Byte%s)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------ */
void
dissect_isup_unknown_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_item_set_text(parameter_item, "Parameter Type unknown/reserved (%u Byte%s)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------
  Dissector all optional parameters
*/
void
dissect_isup_optional_parameter(tvbuff_t *optional_parameters_tvb, proto_tree *isup_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  gint offset = 0;
  guint parameter_type, parameter_length, actual_length;
  tvbuff_t *parameter_tvb;

  /* Dissect all optional parameters while end of message isn't reached */
  parameter_type = 0xFF; /* Start-initializiation since parameter_type is used for while-condition */
  
  while ((tvb_length_remaining(optional_parameters_tvb, offset)  >= 1) && (parameter_type != PARAM_TYPE_END_OF_OPT_PARAMS)){
    parameter_type = tvb_get_guint8(optional_parameters_tvb, offset);
    
    if (parameter_type != PARAM_TYPE_END_OF_OPT_PARAMS){
      parameter_length = tvb_get_guint8(optional_parameters_tvb, offset + PARAMETER_TYPE_LENGTH);
      
      parameter_item = proto_tree_add_text(isup_tree, optional_parameters_tvb,
					   offset,
					   parameter_length  + PARAMETER_TYPE_LENGTH + PARAMETER_LENGTH_IND_LENGTH,
					   "Parameter: type %u",
					   parameter_type);
      parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
      proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, optional_parameters_tvb, offset, PARAMETER_TYPE_LENGTH, parameter_type, "Optional Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));	
      offset += PARAMETER_TYPE_LENGTH;
      
      proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_length, optional_parameters_tvb, offset, PARAMETER_LENGTH_IND_LENGTH, parameter_length, "Parameter length: %u", parameter_length);
      offset += PARAMETER_LENGTH_IND_LENGTH;
      
      actual_length = tvb_length_remaining(optional_parameters_tvb, offset);
      if (actual_length > 0){
	parameter_tvb = tvb_new_subset(optional_parameters_tvb, offset, MIN(parameter_length, actual_length), parameter_length);
	switch (parameter_type) {
	case PARAM_TYPE_CALL_REF:
	  dissect_isup_call_reference_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_TRANSM_MEDIUM_REQU:
	  dissect_isup_transmission_medium_requirement_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_ACC_TRANSP:
	  dissect_isup_access_transport_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_CALLED_PARTY_NR:
	  dissect_isup_called_party_number_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_SUBSQT_NR:
	  dissect_isup_subsequent_number_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_NATURE_OF_CONN_IND:
	  dissect_isup_nature_of_connection_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_FORW_CALL_IND:
	  dissect_isup_forward_call_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_OPT_FORW_CALL_IND:
	  dissect_isup_optional_forward_call_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_CALLING_PRTY_CATEG:
	  dissect_isup_calling_partys_category_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_CALLING_PARTY_NR:
	  dissect_isup_calling_party_number_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_REDIRECTING_NR:
	  dissect_isup_redirecting_number_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_REDIRECTION_NR:
	  dissect_isup_redirection_number_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_CONNECTION_REQ:
	  dissect_isup_connection_request_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_INFO_REQ_IND:
	  dissect_isup_information_request_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_INFO_IND:
	  dissect_isup_information_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_CONTINUITY_IND:
	  dissect_isup_continuity_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_BACKW_CALL_IND:
	  dissect_isup_backward_call_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_CAUSE_INDICATORS:
	  dissect_isup_cause_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_REDIRECTION_INFO:
	  dissect_isup_redirection_information_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_CIRC_GRP_SV_MSG_TYPE:
	  dissect_isup_circuit_group_supervision_message_type_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_RANGE_AND_STATUS:
	  dissect_isup_range_and_status_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_FACILITY_IND:
	  dissect_isup_facility_ind_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_CLSD_USR_GRP_ILOCK_CD:
	  dissect_isup_closed_user_group_interlock_code_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_USER_SERVICE_INFO:
	  dissect_isup_user_service_information_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_SIGNALLING_POINT_CODE:
	  dissect_isup_signalling_point_code_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_USER_TO_USER_INFO:
	  dissect_isup_user_to_user_information_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_CONNECTED_NR:
	  dissect_isup_connected_number_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_SUSP_RESUME_IND:
	  dissect_isup_suspend_resume_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_TRANSIT_NETW_SELECT:
	  dissect_isup_transit_network_selection_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_EVENT_INFO:
	  dissect_isup_event_information_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_CIRC_ASSIGN_MAP:
	  dissect_isup_circuit_assignment_map_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_CIRC_STATE_IND:
	  dissect_isup_circuit_state_ind_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_AUTO_CONG_LEVEL:
	  dissect_isup_automatic_congestion_level_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_ORIG_CALLED_NR:
	  dissect_isup_original_called_number_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_OPT_BACKW_CALL_IND:
	  dissect_isup_optional_backward_call_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_USER_TO_USER_IND:
	  dissect_isup_user_to_user_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	case PARAM_TYPE_ORIG_ISC_POINT_CODE:
	  dissect_isup_original_isc_point_code_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_GENERIC_NOTIF_IND:
	  dissect_isup_generic_notification_indicator_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_CALL_HIST_INFO :
	  dissect_isup_call_history_information_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_ACC_DELIV_INFO:
	  dissect_isup_access_delivery_information_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_NETW_SPECIFIC_FACLTY:
	  dissect_isup_network_specific_facility_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_USER_SERVICE_INFO_PR:
	  dissect_isup_user_service_information_prime_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_PROPAG_DELAY_COUNTER:
	  dissect_isup_propagation_delay_counter_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_REMOTE_OPERATIONS:
	  dissect_isup_remote_operations_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_SERVICE_ACTIVATION:
	  dissect_isup_service_activation_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_USER_TELESERV_INFO:
	  dissect_isup_user_teleservice_information_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_TRANSM_MEDIUM_USED:
	  dissect_isup_transmission_medium_used_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_CALL_DIV_INFO:
	  dissect_isup_call_diversion_information_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_ECHO_CTRL_INFO:
	  dissect_isup_echo_control_information_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_MSG_COMPAT_INFO:
	  dissect_isup_message_compatibility_information_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_PARAM_COMPAT_INFO:
	  dissect_isup_parameter_compatibility_information_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_MLPP_PRECEDENCE:
	  dissect_isup_mlpp_precedence_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_MCID_REQ_IND:
	  dissect_isup_mcid_request_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_MCID_RSP_IND:
	  dissect_isup_mcid_response_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_HOP_COUNTER:
	  dissect_isup_hop_counter_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_TRANSM_MEDIUM_RQUR_PR:
	  dissect_isup_transmission_medium_requirement_prime_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_LOCATION_NR:
	  dissect_isup_location_number_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_REDIR_NR_RSTRCT:
	  dissect_isup_redirection_number_restriction_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_CALL_TRANS_REF:
	  dissect_isup_call_transfer_reference_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_LOOP_PREV_IND:
	  dissect_isup_loop_prevention_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_CALL_TRANS_NR:
	  dissect_isup_call_transfer_number_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_CCSS:
	  dissect_isup_ccss_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_FORW_GVNS:
	  dissect_isup_forward_gvns_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_BACKW_GVNS:
	  dissect_isup_backward_gvns_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_REDIRECT_CAPAB:
	  dissect_isup_redirect_capability_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_NETW_MGMT_CTRL:
	  dissect_isup_network_management_controls_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_CORRELATION_ID:
	  dissect_isup_correlation_id_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_SCF_ID:
	  dissect_isup_scf_id_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_CALL_DIV_TREAT_IND:
	  dissect_isup_call_diversion_treatment_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_CALLED_IN_NR:
	  dissect_isup_called_in_number_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_CALL_OFF_TREAT_IND:
	  dissect_isup_call_offering_treatment_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_CHARGED_PARTY_IDENT:
	  dissect_isup_charged_party_identification_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_CONF_TREAT_IND:
	  dissect_isup_conference_treatment_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_DISPLAY_INFO:
	  dissect_isup_display_information_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_UID_ACTION_IND:
	  dissect_isup_uid_action_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_UID_CAPAB_IND:
	  dissect_isup_uid_capability_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_REDIRECT_COUNTER:
	  dissect_isup_redirect_counter_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_COLLECT_CALL_REQ:
	  dissect_isup_collect_call_request_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_GENERIC_NR:
	  dissect_isup_generic_number_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;
	case PARAM_TYPE_GENERIC_DIGITS:
	  dissect_isup_generic_digits_parameter(parameter_tvb, parameter_tree, parameter_item);	  
	  break;	  
	default:
	  dissect_isup_unknown_parameter(parameter_tvb, parameter_tree, parameter_item);
	  break;
	}
	offset += MIN(parameter_length, actual_length);
      }
      
    }
    else {
	/* End of optional parameters is reached */
	proto_tree_add_uint_format(isup_tree, hf_isup_message_type, optional_parameters_tvb , offset, PARAMETER_TYPE_LENGTH, parameter_type, "End of optional parameters (%u)", parameter_type);
    }
  }
}

/* ------------------------------------------------------------------ */
/* Dissectors for all used message types                              */
/* Called by dissect_isup_message(),                                  */ 
/* call parameter dissectors in order of mandatory parameters         */
/* (since not labeled)                                                */
/* ------------------------------------------------------------------
  Dissector Message Type Initial address message 
 */
gint
dissect_isup_initial_address_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  tvbuff_t *parameter_tvb;
  gint offset = 0;
  gint parameter_type, parameter_pointer, parameter_length, actual_length;
  
  /* Do stuff for first mandatory fixed parameter: Nature of Connection Indicators */
  parameter_type = PARAM_TYPE_NATURE_OF_CONN_IND;
  parameter_item = proto_tree_add_text(isup_tree, message_tvb, offset,
				       NATURE_OF_CONNECTION_IND_LENGTH,
				       "Nature of Connection Indicators");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));		
  actual_length = tvb_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(NATURE_OF_CONNECTION_IND_LENGTH, actual_length), NATURE_OF_CONNECTION_IND_LENGTH);
  dissect_isup_nature_of_connection_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += NATURE_OF_CONNECTION_IND_LENGTH;

  /* Do stuff for 2nd mandatory fixed parameter: Forward Call Indicators */
  parameter_type =  PARAM_TYPE_FORW_CALL_IND;
  parameter_item = proto_tree_add_text(isup_tree, message_tvb, offset,
				       FORWARD_CALL_IND_LENGTH,
				       "Forward Call Indicators");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));		
  actual_length = tvb_length_remaining(message_tvb, offset); 
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(FORWARD_CALL_IND_LENGTH, actual_length), FORWARD_CALL_IND_LENGTH );
  dissect_isup_forward_call_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset +=  FORWARD_CALL_IND_LENGTH;

  /* Do stuff for 3nd mandatory fixed parameter: Calling party's category */
  parameter_type = PARAM_TYPE_CALLING_PRTY_CATEG;
  parameter_item = proto_tree_add_text(isup_tree, message_tvb, offset,
				       CALLING_PRTYS_CATEGORY_LENGTH,
				       "Calling Party's category");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));		
  actual_length = tvb_length_remaining(message_tvb, offset); 
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(CALLING_PRTYS_CATEGORY_LENGTH, actual_length),CALLING_PRTYS_CATEGORY_LENGTH );
  dissect_isup_calling_partys_category_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += CALLING_PRTYS_CATEGORY_LENGTH;

  /* Do stuff for 4th mandatory fixed parameter: Transmission medium requirement */
  parameter_type = PARAM_TYPE_TRANSM_MEDIUM_REQU;
  parameter_item = proto_tree_add_text(isup_tree, message_tvb, offset,
				       TRANSMISSION_MEDIUM_REQUIREMENT_LENGTH,
				       "Transmission medium requirement");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));		       
  actual_length = tvb_length_remaining(message_tvb, offset); 
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(TRANSMISSION_MEDIUM_REQUIREMENT_LENGTH, actual_length), TRANSMISSION_MEDIUM_REQUIREMENT_LENGTH);
  dissect_isup_transmission_medium_requirement_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += TRANSMISSION_MEDIUM_REQUIREMENT_LENGTH;


  /* Do stuff for mandatory variable parameter Called party number */
  parameter_type = PARAM_TYPE_CALLED_PARTY_NR;
  parameter_pointer = tvb_get_guint8(message_tvb, offset);
  parameter_length = tvb_get_guint8(message_tvb, offset + parameter_pointer);

  parameter_item = proto_tree_add_text(isup_tree, message_tvb,
				       offset +  parameter_pointer,
				       parameter_length + PARAMETER_LENGTH_IND_LENGTH,
				       "Called Party Number");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));	
  proto_tree_add_uint_format(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset, PARAMETER_POINTER_LENGTH, parameter_pointer, "Pointer to Parameter: %u", parameter_pointer);  
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer, PARAMETER_LENGTH_IND_LENGTH, parameter_length, "Parameter length: %u", parameter_length);
  actual_length = tvb_length_remaining(message_tvb, offset); 	       
  parameter_tvb = tvb_new_subset(message_tvb, offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH, MIN(parameter_length, actual_length), parameter_length );
  dissect_isup_called_party_number_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += PARAMETER_POINTER_LENGTH;

  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type subsequent address message 
 */
gint dissect_isup_subsequent_address_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  tvbuff_t *parameter_tvb;
  gint offset = 0;
  gint parameter_type, parameter_pointer, parameter_length, actual_length;
  
  /* Do stuff for mandatory variable parameter Subsequent number */
  parameter_type = PARAM_TYPE_SUBSQT_NR;

  parameter_pointer = tvb_get_guint8(message_tvb, offset);
  parameter_length = tvb_get_guint8(message_tvb, offset + parameter_pointer);

  parameter_item = proto_tree_add_text(isup_tree, message_tvb,
				       offset +  parameter_pointer,
				       parameter_length + PARAMETER_LENGTH_IND_LENGTH,
				       "Subsequent Number");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));	
  proto_tree_add_uint_format(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset, PARAMETER_POINTER_LENGTH, parameter_pointer, "Pointer to Parameter: %u", parameter_pointer);  
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer, PARAMETER_LENGTH_IND_LENGTH, parameter_length, "Parameter length: %u", parameter_length);
  actual_length = tvb_length_remaining(message_tvb, offset); 	       
  parameter_tvb = tvb_new_subset(message_tvb, offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH, MIN(parameter_length, actual_length), parameter_length );
  dissect_isup_subsequent_number_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += PARAMETER_POINTER_LENGTH;

  return offset;
}

/* ------------------------------------------------------------------
  Dissector Message Type Information request message 
 */
gint
dissect_isup_information_request_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  tvbuff_t *parameter_tvb;
  gint offset = 0;
  gint parameter_type, actual_length;
 
  /* Do stuff for first mandatory fixed parameter: Information request indicators*/ 
  parameter_type = PARAM_TYPE_INFO_REQ_IND;
  parameter_item = proto_tree_add_text(isup_tree, message_tvb, offset,
				       INFO_REQUEST_IND_LENGTH,
				       "Information request indicators");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));		
  actual_length = tvb_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(INFO_REQUEST_IND_LENGTH, actual_length), INFO_REQUEST_IND_LENGTH);
  dissect_isup_information_request_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += INFO_REQUEST_IND_LENGTH;
  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type Information  
 */
gint
dissect_isup_information_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  tvbuff_t *parameter_tvb;
  gint offset = 0;
  gint parameter_type, actual_length;
 
  /* Do stuff for first mandatory fixed parameter: Information  indicators*/ 
  parameter_type = PARAM_TYPE_INFO_IND;
  parameter_item = proto_tree_add_text(isup_tree, message_tvb, offset,
				       INFO_IND_LENGTH,
				       "Information indicators");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));		
  actual_length = tvb_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(INFO_IND_LENGTH, actual_length), INFO_IND_LENGTH);
  dissect_isup_information_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += INFO_IND_LENGTH;
  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type Continuity 
 */
gint
dissect_isup_continuity_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  tvbuff_t *parameter_tvb;
  gint offset = 0;
  gint parameter_type, actual_length;
 
  /* Do stuff for first mandatory fixed parameter: Continuity indicators*/ 
  parameter_type = PARAM_TYPE_CONTINUITY_IND;
  parameter_item = proto_tree_add_text(isup_tree, message_tvb, offset,
				       CONTINUITY_IND_LENGTH,
				       "Continuity indicators");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));		
  actual_length = tvb_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(CONTINUITY_IND_LENGTH, actual_length), CONTINUITY_IND_LENGTH);
  dissect_isup_continuity_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += CONTINUITY_IND_LENGTH;
  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type Address complete
 */
gint
dissect_isup_address_complete_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  tvbuff_t *parameter_tvb;
  gint offset = 0;
  gint parameter_type, actual_length;
 
  /* Do stuff for first mandatory fixed parameter: backward call indicators*/ 
  parameter_type = PARAM_TYPE_BACKW_CALL_IND;
  parameter_item = proto_tree_add_text(isup_tree, message_tvb, offset,
				       BACKWARD_CALL_IND_LENGTH,
				       "Backward Call Indicators");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));		
  actual_length = tvb_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(BACKWARD_CALL_IND_LENGTH, actual_length), BACKWARD_CALL_IND_LENGTH);
  dissect_isup_backward_call_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += BACKWARD_CALL_IND_LENGTH;
  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type Connect
 */
gint
dissect_isup_connect_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  tvbuff_t *parameter_tvb;
  gint offset = 0;
  gint parameter_type, actual_length;
 
  /* Do stuff for first mandatory fixed parameter: backward call indicators*/ 
  parameter_type = PARAM_TYPE_BACKW_CALL_IND;
  parameter_item = proto_tree_add_text(isup_tree, message_tvb, offset,
				       BACKWARD_CALL_IND_LENGTH,
				       "Backward Call Indicators");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));		
  actual_length = tvb_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(BACKWARD_CALL_IND_LENGTH, actual_length), BACKWARD_CALL_IND_LENGTH);
  dissect_isup_backward_call_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += BACKWARD_CALL_IND_LENGTH;
  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type release message 
 */
gint 
dissect_isup_release_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  tvbuff_t *parameter_tvb;
  gint offset = 0;
  gint parameter_type, parameter_pointer, parameter_length, actual_length;
  
  /* Do stuff for mandatory variable parameter Cause indicators */
  parameter_type =  PARAM_TYPE_CAUSE_INDICATORS;

  parameter_pointer = tvb_get_guint8(message_tvb, offset);
  parameter_length = tvb_get_guint8(message_tvb, offset + parameter_pointer);

  parameter_item = proto_tree_add_text(isup_tree, message_tvb,
				       offset +  parameter_pointer,
				       parameter_length + PARAMETER_LENGTH_IND_LENGTH,
				       "Cause indicators, see Q.850");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));	
  proto_tree_add_uint_format(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset, PARAMETER_POINTER_LENGTH, parameter_pointer, "Pointer to Parameter: %u", parameter_pointer);  
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer, PARAMETER_LENGTH_IND_LENGTH, parameter_length, "Parameter length: %u", parameter_length);
  actual_length = tvb_length_remaining(message_tvb, offset); 	       
  parameter_tvb = tvb_new_subset(message_tvb, offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH, MIN(parameter_length, actual_length), parameter_length );
  dissect_isup_cause_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += PARAMETER_POINTER_LENGTH;

  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type Resume/Suspend
 */
gint
dissect_isup_suspend_resume_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  tvbuff_t *parameter_tvb;
  gint offset = 0;
  gint parameter_type, actual_length;
 
  /* Do stuff for first mandatory fixed parameter: backward call indicators*/ 
  parameter_type = PARAM_TYPE_SUSP_RESUME_IND;
  parameter_item = proto_tree_add_text(isup_tree, message_tvb, offset,
				       SUSPEND_RESUME_IND_LENGTH,
				       "Suspend/Resume indicator");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));		
  actual_length = tvb_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(SUSPEND_RESUME_IND_LENGTH, actual_length), SUSPEND_RESUME_IND_LENGTH);
  dissect_isup_suspend_resume_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += SUSPEND_RESUME_IND_LENGTH;
  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type Circuit group reset/query message
 */
gint 
dissect_isup_circuit_group_reset_query_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  tvbuff_t *parameter_tvb;
  gint offset = 0;
  gint parameter_type, parameter_pointer, parameter_length, actual_length;
  
  /* Do stuff for mandatory variable parameter range and status*/
  parameter_type =  PARAM_TYPE_RANGE_AND_STATUS;

  parameter_pointer = tvb_get_guint8(message_tvb, offset);
  parameter_length = tvb_get_guint8(message_tvb, offset + parameter_pointer);

  parameter_item = proto_tree_add_text(isup_tree, message_tvb,
				       offset +  parameter_pointer,
				       parameter_length + PARAMETER_LENGTH_IND_LENGTH,
				       "Range and status");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));	
  proto_tree_add_uint_format(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset, PARAMETER_POINTER_LENGTH, parameter_pointer, "Pointer to Parameter: %u", parameter_pointer);  
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer, PARAMETER_LENGTH_IND_LENGTH, parameter_length, "Parameter length: %u", parameter_length);
  actual_length = tvb_length_remaining(message_tvb, offset); 	       
  parameter_tvb = tvb_new_subset(message_tvb, offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH, MIN(parameter_length, actual_length), parameter_length );
  dissect_isup_range_and_status_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += PARAMETER_POINTER_LENGTH;

  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type Circuit group blocking/blocking ack/unblocking/unblocking ack messages 
 */
gint 
dissect_isup_circuit_group_blocking_messages(tvbuff_t *message_tvb, proto_tree *isup_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  tvbuff_t *parameter_tvb;
  gint offset = 0;
  gint parameter_type, parameter_pointer, parameter_length, actual_length;

   /* Do stuff for first mandatory fixed parameter: circuit group supervision message type*/ 
  parameter_type = PARAM_TYPE_CIRC_GRP_SV_MSG_TYPE;
  parameter_item = proto_tree_add_text(isup_tree, message_tvb, offset,
				       CIRC_GRP_SV_MSG_TYPE_LENGTH,
				       "Circuit group supervision message type");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));		
  actual_length = tvb_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(CIRC_GRP_SV_MSG_TYPE_LENGTH, actual_length), CIRC_GRP_SV_MSG_TYPE_LENGTH);
  dissect_isup_circuit_group_supervision_message_type_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += CIRC_GRP_SV_MSG_TYPE_LENGTH;
  
  /* Do stuff for mandatory variable parameter range and status*/
  parameter_type =  PARAM_TYPE_RANGE_AND_STATUS;

  parameter_pointer = tvb_get_guint8(message_tvb, offset);
  parameter_length = tvb_get_guint8(message_tvb, offset + parameter_pointer);

  parameter_item = proto_tree_add_text(isup_tree, message_tvb,
				       offset +  parameter_pointer,
				       parameter_length + PARAMETER_LENGTH_IND_LENGTH,
				       "Facility indicator");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));	
  proto_tree_add_uint_format(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset, PARAMETER_POINTER_LENGTH, parameter_pointer, "Pointer to Parameter: %u", parameter_pointer);  
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer, PARAMETER_LENGTH_IND_LENGTH, parameter_length, "Parameter length: %u", parameter_length);
  actual_length = tvb_length_remaining(message_tvb, offset); 	       
  parameter_tvb = tvb_new_subset(message_tvb, offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH, MIN(parameter_length, actual_length), parameter_length );
  dissect_isup_facility_ind_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += PARAMETER_POINTER_LENGTH;

  return offset;
}

/* ------------------------------------------------------------------
  Dissector Message Type Facility request/accepted
 */
gint
dissect_isup_facility_request_accepted_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  tvbuff_t *parameter_tvb;
  gint offset = 0;
  gint parameter_type, actual_length;
 
  /* Do stuff for first mandatory fixed parameter: facility indicators*/ 
  parameter_type = PARAM_TYPE_FACILITY_IND;
  parameter_item = proto_tree_add_text(isup_tree, message_tvb, offset,
				       FACILITY_IND_LENGTH,
				       "Facility indicator");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));		
  actual_length = tvb_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(FACILITY_IND_LENGTH, actual_length), FACILITY_IND_LENGTH);
  dissect_isup_facility_ind_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += FACILITY_IND_LENGTH;
  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type Facility reject
 */
gint
dissect_isup_facility_reject_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  tvbuff_t *parameter_tvb;
  gint offset = 0;
  gint parameter_type, parameter_pointer, parameter_length, actual_length;
 
  /* Do stuff for first mandatory fixed parameter: facility indicators*/ 
  parameter_type = PARAM_TYPE_FACILITY_IND;
  parameter_item = proto_tree_add_text(isup_tree, message_tvb, offset,
				       FACILITY_IND_LENGTH,
				       "Facility indicator");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));		
  actual_length = tvb_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(FACILITY_IND_LENGTH, actual_length), FACILITY_IND_LENGTH);
  dissect_isup_facility_ind_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += FACILITY_IND_LENGTH;

  /* Do stuff for mandatory variable parameter Cause indicators */
  parameter_type =  PARAM_TYPE_CAUSE_INDICATORS;

  parameter_pointer = tvb_get_guint8(message_tvb, offset);
  parameter_length = tvb_get_guint8(message_tvb, offset + parameter_pointer);

  parameter_item = proto_tree_add_text(isup_tree, message_tvb,
				       offset +  parameter_pointer,
				       parameter_length + PARAMETER_LENGTH_IND_LENGTH,
				       "Cause indicators, see Q.850");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));	
  proto_tree_add_uint_format(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset, PARAMETER_POINTER_LENGTH, parameter_pointer, "Pointer to Parameter: %u", parameter_pointer);  
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer, PARAMETER_LENGTH_IND_LENGTH, parameter_length, "Parameter length: %u", parameter_length);
  actual_length = tvb_length_remaining(message_tvb, offset); 	       
  parameter_tvb = tvb_new_subset(message_tvb, offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH, MIN(parameter_length, actual_length), parameter_length );
  dissect_isup_cause_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += PARAMETER_POINTER_LENGTH;

  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type Circuit group reset acknowledgement message 
 */
gint 
dissect_isup_circuit_group_reset_acknowledgement_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  tvbuff_t *parameter_tvb;
  gint offset = 0;
  gint parameter_type, parameter_pointer, parameter_length, actual_length;
  
  /* Do stuff for mandatory variable parameter range and status*/
  parameter_type =  PARAM_TYPE_RANGE_AND_STATUS;

  parameter_pointer = tvb_get_guint8(message_tvb, offset);
  parameter_length = tvb_get_guint8(message_tvb, offset + parameter_pointer);

  parameter_item = proto_tree_add_text(isup_tree, message_tvb,
				       offset +  parameter_pointer,
				       parameter_length + PARAMETER_LENGTH_IND_LENGTH,
				       "Range and status");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));	
  proto_tree_add_uint_format(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset, PARAMETER_POINTER_LENGTH, parameter_pointer, "Pointer to Parameter: %u", parameter_pointer);  
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer, PARAMETER_LENGTH_IND_LENGTH, parameter_length, "Parameter length: %u", parameter_length);
  actual_length = tvb_length_remaining(message_tvb, offset); 	       
  parameter_tvb = tvb_new_subset(message_tvb, offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH, MIN(parameter_length, actual_length), parameter_length );
  dissect_isup_range_and_status_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += PARAMETER_POINTER_LENGTH;

  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type Circuit group query response message
 */
gint 
dissect_isup_circuit_group_query_response_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  tvbuff_t *parameter_tvb;
  gint offset = 0;
  gint parameter_type, parameter_pointer, parameter_length, actual_length;
  
  /* Do stuff for 1. mandatory variable parameter range and status*/
  parameter_type =  PARAM_TYPE_RANGE_AND_STATUS;

  parameter_pointer = tvb_get_guint8(message_tvb, offset);
  parameter_length = tvb_get_guint8(message_tvb, offset + parameter_pointer);

  parameter_item = proto_tree_add_text(isup_tree, message_tvb,
				       offset +  parameter_pointer,
				       parameter_length + PARAMETER_LENGTH_IND_LENGTH,
				       "Range and status");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));	
  proto_tree_add_uint_format(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset, PARAMETER_POINTER_LENGTH, parameter_pointer, "Pointer to Parameter: %u", parameter_pointer);  
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer, PARAMETER_LENGTH_IND_LENGTH, parameter_length, "Parameter length: %u", parameter_length);
  actual_length = tvb_length_remaining(message_tvb, offset); 	       
  parameter_tvb = tvb_new_subset(message_tvb, offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH, MIN(parameter_length, actual_length), parameter_length );
  dissect_isup_range_and_status_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += PARAMETER_POINTER_LENGTH;

  /* Do stuff for 2. mandatory variable parameter Circuit state indicator*/
  parameter_type = PARAM_TYPE_CIRC_STATE_IND;

  parameter_pointer = tvb_get_guint8(message_tvb, offset);
  parameter_length = tvb_get_guint8(message_tvb, offset + parameter_pointer);

  parameter_item = proto_tree_add_text(isup_tree, message_tvb,
				       offset +  parameter_pointer,
				       parameter_length + PARAMETER_LENGTH_IND_LENGTH,
				       "Circuit state indicator (national use)");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));	
  proto_tree_add_uint_format(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset, PARAMETER_POINTER_LENGTH, parameter_pointer, "Pointer to Parameter: %u", parameter_pointer);  
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer, PARAMETER_LENGTH_IND_LENGTH, parameter_length, "Parameter length: %u", parameter_length);
  actual_length = tvb_length_remaining(message_tvb, offset); 	       
  parameter_tvb = tvb_new_subset(message_tvb, offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH, MIN(parameter_length, actual_length), parameter_length );
  dissect_isup_circuit_state_ind_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += PARAMETER_POINTER_LENGTH;

  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type Call Progress
*/
gint
dissect_isup_call_progress_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  tvbuff_t *parameter_tvb;
  gint offset = 0;
  gint parameter_type, actual_length;
 
  /* Do stuff for first mandatory fixed parameter: Event information*/ 
  parameter_type = PARAM_TYPE_EVENT_INFO;
  parameter_item = proto_tree_add_text(isup_tree, message_tvb, offset,
				       EVENT_INFO_LENGTH,
				       "Event information");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));		
  actual_length = tvb_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(EVENT_INFO_LENGTH, actual_length), EVENT_INFO_LENGTH);
  dissect_isup_event_information_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += EVENT_INFO_LENGTH;
  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type User-to-User information
 */
gint 
dissect_isup_user_to_user_information_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  tvbuff_t *parameter_tvb;
  gint offset = 0;
  gint parameter_type, parameter_pointer, parameter_length, actual_length;
  
  /* Do stuff for mandatory variable parameter User-to-user information*/
  parameter_type =  PARAM_TYPE_USER_TO_USER_INFO;

  parameter_pointer = tvb_get_guint8(message_tvb, offset);
  parameter_length = tvb_get_guint8(message_tvb, offset + parameter_pointer);

  parameter_item = proto_tree_add_text(isup_tree, message_tvb,
				       offset +  parameter_pointer,
				       parameter_length + PARAMETER_LENGTH_IND_LENGTH,
				       "User-to-user information, see Q.931");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));	
  proto_tree_add_uint_format(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset, PARAMETER_POINTER_LENGTH, parameter_pointer, "Pointer to Parameter: %u", parameter_pointer);  
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer, PARAMETER_LENGTH_IND_LENGTH, parameter_length, "Parameter length: %u", parameter_length);
  actual_length = tvb_length_remaining(message_tvb, offset); 	       
  parameter_tvb = tvb_new_subset(message_tvb, offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH, MIN(parameter_length, actual_length), parameter_length );
  dissect_isup_user_to_user_information_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += PARAMETER_POINTER_LENGTH;

  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type Confusion  
 */
gint 
dissect_isup_confusion_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  tvbuff_t *parameter_tvb;
  gint offset = 0;
  gint parameter_type, parameter_pointer, parameter_length, actual_length;
  
  /* Do stuff for mandatory variable parameter Cause indicators */
  parameter_type =  PARAM_TYPE_CAUSE_INDICATORS;

  parameter_pointer = tvb_get_guint8(message_tvb, offset);
  parameter_length = tvb_get_guint8(message_tvb, offset + parameter_pointer);

  parameter_item = proto_tree_add_text(isup_tree, message_tvb,
				       offset +  parameter_pointer,
				       parameter_length + PARAMETER_LENGTH_IND_LENGTH,
				       "Cause indicators, see Q.850");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type, "Mandatory Parameter: %u (%s)", parameter_type, val_to_str(parameter_type, isup_parameter_type_value,"unknown"));	
  proto_tree_add_uint_format(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset, PARAMETER_POINTER_LENGTH, parameter_pointer, "Pointer to Parameter: %u", parameter_pointer);  
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer, PARAMETER_LENGTH_IND_LENGTH, parameter_length, "Parameter length: %u", parameter_length);
  actual_length = tvb_length_remaining(message_tvb, offset); 	       
  parameter_tvb = tvb_new_subset(message_tvb, offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH, MIN(parameter_length, actual_length), parameter_length );
  dissect_isup_cause_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += PARAMETER_POINTER_LENGTH;

  return offset;
}
/* ------------------------------------------------------------------ */
void
dissect_isup_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *isup_tree)
{ 
  tvbuff_t *parameter_tvb;
  tvbuff_t *optional_parameter_tvb;
  proto_item* pass_along_item;
  proto_tree* pass_along_tree;
  gint offset, bufferlength;
  guint8 message_type, opt_parameter_pointer;
  gint opt_part_possible = FALSE; /* default setting - for message types allowing optional 
				     params explicitely set to TRUE in case statement */
  offset = 0;
  
  /* Extract message type field */
  message_type = tvb_get_guint8(message_tvb,0); 

  if (check_col(pinfo->fd, COL_INFO)){
    col_append_str(pinfo->fd, COL_INFO, val_to_str(message_type, isup_message_type_value, "reserved"));
    col_append_str(pinfo->fd, COL_INFO, " ");
  }
 
   proto_tree_add_uint_format(isup_tree, hf_isup_message_type, message_tvb, 0, MESSAGE_TYPE_LENGTH, message_type, "Message type: %s (%u)", val_to_str(message_type, isup_message_type_value, "reserved"), message_type);
   offset +=  MESSAGE_TYPE_LENGTH;

   bufferlength = tvb_length_remaining(message_tvb, offset);
   parameter_tvb = tvb_new_subset(message_tvb, offset, bufferlength, bufferlength);

   /* distinguish between message types:*/
   switch (message_type) {
     case MESSAGE_TYPE_INITIAL_ADDR:
       offset += dissect_isup_initial_address_message(parameter_tvb, isup_tree);
       opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_SUBSEQ_ADDR:
       offset += dissect_isup_subsequent_address_message(parameter_tvb, isup_tree);
       opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_INFO_REQ:
       offset += dissect_isup_information_request_message(parameter_tvb, isup_tree);
       opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_INFO:
       offset += dissect_isup_information_message(parameter_tvb, isup_tree);
       opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_CONTINUITY:
       offset += dissect_isup_continuity_message(parameter_tvb, isup_tree);
      break;
    case MESSAGE_TYPE_ADDR_CMPL:
       offset += dissect_isup_address_complete_message(parameter_tvb, isup_tree);
       opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_CONNECT:
       offset += dissect_isup_connect_message(parameter_tvb, isup_tree);
       opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_FORW_TRANS:
      /* no dissector necessary since no mandatory parameters included */
       opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_ANSWER:
      /* no dissector necessary since no mandatory parameters included */
       opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_RELEASE:
       offset += dissect_isup_release_message(parameter_tvb, isup_tree);
       opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_SUSPEND:
       offset += dissect_isup_suspend_resume_message(parameter_tvb, isup_tree);
       opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_RESUME:
       offset += dissect_isup_suspend_resume_message(parameter_tvb, isup_tree);
       opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_REL_CMPL:
      /* no dissector necessary since no mandatory parameters included */
       opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_CONT_CHECK_REQ:
      /* no dissector necessary since no mandatory parameters included */
      break;
    case MESSAGE_TYPE_RESET_CIRCUIT:
      /* no dissector necessary since no mandatory parameters included */
      break;
    case MESSAGE_TYPE_BLOCKING:
      /* no dissector necessary since no mandatory parameters included */
      break;
    case MESSAGE_TYPE_UNBLOCKING:
      /* no dissector necessary since no mandatory parameters included */
      break;
    case MESSAGE_TYPE_BLOCK_ACK:
      /* no dissector necessary since no mandatory parameters included */
      break;
    case MESSAGE_TYPE_UNBLOCK_ACK:
      /* no dissector necessary since no mandatory parameters included */
      break;
    case MESSAGE_TYPE_CIRC_GRP_RST:
       offset += dissect_isup_circuit_group_reset_query_message(parameter_tvb, isup_tree);
      break;
    case MESSAGE_TYPE_CIRC_GRP_BLCK:
       offset += dissect_isup_circuit_group_blocking_messages(parameter_tvb, isup_tree);
      break;
    case MESSAGE_TYPE_CIRC_GRP_UNBL:
       offset += dissect_isup_circuit_group_blocking_messages(parameter_tvb, isup_tree);
      break;
    case MESSAGE_TYPE_CIRC_GRP_BL_ACK:
       offset += dissect_isup_circuit_group_blocking_messages(parameter_tvb, isup_tree);
      break;
    case MESSAGE_TYPE_CIRC_GRP_UNBL_ACK:
       offset += dissect_isup_circuit_group_blocking_messages(parameter_tvb, isup_tree);
      break;
    case MESSAGE_TYPE_FACILITY_REQ:
       offset += dissect_isup_facility_request_accepted_message(parameter_tvb, isup_tree);
       opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_FACILITY_ACC:
       offset += dissect_isup_facility_request_accepted_message(parameter_tvb, isup_tree);
       opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_FACILITY_REJ:
       offset += dissect_isup_facility_reject_message(parameter_tvb, isup_tree);
       opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_LOOP_BACK_ACK:
      /* no dissector necessary since no mandatory parameters included */
      break;
    case MESSAGE_TYPE_PASS_ALONG:
      /* call dissect_isup_message recursively */
      {	guint8 pa_message_type;
	pa_message_type = tvb_get_guint8(parameter_tvb, 0);
	pass_along_item = proto_tree_add_text(isup_tree, parameter_tvb, offset, tvb_length_remaining(parameter_tvb, offset), "Pass-along: %s Message (%u)", val_to_str(pa_message_type, isup_message_type_value, "reserved"), pa_message_type);
	pass_along_tree = proto_item_add_subtree(pass_along_item, ett_isup_pass_along_message);
	dissect_isup_message(parameter_tvb, pinfo, pass_along_tree);
	break;
      }
    case MESSAGE_TYPE_CIRC_GRP_RST_ACK:
       offset += dissect_isup_circuit_group_reset_acknowledgement_message(parameter_tvb, isup_tree);
      break;
    case MESSAGE_TYPE_CIRC_GRP_QRY:
       offset += dissect_isup_circuit_group_reset_query_message(parameter_tvb, isup_tree);
      break;
    case MESSAGE_TYPE_CIRC_GRP_QRY_RSP:
       offset += dissect_isup_circuit_group_query_response_message(parameter_tvb, isup_tree);
      break;
    case MESSAGE_TYPE_CALL_PROGRSS:
       offset += dissect_isup_call_progress_message(parameter_tvb, isup_tree);
       opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_USER2USER_INFO:
      offset += dissect_isup_user_to_user_information_message(parameter_tvb, isup_tree);
      opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_UNEQUIPPED_CIC:
      /* no dissector necessary since no mandatory parameters included */
      break;
    case MESSAGE_TYPE_CONFUSION:
      offset += dissect_isup_confusion_message(parameter_tvb, isup_tree);
       opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_OVERLOAD:
      /* no dissector necessary since no mandatory parameters included */
      break;
    case MESSAGE_TYPE_CHARGE_INFO:
      /* do nothing since format is a national matter */
      proto_tree_add_text(isup_tree, parameter_tvb, 0, bufferlength, "Format is a national matter"); 
      break;
    case MESSAGE_TYPE_NETW_RESRC_MGMT:
      /* no dissector necessary since no mandatory parameters included */
       opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_FACILITY:
      /* no dissector necessary since no mandatory parameters included */
       opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_USER_PART_TEST:
      /* no dissector necessary since no mandatory parameters included */
       opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_USER_PART_AVAIL:
      /* no dissector necessary since no mandatory parameters included */
       opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_IDENT_REQ:
      /* no dissector necessary since no mandatory parameters included */
       opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_IDENT_RSP:
      /* no dissector necessary since no mandatory parameters included */
       opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_SEGMENTATION:
      /* no dissector necessary since no mandatory parameters included */
       opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_LOOP_PREVENTION:
      /* no dissector necessary since no mandatory parameters included */
       opt_part_possible = TRUE;
      break;
    default:
      proto_tree_add_text(isup_tree, parameter_tvb, 0, bufferlength, "Unknown Message type (possibly reserved/used in former ISUP version)");
      break;
  }
   
   /* extract pointer to start of optional part (if any) */
   if (opt_part_possible == TRUE){
     opt_parameter_pointer = tvb_get_guint8(message_tvb, offset);
     if (opt_parameter_pointer > 0){
       proto_tree_add_uint_format(isup_tree, hf_isup_pointer_to_start_of_optional_part, message_tvb, offset, PARAMETER_POINTER_LENGTH, opt_parameter_pointer, "Pointer to start of optional part: %u", opt_parameter_pointer);  
       offset += opt_parameter_pointer;
       optional_parameter_tvb = tvb_new_subset(message_tvb, offset, -1, -1 );
       dissect_isup_optional_parameter(optional_parameter_tvb, isup_tree);
     }
     else
       proto_tree_add_uint_format(isup_tree, hf_isup_pointer_to_start_of_optional_part, message_tvb, offset, PARAMETER_POINTER_LENGTH, opt_parameter_pointer, "No optional parameter present (Pointer: %u)", opt_parameter_pointer);  
   }
   else if (message_type !=MESSAGE_TYPE_CHARGE_INFO)
     proto_tree_add_text(isup_tree, message_tvb, 0, 0, "No optional parameters are possible with this message type");  
    
}
 
/* ------------------------------------------------------------------ */
void
dissect_isup(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *isup_tree;
	tvbuff_t *message_tvb;
	guint16 cic; 

/* Make entries in Protocol column and Info column on summary display */
	if (check_col(pinfo->fd, COL_PROTOCOL)) 
		col_set_str(pinfo->fd, COL_PROTOCOL, "ISUP");

	if (check_col(pinfo->fd, COL_INFO)) 
		col_add_str(pinfo->fd, COL_INFO, "ISUP message: ");

/* In the interest of speed, if "tree" is NULL, don't do any work not
   necessary to generate protocol tree items. */
	if (tree) {
		ti = proto_tree_add_item(tree, proto_isup, tvb, 0, tvb_length(tvb), FALSE);
		isup_tree = proto_item_add_subtree(ti, ett_isup);

		/* dissect CIC in main dissector since pass-along message type carrying complete IUSP message w/o CIC needs 
		   recursive message dissector call */
		cic =          tvb_get_letohs(tvb, CIC_OFFSET) & 0x0FFF; /*since upper 4 bits spare */ 
		
		proto_tree_add_uint_format(isup_tree, hf_isup_cic, tvb, CIC_OFFSET, CIC_LENGTH, cic, "CIC: %u", cic);  

		message_tvb = tvb_new_subset(tvb, CIC_LENGTH, -1, -1);
		dissect_isup_message(message_tvb, pinfo, isup_tree);
	}
}


/*---------------------------------------------------------------------*/
/* Register the protocol with Ethereal */
void
proto_register_isup(void)
{                 
/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_isup_cic,
			{ "CIC",           "isup.cic",
			FT_UINT16, BASE_HEX, NULL, 0xFF0F,          
			  "", HFILL }}, 

		{ &hf_isup_message_type,
			{ "Message Type",  "isup.message_type",
			FT_UINT8, BASE_DEC, NULL, 0x0,          
			"", HFILL }},
			
		{ &hf_isup_parameter_type,
			{ "Parameter Type",  "isup.parameter_type",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }},
			
		{ &hf_isup_parameter_length,
			{ "Parameter Length",  "isup.parameter_length",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }},
			
		{ &hf_isup_mandatory_variable_parameter_pointer,
			{ "Pointer to Parameter",  "isup.mandatory_variable_parameter_pointer",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_isup_pointer_to_start_of_optional_part,
			{ "Pointer to optional parameter part",  "isup.optional_parameter_part_pointer",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_isup_satellite_indicator,
			{ "Satellite Indicator",  "isup.satellite_indicator",
			FT_UINT8, BASE_HEX, VALS(isup_satellite_ind_value), BA_8BIT_MASK,
			"", HFILL }},

		{ &hf_isup_continuity_check_indicator,
			{ "Continuity Check Indicator",  "isup.continuity_check_indicator",
			FT_UINT8, BASE_HEX, VALS(isup_continuity_check_ind_value), DC_8BIT_MASK,
			"", HFILL }},

		{ &hf_isup_echo_control_device_indicator,
			{ "Echo Control Device Indicator",  "isup.echo_control_device_indicator",
			FT_BOOLEAN, 8, TFS(&isup_echo_control_device_ind_value),E_8BIT_MASK,
			"", HFILL }},

		{ &hf_isup_forw_call_natnl_inatnl_call_indicator,
			{ "National/international call indicator",  "isup.forw_call_natnl_inatnl_call_indicator",
			FT_BOOLEAN, 16, TFS(&isup_natnl_inatnl_call_ind_value),A_16BIT_MASK,
			"", HFILL }},

		{ &hf_isup_forw_call_end_to_end_method_indicator,
			{ "End-to-end method indicator",  "isup.forw_call_end_to_end_method_indicator",
			FT_UINT16, BASE_HEX, VALS(isup_end_to_end_method_ind_value), CB_16BIT_MASK,
			"", HFILL }},

		{ &hf_isup_forw_call_interworking_indicator,
			{ "Interworking indicator",  "isup.forw_call_interworking_indicator",
			FT_BOOLEAN, 16, TFS(&isup_interworking_ind_value), D_16BIT_MASK,
			"", HFILL }},

		{ &hf_isup_forw_call_end_to_end_info_indicator,
			{ "End-to-end information indicator",  "isup.forw_call_end_to_end_information_indicator",
			FT_BOOLEAN, 16, TFS(&isup_end_to_end_info_ind_value), E_16BIT_MASK,
			"", HFILL }},

		{ &hf_isup_forw_call_isdn_user_part_indicator,
			{ "ISDN user part indicator",  "isup.forw_call_isdn_user_part_indicator",
			FT_BOOLEAN, 16, TFS(&isup_ISDN_user_part_ind_value), F_16BIT_MASK,
			"", HFILL }},

		{ &hf_isup_forw_call_preferences_indicator,
			{ "ISDN user part preference indicator",  "isup.forw_call_preferences_indicator",
			FT_UINT16, BASE_HEX, VALS(isup_preferences_ind_value), HG_16BIT_MASK,
			"", HFILL }},

		{ &hf_isup_forw_call_isdn_access_indicator,
			{ "ISDN access indicator",  "isup.forw_call_isdn_access_indicator",
			FT_BOOLEAN, 16, TFS(&isup_ISDN_originating_access_ind_value), I_16BIT_MASK,
			"", HFILL }},

		{ &hf_isup_forw_call_sccp_method_indicator,
			{ "SCCP method indicator",  "isup.forw_call_sccp_method_indicator",
			FT_UINT16, BASE_HEX, VALS(isup_SCCP_method_ind_value), KJ_16BIT_MASK,
			"", HFILL }},
							
		{ &hf_isup_calling_partys_category,
			{ "Calling Party's category",  "isup.calling_partys_category",
			FT_UINT8, BASE_HEX, VALS(isup_calling_partys_category_value), 0x0,
			"", HFILL }},
		
		{ &hf_isup_transmission_medium_requirement,
			{ "Transmission medium requirement",  "isup.transmission_medium_requirement",
			FT_UINT8, BASE_DEC, VALS(isup_transmission_medium_requirement_value), 0x0,
			"", HFILL }},

		{ &hf_isup_odd_even_indicator,
			{ "Odd/even indicator",  "isup.isdn_odd_even_indicator",
			FT_BOOLEAN, 8, TFS(&isup_odd_even_ind_value), ISUP_ODD_EVEN_MASK,
			"", HFILL }},

		{ &hf_isup_called_party_nature_of_address_indicator,
			{ "Nature of address indicator",  "isup.called_party_nature_of_address_indicator",
			FT_UINT8, BASE_DEC, VALS(isup_called_party_nature_of_address_ind_value), ISUP_NATURE_OF_ADDRESS_IND_MASK,
			"", HFILL }},
					
		{ &hf_isup_calling_party_nature_of_address_indicator,
			{ "Nature of address indicator",  "isup.calling_party_nature_of_address_indicator",
			FT_UINT8, BASE_DEC, VALS(isup_calling_party_nature_of_address_ind_value), ISUP_NATURE_OF_ADDRESS_IND_MASK,
			"", HFILL }},
					
		{ &hf_isup_inn_indicator,
			{ "INN indicator",  "isup.inn_indicator",
			FT_BOOLEAN, 8, TFS(&isup_INN_ind_value), ISUP_INN_MASK,
			"", HFILL }},

		{ &hf_isup_ni_indicator,
			{ "NI indicator",  "isup.ni_indicator",
			FT_BOOLEAN, 8, TFS(&isup_NI_ind_value), ISUP_NI_MASK,
			"", HFILL }},

		{ &hf_isup_numbering_plan_indicator,
			{ "Numbering plan indicator",  "isup.numbering_plan_indicator",
			FT_UINT8, BASE_DEC, VALS(isup_numbering_plan_ind_value), ISUP_NUMBERING_PLAN_IND_MASK,
			"", HFILL }},

		{ &hf_isup_address_presentation_restricted_indicator,
			{ "Address presentation restricted indicator",  "isup.address_presentation_restricted_indicator",
			FT_UINT8, BASE_DEC, VALS(isup_address_presentation_restricted_ind_value), ISUP_ADDRESS_PRESENTATION_RESTR_IND_MASK,
			"", HFILL }},

		{ &hf_isup_screening_indicator,
			{ "Screening indicator",  "isup.screening_indicator",
			FT_UINT8, BASE_DEC, VALS(isup_screening_ind_value), ISUP_SCREENING_IND_MASK,
			"", HFILL }},

		{ &hf_isup_screening_indicator_enhanced,
			{ "Screening indicator",  "isup.screening_indicator_enhanced",
			FT_UINT8, BASE_DEC, VALS(isup_screening_ind_enhanced_value), ISUP_SCREENING_IND_MASK,
			"", HFILL }},

		{ &hf_isup_called_party_odd_address_signal_digit,
			{ "Address signal digit",  "isup.called_party_odd_address_signal_digit",
			FT_UINT8, BASE_DEC, VALS(isup_called_party_address_digit_value), ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK,
			"", HFILL }},

		{ &hf_isup_calling_party_odd_address_signal_digit,
			{ "Address signal digit",  "isup.calling_party_odd_address_signal_digit",
			FT_UINT8, BASE_DEC, VALS(isup_calling_party_address_digit_value), ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK,
			"", HFILL }},

		{ &hf_isup_called_party_even_address_signal_digit,
			{ "Address signal digit",  "isup.called_party_even_address_signal_digit",
			FT_UINT8, BASE_DEC, VALS(isup_called_party_address_digit_value), ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK,
			"", HFILL }},
					
		{ &hf_isup_calling_party_even_address_signal_digit,
			{ "Address signal digit",  "isup.calling_party_even_address_signal_digit",
			FT_UINT8, BASE_DEC, VALS(isup_calling_party_address_digit_value), ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK,
			"", HFILL }},
					
		{ &hf_isup_calling_party_address_request_indicator,
			{ "Calling party address request indicator",  "isup.calling_party_address_request_indicator",
			FT_BOOLEAN, 16, TFS(&isup_calling_party_address_request_ind_value), A_16BIT_MASK,
			"", HFILL }},
					
		{ &hf_isup_info_req_holding_indicator,
			{ "Holding indicator",  "isup.info_req_holding_indicator",
			FT_BOOLEAN, 16, TFS(&isup_holding_ind_value), B_16BIT_MASK,
			"", HFILL }},
					
		{ &hf_isup_calling_partys_category_request_indicator,
			{ "Calling party's category request indicator",  "isup.calling_partys_category_request_indicator",
			FT_BOOLEAN, 16, TFS(&isup_calling_partys_category_request_ind_value), D_16BIT_MASK,
			"", HFILL }},
					
		{ &hf_isup_charge_information_request_indicator,
			{ "Charge information request indicator",  "isup.charge_information_request_indicator",
			FT_BOOLEAN, 16, TFS(&isup_charge_information_request_ind_value), E_16BIT_MASK,
			"", HFILL }},
					
		{ &hf_isup_malicious_call_identification_request_indicator,
			{ "Malicious call identification request indicator (ISUP'88)",  "isup.malicious_call_ident_request_indicator",
			FT_BOOLEAN, 16, TFS(&isup_malicious_call_identification_request_ind_value), H_16BIT_MASK,
			"", HFILL }},

		{ &hf_isup_calling_party_address_response_indicator,
			{ "Calling party address response indicator",  "isup.calling_party_address_response_indicator",
			FT_UINT16, BASE_HEX, VALS(isup_calling_party_address_response_ind_value), BA_16BIT_MASK,
			"", HFILL }},
					
		{ &hf_isup_hold_provided_indicator,
			{ "Hold provided indicator",  "isup.hold_provided_indicator",
			FT_BOOLEAN, 16, TFS(&isup_hold_provided_ind_value), C_16BIT_MASK,
			"", HFILL }},
					
		{ &hf_isup_calling_partys_category_response_indicator,
			{ "Calling party's category response indicator",  "isup.calling_partys_category_response_indicator",
			FT_BOOLEAN, 16, TFS(&isup_calling_partys_category_response_ind_value), F_16BIT_MASK,
			"", HFILL }},
					
		{ &hf_isup_charge_information_response_indicator,
			{ "Charge information response indicator",  "isup.charge_information_response_indicator",
			FT_BOOLEAN, 16, TFS(&isup_charge_information_response_ind_value), G_16BIT_MASK,
			"", HFILL }},
					
		{ &hf_isup_solicited_indicator,
			{ "Solicited indicator",  "isup.solicided_indicator",
			FT_BOOLEAN, 16, TFS(&isup_solicited_information_ind_value), H_16BIT_MASK,
			"", HFILL }},

		{ &hf_isup_continuity_indicator,
			{ "Continuity indicator",  "isup.continuity_indicator",
			FT_BOOLEAN, 8, TFS(&isup_continuity_ind_value), A_8BIT_MASK,
			"", HFILL }},

		{ &hf_isup_backw_call_charge_ind,
			{ "Charge indicator",  "isup.charge_indicator",
			FT_UINT16, BASE_HEX, VALS(isup_charge_ind_value), BA_16BIT_MASK,
			"", HFILL }},

		{ &hf_isup_backw_call_called_partys_status_ind,
			{ "Called party's status indicator",  "isup.called_partys_status_indicator",
			FT_UINT16, BASE_HEX, VALS(isup_called_partys_status_ind_value), DC_16BIT_MASK,
			"", HFILL }},

		{ &hf_isup_backw_call_called_partys_category_ind,
			{ "Called party's category indicator",  "isup.called_partys_category_indicator",
			FT_UINT16, BASE_HEX, VALS(isup_called_partys_category_ind_value), FE_16BIT_MASK,
			"", HFILL }},

		{ &hf_isup_backw_call_end_to_end_method_ind,
			{ "End-to-end method indicator",  "isup.backw_call_end_to_end_method_indicator",
			FT_UINT16, BASE_HEX, VALS(isup_end_to_end_method_ind_value), HG_16BIT_MASK,
			"", HFILL }},

		{ &hf_isup_backw_call_interworking_ind,
			{ "Interworking indicator",  "isup.backw_call_interworking_indicator",
			FT_BOOLEAN, 16, TFS(&isup_interworking_ind_value), I_16BIT_MASK,
			"", HFILL }},

		{ &hf_isup_backw_call_end_to_end_info_ind,
			{ "End-to-end information indicator",  "isup.backw_call_end_to_end_information_indicator",
			FT_BOOLEAN, 16, TFS(&isup_end_to_end_info_ind_value), J_16BIT_MASK,
			"", HFILL }},

		{ &hf_isup_backw_call_isdn_user_part_ind,
			{ "ISDN user part indicator",  "isup.backw_call_isdn_user_part_indicator",
			FT_BOOLEAN, 16, TFS(&isup_ISDN_user_part_ind_value), K_16BIT_MASK,
			"", HFILL }},

		{ &hf_isup_backw_call_holding_ind,
			{ "Holding indicator",  "isup.backw_call_holding_indicator",
			FT_BOOLEAN, 16, TFS(&isup_holding_ind_value), L_16BIT_MASK,
			"", HFILL }},
					
		{ &hf_isup_backw_call_isdn_access_ind,
			{ "ISDN access indicator",  "isup.backw_call_isdn_access_indicator",
			FT_BOOLEAN, 16, TFS(&isup_ISDN_terminating_access_ind_value), M_16BIT_MASK,
			"", HFILL }},

		{ &hf_isup_backw_call_echo_control_device_ind,
			{ "Echo Control Device Indicator",  "isup.backw_call_echo_control_device_indicator",
			FT_BOOLEAN, 16, TFS(&isup_echo_control_device_ind_value), N_16BIT_MASK,
			"", HFILL }},

		{ &hf_isup_backw_call_sccp_method_ind,
			{ "SCCP method indicator",  "isup.backw_call_sccp_method_indicator",
			FT_UINT16, BASE_HEX, VALS(isup_SCCP_method_ind_value), PO_16BIT_MASK,
			"", HFILL }},
							
		{ &hf_isup_suspend_resume_indicator,
			{ "Suspend/Resume indicator",  "isup.suspend_resume_indicator",
			FT_BOOLEAN, 8, TFS(&isup_suspend_resume_ind_value), A_8BIT_MASK,
			"", HFILL }},
					
		{ &hf_isup_transmission_medium_requirement,
			{ "Transmission medium requirement",  "isup.transmission_medium_requirement",
			FT_UINT8, BASE_DEC, VALS(isup_transmission_medium_requirement_value), 0x0,
			"", HFILL }},

		{ &hf_isup_range_indicator,
		        { "Range indicator",  "isup.range_indicator",
			  FT_UINT8, BASE_DEC, NULL , 0x0,
			  "", HFILL }},

		{ &hf_isup_cgs_message_type,
			{ "Circuit group supervision message type",  "isup.cgs_message_type",
			FT_UINT8, BASE_DEC, VALS(isup_cgs_message_type_value), BA_8BIT_MASK,
			"", HFILL }},

		{ &hf_isup_mtc_blocking_state1,
			{ "Maintenance blocking state",  "isup.mtc_blocking_state",
			FT_UINT8, BASE_DEC, VALS(isup_mtc_blocking_state_DC00_value), BA_8BIT_MASK,
			"", HFILL }},

		{ &hf_isup_mtc_blocking_state2,
			{ "Maintenance blocking state",  "isup.mtc_blocking_state",
			FT_UINT8, BASE_DEC, VALS(isup_mtc_blocking_state_DCnot00_value), BA_8BIT_MASK,
			"", HFILL }},
	
		{ &hf_isup_call_proc_state,
			{ "Call processing state",  "isup.call_processing_state",
			FT_UINT8, BASE_DEC, VALS(isup_call_processing_state_value), DC_8BIT_MASK,
			"", HFILL }},
	
		{ &hf_isup_hw_blocking_state,
			{ "HW blocking state",  "isup.hw_blocking_state",
			FT_UINT8, BASE_DEC, VALS(isup_HW_blocking_state_value), FE_8BIT_MASK,
			"", HFILL }},
							
		{ &hf_isup_event_ind,
			{ "Event indicator",  "isup.event_ind",
			  FT_UINT8, 8, NULL, 0x0,
			"", HFILL }},

		{ &hf_isup_event_presentation_restricted_ind,
			{ "Event presentation restricted indicator",  "isup.event_presentatiation_restr_ind",
			FT_BOOLEAN, 8, TFS(&isup_event_presentation_restricted_ind_value), H_8BIT_MASK,
			"", HFILL }},

		{ &hf_isup_cug_call_ind,
		        { "Closed user group call indicator",  "isup.clg_call_ind",
			FT_UINT8, BASE_DEC, VALS(isup_CUG_call_ind_value), BA_8BIT_MASK,
			"", HFILL }},

		{ &hf_isup_simple_segmentation_ind,
			{ "Simple segmentation indicator",  "isup.simple_segmentation_ind",
			FT_BOOLEAN, 8, TFS(&isup_simple_segmentation_ind_value), C_8BIT_MASK,
			"", HFILL }},

		{ &hf_isup_connected_line_identity_request_ind,
			{ "Connected line identity request indicator",  "isup.connected_line_identity_request_ind",
			FT_BOOLEAN, 8, TFS(&isup_connected_line_identity_request_ind_value), H_8BIT_MASK,
			"", HFILL }},

		{ &hf_isup_redirecting_ind,
		        { "Redirection indicator",  "isup.redirecting_ind",
			FT_UINT16, BASE_DEC, VALS(isup_redirecting_ind_value), CBA_16BIT_MASK,
			"", HFILL }},

		{ &hf_isup_original_redirection_reason,
		        { "Original redirection reason",  "isup.original_redirection_reason",
			FT_UINT16, BASE_DEC, VALS(isup_original_redirection_reason_value), HGFE_16BIT_MASK,
			"", HFILL }},

		{ &hf_isup_redirection_counter,
		        { "Redirection counter",  "isup.redirection_counter",
			FT_UINT16, BASE_DEC, NULL, KJI_16BIT_MASK,
			"", HFILL }},

		{ &hf_isup_redirection_reason,
		        { "Redirection reason",  "isup.redirection_reason",
			FT_UINT16, BASE_DEC, VALS(isup_redirection_reason_value), PONM_16BIT_MASK,
			"", HFILL }},

		{ &hf_isup_type_of_network_identification,
		        { "Type of network identification",  "isup.type_of_network_identification",
			FT_UINT8, BASE_DEC, VALS(isup_type_of_network_identification_value), GFE_8BIT_MASK,
			"", HFILL }},

		{ &hf_isup_network_identification_plan,
		        { "Network identification plan",  "isup.network_identification_plan",
			FT_UINT8, BASE_DEC, VALS(isup_network_identification_plan_value), DCBA_8BIT_MASK,
			"", HFILL }},					

		{ &hf_isup_map_type,
		        { "Map Type",  "isup.map_type",
			FT_UINT8, BASE_DEC, VALS(isup_map_type_value), FEDCBA_8BIT_MASK,
			"", HFILL }},
	
		{ &hf_isup_automatic_congestion_level,
		        { "Automatic congestion level",  "isup.automatic_congestion_level",
			FT_UINT8, BASE_DEC, VALS(isup_auto_congestion_level_value), 0x0,
			"", HFILL }},

		{ &hf_isup_inband_information_ind,
			{ "In-band information indicator",  "isup.inband_information_ind",
			FT_BOOLEAN, 8, TFS(&isup_inband_information_ind_value), A_8BIT_MASK,
			"", HFILL }},

		{ &hf_isup_call_diversion_may_occur_ind,
			{ "Call diversion may occur indicator",  "isup.call_diversion_may_occur_ind",
			FT_BOOLEAN, 8, TFS(&isup_call_diversion_may_occur_ind_value), B_8BIT_MASK,
			"", HFILL }},

		{ &hf_isup_mlpp_user_ind,
			{ "MLPP user indicator",  "isup.mlpp_user",
			FT_BOOLEAN, 8, TFS(&isup_MLPP_user_ind_value), D_8BIT_MASK,
			"", HFILL }},
			
		{ &hf_isup_access_delivery_ind,
			{ "Access delivery indicator",  "isup.access_delivery_ind",
			FT_BOOLEAN, 8, TFS(&isup_access_delivery_ind_value), A_8BIT_MASK,
			"", HFILL }},
		
		{ &hf_isup_transmission_medium_requirement_prime,
			{ "Transmission medium requirement prime",  "isup.transmission_medium_requirement_prime",
			FT_UINT8, BASE_DEC, VALS(isup_transmission_medium_requirement_prime_value), 0x0,
			"", HFILL }},
		
		{ &hf_isup_loop_prevention_response_ind,
			{ "Response indicator",  "isup.loop_prevention_response_ind",
			FT_UINT8, BASE_DEC, VALS(isup_loop_prevention_response_ind_value), CB_8BIT_MASK,
			"", HFILL }},
			
		{ &hf_isup_temporary_alternative_routing_ind,
			{ "Temporary alternative routing indicator",  "isup.temporary_alternative_routing_ind",
			FT_BOOLEAN, 8, TFS(&isup_temporary_alternative_routing_ind_value), A_8BIT_MASK,
			"", HFILL }},
				
		{ &hf_isup_extension_ind,
			{ "Extension indicator",  "isup.extension_ind",
			FT_BOOLEAN, 8, TFS(&isup_extension_ind_value), H_8BIT_MASK,
			"", HFILL }},

		{ &hf_isup_call_to_be_diverted_ind,
			{ "Call to be diverted indicator",  "isup.call_to_be_diverted_ind",
			FT_UINT8, BASE_DEC, VALS(isup_call_to_be_diverted_ind_value), BA_8BIT_MASK,
			"", HFILL }},
			
		{ &hf_isup_call_to_be_offered_ind,
			{ "Call to be offered indicator",  "isup.call_to_be_offered_ind",
			FT_UINT8, BASE_DEC, VALS(isup_call_to_be_offered_ind_value), BA_8BIT_MASK,
			"", HFILL }},		
			
		{ &hf_isup_conference_acceptance_ind,
			{ "Conference acceptance indicator",  "isup.conference_acceptance_ind",
			FT_UINT8, BASE_DEC, VALS(isup_conference_acceptance_ind_value), BA_8BIT_MASK,
			"", HFILL }},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_isup,
		&ett_isup_parameter,
		&ett_isup_address_digits,
		&ett_isup_pass_along_message,
		&ett_isup_circuit_state_ind
	};

/* Register the protocol name and description */
	proto_isup = proto_register_protocol("ISDN User Part",
	    "ISUP", "isup");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_isup, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}


/* ------------------------------------------------------------------ */
/* Register isup with the sub-laying MTP L3 dissector */
void
proto_reg_handoff_isup(void)
{
  dissector_add("mtp3.service_indicator", MTP3_ISUP_SERVICE_INDICATOR, dissect_isup, proto_isup);
}
