/* packet-isup.c
 * Routines for ISUP dissection
 * Copyright 2001, Martina Obermeier <martina.obermeier@icn.siemens.de>
 * Modified 2003-09-10 by Anders Broman
 *		<anders.broman@ericsson.com>
 * Inserted routines for BICC dissection according to Q.765.5 Q.1902 Q.1970 Q.1990,
 * calling SDP dissector for RFC2327 decoding.
 * $Id: packet-isup.c,v 1.34 2003/10/14 17:50:01 guy Exp $
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

#include <glib.h>

#include <epan/packet.h>
#include "packet-q931.h"

#define MTP3_ISUP_SERVICE_INDICATOR     5
#define MTP3_BICC_SERVICE_INDICATOR     13
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
#define MESSAGE_TYPE_APPLICATION_TRANS 65
#define MESSAGE_TYPE_PRE_RELEASE_INFO  66
#define MESSAGE_TYPE_SUBSEQUENT_DIR_NUM 67


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
  { MESSAGE_TYPE_APPLICATION_TRANS,	"Application transport"},
  { MESSAGE_TYPE_PRE_RELEASE_INFO,	"Pre-release information"},	
  { MESSAGE_TYPE_SUBSEQUENT_DIR_NUM,	"Subsequent Directory Number (national use)"},

  { 0,                                  NULL}};

/* Same as above but in acronym form (for the Info column) */
static const value_string isup_message_type_value_acro[] = {
  { MESSAGE_TYPE_INITIAL_ADDR,          "IAM"},
  { MESSAGE_TYPE_SUBSEQ_ADDR,           "SAM"},
  { MESSAGE_TYPE_INFO_REQ,              "INR"},
  { MESSAGE_TYPE_INFO,                  "INF"},
  { MESSAGE_TYPE_CONTINUITY,            "COT"},
  { MESSAGE_TYPE_ADDR_CMPL,             "ACM"},
  { MESSAGE_TYPE_CONNECT,               "CON"},
  { MESSAGE_TYPE_FORW_TRANS,            "FOT"},
  { MESSAGE_TYPE_ANSWER,                "ANM"},
  { MESSAGE_TYPE_RELEASE,               "REL"},
  { MESSAGE_TYPE_SUSPEND,               "SUS"},
  { MESSAGE_TYPE_RESUME,                "RES"},
  { MESSAGE_TYPE_REL_CMPL,              "RLC"},
  { MESSAGE_TYPE_CONT_CHECK_REQ,        "CCR"},
  { MESSAGE_TYPE_RESET_CIRCUIT,         "RSC"},
  { MESSAGE_TYPE_BLOCKING,              "BLO"},
  { MESSAGE_TYPE_UNBLOCKING,            "UBL"},
  { MESSAGE_TYPE_BLOCK_ACK,             "BLA"},
  { MESSAGE_TYPE_UNBLOCK_ACK,           "UBLA"},
  { MESSAGE_TYPE_CIRC_GRP_RST,          "GRS"},
  { MESSAGE_TYPE_CIRC_GRP_BLCK,         "CGB"},
  { MESSAGE_TYPE_CIRC_GRP_UNBL,         "CGU"},
  { MESSAGE_TYPE_CIRC_GRP_BL_ACK,       "CGBA"},
  { MESSAGE_TYPE_CIRC_GRP_UNBL_ACK,     "CGUA"},
  { MESSAGE_TYPE_FACILITY_REQ,          "FAR"},
  { MESSAGE_TYPE_FACILITY_ACC,          "FAA"},
  { MESSAGE_TYPE_FACILITY_REJ,          "FRJ"},
  { MESSAGE_TYPE_LOOP_BACK_ACK,         "LPA"},
  { MESSAGE_TYPE_PASS_ALONG,            "PAM"},
  { MESSAGE_TYPE_CIRC_GRP_RST_ACK,      "GRA"},
  { MESSAGE_TYPE_CIRC_GRP_QRY,          "CQM"},
  { MESSAGE_TYPE_CIRC_GRP_QRY_RSP,      "CQR"},
  { MESSAGE_TYPE_CALL_PROGRSS,          "CPG"},
  { MESSAGE_TYPE_USER2USER_INFO,        "UUI"},
  { MESSAGE_TYPE_UNEQUIPPED_CIC,        "UCIC"},
  { MESSAGE_TYPE_CONFUSION,             "CFN"},
  { MESSAGE_TYPE_OVERLOAD,              "OLM"},
  { MESSAGE_TYPE_CHARGE_INFO,           "CRG"},
  { MESSAGE_TYPE_NETW_RESRC_MGMT,       "NRM"},
  { MESSAGE_TYPE_FACILITY,              "FAC"},
  { MESSAGE_TYPE_USER_PART_TEST,        "UPT"},
  { MESSAGE_TYPE_USER_PART_AVAIL,       "UPA"},
  { MESSAGE_TYPE_IDENT_REQ,             "IDR"},
  { MESSAGE_TYPE_IDENT_RSP,             "IDS"},
  { MESSAGE_TYPE_SEGMENTATION,          "SGM"},
  { MESSAGE_TYPE_LOOP_PREVENTION,       "LOP"},
  { MESSAGE_TYPE_APPLICATION_TRANS,	"APM"},
  { MESSAGE_TYPE_PRE_RELEASE_INFO,	"PRI"}, 	
  { MESSAGE_TYPE_SUBSEQUENT_DIR_NUM,	"SDN"},

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
#define PARAM_TYPE_APPLICATON_TRANS	120
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
  { PARAM_TYPE_APPLICATON_TRANS,       "Application transport"},
  { 0,                                 NULL}};


#define CIC_LENGTH                             2
#define BICC_CIC_LENGTH                        4
#define MESSAGE_TYPE_LENGTH                    1
#define COMMON_HEADER_LENGTH                   (CIC_LENGTH + MESSAGE_TYPE_LENGTH)
#define BICC_COMMON_HEADER_LENGTH              (BICC_CIC_LENGTH + MESSAGE_TYPE_LENGTH)

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
#define BICC_CIC_OFFSET       0

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

static const value_string isup_application_transport_parameter_value[] = {
  /* according 3.82/Q.763 */
  {  0,        "Unidentified Context and Error Handling (UCEH) ASE"},
  {  1,        "PSS1 ASE (VPN)"},
  {  2,        "spare"},
  {  3,        "Charging ASE"},
  {  4,        "GAT"},
  {  5,	   "BAT ASE"},
  {  6,	   "Enhanced Unidentified Context and Error Handling ASE (EUCEH ASE)"},
  {  0,         NULL}};

static const true_false_string isup_Release_call_indicator_value = {
  "release call",
  "do not release call"
};

static const true_false_string isup_Send_notification_ind_value = {
  "send notification",
  "do not send notification"
};
static const value_string isup_APM_segmentation_ind_value[] = {
 
  {  0x00,                     "final segment"},
  {  0x01,                     "number of following segments"},
  {  0x02,                     "number of following segments"},
  {  0x03,                     "number of following segments"},
  {  0x04,                     "number of following segments"},
  {  0x05,                     "number of following segments"},
  {  0x06,                     "number of following segments"},
  {  0x07,                     "number of following segments"},
  {  0x08,                     "number of following segments"},
  {  0x09,                     "number of following segments"},
  {  0,                NULL}};

static const true_false_string isup_Sequence_ind_value = {
  "new sequence",
  "subsequent segment to first segment"
};


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
#define GF_8BIT_MASK 0x60
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
static int proto_bicc = -1;
static int hf_isup_cic = -1;
static int hf_bicc_cic = -1;

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

static int hf_isup_cause_indicator = -1;

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

static int hf_isup_access_delivery_ind = -1;

static int hf_isup_transmission_medium_requirement_prime = -1;

static int hf_isup_loop_prevention_response_ind = -1;

static int hf_isup_temporary_alternative_routing_ind = -1;
static int hf_isup_extension_ind = -1;

static int hf_isup_call_to_be_diverted_ind 			= -1;

static int hf_isup_call_to_be_offered_ind 			= -1;

static int hf_isup_conference_acceptance_ind			= -1;

static int hf_isup_transit_at_intermediate_exchange_ind 	= -1;
static int hf_isup_Release_call_ind 				= -1;
static int hf_isup_Send_notification_ind 			= -1;
static int hf_isup_Discard_message_ind_value			= -1;
static int hf_isup_Discard_parameter_ind			= -1;
static int hf_isup_Pass_on_not_possible_indicator		= -1;
static int hf_isup_Broadband_narrowband_interworking_ind	= -1;

static int hf_isup_app_cont_ident					= -1;
static int hf_isup_app_Send_notification_ind				= -1;
static int hf_isup_apm_segmentation_ind					= -1;
static int hf_isup_apm_si_ind						= -1;
static int hf_isup_app_Release_call_ind					= -1;
static int hf_length_indicator						= -1;
static int hf_afi							= -1;
static int hf_bat_ase_identifier					= -1;
static int hf_Action_Indicator						= -1;

static int hf_Instruction_ind_for_general_action			= -1;	

static int hf_Send_notification_ind_for_general_action			= -1;

static int hf_Instruction_ind_for_pass_on_not_possible			= -1;

static int hf_Send_notification_ind_for_pass_on_not_possible		= -1;
static int hf_BCTP_Version_Indicator					= -1;
static int hf_Tunnelled_Protocol_Indicator				= -1;
static int hf_TPEI							= -1;
static int hf_BVEI							= -1;
static int hf_bncid							= -1;
static int hf_bat_ase_biwfa						= -1;
static int hf_characteristics						= -1;

static int hf_Organization_Identifier					= -1;
static int hf_codec_type						= -1;
static int hf_bearer_control_tunneling					= -1;
static int hf_Local_BCU_ID						= -1;
static int hf_late_cut_trough_cap_ind					= -1;
static int hf_bat_ase_signal						= -1;
static int hf_bat_ase_duration						= -1;
static int hf_bat_ase_bearer_redir_ind					= -1;
static int hf_BAT_ASE_Comp_Report_Reason				= -1;
static int hf_BAT_ASE_Comp_Report_ident					= -1;
static int hf_BAT_ASE_Comp_Report_diagnostic				= -1;


/* Initialize the subtree pointers */
static gint ett_isup 							= -1;
static gint ett_isup_parameter 						= -1;
static gint ett_isup_address_digits 					= -1;
static gint ett_isup_pass_along_message					= -1;
static gint ett_isup_circuit_state_ind					= -1;
static gint ett_bat_ase							= -1;	
static gint ett_bicc 							= -1;
static gint ett_bat_ase_element						= -1;
static gint ett_bat_ase_iwfa						= -1;



static dissector_handle_t sdp_handle;

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
static void
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
static void
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
static void
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
static void
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
static void
dissect_isup_called_party_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
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
					    offset, -1,
					    "Called Party Number");
  address_digits_tree = proto_item_add_subtree(address_digits_item, ett_isup_address_digits);

  while((length = tvb_reported_length_remaining(parameter_tvb, offset)) > 0){
    address_digit_pair = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(address_digits_tree, hf_isup_called_party_odd_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
    called_number[i++] = number_to_char(address_digit_pair & ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK);
    if ((length - 1) > 0 ){
      proto_tree_add_uint(address_digits_tree, hf_isup_called_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      called_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
    }
    offset++;
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
static void
dissect_isup_subsequent_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
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
					    offset, -1,
					    "Subsequent Number");
  address_digits_tree = proto_item_add_subtree(address_digits_item, ett_isup_address_digits);

  while((length = tvb_reported_length_remaining(parameter_tvb, offset)) > 0){
    address_digit_pair = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(address_digits_tree, hf_isup_called_party_odd_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
    called_number[i++] = number_to_char(address_digit_pair & ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK);
    if ((length - 1) > 0 ){
      proto_tree_add_uint(address_digits_tree, hf_isup_called_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      called_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
    }
    offset++;
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
static void
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
static void
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
static void
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
static void
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




static void
dissect_isup_cause_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_reported_length(parameter_tvb);
  proto_tree_add_text(parameter_tree, parameter_tvb,0, -1, "Cause indicators (-> Q.850)");
  dissect_q931_cause_ie(parameter_tvb,0,length,
					    parameter_tree,
					    hf_isup_cause_indicator);
  proto_item_set_text(parameter_item, "Cause indicators, see Q.850 (%u byte%s length)", length , plurality(length, "", "s"));
}

/* ------------------------------------------------------------------
  Dissector Parameter Suspend/Resume Indicators
 */
static void
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
static void
dissect_isup_range_and_status_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 range, actual_status_length;

  range = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint_format(parameter_tree, hf_isup_range_indicator, parameter_tvb, 0, RANGE_LENGTH, range, "Range: %u", range);
  actual_status_length = tvb_reported_length_remaining(parameter_tvb, RANGE_LENGTH);
  if (actual_status_length > 0)
    proto_tree_add_text(parameter_tree, parameter_tvb , RANGE_LENGTH, -1, "Status subfield");
  else
    proto_tree_add_text(parameter_tree, parameter_tvb , 0, 0, "Status subfield is not present with this message type");


  proto_item_set_text(parameter_item, "Range (%u) and status", range);
}
/* ------------------------------------------------------------------
  Dissector Parameter Circuit group supervision message type
 */
static void
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
static void
dissect_isup_facility_ind_parameter(tvbuff_t *parameter_tvb, proto_item *parameter_item)
{
  guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);

  proto_item_set_text(parameter_item, "Facility indicator: %s (%u)"  ,val_to_str(indicator, isup_facility_ind_value,"spare"), indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter Circuit state indicator
 */
static void
dissect_isup_circuit_state_ind_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_item *circuit_state_item;
  proto_tree *circuit_state_tree;
  guint8 circuit_state;
  gint offset=0;
  gint i=0;
  gint length;

  while((length = tvb_reported_length_remaining(parameter_tvb, offset)) > 0){
    circuit_state_item = proto_tree_add_text(parameter_tree, parameter_tvb,
					     offset, -1,
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
  }
  proto_item_set_text(parameter_item, "Circuit state indicator (national use)");
}
/* ------------------------------------------------------------------
  Dissector Parameter Event information
 */
static void
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
static void
dissect_isup_user_to_user_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_reported_length(parameter_tvb);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, -1, "User-to-user info (-> Q.931)");
  dissect_q931_user_user_ie(parameter_tvb, 0, length,
    parameter_tree );
  proto_item_set_text(parameter_item, "User-to-user information, see Q.931 (%u byte%s length)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
  Dissector Parameter Call Reference
 */
static void
dissect_isup_call_reference_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 call_id;
  guint16 spc;

  call_id = tvb_get_ntoh24(parameter_tvb, 0);
  spc = tvb_get_letohs(parameter_tvb, CALL_ID_LENGTH) & 0x3FFF; /*since 1st 2 bits spare */
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, CALL_ID_LENGTH, "Call identity: %u", call_id);
  proto_tree_add_text(parameter_tree, parameter_tvb, CALL_ID_LENGTH, SPC_LENGTH, "Signalling Point Code: %u", spc);

  proto_item_set_text(parameter_item, "Call Reference: Call ID = %u, SPC = %u", call_id, spc);
}
/* ------------------------------------------------------------------
  Dissector Parameter Access Transport - no detailed dissection since defined in Rec. Q.931
 */
static void
dissect_isup_access_transport_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_reported_length(parameter_tvb);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, -1, "Access transport parameter field (-> Q.931)");
  proto_item_set_text(parameter_item, "Access transport, see Q.931 (%u byte%s length)", length , plurality(length, "", "s"));
}

/* dissect x.213 NSAP coded Address */

static const value_string x213_afi_value[] = {
	{ 0x34, "IANA ICP"},
	{ 0x35, "IANA ICP"},
	{ 0x36, "X.121"},
	{ 0x37, "X.121"},
	{ 0x38, "ISO DCC"},
	{ 0x39, "ISO DCC"},
	{ 0x40, "F.69"},
	{ 0x41, "F.69"},
	{ 0x42, "E.163"},
	{ 0x43, "E.163"},
	{ 0x44, "E.164"},
	{ 0x45, "E.164"},
	{ 0x46, "ISO 6523-ICD"},
	{ 0x47, "ISO 6523-ICD"},
	{ 0x48, "Local"},
	{ 0x49, "Local"},
	{ 0x50, "Local ISO/IEC 646 character "},
	{ 0x51, "Local ( National character )"},
	{ 0x52, "X.121"},
	{ 0x53, "X.121"},
	{ 0x54, "F.69"},
	{ 0x55, "F.69"},
	{ 0x56, "E.163"},
	{ 0x57, "E.163"},
	{ 0x58, "E.164"},
	{ 0x59, "E.164"},

	{ 0x76, "ITU-T IND"},
	{ 0x77, "ITU-T IND"},

	{ 0xb8, "IANA ICP Group no"},
	{ 0xb9, "IANA ICP Group no"},
	{ 0xba, "X.121 Group no"},
	{ 0xbb, "X.121 Group no"},
	{ 0xbc, "ISO DCC Group no"},
	{ 0xbd, "ISO DCC Group no"},
	{ 0xbe, "F.69 Group no"},
	{ 0xbf, "F.69 Group no"},
	{ 0xc0, "E.163 Group no"},
	{ 0xc1, "E.163 Group no"},
	{ 0xc2, "E.164 Group no"},
	{ 0xc3, "E.164 Group no"},
	{ 0xc4, "ISO 6523-ICD Group no"},
	{ 0xc5, "ISO 6523-ICD Group no"},
	{ 0xc6, "Local Group no"},
	{ 0xc7, "Local Group no"},
	{ 0xc8, "Local ISO/IEC 646 character Group no"},
	{ 0xc9, "Local ( National character ) Group no"},
	{ 0xca, "X.121 Group no"},
	{ 0xcb, "X.121 Group no"},
	{ 0xcd, "F.69 Group no"},
	{ 0xce, "F.69 Group no"},
	{ 0xcf, "E.163 Group no"},
	{ 0xde, "E.163 Group no"},
	{ 0xd0, "E.164 Group no"},
	{ 0xd1, "E.164 Group no"},

	{ 0xe2, "ITU-T IND Group no"},
	{ 0xe3, "ITU-T IND Group no"},
	{ 0,	NULL }
};

static const value_string E164_country_code_value[] = {
	{ 0x00, "Reserved (Assignment of all 0XX codes will be feasible after 31 December 2000. This question is currently under study.)"}, 
	{ 0x01, "Americas"}, 
	{ 0x020,"Egypt"},
	{ 0x0210,"Spare code"},
	{ 0x0211,"Spare code"},
	{ 0x0212,"Morocco"},
	{ 0x0213,"Algeria"},
	{ 0x0214,"spare code"},
	{ 0x0215,"spare code"}, 
	{ 0x0216,"Tunisia"}, 
	{ 0x0217,"Spare code"}, 
	{ 0x0218,"Libya"},
	{ 0x0219,"Spare code"}, 
	{ 0x0220,"Gambia"},
	{ 0x0221,"Senegal"},
	{ 0x0222,"Mauritania"}, 
	{ 0x0223,"Mali"},
	{ 0x0224,"Guinea"},
	{ 0x0225,"Ivory Coast"}, 
	{ 0x0226,"Burkina Faso"},
	{ 0x0227,"Niger"},
	{ 0x0228,"Togolese Republic"},
	{ 0x0229,"Benin"},
	{ 0x0230,"Mauritius"}, 
	{ 0x0231,"Liberia "},
	{ 0x0232,"Sierra Leone"},
	{ 0x0233,"Ghana"},
	{ 0x0234,"Nigeria"},
	{ 0x0235,"Chad"},
	{ 0x0236,"Central African Republic"},
	{ 0x0237,"Cameroon"},
	{ 0x0238,"Cape Verde"},
	{ 0x0239,"Sao Tome and Principe"},
	{ 0x0240,"Equatorial Guinea"},
	{ 0x0241,"Gabonese Republic"},
	{ 0x0242,"Republic of Congo"},
	{ 0x0243,"Democratic Republic of Congo"},
	{ 0x0244,"Angola"},
	{ 0x0245,"Guinea-Bissau"},
	{ 0x0246,"Diego Garcia"},
	{ 0x0247,"Ascension"},
	{ 0x0248,"Seychelles"},
	{ 0x0249,"Sudan"},
	{ 0x0250,"Rwandese Republic"},
	{ 0x0251,"Ethiopia"},
	{ 0x0252,"Somali"},
	{ 0x0253,"Djibouti"},
	{ 0x0254,"Kenya"},
	{ 0x0255,"Tanzania"}, 
	{ 0x0256,"Uganda"},
	{ 0x0257,"Burundi"},
	{ 0x0258,"Mozambique"}, 
	{ 0x0259,"Spare code"},
	{ 0x0260,"Zambia"},
	{ 0x0261,"Madagascar"}, 
	{ 0x0262,"Reunion Island"}, 
	{ 0x0263,"Zimbabwe"},
	{ 0x0264,"Namibia"},
	{ 0x0265,"Malawi"},
	{ 0x0266,"Lesotho"},
	{ 0x0267,"Botswana"},
	{ 0x0268,"Swaziland"},
	{ 0x0269,"Comoros Mayotte"},
	{ 0x027,"South Africa"},
	{ 0x0281,"spare code"},
	{ 0x0282,"spare code"},
	{ 0x0283,"spare code"},
	{ 0x0284,"spare code"},
	{ 0x0285,"spare code"},
	{ 0x0286,"spare code"},
	{ 0x0287,"spare code"},
	{ 0x0288,"spare code"},
	{ 0x0289,"spare code"},
	{ 0x0290,"Saint Helena"},
	{ 0x0291,"Eritrea"},
	{ 0x0292,"spare code"}, 
	{ 0x0293,"spare code"},
	{ 0x0294,"spare code"},
	{ 0x0295,"spare code"},
	{ 0x0296,"spare code"},
	{ 0x0297,"Aruba"}, 
	{ 0x0298,"Faroe Islands"},
	{ 0x0299,"Greenland"},
	{ 0x030,"Greece"},
	{ 0x031,"Netherlands"}, 
	{ 0x032,"Belgium"},
	{ 0x033,"France"},
	{ 0x034,"Spain"},
	{ 0x0350,"Gibraltar"}, 
	{ 0x0351,"Portugal"},
	{ 0x0352,"Luxembourg"}, 
	{ 0x0353,"Ireland"},
	{ 0x0354,"Iceland"},
	{ 0x0355,"Albania"},
	{ 0x0356,"Malta"},
	{ 0x0357,"Cyprus"},
	{ 0x0358,"Finland"},
	{ 0x0359,"Bulgaria"},
	{ 0x036,"Hungary"},
	{ 0x0370,"Lithuania"}, 
	{ 0x0371,"Latvia"},
	{ 0x0372,"Estonia"},
	{ 0x0373,"Moldova"},
	{ 0x0374,"Armenia"},
	{ 0x0375,"Belarus"},
	{ 0x0376,"Andorra"},
	{ 0x0377,"Monaco"},
	{ 0x0378,"San Marino"}, 
	{ 0x0379,"Vatican"},
	{ 0x0380,"Ukraine"},
	{ 0x0381,"Yugoslavia"}, 
	{ 0x0382,"spare code"},
	{ 0x0383,"spare code"},
	{ 0x0384,"spare code"},
	{ 0x0385,"Croatia"},
	{ 0x0386,"Slovenia"},
	{ 0x0387,"Bosnia and Herzegovina"},
	{ 0x0388,"Groups of contries:"},  
	{ 0x0389,"Macedonia"},
	{ 0x039,"Italy"},
	{ 0x040,"Romania"}, 
	{ 0x041,"Switzerland"}, 
	{ 0x0420,"Czech Republic"}, 
	{ 0x0421,"Slovak Republic"},
	{ 0x0422,"Spare code"},
	{ 0x0423,"Liechtenstein"}, 
	{ 0x0424,"spare code"},
	{ 0x0425,"spare code"},
	{ 0x0426,"spare code"},
	{ 0x0427,"spare code"},
	{ 0x0428,"spare code"},
	{ 0x0429,"spare code"}, 
	{ 0x043,"Austria"},
	{ 0x044,"United Kingdom"},
	{ 0x045,"Denmark"},
	{ 0x046,"Sweden"},
	{ 0x047,"Norway"},
	{ 0x048,"Poland"},
	{ 0x049,"Germany"},
	{ 0x0500,"Falkland Islands (Malvinas)"},
	{ 0x0501,"Belize"},
	{ 0x0502,"Guatemala"}, 
	{ 0x0503,"El Salvador"}, 
	{ 0x0504,"Honduras"},
	{ 0x0505,"Nicaragua"},
	{ 0x0506,"Costa Rica"},
	{ 0x0507,"Panama"},
	{ 0x0508,"Saint Pierre and Miquelon"}, 
	{ 0x0509,"Haiti"},
	{ 0x051,"Peru"},
	{ 0x052,"Mexico"}, 
	{ 0x053,"Cuba"},
	{ 0x054,"Argentina"},
	{ 0x055,"Brazil"},
	{ 0x056,"Chile"},
	{ 0x057,"Colombia"}, 
	{ 0x058,"Venezuela"},
	{ 0x0590,"Guadeloupe"}, 
	{ 0x0591,"Bolivia"},
	{ 0x0592,"Guyana"},
	{ 0x0593,"Ecuador"},
	{ 0x0594,"French Guiana"}, 
	{ 0x0595,"Paraguay"},
	{ 0x0596,"Martinique"}, 
	{ 0x0597,"Suriname"},
	{ 0x0598,"Uruguay"},
	{ 0x0599,"Netherlands Antilles"}, 
	{ 0x060,"Malaysia"},
	{ 0x061,"Australia"},
	{ 0x062,"Indonesia"},
	{ 0x063,"Philippines"}, 
	{ 0x064,"New Zealand"},
	{ 0x065,"Singapore"},
	{ 0x066,"Thailand"},
	{ 0x0670,"East Timor"}, 
	{ 0x0671,"Spare code"},
	{ 0x0672,"Australian External Territories"}, 
	{ 0x0673,"Brunei Darussalam"},
	{ 0x0674,"Nauru"},
	{ 0x0675,"Papua New Guinea"},
	{ 0x0676,"Tonga"},
	{ 0x0677,"Solomon Islands"},
	{ 0x0678,"Vanuatu"},
	{ 0x0679,"Fiji"},
	{ 0x0680,"Palau"},
	{ 0x0681,"Wallis and Futuna"},
	{ 0x0682,"Cook Islands"},
	{ 0x0683,"Niue"},
	{ 0x0684,"American Samoa"},
	{ 0x0685,"Samoa"},
	{ 0x0686,"Kiribati"},
	{ 0x0687,"New Caledonia"},
	{ 0x0688,"Tuvalu"},
	{ 0x0689,"French Polynesia"},
	{ 0x0690,"Tokelau"},
	{ 0x0691,"Micronesia"}, 
	{ 0x0692,"Marshall Islands"},
	{ 0x0693,"spare code"},
	{ 0x0694,"spare code"},
	{ 0x0695,"spare code"},
	{ 0x0696,"spare code"},
	{ 0x0697,"spare code"},
	{ 0x0698,"spare code"},
	{ 0x0699,"spare code"},
	{ 0x07,"Russian Federation,Kazakstan"}, 
	{ 0x0800,"International Freephone Service (see E.169.1)"}, 
	{ 0x0801,"spare code"},
	{ 0x0802,"spare code"},
	{ 0x0803,"spare code"},
	{ 0x0804,"spare code"},
	{ 0x0805,"spare code"},
	{ 0x0806,"spare code"},
	{ 0x0807,"spare code"},
	{ 0x0808,"Universal International Shared Cost Number (see E.169.3)"}, 
	{ 0x0809,"Spare code"},
	{ 0x081,"Japan"},
	{ 0x082,"Korea (Republic of)"}, 
	{ 0x0830,"Spare code"},
	{ 0x0831,"Spare code"},
	{ 0x0832,"Spare code"},
	{ 0x0833,"Spare code"},
	{ 0x0834,"Spare code"},
	{ 0x0835,"Spare code"},
	{ 0x0836,"Spare code"},
	{ 0x0837,"Spare code"},
	{ 0x0838,"Spare code"},
	{ 0x0839,"Spare code"},
	{ 0x084,"Viet Nam"},
	{ 0x0850,"Democratic People's Republic of Korea"}, 
	{ 0x0851,"Spare code"},
	{ 0x0852,"Hongkong, China"}, 
	{ 0x0853,"Macau, China"},
	{ 0x0854,"Spare code"},
	{ 0x0855,"Cambodia"},
	{ 0x0856,"Laos"},
	{ 0x0857,"Spare code"},
	{ 0x0858,"Spare code"},
	{ 0x0859,"Spare code"},
	{ 0x086,"China (People's Republic of)"},
	{ 0x0870,"Inmarsat SNAC"},
	{ 0x0871,"Inmarsat (Atlantic Ocean-East)"}, 
	{ 0x0872,"Inmarsat (Pacific Ocean)"},
	{ 0x0873,"Inmarsat (Indian Ocean)"},
	{ 0x0874,"Inmarsat (Atlantic Ocean-West)"},
	{ 0x0875,"Reserved - Maritime Mobile Service Applications"},
	{ 0x0876,"Reserved - Maritime Mobile Service Applications"},
	{ 0x0877,"Reserved - Maritime Mobile Service Applications"}, 
	{ 0x0878,"Reserved - Universal Personal Telecommunication Service (UPT)"}, 
	{ 0x0879,"Reserved for national non-commercial purposes"},
	{ 0x0880,"Bangladesh"},
	{ 0x0881,"Global Mobile Satellite System (GMSS), shared code:"}, 
	{ 0x0882,"International Networks: (see E.164)"},
	{ 0x0883,"Spare code"},
	{ 0x0884,"Spare code"},
	{ 0x0885,"Spare code"},
	{ 0x0886,"Reserved"}, 
	{ 0x0887,"Spare code"},
	{ 0x0888,"Reserved for future global services (see E.164)"}, 
	{ 0x0889,"Spare code"},
	{ 0x0890,"Spare code"},
	{ 0x0891,"Spare code"},
	{ 0x0892,"Spare code"},
	{ 0x0893,"Spare code"},
	{ 0x0894,"Spare code"},
	{ 0x0895,"Spare code"},
	{ 0x0896,"Spare code"},
	{ 0x0897,"Spare code"},
	{ 0x0898,"Spare code"},
	{ 0x0899,"Spare code"}, 
	{ 0x090,"Turkey"}, 
	{ 0x091,"India"},
	{ 0x092,"Pakistan"}, 
	{ 0x093,"Afghanistan"}, 
	{ 0x094,"Sri Lanka"},
	{ 0x095,"Myanmar"},
	{ 0x0960,"Maldives"}, 
	{ 0x0961,"Lebanon"},
	{ 0x0962,"Jordan"},
	{ 0x0963,"Syrian Arab Republic"}, 
	{ 0x0964,"Iraq"},
	{ 0x0965,"Kuwait"}, 
	{ 0x0966,"Saudi Arabia"}, 
	{ 0x0967,"Yemen"},
	{ 0x0968,"Oman"},
	{ 0x0969,"Reserved"}, 
	{ 0x0970,"Reserved"},
	{ 0x0971,"United Arab Emirates"}, 
	{ 0x0972,"Israel"},
	{ 0x0973,"Bahrain"},
	{ 0x0974,"Qatar"},
	{ 0x0975,"Bhutan"},
	{ 0x0976,"Mongolia"}, 
	{ 0x0977,"Nepal"},
	{ 0x0978,"Spare code"}, 
	{ 0x0979,"Universal International Premium Rate Number (see E.169.2)"}, 
	{ 0x098,"Iran"},
	{ 0x0990,"Spare code"}, 
	{ 0x0991,"Trial service (see E.164.2)"}, 
	{ 0x0992,"Tajikstan"},
	{ 0x0993,"Turkmenistan"}, 
	{ 0x0994,"Azerbaijani Republic"}, 
	{ 0x0995,"Georgia"},
	{ 0x0996,"Kyrgyz Republic"}, 
	{ 0x0997,"Spare code"},
	{ 0x0998,"Uzbekistan"},
	{ 0x0999,"Spare code"},
	{ 0,	NULL }
};    
static const value_string E164_International_Networks_vals[] = {
	{   0x10, "British Telecommunications"}, 
	{   0x11, "Singapore Telecommunications"},
	{   0x12, "MCIWorldCom"},
	{   0x13, "Telespazio"},
	{   0x14, "GTE"},
	{   0x15, "Telstra"}, 
	{   0x16, "United Arab Emirates"}, 
	{   0x17, "AT&T"},
	{   0x18, "Teledesic"}, 
	{   0x19, "Telecom Italia"}, 
	{   0x20, "Asia Cellular Satellite"}, 
	{   0x21, "Ameritech"},
	{   0x22, "Cable & Wireless"}, 
	{   0x23, "Sita-Equant"},
	{   0x24, "Telia AB"},
	{   0x25, "Constellation Communications"}, 
	{   0x26, "SBC Communications"},
	{ 0,	NULL }
};    

static void
dissect_nsap(tvbuff_t *parameter_tvb,gint offset,gint len, proto_tree *parameter_tree)
{
	guint8 afi, cc_length = 0;
	guint8 length = 0;
	guint temp_cc, cc, id_code;

	afi = tvb_get_guint8(parameter_tvb, offset);

	switch ( afi ) {
		case 0x45:	/* E.164 ATM format */
		case 0xC3:	/* E.164 ATM group format */
		proto_tree_add_text(parameter_tree, parameter_tvb, offset, 9,
		    "IDP = %s", tvb_bytes_to_str(parameter_tvb, offset, 9));

		proto_tree_add_uint(parameter_tree, hf_afi, parameter_tvb, offset, len, afi );

		proto_tree_add_text(parameter_tree, parameter_tvb, offset + 1, 8,
		    "IDI = %s", tvb_bytes_to_str(parameter_tvb, offset + 1, 8));
			offset = offset + 1;
			temp_cc = tvb_get_ntohs(parameter_tvb, offset);
			cc = temp_cc >> 4;

			switch ( cc & 0x0f00 ) {
		
			case 0x0 : cc_length = 1;	
			break;

			case 0x0100 : cc_length = 1;	
			break;

			case 0x0200 : 
			switch ( cc & 0x00f0 ) {
				case 0 : 
				case 7 : cc_length = 2;	
				break;
				default : cc_length = 3;
				}
			break;
				
			case 0x0300 : 
			switch ( cc & 0x00f0 ) {
				case 0 : 
				case 1 : 
				case 2 : 
				case 3 : 
				case 4 : 
				case 6 : 
				case 9 : cc_length = 2;
				break;	
				default : cc_length = 3;
				break;
				}
			break;

			case 0x0400 : 
			switch ( cc & 0x00f0 ) {
				case 2 : cc_length = 3;
				break;	
				default : cc_length = 2;
				break;
				}
			break;

			case 0x0500 : 
			switch ( cc & 0x00f0 ) {
				case 0 : 
				case 9 : cc_length = 3;
				break;	
				default : cc_length = 2;
				break;
				}
			break;

			case 0x0600 : 
			switch ( cc & 0x00f0 ) {
				case 7 : 
				case 8 : 
				case 9 : cc_length = 3; 
				break;	
				default : cc_length = 2;
				break;
				}
			break;

			case 0x0700 : cc_length = 1;	
			break;

			case 0x0800 : 
			switch ( cc & 0x00f0 ) {
				case 1 : 
				case 2 : 
				case 4 :  
				case 6 : cc_length = 2; 
				break;	
				default : cc_length = 3;
				break;
				}
			break;

			case 0x0900 : 
				switch ( cc & 0x00f0 ) {
				case 0 : 
				case 1 : 
				case 2 :  
				case 3 :  
				case 4 :  
				case 5 :  
				case 8 : cc_length = 2; 
				break;	
				default : cc_length = 3;
				break;
				}
			break;

			default: ;
			}/* End switch cc */
			switch ( cc_length ) {
			case 0x1 :	cc = cc >> 8;
					length = 1;
			break;
			case 0x2 :	cc = cc >> 4;
					length = 2;
			break;
			default:	length = 2;
			break;
			}/* end switch cc_length */
			proto_tree_add_text(parameter_tree,parameter_tvb, offset, length,"Country Code: %x %s length %u",cc,
					val_to_str(cc,E164_country_code_value,"unknown (%x)"),cc_length);
			switch ( cc ) {
				case 0x882 :
						id_code = tvb_get_ntohs(parameter_tvb, offset + 1);
						id_code = (id_code & 0x0fff) >> 4;
						proto_tree_add_text(parameter_tree,parameter_tvb, (offset + 1), 2,"Identification Code: %x %s ",id_code,
							val_to_str(id_code,E164_International_Networks_vals,"unknown (%x)"));

				break;
				default:;
				}
			proto_tree_add_text(parameter_tree, parameter_tvb, offset + 8, (len - 9),
				    "DSP = %s", tvb_bytes_to_str(parameter_tvb, offset + 8, (len -9)));
	
		break;
		default:
		 	proto_tree_add_uint(parameter_tree, hf_afi, parameter_tvb, offset, len, afi );
		}/* end switch afi */

}


#define  ACTION_INDICATOR                          	0x01	
#define  BACKBONE_NETWORK_CONNECTION_IDENTIFIER    	0x02	
#define  INTERWORKING_FUNCTION_ADDRESS             	0x03	
#define  CODEC_LIST                                	0x04	
#define  CODEC                                    	0x05	
#define  BAT_COMPATIBILITY_REPORT                	0x06	
#define  BEARER_NETWORK_CONNECTION_CHARACTERISTICS	0x07	
#define  BEARER_CONTROL_INFORMATION               	0x08	
#define  BEARER_CONTROL_TUNNELLING               	0x09	
#define  BEARER_CONTROL_UNIT_IDENTIFIER          	0x0A	
#define  SIGNAL			                      	0x0B	
#define  BEARER_REDIRECTION_CAPABILITY            	0x0C	
#define  BEARER_REDIRECTION_INDICATORS            	0x0D	
#define  SIGNAL_TYPE                                 	0x0E	
#define  DURATION                                	0x0F

	
static const value_string bat_ase_list_of_Identifiers_vals[] = {

	{ 0x00                                    	,	"spare" },
	{ ACTION_INDICATOR                         	,	"Action Indicator" },
	{ BACKBONE_NETWORK_CONNECTION_IDENTIFIER   	,	"Backbone Network Connection Identifier" },
	{ INTERWORKING_FUNCTION_ADDRESS            	,	"Interworking Function Address" },
	{ CODEC_LIST                               	,	"Codec List" },
	{ CODEC                                    	,	"Codec" },
	{ BAT_COMPATIBILITY_REPORT                	,	"BAT Compatibility Report" },
	{ BEARER_NETWORK_CONNECTION_CHARACTERISTICS	,	"Bearer Network Connection Characteristics" },
	{ BEARER_CONTROL_INFORMATION               	,	"Bearer Control Information"},
	{ BEARER_CONTROL_TUNNELLING               	,	"Bearer Control Tunnelling"},
	{ BEARER_CONTROL_UNIT_IDENTIFIER          	,	"Bearer Control Unit Identifier" },
	{ SIGNAL			               	,	"Signal"},
	{ BEARER_REDIRECTION_CAPABILITY            	,	"Bearer Redirection Capability"},
	{ BEARER_REDIRECTION_INDICATORS            	,	"Bearer Redirection Indicators"},
	{ SIGNAL_TYPE                                  	,	"Signal Type"},
	{ DURATION                                	,	"Duration" },
	{ 0,	NULL }
};    

/*ITU-T Q.765.5 (06/2000) 13*/
static const value_string Instruction_indicator_for_general_action_vals[] =
{
  { 0,     "Pass on information element"},
  { 1,     "Discard information element"},
  { 2,     "Discard BICC data"},
  { 3,     "Release call"},
  { 0,     NULL}};

static const value_string Instruction_indicator_for_pass_on_not_possible_vals[] = {
  { 0,     "Release call"},
  { 1,     "Discard information element"},
  { 2,     "Discard BICC data"},
  { 3,     "reserved (interpreted as 00)"},
  { 0,     NULL}};

static value_string bat_ase_action_indicator_field_vals[] = {
      
	{ 0x00,	"no indication"},
	{ 0x01,	"connect backward"},
	{ 0x02,	"connect forward"},
	{ 0x03,	"connect forward, no notification"},
	{ 0x04,	"connect forward, plus notification"},
	{ 0x05,	"connect forward, no notification + selected codec"},
	{ 0x06,	"connect forward, plus notification + selected codec"},
	{ 0x07,	"use idle"},
	{ 0x08,	"connected"},
	{ 0x09,	"switched"},
	{ 0x0a,	"selected codec"},
	{ 0x0b,	"modify codec"},
	{ 0x0c,	"successful codec modification"},
	{ 0x0d,	"codec modification failure"},
	{ 0x0e,	"mid-call codec negotiation"},
	{ 0x0f,	"modify to selected codec information"},
	{ 0x10,	"mid-call codec negotiation failure"},
	{ 0x11,	"start signal, notify"},
	{ 0x12,	"start signal, no notify"},
	{ 0x13,	"stop signal, notify"},
	{ 0x14,	"stop signal, no notify"},
	{ 0x15,	"start signal acknowledge"},
	{ 0x16,	"start signal reject"},
	{ 0x16,	"stop signal acknowledge"},
	{ 0x18,	"bearer redirect"},
	{ 0,	NULL }
};    

static const true_false_string BCTP_BVEI_value  = {
  "Version Error Indication, BCTP version not supported",
  "No indication"
};

static value_string BCTP_Tunnelled_Protocol_Indicator_vals[] = {
      
	{ 0x20,	"IPBCP (text encoded)"},
	{ 0x21,	"spare (text encoded protocol)"},
	{ 0x22,	"not used"},
 	{ 0,	NULL }
};    

static const true_false_string BCTP_TPEI_value  = {
  "Protocol Error Indication, Bearer Control Protocol not supported",
  "No indication"
};

#define  ITU_T                          	0x01	

static const value_string bat_ase_organization_identifier_subfield_vals[] = {

	{ 0x00,	"no indication"},
	{ 0x01,	"ITU-T"},
	{ 0x02,	"ETSI (refer to TS 26.103)"},
	{ 0,	NULL }
};


#define	G_711_64_A						0x01
#define	G_711_64_U						0x02
#define	G_711_56_A						0x03
#define	G_711_56_U						0x04
#define	G_722_SB_ADPCM						0x05
#define	G_723_1							0x06
#define	G_723_1_Annex_A						0x07
#define	G_726_ADPCM						0x08
#define	G_727_Embedded_ADPCM					0x09
#define	G_728							0x0a
#define	G_729_CS_ACELP						0x0b
#define	G_729_Annex_B						0x0c

static const value_string ITU_T_codec_type_subfield_vals[] = {

	{ 0x00,				"no indication"},
	{ G_711_64_A,			"G.711 64 kbit/s A-law"},
	{ G_711_64_U,			"G.711 64 kbit/s -law"},
	{ G_711_56_A,			"G.711 56 kbit/s A-law"},
	{ G_711_56_U,			"G.711 56 kbit/s -law"},
	{ G_722_SB_ADPCM,		"G.722 (SB-ADPCM)"},
	{ G_723_1,			"G.723.1"},
	{ G_723_1_Annex_A,		"G.723.1 Annex A (silence suppression)"},
	{ G_726_ADPCM,			"G.726 (ADPCM)"},
	{ G_727_Embedded_ADPCM,		"G.727 (Embedded ADPCM)"},
	{ G_728,			"G.728"},
	{ G_729_CS_ACELP,		"G.729 (CS-ACELP)"},
	{ G_729_Annex_B,		"G.729 Annex B (silence suppression)"},
	{ 0,	NULL }
};


static const value_string bearer_network_connection_characteristics_vals[] = {

	{ 0x00,	"no indication"},
	{ 0x01,	"AAL type 1"},
	{ 0x02,	"AAL type 2"},
	{ 0x03,	"Structured AAL type 1"},
	{ 0x04,	"IP/RTP"},
	{ 0,	NULL }
};

static const true_false_string Bearer_Control_Tunnelling_ind_value  = {
  "Tunnelling to be used",
  "No indication"
};

static const true_false_string late_cut_trough_cap_ind_value  = {
  "Late Cut-through supported",
  "Late Cut-through not supported"
};
/*  ITU-T Rec. Q.765.5/Amd.1 (07/2001) */
static const value_string Bearer_Redirection_Indicator_vals[] = {
	{ 0x00,	" no indication"},
	{ 0x01,	"late cut-through request"},
	{ 0x02,	"redirect temporary reject"},
	{ 0x03,	"redirect backwards request"},
	{ 0x04,	"redirect forwards request"},
	{ 0x05,	"redirect bearer release request"},
	{ 0x06,	"redirect bearer release proceed"},
	{ 0x07,	" redirect bearer release complete"},
	{ 0x08,	"redirect cut-through request"},
	{ 0x09,	"redirect bearer connected indication"},
	{ 0x0a,	"redirect failure"},
	{ 0x0b,	"new connection identifier"},
	{ 0,	NULL }
};

/*26/Q.765.5 - Signal Type */
static const value_string BAt_ASE_Signal_Type_vals[] = {
	{ 0x00,	"DTMF 0"},
	{ 0x01,	"DTMF 1"},
	{ 0x02,	"DTMF 2"},
	{ 0x03,	"DTMF 3"},
	{ 0x04,	"DTMF 4"},
	{ 0x05,	"DTMF 5"},
	{ 0x06,	"DTMF 6"},
	{ 0x07,	"DTMF 7"},
	{ 0x08,	"DTMF 8"},
	{ 0x09,	"DTMF 9"},
	{ 0x0a,	"DTMF *"},
	{ 0x0b,	"DTMF #"},
	{ 0x0c,	"DTMF A"},
	{ 0x0d,	"DTMF B"},
	{ 0x0e,	"DTMF C"},
	{ 0x1f,	"DTMF D"},
	{ 0x40,	"dial tone"},
	{ 0x41,	"PABX internal dial tone"},
	{ 0x42,	"special dial tone"},
	{ 0x43,	"second dial tone"},
	{ 0x44,	"ringing tone"},
	{ 0x45,	"special ringing tone"},
	{ 0x46,	"busy tone"},
	{ 0x47,	"congestion tone"},
	{ 0x48,	"special information tone"},
	{ 0x49,	"warning tone"},
	{ 0x4a,	"intrusion tone"},
	{ 0x4b,	"call waiting tone"},
	{ 0x4c,	"pay tone"},
	{ 0x4d,	"payphone recognition tone"},
	{ 0x4e,	"comfort tone"},
	{ 0x4f,	"tone on hold"},
	{ 0x50,	"record tone"},
	{ 0x51,	"Caller waiting tone"},
	{ 0x52,	"positive indication tone"},
	{ 0x53,	"negative indication tone"},
	{ 0,	NULL }
};

static const value_string BAT_ASE_Report_Reason_vals[] = {

	{ 0x00,	"no indication"},
	{ 0x01,	"information element non-existent or not implemented"},
	{ 0x02,	"BICC data with unrecognized information element, discarded"},
	{ 0,	NULL }
};


/* Dissect BAT ASE message according to Q.765.5 200006 and Amendment 1 200107	*/
/* Layout of message								*/
/*	Element name			Octet					*/			
/*	Identifier 1 			1					*/
/*	Length indicator 1 		2					*/
/*	Compatibility information 1 	3					*/
/*	Contents 1			4					*/
/*	Identifier n 			m					*/
/*	Length indicator n							*/
/*	Compatibility information n						*/
/*	Contents n			p					*/

static void
dissect_bat_ase_Encapsulated_Application_Information(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, gint offset)
{ 
	gint		length = tvb_reported_length_remaining(parameter_tvb, offset);
	tvbuff_t	*next_tvb;
	proto_tree	*bat_ase_tree, *bat_ase_element_tree, *bat_ase_iwfa_tree;
	proto_item	*bat_ase_item, *bat_ase_element_item, *bat_ase_iwfa_item;
	guint8 identifier,compatibility_info,content, BCTP_Indicator_field_1, BCTP_Indicator_field_2;
	guint8 length_indicator, sdp_length, tempdata, content_len, element_no, number_of_indicators;
	guint8 iwfa[32], diagnostic_len;
	guint duration;
	guint diagnostic;
	guint32 bncid, Local_BCU_ID;
	element_no = 0;

	bat_ase_item = proto_tree_add_text(parameter_tree,parameter_tvb,
					   offset, -1,
"Bearer Association Transport (BAT) Application Service Element (ASE) Encapsulated Application Information:");
	bat_ase_tree = proto_item_add_subtree(bat_ase_item , ett_bat_ase);

	proto_tree_add_text(bat_ase_tree, parameter_tvb, offset, -1, "BAT ASE Encapsulated Application Information, (%u byte%s length)", length, plurality(length, "", "s"));
	while(tvb_reported_length_remaining(parameter_tvb, offset) > 0){
		element_no = element_no + 1;
		identifier = tvb_get_guint8(parameter_tvb, offset);
		offset = offset + 1;

		/* length indicator may be 11 bits long 			*/
		/*        temp_length = tvb_get_ntohs(parameter_tvb, offset);*/
	
		length_indicator = tvb_get_guint8(parameter_tvb, offset) & 0x7f;

		bat_ase_element_item = proto_tree_add_text(bat_ase_tree,parameter_tvb,
					  ( offset - 1),(length_indicator + 2),"BAT ASE Element %u, Identifier: %s",element_no,
					val_to_str(identifier,bat_ase_list_of_Identifiers_vals,"unknown (%u)"));
		bat_ase_element_tree = proto_item_add_subtree(bat_ase_element_item , ett_bat_ase_element);

		proto_tree_add_uint(bat_ase_element_tree , hf_bat_ase_identifier , parameter_tvb, offset - 1, 1, identifier );
		proto_tree_add_uint(bat_ase_element_tree , hf_length_indicator  , parameter_tvb, offset, 1, length_indicator );

		offset = offset + 1;
		compatibility_info = tvb_get_guint8(parameter_tvb, offset);
		proto_tree_add_uint(bat_ase_element_tree, hf_Instruction_ind_for_general_action , parameter_tvb, offset, 1, compatibility_info );
		proto_tree_add_boolean(bat_ase_element_tree, hf_Send_notification_ind_for_general_action , parameter_tvb, offset, 1, compatibility_info );
		proto_tree_add_uint(bat_ase_element_tree, hf_Instruction_ind_for_pass_on_not_possible , parameter_tvb, offset, 1, compatibility_info );
		proto_tree_add_boolean(bat_ase_element_tree, hf_Send_notification_ind_for_pass_on_not_possible , parameter_tvb, offset, 1, compatibility_info );
		proto_tree_add_boolean(bat_ase_element_tree, hf_isup_extension_ind , parameter_tvb, offset, 1, compatibility_info );
		offset = offset + 1;
		content_len = length_indicator - 1 ; /* exclude the treated Compatibility information */

		/* content will be different depending on identifier */
		switch ( identifier ){

			case ACTION_INDICATOR :

				content = tvb_get_guint8(parameter_tvb, offset);
				proto_tree_add_uint(bat_ase_element_tree, hf_Action_Indicator , parameter_tvb, offset, 1, content );
				proto_item_append_text(bat_ase_element_item, " - %s",
						 val_to_str(content,bat_ase_action_indicator_field_vals, "unknown (%u)"));
				offset = offset + 1;
				break;                         	
			case BACKBONE_NETWORK_CONNECTION_IDENTIFIER :   	

				bncid = tvb_get_ntohl(parameter_tvb, offset);
				switch ( content_len ){
				case 1:
						bncid = bncid & 0x000000ff;
						break;  
				case 2:
						bncid = bncid & 0x0000ffff;
						break;  
				case 3:
						bncid = bncid & 0x00ffffff;
						break;  
				case 4:;  
				default:;
				}
				proto_tree_add_uint_format(bat_ase_element_tree, hf_bncid, parameter_tvb, offset, content_len, bncid, "BNCId: 0x%08x", bncid);
				proto_item_append_text(bat_ase_element_item, " - 0x%08x",bncid);
				offset = offset + content_len;

			break;
			case INTERWORKING_FUNCTION_ADDRESS :           	
				tvb_memcpy(parameter_tvb, iwfa, offset, content_len);        	
				bat_ase_iwfa_item = proto_tree_add_bytes(bat_ase_element_tree, hf_bat_ase_biwfa, parameter_tvb, offset, content_len,
							    iwfa);
				bat_ase_iwfa_tree = proto_item_add_subtree(bat_ase_iwfa_item , ett_bat_ase_iwfa);
				dissect_nsap(parameter_tvb, offset, content_len, bat_ase_iwfa_tree);

				offset = offset + content_len;
			break;
			case CODEC_LIST :          	
				tempdata = tvb_get_guint8(parameter_tvb, offset);
				proto_tree_add_uint(bat_ase_element_tree, hf_Organization_Identifier , parameter_tvb, offset, 1, tempdata );
				if ( tempdata != ITU_T ){
					proto_tree_add_text(bat_ase_element_tree, parameter_tvb, offset, content_len , "List of Codecs ( Non ITU-T ) %s",
							    tvb_bytes_to_str(parameter_tvb, offset, content_len));
				break;
				}
				offset = offset + 1;
				tempdata = tvb_get_guint8(parameter_tvb, offset);
				proto_tree_add_uint(bat_ase_element_tree, hf_codec_type , parameter_tvb, offset, 1, tempdata );
				offset = offset +1;
				proto_tree_add_text(bat_ase_element_tree, parameter_tvb, offset,content_len , "Not decoded yet, (%u byte%s length)", (content_len), plurality(content_len, "", "s"));
				offset = offset + content_len - 2;
			break;
			case CODEC :                             	

				tempdata = tvb_get_guint8(parameter_tvb, offset);
				proto_tree_add_uint(bat_ase_element_tree, hf_Organization_Identifier , parameter_tvb, offset, 1, tempdata );
				if ( tempdata != ITU_T ){
					proto_tree_add_text(bat_ase_element_tree, parameter_tvb, offset, content_len , "Codec ( Non ITU-T ) %s",
							    tvb_bytes_to_str(parameter_tvb, offset, content_len));
				break;
				}
				offset = offset + 1;
				tempdata = tvb_get_guint8(parameter_tvb, offset);
				proto_tree_add_uint(bat_ase_element_tree, hf_codec_type , parameter_tvb, offset, 1, tempdata );
				offset = offset + 1;

				switch ( tempdata ) {
					
				case G_711_64_A :
		                case G_711_64_U	:		
                		case G_711_56_A	:		
                    		case G_711_56_U	: 		
                    		case G_722_SB_ADPCM :	
                    		case G_723_1 :				
                    		case G_723_1_Annex_A :	/* These codecs have no configuration data */	
				break;

                    		case G_726_ADPCM :					
                    		case G_727_Embedded_ADPCM : /* four bit config data, TODO decode config */
					if ( content_len > 1 ) {	
						proto_tree_add_text(bat_ase_element_tree, parameter_tvb, offset, content_len , "Configuration data : %s",
							    tvb_bytes_to_str(parameter_tvb, offset, 1));
					offset = offset + 1;
					}
				break;	
                    		case G_728 :							
                    		case G_729_CS_ACELP :		
                    		case G_729_Annex_B :	 /* four bit config data, TODO decode config */
					if ( content_len > 1 )	{
						proto_tree_add_text(bat_ase_element_tree, parameter_tvb, offset, content_len , "Configuration data : %s",
							    tvb_bytes_to_str(parameter_tvb, offset, 1));
					offset = offset + 1;
					}
				default:
					break;

				}	
                             	
			break;
			case BAT_COMPATIBILITY_REPORT :                	
				tempdata = tvb_get_guint8(parameter_tvb, offset);
				proto_tree_add_uint(bat_ase_element_tree, hf_BAT_ASE_Comp_Report_Reason, parameter_tvb, offset, 1, tempdata );
				offset = offset + 1;

				diagnostic_len = content_len - 1;
				while ( diagnostic_len > 0 ) {
					tempdata = tvb_get_guint8(parameter_tvb, offset);
					proto_tree_add_uint(bat_ase_element_tree, hf_BAT_ASE_Comp_Report_ident, parameter_tvb, offset, 1, tempdata );
					offset = offset + 1;
					diagnostic = tvb_get_letohs(parameter_tvb, offset);
					proto_tree_add_uint(bat_ase_element_tree, hf_BAT_ASE_Comp_Report_diagnostic, parameter_tvb, offset, 2, diagnostic);
					offset = offset + 2;
					diagnostic_len = diagnostic_len - 3;
				}
			break;
			case BEARER_NETWORK_CONNECTION_CHARACTERISTICS :
				tempdata = tvb_get_guint8(parameter_tvb, offset);
				proto_tree_add_uint(bat_ase_element_tree, hf_characteristics , parameter_tvb,
						 offset, 1, tempdata );
				proto_item_append_text(bat_ase_element_item, " - %s",
						 val_to_str(tempdata,bearer_network_connection_characteristics_vals, "unknown (%u)"));

				offset = offset + content_len;
			break;
/* The Bearer Control Information information element contains the bearer control tunnelling protocol */
/* ITU-T Q.1990 (2001), BICC bearer control tunnelling protocol. */

			case BEARER_CONTROL_INFORMATION :              	
				BCTP_Indicator_field_1 = tvb_get_guint8(parameter_tvb, offset);
				proto_tree_add_uint(bat_ase_element_tree, hf_BCTP_Version_Indicator, parameter_tvb, offset, 1, BCTP_Indicator_field_1 );
				proto_tree_add_boolean(bat_ase_element_tree, hf_BVEI, parameter_tvb, offset, 1, BCTP_Indicator_field_1 );
				offset = offset + 1;

				BCTP_Indicator_field_2 = tvb_get_guint8(parameter_tvb, offset);
				proto_tree_add_uint(bat_ase_element_tree, hf_Tunnelled_Protocol_Indicator , parameter_tvb, offset, 1, BCTP_Indicator_field_2 );
				proto_tree_add_boolean(bat_ase_element_tree, hf_TPEI, parameter_tvb, offset, 1, BCTP_Indicator_field_2 );
				offset = offset + 1;

				sdp_length = ( length_indicator & 0x7f) - 3;

				next_tvb = tvb_new_subset(parameter_tvb, offset, sdp_length, sdp_length);
				call_dissector(sdp_handle, next_tvb, pinfo, bat_ase_element_tree);
				offset = offset + sdp_length;


			break;
			case BEARER_CONTROL_TUNNELLING :              	

				tempdata = tvb_get_guint8(parameter_tvb, offset);
				proto_tree_add_boolean(bat_ase_element_tree, hf_bearer_control_tunneling , parameter_tvb, offset, 1, ( tempdata & 0x01 ) );
				if ( tempdata & 0x01 )
					proto_item_append_text(bat_ase_element_item, " - Tunnelling to be used ");

				offset = offset + content_len;
			break;
			case BEARER_CONTROL_UNIT_IDENTIFIER :          	
				tempdata = tvb_get_guint8(parameter_tvb, offset);
				proto_tree_add_text(bat_ase_element_tree, parameter_tvb, offset, 1, "Network ID Length indicator= %u",tempdata);
				offset = offset +1;
				if ( tempdata > 0 ) {
					offset = offset +1;
				
/* Q.765.5 amd 1
	Network ID
	The coding of the Network ID field is identical to the coding of the Network ID field in the
	Global Call Reference parameter as specified in clause 6/Q.1902.3 (see [3]).
	NOTE .When used inside a network domain, the Network ID may be omitted by setting the
	Network ID Length indicator to the value "0".
 	Q.1902.3
	The following codes are used in the subfields of the global call reference parameter field:
	a) Network ID
	The Network ID contains the value field (coded according to ASN.1 BER) of an object
	identifier identifying the network. This means that the tag and length fields are omitted.
	An example of such an object identifier can be the following:
	.{itu-t (0) administration (2) national regulatory authority (x) network (y)}
	The value for x is the value of the national regulatory authority (one of the Data Country
	Codes associated to the country as specified in ITU-T X.121 shall be used for "national
	regulatory authority"), the value for y is under the control of the national regulatory
	authority concerned.
	b) Node ID
	A binary number that uniquely identifies within the network the node which generates the
	call reference.
	c) Call Reference ID
	A binary number used for the call reference of the call. This is generated by the node for
	each call.

*/
					proto_tree_add_text(bat_ase_element_tree, parameter_tvb, offset, tempdata , "Network ID: %s",
							    tvb_bytes_to_str(parameter_tvb, offset, tempdata));
					offset = offset + tempdata;
				} /* end if */

				Local_BCU_ID = tvb_get_letohl(parameter_tvb, offset);
				proto_tree_add_uint_format(bat_ase_element_tree, hf_Local_BCU_ID , parameter_tvb, offset, 4, Local_BCU_ID , "Local BCU ID : 0x%08x", Local_BCU_ID );
				offset = offset + 4;
			break;
			case SIGNAL :          	
				tempdata = tvb_get_guint8(parameter_tvb, offset);
				proto_tree_add_uint(bat_ase_element_tree, hf_bat_ase_signal , parameter_tvb, offset, 1, tempdata );
				offset = offset + 1;
				if ( content_len > 1){
				duration = tvb_get_letohs(parameter_tvb, offset);
				proto_tree_add_uint(bat_ase_element_tree, hf_bat_ase_duration , parameter_tvb, offset, 2, duration );
				offset = offset + 2;
				}
			break;
			case BEARER_REDIRECTION_CAPABILITY :            	
				tempdata = tvb_get_guint8(parameter_tvb, offset);
				proto_tree_add_boolean(bat_ase_element_tree, hf_late_cut_trough_cap_ind , parameter_tvb, offset, 1, tempdata );
				offset = offset + content_len;
			break;
			case BEARER_REDIRECTION_INDICATORS :
				number_of_indicators = 0;
				while ( number_of_indicators < content_len ) {        	
					tempdata = tvb_get_guint8(parameter_tvb, offset);
					proto_tree_add_uint(bat_ase_element_tree, hf_bat_ase_bearer_redir_ind , parameter_tvb, offset, 1, tempdata );
					offset = offset + 1;
					number_of_indicators = number_of_indicators + 1;
				}
			break;
			case SIGNAL_TYPE :                                  	
				tempdata = tvb_get_guint8(parameter_tvb, offset);
				proto_tree_add_uint(bat_ase_element_tree, hf_bat_ase_signal , parameter_tvb, offset, 1, tempdata );
				offset = offset + content_len;
			break;
			case DURATION :
				duration = tvb_get_letohs(parameter_tvb, offset);
				proto_tree_add_uint(bat_ase_element_tree, hf_bat_ase_duration , parameter_tvb, offset, 2, duration );
				offset = offset + content_len;
			break;
			default :
				proto_tree_add_text(bat_ase_element_tree, parameter_tvb, offset,content_len , "Default ?, (%u byte%s length)", (content_len), plurality(content_len, "", "s"));
				offset = offset + content_len;
			}                                	
  	} 
}

static void
dissect_isup_application_transport_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{ 

  guint8 application_context_identifier;
  guint8 application_transport_instruction_ind;
  guint8 si_and_apm_segmentation_indicator;
  guint8 apm_Segmentation_local_ref;
  guint8 pointer_to_transparent_data;
  guint16 application_context_identifier16;
  gint offset = 0;
  guint length = tvb_reported_length(parameter_tvb);
  
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, -1, "Application transport parameter fields:");
  proto_item_set_text(parameter_item, "Application transport, (%u byte%s length)", length , plurality(length, "", "s"));
  application_context_identifier = tvb_get_guint8(parameter_tvb, 0);
 
  if ( (application_context_identifier & H_8BIT_MASK) == 0x80) {
    proto_tree_add_uint(parameter_tree, hf_isup_app_cont_ident, parameter_tvb,offset, 1, (application_context_identifier & GFEDCBA_8BIT_MASK));
    offset = offset + 1;
    if ((application_context_identifier & 0x7f) > 6)
      return;
  }
  else {
    application_context_identifier16 = tvb_get_letohs(parameter_tvb,offset); 
    proto_tree_add_text(parameter_tree, parameter_tvb, offset, 2, "Application context identifier: 0x%x", application_context_identifier16);
    offset = offset + 2;
    return; /* no further decoding of this element */
  }
  proto_tree_add_text(parameter_tree, parameter_tvb, offset, -1, "Application transport instruction indicators: ");
  application_transport_instruction_ind = tvb_get_guint8(parameter_tvb, offset);	
  proto_tree_add_boolean(parameter_tree, hf_isup_app_Release_call_ind, parameter_tvb, offset, 1, application_transport_instruction_ind);
  proto_tree_add_boolean(parameter_tree, hf_isup_app_Send_notification_ind, parameter_tvb, offset, 1, application_transport_instruction_ind);
  offset = offset + 1; 
  if ( (application_transport_instruction_ind & H_8BIT_MASK) == 0x80) {
        proto_tree_add_text(parameter_tree, parameter_tvb, offset, 1, "APM segmentation indicator:");
	si_and_apm_segmentation_indicator  = tvb_get_guint8(parameter_tvb, offset);
	proto_tree_add_uint(parameter_tree, hf_isup_apm_segmentation_ind , parameter_tvb, offset, 1, si_and_apm_segmentation_indicator  );
	proto_tree_add_boolean(parameter_tree, hf_isup_apm_si_ind , parameter_tvb, offset, 1, si_and_apm_segmentation_indicator  );
	offset = offset + 1;

	if ( (si_and_apm_segmentation_indicator & H_8BIT_MASK) == 0x80) {
	  apm_Segmentation_local_ref  = tvb_get_guint8(parameter_tvb, offset);
	  proto_tree_add_text(parameter_tree, parameter_tvb, offset, 1, "Segmentation local reference (SLR): 0x%x", apm_Segmentation_local_ref  );
	  offset = offset + 1;
  	}
  }	

  proto_tree_add_text(parameter_tree, parameter_tvb, offset, -1, "APM-user information field"  );
  /* dissect BAT ASE element, without transparent data ( Q.765.5-200006) */ 
  if ((application_context_identifier & 0x7f) != 5) {
    proto_tree_add_text(parameter_tree, parameter_tvb, offset, -1, "No further dissection of APM-user information field");
    return;
  }
  pointer_to_transparent_data = tvb_get_guint8(parameter_tvb, offset);
  if (pointer_to_transparent_data != 0)
    proto_tree_add_text(parameter_tree, parameter_tvb, offset, 1, "Pointer to transparent data: 0x%x Don't know how to dissect further", pointer_to_transparent_data  );
  proto_tree_add_text(parameter_tree, parameter_tvb, offset, 1, "Pointer to transparent data: 0x%x No transparent data", pointer_to_transparent_data  );
  offset = offset + 1;
 
  dissect_bat_ase_Encapsulated_Application_Information(parameter_tvb, pinfo, parameter_tree, offset);
}



/* ------------------------------------------------------------------
  Dissector Parameter Optional Forward Call indicators
 */
static void
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
static void
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
					    offset, -1,
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
static void
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
					    offset, -1,
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
static void
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
					    offset, -1,
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
static void
dissect_isup_redirection_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
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
					    offset, -1,
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
static void
dissect_isup_connection_request_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 local_ref;
  guint16 spc;
  guint8 protocol_class, credit, offset=0;

  local_ref = tvb_get_ntoh24(parameter_tvb, 0);
  proto_tree_add_text(parameter_tree, parameter_tvb, offset, LOCAL_REF_LENGTH, "Local Reference: %u", local_ref);
  offset = LOCAL_REF_LENGTH;
  spc = tvb_get_letohs(parameter_tvb,offset) & 0x3FFF; /*since 1st 2 bits spare */
  proto_tree_add_text(parameter_tree, parameter_tvb, offset, SPC_LENGTH, "Signalling Point Code: %u", spc);
  offset += SPC_LENGTH;
  protocol_class = tvb_get_guint8(parameter_tvb, offset);
  proto_tree_add_text(parameter_tree, parameter_tvb, offset, PROTOCOL_CLASS_LENGTH, "Protocol Class: %u", protocol_class);
  offset += PROTOCOL_CLASS_LENGTH;
  credit = tvb_get_guint8(parameter_tvb, offset);
  proto_tree_add_text(parameter_tree, parameter_tvb, offset, CREDIT_LENGTH, "Credit: %u", credit);
  offset += CREDIT_LENGTH;

  proto_item_set_text(parameter_item, "Connection request: Local Reference = %u, SPC = %u, Protocol Class = %u, Credit = %u", local_ref, spc, protocol_class, credit);
}
/* ------------------------------------------------------------------
  Dissector Parameter Redirection information
 */
static void
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
static void
dissect_isup_closed_user_group_interlock_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
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
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, 2, "Network Identity: %s", NI_digits);
  bin_code = tvb_get_ntohs(parameter_tvb, 2);
  proto_tree_add_text(parameter_tree, parameter_tvb, 3, 2, "Binary Code: 0x%x", bin_code);
  proto_item_set_text(parameter_item, "Closed user group interlock code: NI = %s, Binary code = 0x%x", NI_digits, bin_code);
}
/* ------------------------------------------------------------------
  Dissector Parameter User service information- no detailed dissection since defined in Rec. Q.931
 */
static void
dissect_isup_user_service_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, length, "User service information (-> Q.931 Bearer_capability)");
  proto_item_set_text(parameter_item, "User service information, see Q.931 (%u byte%s length)", length , plurality(length, "", "s"));
  dissect_q931_bearer_capability_ie(parameter_tvb,
					    0, length,
					    parameter_tree);
}
/* ------------------------------------------------------------------
  Dissector Parameter Signalling point code
 */
static void
dissect_isup_signalling_point_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 spc;

  spc = tvb_get_letohs(parameter_tvb, 0) & 0x3FFF; /*since 1st 2 bits spare */
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, SIGNALLING_POINT_CODE_LENGTH, "Signalling Point Code: %u", spc);

  proto_item_set_text(parameter_item, "Signalling point code: %u", spc);
}
/* ------------------------------------------------------------------
  Dissector Parameter Connected number
 */
static void
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
					    offset, -1,
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
static void
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
					    offset, -1,
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
static void
dissect_isup_circuit_assignment_map_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 map_type;

  map_type = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_isup_map_type, parameter_tvb, 0, 1, map_type);
  proto_tree_add_text(parameter_tree, parameter_tvb, 1, 5, "Circuit assignment map (bit position indicates usage of corresponding circuit->3.69/Q.763)");
  proto_item_set_text(parameter_item, "Circuit assignment map");
}
/* ------------------------------------------------------------------
  Dissector Parameter Automatic congestion level
 */
static void
dissect_isup_automatic_congestion_level_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 congestion_level;

  congestion_level = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_isup_automatic_congestion_level, parameter_tvb, 0, AUTO_CONGEST_LEVEL_LENGTH, congestion_level);
  proto_item_set_text(parameter_item, "Automatic congestion level: %s (%u)", val_to_str(congestion_level, isup_auto_congestion_level_value, "spare"), congestion_level);
}
/* ------------------------------------------------------------------
  Dissector Parameter Optional backward Call indicators
 */
static void
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
static void
dissect_isup_user_to_user_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 indicators;

  indicators = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, USER_TO_USER_IND_LENGTH, "User-to-user indicators: 0x%x (refer to 3.60/Q.763 for detailed decoding)", indicators );
  proto_item_set_text(parameter_item,"User-to-user indicators: 0x%x", indicators );
}
/* ------------------------------------------------------------------
  Dissector Parameter Original ISC point code
 */
static void
dissect_isup_original_isc_point_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 spc;

  spc = tvb_get_letohs(parameter_tvb, 0) & 0x3FFF; /*since 1st 2 bits spare */
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, ORIGINAL_ISC_POINT_CODE_LENGTH, "Origination ISC Point Code: %u", spc);

  proto_item_set_text(parameter_item, "Origination ISC point code: %u", spc);
}
/* ------------------------------------------------------------------
  Dissector Parameter Generic notification indicator
 */
static void
dissect_isup_generic_notification_indicator_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 indicators;

  indicators = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, GENERIC_NOTIFICATION_IND_LENGTH, "Generic notification indicator: 0x%x (refer to 3.25/Q.763 for detailed decoding)", indicators );
  proto_item_set_text(parameter_item,"Generic notification indicator: 0x%x", indicators );
}
/* ------------------------------------------------------------------
  Dissector Parameter Call history information
 */
static void
dissect_isup_call_history_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 info;

  info = tvb_get_ntohs(parameter_tvb, 0);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, CALL_HISTORY_INFO_LENGTH, "Call history info: propagation delay = %u ms", info);
  proto_item_set_text(parameter_item,"Call history info: propagation delay = %u ms", info);
}
/* ------------------------------------------------------------------
  Dissector Parameter Access delivery information
 */
static void
dissect_isup_access_delivery_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_isup_access_delivery_ind, parameter_tvb, 0, ACCESS_DELIVERY_INFO_LENGTH, indicator);
  proto_item_set_text(parameter_item, "Access delivery information: 0x%x", indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter Network specific facility
 */
static void
dissect_isup_network_specific_facility_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, length, "Network specific facility (refer to 3.36/Q.763 for detailed decoding)");
  proto_item_set_text(parameter_item, "Network specific facility (%u byte%s length)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
  Dissector Parameter User service information prime
 */
static void
dissect_isup_user_service_information_prime_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, length, "User service information prime (-> Q.931)");
  proto_item_set_text(parameter_item, "User service information prime, see Q.931 (%u byte%s length)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
  Dissector Parameter Propagation delay counter
 */
static void
dissect_isup_propagation_delay_counter_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 info;

  info = tvb_get_ntohs(parameter_tvb, 0);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, PROPAGATION_DELAY_COUNT_LENGTH, "Propagation delay counter = %u ms", info);
  proto_item_set_text(parameter_item,"Propagation delay counter = %u ms", info);
}
/* ------------------------------------------------------------------
  Dissector Parameter Remote operations
 */
static void
dissect_isup_remote_operations_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, length, "Remote operations");
  proto_item_set_text(parameter_item, "Remote operations (%u byte%s length)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
  Dissector Parameter Service activation
 */
static void
dissect_isup_service_activation_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint i;
  guint8 feature_code;
  guint length = tvb_length(parameter_tvb);
  for (i=0; i< length; i++){
    feature_code = tvb_get_guint8(parameter_tvb, i);
    proto_tree_add_text(parameter_tree, parameter_tvb, i, 1, "Feature Code %u: %u", i+1, feature_code);
  }
  proto_item_set_text(parameter_item, "Service Activation (%u byte%s length)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
  Dissector Parameter User service information prime - no detailed dissection since defined in Rec. Q.931
 */
static void
dissect_isup_user_teleservice_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, USER_TELESERVICE_INFO_LENGTH, "User teleservice information (-> Q.931)");
  proto_item_set_text(parameter_item, "User teleservice information, see Q.931");
}
/* ------------------------------------------------------------------
  Dissector Parameter Transmission medium requirement used
 */
static void
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
static void
dissect_isup_call_diversion_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, CALL_DIV_INFO_LENGTH, "Call diversion information: 0x%x (refer to 3.6/Q.763 for detailed decoding)", indicator);
  proto_item_set_text(parameter_item, "Call diversion information: 0x%x", indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter Echo control  information
 */
static void
dissect_isup_echo_control_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, ECHO_CONTROL_INFO_LENGTH, "Echo control information: 0x%x (refer to 3.19/Q.763 for detailed decoding)", indicator);
  proto_item_set_text(parameter_item, "Echo control information: 0x%x", indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter Message compatibility information
 */
static void
dissect_isup_message_compatibility_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, length, "Message compatibility information (refer to 3.33/Q.763 for detailed decoding)");
  proto_item_set_text(parameter_item, "Message compatibility information (%u byte%s length)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
  Dissector Parameter compatibility information
 */
static const true_false_string isup_transit_at_intermediate_exchange_ind_value  = {
  "End node interpretation",
  "Transit interpretation"
};


static const true_false_string isup_Discard_message_ind_value = {
	"Discard message",
	"Do not discard message (pass on)",
};

static const true_false_string isup_Discard_parameter_ind_value = {
	"Discard parameter",
	"Do not discard parameter (pass on)",
};

static const value_string isup_Pass_on_not_possible_indicator_vals[] = {
	{ 0x00, "Release call" },
	{ 0x01, "Discard message" },
	{ 0x02, "Discard parameter" },
	{ 0x03, "Reserved (interpreted as 00)" },

};
static const value_string ISUP_Broadband_narrowband_interworking_indicator_vals[] = {
	{ 0x00, "Pass on" },
	{ 0x01, "Discard message" },
	{ 0x02, "Release call" },
	{ 0x03, "Discard parameter" },
}; 

static void
dissect_isup_parameter_compatibility_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint  length = tvb_length(parameter_tvb);
  guint  len = length;
  guint8 upgraded_parameter, upgraded_parameter_no;
  guint8 offset;
  guint8 instruction_indicators; 
  offset = 0;
  upgraded_parameter_no = 0;

  proto_item_set_text(parameter_item, "Parameter compatibility information (%u byte%s length)", length , plurality(length, "", "s"));
/* etxrab Decoded as per Q.763 section 3.41 */

  while ( len > 0 ) {
  upgraded_parameter_no = upgraded_parameter_no + 1;
  upgraded_parameter = tvb_get_guint8(parameter_tvb, offset);

  proto_tree_add_text(parameter_tree, parameter_tvb, offset, 1,
	    "Upgraded parameter no: %u = %s", upgraded_parameter_no,
	    val_to_str(upgraded_parameter, isup_parameter_type_value, "unknown (%u)"));
  offset += 1;
  len -= 1;
  instruction_indicators = tvb_get_guint8(parameter_tvb, offset);

  proto_tree_add_text(parameter_tree, parameter_tvb, offset, 1,
		    "Instruction indicators: 0x%x ",
		    instruction_indicators);

 proto_tree_add_boolean(parameter_tree, hf_isup_transit_at_intermediate_exchange_ind, 
                parameter_tvb, offset, 1, instruction_indicators );

 proto_tree_add_boolean(parameter_tree, hf_isup_Release_call_ind, parameter_tvb, offset, 1, instruction_indicators );

 proto_tree_add_boolean(parameter_tree, hf_isup_Send_notification_ind, parameter_tvb, offset, 1, instruction_indicators );

 proto_tree_add_boolean(parameter_tree, hf_isup_Discard_message_ind_value, parameter_tvb, offset, 1, instruction_indicators );

 proto_tree_add_boolean(parameter_tree, hf_isup_Discard_parameter_ind, parameter_tvb, offset, 1, instruction_indicators );

 proto_tree_add_uint(parameter_tree, hf_isup_Pass_on_not_possible_indicator, parameter_tvb, offset, 1,instruction_indicators);

 proto_tree_add_boolean(parameter_tree, hf_isup_extension_ind , parameter_tvb, offset, 1, instruction_indicators );

  offset += 1;
  len -= 1;
  if (!(instruction_indicators & H_8BIT_MASK)) {
		if (len == 0)
			return;
                  instruction_indicators = tvb_get_guint8(parameter_tvb, offset);
		 proto_tree_add_uint(parameter_tree, hf_isup_Broadband_narrowband_interworking_ind, parameter_tvb, offset, 1,instruction_indicators);
                 offset += 1;
                  len -= 1;
                  }
   if (len == 0)
   return;
  ;
 }
/* etxrab */
 
}
/* ------------------------------------------------------------------
  Dissector Parameter MLPP precedence
 */
static void
dissect_isup_mlpp_precedence_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  char NI_digits[5]="";
  guint8 indicators, digit_pair;
  guint32 bin_code;

  indicators = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, 1, "LFB (Bits 6+7) and precedence level (Bits 1-4): 0x%x",indicators);
  digit_pair = tvb_get_guint8(parameter_tvb, 1);
  NI_digits[0] = number_to_char((digit_pair & HGFE_8BIT_MASK) / 0x10);
  NI_digits[1] = number_to_char(digit_pair & DCBA_8BIT_MASK);
  digit_pair = tvb_get_guint8(parameter_tvb, 2);
  NI_digits[2] = number_to_char((digit_pair & HGFE_8BIT_MASK) / 0x10);
  NI_digits[3] = number_to_char(digit_pair & DCBA_8BIT_MASK);
  NI_digits[4] = '\0';
  proto_tree_add_text(parameter_tree, parameter_tvb, 1, 2, "Network Identity: %s", NI_digits);
  bin_code = tvb_get_ntoh24(parameter_tvb, 3);
  proto_tree_add_text(parameter_tree, parameter_tvb, 3, 3, "MLPP service domain: 0x%x", bin_code);
  proto_item_set_text(parameter_item, "MLPP precedence: NI = %s, MLPP service domain = 0x%x", NI_digits, bin_code);
}
/* ------------------------------------------------------------------
  Dissector Parameter MCID request indicators
 */
static void
dissect_isup_mcid_request_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0,MCID_REQUEST_IND_LENGTH, "MCID request indicators: 0x%x (MCID requested by Bit1=1, Holding requested by Bit2=1 see 3.31/Q.763)", indicator);
  proto_item_set_text(parameter_item, "MCID request indicators: 0x%x", indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter MCID response indicators
 */
static void
dissect_isup_mcid_response_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0,MCID_RESPONSE_IND_LENGTH, "MCID response indicators: 0x%x (MCID included if Bit1=1, Holding provided if Bit2=1 see 3.32/Q.763)", indicator);
  proto_item_set_text(parameter_item, "MCID response indicators: 0x%x", indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter Hop counter
 */
static void
dissect_isup_hop_counter_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 counter;

  counter = tvb_get_guint8(parameter_tvb, 0) & EDCBA_8BIT_MASK; /* since bits H,G and F are spare */
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, HOP_COUNTER_LENGTH, "Hop counter: %u", counter);
  proto_item_set_text(parameter_item,  "Hop counter: %u", counter);
}
/* ------------------------------------------------------------------
  Dissector Parameter Transmission medium requirement prime
 */
static void
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
static void
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
    proto_tree_add_text(parameter_tree, parameter_tvb, 1, 1, "Different meaning for Location Number: Numbering plan indicator = private numbering plan");
  proto_tree_add_uint(parameter_tree, hf_isup_address_presentation_restricted_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_screening_indicator, parameter_tvb, 1, 1, indicators2);
  offset = 2;

  address_digits_item = proto_tree_add_text(parameter_tree, parameter_tvb,
					    offset, -1,
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
static void
dissect_isup_redirection_number_restriction_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  switch (indicator & BA_8BIT_MASK) {
  case 0:
    proto_tree_add_text(parameter_tree, parameter_tvb, 0, REDIRECTION_NUMBER_RESTRICTION_LENGTH, "Presentation indicator: Presentation allowed");
    break;
  case 1:
    proto_tree_add_text(parameter_tree, parameter_tvb, 0, REDIRECTION_NUMBER_RESTRICTION_LENGTH, "Presentation indicator: Presentation restricted");
    break;
  default:
    proto_tree_add_text(parameter_tree, parameter_tvb, 0, REDIRECTION_NUMBER_RESTRICTION_LENGTH, "Presentation indicator: spare");
    break;
  }
  proto_item_set_text(parameter_item, "Redirection number restriction: 0x%x ", indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter Call transfer identity
 */
static void
dissect_isup_call_transfer_reference_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 id;

  id = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, CALL_TRANSFER_REF_LENGTH, "Call transfer identity: %u", id);
  proto_item_set_text(parameter_item,  "Call transfer reference: %u", id);
}
/* ------------------------------------------------------------------
  Dissector Parameter Loop prevention
 */
static void
dissect_isup_loop_prevention_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  if ((indicator & A_8BIT_MASK)==0) {
    proto_tree_add_text(parameter_tree, parameter_tvb, 0, LOOP_PREVENTION_IND_LENGTH, "Type: Request");
    proto_item_set_text(parameter_item, "Loop prevention indicators: Request (%u)", indicator);
  }
  else {
    proto_tree_add_text(parameter_tree, parameter_tvb, 0, LOOP_PREVENTION_IND_LENGTH, "Type: Response");
    proto_tree_add_uint(parameter_tree, hf_isup_loop_prevention_response_ind, parameter_tvb, 0, LOOP_PREVENTION_IND_LENGTH, indicator);
    proto_item_set_text(parameter_item, "Loop prevention indicators: Response (%u)", indicator);
  }
}
/* ------------------------------------------------------------------
  Dissector Parameter Call transfer number
 */
static void
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
    proto_tree_add_text(parameter_tree, parameter_tvb, 1, 1, "Different meaning for Call Transfer Number: Numbering plan indicator = private numbering plan");
  proto_tree_add_uint(parameter_tree, hf_isup_address_presentation_restricted_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_screening_indicator_enhanced, parameter_tvb, 1, 1, indicators2);
  offset = 2;

  address_digits_item = proto_tree_add_text(parameter_tree, parameter_tvb,
					    offset, -1,
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
static void
dissect_isup_ccss_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  if ((indicator & A_8BIT_MASK)==0) {
    proto_tree_add_text(parameter_tree, parameter_tvb, 0, LOOP_PREVENTION_IND_LENGTH, "CCSS call indicator: no indication");
    proto_item_set_text(parameter_item, "CCSS call indicator: no indication (%u)", indicator);
  }
  else {
    proto_tree_add_text(parameter_tree, parameter_tvb, 0, LOOP_PREVENTION_IND_LENGTH, "CCSS call indicator: CCSS call");
    proto_item_set_text(parameter_item, "CCSS call indicator: CCSS call (%u)", indicator);
  }
}
/* ------------------------------------------------------------------
 Parameter Forward GVNS
 */
static void
dissect_isup_forward_gvns_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, length, "Forward GVNS (refer to 3.66/Q.763 for detailed decoding)");
  proto_item_set_text(parameter_item, "Forward GVNS (%u Byte%s)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
 Parameter Redirect capability
 */
static void
dissect_isup_redirect_capability_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, length, "Redirect capability (format is a national matter)");
  proto_item_set_text(parameter_item, "Redirect Capability (%u Byte%s)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
  Dissector Parameter Backward GVNS
 */
static void
dissect_isup_backward_gvns_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, BACKWARD_GVNS_LENGTH, "Backward GVNS: 0x%x (refer to 3.62/Q.763 for detailed decoding)", indicator);
  proto_item_set_text(parameter_item, "Backward GVNS: 0x%x", indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter Network management controls
 */
static void
dissect_isup_network_management_controls_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_isup_temporary_alternative_routing_ind, parameter_tvb, 0,NETWORK_MANAGEMENT_CONTROLS_LENGTH, indicator);
  proto_tree_add_boolean(parameter_tree, hf_isup_extension_ind, parameter_tvb, 0,NETWORK_MANAGEMENT_CONTROLS_LENGTH, indicator);
  proto_item_set_text(parameter_item, "Network management controls: 0x%x", indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter Correlation id - no detailed dissection since defined in Rec. Q.1281
 */
static void
dissect_isup_correlation_id_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, length, "Correlation ID (-> Q.1281)");
  proto_item_set_text(parameter_item, "Correlation ID, see Q.1281 (%u Byte%s)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
  Dissector Parameter SCF id - no detailed dissection since defined in Rec. Q.1281
 */
static void
dissect_isup_scf_id_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, length, "SCF ID (-> Q.1281)");
  proto_item_set_text(parameter_item, "SCF ID, see Q.1281 (%u Byte%s)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
  Dissector Parameter Call diversion treatment indicators
 */
static void
dissect_isup_call_diversion_treatment_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_isup_call_to_be_diverted_ind, parameter_tvb, 0,CALL_DIV_TREATMENT_IND_LENGTH, indicator);
  proto_tree_add_boolean(parameter_tree, hf_isup_extension_ind, parameter_tvb, 0, CALL_DIV_TREATMENT_IND_LENGTH, indicator);
  proto_item_set_text(parameter_item, "Call diversion treatment indicators: 0x%x", indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter called IN  number
 */
static void
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
					    offset, -1,
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
static void
dissect_isup_call_offering_treatment_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_isup_call_to_be_offered_ind, parameter_tvb, 0,CALL_OFFERING_TREATMENT_IND_LENGTH, indicator);
  proto_tree_add_boolean(parameter_tree, hf_isup_extension_ind, parameter_tvb, 0, CALL_OFFERING_TREATMENT_IND_LENGTH, indicator);
  proto_item_set_text(parameter_item, "Call offering treatment indicators: 0x%x", indicator);
}
/* ------------------------------------------------------------------
 Parameter Charged party identification
 */
static void
dissect_isup_charged_party_identification_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, length, "Charged party identification (format is national network specific)");
  proto_item_set_text(parameter_item, "Charged party identification (%u Byte%s)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
  Dissector Parameter Conference treatment indicators
 */
static void
dissect_isup_conference_treatment_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_isup_conference_acceptance_ind, parameter_tvb, 0,CONFERENCE_TREATMENT_IND_LENGTH, indicator);
  proto_tree_add_boolean(parameter_tree, hf_isup_extension_ind, parameter_tvb, 0, CONFERENCE_TREATMENT_IND_LENGTH, indicator);
  proto_item_set_text(parameter_item, "Conference treatment indicators: 0x%x", indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter Display information
 */
static void
dissect_isup_display_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, length, "Display information (-> Q.931)");
  proto_item_set_text(parameter_item, "Display information (%u Byte%s)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
 Parameter UID action indicators
 */
static void
dissect_isup_uid_action_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0,UID_ACTION_IND_LENGTH, "UID action indicators: 0x%x (refer to 3.78/Q.763 for detailed decoding)", indicator);
  proto_item_set_text(parameter_item, "UID action indicators: 0x%x", indicator);
}
/* ------------------------------------------------------------------
 Parameter UID capability indicators
 */
static void
dissect_isup_uid_capability_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0,UID_CAPABILITY_IND_LENGTH, "UID capability indicators: 0x%x (refer to 3.79/Q.763 for detailed decoding)", indicator);
  proto_item_set_text(parameter_item, "UID capability indicators: 0x%x", indicator);
}
/* ------------------------------------------------------------------
 Parameter Redirect counter
 */
static void
dissect_isup_redirect_counter_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, length, "Redirect counter (format is a national matter)");
  proto_item_set_text(parameter_item, "Redirect counter (%u Byte%s)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------
  Dissector Parameter Collect call request
 */
static void
dissect_isup_collect_call_request_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  if ((indicator & A_8BIT_MASK) == 0) {
    proto_tree_add_text(parameter_tree, parameter_tvb, 0, COLLECT_CALL_REQUEST_LENGTH, "Collect call request indicator: no indication");
    proto_item_set_text(parameter_item, "Collect call reqeust: no indication (0x%x)", indicator);
  }
  else {
    proto_tree_add_text(parameter_tree, parameter_tvb, 0, COLLECT_CALL_REQUEST_LENGTH, "Collect call request indicator: collect call requested");
    proto_item_set_text(parameter_item, "Collect call reqeust: collect call requested (0x%x)", indicator);
  }
}
/* ------------------------------------------------------------------
  Dissector Parameter Generic number
 */
static void
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
    proto_tree_add_text(parameter_tree, parameter_tvb, 2, 1, "Different meaning for Generic Number: Numbering plan indicator = private numbering plan");
  proto_tree_add_uint(parameter_tree, hf_isup_address_presentation_restricted_indicator, parameter_tvb, 2, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_screening_indicator_enhanced, parameter_tvb, 2, 1, indicators2);
  offset = 3;

  address_digits_item = proto_tree_add_text(parameter_tree, parameter_tvb,
					    offset, -1,
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
static void
dissect_isup_generic_digits_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, length, "Generic digits (refer to 3.24/Q.673 for detailed decoding)");
  proto_item_set_text(parameter_item, "Generic digits (%u Byte%s)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------ */
static void
dissect_isup_unknown_parameter(tvbuff_t *parameter_tvb, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_item_set_text(parameter_item, "Parameter Type unknown/reserved (%u Byte%s)", length , plurality(length, "", "s"));
}
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------
  Dissector all optional parameters
*/
static void
dissect_isup_optional_parameter(tvbuff_t *optional_parameters_tvb,packet_info *pinfo, proto_tree *isup_tree)
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
	  dissect_isup_facility_ind_parameter(parameter_tvb, parameter_item);
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
	case PARAM_TYPE_APPLICATON_TRANS:
	  dissect_isup_application_transport_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
	  break;
	  
	default:
	  dissect_isup_unknown_parameter(parameter_tvb, parameter_item);
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
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
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
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
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
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
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
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
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
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
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
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
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
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
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
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
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
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
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
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
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
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
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
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
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
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
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
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
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
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
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
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH, MIN(parameter_length, actual_length), parameter_length );
  dissect_isup_facility_ind_parameter(parameter_tvb, parameter_item);
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
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(FACILITY_IND_LENGTH, actual_length), FACILITY_IND_LENGTH);
  dissect_isup_facility_ind_parameter(parameter_tvb, parameter_item);
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
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(FACILITY_IND_LENGTH, actual_length), FACILITY_IND_LENGTH);
  dissect_isup_facility_ind_parameter(parameter_tvb, parameter_item);
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
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
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
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
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
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
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
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
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
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
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
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
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
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH, MIN(parameter_length, actual_length), parameter_length );
  dissect_isup_cause_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += PARAMETER_POINTER_LENGTH;

  return offset;
}
/* ------------------------------------------------------------------ */
static void
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

   proto_tree_add_uint_format(isup_tree, hf_isup_message_type, message_tvb, 0, MESSAGE_TYPE_LENGTH, message_type, "Message type: %s (%u)", val_to_str(message_type, isup_message_type_value, "reserved"), message_type);
   offset +=  MESSAGE_TYPE_LENGTH;

   bufferlength = tvb_ensure_length_remaining(message_tvb, offset);
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
	pass_along_item = proto_tree_add_text(isup_tree, parameter_tvb, offset, -1, "Pass-along: %s Message (%u)", val_to_str(pa_message_type, isup_message_type_value_acro, "reserved"), pa_message_type);
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
    case MESSAGE_TYPE_APPLICATION_TRANS:
      /* no dissector necessary since no mandatory parameters included */
       opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_PRE_RELEASE_INFO:
      /* no dissector necessary since no mandatory parameters included */
       opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_SUBSEQUENT_DIR_NUM:
      /* do nothing since format is a national matter */
      proto_tree_add_text(isup_tree, parameter_tvb, 0, bufferlength, "Format is a national matter");
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
       dissect_isup_optional_parameter(optional_parameter_tvb, pinfo, isup_tree);
     }
     else
       proto_tree_add_uint_format(isup_tree, hf_isup_pointer_to_start_of_optional_part, message_tvb, offset, PARAMETER_POINTER_LENGTH, opt_parameter_pointer, "No optional parameter present (Pointer: %u)", opt_parameter_pointer);
   }
   else if (message_type !=MESSAGE_TYPE_CHARGE_INFO)
     proto_tree_add_text(isup_tree, message_tvb, 0, 0, "No optional parameters are possible with this message type");

}

/* ------------------------------------------------------------------ */
static void
dissect_isup(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *isup_tree;
	tvbuff_t *message_tvb;
	guint16 cic;
	guint8 message_type;

/* Make entries in Protocol column and Info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISUP (ITU)");

/* Extract message type field */
	message_type = tvb_get_guint8(tvb, CIC_OFFSET + CIC_LENGTH);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(message_type, isup_message_type_value_acro, "reserved"));

/* In the interest of speed, if "tree" is NULL, don't do any work not
   necessary to generate protocol tree items. */
	if (tree) {
		ti = proto_tree_add_item(tree, proto_isup, tvb, 0, -1, FALSE);
		isup_tree = proto_item_add_subtree(ti, ett_isup);

		/* dissect CIC in main dissector since pass-along message type carrying complete IUSP message w/o CIC needs
		   recursive message dissector call */
		cic =          tvb_get_letohs(tvb, CIC_OFFSET) & 0x0FFF; /*since upper 4 bits spare */

		proto_tree_add_uint_format(isup_tree, hf_isup_cic, tvb, CIC_OFFSET, CIC_LENGTH, cic, "CIC: %u", cic);

		message_tvb = tvb_new_subset(tvb, CIC_LENGTH, -1, -1);
		dissect_isup_message(message_tvb, pinfo, isup_tree);
	}
}

/* ------------------------------------------------------------------ */
static void
dissect_bicc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *bicc_tree;
	tvbuff_t *message_tvb;
	guint32 bicc_cic;
	guint8 message_type;

/* Make entries in Protocol column and Info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "BICC");

/* Extract message type field */
	message_type = tvb_get_guint8(tvb, BICC_CIC_OFFSET + BICC_CIC_LENGTH);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(message_type, isup_message_type_value_acro, "reserved"));

/* In the interest of speed, if "tree" is NULL, don't do any work not
   necessary to generate protocol tree items. */
	if (tree) {
		ti = proto_tree_add_item(tree, proto_bicc, tvb, 0, -1, FALSE);
		bicc_tree = proto_item_add_subtree(ti, ett_bicc);

		/* dissect CIC in main dissector since pass-along message type carrying complete BICC/ISUP message w/o CIC needs
		   recursive message dissector call */
		bicc_cic = tvb_get_letohl(tvb, BICC_CIC_OFFSET);

		proto_tree_add_uint_format(bicc_tree, hf_bicc_cic, tvb, BICC_CIC_OFFSET, BICC_CIC_LENGTH, bicc_cic, "CIC: %u", bicc_cic);
	
		message_tvb = tvb_new_subset(tvb, BICC_CIC_LENGTH, -1, -1);
		dissect_isup_message(message_tvb, pinfo, bicc_tree);
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
			FT_UINT16, BASE_HEX, NULL, 0x0,
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

		{ &hf_isup_cause_indicator,
			{ "Cause indicator",  "isup.cause_indicator",
			FT_UINT8, BASE_DEC, VALS(q850_cause_code_vals), 0x0,
			"", HFILL }},

		{ &hf_isup_suspend_resume_indicator,
			{ "Suspend/Resume indicator",  "isup.suspend_resume_indicator",
			FT_BOOLEAN, 8, TFS(&isup_suspend_resume_ind_value), A_8BIT_MASK,
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

		{ &hf_isup_transit_at_intermediate_exchange_ind,
			{ "Transit at intermediate exchange indicator", "isup.transit_at_intermediate_exchange_ind",
			FT_BOOLEAN, 8, TFS(&isup_transit_at_intermediate_exchange_ind_value), A_8BIT_MASK,
			"", HFILL }},

		{ &hf_isup_Release_call_ind,
			{ "Release call indicator", "isup.Release_call_ind",
			FT_BOOLEAN, 8, TFS(&isup_Release_call_indicator_value), B_8BIT_MASK,
			"", HFILL }},

		{ &hf_isup_Send_notification_ind,
			{ "Send notification indicator", "isup.Send_notification_ind",
			FT_BOOLEAN, 8, TFS(&isup_Send_notification_ind_value),C_8BIT_MASK,
			"", HFILL }},

		{ &hf_isup_Discard_message_ind_value,
			{ "Discard message indicator","isup.Discard_message_ind_value",
			FT_BOOLEAN, 8, TFS(&isup_Discard_message_ind_value), D_8BIT_MASK,
			"", HFILL }},

		{ &hf_isup_Discard_parameter_ind,		
			{ "Discard parameter indicator","isup.Discard_parameter_ind",
			FT_BOOLEAN, 8, TFS(&isup_Discard_parameter_ind_value), E_8BIT_MASK,
			"", HFILL }},

		{ &hf_isup_Pass_on_not_possible_indicator,
			{ "Pass on not possible indicator",  "isup_Pass_on_not_possible_ind",
			FT_UINT8, BASE_HEX, VALS(isup_Pass_on_not_possible_indicator_vals),GF_8BIT_MASK,
			"", HFILL }},

		{ &hf_isup_Broadband_narrowband_interworking_ind,
			{ "Broadband narrowband interworking indicator Bits JF",  "isup_Pass_on_not_possible_ind",
			FT_UINT8, BASE_HEX, VALS(ISUP_Broadband_narrowband_interworking_indicator_vals),BA_8BIT_MASK,
			"", HFILL }},

		{ &hf_isup_app_cont_ident,
			{ "Application context identifier",  "isup.app_context_identifier",
			FT_UINT8, BASE_DEC, VALS(isup_application_transport_parameter_value),0x0,
			"", HFILL }},

		{ &hf_isup_app_Release_call_ind, 
			{ "Release call indicator (RCI)",  "isup.app_Release_call_ indicator",
			FT_BOOLEAN, 8, TFS(&isup_Release_call_indicator_value), A_8BIT_MASK,
			"", HFILL }},

		{ &hf_isup_app_Send_notification_ind, 
			{ "Send notification indicator (SNI)",  "isup.app_Send_notification_ind",
			FT_BOOLEAN, 8, TFS(&isup_Send_notification_ind_value), B_8BIT_MASK,
			"", HFILL }},

		{ &hf_isup_apm_segmentation_ind,
		        { "APM segmentation indicator",  "isup.apm_segmentation_ind",
			FT_UINT8, BASE_DEC, VALS(isup_APM_segmentation_ind_value), FEDCBA_8BIT_MASK,
			"", HFILL }},

		{ &hf_isup_apm_si_ind, 
			{ "Sequence indicator (SI)",  "isup.APM_Sequence_ind",
			FT_BOOLEAN, 8, TFS(&isup_Sequence_ind_value), G_8BIT_MASK,
			"", HFILL }},
		{ &hf_bat_ase_identifier,
			{ "BAT ASE Identifiers",  "bicc.bat_ase_identifier",
			FT_UINT8, BASE_HEX, VALS(bat_ase_list_of_Identifiers_vals),0x0,	
			"", HFILL }},
  
		{ &hf_length_indicator,
			{ "BAT ASE Element length indicator",  "bicc.bat_ase_length_indicator",
			FT_UINT8, BASE_DEC, NULL,0x0,
			"", HFILL }},

		{ &hf_Action_Indicator,
			{ "BAT ASE action indicator field",  "bicc.bat_ase_bat_ase_action_indicator_field",
			FT_UINT8, BASE_HEX, VALS(bat_ase_action_indicator_field_vals),0x00,	
			"", HFILL }},

		{ &hf_Instruction_ind_for_general_action,
			{ "BAT ASE Instruction indicator for general action",  "bicc.bat_ase_Instruction_ind_for_general_action",
			FT_UINT8, BASE_HEX, VALS(Instruction_indicator_for_general_action_vals),0x03,	
			"", HFILL }},

		{ &hf_Send_notification_ind_for_general_action, 
			{ "Send notification indicator for general action",  "bicc.bat_ase_Send_notification_ind_for_general_action",
			FT_BOOLEAN, 8, TFS(&isup_Send_notification_ind_value), 0x04,
			"", HFILL }},

		{ &hf_Instruction_ind_for_pass_on_not_possible, 
			{ "Instruction ind for pass-on not possible",  "bicc.bat_ase_Instruction_ind_for_pass_on_not_possible",
			FT_UINT8, BASE_HEX, VALS(Instruction_indicator_for_pass_on_not_possible_vals),0x30,	
			"", HFILL }},

		{ &hf_Send_notification_ind_for_pass_on_not_possible, 
			{ "Send notification indication for pass-on not possible",  "bicc.bat_ase_Send_notification_ind_for_pass_on_not_possible",
			FT_BOOLEAN, 8, TFS(&isup_Send_notification_ind_value), 0x40,
			"", HFILL }},

		{ &hf_BCTP_Version_Indicator,
			{ "BCTP Version Indicator",  "bicc.bat_ase_BCTP_Version_Indicator",
			FT_UINT8, BASE_DEC, NULL,0x1f,
			"", HFILL }},
	
		{ &hf_BVEI,
			{ "BCTP Version Error Indicator",  "bicc.bat_ase_BCTP_BVEI",
			FT_BOOLEAN, 8, TFS(&BCTP_BVEI_value), 0x40,
			"", HFILL }},

		{ &hf_Tunnelled_Protocol_Indicator,
			{ "Tunnelled Protocol Indicator",  "bicc.bat_ase_BCTP_Tunnelled_Protocol_Indicator",
			FT_UINT8, BASE_DEC, VALS(BCTP_Tunnelled_Protocol_Indicator_vals),0x3f,	
			"", HFILL }},

		{ &hf_TPEI,
			{ "Tunnelled Protocol Error Indicator value",  "bicc.bat_ase_BCTP_tpei",
			FT_BOOLEAN, 8, TFS(&BCTP_TPEI_value), 0x40,
			"", HFILL }},

		{ &hf_bncid,
			{ "Backbone Network Connection Identifier (BNCId)", "bat_ase.bncid",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			  "", HFILL }},

		{ &hf_bat_ase_biwfa,
			{ "Interworking Function Address( X.213 NSAP encoded)", "bat_ase_biwfa",
			FT_BYTES, BASE_HEX, NULL, 0x0,
			  "", HFILL }},

		{ &hf_afi,
			{ "X.213 Address Format Information ( AFI )",  "x213.afi",
			FT_UINT8, BASE_HEX, VALS(x213_afi_value),0x0,	
			"", HFILL }},

		{ &hf_characteristics,
			{ "Backbone network connection characteristics", "bat_ase.char",
			FT_UINT8, BASE_HEX, VALS(bearer_network_connection_characteristics_vals),0x0,	
			  "", HFILL }},

		{ &hf_Organization_Identifier,
			{ "Organization identifier subfield ",  "bat_ase.organization_identifier_subfield",
			FT_UINT8, BASE_DEC, VALS(bat_ase_organization_identifier_subfield_vals),0x0,
			"", HFILL }},

		{ &hf_codec_type,
			{ "ITU-T codec type subfield",  "bat_ase.ITU_T_codec_type_subfield",
			FT_UINT8, BASE_HEX, VALS(ITU_T_codec_type_subfield_vals),0x0,
			"", HFILL }},

		{ &hf_bearer_control_tunneling,
			{ "Bearer control tunneling",  "bat_ase.bearer_control_tunneling",
			FT_BOOLEAN, 8, TFS(&Bearer_Control_Tunnelling_ind_value),0x01,
			"", HFILL }},

		{ &hf_BAT_ASE_Comp_Report_Reason,
			{ "Compabillity report reason",  "bat_ase.Comp_Report_Reason",
			FT_UINT8, BASE_HEX, VALS(BAT_ASE_Report_Reason_vals),0x0,
			"", HFILL }},


		{ &hf_BAT_ASE_Comp_Report_ident,
			{ "Bearer control tunneling",  "bat_ase.bearer_control_tunneling",
			FT_UINT8, BASE_HEX, VALS(bat_ase_list_of_Identifiers_vals),0x0,
			"", HFILL }},

		{ &hf_BAT_ASE_Comp_Report_diagnostic,
			{ "Diagnostics",  "Comp_Report_diagnostic",
			FT_UINT16, BASE_HEX, NULL,0x0,
			"", HFILL }},

		{ &hf_Local_BCU_ID,
			{ "Local BCU ID",  "bat_ase.Local_BCU_ID",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			  "", HFILL }},

		{ &hf_late_cut_trough_cap_ind,
			{ "Late Cut-through capability indicator",  "bat_ase.late_cut_trough_cap_ind",
			FT_BOOLEAN, 8, TFS(&late_cut_trough_cap_ind_value),0x01,
			"", HFILL }},

		{ &hf_bat_ase_signal,
			{ "Q.765.5 - Signal Type",  "bat_ase.signal_type",
			FT_UINT8, BASE_HEX, VALS(BAt_ASE_Signal_Type_vals),0x0,
			"", HFILL }},

		{ &hf_bat_ase_duration,
			{ "Duration in ms",  "bat_ase.signal_type",
			FT_UINT16, BASE_DEC, NULL,0x0,
			"", HFILL }},

		{ &hf_bat_ase_bearer_redir_ind,
			{ "Redirection Indicator",  "bat_ase_bearer_redir_ind",
			FT_UINT8, BASE_HEX, VALS(Bearer_Redirection_Indicator_vals),0x0,
			"", HFILL }},


	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_isup,
		&ett_isup_parameter,
		&ett_isup_address_digits,
		&ett_isup_pass_along_message,
		&ett_isup_circuit_state_ind,
		&ett_bat_ase,
		&ett_bat_ase_element,
		&ett_bat_ase_iwfa
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
  dissector_handle_t isup_handle;
 
  isup_handle = create_dissector_handle(dissect_isup, proto_isup);
  dissector_add("mtp3.service_indicator", MTP3_ISUP_SERVICE_INDICATOR, isup_handle);
  dissector_add("m3ua.protocol_data_si", MTP3_ISUP_SERVICE_INDICATOR, isup_handle);

}

void
proto_register_bicc(void)
{
/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_bicc_cic,
			{ "Call identification Code (CIC)",           "bicc.cic",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			  "", HFILL }},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_bicc
	};
	proto_bicc = proto_register_protocol("Bearer Independent Call Control ",
	    "BICC", "bicc"); 
/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_bicc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

/* Register isup with the sub-laying MTP L3 dissector */
void
proto_reg_handoff_bicc(void)
{
  dissector_handle_t bicc_handle;
  sdp_handle = find_dissector("sdp");

  bicc_handle = create_dissector_handle(dissect_bicc, proto_bicc);
  dissector_add("mtp3.service_indicator", MTP3_BICC_SERVICE_INDICATOR, bicc_handle);
  dissector_add("m3ua.protocol_data_si", MTP3_BICC_SERVICE_INDICATOR, bicc_handle);
}
