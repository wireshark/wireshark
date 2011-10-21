/* packet-isup.c
 * Routines for ISUP dissection
 * Copyright 2001, Martina Obermeier <martina.obermeier@icn.siemens.de>
 *
 * Copyright 2004-2005, Anders Broman <anders.broman@ericsson.com>
 * Modified 2003-09-10 by Anders Broman
 *          <anders.broman@ericsson.com>
 * Inserted routines for BICC dissection according to Q.765.5 Q.1902 Q.1970 Q.1990,
 * calling SDP dissector for RFC2327 decoding.
 * Modified 2004-01-10 by Anders Broman to add abillity to dissect
 * Content type application/ISUP RFC 3204 used in SIP-T
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * References:
 * ISUP:
 * http://www.itu.int/rec/recommendation.asp?type=products&lang=e&parent=T-REC-Q
 * Q.763-199912, Q.763-200212Amd2
 * ITU-T Q.763/Amd.1 (03/2001)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/stats_tree.h>
#include <epan/asn1.h>
#include <prefs.h>
#include "packet-q931.h"
#include "packet-isup.h"
#include "packet-e164.h"
#include "packet-charging_ase.h"
#include <epan/sctpppids.h>
#include <epan/emem.h>
#include <epan/circuit.h>
#include <epan/reassemble.h>
#include <packet-mtp3.h>

static gint isup_standard = ITU_STANDARD;

#define MTP3_ISUP_SERVICE_INDICATOR     5
#define MTP3_BICC_SERVICE_INDICATOR     13
#define ASCII_NUMBER_DELTA              0x30
#define ASCII_LETTER_DELTA              0x37

/* Definition of protocol field values und lengths */

/* Definition of Message Types */
#define MESSAGE_TYPE_INITIAL_ADDR        1
#define MESSAGE_TYPE_SUBSEQ_ADDR         2
#define MESSAGE_TYPE_INFO_REQ            3
#define MESSAGE_TYPE_INFO                4
#define MESSAGE_TYPE_CONTINUITY          5
#define MESSAGE_TYPE_ADDR_CMPL           6
#define MESSAGE_TYPE_CONNECT             7
#define MESSAGE_TYPE_FORW_TRANS          8
#define MESSAGE_TYPE_ANSWER              9
#define MESSAGE_TYPE_RELEASE            12
#define MESSAGE_TYPE_SUSPEND            13
#define MESSAGE_TYPE_RESUME             14
#define MESSAGE_TYPE_REL_CMPL           16
#define MESSAGE_TYPE_CONT_CHECK_REQ     17
#define MESSAGE_TYPE_RESET_CIRCUIT      18
#define MESSAGE_TYPE_BLOCKING           19
#define MESSAGE_TYPE_UNBLOCKING         20
#define MESSAGE_TYPE_BLOCK_ACK          21
#define MESSAGE_TYPE_UNBLOCK_ACK        22
#define MESSAGE_TYPE_CIRC_GRP_RST       23
#define MESSAGE_TYPE_CIRC_GRP_BLCK      24
#define MESSAGE_TYPE_CIRC_GRP_UNBL      25
#define MESSAGE_TYPE_CIRC_GRP_BL_ACK    26
#define MESSAGE_TYPE_CIRC_GRP_UNBL_ACK  27
#define MESSAGE_TYPE_FACILITY_REQ       31
#define MESSAGE_TYPE_FACILITY_ACC       32
#define MESSAGE_TYPE_FACILITY_REJ       33
#define MESSAGE_TYPE_LOOP_BACK_ACK      36
#define MESSAGE_TYPE_PASS_ALONG         40
#define MESSAGE_TYPE_CIRC_GRP_RST_ACK   41
#define MESSAGE_TYPE_CIRC_GRP_QRY       42
#define MESSAGE_TYPE_CIRC_GRP_QRY_RSP   43
#define MESSAGE_TYPE_CALL_PROGRSS       44
#define MESSAGE_TYPE_USER2USER_INFO     45
#define MESSAGE_TYPE_UNEQUIPPED_CIC     46
#define MESSAGE_TYPE_CONFUSION          47
#define MESSAGE_TYPE_OVERLOAD           48
#define MESSAGE_TYPE_CHARGE_INFO        49
#define MESSAGE_TYPE_NETW_RESRC_MGMT    50
#define MESSAGE_TYPE_FACILITY           51
#define MESSAGE_TYPE_USER_PART_TEST     52
#define MESSAGE_TYPE_USER_PART_AVAIL    53
#define MESSAGE_TYPE_IDENT_REQ          54
#define MESSAGE_TYPE_IDENT_RSP          55
#define MESSAGE_TYPE_SEGMENTATION       56
#define MESSAGE_TYPE_LOOP_PREVENTION    64
#define MESSAGE_TYPE_APPLICATION_TRANS  65
#define MESSAGE_TYPE_PRE_RELEASE_INFO   66
#define MESSAGE_TYPE_SUBSEQUENT_DIR_NUM 67

#define ANSI_ISUP_MESSAGE_TYPE_CIRCUIT_RES_ACK  0xE9
#define ANSI_ISUP_MESSAGE_TYPE_CIRCUIT_RES      0xEA
#define ANSI_ISUP_MESSAGE_TYPE_CCT_VAL_TEST_RSP 0xEB
#define ANSI_ISUP_MESSAGE_TYPE_CCT_VAL_TEST     0xEC
#define ANSI_ISUP_MESSAGE_TYPE_EXIT             0xED

static const value_string isup_message_type_value[] = {
  { MESSAGE_TYPE_INITIAL_ADDR,                "Initial address"},
  { MESSAGE_TYPE_SUBSEQ_ADDR,                 "Subsequent address"},
  { MESSAGE_TYPE_INFO_REQ,                    "Information request (national use)"},
  { MESSAGE_TYPE_INFO,                        "Information (national use)"},
  { MESSAGE_TYPE_CONTINUITY,                  "Continuity"},
  { MESSAGE_TYPE_ADDR_CMPL,                   "Address complete"},
  { MESSAGE_TYPE_CONNECT,                     "Connect"},
  { MESSAGE_TYPE_FORW_TRANS,                  "Forward transfer"},
  { MESSAGE_TYPE_ANSWER,                      "Answer"},

  { 0x0a,                                     "Reserved (used in 1984 version)"},
  { 0x0b,                                     "Reserved (used in 1984 version)"},

  { MESSAGE_TYPE_RELEASE,                     "Release"},
  { MESSAGE_TYPE_SUSPEND,                     "Suspend"},
  { MESSAGE_TYPE_RESUME,                      "Resume"},
  { MESSAGE_TYPE_REL_CMPL,                    "Release complete"},
  { MESSAGE_TYPE_CONT_CHECK_REQ,              "Continuity check request"},
  { MESSAGE_TYPE_RESET_CIRCUIT,               "Reset Circuit"},
  { MESSAGE_TYPE_BLOCKING,                    "Blocking"},
  { MESSAGE_TYPE_UNBLOCKING,                  "Unblocking"},
  { MESSAGE_TYPE_BLOCK_ACK,                   "Blocking acknowledgement"},
  { MESSAGE_TYPE_UNBLOCK_ACK,                 "Unblocking acknowledgment"},
  { MESSAGE_TYPE_CIRC_GRP_RST,                "Circuit group reset"},
  { MESSAGE_TYPE_CIRC_GRP_BLCK,               "Circuit group blocking"},
  { MESSAGE_TYPE_CIRC_GRP_UNBL,               "Circuit group unblocking"},
  { MESSAGE_TYPE_CIRC_GRP_BL_ACK,             "Circuit group blocking acknowledgement"},
  { MESSAGE_TYPE_CIRC_GRP_UNBL_ACK,           "Circuit group unblocking acknowledgement"},

  { 28,                                      "Reserved (used in 1988 version)"},
  { 29,                                      "Reserved (used in 1988 version)"},
  { 30,                                      "Reserved (used in 1988 version)"},

  { MESSAGE_TYPE_FACILITY_REQ,                "Facility request"},
  { MESSAGE_TYPE_FACILITY_ACC,                "Facility accepted"},
  { MESSAGE_TYPE_FACILITY_REJ,                "Facility reject"},

  { 34,                                      "Reserved (used in 1984 version)"},
  { 35,                                      "Reserved (used in 1984 version)"},

  { MESSAGE_TYPE_LOOP_BACK_ACK,               "Loop back acknowledgement (national use)"},

  { 37,                                      "Reserved (used in 1984 version)"},
  { 38,                                      "Reserved (used in 1984 version)"},
  { 39,                                      "Reserved (used in 1984 version)"},

  { MESSAGE_TYPE_PASS_ALONG,                  "Pass-along (national use)"},
  { MESSAGE_TYPE_CIRC_GRP_RST_ACK,            "Circuit group reset acknowledgement"},
  { MESSAGE_TYPE_CIRC_GRP_QRY,                "Circuit group query (national use)"},
  { MESSAGE_TYPE_CIRC_GRP_QRY_RSP,            "Circuit group query response (national use)"},
  { MESSAGE_TYPE_CALL_PROGRSS,                "Call progress"},
  { MESSAGE_TYPE_USER2USER_INFO,              "User-to-user information"},
  { MESSAGE_TYPE_UNEQUIPPED_CIC,              "Unequipped CIC (national use)"},
  { MESSAGE_TYPE_CONFUSION,                   "Confusion"},
  { MESSAGE_TYPE_OVERLOAD,                    "Overload (national use)"},
  { MESSAGE_TYPE_CHARGE_INFO,                 "Charge information (national use)"},
  { MESSAGE_TYPE_NETW_RESRC_MGMT,             "Network resource management"},
  { MESSAGE_TYPE_FACILITY,                    "Facility"},
  { MESSAGE_TYPE_USER_PART_TEST,              "User part test"},
  { MESSAGE_TYPE_USER_PART_AVAIL,             "User part available"},
  { MESSAGE_TYPE_IDENT_REQ,                   "Identification request"},
  { MESSAGE_TYPE_IDENT_RSP,                   "Identification response"},
  { MESSAGE_TYPE_SEGMENTATION,                "Segmentation"},

  { 57,                                       "Reserved (used in B-ISUP)"},
  { 58,                                       "Reserved (used in B-ISUP)"},
  { 59,                                       "Reserved (used in B-ISUP)"},
  { 60,                                       "Reserved (used in B-ISUP)"},
  { 61,                                       "Reserved (used in B-ISUP)"},

  { 63,                                       "Unknown"},
  { 63,                                       "Unknown"},

  { MESSAGE_TYPE_LOOP_PREVENTION,             "Loop prevention"},
  { MESSAGE_TYPE_APPLICATION_TRANS,           "Application transport"},
  { MESSAGE_TYPE_PRE_RELEASE_INFO,            "Pre-release information"},
  { MESSAGE_TYPE_SUBSEQUENT_DIR_NUM,          "Subsequent Directory Number (national use)"},
  { 0,                                  NULL}};
static value_string_ext isup_message_type_value_ext = VALUE_STRING_EXT_INIT(isup_message_type_value);

static const value_string ansi_isup_message_type_value[] = {
  { MESSAGE_TYPE_INITIAL_ADDR,                "Initial address"},
  { MESSAGE_TYPE_SUBSEQ_ADDR,                 "Subsequent address"},
  { MESSAGE_TYPE_INFO_REQ,                    "Information request (national use)"},
  { MESSAGE_TYPE_INFO,                        "Information (national use)"},
  { MESSAGE_TYPE_CONTINUITY,                  "Continuity"},
  { MESSAGE_TYPE_ADDR_CMPL,                   "Address complete"},
  { MESSAGE_TYPE_CONNECT,                     "Connect"},
  { MESSAGE_TYPE_FORW_TRANS,                  "Forward transfer"},
  { MESSAGE_TYPE_ANSWER,                      "Answer"},
  { MESSAGE_TYPE_RELEASE,                     "Release"},
  { MESSAGE_TYPE_SUSPEND,                     "Suspend"},
  { MESSAGE_TYPE_RESUME,                      "Resume"},
  { MESSAGE_TYPE_REL_CMPL,                    "Release complete"},
  { MESSAGE_TYPE_CONT_CHECK_REQ,              "Continuity check request"},
  { MESSAGE_TYPE_RESET_CIRCUIT,               "Reset Circuit"},
  { MESSAGE_TYPE_BLOCKING,                    "Blocking"},
  { MESSAGE_TYPE_UNBLOCKING,                  "Unblocking"},
  { MESSAGE_TYPE_BLOCK_ACK,                   "Blocking acknowledgement"},
  { MESSAGE_TYPE_UNBLOCK_ACK,                 "Unblocking acknowledgment"},
  { MESSAGE_TYPE_CIRC_GRP_RST,                "Circuit group reset"},
  { MESSAGE_TYPE_CIRC_GRP_BLCK,               "Circuit group blocking"},
  { MESSAGE_TYPE_CIRC_GRP_UNBL,               "Circuit group unblocking"},
  { MESSAGE_TYPE_CIRC_GRP_BL_ACK,             "Circuit group blocking acknowledgement"},
  { MESSAGE_TYPE_CIRC_GRP_UNBL_ACK,           "Circuit group unblocking acknowledgement"},
  { MESSAGE_TYPE_FACILITY_REQ,                "Facility request"},
  { MESSAGE_TYPE_FACILITY_ACC,                "Facility accepted"},
  { MESSAGE_TYPE_FACILITY_REJ,                "Facility reject"},
  { MESSAGE_TYPE_LOOP_BACK_ACK,               "Loop back acknowledgement (national use)"},
  { MESSAGE_TYPE_PASS_ALONG,                  "Pass-along (national use)"},
  { MESSAGE_TYPE_CIRC_GRP_RST_ACK,            "Circuit group reset acknowledgement"},
  { MESSAGE_TYPE_CIRC_GRP_QRY,                "Circuit group query (national use)"},
  { MESSAGE_TYPE_CIRC_GRP_QRY_RSP,            "Circuit group query response (national use)"},
  { MESSAGE_TYPE_CALL_PROGRSS,                "Call progress"},
  { MESSAGE_TYPE_USER2USER_INFO,              "User-to-user information"},
  { MESSAGE_TYPE_UNEQUIPPED_CIC,              "Unequipped CIC (national use)"},
  { MESSAGE_TYPE_CONFUSION,                   "Confusion"},
  { MESSAGE_TYPE_OVERLOAD,                    "Overload (national use)"},
  { MESSAGE_TYPE_CHARGE_INFO,                 "Charge information (national use)"},
  { MESSAGE_TYPE_NETW_RESRC_MGMT,             "Network resource management"},
  { MESSAGE_TYPE_FACILITY,                    "Facility"},
  { MESSAGE_TYPE_USER_PART_TEST,              "User part test"},
  { MESSAGE_TYPE_USER_PART_AVAIL,             "User part available"},
  { MESSAGE_TYPE_IDENT_REQ,                   "Identification request"},
  { MESSAGE_TYPE_IDENT_RSP,                   "Identification response"},
  { MESSAGE_TYPE_SEGMENTATION,                "Segmentation"},
  { MESSAGE_TYPE_LOOP_PREVENTION,             "Loop prevention"},
  { MESSAGE_TYPE_APPLICATION_TRANS,           "Application transport"},
  { MESSAGE_TYPE_PRE_RELEASE_INFO,            "Pre-release information"},
  { MESSAGE_TYPE_SUBSEQUENT_DIR_NUM,          "Subsequent Directory Number (national use)"},
  { ANSI_ISUP_MESSAGE_TYPE_CIRCUIT_RES_ACK,   "Circuit Reservation Acknowledge"},
  { ANSI_ISUP_MESSAGE_TYPE_CIRCUIT_RES,       "Circuit Reservation"},
  { ANSI_ISUP_MESSAGE_TYPE_CCT_VAL_TEST_RSP,  "Circuit Validation Test Response"},
  { ANSI_ISUP_MESSAGE_TYPE_CCT_VAL_TEST,      "Circuit Validation Test"},
  { ANSI_ISUP_MESSAGE_TYPE_EXIT,              "Exit"},
  { 0,                                  NULL}};
static value_string_ext ansi_isup_message_type_value_ext = VALUE_STRING_EXT_INIT(ansi_isup_message_type_value);

/* Same as above but in acronym form (for the Info column) */
static const value_string isup_message_type_value_acro[] = {
  { MESSAGE_TYPE_INITIAL_ADDR,                "IAM"},
  { MESSAGE_TYPE_SUBSEQ_ADDR,                 "SAM"},
  { MESSAGE_TYPE_INFO_REQ,                    "INR"},
  { MESSAGE_TYPE_INFO,                        "INF"},
  { MESSAGE_TYPE_CONTINUITY,                  "COT"},
  { MESSAGE_TYPE_ADDR_CMPL,                   "ACM"},
  { MESSAGE_TYPE_CONNECT,                     "CON"},
  { MESSAGE_TYPE_FORW_TRANS,                  "FOT"},
  { MESSAGE_TYPE_ANSWER,                      "ANM"},

  { 0x0a,                                     "Reserved"},
  { 0x0b,                                     "Reserved"},

  { MESSAGE_TYPE_RELEASE,                     "REL"},
  { MESSAGE_TYPE_SUSPEND,                     "SUS"},
  { MESSAGE_TYPE_RESUME,                      "RES"},
  { MESSAGE_TYPE_REL_CMPL,                    "RLC"},
  { MESSAGE_TYPE_CONT_CHECK_REQ,              "CCR"},
  { MESSAGE_TYPE_RESET_CIRCUIT,               "RSC"},
  { MESSAGE_TYPE_BLOCKING,                    "BLO"},
  { MESSAGE_TYPE_UNBLOCKING,                  "UBL"},
  { MESSAGE_TYPE_BLOCK_ACK,                   "BLA"},
  { MESSAGE_TYPE_UNBLOCK_ACK,                 "UBLA"},
  { MESSAGE_TYPE_CIRC_GRP_RST,                "GRS"},
  { MESSAGE_TYPE_CIRC_GRP_BLCK,               "CGB"},
  { MESSAGE_TYPE_CIRC_GRP_UNBL,               "CGU"},
  { MESSAGE_TYPE_CIRC_GRP_BL_ACK,             "CGBA"},
  { MESSAGE_TYPE_CIRC_GRP_UNBL_ACK,           "CGUA"},

  { 28,                                      "Reserved"},
  { 29,                                      "Reserved"},
  { 30,                                      "Reserved"},

  { MESSAGE_TYPE_FACILITY_REQ,                "FAR"},
  { MESSAGE_TYPE_FACILITY_ACC,                "FAA"},
  { MESSAGE_TYPE_FACILITY_REJ,                "FRJ"},

  { 34,                                      "Reserved"},
  { 35,                                      "Reserved"},

  { MESSAGE_TYPE_LOOP_BACK_ACK,               "LPA"},

  { 37,                                      "Reserved"},
  { 38,                                      "Reserved"},
  { 39,                                      "Reserved"},

  { MESSAGE_TYPE_PASS_ALONG,                  "PAM"},
  { MESSAGE_TYPE_CIRC_GRP_RST_ACK,            "GRA"},
  { MESSAGE_TYPE_CIRC_GRP_QRY,                "CQM"},
  { MESSAGE_TYPE_CIRC_GRP_QRY_RSP,            "CQR"},
  { MESSAGE_TYPE_CALL_PROGRSS,                "CPG"},
  { MESSAGE_TYPE_USER2USER_INFO,              "UUI"},
  { MESSAGE_TYPE_UNEQUIPPED_CIC,              "UCIC"},
  { MESSAGE_TYPE_CONFUSION,                   "CFN"},
  { MESSAGE_TYPE_OVERLOAD,                    "OLM"},
  { MESSAGE_TYPE_CHARGE_INFO,                 "CRG"},
  { MESSAGE_TYPE_NETW_RESRC_MGMT,             "NRM"},
  { MESSAGE_TYPE_FACILITY,                    "FAC"},
  { MESSAGE_TYPE_USER_PART_TEST,              "UPT"},
  { MESSAGE_TYPE_USER_PART_AVAIL,             "UPA"},
  { MESSAGE_TYPE_IDENT_REQ,                   "IDR"},
  { MESSAGE_TYPE_IDENT_RSP,                   "IDS"},
  { MESSAGE_TYPE_SEGMENTATION,                "SGM"},

  { 57,                                       "Reserved"},
  { 58,                                       "Reserved"},
  { 59,                                       "Reserved"},
  { 60,                                       "Reserved"},
  { 61,                                       "Reserved"},

  { 63,                                       "Unknown"},
  { 63,                                       "Unknown"},

  { MESSAGE_TYPE_LOOP_PREVENTION,             "LOP"},
  { MESSAGE_TYPE_APPLICATION_TRANS,           "APM"},
  { MESSAGE_TYPE_PRE_RELEASE_INFO,            "PRI"},
  { MESSAGE_TYPE_SUBSEQUENT_DIR_NUM,          "SDN"},
  { 0,                                  NULL}};
value_string_ext isup_message_type_value_acro_ext = VALUE_STRING_EXT_INIT(isup_message_type_value_acro);

  /* Same as above but in acronym form (for the Info column) */
static const value_string ansi_isup_message_type_value_acro[] = {
  { MESSAGE_TYPE_INITIAL_ADDR,                "IAM"},
  { MESSAGE_TYPE_SUBSEQ_ADDR,                 "SAM"},
  { MESSAGE_TYPE_INFO_REQ,                    "INR"},
  { MESSAGE_TYPE_INFO,                        "INF"},
  { MESSAGE_TYPE_CONTINUITY,                  "COT"},
  { MESSAGE_TYPE_ADDR_CMPL,                   "ACM"},
  { MESSAGE_TYPE_CONNECT,                     "CON"},
  { MESSAGE_TYPE_FORW_TRANS,                  "FOT"},
  { MESSAGE_TYPE_ANSWER,                      "ANM"},
  { MESSAGE_TYPE_RELEASE,                     "REL"},
  { MESSAGE_TYPE_SUSPEND,                     "SUS"},
  { MESSAGE_TYPE_RESUME,                      "RES"},
  { MESSAGE_TYPE_REL_CMPL,                    "RLC"},
  { MESSAGE_TYPE_CONT_CHECK_REQ,              "CCR"},
  { MESSAGE_TYPE_RESET_CIRCUIT,               "RSC"},
  { MESSAGE_TYPE_BLOCKING,                    "BLO"},
  { MESSAGE_TYPE_UNBLOCKING,                  "UBL"},
  { MESSAGE_TYPE_BLOCK_ACK,                   "BLA"},
  { MESSAGE_TYPE_UNBLOCK_ACK,                 "UBLA"},
  { MESSAGE_TYPE_CIRC_GRP_RST,                "GRS"},
  { MESSAGE_TYPE_CIRC_GRP_BLCK,               "CGB"},
  { MESSAGE_TYPE_CIRC_GRP_UNBL,               "CGU"},
  { MESSAGE_TYPE_CIRC_GRP_BL_ACK,             "CGBA"},
  { MESSAGE_TYPE_CIRC_GRP_UNBL_ACK,           "CGUA"},
  { MESSAGE_TYPE_FACILITY_REQ,                "FAR"},
  { MESSAGE_TYPE_FACILITY_ACC,                "FAA"},
  { MESSAGE_TYPE_FACILITY_REJ,                "FRJ"},
  { MESSAGE_TYPE_LOOP_BACK_ACK,               "LPA"},
  { MESSAGE_TYPE_PASS_ALONG,                  "PAM"},
  { MESSAGE_TYPE_CIRC_GRP_RST_ACK,            "GRA"},
  { MESSAGE_TYPE_CIRC_GRP_QRY,                "CQM"},
  { MESSAGE_TYPE_CIRC_GRP_QRY_RSP,            "CQR"},
  { MESSAGE_TYPE_CALL_PROGRSS,                "CPG"},
  { MESSAGE_TYPE_USER2USER_INFO,              "UUI"},
  { MESSAGE_TYPE_UNEQUIPPED_CIC,              "UCIC"},
  { MESSAGE_TYPE_CONFUSION,                   "CFN"},
  { MESSAGE_TYPE_OVERLOAD,                    "OLM"},
  { MESSAGE_TYPE_CHARGE_INFO,                 "CRG"},
  { MESSAGE_TYPE_NETW_RESRC_MGMT,             "NRM"},
  { MESSAGE_TYPE_FACILITY,                    "FAC"},
  { MESSAGE_TYPE_USER_PART_TEST,              "UPT"},
  { MESSAGE_TYPE_USER_PART_AVAIL,             "UPA"},
  { MESSAGE_TYPE_IDENT_REQ,                   "IDR"},
  { MESSAGE_TYPE_IDENT_RSP,                   "IDS"},
  { MESSAGE_TYPE_SEGMENTATION,                "SGM"},
  { MESSAGE_TYPE_LOOP_PREVENTION,             "LOP"},
  { MESSAGE_TYPE_APPLICATION_TRANS,           "APM"},
  { MESSAGE_TYPE_PRE_RELEASE_INFO,            "PRI"},
  { MESSAGE_TYPE_SUBSEQUENT_DIR_NUM,          "SDN"},
  { ANSI_ISUP_MESSAGE_TYPE_CIRCUIT_RES_ACK,   "CRA"},
  { ANSI_ISUP_MESSAGE_TYPE_CIRCUIT_RES,       "CRM"},
  { ANSI_ISUP_MESSAGE_TYPE_CCT_VAL_TEST_RSP,  "CVR"},
  { ANSI_ISUP_MESSAGE_TYPE_CCT_VAL_TEST,      "CVT"},
  { ANSI_ISUP_MESSAGE_TYPE_EXIT,              "EXIT"},
  { 0,                                  NULL}};
static value_string_ext ansi_isup_message_type_value_acro_ext = VALUE_STRING_EXT_INIT(ansi_isup_message_type_value_acro);

const value_string isup_parameter_type_value[] = {
  { PARAM_TYPE_END_OF_OPT_PARAMS,         "End of optional parameters"},
  { PARAM_TYPE_CALL_REF,                  "Call Reference (national use)"},
  { PARAM_TYPE_TRANSM_MEDIUM_REQU,        "Transmission medium requirement"},
  { PARAM_TYPE_ACC_TRANSP,                "Access transport"},
  { PARAM_TYPE_CALLED_PARTY_NR,           "Called party number"},
  { PARAM_TYPE_SUBSQT_NR,                 "Subsequent number"},
  { PARAM_TYPE_NATURE_OF_CONN_IND,        "Nature of connection indicators"},
  { PARAM_TYPE_FORW_CALL_IND,             "Forward call indicators"},
  { PARAM_TYPE_OPT_FORW_CALL_IND,         "Optional forward call indicators"},
  { PARAM_TYPE_CALLING_PRTY_CATEG,        "Calling party's category"},
  { PARAM_TYPE_CALLING_PARTY_NR,          "Calling party number"},
  { PARAM_TYPE_REDIRECTING_NR,            "Redirecting number"},
  { PARAM_TYPE_REDIRECTION_NR,            "Redirection number"},
  { PARAM_TYPE_CONNECTION_REQ,            "Connection request"},
  { PARAM_TYPE_INFO_REQ_IND,              "Information request indicators (national use)"},
  { PARAM_TYPE_INFO_IND,                  "Information indicators (national use)"},
  { PARAM_TYPE_CONTINUITY_IND,            "Continuity request"},
  { PARAM_TYPE_BACKW_CALL_IND,            "Backward call indicators"},
  { PARAM_TYPE_CAUSE_INDICATORS,          "Cause indicators"},
  { PARAM_TYPE_REDIRECTION_INFO,          "Redirection information"},
  { PARAM_TYPE_CIRC_GRP_SV_MSG_TYPE,      "Circuit group supervision message type"},
  { PARAM_TYPE_RANGE_AND_STATUS,          "Range and Status"},
  { PARAM_TYPE_FACILITY_IND,              "Facility indicator"},
  { PARAM_TYPE_CLSD_USR_GRP_ILOCK_CD,     "Closed user group interlock code"},
  { PARAM_TYPE_USER_SERVICE_INFO,         "User service information"},
  { PARAM_TYPE_SIGNALLING_POINT_CODE,     "Signalling point code (national use)"},
  { PARAM_TYPE_USER_TO_USER_INFO,         "User-to-user information"},
  { PARAM_TYPE_CONNECTED_NR,              "Connected number"},
  { PARAM_TYPE_SUSP_RESUME_IND,           "Suspend/Resume indicators"},
  { PARAM_TYPE_TRANSIT_NETW_SELECT,       "Transit network selection (national use)"},
  { PARAM_TYPE_EVENT_INFO,                "Event information"},
  { PARAM_TYPE_CIRC_ASSIGN_MAP,           "Circuit assignment map"},
  { PARAM_TYPE_CIRC_STATE_IND,            "Circuit state indicator (national use)"},
  { PARAM_TYPE_AUTO_CONG_LEVEL,           "Automatic congestion level"},
  { PARAM_TYPE_ORIG_CALLED_NR,            "Original called number"},
  { PARAM_TYPE_OPT_BACKW_CALL_IND,        "Backward call indicators"},
  { PARAM_TYPE_USER_TO_USER_IND,          "User-to-user indicators"},
  { PARAM_TYPE_ORIG_ISC_POINT_CODE,       "Origination ISC point code"},
  { PARAM_TYPE_GENERIC_NOTIF_IND,         "Generic notification indicator"},
  { PARAM_TYPE_CALL_HIST_INFO,            "Call history information"},
  { PARAM_TYPE_ACC_DELIV_INFO,            "Access delivery information"},
  { PARAM_TYPE_NETW_SPECIFIC_FACLTY,      "Network specific facility (national use)"},
  { PARAM_TYPE_USER_SERVICE_INFO_PR,      "User service information prime"},
  { PARAM_TYPE_PROPAG_DELAY_COUNTER,      "Propagation delay counter"},
  { PARAM_TYPE_REMOTE_OPERATIONS,         "Remote operations (national use)"},
  { PARAM_TYPE_SERVICE_ACTIVATION,        "Service activation"},
  { PARAM_TYPE_USER_TELESERV_INFO,        "User teleservice information"},
  { PARAM_TYPE_TRANSM_MEDIUM_USED,        "Transmission medium used"},
  { PARAM_TYPE_CALL_DIV_INFO,             "Call diversion information"},
  { PARAM_TYPE_ECHO_CTRL_INFO,            "Echo control information"},
  { PARAM_TYPE_MSG_COMPAT_INFO,           "Message compatibility information"},
  { PARAM_TYPE_PARAM_COMPAT_INFO,         "Parameter compatibility information"},
  { PARAM_TYPE_MLPP_PRECEDENCE,           "MLPP precedence"},
  { PARAM_TYPE_MCID_REQ_IND,              "MCID request indicators"},
  { PARAM_TYPE_MCID_RSP_IND,              "MCID response indicators"},
  { PARAM_TYPE_HOP_COUNTER,               "Hop counter"},
  { PARAM_TYPE_TRANSM_MEDIUM_RQUR_PR,     "Transmission medium requirement prime"},
  { PARAM_TYPE_LOCATION_NR,               "Location number"},
  { PARAM_TYPE_REDIR_NR_RSTRCT,           "Redirection number restriction"},
  { PARAM_TYPE_CALL_TRANS_REF,            "Call transfer reference"},
  { PARAM_TYPE_LOOP_PREV_IND,             "Loop prevention indicators"},
  { PARAM_TYPE_CALL_TRANS_NR,             "Call transfer number"},
  { PARAM_TYPE_CCSS,                      "CCSS"},
  { PARAM_TYPE_FORW_GVNS,                 "Forward GVNS"},
  { PARAM_TYPE_BACKW_GVNS,                "Backward GVNS"},
  { PARAM_TYPE_REDIRECT_CAPAB,            "Redirect capability (reserved for national use)"},
  { PARAM_TYPE_NETW_MGMT_CTRL,            "Network management controls"},
  { PARAM_TYPE_CORRELATION_ID,            "Correlation id"},
  { PARAM_TYPE_SCF_ID,                    "SCF id"},
  { PARAM_TYPE_CALL_DIV_TREAT_IND,        "Call diversion treatment indicators"},
  { PARAM_TYPE_CALLED_IN_NR,              "Called IN number"},
  { PARAM_TYPE_CALL_OFF_TREAT_IND,        "Call offering treatment indicators"},
  { PARAM_TYPE_CHARGED_PARTY_IDENT,       "Charged party identification (national use)"},
  { PARAM_TYPE_CONF_TREAT_IND,            "Conference treatment indicators"},
  { PARAM_TYPE_DISPLAY_INFO,              "Display information"},
  { PARAM_TYPE_UID_ACTION_IND,            "UID action indicators"},
  { PARAM_TYPE_UID_CAPAB_IND,             "UID capability indicators"},
  { PARAM_TYPE_REDIRECT_COUNTER,          "Redirect counter (reserved for national use)"},
  { PARAM_TYPE_APPLICATON_TRANS,          "Application transport"},
  { PARAM_TYPE_COLLECT_CALL_REQ,          "Collect call request"},
  { PARAM_TYPE_GENERIC_NR,                "Generic number"},
  { PARAM_TYPE_GENERIC_DIGITS,            "Generic digits (national use)"},
  { 0,                                 NULL}};
static value_string_ext isup_parameter_type_value_ext = VALUE_STRING_EXT_INIT(isup_parameter_type_value);

static const value_string ansi_isup_parameter_type_value[] = {
  { PARAM_TYPE_END_OF_OPT_PARAMS,         "End of optional parameters"},
  { PARAM_TYPE_CALL_REF,                  "Call Reference (national use)"},
  { PARAM_TYPE_TRANSM_MEDIUM_REQU,        "Transmission medium requirement"},
  { PARAM_TYPE_ACC_TRANSP,                "Access transport"},
  { PARAM_TYPE_CALLED_PARTY_NR,           "Called party number"},
  { PARAM_TYPE_SUBSQT_NR,                 "Subsequent number"},
  { PARAM_TYPE_NATURE_OF_CONN_IND,        "Nature of connection indicators"},
  { PARAM_TYPE_FORW_CALL_IND,             "Forward call indicators"},
  { PARAM_TYPE_OPT_FORW_CALL_IND,         "Optional forward call indicators"},
  { PARAM_TYPE_CALLING_PRTY_CATEG,        "Calling party's category"},
  { PARAM_TYPE_CALLING_PARTY_NR,          "Calling party number"},
  { PARAM_TYPE_REDIRECTING_NR,            "Redirecting number"},
  { PARAM_TYPE_REDIRECTION_NR,            "Redirection number"},
  { PARAM_TYPE_CONNECTION_REQ,            "Connection request"},
  { PARAM_TYPE_INFO_REQ_IND,              "Information request indicators (national use)"},
  { PARAM_TYPE_INFO_IND,                  "Information indicators (national use)"},
  { PARAM_TYPE_CONTINUITY_IND,            "Continuity request"},
  { PARAM_TYPE_BACKW_CALL_IND,            "Backward call indicators"},
  { PARAM_TYPE_CAUSE_INDICATORS,          "Cause indicators"},
  { PARAM_TYPE_REDIRECTION_INFO,          "Redirection information"},
  { PARAM_TYPE_CIRC_GRP_SV_MSG_TYPE,      "Circuit group supervision message type"},
  { PARAM_TYPE_RANGE_AND_STATUS,          "Range and Status"},
  { PARAM_TYPE_FACILITY_IND,              "Facility indicator"},
  { PARAM_TYPE_CLSD_USR_GRP_ILOCK_CD,     "Closed user group interlock code"},
  { PARAM_TYPE_USER_SERVICE_INFO,         "User service information"},
  { PARAM_TYPE_SIGNALLING_POINT_CODE,     "Signalling point code (national use)"},
  { PARAM_TYPE_USER_TO_USER_INFO,         "User-to-user information"},
  { PARAM_TYPE_CONNECTED_NR,              "Connected number"},
  { PARAM_TYPE_SUSP_RESUME_IND,           "Suspend/Resume indicators"},
  { PARAM_TYPE_TRANSIT_NETW_SELECT,       "Transit network selection (national use)"},
  { PARAM_TYPE_EVENT_INFO,                "Event information"},
  { PARAM_TYPE_CIRC_ASSIGN_MAP,           "Circuit assignment map"},
  { PARAM_TYPE_CIRC_STATE_IND,            "Circuit state indicator (national use)"},
  { PARAM_TYPE_AUTO_CONG_LEVEL,           "Automatic congestion level"},
  { PARAM_TYPE_ORIG_CALLED_NR,            "Original called number"},
  { PARAM_TYPE_OPT_BACKW_CALL_IND,        "Backward call indicators"},
  { PARAM_TYPE_USER_TO_USER_IND,          "User-to-user indicators"},
  { PARAM_TYPE_ORIG_ISC_POINT_CODE,       "Origination ISC point code"},
  { PARAM_TYPE_GENERIC_NOTIF_IND,         "Generic notification indicator"},
  { PARAM_TYPE_CALL_HIST_INFO,            "Call history information"},
  { PARAM_TYPE_ACC_DELIV_INFO,            "Access delivery information"},
  { PARAM_TYPE_NETW_SPECIFIC_FACLTY,      "Network specific facility (national use)"},
  { PARAM_TYPE_USER_SERVICE_INFO_PR,      "User service information prime"},
  { PARAM_TYPE_PROPAG_DELAY_COUNTER,      "Propagation delay counter"},
  { PARAM_TYPE_REMOTE_OPERATIONS,         "Remote operations (national use)"},
  { PARAM_TYPE_SERVICE_ACTIVATION,        "Service activation"},
  { PARAM_TYPE_USER_TELESERV_INFO,        "User teleservice information"},
  { PARAM_TYPE_TRANSM_MEDIUM_USED,        "Transmission medium used"},
  { PARAM_TYPE_CALL_DIV_INFO,             "Call diversion information"},
  { PARAM_TYPE_ECHO_CTRL_INFO,            "Echo control information"},
  { PARAM_TYPE_MSG_COMPAT_INFO,           "Message compatibility information"},
  { PARAM_TYPE_PARAM_COMPAT_INFO,         "Parameter compatibility information"},
  { PARAM_TYPE_MLPP_PRECEDENCE,           "MLPP precedence"},
  { PARAM_TYPE_MCID_REQ_IND,              "MCID request indicators"},
  { PARAM_TYPE_MCID_RSP_IND,              "MCID response indicators"},
  { PARAM_TYPE_HOP_COUNTER,               "Hop counter"},
  { PARAM_TYPE_TRANSM_MEDIUM_RQUR_PR,     "Transmission medium requirement prime"},
  { PARAM_TYPE_LOCATION_NR,               "Location number"},
  { PARAM_TYPE_REDIR_NR_RSTRCT,           "Redirection number restriction"},
  { PARAM_TYPE_CALL_TRANS_REF,            "Call transfer reference"},
  { PARAM_TYPE_LOOP_PREV_IND,             "Loop prevention indicators"},
  { PARAM_TYPE_CALL_TRANS_NR,             "Call transfer number"},
  { PARAM_TYPE_CCSS,                      "CCSS"},
  { PARAM_TYPE_FORW_GVNS,                 "Forward GVNS"},
  { PARAM_TYPE_BACKW_GVNS,                "Backward GVNS"},
  { PARAM_TYPE_REDIRECT_CAPAB,            "Redirect capability (reserved for national use)"},
  { PARAM_TYPE_NETW_MGMT_CTRL,            "Network management controls"},
  { PARAM_TYPE_CORRELATION_ID,            "Correlation id"},
  { PARAM_TYPE_SCF_ID,                    "SCF id"},
  { PARAM_TYPE_CALL_DIV_TREAT_IND,        "Call diversion treatment indicators"},
  { PARAM_TYPE_CALLED_IN_NR,              "Called IN number"},
  { PARAM_TYPE_CALL_OFF_TREAT_IND,        "Call offering treatment indicators"},
  { PARAM_TYPE_CHARGED_PARTY_IDENT,       "Charged party identification (national use)"},
  { PARAM_TYPE_CONF_TREAT_IND,            "Conference treatment indicators"},
  { PARAM_TYPE_DISPLAY_INFO,              "Display information"},
  { PARAM_TYPE_UID_ACTION_IND,            "UID action indicators"},
  { PARAM_TYPE_UID_CAPAB_IND,             "UID capability indicators"},
  { PARAM_TYPE_REDIRECT_COUNTER,          "Redirect counter (reserved for national use)"},
  { PARAM_TYPE_APPLICATON_TRANS,          "Application transport"},
  { PARAM_TYPE_COLLECT_CALL_REQ,          "Collect call request"},
  { PARAM_TYPE_CALLING_GEODETIC_LOCATION, "Calling geodetic location"},
  { PARAM_TYPE_GENERIC_NR,                "Generic number"},
  { PARAM_TYPE_GENERIC_DIGITS,            "Generic digits (national use)"},
#if 0 /* XXX: Dups of below */
  { PARAM_TYPE_JURISDICTION,              "Jurisdiction"},
  { PARAM_TYPE_GENERIC_NAME,              "Generic name"},
  { PARAM_TYPE_ORIG_LINE_INFO,            "Originating line info"},
#endif
  { ANSI_ISUP_PARAM_TYPE_OPER_SERV_INF,   "Operator Services information"},
  { ANSI_ISUP_PARAM_TYPE_EGRESS,          "Egress"},
  { ANSI_ISUP_PARAM_TYPE_JURISDICTION,    "Jurisdiction"},
  { ANSI_ISUP_PARAM_TYPE_CARRIER_ID,      "Carrier identification"},
  { ANSI_ISUP_PARAM_TYPE_BUSINESS_GRP,    "Business group"},
  { ANSI_ISUP_PARAM_TYPE_GENERIC_NAME,    "Generic name"},
  { ANSI_ISUP_PARAM_TYPE_NOTIF_IND,       "Notification indicator"},
  { ANSI_ISUP_PARAM_TYPE_CG_CHAR_IND,     "Circuit group characteristic indicator"},
  { ANSI_ISUP_PARAM_TYPE_CVR_RESP_IND,    "Circuit validation response indicator"},
  { ANSI_ISUP_PARAM_TYPE_OUT_TRK_GRP_NM,  "Outgoing trunk group number"},
  { ANSI_ISUP_PARAM_TYPE_CI_NAME_IND,     "Circuit identification name"},
  { ANSI_ISUP_PARAM_CLLI_CODE,            "COMMON LANGUAGE location identification (CLLI) code"},
  { ANSI_ISUP_PARAM_ORIG_LINE_INF,        "Originating line information"},
  { ANSI_ISUP_PARAM_CHRG_NO,              "Charge number"},
  { ANSI_ISUP_PARAM_SERV_CODE_IND,        "Service code indicator"},
  { ANSI_ISUP_PARAM_SPEC_PROC_REQ,        "Special processing request"},
  { ANSI_ISUP_PARAM_CARRIER_SEL_INF,      "Carrier selection information"},
  { ANSI_ISUP_PARAM_NET_TRANS,            "Network transport"},
  { 0,                                 NULL}};
static value_string_ext ansi_isup_parameter_type_value_ext = VALUE_STRING_EXT_INIT(ansi_isup_parameter_type_value);

#define CIC_LENGTH                             2
#define BICC_CIC_LENGTH                        4
#define MESSAGE_TYPE_LENGTH                    1
#define COMMON_HEADER_LENGTH                   (CIC_LENGTH + MESSAGE_TYPE_LENGTH)
#define BICC_COMMON_HEADER_LENGTH              (BICC_CIC_LENGTH + MESSAGE_TYPE_LENGTH)

#define MAXDIGITS                              32 /* Max number of address digits */
#define MAXGNAME                               15 /* Max number of characters in generic name */

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
#define ORIG_LINE_INFO_LENGTH                  1
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
#define USER_TELESERVICE_INFO_LENGTH           2
#define USER_TO_USER_IND_LENGTH                1
#define RANGE_LENGTH                           1

#define CVR_RESP_IND_LENGTH                    1
#define CG_CHAR_IND_LENGTH                     1
#define CI_NAME_IND                           28
#define CLLI_CODE_LENGTH                      13

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

#define ISUP_PREFERRED_ALL_THE_WAY              0
#define ISUP_NOT_REQUIRED_ALL_THE_WAY           1
#define ISUP_REQUIRED_ALL_WAY                   2
#define ISUP_ISDN_USER_PART_IND_SPARE           3
static const value_string isup_preferences_ind_value[] = {
  { ISUP_PREFERRED_ALL_THE_WAY,                  "ISDN user part preferred all the way"},
  { ISUP_NOT_REQUIRED_ALL_THE_WAY,               "ISDN user part not required all the way"},
  { ISUP_REQUIRED_ALL_WAY,                       "ISDN user part required all the way"},
  { ISUP_ISDN_USER_PART_IND_SPARE,               "spare"},
  { 0,                                 NULL}};

static const true_false_string isup_ISDN_originating_access_ind_value = {
  "originating access ISDN",
  "originating access non-ISDN"
};

static const true_false_string isup_ISDN_ported_num_trans_ind_value = {
  "number translated",
  "number not translated"
};

static const true_false_string isup_ISDN_qor_attempt_ind_value = {
  "QoR routing attempt in progress",
  "no QoR routing attempt in progress"
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

  { 6,                                  "available to Administrations"},
  { 7,                                  "available to Administrations"},
  { 8,                                  "available to Administrations"},
  { 9,                                  "reserved (national use)"},

  { ORDINARY_CALLING_SUBSCRIBER,        "ordinary calling subscriber"},
  { CALLING_SUBSCRIBER_WITH_PRIORITY,   "calling subscriber with priority"},
  { DATA_CALL,                          "data call (voice band data)"},
  { TEST_CALL,                          "test call"},
  /* q.763-200212Amd2 */
  { 14,                                 "IEPS call marking for preferential call set up"},
  { PAYPHONE,                           "payphone"},
  { 0,                                 NULL}};
value_string_ext isup_calling_partys_category_value_ext = VALUE_STRING_EXT_INIT(isup_calling_partys_category_value);

#define CVR_RSP_IND_FAILURE     0
#define CVR_RSP_IND_SUCCESS     1

static const value_string isup_cvr_rsp_ind_value[ ] = {
  { CVR_RSP_IND_FAILURE, "CVR Response Fail" },
  { CVR_RSP_IND_SUCCESS, "CVR Response Success" },
  { 0,                  NULL }
};

#define CVR_CG_IND_DOUBLE_SEIZE_NONE 0
#define CVR_CG_IND_DOUBLE_SEIZE_ODD  1
#define CVR_CG_IND_DOUBLE_SEIZE_EVEN 2
#define CVR_CG_IND_DOUBLE_SEIZE_ALL  3

static const value_string isup_cvr_cg_double_seize_value[ ] = {
  { CVR_CG_IND_DOUBLE_SEIZE_NONE, "Double Seize control NONE" },
  { CVR_CG_IND_DOUBLE_SEIZE_ODD,  "Double Seize control odd circuits"},
  { CVR_CG_IND_DOUBLE_SEIZE_EVEN, "Double Seize control even circuits"},
  { CVR_CG_IND_DOUBLE_SEIZE_ALL,  "Double Seize control all circuits"},
  {0, NULL }
};

#define CVR_CG_IND_CAR_IND_UNKNOWN      0
#define CVR_CG_IND_CAR_IND_ANALOG       1
#define CVR_CG_IND_CAR_IND_DIGITAL      2
#define CVR_CG_IND_CAR_IND_ANALOG_DIG   3

static const value_string isup_cvr_cg_car_ind_value[ ] = {
{ CVR_CG_IND_CAR_IND_UNKNOWN   , "Carrier Type Unknown" },
{ CVR_CG_IND_CAR_IND_ANALOG    , "Carrier Type Analog" },
{ CVR_CG_IND_CAR_IND_DIGITAL   , "Carrier Type Digital"},
{ CVR_CG_IND_CAR_IND_ANALOG_DIG, "Carrier Type Digital And Analog"},
{ 0, NULL }
};

#define CVR_CG_IND_ALARM_CAR_IND_UNKNOWN  0
#define CVR_CG_IND_ALARM_CAR_IND_SOFTWARE 1
#define CVR_CG_IND_ALARM_CAR_IND_HARDWARE 2
#define CVR_CG_IND_ALARM_CAR_IND_SPARE    3

static const value_string isup_cvr_alarm_car_ind_value[ ] = {
  { CVR_CG_IND_ALARM_CAR_IND_UNKNOWN    , "Alarm Carrier Ind Default"},
  { CVR_CG_IND_ALARM_CAR_IND_SOFTWARE   , "Alarm Carrier Ind Software"},
  { CVR_CG_IND_ALARM_CAR_IND_HARDWARE   , "Alarm Carrier Ind Hardware"},
  { CVR_CG_IND_ALARM_CAR_IND_SPARE      , "Alarm Carrier Ind Spare"},
  { 0, NULL }
};

#define CVR_CG_IND_CONT_CHK_UNKNOWN  0
#define CVR_CG_IND_CONT_CHK_NONE     1
#define CVR_CG_IND_CONT_CHK_STAT     2
#define CVR_CG_IND_CONT_CHK_PER_CALL 3

static const value_string isup_cvr_cont_chk_ind_value[ ] = {

  { CVR_CG_IND_CONT_CHK_UNKNOWN  , "Continuity Check Unknown"},
  { CVR_CG_IND_CONT_CHK_NONE     , "Continuity Check NONE"},
  { CVR_CG_IND_CONT_CHK_STAT     , "Continuity Check Statistical"},
  { CVR_CG_IND_CONT_CHK_PER_CALL , "Continuity Check Per Call"},
  { 0, NULL }
};

#define MEDIUM_SPEECH                        0
#define MEDIUM_64KBS                         2
#define MEDIUM_3_1_KHZ_AUDIO                 3
#define MEDIUM_RESERVED_SERVICE2_1           4
#define MEDIUM_RESERVED_SERVICE1_2           5
#define MEDIUM_64KBS_PREFERRED               6
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
  { 1,                                   "spare"},
  { MEDIUM_64KBS,                        "64 kbit/s unrestricted"},
  { MEDIUM_3_1_KHZ_AUDIO,                "3.1 kHz audio"},
  { MEDIUM_RESERVED_SERVICE2_1,          "reserved for alternate speech (service 2)/64 kbit/s unrestricted (service 1)"},
  { MEDIUM_RESERVED_SERVICE1_2,          "reserved for alternate 64 kbit/s unrestricted (service 1)/speech (service 2)"},
  { MEDIUM_64KBS_PREFERRED,              "64 kbit/s preferred"},
  { MEDIUM_2_64KBS,                      "2x64 kbit/s unrestricted"},
  { MEDIUM_384KBS,                       "384 kbit/s unrestricted"},
  { MEDIUM_1536KBS,                      "1536 kbit/s unrestricted"},
  { MEDIUM_1920KBS,                      "1920 kbit/s unrestricted"},

  { 11,                                  "spare"},
  { 12,                                  "spare"},
  { 13,                                  "spare"},
  { 14,                                  "spare"},
  { 15,                                  "spare"},

  { MEDIUM_3_64KBS,                      "3x64 kbit/s unrestricted"},
  { MEDIUM_4_64KBS,                      "4x64 kbit/s unrestricted"},
  { MEDIUM_5_64KBS,                      "5x64 kbit/s unrestricted"},

  { 19,                                  "spare"},

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

  { 37,                                  "spare"},

  { MEDIUM_25_64KBS,                     "25x64 kbit/s unrestricted"},
  { MEDIUM_26_64KBS,                     "26x64 kbit/s unrestricted"},
  { MEDIUM_27_64KBS,                     "27x64 kbit/s unrestricted"},
  { MEDIUM_28_64KBS,                     "28x64 kbit/s unrestricted"},
  { MEDIUM_29_64KBS,                     "29x64 kbit/s unrestricted"},
  { 0,                                 NULL}};
value_string_ext isup_transmission_medium_requirement_value_ext = VALUE_STRING_EXT_INIT(isup_transmission_medium_requirement_value);

static const value_string isup_transmission_medium_requirement_prime_value[] = {
  { MEDIUM_SPEECH,                       "speech"},
  { 1,                                   "spare"},
  { MEDIUM_64KBS,                        "reserved for 64 kbit/s unrestricted"},
  { MEDIUM_3_1_KHZ_AUDIO,                "3.1 kHz audio"},
  { MEDIUM_RESERVED_SERVICE2_1,          "reserved for alternate speech (service 2)/64 kbit/s unrestricted (service 1)"},
  { MEDIUM_RESERVED_SERVICE1_2,          "reserved for alternate 64 kbit/s unrestricted (service 1)/speech (service 2)"},
  { MEDIUM_64KBS_PREFERRED,              "reserved for 64 kbit/s preferred"},
  { MEDIUM_2_64KBS,                      "reserved for 2x64 kbit/s unrestricted"},
  { MEDIUM_384KBS,                       "reserved for 384 kbit/s unrestricted"},
  { MEDIUM_1536KBS,                      "reserved for 1536 kbit/s unrestricted"},
  { MEDIUM_1920KBS,                      "reserved for 1920 kbit/s unrestricted"},
  { 0,                                 NULL}};
static value_string_ext isup_transmission_medium_requirement_prime_value_ext = VALUE_STRING_EXT_INIT(isup_transmission_medium_requirement_prime_value);


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

#define ISUP_CHARGE_NATURE_ANI_CGPA_SUB_NR      1
#define ISUP_CHARGE_NATURE_ANI_NA               2
#define ISUP_CHARGE_NATURE_ANI_CGPA_NAT_NR      3
#define ISUP_CHARGE_NATURE_ANI_CDPA_SUB_NR      5
#define ISUP_CHARGE_NATURE_ANI_CDPA_NO_NR       6
#define ISUP_CHARGE_NATURE_ANI_CDPA_NAT_NR      7

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

static const value_string isup_charge_number_nature_of_address_ind_value[] = {
  { ISUP_CHARGE_NATURE_ANI_CGPA_SUB_NR,  "ANI of the calling party; subscriber number"},
  { ISUP_CHARGE_NATURE_ANI_NA,           "ANI not available or not provided"},
  { ISUP_CHARGE_NATURE_ANI_CGPA_NAT_NR,  "ANI of the calling party; national number"},
  { ISUP_CHARGE_NATURE_ANI_CDPA_SUB_NR,  "ANI of the called party; subscriber number"},
  { ISUP_CHARGE_NATURE_ANI_CDPA_NO_NR,   "ANI of the called party; no number present"},
  { ISUP_CHARGE_NATURE_ANI_CDPA_NAT_NR,  "ANI of the called party; national number"},
  { 0,                                 NULL}};

#define ISUP_GENERIC_NAME_PRESENTATION_ALLOWED          0
#define ISUP_GENERIC_NAME_PRESENTATION_RESTRICT         1
#define ISUP_GENERIC_NAME_PRESENTATION_BLOCK_TOGGLE     2
#define ISUP_GENERIC_NAME_PRESENTATION_NO_INDIC         3
#define ISUP_GENERIC_NAME_TYPE_SPARE                    0
#define ISUP_GENERIC_NAME_TYPE_CALLING                  1
#define ISUP_GENERIC_NAME_TYPE_ORIG_CALLED              2
#define ISUP_GENERIC_NAME_TYPE_REDIRECTING              3
#define ISUP_GENERIC_NAME_TYPE_CONNECTED                4

static const value_string isup_generic_name_presentation_value[] = {
  { ISUP_GENERIC_NAME_PRESENTATION_ALLOWED,             "presentation allowed"},
  { ISUP_GENERIC_NAME_PRESENTATION_RESTRICT,            "presentation restricted"},
  { ISUP_GENERIC_NAME_PRESENTATION_BLOCK_TOGGLE,        "blocking toggle"},
  { ISUP_GENERIC_NAME_PRESENTATION_NO_INDIC,            "no indication"},
  { 0,                                 NULL}};

static const true_false_string isup_generic_name_availability_value = {
  "name not available",
  "name available/unknown"
};

static const value_string isup_generic_name_type_value[] = {
  { ISUP_GENERIC_NAME_TYPE_SPARE,               "spare"},
  { ISUP_GENERIC_NAME_TYPE_CALLING,             "calling name"},
  { ISUP_GENERIC_NAME_TYPE_ORIG_CALLED,         "original called name"},
  { ISUP_GENERIC_NAME_TYPE_REDIRECTING,         "redirecting name"},
  { ISUP_GENERIC_NAME_TYPE_CONNECTED,           "connected name"},
  { 5,                                          "spare"},
  { 6,                                          "spare"},
  { 7,                                          "spare"},
  { 0,                                 NULL}};

static const true_false_string isup_INN_ind_value = {
  "routing to internal network number not allowed",
  "routing to internal network number allowed "
};
static const true_false_string isup_NI_ind_value = {
  "incomplete",
  "complete"
};

static const value_string isup_location_presentation_restricted_ind_value[] = {
  { 0,                                 "presentation allowed"},
  { 1,                                 "presentation restricted"},
  { 2,                                 "location not available"},
  { 3,                                 "spare"},
  { 0,                                 NULL}};

static const value_string isup_location_type_of_shape_value[] = {
  { 0,          "ellipsoid point"},
  { 1,          "ellipsoid point with uncertainty"},
  { 2,          "point with altitude and uncertainty"},
  { 3,          "ellipse on the ellipsoid"},
  { 4,          "ellipsoid circle sector"},
  { 5,          "polygon"},
  { 0,          NULL}};

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
  { ADDRESS_NOT_AVAILABLE,           "address not available (national use)"},
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
  {  0,  "no redirection (national use)"},
  {  1,  "call rerouted (national use)"},
  {  2,  "call rerouted, all redirection information presentation restricted (national use)"},
  {  3,  "call diverted"},
  {  4,  "call diverted, all redirection information presentation restricted"},
  {  5,  "call rerouted, redirection number presentation restricted (national use)"},
  {  6,  "call diversion, redirection number presentation restricted (national use)"},
  {  7,  "spare"},
  {  0,  NULL}};

static const value_string isup_original_redirection_reason_value[] = {
  /* according 3.45/Q.763 */
  {  0,  "unknown/not available"},
  {  1,  "user busy (national use)"},
  {  2,  "no reply (national use)"},
  {  3,  "unconditional (national use)"},
  {  0,  NULL}};

static const value_string isup_redirection_reason_value[] = {
  /* according 3.45/Q.763 */
  {  0,  "unknown/not available"},
  {  1,  "user busy (national use)"},
  {  2,  "no reply (national use)"},
  {  3,  "unconditional (national use)"},
  {  4,  "deflection during alerting"},
  {  5,  "deflection immediate response"},
  {  6,  "mobile subscriber not reachable"},
  {  0,  NULL}};

static const value_string isup_type_of_network_identification_value[] = {
  /* according 3.53/Q.763 */
  {  0,  "CCITT/ITU-T-standardized identification"},
  {  2,  "national network identification"},
  {  0,  NULL}};

static const value_string isup_network_identification_plan_value[] = {
  /* according 3.53/Q.763 */
  {  0,  "if CCITT/ITU-T id - unknown"},
  {  3,  "if CCITT/ITU-T id - public data network id code (X.121)"},
  {  6,  "if CCITT/ITU-T id - public land Mobile Network id code (E.211)"},
  {  0,  NULL}};

static const value_string isup_map_type_value[] = {
  /* according 3.69/Q.763 */
  {  1,  "1544 kbit/s digital path map format (64 kbit/s base rate"},
  {  2,  "2048 kbit/s digital path map format (64 kbit/s base rate"},
  {  0,  NULL}};

static const value_string isup_auto_congestion_level_value[] = {
  /* according 3.4/Q.763 */
  {  1,  "Congestion level 1 exceeded"},
  {  2,  "Congestion level 2 exceeded"},
  {  0,  NULL}};

static const true_false_string isup_inband_information_ind_value = {
  /* according 3.37/Q.763 */
  "in-band information or an appropriate pattern is now available",
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
  {  0,  "insufficient information"},
  {  1,  "no loop exists"},
  {  2,  "simultaneous transfer"},
  {  0,  NULL}};

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
  {  0,  "no indication"},
  {  1,  "call diversion allowed"},
  {  2,  "call diversion not allowed"},
  {  3,  "spare"},
  {  0,  NULL}};

static const value_string isup_call_to_be_offered_ind_value[] = {
  /* according 3.72/Q.763 */
  {  0,  "no indication"},
  {  1,  "call offering not allowed"},
  {  2,  "call offering allowed"},
  {  3,  "spare"},
  {  0,  NULL}};

static const value_string isup_conference_acceptance_ind_value[] = {
  /* according 3.76/Q.763 */
  {  0,  "no indication"},
  {  1,  "accept conference request"},
  {  2,  "reject conference request"},
  {  3,  "spare"},
  {  0,  NULL}};

static const value_string isup_application_transport_parameter_value[] = {
  /* according 3.82/Q.763 */
  {  0,  "Unidentified Context and Error Handling (UCEH) ASE"},
  {  1,  "PSS1 ASE (VPN)"},
  {  2,  "spare"},
  {  3,  "Charging ASE"},
  {  4,  "GAT"},
  {  5,  "BAT ASE"},
  {  6,  "Enhanced Unidentified Context and Error Handling ASE (EUCEH ASE)"},
  {  0,  NULL}};

static const true_false_string isup_Release_call_indicator_value = {
  "release call",
  "do not release call"
};

static const true_false_string isup_Send_notification_ind_value = {
  "send notification",
  "do not send notification"
};
static const value_string isup_APM_segmentation_ind_value[] = {

  {  0x00,  "final segment"},
  {  0x01,  "number of following segments"},
  {  0x02,  "number of following segments"},
  {  0x03,  "number of following segments"},
  {  0x04,  "number of following segments"},
  {  0x05,  "number of following segments"},
  {  0x06,  "number of following segments"},
  {  0x07,  "number of following segments"},
  {  0x08,  "number of following segments"},
  {  0x09,  "number of following segments"},
  {  0,     NULL}};

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
#define ED_8BIT_MASK 0x18
#define FE_8BIT_MASK 0x30
#define GF_8BIT_MASK 0x60
#define HG_8BIT_MASK 0xC0
#define GFE_8BIT_MASK 0x70
#define HGF_8BIT_MASK 0xE0
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
static module_t *isup_module;

static gboolean isup_show_cic_in_info = TRUE;

static int hf_isup_called = -1;
static int hf_isup_calling = -1;
static int hf_isup_redirecting = -1;

static int hf_isup_cic = -1;
static int hf_bicc_cic = -1;

static int isup_tap = -1;

static int hf_isup_message_type = -1;
static int hf_isup_parameter_type = -1;
static int hf_isup_parameter_length = -1;
static int hf_isup_mandatory_variable_parameter_pointer = -1;
static int hf_isup_pointer_to_start_of_optional_part = -1;

static int hf_isup_cvr_rsp_ind = -1;
static int hf_isup_cvr_cg_car_ind = -1;
static int hf_isup_cvr_cg_double_seize = -1;
static int hf_isup_cvr_cg_alarm_car_ind = -1;
static int hf_isup_cvr_cont_chk_ind = -1;

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
static int hf_isup_forw_call_ported_num_trans_indicator = -1;
static int hf_isup_forw_call_qor_attempt_indicator = -1;
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

static int hf_isup_generic_name_presentation  = -1;
static int hf_isup_generic_name_availability  = -1;
static int hf_isup_generic_name_type          = -1;
static int hf_isup_generic_name_ia5           = -1;

static int hf_isup_OECD_inf_ind = -1;
static int hf_isup_IECD_inf_ind = -1;
static int hf_isup_OECD_req_ind = -1;
static int hf_isup_IECD_req_ind = -1;

static int hf_isup_calling_party_address_request_indicator = -1;
static int hf_isup_info_req_holding_indicator = -1;
static int hf_isup_calling_partys_category_request_indicator = -1;
static int hf_isup_charge_information_request_indicator = -1;
static int hf_isup_charge_number_nature_of_address_indicator = -1;
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
static int hf_ansi_isup_cause_indicator = -1;

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

static int hf_isup_automatic_congestion_level               = -1;

static int hf_isup_inband_information_ind                   = -1;
static int hf_isup_call_diversion_may_occur_ind             = -1;
static int hf_isup_mlpp_user_ind                            = -1;

static int hf_isup_UUI_type                                 = -1;
static int hf_isup_UUI_req_service1                         = -1;
static int hf_isup_UUI_req_service2                         = -1;
static int hf_isup_UUI_req_service3                         = -1;
static int hf_isup_UUI_res_service1                         = -1;
static int hf_isup_UUI_res_service2                         = -1;
static int hf_isup_UUI_res_service3                         = -1;
static int hf_isup_UUI_network_discard_ind                  = -1;
static int hf_isup_access_delivery_ind                      = -1;

static int hf_isup_transmission_medium_requirement_prime    = -1;

static int hf_isup_loop_prevention_response_ind             = -1;

static int hf_isup_temporary_alternative_routing_ind        = -1;
static int hf_isup_extension_ind                            = -1;

static int hf_isup_call_to_be_diverted_ind                  = -1;

static int hf_isup_call_to_be_offered_ind                   = -1;

static int hf_isup_conference_acceptance_ind                = -1;

static int hf_isup_transit_at_intermediate_exchange_ind     = -1;
static int hf_isup_Release_call_ind                         = -1;
static int hf_isup_Send_notification_ind                    = -1;
static int hf_isup_Discard_message_ind_value                = -1;
static int hf_isup_Discard_parameter_ind                    = -1;
static int hf_isup_Pass_on_not_possible_indicator           = -1;
static int hf_isup_pass_on_not_possible_indicator2          = -1;
static int hf_isup_Broadband_narrowband_interworking_ind    = -1;
static int hf_isup_Broadband_narrowband_interworking_ind2   = -1;

static int hf_isup_app_cont_ident                   = -1;
static int hf_isup_app_Send_notification_ind        = -1;
static int hf_isup_apm_segmentation_ind             = -1;
static int hf_isup_apm_si_ind                       = -1;
static int hf_isup_apm_slr                          = -1;
static int hf_isup_orig_addr_len                    = -1;
static int hf_isup_dest_addr_len                    = -1;
static int hf_isup_app_Release_call_ind             = -1;
static int hf_isup_cause_location                   = -1;

static int hf_ansi_isup_coding_standard             = -1;

static int hf_length_indicator                      = -1;
static int hf_afi                                   = -1;
static int hf_bicc_nsap_dsp                         = -1;
static int hf_bat_ase_identifier                    = -1;

static int hf_Action_Indicator                      = -1;

static int hf_Instruction_ind_for_general_action       = -1;

static int hf_Send_notification_ind_for_general_action = -1;

static int hf_Instruction_ind_for_pass_on_not_possible = -1;

static int hf_Send_notification_ind_for_pass_on_not_possible = -1;
static int hf_BCTP_Version_Indicator        = -1;
static int hf_Tunnelled_Protocol_Indicator  = -1;
static int hf_TPEI                          = -1;
static int hf_BVEI                          = -1;
static int hf_bncid                         = -1;
static int hf_bat_ase_biwfa                 = -1;
static int hf_characteristics               = -1;

static int hf_Organization_Identifier       = -1;
static int hf_codec_type                    = -1;
static int hf_etsi_codec_type               = -1;
static int hf_active_code_set  = -1;
static int hf_active_code_set_12_2  = -1;
static int hf_active_code_set_10_2  = -1;
static int hf_active_code_set_7_95  = -1;
static int hf_active_code_set_7_40  = -1;
static int hf_active_code_set_6_70  = -1;
static int hf_active_code_set_5_90  = -1;
static int hf_active_code_set_5_15  = -1;
static int hf_active_code_set_4_75  = -1;
static int hf_supported_code_set  = -1;
static int hf_supported_code_set_12_2  = -1;
static int hf_supported_code_set_10_2  = -1;
static int hf_supported_code_set_7_95  = -1;
static int hf_supported_code_set_7_40  = -1;
static int hf_supported_code_set_6_70  = -1;
static int hf_supported_code_set_5_90  = -1;
static int hf_supported_code_set_5_15  = -1;
static int hf_supported_code_set_4_75  = -1;
static int hf_optimisation_mode  = -1;
static int hf_max_codec_modes  = -1;
static int hf_bearer_control_tunneling          = -1;
static int hf_Local_BCU_ID                      = -1;
static int hf_late_cut_trough_cap_ind           = -1;
static int hf_bat_ase_signal                    = -1;
static int hf_bat_ase_duration                  = -1;
static int hf_bat_ase_bearer_redir_ind          = -1;
static int hf_BAT_ASE_Comp_Report_Reason        = -1;
static int hf_BAT_ASE_Comp_Report_ident         = -1;
static int hf_BAT_ASE_Comp_Report_diagnostic    = -1;
static int hf_nsap_ipv4_addr                    = -1;
static int hf_nsap_ipv6_addr                    = -1;
static int hf_iana_icp                          = -1;

static int hf_isup_geo_loc_presentation_restricted_ind  = -1;
static int hf_isup_geo_loc_screening_ind        = -1;

static int hf_isup_apm_msg_fragments = -1;
static int hf_isup_apm_msg_fragment = -1;
static int hf_isup_apm_msg_fragment_overlap = -1;
static int hf_isup_apm_msg_fragment_overlap_conflicts = -1;
static int hf_isup_apm_msg_fragment_multiple_tails = -1;
static int hf_isup_apm_msg_fragment_too_long_fragment = -1;
static int hf_isup_apm_msg_fragment_error = -1;
static int hf_isup_apm_msg_fragment_count = -1;
static int hf_isup_apm_msg_reassembled_in = -1;
static int hf_isup_apm_msg_reassembled_length = -1;

/* Initialize the subtree pointers */
static gint ett_isup                            = -1;
static gint ett_isup_parameter                  = -1;
static gint ett_isup_address_digits             = -1;
static gint ett_isup_pass_along_message         = -1;
static gint ett_isup_circuit_state_ind          = -1;
static gint ett_bat_ase                         = -1;
static gint ett_bicc                            = -1;
static gint ett_bat_ase_element                 = -1;
static gint ett_bat_ase_iwfa                    = -1;
static gint ett_acs                             = -1;
static gint ett_scs                             = -1;

static gint ett_isup_apm_msg_fragment = -1;
static gint ett_isup_apm_msg_fragments = -1;


static dissector_handle_t sdp_handle = NULL;
static dissector_handle_t q931_ie_handle = NULL;

/* Declarations to desegment APM Messages */
static gboolean isup_apm_desegment = TRUE;

static const fragment_items isup_apm_msg_frag_items = {
  /* Fragment subtrees */
  &ett_isup_apm_msg_fragment,
  &ett_isup_apm_msg_fragments,
  /* Fragment fields */
  &hf_isup_apm_msg_fragments,
  &hf_isup_apm_msg_fragment,
  &hf_isup_apm_msg_fragment_overlap,
  &hf_isup_apm_msg_fragment_overlap_conflicts,
  &hf_isup_apm_msg_fragment_multiple_tails,
  &hf_isup_apm_msg_fragment_too_long_fragment,
  &hf_isup_apm_msg_fragment_error,
  &hf_isup_apm_msg_fragment_count,
  /* Reassembled in field */
  &hf_isup_apm_msg_reassembled_in,
  /* Reassembled length field */
  &hf_isup_apm_msg_reassembled_length,
  /* Tag */
  "ISUP APM Message fragments"
};

static GHashTable *isup_apm_msg_fragment_table = NULL;
static GHashTable *isup_apm_msg_reassembled_table = NULL;


static void
isup_apm_defragment_init(void)
{
  fragment_table_init (&isup_apm_msg_fragment_table);
  reassembled_table_init(&isup_apm_msg_reassembled_table);
}

/* Info for the tap that must be passed between procedures */
static gchar *tap_called_number = NULL;
static gchar *tap_calling_number = NULL;
static guint8 tap_cause_value = 0;

/* ------------------------------------------------------------------
  Mapping number to ASCII-character
 ------------------------------------------------------------------ */
static char number_to_char(int number)
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
 Dissector Parameter circuit validation response indicator
 */

static void
dissect_isup_cvr_response_ind_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 cvr_response_ind;

  cvr_response_ind = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_isup_cvr_rsp_ind, parameter_tvb, 0, CVR_RESP_IND_LENGTH, cvr_response_ind );
  proto_item_set_text(parameter_item, "Circuit Validation Test Response Indicator: 0x%x", cvr_response_ind );

}

/* ------------------------------------------------------------------
   Dissector Parameter circuit validation response - circuit group
   characters
*/
static void
dissect_isup_circuit_group_char_ind_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 cvr_cg_char_ind;

  cvr_cg_char_ind = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_isup_cvr_cg_car_ind, parameter_tvb, 0, CG_CHAR_IND_LENGTH, cvr_cg_char_ind );
  proto_tree_add_uint(parameter_tree, hf_isup_cvr_cg_double_seize, parameter_tvb, 0, CG_CHAR_IND_LENGTH, cvr_cg_char_ind );
  proto_tree_add_uint(parameter_tree, hf_isup_cvr_cg_alarm_car_ind, parameter_tvb, 0, CG_CHAR_IND_LENGTH, cvr_cg_char_ind );
  proto_tree_add_uint(parameter_tree, hf_isup_cvr_cont_chk_ind, parameter_tvb, 0, CG_CHAR_IND_LENGTH, cvr_cg_char_ind );

  proto_item_set_text(parameter_item, "Circuit Validation Test Response Circuit Group Characteristics: 0x%x", cvr_cg_char_ind );
}

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
  proto_tree_add_boolean(parameter_tree, hf_isup_forw_call_ported_num_trans_indicator, parameter_tvb, 0, FORWARD_CALL_IND_LENGTH, forward_call_ind);
  proto_tree_add_boolean(parameter_tree, hf_isup_forw_call_qor_attempt_indicator, parameter_tvb, 0, FORWARD_CALL_IND_LENGTH, forward_call_ind);

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

  proto_item_set_text(parameter_item, "Calling Party's category: 0x%x (%s)", calling_partys_category, val_to_str_ext_const(calling_partys_category, &isup_calling_partys_category_value_ext, "reserved/spare"));
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

  proto_item_set_text(parameter_item, "Transmission medium requirement: %u (%s)",  transmission_medium_requirement, val_to_str_ext_const(transmission_medium_requirement, &isup_transmission_medium_requirement_value_ext, "spare"));
}
/* ------------------------------------------------------------------
  Dissector Parameter Called party number
 */
void
dissect_isup_called_party_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_item *address_digits_item;
  proto_tree *address_digits_tree;
  proto_item *hidden_item;
  guint8 indicators1, indicators2;
  guint8 address_digit_pair=0;
  gint offset=0;
  gint i=0;
  gint length;
  char called_number[MAXDIGITS + 1]="";
  e164_info_t e164_info;
  gint number_plan;

  indicators1 = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_isup_odd_even_indicator, parameter_tvb, 0, 1, indicators1);
  proto_tree_add_uint(parameter_tree, hf_isup_called_party_nature_of_address_indicator, parameter_tvb, 0, 1, indicators1);
  indicators2 = tvb_get_guint8(parameter_tvb, 1);
  number_plan = (indicators2 & 0x70)>> 4;
  proto_tree_add_boolean(parameter_tree, hf_isup_inn_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_numbering_plan_indicator, parameter_tvb, 1, 1, indicators2);
  offset = 2;

  if (tvb_reported_length_remaining(parameter_tvb, offset) == 0) {
    proto_tree_add_text(parameter_tree, parameter_tvb, offset, 0, "Called Number (empty)");
    proto_item_set_text(parameter_item, "Called Number: (empty)");
    return;
  }

  address_digits_item = proto_tree_add_text(parameter_tree, parameter_tvb,
                                            offset, -1, "Called Party Number");
  address_digits_tree = proto_item_add_subtree(address_digits_item, ett_isup_address_digits);

  while((length = tvb_reported_length_remaining(parameter_tvb, offset)) > 0) {
    address_digit_pair = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(address_digits_tree, hf_isup_called_party_odd_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
    called_number[i++] = number_to_char(address_digit_pair & ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK);
    if (i > MAXDIGITS)
      THROW(ReportedBoundsError);
    if ((length - 1) > 0 ){
      proto_tree_add_uint(address_digits_tree, hf_isup_called_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      called_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
      if (i > MAXDIGITS)
        THROW(ReportedBoundsError);
    }
    offset++;
  }
  if  (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)) { /* Even Indicator set -> last even digit is valid */
    proto_tree_add_uint(address_digits_tree, hf_isup_called_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
    called_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
    if (i > MAXDIGITS)
      THROW(ReportedBoundsError);
  }

  called_number[i++] = '\0';
  proto_item_set_text(address_digits_item, "Called Party Number: %s", called_number);
  proto_item_set_text(parameter_item, "Called Party Number: %s", called_number);
  if ( number_plan == 1 ) {
    e164_info.e164_number_type = CALLED_PARTY_NUMBER;
    e164_info.nature_of_address = indicators1 & 0x7f;
    e164_info.E164_number_str = called_number;
    e164_info.E164_number_length = i - 1;
    dissect_e164_number(parameter_tvb, address_digits_tree, 2, (offset - 2), e164_info);
    hidden_item = proto_tree_add_string(address_digits_tree, hf_isup_called, parameter_tvb,
                                        offset - length, length, called_number);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
  } else {
    proto_tree_add_string(address_digits_tree, hf_isup_called, parameter_tvb,
                          offset - length, length, called_number);
  }
  tap_called_number = ep_strdup(called_number);
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
  char called_number[MAXDIGITS + 1]="";

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
    if (i > MAXDIGITS)
      THROW(ReportedBoundsError);
    if ((length - 1) > 0 ){
      proto_tree_add_uint(address_digits_tree, hf_isup_called_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      called_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
      if (i > MAXDIGITS)
        THROW(ReportedBoundsError);
    }
    offset++;
  }

  if (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_isup_called_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      called_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
      if (i > MAXDIGITS)
        THROW(ReportedBoundsError);
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
  /* The table is "filled" with "unassigned" to make full use of value_string_ext */
static const value_string q850_cause_code_vals[] = {
  { 0x00,  "Valid cause code not yet received" },
  { 0x01,  "Unallocated (unassigned) number" },
  { 0x02,  "No route to specified transit network" },
  { 0x03,  "No route to destination" },
  { 0x04,  "Send special information tone" },
  { 0x05,  "Misdialled trunk prefix" },
  { 0x06,  "Channel unacceptable" },
  { 0x07,  "Call awarded and being delivered in an established channel" },
  { 0x08,  "Preemption" },
  { 0x09,  "Preemption - circuit reserved for reuse" },
  { 0x0A,  "Unassigned" },
  { 0x0B,  "Unassigned" },
  { 0x0C,  "Unassigned" },
  { 0x0D,  "Unassigned" },
  { 0x0E,  "QoR: ported number" },
  { 0x0F,  "Unassigned" },
  { 0x10,  "Normal call clearing" },
  { 0x11,  "User busy" },
  { 0x12,  "No user responding" },
  { 0x13,  "No answer from user (user alerted)" },
  { 0x14,  "Subscriber absent" },
  { 0x15,  "Call rejected" },
  { 0x16,  "Number changed" },
  { 0x17,  "Redirection to new destination" },
  { 0x18,  "Call rejected due to feature at the destination" },
  { 0x19,  "Exchange routing error" },
  { 0x1A,  "Non-selected user clearing" },
  { 0x1B,  "Destination out of order" },
  { 0x1C,  "Invalid number format (address incomplete)" },
  { 0x1D,  "Facility rejected" },
  { 0x1E,  "Response to STATUS ENQUIRY" },
  { 0x1F,  "Normal unspecified" },
  { 0x20,  "Unassigned" },
  { 0x21,  "Circuit out of order" },
  { 0x22,  "No circuit/channel available" },
  { 0x23,  "Unassigned" },
  { 0x24,  "Unassigned" },
  { 0x25,  "Unassigned" },
  { 0x26,  "Network out of order" },
  { 0x27,  "Permanent frame mode connection out of service" },
  { 0x28,  "Permanent frame mode connection operational" },
  { 0x29,  "Temporary failure" },
  { 0x2A,  "Switching equipment congestion" },
  { 0x2B,  "Access information discarded" },
  { 0x2C,  "Requested circuit/channel not available" },
  { 0x2D,  "Unassigned" },
  { 0x2E,  "Precedence call blocked" },
  { 0x2F,  "Resources unavailable, unspecified" },
  { 0x30,  "Unassigned" },
  { 0x31,  "Quality of service unavailable" },
  { 0x32,  "Requested facility not subscribed" },
  { 0x33,  "Unassigned" },
  { 0x34,  "Unassigned" },
  { 0x35,  "Outgoing calls barred within CUG" },
  { 0x36,  "Unassigned" },
  { 0x37,  "Incoming calls barred within CUG" },
  { 0x38,  "Call waiting not subscribed" },
  { 0x39,  "Bearer capability not authorized" },
  { 0x3A,  "Bearer capability not presently available" },
  { 0x3B,  "Unassigned" },
  { 0x3C,  "Unassigned" },
  { 0x3D,  "Unassigned" },
  { 0x3E,  "Inconsistency in designated outgoing access information and subscriber class" },
  { 0x3F,  "Service or option not available, unspecified" },
  { 0x40,  "Unassigned" },
  { 0x41,  "Bearer capability not implemented" },
  { 0x42,  "Channel type not implemented" },
  { 0x43,  "Unassigned" },
  { 0x44,  "Unassigned" },
  { 0x45,  "Requested facility not implemented" },
  { 0x46,  "Only restricted digital information bearer capability is available" },
  { 0x47,  "Unassigned" },
  { 0x48,  "Unassigned" },
  { 0x49,  "Unassigned" },
  { 0x4A,  "Unassigned" },
  { 0x4B,  "Unassigned" },
  { 0x4C,  "Unassigned" },
  { 0x4D,  "Unassigned" },
  { 0x4E,  "Unassigned" },
  { 0x4F,  "Service or option not implemented, unspecified" },
  { 0x50,  "Unassigned" },
  { 0x51,  "Invalid call reference value" },
  { 0x52,  "Identified channel does not exist" },
  { 0x53,  "Call identity does not exist for suspended call" },
  { 0x54,  "Call identity in use" },
  { 0x55,  "No call suspended" },
  { 0x56,  "Call having the requested call identity has been cleared" },
  { 0x57,  "Called user not member of CUG" },
  { 0x58,  "Incompatible destination" },
  { 0x59,  "Unassigned" },
  { 0x5A,  "Non-existing CUG" },
  { 0x5B,  "Invalid transit network selection (national use)" },
  { 0x5C,  "Unassigned" },
  { 0x5D,  "Unassigned" },
  { 0x5E,  "Unassigned" },
  { 0x5F,  "Invalid message, unspecified" },
  { 0x60,  "Mandatory information element is missing" },
  { 0x61,  "Message type non-existent or not implemented" },
  { 0x62,  "Message not compatible with call state or message type non-existent or not implemented" },
  { 0x63,  "Information element nonexistent or not implemented" },
  { 0x64,  "Invalid information element contents" },
  { 0x65,  "Message not compatible with call state" },
  { 0x66,  "Recovery on timer expiry" },
  { 0x67,  "Parameter non-existent or not implemented - passed on" },
  { 0x68,  "Unassigned" },
  { 0x69,  "Unassigned" },
  { 0x6A,  "Unassigned" },
  { 0x6B,  "Unassigned" },
  { 0x6C,  "Unassigned" },
  { 0x6D,  "Unassigned" },
  { 0x6E,  "Message with unrecognized parameter discarded" },
  { 0x6F,  "Protocol error, unspecified" },
  { 0x70,  "Unassigned" },
  { 0x71,  "Unassigned" },
  { 0x72,  "Unassigned" },
  { 0x73,  "Unassigned" },
  { 0x74,  "Unassigned" },
  { 0x75,  "Unassigned" },
  { 0x76,  "Unassigned" },
  { 0x77,  "Unassigned" },
  { 0x78,  "Unassigned" },
  { 0x79,  "Unassigned" },
  { 0x7A,  "Unassigned" },
  { 0x7B,  "Unassigned" },
  { 0x7C,  "Unassigned" },
  { 0x7D,  "Unassigned" },
  { 0x7E,  "Unassigned" },
  { 0x7F,  "Internetworking, unspecified" },
  { 0,  NULL }
};
value_string_ext q850_cause_code_vals_ext = VALUE_STRING_EXT_INIT(q850_cause_code_vals);

static const value_string ansi_isup_cause_code_vals[] = {
  { 0x00,  "Valid cause code not yet received" },
  { 0x01,  "Unallocated (unassigned) number" },
  { 0x02,  "No route to specified transit network" },
  { 0x03,  "No route to destination" },
  { 0x04,  "Send special information tone" },
  { 0x05,  "Misdialled trunk prefix" },
  { 0x06,  "Channel unacceptable" },
  { 0x07,  "Call awarded and being delivered in an established channel" },
  { 0x08,  "Preemption" },
  { 0x09,  "Preemption - circuit reserved for reuse" },
  { 0x0A,  "Unassigned" },
  { 0x0B,  "Unassigned" },
  { 0x0C,  "Unassigned" },
  { 0x0D,  "Unassigned" },
  { 0x0E,  "QoR: ported number" },
  { 0x0F,  "Unassigned" },
  { 0x10,  "Normal call clearing" },
  { 0x11,  "User busy" },
  { 0x12,  "No user responding" },
  { 0x13,  "No answer from user (user alerted)" },
  { 0x14,  "Subscriber absent" },
  { 0x15,  "Call rejected" },
  { 0x16,  "Number changed" },
  { 0x17,  "Unallocated destination number" },
  { 0X18,  "Undefined business group" },
  { 0x19,  "Exchange routing error" },
  { 0x1A,  "Non-selected user clearing" },
  { 0x1B,  "Destination out of order" },
  { 0x1C,  "Invalid number format (address incomplete)" },
  { 0x1D,  "Facility rejected" },
  { 0x1E,  "Response to STATUS ENQUIRY" },
  { 0x1F,  "Normal unspecified" },
  { 0x20,  "Unassigned" },
  { 0x21,  "Circuit out of order" },
  { 0x22,  "No circuit/channel available" },
  { 0x23,  "Unassigned" },
  { 0x24,  "Unassigned" },
  { 0x25,  "Unassigned" },
  { 0x26,  "Network out of order" },
  { 0x27,  "Permanent frame mode connection out of service" },
  { 0x28,  "Permanent frame mode connection operational" },
  { 0x29,  "Temporary failure" },
  { 0x2A,  "Switching equipment congestion" },
  { 0x2B,  "Access information discarded" },
  { 0x2C,  "Requested circuit/channel not available" },
  { 0x2D,  "Preemption" },
  { 0x2E,  "Precedence call blocked" },
  { 0x2F,  "Resources unavailable, unspecified" },
  { 0x30,  "Unassigned" },
  { 0x31,  "Quality of service unavailable" },
  { 0x32,  "Requested facility not subscribed" },
  { 0x33,  "Call type incompatible with service request" },
  { 0x34,  "Unassigned" },
  { 0x35,  "Outgoing calls barred within CUG" },
  { 0x36,  "Call blocked due to group restriction" },
  { 0x37,  "Incoming calls barred within CUG" },
  { 0x38,  "Call waiting not subscribed" },
  { 0x39,  "Bearer capability not authorized" },
  { 0x3A,  "Bearer capability not presently available" },
  { 0x3B,  "Unassigned" },
  { 0x3C,  "Unassigned" },
  { 0x3D,  "Unassigned" },
  { 0x3E,  "Inconsistency in designated outgoing access information and subscriber class" },
  { 0x3F,  "Service or option not available, unspecified" },
  { 0x40,  "Unassigned" },
  { 0x41,  "Bearer capability not implemented" },
  { 0x42,  "Channel type not implemented" },
  { 0x43,  "Unassigned" },
  { 0x44,  "Unassigned" },
  { 0x45,  "Requested facility not implemented" },
  { 0x46,  "Only restricted digital information bearer capability is available" },
  { 0x47,  "Unassigned" },
  { 0x48,  "Unassigned" },
  { 0x49,  "Unassigned" },
  { 0x4A,  "Unassigned" },
  { 0x4B,  "Unassigned" },
  { 0x4C,  "Unassigned" },
  { 0x4D,  "Unassigned" },
  { 0x4E,  "Unassigned" },
  { 0x4F,  "Service or option not implemented, unspecified" },
  { 0x50,  "Unassigned" },
  { 0x51,  "Invalid call reference value" },
  { 0x52,  "Identified channel does not exist" },
  { 0x53,  "Call identity does not exist for suspended call" },
  { 0x54,  "Call identity in use" },
  { 0x55,  "No call suspended" },
  { 0x56,  "Call having the requested call identity has been cleared" },
  { 0x57,  "Called user not member of CUG" },
  { 0x58,  "Incompatible destination" },
  { 0x59,  "Unassigned" },
  { 0x5A,  "Non-existing CUG" },
  { 0x5B,  "Invalid transit network selection (national use)" },
  { 0x5C,  "Unassigned" },
  { 0x5D,  "Unassigned" },
  { 0x5E,  "Unassigned" },
  { 0x5F,  "Invalid message, unspecified" },
  { 0x60,  "Mandatory information element is missing" },
  { 0x61,  "Message type non-existent or not implemented" },
  { 0x62,  "Message not compatible with call state or message type non-existent or not implemented" },
  { 0x63,  "Information element nonexistent or not implemented" },
  { 0x64,  "Invalid information element contents" },
  { 0x65,  "Message not compatible with call state" },
  { 0x66,  "Recovery on timer expiry" },
  { 0x67,  "Parameter non-existent or not implemented - passed on" },
  { 0x68,  "Unassigned" },
  { 0x69,  "Unassigned" },
  { 0x6A,  "Unassigned" },
  { 0x6B,  "Unassigned" },
  { 0x6C,  "Unassigned" },
  { 0x6D,  "Unassigned" },
  { 0x6E,  "Message with unrecognized parameter discarded" },
  { 0x6F,  "Protocol error, unspecified" },
  { 0x70,  "Unassigned" },
  { 0x71,  "Unassigned" },
  { 0x72,  "Unassigned" },
  { 0x73,  "Unassigned" },
  { 0x74,  "Unassigned" },
  { 0x75,  "Unassigned" },
  { 0x76,  "Unassigned" },
  { 0x77,  "Unassigned" },
  { 0x78,  "Unassigned" },
  { 0x79,  "Unassigned" },
  { 0x7A,  "Unassigned" },
  { 0x7B,  "Unassigned" },
  { 0x7C,  "Unassigned" },
  { 0x7D,  "Unassigned" },
  { 0x7E,  "Unassigned" },
  { 0x7F,  "Internetworking, unspecified" },
  { 0,  NULL }
};
static value_string_ext ansi_isup_cause_code_vals_ext = VALUE_STRING_EXT_INIT(ansi_isup_cause_code_vals);

static const value_string ansi_isup_coding_standard_vals[] = {
  { 0, "CCITT Standard" },
  { 1, "Reserved for other international standards" },
  { 2, "ANSI Standard" },
  { 3, "Reserved" },
  { 0,  NULL }
};
void
dissect_isup_cause_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_reported_length(parameter_tvb);
  proto_tree_add_text(parameter_tree, parameter_tvb,0, -1, "Cause indicators (-> Q.850)");
  dissect_q931_cause_ie(parameter_tvb,0,length,
                        parameter_tree,
                        hf_isup_cause_indicator, &tap_cause_value, isup_parameter_type_value);
  proto_item_set_text(parameter_item, "Cause indicators, see Q.850 (%u byte%s length)", length , plurality(length, "", "s"));
}

static void
dissect_ansi_isup_cause_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 coding_standard;
  guint8 cause_value;
  int offset = 0;
  guint length = tvb_reported_length(parameter_tvb);

  coding_standard = (tvb_get_guint8(parameter_tvb, offset)&0x60)>>5;

  switch (coding_standard) {
    case 0:
      /*CCITT*/
      proto_tree_add_item(parameter_tree, hf_isup_cause_location, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(parameter_tree, hf_ansi_isup_coding_standard, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(parameter_tree, hf_isup_extension_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      offset ++;
      length--;
      if (length == 0)
        return;
      proto_tree_add_item(parameter_tree, hf_isup_cause_indicator, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      cause_value=tvb_get_guint8(parameter_tvb, offset)&0x7f;
      offset ++;
      length--;
      proto_item_set_text(parameter_item, "Cause indicators: %s (%u)", val_to_str_ext_const(cause_value, &q850_cause_code_vals_ext, "spare"),cause_value );
      if (length == 0) {
        return;
      }
      proto_tree_add_text(parameter_tree, parameter_tvb, offset,
                          length, "Diagnostic: %s",
                          tvb_bytes_to_str(parameter_tvb, offset, length));
      return;
    case 2:
      /*ANSI*/
      proto_tree_add_item(parameter_tree, hf_isup_cause_location, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(parameter_tree, hf_ansi_isup_coding_standard, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(parameter_tree, hf_isup_extension_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      offset ++;
      length--;
      if (length == 0)
        return;
      proto_tree_add_item(parameter_tree, hf_ansi_isup_cause_indicator, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      cause_value=tvb_get_guint8(parameter_tvb, offset)&0x7f;
      proto_item_set_text(parameter_item, "Cause indicators: %s (%u)",
                          val_to_str_ext_const(cause_value, &ansi_isup_cause_code_vals_ext, "spare"),
                          cause_value );
      offset ++;
      length--;
      if (length == 0) {
        return;
      }
      proto_tree_add_text(parameter_tree, parameter_tvb, offset,
                          length, "Diagnostic: %s",
                          tvb_bytes_to_str(parameter_tvb, offset, length));
      return;
    default:
      proto_tree_add_item(parameter_tree, hf_ansi_isup_coding_standard, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(parameter_tree, hf_isup_extension_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      break;
  }
  proto_item_set_text(parameter_item, "Cause indicators(%u byte%s length)", length , plurality(length, "", "s"));
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

  while(tvb_reported_length_remaining(parameter_tvb, offset) > 0){
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
dissect_isup_user_to_user_information_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_reported_length(parameter_tvb);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, -1,
                      "User-to-user info (-> Q.931)");
  dissect_q931_user_user_ie(parameter_tvb, pinfo, 0, length,
    parameter_tree );
  proto_item_set_text(parameter_item, "User-to-user information,(%u byte%s length)",
                      length , plurality(length, "", "s"));
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
dissect_isup_access_transport_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree,
                                        proto_item *parameter_item, packet_info *pinfo)
{ guint length = tvb_reported_length(parameter_tvb);

  proto_tree_add_text(parameter_tree, parameter_tvb, 0, -1,
                      "Access transport parameter field (-> Q.931)");

  if (q931_ie_handle)
    call_dissector(q931_ie_handle, parameter_tvb, pinfo, parameter_tree);

  proto_item_set_text(parameter_item, "Access transport (%u byte%s length)",
                      length , plurality(length, "", "s"));
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
  { 0xd0, "E.164 Group no"},
  { 0xd1, "E.164 Group no"},
  { 0xde, "E.163 Group no"},

  { 0xe2, "ITU-T IND Group no"},
  { 0xe3, "ITU-T IND Group no"},
  { 0,  NULL }
};
value_string_ext x213_afi_value_ext = VALUE_STRING_EXT_INIT(x213_afi_value);


/* Up-to-date information on the allocated ICP values can be found in   */
/*draft-gray-rfc1888bis-01 at                                           */
/*http://www.ietf.org/internet-drafts/draft-gray-rfc1888bis-01.txt      */
static const value_string iana_icp_values[] = {
  {   0x0, "IP Version 6 Address"},
  {   0x1, "IP Version 4 Address"},
  { 0,  NULL }
};

/*
 * XXX - shouldn't there be a centralized routine for dissecting NSAPs?
 * See also "dissect_atm_nsap()" in epan/dissectors/packet-arp.c and
 * "print_nsap_net_buf()" and "print_nsap_net()" in epan/osi_utils.c.
 */
void
dissect_nsap(tvbuff_t *parameter_tvb,gint offset,gint len, proto_tree *parameter_tree)
{
  guint8 afi;
  guint8 length = 0;
  guint icp, cc_offset;

  afi = tvb_get_guint8(parameter_tvb, offset);

  switch ( afi ) {
    case 0x35:  /* IANA ICP Binary fortmat*/
      proto_tree_add_text(parameter_tree, parameter_tvb, offset, 3,
                          "IDP = %s", tvb_bytes_to_str(parameter_tvb, offset, 3));

      proto_tree_add_uint(parameter_tree, hf_afi, parameter_tvb, offset, 1, afi );
      offset = offset + 1;
      icp = tvb_get_ntohs(parameter_tvb, offset);
      proto_tree_add_uint(parameter_tree, hf_iana_icp, parameter_tvb, offset, 1, icp );
      if ( icp == 0 ){ /* IPv6 addr */
        proto_tree_add_text(parameter_tree, parameter_tvb, offset + 2 , 17,
                            "DSP = %s", tvb_bytes_to_str(parameter_tvb, offset + 2, 17));
        proto_tree_add_item(parameter_tree, hf_nsap_ipv6_addr, parameter_tvb, offset + 2,
                            16, ENC_NA);

      }
      else { /* IPv4 addr */
        /* XXX - this is really only for ICP 1 */
        proto_tree_add_text(parameter_tree, parameter_tvb, offset + 2, 17,
                            "DSP = %s", tvb_bytes_to_str(parameter_tvb, offset + 2, 17));
        proto_tree_add_item(parameter_tree, hf_nsap_ipv4_addr, parameter_tvb, offset + 2, 4, ENC_BIG_ENDIAN);
      }

      break;
    case 0x45:  /* E.164 ATM format */
    case 0xC3:  /* E.164 ATM group format */
      proto_tree_add_text(parameter_tree, parameter_tvb, offset, 9,
                          "IDP = %s", tvb_bytes_to_str(parameter_tvb, offset, 9));

      proto_tree_add_uint(parameter_tree, hf_afi, parameter_tvb, offset, 1, afi );

      proto_tree_add_text(parameter_tree, parameter_tvb, offset + 1, 8,
                          "IDI = %s", tvb_bytes_to_str(parameter_tvb, offset + 1, 8));
      offset = offset +1;
      /* Dissect country code */
      cc_offset = offset;
      dissect_e164_cc(parameter_tvb, parameter_tree, 3, TRUE);

      proto_tree_add_text(parameter_tree,parameter_tvb, cc_offset, length,"DSP length %u(len %u -9 )",(len-9),len );

      proto_tree_add_item(parameter_tree, hf_bicc_nsap_dsp, parameter_tvb, offset + 8, (len - 9),ENC_NA);

      break;
    default:
      proto_tree_add_uint(parameter_tree, hf_afi, parameter_tvb, offset, len, afi );
  }/* end switch afi */

}


#define  ACTION_INDICATOR                               0x01
#define  BACKBONE_NETWORK_CONNECTION_IDENTIFIER         0x02
#define  INTERWORKING_FUNCTION_ADDRESS                  0x03
#define  CODEC_LIST                                     0x04
#define  CODEC                                          0x05
#define  BAT_COMPATIBILITY_REPORT                       0x06
#define  BEARER_NETWORK_CONNECTION_CHARACTERISTICS      0x07
#define  BEARER_CONTROL_INFORMATION                     0x08
#define  BEARER_CONTROL_TUNNELLING                      0x09
#define  BEARER_CONTROL_UNIT_IDENTIFIER                 0x0A
#define  SIGNAL                                         0x0B
#define  BEARER_REDIRECTION_CAPABILITY                  0x0C
#define  BEARER_REDIRECTION_INDICATORS                  0x0D
#define  SIGNAL_TYPE                                    0x0E
#define  DURATION                                       0x0F


static const value_string bat_ase_list_of_Identifiers_vals[] = {

  { 0x00                                        ,   "spare" },
  { ACTION_INDICATOR                            ,   "Action Indicator" },
  { BACKBONE_NETWORK_CONNECTION_IDENTIFIER      ,   "Backbone Network Connection Identifier" },
  { INTERWORKING_FUNCTION_ADDRESS               ,   "Interworking Function Address" },
  { CODEC_LIST                                  ,   "Codec List" },
  { CODEC                                       ,   "Codec" },
  { BAT_COMPATIBILITY_REPORT                    ,   "BAT Compatibility Report" },
  { BEARER_NETWORK_CONNECTION_CHARACTERISTICS   ,   "Bearer Network Connection Characteristics" },
  { BEARER_CONTROL_INFORMATION                  ,   "Bearer Control Information"},
  { BEARER_CONTROL_TUNNELLING                   ,   "Bearer Control Tunnelling"},
  { BEARER_CONTROL_UNIT_IDENTIFIER              ,   "Bearer Control Unit Identifier" },
  { SIGNAL                                      ,   "Signal"},
  { BEARER_REDIRECTION_CAPABILITY               ,   "Bearer Redirection Capability"},
  { BEARER_REDIRECTION_INDICATORS               ,   "Bearer Redirection Indicators"},
  { SIGNAL_TYPE                                 ,   "Signal Type"},
  { DURATION                                    ,   "Duration" },
  { 0,  NULL }
};
static value_string_ext bat_ase_list_of_Identifiers_vals_ext = VALUE_STRING_EXT_INIT(bat_ase_list_of_Identifiers_vals);

/*ITU-T Q.765.5 (06/2000) 13*/
static const value_string Instruction_indicator_for_general_action_vals[] =
{
  { 0,  "Pass on information element"},
  { 1,  "Discard information element"},
  { 2,  "Discard BICC data"},
  { 3,  "Release call"},
  { 0,  NULL}};

static const value_string Instruction_indicator_for_pass_on_not_possible_vals[] = {
  { 0,  "Release call"},
  { 1,  "Discard information element"},
  { 2,  "Discard BICC data"},
  { 3,  "reserved (interpreted as 00)"},
  { 0,  NULL}};

static const value_string bat_ase_action_indicator_field_vals[] = {

  { 0x00,  "no indication"},
  { 0x01,  "connect backward"},
  { 0x02,  "connect forward"},
  { 0x03,  "connect forward, no notification"},
  { 0x04,  "connect forward, plus notification"},
  { 0x05,  "connect forward, no notification + selected codec"},
  { 0x06,  "connect forward, plus notification + selected codec"},
  { 0x07,  "use idle"},
  { 0x08,  "connected"},
  { 0x09,  "switched"},
  { 0x0a,  "selected codec"},
  { 0x0b,  "modify codec"},
  { 0x0c,  "successful codec modification"},
  { 0x0d,  "codec modification failure"},
  { 0x0e,  "mid-call codec negotiation"},
  { 0x0f,  "modify to selected codec information"},
  { 0x10,  "mid-call codec negotiation failure"},
  { 0x11,  "start signal, notify"},
  { 0x12,  "start signal, no notify"},
  { 0x13,  "stop signal, notify"},
  { 0x14,  "stop signal, no notify"},
  { 0x15,  "start signal acknowledge"},
  { 0x16,  "start signal reject"},
  { 0x17,  "stop signal acknowledge"},
  { 0x18,  "bearer redirect"},
  { 0,     NULL }
};
static value_string_ext bat_ase_action_indicator_field_vals_ext = VALUE_STRING_EXT_INIT(bat_ase_action_indicator_field_vals);

static const true_false_string BCTP_BVEI_value  = {
  "Version Error Indication, BCTP version not supported",
  "No indication"
};

static const value_string BCTP_Tunnelled_Protocol_Indicator_vals[] = {

  { 0x20,  "IPBCP (text encoded)"},
  { 0x21,  "spare (text encoded protocol)"},
  { 0x22,  "not used"},
  { 0,  NULL }
};

static const true_false_string BCTP_TPEI_value  = {
  "Protocol Error Indication, Bearer Control Protocol not supported",
  "No indication"
};


#define  ITU_T  0x01
#define  ETSI   0x02

static const value_string bat_ase_organization_identifier_subfield_vals[] = {

  { 0x00,   "no indication"},
  { 0x01,   "ITU-T"},
  { 0x02,   "ETSI (refer to TS 26.103)"},
  { 0,  NULL }
};

#define G_711_64_A            0x01
#define G_711_64_U            0x02
#define G_711_56_A            0x03
#define G_711_56_U            0x04
#define G_722_SB_ADPCM        0x05
#define G_723_1               0x06
#define G_723_1_Annex_A       0x07
#define G_726_ADPCM           0x08
#define G_727_Embedded_ADPCM  0x09
#define G_728                 0x0a
#define G_729_CS_ACELP        0x0b
#define G_729_Annex_B         0x0c

static const value_string ITU_T_codec_type_subfield_vals[] = {

  { 0x00,                  "no indication"},
  { G_711_64_A,            "G.711 64 kbit/s A-law"},
  { G_711_64_U,            "G.711 64 kbit/s -law"},
  { G_711_56_A,            "G.711 56 kbit/s A-law"},
  { G_711_56_U,            "G.711 56 kbit/s -law"},
  { G_722_SB_ADPCM,        "G.722 (SB-ADPCM)"},
  { G_723_1,               "G.723.1"},
  { G_723_1_Annex_A,       "G.723.1 Annex A (silence suppression)"},
  { G_726_ADPCM,           "G.726 (ADPCM)"},
  { G_727_Embedded_ADPCM,  "G.727 (Embedded ADPCM)"},
  { G_728,                 "G.728"},
  { G_729_CS_ACELP,        "G.729 (CS-ACELP)"},
  { G_729_Annex_B,         "G.729 Annex B (silence suppression)"},
  { 0,  NULL }
};
static value_string_ext ITU_T_codec_type_subfield_vals_ext = VALUE_STRING_EXT_INIT(ITU_T_codec_type_subfield_vals);

static const value_string ETSI_codec_type_subfield_vals[] = {

  { 0x00, "GSM Full Rate (13.0 kBit/s)( GSM FR )"},
  { 0x01, "GSM Half Rate (5.6 kBit/s) ( GSM HR )"},
  { 0x02, "GSM Enhanced Full Rate (12.2 kBit/s)( GSM EFR )"},
  { 0x03, "Full Rate Adaptive Multi-Rate ( FR AMR )"},
  { 0x04, "Half Rate Adaptive Multi-Rate ( HR AMR )"},
  { 0x05, "UMTS Adaptive Multi-Rate ( UMTS AMR )"},
  { 0x06, "UMTS Adaptive Multi-Rate 2 ( UMTS AMR 2 )"},
  { 0x07, "TDMA Enhanced Full Rate (7.4 kBit/s) ( TDMA EFR )"},
  { 0x08, "PDC Enhanced Full Rate (6.7 kBit/s) ( PDC EFR )"},
  { 0x09, "Full Rate Adaptive Multi-Rate WideBand ( FR AMR-WB )"},
  { 0x0a, "UMTS Adaptive Multi-Rate WideBand ( UMTS AMR-WB )"},
  { 0x0b, "8PSK Half Rate Adaptive Multi-Rate ( OHR AMR )"},
  { 0x0c, "8PSK Full Rate Adaptive Multi-Rate WideBand  ( OFR AMR-WB )"},
  { 0x0d, "8PSK Half Rate Adaptive Multi-Rate WideBand ( OHR AMR-WB )"},
  { 0xfe, "Reserved for future use."},
  { 0xff, "Reserved for MuMe dummy Codec Type ( MuMe )"},
  { 0,  NULL }
};
static value_string_ext ETSI_codec_type_subfield_vals_ext = VALUE_STRING_EXT_INIT(ETSI_codec_type_subfield_vals);

static const value_string bat_initial_codec_mode_vals[] = {
  {0x7, "12.2 kbps"},
  {0x6, "10.2 kbps"},
  {0x5, "7.95 kbps"},
  {0x4, "7.40 kbps"},
  {0x3, "6.70 kbps"},
  {0x2, "5.90 kbps"},
  {0x1, "5.15 kbps"},
  {0x0, "4.75 kbps"},
  {0, NULL}
};

static const value_string optimisation_mode_vals[] = {
  { 0,  "Optimisation of the ACS not supported,"},
  { 1,  "Optimisation of the ACS supported,"},
  { 0,  NULL }
};

static const value_string bearer_network_connection_characteristics_vals[] = {

  { 0x00,   "no indication"},
  { 0x01,   "AAL type 1"},
  { 0x02,   "AAL type 2"},
  { 0x03,   "Structured AAL type 1"},
  { 0x04,   "IP/RTP"},
  { 0x05,   "TDM (reserved for use by ITU-T Rec. Q.1950)"},
  { 0,  NULL }
};
value_string_ext bearer_network_connection_characteristics_vals_ext = VALUE_STRING_EXT_INIT(bearer_network_connection_characteristics_vals);

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
  { 0x00,  " no indication"},
  { 0x01,  "late cut-through request"},
  { 0x02,  "redirect temporary reject"},
  { 0x03,  "redirect backwards request"},
  { 0x04,  "redirect forwards request"},
  { 0x05,  "redirect bearer release request"},
  { 0x06,  "redirect bearer release proceed"},
  { 0x07,  "redirect bearer release complete"},
  { 0x08,  "redirect cut-through request"},
  { 0x09,  "redirect bearer connected indication"},
  { 0x0a,  "redirect failure"},
  { 0x0b,  "new connection identifier"},
  { 0,  NULL }
};
static value_string_ext Bearer_Redirection_Indicator_vals_ext = VALUE_STRING_EXT_INIT(Bearer_Redirection_Indicator_vals);

/*26/Q.765.5 - Signal Type */
static const value_string BAT_ASE_Signal_Type_vals[] = {
  { 0x00,  "DTMF 0"},
  { 0x01,  "DTMF 1"},
  { 0x02,  "DTMF 2"},
  { 0x03,  "DTMF 3"},
  { 0x04,  "DTMF 4"},
  { 0x05,  "DTMF 5"},
  { 0x06,  "DTMF 6"},
  { 0x07,  "DTMF 7"},
  { 0x08,  "DTMF 8"},
  { 0x09,  "DTMF 9"},
  { 0x0a,  "DTMF *"},
  { 0x0b,  "DTMF #"},
  { 0x0c,  "DTMF A"},
  { 0x0d,  "DTMF B"},
  { 0x0e,  "DTMF C"},
  { 0x0f,  "DTMF D"},
  /* 0001 0000
   * to
   * 0011 1111
   * Spare
   */
  { 0x10,  "Spare"},
  { 0x11,  "Spare"},
  { 0x12,  "Spare"},
  { 0x13,  "Spare"},
  { 0x14,  "Spare"},
  { 0x15,  "Spare"},
  { 0x16,  "Spare"},
  { 0x17,  "Spare"},
  { 0x18,  "Spare"},
  { 0x19,  "Spare"},
  { 0x1a,  "Spare"},
  { 0x1b,  "Spare"},
  { 0x1c,  "Spare"},
  { 0x1d,  "Spare"},
  { 0x1e,  "Spare"},
  { 0x1f,  "Spare"},
  { 0x20,  "Spare"},
  { 0x21,  "Spare"},
  { 0x22,  "Spare"},
  { 0x23,  "Spare"},
  { 0x24,  "Spare"},
  { 0x25,  "Spare"},
  { 0x26,  "Spare"},
  { 0x27,  "Spare"},
  { 0x28,  "Spare"},
  { 0x29,  "Spare"},
  { 0x2a,  "Spare"},
  { 0x2b,  "Spare"},
  { 0x2c,  "Spare"},
  { 0x2d,  "Spare"},
  { 0x2e,  "Spare"},
  { 0x2f,  "Spare"},
  { 0x30,  "Spare"},
  { 0x31,  "Spare"},
  { 0x32,  "Spare"},
  { 0x33,  "Spare"},
  { 0x34,  "Spare"},
  { 0x35,  "Spare"},
  { 0x36,  "Spare"},
  { 0x37,  "Spare"},
  { 0x38,  "Spare"},
  { 0x39,  "Spare"},
  { 0x3a,  "Spare"},
  { 0x3b,  "Spare"},
  { 0x3c,  "Spare"},
  { 0x3d,  "Spare"},
  { 0x3e,  "Spare"},
  { 0x3f,  "Spare"},

  { 0x40,  "dial tone"},
  { 0x41,  "PABX internal dial tone"},
  { 0x42,  "special dial tone"},
  { 0x43,  "second dial tone"},
  { 0x44,  "ringing tone"},
  { 0x45,  "special ringing tone"},
  { 0x46,  "busy tone"},
  { 0x47,  "congestion tone"},
  { 0x48,  "special information tone"},
  { 0x49,  "warning tone"},
  { 0x4a,  "intrusion tone"},
  { 0x4b,  "call waiting tone"},
  { 0x4c,  "pay tone"},
  { 0x4d,  "payphone recognition tone"},
  { 0x4e,  "comfort tone"},
  { 0x4f,  "tone on hold"},
  { 0x50,  "record tone"},
  { 0x51,  "Caller waiting tone"},
  { 0x52,  "positive indication tone"},
  { 0x53,  "negative indication tone"},
  { 0,  NULL }
};
static value_string_ext BAT_ASE_Signal_Type_vals_ext = VALUE_STRING_EXT_INIT(BAT_ASE_Signal_Type_vals);

static const value_string BAT_ASE_Report_Reason_vals[] = {

  { 0x00,   "no indication"},
  { 0x01,   "information element non-existent or not implemented"},
  { 0x02,   "BICC data with unrecognized information element, discarded"},
  { 0,  NULL }
};
/* This routine should bve called with offset at Organization_Identifier not the lengh indicator
 * because of use from other disectors.
 */
extern int dissect_codec_mode(proto_tree *tree, tvbuff_t *tvb, int offset, int len) {
  guint8 tempdata;
  proto_tree *scs_item, *acs_item;
  proto_tree *scs_tree, *acs_tree;


  tempdata = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(tree, hf_Organization_Identifier , tvb, offset, 1, tempdata );
  switch ( tempdata ){
    case ITU_T :
      offset = offset + 1;
      tempdata = tvb_get_guint8(tvb, offset);
      proto_tree_add_uint(tree, hf_codec_type , tvb, offset, 1, tempdata );
      offset = offset + 1;
      switch ( tempdata ) {
        case G_711_64_A :
        case G_711_64_U :
        case G_711_56_A :
        case G_711_56_U :
        case G_722_SB_ADPCM :
        case G_723_1 :
        case G_723_1_Annex_A :
          /* These codecs have no configuration data */
          break;
        case G_726_ADPCM :
        case G_727_Embedded_ADPCM :
          /* four bit config data, TODO decode config */
          if ( len > 2 ) {
            tempdata = tvb_get_guint8(tvb, offset);
            proto_tree_add_text(tree, tvb, offset, 1, "Configuration data : 0x%x", tempdata);
            offset = offset + 1;
          }
          break;
        case G_728 :
        case G_729_CS_ACELP :
        case G_729_Annex_B :
          /* three bit config data, TODO decode config */
          if ( len > 2 ) {
            tempdata = tvb_get_guint8(tvb, offset);
            proto_tree_add_text(tree, tvb, offset, 1 , "Configuration data : 0x%x", tempdata);
            offset = offset + 1;
          }
          break;
        default:
          break;

      }
      break;
    case ETSI:
      offset = offset + 1;
      tempdata = tvb_get_guint8(tvb, offset);
      proto_tree_add_uint(tree, hf_etsi_codec_type , tvb, offset, 1, tempdata );
      if ( len > 2 ) {
        offset = offset + 1;
        tempdata = tvb_get_guint8(tvb, offset);

        acs_item = proto_tree_add_item(tree, hf_active_code_set, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        acs_tree = proto_item_add_subtree(acs_item,ett_acs);
        proto_tree_add_item(acs_tree, hf_active_code_set_12_2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(acs_tree, hf_active_code_set_10_2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(acs_tree, hf_active_code_set_7_95, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(acs_tree, hf_active_code_set_7_40, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(acs_tree, hf_active_code_set_6_70, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(acs_tree, hf_active_code_set_5_90, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(acs_tree, hf_active_code_set_5_15, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(acs_tree, hf_active_code_set_4_75, tvb, offset, 1, ENC_LITTLE_ENDIAN);

      }
      if ( len > 3 ) {
        offset = offset + 1;
        tempdata = tvb_get_guint8(tvb, offset);

        scs_item = proto_tree_add_item(tree, hf_supported_code_set, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        scs_tree = proto_item_add_subtree(scs_item,ett_scs);
        proto_tree_add_item(scs_tree, hf_supported_code_set_12_2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(scs_tree, hf_supported_code_set_10_2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(scs_tree, hf_supported_code_set_7_95, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(scs_tree, hf_supported_code_set_7_40, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(scs_tree, hf_supported_code_set_6_70, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(scs_tree, hf_supported_code_set_5_90, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(scs_tree, hf_supported_code_set_5_15, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(scs_tree, hf_supported_code_set_4_75, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      }
      if ( len > 4 ) {
        offset = offset + 1;
        proto_tree_add_item(tree, hf_optimisation_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_max_codec_modes, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      }
      offset = offset + 1;
      break;
    default:
      offset = offset + 1;
      tempdata = tvb_get_guint8(tvb, offset);
      proto_tree_add_text(tree, tvb, offset, len ,
                          "Unknown organisation Identifier ( Non ITU-T/ETSI codec ) %u", tempdata);
      offset = offset + len - 1;
      break;
  }
  /* switch OID */

  return offset;
}

static int
dissect_codec(tvbuff_t *parameter_tvb, proto_tree *bat_ase_element_tree, gint length_indicator, gint offset,gint identifier)
{
/* offset is at length indicator e.g 1 step past identifier */
  guint8 compatibility_info;

  proto_tree_add_uint(bat_ase_element_tree , hf_bat_ase_identifier , parameter_tvb, offset - 1, 1, identifier );
  proto_tree_add_uint(bat_ase_element_tree , hf_length_indicator  , parameter_tvb, offset, 1, length_indicator );
  offset = offset + 1;
  compatibility_info = tvb_get_guint8(parameter_tvb, offset);
  proto_tree_add_uint(bat_ase_element_tree, hf_Instruction_ind_for_general_action , parameter_tvb, offset, 1, compatibility_info );
  proto_tree_add_boolean(bat_ase_element_tree, hf_Send_notification_ind_for_general_action , parameter_tvb, offset, 1, compatibility_info );
  proto_tree_add_uint(bat_ase_element_tree, hf_Instruction_ind_for_pass_on_not_possible , parameter_tvb, offset, 1, compatibility_info );
  proto_tree_add_boolean(bat_ase_element_tree, hf_Send_notification_ind_for_pass_on_not_possible , parameter_tvb, offset, 1, compatibility_info );
  proto_tree_add_boolean(bat_ase_element_tree, hf_isup_extension_ind , parameter_tvb, offset, 1, compatibility_info );

  offset = dissect_codec_mode(bat_ase_element_tree, parameter_tvb, offset+1,length_indicator-1);
  return offset;
}

/* Dissect BAT ASE message according to Q.765.5 200006 and Amendment 1 200107
 * Layout of message        Length          Octet
 *  Element name
 *  Identifier                  1           1
 *  Length indicator            1           2
 *  Compatibility information   1           3
 *  Contents                    1           4
 *  Identifier                  n           m
 *  Length indicator            n
 *  Compatibility information   n
 *  Contents                    n           p
 */

static void
dissect_bat_ase_Encapsulated_Application_Information(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, gint offset)
{
  gint        length = tvb_reported_length_remaining(parameter_tvb, offset), list_end;
  tvbuff_t   *next_tvb;
  proto_tree *bat_ase_tree, *bat_ase_element_tree, *bat_ase_iwfa_tree;
  proto_item *bat_ase_item, *bat_ase_element_item, *bat_ase_iwfa_item;
  guint8      identifier,content, BCTP_Indicator_field_1, BCTP_Indicator_field_2;
  guint8      tempdata, element_no, number_of_indicators;
  guint16     sdp_length;
  guint8      diagnostic_len;
  guint8      length_ind_len;
  guint       tempdata16;
  guint       content_len, length_indicator;
  guint       duration;
  guint       diagnostic;
  guint32      bncid, Local_BCU_ID;

  element_no = 0;

  bat_ase_item = proto_tree_add_text(parameter_tree,parameter_tvb, offset, -1,
                                     "Bearer Association Transport (BAT) Application Service Element (ASE) Encapsulated Application Information:");
  bat_ase_tree = proto_item_add_subtree(bat_ase_item , ett_bat_ase);

  proto_tree_add_text(bat_ase_tree, parameter_tvb, offset, -1,
                      "BAT ASE Encapsulated Application Information, (%u byte%s length)", length, plurality(length, "", "s"));
  while(tvb_reported_length_remaining(parameter_tvb, offset) > 0){
    element_no = element_no + 1;
    identifier = tvb_get_guint8(parameter_tvb, offset);

    /* length indicator may be 11 bits long */
    offset = offset + 1;
    proto_tree_add_item( bat_ase_tree, hf_isup_extension_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN );
    tempdata = tvb_get_guint8(parameter_tvb, offset);
    if ( tempdata & 0x80 ) {
      length_indicator = tempdata & 0x7f;
      length_ind_len = 1;
    }
    else {
      offset = offset + 1;
      tempdata16 = ( tempdata & 0x7f );
      length_indicator = tvb_get_guint8(parameter_tvb, offset)& 0x0f;
      length_indicator = length_indicator << 7;
      length_indicator = length_indicator + tempdata16;
      length_ind_len = 2;
    }

    bat_ase_element_item = proto_tree_add_text(bat_ase_tree,parameter_tvb,
                                               ( offset - length_ind_len),(length_indicator + 2),"BAT ASE Element %u, Identifier: %s",element_no,
                                               val_to_str_ext(identifier,&bat_ase_list_of_Identifiers_vals_ext,"unknown (%u)"));
    bat_ase_element_tree = proto_item_add_subtree(bat_ase_element_item ,
                                                  ett_bat_ase_element);
    if ( identifier != CODEC ) {
      /* identifier, length indicator and compabillity info must be printed inside CODEC */
      /* dissection in order to use dissect_codec routine for codec list */
      proto_tree_add_uint(bat_ase_element_tree , hf_bat_ase_identifier , parameter_tvb,
                          offset - length_ind_len, 1, identifier );
      proto_tree_add_uint(bat_ase_element_tree , hf_length_indicator  , parameter_tvb,
                          offset - length_ind_len + 1, length_ind_len, length_indicator );

      offset = offset + 1;
      proto_tree_add_item( bat_ase_element_tree, hf_isup_extension_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN );
      proto_tree_add_item( bat_ase_element_tree, hf_Send_notification_ind_for_pass_on_not_possible, parameter_tvb, offset, 1, ENC_BIG_ENDIAN );
      proto_tree_add_item( bat_ase_element_tree, hf_Instruction_ind_for_pass_on_not_possible, parameter_tvb, offset, 1, ENC_BIG_ENDIAN );
      proto_tree_add_item( bat_ase_element_tree, hf_Send_notification_ind_for_general_action, parameter_tvb, offset, 1, ENC_BIG_ENDIAN );
      proto_tree_add_item( bat_ase_element_tree, hf_Instruction_ind_for_general_action, parameter_tvb, offset, 1, ENC_BIG_ENDIAN );
      offset = offset + 1;
    }
    content_len = length_indicator - 1 ; /* exclude the treated Compatibility information */

    /* content will be different depending on identifier */
    switch ( identifier ){

      case ACTION_INDICATOR :

        content = tvb_get_guint8(parameter_tvb, offset);
        proto_tree_add_uint(bat_ase_element_tree, hf_Action_Indicator , parameter_tvb, offset, 1, content );
        proto_item_append_text(bat_ase_element_item, " - %s",
                               val_to_str_ext(content,&bat_ase_action_indicator_field_vals_ext, "unknown (%u)"));
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
        bat_ase_iwfa_item = proto_tree_add_item(bat_ase_element_tree, hf_bat_ase_biwfa, parameter_tvb, offset, content_len,
                                                ENC_NA);
        bat_ase_iwfa_tree = proto_item_add_subtree(bat_ase_iwfa_item , ett_bat_ase_iwfa);
        dissect_nsap(parameter_tvb, offset, content_len, bat_ase_iwfa_tree);

        offset = offset + content_len;
        break;
      case CODEC_LIST :
        list_end = offset + content_len;
        while ( offset < ( list_end - 1 )) {
          identifier = tvb_get_guint8(parameter_tvb, offset);
          offset = offset + 1;
          tempdata = tvb_get_guint8(parameter_tvb, offset);
          if ( tempdata & 0x80 ) {
            length_indicator = tempdata & 0x7f;
          }
          else {
            offset = offset +1;
            length_indicator = tvb_get_guint8(parameter_tvb, offset);
            length_indicator = length_indicator << 7;
            length_indicator = length_indicator & ( tempdata & 0x7f );
          }
          offset = dissect_codec(parameter_tvb, bat_ase_element_tree, length_indicator , offset, identifier);
        }
        break;
      case CODEC :
        /* offset is at length indicator in this case */
        offset = dissect_codec(parameter_tvb, bat_ase_element_tree, length_indicator , offset, identifier);
        break;/* case codec */
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
                               val_to_str_ext(tempdata,&bearer_network_connection_characteristics_vals_ext, "unknown (%u)"));

        offset = offset + content_len;
        break;
/* The Bearer Control Information information element contains the bearer control tunnelling protocol */
/* ITU-T Q.1990 (2001), BICC bearer control tunnelling protocol. */

      case BEARER_CONTROL_INFORMATION :
        BCTP_Indicator_field_1 = tvb_get_guint8(parameter_tvb, offset);
        proto_tree_add_uint(bat_ase_element_tree, hf_BCTP_Version_Indicator,
                            parameter_tvb, offset, 1, BCTP_Indicator_field_1 );

        proto_tree_add_boolean(bat_ase_element_tree, hf_BVEI,
                               parameter_tvb, offset, 1, BCTP_Indicator_field_1 );
        offset = offset + 1;

        BCTP_Indicator_field_2 = tvb_get_guint8(parameter_tvb, offset);

        proto_tree_add_uint(bat_ase_element_tree, hf_Tunnelled_Protocol_Indicator ,
                            parameter_tvb, offset, 1, BCTP_Indicator_field_2 );

        proto_tree_add_boolean(bat_ase_element_tree, hf_TPEI,
                               parameter_tvb, offset, 1, BCTP_Indicator_field_2 );
        offset = offset + 1;

        sdp_length = ( length_indicator ) - 3;

        if(sdp_length > tvb_length_remaining(parameter_tvb,offset)){
          /* If this is a segmented message we may not have all the data */
          next_tvb = tvb_new_subset_remaining(parameter_tvb, offset);
        }else{
          next_tvb = tvb_new_subset(parameter_tvb, offset, sdp_length, sdp_length);
        }
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
        proto_tree_add_text(bat_ase_element_tree, parameter_tvb, offset, 1, "Network ID Length indicator = %u",tempdata);
        offset = offset + 1;
        if ( tempdata > 0 ) {

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
        /* As type is Constructor new elements follow, return to main loop */
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



/*
Octet
    -------------------------------------------
1   | ext. Application context identifier lsb
    -------------------------------------------
1a  | ext. msb
    -------------------------------------------
2   | ext. spare                        SNI RCI
    -------------------------------------------
3   | ext. SI APM segmentation indicator
    -------------------------------------------
3a  | ext. Segmentation local reference
    -------------------------------------------
4a  |
:   |   APM-user information
4n  |
    +-------------------------------------------

        Figure 77/Q.763 . Application transport parameter field
*/
static void
dissect_isup_application_transport_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{

  guint8 si_and_apm_seg_ind;
  guint8 apm_Segmentation_local_ref = 0;
  guint16 aci16;
  gint offset = 0;
  guint8 octet;
  guint length = tvb_reported_length(parameter_tvb);

  gboolean more_frag;
  gboolean   save_fragmented;
  tvbuff_t* new_tvb = NULL;
  tvbuff_t* next_tvb = NULL;
  fragment_data *frag_msg = NULL;

  proto_tree_add_text(parameter_tree, parameter_tvb, offset, -1, "Application transport parameter fields:");
  proto_item_set_text(parameter_item, "Application transport, (%u byte%s length)", length , plurality(length, "", "s"));
  aci16 = tvb_get_guint8(parameter_tvb, offset);

  if ( (aci16 & H_8BIT_MASK) == 0x80) {
    /* Octet 1 */
    aci16 = aci16 & 0x7f;
    proto_tree_add_item( parameter_tree, hf_isup_extension_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN );
    proto_tree_add_uint(parameter_tree, hf_isup_app_cont_ident , parameter_tvb, offset, 1, aci16);
    offset = offset + 1;
  }
  /* Octet 1a */
  else {
    aci16 = (aci16<<8) | (tvb_get_guint8(parameter_tvb, offset) & 0x7f);
    proto_tree_add_uint(parameter_tree, hf_isup_app_cont_ident , parameter_tvb, offset, 2, aci16);
    offset = offset + 2;
  }

  /* Octet 2 */
  proto_tree_add_text(parameter_tree, parameter_tvb, offset, -1, "Application transport instruction indicators: ");
  proto_tree_add_item( parameter_tree, hf_isup_extension_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item( parameter_tree, hf_isup_app_Send_notification_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item( parameter_tree, hf_isup_app_Release_call_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN );
  offset = offset + 1;

  /* Octet 3*/
  proto_tree_add_text(parameter_tree, parameter_tvb, offset, 1, "APM segmentation indicator:");
  si_and_apm_seg_ind  = tvb_get_guint8(parameter_tvb, offset);
  proto_tree_add_item( parameter_tree, hf_isup_extension_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item( parameter_tree, hf_isup_apm_si_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item( parameter_tree, hf_isup_apm_segmentation_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN );
  offset = offset + 1;

  /* Octet 3a */
  if ( (si_and_apm_seg_ind & H_8BIT_MASK) == 0x00) {
    apm_Segmentation_local_ref  = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_item( parameter_tree, hf_isup_extension_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN );
    proto_tree_add_item( parameter_tree, hf_isup_apm_slr, parameter_tvb, offset, 1, ENC_BIG_ENDIAN );
    offset = offset + 1;
  }
  /* For APM'98'-user applications. ( aci 0 - 3 ), APM-user information field starts at octet 4 */
  if (aci16 > 3) {
    /* Octet 4 Originating Address length */
    octet = tvb_get_guint8(parameter_tvb,offset);
    proto_tree_add_item( parameter_tree, hf_isup_orig_addr_len, parameter_tvb, offset, 1, ENC_BIG_ENDIAN );
    offset++;
    if ( octet != 0){
      /* 4b */
      proto_tree_add_item( parameter_tree, hf_isup_odd_even_indicator, parameter_tvb, offset, 1, ENC_BIG_ENDIAN );
      /* nature of address indicator */
      offset++;
      proto_tree_add_item( parameter_tree, hf_isup_inn_indicator, parameter_tvb, offset, 1, ENC_BIG_ENDIAN );
      proto_tree_add_item( parameter_tree, hf_isup_numbering_plan_indicator, parameter_tvb, offset, 1, ENC_BIG_ENDIAN );
      offset++;
      /* Address digits */
      proto_tree_add_text(parameter_tree, parameter_tvb, offset, octet - 2, "Address digits");
      offset = offset + octet - 2;
    }
    /* Octet 5 Destination Address length */
    octet = tvb_get_guint8(parameter_tvb,offset);
    proto_tree_add_item( parameter_tree, hf_isup_dest_addr_len, parameter_tvb, offset, 1, ENC_BIG_ENDIAN );
    offset++;
    if ( octet != 0){
      /* 4b */
      proto_tree_add_item( parameter_tree, hf_isup_odd_even_indicator, parameter_tvb, offset, 1, ENC_BIG_ENDIAN );
      /* nature of address indicator */
      offset++;
      proto_tree_add_item( parameter_tree, hf_isup_inn_indicator, parameter_tvb, offset, 1, ENC_BIG_ENDIAN );
      proto_tree_add_item( parameter_tree, hf_isup_numbering_plan_indicator, parameter_tvb, offset, 1, ENC_BIG_ENDIAN );
      offset++;
      /* Address digits */
      proto_tree_add_text(parameter_tree, parameter_tvb, offset, octet - 2, "Address digits");
      offset = offset + octet - 2;
    }
  }
  /*
   * Defragment ?
   *
   */
  if (isup_apm_desegment){
    if ((si_and_apm_seg_ind != 0xc0) && ((si_and_apm_seg_ind & H_8BIT_MASK)!=0x80)){
      /* debug g_warning("got here Frame %u",pinfo->fd->num); */
      /* Segmented message */
      save_fragmented = pinfo->fragmented;
      pinfo->fragmented = TRUE;
      more_frag = TRUE;
      if (si_and_apm_seg_ind == 0)
        more_frag = FALSE;

      frag_msg = fragment_add_seq_next(parameter_tvb, offset, pinfo,
                                       (apm_Segmentation_local_ref & 0x7f),         /* ID for fragments belonging together */
                                       isup_apm_msg_fragment_table,                 /* list of message fragments */
                                       isup_apm_msg_reassembled_table,              /* list of reassembled messages */
                                       tvb_length_remaining(parameter_tvb, offset), /* fragment length - to the end */
                                       more_frag);                                  /* More fragments? */

      if ((si_and_apm_seg_ind & 0x3f) !=0 && (si_and_apm_seg_ind &0x40) !=0){
        /* First fragment set number of fragments */
        fragment_set_tot_len(pinfo, apm_Segmentation_local_ref & 0x7f, isup_apm_msg_fragment_table, (si_and_apm_seg_ind & 0x3f));
      }

      new_tvb = process_reassembled_data(parameter_tvb, offset, pinfo,
                                         "Reassembled ISUP", frag_msg, &isup_apm_msg_frag_items,
                                         NULL, parameter_tree);

      if (frag_msg) { /* Reassembled */
        col_append_str(pinfo->cinfo, COL_INFO,
                       " (Message Reassembled)");
      } else { /* Not last packet of reassembled Short Message */
        col_append_str(pinfo->cinfo, COL_INFO,
                       " (Message fragment )");
      }

      pinfo->fragmented = save_fragmented;
    }
  }/*isup_apm_desegment*/

  if ( offset == (gint)length){
    /* No data */
    proto_tree_add_text(parameter_tree, parameter_tvb, offset, 0, "Empty APM-user information field"  );
    return;
  }
  if (new_tvb) { /* take it all */
    next_tvb = new_tvb;
  } else { /* make a new subset */
    next_tvb = tvb_new_subset_remaining(parameter_tvb, offset);
  }

  proto_tree_add_text(parameter_tree, parameter_tvb, offset, -1,
                      "APM-user information field (%u Bytes)",tvb_length_remaining(parameter_tvb, offset));

  switch(aci16 & 0x7fff){
    case 3:
      /* Charging ASE */
      dissect_charging_ase_ChargingMessageType_PDU(next_tvb, pinfo, parameter_tree);
      break;
    case 5:
      /* dissect BAT ASE element, without transparent data ( Q.765.5-200006) */
      dissect_bat_ase_Encapsulated_Application_Information(next_tvb, pinfo, parameter_tree, 0);
      break;
    default:
      proto_tree_add_text(parameter_tree, parameter_tvb, offset, -1, "No further dissection of APM-user information field");
      break;
  }
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
void
dissect_isup_calling_party_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_item *address_digits_item;
  proto_tree *address_digits_tree;
  proto_item *hidden_item;
  guint8 indicators1, indicators2;
  guint8 address_digit_pair=0;
  gint offset=0;
  gint i=0;
  gint length;
  char calling_number[MAXDIGITS + 1]="";
  e164_info_t e164_info;
  gint number_plan;

  indicators1 = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_isup_odd_even_indicator, parameter_tvb, 0, 1, indicators1);
  proto_tree_add_uint(parameter_tree, hf_isup_calling_party_nature_of_address_indicator, parameter_tvb, 0, 1, indicators1);
  indicators2 = tvb_get_guint8(parameter_tvb, 1);
  number_plan = (indicators2 & 0x70)>> 4;
  proto_tree_add_boolean(parameter_tree, hf_isup_ni_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_numbering_plan_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_address_presentation_restricted_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_screening_indicator, parameter_tvb, 1, 1, indicators2);
  offset = 2;

  length = tvb_length_remaining(parameter_tvb, offset);
  if (length == 0) {
    proto_tree_add_text(parameter_tree, parameter_tvb, offset, 0, "Calling Number (empty)");
    proto_item_set_text(parameter_item, "Calling Number: (empty)");
    return;
  }

  address_digits_item = proto_tree_add_text(parameter_tree, parameter_tvb,
                                            offset, -1,
                                            "Calling Party Number");
  address_digits_tree = proto_item_add_subtree(address_digits_item, ett_isup_address_digits);

  while(length > 0){
    address_digit_pair = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_odd_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
    calling_number[i++] = number_to_char(address_digit_pair & ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK);
    if (i > MAXDIGITS)
      THROW(ReportedBoundsError);
    if ((length - 1) > 0 ){
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
      if (i > MAXDIGITS)
        THROW(ReportedBoundsError);
    }
    offset++;
    length = tvb_length_remaining(parameter_tvb, offset);
  }

  if  (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
    proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
    calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
    if (i > MAXDIGITS)
      THROW(ReportedBoundsError);
  }
  proto_item_set_text(address_digits_item, "Calling Party Number: %s", calling_number);
  calling_number[i++] = '\0';
  if ( number_plan == 1 ) {
    e164_info.e164_number_type = CALLING_PARTY_NUMBER;
    e164_info.nature_of_address = indicators1 & 0x7f;
    e164_info.E164_number_str = calling_number;
    e164_info.E164_number_length = i - 1;
    dissect_e164_number(parameter_tvb, address_digits_tree, 2, (offset - 2), e164_info);
    hidden_item = proto_tree_add_string(address_digits_tree, hf_isup_calling, parameter_tvb,
                                        offset - length, length, calling_number);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
  } else {
    proto_tree_add_string(address_digits_tree, hf_isup_calling, parameter_tvb,
                          offset - length, length, calling_number);
  }

  proto_item_set_text(parameter_item, "Calling Party Number: %s", calling_number);
  tap_calling_number = ep_strdup(calling_number);
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
  char calling_number[MAXDIGITS + 1]="";

  indicators1 = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_isup_odd_even_indicator, parameter_tvb, 0, 1, indicators1);
  proto_tree_add_uint(parameter_tree, hf_isup_calling_party_nature_of_address_indicator, parameter_tvb, 0, 1, indicators1);
  indicators2 = tvb_get_guint8(parameter_tvb, 1);
  proto_tree_add_uint(parameter_tree, hf_isup_numbering_plan_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_address_presentation_restricted_indicator, parameter_tvb, 1, 1, indicators2);
  offset = 2;

  length = tvb_length_remaining(parameter_tvb, offset);

  if (length == 0) {
    proto_tree_add_text(parameter_tree, parameter_tvb, offset, 0, "Original Called Number (empty)");
    proto_item_set_text(parameter_item, "Original Called Number: (empty)");
    return;
  }

  address_digits_item = proto_tree_add_text(parameter_tree, parameter_tvb,
                                            offset, -1,
                                            "Original Called Number");
  address_digits_tree = proto_item_add_subtree(address_digits_item, ett_isup_address_digits);

  length = tvb_length_remaining(parameter_tvb, offset);
  while(length > 0){
    address_digit_pair = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_odd_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
    calling_number[i++] = number_to_char(address_digit_pair & ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK);
    if (i > MAXDIGITS)
      THROW(ReportedBoundsError);
    if ((length - 1) > 0 ){
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
      if (i > MAXDIGITS)
        THROW(ReportedBoundsError);
    }
    offset++;
    length = tvb_length_remaining(parameter_tvb, offset);
  }

  if  (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
      if (i > MAXDIGITS)
        THROW(ReportedBoundsError);
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
  char calling_number[MAXDIGITS + 1]="";

  indicators1 = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_isup_odd_even_indicator, parameter_tvb, 0, 1, indicators1);
  proto_tree_add_uint(parameter_tree, hf_isup_calling_party_nature_of_address_indicator, parameter_tvb, 0, 1, indicators1);
  indicators2 = tvb_get_guint8(parameter_tvb, 1);
  proto_tree_add_uint(parameter_tree, hf_isup_numbering_plan_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_address_presentation_restricted_indicator, parameter_tvb, 1, 1, indicators2);
  offset = 2;

  length = tvb_length_remaining(parameter_tvb, offset);

  if (length == 0) {
    proto_tree_add_text(parameter_tree, parameter_tvb, offset, 0, "Redirecting Number (empty)");
    proto_item_set_text(parameter_item, "Redirecting Number: (empty)");
    return;
  }

  address_digits_item = proto_tree_add_text(parameter_tree, parameter_tvb,
                                            offset, -1,
                                            "Redirecting Number");
  address_digits_tree = proto_item_add_subtree(address_digits_item, ett_isup_address_digits);

  length = tvb_length_remaining(parameter_tvb, offset);
  while(length > 0){
    address_digit_pair = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_odd_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
    calling_number[i++] = number_to_char(address_digit_pair & ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK);
    if (i > MAXDIGITS)
      THROW(ReportedBoundsError);
    if ((length - 1) > 0 ){
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
      if (i > MAXDIGITS)
        THROW(ReportedBoundsError);
    }
    offset++;
    length = tvb_length_remaining(parameter_tvb, offset);
  }

  if  (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
      if (i > MAXDIGITS)
        THROW(ReportedBoundsError);
  }
  calling_number[i++] = '\0';

  proto_item_set_text(address_digits_item, "Redirecting Number: %s", calling_number);
  proto_tree_add_string(address_digits_tree, hf_isup_redirecting, parameter_tvb, offset - length, length, calling_number);
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
  char called_number[MAXDIGITS + 1]="";

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
    if (i > MAXDIGITS)
      THROW(ReportedBoundsError);
    if ((length - 1) > 0 ){
      proto_tree_add_uint(address_digits_tree, hf_isup_called_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      called_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
      if (i > MAXDIGITS)
        THROW(ReportedBoundsError);
    }
    offset++;
    length = tvb_length_remaining(parameter_tvb, offset);
  }

  if  (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_isup_called_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      called_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
      if (i > MAXDIGITS)
        THROW(ReportedBoundsError);
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
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, length,
                      "User service information (-> Q.931 Bearer_capability)");
  proto_item_set_text(parameter_item, "User service information, (%u byte%s length)",
                      length , plurality(length, "", "s"));
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
  char calling_number[MAXDIGITS + 1]="";

  indicators1 = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_isup_odd_even_indicator, parameter_tvb, 0, 1, indicators1);
  proto_tree_add_uint(parameter_tree, hf_isup_calling_party_nature_of_address_indicator, parameter_tvb, 0, 1, indicators1);
  indicators2 = tvb_get_guint8(parameter_tvb, 1);
  proto_tree_add_uint(parameter_tree, hf_isup_numbering_plan_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_address_presentation_restricted_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_screening_indicator, parameter_tvb, 1, 1, indicators2);
  offset = 2;

  length = tvb_length_remaining(parameter_tvb, offset);
  if (length == 0)
    return; /* empty connected number */
  address_digits_item = proto_tree_add_text(parameter_tree, parameter_tvb,
                                            offset, -1,
                                            "Connected Number");
  address_digits_tree = proto_item_add_subtree(address_digits_item, ett_isup_address_digits);

  while(length > 0){
    address_digit_pair = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_odd_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
    calling_number[i++] = number_to_char(address_digit_pair & ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK);
    if (i > MAXDIGITS)
      THROW(ReportedBoundsError);
    if ((length - 1) > 0 ){
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
      if (i > MAXDIGITS)
        THROW(ReportedBoundsError);
    }
    offset++;
    length = tvb_length_remaining(parameter_tvb, offset);
  }

  if  (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
      if (i > MAXDIGITS)
        THROW(ReportedBoundsError);
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
  char network_id[MAXDIGITS + 1]="";

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
    if (i > MAXDIGITS)
      THROW(ReportedBoundsError);
    if ((length - 1) > 0 ){
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      network_id[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
      if (i > MAXDIGITS)
        THROW(ReportedBoundsError);
    }
    offset++;
    length = tvb_length_remaining(parameter_tvb, offset);
  }

  if  (((indicators & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      network_id[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
      if (i > MAXDIGITS)
        THROW(ReportedBoundsError);
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
static const true_false_string isup_UUI_type_value = {
  "Response",
  "Request"
};
static const value_string isup_UUI_request_service_values[] = {
  { 0,  "No information"},
  { 1,  "Spare"},
  { 2,  "Request, not essential"},
  { 3,  "Request,essential"},
  { 0,  NULL}
};

static const value_string isup_UUI_response_service_values[] = {
  { 0,  "No information"},
  { 1,  "Not provided"},
  { 2,  "Provided"},
  { 3,  "Spare"},
  { 0,  NULL}
};
static const true_false_string isup_UUI_network_discard_ind_value= {
  "User-to-user information discarded by the network",
  "No information"
};

static void
dissect_isup_user_to_user_indicators_parameter(tvbuff_t *parameter_tvb,
                                               proto_tree *parameter_tree,
                                               proto_item *parameter_item)
{
  guint8 indicators;

  indicators = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_isup_UUI_type, parameter_tvb, 0, 1, indicators);
  if ( (indicators & 0x01) == 0 ){
    /* Request */
    proto_tree_add_uint(parameter_tree, hf_isup_UUI_req_service1, parameter_tvb, 0, 1, indicators);
    proto_tree_add_uint(parameter_tree, hf_isup_UUI_req_service2, parameter_tvb, 0, 1, indicators);
    proto_tree_add_uint(parameter_tree, hf_isup_UUI_req_service3, parameter_tvb, 0, 1, indicators);
  }
  else {
    /* Response */
    proto_tree_add_uint(parameter_tree, hf_isup_UUI_res_service1, parameter_tvb, 0, 1, indicators);
    proto_tree_add_uint(parameter_tree, hf_isup_UUI_res_service2, parameter_tvb, 0, 1, indicators);
    proto_tree_add_uint(parameter_tree, hf_isup_UUI_res_service3, parameter_tvb, 0, 1, indicators);
    proto_tree_add_boolean(parameter_tree, hf_isup_UUI_network_discard_ind, parameter_tvb, 0, 1, indicators);

  }
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
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, length,
                      "User service information prime (-> Q.931 Bearer capability information IE)");
  dissect_q931_bearer_capability_ie(parameter_tvb,
                                    0, length,
                                    parameter_tree);

  proto_item_set_text(parameter_item, "User service information prime, (%u byte%s length)",
                      length , plurality(length, "", "s"));
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
  guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, length,
                      "User teleservice information (-> Q.931 High Layer Compatibility IE)");

  dissect_q931_high_layer_compat_ie(parameter_tvb, 0, length, parameter_tree);

  proto_item_set_text(parameter_item,
                      "User teleservice information");
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

  proto_item_set_text(parameter_item, "Transmission medium used: %u (%s)",  transmission_medium_requirement, val_to_str_ext_const(transmission_medium_requirement, &isup_transmission_medium_requirement_prime_value_ext, "spare/reserved"));
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
static const value_string OECD_inf_ind_vals[] = {
  {0x00, "no information"},
  {0x01, "outgoing echo control device not included and not available"},
  {0x02, "outgoing echo control device included"},
  {0x03, "outgoing echo control device not included but available"},
  { 0,  NULL }
};
static const value_string IECD_inf_ind_vals[] = {
  {0x00, "no information"},
  {0x01, "incoming echo control device not included and not available"},
  {0x02, "incoming echo control device included"},
  {0x03, "incoming echo control device not included but available"},
  { 0,  NULL }
};

static const value_string OECD_req_ind_vals[] = {
  {0x00, "no information"},
  {0x01, "outgoing echo control device activation request"},
  {0x02, "outgoing echo control device deactivation request"},
  {0x03, "spare"},
  { 0,  NULL }
};

static const value_string IECD_req_ind_vals[] = {
  {0x00, "no information"},
  {0x01, "incoming echo control device activation request"},
  {0x02, "incoming echo control device deactivation request"},
  {0x03, "spare"},
  { 0,  NULL }
};

static void
dissect_isup_echo_control_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;
  gint offset = 0;
  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, ECHO_CONTROL_INFO_LENGTH,
                      "Echo control information: 0x%x", indicator);

  proto_tree_add_uint(parameter_tree, hf_isup_OECD_inf_ind,
                      parameter_tvb, offset, 1, indicator );

  proto_tree_add_uint(parameter_tree, hf_isup_IECD_inf_ind,
                      parameter_tvb, offset, 1, indicator );

  proto_tree_add_uint(parameter_tree, hf_isup_OECD_req_ind,
                      parameter_tvb, offset, 1, indicator );

  proto_tree_add_uint(parameter_tree, hf_isup_IECD_req_ind,
                parameter_tvb, offset, 1, indicator );

  proto_item_set_text(parameter_item, "Echo control information: 0x%x", indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter Message compatibility information
 */

static const true_false_string isup_pass_on_not_possible_indicator_value = {
  "discard information",
  "release call",
};

static void
dissect_isup_message_compatibility_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint length = tvb_length(parameter_tvb);
  guint instruction_indicators;
  gint offset = 0;
  instruction_indicators = tvb_get_guint8(parameter_tvb, offset);

  proto_tree_add_text(parameter_tree, parameter_tvb, 0, length,
                      "Message compatibility information");

  proto_tree_add_boolean(parameter_tree, hf_isup_transit_at_intermediate_exchange_ind,
                         parameter_tvb, offset, 1, instruction_indicators );

  proto_tree_add_boolean(parameter_tree, hf_isup_Release_call_ind,
                         parameter_tvb, offset, 1, instruction_indicators );

  proto_tree_add_boolean(parameter_tree, hf_isup_Send_notification_ind,
                         parameter_tvb, offset, 1, instruction_indicators );

  proto_tree_add_boolean(parameter_tree, hf_isup_Discard_message_ind_value,
                         parameter_tvb, offset, 1, instruction_indicators );

  proto_tree_add_boolean(parameter_tree, hf_isup_pass_on_not_possible_indicator2,
                         parameter_tvb, offset, 1,instruction_indicators);

  proto_tree_add_uint(parameter_tree, hf_isup_Broadband_narrowband_interworking_ind2,
                      parameter_tvb, offset, 1,instruction_indicators);

  proto_tree_add_boolean(parameter_tree, hf_isup_extension_ind ,
                         parameter_tvb, offset, 1, instruction_indicators );

  proto_item_set_text(parameter_item, "Message compatibility information (%u byte%s length)",
                      length , plurality(length, "", "s"));
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
  { 0, NULL },
};
static const value_string ISUP_Broadband_narrowband_interworking_indicator_vals[] = {
  { 0x00, "Pass on" },
  { 0x01, "Discard message" },
  { 0x02, "Release call" },
  { 0x03, "Discard parameter" },
  { 0, NULL },
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
                      val_to_str_ext(upgraded_parameter, &isup_parameter_type_value_ext, "unknown (%u)"));
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
  const char *temp_text = "";
  guint8 indicators, digit_pair;
  guint32 bin_code;

  indicators = tvb_get_guint8(parameter_tvb, 0);
  switch ((indicators & 0x60) >> 5) {
    case 0x0:
      temp_text = "Allowed";
      break;
    case 0x1:
      temp_text = "Not Allowed";
      break;
    case 0x2:
      temp_text = "Path reserved";
      break;
    case 0x3:
      temp_text = "Spare";
      break;
  }
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, 1, "Look forward busy: %s", temp_text);
  switch (indicators & 0xf) {
    case 0x0:
      temp_text = "Flash Override";
      break;
    case 0x1:
      temp_text = "Flash";
      break;
    case 0x2:
      temp_text = "Immediate";
      break;
    case 0x3:
      temp_text = "Priority";
      break;
    case 0x4:
      temp_text = "Routine";
      break;
    default:
      temp_text = "Spare";
      break;
  }


  proto_tree_add_text(parameter_tree, parameter_tvb, 0, 1, "Precedence Level: %s",temp_text);
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
  proto_item_set_text(parameter_item, "MLPP precedence: Prec = %s, NI = %s, MLPP service domain = 0x%x", temp_text, NI_digits, bin_code);
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
  Dissector Parameter Originating line information
 */
static void
dissect_isup_orig_line_info_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 info;

  info = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, ORIG_LINE_INFO_LENGTH, "Originating line info: %u", info);
  proto_item_set_text(parameter_item,  "Originating line info: %u (ANI II if < 51, reserved otherwise)", info);
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

  proto_item_set_text(parameter_item, "Transmission medium requirement prime: %u (%s)",  transmission_medium_requirement, val_to_str_ext_const(transmission_medium_requirement, &isup_transmission_medium_requirement_prime_value_ext, "spare/reserved"));
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
  char calling_number[MAXDIGITS + 1]="";

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

   /* NOTE  When the address presentation restricted indicator indicates address not available, the
    * subfields in items a), b), c) and d) are coded with 0's, and the screening indicator is set to 11
    * (network provided).
    * BUG 938 - Just check if there is someting more to dissect.
    */
  if (tvb_length_remaining(parameter_tvb, offset) < 3){
    proto_tree_add_text(parameter_tree, parameter_tvb, 1, -1, "Location number: address not available");
    proto_item_set_text(parameter_item, "Location number: address not available");
    return;
  }

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
    if (i > MAXDIGITS)
      THROW(ReportedBoundsError);
    if ((length - 1) > 0 ){
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
      if (i > MAXDIGITS)
        THROW(ReportedBoundsError);
    }
    offset++;
    length = tvb_length_remaining(parameter_tvb, offset);
  }

  if  (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
      if (i > MAXDIGITS)
        THROW(ReportedBoundsError);
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
  char calling_number[MAXDIGITS + 1]="";

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
    if (i > MAXDIGITS)
      THROW(ReportedBoundsError);
    if ((length - 1) > 0 ){
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
      if (i > MAXDIGITS)
        THROW(ReportedBoundsError);
    }
    offset++;
    length = tvb_length_remaining(parameter_tvb, offset);
  }

  if  (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
      if (i > MAXDIGITS)
        THROW(ReportedBoundsError);
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
  char calling_number[MAXDIGITS + 1]="";

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
    if (i > MAXDIGITS)
      THROW(ReportedBoundsError);
    if ((length - 1) > 0 ){
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
      if (i > MAXDIGITS)
        THROW(ReportedBoundsError);
    }
    offset++;
    length = tvb_length_remaining(parameter_tvb, offset);
  }

  if  (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
      if (i > MAXDIGITS)
        THROW(ReportedBoundsError);
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
 * TODO Output Display info :
 * Quote from Q.931:
 * 4.5.16 Display
 * The purpose of the Display information element is to supply display information
 * that may be displayed by the user. The information contained in this element is coded
 * in IA5 characters.
 * 8 7 6 5 4 3 2 1   Octet
 * 0 0 1 0 1 0 0 0   1      Display information element identifier
 *                   2      Length of display contents
 * 0                 3      Display information (IA5 characters)
 * etc.
 * - end - quote -
 * Assuming octet 2 and onwards is pased here - just output text ?
 */
static void
dissect_isup_display_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint length = tvb_length(parameter_tvb);
  proto_tree_add_text(parameter_tree, parameter_tvb, 0, length,
                      "Display information (-> Q.931)");
  proto_item_set_text(parameter_item, "Display information (%u Byte%s)",
                      length , plurality(length, "", "s"));
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
    proto_item_set_text(parameter_item, "Collect call request: no indication (0x%x)", indicator);
  }
  else {
    proto_tree_add_text(parameter_tree, parameter_tvb, 0, COLLECT_CALL_REQUEST_LENGTH, "Collect call request indicator: collect call requested");
    proto_item_set_text(parameter_item, "Collect call request: collect call requested (0x%x)", indicator);
  }
}
/* ------------------------------------------------------------------
  Dissector Parameter Calling geodetic location
 */
static void
dissect_isup_calling_geodetic_location_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint         length = tvb_length(parameter_tvb);
  guint8        oct, lpri;

  oct = tvb_get_guint8(parameter_tvb, 0);
  lpri = (oct & 0xc0) >> 2;

  proto_tree_add_uint(parameter_tree, hf_isup_geo_loc_presentation_restricted_ind, parameter_tvb, 0, 1, oct);
  proto_tree_add_uint(parameter_tree, hf_isup_geo_loc_screening_ind, parameter_tvb, 0, 1, oct);

  oct = tvb_get_guint8(parameter_tvb, 1);

  proto_tree_add_boolean(parameter_tree, hf_isup_extension_ind, parameter_tvb, 1, 1, oct);
  proto_tree_add_text(parameter_tree, parameter_tvb, 1, 1,
    "Calling geodetic location type of shape: %s (%u)",
    val_to_str(oct & GFEDCBA_8BIT_MASK, isup_location_type_of_shape_value, "spare/reserved"), oct);

  if (length > 2)
  {
    if (lpri < 0x2)
    {
      proto_tree_add_text(parameter_tree, parameter_tvb, 2, length - 2,
        "Shape description");
    }
    else
    {
      /* not supposed to have any data if 'lpri' was 'location not available' */

      proto_tree_add_text(parameter_tree, parameter_tvb, 2, length - 2,
        "Unknown (?), should not have data if LPRI is 'location not available'");
    }
  }

  proto_item_set_text(parameter_item, "Calling geodetic location");
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
  char calling_number[MAXDIGITS + 1]="";

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
    if (i > MAXDIGITS)
      THROW(ReportedBoundsError);
    if ((length - 1) > 0 ){
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
      if (i > MAXDIGITS)
        THROW(ReportedBoundsError);
    }
    offset++;
    length = tvb_length_remaining(parameter_tvb, offset);
  }

  if  (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
      if (i > MAXDIGITS)
        THROW(ReportedBoundsError);
  }
  calling_number[i++] = '\0';

  /*
   * Indicators1 = Nature of address
   * Indicators2 = Number plan indicator
   */
  indicators1 = indicators1 & 0x7f;
  indicators2 = (indicators2 & 0x70)>>4;
  if ((indicators1 == ISUP_CALLED_PARTY_NATURE_INTERNATNL_NR)&&(indicators2==ISDN_NUMBERING_PLAN))
    dissect_e164_cc(parameter_tvb, address_digits_tree, 3, TRUE);

  proto_item_set_text(address_digits_item, "Generic number: %s", calling_number);
  proto_item_set_text(parameter_item, "Generic number: %s", calling_number);

}
/* ------------------------------------------------------------------
  Dissector Parameter  Jurisdiction parameter
 */
static void
dissect_isup_jurisdiction_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_item *address_digits_item;
  proto_tree *address_digits_tree;
  guint8 address_digit_pair=0;
  gint offset=0;
  gint i=0;
  gint length;
  char called_number[MAXDIGITS + 1]="";

  offset = 0;

  address_digits_item = proto_tree_add_text(parameter_tree, parameter_tvb,
                                            offset, -1,
                                            "Jurisdiction");
  address_digits_tree = proto_item_add_subtree(address_digits_item, ett_isup_address_digits);

  while((length = tvb_reported_length_remaining(parameter_tvb, offset)) > 0){
    address_digit_pair = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(address_digits_tree, hf_isup_called_party_odd_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
    called_number[i++] = number_to_char(address_digit_pair & ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK);
    if (i > MAXDIGITS)
      THROW(ReportedBoundsError);
    if ((length - 1) > 0 ){
      proto_tree_add_uint(address_digits_tree, hf_isup_called_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      called_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
      if (i > MAXDIGITS)
        THROW(ReportedBoundsError);
    }
    offset++;
  }

  if (tvb_length(parameter_tvb) > 0){
      proto_tree_add_uint(address_digits_tree, hf_isup_called_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      called_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
      if (i > MAXDIGITS)
        THROW(ReportedBoundsError);
  }
  called_number[i++] = '\0';

  proto_item_set_text(address_digits_item, "Jurisdiction: %s", called_number);
  proto_item_set_text(parameter_item, "Jurisdiction: %s", called_number);

}/* ------------------------------------------------------------------
  Dissector Parameter Generic name
 */
static void
dissect_isup_generic_name_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 indicator;
  gint gen_name_length;
  char *gen_name=NULL;

  gen_name=ep_alloc(MAXGNAME + 1);
  gen_name[0] = '\0';
  gen_name_length = tvb_length(parameter_tvb) - 1;
  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_isup_generic_name_presentation, parameter_tvb, 1, 1, indicator);
  proto_tree_add_boolean(parameter_tree, hf_isup_generic_name_availability, parameter_tvb, 1, 1, indicator);
  proto_tree_add_uint(parameter_tree, hf_isup_generic_name_type, parameter_tvb, 1, 1, indicator);
  gen_name = tvb_get_ephemeral_string(parameter_tvb,1,gen_name_length);
  gen_name[gen_name_length] = '\0';
  proto_tree_add_string(parameter_tree, hf_isup_generic_name_ia5, parameter_tvb, 2, gen_name_length, gen_name);
  proto_item_set_text(parameter_item, "Generic name: %s", gen_name);

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

/* ------------------------------------------------------------------
  Dissector Parameter Charge number
 */
static void
dissect_isup_charge_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_item *address_digits_item;
  proto_tree *address_digits_tree;
  guint8 indicators1, indicators2;
  guint8 address_digit_pair=0;
  gint offset=0;
  gint i=0;
  gint length;
  char calling_number[MAXDIGITS + 1]="";

  indicators1 = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_isup_odd_even_indicator, parameter_tvb, 0, 1, indicators1);
  proto_tree_add_uint(parameter_tree, hf_isup_charge_number_nature_of_address_indicator, parameter_tvb, 0, 1, indicators1);
  indicators2 = tvb_get_guint8(parameter_tvb, 1);
  proto_tree_add_uint(parameter_tree, hf_isup_numbering_plan_indicator, parameter_tvb, 1, 1, indicators2);
  offset = 2;

  address_digits_item = proto_tree_add_text(parameter_tree, parameter_tvb,
                                            offset, -1,
                                            "Charge Number");
  address_digits_tree = proto_item_add_subtree(address_digits_item, ett_isup_address_digits);

  length = tvb_length_remaining(parameter_tvb, offset);
  while(length > 0){
    address_digit_pair = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_odd_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
    calling_number[i++] = number_to_char(address_digit_pair & ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK);
    if (i > MAXDIGITS)
      THROW(ReportedBoundsError);
    if ((length - 1) > 0 ){
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
      if (i > MAXDIGITS)
        THROW(ReportedBoundsError);
    }
    offset++;
    length = tvb_length_remaining(parameter_tvb, offset);
  }

  if  (((indicators1 & 0x80) == 0) && (tvb_length(parameter_tvb) > 0)){ /* Even Indicator set -> last even digit is valid & has be displayed */
      proto_tree_add_uint(address_digits_tree, hf_isup_calling_party_even_address_signal_digit, parameter_tvb, offset - 1, 1, address_digit_pair);
      calling_number[i++] = number_to_char((address_digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10);
      if (i > MAXDIGITS)
        THROW(ReportedBoundsError);
  }
  calling_number[i++] = '\0';

  proto_item_set_text(address_digits_item, "Charge Number: %s", calling_number);
  proto_item_set_text(parameter_item, "Charge Number: %s", calling_number);

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
  guint8 octet;

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
      proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, optional_parameters_tvb, offset, PARAMETER_TYPE_LENGTH,
                                 parameter_type,
                                 "Optional Parameter: %u (%s)",
                                 parameter_type,
                                 val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext,"unknown"));
      offset += PARAMETER_TYPE_LENGTH;

      octet = tvb_get_guint8(optional_parameters_tvb,offset);

      proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_length, optional_parameters_tvb, offset, PARAMETER_LENGTH_IND_LENGTH, parameter_length, "Parameter length: %u", parameter_length);
      offset += PARAMETER_LENGTH_IND_LENGTH;
      if ( octet == 0 )
        continue;

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
            dissect_isup_access_transport_parameter(parameter_tvb, parameter_tree, parameter_item, pinfo);
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
            dissect_isup_user_to_user_information_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
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
      proto_tree_add_uint_format(isup_tree, hf_isup_parameter_type, optional_parameters_tvb , offset, PARAMETER_TYPE_LENGTH,
                                 parameter_type, "End of optional parameters (%u)", parameter_type);
    }
  }
}

/* ------------------------------------------------------------------
  Dissector all ANSI optional parameters
  TODO: Actullay make this dissect ANSI :) - It's still plain old ITU for now
*/
static void
dissect_ansi_isup_optional_parameter(tvbuff_t *optional_parameters_tvb,packet_info *pinfo, proto_tree *isup_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  gint offset = 0;
  guint parameter_type, parameter_length, actual_length;
  tvbuff_t *parameter_tvb;
  guint8 octet;

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
      proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, optional_parameters_tvb, offset, PARAMETER_TYPE_LENGTH, parameter_type,
                                 "Optional Parameter: %u (%s)", parameter_type,
                                 val_to_str_ext_const(parameter_type, &ansi_isup_parameter_type_value_ext,"unknown"));
      offset += PARAMETER_TYPE_LENGTH;

      octet = tvb_get_guint8(optional_parameters_tvb,offset);

      proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_length, optional_parameters_tvb, offset, PARAMETER_LENGTH_IND_LENGTH, parameter_length,
                                 "Parameter length: %u", parameter_length);
      offset += PARAMETER_LENGTH_IND_LENGTH;
      if ( octet == 0 )
        continue;

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
            dissect_isup_access_transport_parameter(parameter_tvb, parameter_tree, parameter_item, pinfo);
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
            dissect_ansi_isup_cause_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
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
            dissect_isup_user_to_user_information_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
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
          case PARAM_TYPE_ORIG_LINE_INFO:
            dissect_isup_orig_line_info_parameter(parameter_tvb, parameter_tree, parameter_item);
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
          case PARAM_TYPE_CALLING_GEODETIC_LOCATION:
            dissect_isup_calling_geodetic_location_parameter(parameter_tvb, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_GENERIC_NR:
            dissect_isup_generic_number_parameter(parameter_tvb, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_JURISDICTION:
            dissect_isup_jurisdiction_parameter(parameter_tvb, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_GENERIC_NAME:
            dissect_isup_generic_name_parameter(parameter_tvb, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_GENERIC_DIGITS:
            dissect_isup_generic_digits_parameter(parameter_tvb, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_CHARGE_NR:
            dissect_isup_charge_number_parameter(parameter_tvb, parameter_tree, parameter_item);
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
      proto_tree_add_uint_format(isup_tree, hf_isup_parameter_type, optional_parameters_tvb , offset, PARAMETER_TYPE_LENGTH, parameter_type, "End of optional parameters (%u)", parameter_type);
    }
  }
}
/* ------------------------------------------------------------------ */
/* Dissectors for all used message types                              */
/* Called by dissect_isup_message(),                                  */
/* call parameter dissectors in order of mandatory parameters         */
/* (since not labeled)                                                */
/* ------------------------------------------------------------------
  Dissector Message Type Circuit Validation Test Response
 */
static gint
dissect_ansi_isup_circuit_validation_test_resp_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{
  proto_item* parameter_item;
  proto_tree* parameter_tree;
  tvbuff_t *parameter_tvb;
  gint offset = 0;
  gint parameter_type,actual_length;

  /* Do stuff for first mandatory fixed parameter: CVR Repsonse Indicator */
  parameter_type = ANSI_ISUP_PARAM_TYPE_CVR_RESP_IND;
  parameter_item = proto_tree_add_text(isup_tree, message_tvb, offset, CVR_RESP_IND_LENGTH, "CVR Response Indicator");

  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                             "Mandatory Parameter: %u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext,"CVR Response Indicator"));

  actual_length = tvb_ensure_length_remaining(message_tvb, offset);

  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(CVR_RESP_IND_LENGTH, actual_length), CVR_RESP_IND_LENGTH);
  dissect_isup_cvr_response_ind_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += CVR_RESP_IND_LENGTH;

  /* Do stuff for second mandatory fixed parameter: CG Characteristics Indicator */
  parameter_type = ANSI_ISUP_PARAM_TYPE_CG_CHAR_IND;
  parameter_item = proto_tree_add_text(isup_tree, message_tvb, offset,
                                       CG_CHAR_IND_LENGTH,
                                       "Circuit Group Characteristics Indicators");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                             "Mandatory Parameter: %u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "Circuit Group Characters"));
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(CG_CHAR_IND_LENGTH, actual_length), CG_CHAR_IND_LENGTH);
  dissect_isup_circuit_group_char_ind_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += CG_CHAR_IND_LENGTH;

  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type Circuit Reservation
 */
static gint
dissect_ansi_isup_circuit_reservation_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{ proto_item* parameter_item;
  proto_tree* parameter_tree;
  tvbuff_t *parameter_tvb;
  gint offset = 0;
  gint parameter_type, actual_length;

  /* Do stuff for mandatory fixed parameter: Nature of Connection Indicators */
  parameter_type = PARAM_TYPE_NATURE_OF_CONN_IND;
  parameter_item = proto_tree_add_text(isup_tree, message_tvb, offset,
                                       NATURE_OF_CONNECTION_IND_LENGTH,
                                       "Nature of Connection Indicators");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                             "Mandatory Parameter: %u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext,"unknown"));
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(NATURE_OF_CONNECTION_IND_LENGTH, actual_length), NATURE_OF_CONNECTION_IND_LENGTH);
  dissect_isup_nature_of_connection_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += NATURE_OF_CONNECTION_IND_LENGTH;

  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type Initial address message
 */
static gint
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
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                             "Mandatory Parameter: %u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "unknown"));
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
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                             "Mandatory Parameter: %u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "unknown"));
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
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                             "Mandatory Parameter: %u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "unknown"));
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(CALLING_PRTYS_CATEGORY_LENGTH, actual_length),CALLING_PRTYS_CATEGORY_LENGTH );
  dissect_isup_calling_partys_category_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += CALLING_PRTYS_CATEGORY_LENGTH;

  switch (isup_standard){
    case ITU_STANDARD:
      /* If ITU, do stuff for 4th mandatory fixed parameter: Transmission medium requirement */
      parameter_type = PARAM_TYPE_TRANSM_MEDIUM_REQU;
      parameter_item = proto_tree_add_text(isup_tree, message_tvb, offset,
                                           TRANSMISSION_MEDIUM_REQUIREMENT_LENGTH,
                                           "Transmission medium requirement");
      parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
      proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                                 "Mandatory Parameter: %u (%s)",
                                 parameter_type,
                                 val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "unknown"));
      actual_length = tvb_ensure_length_remaining(message_tvb, offset);
      parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(TRANSMISSION_MEDIUM_REQUIREMENT_LENGTH, actual_length), TRANSMISSION_MEDIUM_REQUIREMENT_LENGTH);
      dissect_isup_transmission_medium_requirement_parameter(parameter_tvb, parameter_tree, parameter_item);
      offset += TRANSMISSION_MEDIUM_REQUIREMENT_LENGTH;
      break;
    case ANSI_STANDARD:
      /* If ANSI, do stuff for the first mandatory variable parameter, USER_SERVICE_INFORMATION */
      parameter_type = PARAM_TYPE_USER_SERVICE_INFO;
      parameter_pointer = tvb_get_guint8(message_tvb, offset);
      parameter_length = tvb_get_guint8(message_tvb, offset + parameter_pointer);
      parameter_item = proto_tree_add_text(isup_tree, message_tvb,
                                           offset +  parameter_pointer,
                                           parameter_length + PARAMETER_LENGTH_IND_LENGTH,
                                           "User Service Information");
      parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
      proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                                 "Mandatory Parameter: %u (%s)",
                                 parameter_type,
                                 val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "unknown"));
      proto_tree_add_uint_format(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset, PARAMETER_POINTER_LENGTH, parameter_pointer, "Pointer to Parameter: %u", parameter_pointer);
      proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer, PARAMETER_LENGTH_IND_LENGTH, parameter_length, "Parameter length: %u", parameter_length);
      actual_length = tvb_ensure_length_remaining(message_tvb, offset);
      parameter_tvb = tvb_new_subset(message_tvb, offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH, MIN(parameter_length, actual_length), parameter_length );
      dissect_isup_user_service_information_parameter(parameter_tvb, parameter_tree, parameter_item);
      offset += PARAMETER_POINTER_LENGTH;
      break;
  }

  /* Do stuff for mandatory variable parameter Called party number */
  parameter_type = PARAM_TYPE_CALLED_PARTY_NR;
  parameter_pointer = tvb_get_guint8(message_tvb, offset);
  parameter_length = tvb_get_guint8(message_tvb, offset + parameter_pointer);

  parameter_item = proto_tree_add_text(isup_tree, message_tvb,
                                       offset +  parameter_pointer,
                                       parameter_length + PARAMETER_LENGTH_IND_LENGTH,
                                       "Called Party Number");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                             "Mandatory Parameter: %u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "unknown"));
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
static gint dissect_isup_subsequent_address_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
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
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                             "Mandatory Parameter: %u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "unknown"));
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
static gint
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
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                             "Mandatory Parameter: %u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "unknown"));
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(INFO_REQUEST_IND_LENGTH, actual_length), INFO_REQUEST_IND_LENGTH);
  dissect_isup_information_request_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += INFO_REQUEST_IND_LENGTH;
  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type Information
 */
static gint
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
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                             "Mandatory Parameter: %u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "unknown"));
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(INFO_IND_LENGTH, actual_length), INFO_IND_LENGTH);
  dissect_isup_information_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += INFO_IND_LENGTH;
  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type Continuity
 */
static gint
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
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                             "Mandatory Parameter: %u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "unknown"));
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(CONTINUITY_IND_LENGTH, actual_length), CONTINUITY_IND_LENGTH);
  dissect_isup_continuity_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += CONTINUITY_IND_LENGTH;
  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type Address complete
 */
static gint
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
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                             "Mandatory Parameter: %u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "unknown"));
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(BACKWARD_CALL_IND_LENGTH, actual_length), BACKWARD_CALL_IND_LENGTH);
  dissect_isup_backward_call_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += BACKWARD_CALL_IND_LENGTH;
  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type Connect
 */
static gint
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
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                             "Mandatory Parameter: %u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "unknown"));
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(BACKWARD_CALL_IND_LENGTH, actual_length), BACKWARD_CALL_IND_LENGTH);
  dissect_isup_backward_call_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += BACKWARD_CALL_IND_LENGTH;
  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type release message
 */
static gint
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
                                       "Cause indicators");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                             "Mandatory Parameter: %u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "unknown"));
  proto_tree_add_uint_format(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset, PARAMETER_POINTER_LENGTH, parameter_pointer, "Pointer to Parameter: %u", parameter_pointer);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer, PARAMETER_LENGTH_IND_LENGTH, parameter_length, "Parameter length: %u", parameter_length);
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH, MIN(parameter_length, actual_length), parameter_length );
  switch (isup_standard){
    case ITU_STANDARD:
      dissect_isup_cause_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
      break;
    case ANSI_STANDARD:
      dissect_ansi_isup_cause_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
      break;
  }
  offset += PARAMETER_POINTER_LENGTH;

  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type Resume/Suspend
 */
static gint
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
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                             "Mandatory Parameter: %u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "unknown"));
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(SUSPEND_RESUME_IND_LENGTH, actual_length), SUSPEND_RESUME_IND_LENGTH);
  dissect_isup_suspend_resume_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += SUSPEND_RESUME_IND_LENGTH;
  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type Circuit group reset/query message
 */
static gint
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
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                             "Mandatory Parameter: %u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "unknown"));
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
static gint
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
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                             "Mandatory Parameter: %u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "unknown"));
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
                                       "Range and status");
  parameter_tree = proto_item_add_subtree(parameter_item, ett_isup_parameter);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                             "Mandatory Parameter: %u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "unknown"));
  proto_tree_add_uint_format(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset, PARAMETER_POINTER_LENGTH, parameter_pointer, "Pointer to Parameter: %u", parameter_pointer);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer, PARAMETER_LENGTH_IND_LENGTH, parameter_length, "Parameter length: %u", parameter_length);
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH, MIN(parameter_length, actual_length), parameter_length );
  dissect_isup_range_and_status_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += PARAMETER_POINTER_LENGTH;

  return offset;
}

/* ------------------------------------------------------------------
  Dissector Message Type Facility request/accepted
 */
static gint
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
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                             "Mandatory Parameter: %u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "unknown"));
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(FACILITY_IND_LENGTH, actual_length), FACILITY_IND_LENGTH);
  dissect_isup_facility_ind_parameter(parameter_tvb, parameter_item);
  offset += FACILITY_IND_LENGTH;
  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type Facility reject
 */
static gint
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
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                             "Mandatory Parameter: %u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "unknown"));
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
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                             "Mandatory Parameter: %u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "unknown"));
  proto_tree_add_uint_format(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset, PARAMETER_POINTER_LENGTH, parameter_pointer, "Pointer to Parameter: %u", parameter_pointer);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer, PARAMETER_LENGTH_IND_LENGTH, parameter_length, "Parameter length: %u", parameter_length);
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH, MIN(parameter_length, actual_length), parameter_length );
  switch (isup_standard){
    case ITU_STANDARD:
      dissect_isup_cause_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
      break;
    case ANSI_STANDARD:
      dissect_ansi_isup_cause_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
      break;
  }
  offset += PARAMETER_POINTER_LENGTH;

  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type Circuit group reset acknowledgement message
 */
static gint
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
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                             "Mandatory Parameter: %u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "unknown"));
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
static gint
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
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                             "Mandatory Parameter: %u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "unknown"));
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
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                             "Mandatory Parameter: %u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "unknown"));
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
static gint
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
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                             "Mandatory Parameter: %u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "unknown"));
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset, MIN(EVENT_INFO_LENGTH, actual_length), EVENT_INFO_LENGTH);
  dissect_isup_event_information_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += EVENT_INFO_LENGTH;
  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type User-to-User information
 */
static gint
dissect_isup_user_to_user_information_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *isup_tree)
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
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                             "Mandatory Parameter: %u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "unknown"));
  proto_tree_add_uint_format(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset, PARAMETER_POINTER_LENGTH, parameter_pointer, "Pointer to Parameter: %u", parameter_pointer);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer, PARAMETER_LENGTH_IND_LENGTH, parameter_length, "Parameter length: %u", parameter_length);
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH, MIN(parameter_length, actual_length), parameter_length );
  dissect_isup_user_to_user_information_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
  offset += PARAMETER_POINTER_LENGTH;

  return offset;
}
/* ------------------------------------------------------------------
  Dissector Message Type Confusion
 */
static gint
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
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_type, message_tvb, 0, 0, parameter_type,
                             "Mandatory Parameter: %u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "unknown"));
  proto_tree_add_uint_format(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset, PARAMETER_POINTER_LENGTH, parameter_pointer, "Pointer to Parameter: %u", parameter_pointer);
  proto_tree_add_uint_format(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer, PARAMETER_LENGTH_IND_LENGTH, parameter_length, "Parameter length: %u", parameter_length);
  actual_length = tvb_ensure_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset(message_tvb, offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH, MIN(parameter_length, actual_length), parameter_length );

  switch (isup_standard){
    case ITU_STANDARD:
      dissect_isup_cause_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
      break;
    case ANSI_STANDARD:
      dissect_ansi_isup_cause_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
      break;
  }
  offset += PARAMETER_POINTER_LENGTH;

  return offset;
}
/* ------------------------------------------------------------------ */
static void
dissect_isup_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *isup_tree)
{
  isup_tap_rec_t *tap_rec;

  tvbuff_t *parameter_tvb;
  tvbuff_t *optional_parameter_tvb;
  proto_item* pass_along_item;
  proto_tree* pass_along_tree;
  gint offset, bufferlength;
  guint8 message_type, opt_parameter_pointer;
  gint opt_part_possible = FALSE; /* default setting - for message types allowing optional
                                     params explicitely set to TRUE in case statement */
  tap_calling_number = NULL;
  offset = 0;

  /* Extract message type field */
  message_type = tvb_get_guint8(message_tvb,0);

  switch (isup_standard){
    case ITU_STANDARD:
      proto_tree_add_uint_format(isup_tree, hf_isup_message_type, message_tvb, 0, MESSAGE_TYPE_LENGTH, message_type,
                                 "Message type: %s (%u)",
                                 val_to_str_ext_const(message_type, &isup_message_type_value_ext, "reserved"),
                                 message_type);
      break;
    case ANSI_STANDARD:
      proto_tree_add_uint_format(isup_tree, hf_isup_message_type, message_tvb, 0, MESSAGE_TYPE_LENGTH, message_type, "Message type: %s (%u)",
                                 val_to_str_ext_const(message_type, &ansi_isup_message_type_value_ext, "reserved"), message_type);
      break;
  }
   offset +=  MESSAGE_TYPE_LENGTH;

   tap_rec = (isup_tap_rec_t *)ep_alloc(sizeof(isup_tap_rec_t));
   tap_rec->message_type = message_type;
   tap_rec->calling_number = NULL;
   tap_rec->called_number = NULL;

   parameter_tvb = tvb_new_subset_remaining(message_tvb, offset);

   /* distinguish between message types:*/
   switch (isup_standard){
     case ITU_STANDARD:
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
         {
           guint8 pa_message_type;
           pa_message_type = tvb_get_guint8(parameter_tvb, 0);
           pass_along_item = proto_tree_add_text(isup_tree, parameter_tvb, offset, -1,
                                                 "Pass-along: %s Message (%u)",
                                                 val_to_str_ext_const(pa_message_type, &isup_message_type_value_acro_ext, "reserved"),
                                                 pa_message_type);
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
           offset += dissect_isup_user_to_user_information_message(parameter_tvb, pinfo, isup_tree);
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
           bufferlength = tvb_length_remaining(message_tvb, offset);
           if (bufferlength != 0)
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
           bufferlength = tvb_length_remaining(message_tvb, offset);
           if (bufferlength != 0)
             proto_tree_add_text(isup_tree, parameter_tvb, 0, bufferlength, "Format is a national matter");
           break;
         default:
           bufferlength = tvb_length_remaining(message_tvb, offset);
           if (bufferlength != 0)
             proto_tree_add_text(isup_tree, parameter_tvb, 0, bufferlength, "Unknown Message type (possibly reserved/used in former ISUP version)");
           break;
       }
       break;
     case ANSI_STANDARD:
       /* TODO if neccessary make new "dissect_ansi_isup_xxx() routines or add branches in the current ones.
        */
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
         {
           guint8 pa_message_type;
           pa_message_type = tvb_get_guint8(parameter_tvb, 0);
           pass_along_item = proto_tree_add_text(isup_tree, parameter_tvb, offset, -1,
                                                 "Pass-along: %s Message (%u)",
                                                 val_to_str_ext_const(pa_message_type, &isup_message_type_value_acro_ext, "reserved"),
                                                 pa_message_type);
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
           offset += dissect_isup_user_to_user_information_message(parameter_tvb, pinfo, isup_tree);
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
           bufferlength = tvb_length_remaining(message_tvb, offset);
           if (bufferlength != 0)
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
           bufferlength = tvb_length_remaining(message_tvb, offset);
           if (bufferlength != 0)
             proto_tree_add_text(isup_tree, parameter_tvb, 0, bufferlength, "Format is a national matter");
           break;
         case ANSI_ISUP_MESSAGE_TYPE_CIRCUIT_RES_ACK:
           /* no dissector necessary since no mandatory parameters included */
           break;
         case ANSI_ISUP_MESSAGE_TYPE_CIRCUIT_RES:
           offset += dissect_ansi_isup_circuit_reservation_message( parameter_tvb, isup_tree );
           break;
         case ANSI_ISUP_MESSAGE_TYPE_CCT_VAL_TEST_RSP:
           opt_part_possible = TRUE;
           offset += dissect_ansi_isup_circuit_validation_test_resp_message( parameter_tvb, isup_tree );
           break;
         case ANSI_ISUP_MESSAGE_TYPE_CCT_VAL_TEST:
           /* no dissector necessary since no mandatory parameters included */
           break;
         default:
           bufferlength = tvb_length_remaining(message_tvb, offset);
           if (bufferlength != 0)
             proto_tree_add_text(isup_tree, parameter_tvb, 0, bufferlength, "Unknown Message type (possibly reserved/used in former ISUP version)");
           break;
       }
       break;
   }

   /* extract pointer to start of optional part (if any) */
   if (opt_part_possible == TRUE){
     opt_parameter_pointer = tvb_get_guint8(message_tvb, offset);
     if (opt_parameter_pointer > 0){
       proto_tree_add_uint_format(isup_tree, hf_isup_pointer_to_start_of_optional_part, message_tvb, offset, PARAMETER_POINTER_LENGTH, opt_parameter_pointer, "Pointer to start of optional part: %u", opt_parameter_pointer);
       offset += opt_parameter_pointer;
       optional_parameter_tvb = tvb_new_subset_remaining(message_tvb, offset);
       switch(isup_standard){
         case ITU_STANDARD:
           dissect_isup_optional_parameter(optional_parameter_tvb, pinfo, isup_tree);
           break;
         case ANSI_STANDARD:
           dissect_ansi_isup_optional_parameter(optional_parameter_tvb, pinfo, isup_tree);
           break;
       }
     }
     else
       proto_tree_add_uint_format(isup_tree, hf_isup_pointer_to_start_of_optional_part, message_tvb, offset, PARAMETER_POINTER_LENGTH, opt_parameter_pointer, "No optional parameter present (Pointer: %u)", opt_parameter_pointer);
   }
   else if (message_type !=MESSAGE_TYPE_CHARGE_INFO)
     proto_tree_add_text(isup_tree, message_tvb, 0, 0, "No optional parameters are possible with this message type");
   /* if there are calling/called number, we'll get them for the tap */

   tap_rec->calling_number=tap_calling_number?tap_calling_number:ep_strdup("");
   tap_rec->called_number=tap_called_number;
   tap_rec->cause_value=tap_cause_value;
   tap_queue_packet(isup_tap, pinfo, tap_rec);
}

/* ------------------------------------------------------------------ */
static void
dissect_isup(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures needed to add the protocol subtree and manage it */
  proto_item *ti;
  proto_tree *isup_tree = NULL;
  tvbuff_t *message_tvb;
  guint16 cic;
  guint8 message_type;

  switch(mtp3_standard){
    case ANSI_STANDARD:
      isup_standard = ANSI_STANDARD;
      break;
    default:
      isup_standard = ITU_STANDARD;
  }

/* Make entries in Protocol column and Info column on summary display */
  switch (isup_standard){
    case ITU_STANDARD:
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISUP(ITU)");
      break;
    case ANSI_STANDARD:
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISUP(ANSI)");
      break;
  }

/* Extract message type field */
  message_type = tvb_get_guint8(tvb, CIC_OFFSET + CIC_LENGTH);
  /* dissect CIC in main dissector since pass-along message type carrying complete IUSP message w/o CIC needs
     recursive message dissector call */
  if (mtp3_standard == ANSI_STANDARD)
    cic = tvb_get_letohs(tvb, CIC_OFFSET) & 0x3FFF; /*since upper 2 bits spare */
  else /* ITU, China, and Japan; yes, J7's CICs are a different size */
    cic = tvb_get_letohs(tvb, CIC_OFFSET) & 0x0FFF; /*since upper 4 bits spare */

  pinfo->ctype = CT_ISUP;
  pinfo->circuit_id = cic;

  if (isup_show_cic_in_info){
    switch (isup_standard){
      case ITU_STANDARD:
        col_add_fstr(pinfo->cinfo, COL_INFO,
                     "%s (CIC %u) ",
                     val_to_str_ext_const(message_type, &isup_message_type_value_acro_ext, "reserved"),
                     cic);
        break;
      case ANSI_STANDARD:
        col_add_fstr(pinfo->cinfo, COL_INFO,
                     "%s (CIC %u) ",
                     val_to_str_ext_const(message_type, &ansi_isup_message_type_value_acro_ext, "reserved"),
                     cic);
        break;
    }
  }else{
    switch (isup_standard){
      case ITU_STANDARD:
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str_ext_const(message_type, &isup_message_type_value_acro_ext, "reserved"));
        break;
      case ANSI_STANDARD:
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str_ext_const(message_type, &ansi_isup_message_type_value_acro_ext, "reserved"));
        break;
    }
  }

  /* In the interest of speed, if "tree" is NULL, don't do any work not
   * necessary to generate protocol tree items.
   */
  if (tree) {
    ti = proto_tree_add_item(tree, proto_isup, tvb, 0, -1, FALSE);
    isup_tree = proto_item_add_subtree(ti, ett_isup);


    proto_tree_add_uint_format(isup_tree, hf_isup_cic, tvb, CIC_OFFSET, CIC_LENGTH, cic, "CIC: %u", cic);
  }

  message_tvb = tvb_new_subset_remaining(tvb, CIC_LENGTH);
  dissect_isup_message(message_tvb, pinfo, isup_tree);
}

/* ------------------------------------------------------------------ */
static void
dissect_bicc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures needed to add the protocol subtree and manage it */
  proto_item *ti;
  proto_tree *bicc_tree = NULL;
  tvbuff_t *message_tvb;
  guint32 bicc_cic;
  guint8 message_type;

  /*circuit_t *circuit;*/

/* Make entries in Protocol column and Info column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "BICC");

/* Extract message type field */
  message_type = tvb_get_guint8(tvb, BICC_CIC_OFFSET + BICC_CIC_LENGTH);

  bicc_cic = tvb_get_letohl(tvb, BICC_CIC_OFFSET);

  pinfo->ctype = CT_BICC;
  pinfo->circuit_id = bicc_cic;

  col_clear(pinfo->cinfo, COL_INFO);
  if (isup_show_cic_in_info) {
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ",
                 "%s (CIC %u)",
                 val_to_str_ext_const(message_type, &isup_message_type_value_acro_ext, "reserved"),
                 bicc_cic);
  } else {
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ",
                 "%s",
                 val_to_str_ext_const(message_type, &isup_message_type_value_acro_ext, "reserved"));
  }
  /* dissect CIC in main dissector since pass-along message type carrying complete BICC/ISUP message w/o CIC needs
   * recursive message dissector call
   */
  /* In the interest of speed, if "tree" is NULL, don't do any work not
   * necessary to generate protocol tree items.
   */
  if (tree) {
    ti = proto_tree_add_item(tree, proto_bicc, tvb, 0, -1, FALSE);
    bicc_tree = proto_item_add_subtree(ti, ett_bicc);


    proto_tree_add_uint_format(bicc_tree, hf_bicc_cic, tvb, BICC_CIC_OFFSET, BICC_CIC_LENGTH, bicc_cic, "CIC: %u", bicc_cic);
  }

  message_tvb = tvb_new_subset_remaining(tvb, BICC_CIC_LENGTH);
  dissect_isup_message(message_tvb, pinfo, bicc_tree);
  col_set_fence(pinfo->cinfo, COL_INFO);
}

static void
dissect_application_isup(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
/* Set up structures needed to add the protocol subtree and manage it */
  proto_item *ti;
  proto_tree *isup_tree = NULL;
  tvbuff_t *message_tvb;
  guint8 message_type;

/* Make entries in Protocol column and Info column on summary display */
  col_append_str(pinfo->cinfo, COL_PROTOCOL, "/ISUP(ITU)");

/* Extract message type field */
  message_type = tvb_get_guint8(tvb, 0);
  /* application/ISUP has no  CIC  */
  col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ",
                      "ISUP:%s",
                      val_to_str_ext_const(message_type, &isup_message_type_value_acro_ext, "reserved"));

/* In the interest of speed, if "tree" is NULL, don't do any work not
   necessary to generate protocol tree items. */
  if (tree) {
    ti = proto_tree_add_item(tree, proto_isup, tvb, 0, -1, FALSE);
    isup_tree = proto_item_add_subtree(ti, ett_isup);
  }

  message_tvb = tvb_new_subset_remaining(tvb, 0);
  dissect_isup_message(message_tvb, pinfo, isup_tree);
}
/* ---------------------------------------------------- stats tree
*/
static int st_node_msg = -1;
static int st_node_dir = -1;

static void
msg_stats_tree_init(stats_tree* st)
{
  st_node_msg = stats_tree_create_node(st, "Messages by Type", 0, TRUE);
  st_node_dir = stats_tree_create_node(st, "Messages by Direction", 0, TRUE);
}

static int
msg_stats_tree_packet(stats_tree *st, packet_info *pinfo, epan_dissect_t *edt _U_, const void *p )
{
  const gchar *msg = match_strval_ext(((const isup_tap_rec_t*)p)->message_type, &isup_message_type_value_acro_ext);
  gchar *dir;
  int msg_node;
  int dir_node;

  dir = ep_strdup_printf("%s->%s", ep_address_to_str(&pinfo->src), ep_address_to_str(&pinfo->dst));

  msg_node = tick_stat_node(st, msg, st_node_msg, TRUE);
  tick_stat_node(st, dir, msg_node, FALSE);

  dir_node = tick_stat_node(st, dir, st_node_dir, TRUE);
  tick_stat_node(st, msg, dir_node, FALSE);

  return 1;
}

/*---------------------------------------------------------------------*/
/* Register the protocol with Wireshark */
void
proto_register_isup(void)
{
/* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    { &hf_isup_cic,
      { "CIC",           "isup.cic",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_message_type,
      { "Message Type",  "isup.message_type",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_parameter_type,
      { "Parameter Type",  "isup.parameter_type",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_parameter_length,
      { "Parameter Length",  "isup.parameter_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_mandatory_variable_parameter_pointer,
      { "Pointer to Parameter",  "isup.mandatory_variable_parameter_pointer",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_pointer_to_start_of_optional_part,
      { "Pointer to optional parameter part",  "isup.optional_parameter_part_pointer",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_satellite_indicator,
      { "Satellite Indicator",  "isup.satellite_indicator",
        FT_UINT8, BASE_HEX, VALS(isup_satellite_ind_value), BA_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_continuity_check_indicator,
      { "Continuity Check Indicator",  "isup.continuity_check_indicator",
        FT_UINT8, BASE_HEX, VALS(isup_continuity_check_ind_value), DC_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_echo_control_device_indicator,
      { "Echo Control Device Indicator",  "isup.echo_control_device_indicator",
        FT_BOOLEAN, 8, TFS(&isup_echo_control_device_ind_value),E_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_forw_call_natnl_inatnl_call_indicator,
      { "National/international call indicator",  "isup.forw_call_natnl_inatnl_call_indicator",
        FT_BOOLEAN, 16, TFS(&isup_natnl_inatnl_call_ind_value),A_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_forw_call_end_to_end_method_indicator,
      { "End-to-end method indicator",  "isup.forw_call_end_to_end_method_indicator",
        FT_UINT16, BASE_HEX, VALS(isup_end_to_end_method_ind_value), CB_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_forw_call_interworking_indicator,
      { "Interworking indicator",  "isup.forw_call_interworking_indicator",
        FT_BOOLEAN, 16, TFS(&isup_interworking_ind_value), D_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_forw_call_end_to_end_info_indicator,
      { "End-to-end information indicator",  "isup.forw_call_end_to_end_information_indicator",
        FT_BOOLEAN, 16, TFS(&isup_end_to_end_info_ind_value), E_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_forw_call_isdn_user_part_indicator,
      { "ISDN user part indicator",  "isup.forw_call_isdn_user_part_indicator",
        FT_BOOLEAN, 16, TFS(&isup_ISDN_user_part_ind_value), F_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_forw_call_preferences_indicator,
      { "ISDN user part preference indicator",  "isup.forw_call_preferences_indicator",
        FT_UINT16, BASE_HEX, VALS(isup_preferences_ind_value), HG_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_forw_call_isdn_access_indicator,
      { "ISDN access indicator",  "isup.forw_call_isdn_access_indicator",
        FT_BOOLEAN, 16, TFS(&isup_ISDN_originating_access_ind_value), I_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_forw_call_sccp_method_indicator,
      { "SCCP method indicator",  "isup.forw_call_sccp_method_indicator",
        FT_UINT16, BASE_HEX, VALS(isup_SCCP_method_ind_value), KJ_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_forw_call_ported_num_trans_indicator,
      { "Ported number translation indicator",  "isup.forw_call_ported_num_trans_indicator",
        FT_BOOLEAN, 16, TFS(&isup_ISDN_ported_num_trans_ind_value), M_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_forw_call_qor_attempt_indicator,
      { "Query on Release attempt indicator",  "isup.forw_call_isdn_access_indicator",
        FT_BOOLEAN, 16, TFS(&isup_ISDN_qor_attempt_ind_value), N_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_calling_partys_category,
      { "Calling Party's category",  "isup.calling_partys_category",
        FT_UINT8, BASE_HEX|BASE_EXT_STRING, &isup_calling_partys_category_value_ext, 0x0,
        NULL, HFILL }},

    { &hf_isup_transmission_medium_requirement,
      { "Transmission medium requirement",  "isup.transmission_medium_requirement",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &isup_transmission_medium_requirement_value_ext, 0x0,
        NULL, HFILL }},

    { &hf_isup_odd_even_indicator,
      { "Odd/even indicator",  "isup.isdn_odd_even_indicator",
        FT_BOOLEAN, 8, TFS(&isup_odd_even_ind_value), ISUP_ODD_EVEN_MASK,
        NULL, HFILL }},

    { &hf_isup_generic_name_presentation,
      { "Presentation indicator",  "isup.isdn_generic_name_presentation",
        FT_UINT8, BASE_DEC, VALS(isup_generic_name_presentation_value), BA_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_generic_name_availability,
      { "Availability indicator",  "isup.isdn_generic_name_availability",
        FT_BOOLEAN, 8, TFS(&isup_generic_name_availability_value), E_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_generic_name_type,
      { "Type indicator",  "isup.isdn_generic_name_type",
        FT_UINT8, BASE_DEC, VALS(isup_generic_name_type_value), HGF_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_generic_name_ia5,
      { "Generic Name",  "isup.isdn_generic_name_ia5",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_called_party_nature_of_address_indicator,
      { "Nature of address indicator",  "isup.called_party_nature_of_address_indicator",
        FT_UINT8, BASE_DEC, VALS(isup_called_party_nature_of_address_ind_value), ISUP_NATURE_OF_ADDRESS_IND_MASK,
        NULL, HFILL }},

    { &hf_isup_calling_party_nature_of_address_indicator,
      { "Nature of address indicator",  "isup.calling_party_nature_of_address_indicator",
        FT_UINT8, BASE_DEC, VALS(isup_calling_party_nature_of_address_ind_value), ISUP_NATURE_OF_ADDRESS_IND_MASK,
        NULL, HFILL }},

    { &hf_isup_charge_number_nature_of_address_indicator,
      { "Nature of address indicator",  "isup.charge_number_nature_of_address_indicator",
        FT_UINT8, BASE_DEC, VALS(isup_charge_number_nature_of_address_ind_value), ISUP_NATURE_OF_ADDRESS_IND_MASK,
        NULL, HFILL }},

    { &hf_isup_inn_indicator,
      { "INN indicator",  "isup.inn_indicator",
        FT_BOOLEAN, 8, TFS(&isup_INN_ind_value), ISUP_INN_MASK,
        NULL, HFILL }},

    { &hf_isup_ni_indicator,
      { "NI indicator",  "isup.ni_indicator",
        FT_BOOLEAN, 8, TFS(&isup_NI_ind_value), ISUP_NI_MASK,
        NULL, HFILL }},

    { &hf_isup_numbering_plan_indicator,
      { "Numbering plan indicator",  "isup.numbering_plan_indicator",
        FT_UINT8, BASE_DEC, VALS(isup_numbering_plan_ind_value), ISUP_NUMBERING_PLAN_IND_MASK,
        NULL, HFILL }},

    { &hf_isup_address_presentation_restricted_indicator,
      { "Address presentation restricted indicator",  "isup.address_presentation_restricted_indicator",
        FT_UINT8, BASE_DEC, VALS(isup_address_presentation_restricted_ind_value), ISUP_ADDRESS_PRESENTATION_RESTR_IND_MASK,
        NULL, HFILL }},

    { &hf_isup_screening_indicator,
      { "Screening indicator",  "isup.screening_indicator",
        FT_UINT8, BASE_DEC, VALS(isup_screening_ind_value), ISUP_SCREENING_IND_MASK,
        NULL, HFILL }},

    { &hf_isup_screening_indicator_enhanced,
      { "Screening indicator",  "isup.screening_indicator_enhanced",
        FT_UINT8, BASE_DEC, VALS(isup_screening_ind_enhanced_value), ISUP_SCREENING_IND_MASK,
        NULL, HFILL }},

    { &hf_isup_called_party_odd_address_signal_digit,
      { "Address signal digit",  "isup.called_party_odd_address_signal_digit",
        FT_UINT8, BASE_DEC, VALS(isup_called_party_address_digit_value), ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK,
        NULL, HFILL }},

    { &hf_isup_calling_party_odd_address_signal_digit,
      { "Address signal digit",  "isup.calling_party_odd_address_signal_digit",
        FT_UINT8, BASE_DEC, VALS(isup_calling_party_address_digit_value), ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK,
        NULL, HFILL }},

    { &hf_isup_called_party_even_address_signal_digit,
      { "Address signal digit",  "isup.called_party_even_address_signal_digit",
        FT_UINT8, BASE_DEC, VALS(isup_called_party_address_digit_value), ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK,
        NULL, HFILL }},

    { &hf_isup_calling_party_even_address_signal_digit,
      { "Address signal digit",  "isup.calling_party_even_address_signal_digit",
        FT_UINT8, BASE_DEC, VALS(isup_calling_party_address_digit_value), ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK,
        NULL, HFILL }},

    { &hf_isup_calling_party_address_request_indicator,
      { "Calling party address request indicator",  "isup.calling_party_address_request_indicator",
        FT_BOOLEAN, 16, TFS(&isup_calling_party_address_request_ind_value), A_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_info_req_holding_indicator,
      { "Holding indicator",  "isup.info_req_holding_indicator",
        FT_BOOLEAN, 16, TFS(&isup_holding_ind_value), B_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_calling_partys_category_request_indicator,
      { "Calling party's category request indicator",  "isup.calling_partys_category_request_indicator",
        FT_BOOLEAN, 16, TFS(&isup_calling_partys_category_request_ind_value), D_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_charge_information_request_indicator,
      { "Charge information request indicator",  "isup.charge_information_request_indicator",
        FT_BOOLEAN, 16, TFS(&isup_charge_information_request_ind_value), E_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_malicious_call_identification_request_indicator,
      { "Malicious call identification request indicator (ISUP'88)",  "isup.malicious_call_ident_request_indicator",
        FT_BOOLEAN, 16, TFS(&isup_malicious_call_identification_request_ind_value), H_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_calling_party_address_response_indicator,
      { "Calling party address response indicator",  "isup.calling_party_address_response_indicator",
        FT_UINT16, BASE_HEX, VALS(isup_calling_party_address_response_ind_value), BA_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_OECD_inf_ind,
      { "OECD information indicator",  "isup.OECD_inf_ind_vals",
        FT_UINT8, BASE_HEX, VALS(OECD_inf_ind_vals), BA_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_IECD_inf_ind,
      { "IECD information indicator",  "isup.IECD_inf_ind_vals",
        FT_UINT8, BASE_HEX, VALS(IECD_inf_ind_vals), DC_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_OECD_req_ind,
      { "OECD request indicator",  "isup.OECD_req_ind_vals",
        FT_UINT8, BASE_HEX, VALS(OECD_req_ind_vals), FE_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_IECD_req_ind,
      { "IECD request indicator",  "isup.IECD_req_ind_vals",
        FT_UINT8, BASE_HEX, VALS(IECD_req_ind_vals), HG_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_hold_provided_indicator,
      { "Hold provided indicator",  "isup.hold_provided_indicator",
        FT_BOOLEAN, 16, TFS(&isup_hold_provided_ind_value), C_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_calling_partys_category_response_indicator,
      { "Calling party's category response indicator",  "isup.calling_partys_category_response_indicator",
        FT_BOOLEAN, 16, TFS(&isup_calling_partys_category_response_ind_value), F_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_charge_information_response_indicator,
      { "Charge information response indicator",  "isup.charge_information_response_indicator",
        FT_BOOLEAN, 16, TFS(&isup_charge_information_response_ind_value), G_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_solicited_indicator,
      { "Solicited indicator",  "isup.solicided_indicator",
        FT_BOOLEAN, 16, TFS(&isup_solicited_information_ind_value), H_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_continuity_indicator,
      { "Continuity indicator",  "isup.continuity_indicator",
        FT_BOOLEAN, 8, TFS(&isup_continuity_ind_value), A_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_backw_call_charge_ind,
      { "Charge indicator",  "isup.charge_indicator",
        FT_UINT16, BASE_HEX, VALS(isup_charge_ind_value), BA_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_backw_call_called_partys_status_ind,
      { "Called party's status indicator",  "isup.called_partys_status_indicator",
        FT_UINT16, BASE_HEX, VALS(isup_called_partys_status_ind_value), DC_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_backw_call_called_partys_category_ind,
      { "Called party's category indicator",  "isup.called_partys_category_indicator",
        FT_UINT16, BASE_HEX, VALS(isup_called_partys_category_ind_value), FE_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_backw_call_end_to_end_method_ind,
      { "End-to-end method indicator",  "isup.backw_call_end_to_end_method_indicator",
        FT_UINT16, BASE_HEX, VALS(isup_end_to_end_method_ind_value), HG_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_backw_call_interworking_ind,
      { "Interworking indicator",  "isup.backw_call_interworking_indicator",
        FT_BOOLEAN, 16, TFS(&isup_interworking_ind_value), I_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_backw_call_end_to_end_info_ind,
      { "End-to-end information indicator",  "isup.backw_call_end_to_end_information_indicator",
        FT_BOOLEAN, 16, TFS(&isup_end_to_end_info_ind_value), J_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_backw_call_isdn_user_part_ind,
      { "ISDN user part indicator",  "isup.backw_call_isdn_user_part_indicator",
        FT_BOOLEAN, 16, TFS(&isup_ISDN_user_part_ind_value), K_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_backw_call_holding_ind,
      { "Holding indicator",  "isup.backw_call_holding_indicator",
        FT_BOOLEAN, 16, TFS(&isup_holding_ind_value), L_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_backw_call_isdn_access_ind,
      { "ISDN access indicator",  "isup.backw_call_isdn_access_indicator",
        FT_BOOLEAN, 16, TFS(&isup_ISDN_terminating_access_ind_value), M_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_backw_call_echo_control_device_ind,
      { "Echo Control Device Indicator",  "isup.backw_call_echo_control_device_indicator",
        FT_BOOLEAN, 16, TFS(&isup_echo_control_device_ind_value), N_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_backw_call_sccp_method_ind,
      { "SCCP method indicator",  "isup.backw_call_sccp_method_indicator",
        FT_UINT16, BASE_HEX, VALS(isup_SCCP_method_ind_value), PO_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_cause_indicator,
      { "Cause indicator",  "isup.cause_indicator",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &q850_cause_code_vals_ext, 0x7f,
        NULL, HFILL }},

    { &hf_ansi_isup_cause_indicator,
      { "Cause indicator",  "ansi_isup.cause_indicator",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &ansi_isup_cause_code_vals_ext, 0x7f,
        NULL, HFILL }},

    { &hf_isup_suspend_resume_indicator,
      { "Suspend/Resume indicator",  "isup.suspend_resume_indicator",
        FT_BOOLEAN, 8, TFS(&isup_suspend_resume_ind_value), A_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_range_indicator,
      { "Range indicator",  "isup.range_indicator",
        FT_UINT8, BASE_DEC, NULL , 0x0,
        NULL, HFILL }},

    { &hf_isup_cgs_message_type,
      { "Circuit group supervision message type",  "isup.cgs_message_type",
        FT_UINT8, BASE_DEC, VALS(isup_cgs_message_type_value), BA_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_mtc_blocking_state1,
      { "Maintenance blocking state",  "isup.mtc_blocking_state",
        FT_UINT8, BASE_DEC, VALS(isup_mtc_blocking_state_DC00_value), BA_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_mtc_blocking_state2,
      { "Maintenance blocking state",  "isup.mtc_blocking_state",
        FT_UINT8, BASE_DEC, VALS(isup_mtc_blocking_state_DCnot00_value), BA_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_call_proc_state,
      { "Call processing state",  "isup.call_processing_state",
        FT_UINT8, BASE_DEC, VALS(isup_call_processing_state_value), DC_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_hw_blocking_state,
      { "HW blocking state",  "isup.hw_blocking_state",
        FT_UINT8, BASE_DEC, VALS(isup_HW_blocking_state_value), FE_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_event_ind,
      { "Event indicator",  "isup.event_ind",
        FT_UINT8, BASE_DEC, VALS(isup_event_ind_value), GFEDCBA_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_event_presentation_restricted_ind,
      { "Event presentation restricted indicator",  "isup.event_presentatiation_restr_ind",
        FT_BOOLEAN, 8, TFS(&isup_event_presentation_restricted_ind_value), H_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_cug_call_ind,
      { "Closed user group call indicator",  "isup.clg_call_ind",
        FT_UINT8, BASE_DEC, VALS(isup_CUG_call_ind_value), BA_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_simple_segmentation_ind,
      { "Simple segmentation indicator",  "isup.simple_segmentation_ind",
        FT_BOOLEAN, 8, TFS(&isup_simple_segmentation_ind_value), C_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_connected_line_identity_request_ind,
      { "Connected line identity request indicator",  "isup.connected_line_identity_request_ind",
        FT_BOOLEAN, 8, TFS(&isup_connected_line_identity_request_ind_value), H_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_redirecting_ind,
      { "Redirection indicator",  "isup.redirecting_ind",
        FT_UINT16, BASE_DEC, VALS(isup_redirecting_ind_value), CBA_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_original_redirection_reason,
      { "Original redirection reason",  "isup.original_redirection_reason",
        FT_UINT16, BASE_DEC, VALS(isup_original_redirection_reason_value), HGFE_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_redirection_counter,
      { "Redirection counter",  "isup.redirection_counter",
        FT_UINT16, BASE_DEC, NULL, KJI_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_redirection_reason,
      { "Redirection reason",  "isup.redirection_reason",
        FT_UINT16, BASE_DEC, VALS(isup_redirection_reason_value), PONM_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_type_of_network_identification,
      { "Type of network identification",  "isup.type_of_network_identification",
        FT_UINT8, BASE_DEC, VALS(isup_type_of_network_identification_value), GFE_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_network_identification_plan,
      { "Network identification plan",  "isup.network_identification_plan",
        FT_UINT8, BASE_DEC, VALS(isup_network_identification_plan_value), DCBA_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_map_type,
      { "Map Type",  "isup.map_type",
        FT_UINT8, BASE_DEC, VALS(isup_map_type_value), FEDCBA_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_automatic_congestion_level,
      { "Automatic congestion level",  "isup.automatic_congestion_level",
        FT_UINT8, BASE_DEC, VALS(isup_auto_congestion_level_value), 0x0,
        NULL, HFILL }},

    { &hf_isup_inband_information_ind,
      { "In-band information indicator",  "isup.inband_information_ind",
        FT_BOOLEAN, 8, TFS(&isup_inband_information_ind_value), A_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_call_diversion_may_occur_ind,
      { "Call diversion may occur indicator",  "isup.call_diversion_may_occur_ind",
        FT_BOOLEAN, 8, TFS(&isup_call_diversion_may_occur_ind_value), B_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_mlpp_user_ind,
      { "MLPP user indicator",  "isup.mlpp_user",
        FT_BOOLEAN, 8, TFS(&isup_MLPP_user_ind_value), D_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_UUI_type,
      { "User-to-User indicator type",  "isup.UUI_type",
        FT_BOOLEAN, 8, TFS(&isup_UUI_type_value), A_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_UUI_req_service1,
      { "User-to-User indicator request service 1",  "isup.UUI_req_service1",
        FT_UINT8, BASE_DEC, VALS(isup_UUI_request_service_values), CB_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_UUI_req_service2,
      { "User-to-User indicator request service 2",  "isup.UUI_req_service2",
        FT_UINT8, BASE_DEC, VALS(isup_UUI_request_service_values), ED_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_UUI_req_service3,
      { "User-to-User indicator request service 3",  "isup.UUI_req_service3",
        FT_UINT8, BASE_DEC, VALS(isup_UUI_request_service_values), GF_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_UUI_res_service1,
      { "User-to-User indicator response service 1",  "isup.UUI_res_service1",
        FT_UINT8, BASE_DEC, VALS(isup_UUI_response_service_values), CB_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_UUI_res_service2,
      { "User-to-User indicator response service 2",  "isup.UUI_res_service2",
        FT_UINT8, BASE_DEC, VALS(isup_UUI_response_service_values), ED_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_UUI_res_service3,
      { "User-to-User response service 3",  "isup.UUI_res_service3",
        FT_UINT8, BASE_DEC, VALS(isup_UUI_response_service_values), GF_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_UUI_network_discard_ind,
      { "User-to-User indicator network discard indicator",  "isup.UUI_network_discard_ind",
        FT_BOOLEAN, 8, TFS(&isup_UUI_network_discard_ind_value), H_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_access_delivery_ind,
      { "Access delivery indicator",  "isup.access_delivery_ind",
        FT_BOOLEAN, 8, TFS(&isup_access_delivery_ind_value), A_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_transmission_medium_requirement_prime,
      { "Transmission medium requirement prime",  "isup.transmission_medium_requirement_prime",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &isup_transmission_medium_requirement_prime_value_ext, 0x0,
        NULL, HFILL }},

    { &hf_isup_loop_prevention_response_ind,
      { "Response indicator",  "isup.loop_prevention_response_ind",
        FT_UINT8, BASE_DEC, VALS(isup_loop_prevention_response_ind_value), CB_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_temporary_alternative_routing_ind,
      { "Temporary alternative routing indicator",  "isup.temporary_alternative_routing_ind",
        FT_BOOLEAN, 8, TFS(&isup_temporary_alternative_routing_ind_value), A_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_extension_ind,
      { "Extension indicator",  "isup.extension_ind",
        FT_BOOLEAN, 8, TFS(&isup_extension_ind_value), H_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_call_to_be_diverted_ind,
      { "Call to be diverted indicator",  "isup.call_to_be_diverted_ind",
        FT_UINT8, BASE_DEC, VALS(isup_call_to_be_diverted_ind_value), BA_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_call_to_be_offered_ind,
      { "Call to be offered indicator",  "isup.call_to_be_offered_ind",
        FT_UINT8, BASE_DEC, VALS(isup_call_to_be_offered_ind_value), BA_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_conference_acceptance_ind,
      { "Conference acceptance indicator",  "isup.conference_acceptance_ind",
        FT_UINT8, BASE_DEC, VALS(isup_conference_acceptance_ind_value), BA_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_transit_at_intermediate_exchange_ind,
      { "Transit at intermediate exchange indicator", "isup.transit_at_intermediate_exchange_ind",
        FT_BOOLEAN, 8, TFS(&isup_transit_at_intermediate_exchange_ind_value), A_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_Release_call_ind,
      { "Release call indicator", "isup.Release_call_ind",
        FT_BOOLEAN, 8, TFS(&isup_Release_call_indicator_value), B_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_Send_notification_ind,
      { "Send notification indicator", "isup.Send_notification_ind",
        FT_BOOLEAN, 8, TFS(&isup_Send_notification_ind_value),C_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_Discard_message_ind_value,
      { "Discard message indicator","isup.Discard_message_ind_value",
        FT_BOOLEAN, 8, TFS(&isup_Discard_message_ind_value), D_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_Discard_parameter_ind,
      { "Discard parameter indicator","isup.Discard_parameter_ind",
        FT_BOOLEAN, 8, TFS(&isup_Discard_parameter_ind_value), E_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_Pass_on_not_possible_indicator,
      { "Pass on not possible indicator",  "isup_Pass_on_not_possible_ind",
        FT_UINT8, BASE_HEX, VALS(isup_Pass_on_not_possible_indicator_vals),GF_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_pass_on_not_possible_indicator2,
      { "Pass on not possible indicator",  "isup_Pass_on_not_possible_val",
        FT_BOOLEAN, 8, TFS(&isup_pass_on_not_possible_indicator_value),E_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_Broadband_narrowband_interworking_ind,
      { "Broadband narrowband interworking indicator Bits JF",  "isup_broadband-narrowband_interworking_ind",
        FT_UINT8, BASE_HEX, VALS(ISUP_Broadband_narrowband_interworking_indicator_vals),BA_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_Broadband_narrowband_interworking_ind2,
      { "Broadband narrowband interworking indicator Bits GF",  "isup_broadband-narrowband_interworking_ind2",
        FT_UINT8, BASE_HEX, VALS(ISUP_Broadband_narrowband_interworking_indicator_vals),GF_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_app_cont_ident,
      { "Application context identifier",  "isup.app_context_identifier",
        FT_UINT16, BASE_DEC, VALS(isup_application_transport_parameter_value),GFEDCBA_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_app_Release_call_ind,
      { "Release call indicator (RCI)",  "isup.app_Release_call_indicator",
        FT_BOOLEAN, 8, TFS(&isup_Release_call_indicator_value), A_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_app_Send_notification_ind,
      { "Send notification indicator (SNI)",  "isup.app_Send_notification_ind",
        FT_BOOLEAN, 8, TFS(&isup_Send_notification_ind_value), B_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_apm_segmentation_ind,
      { "APM segmentation indicator",  "isup.apm_segmentation_ind",
        FT_UINT8, BASE_DEC, VALS(isup_APM_segmentation_ind_value), FEDCBA_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_apm_si_ind,
      { "Sequence indicator (SI)",  "isup.APM_Sequence_ind",
        FT_BOOLEAN, 8, TFS(&isup_Sequence_ind_value), G_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_orig_addr_len,
      { "Originating Address length",  "isup.orig_addr_len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_dest_addr_len,
      { "Destination Address length",  "isup.orig_addr_len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_apm_slr,
      { "Segmentation local reference (SLR)",  "isup.APM_slr",
        FT_UINT8, BASE_DEC, NULL,GFEDCBA_8BIT_MASK,
        NULL, HFILL }},
    { &hf_isup_cause_location,
      { "Cause location", "isup.cause_location",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &q931_cause_location_vals_ext, 0x0f,
        NULL, HFILL }},

    { &hf_ansi_isup_coding_standard,
      { "Coding standard", "ansi_isup.coding_standard", FT_UINT8, BASE_HEX,
        VALS(ansi_isup_coding_standard_vals), 0x60,NULL, HFILL }},

    { &hf_bat_ase_identifier,
      { "BAT ASE Identifiers",  "bicc.bat_ase_identifier",
        FT_UINT8, BASE_HEX|BASE_EXT_STRING, &bat_ase_list_of_Identifiers_vals_ext,0x0,
        NULL, HFILL }},

    { &hf_length_indicator,
      { "BAT ASE Element length indicator",  "bicc.bat_ase_length_indicator",
        FT_UINT16, BASE_DEC, NULL,0x0,
        NULL, HFILL }},

    { &hf_Action_Indicator,
      { "BAT ASE action indicator field",  "bicc.bat_ase_bat_ase_action_indicator_field",
        FT_UINT8, BASE_HEX|BASE_EXT_STRING, &bat_ase_action_indicator_field_vals_ext,0x00,
        NULL, HFILL }},

    { &hf_Instruction_ind_for_general_action,
      { "BAT ASE Instruction indicator for general action",  "bicc.bat_ase_Instruction_ind_for_general_action",
        FT_UINT8, BASE_HEX, VALS(Instruction_indicator_for_general_action_vals),0x03,
        NULL, HFILL }},

    { &hf_Send_notification_ind_for_general_action,
      { "Send notification indicator for general action",  "bicc.bat_ase_Send_notification_ind_for_general_action",
        FT_BOOLEAN, 8, TFS(&isup_Send_notification_ind_value), 0x04,
        NULL, HFILL }},

    { &hf_Instruction_ind_for_pass_on_not_possible,
      { "Instruction ind for pass-on not possible",  "bicc.bat_ase_Instruction_ind_for_pass_on_not_possible",
        FT_UINT8, BASE_HEX, VALS(Instruction_indicator_for_pass_on_not_possible_vals),0x30,
        NULL, HFILL }},

    { &hf_Send_notification_ind_for_pass_on_not_possible,
      { "Send notification indication for pass-on not possible",  "bicc.bat_ase_Send_notification_ind_for_pass_on_not_possible",
        FT_BOOLEAN, 8, TFS(&isup_Send_notification_ind_value), 0x40,
        NULL, HFILL }},

    { &hf_BCTP_Version_Indicator,
      { "BCTP Version Indicator",  "bicc.bat_ase_BCTP_Version_Indicator",
        FT_UINT8, BASE_DEC, NULL,0x1f,
        NULL, HFILL }},

    { &hf_BVEI,
      { "BVEI",  "bicc.bat_ase_BCTP_BVEI",
        FT_BOOLEAN, 8, TFS(&BCTP_BVEI_value), 0x40,
        NULL, HFILL }},

    { &hf_Tunnelled_Protocol_Indicator,
      { "Tunnelled Protocol Indicator",  "bicc.bat_ase_BCTP_Tunnelled_Protocol_Indicator",
        FT_UINT8, BASE_DEC, VALS(BCTP_Tunnelled_Protocol_Indicator_vals),0x3f,
        NULL, HFILL }},

    { &hf_TPEI,
      { "TPEI",  "bicc.bat_ase_BCTP_tpei",
        FT_BOOLEAN, 8, TFS(&BCTP_TPEI_value), 0x40,
        NULL, HFILL }},

    { &hf_bncid,
      { "Backbone Network Connection Identifier (BNCId)", "bat_ase.bncid",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_bat_ase_biwfa,
      { "Interworking Function Address( X.213 NSAP encoded)", "bat_ase_biwfa",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_afi,
      { "X.213 Address Format Information ( AFI )",  "x213.afi",
        FT_UINT8, BASE_HEX|BASE_EXT_STRING, &x213_afi_value_ext,0x0,
        NULL, HFILL }},

    { &hf_bicc_nsap_dsp,
      { "X.213 Address Format Information ( DSP )",  "x213.dsp",
        FT_BYTES, BASE_NONE, NULL,0x0,
        NULL, HFILL }},
    { &hf_characteristics,
      { "Backbone network connection characteristics", "bat_ase.char",
        FT_UINT8, BASE_HEX|BASE_EXT_STRING, &bearer_network_connection_characteristics_vals_ext,0x0,
        NULL, HFILL }},

    { &hf_Organization_Identifier,
      { "Organization identifier subfield",  "bat_ase.organization_identifier_subfield",
        FT_UINT8, BASE_DEC, VALS(bat_ase_organization_identifier_subfield_vals),0x0,
        NULL, HFILL }},

    { &hf_codec_type,
      { "ITU-T codec type subfield",  "bat_ase.ITU_T_codec_type_subfield",
        FT_UINT8, BASE_HEX|BASE_EXT_STRING, &ITU_T_codec_type_subfield_vals_ext,0x0,
        NULL, HFILL }},

    { &hf_etsi_codec_type,
      { "ETSI codec type subfield",  "bat_ase.ETSI_codec_type_subfield",
        FT_UINT8, BASE_HEX|BASE_EXT_STRING, &ETSI_codec_type_subfield_vals_ext,0x0,
        NULL, HFILL }},

    { &hf_active_code_set,
      { "Active Code Set",  "bat_ase.acs",
        FT_UINT8, BASE_HEX, NULL,0x0,
        NULL, HFILL }},

    { &hf_active_code_set_12_2,
      { "12.2 kbps rate",  "bat_ase.acs.12_2",
        FT_UINT8, BASE_HEX, NULL,0x80,
        NULL, HFILL }},

    { &hf_active_code_set_10_2,
      { "10.2 kbps rate",  "bat_ase.acs.10_2",
        FT_UINT8, BASE_HEX, NULL,0x40,
        NULL, HFILL }},

    { &hf_active_code_set_7_95,
      { "7.95 kbps rate",  "bat_ase.acs.7_95",
        FT_UINT8, BASE_HEX, NULL,0x20,
        NULL, HFILL }},

    { &hf_active_code_set_7_40,
      { "7.40 kbps rate",  "bat_ase.acs.7_40",
        FT_UINT8, BASE_HEX, NULL,0x10,
        NULL, HFILL }},

    { &hf_active_code_set_6_70,
      { "6.70 kbps rate",  "bat_ase.acs.6_70",
        FT_UINT8, BASE_HEX, NULL,0x08,
        NULL, HFILL }},

    { &hf_active_code_set_5_90,
      { "5.90 kbps rate",  "bat_ase.acs.5_90",
        FT_UINT8, BASE_HEX, NULL,0x04,
        NULL, HFILL }},

    { &hf_active_code_set_5_15,
      { "5.15 kbps rate",  "bat_ase.acs.5_15",
        FT_UINT8, BASE_HEX, NULL,0x02,
        NULL, HFILL }},

    { &hf_active_code_set_4_75,
      { "4.75 kbps rate",  "bat_ase.acs.4_75",
        FT_UINT8, BASE_HEX, NULL,0x01,
        NULL, HFILL }},

    { &hf_supported_code_set,
      { "Supported Code Set",  "bat_ase.scs",
        FT_UINT8, BASE_HEX, NULL,0x0,
        NULL, HFILL }},

    { &hf_supported_code_set_12_2,
      { "12.2 kbps rate",  "bat_ase.scs.12_2",
        FT_UINT8, BASE_HEX, NULL,0x80,
        NULL, HFILL }},

    { &hf_supported_code_set_10_2,
      { "10.2 kbps rate",  "bat_ase.scs.10_2",
        FT_UINT8, BASE_HEX, NULL,0x40,
        NULL, HFILL }},

    { &hf_supported_code_set_7_95,
      { "7.95 kbps rate",  "bat_ase.scs.7_95",
        FT_UINT8, BASE_HEX, NULL,0x20,
        NULL, HFILL }},

    { &hf_supported_code_set_7_40,
      { "7.40 kbps rate",  "bat_ase.scs.7_40",
        FT_UINT8, BASE_HEX, NULL,0x10,
        NULL, HFILL }},

    { &hf_supported_code_set_6_70,
      { "6.70 kbps rate",  "bat_ase.scs.6_70",
        FT_UINT8, BASE_HEX, NULL,0x08,
        NULL, HFILL }},

    { &hf_supported_code_set_5_90,
      { "5.90 kbps rate",  "bat_ase.scs.5_90",
        FT_UINT8, BASE_HEX, NULL,0x04,
        NULL, HFILL }},

    { &hf_supported_code_set_5_15,
      { "5.15 kbps rate",  "bat_ase.scs.5_15",
        FT_UINT8, BASE_HEX, NULL,0x02,
        NULL, HFILL }},

    { &hf_supported_code_set_4_75,
      { "4.75 kbps rate",  "bat_ase.scs.4_75",
        FT_UINT8, BASE_HEX, NULL,0x01,
        NULL, HFILL }},

    { &hf_optimisation_mode,
      { "Optimisation Mode for ACS , OM",  "bat_ase.optimisation_mode",
        FT_UINT8, BASE_HEX, VALS(optimisation_mode_vals),0x8,
        NULL, HFILL }},

    { &hf_max_codec_modes,
      { "Maximal number of Codec Modes, MACS",  "bat_ase.macs",
        FT_UINT8, BASE_DEC, NULL,0x07,
        NULL, HFILL }},


    { &hf_bearer_control_tunneling,
      { "Bearer control tunneling",  "bat_ase.bearer_control_tunneling",
        FT_BOOLEAN, 8, TFS(&Bearer_Control_Tunnelling_ind_value),0x01,
        NULL, HFILL }},

    { &hf_BAT_ASE_Comp_Report_Reason,
      { "Compatibility report reason",  "bat_ase.Comp_Report_Reason",
        FT_UINT8, BASE_HEX, VALS(BAT_ASE_Report_Reason_vals),0x0,
        NULL, HFILL }},


    { &hf_BAT_ASE_Comp_Report_ident,
      { "Bearer control tunneling",  "bat_ase.bearer_control_tunneling",
        FT_UINT8, BASE_HEX|BASE_EXT_STRING, &bat_ase_list_of_Identifiers_vals_ext,0x0,
        NULL, HFILL }},

    { &hf_BAT_ASE_Comp_Report_diagnostic,
      { "Diagnostics",  "bat_ase.Comp_Report_diagnostic",
        FT_UINT16, BASE_HEX, NULL,0x0,
        NULL, HFILL }},

    { &hf_Local_BCU_ID,
      { "Local BCU ID",  "bat_ase.Local_BCU_ID",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_late_cut_trough_cap_ind,
      { "Late Cut-through capability indicator",  "bat_ase.late_cut_trough_cap_ind",
        FT_BOOLEAN, 8, TFS(&late_cut_trough_cap_ind_value),0x01,
        NULL, HFILL }},

    { &hf_bat_ase_signal,
      { "Q.765.5 - Signal Type",  "bat_ase.signal_type",
        FT_UINT8, BASE_HEX|BASE_EXT_STRING, &BAT_ASE_Signal_Type_vals_ext,0x0,
        NULL, HFILL }},

    { &hf_bat_ase_duration,
      { "Duration in ms",  "bat_ase.signal_type",
        FT_UINT16, BASE_DEC, NULL,0x0,
        NULL, HFILL }},

    { &hf_bat_ase_bearer_redir_ind,
      { "Redirection Indicator",  "bat_ase.bearer_redir_ind",
        FT_UINT8, BASE_HEX|BASE_EXT_STRING, &Bearer_Redirection_Indicator_vals_ext,0x0,
        NULL, HFILL }},

    { &hf_nsap_ipv4_addr,
      { "IWFA IPv4 Address", "nsap.ipv4_addr",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        "IPv4 address", HFILL }},

    { &hf_nsap_ipv6_addr,
      { "IWFA IPv6 Address", "nsap.ipv6_addr",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        "IPv6 address", HFILL}},

    { &hf_iana_icp,
      { "IANA ICP",  "nsap.iana_icp",
        FT_UINT16, BASE_HEX, VALS(iana_icp_values),0x0,
        NULL, HFILL }},

    { &hf_isup_called,
      { "ISUP Called Number",  "isup.called",
        FT_STRING, BASE_NONE, NULL,0x0,
        NULL, HFILL }},

    { &hf_isup_calling,
      { "ISUP Calling Number",  "isup.calling",
        FT_STRING, BASE_NONE, NULL,0x0,
        NULL, HFILL }},

    { &hf_isup_redirecting,
      { "ISUP Redirecting Number",  "isup.redirecting",
        FT_STRING, BASE_NONE, NULL,0x0,
        NULL, HFILL }},
    {&hf_isup_apm_msg_fragments,
     {"Message fragments", "isup_apm.msg.fragments",
      FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    {&hf_isup_apm_msg_fragment,
     {"Message fragment", "isup_apm.msg.fragment",
      FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    {&hf_isup_apm_msg_fragment_overlap,
     {"Message fragment overlap", "isup_apm.msg.fragment.overlap",
      FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    {&hf_isup_apm_msg_fragment_overlap_conflicts,
     {"Message fragment overlapping with conflicting data","isup_apm.msg.fragment.overlap.conflicts",
      FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    {&hf_isup_apm_msg_fragment_multiple_tails,
     {"Message has multiple tail fragments", "isup_apm.msg.fragment.multiple_tails",
      FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    {&hf_isup_apm_msg_fragment_too_long_fragment,
     {"Message fragment too long", "isup_apm.msg.fragment.too_long_fragment",
      FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    {&hf_isup_apm_msg_fragment_error,
     {"Message defragmentation error", "isup_apm.msg.fragment.error",
      FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    {&hf_isup_apm_msg_fragment_count,
     {"Message fragment count", "isup_apm.msg.fragment.count",
      FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
    },
    {&hf_isup_apm_msg_reassembled_in,
     {"Reassembled in", "isup_apm.msg.reassembled.in",
      FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    {&hf_isup_apm_msg_reassembled_length,
     {"Reassembled ISUP length", "isup_apm.msg.reassembled.length",
      FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
    },
    {&hf_isup_cvr_rsp_ind,
     {"CVR Response Ind", "conn_rsp_ind",
      FT_UINT8, BASE_DEC, VALS(isup_cvr_rsp_ind_value), BA_8BIT_MASK,
      NULL, HFILL }},
    {&hf_isup_cvr_cg_car_ind,
     {"CVR Circuit Group Carrier","cg_carrier_ind",
      FT_UINT8, BASE_HEX, VALS(isup_cvr_cg_car_ind_value), BA_8BIT_MASK,
      NULL, HFILL }},
    {&hf_isup_cvr_cg_double_seize,
     {"Double Seize Control", "cg_char_ind.doubleSeize",
      FT_UINT8, BASE_HEX, VALS(isup_cvr_cg_double_seize_value), DC_8BIT_MASK,
      NULL, HFILL }},
    {&hf_isup_cvr_cg_alarm_car_ind,
     {"Alarm Carrier Indicator", "cg_alarm_car_ind",
      FT_UINT8, BASE_HEX, VALS(isup_cvr_alarm_car_ind_value), FE_8BIT_MASK,
      NULL, HFILL }},
    {&hf_isup_cvr_cont_chk_ind,
     {"Continuity Check Indicator","cg_alarm_cnt_chk",
      FT_UINT8, BASE_HEX, VALS(isup_cvr_cont_chk_ind_value), HG_8BIT_MASK,
      NULL,HFILL }},

    { &hf_isup_geo_loc_presentation_restricted_ind,
      { "Calling Geodetic Location presentation restricted indicator",  "isup.location_presentation_restr_ind",
        FT_UINT8, BASE_DEC, VALS(isup_location_presentation_restricted_ind_value), DC_8BIT_MASK,
        NULL, HFILL }},
    { &hf_isup_geo_loc_screening_ind,
      { "Calling Geodetic Location screening indicator",  "isup.location_screening_ind",
        FT_UINT8, BASE_DEC, VALS(isup_screening_ind_enhanced_value), BA_8BIT_MASK,        /* using previously defined screening values */
        NULL, HFILL }}
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
    &ett_bat_ase_iwfa,
    &ett_scs,
    &ett_acs,
    &ett_isup_apm_msg_fragment,
    &ett_isup_apm_msg_fragments,
  };

/* Register the protocol name and description */
  proto_isup = proto_register_protocol("ISDN User Part",
                                       "ISUP", "isup");

  register_dissector("isup", dissect_isup, proto_isup);

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_isup, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  isup_tap = register_tap("isup");

  isup_module = prefs_register_protocol(proto_isup, NULL);


  prefs_register_bool_preference(isup_module, "show_cic_in_info", "Show CIC in Info column",
                                 "Show the CIC value (in addition to the message type) in the Info column",
                                 (gint *)&isup_show_cic_in_info);

  prefs_register_bool_preference(isup_module, "defragment_apm",
                                 "Reassemble APM messages",
                                 "Whether APM messages datagrams should be reassembled",
                                 &isup_apm_desegment);

  /* Register the stats_tree */
  stats_tree_register_with_group("isup", "isup_msg", "_ISUP Messages",
                                 0, msg_stats_tree_packet, msg_stats_tree_init,
                                 NULL, REGISTER_STAT_GROUP_TELEPHONY);
}


/* ------------------------------------------------------------------ */
/* Register isup with the sub-laying MTP L3 dissector */
void
proto_reg_handoff_isup(void)
{
  dissector_handle_t isup_handle;
  dissector_handle_t application_isup_handle;

  isup_handle = create_dissector_handle(dissect_isup, proto_isup);
  application_isup_handle = create_dissector_handle(dissect_application_isup, proto_isup);
  dissector_add_uint("mtp3.service_indicator", MTP3_ISUP_SERVICE_INDICATOR, isup_handle);
  dissector_add_string("media_type","application/isup", application_isup_handle);
  dissector_add_string("tali.opcode", "isot", isup_handle);

}

void
proto_register_bicc(void)
{
/* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    { &hf_bicc_cic,
      { "Call identification Code (CIC)",           "bicc.cic",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_bicc
  };
  proto_bicc = proto_register_protocol("Bearer Independent Call Control",
                                       "BICC", "bicc");
  register_dissector("bicc", dissect_bicc, proto_bicc);
/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_bicc, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_init_routine(isup_apm_defragment_init);
}

/* Register isup with the sub-laying MTP L3 dissector */
void
proto_reg_handoff_bicc(void)
{
  dissector_handle_t bicc_handle;
  sdp_handle = find_dissector("sdp");
  q931_ie_handle = find_dissector("q931.ie");

  bicc_handle = create_dissector_handle(dissect_bicc, proto_bicc);
  dissector_add_uint("mtp3.service_indicator", MTP3_BICC_SERVICE_INDICATOR, bicc_handle);
  dissector_add_uint("sctp.ppi", BICC_PAYLOAD_PROTOCOL_ID, bicc_handle);
}
