/* packet-isup.c
 * Routines for ISUP dissection
 * Copyright 2001, Martina Obermeier <martina.obermeier@icn.siemens.de>
 *
 * Modified 2003-09-10 by Anders Broman
 *          <anders.broman@ericsson.com>
 * Inserted routines for BICC dissection according to Q.765.5 Q.1902 Q.1970 Q.1990,
 * calling SDP dissector for RFC2327 decoding.
 * Modified 2004-01-10 by Anders Broman to add ability to dissect
 * Content type application/ISUP RFC 3204 used in SIP-T
 *
 * Copyright 2004-2005, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 * References:
 * ISUP:
 * http://www.itu.int/rec/recommendation.asp?type=products&lang=e&parent=T-REC-Q
 * Q.763-199912, Q.763-200212Amd2
 * ITU-T Q.763/Amd.1 (03/2001)
 *
 * National variants
 * French ISUP Specification: SPIROU 1998 - 002-005 edition 1 ( Info found here http://www.icg-corp.com/docs/ISUP.pdf ).
 *   See also http://www.fftelecoms.org/sites/default/files/contenus_lies/fft_interco_ip_-_sip-i_interface_specification_v1_0.pdf
 * Israeli ISUP Specification: excertp (for BCM message) found in https://gitlab.com/wireshark/wireshark/-/issues/4231 .
 * Russian national ISUP-R 2000: RD 45.217-2001 book 4
 * Japan ISUP http://www.ttc.or.jp/jp/document_list/sum/sum_JT-Q763v21.1.pdf
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/exceptions.h>
#include <epan/conversation.h>
#include <epan/stats_tree.h>
#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/sctpppids.h>
#include <epan/osi-utils.h>
#include <epan/reassemble.h>
#include <epan/to_str.h>
#include <epan/media_params.h>
#include <wsutil/str_util.h>
#include "packet-q931.h"
#include "packet-isup.h"
#include "packet-e164.h"
#include "packet-charging_ase.h"
#include "packet-mtp3.h"
#include "packet-http.h"

void proto_register_isup(void);
void proto_reg_handoff_isup(void);
void proto_register_bicc(void);
void proto_reg_handoff_bicc(void);

static dissector_handle_t isup_handle;

#define ISUP_ITU_STANDARD_VARIANT 0
#define ISUP_FRENCH_VARIANT       1
#define ISUP_ISRAELI_VARIANT      2
#define ISUP_RUSSIAN_VARIANT      3
#define ISUP_JAPAN_VARIANT        4
#define ISUP_JAPAN_TTC_VARIANT    5

static gint isup_standard = ITU_STANDARD;
/* Preference standard or national ISUP variants */
static gint g_isup_variant = ISUP_ITU_STANDARD_VARIANT;

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

  { 10,                                       "Reserved (used in 1984 version)"},
  { 11,                                       "Reserved (used in 1984 version)"},

  { MESSAGE_TYPE_RELEASE,                     "Release"},
  { MESSAGE_TYPE_SUSPEND,                     "Suspend"},
  { MESSAGE_TYPE_RESUME,                      "Resume"},

  { 15,                                       "Reserved"},

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

  { 28,                                       "Reserved (used in 1988 version)"},
  { 29,                                       "Reserved (used in 1988 version)"},
  { 30,                                       "Reserved (used in 1988 version)"},

  { MESSAGE_TYPE_FACILITY_REQ,                "Facility request"},
  { MESSAGE_TYPE_FACILITY_ACC,                "Facility accepted"},
  { MESSAGE_TYPE_FACILITY_REJ,                "Facility reject"},

  { 34,                                       "Reserved (used in 1984 version)"},
  { 35,                                       "Reserved (used in 1984 version)"},

  { MESSAGE_TYPE_LOOP_BACK_ACK,               "Loop back acknowledgement (national use)"},

  { 37,                                       "Reserved (used in 1984 version)"},
  { 38,                                       "Reserved (used in 1984 version)"},
  { 39,                                       "Reserved (used in 1984 version)"},

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

  { 62,                                       "Unknown"},
  { 63,                                       "Unknown"},

  { MESSAGE_TYPE_LOOP_PREVENTION,             "Loop prevention"},
  { MESSAGE_TYPE_APPLICATION_TRANS,           "Application transport"},
  { MESSAGE_TYPE_PRE_RELEASE_INFO,            "Pre-release information"},
  { MESSAGE_TYPE_SUBSEQUENT_DIR_NUM,          "Subsequent Directory Number (national use)"},
  { 0,                                  NULL}};
static value_string_ext isup_message_type_value_ext = VALUE_STRING_EXT_INIT(isup_message_type_value);

#define FRENCH_CHARGING_PULSE 0xe1
#define FRENCH_CHARGING_ACK 0xe2
static const value_string french_isup_message_type_value[] = {
  { MESSAGE_TYPE_INITIAL_ADDR,                "Initial address"},
  { MESSAGE_TYPE_SUBSEQ_ADDR,                 "Subsequent address"},
  { MESSAGE_TYPE_INFO_REQ,                    "Information request (national use)"},
  { MESSAGE_TYPE_INFO,                        "Information (national use)"},
  { MESSAGE_TYPE_CONTINUITY,                  "Continuity"},
  { MESSAGE_TYPE_ADDR_CMPL,                   "Address complete"},
  { MESSAGE_TYPE_CONNECT,                     "Connect"},
  { MESSAGE_TYPE_FORW_TRANS,                  "Forward transfer"},
  { MESSAGE_TYPE_ANSWER,                      "Answer"},

  { 10,                                       "Reserved (used in 1984 version)"},
  { 11,                                       "Reserved (used in 1984 version)"},

  { MESSAGE_TYPE_RELEASE,                     "Release"},
  { MESSAGE_TYPE_SUSPEND,                     "Suspend"},
  { MESSAGE_TYPE_RESUME,                      "Resume"},

  { 15,                                       "Reserved"},

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

  { 28,                                       "Reserved (used in 1988 version)"},
  { 29,                                       "Reserved (used in 1988 version)"},
  { 30,                                       "Reserved (used in 1988 version)"},

  { MESSAGE_TYPE_FACILITY_REQ,                "Facility request"},
  { MESSAGE_TYPE_FACILITY_ACC,                "Facility accepted"},
  { MESSAGE_TYPE_FACILITY_REJ,                "Facility reject"},

  { 34,                                       "Reserved (used in 1984 version)"},
  { 35,                                       "Reserved (used in 1984 version)"},

  { MESSAGE_TYPE_LOOP_BACK_ACK,               "Loop back acknowledgement (national use)"},

  { 37,                                       "Reserved (used in 1984 version)"},
  { 38,                                       "Reserved (used in 1984 version)"},
  { 39,                                       "Reserved (used in 1984 version)"},

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

  { 62,                                       "Unknown"},
  { 63,                                       "Unknown"},

  { MESSAGE_TYPE_LOOP_PREVENTION,             "Loop prevention"},
  { MESSAGE_TYPE_APPLICATION_TRANS,           "Application transport"},
  { MESSAGE_TYPE_PRE_RELEASE_INFO,            "Pre-release information"},
  { MESSAGE_TYPE_SUBSEQUENT_DIR_NUM,          "Subsequent Directory Number (national use)"},
  { FRENCH_CHARGING_PULSE,                    "Charging Pulse"},
  { FRENCH_CHARGING_ACK,                      "Charging Acknowledge"},
  { 0,                                  NULL}};
static value_string_ext french_isup_message_type_value_ext = VALUE_STRING_EXT_INIT(french_isup_message_type_value);

#define ISRAELI_BACKWARD_CHARGING 232
#define ISRAELI_TRAFFIC_CHANGE 233
#define ISRAELI_CHARGE_ACK 234
static const value_string israeli_isup_message_type_value[] = {
  { MESSAGE_TYPE_INITIAL_ADDR,                "Initial address"},
  { MESSAGE_TYPE_SUBSEQ_ADDR,                 "Subsequent address"},
  { MESSAGE_TYPE_INFO_REQ,                    "Information request (national use)"},
  { MESSAGE_TYPE_INFO,                        "Information (national use)"},
  { MESSAGE_TYPE_CONTINUITY,                  "Continuity"},
  { MESSAGE_TYPE_ADDR_CMPL,                   "Address complete"},
  { MESSAGE_TYPE_CONNECT,                     "Connect"},
  { MESSAGE_TYPE_FORW_TRANS,                  "Forward transfer"},
  { MESSAGE_TYPE_ANSWER,                      "Answer"},

  { 10,                                       "Reserved (used in 1984 version)"},
  { 11,                                       "Reserved (used in 1984 version)"},

  { MESSAGE_TYPE_RELEASE,                     "Release"},
  { MESSAGE_TYPE_SUSPEND,                     "Suspend"},
  { MESSAGE_TYPE_RESUME,                      "Resume"},

  { 15,                                       "Reserved"},

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

  { 28,                                       "Reserved (used in 1988 version)"},
  { 29,                                       "Reserved (used in 1988 version)"},
  { 30,                                       "Reserved (used in 1988 version)"},

  { MESSAGE_TYPE_FACILITY_REQ,                "Facility request"},
  { MESSAGE_TYPE_FACILITY_ACC,                "Facility accepted"},
  { MESSAGE_TYPE_FACILITY_REJ,                "Facility reject"},

  { 34,                                       "Reserved (used in 1984 version)"},
  { 35,                                       "Reserved (used in 1984 version)"},

  { MESSAGE_TYPE_LOOP_BACK_ACK,               "Loop back acknowledgement (national use)"},

  { 37,                                       "Reserved (used in 1984 version)"},
  { 38,                                       "Reserved (used in 1984 version)"},
  { 39,                                       "Reserved (used in 1984 version)"},

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

  { 62,                                       "Unknown"},
  { 63,                                       "Unknown"},

  { MESSAGE_TYPE_LOOP_PREVENTION,             "Loop prevention"},
  { MESSAGE_TYPE_APPLICATION_TRANS,           "Application transport"},
  { MESSAGE_TYPE_PRE_RELEASE_INFO,            "Pre-release information"},
  { MESSAGE_TYPE_SUBSEQUENT_DIR_NUM,          "Subsequent Directory Number (national use)"},
  { ISRAELI_BACKWARD_CHARGING,                 "Backward Charging"},
  { ISRAELI_TRAFFIC_CHANGE,                    "Traffic Change"},
  { ISRAELI_CHARGE_ACK,                        "Charge Ack"},
  { 0,                                  NULL}};
static value_string_ext israeli_isup_message_type_value_ext = VALUE_STRING_EXT_INIT(israeli_isup_message_type_value);

#define RUSSIAN_CLEAR_CALLING_LINE 252
#define RUSSIAN_RINGING            255

static const value_string russian_isup_message_type_value[] = {
  { MESSAGE_TYPE_INITIAL_ADDR,                "Initial address"},
  { MESSAGE_TYPE_SUBSEQ_ADDR,                 "Subsequent address"},
  { MESSAGE_TYPE_INFO_REQ,                    "Information request (national use)"},
  { MESSAGE_TYPE_INFO,                        "Information (national use)"},
  { MESSAGE_TYPE_CONTINUITY,                  "Continuity"},
  { MESSAGE_TYPE_ADDR_CMPL,                   "Address complete"},
  { MESSAGE_TYPE_CONNECT,                     "Connect"},
  { MESSAGE_TYPE_FORW_TRANS,                  "Forward transfer"},
  { MESSAGE_TYPE_ANSWER,                      "Answer"},

  { 10,                                       "Reserved (used in 1984 version)"},
  { 11,                                       "Reserved (used in 1984 version)"},

  { MESSAGE_TYPE_RELEASE,                     "Release"},
  { MESSAGE_TYPE_SUSPEND,                     "Suspend"},
  { MESSAGE_TYPE_RESUME,                      "Resume"},

  { 15,                                       "Reserved"},

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

  { 28,                                       "Reserved (used in 1988 version)"},
  { 29,                                       "Reserved (used in 1988 version)"},
  { 30,                                       "Reserved (used in 1988 version)"},

  { MESSAGE_TYPE_FACILITY_REQ,                "Facility request"},
  { MESSAGE_TYPE_FACILITY_ACC,                "Facility accepted"},
  { MESSAGE_TYPE_FACILITY_REJ,                "Facility reject"},

  { 34,                                       "Reserved (used in 1984 version)"},
  { 35,                                       "Reserved (used in 1984 version)"},

  { MESSAGE_TYPE_LOOP_BACK_ACK,               "Loop back acknowledgement (national use)"},

  { 37,                                       "Reserved (used in 1984 version)"},
  { 38,                                       "Reserved (used in 1984 version)"},
  { 39,                                       "Reserved (used in 1984 version)"},

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

  { 62,                                       "Unknown"},
  { 63,                                       "Unknown"},

  { MESSAGE_TYPE_LOOP_PREVENTION,             "Loop prevention"},
  { MESSAGE_TYPE_APPLICATION_TRANS,           "Application transport"},
  { MESSAGE_TYPE_PRE_RELEASE_INFO,            "Pre-release information"},
  { MESSAGE_TYPE_SUBSEQUENT_DIR_NUM,          "Subsequent Directory Number (national use)"},
  { RUSSIAN_CLEAR_CALLING_LINE,               "Clear Calling Line"}, /* 252 */
  { RUSSIAN_RINGING,                          "Ringing"},            /* 255 */

  { 0,                                  NULL}};
static value_string_ext russian_isup_message_type_value_ext = VALUE_STRING_EXT_INIT(russian_isup_message_type_value);

/* http://www.ttc.or.jp/jp/document_list/sum/sum_JT-Q763v21.1.pdf */
#define MESSAGE_TYPE_JAPAN_CHARG_INF 254
static const value_string japan_isup_message_type_value[] = {
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

  { 15,                                       "Reserved"},

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

  { 28,                                       "Reserved (used in 1988 version)"},
  { 29,                                       "Reserved (used in 1988 version)"},
  { 30,                                       "Reserved (used in 1988 version)"},

  { MESSAGE_TYPE_FACILITY_REQ,                "Facility request"},
  { MESSAGE_TYPE_FACILITY_ACC,                "Facility accepted"},
  { MESSAGE_TYPE_FACILITY_REJ,                "Facility reject"},

  { 34,                                       "Reserved (used in 1984 version)"},
  { 35,                                       "Reserved (used in 1984 version)"},

  { MESSAGE_TYPE_LOOP_BACK_ACK,               "Loop back acknowledgement (national use)"},

  { 37,                                       "Reserved (used in 1984 version)"},
  { 38,                                       "Reserved (used in 1984 version)"},
  { 39,                                       "Reserved (used in 1984 version)"},

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

  { 62,                                       "Unknown"},
  { 63,                                       "Unknown"},

  { MESSAGE_TYPE_LOOP_PREVENTION,             "Loop prevention"},
  { MESSAGE_TYPE_APPLICATION_TRANS,           "Application transport"},
  { MESSAGE_TYPE_PRE_RELEASE_INFO,            "Pre-release information"},
  { MESSAGE_TYPE_SUBSEQUENT_DIR_NUM,          "Subsequent Directory Number (national use)"},
  { MESSAGE_TYPE_JAPAN_CHARG_INF,             "Charge information"},
  { 0,                                  NULL}};
static value_string_ext japan_isup_message_type_value_ext = VALUE_STRING_EXT_INIT(japan_isup_message_type_value);

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

  { 10,                                       "Reserved"},
  { 11,                                       "Reserved"},

  { MESSAGE_TYPE_RELEASE,                     "REL"},
  { MESSAGE_TYPE_SUSPEND,                     "SUS"},
  { MESSAGE_TYPE_RESUME,                      "RES"},

  { 15,                                       "Reserved"},

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

  { 28,                                       "Reserved"},
  { 29,                                       "Reserved"},
  { 30,                                       "Reserved"},

  { MESSAGE_TYPE_FACILITY_REQ,                "FAR"},
  { MESSAGE_TYPE_FACILITY_ACC,                "FAA"},
  { MESSAGE_TYPE_FACILITY_REJ,                "FRJ"},

  { 34,                                       "Reserved"},
  { 35,                                       "Reserved"},

  { MESSAGE_TYPE_LOOP_BACK_ACK,               "LPA"},

  { 37,                                       "Reserved"},
  { 38,                                       "Reserved"},
  { 39,                                       "Reserved"},

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

  { 62,                                       "Unknown"},
  { 63,                                       "Unknown"},

  { MESSAGE_TYPE_LOOP_PREVENTION,             "LOP"},
  { MESSAGE_TYPE_APPLICATION_TRANS,           "APM"},
  { MESSAGE_TYPE_PRE_RELEASE_INFO,            "PRI"},
  { MESSAGE_TYPE_SUBSEQUENT_DIR_NUM,          "SDN"},
  { 0,                                  NULL}};
value_string_ext isup_message_type_value_acro_ext = VALUE_STRING_EXT_INIT(isup_message_type_value_acro);

static const value_string french_isup_message_type_value_acro[] = {
  { MESSAGE_TYPE_INITIAL_ADDR,                "IAM"},
  { MESSAGE_TYPE_SUBSEQ_ADDR,                 "SAM"},
  { MESSAGE_TYPE_INFO_REQ,                    "INR"},
  { MESSAGE_TYPE_INFO,                        "INF"},
  { MESSAGE_TYPE_CONTINUITY,                  "COT"},
  { MESSAGE_TYPE_ADDR_CMPL,                   "ACM"},
  { MESSAGE_TYPE_CONNECT,                     "CON"},
  { MESSAGE_TYPE_FORW_TRANS,                  "FOT"},
  { MESSAGE_TYPE_ANSWER,                      "ANM"},

  { 10,                                       "Reserved"},
  { 11,                                       "Reserved"},

  { MESSAGE_TYPE_RELEASE,                     "REL"},
  { MESSAGE_TYPE_SUSPEND,                     "SUS"},
  { MESSAGE_TYPE_RESUME,                      "RES"},

  { 15,                                       "Reserved"},

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

  { 28,                                       "Reserved"},
  { 29,                                       "Reserved"},
  { 30,                                       "Reserved"},

  { MESSAGE_TYPE_FACILITY_REQ,                "FAR"},
  { MESSAGE_TYPE_FACILITY_ACC,                "FAA"},
  { MESSAGE_TYPE_FACILITY_REJ,                "FRJ"},

  { 34,                                       "Reserved"},
  { 35,                                       "Reserved"},

  { MESSAGE_TYPE_LOOP_BACK_ACK,               "LPA"},

  { 37,                                       "Reserved"},
  { 38,                                       "Reserved"},
  { 39,                                       "Reserved"},

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

  { 62,                                       "Unknown"},
  { 63,                                       "Unknown"},

  { MESSAGE_TYPE_LOOP_PREVENTION,             "LOP"},
  { MESSAGE_TYPE_APPLICATION_TRANS,           "APM"},
  { MESSAGE_TYPE_PRE_RELEASE_INFO,            "PRI"},
  { MESSAGE_TYPE_SUBSEQUENT_DIR_NUM,          "SDN"},
  { FRENCH_CHARGING_PULSE,                    "CHP"},
  { FRENCH_CHARGING_ACK,                      "CHA"},
  { 0,                                  NULL}};
static value_string_ext french_isup_message_type_value_acro_ext = VALUE_STRING_EXT_INIT(french_isup_message_type_value_acro);

static const value_string israeli_isup_message_type_value_acro[] = {
  { MESSAGE_TYPE_INITIAL_ADDR,                "IAM"},
  { MESSAGE_TYPE_SUBSEQ_ADDR,                 "SAM"},
  { MESSAGE_TYPE_INFO_REQ,                    "INR"},
  { MESSAGE_TYPE_INFO,                        "INF"},
  { MESSAGE_TYPE_CONTINUITY,                  "COT"},
  { MESSAGE_TYPE_ADDR_CMPL,                   "ACM"},
  { MESSAGE_TYPE_CONNECT,                     "CON"},
  { MESSAGE_TYPE_FORW_TRANS,                  "FOT"},
  { MESSAGE_TYPE_ANSWER,                      "ANM"},

  { 10,                                       "Reserved"},
  { 11,                                       "Reserved"},

  { MESSAGE_TYPE_RELEASE,                     "REL"},
  { MESSAGE_TYPE_SUSPEND,                     "SUS"},
  { MESSAGE_TYPE_RESUME,                      "RES"},

  { 15,                                       "Reserved"},

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

  { 28,                                       "Reserved"},
  { 29,                                       "Reserved"},
  { 30,                                       "Reserved"},

  { MESSAGE_TYPE_FACILITY_REQ,                "FAR"},
  { MESSAGE_TYPE_FACILITY_ACC,                "FAA"},
  { MESSAGE_TYPE_FACILITY_REJ,                "FRJ"},

  { 34,                                       "Reserved"},
  { 35,                                       "Reserved"},

  { MESSAGE_TYPE_LOOP_BACK_ACK,               "LPA"},

  { 37,                                       "Reserved"},
  { 38,                                       "Reserved"},
  { 39,                                       "Reserved"},

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

  { 62,                                       "Unknown"},
  { 63,                                       "Unknown"},

  { MESSAGE_TYPE_LOOP_PREVENTION,             "LOP"},
  { MESSAGE_TYPE_APPLICATION_TRANS,           "APM"},
  { MESSAGE_TYPE_PRE_RELEASE_INFO,            "PRI"},
  { MESSAGE_TYPE_SUBSEQUENT_DIR_NUM,          "SDN"},
  { ISRAELI_BACKWARD_CHARGING,                "BCM"},
  { ISRAELI_TRAFFIC_CHANGE,                   "TCM"},
  { ISRAELI_CHARGE_ACK,                       "CAM"},
  { 0,                                  NULL}};
static value_string_ext israeli_isup_message_type_value_acro_ext = VALUE_STRING_EXT_INIT(israeli_isup_message_type_value_acro);

/* Same as above but in acronym form (for the Info column) */
static const value_string russian_isup_message_type_value_acro[] = {
  { MESSAGE_TYPE_INITIAL_ADDR,                "IAM"},
  { MESSAGE_TYPE_SUBSEQ_ADDR,                 "SAM"},
  { MESSAGE_TYPE_INFO_REQ,                    "INR"},
  { MESSAGE_TYPE_INFO,                        "INF"},
  { MESSAGE_TYPE_CONTINUITY,                  "COT"},
  { MESSAGE_TYPE_ADDR_CMPL,                   "ACM"},
  { MESSAGE_TYPE_CONNECT,                     "CON"},
  { MESSAGE_TYPE_FORW_TRANS,                  "FOT"},
  { MESSAGE_TYPE_ANSWER,                      "ANM"},

  { 10,                                       "Reserved"},
  { 11,                                       "Reserved"},

  { MESSAGE_TYPE_RELEASE,                     "REL"},
  { MESSAGE_TYPE_SUSPEND,                     "SUS"},
  { MESSAGE_TYPE_RESUME,                      "RES"},

  { 15,                                       "Reserved"},

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

  { 28,                                       "Reserved"},
  { 29,                                       "Reserved"},
  { 30,                                       "Reserved"},

  { MESSAGE_TYPE_FACILITY_REQ,                "FAR"},
  { MESSAGE_TYPE_FACILITY_ACC,                "FAA"},
  { MESSAGE_TYPE_FACILITY_REJ,                "FRJ"},

  { 34,                                       "Reserved"},
  { 35,                                       "Reserved"},

  { MESSAGE_TYPE_LOOP_BACK_ACK,               "LPA"},

  { 37,                                       "Reserved"},
  { 38,                                       "Reserved"},
  { 39,                                       "Reserved"},

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

  { 62,                                       "Unknown"},
  { 63,                                       "Unknown"},

  { MESSAGE_TYPE_LOOP_PREVENTION,             "LOP"},
  { MESSAGE_TYPE_APPLICATION_TRANS,           "APM"},
  { MESSAGE_TYPE_PRE_RELEASE_INFO,            "PRI"},
  { MESSAGE_TYPE_SUBSEQUENT_DIR_NUM,          "SDN"},
  { RUSSIAN_CLEAR_CALLING_LINE,               "CCL"},  /* 252 */
  { RUSSIAN_RINGING,                          "RNG"},  /* 255 */
  { 0,                                  NULL}};
static value_string_ext russian_isup_message_type_value_acro_ext = VALUE_STRING_EXT_INIT(russian_isup_message_type_value_acro);

static const value_string japan_isup_message_type_value_acro[] = {
  { MESSAGE_TYPE_INITIAL_ADDR,                "IAM"},
  { MESSAGE_TYPE_SUBSEQ_ADDR,                 "SAM"},
  { MESSAGE_TYPE_INFO_REQ,                    "INR"},
  { MESSAGE_TYPE_INFO,                        "INF"},
  { MESSAGE_TYPE_CONTINUITY,                  "COT"},
  { MESSAGE_TYPE_ADDR_CMPL,                   "ACM"},
  { MESSAGE_TYPE_CONNECT,                     "CON"},
  { MESSAGE_TYPE_FORW_TRANS,                  "FOT"},
  { MESSAGE_TYPE_ANSWER,                      "ANM"},

  { 10,                                       "Reserved"},
  { 11,                                       "Reserved"},

  { MESSAGE_TYPE_RELEASE,                     "REL"},
  { MESSAGE_TYPE_SUSPEND,                     "SUS"},
  { MESSAGE_TYPE_RESUME,                      "RES"},

  { 15,                                       "Reserved"},

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

  { 28,                                       "Reserved"},
  { 29,                                       "Reserved"},
  { 30,                                       "Reserved"},

  { MESSAGE_TYPE_FACILITY_REQ,                "FAR"},
  { MESSAGE_TYPE_FACILITY_ACC,                "FAA"},
  { MESSAGE_TYPE_FACILITY_REJ,                "FRJ"},

  { 34,                                       "Reserved"},
  { 35,                                       "Reserved"},

  { MESSAGE_TYPE_LOOP_BACK_ACK,               "LPA"},

  { 37,                                       "Reserved"},
  { 38,                                       "Reserved"},
  { 39,                                       "Reserved"},

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

  { 62,                                       "Unknown"},
  { 63,                                       "Unknown"},

  { MESSAGE_TYPE_LOOP_PREVENTION,             "LOP"},
  { MESSAGE_TYPE_APPLICATION_TRANS,           "APM"},
  { MESSAGE_TYPE_PRE_RELEASE_INFO,            "PRI"},
  { MESSAGE_TYPE_SUBSEQUENT_DIR_NUM,          "SDN"},
  { MESSAGE_TYPE_JAPAN_CHARG_INF,             "CHG"},  /* 254 */
  { 0,                                  NULL}};
static value_string_ext japan_isup_message_type_value_acro_ext = VALUE_STRING_EXT_INIT(japan_isup_message_type_value_acro);

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

/* Table 5/Q.763 */
const value_string isup_parameter_type_value[] = {
/*   0 */  { PARAM_TYPE_END_OF_OPT_PARAMS,         "End of optional parameters"},
/*   1 */  { PARAM_TYPE_CALL_REF,                  "Call Reference (national use)"},
/*   2 */  { PARAM_TYPE_TRANSM_MEDIUM_REQU,        "Transmission medium requirement"},
/*   3 */  { PARAM_TYPE_ACC_TRANSP,                "Access transport"},
/*   4 */  { PARAM_TYPE_CALLED_PARTY_NR,           "Called party number"},
/*   5 */  { PARAM_TYPE_SUBSQT_NR,                 "Subsequent number"},
/*   6 */  { PARAM_TYPE_NATURE_OF_CONN_IND,        "Nature of connection indicators"},
/*   7 */  { PARAM_TYPE_FORW_CALL_IND,             "Forward call indicators"},
/*   8 */  { PARAM_TYPE_OPT_FORW_CALL_IND,         "Optional forward call indicators"},
/*   9 */  { PARAM_TYPE_CALLING_PRTY_CATEG,        "Calling party's category"},
/*  10 */  { PARAM_TYPE_CALLING_PARTY_NR,          "Calling party number"},
/*  11 */  { PARAM_TYPE_REDIRECTING_NR,            "Redirecting number"},
/*  12 */  { PARAM_TYPE_REDIRECTION_NR,            "Redirection number"},
/*  13 */  { PARAM_TYPE_CONNECTION_REQ,            "Connection request"},
/*  14 */  { PARAM_TYPE_INFO_REQ_IND,              "Information request indicators (national use)"},
/*  15 */  { PARAM_TYPE_INFO_IND,                  "Information indicators (national use)"},
/*  16 */  { PARAM_TYPE_CONTINUITY_IND,            "Continuity request"},
/*  17 */  { PARAM_TYPE_BACKW_CALL_IND,            "Backward call indicators"},
/*  18 */  { PARAM_TYPE_CAUSE_INDICATORS,          "Cause indicators"},
/*  19 */  { PARAM_TYPE_REDIRECTION_INFO,          "Redirection information"},
/*  20 */  { 20,                                   "Not used"},
/*  21 */  { PARAM_TYPE_CIRC_GRP_SV_MSG_TYPE,      "Circuit group supervision message type"},
/*  22 */  { PARAM_TYPE_RANGE_AND_STATUS,          "Range and Status"},
/*  23 */  { 23,                                   "Not used"},
/*  24 */  { PARAM_TYPE_FACILITY_IND,              "Facility indicator"},
/*  25 */  { 25,                                   "Not used"},
/*  26 */  { PARAM_TYPE_CLSD_USR_GRP_ILOCK_CD,     "Closed user group interlock code"},
/*  27 */  { 27,                                   "Not used"},
/*  28 */  { 28,                                   "Not used"},
/*  29 */  { PARAM_TYPE_USER_SERVICE_INFO,         "User service information"},
/*  30 */  { PARAM_TYPE_SIGNALLING_POINT_CODE,     "Signalling point code (national use)"},
/*  31 */  { 31,                                   "Not used"},
/*  32 */  { PARAM_TYPE_USER_TO_USER_INFO,         "User-to-user information"},
/*  33 */  { PARAM_TYPE_CONNECTED_NR,              "Connected number"},
/*  34 */  { PARAM_TYPE_SUSP_RESUME_IND,           "Suspend/Resume indicators"},
/*  35 */  { PARAM_TYPE_TRANSIT_NETW_SELECT,       "Transit network selection (national use)"},
/*  36 */  { PARAM_TYPE_EVENT_INFO,                "Event information"},
/*  37 */  { PARAM_TYPE_CIRC_ASSIGN_MAP,           "Circuit assignment map"},
/*  38 */  { PARAM_TYPE_CIRC_STATE_IND,            "Circuit state indicator (national use)"},
/*  39 */  { PARAM_TYPE_AUTO_CONG_LEVEL,           "Automatic congestion level"},
/*  40 */  { PARAM_TYPE_ORIG_CALLED_NR,            "Original called number"},
/*  41 */  { PARAM_TYPE_OPT_BACKW_CALL_IND,        "Backward call indicators"},
/*  42 */  { PARAM_TYPE_USER_TO_USER_IND,          "User-to-user indicators"},
/*  43 */  { PARAM_TYPE_ORIG_ISC_POINT_CODE,       "Origination ISC point code"},
/*  44 */  { PARAM_TYPE_GENERIC_NOTIF_IND,         "Generic notification indicator"},
/*  45 */  { PARAM_TYPE_CALL_HIST_INFO,            "Call history information"},
/*  46 */  { PARAM_TYPE_ACC_DELIV_INFO,            "Access delivery information"},
/*  47 */  { PARAM_TYPE_NETW_SPECIFIC_FACLTY,      "Network specific facility (national use)"},
/*  48 */  { PARAM_TYPE_USER_SERVICE_INFO_PR,      "User service information prime"},
/*  49 */  { PARAM_TYPE_PROPAG_DELAY_COUNTER,      "Propagation delay counter"},
/*  50 */  { PARAM_TYPE_REMOTE_OPERATIONS,         "Remote operations (national use)"},
/*  51 */  { PARAM_TYPE_SERVICE_ACTIVATION,        "Service activation"},
/*  52 */  { PARAM_TYPE_USER_TELESERV_INFO,        "User teleservice information"},
/*  53 */  { PARAM_TYPE_TRANSM_MEDIUM_USED,        "Transmission medium used"},
/*  54 */  { PARAM_TYPE_CALL_DIV_INFO,             "Call diversion information"},
/*  55 */  { PARAM_TYPE_ECHO_CTRL_INFO,            "Echo control information"},
/*  56 */  { PARAM_TYPE_MSG_COMPAT_INFO,           "Message compatibility information"},
/*  57 */  { PARAM_TYPE_PARAM_COMPAT_INFO,         "Parameter compatibility information"},
/*  58 */  { PARAM_TYPE_MLPP_PRECEDENCE,           "MLPP precedence"},
/*  59 */  { PARAM_TYPE_MCID_REQ_IND,              "MCID request indicators"},
/*  60 */  { PARAM_TYPE_MCID_RSP_IND,              "MCID response indicators"},
/*  61 */  { PARAM_TYPE_HOP_COUNTER,               "Hop counter"},
/*  62 */  { PARAM_TYPE_TRANSM_MEDIUM_RQUR_PR,     "Transmission medium requirement prime"},
/*  63 */  { PARAM_TYPE_LOCATION_NR,               "Location number"},
/*  64 */  { PARAM_TYPE_REDIR_NR_RSTRCT,           "Redirection number restriction"},
/*  65 */  { 65,                                   "Not used"},
/*  66 */  { 66,                                   "Not used"},
/*  67 */  { PARAM_TYPE_CALL_TRANS_REF,            "Call transfer reference"},
/*  68 */  { PARAM_TYPE_LOOP_PREV_IND,             "Loop prevention indicators"},
/*  69 */  { PARAM_TYPE_CALL_TRANS_NR,             "Call transfer number"},
/*  70 */  { 70,                                   "Not used"},
/*  71 */  { 71,                                   "Not used"},
/*  72 */  { 72,                                   "Not used"},
/*  73 */  { 73,                                   "Not used"},
/*  74 */  { 74,                                   "Not used"},
/*  75 */  { PARAM_TYPE_CCSS,                      "CCSS"},
/*  76 */  { PARAM_TYPE_FORW_GVNS,                 "Forward GVNS"},
/*  77 */  { PARAM_TYPE_BACKW_GVNS,                "Backward GVNS"},
/*  78 */  { PARAM_TYPE_REDIRECT_CAPAB,            "Redirect capability (reserved for national use)"},
/*  79 */  { 79,                                   "Not used"},
/*  80 */  { 80,                                   "Not used"},
/*  81 */  { 81,                                   "Not used"},
/*  82 */  { 82,                                   "Not used"},
/*  83 */  { 83,                                   "Not used"},
/*  84 */  { 84,                                   "Not used"},
/*  85 */  { 85,                                   "Not used"},
/*  86 */  { 86,                                   "Not used"},
/*  87 */  { 87,                                   "Not used"},
/*  88 */  { 88,                                   "Not used"},
/*  89 */  { 89,                                   "Not used"},
/*  90 */  { 90,                                   "Not used"},
/*  91 */  { PARAM_TYPE_NETW_MGMT_CTRL,            "Network management controls"},
/*  92 */  { 92,                                   "Not used"},
/*  93 */  { 93,                                   "Not used"},
/*  94 */  { 94,                                   "Not used"},
/*  95 */  { 95,                                   "Not used"},
/*  96 */  { 96,                                   "Not used"},
/*  97 */  { 97,                                   "Not used"},
/*  98 */  { 98,                                   "Not used"},
/*  99 */  { 99,                                   "Not used"},
/* 100 */  { 100,                                  "Not used"},
/* 101 */  { PARAM_TYPE_CORRELATION_ID,            "Correlation id"},
/* 102 */  { PARAM_TYPE_SCF_ID,                    "SCF id"},
/* 103 */  { 103,                                  "Not used"},
/* 104 */  { 104,                                  "Not used"},
/* 105 */  { 105,                                  "Not used"},
/* 106 */  { 106,                                  "Not used"},
/* 107 */  { 107,                                  "Not used"},
/* 108 */  { 108,                                  "Not used"},
/* 109 */  { 109,                                  "Not used"},
/* 110 */  { PARAM_TYPE_CALL_DIV_TREAT_IND,        "Call diversion treatment indicators"},
/* 111 */  { PARAM_TYPE_CALLED_IN_NR,              "Called IN number"},
/* 112 */  { PARAM_TYPE_CALL_OFF_TREAT_IND,        "Call offering treatment indicators"},
/* 113 */  { PARAM_TYPE_CHARGED_PARTY_IDENT,       "Charged party identification (national use)"},
/* 114 */  { PARAM_TYPE_CONF_TREAT_IND,            "Conference treatment indicators"},
/* 115 */  { PARAM_TYPE_DISPLAY_INFO,              "Display information"},
/* 116 */  { PARAM_TYPE_UID_ACTION_IND,            "UID action indicators"},
/* 117 */  { PARAM_TYPE_UID_CAPAB_IND,             "UID capability indicators"},
/* 119 */  { PARAM_TYPE_REDIRECT_COUNTER,          "Redirect counter (reserved for national use)"},
/* 120 */  { PARAM_TYPE_APPLICATON_TRANS,          "Application transport"},
/* 121 */  { PARAM_TYPE_COLLECT_CALL_REQ,          "Collect call request"},
/* 122 */  { 122,                                  "Not used"},
/* 123 */  { 123,                                  "Not used"},
/* 124 */  { 124,                                  "Not used"},
/* 125 */  { 125,                                  "Not used"},
/* 126 */  { 126,                                  "Not used"},
/* 127 */  { 127,                                  "Not used"},
/* 128 */  { 128,                                  "Not used"},
/* 129 */  { 129,                                  "Not used"},
/* 130 */  { 130,                                  "Not used"},
/* 142 */  { 142,                                  "Forward CAT indicators"},   /* Q.763 Amendment 6(10/2009) */
/* 143 */  { 143,                                  "Backward CAT indicators"},  /* Q.763 Amendment 6(10/2009) */
/* 150 */  { 150,                                  "Automatic re-routing" },    /* Q.763 Amendment 3(04/2004) */
/* 166 */  { 166,                                  "IEPS call information" },   /* Q.763 Amendment 4(01/2006) */
/* 168 */  { 168,                                  "VED information" },         /* Q.763 Amendment 5(09/2006) */
/* 192 */  { PARAM_TYPE_GENERIC_NR,                "Generic number"},
/* 193 */  { PARAM_TYPE_GENERIC_DIGITS,            "Generic digits (national use)"},
  { 0,                                 NULL}};
static value_string_ext isup_parameter_type_value_ext = VALUE_STRING_EXT_INIT(isup_parameter_type_value);

#define JAPAN_ISUP_PARAM_CALLED_DIRECTORY_NUMBER         125 /* 7D */
#define JAPAN_ISUP_PARAM_REDIRECT_FORWARD_INF            139 /* 8B */
#define JAPAN_ISUP_PARAM_REDIRECT_BACKWARD_INF           140 /* 8C */
#define JAPAN_ISUP_PARAM_EMERGENCY_CALL_IND              215 /* D7 */
#define JAPAN_ISUP_PARAM_EMERGENCY_CALL_INF_IND          236 /* EC */
#define JAPAN_ISUP_PARAM_NETWORK_POI_CA                  238 /* EE */
#define JAPAN_ISUP_PARAM_TYPE_CARRIER_INFO               241 /* F1 */
#define JAPAN_ISUP_PARAM_CHARGE_INF_DELAY                242 /* F2 */

#define JAPAN_ISUP_PARAM_TYPE_ADDITONAL_USER_CAT         243 /* F3 */
#define JAPAN_ISUP_PARAM_REASON_FOR_CLIP_FAIL            245 /* F5 */
#define JAPAN_ISUP_PARAM_TYPE_CONTRACTOR_NUMBER          249 /* F9 */
#define JAPAN_ISUP_PARAM_TYPE_CHARGE_INF_TYPE            250 /* FA */
#define JAPAN_ISUP_PARAM_TYPE_CHARGE_INF                 251 /* FB */
#define JAPAN_ISUP_PARAM_TYPE_CHARGE_AREA_INFO           253 /* FD */

static const value_string japan_isup_parameter_type_value[] = {
/*   0 */  { PARAM_TYPE_END_OF_OPT_PARAMS,         "End of optional parameters"},
/*   1 */  { PARAM_TYPE_CALL_REF,                  "Call Reference (national use)"},
/*   2 */  { PARAM_TYPE_TRANSM_MEDIUM_REQU,        "Transmission medium requirement"},
/*   3 */  { PARAM_TYPE_ACC_TRANSP,                "Access transport"},
/*   4 */  { PARAM_TYPE_CALLED_PARTY_NR,           "Called party number"},
/*   5 */  { PARAM_TYPE_SUBSQT_NR,                 "Subsequent number"},
/*   6 */  { PARAM_TYPE_NATURE_OF_CONN_IND,        "Nature of connection indicators"},
/*   7 */  { PARAM_TYPE_FORW_CALL_IND,             "Forward call indicators"},
/*   8 */  { PARAM_TYPE_OPT_FORW_CALL_IND,         "Optional forward call indicators"},
/*   9 */  { PARAM_TYPE_CALLING_PRTY_CATEG,        "Calling party's category"},
/*  10 */  { PARAM_TYPE_CALLING_PARTY_NR,          "Calling party number"},
/*  11 */  { PARAM_TYPE_REDIRECTING_NR,            "Redirecting number"},
/*  12 */  { PARAM_TYPE_REDIRECTION_NR,            "Redirection number"},
/*  13 */  { PARAM_TYPE_CONNECTION_REQ,            "Connection request"},
/*  14 */  { PARAM_TYPE_INFO_REQ_IND,              "Information request indicators (national use)"},
/*  15 */  { PARAM_TYPE_INFO_IND,                  "Information indicators (national use)"},
/*  16 */  { PARAM_TYPE_CONTINUITY_IND,            "Continuity request"},
/*  17 */  { PARAM_TYPE_BACKW_CALL_IND,            "Backward call indicators"},
/*  18 */  { PARAM_TYPE_CAUSE_INDICATORS,          "Cause indicators"},
/*  19 */  { PARAM_TYPE_REDIRECTION_INFO,          "Redirection information"},
/*  20 */  { 20,                                   "Not used"},
/*  21 */  { PARAM_TYPE_CIRC_GRP_SV_MSG_TYPE,      "Circuit group supervision message type"},
/*  22 */  { PARAM_TYPE_RANGE_AND_STATUS,          "Range and Status"},
/*  23 */  { 23,                                   "Not used"},
/*  24 */  { PARAM_TYPE_FACILITY_IND,              "Facility indicator"},
/*  25 */  { 25,                                   "Not used"},
/*  26 */  { PARAM_TYPE_CLSD_USR_GRP_ILOCK_CD,     "Closed user group interlock code"},
/*  27 */  { 27,                                   "Not used"},
/*  28 */  { 28,                                   "Not used"},
/*  29 */  { PARAM_TYPE_USER_SERVICE_INFO,         "User service information"},
/*  30 */  { PARAM_TYPE_SIGNALLING_POINT_CODE,     "Signalling point code (national use)"},
/*  31 */  { 31,                                   "Not used"},
/*  32 */  { PARAM_TYPE_USER_TO_USER_INFO,         "User-to-user information"},
/*  33 */  { PARAM_TYPE_CONNECTED_NR,              "Connected number"},
/*  34 */  { PARAM_TYPE_SUSP_RESUME_IND,           "Suspend/Resume indicators"},
/*  35 */  { PARAM_TYPE_TRANSIT_NETW_SELECT,       "Transit network selection (national use)"},
/*  36 */  { PARAM_TYPE_EVENT_INFO,                "Event information"},
/*  37 */  { PARAM_TYPE_CIRC_ASSIGN_MAP,           "Circuit assignment map"},
/*  38 */  { PARAM_TYPE_CIRC_STATE_IND,            "Circuit state indicator (national use)"},
/*  39 */  { PARAM_TYPE_AUTO_CONG_LEVEL,           "Automatic congestion level"},
/*  40 */  { PARAM_TYPE_ORIG_CALLED_NR,            "Original called number"},
/*  41 */  { PARAM_TYPE_OPT_BACKW_CALL_IND,        "Backward call indicators"},
/*  42 */  { PARAM_TYPE_USER_TO_USER_IND,          "User-to-user indicators"},
/*  43 */  { PARAM_TYPE_ORIG_ISC_POINT_CODE,       "Origination ISC point code"},
/*  44 */  { PARAM_TYPE_GENERIC_NOTIF_IND,         "Generic notification indicator"},
/*  45 */  { PARAM_TYPE_CALL_HIST_INFO,            "Call history information"},
/*  46 */  { PARAM_TYPE_ACC_DELIV_INFO,            "Access delivery information"},
/*  47 */  { PARAM_TYPE_NETW_SPECIFIC_FACLTY,      "Network specific facility (national use)"},
/*  48 */  { PARAM_TYPE_USER_SERVICE_INFO_PR,      "User service information prime"},
/*  49 */  { PARAM_TYPE_PROPAG_DELAY_COUNTER,      "Propagation delay counter"},
/*  50 */  { PARAM_TYPE_REMOTE_OPERATIONS,         "Remote operations (national use)"},
/*  51 */  { PARAM_TYPE_SERVICE_ACTIVATION,        "Service activation"},
/*  52 */  { PARAM_TYPE_USER_TELESERV_INFO,        "User teleservice information"},
/*  53 */  { PARAM_TYPE_TRANSM_MEDIUM_USED,        "Transmission medium used"},
/*  54 */  { PARAM_TYPE_CALL_DIV_INFO,             "Call diversion information"},
/*  55 */  { PARAM_TYPE_ECHO_CTRL_INFO,            "Echo control information"},
/*  56 */  { PARAM_TYPE_MSG_COMPAT_INFO,           "Message compatibility information"},
/*  57 */  { PARAM_TYPE_PARAM_COMPAT_INFO,         "Parameter compatibility information"},
/*  58 */  { PARAM_TYPE_MLPP_PRECEDENCE,           "MLPP precedence"},
/*  59 */  { PARAM_TYPE_MCID_REQ_IND,              "MCID request indicators"},
/*  60 */  { PARAM_TYPE_MCID_RSP_IND,              "MCID response indicators"},
/*  61 */  { PARAM_TYPE_HOP_COUNTER,               "Hop counter"},
/*  62 */  { PARAM_TYPE_TRANSM_MEDIUM_RQUR_PR,     "Transmission medium requirement prime"},
/*  63 */  { PARAM_TYPE_LOCATION_NR,               "Location number"},
/*  64 */  { PARAM_TYPE_REDIR_NR_RSTRCT,           "Redirection number restriction"},
/*  65 */  { 65,                                   "Not used"},
/*  66 */  { 66,                                   "Not used"},
/*  67 */  { PARAM_TYPE_CALL_TRANS_REF,            "Call transfer reference"},
/*  68 */  { PARAM_TYPE_LOOP_PREV_IND,             "Loop prevention indicators"},
/*  69 */  { PARAM_TYPE_CALL_TRANS_NR,             "Call transfer number"},
/*  70 */  { 70,                                   "Not used"},
/*  71 */  { 71,                                   "Not used"},
/*  72 */  { 72,                                   "Not used"},
/*  73 */  { 73,                                   "Not used"},
/*  74 */  { 74,                                   "Not used"},
/*  75 */  { PARAM_TYPE_CCSS,                      "CCSS"},
/*  76 */  { PARAM_TYPE_FORW_GVNS,                 "Forward GVNS"},
/*  77 */  { PARAM_TYPE_BACKW_GVNS,                "Backward GVNS"},
/*  78 */  { PARAM_TYPE_REDIRECT_CAPAB,            "Redirect capability (reserved for national use)"},
/*  79 */  { 79,                                   "Not used"},
/*  80 */  { 80,                                   "Not used"},
/*  81 */  { 81,                                   "Not used"},
/*  82 */  { 82,                                   "Not used"},
/*  83 */  { 83,                                   "Not used"},
/*  84 */  { 84,                                   "Not used"},
/*  85 */  { 85,                                   "Not used"},
/*  86 */  { 86,                                   "Not used"},
/*  87 */  { 87,                                   "Not used"},
/*  88 */  { 88,                                   "Not used"},
/*  89 */  { 89,                                   "Not used"},
/*  90 */  { 90,                                   "Not used"},
/* 101 */  { PARAM_TYPE_CORRELATION_ID,            "Correlation id"},
/* 102 */  { PARAM_TYPE_SCF_ID,                    "SCF id"},
/* 103 */  { 103,                                  "Not used"},
/* 104 */  { 104,                                  "Not used"},
/* 105 */  { 105,                                  "Not used"},
/* 106 */  { 106,                                  "Not used"},
/* 107 */  { 107,                                  "Not used"},
/* 108 */  { 108,                                  "Not used"},
/* 109 */  { 109,                                  "Not used"},
/* 110 */  { PARAM_TYPE_CALL_DIV_TREAT_IND,        "Call diversion treatment indicators"},
/* 111 */  { PARAM_TYPE_CALLED_IN_NR,              "Called IN number"},
/* 112 */  { PARAM_TYPE_CALL_OFF_TREAT_IND,        "Call offering treatment indicators"},
/* 113 */  { PARAM_TYPE_CHARGED_PARTY_IDENT,       "Charged party identification (national use)"},
/* 114 */  { PARAM_TYPE_CONF_TREAT_IND,            "Conference treatment indicators"},
/* 115 */  { PARAM_TYPE_DISPLAY_INFO,              "Display information"},
/* 116 */  { PARAM_TYPE_UID_ACTION_IND,            "UID action indicators"},
/* 117 */  { PARAM_TYPE_UID_CAPAB_IND,             "UID capability indicators"},
/* 119 */  { PARAM_TYPE_REDIRECT_COUNTER,          "Redirect counter (reserved for national use)"},
/* 120 */  { PARAM_TYPE_APPLICATON_TRANS,          "Application transport"},
/* 121 */  { PARAM_TYPE_COLLECT_CALL_REQ,          "Collect call request"},
/* 122 */  { 122,                                  "Not used"},
/* 123 */  { 123,                                  "Not used"},
/* 124 */  { 124,                                  "Not used"},
/* 125 */  { JAPAN_ISUP_PARAM_CALLED_DIRECTORY_NUMBER, "Called Directory Number"},     /* 125 7D */
/* 126 */  { 126,                                  "Not used"},
/* 127 */  { 127,                                  "Not used"},
/* 128 */  { 128,                                  "Not used"},
/* 129 */  { 129,                                  "Not used"},
/* 130 */  { 130,                                  "Not used"},
/* 131 */  { 131,                                  "Not used"},
/* 132 */  { 132,                                  "Not used"},
/* 133 */  { 133,                                  "Not used"},
/* 134 */  { 134,                                  "Not used"},
/* 135 */  { 135,                                  "Not used"},
/* 136 */  { 136,                                  "Not used"},
/* 137 */  { 137,                                  "Not used"},
/* 138 */  { 138,                                  "Not used"},
/* 139 */  { JAPAN_ISUP_PARAM_REDIRECT_FORWARD_INF,    "Redirect forward information"},         /* 8B */
/* 140 */  { JAPAN_ISUP_PARAM_REDIRECT_BACKWARD_INF,   "Redirect Backward information"},        /* 8C */

/* 192 */  { PARAM_TYPE_GENERIC_NR,                "Generic number"},
/* 193 */  { PARAM_TYPE_GENERIC_DIGITS,            "Generic digits (national use)"},
  { JAPAN_ISUP_PARAM_EMERGENCY_CALL_IND,      "Emergency Call indicator"},             /* 215 EC */
  { JAPAN_ISUP_PARAM_EMERGENCY_CALL_INF_IND,  "Emergency Call Information indicator"}, /* 236 EC */
  { JAPAN_ISUP_PARAM_NETWORK_POI_CA,          "Network POI-CA"},                       /* 238 EE */
  { JAPAN_ISUP_PARAM_TYPE_CARRIER_INFO,       "Carrier Information transfer"},         /* 241 F1 */
  { JAPAN_ISUP_PARAM_CHARGE_INF_DELAY,        "Charge Information Delay"},             /* 242 F2 */
  { JAPAN_ISUP_PARAM_TYPE_ADDITONAL_USER_CAT, "Additional party's category"},          /* 243 F3 */
  { JAPAN_ISUP_PARAM_REASON_FOR_CLIP_FAIL,    "Reason For CLIP Failure"},              /* 245 F5 */
  { JAPAN_ISUP_PARAM_TYPE_CONTRACTOR_NUMBER,  "Contractor Number"},                    /* 249 F9 */
  { JAPAN_ISUP_PARAM_TYPE_CHARGE_INF_TYPE,    "Charge information type"},              /* 250 FA */
  { JAPAN_ISUP_PARAM_TYPE_CHARGE_INF,         "Charge information"},                   /* 250 FA */
  { JAPAN_ISUP_PARAM_TYPE_CHARGE_AREA_INFO,   "Charge area information"},              /* 253 FD */

  { 0,                                 NULL}};
static value_string_ext japan_isup_parameter_type_value_ext = VALUE_STRING_EXT_INIT(japan_isup_parameter_type_value);

static const value_string ansi_isup_parameter_type_value[] = {
/*   0 */  { PARAM_TYPE_END_OF_OPT_PARAMS,         "End of optional parameters"},
/*   1 */  { PARAM_TYPE_CALL_REF,                  "Call Reference (national use)"},
/*   2 */  { PARAM_TYPE_TRANSM_MEDIUM_REQU,        "Transmission medium requirement"},
/*   3 */  { PARAM_TYPE_ACC_TRANSP,                "Access transport"},
/*   4 */  { PARAM_TYPE_CALLED_PARTY_NR,           "Called party number"},
/*   5 */  { PARAM_TYPE_SUBSQT_NR,                 "Subsequent number"},
/*   6 */  { PARAM_TYPE_NATURE_OF_CONN_IND,        "Nature of connection indicators"},
/*   7 */  { PARAM_TYPE_FORW_CALL_IND,             "Forward call indicators"},
/*   8 */  { PARAM_TYPE_OPT_FORW_CALL_IND,         "Optional forward call indicators"},
/*   9 */  { PARAM_TYPE_CALLING_PRTY_CATEG,        "Calling party's category"},
/*  10 */  { PARAM_TYPE_CALLING_PARTY_NR,          "Calling party number"},
/*  11 */  { PARAM_TYPE_REDIRECTING_NR,            "Redirecting number"},
/*  12 */  { PARAM_TYPE_REDIRECTION_NR,            "Redirection number"},
/*  13 */  { PARAM_TYPE_CONNECTION_REQ,            "Connection request"},
/*  14 */  { PARAM_TYPE_INFO_REQ_IND,              "Information request indicators (national use)"},
/*  15 */  { PARAM_TYPE_INFO_IND,                  "Information indicators (national use)"},
/*  16 */  { PARAM_TYPE_CONTINUITY_IND,            "Continuity request"},
/*  17 */  { PARAM_TYPE_BACKW_CALL_IND,            "Backward call indicators"},
/*  18 */  { PARAM_TYPE_CAUSE_INDICATORS,          "Cause indicators"},
/*  19 */  { PARAM_TYPE_REDIRECTION_INFO,          "Redirection information"},
/*  20 */  { 20,                                   "Not used"},
/*  21 */  { PARAM_TYPE_CIRC_GRP_SV_MSG_TYPE,      "Circuit group supervision message type"},
/*  22 */  { PARAM_TYPE_RANGE_AND_STATUS,          "Range and Status"},
/*  23 */  { 23,                                   "Not used"},
/*  24 */  { PARAM_TYPE_FACILITY_IND,              "Facility indicator"},
/*  25 */  { 25,                                   "Not used"},
/*  26 */  { PARAM_TYPE_CLSD_USR_GRP_ILOCK_CD,     "Closed user group interlock code"},
/*  27 */  { 27,                                   "Not used"},
/*  28 */  { 28,                                   "Not used"},
/*  29 */  { PARAM_TYPE_USER_SERVICE_INFO,         "User service information"},
/*  30 */  { PARAM_TYPE_SIGNALLING_POINT_CODE,     "Signalling point code (national use)"},
/*  31 */  { 31,                                   "Not used"},
/*  32 */  { PARAM_TYPE_USER_TO_USER_INFO,         "User-to-user information"},
/*  33 */  { PARAM_TYPE_CONNECTED_NR,              "Connected number"},
/*  34 */  { PARAM_TYPE_SUSP_RESUME_IND,           "Suspend/Resume indicators"},
/*  35 */  { PARAM_TYPE_TRANSIT_NETW_SELECT,       "Transit network selection (national use)"},
/*  36 */  { PARAM_TYPE_EVENT_INFO,                "Event information"},
/*  37 */  { PARAM_TYPE_CIRC_ASSIGN_MAP,           "Circuit assignment map"},
/*  38 */  { PARAM_TYPE_CIRC_STATE_IND,            "Circuit state indicator (national use)"},
/*  39 */  { PARAM_TYPE_AUTO_CONG_LEVEL,           "Automatic congestion level"},
/*  40 */  { PARAM_TYPE_ORIG_CALLED_NR,            "Original called number"},
/*  41 */  { PARAM_TYPE_OPT_BACKW_CALL_IND,        "Backward call indicators"},
/*  42 */  { PARAM_TYPE_USER_TO_USER_IND,          "User-to-user indicators"},
/*  43 */  { PARAM_TYPE_ORIG_ISC_POINT_CODE,       "Origination ISC point code"},
/*  44 */  { PARAM_TYPE_GENERIC_NOTIF_IND,         "Generic notification indicator"},
/*  45 */  { PARAM_TYPE_CALL_HIST_INFO,            "Call history information"},
/*  46 */  { PARAM_TYPE_ACC_DELIV_INFO,            "Access delivery information"},
/*  47 */  { PARAM_TYPE_NETW_SPECIFIC_FACLTY,      "Network specific facility (national use)"},
/*  48 */  { PARAM_TYPE_USER_SERVICE_INFO_PR,      "User service information prime"},
/*  49 */  { PARAM_TYPE_PROPAG_DELAY_COUNTER,      "Propagation delay counter"},
/*  50 */  { PARAM_TYPE_REMOTE_OPERATIONS,         "Remote operations (national use)"},
/*  51 */  { PARAM_TYPE_SERVICE_ACTIVATION,        "Service activation"},
/*  52 */  { PARAM_TYPE_USER_TELESERV_INFO,        "User teleservice information"},
/*  53 */  { PARAM_TYPE_TRANSM_MEDIUM_USED,        "Transmission medium used"},
/*  54 */  { PARAM_TYPE_CALL_DIV_INFO,             "Call diversion information"},
/*  55 */  { PARAM_TYPE_ECHO_CTRL_INFO,            "Echo control information"},
/*  56 */  { PARAM_TYPE_MSG_COMPAT_INFO,           "Message compatibility information"},
/*  57 */  { PARAM_TYPE_PARAM_COMPAT_INFO,         "Parameter compatibility information"},
/*  58 */  { PARAM_TYPE_MLPP_PRECEDENCE,           "MLPP precedence"},
/*  59 */  { PARAM_TYPE_MCID_REQ_IND,              "MCID request indicators"},
/*  60 */  { PARAM_TYPE_MCID_RSP_IND,              "MCID response indicators"},
/*  61 */  { PARAM_TYPE_HOP_COUNTER,               "Hop counter"},
/*  62 */  { PARAM_TYPE_TRANSM_MEDIUM_RQUR_PR,     "Transmission medium requirement prime"},
/*  63 */  { PARAM_TYPE_LOCATION_NR,               "Location number"},
/*  64 */  { PARAM_TYPE_REDIR_NR_RSTRCT,           "Redirection number restriction"},
/*  65 */  { 65,                                   "Not used"},
/*  66 */  { 66,                                   "Not used"},
/*  67 */  { PARAM_TYPE_CALL_TRANS_REF,            "Call transfer reference"},
/*  68 */  { PARAM_TYPE_LOOP_PREV_IND,             "Loop prevention indicators"},
/*  69 */  { PARAM_TYPE_CALL_TRANS_NR,             "Call transfer number"},
/*  70 */  { 70,                                   "Not used"},
/*  71 */  { 71,                                   "Not used"},
/*  72 */  { 72,                                   "Not used"},
/*  73 */  { 73,                                   "Not used"},
/*  74 */  { 74,                                   "Not used"},
/*  75 */  { PARAM_TYPE_CCSS,                      "CCSS"},
/*  76 */  { PARAM_TYPE_FORW_GVNS,                 "Forward GVNS"},
/*  77 */  { PARAM_TYPE_BACKW_GVNS,                "Backward GVNS"},
/*  78 */  { PARAM_TYPE_REDIRECT_CAPAB,            "Redirect capability (reserved for national use)"},
/*  79 */  { 79,                                   "Not used"},
/*  80 */  { 80,                                   "Not used"},
/*  81 */  { 81,                                   "Not used"},
/*  82 */  { 82,                                   "Not used"},
/*  83 */  { 83,                                   "Not used"},
/*  84 */  { 84,                                   "Not used"},
/*  85 */  { 85,                                   "Not used"},
/*  86 */  { 86,                                   "Not used"},
/*  87 */  { 87,                                   "Not used"},
/*  88 */  { 88,                                   "Not used"},
/*  89 */  { 89,                                   "Not used"},
/*  90 */  { 90,                                   "Not used"},
/* 101 */  { PARAM_TYPE_CORRELATION_ID,            "Correlation id"},
/* 102 */  { PARAM_TYPE_SCF_ID,                    "SCF id"},
/* 103 */  { 103,                                  "Not used"},
/* 104 */  { 104,                                  "Not used"},
/* 105 */  { 105,                                  "Not used"},
/* 106 */  { 106,                                  "Not used"},
/* 107 */  { 107,                                  "Not used"},
/* 108 */  { 108,                                  "Not used"},
/* 109 */  { 109,                                  "Not used"},
/* 110 */  { PARAM_TYPE_CALL_DIV_TREAT_IND,        "Call diversion treatment indicators"},
/* 111 */  { PARAM_TYPE_CALLED_IN_NR,              "Called IN number"},
/* 112 */  { PARAM_TYPE_CALL_OFF_TREAT_IND,        "Call offering treatment indicators"},
/* 113 */  { PARAM_TYPE_CHARGED_PARTY_IDENT,       "Charged party identification (national use)"},
/* 114 */  { PARAM_TYPE_CONF_TREAT_IND,            "Conference treatment indicators"},
/* 115 */  { PARAM_TYPE_DISPLAY_INFO,              "Display information"},
/* 116 */  { PARAM_TYPE_UID_ACTION_IND,            "UID action indicators"},
/* 117 */  { PARAM_TYPE_UID_CAPAB_IND,             "UID capability indicators"},
/* 119 */  { PARAM_TYPE_REDIRECT_COUNTER,          "Redirect counter (reserved for national use)"},
/* 120 */  { PARAM_TYPE_APPLICATON_TRANS,          "Application transport"},
/* 121 */  { PARAM_TYPE_COLLECT_CALL_REQ,          "Collect call request"},
/* 122 */  { 122,                                  "Not used"},
/* 123 */  { 123,                                  "Not used"},
/* 124 */  { 124,                                  "Not used"},
/* 125 */  { 125,                                  "Not used"},
/* 126 */  { 126,                                  "Not used"},
/* 127 */  { 127,                                  "Not used"},
/* 128 */  { 128,                                  "Not used"},
/* 129 */  { PARAM_TYPE_CALLING_GEODETIC_LOCATION, "Calling geodetic location"},
/* 130 */  { 130,                                  "Not used"},

/* 192 */  { PARAM_TYPE_GENERIC_NR,                "Generic number"},
/* 193 */  { PARAM_TYPE_GENERIC_DIGITS,            "Generic digits (national use)"},
#if 0 /* XXX: Dups of below */
  { PARAM_TYPE_JURISDICTION,              "Jurisdiction"},
  { PARAM_TYPE_GENERIC_NAME,              "Generic name"},
  { PARAM_TYPE_ORIG_LINE_INFO,            "Originating line info"},
#endif
/* 194 */  { ANSI_ISUP_PARAM_TYPE_OPER_SERV_INF,   "Operator Services information"},
/* 195 */  { ANSI_ISUP_PARAM_TYPE_EGRESS,          "Egress"},
/* 196 */  { ANSI_ISUP_PARAM_TYPE_JURISDICTION,    "Jurisdiction"},
/* 197 */  { ANSI_ISUP_PARAM_TYPE_CARRIER_ID,      "Carrier identification"},
/* 198 */  { ANSI_ISUP_PARAM_TYPE_BUSINESS_GRP,    "Business group"},
/* 199 */  { ANSI_ISUP_PARAM_TYPE_GENERIC_NAME,    "Generic name"},
/* 225 */  { ANSI_ISUP_PARAM_TYPE_NOTIF_IND,       "Notification indicator"},
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
#define CONTINUITY_CHECK_SPARE                  3
static const value_string isup_continuity_check_ind_value[] = {
  { CONTINUITY_CHECK_NOT_REQUIRED,               "Continuity check not required"},
  { CONTINUITY_CHECK_REQUIRED,                   "Continuity check required on this circuit"},
  { CONTINUITY_CHECK_ON_A_PREVIOUS_CIRCUIT ,     "Continuity check performed on a previous circuit"},
  { CONTINUITY_CHECK_SPARE ,                     "spare"},
  { 0,                                 NULL}};

static const value_string bicc_continuity_check_ind_value[] = {
  { CONTINUITY_CHECK_NOT_REQUIRED,               "no COT to be expected"},
  { CONTINUITY_CHECK_REQUIRED,                   "reserved"},
  { CONTINUITY_CHECK_ON_A_PREVIOUS_CIRCUIT ,     "COT to be expected"},
  { CONTINUITY_CHECK_SPARE ,                     "spare"},
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

static const value_string bicc_end_to_end_method_ind_value[] = {
  { NO_END_TO_END_METHOD_AVAILABLE,          "No End-to-end method available (only link-by-link method available)"},
  { PASS_ALONG_METHOD_AVAILABLE,             "reserved"},
  { SCCP_METHOD_AVAILABLE,                   "reserved"},
  { PASS_ALONG_AND_SCCP_METHOD_AVAILABLE,    "reserved"},
  { 0,                                 NULL}};

static const true_false_string isup_interworking_ind_value = {
  "interworking encountered",
  "no interworking encountered (No.7 signalling all the way)"
};

static const true_false_string isup_end_to_end_info_ind_value = {
  "end-to-end information available",
  "no end-to-end information available"
};

static const true_false_string bicc_end_to_end_info_ind_value = {
    "reserved",
    "no end-to-end information available"
};

static const true_false_string ansi_isup_iam_seg_ind_value = {
  "Additional information has been received and incorporated into call set-up",
  "No Indication"
};

static const true_false_string isup_ISDN_user_part_ind_value = {
  "ISDN user part used all the way",
  "ISDN user part not used all the way"
};

static const true_false_string bicc_ISDN_user_part_ind_value = {
    "BICC used all the way",
    "BICC not used all the way"
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

static const value_string bicc_preferences_ind_value[] = {
    { ISUP_PREFERRED_ALL_THE_WAY,                  "BICC preferred all the way"},
    { ISUP_NOT_REQUIRED_ALL_THE_WAY,               "BICC not required all the way"},
    { ISUP_REQUIRED_ALL_WAY,                       "BICC required all the way"},
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
#define CONNECTION_ORIENTED_METHOD_AVAILABLE         2
#define CONNECTIONLESS_AND_ORIENTED_METHOD_AVAILABLE 3
static const value_string isup_SCCP_method_ind_value[] = {
  { NO_INDICATION,                                  "No indication"},
  { CONNECTIONLESS_METHOD_AVAILABLE,                "Connectionless method available (national use)"},
  { CONNECTION_ORIENTED_METHOD_AVAILABLE,           "Connection oriented method available"},
  { CONNECTIONLESS_AND_ORIENTED_METHOD_AVAILABLE,   "Connectionless and -oriented method available (national use)"},
  { 0,                                 NULL}};

static const value_string bicc_SCCP_method_ind_value[] = {
    { NO_INDICATION,                                  "No indication"},
    { CONNECTIONLESS_METHOD_AVAILABLE,                "reserved"},
    { CONNECTION_ORIENTED_METHOD_AVAILABLE,           "reserved"},
    { CONNECTIONLESS_AND_ORIENTED_METHOD_AVAILABLE,   "reserved"},
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
  /* q.763-200212Amd3 */
  { 16,                                 "Mobile terminal located in the home PLMN"},
  { 17,                                 "Mobile terminal located in a visited PLMN"},
  { 0,                                 NULL}};
value_string_ext isup_calling_partys_category_value_ext = VALUE_STRING_EXT_INIT(isup_calling_partys_category_value);

static const value_string russian_isup_calling_partys_category_value[] = {
  { UNKNOWN_AT_THIS_TIME,               "Category unknown at this time (national use)"},
  { OPERATOR_FRENCH,                    "operator, language French"},
  { OPERATOR_ENGLISH,                   "operator, language English"},
  { OPERATOR_GERMAN,                    "operator, language German"},
  { OPERATOR_RUSSIAN,                   "operator, language Russian"},
  { OPERATOR_SPANISH,                   "operator, language Spanish"},

  { 6,                                  "Operator, language by mutual agreement by Administration"},
  { 7,                                  "Operator, language by mutual agreement by Administration"},
  { 8,                                  "Operator, language by mutual agreement by Administration"},
  { 9,                                  "National Operator"},

  { ORDINARY_CALLING_SUBSCRIBER,        "ordinary calling subscriber"},
  { CALLING_SUBSCRIBER_WITH_PRIORITY,   "calling subscriber with priority"},
  { DATA_CALL,                          "data call (voice band data)"},
  { TEST_CALL,                          "test call"},
  /* q.763-200212Amd2 */
  { 14,                                 "IEPS call marking for preferential call set up"},
  { PAYPHONE,                           "payphone"},
  /* q.763-200212Amd3 */
  { 16,                                 "Mobile terminal located in the home PLMN"},
  { 17,                                 "Mobile terminal located in a visited PLMN"},

  { 0xe0,                               "Reserved (Sub.Category 0)"},
  { 0xe1,                               "Hotel subscriber"},
  { 0xe2,                               "Charge free subscriber"},
  { 0xe3,                               "Subscriber with special service access"},
  { 0xe4,                               "Local subscriber"},
  { 0xe5,                               "Local coinbox"},
  { 0xf0,                               "Automatic call of category I"},
  { 0xf1,                               "Semiautomatic call of category I"},
  { 0xf2,                               "Automatic call of category II"},
  { 0xf3,                               "Semiautomatic call of category II"},
  { 0xf4,                               "Automatic call of category III"},
  { 0xf5,                               "Semiautomatic call of category III"},
  { 0xf6,                               "Automatic call of category IV"},
  { 0xf7,                               "Semiautomatic call of category IV"},

  { 0,                                 NULL}};
static value_string_ext russian_isup_calling_partys_category_value_ext = VALUE_STRING_EXT_INIT(russian_isup_calling_partys_category_value);

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
  { 5,                                          "PISN specific number"},
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
  { 0,                       "Unknown (national use)"},
  { ISDN_NUMBERING_PLAN,     "ISDN (Telephony) numbering plan ITU-T E.164"},
  { DATA_NUMBERING_PLAN,     "Data numbering plan ITU-T X.121(national use)"},
  { TELEX_NUMBERING_PLAN,    "Telex numbering plan ITU-T F.69(national use)"},
  { 5,                       "Private numbering plan (national use)"},
  { 6,                       "Reserved for national use"},
  { 0,                        NULL}};

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
  {  0, "0"},
  {  1, "1"},
  {  2, "2"},
  {  3, "3"},
  {  4, "4"},
  {  5, "5"},
  {  6, "6"},
  {  7, "7"},
  {  8, "8"},
  {  9, "9"},
  { 10, "spare"},
  { 11, "code 11 "},
  { 12, "code 12"},
  { 15, "Stop sending"},
  { 0,  NULL}};
static value_string_ext isup_called_party_address_digit_value_ext = VALUE_STRING_EXT_INIT(isup_called_party_address_digit_value);

static const value_string isup_calling_party_address_digit_value[] = {
  {  0, "0"},
  {  1, "1"},
  {  2, "2"},
  {  3, "3"},
  {  4, "4"},
  {  5, "5"},
  {  6, "6"},
  {  7, "7"},
  {  8, "8"},
  {  9, "9"},
  { 10, "spare"},
  { 11, "code 11 "},
  { 12, "code 12"},
  { 15, "spare"},
  { 0,  NULL}};
static value_string_ext isup_calling_party_address_digit_value_ext = VALUE_STRING_EXT_INIT(isup_calling_party_address_digit_value);

/*End of Called/Calling party address definitions */

 /* Japan ISUP*/
/*******************************/
/*    CARRIER INFORMATION      */
/*******************************/

/*         IEC INDICATOR       */
#define CARRIER_INFO_IEC_NO_TRANSFER                   0
#define CARRIER_INFO_IEC_TRANSFER_FORW                 1
#define CARRIER_INFO_IEC_TRANSFER_BACK                 2
#define CARRIER_INFO_IEC_TRANSFER_BOTH_DIR             3
static const value_string isup_carrier_info_iec_indic_value[] = {
  { CARRIER_INFO_IEC_NO_TRANSFER,       "No transfer"},
  { CARRIER_INFO_IEC_TRANSFER_FORW,     "Transfer in forward direction"},
  { CARRIER_INFO_IEC_TRANSFER_BACK,     "Transfer in backward direction"},
  { CARRIER_INFO_IEC_TRANSFER_BOTH_DIR, "Transfer in both directions"},
  { 0, NULL}};


/*      CATEGORY OF CARRIER    */
#define CARRIER_INFO_CATEGORY_SCPC               0xFA
#define CARRIER_INFO_CATEGORY_OLEC               0xFB
#define CARRIER_INFO_CATEGORY_TLEC               0xFC
#define CARRIER_INFO_CATEGORY_CIEC               0xFD
#define CARRIER_INFO_CATEGORY_IEC                0xFE
#define CARRIER_INFO_CATEGORY_SPARE              0xFF
static const value_string isup_carrier_info_category_value[] = {
  { CARRIER_INFO_CATEGORY_SCPC,  "(Service Control Point Carrier)"},
  { CARRIER_INFO_CATEGORY_OLEC,  "(Originating Local Exchange Carrier)"},
  { CARRIER_INFO_CATEGORY_TLEC,  "(Terminating Local Exchange Carrier)"},
  { CARRIER_INFO_CATEGORY_CIEC,  "(Chosen Inter|Exchange Carrier)"},
  { CARRIER_INFO_CATEGORY_IEC,   "(Inter|Exchange Carrier)"},
  { CARRIER_INFO_CATEGORY_SPARE, "Spare"},
  { 0, NULL}};
static value_string_ext isup_carrier_info_category_vals_ext = VALUE_STRING_EXT_INIT(isup_carrier_info_category_value);

/* TYPE OF CARRIER INFORMATION */
#define CARRIER_INFO_TYPE_OF_CARRIER_POIHIE      0xFC
#define CARRIER_INFO_TYPE_OF_CARRIER_POICA       0xFD
#define CARRIER_INFO_TYPE_OF_CARRIER_CARID       0xFE
#define CARRIER_INFO_TYPE_OF_CARRIER_SPARE       0xFF
static const value_string isup_carrier_info_type_of_carrier_value[] = {
  { CARRIER_INFO_TYPE_OF_CARRIER_POIHIE, "POI Hierarchy information"},
  { CARRIER_INFO_TYPE_OF_CARRIER_POICA,  "POI|CA information (Charge Area)"},
  { CARRIER_INFO_TYPE_OF_CARRIER_CARID,  "Carrier identification (ID) code"},
  { CARRIER_INFO_TYPE_OF_CARRIER_SPARE,  "Spare"},
  { 0, NULL}};
static value_string_ext isup_carrier_info_type_of_carrier_vals_ext = VALUE_STRING_EXT_INIT(isup_carrier_info_type_of_carrier_value);

/* POI/HIE */
#define CARRIER_INFO_POIHIE_NOINDIC              0
#define CARRIER_INFO_POIHIE_HIE1                 1
#define CARRIER_INFO_POIHIE_HIE2                 2
static const value_string isup_carrier_info_poihie_value[] = {
  { CARRIER_INFO_POIHIE_NOINDIC, "No indication"},
  { CARRIER_INFO_POIHIE_HIE1,    "Hierarchy level 1"},
  { CARRIER_INFO_POIHIE_HIE2,    "Hierarchy level 2"},
  { 0, NULL}};

#if 0
/* POICA */
/* ODD/EVEN */
#define CARRIER_INFO_CA_OE_0                  0
#define CARRIER_INFO_CA_OE_1                  1
static const value_string isup_carrier_info_poica_oe_value[] = {
  { CARRIER_INFO_CA_OE_0, "Reserved"},
  { CARRIER_INFO_CA_OE_1, "Odd number of charge area digits"},
  { 0, NULL}};
#endif

#if 0
/* CARID */
/* ODD/EVEN */
#define CARRIER_INFO_CARID_OE_0                  0
#define CARRIER_INFO_CARID_OE_1                  1
static const value_string isup_carrier_info_carid_oe_value[] = {
  { CARRIER_INFO_CARID_OE_0, "Even number of ID code digits"},
  { CARRIER_INFO_CARID_OE_1, "Odd number of ID code digits"},
  { 0, NULL}};
#endif

/* CARRIER INFORMATION DIGITS */
#define CARRIER_INFO_DIGIT_0                  0
#define CARRIER_INFO_DIGIT_1                  1
#define CARRIER_INFO_DIGIT_2                  2
#define CARRIER_INFO_DIGIT_3                  3
#define CARRIER_INFO_DIGIT_4                  4
#define CARRIER_INFO_DIGIT_5                  5
#define CARRIER_INFO_DIGIT_6                  6
#define CARRIER_INFO_DIGIT_7                  7
#define CARRIER_INFO_DIGIT_8                  8
#define CARRIER_INFO_DIGIT_9                  9
static const value_string isup_carrier_info_digits_value[] = {
  { CARRIER_INFO_DIGIT_0, "Digit 0"},
  { CARRIER_INFO_DIGIT_1, "Digit 1"},
  { CARRIER_INFO_DIGIT_2, "Digit 2"},
  { CARRIER_INFO_DIGIT_3, "Digit 3"},
  { CARRIER_INFO_DIGIT_4, "Digit 4"},
  { CARRIER_INFO_DIGIT_5, "Digit 5"},
  { CARRIER_INFO_DIGIT_6, "Digit 6"},
  { CARRIER_INFO_DIGIT_7, "Digit 7"},
  { CARRIER_INFO_DIGIT_8, "Digit 8"},
  { CARRIER_INFO_DIGIT_9, "Digit 9"},
  { 0, NULL}};

/*******************************/
/*    CHARGE AREA INFORMATION  */
/*******************************/
#if 0
/* ODD/EVEN */
#define CHARGE_AREA_INFO_OE_0                  0
#define CHARGE_AREA_INFO_OE_1                  1
static const value_string isup_charge_area_info_oe_value[] = {
  { CHARGE_AREA_INFO_OE_0, "Even number of Charge Area digits"},
  { CHARGE_AREA_INFO_OE_1, "Odd number of Charge Area code digits"},
  { 0, NULL}};
#endif

#define CHARGE_AREA_NAT_INFO_MA                0
#define CHARGE_AREA_NAT_INFO_CA                1
static const value_string isup_charge_area_info_nat_of_info_value[] = {
  { CHARGE_AREA_NAT_INFO_MA, "MA code (and optionally NC)"},
  { CHARGE_AREA_NAT_INFO_CA, "CA code"},
  { 0, NULL}};

static const true_false_string isup_calling_party_address_request_ind_value = {
  "calling party address requested",
  "calling party address not requested"
};
static const true_false_string isup_holding_ind_value = {
  "holding requested/(ANSI)holding required (No procedure specified for U.S. networks)",
  "holding not requested/(ANSI)holding not required"
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
  { CALLING_PARTY_ADDRESS_NOT_INCLUDED,  "Calling party address not included"},
  { CALLING_PARTY_ADDRESS_NOT_AVAILABLE, "Calling party address not available"},
  { 4,                                   "spare"},
  { CALLING_PARTY_ADDRESS_INCLUDED,      "Calling party address included"},
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
  "Continuity check failed"
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
  {  EVENT_ALERTING,      "ALERTING"},
  {  EVENT_PROGRESS,      "PROGRESS"},
  {  EVENT_INBAND_INFO,   "in-band information or an appropriate pattern is now available"},
  {  EVENT_ON_BUSY,       "call forwarded on busy (national use)"},
  {  EVENT_ON_NO_REPLY,   "call forwarded on no reply (national use)"},
  {  EVENT_UNCONDITIONAL, "call forwarded unconditional (national use)"},
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
#define A_8BIT_MASK       0x01
#define B_8BIT_MASK       0x02
#define C_8BIT_MASK       0x04
#define D_8BIT_MASK       0x08
#define E_8BIT_MASK       0x10
#define F_8BIT_MASK       0x20
#define G_8BIT_MASK       0x40
#define H_8BIT_MASK       0x80

#define BA_8BIT_MASK      0x03
#define CB_8BIT_MASK      0x06
#define DC_8BIT_MASK      0x0C
#define ED_8BIT_MASK      0x18
#define FE_8BIT_MASK      0x30
#define GF_8BIT_MASK      0x60
#define HG_8BIT_MASK      0xC0
#define GFE_8BIT_MASK     0x70
#define HGF_8BIT_MASK     0xE0
#define DCBA_8BIT_MASK    0x0F
#define EDCBA_8BIT_MASK   0x1F
#define HGFE_8BIT_MASK    0xF0
#define GFEDCBA_8BIT_MASK 0x7F
#define FEDCBA_8BIT_MASK  0x3F

#define A_16BIT_MASK    0x0100
#define B_16BIT_MASK    0x0200
#define C_16BIT_MASK    0x0400
#define D_16BIT_MASK    0x0800
#define E_16BIT_MASK    0x1000
#define F_16BIT_MASK    0x2000
#define G_16BIT_MASK    0x4000
#define H_16BIT_MASK    0x8000
#define I_16BIT_MASK    0x0001
#define J_16BIT_MASK    0x0002
#define K_16BIT_MASK    0x0004
#define L_16BIT_MASK    0x0008
#define M_16BIT_MASK    0x0010
#define N_16BIT_MASK    0x0020
#define O_16BIT_MASK    0x0040
#define P_16BIT_MASK    0x0080

#define BA_16BIT_MASK   0x0300
#define CB_16BIT_MASK   0x0600
#define DC_16BIT_MASK   0x0C00
#define FE_16BIT_MASK   0x3000
#define HG_16BIT_MASK   0xC000
#define KJ_16BIT_MASK   0x0006
#define PO_16BIT_MASK   0x00C0

#define CBA_16BIT_MASK  0x0700
#define KJI_16BIT_MASK  0x0007
#define HGFE_16BIT_MASK 0xF000
#define PONM_16BIT_MASK 0x00F0

/* Initialize the protocol and registered fields */
static int proto_isup = -1;
static int proto_bicc = -1;

static gboolean isup_show_cic_in_info = TRUE;

static int hf_isup_called = -1;
static int hf_isup_calling = -1;
static int hf_isup_redirecting = -1;
static int hf_isup_redirection_number = -1;
static int hf_isup_subsequent_number = -1;
static int hf_isup_connected_number = -1;
static int hf_isup_transit_network_selection = -1;
static int hf_isup_original_called_number = -1;
static int hf_isup_location_number = -1;
static int hf_isup_call_transfer_number = -1;
static int hf_isup_called_in_number = -1;
static int hf_isup_generic_number = -1;
static int hf_isup_jurisdiction = -1;
static int hf_isup_charge_number = -1;

static int hf_isup_cic = -1;
static int hf_bicc_cic = -1;

static int isup_tap = -1;

static int hf_isup_message_type = -1;
static int hf_isup_parameter_type = -1;
static int hf_isup_parameter_value = -1;
static int hf_isup_mand_parameter_type = -1;
static int hf_isup_opt_parameter_type = -1;
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
static int hf_bicc_continuity_check_indicator = -1;
static int hf_isup_echo_control_device_indicator = -1;

static int hf_isup_forw_call_natnl_inatnl_call_indicator = -1;
static int hf_isup_forw_call_end_to_end_method_indicator = -1;
static int hf_bicc_forw_call_end_to_end_method_indicator = -1;
static int hf_isup_forw_call_interworking_indicator = -1;
static int hf_isup_forw_call_end_to_end_info_indicator = -1;
static int hf_bicc_forw_call_end_to_end_info_indicator = -1;
static int hf_isup_forw_call_isdn_user_part_indicator = -1;
static int hf_bicc_forw_call_isdn_user_part_indicator = -1;
static int hf_isup_forw_call_preferences_indicator = -1;
static int hf_bicc_forw_call_preferences_indicator = -1;
static int hf_isup_forw_call_isdn_access_indicator = -1;
static int hf_isup_forw_call_ported_num_trans_indicator = -1;
static int hf_isup_forw_call_qor_attempt_indicator = -1;
static int hf_isup_forw_call_sccp_method_indicator = -1;
static int hf_bicc_forw_call_sccp_method_indicator = -1;

static int hf_isup_calling_partys_category = -1;
static int hf_russian_isup_calling_partys_category = -1;

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
static int hf_bicc_backw_call_end_to_end_method_ind = -1;
static int hf_isup_backw_call_interworking_ind = -1;
static int hf_isup_backw_call_end_to_end_info_ind = -1;
static int hf_bicc_backw_call_end_to_end_info_ind = -1;
static int hf_isup_backw_call_iam_seg_ind = -1;
static int hf_isup_backw_call_isdn_user_part_ind = -1;
static int hf_bicc_backw_call_isdn_user_part_ind = -1;
static int hf_isup_backw_call_holding_ind = -1;
static int hf_isup_backw_call_isdn_access_ind = -1;
static int hf_isup_backw_call_echo_control_device_ind = -1;
static int hf_isup_backw_call_sccp_method_ind = -1;
static int hf_bicc_backw_call_sccp_method_ind = -1;

static int hf_isup_cause_indicator = -1;
static int hf_ansi_isup_cause_indicator = -1;

static int hf_isup_suspend_resume_indicator = -1;

static int hf_isup_range_indicator = -1;
static int hf_isup_bitbucket = -1;
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
static int hf_isup_notification_indicator                   = -1;
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
static int hf_ansi_isup_spare_b7 = -1;
static int hf_ansi_isup_type_of_nw_id = -1;
static int hf_ansi_isup_nw_id_plan = -1;
static int hf_ansi_isup_tns_nw_id_plan = -1;
static int hf_ansi_isup_nw_id = -1;
static int hf_ansi_isup_circuit_code = -1;

static int hf_length_indicator                      = -1;
static int hf_afi                                   = -1;
static int hf_bicc_nsap_dsp                         = -1;
static int hf_bicc_nsap_dsp_length                  = -1;
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
static int hf_late_cut_through_cap_ind           = -1;
static int hf_bat_ase_signal                    = -1;
static int hf_bat_ase_duration                  = -1;
static int hf_bat_ase_bearer_redir_ind          = -1;
static int hf_bat_ase_default                   = -1;
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

/* national parameters */
static int hf_isup_french_coll_field = -1;
static int hf_isup_french_msg_num = -1;

static int hf_isup_israeli_charging_message_indicators_current = -1;
static int hf_isup_israeli_charging_message_indicators_next = -1;
static int hf_isup_israeli_current_rate = -1;
static int hf_isup_israeli_time_indicator = -1;
static int hf_isup_israeli_next_rate = -1;

static int hf_japan_isup_redirect_capability = -1;
static int hf_japan_isup_redirect_counter = -1;
static int hf_japan_isup_rfi_info_type = -1;
static int hf_japan_isup_rfi_info_len = -1;
static int hf_japan_isup_perf_redir_reason = -1;
static int hf_japan_isup_redir_pos_ind = -1;
static int hf_japan_isup_inv_redir_reason = -1;
static int hf_japan_isup_bwd_info_type = -1;
static int hf_japan_isup_tag_len = -1;
static int hf_japan_isup_hold_at_emerg_call_disc_ind = -1;
static int hf_japan_isup_emerg_call_type = -1;
static int hf_japan_isup_add_user_cat_type = -1;
static int hf_japan_isup_type_1_add_fixed_serv_inf = -1;
static int hf_japan_isup_type_1_add_mobile_serv_inf = -1;
static int hf_japan_isup_type_2_add_mobile_serv_inf = -1;
static int hf_japan_isup_type_3_add_mobile_serv_inf = -1;
static int hf_japan_isup_reason_for_clip_fail = -1;
static int hf_japan_isup_contractor_number = -1;

static int hf_isup_carrier_info_iec = -1;
/*static int hf_isup_carrier_info_cat_of_carrier = -1;*/
/*static int hf_isup_carrier_info_type_of_carrier_info = -1;*/
static int hf_japan_isup_carrier_info_length = -1;
static int hf_isup_carrier_info_odd_no_digits = -1;
static int hf_isup_carrier_info_even_no_digits = -1;
static int hf_isup_carrier_info_ca_odd_no_digits = -1;
static int hf_isup_carrier_info_ca_even_no_digits = -1;
static int hf_isup_carrier_info_poi_entry_HEI = -1;
static int hf_isup_carrier_info_poi_exit_HEI = -1;

static int hf_japan_isup_charge_delay_type = -1;
static int hf_japan_isup_charge_info_type = -1;
static int hf_japan_isup_sig_elem_type = -1;
static int hf_japan_isup_activation_id = -1;
static int hf_japan_isup_op_cls = -1;
static int hf_japan_isup_op_type = -1;
static int hf_japan_isup_charging_party_type = -1;
static int hf_japan_isup_utp = -1;
static int hf_japan_isup_crci1 = -1;
static int hf_japan_isup_crci2 = -1;
static int hf_japan_isup_crci1_len = -1;
static int hf_japan_isup_iu = -1;
static int hf_japan_isup_dcr = -1;
static int hf_japan_isup_ecr = -1;
static int hf_japan_isup_ncr = -1;
static int hf_japan_isup_scr = -1;
static int hf_japan_isup_collecting_method = -1;
static int hf_japan_isup_tariff_rate_pres = -1;

static int hf_japan_isup_charge_area_nat_of_info_value = -1;
static int hf_japan_isup_charging_info_nc_odd_digits = -1;
static int hf_japan_isup_charging_info_nc_even_digits = -1;
static int hf_isup_charging_info_maca_odd_digits = -1;
static int hf_isup_charging_info_maca_even_digits = -1;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_isup_protocol_class = -1;
static int hf_isup_geo_loc_shape_description = -1;
static int hf_isup_geo_loc_shape = -1;
static int hf_isup_ccss_call_indicator = -1;
static int hf_isup_charged_party_identification = -1;
static int hf_isup_forward_gvns = -1;
static int hf_isup_idi = -1;
static int hf_isup_precedence_level = -1;
static int hf_isup_configuration_data = -1;
static int hf_isup_redirect_capability = -1;
static int hf_isup_credit = -1;
static int hf_isup_idp = -1;
static int hf_isup_apm_seg_indicator = -1;
static int hf_isup_user_service_information = -1;
static int hf_isup_tunnelled_protocol_data = -1;
static int hf_isup_mlpp_service_domain = -1;
static int hf_isup_uid_capability_indicators = -1;
static int hf_isup_call_identity = -1;
static int hf_isup_scf_id = -1;
static int hf_isup_call_diversion_information = -1;
static int hf_isup_display_information = -1;
static int hf_isup_call_history_info = -1;
static int hf_isup_remote_operations = -1;
static int hf_isup_user_to_user_info = -1;
static int hf_isup_address_digits = -1;
static int hf_isup_network_id = -1;
static int hf_isup_uid_action_indicators = -1;
static int hf_isup_dsp = -1;
static int hf_isup_instruction_indicators = -1;
static int hf_isup_circuit_assignment_map = -1;
static int hf_isup_collect_call_request_indicator = -1;
static int hf_isup_hop_counter = -1;
static int hf_isup_user_service_information_prime = -1;
static int hf_isup_message_compatibility_information = -1;
static int hf_isup_app_transport_param_field8 = -1;
static int hf_isup_app_transport_param_field16 = -1;
static int hf_isup_binary_code = -1;
static int hf_isup_local_reference = -1;
static int hf_isup_cause_indicators = -1;
static int hf_isup_backward_gvns = -1;
static int hf_isup_presentation_indicator = -1;
static int hf_isup_mcid_request_indicators = -1;
static int hf_isup_origination_isc_point_code = -1;
static int hf_isup_upgraded_parameter = -1;
static int hf_isup_generic_digits = -1;
static int hf_isup_diagnostic = -1;
static int hf_isup_network_specific_facility = -1;
static int hf_isup_app_transport_instruction_indicator = -1;
static int hf_isup_look_forward_busy = -1;
static int hf_isup_redirect_counter = -1;
static int hf_isup_correlation_id = -1;
static int hf_isup_network_identity = -1;
static int hf_isup_user_teleservice_information = -1;
static int hf_isup_mcid_response_indicators = -1;
static int hf_isup_apm_user_info_field = -1;
static int hf_isup_feature_code = -1;
static int hf_isup_number_qualifier_indicator = -1;
static int hf_isup_echo_control_information = -1;
static int hf_isup_network_id_length_indicator = -1;
static int hf_isup_unknown_organisation_identifier = -1;
static int hf_isup_originating_line_info = -1;
static int hf_isup_loop_prevention_indicator_type = -1;
static int hf_isup_signalling_point_code = -1;
static int hf_isup_call_transfer_identity = -1;
static int hf_isup_access_transport_parameter_field = -1;
static int hf_isup_propagation_delay_counter = -1;
static int hf_isup_number_different_meaning = -1;

/* Initialize the subtree pointers */
static gint ett_isup                            = -1;
static gint ett_isup_parameter                  = -1;
static gint ett_isup_address_digits             = -1;
static gint ett_isup_carrier_info               = -1;
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
static gint ett_isup_range = -1;
static gint ett_app_transport_fields = -1;
static gint ett_app_transport = -1;
static gint ett_apm_seg_indicator = -1;
static gint ett_echo_control_information = -1;
static gint ett_instruction_indicators = -1;
static gint ett_message_compatibility_information = -1;

static expert_field ei_isup_format_national_matter = EI_INIT;
static expert_field ei_isup_message_type_unknown = EI_INIT;
static expert_field ei_isup_not_dissected_yet = EI_INIT;
static expert_field ei_isup_message_type_no_optional_parameters = EI_INIT;
static expert_field ei_isup_status_subfield_not_present = EI_INIT;
static expert_field ei_isup_empty_number = EI_INIT;
static expert_field ei_isup_too_many_digits = EI_INIT;
static expert_field ei_isup_opt_par_length_err = EI_INIT;

static dissector_handle_t bicc_handle;

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
  /* Reassembled data field */
  NULL,
  /* Tag */
  "ISUP APM Message fragments"
};

static reassembly_table isup_apm_msg_reassembly_table;

/* Info for the tap that must be passed between procedures */
static gchar *tap_called_number  = NULL;
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
  proto_tree_add_uint(parameter_tree, hf_isup_cvr_rsp_ind, parameter_tvb, 0, CVR_RESP_IND_LENGTH, cvr_response_ind);
  proto_item_append_text(parameter_item, " : 0x%x", cvr_response_ind);

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
  proto_tree_add_uint(parameter_tree, hf_isup_cvr_cg_car_ind, parameter_tvb, 0, CG_CHAR_IND_LENGTH, cvr_cg_char_ind);
  proto_tree_add_uint(parameter_tree, hf_isup_cvr_cg_double_seize, parameter_tvb, 0, CG_CHAR_IND_LENGTH, cvr_cg_char_ind);
  proto_tree_add_uint(parameter_tree, hf_isup_cvr_cg_alarm_car_ind, parameter_tvb, 0, CG_CHAR_IND_LENGTH, cvr_cg_char_ind);
  proto_tree_add_uint(parameter_tree, hf_isup_cvr_cont_chk_ind, parameter_tvb, 0, CG_CHAR_IND_LENGTH, cvr_cg_char_ind);

  proto_item_append_text(parameter_item, " : 0x%x", cvr_cg_char_ind);
}

/* ------------------------------------------------------------------
 Dissector Parameter nature of connection flags
 */
static void
dissect_isup_nature_of_connection_indicators_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 nature_of_connection_ind;
  static int * const isup_indicators[] = {
    &hf_isup_satellite_indicator,
    &hf_isup_continuity_check_indicator,
    &hf_isup_echo_control_device_indicator,
    NULL
  };

  static int * const bicc_indicators[] = {
    &hf_isup_satellite_indicator,
    &hf_bicc_continuity_check_indicator,
    &hf_isup_echo_control_device_indicator,
    NULL
  };

  nature_of_connection_ind = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 0, NATURE_OF_CONNECTION_IND_LENGTH,
                              g_str_equal(pinfo -> current_proto, "ISUP") ? isup_indicators : bicc_indicators, ENC_BIG_ENDIAN);

  proto_item_append_text(parameter_item, " : 0x%x", nature_of_connection_ind);
}

/* ------------------------------------------------------------------
 Dissector Parameter Forward Call Indicators
 */
static void
dissect_isup_forward_call_indicators_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_item *parameter_item, proto_tree *parameter_tree)
{
  guint16 forward_call_ind = tvb_get_ntohs(parameter_tvb, 0);
  static int * const isup_indicators[] = {
    &hf_isup_forw_call_natnl_inatnl_call_indicator,
    &hf_isup_forw_call_end_to_end_method_indicator,
    &hf_isup_forw_call_interworking_indicator,
    &hf_isup_forw_call_end_to_end_info_indicator,
    &hf_isup_forw_call_isdn_user_part_indicator,
    &hf_isup_forw_call_preferences_indicator,
    &hf_isup_forw_call_isdn_access_indicator,
    &hf_isup_forw_call_sccp_method_indicator,
    &hf_isup_forw_call_ported_num_trans_indicator,
    &hf_isup_forw_call_qor_attempt_indicator,
    NULL
  };

  static int * const bicc_indicators[] = {
    &hf_isup_forw_call_natnl_inatnl_call_indicator,
    &hf_bicc_forw_call_end_to_end_method_indicator,
    &hf_isup_forw_call_interworking_indicator,
    &hf_bicc_forw_call_end_to_end_info_indicator,
    &hf_bicc_forw_call_isdn_user_part_indicator,
    &hf_bicc_forw_call_preferences_indicator,
    &hf_isup_forw_call_isdn_access_indicator,
    &hf_bicc_forw_call_sccp_method_indicator,
    &hf_isup_forw_call_ported_num_trans_indicator,
    &hf_isup_forw_call_qor_attempt_indicator,
    NULL
  };

  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 0, FORWARD_CALL_IND_LENGTH,
                              g_str_equal(pinfo -> current_proto, "ISUP") ? isup_indicators : bicc_indicators, ENC_BIG_ENDIAN);

  proto_item_append_text(parameter_item, " : 0x%x", forward_call_ind);
}

/* ------------------------------------------------------------------
 Dissector Parameter Calling Party's Category
 */
static void
dissect_isup_calling_partys_category_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item, guint8 itu_isup_variant)
{
  guint8 calling_partys_category;

  calling_partys_category = tvb_get_guint8(parameter_tvb, 0);

  if (itu_isup_variant == ISUP_RUSSIAN_VARIANT) {
      proto_tree_add_uint(parameter_tree, hf_russian_isup_calling_partys_category,
                          parameter_tvb, 0, CALLING_PRTYS_CATEGORY_LENGTH, calling_partys_category);

      proto_item_append_text(parameter_item, " : 0x%x (%s)",
          calling_partys_category,
          val_to_str_ext_const(calling_partys_category,
          &russian_isup_calling_partys_category_value_ext,
          "reserved/spare"));

  } else {
      proto_tree_add_uint(parameter_tree, hf_isup_calling_partys_category,
                          parameter_tvb, 0, CALLING_PRTYS_CATEGORY_LENGTH, calling_partys_category);

      proto_item_append_text(parameter_item, " : 0x%x (%s)",
                          calling_partys_category,
                          val_to_str_ext_const(calling_partys_category,
                                               &isup_calling_partys_category_value_ext,
                                               "reserved/spare"));
  }
}


/* ------------------------------------------------------------------
  Dissector Parameter Transmission medium requirement
 */
static void
dissect_isup_transmission_medium_requirement_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 transmission_medium_requirement;

  transmission_medium_requirement = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_isup_transmission_medium_requirement,
                      parameter_tvb, 0, TRANSMISSION_MEDIUM_REQUIREMENT_LENGTH, transmission_medium_requirement);

  proto_item_append_text(parameter_item, " : %u (%s)", transmission_medium_requirement,
                      val_to_str_ext_const(transmission_medium_requirement, &isup_transmission_medium_requirement_value_ext, "spare"));
}

static char *
dissect_isup_digits_common(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree, proto_item *item,
                           gint hf_number, gint hf_odd_digit, gint hf_even_digit,
                           gboolean even_indicator, e164_number_type_t number_type, guint nature_of_address)
{
  gint           i = 0;
  gint           reported_length, captured_length;
  proto_item    *digits_item;
  proto_tree    *digits_tree;
  guint8         digit_pair = 0;
  wmem_strbuf_t *strbuf_number;
  char          *number;
  e164_info_t    e164_info;
  gint           start_offset = offset;

  reported_length = tvb_reported_length_remaining(tvb, offset);
  if (reported_length == 0) {
    expert_add_info(pinfo, item, &ei_isup_empty_number);
    proto_item_append_text(item, ": (empty)");
    return NULL;
  }

  strbuf_number = wmem_strbuf_sized_new(pinfo->pool, MAXDIGITS+1, 0);

  /* Make the digit string, looping on captured length (in case a snaplen was set) */
  captured_length = tvb_captured_length_remaining(tvb, offset);
  while (captured_length > 0) {
    if (++i > MAXDIGITS) {
      break;
    }
    digit_pair = tvb_get_guint8(tvb, offset);
    wmem_strbuf_append_c(strbuf_number, number_to_char(digit_pair & ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK));

    if ((captured_length - 1) > 0) {
      if (++i > MAXDIGITS) {
        break;
      }
      wmem_strbuf_append_c(strbuf_number, number_to_char((digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10));
    }

    offset += 1;
    captured_length -= 1;
  }

  if  (even_indicator && (tvb_captured_length(tvb) > 0) && (++i < MAXDIGITS)) {
    /* Even Indicator set -> last (even) digit is valid and has be displayed */
    wmem_strbuf_append_c(strbuf_number, number_to_char((digit_pair & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10));
  }

  number = wmem_strbuf_finalize(strbuf_number);

  /* Now make the tree */
  offset = start_offset;
  i = 0;
  digits_item = proto_tree_add_string(tree, hf_number, tvb, offset, -1, number);
  digits_tree = proto_item_add_subtree(digits_item, ett_isup_address_digits);

  while (reported_length > 0) {
    if (++i > MAXDIGITS) {
      expert_add_info(pinfo, digits_item, &ei_isup_too_many_digits);
      break;
    }
    proto_tree_add_item(digits_tree, hf_odd_digit, tvb, offset, 1, ENC_NA);

    if ((reported_length - 1) > 0) {
      if (++i > MAXDIGITS) {
        expert_add_info(pinfo, digits_item, &ei_isup_too_many_digits);
        break;
      }
      proto_tree_add_item(digits_tree, hf_even_digit, tvb, offset, 1, ENC_NA);
    }

    offset += 1;
    reported_length -= 1;
  }

  if  (even_indicator && (tvb_reported_length(tvb) > 0)) {
    if (++i < MAXDIGITS) {
      /* Even Indicator set -> last (even) digit is valid and has be displayed */
      proto_tree_add_item(digits_tree, hf_even_digit, tvb, offset - 1, 1, ENC_NA);
    } else {
      expert_add_info(pinfo, digits_item, &ei_isup_too_many_digits);
    }
  }

  if (number_type != NONE) {
    e164_info.e164_number_type = number_type;
    e164_info.nature_of_address = nature_of_address;
    e164_info.E164_number_str = number;
    e164_info.E164_number_length = i - 1;
    dissect_e164_number(tvb, digits_tree, 2, (offset - 2), e164_info);
  }

  proto_item_append_text(item, ": %s", number);

  return number;
}

/* ------------------------------------------------------------------
  Dissector Parameter Called party number
 */
void
dissect_isup_called_party_number_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8       indicators1, indicators2;
  gint         offset = 0;
  gint         number_plan;
  static int * const indicators1_flags[] = {
    &hf_isup_odd_even_indicator,
    &hf_isup_called_party_nature_of_address_indicator,
    NULL
  };

  static int * const indicators2_flags[] = {
    &hf_isup_inn_indicator,
    &hf_isup_numbering_plan_indicator,
    NULL
  };

  indicators1 = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 0, 1, indicators1_flags, ENC_NA);
  indicators2 = tvb_get_guint8(parameter_tvb, 1);
  number_plan = (indicators2 & 0x70)>> 4;
  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 1, 1, indicators2_flags, ENC_NA);
  offset = 2;

  tap_called_number = dissect_isup_digits_common(parameter_tvb, offset, pinfo, parameter_tree, parameter_item,
                             hf_isup_called, hf_isup_called_party_odd_address_signal_digit,
                             hf_isup_called_party_even_address_signal_digit, ((indicators1 & 0x80) == 0),
                             number_plan == 1 ? CALLED_PARTY_NUMBER : NONE,
                             (indicators1 & 0x7f));
}

/* ------------------------------------------------------------------
  Dissector Parameter  Subsequent number
 */
static void
dissect_isup_subsequent_number_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8      indicators1;
  gint        offset = 0;

  indicators1 = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_isup_odd_even_indicator, parameter_tvb, 0, 1, indicators1);
  offset = 1;

  dissect_isup_digits_common(parameter_tvb, offset, pinfo, parameter_tree, parameter_item,
                             hf_isup_subsequent_number, hf_isup_called_party_odd_address_signal_digit,
                             hf_isup_called_party_even_address_signal_digit, ((indicators1 & 0x80) == 0),
                             NONE, 0);
}
/* ------------------------------------------------------------------
  Dissector Parameter Information Request Indicators
 */
static void
dissect_isup_information_request_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  static int * const indicators[] = {
    &hf_isup_calling_party_address_request_indicator,
    &hf_isup_info_req_holding_indicator,
    &hf_isup_calling_partys_category_request_indicator,
    &hf_isup_charge_information_request_indicator,
    &hf_isup_malicious_call_identification_request_indicator,
    NULL
  };

  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 0, INFO_REQUEST_IND_LENGTH, indicators, ENC_BIG_ENDIAN);

  proto_item_append_text(parameter_item, " : 0x%x", tvb_get_ntohs(parameter_tvb, 0));
}
/* ------------------------------------------------------------------
  Dissector Parameter Information Indicators
 */
static void
dissect_isup_information_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  static int * const indicators[] = {
    &hf_isup_calling_party_address_response_indicator,
    &hf_isup_hold_provided_indicator,
    &hf_isup_calling_partys_category_response_indicator,
    &hf_isup_charge_information_response_indicator,
    &hf_isup_solicited_indicator,
    NULL
  };

  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 0, INFO_IND_LENGTH, indicators, ENC_BIG_ENDIAN);

  proto_item_append_text(parameter_item, " : 0x%x", tvb_get_ntohs(parameter_tvb, 0));
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

  proto_item_append_text(parameter_item, " : 0x%x", continuity_indicators);
}
/* ------------------------------------------------------------------
 Dissector Parameter Backward Call Indicators
 */
static void
dissect_isup_backward_call_indicators_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  static int * const isup_indicators[] = {
    &hf_isup_backw_call_charge_ind,
    &hf_isup_backw_call_called_partys_status_ind,
    &hf_isup_backw_call_called_partys_category_ind,
    &hf_isup_backw_call_end_to_end_method_ind,
    &hf_isup_backw_call_interworking_ind,
    &hf_isup_backw_call_end_to_end_info_ind,
    &hf_isup_backw_call_isdn_user_part_ind,
    &hf_isup_backw_call_holding_ind,
    &hf_isup_backw_call_isdn_access_ind,
    &hf_isup_backw_call_echo_control_device_ind,
    &hf_isup_backw_call_sccp_method_ind,
    NULL
  };

  static int * const bicc_indicators[] = {
      &hf_isup_backw_call_charge_ind,
      &hf_isup_backw_call_called_partys_status_ind,
      &hf_isup_backw_call_called_partys_category_ind,
      &hf_bicc_backw_call_end_to_end_method_ind,
      &hf_isup_backw_call_interworking_ind,
      &hf_bicc_backw_call_end_to_end_info_ind,
      &hf_bicc_backw_call_isdn_user_part_ind,
      &hf_isup_backw_call_holding_ind,
      &hf_isup_backw_call_isdn_access_ind,
      &hf_isup_backw_call_echo_control_device_ind,
      &hf_bicc_backw_call_sccp_method_ind,
      NULL
  };

  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 0, BACKWARD_CALL_IND_LENGTH,
                              g_str_equal(pinfo -> current_proto, "ISUP") ? isup_indicators : bicc_indicators,
                              ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " : 0x%x", tvb_get_ntohs(parameter_tvb, 0));
}

static void
dissect_ansi_isup_backward_call_indicators_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  static int * const isup_indicators[] = {
    &hf_isup_backw_call_charge_ind,
    &hf_isup_backw_call_called_partys_status_ind,
    &hf_isup_backw_call_called_partys_category_ind,
    &hf_isup_backw_call_end_to_end_method_ind,
    &hf_isup_backw_call_interworking_ind,
    &hf_isup_backw_call_iam_seg_ind,
    &hf_isup_backw_call_isdn_user_part_ind,
    &hf_isup_backw_call_holding_ind,
    &hf_isup_backw_call_isdn_access_ind,
    &hf_isup_backw_call_echo_control_device_ind,
    &hf_isup_backw_call_sccp_method_ind,
    NULL
  };

  static int * const bicc_indicators[] = {
      &hf_isup_backw_call_charge_ind,
      &hf_isup_backw_call_called_partys_status_ind,
      &hf_isup_backw_call_called_partys_category_ind,
      &hf_bicc_backw_call_end_to_end_method_ind,
      &hf_isup_backw_call_interworking_ind,
      &hf_isup_backw_call_iam_seg_ind,
      &hf_bicc_backw_call_isdn_user_part_ind,
      &hf_isup_backw_call_holding_ind,
      &hf_isup_backw_call_isdn_access_ind,
      &hf_isup_backw_call_echo_control_device_ind,
      &hf_bicc_backw_call_sccp_method_ind,
      NULL
  };

  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 0, BACKWARD_CALL_IND_LENGTH,
                              g_str_equal(pinfo -> current_proto, "ISUP") ? isup_indicators : bicc_indicators, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " : 0x%x", tvb_get_ntohs(parameter_tvb, 0));
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
dissect_isup_cause_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{ guint length = tvb_reported_length(parameter_tvb);
  proto_tree_add_item(parameter_tree, hf_isup_cause_indicators, parameter_tvb, 0, -1, ENC_NA);
  dissect_q931_cause_ie(parameter_tvb, 0, length,
                        parameter_tree,
                        hf_isup_cause_indicator, &tap_cause_value, isup_parameter_type_value);
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
      offset += 1;
      length -= 1;
      if (length == 0)
        return;
      proto_tree_add_item(parameter_tree, hf_isup_cause_indicator, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      cause_value = tvb_get_guint8(parameter_tvb, offset)&0x7f;
      offset += 1;
      length -= 1;
      proto_item_append_text(parameter_item, " : %s (%u)",
                          val_to_str_ext_const(cause_value, &q850_cause_code_vals_ext, "spare"), cause_value);
      if (length == 0) {
        return;
      }
      proto_tree_add_item(parameter_tree, hf_isup_diagnostic, parameter_tvb, offset, length, ENC_NA);
      return;
    case 2:
      /*ANSI*/
      proto_tree_add_item(parameter_tree, hf_isup_cause_location, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(parameter_tree, hf_ansi_isup_coding_standard, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(parameter_tree, hf_isup_extension_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
      length -= 1;
      if (length == 0)
        return;
      proto_tree_add_item(parameter_tree, hf_ansi_isup_cause_indicator, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      cause_value = tvb_get_guint8(parameter_tvb, offset)&0x7f;
      proto_item_append_text(parameter_item, " : %s (%u)",
                          val_to_str_ext_const(cause_value, &ansi_isup_cause_code_vals_ext, "spare"),
                          cause_value);
      offset += 1;
      length -= 1;
      if (length == 0) {
        return;
      }
      proto_tree_add_item(parameter_tree, hf_isup_diagnostic, parameter_tvb, offset, length, ENC_NA);
      return;
    default:
      proto_tree_add_item(parameter_tree, hf_ansi_isup_coding_standard, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(parameter_tree, hf_isup_extension_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      break;
  }
}

/* ------------------------------------------------------------------
  Dissector ANSI Transit network selection
 */

static const value_string ansi_isup_tns_nw_id_plan_vals[] = {
    { 0x00, "Unknown" },
    { 0x01, "3-digit carrier id with circuit code" },
    { 0x02, "4-digit carrier id with circuit code" },
    {    0, NULL } };

static void
dissect_ansi_isup_transit_network_selection_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo _U_, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{
  gint        offset = 0;

  static int * const indicators_fields[] = {
    &hf_ansi_isup_spare_b7,
    &hf_isup_type_of_network_identification,
    &hf_ansi_isup_tns_nw_id_plan,
    NULL
  };

  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 0, 1, indicators_fields, ENC_NA);
  offset = 1;

  proto_tree_add_item(parameter_tree, hf_ansi_isup_nw_id, parameter_tvb, offset, 2, ENC_BCD_DIGITS_0_9);
  offset += 2;
  proto_tree_add_item(parameter_tree, hf_ansi_isup_circuit_code, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);

}

static const value_string ansi_isup_type_of_nw_id_vals[] = {
    { 0x00, "Spare" },
    { 0x01, "Spare" },
    { 0x02, "National network identification" },
    { 0x03, "Spare" },
    { 0x04, "Spare" },
    { 0x05, "Spare" },
    { 0x06, "Spare" },
    { 0x07, "Spare" },
    {    0, NULL } };

static const value_string ansi_isup_nw_id_plan_vals[] = {
    { 0x00, "Unknown" },
    { 0x01, "3-digit carrier id" },
    { 0x02, "4-digit carrier id" },
    {    0, NULL } };

static void
dissect_ansi_isup_param_carrier_id(tvbuff_t *parameter_tvb, packet_info *pinfo _U_, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{
  int offset = 0;

  static int * const flags[] = {
    &hf_ansi_isup_spare_b7,
    &hf_ansi_isup_type_of_nw_id,
    &hf_ansi_isup_nw_id_plan,
    NULL
  };

  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, offset, 1, flags, ENC_BIG_ENDIAN);
  offset++;

  proto_tree_add_item(parameter_tree, hf_ansi_isup_nw_id, parameter_tvb, offset, 2, ENC_BCD_DIGITS_0_9);

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

  proto_item_append_text(parameter_item, " : 0x%x", indicators);
}
/* ------------------------------------------------------------------
  Dissector Parameter Range and Status Indicators
 */
static void
dissect_isup_range_and_status_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_tree *range_tree;
  int offset = 0;
  guint8 range, actual_status_length;

  range = tvb_get_guint8(parameter_tvb, 0) + 1;
  proto_tree_add_uint_format(parameter_tree, hf_isup_range_indicator, parameter_tvb, offset, RANGE_LENGTH, range, "Range: %u", range);
  offset = offset + RANGE_LENGTH;

  actual_status_length = tvb_reported_length_remaining(parameter_tvb, offset);
  if (actual_status_length > 0) {
    range_tree = proto_tree_add_subtree(parameter_tree, parameter_tvb, offset, -1, ett_isup_range, NULL, "Status subfield");
    if (range<9) {
      proto_tree_add_uint_bits_format_value(range_tree, hf_isup_bitbucket, parameter_tvb, (offset*8)+(8-range), range,
                          tvb_get_guint8(parameter_tvb, offset), ENC_BIG_ENDIAN, "%u bit 1", range);
    }
  } else {
    expert_add_info(pinfo, parameter_item, &ei_isup_status_subfield_not_present);
  }

  proto_item_append_text(parameter_item, ": Range (%u) and status", range);
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

  proto_item_append_text(parameter_item, " : %s (%u)",
                      val_to_str_const(cgs_message_type, isup_cgs_message_type_value, "unknown"), cgs_message_type);
}
/* ------------------------------------------------------------------
  Dissector Parameter Facility indicator parameter
 */
static void
dissect_isup_facility_ind_parameter(tvbuff_t *parameter_tvb, proto_item *parameter_item)
{
  guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);

  proto_item_append_text(parameter_item, " : %s (%u)"  , val_to_str_const(indicator, isup_facility_ind_value, "spare"), indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter Circuit state indicator
 */
static void
dissect_isup_circuit_state_ind_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_item *circuit_state_item;
  proto_tree *circuit_state_tree;
  guint8      circuit_state;
  gint        offset = 0;
  gint        i      = 0;

  while (tvb_reported_length_remaining(parameter_tvb, offset) > 0) {
    circuit_state_tree = proto_tree_add_subtree_format(parameter_tree, parameter_tvb, offset, -1,
                                             ett_isup_circuit_state_ind, &circuit_state_item,
                                             "Circuit# CIC+%u state", i);
    circuit_state = tvb_get_guint8(parameter_tvb, offset);
    if ((circuit_state & DC_8BIT_MASK) == 0) {
      proto_tree_add_uint(circuit_state_tree, hf_isup_mtc_blocking_state1, parameter_tvb, offset, 1, circuit_state);
      proto_item_append_text(circuit_state_item, ": %s",
                          val_to_str_const(circuit_state&BA_8BIT_MASK, isup_mtc_blocking_state_DC00_value, "unknown"));
    }
    else {
      proto_tree_add_uint(circuit_state_tree, hf_isup_mtc_blocking_state2, parameter_tvb, offset, 1, circuit_state);
      proto_tree_add_uint(circuit_state_tree, hf_isup_call_proc_state, parameter_tvb, offset, 1, circuit_state);
      proto_tree_add_uint(circuit_state_tree, hf_isup_hw_blocking_state, parameter_tvb, offset, 1, circuit_state);
      proto_item_append_text(circuit_state_item, ": %s", val_to_str_const(circuit_state&BA_8BIT_MASK, isup_mtc_blocking_state_DCnot00_value, "unknown"));
    }
    i++;
    offset += 1;
  }
  proto_item_append_text(parameter_item, " (national use)");
}
/* ------------------------------------------------------------------
  Dissector Parameter Event information
 */
static void
dissect_isup_event_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 indicators;

  indicators = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint_format_value(parameter_tree, hf_isup_event_ind, parameter_tvb, 0, EVENT_INFO_LENGTH, indicators,
                             "%s (%u)",
                             val_to_str_const(indicators & GFEDCBA_8BIT_MASK, isup_event_ind_value, "spare"),
                             indicators & GFEDCBA_8BIT_MASK);
  proto_tree_add_boolean(parameter_tree, hf_isup_event_presentation_restricted_ind, parameter_tvb, 0, EVENT_INFO_LENGTH, indicators);

  proto_item_append_text(parameter_item, " : %s (%u)", val_to_str_const(indicators & GFEDCBA_8BIT_MASK, isup_event_ind_value, "spare"), indicators);
}
/* ------------------------------------------------------------------
  Dissector Parameter User-to-user information- no detailed dissection since defined in Rec. Q.931
 */
static void
dissect_isup_user_to_user_information_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{ guint length = tvb_reported_length(parameter_tvb);
  proto_tree_add_item(parameter_tree, hf_isup_user_to_user_info, parameter_tvb, 0, -1, ENC_NA);
  dissect_q931_user_user_ie(parameter_tvb, pinfo, 0, length,
    parameter_tree);
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
  proto_tree_add_item(parameter_tree, hf_isup_call_identity, parameter_tvb, 0, CALL_ID_LENGTH, ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_isup_signalling_point_code, parameter_tvb, CALL_ID_LENGTH, SPC_LENGTH, ENC_BIG_ENDIAN);

  proto_item_append_text(parameter_item, " : Call ID = %u, SPC = %u", call_id, spc);
}
/* ------------------------------------------------------------------
  Dissector Parameter Access Transport - no detailed dissection since defined in Rec. Q.931
 */
static void
dissect_isup_access_transport_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree,
                                        proto_item *parameter_item _U_, packet_info *pinfo)
{

  proto_tree_add_item(parameter_tree, hf_isup_access_transport_parameter_field, parameter_tvb, 0, -1, ENC_NA);

  if (q931_ie_handle)
    call_dissector(q931_ie_handle, parameter_tvb, pinfo, parameter_tree);
}

/* dissect x.213 NSAP coded Address */

static const value_string x213_afi_value[] = {
  { NSAP_IDI_IANA_ICP_DEC,              "IANA ICP, decimal"},
  { NSAP_IDI_IANA_ICP_BIN,              "IANA ICP, binary"},
  { NSAP_IDI_X_121_DEC_FSD_NZ,          "X.121, decimal, first significant digit non-zero"},
  { NSAP_IDI_X_121_BIN_FSD_NZ,          "X.121, binary, first significant digit non-zero"},
  { NSAP_IDI_ISO_DCC_DEC,               "ISO DCC, decimal"},
  { NSAP_IDI_ISO_DCC_BIN,               "ISO DCC, binary"},
  { NSAP_IDI_F_69_DEC_FSD_NZ,           "F.69, decimal, first significant digit non-zero"},
  { NSAP_IDI_F_69_BIN_FSD_NZ,           "F.69, binary, first significant digit non-zero"},
  { NSAP_IDI_E_163_DEC_FSD_NZ,          "E.163, decimal, first significant digit non-zero"},
  { NSAP_IDI_E_163_BIN_FSD_NZ,          "E.163, binary, first significant digit non-zero"},
  { NSAP_IDI_E_164_DEC_FSD_NZ,          "E.164, decimal, first significant digit non-zero"},
  { NSAP_IDI_E_164_BIN_FSD_NZ,          "E.164, binary, first significant digit non-zero"},
  { NSAP_IDI_ISO_6523_ICD_DEC,          "ISO 6523-ICD, decimal"},
  { NSAP_IDI_ISO_6523_ICD_BIN,          "ISO 6523-ICD, binary"},
  { NSAP_IDI_LOCAL_DEC,                 "Local, decimal"},
  { NSAP_IDI_LOCAL_BIN,                 "Local, binary"},
  { NSAP_IDI_LOCAL_ISO_646_CHAR,        "Local, ISO/IEC 646 character"},
  { NSAP_IDI_LOCAL_NATIONAL_CHAR,       "Local, National character"},
  { NSAP_IDI_X_121_DEC_FSD_Z,           "X.121, decimal, first significant digit zero"},
  { NSAP_IDI_X_121_BIN_FSD_Z,           "X.121, binary, first significant digit zero"},
  { NSAP_IDI_F_69_DEC_FSD_Z,            "F.69, decimal, first significant digit zero"},
  { NSAP_IDI_F_69_BIN_FSD_Z,            "F.69, binary, first significant digit zero"},
  { NSAP_IDI_E_163_DEC_FSD_Z,           "E.163, decimal, first significant digit zero"},
  { NSAP_IDI_E_163_BIN_FSD_Z,           "E.163, binary, first significant digit zero"},
  { NSAP_IDI_E_164_DEC_FSD_Z,           "E.164, decimal, first significant digit zero"},
  { NSAP_IDI_E_164_BIN_FSD_Z,           "E.164, binary, first significant digit zero"},

  { NSAP_IDI_ITU_T_IND_DEC,             "ITU-T IND, decimal"},
  { NSAP_IDI_ITU_T_IND_BIN,             "ITU-T IND, binary"},

  { NSAP_IDI_IANA_ICP_DEC_GROUP,        "IANA ICP Group no, decimal"},
  { NSAP_IDI_IANA_ICP_BIN_GROUP,        "IANA ICP Group no, binary"},
  { NSAP_IDI_X_121_DEC_FSD_NZ_GROUP,    "X.121 Group no, decimal, first significant digit non-zero"},
  { NSAP_IDI_X_121_BIN_FSD_NZ_GROUP,    "X.121 Group no, binary, first significant digit non-zero"},
  { NSAP_IDI_ISO_DCC_DEC_GROUP,         "ISO DCC Group no, decimal"},
  { NSAP_IDI_ISO_DCC_BIN_GROUP,         "ISO DCC Group no, binary"},
  { NSAP_IDI_F_69_DEC_FSD_NZ_GROUP,     "F.69 Group no, decimal, first significant digit non-zero"},
  { NSAP_IDI_F_69_BIN_FSD_NZ_GROUP,     "F.69 Group no, binary, first significant digit non-zero"},
  { NSAP_IDI_E_163_DEC_FSD_NZ_GROUP,    "E.163 Group no, decimal, first significant digit non-zero"},
  { NSAP_IDI_E_163_BIN_FSD_NZ_GROUP,    "E.163 Group no, binary, first significant digit non-zero"},
  { NSAP_IDI_E_164_DEC_FSD_NZ_GROUP,    "E.164 Group no, decimal, first significant digit non-zero"},
  { NSAP_IDI_E_164_BIN_FSD_NZ_GROUP,    "E.164 Group no, binary, first significant digit non-zero"},
  { NSAP_IDI_ISO_6523_ICD_DEC_GROUP,    "ISO 6523-ICD Group no, decimal"},
  { NSAP_IDI_ISO_6523_ICD_BIN_GROUP,    "ISO 6523-ICD Group no, binary"},
  { NSAP_IDI_LOCAL_DEC_GROUP,           "Local Group no, decimal"},
  { NSAP_IDI_LOCAL_BIN_GROUP,           "Local Group no, binary"},
  { NSAP_IDI_LOCAL_ISO_646_CHAR_GROUP,  "Local Group no, ISO/IEC 646 character"},
  { NSAP_IDI_LOCAL_NATIONAL_CHAR_GROUP, "Local Group no, national character"},
  { NSAP_IDI_X_121_DEC_FSD_Z_GROUP,     "X.121 Group no, decimal, first significant digit zero"},
  { NSAP_IDI_X_121_BIN_FSD_Z_GROUP,     "X.121 Group no, binary, first significant digit zero"},
  { NSAP_IDI_F_69_DEC_FSD_Z_GROUP,      "F.69 Group no, decimal, first significant digit zero"},
  { NSAP_IDI_F_69_BIN_FSD_Z_GROUP,      "F.69 Group no, binary, first significant digit zero"},
  { NSAP_IDI_E_163_DEC_FSD_Z_GROUP,     "E.163 Group no, decimal, first significant digit zero"},
  { NSAP_IDI_E_163_BIN_FSD_Z_GROUP,     "E.163 Group no, binary, first significant digit zero"},
  { NSAP_IDI_E_164_DEC_FSD_Z_GROUP,     "E.164 Group no, decimal, first significant digit zero"},
  { NSAP_IDI_E_164_BIN_FSD_Z_GROUP,     "E.163 Group no, binary, first significant digit zero"},

  { NSAP_IDI_ITU_T_IND_DEC_GROUP,       "ITU-T IND Group no, decimal"},
  { NSAP_IDI_ITU_T_IND_BIN_GROUP,       "ITU-T IND Group no, binary"},
  { 0,  NULL }
};
value_string_ext x213_afi_value_ext = VALUE_STRING_EXT_INIT(x213_afi_value);


/* Up-to-date information on the allocated ICP values can be found in   */
/* RFC 4548 at                                                          */
/* https://tools.ietf.org/html/rfc4548                                  */
static const value_string iana_icp_values[] = {
  { 0x0, "IP Version 6 Address"},
  { 0x1, "IP Version 4 Address"},
  { 0,  NULL }
};

/*
 * XXX - shouldn't there be a centralized routine for dissecting NSAPs?
 * See also "dissect_atm_nsap()" in epan/dissectors/packet-arp.c and
 * "print_nsap_net()" in epan/osi_utils.c.
 */
void
dissect_nsap(tvbuff_t *parameter_tvb, gint offset, gint len, proto_tree *parameter_tree)
{
  guint8 afi;
  guint  icp;

  afi = tvb_get_guint8(parameter_tvb, offset);

  switch (afi) {
    case NSAP_IDI_IANA_ICP_BIN:  /* IANA ICP Binary fortmat*/
      proto_tree_add_item(parameter_tree, hf_isup_idp, parameter_tvb, offset, 3, ENC_NA);

      proto_tree_add_uint(parameter_tree, hf_afi, parameter_tvb, offset, 1, afi);
      offset = offset + 1;
      icp = tvb_get_ntohs(parameter_tvb, offset);
      proto_tree_add_uint(parameter_tree, hf_iana_icp, parameter_tvb, offset, 1, icp);
      if (icp == 0) { /* IPv6 addr */
        proto_tree_add_item(parameter_tree, hf_isup_dsp, parameter_tvb, offset + 2, 17, ENC_NA);
        proto_tree_add_item(parameter_tree, hf_nsap_ipv6_addr, parameter_tvb, offset + 2,
                            16, ENC_NA);

      }
      else { /* IPv4 addr */
        /* XXX - this is really only for ICP 1 */
        proto_tree_add_item(parameter_tree, hf_isup_dsp, parameter_tvb, offset + 2, 17, ENC_NA);
        proto_tree_add_item(parameter_tree, hf_nsap_ipv4_addr, parameter_tvb, offset + 2, 4, ENC_BIG_ENDIAN);
      }

      break;
    case NSAP_IDI_E_164_BIN_FSD_NZ:       /* E.164 ATM format */
    case NSAP_IDI_E_164_BIN_FSD_NZ_GROUP: /* E.164 ATM group format */
      proto_tree_add_item(parameter_tree, hf_isup_idp, parameter_tvb, offset, 9, ENC_NA);

      proto_tree_add_uint(parameter_tree, hf_afi, parameter_tvb, offset, 1, afi);

      proto_tree_add_item(parameter_tree, hf_isup_idi, parameter_tvb, offset + 1, 8, ENC_NA);
      offset = offset +1;
      /* Dissect country code */
      dissect_e164_cc(parameter_tvb, parameter_tree, offset, E164_ENC_BCD);

      proto_tree_add_uint_format_value(parameter_tree, hf_bicc_nsap_dsp_length, parameter_tvb, offset, 0,
          (len-9), "%u (len %u -9)", (len-9), len);

      proto_tree_add_item(parameter_tree, hf_bicc_nsap_dsp, parameter_tvb, offset + 8, (len - 9), ENC_NA);

      break;
    default:
      proto_tree_add_uint(parameter_tree, hf_afi, parameter_tvb, offset, len, afi);
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

  { 0x00, "GSM Full Rate (13.0 kBit/s)(GSM FR)"},
  { 0x01, "GSM Half Rate (5.6 kBit/s) (GSM HR)"},
  { 0x02, "GSM Enhanced Full Rate (12.2 kBit/s)(GSM EFR)"},
  { 0x03, "Full Rate Adaptive Multi-Rate (FR AMR)"},
  { 0x04, "Half Rate Adaptive Multi-Rate (HR AMR)"},
  { 0x05, "UMTS Adaptive Multi-Rate (UMTS AMR)"},
  { 0x06, "UMTS Adaptive Multi-Rate 2 (UMTS AMR 2)"},
  { 0x07, "TDMA Enhanced Full Rate (7.4 kBit/s) (TDMA EFR)"},
  { 0x08, "PDC Enhanced Full Rate (6.7 kBit/s) (PDC EFR)"},
  { 0x09, "Full Rate Adaptive Multi-Rate WideBand (FR AMR-WB)"},
  { 0x0a, "UMTS Adaptive Multi-Rate WideBand (UMTS AMR-WB)"},
  { 0x0b, "8PSK Half Rate Adaptive Multi-Rate (OHR AMR)"},
  { 0x0c, "8PSK Full Rate Adaptive Multi-Rate WideBand  (OFR AMR-WB)"},
  { 0x0d, "8PSK Half Rate Adaptive Multi-Rate WideBand (OHR AMR-WB)"},
  { 0xfe, "Reserved for future use."},
  { 0xff, "Reserved for MuMe dummy Codec Type (MuMe)"},
  { 0,  NULL }
};
static value_string_ext ETSI_codec_type_subfield_vals_ext = VALUE_STRING_EXT_INIT(ETSI_codec_type_subfield_vals);

#if 0
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
#endif

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

static const true_false_string late_cut_through_cap_ind_value  = {
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
/* This routine should be called with offset at Organization_Identifier not the lengh indicator
 * because of use from other disectors.
 */
extern int dissect_codec_mode(proto_tree *tree, tvbuff_t *tvb, int offset, int len) {
  guint8 tempdata;
  static int * const active_code_sets[] = {
    &hf_active_code_set_12_2,
    &hf_active_code_set_10_2,
    &hf_active_code_set_7_95,
    &hf_active_code_set_7_40,
    &hf_active_code_set_6_70,
    &hf_active_code_set_5_90,
    &hf_active_code_set_5_15,
    &hf_active_code_set_4_75,
    NULL
  };

  static int * const supported_code_sets[] = {
    &hf_supported_code_set_12_2,
    &hf_supported_code_set_10_2,
    &hf_supported_code_set_7_95,
    &hf_supported_code_set_7_40,
    &hf_supported_code_set_6_70,
    &hf_supported_code_set_5_90,
    &hf_supported_code_set_5_15,
    &hf_supported_code_set_4_75,
    NULL
  };

  tempdata = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(tree, hf_Organization_Identifier , tvb, offset, 1, tempdata);
  switch (tempdata) {
    case ITU_T :
      offset = offset + 1;
      tempdata = tvb_get_guint8(tvb, offset);
      proto_tree_add_uint(tree, hf_codec_type , tvb, offset, 1, tempdata);
      offset = offset + 1;
      switch (tempdata) {
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
          if (len > 2) {
            proto_tree_add_item(tree, hf_isup_configuration_data, tvb, offset, 1, ENC_NA);
            offset = offset + 1;
          }
          break;
        case G_728 :
        case G_729_CS_ACELP :
        case G_729_Annex_B :
          /* three bit config data, TODO decode config */
          if (len > 2) {
            proto_tree_add_item(tree, hf_isup_configuration_data, tvb, offset, 1, ENC_NA);
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
      proto_tree_add_uint(tree, hf_etsi_codec_type , tvb, offset, 1, tempdata);
      if (len > 2) {
        offset = offset + 1;

        proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_active_code_set,
                           ett_acs, active_code_sets, ENC_LITTLE_ENDIAN, BMT_NO_APPEND);
      }
      if (len > 3) {
        offset = offset + 1;

        proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_supported_code_set,
                           ett_acs, supported_code_sets, ENC_LITTLE_ENDIAN, BMT_NO_APPEND);
      }
      if (len > 4) {
        offset = offset + 1;
        proto_tree_add_item(tree, hf_optimisation_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_max_codec_modes, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      }
      offset = offset + 1;
      break;
    default:
      offset = offset + 1;
      proto_tree_add_item(tree, hf_isup_unknown_organisation_identifier, tvb, offset, len, ENC_NA);
      offset = offset + len - 1;
      break;
  }
  /* switch OID */

  return offset;
}

static int
dissect_codec(tvbuff_t *parameter_tvb, proto_tree *bat_ase_element_tree, gint length_indicator, gint offset, gint identifier)
{
/* offset is at length indicator e.g 1 step past identifier */
  static int * const compatibility_info[] = {
    &hf_Instruction_ind_for_general_action,
    &hf_Send_notification_ind_for_general_action,
    &hf_Instruction_ind_for_pass_on_not_possible,
    &hf_Send_notification_ind_for_pass_on_not_possible,
    &hf_isup_extension_ind,
    NULL
  };

  proto_tree_add_uint(bat_ase_element_tree , hf_bat_ase_identifier , parameter_tvb, offset - 1, 1, identifier);
  proto_tree_add_uint(bat_ase_element_tree , hf_length_indicator  , parameter_tvb, offset, 1, length_indicator);
  offset = offset + 1;

  proto_tree_add_bitmask_list(bat_ase_element_tree, parameter_tvb, offset, 1, compatibility_info, ENC_NA);

  offset = dissect_codec_mode(bat_ase_element_tree, parameter_tvb, offset+1, length_indicator-1);
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
  gint        list_end;
  tvbuff_t   *next_tvb;
  proto_tree *bat_ase_tree, *bat_ase_element_tree, *bat_ase_iwfa_tree;
  proto_item *bat_ase_element_item, *bat_ase_iwfa_item;
  guint8      identifier, content, BCTP_Indicator_field_1, BCTP_Indicator_field_2;
  guint8      tempdata, element_no, number_of_indicators;
  guint16     sdp_length;
  guint8      diagnostic_len;
  guint8      length_ind_len;
  guint       tempdata16;
  guint       content_len, length_indicator;
  guint       duration;
  guint       diagnostic;
  guint32     bncid;

  element_no = 0;

  bat_ase_tree = proto_tree_add_subtree(parameter_tree, parameter_tvb, offset, -1, ett_bat_ase, NULL,
                                     "Bearer Association Transport (BAT) Application Service Element (ASE) Encapsulated Application Information:");

  while (tvb_reported_length_remaining(parameter_tvb, offset) > 0) {
    element_no = element_no + 1;
    identifier = tvb_get_guint8(parameter_tvb, offset);

    /* length indicator may be 11 bits long */
    offset = offset + 1;
    proto_tree_add_item(bat_ase_tree, hf_isup_extension_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
    tempdata = tvb_get_guint8(parameter_tvb, offset);
    if (tempdata & 0x80) {
      length_indicator = tempdata & 0x7f;
      length_ind_len = 1;
    }
    else {
      offset = offset + 1;
      tempdata16 = (tempdata & 0x7f);
      length_indicator = tvb_get_guint8(parameter_tvb, offset)& 0x0f;
      length_indicator = length_indicator << 7;
      length_indicator = length_indicator + tempdata16;
      length_ind_len = 2;
    }

    bat_ase_element_tree = proto_tree_add_subtree_format(bat_ase_tree, parameter_tvb,
                                               (offset - length_ind_len), (length_indicator + 2),
                                               ett_bat_ase_element, &bat_ase_element_item,
                                               "BAT ASE Element %u, Identifier: %s", element_no,
                                               val_to_str_ext(identifier, &bat_ase_list_of_Identifiers_vals_ext, "unknown (%u)"));

    if (identifier != CODEC) {
      /* identifier, length indicator and compatibility info must be printed inside CODEC */
      /* dissection in order to use dissect_codec routine for codec list */
      proto_tree_add_uint(bat_ase_element_tree , hf_bat_ase_identifier , parameter_tvb,
                          offset - length_ind_len, 1, identifier);
      proto_tree_add_uint(bat_ase_element_tree , hf_length_indicator  , parameter_tvb,
                          offset - length_ind_len + 1, length_ind_len, length_indicator);

      offset = offset + 1;
      proto_tree_add_item(bat_ase_element_tree, hf_isup_extension_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(bat_ase_element_tree, hf_Send_notification_ind_for_pass_on_not_possible, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(bat_ase_element_tree, hf_Instruction_ind_for_pass_on_not_possible, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(bat_ase_element_tree, hf_Send_notification_ind_for_general_action, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(bat_ase_element_tree, hf_Instruction_ind_for_general_action, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      offset = offset + 1;
    }
    content_len = length_indicator - 1 ; /* exclude the treated Compatibility information */

    /* content will be different depending on identifier */
    switch (identifier) {

      case ACTION_INDICATOR :

        content = tvb_get_guint8(parameter_tvb, offset);
        proto_tree_add_uint(bat_ase_element_tree, hf_Action_Indicator , parameter_tvb, offset, 1, content);
        proto_item_append_text(bat_ase_element_item, " - %s",
                               val_to_str_ext(content, &bat_ase_action_indicator_field_vals_ext, "unknown (%u)"));
        offset = offset + 1;
        break;
      case BACKBONE_NETWORK_CONNECTION_IDENTIFIER :

        bncid = tvb_get_ntohl(parameter_tvb, offset);
        switch (content_len) {
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
        proto_item_append_text(bat_ase_element_item, " - 0x%08x", bncid);
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
        while (offset < (list_end - 1)) {
          identifier = tvb_get_guint8(parameter_tvb, offset);
          offset = offset + 1;
          tempdata = tvb_get_guint8(parameter_tvb, offset);
          if (tempdata & 0x80) {
            length_indicator = tempdata & 0x7f;
          }
          else {
            offset = offset +1;
            length_indicator = tvb_get_guint8(parameter_tvb, offset);
            length_indicator = length_indicator << 7;
            length_indicator = length_indicator & (tempdata & 0x7f);
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
        proto_tree_add_uint(bat_ase_element_tree, hf_BAT_ASE_Comp_Report_Reason, parameter_tvb, offset, 1, tempdata);
        offset = offset + 1;

        diagnostic_len = content_len - 1;
        while (diagnostic_len > 0) {
          tempdata = tvb_get_guint8(parameter_tvb, offset);
          proto_tree_add_uint(bat_ase_element_tree, hf_BAT_ASE_Comp_Report_ident, parameter_tvb, offset, 1, tempdata);
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
                            offset, 1, tempdata);
        proto_item_append_text(bat_ase_element_item, " - %s",
                               val_to_str_ext(tempdata, &bearer_network_connection_characteristics_vals_ext, "unknown (%u)"));

        offset = offset + content_len;
        break;
/* The Bearer Control Information information element contains the bearer control tunnelling protocol */
/* ITU-T Q.1990 (2001), BICC bearer control tunnelling protocol. */

      case BEARER_CONTROL_INFORMATION :
        BCTP_Indicator_field_1 = tvb_get_guint8(parameter_tvb, offset);
        proto_tree_add_uint(bat_ase_element_tree, hf_BCTP_Version_Indicator,
                            parameter_tvb, offset, 1, BCTP_Indicator_field_1);

        proto_tree_add_boolean(bat_ase_element_tree, hf_BVEI,
                               parameter_tvb, offset, 1, BCTP_Indicator_field_1);
        offset = offset + 1;

        BCTP_Indicator_field_2 = tvb_get_guint8(parameter_tvb, offset);

        proto_tree_add_uint(bat_ase_element_tree, hf_Tunnelled_Protocol_Indicator ,
                            parameter_tvb, offset, 1, BCTP_Indicator_field_2);

        proto_tree_add_boolean(bat_ase_element_tree, hf_TPEI,
                               parameter_tvb, offset, 1, BCTP_Indicator_field_2);
        offset = offset + 1;

        sdp_length = (length_indicator) - 3;

        if (sdp_length > tvb_reported_length_remaining(parameter_tvb, offset)) {
          /* If this is a segmented message we may not have all the data */
          next_tvb = tvb_new_subset_remaining(parameter_tvb, offset);
        } else {
          next_tvb = tvb_new_subset_length(parameter_tvb, offset, sdp_length);
        }
        if (BCTP_Indicator_field_2==0x20) {
          /* IPBCP (text encoded) */
          call_dissector(sdp_handle, next_tvb, pinfo, bat_ase_element_tree);
        } else {
          proto_tree_add_item(bat_ase_element_tree, hf_isup_tunnelled_protocol_data, next_tvb, 0, -1, ENC_NA);
        }
        offset = offset + sdp_length;
        break;
      case BEARER_CONTROL_TUNNELLING :

        tempdata = tvb_get_guint8(parameter_tvb, offset);
        proto_tree_add_boolean(bat_ase_element_tree, hf_bearer_control_tunneling , parameter_tvb, offset, 1, (tempdata & 0x01));
        if (tempdata & 0x01)
          proto_item_append_text(bat_ase_element_item, " - Tunnelling to be used ");

        offset = offset + content_len;
        break;
      case BEARER_CONTROL_UNIT_IDENTIFIER :
        tempdata = tvb_get_guint8(parameter_tvb, offset);
        proto_tree_add_item(bat_ase_element_tree, hf_isup_network_id_length_indicator, parameter_tvb, offset, 1, ENC_NA);
        offset = offset + 1;
        if (tempdata > 0) {

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
          proto_tree_add_item(bat_ase_element_tree, hf_isup_network_id, parameter_tvb, offset, tempdata, ENC_NA);
          offset += tempdata;
        } /* end if */

        proto_tree_add_item(bat_ase_element_tree, hf_Local_BCU_ID, parameter_tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        break;
      case SIGNAL :
        /* As type is Constructor new elements follow, return to main loop */
        break;
      case BEARER_REDIRECTION_CAPABILITY :
        tempdata = tvb_get_guint8(parameter_tvb, offset);
        proto_tree_add_boolean(bat_ase_element_tree, hf_late_cut_through_cap_ind , parameter_tvb, offset, 1, tempdata);
        offset = offset + content_len;
        break;
      case BEARER_REDIRECTION_INDICATORS :
        number_of_indicators = 0;
        while (number_of_indicators < content_len) {
          tempdata = tvb_get_guint8(parameter_tvb, offset);
          proto_tree_add_uint(bat_ase_element_tree, hf_bat_ase_bearer_redir_ind , parameter_tvb, offset, 1, tempdata);
          offset = offset + 1;
          number_of_indicators = number_of_indicators + 1;
        }
        break;
      case SIGNAL_TYPE :
        tempdata = tvb_get_guint8(parameter_tvb, offset);
        proto_tree_add_uint(bat_ase_element_tree, hf_bat_ase_signal , parameter_tvb, offset, 1, tempdata);
        offset = offset + content_len;
        break;
      case DURATION :
        duration = tvb_get_letohs(parameter_tvb, offset);
        proto_tree_add_uint(bat_ase_element_tree, hf_bat_ase_duration , parameter_tvb, offset, 2, duration);
        offset = offset + content_len;
        break;
      default :
        proto_tree_add_item(bat_ase_element_tree, hf_bat_ase_default, parameter_tvb, offset, content_len, ENC_NA);
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
dissect_isup_application_transport_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{

  guint8   si_and_apm_seg_ind;
  guint8   apm_Segmentation_local_ref = 0;
  guint16  aci16;
  gint     offset = 0;
  guint8   octet;
  guint    length = tvb_reported_length(parameter_tvb);
  gboolean more_frag;
  gboolean save_fragmented;

  tvbuff_t      *new_tvb  = NULL;
  tvbuff_t      *next_tvb = NULL;
  fragment_head *frag_msg = NULL;

  static int * const apm_flags[] = {
    &hf_isup_extension_ind,
    &hf_isup_apm_si_ind,
    &hf_isup_apm_segmentation_ind,
    NULL
  };

  static int * const app_trans_flags[] = {
    &hf_isup_extension_ind,
    &hf_isup_app_Send_notification_ind,
    &hf_isup_app_Release_call_ind,
    NULL
  };

  static int * const app_field_flags[] = {
    &hf_isup_extension_ind,
    &hf_isup_app_cont_ident,
    NULL
  };

  aci16 = tvb_get_guint8(parameter_tvb, offset);

  if ((aci16 & H_8BIT_MASK) == 0x80) {
    /* Octet 1 */
    aci16 = aci16 & 0x7f;
    proto_tree_add_bitmask(parameter_tree, parameter_tvb, offset, hf_isup_app_transport_param_field8, ett_app_transport_fields, app_field_flags, ENC_NA);
    offset = offset + 1;
  }
  /* Octet 1a */
  else {
    proto_tree_add_item(parameter_tree, hf_isup_app_transport_param_field16, parameter_tvb, offset, 2, ENC_BIG_ENDIAN);
    aci16 = (aci16<<8) | (tvb_get_guint8(parameter_tvb, offset) & 0x7f);
    proto_tree_add_uint(parameter_tree, hf_isup_app_cont_ident , parameter_tvb, offset, 2, aci16);
    offset = offset + 2;
  }

  /* Octet 2 */
  proto_tree_add_bitmask(parameter_tree, parameter_tvb, offset, hf_isup_app_transport_instruction_indicator, ett_app_transport, app_trans_flags, ENC_NA);
  offset = offset + 1;

  /* Octet 3*/
  si_and_apm_seg_ind  = tvb_get_guint8(parameter_tvb, offset);
  proto_tree_add_bitmask(parameter_tree, parameter_tvb, offset, hf_isup_apm_seg_indicator, ett_apm_seg_indicator, apm_flags, ENC_NA);
  offset = offset + 1;

  /* Octet 3a */
  if ((si_and_apm_seg_ind & H_8BIT_MASK) == 0x00) {
    apm_Segmentation_local_ref  = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_item(parameter_tree, hf_isup_extension_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(parameter_tree, hf_isup_apm_slr, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
    offset = offset + 1;
  }
  /* For APM'98'-user applications. (aci 0 - 3), APM-user information field starts at octet 4 */
  if (aci16 > 3) {
    /* Octet 4 Originating Address length */
    octet = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_item(parameter_tree, hf_isup_orig_addr_len, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    if (octet != 0) {
      /* 4b */
      proto_tree_add_item(parameter_tree, hf_isup_odd_even_indicator, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      /* nature of address indicator */
      offset += 1;
      proto_tree_add_item(parameter_tree, hf_isup_inn_indicator, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(parameter_tree, hf_isup_numbering_plan_indicator, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
      /* Address digits */
      proto_tree_add_item(parameter_tree, hf_isup_address_digits, parameter_tvb, offset, octet - 2, ENC_NA);
      offset = offset + octet - 2;
    }
    /* Octet 5 Destination Address length */
    octet = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_item(parameter_tree, hf_isup_dest_addr_len, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    if (octet != 0) {
      /* 4b */
      proto_tree_add_item(parameter_tree, hf_isup_odd_even_indicator, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      /* nature of address indicator */
      offset += 1;
      proto_tree_add_item(parameter_tree, hf_isup_inn_indicator, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(parameter_tree, hf_isup_numbering_plan_indicator, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
      /* Address digits */
      proto_tree_add_item(parameter_tree, hf_isup_address_digits, parameter_tvb, offset, octet - 2, ENC_NA);
      offset = offset + octet - 2;
    }
  }
  /*
   * Defragment ?
   *
   */
  if (isup_apm_desegment) {
    if ((si_and_apm_seg_ind != 0xc0) && ((si_and_apm_seg_ind & H_8BIT_MASK)!=0x80)) {
      /* debug ws_warning("got here Frame %u", pinfo->num); */
      /* Segmented message */
      save_fragmented = pinfo->fragmented;
      pinfo->fragmented = TRUE;
      more_frag = TRUE;
      if (si_and_apm_seg_ind == 0)
        more_frag = FALSE;

      frag_msg = fragment_add_seq_next(&isup_apm_msg_reassembly_table,
                                       parameter_tvb, offset,
                                       pinfo,
                                       (apm_Segmentation_local_ref & 0x7f),         /* ID for fragments belonging together */
                                       NULL,
                                       tvb_reported_length_remaining(parameter_tvb, offset), /* fragment length - to the end */
                                       more_frag);                                  /* More fragments? */

      if ((si_and_apm_seg_ind & 0x3f) !=0 && (si_and_apm_seg_ind &0x40) !=0) {
        /* First fragment set number of fragments */
        fragment_set_tot_len(&isup_apm_msg_reassembly_table,
                             pinfo,
                             apm_Segmentation_local_ref & 0x7f,
                             NULL,
                             (si_and_apm_seg_ind & 0x3f));
      }

      new_tvb = process_reassembled_data(parameter_tvb, offset, pinfo,
                                         "Reassembled ISUP", frag_msg, &isup_apm_msg_frag_items,
                                         NULL, parameter_tree);

      if (frag_msg) { /* Reassembled */
        col_append_str(pinfo->cinfo, COL_INFO,
                       " (Message Reassembled)");
      } else { /* Not last packet of reassembled Short Message */
        col_append_str(pinfo->cinfo, COL_INFO,
                       " (Message fragment)");
      }

      pinfo->fragmented = save_fragmented;
    }
  }/*isup_apm_desegment*/

  if (offset == (gint)length) {
    /* No data */
    proto_tree_add_item(parameter_tree, hf_isup_apm_user_info_field, parameter_tvb, offset, 0, ENC_NA);
    return;
  }
  if (new_tvb) { /* take it all */
    next_tvb = new_tvb;
  } else { /* make a new subset */
    next_tvb = tvb_new_subset_remaining(parameter_tvb, offset);
  }

  proto_tree_add_item(parameter_tree, hf_isup_apm_user_info_field, parameter_tvb, offset, -1, ENC_NA);

  switch (aci16 & 0x7fff) {
    case 3:
      /* Charging ASE */
      dissect_charging_ase_ChargingMessageType_PDU(next_tvb, pinfo, parameter_tree, NULL);
      break;
    case 5:
      /* dissect BAT ASE element, without transparent data (Q.765.5-200006) */
      dissect_bat_ase_Encapsulated_Application_Information(next_tvb, pinfo, parameter_tree, 0);
      break;
    default:
      expert_add_info_format(pinfo, parameter_tree, &ei_isup_not_dissected_yet, "No further dissection of APM-user information field");
      break;
  }
}



/* ------------------------------------------------------------------
  Dissector Parameter Optional Forward Call indicators
 */
static void
dissect_isup_optional_forward_call_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 ind;
  static int * const indicators[] = {
    &hf_isup_cug_call_ind,
    &hf_isup_simple_segmentation_ind,
    &hf_isup_connected_line_identity_request_ind,
    NULL
  };

  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 0, OPTIONAL_FORWARD_CALL_IND_LENGTH, indicators, ENC_NA);

  ind = tvb_get_guint8(parameter_tvb, 0);
  proto_item_append_text(parameter_item, " : %s (%u)",
                      val_to_str_const(ind & BA_8BIT_MASK, isup_CUG_call_ind_value, "spare"),
                      ind);
}
/* ------------------------------------------------------------------
  Dissector Parameter calling party number
 */
void
dissect_isup_calling_party_number_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8       indicators1, indicators2;
  gint         offset = 0;
  gint         number_plan;
  static int * const indicators1_fields[] = {
    &hf_isup_odd_even_indicator,
    &hf_isup_calling_party_nature_of_address_indicator,
    NULL
  };
  static int * const indicators2_fields[] = {
    &hf_isup_ni_indicator,
    &hf_isup_numbering_plan_indicator,
    &hf_isup_address_presentation_restricted_indicator,
    &hf_isup_screening_indicator,
    NULL
  };

  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 0, 1, indicators1_fields, ENC_NA);
  indicators1 = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 1, 1, indicators2_fields, ENC_NA);
  indicators2 = tvb_get_guint8(parameter_tvb, 1);
  number_plan = (indicators2 & 0x70)>> 4;
  offset = 2;

  tap_calling_number = dissect_isup_digits_common(parameter_tvb, offset, pinfo, parameter_tree, parameter_item,
                             hf_isup_calling, hf_isup_calling_party_odd_address_signal_digit,
                             hf_isup_calling_party_even_address_signal_digit, ((indicators1 & 0x80) == 0),
                             number_plan == 1 ? CALLING_PARTY_NUMBER : NONE,
                             (indicators1 & 0x7f));
}
/* ------------------------------------------------------------------
  Dissector Parameter Original called  number
 */
void
dissect_isup_original_called_number_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8      indicators1;
  gint        offset = 0;
  static int * const indicators1_fields[] = {
    &hf_isup_odd_even_indicator,
    &hf_isup_calling_party_nature_of_address_indicator,
    NULL
  };
  static int * const indicators2_fields[] = {
    &hf_isup_numbering_plan_indicator,
    &hf_isup_address_presentation_restricted_indicator,
    NULL
  };


  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 0, 1, indicators1_fields, ENC_NA);
  indicators1 = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 1, 1, indicators2_fields, ENC_NA);
  offset = 2;

  dissect_isup_digits_common(parameter_tvb, offset, pinfo, parameter_tree, parameter_item,
                             hf_isup_original_called_number,
                             hf_isup_calling_party_odd_address_signal_digit,
                             hf_isup_calling_party_even_address_signal_digit,
                             ((indicators1 & 0x80) == 0), NONE, 0);
}
/* ------------------------------------------------------------------
  Dissector Parameter Redirecting number
 */
void
dissect_isup_redirecting_number_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8      indicators1;
  gint        offset = 0;
  static int * const indicators1_fields[] = {
    &hf_isup_odd_even_indicator,
    &hf_isup_calling_party_nature_of_address_indicator,
    NULL
  };
  static int * const indicators2_fields[] = {
    &hf_isup_numbering_plan_indicator,
    &hf_isup_address_presentation_restricted_indicator,
    NULL
  };

  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 0, 1, indicators1_fields, ENC_NA);
  indicators1 = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 1, 1, indicators2_fields, ENC_NA);
  offset = 2;

  dissect_isup_digits_common(parameter_tvb, offset, pinfo, parameter_tree, parameter_item,
                             hf_isup_redirecting, hf_isup_calling_party_odd_address_signal_digit,
                             hf_isup_calling_party_even_address_signal_digit, ((indicators1 & 0x80) == 0),
                             NONE, 0);
}

/* ------------------------------------------------------------------
  Dissector Parameter Redirection number
 */
static void
dissect_isup_redirection_number_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8      indicators1;
  gint        offset = 0;
  static int * const indicators1_fields[] = {
    &hf_isup_odd_even_indicator,
    &hf_isup_called_party_nature_of_address_indicator,
    NULL
  };
  static int * const indicators2_fields[] = {
    &hf_isup_inn_indicator,
    &hf_isup_numbering_plan_indicator,
    NULL
  };

  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 0, 1, indicators1_fields, ENC_NA);
  indicators1 = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 1, 1, indicators2_fields, ENC_NA);
  offset = 2;

  dissect_isup_digits_common(parameter_tvb, offset, pinfo, parameter_tree, parameter_item,
                             hf_isup_redirection_number, hf_isup_called_party_odd_address_signal_digit,
                             hf_isup_called_party_even_address_signal_digit, ((indicators1 & 0x80) == 0),
                             NONE, 0);
}

/* ------------------------------------------------------------------
  Dissector Parameter Connection request
 */
static void
dissect_isup_connection_request_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 local_ref;
  guint16 spc;
  guint8  protocol_class, credit, offset = 0;

  local_ref = tvb_get_ntoh24(parameter_tvb, 0);
  proto_tree_add_item(parameter_tree, hf_isup_local_reference, parameter_tvb, offset, LOCAL_REF_LENGTH, ENC_BIG_ENDIAN);
  offset = LOCAL_REF_LENGTH;
  spc = tvb_get_letohs(parameter_tvb, offset) & 0x3FFF; /*since 1st 2 bits spare */
  proto_tree_add_item(parameter_tree, hf_isup_signalling_point_code, parameter_tvb, offset, SPC_LENGTH, ENC_BIG_ENDIAN);
  offset += SPC_LENGTH;
  protocol_class = tvb_get_guint8(parameter_tvb, offset);
  proto_tree_add_item(parameter_tree, hf_isup_protocol_class, parameter_tvb, offset, PROTOCOL_CLASS_LENGTH, ENC_BIG_ENDIAN);
  offset += PROTOCOL_CLASS_LENGTH;
  credit = tvb_get_guint8(parameter_tvb, offset);
  proto_tree_add_item(parameter_tree, hf_isup_credit, parameter_tvb, offset, CREDIT_LENGTH, ENC_BIG_ENDIAN);

  proto_item_append_text(parameter_item,
                      " : Local Reference = %u, SPC = %u, Protocol Class = %u, Credit = %u",
                      local_ref, spc, protocol_class, credit);
}
/* ------------------------------------------------------------------
  Dissector Parameter Redirection information
 */
void
dissect_isup_redirection_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  if (tvb_reported_length(parameter_tvb) == 2) {
    guint16 indicators;
    indicators = tvb_get_ntohs(parameter_tvb, 0);
    proto_tree_add_uint(parameter_tree, hf_isup_redirecting_ind, parameter_tvb, 0, REDIRECTION_INFO_LENGTH, indicators);
    proto_tree_add_uint(parameter_tree, hf_isup_original_redirection_reason, parameter_tvb, 0, REDIRECTION_INFO_LENGTH, indicators);
    proto_tree_add_uint(parameter_tree, hf_isup_redirection_counter, parameter_tvb, 0, REDIRECTION_INFO_LENGTH, indicators);
    proto_tree_add_uint(parameter_tree, hf_isup_redirection_reason, parameter_tvb, 0, REDIRECTION_INFO_LENGTH, indicators);
  }
  else { /* ISUP'88 (blue book) */
    guint16 indicators;
    indicators = tvb_get_guint8(parameter_tvb, 0) * 0x100; /*since 2nd octet isn't present*/
    proto_tree_add_uint(parameter_tree, hf_isup_redirecting_ind, parameter_tvb, 0, 1, indicators);
    proto_tree_add_uint(parameter_tree, hf_isup_original_redirection_reason, parameter_tvb, 0, 1, indicators);
    proto_item_append_text(parameter_item, " (2nd octet not present since ISUP '88)");
  }
}
/* ------------------------------------------------------------------
  Dissector Parameter Closed user group interlock code
 */
static void
dissect_isup_closed_user_group_interlock_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  char    NI_digits[5] = "";
  guint8  digit_pair;
  guint16 bin_code;

  digit_pair = tvb_get_guint8(parameter_tvb, 0);
  NI_digits[0] = number_to_char((digit_pair & HGFE_8BIT_MASK) / 0x10);
  NI_digits[1] = number_to_char(digit_pair & DCBA_8BIT_MASK);
  digit_pair = tvb_get_guint8(parameter_tvb, 1);
  NI_digits[2] = number_to_char((digit_pair & HGFE_8BIT_MASK) / 0x10);
  NI_digits[3] = number_to_char(digit_pair & DCBA_8BIT_MASK);
  NI_digits[4] = '\0';
  proto_tree_add_string(parameter_tree, hf_isup_network_identity, parameter_tvb, 0, 2, NI_digits);
  bin_code = tvb_get_ntohs(parameter_tvb, 2);
  proto_tree_add_item(parameter_tree, hf_isup_binary_code, parameter_tvb, 2, 2, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " : NI = %s, Binary code = 0x%x", NI_digits, bin_code);
}
/* ------------------------------------------------------------------
  Dissector Parameter User service information- no detailed dissection since defined in Rec. Q.931
 */
static void
dissect_isup_user_service_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{ guint length = tvb_reported_length(parameter_tvb);
  proto_tree_add_item(parameter_tree, hf_isup_user_service_information, parameter_tvb, 0, length, ENC_NA);
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
  proto_tree_add_item(parameter_tree, hf_isup_signalling_point_code, parameter_tvb, 0, SIGNALLING_POINT_CODE_LENGTH, ENC_BIG_ENDIAN);

  proto_item_append_text(parameter_item, " : %u", spc);
}
/* ------------------------------------------------------------------
  Dissector Parameter Connected number
 */
static void
dissect_isup_connected_number_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8      indicators1;
  gint        offset = 0;
  static int * const indicators1_fields[] = {
    &hf_isup_odd_even_indicator,
    &hf_isup_calling_party_nature_of_address_indicator,
    NULL
  };
  static int * const indicators2_fields[] = {
    &hf_isup_numbering_plan_indicator,
    &hf_isup_address_presentation_restricted_indicator,
    &hf_isup_screening_indicator,
    NULL
  };

  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 0, 1, indicators1_fields, ENC_NA);
  indicators1 = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 1, 1, indicators2_fields, ENC_NA);
  offset = 2;

  dissect_isup_digits_common(parameter_tvb, offset, pinfo, parameter_tree, parameter_item,
                             hf_isup_connected_number, hf_isup_calling_party_odd_address_signal_digit,
                             hf_isup_calling_party_even_address_signal_digit, ((indicators1 & 0x80) == 0),
                             NONE, 0);
}

/* ------------------------------------------------------------------
  Dissector Transit network selection
 */
static void
dissect_isup_transit_network_selection_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8      indicators1;
  gint        offset = 0;
  static int * const indicators_fields[] = {
    &hf_isup_odd_even_indicator,
    &hf_isup_type_of_network_identification,
    &hf_isup_network_identification_plan,
    NULL
  };

  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 0, 1, indicators_fields, ENC_NA);
  indicators1 = tvb_get_guint8(parameter_tvb, 0);
  offset = 1;

  dissect_isup_digits_common(parameter_tvb, offset, pinfo, parameter_tree, parameter_item,
                             hf_isup_transit_network_selection, hf_isup_calling_party_odd_address_signal_digit,
                             hf_isup_calling_party_even_address_signal_digit, ((indicators1 & 0x80) == 0),
                             NONE, 0);
}

/* ------------------------------------------------------------------
  Dissector Parameter Circuit assignment map
 */
static void
dissect_isup_circuit_assignment_map_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{ guint8 map_type;

  map_type = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_isup_map_type, parameter_tvb, 0, 1, map_type);
  proto_tree_add_item(parameter_tree, hf_isup_circuit_assignment_map, parameter_tvb, 1, 5, ENC_NA);
}
/* ------------------------------------------------------------------
  Dissector Parameter Automatic congestion level
 */
static void
dissect_isup_automatic_congestion_level_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 congestion_level;

  congestion_level = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_isup_automatic_congestion_level, parameter_tvb, 0, AUTO_CONGEST_LEVEL_LENGTH, congestion_level);
  proto_item_append_text(parameter_item, " : %s (%u)",
                      val_to_str_const(congestion_level, isup_auto_congestion_level_value, "spare"), congestion_level);
}
/* ------------------------------------------------------------------
  Dissector Parameter Optional backward Call indicators
 */
static void
dissect_isup_optional_backward_call_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  static int * const indicators[] = {
    &hf_isup_inband_information_ind,
    &hf_isup_call_diversion_may_occur_ind,
    &hf_isup_simple_segmentation_ind,
    &hf_isup_mlpp_user_ind,
    NULL
  };

  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 0, OPTIONAL_BACKWARD_CALL_IND_LENGTH, indicators, ENC_NA);

  proto_item_append_text(parameter_item, " : 0x%x", tvb_get_guint8(parameter_tvb, 0));
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
static const true_false_string isup_UUI_network_discard_ind_value = {
  "User-to-user information discarded by the network",
  "No information"
};

static void
dissect_isup_user_to_user_indicators_parameter(tvbuff_t *parameter_tvb,
                                               proto_tree *parameter_tree,
                                               proto_item *parameter_item)
{
  guint8 indicators;
  static int * const req_fields[] = {
    &hf_isup_UUI_type,
    &hf_isup_UUI_req_service1,
    &hf_isup_UUI_req_service2,
    &hf_isup_UUI_req_service3,
    NULL
  };
  static int * const res_fields[] = {
    &hf_isup_UUI_type,
    &hf_isup_UUI_res_service1,
    &hf_isup_UUI_res_service2,
    &hf_isup_UUI_res_service3,
    &hf_isup_UUI_network_discard_ind,
    NULL
  };

  indicators = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_isup_UUI_type, parameter_tvb, 0, 1, indicators);
  if ((indicators & 0x01) == 0) {
    /* Request */
    proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 0, 1, req_fields, ENC_NA);
  }
  else {
    /* Response */
    proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 0, 1, res_fields, ENC_NA);
  }
  proto_item_append_text(parameter_item, " : 0x%x", indicators);
}
/* ------------------------------------------------------------------
  Dissector Parameter Original ISC point code
 */
static void
dissect_isup_original_isc_point_code_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 spc;

  spc = tvb_get_letohs(parameter_tvb, 0) & 0x3FFF; /*since 1st 2 bits spare */
  proto_tree_add_item(parameter_tree, hf_isup_origination_isc_point_code, parameter_tvb, 0, ORIGINAL_ISC_POINT_CODE_LENGTH, ENC_BIG_ENDIAN);

  proto_item_append_text(parameter_item, " : %u", spc);
}
/* ------------------------------------------------------------------
   Dissector Parameter Generic notification indicator

   3.25 Generic notification indicator

   a) Extension indicator (ext.)
   0 information continues in the next octet
   1 last octet

   b) Notification indicator
   0 0 0 0 0 0 0 user suspended
   0 0 0 0 0 0 1 user resumed
   0 0 0 0 0 1 0 bearer service change
   0 0 0 0 0 1 1 encoded component discriminator for extension to ASN.1 (used in DSS1)
   0 0 0 0 1 0 0 call completion delay
   
   1 0 0 0 0 0 1
   to
   0 0 0 0 1 0 1 reserved

   1 0 0 0 0 1 0 conference established
   1 0 0 0 0 1 1 conference disconnected
   1 0 0 0 1 0 0 other party added
   1 0 0 0 1 0 1 isolated
   1 0 0 0 1 1 0 reattached
   1 0 0 0 1 1 1 other party isolated
   1 0 0 1 0 0 0 other party reattached
   1 0 0 1 0 0 1 other party split
   1 0 0 1 0 1 0 other party disconnected
   1 0 0 1 0 1 1 conference floating
   
   1 0 1 1 1 1 1
   to
   1 0 0 1 1 0 0 reserved

   1 1 0 0 0 0 0 call is a waiting call
   
   1 1 0 0 1 1 1
   to
   1 1 0 0 0 0 1 reserved

   1 1 0 1 0 0 0 diversion activated (used in DSS1)
   1 1 0 1 0 0 1 call transfer, alerting
   1 1 0 1 0 1 0 call transfer, active
   
   
   
   1 1 1 1 0 0 0
   to
   1 1 0 1 0 1 1
   reserved
   1 1 1 1 0 0 1 remote hold
   1 1 1 1 0 1 0 remote retrieval
   1 1 1 1 0 1 1 call is diverting
   
   
   
   1 1 1 1 1 1 1
   to
   1 1 1 1 1 0 0
   reserved
*/
static const value_string q763_generic_notification_indicator_vals[] = {
    { 0x00 , "User Suspended" },
    { 0x01 , "User Resumed" },
    { 0x02 , "Bearer service change" },
    { 0x03 , "Discriminator for extension to ASN.1 encoded component (used in DSS1)" },
    { 0x04 , "Call completion delay" },
    { 0x42 , "Conference established" },
    { 0x43 , "Conference disconnected" },
    { 0x44 , "Other party added" },
    { 0x45 , "Isolated" },
    { 0x46 , "Reattached" },
    { 0x47 , "Other party isolated" },
    { 0x48 , "Other party reattached" },
    { 0x49 , "Other party split" },
    { 0x4A , "Other party disconnected" },
    { 0x4B , "Conference floating" },
    { 0x60 , "Call is a waiting call" },
    { 0x68 , "Diversion activated (used in DSS1)" },
    { 0x69 , "Call transfer, alerting" },
    { 0x6A , "Call transfer, active" },
    { 0x79 , "Remote hold" },
    { 0x7A , "Remote retrieval" },
    { 0x7B , "Call is diverting" },
    { 0 , NULL },
};
static value_string_ext q763_generic_notification_indicator_vals_ext = VALUE_STRING_EXT_INIT(q763_generic_notification_indicator_vals);

static void
dissect_isup_generic_notification_indicator_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 indicators;

  indicators = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_item(parameter_tree, hf_isup_extension_ind, parameter_tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_isup_notification_indicator, parameter_tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item, " : %s",
                      val_to_str_ext((indicators&0x7f), &q763_generic_notification_indicator_vals_ext, "Reserved (0x%X)"));
}
/* ------------------------------------------------------------------
  Dissector Parameter Call history information
 */
static void
dissect_isup_call_history_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint16 info;

  info = tvb_get_ntohs(parameter_tvb, 0);
  proto_tree_add_uint_format_value(parameter_tree, hf_isup_call_history_info, parameter_tvb, 0, CALL_HISTORY_INFO_LENGTH, info, "propagation delay = %u ms", info);
  proto_item_append_text(parameter_item, " : propagation delay = %u ms", info);
}
/* ------------------------------------------------------------------
  Dissector Parameter Access delivery information
 */
static void
dissect_isup_access_delivery_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_isup_access_delivery_ind, parameter_tvb, 0, ACCESS_DELIVERY_INFO_LENGTH, indicator);
  proto_item_append_text(parameter_item, " : 0x%x", indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter Network specific facility
 */
static void
dissect_isup_network_specific_facility_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{ guint length = tvb_reported_length(parameter_tvb);
  proto_tree_add_item(parameter_tree, hf_isup_network_specific_facility, parameter_tvb, 0, length, ENC_NA);
}
/* ------------------------------------------------------------------
  Dissector Parameter User service information prime
 */
static void
dissect_isup_user_service_information_prime_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{ guint length = tvb_reported_length(parameter_tvb);
  proto_tree_add_item(parameter_tree, hf_isup_user_service_information_prime, parameter_tvb, 0, length, ENC_NA);
  dissect_q931_bearer_capability_ie(parameter_tvb,
                                    0, length,
                                    parameter_tree);
}
/* ------------------------------------------------------------------
  Dissector Parameter Propagation delay counter
 */
static void
dissect_isup_propagation_delay_counter_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint32 info;

  proto_tree_add_item_ret_uint(parameter_tree, hf_isup_propagation_delay_counter, parameter_tvb, 0, PROPAGATION_DELAY_COUNT_LENGTH, ENC_BIG_ENDIAN, &info);
  proto_item_append_text(parameter_item, ": counter = %u ms", info);
}
/* ------------------------------------------------------------------
  Dissector Parameter Remote operations
 */
static void
dissect_isup_remote_operations_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{ guint length = tvb_reported_length(parameter_tvb);
  proto_tree_add_item(parameter_tree, hf_isup_remote_operations, parameter_tvb, 0, length, ENC_NA);
}
/* ------------------------------------------------------------------
  Dissector Parameter Service activation
 */
static void
dissect_isup_service_activation_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{
  guint  i;
  guint8 feature_code;
  guint  length = tvb_reported_length(parameter_tvb);

  for (i=0; i<length; i++) {
    feature_code = tvb_get_guint8(parameter_tvb, i);
    proto_tree_add_uint_format(parameter_tree, hf_isup_feature_code, parameter_tvb, i, 1, feature_code, "Feature Code %u: %u", i+1, feature_code);
  }
}
/* ------------------------------------------------------------------
  Dissector Parameter User service information prime - no detailed dissection since defined in Rec. Q.931
 */
static void
dissect_isup_user_teleservice_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{
  guint length = tvb_reported_length(parameter_tvb);
  proto_tree_add_item(parameter_tree, hf_isup_user_teleservice_information, parameter_tvb, 0, length, ENC_NA);

  dissect_q931_high_layer_compat_ie(parameter_tvb, 0, length, parameter_tree);
}
/* ------------------------------------------------------------------
  Dissector Parameter Transmission medium requirement used
 */
static void
dissect_isup_transmission_medium_used_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 transmission_medium_requirement;

  transmission_medium_requirement = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_isup_transmission_medium_requirement_prime,
                      parameter_tvb, 0, TRANSMISSION_MEDIUM_RQMT_PRIME_LENGTH, transmission_medium_requirement);

  proto_item_append_text(parameter_item,
                      " : %u (%s)",
                      transmission_medium_requirement,
                      val_to_str_ext_const(transmission_medium_requirement,
                                           &isup_transmission_medium_requirement_prime_value_ext,
                                           "spare/reserved"));
}
/* ------------------------------------------------------------------
  Dissector Parameter Call diversion information
 */
static void
dissect_isup_call_diversion_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint_format_value(parameter_tree, hf_isup_call_diversion_information, parameter_tvb, 0, CALL_DIV_INFO_LENGTH, indicator,
        "0x%x (refer to 3.6/Q.763 for detailed decoding)", indicator);
  proto_item_append_text(parameter_item, " : 0x%x", indicator);
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
  static int * const info[] = {
    &hf_isup_OECD_inf_ind,
    &hf_isup_IECD_inf_ind,
    &hf_isup_OECD_req_ind,
    &hf_isup_IECD_req_ind,
    NULL
  };

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_bitmask(parameter_tree, parameter_tvb, 0, hf_isup_echo_control_information, ett_echo_control_information, info, ENC_NA);

  proto_item_append_text(parameter_item, " : 0x%x", indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter Message compatibility information
 */

static const true_false_string isup_pass_on_not_possible_indicator_value = {
  "discard information",
  "release call",
};

static void
dissect_isup_message_compatibility_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{
  gint  offset = 0;

  static int * const params[] = {
    &hf_isup_transit_at_intermediate_exchange_ind,
    &hf_isup_Release_call_ind,
    &hf_isup_Send_notification_ind,
    &hf_isup_Discard_message_ind_value,
    &hf_isup_pass_on_not_possible_indicator2,
    &hf_isup_Broadband_narrowband_interworking_ind2,
    &hf_isup_extension_ind,
    NULL
  };

  proto_tree_add_bitmask(parameter_tree, parameter_tvb, offset, hf_isup_message_compatibility_information, ett_message_compatibility_information, params, ENC_NA);
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
dissect_isup_parameter_compatibility_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{
  guint  length = tvb_reported_length(parameter_tvb);
  guint  len    = length;
  guint8 upgraded_parameter, upgraded_parameter_no;
  guint8 offset;
  guint8 instruction_indicators;

  static int * const indicator_flags[] = {
    &hf_isup_transit_at_intermediate_exchange_ind,
    &hf_isup_Release_call_ind,
    &hf_isup_Send_notification_ind,
    &hf_isup_Discard_message_ind_value,
    &hf_isup_Discard_parameter_ind,
    &hf_isup_Pass_on_not_possible_indicator,
    &hf_isup_extension_ind,
    NULL
  };

  offset = 0;
  upgraded_parameter_no = 0;

/* etxrab Decoded as per Q.763 section 3.41 */

  while (len > 0) {
  upgraded_parameter_no = upgraded_parameter_no + 1;
  upgraded_parameter = tvb_get_guint8(parameter_tvb, offset);

  proto_tree_add_uint_format(parameter_tree, hf_isup_upgraded_parameter, parameter_tvb, offset, 1, upgraded_parameter,
                      "Upgraded parameter no: %u = %s", upgraded_parameter_no,
                      val_to_str_ext(upgraded_parameter, &isup_parameter_type_value_ext, "unknown (%u)"));
  offset += 1;
  len -= 1;
  instruction_indicators = tvb_get_guint8(parameter_tvb, offset);
  proto_tree_add_bitmask(parameter_tree, parameter_tvb, offset, hf_isup_instruction_indicators, ett_instruction_indicators, indicator_flags, ENC_NA);

  offset += 1;
  len -= 1;
  if (!(instruction_indicators & H_8BIT_MASK)) {
    if (len == 0)
      return;
    instruction_indicators = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(parameter_tree, hf_isup_Broadband_narrowband_interworking_ind,
                        parameter_tvb, offset, 1, instruction_indicators);
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
static const value_string isup_mlpp_precedence_look_forward_busy_vals[] = {
    { 0x00 , "Allowed" },
    { 0x01 , "Not Allowed" },
    { 0x02 , "Path reserved" },
    { 0x03 , "Spare" },
    { 0 , NULL },
};

static const value_string isup_mlpp_precedence_level_vals[] = {
    { 0x00 , "Flash Override" },
    { 0x01 , "Flash" },
    { 0x02 , "Immediate" },
    { 0x03 , "Priority" },
    { 0x04 , "Routine" },
    { 0x05 , "Spare" },
    { 0x06 , "Spare" },
    { 0x07 , "Spare" },
    { 0x08 , "Spare" },
    { 0x09 , "Spare" },
    { 0x0A , "Spare" },
    { 0x0B , "Spare" },
    { 0x0C , "Spare" },
    { 0x0D , "Spare" },
    { 0x0E , "Spare" },
    { 0x0F , "Spare" },
    { 0 , NULL },
};

static void
dissect_isup_mlpp_precedence_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  char        NI_digits[5] = "";
  const char *temp_text = "";
  guint8      digit_pair;
  guint32     bin_code;

  proto_tree_add_item(parameter_tree, hf_isup_look_forward_busy, parameter_tvb, 0, 1, ENC_NA);

  proto_tree_add_item(parameter_tree, hf_isup_precedence_level, parameter_tvb, 0, 1, ENC_NA);

  digit_pair   = tvb_get_guint8(parameter_tvb, 1);
  NI_digits[0] = number_to_char((digit_pair & HGFE_8BIT_MASK) / 0x10);
  NI_digits[1] = number_to_char(digit_pair & DCBA_8BIT_MASK);
  digit_pair   = tvb_get_guint8(parameter_tvb, 2);
  NI_digits[2] = number_to_char((digit_pair & HGFE_8BIT_MASK) / 0x10);
  NI_digits[3] = number_to_char(digit_pair & DCBA_8BIT_MASK);
  NI_digits[4] = '\0';
  proto_tree_add_string(parameter_tree, hf_isup_network_identity, parameter_tvb, 1, 2, NI_digits);
  bin_code = tvb_get_ntoh24(parameter_tvb, 3);
  proto_tree_add_item(parameter_tree, hf_isup_mlpp_service_domain, parameter_tvb, 3, 3, ENC_BIG_ENDIAN);
  proto_item_append_text(parameter_item,
                      " : Prec = %s, NI = %s, MLPP service domain = 0x%x", temp_text, NI_digits, bin_code);
}
/* ------------------------------------------------------------------
  Dissector Parameter MCID request indicators
 */
static void
dissect_isup_mcid_request_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint_format_value(parameter_tree, hf_isup_mcid_request_indicators, parameter_tvb, 0, MCID_REQUEST_IND_LENGTH, indicator, "0x%x (MCID requested by Bit1=1, Holding requested by Bit2=1 see 3.31/Q.763)", indicator);
  proto_item_append_text(parameter_item, " : 0x%x", indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter MCID response indicators
 */
static void
dissect_isup_mcid_response_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint_format_value(parameter_tree, hf_isup_mcid_response_indicators, parameter_tvb, 0, MCID_RESPONSE_IND_LENGTH, indicator, "0x%x (MCID included if Bit1=1, Holding provided if Bit2=1 see 3.32/Q.763)", indicator);
  proto_item_append_text(parameter_item, " : 0x%x", indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter Hop counter
 */
static void
dissect_isup_hop_counter_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 counter;

  counter = tvb_get_guint8(parameter_tvb, 0) & EDCBA_8BIT_MASK; /* since bits H,G and F are spare */
  proto_tree_add_item(parameter_tree, hf_isup_hop_counter, parameter_tvb, 0, HOP_COUNTER_LENGTH, ENC_NA);
  proto_item_append_text(parameter_item, " : %u", counter);
}
/* ------------------------------------------------------------------
  Dissector Parameter Originating line information
 */
static void
dissect_isup_orig_line_info_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 info;

  info = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_item(parameter_tree, hf_isup_originating_line_info, parameter_tvb, 0, ORIG_LINE_INFO_LENGTH, ENC_NA);
  proto_item_append_text(parameter_item,  " : %u (ANI II if < 51, reserved otherwise)", info);
}
/* ------------------------------------------------------------------
  Dissector Parameter Transmission medium requirement prime
 */
static void
dissect_isup_transmission_medium_requirement_prime_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 transmission_medium_requirement;

  transmission_medium_requirement = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_isup_transmission_medium_requirement_prime,
                      parameter_tvb, 0, TRANSMISSION_MEDIUM_RQMT_PRIME_LENGTH, transmission_medium_requirement);

  proto_item_append_text(parameter_item,
                      " : %u (%s)",
                      transmission_medium_requirement,
                      val_to_str_ext_const(transmission_medium_requirement,
                                           &isup_transmission_medium_requirement_prime_value_ext,
                                           "spare/reserved"));
}

/* ------------------------------------------------------------------
  Dissector Parameter location number
 */
void
dissect_isup_location_number_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8      indicators1, indicators2;
  gint        offset = 0;
  static int * const indicators1_fields[] = {
    &hf_isup_odd_even_indicator,
    &hf_isup_calling_party_nature_of_address_indicator,
    NULL
  };

  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 0, 1, indicators1_fields, ENC_NA);
  indicators1 = tvb_get_guint8(parameter_tvb, 0);
  indicators2 = tvb_get_guint8(parameter_tvb, 1);
  proto_tree_add_boolean(parameter_tree, hf_isup_inn_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_numbering_plan_indicator, parameter_tvb, 1, 1, indicators2);
  if ((indicators2 & GFE_8BIT_MASK) == 0x50) {
    proto_tree_add_uint_format_value(parameter_tree, hf_isup_number_different_meaning, parameter_tvb, 1, 1, indicators2 & GFE_8BIT_MASK,
                                     "Numbering plan indicator = private numbering plan");
  }
  proto_tree_add_uint(parameter_tree, hf_isup_address_presentation_restricted_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_screening_indicator, parameter_tvb, 1, 1, indicators2);

   /* NOTE  When the address presentation restricted indicator indicates address not available, the
    * subfields in items a), b), c) and d) are coded with 0's, and the screening indicator is set to 11
    * (network provided).
    * BUG 938 - Just check if there is someting more to dissect.
    */
  if (tvb_reported_length_remaining(parameter_tvb, offset) < 3) {
    proto_item_append_text(parameter_item, " : address not available");
    return;
  }

  offset = 2;

  dissect_isup_digits_common(parameter_tvb, offset, pinfo, parameter_tree, parameter_item,
                             hf_isup_location_number, hf_isup_calling_party_odd_address_signal_digit,
                             hf_isup_calling_party_even_address_signal_digit, ((indicators1 & 0x80) == 0),
                             NONE, 0);
}

/* ------------------------------------------------------------------
  Dissector Parameter Redirection number restriction
 */
static const value_string isup_redirection_presentation_indicator_vals[] = {
    { 0x00 , "Presentation allowed" },
    { 0x01 , "Presentation restricted" },
    { 0x02 , "Spare" },
    { 0x03 , "Spare" },
    { 0 , NULL },
};

static void
dissect_isup_redirection_number_restriction_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_item(parameter_tree, hf_isup_presentation_indicator, parameter_tvb, 0, REDIRECTION_NUMBER_RESTRICTION_LENGTH, ENC_NA);
  proto_item_append_text(parameter_item, " : 0x%x ", indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter Call transfer identity
 */
static void
dissect_isup_call_transfer_reference_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 id;

  id = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_item(parameter_tree, hf_isup_call_transfer_identity, parameter_tvb, 0, CALL_TRANSFER_REF_LENGTH, ENC_NA);
  proto_item_append_text(parameter_item,  " : %u", id);
}
/* ------------------------------------------------------------------
  Dissector Parameter Loop prevention
 */

static void
dissect_isup_loop_prevention_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_item(parameter_tree, hf_isup_loop_prevention_indicator_type, parameter_tvb, 0, LOOP_PREVENTION_IND_LENGTH, ENC_NA);
  if ((indicator & A_8BIT_MASK) == 0) {
    proto_item_append_text(parameter_item, " : Request (%u)", indicator);
  }
  else {
    proto_tree_add_uint(parameter_tree, hf_isup_loop_prevention_response_ind,
                        parameter_tvb, 0, LOOP_PREVENTION_IND_LENGTH, indicator);
    proto_item_append_text(parameter_item, " : Response (%u)", indicator);
  }
}

/* ------------------------------------------------------------------
  Dissector Parameter Call transfer number
 */
static void
dissect_isup_call_transfer_number_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8      indicators1, indicators2;
  gint        offset = 0;

  indicators1 = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_isup_odd_even_indicator, parameter_tvb, 0, 1, indicators1);
  proto_tree_add_uint(parameter_tree, hf_isup_calling_party_nature_of_address_indicator, parameter_tvb, 0, 1, indicators1);
  indicators2 = tvb_get_guint8(parameter_tvb, 1);
  proto_tree_add_uint(parameter_tree, hf_isup_numbering_plan_indicator, parameter_tvb, 1, 1, indicators2);
  if ((indicators2 & GFE_8BIT_MASK) == 0x50)
    proto_tree_add_uint_format_value(parameter_tree, hf_isup_number_different_meaning, parameter_tvb, 1, 1, indicators2 & GFE_8BIT_MASK,
                    "Numbering plan indicator = private numbering plan");
  proto_tree_add_uint(parameter_tree, hf_isup_address_presentation_restricted_indicator, parameter_tvb, 1, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_screening_indicator_enhanced, parameter_tvb, 1, 1, indicators2);
  offset = 2;

  dissect_isup_digits_common(parameter_tvb, offset, pinfo, parameter_tree, parameter_item,
                             hf_isup_call_transfer_number, hf_isup_calling_party_odd_address_signal_digit,
                             hf_isup_calling_party_even_address_signal_digit, ((indicators1 & 0x80) == 0),
                             NONE, 0);
}

/* ------------------------------------------------------------------
  Dissector Parameter CCSS
 */
static const true_false_string tfs_ccss_call_no_indication = { "CCSS call", "no indication"};

static void
dissect_isup_ccss_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_item(parameter_tree, hf_isup_ccss_call_indicator, parameter_tvb, 0, LOOP_PREVENTION_IND_LENGTH, ENC_NA);
  if ((indicator & A_8BIT_MASK) == 0) {
    proto_item_append_text(parameter_item, " : no indication (%u)", indicator);
  }
  else {
    proto_item_append_text(parameter_item, " : CCSS call (%u)", indicator);
  }
}
/* ------------------------------------------------------------------
 Parameter Forward GVNS
 */
static void
dissect_isup_forward_gvns_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{ guint length = tvb_reported_length(parameter_tvb);
  proto_tree_add_item(parameter_tree, hf_isup_forward_gvns, parameter_tvb, 0, length, ENC_NA);
}
/* ------------------------------------------------------------------
 Parameter Redirect capability
 */

static const value_string isup_jpn_redirect_capabilit_vals[] = {
  { 0,   "Reserved" },
  { 1,   "Redirect possible before ACM" },
  { 2,   "Reserved" },
  { 3,   "Reserved" },
  { 4,   "Spare" },
  { 5,   "Spare" },
  { 6,   "Spare" },
  { 7,   "Spare" },
  { 0,   NULL}
};

static void
dissect_isup_redirect_capability_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_, guint8 itu_isup_variant)
{
  guint length = tvb_reported_length(parameter_tvb);

  switch (itu_isup_variant) {
    case ISUP_JAPAN_VARIANT:
    /* Fall through */
    case ISUP_JAPAN_TTC_VARIANT:
      proto_tree_add_item(parameter_tree, hf_isup_extension_ind,             parameter_tvb, 0, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(parameter_tree, hf_japan_isup_redirect_capability, parameter_tvb, 0, 1, ENC_BIG_ENDIAN);
      break;
    default:
      proto_tree_add_uint_format_value(parameter_tree, hf_isup_redirect_capability, parameter_tvb, 0, length, itu_isup_variant, "(format is a national matter)");
      break;
  }
}
/* ------------------------------------------------------------------
  Dissector Parameter Backward GVNS
 */
static void
dissect_isup_backward_gvns_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint_format_value(parameter_tree, hf_isup_backward_gvns, parameter_tvb, 0, BACKWARD_GVNS_LENGTH, indicator,
                    "0x%x (refer to 3.62/Q.763 for detailed decoding)", indicator);
  proto_item_append_text(parameter_item, " : 0x%x", indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter Network management controls
 */
static void
dissect_isup_network_management_controls_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_boolean(parameter_tree, hf_isup_temporary_alternative_routing_ind,
                         parameter_tvb, 0, NETWORK_MANAGEMENT_CONTROLS_LENGTH, indicator);
  proto_tree_add_boolean(parameter_tree, hf_isup_extension_ind, parameter_tvb, 0, NETWORK_MANAGEMENT_CONTROLS_LENGTH, indicator);
  proto_item_append_text(parameter_item, " : 0x%x", indicator);
}
/* ------------------------------------------------------------------
  Dissector Parameter Correlation id - no detailed dissection since defined in Rec. Q.1281
 */
static void
dissect_isup_correlation_id_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{ guint length = tvb_reported_length(parameter_tvb);
  proto_tree_add_item(parameter_tree, hf_isup_correlation_id, parameter_tvb, 0, length, ENC_NA);
}
/* ------------------------------------------------------------------
  Dissector Parameter SCF id - no detailed dissection since defined in Rec. Q.1281
 */
static void
dissect_isup_scf_id_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{ guint length = tvb_reported_length(parameter_tvb);
  proto_tree_add_item(parameter_tree, hf_isup_scf_id, parameter_tvb, 0, length, ENC_NA);
}
/* ------------------------------------------------------------------
  Dissector Parameter Call diversion treatment indicators
 */
static void
dissect_isup_call_diversion_treatment_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_isup_call_to_be_diverted_ind, parameter_tvb, 0, CALL_DIV_TREATMENT_IND_LENGTH, indicator);
  proto_tree_add_boolean(parameter_tree, hf_isup_extension_ind, parameter_tvb, 0, CALL_DIV_TREATMENT_IND_LENGTH, indicator);
  proto_item_append_text(parameter_item, " : 0x%x", indicator);
}

/* ------------------------------------------------------------------
  Dissector Parameter called IN  number
 */
static void
dissect_isup_called_in_number_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8      indicators1;
  gint        offset = 0;
  static int * const indicators1_fields[] = {
    &hf_isup_odd_even_indicator,
    &hf_isup_calling_party_nature_of_address_indicator,
    NULL
  };
  static int * const indicators2_fields[] = {
    &hf_isup_numbering_plan_indicator,
    &hf_isup_address_presentation_restricted_indicator,
    NULL
  };

  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 0, 1, indicators1_fields, ENC_NA);
  indicators1 = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 1, 1, indicators2_fields, ENC_NA);
  offset = 2;

  dissect_isup_digits_common(parameter_tvb, offset, pinfo, parameter_tree, parameter_item,
                             hf_isup_called_in_number, hf_isup_calling_party_odd_address_signal_digit,
                             hf_isup_calling_party_even_address_signal_digit, ((indicators1 & 0x80) == 0),
                             NONE, 0);
}

/* ------------------------------------------------------------------
  Dissector Parameter Call offering treatment indicators
 */
static void
dissect_isup_call_offering_treatment_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_isup_call_to_be_offered_ind, parameter_tvb, 0, CALL_OFFERING_TREATMENT_IND_LENGTH, indicator);
  proto_tree_add_boolean(parameter_tree, hf_isup_extension_ind, parameter_tvb, 0, CALL_OFFERING_TREATMENT_IND_LENGTH, indicator);
  proto_item_append_text(parameter_item, " : 0x%x", indicator);
}
/* ------------------------------------------------------------------
 Parameter Charged party identification
 */
static void
dissect_isup_charged_party_identification_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{ guint length = tvb_reported_length(parameter_tvb);
  proto_tree_add_item(parameter_tree, hf_isup_charged_party_identification, parameter_tvb, 0, length, ENC_NA);
}
/* ------------------------------------------------------------------
  Dissector Parameter Conference treatment indicators
 */
static void
dissect_isup_conference_treatment_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_isup_conference_acceptance_ind, parameter_tvb, 0, CONFERENCE_TREATMENT_IND_LENGTH, indicator);
  proto_tree_add_boolean(parameter_tree, hf_isup_extension_ind, parameter_tvb, 0, CONFERENCE_TREATMENT_IND_LENGTH, indicator);
  proto_item_append_text(parameter_item, " : 0x%x", indicator);
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
dissect_isup_display_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{ guint length = tvb_reported_length(parameter_tvb);
  proto_tree_add_item(parameter_tree, hf_isup_display_information, parameter_tvb, 0, length, ENC_NA);
}
/* ------------------------------------------------------------------
 Parameter UID action indicators
 */
static void
dissect_isup_uid_action_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint_format_value(parameter_tree, hf_isup_uid_action_indicators, parameter_tvb, 0, UID_ACTION_IND_LENGTH, indicator,
        "0x%x (refer to 3.78/Q.763 for detailed decoding)", indicator);
  proto_item_append_text(parameter_item, " : 0x%x", indicator);
}
/* ------------------------------------------------------------------
 Parameter UID capability indicators
 */
static void
dissect_isup_uid_capability_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint_format_value(parameter_tree, hf_isup_uid_capability_indicators, parameter_tvb, 0, UID_CAPABILITY_IND_LENGTH,
                      indicator, "0x%x (refer to 3.79/Q.763 for detailed decoding)", indicator);
  proto_item_append_text(parameter_item, " : 0x%x", indicator);
}
/* ------------------------------------------------------------------
 Parameter Redirect counter
 */
static void
dissect_isup_redirect_counter_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_, guint8 itu_isup_variant)
{
  guint length = tvb_reported_length(parameter_tvb);

  switch (itu_isup_variant) {
    case ISUP_JAPAN_VARIANT:
    /* Fall through */
    case ISUP_JAPAN_TTC_VARIANT:
      proto_tree_add_item(parameter_tree, hf_japan_isup_redirect_counter, parameter_tvb, 0, 1, ENC_BIG_ENDIAN);
      break;
    default:
      proto_tree_add_uint_format_value(parameter_tree, hf_isup_redirect_counter, parameter_tvb, 0, length, itu_isup_variant, "(format is a national matter)");
      break;
  }
}
/* ------------------------------------------------------------------
  Dissector Parameter Collect call request
 */
static const true_false_string tfs_collect_call_req_no_indication = { "collect call requested", "no indication"};

static void
dissect_isup_collect_call_request_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item)
{ guint8 indicator;

  indicator = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_item(parameter_tree, hf_isup_collect_call_request_indicator, parameter_tvb, 0, COLLECT_CALL_REQUEST_LENGTH, ENC_NA);
  if ((indicator & A_8BIT_MASK) == 0) {
    proto_item_append_text(parameter_item, " : no indication (0x%x)", indicator);
  }
  else {
    proto_item_append_text(parameter_item, " : collect call requested (0x%x)", indicator);
  }
}
/* ------------------------------------------------------------------
  Dissector Parameter Calling geodetic location
 */
void
dissect_isup_calling_geodetic_location_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{
  guint  length = tvb_reported_length(parameter_tvb);
  guint8 oct, lpri;

  oct = tvb_get_guint8(parameter_tvb, 0);
  lpri = (oct & 0xc0) >> 2;

  proto_tree_add_uint(parameter_tree, hf_isup_geo_loc_presentation_restricted_ind, parameter_tvb, 0, 1, oct);
  proto_tree_add_uint(parameter_tree, hf_isup_geo_loc_screening_ind, parameter_tvb, 0, 1, oct);

  proto_tree_add_item(parameter_tree, hf_isup_extension_ind, parameter_tvb, 1, 1, ENC_NA);
  proto_tree_add_item(parameter_tree, hf_isup_geo_loc_shape, parameter_tvb, 1, 1, ENC_NA);

  if (length > 2)
  {
    if (lpri < 0x2)
    {
      proto_tree_add_item(parameter_tree, hf_isup_geo_loc_shape_description, parameter_tvb, 2, length - 2, ENC_NA);
    }
    else
    {
      /* not supposed to have any data if 'lpri' was 'location not available' */

      proto_tree_add_expert_format(parameter_tree, pinfo, &ei_isup_not_dissected_yet, parameter_tvb, 2, length - 2,
                "Unknown (?), should not have data if LPRI is 'location not available'");
    }
  }
}

/* ------------------------------------------------------------------
  Dissector Parameter Generic number
 */
static const range_string number_qualifier_indicator_vals[] = {
  { 0x00, 0x00, "reserved (dialled digits) (national use)"},
  { 0x01, 0x01, "additional called number (national use)"},
  { 0x02, 0x02, "reserved (supplemental user provided calling number - failed network screening) (national use)"},
  { 0x03, 0x03, "reserved (supplemental user provided calling number - not screened) (national use)"},
  { 0x04, 0x04, "reserved (redirecting terminating number) (national use)"},
  { 0x05, 0x05, "additional connected number"},
  { 0x06, 0x06, "additional calling party number"},
  { 0x07, 0x07, "reserved for additional original called number"},
  { 0x08, 0x08, "reserved for additional redirecting number"},
  { 0x09, 0x09, "reserved for additional redirection number"},
  { 0x0a, 0x0a, "reserved (used in 1992 version)"},
  { 0x0b, 0x7f, "spare"},
  { 0x80, 0xfe, "reserved for national use"},
  { 0xff, 0xff, "reserved for expansion"},
  { 0, 0, NULL}
};
void
dissect_isup_generic_number_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8      indicators1, indicators2;
  gint        offset = 0;
  static int * const indicators1_fields[] = {
    &hf_isup_odd_even_indicator,
    &hf_isup_calling_party_nature_of_address_indicator,
    NULL
  };

  proto_tree_add_item(parameter_tree, hf_isup_number_qualifier_indicator, parameter_tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb,1 , 1, indicators1_fields, ENC_NA);
  indicators1 = tvb_get_guint8(parameter_tvb, 1);
  indicators2 = tvb_get_guint8(parameter_tvb, 2);
  proto_tree_add_boolean(parameter_tree, hf_isup_ni_indicator, parameter_tvb, 2, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_numbering_plan_indicator, parameter_tvb, 2, 1, indicators2);
  if ((indicators2 & GFE_8BIT_MASK) == 0x50) {
    proto_tree_add_uint_format_value(parameter_tree, hf_isup_number_different_meaning, parameter_tvb, 2, 1, indicators2 & GFE_8BIT_MASK,
                                     "Numbering plan indicator = private numbering plan");
  }
  proto_tree_add_uint(parameter_tree, hf_isup_address_presentation_restricted_indicator, parameter_tvb, 2, 1, indicators2);
  proto_tree_add_uint(parameter_tree, hf_isup_screening_indicator_enhanced, parameter_tvb, 2, 1, indicators2);
  offset = 3;

  dissect_isup_digits_common(parameter_tvb, offset, pinfo, parameter_tree, parameter_item,
                             hf_isup_generic_number, hf_isup_calling_party_odd_address_signal_digit,
                             hf_isup_calling_party_even_address_signal_digit, ((indicators1 & 0x80) == 0),
                             NONE, 0);

  /*
   * Indicators1 = Nature of address
   * Indicators2 = Number plan indicator
   */
  indicators1 = indicators1 & 0x7f;
  indicators2 = (indicators2 & 0x70)>>4;
  if ((indicators1 == ISUP_CALLED_PARTY_NATURE_INTERNATNL_NR) && (indicators2 == ISDN_NUMBERING_PLAN))
    dissect_e164_cc(parameter_tvb, parameter_tree, 3, E164_ENC_BCD);
}

/* ------------------------------------------------------------------
  Dissector Parameter  Jurisdiction parameter
 */
static void
dissect_isup_jurisdiction_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  gint        offset = 0;

  offset = 0;

  dissect_isup_digits_common(parameter_tvb, offset, pinfo, parameter_tree, parameter_item,
                             hf_isup_jurisdiction, hf_isup_called_party_odd_address_signal_digit,
                             hf_isup_called_party_even_address_signal_digit, (tvb_reported_length(parameter_tvb) > 0),
                             NONE, 0);
}

/* ------------------------------------------------------------------
  Dissector Parameter Generic name
 */
static void
dissect_isup_generic_name_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  gint    gen_name_length;
  char   *gen_name = NULL;
  static int * const indicators[] = {
    &hf_isup_generic_name_presentation,
    &hf_isup_generic_name_availability,
    &hf_isup_generic_name_type,
    NULL
  };

  gen_name = (char *)wmem_alloc(pinfo->pool, MAXGNAME + 1);
  gen_name[0] = '\0';
  gen_name_length = tvb_reported_length(parameter_tvb) - 1;

  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 0, 1, indicators, ENC_NA);

  gen_name = tvb_get_string_enc(pinfo->pool, parameter_tvb, 1, gen_name_length, ENC_ASCII);
  gen_name[gen_name_length] = '\0';
  proto_tree_add_string(parameter_tree, hf_isup_generic_name_ia5, parameter_tvb, 1, gen_name_length, gen_name);
  proto_item_append_text(parameter_item, " : %s", gen_name);

  }

/* ------------------------------------------------------------------
 Dissector Parameter Generic digits
 */
void
dissect_isup_generic_digits_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{ guint length = tvb_reported_length(parameter_tvb);
  proto_tree_add_item(parameter_tree, hf_isup_generic_digits, parameter_tvb, 0, length, ENC_NA);
}

/* ------------------------------------------------------------------
  Dissector Parameter Charge number
 */
static void
dissect_isup_charge_number_parameter(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  guint8      indicators1;
  gint        offset = 0;
  static int * const indicators1_fields[] = {
    &hf_isup_odd_even_indicator,
    &hf_isup_charge_number_nature_of_address_indicator,
    NULL
  };

  proto_tree_add_bitmask_list(parameter_tree, parameter_tvb, 0, 1, indicators1_fields, ENC_NA);
  indicators1 = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_item(parameter_tree, hf_isup_numbering_plan_indicator, parameter_tvb, 1, 1, ENC_NA);
  offset = 2;

  dissect_isup_digits_common(parameter_tvb, offset, pinfo, parameter_tree, parameter_item,
                             hf_isup_charge_number, hf_isup_calling_party_odd_address_signal_digit,
                             hf_isup_calling_party_even_address_signal_digit, ((indicators1 & 0x80) == 0),
                             NONE, 0);
}

/* ------------------------------------------------------------------ */
static void
dissect_isup_unknown_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{
  guint length = tvb_reported_length(parameter_tvb);
  proto_tree_add_item(parameter_tree, hf_isup_parameter_value, parameter_tvb, 0, length, ENC_NA);
}
/* ------------------------------------------------------------------ */

/* Japan ISUP */

/*
  8 7 6 5 4 3 2 1
  O/E Nature of address indicator 1
  INN NAPI Spare 2
  2nd address signal 1st address signal 3
  ... ... :
  Filler (if necessary) nth address signal 15
*/
static void
dissect_japan_isup_called_dir_num(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{
  int offset = 0;
  int parameter_length;

  parameter_length = tvb_reported_length_remaining(parameter_tvb, offset);

  proto_tree_add_item(parameter_tree, hf_isup_odd_even_indicator, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_isup_called_party_nature_of_address_indicator, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(parameter_tree, hf_isup_inn_indicator, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_isup_numbering_plan_indicator, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_expert_format(parameter_tree, pinfo, &ei_isup_not_dissected_yet, parameter_tvb, offset, parameter_length-offset, "Number not dissected yet");
}


/*
  8     7     6     5     4     3     2    1
  +-----+-----+-----+-----+-----+-----+-----+-----+
  -            Information Type Tag               -  1
  +-----------------------------------------------+
  -           Information Type Length             -  2
  +-----------------------------------------------+
  -           Information Type Value              -  3
  +-----------------------------------------------+
  .                                              .
  .                                              .
  .                                              .
  +-----------------------------------------------+
  -            Information Type Tag               -  n+1
  +-----------------------------------------------+
  -           Information Type Length             -  n+2
  +-----------------------------------------------+
  -           Information Type Value              -  n+3
  |-----------------------------------------------/

  Information Type Tag

  00000000  Reserved (Note)
  00000001  Reserved
  00000010  Reserved
  00000011  Performing redirect indicator
  00000100  Invoking redirect reason
  00000101
  to     Spare
  11111111

  Note: In standard this value is marked as -Not used-,
  here is treated as reserved.

  Performing redirect indicator

  8     7     6     5     4     3     2     1
  +-----+-----+-----+-----+-----+-----+-----+-----+
  - ext -      Performing redirect reason         -  1
  +-----+-----------------------------------------+
  -                             -Redirect possible-
  -          Spare              -  indicator at   -  2
  -                             -   performing    -
  -                             -    exchange     -
  +-----------------------------+-----------------+
  :                       :                       :  :
  :                       :                       :
  +-----------------------------------------------+
  - ext -      Performing redirect reason         -  2n|1
  +-----+-----------------------|-----------------+    Reason n
  -                             -Redirect possible-
  -          Spare              -  indicator at   -  2n
  -                             -   performing    -
  -                             -    exchange     -
  |-----------------------------+-----------------/


  Redirect possible indicator at performing exchange
  000      No indication
  001      Redirect possible before ACM
  010      Reserved
  011      Reserved
  100
  to       Spare
  111

  Invoking redirect reason

  8     7     6     5     4     3     2    1
  +-----+-----+-----+-----+-----+-----+-----+-----+
  - ext -        Invoking redirect reason         -  1
  +-----+-----------------------------------------+
  :     :                                         :
  :     :                                         :
  +-----------------------------------------------+
  - ext -        Invoking redirect reason         -  n
  |-----+-----------------------------------------/

  Extension indicator (ext)

  0        Information continues in next octet
  1        Last octet

  Invoking redirect reason

  0000000  Unknown / not available
  0000001  Service provider portability (national use)
  0000010  Reserved for location portability
  0000011  Reserved for service portability
  0000100
  to       Spare
  0111111
  1000000
  to       Reserved for national use
  1111101
  1111110  Local number portability / Mobile number
  portability
  1111111  Reserved for national use

*/

static const value_string isup_rfi_info_type_values[] = {
  { 0,   "Reserved" },
  { 1,   "Reserved" },
  { 2,   "Reserved" },
  { 3,   "Performing redirect indicator" },
  { 4,   "Invoking redirect reason" },
  { 0,   NULL}
};

/* Performing redirect reason */
static const value_string perf_redir_reason_vals[] = {
  { 0,   "Unknown/not available" },
  { 1,   "Service provider portability (national use)" },
  { 2,   "Reserved for location portability" },
  { 3,   "Reserved for service portability" },
/*
  0000100
  to       Spare
  0111111
  1000000
  to       Reserved for national use
  1111101
*/
  { 0x7e,   "Local number portability / Mobile number portability" },
  { 0x7f,   "Reserved for national use" },
  { 0,   NULL}
};


static const value_string redir_pos_ind_vals[] = {
  { 0,   "No indication" },
  { 1,   "Redirect possible before ACM" },
  { 2,   "Reserved" },
  { 3,   "Reserved" },
  { 4,   "Reserved" },
  { 5,   "Reserved" },
  { 6,   "Reserved" },
  { 7,   "Reserved" },
  { 0,   NULL}
};


static void
dissect_japan_isup_redirect_fwd_inf(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{
  int    offset = 0;
  guint8 tag, tag_len, ext_ind;
  int    parameter_length;

  parameter_length = tvb_reported_length_remaining(parameter_tvb, offset);

  while (offset < parameter_length) {
    /* Information Type Tag */
    tag = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_item(parameter_tree, hf_japan_isup_rfi_info_type, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* Information Type Length */
    tag_len = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_item(parameter_tree, hf_japan_isup_rfi_info_len, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    switch (tag) {
      case 3: /* Performing redirect indicator */
        /* Performing redirect reason oct 1 */
        ext_ind = 0;
        while (ext_ind == 0) {
          ext_ind = tvb_get_guint8(parameter_tvb, offset) >> 7;
          proto_tree_add_item(parameter_tree, hf_isup_extension_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item(parameter_tree, hf_japan_isup_perf_redir_reason, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
          /* Redirect possible indicator at performing exchange */
          proto_tree_add_item(parameter_tree, hf_japan_isup_redir_pos_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
        }
        break;
      case 4:
        /* Invoking redirect reason */
        ext_ind = 0;
        while (ext_ind == 0) {
          ext_ind = tvb_get_guint8(parameter_tvb, offset)>>7;
          proto_tree_add_item(parameter_tree, hf_isup_extension_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item(parameter_tree, hf_japan_isup_inv_redir_reason, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
        }
        break;
      default:
        /* Information Type Value */
        proto_tree_add_expert_format(parameter_tree, pinfo, &ei_isup_not_dissected_yet, parameter_tvb, offset, tag_len, "Unknown(not dissected) tag");
        offset = offset + tag_len;
        break;
    }
  }
}


static const value_string japan_isup_bwd_info_type_vals[] = {
  { 0,   "Reserved" },
  { 1,   "Reserved" },
  { 2,   "Reserved" },
  { 3,   "invoking redirect reason" },
  { 0,   NULL}
};

static void
dissect_japan_isup_redirect_backw_inf(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{
  int    offset = 0;
  guint8 tag, tag_len, ext_ind;
  int    parameter_length;

  parameter_length = tvb_reported_length_remaining(parameter_tvb, offset);

  while (offset < parameter_length) {
    /* Information Type Tag */
    tag = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_item(parameter_tree, hf_japan_isup_bwd_info_type, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* Information Type Length */
    tag_len = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_item(parameter_tree, hf_japan_isup_tag_len, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    switch (tag) {
      case 3: /* invoking redirect reason */
        /* invoking redirect reason oct 1 */
        ext_ind = 0;
        while (ext_ind == 0) {
          ext_ind = tvb_get_guint8(parameter_tvb, offset)>>7;
          proto_tree_add_item(parameter_tree, hf_isup_extension_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item(parameter_tree, hf_japan_isup_inv_redir_reason, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
        }
        break;
      default:
        /* Information Type Value */
        proto_tree_add_expert_format(parameter_tree, pinfo, &ei_isup_not_dissected_yet, parameter_tvb, offset, tag_len, "Unknown(not dissected) tag");
        offset = offset + tag_len;
        break;
    }
  }
}


static const value_string japan_isup_emerg_call_type_vals[] = {
  { 0,   "No specific category" },
  { 1,   "Spare" },
  { 2,   "Spare" },
  { 3,   "Spare" },
  { 0,   NULL}
};
static void
dissect_japan_isup_emergency_call_ind(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{
  int offset = 0;

  proto_tree_add_item(parameter_tree, hf_japan_isup_emerg_call_type, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
}

static const value_string hold_at_emerg_call_disc_ind_vals[] = {
  { 0,   "No indication" },
  { 1,   "Emergency Call is holding" },
  { 2,   "Call Back from the Emergency Center" },
  { 3,   "Re-answer to an Emergency call" },
  { 0,   NULL}
};

static void
dissect_japan_isup_emergency_call_inf_ind(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{
  int offset = 0;


  proto_tree_add_item(parameter_tree, hf_japan_isup_hold_at_emerg_call_disc_ind, parameter_tvb, offset, 2, ENC_BIG_ENDIAN);
}

static void
dissect_japan_isup_network_poi_cad(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{
  proto_item    *digits_item;
  proto_tree    *digits_tree;
  int            offset = 0;
  guint8         octet;
  guint8         odd_even;
  guint8         carrier_info_length;
  gint           num_octets_with_digits = 0;
  gint           digit_index = 0;
  wmem_strbuf_t *ca_number = wmem_strbuf_sized_new(pinfo->pool, MAXDIGITS+1, 0);

  /* POI Hierarchy information

     8     7     6     5     4     3     2    1
     +-----------------------|-----------------------+
     |  Entry POI Hierarchy  |  Exit POI Hierarchy   |  1
     |                       |                       |
     \-----------------------------------------------|

  */

  /* POI Hierarchy information */
  proto_tree_add_item(parameter_tree, hf_isup_carrier_info_poi_entry_HEI, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_isup_carrier_info_poi_exit_HEI, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  /* length of CA information (in octets) */
  carrier_info_length = tvb_get_guint8(parameter_tvb, offset);
  proto_tree_add_item(parameter_tree, hf_japan_isup_carrier_info_length, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  /* POI|CA information (Charge Area)

     8     7     6     5     4     3     2     1
     +-----|-----------------------------------------+
     |Odd/ |                Spare                    |  1
     |even |                                         |
     +-----------------------------------------------+
     |   2nd CA code digit   |   1st CA code digit   |  2
     |                       |                       |
     +-----------------------+-----------------------+
     .                      .                       .
     .                      .                       .
     .                      .                       .
     +-----------------------+-----------------------+
     |         Filler        |   5|th CA code digit  |  m
     |                       |                       |
     \-----------------------------------------------|
  */

  digits_tree = proto_tree_add_subtree(parameter_tree, parameter_tvb, offset, -1,
                                ett_isup_address_digits, &digits_item, "Charge Area Number");

  /* Odd.Even Indicator*/
  odd_even = tvb_get_guint8(parameter_tvb, offset);
  proto_tree_add_boolean(digits_tree, hf_isup_odd_even_indicator, parameter_tvb, 0, 1, odd_even);

  /* Number of Octets containing digits*/
  num_octets_with_digits = carrier_info_length - 1;

  /* Lets now load up the digits.*/
  /* If the odd indicator is set... drop the Filler from the last octet.*/
  /* This loop also loads up ca_number with the digits for display*/
  digit_index = 0;
  while (num_octets_with_digits > 0) {
    offset += 1;
    octet = tvb_get_guint8(parameter_tvb, offset);
    if (++digit_index > MAXDIGITS) {
      expert_add_info(pinfo, digits_item, &ei_isup_too_many_digits);
      break;
    }
    proto_tree_add_uint(digits_tree, hf_isup_carrier_info_ca_odd_no_digits, parameter_tvb, 0, 1, octet);
    wmem_strbuf_append_c(ca_number, number_to_char(octet & ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK));
    if (num_octets_with_digits == 1) {
      if (odd_even == 0) {
        if (++digit_index > MAXDIGITS) {
          expert_add_info(pinfo, digits_item, &ei_isup_too_many_digits);
          break;
        }
        proto_tree_add_uint(digits_tree, hf_isup_carrier_info_ca_even_no_digits, parameter_tvb, 0, 1, octet);
        wmem_strbuf_append_c(ca_number, number_to_char((octet & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10));
      }
    }
    else {
      if (++digit_index > MAXDIGITS) {
        expert_add_info(pinfo, digits_item, &ei_isup_too_many_digits);
        break;
      }
      proto_tree_add_uint(digits_tree, hf_isup_carrier_info_ca_even_no_digits, parameter_tvb, 0, 1, octet);
      wmem_strbuf_append_c(ca_number, number_to_char((octet & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10));
    }

    num_octets_with_digits--;
  }
  proto_item_append_text(digits_item, ": %s", wmem_strbuf_get_str(ca_number));
}

static const range_string jpn_isup_add_user_cat_type_vals[] = {
  {  0,    0,    "Spare" },
  {  1,    0x80, "Reserved for network specific use" },
  {  0x81, 0xfa, "Spare" },
  {  0xfb, 0xfb, "Type 3 of additional mobile service information" },
  {  0xfc, 0xfc, "Type 2 of additional mobile service information" },
  {  0xfd, 0xfd, "Type 1 of additional mobile service information" },
  {  0xfe, 0xfe, "Type 1 of additional fixed service information" },
  {  0xff, 0xff, "Spare" },
  {  0,    0,    NULL } };

static const value_string jpn_isup_type_1_add_fixed_serv_inf_vals[] = {
  { 0,   "Spare" },
  { 1,   "Train payphone" },
  { 2,   "Pink (non-NTT payphone)" },
  { 0,   NULL}
};

static const value_string jpn_isup_type_1_add_mobile_serv_inf_vals[] = {
  { 0,   "Spare" },
  { 1,   "Cellular telephone service" },
  { 2,   "Maritime telephone service" },
  { 3,   "Airplane telephone service" },
  { 4,   "Paging service" },
  { 5,   "PHS service" },
  { 6,   "Spare" },
  { 0,   NULL}
};
static const value_string jpn_isup_type_2_add_mobile_serv_inf_vals[] = {
  { 0,   "Spare" },
  { 1,   "HiCap method (analog)" },
  { 2,   "N/J-TACS" },
  { 3,   "PDC 800 MHz" },
  { 4,   "PDC 1500 MHz" },
  { 5,   "N-STAR satellite" },
  { 6,   "cdmaOne 800 MHz" },
  { 7,   "Iridium satellite" },
  { 8,   "IMT-2000" },
  { 9,   "PHS (fixed network dependent)" },
  { 10,   "Spare" },
  { 0,   NULL}
};
static value_string_ext jpn_isup_type_2_add_mobile_serv_inf_vals_ext = VALUE_STRING_EXT_INIT(jpn_isup_type_2_add_mobile_serv_inf_vals);


void
dissect_japan_isup_additonal_user_cat(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{
  int    offset = 0;
  guint8 type;
  int    parameter_length;

  parameter_length = tvb_reported_length_remaining(parameter_tvb, offset);

  while (offset < parameter_length) {
    /* Type of Additional User/Service Information */
    type = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_item(parameter_tree, hf_japan_isup_add_user_cat_type, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* Additional User/Service Information  */
    switch (type) {
      case 0xfe:
        /* Type 1 of additional fixed service information */
        proto_tree_add_item(parameter_tree, hf_japan_isup_type_1_add_fixed_serv_inf, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
      case 0xfd:
        /* Type 1 of additional mobile service information */
        proto_tree_add_item(parameter_tree, hf_japan_isup_type_1_add_mobile_serv_inf, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
      case 0xfc:
        /* Type 2 of additional mobile service information */
        proto_tree_add_item(parameter_tree, hf_japan_isup_type_2_add_mobile_serv_inf, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
      case 0xfb:
        /* Type 3 of additional mobile service information */
        proto_tree_add_item(parameter_tree, hf_japan_isup_type_3_add_mobile_serv_inf, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
      default:
        proto_tree_add_expert_format(parameter_tree, pinfo, &ei_isup_not_dissected_yet, parameter_tvb, offset, 1,
                "Unknown(not dissected) Additional User/Service Information");
        break;
    }
    offset += 1;
  }
}


static const value_string jpn_isup_reason_for_clip_fail_vals[] = {
  { 0,   "Spare" },
  { 1,   "User's request" },
  { 2,   "Interaction with other service" },
  { 3,   "Public telephone origination" },
  { 4,   "Spare" },
  { 0,   NULL}
};
static void
dissect_japan_isup_reason_for_clip_fail(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{
  int offset = 0;


  proto_tree_add_item(parameter_tree, hf_isup_extension_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_japan_isup_reason_for_clip_fail, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_japan_isup_contractor_number(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  int         offset = 0;
  int         parameter_length;
  char        *digit_str;

  parameter_length = tvb_reported_length_remaining(parameter_tvb, offset);

  proto_tree_add_item(parameter_tree, hf_isup_odd_even_indicator, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_isup_called_party_nature_of_address_indicator, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(parameter_tree, hf_isup_numbering_plan_indicator, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item_ret_display_string(parameter_tree, hf_japan_isup_contractor_number,  parameter_tvb, offset, parameter_length-2, ENC_BCD_DIGITS_0_9, pinfo->pool, &digit_str);

  proto_item_append_text(parameter_item, " %s", digit_str);

}
/* ------------------------------------------------------------------
  Dissector Parameter Optional .Carrier Information


   8     7     6     5     4     3     2    1
+-----------------------------------------------+
|                 spare             |    IEC    |  1
|                                   | indicator |
+-----------------------------------------------+
|         Category of carrier 1                 |  2
|                                               |
+-----------------------------------------------+
|         Length of carrier 1 information       |  3
|                                               |
+-----------------------------------------------+
|         Carrier 1 information / octet 1       |  4
|                                               |
+-----------------------------------------------+
 .                    .                         .
 .                    .                         .
 .                    .                         .
+-----------------------------------------------+
|         Carrier 1 information / octet n       |  3+n
|                                               |
+-----------------------------------------------+
 .                                              .
 */
static void
dissect_japan_isup_carrier_information(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item)
{
  proto_item *catagory_of_carrier;
  proto_tree *carrier_info_tree;

  proto_item *digits_item;
  proto_tree *digits_tree;

  proto_item *type_of_carrier;
  proto_tree *type_of_carrier_tree;

  guint8 octet;
  guint8 odd_even;
  guint8 type_of_carrier_info;
  guint8 carrier_info_length;
  guint8 carrierX_end_index;

  gint offset = 0;
  gint length = 0;

  gint num_octets_with_digits = 0;

  gint digit_index;
  wmem_strbuf_t *cid_number;
  wmem_strbuf_t *ca_number;

  /*Octet 1 : IEC Indicator*/
  octet = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_uint(parameter_tree, hf_isup_carrier_info_iec, parameter_tvb, 0, 1, octet);


  length = tvb_reported_length_remaining(parameter_tvb, 2);
  if (length == 0) {
    expert_add_info(pinfo, parameter_item, &ei_isup_empty_number);
    proto_item_append_text(parameter_item, ": (empty)");
    return;
  }

  offset = 1;

  /* Lets loop through the Carrier Information*/

  while (length > 0) {

    carrier_info_tree = proto_tree_add_subtree(parameter_tree, parameter_tvb, offset, -1,
                        ett_isup_carrier_info, &catagory_of_carrier, "Category of Carrier:");

    /*Octet 2 : Category of Carrier*/
    octet = tvb_get_guint8(parameter_tvb, offset);
    /*proto_tree_add_uint(carrier_info_tree, hf_isup_carrier_info_cat_of_carrier, parameter_tvb, 0, 1, octet);*/
    proto_item_append_text(catagory_of_carrier, ": %s (%u)", val_to_str_ext_const(octet, &isup_carrier_info_category_vals_ext, "spare"), octet );


    /*Octet 3 : Length of Category Information No.x*/
    offset += 1;
    carrierX_end_index = tvb_get_guint8(parameter_tvb, offset)+offset;

    while (offset < carrierX_end_index) {

      type_of_carrier_tree = proto_tree_add_subtree(carrier_info_tree, parameter_tvb, offset, -1,
                                    ett_isup_carrier_info, &type_of_carrier, "Type of Carrier:");

      /* Type of Carrier Information*/
      offset += 1;
      type_of_carrier_info = tvb_get_guint8(parameter_tvb, offset);
      /*proto_tree_add_uint(type_of_carrier_tree, hf_isup_carrier_info_type_of_carrier_info, parameter_tvb, 0, 1, type_of_carrier_info);*/
      proto_item_append_text(type_of_carrier, ": %s (%u)", val_to_str_ext_const(type_of_carrier_info, &isup_carrier_info_type_of_carrier_vals_ext, "spare"), type_of_carrier_info );


      /* Carrier Information Length */
      offset += 1;
      carrier_info_length = tvb_get_guint8(parameter_tvb, offset);

      /* POI Hierarchy information

         8     7     6     5     4     3     2    1
         +-----------------------|-----------------------+
         |  Entry POI Hierarchy  |  Exit POI Hierarchy   |  1
         |                       |                       |
         \-----------------------------------------------|

      */

      if (type_of_carrier_info == CARRIER_INFO_TYPE_OF_CARRIER_POIHIE) {
        /* POI Hierarchy information */
        offset += 1;
        octet = tvb_get_guint8(parameter_tvb, offset);
        proto_tree_add_uint(type_of_carrier_tree, hf_isup_carrier_info_poi_entry_HEI, parameter_tvb, 0, 1, octet);
        proto_tree_add_uint(type_of_carrier_tree, hf_isup_carrier_info_poi_exit_HEI, parameter_tvb, 0, 1, octet);
      }

      /* POI|CA information (Charge Area)

         8     7     6     5     4     3     2     1
         +-----|-----------------------------------------+
         |Odd/ |                Spare                    |  1
         |even |                                         |
         +-----------------------------------------------+
         |   2nd CA code digit   |   1st CA code digit   |  2
         |                       |                       |
         +-----------------------+-----------------------+
         .                      .                       .
         .                      .                       .
         .                      .                       .
         +-----------------------+-----------------------+
         |         Filler        |   5|th CA code digit  |  m
         |                       |                       |
         \-----------------------------------------------|
      */
      if (type_of_carrier_info == CARRIER_INFO_TYPE_OF_CARRIER_POICA) {

        digits_tree = proto_tree_add_subtree(type_of_carrier_tree, parameter_tvb, offset, -1,
                                        ett_isup_address_digits, &digits_item, "Charge Area");

        /* Odd.Even Indicator*/
        offset += 1;
        odd_even = tvb_get_guint8(parameter_tvb, offset);
        proto_tree_add_boolean(digits_tree, hf_isup_odd_even_indicator, parameter_tvb, 0, 1, odd_even);

        /* Number of Octets containing digits*/
        num_octets_with_digits = carrier_info_length - 1;

        /* Lets now load up the digits.*/
        /* If the odd indicator is set... drop the Filler from the last octet.*/
        /* This loop also loads up ca_number with the digits for display*/
        ca_number = wmem_strbuf_sized_new(pinfo->pool, MAXDIGITS+1, 0);
        digit_index = 0;
        while (num_octets_with_digits > 0) {
          offset += 1;
          if (++digit_index > MAXDIGITS) {
            expert_add_info(pinfo, digits_item, &ei_isup_too_many_digits);
            break;
          }
          octet = tvb_get_guint8(parameter_tvb, offset);
          proto_tree_add_uint(digits_tree, hf_isup_carrier_info_ca_odd_no_digits, parameter_tvb, 0, 1, octet);
          wmem_strbuf_append_c(ca_number, number_to_char(octet & ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK));
          if (num_octets_with_digits == 1) {
            if (odd_even == 0) {
              if (++digit_index > MAXDIGITS) {
                expert_add_info(pinfo, digits_item, &ei_isup_too_many_digits);
                break;
              }
              proto_tree_add_uint(digits_tree, hf_isup_carrier_info_ca_even_no_digits, parameter_tvb, 0, 1, octet);
              wmem_strbuf_append_c(ca_number, number_to_char((octet & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10));
            }
          }
          else {
            if (++digit_index > MAXDIGITS) {
              expert_add_info(pinfo, digits_item, &ei_isup_too_many_digits);
              break;
            }
            proto_tree_add_uint(digits_tree, hf_isup_carrier_info_ca_even_no_digits, parameter_tvb, 0, 1, octet);
            wmem_strbuf_append_c(ca_number, number_to_char((octet & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10));
          }

          num_octets_with_digits--;
        }

        proto_item_append_text(digits_item, ": %s", wmem_strbuf_get_str(ca_number));

      }

      /* Carrier Identification Code
         8     7     6     5     4     3     2     1
         +-----|-----------------------------------------+
         |Odd/ |                Spare                    |  1
         |even |                                         |
         +-----------------------------------------------+
         |   2nd ID code digit   |   1st ID code digit   |  2
         |                       |                       |
         +-----------------------+-----------------------+
         .                      .                       .
         .                      .                       .
         .                      .                       .
         +-----------------------+-----------------------+
         | Filler (if necessary) |   n|th ID code digit  |  m
         |                       |                       |
         \-----------------------------------------------|
      */

      if (type_of_carrier_info == CARRIER_INFO_TYPE_OF_CARRIER_CARID) {
        digits_tree = proto_tree_add_subtree(type_of_carrier_tree, parameter_tvb, offset, -1,
                                        ett_isup_address_digits, &digits_item, "Carrier ID Code");

        offset += 1;
        /* Odd.Even Indicator*/
        odd_even = tvb_get_guint8(parameter_tvb, offset);
        proto_tree_add_boolean(digits_tree, hf_isup_odd_even_indicator, parameter_tvb, 0, 1, odd_even);

        /* Number of Octets containing digits*/
        num_octets_with_digits = carrier_info_length - 1;

        /* Lets now load up the digits.*/
        /* If the odd indicator is set... drop the Filler from the last octet.*/
        /* This loop also loads up cid_number with the digits for display*/
        cid_number = wmem_strbuf_sized_new(pinfo->pool, MAXDIGITS+1, 0);
        digit_index = 0;
        while (num_octets_with_digits > 0) {
          offset += 1;
          if (++digit_index > MAXDIGITS) {
            expert_add_info(pinfo, digits_item, &ei_isup_too_many_digits);
            break;
          }
          octet = tvb_get_guint8(parameter_tvb, offset);
          proto_tree_add_uint(digits_tree, hf_isup_carrier_info_odd_no_digits, parameter_tvb, 0, 1, octet);
          wmem_strbuf_append_c(cid_number, number_to_char(octet & ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK));
          if (num_octets_with_digits == 1) {
            if (odd_even == 0) {
              if (++digit_index > MAXDIGITS) {
                expert_add_info(pinfo, digits_item, &ei_isup_too_many_digits);
                break;
              }
              proto_tree_add_uint(digits_tree, hf_isup_carrier_info_even_no_digits, parameter_tvb, 0, 1, octet);
              wmem_strbuf_append_c(cid_number, number_to_char((octet & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10));
            }
          }
          else {
            if (++digit_index > MAXDIGITS) {
              expert_add_info(pinfo, digits_item, &ei_isup_too_many_digits);
              break;
            }
            proto_tree_add_uint(digits_tree, hf_isup_carrier_info_even_no_digits, parameter_tvb, 0, 1, octet);
            wmem_strbuf_append_c(cid_number, number_to_char((octet & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10));
          }
          num_octets_with_digits--;
        }
        proto_item_append_text(digits_item, ": %s", wmem_strbuf_get_str(cid_number));
      }
    }

    offset += 1;
    length = tvb_reported_length_remaining(parameter_tvb, offset);
  }
}


static const range_string japan_isup_charge_delay_type_value[] = {
  {  0,    0,    "Spare" },
  {  1,    0x80, "Reserved for network specific use" },
  {  0x81, 0xfa, "Spare" },
  {  0xfb, 0xfc, "Reserved" },
  {  0xfd, 0xfd, "Charge rate transfer" },
  {  0xfe, 0xfe, "Terminating charge area information" },
  {  0xff, 0xff, "Spare" },
  {  0,    0,    NULL } };

static void
dissect_japan_isup_charge_inf_delay(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{

  int offset = 0;
  int parameter_length;

  parameter_length = tvb_reported_length_remaining(parameter_tvb, offset);

  while (offset < parameter_length) {
    proto_tree_add_item(parameter_tree, hf_japan_isup_charge_delay_type, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
  }
}

/* ----------------------------------------------------
  Dissector Parameter Optional .Additional User Information

   8     7     6     5     4     3     2    1
+-----------------------------------------------+
|     Type of additional user/service           |  1
|     information (1)                           |
+-----------------------------------------------+
|     Additional user/service information (1)   |  2
|                                               |
+-----------------------------------------------+
 .                                              .
 .                                              .
 .                                              .
+-----------------------------------------------+
|      Type of additional user/service          |  2n|1
|      information (n)                          |
+-----------------------------------------------+
|      Additional user/service information (n)  |  2n
|                                               |
\------------------------------------------------
*/



/* ----------------------------------------------------
  Dissector Parameter Optional .Charge Area Information

  8     7     6     5     4     3     2     1
+-----+-----------------------------------------+
|Odd/ |     Nature of information indicator     |  1
|even |                                         |
+-----------------------------------------------+
| 2nd NC digit          | 1st NC digit          |  2 ||
|                       |                       |     | see
+-----------------------+-----------------------+     | Note
|  4th NC digit         | 3rd NC digit          |  3 ||
|                       |                       |
+-----------------------+-----------------------+
| 2nd MA/CA code digit  | 1st MA/CA code digit  |  4
|                       |                       |
+-----------------------+-----------------------+
 .                      .                       .
 .                      .                       .
 .                      .                       .
+-----------------------+-----------------------+
| Filler (if necessary) | nth MA/CA code digit  |  m
|                       |                       |
\-----------------------------------------------|
*/
static void
dissect_japan_isup_charge_area_info(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{
  proto_item *digits_item;
  proto_tree *digits_tree;

  guint8 octet;

  gint nat_of_info_indic;
  gint length;
  gint offset;
  gint odd_even;
  gint digit_index = 0;

  wmem_strbuf_t *ca_number = wmem_strbuf_sized_new(pinfo->pool, MAXDIGITS+1, 0);

  /*Octet 1 : Indicator*/
  octet = tvb_get_guint8(parameter_tvb, 0);
  nat_of_info_indic = octet & 0x7F;
  odd_even = octet & 0x80;
  proto_tree_add_boolean(parameter_tree, hf_isup_odd_even_indicator, parameter_tvb, 0, 1, octet);
  proto_tree_add_uint(parameter_tree, hf_japan_isup_charge_area_nat_of_info_value, parameter_tvb, 0, 1, octet);

  offset = 1;
  length = tvb_reported_length_remaining(parameter_tvb, offset);

  /*Only CA code digits.*/
  if (nat_of_info_indic == CHARGE_AREA_NAT_INFO_CA) {
    digits_tree = proto_tree_add_subtree(parameter_tree, parameter_tvb, offset, -1,
                                ett_isup_address_digits, &digits_item, "Charge Area");

    while (length > 0) {
      if (++digit_index > MAXDIGITS) {
        expert_add_info(pinfo, digits_item, &ei_isup_too_many_digits);
        break;
      }
      octet = tvb_get_guint8(parameter_tvb, offset);
      proto_tree_add_uint(digits_tree, hf_isup_carrier_info_ca_odd_no_digits, parameter_tvb, 0, 1, octet);
      wmem_strbuf_append_c(ca_number, number_to_char(octet & ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK));
      if (length == 1) {
        if (odd_even == 0) {
          if (++digit_index > MAXDIGITS) {
            expert_add_info(pinfo, digits_item, &ei_isup_too_many_digits);
            break;
          }
          proto_tree_add_uint(digits_tree, hf_isup_carrier_info_ca_even_no_digits, parameter_tvb, 0, 1, octet);
          wmem_strbuf_append_c(ca_number, number_to_char((octet & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10));
        }
      }
      else {
        if (++digit_index > MAXDIGITS) {
          expert_add_info(pinfo, digits_item, &ei_isup_too_many_digits);
          break;
        }
        proto_tree_add_uint(digits_tree, hf_isup_carrier_info_ca_even_no_digits, parameter_tvb, 0, 1, octet);
        wmem_strbuf_append_c(ca_number, number_to_char((octet & ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK) / 0x10));
      }
      offset += 1;
      length -= 1;
    }
    proto_item_append_text(digits_item, ": %s", wmem_strbuf_get_str(ca_number));
  }
  /*Only MA code digits.*/
  if (nat_of_info_indic == CHARGE_AREA_NAT_INFO_MA) {
    digits_tree = proto_tree_add_subtree(parameter_tree, parameter_tvb, offset, -1,
                                ett_isup_address_digits, &digits_item, "Message Area:");

    /* First two octets contains*/
    /* four NC digits*/
    octet = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(digits_tree, hf_japan_isup_charging_info_nc_odd_digits, parameter_tvb, 0, 1, octet);
    proto_tree_add_uint(digits_tree, hf_japan_isup_charging_info_nc_even_digits, parameter_tvb, 0, 1, octet);
    offset++;
    octet = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_uint(digits_tree, hf_japan_isup_charging_info_nc_odd_digits, parameter_tvb, 0, 1, octet);
    proto_tree_add_uint(digits_tree, hf_japan_isup_charging_info_nc_even_digits, parameter_tvb, 0, 1, octet);
    offset++;

    /* Now loop through MA/CA digits.*/
    length = tvb_reported_length_remaining(parameter_tvb, offset);

    while (length > 0) {
      octet = tvb_get_guint8(parameter_tvb, offset);
      proto_tree_add_uint(digits_tree, hf_isup_charging_info_maca_odd_digits, parameter_tvb, 0, 1, octet);
      if (length == 1) {
        if (odd_even == 0) {
          proto_tree_add_uint(digits_tree, hf_isup_charging_info_maca_even_digits, parameter_tvb, 0, 1, octet);
        }
      }
      else {
        proto_tree_add_uint(digits_tree, hf_isup_charging_info_maca_even_digits, parameter_tvb, 0, 1, octet);
      }
      offset += 1;
      length -= 1;
    }

  }
}

static const value_string japan_isup_chg_info_type_value[] = {
  { 0,      "Spare" },
  { 1,      "Reserved" },
  { 2,      "Reserved" },
  { 3,      "Advanced Charge Rate Transfer(TDS Service)" },
  { 0xfe,   "Charge rate transfer (flexible charging)" },
  { 0xff,   "Spare" },
  { 0,   NULL}
};

static guint16
dissect_japan_chg_inf_type(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{
  guint16 chg_inf_type;

  chg_inf_type = tvb_get_guint8(parameter_tvb, 0);
  proto_tree_add_item(parameter_tree, hf_japan_isup_charge_info_type, parameter_tvb, 0, 1, ENC_BIG_ENDIAN);

  return chg_inf_type;
}

static const value_string japan_isup_sig_elem_type_values[] = {
  { 2,   "Activate" },
  { 0,   NULL}
};

static const value_string japan_isup_op_cls_values[] = {
  { 0,   "Class 1" },
  { 1,   "Class 2" },
  { 2,   "Class 3" },
  { 3,   "Class 4" },
  { 0,   NULL}
};

static const value_string japan_isup_op_type_values[] = {
  { 6,   "Immediate charging" },
  { 0,   NULL}
};

static const value_string japan_isup_charging_party_type_values[] = {
  { 0,   "Originator charge" },
  { 0,   NULL}
};

static const value_string japan_isup_collecting_method_values[] = {
  { 0,   "Subscriber will be claimed" },
  { 0,   NULL}
};

static const value_string japan_isup_tariff_rate_pres_values[] = {
  { 2,   "No charge rate information" },
  { 0,   NULL}
};

static void
dissect_japan_chg_inf_type_acr(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{
  int    offset = 0;
  guint8 ext_ind;

  /* length : 2-5 octets */
  ext_ind = tvb_get_guint8(parameter_tvb, offset)>>7;
  proto_tree_add_item(parameter_tree, hf_isup_extension_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_japan_isup_sig_elem_type, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  if (!ext_ind) {
    /* Activation ID */
    ext_ind = tvb_get_guint8(parameter_tvb, offset)>>7;
    proto_tree_add_item(parameter_tree, hf_isup_extension_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(parameter_tree, hf_japan_isup_activation_id, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    if (!ext_ind) {
      /* Operation type and class */
      ext_ind = tvb_get_guint8(parameter_tvb, offset)>>7;
      proto_tree_add_item(parameter_tree, hf_isup_extension_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(parameter_tree, hf_japan_isup_op_cls, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(parameter_tree, hf_japan_isup_op_type, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
      if (!ext_ind) {
        /* Tariff collecting method and charging party type */
        proto_tree_add_item(parameter_tree, hf_isup_extension_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(parameter_tree, hf_japan_isup_charging_party_type, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(parameter_tree, hf_japan_isup_collecting_method, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
      }
    }
  }
  /* Tariff rate presentation */
  proto_tree_add_item(parameter_tree, hf_japan_isup_tariff_rate_pres, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);

}


static const value_string japan_isup_utp_values[] = {
  { 0,   "Spare" },
  { 0xfc,   "100 yen" },
  { 0xfd,   "10 yen" },
  { 0xfe,   "No indication" },
  { 0xff,   "Spare" },
  { 0,   NULL}
};

static const value_string japan_isup_crci1_values[] = {
  { 0,   "Spare" },
  { 0x7c,   "Public (Payphone)" },
  { 0x7d,   "Ordinary" },
  { 0x7e,   "No flexible charge rate information" },
  { 0x7f,   "Spare" },
  { 0,   NULL}
};

static void
dissect_japan_chg_inf_type_crt(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item _U_)
{
  int    offset = 0;
  guint8 ext_ind;
  guint8 len;
  int    parameter_length;

  parameter_length = tvb_reported_length_remaining(parameter_tvb, offset);


  /* Unit per Time Period (UTP) */
  proto_tree_add_item(parameter_tree, hf_japan_isup_utp, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  /* Charge rate information category 1 (CRIC 1) */
  ext_ind = tvb_get_guint8(parameter_tvb, offset)>>7;
  proto_tree_add_item(parameter_tree, hf_isup_extension_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(parameter_tree, hf_japan_isup_crci1, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  if (!ext_ind) {
    len = tvb_get_guint8(parameter_tvb, offset);
    proto_tree_add_item(parameter_tree, hf_japan_isup_crci1_len, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* Initial units (IU) IA5 coded in two octets */
    proto_tree_add_item(parameter_tree, hf_japan_isup_iu, parameter_tvb, offset, 2, ENC_NA|ENC_ASCII);
    offset += 2;
    /* Daytime Charge rate (DCR) (Octets A, B, C) IA5 coded in three octets */
    proto_tree_add_item(parameter_tree, hf_japan_isup_dcr, parameter_tvb, offset, 3, ENC_NA|ENC_ASCII);
    offset+=3;
    if (len > 5) {
      /* Evening Charge rate (ECR) (Octets B, E, F) IA5 coded in three octets */
      proto_tree_add_item(parameter_tree, hf_japan_isup_ecr, parameter_tvb, offset, 3, ENC_NA|ENC_ASCII);
      offset += 3;
    }
    if (len > 8) {
      /* Nighttime Charge rate (NCR) (Octet G,H,I) IA5 coded in three octets */
      proto_tree_add_item(parameter_tree, hf_japan_isup_ncr, parameter_tvb, offset, 3, ENC_NA|ENC_ASCII);
      offset += 3;
    }
    if (len > 11) {
      /* Spare charge rate (SCR) (Octets J,K,L) IA5 coded in three octets */
      proto_tree_add_item(parameter_tree, hf_japan_isup_scr, parameter_tvb, offset, 3, ENC_NA|ENC_ASCII);
      offset += 3;
    }
  }
  if (parameter_length > offset) {
    /* Charge rate information category 2 (CRIC 2) */
    ext_ind = tvb_get_guint8(parameter_tvb, offset)>>7;
    proto_tree_add_item(parameter_tree, hf_isup_extension_ind, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(parameter_tree, hf_japan_isup_crci2, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    if (!ext_ind) {
      len = tvb_get_guint8(parameter_tvb, offset);
      proto_tree_add_item(parameter_tree, hf_japan_isup_crci1_len, parameter_tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
      /* Initial units (IU) IA5 coded in two octets */
      proto_tree_add_item(parameter_tree, hf_japan_isup_iu, parameter_tvb, offset, 2, ENC_NA|ENC_ASCII);
      offset += 2;
      /* Daytime Charge rate (DCR) (Octets A, B, C) IA5 coded in three octets */
      proto_tree_add_item(parameter_tree, hf_japan_isup_dcr, parameter_tvb, offset, 3, ENC_NA|ENC_ASCII);
      offset += 3;
      if (len > 5) {
        /* Evening Charge rate (ECR) (Octets B, E, F) IA5 coded in three octets */
        proto_tree_add_item(parameter_tree, hf_japan_isup_ecr, parameter_tvb, offset, 3, ENC_NA|ENC_ASCII);
        offset += 3;
      }
      if (len > 8) {
        /* Nighttime Charge rate (NCR) (Octet G,H,I) IA5 coded in three octets */
        proto_tree_add_item(parameter_tree, hf_japan_isup_ncr, parameter_tvb, offset, 3, ENC_NA|ENC_ASCII);
        offset += 3;
      }
      if (len > 11) {
        /* Spare charge rate (SCR) (Octets J,K,L) IA5 coded in three octets */
        proto_tree_add_item(parameter_tree, hf_japan_isup_scr, parameter_tvb, offset, 3, ENC_NA|ENC_ASCII);
        /*offset += 3;*/
      }
    }
  }
}


static void
dissect_japan_chg_inf_param(tvbuff_t *parameter_tvb, packet_info *pinfo, proto_tree *parameter_tree, proto_item *parameter_item, guint16 chg_inf_type)
{

  switch (chg_inf_type) {
    case 3:
      /* Advanced Charge Rate Transfer (TDS service) */
      dissect_japan_chg_inf_type_acr(parameter_tvb, parameter_tree, parameter_item);
      break;
    case 254:
      /* Charge rate transfer (flexible charging) */
      dissect_japan_chg_inf_type_crt(parameter_tvb, parameter_tree, parameter_item);
      break;
    default:
      proto_tree_add_expert_format(parameter_tree, pinfo, &ei_isup_not_dissected_yet, parameter_tvb, 0, -1, "Charge information data, not dissected yet");
      break;
  }
}

/* END Japan ISUP */

/* ------------------------------------------------------------------
  Dissector all optional parameters
*/
static void
dissect_isup_optional_parameter(tvbuff_t *optional_parameters_tvb, packet_info *pinfo, proto_tree *isup_tree, guint8 itu_isup_variant)
{
  proto_item *parameter_item;
  proto_tree *parameter_tree;
  gint        offset = 0;
  guint       parameter_type, parameter_length, actual_length;
  tvbuff_t   *parameter_tvb;
  guint8      octet;
  guint16     chg_inf_type = 0xffff;

  /* Dissect all optional parameters while end of message isn't reached */
  parameter_type = 0xFF; /* Start-initialization since parameter_type is used for while-condition */

  while ((tvb_reported_length_remaining(optional_parameters_tvb, offset)  >= 1) && (parameter_type != PARAM_TYPE_END_OF_OPT_PARAMS)) {
    parameter_type = tvb_get_guint8(optional_parameters_tvb, offset);

    if (parameter_type != PARAM_TYPE_END_OF_OPT_PARAMS) {
      parameter_length = tvb_get_guint8(optional_parameters_tvb, offset + PARAMETER_TYPE_LENGTH);
      if (parameter_length + PARAMETER_TYPE_LENGTH + PARAMETER_LENGTH_IND_LENGTH > (guint)(tvb_reported_length_remaining(optional_parameters_tvb, offset))) {
        proto_tree_add_expert_format(isup_tree, pinfo, &ei_isup_opt_par_length_err, optional_parameters_tvb, offset, -1,
          "Wrong parameter length %u, should be %u",
          parameter_length,
          tvb_reported_length_remaining(optional_parameters_tvb, offset)- (PARAMETER_TYPE_LENGTH + PARAMETER_LENGTH_IND_LENGTH));
        return;
      }

      parameter_tree = proto_tree_add_subtree_format(isup_tree, optional_parameters_tvb,
                                           offset,
                                           parameter_length  + PARAMETER_TYPE_LENGTH + PARAMETER_LENGTH_IND_LENGTH,
                                           ett_isup_parameter, &parameter_item,
                                           "Parameter: (t=%u, l=%u)",
                                           parameter_type, parameter_length);
      /* Handle national extensions here */
      switch (itu_isup_variant) {
        case ISUP_JAPAN_VARIANT:
        /* Fall through */
        case ISUP_JAPAN_TTC_VARIANT:
          proto_tree_add_uint_format_value(parameter_tree, hf_isup_opt_parameter_type, optional_parameters_tvb, offset, PARAMETER_TYPE_LENGTH,
                                     parameter_type,
                                     "%u (%s)",
                                     parameter_type,
                                     val_to_str_ext_const(parameter_type, &japan_isup_parameter_type_value_ext, "unknown"));
          proto_item_append_text(parameter_tree, ": %s", val_to_str_ext(parameter_type, &japan_isup_parameter_type_value_ext, "Unknown"));
          break;
        default:
          proto_tree_add_uint(parameter_tree, hf_isup_opt_parameter_type, optional_parameters_tvb, offset, PARAMETER_TYPE_LENGTH, parameter_type);
          proto_item_append_text(parameter_tree, ": %s", val_to_str_ext(parameter_type, &ansi_isup_parameter_type_value_ext, "Unknown"));
          break;

      }
      offset += PARAMETER_TYPE_LENGTH;

      octet = tvb_get_guint8(optional_parameters_tvb, offset);

      proto_tree_add_uint(parameter_tree, hf_isup_parameter_length, optional_parameters_tvb, offset,
                                 PARAMETER_LENGTH_IND_LENGTH, parameter_length);
      offset += PARAMETER_LENGTH_IND_LENGTH;
      if (octet == 0)
        continue;

      actual_length = tvb_reported_length_remaining(optional_parameters_tvb, offset);
      if (actual_length > 0) {
        parameter_tvb = tvb_new_subset_length_caplen(optional_parameters_tvb, offset, MIN(parameter_length, actual_length), parameter_length);
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
            dissect_isup_called_party_number_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_SUBSQT_NR:
            dissect_isup_subsequent_number_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_NATURE_OF_CONN_IND:
            dissect_isup_nature_of_connection_indicators_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_FORW_CALL_IND:
            dissect_isup_forward_call_indicators_parameter(parameter_tvb, pinfo, parameter_item, parameter_tree);
            break;
          case PARAM_TYPE_OPT_FORW_CALL_IND:
            dissect_isup_optional_forward_call_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_CALLING_PRTY_CATEG:
            dissect_isup_calling_partys_category_parameter(parameter_tvb, parameter_tree, parameter_item, itu_isup_variant);
            break;
          case PARAM_TYPE_CALLING_PARTY_NR:
            dissect_isup_calling_party_number_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_REDIRECTING_NR:
            dissect_isup_redirecting_number_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_REDIRECTION_NR:
            dissect_isup_redirection_number_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
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
            dissect_isup_backward_call_indicators_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
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
            dissect_isup_range_and_status_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
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
            dissect_isup_connected_number_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_SUSP_RESUME_IND:
            dissect_isup_suspend_resume_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_TRANSIT_NETW_SELECT:
            dissect_isup_transit_network_selection_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
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
            dissect_isup_original_called_number_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
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
            dissect_isup_location_number_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
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
            dissect_isup_call_transfer_number_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
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
            dissect_isup_redirect_capability_parameter(parameter_tvb, parameter_tree, parameter_item, itu_isup_variant);
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
            dissect_isup_called_in_number_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
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
            dissect_isup_redirect_counter_parameter(parameter_tvb, parameter_tree, parameter_item, itu_isup_variant);
            break;
          case PARAM_TYPE_COLLECT_CALL_REQ:
            dissect_isup_collect_call_request_parameter(parameter_tvb, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_GENERIC_NR:
            dissect_isup_generic_number_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_GENERIC_DIGITS:
            dissect_isup_generic_digits_parameter(parameter_tvb, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_APPLICATON_TRANS:
            dissect_isup_application_transport_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
            break;

          default:
            switch (itu_isup_variant) {
              case ISUP_JAPAN_VARIANT:
              /* Fall through */
              case ISUP_JAPAN_TTC_VARIANT:
                switch (parameter_type) {
                  case JAPAN_ISUP_PARAM_CALLED_DIRECTORY_NUMBER:
                    dissect_japan_isup_called_dir_num(parameter_tvb, pinfo, parameter_tree, parameter_item);
                    break;
                  case JAPAN_ISUP_PARAM_REDIRECT_FORWARD_INF: /* 0x8B */
                    dissect_japan_isup_redirect_fwd_inf(parameter_tvb, pinfo, parameter_tree, parameter_item);
                    break;
                  case JAPAN_ISUP_PARAM_REDIRECT_BACKWARD_INF:  /* 0x8C */
                    dissect_japan_isup_redirect_backw_inf(parameter_tvb, pinfo, parameter_tree, parameter_item);
                    break;
                  case JAPAN_ISUP_PARAM_EMERGENCY_CALL_IND: /* D7 */
                    dissect_japan_isup_emergency_call_ind(parameter_tvb, parameter_tree, parameter_item);
                    break;
                  case JAPAN_ISUP_PARAM_EMERGENCY_CALL_INF_IND: /* EC */
                    dissect_japan_isup_emergency_call_inf_ind(parameter_tvb, parameter_tree, parameter_item);
                    break;
                  case JAPAN_ISUP_PARAM_NETWORK_POI_CA: /* EE */
                    dissect_japan_isup_network_poi_cad(parameter_tvb, pinfo, parameter_tree, parameter_item);
                    break;
                  case JAPAN_ISUP_PARAM_TYPE_CARRIER_INFO: /* 241 F1 */
                    dissect_japan_isup_carrier_information(parameter_tvb, pinfo, parameter_tree, parameter_item);
                    break;
                  case JAPAN_ISUP_PARAM_CHARGE_INF_DELAY:  /* 242 F2 */
                    dissect_japan_isup_charge_inf_delay(parameter_tvb, parameter_tree, parameter_item);
                    break;
                  case JAPAN_ISUP_PARAM_TYPE_ADDITONAL_USER_CAT: /* F3 */
                    dissect_japan_isup_additonal_user_cat(parameter_tvb, pinfo, parameter_tree, parameter_item);
                    break;
                  case JAPAN_ISUP_PARAM_REASON_FOR_CLIP_FAIL: /* F5 */
                    dissect_japan_isup_reason_for_clip_fail(parameter_tvb, parameter_tree, parameter_item);
                    break;
                  case JAPAN_ISUP_PARAM_TYPE_CONTRACTOR_NUMBER: /* F9 */
                    dissect_japan_isup_contractor_number(parameter_tvb, pinfo, parameter_tree, parameter_item);
                    break;
                  case JAPAN_ISUP_PARAM_TYPE_CHARGE_INF_TYPE: /* FA */
                    chg_inf_type = dissect_japan_chg_inf_type(parameter_tvb, parameter_tree, parameter_item);
                    break;
                  case JAPAN_ISUP_PARAM_TYPE_CHARGE_INF:
                    dissect_japan_chg_inf_param(parameter_tvb, pinfo, parameter_tree, parameter_item, chg_inf_type);
                    break;
                  case JAPAN_ISUP_PARAM_TYPE_CHARGE_AREA_INFO:
                    dissect_japan_isup_charge_area_info(parameter_tvb, pinfo, parameter_tree, parameter_item);
                    break;
                  default:
                    dissect_isup_unknown_parameter(parameter_tvb, parameter_tree, parameter_item);
                    break;
                }
                break;
              default:
                dissect_isup_unknown_parameter(parameter_tvb, parameter_tree, parameter_item);
                break;
            }
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
  TODO: Actually make this dissect ANSI :) - It's still plain old ITU for now
*/
static void
dissect_ansi_isup_optional_parameter(tvbuff_t *optional_parameters_tvb, packet_info *pinfo, proto_tree *isup_tree, guint8 itu_isup_variant)
{ proto_item *parameter_item;
  proto_tree *parameter_tree;
  gint        offset = 0;
  guint       parameter_type, parameter_length, actual_length;
  tvbuff_t   *parameter_tvb;
  guint8      octet;

  /* Dissect all optional parameters while end of message isn't reached */
  parameter_type = 0xFF; /* Start-initialization since parameter_type is used for while-condition */

  while ((tvb_reported_length_remaining(optional_parameters_tvb, offset)  >= 1) && (parameter_type != PARAM_TYPE_END_OF_OPT_PARAMS)) {
    parameter_type = tvb_get_guint8(optional_parameters_tvb, offset);

    if (parameter_type != PARAM_TYPE_END_OF_OPT_PARAMS) {
      parameter_length = tvb_get_guint8(optional_parameters_tvb, offset + PARAMETER_TYPE_LENGTH);

      parameter_tree = proto_tree_add_subtree_format(isup_tree, optional_parameters_tvb,
                                           offset, parameter_length  + PARAMETER_TYPE_LENGTH + PARAMETER_LENGTH_IND_LENGTH,
                                           ett_isup_parameter, &parameter_item, "Parameter: (t=%u, l=%u): %s", parameter_type, parameter_length, val_to_str_ext(parameter_type, &ansi_isup_parameter_type_value_ext, "Unknown"));
      proto_tree_add_uint(parameter_tree, hf_isup_opt_parameter_type, optional_parameters_tvb, offset,
                                 PARAMETER_TYPE_LENGTH, parameter_type);
      offset += PARAMETER_TYPE_LENGTH;

      octet = tvb_get_guint8(optional_parameters_tvb, offset);

      proto_tree_add_uint(parameter_tree, hf_isup_parameter_length, optional_parameters_tvb, offset,
                                 PARAMETER_LENGTH_IND_LENGTH, parameter_length);
      offset += PARAMETER_LENGTH_IND_LENGTH;
      if (octet == 0)
        continue;

      actual_length = tvb_reported_length_remaining(optional_parameters_tvb, offset);
      if (actual_length > 0) {
        parameter_tvb = tvb_new_subset_length_caplen(optional_parameters_tvb, offset, MIN(parameter_length, actual_length), parameter_length);
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
            dissect_isup_called_party_number_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_SUBSQT_NR:
            dissect_isup_subsequent_number_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_NATURE_OF_CONN_IND:
            dissect_isup_nature_of_connection_indicators_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_FORW_CALL_IND:
            dissect_isup_forward_call_indicators_parameter(parameter_tvb, pinfo, parameter_item, parameter_tree);
            break;
          case PARAM_TYPE_OPT_FORW_CALL_IND:
            dissect_isup_optional_forward_call_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_CALLING_PRTY_CATEG:
            dissect_isup_calling_partys_category_parameter(parameter_tvb, parameter_tree, parameter_item, itu_isup_variant);
            break;
          case PARAM_TYPE_CALLING_PARTY_NR:
            dissect_isup_calling_party_number_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_REDIRECTING_NR:
            dissect_isup_redirecting_number_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_REDIRECTION_NR:
            dissect_isup_redirection_number_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
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
            dissect_ansi_isup_backward_call_indicators_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
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
            dissect_isup_range_and_status_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
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
            dissect_isup_connected_number_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_SUSP_RESUME_IND:
            dissect_isup_suspend_resume_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_TRANSIT_NETW_SELECT:
            dissect_ansi_isup_transit_network_selection_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
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
            dissect_isup_original_called_number_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
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
            dissect_isup_location_number_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
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
            dissect_isup_call_transfer_number_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
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
            dissect_isup_redirect_capability_parameter(parameter_tvb, parameter_tree, parameter_item, itu_isup_variant);
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
            dissect_isup_called_in_number_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
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
            dissect_isup_redirect_counter_parameter(parameter_tvb, parameter_tree, parameter_item, itu_isup_variant);
            break;
          case PARAM_TYPE_COLLECT_CALL_REQ:
            dissect_isup_collect_call_request_parameter(parameter_tvb, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_CALLING_GEODETIC_LOCATION:
            dissect_isup_calling_geodetic_location_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_GENERIC_NR:
            dissect_isup_generic_number_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_JURISDICTION:
            dissect_isup_jurisdiction_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_GENERIC_NAME:
            dissect_isup_generic_name_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_GENERIC_DIGITS:
            dissect_isup_generic_digits_parameter(parameter_tvb, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_CHARGE_NR:
            dissect_isup_charge_number_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
            break;
          case PARAM_TYPE_APPLICATON_TRANS:
            dissect_isup_application_transport_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
            break;
          case ANSI_ISUP_PARAM_TYPE_CARRIER_ID:
            dissect_ansi_isup_param_carrier_id(parameter_tvb, pinfo, parameter_tree, parameter_item);
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
      proto_tree_add_uint_format(isup_tree, hf_isup_parameter_type, optional_parameters_tvb , offset,
                                 PARAMETER_TYPE_LENGTH, parameter_type, "End of optional parameters (%u)", parameter_type);
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
  proto_item *parameter_item;
  proto_tree *parameter_tree;
  tvbuff_t   *parameter_tvb;
  gint        offset = 0;
  gint        parameter_type, actual_length;

  /* Do stuff for first mandatory fixed parameter: CVR Response Indicator */
  parameter_type = ANSI_ISUP_PARAM_TYPE_CVR_RESP_IND;
  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb, offset, CVR_RESP_IND_LENGTH,
                                    ett_isup_parameter, &parameter_item, "CVR Response Indicator");

  proto_tree_add_uint_format_value(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type,
                             "%u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "CVR Response Indicator"));

  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);

  parameter_tvb = tvb_new_subset_length_caplen(message_tvb, offset, MIN(CVR_RESP_IND_LENGTH, actual_length), CVR_RESP_IND_LENGTH);
  dissect_isup_cvr_response_ind_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += CVR_RESP_IND_LENGTH;

  /* Do stuff for second mandatory fixed parameter: CG Characteristics Indicator */
  parameter_type = ANSI_ISUP_PARAM_TYPE_CG_CHAR_IND;
  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb, offset,
                                       CG_CHAR_IND_LENGTH, ett_isup_parameter, &parameter_item,
                                       "Circuit Group Characteristics Indicators");
  proto_tree_add_uint_format_value(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type,
                             "%u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &isup_parameter_type_value_ext, "Circuit Group Characters"));
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb, offset, MIN(CG_CHAR_IND_LENGTH, actual_length), CG_CHAR_IND_LENGTH);
  dissect_isup_circuit_group_char_ind_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += CG_CHAR_IND_LENGTH;

  return offset;
}

/* ------------------------------------------------------------------
  Dissector Message Type Circuit Reservation
 */
static gint
dissect_ansi_isup_circuit_reservation_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *isup_tree)
{ proto_item *parameter_item;
  proto_tree *parameter_tree;
  tvbuff_t   *parameter_tvb;
  gint        offset = 0;
  gint        parameter_type, actual_length;

  /* Do stuff for mandatory fixed parameter: Nature of Connection Indicators */
  parameter_type = PARAM_TYPE_NATURE_OF_CONN_IND;
  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb, offset,
                                       NATURE_OF_CONNECTION_IND_LENGTH, ett_isup_parameter, &parameter_item,
                                       "Nature of Connection Indicators");
  proto_tree_add_uint(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type);
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb, offset, MIN(NATURE_OF_CONNECTION_IND_LENGTH, actual_length), NATURE_OF_CONNECTION_IND_LENGTH);
  dissect_isup_nature_of_connection_indicators_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
  offset += NATURE_OF_CONNECTION_IND_LENGTH;

  return offset;
}

/* ------------------------------------------------------------------
  Dissector Message Type Initial address message
 */
static gint
dissect_isup_initial_address_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *isup_tree, guint8 itu_isup_variant)
{ proto_item *parameter_item;
  proto_tree *parameter_tree;
  tvbuff_t   *parameter_tvb;
  gint        offset = 0;
  gint        parameter_type, parameter_pointer, parameter_length, actual_length;

  /* Do stuff for first mandatory fixed parameter: Nature of Connection Indicators */
  parameter_type = PARAM_TYPE_NATURE_OF_CONN_IND;
  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb, offset,
                                       NATURE_OF_CONNECTION_IND_LENGTH, ett_isup_parameter, &parameter_item,
                                       "Nature of Connection Indicators");
  proto_tree_add_uint(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type);
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb, offset, MIN(NATURE_OF_CONNECTION_IND_LENGTH, actual_length), NATURE_OF_CONNECTION_IND_LENGTH);
  dissect_isup_nature_of_connection_indicators_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
  offset += NATURE_OF_CONNECTION_IND_LENGTH;

  /* Do stuff for 2nd mandatory fixed parameter: Forward Call Indicators */
  parameter_type =  PARAM_TYPE_FORW_CALL_IND;
  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb, offset,
                                       FORWARD_CALL_IND_LENGTH, ett_isup_parameter, &parameter_item,
                                       "Forward Call Indicators");
  proto_tree_add_uint(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type);
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb, offset, MIN(FORWARD_CALL_IND_LENGTH, actual_length), FORWARD_CALL_IND_LENGTH);
  dissect_isup_forward_call_indicators_parameter(parameter_tvb, pinfo, parameter_item, parameter_tree);
  offset +=  FORWARD_CALL_IND_LENGTH;

  /* Do stuff for 3nd mandatory fixed parameter: Calling party's category */
  parameter_type = PARAM_TYPE_CALLING_PRTY_CATEG;
  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb, offset,
                                       CALLING_PRTYS_CATEGORY_LENGTH,
                                        ett_isup_parameter, &parameter_item,
                                       "Calling Party's category");
  proto_tree_add_uint(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type);
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb, offset, MIN(CALLING_PRTYS_CATEGORY_LENGTH, actual_length), CALLING_PRTYS_CATEGORY_LENGTH);
  dissect_isup_calling_partys_category_parameter(parameter_tvb, parameter_tree, parameter_item, itu_isup_variant);
  offset += CALLING_PRTYS_CATEGORY_LENGTH;

  switch (isup_standard) {
    case ITU_STANDARD:
      /* If ITU, do stuff for 4th mandatory fixed parameter: Transmission medium requirement */
      parameter_type = PARAM_TYPE_TRANSM_MEDIUM_REQU;
      parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb, offset,
                                           TRANSMISSION_MEDIUM_REQUIREMENT_LENGTH,
                                           ett_isup_parameter, &parameter_item,
                                           "Transmission medium requirement");
      proto_tree_add_uint(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type);
      actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
      parameter_tvb = tvb_new_subset_length_caplen(message_tvb,
                                     offset,
                                     MIN(TRANSMISSION_MEDIUM_REQUIREMENT_LENGTH, actual_length),
                                     TRANSMISSION_MEDIUM_REQUIREMENT_LENGTH);
      dissect_isup_transmission_medium_requirement_parameter(parameter_tvb, parameter_tree, parameter_item);
      offset += TRANSMISSION_MEDIUM_REQUIREMENT_LENGTH;
      break;
    case ANSI_STANDARD:
      /* If ANSI, do stuff for the first mandatory variable parameter, USER_SERVICE_INFORMATION */
      parameter_type = PARAM_TYPE_USER_SERVICE_INFO;
      parameter_pointer = tvb_get_guint8(message_tvb, offset);
      parameter_length  = tvb_get_guint8(message_tvb, offset + parameter_pointer);
      parameter_tree    = proto_tree_add_subtree(isup_tree, message_tvb,
                                              offset +  parameter_pointer,
                                              parameter_length + PARAMETER_LENGTH_IND_LENGTH,
                                               ett_isup_parameter, &parameter_item,
                                              "User Service Information");
      proto_tree_add_uint(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type);
      proto_tree_add_uint(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset,
                                 PARAMETER_POINTER_LENGTH, parameter_pointer);
      proto_tree_add_uint(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer,
                                 PARAMETER_LENGTH_IND_LENGTH, parameter_length);
      actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
      parameter_tvb = tvb_new_subset_length_caplen(message_tvb,
                                     offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH,
                                     MIN(parameter_length, actual_length),
                                     parameter_length);
      dissect_isup_user_service_information_parameter(parameter_tvb, parameter_tree, parameter_item);
      offset += PARAMETER_POINTER_LENGTH;
      break;
  }

  /* Do stuff for mandatory variable parameter Called party number */
  parameter_type = PARAM_TYPE_CALLED_PARTY_NR;
  parameter_pointer = tvb_get_guint8(message_tvb, offset);
  parameter_length  = tvb_get_guint8(message_tvb, offset + parameter_pointer);

  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb,
                                       offset +  parameter_pointer,
                                       parameter_length + PARAMETER_LENGTH_IND_LENGTH,
                                        ett_isup_parameter, &parameter_item,
                                       "Called Party Number");
  proto_tree_add_uint(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type);
  proto_tree_add_uint(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset,
                             PARAMETER_POINTER_LENGTH, parameter_pointer);
  proto_tree_add_uint(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer,
                             PARAMETER_LENGTH_IND_LENGTH, parameter_length);
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb,
                                 offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH,
                                 MIN(parameter_length, actual_length),
                                 parameter_length);
  dissect_isup_called_party_number_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
  offset += PARAMETER_POINTER_LENGTH;

  return offset;
}

/* ------------------------------------------------------------------
  Dissector Message Type subsequent address message
 */
static gint dissect_isup_subsequent_address_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *isup_tree)
{ proto_item *parameter_item;
  proto_tree *parameter_tree;
  tvbuff_t   *parameter_tvb;
  gint        offset = 0;
  gint        parameter_type, parameter_pointer, parameter_length, actual_length;

  /* Do stuff for mandatory variable parameter Subsequent number */
  parameter_type = PARAM_TYPE_SUBSQT_NR;

  parameter_pointer = tvb_get_guint8(message_tvb, offset);
  parameter_length  = tvb_get_guint8(message_tvb, offset + parameter_pointer);

  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb,
                                       offset +  parameter_pointer,
                                       parameter_length + PARAMETER_LENGTH_IND_LENGTH,
                                        ett_isup_parameter, &parameter_item,
                                       "Subsequent Number");
  proto_tree_add_uint(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type);
  proto_tree_add_uint(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset,
                             PARAMETER_POINTER_LENGTH, parameter_pointer);
  proto_tree_add_uint(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer,
                             PARAMETER_LENGTH_IND_LENGTH, parameter_length);
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb,
                                 offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH,
                                 MIN(parameter_length, actual_length),
                                 parameter_length);
  dissect_isup_subsequent_number_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
  offset += PARAMETER_POINTER_LENGTH;

  return offset;
}

/* ------------------------------------------------------------------
  Dissector Message Type Information request message
 */
static gint
dissect_isup_information_request_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{ proto_item *parameter_item;
  proto_tree *parameter_tree;
  tvbuff_t   *parameter_tvb;
  gint        offset = 0;
  gint        parameter_type, actual_length;

  /* Do stuff for first mandatory fixed parameter: Information request indicators*/
  parameter_type = PARAM_TYPE_INFO_REQ_IND;
  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb, offset,
                                       INFO_REQUEST_IND_LENGTH,
                                        ett_isup_parameter, &parameter_item,
                                       "Information request indicators");
  proto_tree_add_uint(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type);
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb, offset, MIN(INFO_REQUEST_IND_LENGTH, actual_length), INFO_REQUEST_IND_LENGTH);
  dissect_isup_information_request_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += INFO_REQUEST_IND_LENGTH;
  return offset;
}

/* ------------------------------------------------------------------
  Dissector Message Type Information
 */
static gint
dissect_isup_information_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{
  proto_item *parameter_item;
  proto_tree *parameter_tree;
  tvbuff_t   *parameter_tvb;
  gint        offset = 0;
  gint        parameter_type, actual_length;

  /* Do stuff for first mandatory fixed parameter: Information  indicators*/
  parameter_type = PARAM_TYPE_INFO_IND;
  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb, offset,
                                       INFO_IND_LENGTH, ett_isup_parameter, &parameter_item,
                                       "Information indicators");
  proto_tree_add_uint(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type);
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb, offset, MIN(INFO_IND_LENGTH, actual_length), INFO_IND_LENGTH);
  dissect_isup_information_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += INFO_IND_LENGTH;
  return offset;
}

/* ------------------------------------------------------------------
  Dissector Message Type Continuity
 */
static gint
dissect_isup_continuity_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{ proto_item *parameter_item;
  proto_tree *parameter_tree;
  tvbuff_t   *parameter_tvb;
  gint        offset = 0;
  gint        parameter_type, actual_length;

  /* Do stuff for first mandatory fixed parameter: Continuity indicators*/
  parameter_type = PARAM_TYPE_CONTINUITY_IND;
  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb, offset,
                                       CONTINUITY_IND_LENGTH, ett_isup_parameter, &parameter_item,
                                       "Continuity indicators");
  proto_tree_add_uint(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type);
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb, offset, MIN(CONTINUITY_IND_LENGTH, actual_length), CONTINUITY_IND_LENGTH);
  dissect_isup_continuity_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += CONTINUITY_IND_LENGTH;
  return offset;
}

/* ------------------------------------------------------------------
  Dissector Message Type Address complete
 */
static gint
dissect_isup_address_complete_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *isup_tree)
{
  proto_item *parameter_item;
  proto_tree *parameter_tree;
  tvbuff_t   *parameter_tvb;
  gint        offset = 0;
  gint        parameter_type, actual_length;

  /* Do stuff for first mandatory fixed parameter: backward call indicators*/
  parameter_type = PARAM_TYPE_BACKW_CALL_IND;
  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb, offset,
                                       BACKWARD_CALL_IND_LENGTH, ett_isup_parameter, &parameter_item,
                                       "Backward Call Indicators");
  proto_tree_add_uint(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type);
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb, offset, MIN(BACKWARD_CALL_IND_LENGTH, actual_length), BACKWARD_CALL_IND_LENGTH);
  dissect_isup_backward_call_indicators_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
  offset += BACKWARD_CALL_IND_LENGTH;
  return offset;
}

static gint
dissect_ansi_isup_address_complete_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *isup_tree)
{
  proto_item *parameter_item;
  proto_tree *parameter_tree;
  tvbuff_t   *parameter_tvb;
  gint        offset = 0;
  gint        parameter_type, actual_length;

  /* Do stuff for first mandatory fixed parameter: backward call indicators*/
  parameter_type = PARAM_TYPE_BACKW_CALL_IND;
  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb, offset,
    BACKWARD_CALL_IND_LENGTH, ett_isup_parameter, &parameter_item,
    "Backward Call Indicators");
  proto_tree_add_uint(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type);
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb, offset, MIN(BACKWARD_CALL_IND_LENGTH, actual_length), BACKWARD_CALL_IND_LENGTH);
  dissect_ansi_isup_backward_call_indicators_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
  offset += BACKWARD_CALL_IND_LENGTH;
  return offset;
}

/* ------------------------------------------------------------------
  Dissector Message Type Connect
 */
static gint
dissect_isup_connect_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *isup_tree)
{ proto_item *parameter_item;
  proto_tree *parameter_tree;
  tvbuff_t   *parameter_tvb;
  gint        offset = 0;
  gint        parameter_type, actual_length;

  /* Do stuff for first mandatory fixed parameter: backward call indicators*/
  parameter_type = PARAM_TYPE_BACKW_CALL_IND;
  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb, offset,
                                       BACKWARD_CALL_IND_LENGTH, ett_isup_parameter, &parameter_item,
                                       "Backward Call Indicators");
  proto_tree_add_uint(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type);
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb, offset, MIN(BACKWARD_CALL_IND_LENGTH, actual_length), BACKWARD_CALL_IND_LENGTH);
  dissect_isup_backward_call_indicators_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
  offset += BACKWARD_CALL_IND_LENGTH;
  return offset;
}

/* ------------------------------------------------------------------
  Dissector Message Type release message
 */
static gint
dissect_isup_release_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{ proto_item *parameter_item;
  proto_tree *parameter_tree;
  tvbuff_t   *parameter_tvb;
  gint        offset = 0;
  gint        parameter_type, parameter_pointer, parameter_length, actual_length;

  /* Do stuff for mandatory variable parameter Cause indicators */
  parameter_type =  PARAM_TYPE_CAUSE_INDICATORS;

  parameter_pointer = tvb_get_guint8(message_tvb, offset);
  parameter_length  = tvb_get_guint8(message_tvb, offset + parameter_pointer);

  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb,
                                       offset +  parameter_pointer,
                                       parameter_length + PARAMETER_LENGTH_IND_LENGTH,
                                        ett_isup_parameter, &parameter_item,
                                       "Cause indicators");
  proto_tree_add_uint(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type);
  proto_tree_add_uint(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset,
                             PARAMETER_POINTER_LENGTH, parameter_pointer);
  proto_tree_add_uint(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer,
                             PARAMETER_LENGTH_IND_LENGTH, parameter_length);
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb,
                                 offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH,
                                 MIN(parameter_length, actual_length),
                                 parameter_length);
  switch (isup_standard) {
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
{ proto_item *parameter_item;
  proto_tree *parameter_tree;
  tvbuff_t   *parameter_tvb;
  gint        offset = 0;
  gint        parameter_type, actual_length;

  /* Do stuff for first mandatory fixed parameter: backward call indicators*/
  parameter_type = PARAM_TYPE_SUSP_RESUME_IND;
  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb, offset,
                                       SUSPEND_RESUME_IND_LENGTH,
                                        ett_isup_parameter, &parameter_item,
                                       "Suspend/Resume indicator");
  proto_tree_add_uint(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type);
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb, offset, MIN(SUSPEND_RESUME_IND_LENGTH, actual_length), SUSPEND_RESUME_IND_LENGTH);
  dissect_isup_suspend_resume_indicators_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += SUSPEND_RESUME_IND_LENGTH;
  return offset;
}

/* ------------------------------------------------------------------
  Dissector Message Type Circuit group reset/query message
 */
static gint
dissect_isup_circuit_group_reset_query_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *isup_tree)
{ proto_item *parameter_item;
  proto_tree *parameter_tree;
  tvbuff_t   *parameter_tvb;
  gint        offset = 0;
  gint        parameter_type, parameter_pointer, parameter_length, actual_length;

  /* Do stuff for mandatory variable parameter range and status*/
  parameter_type =  PARAM_TYPE_RANGE_AND_STATUS;

  parameter_pointer = tvb_get_guint8(message_tvb, offset);
  parameter_length  = tvb_get_guint8(message_tvb, offset + parameter_pointer);

  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb,
                                       offset +  parameter_pointer,
                                       parameter_length + PARAMETER_LENGTH_IND_LENGTH,
                                        ett_isup_parameter, &parameter_item,
                                       "Range and status");
  proto_tree_add_uint(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type);
  proto_tree_add_uint(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset,
                             PARAMETER_POINTER_LENGTH, parameter_pointer);
  proto_tree_add_uint(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer,
                             PARAMETER_LENGTH_IND_LENGTH, parameter_length);
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb,
                                 offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH,
                                 MIN(parameter_length, actual_length),
                                 parameter_length);
  dissect_isup_range_and_status_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
  offset += PARAMETER_POINTER_LENGTH;

  return offset;
}

/* ------------------------------------------------------------------
  Dissector Message Type Circuit group blocking/blocking ack/unblocking/unblocking ack messages
 */
static gint
dissect_isup_circuit_group_blocking_messages(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *isup_tree)
{ proto_item *parameter_item;
  proto_tree *parameter_tree;
  tvbuff_t   *parameter_tvb;
  gint        offset = 0;
  gint        parameter_type, parameter_pointer, parameter_length, actual_length;

   /* Do stuff for first mandatory fixed parameter: circuit group supervision message type*/
  parameter_type = PARAM_TYPE_CIRC_GRP_SV_MSG_TYPE;
  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb, offset,
                                       CIRC_GRP_SV_MSG_TYPE_LENGTH,
                                        ett_isup_parameter, &parameter_item,
                                       "Circuit group supervision message type");
  proto_tree_add_uint(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type);
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb, offset, MIN(CIRC_GRP_SV_MSG_TYPE_LENGTH, actual_length), CIRC_GRP_SV_MSG_TYPE_LENGTH);
  dissect_isup_circuit_group_supervision_message_type_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += CIRC_GRP_SV_MSG_TYPE_LENGTH;

  /* Do stuff for mandatory variable parameter range and status*/
  parameter_type =  PARAM_TYPE_RANGE_AND_STATUS;

  parameter_pointer = tvb_get_guint8(message_tvb, offset);
  parameter_length  = tvb_get_guint8(message_tvb, offset + parameter_pointer);

  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb,
                                       offset +  parameter_pointer,
                                       parameter_length + PARAMETER_LENGTH_IND_LENGTH,
                                        ett_isup_parameter, &parameter_item,
                                       "Range and status");
  proto_tree_add_uint(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type);
  proto_tree_add_uint(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset,
                             PARAMETER_POINTER_LENGTH, parameter_pointer);
  proto_tree_add_uint(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer,
                             PARAMETER_LENGTH_IND_LENGTH, parameter_length);
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb,
                                 offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH,
                                 MIN(parameter_length, actual_length),
                                 parameter_length);
  dissect_isup_range_and_status_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
  offset += PARAMETER_POINTER_LENGTH;

  return offset;
}

/* ------------------------------------------------------------------
  Dissector Message Type Facility request/accepted
 */
static gint
dissect_isup_facility_request_accepted_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{ proto_item *parameter_item;
  proto_tree *parameter_tree;
  tvbuff_t   *parameter_tvb;
  gint        offset = 0;
  gint        parameter_type, actual_length;

  /* Do stuff for first mandatory fixed parameter: facility indicators*/
  parameter_type = PARAM_TYPE_FACILITY_IND;
  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb, offset,
                                       FACILITY_IND_LENGTH,
                                        ett_isup_parameter, &parameter_item,
                                       "Facility indicator");
  proto_tree_add_uint(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type);
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb, offset, MIN(FACILITY_IND_LENGTH, actual_length), FACILITY_IND_LENGTH);
  dissect_isup_facility_ind_parameter(parameter_tvb, parameter_item);
  offset += FACILITY_IND_LENGTH;
  return offset;
}

/* ------------------------------------------------------------------
  Dissector Message Type Facility reject
 */
static gint
dissect_isup_facility_reject_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{ proto_item *parameter_item;
  proto_tree *parameter_tree;
  tvbuff_t   *parameter_tvb;
  gint        offset = 0;
  gint        parameter_type, parameter_pointer, parameter_length, actual_length;

  /* Do stuff for first mandatory fixed parameter: facility indicators*/
  parameter_type = PARAM_TYPE_FACILITY_IND;
  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb, offset,
                                       FACILITY_IND_LENGTH,
                                        ett_isup_parameter, &parameter_item,
                                       "Facility indicator");
  proto_tree_add_uint(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type);
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb, offset, MIN(FACILITY_IND_LENGTH, actual_length), FACILITY_IND_LENGTH);
  dissect_isup_facility_ind_parameter(parameter_tvb, parameter_item);
  offset += FACILITY_IND_LENGTH;

  /* Do stuff for mandatory variable parameter Cause indicators */
  parameter_type =  PARAM_TYPE_CAUSE_INDICATORS;

  parameter_pointer = tvb_get_guint8(message_tvb, offset);
  parameter_length  = tvb_get_guint8(message_tvb, offset + parameter_pointer);

  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb,
                                       offset +  parameter_pointer,
                                       parameter_length + PARAMETER_LENGTH_IND_LENGTH,
                                        ett_isup_parameter, &parameter_item,
                                       "Cause indicators, see Q.850");
  proto_tree_add_uint(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type);
  proto_tree_add_uint(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb,
                             offset, PARAMETER_POINTER_LENGTH, parameter_pointer);
  proto_tree_add_uint(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer,
                             PARAMETER_LENGTH_IND_LENGTH, parameter_length);
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb,
                                 offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH,
                                 MIN(parameter_length, actual_length),
                                 parameter_length);
  switch (isup_standard) {
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
dissect_isup_circuit_group_reset_acknowledgement_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *isup_tree)
{ proto_item *parameter_item;
  proto_tree *parameter_tree;
  tvbuff_t   *parameter_tvb;
  gint        offset = 0;
  gint        parameter_type, parameter_pointer, parameter_length, actual_length;

  /* Do stuff for mandatory variable parameter range and status*/
  parameter_type =  PARAM_TYPE_RANGE_AND_STATUS;

  parameter_pointer = tvb_get_guint8(message_tvb, offset);
  parameter_length  = tvb_get_guint8(message_tvb, offset + parameter_pointer);

  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb,
                                       offset +  parameter_pointer,
                                       parameter_length + PARAMETER_LENGTH_IND_LENGTH,
                                       ett_isup_parameter, &parameter_item,
                                       "Range and status");
  proto_tree_add_uint(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type);
  proto_tree_add_uint(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset,
                             PARAMETER_POINTER_LENGTH, parameter_pointer);
  proto_tree_add_uint(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer,
                             PARAMETER_LENGTH_IND_LENGTH, parameter_length);
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb,
                                 offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH,
                                 MIN(parameter_length, actual_length),
                                 parameter_length);
  dissect_isup_range_and_status_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
  offset += PARAMETER_POINTER_LENGTH;

  return offset;
}

/* ------------------------------------------------------------------
  Dissector Message Type Circuit group query response message
 */
static gint
dissect_isup_circuit_group_query_response_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *isup_tree)
{ proto_item *parameter_item;
  proto_tree *parameter_tree;
  tvbuff_t   *parameter_tvb;
  gint        offset = 0;
  gint        parameter_type, parameter_pointer, parameter_length, actual_length;

  /* Do stuff for 1. mandatory variable parameter range and status*/
  parameter_type =  PARAM_TYPE_RANGE_AND_STATUS;

  parameter_pointer = tvb_get_guint8(message_tvb, offset);
  parameter_length  = tvb_get_guint8(message_tvb, offset + parameter_pointer);

  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb,
                                       offset +  parameter_pointer,
                                       parameter_length + PARAMETER_LENGTH_IND_LENGTH,
                                        ett_isup_parameter, &parameter_item,
                                       "Range and status");
  proto_tree_add_uint(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type);
  proto_tree_add_uint(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset,
                             PARAMETER_POINTER_LENGTH, parameter_pointer);
  proto_tree_add_uint(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer,
                             PARAMETER_LENGTH_IND_LENGTH, parameter_length);
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb,
                                 offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH,
                                 MIN(parameter_length, actual_length),
                                 parameter_length);
  dissect_isup_range_and_status_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
  offset += PARAMETER_POINTER_LENGTH;

  /* Do stuff for 2. mandatory variable parameter Circuit state indicator*/
  parameter_type = PARAM_TYPE_CIRC_STATE_IND;

  parameter_pointer = tvb_get_guint8(message_tvb, offset);
  parameter_length  = tvb_get_guint8(message_tvb, offset + parameter_pointer);

  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb,
                                       offset +  parameter_pointer,
                                       parameter_length + PARAMETER_LENGTH_IND_LENGTH,
                                        ett_isup_parameter, &parameter_item,
                                       "Circuit state indicator (national use)");
  proto_tree_add_uint(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type);
  proto_tree_add_uint(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset,
                             PARAMETER_POINTER_LENGTH, parameter_pointer);
  proto_tree_add_uint(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer,
                             PARAMETER_LENGTH_IND_LENGTH, parameter_length);
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb,
                                 offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH,
                                 MIN(parameter_length, actual_length),
                                 parameter_length);
  dissect_isup_circuit_state_ind_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += PARAMETER_POINTER_LENGTH;

  return offset;
}

/* ------------------------------------------------------------------
  Dissector Message Type Call Progress
*/
static gint
dissect_isup_call_progress_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{ proto_item *parameter_item;
  proto_tree *parameter_tree;
  tvbuff_t   *parameter_tvb;
  gint        offset = 0;
  gint        parameter_type, actual_length;

  /* Do stuff for first mandatory fixed parameter: Event information*/
  parameter_type = PARAM_TYPE_EVENT_INFO;
  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb, offset,
                                       EVENT_INFO_LENGTH, ett_isup_parameter, &parameter_item,
                                       "Event information");
  proto_tree_add_uint(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type);
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb, offset, MIN(EVENT_INFO_LENGTH, actual_length), EVENT_INFO_LENGTH);
  dissect_isup_event_information_parameter(parameter_tvb, parameter_tree, parameter_item);
  offset += EVENT_INFO_LENGTH;
  return offset;
}

/* ------------------------------------------------------------------
  Dissector Message Type User-to-User information
 */
static gint
dissect_isup_user_to_user_information_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *isup_tree)
{ proto_item *parameter_item;
  proto_tree *parameter_tree;
  tvbuff_t   *parameter_tvb;
  gint        offset = 0;
  gint        parameter_type, parameter_pointer, parameter_length, actual_length;

  /* Do stuff for mandatory variable parameter User-to-user information*/
  parameter_type =  PARAM_TYPE_USER_TO_USER_INFO;

  parameter_pointer = tvb_get_guint8(message_tvb, offset);
  parameter_length  = tvb_get_guint8(message_tvb, offset + parameter_pointer);

  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb,
                                       offset +  parameter_pointer,
                                       parameter_length + PARAMETER_LENGTH_IND_LENGTH,
                                       ett_isup_parameter, &parameter_item,
                                       "User-to-user information, see Q.931");
  proto_tree_add_uint(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type);
  proto_tree_add_uint(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset,
                             PARAMETER_POINTER_LENGTH, parameter_pointer);
  proto_tree_add_uint(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer,
                             PARAMETER_LENGTH_IND_LENGTH, parameter_length);
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb,
                                 offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH,
                                 MIN(parameter_length, actual_length),
                                 parameter_length);
  dissect_isup_user_to_user_information_parameter(parameter_tvb, pinfo, parameter_tree, parameter_item);
  offset += PARAMETER_POINTER_LENGTH;

  return offset;
}

/* ------------------------------------------------------------------
  Dissector Message Type Confusion
 */
static gint
dissect_isup_confusion_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{ proto_item *parameter_item;
  proto_tree *parameter_tree;
  tvbuff_t   *parameter_tvb;
  gint        offset = 0;
  gint        parameter_type, parameter_pointer, parameter_length, actual_length;

  /* Do stuff for mandatory variable parameter Cause indicators */
  parameter_type =  PARAM_TYPE_CAUSE_INDICATORS;

  parameter_pointer = tvb_get_guint8(message_tvb, offset);
  parameter_length  = tvb_get_guint8(message_tvb, offset + parameter_pointer);

  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb,
                                       offset +  parameter_pointer,
                                       parameter_length + PARAMETER_LENGTH_IND_LENGTH,
                                        ett_isup_parameter, &parameter_item,
                                       "Cause indicators, see Q.850");
  proto_tree_add_uint(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type);
  proto_tree_add_uint(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset,
                             PARAMETER_POINTER_LENGTH, parameter_pointer);
  proto_tree_add_uint(parameter_tree, hf_isup_parameter_length,
                             message_tvb, offset + parameter_pointer, PARAMETER_LENGTH_IND_LENGTH,
                             parameter_length);
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb,
                                 offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH,
                                 MIN(parameter_length, actual_length),
                                 parameter_length);

  switch (isup_standard) {
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

/* Dissect national messages */
static int
dissect_french_isup_charging_pulse_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{
  gint offset = 0;

  proto_tree_add_item(isup_tree, hf_isup_french_coll_field, message_tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  proto_tree_add_item(isup_tree, hf_isup_french_msg_num, message_tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  return offset;
}

static const value_string israeli_cmi_current_rate[] = {
  { 0,   "Current rate not present" },
  { 1,   "Rate expressed in deciseconds" },
  { 2,   "Rate expressed in centiseconds" },
  { 3,   "Rate expressed in milliseconds" },
  { 0,   NULL}
};
static const value_string israeli_cmi_next_rate[] = {
  { 0,   "Time indicator and next rate not present" },
  { 1,   "Rate expressed in deciseconds" },
  { 2,   "Rate expressed in centiseconds" },
  { 3,   "Rate expressed in milliseconds" },
  { 0,   NULL}
};
static const value_string israeli_time_indicators[] = {
  {  0,   "spare" },
  {  1,   "00.30 H" },
  {  2,   "01.00 H" },
  {  3,   "01.30 H" },
  {  4,   "02.00 H" },
  {  5,   "02.30 H" },
  {  6,   "03.00 H" },
  {  7,   "03.30 H" },
  {  8,   "04.00 H" },
  {  9,   "04.30 H" },
  { 10,   "05.00 H" },
  { 11,   "05.30 H" },
  { 12,   "06.00 H" },
  { 13,   "06.30 H" },
  { 14,   "07.00 H" },
  { 15,   "07.30 H" },
  { 16,   "08.00 H" },
  { 17,   "08.30 H" },
  { 18,   "09.00 H" },
  { 19,   "09.30 H" },
  { 20,   "10.00 H" },
  { 21,   "10.30 H" },
  { 22,   "11.00 H" },
  { 23,   "11.30 H" },
  { 24,   "12.00 H" },
  { 25,   "12.30 H" },
  { 26,   "13.00 H" },
  { 27,   "13.30 H" },
  { 28,   "14.00 H" },
  { 29,   "14.30 H" },
  { 30,   "15.00 H" },
  { 31,   "15.30 H" },
  { 32,   "16.00 H" },
  { 33,   "16.30 H" },
  { 34,   "17.00 H" },
  { 35,   "17.30 H" },
  { 36,   "18.00 H" },
  { 37,   "18.30 H" },
  { 38,   "19.00 H" },
  { 39,   "19.30 H" },
  { 40,   "20.00 H" },
  { 41,   "20.30 H" },
  { 42,   "21.00 H" },
  { 43,   "21.30 H" },
  { 44,   "22.00 H" },
  { 45,   "22.30 H" },
  { 46,   "23.00 H" },
  { 47,   "23.30 H" },
  { 48,   "24.00 H" },
  { 0,   NULL}
};
static value_string_ext israeli_time_indicators_ext = VALUE_STRING_EXT_INIT(israeli_time_indicators);

static int
dissect_israeli_backward_charging_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{
  gint offset = 0;

  proto_tree_add_item(isup_tree, hf_isup_israeli_charging_message_indicators_current, message_tvb, offset, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(isup_tree, hf_isup_israeli_charging_message_indicators_next, message_tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;
  proto_tree_add_item(isup_tree, hf_isup_israeli_current_rate, message_tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;
  proto_tree_add_item(isup_tree, hf_isup_israeli_time_indicator, message_tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;
  proto_tree_add_item(isup_tree, hf_isup_israeli_next_rate, message_tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

  return offset;
}

static int
dissect_israeli_traffic_change_message(tvbuff_t *message_tvb, proto_tree *isup_tree)
{
  gint offset = 0;

  proto_tree_add_item(isup_tree, hf_isup_israeli_charging_message_indicators_current, message_tvb, offset, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(isup_tree, hf_isup_israeli_charging_message_indicators_next, message_tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;
  proto_tree_add_item(isup_tree, hf_isup_israeli_time_indicator, message_tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;
  proto_tree_add_item(isup_tree, hf_isup_israeli_next_rate, message_tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;

  return offset;
}

static int
dissect_japan_chg_inf(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *isup_tree)
{
  proto_item *parameter_item;
  proto_tree *parameter_tree;
  tvbuff_t   *parameter_tvb;
  gint        offset = 0;
  gint        parameter_type, parameter_pointer, parameter_length, actual_length;
  guint8      chg_inf_type;

  /* Do stuff for first mandatory fixed parameter: Charge information type */
  parameter_type = JAPAN_ISUP_PARAM_TYPE_CHARGE_INF_TYPE;
  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb, offset, 1,
                            ett_isup_parameter, &parameter_item, "Charge information type");
  proto_tree_add_uint_format_value(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type,
                             "%u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &japan_isup_parameter_type_value_ext, "unknown"));
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb, offset, MIN(1, actual_length), 1);
  chg_inf_type = tvb_get_guint8(parameter_tvb, 0);
  dissect_japan_chg_inf_type(parameter_tvb, parameter_tree, parameter_item);
  offset += 1;

  /* Do stuff for mandatory variable parameter Charge information */
  parameter_type = JAPAN_ISUP_PARAM_TYPE_CHARGE_INF;
  parameter_pointer = tvb_get_guint8(message_tvb, offset);
  parameter_length  = tvb_get_guint8(message_tvb, offset + parameter_pointer);

  parameter_tree = proto_tree_add_subtree(isup_tree, message_tvb,
                                       offset +  parameter_pointer,
                                       parameter_length + PARAMETER_LENGTH_IND_LENGTH,
                                       ett_isup_parameter, &parameter_item,
                                       "Charge information");
  proto_tree_add_uint_format_value(parameter_tree, hf_isup_mand_parameter_type, message_tvb, 0, 0, parameter_type,
                             "%u (%s)",
                             parameter_type,
                             val_to_str_ext_const(parameter_type, &japan_isup_parameter_type_value_ext, "unknown"));
  proto_tree_add_uint(parameter_tree, hf_isup_mandatory_variable_parameter_pointer, message_tvb, offset,
                      PARAMETER_POINTER_LENGTH, parameter_pointer);
  proto_tree_add_uint(parameter_tree, hf_isup_parameter_length, message_tvb, offset + parameter_pointer,
                      PARAMETER_LENGTH_IND_LENGTH, parameter_length);
  actual_length = tvb_ensure_captured_length_remaining(message_tvb, offset);
  parameter_tvb = tvb_new_subset_length_caplen(message_tvb,
                                 offset + parameter_pointer + PARAMETER_LENGTH_IND_LENGTH,
                                 MIN(parameter_length, actual_length),
                                 parameter_length);

  /* TODO: Dissect the parameter here, switch on type */
  switch (chg_inf_type) {
    case 3:
      /* Advanced Charge Rate Transfer (TDS service) */
      dissect_japan_chg_inf_type_acr(parameter_tvb, parameter_tree, parameter_item);
      break;
    case 254:
      /* Charge rate transfer (flexible charging) */
      dissect_japan_chg_inf_type_crt(parameter_tvb, parameter_tree, parameter_item);
      break;
    default:
      proto_tree_add_expert_format(parameter_tree, pinfo, &ei_isup_not_dissected_yet, parameter_tvb, 0, -1, "Charge information data, not dissected yet");
      break;
  }


  offset += PARAMETER_POINTER_LENGTH;

  return offset;

}

/* ------------------------------------------------------------------ */
static void
dissect_ansi_isup_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *isup_tree, guint8 itu_isup_variant, guint32 circuit_id)
{
  isup_tap_rec_t *tap_rec;

  tvbuff_t   *parameter_tvb;
  tvbuff_t   *optional_parameter_tvb;
  proto_tree *pass_along_tree;
  proto_item *type_item;
  gint        offset, bufferlength;
  guint8      message_type, opt_parameter_pointer;
  gint        opt_part_possible = FALSE; /* default setting - for message types allowing optional
                                            params explicitly set to TRUE in case statement */
  tap_calling_number            = NULL;
  offset                        = 0;

  /* Extract message type field */
  message_type = tvb_get_guint8(message_tvb, 0);

  type_item = proto_tree_add_uint_format(isup_tree, hf_isup_message_type, message_tvb, 0, MESSAGE_TYPE_LENGTH, message_type, "Message type: %s (%u)",
                             val_to_str_ext_const(message_type, &ansi_isup_message_type_value_ext, "reserved"), message_type);

  offset +=  MESSAGE_TYPE_LENGTH;

  tap_rec = wmem_new(pinfo->pool, isup_tap_rec_t);
  tap_rec->message_type   = message_type;
  tap_rec->calling_number = NULL;
  tap_rec->called_number  = NULL;
  tap_rec->circuit_id     = circuit_id;

  parameter_tvb = tvb_new_subset_remaining(message_tvb, offset);

  /* distinguish between message types:*/
  switch (message_type) {
    case MESSAGE_TYPE_INITIAL_ADDR:
      offset += dissect_isup_initial_address_message(parameter_tvb, pinfo, isup_tree, itu_isup_variant);
      opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_SUBSEQ_ADDR:
      offset += dissect_isup_subsequent_address_message(parameter_tvb, pinfo, isup_tree);
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
      offset += dissect_ansi_isup_address_complete_message(parameter_tvb, pinfo, isup_tree);
      opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_CONNECT:
      offset += dissect_isup_connect_message(parameter_tvb, pinfo, isup_tree);
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
      offset += dissect_isup_circuit_group_reset_query_message(parameter_tvb, pinfo, isup_tree);
      break;
    case MESSAGE_TYPE_CIRC_GRP_BLCK:
      offset += dissect_isup_circuit_group_blocking_messages(parameter_tvb, pinfo, isup_tree);
      break;
    case MESSAGE_TYPE_CIRC_GRP_UNBL:
      offset += dissect_isup_circuit_group_blocking_messages(parameter_tvb, pinfo, isup_tree);
      break;
    case MESSAGE_TYPE_CIRC_GRP_BL_ACK:
      offset += dissect_isup_circuit_group_blocking_messages(parameter_tvb, pinfo, isup_tree);
      break;
    case MESSAGE_TYPE_CIRC_GRP_UNBL_ACK:
      offset += dissect_isup_circuit_group_blocking_messages(parameter_tvb, pinfo, isup_tree);
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
      pass_along_tree = proto_tree_add_subtree_format(isup_tree, parameter_tvb, offset, -1,
                                            ett_isup_pass_along_message, NULL, "Pass-along: %s Message (%u)",
                                            val_to_str_ext_const(pa_message_type, &isup_message_type_value_acro_ext, "reserved"),
                                            pa_message_type);
      dissect_ansi_isup_message(parameter_tvb, pinfo, pass_along_tree, itu_isup_variant, circuit_id);
      break;
    }
    case MESSAGE_TYPE_CIRC_GRP_RST_ACK:
      offset += dissect_isup_circuit_group_reset_acknowledgement_message(parameter_tvb, pinfo, isup_tree);
      break;
    case MESSAGE_TYPE_CIRC_GRP_QRY:
      offset += dissect_isup_circuit_group_reset_query_message(parameter_tvb, pinfo, isup_tree);
      break;
    case MESSAGE_TYPE_CIRC_GRP_QRY_RSP:
      offset += dissect_isup_circuit_group_query_response_message(parameter_tvb, pinfo, isup_tree);
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
      bufferlength = tvb_reported_length_remaining(message_tvb, offset);
      if (bufferlength != 0)
        proto_tree_add_expert(isup_tree, pinfo, &ei_isup_format_national_matter, parameter_tvb, 0, bufferlength);
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
      bufferlength = tvb_reported_length_remaining(message_tvb, offset);
      if (bufferlength != 0)
        proto_tree_add_expert(isup_tree, pinfo, &ei_isup_format_national_matter, parameter_tvb, 0, bufferlength);
      break;
    case ANSI_ISUP_MESSAGE_TYPE_CIRCUIT_RES_ACK:
      /* no dissector necessary since no mandatory parameters included */
      break;
    case ANSI_ISUP_MESSAGE_TYPE_CIRCUIT_RES:
      offset += dissect_ansi_isup_circuit_reservation_message(parameter_tvb, pinfo, isup_tree);
      break;
    case ANSI_ISUP_MESSAGE_TYPE_CCT_VAL_TEST_RSP:
      opt_part_possible = TRUE;
      offset += dissect_ansi_isup_circuit_validation_test_resp_message(parameter_tvb, isup_tree);
      break;
    case ANSI_ISUP_MESSAGE_TYPE_CCT_VAL_TEST:
      /* no dissector necessary since no mandatory parameters included */
      break;
    default:
      bufferlength = tvb_reported_length_remaining(message_tvb, offset);
      if (bufferlength != 0)
        expert_add_info(pinfo, type_item, &ei_isup_message_type_unknown);
      break;
  }

  /* extract pointer to start of optional part (if any) */
  if (opt_part_possible == TRUE) {
    opt_parameter_pointer = tvb_get_guint8(message_tvb, offset);
    if (opt_parameter_pointer > 0) {
      proto_tree_add_uint_format(isup_tree, hf_isup_pointer_to_start_of_optional_part, message_tvb, offset,
                                 PARAMETER_POINTER_LENGTH, opt_parameter_pointer,
                                 "Pointer to start of optional part: %u", opt_parameter_pointer);
      offset += opt_parameter_pointer;
      optional_parameter_tvb = tvb_new_subset_remaining(message_tvb, offset);
      dissect_ansi_isup_optional_parameter(optional_parameter_tvb, pinfo, isup_tree, itu_isup_variant);
    }
    else
      proto_tree_add_uint_format(isup_tree, hf_isup_pointer_to_start_of_optional_part, message_tvb, offset,
                                 PARAMETER_POINTER_LENGTH, opt_parameter_pointer,
                                 "No optional parameter present (Pointer: %u)", opt_parameter_pointer);
  }
  else if (message_type != MESSAGE_TYPE_CHARGE_INFO)
    expert_add_info(pinfo, type_item, &ei_isup_message_type_no_optional_parameters);

  /* if there are calling/called number, we'll get them for the tap */
  tap_rec->calling_number = tap_calling_number ? tap_calling_number : wmem_strdup(pinfo->pool, "");
  tap_rec->called_number  = tap_called_number;
  tap_rec->cause_value    = tap_cause_value;
  tap_queue_packet(isup_tap, pinfo, tap_rec);
}

static void
dissect_isup_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *isup_tree, guint8 itu_isup_variant, guint32 circuit_id)
{
  isup_tap_rec_t *tap_rec;

  tvbuff_t   *parameter_tvb;
  tvbuff_t   *optional_parameter_tvb;
  proto_tree *pass_along_tree;
  proto_item *type_item = NULL;
  gint        offset, bufferlength;
  guint8      message_type, opt_parameter_pointer;
  gint        opt_part_possible = FALSE; /* default setting - for message types allowing optional
                                             params explicitly set to TRUE in case statement */
  tap_calling_number            = NULL;
  offset                        = 0;

  /* Extract message type field */
  message_type = tvb_get_guint8(message_tvb, 0);

  switch (itu_isup_variant) {
    case ISUP_ITU_STANDARD_VARIANT:
      type_item = proto_tree_add_uint_format_value(isup_tree, hf_isup_message_type, message_tvb, 0, MESSAGE_TYPE_LENGTH, message_type,
                                 "%s (%u)",
                                 val_to_str_ext_const(message_type, &isup_message_type_value_ext, "reserved"),
                                 message_type);
      break;
    case ISUP_FRENCH_VARIANT:
      type_item = proto_tree_add_uint_format_value(isup_tree, hf_isup_message_type, message_tvb, 0, MESSAGE_TYPE_LENGTH, message_type,
                                 "%s (%u)",
                                 val_to_str_ext_const(message_type, &french_isup_message_type_value_ext, "reserved"),
                                 message_type);
      break;
    case ISUP_ISRAELI_VARIANT:
      type_item = proto_tree_add_uint_format_value(isup_tree, hf_isup_message_type, message_tvb, 0, MESSAGE_TYPE_LENGTH, message_type,
                                 "%s (%u)",
                                 val_to_str_ext_const(message_type, &israeli_isup_message_type_value_ext, "reserved"),
                                 message_type);
      break;
    case ISUP_RUSSIAN_VARIANT:
      type_item = proto_tree_add_uint_format_value(isup_tree, hf_isup_message_type, message_tvb, 0, MESSAGE_TYPE_LENGTH, message_type,
                                 "%s (%u)",
                                 val_to_str_ext_const(message_type, &russian_isup_message_type_value_ext, "reserved"),
                                 message_type);
      break;
  case ISUP_JAPAN_VARIANT:
  /* Fall through */
  case ISUP_JAPAN_TTC_VARIANT:
      type_item = proto_tree_add_uint_format_value(isup_tree, hf_isup_message_type, message_tvb, 0, MESSAGE_TYPE_LENGTH, message_type,
                                 "%s (%u)",
                                 val_to_str_ext_const(message_type, &japan_isup_message_type_value_ext, "reserved"),
                                 message_type);
      break;
  }

  offset +=  MESSAGE_TYPE_LENGTH;

  tap_rec = wmem_new(pinfo->pool, isup_tap_rec_t);
  tap_rec->message_type   = message_type;
  tap_rec->calling_number = NULL;
  tap_rec->called_number  = NULL;
  tap_rec->circuit_id     = circuit_id;

  parameter_tvb = tvb_new_subset_remaining(message_tvb, offset);

  /* distinguish between message types:*/
  switch (message_type) {
    case MESSAGE_TYPE_INITIAL_ADDR:
      offset += dissect_isup_initial_address_message(parameter_tvb, pinfo, isup_tree, itu_isup_variant);
      opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_SUBSEQ_ADDR:
      offset += dissect_isup_subsequent_address_message(parameter_tvb, pinfo, isup_tree);
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
      offset += dissect_isup_address_complete_message(parameter_tvb, pinfo, isup_tree);
      opt_part_possible = TRUE;
      break;
    case MESSAGE_TYPE_CONNECT:
      offset += dissect_isup_connect_message(parameter_tvb, pinfo, isup_tree);
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
      offset += dissect_isup_circuit_group_reset_query_message(parameter_tvb, pinfo, isup_tree);
      break;
    case MESSAGE_TYPE_CIRC_GRP_BLCK:
      offset += dissect_isup_circuit_group_blocking_messages(parameter_tvb, pinfo, isup_tree);
      break;
    case MESSAGE_TYPE_CIRC_GRP_UNBL:
      offset += dissect_isup_circuit_group_blocking_messages(parameter_tvb, pinfo, isup_tree);
      break;
    case MESSAGE_TYPE_CIRC_GRP_BL_ACK:
      offset += dissect_isup_circuit_group_blocking_messages(parameter_tvb, pinfo, isup_tree);
      break;
    case MESSAGE_TYPE_CIRC_GRP_UNBL_ACK:
      offset += dissect_isup_circuit_group_blocking_messages(parameter_tvb, pinfo, isup_tree);
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
      pass_along_tree = proto_tree_add_subtree_format(isup_tree, parameter_tvb, offset, -1,
                                            ett_isup_pass_along_message, NULL,
                                            "Pass-along: %s Message (%u)",
                                            val_to_str_ext_const(pa_message_type, &isup_message_type_value_acro_ext, "reserved"),
                                            pa_message_type);
      dissect_isup_message(parameter_tvb, pinfo, pass_along_tree, itu_isup_variant, circuit_id);
      break;
    }
    case MESSAGE_TYPE_CIRC_GRP_RST_ACK:
      offset += dissect_isup_circuit_group_reset_acknowledgement_message(parameter_tvb, pinfo, isup_tree);
      break;
    case MESSAGE_TYPE_CIRC_GRP_QRY:
      offset += dissect_isup_circuit_group_reset_query_message(parameter_tvb, pinfo, isup_tree);
      break;
    case MESSAGE_TYPE_CIRC_GRP_QRY_RSP:
      offset += dissect_isup_circuit_group_query_response_message(parameter_tvb, pinfo, isup_tree);
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
      bufferlength = tvb_reported_length_remaining(message_tvb, offset);
      if (bufferlength != 0) {
        switch (itu_isup_variant) {
          case ISUP_RUSSIAN_VARIANT:
            proto_tree_add_expert(isup_tree, pinfo, &ei_isup_format_national_matter, parameter_tvb, 0, bufferlength);
            break;
          default:
            proto_tree_add_expert(isup_tree, pinfo, &ei_isup_format_national_matter, parameter_tvb, 0, bufferlength);
            break;
        }
      }
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
      bufferlength = tvb_reported_length_remaining(message_tvb, offset);
      if (bufferlength != 0)
         proto_tree_add_expert(isup_tree, pinfo, &ei_isup_format_national_matter, parameter_tvb, 0, bufferlength);
      break;
    default:
      /* Handle national extensions here */
      switch (itu_isup_variant) {
        case ISUP_ITU_STANDARD_VARIANT:
          bufferlength = tvb_reported_length_remaining(message_tvb, offset);
          if (bufferlength != 0)
            expert_add_info(pinfo, type_item, &ei_isup_message_type_unknown);
          break;
        case ISUP_FRENCH_VARIANT:
          switch (message_type) {
            case FRENCH_CHARGING_PULSE:
              offset += dissect_french_isup_charging_pulse_message(parameter_tvb, isup_tree);
              opt_part_possible = TRUE;
              break;
            case FRENCH_CHARGING_ACK:
              opt_part_possible = TRUE;
              break;
            default:
              bufferlength = tvb_reported_length_remaining(message_tvb, offset);
              if (bufferlength != 0)
                expert_add_info(pinfo, type_item, &ei_isup_message_type_unknown);
              break;
          }
          break;
        case ISUP_ISRAELI_VARIANT:
          switch (message_type) {
            case ISRAELI_BACKWARD_CHARGING:
              offset += dissect_israeli_backward_charging_message(parameter_tvb, isup_tree);
              break;
            case ISRAELI_TRAFFIC_CHANGE:
              offset += dissect_israeli_traffic_change_message(parameter_tvb, isup_tree);
              break;
            case ISRAELI_CHARGE_ACK:
              /* No parameters */
              break;
            default:
              bufferlength = tvb_reported_length_remaining(message_tvb, offset);
              if (bufferlength != 0)
                expert_add_info(pinfo, type_item, &ei_isup_message_type_unknown);
              break;
          }
          break;
        case ISUP_RUSSIAN_VARIANT:
          switch (message_type) {
            case RUSSIAN_CLEAR_CALLING_LINE:
              /* no dissector necessary since no mandatory parameters included */
              break;
            case RUSSIAN_RINGING:
              /* no dissector necessary since no mandatory parameters included */
              opt_part_possible = TRUE;
              break;
            default:
              bufferlength = tvb_reported_length_remaining(message_tvb, offset);
              if (bufferlength != 0)
                expert_add_info(pinfo, type_item, &ei_isup_message_type_unknown);
              break;
          }
          break;
        case ISUP_JAPAN_VARIANT:
        /* Fall through */
        case ISUP_JAPAN_TTC_VARIANT:
          switch (message_type) {
            case MESSAGE_TYPE_JAPAN_CHARG_INF:
              offset += dissect_japan_chg_inf(parameter_tvb, pinfo, isup_tree);
              opt_part_possible = TRUE;
              break;
            default:
              bufferlength = tvb_reported_length_remaining(message_tvb, offset);
              if (bufferlength != 0)
                expert_add_info(pinfo, type_item, &ei_isup_message_type_unknown);
              break;
          }
          break;
      } /* switch (itu_isup_variant) */
      break;
  }

  /* extract pointer to start of optional part (if any) */
  if (opt_part_possible == TRUE) {
    opt_parameter_pointer = tvb_get_guint8(message_tvb, offset);
    if (opt_parameter_pointer > 0) {
      proto_tree_add_uint_format(isup_tree, hf_isup_pointer_to_start_of_optional_part, message_tvb, offset,
                                 PARAMETER_POINTER_LENGTH, opt_parameter_pointer,
                                 "Pointer to start of optional part: %u", opt_parameter_pointer);
      offset += opt_parameter_pointer;
      optional_parameter_tvb = tvb_new_subset_remaining(message_tvb, offset);
      dissect_isup_optional_parameter(optional_parameter_tvb, pinfo, isup_tree, itu_isup_variant);
    }
    else
      proto_tree_add_uint_format(isup_tree, hf_isup_pointer_to_start_of_optional_part, message_tvb, offset,
                                 PARAMETER_POINTER_LENGTH, opt_parameter_pointer,
                                 "No optional parameter present (Pointer: %u)", opt_parameter_pointer);
  }
  else if (message_type != MESSAGE_TYPE_CHARGE_INFO)
    expert_add_info(pinfo, type_item, &ei_isup_message_type_no_optional_parameters);

  /* if there are calling/called number, we'll get them for the tap */
  tap_rec->calling_number = tap_calling_number ? tap_calling_number : wmem_strdup(pinfo->pool, "");
  tap_rec->called_number  = tap_called_number;
  tap_rec->cause_value    = tap_cause_value;
  tap_queue_packet(isup_tap, pinfo, tap_rec);
}

/* ------------------------------------------------------------------ */
static int
dissect_isup(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{

/* Set up structures needed to add the protocol subtree and manage it */
  proto_item       *ti;
  proto_tree       *isup_tree = NULL;
  tvbuff_t         *message_tvb;
  guint16           cic;
  guint8            message_type;
  guint8            itu_isup_variant = g_isup_variant;
  value_string_ext *used_value_string_ext;

/* Make entries in Protocol column and Info column on summary display */
/* dissect CIC in main dissector since pass-along message type carrying complete IUSP message w/o CIC needs
 *    recursive message dissector call
 */
/* Extract message type field */
  message_type = tvb_get_guint8(tvb, CIC_OFFSET + CIC_LENGTH);

  switch (mtp3_standard) {
    case ANSI_STANDARD:
      isup_standard = ANSI_STANDARD;
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISUP(ANSI)");
      cic = tvb_get_letohs(tvb, CIC_OFFSET) & 0x3FFF; /*since upper 2 bits spare */
      if (isup_show_cic_in_info) {
        col_add_fstr(pinfo->cinfo, COL_INFO,
                     "%s (CIC %u) ",
                     val_to_str_ext_const(message_type, &ansi_isup_message_type_value_acro_ext, "reserved"),
                     cic);
      } else {
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s ",
                     val_to_str_ext_const(message_type, &ansi_isup_message_type_value_acro_ext, "reserved"));
      }
      if (tree) {
        ti = proto_tree_add_item(tree, proto_isup, tvb, 0, -1, ENC_NA);
        isup_tree = proto_item_add_subtree(ti, ett_isup);
        proto_tree_add_uint(isup_tree, hf_isup_cic, tvb, CIC_OFFSET, CIC_LENGTH, cic);
      }
      conversation_create_endpoint_by_id(pinfo, ENDPOINT_ISUP, cic);
      message_tvb = tvb_new_subset_remaining(tvb, CIC_LENGTH);
      dissect_ansi_isup_message(message_tvb, pinfo, isup_tree, ISUP_ITU_STANDARD_VARIANT, cic);
      break;
    default:
      isup_standard = ITU_STANDARD;
      /* ITU, China, and Japan; yes, J7's CICs are a different size */
      cic = tvb_get_letohs(tvb, CIC_OFFSET) & 0x0FFF; /*since upper 4 bits spare */
      switch (itu_isup_variant) {
        case ISUP_FRENCH_VARIANT:
          col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISUP(French)");
          used_value_string_ext = &french_isup_message_type_value_acro_ext;
          break;
        case ISUP_ISRAELI_VARIANT:
          col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISUP(Israeli)");
          used_value_string_ext = &israeli_isup_message_type_value_acro_ext;
          break;
        case ISUP_RUSSIAN_VARIANT:
          col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISUP(Russian)");
          used_value_string_ext = &russian_isup_message_type_value_acro_ext;
          break;
        case ISUP_JAPAN_VARIANT:
          col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISUP(Japan)");
          used_value_string_ext = &japan_isup_message_type_value_acro_ext;
          break;
        case ISUP_JAPAN_TTC_VARIANT:
          col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISUP(Japan TTC)");
          used_value_string_ext = &japan_isup_message_type_value_acro_ext;
          cic = tvb_get_letohs(tvb, CIC_OFFSET) & 0x1FFF; /*since upper 3 bits spare */
          break;
        default:
          col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISUP(ITU)");
          used_value_string_ext = &isup_message_type_value_acro_ext;
          break;
      }
      if (isup_show_cic_in_info) {
        col_add_fstr(pinfo->cinfo, COL_INFO,
                     "%s (CIC %u) ",
                     val_to_str_ext_const(message_type, used_value_string_ext, "reserved"),
                     cic);
      } else {
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s ",
                     val_to_str_ext_const(message_type, used_value_string_ext, "reserved"));
      }
      if (tree) {
        ti = proto_tree_add_item(tree, proto_isup, tvb, 0, -1, ENC_NA);
        isup_tree = proto_item_add_subtree(ti, ett_isup);
        proto_tree_add_uint(isup_tree, hf_isup_cic, tvb, CIC_OFFSET, CIC_LENGTH, cic);
      }
      conversation_create_endpoint_by_id(pinfo, ENDPOINT_ISUP, cic);
      message_tvb = tvb_new_subset_remaining(tvb, CIC_LENGTH);
      dissect_isup_message(message_tvb, pinfo, isup_tree, itu_isup_variant, cic);
  }
  return tvb_captured_length(tvb);
}

/* ------------------------------------------------------------------ */
static int
dissect_bicc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{

/* Set up structures needed to add the protocol subtree and manage it */
  proto_item       *ti;
  proto_tree       *bicc_tree = NULL;
  tvbuff_t         *message_tvb;
  guint32           bicc_cic;
  guint8            message_type;
  guint8            itu_isup_variant = g_isup_variant;
  value_string_ext *used_value_string_ext;

  /*circuit_t *circuit;*/

/* Make entries in Protocol column and Info column on summary display */
  switch (itu_isup_variant) {
    case ISUP_FRENCH_VARIANT:
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "BICC(French)");
      used_value_string_ext = &french_isup_message_type_value_acro_ext;
      break;
    case ISUP_ISRAELI_VARIANT:
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "BICC(Israeli)");
      used_value_string_ext = &israeli_isup_message_type_value_acro_ext;
      break;
    case ISUP_RUSSIAN_VARIANT:
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "BICC(Russian)");
      used_value_string_ext = &russian_isup_message_type_value_acro_ext;
      break;
    case ISUP_JAPAN_VARIANT:
    /* Fall through */
    case ISUP_JAPAN_TTC_VARIANT:
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "BICC(Japan)");
      used_value_string_ext = &japan_isup_message_type_value_acro_ext;
      break;
    default:
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "BICC(ITU)");
      used_value_string_ext = &isup_message_type_value_acro_ext;
      break;
  }

/* Extract message type field */
  message_type = tvb_get_guint8(tvb, BICC_CIC_OFFSET + BICC_CIC_LENGTH);

  bicc_cic = tvb_get_letohl(tvb, BICC_CIC_OFFSET);

  conversation_create_endpoint_by_id(pinfo, ENDPOINT_BICC, bicc_cic);

  col_clear(pinfo->cinfo, COL_INFO);
  if (isup_show_cic_in_info) {
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ",
                        "%s (CIC %u)",
                        val_to_str_ext_const(message_type, used_value_string_ext, "reserved"),
                        bicc_cic);
  } else {
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ",
                        val_to_str_ext_const(message_type, used_value_string_ext, "reserved"));
  }
  /* dissect CIC in main dissector since pass-along message type carrying complete BICC/ISUP message w/o CIC needs
   * recursive message dissector call
   */
  if (tree) {
    ti = proto_tree_add_item(tree, proto_bicc, tvb, 0, -1, ENC_NA);
    bicc_tree = proto_item_add_subtree(ti, ett_bicc);


    proto_tree_add_uint_format(bicc_tree, hf_bicc_cic, tvb, BICC_CIC_OFFSET, BICC_CIC_LENGTH,
                               bicc_cic, "CIC: %u", bicc_cic);
  }

  message_tvb = tvb_new_subset_remaining(tvb, BICC_CIC_LENGTH);
  dissect_isup_message(message_tvb, pinfo, bicc_tree, itu_isup_variant, bicc_cic);
  col_set_fence(pinfo->cinfo, COL_INFO);
  return tvb_captured_length(tvb);
}

static int
dissect_application_isup(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
/* Set up structures needed to add the protocol subtree and manage it */
  proto_item *ti;
  proto_tree *isup_tree = NULL;
  tvbuff_t   *message_tvb;
  guint8      message_type;
  char       *version, *base;
  guint8      itu_isup_variant = ISUP_ITU_STANDARD_VARIANT; /* Default */

  if (data) {
    http_message_info_t *message_info = (http_message_info_t *)data;
    if (message_info->media_str) {
      version = ws_find_media_type_parameter(pinfo->pool, message_info->media_str, "version");
      base = ws_find_media_type_parameter(pinfo->pool, message_info->media_str, "base");
      if ((version && g_ascii_strncasecmp(version, "ansi", 4) == 0) ||
          (base && g_ascii_strncasecmp(base, "ansi", 4) == 0) ||
          (version && g_ascii_strncasecmp(version, "gr", 2) == 0) ||
          (base && g_ascii_strncasecmp(base, "gr", 2) == 0)) {
        /*
         * "version" or "base" parameter begins with "ansi" or "gr", so it's
         * ANSI or Bellcore.
         */
        isup_standard = ANSI_STANDARD;
        col_append_str(pinfo->cinfo, COL_PROTOCOL, "/ISUP(ANSI)");
        message_type = tvb_get_guint8(tvb, 0);
        /* application/ISUP has no  CIC  */
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ",
                            "ISUP:%s",
                            val_to_str_ext_const(message_type, &ansi_isup_message_type_value_acro_ext, "reserved"));
        if (tree) {
          ti = proto_tree_add_item(tree, proto_isup, tvb, 0, -1, ENC_NA);
          isup_tree = proto_item_add_subtree(ti, ett_isup);
        }

        message_tvb = tvb_new_subset_remaining(tvb, 0);
        dissect_ansi_isup_message(message_tvb, pinfo, isup_tree, ISUP_ITU_STANDARD_VARIANT, 0);
        return tvb_reported_length(tvb);
      } else if ((version && g_ascii_strcasecmp(version, "spirou") == 0) ||
          (base && g_ascii_strcasecmp(base, "spirou") == 0)) {
        /*
         * "version" or "base" version is "spirou", so it's SPIROU.
         */
        isup_standard    = ITU_STANDARD;
        itu_isup_variant = ISUP_FRENCH_VARIANT;
      } else {
        isup_standard = ITU_STANDARD;
      }
    } else {
      /* default to ITU */
      isup_standard = ITU_STANDARD;
    }
  } else {
    /* default to ITU */
    isup_standard = ITU_STANDARD;
  }


  /* Extract message type field */
  message_type = tvb_get_guint8(tvb, 0);

  switch (itu_isup_variant) {
    case ISUP_ITU_STANDARD_VARIANT:
      /* Make entries in Protocol column and Info column on summary display */
      col_append_str(pinfo->cinfo, COL_PROTOCOL, "/ISUP(ITU)");

      /* application/ISUP has no  CIC  */
      col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ",
                          "ISUP:%s",
                          val_to_str_ext_const(message_type, &isup_message_type_value_acro_ext, "reserved"));
      break;
    case ISUP_FRENCH_VARIANT:
      /* Make entries in Protocol column and Info column on summary display */
      col_append_str(pinfo->cinfo, COL_PROTOCOL, "/ISUP(French)");

      /* application/ISUP has no  CIC  */
      col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ",
                          "ISUP:%s",
                          val_to_str_ext_const(message_type, &french_isup_message_type_value_acro_ext, "reserved"));
      break;
#if 0
      /* This case can't happen unless/until we can parse the Israeli variant
       * out of the content type
       */
    case ISUP_ISRAELI_VARIANT:
      /* Make entries in Protocol column and Info column on summary display */
      col_append_str(pinfo->cinfo, COL_PROTOCOL, "/ISUP(Israeli)");

      /* application/ISUP has no  CIC  */
      col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ",
                          "ISUP:%s",
                          val_to_str_ext_const(message_type, &israeli_isup_message_type_value_acro_ext, "reserved"));
      break;
#endif
    default:
      col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ",
                          "ISUP: Unknown variant %d", itu_isup_variant);
      break;
  }

  if (tree) {
    ti = proto_tree_add_item(tree, proto_isup, tvb, 0, -1, ENC_NA);
    isup_tree = proto_item_add_subtree(ti, ett_isup);
  }

  message_tvb = tvb_new_subset_remaining(tvb, 0);
  dissect_isup_message(message_tvb, pinfo, isup_tree, itu_isup_variant, 0);
  return tvb_reported_length(tvb);
}
/* ---------------------------------------------------- stats tree
*/
static int st_node_msg = -1;
static int st_node_dir = -1;

static void
msg_stats_tree_init(stats_tree *st)
{
  st_node_msg = stats_tree_create_node(st, "Messages by Type", 0, STAT_DT_INT, TRUE);
  st_node_dir = stats_tree_create_node(st, "Messages by Direction", 0, STAT_DT_INT, TRUE);
}

static tap_packet_status
msg_stats_tree_packet(stats_tree *st, packet_info *pinfo, epan_dissect_t *edt _U_, const void *p, tap_flags_t flags _U_)
{
  const gchar *msg = try_val_to_str_ext(((const isup_tap_rec_t*)p)->message_type, &isup_message_type_value_acro_ext);
  gchar       *src, *dst, *dir;
  int          msg_node;
  int          dir_node;

  src = address_to_str(NULL, &pinfo->src);
  dst = address_to_str(NULL, &pinfo->dst);
  dir = wmem_strdup_printf(NULL, "%s->%s", src, dst);
  wmem_free(NULL, src);
  wmem_free(NULL, dst);

  msg_node = tick_stat_node(st, msg, st_node_msg, TRUE);
  tick_stat_node(st, dir, msg_node, FALSE);

  dir_node = tick_stat_node(st, dir, st_node_dir, TRUE);
  tick_stat_node(st, msg, dir_node, FALSE);

  wmem_free(NULL, dir);

  return TAP_PACKET_REDRAW;
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
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_message_type,
      { "Message Type",  "isup.message_type",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_parameter_type,
      { "Parameter Type",  "isup.parameter_type",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_parameter_value,
      { "Parameter Value",  "isup.parameter_value",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_mand_parameter_type,
      { "Mandatory Parameter",  "isup.parameter_type",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &isup_parameter_type_value_ext, 0x0,
        NULL, HFILL }},

    { &hf_isup_opt_parameter_type,
      { "Optional Parameter",  "isup.parameter_type",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &ansi_isup_parameter_type_value_ext, 0x0,
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
        FT_BOOLEAN, 8, TFS(&isup_echo_control_device_ind_value), E_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_forw_call_natnl_inatnl_call_indicator,
      { "National/international call indicator",  "isup.forw_call_natnl_inatnl_call_indicator",
        FT_BOOLEAN, 16, TFS(&isup_natnl_inatnl_call_ind_value), A_16BIT_MASK,
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
      { "Query on Release attempt indicator",  "isup.forw_call_qor_attempt_indicator",
        FT_BOOLEAN, 16, TFS(&isup_ISDN_qor_attempt_ind_value), N_16BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_calling_partys_category,
      { "Calling Party's category",  "isup.calling_partys_category",
        FT_UINT8, BASE_HEX|BASE_EXT_STRING, &isup_calling_partys_category_value_ext, 0x0,
        NULL, HFILL }},

    { &hf_russian_isup_calling_partys_category,
      { "Calling Party's category",  "isup.russian.calling_partys_category",
        FT_UINT8, BASE_HEX, VALS(isup_calling_partys_category_value), 0x0,
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

    { &hf_isup_number_different_meaning,
      { "Different meaning for number",  "isup.number_different_meaning",
        FT_UINT8, BASE_HEX, NULL, 0,
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
        FT_UINT8, BASE_DEC | BASE_EXT_STRING, &isup_called_party_address_digit_value_ext, ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK,
        NULL, HFILL }},

    { &hf_isup_calling_party_odd_address_signal_digit,
      { "Address signal digit",  "isup.calling_party_odd_address_signal_digit",
        FT_UINT8, BASE_DEC | BASE_EXT_STRING, &isup_calling_party_address_digit_value_ext, ISUP_ODD_ADDRESS_SIGNAL_DIGIT_MASK,
        NULL, HFILL }},

    { &hf_isup_called_party_even_address_signal_digit,
      { "Address signal digit",  "isup.called_party_even_address_signal_digit",
        FT_UINT8, BASE_DEC | BASE_EXT_STRING, &isup_called_party_address_digit_value_ext, ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK,
        NULL, HFILL }},

    { &hf_isup_calling_party_even_address_signal_digit,
      { "Address signal digit",  "isup.calling_party_even_address_signal_digit",
        FT_UINT8, BASE_DEC | BASE_EXT_STRING, &isup_calling_party_address_digit_value_ext, ISUP_EVEN_ADDRESS_SIGNAL_DIGIT_MASK,
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
      { "Solicited indicator",  "isup.solicited_indicator",
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

    { &hf_isup_backw_call_iam_seg_ind,
      { "IAM segmentation indicator",  "isup.backw_call_iam_seg_ind",
        FT_BOOLEAN, 16, TFS(&ansi_isup_iam_seg_ind_value), J_16BIT_MASK,
        NULL, HFILL } },

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

    { &hf_isup_bitbucket,
      { "Bit",  "isup.bitbucket",
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
      { "Event presentation restricted indicator",  "isup.event_presentation_restr_ind",
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
        FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), H_8BIT_MASK,
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

    { &hf_isup_notification_indicator,
      { "Notification indicator",  "isup.notification_indicator",
        FT_UINT8, BASE_DEC | BASE_EXT_STRING, &q763_generic_notification_indicator_vals_ext, 0x7f,
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
        FT_BOOLEAN, 8, TFS(&isup_Send_notification_ind_value), C_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_Discard_message_ind_value,
      { "Discard message indicator", "isup.Discard_message_ind_value",
        FT_BOOLEAN, 8, TFS(&isup_Discard_message_ind_value), D_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_Discard_parameter_ind,
      { "Discard parameter indicator", "isup.Discard_parameter_ind",
        FT_BOOLEAN, 8, TFS(&isup_Discard_parameter_ind_value), E_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_Pass_on_not_possible_indicator,
      { "Pass on not possible indicator",  "isup.Pass_on_not_possible_ind",
        FT_UINT8, BASE_HEX, VALS(isup_Pass_on_not_possible_indicator_vals), GF_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_pass_on_not_possible_indicator2,
      { "Pass on not possible indicator",  "isup.Pass_on_not_possible_val",
        FT_BOOLEAN, 8, TFS(&isup_pass_on_not_possible_indicator_value), E_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_Broadband_narrowband_interworking_ind,
      { "Broadband narrowband interworking indicator Bits JF",  "isup.broadband_narrowband_interworking_ind",
        FT_UINT8, BASE_HEX, VALS(ISUP_Broadband_narrowband_interworking_indicator_vals), BA_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_Broadband_narrowband_interworking_ind2,
      { "Broadband narrowband interworking indicator Bits GF",  "isup.broadband_narrowband_interworking_ind2",
        FT_UINT8, BASE_HEX, VALS(ISUP_Broadband_narrowband_interworking_indicator_vals), GF_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_app_cont_ident,
      { "Application context identifier",  "isup.app_context_identifier",
        FT_UINT16, BASE_DEC, VALS(isup_application_transport_parameter_value), GFEDCBA_8BIT_MASK,
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
      { "Destination Address length",  "isup.dest_addr_len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_apm_slr,
      { "Segmentation local reference (SLR)",  "isup.APM_slr",
        FT_UINT8, BASE_DEC, NULL, GFEDCBA_8BIT_MASK,
        NULL, HFILL }},
    { &hf_isup_cause_location,
      { "Cause location", "isup.cause_location",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &q931_cause_location_vals_ext, 0x0f,
        NULL, HFILL }},

    { &hf_ansi_isup_coding_standard,
      { "Coding standard", "ansi_isup.coding_standard",
        FT_UINT8, BASE_HEX, VALS(ansi_isup_coding_standard_vals), 0x60,
        NULL, HFILL }},
    { &hf_ansi_isup_spare_b7,
      { "Spare", "ansi_isup.spare.b7",
      FT_UINT8, BASE_DEC, NULL, 0x80,
      NULL, HFILL }},
    { &hf_ansi_isup_type_of_nw_id,
      { "Type of network identification", "ansi_isup.type_of_nw_id",
        FT_UINT8, BASE_DEC, VALS(ansi_isup_type_of_nw_id_vals), 0x70,
        NULL, HFILL } },
    { &hf_ansi_isup_nw_id_plan,
      { "Network identification plan", "ansi_isup.nw_id_plan",
        FT_UINT8, BASE_DEC, VALS(ansi_isup_nw_id_plan_vals), 0x0f,
        NULL, HFILL } },
    { &hf_ansi_isup_tns_nw_id_plan,
      { "Network identification plan", "ansi_isup.tns.nw_id_plan",
        FT_UINT8, BASE_DEC, VALS(ansi_isup_tns_nw_id_plan_vals), 0x0f,
        NULL, HFILL } },
    { &hf_ansi_isup_nw_id,
      { "Network id",  "ansi_isup.nw_id",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL } },
    { &hf_ansi_isup_circuit_code,
      { "Circuit code", "ansi_isup.circuit_code",
        FT_UINT8, BASE_DEC, NULL, 0xf0,
        NULL, HFILL } },

      { &hf_bat_ase_identifier,
      { "BAT ASE Identifiers",  "bicc.bat_ase_identifier",
        FT_UINT8, BASE_HEX|BASE_EXT_STRING, &bat_ase_list_of_Identifiers_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_length_indicator,
      { "BAT ASE Element length indicator",  "bicc.bat_ase_length_indicator",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_Action_Indicator,
      { "BAT ASE action indicator field",  "bicc.bat_ase_bat_ase_action_indicator_field",
        FT_UINT8, BASE_HEX|BASE_EXT_STRING, &bat_ase_action_indicator_field_vals_ext, 0x00,
        NULL, HFILL }},

    { &hf_Instruction_ind_for_general_action,
      { "BAT ASE Instruction indicator for general action",  "bicc.bat_ase_Instruction_ind_for_general_action",
        FT_UINT8, BASE_HEX, VALS(Instruction_indicator_for_general_action_vals), 0x03,
        NULL, HFILL }},

    { &hf_Send_notification_ind_for_general_action,
      { "Send notification indicator for general action",  "bicc.bat_ase_Send_notification_ind_for_general_action",
        FT_BOOLEAN, 8, TFS(&isup_Send_notification_ind_value), 0x04,
        NULL, HFILL }},

    { &hf_Instruction_ind_for_pass_on_not_possible,
      { "Instruction ind for pass-on not possible",  "bicc.bat_ase_Instruction_ind_for_pass_on_not_possible",
        FT_UINT8, BASE_HEX, VALS(Instruction_indicator_for_pass_on_not_possible_vals), 0x30,
        NULL, HFILL }},

    { &hf_Send_notification_ind_for_pass_on_not_possible,
      { "Send notification indication for pass-on not possible",  "bicc.bat_ase_Send_notification_ind_for_pass_on_not_possible",
        FT_BOOLEAN, 8, TFS(&isup_Send_notification_ind_value), 0x40,
        NULL, HFILL }},

    { &hf_BCTP_Version_Indicator,
      { "BCTP Version Indicator",  "bicc.bat_ase_BCTP_Version_Indicator",
        FT_UINT8, BASE_DEC, NULL, 0x1f,
        NULL, HFILL }},

    { &hf_BVEI,
      { "BVEI",  "bicc.bat_ase_BCTP_BVEI",
        FT_BOOLEAN, 8, TFS(&BCTP_BVEI_value), 0x40,
        NULL, HFILL }},

    { &hf_Tunnelled_Protocol_Indicator,
      { "Tunnelled Protocol Indicator",  "bicc.bat_ase_BCTP_Tunnelled_Protocol_Indicator",
        FT_UINT8, BASE_DEC, VALS(BCTP_Tunnelled_Protocol_Indicator_vals), 0x3f,
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
      { "Interworking Function Address(X.213 NSAP encoded)", "bat_ase.biwfa",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_afi,
      { "X.213 Address Format Information (AFI)",  "x213.afi",
        FT_UINT8, BASE_HEX|BASE_EXT_STRING, &x213_afi_value_ext, 0x0,
        NULL, HFILL }},

    { &hf_bicc_nsap_dsp,
      { "X.213 Address Format Information (DSP)",  "x213.dsp",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_bicc_nsap_dsp_length,
      { "DSP Length",  "x213.dsp_length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_characteristics,
      { "Backbone network connection characteristics", "bat_ase.char",
        FT_UINT8, BASE_HEX|BASE_EXT_STRING, &bearer_network_connection_characteristics_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_Organization_Identifier,
      { "Organization identifier subfield",  "bat_ase.organization_identifier_subfield",
        FT_UINT8, BASE_DEC, VALS(bat_ase_organization_identifier_subfield_vals), 0x0,
        NULL, HFILL }},

    { &hf_codec_type,
      { "ITU-T codec type subfield",  "bat_ase.ITU_T_codec_type_subfield",
        FT_UINT8, BASE_HEX|BASE_EXT_STRING, &ITU_T_codec_type_subfield_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_etsi_codec_type,
      { "ETSI codec type subfield",  "bat_ase.ETSI_codec_type_subfield",
        FT_UINT8, BASE_HEX|BASE_EXT_STRING, &ETSI_codec_type_subfield_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_active_code_set,
      { "Active Code Set",  "bat_ase.acs",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_active_code_set_12_2,
      { "12.2 kbps rate",  "bat_ase.acs.12_2",
        FT_UINT8, BASE_HEX, NULL, 0x80,
        NULL, HFILL }},

    { &hf_active_code_set_10_2,
      { "10.2 kbps rate",  "bat_ase.acs.10_2",
        FT_UINT8, BASE_HEX, NULL, 0x40,
        NULL, HFILL }},

    { &hf_active_code_set_7_95,
      { "7.95 kbps rate",  "bat_ase.acs.7_95",
        FT_UINT8, BASE_HEX, NULL, 0x20,
        NULL, HFILL }},

    { &hf_active_code_set_7_40,
      { "7.40 kbps rate",  "bat_ase.acs.7_40",
        FT_UINT8, BASE_HEX, NULL, 0x10,
        NULL, HFILL }},

    { &hf_active_code_set_6_70,
      { "6.70 kbps rate",  "bat_ase.acs.6_70",
        FT_UINT8, BASE_HEX, NULL, 0x08,
        NULL, HFILL }},

    { &hf_active_code_set_5_90,
      { "5.90 kbps rate",  "bat_ase.acs.5_90",
        FT_UINT8, BASE_HEX, NULL, 0x04,
        NULL, HFILL }},

    { &hf_active_code_set_5_15,
      { "5.15 kbps rate",  "bat_ase.acs.5_15",
        FT_UINT8, BASE_HEX, NULL, 0x02,
        NULL, HFILL }},

    { &hf_active_code_set_4_75,
      { "4.75 kbps rate",  "bat_ase.acs.4_75",
        FT_UINT8, BASE_HEX, NULL, 0x01,
        NULL, HFILL }},

    { &hf_supported_code_set,
      { "Supported Code Set",  "bat_ase.scs",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_supported_code_set_12_2,
      { "12.2 kbps rate",  "bat_ase.scs.12_2",
        FT_UINT8, BASE_HEX, NULL, 0x80,
        NULL, HFILL }},

    { &hf_supported_code_set_10_2,
      { "10.2 kbps rate",  "bat_ase.scs.10_2",
        FT_UINT8, BASE_HEX, NULL, 0x40,
        NULL, HFILL }},

    { &hf_supported_code_set_7_95,
      { "7.95 kbps rate",  "bat_ase.scs.7_95",
        FT_UINT8, BASE_HEX, NULL, 0x20,
        NULL, HFILL }},

    { &hf_supported_code_set_7_40,
      { "7.40 kbps rate",  "bat_ase.scs.7_40",
        FT_UINT8, BASE_HEX, NULL, 0x10,
        NULL, HFILL }},

    { &hf_supported_code_set_6_70,
      { "6.70 kbps rate",  "bat_ase.scs.6_70",
        FT_UINT8, BASE_HEX, NULL, 0x08,
        NULL, HFILL }},

    { &hf_supported_code_set_5_90,
      { "5.90 kbps rate",  "bat_ase.scs.5_90",
        FT_UINT8, BASE_HEX, NULL, 0x04,
        NULL, HFILL }},

    { &hf_supported_code_set_5_15,
      { "5.15 kbps rate",  "bat_ase.scs.5_15",
        FT_UINT8, BASE_HEX, NULL, 0x02,
        NULL, HFILL }},

    { &hf_supported_code_set_4_75,
      { "4.75 kbps rate",  "bat_ase.scs.4_75",
        FT_UINT8, BASE_HEX, NULL, 0x01,
        NULL, HFILL }},

    { &hf_optimisation_mode,
      { "Optimisation Mode for ACS , OM",  "bat_ase.optimisation_mode",
        FT_UINT8, BASE_HEX, VALS(optimisation_mode_vals), 0x8,
        NULL, HFILL }},

    { &hf_max_codec_modes,
      { "Maximal number of Codec Modes, MACS",  "bat_ase.macs",
        FT_UINT8, BASE_DEC, NULL, 0x07,
        NULL, HFILL }},


    { &hf_bearer_control_tunneling,
      { "Bearer control tunneling",  "bat_ase.bearer_control_tunneling",
        FT_BOOLEAN, 8, TFS(&Bearer_Control_Tunnelling_ind_value), 0x01,
        NULL, HFILL }},

    { &hf_BAT_ASE_Comp_Report_Reason,
      { "Compatibility report reason",  "bat_ase.Comp_Report_Reason",
        FT_UINT8, BASE_HEX, VALS(BAT_ASE_Report_Reason_vals), 0x0,
        NULL, HFILL }},


    { &hf_BAT_ASE_Comp_Report_ident,
      { "Compatibility report ident",  "bat_ase.Comp_Report_ident",
        FT_UINT8, BASE_HEX|BASE_EXT_STRING, &bat_ase_list_of_Identifiers_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_BAT_ASE_Comp_Report_diagnostic,
      { "Diagnostics",  "bat_ase.Comp_Report_diagnostic",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_Local_BCU_ID,
      { "Local BCU ID",  "bat_ase.Local_BCU_ID",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_late_cut_through_cap_ind,
      { "Late Cut-through capability indicator",  "bat_ase.late_cut_through_cap_ind",
        FT_BOOLEAN, 8, TFS(&late_cut_through_cap_ind_value), 0x01,
        NULL, HFILL }},

    { &hf_bat_ase_signal,
      { "Q.765.5 - Signal Type",  "bat_ase.signal_type",
        FT_UINT8, BASE_HEX|BASE_EXT_STRING, &BAT_ASE_Signal_Type_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_bat_ase_duration,
      { "Duration in ms",  "bat_ase.duration",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_bat_ase_default,
      { "Default",  "bat_ase.default",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_bat_ase_bearer_redir_ind,
      { "Redirection Indicator",  "bat_ase.bearer_redir_ind",
        FT_UINT8, BASE_HEX|BASE_EXT_STRING, &Bearer_Redirection_Indicator_vals_ext, 0x0,
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
        FT_UINT16, BASE_HEX, VALS(iana_icp_values), 0x0,
        NULL, HFILL }},

    { &hf_isup_called,
      { "Called Party Number",  "isup.called",
        FT_STRING, ENC_ASCII, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_calling,
      { "Calling Party Number",  "isup.calling",
        FT_STRING, ENC_ASCII, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_redirecting,
      { "Redirecting Number",  "isup.redirecting",
        FT_STRING, ENC_ASCII, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_redirection_number,
      { "Redirection Number",  "isup.redirection_number",
        FT_STRING, ENC_ASCII, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_subsequent_number,
      { "Subsequent Number",  "isup.subsequent_number",
        FT_STRING, ENC_ASCII, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_connected_number,
      { "Connected Number",  "isup.connected_number",
        FT_STRING, ENC_ASCII, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_transit_network_selection,
      { "Transit Network Selection",  "isup.transit_network_selection",
        FT_STRING, ENC_ASCII, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_original_called_number,
      { "Original Called Number",  "isup.original_called_number",
        FT_STRING, ENC_ASCII, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_location_number,
      { "Location Number",  "isup.location_number",
        FT_STRING, ENC_ASCII, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_call_transfer_number,
      { "Call Transfer Number",  "isup.call_transfer_number",
        FT_STRING, ENC_ASCII, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_called_in_number,
      { "Called IN Number",  "isup.called_in_number",
        FT_STRING, ENC_ASCII, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_generic_number,
      { "Generic Number",  "isup.generic_number",
        FT_STRING, ENC_ASCII, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_jurisdiction,
      { "Jurisdiction",  "isup.jurisdiction",
        FT_STRING, ENC_ASCII, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_charge_number,
      { "Charge Number",  "isup.charge_number",
        FT_STRING, ENC_ASCII, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_apm_msg_fragments,
     { "Message fragments", "isup.apm.msg.fragments",
      FT_NONE, BASE_NONE, NULL, 0x00,
      NULL, HFILL }},

    { &hf_isup_apm_msg_fragment,
      { "Message fragment", "isup.apm.msg.fragment",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},

    { &hf_isup_apm_msg_fragment_overlap,
      { "Message fragment overlap", "isup.apm.msg.fragment.overlap",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_apm_msg_fragment_overlap_conflicts,
      { "Message fragment overlapping with conflicting data", "isup.apm.msg.fragment.overlap.conflicts",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_apm_msg_fragment_multiple_tails,
      { "Message has multiple tail fragments", "isup.apm.msg.fragment.multiple_tails",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_apm_msg_fragment_too_long_fragment,
      { "Message fragment too long", "isup.apm.msg.fragment.too_long_fragment",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_apm_msg_fragment_error,
      { "Message defragmentation error", "isup.apm.msg.fragment.error",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},

    { &hf_isup_apm_msg_fragment_count,
      { "Message fragment count", "isup.apm.msg.fragment.count",
        FT_UINT32, BASE_DEC, NULL, 0x00,
        NULL, HFILL }},

    { &hf_isup_apm_msg_reassembled_in,
      { "Reassembled in", "isup.apm.msg.reassembled.in",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},

    { &hf_isup_apm_msg_reassembled_length,
      { "Reassembled ISUP length", "isup.apm.msg.reassembled.length",
        FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},

    { &hf_isup_cvr_rsp_ind,
      { "CVR Response Ind", "isup.conn_rsp_ind",
        FT_UINT8, BASE_DEC, VALS(isup_cvr_rsp_ind_value), BA_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_cvr_cg_car_ind,
      { "CVR Circuit Group Carrier", "isup.cg_carrier_ind",
        FT_UINT8, BASE_HEX, VALS(isup_cvr_cg_car_ind_value), BA_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_cvr_cg_double_seize,
      { "Double Seize Control", "isup.cg_char_ind.doubleSeize",
        FT_UINT8, BASE_HEX, VALS(isup_cvr_cg_double_seize_value), DC_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_cvr_cg_alarm_car_ind,
      { "Alarm Carrier Indicator", "isup.cg_alarm_car_ind",
        FT_UINT8, BASE_HEX, VALS(isup_cvr_alarm_car_ind_value), FE_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_cvr_cont_chk_ind,
      { "Continuity Check Indicator", "isup.cg_alarm_cnt_chk",
        FT_UINT8, BASE_HEX, VALS(isup_cvr_cont_chk_ind_value), HG_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_geo_loc_presentation_restricted_ind,
      { "Calling Geodetic Location presentation restricted indicator",  "isup.location_presentation_restr_ind",
        FT_UINT8, BASE_DEC, VALS(isup_location_presentation_restricted_ind_value), DC_8BIT_MASK,
        NULL, HFILL }},

    { &hf_isup_geo_loc_screening_ind,
      { "Calling Geodetic Location screening indicator",  "isup.location_screening_ind",
        FT_UINT8, BASE_DEC, VALS(isup_screening_ind_enhanced_value), BA_8BIT_MASK,        /* using previously defined screening values */
        NULL, HFILL }},

    /* French ISUP parameters */
    { &hf_isup_french_coll_field,
      { "Collection field",  "isup.french.coll_field",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_french_msg_num,
      { "Message number",  "isup.french.msg_num",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    /* Israeli ISUP parameters */
    { &hf_isup_israeli_charging_message_indicators_current,
      { "Current Tariff",  "isup.israeli.cmi_current",
        FT_UINT8, BASE_DEC, VALS(israeli_cmi_current_rate), 0x03,
        NULL, HFILL }},

    { &hf_isup_israeli_charging_message_indicators_next,
      { "Next Tariff",  "isup.israeli.cmi_next",
        FT_UINT8, BASE_DEC, VALS(israeli_cmi_next_rate), 0x0C,
        NULL, HFILL }},

    { &hf_isup_israeli_current_rate,
      { "Current Rate",  "isup.israeli.current_rate",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_israeli_time_indicator,
      { "Time Indicator",  "isup.israeli.time_indicator",
        FT_UINT8, BASE_DEC | BASE_EXT_STRING, &israeli_time_indicators_ext, 0x0,
        NULL, HFILL }},

    { &hf_isup_israeli_next_rate,
      { "Next Rate",  "isup.israeli.next_ratej",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    /* Japan ISUP */
    { &hf_japan_isup_redirect_capability,
      { "Redirect possible indicator",  "isup.jpn.redirect_capability",
        FT_UINT8, BASE_DEC, VALS(isup_jpn_redirect_capabilit_vals), 0x07,
        NULL, HFILL }},

    { &hf_japan_isup_redirect_counter,
      { "Redirect counter",  "isup.jpn.redirect_counter",
        FT_UINT8, BASE_DEC, NULL, 0x0f,
        NULL, HFILL }},

    { &hf_japan_isup_rfi_info_type,
      { "Information Type Tag",  "isup.rfi.info_type",
        FT_UINT8, BASE_DEC, VALS(isup_rfi_info_type_values), 0x0,
        NULL, HFILL }},

    { &hf_japan_isup_rfi_info_len,
      { "Length",  "isup.rfi.info_len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_japan_isup_perf_redir_reason,
      { "Performing redirect reason",  "isup.rfi.perf_redir_reason",
        FT_UINT8, BASE_DEC, VALS(perf_redir_reason_vals), 0x7f,
        NULL, HFILL }},

    { &hf_japan_isup_redir_pos_ind,
      { "Redirect possible indicator at performing exchange",  "isup.rfi.redir_pos_ind",
        FT_UINT8, BASE_DEC, VALS(redir_pos_ind_vals), 0x07,
        NULL, HFILL }},

    { &hf_japan_isup_emerg_call_type,
      { "Emergency Call Type",  "isup.jpn.emerg_call_type",
        FT_UINT8, BASE_DEC, VALS(japan_isup_emerg_call_type_vals), 0x03,
        NULL, HFILL }},

    { &hf_japan_isup_hold_at_emerg_call_disc_ind,
      { "Hold at emergency Call Disconnection Indicators",  "isup.jpn.hold_at_emerg_call_disc_ind",
        FT_UINT16, BASE_DEC, VALS(hold_at_emerg_call_disc_ind_vals), 0x0300,
        NULL, HFILL }},

    /* Value string values the same as perf_redir_reason_vals */
    { &hf_japan_isup_inv_redir_reason,
      { "Invoking redirect reason",  "isup.rfi.inv_redir_reason",
        FT_UINT8, BASE_DEC, VALS(perf_redir_reason_vals), 0x7f,
        NULL, HFILL }},

    { &hf_japan_isup_bwd_info_type,
      { "Information Type Tag",  "isup.jpn.bwd_info_type",
        FT_UINT8, BASE_DEC, VALS(japan_isup_bwd_info_type_vals), 0x0,
        NULL, HFILL }},

    { &hf_japan_isup_tag_len,
      { "Length",  "isup.jpn.tag_len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_japan_isup_add_user_cat_type,
      { "Type of Additional User/Service Information",  "isup.jpn.add_user_cat_type",
        FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(jpn_isup_add_user_cat_type_vals), 0x0,
        NULL, HFILL }},

    { &hf_japan_isup_type_1_add_fixed_serv_inf,
      { "Type 1 of additional fixed service information",  "isup.jpn.type_1_add_fixed_serv_inf",
        FT_UINT8, BASE_DEC, VALS(jpn_isup_type_1_add_fixed_serv_inf_vals), 0x0,
        NULL, HFILL }},

    { &hf_japan_isup_type_1_add_mobile_serv_inf,
      { "Type 1 of additional mobile service information",  "isup.jpn.type_1_add_mobile_serv_inf",
        FT_UINT8, BASE_DEC, VALS(jpn_isup_type_1_add_mobile_serv_inf_vals), 0x0,
        NULL, HFILL }},

    { &hf_japan_isup_type_2_add_mobile_serv_inf,
      { "Type 2 of additional mobile service information (Communication Method)",  "isup.jpn.type_2_add_mobile_serv_inf",
        FT_UINT8, BASE_DEC | BASE_EXT_STRING, &jpn_isup_type_2_add_mobile_serv_inf_vals_ext, 0x0,
        NULL, HFILL }},

    { &hf_japan_isup_type_3_add_mobile_serv_inf,
      { "Type 3 of additional mobile service information (Charging Method)",  "isup.jpn.type_3_add_mobile_serv_inf",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_japan_isup_reason_for_clip_fail,
      { "Reason for CLIP failure",  "isup.jpn.reason_for_clip_fail",
        FT_UINT8, BASE_DEC, VALS(jpn_isup_reason_for_clip_fail_vals), 0x0,
        NULL, HFILL }},

    { &hf_japan_isup_contractor_number,
      { "Contractor Number",  "isup.jpn.contractor_number",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    /* CHARGE AREA INFORMATION */
    { &hf_japan_isup_charge_area_nat_of_info_value,
      { "Nature of Information indicator",  "isup.charg_area_info.oddeven_indic",
        FT_UINT8, BASE_DEC, VALS(isup_charge_area_info_nat_of_info_value), 0x7F,
        NULL, HFILL }},

    { &hf_japan_isup_charging_info_nc_odd_digits,
      { "NC",  "isup.charg_area_info.nc_odd_digit",
        FT_UINT8, BASE_DEC, VALS(isup_carrier_info_digits_value), 0x0F,
        NULL, HFILL }},

    { &hf_japan_isup_charging_info_nc_even_digits,
      { "NC", "isup.charg_area_info.nc_even_digit",
        FT_UINT8, BASE_DEC, VALS(isup_carrier_info_digits_value), 0xF0,
        NULL, HFILL }},

    { &hf_isup_charging_info_maca_odd_digits,
      { "MA/CA", "isup.charg_area_info.maca_odd_digit",
        FT_UINT8, BASE_DEC, VALS(isup_carrier_info_digits_value), 0x0F,
        NULL, HFILL }},

    { &hf_isup_charging_info_maca_even_digits,
      { "MA/CA", "isup.charg_area_info.maca_even_digit",
        FT_UINT8, BASE_DEC, VALS(isup_carrier_info_digits_value), 0xF0,
        NULL, HFILL }},

    /* CARRIER INFORMATION */
    { &hf_isup_carrier_info_iec,
      { "IEC Indicator", "isup.carrier_info.iec",
        FT_UINT8, BASE_DEC, VALS(isup_carrier_info_iec_indic_value), 0x00,
        NULL, HFILL }},

#if 0 /* TODO: tools/checkhf.pl reported these as unused */
    { &hf_isup_carrier_info_cat_of_carrier,
      { "Category of Carrier", "isup.carrier_info.cat_of_carrier",
        FT_UINT8, BASE_HEX, VALS(isup_carrier_info_category_value), 0x00,
        NULL, HFILL }},

    { &hf_isup_carrier_info_type_of_carrier_info,
      { "Type of Carrier", "isup.carrier_info.type_of_carrier",
        FT_UINT8, BASE_HEX, VALS(isup_carrier_info_type_of_carrier_value), 0x00,
        NULL, HFILL }},
#endif

    { &hf_japan_isup_carrier_info_length,
      { "Length of Carrier Information", "isup.jpn.carrier_info_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isup_carrier_info_odd_no_digits,
      { "CID", "isup.carrier_info.cid_odd_digit",
        FT_UINT8, BASE_DEC, VALS(isup_carrier_info_digits_value), 0x0F,
        NULL, HFILL }},

    { &hf_isup_carrier_info_even_no_digits,
      { "CID", "isup.carrier_info.cid_even_digit",
        FT_UINT8, BASE_DEC, VALS(isup_carrier_info_digits_value), 0xF0,
        NULL, HFILL }},

    { &hf_isup_carrier_info_ca_odd_no_digits,
      { "CA", "isup.carrier_info.ca_odd_digit",
      FT_UINT8, BASE_DEC, VALS(isup_carrier_info_digits_value), 0x0F,
      NULL, HFILL }},

    { &hf_isup_carrier_info_ca_even_no_digits,
      { "CA", "isup.carrier_info.ca_even_digit",
        FT_UINT8, BASE_DEC, VALS(isup_carrier_info_digits_value), 0xF0,
        NULL, HFILL }},

    { &hf_isup_carrier_info_poi_exit_HEI,
      { "Exit POI Hierarchy", "isup.carrier_info_exit_hierarchy",
        FT_UINT8, BASE_DEC, VALS(isup_carrier_info_poihie_value), 0x0F,
        NULL, HFILL }},

    { &hf_isup_carrier_info_poi_entry_HEI,
      { "Entry POI Hierarchy", "isup.carrier_info_entry_hierarchy",
        FT_UINT8, BASE_DEC, VALS(isup_carrier_info_poihie_value), 0xF0,
        NULL, HFILL }},

    { &hf_japan_isup_charge_delay_type,
      { "Type of delayed charging information", "isup.japan.charge_delay_type",
        FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(japan_isup_charge_delay_type_value), 0x0,
        NULL, HFILL }},

    { &hf_japan_isup_charge_info_type,
      { "Charge information type", "isup.japan.chg_inf_type",
        FT_UINT8, BASE_DEC, VALS(japan_isup_chg_info_type_value), 0x0,
        NULL, HFILL }},

    { &hf_japan_isup_sig_elem_type,
      { "Signal element type", "isup.japan.sig_elem_type",
        FT_UINT8, BASE_DEC, VALS(japan_isup_sig_elem_type_values), 0x7f,
        NULL, HFILL }},

    { &hf_japan_isup_activation_id,
      { "Activation id", "isup.japan.activation_id",
        FT_UINT8, BASE_DEC, NULL, 0x7F,
        NULL, HFILL }},

    { &hf_japan_isup_op_cls,
      { "Operation class", "isup.japan.op_cls",
        FT_UINT8, BASE_DEC, VALS(japan_isup_op_cls_values), 0x60,
        NULL, HFILL }},

    { &hf_japan_isup_op_type,
      { "Operation type", "isup.japan.op_type",
        FT_UINT8, BASE_DEC, VALS(japan_isup_op_type_values), 0x1f,
        NULL, HFILL }},

    { &hf_japan_isup_charging_party_type,
      { "Charging party type", "isup.japan.charging_party_type",
        FT_UINT8, BASE_DEC, VALS(japan_isup_charging_party_type_values), 0x70,
        NULL, HFILL }},

    { &hf_japan_isup_utp,
      { "Unit per Time Period (UTP)", "isup.japan.utp",
        FT_UINT8, BASE_DEC, VALS(japan_isup_utp_values), 0x0,
        NULL, HFILL }},

    { &hf_japan_isup_crci1,
      { "Charge rate information category 1 (CRIC 1)", "isup.japan.crci1",
        FT_UINT8, BASE_DEC, VALS(japan_isup_crci1_values), 0x7f,
        NULL, HFILL }},

    { &hf_japan_isup_crci2,
      { "Charge rate information category 2 (CRIC 2)", "isup.japan.crci2",
        FT_UINT8, BASE_DEC, VALS(japan_isup_crci1_values), 0x7f,
        NULL, HFILL }},

    { &hf_japan_isup_crci1_len,
      { "Length",  "isup.japan.crci1_len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_japan_isup_iu,
      { "Initial units (IU)",  "isup.japan.iu",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_japan_isup_dcr,
      { "Daytime Charge rate (DCR)",  "isup.japan.dcr",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_japan_isup_ecr,
      { "Evening Charge rate (ECR)",  "isup.japan.ecr",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_japan_isup_ncr,
      { "Nighttime Charge rate (NCR)",  "isup.japan.ncr",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_japan_isup_scr,
      { "Spare charge rate (SCR)",  "isup.japan.scr",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_japan_isup_collecting_method,
      { "Charging party type", "isup.japan.collecting_method",
        FT_UINT8, BASE_DEC, VALS(japan_isup_collecting_method_values), 0x0f,
        NULL, HFILL }},

    { &hf_japan_isup_tariff_rate_pres,
      { "Tariff rate presentation", "isup.japan.tariff_rate_pres",
        FT_UINT8, BASE_DEC, VALS(japan_isup_tariff_rate_pres_values), 0x7f,
        NULL, HFILL }},

      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_isup_cause_indicators, { "Cause indicators (-> Q.850)", "isup.cause_indicators", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_diagnostic, { "Diagnostic", "isup.diagnostic", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_user_to_user_info, { "User-to-user info (-> Q.931)", "isup.user_to_user_info", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_call_identity, { "Call identity", "isup.call_identity", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_signalling_point_code, { "Signalling Point Code", "isup.signalling_point_code", FT_UINT16, BASE_DEC, NULL, 0x3FFF, NULL, HFILL }},
      { &hf_isup_access_transport_parameter_field, { "Access transport parameter field (-> Q.931)", "isup.access_transport_parameter_field", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_idp, { "IDP", "isup.idp", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_dsp, { "DSP", "isup.dsp", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_idi, { "IDI", "isup.idi", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_configuration_data, { "Configuration data", "isup.configuration_data", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_unknown_organisation_identifier, { "Unknown organisation Identifier (Non ITU-T/ETSI codec)", "isup.unknown_organisation_identifier", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_tunnelled_protocol_data, { "Tunnelled Protocol Data", "isup.tunnelled_protocol_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_network_id_length_indicator, { "Network ID Length indicator", "isup.network_id_length_indicator", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_network_id, { "Network ID", "isup.network_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_app_transport_param_field8, { "Application transport parameter fields", "isup.app_transport_param_field", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_app_transport_param_field16, { "Application transport parameter fields", "isup.app_transport_param_field", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_app_transport_instruction_indicator, { "Application transport instruction indicators", "isup.app_transport_instruction_indicator", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_apm_seg_indicator, { "APM segmentation indicator", "isup.apm_seg_indicator", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_address_digits, { "Address digits", "isup.address_digits", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_apm_user_info_field, { "APM-user information field", "isup.apm_user_info_field", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_local_reference, { "Local Reference", "isup.local_reference", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_protocol_class, { "Protocol Class", "isup.protocol_class", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_credit, { "Credit", "isup.credit", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_network_identity, { "Network Identity", "isup.network_identity", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_binary_code, { "Binary Code", "isup.binary_code", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_user_service_information, { "User service information (-> Q.931 Bearer_capability)", "isup.user_service_information", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_circuit_assignment_map, { "Circuit assignment map (bit position indicates usage of corresponding circuit->3.69/Q.763)", "isup.circuit_assignment_map", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_origination_isc_point_code, { "Origination ISC Point Code", "isup.origination_isc_point_code", FT_UINT16, BASE_DEC, NULL, 0x3FFF, NULL, HFILL }},
      { &hf_isup_call_history_info, { "Call history info", "isup.call_history_info", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_network_specific_facility, { "Network specific facility (refer to 3.36/Q.763 for detailed decoding)", "isup.network_specific_facility", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_user_service_information_prime, { "User service information prime (-> Q.931 Bearer capability information IE)", "isup.user_service_information_prime", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_propagation_delay_counter, { "Propagation delay counter", "isup.propagation_delay_counter", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL }},
      { &hf_isup_remote_operations, { "Remote operations", "isup.remote_operations", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_feature_code, { "Feature Code", "isup.feature_code", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_user_teleservice_information, { "User teleservice information (-> Q.931 High Layer Compatibility IE)", "isup.user_teleservice_information", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_call_diversion_information, { "Call diversion information", "isup.call_diversion_information", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_echo_control_information, { "Echo control information", "isup.echo_control_information", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_message_compatibility_information, { "Message compatibility information", "isup.message_compatibility_information", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_upgraded_parameter, { "Upgraded parameter", "isup.upgraded_parameter", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &isup_parameter_type_value_ext, 0x0, NULL, HFILL }},
      { &hf_isup_instruction_indicators, { "Instruction indicators", "isup.instruction_indicators", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_look_forward_busy, { "Look forward busy", "isup.look_forward_busy", FT_UINT8, BASE_DEC, VALS(isup_mlpp_precedence_look_forward_busy_vals), 0x60, NULL, HFILL }},
      { &hf_isup_precedence_level, { "Precedence Level", "isup.precedence_level", FT_UINT8, BASE_DEC, VALS(isup_mlpp_precedence_level_vals), 0x0F, NULL, HFILL }},
      { &hf_isup_mlpp_service_domain, { "MLPP service domain", "isup.mlpp_service_domain", FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_mcid_request_indicators, { "MCID request indicators", "isup.mcid_request_indicators", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_mcid_response_indicators, { "MCID response indicators", "isup.mcid_response_indicators", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_hop_counter, { "Hop counter", "isup.hop_counter", FT_UINT8, BASE_DEC, NULL, EDCBA_8BIT_MASK, NULL, HFILL }},
      { &hf_isup_originating_line_info, { "Originating line info", "isup.originating_line_info", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_presentation_indicator, { "Presentation indicator", "isup.presentation_indicator", FT_UINT8, BASE_DEC, VALS(isup_redirection_presentation_indicator_vals), BA_8BIT_MASK, NULL, HFILL }},
      { &hf_isup_call_transfer_identity, { "Call transfer identity", "isup.call_transfer_identity", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_loop_prevention_indicator_type, { "Type", "isup.loop_prevention_indicator_type", FT_BOOLEAN, 8, TFS(&tfs_response_request), A_8BIT_MASK, NULL, HFILL }},
      { &hf_isup_ccss_call_indicator, { "CCSS call indicator", "isup.ccss_call_indicator", FT_BOOLEAN, 8, TFS(&tfs_ccss_call_no_indication), A_8BIT_MASK, NULL, HFILL }},
      { &hf_isup_forward_gvns, { "Forward GVNS (refer to 3.66/Q.763 for detailed decoding)", "isup.forward_gvns", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_redirect_capability, { "Redirect capability", "isup.redirect_capability", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_backward_gvns, { "Backward GVNS", "isup.backward_gvns", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_correlation_id, { "Correlation ID (-> Q.1281)", "isup.correlation_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_scf_id, { "SCF ID (-> Q.1281)", "isup.scf_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_charged_party_identification, { "Charged party identification (format is national network specific)", "isup.charged_party_identification", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_display_information, { "Display information (-> Q.931)", "isup.display_information", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_uid_action_indicators, { "UID action indicators", "isup.uid_action_indicators", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_uid_capability_indicators, { "UID capability indicators", "isup.uid_capability_indicators", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_redirect_counter, { "Redirect counter", "isup.redirect_counter", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_collect_call_request_indicator, { "Collect call request indicator", "isup.collect_call_request_indicator", FT_BOOLEAN, 8, TFS(&tfs_collect_call_req_no_indication), A_8BIT_MASK, NULL, HFILL }},
      { &hf_isup_geo_loc_shape, { "Calling geodetic location type of shape", "isup.geo_loc_shape", FT_UINT8, BASE_DEC, VALS(isup_location_type_of_shape_value), GFEDCBA_8BIT_MASK, NULL, HFILL }},
      { &hf_isup_geo_loc_shape_description, { "Shape description", "isup.shape_description", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_isup_number_qualifier_indicator, { "Number qualifier indicator", "isup.number_qualifier_indicator", FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(number_qualifier_indicator_vals), 0x0, NULL, HFILL }},
      { &hf_isup_generic_digits, { "Generic digits (refer to 3.24/Q.673 for detailed decoding)", "isup.generic_digits", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_isup,
    &ett_isup_parameter,
    &ett_isup_address_digits,
    &ett_isup_carrier_info,
    &ett_isup_pass_along_message,
    &ett_isup_circuit_state_ind,
    &ett_bat_ase,
    &ett_bat_ase_element,
    &ett_bat_ase_iwfa,
    &ett_scs,
    &ett_acs,
    &ett_isup_apm_msg_fragment,
    &ett_isup_apm_msg_fragments,
    &ett_isup_range,
    &ett_app_transport_fields,
    &ett_app_transport,
    &ett_apm_seg_indicator,
    &ett_echo_control_information,
    &ett_instruction_indicators,
    &ett_message_compatibility_information,
  };

  static ei_register_info ei[] = {
    { &ei_isup_format_national_matter, { "isup.format_national_matter", PI_PROTOCOL, PI_NOTE, "Format is a national matter", EXPFILL }},
    { &ei_isup_message_type_unknown, { "isup.message_type.unknown", PI_PROTOCOL, PI_WARN, "Unknown Message type (possibly reserved/used in former ISUP version)", EXPFILL }},
    { &ei_isup_not_dissected_yet, { "isup.not_dissected_yet", PI_UNDECODED, PI_WARN, "Not dissected yet", EXPFILL }},
    { &ei_isup_status_subfield_not_present, { "isup.status_subfield_not_present", PI_PROTOCOL, PI_NOTE, "Status subfield is not present with this message type", EXPFILL }},
    { &ei_isup_message_type_no_optional_parameters, { "isup.message_type.no_optional_parameters", PI_PROTOCOL, PI_NOTE, "No optional parameters are possible with this message type", EXPFILL }},
    { &ei_isup_empty_number, { "isup.empty_number", PI_PROTOCOL, PI_NOTE, "(empty) number", EXPFILL }},
    { &ei_isup_too_many_digits, { "isup.too_many_digits", PI_MALFORMED, PI_ERROR, "Too many digits", EXPFILL }},
    { &ei_isup_opt_par_length_err, { "isup.opt_par_length_err", PI_MALFORMED, PI_ERROR, "Optional parameter length is wrong", EXPFILL }}
  };

  static const enum_val_t isup_variants[] = {
    {"ITU Standard",              "ITU Standard",              ISUP_ITU_STANDARD_VARIANT},
    {"French National Standard",  "French National Standard",  ISUP_FRENCH_VARIANT},
    {"Israeli National Standard", "Israeli National Standard", ISUP_ISRAELI_VARIANT},
    {"Russian National Standard", "Russian National Standard", ISUP_RUSSIAN_VARIANT},
    {"Japan National Standard",   "Japan National Standard",   ISUP_JAPAN_VARIANT},
    {"Japan National Standard (TTC)",   "Japan National Standard (TTC)",   ISUP_JAPAN_TTC_VARIANT},
    {NULL, NULL, -1}
  };

  module_t *isup_module;
  expert_module_t* expert_isup;

/* Register the protocol name and description */
  proto_isup = proto_register_protocol("ISDN User Part",
                                       "ISUP", "isup");

  isup_handle = register_dissector("isup", dissect_isup, proto_isup);

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_isup, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_isup = expert_register_protocol(proto_isup);
  expert_register_field_array(expert_isup, ei, array_length(ei));

  isup_tap = register_tap("isup");

  isup_module = prefs_register_protocol(proto_isup, NULL);

  prefs_register_enum_preference(isup_module, "variant",
                    "Select Standard or national ISUP variant",
                    "Note national variants may not be fully supported",
                    &g_isup_variant, isup_variants, FALSE);


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
  dissector_handle_t application_isup_handle;

  application_isup_handle = create_dissector_handle(dissect_application_isup, proto_isup);
  dissector_add_uint("mtp3.service_indicator", MTP_SI_ISUP, isup_handle);
  dissector_add_string("media_type", "application/isup", application_isup_handle);
  dissector_add_string("tali.opcode", "isot", isup_handle);

}

void
proto_register_bicc(void)
{
/* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    { &hf_bicc_cic,
      { "Call identification Code (CIC)",           "bicc.cic",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_bicc_continuity_check_indicator,
      { "Continuity Indicator",  "bicc.continuity_check_indicator",
        FT_UINT8, BASE_HEX, VALS(bicc_continuity_check_ind_value), DC_8BIT_MASK,
        NULL, HFILL }},
    { &hf_bicc_forw_call_end_to_end_method_indicator,
      { "End-to-end method indicator",  "bicc.forw_call_end_to_end_method_indicator",
        FT_UINT16, BASE_HEX, VALS(bicc_end_to_end_method_ind_value), CB_16BIT_MASK,
        NULL, HFILL }},
    { &hf_bicc_backw_call_end_to_end_method_ind,
      { "End-to-end method indicator",  "bicc.backw_call_end_to_end_method_indicator",
        FT_UINT16, BASE_HEX, VALS(bicc_end_to_end_method_ind_value), HG_16BIT_MASK,
        NULL, HFILL }},
    { &hf_bicc_backw_call_end_to_end_info_ind,
      { "End-to-end information indicator",  "bicc.backw_call_end_to_end_information_indicator",
        FT_BOOLEAN, 16, TFS(&bicc_end_to_end_info_ind_value), J_16BIT_MASK,
        NULL, HFILL }},
    { &hf_bicc_backw_call_isdn_user_part_ind,
      { "BICC indicator",  "bicc.backw_call_isdn_user_part_indicator",
        FT_BOOLEAN, 16, TFS(&bicc_ISDN_user_part_ind_value), K_16BIT_MASK,
        NULL, HFILL }},
    { &hf_bicc_backw_call_sccp_method_ind,
      { "SCCP method indicator",  "bicc.backw_call_sccp_method_indicator",
        FT_UINT16, BASE_HEX, VALS(bicc_SCCP_method_ind_value), PO_16BIT_MASK,
        NULL, HFILL }},
    { &hf_bicc_forw_call_end_to_end_info_indicator,
      { "End-to-end information indicator",  "bicc.forw_call_end_to_end_information_indicator",
        FT_BOOLEAN, 16, TFS(&bicc_end_to_end_info_ind_value), E_16BIT_MASK,
        NULL, HFILL }},
    { &hf_bicc_forw_call_isdn_user_part_indicator,
      { "BICC indicator",  "bicc.forw_call_isdn_user_part_indicator",
        FT_BOOLEAN, 16, TFS(&bicc_ISDN_user_part_ind_value), F_16BIT_MASK,
        NULL, HFILL }},
    { &hf_bicc_forw_call_preferences_indicator,
      { "BICC preference indicator",  "bicc.forw_call_preferences_indicator",
        FT_UINT16, BASE_HEX, VALS(bicc_preferences_ind_value), HG_16BIT_MASK,
        NULL, HFILL }},
    { &hf_bicc_forw_call_sccp_method_indicator,
      { "SCCP method indicator",  "bicc.forw_call_sccp_method_indicator",
        FT_UINT16, BASE_HEX, VALS(bicc_SCCP_method_ind_value), KJ_16BIT_MASK,
        NULL, HFILL }},
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_bicc
  };

  proto_bicc = proto_register_protocol("Bearer Independent Call Control",
                                       "BICC", "bicc");

  bicc_handle = register_dissector("bicc", dissect_bicc, proto_bicc);

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_bicc, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  reassembly_table_register(&isup_apm_msg_reassembly_table,
                         &addresses_reassembly_table_functions);

}

/* Register isup with the sub-laying MTP L3 dissector */
void
proto_reg_handoff_bicc(void)
{
  sdp_handle     = find_dissector_add_dependency("sdp", proto_isup);
  q931_ie_handle = find_dissector_add_dependency("q931.ie", proto_isup);

  dissector_add_uint("mtp3.service_indicator", MTP_SI_BICC, bicc_handle);
  dissector_add_uint("sctp.ppi", BICC_PAYLOAD_PROTOCOL_ID, bicc_handle);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
