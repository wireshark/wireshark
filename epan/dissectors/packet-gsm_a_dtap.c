/* packet-gsm_a_dtap.c
 * Routines for GSM A Interface DTAP dissection - A.K.A. GSM layer 3
 * NOTE: it actually includes RR messages, which are (generally) not carried
 * over the A interface on DTAP, but are part of the same Layer 3 protocol set
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 *
 * Added the GPRS Mobility Managment Protocol and
 * the GPRS Session Managment Protocol
 *   Copyright 2004, Rene Pilz <rene.pilz [AT] ftw.com>
 *   In association with Telecommunications Research Center
 *   Vienna (ftw.)Betriebs-GmbH within the Project Metawin.
 *
 * Added Dissection of Radio Resource Management Information Elements
 * and other enhancements and fixes.
 * Copyright 2005 - 2009, Anders Broman [AT] ericsson.com
 * Small bugfixes, mainly in Qos and TFT by Nils Ljungberg and Stefan Boman [AT] ericsson.com
 *
 * Various updates, enhancements and fixes
 * Copyright 2009, Gerasimos Dimitriadis <dimeg [AT] intracom.gr>
 * In association with Intracom Telecom SA
 *
 * Added Dissection of Group Call Control (GCC) protocol.
 * Added Dissection of Broadcast Call Control (BCC) protocol.
 * Copyright 2015, Michail Koreshkov <michail.koreshkov [at] zte.com.cn
 *
 * Title        3GPP            Other
 *
 *   Reference [3]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 4.7.0 Release 4)
 *   (ETSI TS 124 008 V6.8.0 (2005-03))
 *
 *   Reference [4]
 *   Mobile radio interface layer 3 specification;
 *   Radio Resource Control Protocol
 *   (GSM 04.18 version 8.4.1 Release 1999)
 *   (3GPP TS 04.18 version 8.26.0 Release 1999)
 *
 *   Reference [5]
 *   Point-to-Point (PP) Short Message Service (SMS)
 *   support on mobile radio interface
 *   (3GPP TS 24.011 version 4.1.1 Release 4)
 *
 *   Reference [6]
 *   Mobile radio Layer 3 supplementary service specification;
 *   Formats and coding
 *   (3GPP TS 24.080 version 4.3.0 Release 4)
 *
 *   Reference [7]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 5.9.0 Release 5)
 *
 *   Reference [8]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 6.7.0 Release 6)
 *   (3GPP TS 24.008 version 6.8.0 Release 6)
 *
 *   Reference [9]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 9.6.0 Release 9)
 *
 *   Reference [10]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 10.6.1 Release 10)
 *
 *   Reference [11]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 11.6.0 Release 11)
 *
 *   Reference [12]
 *   Digital cellular telecommunications system (Phase 2+);
 *   Group Call Control (GCC) protocol
 *   (GSM 04.68 version 8.1.0 Release 1999)
 *
 *   Reference [13]
 *   Digital cellular telecommunications system (Phase 2+);
 *   Broadcast Call Control (BCC) protocol
 *   (3GPP TS 44.069 version 11.0.0 Release 11)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/tap.h>
#include <epan/strutil.h>

#include "packet-bssap.h"
#include "packet-ber.h"
#include "packet-q931.h"
#include "packet-gsm_a_common.h"
#include "packet-ppp.h"
#include "packet-isup.h"

void proto_register_gsm_a_dtap(void);
void proto_reg_handoff_gsm_a_dtap(void);

/* PROTOTYPES/FORWARDS */

const value_string gsm_a_dtap_msg_gcc_strings[] = {
    { 0x31, "Immediate Setup" },
    { 0x32, "Setup" },
    { 0x33, "Connect" },
    { 0x34, "Termination" },
    { 0x35, "Termination Request" },
    { 0x36, "Termination Reject" },
    { 0x38, "Status" },
    { 0x39, "Get Status" },
    { 0x3A, "Set Parameter" },
    { 0, NULL }
};

const value_string gsm_a_dtap_msg_bcc_strings[] = {
    { 0x31, "Immediate Setup" },
    { 0x32, "Setup" },
    { 0x33, "Connect" },
    { 0x34, "Termination" },
    { 0x35, "Termination Request" },
    { 0x36, "Termination Reject" },
    { 0x38, "Status" },
    { 0x39, "Get Status" },
    { 0x3A, "Set Parameter" },
    { 0x3B, "Immediate Setup 2" },
    { 0, NULL }
};

const value_string gsm_a_dtap_msg_mm_strings[] = {
    { 0x01, "IMSI Detach Indication" },
    { 0x02, "Location Updating Accept" },
    { 0x04, "Location Updating Reject" },
    { 0x08, "Location Updating Request" },
    { 0x11, "Authentication Reject" },
    { 0x12, "Authentication Request" },
    { 0x14, "Authentication Response" },
    { 0x1c, "Authentication Failure" },
    { 0x18, "Identity Request" },
    { 0x19, "Identity Response" },
    { 0x1a, "TMSI Reallocation Command" },
    { 0x1b, "TMSI Reallocation Complete" },
    { 0x21, "CM Service Accept" },
    { 0x22, "CM Service Reject" },
    { 0x23, "CM Service Abort" },
    { 0x24, "CM Service Request" },
    { 0x25, "CM Service Prompt" },
    { 0x26, "Reserved: was allocated in earlier phases of the protocol" },
    { 0x28, "CM Re-establishment Request" },
    { 0x29, "Abort" },
    { 0x30, "MM Null" },
    { 0x31, "MM Status" },
    { 0x32, "MM Information" },
    { 0, NULL }
};

const value_string gsm_a_dtap_msg_cc_strings[] = {
    { 0x01, "Alerting" },
    { 0x08, "Call Confirmed" },
    { 0x02, "Call Proceeding" },
    { 0x07, "Connect" },
    { 0x0f, "Connect Acknowledge" },
    { 0x0e, "Emergency Setup" },
    { 0x03, "Progress" },
    { 0x04, "CC-Establishment" },
    { 0x06, "CC-Establishment Confirmed" },
    { 0x0b, "Recall" },
    { 0x09, "Start CC" },
    { 0x05, "Setup" },
    { 0x17, "Modify" },
    { 0x1f, "Modify Complete" },
    { 0x13, "Modify Reject" },
    { 0x10, "User Information" },
    { 0x18, "Hold" },
    { 0x19, "Hold Acknowledge" },
    { 0x1a, "Hold Reject" },
    { 0x1c, "Retrieve" },
    { 0x1d, "Retrieve Acknowledge" },
    { 0x1e, "Retrieve Reject" },
    { 0x25, "Disconnect" },
    { 0x2d, "Release" },
    { 0x2a, "Release Complete" },
    { 0x39, "Congestion Control" },
    { 0x3e, "Notify" },
    { 0x3d, "Status" },
    { 0x34, "Status Enquiry" },
    { 0x35, "Start DTMF" },
    { 0x31, "Stop DTMF" },
    { 0x32, "Stop DTMF Acknowledge" },
    { 0x36, "Start DTMF Acknowledge" },
    { 0x37, "Start DTMF Reject" },
    { 0x3a, "Facility" },
    { 0, NULL }
};

const value_string gsm_a_dtap_msg_sms_strings[] = {
    { 0x01, "CP-DATA" },
    { 0x04, "CP-ACK" },
    { 0x10, "CP-ERROR" },
    { 0, NULL }
};

const value_string gsm_a_dtap_msg_ss_strings[] = {
    { 0x2a, "Release Complete" },
    { 0x3a, "Facility" },
    { 0x3b, "Register" },
    { 0, NULL }
};

const value_string gsm_a_dtap_msg_tp_strings[] = {
    { 0x00, "Close TCH Loop Cmd" },
    { 0x01, "Close TCH Loop Ack" },
    { 0x06, "Open Loop Cmd" },
    { 0x0c, "Act EMMI Cmd" },
    { 0x0d, "Act EMMI Ack" },
    { 0x10, "Deact EMMI" },
    { 0x14, "Test Interface" },
    { 0x20, "Close Multi-slot Loop Cmd" },
    { 0x21, "Close Multi-slot Loop Ack" },
    { 0x22, "Open Multi-slot Loop Cmd" },
    { 0x23, "Open Multi-slot Loop Ack" },
    { 0x24, "GPRS Test Mode Cmd" },
    { 0x25, "EGPRS Start Radio Block Loopback Cmd" },
    { 0x26, "Reset MS Positioning Stored Information" },
    { 0x40, "Close UE Test Loop" },
    { 0x41, "Close UE Test Loop Complete" },
    { 0x42, "Open UE Test Loop" },
    { 0x43, "Open UE Test Loop Complete" },
    { 0x44, "Activate RB Test Mode" },
    { 0x45, "Activate RB Test Mode Complete" },
    { 0x46, "Deactivate RB Test Mode" },
    { 0x47, "Deactivate RB Test Mode Complete" },
    { 0x48, "Reset UE Positioning Stored Information" },
    { 0x49, "UE Test Loop Mode 3 RLC SDU Counter Request" },
    { 0x4A, "UE Test Loop Mode 3 RLC SDU Counter Response" },
    { 0x80, "Close UE Test Loop" },
    { 0x81, "Close UE Test Loop Complete" },
    { 0x82, "Open UE Test Loop" },
    { 0x83, "Open UE Test Loop Complete" },
    { 0x84, "Activate Test Mode" },
    { 0x85, "Activate Test Mode Complete" },
    { 0x86, "Deactivate Test Mode" },
    { 0x87, "Deactivate Test Mode Complete" },
    { 0x88, "Reset UE Positioning Stored Information" },
    { 0x89, "UE Test Loop Mode C MBMS Packet Counter Request" },
    { 0x8a, "UE Test Loop Mode C MBMS Packet Counter Response" },
    { 0x8b, "Update UE Location Information" },
    { 0, NULL }
};

static const value_string gsm_dtap_elem_strings[] = {
    /* Mobility Management Information Elements 10.5.3 */
    { DE_AUTH_PARAM_RAND,                  "Authentication Parameter RAND" },
    { DE_AUTH_PARAM_AUTN,                  "Authentication Parameter AUTN (UMTS and EPS authentication challenge)" },
    { DE_AUTH_RESP_PARAM,                  "Authentication Response Parameter" },
    { DE_AUTH_RESP_PARAM_EXT,              "Authentication Response Parameter (extension) (UMTS authentication challenge only)" },
    { DE_AUTH_FAIL_PARAM,                  "Authentication Failure Parameter (UMTS and EPS authentication challenge)" },
    { DE_CM_SRVC_TYPE,                     "CM Service Type" },
    { DE_ID_TYPE,                          "Identity Type" },
    { DE_LOC_UPD_TYPE,                     "Location Updating Type" },
    { DE_NETWORK_NAME,                     "Network Name" },
    { DE_REJ_CAUSE,                        "Reject Cause" },
    { DE_FOP,                              "Follow-on Proceed" },
    { DE_TIME_ZONE,                        "Time Zone" },
    { DE_TIME_ZONE_TIME,                   "Time Zone and Time" },
    { DE_CTS_PERM,                         "CTS Permission" },
    { DE_LSA_ID,                           "LSA Identifier" },
    { DE_DAY_SAVING_TIME,                  "Daylight Saving Time" },
    { DE_EMERGENCY_NUM_LIST,               "Emergency Number List" },
    { DE_ADD_UPD_PARAMS,                   "Additional update parameters" },
    { DE_MM_TIMER,                         "MM Timer" },
    /* Call Control Information Elements 10.5.4 */
    { DE_AUX_STATES,                       "Auxiliary States" },                /* 10.5.4.4 Auxiliary states */
    { DE_BEARER_CAP,                       "Bearer Capability" },               /* 10.5.4.4a Backup bearer capability */
    { DE_CC_CAP,                           "Call Control Capabilities" },
    { DE_CALL_STATE,                       "Call State" },
    { DE_CLD_PARTY_BCD_NUM,                "Called Party BCD Number" },
    { DE_CLD_PARTY_SUB_ADDR,               "Called Party Subaddress" },
    { DE_CLG_PARTY_BCD_NUM,                "Calling Party BCD Number" },
    { DE_CLG_PARTY_SUB_ADDR,               "Calling Party Subaddress" },
    { DE_CAUSE,                            "Cause" },
    { DE_CLIR_SUP,                         "CLIR Suppression" },
    { DE_CLIR_INV,                         "CLIR Invocation" },
    { DE_CONGESTION,                       "Congestion Level" },
    { DE_CONN_NUM,                         "Connected Number" },
    { DE_CONN_SUB_ADDR,                    "Connected Subaddress" },
    { DE_FACILITY,                         "Facility" },
    { DE_HLC,                              "High Layer Compatibility" },
    { DE_KEYPAD_FACILITY,                  "Keypad Facility" },
    { DE_LLC,                              "Low Layer Compatibility" },
    { DE_MORE_DATA,                        "More Data" },
    { DE_NOT_IND,                          "Notification Indicator" },
    { DE_PROG_IND,                         "Progress Indicator" },
    { DE_RECALL_TYPE,                      "Recall type $(CCBS)$" },
    { DE_RED_PARTY_BCD_NUM,                "Redirecting Party BCD Number" },
    { DE_RED_PARTY_SUB_ADDR,               "Redirecting Party Subaddress" },
    { DE_REPEAT_IND,                       "Repeat Indicator" },
    { DE_REV_CALL_SETUP_DIR,               "Reverse Call Setup Direction" },
    { DE_SETUP_CONTAINER,                  "SETUP Container $(CCBS)$" },
    { DE_SIGNAL,                           "Signal" },
    { DE_SS_VER_IND,                       "SS Version Indicator" },
    { DE_USER_USER,                        "User-user" },
    { DE_ALERT_PATTERN,                    "Alerting Pattern $(NIA)$" },        /* 10.5.4.26 Alerting Pattern $(NIA)$ */
    { DE_ALLOWED_ACTIONS,                  "Allowed Actions $(CCBS)$" },
    { DE_SI,                               "Stream Identifier" },
    { DE_NET_CC_CAP,                       "Network Call Control Capabilities" },
    { DE_CAUSE_NO_CLI,                     "Cause of No CLI" },                 /* 10.5.4.30 Cause of No CLI */
    /* 10.5.4.31 Void */
    { DE_SUP_CODEC_LIST,                   "Supported Codec List" },            /* 10.5.4.32 Supported codec list */
    { DE_SERV_CAT,                         "Service Category" },                /* 10.5.4.33 Service category */
    { DE_REDIAL,                           "Redial" },                          /* 10.5.4.34 Redial */
    { DE_NET_INIT_SERV_UPG,                "Network-initiated Service Upgrade indicator" },
    /* 10.5.4.35 Network-initiated Service Upgrade indicator */
    /* Short Message Service Information Elements [5] 8.1.4 */
    { DE_CP_USER_DATA,                     "CP-User Data" },
    { DE_CP_CAUSE,                         "CP-Cause" },
    /* Tests procedures information elements 3GPP TS 44.014 6.4.0, 3GPP TS 34.109 6.4.0 and 3GPP TS 36.509 9.1.0*/
    { DE_TP_SUB_CHANNEL,                   "Close TCH Loop Cmd Sub-channel"},
    { DE_TP_ACK,                           "Open Loop Cmd Ack"},
    { DE_TP_LOOP_TYPE,                     "Close Multi-slot Loop Cmd Loop type"},
    { DE_TP_LOOP_ACK,                      "Close Multi-slot Loop Ack Result"},
    { DE_TP_TESTED_DEVICE,                 "Test Interface Tested device"},
    { DE_TP_PDU_DESCRIPTION,               "GPRS Test Mode Cmd PDU description"},
    { DE_TP_MODE_FLAG,                     "GPRS Test Mode Cmd Mode flag"},
    { DE_TP_EGPRS_MODE_FLAG,               "EGPRS Start Radio Block Loopback Cmd Mode flag"},
    { DE_TP_MS_POSITIONING_TECHNOLOGY,     "MS Positioning Technology"},
    { DE_TP_UE_TEST_LOOP_MODE,             "Close UE Test Loop Mode"},
    { DE_TP_UE_POSITIONING_TECHNOLOGY,     "UE Positioning Technology"},
    { DE_TP_RLC_SDU_COUNTER_VALUE,         "RLC SDU Counter Value"},
    { DE_TP_EPC_UE_TEST_LOOP_MODE,         "UE Test Loop Mode"},
    { DE_TP_EPC_UE_TL_A_LB_SETUP,          "UE Test Loop Mode A LB Setup"},
    { DE_TP_EPC_UE_TL_B_LB_SETUP,          "UE Test Loop Mode B LB Setup"},
    { DE_TP_EPC_UE_TL_C_SETUP,             "UE Test Loop Mode C Setup"},
    { DE_TP_EPC_UE_POSITIONING_TECHNOLOGY, "UE Positioning Technology"},
    { DE_TP_EPC_MBMS_PACKET_COUNTER_VALUE, "MBMS Packet Counter Value"},
    { DE_TP_EPC_ELLIPSOID_POINT_WITH_ALT,  "Ellipsoid Point With Altitude"},
    { DE_TP_EPC_HORIZONTAL_VELOCITY,       "Horizontal Velocity"},
    { DE_TP_EPC_GNSS_TOD_MSEC,             "GNSS-TOD-msec"},
    /* Group Call Control Service Information Elements ETSI TS 100 948 V8.1.0 (GSM 04.68 version 8.1.0 Release 1999) */
    { DE_GCC_CALL_REF,                     "Call Reference"},
    { DE_GCC_CALL_STATE,                   "Call state"},
    { DE_GCC_CAUSE,                        "Cause"},
    { DE_GCC_ORIG_IND,                     "Originator indication"},
    { DE_GCC_STATE_ATTR,                   "State attributes"},
    /* Broadcast Call Control Information Elements ETSI TS 144 069 V10.0.0 (3GPP TS 44.069 version 10.0.0 Release 10) */
    {DE_BCC_CALL_REF,                      "Call Reference"},
    {DE_BCC_CALL_STATE,                    "Call state"},
    {DE_BCC_CAUSE,                         "Cause"},
    {DE_BCC_ORIG_IND,                      "Originator indication"},
    {DE_BCC_STATE_ATTR,                    "State attributes"},
    {DE_BCC_COMPR_OTDI,                    "Compressed otdi"},
    { 0, NULL }
};
value_string_ext gsm_dtap_elem_strings_ext = VALUE_STRING_EXT_INIT(gsm_dtap_elem_strings);

const gchar *gsm_a_pd_str[] = {
    "Group Call Control",
    "Broadcast Call Control",
    "EPS session management messages",
    "Call Control; call related SS messages",
    "GPRS Transparent Transport Protocol (GTTP)",
    "Mobility Management messages",
    "Radio Resources Management messages",
    "EPS mobility management messages",
    "GPRS Mobility Management messages",
    "SMS messages",
    "GPRS Session Management messages",
    "Non call related SS messages",
    "Location services specified in 3GPP TS 44.071",
    "Unknown",
    "Reserved for extension of the PD to one octet length",
    "Special conformance testing functions"
};
/* L3 Protocol discriminator values according to TS 24 007 (6.4.0)  */
const value_string protocol_discriminator_vals[] = {
    {0x0,       "Group call control"},
    {0x1,       "Broadcast call control"},
    {0x2,       "EPS session management messages"},
    {0x3,       "Call Control; call related SS messages"},
    {0x4,       "GPRS Transparent Transport Protocol (GTTP)"},
    {0x5,       "Mobility Management messages"},
    {0x6,       "Radio Resources Management messages"},
    {0x7,       "EPS mobility management messages"},
    {0x8,       "GPRS mobility management messages"},
    {0x9,       "SMS messages"},
    {0xa,       "GPRS session management messages"},
    {0xb,       "Non call related SS messages"},
    {0xc,       "Location services specified in 3GPP TS 44.071"},
    {0xd,       "Unknown"},
    {0xe,       "Reserved for extension of the PD to one octet length "},
    {0xf,       "Tests procedures described in 3GPP TS 44.014, 3GPP TS 34.109 and 3GPP TS 36.509"},
    { 0,    NULL }
};

const value_string gsm_a_pd_short_str_vals[] = {
    {0x0,       "GCC"},     /* Group Call Control */
    {0x1,       "BCC"},     /* Broadcast Call Control */
    {0x2,       "Reserved"},    /* : was allocated in earlier phases of the protocol */
    {0x3,       "CC"},      /* Call Control; call related SS messages */
    {0x4,       "GTTP"},    /* GPRS Transparent Transport Protocol (GTTP) */
    {0x5,       "MM"},      /* Mobility Management messages */
    {0x6,       "RR"},      /* Radio Resources Management messages */
    {0x7,       "Unknown"},
    {0x8,       "GMM"},     /* GPRS Mobility Management messages */
    {0x9,       "SMS"},
    {0xa,       "SM"},      /* GPRS Session Management messages */
    {0xb,       "SS"},
    {0xc,       "LS"},      /* Location Services */
    {0xd,       "Unknown"},
    {0xe,       "Reserved"},    /*  for extension of the PD to one octet length  */
    {0xf,       "TP"},      /*  for tests procedures described in 3GPP TS 44.014 6.4.0 and 3GPP TS 34.109 6.4.0.*/
    { 0,    NULL }
};

static const true_false_string tfs_acceptable_not_acceptable = { "Acceptable", "Not Acceptable" };


#define DTAP_PD_MASK        0x0f
#define DTAP_SKIP_MASK      0xf0
#define DTAP_TI_MASK        DTAP_SKIP_MASK
#define DTAP_TIE_PRES_MASK  0x07            /* after TI shifted to right */
#define DTAP_TIE_MASK       0x7f

#define DTAP_MM_IEI_MASK    0x3f
#define DTAP_GCC_IEI_MASK   0x3f
#define DTAP_BCC_IEI_MASK   0x3f
#define DTAP_CC_IEI_MASK    0x3f
#define DTAP_SMS_IEI_MASK   0xff
#define DTAP_SS_IEI_MASK    0x3f
#define DTAP_TP_IEI_MASK    0xff

/* Initialize the protocol and registered fields */
static int proto_a_dtap = -1;

static int hf_gsm_a_dtap_msg_gcc_type = -1;
static int hf_gsm_a_dtap_msg_bcc_type = -1;
static int hf_gsm_a_dtap_msg_mm_type = -1;
static int hf_gsm_a_dtap_msg_cc_type = -1;
static int hf_gsm_a_seq_no = -1;
static int hf_gsm_a_dtap_msg_sms_type = -1;
static int hf_gsm_a_dtap_msg_ss_type = -1;
static int hf_gsm_a_dtap_msg_tp_type = -1;
int hf_gsm_a_dtap_elem_id = -1;
static int hf_gsm_a_dtap_cld_party_bcd_num = -1;
static int hf_gsm_a_dtap_clg_party_bcd_num = -1;
static int hf_gsm_a_dtap_conn_num   = -1;
static int hf_gsm_a_dtap_red_party_bcd_num = -1;
static int hf_gsm_a_dtap_present_ind = -1;
static int hf_gsm_a_dtap_screening_ind = -1;
static int hf_gsm_a_dtap_type_of_sub_addr   = -1;
static int hf_gsm_a_dtap_odd_even_ind   = -1;

static int hf_gsm_a_dtap_cause = -1;
static int hf_gsm_a_dtap_cause_ss_diagnostics   = -1;
static int hf_gsm_a_dtap_emergency_bcd_num  = -1;
static int hf_gsm_a_dtap_emerg_num_info_length = -1;

static int hf_gsm_a_dtap_type_of_number = -1;
static int hf_gsm_a_dtap_numbering_plan_id = -1;

static int hf_gsm_a_dtap_lsa_id = -1;
static int hf_gsm_a_dtap_speech_vers_ind = -1;
static int hf_gsm_a_dtap_itc = -1;
static int hf_gsm_a_dtap_sysid = -1;
static int hf_gsm_a_dtap_bitmap_length = -1;
static int hf_gsm_a_dtap_serv_cat_b7 = -1;
static int hf_gsm_a_dtap_serv_cat_b6 = -1;
static int hf_gsm_a_dtap_serv_cat_b5 = -1;
static int hf_gsm_a_dtap_serv_cat_b4 = -1;
static int hf_gsm_a_dtap_serv_cat_b3 = -1;
static int hf_gsm_a_dtap_serv_cat_b2 = -1;
static int hf_gsm_a_dtap_serv_cat_b1 = -1;
static int hf_gsm_a_dtap_csmo = -1;
static int hf_gsm_a_dtap_csmt = -1;
static int hf_gsm_a_dtap_mm_timer_unit = -1;
static int hf_gsm_a_dtap_mm_timer_value = -1;
static int hf_gsm_a_dtap_alerting_pattern = -1;
static int hf_gsm_a_dtap_ccbs_activation = -1;
static int hf_gsm_a_dtap_stream_identifier = -1;
static int hf_gsm_a_dtap_mcs = -1;
static int hf_gsm_a_dtap_cause_of_no_cli = -1;
static int hf_gsm_a_dtap_signal_value = -1;

static int hf_gsm_a_dtap_codec_tdma_efr = -1;
static int hf_gsm_a_dtap_codec_umts_amr_2 = -1;
static int hf_gsm_a_dtap_codec_umts_amr = -1;
static int hf_gsm_a_dtap_codec_hr_amr = -1;
static int hf_gsm_a_dtap_codec_fr_amr = -1;
static int hf_gsm_a_dtap_codec_gsm_efr = -1;
static int hf_gsm_a_dtap_codec_gsm_hr = -1;
static int hf_gsm_a_dtap_codec_gsm_fr = -1;
static int hf_gsm_a_dtap_codec_ohr_amr_wb = -1;
static int hf_gsm_a_dtap_codec_ofr_amr_wb = -1;
static int hf_gsm_a_dtap_codec_ohr_amr = -1;
static int hf_gsm_a_dtap_codec_umts_amr_wb = -1;
static int hf_gsm_a_dtap_codec_fr_amr_wb = -1;
static int hf_gsm_a_dtap_codec_pdc_efr = -1;

static int hf_gsm_a_dtap_notification_description = -1;
static int hf_gsm_a_dtap_recall_type    = -1;
static int hf_gsm_a_dtap_coding_standard    = -1;
static int hf_gsm_a_dtap_call_state = -1;
static int hf_gsm_a_dtap_prog_coding_standard    = -1;
static int hf_gsm_a_dtap_location   = -1;
static int hf_gsm_a_dtap_progress_description   = -1;
static int hf_gsm_a_dtap_afi    = -1;
static int hf_gsm_a_dtap_rej_cause  = -1;
static int hf_gsm_a_dtap_timezone  = -1;
static int hf_gsm_a_dtap_u2u_prot_discr = -1;
static int hf_gsm_a_dtap_mcat   = -1;
static int hf_gsm_a_dtap_enicm  = -1;
static int hf_gsm_a_dtap_rand   = -1;
static int hf_gsm_a_dtap_autn   = -1;
static int hf_gsm_a_dtap_xres   = -1;
static int hf_gsm_a_dtap_sres   = -1;
static int hf_gsm_a_dtap_auts   = -1;
static int hf_gsm_a_dtap_autn_sqn_xor_ak = -1;
static int hf_gsm_a_dtap_autn_amf   = -1;
static int hf_gsm_a_dtap_autn_mac   = -1;
static int hf_gsm_a_dtap_auts_sqn_ms_xor_ak  = -1;
static int hf_gsm_a_dtap_auts_mac_s = -1;

static int hf_gsm_a_dtap_epc_ue_tl_mode = -1;
static int hf_gsm_a_dtap_epc_ue_tl_a_ul_sdu_size = -1;
static int hf_gsm_a_dtap_epc_ue_tl_a_drb = -1;
static int hf_gsm_a_dtap_epc_ue_tl_b_ip_pdu_delay = -1;
static int hf_gsm_a_dtap_epc_ue_tl_c_mbsfn_area_id = -1;
static int hf_gsm_a_dtap_epc_ue_tl_c_mch_id = -1;
static int hf_gsm_a_dtap_epc_ue_tl_c_lcid = -1;
static int hf_gsm_a_dtap_epc_ue_positioning_technology = -1;
static int hf_gsm_a_dtap_epc_mbms_packet_counter_value = -1;
static int hf_gsm_a_dtap_epc_latitude_sign = -1;
static int hf_gsm_a_dtap_epc_degrees_latitude = -1;
static int hf_gsm_a_dtap_epc_degrees_longitude = -1;
static int hf_gsm_a_dtap_epc_altitude_dir = -1;
static int hf_gsm_a_dtap_epc_altitude = -1;
static int hf_gsm_a_dtap_epc_bearing = -1;
static int hf_gsm_a_dtap_epc_horizontal_speed = -1;
static int hf_gsm_a_dtap_epc_gnss_tod_msec = -1;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_gsm_a_dtap_maximum_number_of_supported_bearers = -1;
static int hf_gsm_a_dtap_edge_channel_codings = -1;
static int hf_gsm_a_dtap_acceptable_channel_codings_TCH_F9_6 = -1;
static int hf_gsm_a_dtap_assignor_assignee = -1;
static int hf_gsm_a_dtap_configuration = -1;
static int hf_gsm_a_dtap_de_cause_coding_standard = -1;
static int hf_gsm_a_dtap_ss_version_indicator = -1;
static int hf_gsm_a_dtap_mode_of_operation = -1;
static int hf_gsm_a_dtap_bearer_cap_coding_standard = -1;
static int hf_gsm_a_dtap_nirr = -1;
static int hf_gsm_a_dtap_other_rate_adaption = -1;
static int hf_gsm_a_dtap_connection_element = -1;
static int hf_gsm_a_dtap_nic_on_tx = -1;
static int hf_gsm_a_dtap_user_rate = -1;
static int hf_gsm_a_dtap_protocol_discriminator = -1;
static int hf_gsm_a_dtap_cp_cause = -1;
static int hf_gsm_a_dtap_rate_adaption_header = -1;
static int hf_gsm_a_dtap_synchronous = -1;
static int hf_gsm_a_dtap_logical_link_identifier_negotiation = -1;
static int hf_gsm_a_dtap_multi_party_auxiliary_state = -1;
static int hf_gsm_a_dtap_parity_information = -1;
static int hf_gsm_a_dtap_channel_coding03 = -1;
static int hf_gsm_a_dtap_channel_coding30 = -1;
static int hf_gsm_a_dtap_loop_mechanism0E = -1;
static int hf_gsm_a_dtap_loop_mechanism1C = -1;
static int hf_gsm_a_dtap_multislot_tch = -1;
static int hf_gsm_a_dtap_acceptable_channel_codings_ext_TCH_F43_2 = -1;
static int hf_gsm_a_dtap_ue_positioning_technology = -1;
static int hf_gsm_a_dtap_acceptable_channel_codings_TCH_F4_8 = -1;
static int hf_gsm_a_dtap_number_of_spare_bits = -1;
static int hf_gsm_a_dtap_tie = -1;
static int hf_gsm_a_dtap_updating_type = -1;
static int hf_gsm_a_dtap_multiple_frame_establishment_support = -1;
static int hf_gsm_a_dtap_maximum_number_of_traffic_channels = -1;
static int hf_gsm_a_dtap_compression = -1;
static int hf_gsm_a_dtap_compression_up = -1;
static int hf_gsm_a_dtap_downlink_timeslot_offset = -1;
static int hf_gsm_a_dtap_acceptable_channel_codings_ext_TCH_F32_0 = -1;
static int hf_gsm_a_dtap_tio = -1;
static int hf_gsm_a_dtap_other_modem_type = -1;
static int hf_gsm_a_dtap_other_itc = -1;
static int hf_gsm_a_dtap_negotiation = -1;
static int hf_gsm_a_dtap_rate_adaption = -1;
static int hf_gsm_a_dtap_ms_positioning_technology = -1;
static int hf_gsm_a_dtap_ue_test_loop_mode = -1;
static int hf_gsm_a_dtap_number_of_data_bits = -1;
static int hf_gsm_a_dtap_follow_on_request = -1;
static int hf_gsm_a_dtap_repeat_indicator = -1;
static int hf_gsm_a_dtap_dst_adjustment = -1;
static int hf_gsm_a_dtap_pcp = -1;
static int hf_gsm_a_dtap_user_information_layer_2_protocol = -1;
static int hf_gsm_a_dtap_structure = -1;
static int hf_gsm_a_dtap_congestion_level = -1;
static int hf_gsm_a_dtap_access_identity = -1;
static int hf_gsm_a_dtap_modem_type = -1;
static int hf_gsm_a_dtap_test_loop = -1;
static int hf_gsm_a_dtap_subchannel = -1;
static int hf_gsm_a_dtap_ack_element = -1;
static int hf_gsm_a_dtap_layer_1_identity = -1;
static int hf_gsm_a_dtap_ciphering_key_sequence_number70 = -1;
static int hf_gsm_a_dtap_tp_pdu_description = -1;
static int hf_gsm_a_dtap_mode_flag = -1;
static int hf_gsm_a_dtap_egprs_mode_flag = -1;
static int hf_gsm_a_dtap_dtmf = -1;
static int hf_gsm_a_dtap_coding = -1;
static int hf_gsm_a_dtap_nic_on_rx = -1;
static int hf_gsm_a_dtap_emergency_number_information = -1;
static int hf_gsm_a_dtap_uimi = -1;
static int hf_gsm_a_dtap_number_of_stop_bits = -1;
static int hf_gsm_a_dtap_acceptable_channel_codings_spare78 = -1;
static int hf_gsm_a_dtap_type_of_identity = -1;
static int hf_gsm_a_dtap_ciphering_key_sequence_number = -1;
static int hf_gsm_a_dtap_recommendation = -1;
static int hf_gsm_a_dtap_max_num_of_speech_bearers = -1;
static int hf_gsm_a_dtap_keypad_information = -1;
static int hf_gsm_a_dtap_signalling_access_protocol = -1;
static int hf_gsm_a_dtap_user_information_layer_1_protocol = -1;
static int hf_gsm_a_dtap_wanted_air_interface_user_rate = -1;
static int hf_gsm_a_dtap_hold_auxiliary_state = -1;
static int hf_gsm_a_dtap_radio_channel_requirement = -1;
static int hf_gsm_a_dtap_channel_coding_asymmetry_indication = -1;
static int hf_gsm_a_dtap_service_type = -1;
static int hf_gsm_a_dtap_text_string = -1;
static int hf_gsm_a_dtap_tp_tested_device = -1;
static int hf_gsm_a_dtap_fixed_network_user_rate = -1;
static int hf_gsm_a_dtap_coding_scheme = -1;
static int hf_gsm_a_dtap_acceptable_channel_codings_ext_TCH_F28_8 = -1;
static int hf_gsm_a_dtap_v110_x30_rate_adaptation = -1;
static int hf_gsm_a_dtap_transfer_mode = -1;
static int hf_gsm_a_dtap_layer_2_identity = -1;
static int hf_gsm_a_dtap_add_ci = -1;
static int hf_gsm_a_dtap_mm_timer = -1;
static int hf_gsm_a_dtap_in_out_band = -1;
static int hf_gsm_a_dtap_data = -1;
static int hf_gsm_a_dtap_acceptable_channel_codings_TCH_F14_4 = -1;
static int hf_gsm_a_dtap_ti_flag = -1;
static int hf_gsm_a_dtap_time_zone_time = -1;
static int hf_gsm_a_dtap_acceptable_channel_codings_spare20 = -1;
static int hf_gsm_a_dtap_establishment = -1;
static int hf_gsm_a_dtap_duplex_mode = -1;
static int hf_gsm_a_dtap_subaddress = -1;
static int hf_gsm_a_dtap_subaddress_information = -1;
static int hf_gsm_a_dtap_message_elements = -1;
static int hf_gsm_a_dtap_rpdu = -1;
static int hf_gsm_a_dtap_timeslot_number = -1;
static int hf_gsm_a_dtap_uplink_rlc_sdu_size = -1;
static int hf_gsm_a_dtap_radio_bearer = -1;
static int hf_gsm_a_dtap_mbms_short_transmission_identity = -1;
static int hf_gsm_a_dtap_ue_received_rlc_sdu_counter_value = -1;
static int hf_gsm_a_dtap_num_lb_entities = -1;


static int hf_gsm_a_dtap_gcc_call_ref              = -1;
static int hf_gsm_a_dtap_gcc_call_ref_has_priority = -1;
static int hf_gsm_a_dtap_gcc_call_priority         = -1;
static int hf_gsm_a_dtap_gcc_call_state            = -1;
static int hf_gsm_a_dtap_gcc_cause                 = -1;
static int hf_gsm_a_dtap_gcc_cause_structure       = -1;
static int hf_gsm_a_dtap_gcc_orig_ind              = -1;
static int hf_gsm_a_dtap_gcc_state_attr            = -1;
static int hf_gsm_a_dtap_gcc_state_attr_da         = -1;
static int hf_gsm_a_dtap_gcc_state_attr_ua         = -1;
static int hf_gsm_a_dtap_gcc_state_attr_comm       = -1;
static int hf_gsm_a_dtap_gcc_state_attr_oi         = -1;

static int hf_gsm_a_dtap_gcc_spare_1 = -1;
static int hf_gsm_a_dtap_gcc_spare_3 = -1;
static int hf_gsm_a_dtap_gcc_spare_4 = -1;

static int hf_gsm_a_dtap_bcc_call_ref              = -1;
static int hf_gsm_a_dtap_bcc_call_ref_has_priority = -1;
static int hf_gsm_a_dtap_bcc_call_priority         = -1;
static int hf_gsm_a_dtap_bcc_call_state            = -1;
static int hf_gsm_a_dtap_bcc_cause                 = -1;
static int hf_gsm_a_dtap_bcc_cause_structure       = -1;
static int hf_gsm_a_dtap_bcc_orig_ind              = -1;
static int hf_gsm_a_dtap_bcc_state_attr            = -1;
static int hf_gsm_a_dtap_bcc_state_attr_da         = -1;
static int hf_gsm_a_dtap_bcc_state_attr_ua         = -1;
static int hf_gsm_a_dtap_bcc_state_attr_comm       = -1;
static int hf_gsm_a_dtap_bcc_state_attr_oi         = -1;
static int hf_gsm_a_dtap_bcc_compr_otdi            = -1;

static int hf_gsm_a_dtap_bcc_spare_1 = -1;
static int hf_gsm_a_dtap_bcc_spare_3 = -1;
static int hf_gsm_a_dtap_bcc_spare_4 = -1;



/* Initialize the subtree pointers */
static gint ett_dtap_msg = -1;
static gint ett_dtap_oct_1 = -1;
static gint ett_cm_srvc_type = -1;
static gint ett_gsm_enc_info = -1;
static gint ett_bc_oct_3 = -1;
static gint ett_bc_oct_3a = -1;
static gint ett_bc_oct_4 = -1;
static gint ett_bc_oct_5 = -1;
static gint ett_bc_oct_5a = -1;
static gint ett_bc_oct_5b = -1;
static gint ett_bc_oct_6 = -1;
static gint ett_bc_oct_6a = -1;
static gint ett_bc_oct_6b = -1;
static gint ett_bc_oct_6c = -1;
static gint ett_bc_oct_6d = -1;
static gint ett_bc_oct_6e = -1;
static gint ett_bc_oct_6f = -1;
static gint ett_bc_oct_6g = -1;
static gint ett_bc_oct_7 = -1;
static gint ett_epc_ue_tl_a_lb_setup = -1;
static gint ett_mm_timer = -1;
static gint ett_ue_test_loop_mode = -1;

static expert_field ei_gsm_a_dtap_keypad_info_not_dtmf_digit = EI_INIT;
static expert_field ei_gsm_a_dtap_text_string_not_multiple_of_7 = EI_INIT;
static expert_field ei_gsm_a_dtap_autn = EI_INIT;
static expert_field ei_gsm_a_dtap_invalid_ia5_character = EI_INIT;
static expert_field ei_gsm_a_dtap_auts = EI_INIT;
static expert_field ei_gsm_a_dtap_not_digit = EI_INIT;
static expert_field ei_gsm_a_dtap_end_mark_unexpected = EI_INIT;
static expert_field ei_gsm_a_dtap_extraneous_data = EI_INIT;
static expert_field ei_gsm_a_dtap_missing_mandatory_element = EI_INIT;
static expert_field ei_gsm_a_dtap_coding_scheme = EI_INIT;


static dissector_table_t u2u_dissector_table;

static dissector_handle_t gsm_map_handle;
static dissector_handle_t rp_handle;

static proto_tree *g_tree;

/*
 * this should be set on a per message basis, if possible
 */
static gint is_uplink;
static guint8 epc_test_loop_mode;

#define NUM_GSM_DTAP_ELEM (sizeof(gsm_dtap_elem_strings)/sizeof(value_string))
gint ett_gsm_dtap_elem[NUM_GSM_DTAP_ELEM];

static dgt_set_t Dgt_mbcd = {
    {
    /* 0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f */
      '0','1','2','3','4','5','6','7','8','9','*','#','a','b','c','?'
    }
};

/*
 * [9] 10.5.3.1 Authentication parameter RAND
 */
static guint16
de_auth_param_rand(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    /* The RAND value is 16 octets long */
    proto_tree_add_item(tree, hf_gsm_a_dtap_rand, tvb, offset, 16, ENC_NA);

    /* no length check possible */
    return (16);
}

/*
 * [9] 10.5.3.1.1 Authentication Parameter AUTN (UMTS and EPS authentication challenge)
 */
static guint16
de_auth_param_autn(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    proto_item *item;
    proto_tree *subtree;

    item = proto_tree_add_item(tree, hf_gsm_a_dtap_autn, tvb, offset, len, ENC_NA);
    subtree = proto_item_add_subtree(item, ett_gsm_dtap_elem[DE_AUTH_PARAM_AUTN]);

    if (len == 16)
    {
        proto_tree_add_item(subtree, hf_gsm_a_dtap_autn_sqn_xor_ak, tvb, offset, 6, ENC_NA);
        proto_tree_add_item(subtree, hf_gsm_a_dtap_autn_amf, tvb, offset + 6, 2, ENC_NA);
        proto_tree_add_item(subtree, hf_gsm_a_dtap_autn_mac, tvb, offset + 8, 8, ENC_NA);
    }
    else
        expert_add_info(pinfo, item, &ei_gsm_a_dtap_autn);

    return (len);
}

/*
 * [9] 10.5.3.2 Authentication Response parameter
 */
static guint16
de_auth_resp_param(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    /* This IE contains either the SRES or the 4 most significant octets of the RES */
    proto_tree_add_item(tree, hf_gsm_a_dtap_sres, tvb, offset, 4, ENC_NA);

    /* no length check possible */
    return (4);
}

/*
 * [9] 10.5.3.2.1 Authentication Response Parameter (extension) (UMTS authentication challenge only)
 */
static guint16
de_auth_resp_param_ext(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    /* This IE contains all but 4 most significant octets of RES */
    proto_tree_add_item(tree, hf_gsm_a_dtap_xres, tvb, offset, len, ENC_NA);

    return (len);
}

/*
 * [9] 10.5.3.2.2 Authentication Failure parameter (UMTS and EPS authentication challenge)
 */
static guint16
de_auth_fail_param(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    proto_item *item;
    proto_tree *subtree;

    item = proto_tree_add_item(tree, hf_gsm_a_dtap_auts, tvb, offset, len, ENC_NA);
    subtree = proto_item_add_subtree(item, ett_gsm_dtap_elem[DE_AUTH_FAIL_PARAM]);

    if (len == 14)
    {
        proto_tree_add_item(subtree, hf_gsm_a_dtap_auts_sqn_ms_xor_ak, tvb, offset, 6, ENC_NA);
        proto_tree_add_item(subtree, hf_gsm_a_dtap_auts_mac_s, tvb, offset + 6, 8, ENC_NA);
    }
    else
        expert_add_info(pinfo, item, &ei_gsm_a_dtap_auts);

    return (len);
}

/*
 * 10.5.3.3 CM service type
 *  handled inline
 */
/*
 * 10.5.3.4 Identity type
 *  handled inline
 */
/*
 * 10.5.3.5 Location updating type
 *  handled inline
 */
/*
 * [3] 10.5.3.5a Network Name
 */
static const value_string gsm_a_dtap_number_of_spare_bits_vals[] = {
    { 0, "this field carries no information about the number of spare bits in octet n"},
    { 1, "bit 8 is spare and set to '0' in octet n"},
    { 2, "bits 7 and 8 are spare and set to '0' in octet n"},
    { 3, "bits 6 to 8(inclusive) are spare and set to '0' in octet n"},
    { 4, "bits 5 to 8(inclusive) are spare and set to '0' in octet n"},
    { 5, "bits 4 to 8(inclusive) are spare and set to '0' in octet n"},
    { 6, "bits 3 to 8(inclusive) are spare and set to '0' in octet n"},
    { 7, "bits 2 to 8(inclusive) are spare and set to '0' in octet n"},
    { 0, NULL }
};

const true_false_string tfs_add_ci = { "The MS should add the letters for the Country's Initials and a separator (e.g. a space) to the text string",
                                       "The MS should not add the letters for the Country's Initials to the text string" };

static const value_string gsm_a_dtap_coding_scheme_vals[] = {
    { 0, "Cell Broadcast data coding scheme, GSM default alphabet, language unspecified, defined in 3GPP TS 23.038"},
    { 1, "UCS2 (16 bit)"},
    { 2, "Reserved"},
    { 3, "Reserved"},
    { 4, "Reserved"},
    { 5, "Reserved"},
    { 6, "Reserved"},
    { 7, "Reserved"},
    { 0, NULL }
};
static guint16
de_network_name(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint8       oct;
    guint32      curr_offset;
    guint8       coding_scheme, num_spare_bits;
    guint32      num_text_bits;
    proto_item  *item;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_item(tree, hf_gsm_a_extension, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    coding_scheme = (oct & 0x70) >> 4;
    proto_tree_add_item(tree, hf_gsm_a_dtap_coding_scheme, tvb, curr_offset, 1, ENC_NA);

    proto_tree_add_item(tree, hf_gsm_a_dtap_add_ci, tvb, curr_offset, 1, ENC_NA);

    num_spare_bits = oct & 0x07;
    item = proto_tree_add_item(tree, hf_gsm_a_dtap_number_of_spare_bits, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    NO_MORE_DATA_CHECK(len);
    switch (coding_scheme)
    {
    case 0:
        /* Check if there was a reasonable value for number of spare bits in last octet */
        num_text_bits = ((len - 1) << 3) - num_spare_bits;
        if (num_spare_bits && (num_text_bits % 7))
        {
            expert_add_info(pinfo, item, &ei_gsm_a_dtap_text_string_not_multiple_of_7);
        }
        proto_tree_add_ts_23_038_7bits_item(tree, hf_gsm_a_dtap_text_string, tvb, curr_offset<<3, num_text_bits/7);
        break;
    case 1:
        proto_tree_add_item(tree, hf_gsm_a_dtap_text_string, tvb, curr_offset, len - 1, ENC_UCS_2|ENC_BIG_ENDIAN);
        break;
    default:
        proto_tree_add_expert(tree, pinfo, &ei_gsm_a_dtap_coding_scheme, tvb, curr_offset, len - 1);
    }

    return (len);
}

/* 3GPP TS 24.008
 * [9] 10.5.3.6 Reject cause
 */
static const range_string gsm_a_dtap_rej_cause_vals[] = {
    { 0x02, 0x02, "IMSI unknown in HLR"},
    { 0x03, 0x03, "Illegal MS"},
    { 0x04, 0x04, "IMSI unknown in VLR"},
    { 0x05, 0x05, "IMEI not accepted"},
    { 0x06, 0x06, "Illegal ME"},
    { 0x0b, 0x0b, "PLMN not allowed"},
    { 0x0c, 0x0c, "Location Area not allowed"},
    { 0x0d, 0x0d, "Roaming not allowed in this location area"},
    { 0x0f, 0x0f, "No Suitable Cells In Location Area"},
    { 0x11, 0x11, "Network failure"},
    { 0x14, 0x14, "MAC failure"},
    { 0x15, 0x15, "Synch failure"},
    { 0x16, 0x16, "Congestion"},
    { 0x17, 0x17, "GSM authentication unacceptable"},
    { 0x19, 0x19, "Not authorized for this CSG"},
    { 0x20, 0x20, "Service option not supported"},
    { 0x21, 0x21, "Requested service option not subscribed"},
    { 0x22, 0x22, "Service option temporarily out of order"},
    { 0x26, 0x26, "Call cannot be identified"},
    { 0x30, 0x3f, "Retry upon entry into a new cell"},
    { 0x5f, 0x5f, "Semantically incorrect message"},
    { 0x60, 0x60, "Invalid mandatory information"},
    { 0x61, 0x61, "Message type non-existent or not implemented"},
    { 0x62, 0x62, "Message type not compatible with the protocol state"},
    { 0x63, 0x63, "Information element non-existent or not implemented"},
    { 0x64, 0x64, "Conditional IE error"},
    { 0x65, 0x65, "Message not compatible with the protocol state"},
    { 0x6f, 0x6f, "Protocol error, unspecified"},
    { 0, 0, NULL }
};

guint16
de_rej_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint8       oct;
    const gchar *str;

    oct = tvb_get_guint8(tvb, offset);

    str = try_rval_to_str(oct, gsm_a_dtap_rej_cause_vals);
    if (!str)
    {
        if (is_uplink == IS_UPLINK_TRUE)
            str = "Protocol error, unspecified";
        else
            str = "Service option temporarily out of order";
    }

    proto_tree_add_uint_format_value(tree, hf_gsm_a_dtap_rej_cause, tvb,
                offset, 1, oct, "%s (%u)", str, oct);

    /* no length check possible */

    return (1);
}

/*
 * 10.5.3.7 Follow-on Proceed
 *  No data
 */
/*
 * [3] 10.5.3.8 Time Zone
 */
guint16
de_time_zone(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint8  oct;
    guint32 curr_offset;
    char    sign;

    curr_offset = offset;

    /* 3GPP TS 23.040 version 6.6.0 Release 6
     * 9.2.3.11 TP-Service-Centre-Time-Stamp (TP-SCTS)
     * :
     * The Time Zone indicates the difference, expressed in quarters of an hour,
     * between the local time and GMT. In the first of the two semi-octets,
     * the first bit (bit 3 of the seventh octet of the TP-Service-Centre-Time-Stamp field)
     * represents the algebraic sign of this difference (0: positive, 1: negative).
     */

    oct = tvb_get_guint8(tvb, curr_offset);
    sign = (oct & 0x08)?'-':'+';
    oct = (oct >> 4) + (oct & 0x07) * 10;

    proto_tree_add_uint_format_value(tree, hf_gsm_a_dtap_timezone, tvb, curr_offset, 1, oct, "GMT %c %d hours %d minutes", sign, oct / 4, oct % 4 * 15);
    curr_offset++;

    /* no length check possible */

    return (curr_offset - offset);
}

/*
 * [3] 10.5.3.9 Time Zone and Time
 */
static guint16
de_time_zone_time(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint8  oct;
    guint32 curr_offset;
    char    sign;
    nstime_t tv;
    struct tm tm;

    curr_offset = offset;

    /* "unused" part of structure */
    tm.tm_wday = 0;
    tm.tm_yday = 0;
    tm.tm_isdst = -1;

    oct = tvb_get_guint8(tvb, curr_offset);
    tm.tm_year = (oct & 0x0f)*10 + ((oct & 0xf0) >> 4) + 100;
    oct = tvb_get_guint8(tvb, curr_offset+1);
    tm.tm_mon = (oct & 0x0f)*10 + ((oct & 0xf0) >> 4) - 1;
    oct = tvb_get_guint8(tvb, curr_offset+2);
    tm.tm_mday = (oct & 0x0f)*10 + ((oct & 0xf0) >> 4);
    oct = tvb_get_guint8(tvb, curr_offset+3);
    tm.tm_hour = (oct & 0x0f)*10 + ((oct & 0xf0) >> 4);
    oct = tvb_get_guint8(tvb, curr_offset+4);
    tm.tm_min = (oct & 0x0f)*10 + ((oct & 0xf0) >> 4);
    oct = tvb_get_guint8(tvb, curr_offset+5);
    tm.tm_sec = (oct & 0x0f)*10 + ((oct & 0xf0) >> 4);

    tv.secs = mktime(&tm);
    tv.nsecs = 0;

    proto_tree_add_time_format_value(tree, hf_gsm_a_dtap_time_zone_time, tvb, curr_offset, 6,
                                     &tv, "%s", abs_time_to_str(wmem_packet_scope(), &tv, ABSOLUTE_TIME_LOCAL, FALSE));
    curr_offset += 6;

    /* 3GPP TS 23.040 version 6.6.0 Release 6
     * 9.2.3.11 TP-Service-Centre-Time-Stamp (TP-SCTS)
     * :
     * The Time Zone indicates the difference, expressed in quarters of an hour,
     * between the local time and GMT. In the first of the two semi-octets,
     * the first bit (bit 3 of the seventh octet of the TP-Service-Centre-Time-Stamp field)
     * represents the algebraic sign of this difference (0: positive, 1: negative).
     */

    oct = tvb_get_guint8(tvb, curr_offset);
    sign = (oct & 0x08)?'-':'+';
    oct = (oct >> 4) + (oct & 0x07) * 10;

    proto_tree_add_uint_format_value(tree, hf_gsm_a_dtap_timezone, tvb, curr_offset, 1, oct, "GMT %c %d hours %d minutes", sign, oct / 4, oct % 4 * 15);

    curr_offset++;

    /* no length check possible */

    return (curr_offset - offset);
}
/*
 * 10.5.3.10 CTS permission
 * No data
 */
/*
 * [3] 10.5.3.11 LSA Identifier
 * 3GPP TS 24.008 version 6.8.0 Release 6
 */
static guint16
de_lsa_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    if (len == 0) {
        proto_tree_add_uint_format_value(tree, hf_gsm_a_dtap_lsa_id, tvb, curr_offset, len, 0, "not included");
    }
    else
    {
        proto_tree_add_item(tree, hf_gsm_a_dtap_lsa_id, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
    }

    curr_offset += len;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_dtap_extraneous_data);

    return (curr_offset - offset);
}

/*
 * [3] 10.5.3.12 Daylight Saving Time
 */
static const value_string gsm_a_dtap_dst_adjustment_vals[] = {
    { 0, "No adjustment for Daylight Saving Time"},
    { 1, "+1 hour adjustment for Daylight Saving Time"},
    { 2, "+2 hours adjustment for Daylight Saving Time"},
    { 3, "Reserved"},
    { 0, NULL }
};

static guint16
de_day_saving_time(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32      curr_offset;

    curr_offset = offset;

    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, curr_offset<<3, 6, ENC_BIG_ENDIAN);

    proto_tree_add_item(tree, hf_gsm_a_dtap_dst_adjustment, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_dtap_extraneous_data);

    return (curr_offset - offset);
}

/*
 * 10.5.3.13 Emergency Number List
 */
static guint16
de_emerg_num_list(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32     curr_offset;
    guint8      en_len;
    guint8      count;
    proto_tree *subtree;
    proto_item *item;
    const char *digit_str;

    curr_offset = offset;

    count = 1;
    while ((curr_offset - offset) < len) {
        /* Length of 1st Emergency Number information note 1) octet 3
         * NOTE 1: The length contains the number of octets used to encode the
         * Emergency Service Category Value and the Number digits.
         */
        en_len = tvb_get_guint8(tvb, curr_offset);

        item = proto_tree_add_uint(tree, hf_gsm_a_dtap_emergency_number_information,
            tvb, curr_offset, en_len + 1, count);
        subtree = proto_item_add_subtree(item, ett_gsm_dtap_elem[DE_EMERGENCY_NUM_LIST]);
        proto_tree_add_item(subtree, hf_gsm_a_dtap_emerg_num_info_length, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

        curr_offset++;
        /* 0 0 0 Emergency Service Category Value (see
         *       Table 10.5.135d/3GPP TS 24.008
         * Table 10.5.135d/3GPP TS 24.008: Service Category information element
         */
        proto_tree_add_bits_item(subtree, hf_gsm_a_spare_bits, tvb, curr_offset<<3, 3, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_gsm_a_dtap_serv_cat_b5, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_gsm_a_dtap_serv_cat_b4, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_gsm_a_dtap_serv_cat_b3, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_gsm_a_dtap_serv_cat_b2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_gsm_a_dtap_serv_cat_b1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset++;
        en_len--;

        digit_str = tvb_bcd_dig_to_wmem_packet_str(tvb, curr_offset, en_len, NULL, FALSE);
        item = proto_tree_add_string(subtree, hf_gsm_a_dtap_emergency_bcd_num, tvb, curr_offset, en_len, digit_str);

        /* Check for values that aren't digits; they get mapped to '?' */
        if(strchr(digit_str,'?')){
            expert_add_info(pinfo, item, &ei_gsm_a_dtap_not_digit);
        }

        curr_offset = curr_offset + en_len;
        count++;
    }

    return (len);
}

/*
 * 10.5.3.14 Additional update parameters
 */
static const true_false_string gsm_a_dtap_csmo_value = {
    "CS fallback mobile originating call",
    "No additional information"
};

static const true_false_string gsm_a_dtap_csmt_value = {
    "CS fallback mobile terminating call",
    "No additional information"
};

static guint16
de_add_upd_params(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3)+4, 2, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(tree, hf_gsm_a_dtap_csmo, tvb, (curr_offset<<3)+6, 1, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(tree, hf_gsm_a_dtap_csmt, tvb, (curr_offset<<3)+7, 1, ENC_BIG_ENDIAN);

    return (len);
}

/*
 * 10.5.3.15 MM Timer
 */
static const value_string gsm_a_dtap_mm_timer_unit_vals[] = {
    { 0x00, "value is incremented in multiples of 2 seconds" },
    { 0x01, "value is incremented in multiples of 1 minute" },
    { 0x02, "value is incremented in multiples of decihours" },
    { 0x07, "value indicates that the timer is deactivated" },
    { 0, NULL }
};

static guint16
de_mm_timer(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint8       oct;
    guint16      val;
    const gchar *str;
    proto_tree  *subtree;
    proto_item  *item = NULL;

    oct = tvb_get_guint8(tvb, offset);
    val = oct&0x1f;

    switch (oct>>5)
    {
    case 0:
        str = "sec"; val*=2;
        break;
    case 1:
        str = "min";
        break;
    case 2:
        str = "min"; val*=6;
        break;
    case 7:
        str = "";
        item = proto_tree_add_uint_format_value(tree, hf_gsm_a_dtap_mm_timer, tvb, offset, 1,
                            oct, "timer is deactivated");
        break;
    default:
        str = "min";
        break;
    }

    if (item == NULL) {
        item = proto_tree_add_uint_format_value(tree, hf_gsm_a_dtap_mm_timer, tvb, offset, 1, val,
                                   "%u %s", val, str);
    }

    subtree = proto_item_add_subtree(item, ett_mm_timer);
    proto_tree_add_item(subtree, hf_gsm_a_dtap_mm_timer_unit, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_a_dtap_mm_timer_value, tvb, offset, 1, ENC_BIG_ENDIAN);

    return (1);
}

 /*
 * [3] 10.5.4.4 Auxiliary states
 */

static const value_string gsm_a_dtap_hold_auxilary_state_vals[] = {
    { 0x00, "Idle" },
    { 0x01, "Hold request" },
    { 0x02, "Call held" },
    { 0x03, "Retrieve request" },
    { 0, NULL }
};

static const value_string gsm_a_dtap_multi_party_auxilary_state_vals[] = {
    { 0x00, "Idle" },
    { 0x01, "MPTY request" },
    { 0x02, "Call in MPTY" },
    { 0x03, "Split request" },
    { 0, NULL }
};

static guint16
de_aux_states(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32      curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_extension, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3)+1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_dtap_hold_auxiliary_state, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_dtap_multi_party_auxiliary_state, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_dtap_extraneous_data);

    return (curr_offset - offset);
}
/*
 * 10.5.4.4a Backup bearer capability
 */
/*
 * [3] 10.5.4.5 Bearer capability (3GPP TS 24.008 version 8.4.0 Release 8)
 */
/* Speech version indication (octet(s) 3a etc.) Bits 4 3 2 1 */

static const value_string gsm_a_dtap_speech_vers_ind_values[] = {
    { 0x0,  "GSM full rate speech version 1(GSM FR)" },
    { 0x1,  "GSM half rate speech version 1(GSM HR)" },
    { 0x2,  "GSM full rate speech version 2(GSM EFR)" },
    { 0x3,  "Speech version tbd" },
    { 0x4,  "GSM full rate speech version 3(FR AMR)" },
    { 0x5,  "GSM half rate speech version 3(HR AMR)" },
    { 0x6,  "GSM full rate speech version 4(OFR AMR-WB)" },
    { 0x7,  "GSM half rate speech version 4(OHR AMR-WB)" },
    { 0x8,  "GSM full rate speech version 5(FR AMR-WB)" },
    { 0x9,  "Speech version tbd" },
    { 0xa,  "Speech version tbd" },
    { 0xb,  "GSM half rate speech version 6(OHR AMR)" },
    { 0xc,  "Speech version tbd" },
    { 0xd,  "Speech version tbd" },
    { 0xe,  "Speech version tbd" },
    { 0xf,  "No speech version supported for GERAN" },
    { 0, NULL }
};
/* All other values have the meaning "speech version tbd" and shall be ignored
 * when received.
 */
/*
 * Information transfer capability (octet 3) Bits 3 2 1
 */
static const value_string gsm_a_dtap_itc_values[] = {
    { 0x0,  "Speech" },
    { 0x1,  "Unrestricted digital information" },
    { 0x2,  "3.1 kHz audio, ex PLMN" },
    { 0x3,  "Facsimile group 3" },
    { 0x5,  "Other ITC (See Octet 5a)" },
    { 0x7,  "Reserved,(In Network alternate speech/facsimile group 3)" },
    { 0, NULL }
};

static const value_string gsm_a_dtap_structure_vals[] = {
    { 0x0,  "Service data unit integrity" },
    { 0x1,  "Reserved" },
    { 0x2,  "Reserved" },
    { 0x3,  "Unstructured" },
    { 0, NULL }
};

static const value_string gsm_a_dtap_access_identity_vals[] = {
    { 0x0,  "Octet identifier" },
    { 0x1,  "Octet identifier" },
    { 0x2,  "Octet identifier" },
    { 0x3,  "Reserved" },
    { 0, NULL }
};

static const value_string gsm_a_dtap_rate_adaption_vals[] = {
    { 0x0,  "No rate adaption" },
    { 0x1,  "Rate adaptation according to ITU-T Rec. V.110 and ITU-T Rec. X.30" },
    { 0x2,  "Flag stuffing according to ITU-T Rec. X.31" },
    { 0x3,  "Other rate adaption (see octet 5a)" },
    { 0, NULL }
};

static const value_string gsm_a_dtap_signal_access_protocol_vals[] = {
    { 0x0,  "Reserved" },
    { 0x1,  "Rate adaptation according to ITU-T Rec. V.110 and ITU-T Rec. X.30" },
    { 0x2,  "Flag stuffing according to ITU-T Rec. X.31" },
    { 0x3,  "Other rate adaption (see octet 5a)" },
    { 0x4,  "No rate adaption" },
    { 0x5,  "Rate adaptation according to ITU-T Rec. V.110 and ITU-T Rec. X.30" },
    { 0x6,  "Flag stuffing according to ITU-T Rec. X.31" },
    { 0x7,  "Reserved" },
    { 0, NULL }
};

static const value_string gsm_a_dtap_other_itc_vals[] = {
    { 0x0,  "Restricted digital information" },
    { 0x1,  "Restricted digital information" },
    { 0x2,  "Restricted digital information" },
    { 0x3,  "Reserved" },
    { 0, NULL }
};

static const value_string gsm_a_dtap_other_rate_adaption_vals[] = {
    { 0x0,  "According to ITU-T Rec. V.120" },
    { 0x1,  "According to ITU-T Rec. H.223 and ITU-T Rec. H.245" },
    { 0x2,  "PIAFS" },
    { 0x3,  "Reserved" },
    { 0, NULL }
};

static const value_string gsm_a_dtap_user_rate_vals[] = {
    { 0x1,  "0.3 kbit/s (according to ITU-T Rec. X.1 and ITU-T Rec. V.110)" },
    { 0x2,  "1.2 kbit/s (according to ITU-T Rec. X.1 and ITU-T Rec. V.110)" },
    { 0x3,  "2.4 kbit/s (according to ITU-T Rec. X.1 and ITU-T Rec. V.110)" },
    { 0x4,  "4.8 kbit/s (according to ITU-T Rec. X.1 and ITU-T Rec. V.110)" },
    { 0x5,  "9.6 kbit/s (according to ITU-T Rec. X.1 and ITU-T Rec. V.110)" },
    { 0x6,  "12.0 kbit/s transparent (non compliance with ITU-T Rec. X.1 and ITU-T Rec. V.110)" },
    { 0x7,  "Reserved: was allocated in earlier phases of the protocol" },
    { 0, NULL }
};

static const value_string gsm_a_dtap_v110_x30_rate_adaptation_vals[] = {
    { 0x0,  "Reserved" },
    { 0x1,  "Reserved" },
    { 0x2,  "8 kbit/s" },
    { 0x3,  "16 kbit/s" },
    { 0, NULL }
};

static const value_string gsm_a_dtap_parity_info_vals[] = {
    { 0x0,  "Odd" },
    { 0x1,  "Reserved" },
    { 0x2,  "Even" },
    { 0x3,  "None" },
    { 0x4,  "Forced to 0" },
    { 0x5,  "Forced to 1" },
    { 0x6,  "Reserved" },
    { 0x7,  "Reserved" },
    { 0, NULL }
};

static const value_string gsm_a_dtap_connection_element_vals[] = {
    { 0x0,  "Transparent" },
    { 0x1,  "Non transparent (RLP)" },
    { 0x2,  "Both, transparent preferred" },
    { 0x3,  "Both, non transparent preferred" },
    { 0, NULL }
};

static const value_string gsm_a_dtap_modem_type_vals[] = {
    { 0x0,  "None" },
    { 0x1,  "According to ITU-T Rec. V.21" },
    { 0x2,  "According to ITU-T Rec. V.22" },
    { 0x3,  "According to ITU-T Rec. V.22 bis" },
    { 0x4,  "Reserved: was allocated in earlier phases of the protocol" },
    { 0x5,  "According to ITU-T Rec. V.26 ter" },
    { 0x6,  "According to ITU-T Rec. V.32" },
    { 0x7,  "Modem for undefined interface" },
    { 0x8,  "Autobauding type 1" },
    { 0, NULL }
};

static const value_string gsm_a_dtap_other_modem_type_vals[] = {
    { 0x0,  "No other modem type specified in this field" },
    { 0x1,  "Reserved" },
    { 0x2,  "According to ITU-T Rec. V.34" },
    { 0x3,  "Reserved" },
    { 0, NULL }
};

static const value_string gsm_a_dtap_fixed_network_user_rate_vals[] = {
    { 0x00, "Fixed network user rate not applicable/No meaning is associated with this value"},
    { 0x01, "9.6 kbit/s (according to ITU-T Rec. X.1 and ITU-T Rec. V.110)"},
    { 0x02, "14.4 kbit/s (according to ITU-T Rec. X.1 and ITU-T Rec. V.110)"},
    { 0x03, "19.2 kbit/s (according to ITU-T Rec. X.1 and ITU-T Rec. V.110)"},
    { 0x04, "28.8 kbit/s (according to ITU-T Rec. X.1 and ITU-T Rec. V.110)"},
    { 0x05, "38.4 kbit/s (according to ITU-T Rec. X.1 and ITU-T Rec. V.110)"},
    { 0x06, "48.0 kbit/s (according to ITU-T Rec. X.1 and ITU-T Rec. V.110 (synch))"},
    { 0x07, "56.0 kbit/s (according to ITU-T Rec. X.1 and ITU-T Rec. V.110 (synch) /bit transparent)"},
    { 0x08, "64.0 kbit/s bit transparent"},
    { 0x09, "33.6 kbit/s bit transparent"},
    { 0x0a, "32.0 kbit/s (according to ITU-T Rec. I.460)"},
    { 0x0b, "31.2 kbit/s (according to ITU-T Rec. V.34)"},
    { 0, NULL }
};

static const value_string gsm_a_dtap_uimi_vals[] = {
    { 0x0,  "not allowed/required/applicable" },
    { 0x1,  "up to 1 TCH/F allowed/may be requested" },
    { 0x2,  "up to 2 TCH/F allowed/may be requested" },
    { 0x3,  "up to 3 TCH/F allowed/may be requested" },
    { 0x4,  "up to 4 TCH/F allowed/may be requested" },
    { 0x5,  "up to 4 TCH/F may be requested" },
    { 0x6,  "up to 4 TCH/F may be requested" },
    { 0x7,  "up to 4 TCH/F may be requested" },
    { 0, NULL }
};

static const value_string gsm_a_dtap_wanted_air_rate_vals[] = {
    { 0x0,  "Air interface user rate not applicable/No meaning associated with this value" },
    { 0x1,  "9.6 kbit/s" },
    { 0x2,  "14.4 kbit/s" },
    { 0x3,  "19.2 kbit/s" },
    { 0x4,  "Reserved" },
    { 0x5,  "28.8 kbit/s" },
    { 0x6,  "38.4 kbit/s" },
    { 0x7,  "43.2 kbit/s" },
    { 0x8,  "57.6 kbit/s" },
    { 0x9,  "interpreted by the network as 38.4 kbit/s in this version of the protocol" },
    { 0xa,  "interpreted by the network as 38.4 kbit/s in this version of the protocol" },
    { 0xb,  "interpreted by the network as 38.4 kbit/s in this version of the protocol" },
    { 0xc,  "interpreted by the network as 38.4 kbit/s in this version of the protocol" },
    { 0xd,  "Reserved" },
    { 0xe,  "Reserved" },
    { 0xf,  "Reserved" },
    { 0, NULL }
};

static const value_string gsm_a_dtap_channel_coding_asymmetry_ind_vals[] = {
    { 0x0,  "Channel coding symmetry preferred" },
    { 0x1,  "Uplink biased channel coding asymmetry is preferred" },
    { 0x2,  "Downlink biased channel coding asymmetry is preferred" },
    { 0x3,  "Unused, treat as Channel coding symmetry preferred" },
    { 0, NULL }
};

static const value_string gsm_a_dtap_user_info_layer2_vals[] = {
    { 0x06, "Reserved: was allocated in earlier phases of the protocol" },
    { 0x08, "According to ISO/IEC 6429, codeset 0 (DC1/DC3)" },
    { 0x09, "Reserved: was allocated but never used in earlier phases of the protocol" },
    { 0x0a, "Videotex profile 1" },
    { 0x0c, "COPnoFlCt (Character oriented Protocol with no Flow Control mechanism)" },
    { 0x0d, "Reserved: was allocated in earlier phases of the protocol" },
    { 0, NULL }
};

static const true_false_string tfs_bearer_cap_coding_standard = { "reserved", "GSM standardized coding" };
static const true_false_string tfs_bearer_cap_transfer_mode = { "packet", "circuit" };
static const true_false_string tfs_bearer_cap_coding = { "octet used for other extension of octet 3", "octet used for extension of information transfer capability" };
static const true_false_string tfs_bearer_cap_configuration = { "Reserved", "Point-to-point" };
static const true_false_string tfs_nirr = { "Data up to and including 4.8 kb/s, full rate, non-transparent, 6 kb/s radio interface rate is requested",
                        "No meaning is associated with this value" };
static const true_false_string tfs_bearer_cap_establishment = { "Reserved", "Demand" };
static const true_false_string tfs_frame_est_supported_not_supported = { "Supported", "Not supported, only UI frames allowed" };
static const true_false_string tfs_log_link_neg = { "Full protocol negotiation", "Default, LLI=256 only" };
static const true_false_string tfs_assignor_assignee = { "Message originator is assignor only", "Message originator is default assignee" };
static const true_false_string tfs_in_out_band = { "Negotiation is done with USER INFORMATION messages on a temporary signalling connection",
                           "Negotiation is done in-band using logical link zero" };
static const true_false_string tfs_stop_bits = { "2", "1" };
static const true_false_string tfs_negotiation = { "Reserved", "In-band negotiation not possible" };
static const true_false_string tfs_parity_bits = { "8", "7" };
static const true_false_string tfs_nic_on_tx = { "requires to send data with network independent clock",
                         "does not require to send data with network independent clock" };
static const true_false_string tfs_nic_on_rx = { "can accept data with network independent clock",
                         "cannot accept data with network independent clock" };

guint16
de_bearer_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8       oct;
    guint8       itc;
    gboolean     extended;
    guint32      curr_offset;
    guint32      saved_offset;
    proto_tree  *subtree;
    proto_item  *item;
    const gchar *str;

#define DE_BC_ITC_SPEECH    0x00
#define DE_BC_ITC_UDI       0x01
#define DE_BC_ITC_EX_PLMN   0x02
#define DE_BC_ITC_FASC_G3   0x03
#define DE_BC_ITC_OTHER_ITC 0x05
#define DE_BC_ITC_RSVD_NET  0x07

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    /* octet 3 */

    /*
     * warning, bearer cap uses extended values that
     * are reversed from other parameters!
     */
    subtree =
        proto_tree_add_subtree(tree,
            tvb, curr_offset, 1,
            ett_bc_oct_3, NULL, "Octet 3");

    extended = (oct & 0x80) ? FALSE : TRUE;
    itc = oct & 0x07;

    proto_tree_add_item(subtree, hf_gsm_a_extension, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    switch (is_uplink)
    {
    case IS_UPLINK_FALSE:
        str = "Spare";
        break;

    case IS_UPLINK_TRUE:
        /*
         * depends on Information transfer capability
         */
        switch (itc)
        {
        case DE_BC_ITC_SPEECH:
            if (extended)
            {
                switch ((oct & 0x60) >> 5)
                {
                case 1: str = "MS supports at least full rate speech version 1 but does not support half rate speech version 1"; break;
                case 2: str = "MS supports at least full rate speech version 1 and half rate speech version 1. MS has a greater preference for half rate speech version 1 than for full rate speech version 1"; break;
                case 3: str = "MS supports at least full rate speech version 1 and half rate speech version 1. MS has a greater preference for full rate speech version 1 than for half rate speech version 1"; break;
                default:
                    str = "Reserved";
                    break;
                }
            }
            else
            {
                switch ((oct & 0x60) >> 5)
                {
                case 1: str = "Full rate support only MS/fullrate speech version 1 supported"; break;
                case 2: str = "Dual rate support MS/half rate speech version 1 preferred, full rate speech version 1 also supported"; break;
                case 3: str = "Dual rate support MS/full rate speech version 1 preferred, half rate speech version 1 also supported"; break;
                default:
                    str = "Reserved";
                    break;
                }
            }
            break;

        default:
            switch ((oct & 0x60) >> 5)
            {
            case 1: str = "Full rate support only MS"; break;
            case 2: str = "Dual rate support MS/half rate preferred"; break;
            case 3: str = "Dual rate support MS/full rate preferred"; break;
            default:
                str = "Reserved";
                break;
            }
            break;
        }
        break;

        default:
            str = "(dissect problem)";
            break;
        }

    proto_tree_add_uint_format_value(subtree, hf_gsm_a_dtap_radio_channel_requirement, tvb, curr_offset, 1,
                                     oct, "%s", str);

    proto_tree_add_item(subtree, hf_gsm_a_dtap_bearer_cap_coding_standard, tvb, curr_offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_gsm_a_dtap_transfer_mode, tvb, curr_offset, 1, ENC_NA);

    proto_tree_add_item(subtree, hf_gsm_a_dtap_itc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    if (add_string)
        g_snprintf(add_string, string_len, " - (%s)", str);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    switch (itc)
    {
    case DE_BC_ITC_SPEECH:
        /* octets 3a */

        subtree =
            proto_tree_add_subtree(tree,
                tvb, curr_offset, -1, ett_bc_oct_3a, &item,
                "Octets 3a - Speech Versions");

        saved_offset = curr_offset;

        do
        {
            oct = tvb_get_guint8(tvb, curr_offset);

            extended = (oct & 0x80) ? FALSE : TRUE;

            proto_tree_add_item(subtree, hf_gsm_a_extension, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree, hf_gsm_a_dtap_coding, tvb, curr_offset, 1, ENC_NA);
            proto_tree_add_bits_item(subtree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3)+2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree, hf_gsm_a_dtap_speech_vers_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            curr_offset++;
        }
        while (extended &&
            ((len - (curr_offset - offset)) > 0));

        proto_item_set_len(item, curr_offset - saved_offset);
        break;

        default:
        /* octet 4 */

        subtree =
            proto_tree_add_subtree(tree,
                tvb, curr_offset, 1,
                ett_bc_oct_4, NULL, "Octet 4");

        proto_tree_add_item(subtree, hf_gsm_a_extension, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, is_uplink ? hf_gsm_a_dtap_compression_up : hf_gsm_a_dtap_compression,
            tvb, curr_offset, 1, ENC_NA);

        proto_tree_add_item(subtree, hf_gsm_a_dtap_structure, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_gsm_a_dtap_duplex_mode, tvb, curr_offset, 1, ENC_NA);
        proto_tree_add_item(subtree, hf_gsm_a_dtap_configuration, tvb, curr_offset, 1, ENC_NA);
        proto_tree_add_item(subtree, hf_gsm_a_dtap_nirr, tvb, curr_offset, 1, ENC_NA);
        proto_tree_add_item(subtree, hf_gsm_a_dtap_establishment, tvb, curr_offset, 1, ENC_NA);
        curr_offset++;

    NO_MORE_DATA_CHECK(len);

    /* octet 5 */

    subtree =
        proto_tree_add_subtree(tree,
        tvb, curr_offset, 1,
        ett_bc_oct_5, NULL, "Octet 5");

    oct = tvb_get_guint8(tvb, curr_offset);

    extended = (oct & 0x80) ? FALSE : TRUE;

    proto_tree_add_item(subtree, hf_gsm_a_extension, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_a_dtap_access_identity, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_a_dtap_rate_adaption, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_a_dtap_signalling_access_protocol, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    if (!extended) goto bc_octet_6;

    /* octet 5a */

    subtree =
        proto_tree_add_subtree(tree,
        tvb, curr_offset, 1,
        ett_bc_oct_5a, NULL, "Octet 5a");

    oct = tvb_get_guint8(tvb, curr_offset);

    extended = (oct & 0x80) ? FALSE : TRUE;

    proto_tree_add_item(subtree, hf_gsm_a_extension, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_a_dtap_other_itc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_a_dtap_other_rate_adaption, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3)+5, 3, ENC_BIG_ENDIAN);
    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    if (!extended) goto bc_octet_6;

    /* octet 5b */

    subtree =
        proto_tree_add_subtree(tree,
        tvb, curr_offset, 1,
        ett_bc_oct_5b, NULL, "Octet 5b");

    proto_tree_add_item(subtree, hf_gsm_a_extension, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_a_dtap_rate_adaption_header, tvb, curr_offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_gsm_a_dtap_multiple_frame_establishment_support, tvb, curr_offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_gsm_a_dtap_mode_of_operation, tvb, curr_offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_gsm_a_dtap_logical_link_identifier_negotiation, tvb, curr_offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_gsm_a_dtap_assignor_assignee, tvb, curr_offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_gsm_a_dtap_in_out_band, tvb, curr_offset, 1, ENC_NA);
    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3)+7, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

bc_octet_6:

    /* octet 6 */

    subtree =
        proto_tree_add_subtree(tree,
        tvb, curr_offset, 1,
        ett_bc_oct_6, NULL, "Octet 6");

    oct = tvb_get_guint8(tvb, curr_offset);

    extended = (oct & 0x80) ? FALSE : TRUE;

    proto_tree_add_item(subtree, hf_gsm_a_extension, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_uint_format_value(subtree, hf_gsm_a_dtap_layer_1_identity, tvb, curr_offset, 1, oct,
        "%s", ((oct & 0x60) == 0x20) ? "Octet identifier" : "Reserved");

    proto_tree_add_uint_format_value(subtree, hf_gsm_a_dtap_user_information_layer_1_protocol,
        tvb, curr_offset, 1, oct, "%s",
        (oct & 0x1e) ? "Reserved" : "Default layer 1 protocol");

    proto_tree_add_item(subtree, hf_gsm_a_dtap_synchronous, tvb, curr_offset, 1, ENC_NA);
    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    if (!extended) goto bc_octet_7;

    /* octet 6a */

    subtree =
        proto_tree_add_subtree(tree,
        tvb, curr_offset, 1,
        ett_bc_oct_6a, NULL, "Octet 6a");

    oct = tvb_get_guint8(tvb, curr_offset);

    extended = (oct & 0x80) ? FALSE : TRUE;

    proto_tree_add_item(subtree, hf_gsm_a_extension, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_a_dtap_number_of_stop_bits, tvb, curr_offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_gsm_a_dtap_negotiation, tvb, curr_offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_gsm_a_dtap_number_of_data_bits, tvb, curr_offset, 1, ENC_NA);

    proto_tree_add_uint_format_value(subtree, hf_gsm_a_dtap_user_rate,
        tvb, curr_offset, 1, oct, "%s", val_to_str_const(oct & 0xF, gsm_a_dtap_user_rate_vals, "Reserved"));

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    if (!extended) goto bc_octet_7;

    /* octet 6b */

    subtree =
        proto_tree_add_subtree(tree,
        tvb, curr_offset, 1,
        ett_bc_oct_6b, NULL, "Octet 6b");

    oct = tvb_get_guint8(tvb, curr_offset);

    extended = (oct & 0x80) ? FALSE : TRUE;

    proto_tree_add_item(subtree, hf_gsm_a_extension, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_a_dtap_v110_x30_rate_adaptation, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_a_dtap_nic_on_tx, tvb, curr_offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_gsm_a_dtap_nic_on_rx, tvb, curr_offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_gsm_a_dtap_parity_information, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    if (!extended) goto bc_octet_7;

    /* octet 6c */

    subtree =
        proto_tree_add_subtree(tree,
        tvb, curr_offset, 1,
        ett_bc_oct_6c, NULL, "Octet 6c");

    oct = tvb_get_guint8(tvb, curr_offset);

    extended = (oct & 0x80) ? FALSE : TRUE;

    proto_tree_add_item(subtree, hf_gsm_a_extension, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_a_dtap_connection_element, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_uint_format_value(subtree, hf_gsm_a_dtap_modem_type, tvb, curr_offset, 1,
        oct, "%s", val_to_str_const(oct & 0x1f, gsm_a_dtap_modem_type_vals, "Reserved"));

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    if (!extended) goto bc_octet_7;

    /* octet 6d */

    subtree =
        proto_tree_add_subtree(tree,
        tvb, curr_offset, 1,
        ett_bc_oct_6d, NULL, "Octet 6d");

    oct = tvb_get_guint8(tvb, curr_offset);

    extended = (oct & 0x80) ? FALSE : TRUE;

    proto_tree_add_item(subtree, hf_gsm_a_extension, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_a_dtap_other_modem_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_uint_format_value(subtree, hf_gsm_a_dtap_fixed_network_user_rate, tvb, curr_offset, 1,
        oct, "%s", val_to_str_const(oct & 0x1f, gsm_a_dtap_fixed_network_user_rate_vals, "Reserved"));
    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    if (!extended) goto bc_octet_7;

    /* octet 6e */

    subtree =
        proto_tree_add_subtree(tree,
        tvb, curr_offset, 1,
        ett_bc_oct_6e, NULL, "Octet 6e");

    oct = tvb_get_guint8(tvb, curr_offset);

    extended = (oct & 0x80) ? FALSE : TRUE;

    proto_tree_add_item(subtree, hf_gsm_a_extension, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    if (is_uplink == IS_UPLINK_TRUE)
    {
        proto_tree_add_item(subtree, hf_gsm_a_dtap_acceptable_channel_codings_TCH_F14_4, tvb, curr_offset, 1, ENC_NA);
        proto_tree_add_item(subtree, hf_gsm_a_dtap_acceptable_channel_codings_spare20, tvb, curr_offset, 1, ENC_NA);
        proto_tree_add_item(subtree, hf_gsm_a_dtap_acceptable_channel_codings_TCH_F9_6, tvb, curr_offset, 1, ENC_NA);
        proto_tree_add_item(subtree, hf_gsm_a_dtap_acceptable_channel_codings_TCH_F4_8, tvb, curr_offset, 1, ENC_NA);

        proto_tree_add_uint_format_value(subtree, hf_gsm_a_dtap_maximum_number_of_traffic_channels, tvb, curr_offset, 1,
            (oct & 0x07) + 1, "%u TCH", (oct & 0x07) + 1);
    }
    else
    {
        proto_tree_add_uint_format_value(subtree, hf_gsm_a_dtap_acceptable_channel_codings_spare78, tvb, curr_offset, 1,
            oct, "Spare");
        proto_tree_add_uint_format_value(subtree, hf_gsm_a_dtap_maximum_number_of_traffic_channels, tvb, curr_offset, 1,
            oct, "Spare");
    }

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    if (!extended) goto bc_octet_7;

    /* octet 6f */

    subtree =
        proto_tree_add_subtree(tree,
        tvb, curr_offset, 1,
        ett_bc_oct_6f, NULL, "Octet 6f");

    oct = tvb_get_guint8(tvb, curr_offset);

    extended = (oct & 0x80) ? FALSE : TRUE;

    proto_tree_add_item(subtree, hf_gsm_a_extension, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_a_dtap_uimi, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    if (is_uplink == IS_UPLINK_TRUE)
    {
        proto_tree_add_item(subtree, hf_gsm_a_dtap_wanted_air_interface_user_rate, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    }
    else
    {
        proto_tree_add_uint_format_value(subtree, hf_gsm_a_dtap_wanted_air_interface_user_rate, tvb, curr_offset, 1,
            oct, "Spare");
    }

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    if (!extended) goto bc_octet_7;

    /* octet 6g */

    subtree =
        proto_tree_add_subtree(tree,
        tvb, curr_offset, 1,
        ett_bc_oct_6g, NULL, "Octet 6g");

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_item(subtree, hf_gsm_a_extension, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    if (is_uplink == IS_UPLINK_TRUE)
    {
        proto_tree_add_item(subtree, hf_gsm_a_dtap_acceptable_channel_codings_ext_TCH_F28_8, tvb, curr_offset, 1, ENC_NA);
        proto_tree_add_item(subtree, hf_gsm_a_dtap_acceptable_channel_codings_ext_TCH_F32_0, tvb, curr_offset, 1, ENC_NA);
        proto_tree_add_item(subtree, hf_gsm_a_dtap_acceptable_channel_codings_ext_TCH_F43_2, tvb, curr_offset, 1, ENC_NA);
        proto_tree_add_item(subtree, hf_gsm_a_dtap_channel_coding_asymmetry_indication, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    }
    else
    {
        proto_tree_add_uint_format_value(subtree, hf_gsm_a_dtap_edge_channel_codings, tvb, curr_offset, 1, oct, "Spare");
    }

    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3)+6, 2, ENC_BIG_ENDIAN);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

bc_octet_7:
    /* octet 7 */

    subtree =
        proto_tree_add_subtree(tree,
        tvb, curr_offset, 1,
        ett_bc_oct_7, NULL, "Octet 7");

    proto_tree_add_item(subtree, hf_gsm_a_extension, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_uint_format_value(subtree, hf_gsm_a_dtap_layer_2_identity, tvb, curr_offset, 1, oct,
        "%s", ((oct & 0x60) == 0x40) ? "Octet identifier" : "Reserved");

    proto_tree_add_uint_format_value(subtree, hf_gsm_a_dtap_user_information_layer_2_protocol, tvb, curr_offset, 1,
        oct, "%s", val_to_str_const(oct & 0x1F, gsm_a_dtap_user_info_layer2_vals, "Reserved"));
    break;
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_dtap_extraneous_data);

    return (curr_offset - offset);
}


guint16
de_bearer_cap_uplink(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string, int string_len)
{
    is_uplink = IS_UPLINK_TRUE;
    return de_bearer_cap(tvb, tree, pinfo, offset, len, add_string, string_len);

}

/*
 * [9] 10.5.4.5a Call Control Capabilities
 */
const true_false_string gsm_a_dtap_mcat_value = {
    "The mobile station supports Multimedia CAT during the alerting phase of a mobile originated multimedia call establishment",
    "The mobile station does not support Multimedia CAT"
};

const true_false_string gsm_a_dtap_enicm_value = {
    "The mobile station supports the Enhanced Network-initiated In-Call Modification procedure",
    "The mobile station does not support the Enhanced Network-initiated In-Call Modification procedure"
};

const true_false_string gsm_a_dtap_dtmf_value = {
    "the mobile station supports DTMF as specified in subclause 5.5.7 of TS 24.008",
    "reserved for earlier versions of the protocol"
};

static guint16
de_cc_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_) {
    guint8  oct;
    guint32 curr_offset;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    if (((oct & 0xf0) >> 4) == 0)
    {
        proto_tree_add_uint_format_value(tree, hf_gsm_a_dtap_maximum_number_of_supported_bearers, tvb, curr_offset, 1, 0, "1");
    }
    else
    {
        proto_tree_add_item(tree, hf_gsm_a_dtap_maximum_number_of_supported_bearers, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    }

    proto_tree_add_item(tree, hf_gsm_a_dtap_mcat, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_dtap_enicm, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_dtap_pcp, tvb, curr_offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_gsm_a_dtap_dtmf, tvb, curr_offset, 1, ENC_NA);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, curr_offset<<3, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_dtap_max_num_of_speech_bearers, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_dtap_extraneous_data);

    return (curr_offset - offset);
}

/*
 * [3] 10.5.4.6 Call state
 */
static const value_string gsm_a_dtap_coding_standard_vals[] = {
    { 0x00, "standardized coding as described in ITU-T Rec. Q.931" },
    { 0x01, "reserved for other international standards" },
    { 0x02, "national standard" },
    { 0x03, "standard defined for the GSM PLMNS as described below" },
    { 0, NULL }
};

static const value_string gsm_a_dtap_call_state_vals[] = {
    { 0x00, "U0/N0 - null" },
    { 0x02, "U0.1/N0.1 - MM connection pending" },
    { 0x22, "U0.2 - CC prompt present / N0.2 - CC connection pending" },
    { 0x23, "U0.3 - Wait for network information / N0.3 - Network answer pending" },
    { 0x24, "U0.4/N0.4 - CC-Establishment present" },
    { 0x25, "U0.5/N0.5 - CC-Establishment confirmed" },
    { 0x26, "U0.6/N0.6 - Recall present" },
    { 0x01, "U1/N1 - call initiated" },
    { 0x03, "U3/N3 - mobile originating call proceeding" },
    { 0x04, "U4/N4 - call delivered" },
    { 0x06, "U6/N6 - call present" },
    { 0x07, "U7/N7 - call received" },
    { 0x08, "U8/N8 - connect request" },
    { 0x09, "U9/N9 - mobile terminating call confirmed" },
    { 0x0a, "U10/N10 - active" },
    { 0x0b, "U11 - disconnect request" },
    { 0x0c, "U12/N12 - disconnect indication" },
    { 0x13, "U19/N19 - release request" },
    { 0x1a, "U26/N26 - mobile originating modify" },
    { 0x1b, "U27/N27 - mobile terminating modify" },
    { 0x1c, "N28 - connect indication" },
    { 0, NULL }
};

static guint16
de_call_state(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint8      oct, coding_standard, call_state;
    proto_tree *subtree;

    subtree =
    proto_tree_add_subtree(tree,
        tvb, offset, 1, ett_gsm_dtap_elem[DE_CALL_STATE], NULL,
        val_to_str_ext_const(DE_CALL_STATE, &gsm_dtap_elem_strings_ext, ""));

    proto_tree_add_item(subtree, hf_gsm_a_dtap_coding_standard, tvb, offset, 1, ENC_BIG_ENDIAN);

    oct = tvb_get_guint8(tvb, offset);
    coding_standard = (oct & 0xc0) >> 6;
    call_state = oct & 0x3f;

    switch (coding_standard)
    {
    case 0:
        proto_tree_add_uint_format_value(subtree, hf_gsm_a_dtap_call_state, tvb,
                offset, 1, call_state, "%s (%u)",
                val_to_str_ext_const(call_state, &q931_call_state_vals_ext, "Reserved"),
                call_state);
        break;
    case 1:
    case 2:
        proto_tree_add_item(subtree, hf_gsm_a_dtap_call_state, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    default:
        proto_tree_add_uint_format_value(subtree, hf_gsm_a_dtap_call_state, tvb,
                offset, 1, call_state, "%s (%u)",
                val_to_str_const(call_state, gsm_a_dtap_call_state_vals, "Reserved"),
                call_state);
        break;
    }

    /* no length check possible */

    return (1);
}

/*
 * Helper function for BCD address decoding
 */
const value_string gsm_a_dtap_type_of_number_values[] = {
    { 0x00, "unknown" },
    { 0x01, "International Number" },
    { 0x02, "National number" },
    { 0x03, "Network Specific Number" },
    { 0x04, "Dedicated access, short code" },
    { 0x05, "Reserved" },
    { 0x06, "Reserved" },
    { 0x07, "Reserved for extension" },
    { 0, NULL }
};

const value_string gsm_a_dtap_numbering_plan_id_values[] = {
    { 0x00, "unknown" },
    { 0x01, "ISDN/Telephony Numbering (ITU-T Rec. E.164 / ITU-T Rec. E.163)" },
    { 0x02, "spare" },
    { 0x03, "Data Numbering (ITU-T Rec. X.121)" },
    { 0x04, "Telex Numbering (ITU-T Rec. F.69)" },
    { 0x08, "National Numbering" },
    { 0x09, "Private Numbering" },
    { 0x0d, "Reserved for CTS (see 3GPP TS 44.056)" },
    { 0x0f, "Reserved for extension" },
    { 0, NULL }
};

const value_string gsm_a_dtap_present_ind_values[] = {
    { 0x00, "Presentation allowed" },
    { 0x01, "Presentation restricted" },
    { 0x02, "Number not available due to interworking" },
    { 0x03, "Reserved" },
    { 0, NULL }
};

const value_string gsm_a_dtap_screening_ind_values[] = {
    { 0x00, "User-provided, not screened" },
    { 0x01, "User-provided, verified and passed" },
    { 0x02, "User-provided, verified and failed" },
    { 0x03, "Network provided" },
    { 0, NULL }
};

static guint16
de_bcd_num(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, int header_field, const gchar **extracted_address)
{
    guint8      extension;
    guint32     curr_offset, num_string_len;
    proto_item *item;

    *extracted_address = NULL;
    curr_offset = offset;

    extension = tvb_get_guint8(tvb, curr_offset) & 0x80;
    proto_tree_add_item(tree, hf_gsm_a_extension, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_dtap_type_of_number, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_dtap_numbering_plan_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    if (!extension)
    {
        proto_tree_add_item(tree, hf_gsm_a_extension, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_gsm_a_dtap_present_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3)+3, 3, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_gsm_a_dtap_screening_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset++;
    }

    NO_MORE_DATA_CHECK(len);

    num_string_len = len - (curr_offset - offset);

    *extracted_address = tvb_bcd_dig_to_wmem_packet_str(tvb, curr_offset, num_string_len, &Dgt_mbcd, FALSE);
    item = proto_tree_add_string(tree, header_field, tvb, curr_offset, num_string_len, *extracted_address);

    /* Check for an end mark, which gets mapped to '?' */
    if(strchr(*extracted_address,'?')){
        expert_add_info(pinfo, item, &ei_gsm_a_dtap_end_mark_unexpected);
    }

    return (len);
}

/*
 * Helper function for sub address decoding
 */
const value_string gsm_a_dtap_type_of_sub_addr_values[] = {
    { 0x00, "NSAP (ITU-T Rec. X.213/ISO 8348 AD2)" },
    { 0x02, "User specified" },
    { 0, NULL }
};

const value_string gsm_a_dtap_odd_even_ind_values[] = {
    { 0x00, "even number of address signals" },
    { 0x01, "odd number of address signals" },
    { 0, NULL }
};


static guint16
de_sub_addr(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar **extracted_address)
{
    guint32     curr_offset, ia5_string_len, i;
    guint8      type_of_sub_addr, afi, dig1, dig2, oct;
    gchar      *ia5_string;
    gboolean    invalid_ia5_char;
    proto_item *item;

    curr_offset = offset;

    *extracted_address = NULL;
    proto_tree_add_item(tree, hf_gsm_a_extension, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_dtap_type_of_sub_addr, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_dtap_odd_even_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3)+5, 3, ENC_BIG_ENDIAN);
    type_of_sub_addr = (tvb_get_guint8(tvb, curr_offset) & 0x70) >> 4;
    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    if (!type_of_sub_addr)
    {
        afi = tvb_get_guint8(tvb, curr_offset);
        proto_tree_add_item(tree, hf_gsm_a_dtap_afi, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset++;

        NO_MORE_DATA_CHECK(len);

        if (afi == 0x50)
        {
            ia5_string_len = len - (curr_offset - offset);
            ia5_string = (guint8 *)tvb_memdup(wmem_packet_scope(), tvb, curr_offset, ia5_string_len);
            *extracted_address = (gchar *)wmem_alloc(wmem_packet_scope(), ia5_string_len);

            invalid_ia5_char = FALSE;
            for(i = 0; i < ia5_string_len; i++)
            {
                dig1 = (ia5_string[i] & 0xf0) >> 4;
                dig2 = ia5_string[i] & 0x0f;
                oct = (dig1 * 10) + dig2 + 32;
                if (oct > 127)
                    invalid_ia5_char = TRUE;
                ia5_string[i] = oct;

            }

            IA5_7BIT_decode(*extracted_address, ia5_string, ia5_string_len);

            item = proto_tree_add_string(tree, hf_gsm_a_dtap_subaddress, tvb, curr_offset, len - (curr_offset - offset), *extracted_address);

            if (invalid_ia5_char)
                expert_add_info(pinfo, item, &ei_gsm_a_dtap_invalid_ia5_character);

            return (len);
        }
    }

    proto_tree_add_item(tree, hf_gsm_a_dtap_subaddress_information, tvb, curr_offset, len - (curr_offset - offset), ENC_NA);

    return (len);
}

/*
 * [3] 10.5.4.7 Called party BCD number
 */
guint16
de_cld_party_bcd_num(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string, int string_len)
{
    const gchar *extr_addr;

    de_bcd_num(tvb, tree, pinfo, offset, len, hf_gsm_a_dtap_cld_party_bcd_num, &extr_addr);

    if (extr_addr) {
        if (sccp_assoc && ! sccp_assoc->called_party) {
            sccp_assoc->called_party = wmem_strdup(wmem_file_scope(), extr_addr);
        }

        if (add_string)
            g_snprintf(add_string, string_len, " - (%s)", extr_addr);
    }

    return (len);
}

/*
 * [3] 10.5.4.8 Called party subaddress
 */
static guint16
de_cld_party_sub_addr(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    gchar *extr_addr;

    de_sub_addr(tvb, tree, pinfo, offset, len, &extr_addr);

    if (extr_addr && add_string)
        g_snprintf(add_string, string_len, " - (%s)", extr_addr);

    return (len);
}

/* 3GPP TS 24.008
 * [3] 10.5.4.9 Calling party BCD number
 */
static guint16
de_clg_party_bcd_num(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string, int string_len)
{
    const gchar *extr_addr;

    de_bcd_num(tvb, tree, pinfo, offset, len, hf_gsm_a_dtap_clg_party_bcd_num, &extr_addr);

    if (extr_addr && add_string)
        g_snprintf(add_string, string_len, " - (%s)", extr_addr);

    return (len);
}

/*
 * [3] 10.5.4.10 Calling party subaddress
 */
static guint16
de_clg_party_sub_addr(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    gchar *extr_addr;

    de_sub_addr(tvb, tree, pinfo, offset, len, &extr_addr);

    if (extr_addr && add_string)
        g_snprintf(add_string, string_len, " - (%s)", extr_addr);

    return (len);
}

/*
 * [3] 10.5.4.11 Cause
 */
static const value_string gsm_a_dtap_cause_ss_diagnostics_vals[] = {
    { 0x01, "Outgoing calls barred within CUG" },
    { 0x02, "No CUG selected" },
    { 0x03, "Unknown CUG index" },
    { 0x04, "CUG index incompatible with requested basic service" },
    { 0x05, "CUG call failure, unspecified" },
    { 0x06, "CLIR not subscribed" },
    { 0x07, "CCBS possible" },
    { 0x08, "CCBS not possible" },
    { 0, NULL }
};

static const value_string gsm_a_dtap_de_cause_coding_standard_vals[] = {
    { 0x00, "Coding as specified in ITU-T Rec. Q.931" },
    { 0x01, "Reserved for other international standards" },
    { 0x02, "National standard" },
    { 0x03, "Standard defined for the GSM PLMNS" },
    { 0, NULL }
};

static guint16
de_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8       oct;
    guint8       cause;
    guint32      curr_offset;
    guint32      diag_length;
    proto_tree  *subtree;
    const gchar *str;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_extension, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_dtap_de_cause_coding_standard, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3)+3, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(tree, hf_gsm_a_dtap_location, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    oct = tvb_get_guint8(tvb, curr_offset);

    if (!(oct & 0x80))
    {
    proto_tree_add_item(tree, hf_gsm_a_extension, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_dtap_recommendation, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    oct = tvb_get_guint8(tvb, curr_offset);
    }

    proto_tree_add_item(tree, hf_gsm_a_extension, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    cause = oct & 0x7f;
    switch (cause)
    {
    case   1: str = "Unassigned (unallocated) number";                                    break;
    case   3: str = "No route to destination";                                            break;
    case   6: str = "Channel unacceptable";                                               break;
    case   8: str = "Operator determined barring";                                        break;
    case  16: str = "Normal call clearing";                                               break;
    case  17: str = "User busy";                                                          break;
    case  18: str = "No user responding";                                                 break;
    case  19: str = "User alerting, no answer";                                           break;
    case  21: str = "Call rejected";                                                      break;
    case  22: str = "Call rejected due to feature at the destination";                    break;
    case  24: str = "Number changed";                                                     break;
    case  25: str = "Pre-emption";                                                        break;
    case  26: str = "Non selected user clearing";                                         break;
    case  27: str = "Destination out of order";                                           break;
    case  28: str = "Invalid number format (incomplete number)";                          break;
    case  29: str = "Facility rejected";                                                  break;
    case  30: str = "Response to STATUS ENQUIRY";                                         break;
    case  31: str = "Normal, unspecified";                                                break;
    case  34: str = "No circuit/channel available";                                       break;
    case  38: str = "Network out of order";                                               break;
    case  41: str = "Temporary failure";                                                  break;
    case  42: str = "Switching equipment congestion";                                     break;
    case  43: str = "Access information discarded";                                       break;
    case  44: str = "requested circuit/channel not available";                            break;
    case  47: str = "Resources unavailable, unspecified";                                 break;
    case  49: str = "Quality of service unavailable";                                     break;
    case  50: str = "Requested facility not subscribed";                                  break;
    case  55: str = "Incoming calls barred within the CUG";                               break;
    case  57: str = "Bearer capability not authorized";                                   break;
    case  58: str = "Bearer capability not presently available";                          break;
    case  63: str = "Service or option not available, unspecified";                       break;
    case  65: str = "Bearer service not implemented";                                     break;
    case  68: str = "ACM equal to or greater than ACMmax";                                break;
    case  69: str = "Requested facility not implemented";                                 break;
    case  70: str = "Only restricted digital information bearer capability is available"; break;
    case  79: str = "Service or option not implemented, unspecified";                     break;
    case  81: str = "Invalid transaction identifier value";                               break;
    case  87: str = "User not member of CUG";                                             break;
    case  88: str = "Incompatible destination";                                           break;
    case  91: str = "Invalid transit network selection";                                  break;
    case  95: str = "Semantically incorrect message";                                     break;
    case  96: str = "Invalid mandatory information";                                      break;
    case  97: str = "Message type non-existent or not implemented";                       break;
    case  98: str = "Message type not compatible with protocol state";                    break;
    case  99: str = "Information element non-existent or not implemented";                break;
    case 100: str = "Conditional IE error";                                               break;
    case 101: str = "Message not compatible with protocol state";                         break;
    case 102: str = "Recovery on timer expiry";                                           break;
    case 111: str = "Protocol error, unspecified";                                        break;
    case 127: str = "Interworking, unspecified";                                          break;
    default:
        if (cause <= 31) { str = "Treat as Normal, unspecified"; }
        else if ((cause >= 32) && (cause <= 47)) { str = "Treat as Resources unavailable, unspecified"; }
        else if ((cause >= 48) && (cause <= 63)) { str = "Treat as Service or option not available, unspecified"; }
        else if ((cause >= 64) && (cause <= 79)) { str = "Treat as Service or option not implemented, unspecified"; }
        else if ((cause >= 80) && (cause <= 95)) { str = "Treat as Semantically incorrect message"; }
        else if ((cause >= 96) && (cause <= 111)) { str = "Treat as Protocol error, unspecified"; }
        else { str = "Treat as Interworking, unspecified"; }
        break;
    }

    proto_tree_add_uint_format_value(tree, hf_gsm_a_dtap_cause,
        tvb, curr_offset, 1, cause,
        "Cause: (%u) %s",
        cause,
        str);

    curr_offset++;

    if (add_string)
        g_snprintf(add_string, string_len, " - (%u) %s", cause, str);

    NO_MORE_DATA_CHECK(len);

    subtree = proto_tree_add_subtree(tree, tvb, curr_offset, len - (curr_offset - offset),
                                        ett_gsm_dtap_elem[DE_CAUSE], NULL, "Diagnostics");

    /*
     * Diagnostics for supplementary services may be included in the case of
     * the following cause codes:
     *   17 - User busy
     *   29 - Facility rejected
     *   34 - No circuit/channel available
     *   50 - Requested facility not subscribed
     *   55 - Incoming calls barred within the CUG
     *   69 - Requested facility not implemented
     *   87 - User not member of CUG
     */
    if ((cause == 17) || (cause == 29) || (cause == 34) || (cause == 50) ||
        (cause == 55) || (cause == 69) || (cause == 87))
    {
        proto_tree_add_item(subtree, hf_gsm_a_extension, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_gsm_a_dtap_cause_ss_diagnostics, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset++;
    }
    else
    {
        diag_length = len - (curr_offset - offset);
        proto_tree_add_item(subtree, hf_gsm_a_dtap_data, tvb, curr_offset, diag_length, ENC_NA);
        curr_offset += diag_length;
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_dtap_extraneous_data);

    return (curr_offset - offset);
}
/*
 * 10.5.4.11a CLIR suppression
 * No data
 */
/*
 * 10.5.4.11b CLIR invocation
 * No data
 */
/*
 * 10.5.4.12 Congestion level
 *  handled inline
 */
/*
 * 10.5.4.13 Connected number
 */
static guint16
de_conn_num(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string, int string_len)
{
    const gchar *extr_addr;

    de_bcd_num(tvb, tree, pinfo, offset, len, hf_gsm_a_dtap_conn_num, &extr_addr);

    if (extr_addr && add_string)
        g_snprintf(add_string, string_len, " - (%s)", extr_addr);

    return (len);
}

/*
 * 10.5.4.14 Connected subaddress
 */
static guint16
de_conn_sub_addr(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    gchar *extr_addr;

    de_sub_addr(tvb, tree, pinfo, offset, len, &extr_addr);

    if (extr_addr && add_string)
        g_snprintf(add_string, string_len, " - (%s)", extr_addr);

    return (len);
}

/*
 * 10.5.4.15 Facility
 */

static guint16
de_facility(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint fac_len, gchar *add_string _U_, int string_len _U_)
{
    guint        saved_offset;
    gint8        appclass;
    gboolean     pc;
    gboolean     ind           = FALSE;
    guint32      component_len = 0;
    guint32      header_end_offset;
    guint32      header_len;
    asn1_ctx_t   asn1_ctx;
    tvbuff_t    *SS_tvb        = NULL;
    static gint  comp_type_tag;

    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

    saved_offset = offset;
    col_append_str(pinfo->cinfo, COL_PROTOCOL,"/");
    col_set_fence(pinfo->cinfo, COL_PROTOCOL);
    while (fac_len > (offset - saved_offset)) {

        /* Get the length of the component there can be more than one component in a facility message */

        header_end_offset = get_ber_identifier(tvb, offset, &appclass, &pc, &comp_type_tag);
        header_end_offset = get_ber_length(tvb, header_end_offset, &component_len, &ind);
        header_len = header_end_offset - offset;
        component_len = header_len + component_len;
        /*
        dissect_ROS_Component(FALSE, tvb, offset, &asn1_ctx, tree, hf_ROS_component);
        TODO Call gsm map here
        */
        SS_tvb = tvb_new_subset_length(tvb, offset, component_len);
        col_append_str(pinfo->cinfo, COL_INFO,"(GSM MAP) ");
        col_set_fence(pinfo->cinfo, COL_INFO);
        call_dissector(gsm_map_handle, SS_tvb, pinfo, tree);
        offset = offset + component_len;
    }
    return (fac_len);
}
/*
 * 10.5.4.16 High layer compatibility
 */
static guint16
de_hlc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    dissect_q931_high_layer_compat_ie(tvb, offset, len, tree);

    curr_offset = curr_offset + len;
    return (curr_offset - offset);
}

/*
 * [3] 10.5.4.17 Keypad facility
 */
static guint16
de_keypad_facility(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len _U_, gchar *add_string, int string_len)
{
    guint8      keypad_char;
    guint32     curr_offset;
    proto_item *item;

    curr_offset = offset;

    keypad_char = tvb_get_guint8(tvb, curr_offset) & 0x7f;

    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, curr_offset<<3, 1, ENC_BIG_ENDIAN);

    item = proto_tree_add_uint_format_value(tree, hf_gsm_a_dtap_keypad_information, tvb, curr_offset, 1,
        keypad_char, "%c", keypad_char);

    if (((keypad_char < '0') || (keypad_char > '9')) &&
        ((keypad_char < 'A') || (keypad_char > 'D')) &&
        (keypad_char != '*') && (keypad_char != '#'))
        expert_add_info(pinfo, item, &ei_gsm_a_dtap_keypad_info_not_dtmf_digit);
    curr_offset++;

    if (add_string)
        g_snprintf(add_string, string_len, " - %c", keypad_char);

    /* no length check possible */

    return (curr_offset - offset);
}

/*
 * 10.5.4.18 Low layer compatibility
 */
static guint16
de_llc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    dissect_q931_bearer_capability_ie(tvb, offset, len, tree);

    curr_offset = curr_offset + len;
    return (curr_offset - offset);
}

/*
 * 10.5.4.19 More data
 * No data
 */
/*
 * 10.5.4.20 Notification indicator
 */
static const value_string gsm_a_dtap_notification_description_vals[] = {
    { 0x00, "User suspended" },
    { 0x01, "User resumed" },
    { 0x02, "Bearer change" },
    { 0, NULL }
};

static guint16
de_notif_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_item(tree, hf_gsm_a_extension, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_dtap_notification_description, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 1;
}
/*
 * [3] 10.5.4.21 Progress indicator
 */
static const value_string gsm_a_dtap_location_vals[] = {
    { 0x00, "User" },
    { 0x01, "Private network serving the local user" },
    { 0x02, "Public network serving the local user" },
    { 0x03, "Transit network" },
    { 0x04, "Public network serving the remote user" },
    { 0x05, "Private network serving the remote user" },
    { 0x07, "International network" },
    { 0x0a, "Network beyond interworking point" },
    { 0, NULL }
};

static const value_string gsm_a_dtap_progress_description_vals[] = {
    { 0x01, "Call is not end-to-end PLMN/ISDN, further call progress information may be available in-band" },
    { 0x02, "Destination address in non-PLMN/ISDN" },
    { 0x03, "Origination address in non-PLMN/ISDN" },
    { 0x04, "Call has returned to the PLMN/ISDN" },
    { 0x08, "In-band information or appropriate pattern now available" },
    { 0x09, "In-band multimedia CAT available" },
    { 0x20, "Call is end-to-end PLMN/ISDN" },
    { 0x40, "Queueing" },
    { 0, NULL }
};

static guint16
de_prog_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint8  oct, coding_standard, progress_description;
    guint32 curr_offset;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);
    coding_standard = (oct & 0x60) >> 5;
    proto_tree_add_item(tree, hf_gsm_a_extension, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_dtap_prog_coding_standard, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset << 3) + 3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_dtap_location, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    oct = tvb_get_guint8(tvb, curr_offset);
    progress_description = oct & 0x7f;
    proto_tree_add_item(tree, hf_gsm_a_extension, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    switch (coding_standard)
    {
    case 0:
        proto_tree_add_uint_format_value(tree, hf_gsm_a_dtap_progress_description, tvb,
                curr_offset, 1, progress_description, "%s (%u)",
                val_to_str_ext_const(progress_description, &q931_progress_description_vals_ext, "Reserved"),
                progress_description);
        break;
    case 1:
    case 2:
        proto_tree_add_item(tree, hf_gsm_a_dtap_progress_description, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        break;
    default:
        proto_tree_add_uint_format_value(tree, hf_gsm_a_dtap_progress_description, tvb,
                curr_offset, 1, progress_description, "%s (%u)",
                val_to_str_const(progress_description, gsm_a_dtap_progress_description_vals, "Unspecific"),
                progress_description);
        break;
    }
    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_dtap_extraneous_data);

    return (curr_offset - offset);
}

/*
 * 10.5.4.21a Recall type $(CCBS)$
 */
static const range_string gsm_a_dtap_recall_type_vals[] = {
    { 0x00, 0x00, "CCBS" },
    { 0x01, 0x06, "shall be treated as CCBS (intended for other similar type of Recall)" },
    { 0, 0, NULL }
};

static guint16
de_recall_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (offset<<3), 5, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_dtap_recall_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    return (1);
}

/*
 * 10.5.4.21b Redirecting party BCD number
 */
static guint16
de_red_party_bcd_num(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string, int string_len)
{
    const gchar *extr_addr;

    de_bcd_num(tvb, tree, pinfo, offset, len, hf_gsm_a_dtap_red_party_bcd_num, &extr_addr);

    if (extr_addr && add_string)
        g_snprintf(add_string, string_len, " - (%s)", extr_addr);

    return (len);
}

/*
 * 10.5.4.21c Redirecting party subaddress
 */
static guint16
de_red_party_sub_addr(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    gchar *extr_addr;

    de_sub_addr(tvb, tree, pinfo, offset, len, &extr_addr);

    if (extr_addr && add_string)
        g_snprintf(add_string, string_len, " - (%s)", extr_addr);

    return (len);
}

/*
 * [3] 10.5.4.22 Repeat indicator
 */
static const value_string gsm_a_dtap_repeat_indicator_vals[] = {
    { 0x01, "Circular for successive selection 'mode 1 alternate mode 2'" },
    { 0x02, "Support of fallback mode 1 preferred, mode 2 selected if setup of mode 1 fails" },
    { 0x03, "Reserved: was allocated in earlier phases of the protocol" },
    { 0, NULL }
};

static guint16
de_repeat_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint8  oct;
    guint32 curr_offset;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_uint_format_value(tree, hf_gsm_a_dtap_repeat_indicator, tvb, curr_offset, 1, oct,
        "%s", val_to_str_const(oct & 0xF, gsm_a_dtap_repeat_indicator_vals, "Reserved"));
    curr_offset++;

    /* no length check possible */

    return (curr_offset - offset);
}
/*
 * 10.5.4.22a Reverse call setup direction
 * No data
 */
/*
 * 10.5.4.22b SETUP Container $(CCBS)$
 */
static void
dtap_cc_setup(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len);

static guint16
de_setup_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    dtap_cc_setup(tvb, tree, pinfo, offset, len);

    return (len);
}

/*
 * 10.5.4.23 Signal
 */
static const value_string gsm_a_dtap_signal_value_vals[] = {
    { 0x00, "dial tone on" },
    { 0x01, "ring back tone on" },
    { 0x02, "intercept tone on" },
    { 0x03, "network congestion tone on" },
    { 0x04, "busy tone on" },
    { 0x05, "confirm tone on" },
    { 0x06, "answer tone on" },
    { 0x07, "call waiting tone on" },
    { 0x08, "off-hook warning tone on" },
    { 0x3f, "tones off" },
    { 0x4f, "alerting off" },
    { 0, NULL }
};

static guint16
de_signal(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_item(tree, hf_gsm_a_dtap_signal_value, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 1;
}

/*
 * 10.5.4.24 SS Version Indicator
 */
static const value_string gsm_a_dtap_ss_ver_ind_vals[] = {
    { 0x00, "Phase 2 service, ellipsis notation, and phase 2 error handling is supported" },
    { 0x01, "SS-Protocol version 3 is supported, and phase 2 error handling is supported" },
    { 0, NULL }
};

static guint16
de_ss_ver_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint8       oct;
    guint32      curr_offset;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_uint_format_value(tree, hf_gsm_a_dtap_ss_version_indicator, tvb, curr_offset, 1,
        oct, "%s", val_to_str_const(oct, gsm_a_dtap_ss_ver_ind_vals, "Reserved"));
    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_dtap_extraneous_data);

    return (curr_offset - offset);
}
/*
 * 10.5.4.25 User-user
 */
/*
User-user protocol discriminator (octet 3)
Bits
8   7   6   5   4   3   2   1
0   0   0   0   0   0   0   0       User specific protocol (Note 1)
0   0   0   0   0   0   0   1       OSI high layer protocols
0   0   0   0   0   0   1   0       X.244 (Note 2)
0   0   0   0   0   0   1   1       Reserved for system management convergence function
0   0   0   0   0   1   0   0       IA5 characters (Note 3)
0   0   0   0   0   1   1   1       Rec.V.120 rate adaption
0   0   0   0   1   0   0   0       Q.931 (I.451) user-network call control messages

0   0   0   1   0   0   0   0       Reserved for other network layer or
through     layer 3 protocols
0   0   1   1   1   1   1   1

0   1   0   0   0   0   0   0
through     National use
0   1   0   0   1   1   1   0
0   1   0   0   1   1   1   1       3GPP capability exchange protocol (NOTE 4)

0   1   0   1   0   0   0   0       Reserved for other network
through     layer or layer 3 protocols
1   1   1   1   1   1   1   0

All other values are reserved.
*/
static const range_string gsm_a_dtap_u2u_prot_discr_vals[] = {
    { 0x00, 0x00, "User specific protocol" },
    { 0x01, 0x01, "OSI high layer protocols" },
    { 0x02, 0x02, "X.244" },
    { 0x03, 0x03, "Reserved for system management convergence function" },
    { 0x04, 0x04, "IA5 characters" },
    { 0x07, 0x07, "Rate adaption according to ITU-T Rec. V.120" },
    { 0x08, 0x08, "User-network call control messages according to ITU-T Rec. Q.931" },
    { 0x10, 0x3F, "Reserved for other network layer or layer 3 protocols" },
    { 0x40, 0x4E, "National use" },
    { 0x4F, 0x4F, "3GPP capability exchange protocol" },
    { 0x50, 0xFE, "Reserved for other network layer or layer 3 protocols" },
    { 0, 0, NULL }
};

static guint16
de_u2u(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32     curr_offset;
    guint32     proto_discr;
    proto_tree *subtree;
    tvbuff_t   *u2u_tvb;

    curr_offset = offset;
    proto_tree_add_item_ret_uint(tree, hf_gsm_a_dtap_u2u_prot_discr, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &proto_discr);
    curr_offset++;

    subtree = proto_tree_add_subtree(tree, tvb, curr_offset, len - 1, ett_gsm_dtap_elem[DE_USER_USER], NULL, "User-user information");
    proto_tree_add_item(subtree, hf_gsm_a_dtap_data, tvb, curr_offset, len - 1, ENC_NA);

    u2u_tvb = tvb_new_subset_length(tvb, curr_offset, len - 1);
    dissector_try_uint_new(u2u_dissector_table, proto_discr, u2u_tvb, pinfo, proto_tree_get_root(tree), TRUE, NULL);


    return (len);
}
/*
 * 10.5.4.26 Alerting Pattern $(NIA)$
 */
static const value_string gsm_a_alerting_pattern_vals[] = {
    { 0x00, "Alerting Pattern 1" },
    { 0x01, "Alerting Pattern 2" },
    { 0x02, "Alerting Pattern 3" },
    { 0x04, "Alerting Pattern 5" },
    { 0x05, "Alerting Pattern 6" },
    { 0x06, "Alerting Pattern 7" },
    { 0x07, "Alerting Pattern 8" },
    { 0x08, "Alerting Pattern 9" },
    { 0, NULL }
};

static guint16
de_alert_pat(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset << 3), 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_dtap_alerting_pattern, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_dtap_extraneous_data);

    return (len);
}
/*
 * 10.5.4.27 Allowed actions $(CCBS)$
 */
const true_false_string gsm_a_ccbs_activation_value = {
    "Activation of CCBS possible",
    "Activation of CCBS not possible"
};
static guint16
de_allowed_act(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_dtap_ccbs_activation, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset << 3) + 1, 7, ENC_BIG_ENDIAN);

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_dtap_extraneous_data);

    return (len);
}
/*
 * 10.5.4.28 Stream Identifier
 */
static guint16
de_stream_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string, int string_len)
{
    guint32 curr_offset;
    guint8 oct;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);
    if (oct == 0x00)
    {
        proto_tree_add_uint_format_value(tree, hf_gsm_a_dtap_stream_identifier, tvb, curr_offset, 1, oct,
            "No Bearer (%u)", oct);

        if (add_string)
            g_snprintf(add_string, string_len, " - (No Bearer)");
    }
    else
    {
        proto_tree_add_item(tree, hf_gsm_a_dtap_stream_identifier, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

        if (add_string)
            g_snprintf(add_string, string_len, " - (%u)", oct);
    }

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_dtap_extraneous_data);

    return (len);
}
/*
 * 10.5.4.29 Network Call Control Capabilities
 */

static const true_false_string gsm_a_mcs_value = {
    "This value indicates that the network supports the multicall",
    "This value indicates that the network does not support the multicall"
};
static guint16
de_nw_call_ctrl_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset << 3), 7, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_dtap_mcs, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_dtap_extraneous_data);

    return (len);
}
/*
 * 10.5.4.30 Cause of No CLI
 */
static const value_string gsm_a_cause_of_no_cli_values[] = {
    { 0x00, "Unavailable" },
    { 0x01, "Reject by user" },
    { 0x02, "Interaction with other service" },
    { 0x03, "Coin line/payphone" },
    { 0, NULL }
};

static guint16
de_ca_of_no_cli(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string, int string_len)
{
    guint32 curr_offset;
    guint8  oct;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);
    proto_tree_add_uint_format_value(tree, hf_gsm_a_dtap_cause_of_no_cli, tvb, curr_offset, 1, oct,
                   "%s (%u)",
                   val_to_str_const(oct, gsm_a_cause_of_no_cli_values, "Unavailable"),
                   oct);

    curr_offset++;

    if (add_string)
        g_snprintf(add_string, string_len, " - (%s)", val_to_str_const(oct, gsm_a_cause_of_no_cli_values, "Unavailable"));

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_dtap_extraneous_data);

    return (len);
}
/*
 * 10.5.4.31 Void
 */
/*
 * 10.5.4.32 Supported codec list
 */
/* 6.1 System Identifiers for GSM and UMTS
 * The system identifiers for the radio access technologies
 * supported by this specification are:
 * SysID for GSM: 0x0000.0000 (bit 8 .. bit 1)
 * SysID for UMTS: 0x0000.0100 (bit 8 .. bit 1)
 * These values are selected in accordance with [7] (3GPP TS 28.062).
 */
static const value_string gsm_a_dtap_sysid_values[] = {
    { 0x0,  "GSM" },
    { 0x4,  "UMTS" },
    { 0, NULL }
};
guint16
de_sup_codec_list(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32     curr_offset;
    guint8      length;
    proto_tree *subtree;
    guint8      sysid_counter;

    curr_offset = offset;

    /*  System Identification 1 (SysID 1) octet 3
     * SysID indicates the radio access technology for which the subsequent Codec
     * Bitmap indicates the supported codec types.
     * Coding of this Octet is defined in 3GPP TS 26.103
     */
    sysid_counter = 0;
    while (len>(curr_offset-offset)) {
        sysid_counter++;
        proto_tree_add_item(tree, hf_gsm_a_dtap_sysid, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset++;
        /*  Length Of Bitmap for SysID */
        proto_tree_add_item(tree, hf_gsm_a_dtap_bitmap_length, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        length = tvb_get_guint8(tvb,curr_offset);
        curr_offset++;
        if (length > 0)
        {
            subtree = proto_tree_add_subtree_format(tree, tvb, curr_offset, length, ett_gsm_dtap_elem[DE_SUP_CODEC_LIST], NULL,
                                                "Codec Bitmap for SysID %u", sysid_counter);
            /* 6.2 Codec Bitmap
             * The Codec Types are coded in the first and second octet of the Codec List
             * Bitmap as follows:
             * 8         7         6        5       4       3       2       bit 1
             * TDMA      UMTS      UMTS     HR AMR  FR AMR  GSM EFR GSM HR  GSM FR Octet 1
             * EFR       AMR 2     AMR
             * bit 16    15        14       13      12      11      10      bit 9
             *(reserved) (reserved)OHR      OFR     OHR     UMTS    FR      PDC EFR Octet 2
             *                     AMR-WB   AMR-WB  AMR     AMR-WB  AMR-WB
             * A Codec Type is supported, if the corresponding bit is set to "1".
             * All reserved bits shall be set to "0".
             *
             * NOTE: If the Codec Bitmap for a SysID is 1 octet, it is an indication that
             * all codecs of the 2nd octet are not supported.
             * If the Codec Bitmap for a SysID is more than 2 octets, the network shall
             * ignore the additional octet(s) of the bitmap and process the rest of the
             * information element.
             *
             * Right now we are sure that at least the first octet of the bitmap is present
             */
            proto_tree_add_item(subtree, hf_gsm_a_dtap_codec_tdma_efr, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree, hf_gsm_a_dtap_codec_umts_amr_2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree, hf_gsm_a_dtap_codec_umts_amr, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree, hf_gsm_a_dtap_codec_hr_amr, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree, hf_gsm_a_dtap_codec_fr_amr, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree, hf_gsm_a_dtap_codec_gsm_efr, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree, hf_gsm_a_dtap_codec_gsm_hr, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree, hf_gsm_a_dtap_codec_gsm_fr, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            curr_offset++;
            length--;

            if (length > 0)
            {
                /*
                 * We can proceed with the second octet of the bitmap
                 */
                proto_tree_add_bits_item(subtree, hf_gsm_a_spare_bits, tvb, curr_offset << 3, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_gsm_a_dtap_codec_ohr_amr_wb, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_gsm_a_dtap_codec_ofr_amr_wb, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_gsm_a_dtap_codec_ohr_amr, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_gsm_a_dtap_codec_umts_amr_wb, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_gsm_a_dtap_codec_fr_amr_wb, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_gsm_a_dtap_codec_pdc_efr, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                curr_offset++;
                length--;
            }
        }

        curr_offset = curr_offset + length;
    }


    return (curr_offset-offset);
}
/*
 * 10.5.4.33 Service category
 */
/*
Emergency Service Category Value (octet 3)
The meaning of the Emergency Category Value is derived from the following settings (see 3GPP TS 22.101 [8] clause
10):
Bit 1 Police
Bit 2 Ambulance
Bit 3 Fire Brigade
Bit 4 Marine Guard
Bit 5 Mountain Rescue
Bit 6 manually initiated eCall
Bit 7 automatically initiated eCall
Bit 8 is spare and set to "0"
*/
guint16
de_serv_cat(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, curr_offset<<3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_dtap_serv_cat_b7, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_dtap_serv_cat_b6, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_dtap_serv_cat_b5, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_dtap_serv_cat_b4, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_dtap_serv_cat_b3, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_dtap_serv_cat_b2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_dtap_serv_cat_b1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    return len;
}
/*
 * 10.5.4.34 Redial
 * No data
 */
/*
 * 10.5.4.35 Network-initiated Service Upgrade indicator
 * No data
 */
/*
 * [5] 8.1.4.1 3GPP TS 24.011 version 6.1.0 Release 6
 */
static guint16
de_cp_user_data(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32   curr_offset;
    tvbuff_t *rp_tvb;

    curr_offset = offset;

    proto_tree_add_bytes_format(tree, hf_gsm_a_dtap_rpdu, tvb, curr_offset, len, NULL, "RPDU (not displayed)");

    /*
     * dissect the embedded RP message
     */
    rp_tvb = tvb_new_subset_length(tvb, curr_offset, len);

    call_dissector(rp_handle, rp_tvb, pinfo, g_tree);

    curr_offset += len;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_dtap_extraneous_data);

    return (curr_offset - offset);
}

/*
 * [5] 8.1.4.2
 */
static const value_string gsm_a_dtap_cp_cause_values[] = {
    { 17, "Network failure"},
    { 22, "Congestion"},
    { 81, "Invalid Transaction Identifier value"},
    { 95, "Semantically incorrect message"},
    { 96, "Invalid mandatory information"},
    { 97, "Message type non-existent or not implemented"},
    { 98, "Message not compatible with the short message protocol state"},
    { 99, "Information element non-existent or not implemented"},
    { 111, "Protocol error, unspecified"},
    { 0, NULL }
};

static guint16
de_cp_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string, int string_len)
{
    guint8       oct;
    guint32      curr_offset;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);
    str = val_to_str_const(oct, gsm_a_dtap_cp_cause_values, "Reserved, treat as Protocol error, unspecified");
    proto_tree_add_uint_format_value(tree, hf_gsm_a_dtap_cp_cause, tvb, curr_offset, 1,
        oct, "(%u) %s", oct, str);
    curr_offset++;

    if (add_string)
        g_snprintf(add_string, string_len, " - (%u) %s", oct, str);

    /* no length check possible */

    return (curr_offset - offset);
}

static const true_false_string tfs_gsm_a_dtap_subchannel = { "Only one TCH active or sub-channel 0 of two half rate channels is to be looped", "Sub-channel 1 of two half rate channels is to be looped" };


static guint16
de_tp_sub_channel(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32      curr_offset;
    guchar       oct;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset) & 0x3f;
    if ((oct & 0x38) == 0x38)
        str = "I";
    else if ((oct & 0x38) == 0x18)
        str = "F";
    else if ((oct & 0x38) == 0x10)
        str = "E";
    else if ((oct & 0x38) == 0x08)
        str = "D";
    else if ((oct & 0x3c) == 0x04)
        str = "C";
    else if ((oct & 0x3e) == 0x02)
        str = "B";
    else if ((oct & 0x3e) == 0x00)
        str = "A";
    else
        str = "unknown";

    proto_tree_add_uint_format_value(tree, hf_gsm_a_dtap_test_loop, tvb, curr_offset, 1, oct, "%s", str);
    proto_tree_add_item(tree, hf_gsm_a_dtap_subchannel, tvb, curr_offset, 1, ENC_NA);
    curr_offset+= 1;

    return (curr_offset - offset);
}

static guint16
de_tp_ack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    guchar  oct;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    if ((oct & 0xF0) == 0x80)
        proto_tree_add_uint(tree, hf_gsm_a_dtap_ack_element, tvb, curr_offset, 1, oct&0x01);
    else
        proto_tree_add_uint_format_value(tree, hf_gsm_a_dtap_ack_element, tvb, curr_offset, 1, 0xFF, "No acknowledgment element present");

    curr_offset+= 1;

    return (curr_offset - offset);
}

static const value_string gsm_channel_coding_vals[] = {
    { 0x00, "not needed. The Burst-by-Burst loop is activated, type G" },
    { 0x01, "Channel coding needed. Frame erasure is to be signalled, type H" },
    { 0x02, "reserved" },
    { 0x03, "reserved" },
    { 0, NULL }
};

static const value_string gsm_a_dtap_loop_mech_vals[] = {
    { 0, "Multi-slot mechanism 1"},
    { 1, "Multi-slot mechanism 2"},
    { 2, "Reserved"},
    { 3, "Reserved"},
    { 4, "Reserved"},
    { 5, "Reserved"},
    { 6, "Reserved"},
    { 7, "Reserved"},
    { 0, NULL }
};

static guint16
de_tp_loop_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    guchar  oct;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_item(tree, hf_gsm_a_dtap_channel_coding03, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_dtap_loop_mechanism1C, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    if ((oct & 0x1c) == 0)
    {
        proto_tree_add_item(tree, hf_gsm_a_dtap_timeslot_number, tvb, curr_offset, 1, ENC_NA);
    }

    curr_offset+= 1;

    return (curr_offset - offset);
}

static const true_false_string tfs_multislot_tch = { "not closed due to error", "closed successfully" };

static guint16
de_tp_loop_ack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_dtap_channel_coding30, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_dtap_loop_mechanism0E, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_dtap_multislot_tch, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset+= 1;

    return (curr_offset - offset);
}

static const value_string gsm_tp_tested_device_vals[] = {
    { 0x00, "Normal operation (no tested device via DAI)" },
    { 0x01, "Test of speech decoder / DTX functions (downlink)" },
    { 0x02, "Test of speech encoder / DTX functions (uplink)" },
    { 0x03, "Test of acoustic devices and A/D & D/A" },
    { 0, NULL }
};

static guint16
de_tp_tested_device(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    guchar  oct;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);
    proto_tree_add_uint_format_value(tree, hf_gsm_a_dtap_tp_tested_device, tvb, curr_offset, 1,
        oct, "%s", val_to_str(oct, gsm_tp_tested_device_vals, "Reserved (%d)"));
    curr_offset+= 1;

    return (curr_offset - offset);
}

static guint16
de_tp_pdu_description(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    guint16 value;

    curr_offset = offset;

    value = tvb_get_ntohs(tvb, curr_offset);
    curr_offset += 2;

    if (value & 0x8000)
    {
        if ((value & 0xfff) == 0)
            proto_tree_add_uint_format_value(tree, hf_gsm_a_dtap_tp_pdu_description,
                tvb, curr_offset, 2, value, "Infinite number of PDUs to be transmitted in the TBF");
        else
            proto_tree_add_uint_format_value(tree, hf_gsm_a_dtap_tp_pdu_description,
                tvb, curr_offset, 2, value & 0xfff, "%d PDUs to be transmitted in the TBF", value & 0xfff);
    }
    else
        proto_tree_add_uint_format_value(tree, hf_gsm_a_dtap_tp_pdu_description,
            tvb, curr_offset, 2, value, "reserved");

    return (curr_offset - offset);
}

static const true_false_string tfs_gsm_a_dtap_mode_flag = { "MS shall select the loop back option", "MS shall itself generate the pseudorandom data" };

static guint16
de_tp_mode_flag(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_dtap_mode_flag, tvb, curr_offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_gsm_a_dtap_downlink_timeslot_offset, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset+= 1;

    return (curr_offset - offset);
}

static const true_false_string tfs_gsm_a_dtap_egprs_mode_flag = { "MS loops back blocks on the uplink using GMSK modulation only",
                                                            "MS loops back blocks on the uplink using either GMSK or 8-PSK modulation following the detected received modulation" };

static guint16
de_tp_egprs_mode_flag(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_dtap_egprs_mode_flag, tvb, curr_offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_gsm_a_dtap_downlink_timeslot_offset, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset+= 1;

    return (curr_offset - offset);
}

static const value_string gsm_positioning_technology_vals[] = {
    { 0x00, "AGPS" },
    { 0x01, "AGNSS" },
    { 0, NULL }
};

static guint16
de_tp_ms_positioning_technology(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    guchar  oct;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);
    proto_tree_add_uint_format_value(tree, hf_gsm_a_dtap_ms_positioning_technology, tvb, curr_offset, 1,
        oct, "%s", val_to_str(oct, gsm_positioning_technology_vals, "Reserved (%d)"));
    curr_offset+= 1;

    return (curr_offset - offset);
}

static const value_string gsm_a_dtap_ue_test_loop_mode_vals[] = {
    { 0, "Mode 1 loop back (loopback of RLC SDUs or PDCP SDUs)"},
    { 1, "Mode 2 loop back (loopback of transport block data and CRC bits)"},
    { 2, "Mode 3 RLC SDU counting (counting of received RLC SDUs)"},
    { 3, "Reserved"},
    { 0, NULL }
};

static guint16
de_tp_ue_test_loop_mode(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    guchar  oct;
    guint8  lb_setup_length,i,j;
    guint16 value;
    proto_tree* subtree;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);
    proto_tree_add_item(tree, hf_gsm_a_dtap_ue_test_loop_mode, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset+= 1;

    switch (oct & 0x03)
    {
    case 0:
    {
        lb_setup_length = tvb_get_guint8(tvb, curr_offset);
        curr_offset += 1;
        for (i=0,j=0; (i<lb_setup_length) && (j<4); i+=3,j++)
        {
            subtree = proto_tree_add_subtree_format(tree, tvb, curr_offset, 3, ett_ue_test_loop_mode, NULL, "LB setup RB IE: %d",j+1);
            value = tvb_get_ntohs(tvb, curr_offset);
            proto_tree_add_uint_format_value(subtree, hf_gsm_a_dtap_uplink_rlc_sdu_size, tvb, curr_offset, 2, value, "%d bits", value);
            curr_offset += 2;
            proto_tree_add_item(subtree, hf_gsm_a_dtap_radio_bearer, tvb, curr_offset, 1, ENC_NA);
            curr_offset+= 1;
        }
        break;
    }
    case 2:
        oct = tvb_get_guint8(tvb, curr_offset);
        curr_offset+= 1;
        proto_tree_add_uint(tree, hf_gsm_a_dtap_mbms_short_transmission_identity, tvb, curr_offset, 1, (oct & 0x1f)+1);
        break;
    }

    return (curr_offset - offset);
}

static guint16
de_tp_ue_positioning_technology(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    guchar  oct;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_uint_format_value(tree, hf_gsm_a_dtap_ue_positioning_technology, tvb, curr_offset, 1,
        oct, "%s", val_to_str(oct, gsm_positioning_technology_vals, "Reserved (%d)"));
    curr_offset+= 1;

    return (curr_offset - offset);
}

static guint16
de_tp_rlc_sdu_counter_value(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_dtap_ue_received_rlc_sdu_counter_value, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
    curr_offset+= 4;


    return (curr_offset - offset);
}

static const value_string epc_ue_test_loop_mode_vals[] = {
    { 0,    "A"},
    { 1,    "B"},
    { 2,    "C"},
    { 3,    "reserved"},
    { 0, NULL }
};
static guint16
de_tp_epc_ue_test_loop_mode(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    guint32 bit_offset;

    curr_offset = offset;
    bit_offset = curr_offset<<3;

    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, bit_offset, 6, ENC_BIG_ENDIAN);
    bit_offset += 6;
    proto_tree_add_bits_item(tree, hf_gsm_a_dtap_epc_ue_tl_mode, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
    /*bit_offset += 2;*/
    /* Store test loop mode to know how to dissect Close UE Test Loop message */
    epc_test_loop_mode = tvb_get_guint8(tvb, curr_offset) & 0x03;
    curr_offset++;

    return (curr_offset - offset);
}

static guint16
de_tp_epc_ue_tl_a_lb_setup(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32     curr_offset;
    guint32     count, nb_lb;
    guint8      drb;
    proto_tree *lb_setup_tree = NULL;
    proto_item *ti;

    curr_offset = offset;

    count = 0;
    nb_lb = len / 3;

    ti = proto_tree_add_uint(tree, hf_gsm_a_dtap_num_lb_entities, tvb, curr_offset, 1, nb_lb);
    proto_item_set_len(ti, len);
    while ((count < nb_lb) && (count < 8)) {
        lb_setup_tree = proto_tree_add_subtree_format(tree, tvb, curr_offset, 3,
                                ett_epc_ue_tl_a_lb_setup, NULL, "LB entity %d", count);

        proto_tree_add_bits_item(lb_setup_tree, hf_gsm_a_dtap_epc_ue_tl_a_ul_sdu_size, tvb, curr_offset<<3, 16, ENC_BIG_ENDIAN);
        curr_offset += 2;
        drb = tvb_get_guint8(tvb, curr_offset) & 0x1f;
        proto_tree_add_uint_format_value(lb_setup_tree, hf_gsm_a_dtap_epc_ue_tl_a_drb, tvb, curr_offset, 1,
                                         drb, "%d (%d)", drb+1, drb);
        curr_offset++;
        count++;
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_dtap_extraneous_data);

    return (len);
}

static guint16
de_tp_epc_ue_tl_b_lb_setup(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_bits_item(tree, hf_gsm_a_dtap_epc_ue_tl_b_ip_pdu_delay, tvb, curr_offset<<3, 8, ENC_BIG_ENDIAN);
    curr_offset++;

    return (curr_offset - offset);
}

static guint16
de_tp_epc_ue_tl_c_setup(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_bits_item(tree, hf_gsm_a_dtap_epc_ue_tl_c_mbsfn_area_id, tvb, curr_offset<<3, 8, ENC_BIG_ENDIAN);
    curr_offset++;
    proto_tree_add_bits_item(tree, hf_gsm_a_dtap_epc_ue_tl_c_mch_id, tvb, (curr_offset<<3)+4, 4, ENC_BIG_ENDIAN);
    curr_offset++;
    proto_tree_add_bits_item(tree, hf_gsm_a_dtap_epc_ue_tl_c_lcid, tvb, (curr_offset<<3)+3, 5, ENC_BIG_ENDIAN);
    curr_offset++;

    return (curr_offset - offset);
}

static const value_string epc_ue_positioning_technology_vals[] = {
    { 0,    "AGNSS"},
    { 1,    "OTDOA"},
    { 0, NULL }
};

static guint16
de_tp_epc_ue_positioning_technology(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_bits_item(tree, hf_gsm_a_dtap_epc_ue_positioning_technology, tvb, curr_offset<<3, 8, ENC_BIG_ENDIAN);
    curr_offset++;

    return (curr_offset - offset);
}

static guint16
de_tp_epc_mbms_packet_counter_value(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_bits_item(tree, hf_gsm_a_dtap_epc_mbms_packet_counter_value, tvb, curr_offset<<3, 32, ENC_BIG_ENDIAN);
    curr_offset += 4;

    return (curr_offset - offset);
}

static const true_false_string epc_latitude_sign_value = {
    "South",
    "North"
};

static const true_false_string epc_altitude_dir_value = {
    "Depth",
    "Height"
};

static guint16
de_tp_epc_ellipsoid_point_with_alt(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    guint32 longitude;

    curr_offset = offset;

    proto_tree_add_bits_item(tree, hf_gsm_a_dtap_epc_latitude_sign, tvb, curr_offset<<3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(tree, hf_gsm_a_dtap_epc_degrees_latitude, tvb, (curr_offset<<3)+1, 23, ENC_BIG_ENDIAN);
    curr_offset += 3;
    longitude = tvb_get_ntoh24(tvb, curr_offset);
    proto_tree_add_int_format(tree, hf_gsm_a_dtap_epc_degrees_longitude, tvb, curr_offset, 3, longitude,
                              "%s = %s: %d", decode_bits_in_field(curr_offset<<3, 24, longitude),
                              proto_registrar_get_name(hf_gsm_a_dtap_epc_degrees_longitude), longitude-8388608);
    curr_offset += 3;
    proto_tree_add_bits_item(tree, hf_gsm_a_dtap_epc_altitude_dir, tvb, curr_offset<<3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(tree, hf_gsm_a_dtap_epc_altitude, tvb, (curr_offset<<3)+1, 15, ENC_BIG_ENDIAN);
    curr_offset += 2;

    return (curr_offset - offset);
}

static guint16
de_tp_epc_horizontal_velocity(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_bits_item(tree, hf_gsm_a_dtap_epc_bearing, tvb, curr_offset<<3, 9, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(tree, hf_gsm_a_dtap_epc_horizontal_speed, tvb, (curr_offset<<3)+9, 11, ENC_BIG_ENDIAN);
    curr_offset += 3;

    return (curr_offset - offset);
}

static guint16
de_tp_epc_gnss_tod_msec(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_bits_item(tree, hf_gsm_a_dtap_epc_gnss_tod_msec, tvb, (curr_offset<<3)+2, 22, ENC_BIG_ENDIAN);
    curr_offset += 3;

    return (curr_offset - offset);
}

static const value_string gcc_call_ref_priority[] = {
    { 0, "reserved"},
    { 1, "level 4"},
    { 2, "level 3"},
    { 3, "level 2"},
    { 4, "level 1"},
    { 5, "level 0"},
    { 6, "level B"},
    { 7, "level A"},
    { 0, NULL }
};
static guint16
de_gcc_call_ref(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    guint32 value;

    curr_offset = offset;

    value = tvb_get_ntohl(tvb, curr_offset);

    proto_tree_add_item(tree, hf_gsm_a_dtap_gcc_call_ref, tvb, curr_offset, 4, ENC_BIG_ENDIAN);

    if (value & 0x10){
        proto_tree_add_item(tree, hf_gsm_a_dtap_gcc_call_ref_has_priority, tvb, curr_offset, 4, ENC_NA);
        proto_tree_add_item(tree, hf_gsm_a_dtap_gcc_call_priority, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_gsm_a_dtap_gcc_spare_1, tvb, curr_offset, 4, ENC_NA);
    }
    else{
        proto_tree_add_item(tree, hf_gsm_a_dtap_gcc_call_ref_has_priority, tvb, curr_offset, 4, ENC_NA);
        proto_tree_add_item(tree, hf_gsm_a_dtap_gcc_spare_4, tvb, curr_offset, 4, ENC_NA);
    }

    curr_offset += 4;

    return(curr_offset - offset);
}

static const value_string gcc_call_state_vals[] = {
    { 0,  "U0"},
    { 1,  "U1"},
    { 2,  "U2sl"},
    { 3,  "U3"},
    { 4,  "U4"},
    { 5,  "U5"},
    { 6,  "U0.p"},
    { 7,  "U2wr"},
    { 8,  "U2r"},
    { 9,  "U2ws"},
    { 10, "U2sr"},
    { 11, "U2nc"},
    { 0, NULL }
    /* All other values are reserved. */
};

static guint16
de_gcc_call_state(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_item(tree, hf_gsm_a_dtap_gcc_call_state, tvb, offset, 2, ENC_BIG_ENDIAN);

    return 2;
}

static const range_string gcc_cause_vals[] = {
    {0,   2,   "Unspecified"},
    {3,   3,   "Illegal MS"},
    {4,   4,   "Unspecified"},
    {5,   5,   "IMEI not accepted"},
    {6,   6,   "Illegal ME"},
    {7,   7,   "Unspecified"},
    {8,   8,   "Service not authorized"},
    {9,   9,   "Application not supported on the protocol"},
    {10,  10,  "RR connection aborted"},
    {11,  15,  "Unspecified"},
    {16,  16,  "Normal call clearing"},
    {17,  17,  "Network failure"},
    {18,  19,  "Unspecified"},
    {20,  20,  "Busy"},
    {21,  21,  "Unspecified"},
    {22,  22,  "Congestion"},
    {23,  23,  "User not originator of call"},
    {24,  24,  "Network wants to maintain call"},
    {25,  29,  "Unspecified"},
    {30,  30,  "Response to GET STATUS"},
    {31,  31,  "Unspecified"},
    {32,  32,  "Service option not supported"},
    {33,  33,  "Requested service option not subscribed"},
    {34,  34,  "Service option temporarily out of order"},
    {35,  37,  "Unspecified"},
    {38,  38,  "Call cannot be identified"},
    {39,  47,  "Unspecified"},
    {48,  63,  "Retry upon entry into a new cell"},
    {64,  80,   "Unspecified"},
    {81,  81,  "Invalid transaction identifier value"},
    {82,  94,  "Unspecified"},
    {95,  95,  "Semantically incorrect message"},
    {96,  96,  "Invalid mandatory information"},
    {97,  97,  "Message type non-existent or not implemented"},
    {98,  98,  "Message type not compatible with the protocol state"},
    {99,  99,  "Information element non-existent or not implemented"},
    {100, 100, "Message type not compatible with the protocol state"},
    {101, 111, "Unspecified"},
    {112, 112, "Protocol error, unspecified"},
    {113, 127, "Unspecified"},
    {0, 0, NULL }
};

static const true_false_string gcc_cause_structure_val = {
    "cause_part [diagnostics]",
    "cause_part <cause>"
};

static guint16
de_gcc_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    int curr_len;
    curr_len = len;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_dtap_gcc_cause_structure, tvb, curr_offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_gsm_a_dtap_gcc_cause, tvb, curr_offset, 1, ENC_NA);

    curr_offset++;
    curr_len--;

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);

    return(curr_offset - offset);
}

static const true_false_string gcc_orig_ind_vals = {
    "The MS is the originator of the call",
    "The MS is not the originator of the call"
};
static guint16
de_gcc_orig_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_dtap_gcc_spare_3, tvb, curr_offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_gsm_a_dtap_gcc_orig_ind, tvb, curr_offset, 1, ENC_NA);

    curr_offset++;

    return(curr_offset - offset);
}

static const true_false_string gcc_state_attr_da = {
    "User connection in the downlink attached (D-ATT = T)",
    "User connection in the downlink not attached (D-ATT = F)"
};
static const true_false_string gcc_state_attr_ua = {
    "User connection in the uplink attached (U-ATT = T)",
    "User connection in the uplink not attached (U-ATT = F)"
};
static const true_false_string gcc_state_attr_comm = {
    "Communication with its peer entity is enabled in both directions  (COMM = T)",
    "Communication with its peer entity is not enabled in both directions (COMM = F)"
};
static const true_false_string gcc_state_attr_oi = {
    "The MS is the originator of the call (ORIG = T)",
    "The MS is not the originator of the call (ORIG = F)"
};
static guint16
de_gcc_state_attr(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_item(tree, hf_gsm_a_dtap_gcc_state_attr, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_gsm_a_dtap_gcc_state_attr_da, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_gsm_a_dtap_gcc_state_attr_ua, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_gsm_a_dtap_gcc_state_attr_comm, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_gsm_a_dtap_gcc_state_attr_oi, tvb, offset, 1, ENC_NA);

    return 1;
}

static const value_string bcc_call_ref_priority[] = {
    { 0, "reserved"},
    { 1, "level 4"},
    { 2, "level 3"},
    { 3, "level 2"},
    { 4, "level 1"},
    { 5, "level 0"},
    { 6, "level B"},
    { 7, "level A"},
    { 0, NULL }
};
static guint16
de_bcc_call_ref(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    guint32 value;

    curr_offset = offset;

    value = tvb_get_ntohl(tvb, curr_offset);

    proto_tree_add_item(tree, hf_gsm_a_dtap_bcc_call_ref, tvb, curr_offset, 4, ENC_BIG_ENDIAN);

    if (value & 0x10){
        proto_tree_add_item(tree, hf_gsm_a_dtap_bcc_call_ref_has_priority, tvb, curr_offset, 4, ENC_NA);
        proto_tree_add_item(tree, hf_gsm_a_dtap_bcc_call_priority, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_gsm_a_dtap_bcc_spare_1, tvb, curr_offset, 4, ENC_NA);
    }
    else{
        proto_tree_add_item(tree, hf_gsm_a_dtap_bcc_call_ref_has_priority, tvb, curr_offset, 4, ENC_NA);
        proto_tree_add_item(tree, hf_gsm_a_dtap_bcc_spare_4, tvb, curr_offset, 4, ENC_NA);
    }

    curr_offset += 4;

    return(curr_offset - offset);
}

static const range_string bcc_call_state_vals[] = {
    {0, 0,  "U0"},
    {1, 1,  "U1"},
    {2, 2,  "U2"},
    {3, 3,  "U3"},
    {4, 4,  "U4"},
    {5, 5,  "U5"},
    {6, 6,  "U0.p"},
    {7, 7,  "U6"},
    {8, 15, "Reserved"},
    {0, 0, NULL }
};

static guint16
de_bcc_call_state(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_item(tree, hf_gsm_a_dtap_bcc_call_state, tvb, offset, 2, ENC_NA);

    return 1;
}

static const range_string bcc_cause_vals[] = {
    {0,   2,   "Unspecified"},
    {3,   3,   "Illegal MS"},
    {4,   4,   "Unspecified"},
    {5,   5,   "IMEI not accepted"},
    {6,   6,   "Illegal ME"},
    {7,   7,   "Unspecified"},
    {8,   8,   "Service not authorized"},
    {9,   9,   "Application not supported on the protocol"},
    {10,  10,  "RR connection aborted"},
    {11,  15,  "Unspecified"},
    {16,  16,  "Normal call clearing"},
    {17,  17,  "Network failure"},
    {18,  19,  "Unspecified"},
    {20,  20,  "Busy"},
    {21,  21,  "Unspecified"},
    {22,  22,  "Congestion"},
    {23,  23,  "User not originator of call"},
    {24,  24,  "Network wants to maintain call"},
    {25,  29,  "Unspecified"},
    {30,  30,  "Response to GET STATUS"},
    {31,  31,  "Unspecified"},
    {32,  32,  "Service option not supported"},
    {33,  33,  "Requested service option not subscribed"},
    {34,  34,  "Service option temporarily out of order"},
    {35,  37,  "Unspecified"},
    {38,  38,  "Call cannot be identified"},
    {39,  47,  "Unspecified"},
    {48,  63,  "Retry upon entry into a new cell"},
    {64,  80,   "Unspecified"},
    {81,  81,  "Invalid transaction identifier value"},
    {82,  94,  "Unspecified"},
    {95,  95,  "Semantically incorrect message"},
    {96,  96,  "Invalid mandatory information"},
    {97,  97,  "Message type non-existent or not implemented"},
    {98,  98,  "Message type not compatible with the protocol state"},
    {99,  99,  "Information element non-existent or not implemented"},
    {100, 100, "Message type not compatible with the protocol state"},
    {101, 111, "Unspecified"},
    {112, 112, "Protocol error, unspecified"},
    {113, 127, "Unspecified"},
    {0, 0, NULL }
};

static const true_false_string bcc_cause_structure_val = {
    "cause_part [diagnostics]",
    "cause_part <cause>"
};

static guint16
de_bcc_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    int curr_len;
    curr_len = len;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_dtap_bcc_cause_structure, tvb, curr_offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_gsm_a_dtap_bcc_cause, tvb, curr_offset, 1, ENC_NA);

    curr_offset++;
    curr_len--;

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);

    return(curr_offset - offset);
}

static const true_false_string bcc_orig_ind_vals = {
    "The MS is the originator of the call",
    "The MS is not the originator of the call"
};
static guint16
de_bcc_orig_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_dtap_bcc_spare_3, tvb, curr_offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_gsm_a_dtap_bcc_orig_ind, tvb, curr_offset, 1, ENC_NA);

    curr_offset++;

    return(curr_offset - offset);
}

static const true_false_string bcc_state_attr_da = {
    "User connection in the downlink attached (D-ATT = T)",
    "User connection in the downlink not attached (D-ATT = F)"
};
static const true_false_string bcc_state_attr_ua = {
    "User connection in the uplink attached (U-ATT = T)",
    "User connection in the uplink not attached (U-ATT = F)"
};
static const true_false_string bcc_state_attr_comm = {
    "Communication with its peer entity is enabled in both directions  (COMM = T)",
    "Communication with its peer entity is not enabled in both directions (COMM = F)"
};
static const true_false_string bcc_state_attr_oi = {
    "The MS is the originator of the call (ORIG = T)",
    "The MS is not the originator of the call (ORIG = F)"
};
static guint16
de_bcc_state_attr(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_item(tree, hf_gsm_a_dtap_bcc_state_attr, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_gsm_a_dtap_bcc_state_attr_da, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_gsm_a_dtap_bcc_state_attr_ua, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_gsm_a_dtap_bcc_state_attr_comm, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_gsm_a_dtap_bcc_state_attr_oi, tvb, offset, 1, ENC_NA);

    return 1;
}

static guint16
de_bcc_compr_otdi(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_item(tree, hf_gsm_a_dtap_bcc_compr_otdi, tvb, offset, len, ENC_NA);

    return len;
}

guint16 (*dtap_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string, int string_len) = {
    /* Mobility Management Information Elements 10.5.3 */
    de_auth_param_rand,                  /* Authentication Parameter RAND */
    de_auth_param_autn,                  /* Authentication Parameter AUTN (UMTS and EPS authentication challenge) */
    de_auth_resp_param,                  /* Authentication Response Parameter */
    de_auth_resp_param_ext,              /* Authentication Response Parameter (extension) (UMTS authentication challenge only) */
    de_auth_fail_param,                  /* Authentication Failure Parameter (UMTS and EPS authentication challenge) */
    NULL                                 /* handled inline */,  /* CM Service Type */
    NULL                                 /* handled inline */,  /* Identity Type */
    NULL                                 /* handled inline */,  /* Location Updating Type */
    de_network_name,                     /* Network Name */
    de_rej_cause,                        /* Reject Cause */
    NULL                                 /* no associated data */,  /* Follow-on Proceed */
    de_time_zone,                        /* Time Zone */
    de_time_zone_time,                   /* Time Zone and Time */
    NULL                                 /* no associated data */,  /* CTS Permission */
    de_lsa_id,                           /* LSA Identifier */
    de_day_saving_time,                  /* Daylight Saving Time */
    de_emerg_num_list,                   /* Emergency Number List */
    de_add_upd_params,                   /* Additional update parameters */
    de_mm_timer,                         /* MM Timer */
                                         /* Call Control Information Elements 10.5.4 */
    de_aux_states,                       /* Auxiliary States */
    de_bearer_cap,                       /* Bearer Capability */
    de_cc_cap,                           /* Call Control Capabilities */
    de_call_state,                       /* Call State */
    de_cld_party_bcd_num,                /* Called Party BCD Number */
    de_cld_party_sub_addr,               /* Called Party Subaddress */
    de_clg_party_bcd_num,                /* Calling Party BCD Number */
    de_clg_party_sub_addr,               /* Calling Party Subaddress */
    de_cause,                            /* Cause */
    NULL                                 /* no associated data */,  /* CLIR Suppression */
    NULL                                 /* no associated data */,  /* CLIR Invocation */
    NULL                                 /* handled inline */,  /* Congestion Level */
    de_conn_num,                         /* Connected Number */
    de_conn_sub_addr,                    /* Connected Subaddress */
    de_facility,                         /* Facility */
    de_hlc,                              /* High Layer Compatibility */
    de_keypad_facility,                  /* Keypad Facility */
    de_llc,                              /* 10.5.4.18 Low layer compatibility */
    NULL,                                /* More Data */
    de_notif_ind,                        /* Notification Indicator */
    de_prog_ind,                         /* Progress Indicator */
    de_recall_type,                      /* 10.5.4.21a Recall type $(CCBS)$ */
    de_red_party_bcd_num,                /* Redirecting Party BCD Number */
    de_red_party_sub_addr,               /* Redirecting Party Subaddress */
    de_repeat_ind,                       /* Repeat Indicator */
    NULL                                 /* no associated data */,  /* Reverse Call Setup Direction */
    de_setup_cont,                       /* SETUP Container $(CCBS)$ */
    de_signal,                           /* Signal */
    de_ss_ver_ind,                       /* SS Version Indicator */
    de_u2u,                              /* User-user */
    de_alert_pat,                        /* Alerting Pattern $(NIA)$ */
    de_allowed_act,                      /* Allowed Actions $(CCBS)$ */
    de_stream_id,                        /* Stream Identifier */
    de_nw_call_ctrl_cap,                 /* Network Call Control Capabilities */
    de_ca_of_no_cli,                     /* Cause of No CLI */
    de_sup_codec_list,                   /* Supported Codec List */
    de_serv_cat,                         /* Service Category */
    NULL,                                /* 10.5.4.34 Redial */
    NULL,                                /* 10.5.4.35 Network-initiated Service Upgrade ind */
                                         /* Short Message Service Information Elements [5] 8.1.4 */
    de_cp_user_data,                     /* CP-User Data */
    de_cp_cause,                         /* CP-Cause */
                                         /* Tests procedures information elements 3GPP TS 44.014 6.4.0 and 3GPP TS 34.109 6.4.0 */
    de_tp_sub_channel,                   /* Close TCH Loop Cmd Sub-channel */
    de_tp_ack,                           /* Open Loop Cmd Ack */
    de_tp_loop_type,                     /* Close Multi-slot Loop Cmd Loop type */
    de_tp_loop_ack,                      /* Close Multi-slot Loop Ack Result */
    de_tp_tested_device,                 /* Test Interface Tested device */
    de_tp_pdu_description,               /* GPRS Test Mode Cmd PDU description */
    de_tp_mode_flag,                     /* GPRS Test Mode Cmd Mode flag */
    de_tp_egprs_mode_flag,               /* EGPRS Start Radio Block Loopback Cmd Mode flag */
    de_tp_ms_positioning_technology,     /* MS Positioning Technology */
    de_tp_ue_test_loop_mode,             /* Close UE Test Loop Mode */
    de_tp_ue_positioning_technology,     /* UE Positioning Technology */
    de_tp_rlc_sdu_counter_value,         /* RLC SDU Counter Value */
    de_tp_epc_ue_test_loop_mode,         /* UE Test Loop Mode */
    de_tp_epc_ue_tl_a_lb_setup,          /* UE Test Loop Mode A LB Setup */
    de_tp_epc_ue_tl_b_lb_setup,          /* UE Test Loop Mode B LB Setup */
    de_tp_epc_ue_tl_c_setup,             /* UE Test Loop Mode C Setup */
    de_tp_epc_ue_positioning_technology, /* UE Positioning Technology */
    de_tp_epc_mbms_packet_counter_value, /* MBMS Packet Counter Value */
    de_tp_epc_ellipsoid_point_with_alt,  /* ellipsoidPointWithAltitude */
    de_tp_epc_horizontal_velocity,       /* horizontalVelocity */
    de_tp_epc_gnss_tod_msec,             /* gnss-TOD-msec */
                                         /* GCC Elements */
    de_gcc_call_ref,                     /* Call Reference */
    de_gcc_call_state,                   /* Call state */
    de_gcc_cause,                        /* Cause  */
    de_gcc_orig_ind,                     /* Originator indication */
    de_gcc_state_attr,                   /* State attributes */
                                         /* BCC Elements */
    de_bcc_call_ref,                     /* Call Reference */
    de_bcc_call_state,                   /* Call state */
    de_bcc_cause,                        /* Cause  */
    de_bcc_orig_ind,                     /* Originator indication */
    de_bcc_state_attr,                   /* State attributes */
    de_bcc_compr_otdi,                   /* Compressed otdi */
    NULL,                                /* NONE */
};

/* MESSAGE FUNCTIONS */

/*
 * [12] 8.3 IMMEDIATE SETUP
 */
static void
dtap_gcc_imm_setup(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;
    guint8  oct;
    proto_tree *subtree;

    curr_offset = offset;
    curr_len = len;

    /*
     * special dissection for Cipher Key Sequence Number
     */
    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, curr_offset<<3, 4, ENC_BIG_ENDIAN);

    subtree =
    proto_tree_add_subtree(tree,
        tvb, curr_offset, 1, ett_gsm_common_elem[DE_CIPH_KEY_SEQ_NUM], NULL,
        val_to_str_ext_const(DE_CIPH_KEY_SEQ_NUM, &gsm_common_elem_strings_ext, ""));

    proto_tree_add_bits_item(subtree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3)+4, 1, ENC_BIG_ENDIAN);

    switch (oct & 0x07)
    {
    case 0x07:
        proto_tree_add_uint_format_value(subtree, hf_gsm_a_dtap_ciphering_key_sequence_number, tvb, curr_offset, 1,
            oct, "No key is available");
        break;

    default:
        proto_tree_add_item(subtree, hf_gsm_a_dtap_ciphering_key_sequence_number, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        break;
    }

    curr_offset++;
    curr_len--;

    ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MS_CM_2, NULL);
    ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID, NULL);
    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_GCC_CALL_REF, NULL);
    ELEM_OPT_TLV(0x7e, GSM_A_PDU_TYPE_DTAP, DE_USER_USER, NULL);
}

/*
 * [12] 8.5 SETUP
 */
static void
dtap_gcc_setup(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_GCC_CALL_REF, NULL);
    ELEM_OPT_TLV(0x7e, GSM_A_PDU_TYPE_DTAP, DE_USER_USER, NULL);
}

/*
 * [12] 8.1 CONNECT
 */
static void
dtap_gcc_connect(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_GCC_CALL_REF, NULL);

    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, curr_offset<<3, 4, ENC_NA);

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_GCC_ORIG_IND, NULL);
}

/*
 * [12] 8.7 TERMINATION
 */
static void
dtap_gcc_term(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_GCC_CAUSE, NULL);
}

/*
 * [12] 8.9 TERMINATION REQUEST
 */
static void
dtap_gcc_term_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_GCC_CALL_REF, NULL);
}

/*
 * [12] 8.8 TERMINATION REJECT
 */
static void
dtap_gcc_term_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_GCC_CAUSE, "(Reject Cause)");
}

/*
 * [12] 8.6 STATUS
 */
static void
dtap_gcc_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_GCC_CAUSE, NULL);
    ELEM_OPT_TV_SHORT(0xa0, GSM_A_PDU_TYPE_DTAP, DE_GCC_CALL_STATE, NULL);
    ELEM_OPT_TV_SHORT(0xb0, GSM_A_PDU_TYPE_DTAP, DE_GCC_STATE_ATTR, NULL);
}

/*
 * [12] 8.2 GET STATUS
 */
static void
dtap_gcc_get_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_TLV(0x17, GSM_A_PDU_TYPE_COMMON, DE_MID, NULL);
    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [12] 8.4 SET PARAMETER
 */
static void
dtap_gcc_set_param(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, curr_offset<<3, 4, ENC_NA);
    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_GCC_STATE_ATTR, NULL);

}

/*
 * [13] 8.1 CONNECT
 */
static void
dtap_bcc_connect(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_BCC_CALL_REF, NULL);

    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, curr_offset<<3, 4, ENC_NA);

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_BCC_ORIG_IND, "(Broadcast call reference)");
}

/*
 * [13] 8.2 GET STATUS
 */
static void
dtap_bcc_get_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_OPT_TLV(0x17, GSM_A_PDU_TYPE_COMMON, DE_MID, NULL);
    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [13] 8.3 IMMEDIATE SETUP
 */
static void
dtap_bcc_imm_setup(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;
    guint8  oct;
    proto_tree *subtree;

    curr_offset = offset;
    curr_len = len;

    /*
     * special dissection for Cipher Key Sequence Number
     */
    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, curr_offset<<3, 4, ENC_BIG_ENDIAN);

    subtree =
    proto_tree_add_subtree(tree,
        tvb, curr_offset, 1, ett_gsm_common_elem[DE_CIPH_KEY_SEQ_NUM], NULL,
        val_to_str_ext_const(DE_CIPH_KEY_SEQ_NUM, &gsm_common_elem_strings_ext, ""));

    proto_tree_add_bits_item(subtree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3)+4, 1, ENC_BIG_ENDIAN);

    switch (oct & 0x07)
    {
    case 0x07:
        proto_tree_add_uint_format_value(subtree, hf_gsm_a_dtap_ciphering_key_sequence_number, tvb, curr_offset, 1,
            oct, "No key is available");
        break;

    default:
        proto_tree_add_item(subtree, hf_gsm_a_dtap_ciphering_key_sequence_number, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        break;
    }

    curr_offset++;
    curr_len--;

    ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MS_CM_2, NULL);
    ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID, NULL);
    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_BCC_CALL_REF, "(Broadcast identity)");
}

/*
 * [13] 8.3a IMMEDIATE SETUP 2
 */
static void
dtap_bcc_imm_setup2(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;
    guint8  oct;
    proto_tree *subtree;

    curr_offset = offset;
    curr_len = len;

    /*
     * special dissection for Cipher Key Sequence Number
     */
    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, curr_offset<<3, 4, ENC_BIG_ENDIAN);

    subtree =
    proto_tree_add_subtree(tree,
        tvb, curr_offset, 1, ett_gsm_common_elem[DE_CIPH_KEY_SEQ_NUM], NULL,
        val_to_str_ext_const(DE_CIPH_KEY_SEQ_NUM, &gsm_common_elem_strings_ext, ""));

    proto_tree_add_bits_item(subtree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3)+4, 1, ENC_BIG_ENDIAN);

    switch (oct & 0x07)
    {
    case 0x07:
        proto_tree_add_uint_format_value(subtree, hf_gsm_a_dtap_ciphering_key_sequence_number, tvb, curr_offset, 1,
            oct, "No key is available");
        break;

    default:
        proto_tree_add_item(subtree, hf_gsm_a_dtap_ciphering_key_sequence_number, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        break;
    }

    curr_offset++;
    curr_len--;

    ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MS_CM_2, NULL);
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_TMSI_STAT, NULL)
    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_BCC_CALL_REF, "(Group identity)");
    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_BCC_COMPR_OTDI, NULL);
}

/*
 * [13] 8.4 SET PARAMETER
 */
static void
dtap_bcc_set_param(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, curr_offset<<3, 4, ENC_NA);
    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_BCC_STATE_ATTR, NULL);

}

/*
 * [13] 8.5 SETUP
 */
static void
dtap_bcc_setup(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_BCC_CALL_REF, "(Broadcast identity)");
    ELEM_OPT_TLV(0x7e, GSM_A_PDU_TYPE_DTAP, DE_USER_USER, "(Originator-to-dispatcher information)");
}

/*
 * [13] 8.6 STATUS
 */
static void
dtap_bcc_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_BCC_CAUSE, NULL);
    ELEM_OPT_TV_SHORT(0xa0, GSM_A_PDU_TYPE_DTAP, DE_BCC_CALL_STATE, NULL);
    ELEM_OPT_TV_SHORT(0xb0, GSM_A_PDU_TYPE_DTAP, DE_BCC_STATE_ATTR, NULL);
}

/*
 * [13] 8.7 TERMINATION
 */
static void
dtap_bcc_term(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_BCC_CAUSE, NULL);
}

/*
 * [13] 8.8 TERMINATION REJECT
 */
static void
dtap_bcc_term_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_BCC_CAUSE, "(Reject Cause)");
}

/*
 * [13] 8.9 TERMINATION REQUEST
 */
static void
dtap_bcc_term_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_BCC_CALL_REF, "(Broadcast call reference)");
}

/*
 * [4] 9.2.2 Authentication request
 */
static void
dtap_mm_auth_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;
    guint8      oct;
    proto_tree *subtree;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    /*
     * special dissection for Cipher Key Sequence Number
     */
    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, curr_offset<<3, 4, ENC_BIG_ENDIAN);

    subtree =
    proto_tree_add_subtree(tree,
        tvb, curr_offset, 1, ett_gsm_common_elem[DE_CIPH_KEY_SEQ_NUM], NULL,
        val_to_str_ext_const(DE_CIPH_KEY_SEQ_NUM, &gsm_common_elem_strings_ext, ""));

    proto_tree_add_bits_item(subtree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3)+4, 1, ENC_BIG_ENDIAN);

    switch (oct & 0x07)
    {
    case 0x07:
        proto_tree_add_uint_format_value(subtree, hf_gsm_a_dtap_ciphering_key_sequence_number, tvb, curr_offset, 1,
            oct, "No key is available");
        break;

    default:
        proto_tree_add_item(subtree, hf_gsm_a_dtap_ciphering_key_sequence_number, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        break;
    }

    curr_offset++;
    curr_len--;

    if ((signed)curr_len <= 0) return;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_AUTH_PARAM_RAND, " - UMTS challenge or GSM challenge");

    ELEM_OPT_TLV(0x20, GSM_A_PDU_TYPE_DTAP, DE_AUTH_PARAM_AUTN, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [4] 9.2.3 Authentication response
 */
static void
dtap_mm_auth_resp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_AUTH_RESP_PARAM, NULL);

    ELEM_OPT_TLV(0x21, GSM_A_PDU_TYPE_DTAP, DE_AUTH_RESP_PARAM_EXT, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [4] 9.2.3a Authentication Failure
 */
static void
dtap_mm_auth_fail(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_REJ_CAUSE, NULL);

    ELEM_OPT_TLV(0x22, GSM_A_PDU_TYPE_DTAP, DE_AUTH_FAIL_PARAM, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [3] 9.2.4 CM Re-establishment request
 */
static void
dtap_mm_cm_reestab_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;
    guint8      oct;
    proto_tree *subtree;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    /*
     * special dissection for Cipher Key Sequence Number
     */
    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, curr_offset<<3, 4, ENC_BIG_ENDIAN);

    subtree =
    proto_tree_add_subtree(tree,
        tvb, curr_offset, 1, ett_gsm_common_elem[DE_CIPH_KEY_SEQ_NUM], NULL,
        val_to_str_ext_const(DE_CIPH_KEY_SEQ_NUM, &gsm_common_elem_strings_ext, ""));

    proto_tree_add_bits_item(subtree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3)+4, 1, ENC_BIG_ENDIAN);

    switch (oct & 0x07)
    {
    case 0x07:
        proto_tree_add_uint_format_value(subtree, hf_gsm_a_dtap_ciphering_key_sequence_number, tvb, curr_offset, 1,
            oct, "No key is available");
        break;

    default:
        proto_tree_add_item(subtree, hf_gsm_a_dtap_ciphering_key_sequence_number, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        break;
    }

    curr_offset++;
    curr_len--;

    if ((signed)curr_len <= 0) return;

    ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MS_CM_2, NULL);

    ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID, NULL);

    ELEM_OPT_TV(0x13, GSM_A_PDU_TYPE_COMMON, DE_LAI, NULL);

    ELEM_OPT_TV_SHORT(0xD0, GSM_A_PDU_TYPE_GM, DE_DEVICE_PROPERTIES, NULL);


    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [3] 9.2.5a CM service prompt $(CCBS)
 */
static void
dtap_mm_cm_srvc_prompt(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_PD_SAPI, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [4] 9.2.6 CM service reject
 */
static void
dtap_mm_cm_srvc_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_REJ_CAUSE, NULL);

    ELEM_OPT_TLV(0x36, GSM_A_PDU_TYPE_DTAP, DE_MM_TIMER, " - T3246 value");

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [4] 9.2.8 Abort
 */
static void
dtap_mm_abort(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_REJ_CAUSE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [3] 9.2.9 CM service request
 */
static const value_string gsm_a_dtap_service_type_vals[] = {
    { 0x00, "Reserved"},
    { 0x01, "Mobile originating call establishment or packet mode connection establishment"},
    { 0x02, "Emergency call establishment"},
    { 0x03, "Reserved"},
    { 0x04, "Short message service"},
    { 0x05, "Reserved"},
    { 0x06, "Reserved"},
    { 0x07, "Reserved"},
    { 0x08, "Supplementary service activation"},
    { 0x09, "Voice group call establishment"},
    { 0x0a, "Voice broadcast call establishment"},
    { 0x0b, "Location Services"},
    { 0x0c, "Reserved"},
    { 0x0d, "Reserved"},
    { 0x0e, "Reserved"},
    { 0x0f, "Reserved"},
    { 0, NULL }
};

static void
dtap_mm_cm_srvc_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32      curr_offset;
    guint32      consumed;
    guint        curr_len;
    guint8       oct;
    proto_tree  *subtree;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    /*
     * special dissection for CM Service Type
     */
    oct = tvb_get_guint8(tvb, curr_offset);

    subtree =
    proto_tree_add_subtree(tree,
        tvb, curr_offset, 1, ett_gsm_common_elem[DE_CIPH_KEY_SEQ_NUM], NULL,
        val_to_str_ext_const(DE_CIPH_KEY_SEQ_NUM, &gsm_common_elem_strings_ext, ""));

    proto_tree_add_bits_item(subtree, hf_gsm_a_spare_bits, tvb, curr_offset<<3, 1, ENC_BIG_ENDIAN);

    switch ((oct & 0x70) >> 4)
    {
    case 0x07:
        proto_tree_add_uint_format_value(subtree, hf_gsm_a_dtap_ciphering_key_sequence_number70, tvb, curr_offset, 1,
            oct, "No key is available");
        break;

    default:
        proto_tree_add_item(subtree, hf_gsm_a_dtap_ciphering_key_sequence_number70, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        break;
    }

    subtree =
    proto_tree_add_subtree(tree,
        tvb, curr_offset, 1, ett_gsm_dtap_elem[DE_CM_SRVC_TYPE], NULL,
        val_to_str_ext_const(DE_CM_SRVC_TYPE, &gsm_dtap_elem_strings_ext, ""));

    proto_tree_add_item(subtree, hf_gsm_a_dtap_service_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;
    curr_len--;

    if ((signed)curr_len <= 0) return;

    ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MS_CM_2, NULL);

    ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID, NULL);

    ELEM_OPT_TV_SHORT(0x80, GSM_A_PDU_TYPE_COMMON, DE_PRIO, NULL);

    ELEM_OPT_TV_SHORT(0xC0, GSM_A_PDU_TYPE_DTAP, DE_ADD_UPD_PARAMS, NULL);

    ELEM_OPT_TV_SHORT(0xD0, GSM_A_PDU_TYPE_GM, DE_DEVICE_PROPERTIES, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [3] 9.2.10 Identity request
 */
static const value_string gsm_a_dtap_type_of_identity_vals[] = {
    { 0x00, "Reserved"},
    { 0x01, "IMSI"},
    { 0x02, "IMEI"},
    { 0x03, "IMEISV"},
    { 0x04, "TMSI"},
    { 0x05, "P-TMSI, RAI, P-TMSI signature"},
    { 0x06, "Reserved"},
    { 0x07, "Reserved"},
    { 0, NULL }
};

static void
dtap_mm_id_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32      curr_offset;
    guint        curr_len;
    proto_tree  *subtree;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    /*
     * special dissection for Identity Type
     */
    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, curr_offset<<3, 4, ENC_BIG_ENDIAN);

    subtree =
    proto_tree_add_subtree(tree,
        tvb, curr_offset, 1, ett_gsm_dtap_elem[DE_ID_TYPE], NULL,
        val_to_str_ext_const(DE_ID_TYPE, &gsm_dtap_elem_strings_ext, ""));

    proto_tree_add_bits_item(subtree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3)+4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_a_dtap_type_of_identity, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;
    curr_len--;

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [3] 9.2.11 Identity response
 */
static void
dtap_mm_id_resp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID, NULL);

    ELEM_OPT_TV_SHORT(0xE0, GSM_A_PDU_TYPE_GM, DE_PTMSI_TYPE, NULL);

    ELEM_OPT_TLV( 0x1B, GSM_A_PDU_TYPE_GM, DE_RAI_2, " - Routing area identification");

    ELEM_OPT_TLV( 0x19, GSM_A_PDU_TYPE_GM, DE_P_TMSI_SIG_2, " - P-TMSI signature");

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [3] 9.2.12 IMSI detach indication
 */
static void
dtap_mm_imsi_det_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_MS_CM_1, NULL);

    ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [3] 9.2.13 Location updating accept
 */
static void
dtap_mm_loc_upd_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_LAI, NULL);

    ELEM_OPT_TLV(0x17, GSM_A_PDU_TYPE_COMMON, DE_MID, NULL);

    ELEM_OPT_T(0xa1, GSM_A_PDU_TYPE_DTAP, DE_FOP, NULL);

    /* CTS permission O T 1 10.5.3.10 */
    ELEM_OPT_T(0xa2, GSM_A_PDU_TYPE_DTAP, DE_CTS_PERM, NULL);

    /* PLMN list O TLV 5-47 10.5.1.13 */
    ELEM_OPT_TLV(0x4a, GSM_A_PDU_TYPE_COMMON, DE_PLMN_LIST, " Equivalent");

    /* 34 Emergency Number List O TLV 5-50 10.5.3.13 */
    ELEM_OPT_TLV(0x34, GSM_A_PDU_TYPE_DTAP, DE_EMERGENCY_NUM_LIST, NULL);

    ELEM_OPT_TLV(0x35, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - Per MS T3212");

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [3] 9.2.14 Location updating reject
 */
static void
dtap_mm_loc_upd_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_REJ_CAUSE, NULL);

    ELEM_OPT_TLV(0x36, GSM_A_PDU_TYPE_DTAP, DE_MM_TIMER, " - T3246 value");

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [3] 9.2.15 Location updating request
 */
static const value_string gsm_a_dtap_updating_type_vals[] = {
    { 0x00, "Normal"},
    { 0x01, "Periodic"},
    { 0x02, "IMSI attach"},
    { 0x03, "Reserved"},
    { 0, NULL }
};

static const true_false_string tfs_follow_on_request_value = {
    "Follow-on request pending",
    "No follow-on request pending"
};

static void
dtap_mm_loc_upd_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;
    guint8  oct;
    proto_tree  *subtree;
    proto_item  *item;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    /*
     * special dissection for Location Updating Type
     */
    oct = tvb_get_guint8(tvb, curr_offset);

    subtree =
    proto_tree_add_subtree(tree,
        tvb, curr_offset, 1, ett_gsm_common_elem[DE_CIPH_KEY_SEQ_NUM], NULL,
        val_to_str_ext_const(DE_CIPH_KEY_SEQ_NUM, &gsm_common_elem_strings_ext, ""));

    proto_tree_add_bits_item(subtree, hf_gsm_a_spare_bits, tvb, curr_offset<<3, 1, ENC_BIG_ENDIAN);

    switch ((oct & 0x70) >> 4)
    {
    case 0x07:
        proto_tree_add_uint_format_value(subtree, hf_gsm_a_dtap_ciphering_key_sequence_number70, tvb, curr_offset, 1,
            oct, "No key is available");
        break;

    default:
        proto_tree_add_item(subtree, hf_gsm_a_dtap_ciphering_key_sequence_number70, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        break;
    }

    subtree =
    proto_tree_add_subtree(tree,
        tvb, curr_offset, 1, ett_gsm_dtap_elem[DE_LOC_UPD_TYPE], &item,
        val_to_str_ext_const(DE_LOC_UPD_TYPE, &gsm_dtap_elem_strings_ext, ""));

    proto_tree_add_item(subtree, hf_gsm_a_dtap_follow_on_request, tvb, curr_offset, 1, ENC_NA);

    proto_tree_add_bits_item(subtree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3)+5, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(subtree, hf_gsm_a_dtap_updating_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    proto_item_append_text(item, " - %s", val_to_str_const(oct & 0x03, gsm_a_dtap_updating_type_vals, "Reserved"));

    curr_offset++;
    curr_len--;

    if ((signed)curr_len <= 0) return;

    ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_LAI, NULL);

    ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_MS_CM_1, NULL);

    ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID, NULL);

    ELEM_OPT_TLV(0x33, GSM_A_PDU_TYPE_COMMON, DE_MS_CM_2, " - Mobile station classmark for UMTS");

    ELEM_OPT_TV_SHORT(0xc0, GSM_A_PDU_TYPE_DTAP, DE_ADD_UPD_PARAMS, NULL);

    ELEM_OPT_TV_SHORT(0xD0, GSM_A_PDU_TYPE_GM, DE_DEVICE_PROPERTIES, NULL);

    ELEM_OPT_TV_SHORT(0xE0, GSM_A_PDU_TYPE_COMMON, DE_MS_NET_FEAT_SUP, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}


/*
 * [4] 9.2.15a MM information
 */
void
dtap_mm_mm_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_OPT_TLV(0x43, GSM_A_PDU_TYPE_DTAP, DE_NETWORK_NAME, " - Full Name");

    ELEM_OPT_TLV(0x45, GSM_A_PDU_TYPE_DTAP, DE_NETWORK_NAME, " - Short Name");

    ELEM_OPT_TV(0x46, GSM_A_PDU_TYPE_DTAP, DE_TIME_ZONE, " - Local");

    ELEM_OPT_TV(0x47, GSM_A_PDU_TYPE_DTAP, DE_TIME_ZONE_TIME, " - Universal Time and Local Time Zone");

    ELEM_OPT_TLV(0x48, GSM_A_PDU_TYPE_DTAP, DE_LSA_ID, NULL);

    ELEM_OPT_TLV(0x49, GSM_A_PDU_TYPE_DTAP, DE_DAY_SAVING_TIME, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [4] 9.2.16 MM Status
 */
static void
dtap_mm_mm_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_REJ_CAUSE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [3] 9.2.17 TMSI reallocation command
 */
static void
dtap_mm_tmsi_realloc_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_LAI, NULL);

    ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}
/*
 * 9.2.18 TMSI reallocation complete
 * No data
 */

/*
 * 9.2.19 MM Null
 * No data
 */

/*
 * [4] 9.3.1 Alerting
 */
static void
dtap_cc_alerting(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_OPT_TLV(0x1c, GSM_A_PDU_TYPE_DTAP, DE_FACILITY, NULL);

    ELEM_OPT_TLV(0x1e, GSM_A_PDU_TYPE_DTAP, DE_PROG_IND, NULL);

    ELEM_OPT_TLV(0x7e, GSM_A_PDU_TYPE_DTAP, DE_USER_USER, NULL);

    /* uplink only */

    ELEM_OPT_TLV(0x7f, GSM_A_PDU_TYPE_DTAP, DE_SS_VER_IND, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [4] 9.3.2 Call confirmed
 */
static void
dtap_cc_call_conf(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_OPT_TV_SHORT(0xd0, GSM_A_PDU_TYPE_DTAP, DE_REPEAT_IND, " BC repeat indicator");

    ELEM_OPT_TLV(0x04, GSM_A_PDU_TYPE_DTAP, DE_BEARER_CAP, " 1");

    ELEM_OPT_TLV(0x04, GSM_A_PDU_TYPE_DTAP, DE_BEARER_CAP, " 2");

    ELEM_OPT_TLV(0x08, GSM_A_PDU_TYPE_DTAP, DE_CAUSE, NULL);

    ELEM_OPT_TLV(0x15, GSM_A_PDU_TYPE_DTAP, DE_CC_CAP, NULL);

    ELEM_OPT_TLV(0x2d, GSM_A_PDU_TYPE_DTAP, DE_SI, NULL);

    ELEM_OPT_TLV(0x40, GSM_A_PDU_TYPE_DTAP, DE_SUP_CODEC_LIST, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [4] 9.3.3 Call proceeding
 */
static void
dtap_cc_call_proceed(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_OPT_TV_SHORT(0xd0, GSM_A_PDU_TYPE_DTAP, DE_REPEAT_IND, " BC repeat indicator");

    ELEM_OPT_TLV(0x04, GSM_A_PDU_TYPE_DTAP, DE_BEARER_CAP, " 1");

    ELEM_OPT_TLV(0x04, GSM_A_PDU_TYPE_DTAP, DE_BEARER_CAP, " 2");

    ELEM_OPT_TLV(0x1c, GSM_A_PDU_TYPE_DTAP, DE_FACILITY, NULL);

    ELEM_OPT_TLV(0x1e, GSM_A_PDU_TYPE_DTAP, DE_PROG_IND, NULL);

    ELEM_OPT_TV_SHORT(0x80, GSM_A_PDU_TYPE_COMMON, DE_PRIO, NULL);

    ELEM_OPT_TLV(0x2f, GSM_A_PDU_TYPE_DTAP, DE_NET_CC_CAP, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [4] 9.3.4 Congestion control
 */
static const value_string gsm_a_dtap_congestion_level_vals[] = {
    { 0, "Receiver ready"},
    { 15, "Receiver not ready"},
    { 0, NULL }
};

static void
dtap_cc_congestion_control(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32      curr_offset;
    guint32      consumed;
    guint        curr_len;
    guint8       oct;
    proto_tree  *subtree;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    /*
     * special dissection for Congestion Level
     */
    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, curr_offset<<3, 4, ENC_BIG_ENDIAN);

    subtree =
    proto_tree_add_subtree(tree,
            tvb, curr_offset, 1, ett_gsm_dtap_elem[DE_CONGESTION], NULL,
            val_to_str_ext_const(DE_CONGESTION, &gsm_dtap_elem_strings_ext, ""));

    proto_tree_add_uint_format_value(subtree, hf_gsm_a_dtap_congestion_level, tvb, curr_offset, 1,
        oct, "%s", val_to_str_const(oct & 0xF, gsm_a_dtap_congestion_level_vals, "Reserved"));

    curr_offset++;
    curr_len--;

    if ((signed)curr_len <= 0) return;

    ELEM_OPT_TLV(0x08, GSM_A_PDU_TYPE_DTAP, DE_CAUSE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [4] 9.3.5 Connect
 */
static void
dtap_cc_connect(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_OPT_TLV(0x1c, GSM_A_PDU_TYPE_DTAP, DE_FACILITY, NULL);

    ELEM_OPT_TLV(0x1e, GSM_A_PDU_TYPE_DTAP, DE_PROG_IND, NULL);

    ELEM_OPT_TLV(0x4c, GSM_A_PDU_TYPE_DTAP, DE_CONN_NUM, NULL);

    ELEM_OPT_TLV(0x4d, GSM_A_PDU_TYPE_DTAP, DE_CONN_SUB_ADDR, NULL);

    ELEM_OPT_TLV(0x7e, GSM_A_PDU_TYPE_DTAP, DE_USER_USER, NULL);

    /* uplink only */

    ELEM_OPT_TLV(0x7f, GSM_A_PDU_TYPE_DTAP, DE_SS_VER_IND, NULL);

    ELEM_OPT_TLV(0x2d, GSM_A_PDU_TYPE_DTAP, DE_SI, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [4] 9.3.7 Disconnect
 */
static void
dtap_cc_disconnect(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_CAUSE, NULL);

    ELEM_OPT_TLV(0x1c, GSM_A_PDU_TYPE_DTAP, DE_FACILITY, NULL);

    ELEM_OPT_TLV(0x1e, GSM_A_PDU_TYPE_DTAP, DE_PROG_IND, NULL);

    ELEM_OPT_TLV(0x7e, GSM_A_PDU_TYPE_DTAP, DE_USER_USER, NULL);

    ELEM_OPT_TLV(0x7b, GSM_A_PDU_TYPE_DTAP, DE_ALLOWED_ACTIONS, NULL);

    /* uplink only */

    ELEM_OPT_TLV(0x7f, GSM_A_PDU_TYPE_DTAP, DE_SS_VER_IND, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [4] 9.3.8 Emergency setup
 */
static void
dtap_cc_emerg_setup(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_OPT_TLV(0x04, GSM_A_PDU_TYPE_DTAP, DE_BEARER_CAP, NULL);

    ELEM_OPT_TLV(0x2d, GSM_A_PDU_TYPE_DTAP, DE_SI, NULL);

    ELEM_OPT_TLV(0x40, GSM_A_PDU_TYPE_DTAP, DE_SUP_CODEC_LIST, NULL);

    ELEM_OPT_TLV(0x2e, GSM_A_PDU_TYPE_DTAP, DE_SERV_CAT, " - Emergency category");

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [4] 9.3.9 Facility
 */
static void
dtap_cc_facility(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_FACILITY, NULL);

    /* uplink only */

    ELEM_OPT_TLV(0x7f, GSM_A_PDU_TYPE_DTAP, DE_SS_VER_IND, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}
/*
 * 9.3.10 Hold
 * No data
 */
/*
 * 9.3.11 Hold Acknowledge
 */
/*
 * [4] 9.3.12 Hold Reject
 */
static void
dtap_cc_hold_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_CAUSE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [4] 9.3.13 Modify
 */
static void
dtap_cc_modify(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_BEARER_CAP, NULL);

    ELEM_OPT_TLV(0x7c, GSM_A_PDU_TYPE_DTAP, DE_LLC, NULL);

    ELEM_OPT_TLV(0x7d, GSM_A_PDU_TYPE_DTAP, DE_HLC, NULL);

    ELEM_OPT_T(0xa3, GSM_A_PDU_TYPE_DTAP, DE_REV_CALL_SETUP_DIR, NULL);

    ELEM_OPT_T(0xa4, GSM_A_PDU_TYPE_DTAP, DE_NET_INIT_SERV_UPG, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [4] 9.3.14 Modify complete
 */
static void
dtap_cc_modify_complete(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_BEARER_CAP, NULL);

    ELEM_OPT_TLV(0x7c, GSM_A_PDU_TYPE_DTAP, DE_LLC, NULL);

    ELEM_OPT_TLV(0x7d, GSM_A_PDU_TYPE_DTAP, DE_HLC, NULL);

    ELEM_OPT_T(0xa3, GSM_A_PDU_TYPE_DTAP, DE_REV_CALL_SETUP_DIR, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [4] 9.3.15 Modify reject
 */
static void
dtap_cc_modify_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_BEARER_CAP, NULL);

    ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_CAUSE, NULL);

    ELEM_OPT_TLV(0x7c, GSM_A_PDU_TYPE_DTAP, DE_LLC, NULL);

    ELEM_OPT_TLV(0x7d, GSM_A_PDU_TYPE_DTAP, DE_HLC, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [4] 9.3.16 Notify
 */
static void
dtap_cc_notify(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_NOT_IND, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [4] 9.3.17 Progress
 */
static void
dtap_cc_progress(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_PROG_IND, NULL);

    ELEM_OPT_TLV(0x7e, GSM_A_PDU_TYPE_DTAP, DE_USER_USER, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [4] 9.3.17a CC-Establishment $(CCBS)$
 */
static void
dtap_cc_cc_est(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_SETUP_CONTAINER, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [4] 9.3.17b CC-Establishment confirmed $(CCBS)$
 */
static void
dtap_cc_cc_est_conf(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_OPT_TV_SHORT(0xd0, GSM_A_PDU_TYPE_DTAP, DE_REPEAT_IND, " Repeat indicator");

    ELEM_MAND_TLV(0x04, GSM_A_PDU_TYPE_DTAP, DE_BEARER_CAP, " 1", ei_gsm_a_dtap_missing_mandatory_element);

    ELEM_OPT_TLV(0x04, GSM_A_PDU_TYPE_DTAP, DE_BEARER_CAP, " 2");

    ELEM_OPT_TLV(0x08, GSM_A_PDU_TYPE_DTAP, DE_CAUSE, NULL);

    ELEM_OPT_TLV(0x40, GSM_A_PDU_TYPE_DTAP, DE_SUP_CODEC_LIST, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [4] 9.3.18 Release
 */
static void
dtap_cc_release(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_OPT_TLV(0x08, GSM_A_PDU_TYPE_DTAP, DE_CAUSE, NULL);

    ELEM_OPT_TLV(0x08, GSM_A_PDU_TYPE_DTAP, DE_CAUSE, " 2");

    ELEM_OPT_TLV(0x1c, GSM_A_PDU_TYPE_DTAP, DE_FACILITY, NULL);

    ELEM_OPT_TLV(0x7e, GSM_A_PDU_TYPE_DTAP, DE_USER_USER, NULL);

    /* uplink only */

    ELEM_OPT_TLV(0x7f, GSM_A_PDU_TYPE_DTAP, DE_SS_VER_IND, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [4] 9.3.18a Recall $(CCBS)$
 */
static void
dtap_cc_recall(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_RECALL_TYPE, NULL);

    ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_FACILITY, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [4] 9.3.19 Release complete
 */
static void
dtap_cc_release_complete(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_OPT_TLV(0x08, GSM_A_PDU_TYPE_DTAP, DE_CAUSE, NULL);

    ELEM_OPT_TLV(0x1c, GSM_A_PDU_TYPE_DTAP, DE_FACILITY, NULL);

    ELEM_OPT_TLV(0x7e, GSM_A_PDU_TYPE_DTAP, DE_USER_USER, NULL);

    /* uplink only */

    ELEM_OPT_TLV(0x7f, GSM_A_PDU_TYPE_DTAP, DE_SS_VER_IND, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [4] 9.3.22 Retrieve
 */
static void
dtap_cc_retrieve_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_CAUSE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * 9.3.21 Retrieve Acknowledge
 * No data
 */
/*
 * 9.3.22 Retrieve Reject
 * No data
 */
/*
 * [4] 9.3.23 Setup
 * 3GPP TS 24.008 version 7.5.0 Release 7
 */
static void
dtap_cc_setup(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_OPT_TV_SHORT(0xd0, GSM_A_PDU_TYPE_DTAP, DE_REPEAT_IND, " BC repeat indicator");

    ELEM_OPT_TLV(0x04, GSM_A_PDU_TYPE_DTAP, DE_BEARER_CAP, " 1");

    ELEM_OPT_TLV(0x04, GSM_A_PDU_TYPE_DTAP, DE_BEARER_CAP, " 2");

    ELEM_OPT_TLV(0x1c, GSM_A_PDU_TYPE_DTAP, DE_FACILITY, NULL);

    ELEM_OPT_TLV(0x1e, GSM_A_PDU_TYPE_DTAP, DE_PROG_IND, NULL);

    ELEM_OPT_TV(0x34, GSM_A_PDU_TYPE_DTAP, DE_SIGNAL, NULL);

    ELEM_OPT_TLV(0x5c, GSM_A_PDU_TYPE_DTAP, DE_CLG_PARTY_BCD_NUM, NULL);

    ELEM_OPT_TLV(0x5d, GSM_A_PDU_TYPE_DTAP, DE_CLG_PARTY_SUB_ADDR, NULL);

    ELEM_OPT_TLV(0x5e, GSM_A_PDU_TYPE_DTAP, DE_CLD_PARTY_BCD_NUM, NULL);

    ELEM_OPT_TLV(0x6d, GSM_A_PDU_TYPE_DTAP, DE_CLD_PARTY_SUB_ADDR, NULL);

    ELEM_OPT_TLV(0x74, GSM_A_PDU_TYPE_DTAP, DE_RED_PARTY_BCD_NUM, NULL);

    ELEM_OPT_TLV(0x75, GSM_A_PDU_TYPE_DTAP, DE_RED_PARTY_SUB_ADDR, NULL);

    ELEM_OPT_TV_SHORT(0xd0, GSM_A_PDU_TYPE_DTAP, DE_REPEAT_IND, " LLC repeat indicator");

    ELEM_OPT_TLV(0x7c, GSM_A_PDU_TYPE_DTAP, DE_LLC, " 1");

    ELEM_OPT_TLV(0x7c, GSM_A_PDU_TYPE_DTAP, DE_LLC, " 2");

    ELEM_OPT_TV_SHORT(0xd0, GSM_A_PDU_TYPE_DTAP, DE_REPEAT_IND, " HLC repeat indicator");

    ELEM_OPT_TLV(0x7d, GSM_A_PDU_TYPE_DTAP, DE_HLC, " 1");

    ELEM_OPT_TLV(0x7d, GSM_A_PDU_TYPE_DTAP, DE_HLC, " 2");

    ELEM_OPT_TLV(0x7e, GSM_A_PDU_TYPE_DTAP, DE_USER_USER, NULL);

    /* downlink only */

    ELEM_OPT_TV_SHORT(0x80, GSM_A_PDU_TYPE_COMMON, DE_PRIO, NULL);

    ELEM_OPT_TLV(0x19, GSM_A_PDU_TYPE_DTAP, DE_ALERT_PATTERN, NULL);

    ELEM_OPT_TLV(0x2f, GSM_A_PDU_TYPE_DTAP, DE_NET_CC_CAP, NULL);

    ELEM_OPT_TLV(0x3a, GSM_A_PDU_TYPE_DTAP, DE_CAUSE_NO_CLI, NULL);

    /* Backup bearer capability O TLV 3-15 10.5.4.4a */
    ELEM_OPT_TLV(0x41, GSM_A_PDU_TYPE_DTAP, DE_BEARER_CAP, NULL);

    /* uplink only */

    ELEM_OPT_TLV(0x7f, GSM_A_PDU_TYPE_DTAP, DE_SS_VER_IND, NULL);

    ELEM_OPT_T(0xa1, GSM_A_PDU_TYPE_DTAP, DE_CLIR_SUP, NULL);

    ELEM_OPT_T(0xa2, GSM_A_PDU_TYPE_DTAP, DE_CLIR_INV, NULL);

    ELEM_OPT_TLV(0x15, GSM_A_PDU_TYPE_DTAP, DE_CC_CAP, NULL);

    ELEM_OPT_TLV(0x1d, GSM_A_PDU_TYPE_DTAP, DE_FACILITY, " $(CCBS)$ (advanced recall alignment)");

    ELEM_OPT_TLV(0x1b, GSM_A_PDU_TYPE_DTAP, DE_FACILITY, " (recall alignment Not essential) $(CCBS)$");

    ELEM_OPT_TLV(0x2d, GSM_A_PDU_TYPE_DTAP, DE_SI, NULL);

    ELEM_OPT_TLV(0x40, GSM_A_PDU_TYPE_DTAP, DE_SUP_CODEC_LIST, NULL);

    /*A3 Redial O T 1 10.5.4.34 */
    ELEM_OPT_T(0xA3, GSM_A_PDU_TYPE_DTAP, DE_REDIAL, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [4] 9.3.23a Start CC $(CCBS)$
 */
static void
dtap_cc_start_cc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_OPT_TLV(0x15, GSM_A_PDU_TYPE_DTAP, DE_CC_CAP, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [4] 9.3.24 Start DTMF
 */
static void
dtap_cc_start_dtmf(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_TV(0x2c, GSM_A_PDU_TYPE_DTAP, DE_KEYPAD_FACILITY, NULL, ei_gsm_a_dtap_missing_mandatory_element);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [4] 9.3.25 Start DTMF Acknowledge
 */
static void
dtap_cc_start_dtmf_ack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_MAND_TV(0x2c, GSM_A_PDU_TYPE_DTAP, DE_KEYPAD_FACILITY, NULL, ei_gsm_a_dtap_missing_mandatory_element);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [4] 9.3.26 Start DTMF reject
 */
static void
dtap_cc_start_dtmf_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_CAUSE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [4] 9.3.27 Status
 */
static void
dtap_cc_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_FALSE;

    ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_CAUSE, NULL);

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_CALL_STATE, NULL);

    ELEM_OPT_TLV(0x24, GSM_A_PDU_TYPE_DTAP, DE_AUX_STATES, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}
/*
 * 9.3.28 Status enquiry
 * No data
 */
/*
 * 9.3.29 Stop DTMF
 * No data
 */
/*
 * Stop DTMF acknowledge
 * No data
 */
/*
 * [4] 9.3.31 User information
 */
static void
dtap_cc_user_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_USER_USER, NULL);

    ELEM_OPT_T(0xa0, GSM_A_PDU_TYPE_DTAP, DE_MORE_DATA, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * 3GPP TS 24.080
 * [6] 2.4.2
 */
static void
dtap_ss_register(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_TLV(0x1c, GSM_A_PDU_TYPE_DTAP, DE_FACILITY, NULL, ei_gsm_a_dtap_missing_mandatory_element);

    ELEM_OPT_TLV(0x7f, GSM_A_PDU_TYPE_DTAP, DE_SS_VER_IND, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * 3GPP TS 24.011
 * [5] 7.2.1
 */
static void
dtap_sms_cp_data(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_CP_USER_DATA, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

/*
 * [5] 7.2.3
 */
static void
dtap_sms_cp_error(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    is_uplink = IS_UPLINK_TRUE;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_CP_CAUSE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

static void
dtap_tp_close_tch_loop_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_len = len;
    curr_offset = offset;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_SUB_CHANNEL, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

static void
dtap_tp_open_loop_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_len = len;
    curr_offset = offset;

    if (curr_len)
        ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_ACK, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

static void
dtap_tp_multi_slot_loop_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_len = len;
    curr_offset = offset;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_LOOP_TYPE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

static void
dtap_tp_multi_slot_loop_ack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_len = len;
    curr_offset = offset;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_LOOP_ACK, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

static void
dtap_tp_test_interface(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_len = len;
    curr_offset = offset;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_TESTED_DEVICE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

static void
dtap_tp_gprs_test_mode_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_len = len;
    curr_offset = offset;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_PDU_DESCRIPTION, NULL);

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_MODE_FLAG, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

static void
dtap_tp_egprs_start_radio_block_loopback_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_len = len;
    curr_offset = offset;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_EGPRS_MODE_FLAG, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

static void
dtap_tp_reset_ms_positioning_stored_information(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_len = len;
    curr_offset = offset;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_MS_POSITIONING_TECHNOLOGY, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

static void
dtap_tp_close_ue_test_loop(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_len = len;
    curr_offset = offset;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_UE_TEST_LOOP_MODE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

static void
dtap_tp_reset_ue_positioning_stored_information(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_len = len;
    curr_offset = offset;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_UE_POSITIONING_TECHNOLOGY, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

static void
dtap_tp_ue_test_loop_mode_3_rlc_sdu_counter_response(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_len = len;
    curr_offset = offset;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_RLC_SDU_COUNTER_VALUE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

static void
dtap_tp_epc_close_ue_test_loop(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_len = len;
    curr_offset = offset;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_EPC_UE_TEST_LOOP_MODE, NULL);

    switch (epc_test_loop_mode)
    {
    case 0:
        ELEM_MAND_LV(GSM_A_PDU_TYPE_DTAP, DE_TP_EPC_UE_TL_A_LB_SETUP, NULL);
        break;
    case 1:
        ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_EPC_UE_TL_B_LB_SETUP, NULL);
        break;
    case 2:
        ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_EPC_UE_TL_C_SETUP, NULL);
        break;
    default:
        break;
    }

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

static void
dtap_tp_epc_activate_test_mode(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_len = len;
    curr_offset = offset;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_EPC_UE_TEST_LOOP_MODE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

static void
dtap_tp_epc_reset_ue_positioning_stored_information(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_len = len;
    curr_offset = offset;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_EPC_UE_POSITIONING_TECHNOLOGY, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

static void
dtap_tp_epc_test_loop_mode_c_mbms_packet_counter_response(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_len = len;
    curr_offset = offset;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_EPC_MBMS_PACKET_COUNTER_VALUE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}
static void
dtap_tp_epc_update_ue_location_information(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_len = len;
    curr_offset = offset;

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_EPC_ELLIPSOID_POINT_WITH_ALT, NULL);

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_EPC_HORIZONTAL_VELOCITY, NULL);

    ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_TP_EPC_GNSS_TOD_MSEC, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_dtap_extraneous_data);
}

#define NUM_GSM_DTAP_MSG_GCC (sizeof(gsm_a_dtap_msg_gcc_strings)/sizeof(value_string))
static gint ett_gsm_dtap_msg_gcc[NUM_GSM_DTAP_MSG_GCC];
static void (*dtap_msg_gcc[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len) = {
    dtap_gcc_imm_setup,         /* IMMEDIATE SETUP */
    dtap_gcc_setup,             /* SETUP */
    dtap_gcc_connect,           /* CONNECT */
    dtap_gcc_term,              /* TERMINATION */
    dtap_gcc_term_req,          /* TERMINATION REQUEST */
    dtap_gcc_term_rej,          /* TERMINATION REJECT */
    dtap_gcc_status,            /* STATUS */
    dtap_gcc_get_status,        /* GET STATUS */
    dtap_gcc_set_param,         /* SET PARAMETER */
    NULL,                       /* NONE */
};

#define NUM_GSM_DTAP_MSG_BCC (sizeof(gsm_a_dtap_msg_bcc_strings)/sizeof(value_string))
static gint ett_gsm_dtap_msg_bcc[NUM_GSM_DTAP_MSG_BCC];
static void (*dtap_msg_bcc[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len) = {
    dtap_bcc_imm_setup,         /* IMMEDIATE SETUP */
    dtap_bcc_setup,             /* SETUP */
    dtap_bcc_connect,           /* CONNECT */
    dtap_bcc_term,              /* TERMINATION */
    dtap_bcc_term_req,          /* TERMINATION REQUEST */
    dtap_bcc_term_rej,          /* TERMINATION REJECT */
    dtap_bcc_status,            /* STATUS */
    dtap_bcc_get_status,        /* GET STATUS */
    dtap_bcc_set_param,         /* SET PARAMETER */
    dtap_bcc_imm_setup2,        /* IMMEDIATE SETUP 2 */
    NULL,                       /* NONE */
};

#define NUM_GSM_DTAP_MSG_MM (sizeof(gsm_a_dtap_msg_mm_strings)/sizeof(value_string))
static gint ett_gsm_dtap_msg_mm[NUM_GSM_DTAP_MSG_MM];
static void (*dtap_msg_mm_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len) = {
    dtap_mm_imsi_det_ind,       /* IMSI Detach Indication */
    dtap_mm_loc_upd_acc,        /* Location Updating Accept */
    dtap_mm_loc_upd_rej,        /* Location Updating Reject */
    dtap_mm_loc_upd_req,        /* Location Updating Request */
    NULL                        /* no associated data */,   /* Authentication Reject */
    dtap_mm_auth_req,           /* Authentication Request */
    dtap_mm_auth_resp,          /* Authentication Response */
    dtap_mm_auth_fail,          /* Authentication Failure */
    dtap_mm_id_req,             /* Identity Request */
    dtap_mm_id_resp,            /* Identity Response */
    dtap_mm_tmsi_realloc_cmd,   /* TMSI Reallocation Command */
    NULL                        /* no associated data */,   /* TMSI Reallocation Complete */
    NULL                        /* no associated data */,   /* CM Service Accept */
    dtap_mm_cm_srvc_rej,        /* CM Service Reject */
    NULL                        /* no associated data */,   /* CM Service Abort */
    dtap_mm_cm_srvc_req,        /* CM Service Request */
    dtap_mm_cm_srvc_prompt,     /* CM Service Prompt */
    NULL,                       /* Reserved: was allocated in earlier phases of the protocol */
    dtap_mm_cm_reestab_req,     /* CM Re-establishment Request */
    dtap_mm_abort,              /* Abort */
    NULL                        /* no associated data */,   /* MM Null */
    dtap_mm_mm_status,          /* MM Status */
    dtap_mm_mm_info,            /* MM Information */
    NULL,                       /* NONE */
};

#define NUM_GSM_DTAP_MSG_CC (sizeof(gsm_a_dtap_msg_cc_strings)/sizeof(value_string))
static gint ett_gsm_dtap_msg_cc[NUM_GSM_DTAP_MSG_CC];
static void (*dtap_msg_cc_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len) = {
    dtap_cc_alerting,           /* Alerting */
    dtap_cc_call_conf,          /* Call Confirmed */
    dtap_cc_call_proceed,       /* Call Proceeding */
    dtap_cc_connect,            /* Connect */
    NULL                        /* no associated data */,   /* Connect Acknowledge */
    dtap_cc_emerg_setup,        /* Emergency Setup */
    dtap_cc_progress,           /* Progress */
    dtap_cc_cc_est,             /* CC-Establishment */
    dtap_cc_cc_est_conf,        /* CC-Establishment Confirmed */
    dtap_cc_recall,             /* Recall */
    dtap_cc_start_cc,           /* Start CC */
    dtap_cc_setup,              /* Setup */
    dtap_cc_modify,             /* Modify */
    dtap_cc_modify_complete,    /* Modify Complete */
    dtap_cc_modify_rej,         /* Modify Reject */
    dtap_cc_user_info,          /* User Information */
    NULL                        /* no associated data */,   /* Hold */
    NULL                        /* no associated data */,   /* Hold Acknowledge */
    dtap_cc_hold_rej,           /* Hold Reject */
    NULL                        /* no associated data */,   /* Retrieve */
    NULL                        /* no associated data */,   /* Retrieve Acknowledge */
    dtap_cc_retrieve_rej,       /* Retrieve Reject */
    dtap_cc_disconnect,         /* Disconnect */
    dtap_cc_release,            /* Release */
    dtap_cc_release_complete,   /* Release Complete */
    dtap_cc_congestion_control, /* Congestion Control */
    dtap_cc_notify,             /* Notify */
    dtap_cc_status,             /* Status */
    NULL                        /* no associated data */,   /* Status Enquiry */
    dtap_cc_start_dtmf,         /* Start DTMF */
    NULL                        /* no associated data */,   /* Stop DTMF */
    NULL                        /* no associated data */,   /* Stop DTMF Acknowledge */
    dtap_cc_start_dtmf_ack,     /* Start DTMF Acknowledge */
    dtap_cc_start_dtmf_rej,     /* Start DTMF Reject */
    dtap_cc_facility,           /* Facility */
    NULL,                       /* NONE */
};

#define NUM_GSM_DTAP_MSG_SMS (sizeof(gsm_a_dtap_msg_sms_strings)/sizeof(value_string))
static gint ett_gsm_dtap_msg_sms[NUM_GSM_DTAP_MSG_SMS];
static void (*dtap_msg_sms_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len) = {
    dtap_sms_cp_data,  /* CP-DATA */
    NULL               /* no associated data */,    /* CP-ACK */
    dtap_sms_cp_error, /* CP-ERROR */
    NULL,              /* NONE */
};

#define NUM_GSM_DTAP_MSG_SS (sizeof(gsm_a_dtap_msg_ss_strings)/sizeof(value_string))
static gint ett_gsm_dtap_msg_ss[NUM_GSM_DTAP_MSG_SS];
static void (*dtap_msg_ss_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len) = {
    dtap_cc_release_complete, /* Release Complete */
    dtap_cc_facility,         /* Facility */
    dtap_ss_register,         /* Register */
    NULL,                     /* NONE */
};

#define NUM_GSM_DTAP_MSG_TP (sizeof(gsm_a_dtap_msg_tp_strings)/sizeof(value_string))
static gint ett_gsm_dtap_msg_tp[NUM_GSM_DTAP_MSG_TP];
static void (*dtap_msg_tp_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len) = {
    dtap_tp_close_tch_loop_cmd,                                /* CLOSE TCH LOOP CMD */
    NULL,                                                      /* CLOSE TCH LOOP ACK */
    dtap_tp_open_loop_cmd,                                     /* OPEN LOOP CMD */
    NULL,                                                      /* ACT EMMI CMD */
    NULL,                                                      /* ACT EMMI ACK */
    NULL,                                                      /* DEACT EMMI */
    dtap_tp_test_interface,                                    /* Test Interface */
    dtap_tp_multi_slot_loop_cmd,                               /* CLOSE Multi-slot LOOP CMD */
    dtap_tp_multi_slot_loop_ack,                               /* CLOSE Multi-slot LOOP ACK */
    NULL,                                                      /* OPEN Multi-slot LOOP CMD */
    NULL,                                                      /* OPEN Multi-slot LOOP ACK */
    dtap_tp_gprs_test_mode_cmd,                                /* GPRS TEST MODE CMD */
    dtap_tp_egprs_start_radio_block_loopback_cmd,              /* EGPRS START RADIO BLOCK LOOPBACK CMD */
    dtap_tp_reset_ms_positioning_stored_information,           /* RESET MS POSITIONING STORED INFORMATION */
    dtap_tp_close_ue_test_loop,                                /* CLOSE UE TEST LOOP */
    NULL,                                                      /* CLOSE UE TEST LOOP COMPLETE */
    NULL,                                                      /* OPEN UE TEST LOOP */
    NULL,                                                      /* OPEN UE TEST LOOP COMPLETE */
    NULL,                                                      /* ACTIVATE RB TEST MODE */
    NULL,                                                      /* ACTIVATE RB TEST MODE COMPLETE */
    NULL,                                                      /* DEACTIVATE RB TEST MODE */
    NULL,                                                      /* DEACTIVATE RB TEST MODE COMPLETE */
    dtap_tp_reset_ue_positioning_stored_information,           /* RESET UE POSITIONING STORED INFORMATION */
    NULL,                                                      /* UE TEST LOOP MODE 3 RLC SDU COUNTER REQUEST */
    dtap_tp_ue_test_loop_mode_3_rlc_sdu_counter_response,      /* UE TEST LOOP MODE 3 RLC SDU COUNTER RESPONSE */
    dtap_tp_epc_close_ue_test_loop,                            /* CLOSE UE TEST LOOP */
    NULL,                                                      /* CLOSE UE TEST LOOP COMPLETE */
    NULL,                                                      /* OPEN UE TEST LOOP */
    NULL,                                                      /* OPEN UE TEST LOOP COMPLETE */
    dtap_tp_epc_activate_test_mode,                            /* ACTIVATE TEST MODE */
    NULL,                                                      /* ACTIVATE TEST MODE COMPLETE */
    NULL,                                                      /* DEACTIVATE TEST MODE */
    NULL,                                                      /* DEACTIVATE TEST MODE COMPLETE */
    dtap_tp_epc_reset_ue_positioning_stored_information,       /* RESET UE POSITIONING STORED INFORMATION */
    NULL,                                                      /* UE TEST LOOP MODE C MBMS PACKET COUNTER REQUEST */
    dtap_tp_epc_test_loop_mode_c_mbms_packet_counter_response, /* UE TEST LOOP MODE C MBMS PACKET COUNTER RESPONSE */
    dtap_tp_epc_update_ue_location_information,                /* UPDATE UE LOCATION INFORMATION */
    NULL,                                                      /* NONE */
};

/* GENERIC DISSECTOR FUNCTIONS */

static int
dissect_dtap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    static gsm_a_tap_rec_t  tap_rec[4];
    static gsm_a_tap_rec_t *tap_p;
    static guint            tap_current = 0;

    void  (*dtap_msg_fcn)(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len);

    guint8        oct;
    guint8        pd;
    guint32       offset;
    guint32       len;
    guint32       oct_1;
    gint          idx;
    proto_item   *dtap_item   = NULL;
    proto_tree   *dtap_tree   = NULL;
    proto_item   *oct_1_item  = NULL;
    proto_tree   *pd_tree     = NULL;
    const gchar  *msg_str;
    gint          ett_tree;
    gint          ti;
    int       hf_idx;
    gboolean      nsd;
    sccp_msg_info_t* sccp_msg = (sccp_msg_info_t*)data;


    len = tvb_reported_length(tvb);

    if (len < 2)
    {
        /*
         * too short to be DTAP
         */
        call_data_dissector(tvb, pinfo, tree);
        return len;
    }

    col_append_str(pinfo->cinfo, COL_INFO, "(DTAP) ");

    /*
     * set tap record pointer
     */
    tap_current++;
    if (tap_current >= 4)
    {
        tap_current = 0;
    }
    tap_p = &tap_rec[tap_current];


    offset = 0;

    g_tree = tree;

    /*
     * get protocol discriminator
     */
    oct_1 = tvb_get_guint8(tvb, offset++);

    if ((((oct_1 & DTAP_TI_MASK) >> 4) & DTAP_TIE_PRES_MASK) == DTAP_TIE_PRES_MASK)
    {
        /*
         * eventhough we don't know if a TI should be in the message yet
         * we rely on the TI/SKIP indicator to be 0 to avoid taking this
         * octet
         */
        offset++;
    }

    oct = tvb_get_guint8(tvb, offset);

    pd = oct_1 & DTAP_PD_MASK;
    ti = -1;
    msg_str = NULL;
    ett_tree = -1;
    hf_idx = -1;
    dtap_msg_fcn = NULL;
    nsd = FALSE;
    col_append_fstr(pinfo->cinfo, COL_INFO, "(%s) ",val_to_str_const(pd,gsm_a_pd_short_str_vals,"unknown"));

    /*
     * octet 1
     */
    /* Initialize hf_idx, ett_tree and dtap_msg_fcn.
       ett_tree and dtap_msg_fcn will not be used if msg_str == NULL. */
    switch (pd)
    {
    case 0:
        msg_str = try_val_to_str_idx((guint32) (oct & DTAP_GCC_IEI_MASK), gsm_a_dtap_msg_gcc_strings, &idx);
        if (msg_str != NULL)
        {
            ett_tree = ett_gsm_dtap_msg_gcc[idx];
            dtap_msg_fcn = dtap_msg_gcc[idx];
        }
        hf_idx = hf_gsm_a_dtap_msg_gcc_type;
        ti = (oct_1 & DTAP_TI_MASK) >> 4;
        nsd = TRUE;
        break;
    case 1:
        msg_str = try_val_to_str_idx((guint32) (oct & DTAP_BCC_IEI_MASK), gsm_a_dtap_msg_bcc_strings, &idx);
        if (msg_str != NULL)
        {
            ett_tree = ett_gsm_dtap_msg_bcc[idx];
            dtap_msg_fcn = dtap_msg_bcc[idx];
        }
        hf_idx = hf_gsm_a_dtap_msg_bcc_type;
        ti = (oct_1 & DTAP_TI_MASK) >> 4;
        nsd = TRUE;
        break;
    case 3:
        msg_str = try_val_to_str_idx((guint32) (oct & DTAP_CC_IEI_MASK), gsm_a_dtap_msg_cc_strings, &idx);
        if (msg_str != NULL)
        {
            ett_tree = ett_gsm_dtap_msg_cc[idx];
            dtap_msg_fcn = dtap_msg_cc_fcn[idx];
        }
        hf_idx = hf_gsm_a_dtap_msg_cc_type;
        ti = (oct_1 & DTAP_TI_MASK) >> 4;
        nsd = TRUE;
        break;

    case 5:
        msg_str = try_val_to_str_idx((guint32) (oct & DTAP_MM_IEI_MASK), gsm_a_dtap_msg_mm_strings, &idx);
        if (msg_str != NULL)
        {
            ett_tree = ett_gsm_dtap_msg_mm[idx];
            dtap_msg_fcn = dtap_msg_mm_fcn[idx];
        }
        hf_idx = hf_gsm_a_dtap_msg_mm_type;
        nsd = TRUE;
        break;

    case 6:
        get_rr_msg_params(oct, &msg_str, &ett_tree, &hf_idx, &dtap_msg_fcn);
        break;

    case 8:
        get_gmm_msg_params(oct, &msg_str, &ett_tree, &hf_idx, &dtap_msg_fcn);
        break;

    case 9:
        msg_str = try_val_to_str_idx((guint32) (oct & DTAP_SMS_IEI_MASK), gsm_a_dtap_msg_sms_strings, &idx);
        hf_idx = hf_gsm_a_dtap_msg_sms_type;
        if (msg_str != NULL)
        {
            ett_tree = ett_gsm_dtap_msg_sms[idx];
            dtap_msg_fcn = dtap_msg_sms_fcn[idx];
        }
        ti = (oct_1 & DTAP_TI_MASK) >> 4;
        break;

    case 10:
        get_sm_msg_params(oct, &msg_str, &ett_tree, &hf_idx, &dtap_msg_fcn);
        ti = (oct_1 & DTAP_TI_MASK) >> 4;
        break;

    case 11:
        msg_str = try_val_to_str_idx((guint32) (oct & DTAP_SS_IEI_MASK), gsm_a_dtap_msg_ss_strings, &idx);
        hf_idx = hf_gsm_a_dtap_msg_ss_type;
        if (msg_str != NULL)
        {
            ett_tree = ett_gsm_dtap_msg_ss[idx];
            dtap_msg_fcn = dtap_msg_ss_fcn[idx];
        }
        ti = (oct_1 & DTAP_TI_MASK) >> 4;
        nsd = TRUE;
        break;

    case 15:
        msg_str = try_val_to_str_idx((guint32) (oct & DTAP_TP_IEI_MASK), gsm_a_dtap_msg_tp_strings, &idx);
        hf_idx = hf_gsm_a_dtap_msg_tp_type;
        if (msg_str != NULL)
        {
            ett_tree = ett_gsm_dtap_msg_tp[idx];
            dtap_msg_fcn = dtap_msg_tp_fcn[idx];
        }
        nsd = TRUE;
        break;

    default:
        /* XXX - hf_idx is still -1! this is a bug in the implementation, and I don't know how to fix it so simple return here */
        return len;
    }

    if (sccp_msg && sccp_msg->data.co.assoc) {
        sccp_assoc = sccp_msg->data.co.assoc;
    }
    else
    {
        sccp_assoc = NULL;
        sccp_msg = NULL;
    }

    /*
     * create the protocol tree
     */
    if (msg_str == NULL)
    {
        dtap_item =
            proto_tree_add_protocol_format(tree, proto_a_dtap, tvb, 0, len,
            "GSM A-I/F DTAP - Unknown DTAP Message Type (0x%02x)",
            oct);

        dtap_tree = proto_item_add_subtree(dtap_item, ett_dtap_msg);

        if (sccp_msg && !sccp_msg->data.co.label) {
            sccp_msg->data.co.label = wmem_strdup_printf(wmem_file_scope(), "DTAP (0x%02x)",oct);
        }


    }
    else
    {
        dtap_item =
            proto_tree_add_protocol_format(tree, proto_a_dtap, tvb, 0, -1,
                "GSM A-I/F DTAP - %s",
                msg_str);

        dtap_tree = proto_item_add_subtree(dtap_item, ett_tree);

        if (sccp_msg && !sccp_msg->data.co.label) {
            sccp_msg->data.co.label = wmem_strdup(wmem_file_scope(), msg_str);
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", msg_str);
        col_set_fence(pinfo->cinfo, COL_INFO);
    }

    oct_1_item = proto_tree_add_uint(dtap_tree, hf_gsm_a_dtap_protocol_discriminator, tvb, 0, 1, pd);
    pd_tree = proto_item_add_subtree(oct_1_item, ett_dtap_oct_1);

    proto_tree_add_item(pd_tree, hf_gsm_a_L3_protocol_discriminator, tvb, 0, 1, ENC_BIG_ENDIAN);

    if (ti == -1)
    {
        proto_tree_add_item(pd_tree, hf_gsm_a_skip_ind, tvb, 0, 1, ENC_BIG_ENDIAN);
    }
    else
    {

        proto_tree_add_item(pd_tree, hf_gsm_a_dtap_ti_flag, tvb, 0, 1, ENC_NA);

        if ((ti & DTAP_TIE_PRES_MASK) == DTAP_TIE_PRES_MASK)
        {
            /* ti is extended to next octet */
            proto_tree_add_uint_format_value(pd_tree, hf_gsm_a_dtap_tio, tvb, 0, 1,
                oct_1, "The TI value is given by the TIE in octet 2");
        }
        else
        {
            proto_tree_add_item(pd_tree, hf_gsm_a_dtap_tio, tvb, 0, 1, ENC_BIG_ENDIAN);
        }
    }

    if ((ti != -1) &&
        (ti & DTAP_TIE_PRES_MASK) == DTAP_TIE_PRES_MASK)
    {
        proto_tree_add_item(tree, hf_gsm_a_extension, tvb, 1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(pd_tree, hf_gsm_a_dtap_tie, tvb, 1, 1, ENC_BIG_ENDIAN);
    }

    /*
     * N(SD)
     */
    if ((pinfo->p2p_dir == P2P_DIR_RECV) &&
        nsd)
    {
        /* XXX */
    }
    /* 3GPP TS 24.008 version 8.5.0 Release 8
     * Bits 5 to 8 of the first octet of every message belonging to the protocols "Call Control;
     * call related SS messages" and "Session Management"contain the transaction identifier (TI).
     * The transaction identifier and its use are defined in 3GPP TS 24.007 [20].
     *  5 = Mobility Management messages
     *  3 = Call Control; call related SS messages
     * 10 = GPRS session management messages
     * 11 = Non call related SS messages
     */
    if ((pd == 5) || (pd == 3) || (pd == 10) || (pd == 11)) {
        proto_tree_add_item(dtap_tree, hf_gsm_a_seq_no, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    /*
     * add DTAP message name
     */
    proto_tree_add_item(dtap_tree, hf_idx, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    tap_p->pdu_type = GSM_A_PDU_TYPE_DTAP;
    tap_p->message_type = (nsd ? (oct & 0x3f) : oct);
    tap_p->protocol_disc = (gsm_a_pd_str_e)pd;

    tap_queue_packet(gsm_a_tap, pinfo, tap_p);

    if (msg_str == NULL) return len;

    if (offset >= len) return len;

    /*
     * decode elements
     */
    if (dtap_msg_fcn == NULL)
    {
        proto_tree_add_item(dtap_tree, hf_gsm_a_dtap_message_elements, tvb, offset, len - offset, ENC_NA);
    }
    else
    {
        (*dtap_msg_fcn)(tvb, dtap_tree, pinfo, offset, len - offset);
    }

    return len;
}


/* Register the protocol with Wireshark */
void
proto_register_gsm_a_dtap(void)
{
    guint i;
    guint last_offset;

    /* Setup list of header fields */

    static hf_register_info hf[] = {
        { &hf_gsm_a_seq_no,
          { "Sequence number", "gsm_a.dtap.seq_no",
            FT_UINT8, BASE_DEC, NULL, 0xc0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_msg_gcc_type,
          { "DTAP Group Call Control Message Type", "gsm_a.dtap.msg_gcc_type",
            FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_msg_gcc_strings), 0x3f,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_msg_bcc_type,
          { "DTAP Broadcast Call Control Message Type", "gsm_a.dtap.msg_bcc_type",
            FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_msg_bcc_strings), 0x3f,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_msg_mm_type,
          { "DTAP Mobility Management Message Type", "gsm_a.dtap.msg_mm_type",
            FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_msg_mm_strings), 0x3f,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_msg_cc_type,
          { "DTAP Call Control Message Type", "gsm_a.dtap.msg_cc_type",
            FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_msg_cc_strings), 0x3f,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_msg_sms_type,
          { "DTAP Short Message Service Message Type", "gsm_a.dtap.msg_sms_type",
            FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_msg_sms_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_msg_ss_type,
          { "DTAP Non call Supplementary Service Message Type", "gsm_a.dtap.msg_ss_type",
            FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_msg_ss_strings), 0x3f,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_msg_tp_type,
          { "DTAP Tests Procedures Message Type", "gsm_a.dtap.msg_tp_type",
            FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_msg_tp_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_elem_id,
          { "Element ID", "gsm_a.dtap.elem_id",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_cld_party_bcd_num,
          { "Called Party BCD Number", "gsm_a.dtap.cld_party_bcd_num",
            FT_STRING, BASE_NONE, 0, 0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_clg_party_bcd_num,
          { "Calling Party BCD Number", "gsm_a.dtap.clg_party_bcd_num",
            FT_STRING, BASE_NONE, 0, 0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_conn_num,
          { "Connected Number", "gsm_a.dtap.conn_num",
            FT_STRING, BASE_NONE, 0, 0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_red_party_bcd_num,
          { "Redirecting Party BCD Number", "gsm_a.dtap.red_party_bcd_num",
            FT_STRING, BASE_NONE, 0, 0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_cause,
          { "DTAP Cause", "gsm_a.dtap.cause",
            FT_UINT8, BASE_HEX, 0, 0x7f,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_type_of_number,
          { "Type of number", "gsm_a.dtap.type_of_number",
            FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_type_of_number_values), 0x70,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_numbering_plan_id,
          { "Numbering plan identification", "gsm_a.dtap.numbering_plan_id",
            FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_numbering_plan_id_values), 0x0f,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_present_ind,
          { "Presentation indicator", "gsm_a.dtap.present_ind",
            FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_present_ind_values), 0x60,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_screening_ind,
          { "Screening indicator", "gsm_a.dtap.screening_ind",
            FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_screening_ind_values), 0x03,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_type_of_sub_addr,
          { "Type of subaddress", "gsm_a.dtap.type_of_sub_addr",
            FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_type_of_sub_addr_values), 0x70,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_odd_even_ind,
          { "Odd/even indicator", "gsm_a.dtap.odd_even_ind",
            FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_odd_even_ind_values), 0x08,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_lsa_id,
          { "LSA Identifier", "gsm_a.dtap.lsa_id",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_speech_vers_ind,
          { "Speech version indication", "gsm_a.dtap.speech_vers_ind",
            FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_speech_vers_ind_values), 0x0f,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_itc,
          { "Information transfer capability", "gsm_a.dtap.itc",
            FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_itc_values), 0x07,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_sysid,
          { "System Identification (SysID)", "gsm_a.dtap.sysid",
            FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_sysid_values), 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_bitmap_length,
          { "Bitmap Length", "gsm_a.dtap.bitmap_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_serv_cat_b7,
          { "Automatically initiated eCall", "gsm_a.dtap.serv_cat_b7",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_serv_cat_b6,
          { "Manually initiated eCall", "gsm_a.dtap.serv_cat_b6",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_serv_cat_b5,
          { "Mountain Rescue", "gsm_a.dtap.serv_cat_b5",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_serv_cat_b4,
          { "Marine Guard", "gsm_a.dtap.serv_cat_b4",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_serv_cat_b3,
          { "Fire Brigade", "gsm_a.dtap.serv_cat_b3",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_serv_cat_b2,
          { "Ambulance", "gsm_a.dtap.serv_cat_b2",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_serv_cat_b1,
          { "Police", "gsm_a.dtap.serv_cat_b1",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_csmo,
          { "CSMO", "gsm_a.dtap.csmo",
            FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_dtap_csmo_value), 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_csmt,
          { "CSMT", "gsm_a.dtap.csmt",
            FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_dtap_csmt_value), 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_mm_timer_unit,
          { "Unit", "gsm_a.dtap.mm_timer_unit",
            FT_UINT8, BASE_DEC, VALS(gsm_a_dtap_mm_timer_unit_vals), 0xe0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_mm_timer_value,
          { "Timer value", "gsm_a.dtap.mm_timer_value",
            FT_UINT8, BASE_DEC, NULL, 0x1f,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_alerting_pattern,
          { "Alerting Pattern", "gsm_a.dtap.alerting_pattern",
            FT_UINT8, BASE_DEC, VALS(gsm_a_alerting_pattern_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_ccbs_activation,
          { "CCBS Activation", "gsm_a.dtap.ccbs_activation",
            FT_BOOLEAN, 8, TFS(&gsm_a_ccbs_activation_value), 0x80,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_stream_identifier,
          { "Stream Identifier", "gsm_a.dtap.stream_identifier",
            FT_UINT8, BASE_HEX, 0, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_mcs,
          { "MCS", "gsm_a.dtap.mcs",
            FT_BOOLEAN, 8, TFS(&gsm_a_mcs_value), 0x01,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_cause_of_no_cli,
          { "Cause of no CLI", "gsm_a.dtap.cause_of_no_cli",
            FT_UINT8, BASE_HEX, 0, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_cause_ss_diagnostics,
          { "Supplementary Services Diagnostics", "gsm_a.dtap.cause_ss_diagnostics",
            FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_cause_ss_diagnostics_vals), 0x7f,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_codec_tdma_efr,
          { "TDMA EFR", "gsm_a.dtap.codec.tdma_efr",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_codec_umts_amr_2,
          { "UMTS AMR 2", "gsm_a.dtap.codec.umts_amr_2",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_codec_umts_amr,
          { "UMTS AMR", "gsm_a.dtap.codec.umts_amr",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_codec_hr_amr,
          { "HR AMR", "gsm_a.dtap.codec.hr_amr",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_codec_fr_amr,
          { "FR AMR", "gsm_a.dtap.codec.fr_amr",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_codec_gsm_efr,
          { "GSM EFR", "gsm_a.dtap.codec.gsm_efr",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_codec_gsm_hr,
          { "GSM HR", "gsm_a.dtap.codec.gsm_hr",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_codec_gsm_fr,
          { "GSM FR", "gsm_a.dtap.codec.gsm_fr",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_codec_ohr_amr_wb,
          { "OHR AMR-WB", "gsm_a.dtap.codec.ohr_amr_wb",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_codec_ofr_amr_wb,
          { "OFR AMR-WB", "gsm_a.dtap.codec.ofr_amr_wb",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_codec_ohr_amr,
          { "OHR AMR", "gsm_a.dtap.codec.ohr_amr",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_codec_umts_amr_wb,
          { "UMTS AMR-WB", "gsm_a.dtap.codec.umts_amr_wb",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_codec_fr_amr_wb,
          { "FR AMR-WB", "gsm_a.dtap.codec.fr_amr_wb",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_codec_pdc_efr,
          { "PDC EFR", "gsm_a.dtap.codec.pdc_efr",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_notification_description,
          { "Notification description", "gsm_a.dtap.notif_descr",
            FT_UINT8, BASE_DEC, VALS(gsm_a_dtap_notification_description_vals), 0x7f,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_emerg_num_info_length,
          { "Emergency Number Info length", "gsm_a.dtap.emerg_num_info_length",
            FT_UINT8, BASE_DEC, 0, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_emergency_bcd_num,
          { "Emergency BCD Number", "gsm_a.dtap.emergency_bcd_num",
            FT_STRING, BASE_NONE, 0, 0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_signal_value,
          { "Signal value", "gsm_a.dtap.signal_value",
            FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_signal_value_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_recall_type,
          { "Recall type", "gsm_a.dtap.recall_type",
            FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(gsm_a_dtap_recall_type_vals), 0x07,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_coding_standard,
          { "Coding standard", "gsm_a.dtap.coding_standard",
            FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_coding_standard_vals), 0xc0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_call_state,
          { "Call state", "gsm_a.dtap.call_state",
            FT_UINT8, BASE_DEC, NULL, 0x3f,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_prog_coding_standard,
          { "Coding standard", "gsm_a.dtap.coding_standard",
            FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_coding_standard_vals), 0x60,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_location,
          { "Location", "gsm_a.dtap.location",
            FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_location_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_progress_description,
          { "Progress description", "gsm_a.dtap.progress_description",
            FT_UINT8, BASE_DEC, NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_afi,
          { "Authority and Format Identifier", "gsm_a.dtap.afi",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &x213_afi_value_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_rej_cause,
          { "Reject cause", "gsm_a.dtap.rej_cause",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_timezone,
          { "Timezone", "gsm_a.dtap.timezone",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_u2u_prot_discr,
          { "User-user protocol discriminator", "gsm_a.dtap.u2u_prot_discr",
            FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(gsm_a_dtap_u2u_prot_discr_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_mcat,
          { "MCAT", "gsm_a.dtap.mcat",
            FT_BOOLEAN, 8, TFS(&gsm_a_dtap_mcat_value), 0x08,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_enicm,
          { "ENICM", "gsm_a.dtap.mcat",
            FT_BOOLEAN, 8, TFS(&gsm_a_dtap_enicm_value), 0x04,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_rand,
          { "RAND value", "gsm_a.dtap.rand",
            FT_BYTES, FT_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_autn,
          { "AUTN value", "gsm_a.dtap.autn",
            FT_BYTES, FT_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_sres,
          { "SRES value", "gsm_a.dtap.sres",
            FT_BYTES, FT_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_xres,
          { "XRES value", "gsm_a.dtap.xres",
            FT_BYTES, FT_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_auts,
          { "AUTS value", "gsm_a.dtap.auts",
            FT_BYTES, FT_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_autn_sqn_xor_ak,
          { "SQN xor AK", "gsm_a.dtap.autn.sqn_xor_ak",
            FT_BYTES, FT_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_autn_amf,
          { "AMF", "gsm_a.dtap.autn.amf",
            FT_BYTES, FT_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_autn_mac,
          { "MAC", "gsm_a.dtap.autn.mac",
            FT_BYTES, FT_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_auts_sqn_ms_xor_ak,
          { "SQN_MS xor AK", "gsm_a.dtap.auts.sqn_ms_xor_ak",
            FT_BYTES, FT_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_auts_mac_s,
          { "MAC-S", "gsm_a.dtap.auts.mac_s",
            FT_BYTES, FT_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_epc_ue_tl_mode,
          { "UE test loop mode","gsm_a.dtap.epc.ue_tl_mode",
            FT_UINT8,BASE_DEC, VALS(epc_ue_test_loop_mode_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_epc_ue_tl_a_ul_sdu_size,
          { "Uplink PDCP SDU size in bits","gsm_a.dtap.epc.ue_tl_a_ul_sdu_size",
            FT_UINT16,BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_epc_ue_tl_a_drb,
          { "Data Radio Bearer identity number","gsm_a.dtap.epc.ue_tl_a_drb",
            FT_UINT8,BASE_DEC, NULL, 0x1f,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_epc_ue_tl_b_ip_pdu_delay,
          { "IP PDU delay in seconds","gsm_a.dtap.epc.ue_tl_b_ip_pdu_delay",
            FT_UINT8,BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_epc_ue_tl_c_mbsfn_area_id,
          { "MBSFN area identity","gsm_a.dtap.epc.ue_tl_c_mbsfn_area_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_epc_ue_tl_c_mch_id,
          { "MCH identity","gsm_a.dtap.epc.ue_tl_c_mch_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_epc_ue_tl_c_lcid,
          { "Logical channel identity","gsm_a.dtap.epc.ue_tl_c_lcid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_epc_ue_positioning_technology,
          { "UE positioning technology","gsm_a.dtap.epc.ue_positioning_technology",
            FT_UINT8, BASE_DEC, VALS(epc_ue_positioning_technology_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_epc_mbms_packet_counter_value,
          { "MBMS packet counter value","gsm_a.dtap.epc.mbms_packet_counter_value",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_epc_latitude_sign,
          { "Latitude Sign","gsm_a.dtap.epc.latitude_sign",
            FT_BOOLEAN, BASE_NONE, TFS(&epc_latitude_sign_value), 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_epc_degrees_latitude,
          { "Degrees Latitude","gsm_a.dtap.epc.degrees_latitude",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_epc_degrees_longitude,
          { "Degrees Longitude","gsm_a.dtap.epc.degrees_longitude",
            FT_INT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_epc_altitude_dir,
          { "Altitude Direction","gsm_a.dtap.epc.altitude_direction",
            FT_BOOLEAN, BASE_NONE, TFS(&epc_altitude_dir_value), 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_epc_altitude,
          { "Altitude","gsm_a.dtap.epc.altitude",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_epc_bearing,
          { "Bearing","gsm_a.dtap.epc.bearing",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_epc_horizontal_speed,
          { "Horizontal Speed","gsm_a.dtap.epc.horizontal_speed",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_epc_gnss_tod_msec,
          { "GNSS-TOD-msec","gsm_a.dtap.epc.gnss_tod_msec",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_gcc_call_ref,
          { "Call Reference", "gsm_a.dtap.gcc.call_ref",
            FT_UINT32, BASE_DEC, NULL, 0xffffffe0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_gcc_call_ref_has_priority,
          { "Call Reference includes priority", "gsm_a.dtap.gcc.call_ref_has_priority",
            FT_BOOLEAN, 32, NULL, 0x00000010,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_gcc_call_priority,
          { "Call Priority", "gsm_a.dtap.gcc.call_priority",
            FT_UINT32, BASE_DEC, VALS(gcc_call_ref_priority), 0x0000000e,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_gcc_call_state,
          { "Call state", "gsm_a.dtap.gcc.call_state",
            FT_UINT24, BASE_DEC, VALS(gcc_call_state_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_gcc_cause_structure,
          { "Cause structure", "gsm_a.dtap.gcc.cause_structure",
            FT_BOOLEAN, 8, TFS(&gcc_cause_structure_val), 0x80,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_gcc_cause,
          { "Cause", "gsm_a.dtap.gcc.cause",
            FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gcc_cause_vals), 0x7f,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_gcc_orig_ind,
          { "Originator indication", "gsm_a.dtap.gcc.orig_ind",
            FT_BOOLEAN, 8, TFS(&gcc_orig_ind_vals), 0x01,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_gcc_state_attr,
          { "State attributes", "gsm_a.dtap.gcc.state_attr",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_gcc_state_attr_da,
          { "DA", "gsm_a.dtap.gcc.state_attr_da",
            FT_BOOLEAN, 8, TFS(&gcc_state_attr_da), 0x08,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_gcc_state_attr_ua,
          { "UA", "gsm_a.dtap.gcc.state_attr_ua",
            FT_BOOLEAN, 8, TFS(&gcc_state_attr_ua), 0x04,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_gcc_state_attr_comm,
          { "COMM", "gsm_a.dtap.gcc.state_attr_comm",
            FT_BOOLEAN, 8, TFS(&gcc_state_attr_comm), 0x02,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_gcc_state_attr_oi,
          { "OI", "gsm_a.dtap.gcc.state_attr_oi",
            FT_BOOLEAN, 8, TFS(&gcc_state_attr_oi), 0x01,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_gcc_spare_1,
          { "Spare_1 (This field shall be ignored)", "gsm_a.dtap.gcc.spare_1",
            FT_UINT32, BASE_DEC, NULL, 0x00000001,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_gcc_spare_3,
          { "Spare_3 (This field shall be ignored)", "gsm_a.dtap.gcc.spare_3",
            FT_UINT8, BASE_DEC, NULL, 0x0e,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_gcc_spare_4,
          { "Spare_4 (This field shall be ignored)", "gsm_a.dtap.gcc.spare_4",
            FT_UINT32, BASE_DEC, NULL, 0x00000010,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_bcc_call_ref,
        { "Call Reference", "gsm_a.dtap.bcc.call_ref",
            FT_UINT32, BASE_DEC, NULL, 0xffffffe0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_bcc_call_ref_has_priority,
          { "Call Reference includes priority", "gsm_a.dtap.bcc.call_ref_has_priority",
            FT_BOOLEAN, 32, NULL, 0x00000010,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_bcc_call_priority,
          { "Call Priority", "gsm_a.dtap.bcc.call_priority",
            FT_UINT32, BASE_DEC, VALS(bcc_call_ref_priority), 0x0000000e,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_bcc_call_state,
          { "Call state", "gsm_a.dtap.bcc.call_state",
            FT_UINT24, BASE_DEC|BASE_RANGE_STRING, RVALS(bcc_call_state_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_bcc_cause_structure,
          { "Cause structure", "gsm_a.dtap.bcc.cause_structure",
            FT_BOOLEAN, 8, TFS(&bcc_cause_structure_val), 0x80,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_bcc_cause,
          { "Cause", "gsm_a.dtap.bcc.cause",
            FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(bcc_cause_vals), 0x7f,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_bcc_orig_ind,
          { "Originator indication", "gsm_a.dtap.bcc.orig_ind",
            FT_BOOLEAN, 8, TFS(&bcc_orig_ind_vals), 0x01,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_bcc_state_attr,
          { "State attributes", "gsm_a.dtap.bcc.state_attr",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_bcc_state_attr_da,
          { "DA", "gsm_a.dtap.bcc.state_attr_da",
            FT_BOOLEAN, 8, TFS(&bcc_state_attr_da), 0x08,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_bcc_state_attr_ua,
          { "UA", "gsm_a.dtap.bcc.state_attr_ua",
            FT_BOOLEAN, 8, TFS(&bcc_state_attr_ua), 0x04,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_bcc_state_attr_comm,
          { "COMM", "gsm_a.dtap.bcc.state_attr_comm",
            FT_BOOLEAN, 8, TFS(&bcc_state_attr_comm), 0x02,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_bcc_state_attr_oi,
          { "OI", "gsm_a.dtap.bcc.state_attr_oi",
            FT_BOOLEAN, 8, TFS(&bcc_state_attr_oi), 0x01,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_bcc_compr_otdi,
          { "Compressed otdi", "gsm_a.dtap.bcc.compr_otdi",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_bcc_spare_1,
          { "Spare_1 (This field shall be ignored)", "gsm_a.dtap.bcc.spare_1",
            FT_UINT32, BASE_DEC, NULL, 0x00000001,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_bcc_spare_3,
          { "Spare_3 (This field shall be ignored)", "gsm_a.dtap.bcc.spare_3",
            FT_UINT8, BASE_DEC, NULL, 0x0e,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_bcc_spare_4,
          { "Spare_4 (This field shall be ignored)", "gsm_a.dtap.bcc.spare_4",
            FT_UINT32, BASE_DEC, NULL, 0x00000010,
            NULL, HFILL }
        },
        /* Generated from convert_proto_tree_add_text.pl */
        { &hf_gsm_a_dtap_coding_scheme,
          { "Coding Scheme", "gsm_a.dtap.coding_scheme",
            FT_UINT8, BASE_DEC, VALS(gsm_a_dtap_coding_scheme_vals), 0x70,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_add_ci,
          { "Add CI", "gsm_a.dtap.add_ci",
            FT_BOOLEAN, 8, TFS(&tfs_add_ci), 0x08,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_number_of_spare_bits,
          { "Number of spare bits in last octet", "gsm_a.dtap.number_of_spare_bits",
            FT_UINT8, BASE_DEC, VALS(gsm_a_dtap_number_of_spare_bits_vals), 0x07,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_text_string,
          { "Text String", "gsm_a.dtap.text_string",
            FT_STRING, STR_UNICODE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_time_zone_time,
          { "Time", "gsm_a.dtap.time_zone_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_dst_adjustment,
          { "DST Adjustment", "gsm_a.dtap.dst_adjustment",
            FT_UINT8, BASE_DEC, VALS(gsm_a_dtap_dst_adjustment_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_emergency_number_information,
          { "Emergency Number Information", "gsm_a.dtap.emergency_number_information",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_mm_timer,
          { "MM Timer", "gsm_a.dtap.mm_timer",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_hold_auxiliary_state,
          { "Hold auxiliary state", "gsm_a.dtap.hold_auxiliary_state",
            FT_UINT8, BASE_DEC, VALS(gsm_a_dtap_hold_auxilary_state_vals), 0x0C,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_multi_party_auxiliary_state,
          { "Multi party auxiliary state", "gsm_a.dtap.multi_party_auxiliary_state",
            FT_UINT8, BASE_DEC, VALS(gsm_a_dtap_multi_party_auxilary_state_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_radio_channel_requirement,
          { "Radio channel requirement", "gsm_a.dtap.radio_channel_requirement",
            FT_UINT8, BASE_DEC, NULL, 0x60,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_bearer_cap_coding_standard,
          { "Coding standard", "gsm_a.dtap.cap_coding_standard",
            FT_BOOLEAN, 8, TFS(&tfs_bearer_cap_coding_standard), 0x10,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_transfer_mode,
          { "Transfer mode", "gsm_a.dtap.transfer_mode",
            FT_BOOLEAN, 8, TFS(&tfs_bearer_cap_transfer_mode), 0x08,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_coding,
          { "Coding", "gsm_a.dtap.coding",
            FT_BOOLEAN, 8, TFS(&tfs_bearer_cap_coding), 0x40,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_compression,
          { "Compression", "gsm_a.dtap.compression",
            FT_BOOLEAN, 8, TFS(&tfs_possible_not_possible), 0x40,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_compression_up,
          { "Compression", "gsm_a.dtap.compression",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x40,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_structure,
          { "Structure", "gsm_a.dtap.structure",
            FT_UINT8, BASE_DEC, VALS(gsm_a_dtap_structure_vals), 0x30,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_duplex_mode,
          { "Duplex mode", "gsm_a.dtap.duplex_mode",
            FT_BOOLEAN, 8, TFS(&tfs_full_half), 0x08,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_subaddress,
          { "Subaddress", "gsm_a.dtap.subaddress",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_subaddress_information,
          { "Subaddress information", "gsm_a.dtap.subaddress_information",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_message_elements,
          { "Message Elements", "gsm_a.dtap.message_elements",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_rpdu,
          { "RPDU", "gsm_a.dtap.rpdu",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_configuration,
          { "Configuration", "gsm_a.dtap.configuration",
            FT_BOOLEAN, 8, TFS(&tfs_bearer_cap_configuration), 0x04,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_nirr,
          { "NIRR", "gsm_a.dtap.nirr",
            FT_BOOLEAN, 8, TFS(&tfs_nirr), 0x02,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_establishment,
          { "Establishment", "gsm_a.dtap.establishment",
            FT_BOOLEAN, 8, TFS(&tfs_bearer_cap_establishment), 0x01,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_access_identity,
          { "Access Identity", "gsm_a.dtap.access_identity",
            FT_UINT8, BASE_DEC, VALS(gsm_a_dtap_access_identity_vals), 0x60,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_rate_adaption,
          { "Rate Adaption", "gsm_a.dtap.rate_adaption",
            FT_UINT8, BASE_DEC, VALS(gsm_a_dtap_rate_adaption_vals), 0x18,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_signalling_access_protocol,
          { "Signalling Access Protocol", "gsm_a.dtap.signalling_access_protocol",
            FT_UINT8, BASE_DEC, VALS(gsm_a_dtap_signal_access_protocol_vals), 0x07,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_other_itc,
          { "Other ITC", "gsm_a.dtap.other_itc",
            FT_UINT8, BASE_DEC, VALS(gsm_a_dtap_other_itc_vals), 0x60,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_other_rate_adaption,
          { "Other Rate Adaption", "gsm_a.dtap.other_rate_adaption",
            FT_UINT8, BASE_DEC, VALS(gsm_a_dtap_other_rate_adaption_vals), 0x18,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_rate_adaption_header,
          { "Rate Adaption Header", "gsm_a.dtap.rate_adaption_header",
            FT_BOOLEAN, 8, TFS(&tfs_included_not_included), 0x40,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_multiple_frame_establishment_support,
          { "Multiple frame establishment support in data link", "gsm_a.dtap.multiple_frame_establishment_support",
            FT_BOOLEAN, 8, TFS(&tfs_frame_est_supported_not_supported), 0x20,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_mode_of_operation,
          { "Mode of operation", "gsm_a.dtap.mode_of_operation",
            FT_BOOLEAN, 8, TFS(&tfs_protocol_sensative_bit_transparent), 0x10,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_logical_link_identifier_negotiation,
          { "Logical link identifier negotiation", "gsm_a.dtap.logical_link_identifier_negotiation",
            FT_BOOLEAN, 8, TFS(&tfs_log_link_neg), 0x08,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_assignor_assignee,
          { "Assignor/Assignee", "gsm_a.dtap.assignor_assignee",
            FT_BOOLEAN, 8, TFS(&tfs_assignor_assignee), 0x04,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_in_out_band,
          { "In band/Out of band negotiation", "gsm_a.dtap.in_out_band",
            FT_BOOLEAN, 8, TFS(&tfs_in_out_band), 0x02,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_layer_1_identity,
          { "Layer 1 Identity", "gsm_a.dtap.layer_1_identity",
            FT_UINT8, BASE_DEC, NULL, 0x60,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_user_information_layer_1_protocol,
          { "User information layer 1 protocol", "gsm_a.dtap.user_information_layer_1_protocol",
            FT_UINT8, BASE_DEC, NULL, 0x1e,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_synchronous,
          { "Synchronous/asynchronous", "gsm_a.dtap.synchronous",
            FT_BOOLEAN, 8, TFS(&tfs_asynchronous_synchronous), 0x01,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_number_of_stop_bits,
          { "Number of Stop Bits", "gsm_a.dtap.number_of_stop_bits",
            FT_BOOLEAN, 8, TFS(&tfs_stop_bits), 0x40,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_negotiation,
          { "Negotiation", "gsm_a.dtap.negotiation",
            FT_BOOLEAN, 8, TFS(&tfs_negotiation), 0x20,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_number_of_data_bits,
          { "Number of data bits excluding parity bit if present", "gsm_a.dtap.number_of_data_bits",
            FT_BOOLEAN, 8, TFS(&tfs_parity_bits), 0x10,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_user_rate,
          { "User rate", "gsm_a.dtap.user_rate",
            FT_UINT8, BASE_DEC, VALS(gsm_a_dtap_user_rate_vals), 0x0F,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_v110_x30_rate_adaptation,
          { "V.110/X.30 rate adaptation Intermediate rate", "gsm_a.dtap.v110_x30_rate_adaptation",
            FT_UINT8, BASE_DEC, VALS(gsm_a_dtap_v110_x30_rate_adaptation_vals), 0x60,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_nic_on_tx,
          { "Network independent clock (NIC) on transmission (Tx)", "gsm_a.dtap.nic_on_tx",
            FT_BOOLEAN, 8, TFS(&tfs_nic_on_tx), 0x10,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_nic_on_rx,
          { "Network independent clock (NIC) on reception (Rx)", "gsm_a.dtap.nic_on_rx",
            FT_BOOLEAN, 8, TFS(&tfs_nic_on_rx), 0x08,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_parity_information,
          { "Parity information", "gsm_a.dtap.parity_information",
            FT_UINT8, BASE_DEC, VALS(gsm_a_dtap_parity_info_vals), 0x07,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_connection_element,
          { "Connection element", "gsm_a.dtap.connection_element",
            FT_UINT8, BASE_DEC, VALS(gsm_a_dtap_connection_element_vals), 0x60,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_modem_type,
          { "Modem type", "gsm_a.dtap.modem_type",
            FT_UINT8, BASE_DEC, NULL, 0x1f,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_other_modem_type,
          { "Other modem type", "gsm_a.dtap.other_modem_type",
            FT_UINT8, BASE_DEC, VALS(gsm_a_dtap_other_modem_type_vals), 0x60,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_fixed_network_user_rate,
          { "Fixed network user rate", "gsm_a.dtap.fixed_network_user_rate",
            FT_UINT8, BASE_DEC, NULL, 0x1f,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_acceptable_channel_codings_TCH_F14_4,
          { "Acceptable channel codings (TCH/F14.4)", "gsm_a.dtap.acceptable_channel_codings.TCH_F14_4",
            FT_BOOLEAN, 8, TFS(&tfs_acceptable_not_acceptable), 0x40,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_acceptable_channel_codings_spare20,
          { "Acceptable channel codings (Spare)", "gsm_a.dtap.acceptable_channel_codings.spare",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_acceptable_channel_codings_TCH_F9_6,
          { "Acceptable channel codings (TCH/F9.6)", "gsm_a.dtap.acceptable_channel_codings.TCH_F9_6",
            FT_BOOLEAN, 8, TFS(&tfs_acceptable_not_acceptable), 0x10,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_acceptable_channel_codings_TCH_F4_8,
          { "Acceptable channel codings (TCH/F4.8)", "gsm_a.dtap.acceptable_channel_codings.TCH_F4_8",
            FT_BOOLEAN, 8, TFS(&tfs_acceptable_not_acceptable), 0x08,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_maximum_number_of_traffic_channels,
          { "Maximum number of traffic channels", "gsm_a.dtap.maximum_number_of_traffic_channels",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_acceptable_channel_codings_spare78,
          { "Acceptable channel codings", "gsm_a.dtap.acceptable_channel_codings",
            FT_UINT8, BASE_DEC, NULL, 0x78,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_uimi,
          { "UIMI, User initiated modification indication",
            "gsm_a.dtap.uimi", FT_UINT8, BASE_DEC, VALS(gsm_a_dtap_uimi_vals),
            0x70, NULL, HFILL }
        },
        { &hf_gsm_a_dtap_wanted_air_interface_user_rate,
          { "Wanted air interface user rate", "gsm_a.dtap.wanted_air_interface_user_rate",
            FT_UINT8, BASE_DEC, VALS(gsm_a_dtap_wanted_air_rate_vals), 0x0F,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_acceptable_channel_codings_ext_TCH_F28_8,
          { "Acceptable channel codings extended (TCH/F28.8)", "gsm_a.dtap.acceptable_channel_codings_ext.TCH_F28_8",
            FT_BOOLEAN, 8, TFS(&tfs_acceptable_not_acceptable), 0x40,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_acceptable_channel_codings_ext_TCH_F32_0,
          { "Acceptable channel codings extended (TCH/F32.0)", "gsm_a.dtap.acceptable_channel_codings_ext.TCH_F32_0",
            FT_BOOLEAN, 8, TFS(&tfs_acceptable_not_acceptable), 0x20,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_acceptable_channel_codings_ext_TCH_F43_2,
          { "Acceptable channel codings extended (TCH/F43.2)", "gsm_a.dtap.acceptable_channel_codings_ext.TCH_F43_2",
            FT_BOOLEAN, 8, TFS(&tfs_acceptable_not_acceptable), 0x10,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_channel_coding_asymmetry_indication,
          { "Channel Coding Asymmetry Indication", "gsm_a.dtap.channel_coding_asymmetry_indication",
            FT_UINT8, BASE_DEC, VALS(gsm_a_dtap_channel_coding_asymmetry_ind_vals), 0x0c,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_edge_channel_codings,
          { "EDGE Channel Codings", "gsm_a.dtap.edge_channel_codings",
            FT_UINT8, BASE_DEC, NULL, 0x7c,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_layer_2_identity,
          { "Layer 2 Identity", "gsm_a.dtap.layer_2_identity",
            FT_UINT8, BASE_DEC, NULL, 0x60,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_user_information_layer_2_protocol,
          { "User information layer 2 protocol", "gsm_a.dtap.user_information_layer_2_protocol",
            FT_UINT8, BASE_DEC, NULL, 0x1f,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_maximum_number_of_supported_bearers,
          { "Maximum number of supported bearers", "gsm_a.dtap.maximum_number_of_supported_bearers",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_pcp,
          { "Prolonged Clearing Procedure", "gsm_a.dtap.pcp",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_dtmf,
          { "DTMF", "gsm_a.dtap.dtmf",
            FT_BOOLEAN, 8, TFS(&gsm_a_dtap_dtmf_value), 0x01,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_max_num_of_speech_bearers,
          { "Maximum number of speech bearers", "gsm_a.dtap.max_num_of_speech_bearers",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_de_cause_coding_standard,
          { "Coding standard", "gsm_a.dtap.coding_standard",
            FT_UINT8, BASE_DEC, VALS(gsm_a_dtap_de_cause_coding_standard_vals), 0x60,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_recommendation,
          { "Recommendation", "gsm_a.dtap.recommendation",
            FT_UINT8, BASE_DEC, NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_data,
          { "Data", "gsm_a.dtap.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_keypad_information,
          { "Keypad information", "gsm_a.dtap.keypad_information",
            FT_UINT8, BASE_DEC, NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_repeat_indicator,
          { "Repeat Indicator", "gsm_a.dtap.repeat_indicator",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_ss_version_indicator,
          { "SS Version Indicator", "gsm_a.dtap.ss_version_indicator",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_cp_cause,
          { "Cause", "gsm_a.dtap.cp_cause",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_test_loop,
          { "Test Loop", "gsm_a.dtap.test_loop",
            FT_UINT8, BASE_DEC, NULL, 0x3f,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_subchannel,
          { "Subchannel", "gsm_a.dtap.subchannel",
            FT_BOOLEAN, 8, TFS(&tfs_gsm_a_dtap_subchannel), 0x01,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_ack_element,
          { "Acknowledgment element", "gsm_a.dtap.ack_element",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_channel_coding03,
          { "Channel coding", "gsm_a.dtap.channel_coding",
            FT_UINT8, BASE_DEC, VALS(gsm_channel_coding_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_channel_coding30,
          { "Channel coding", "gsm_a.dtap.channel_coding",
            FT_UINT8, BASE_DEC, VALS(gsm_channel_coding_vals), 0x30,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_loop_mechanism0E,
          { "Loop mechanism", "gsm_a.dtap.loop_mechanism",
            FT_UINT8, BASE_DEC, VALS(gsm_a_dtap_loop_mech_vals), 0x0e,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_loop_mechanism1C,
          { "Loop mechanism", "gsm_a.dtap.loop_mechanism",
            FT_UINT8, BASE_DEC, VALS(gsm_a_dtap_loop_mech_vals), 0x1c,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_multislot_tch,
          { "Multi-slot TCH loop", "gsm_a.dtap.multislot_tch",
            FT_BOOLEAN, 8, TFS(&tfs_multislot_tch), 0x01,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_tp_tested_device,
          { "Tested device", "gsm_a.dtap.tp_tested_device",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_tp_pdu_description,
          { "PDUs transmitted", "gsm_a.dtap.tp_pdu_description",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_mode_flag,
          { "Mode flag", "gsm_a.dtap.mode_flag",
            FT_BOOLEAN, 8, TFS(&tfs_gsm_a_dtap_mode_flag), 0x01,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_egprs_mode_flag,
          { "EGPRS Mode flag", "gsm_a.dtap.egprs_mode_flag",
            FT_BOOLEAN, 8, TFS(&tfs_gsm_a_dtap_egprs_mode_flag), 0x01,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_downlink_timeslot_offset,
          { "Downlink Timeslot Offset", "gsm_a.dtap.downlink_timeslot_offset",
            FT_UINT8, BASE_DEC, NULL, 0x0E,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_ms_positioning_technology,
          { "MS positioning technology", "gsm_a.dtap.ms_positioning_technology",
            FT_UINT8, BASE_DEC, VALS(gsm_positioning_technology_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_ue_test_loop_mode,
          { "UE test loop mode", "gsm_a.dtap.ue_test_loop_mode",
            FT_UINT8, BASE_DEC, VALS(gsm_a_dtap_ue_test_loop_mode_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_ue_positioning_technology,
          { "UE positioning technology", "gsm_a.dtap.ue_positioning_technology",
            FT_UINT8, BASE_DEC, VALS(gsm_positioning_technology_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_ciphering_key_sequence_number,
          { "Ciphering Key Sequence Number", "gsm_a.dtap.ciphering_key_sequence_number",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_ciphering_key_sequence_number70,
          { "Ciphering Key Sequence Number", "gsm_a.dtap.ciphering_key_sequence_number",
            FT_UINT8, BASE_DEC, NULL, 0x70,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_service_type,
          { "Service Type", "gsm_a.dtap.service_type",
            FT_UINT8, BASE_DEC, VALS(gsm_a_dtap_service_type_vals), 0x0F,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_type_of_identity,
          { "Type of identity", "gsm_a.dtap.type_of_identity",
            FT_UINT8, BASE_DEC, VALS(gsm_a_dtap_type_of_identity_vals), 0x07,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_follow_on_request,
          { "Follow-On Request (FOR)", "gsm_a.dtap.follow_on_request",
            FT_BOOLEAN, 8, TFS(&tfs_follow_on_request_value ), 0x08,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_updating_type,
          { "Updating Type", "gsm_a.dtap.updating_type",
            FT_UINT8, BASE_DEC, VALS(gsm_a_dtap_updating_type_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_congestion_level,
          { "Congestion level", "gsm_a.dtap.congestion_level",
            FT_UINT8, BASE_DEC, NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_protocol_discriminator,
          { "Protocol Discriminator", "gsm_a.dtap.protocol_discriminator",
            FT_UINT8, BASE_DEC, VALS(protocol_discriminator_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_ti_flag,
          { "TI flag", "gsm_a.dtap.ti_flag",
            FT_BOOLEAN, 8, TFS(&tfs_allocated_by_receiver_sender), 0x80,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_tio,
          { "TIO", "gsm_a.dtap.tio",
            FT_UINT8, BASE_DEC, NULL, 0x70,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_tie,
          { "TIE", "gsm_a.dtap.tie",
            FT_UINT8, BASE_DEC, NULL, DTAP_TIE_MASK,
            NULL, HFILL }
        },
        { &hf_gsm_a_dtap_timeslot_number,
          { "Timeslot number", "gsm_a_dtap.timeslot_number",
          FT_UINT8, BASE_DEC, NULL, 0xe0,
          NULL, HFILL }
        },
        { &hf_gsm_a_dtap_uplink_rlc_sdu_size,
          { "Uplink RLC SDU size", "gsm_a_dtap.uplink_rlc_sdu_size",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
        },
        { &hf_gsm_a_dtap_radio_bearer,
          { "Radio Bearer", "gsm_a_dtap.radio_bearer",
          FT_UINT8, BASE_DEC, NULL, 0x1F,
          NULL, HFILL }
        },
        { &hf_gsm_a_dtap_mbms_short_transmission_identity,
          { "MBMS short transmission identity", "gsm_a_dtap.mbms_short_transmission_identity",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
        },
        { &hf_gsm_a_dtap_ue_received_rlc_sdu_counter_value,
          { "UE received RLC SDU counter value", "gsm_a_dtap.ue_received_rlc_sdu_counter_value",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
        },
        { &hf_gsm_a_dtap_num_lb_entities,
          { "Number of LB entities", "gsm_a_dtap.num_lb_entities",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
#define NUM_INDIVIDUAL_ELEMS    22
    gint *ett[NUM_INDIVIDUAL_ELEMS +
          NUM_GSM_DTAP_MSG_MM + NUM_GSM_DTAP_MSG_CC +
          NUM_GSM_DTAP_MSG_SMS + NUM_GSM_DTAP_MSG_SS + NUM_GSM_DTAP_MSG_TP +
          NUM_GSM_DTAP_ELEM];

    static ei_register_info ei[] = {
        { &ei_gsm_a_dtap_autn, { "gsm_a.dtap.autn.invalid", PI_MALFORMED, PI_WARN, "AUTN length not equal to 16", EXPFILL }},
        { &ei_gsm_a_dtap_auts, { "gsm_a.dtap.auts.invalid", PI_MALFORMED, PI_WARN, "AUTS length not equal to 14", EXPFILL }},
        { &ei_gsm_a_dtap_text_string_not_multiple_of_7, { "gsm_a.dtap.text_string_not_multiple_of_7", PI_MALFORMED, PI_WARN, "Value leads to a Text String whose length is not a multiple of 7 bits", EXPFILL }},
        { &ei_gsm_a_dtap_not_digit, { "gsm_a.dtap.not_digit", PI_MALFORMED, PI_WARN, "BCD number contains a value that is not a digit", EXPFILL }},
        { &ei_gsm_a_dtap_end_mark_unexpected, { "gsm_a.dtap.end_mark_unexpected", PI_MALFORMED, PI_WARN, "\'f\' end mark present in unexpected position", EXPFILL }},
        { &ei_gsm_a_dtap_invalid_ia5_character, { "gsm_a.dtap.invalid_ia5_character", PI_MALFORMED, PI_WARN, "Invalid IA5 character(s) in string (value > 127)", EXPFILL }},
        { &ei_gsm_a_dtap_keypad_info_not_dtmf_digit, { "gsm_a.dtap.keypad_info_not_dtmf_digit", PI_MALFORMED, PI_WARN, "Keypad information contains character that is not a DTMF digit", EXPFILL }},
        { &ei_gsm_a_dtap_extraneous_data, { "gsm_a.dtap.extraneous_data", PI_PROTOCOL, PI_NOTE, "Extraneous Data, dissector bug or later version spec(report to wireshark.org)", EXPFILL }},
        { &ei_gsm_a_dtap_missing_mandatory_element, { "gsm_a.dtap.missing_mandatory_element", PI_PROTOCOL, PI_WARN, "Missing Mandatory element, rest of dissection is suspect", EXPFILL }},
        { &ei_gsm_a_dtap_coding_scheme, { "gsm_a.dtap.coding_scheme.unknown", PI_PROTOCOL, PI_WARN, "Text string encoded according to an unknown Coding Scheme", EXPFILL }},
    };

    expert_module_t* expert_a_dtap;

    ett[0]  = &ett_dtap_msg;
    ett[1]  = &ett_dtap_oct_1;
    ett[2]  = &ett_cm_srvc_type;
    ett[3]  = &ett_gsm_enc_info;
    ett[4]  = &ett_bc_oct_3;
    ett[5]  = &ett_bc_oct_3a;
    ett[6]  = &ett_bc_oct_4;
    ett[7]  = &ett_bc_oct_5;
    ett[8]  = &ett_bc_oct_5a;
    ett[9]  = &ett_bc_oct_5b;
    ett[10] = &ett_bc_oct_6;
    ett[11] = &ett_bc_oct_6a;
    ett[12] = &ett_bc_oct_6b;
    ett[13] = &ett_bc_oct_6c;
    ett[14] = &ett_bc_oct_6d;
    ett[15] = &ett_bc_oct_6e;
    ett[16] = &ett_bc_oct_6f;
    ett[17] = &ett_bc_oct_6g;
    ett[18] = &ett_bc_oct_7;
    ett[19] = &ett_epc_ue_tl_a_lb_setup;
    ett[20] = &ett_mm_timer;
    ett[21] = &ett_ue_test_loop_mode;

    last_offset = NUM_INDIVIDUAL_ELEMS;

    for (i=0; i < NUM_GSM_DTAP_MSG_MM; i++, last_offset++)
    {
        ett_gsm_dtap_msg_mm[i] = -1;
        ett[last_offset] = &ett_gsm_dtap_msg_mm[i];
    }

    for (i=0; i < NUM_GSM_DTAP_MSG_CC; i++, last_offset++)
    {
        ett_gsm_dtap_msg_cc[i] = -1;
        ett[last_offset] = &ett_gsm_dtap_msg_cc[i];
    }

    for (i=0; i < NUM_GSM_DTAP_MSG_SMS; i++, last_offset++)
    {
        ett_gsm_dtap_msg_sms[i] = -1;
        ett[last_offset] = &ett_gsm_dtap_msg_sms[i];
    }

    for (i=0; i < NUM_GSM_DTAP_MSG_SS; i++, last_offset++)
    {
        ett_gsm_dtap_msg_ss[i] = -1;
        ett[last_offset] = &ett_gsm_dtap_msg_ss[i];
    }

    for (i=0; i < NUM_GSM_DTAP_MSG_TP; i++, last_offset++)
    {
        ett_gsm_dtap_msg_tp[i] = -1;
        ett[last_offset] = &ett_gsm_dtap_msg_tp[i];
    }

    for (i=0; i < NUM_GSM_DTAP_ELEM; i++, last_offset++)
    {
        ett_gsm_dtap_elem[i] = -1;
        ett[last_offset] = &ett_gsm_dtap_elem[i];
    }

    /* Register the protocol name and description */

    proto_a_dtap =
        proto_register_protocol("GSM A-I/F DTAP", "GSM DTAP", "gsm_a.dtap");

    proto_register_field_array(proto_a_dtap, hf, array_length(hf));

    proto_register_subtree_array(ett, array_length(ett));
    expert_a_dtap = expert_register_protocol(proto_a_dtap);
    expert_register_field_array(expert_a_dtap, ei, array_length(ei));


    /* subdissector code */
    register_dissector("gsm_a_dtap", dissect_dtap, proto_a_dtap);
    u2u_dissector_table = register_dissector_table("gsm_a.dtap.u2u_prot_discr", "GSM User to User Signalling",
                                                  proto_a_dtap, FT_UINT8, BASE_DEC);
}

void
proto_reg_handoff_gsm_a_dtap(void)
{
    dissector_handle_t dtap_handle;

    dtap_handle = find_dissector("gsm_a_dtap");
    dissector_add_uint("bssap.pdu_type", BSSAP_PDU_TYPE_DTAP, dtap_handle);
    dissector_add_uint("ranap.nas_pdu", BSSAP_PDU_TYPE_DTAP, dtap_handle);
    dissector_add_uint("llcgprs.sapi", 1 , dtap_handle); /* GPRS Mobility Management */
    dissector_add_uint("llcgprs.sapi", 7 , dtap_handle); /* SMS */
    dissector_add_uint("lapdm.sapi",   0 , dtap_handle); /* LAPDm: CC/RR/MM */
    dissector_add_uint("lapdm.sapi",   3 , dtap_handle); /* LAPDm: SMS/SS */

    gsm_map_handle = find_dissector_add_dependency("gsm_map", proto_a_dtap);
    rp_handle      = find_dissector_add_dependency("gsm_a_rp", proto_a_dtap);
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
