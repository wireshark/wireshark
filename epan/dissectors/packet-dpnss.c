/* packet-dpnss_dass2.c
 * Routines for DPNNS/DASS2 dissection
 * Copyright 2007, Anders Broman <anders.broman[at]ericsson.com>
 *
 * Supplementary string parameter table and testing by Tomas Muehlhoff.
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * References:
 * ND1301:2001/03  http://www.nicc.org.uk/nicc-public/Public/interconnectstandards/dpnss/nd1301_2004_11.pdf
 * http://acacia-net.com/wwwcla/protocol/dass2_l3.htm
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>

#include <glib.h>

#include <epan/packet.h>

/* Initialize the protocol and registered fields */
static int proto_dpnss                      = -1;
static int hf_dpnss_msg_grp_id              = -1;
static int hf_dpnss_cc_msg_type             = -1;
static int hf_dpnss_e2e_msg_type            = -1;
static int hf_dpnss_LbL_msg_type            = -1;
static int hf_dpnss_ext_bit                 = -1;
static int hf_dpnss_ext_bit_notall          = -1;
static int hf_dpnss_sic_type                = -1;
static int hf_dpnss_sic_details_for_speech  = -1;
static int hf_dpnss_sic_details_for_data1   = -1;
static int hf_dpnss_sic_details_for_data2   = -1;
static int hf_dpnss_dest_addr               = -1;
static int hf_dpnss_sic_oct2_data_type      = -1;
static int hf_dpnss_sic_oct2_duplex         = -1;
static int hf_dpnss_sic_oct2_sync_data_format = -1;
static int hf_dpnss_sic_oct2_sync_byte_timing = -1;
static int hf_dpnss_sic_oct2_net_ind_clk    = -1;
static int hf_dpnss_sic_oct2_async_data     = -1;
static int hf_dpnss_sic_oct2_async_flow_ctrl = -1;
static int hf_dpnss_clearing_cause          = -1;
static int hf_dpnss_rejection_cause         = -1;
static int hf_dpnss_man_code                = -1;
static int hf_dpnss_subcode                 = -1;
static int hf_dpnss_maintenance_action      = -1;

/* parameters */
static int hf_dpnss_a_b_party_addr          = -1;
static int hf_dpnss_call_idx                = -1;

#define DPNNS_MESSAGE_GROUP_CC          0
#define DPNNS_MESSAGE_GROUP_E2E         2
#define DPNNS_MESSAGE_GROUP_LbL         4

#define DPNSS_CC_MSG_ISRM_C             0
#define DPNSS_CC_MSG_ISRM_I             1
#define DPNSS_CC_MSG_RM_C               2
#define DPNSS_CC_MSG_RM_I               3
#define DPNSS_CC_MSG_CS                 4
#define DPNSS_CC_MSG_CCM                5
#define DPNSS_CC_MSG_NIM                6
#define DPNSS_CC_MSG_CA                 7
#define DPNSS_CC_MSG_CRM                8
#define DPNSS_CC_MSG_NAM                9
#define DPNSS_CC_MSG_RRM                10
#define DPNSS_CC_MSG_SSRM_I             11
#define DPNSS_CC_MSG_SSRM_C             12

/* Initialize the subtree pointers */
static int ett_dpnss            = -1;
static int ett_dpnss_sel_field  = -1;
static int ett_dpnss_sic_field  = -1;
static int ett_dpnss_ind_field  = -1;
static int ett_dpnss_sup_str    = -1;

static const value_string dpnss_msg_grp_id_vals[] = {
    {0,     "Call Control Message Group"},
    {2,     "End-to-End Message Group"},
    {4,     "Link-by-Link Message Group"},
    {0, NULL }
};

static const value_string dpnss_cc_msg_type_vals[] = {
    {DPNSS_CC_MSG_ISRM_C,       "INITIAL SERVICE REQUEST Message (COMPLETE) - ISRM(C)"},
    {DPNSS_CC_MSG_ISRM_I,       "INITIAL SERVICE REQUEST Message (INCOMPLETE) - ISRM(I)"},
    {DPNSS_CC_MSG_RM_C,         "RECALL Message (COMPLETE) - RM(C)"},
    {DPNSS_CC_MSG_RM_I,         "RECALL Message (INCOMPLETE) - RM(I)"},
    {DPNSS_CC_MSG_CS,           "CHANNEL SEIZED - CS"},
    {DPNSS_CC_MSG_CCM,          "CALL CONNECTED Message - CCM"},
    {DPNSS_CC_MSG_NIM,          "NETWORK INDICATION Message - NIM"},
    {DPNSS_CC_MSG_CA,           "CALL ARRIVAL Message - CA"},
    {DPNSS_CC_MSG_CRM,          "CLEAR REQUEST Message - CRM/CLEAR INDICATION Message - CIM"}, /* Humm chek 2.1.7/2.1.8 - depends on dir? */
    {DPNSS_CC_MSG_NAM,          "NUMBER ACKNOWLEDGE Message - NAM"},
    {DPNSS_CC_MSG_RRM,          "RECALL REJECTION Message - RRM"},
    {DPNSS_CC_MSG_SSRM_I,       "SUBSEQUENT SERVICE REQUEST Message (INCOMPLETE) - SSRM(I)"},
    {DPNSS_CC_MSG_SSRM_C,       "SUBSEQUENT SERVICE REQUEST Message (COMPLETE) - SSRM(C)"},
    { 0,    NULL }
};


static const value_string dpnss_cc_msg_short_type_vals[] = {
    {DPNSS_CC_MSG_ISRM_C,       "ISRM(C)"},
    {DPNSS_CC_MSG_ISRM_I,       "ISRM(I)"},
    {DPNSS_CC_MSG_RM_C,         "RM(C)"},
    {DPNSS_CC_MSG_RM_I,         "RM(I)"},
    {DPNSS_CC_MSG_CS,           "CS"},
    {DPNSS_CC_MSG_CCM,          "CCM"},
    {DPNSS_CC_MSG_CA,           "CA"},
    {DPNSS_CC_MSG_NIM,          "NIM"},
    {DPNSS_CC_MSG_CRM,          "CRM/CIM"}, /* Humm chek 2.1.7/2.1.8 - depends on dir? */
    {DPNSS_CC_MSG_NAM,          "NAM"},
    {DPNSS_CC_MSG_RRM,          "RRM"},
    {DPNSS_CC_MSG_SSRM_I,       "SSRM(I)"},
    {DPNSS_CC_MSG_SSRM_C,       "SSRM(C)"},
    {0, NULL }
};

#define DPNSS_E2E_MSG_EEM_C             2
#define DPNSS_E2E_MSG_EEM_I             3
#define DPNSS_E2E_MSG_SCRM              4
#define DPNSS_E2E_MSG_SCIM              5
#define DPNSS_E2E_MSG_ERM_C             6
#define DPNSS_E2E_MSG_ERM_I             7
#define DPNSS_E2E_MSG_NSIM              8


/* 2.2 END-TO-END MESSAGE GROUP */
static const value_string dpnss_e2e_msg_type_vals[] = {
    {2,     "END-to-END Message (COMPLETE) - EEM(C)"},
    {3,     "END-to-END Message (INCOMPLETE) - EEM(I)"},
    {4,     "SINGLE-CHANNEL CLEAR REQUEST Message - SCRM"},
    {5,     "SINGLE-CHANNEL CLEAR INDICATION Message - SCIM"},
    {6,     "END-to-END RECALL Message (COMPLETE) - ERM(C)"},
    {7,     "END-to-END RECALL Message (INCOMPLETE) - ERM(I)"},
    {8,     "NON SPECIFIED INFORMATION Message - NSIM"},
    { 0,    NULL }
};

static const value_string dpnss_e2e_msg_short_type_vals[] = {
    {2,     "EEM(C)"},
    {3,     "EEM(I)"},
    {4,     "SCRM"},
    {5,     "SCIM"},
    {6,     "ERM(C)"},
    {7,     "ERM(I)"},
    {8,     "NSIM"},
    { 0,    NULL }
};

#define DPNSS_LbL_MSG_LLM_C             0
#define DPNSS_LbL_MSG_LLM_I             1
#define DPNSS_LbL_MSG_LLRM              2
#define DPNSS_LbL_MSG_SM                4
#define DPNSS_LbL_MSG_LMM               5
#define DPNSS_LbL_MSG_LMRM              6

/* 2.3 LINK-BY-LINK MESSAGE GROUP */
static const value_string dpnss_LbL_msg_type_vals[] = {
    {0,     "LINK-by-LINK Message (COMPLETE) - LLM(C)"},
    {1,     "LINK-by-LINK Message (INCOMPLETE) - LLM(I)"},
    {2,     "LINK-by-LINK REJECT Message - LLRM"},
    {4,     "SWAP Message - SM"},
    {5,     "LINK MAINTENANCE Message - LMM"},
    {6,     "LINK MAINTENANCE REJECT Message - LMRM"},
    { 0,    NULL }
};

static const value_string dpnss_LbL_msg_short_type_vals[] = {
    {0,     "LLM(C)"},
    {1,     "LLM(I)"},
    {2,     "LLRM"},
    {4,     "SM"},
    {5,     "LMM"},
    {6,     "LMRM"},
    { 0,    NULL }
};

static const true_false_string dpnss_ext_bit_vals = {
  "further octet(s) follow",
  "no further octets"
};

static const true_false_string dpnss_ext_bit_no_ext_vals = {
  "no further octets",
  "Invalid"
};
/* SECTION 4 ANNEX 1 */
static const value_string dpnss_sic_type_type_vals[] = {
    {0,     "invalid"},
    {1,     "speech"},
    {2,     "data"},
    {3,     "data"},
    {4,     "interworking with DASS 2 - treat as data"},
    {5,     "interworking with DASS 2 - treat as data"},
    {6,     "interworking with DASS 2 - treat as data"},
    {7,     "interworking with DASS 2 - treat as data"},
    { 0,    NULL }
};

static const value_string dpnss_sic_details_for_speech_vals[] = {
    {0,     "64 kbit/s PCM G.711 A-Law or analogue"},
    {1,     "32 kbit/s ADPCM G.721"},
    {2,     "64 kbit/s PCM G.711 u-Law or analogue"},
    {3,     "Invalid"},
    {4,     "Invalid"},
    {5,     "Invalid"},
    {6,     "Invalid"},
    {7,     "Invalid"},
    {8,     "Invalid"},
    {9,     "Invalid"},
    {10,    "Invalid"},
    {11,    "Invalid"},
    {12,    "Invalid"},
    {13,    "Invalid"},
    {14,    "Invalid"},
    {15,    "Invalid"},
    { 0,    NULL }
};

static const value_string dpnss_sic_details_for_data_rates1_vals[] = {
    {0,     "64000 bit/s"},
    {1,     "56000 bit/s"},
    {2,     "48000 bit/s"},
    {3,     "32000 bit/s"},
    {4,     "19200 bit/s"},
    {5,     "16000 bit/s"},
    {6,     "14400 bit/s"},
    {7,     "12000 bit/s"},
    {8,     "9600 bit/s"},
    {9,     "8000 bit/s"},
    {10,    "7200 bit/s"},
    {11,    "4800 bit/s"},
    {12,    "3600 bit/s"},
    {13,    "2400 bit/s"},
    {14,    "1200 bit/s"},
    {15,    "600 bit/s"},
    { 0,    NULL }
};

static const value_string dpnss_sic_details_for_data_rates2_vals[] = {
    {0,     "300 bit/s"},
    {1,     "200 bit/s"},
    {2,     "150 bit/s"},
    {3,     "134.5 bit/s"},
    {4,     "110 bit/s"},
    {5,     "100 bit/s"},
    {6,     "75 bit/s"},
    {7,     "50 bit/s"},
    {8,     "75/1200 bit/s"},
    {9,     "1200/75 bit/s"},
    {10,    "invalid"},
    {11,    "invalid"},
    {12,    "invalid"},
    {13,    "invalid"},
    {14,    "invalid"},
    {15,    "invalid"},
    { 0,    NULL }
};
/* Octet 2 */

static const value_string dpnss_sic_oct2_data_type_vals[] = {
    {0,     "Invalid"},
    {1,     "Invalid"},
    {2,     "Invalid"},
    {3,     "Synchronous"},
    {4,     "Synchronous"},
    {5,     "Asynchronous"},
    {6,     "Asynchronous"},
    {7,     "Asynchronous"},
    { 0,    NULL }
};

static const true_false_string dpnss_duplex_vals = {
  "Half Duplex (HDX)",
  "Full Duplex (FDX)"
};

static const true_false_string dpnss_sic_oct2_sync_data_format_vals = {
  "X.25 Packet Mode",
  "Anonymous or Unformatted"
};

static const true_false_string dpnss_sic_oct2_net_ind_clk_vals = {
  "Bits E4/E5/E6 indicate phase",
  "Clock Locked to Transmission"
};

static const true_false_string dpnss_provided_vals = {
  "Provided",
  "Not Provided"
};

static const value_string dpnss_sic_oct2_async_data_type_vals[] = {
    {0,     "Unspecified"},
    {1,     "5 data bits"},
    {2,     "7 data bits"},
    {3,     "8 data bits"},
    { 0,    NULL }
};
static const true_false_string dpnss_flow_control_vals = {
  "TA has ESRA capability",
  "TA does not have ESRA capability"
};

/* SECTION 4 Global Issue 7
 * ANNEX 3 CLEARING/REJECTION CAUSE CODES
 */
static const value_string dpnss_clearing_cause_code_vals[] = {
    {0x29,      "Access Barred"},
    {0x14,      "Acknowledgement"},
    {0x01,      "Address Incomplete"},
    {0x08,      "Busy"},
    {0x23,      "Channel Out of Service"},
    {0x2d,      "DTE Controlled Not Ready"},
    {0x07,      "Congestion"},
    {0x30,      "Call Termination"},
    {0x18,      "Facility Not Registered"},
    {0x0a,      "Incoming Calls Barred"},
    {0x13,      "Service Incompatible"},
    {0x1a,      "Message Not Understood"},
    {0x1e,      "Network Address Extension-Error"},
    {0x02,      "Network Termination"},
    {0x00,      "Number Unobtainable"},
    {0x24,      "Priority Forced Release"},
    {0x19,      "Reject"},
    {0x1c,      "Route Out of Service"},
    {0x04,      "Subscriber Incompatible"},
    {0x15,      "Signal Not Understood"},
    {0x16,      "Signal Not Valid"},
    {0x09,      "Subscriber Out of Service"},
    {0x1b,      "Signalling System Incompatible"},
    {0x17,      "Service Temporarily Unavailable"},
    {0x03,      "Service Unavailable"},
    {0x1d,      "Transferred"},
    {0x2e,      "DTE Uncontrolled Not Ready"},
    { 0,    NULL }
};
/* ANNEX 6 : MAINTENANCE ACTIONS (p235) */
static const value_string dpnss_maintenance_actions_vals[] = {
    {0x1,       "BBC - Back-Busy Control"},
    {0x2,       "LBC - Loop-Back Control"},
    {0x3,       "LBA - Loop-Back Abort"},
    {0x4,       "TCS-R - Traffic Channel Status Request"},
    {0x5,       "ACK - Acknowledge"},
    {0x6,       "NTC - Non-Looped-Back Test Control"},
    { 0,    NULL }
};

/* ANNEX 7 : CODING OF USAGE IDENTIFIERS */
static const value_string dpnss_man_code_vals[] = {
    {0x0,       "Reserved"},
    {0x1,       "BT"},
    {0x2,       "Ericsson"},
    {0x3,       "Lucent"},
    {0x4,       "Philips"},
    {0x5,       "Siemens"},
    {0x6,       "Westell"},
    {0x7,       "Mitel"},
    { 0,    NULL }
};



#define DPNSS_NONE                              0
#define DPNSS_SERV_MAR                          1
#define DPNSS_STATUS                            2
#define DPNSS_ROUTE_RES_CLASS                   3
#define DPNSS_CBR_GRP                           4
#define DPNSS_FAC_LST_CODE                      5
#define DPNSS_NO_OF_FUR_TRANS                   6
#define DPNSS_NO_OF_FUR_ALT_R                   7
#define DPNSS_INT_CAP_LEV                       8
#define DPNSS_NESTING_LEVEL                     9
#define DPNSS_C_PARTY_ADDR                      10
#define DPNSS_B_PARTY_ADDR                      11
#define DPNSS_SIC                               12
#define DPNSS_A_B_PARTY_ADDR                    13
#define DPNSS_DIVERSION_TYPE                    14
#define DPNSS_NSI_IDENTIFIER                    15
#define DPNSS_USER_DEFINED                      16
#define DPNSS_TEXT                              17
#define DPNSS_CALL_INDEX                        18
#define DPNSS_PASSWORD                          19
#define DPNSS_CALL_DIR                          20
#define DPNSS_DPNSS_ISDN_TYPE                   21
#define DPNSS_HC_CLC                            22
#define DPNSS_ENHANCED_STR_ID                   23
#define DPNSS_STRING_ID                         24
#define DPNSS_STRING_ID_LIST                    25
#define DPNSS_TEXT_TYPE                         26
#define DPNSS_CHANNEL_STATUS                    27
#define DPNSS_CHANNEL_NUMBER                    28
#define DPNSS_BPL                               29
#define DPNSS_BCL                               30
#define DPNSS_DEVICE_INDEX                      31
#define DPNSS_CR_NO                             32
#define DPNSS_CALL_ID_LENGTH                    33
#define DPNSS_STATE_OF_DEST                     34
#define DPNSS_STATE_OF_DEST_QUAL                35
#define DPNSS_REASON_FOR_REDIR                  36
#define DPNSS_CLEARING_CAUSE                    37
#define DPNSS_RECONT_ADDR                       38
#define DPNSS_STATE_OF_OPERATOR                 39
#define DPNSS_NIGHT_SERVICE                     40
#define DPNSS_PBX_FLAG                          41
#define DPNSS_NUMBER_OF_CALLS                   42
#define DPNSS_NUMBER_OF_SERVERS                 43
#define DPNSS_PRIORITY_LEVEL                    44
#define DPNSS_LOCATION                          45
#define DPNSS_SUBADDRESS                        46
#define DPNSS_ALARM_LEVEL                       47
#define DPNSS_STAFF_PRESENT                     48
#define DPNSS_TIME_AND_DATE                     49
#define DPNSS_SERVICES                          50
#define DPNSS_PBX_REFERENCE                     51
#define DPNSS_TRUNK_GROUP_REF_NUMBER            52
#define DPNSS_TRUNK_MEMBER_REF_NUMBER           53
#define DPNSS_CONF_PARTY_INDEX                  54
#define DPNSS_CONF_PARTY_DET                    55
#define DPNSS_ACCOUNT_CODE                      56
#define DPNSS_CONF_BRIDGE_ADDR                  57
#define DPNSS_COST_QUALIFIER                    58
#define DPNSS_CURRENCY_INDICATION               59
#define DPNSS_CURRENCY_UNITS                    60
#define DPNSS_TIME_INTERVAL                     61
#define DPNSS_UNITS                             62
#define DPNSS_REMOTE_ADDRESS                    63
#define DPNSS_TEST_INDEX                        64
#define DPNSS_TEST_RESULT                       65
#define DPNSS_TYPE_OF_ASSISTANCE                66
#define DPNSS_REST_DOMAIN                       67
#define DPNSS_GRP_PICK_UP_CODE                  68
#define DPNSS_PICK_UP_CALL_TYPE                 69
#define DPNSS_MALICIOUS_CALL_REF                70
#define DPNSS_TIMER_VALUE                       71
#define DPNSS_BEARER_CAP                        72
#define DPNSS_ISDN_NUM_ATTR                     73
#define DPNSS_ISDN_DPNSS_SUBADDRESS             74
#define DPNSS_ISDN_NUMBER_DIGITS                75
#define DPNSS_HIGH_LAYER_COMP                   76
#define DPNSS_LOW_LAYER_COMP                    77
#define DPNSS_PROGRESS_INDICATOR                78
#define DPNSS_VPN_ACCESS_REF_NUM                79
#define DPNSS_INDEX_NUMBER                      80
#define DPNSS_RESTRICTION_INDICATOR             81
#define DPNSS_CAUSE                             82


typedef struct {
    gint        id_code_no;
    const char  *compact_name;
    const char  *name;
    gint        par1_num;
    gint        par2_num;
    gint        par3_num;
    gint        par4_num;
} dpnns_sup_serv_set_t;

static const dpnns_sup_serv_set_t dpnns_sup_serv_set[] = {
    {0, "NOT USED",     "NOT USED",                                     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {1, "CLC-ORD",      "CALLING/CALLED LINE CATEGORY ORDINARY",        DPNSS_SERV_MAR,         DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {2, "CLC-DEC",      "CALLING/CALLED LINE CATEGORY DECADIC",         DPNSS_STATUS,           DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {3, "CLC-ISDN",     "CALLING/CALLED LINE CATEGORY-PUBLIC ISDN",     DPNSS_STATUS,           DPNSS_DPNSS_ISDN_TYPE,  DPNSS_NONE,             DPNSS_NONE },
    {4, "CLC-PSTN",     "CALLING/CALLED LINE CATEGORY-PSTN",            DPNSS_STATUS,           DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {5, "CLC-MF5",      "CALLING/CALLED LINE CATEGORY-SSMF5",           DPNSS_STATUS,           DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {6, "CLC-OP",       "CALLING/CALLED LINE CATEGORY-OPERATOR",        DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {7, "CLC-NET",      "CALLING/CALLED LINE CATEGORY-NETWORK",         DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {8, "undefined",    "undefined",                                    DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {9, "undefined",    "undefined",                                    DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {10, "CBWF-R",      "CALL BACK WHEN FREE-REQUEST",                  DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {11, "CBWF-FN",     "CALL BACK WHEN FREE-FREE NOTIFICATION",        DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {12, "CBWF-CSUI",   "CALL BACK WHEN FREE-CALL SET-UP(IMMEDIATE)",   DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {13, "CBWF-C",      "CALL BACK WHEN FREE-CANCEL",                   DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {14, "RO",          "RING OUT",                                     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {15, "CBC",         "CALL BACK COMPLETE",                           DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {16, "CBWF-CSUD",   "CALL BACK WHEN FREE -CALL SET-UP(DELAYED)",    DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {17, "CBWNU-R",     "CALL BACK WHEN NEXT USEDREQUEST",              DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {18, "COS",         "CLASS OF SERVICE",                             DPNSS_ROUTE_RES_CLASS,  DPNSS_CBR_GRP,          DPNSS_FAC_LST_CODE,     DPNSS_NONE},
    {19, "LA",          "LOOP AVOIDANCE",                               DPNSS_NO_OF_FUR_TRANS,  DPNSS_NO_OF_FUR_ALT_R,  DPNSS_NONE,             DPNSS_NONE },
    {20, "EI-PVR",      "EXECUTIVE INTRUSION-PRIOR VALIDATION",         DPNSS_INT_CAP_LEV,      DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {21, "EI-R",        "EXECUTIVE INTRUSION-REQUEST",                  DPNSS_INT_CAP_LEV,      DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {22, "IPL-R",       "INTRUSION PROTECTION LEVEL-REQUEST",           DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {23, "IPL",         "INTRUSION PROTECTION LEVEL",                   DPNSS_INT_CAP_LEV,      DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {24, "EI-C",        "EXECUTIVE INTRUSION-CONVERT",                  DPNSS_INT_CAP_LEV,      DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {25, "EI-I",        "EXECUTIVE INTRUSION-INTRUDED",                 DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {26, "CW",          "CALL WAITING",                                 DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {27, "CO",          "CALL OFFER",                                   DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {28, "SN-REQ",      "SEND NEXT-REQUEST",                            DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {29, "HGF",         "HUNT GROUP FORWARDED",                         DPNSS_NESTING_LEVEL,    DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {30, "DIV-V",       "DIVERSION-VALIDATION",                         DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {31, "DIV-FM",      "DIVERSION-FOLLOW ME",                          DPNSS_C_PARTY_ADDR,     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {32, "DIV-BY",      "DIVERSION-BY PASS",                            DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {33, "DIV-CI",      "DIVERSION CANCEL-IMMEDIATE",                   DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {34, "DIV-CR",      "DIVERSION CANCEL-ON NO REPLY",                 DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {35, "DIV-CB",      "DIVERSION CANCEL-ON BUSY",                     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {36, "DIV-CA",      "DIVERSION CANCEL-ALL",                         DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {37, "DVG-I",       "DIVERTING IMMEDIATE",                          DPNSS_B_PARTY_ADDR,     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {38, "DVG-B",       "DIVERTING ON BUSY",                            DPNSS_B_PARTY_ADDR,     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {39, "DVG-R",       "DIVERTING ON NO REPLY",                        DPNSS_B_PARTY_ADDR,     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {40, "DVT-I",       "DIVERT IMMEDIATE",                             DPNSS_C_PARTY_ADDR,     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {41, "DVT-B",       "DIVERT ON BUSY",                               DPNSS_C_PARTY_ADDR,     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {42, "DVD-I",       "DIVERTED IMMEDIATE",                           DPNSS_C_PARTY_ADDR,     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {43, "DVD-B",       "DIVERTED ON BUSY",                             DPNSS_C_PARTY_ADDR,     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {44, "DVD-R",       "DIVERTED ON NO REPLY",                         DPNSS_C_PARTY_ADDR,     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {45, "DVT-R",       "DIVERT ON NO REPLY",                           DPNSS_C_PARTY_ADDR,     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {46, "SIC",         "SERVICE INDICATOR CODE",                       DPNSS_SIC,              DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {47, "BSS-M",       "BEARER SERVICE SELECTION-MANDATORY",           DPNSS_SIC,              DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {48, "BSS-P",       "BEARER SERVICE SELECTION-PREFERRED",           DPNSS_SIC,              DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {49, "BSS-N",       "BEARER SERVICE SELECTION-NOTIFICATION",        DPNSS_SIC,              DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {50, "OLI/CLI",     "ORIGINATING LINE IDENTITY/CALLED LINE IDENTITY", DPNSS_A_B_PARTY_ADDR, DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {51, "RTI",         "ROUTING INFORMATION, ROUTING INFORMATION",     DPNSS_DPNSS_ISDN_TYPE,  DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {52, "undefined",   "undefined",                                    DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {53, "DVD-E",       "DIVERTED-EXTERNALLY",                          DPNSS_DIVERSION_TYPE,   DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {54, "REJ",         "REJECT",                                       DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {55, "ACK",         "ACKNOWLEDGE",                                  DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {56, "SN",          "SEND NEXT",                                    DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {57, "D-SIC",       "DASS 2-SERVICE INDICATOR CODE",                DPNSS_SIC,              DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {58, "NSI",         "NON-SPECIFIED INFORMATION",                    DPNSS_NSI_IDENTIFIER,   DPNSS_USER_DEFINED,     DPNSS_USER_DEFINED,     DPNSS_NONE },
    {59, "OCP",         "ORIGINALLY CALLED PARTY",                      DPNSS_B_PARTY_ADDR,     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {60, "HOLD-REQ",    "HOLD REQUEST",                                 DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {61, "RECON",       "RECONNECTED",                                  DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {62, "HDG",         "HOLDING",                                      DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {63, "CD-Q",        "CALL DISTRIBUTION-QUEUE",                      DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {64, "TEXT-M",      "TEXT MESSAGE",                                 DPNSS_TEXT,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {65, "SOD-B",       "STATE OF DESTINATION-BUSY",                    DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {66, "SOD-F",       "STATE OF DESTINATION-FREE",                    DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {67, "CD-DNQ",      "CALL DISTRIBUTION-DO NOT QUEUE",               DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {68, "undefined",   "undefined",                                    DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {69, "CD-LINK",     "CALL DISTRIBUTION-LINKED",                     DPNSS_CALL_INDEX,       DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {70, "DIV-RSI",     "DIVERSION-REMOTE SET IMMEDIATE",               DPNSS_C_PARTY_ADDR,     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {71, "DIV-RSB",     "DIVERSION-REMOTE SET ON BUSY",                 DPNSS_C_PARTY_ADDR,     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {72, "DIV-RSR",     "DIVERSION-REMOTE SET ON NO REPLY",             DPNSS_C_PARTY_ADDR,     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {73, "DIV-RCI",     "DIVERSION-REMOTE CANCEL IMMEDIATE",            DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {74, "DIV-RCB",     "DIVERSION-REMOTE CANCEL ON BUSY",              DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {75, "DIV-RCR",     "DIVERSION-REMOTE CANCEL ON NO REPLY",          DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {76, "DIV-RCA",     "DIVERSION-REMOTE CANCEL ALL",                  DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {77, "PASSW",       "PASSWORD",                                     DPNSS_PASSWORD,         DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {78, "SPL",         "SPLIT",                                        DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {79, "TWP",         "TWO PARTY",                                    DPNSS_CALL_DIR,         DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {80, "ENQ",         "ENQUIRY CALL",                                 DPNSS_HC_CLC,           DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {81, "SCE",         "SINGLE CHANNEL ENQUIRY",                       DPNSS_HC_CLC,           DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {82, "TRFD",        "TRANSFERRED",                                  DPNSS_CALL_DIR,         DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {83, "SHTL",        "SHUTTLE",                                      DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {84, "COC",         "CONNECTED CALL",                               DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {85, "TRFR",        "TRANSFER",                                     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {86, "CD-FN",       "CALL DISTRIBUTION-FREE NOTIFY",                DPNSS_CALL_INDEX,       DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {87, "ICC",         "INTERCOM CALL",                                DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {88, "AD-RQ",       "ADD-ON REQUEST",                               DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {89, "AD-V",        "ADD-ON VALIDATION",                            DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {90, "AD-O",        "ADDED-ON",                                     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {91, "ENH",         "ENHANCED SSMF5",                               DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {92, "BAS",         "BASIC SSMF5",                                  DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {93, "CD-UNLINK",   "CALL DISTRIBUTION-UNLINKED",                   DPNSS_CALL_INDEX,       DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {94, "SNU",         "SIGNAL NOT UNDERSTOOD",                        DPNSS_ENHANCED_STR_ID,  DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {95, "SU",          "SERVICE UNAVAILABLE",                          DPNSS_STRING_ID,        DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {96, "RR-SNU",      "RECALL REJECTED SIGNAL NOT UNDERSTOOD",        DPNSS_ENHANCED_STR_ID,  DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {97, "CD-CSU",      "CALL DISTRIBUTION-CALL SET UP",                DPNSS_CALL_INDEX,       DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {98, "IG-SNU",      "IGNORED-SIGNAL NOT UNDERSTOOD",                DPNSS_STRING_ID_LIST,   DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {99, "IG-SU",       "IGNORED-SERVICE UNAVAILABLE",                  DPNSS_STRING_ID_LIST,   DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {100, "TEXT",       "TEXTUAL DISPLAY",                              DPNSS_TEXT,             DPNSS_TEXT_TYPE,        DPNSS_NONE,             DPNSS_NONE },
    {101, "SIM-A",      "SIMULATED ANSWER",                             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {102, "ACT",        "ACTIVATE",                                     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {103, "DEACT",      "DEACTIVATE",                                   DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {104, "TCS",        "TRAFFIC-CHANNEL STATUS",                       DPNSS_CHANNEL_STATUS,   DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {105, "CHID",       "CHANNEL IDENTITY",                             DPNSS_CHANNEL_NUMBER,   DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {106, "FR-R",       "FORCED RELEASE-REQUEST",                       DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {107, "PB-P",       "PRIORITY BREAKDOWN-PROTECTION",                DPNSS_BPL,              DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {108, "PB-R",       "PRIORITY BREAKDOWN-REQUEST",                   DPNSS_BCL,              DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {109, "DI",         "DEVICE IDENTITY",                              DPNSS_DEVICE_INDEX,     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {110, "ROP-R",      "ROUTE OPTIMISATION-REQUEST",                   DPNSS_CR_NO,            DPNSS_CALL_ID_LENGTH,   DPNSS_NONE,             DPNSS_NONE },
    {111, "ROP-CSU",    "ROUTE OPTIMISATION-CALL SET UP",               DPNSS_CALL_ID_LENGTH,   DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {112, "ROP-CON",    "ROUTE OPTIMISATION-CONNECTED",                 DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {113, "DND",        "DO NOT DISTURB",                               DPNSS_STATE_OF_DEST,    DPNSS_STATE_OF_DEST_QUAL, DPNSS_NONE,           DPNSS_NONE },
    {114, "DND-O",      "DO NOT DISTURB-OVERRIDE",                      DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {115, "DND-S",      "DO NOT DISTURB-SET",                           DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {116, "DND-C",      "DO NOT DISTURB-CLEAR",                         DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {117, "undefined",  "undefined",                                    DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {118, "EST",        "EXTENSION STATUS CALL",                        DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {119, "CDIV",       "CONTROLLED DIVERSION",                         DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {120, "RDG",        "REDIRECTING",                                  DPNSS_REASON_FOR_REDIR, DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {121, "RCF",        "REDIRECTING ON CALL FAILURE",                  DPNSS_CLEARING_CAUSE,   DPNSS_B_PARTY_ADDR,     DPNSS_NONE,             DPNSS_NONE },
    {122, "TOV-R",      "TAKEOVER REQUEST",                             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {123, "TOV-V",      "TAKEOVER VALIDATION",                          DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {124, "SER-R",      "SERIES CALL REQUEST",                          DPNSS_RECONT_ADDR,      DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {125, "SER-C",      "SERIES CALL-CANCEL",                           DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {126, "SER-E",      "SERIES CALL-ESTABLISHMENT",                    DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {127, "NS-N, NIGHT","SERVICE-NOTIFICATION",                         DPNSS_STATE_OF_OPERATOR, DPNSS_NONE,            DPNSS_NONE,             DPNSS_NONE },
    {128, "NS-DVT",     "NIGHT SERVICE-DIVERT",                         DPNSS_NIGHT_SERVICE,    DPNSS_PBX_FLAG,         DPNSS_NONE,             DPNSS_NONE },
    {129, "NS-DVG",     "DPNSS_NIGHT_SERVICE-DIVERTING",                DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {130, "NS-DVD",     "DPNSS_NIGHT_SERVICE-DIVERTED",                 DPNSS_C_PARTY_ADDR,     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {131, "NS-RDVT",    "DPNSS_NIGHT_SERVICE-REDIVERT",                 DPNSS_C_PARTY_ADDR,     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {132, "NS-RDVG",    "DPNSS_NIGHT_SERVICE-REDIVERTING",              DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {133, "NS-RDVD",    "DPNSS_NIGHT_SERVICE-REDIVERTED",               DPNSS_C_PARTY_ADDR,     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {134, "NS-DA",      "DPNSS_NIGHT_SERVICE-DEACTIVATED",              DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {135, "Q-INFO",     "QUEUE INFORMATION",                            DPNSS_NUMBER_OF_CALLS,  DPNSS_NUMBER_OF_SERVERS, DPNSS_NONE,            DPNSS_NONE },
    {136, "Q-PRIO",     "QUEUE PRIORITY",                               DPNSS_PRIORITY_LEVEL,   DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {137, "SW-V",       "SWAP - VALIDATION",                            DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {138, "SW-R",       "SWAP - REJECTED",                              DPNSS_LOCATION,         DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {139, "undefined",  "undefined",                                    DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {140, "A2",         "SSMF5 SIGNAL 'A-2'",                           DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {141, "undefined",  "undefined",                                    DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {142, "A5",         "SSMF5 SIGNAL 'A-5'",                           DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {143, "undefined",  "undefined",                                    DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {144, "A8",         "SSMF5 SIGNAL 'A-8'",                           DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {145, "A10",        "SSMF5 SIGNAL 'A-10'",                          DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {146, "undefined",  "undefined",                                    DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {147, "A13",        "SSMF5 SIGNAL 'A-13'",                          DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {148, "A14",        "SSMF5 SIGNAL 'A-14'",                          DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {149, "A12",        "SSMF5 SIGNAL 'A-12'",                          DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {150, "A7",         "SSMF5 SIGNAL 'A-7'",                           DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {151, "CBWF-CLB",   "CALL BACK WHEN FREE-CALL BACK",                DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {152, "DVT",        "DIVERT", DPNSS_C_PARTY_ADDR,                   DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {153, "SOD-I",      "DPNSS_STATE_OF_DEST-INDETERMINABLE",           DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {154, "DVG",        "DIVERTING",                                    DPNSS_B_PARTY_ADDR,     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {155, "SOD-REQ",    "REQUEST DPNSS_STATE_OF_DEST",                  DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {156, "CBWF-CB",    "CALL BACK WHEN FREE-CALL BACK REQUEST",        DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {157, "NAE-DC",     "NETWORK ADDRESS EXTENSION",                    DPNSS_SUBADDRESS,       DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {158, "SFI",        "SUPPLEMENTARY FACILITIES INHIBITED",           DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {159, "NAE-DI",     "NETWORK ADDRESS EXTENSION-DESTINATION INCOMPLETE", DPNSS_SUBADDRESS,   DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {160, "DRS",        "DIRECT ROUTE SELECT",                          DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {161, "AS",         "ALARM STATUS",                                 DPNSS_ALARM_LEVEL,      DPNSS_STAFF_PRESENT,    DPNSS_NONE, DPNSS_NONE },
    {162, "AS-R",       "ALARM STATUS-REQUEST",                         DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {163, "TAD-R",      "TIME AND DATE-REQUEST",                        DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {164, "TAD",        "TIME AND DATE",                                DPNSS_TIME_AND_DATE,    DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {165, "SATB",       "SATELLITE BARRED",                             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {166, "SERV",       "SERVICE INFORMATION",                          DPNSS_SERVICES,         DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {167, "TID",        "TRUNK IDENTITY",                               DPNSS_PBX_REFERENCE,    DPNSS_TRUNK_GROUP_REF_NUMBER, DPNSS_TRUNK_MEMBER_REF_NUMBER, DPNSS_NONE},
    {168, "PARK",       "PARK REQUEST",                                 DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {169, "PKD",        "PARKED",                                       DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {170, "AC-NAO",     "ADD-ON CONFERENCE-NO ADD ON CURRENTLY AVAILABLE", DPNSS_NONE,          DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {171, "CBM-R",      "CALL BACK MESSAGING-REQUEST",                  DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {172, "CBM-C",      "CALL BACK MESSAGING-CANCEL",                   DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {173, "NAE-CC",     "NETWORK ADDRESS EXTENSION-CALLING/CALLED IDENTITY COMPLETE", DPNSS_SUBADDRESS, DPNSS_NONE,     DPNSS_NONE,             DPNSS_NONE },
    {174, "NAE-CI",     "NETWORK ADDRESS EXTENSION-CALLING/CALLED IDENTITY INCOMPLETE", DPNSS_SUBADDRESS, DPNSS_NONE,   DPNSS_NONE,             DPNSS_NONE },
    {175, "undefined",  "undefined",                                    DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {176, "AC-CDC",     "ADD-ON CONFERENCE-CLEARDOWN CONFERENCE",       DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {177, "AC-PI",      "ADD-ON CONFERENCE-PARTY INDEX",                DPNSS_CONF_PARTY_INDEX, DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {178, "undefined",  "undefined",                                    DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {179, "AC-DR",      "ADD-ON CONFERENCE - DETAILS REQUEST",          DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {180, "AC-PD",      "ADD-ON CONFERENCE - PARTY",                    DPNSS_CONF_PARTY_DET,   DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {181, "AC-CBI",     "ADD-ON CONFERENCE - CONFERENCE BRIDGE IDENTITY", DPNSS_CONF_BRIDGE_ADDR, DPNSS_NONE,               DPNSS_NONE,             DPNSS_NONE },
    {182, "CH-AC",      "CHARGE REPORTING ACCOUNT CODE",                DPNSS_ACCOUNT_CODE,     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {183, "CH-ACR",     "CHARGE REPORTING ACCOUNT CODE REQUEST",        DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {184, "CH-ACT",     "CHARGE REPORTING - ACTIVE",                    DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {185, "CH-CLR",     "CHARGE REPORTING - CLEAR",                     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {186, "CH-CR",      "CHARGE REPORTING - COST REQUEST",              DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {187, "CH-CST",     "CHARGE REPORTING - COST, CURRENCY UNITS",      DPNSS_COST_QUALIFIER,   DPNSS_CURRENCY_INDICATION, DPNSS_NONE, DPNSS_NONE },
    {188, "CH-TR",      "CHARGE REPORTING - TIME RATE",                 DPNSS_CURRENCY_UNITS,   DPNSS_TIME_INTERVAL, DPNSS_COST_QUALIFIER, DPNSS_CURRENCY_INDICATION},
    {189, "CH-UR",      "CHARGE REPORTING - UNIT",                      DPNSS_CURRENCY_UNITS,   DPNSS_COST_QUALIFIER, DPNSS_CURRENCY_INDICATION, DPNSS_NONE},
    {190, "CH-UU",      "CHARGE REPORTING - UNITS USED",                DPNSS_UNITS,            DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {191, "OPD",        "OUTPUT DIGITS",                                DPNSS_REMOTE_ADDRESS,   DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {192, "OPD-R",      "OUTPUT DIGITS - REQUEST",                      DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {193, "IRD",        "INTERNAL REROUTING DISABLED",                  DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {194, "ERD",        "EXTERNAL REROUTING DISABLED",                  DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {195, "NLT-PT",     "NON-LOOPED BACK TEST-PERFORM TEST",            DPNSS_TEST_INDEX,       DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {196, "NLT-RQ",     "NON-LOOPED BACK TEST-TEST REQUEST",            DPNSS_TEST_INDEX,       DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {197, "NLT-SC",     "NON-LOOPED BACK TEST-SEQUENCE COMPLETE",       DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {198, "NLT-RES",    "NON-LOOPED BACK TEST-RESULT",                  DPNSS_TEST_RESULT,      DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {199, "AUTO-A",     "AUTOANSWER",                                   DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {200, "HF-A",       "HANDS-FREE - ACTIVATED",                       DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {201, "HF-D",       "HANDS-FREE - DEACTIVATED",                     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {202, "EI-W",       "EXECUTIVE INTRUSION-WITHDRAW",                 DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {203, "DVT-RD",     "DIVERT-REDIRECTION",                           DPNSS_REASON_FOR_REDIR, DPNSS_C_PARTY_ADDR, DPNSS_NONE, DPNSS_NONE },
    {204, "DVT-CF",     "DIVERT-CALL FAILURE",                          DPNSS_C_PARTY_ADDR,     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {205, "ASST-INFO",  "ASSISTANCE-INFORMATION",                       DPNSS_TYPE_OF_ASSISTANCE, DPNSS_NONE,               DPNSS_NONE,             DPNSS_NONE },
    {206, "RED-BY",     "REDIRECTION-BYPASS",                           DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {207, "undefined",  "undefined",                                    DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {208, "VIC",        "VPN INITIATED CLEAR",                          DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {209, "NPR-A",      "NUMBER PRESENTATION RESTRICTION-A PARTY",      DPNSS_REST_DOMAIN, DPNSS_NONE,              DPNSS_NONE,             DPNSS_NONE },
    {210, "NPR-B",      "NUMBER PRESENTATION RESTRICTION-B PARTY",      DPNSS_REST_DOMAIN, DPNSS_NONE,              DPNSS_NONE,             DPNSS_NONE },
    {211, "ARC",        "AUXILIARY DPNSS_ROUTE_RES_CLASS",              DPNSS_ROUTE_RES_CLASS,  DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {212, "WOB",        "WAIT ON BUSY",                                 DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {213, "GPU-R",      "GROUP PICK-UP REQUEST",                        DPNSS_GRP_PICK_UP_CODE, DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {214, "PU-DVT",     "PICK-UP DIVERT",                               DPNSS_C_PARTY_ADDR,     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {215, "PU-DVG",     "PICK-UP DIVERTING",                            DPNSS_TIME_INTERVAL,    DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {216, "DPU-R",      "DIRECTED PICK-UP REQUEST",                     DPNSS_PICK_UP_CALL_TYPE, DPNSS_NONE,                DPNSS_NONE,             DPNSS_NONE },
    {217, "RCC-CA",     "ROUTE CAPACITY CONTROL-CAPACITY AVAILABLE",    DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {218, "undefined",  "undefined",                                    DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {219, "RCC-OI",     "ROUTE CAPACITY CONTROL-OVERRIDE INVOKED",      DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {220, "PU-DVD",     "PICK-UP DIVERTED",                             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {221, "NPR-O",      "NUMBER PRESENTATION RESTRICTION - OTHER PARTY", DPNSS_REST_DOMAIN,     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {222, "MCI",        "MALICIOUS CALL INDICATION",                    DPNSS_MALICIOUS_CALL_REF, DPNSS_NONE,               DPNSS_NONE,             DPNSS_NONE },
    {223, "NSL",        "NETWORK SIGNALLING LIMIT", DPNSS_NONE,         DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {224, "undefined",  "undefined",                                    DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {225, "undefined",  "undefined",                                    DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {226, "TCOS",       "TRAVELLING CLASS OF SERVICE",                  DPNSS_ROUTE_RES_CLASS, DPNSS_CBR_GRP, DPNSS_FAC_LST_CODE, DPNSS_NONE},
    {227, "TCOS-R",     "TRAVELLING CLASS OF SERVICE-REQUEST",          DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {228, "DIV-RSC",    "DIVERSION-REMOTE SET COMBINED",                DPNSS_C_PARTY_ADDR,     DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {229, "DIV-RCC",    "DIVERSION-REMOTE CANCEL COMBINED",             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {230, "RDC",        "REDIRECTION CONTROL",                          DPNSS_TIMER_VALUE,      DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {231, "CAUSE",      "DPNSS_CLEARING_CAUSE",                         DPNSS_CLEARING_CAUSE,   DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {232, "CP",         "CALL PROCEEDING",                              DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {233, "I-BC",       "ISDN-BEARER CAPABILITY",                       DPNSS_BEARER_CAP,       DPNSS_NONE,         DPNSS_NONE,             DPNSS_NONE },
    {234, "I-CC",       "ISDN-DPNSS_CLEARING_CAUSE",                    DPNSS_CAUSE,            DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {235, "I-CPN",      "ISDN-CALLING PARTY/CONNECTED NUMBER",          DPNSS_ISDN_NUM_ATTR,    DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {236, "I-CSA",      "ISDN-CALLING PARTY/CONNECTED DPNSS_SUBADDRESS", DPNSS_ISDN_DPNSS_SUBADDRESS, DPNSS_ISDN_NUMBER_DIGITS, DPNSS_NONE, DPNSS_NONE },
    {237, "I-DSA",      "ISDN-DESTINATION (CALLED PARTY) DPNSS_SUBADDRESS",     DPNSS_ISDN_DPNSS_SUBADDRESS, DPNSS_NONE,                DPNSS_NONE,             DPNSS_NONE },
    {238, "I-HLC",      "ISDN-HIGH LAYER COMPATIBILITY",                DPNSS_HIGH_LAYER_COMP,  DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {239, "I-LLC",      "ISDN-LOW LAYER COMPATIBILITY",                 DPNSS_LOW_LAYER_COMP,   DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {240, "I-PROG",     "ISDN-PROGRESS",                                DPNSS_PROGRESS_INDICATOR, DPNSS_NONE,               DPNSS_NONE,             DPNSS_NONE },
    {241, "IPN",        "INTERWORKING VIA A PRIVATE ISDN",              DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {242, "SAVE",       "SAVE",                                         DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {243, "V-NID",      "VPN-NODAL IDENTITY",                           DPNSS_VPN_ACCESS_REF_NUM, DPNSS_NONE,               DPNSS_NONE,             DPNSS_NONE },
    {244, "M-INDEX",    "MESSAGE INDEX",                                DPNSS_INDEX_NUMBER, DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {245, "CBM-CSU",    "CALL BACK MESSAGING CALL SET-UP",              DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {246, "INT-A",      "INTERIM ANSWER",                               DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {247, "undefined",  "undefined",                                    DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {248, "DVL",        "DIVERSION - LAST CONTROLLING EXTENSION IDENTITY", DPNSS_B_PARTY_ADDR, DPNSS_DIVERSION_TYPE, DPNSS_RESTRICTION_INDICATOR, DPNSS_NONE},
    {249, "ROP-INV",    "ROUTE OPTIMISATION INVITE",                    DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {250, "ROP-INVA",   "ROUTE OPTIMISATION INVITE WITH ACKNOWLEDGEMENT", DPNSS_NONE,               DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {251, "PCLG-P",     "PUBLIC CALLING PARTY NUMBER-PROVIDED",         DPNSS_ISDN_NUM_ATTR, DPNSS_ISDN_NUMBER_DIGITS, DPNSS_NONE, DPNSS_NONE },
    {252, "PCLG-D",     "PUBLIC CALLING PARTY NUMBER-DEFAULT",          DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
    {253, "PCON-P",     "PUBLIC CONNECTED NUMBER-PROVIDED",             DPNSS_ISDN_NUM_ATTR, DPNSS_ISDN_NUMBER_DIGITS, DPNSS_NONE, DPNSS_NONE },
    {254, "PCON-D",     "PUBLIC CONNECTED NUMBER-DEFAULT",              DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE,             DPNSS_NONE },
};

static int
dissect_dpnss_sic(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
    guint8 octet, type_of_data;

    octet = tvb_get_guint8(tvb,offset);
    type_of_data = (octet & 0x70)>>4;
    proto_tree_add_item(tree, hf_dpnss_ext_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_dpnss_sic_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    switch(type_of_data){
    case 1:
        /* Type of Data (001) : Details for Speech */
        proto_tree_add_item(tree, hf_dpnss_sic_details_for_speech, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    case 2:
        /* Type of Data (010) : Data Rates */
        proto_tree_add_item(tree, hf_dpnss_sic_details_for_data1, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    case 3:
        /* Type of Data (011) : Data Rates */
        proto_tree_add_item(tree, hf_dpnss_sic_details_for_data2, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    default:
        /* Illegal */
        break;
    }
    offset++;
    if((octet&0x80)==0x80){
        /* Extension bit set
         * Synch/Asynchronous Information
         */
        octet = tvb_get_guint8(tvb,offset);
        type_of_data = octet&0x3;
        proto_tree_add_item(tree, hf_dpnss_ext_bit_notall, tvb, offset, 1, ENC_BIG_ENDIAN);
        switch(type_of_data){
        case 3:
            /* Synchronous */
        case 4:
            /* Synchronous */
            proto_tree_add_item(tree, hf_dpnss_sic_oct2_net_ind_clk, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_dpnss_sic_oct2_sync_data_format, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_dpnss_sic_oct2_sync_byte_timing, tvb, offset, 1, ENC_BIG_ENDIAN);
            break;
        case 5:
            /* Asynchronous */
        case 6:
            /* Asynchronous */
        case 7:
            /* Asynchronous */
            proto_tree_add_item(tree, hf_dpnss_sic_oct2_async_flow_ctrl, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_dpnss_sic_oct2_async_data, tvb, offset, 1, ENC_BIG_ENDIAN);
            break;
        default:
            break;
        }
        proto_tree_add_item(tree, hf_dpnss_sic_oct2_duplex, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_dpnss_sic_oct2_data_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }
    return offset;
}
/*
static const value_string dpnss_serv_mark_vals[] = {
    { 1,        "PSTN BARRED"},
    { 2,        "EMERGENCY TELEPHONE"},
    { 3,        "HUNT GROUP"},
    { 4,        "DISTRIBUTED GROUP"},
    { 5,        "UNABLE TO INITIATE CLEARING AFTER ANSWER"},
    { 6,        "RING GROUP"},
    { 0,    NULL }
};
*/
/* Supplementary Information parameters
 * TODO Add decoding of parameters where needed.
 */

static const value_string dpnss_sup_serv_par_str_vals[] = {
    { DPNSS_NONE,                   "None"},
    { DPNSS_SERV_MAR,               "Servive Marking"},
    { DPNSS_STATUS,                 "Status"},
    { DPNSS_ROUTE_RES_CLASS,        "Route Restriction Class"},
    { DPNSS_CBR_GRP,                "Call Barring Group"},
    { DPNSS_FAC_LST_CODE,           "Facility list code"},
    { DPNSS_NO_OF_FUR_TRANS,        "Number of Further Transits"},
    { DPNSS_NO_OF_FUR_ALT_R,        "Number of Further Alternative routes"},
    { DPNSS_INT_CAP_LEV,            "Intrusion Capability level"},
    { DPNSS_NESTING_LEVEL,          "Nesting level"},
    { DPNSS_C_PARTY_ADDR,           "C Party Address"},
    { DPNSS_B_PARTY_ADDR,           "B Party Address"},
    { DPNSS_SIC,                    "SIC"},
    { DPNSS_A_B_PARTY_ADDR,         "A/B Party Address"},
    { DPNSS_DIVERSION_TYPE,         "Diversion Type"},
    { DPNSS_NSI_IDENTIFIER,         "NSI Identifier"},
    { DPNSS_USER_DEFINED,           "User Defined"},
    { DPNSS_TEXT,                   "Text"},
    { DPNSS_CALL_INDEX,             "Call Index"},
    { DPNSS_PASSWORD,               "Password"},
    { DPNSS_CALL_DIR,               "Call Direction"},
    { DPNSS_DPNSS_ISDN_TYPE,        "DPNNS ISDN Type"},
    { DPNSS_HC_CLC,                 "HC CLC"},
    { DPNSS_ENHANCED_STR_ID,        "Enhanced String Identity"},
    { DPNSS_STRING_ID,              "String Identity"},
    { DPNSS_STRING_ID_LIST,         "String Identity List"},
    { DPNSS_TEXT_TYPE,              "Text Type"},
    { DPNSS_CHANNEL_STATUS,         "Channel Status"},
    { DPNSS_CHANNEL_NUMBER,         "Channel Number"},
    { DPNSS_BPL,                    "BPL"},
    { DPNSS_BCL,                    "BCL"},
    { DPNSS_DEVICE_INDEX,           "Device Index"},
    { DPNSS_CR_NO,                  "Call Reference Number"},
    { DPNSS_CALL_ID_LENGTH,         "Call Identity Length"},
    { DPNSS_STATE_OF_DEST,          "State of Destination"},
    { DPNSS_STATE_OF_DEST_QUAL,     "State of Destination Qualifier"},
    { DPNSS_REASON_FOR_REDIR,       "Reason For Redirection"},
    { DPNSS_CLEARING_CAUSE,         "Clearing Cause"},
    { DPNSS_RECONT_ADDR,            "Reconnect Address"},
    { DPNSS_STATE_OF_OPERATOR,      "State of Operator"},
    { DPNSS_NIGHT_SERVICE,          "Night Service"},
    { DPNSS_PBX_FLAG,               "PBX flag"},
    { DPNSS_NUMBER_OF_CALLS,        "Number of Calls"},
    { DPNSS_NUMBER_OF_SERVERS,      "Number of Servers"},
    { DPNSS_PRIORITY_LEVEL,         "Priority Level"},
    { DPNSS_LOCATION,               "Location"},
    { DPNSS_SUBADDRESS,             "Subaddress"},
    { DPNSS_ALARM_LEVEL,            "Alarm Level"},
    { DPNSS_STAFF_PRESENT,          "Staff Present"},
    { DPNSS_TIME_AND_DATE,          "Time and Date"},
    { DPNSS_SERVICES,               "Services"},
    { DPNSS_PBX_REFERENCE,          "PBX Reference"},
    { DPNSS_TRUNK_GROUP_REF_NUMBER, "Trunk Group reference Number"},
    { DPNSS_TRUNK_MEMBER_REF_NUMBER,"Trunk Member Reference Number"},
    { DPNSS_CONF_PARTY_INDEX,       "Conference Party Index"},
    { DPNSS_CONF_PARTY_DET,         "Conference Party Details"},
    { DPNSS_ACCOUNT_CODE,           "Account code"},
    { DPNSS_CONF_BRIDGE_ADDR,       "Conference Bridge Address"},
    { DPNSS_COST_QUALIFIER,         "Cost Qualifier"},
    { DPNSS_CURRENCY_INDICATION,    "Currency Indication"},
    { DPNSS_CURRENCY_UNITS,         "Currency Units"},
    { DPNSS_TIME_INTERVAL,          "Time Interval"},
    { DPNSS_UNITS,                  "Units"},
    { DPNSS_REMOTE_ADDRESS,         "Remote Address"},
    { DPNSS_TEST_INDEX,             "Test Index"},
    { DPNSS_TEST_RESULT,            "Test Result"},
    { DPNSS_TYPE_OF_ASSISTANCE,     "Type of assistance"},
    { DPNSS_REST_DOMAIN,            "Restriction Domain"},
    { DPNSS_GRP_PICK_UP_CODE,       "Group Pick-Up Code"},
    { DPNSS_PICK_UP_CALL_TYPE,      "Pick-Up call type"},
    { DPNSS_MALICIOUS_CALL_REF,     "Malicious call reference"},
    { DPNSS_TIMER_VALUE,            "Timer Value"},
    { DPNSS_BEARER_CAP,             "Bearer capability"},
    { DPNSS_ISDN_NUM_ATTR,          "ISDM number attribute"},
    { DPNSS_ISDN_DPNSS_SUBADDRESS,  "ISDN DPNNS Subaddress"},
    { DPNSS_ISDN_NUMBER_DIGITS,     "ISDN Number Digits"},
    { DPNSS_HIGH_LAYER_COMP,        "High Layer Compatibility"},
    { DPNSS_LOW_LAYER_COMP,         "Low layer Compatibility"},
    { DPNSS_PROGRESS_INDICATOR,     "Progress Indicator"},
    { DPNSS_VPN_ACCESS_REF_NUM,     "VPN Access reference Number"},
    { DPNSS_INDEX_NUMBER,           "Index Number"},
    { DPNSS_RESTRICTION_INDICATOR,  "Restriction Indicator"},
    { DPNSS_CAUSE,                  "Cause"},
    { 0,    NULL }
};

static void
dissect_dpnns_sup_str_par(tvbuff_t *tvb, proto_tree * tree, int par_type_num, int par_start_offset, int par_end_offset)
{

    int     par_len;

    par_len = par_end_offset - par_start_offset;
    if(par_len==0){
        par_type_num = DPNSS_NONE;
    }
    switch (par_type_num){
    case DPNSS_NONE:
        proto_tree_add_text(tree, tvb, par_start_offset, par_len,"Par: None");
        break;

/* TODO: Use individual dissection of parameters if hf fields needed or in the case where
        special handling is needed for greater detail

    case DPNSS_SERV_MAR:
         * p 173
         * More than one Service Marking character can be
         * included in the Parameter, each being separated
         * by the IA5 character space (2/0).
         * If decoded use: dpnss_serv_mark_vals
         *
    case DPNSS_STATUS:
    case DPNSS_ROUTE_RES_CLASS:
    case DPNSS_CBR_GRP:
    case DPNSS_FAC_LST_CODE:
    case DPNSS_NO_OF_FUR_TRANS:
    case DPNSS_NO_OF_FUR_ALT_R:
    case DPNSS_INT_CAP_LEV:
    case DPNSS_NESTING_LEVEL:
    case DPNSS_C_PARTY_ADDR:
    case DPNSS_B_PARTY_ADDR:
    case DPNSS_SIC:
    */
    case DPNSS_A_B_PARTY_ADDR:
        proto_tree_add_item(tree, hf_dpnss_a_b_party_addr, tvb, par_start_offset, par_len, ENC_ASCII|ENC_NA);
        break;

        /*
    case DPNSS_DIVERSION_TYPE:
    case DPNSS_NSI_IDENTIFIER:
    case DPNSS_USER_DEFINED:
    case DPNSS_TEXT:
    */
    case DPNSS_CALL_INDEX:
        proto_tree_add_item(tree, hf_dpnss_call_idx, tvb, par_start_offset, par_len, ENC_ASCII|ENC_NA);
        break;
        /*

    case DPNSS_PASSWORD:
    case DPNSS_CALL_DIR:
    case DPNSS_DPNSS_ISDN_TYPE:
    case DPNSS_HC_CLC:
    case DPNSS_ENHANCED_STR_ID:
    case DPNSS_STRING_ID:
    case DPNSS_STRING_ID_LIST:
    case DPNSS_TEXT_TYPE:
    case DPNSS_CHANNEL_STATUS:
    case DPNSS_CHANNEL_NUMBER:
    case DPNSS_BPL:
    case DPNSS_BCL:
    case DPNSS_DEVICE_INDEX:
    case DPNSS_CR_NO:
    case DPNSS_CALL_ID_LENGTH:
    case DPNSS_STATE_OF_DEST:
    case DPNSS_STATE_OF_DEST_QUAL:
    case DPNSS_REASON_FOR_REDIR:
    case DPNSS_CLEARING_CAUSE:
    case DPNSS_RECONT_ADDR:
    case DPNSS_STATE_OF_OPERATOR:
    case DPNSS_NIGHT_SERVICE:
    case DPNSS_PBX_FLAG:
    case DPNSS_NUMBER_OF_CALLS:
    case DPNSS_NUMBER_OF_SERVERS:
    case DPNSS_PRIORITY_LEVEL:
    case DPNSS_LOCATION:
    case DPNSS_SUBADDRESS:
    case DPNSS_ALARM_LEVEL:
    case DPNSS_STAFF_PRESENT:
    case DPNSS_TIME_AND_DATE:
    case DPNSS_SERVICES:
         * More than one Service Marking character can be
         * included in the Parameter, each being separated
         * by the IA5 character space (2/0).
         * 1 = Call Offer not possible
         * 2 = Executive Intrusion not possible
         * 3 = Call Back When Free not possible
         * 4 = Call Back Messaging not possible (see Note)
         * 5 = Hold not possible
         * 6 = Call Back When Next Used not possible
    case DPNSS_PBX_REFERENCE:
    case DPNSS_TRUNK_GROUP_REF_NUMBER:
    case DPNSS_TRUNK_MEMBER_REF_NUMBER:
    case DPNSS_CONF_PARTY_INDEX:
    case DPNSS_CONF_PARTY_DET:
    case DPNSS_ACCOUNT_CODE:
    case DPNSS_CONF_BRIDGE_ADDR:
    case DPNSS_COST_QUALIFIER:
    case DPNSS_CURRENCY_INDICATION:
    case DPNSS_CURRENCY_UNITS:
    case DPNSS_TIME_INTERVAL:
    case DPNSS_UNITS:
    case DPNSS_REMOTE_ADDRESS:
    case DPNSS_TEST_INDEX:
    case DPNSS_TEST_RESULT:
    case DPNSS_TYPE_OF_ASSISTANCE:
    case DPNSS_REST_DOMAIN:
    case DPNSS_GRP_PICK_UP_CODE:
    case DPNSS_PICK_UP_CALL_TYPE:
    case DPNSS_MALICIOUS_CALL_REF:
    case DPNSS_TIMER_VALUE:
    case DPNSS_BEARER_CAP:
    case DPNSS_ISDN_NUM_ATTR:
    case DPNSS_ISDN_DPNSS_SUBADDRESS:
    case DPNSS_ISDN_NUMBER_DIGITS:
    case DPNSS_HIGH_LAYER_COMP:
    case DPNSS_LOW_LAYER_COMP:
    case DPNSS_PROGRESS_INDICATOR:
    case DPNSS_VPN_ACCESS_REF_NUM:
    case DPNSS_INDEX_NUMBER:
    case DPNSS_RESTRICTION_INDICATOR:
    case DPNSS_CAUSE:
*/
    default:
        /* Used to print all pars without any special handling */
        proto_tree_add_text(tree, tvb, par_start_offset, par_len,"Parameter %s: %s",
            val_to_str(par_type_num, dpnss_sup_serv_par_str_vals, "Unknown (%d)" ),
            tvb_format_text(tvb,par_start_offset, par_len)
            );
        break;
    }

}

/* 3.1 Supplementary Information Strings
 * A Supplementary Information String comprises a Supplementary
 * Information Identifier which may be followed by one or more
 * Parameters. A Supplementary Information String starts with the
 * IA5 character * and ends with the IA5 character #.
 *
 *  When the Supplementary Information String includes Parameters
 * these are separated from the identifier and each other by a *.
 * eg * Supplementary Information Identifier code #
 * or * Supplementary Information Identifier code * Parameter #
 * or * Supplementary Information Identifier code * Parameter * Parameter #
 * A Supplementary Information String shall be wholly contained
 * within one Selection or Indication Field (ie it shall not be
 * split between messages).
 *
 * 3.2 Supplementary Information String Identifier
 * The identifier comprises one or more IA5 numerals 0-9 which may
 * be followed by a single IA5 alpha-character suffix in the range A-Z.
 * The numerals of the identifier indicate the main function of the
 * Supplementary Information String, eg "39F" indicates "Diverting
 * on No Reply". "F" is the suffix.
 *
 * 3.5 Destination Address
 * The Destination Address comprises one or more IA5 numerals 0 to
 * 9, has no identifier code and is not prefixed by a * or
 * terminated by a #. The digits are always the last characters in
 * the Selection Block. The first Destination Address digit
 * immediately follows the # of the last Supplementary Information
 * String.
 */

static int
dissect_dpnss_sup_info_str(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
    proto_item *sup_str_item;
    proto_tree *sup_str_tree;
    gint        start_offset, hash_offset, tvb_end_offset, sup_inf_str_end_offset, str_no;
    gint        par_start_offset, par_end_offset, number_of_found_par;
    gint        sup_inf_str_len, par_type_num;
    guint       sup_str_num;
    guint8      octet;
    gboolean    last_string = FALSE;
    gboolean    has_par;

    tvb_end_offset = tvb_length(tvb);

    str_no = 1;
    while((offset<tvb_end_offset)&&(last_string == FALSE)){
        octet = tvb_get_guint8(tvb,offset);
        if (octet == '*'){
            /* Supplementary Information String */
            start_offset = offset;
            has_par = TRUE;
            number_of_found_par = 0;
            /* offset points to start of supplementary information string */
            offset++;
            hash_offset = tvb_find_guint8(tvb, offset, -1, '#');
            sup_str_item = proto_tree_add_text(tree, tvb, start_offset, hash_offset-start_offset+1,
                                               "Supplementary Information %u: %s",str_no,
                                               tvb_format_text(tvb,start_offset,hash_offset-start_offset+1));
            sup_str_tree = proto_item_add_subtree(sup_str_item, ett_dpnss_sup_str);
            /* SUPPLEMENTARY INFORMATION STRING IDENTIFIER
             * Get the parameter number string and translate it to an index into the dpnns_sup_serv_set.
             * The number may have a trailing alpha character at the end.
             */
            sup_inf_str_end_offset = tvb_find_guint8(tvb, offset, hash_offset-offset, '*');
            if(sup_inf_str_end_offset==-1){
                /* no parameters */
                has_par = FALSE;
                sup_inf_str_end_offset = hash_offset;
            }
            sup_inf_str_len = sup_inf_str_end_offset - offset;
            sup_str_num = atoi(tvb_format_text(tvb, offset, sup_inf_str_len));
            if((sup_str_num != 0) && (sup_str_num < array_length(dpnns_sup_serv_set))){
                proto_tree_add_text(sup_str_tree, tvb,offset,sup_inf_str_len,
                                    "Sup str:%s ", dpnns_sup_serv_set[sup_str_num].compact_name);
                offset = sup_inf_str_end_offset+1;
                /* Find parameter(s) */
                while(has_par){
                    number_of_found_par++;
                    /* 1:st Parameter */
                    par_start_offset = offset;
                    par_end_offset = tvb_find_guint8(tvb, offset, -1, '*');
                    if(par_end_offset == -1){
                        /* last parameter */
                        par_end_offset = hash_offset;
                        has_par = FALSE;
                    }
                    switch(number_of_found_par){
                    case 1:
                        par_type_num = dpnns_sup_serv_set[sup_str_num].par1_num;
                        dissect_dpnns_sup_str_par(tvb,sup_str_tree, par_type_num, par_start_offset, par_end_offset);
                        break;
                    case 2:
                        par_type_num = dpnns_sup_serv_set[sup_str_num].par2_num;
                        dissect_dpnns_sup_str_par(tvb,sup_str_tree, par_type_num, par_start_offset, par_end_offset);
                        break;
                    case 3:
                        par_type_num = dpnns_sup_serv_set[sup_str_num].par3_num;
                        dissect_dpnns_sup_str_par(tvb,sup_str_tree, par_type_num, par_start_offset, par_end_offset);
                        break;
                    case 4:
                        par_type_num = dpnns_sup_serv_set[sup_str_num].par4_num;
                        dissect_dpnns_sup_str_par(tvb,sup_str_tree, par_type_num, par_start_offset, par_end_offset);
                        break;
                    default:
                        break;
                    }
                    /* More parameters ? */
                    offset = par_end_offset+1;

                }
            }
            offset = hash_offset+1;
            str_no++;
        }else{
            last_string = TRUE;
            proto_tree_add_item(tree, hf_dpnss_dest_addr, tvb, offset, -1, ENC_ASCII|ENC_NA);
        }
    }
    return offset;
}


static void
dissect_dpnss_LbL_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *sic_field_item, *ind_field_item;
    proto_tree *sic_field_tree, *ind_field_tree;
    int offset = 0;
    int tvb_end_offset;
    guint8 octet;

    tvb_end_offset = tvb_length(tvb);

    proto_tree_add_item(tree, hf_dpnss_LbL_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    octet = tvb_get_guint8(tvb,offset)&0x0f;
    offset++;
    if(check_col(pinfo->cinfo, COL_INFO))
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s ",
            val_to_str(octet, dpnss_LbL_msg_short_type_vals, "Unknown (%d)" ));
    if(tree){
        switch (octet){
        case DPNSS_LbL_MSG_LLM_C:
            /* 2.3.1 LINK-by-LINK Message (COMPLETE) - LLM(C)*/
        case DPNSS_LbL_MSG_LLM_I:
            /* 2.3.2 LINK-by-LINK Message (INCOMPLETE) - LLM(I) */
            /* Indication Field */
            ind_field_item = proto_tree_add_text(tree, tvb, offset, -1,
                                                 "Indication Field: %s",
                                                 tvb_format_text(tvb,offset,tvb_length_remaining(tvb, offset)));
            ind_field_tree = proto_item_add_subtree(ind_field_item, ett_dpnss_ind_field);
            offset = dissect_dpnss_sup_info_str(tvb, pinfo, ind_field_tree, offset);
            break;
        case DPNSS_LbL_MSG_LLRM:
            /* 2.3.3 LINK-by-LINK REJECT Message - LLRM */
            /* Rejection Cause */
            proto_tree_add_item(tree, hf_dpnss_rejection_cause, tvb, offset, 1, ENC_BIG_ENDIAN);
            /* Indication Field (Optional) */
            if(tvb_end_offset>offset){
                ind_field_item = proto_tree_add_text(tree, tvb, offset, -1,
                                                     "Indication Field: %s",
                                                     tvb_format_text(tvb,offset,tvb_length_remaining(tvb, offset)));
                ind_field_tree = proto_item_add_subtree(ind_field_item, ett_dpnss_ind_field);
                offset = dissect_dpnss_sup_info_str(tvb, pinfo, ind_field_tree, offset);
            }
            break;
        case DPNSS_LbL_MSG_SM:
            /* 2.3.4 SWAP Message - SM */
            /* Service Indicator Code
             * Note: On data calls the SIC may comprise more than one octet.
             * The Service Indicator Code is coded in accordance with ANNEX 1.
             */
            sic_field_item = proto_tree_add_text(tree, tvb, offset, -1, "Service Indicator Code");
            sic_field_tree = proto_item_add_subtree(sic_field_item, ett_dpnss_sic_field);
            offset =dissect_dpnss_sic(tvb, pinfo, sic_field_tree, offset);
            /* Indication Field */
            ind_field_item = proto_tree_add_text(tree, tvb, offset, -1,
                                                 "Indication Field: %s",
                                                 tvb_format_text(tvb,offset,tvb_length_remaining(tvb, offset)));
            ind_field_tree = proto_item_add_subtree(ind_field_item, ett_dpnss_ind_field);
            offset = dissect_dpnss_sup_info_str(tvb, pinfo, ind_field_tree, offset);
            break;
        case DPNSS_LbL_MSG_LMM:
            /* 2.3.5 LINK MAINTENANCE Message - LMM */
            /* Maintenance Action
             * respond to a request for,maintenance actions to be performed.
             * The Maintenance Action field identifies the action required or
             * the response being made. The Maintenance Action field is coded
             * as shown in ANNEX 6.
             */
            proto_tree_add_item(tree, hf_dpnss_maintenance_action, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            /* Indication Field */
            ind_field_item = proto_tree_add_text(tree, tvb, offset, -1,
                                                 "Indication Field: %s",
                                                 tvb_format_text(tvb,offset,tvb_length_remaining(tvb, offset)));
            ind_field_tree = proto_item_add_subtree(ind_field_item, ett_dpnss_ind_field);
            offset = dissect_dpnss_sup_info_str(tvb, pinfo, ind_field_tree, offset);
            break;
        case DPNSS_LbL_MSG_LMRM:
            /* 2.3.6 LINK MAINTENANCE REJECT Message - LMRM */
            proto_tree_add_item(tree, hf_dpnss_clearing_cause, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            /* Indication Field */
            ind_field_item = proto_tree_add_text(tree, tvb, offset, -1,
                                                 "Indication Field: %s",
                                                 tvb_format_text(tvb,offset,tvb_length_remaining(tvb, offset)));
            ind_field_tree = proto_item_add_subtree(ind_field_item, ett_dpnss_ind_field);
            offset = dissect_dpnss_sup_info_str(tvb, pinfo, ind_field_tree, offset);
            break;
        default:
            proto_tree_add_text(tree, tvb, offset, 1, "Dissection of this message not supported yet");
            break;
        }
    }
}


static void
dissect_dpnss_e2e_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *sel_field_item, *sic_field_item, *ind_field_item;
    proto_tree *sel_field_tree, *sic_field_tree, *ind_field_tree;
    int offset = 0;
    int tvb_end_offset;
    guint8 octet;

    tvb_end_offset = tvb_length(tvb);

    proto_tree_add_item(tree, hf_dpnss_e2e_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    octet = tvb_get_guint8(tvb,offset)&0x0f;
    offset++;
    if(check_col(pinfo->cinfo, COL_INFO))
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s ",
            val_to_str(octet, dpnss_e2e_msg_short_type_vals, "Unknown (%d)" ));
    if(tree){
        switch (octet){
        case DPNSS_E2E_MSG_EEM_C:
        /* 2.2.1 END-to-END Message (COMPLETE) - EEM(C) */
        case DPNSS_E2E_MSG_EEM_I:
            /* Fall trough */
            /* Indication Field */
            ind_field_item = proto_tree_add_text(tree, tvb, offset, -1,
                                                 "Indication Field: %s",
                                                 tvb_format_text(tvb,offset,tvb_length_remaining(tvb, offset)));
            ind_field_tree = proto_item_add_subtree(ind_field_item, ett_dpnss_ind_field);
            offset = dissect_dpnss_sup_info_str(tvb, pinfo, ind_field_tree, offset);
            break;
        case DPNSS_E2E_MSG_SCRM:
            /* 2.2.3 SINGLE-CHANNEL CLEAR REQUEST Message - SCRM */
        case DPNSS_E2E_MSG_SCIM:
            /* 2.2.4 SINGLE-CHANNEL CLEAR INDICATION Message - SCIM */
            /* Clearing Cause */
            proto_tree_add_item(tree, hf_dpnss_clearing_cause, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            /* Indication Field (Optional) */
            if(tvb_end_offset>offset){
                ind_field_item = proto_tree_add_text(tree, tvb, offset, -1,
                                                     "Indication Field: %s",
                                                     tvb_format_text(tvb,offset,tvb_length_remaining(tvb, offset)));
                ind_field_tree = proto_item_add_subtree(ind_field_item, ett_dpnss_ind_field);
                offset = dissect_dpnss_sup_info_str(tvb, pinfo, ind_field_tree, offset);
            }
            break;
        case DPNSS_E2E_MSG_ERM_C:
            /* 2.2.5 END-to-END RECALL Message (COMPLETE) - ERM(C) */
        case DPNSS_E2E_MSG_ERM_I:
            /* 2.2.6 END-to-END RECALL Message (INCOMPLETE) - ERM(I) */
            /* Service Indicator Code
             * Note: On data calls the SIC may comprise more than one octet.
             * The Service Indicator Code is coded in accordance with ANNEX 1.
             */
            sic_field_item = proto_tree_add_text(tree, tvb, offset, -1, "Service Indicator Code");
            sic_field_tree = proto_item_add_subtree(sic_field_item, ett_dpnss_sic_field);
            offset =dissect_dpnss_sic(tvb, pinfo, sic_field_tree, offset);
            /*
             * Selection Field
             * The Selection Field contains the selection information relating
             * to a call set-up or Supplementary Service Request, and is
             * structured as shown in Subsection 3.
             */
            sel_field_item = proto_tree_add_text(tree, tvb, offset, -1,
                                                 "Selection Field: %s",
                                                 tvb_format_text(tvb,offset,tvb_length_remaining(tvb, offset)));
            sel_field_tree = proto_item_add_subtree(sel_field_item, ett_dpnss_sel_field);
            offset = dissect_dpnss_sup_info_str(tvb, pinfo, sel_field_tree, offset);
            break;
        case DPNSS_E2E_MSG_NSIM:
            /* 2.2.7 NON SPECIFIED INFORMATION Message - NSIM */
            /* Usage Identifier Oct 1 -
             * coding of the Usage Identifier, as described in section 49.
             * The use of NSIMs is described in greater detail in SECTION 49.
             * BIT  8       7 6 5 4 3          2 1
             *     ext | Manufacturer code | subcode
             */
            octet = tvb_get_guint8(tvb,offset);
            proto_tree_add_item(tree, hf_dpnss_ext_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_dpnss_man_code, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_dpnss_subcode, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            if((octet&0x80)==0x80){
                /* Extension bit set */
                offset++;
            }
            /* User Information oct 2 + n
             */
            proto_tree_add_text(tree, tvb, offset, -1, "User Information");
            break;
        default:
            proto_tree_add_text(tree, tvb, offset, 1, "Dissection of this message not supported yet");
            break;
        }
    }
}

static void
dissect_dpnss_cc_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *sel_field_item, *sic_field_item, *ind_field_item;
    proto_tree *sel_field_tree, *sic_field_tree, *ind_field_tree;
    int offset = 0;
    int tvb_end_offset;
    guint8 octet;

    tvb_end_offset = tvb_length(tvb);
    proto_tree_add_item(tree, hf_dpnss_cc_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    octet = tvb_get_guint8(tvb,offset)&0x0f;
    offset++;
    if(check_col(pinfo->cinfo, COL_INFO))
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s ",
            val_to_str(octet, dpnss_cc_msg_short_type_vals, "Unknown (%d)" ));

    if(tree){
        switch (octet){
        case DPNSS_CC_MSG_ISRM_C:
            /* 2.1.1 INITIAL SERVICE REQUEST Message (COMPLETE) - ISRM (C) */
            /* fall trough */
        case DPNSS_CC_MSG_ISRM_I:
            /* 2.1.2 INITIAL SERVICE REQUEST Message (INCOMPLETE) - ISRM(I) */
        case DPNSS_CC_MSG_RM_C:
            /* 2.1.3 RECALL Message (COMPLETE) - RM(C) */
            /* fall trough */
        case DPNSS_CC_MSG_RM_I:
            /* 2.1.4 RECALL Message (INCOMPLETE) - RM(I)*/
            /* fall trough */
            /* Service Indicator Code
             * Note: On data calls the SIC may comprise more than one octet.
             * The Service Indicator Code is coded in accordance with ANNEX 1.
             */
            sic_field_item = proto_tree_add_text(tree, tvb, offset, -1, "Service Indicator Code");
            sic_field_tree = proto_item_add_subtree(sic_field_item, ett_dpnss_sic_field);
            offset =dissect_dpnss_sic(tvb, pinfo, sic_field_tree, offset);
            /*
             * Selection Field
             * The Selection Field contains the selection information relating
             * to a call set-up or Supplementary Service Request, and is
             * structured as shown in Subsection 3.
             */
            sel_field_item = proto_tree_add_text(tree, tvb, offset, -1,
                                                 "Selection Field: %s",
                                                 tvb_format_text(tvb,offset,tvb_length_remaining(tvb, offset)));
            sel_field_tree = proto_item_add_subtree(sel_field_item, ett_dpnss_sel_field);
            offset = dissect_dpnss_sup_info_str(tvb, pinfo, sel_field_tree, offset);
            break;
        case DPNSS_CC_MSG_CCM:
            /* 2.1.5 CALL CONNECTED Message - CCM */
            if(tvb_end_offset>offset){
                /* Indication Field (Optional) */
                ind_field_item = proto_tree_add_text(tree, tvb, offset, -1,
                                                     "Indication Field: %s",
                                                     tvb_format_text(tvb,offset,tvb_length_remaining(tvb, offset)));
                ind_field_tree = proto_item_add_subtree(ind_field_item, ett_dpnss_ind_field);
                offset = dissect_dpnss_sup_info_str(tvb, pinfo, ind_field_tree, offset);
            }
            break;
        case DPNSS_CC_MSG_NIM:
            /* 2.1.6 NETWORK INDICATION Message - NIM */
            /* fall trough */
        case DPNSS_CC_MSG_NAM:
            /* 2.1.9 NUMBER ACKNOWLEDGE Message - NAM */
            /* Indication Field */
            ind_field_item = proto_tree_add_text(tree, tvb, offset, -1,
                                                 "Indication Field: %s",
                                                 tvb_format_text(tvb,offset,tvb_length_remaining(tvb, offset)));
            ind_field_tree = proto_item_add_subtree(ind_field_item, ett_dpnss_ind_field);
            offset = dissect_dpnss_sup_info_str(tvb, pinfo, ind_field_tree, offset);
            break;
        case DPNSS_CC_MSG_CRM:
            /* 2.1.7 CLEAR REQUEST Message - CRM */
            /* 2.1.8 CLEAR INDICATION Message - CIM */
            /* Clearing Cause */
            proto_tree_add_item(tree, hf_dpnss_clearing_cause, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            /* Indication Field (Optional) */
            if(tvb_end_offset>offset){
                ind_field_item = proto_tree_add_text(tree, tvb, offset, -1,
                                                     "Indication Field: %s",
                                                     tvb_format_text(tvb,offset,tvb_length_remaining(tvb, offset)));
                ind_field_tree = proto_item_add_subtree(ind_field_item, ett_dpnss_ind_field);
                offset = dissect_dpnss_sup_info_str(tvb, pinfo, ind_field_tree, offset);
            }
            break;
        case DPNSS_CC_MSG_RRM:
            /* 2.1.10 RECALL REJECTION Message - RRM */
            /* Rejection Cause */
            proto_tree_add_item(tree, hf_dpnss_rejection_cause, tvb, offset, 1, ENC_BIG_ENDIAN);
            /* Indication Field (Optional) */
            if(tvb_end_offset>offset){
                ind_field_item = proto_tree_add_text(tree, tvb, offset, -1,
                                                     "Indication Field: %s",
                                                     tvb_format_text(tvb,offset,tvb_length_remaining(tvb, offset)));
                ind_field_tree = proto_item_add_subtree(ind_field_item, ett_dpnss_ind_field);
                offset = dissect_dpnss_sup_info_str(tvb, pinfo, ind_field_tree, offset);
            }
            break;
        case DPNSS_CC_MSG_SSRM_I:
            /* 2.1.11 SUBSEQUENT SERVICE REQUEST Message (INCOMPLETE) - SSRM(I) */
            /* Selection Field */
            sel_field_item = proto_tree_add_text(tree, tvb, offset, -1,
                                                 "Selection Field: %s",
                                                 tvb_format_text(tvb,offset,tvb_length_remaining(tvb, offset)));
            sel_field_tree = proto_item_add_subtree(sel_field_item, ett_dpnss_sel_field);
            offset = dissect_dpnss_sup_info_str(tvb, pinfo, sel_field_tree, offset);
            break;
        case DPNSS_CC_MSG_SSRM_C:
            /* 2.1.12 SUBSEQUENT SERVICE REQUEST Message (COMPLETE) - SSRM(C) */
            /* Selection Field (Optional) */
            if(tvb_end_offset>offset){
                sel_field_item = proto_tree_add_text(tree, tvb, offset, -1,
                                                     "Selection Field: %s",
                                                     tvb_format_text(tvb,offset,tvb_length_remaining(tvb, offset)));
                sel_field_tree = proto_item_add_subtree(sel_field_item, ett_dpnss_sel_field);
                offset = dissect_dpnss_sup_info_str(tvb, pinfo, sel_field_tree, offset);
            }
            break;
        case DPNSS_CC_MSG_CS:
        case DPNSS_CC_MSG_CA:
            /* DASS2 ?*/
        default:
            proto_tree_add_text(tree, tvb, offset, 1, "Unknown or Dissection of this message not supported yet");
            break;
        }
    }
}
/* Code to actually dissect the packets */
static void
dissect_dpnss(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    proto_item *item;
    proto_tree *dpnss_tree;
    guint8 octet;

/* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DPNSS");

    item = proto_tree_add_item(tree, proto_dpnss, tvb, 0, -1, ENC_NA);
    dpnss_tree = proto_item_add_subtree(item, ett_dpnss);
    proto_tree_add_item(dpnss_tree, hf_dpnss_msg_grp_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    octet = tvb_get_guint8(tvb,offset)>>4;
    switch (octet){
    case DPNNS_MESSAGE_GROUP_CC:
        /* Call Control Message Group */
        dissect_dpnss_cc_msg(tvb, pinfo, dpnss_tree);
        break;
    case DPNNS_MESSAGE_GROUP_E2E:
        /* End-to-End Message Group */
        dissect_dpnss_e2e_msg(tvb, pinfo, dpnss_tree);
        break;
    case DPNNS_MESSAGE_GROUP_LbL:
        /* Link-by-Link Message Group */
        dissect_dpnss_LbL_msg(tvb, pinfo, dpnss_tree);
        break;
    default:
        proto_tree_add_text(tree, tvb, offset, 1, "Unknown Message Group");
        break;
    }
}

void
proto_register_dpnss(void)
{


/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_dpnss_msg_grp_id,
            { "Message Group Identifier",           "dpnss.msg_grp_id",
            FT_UINT8, BASE_DEC, VALS(dpnss_msg_grp_id_vals), 0xf0,
            NULL, HFILL }
        },
        { &hf_dpnss_cc_msg_type,
            { "Call Control Message Type",           "dpnss.cc_msg_type",
            FT_UINT8, BASE_DEC, VALS(dpnss_cc_msg_type_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_dpnss_e2e_msg_type,
            { "END-TO-END Message Type",           "dpnss.e2e_msg_type",
            FT_UINT8, BASE_DEC, VALS(dpnss_e2e_msg_type_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_dpnss_LbL_msg_type,
            { "LINK-BY-LINK Message Type",           "dpnss.lbl_msg_type",
            FT_UINT8, BASE_DEC, VALS(dpnss_LbL_msg_type_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_dpnss_ext_bit,
            { "Extension bit",           "dpnss.ext_bit",
            FT_BOOLEAN, 8, TFS(&dpnss_ext_bit_vals), 0x80,
            NULL, HFILL }
        },
        { &hf_dpnss_ext_bit_notall,
            { "Extension bit",           "dpnss.ext_bit_notall",
            FT_BOOLEAN, 8, TFS(&dpnss_ext_bit_no_ext_vals), 0x80,
            NULL, HFILL }
        },
        { &hf_dpnss_sic_type,
            { "Type of data",           "dpnss.sic_type",
            FT_UINT8, BASE_DEC, VALS(dpnss_sic_type_type_vals), 0x70,
            NULL, HFILL }
        },
        { &hf_dpnss_sic_details_for_speech,
            { "Details for Speech",           "dpnss.sic_details_for_speech",
            FT_UINT8, BASE_DEC, VALS(dpnss_sic_details_for_speech_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_dpnss_sic_details_for_data1,
            { "Data Rates",           "dpnss.sic_details_for_data1",
            FT_UINT8, BASE_DEC, VALS(dpnss_sic_details_for_data_rates1_vals), 0x0f,
            "Type of Data (010) : Data Rates", HFILL }
        },
        { &hf_dpnss_sic_details_for_data2,
            { "Data Rates",           "dpnss.sic_details_data2",
            FT_UINT8, BASE_DEC, VALS(dpnss_sic_details_for_data_rates2_vals), 0x0f,
            "Type of Data (011) : Data Rates", HFILL }
        },
        { &hf_dpnss_dest_addr,
            { "Destination Address",           "dpnss.dest_addr",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_dpnss_sic_oct2_data_type,
            { "Data Type",           "dpnss.sic_oct2_data_type",
            FT_UINT8, BASE_DEC, VALS(dpnss_sic_oct2_data_type_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_dpnss_sic_oct2_duplex,
            { "Data Type",           "dpnss.sic_oct2_duplex",
            FT_BOOLEAN, 8, TFS(&dpnss_duplex_vals), 0x08,
            NULL, HFILL }
        },
        { &hf_dpnss_sic_oct2_net_ind_clk,
            { "Network Independent Clock",           "dpnss.sic_oct2_sync_data_format",
            FT_BOOLEAN, 8, TFS(&dpnss_sic_oct2_net_ind_clk_vals), 0x40,
            NULL, HFILL }
        },
        { &hf_dpnss_sic_oct2_sync_data_format,
            { "Data Format",           "dpnss.sic_oct2_sync_data_format",
            FT_BOOLEAN, 8, TFS(&dpnss_sic_oct2_sync_data_format_vals), 0x20,
            NULL, HFILL }
        },
        { &hf_dpnss_sic_oct2_sync_byte_timing,
            { "Byte Timing",           "dpnss.sic_oct2_sync_byte_timing",
            FT_BOOLEAN, 8, TFS(&dpnss_provided_vals), 0x10,
            NULL, HFILL }
        },
        { &hf_dpnss_sic_oct2_async_data,
            { "Data Format",           "dpnss.sic_oct2_async_data",
            FT_UINT8, BASE_DEC, VALS(dpnss_sic_oct2_async_data_type_vals), 0x30,
            NULL, HFILL }
        },
        { &hf_dpnss_sic_oct2_async_flow_ctrl,
            { "Flow Control",           "dpnss.sic_oct2_async_flow_ctrl",
            FT_BOOLEAN, 8, TFS(&dpnss_flow_control_vals), 0x40,
            NULL, HFILL }
        },
        { &hf_dpnss_clearing_cause,
            { "Clearing Cause",           "dpnss.clearing_cause",
            FT_UINT8, BASE_DEC, VALS(dpnss_clearing_cause_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_dpnss_rejection_cause,
            { "Rejection Cause",           "dpnss.rejection_cause",
            FT_UINT8, BASE_DEC, VALS(dpnss_clearing_cause_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_dpnss_man_code,
            { "Manufacturer Code",           "dpnss.man_code",
            FT_UINT8, BASE_DEC, VALS(dpnss_man_code_vals), 0x3c,
            NULL, HFILL }
        },
        { &hf_dpnss_subcode,
            { "Subcode",           "dpnss.subcode",
            FT_UINT8, BASE_DEC, NULL, 0x03,
            NULL, HFILL }
        },
        { &hf_dpnss_maintenance_action,
            { "Maintenance action",           "dpnss.maint_act",
            FT_UINT8, BASE_DEC, VALS(dpnss_maintenance_actions_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_dpnss_a_b_party_addr,
            { "A/B party Address",           "dpnss.a_b_party_addr",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_dpnss_call_idx,
            { "Call Index",           "dpnss.call_idx",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };

/* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_dpnss,
        &ett_dpnss_sel_field,
        &ett_dpnss_sic_field,
        &ett_dpnss_ind_field,
        &ett_dpnss_sup_str,
    };

/* Register the protocol name and description */
    proto_dpnss = proto_register_protocol("Digital Private Signalling System No 1","DPNSS", "dpnss");
    register_dissector("dpnss", dissect_dpnss, proto_dpnss);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_dpnss, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

}
