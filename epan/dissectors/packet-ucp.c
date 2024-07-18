/* packet-ucp.c
 * Routines for Universal Computer Protocol dissection
 * Copyright 2001, Tom Uijldert <tom.uijldert@cmg.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 * ----------
 *
 * Dissector of a UCP (Universal Computer Protocol) PDU, as defined for the
 * ERMES paging system in ETS 300 133-3 (2nd final draft, September 1997,
 * www.etsi.org).
 * Includes the extension of EMI-UCP interface
 * (V4.0, May 2001, www.advox.se/download/protocols/EMI_UCP.pdf)
 *
 * Support for statistics using the Stats Tree API added by
 * Abhik Sarkar <sarkar.abhik@gmail.com>
 *
 */

#include "config.h"

#include <stdlib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/stats_tree.h>
#include <epan/charsets.h>

#include <wsutil/strtoi.h>

#include "packet-tcp.h"

void proto_register_ucp(void);
void proto_reg_handoff_ucp(void);

/* Tap Record */
typedef struct _ucp_tap_rec_t {
    unsigned message_type; /* 0 = Operation; 1 = Result */
    unsigned operation;    /* Operation Type */
    unsigned result;       /* 0 = Success; Non 0 = Error Code */
} ucp_tap_rec_t;

/* Preferences */
static bool ucp_desegment = true;

/* STX + TRN(2 num. char.) + / + LEN(5 num. char.) + / + 'O'/'R' + / + OT(2 num. char.) + / */
#define UCP_HEADER_SIZE 15

/*
 * Convert ASCII-hex character to binary equivalent. No checks, assume
 * is valid hex character.
 */
#define AHex2Bin(n)     (((n) & 0x40) ? ((n) & 0x0F) + 9 : ((n) & 0x0F))

#define UCP_STX       0x02                      /* Start of UCP PDU      */
#define UCP_ETX       0x03                      /* End of UCP PDU        */

#define UCP_MALFORMED   -1                      /* Not a valid PDU       */
#define UCP_INV_CHK     -2                      /* Incorrect checksum    */

#define UCP_TRN_OFFSET   1
#define UCP_LEN_OFFSET   4
#define UCP_O_R_OFFSET  10                      /* Location of O/R field */
#define UCP_OT_OFFSET   12                      /* Location of OT field  */

#define UCP_TRN_LEN      2                      /* Length of TRN-field   */
#define UCP_LEN_LEN      5                      /* Length of LEN-field   */
#define UCP_O_R_LEN      1                      /* Length of O/R-field   */
#define UCP_OT_LEN       2                      /* Length of OT-field    */


static  dissector_handle_t ucp_handle;

/*
 * Initialize the protocol and registered fields
 *
 * Header (fixed) section
 */
static int proto_ucp;

static int hf_ucp_hdr_TRN;
static int hf_ucp_hdr_LEN;
static int hf_ucp_hdr_O_R;
static int hf_ucp_hdr_OT;

/*
 * Stats section
 */
static int st_ucp_messages       = -1;
static int st_ucp_ops            = -1;
static int st_ucp_res            = -1;
static int st_ucp_results        = -1;
static int st_ucp_results_pos    = -1;
static int st_ucp_results_neg    = -1;

static const char st_str_ucp[]     = "UCP Messages";
static const char st_str_ops[]     = "Operations";
static const char st_str_res[]     = "Results";
static const char st_str_ucp_res[] = "UCP Results Acks/Nacks";
static const char st_str_pos[]     = "Positive";
static const char st_str_neg[]     = "Negative";

/*
 * Data (variable) section
 */
static int hf_ucp_oper_section;
static int hf_ucp_parm_AdC;
static int hf_ucp_parm_OAdC;
static int hf_ucp_parm_DAdC;
static int hf_ucp_parm_AC;
static int hf_ucp_parm_OAC;
static int hf_ucp_parm_BAS;
static int hf_ucp_parm_LAR;
static int hf_ucp_parm_LAC;
static int hf_ucp_parm_L1R;
static int hf_ucp_parm_L1P;
static int hf_ucp_parm_L3R;
static int hf_ucp_parm_L3P;
static int hf_ucp_parm_LCR;
static int hf_ucp_parm_LUR;
static int hf_ucp_parm_LRR;
static int hf_ucp_parm_RT;
static int hf_ucp_parm_NoN;
static int hf_ucp_parm_NoA;
static int hf_ucp_parm_NoB;
static int hf_ucp_parm_NAC;
static int hf_ucp_parm_PNC;
static int hf_ucp_parm_AMsg;
static int hf_ucp_parm_LNo;
static int hf_ucp_parm_LST;
static int hf_ucp_parm_TNo;
static int hf_ucp_parm_CS;
static int hf_ucp_parm_PID;
static int hf_ucp_parm_NPL;
static int hf_ucp_parm_GA;
static int hf_ucp_parm_RP;
static int hf_ucp_parm_LRP;
static int hf_ucp_parm_PR;
static int hf_ucp_parm_LPR;
static int hf_ucp_parm_UM;
static int hf_ucp_parm_LUM;
static int hf_ucp_parm_RC;
static int hf_ucp_parm_LRC;
static int hf_ucp_parm_NRq;
static int hf_ucp_parm_GAdC;
static int hf_ucp_parm_A_D;
static int hf_ucp_parm_CT;
static int hf_ucp_parm_AAC;
static int hf_ucp_parm_MNo;
static int hf_ucp_parm_R_T;
static int hf_ucp_parm_IVR5x;
static int hf_ucp_parm_REQ_OT;
static int hf_ucp_parm_SSTAT;
static int hf_ucp_parm_LMN;
static int hf_ucp_parm_NMESS;
static int hf_ucp_parm_NAdC;
static int hf_ucp_parm_NT;
static int hf_ucp_parm_NPID;
static int hf_ucp_parm_LRq;
static int hf_ucp_parm_LRAd;
static int hf_ucp_parm_LPID;
static int hf_ucp_parm_DD;
static int hf_ucp_parm_DDT;
static int hf_ucp_parm_STx;
static int hf_ucp_parm_ST;
static int hf_ucp_parm_SP;
static int hf_ucp_parm_VP;
static int hf_ucp_parm_RPID;
static int hf_ucp_parm_SCTS;
static int hf_ucp_parm_Dst;
static int hf_ucp_parm_Rsn;
static int hf_ucp_parm_DSCTS;
static int hf_ucp_parm_MT;
static int hf_ucp_parm_NB;
static int hf_ucp_data_section;
static int hf_ucp_parm_MMS;
static int hf_ucp_parm_DCs;
static int hf_ucp_parm_MCLs;
static int hf_ucp_parm_RPI;
static int hf_ucp_parm_CPg;
static int hf_ucp_parm_RPLy;
static int hf_ucp_parm_OTOA;
static int hf_ucp_parm_HPLMN;
static int hf_ucp_parm_RES4;
static int hf_ucp_parm_RES5;
static int hf_ucp_parm_OTON;
static int hf_ucp_parm_ONPI;
static int hf_ucp_parm_STYP0;
static int hf_ucp_parm_STYP1;
static int hf_ucp_parm_ACK;
static int hf_ucp_parm_PWD;
static int hf_ucp_parm_NPWD;
static int hf_ucp_parm_VERS;
static int hf_ucp_parm_LAdC;
static int hf_ucp_parm_LTON;
static int hf_ucp_parm_LNPI;
static int hf_ucp_parm_OPID;
static int hf_ucp_parm_RES1;
static int hf_ucp_parm_RES2;
static int hf_ucp_parm_MVP;
static int hf_ucp_parm_EC;
static int hf_ucp_parm_SM;
static int hf_ucp_not_subscribed;
static int hf_ucp_ga_roaming;
static int hf_ucp_call_barring;
static int hf_ucp_deferred_delivery;
static int hf_ucp_diversion;

static int hf_ucp_parm_XSer;
static int hf_xser_service;
static int hf_xser_length;
static int hf_xser_data;

/* Initialize the subtree pointers */
static int ett_ucp;
static int ett_sub;
static int ett_XSer;

static expert_field ei_ucp_stx_missing;
static expert_field ei_ucp_intstring_invalid;
static expert_field ei_ucp_hexstring_invalid;
static expert_field ei_ucp_short_data;

/* Tap */
static int ucp_tap;

/*
 * Value-arrays for certain field-contents
 */
static const value_string vals_hdr_O_R[] = {
    {  'O', "Operation" },
    {  'R', "Result" },
    {  0, NULL }
};

static const value_string vals_hdr_OT[] = {     /* Operation type       */
    {  0, "Enquiry" },
    {  1, "Call input" },
    {  2, "Call input (multiple address)" },
    {  3, "Call input (supplementary services included)" },
    {  4, "Address list information" },
    {  5, "Change address list" },
    {  6, "Advice of accumulated charges" },
    {  7, "Password management" },
    {  8, "Legitimisation code management" },
    {  9, "Standard text information" },
    { 10, "Change standard text" },
    { 11, "Request roaming information" },
    { 12, "Change roaming information" },
    { 13, "Roaming reset" },
    { 14, "Message retrieval" },
    { 15, "Request call barring" },
    { 16, "Cancel call barring" },
    { 17, "Request call diversion" },
    { 18, "Cancel call diversion" },
    { 19, "Request deferred delivery" },
    { 20, "Cancel deferred delivery" },
    { 21, "All features reset" },
    { 22, "Call input (with specific character set)" },
    { 23, "UCP version status request" },
    { 24, "Mobile subscriber feature status request" },
    { 30, "SMS message transfer" },
    { 31, "SMT alert" },
    { 32, "(proprietary)" },
    { 34, "(proprietary)" },
    { 36, "(proprietary)" },
    { 38, "(proprietary)" },
    { 40, "(proprietary)" },
    { 41, "(proprietary)" },
    { 42, "(proprietary)" },
    { 43, "(proprietary)" },
    { 44, "(proprietary)" },
    { 45, "(proprietary)" },
    { 51, "Submit short message" },
    { 52, "Deliver short message" },
    { 53, "Deliver notification" },
    { 54, "Modify message" },
    { 55, "Inquiry message" },
    { 56, "Delete message" },
    { 57, "Inquiry response message" },
    { 58, "Delete response message" },
    { 60, "Session management" },
    { 61, "List management" },
    { 95, "(proprietary)" },
    { 96, "(proprietary)" },
    { 97, "(proprietary)" },
    { 98, "(proprietary)" },
    { 99, "(proprietary)" },
    {  0, NULL }
};
static value_string_ext vals_hdr_OT_ext = VALUE_STRING_EXT_INIT(vals_hdr_OT);

static const value_string vals_parm_EC[] = {    /* Error code   */
    {  1, "Checksum error" },
    {  2, "Syntax error" },
    {  3, "Operation not supported by system" },
    {  4, "Operation not allowed" },
    {  5, "Call barring active" },
    {  6, "AdC invalid" },
    {  7, "Authentication failure" },
    {  8, "Legitimisation code for all calls, failure" },
    {  9, "GA not valid" },
    { 10, "Repetition not allowed" },
    { 11, "Legitimisation code for repetition, failure" },
    { 12, "Priority call not allowed" },
    { 13, "Legitimisation code for priority call, failure" },
    { 14, "Urgent message not allowed" },
    { 15, "Legitimisation code for urgent message, failure" },
    { 16, "Reverse charging not allowed" },
    { 17, "Legitimisation code for rev. charging, failure" },
    { 18, "Deferred delivery not allowed" },
    { 19, "New AC not valid" },
    { 20, "New legitimisation code not valid" },
    { 21, "Standard text not valid" },
    { 22, "Time period not valid" },
    { 23, "Message type not supported by system" },
    { 24, "Message too long" },
    { 25, "Requested standard text not valid" },
    { 26, "Message type not valid for the pager type" },
    { 27, "Message not found in SMSC" },
    { 28, "Invalid character set" },
    { 30, "Subscriber hang-up" },
    { 31, "Fax group not supported" },
    { 32, "Fax message type not supported" },
    { 33, "Address already in list (60-series)" },
    { 34, "Address not in list (60-series)" },
    { 35, "List full, cannot add address to list (60-series)" },
    { 36, "RPID already in use" },
    { 37, "Delivery in progress" },
    { 38, "Message forwarded" },
    { 50, "Low network status" },
    { 51, "Legitimisation code for standard text, failure" },
    { 53, "Operation partially successful" },
    { 54, "Operation not successful" },
    { 55, "System error" },
    { 57, "AdC already a member of GAdC address list" },
    { 58, "AdC not a member of GAdC address list" },
    { 59, "Requested standard text list invalid" },
    { 61, "Not controller of GAdC address list" },
    { 62, "Standard text too large" },
    { 63, "Not owner of standard text list" },
    { 64, "Address list full" },
    { 65, "GAdC invalid" },
    { 66, "Operation restricted to mobile subscribers" },
    { 68, "Invalid AdC type" },
    { 69, "Cannot add AdC to GAdC address list" },
    { 90, "(proprietary error code)" },
    { 91, "(proprietary error code)" },
    { 92, "(proprietary error code)" },
    { 93, "(proprietary error code)" },
    { 94, "(proprietary error code)" },
    { 95, "(proprietary error code)" },
    { 96, "(proprietary error code)" },
    { 97, "(proprietary error code)" },
    { 98, "(proprietary error code)" },
    { 99, "(proprietary error code)" },
    {  0, NULL },
};
static value_string_ext vals_parm_EC_ext = VALUE_STRING_EXT_INIT(vals_parm_EC);

static const value_string vals_parm_NRq[] = {
    {  '0', "NAdC not used" },
    {  '1', "NAdC used" },
    {  0, NULL },
};

static const value_string vals_parm_NT[] = {
    {  '0', "Default value" },
    {  '1', "Delivery notification" },
    {  '2', "Non-delivery notification" },
    {  '3', "Delivery and Non-delivery notification" },
    {  '4', "Buffered message notification" },
    {  '5', "Buffered and Delivery notification" },
    {  '6', "Buffered and Non-delivery notification" },
    {  '7', "All notifications" },
    {  0, NULL },
};

static const value_string vals_parm_PID[] = {
    {  100, "Mobile station" },
    {  122, "Fax Group 3" },
    {  131, "X.400" },
    {  138, "Menu over PSTN" },
    {  139, "PC appl. over PSTN (E.164)" },
    {  339, "PC appl. over X.25 (X.121)" },
    {  439, "PC appl. over ISDN (E.164)" },
    {  539, "PC appl. over TCP/IP" },
    {  639, "PC appl. via abbreviated number" },
    {  0, NULL },
};

static const value_string vals_parm_LRq[] = {
    {  '0', "LRAd not used" },
    {  '1', "LRAd used" },
    {  0, NULL },
};

static const value_string vals_parm_DD[] = {
    {  '0', "DDT not used" },
    {  '1', "DDT used" },
    {  0, NULL },
};

static const value_string vals_parm_Dst[] = {
    {  '0', "delivered" },
    {  '1', "buffered (see Rsn)" },
    {  '2', "not delivered (see Rsn)" },
    {  0, NULL },
};

static const value_string vals_parm_Rsn[] = {
    {    0, "Unknown subscriber" },
    {    1, "Service temporary not available" },
    {    2, "Service temporary not available" },
    {    3, "Service temporary not available" },
    {    4, "Service temporary not available" },
    {    5, "Service temporary not available" },
    {    6, "Service temporary not available" },
    {    7, "Service temporary not available" },
    {    8, "Service temporary not available" },
    {    9, "Illegal error code" },
    {   10, "Network time-out" },
    {  100, "Facility not supported" },
    {  101, "Unknown subscriber" },
    {  102, "Facility not provided" },
    {  103, "Call barred" },
    {  104, "Operation barred" },
    {  105, "SC congestion" },
    {  106, "Facility not supported" },
    {  107, "Absent subscriber" },
    {  108, "Delivery fail" },
    {  109, "Sc congestion" },
    {  110, "Protocol error" },
    {  111, "MS not equipped" },
    {  112, "Unknown SC" },
    {  113, "SC congestion" },
    {  114, "Illegal MS" },
    {  115, "MS nota subscriber" },
    {  116, "Error in MS" },
    {  117, "SMS lower layer not provisioned" },
    {  118, "System fail" },
    {  119, "PLMN system failure" },
    {  120, "HLR system failure" },
    {  121, "VLR system failure" },
    {  122, "Previous VLR system failure" },
    {  123, "Controlling MSC system failure" },
    {  124, "VMSC system failure" },
    {  125, "EIR system failure" },
    {  126, "System failure" },
    {  127, "Unexpected data value" },
    {  200, "Error in address service centre" },
    {  201, "Invalid absolute validity period" },
    {  202, "Short message exceeds maximum" },
    {  203, "Unable to unpack GSM message" },
    {  204, "Unable to convert to IRA alphabet" },
    {  205, "Invalid validity period format" },
    {  206, "Invalid destination address" },
    {  207, "Duplicate message submit" },
    {  208, "Invalid message type indicator" },
    {  0, NULL },
};
static value_string_ext vals_parm_Rsn_ext = VALUE_STRING_EXT_INIT(vals_parm_Rsn);

static const value_string vals_parm_MT[] = {
    {  '2', "Numeric message" },
    {  '3', "Alphanumeric message" },
    {  '4', "Transparent data" },
    {  0, NULL },
};

static const value_string vals_parm_DCs[] = {
    {  '0', "default alphabet" },
    {  '1', "User defined data (8 bit)" },
    {  0, NULL },
};

static const value_string vals_parm_MCLs[] = {
    {  '0', "message class 0" },
    {  '1', "message class 1" },
    {  '2', "message class 2" },
    {  '3', "message class 3" },
    {  0, NULL },
};

static const value_string vals_parm_RPI[] = {
    {  '1', "Request" },
    {  '2', "Response" },
    {  0, NULL },
};

static const value_string vals_parm_ACK[] = {
    {  'A', "Ack" },
    {  'N', "Nack" },
    {  0, NULL },
};

static const value_string vals_parm_RP[] = {
    {  '1', "Repetition requested" },
    {  0, NULL },
};

static const value_string vals_parm_UM[] = {
    {  '1', "Urgent message" },
    {  0, NULL },
};

static const value_string vals_parm_RC[] = {
    {  '1', "Reverse charging request" },
    {  0, NULL },
};

static const value_string vals_parm_OTOA[] = {
    { 1139, "The OAdC is set to NPI telephone and TON international" },
    { 5039, "The OAdC contains an alphanumeric address" },
    { 0, NULL }
};

static const value_string vals_parm_OTON[] = {
    {  '1', "International number" },
    {  '2', "National number" },
    {  '6', "Abbreviated number (short number alias)" },
    {  0, NULL },
};

static const value_string vals_parm_ONPI[] = {
    {  '1', "E.164 address" },
    {  '3', "X.121 address" },
    {  '5', "Private -TCP/IP or abbreviated number- address" },
    {  0, NULL },
};

static const value_string vals_parm_STYP0[] = {
    {  '1', "open session" },
    {  '2', "reserved" },
    {  '3', "change password" },
    {  '4', "open provisioning session" },
    {  '5', "reserved" },
    {  '6', "change provisioning password" },
    {  0, NULL },
};

static const value_string vals_parm_STYP1[] = {
    {  '1', "add item to mo-list" },
    {  '2', "remove item from mo-list" },
    {  '3', "verify item mo-list" },
    {  '4', "add item to mt-list" },
    {  '5', "remove item from mt-list" },
    {  '6', "verify item mt-list" },
    {  0, NULL },
};

static const value_string vals_parm_OPID[] = {
    {  0, "Mobile station" },
    {  39, "PC application" },
    {  0, NULL },
};

static const value_string vals_parm_BAS[] = {
    {  '1', "Barred" },
    {  0, NULL },
};

static const value_string vals_parm_LAR[] = {
    {  '1', "Leg. code for all calls requested" },
    {  0, NULL },
};

static const value_string vals_parm_L1R[] = {
    {  '1', "Leg. code for priority 1 requested" },
    {  0, NULL },
};

static const value_string vals_parm_L3R[] = {
    {  '1', "Leg. code for priority 3 requested" },
    {  0, NULL },
};

static const value_string vals_parm_LCR[] = {
    {  '1', "Leg. code for reverse charging requested" },
    {  0, NULL },
};

static const value_string vals_parm_LUR[] = {
    {  '1', "Leg. code for urgent message requested" },
    {  0, NULL },
};

static const value_string vals_parm_LRR[] = {
    {  '1', "Leg. code for repetition requested" },
    {  0, NULL },
};

static const value_string vals_parm_RT[] = {
    {  '1', "Tone only" },
    {  '2', "Numeric" },
    {  '3', "Alphanumeric" },
    {  '4', "Transparent data" },
    {  0, NULL },
};

static const value_string vals_parm_PNC[] = {
    {  'H', "Home PNC" },
    {  'I', "Input PNC" },
    {  0, NULL },
};

static const value_string vals_parm_A_D[] = {
    {  'A', "Add" },
    {  'D', "Delete" },
    {  0, NULL },
};

static const value_string vals_parm_R_T[] = {
    {  'R', "Retrieval Ok" },
    {  'T', "Retransmit on radio channel" },
    {  0, NULL },
};

static const value_string vals_parm_REQ_OT[] = {
    {  'S', "Send used operation types" },
    {  'N', "Don't send used operation types" },
    {  0, NULL },
};

static const value_string vals_parm_SSTAT[] = {
    {  '0', "All services" },
    {  '1', "All in the moment active services" },
    {  '2', "Call diversion" },
    {  '3', "Roaming information status" },
    {  '4', "Call barring status" },
    {  '5', "Deferred delivery status" },
    {  '6', "Number of stored messages" },
    {  0, NULL },
};

static const value_string vals_xser_service[] = {
    {  0, "Not Used" },
    {  1, "GSM UDH information" },
    {  2, "GSM DCS information" },
    {  3, "[Message Type]            TDMA information exchange" },
    {  4, "[Message Reference]       TDMA information exchange" },
    {  5, "[Privacy Indicator]       TDMA information exchange" },
    {  6, "[Urgency Indicator]       TDMA information exchange" },
    {  7, "[Acknowledgement Request] TDMA information exchange" },
    {  8, "[Message Updating]        TDMA information exchange" },
    {  9, "[Call Back Number]        TDMA information exchange" },
    { 10, "[Response Code]           TDMA information exchange" },
    { 11, "[Teleservice ID]          TDMA information exchange" },
    { 12, "Billing identifier" },
    { 13, "Single shot indicator" },
    { 14, "Originator TON" },
    { 15, "Originator NPI" },
    { 16, "Recipient TON" },
    { 17, "Recipient NPI" },
    { 18, "Message Original Submission Time" },
    { 19, "Destination Network Type" },
    {  0, NULL },
};
static value_string_ext vals_xser_service_ext = VALUE_STRING_EXT_INIT(vals_xser_service);

/* For statistics */
static void
ucp_stats_tree_init(stats_tree* st)
{
    st_ucp_messages    = stats_tree_create_node(st, st_str_ucp, 0, STAT_DT_INT, true);
    st_ucp_ops         = stats_tree_create_node(st, st_str_ops, st_ucp_messages, STAT_DT_INT, true);
    st_ucp_res         = stats_tree_create_node(st, st_str_res, st_ucp_messages, STAT_DT_INT, true);
    st_ucp_results     = stats_tree_create_node(st, st_str_ucp_res, 0, STAT_DT_INT, true);
    st_ucp_results_pos = stats_tree_create_node(st, st_str_pos, st_ucp_results, STAT_DT_INT, true);
    st_ucp_results_neg = stats_tree_create_node(st, st_str_neg, st_ucp_results, STAT_DT_INT, true);
}

static tap_packet_status
ucp_stats_tree_per_packet(stats_tree *st, /* st as it was passed to us */
                                      packet_info *pinfo _U_,
                                      epan_dissect_t *edt _U_,
                                      const void *p,
                                      tap_flags_t flags _U_) /* Used for getting UCP stats */
{
    const ucp_tap_rec_t *tap_rec = (const ucp_tap_rec_t*)p;

    tick_stat_node(st, st_str_ucp, 0, true);

    if (tap_rec->message_type == 0) /* Operation */
    {
        tick_stat_node(st, st_str_ops, st_ucp_messages, true);
        tick_stat_node(st, val_to_str_ext(tap_rec->operation, &vals_hdr_OT_ext,
                       "Unknown OT: %d"), st_ucp_ops, false);
    }
    else /* Result */
    {
        tick_stat_node(st, st_str_res, st_ucp_messages, true);
        tick_stat_node(st, val_to_str_ext(tap_rec->operation, &vals_hdr_OT_ext,
                       "Unknown OT: %d"), st_ucp_res, false);

        tick_stat_node(st, st_str_ucp_res, 0, true);

        if (tap_rec->result == 0) /* Positive Result */
        {
            tick_stat_node(st, st_str_pos, st_ucp_results, false);
        }
        else /* Negative Result */
        {
            tick_stat_node(st, st_str_neg, st_ucp_results, true);
            tick_stat_node(st, val_to_str_ext(tap_rec->result, &vals_parm_EC_ext,
                           "Unknown EC: %d"), st_ucp_results_neg, false);
        }
    }

    return TAP_PACKET_REDRAW;
}

/*!
 * Checks whether the PDU looks a bit like UCP and checks the checksum
 *
 * Note: check_ucp is called only with a buffer of at least LEN+2 bytes.
 *       IOW: The buffer should contain a complete UCP PDU [STX ... ETX]
 *
 * \param       tvb     The buffer with PDU-data
 * \param       endpkt  Returns pointer, indicating the end of the PDU
 *
 * \return              The state of this PDU
 *       0               Definitely UCP
 *       UCP_MALFORMED   ???
 *       UCP_INV_CHK     Nice packet, but checksum doesn't add up...
 */
static int
check_ucp(tvbuff_t *tvb, int *endpkt)
{
    unsigned     offset = 1;
    unsigned     checksum = 0;
    int          pkt_check, tmp;
    int          length;

    length = tvb_find_guint8(tvb, offset, -1, UCP_ETX);
    if (length == -1) {
        *endpkt = tvb_reported_length_remaining(tvb, offset);
        return UCP_MALFORMED;
    }
    for (; offset < (unsigned) (length - 2); offset++)
        checksum += tvb_get_uint8(tvb, offset);
    checksum &= 0xFF;
    tmp = tvb_get_uint8(tvb, offset++);
    pkt_check = AHex2Bin(tmp);
    tmp = tvb_get_uint8(tvb, offset++);
    pkt_check = 16 * pkt_check + AHex2Bin(tmp);
    *endpkt = offset + 1;
    if (checksum == (unsigned) pkt_check)
        return 0;
    else
        return UCP_INV_CHK;
}

/*!
 * UCP equivalent of mktime() (3). Convert date to standard 'time_t' format
 *
 * \param       len The length of datestr
 * \param       datestr The UCP-formatted date to convert
 *
 * \return              The date in standard 'time_t' format.
 */
static time_t
ucp_mktime(const int len, const char *datestr)
{
    struct tm    r_time;

    r_time.tm_mday = (10 * (datestr[0] - '0') + (datestr[1] - '0'));

    if (len >= 4)
        r_time.tm_mon  = (10 * (datestr[2] - '0') + (datestr[3] - '0')) - 1;
    else
        r_time.tm_mon  = 0;

    if (len >= 6)
        r_time.tm_year = (10 * (datestr[4] - '0') + (datestr[5] - '0'));
    else
        r_time.tm_year = 0;
    if (r_time.tm_year < 90)
        r_time.tm_year += 100;

    if (len >= 8)
        r_time.tm_hour = (10 * (datestr[6] - '0') + (datestr[7] - '0'));
    else
        r_time.tm_hour = 0;

    if (len >= 10)
        r_time.tm_min  = (10 * (datestr[8] - '0') + (datestr[9] - '0'));
    else
        r_time.tm_min  = 0;

    if (len >= 12)
        r_time.tm_sec  = (10 * (datestr[10] - '0') + (datestr[11] - '0'));
    else
        r_time.tm_sec  = 0;

    r_time.tm_isdst = -1;

    return mktime(&r_time);
}

/*!
 * Scanning routines to add standard types (byte, int, string, data)
 * to the protocol-tree. Each field is separated with a slash ('/').
 *
 * \param       tree    The protocol tree to add to
 * \param       tvb     Buffer containing the data
 * \param       field   The actual field, whose value needs displaying
 * \param       offset  Location of field within the buffer, returns location
 *                      of next field.
 *
 */
static proto_item*
ucp_handle_string(proto_tree *tree, tvbuff_t *tvb, int field, int *offset)
{
    proto_item  *ti = NULL;
    int          idx, len;

    idx = tvb_find_guint8(tvb, *offset, -1, '/');
    if (idx == -1) {
        /* Force the appropriate exception to be thrown. */
        len = tvb_captured_length_remaining(tvb, *offset);
        tvb_ensure_bytes_exist(tvb, *offset, len + 1);
    } else
        len = idx - *offset;
    if (len > 0)
        ti = proto_tree_add_item(tree, field, tvb, *offset, len, ENC_ASCII|ENC_NA);
    *offset += len;
    if (idx != -1)
        *offset += 1;   /* skip terminating '/' */
    return ti;
}

static void
ucp_handle_IRAstring(proto_tree *tree, tvbuff_t *tvb, int field, int *offset)
{
    GByteArray    *bytes;
    wmem_strbuf_t *strbuf;
    char          *strval = NULL;
    int           idx, len;
    int           tmpoff;

    idx = tvb_find_guint8(tvb, *offset, -1, '/');
    if (idx == -1) {
        /* Force the appropriate exception to be thrown. */
        len = tvb_captured_length_remaining(tvb, *offset);
        tvb_ensure_bytes_exist(tvb, *offset, len + 1);
    } else {
        len = idx - *offset;
    }
    bytes = g_byte_array_sized_new(len);
    if (tvb_get_string_bytes(tvb, *offset, len, ENC_ASCII|ENC_STR_HEX|ENC_SEP_NONE, bytes, &tmpoff)) {
        strval = get_ts_23_038_7bits_string_unpacked(wmem_packet_scope(), bytes->data, bytes->len);
    }
    strbuf = wmem_strbuf_new(wmem_packet_scope(), strval);
    while ((tmpoff + 1) < idx) {
        wmem_strbuf_append_unichar_repl(strbuf);
        tmpoff += 2;
        if ((tmpoff + 1) >= idx) break;
        bytes = g_byte_array_set_size(bytes, 0);
        if (tvb_get_string_bytes(tvb, tmpoff, idx-tmpoff, ENC_ASCII|ENC_STR_HEX|ENC_SEP_NONE, bytes, &tmpoff)) {
            strval = get_ts_23_038_7bits_string_unpacked(wmem_packet_scope(), bytes->data, bytes->len);
            wmem_strbuf_append(strbuf, strval);
        }
    }
    if (tmpoff < idx) {
        /* Odd string length, which is impossible and indicates an error. */
        wmem_strbuf_append_unichar_repl(strbuf);
    }
    g_byte_array_free(bytes, true);
    if (len > 0) {
        proto_tree_add_string(tree, field, tvb, *offset,
                              len, wmem_strbuf_finalize(strbuf));
    }
    *offset += len;
    if (idx != -1)
        *offset += 1;   /* skip terminating '/' */
}

static unsigned
ucp_handle_byte(proto_tree *tree, tvbuff_t *tvb, int field, int *offset)
{
    unsigned     intval = 0;

    if ((intval = tvb_get_uint8(tvb, (*offset)++)) != '/') {
        proto_tree_add_uint(tree, field, tvb, *offset - 1, 1, intval);
        (*offset)++;
    }
    return intval;
}

static unsigned
ucp_handle_int(proto_tree *tree, packet_info* pinfo, tvbuff_t *tvb, int field, int *offset)
{
    int           idx, len;
    const char   *strval;
    unsigned      intval = 0;
    bool          intval_valid;
    proto_item   *pi;

    idx = tvb_find_guint8(tvb, *offset, -1, '/');
    if (idx == -1) {
        /* Force the appropriate exception to be thrown. */
        len = tvb_captured_length_remaining(tvb, *offset);
        tvb_ensure_bytes_exist(tvb, *offset, len + 1);
    } else
        len = idx - *offset;
    strval = tvb_get_string_enc(wmem_packet_scope(), tvb, *offset, len, ENC_ASCII);
    if (len > 0) {
        intval_valid = ws_strtou32(strval, NULL, &intval);
        pi = proto_tree_add_uint(tree, field, tvb, *offset, len, intval);
        if (!intval_valid)
            expert_add_info_format(pinfo, pi, &ei_ucp_intstring_invalid,
                "Invalid integer string: %s", strval);
    }
    *offset += len;
    if (idx != -1)
        *offset += 1;   /* skip terminating '/' */
    return intval;
}

static void
ucp_handle_time(proto_tree *tree, tvbuff_t *tvb, int field, int *offset)
{
    int         idx, len;
    const char *strval;
    time_t      tval;
    nstime_t    tmptime;

    idx = tvb_find_guint8(tvb, *offset, -1, '/');
    if (idx == -1) {
        /* Force the appropriate exception to be thrown. */
        len = tvb_captured_length_remaining(tvb, *offset);
        tvb_ensure_bytes_exist(tvb, *offset, len + 1);
    } else
        len = idx - *offset;
    strval = tvb_get_string_enc(wmem_packet_scope(), tvb, *offset, len, ENC_ASCII);
    if (len > 0) {
        tval = ucp_mktime(len, strval);
        tmptime.secs  = tval;
        tmptime.nsecs = 0;
        proto_tree_add_time(tree, field, tvb, *offset, len, &tmptime);
    }
    *offset += len;
    if (idx != -1)
        *offset += 1;   /* skip terminating '/' */
}

static void
ucp_handle_data(proto_tree *tree, tvbuff_t *tvb, int field, int *offset)
{
    int          tmpoff = *offset;

    while (tvb_get_uint8(tvb, tmpoff++) != '/')
        ;
    if ((tmpoff - *offset) > 1)
        proto_tree_add_item(tree, field, tvb, *offset,
                            tmpoff - *offset - 1, ENC_NA);
    *offset = tmpoff;
}

static void
ucp_handle_data_string(proto_tree *tree, tvbuff_t *tvb, int field, int *offset)
{
    int          tmpoff = *offset;

    while (tvb_get_uint8(tvb, tmpoff++) != '/')
        ;
    if ((tmpoff - *offset) > 1)
        proto_tree_add_item(tree, field, tvb, *offset,
                            tmpoff - *offset - 1, ENC_ASCII|ENC_NA);
    *offset = tmpoff;
}

/*!
 * Handle the data-field within the UCP-message, according the Message Type
 *      - 1     Tone only
 *      - 2     Numeric message
 *      - 3     Alphanumeric message
 *      - 4     Transparent (binary) data
 *      - 5     Standard text handling
 *      - 6     Alphanumeric message in specified character set
 *
 * \param       tree    The protocol tree to add to
 * \param       tvb     Buffer containing the data
 * \param       offset  Location of field within the buffer, returns location
 *                      of next field.
 */
static void
ucp_handle_mt(proto_tree *tree, packet_info* pinfo, tvbuff_t *tvb, int *offset)
{
    unsigned             intval;

    intval = ucp_handle_byte(tree, tvb, hf_ucp_parm_MT, offset);
    switch (intval) {
        case '1':                               /* Tone only, no data   */
            break;
        case '4':                               /* TMsg, no of bits     */
            ucp_handle_string(tree, tvb, hf_ucp_parm_NB, offset);
            /* fall through here for the data piece     */
            /* FALLTHROUGH */
        case '2':
            ucp_handle_data(tree, tvb, hf_ucp_data_section, offset);
            break;
        case '3':
            ucp_handle_IRAstring(tree, tvb, hf_ucp_parm_AMsg, offset);
            break;
        case '5':
            ucp_handle_byte(tree, tvb, hf_ucp_parm_PNC, offset);
            ucp_handle_string(tree, tvb, hf_ucp_parm_LNo, offset);
            ucp_handle_string(tree, tvb, hf_ucp_parm_LST, offset);
            ucp_handle_string(tree, tvb, hf_ucp_parm_TNo, offset);
            break;
        case '6':
            ucp_handle_data(tree, tvb, hf_ucp_data_section, offset);
            ucp_handle_int(tree, pinfo, tvb, hf_ucp_parm_CS, offset);
            break;
        default:
            break;              /* No data so ? */
    }
}

/*!
 * Handle the data within the 'Extended services' field. Each field having the
 * format TTLLDD..., TT being the type of service, LL giving the length of the
 * field, DD... containing the actual data
 *
 * \param       tree    The protocol tree to add to
 * \param       tvb     Buffer containing the extended services data
 */
static void
ucp_handle_XSer(proto_tree *tree, tvbuff_t *tvb)
{
    int          offset = 0;
    unsigned     intval;
    int          service;
    int          len;

    while ((intval = tvb_get_uint8(tvb, offset)) != '/') {
        service = AHex2Bin(intval);
        intval = tvb_get_uint8(tvb, offset+1);
        service = service * 16 + AHex2Bin(intval);
        intval = tvb_get_uint8(tvb, offset+2);
        len = AHex2Bin(intval);
        intval = tvb_get_uint8(tvb, offset+3);
        len = len * 16 + AHex2Bin(intval);
        proto_tree_add_uint(tree, hf_xser_service, tvb, offset,   2, service);
        proto_tree_add_uint(tree, hf_xser_length,  tvb, offset+2, 2, len);
        proto_tree_add_item(tree, hf_xser_data,    tvb, offset+4, len*2, ENC_ASCII);
        offset += 4 + (2 * len);
    }
}

static proto_item*
ucp_handle_alphanum_OAdC(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int field, int *offset)
{
    proto_item    *ti = NULL;
    GByteArray    *bytes;
    char          *strval = NULL;
    int           idx, len;
    int           tmpoff;

    idx = tvb_find_guint8(tvb, *offset, -1, '/');
    if (idx == -1) {
        /* Force the appropriate exception to be thrown. */
        len = tvb_captured_length_remaining(tvb, *offset);
        tvb_ensure_bytes_exist(tvb, *offset, len + 1);
    } else {
        len = idx - *offset;
    }

    if (len == 0) {
        if (idx != -1)
            *offset += 1;   /* skip terminating '/' */
        return ti;
    }

    bytes = g_byte_array_sized_new(len);
    if (tvb_get_string_bytes(tvb, *offset, len, ENC_ASCII|ENC_STR_HEX|ENC_SEP_NONE, bytes, &tmpoff)) {
        /* If this returns true, there's at least one byte */
        unsigned addrlength = bytes->data[0]; // expected number of semi-octets/nibbles
        unsigned numdigocts = (addrlength + 1) / 2;
        int no_of_chars = (addrlength << 2) / 7;
        if (bytes->len + 1 < numdigocts) {
            // Short data
            proto_tree_add_expert(tree, pinfo, &ei_ucp_short_data, tvb, *offset, len);
            no_of_chars = ((bytes->len - 1) << 3) / 7;
        }
        strval = get_ts_23_038_7bits_string_packed(pinfo->pool, &bytes->data[1], 0, no_of_chars);
    }
    g_byte_array_free(bytes, true);
    ti = proto_tree_add_string(tree, field, tvb, *offset,
                          len, strval);
    if (tmpoff < *offset + len) {
        /* We didn't consume all the bytes, so either a failed conversion
         * from ASCII hex bytes, or an odd number of bytes.
         */
        expert_add_info(pinfo, ti, &ei_ucp_hexstring_invalid);
    }
    *offset += len;
    if (idx != -1)
        *offset += 1;   /* skip terminating '/' */

    return ti;
}

/* Next definitions are just a convenient shorthand to make the coding a
 * bit more readable instead of summing up all these parameters.
 */
#define UcpHandleString(field)  ucp_handle_string(tree, tvb, (field), &offset)

#define UcpHandleIRAString(field) \
                        ucp_handle_IRAstring(tree, tvb, (field), &offset)

#define UcpHandleByte(field)    ucp_handle_byte(tree, tvb, (field), &offset)

#define UcpHandleInt(field)     ucp_handle_int(tree, pinfo, tvb, (field), &offset)

#define UcpHandleTime(field)    ucp_handle_time(tree, tvb, (field), &offset)

#define UcpHandleData(field)    ucp_handle_data(tree, tvb, (field), &offset)

#define UcpHandleDataString(field)\
                        ucp_handle_data_string(tree, tvb, (field), &offset)

/*!
 * The next set of routines handle the different operation types,
 * associated with UCP.
 */
static void
add_00O(proto_tree *tree, tvbuff_t *tvb)
{                                               /* Enquiry      */
    int          offset = 1;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_OAdC);
    UcpHandleString(hf_ucp_parm_OAC);
}

static void
add_00R(proto_tree *tree, packet_info* pinfo, tvbuff_t *tvb, ucp_tap_rec_t *tap_rec)
{
    int          offset = 1;
    unsigned     intval;

    intval = UcpHandleByte(hf_ucp_parm_ACK);
    if (intval == 'A')
    {
        UcpHandleByte(hf_ucp_parm_BAS);
        UcpHandleByte(hf_ucp_parm_LAR);
        UcpHandleByte(hf_ucp_parm_L1R);
        UcpHandleByte(hf_ucp_parm_L3R);
        UcpHandleByte(hf_ucp_parm_LCR);
        UcpHandleByte(hf_ucp_parm_LUR);
        UcpHandleByte(hf_ucp_parm_LRR);
        UcpHandleByte(hf_ucp_parm_RT);
        UcpHandleInt(hf_ucp_parm_NoN);
        UcpHandleInt(hf_ucp_parm_NoA);
        UcpHandleInt(hf_ucp_parm_NoB);

        tap_rec->result = 0;
    } else {
        tap_rec->result = UcpHandleInt(hf_ucp_parm_EC);
        UcpHandleString(hf_ucp_parm_SM);
    }
}

static void
add_01O(proto_tree *tree, packet_info* pinfo, tvbuff_t *tvb)
{                                               /* Call input   */
    int          offset = 1;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_OAdC);
    UcpHandleString(hf_ucp_parm_OAC);
    ucp_handle_mt(tree, pinfo, tvb, &offset);
}

static void
add_01R(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, ucp_tap_rec_t *tap_rec)
{
    int          offset = 1;
    unsigned     intval;

    intval = UcpHandleByte(hf_ucp_parm_ACK);
    if (intval == 'N')
        tap_rec->result = UcpHandleInt(hf_ucp_parm_EC);
    else
        tap_rec->result = 0;
    UcpHandleString(hf_ucp_parm_SM);
}

static void
add_02O(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb)
{                                               /* Multiple address call input*/
    int          offset = 1;
    unsigned     intval;
    unsigned     idx;

    intval = UcpHandleInt(hf_ucp_parm_NPL);
    for (idx = 0; idx < intval; idx++)
        UcpHandleString(hf_ucp_parm_AdC);

    UcpHandleString(hf_ucp_parm_OAdC);
    UcpHandleString(hf_ucp_parm_OAC);
    ucp_handle_mt(tree, pinfo, tvb, &offset);
}

#define add_02R(a, b, c, d) add_01R(a, b, c, d)

static void
add_03O(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb)
{                                               /* Call input with SS   */
    int          offset = 1;
    unsigned     intval;
    unsigned     idx;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_OAdC);
    UcpHandleString(hf_ucp_parm_OAC);
    intval = UcpHandleInt(hf_ucp_parm_NPL);
    for (idx = 0; idx < intval; idx++)
        UcpHandleString(hf_ucp_parm_GA);

    UcpHandleByte(hf_ucp_parm_RP);
    UcpHandleString(hf_ucp_parm_LRP);
    UcpHandleByte(hf_ucp_parm_PR);
    UcpHandleString(hf_ucp_parm_LPR);
    UcpHandleByte(hf_ucp_parm_UM);
    UcpHandleString(hf_ucp_parm_LUM);
    UcpHandleByte(hf_ucp_parm_RC);
    UcpHandleString(hf_ucp_parm_LRC);
    UcpHandleByte(hf_ucp_parm_DD);
    UcpHandleTime(hf_ucp_parm_DDT);    /* DDMMYYHHmm */
    ucp_handle_mt(tree, pinfo, tvb, &offset);
}

#define add_03R(a, b, c, d) add_01R(a, b, c, d)

static void
add_04O(proto_tree *tree, tvbuff_t *tvb)
{                                               /* Address list information */
    int          offset = 1;

    UcpHandleString(hf_ucp_parm_GAdC);
    UcpHandleString(hf_ucp_parm_AC);
    UcpHandleString(hf_ucp_parm_OAdC);
    UcpHandleString(hf_ucp_parm_OAC);
}

static void
add_04R(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, ucp_tap_rec_t *tap_rec)
{
    int          offset = 1;
    unsigned     intval;
    unsigned     idx;

    intval = UcpHandleByte(hf_ucp_parm_ACK);
    if (intval == 'A') {
        intval = UcpHandleInt(hf_ucp_parm_NPL);
        for (idx = 0; idx < intval; idx++)
            UcpHandleString(hf_ucp_parm_AdC);
        UcpHandleString(hf_ucp_parm_GAdC);
        tap_rec->result = 0;
    } else
        tap_rec->result = UcpHandleInt(hf_ucp_parm_EC);
    UcpHandleString(hf_ucp_parm_SM);
}

static void
add_05O(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb)
{                                               /* Change address list */
    int          offset = 1;
    unsigned     intval;
    unsigned     idx;

    UcpHandleString(hf_ucp_parm_GAdC);
    UcpHandleString(hf_ucp_parm_AC);
    UcpHandleString(hf_ucp_parm_OAdC);
    UcpHandleString(hf_ucp_parm_OAC);
    intval = UcpHandleInt(hf_ucp_parm_NPL);
    for (idx = 0; idx < intval; idx++)
        UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleByte(hf_ucp_parm_A_D);
}

#define add_05R(a, b, c, d) add_01R(a, b, c, d)

static void
add_06O(proto_tree *tree, tvbuff_t *tvb)
{                                               /* Advice of accum. charges */
    int          offset = 1;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_AC);
}

static void
add_06R(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, ucp_tap_rec_t *tap_rec)
{
    int          offset = 1;
    unsigned     intval;

    intval = UcpHandleByte(hf_ucp_parm_ACK);
    if (intval == 'A') {
        UcpHandleTime(hf_ucp_parm_CT);
        UcpHandleString(hf_ucp_parm_AAC);
        tap_rec->result = 0;
    } else
        tap_rec->result = UcpHandleInt(hf_ucp_parm_EC);
    UcpHandleString(hf_ucp_parm_SM);
}

static void
add_07O(proto_tree *tree, tvbuff_t *tvb)
{                                               /* Password management  */
    int          offset = 1;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_AC);
    UcpHandleString(hf_ucp_parm_NAC);
}

#define add_07R(a, b, c, d) add_01R(a, b, c, d)

static void
add_08O(proto_tree *tree, tvbuff_t *tvb)
{                                               /* Leg. code management */
    int          offset = 1;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_AC);
    UcpHandleString(hf_ucp_parm_LAC);
    UcpHandleString(hf_ucp_parm_L1P);
    UcpHandleString(hf_ucp_parm_L3P);
    UcpHandleString(hf_ucp_parm_LRC);
    UcpHandleString(hf_ucp_parm_LUM);
    UcpHandleString(hf_ucp_parm_LRP);
    UcpHandleString(hf_ucp_parm_LST);
}

#define add_08R(a, b, c, d) add_01R(a, b, c, d)

static void
add_09O(proto_tree *tree, tvbuff_t *tvb)
{                                               /* Standard text information */
    int          offset = 1;

    UcpHandleString(hf_ucp_parm_LNo);
    UcpHandleString(hf_ucp_parm_LST);
}

static void
add_09R(proto_tree *tree, packet_info *pinfo,tvbuff_t *tvb, ucp_tap_rec_t *tap_rec)
{
    int          offset = 1;
    unsigned     intval;
    unsigned     idx;

    intval = UcpHandleByte(hf_ucp_parm_ACK);
    if (intval == 'A') {
        intval = UcpHandleInt(hf_ucp_parm_NPL);
        for (idx = 0; idx < intval; idx++)
            UcpHandleString(hf_ucp_parm_LST);
        tap_rec->result = 0;
    } else
        tap_rec->result = UcpHandleInt(hf_ucp_parm_EC);
    UcpHandleString(hf_ucp_parm_SM);
}

static void
add_10O(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb)
{                                               /* Change standard text */
    int          offset = 1;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_AC);
    UcpHandleString(hf_ucp_parm_LNo);
    UcpHandleString(hf_ucp_parm_TNo);
    UcpHandleData(hf_ucp_parm_STx);
    UcpHandleInt(hf_ucp_parm_CS);
}

#define add_10R(a, b, c, d) add_01R(a, b, c, d)

#define add_11O(a, b) add_06O(a, b)             /* Request roaming info */

static void
add_11R(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, ucp_tap_rec_t *tap_rec)
{
    int          offset = 1;
    unsigned     intval;
    unsigned     idx;

    intval = UcpHandleByte(hf_ucp_parm_ACK);
    if (intval == 'A') {
        intval = UcpHandleInt(hf_ucp_parm_NPL);
        for (idx = 0; idx < intval; idx++)
            UcpHandleString(hf_ucp_parm_GA);
        tap_rec->result = 0;
    } else
        tap_rec->result = UcpHandleInt(hf_ucp_parm_EC);
    UcpHandleString(hf_ucp_parm_SM);
}

static void
add_12O(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb)
{                                               /* Change roaming       */
    int          offset = 1;
    unsigned     intval;
    unsigned     idx;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_AC);
    intval = UcpHandleInt(hf_ucp_parm_NPL);
    for (idx = 0; idx < intval; idx++)
        UcpHandleString(hf_ucp_parm_GA);
}

#define add_12R(a, b, c, d) add_01R(a, b, c, d)

#define add_13O(a, c) add_06O(a, c)             /* Roaming reset        */

#define add_13R(a, b, c, d) add_01R(a, b, c, d)

static void
add_14O(proto_tree *tree, tvbuff_t *tvb)
{                                               /* Message retrieval    */
    int          offset = 1;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_AC);
    UcpHandleString(hf_ucp_parm_MNo);
    UcpHandleByte(hf_ucp_parm_R_T);
}

static void
add_14R(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, ucp_tap_rec_t *tap_rec)
{
    int          offset = 1;
    unsigned     intval;
    unsigned     idx;

    intval = UcpHandleByte(hf_ucp_parm_ACK);
    if (intval == 'A') {
        intval = UcpHandleInt(hf_ucp_parm_NPL);
        /*
         * Spec is unclear here. Is 'SM' part of the Msg:s field or not?
         * For now, assume it is part of it...
         */
        for (idx = 0; idx < intval; idx++)
            UcpHandleData(hf_ucp_data_section);
        tap_rec->result = 0;
    } else {
        tap_rec->result = UcpHandleInt(hf_ucp_parm_EC);
        UcpHandleString(hf_ucp_parm_SM);
    }
}

static void
add_15O(proto_tree *tree, tvbuff_t *tvb)
{                                               /* Request call barring */
    int          offset = 1;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_AC);
    UcpHandleTime(hf_ucp_parm_ST);
    UcpHandleTime(hf_ucp_parm_SP);
}

#define add_15R(a, b, c, d) add_01R(a, b, c, d)

#define add_16O(a, b) add_06O(a, b)             /* Cancel call barring  */

#define add_16R(a, b, c, d) add_01R(a, b, c, d)

static void
add_17O(proto_tree *tree, tvbuff_t *tvb)
{                                               /* Request call diversion */
    int          offset = 1;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_AC);
    UcpHandleString(hf_ucp_parm_DAdC);
    UcpHandleTime(hf_ucp_parm_ST);
    UcpHandleTime(hf_ucp_parm_SP);
}

#define add_17R(a, b, c, d) add_01R(a, b, c, d)

#define add_18O(a, b) add_06O(a, b)             /* Cancel call diversion */

#define add_18R(a, b, c, d) add_01R(a, b, c, d)

static void
add_19O(proto_tree *tree, tvbuff_t *tvb)
{                                               /* Request deferred delivery*/
    int          offset = 1;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_AC);
    UcpHandleTime(hf_ucp_parm_ST);
    UcpHandleTime(hf_ucp_parm_SP);
}

#define add_19R(a, b, c, d) add_01R(a, b, c, d)

#define add_20O(a, b) add_06O(a, b)             /* Cancel deferred delivery */

#define add_20R(a, b, c, d) add_01R(a, b, c, d)

#define add_21O(a, b) add_06O(a, b)             /* All features reset   */

#define add_21R(a, b, c, d) add_01R(a, b, c, d)

static void
add_22O(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb)
{                                               /* Call input w. add. CS */
    int          offset = 1;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_OAdC);
    UcpHandleString(hf_ucp_parm_OAC);
    UcpHandleData(hf_ucp_data_section);
    UcpHandleInt(hf_ucp_parm_CS);
}

#define add_22R(a, b, c, d) add_01R(a, b, c, d)

static void
add_23O(proto_tree *tree, tvbuff_t *tvb)
{                                               /* UCP version status   */
    int          offset = 1;

    UcpHandleString(hf_ucp_parm_IVR5x);
    UcpHandleByte(hf_ucp_parm_REQ_OT);
}

static void
add_23R(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, ucp_tap_rec_t *tap_rec)
{
    int          offset = 1;
    unsigned     intval;
    unsigned     idx;

    intval = UcpHandleByte(hf_ucp_parm_ACK);
    if (intval == 'A') {
        UcpHandleByte(hf_ucp_parm_IVR5x);
        intval = UcpHandleInt(hf_ucp_parm_NPL);
        for (idx = 0; idx < intval; idx++)
            UcpHandleInt(hf_ucp_hdr_OT);
        tap_rec->result = 0;
    } else
        tap_rec->result = UcpHandleInt(hf_ucp_parm_EC);
    UcpHandleString(hf_ucp_parm_SM);
}

static void
add_24O(proto_tree *tree, tvbuff_t *tvb)
{                                               /* Mobile subs. feature stat*/
    int          offset = 1;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_AC);
    UcpHandleByte(hf_ucp_parm_SSTAT);
}

static void
add_24R(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, ucp_tap_rec_t *tap_rec)
{
    int          offset = 1;
    unsigned     intval;
    unsigned     idx;

    intval = UcpHandleByte(hf_ucp_parm_ACK);
    if (intval == 'A') {
        if ((intval = tvb_get_uint8(tvb, offset++)) != '/') {
            proto_tree_add_item(tree, hf_ucp_ga_roaming, tvb, offset - 1, 1, ENC_NA);
            if (intval == 'N') {
                proto_tree_add_item(tree, hf_ucp_not_subscribed, tvb, offset -1, 1, ENC_NA);
                offset++;
            } else {
                --offset;
                intval = UcpHandleInt(hf_ucp_parm_NPL);
                for (idx = 0; idx < intval; idx++)
                    UcpHandleData(hf_ucp_data_section);
            }
        }
        if ((intval = tvb_get_uint8(tvb, offset++)) != '/') {
            proto_tree_add_item(tree, hf_ucp_call_barring, tvb, offset - 1, 1, ENC_NA);
            if (intval == 'N') {
                proto_tree_add_item(tree, hf_ucp_not_subscribed, tvb, offset -1, 1, ENC_NA);
                offset++;
            } else {
                --offset;
                intval = UcpHandleInt(hf_ucp_parm_NPL);
                for (idx = 0; idx < intval; idx++)
                    UcpHandleData(hf_ucp_data_section);
            }
        }
        if ((intval = tvb_get_uint8(tvb, offset++)) != '/') {
            proto_tree_add_item(tree, hf_ucp_deferred_delivery, tvb, offset - 1, 1, ENC_NA);
            if (intval == 'N') {
                proto_tree_add_item(tree, hf_ucp_not_subscribed, tvb, offset -1, 1, ENC_NA);
                offset++;
            } else {
                --offset;
                intval = UcpHandleInt(hf_ucp_parm_NPL);
                for (idx = 0; idx < intval; idx++)
                    UcpHandleData(hf_ucp_data_section);
            }
        }
        if ((intval = tvb_get_uint8(tvb, offset++)) != '/') {
            proto_tree_add_item(tree, hf_ucp_diversion, tvb, offset - 1, 1, ENC_NA);
            if (intval == 'N') {
                proto_tree_add_item(tree, hf_ucp_not_subscribed, tvb, offset -1, 1, ENC_NA);
                offset++;
            } else {
                --offset;
                intval = UcpHandleInt(hf_ucp_parm_NPL);
                for (idx = 0; idx < intval; idx++)
                    UcpHandleData(hf_ucp_data_section);
            }
        }
        UcpHandleInt(hf_ucp_parm_LMN);
        if ((intval = tvb_get_uint8(tvb, offset++)) != '/') {
            if (intval == 'N') {
                proto_tree_add_item(tree, hf_ucp_not_subscribed, tvb, offset -1, 1, ENC_NA);
                offset++;
            } else {
                --offset;
                UcpHandleInt(hf_ucp_parm_NMESS);
            }
        }
        tap_rec->result = 0;
    } else
        tap_rec->result = UcpHandleInt(hf_ucp_parm_EC);
    UcpHandleString(hf_ucp_parm_SM);
}

static void
add_30O(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb)
{                                               /* SMS message transfer */
    int          offset = 1;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_OAdC);
    UcpHandleString(hf_ucp_parm_AC);
    UcpHandleByte(hf_ucp_parm_NRq);
    UcpHandleString(hf_ucp_parm_NAdC);
    UcpHandleInt(hf_ucp_parm_NPID);
    UcpHandleByte(hf_ucp_parm_DD);
    UcpHandleTime(hf_ucp_parm_DDT);     /* DDMMYYHHmm */
    UcpHandleTime(hf_ucp_parm_VP);      /* DDMMYYHHmm */
    UcpHandleIRAString(hf_ucp_parm_AMsg);
}

static void
add_30R(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, ucp_tap_rec_t *tap_rec)
{
    int          offset = 1;
    unsigned     intval;

    intval = UcpHandleByte(hf_ucp_parm_ACK);
    if (intval == 'A') {
        UcpHandleTime(hf_ucp_parm_MVP); /* DDMMYYHHmm */
        tap_rec->result = 0;
    } else {
        tap_rec->result = UcpHandleInt(hf_ucp_parm_EC);
    }
    UcpHandleString(hf_ucp_parm_SM);
}

static void
add_31O(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb)
{                                               /* SMT alert            */
    int          offset = 1;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleInt(hf_ucp_parm_PID);
}

#define add_31R(a, b, c, d) add_01R(a, b, c, d)

static void
add_5xO(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb)
{                                               /* 50-series operations */
    unsigned     intval;
    int          offset = 1;
    int          tmpoff, oadc_offset;
    proto_item  *ti, *oadc_item;
    tvbuff_t    *tmptvb;

    UcpHandleString(hf_ucp_parm_AdC);
    oadc_offset = offset;
    oadc_item = UcpHandleString(hf_ucp_parm_OAdC);
    UcpHandleString(hf_ucp_parm_AC);
    UcpHandleByte(hf_ucp_parm_NRq);
    UcpHandleString(hf_ucp_parm_NAdC);
    UcpHandleByte(hf_ucp_parm_NT);
    UcpHandleInt(hf_ucp_parm_NPID);
    UcpHandleByte(hf_ucp_parm_LRq);
    UcpHandleString(hf_ucp_parm_LRAd);
    UcpHandleInt(hf_ucp_parm_LPID);
    UcpHandleByte(hf_ucp_parm_DD);
    UcpHandleTime(hf_ucp_parm_DDT);     /* DDMMYYHHmm */
    UcpHandleTime(hf_ucp_parm_VP);      /* DDMMYYHHmm */
    UcpHandleString(hf_ucp_parm_RPID);
    UcpHandleTime(hf_ucp_parm_SCTS);    /* DDMMYYhhmmss */
    UcpHandleByte(hf_ucp_parm_Dst);
    UcpHandleInt(hf_ucp_parm_Rsn);
    UcpHandleTime(hf_ucp_parm_DSCTS);   /* DDMMYYhhmmss */
    intval = UcpHandleByte(hf_ucp_parm_MT);
    UcpHandleString(hf_ucp_parm_NB);
    if (intval != '3')
        UcpHandleData(hf_ucp_data_section);
    else
        UcpHandleIRAString(hf_ucp_parm_AMsg);
    UcpHandleByte(hf_ucp_parm_MMS);
    UcpHandleByte(hf_ucp_parm_PR);
    UcpHandleByte(hf_ucp_parm_DCs);
    UcpHandleByte(hf_ucp_parm_MCLs);
    UcpHandleByte(hf_ucp_parm_RPI);
    if (tvb_get_uint8(tvb, offset++) != '/') {
        proto_tree_add_string(tree, hf_ucp_parm_CPg, tvb, offset - 1,1,
                              "(reserved for Code Page)");
        offset++;
    }
    if (tvb_get_uint8(tvb, offset++) != '/') {
        proto_tree_add_string(tree, hf_ucp_parm_RPLy, tvb, offset - 1,1,
                              "(reserved for Reply type)");
        offset++;
    }
    intval = UcpHandleInt(hf_ucp_parm_OTOA);
    if (intval == 5039) {
        ti = ucp_handle_alphanum_OAdC(tree, pinfo, tvb, hf_ucp_parm_OAdC, &oadc_offset);
        if (ti && oadc_item) {
            proto_tree_move_item(tree, oadc_item, ti);
            proto_item_set_hidden(oadc_item);
        }
    }
    UcpHandleString(hf_ucp_parm_HPLMN);
    tmpoff = offset;                            /* Extra services       */
    while (tvb_get_uint8(tvb, tmpoff++) != '/')
        ;
    if ((tmpoff - offset) > 1) {
        int      len = tmpoff - offset - 1;
        proto_tree *subtree;

        ti = proto_tree_add_item(tree, hf_ucp_parm_XSer, tvb, offset, len, ENC_NA);
        tmptvb = tvb_new_subset_length(tvb, offset, len + 1);
        subtree = proto_item_add_subtree(ti, ett_XSer);
        ucp_handle_XSer(subtree, tmptvb);
    }
    offset = tmpoff;
    UcpHandleDataString(hf_ucp_parm_RES4);
    UcpHandleDataString(hf_ucp_parm_RES5);
}

#define add_5xR(a, b, c, d) add_30R(a, b, c, d)

static void
add_6xO(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, uint8_t OT)
{                                               /* 60-series operations */
    int          offset = 1;

    UcpHandleString(hf_ucp_parm_OAdC);
    UcpHandleByte(hf_ucp_parm_OTON);
    UcpHandleByte(hf_ucp_parm_ONPI);
    if (OT == 60) {
        UcpHandleByte(hf_ucp_parm_STYP0);
    } else {
        UcpHandleByte(hf_ucp_parm_STYP1);
    }
    UcpHandleIRAString(hf_ucp_parm_PWD);
    UcpHandleIRAString(hf_ucp_parm_NPWD);
    UcpHandleString(hf_ucp_parm_VERS);
    UcpHandleString(hf_ucp_parm_LAdC);
    UcpHandleByte(hf_ucp_parm_LTON);
    UcpHandleByte(hf_ucp_parm_LNPI);
    if (OT == 60) {
        UcpHandleInt(hf_ucp_parm_OPID);
    }
    UcpHandleDataString(hf_ucp_parm_RES1);
    if (OT == 61) {
        UcpHandleDataString(hf_ucp_parm_RES2);
    }
}

#define add_6xR(a, b, c, d) add_01R(a, b, c, d)

/*
 * End of convenient shorthands
 */
#undef UcpHandleString
#undef UcpHandleIRAString
#undef UcpHandleByte
#undef UcpHandleInt
#undef UcpHandleTime
#undef UcpHandleData

static unsigned
get_ucp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    unsigned     intval=0;
    int          i;

    offset = offset + 4;
    for (i = 0; i < UCP_LEN_LEN; i++) { /* Length       */
        intval = 10 * intval +
            (tvb_get_uint8(tvb, offset) - '0');
        offset++;
    }

    return intval + 2;
}

/*
 * The actual dissector
 */

/* We get here only with at least LEN+2 bytes in the buffer */

static int
dissect_ucp_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int            offset = 0;  /* Offset in packet within tvbuff       */
    uint8_t        O_R;         /* Request or response                  */
    uint8_t        OT;          /* Operation type                       */
    unsigned       intval;
    int            i;
    int            result;
    int            endpkt;
    ucp_tap_rec_t *tap_rec;     /* Tap record                           */

    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item  *ti;
    proto_item  *sub_ti;
    proto_tree  *ucp_tree;
    proto_tree  *sub_tree;
    tvbuff_t    *tmp_tvb;

    /* Make entries in Protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UCP");
    col_clear(pinfo->cinfo, COL_INFO);

    if (tvb_get_uint8(tvb, 0) != UCP_STX){
        proto_tree_add_expert(tree, pinfo, &ei_ucp_stx_missing, tvb, 0, -1);
        return tvb_captured_length(tvb);
    }

    /* Get data needed for dissect_ucp_common */
    result = check_ucp(tvb, &endpkt);

    O_R = tvb_get_uint8(tvb, UCP_O_R_OFFSET);
    OT  = tvb_get_uint8(tvb, UCP_OT_OFFSET) - '0';
    OT  = 10 * OT + (tvb_get_uint8(tvb, UCP_OT_OFFSET + 1) - '0');

    /* Create Tap record */
    tap_rec = wmem_new0(wmem_packet_scope(), ucp_tap_rec_t);
    tap_rec->message_type = (O_R == 'O' ? 0 : 1);
    tap_rec->operation = OT;

     /* Make entries in  Info column on summary display */
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s (%s)",
                    val_to_str_ext_const(OT,  &vals_hdr_OT_ext,  "unknown operation"),
                    val_to_str(O_R, vals_hdr_O_R, "Unknown (%d)"));
    if (result == UCP_INV_CHK)
        col_append_str(pinfo->cinfo, COL_INFO, " [checksum invalid]");

    /* In the interest of speed, if "tree" is NULL, don't do any work not
       necessary to generate protocol tree items. */
    if (tree) {

        /* create display subtree for the protocol */
        ti = proto_tree_add_item(tree, proto_ucp, tvb, 0, -1, ENC_NA);

        ucp_tree = proto_item_add_subtree(ti, ett_ucp);
        /*
         * Process the packet here.
         * Transaction number
         */
        offset++;                               /* Skip <stx>   */
        intval = tvb_get_uint8(tvb, offset+0) - '0';
        intval = 10 * intval + (tvb_get_uint8(tvb, offset+1) - '0');
        proto_tree_add_uint(ucp_tree, hf_ucp_hdr_TRN, tvb, offset,
                            UCP_TRN_LEN, intval);
        offset += UCP_TRN_LEN + 1;              /* Skip TN/     */

        intval = 0;
        for (i = 0; i < UCP_LEN_LEN; i++) {     /* Length       */
            intval = 10 * intval +
                        (tvb_get_uint8(tvb, offset+i) - '0');
        }
        proto_tree_add_uint(ucp_tree, hf_ucp_hdr_LEN, tvb, offset,
                            UCP_LEN_LEN, intval);
        offset += UCP_LEN_LEN + 1;              /* skip LEN/    */

        proto_tree_add_uint(ucp_tree, hf_ucp_hdr_O_R, tvb, offset,
                            UCP_O_R_LEN, O_R);

        offset += UCP_O_R_LEN + 1;              /* skip Operation_type/ */

        proto_tree_add_uint(ucp_tree, hf_ucp_hdr_OT, tvb, offset,
                            UCP_OT_LEN, OT);
        offset += UCP_OT_LEN;

        /*
         * Variable part starts here.
         */

        tmp_tvb = tvb_new_subset_remaining(tvb, offset);
        sub_ti = proto_tree_add_item(ucp_tree, hf_ucp_oper_section, tvb,
                                     offset, endpkt - offset, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_ti, ett_sub);

        switch (OT) {
            case  0:
                O_R == 'O' ? add_00O(sub_tree, tmp_tvb) : add_00R(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            case  1:
                O_R == 'O' ? add_01O(sub_tree, pinfo, tmp_tvb) : add_01R(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            case  2:
                O_R == 'O' ? add_02O(sub_tree, pinfo, tmp_tvb) : add_02R(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            case  3:
                O_R == 'O' ? add_03O(sub_tree, pinfo, tmp_tvb) : add_03R(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            case  4:
                O_R == 'O' ? add_04O(sub_tree, tmp_tvb) : add_04R(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            case  5:
                O_R == 'O' ? add_05O(sub_tree, pinfo, tmp_tvb) : add_05R(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            case  6:
                O_R == 'O' ? add_06O(sub_tree, tmp_tvb) : add_06R(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            case  7:
                O_R == 'O' ? add_07O(sub_tree,tmp_tvb) : add_07R(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            case  8:
                O_R == 'O' ? add_08O(sub_tree,tmp_tvb) : add_08R(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            case  9:
                O_R == 'O' ? add_09O(sub_tree,tmp_tvb) : add_09R(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            case 10:
                O_R == 'O' ? add_10O(sub_tree, pinfo, tmp_tvb) : add_10R(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            case 11:
                O_R == 'O' ? add_11O(sub_tree,tmp_tvb) : add_11R(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            case 12:
                O_R == 'O' ? add_12O(sub_tree, pinfo, tmp_tvb) : add_12R(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            case 13:
                O_R == 'O' ? add_13O(sub_tree, tmp_tvb) : add_13R(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            case 14:
                O_R == 'O' ? add_14O(sub_tree,tmp_tvb) : add_14R(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            case 15:
                O_R == 'O' ? add_15O(sub_tree,tmp_tvb) : add_15R(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            case 16:
                O_R == 'O' ? add_16O(sub_tree,tmp_tvb) : add_16R(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            case 17:
                O_R == 'O' ? add_17O(sub_tree,tmp_tvb) : add_17R(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            case 18:
                O_R == 'O' ? add_18O(sub_tree,tmp_tvb) : add_18R(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            case 19:
                O_R == 'O' ? add_19O(sub_tree,tmp_tvb) : add_19R(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            case 20:
                O_R == 'O' ? add_20O(sub_tree,tmp_tvb) : add_20R(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            case 21:
                O_R == 'O' ? add_21O(sub_tree,tmp_tvb) : add_21R(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            case 22:
                O_R == 'O' ? add_22O(sub_tree, pinfo, tmp_tvb) : add_22R(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            case 23:
                O_R == 'O' ? add_23O(sub_tree,tmp_tvb) : add_23R(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            case 24:
                O_R == 'O' ? add_24O(sub_tree,tmp_tvb) : add_24R(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            case 30:
                O_R == 'O' ? add_30O(sub_tree, pinfo, tmp_tvb) : add_30R(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            case 31:
                O_R == 'O' ? add_31O(sub_tree, pinfo, tmp_tvb) : add_31R(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            case 51: case 52: case 53: case 54: case 55: case 56: case 57:
            case 58:
                O_R == 'O' ? add_5xO(sub_tree, pinfo, tmp_tvb) : add_5xR(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            case 60: case 61:
                O_R == 'O' ? add_6xO(sub_tree, pinfo, tmp_tvb,OT) : add_6xR(sub_tree, pinfo, tmp_tvb, tap_rec);
                break;
            default:
                break;
        }
    }

    /* Queue packet for Tap */
    tap_queue_packet(ucp_tap, pinfo, tap_rec);

    return tvb_captured_length(tvb);
}

static int
dissect_ucp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, ucp_desegment, UCP_HEADER_SIZE,
                     get_ucp_pdu_len, dissect_ucp_common, data);
    return tvb_captured_length(tvb);
}

/*
 * The heuristic dissector
 */

static bool
dissect_ucp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    conversation_t *conversation;

    /* Heuristic */

    if (tvb_captured_length(tvb) < UCP_HEADER_SIZE)
        return false;

    if ((tvb_get_uint8(tvb, 0)                            != UCP_STX) ||
        (tvb_get_uint8(tvb, UCP_TRN_OFFSET + UCP_TRN_LEN) != '/') ||
        (tvb_get_uint8(tvb, UCP_LEN_OFFSET + UCP_LEN_LEN) != '/') ||
        (tvb_get_uint8(tvb, UCP_O_R_OFFSET + UCP_O_R_LEN) != '/') ||
        (tvb_get_uint8(tvb, UCP_OT_OFFSET  + UCP_OT_LEN)  != '/'))
        return false;

    if (try_val_to_str(tvb_get_uint8(tvb, UCP_O_R_OFFSET), vals_hdr_O_R) == NULL)
        return false;

    /*
     * Ok, looks like a valid packet
     */

    /* Set up a conversation with attached dissector so dissect_ucp_heur
     *  won't be called any more for this TCP connection.
     */

    conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, ucp_handle);

    dissect_ucp_tcp(tvb, pinfo, tree, data);

    return true;
}

/* Register the protocol with Wireshark */
void
proto_register_ucp(void)
{

    /* Setup list of fields     */
    static hf_register_info hf[] = {
        { &hf_ucp_hdr_TRN,
          { "Transaction Reference Number", "ucp.hdr.TRN",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            "Transaction number for this command, used in windowing.",
            HFILL
          }
        },
        { &hf_ucp_hdr_LEN,
          { "Length", "ucp.hdr.LEN",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            "Total number of characters between <stx>...<etx>.",
            HFILL
          }
        },
        { &hf_ucp_hdr_O_R,
          { "Type", "ucp.hdr.O_R",
            FT_CHAR, BASE_HEX, VALS(vals_hdr_O_R), 0x00,
            "Your basic 'is a request or response'.",
            HFILL
          }
        },
        { &hf_ucp_hdr_OT,
          { "Operation", "ucp.hdr.OT",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &vals_hdr_OT_ext, 0x00,
            "The operation that is requested with this message.",
            HFILL
          }
        },
        { &hf_ucp_oper_section,
          { "Data", "ucp.parm",
            FT_NONE, BASE_NONE, NULL, 0x00,
            "The actual content of the operation.",
            HFILL
          }
        },
        { &hf_ucp_parm_AdC,
          { "AdC", "ucp.parm.AdC",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Address code recipient.",
            HFILL
          }
        },
        { &hf_ucp_parm_OAdC,
          { "OAdC", "ucp.parm.OAdC",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Address code originator.",
            HFILL
          }
        },
        { &hf_ucp_parm_DAdC,
          { "DAdC", "ucp.parm.DAdC",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Diverted address code.",
            HFILL
          }
        },
        { &hf_ucp_parm_AC,
          { "AC", "ucp.parm.AC",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Authentication code.",
            HFILL
          }
        },
        { &hf_ucp_parm_OAC,
          { "OAC", "ucp.parm.OAC",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Authentication code, originator.",
            HFILL
          }
        },
        { &hf_ucp_parm_NAC,
          { "NAC", "ucp.parm.NAC",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "New authentication code.",
            HFILL
          }
        },
        { &hf_ucp_parm_BAS,
          { "BAS", "ucp.parm.BAS",
            FT_CHAR, BASE_HEX, VALS(vals_parm_BAS), 0x00,
            "Barring status flag.",
            HFILL
          }
        },
        { &hf_ucp_parm_LAR,
          { "LAR", "ucp.parm.LAR",
            FT_CHAR, BASE_HEX, VALS(vals_parm_LAR), 0x00,
            "Leg. code for all calls flag.",
            HFILL
          }
        },
        { &hf_ucp_parm_LAC,
          { "LAC", "ucp.parm.LAC",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "New leg. code for all calls.",
            HFILL
          }
        },
        { &hf_ucp_parm_L1R,
          { "L1R", "ucp.parm.L1R",
            FT_CHAR, BASE_HEX, VALS(vals_parm_L1R), 0x00,
            "Leg. code for priority 1 flag.",
            HFILL
          }
        },
        { &hf_ucp_parm_L1P,
          { "L1P", "ucp.parm.L1P",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "New leg. code for level 1 priority.",
            HFILL
          }
        },
        { &hf_ucp_parm_L3R,
          { "L3R", "ucp.parm.L3R",
            FT_CHAR, BASE_HEX, VALS(vals_parm_L3R), 0x00,
            "Leg. code for priority 3 flag.",
            HFILL
          }
        },
        { &hf_ucp_parm_L3P,
          { "L3P", "ucp.parm.L3P",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "New leg. code for level 3 priority.",
            HFILL
          }
        },
        { &hf_ucp_parm_LCR,
          { "LCR", "ucp.parm.LCR",
            FT_CHAR, BASE_HEX, VALS(vals_parm_LCR), 0x00,
            "Leg. code for reverse charging flag.",
            HFILL
          }
        },
        { &hf_ucp_parm_LUR,
          { "LUR", "ucp.parm.LUR",
            FT_CHAR, BASE_HEX, VALS(vals_parm_LUR), 0x00,
            "Leg. code for urgent message flag.",
            HFILL
          }
        },
        { &hf_ucp_parm_LRR,
          { "LRR", "ucp.parm.LRR",
            FT_CHAR, BASE_HEX, VALS(vals_parm_LRR), 0x00,
            "Leg. code for repetition flag.",
            HFILL
          }
        },
        { &hf_ucp_parm_RT,
          { "RT", "ucp.parm.RT",
            FT_CHAR, BASE_HEX, VALS(vals_parm_RT), 0x00,
            "Receiver type.",
            HFILL
          }
        },
        { &hf_ucp_parm_NoN,
          { "NoN", "ucp.parm.NoN",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            "Maximum number of numerical characters accepted.",
            HFILL
          }
        },
        { &hf_ucp_parm_NoA,
          { "NoA", "ucp.parm.NoA",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            "Maximum number of alphanumerical characters accepted.",
            HFILL
          }
        },
        { &hf_ucp_parm_NoB,
          { "NoB", "ucp.parm.NoB",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            "Maximum number of data bits accepted.",
            HFILL
          }
        },
        { &hf_ucp_parm_PNC,
          { "PNC", "ucp.parm.PNC",
            FT_CHAR, BASE_HEX, VALS(vals_parm_PNC), 0x00,
            "Paging network controller.",
            HFILL
          }
        },
        { &hf_ucp_parm_AMsg,
          { "AMsg", "ucp.parm.AMsg",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "The alphanumeric message that is being sent.",
            HFILL
          }
        },
        { &hf_ucp_parm_LNo,
          { "LNo", "ucp.parm.LNo",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Standard text list number requested by calling party.",
            HFILL
          }
        },
        { &hf_ucp_parm_LST,
          { "LST", "ucp.parm.LST",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Legitimisation code for standard text.",
            HFILL
          }
        },
        { &hf_ucp_parm_TNo,
          { "TNo", "ucp.parm.TNo",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Standard text number requested by calling party.",
            HFILL
          }
        },
        { &hf_ucp_parm_CS,
          { "CS", "ucp.parm.CS",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            "Additional character set number.",
            HFILL
          }
        },
        { &hf_ucp_parm_PID,
          { "PID", "ucp.parm.PID",
            FT_UINT16, BASE_DEC, VALS(vals_parm_PID), 0x00,
            "SMT PID value.",
            HFILL
          }
        },
        { &hf_ucp_parm_NPL,
          { "NPL", "ucp.parm.NPL",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            "Number of parameters in the following list.",
            HFILL
          }
        },
        { &hf_ucp_parm_GA,
          { "GA", "ucp.parm.GA",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "GA?? haven't got a clue.",
            HFILL
          }
        },
        { &hf_ucp_parm_RP,
          { "RP", "ucp.parm.RP",
            FT_CHAR, BASE_HEX, VALS(vals_parm_RP), 0x00,
            "Repetition requested.",
            HFILL
          }
        },
        { &hf_ucp_parm_LRP,
          { "LRP", "ucp.parm.LRP",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Legitimisation code for repetition.",
            HFILL
          }
        },
        { &hf_ucp_parm_PR,
          { "PR", "ucp.parm.PR",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            "Priority requested.",
            HFILL
          }
        },
        { &hf_ucp_parm_LPR,
          { "LPR", "ucp.parm.LPR",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Legitimisation code for priority requested.",
            HFILL
          }
        },
        { &hf_ucp_parm_UM,
          { "UM", "ucp.parm.UM",
            FT_CHAR, BASE_HEX, VALS(vals_parm_UM), 0x00,
            "Urgent message indicator.",
            HFILL
          }
        },
        { &hf_ucp_parm_LUM,
          { "LUM", "ucp.parm.LUM",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Legitimisation code for urgent message.",
            HFILL
          }
        },
        { &hf_ucp_parm_RC,
          { "RC", "ucp.parm.RC",
            FT_CHAR, BASE_HEX, VALS(vals_parm_RC), 0x00,
            "Reverse charging request.",
            HFILL
          }
        },
        { &hf_ucp_parm_LRC,
          { "LRC", "ucp.parm.LRC",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Legitimisation code for reverse charging.",
            HFILL
          }
        },
        { &hf_ucp_parm_NRq,
          { "NRq", "ucp.parm.NRq",
            FT_CHAR, BASE_HEX, VALS(vals_parm_NRq), 0x00,
            "Notification request.",
            HFILL
          }
        },
        { &hf_ucp_parm_GAdC,
          { "GAdC", "ucp.parm.GAdC",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Group address code.",
            HFILL
          }
        },
        { &hf_ucp_parm_A_D,
          { "A_D", "ucp.parm.A_D",
            FT_CHAR, BASE_HEX, VALS(vals_parm_A_D), 0x00,
            "Add to/delete from fixed subscriber address list record.",
            HFILL
          }
        },
        { &hf_ucp_parm_CT,
          { "CT", "ucp.parm.CT",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x00,
            "Accumulated charges timestamp.",
            HFILL
          }
        },
        { &hf_ucp_parm_AAC,
          { "AAC", "ucp.parm.AAC",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Accumulated charges.",
            HFILL
          }
        },
        { &hf_ucp_parm_MNo,
          { "MNo", "ucp.parm.MNo",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Message number.",
            HFILL
          }
        },
        { &hf_ucp_parm_R_T,
          { "R_T", "ucp.parm.R_T",
            FT_CHAR, BASE_HEX, VALS(vals_parm_R_T), 0x00,
            "Message number.",
            HFILL
          }
        },
        { &hf_ucp_parm_NAdC,
          { "NAdC", "ucp.parm.NAdC",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Notification address.",
            HFILL
          }
        },
        { &hf_ucp_parm_NT,
          { "NT", "ucp.parm.NT",
            FT_CHAR, BASE_HEX, VALS(vals_parm_NT), 0x00,
            "Notification type.",
            HFILL
          }
        },
        { &hf_ucp_parm_IVR5x,
          { "IVR5x", "ucp.parm.IVR5x",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "UCP release number supported/accepted.",
            HFILL
          }
        },
        { &hf_ucp_parm_REQ_OT,
          { "REQ_OT", "ucp.parm.REQ_OT",
            FT_CHAR, BASE_HEX, VALS(vals_parm_REQ_OT), 0x00,
            "UCP release number supported/accepted.",
            HFILL
          }
        },
        { &hf_ucp_parm_SSTAT,
          { "SSTAT", "ucp.parm.SSTAT",
            FT_CHAR, BASE_HEX, VALS(vals_parm_SSTAT), 0x00,
            "Supplementary services for which status is requested.",
            HFILL
          }
        },
        { &hf_ucp_parm_LMN,
          { "LMN", "ucp.parm.LMN",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            "Last message number.",
            HFILL
          }
        },
        { &hf_ucp_parm_NMESS,
          { "NMESS", "ucp.parm.NMESS",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            "Number of stored messages.",
            HFILL
          }
        },
        { &hf_ucp_parm_NPID,
          { "NPID", "ucp.parm.NPID",
            FT_UINT16, BASE_DEC, VALS(vals_parm_PID), 0x00,
            "Notification PID value.",
            HFILL
          }
        },
        { &hf_ucp_parm_LRq,
          { "LRq", "ucp.parm.LRq",
            FT_CHAR, BASE_HEX, VALS(vals_parm_LRq), 0x00,
            "Last resort address request.",
            HFILL
          }
        },
        { &hf_ucp_parm_LRAd,
          { "LRAd", "ucp.parm.LRAd",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Last resort address.",
            HFILL
          }
        },
        { &hf_ucp_parm_LPID,
          { "LPID", "ucp.parm.LPID",
            FT_UINT16, BASE_DEC, VALS(vals_parm_PID), 0x00,
            "Last resort PID value.",
            HFILL
          }
        },
        { &hf_ucp_parm_DD,
          { "DD", "ucp.parm.DD",
            FT_CHAR, BASE_HEX, VALS(vals_parm_DD), 0x00,
            "Deferred delivery requested.",
            HFILL
          }
        },
        { &hf_ucp_parm_DDT,
          { "DDT", "ucp.parm.DDT",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x00,
            "Deferred delivery time.",
            HFILL
          }
        },
        { &hf_ucp_parm_STx,
          { "STx", "ucp.parm.STx",
            FT_NONE, BASE_NONE, NULL, 0x00,
            "Standard text.",
            HFILL
          }
        },
        { &hf_ucp_parm_ST,
          { "ST", "ucp.parm.ST",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x00,
            "Start time.",
            HFILL
          }
        },
        { &hf_ucp_parm_SP,
          { "SP", "ucp.parm.SP",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x00,
            "Stop time.",
            HFILL
          }
        },
        { &hf_ucp_parm_VP,
          { "VP", "ucp.parm.VP",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x00,
            "Validity period.",
            HFILL
          }
        },
        { &hf_ucp_parm_RPID,
          { "RPID", "ucp.parm.RPID",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Replace PID",
            HFILL
          }
        },
        { &hf_ucp_parm_SCTS,
          { "SCTS", "ucp.parm.SCTS",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x00,
            "Service Centre timestamp.",
            HFILL
          }
        },
        { &hf_ucp_parm_Dst,
          { "Dst", "ucp.parm.Dst",
            FT_CHAR, BASE_HEX, VALS(vals_parm_Dst), 0x00,
            "Delivery status.",
            HFILL
          }
        },
        { &hf_ucp_parm_Rsn,
          { "Rsn", "ucp.parm.Rsn",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &vals_parm_Rsn_ext, 0x00,
            "Reason code.",
            HFILL
          }
        },
        { &hf_ucp_parm_DSCTS,
          { "DSCTS", "ucp.parm.DSCTS",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x00,
            "Delivery timestamp.",
            HFILL
          }
        },
        { &hf_ucp_parm_MT,
          { "MT", "ucp.parm.MT",
            FT_CHAR, BASE_HEX, VALS(vals_parm_MT), 0x00,
            "Message type.",
            HFILL
          }
        },
        { &hf_ucp_parm_NB,
          { "NB", "ucp.parm.NB",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "No. of bits in Transparent Data (TD) message.",
            HFILL
          }
        },
        { &hf_ucp_data_section,
          { "Data", "ucp.message",
            FT_NONE, BASE_NONE, NULL, 0x00,
            "The actual message or data.",
            HFILL
          }
        },
        { &hf_ucp_parm_MMS,
          { "MMS", "ucp.parm.MMS",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            "More messages to send.",
            HFILL
          }
        },
        { &hf_ucp_parm_DCs,
          { "DCs", "ucp.parm.DCs",
            FT_CHAR, BASE_HEX, VALS(vals_parm_DCs), 0x00,
            "Data coding scheme (deprecated).",
            HFILL
          }
        },
        { &hf_ucp_parm_MCLs,
          { "MCLs", "ucp.parm.MCLs",
            FT_CHAR, BASE_HEX, VALS(vals_parm_MCLs), 0x00,
            "Message class.",
            HFILL
          }
        },
        { &hf_ucp_parm_RPI,
          { "RPI", "ucp.parm.RPI",
            FT_CHAR, BASE_HEX, VALS(vals_parm_RPI), 0x00,
            "Reply path.",
            HFILL
          }
        },
        { &hf_ucp_parm_CPg,
          { "CPg", "ucp.parm.CPg",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Reserved for Code Page.",
            HFILL
          }
        },
        { &hf_ucp_parm_RPLy,
          { "RPLy", "ucp.parm.RPLy",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Reserved for Reply type.",
            HFILL
          }
        },
        { &hf_ucp_parm_OTOA,
          { "OTOA", "ucp.parm.OTOA",
            FT_UINT16, BASE_DEC, VALS(vals_parm_OTOA), 0x00,
            "Originator Type Of Address.",
            HFILL
          }
        },
        { &hf_ucp_parm_HPLMN,
          { "HPLMN", "ucp.parm.HPLMN",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Home PLMN address.",
            HFILL
          }
        },
        { &hf_ucp_parm_XSer,
          { "Extra services:", "ucp.parm.XSer",
            FT_NONE, BASE_NONE, NULL, 0x00,
            "Extra services.",
            HFILL
          }
        },
        { &hf_ucp_parm_RES4,
          { "RES4", "ucp.parm.RES4",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Reserved for future use.",
            HFILL
          }
        },
        { &hf_ucp_parm_RES5,
          { "RES5", "ucp.parm.RES5",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Reserved for future use.",
            HFILL
          }
        },
        { &hf_ucp_parm_OTON,
          { "OTON", "ucp.parm.OTON",
            FT_CHAR, BASE_HEX, VALS(vals_parm_OTON), 0x00,
            "Originator type of number.",
            HFILL
          }
        },
        { &hf_ucp_parm_ONPI,
          { "ONPI", "ucp.parm.ONPI",
            FT_CHAR, BASE_HEX, VALS(vals_parm_ONPI), 0x00,
            "Originator numbering plan id.",
            HFILL
          }
        },
        { &hf_ucp_parm_STYP0,
          { "STYP0", "ucp.parm.STYP0",
            FT_CHAR, BASE_HEX, VALS(vals_parm_STYP0), 0x00,
            "Subtype of operation.",
            HFILL
          }
        },
        { &hf_ucp_parm_STYP1,
          { "STYP1", "ucp.parm.STYP1",
            FT_CHAR, BASE_HEX, VALS(vals_parm_STYP1), 0x00,
            "Subtype of operation.",
            HFILL
          }
        },
        { &hf_ucp_parm_PWD,
          { "PWD", "ucp.parm.PWD",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Current password.",
            HFILL
          }
        },
        { &hf_ucp_parm_NPWD,
          { "NPWD", "ucp.parm.NPWD",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "New password.",
            HFILL
          }
        },
        { &hf_ucp_parm_VERS,
          { "VERS", "ucp.parm.VERS",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Version number.",
            HFILL
          }
        },
        { &hf_ucp_parm_LAdC,
          { "LAdC", "ucp.parm.LAdC",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Address for VSMSC list operation.",
            HFILL
          }
        },
        { &hf_ucp_parm_LTON,
          { "LTON", "ucp.parm.LTON",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            "Type of number list address.",
            HFILL
          }
        },
        { &hf_ucp_parm_LNPI,
          { "LNPI", "ucp.parm.LNPI",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            "Numbering plan id. list address.",
            HFILL
          }
        },
        { &hf_ucp_parm_OPID,
          { "OPID", "ucp.parm.OPID",
            FT_UINT8, BASE_DEC, VALS(vals_parm_OPID), 0x00,
            "Originator protocol identifier.",
            HFILL
          }
        },
        { &hf_ucp_parm_RES1,
          { "RES1", "ucp.parm.RES1",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Reserved for future use.",
            HFILL
          }
        },
        { &hf_ucp_parm_RES2,
          { "RES2", "ucp.parm.RES2",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Reserved for future use.",
            HFILL
          }
        },
        { &hf_ucp_parm_ACK,
          { "(N)Ack", "ucp.parm.ACK",
            FT_CHAR, BASE_HEX, VALS(vals_parm_ACK), 0x00,
            "Positive or negative acknowledge of the operation.",
            HFILL
          }
        },
        { &hf_ucp_parm_MVP,
          { "MVP", "ucp.parm.MVP",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x00,
            "Modified validity period.",
            HFILL
          }
        },
        { &hf_ucp_parm_EC,
          { "Error code", "ucp.parm.EC",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &vals_parm_EC_ext, 0x00,
            "The result of the requested operation.",
            HFILL
          }
        },
        { &hf_ucp_parm_SM,
          { "SM", "ucp.parm.SM",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "System message.",
            HFILL
          }
        },
        { &hf_ucp_ga_roaming,
          { "GA roaming definitions", "ucp.parm.ga_roaming",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL,
            HFILL
          }
        },
        { &hf_ucp_call_barring,
          { "Call barring definitions", "ucp.parm.call_barring",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL,
            HFILL
          }
        },
        { &hf_ucp_deferred_delivery,
          { "Deferred delivery definitions", "ucp.parm.deferred_delivery",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL,
            HFILL
          }
        },
        { &hf_ucp_diversion,
          { "Diversion definitions", "ucp.parm.diversion",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL,
            HFILL
          }
        },
        { &hf_ucp_not_subscribed,
          { "Not subscribed/not allowed", "ucp.parm.not_subscribed",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL,
            HFILL
          }
        },
        { &hf_xser_service,
          { "Type of service", "ucp.xser.service",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &vals_xser_service_ext, 0x00,
            "The type of service specified.",
            HFILL
          }
        },
        { &hf_xser_length,
          { "Length", "ucp.xser.length",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL,
            HFILL
          }
        },
        { &hf_xser_data,
          { "Data", "ucp.xser.data",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL,
            HFILL
          }
        },
    };
    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_ucp,
        &ett_sub,
        &ett_XSer
    };

    static ei_register_info ei[] = {
        { &ei_ucp_stx_missing, { "ucp.stx_missing", PI_MALFORMED, PI_ERROR, "UCP_STX missing, this is not a new packet", EXPFILL }},
        { &ei_ucp_intstring_invalid, { "ucp.intstring.invalid", PI_MALFORMED, PI_ERROR, "Invalid integer string", EXPFILL }},
        { &ei_ucp_hexstring_invalid, { "ucp.hexstring.invalid", PI_PROTOCOL, PI_WARN, "Invalid hex string", EXPFILL }},
        { &ei_ucp_short_data, { "ucp.short_data", PI_PROTOCOL, PI_WARN, "Short Data (?)", EXPFILL }}
    };

    module_t *ucp_module;
    expert_module_t* expert_ucp;

    /* Register the protocol name and description */
    proto_ucp = proto_register_protocol("Universal Computer Protocol",
                                        "UCP", "ucp");

    /* Required function calls to register header fields and subtrees used */
    proto_register_field_array(proto_ucp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_ucp = expert_register_protocol(proto_ucp);
    expert_register_field_array(expert_ucp, ei, array_length(ei));

    /* Register the dissector handle */
    ucp_handle = register_dissector("ucp", dissect_ucp_tcp, proto_ucp);

    /* Register for tapping */
    ucp_tap = register_tap("ucp");

    /* register preferences */
    ucp_module = prefs_register_protocol(proto_ucp, NULL);
    prefs_register_bool_preference(ucp_module, "desegment_ucp_messages",
                                   "Reassemble UCP messages spanning multiple TCP segments",
                                   "Whether the UCP dissector should reassemble messages spanning"
                                   " multiple TCP segments."
                                   " To use this option, you must also enable "
                                   "\"Allow subdissectors to reassemble TCP streams\" in the "
                                   "TCP protocol settings.",
                                   &ucp_desegment);
}

void
proto_reg_handoff_ucp(void)
{
    /*
     * UCP can be spoken on any port so, when not on a specific port, try heuristic
     * whenever TCP is spoken.
     */
    heur_dissector_add("tcp", dissect_ucp_heur, "UCP over TCP", "ucp_tcp", proto_ucp, HEURISTIC_ENABLE);

    /*
     * Also register as a dissector that can be selected by a TCP port number via "decode as".
     */
    dissector_add_for_decode_as_with_preference("tcp.port", ucp_handle);

    /* Tapping setup */
    stats_tree_cfg *st_config = stats_tree_register("ucp", "ucp_messages", "_UCP Messages", 0,
                        ucp_stats_tree_per_packet, ucp_stats_tree_init, NULL);
    stats_tree_set_group(st_config, REGISTER_TELEPHONY_GROUP_UNSORTED);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
