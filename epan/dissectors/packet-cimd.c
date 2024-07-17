/* packet-cimd.c
 *
 * Routines for Computer Interface to Message Distribution (CIMD) version 2 dissection
 *
 * Copyright : 2005 Viorel Suman <vsuman[AT]avmob.ro>, Lucian Piros <lpiros[AT]avmob.ro>
 *             In association with Avalanche Mobile BV, http://www.avmob.com
 *
 * Updates :
 *            Sub routines for further dissection of Status and Error codes added by Vineeth <vineethvijaysv@gmail.com>
 *
 * Refer to the AUTHORS file or the AUTHORS section in the man page
 * for contacting the author(s) of this file.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <stdlib.h>

#include <epan/packet.h>
#include <epan/charsets.h>
#define CIMD_STX   0x02 /* Start of CIMD PDU */
#define CIMD_ETX   0x03 /* End of CIMD PDU */
#define CIMD_COLON 0x3A /* CIMD colon */
#define CIMD_DELIM 0x09 /* CIMD Delimiter */

#define CIMD_OC_OFFSET  1 /* CIMD Operation Code Offset */
#define CIMD_OC_LENGTH  2 /* CIMD Operation Code Length */
#define CIMD_PN_OFFSET  4 /* CIMD Packet Number Offset */
#define CIMD_PN_LENGTH  3 /* CIMD Packet Number Length */
#define CIMD_PC_LENGTH  3 /* CIMD Parameter Code Length */
#define CIMD_MIN_LENGTH 9 /* CIMD Minimal packet length : STX(1) + OC(2) + COLON(1) + PN(3) + DELIM(1) + ETX(1)*/

/* define CIMD2 operation code */

#define CIMD_Login                     1
#define CIMD_LoginResp                51
#define CIMD_Logout                    2
#define CIMD_LogoutResp               52
#define CIMD_SubmitMessage             3
#define CIMD_SubmitMessageResp        53
#define CIMD_EnqMessageStatus          4
#define CIMD_EnqMessageStatusResp     54
#define CIMD_DeliveryRequest           5
#define CIMD_DeliveryRequestResp      55
#define CIMD_CancelMessage             6
#define CIMD_CancelMessageResp        56
#define CIMD_SetMessage                8
#define CIMD_SetMessageResp           58
#define CIMD_GetMessage                9
#define CIMD_GetMessageResp           59
#define CIMD_Alive                    40
#define CIMD_AliveResp                90
#define CIMD_GeneralErrorResp         98
#define CIMD_NACK                     99
  /* SC2App */
#define CIMD_DeliveryMessage          20
#define CIMD_DeliveryMessageResp      70
#define CIMD_DeliveryStatusReport     23
#define CIMD_DeliveryStatusReportResp 73

/* define CIMD2 operation's parameter codes */

#define CIMD_UserIdentity            10
#define CIMD_Password                11
#define CIMD_Subaddress              12
#define CIMD_WindowSize              19
#define CIMD_DestinationAddress      21
#define CIMD_OriginatingAddress      23
#define CIMD_OriginatingImsi         26
#define CIMD_AlphaOriginatingAddr    27
#define CIMD_OriginatedVisitedMSCAd  28
#define CIMD_DataCodingScheme        30
#define CIMD_UserDataHeader          32
#define CIMD_UserData                33
#define CIMD_UserDataBinary          34
#define CIMD_MoreMessagesToSend      44
#define CIMD_ValidityPeriodRelative  50
#define CIMD_ValidityPeriodAbsolute  51
#define CIMD_ProtocolIdentifier      52
#define CIMD_FirstDeliveryTimeRel    53
#define CIMD_FirstDeliveryTimeAbs    54
#define CIMD_ReplyPath               55
#define CIMD_StatusReportRequest     56
#define CIMD_CancelEnabled           58
#define CIMD_CancelMode              59
#define CIMD_SCTimeStamp             60
#define CIMD_StatusCode              61
#define CIMD_StatusErrorCode         62
#define CIMD_DischargeTime           63
#define CIMD_TariffClass             64
#define CIMD_ServiceDescription      65
#define CIMD_MessageCount            66
#define CIMD_Priority                67
#define CIMD_DeliveryRequestMode     68
#define CIMD_SCAddress               69
#define CIMD_GetParameter           500
#define CIMD_SMSCTime               501
#define CIMD_ErrorCode              900
#define CIMD_ErrorText              901

#define MAXPARAMSCOUNT               37

typedef struct cimd_parameter_t cimd_parameter_t;

typedef void (*cimd_pdissect)(tvbuff_t *tvb, proto_tree *tree, int pindex, int startOffset, int endOffset);

struct cimd_parameter_t {
  cimd_pdissect  diss;
  int           *ett_p;
  int           *hf_p;
};

void proto_register_cimd(void);
void proto_reg_handoff_cimd(void);
static void dissect_cimd_parameter(tvbuff_t *tvb, proto_tree *tree, int pindex, int startOffset, int endOffset);
static void dissect_cimd_ud(tvbuff_t *tvb, proto_tree *tree, int pindex, int startOffset, int endOffset);
static void dissect_cimd_dcs(tvbuff_t *tvb, proto_tree *tree, int pindex, int startOffset, int endOffset);
static void dissect_cimd_error_code(tvbuff_t *tvb, proto_tree *tree, int pindex, int startOffset, int endOffset);

static dissector_handle_t cimd_handle;

static int proto_cimd;
/* Initialize the subtree pointers */
static int ett_cimd;

/* Initialize the protocol and registered fields */
static int hf_cimd_opcode_indicator;
static int hf_cimd_packet_number_indicator;
static int hf_cimd_checksum_indicator;
static int hf_cimd_pcode_indicator;

static int hf_cimd_dcs_coding_group_indicatorC0;
static int hf_cimd_dcs_coding_group_indicatorF0;
static int hf_cimd_dcs_compressed_indicator;
static int hf_cimd_dcs_message_class_meaning_indicator;
static int hf_cimd_dcs_message_class_indicator;
static int hf_cimd_dcs_character_set_indicator0C;
static int hf_cimd_dcs_character_set_indicator04;
static int hf_cimd_dcs_indication_sense;
static int hf_cimd_dcs_indication_type;

static const value_string vals_hdr_OC[] = {
  /* operation codes array */
  {CIMD_Login,                    "Login"},
  {CIMD_LoginResp,                "Login Resp"},
  {CIMD_Logout,                   "Logout"},
  {CIMD_LogoutResp,               "Logout Resp"},
  {CIMD_SubmitMessage,            "Submit message"},
  {CIMD_SubmitMessageResp,        "Submit message Resp"},
  {CIMD_EnqMessageStatus,         "Enquire message status"},
  {CIMD_EnqMessageStatusResp,     "Enquire message status Resp"},
  {CIMD_DeliveryRequest,          "Delivery request"},
  {CIMD_DeliveryRequestResp,      "Delivery request Resp"},
  {CIMD_CancelMessage,            "Cancel message"},
  {CIMD_CancelMessageResp,        "Cancel message Resp"},
  {CIMD_SetMessage,               "Set message"},
  {CIMD_SetMessageResp,           "Set message Resp"},
  {CIMD_GetMessage,               "Get message"},
  {CIMD_GetMessageResp,           "Get message Resp"},
  {CIMD_Alive,                    "Alive"},
  {CIMD_AliveResp,                "Alive Resp"},
  {CIMD_GeneralErrorResp,         "General error Resp"},
  {CIMD_NACK,                     "Nack"},
  /* SC2App */
  {CIMD_DeliveryMessage,          "Deliver message"},
  {CIMD_DeliveryMessageResp,      "Deliver message Resp"},
  {CIMD_DeliveryStatusReport,     "Deliver status report"},
  {CIMD_DeliveryStatusReportResp, "Deliver status report Resp"},
  {0, NULL}
};

static const value_string cimd_vals_PC[] = {
  /* parameter codes array */
  {CIMD_UserIdentity,           "User Identity"},
  {CIMD_Password,               "Password"},
  {CIMD_Subaddress,             "Subaddr"},
  {CIMD_WindowSize,             "Window Size"},
  {CIMD_DestinationAddress,     "Destination Address"},
  {CIMD_OriginatingAddress,     "Originating Address"},
  {CIMD_OriginatingImsi,        "Originating IMSI"},
  {CIMD_AlphaOriginatingAddr,   "Alphanumeric Originating Address"},
  {CIMD_OriginatedVisitedMSCAd, "Originated Visited MSC Address"},
  {CIMD_DataCodingScheme,       "Data Coding Scheme"},
  {CIMD_UserDataHeader,         "User Data Header"},
  {CIMD_UserData,               "User Data"},
  {CIMD_UserDataBinary,         "User Data Binary"},
  {CIMD_MoreMessagesToSend,     "More Messages To Send"},
  {CIMD_ValidityPeriodRelative, "Validity Period Relative"},
  {CIMD_ValidityPeriodAbsolute, "Validity Period Absolute"},
  {CIMD_ProtocolIdentifier,     "Protocol Identifier"},
  {CIMD_FirstDeliveryTimeRel,   "First Delivery Time Relative"},
  {CIMD_FirstDeliveryTimeAbs,   "First Delivery Time Absolute"},
  {CIMD_ReplyPath,              "Reply Path"},
  {CIMD_StatusReportRequest,    "Status Report Request"},
  {CIMD_CancelEnabled,          "Cancel Enabled"},
  {CIMD_CancelMode,             "Cancel Mode"},
  {CIMD_SCTimeStamp,            "Service Centre Time Stamp"},
  {CIMD_StatusCode,             "Status Code"},
  {CIMD_StatusErrorCode,        "Status Error Code"},
  {CIMD_DischargeTime,          "Discharge Time"},
  {CIMD_TariffClass,            "Tariff Class"},
  {CIMD_ServiceDescription,     "Service Description"},
  {CIMD_MessageCount,           "Message Count"},
  {CIMD_Priority,               "Priority"},
  {CIMD_DeliveryRequestMode,    "Delivery Request Mode"},
  {CIMD_SCAddress,              "Service Center Address"},
  {CIMD_GetParameter,           "Get Parameter"},
  {CIMD_SMSCTime,               "SMS Center Time"},
  {CIMD_ErrorCode,              "Error Code"},
  {CIMD_ErrorText,              "Error Text"},
  {0, NULL}
};

static const value_string cimd_dcs_coding_groups[] = {
  {0x00, "General Data Coding indication"},
  {0x01, "General Data Coding indication"},
  {0x02, "General Data Coding indication"},
  {0x03, "General Data Coding indication"},
  {0x04, "Message Marked for Automatic Deletion Group"},
  {0x05, "Message Marked for Automatic Deletion Group"},
  {0x06, "Message Marked for Automatic Deletion Group"},
  {0x07, "Message Marked for Automatic Deletion Group"},
  {0x08, "Reserved coding group"},
  {0x09, "Reserved coding group"},
  {0x0A, "Reserved coding group"},
  {0x0B, "Reserved coding group"},
  {0x0C, "Message Waiting Indication Group: Discard Message (7-bit encoded)"},
  {0x0D, "Message Waiting Indication Group: Store Message (7-bit encoded)"},
  {0x0E, "Message Waiting Indication Group: Store Message (uncompressed UCS2 encoded)"},
  {0x0F, "Data coding/message class"},
  {0, NULL}
};

static const value_string cimd_dcs_compressed[] = {
  {0x00, "Text is uncompressed"},
  {0x01, "Text is compressed"},
  {0, NULL}
};

static const value_string cimd_dcs_message_class_meaning[] = {
  {0x00, "Reserved, bits 1 to 0 have no message class meaning"},
  {0x01, "Bits 1 to 0 have message class meaning"},
  {0, NULL}
};

static const value_string cimd_dcs_message_class[] = {
  {0x00, "Class 0"},
  {0x01, "Class 1 Default meaning: ME-specific"},
  {0x02, "Class 2 (U)SIM specific message"},
  {0x03, "Class 3 Default meaning: TE-specific"},
  {0, NULL}
};

static const value_string cimd_dcs_character_set[] = {
  {0x00, "GSM 7 bit default alphabet"},
  {0x01, "8 bit data"},
  {0x02, "UCS2 (16bit)"},
  {0x03, "Reserved"},
  {0, NULL}
};

static const value_string cimd_dcs_indication_sense[] = {
  {0x00, "Set Indication Inactive"},
  {0x01, "Set Indication Active"},
  {0, NULL}
};

static const value_string cimd_dcs_indication_type[] = {
  {0x00, "Voicemail Message Waiting"},
  {0x01, "Fax Message Waiting"},
  {0x02, "Electronic Mail Message Waiting"},
  {0x03, "Other Message Waiting"},
  {0, NULL}
};

static const value_string cimd_error_vals[] = {
  {1, "Unexpected operation"},
  {2, "Syntax error"},
  {3, "Unsupported parameter error"},
  {4, "Connection to SMS Center lost"},
  {5, "No response from SMS Center"},
  {6, "General system error"},
  {7, "Cannot find information"},
  {8, "Parameter formatting error"},
  {9, "Requested operation failed"},
  {10, "Temporary congestion error"},
  {100, "Invalid login"},
  {101, "Incorrect access type"},
  {102, "Too many users with this login ID"},
  {103, "Login refused by SMS Center"},
  {104, "Invalid window size"},
  {105, "Windowing disabled"},
  {106, "Virtual SMS Center-based barring"},
  {107, "Invalid subaddr"},
  {108, "Alias account, login refused"},
  {300, "Incorrect destination address"},
  {301, "Incorrect number of destination addresses"},
  {302, "Syntax error in user data parameter"},
  {303, "Incorrect bin/head/normal user data parameter combination"},
  {304, "Incorrect dcs parameter usage"},
  {305, "Incorrect validity period parameters usage"},
  {306, "Incorrect originator address usage"},
  {307, "Incorrect PID parameter usage"},
  {308, "Incorrect first delivery parameter usage"},
  {309, "Incorrect reply path usage"},
  {310, "Incorrect status report request parameter usage"},
  {311, "Incorrect cancel enabled parameter usage"},
  {312, "Incorrect priority parameter usage"},
  {313, "Incorrect tariff class parameter usage"},
  {314, "Incorrect service description parameter usage"},
  {315, "Incorrect transport type parameter usage"},
  {316, "Incorrect message type parameter usage"},
  {318, "Incorrect MMs parameter usage"},
  {319, "Incorrect operation timer parameter usage"},
  {320, "Incorrect dialogue ID parameter usage"},
  {321, "Incorrect alpha originator address usage"},
  {322, "Invalid data for alpha numeric originator"},
  {400, "Incorrect address parameter usage"},
  {401, "Incorrect scts parameter usage"},
  {500, "Incorrect scts parameter usage"},
  {501, "Incorrect mode parameter usage"},
  {502, "Incorrect parameter combination"},
  {600, "Incorrect scts parameter usage"},
  {601, "Incorrect address parameter usage"},
  {602, "Incorrect mode parameter usage"},
  {603, "Incorrect parameter combination"},
  {800, "Changing password failed"},
  {801, "Changing password not allowed"},
  {900, "Unsupported item requested"},
  {0, NULL}
};

static value_string_ext cimd_error_vals_ext = VALUE_STRING_EXT_INIT(cimd_error_vals);

static const value_string cimd_status_code_vals[] = {
  {1, " in process"},
  {2, " validity period expired"},
  {3, " delivery failed"},
  {4, " delivery successful"},
  {5, " no response"},
  {6, " last no response"},
  {7, " message cancelled"},
  {8, " message deleted"},
  {9, " message deleted by cancel"},
  {0, NULL}
};

static const value_string cimd_status_error_vals[] = {
 {1, "Unknown subscriber"},
 {9, "Illegal subscriber"},
 {11, "Teleservice not provisioned"},
 {13, "Call barred"},
 {15, "CUG reject"},
 {19, "No SMS support in MS"},
 {20, "Error in MS"},
 {21, "Facility not supported"},
 {22, "Memory capacity exceeded"},
 {29, "Absent subscriber"},
 {30, "MS busy for MT SMS"},
 {36, "Network/Protocol failure"},
 {44, "Illegal equipment"},
 {60, "No paging response"},
 {61, "GMSC congestion"},
 {63, "HLR timeout"},
 {64, "MSC/SGSN_timeout"},
 {70, "SMRSE/TCP error"},
 {72, "MT congestion"},
 {75, "GPRS suspended"},
 {80, "No paging response via MSC"},
 {81, "IMSI detached"},
 {82, "Roaming restriction"},
 {83, "Deregistered in HLR for GSM"},
 {84, "Purged for GSM"},
 {85, "No paging response via SGSN"},
 {86, "GPRS detached"},
 {87, "Deregistered in HLR for GPRS"},
 {88, "The MS purged for GPRS"},
 {89, "Unidentified subscriber via MSC"},
 {90, "Unidentified subscriber via SGSN"},
 {112, "Originator missing credit on prepaid account"},
 {113, "Destination missing credit on prepaid account"},
 {114, "Error in prepaid system"},
 {0, NULL}
};

static value_string_ext cimd_status_error_vals_ext = VALUE_STRING_EXT_INIT(cimd_status_error_vals);

static const cimd_pdissect cimd_pc_handles[] = {
 /* function handles for parsing cimd parameters */
  dissect_cimd_parameter,
  dissect_cimd_parameter,
  dissect_cimd_parameter,
  dissect_cimd_parameter,
  dissect_cimd_parameter,
  dissect_cimd_parameter,
  dissect_cimd_parameter,
  dissect_cimd_parameter,
  dissect_cimd_parameter,
  dissect_cimd_dcs,
  dissect_cimd_parameter,
  dissect_cimd_ud,
  dissect_cimd_parameter,
  dissect_cimd_parameter,
  dissect_cimd_parameter,
  dissect_cimd_parameter,
  dissect_cimd_parameter,
  dissect_cimd_parameter,
  dissect_cimd_parameter,
  dissect_cimd_parameter,
  dissect_cimd_parameter,
  dissect_cimd_parameter,
  dissect_cimd_parameter,
  dissect_cimd_parameter,
  dissect_cimd_error_code,
  dissect_cimd_error_code,
  dissect_cimd_parameter,
  dissect_cimd_parameter,
  dissect_cimd_parameter,
  dissect_cimd_parameter,
  dissect_cimd_parameter,
  dissect_cimd_parameter,
  dissect_cimd_parameter,
  dissect_cimd_parameter,
  dissect_cimd_parameter,
  dissect_cimd_error_code,
  dissect_cimd_parameter
};

/* Parameters */
static cimd_parameter_t vals_hdr_PC[MAXPARAMSCOUNT + 1];
static int ett_index[MAXPARAMSCOUNT];
static int hf_index[MAXPARAMSCOUNT];

static void dissect_cimd_parameter(tvbuff_t *tvb, proto_tree *tree, int pindex, int startOffset, int endOffset)
{
  /* Set up structures needed to add the param subtree and manage it */
  proto_tree *param_tree;

  param_tree = proto_tree_add_subtree(tree, tvb, startOffset + 1, endOffset - (startOffset + 1),
                                   (*vals_hdr_PC[pindex].ett_p), NULL, cimd_vals_PC[pindex].strptr);

  proto_tree_add_item(param_tree, hf_cimd_pcode_indicator, tvb,
    startOffset + 1, CIMD_PC_LENGTH, ENC_ASCII);
  proto_tree_add_item(param_tree, (*vals_hdr_PC[pindex].hf_p), tvb,
    startOffset + 1 + CIMD_PC_LENGTH + 1, endOffset - (startOffset + 1 + CIMD_PC_LENGTH + 1), ENC_ASCII|ENC_NA);
}

static void dissect_cimd_ud(tvbuff_t *tvb, proto_tree *tree, int pindex, int startOffset, int endOffset)
{
  /* Set up structures needed to add the param subtree and manage it */
  proto_tree *param_tree;

  uint8_t *tmpBuffer1;
  const uint8_t* payloadText;
  wmem_strbuf_t *tmpBuffer;
  int    loop;
  int    g_offset, g_size;
  char   token[4];

  /* The user data (33) parameter is used when the data coding scheme (30)
   * indicates that the default GSM character set is being used.
   * It is not transmitted directly as the 23.038 GSM encoding (packed
   * or unpacked), but rather each character is converted to ASCII
   * or Latin-1 (ISO-8859-1).
   *
   * (XXX: It is possible that the UDH indicates that a national
   * language shift table is to be used, but we don't implement that.
   * It is also theoretically possible for some encoding other than
   * Latin-1 to be used.)
   *
   * It is simplest to first convert back to the GSM 7 bit encoding (unpacked),
   * and then convert that to UTF-8, since the GSM extension table characters
   * require a second level of escape handling. We will use '\xff' as a
   * placeholder for illegal characters that will be replaced with Unicode
   * REPLACEMENT CHARACTERS upon final conversion.
   */
  static const value_string combining_mapping[] = {
    {  0, "_Oa"},
    {  1, "_L-"},
    {  3, "_Y-"},
    {  4, "_e`"},
    {  5, "_e'"},
    {  6, "_u`"},
    {  7, "_i`"},
    {  8, "_o`"},
    {  9, "_C,"},
    { 11, "_O/"},
    { 12, "_o/"},
    { 14, "_A*"},
    { 15, "_a*"},
    { 16, "_gd"},
    { 17, "_--"},
    { 18, "_gf"},
    { 19, "_gg"},
    { 20, "_gl"},
    { 21, "_go"},
    { 22, "_gp"},
    { 23, "_gi"},
    { 24, "_gs"},
    { 25, "_gt"},
    { 26, "_gx"},
    { 27, "_XX"},
    { 28, "_AE"},
    { 29, "_ae"},
    { 30, "_ss"},
    { 31, "_E'"},
    { 34, "_qq"},
    { 36, "_ox"},
    { 40, "_!!"},
    { 91, "_A\""},
    { 92, "_O\""},
    { 93, "_N~"},
    { 94, "_U\""},
    { 95, "_so"},
    { 96, "_??"},
    {123, "_a\""},
    {124, "_o\""},
    {125, "_n~"},
    {126, "_n\""},
    {127, "_a`"},
    {  0, NULL }
  };

  static const char latin_mapping[256] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     /* 0x00 -       */
    0xff, 0xff, 0x0a, 0xff, 0xff, 0x0d, 0xff, 0xff,     /*      - 0x0F  */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     /* 0x10 -       */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     /*      - 0x1F  */
    0x20, 0x21, 0x22, 0x23, 0x02, 0x25, 0x26, 0x27,     /* 0x20 -       */
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,     /*      - 0x2F  */
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,     /* 0x30 -       */
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,     /*      - 0x3F  */
    0x00, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,     /* 0x40 -       */
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,     /*      - 0x4F  */
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,     /* 0x50 -       */
    0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x0e, 0x5e, 0xff,     /*      - 0x5F  */
    0xff, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,     /* 0x60 -       */
    0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,     /*      - 0x6F  */
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,     /* 0x70 -       */
    0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x0f, 0x7e, 0xff,     /*      - 0x7F  */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     /* 0x80 -       */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     /*      - 0x8F  */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     /* 0x90 -       */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     /*      - 0x9F  */
    0xff, 0x40, 0xff, 0x01, 0x24, 0x03, 0xff, 0x5f,     /* 0xA0 -       */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     /*      - 0xAF  */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     /* 0xB0 -       */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x60,     /*      - 0xBF  */
    0xff, 0xff, 0xff, 0xff, 0x5b, 0x0e, 0x1c, 0x09,     /* 0xC0 -       */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     /*      - 0xCF  */
  };

  param_tree = proto_tree_add_subtree(tree, tvb,
    startOffset + 1, endOffset - (startOffset + 1),
    (*vals_hdr_PC[pindex].ett_p), NULL, cimd_vals_PC[pindex].strptr
  );
  proto_tree_add_item(param_tree, hf_cimd_pcode_indicator, tvb,
    startOffset + 1, CIMD_PC_LENGTH, ENC_ASCII);

  g_offset = startOffset + 1 + CIMD_PC_LENGTH + 1;
  g_size   = endOffset - g_offset;

  payloadText = tvb_get_ptr(tvb, g_offset, g_size);
  tmpBuffer = wmem_strbuf_new_sized(wmem_packet_scope(), g_size+1);
  for (loop = 0; loop < g_size; loop++)
  {
    if (payloadText[loop] == '_')
    {
      if (loop < g_size - 2)
      {
        token[0] = payloadText[loop++];
        token[1] = payloadText[loop++];
        token[2] = payloadText[loop];
        token[3] = '\0';
        wmem_strbuf_append_c(tmpBuffer, str_to_val(token, combining_mapping, 0xff));
      }
      else
      {
        /* Not enough room for a combining sequence. */
        wmem_strbuf_append_c(tmpBuffer, 0xff);
      }
    }
    else
    {
      wmem_strbuf_append_c(tmpBuffer, latin_mapping[payloadText[loop]]);
    }
  }

  tmpBuffer1 = get_ts_23_038_7bits_string_unpacked(wmem_packet_scope(), wmem_strbuf_get_str(tmpBuffer), (int)wmem_strbuf_get_len(tmpBuffer));
  wmem_strbuf_destroy(tmpBuffer);
  proto_tree_add_string(param_tree, (*vals_hdr_PC[pindex].hf_p), tvb, g_offset, g_size, tmpBuffer1);
}

static void dissect_cimd_dcs(tvbuff_t *tvb, proto_tree *tree, int pindex, int startOffset, int endOffset)
{
  /* Set up structures needed to add the param subtree and manage it */
  proto_tree *param_tree;
  int         offset;
  uint32_t    dcs;
  uint32_t    dcs_cg;           /* coding group */

  param_tree = proto_tree_add_subtree(tree, tvb,
    startOffset + 1, endOffset - (startOffset + 1),
    (*vals_hdr_PC[pindex].ett_p), NULL, cimd_vals_PC[pindex].strptr
  );

  proto_tree_add_item(param_tree, hf_cimd_pcode_indicator, tvb,
    startOffset + 1, CIMD_PC_LENGTH, ENC_ASCII);

  offset = startOffset + 1 + CIMD_PC_LENGTH + 1;
  dcs    = (uint32_t) strtoul(tvb_get_string_enc(wmem_packet_scope(), tvb, offset, endOffset - offset, ENC_ASCII), NULL, 10);
  proto_tree_add_uint(param_tree, (*vals_hdr_PC[pindex].hf_p), tvb, offset, endOffset - offset, dcs);

  dcs_cg = (dcs & 0xF0) >> 4;
  if (dcs_cg <= 0x07)
  {
     proto_tree_add_uint(param_tree, hf_cimd_dcs_coding_group_indicatorC0, tvb, offset, 1, dcs);
  }
  else
  {
     proto_tree_add_uint(param_tree, hf_cimd_dcs_coding_group_indicatorF0, tvb, offset, 1, dcs);
  }

  if (dcs_cg <= 0x07)
  {
    proto_tree_add_uint(param_tree, hf_cimd_dcs_compressed_indicator, tvb, offset, 1, dcs);
    proto_tree_add_uint(param_tree, hf_cimd_dcs_message_class_meaning_indicator, tvb, offset, 1, dcs);
    proto_tree_add_uint(param_tree, hf_cimd_dcs_character_set_indicator0C, tvb, offset, 1, dcs);

    if (dcs & 0x10)
    {
      proto_tree_add_uint(param_tree, hf_cimd_dcs_message_class_indicator, tvb, offset, 1, dcs);
    }
  }
  else if (dcs_cg >= 0x0C && dcs_cg <= 0x0E)
  {
    proto_tree_add_uint(param_tree, hf_cimd_dcs_indication_sense, tvb, offset, 1, dcs);
    proto_tree_add_uint(param_tree, hf_cimd_dcs_indication_type, tvb, offset, 1, dcs);
  }
  else if (dcs_cg == 0x0F)
  {
    proto_tree_add_uint(param_tree, hf_cimd_dcs_character_set_indicator04, tvb, offset, 1, dcs);
    proto_tree_add_uint(param_tree, hf_cimd_dcs_message_class_indicator, tvb, offset, 1, dcs);
  }
}

static void dissect_cimd_error_code( tvbuff_t *tvb, proto_tree *tree, int pindex, int startOffset, int endOffset )
{
  /* Same routine can be used to dissect CIMD Error,Status and Status Error Codes */
  proto_tree *param_tree;
  uint32_t err_code;

  param_tree = proto_tree_add_subtree(tree, tvb, startOffset + 1, endOffset - (startOffset + 1),
                                      (*vals_hdr_PC[pindex].ett_p), NULL, cimd_vals_PC[pindex].strptr);

  proto_tree_add_item(param_tree, hf_cimd_pcode_indicator, tvb, startOffset + 1, CIMD_PC_LENGTH, ENC_ASCII);

  err_code = (uint32_t) strtoul(tvb_get_string_enc(wmem_packet_scope(), tvb,
                                                  startOffset + 1 + CIMD_PC_LENGTH + 1, endOffset - (startOffset + 1 + CIMD_PC_LENGTH + 1), ENC_ASCII),
                               NULL, 10);
  proto_tree_add_uint(param_tree, (*vals_hdr_PC[pindex].hf_p), tvb, startOffset + 1 + CIMD_PC_LENGTH + 1, endOffset - (startOffset + 1 + CIMD_PC_LENGTH + 1), err_code);
}

static void
dissect_cimd_operation(tvbuff_t *tvb, proto_tree *tree, int etxp, uint16_t checksum, uint8_t last1,uint8_t OC, uint8_t PN)
{
  uint32_t    PC        = 0;    /* Parameter code */
  int         idx;
  int         offset    = 0;
  int         endOffset = 0;
  proto_item *cimd_item;
  proto_tree *cimd_tree;

    /* create display subtree for the protocol */
  cimd_item = proto_tree_add_item(tree, proto_cimd, tvb, 0, etxp + 1, ENC_NA);
  cimd_tree = proto_item_add_subtree(cimd_item, ett_cimd);
  proto_tree_add_uint(cimd_tree, hf_cimd_opcode_indicator, tvb, CIMD_OC_OFFSET, CIMD_OC_LENGTH, OC);
  proto_tree_add_uint(cimd_tree, hf_cimd_packet_number_indicator, tvb, CIMD_PN_OFFSET, CIMD_PN_LENGTH, PN);

  offset = CIMD_PN_OFFSET + CIMD_PN_LENGTH;
  while (offset < etxp && tvb_get_uint8(tvb, offset) == CIMD_DELIM)
  {
    endOffset = tvb_find_guint8(tvb, offset + 1, etxp, CIMD_DELIM);
    if (endOffset == -1)
      break;

    PC = (uint32_t) strtoul(tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 1, CIMD_PC_LENGTH, ENC_ASCII), NULL, 10);
    try_val_to_str_idx(PC, cimd_vals_PC, &idx);
    if (idx != -1 && tree)
    {
      (vals_hdr_PC[idx].diss)(tvb, cimd_tree, idx, offset, endOffset);
    }
    offset = endOffset;
  }

  if (last1 != CIMD_DELIM)
  {
    /* Checksum is present */
    proto_tree_add_uint(cimd_tree, hf_cimd_checksum_indicator, tvb, etxp - 2, 2, checksum);
  }
}

static int
dissect_cimd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  uint8_t  OC;                  /* Operation Code */
  uint8_t  PN;                  /* Packet number */
  uint16_t checksum        = 0; /* Checksum */
  uint16_t pkt_check       = 0;
  int      etxp            = 0; /* ETX position */
  int      offset          = 0;
  bool checksumIsValid = true;
  uint8_t  last1, last2, last3;

  etxp = tvb_find_guint8(tvb, CIMD_PN_OFFSET + CIMD_PN_LENGTH, -1, CIMD_ETX);
  if (etxp == -1) return 0;

  OC = (uint8_t)strtoul(tvb_get_string_enc(pinfo->pool, tvb, CIMD_OC_OFFSET, CIMD_OC_LENGTH, ENC_ASCII), NULL, 10);
  PN = (uint8_t)strtoul(tvb_get_string_enc(pinfo->pool, tvb, CIMD_PN_OFFSET, CIMD_PN_LENGTH, ENC_ASCII), NULL, 10);

  last1 = tvb_get_uint8(tvb, etxp - 1);
  last2 = tvb_get_uint8(tvb, etxp - 2);
  last3 = tvb_get_uint8(tvb, etxp - 3);

  if (last1 == CIMD_DELIM) {
    /* valid packet, CC is missing */
  } else if (last1 != CIMD_DELIM && last2 != CIMD_DELIM && last3 == CIMD_DELIM) {
    /* looks valid, it would be nice to check that last1 and last2 are HEXA */
    /* CC is present */
    checksum = (uint16_t)strtoul(tvb_get_string_enc(pinfo->pool, tvb, etxp - 2, 2, ENC_ASCII), NULL, 16);
    for (; offset < (etxp - 2); offset++)
    {
      pkt_check += tvb_get_uint8(tvb, offset);
      pkt_check &= 0xFF;
    }
    checksumIsValid = (checksum == pkt_check);
  } else {
    checksumIsValid = false;
  }

  /* Make entries in Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "CIMD");

  if (checksumIsValid)
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str(OC, vals_hdr_OC, "Unknown (%d)"));
  else
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s - %s", val_to_str(OC, vals_hdr_OC, "Unknown (%d)"), "invalid checksum");

  dissect_cimd_operation(tvb, tree, etxp, checksum, last1, OC, PN);
  return tvb_captured_length(tvb);
}

/**
 * A 'heuristic dissector' that attemtps to establish whether we have
 * a CIMD MSU here.
 */
static bool
dissect_cimd_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  int    etxp;
  uint8_t opcode = 0;            /* Operation code */

  if (tvb_captured_length(tvb) < CIMD_MIN_LENGTH)
    return false;

  if (tvb_get_uint8(tvb, 0) != CIMD_STX)
    return false;

  etxp = tvb_find_guint8(tvb, CIMD_OC_OFFSET, -1, CIMD_ETX);
  if (etxp == -1)
  { /* XXX - should we have an option to request reassembly? */
    return false;
  }

  /* Try getting the operation-code */
  opcode = (uint8_t)strtoul(tvb_get_string_enc(pinfo->pool, tvb, CIMD_OC_OFFSET, CIMD_OC_LENGTH, ENC_ASCII), NULL, 10);
  if (try_val_to_str(opcode, vals_hdr_OC) == NULL)
    return false;

  if (tvb_get_uint8(tvb, CIMD_OC_OFFSET + CIMD_OC_LENGTH) != CIMD_COLON)
    return false;

  if (tvb_get_uint8(tvb, CIMD_PN_OFFSET + CIMD_PN_LENGTH) != CIMD_DELIM)
    return false;

  /* Ok, looks like a valid packet, go dissect. */
  dissect_cimd(tvb, pinfo, tree, data);
  return true;
}

void
proto_register_cimd(void)
{
  static hf_register_info hf[] = {
    { &hf_cimd_opcode_indicator,
      { "Operation Code", "cimd.opcode",
        FT_UINT8, BASE_DEC, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_cimd_packet_number_indicator,
      { "Packet Number", "cimd.pnumber",
        FT_UINT8, BASE_DEC, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_cimd_pcode_indicator,
      { "Parameter Code", "cimd.pcode",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_cimd_checksum_indicator,
      { "Checksum", "cimd.chksum",
        FT_UINT8, BASE_HEX, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_cimd_dcs_coding_group_indicatorC0,
      { "DCS Coding Group", "cimd.dcs.cg",
        FT_UINT8, BASE_DEC, VALS(cimd_dcs_coding_groups), 0xC0,
        NULL, HFILL }
    },
    { &hf_cimd_dcs_coding_group_indicatorF0,
      { "DCS Coding Group", "cimd.dcs.cg",
        FT_UINT8, BASE_DEC, VALS(cimd_dcs_coding_groups), 0xF0,
        NULL, HFILL }
    },
    { &hf_cimd_dcs_compressed_indicator,
      { "DCS Compressed Flag", "cimd.dcs.cf",
        FT_UINT8, BASE_DEC, VALS(cimd_dcs_compressed), 0x20,
        NULL, HFILL }
    },
    { &hf_cimd_dcs_message_class_meaning_indicator,
      { "DCS Message Class Meaning", "cimd.dcs.mcm",
        FT_UINT8, BASE_DEC, VALS(cimd_dcs_message_class_meaning), 0x10,
        NULL, HFILL }
    },
    { &hf_cimd_dcs_message_class_indicator,
      { "DCS Message Class", "cimd.dcs.mc",
        FT_UINT8, BASE_DEC, VALS(cimd_dcs_message_class), 0x03,
        NULL, HFILL }
    },
    { &hf_cimd_dcs_character_set_indicator0C,
      { "DCS Character Set", "cimd.dcs.chs",
        FT_UINT8, BASE_DEC, VALS(cimd_dcs_character_set), 0x0C,
        NULL, HFILL }
    },
    { &hf_cimd_dcs_character_set_indicator04,
      { "DCS Character Set", "cimd.dcs.chs",
        FT_UINT8, BASE_DEC, VALS(cimd_dcs_character_set), 0x04,
        NULL, HFILL }
    },
    { &hf_cimd_dcs_indication_sense,
      { "DCS Indication Sense", "cimd.dcs.is",
        FT_UINT8, BASE_DEC, VALS(cimd_dcs_indication_sense), 0x04,
        NULL, HFILL }
    },
    { &hf_cimd_dcs_indication_type,
      { "DCS Indication Type", "cimd.dcs.it",
        FT_UINT8, BASE_DEC, VALS(cimd_dcs_indication_type), 0x03,
        NULL, HFILL }
    },
    { &hf_index[0],
      { "User Identity", "cimd.ui",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[1],
      { "Password", "cimd.passwd",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[2],
      { "Subaddress", "cimd.saddr",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[3],
      { "Window Size", "cimd.ws",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[4],
      { "Destination Address", "cimd.da",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[5],
      { "Originating Address", "cimd.oa",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[6],
      { "Originating IMSI", "cimd.oimsi",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[7],
      { "Alphanumeric Originating Address", "cimd.aoi",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[8],
      { "Originated Visited MSC Address", "cimd.ovma",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[9],
      { "Data Coding Scheme", "cimd.dcs",
        FT_UINT8, BASE_HEX, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[10],
      { "User Data Header", "cimd.udh",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[11],
      { "User Data", "cimd.ud",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[12],
      { "User Data Binary", "cimd.udb",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[13],
      { "More Messages To Send", "cimd.mms",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[14],
      { "Validity Period Relative", "cimd.vpr",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[15],
      { "Validity Period Absolute", "cimd.vpa",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[16],
      { "Protocol Identifier", "cimd.pi",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[17],
      { "First Delivery Time Relative", "cimd.fdtr",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[18],
      { "First Delivery Time Absolute", "cimd.fdta",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[19],
      { "Reply Path", "cimd.rpath",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[20],
      { "Status Report Request", "cimd.srr",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[21],
      { "Cancel Enabled", "cimd.ce",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[22],
      { "Cancel Mode", "cimd.cm",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[23],
      { "Service Center Time Stamp", "cimd.scts",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[24],
      { "Status Code", "cimd.stcode",
        FT_UINT8, BASE_DEC, VALS(cimd_status_code_vals), 0x00,
        NULL, HFILL }
    },
    { &hf_index[25],
      { "Status Error Code", "cimd.sterrcode",
        FT_UINT16, BASE_DEC|BASE_EXT_STRING, &cimd_status_error_vals_ext, 0x00,
        NULL, HFILL }
    },
    { &hf_index[26],
      { "Discharge Time", "cimd.dt",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[27],
      { "Tariff Class", "cimd.tclass",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[28],
      { "Service Description", "cimd.sdes",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[29],
      { "Message Count", "cimd.mcount",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[30],
      { "Priority", "cimd.priority",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[31],
      { "Delivery Request Mode", "cimd.drmode",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[32],
      { "Service Center Address", "cimd.scaddr",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[33],
      { "Get Parameter", "cimd.gpar",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[34],
      { "SMS Center Time", "cimd.smsct",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_index[35],
      { "Error Code Description", "cimd.errcode",
        FT_UINT16, BASE_DEC|BASE_EXT_STRING, &cimd_error_vals_ext, 0x00,
        NULL, HFILL }
    },
    { &hf_index[36],
      { "Error Text", "cimd.errtext",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }
    }
  };

  /* Setup protocol subtree array */
  int *ett[MAXPARAMSCOUNT + 1];
  int i;

  ett[0] = &ett_cimd;

  for(i=0;i<MAXPARAMSCOUNT;i++)
  {
    ett[i + 1]           = &(ett_index[i]);
    vals_hdr_PC[i].ett_p = &(ett_index[i]);
    vals_hdr_PC[i].hf_p  = &(hf_index[i]);
    vals_hdr_PC[i].diss  = cimd_pc_handles[i];
  };

  /* Register the protocol name and description */
  proto_cimd = proto_register_protocol("Computer Interface to Message Distribution", "CIMD", "cimd");
  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_cimd, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register the dissector */
  cimd_handle = register_dissector("cimd", dissect_cimd, proto_cimd);
}

void
proto_reg_handoff_cimd(void)
{
  /**
   * CIMD can be spoken on any port so, when not on a specific port, try this
   * one whenever TCP is spoken.
   */
  heur_dissector_add("tcp", dissect_cimd_heur, "CIMD over TCP", "cimd_tcp", proto_cimd, HEURISTIC_ENABLE);

  /**
   * Also register as one that can be selected by a TCP port number.
   */
  dissector_add_for_decode_as_with_preference("tcp.port", cimd_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
