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

#include <glib.h>
#include <stdlib.h>

#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/wmem/wmem.h>

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

typedef void (*cimd_pdissect)(tvbuff_t *tvb, proto_tree *tree, gint pindex, gint startOffset, gint endOffset);

struct cimd_parameter_t {
  cimd_pdissect  diss;
  gint          *ett_p;
  gint          *hf_p;
};

void proto_register_cimd(void);
void proto_reg_handoff_cimd(void);
static void dissect_cimd_parameter(tvbuff_t *tvb, proto_tree *tree, gint pindex, gint startOffset, gint endOffset);
static void dissect_cimd_ud(tvbuff_t *tvb, proto_tree *tree, gint pindex, gint startOffset, gint endOffset);
static void dissect_cimd_dcs(tvbuff_t *tvb, proto_tree *tree, gint pindex, gint startOffset, gint endOffset);
static void dissect_cimd_error_code(tvbuff_t *tvb, proto_tree *tree, gint pindex, gint startOffset, gint endOffset);

static int proto_cimd = -1;
/* Initialize the subtree pointers */
static gint ett_cimd = -1;

/* Initialize the protocol and registered fields */
static int hf_cimd_opcode_indicator = -1;
static int hf_cimd_packet_number_indicator = -1;
static int hf_cimd_checksum_indicator = -1;
static int hf_cimd_pcode_indicator = -1;

static int hf_cimd_dcs_coding_group_indicatorC0 = -1;
static int hf_cimd_dcs_coding_group_indicatorF0 = -1;
static int hf_cimd_dcs_compressed_indicator = -1;
static int hf_cimd_dcs_message_class_meaning_indicator = -1;
static int hf_cimd_dcs_message_class_indicator = -1;
static int hf_cimd_dcs_character_set_indicator0C = -1;
static int hf_cimd_dcs_character_set_indicator04 = -1;
static int hf_cimd_dcs_indication_sense = -1;
static int hf_cimd_dcs_indication_type = -1;

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
static gint ett_index[MAXPARAMSCOUNT];
static gint hf_index[MAXPARAMSCOUNT];

static void dissect_cimd_parameter(tvbuff_t *tvb, proto_tree *tree, gint pindex, gint startOffset, gint endOffset)
{
  /* Set up structures needed to add the param subtree and manage it */
  proto_item *param_item;
  proto_tree *param_tree;

  param_item = proto_tree_add_text(tree, tvb, startOffset + 1, endOffset - (startOffset + 1),
                                   "%s", cimd_vals_PC[pindex].strptr);
  param_tree = proto_item_add_subtree(param_item, (*vals_hdr_PC[pindex].ett_p));

  proto_tree_add_item(param_tree, hf_cimd_pcode_indicator, tvb,
    startOffset + 1, CIMD_PC_LENGTH, ENC_ASCII|ENC_NA);
  proto_tree_add_item(param_tree, (*vals_hdr_PC[pindex].hf_p), tvb,
    startOffset + 1 + CIMD_PC_LENGTH + 1, endOffset - (startOffset + 1 + CIMD_PC_LENGTH + 1), ENC_ASCII|ENC_NA);
}

static void dissect_cimd_ud(tvbuff_t *tvb, proto_tree *tree, gint pindex, gint startOffset, gint endOffset)
{
  /* Set up structures needed to add the param subtree and manage it */
  proto_item *param_item;
  proto_tree *param_tree;

  gchar *payloadText, *tmpBuffer, *tmpBuffer1;
  int    loop,i,poz, bufPoz = 0, bufPoz1 = 0, size, size1, resch;
  gint   g_offset, g_size;
  gchar  token[4];
  gchar  ch;
  static const char* mapping[128]  = {
    "_Oa" , "_L-", ""    , "_Y-", "_e`", "_e'", "_u`", "_i`", "_o`", "_C,",        /*10*/
    ""    , "_O/", "_o/" , ""   , "_A*", "_a*", "_gd", "_--", "_gf", "_gg", "_gl", /*21*/
    "_go" , "_gp", "_gi" , "_gs", "_gt", "_gx", "_XX", "_AE", "_ae", "_ss", "_E'", /*32*/
    ""    , ""   , "_qq" , ""   , "_ox", ""   , ""   , ""   , ""   , ""   , ""   , ""    , ""    , ""   , "", "",
    ""    , ""   , ""    , ""   , ""   , ""   , ""   , ""   , ""   , ""   , ""   , ""    , ""    , ""   , "", "",
    "_!!" , ""   , ""    , ""   , ""   , ""   , ""   , ""   , ""   , ""   , ""   , ""    , ""    , ""   , "", "",
    ""    , ""   , ""    , ""   , ""   , ""   , ""   , ""   , ""   , ""   , ""   , "_A\"", "_O\"", "_N~",
    "_U\"", "_so", "_??" , ""   , ""   , ""   , ""   , ""   , ""   , ""   , ""   , ""    , ""    , ""   ,
    ""    , ""   , ""    , ""   , ""   , ""   , ""   , ""   , ""   , ""   , ""   , ""    , ""    , ""   , "", "_a\"",
    "_o\"", "_n~", "_n\"","_a`"
  };

  param_item = proto_tree_add_text(tree, tvb,
    startOffset + 1, endOffset - (startOffset + 1),
    "%s", cimd_vals_PC[pindex].strptr
  );
  param_tree = proto_item_add_subtree(param_item, (*vals_hdr_PC[pindex].ett_p));
  proto_tree_add_item(param_tree, hf_cimd_pcode_indicator, tvb,
    startOffset + 1, CIMD_PC_LENGTH, ENC_ASCII|ENC_NA);

  g_offset = startOffset + 1 + CIMD_PC_LENGTH + 1;
  g_size   = endOffset - g_offset;

  payloadText = tvb_format_text(tvb, g_offset, g_size);
  size = (int)strlen(payloadText);
  tmpBuffer = (gchar*)wmem_alloc(wmem_packet_scope(), size+1);
  for (loop = 0; loop < size; loop++)
  {
    if (payloadText[loop] == '_')
    {
      if (loop < size - 2)
      {
        token[0] = payloadText[loop++];
        token[1] = payloadText[loop++];
        token[2] = payloadText[loop];
        token[3] = '\0';
        poz = -1;
        for (i = 0; i < 128; i++)
        {
          if (strcmp(token, mapping[i]) == 0)
          {
            poz = i;
            break;
          }
        }
        if (poz > 0)
        {
          tmpBuffer[bufPoz++] = poz;
        }
        else
        {
          tmpBuffer[bufPoz++] = payloadText[loop-2];
          tmpBuffer[bufPoz++] = payloadText[loop-1];
          tmpBuffer[bufPoz++] = payloadText[loop];
        }
      }
      else
      {
        if (loop < size) tmpBuffer[bufPoz++] = payloadText[loop++];
        if (loop < size) tmpBuffer[bufPoz++] = payloadText[loop++];
        if (loop < size) tmpBuffer[bufPoz++] = payloadText[loop++];
      }
    }
    else
    {
      tmpBuffer[bufPoz++] = payloadText[loop];
    }
  }
  tmpBuffer[bufPoz] = '\0';

  size1 = (int)strlen(tmpBuffer);
  tmpBuffer1 = (gchar*)wmem_alloc(wmem_packet_scope(), size1+1);
  for (loop=0; loop<size1; loop++)
  {
    ch = tmpBuffer[loop];
    switch ((gint)ch)
    {
    case 0x40: resch = 0x0040; break;
    case 0x01: resch = 0x00A3; break;
    case 0x02: resch = 0x0024; break;
    case 0x03: resch = 0x00A5; break;
    case 0x04: resch = 0x00E8; break;
    case 0x05: resch = 0x00E9; break;
    case 0x06: resch = 0x00F9; break;
    case 0x07: resch = 0x00EC; break;
    case 0x08: resch = 0x00F2; break;
    case 0x09: resch = 0x00E7; break;
    case 0x0B: resch = 0x00D8; break;
    case 0x0C: resch = 0x00F8; break;
    case 0x0E: resch = 0x00C5; break;
    case 0x0F: resch = 0x00E5; break;
    case 0x11: resch = 0x005F; break;
/*  case 0x1B14: resch = 0x005E; break; */
/*  case 0x1B28: resch = 0x007B; break; */
/*  case 0x1B29: resch = 0x007D; break; */
/*  case 0x1B2F: resch = 0x005C; break; */
/*  case 0x1B3C: resch = 0x005B; break; */
/*  case 0x1B3D: resch = 0x007E; break; */
/*  case 0x1B3E: resch = 0x005D; break; */
/*  case 0x1B40: resch = 0x007C; break; */
    case 0x1C: resch = 0x00C6; break;
    case 0x1D: resch = 0x00E6; break;
    case 0x1E: resch = 0x00DF; break;
    case 0x1F: resch = 0x00C9; break;
    case 0x20: resch = 0x0020; break;
    case 0x21: resch = 0x0021; break;
    case 0x22: resch = 0x0022; break;
    case 0x23: resch = 0x0023; break;
    case 0xA4: resch = 0x00A4; break;
    case 0x25: resch = 0x0025; break;
    case 0x26: resch = 0x0026; break;
    case 0x27: resch = 0x0027; break;
    case 0x28: resch = 0x0028; break;
    case 0x29: resch = 0x0029; break;
    case 0x2A: resch = 0x002A; break;
    case 0x2B: resch = 0x002B; break;
    case 0x2C: resch = 0x002C; break;
    case 0x2D: resch = 0x002D; break;
    case 0x2E: resch = 0x002E; break;
    case 0x2F: resch = 0x002F; break;
    case 0x30: resch = 0x0030; break;
    case 0x31: resch = 0x0031; break;
    case 0x32: resch = 0x0032; break;
    case 0x33: resch = 0x0033; break;
    case 0x34: resch = 0x0034; break;
    case 0x35: resch = 0x0035; break;
    case 0x36: resch = 0x0036; break;
    case 0x37: resch = 0x0037; break;
    case 0x38: resch = 0x0038; break;
    case 0x39: resch = 0x0039; break;
    case 0x3A: resch = 0x003A; break;
    case 0x3B: resch = 0x003B; break;
    case 0x3C: resch = 0x003C; break;
    case 0x3D: resch = 0x003D; break;
    case 0x3E: resch = 0x003E; break;
    case 0x3F: resch = 0x003F; break;
/*  case 0x40: resch = 0x00A1; break; */
    case 0x41: resch = 0x0041; break;
    case 0x42: resch = 0x0042; break;
/*  case 0x42: resch = 0x0392; break; */
    case 0x43: resch = 0x0043; break;
    case 0x44: resch = 0x0044; break;
    case 0x45: resch = 0x0045; break;
    case 0x46: resch = 0x0046; break;
    case 0x47: resch = 0x0047; break;
    case 0x48: resch = 0x0048; break;
    case 0x49: resch = 0x0049; break;
    case 0x4A: resch = 0x004A; break;
    case 0x4B: resch = 0x004B; break;
    case 0x4C: resch = 0x004C; break;
    case 0x4D: resch = 0x004D; break;
    case 0x4E: resch = 0x004E; break;
    case 0x4F: resch = 0x004F; break;
    case 0x50: resch = 0x0050; break;
    case 0x51: resch = 0x0051; break;
    case 0x52: resch = 0x0052; break;
    case 0x53: resch = 0x0053; break;
    case 0x54: resch = 0x0054; break;
    case 0x55: resch = 0x0055; break;
    case 0x56: resch = 0x0056; break;
    case 0x57: resch = 0x0057; break;
    case 0x58: resch = 0x0058; break;
    case 0x59: resch = 0x0059; break;
    case 0x5A: resch = 0x005A; break;
    case 0x5B: resch = 0x00C4; break;
    case 0x5C: resch = 0x00D6; break;
    case 0x5D: resch = 0x00D1; break;
    case 0x5E: resch = 0x00DC; break;
    case 0x5F: resch = 0x00A7; break;
    case 0x60: resch = 0x00BF; break;
    case 0x61: resch = 0x0061; break;
    case 0x62: resch = 0x0062; break;
    case 0x63: resch = 0x0063; break;
    case 0x64: resch = 0x0064; break;
    case 0x65: resch = 0x0065; break;
    case 0x66: resch = 0x0066; break;
    case 0x67: resch = 0x0067; break;
    case 0x68: resch = 0x0068; break;
    case 0x69: resch = 0x0069; break;
    case 0x6A: resch = 0x006A; break;
    case 0x6B: resch = 0x006B; break;
    case 0x6C: resch = 0x006C; break;
    case 0x6D: resch = 0x006D; break;
    case 0x6E: resch = 0x006E; break;
    case 0x6F: resch = 0x006F; break;
    case 0x70: resch = 0x0070; break;
    case 0x71: resch = 0x0071; break;
    case 0x72: resch = 0x0072; break;
    case 0x73: resch = 0x0073; break;
    case 0x74: resch = 0x0074; break;
    case 0x75: resch = 0x0075; break;
    case 0x76: resch = 0x0076; break;
    case 0x77: resch = 0x0077; break;
    case 0x78: resch = 0x0078; break;
    case 0x79: resch = 0x0079; break;
    case 0x7A: resch = 0x007A; break;
    case 0x7B: resch = 0x00E4; break;
    case 0x7C: resch = 0x00F6; break;
    case 0x7D: resch = 0x00F1; break;
    case 0x7F: resch = 0x00E0; break;
    default:resch = ch; break;
    }
    tmpBuffer1[bufPoz1++] = (gchar)resch;
  }

  tmpBuffer1[bufPoz1] = '\0';
  proto_tree_add_string(param_tree, (*vals_hdr_PC[pindex].hf_p), tvb, g_offset, g_size, tmpBuffer1);
}

static void dissect_cimd_dcs(tvbuff_t *tvb, proto_tree *tree, gint pindex, gint startOffset, gint endOffset)
{
  /* Set up structures needed to add the param subtree and manage it */
  proto_item *param_item;
  proto_tree *param_tree;
  gint        offset;
  guint32     dcs;
  guint32     dcs_cg;           /* coding group */

  param_item = proto_tree_add_text(tree, tvb,
    startOffset + 1, endOffset - (startOffset + 1),
    "%s", cimd_vals_PC[pindex].strptr
  );
  param_tree = proto_item_add_subtree(param_item, (*vals_hdr_PC[pindex].ett_p));

  proto_tree_add_item(param_tree, hf_cimd_pcode_indicator, tvb,
    startOffset + 1, CIMD_PC_LENGTH, ENC_ASCII|ENC_NA);

  offset = startOffset + 1 + CIMD_PC_LENGTH + 1;
  dcs    = (guint32) strtoul(tvb_get_string_enc(wmem_packet_scope(), tvb, offset, endOffset - offset, ENC_ASCII), NULL, 10);
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

static void dissect_cimd_error_code( tvbuff_t *tvb, proto_tree *tree, gint pindex, gint startOffset, gint endOffset )
{
    /* Same routine can be used to dissect CIMD Error,Status and Status Error Codes */
    proto_item *param_item;
    proto_tree *param_tree;
    guint32 err_code;

    param_item = proto_tree_add_text(tree, tvb, startOffset + 1, endOffset - (startOffset + 1),
                                     "%s", cimd_vals_PC[pindex].strptr);
    param_tree = proto_item_add_subtree(param_item, (*vals_hdr_PC[pindex].ett_p));

    proto_tree_add_item(param_tree, hf_cimd_pcode_indicator, tvb, startOffset + 1, CIMD_PC_LENGTH, ENC_ASCII|ENC_NA);

    err_code = (guint32) strtoul(tvb_get_string_enc(wmem_packet_scope(), tvb,
                                       startOffset + 1 + CIMD_PC_LENGTH + 1, endOffset - (startOffset + 1 + CIMD_PC_LENGTH + 1), ENC_ASCII),
                                       NULL, 10);
    proto_tree_add_uint(param_tree, (*vals_hdr_PC[pindex].hf_p), tvb, startOffset + 1 + CIMD_PC_LENGTH + 1, endOffset - (startOffset + 1 + CIMD_PC_LENGTH + 1), err_code);
}

static void
dissect_cimd_operation(tvbuff_t *tvb, proto_tree *tree, gint etxp, guint16 checksum, guint8 last1,guint8 OC, guint8 PN)
{
  guint32     PC        = 0;    /* Parameter code */
  gint        idx;
  gint        offset    = 0;
  gint        endOffset = 0;
  proto_item *cimd_item;
  proto_tree *cimd_tree;

    /* create display subtree for the protocol */
  cimd_item = proto_tree_add_item(tree, proto_cimd, tvb, 0, etxp + 1, ENC_NA);
  cimd_tree = proto_item_add_subtree(cimd_item, ett_cimd);
  proto_tree_add_uint(cimd_tree, hf_cimd_opcode_indicator, tvb, CIMD_OC_OFFSET, CIMD_OC_LENGTH, OC);
  proto_tree_add_uint(cimd_tree, hf_cimd_packet_number_indicator, tvb, CIMD_PN_OFFSET, CIMD_PN_LENGTH, PN);

  offset = CIMD_PN_OFFSET + CIMD_PN_LENGTH;
  while (offset < etxp && tvb_get_guint8(tvb, offset) == CIMD_DELIM)
  {
    endOffset = tvb_find_guint8(tvb, offset + 1, etxp, CIMD_DELIM);
    if (endOffset == -1)
      break;

    PC = (guint32) strtoul(tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 1, CIMD_PC_LENGTH, ENC_ASCII), NULL, 10);
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

static void
dissect_cimd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint8   OC;                  /* Operation Code */
  guint8   PN;                  /* Packet number */
  guint16  checksum        = 0; /* Checksum */
  guint16  pkt_check       = 0;
  gint     etxp            = 0; /* ETX position */
  gint     offset          = 0;
  gboolean checksumIsValid = TRUE;
  guint8   last1, last2, last3;

  etxp = tvb_find_guint8(tvb, CIMD_PN_OFFSET + CIMD_PN_LENGTH, -1, CIMD_ETX);
  if (etxp == -1) return;

  OC = (guint8)strtoul(tvb_get_string_enc(wmem_packet_scope(), tvb, CIMD_OC_OFFSET, CIMD_OC_LENGTH, ENC_ASCII), NULL, 10);
  PN = (guint8)strtoul(tvb_get_string_enc(wmem_packet_scope(), tvb, CIMD_PN_OFFSET, CIMD_PN_LENGTH, ENC_ASCII), NULL, 10);

  last1 = tvb_get_guint8(tvb, etxp - 1);
  last2 = tvb_get_guint8(tvb, etxp - 2);
  last3 = tvb_get_guint8(tvb, etxp - 3);

  if (last1 == CIMD_DELIM) {
    /* valid packet, CC is missing */
  } else if (last1 != CIMD_DELIM && last2 != CIMD_DELIM && last3 == CIMD_DELIM) {
    /* looks valid, it would be nice to check that last1 and last2 are HEXA */
    /* CC is present */
    checksum = (guint16)strtoul(tvb_get_string_enc(wmem_packet_scope(), tvb, etxp - 2, 2, ENC_ASCII), NULL, 16);
    for (; offset < (etxp - 2); offset++)
    {
      pkt_check += tvb_get_guint8(tvb, offset);
      pkt_check &= 0xFF;
    }
    checksumIsValid = (checksum == pkt_check);
  } else {
    checksumIsValid = FALSE;
  }

  /* Make entries in Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "CIMD");

  if (checksumIsValid)
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str(OC, vals_hdr_OC, "Unknown (%d)"));
  else
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s - %s", val_to_str(OC, vals_hdr_OC, "Unknown (%d)"), "invalid checksum");

  dissect_cimd_operation(tvb, tree, etxp, checksum, last1, OC, PN);
}

/**
 * A 'heuristic dissector' that attemtps to establish whether we have
 * a CIMD MSU here.
 */
static gboolean
dissect_cimd_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  int    etxp;
  guint8 opcode = 0;            /* Operation code */

  if (tvb_length(tvb) < CIMD_MIN_LENGTH)
    return FALSE;

  if (tvb_get_guint8(tvb, 0) != CIMD_STX)
    return FALSE;

  etxp = tvb_find_guint8(tvb, CIMD_OC_OFFSET, -1, CIMD_ETX);
  if (etxp == -1)
  { /* XXX - should we have an option to request reassembly? */
    return FALSE;
  }

  /* Try getting the operation-code */
  opcode = (guint8)strtoul(tvb_get_string_enc(wmem_packet_scope(), tvb, CIMD_OC_OFFSET, CIMD_OC_LENGTH, ENC_ASCII), NULL, 10);
  if (try_val_to_str(opcode, vals_hdr_OC) == NULL)
    return FALSE;

  if (tvb_get_guint8(tvb, CIMD_OC_OFFSET + CIMD_OC_LENGTH) != CIMD_COLON)
    return FALSE;

  if (tvb_get_guint8(tvb, CIMD_PN_OFFSET + CIMD_PN_LENGTH) != CIMD_DELIM)
    return FALSE;

  /* Ok, looks like a valid packet, go dissect. */
  dissect_cimd(tvb, pinfo, tree);
  return TRUE;
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
  gint *ett[MAXPARAMSCOUNT + 1];
  int i;

  ett[0] = &ett_cimd;

  for(i=0;i<MAXPARAMSCOUNT;i++)
  {
    ett_index[i]         = -1;
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
}

void
proto_reg_handoff_cimd(void)
{
  dissector_handle_t cimd_handle;

  /**
   * CIMD can be spoken on any port so, when not on a specific port, try this
   * one whenever TCP is spoken.
   */
  heur_dissector_add("tcp", dissect_cimd_heur, proto_cimd);

  /**
   * Also register as one that can be selected by a TCP port number.
   */
  cimd_handle = create_dissector_handle(dissect_cimd, proto_cimd);
  dissector_add_for_decode_as("tcp.port", cimd_handle);
}
