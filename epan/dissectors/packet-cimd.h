/* packet-cimd.h
 *
 * Routines for Computer Interface to Message Distribution (CIMD) version 2 dissection
 *
 * Copyright : 2005 Viorel Suman <vsuman[AT]avmob.ro>, Lucian Piros <lpiros[AT]avmob.ro>
 *             In association with Avalanche Mobile BV, http://www.avmob.com
 *
 * $Id$
 *
 * Refer to the AUTHORS file or the AUTHORS section in the man page
 * for contacting the author(s) of this file.
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

#include <string.h>
#include <glib.h>

#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/prefs.h>
#include "packet-tcp.h"

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

#define CIMD_Login                    1
#define CIMD_LoginResp                51
#define CIMD_Logout                   2
#define CIMD_LogoutResp               52
#define CIMD_SubmitMessage            3
#define CIMD_SubmitMessageResp        53
#define CIMD_EnqMessageStatus         4
#define CIMD_EnqMessageStatusResp     54
#define CIMD_DeliveryRequest          5
#define CIMD_DeliveryRequestResp      55    
#define CIMD_CancelMessage            6
#define CIMD_CancelMessageResp        56
#define CIMD_SetMessage               8
#define CIMD_SetMessageResp           58
#define CIMD_GetMessage               9 
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

#define CIMD_UserIdentity           10
#define CIMD_Password               11
#define CIMD_Subaddress             12
#define CIMD_WindowSize             19
#define CIMD_DestinationAddress     21
#define CIMD_OriginatingAddress     23
#define CIMD_OriginatingImsi        26
#define CIMD_AlphaOriginatingAddr   27
#define CIMD_OriginatedVisitedMSCAd 28
#define CIMD_DataCodingScheme       30
#define CIMD_UserDataHeader         32
#define CIMD_UserData               33
#define CIMD_UserDataBinary         34
#define CIMD_MoreMessagesToSend     44
#define CIMD_ValidityPeriodRelative 50
#define CIMD_ValidityPeriodAbsolute 51
#define CIMD_ProtocolIdentifier     52
#define CIMD_FirstDeliveryTimeRel   53
#define CIMD_FirstDeliveryTimeAbs   54
#define CIMD_ReplyPath              55
#define CIMD_StatusReportRequest    56
#define CIMD_CancelEnabled          58
#define CIMD_CancelMode             59
#define CIMD_SCTimeStamp            60
#define CIMD_StatusCode             61
#define CIMD_StatusErrorCode        62
#define CIMD_DischargeTime          63
#define CIMD_TariffClass            64
#define CIMD_ServiceDescription     65
#define CIMD_MessageCount           66
#define CIMD_Priority               67
#define CIMD_DeliveryRequestMode    68
#define CIMD_SCAddress              69
#define CIMD_GetParameter           500
#define CIMD_SMSCTime               501
#define CIMD_ErrorCode              900
#define CIMD_ErrorText              901

#define MAXPARAMSCOUNT              37

typedef void (*cimd_odissect)(tvbuff_t *tvb, proto_tree *tree, gint etxp, guint16 checksum, guint8 last1,guint8 OC, guint8 PN);
                                    
typedef struct cimd_parameter_t cimd_parameter_t;

typedef void (*cimd_pdissect)(tvbuff_t *tvb, proto_tree *tree, gint pindex, gint startOffset, gint endOffset);

struct cimd_parameter_t {
  cimd_pdissect diss;
  gint *ett_p;
  gint *hf_p;
};

static void dissect_cimd_operation(tvbuff_t *tvb, proto_tree *tree, gint etxp, guint16 checksum, guint8 last1,guint8 OC, guint8 PN);
static void dissect_cimd_parameter(tvbuff_t *tvb, proto_tree *tree, gint pindex, gint startOffset, gint endOffset);
static void dissect_cimd_ud(tvbuff_t *tvb, proto_tree *tree, gint pindex, gint startOffset, gint endOffset);
static void dissect_cimd_dcs(tvbuff_t *tvb, proto_tree *tree, gint pindex, gint startOffset, gint endOffset);

