/* packet-pres.h
*
* Routine to dissect ISO 8823 OSI Presentation Protocol packets
*
* $Id: packet-pres.h,v 1.1 2004/01/13 02:10:25 guy Exp $
*
* Yuriy Sidelnikov <YSidelnikov@hotmail.com>
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
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

#define PROTO_STRING_PRES "ISO 8823 OSI Presentation Protocol"
#define PROTO_STRING_PRES_INFO "ISO 8823 OSI Presentation Protocol."

/*     type of PPDU   */

#define PRES_CONNECTION_REQUEST_CONFIRM		0x31
#define PRES_CONNECTION_REFUSE				0x30

/* asn.1 definitions   */
#define	ASN1_CLASS_UNIVERSAL				0x00
#define	ASN1_CLASS_APPLICATION				0x40
#define	ASN1_CLASS_CONTEXT_SPECIFIC			0x80
#define	ASN1_CLASS_Private					0xc0
#define	ASN1_CLASS_PC						0x20

#define	INTEGER_ITEM						0x01
#define	BOOLEAN_ITEM						0x01

/*       type of parameters */
#define MODE_SELECTOR						0
#define SET_TOP								1
#define SEQUENCE_TOP						2


#define SEQUENCE							0x30

/*    sequence top   */
#define TAG_00									0
#define TAG_01									1

enum
{
PROTOCOL_VERSION,
CALLING_PRESENTATION_SELECTOR,
CALLED_PRESENTATION_SELECTOR,
RESPONDING_PRESENTATION_SELECTOR,
PRESENTATION_CONTEXT_DEFINITION_LIST,
PRESENTATION_CONTEXT_DEFINITION_RESULT_LIST,
DEFAULT_CONTEXT_NAME,
DEFAULT_CONTEXT_RESULT,
PRESENTATION_REQUIREMENTS,
USER_SESSION_REQUIREMENTS,
PROVIDER_REASON
};
/*   definition list **/
#define   PRESENTATION_CONTEXT_IDENTIFIER		 2
#define   ABSTRACT_SYNTAX_NAME					 6
#define   TRANSFER_SYNTAX_NAMES					 0x30
/*   result    list */
#define   PRESENTATION_RESULT								0x80
#define   PRESENTATION_RESULT_TRANSFER_SYNTAX_NAME			0x81
#define   PRESENTATION_RESULT_INTEGER						0x82

/*     result  values  */
#define   PRESENTATION_RESULT_ACCEPTANCE		 0
#define   PRESENTATION_RESULT_USER_REJECTION	 1
#define   PRESENTATION_RESULT_PROVIDER_REJECTION 2

/* provider reason  */
enum
{
REASON_NOT_SPECIFIED,
TEMPORARY_CONGESTION,
LOCAL_LIMIT_EXCEEDED,
CALLED_PRESENTATION_ADDRESS_UNKNOWN,
PROTOCOL_VERSION_NOT_SUPPORTED,
DEFAULT_CONTEXT_NOT_SUPPORTED,
USER_DATA_NOT_READABLE,
NO_PSAP_AVAILABLE
};
/*  user data   */
#define   SIMPLY_ENCODED_DATA									0x60
#define   FULLY_ENCODED_DATA									0x61

/*  PDV    */
#define   SINGLE_ASN1_TYPE										0xa0
#define   OCTET_ALIGNED											0xa1
#define   ARBITRARY												0xa2

/* provider reasons */
enum
{
PR_REASON_NOT_SPECIFIED,
UNRECOGNIZED_PDU,
UNEXPECTED_PDU,
UNEXPECTED_SESSION_SERVICE_PRIMITIVE,
UNRECOGNIZED_PPDU_PARAMETER,
UNEXPECTED_PPDU_PARAMETER,
INVALID_PPDU_PARAMETER_VALUE
};
/*  event identifier    */
enum
{
REASON_CP_PPDU,
REASON_CPA_PPDU,
REASON_CPR_PPDU,
REASON_ARU_PPDU,
REASON_ARP_PPDU,
REASON_AC_PPDU,
REASON_ACA_PPDU,
REASON_TD_PPDU,
REASON_TTD_PPDU,
REASON_TE_PPDU,
REASON_TC_PPDU,
REASON_TCC_PPDU,
REASON_RS_PPDU,
REASON_RSA_PPDU,
S_RELEASE_INDICATION,
S_RELEASE_CONFIRM,
S_TOKEN_GIVE_INDICATION,
S_TOKEN_PLEASE_INDICATION,
S_CONTROL_GIVE_INDICATION,
S_SYNC_MINOR_INDICATION,
S_SYNC_MINOR_CONFIRM,
S_SYNC_MAJOR_INDICATION,
S_SYNC_MAJOR_CONFIRM,
S_P_EXCEPTION_REPORT_INDICATION,
S_U_EXCEPTION_REPORT_INDICATION,
S_ACTIVITY_START_INDICATION,
S_ACTIVITY_RESUME_INDICATION,
S_ACTIVITY_INTERRUPT_INDICATION,
S_ACTIVITY_INTERRUPT_CONFIRM,
S_ACTIVITY_DISCARD_INDICATION,
S_ACTIVITY_DISCARD_CONFIRM,
S_ACTIVITY_END_INDICATION,
S_ACTIVITY_END_CONFIRM
};

/*   flags   */
#define	PRES_PROTOCOL_VERGION					0x0080

#define	PRES_CONTEXT_MANAGEMENT					0x0080
#define	PRES_RESTORATION						0x0040

#define	ACSE_PRESENTATION_CONTEXT_IDENTIFIER				3


#define			MAXSTRING					256
#define			UNKNOWN_SES_PDU_TYPE         -1

#define			ABORT_REASON_LEN			3



