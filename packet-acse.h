/* packet-acse.h
*
* Routine to dissect OSI ISO/IEC 10035-1 ACSE Protocol packets
*
* $Id: packet-acse.h,v 1.1 2004/01/23 10:15:37 guy Exp $
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

#define PROTO_STRING_ACSE "OSI ISO/IEC 10035-1 ACSE Protocol"
#define PROTO_STRING_ACSE_INFO "OSI ISO/IEC 10035-1 ACSE Protocol"

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
ACSE_AARQ = 0x60,
ACSE_AARE,
ACSE_RLRQ,
ACSE_RLRE,
ACSE_ABRT
};


enum
{
PROTOCOL_VERSION,
APPLICATION_CONTEXT_NAME,
CALLED_AP_TITLE,
CALLED_AE_QUALIFIER,
CALLED_AP_INVOKATION_ID,
CALLED_AE_INVOKATION_ID,
CALLING_AP_TITLE,
CALLING_AE_QUALIFIER,
CALLING_AP_INVOKATION_ID,
CALLING_AE_INVOKATION_ID,
};

#define		IMPLEMENTATION_INFORMATION				29
#define		USER_INFORMATION						30
#define		ACSE_EXTERNAL							8

enum
{
PROTOCOL_VERSION_2,
APPLICATION_CONTEXT_NAME_2,
ACSE_RESULT,
ACSE_RESULT_SOURCE_DIAGNOSTIC,
RESPONDING_AP_TITLE,
RESPONDING_AE_QUALIFIER,
RESPONDING_AP_INVOKATION_ID,
RESPONDING_AE_INVOKATION_ID,
};

enum
{
ACSE_NULL,
ACSE_NO_REASON_GIVEN,
ACSE_APPLICATION_CONTEXT_NAME_NOT_SUPPORTED,
ACSE_CALLING_AP_TITLE_NOT_RECOGNIZED,
ACSE_CALLING_AP_INVOKATION_IDENTIFIER_NOT_RECOGNIZED,
ACSE_CALLING_AE_QUALIFIER_NOT_RECOGNIZED,
ACSE_CALLING_AE_INVOKATION_IDENTIFIER_NOT_RECOGNIZED,
ACSE_CALLED_AP_TITLE_NOT_RECOGNIZED,
ACSE_CALLED_AP_INVOKATION_IDENTIFIER_NOT_RECOGNIZED,
ACSE_CALLED_AE_QUALIFIER_NOT_RECOGNIZED,
ACSE_CALLED_AE_INVOKATION_IDENTIFIER_NOT_RECOGNIZED,
};

#define		ACSE_NO_COMMON_ACSE_VERSION			2


#define			ACSE_SERVICE_USER				1
#define			ACSE_SERVICE_PROVIDER			2
#define			ACSE_EXTERNAL_USER				8

////////////////////////////////////////////////////
//enum
//{
//PROTOCOL_VERSION_1,
//CALLING_PRESENTATION_SELECTOR,
//CALLED_PRESENTATION_SELECTOR,
//RESPONDING_PRESENTATION_SELECTOR,
//PRESENTATION_CONTEXT_DEFINITION_LIST,
//PRESENTATION_CONTEXT_DEFINITION_RESULT_LIST,
//DEFAULT_CONTEXT_NAME,
//DEFAULT_CONTEXT_RESULT,
//PRESENTATION_REQUIREMENTS,
//USER_SESSION_REQUIREMENTS,
//PROVIDER_REASON
//};
/////////////////////////////////////////////////






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

enum
{
RRR_NORMAL,
RRR_URGENT,
RRR_USER_DEFINED,
};
enum
{
RRPR_NORMAL,
RRPR_URGENT,
RRPR_USER_DEFINED
};
enum
{
ABRT_ACSE_SERVICE_USER,
ABRT_ACSE_SERVICE_PROVIDER,
};
/*  user data   */
#define   SIMPLY_ENCODED_DATA									0x60
#define   FULLY_ENCODED_DATA									0x61

/*  PDV    */
#define   SINGLE_ASN1_TYPE										0xa0
#define   OCTET_ALIGNED											0xa1
#define   ARBITRARY												0xa2



#define	ACSE_PROTOCOL_VERGION					0x0080
#define			MAXSTRING					256
#define			ABORT_REASON_LEN			3


#define			FTAM_APP					1
#define			CMIP_APP					2






