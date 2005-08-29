/* packet-ses.h
*
* Routine to dissect ISO 8327-1 OSI Session Protocol packets
*
* $Id$
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

#define PROTO_STRING_SES "ISO 8327-1 OSI Session Protocol"
#define PROTO_STRING_SES_INFO "ISO 8327-1 OSI Session Protocol."
/*
* Dissect ses-encapsulated data in a TCP stream.
*/

/* session parms */
#define  SES_EXT_CONT		0x01

/* protocol versions  */
#define  PROTOCOL_VERSION_1	0x01
#define  PROTOCOL_VERSION_2	0x02

/* enclosure item */
#define BEGINNING_SPDU		0x01
#define END_SPDU		0x02

#define DATA_TOKEN				0x01
#define RELEASE_TOKEN				0x40
#define SYNCHRONIZE_MINOR_TOKEN			0x04
#define MAJOR_ACTIVITY_TOKEN			0x10

/* session user req  flag   */
#define HALF_DUPLEX_FUNCTION_UNIT		0x0001
#define DUPLEX_FUNCTION_UNIT			0x0002
#define EXPEDITED_DATA_FUNCTION_UNIT		0x0004
#define MINOR_SYNCHRONIZE_FUNCTION_UNIT		0x0008
#define MAJOR_SYNCHRONIZE_FUNCTION_UNIT		0x0010
#define RESYNCHRONIZE_FUNCTION_UNIT		0x0020
#define ACTIVITY_MANAGEMENT_FUNCTION_UNIT	0x0040
#define NEGOTIATED_RELEASE_FUNCTION_UNIT	0x0080
#define CAPABILITY_DATA_FUNCTION_UNIT		0x0100
#define EXCEPTION_FUNCTION_UNIT			0x0200
#define TYPED_DATA_FUNCTION_UNIT		0x0400
#define SYMMETRIC_SYNCHRONIZE_FUNCTION_UNIT	0x0800
#define DATA_SEPARATION_FUNCTION_UNIT		0x1000

#define SES_EXCEPTION_REPORT			0x2000
/*define SES_EXCEPTION_REPORT			0    */
#define SES_DATA_TRANSFER			1
#define SES_GIVE_TOKENS				1
#define SES_PLEASE_TOKENS			2
#define SES_EXPEDITED				5
#define SES_PREPARE				7
#define SES_NOT_FINISHED			8
#define SES_FINISH				9
#define SES_DISCONNECT				10
#define SES_REFUSE				12
#define SES_CONNECTION_REQUEST			13
#define SES_CONNECTION_ACCEPT			14
#define SES_CONNECTION_DATA_OVERFLOW		15
#define SES_OVERFLOW_ACCEPT			16
#define SES_GIVE_TOKENS_CONFIRM			21
#define SES_GIVE_TOKENS_ACK			22
#define SES_ABORT				25
#define SES_ABORT_ACCEPT			26
/*#define SES_ACTIVITY_INTERRUPT		25
#define SES_ACTIVITY_INTERRUPT_ACK		26  */
#define SES_ACTIVITY_RESUME			29
#define SES_TYPED_DATA				33
#define SES_RESYNCHRONIZE_ACK			34
#define SES_MAJOR_SYNC_POINT			41
/*#define SES_MAJOR_SYNC_POINT			41
#define SES_ACTIVITY_END			41  */
#define SES_MAJOR_SYNC_ACK			42
#define SES_ACTIVITY_START			45
#define SES_EXCEPTION_DATA			48
#define SES_MINOR_SYNC_POINT			49
#define SES_MINOR_SYNC_ACK			50
#define SES_RESYNCHRONIZE			53
#define SES_ACTIVITY_DISCARD			57
#define SES_ACTIVITY_DISCARD_ACK		58
#define SES_CAPABILITY				61
#define SES_CAPABILITY_DATA_ACK			62

/*
reason code
	0:	Rejection by called SS-user; reason not specified.
	1:	Rejection by called SS-user due to temporary congestion.
	2:	Rejection by called SS-user. Subsequent octets may be used
		for user data up to a length of 512 octets if Protocol
		Version 1 has been selected, and up to a length such that
		the total length (including SI and LI)  of the SPDU does
		not exceed 65 539 octets if Protocol Version 2 has been
		selected.
	128 + 1:	Session Selector unknown.
	128 + 2:	SS-user not attached to SSAP.
	128 + 3:	SPM congestion at connect time.
	128 + 4:	Proposed protocol versions not supported.
	128 + 5:	Rejection by the SPM; reason not specified.
	128 + 6:	Rejection by the SPM; implementation restriction stated in the 
			PICS.
*/
#define reason_not_specified		0
#define temporary_congestion		1
#define Subsequent			2
#define Session_Selector_unknown	128+1
#define SS_user_not_attached_to_SSAP	128+2
#define SPM_congestion_at_connect_time	128+3
#define versions_not_supported		128+4
#define SPM_reason_not_specified	128+5
#define SPM_implementation_restriction	128+6

#define		NON_TOKENS_SPDU			FALSE
#define		TOKENS_SPDU			TRUE

#define		TWO_BYTE_LEN			0xff

/* PGI's */

#define	Connection_Identifier			1
#define	Connect_Accept_Item			5
#define	Linking_Information			33
#define	User_Data				193
#define	Extended_User_Data			194

/* PI's */

#define Called_SS_user_Reference		9
#define Calling_SS_user_Reference		10
#define Common_Reference			11
#define Additional_Reference_Information	12

#define Sync_Type_Item				15
#define Token_Item				16
#define Transport_Disconnect			17

#define Protocol_Options			19
#define Session_Requirement			20
#define TSDU_Maximum_Size			21
#define Version_Number				22
#define Initial_Serial_Number			23
#define Prepare_Type				24
#define EnclosureItem				25
#define Token_Setting_Item			26
#define Resync_Type				27

#define Serial_Number				42

#define Reflect_Parameter			49

#define Reason_Code				50
#define Calling_Session_Selector		51
#define Called_Session_Selector			52
#define Second_Resync_Type			53
#define Second_Serial_Number			54
#define Second_Initial_Serial_Number		55
#define Upper_Limit_Serial_Number		56
#define Large_Initial_Serial_Number		57
#define Large_Second_Initial_Serial_Number	58

#define Data_Overflow				60

/* transport disconnect values */
#define		transport_connection_is_released	0x01
#define		user_abort				0x02
#define		protocol_error				0x04
#define		no_reason				0x08


#define		SESSION_NO_ABORT		0
#define		SESSION_USER_ABORT		1
#define		SESSION_PROVIDER_ABORT		2

/* data for presentation selector      */
struct SESSION_DATA_STRUCTURE
{
	guint8  spdu_type;
	guint8  abort_type;
	guint8  pres_ctx_id;
};
#define		implementation_restriction		0x10

const value_string ses_vals[];

