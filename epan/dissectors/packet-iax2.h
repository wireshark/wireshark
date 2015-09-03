/* packet-iax2.h
 *
 * Copyright (C) 2003, Digium
 * Mark Spencer <markster@digium.com>
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

#ifndef __PACKET_IAX2_H__
#define __PACKET_IAX2_H__

#include <epan/tap-voip.h>

/* Max version of IAX protocol we support */
#define IAX_PROTO_VERSION	2

#define IAX_MAX_CALLS		32768

#define IAX_FLAG_FULL		0x8000

#define IAX_FLAG_RETRANS	0x8000

#define IAX_FLAG_SC_LOG		0x80

#define IAX_MAX_SHIFT		0x1F

#define IAX_WINDOW		64

#define AST_FRAME_DTMF_END  1       /* A DTMF end event, subclass is the digit */
#define AST_FRAME_VOICE     2       /* Voice data, subclass is AST_FORMAT_* */
#define AST_FRAME_VIDEO     3       /* Video frame, maybe?? :) */
#define AST_FRAME_CONTROL   4       /* A control frame, subclass is AST_CONTROL_* */
#define AST_FRAME_NULL      5       /* An empty, useless frame */
#define AST_FRAME_IAX       6       /* Inter Aterisk Exchange private frame type */
#define AST_FRAME_TEXT      7       /* Text messages */
#define AST_FRAME_IMAGE     8       /* Image Frames */
#define AST_FRAME_HTML      9       /* HTML Frames */
#define AST_FRAME_CNG      10       /* Confort Noise Generation */
#define AST_FRAME_MODEM    11       /* Modem-over-IP datastream */
#define AST_FRAME_DTMF_BEGIN 12     /* A DTMF begin event, subclass is the digit */



/* Subclass for AST_FRAME_IAX */
#define IAX_COMMAND_NEW		1
#define IAX_COMMAND_PING	2
#define IAX_COMMAND_PONG	3
#define IAX_COMMAND_ACK		4
#define IAX_COMMAND_HANGUP	5
#define IAX_COMMAND_REJECT	6
#define IAX_COMMAND_ACCEPT	7
#define IAX_COMMAND_AUTHREQ	8
#define IAX_COMMAND_AUTHREP	9
#define IAX_COMMAND_INVAL	10
#define IAX_COMMAND_LAGRQ	11
#define IAX_COMMAND_LAGRP	12
#define IAX_COMMAND_REGREQ	13	/* Registration request */
#define IAX_COMMAND_REGAUTH	14	/* Registration authentication required */
#define IAX_COMMAND_REGACK	15	/* Registration accepted */
#define IAX_COMMAND_REGREJ	16	/* Registration rejected */
#define IAX_COMMAND_REGREL	17	/* Force release of registration */
#define IAX_COMMAND_VNAK	18	/* If we receive voice before valid first voice frame, send this */
#define IAX_COMMAND_DPREQ	19	/* Request status of a dialplan entry */
#define IAX_COMMAND_DPREP	20	/* Request status of a dialplan entry */
#define IAX_COMMAND_DIAL	21	/* Request a dial on channel brought up TBD */
#define IAX_COMMAND_TXREQ	22	/* Transfer Request */
#define IAX_COMMAND_TXCNT	23	/* Transfer Connect */
#define IAX_COMMAND_TXACC	24	/* Transfer Accepted */
#define IAX_COMMAND_TXREADY	25	/* Transfer ready */
#define IAX_COMMAND_TXREL	26	/* Transfer release */
#define IAX_COMMAND_TXREJ	27	/* Transfer reject */
#define IAX_COMMAND_QUELCH	28	/* Stop audio/video transmission */
#define IAX_COMMAND_UNQUELCH	29	/* Resume audio/video transmission */
#define IAX_COMMAND_POKE	30	/* Like ping, but does not require an open connection */
#define IAX_COMMAND_PAGE	31	/* Paging description */
#define IAX_COMMAND_MWI		32	/* Stand-alone message waiting indicator */
#define IAX_COMMAND_UNSUPPORT	33	/* Unsupported message received */
#define IAX_COMMAND_TRANSFER	34	/* Request remote transfer */
#define IAX_COMMAND_PROVISION   35      /* Provision device */
#define IAX_COMMAND_FWDOWNL     36      /* Download firmware */
#define IAX_COMMAND_FWDATA      37      /* Firmware Data */
#define IAX_COMMAND_TXMEDIA     38      /* Transfer Media */
#define IAX_COMMAND_RTKEY       39      /* Rotate key */
#define IAX_COMMAND_CALLTOKEN   40      /* Call token */

#define IAX_DEFAULT_REG_EXPIRE  60	/* By default require re-registration once per minute */

#define IAX_LINGER_TIMEOUT	10	/* How long to wait before closing bridged call */

#define IAX_DEFAULT_PORTNO	4569

/* IAX Information elements */
#define IAX_IE_CALLED_NUMBER		1		/* Number/extension being called - string */
#define IAX_IE_CALLING_NUMBER		2		/* Calling number - string */
#define IAX_IE_CALLING_ANI		3		/* Calling number ANI for billing  - string */
#define IAX_IE_CALLING_NAME		4		/* Name of caller - string */
#define IAX_IE_CALLED_CONTEXT		5		/* Context for number - string */
#define IAX_IE_USERNAME			6		/* Username (peer or user) for authentication - string */
#define IAX_IE_PASSWORD			7		/* Password for authentication - string */
#define IAX_IE_CAPABILITY		8		/* Actual codec capability - unsigned int */
#define IAX_IE_FORMAT			9		/* Desired codec format - unsigned int */
#define IAX_IE_LANGUAGE			10		/* Desired language - string */
#define IAX_IE_VERSION			11		/* Protocol version - short */
#define IAX_IE_ADSICPE			12		/* CPE ADSI capability - short */
#define IAX_IE_DNID			13		/* Originally dialed DNID - string */
#define IAX_IE_AUTHMETHODS		14		/* Authentication method(s) - short */
#define IAX_IE_CHALLENGE		15		/* Challenge data for MD5/RSA - string */
#define IAX_IE_MD5_RESULT		16		/* MD5 challenge result - string */
#define IAX_IE_RSA_RESULT		17		/* RSA challenge result - string */
#define IAX_IE_APPARENT_ADDR		18		/* Apparent address of peer - struct sockaddr_in */
#define IAX_IE_REFRESH			19		/* When to refresh registration - short */
#define IAX_IE_DPSTATUS			20		/* Dialplan status - short */
#define IAX_IE_CALLNO			21		/* Call number of peer - short */
#define IAX_IE_CAUSE			22		/* Cause - string */
#define IAX_IE_IAX_UNKNOWN		23		/* Unknown IAX command - byte */
#define IAX_IE_MSGCOUNT			24		/* How many messages waiting - short */
#define IAX_IE_AUTOANSWER		25		/* Request auto-answering -- none */
#define IAX_IE_MUSICONHOLD		26		/* Request musiconhold with QUELCH -- none or string */
#define IAX_IE_TRANSFERID		27		/* Transfer Request Identifier -- int */
#define IAX_IE_RDNIS			28		/* Referring DNIS -- string */
#define IAX_IE_PROVISIONING		29		/* Provisioning info */
#define IAX_IE_AESPROVISIONING		30		/* AES Provisioning info */
#define IAX_IE_DATETIME			31		/* Date/Time -- unsigned int */
#define IAX_IE_DEVICETYPE		32		/* Device Type -- string */
#define IAX_IE_SERVICEIDENT		33		/* Service Identifier -- string */
#define IAX_IE_FIRMWAREVER		34		/* Firmware revision -- u16 */
#define IAX_IE_FWBLOCKDESC		35		/* Firmware block description -- u32 */
#define IAX_IE_FWBLOCKDATA		36		/* Firmware block of data -- raw */
#define IAX_IE_PROVVER			37		/* Provisioning Version (u32) */
#define IAX_IE_CALLINGPRES		38		/* Calling presentation (u8) */
#define IAX_IE_CALLINGTON		39		/* Calling type of number (u8) */
#define IAX_IE_CALLINGTNS		40		/* Calling transit network select (u16) */
#define IAX_IE_SAMPLINGRATE		41		/* Supported sampling rates (u16) */
#define IAX_IE_CAUSECODE		42		/* Hangup cause (u8) */
#define IAX_IE_ENCRYPTION		43		/* Encryption format (u16) */
#define IAX_IE_ENCKEY			44		/* Encryption key (raw) */
#define IAX_IE_CODEC_PREFS		45		/* Codec Negotiation */
#define IAX_IE_RR_JITTER		46		/* Received jitter (as in RFC1889) u32 */
#define IAX_IE_RR_LOSS			47		/* Received loss (high byte loss pct, low 24 bits loss count, as in rfc1889 */
#define IAX_IE_RR_PKTS			48		/* Received frames (total frames received) u32 */
#define IAX_IE_RR_DELAY			49		/* Max playout delay for received frames (in ms) u16 */
#define IAX_IE_RR_DROPPED		50		/* Dropped frames (presumably by jitterbuf) u32 */
#define IAX_IE_RR_OOO			51		/* Frames received Out of Order u32 */
#define IAX_IE_VARIABLE			52		/* IAX variable transmission */
#define IAX_IE_OSPTOKEN			53		/* OSP Token */
#define IAX_IE_CALLTOKEN		54		/* Call Token */
#define IAX_IE_CAPABILITY2		55		/* Codec capability */
#define IAX_IE_FORMAT2			56		/* Desired codec capability */
#define IAX_IE_DATAFORMAT		255		/* Data call format -- iax_dataformat_t */

/* hangup cause codes */
#define AST_CAUSE_UNALLOCATED				1
#define AST_CAUSE_NO_ROUTE_TRANSIT_NET			2
#define AST_CAUSE_NO_ROUTE_DESTINATION			3
#define AST_CAUSE_MISDIALLED_TRUNK_PREFIX		5
#define AST_CAUSE_CHANNEL_UNACCEPTABLE			6
#define AST_CAUSE_CALL_AWARDED_DELIVERED		7
#define AST_CAUSE_PRE_EMPTED				8
#define AST_CAUSE_NUMBER_PORTED_NOT_HERE		14
#define AST_CAUSE_NORMAL_CLEARING			16
#define AST_CAUSE_USER_BUSY				17
#define AST_CAUSE_NO_USER_RESPONSE			18
#define AST_CAUSE_NO_ANSWER				19
#define AST_CAUSE_SUBSCRIBER_ABSENT			20
#define AST_CAUSE_CALL_REJECTED				21
#define AST_CAUSE_NUMBER_CHANGED			22
#define AST_CAUSE_REDIRECTED_TO_NEW_DESTINATION	23
#define AST_CAUSE_ANSWERED_ELSEWHERE			26
#define AST_CAUSE_DESTINATION_OUT_OF_ORDER		27
#define AST_CAUSE_INVALID_NUMBER_FORMAT			28
#define AST_CAUSE_FACILITY_REJECTED			29
#define AST_CAUSE_RESPONSE_TO_STATUS_ENQUIRY		30
#define AST_CAUSE_NORMAL_UNSPECIFIED			31
#define AST_CAUSE_NORMAL_CIRCUIT_CONGESTION		34
#define AST_CAUSE_NETWORK_OUT_OF_ORDER			38
#define AST_CAUSE_NORMAL_TEMPORARY_FAILURE		41
#define AST_CAUSE_SWITCH_CONGESTION			42
#define AST_CAUSE_ACCESS_INFO_DISCARDED			43
#define AST_CAUSE_REQUESTED_CHAN_UNAVAIL		44
#define AST_CAUSE_FACILITY_NOT_SUBSCRIBED		50
#define AST_CAUSE_OUTGOING_CALL_BARRED			52
#define AST_CAUSE_INCOMING_CALL_BARRED			54
#define AST_CAUSE_BEARERCAPABILITY_NOTAUTH		57
#define AST_CAUSE_BEARERCAPABILITY_NOTAVAIL		58
#define AST_CAUSE_BEARERCAPABILITY_NOTIMPL		65
#define AST_CAUSE_CHAN_NOT_IMPLEMENTED			66
#define AST_CAUSE_FACILITY_NOT_IMPLEMENTED		69
#define AST_CAUSE_INVALID_CALL_REFERENCE		81
#define AST_CAUSE_INCOMPATIBLE_DESTINATION		88
#define AST_CAUSE_INVALID_MSG_UNSPECIFIED		95
#define AST_CAUSE_MANDATORY_IE_MISSING			96
#define AST_CAUSE_MESSAGE_TYPE_NONEXIST			97
#define AST_CAUSE_WRONG_MESSAGE				98
#define AST_CAUSE_IE_NONEXIST				99
#define AST_CAUSE_INVALID_IE_CONTENTS			100
#define AST_CAUSE_WRONG_CALL_STATE			101
#define AST_CAUSE_RECOVERY_ON_TIMER_EXPIRE		102
#define AST_CAUSE_MANDATORY_IE_LENGTH_ERROR		103
#define AST_CAUSE_PROTOCOL_ERROR			111
#define AST_CAUSE_INTERWORKING				127

#define IAX_AUTH_PLAINTEXT			(1 << 0)
#define IAX_AUTH_MD5				(1 << 1)
#define IAX_AUTH_RSA				(1 << 2)

#define IAX_META_TRUNK				1		/* Trunk meta-message */
#define IAX_META_VIDEO				2		/* Video frame */

#define IAX_DPSTATUS_EXISTS		(1 << 0)
#define IAX_DPSTATUS_CANEXIST		(1 << 1)
#define IAX_DPSTATUS_NONEXISTANT	(1 << 2)
#define IAX_DPSTATUS_IGNOREPAT		(1 << 14)
#define IAX_DPSTATUS_MATCHMORE		(1 << 15)

typedef enum {
  IAX2_MINI_VOICE_PACKET,
  IAX2_FULL_PACKET,
  IAX2_MINI_VIDEO_PACKET,
  IAX2_TRUNK_PACKET
} packet_type;

/* Container for tapping relevant data */
typedef struct _iax2_info_t
{
	packet_type ptype;
	guint16 scallno;
	guint16 dcallno;
	guint8 ftype;
	guint8 csub;
	guint32 timestamp;
	guint payload_len;
	voip_call_state callState;
	const gchar *messageName;
	const gchar *callingParty;
	const gchar *calledParty;
	const guint8 *payload_data;
} iax2_info_t;

/* Container for passing data between dissectors */
typedef struct _iax2_dissector_info_t
{
	circuit_type ctype;
	guint32 circuit_id;
} iax2_dissector_info_t;

#endif /* __PACKET_IAX2_H__ */
