/*
 * Asterisk -- A telephony toolkit for Linux.
 *
 * Implementation of Inter-Asterisk eXchange
 * 
 * Copyright (C) 2003, Digium
 *
 * Mark Spencer <markster@linux-support.net>
 *
 * $Id: packet-iax2.h,v 1.1 2004/01/27 01:35:25 guy Exp $
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License
 */
 
#ifndef _PACKET_IAX2_H
#define _PACKET_IAX2_H

/* Max version of IAX protocol we support */
#define IAX_PROTO_VERSION 2

#define IAX_MAX_CALLS 32768

#define IAX_FLAG_FULL		0x8000

#define IAX_FLAG_RETRANS	0x8000

#define IAX_FLAG_SC_LOG		0x80

#define IAX_MAX_SHIFT		0x1F

#define IAX_WINDOW			64

#define AST_FRAME_DTMF      1       /* A DTMF digit, subclass is the digit */
#define AST_FRAME_VOICE     2       /* Voice data, subclass is AST_FORMAT_* */
#define AST_FRAME_VIDEO     3       /* Video frame, maybe?? :) */
#define AST_FRAME_CONTROL   4       /* A control frame, subclass is AST_CONTROL_* */
#define AST_FRAME_NULL      5       /* An empty, useless frame */
#define AST_FRAME_IAX       6       /* Inter Aterisk Exchange private frame type */
#define AST_FRAME_TEXT      7       /* Text messages */
#define AST_FRAME_IMAGE     8       /* Image Frames */
#define AST_FRAME_HTML      9       /* HTML Frames */

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
#define IAX_COMMAND_UNQUELCH 29	/* Resume audio/video transmission */
#define IAX_COMMAND_POKE    30  /* Like ping, but does not require an open connection */
#define IAX_COMMAND_PAGE	31	/* Paging description */
#define IAX_COMMAND_MWI	32	/* Stand-alone message waiting indicator */
#define IAX_COMMAND_UNSUPPORT	33	/* Unsupported message received */
#define IAX_COMMAND_TRANSFER	34	/* Request remote transfer */

#define IAX_DEFAULT_REG_EXPIRE  60	/* By default require re-registration once per minute */

#define IAX_LINGER_TIMEOUT		10 /* How long to wait before closing bridged call */

#define IAX_DEFAULT_PORTNO		4569

/* IAX Information elements */
#define IAX_IE_CALLED_NUMBER		1		/* Number/extension being called - string */
#define IAX_IE_CALLING_NUMBER		2		/* Calling number - string */
#define IAX_IE_CALLING_ANI			3		/* Calling number ANI for billing  - string */
#define IAX_IE_CALLING_NAME			4		/* Name of caller - string */
#define IAX_IE_CALLED_CONTEXT		5		/* Context for number - string */
#define IAX_IE_USERNAME				6		/* Username (peer or user) for authentication - string */
#define IAX_IE_PASSWORD				7		/* Password for authentication - string */
#define IAX_IE_CAPABILITY			8		/* Actual codec capability - unsigned int */
#define IAX_IE_FORMAT				9		/* Desired codec format - unsigned int */
#define IAX_IE_LANGUAGE				10		/* Desired language - string */
#define IAX_IE_VERSION				11		/* Protocol version - short */
#define IAX_IE_ADSICPE				12		/* CPE ADSI capability - short */
#define IAX_IE_DNID					13		/* Originally dialed DNID - string */
#define IAX_IE_AUTHMETHODS			14		/* Authentication method(s) - short */
#define IAX_IE_CHALLENGE			15		/* Challenge data for MD5/RSA - string */
#define IAX_IE_MD5_RESULT			16		/* MD5 challenge result - string */
#define IAX_IE_RSA_RESULT			17		/* RSA challenge result - string */
#define IAX_IE_APPARENT_ADDR		18		/* Apparent address of peer - struct sockaddr_in */
#define IAX_IE_REFRESH				19		/* When to refresh registration - short */
#define IAX_IE_DPSTATUS				20		/* Dialplan status - short */
#define IAX_IE_CALLNO				21		/* Call number of peer - short */
#define IAX_IE_CAUSE				22		/* Cause - string */
#define IAX_IE_IAX_UNKNOWN			23		/* Unknown IAX command - byte */
#define IAX_IE_MSGCOUNT				24		/* How many messages waiting - short */
#define IAX_IE_AUTOANSWER			25		/* Request auto-answering -- none */
#define IAX_IE_MUSICONHOLD			26		/* Request musiconhold with QUELCH -- none or string */
#define IAX_IE_TRANSFERID			27		/* Transfer Request Identifier -- int */
#define IAX_IE_RDNIS				28		/* Referring DNIS -- string */

#define IAX_AUTH_PLAINTEXT			(1 << 0)
#define IAX_AUTH_MD5				(1 << 1)
#define IAX_AUTH_RSA				(1 << 2)

#define IAX_META_TRUNK				1		/* Trunk meta-message */
#define IAX_META_VIDEO				2		/* Video frame */

#define IAX_DPSTATUS_EXISTS			(1 << 0)
#define IAX_DPSTATUS_CANEXIST		(1 << 1)
#define IAX_DPSTATUS_NONEXISTANT	(1 << 2)
#define IAX_DPSTATUS_IGNOREPAT		(1 << 14)
#define IAX_DPSTATUS_MATCHMORE		(1 << 15)

#define AST_FORMAT_G723_1   (1 << 0)    /* G.723.1 compression */
#define AST_FORMAT_GSM      (1 << 1)    /* GSM compression */
#define AST_FORMAT_ULAW     (1 << 2)    /* Raw mu-law data (G.711) */
#define AST_FORMAT_ALAW     (1 << 3)    /* Raw A-law data (G.711) */
#define AST_FORMAT_MP3      (1 << 4)    /* MPEG-2 layer 3 */
#define AST_FORMAT_ADPCM    (1 << 5)    /* ADPCM (whose?) */
#define AST_FORMAT_SLINEAR  (1 << 6)    /* Raw 16-bit Signed Linear (8000 Hz) PCM */
#define AST_FORMAT_LPC10    (1 << 7)    /* LPC10, 180 samples/frame */
#define AST_FORMAT_G729A    (1 << 8)    /* G.729a Audio */

#endif
