/* packet-yhoo.h
 * Definitions for packet disassembly structures and routines
 *
 * $Id: packet-yhoo.h,v 1.1 1999/10/14 01:28:26 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 * Joerg Mayer <jmayer@telemation.de>
 *
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

/* This is from yahoolib.h from gtkyahoo */

#ifndef YAHOO_LIB_H
#define YAHOO_LIB_H

/* Service constants */
#define YAHOO_SERVICE_LOGON		1
#define YAHOO_SERVICE_LOGOFF		2
#define YAHOO_SERVICE_ISAWAY		3
#define YAHOO_SERVICE_ISBACK		4
#define YAHOO_SERVICE_IDLE		5
#define YAHOO_SERVICE_MESSAGE		6
#define YAHOO_SERVICE_IDACT		7
#define YAHOO_SERVICE_IDDEACT		8
#define YAHOO_SERVICE_MAILSTAT	9
#define YAHOO_SERVICE_USERSTAT	10
#define YAHOO_SERVICE_NEWMAIL		11
#define YAHOO_SERVICE_CHATINVITE	12
#define YAHOO_SERVICE_CALENDAR	13
#define YAHOO_SERVICE_NEWPERSONALMAIL		14
#define YAHOO_SERVICE_NEWCONTACT	15
#define YAHOO_SERVICE_ADDIDENT	16
#define YAHOO_SERVICE_ADDIGNORE	17
#define YAHOO_SERVICE_PING		18
#define YAHOO_SERVICE_GROUPRENAME	19
#define YAHOO_SERVICE_SYSMESSAGE	20
#define YAHOO_SERVICE_PASSTHROUGH2	22
#define YAHOO_SERVICE_CONFINVITE 24
#define YAHOO_SERVICE_CONFLOGON	25
#define YAHOO_SERVICE_CONFDECLINE 26
#define YAHOO_SERVICE_CONFLOGOFF		27
#define YAHOO_SERVICE_UNKN_28 28
#define YAHOO_SERVICE_CONFMSG 29
#define YAHOO_SERVICE_CHATLOGON	30
#define YAHOO_SERVICE_CHATLOGOFF	31
#define YAHOO_SERVICE_CHATMSG 32
#define YAHOO_SERVICE_FILETRANSFER 70

/* Message flags */
#define YAHOO_MSGTYPE_NORMAL 1
#define YAHOO_MSGTYPE_BOUNCE 2
#define YAHOO_MSGTYPE_STATUS 4
#define YAHOO_MSGTYPE_OFFLINE 1515563606	/* yuck! */

struct yahoo_rawpacket
{
	char version[8];			/* 7 chars and trailing null */
	unsigned char len[4];		/* length - little endian */
	unsigned char service[4];	/* service - little endian */
	unsigned char connection_id[4];		/* connection number - little endian */
	unsigned char magic_id[4];	/* magic number used for http session */
	unsigned char unknown1[4];
	unsigned char msgtype[4];
	char nick1[36];
	char nick2[36];
	char content[1];			/* was zero, had problems with aix xlc */
};

/* Misc contants */
#define YAHOO_PACKET_HEADER_SIZE 104	/* size of a standard header */

/* Constants for status codes */
enum
{
	YAHOO_STATUS_AVAILABLE,
	YAHOO_STATUS_BRB,
	YAHOO_STATUS_BUSY,
	YAHOO_STATUS_NOTATHOME,
	YAHOO_STATUS_NOTATDESK,
	YAHOO_STATUS_NOTINOFFICE,
	YAHOO_STATUS_ONPHONE,
	YAHOO_STATUS_ONVACATION,
	YAHOO_STATUS_OUTTOLUNCH,
	YAHOO_STATUS_STEPPEDOUT,
	YAHOO_STATUS_INVISIBLE = 12,
	YAHOO_STATUS_IDLE = 999
};

#endif
