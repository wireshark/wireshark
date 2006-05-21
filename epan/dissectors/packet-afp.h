/* packet-afp.h
 * Definitions for packet disassembly structures and routines
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef PACKET_AFP_H
#define PACKET_AFP_H

#define AFP_OK				0
#define AFPERR_ACCESS	(-5000)   /* permission denied */
#define AFPERR_AUTHCONT	(-5001)   /* logincont */
#define AFPERR_BADUAM	(-5002)   /* uam doesn't exist */
#define AFPERR_BADVERS	(-5003)   /* bad afp version number */
#define AFPERR_BITMAP	(-5004)   /* invalid bitmap */
#define AFPERR_CANTMOVE (-5005)   /* can't move file */
#define AFPERR_DENYCONF	(-5006)   /* file synchronization locks conflict */
#define AFPERR_DIRNEMPT	(-5007)   /* directory not empty */
#define AFPERR_DFULL	(-5008)   /* disk full */
#define AFPERR_EOF		(-5009)   /* end of file -- catsearch and afp_read */
#define AFPERR_BUSY		(-5010)   /* FileBusy */
#define AFPERR_FLATVOL  (-5011)   /* volume doesn't support directories */
#define AFPERR_NOITEM	(-5012)   /* ItemNotFound */
#define AFPERR_LOCK     (-5013)   /* LockErr */
#define AFPERR_MISC     (-5014)   /* misc. err */
#define AFPERR_NLOCK    (-5015)   /* no more locks */
#define AFPERR_NOSRVR	(-5016)   /* no response by server at that address */
#define AFPERR_EXIST	(-5017)   /* object already exists */
#define AFPERR_NOOBJ	(-5018)   /* object not found */
#define AFPERR_PARAM	(-5019)   /* parameter error */
#define AFPERR_NORANGE  (-5020)   /* no range lock */
#define AFPERR_RANGEOVR (-5021)   /* range overlap */
#define AFPERR_SESSCLOS (-5022)   /* session closed */
#define AFPERR_NOTAUTH	(-5023)   /* user not authenticated */
#define AFPERR_NOOP		(-5024)   /* command not supported */
#define AFPERR_BADTYPE	(-5025)   /* object is the wrong type */
#define AFPERR_NFILE	(-5026)   /* too many files open */
#define AFPERR_SHUTDOWN	(-5027)   /* server is going down */
#define AFPERR_NORENAME (-5028)   /* can't rename */
#define AFPERR_NODIR	(-5029)   /* couldn't find directory */
#define AFPERR_ITYPE	(-5030)   /* wrong icon type */
#define AFPERR_VLOCK	(-5031)   /* volume locked */
#define AFPERR_OLOCK    (-5032)   /* object locked */
#define AFPERR_CTNSHRD  (-5033)   /* share point contains a share point */
#define AFPERR_NOID     (-5034)   /* file thread not found */
#define AFPERR_EXISTID  (-5035)   /* file already has an id */
#define AFPERR_DIFFVOL  (-5036)   /* different volume */
#define AFPERR_CATCHNG  (-5037)   /* catalog has changed */
#define AFPERR_SAMEOBJ  (-5038)   /* source file == destination file */
#define AFPERR_BADID    (-5039)   /* non-existent file id */
#define AFPERR_PWDSAME  (-5040)   /* same password/can't change password */
#define AFPERR_PWDSHORT (-5041)   /* password too short */
#define AFPERR_PWDEXPR  (-5042)   /* password expired */
#define AFPERR_INSHRD   (-5043)   /* folder being shared is inside a shared folder. may be returned by
				   				   afpMoveAndRename. */
#define AFPERR_INTRASH  (-5044)   /* shared folder in trash. */
#define AFPERR_PWDCHNG  (-5045)   /* password needs to be changed */
#define AFPERR_PWDPOLCY (-5046)   /* password fails policy check */
#define AFPERR_USRLOGIN (-5047)   /* user already logged on */

extern const value_string asp_error_vals[];
extern const value_string afp_server_addr_type_vals[];

/* server flags */
#define AFPSRVRINFO_COPY         (1<<0)  /* supports copyfile */
#define AFPSRVRINFO_PASSWD       (1<<1)  /* supports change password */
#define AFPSRVRINFO_NOSAVEPASSWD (1<<2)  /* don't allow save password */
#define AFPSRVRINFO_SRVMSGS      (1<<3)  /* supports server messages */
#define AFPSRVRINFO_SRVSIGNATURE (1<<4)  /* supports server signature */
#define AFPSRVRINFO_TCPIP        (1<<5)  /* supports tcpip */
#define AFPSRVRINFO_SRVNOTIFY    (1<<6)  /* supports server notifications */
#define AFPSRVRINFO_SRVRECONNECT (1<<7)  /* supports reconnect */
#define AFPSRVRINFO_SRVDIRECTORY (1<<8)  /* supports directory services */
#define AFPSRVRINFO_SRVUTF8      (1<<9)  /* supports UTF8 names AFP 3.1 */
#define AFPSRVRINFO_UUID         (1<<10)  /* supports UUIDs AFP 3.2 */
#define AFPSRVRINFO_FASTBOZO     (1<<15) /* fast copying */


#define AFPSTATUS_MACHOFF     0
#define AFPSTATUS_VERSOFF     2
#define AFPSTATUS_UAMSOFF     4
#define AFPSTATUS_ICONOFF     6
#define AFPSTATUS_FLAGOFF     8
#define AFPSTATUS_PRELEN     10
#define AFPSTATUS_POSTLEN     4
#define AFPSTATUS_LEN        (AFPSTATUS_PRELEN + AFPSTATUS_POSTLEN)

/*
 * Private data passed from DSI,DDP dissectors to AFP dissector.
 *                       DSI              DDP
 * aspinfo.reply     	dsi.flags       atp.function == 0x80
 *         release                      atp.function == 0xc0
 *         command          command     asp.function
 *         seq              requestid   atp.tid
 *         code             code
 */
struct aspinfo {
	guint8	reply;			/* 0 query  1 reply */
	guint8  release;
	guint16	command;		/* 2  6 write */
	guint16	seq;			/* sequence number */
	gint32  code;			/* error code/ offset NU */
};

/*
 * value_string table for AFP command codes.
 */
ETH_VAR_IMPORT const value_string CommandCode_vals[];

/*
 * Value from table matching requests and responses; also passed to AFP
 * tap for responses.
 */
typedef struct {
	guint8	command;
	guint32 frame_req, frame_res;
	nstime_t req_time;
} afp_request_val;

#endif
