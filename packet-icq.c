/* packet-icq.c
 * Routines for ICQ packet disassembly
 *
 * $Id: packet-icq.c,v 1.24 2000/11/21 16:17:58 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Johan Feyaerts
 * Copyright 1999 Johan Feyaerts
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

/*
 * This file: by Kojak <kojak@bigwig.net>
 *
 * Decoding code ripped, reference to the original author at the
 * appropriate place with the code itself.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include "packet.h"
#include "resolv.h"

static int proto_icq = -1;
static int hf_icq_uin =-1;
static int hf_icq_cmd =-1;
static int hf_icq_sessionid =-1;
static int hf_icq_checkcode =-1;
static int hf_icq_decode = -1;
static int hf_icq_type = -1;

static gint ett_icq = -1;
static gint ett_icq_header = -1;
static gint ett_icq_decode = -1;
static gint ett_icq_body = -1;
static gint ett_icq_body_parts = -1;

#define UDP_PORT_ICQ	4000

enum { ICQ5_client, ICQ5_server};

static void dissect_icqv5(const u_char *pd,
		   int offset,
		   frame_data *fd,
		   proto_tree *tree);

static void
dissect_icqv5Server(const u_char *pd,
		    int offset,
		    frame_data *fd,
		    proto_tree *tree,
		    guint32 pktsize);

/* Offsets of fields in the ICQ headers */
/* Can be 0x0002 or 0x0005 */
#define ICQ_VERSION		0x00
/* Is either one (server) or four (client) bytes long */
/* Client header offsets */
#define ICQ5_UNKNOWN		0x02
#define ICQ5_CL_UIN		0x06
#define ICQ5_CL_SESSIONID	0x0a
#define ICQ5_CL_CMD		0x0e
#define ICQ5_CL_SEQNUM1		0x10
#define ICQ5_CL_SEQNUM2		0x12
#define ICQ5_CL_CHECKCODE	0x14
#define ICQ5_CL_PARAM		0x18
#define ICQ5_CL_HDRSIZE		0x18

/* Server header offsets */
#define ICQ5_SRV_SESSIONID	0x03
#define ICQ5_SRV_CMD		0x07
#define ICQ5_SRV_SEQNUM1	0x09
#define ICQ5_SRV_SEQNUM2	0x0b
#define ICQ5_SRV_UIN		0x0d
#define ICQ5_SRV_CHECKCODE	0x11
#define ICQ5_SRV_PARAM		0x15
#define ICQ5_SRV_HDRSIZE	0x15

typedef struct _cmdcode {
    char* descr;
    int code;
} cmdcode;

#define SRV_ACK			0x000a

#define SRV_SILENT_TOO_LONG	0x001e

#define SRV_GO_AWAY		0x0028

#define SRV_NEW_UIN		0x0046

/* LOGIN_REPLY is very scary. It has a lot of fields that are undocumented
 * Only the IP field makes sense */
#define SRV_LOGIN_REPLY		0x005a
#define SRV_LOGIN_REPLY_IP	0x000c

#define SRV_BAD_PASS		0x0064

#define SRV_USER_ONLINE		0x006e
#define SRV_USER_ONL_UIN	0x0000
#define SRV_USER_ONL_IP		0x0004
#define SRV_USER_ONL_PORT	0x0008
#define SRV_USER_ONL_REALIP	0x000c
#define SRV_USER_ONL_X1		0x0010
#define SRV_USER_ONL_STATUS	0x0013
#define SRV_USER_ONL_X2		0x0015

#define SRV_USER_OFFLINE	0x0078
#define SRV_USER_OFFLINE_UIN	0x0000

#define SRV_MULTI		0x0212
#define SRV_MULTI_NUM		0x0000

#define SRV_META_USER		0x03de
#define SRV_META_USER_SUBCMD	0x0000
#define SRV_META_USER_RESULT	0x0002
#define SRV_META_USER_DATA	0x0003

#define SRV_UPDATE_SUCCESS	0x01e0

#define SRV_UPDATE_FAIL		0x01ea

/*
 * ICQv5 SRV_META_USER subcommands
 */
#define META_EX_USER_FOUND	0x0190
#define META_USER_FOUND		0x019a
#define META_ABOUT		0x00e6
#define META_USER_INFO		0x00c8

#define SRV_RECV_MESSAGE	0x00dc
#define SRV_RECV_MSG_UIN	0x0000
#define SRV_RECV_MSG_YEAR	0x0004
#define SRV_RECV_MSG_MONTH	0x0006
#define SRV_RECV_MSG_DAY	0x0007
#define SRV_RECV_MSG_HOUR	0x0008
#define SRV_RECV_MSG_MINUTE	0x0009
#define SRV_RECV_MSG_MSG_TYPE	0x000a

#define SRV_RAND_USER		0x024e
#define SRV_RAND_USER_UIN	0x0000
#define SRV_RAND_USER_IP	0x0004
#define SRV_RAND_USER_PORT	0x0008
#define SRV_RAND_USER_REAL_IP	0x000c
#define SRV_RAND_USER_CLASS	0x0010
#define SRV_RAND_USER_X1	0x0011
#define SRV_RAND_USER_STATUS	0x0015
#define SRV_RAND_USER_TCP_VER	0x0019

/* This message has the same structure as cmd_send_msg */
#define SRV_SYS_DELIVERED_MESS	0x0104

cmdcode serverMetaSubCmdCode[] = {
    { "META_USER_FOUND", META_USER_FOUND },
    { "META_EX_USER_FOUND", META_EX_USER_FOUND },
    { "META_ABOUT", META_ABOUT },
    { "META_USER_INFO", META_USER_INFO },
    { NULL, -1 }
};

cmdcode serverCmdCode[] = {
    { "SRV_ACK", SRV_ACK },
    { "SRV_SILENT_TOO_LONG", SRV_SILENT_TOO_LONG },
    { "SRV_GO_AWAY", SRV_GO_AWAY },
    { "SRV_NEW_UIN", SRV_NEW_UIN },
    { "SRV_LOGIN_REPLY", SRV_LOGIN_REPLY },
    { "SRV_BAD_PASS", SRV_BAD_PASS },
    { "SRV_USER_ONLINE", SRV_USER_ONLINE },
    { "SRV_USER_OFFLINE", SRV_USER_OFFLINE },
    { "SRV_QUERY", 130 },
    { "SRV_USER_FOUND", 140 },
    { "SRV_END_OF_SEARCH", 160 },
    { "SRV_NEW_USER", 180 },
    { "SRV_UPDATE_EXT", 200 },
    { "SRV_RECV_MESSAGE", SRV_RECV_MESSAGE },
    { "SRV_END_OFFLINE_MESSAGES", 230 },
    { "SRV_NOT_CONNECTED", 240 },
    { "SRV_TRY_AGAIN", 250 },
    { "SRV_SYS_DELIVERED_MESS", SRV_SYS_DELIVERED_MESS },
    { "SRV_INFO_REPLY", 280 },
    { "SRV_EXT_INFO_REPLY", 290 },
    { "SRV_STATUS_UPDATE", 420 },
    { "SRV_SYSTEM_MESSAGE", 450 },
    { "SRV_UPDATE_SUCCESS", SRV_UPDATE_SUCCESS },
    { "SRV_UPDATE_FAIL", SRV_UPDATE_FAIL },
    { "SRV_AUTH_UPDATE", 500 },
    { "SRV_MULTI_PACKET", SRV_MULTI },
    { "SRV_END_CONTACTLIST_STATUS", 540 },
    { "SRV_RAND_USER", SRV_RAND_USER },
    { "SRV_META_USER", SRV_META_USER },
    { NULL, -1 }
};

#define MSG_TEXT		0x0001
#define MSG_URL			0x0004
#define MSG_AUTH_REQ		0x0006
#define MSG_AUTH		0x0008
#define MSG_USER_ADDED		0x000c
#define MSG_EMAIL		0x000e
#define MSG_CONTACTS		0x0013

#define STATUS_ONLINE		0x00000000
#define STATUS_AWAY		0x00000001
#define STATUS_DND		0x00000013
#define STATUS_INVISIBLE	0x00000100
#define STATUS_OCCUPIED		0x00000010
#define STATUS_NA		0x00000004
#define STATUS_CHAT		0x00000020

/* Offsets for all packets measured from the start of the payload; i.e.
 * with the ICQ header removed
 */
#define CMD_ACK			0x000a
#define CMD_ACK_RANDOM		0x0000

#define CMD_SEND_MSG		0x010E
#define CMD_SEND_MSG_RECV_UIN	0x0000
#define CMD_SEND_MSG_MSG_TYPE	0x0004
#define CMD_SEND_MSG_MSG_LEN	0x0006
#define CMD_SEND_MSG_MSG_TEXT	0x0008
/* The rest of the packet should be a null-term string */

#define CMD_LOGIN		0x03E8
#define CMD_LOGIN_TIME		0x0000
#define CMD_LOGIN_PORT		0x0004
#define CMD_LOGIN_PASSLEN	0x0008
#define CMD_LOGIN_PASSWD	0x000A
/* The password is variable length; so when we've decoded the passwd,
 * the structure starts counting at 0 again.
 */
#define CMD_LOGIN_IP		0x0004
#define CMD_LOGIN_STATUS	0x0009

#define CMD_CONTACT_LIST	0x0406
#define CMD_CONTACT_LIST_NUM	0x0000

#define CMD_USER_META		0x064a

#define CMD_REG_NEW_USER	0x03fc

#define CMD_ACK_MESSAGES	0x0442
#define CMD_ACK_MESSAGES_RANDOM	0x0000

#define CMD_KEEP_ALIVE		0x042e
#define CMD_KEEP_ALIVE_RANDOM	0x0000

#define CMD_SEND_TEXT_CODE	0x0438
#define CMD_SEND_TEXT_CODE_LEN	0x0000
#define CMD_SEND_TEXT_CODE_TEXT	0x0002

#define CMD_MSG_TO_NEW_USER     0x0456

#define CMD_QUERY_SERVERS	0x04ba

#define CMD_QUERY_ADDONS	0x04c4

#define CMD_STATUS_CHANGE	0x04d8
#define CMD_STATUS_CHANGE_STATUS	0x0000

#define CMD_ADD_TO_LIST		0x053c
#define CMD_ADD_TO_LIST_UIN	0x0000

#define CMD_RAND_SEARCH		0x056e
#define CMD_RAND_SEARCH_GROUP	0x0000

#define CMD_META_USER		0x064a

cmdcode msgTypeCode[] = {
    { "MSG_TEXT", MSG_TEXT },
    { "MSG_URL", MSG_URL },
    { "MSG_AUTH_REQ", MSG_AUTH_REQ },
    { "MSG_AUTH", MSG_AUTH },
    { "MSG_USER_ADDED", MSG_USER_ADDED},
    { "MSG_EMAIL", MSG_EMAIL},
    { "MSG_CONTACTS", MSG_CONTACTS},
    { NULL, 0}
};

cmdcode statusCode[] = {
    { "ONLINE", STATUS_ONLINE },
    { "AWAY", STATUS_AWAY },
    { "DND", STATUS_DND },
    { "INVISIBLE", STATUS_INVISIBLE },
    { "OCCUPIED", STATUS_OCCUPIED },
    { "NA", STATUS_NA },
    { "Free for Chat", STATUS_CHAT },
    { NULL, 0}
};

cmdcode clientCmdCode[] = {
    { "CMD_ACK", CMD_ACK },
    { "CMD_SEND_MESSAGE", CMD_SEND_MSG },
    { "CMD_LOGIN", CMD_LOGIN },
    { "CMD_REG_NEW_USER", CMD_REG_NEW_USER },
    { "CMD_CONTACT_LIST", 1030 },
    { "CMD_SEARCH_UIN", 1050 },
    { "CMD_SEARCH_USER", 1060 },
    { "CMD_KEEP_ALIVE", 1070 },
    { "CMD_SEND_TEXT_CODE", CMD_SEND_TEXT_CODE },
    { "CMD_ACK_MESSAGES", CMD_ACK_MESSAGES },
    { "CMD_LOGIN_1", 1100 },
    { "CMD_MSG_TO_NEW_USER", CMD_MSG_TO_NEW_USER },
    { "CMD_INFO_REQ", 1120 },
    { "CMD_EXT_INFO_REQ", 1130 },
    { "CMD_CHANGE_PW", 1180 },
    { "CMD_NEW_USER_INFO", 1190 },
    { "CMD_UPDATE_EXT_INFO", 1200 },
    { "CMD_QUERY_SERVERS", CMD_QUERY_SERVERS },
    { "CMD_QUERY_ADDONS", CMD_QUERY_ADDONS },
    { "CMD_STATUS_CHANGE", CMD_STATUS_CHANGE },
    { "CMD_NEW_USER_1", 1260 },
    { "CMD_UPDATE_INFO", 1290 },
    { "CMD_AUTH_UPDATE", 1300 },
    { "CMD_KEEP_ALIVE2", 1310 },
    { "CMD_LOGIN_2", 1320 },
    { "CMD_ADD_TO_LIST", CMD_ADD_TO_LIST },
    { "CMD_RAND_SET", 1380 },
    { "CMD_RAND_SEARCH", CMD_RAND_SEARCH },
    { "CMD_META_USER", CMD_META_USER },
    { "CMD_INVIS_LIST", 1700 },
    { "CMD_VIS_LIST", 1710 },
    { "CMD_UPDATE_LIST", 1720 },
    { NULL, 0 }
};

/*
 * All ICQv5 decryption code thanx to Sebastien Dault (daus01@gel.usherb.ca)
 */
const u_char
table_v5 [] = {
 0x59, 0x60, 0x37, 0x6B, 0x65, 0x62, 0x46, 0x48, 0x53, 0x61, 0x4C, 0x59, 0x60, 0x57, 0x5B, 0x3D,
 0x5E, 0x34, 0x6D, 0x36, 0x50, 0x3F, 0x6F, 0x67, 0x53, 0x61, 0x4C, 0x59, 0x40, 0x47, 0x63, 0x39,
 0x50, 0x5F, 0x5F, 0x3F, 0x6F, 0x47, 0x43, 0x69, 0x48, 0x33, 0x31, 0x64, 0x35, 0x5A, 0x4A, 0x42,
 0x56, 0x40, 0x67, 0x53, 0x41, 0x07, 0x6C, 0x49, 0x58, 0x3B, 0x4D, 0x46, 0x68, 0x43, 0x69, 0x48,
 0x33, 0x31, 0x44, 0x65, 0x62, 0x46, 0x48, 0x53, 0x41, 0x07, 0x6C, 0x69, 0x48, 0x33, 0x51, 0x54,
 0x5D, 0x4E, 0x6C, 0x49, 0x38, 0x4B, 0x55, 0x4A, 0x62, 0x46, 0x48, 0x33, 0x51, 0x34, 0x6D, 0x36,
 0x50, 0x5F, 0x5F, 0x5F, 0x3F, 0x6F, 0x47, 0x63, 0x59, 0x40, 0x67, 0x33, 0x31, 0x64, 0x35, 0x5A,
 0x6A, 0x52, 0x6E, 0x3C, 0x51, 0x34, 0x6D, 0x36, 0x50, 0x5F, 0x5F, 0x3F, 0x4F, 0x37, 0x4B, 0x35,
 0x5A, 0x4A, 0x62, 0x66, 0x58, 0x3B, 0x4D, 0x66, 0x58, 0x5B, 0x5D, 0x4E, 0x6C, 0x49, 0x58, 0x3B,
 0x4D, 0x66, 0x58, 0x3B, 0x4D, 0x46, 0x48, 0x53, 0x61, 0x4C, 0x59, 0x40, 0x67, 0x33, 0x31, 0x64,
 0x55, 0x6A, 0x32, 0x3E, 0x44, 0x45, 0x52, 0x6E, 0x3C, 0x31, 0x64, 0x55, 0x6A, 0x52, 0x4E, 0x6C,
 0x69, 0x48, 0x53, 0x61, 0x4C, 0x39, 0x30, 0x6F, 0x47, 0x63, 0x59, 0x60, 0x57, 0x5B, 0x3D, 0x3E,
 0x64, 0x35, 0x3A, 0x3A, 0x5A, 0x6A, 0x52, 0x4E, 0x6C, 0x69, 0x48, 0x53, 0x61, 0x6C, 0x49, 0x58,
 0x3B, 0x4D, 0x46, 0x68, 0x63, 0x39, 0x50, 0x5F, 0x5F, 0x3F, 0x6F, 0x67, 0x53, 0x41, 0x25, 0x41,
 0x3C, 0x51, 0x54, 0x3D, 0x5E, 0x54, 0x5D, 0x4E, 0x4C, 0x39, 0x50, 0x5F, 0x5F, 0x5F, 0x3F, 0x6F,
 0x47, 0x43, 0x69, 0x48, 0x33, 0x51, 0x54, 0x5D, 0x6E, 0x3C, 0x31, 0x64, 0x35, 0x5A, 0x00, 0x00 };
 
static char*
findcmd(cmdcode* c, int num)
{
    static char buf[16];
    cmdcode* p = c;
    while (p->descr != NULL) {
	if (p->code == num) {
	    return p->descr;
	}
	p++;
    }
    snprintf(buf, sizeof(buf), "(%x)", num);
    return buf;
}

static char*
findMsgType(int num)
{
    return findcmd(msgTypeCode, num);
}

static char*
findSubCmd(int num)
{
    return findcmd(serverMetaSubCmdCode, num);
}

static char*
findClientCmd(int num)
{
    return findcmd(clientCmdCode, num);
}

static char*
findServerCmd(int num)
{
    return findcmd(serverCmdCode, num);
}

static char*
findStatus(int num)
{
    return findcmd(statusCode, num);
}

static void
proto_tree_add_hexdump(proto_tree* t,
		       guint32 offset,
		       const u_char *data,
		       int size)
{
    int i;
    char buf[96];
    int n;
    int done = 0, line = 0;
    int added = 0;

    if (size==0)
	return;
    
    line = size / 16;
    
    for (i=0;i<line;i++) {
	added = 0;
	done = 0;
	for (n = i * 16; n < (i+1)*16; n++) {
	    added = sprintf(buf+done, "%02x", data[n]);
	    if ((n%8)==7)
		added += sprintf(buf + done + added, "  ");
	    else
		added += sprintf(buf + done + added, " ");
	    done += added;
	}
	for (n = i * 16; n < (i+1)*16; n++) {
	    if (isprint(data[n]))
		added = sprintf(buf + done, "%c", data[n]);
	    else
		added = sprintf(buf + done, ".");
	    done += added;
	}
	proto_tree_add_text(t, NullTVB,
			    offset + i*16,
			    16,
			    buf);
    }
    if ((size%16)!=0) {
	done = 0;
	for (n = line * 16 ; n < size ; n++) {
	    added = sprintf(buf+done, "%02x", data[n]);
	    if ((n%8)==7)
		added += sprintf(buf + done + added, "  ");
	    else
		added += sprintf(buf + done + added, " ");
	    done += added;
	}
	for (n = size ; (n%16)!=0;n++) {
	    added = 0;
	    if ((n%8)==7)
		added += sprintf(buf + done + added, "    ");
	    else
		added += sprintf(buf + done + added, "   ");
	    done += added;
	}
	for (n = line * 16; n < (line+1)*16; n++) {
	    added = 0;
	    if (n<size) {
		if (isprint(data[n]))
		    added = sprintf(buf + done, "%c", data[n]);
		else
		    added = sprintf(buf + done, ".");
	    } else {
		added = sprintf(buf + done, " ");
	    }
	    done += added;
	}
	proto_tree_add_text(t, NullTVB,
			    offset + line*16,
			    size % 16,
			    buf);
    }
}

static guint32
get_v5key(const u_char* pd, int len)
{
    guint32 a1, a2, a3, a4, a5;
    guint32 code, check, key;

    code = pletohl(&pd[ICQ5_CL_CHECKCODE]);

    a1 = code & 0x0001f000;
    a2 = code & 0x07c007c0;
    a3 = code & 0x003e0001;
    a4 = code & 0xf8000000;
    a5 = code & 0x0000083e;

    a1 = a1 >> 0x0c;
    a2 = a2 >> 0x01;
    a3 = a3 << 0x0a;
    a4 = a4 >> 0x10;
    a5 = a5 << 0x0f;

    check = a5 + a1 + a2 + a3 + a4;
    key = len * 0x68656C6C;
    key += check;
    return key;
}

static void
decrypt_v5(u_char *bfr, guint32 size,guint32 key)
{
    guint32 i;
    guint32 k;
    for (i=0x0a; i < size+3; i+=4 ) {
	k = key+table_v5[i&0xff];
	if ( i != 0x16 ) {
	    bfr[i] ^= (u_char)(k & 0xff);
	    bfr[i+1] ^= (u_char)((k & 0xff00)>>8);
	}
	if ( i != 0x12 ) {
	    bfr[i+2] ^= (u_char)((k & 0xff0000)>>16);
	    bfr[i+3] ^= (u_char)((k & 0xff000000)>>24);
	}
    }
}

static void
dissect_icqv4(const u_char *pd,
	      int offset,
	      frame_data *fd, 
	      proto_tree *tree)
{
    /* Not really implemented yet */
    if (check_col(fd, COL_PROTOCOL)) {
	col_set_str(fd, COL_PROTOCOL, "ICQv4 (UDP)");
    }
    if (check_col(fd, COL_INFO)) {
	col_set_str(fd, COL_INFO, "ICQ Version 4 protocol");
    }
}

static void
dissect_icqv3(const u_char *pd,
	      int offset,
	      frame_data *fd, 
	      proto_tree *tree)
{
    /* Not really implemented yet */
    if (check_col(fd, COL_PROTOCOL)) {
	col_set_str(fd, COL_PROTOCOL, "ICQv3 (UDP)");
    }
    if (check_col(fd, COL_INFO)) {
	col_set_str(fd, COL_INFO, "ICQ Version 3 protocol");
    }
}

static void
dissect_icqv2(const u_char *pd,
	      int offset,
	      frame_data *fd, 
	      proto_tree *tree)
{
    /* Not really implemented yet */
    if (check_col(fd, COL_PROTOCOL)) {
	col_set_str(fd, COL_PROTOCOL, "ICQv2 (UDP)");
    }
    if (check_col(fd, COL_INFO)) {
	col_set_str(fd, COL_INFO, "ICQ Version 2 protocol");
    }
}

/*
 * Find first occurrence of ch in buf
 * Buf is max size big.
 */
static char*
strnchr(const u_char* buf, u_char ch, int size)
{
    int i;
    u_char* p = (u_char*) buf;
    for (i=0;(*p) && (*p!=ch) && (i<size); p++, i++)
	;
    if ((*p == '\0') || (i>=size))
	return NULL;
    return p;
}

/*
 * The packet at pd has a (len, string) pair.
 * Copy the string to a buffer, and display it in the tree.
 * Observe any limits you might cross.
 *
 * If anything is wrong, return -1, since -1 is not a valid string
 * length. Else, return the number of chars processed.
 */
static guint16
proto_add_icq_attr(proto_tree* tree, /* The tree to add to */
		   const char* pd, /* Pointer to the field */
		   const int offset, /* Offset from the start of packet */
		   const int size, /* The number of bytes left in pd */
		   char* descr)	/* The description to use in the tree */
{
    guint16 len;
    char* data;
    int left = size;
    
    if (size<sizeof(guint16))
	return -1;
    len = pletohs(pd);
    left -= sizeof(guint16);
    if (left<len) {
	proto_tree_add_text(tree, NullTVB,
			    offset,
			    sizeof(guint16),
			    "Length: %u", len);
	return -1;
    }
			    
    data = g_malloc(len);

    strncpy(data, pd + sizeof(guint16), len);
    data[len - 1] = '\0';

    proto_tree_add_text(tree, NullTVB,
			offset,
			sizeof(guint16) + len,
			"%s[%u]: %s", descr, len, data);
    g_free(data);

    return len + sizeof(guint16);
}

static void
icqv5_decode_msgType(proto_tree* tree,
		     const unsigned char* pd, /* From start of messageType */
		     int offset,
		     int size)
{
    proto_item* ti = NULL;
    proto_tree* subtree = NULL;
    int left = size;
    char *msgText = NULL;
    guint16 msgType = -1;
    guint16 msgLen = -1;
    int i,j,n;
    static char* auth_req_field_descr[] = {
	"Nickname",
	"First name",
	"Last name",
	"Email address",
	"Unknown",
	"Reason"};
    static char* emain_field_descr[] = {
	"Nickname",
	"First name",
	"Last name",
	"Email address",
	"Unknown",
	"Text\n"
    };
    
    enum {OFF_MSG_TYPE=0,
	  OFF_MSG_LEN=2,
	  OFF_MSG_TEXT=4};

    
    if (left >= sizeof(guint16)) {
	msgType = pletohs(pd + OFF_MSG_TYPE);
	left -= sizeof(guint16);
    }
    if (left >= sizeof(guint16)) {
	msgLen = pletohs(pd + OFF_MSG_LEN);
	left -= sizeof(guint16);
    }

    ti = proto_tree_add_text(tree, NullTVB,
			     offset ,
			     2,
			     "Type: %u (%s)", msgType, findMsgType(msgType));
    /* Create a new subtree */
    subtree = proto_item_add_subtree(ti, ett_icq_body_parts);

    switch(msgType) {
    case 0xffff:           /* Field unknown */
	break;
    default:
	fprintf(stderr, "Unknown msgType: %u (%04x)\n", msgType, msgType);
	break;
    case MSG_TEXT:
	msgText = g_malloc(left + 1);
	strncpy(msgText, pd + OFF_MSG_TEXT, left);
	msgText[left] = '\0';
	proto_tree_add_text(subtree, NullTVB,
			    offset + OFF_MSG_TEXT,
			    left,
			    "Msg: %s", msgText);
	g_free(msgText);
	break;
    case MSG_URL:
	/* Two parts, a description and the URL. Separeted by FE */
	for (i=0;i<left;i++) {
	    if (pd[OFF_MSG_TEXT + i] == 0xfe)
		break;
	}
	msgText = g_malloc(i + 1);
	strncpy(msgText, pd + OFF_MSG_TEXT, i);
	if (i==left)
	    msgText[i] = '\0';
	else
	    msgText[i-1] = '\0';
	proto_tree_add_text(subtree, NullTVB,
			    offset + OFF_MSG_TEXT,
			    i,
			    "Description: %s", msgText);
	if (i==left)
	    break;
	msgText = g_realloc(msgText, left - i);
	strncpy(msgText, pd + OFF_MSG_TEXT + i + 1, left - i - 1);
	msgText[left - i] = '\0';
	proto_tree_add_text(subtree, NullTVB,
			    offset + OFF_MSG_TEXT,
			    i,
			    "URL: %s", msgText);
	g_free(msgText);
	break;
    case MSG_EMAIL:
	i = 0;
	j = 0;
	msgText = NULL;
	for (n = 0; n < 6; n++) {
	    for (;
		 (i<left) && (pd[OFF_MSG_TEXT+i]!=0xfe);
		 i++)
		;
	    if (i>j) {
		msgText = g_realloc(msgText, i-j);
		strncpy(msgText, pd + OFF_MSG_TEXT + j, i - j - 1);
		msgText[i-j-1] = '\0';
		proto_tree_add_text(subtree, NullTVB,
				    offset + OFF_MSG_TEXT + j,
				    i - j - 1,
				    "%s: %s", emain_field_descr[n], msgText);
	    } else {
		proto_tree_add_text(subtree, NullTVB,
				    offset + OFF_MSG_TEXT + j,
				    0,
				    "%s: %s", emain_field_descr[n], "(empty)");
	    }
	    j = ++i;
	}
	if (msgText != NULL)
	    g_free(msgText);
	break;
	
    case MSG_AUTH:
    {
	/* Three bytes, first is a char signifying success */
	unsigned char auth_suc = pd[OFF_MSG_LEN];
	guint16 x1 = pd[OFF_MSG_LEN+1];
	proto_tree_add_text(subtree, NullTVB,
			    offset + OFF_MSG_LEN,
			    1,
			    "Authorization: (%u) %s",auth_suc,
			    (auth_suc==0)?"Denied":"Allowed");
	proto_tree_add_text(subtree, NullTVB,
			    offset + OFF_MSG_LEN + 1,
			    sizeof(guint16),
			    "x1: 0x%04x",x1);
	break;
    }
    case MSG_AUTH_REQ:
	/* Six parts, separated by FE */
	i = 0;
	j = 0;
	msgText = g_malloc(64);
	for (n = 0; n < 6 && i<left; n++) {
            while (i<left && pd[OFF_MSG_TEXT+i]!=0xfe)
                i++;
            if (i<=left) {
                /* pd[OFF_MSG_TEXT+i] == 0xfe */
                if (i!=j) {   
                    /* Otherwise, it'd be a null string */
                    msgText = g_realloc(msgText, i - j);
                    strncpy(msgText, pd + OFF_MSG_TEXT + j, i-j);
		    msgText[i-j] = '\0';
                    proto_tree_add_text(subtree, NullTVB,
                                        offset + OFF_MSG_TEXT + j,
                                        i - j,
                                        "%s: %s", auth_req_field_descr[n], msgText);
                } else {
                    proto_tree_add_text(subtree, NullTVB,
                                        offset + OFF_MSG_TEXT + j,
                                        i - j,
                                        "%s: %s", auth_req_field_descr[n], "(null)");
                }
                j = ++i;
                /* i and j point after the 0xfe character */
            }
        }    

	if (msgText != NULL)
	    g_free(msgText);
	break;
    case MSG_USER_ADDED:
	/* Four parts, separated by FE */
	i = 0;
	j = 0;
	/* This is necessary, because g_realloc does not behave like
	     * g_malloc if the first parameter == NULL */
	msgText = g_malloc(64);
        for (n = 0; n < 4 && i<left; n++) {
            while (i<left && pd[OFF_MSG_TEXT+i]!=0xfe)
                i++;
            if (i<=left) {
                /* pd[OFF_MSG_TEXT+i] == 0xfe */
                if (i!=j) {   
                    /* Otherwise, it'd be a null string */
                    msgText = g_realloc(msgText, i - j);
                    strncpy(msgText, pd + OFF_MSG_TEXT + j, i-j);
		    msgText[i-j] = '\0';
                    proto_tree_add_text(subtree, NullTVB,
                                        offset + OFF_MSG_TEXT + j,
                                        i - j,
                                        "%s: %s", auth_req_field_descr[n], msgText);
                } else {
                    proto_tree_add_text(subtree, NullTVB,
                                        offset + OFF_MSG_TEXT + j,
                                        i - j,
                                        "%s: %s", auth_req_field_descr[n], "(null)");
                }
                j = ++i;
                /* i and j point after the 0xfe character */
            }
        }    
	if (msgText != NULL)
	    g_free(msgText);
	break;
    case MSG_CONTACTS:
    {
	u_char* p = (u_char*) &pd[OFF_MSG_TEXT];
	u_char* pprev = p;
	int sz = 0;            /* Size of the current element */
	int n = 0;             /* The nth element */
	int done = 0;          /* Number of chars processed */
	u_char* msgText2 = NULL;
	msgText = NULL;
	/* Create a new subtree */
	subtree = proto_item_add_subtree(ti, ett_icq_body_parts);
	while (p!=NULL) {
	    p = strnchr(pprev, 0xfe, left);
	    
	    if (p!=NULL)
		sz = (int)(p - pprev);
	    else
		sz = left;
	    msgText = g_realloc(msgText, sz+1);
	    strncpy(msgText, pprev, sz);
	    msgText[sz] = '\0';
	    
	    if (n == 0) {
		/* The first element is the number of Nick/UIN pairs follow */
		proto_tree_add_text(subtree, NullTVB,
				    offset + OFF_MSG_TEXT + done,
				    sz,
				    "Number of pairs: %s", msgText);
		n++;
	    } else if (p!=NULL) {
		int svsz = sz;
		left -= (sz+1);
		pprev = p + 1;
		p = strnchr(pprev, 0xfe, left);
		if (p!=NULL)
		    sz = (int)(p - pprev);
		else
		    sz = left;
		msgText2 = g_malloc(sz+1);
		strncpy(msgText2, pprev, sz);
		msgText2[sz] = '\0';
		
		proto_tree_add_text(subtree, NullTVB,
				    offset + OFF_MSG_TEXT + done,
				    sz + svsz + 2,
				    "%s:%s", msgText, msgText2);
		n+=2;
		g_free(msgText2);
	    }
	    
	    left -= (sz+1);
	    pprev = p+1;
	}
	if (msgText != NULL)
	    g_free(msgText);
	break;
    }}
}

/*********************************
 * 
 * Client commands
 *
 *********************************/
static void
icqv5_cmd_ack(proto_tree* tree,/* Tree to put the data in */
		     const u_char* pd, /* Packet content */
		     int offset, /* Offset from the start of the packet to the content */
		     int size)	/* Number of chars left to do */
{
    guint32 random = pletohl(pd + CMD_ACK_RANDOM);
    proto_tree* subtree;
    proto_item* ti;

    if (tree){
	ti = proto_tree_add_uint_format(tree,
					hf_icq_cmd,
					NullTVB,
					offset,
					4,
					CMD_ACK,
					"Body");
	subtree = proto_item_add_subtree(ti, ett_icq_body);
	proto_tree_add_text(subtree, NullTVB,
			    offset + CMD_ACK_RANDOM,
			    4,
			    "Random: 0x%08x", random);
    }
}

static void
icqv5_cmd_rand_search(proto_tree* tree,       /* Tree to put the data in */
		      const u_char* pd,       /* Packet content */
		      int offset,             /* Offset from the start of the packet to the content */
		      int size)               /* Number of chars left to do */
{
    guint16 group = pletohs(pd + CMD_RAND_SEARCH_GROUP);
    proto_tree* subtree;
    proto_item* ti;

    static const char* groups[] = {
	"Name",
	"General",
	"Romance",
	"Games",
	"Students",
	"20 Something",
	"30 Something",
	"40 Something",
	"50 or worse",
	"Man want women",
	"Women want men"
    };
    
    if (tree){
	ti = proto_tree_add_uint_format(tree,
					hf_icq_cmd,
					NullTVB,
					offset,
					4,
					CMD_RAND_SEARCH,
					"Body");
	subtree = proto_item_add_subtree(ti, ett_icq_body);
	if (group>0 && (group<=sizeof(groups)/sizeof(const char*)))
	    proto_tree_add_text(subtree, NullTVB,
				offset + CMD_RAND_SEARCH_GROUP,
				4,
				"Group: (%u) %s", group, groups[group-1]);
	else
	    proto_tree_add_text(subtree, NullTVB,
				offset + CMD_RAND_SEARCH_GROUP,
				4,
				"Group: (%u)", group);
    }
}

static void
icqv5_cmd_ack_messages(proto_tree* tree,/* Tree to put the data in */
		       const u_char* pd,      /* Packet content */
		       int offset,              /* Offset from the start of the packet to the content */
		       int size)                  /* Number of chars left to do */
{
    guint32 random = pletohl(pd + CMD_ACK_MESSAGES_RANDOM);
    proto_tree* subtree;
    proto_item* ti;

    if (tree){
	ti = proto_tree_add_uint_format(tree,
					hf_icq_cmd,
					NullTVB,
					offset,
					4,
					CMD_ACK_MESSAGES,
					"Body");
	subtree = proto_item_add_subtree(ti, ett_icq_body);
	proto_tree_add_text(subtree, NullTVB,
			    offset + CMD_ACK_MESSAGES_RANDOM,
			    4,
			    "Random: 0x%08x", random);
    }
}

static void
icqv5_cmd_keep_alive(proto_tree* tree,/* Tree to put the data in */
		       const u_char* pd,      /* Packet content */
		       int offset,              /* Offset from the start of the packet to the content */
		       int size)                  /* Number of chars left to do */
{
    guint32 random = pletohl(pd + CMD_KEEP_ALIVE_RANDOM);
    proto_tree* subtree;
    proto_item* ti;

    if (tree){
	ti = proto_tree_add_uint_format(tree,
					hf_icq_cmd,
					NullTVB,
					offset,
					4,
					CMD_KEEP_ALIVE,
					"Body");
	subtree = proto_item_add_subtree(ti, ett_icq_body);
	proto_tree_add_text(subtree, NullTVB,
			    offset + CMD_KEEP_ALIVE_RANDOM,
			    4,
			    "Random: 0x%08x", random);
    }
}

static void
icqv5_cmd_send_text_code(proto_tree* tree,/* Tree to put the data in */
			 const u_char* pd,      /* Packet content */
			 int offset,              /* Offset from the start of the packet to the content */
			 int size)                  /* Number of chars left to do */
{
    proto_tree* subtree = NULL;
    proto_item* ti = NULL;
    guint16 len = 0;
    guint16 x1 = -1;
    char* text;
    int left = size;		/* The amount of data left to analyse */

    if (tree){
	ti = proto_tree_add_uint_format(tree,
					hf_icq_cmd,
					NullTVB,
					offset,
					left,
					CMD_KEEP_ALIVE,
					"Body");
    }

    if (left<sizeof(guint16))
	return;
    len = pletohs(pd+CMD_SEND_TEXT_CODE_LEN);
    left -= sizeof(gint16);
    if (tree){
	subtree = proto_item_add_subtree(ti, ett_icq_body);
	proto_tree_add_text(subtree, NullTVB,
			    offset + CMD_SEND_TEXT_CODE_LEN,
			    2,
			    "Length: %d", len);
    }

    if (len>0) {
	len = MIN(len, left);
	text = g_malloc(len+1);
	memcpy(text, pd + CMD_SEND_TEXT_CODE_TEXT, len);
	text[len] = '\0';
	left -= len;
	if (tree){
	    proto_tree_add_text(subtree, NullTVB,
			    offset + CMD_SEND_TEXT_CODE_TEXT,
			    len,
			    "Text: %s",text);
	}
	g_free(text);
    }

    if (left<sizeof(gint16))
	return;

    x1 = pletohs(pd + size - left);
    left -= sizeof(gint16);
    if (tree){
	proto_tree_add_text(subtree, NullTVB,
			    offset + CMD_SEND_TEXT_CODE_TEXT + len,
			    2,
			    "X1: 0x%04x", x1);
    }
}

static void
icqv5_cmd_add_to_list(proto_tree* tree,/* Tree to put the data in */
		      const u_char* pd,      /* Packet content */
		      int offset,            /* Offset from the start of the packet to the content */
		      int size)              /* Number of chars left to do */
{
    guint32 uin = -1;
    proto_tree* subtree;
    proto_item* ti;
    if (size>=4)
	uin = pletohl(pd + CMD_ADD_TO_LIST);
    if (tree){
	ti = proto_tree_add_uint_format(tree,
					hf_icq_cmd,
					NullTVB,
					offset,
					4,
					CMD_ADD_TO_LIST,
					"Body");
	subtree = proto_item_add_subtree(ti, ett_icq_body);
	proto_tree_add_text(subtree, NullTVB,
			    offset + CMD_ADD_TO_LIST_UIN,
			    4,
			    "UIN: %u", uin);
    }
}

static void
icqv5_cmd_status_change(proto_tree* tree,/* Tree to put the data in */
			const u_char* pd,       /* Packet content */
			int offset,                /* Offset from the start of the packet to the content */
			int size)                     /* Number of chars left to do */
{
    guint32 status = -1;
    proto_tree* subtree;
    proto_item* ti;

    if (size >= CMD_STATUS_CHANGE_STATUS + 4)
	status = pletohl(pd + CMD_STATUS_CHANGE_STATUS);
    if (tree){
	ti = proto_tree_add_uint_format(tree,
					hf_icq_cmd,
					NullTVB,
					offset,
					4,
					CMD_STATUS_CHANGE,
					"Body");
	subtree = proto_item_add_subtree(ti, ett_icq_body);
	if (status!=-1)
	    proto_tree_add_text(subtree, NullTVB,
				offset + CMD_STATUS_CHANGE_STATUS,
				4,
				"Status: %08x (%s)", status, findStatus(status));
    }
}

static void
icqv5_cmd_send_msg(proto_tree* tree,
		   const u_char* pd,
		   int offset,
		   int size,
		   int cmd)
{
    proto_tree* subtree;
    proto_item* ti;
    guint32 receiverUIN = 0xffffffff;
    guint16 msgType = 0xffff;
    guint16 msgLen = 0xffff;
    int left = size;		/* left chars to do */
    
    if (left < 4)
	return;
    receiverUIN = pletohl(pd + CMD_SEND_MSG_RECV_UIN);
    left -= 4;
    if (left < 2) 
	return;
    msgType = pletohs(pd + CMD_SEND_MSG_MSG_TYPE);
    left -= 2;
    if (left < 2) 
	return;
    msgLen = pletohs(pd + CMD_SEND_MSG_MSG_LEN);
    left -= 2;

    if (tree) {
	ti = proto_tree_add_uint_format(tree,
					hf_icq_cmd,
					NullTVB,
					offset,
					size,
					cmd,
					"Body");
	subtree = proto_item_add_subtree(ti, ett_icq_body);
	proto_tree_add_text(subtree, NullTVB,
			    offset + CMD_SEND_MSG_RECV_UIN,
			    4,
			    "Receiver UIN: %u", receiverUIN);
	proto_tree_add_text(subtree, NullTVB,
			    offset + CMD_SEND_MSG_MSG_LEN,
			    2,
			    "Length: %u", msgLen);

	icqv5_decode_msgType(subtree,
			     pd + CMD_SEND_MSG_MSG_TYPE,
			     offset + CMD_SEND_MSG_MSG_TYPE,
			     left+4); /* There are 4 bytes more... */
    }
}

static void
icqv5_cmd_login(proto_tree* tree,
		const u_char* pd,
		int offset,
		int size)
{
    proto_item* ti;
    proto_tree* subtree;
    time_t theTime = -1;
    guint32 port = -1;
    guint32 passwdLen = -1;
    char* password = NULL;
    const u_char *ipAddrp = NULL;
    guint32 status = -1;
    guint32 left = size;

    if (left>=4) {
	theTime = pletohl(pd + CMD_LOGIN_TIME);
    }
    if (left>=8) {
	port = pletohl(pd + CMD_LOGIN_PORT);
    }
    if (left>=10) {
	passwdLen = pletohs(pd + CMD_LOGIN_PASSLEN);
    }
    if (left>=10+passwdLen) {
	password = g_malloc(passwdLen + 1);
	strncpy(password, pd + CMD_LOGIN_PASSWD, passwdLen);
	password[passwdLen] = '\0';
    }

    if (left>=10+passwdLen+CMD_LOGIN_IP+4) {
	ipAddrp = pd + CMD_LOGIN_PASSWD + passwdLen + CMD_LOGIN_IP;
    }
    if (left>=10+passwdLen+CMD_LOGIN_STATUS+4) {
	status = pletohs(pd + CMD_LOGIN_PASSWD + passwdLen + CMD_LOGIN_STATUS);
    }
    if (tree) {
	ti = proto_tree_add_uint_format(tree,
					hf_icq_cmd,
					NullTVB,
					offset,
					size,
					CMD_SEND_MSG,
					"Body");
	subtree = proto_item_add_subtree(ti, ett_icq_body);
	if (theTime!=-1) {
	    char *aTime = ctime(&theTime);

	    aTime[strlen(aTime)-1] = '\0';
	    proto_tree_add_text(subtree, NullTVB,
				offset + CMD_LOGIN_TIME,
				4,
				"Time: %ld = %s", (long)theTime, aTime);
	}
	if (port!=-1)
	    proto_tree_add_text(subtree, NullTVB,
				offset + CMD_LOGIN_PORT,
				4,
				"Port: %u", port);
	if ((passwdLen!=-1) && (password!=NULL))
	    proto_tree_add_text(subtree, NullTVB,
				offset + CMD_LOGIN_PASSLEN,
				2 + passwdLen,
				"Passwd: %s", password);
	if (ipAddrp!=NULL)
	    proto_tree_add_text(subtree, NullTVB,
				offset + CMD_LOGIN_PASSWD + passwdLen + CMD_LOGIN_IP,
				4,
				"IP: %s", ip_to_str(ipAddrp));
	if (status!=-1)
	    proto_tree_add_text(subtree, NullTVB,
				offset + CMD_LOGIN_PASSWD + passwdLen + CMD_LOGIN_STATUS,
				4,
				"Status: %s", findStatus(status));
    }
    if (password!=NULL)
	g_free(password);
}

static void
icqv5_cmd_contact_list(proto_tree* tree,
		       const u_char* pd,
		       int offset,
		       int size)
{
    proto_tree* subtree;
    proto_item* ti;
    unsigned char num = -1;
    int i, left;
    guint32 uin;
    const u_char* p = NULL;

    if (size >= CMD_CONTACT_LIST_NUM + 1) 
	num = pd[CMD_CONTACT_LIST_NUM];

    if (tree) {
	ti = proto_tree_add_uint_format(tree,
					hf_icq_cmd,
					NullTVB,
					offset,
					size,
					CMD_CONTACT_LIST,
					"Body");
	subtree = proto_item_add_subtree(ti, ett_icq_body);
	proto_tree_add_text(subtree, NullTVB,
			    offset + CMD_CONTACT_LIST,
			    1,
			    "Number of uins: %u", num);
	/*
	 * A sequence of num times UIN follows
	 */
	offset += (CMD_CONTACT_LIST_NUM + 1);
	left = size;
	p = &pd[CMD_CONTACT_LIST_NUM + 1];
	for (i = 0; (i<num) && (left>0);i++) {
	    if (left>=4) {
		uin = pletohl(p);
		proto_tree_add_text(subtree, NullTVB,
				    offset,
				    4,
				    "UIN[%d]: %u",i,uin);
		p += 4;
		offset += 4;
		left -= 4;
	    }
	}
    }
}

static void
icqv5_cmd_no_params(proto_tree* tree,/* Tree to put the data in */
		    const u_char* pd,      /* Packet content */
		    int offset,            /* Offset from the start of the packet to the content */
		    int size,              /* Number of chars left to do */
		    int cmd)
{
    proto_tree* subtree;
    proto_item* ti;

    if (tree){
	ti = proto_tree_add_uint_format(tree,
					hf_icq_cmd,
					NullTVB,
					offset,
					0,
					cmd,
					"Body");
	subtree = proto_item_add_subtree(ti, ett_icq_body);
	proto_tree_add_text(subtree, NullTVB,
			    offset,
			    0,
			    "No parameters");
    }
}

/**********************
 *
 * Server commands
 *
 **********************
 */
static void
icqv5_srv_no_params(proto_tree* tree,/* Tree to put the data in */
		    const u_char* pd,      /* Packet content */
		    int offset,            /* Offset from the start of the packet to the content */
		    int size,              /* Number of chars left to do */
		    int cmd)
{
    proto_tree* subtree;
    proto_item* ti;

    if (tree){
	ti = proto_tree_add_uint_format(tree,
					hf_icq_cmd,
					NullTVB,
					offset,
					0,
					cmd,
					"Body");
	subtree = proto_item_add_subtree(ti, ett_icq_body);
	proto_tree_add_text(subtree, NullTVB,
			    offset,
			    0,
			    "No Parameters");
    }
}

static void
icqv5_srv_login_reply(proto_tree* tree,/* Tree to put the data in */
		      const u_char* pd,       /* Packet content */
		      int offset,                /* Offset from the start of the packet to the content */
		      int size)                     /* Number of chars left to do */
{
    proto_tree* subtree;
    proto_item* ti;
    const u_char *ipAddrp = NULL;

    if (size >= SRV_LOGIN_REPLY_IP + 4) 
	ipAddrp = &pd[SRV_LOGIN_REPLY_IP];

    if (tree) {
	ti = proto_tree_add_uint_format(tree,
					hf_icq_cmd,
					NullTVB,
					offset,
					SRV_LOGIN_REPLY_IP + 8,
					SRV_LOGIN_REPLY,
					"Body");
	subtree = proto_item_add_subtree(ti, ett_icq_body);
	proto_tree_add_text(subtree, NullTVB,
			    offset + SRV_LOGIN_REPLY_IP,
			    4,
			    "IP: %s", ip_to_str(ipAddrp));
    }
}

static void
icqv5_srv_user_online(proto_tree* tree,/* Tree to put the data in */
		      const u_char* pd,       /* Packet content */
		      int offset,                /* Offset from the start of the packet to the content */
		      int size)                     /* Number of chars left to do */
{
    proto_tree* subtree;
    proto_item* ti;
    guint32 uin = -1;
    const u_char *ipAddrp = NULL;
    guint32 port = -1;
    const u_char *realipAddrp = NULL;
    guint32 status = -1;
    guint32 version = -1;

    if (size >= SRV_USER_ONL_UIN + 4)
	uin = pletohl(pd + SRV_USER_ONL_UIN);
    
    if (size >= SRV_USER_ONL_IP + 4) 
	ipAddrp = &pd[SRV_USER_ONL_IP];

    if (size >= SRV_USER_ONL_PORT + 4)
	port = pletohl(pd + SRV_USER_ONL_PORT);

    if (size >= SRV_USER_ONL_REALIP + 4)
	realipAddrp = &pd[SRV_USER_ONL_REALIP];

    if (size >= SRV_USER_ONL_STATUS + 2)
	status = pletohs(pd + SRV_USER_ONL_STATUS);

    /*
     * Kojak: Hypothesis is that this field might be an encoding for the
     * version used by the UIN that changed. To test this, I included
     * this line to the code.
     */
    if (size >= SRV_USER_ONL_X2 + 4)
	version = pletohl(pd + SRV_USER_ONL_X2);

    if (tree) {
	ti = proto_tree_add_uint_format(tree,
					hf_icq_cmd,
					NullTVB,
					offset,
					SRV_LOGIN_REPLY_IP + 8,
					SRV_LOGIN_REPLY,
					"Body");
	subtree = proto_item_add_subtree(ti, ett_icq_body);
	proto_tree_add_text(subtree, NullTVB,
			    offset + SRV_USER_ONL_UIN,
			    4,
			    "UIN: %u", uin);
	proto_tree_add_text(subtree, NullTVB,
			    offset + SRV_USER_ONL_IP,
			    4,
			    "IP: %s", ip_to_str(ipAddrp));
	proto_tree_add_text(subtree, NullTVB,
			    offset + SRV_USER_ONL_PORT,
			    4,
			    "Port: %u", port);
	proto_tree_add_text(subtree, NullTVB,
			    offset + SRV_USER_ONL_REALIP,
			    4,
			    "RealIP: %s", ip_to_str(realipAddrp));
	proto_tree_add_text(subtree, NullTVB,
			    offset + SRV_USER_ONL_STATUS,
			    2,
			    "Status: %s", findStatus(status));
	proto_tree_add_text(subtree, NullTVB,
			    offset + SRV_USER_ONL_X2,
			    4,
			    "Version: %08x", version);
    }
}

static void
icqv5_srv_user_offline(proto_tree* tree,/* Tree to put the data in */
		      const u_char* pd,       /* Packet content */
		      int offset,                /* Offset from the start of the packet to the content */
		      int size)                     /* Number of chars left to do */
{
    proto_tree* subtree;
    proto_item* ti;
    guint32 uin = -1;

    if (size >= SRV_USER_OFFLINE + 4) 
	uin = pletohl(&pd[SRV_USER_OFFLINE]);

    if (tree) {
	ti = proto_tree_add_uint_format(tree,
					hf_icq_cmd,
					NullTVB,
					offset,
					SRV_USER_OFFLINE_UIN + 4,
					SRV_USER_OFFLINE,
					"Body");
	subtree = proto_item_add_subtree(ti, ett_icq_body);
	proto_tree_add_text(subtree, NullTVB,
			    offset + SRV_USER_OFFLINE_UIN,
			    4,
			    "UIN: %u", uin);
    }
}

static void
icqv5_srv_multi(proto_tree* tree,/* Tree to put the data in */
		const u_char* pd,      /* Packet content */
		int offset,            /* Offset from the start of the packet to the content */
		int size,              /* Number of chars left to do */
		frame_data* fd)
{
    proto_tree* subtree;
    proto_item* ti;
    unsigned char num = -1;
    guint16 pktSz;
    int i, left;
    const u_char* p = NULL;

    if (size >= SRV_MULTI_NUM + 1) 
	num = pd[SRV_MULTI_NUM];

    if (tree) {
	ti = proto_tree_add_uint_format(tree,
					hf_icq_cmd,
					NullTVB,
					offset,
					size,
					SRV_MULTI,
					"Body");
	subtree = proto_item_add_subtree(ti, ett_icq_body);
	proto_tree_add_text(subtree, NullTVB,
			    offset + SRV_MULTI_NUM,
			    1,
			    "Number of pkts: %u", num);
	/*
	 * A sequence of num times ( pktsize, packetData) follows
	 */
	offset += (SRV_MULTI_NUM + 1);
	left = size;
	p = &pd[SRV_MULTI_NUM + 1];
	for (i = 0; (i<num) && (left>0);i++) {
	    if (left>=2) {
		pktSz = pletohs(p);
		p += 2;
		offset += 2;
		left -= 2;
		if (left>=pktSz) {
		    dissect_icqv5Server(p, offset, fd, subtree, pktSz);
		    p += pktSz;
		    offset += pktSz;
		    left -= pktSz;
		}
	    }
	}
    }
}

static void
icqv5_srv_meta_user(proto_tree* tree,      /* Tree to put the data in */
		    const u_char* pd,      /* Packet content */
		    int offset,            /* Offset from the start of the packet to the content */
		    int size)              /* Number of chars left to do */
{
#if 0
    proto_tree* subtree = NULL;
#endif
    proto_tree* sstree = NULL;
    proto_item* ti = NULL;
    int left = size;
    const char* p = pd;

    guint16 subcmd = -1;
    unsigned char result = -1;

    if (size>=SRV_META_USER_SUBCMD + 2)
	subcmd = pletohs(pd+SRV_META_USER_SUBCMD);
    if (size>=SRV_META_USER_RESULT + 1)
	result = pd[SRV_META_USER_RESULT];

    if (tree) {
#if 0
	ti = proto_tree_add_uint_format(tree,
					hf_icq_cmd,
					NullTVB,
					offset,
					size,
					SRV_META_USER,
					"Body");
	subtree = proto_item_add_subtree(ti, ett_icq_body);
	ti = proto_tree_add_text(subtree, NullTVB,
				 offset + SRV_META_USER_SUBCMD,
				 2,
				 "%s", findSubCmd(subcmd));
	proto_tree_add_text(subtree, NullTVB,
			    offset + SRV_META_USER_RESULT,
			    1,
			    "%s", (result==0x0a)?"Success":"Failure");
	sstree = proto_item_add_subtree(ti, ett_icq_body_parts);
#else
	ti = proto_tree_add_text(tree, NullTVB,
				 offset + SRV_META_USER_SUBCMD,
				 2,
				 "%s", findSubCmd(subcmd));
	sstree = proto_item_add_subtree(ti, ett_icq_body_parts);
	proto_tree_add_text(sstree, NullTVB,
			    offset + SRV_META_USER_RESULT,
			    1,
			    "%s", (result==0x0a)?"Success":"Failure");
#endif

	/* Skip the META_USER header */
	left -= 3;
	p += 3;

	switch(subcmd) {
	case META_EX_USER_FOUND:
	{
	    /* This is almost the same as META_USER_FOUND,
	     * however, there's an extra length field
	     */
	    guint16 pktLen = -1;

	    /* Read the lenght field */
	    pktLen = pletohs(p);
	    proto_tree_add_text(sstree, NullTVB,
				offset + size - left,
				sizeof(guint16),
				"Length: %u", pktLen);
	    
	    p += sizeof(guint16); left -= sizeof(guint16);
	}
	case META_USER_FOUND:
	{
	    /* The goto mentioned in this block should be local to this
	     * block if C'd allow it.
	     *
	     * They are used to "implement" a poorman's exception handling
	     */
	    guint32 uin = -1;
	    int len = 0;
	    char *descr[] = {
		"Nick",
		"First name",
		"Last name",
		"Email",
		NULL};
	    char** d = descr;
	    guint16 x2 = -1;
	    guint32 x3 = -1;
	    unsigned char auth;
	    /*
	     * Read UIN
	     */
	    if (left<sizeof(guint32))
		break;
	    uin = pletohl(p);
	    proto_tree_add_text(sstree, NullTVB,
				offset + size - left,
				sizeof(guint32),
				"UIN: %u", uin);
	    p+=sizeof(guint32);left-=sizeof(guint32);

	    for ( ; *d!=NULL; d++) {
		len = proto_add_icq_attr(sstree,
					 p,
					 offset + size - left,
					 left,
					 *d);
		if (len == -1)
		    return;
		p += len; left -= len;
	    }
	    /* Get the authorize setting */
	    if (left<sizeof(unsigned char))
		break;
	    auth = *p;
	    proto_tree_add_text(sstree, NullTVB,
				offset + size - left,
				sizeof(guint16),
				"authorization: %s", (auth==0x01)?"Neccessary":"Who needs it");
	    p++; left--;
	    /* Get x2 */
	    if (left<sizeof(guint16))
		break;
	    x2 = pletohs(p);
	    proto_tree_add_text(sstree, NullTVB,
				offset + size - left,
				sizeof(guint16),
				"x2: %04x", x2);
	    p+=sizeof(guint16);left-=sizeof(guint16);
	    /* Get x3 */
	    if (left<sizeof(guint32))
		break;
	    x3 = pletohl(p);
	    proto_tree_add_text(sstree, NullTVB,
				offset + size - left,
				sizeof(guint32),
				"x3: %08x", x3);
	    p+=sizeof(guint32);left-=sizeof(guint32);
	    break;
	}
	case META_ABOUT:
	{
	    int len;
	    char* about = NULL;
	    /* Get the about information */
	    if (left<sizeof(guint16))
		break;
	    len = pletohs(p);
	    p+=sizeof(guint16);left-=sizeof(guint16);
	    if ((len<=0) || (left<len))
		break;
	    about = g_malloc(len);
	    strncpy(about, p, len);
	    proto_tree_add_text(sstree, NullTVB,
				offset + size - left,
				sizeof(guint16)+len,
				"About(%d): %s", len, about);
	    p+=len;left-=len;
	    left -= 3;
	    g_free(about);
	    break;
	}
	case META_USER_INFO:
	{
	    /* The goto mentioned in this block should be local to this
	     * block if C'd allow it.
	     *
	     * They are used to "implement" a poorman's exception handling
	     */
	    static const char* descr[] = {
		"Nick",
		"First name",
		"Last name",
		"Primary email",
		"Secundary email",
		"Old email",
		"City",
		"State",
		"Phone",
		"Fax",
		"Street",
		"Cellphone",
		"Zip",
		NULL};
	    const char** d = descr;
	    char* item = NULL;
	    guint16 country;
	    unsigned char user_timezone = -1;
	    unsigned char auth = -1;
	    int len = 0;
#if 0
	    /* Get the uin */
	    if (left<sizeof(guint32))
		break;
	    uin = pletohl(p);
	    proto_tree_add_text(sstree, NullTVB,
				offset + size - left,
				sizeof(guint32),
				"UIN: %u", uin);
	    p+=sizeof(guint32);left-=sizeof(guint32);
#endif
	    
	    /*
	     * Get every field from the description
	     */
	    while ((*d)!=NULL) {
		if (left<sizeof(guint16))
		    break;
		len = pletohs(p);
		p+=sizeof(guint16);left-=sizeof(guint16);
		if ((len<0) || (left<len))
		    break;
		if (len>0) {
		    item = g_malloc(len);
		    strncpy(item, p, len);
		    proto_tree_add_text(sstree, NullTVB,
					offset + size - left - sizeof(guint16),
					sizeof(guint16)+len,
					"%s(%d): %s",*d, len, item);
		    g_free(item);
		    p+=len;left-=len;
		}
		d++;
	    }
	    /* Get country code */
	    if (left<sizeof(guint16))
		break;
	    country = pletohs(p);
	    proto_tree_add_text(sstree, NullTVB,
				offset + size - left,
				sizeof(guint16),
				"Countrycode: %u", country);
	    p+=sizeof(guint16); left-=sizeof(guint16);
	    /* Get the timezone setting */
	    if (left<sizeof(unsigned char))
		break;
	    user_timezone = *p;
	    proto_tree_add_text(sstree, NullTVB,
				offset + size - left,
				sizeof(unsigned char),
				"Timezone: %u", user_timezone);
	    p++; left--;
	    /* Get the authorize setting */
	    if (left<sizeof(unsigned char))
		break;
	    auth = *p;
	    proto_tree_add_text(sstree, NullTVB,
				offset + size - left,
				sizeof(unsigned char),
				"Authorization: (%u) %s",
				auth, (auth==0)?"No":"Yes");
	    p++; left--;
	    /* Get the webaware setting */
	    if (left<sizeof(unsigned char))
		break;
	    auth = *p;
	    proto_tree_add_text(sstree, NullTVB,
				offset + size - left,
				sizeof(unsigned char),
				"Webaware: (%u) %s",
				auth, (auth==0)?"No":"Yes");
	    p++; left--;
	    /* Get the authorize setting */
	    if (left<sizeof(unsigned char))
		break;
	    auth = *p;
	    proto_tree_add_text(sstree, NullTVB,
				offset + size - left,
				sizeof(unsigned char),
				"HideIP: (%u) %s",
				auth, (auth==0)?"No":"Yes");
	    p++; left--;
	    break;
	}
	default:
	    /* This information is already printed in the tree */
	    fprintf(stderr, "Meta subcmd: %04x\n", subcmd);
	    break;
	}
    }
}

static void
icqv5_srv_recv_message(proto_tree* tree,      /* Tree to put the data in */
		       const u_char* pd,      /* Packet content */
		       int offset,            /* Offset from the start of the packet to the content */
		       int size)              /* Number of chars left to do */
{
    proto_tree* subtree = NULL;
    proto_item* ti = NULL;
    int left = size;
    guint32 uin = -1;
    guint16 year = -1;
    unsigned char month = -1;
    unsigned char day = -1;
    unsigned char hour = -1;
    unsigned char minute = -1;
    
    if (tree) {
	ti = proto_tree_add_uint_format(tree,
					hf_icq_cmd,
					NullTVB,
					offset,
					4,
					SRV_RECV_MESSAGE,
					"Body");
	subtree = proto_item_add_subtree(ti, ett_icq_body);
	if (left>=sizeof(guint32)) {
	    uin = pletohl(pd + SRV_RECV_MSG_UIN);
	    proto_tree_add_uint_format(subtree,
				       hf_icq_uin,
				       NullTVB,
				       offset + SRV_RECV_MSG_UIN,
				       sizeof(guint32),
				       uin,
				       "UIN: %u", uin);
	    left -= sizeof(guint32);
	} else
	    return;
	if (left>=(sizeof(guint16)+4*sizeof(unsigned char))) {
	    year = pletohs(pd + SRV_RECV_MSG_YEAR);
	    month = pd[SRV_RECV_MSG_MONTH];
	    day = pd[SRV_RECV_MSG_DAY];
	    hour = pd[SRV_RECV_MSG_HOUR];
	    minute = pd[SRV_RECV_MSG_MINUTE];

	    proto_tree_add_text(subtree, NullTVB,
				offset + SRV_RECV_MSG_YEAR,
				sizeof(guint16) + 4*sizeof(unsigned char),
				"Time: %u-%u-%u %02u:%02u",
				day, month, year, hour, minute);
	    
	    left -= (sizeof(guint16)+4*sizeof(unsigned char));
	} else
	    return;
	icqv5_decode_msgType(subtree,
			     pd + SRV_RECV_MSG_MSG_TYPE,
			     offset + SRV_RECV_MSG_MSG_TYPE,
			     left);
    }
}

static void
icqv5_srv_rand_user(proto_tree* tree,      /* Tree to put the data in */
		       const u_char* pd,      /* Packet content */
		       int offset,            /* Offset from the start of the packet to the content */
		       int size)              /* Number of chars left to do */
{
    proto_tree* subtree = NULL;
    proto_item* ti = NULL;
    guint32 uin = -1;
    const unsigned char* IP = NULL;
    guint32 port = -1;
    const unsigned char* realIP = NULL;
    unsigned char commClass = -1;
    guint32 status;
    guint16 tcpVer;
    int left = size;
    
    if (tree) {
	ti = proto_tree_add_uint_format(tree,
					hf_icq_cmd,
					NullTVB,
					offset,
					SRV_RAND_USER_TCP_VER + 2,
					SRV_RAND_USER,
					"Body");
	subtree = proto_item_add_subtree(ti, ett_icq_body);
	/* guint32 UIN */
	if (left<sizeof(guint32))
	    return;
	uin = pletohl(pd + SRV_RAND_USER_UIN);
	proto_tree_add_text(subtree, NullTVB,
			    offset + SRV_RAND_USER_UIN,
			    sizeof(guint32),
			    "UIN: %u", uin);
	left -= sizeof(guint32);
	/* guint32 IP */
	if (left<sizeof(guint32))
	    return;
	IP = pd + SRV_RAND_USER_IP;
	proto_tree_add_text(subtree, NullTVB,
			    offset + SRV_RAND_USER_IP,
			    sizeof(guint32),
			    "IP: %s", ip_to_str(IP));
	left -= sizeof(guint32);
	/* guint32 portNum */
	if (left<sizeof(guint32))
	    return;
	port = pletohs(pd + SRV_RAND_USER_PORT);
	proto_tree_add_text(subtree, NullTVB,
			    offset + SRV_RAND_USER_UIN,
			    sizeof(guint32),
			    "Port: %u", port);
	left -= sizeof(guint32);
	/* guint32 realIP */			    
	if (left<sizeof(guint32))
	    return;
	realIP = pd + SRV_RAND_USER_REAL_IP;
	proto_tree_add_text(subtree, NullTVB,
			    offset + SRV_RAND_USER_REAL_IP,
			    sizeof(guint32),
			    "RealIP: %s", ip_to_str(realIP));
	left -= sizeof(guint32);
	/* guit16 Communication Class */
	if (left<sizeof(unsigned char))
	    return;
	commClass = pd[SRV_RAND_USER_CLASS];
	proto_tree_add_text(subtree, NullTVB,
			    offset + SRV_RAND_USER_CLASS,
			    sizeof(unsigned char),
			    "Class: %s", (commClass!=4)?"User to User":"Through Server");
	left -= sizeof(unsigned char);
	/* guint32 status */
	if (left<sizeof(guint32))
	    return;
	status = pletohs(pd + SRV_RAND_USER_STATUS);
	proto_tree_add_text(subtree, NullTVB,
			    offset + SRV_RAND_USER_STATUS,
			    sizeof(guint32),
			    "Status: (%u) %s", status, findStatus(status));
	/* guint16 tcpVersion */
	if (left<sizeof(guint16))
	    return;
	tcpVer = pletohs(pd + SRV_RAND_USER_TCP_VER);
	proto_tree_add_text(subtree, NullTVB,
			    offset + SRV_RAND_USER_TCP_VER,
			    sizeof(guint16),
			    "TCPVersion: %u", tcpVer);
	left -= sizeof(guint16);
    }
}

/*
 * Dissect all the v5 client traffic. This is encrypted, so be careful.
 */
static void
dissect_icqv5Client(const u_char *pd,
		    int offset,
		    frame_data *fd, 
		    proto_tree *tree)
{
    proto_tree *icq_tree = NULL;
    proto_tree *icq_header_tree = NULL;
    proto_tree *icq_decode_tree = NULL;
    proto_item *ti = NULL;

    guint16 version = -1, cmd = -1;
    guint16 seqnum1 = 0 , seqnum2 = 0;
    guint32 uin = -1, sessionid = -1;
    guint32 key = -1;
    guint16 pktsize = -1;		/* The size of the ICQ content */
    static u_char *decr_pd = NULL;	/* Decrypted content */
    static int decr_size = 0;		/* Size of decrypted-content buffer */
    
    pktsize = END_OF_FRAME;

    if (decr_size == 0 ) {
        decr_size = sizeof(u_char) * 128;
	decr_pd = g_malloc(decr_size);
    }
    	
    while (decr_size < pktsize + 3) {
        decr_size *= 2;
	decr_pd = g_realloc(decr_pd, decr_size);
    }
    
    /* First copy the memory, we don't want to overwrite the old content */
    memcpy(decr_pd, &pd[offset], pktsize);
    if (pktsize>0x14) {
	key = get_v5key(decr_pd, pktsize);
	decrypt_v5(decr_pd, pktsize, key);
    
	/* This information only makes sense in the decrypted version */
	uin = pletohl(&decr_pd[ICQ5_CL_UIN]);
	cmd = pletohs(&decr_pd[ICQ5_CL_CMD]);
	sessionid = pletohl(&decr_pd[ICQ5_CL_SESSIONID]);
	version = pletohs(&decr_pd[ICQ_VERSION]);
	seqnum1 = pletohs(&decr_pd[ICQ5_CL_SEQNUM1]);
	seqnum2 = pletohs(&decr_pd[ICQ5_CL_SEQNUM2]);

	if (check_col(fd, COL_INFO))
	    col_add_fstr(fd, COL_INFO, "ICQv5 %s", findClientCmd(cmd));
    }
    
    if (tree) {
        ti = proto_tree_add_protocol_format(tree,
				 proto_icq,
				 NullTVB,
				 offset,
				 pktsize,
				 "ICQv5 %s (len %u)",
				 findClientCmd(cmd),
				 pktsize);
        icq_tree = proto_item_add_subtree(ti, ett_icq);
	ti = proto_tree_add_uint_format(icq_tree,
					hf_icq_type,
					NullTVB,
					offset,
					ICQ5_CL_HDRSIZE,
					ICQ5_client,
					"Header");
	icq_header_tree = proto_item_add_subtree(ti, ett_icq_header);
					
	proto_tree_add_text(icq_header_tree, NullTVB,
			    offset + ICQ_VERSION,
			    2,
			    "Version: %u", version);
	proto_tree_add_uint_format(icq_header_tree,
				   hf_icq_uin,
				   NullTVB,
				   offset+ICQ5_CL_UIN,
				   4,
				   uin,
				   "UIN: %u (0x%08X)",
				   uin, uin);
	proto_tree_add_uint_format(icq_header_tree,
				   hf_icq_sessionid,
				   NullTVB,
				   offset+ICQ5_CL_SESSIONID,
				   4,
				   sessionid,
				   "Session ID: 0x%08x",
				   sessionid);
	proto_tree_add_text(icq_header_tree, NullTVB,
			    offset + ICQ5_CL_CMD,
			    2,
			    "Command: %s (%u)", findClientCmd(cmd), cmd);
	proto_tree_add_text(icq_header_tree, NullTVB,
			    offset + ICQ5_CL_SEQNUM1,
			    2,
			    "Seq Number 1: 0x%04x", seqnum1);
	proto_tree_add_text(icq_header_tree, NullTVB,
			    offset + ICQ5_CL_SEQNUM2,
			    2,
			    "Seq Number 2: 0x%04x", seqnum2);
	proto_tree_add_uint_format(icq_header_tree,
				   hf_icq_checkcode,
				   NullTVB,
				   offset+ICQ5_CL_CHECKCODE,
				   4,
				   key,
				   "Key: 0x%08x",
				   key);
	switch(cmd) {
	case CMD_ACK:
	    icqv5_cmd_ack(icq_tree,
			  decr_pd + ICQ5_CL_HDRSIZE,
			  offset + ICQ5_CL_HDRSIZE,
			  pktsize - ICQ5_CL_HDRSIZE);
	    break;
	case CMD_SEND_MSG:
	case CMD_MSG_TO_NEW_USER:
	    icqv5_cmd_send_msg(icq_tree,
			       decr_pd + ICQ5_CL_HDRSIZE,
			       offset + ICQ5_CL_HDRSIZE,
			       pktsize - ICQ5_CL_HDRSIZE,
			       cmd);
	    break;
	case CMD_RAND_SEARCH:
	    icqv5_cmd_rand_search(icq_tree,
				  decr_pd + ICQ5_CL_HDRSIZE,
				  offset + ICQ5_CL_HDRSIZE,
				  pktsize - ICQ5_CL_HDRSIZE);
	    break;
	case CMD_LOGIN:
	    icqv5_cmd_login(icq_tree,
			    decr_pd + ICQ5_CL_HDRSIZE,
			    offset + ICQ5_CL_HDRSIZE,
			    pktsize - ICQ5_CL_HDRSIZE);
	    break;
	case CMD_SEND_TEXT_CODE:
	    icqv5_cmd_send_text_code(icq_tree,
				     decr_pd + ICQ5_CL_HDRSIZE,
				     offset + ICQ5_CL_HDRSIZE,
				     pktsize - ICQ5_CL_HDRSIZE);
	    break;
	case CMD_STATUS_CHANGE:
	    icqv5_cmd_status_change(icq_tree,
				    decr_pd + ICQ5_CL_HDRSIZE,
				    offset + ICQ5_CL_HDRSIZE,
				    pktsize - ICQ5_CL_HDRSIZE);
	    break;
	case CMD_ACK_MESSAGES:
	    icqv5_cmd_ack_messages(icq_tree,
				   decr_pd + ICQ5_CL_HDRSIZE,
				   offset + ICQ5_CL_HDRSIZE,
				   pktsize - ICQ5_CL_HDRSIZE);
	    break;
	case CMD_KEEP_ALIVE:
	    icqv5_cmd_keep_alive(icq_tree,
				 decr_pd + ICQ5_CL_HDRSIZE,
				 offset + ICQ5_CL_HDRSIZE,
				 pktsize - ICQ5_CL_HDRSIZE);
	    break;
	case CMD_ADD_TO_LIST:
	    icqv5_cmd_add_to_list(icq_tree,
				   decr_pd + ICQ5_CL_HDRSIZE,
				   offset + ICQ5_CL_HDRSIZE,
				   pktsize - ICQ5_CL_HDRSIZE);
	    break;
	case CMD_CONTACT_LIST:
	    icqv5_cmd_contact_list(icq_tree,
				   decr_pd + ICQ5_CL_HDRSIZE,
				   offset + ICQ5_CL_HDRSIZE,
				   pktsize - ICQ5_CL_HDRSIZE);
	    break;
	case CMD_META_USER:
	case CMD_REG_NEW_USER:
	case CMD_QUERY_SERVERS:
	case CMD_QUERY_ADDONS:
	    icqv5_cmd_no_params(icq_tree,
				decr_pd + ICQ5_CL_HDRSIZE,
				offset + ICQ5_CL_HDRSIZE,
				pktsize - ICQ5_CL_HDRSIZE,
				cmd);
	    break;
	default:
	    proto_tree_add_uint_format(icq_tree,
				       hf_icq_cmd,
				       NullTVB,
				       offset+ICQ5_CL_CMD,
				       2,
				       cmd,
				       "Command: %u (%s)",
				       cmd, findClientCmd(cmd));
	    fprintf(stderr,"Missing: %s\n", findClientCmd(cmd));
	    break;
	}
	ti = proto_tree_add_text(icq_tree, NullTVB,
				 offset,
				 pktsize,
				 "Decoded packet");
        icq_decode_tree = proto_item_add_subtree(ti,
						 ett_icq_decode);
	proto_tree_add_hexdump(icq_decode_tree, offset, decr_pd, pktsize);

    }
}

static void
dissect_icqv5Server(const u_char *pd,
		    int offset,
		    frame_data *fd, 
		    proto_tree *tree,
		    guint32 pktsize)
{
    /* Server traffic is easy, not encrypted */
    proto_tree *icq_tree = NULL;
    proto_tree *icq_header_tree = NULL;
    proto_item *ti = NULL;
    const u_char* decr_pd;
    int changeCol = (pktsize==(guint32)-1);

    guint16 version, cmd;
    guint32 uin, sessionid;
    guint16 seqnum1, seqnum2;
    guint32 checkcode;
    
    uin = pletohl(&pd[ICQ5_SRV_UIN]);
    sessionid = pletohl(&pd[ICQ5_SRV_SESSIONID]);
    cmd = pletohs(&pd[ICQ5_SRV_CMD]);
    version = pletohs(&pd[ICQ_VERSION]);
    checkcode = pletohl(&pd[ICQ5_SRV_CHECKCODE]);
    seqnum1 = pletohs(&pd[ICQ5_SRV_SEQNUM1]);
    seqnum2 = pletohs(&pd[ICQ5_SRV_SEQNUM2]);
    if (pktsize == -1)
	pktsize = END_OF_FRAME;
    decr_pd = pd;
    
    if (changeCol && check_col(fd, COL_INFO))
	col_add_fstr(fd, COL_INFO, "ICQv5 %s", findServerCmd(cmd));

    if (tree) {
        ti = proto_tree_add_protocol_format(tree,
					proto_icq,
					NullTVB,
					offset,
					pktsize,
					"ICQv5 %s (len %u)",
					findServerCmd(cmd),
					pktsize);
	
        icq_tree = proto_item_add_subtree(ti, ett_icq);

	ti = proto_tree_add_uint_format(icq_tree,
					hf_icq_type,
					NullTVB,
					offset,
					ICQ5_SRV_HDRSIZE,
					ICQ5_server,
					"Header");
	icq_header_tree = proto_item_add_subtree(ti, ett_icq_header);
					
	proto_tree_add_text(icq_header_tree, NullTVB,
			    offset + ICQ_VERSION,
			    2,
			    "Version: %u", version);
	proto_tree_add_uint_format(icq_header_tree,
				   hf_icq_sessionid,
				   NullTVB,
				   offset+ICQ5_SRV_SESSIONID,
				   4,
				   sessionid,
				   "Session ID: 0x%08x",
				   sessionid);
	proto_tree_add_text(icq_header_tree, NullTVB,
			    offset + ICQ5_SRV_CMD,
			    2,
			    "Command: %s (%u)", findServerCmd(cmd), cmd);
	proto_tree_add_text(icq_header_tree, NullTVB,
			    offset + ICQ5_SRV_SEQNUM1,
			    2,
			    "Seq Number 1: 0x%04x", seqnum1);
	proto_tree_add_text(icq_header_tree, NullTVB,
			    offset + ICQ5_SRV_SEQNUM2,
			    2,
			    "Seq Number 2: 0x%04x", seqnum2);
	proto_tree_add_uint_format(icq_header_tree,
				   hf_icq_uin,
				   NullTVB,
				   offset+ICQ5_SRV_UIN,
				   4,
				   uin,
				   "UIN: %u",
				   uin);
	proto_tree_add_uint_format(icq_header_tree,
				   hf_icq_checkcode,
				   NullTVB,
				   offset+ICQ5_SRV_CHECKCODE,
				   4,
				   checkcode,
				   "Checkcode: 0x%08x",
				   checkcode);
	switch (cmd) {
	case SRV_RAND_USER:
	    icqv5_srv_rand_user(icq_tree,
			       decr_pd + ICQ5_SRV_HDRSIZE,
			       offset + ICQ5_SRV_HDRSIZE,
			       pktsize - ICQ5_SRV_HDRSIZE);
	    break;
	case SRV_SYS_DELIVERED_MESS:
	    /* The message structures are all the same. Why not run
	     * the same routine? */
	    icqv5_cmd_send_msg(icq_tree,
			       decr_pd + ICQ5_SRV_HDRSIZE,
			       offset + ICQ5_SRV_HDRSIZE,
			       pktsize - ICQ5_SRV_HDRSIZE,
			       cmd);
	    break;
	case SRV_USER_ONLINE:
	    icqv5_srv_user_online(icq_tree,
			       decr_pd + ICQ5_SRV_HDRSIZE,
			       offset + ICQ5_SRV_HDRSIZE,
			       pktsize - ICQ5_SRV_HDRSIZE);
	    break;
	case SRV_USER_OFFLINE:
	    icqv5_srv_user_offline(icq_tree,
			       decr_pd + ICQ5_SRV_HDRSIZE,
			       offset + ICQ5_SRV_HDRSIZE,
			       pktsize - ICQ5_SRV_HDRSIZE);
	    break;
	case SRV_LOGIN_REPLY:
	    icqv5_srv_login_reply(icq_tree,
			       decr_pd + ICQ5_SRV_HDRSIZE,
			       offset + ICQ5_SRV_HDRSIZE,
			       pktsize - ICQ5_SRV_HDRSIZE);
	    break;
	case SRV_META_USER:
	    icqv5_srv_meta_user(icq_tree,
			       decr_pd + ICQ5_SRV_HDRSIZE,
			       offset + ICQ5_SRV_HDRSIZE,
			       pktsize - ICQ5_SRV_HDRSIZE);
	    break;
	case SRV_RECV_MESSAGE:
	    icqv5_srv_recv_message(icq_tree,
				   decr_pd + ICQ5_SRV_HDRSIZE,
				   offset + ICQ5_SRV_HDRSIZE,
				   pktsize - ICQ5_SRV_HDRSIZE);
	    break;
	case SRV_MULTI:
	    icqv5_srv_multi(icq_tree,
			    decr_pd + ICQ5_SRV_HDRSIZE,
			    offset + ICQ5_SRV_HDRSIZE,
			    pktsize - ICQ5_SRV_HDRSIZE,
			    fd);
	    break;
	case SRV_ACK:
	case SRV_SILENT_TOO_LONG:
	case SRV_GO_AWAY:
	case SRV_NEW_UIN:
	case SRV_BAD_PASS:
	case SRV_UPDATE_SUCCESS:
	    icqv5_srv_no_params(icq_tree,
				decr_pd + ICQ5_SRV_HDRSIZE,
				offset + ICQ5_SRV_HDRSIZE,
				pktsize - ICQ5_SRV_HDRSIZE,
				cmd);
	    break;
	default:
	    proto_tree_add_uint_format(icq_tree,
				       hf_icq_cmd,
				       NullTVB,
				       offset + ICQ5_SRV_CMD,
				       2,
				       cmd,
				       "Command: %u (%s)",
				       cmd, findServerCmd(cmd));
	    fprintf(stderr,"Missing: %s\n", findServerCmd(cmd));
	    break;
	}
    }
}

static void dissect_icqv5(const u_char *pd,
			  int offset,
			  frame_data *fd, 
			  proto_tree *tree)
{
  guint32 unknown = pletohl(&pd[offset + ICQ5_UNKNOWN]);
  
  if (check_col(fd, COL_PROTOCOL))
      col_set_str(fd, COL_PROTOCOL, "ICQv5 (UDP)");
  if (check_col(fd, COL_INFO))
      col_set_str(fd, COL_INFO, "ICQv5 packet");
  if (unknown == 0x0L) {
      dissect_icqv5Client(pd, offset, fd, tree);
  } else {
      dissect_icqv5Server(pd + offset, offset, fd, tree, (guint32) -1);
  }
}

static void dissect_icq(const u_char *pd,
			int offset,
			frame_data *fd, 
			proto_tree *tree)
{
  int version = 0;

  OLD_CHECK_DISPLAY_AS_DATA(proto_icq, pd, offset, fd, tree);

  version = pletohs(&pd[offset + ICQ_VERSION]);
  switch (version) {
  case 0x0005:
      dissect_icqv5(pd, offset, fd, tree);
      break;
  case 0x0004:
      dissect_icqv4(pd, offset, fd, tree);
      break;
  case 0x0003:
      dissect_icqv3(pd, offset, fd, tree);
      break;
  case 0x0002:
      dissect_icqv2(pd, offset, fd, tree);
      break;
  default:
      fprintf(stderr, "ICQ: Unknown version (%d)\n", version);
      break;
  }
}

/* registration with the filtering engine */
void
proto_register_icq(void)
{
    static hf_register_info hf[] = {
	{ &hf_icq_type,
	  {"Type", "icq.type", FT_UINT16, BASE_DEC, NULL, 0x0, ""}},
	{ &hf_icq_uin,
	  {"UIN", "icq.uin", FT_UINT32, BASE_DEC, NULL, 0x0, ""}},
	{ &hf_icq_sessionid,
	  {"SessionID", "icq.sessionid", FT_UINT32, BASE_HEX, NULL, 0x0, ""}},
	{ &hf_icq_cmd,
	  {"Command", "icq.cmd", FT_UINT16, BASE_DEC, NULL, 0x0, ""}},
	{ &hf_icq_checkcode,
	  {"Checkcode", "icq.checkcode", FT_UINT32, BASE_HEX, NULL, 0x0, ""}},
	{ &hf_icq_decode,
	  {"Decode", "icq.decode", FT_STRING, BASE_NONE, NULL, 0x0, ""}}
    };
    static gint *ett[] = {
        &ett_icq,
        &ett_icq_header,
        &ett_icq_decode,
        &ett_icq_body,
        &ett_icq_body_parts,
    };
    
    proto_icq = proto_register_protocol ("ICQ Protocol", "icq");
    
    proto_register_field_array(proto_icq, hf, array_length(hf));

    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_icq(void)
{
    old_dissector_add("udp.port", UDP_PORT_ICQ, dissect_icq);
}
