/* packet-icq.c
 * Routines for ICQ packet disassembly
 *
 * $Id: packet-icq.c,v 1.3 1999/10/25 20:32:52 guy Exp $
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
#include <string.h>
#include <glib.h>

#ifdef NEED_SNPRINTF_H
# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# else
#  include <varargs.h>
# endif
# include "snprintf.h"
#endif

#include "packet.h"
#include "resolv.h"

int proto_icq = -1;
int hf_icq_uin =-1;
int hf_icq_cmd =-1;
int hf_icq_sessionid =-1;
int hf_icq_checkcode =-1;
int hf_icq_decode = -1;

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

cmdcode serverCmdCode[] = {
    { "SRV_ACK", 10 },
    { "SRV_GO_AWAY", 40 },
    { "SRV_NEW_UIN", 70 },
    { "SRV_LOGIN_REPLY", 90 },
    { "SRV_BAD_PASS", 100 },
    { "SRV_USER_ONLINE", 110 },
    { "SRV_USER_OFFLINE", 120 },
    { "SRV_QUERY", 130 },
    { "SRV_USER_FOUND", 140 },
    { "SRV_END_OF_SEARCH", 160 },
    { "SRV_NEW_USER", 180 },
    { "SRV_UPDATE_EXT", 200 },
    { "SRV_RECV_MESSAGE", 220 },
    { "SRV_X2", 230 },
    { "SRV_NOT_CONNECTED", 240 },
    { "SRV_TRY_AGAIN", 250 },
    { "SRV_SYS_DELIVERED_MESS", 260 },
    { "SRV_INFO_REPLY", 280 },
    { "SRV_EXT_INFO_REPLY", 290 },
    { "SRV_STATUS_UPDATE", 420 },
    { "SRV_SYSTEM_MESSAGE", 450 },
    { "SRV_UPDATE_SUCCESS", 480 },
    { "SRV_UPDATE_FAIL", 490 },
    { "SRV_AUTH_UPDATE", 500 },
    { "SRV_MULTI_PACKET", 530 },
    { "SRV_X1", 540 },
    { "SRV_RAND_USER", 590 },
    { "SRV_META_USER", 990 },
    { NULL, 0 }
};

#define MSG_TEXT		0x0001
#define MSG_URL			0x0004
#define MSG_AUTH_REQ		0x0006
#define MSG_AUTH		0x0008
#define MSG_USER_ADDED		0x000c
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


cmdcode msgTypeCode[] = {
    { "MSG_TEXT", MSG_TEXT },
    { "MSG_URL", MSG_URL },
    { "MSG_AUTH_REQ", MSG_AUTH_REQ },
    { "MSG_AUTH", MSG_AUTH },
    { "MSG_USER_ADDED", MSG_USER_ADDED},
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
    { "CMD_REG_NEW_USER", 1020 },
    { "CMD_CONTACT_LIST", 1030 },
    { "CMD_SEARCH_UIN", 1050 },
    { "CMD_SEARCH_USER", 1060 },
    { "CMD_KEEP_ALIVE", 1070 },
    { "CMD_SEND_TEXT_CODE", 1080 },
    { "CMD_ACK_MESSAGES", 1090 },
    { "CMD_LOGIN_1", 1100 },
    { "CMD_MSG_TO_NEW_USER", 1110 },
    { "CMD_INFO_REQ", 1120 },
    { "CMD_EXT_INFO_REQ", 1130 },
    { "CMD_CHANGE_PW", 1180 },
    { "CMD_NEW_USER_INFO", 1190 },
    { "CMD_UPDATE_EXT_INFO", 1200 },
    { "CMD_QUERY_SERVERS", 1210 },
    { "CMD_QUERY_ADDONS", 1220 },
    { "CMD_STATUS_CHANGE", 1240 },
    { "CMD_NEW_USER_1", 1260 },
    { "CMD_UPDATE_INFO", 1290 },
    { "CMD_AUTH_UPDATE", 1300 },
    { "CMD_KEEP_ALIVE2", 1310 },
    { "CMD_LOGIN_2", 1320 },
    { "CMD_ADD_TO_LIST", 1340 },
    { "CMD_RAND_SET", 1380 },
    { "CMD_RAND_SEARCH", 1390 },
    { "CMD_META_USER", 1610 },
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
	proto_tree_add_text(t,
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
	proto_tree_add_text(t,
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
dissect_icqv2(const u_char *pd,
	      int offset,
	      frame_data *fd, 
	      proto_tree *tree)
{
    /* Not really implemented yet */
    if (check_col(fd, COL_PROTOCOL)) {
	col_add_str(fd, COL_PROTOCOL, "ICQv2 (UDP)");
    }
    if (check_col(fd, COL_INFO)) {
	col_add_str(fd, COL_INFO, "ICQ Version 2 protocol");
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
	ti = proto_tree_add_item_format(tree,
					hf_icq_cmd,
					offset,
					4,
					CMD_ACK,
					"%s : %d",
					findClientCmd(CMD_ACK),
					CMD_ACK);
	subtree = proto_item_add_subtree(ti, ETT_ICQ_SUBTREE);
	proto_tree_add_text(subtree,
			    offset + CMD_ACK_RANDOM,
			    4,
			    "Random: 0x%08lx", random);
    }
}

static void
icqv5_cmd_send_msg(proto_tree* tree,
		   const u_char* pd,
		   int offset,
		   int size)
{
    proto_tree* subtree;
    proto_item* ti;
    guint32 receiverUIN = 0xffffffff;
    guint16 msgType = 0xffff;
    guint16 msgLen = 0xffff;
    u_char* msgText = NULL;
    int left = size;		/* left chars to do */
    int i,n,j;
    static char* auth_req_field_descr[] = {
	"Nickname",
	"First name",
	"Last name",
	"Email address",
	"Reason"};
    
    if (left >= 4) {
	receiverUIN = pletohl(pd + CMD_SEND_MSG_RECV_UIN);
	left -= 4;
    }
    if (left >= 2) {
	msgType = pletohs(pd + CMD_SEND_MSG_MSG_TYPE);
	left -= 2;
    }
    if (left >= 2) {
	msgLen = pletohs(pd + CMD_SEND_MSG_MSG_LEN);
	left -= 2;
    }
    if (tree) {
	ti = proto_tree_add_item_format(tree,
					hf_icq_cmd,
					offset,
					size,
					CMD_SEND_MSG,
					"Body");
	subtree = proto_item_add_subtree(ti, ETT_ICQ_SUBTREE);
	proto_tree_add_text(subtree,
			    offset + CMD_SEND_MSG_RECV_UIN,
			    4,
			    "Receiver UIN: %ld", receiverUIN);
	ti = proto_tree_add_text(subtree,
				 offset + CMD_SEND_MSG_MSG_TYPE,
				 2,
				 "Type: %d (%s)", msgType, findMsgType(msgType));
	proto_tree_add_text(subtree,
			    offset + CMD_SEND_MSG_MSG_LEN,
			    2,
			    "Length: %d", msgLen);

	/* It's silly to do anything if there's nothing left */
	if (left==0)
	    return;
	if (msgLen == 0)
	    return;
	/* Create a subtree for every message type */
	switch(msgType) {
	case 0xffff:		/* Field unknown */
	    break;
	case MSG_TEXT:
	    msgText = g_malloc(left + 1);
	    strncpy(msgText, pd + CMD_SEND_MSG_MSG_TEXT, left);
	    msgText[left] = '\0';
	    proto_tree_add_text(subtree,
				offset + CMD_SEND_MSG_MSG_TEXT,
				left,
				"Msg: %s", msgText);
	    g_free(msgText);
	    break;
	case MSG_URL:
	    /* Two parts, a description and the URL. Separeted by FE */
	    for (i=0;i<left;i++) {
		if (pd[CMD_SEND_MSG_MSG_TEXT + i] == 0xfe)
		    break;
	    }
	    msgText = g_malloc(i + 1);
	    strncpy(msgText, pd + CMD_SEND_MSG_MSG_TEXT, i);
	    if (i==left)
		msgText[i] = '\0';
	    else
		msgText[i-1] = '\0';
	    proto_tree_add_text(subtree,
				offset + CMD_SEND_MSG_MSG_TEXT,
				i,
				"Description: %s", msgText);
	    if (i==left)
		break;
	    msgText = g_realloc(msgText, left - i);
	    strncpy(msgText, pd + CMD_SEND_MSG_MSG_TEXT + i + 1, left - i - 1);
	    msgText[left - i] = '\0';
	    proto_tree_add_text(subtree,
				offset + CMD_SEND_MSG_MSG_TEXT,
				i,
				"URL: %s", msgText);
	    g_free(msgText);
	    break;
	case MSG_AUTH_REQ:
	    /* Five parts, separated by FE */
	    i = 0;
	    j = 0;
	    msgText = NULL;
	    for (n = 0; n < 5; n++) {
		for (;
		     (i<left) && (pd[CMD_SEND_MSG_MSG_TEXT+i]!=0xfe);
		     i++)
		    ;
		msgText = g_realloc(msgText, i-j);
		strncpy(msgText, pd + CMD_SEND_MSG_MSG_TEXT + j, i - j - 1);
		msgText[i-j-1] = '\0';
		proto_tree_add_text(subtree,
				    offset + CMD_SEND_MSG_MSG_TEXT + j,
				    i - j - 1,
				    "%s: %s", auth_req_field_descr[n], msgText);
		j = ++i;
	    }
	    if (msgText != NULL)
		g_free(msgText);
	    break;
	case MSG_USER_ADDED:
	    /* Create a new subtree */
	    subtree = proto_item_add_subtree(ti, ETT_ICQ_SUBTREE);
	    /* Four parts, separated by FE */
	    i = 0;
	    j = 0;
            /* This is necessary, because g_realloc does not behave like
	     * g_malloc if the first parameter == NULL */
	    msgText = g_malloc(64);
	    for (n = 0; n < 4; n++) {
		for (;
		     (i<left) && (pd[CMD_SEND_MSG_MSG_TEXT+i]!=0xfe);
		     i++)
		    ;
		msgText = g_realloc(msgText, i-j+1);
		strncpy(msgText, pd + CMD_SEND_MSG_MSG_TEXT + j, i - j);
		msgText[i-j] = '\0';
		proto_tree_add_text(subtree,
				    offset + CMD_SEND_MSG_MSG_TEXT + j,
				    i - j,
				    "%s: %s", auth_req_field_descr[n], msgText);
		j = ++i;
	    }
	    if (msgText != NULL)
		g_free(msgText);
	    break;
	case MSG_CONTACTS:
	{
	    u_char* p = (u_char*) &pd[CMD_SEND_MSG_MSG_TEXT];
	    u_char* pprev = p;
	    int sz = 0;		/* Size of the current element */
	    int n = 0;		/* The nth element */
	    int done = 0;	/* Number of chars processed */
	    u_char* msgText2 = NULL;
	    msgText = NULL;
	    /* Create a new subtree */
	    subtree = proto_item_add_subtree(ti, ETT_ICQ_SUBTREE);
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
		    proto_tree_add_text(subtree,
					offset + CMD_SEND_MSG_MSG_TEXT + done,
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

		    proto_tree_add_text(subtree,
					offset + CMD_SEND_MSG_MSG_TEXT + done,
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
	ti = proto_tree_add_item_format(tree,
					hf_icq_cmd,
					offset,
					size,
					CMD_SEND_MSG,
					"Body");
	subtree = proto_item_add_subtree(ti, ETT_ICQ_SUBTREE);
	if (theTime!=-1)
	    proto_tree_add_text(subtree,
				offset + CMD_LOGIN_TIME,
				4,
				"Time: %d = %s", theTime, ctime(&theTime));
	if (port!=-1)
	    proto_tree_add_text(subtree,
				offset + CMD_LOGIN_PORT,
				4,
				"Port: %d", port);
	if ((passwdLen!=-1) && (password!=NULL))
	    proto_tree_add_text(subtree,
				offset + CMD_LOGIN_PASSLEN,
				2 + passwdLen,
				"Passwd: %s", password);
	if (ipAddrp!=NULL)
	    proto_tree_add_text(subtree,
				offset + CMD_LOGIN_PASSWD + CMD_LOGIN_IP,
				4,
				"IP: %s", ip_to_str(ipAddrp));
	if (status!=-1)
	    proto_tree_add_text(subtree,
				offset + CMD_LOGIN_PASSWD + CMD_LOGIN_IP,
				4,
				"Status: %s", findStatus(status));
    }
    if (password!=NULL)
	g_free(password);
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
    guint16 pktsize = -1;	/* The size of the ICQ content */
    u_char decr_pd[1600];	/* Decrypted content, size should be dynamic */
    
    pktsize = fd->pkt_len - offset;
    /* First copy the memory, we don't want to overwrite the old content */
    memcpy(decr_pd, &pd[offset], pktsize);
    if (fd->pkt_len > fd->cap_len) {
	pktsize -= (fd->pkt_len - fd->cap_len);
    }
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
        ti = proto_tree_add_item_format(tree,
				 proto_icq,
				 offset,
				 pktsize, NULL,
				 "ICQv5 %s (len %d)",
				 findClientCmd(cmd),
				 pktsize);
        icq_tree = proto_item_add_subtree(ti, ETT_CL_ICQ);
	ti = proto_tree_add_text(icq_tree,
				 offset,
				 ICQ5_CL_HDRSIZE,
				 "Header");
	icq_header_tree = proto_item_add_subtree(ti, ETT_ICQ_SUBTREE);
					
	proto_tree_add_item_format(icq_header_tree,
				   hf_icq_sessionid,
				   offset+ICQ5_CL_SESSIONID,
				   4,
				   sessionid,
				   "Session ID: 0x%08x",
				   sessionid);
	proto_tree_add_item_format(icq_header_tree,
				   hf_icq_checkcode,
				   offset+ICQ5_CL_CHECKCODE,
				   4,
				   key,
				   "Key: 0x%08x",
				   key);
	proto_tree_add_item_format(icq_header_tree,
				   hf_icq_uin,
				   offset+ICQ5_CL_UIN,
				   4,
				   uin,
				   "UIN: %ld (0x%08X)",
				   uin, uin);
	proto_tree_add_text(icq_header_tree,
			    offset + ICQ5_CL_SEQNUM1,
			    2,
			    "Seqnum1: 0x%04x", seqnum1);
	proto_tree_add_text(icq_header_tree,
			    offset + ICQ5_CL_SEQNUM1,
			    2,
			    "Seqnum2: 0x%04x", seqnum2);
	switch(cmd) {
	case CMD_ACK:
	    icqv5_cmd_ack(icq_tree,
			  decr_pd + ICQ5_CL_HDRSIZE,
			  offset + ICQ5_CL_HDRSIZE,
			  pktsize - ICQ5_CL_HDRSIZE);
	    break;
	case CMD_SEND_MSG:
	    icqv5_cmd_send_msg(icq_tree,
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
	default:
	    proto_tree_add_item_format(icq_tree,
				       hf_icq_cmd,
				       offset+ICQ5_CL_CMD,
				       2,
				       cmd,
				       "Command: %d (%s)", cmd, findcmd(clientCmdCode, cmd));
	    break;
	}
	ti = proto_tree_add_text(icq_tree,
				 offset,
				 pktsize,
				 "Decoded packet");
        icq_decode_tree = proto_item_add_subtree(ti,
						 ETT_CL_ICQ_DECODE);
	proto_tree_add_hexdump(icq_decode_tree, offset, decr_pd, pktsize);

    }
}

static void
dissect_icqv5Server(const u_char *pd,
		    int offset,
		    frame_data *fd, 
		    proto_tree *tree)
{
    /* Server traffic is easy, not encrypted */
    proto_tree *icq_tree = NULL;
    proto_tree *icq_decode_tree = NULL;
    proto_item *ti = NULL;

    guint16 version, cmd;
    guint32 uin, sessionid;
    guint32 pktsize;
    
    uin = pletohl(&pd[offset + ICQ5_SRV_UIN]);
    cmd = pletohs(&pd[offset + ICQ5_SRV_CMD]);
    sessionid = pletohl(&pd[offset + ICQ5_SRV_SESSIONID]);
    version = pletohs(&pd[offset + ICQ_VERSION]);
    pktsize = fd->pkt_len - offset;
    
    if (check_col(fd, COL_INFO))
	col_add_fstr(fd, COL_INFO, "ICQv5 %s", findServerCmd(cmd));

    if (tree) {
        ti = proto_tree_add_item_format(tree,
					proto_icq,
					offset,
					pktsize,
					NULL,
					"ICQv5 Server: len %d", pktsize);
	
        icq_tree = proto_item_add_subtree(ti, ETT_SRV_ICQ);
	proto_tree_add_item_format(icq_tree,
				   hf_icq_cmd,
				   offset + ICQ5_SRV_CMD,
				   2,
				   cmd,
				   "Command: %d (%s)",
				   cmd, findServerCmd(cmd));
	proto_tree_add_item_format(icq_tree,
				   hf_icq_uin,
				   offset+ICQ5_SRV_UIN,
				   4,
				   uin,
				   "UIN: %ld",
				   uin);
	proto_tree_add_item_format(icq_tree,
				   hf_icq_sessionid,
				   offset+ICQ5_SRV_SESSIONID,
				   4,
				   sessionid,
				   "Session ID: 0x%08x",
				   sessionid);
	ti = proto_tree_add_text(icq_tree,
				 offset,
				 pktsize,
				 "Decoded packet");
        icq_decode_tree = proto_item_add_subtree(ti,
						 ETT_CL_ICQ_DECODE);
	proto_tree_add_hexdump(icq_decode_tree, offset, pd+offset, pktsize);
    }
}

void dissect_icqv5(const u_char *pd,
		   int offset,
		   frame_data *fd, 
		   proto_tree *tree)
{
  guint32 unknown = pletohl(&pd[offset + ICQ5_UNKNOWN]);
  
  if (check_col(fd, COL_PROTOCOL))
      col_add_str(fd, COL_PROTOCOL, "ICQv5 (UDP)");
  if (check_col(fd, COL_INFO))
      col_add_str(fd, COL_INFO, "ICQv5 packet");
  if (unknown == 0x0L) {
      dissect_icqv5Client(pd, offset, fd, tree);
  } else {
      dissect_icqv5Server(pd, offset, fd, tree);
  }
}

void dissect_icq(const u_char *pd,
		 int offset,
		 frame_data *fd, 
		 proto_tree *tree)
{
  int version = 0;

  version = pletohs(&pd[offset + ICQ_VERSION]);
  switch (version) {
  case 0x0005:
      dissect_icqv5(pd, offset, fd, tree);
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
    
    proto_icq = proto_register_protocol ("ICQ Protocol", "icq");
    
    proto_register_field_array(proto_icq, hf, array_length(hf));
}
