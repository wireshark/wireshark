/* packet-icq.c
 * Routines for ICQ packet disassembly
 *
 * $Id: packet-icq.c,v 1.1 1999/10/24 00:55:49 guy Exp $
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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include <glib.h>
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

cmdcode clientCmdCode[] = {
    { "CMD_ACK", 10 },
    { "CMD_SEND_MESSAGE", 270 },
    { "CMD_LOGIN", 1000 },
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

typedef struct {
    u_int32_t random;
} cl_cmd_ack;

typedef struct _cl_cmd_send_msg {
#define MSG_TEXT	0x0100
#define MSG_URL		0x0400
#define MSG_AUTH_REQ	0x0600
#define MSG_AUTH	0x0800
#define MSG_USER_ADDED	0x0c00
#define MSG_CONTACTS	0x1300
    u_int32_t receiverUIN;
    u_int16_t msgType;
    u_int16_t msgLen;
    /*
     * Followed by char[msgLen]
     */
} cl_cmd_send_msg;

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
    while (p->code != 0) {
	if (p->code == num) {
	    return p->descr;
	}
	p++;
    }
    snprintf(buf, sizeof(buf), "(%x)", num);
    return buf;
}

void
proto_tree_add_hexdump(proto_tree* t,
		       u_int32_t offset,
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

static u_int32_t
get_v5key(const u_char* pd, int len)
{
    u_int32_t a1, a2, a3, a4, a5;
    u_int32_t code, check, key;

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
decrypt_v5(u_char *bfr, u_int32_t size,u_int32_t key)
{
    u_int32_t i;
    u_int32_t k;
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
 * Dissect all the v5 client traffic. This is encrypted, so be careful.
 */
static void
dissect_icqv5Client(const u_char *pd,
		    int offset,
		    frame_data *fd, 
		    proto_tree *tree)
{
    proto_tree *icq_tree = NULL;
    proto_tree *icq_decode_tree = NULL;
    proto_item *ti = NULL;

    u_int16_t version = -1, cmd = -1;
    u_int16_t seqnum1 = 0 , seqnum2 = 0;
    u_int32_t uin = -1, sessionid = -1;
    u_int32_t key = -1;
    u_int16_t pktsize = -1;	/* The size of the ICQ content */
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
    }
    
    if (tree) {
        ti = proto_tree_add_item_format(tree,
				 proto_icq,
				 offset,
				 pktsize, NULL,
				 "ICQv5 Client: len %d", pktsize);
        icq_tree = proto_item_add_subtree(ti, ETT_CL_ICQ);
	proto_tree_add_item_format(icq_tree,
				   hf_icq_cmd,
				   offset+ICQ5_CL_CMD,
				   2,
				   cmd,
				   "Command: %d (%s)", cmd, findcmd(clientCmdCode, cmd));
	proto_tree_add_item_format(icq_tree,
				   hf_icq_sessionid,
				   offset+ICQ5_CL_SESSIONID,
				   4,
				   sessionid,
				   "Session ID: 0x%08x",
				   sessionid);
	proto_tree_add_item_format(icq_tree,
				   hf_icq_checkcode,
				   offset+ICQ5_CL_CHECKCODE,
				   4,
				   key,
				   "Key: 0x%08x",
				   key);
	proto_tree_add_item_format(icq_tree,
				   hf_icq_uin,
				   offset+ICQ5_CL_UIN,
				   4,
				   uin,
				   "UIN: %ld (0x%08X)",
				   uin, uin);
	proto_tree_add_text(icq_tree,
			    offset + ICQ5_CL_SEQNUM1,
			    2,
			    "Seqnum1: 0x%04x", seqnum1);
	proto_tree_add_text(icq_tree,
			    offset + ICQ5_CL_SEQNUM1,
			    2,
			    "Seqnum2: 0x%04x", seqnum2);
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

    u_int16_t version, cmd;
    u_int32_t uin, sessionid;
    u_int32_t pktsize;
    
    uin = pletohl(&pd[offset + ICQ5_SRV_UIN]);
    cmd = pletohs(&pd[offset + ICQ5_SRV_CMD]);
    sessionid = pletohl(&pd[offset + ICQ5_SRV_SESSIONID]);
    version = pletohs(&pd[offset + ICQ_VERSION]);
    pktsize = fd->pkt_len - offset;
    
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
				   cmd, findcmd(serverCmdCode, cmd));
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
  u_int32_t unknown = pletohl(&pd[offset + ICQ5_UNKNOWN]);
  
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
      fprintf(stderr, "ICQ: Unknown version\n");
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
