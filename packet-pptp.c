/* packet-pptp.c
 * Routines for the Point-to-Point Tunnelling Protocol (PPTP) (RFC 2637)
 * Brad Robel-Forrest <brad.robel-forrest@watchguard.com>
 *
 * $Id: packet-pptp.c,v 1.13 2000/11/19 08:54:02 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <stdio.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <glib.h>
#include "packet.h"

static int proto_pptp = -1;
static int hf_pptp_message_type = -1;

static gint ett_pptp = -1;

#define TCP_PORT_PPTP			1723

#define MAGIC_COOKIE		0x1A2B3C4D

#define NUM_MSG_TYPES		3
#define msgtype2str(t)	\
  ((t < NUM_MSG_TYPES) ? msgtypestr[t] : "UNKNOWN-MESSAGES-TYPE")

static const char *msgtypestr[NUM_MSG_TYPES] = {
  "UNKNOWN-MESSAGE-TYPE",
  "CONTROL-MESSAGE",
  "MANAGEMENT-MESSAGE"
};

#define NUM_FRAME_TYPES		4
#define frametype2str(t)	\
  ((t < NUM_FRAME_TYPES) ? frametypestr[t] : "UNKNOWN-FRAMING-TYPE")

static const char *frametypestr[NUM_FRAME_TYPES] = {
  "UNKNOWN-FRAMING-TYPE",
  "ASYNCHRONOUS",
  "SYNCHRONOUS",
  "EITHER"
};

#define NUM_BEARER_TYPES	4
#define bearertype2str(t)	\
  ((t < NUM_BEARER_TYPES) ? bearertypestr[t] : "UNKNOWN-BEARER-TYPE")

static const char *bearertypestr[NUM_BEARER_TYPES] = {
  "UNKNOWN-BEARER-TYPE",
  "ANALOG",
  "DIGITAL",
  "EITHER"
};

#define NUM_CNTRLRESULT_TYPES	6
#define cntrlresulttype2str(t)	\
  ((t < NUM_CNTRLRESULT_TYPES) ? cntrlresulttypestr[t] : "UNKNOWN-CNTRLRESULT-TYPE")

static const char *cntrlresulttypestr[NUM_CNTRLRESULT_TYPES] = {
  "UNKNOWN-CNTRLRESULT-TYPE",
  "SUCCESS",
  "GENERAL-ERROR",
  "COMMAND-CHANNEL-EXISTS",
  "NOT-AUTHORIZED",
  "VERSION-NOT-SUPPORTED"
};

#define NUM_ERROR_TYPES		7
#define errortype2str(t)	\
  ((t < NUM_ERROR_TYPES) ? errortypestr[t] : "UNKNOWN-ERROR-TYPE")

static const char *errortypestr[NUM_ERROR_TYPES] = {
  "NONE",
  "NOT-CONNECTED",
  "BAD-FORMAT",
  "BAD-VALUE",
  "NO-RESOURCE",
  "BAD-CALL-ID",
  "PAC-ERROR"
};

#define NUM_REASON_TYPES	4
#define reasontype2str(t)	\
  ((t < NUM_REASON_TYPES) ? reasontypestr[t] : "UNKNOWN-REASON-TYPE")

static const char *reasontypestr[NUM_REASON_TYPES] = {
  "UNKNOWN-REASON-TYPE",
  "NONE",
  "STOP-PROTOCOL",
  "STOP-LOCAL-SHUTDOWN"
};

#define NUM_STOPRESULT_TYPES	3
#define stopresulttype2str(t)	\
  ((t < NUM_STOPRESULT_TYPES) ? stopresulttypestr[t] : "UNKNOWN-STOPRESULT-TYPE")

static const char *stopresulttypestr[NUM_STOPRESULT_TYPES] = {
  "UNKNOWN-STOPRESULT-TYPE",
  "SUCCESS",
  "GENERAL-ERROR"
};

#define NUM_ECHORESULT_TYPES	3
#define echoresulttype2str(t)	\
  ((t < NUM_ECHORESULT_TYPES) ? echoresulttypestr[t] : "UNKNOWN-ECHORESULT-TYPE")

static const char *echoresulttypestr[NUM_ECHORESULT_TYPES] = {
  "UNKNOWN-ECHORESULT-TYPE",
  "SUCCESS",
  "GENERAL-ERROR"
};

#define NUM_OUTRESULT_TYPES	8
#define outresulttype2str(t)	\
  ((t < NUM_OUTRESULT_TYPES) ? outresulttypestr[t] : "UNKNOWN-OUTRESULT-TYPE")

static const char *outresulttypestr[NUM_OUTRESULT_TYPES] = {
  "UNKNOWN-OUTRESULT-TYPE",
  "CONNECTED",
  "GENERAL-ERROR",
  "NO-CARRIER",
  "BUSY",
  "NO-DIAL-TONE",
  "TIME-OUT",
  "DO-NOT-ACCEPT"
};

#define NUM_INRESULT_TYPES	4
#define inresulttype2str(t)	\
  ((t < NUM_INRESULT_TYPES) ? inresulttypestr[t] : "UNKNOWN-INRESULT-TYPE")

static const char *inresulttypestr[NUM_INRESULT_TYPES] = {
  "UNKNOWN-INRESULT-TYPE",
  "CONNECT",
  "GENERAL-ERROR",
  "DO-NOT-ACCEPT"
};

#define NUM_DISCRESULT_TYPES	5
#define discresulttype2str(t)	\
  ((t < NUM_DISCRESULT_TYPES) ? discresulttypestr[t] : "UNKNOWN-DISCRESULT-TYPE")

static const char *discresulttypestr[NUM_DISCRESULT_TYPES] = {
  "UNKNOWN-DISCRESULT-TYPE",
  "LOST-CARRIER",
  "GENERAL-ERROR",
  "ADMIN-SHUTDOWN",
  "REQUEST"
};

static void dissect_unknown(const u_char *, int, frame_data *, proto_tree *);
static void dissect_cntrl_req(const u_char *, int, frame_data *, proto_tree *);
static void dissect_cntrl_reply(const u_char *, int, frame_data *, proto_tree *);
static void dissect_stop_req(const u_char *, int, frame_data *, proto_tree *);
static void dissect_stop_reply(const u_char *, int, frame_data *, proto_tree *);
static void dissect_echo_req(const u_char *, int, frame_data *, proto_tree *);
static void dissect_echo_reply(const u_char *, int, frame_data *, proto_tree *);
static void dissect_out_req(const u_char *, int, frame_data *, proto_tree *);
static void dissect_out_reply(const u_char *, int, frame_data *, proto_tree *);
static void dissect_in_req(const u_char *, int, frame_data *, proto_tree *);
static void dissect_in_reply(const u_char *, int, frame_data *, proto_tree *);
static void dissect_in_connected(const u_char *, int, frame_data *, proto_tree *);
static void dissect_clear_req(const u_char *, int, frame_data *, proto_tree *);
static void dissect_disc_notify(const u_char *, int, frame_data *, proto_tree *);
static void dissect_error_notify(const u_char *, int, frame_data *, proto_tree *);
static void dissect_set_link(const u_char *, int, frame_data *, proto_tree *);

#define NUM_CNTRL_TYPES		16
#define cntrltype2str(t)	\
  ((t < NUM_CNTRL_TYPES) ? strfuncs[t].str : "UNKNOWN-CONTROL-TYPE")

static struct strfunc {
  const char *	str;
  void          (*func)(const u_char *, int, frame_data *, proto_tree *);
} strfuncs[NUM_CNTRL_TYPES] = {
  {"UNKNOWN-CONTROL-TYPE",    dissect_unknown      },
  {"START-CONTROL-REQUEST",   dissect_cntrl_req    },
  {"START-CONTROL-REPLY",     dissect_cntrl_reply  },
  {"STOP-CONTROL-REQUEST",    dissect_stop_req     },
  {"STOP-CONTROL-REPLY",      dissect_stop_reply   },
  {"ECHO-REQUEST",            dissect_echo_req     },
  {"ECHO-REPLY",              dissect_echo_reply   },
  {"OUTGOING-CALL-REQUEST",   dissect_out_req      },
  {"OUTGOING-CALL-REPLY",     dissect_out_reply    },
  {"INCOMING-CALL-REQUEST",   dissect_in_req       },
  {"INCOMING-CALL-REPLY",     dissect_in_reply     },
  {"INCOMING-CALL-CONNECTED", dissect_in_connected },
  {"CLEAR-CALL-REQUEST",      dissect_clear_req    },
  {"DISCONNECT-NOTIFY",       dissect_disc_notify  },
  {"ERROR-NOTIFY",            dissect_error_notify },
  {"SET-LINK",                dissect_set_link     }
};

struct pptp_hdr
{
  guint16	len;
  guint16	type;
  guint32	cookie;
  guint16	cntrl_type;
  guint16	resv;
};

struct cntrl_req
{
  guint8	major_ver;
  guint8	minor_ver;
  guint16	resv;
  guint32	frame;
  guint32	bearer;
  guint16	max_chan;
  guint16	firm_rev;
  guint8	host[64];
  guint8	vendor[64];
};

struct cntrl_reply
{
  guint8	major_ver;
  guint8	minor_ver;
  guint8	result;
  guint8	error;
  guint32	frame;
  guint32	bearer;
  guint16	max_chan;
  guint16	firm_rev;
  guint8	host[64];
  guint8	vendor[64];
};

struct stop_req
{
  guint8	reason;
  guint8	resv0;
  guint16	resv1;
};

struct stop_reply
{
  guint8	result;
  guint8	error;
  guint16	resv;
};

struct echo_req
{
  guint32	ident;
};

struct echo_reply
{
  guint32	ident;
  guint8	result;
  guint8	error;
  guint16	resv;
};

struct out_req
{
  guint16	call_id;
  guint16	call_serial;
  guint32	min_bps;
  guint32	max_bps;
  guint32	bearer;
  guint32	frame;
  guint16	win_size;
  guint16	delay;
  guint16	phone_len;
  guint16	resv;
  guint8	phone[64];
  guint8	subaddr[64];
};

struct out_reply
{
  guint16	call_id;
  guint16	peer_id;
  guint8	result;
  guint8	error;
  guint16	cause;
  guint32	speed;
  guint16	win_size;
  guint16	delay;
  guint32	channel_id;
};

struct in_req
{
  guint16	call_id;
  guint16	call_serial;
  guint32	bearer;
  guint32	channel_id;
  guint16	dialed_len;
  guint16	dialing_len;
  guint8	dialed[64];
  guint8	dialing[64];
  guint8	subaddr[64];
};

struct in_reply
{
  guint16	call_id;
  guint16	peer_id;
  guint8	result;
  guint8	error;
  guint16	win_size;
  guint16	delay;
  guint16	resv;
};

struct in_connected
{
  guint16	peer_id;
  guint16	resv;
  guint32	speed;
  guint16	win_size;
  guint16	delay;
  guint32	frame;
};

struct clear_req
{
  guint16	call_id;
  guint16	resv;
};

struct disc_notify
{
  guint16	call_id;
  guint8	result;
  guint8	error;
  guint16	cause;
  guint16	resv;
  guint8	stats[128];
};

struct error_notify
{
  guint16	peer_id;
  guint16	resv;
  guint32	crc;
  guint32	frame;
  guint32	hardware;
  guint32	buffer;
  guint32	timeout;
  guint32	alignment;
};

struct set_link
{
  guint16	peer_id;
  guint16	resv;
  guint32	send_acm;
  guint32	recv_acm;
};

static void
dissect_pptp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

  struct pptp_hdr *	hdr = (struct pptp_hdr *)(pd + offset);
  guint16		len;
  guint16		cntrl_type;

  OLD_CHECK_DISPLAY_AS_DATA(proto_pptp, pd, offset, fd, tree);

  if (check_col(fd, COL_PROTOCOL))
    col_set_str(fd, COL_PROTOCOL, "PPTP");
  
  len	     = pntohs(&hdr->len);
  cntrl_type = pntohs(&hdr->cntrl_type);

  if (check_col(fd, COL_INFO))
    col_add_fstr(fd, COL_INFO, "%s", cntrltype2str(cntrl_type));
    
  if (IS_DATA_IN_FRAME(offset) && tree) {
    guint16		msg_type;
    guint32		cookie;
    proto_item *	ti;
    proto_tree *	pptp_tree;

    ti = proto_tree_add_item(tree, proto_pptp, NullTVB, offset, len, FALSE);
    pptp_tree = proto_item_add_subtree(ti, ett_pptp);
    
    proto_tree_add_text(pptp_tree, NullTVB, offset, sizeof(hdr->len), 
			"Length: %u", len);
    offset += sizeof(hdr->len);

    msg_type = pntohs(&hdr->type);
    proto_tree_add_uint_format(pptp_tree, hf_pptp_message_type, NullTVB,
			       offset, sizeof(hdr->type), 
			       msg_type,
			       "Message type: %s (%u)", 
			       msgtype2str(msg_type), msg_type);
    
    offset += sizeof(hdr->type);

    cookie = pntohl(&hdr->cookie);

    if (cookie == MAGIC_COOKIE)
      proto_tree_add_text(pptp_tree, NullTVB, offset, sizeof(hdr->cookie),
			  "Cookie: %#08x (correct)", cookie);
    else
      proto_tree_add_text(pptp_tree, NullTVB, offset, sizeof(hdr->cookie),
			  "Cookie: %#08x (incorrect)", cookie);
    offset += sizeof(hdr->cookie);
    
    proto_tree_add_text(pptp_tree, NullTVB, offset, sizeof(hdr->cntrl_type),
			"Control type: %s (%u)", cntrltype2str(cntrl_type), cntrl_type);
    offset += sizeof(hdr->cntrl_type);

    proto_tree_add_text(pptp_tree, NullTVB, offset, sizeof(hdr->resv),
			"Reserved: %u", pntohs(&hdr->resv));
    offset += sizeof(hdr->resv);

    if (cntrl_type < NUM_CNTRL_TYPES)
      ( *(strfuncs[cntrl_type].func))(pd, offset, fd, pptp_tree);
    else
      old_dissect_data(pd, offset, fd, pptp_tree);
  }
}

static void
dissect_unknown(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  old_dissect_data(pd, offset, fd, tree);
}

static void
dissect_cntrl_req(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

  struct cntrl_req *	hdr = (struct cntrl_req *)(pd + offset);
  guint32		frame;
  guint32		bearer;
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->major_ver) + sizeof(hdr->minor_ver), 
		      "Protocol version: %u.%u", hdr->major_ver, hdr->minor_ver );
  offset += sizeof(hdr->major_ver) + sizeof(hdr->minor_ver);

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->resv),
		      "Reserved: %u", pntohs(&hdr->resv));
  offset += sizeof(hdr->resv);

  frame = pntohl(&hdr->frame);
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->frame),
		      "Framing capabilities: %s (%u)", frametype2str(frame), frame);
  offset += sizeof(hdr->frame);

  bearer = pntohl(&hdr->bearer);
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->bearer),
		      "Bearer capabilities: %s (%u)", bearertype2str(bearer), bearer);
  offset += sizeof(hdr->bearer);

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->max_chan),
		      "Maximum channels: %u", pntohs(&hdr->max_chan));
  offset += sizeof(hdr->max_chan);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->firm_rev),
		      "Firmware revision: %u", pntohs(&hdr->firm_rev));
  offset += sizeof(hdr->firm_rev);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->host),
		      "Hostname: %s", hdr->host);
  offset += sizeof(hdr->host);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->vendor),
		      "Vendor: %s", hdr->vendor);
}

static void
dissect_cntrl_reply(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  struct cntrl_reply *	hdr = (struct cntrl_reply *)(pd + offset);
  guint32		frame;
  guint32		bearer;

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->major_ver) + sizeof(hdr->minor_ver), 
		      "Protocol version: %u.%u", hdr->major_ver, hdr->minor_ver );
  offset += sizeof(hdr->major_ver) + sizeof(hdr->minor_ver);

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->result),
		      "Result: %s (%u)", cntrlresulttype2str(hdr->result), hdr->result);
  offset += sizeof(hdr->result);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->error),
		      "Error: %s (%u)", errortype2str(hdr->error), hdr->error);
  offset += sizeof(hdr->error);
  
  frame = pntohl(&hdr->frame);
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->frame),
		      "Framing capabilities: %s (%u)", frametype2str(frame), frame);
  offset += sizeof(hdr->frame);

  bearer = pntohl(&hdr->bearer);
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->bearer),
		      "Bearer capabilities: %s (%u)", bearertype2str(bearer), bearer);
  offset += sizeof(hdr->bearer);

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->max_chan),
		      "Maximum channels: %u", pntohs(&hdr->max_chan));
  offset += sizeof(hdr->max_chan);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->firm_rev),
		      "Firmware revision: %u", pntohs(&hdr->firm_rev));
  offset += sizeof(hdr->firm_rev);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->host),
		      "Hostname: %s", hdr->host);
  offset += sizeof(hdr->host);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->vendor),
		      "Vendor: %s", hdr->vendor);
}

static void
dissect_stop_req(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  struct stop_req *	hdr = (struct stop_req *)(pd + offset);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->reason),
		      "Reason: %s (%u)", reasontype2str(hdr->reason), hdr->reason);
  offset += sizeof(hdr->reason);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->resv0),
		      "Reserved: %u", hdr->resv0);
  offset += sizeof(hdr->resv0);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->resv1),
		      "Reserved: %u", pntohs(&hdr->resv1));
  offset += sizeof(hdr->resv1);
}

static void
dissect_stop_reply(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  struct stop_reply *	hdr = (struct stop_reply *)(pd + offset);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->result),
		      "Result: %s (%u)", stopresulttype2str(hdr->result), hdr->result);
  offset += sizeof(hdr->result);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->error),
		      "Error: %s (%u)", errortype2str(hdr->error), hdr->error);
  offset += sizeof(hdr->error);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->resv),
		      "Reserved: %u", pntohs(&hdr->resv));
  offset += sizeof(hdr->resv);
}

static void
dissect_echo_req(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  struct echo_req *	hdr = (struct echo_req *)(pd + offset);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->ident),
		      "Identifier: %u", pntohl(&hdr->ident));
  offset += sizeof(hdr->ident);
}

static void
dissect_echo_reply(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  struct echo_reply *	hdr = (struct echo_reply *)(pd + offset);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->ident),
		      "Identifier: %u", pntohl(&hdr->ident));
  offset += sizeof(hdr->ident);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->result),
		      "Result: %s (%u)", echoresulttype2str(hdr->result), hdr->result);
  offset += sizeof(hdr->result);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->error),
		      "Error: %s (%u)", errortype2str(hdr->error), hdr->error);
  offset += sizeof(hdr->error);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->resv),
		      "Reserved: %u", pntohs(&hdr->resv));
  offset += sizeof(hdr->resv);
}

static void
dissect_out_req(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  struct out_req *	hdr = (struct out_req *)(pd + offset);
  guint32		bearer;
  guint32		frame;
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->call_id),
		      "Call ID: %u", pntohs(&hdr->call_id));
  offset += sizeof(hdr->call_id);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->call_serial),
		      "Call Serial Number: %u", pntohs(&hdr->call_serial));
  offset += sizeof(hdr->call_serial);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->min_bps),
		      "Minimum BPS: %u", pntohl(&hdr->min_bps));
  offset += sizeof(hdr->min_bps);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->max_bps),
		      "Maximum BPS: %u", pntohl(&hdr->max_bps));
  offset += sizeof(hdr->max_bps);
  
  bearer = pntohl(&hdr->bearer);
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->bearer),
		      "Bearer capabilities: %s (%u)", bearertype2str(bearer), bearer);
  offset += sizeof(hdr->bearer);

  frame = pntohl(&hdr->frame);
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->frame),
		      "Framing capabilities: %s (%u)", frametype2str(frame), frame);
  offset += sizeof(hdr->frame);

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->win_size),
		      "Receive window size: %u", pntohs(&hdr->win_size));
  offset += sizeof(hdr->win_size);

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->delay),
		      "Processing delay: %u", pntohs(&hdr->delay));
  offset += sizeof(hdr->delay);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->phone_len),
		      "Phone number length: %u", pntohs(&hdr->phone_len));
  offset += sizeof(hdr->phone_len);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->resv),
		      "Reserved: %u", pntohs(&hdr->resv));
  offset += sizeof(hdr->resv);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->phone),
		      "Phone number: %s", hdr->phone);
  offset += sizeof(hdr->phone);

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->subaddr),
		      "Subaddress: %s", hdr->subaddr);
  offset += sizeof(hdr->subaddr);
}

static void
dissect_out_reply(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  struct out_reply *	hdr = (struct out_reply *)(pd + offset);

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->call_id),
		      "Call ID: %u", pntohs(&hdr->call_id));
  offset += sizeof(hdr->call_id);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->peer_id),
		      "Peer's call ID: %u", pntohs(&hdr->peer_id));
  offset += sizeof(hdr->peer_id);

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->result),
		      "Result: %s (%u)", outresulttype2str(hdr->result), hdr->result);
  offset += sizeof(hdr->result);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->error),
		      "Error: %s (%u)", errortype2str(hdr->error), hdr->error);
  offset += sizeof(hdr->error);

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->cause),
		      "Cause code: %u", pntohs(&hdr->cause));
  offset += sizeof(hdr->cause);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->speed),
		      "Connect speed: %u", pntohl(&hdr->speed));
  offset += sizeof(hdr->speed);

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->win_size),
		      "Receive window size: %u", pntohs(&hdr->win_size));
  offset += sizeof(hdr->win_size);

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->delay),
		      "Processing delay: %u", pntohs(&hdr->delay));
  offset += sizeof(hdr->delay);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->channel_id),
		      "Physical channel ID: %u", pntohl(&hdr->channel_id));
  offset += sizeof(hdr->channel_id);
}


static void
dissect_in_req(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  struct in_req *	hdr = (struct in_req *)(pd + offset);
  guint32		bearer;
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->call_id),
		      "Call ID: %u", pntohs(&hdr->call_id));
  offset += sizeof(hdr->call_id);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->call_serial),
		      "Call serial number: %u", pntohs(&hdr->call_serial));
  offset += sizeof(hdr->call_serial);
  
  bearer = pntohl(&hdr->bearer);
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->bearer),
		      "Bearer capabilities: %s (%u)", bearertype2str(bearer), bearer);
  offset += sizeof(hdr->bearer);

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->channel_id),
		      "Physical channel ID: %u", pntohl(&hdr->channel_id));
  offset += sizeof(hdr->channel_id);

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->dialed_len),
		      "Dialed number length: %u", pntohs(&hdr->dialed_len));
  offset += sizeof(hdr->dialed_len);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->dialing_len),
		      "Dialing number length: %u", pntohs(&hdr->dialing_len));
  offset += sizeof(hdr->dialing_len);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->dialed),
		      "Dialed number: %s", hdr->dialed);
  offset += sizeof(hdr->dialed);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->dialing),
		      "Dialing number: %s", hdr->dialing);
  offset += sizeof(hdr->dialing);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->subaddr),
		      "Subaddress: %s", hdr->subaddr);
  offset += sizeof(hdr->subaddr);
}

static void
dissect_in_reply(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  struct in_reply *	hdr = (struct in_reply *)(pd + offset);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->call_id),
		      "Call ID: %u", pntohs(&hdr->call_id));
  offset += sizeof(hdr->call_id);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->peer_id),
		      "Peer's call ID: %u", pntohs(&hdr->peer_id));
  offset += sizeof(hdr->peer_id);

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->result),
		      "Result: %s (%u)", inresulttype2str(hdr->result), hdr->result);
  offset += sizeof(hdr->result);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->error),
		      "Error: %s (%u)", errortype2str(hdr->error), hdr->error);
  offset += sizeof(hdr->error);

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->win_size),
		      "Receive window size: %u", pntohs(&hdr->win_size));
  offset += sizeof(hdr->win_size);

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->delay),
		      "Processing delay: %u", pntohs(&hdr->delay));
  offset += sizeof(hdr->delay);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->resv),
		      "Reserved: %u", hdr->resv);
  offset += sizeof(hdr->resv);
}

static void
dissect_in_connected(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  struct in_connected *	hdr = (struct in_connected *)(pd + offset);
  guint32		frame;
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->peer_id),
		      "Peer's call ID: %u", pntohs(&hdr->peer_id));
  offset += sizeof(hdr->peer_id);

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->resv),
		      "Reserved: %u", pntohs(&hdr->resv));
  offset += sizeof(hdr->resv);

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->speed),
		      "Connect speed: %u", pntohl(&hdr->speed));
  offset += sizeof(hdr->speed);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->win_size),
		      "Receive window size: %u", pntohs(&hdr->win_size));
  offset += sizeof(hdr->win_size);

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->delay),
		      "Processing delay: %u", pntohs(&hdr->delay));
  offset += sizeof(hdr->delay);
  
  frame = pntohl(&hdr->frame);
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->frame),
		      "Framing capabilities: %s (%u)", frametype2str(frame), frame);
  offset += sizeof(hdr->frame);
}

static void
dissect_clear_req(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  struct clear_req *	hdr = (struct clear_req *)(pd + offset);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->call_id),
		      "Call ID: %u", pntohs(&hdr->call_id));
  offset += sizeof(hdr->call_id);

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->resv),
		      "Reserved: %u", pntohs(&hdr->resv));
  offset += sizeof(hdr->resv);
}

static void
dissect_disc_notify(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  struct disc_notify *	hdr = (struct disc_notify *)(pd + offset);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->call_id),
		      "Call ID: %u", pntohs(&hdr->call_id));
  offset += sizeof(hdr->call_id);

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->result),
		      "Result: %s (%u)", discresulttype2str(hdr->result), hdr->result);
  offset += sizeof(hdr->result);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->error),
		      "Error: %s (%u)", errortype2str(hdr->error), hdr->error);
  offset += sizeof(hdr->error);

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->cause),
		      "Cause code: %u", pntohs(&hdr->cause));
  offset += sizeof(hdr->cause);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->resv),
		      "Reserved: %u", pntohs(&hdr->resv));
  offset += sizeof(hdr->resv);

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->stats),
		      "Call statistics: %s", hdr->stats);
  offset += sizeof(hdr->stats);
}

static void
dissect_error_notify(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  struct error_notify *	hdr = (struct error_notify *)(pd + offset);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->peer_id),
		      "Peer's call ID: %u", pntohs(&hdr->peer_id));
  offset += sizeof(hdr->peer_id);

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->resv),
		      "Reserved: %u", pntohs(&hdr->resv));
  offset += sizeof(hdr->resv);

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->crc),
		      "CRC errors: %u", pntohl(&hdr->crc));
  offset += sizeof(hdr->crc);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->frame),
		      "Framing errors: %u", pntohl(&hdr->frame));
  offset += sizeof(hdr->frame);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->hardware),
		      "Hardware overruns: %u", pntohl(&hdr->hardware));
  offset += sizeof(hdr->hardware);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->buffer),
		      "Buffer overruns: %u", pntohl(&hdr->buffer));
  offset += sizeof(hdr->buffer);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->timeout),
		      "Time-out errors: %u", pntohl(&hdr->timeout));
  offset += sizeof(hdr->timeout);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->alignment),
		      "Alignment errors: %u", pntohl(&hdr->alignment));
  offset += sizeof(hdr->alignment);
}

static void
dissect_set_link(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  struct set_link *	hdr = (struct set_link *)(pd + offset);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->peer_id),
		      "Peer's call ID: %u", pntohs(&hdr->peer_id));
  offset += sizeof(hdr->peer_id);

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->resv),
		      "Reserved: %u", pntohs(&hdr->resv));
  offset += sizeof(hdr->resv);

  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->send_acm),
		      "Send ACCM: %#08x", pntohl(&hdr->send_acm));
  offset += sizeof(hdr->send_acm);
  
  proto_tree_add_text(tree, NullTVB, offset, sizeof(hdr->recv_acm),
		      "Recv ACCM: %#08x", pntohl(&hdr->recv_acm));
  offset += sizeof(hdr->recv_acm);
}

void
proto_register_pptp(void)
{
  static gint *ett[] = {
    &ett_pptp,
  };

  static hf_register_info hf[] = {
    { &hf_pptp_message_type,
      { "Message Type",			"pptp.type",
	FT_UINT16,	BASE_HEX,	NULL,	0x0,
      	"PPTP message type" }}
  };

  proto_pptp = proto_register_protocol("Point-to-Point Tunnelling Protocol",
				       "pptp");
  proto_register_field_array(proto_pptp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_pptp(void)
{
  old_dissector_add("tcp.port", TCP_PORT_PPTP, dissect_pptp);
}
