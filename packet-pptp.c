/* packet-pptp.c
 * Routines for the Point-to-Point Tunnelling Protocol (PPTP) (RFC 2637)
 * Brad Robel-Forrest <brad.robel-forrest@watchguard.com>
 *
 * $Id: packet-pptp.c,v 1.19 2001/06/18 02:17:50 guy Exp $
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

static const value_string msgtype_vals[] = {
  { 1, "CONTROL-MESSAGE" },
  { 2, "MANAGEMENT-MESSAGE" },
  { 0, NULL }
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

static void dissect_unknown(tvbuff_t *, int, packet_info *, proto_tree *);
static void dissect_cntrl_req(tvbuff_t *, int, packet_info *, proto_tree *);
static void dissect_cntrl_reply(tvbuff_t *, int, packet_info *, proto_tree *);
static void dissect_stop_req(tvbuff_t *, int, packet_info *, proto_tree *);
static void dissect_stop_reply(tvbuff_t *, int, packet_info *, proto_tree *);
static void dissect_echo_req(tvbuff_t *, int, packet_info *, proto_tree *);
static void dissect_echo_reply(tvbuff_t *, int, packet_info *, proto_tree *);
static void dissect_out_req(tvbuff_t *, int, packet_info *, proto_tree *);
static void dissect_out_reply(tvbuff_t *, int, packet_info *, proto_tree *);
static void dissect_in_req(tvbuff_t *, int, packet_info *, proto_tree *);
static void dissect_in_reply(tvbuff_t *, int, packet_info *, proto_tree *);
static void dissect_in_connected(tvbuff_t *, int, packet_info *, proto_tree *);
static void dissect_clear_req(tvbuff_t *, int, packet_info *, proto_tree *);
static void dissect_disc_notify(tvbuff_t *, int, packet_info *, proto_tree *);
static void dissect_error_notify(tvbuff_t *, int, packet_info *, proto_tree *);
static void dissect_set_link(tvbuff_t *, int, packet_info *, proto_tree *);

#define NUM_CNTRL_TYPES		16
#define cntrltype2str(t)	\
  ((t < NUM_CNTRL_TYPES) ? strfuncs[t].str : "UNKNOWN-CONTROL-TYPE")

static struct strfunc {
  const char *	str;
  void          (*func)(tvbuff_t *, int, packet_info *, proto_tree *);
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

/*
 * Length of host name and vendor name strings in control requests and
 * replies.
 */
#define HOSTLEN		64
#define VENDORLEN	64

/*
 * Length of phone number(s) and subaddress in call requests.
 */
#define PHONELEN	64
#define SUBADDRLEN	64

/*
 * Length of statistics in a Call-Disconnect-Notify message.
 */
#define STATSLEN	128

static void
dissect_pptp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  int			offset = 0;
  guint16		len;
  guint16		cntrl_type;

  if (check_col(pinfo->fd, COL_PROTOCOL))
    col_set_str(pinfo->fd, COL_PROTOCOL, "PPTP");
  if (check_col(pinfo->fd, COL_INFO))
    col_clear(pinfo->fd, COL_INFO);
  
  len	     = tvb_get_ntohs(tvb, offset);
  cntrl_type = tvb_get_ntohs(tvb, offset + 8);

  if (check_col(pinfo->fd, COL_INFO))
    col_add_fstr(pinfo->fd, COL_INFO, "%s", cntrltype2str(cntrl_type));

  if (tree) {
    guint32		cookie;
    proto_item *	ti;
    proto_tree *	pptp_tree;

    ti = proto_tree_add_item(tree, proto_pptp, tvb, offset, len, FALSE);
    pptp_tree = proto_item_add_subtree(ti, ett_pptp);
    
    proto_tree_add_text(pptp_tree, tvb, offset, 2, "Length: %u", len);
    offset += 2;

    proto_tree_add_item(pptp_tree, hf_pptp_message_type, tvb,
			       offset, 2, FALSE);
    offset += 2;

    cookie = tvb_get_ntohl(tvb, offset);

    if (cookie == MAGIC_COOKIE)
      proto_tree_add_text(pptp_tree, tvb, offset, 4,
			  "Cookie: %#08x (correct)", cookie);
    else
      proto_tree_add_text(pptp_tree, tvb, offset, 4,
			  "Cookie: %#08x (incorrect)", cookie);
    offset += 4;
    
    proto_tree_add_text(pptp_tree, tvb, offset, 2,
			"Control type: %s (%u)", cntrltype2str(cntrl_type), cntrl_type);
    offset += 2;

    proto_tree_add_text(pptp_tree, tvb, offset, 2,
			"Reserved: %u", tvb_get_ntohs(tvb, offset));
    offset += 2;

    if (cntrl_type < NUM_CNTRL_TYPES)
      ( *(strfuncs[cntrl_type].func))(tvb, offset, pinfo, pptp_tree);
    else
      dissect_data(tvb, offset, pinfo, pptp_tree);
  }
}

static void
dissect_unknown(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree)
{
  dissect_data(tvb, offset, pinfo, tree);
}

static void
dissect_cntrl_req(tvbuff_t *tvb, int offset, packet_info *pinfo,
		  proto_tree *tree)
{
  guint8		major_ver;
  guint8		minor_ver;
  guint32		frame;
  guint32		bearer;
  guint8		host[HOSTLEN+1];
  guint8		vendor[VENDORLEN+1];

  major_ver = tvb_get_guint8(tvb, offset);
  minor_ver = tvb_get_guint8(tvb, offset + 1);
  proto_tree_add_text(tree, tvb, offset, 2, 
		      "Protocol version: %u.%u", major_ver, minor_ver);
  offset += 2;

  proto_tree_add_text(tree, tvb, offset, 2,
		      "Reserved: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;

  frame = tvb_get_ntohl(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 4,
		      "Framing capabilities: %s (%u)", frametype2str(frame), frame);
  offset += 4;

  bearer = tvb_get_ntohl(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 4,
		      "Bearer capabilities: %s (%u)", bearertype2str(bearer), bearer);
  offset += 4;

  proto_tree_add_text(tree, tvb, offset, 2,
		      "Maximum channels: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;
  
  proto_tree_add_text(tree, tvb, offset, 2,
		      "Firmware revision: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;
  
  tvb_get_nstringz0(tvb, offset, HOSTLEN, host);
  proto_tree_add_text(tree, tvb, offset, HOSTLEN,
		      "Hostname: %s", host);
  offset += HOSTLEN;
  
  tvb_get_nstringz0(tvb, offset, VENDORLEN, vendor);
  proto_tree_add_text(tree, tvb, offset, VENDORLEN,
		      "Vendor: %s", vendor);
}

static void
dissect_cntrl_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
		    proto_tree *tree)
{
  guint8		major_ver;
  guint8		minor_ver;
  guint8		result;
  guint8		error;
  guint32		frame;
  guint32		bearer;
  guint8		host[HOSTLEN+1];
  guint8		vendor[VENDORLEN+1];

  major_ver = tvb_get_guint8(tvb, offset);
  minor_ver = tvb_get_guint8(tvb, offset + 1);
  proto_tree_add_text(tree, tvb, offset, 2, 
		      "Protocol version: %u.%u", major_ver, minor_ver);
  offset += 2;

  result = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Result: %s (%u)", cntrlresulttype2str(result), result);
  offset += 1;
  
  error = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Error: %s (%u)", errortype2str(error), error);
  offset += 1;
  
  frame = tvb_get_ntohl(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 4,
		      "Framing capabilities: %s (%u)", frametype2str(frame), frame);
  offset += 4;

  bearer = tvb_get_ntohl(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 4,
		      "Bearer capabilities: %s (%u)", bearertype2str(bearer), bearer);
  offset += 4;

  proto_tree_add_text(tree, tvb, offset, 2,
		      "Maximum channels: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;
  
  proto_tree_add_text(tree, tvb, offset, 2,
		      "Firmware revision: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;
  
  tvb_get_nstringz0(tvb, offset, HOSTLEN, host);
  proto_tree_add_text(tree, tvb, offset, HOSTLEN,
		      "Hostname: %s", host);
  offset += HOSTLEN;
  
  tvb_get_nstringz0(tvb, offset, VENDORLEN, vendor);
  proto_tree_add_text(tree, tvb, offset, VENDORLEN,
		      "Vendor: %s", vendor);
}

static void
dissect_stop_req(tvbuff_t *tvb, int offset, packet_info *pinfo,
		 proto_tree *tree)
{
  guint8		reason;

  reason = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Reason: %s (%u)", reasontype2str(reason), reason);
  offset += 1;
  
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Reserved: %u", tvb_get_guint8(tvb, offset));
  offset += 1;
  
  proto_tree_add_text(tree, tvb, offset, 2,
		      "Reserved: %u", tvb_get_ntohs(tvb, offset));
}

static void
dissect_stop_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
		   proto_tree *tree)
{
  guint8		result;
  guint8		error;

  result = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Result: %s (%u)", stopresulttype2str(result), result);
  offset += 1;
  
  error = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Error: %s (%u)", errortype2str(error), error);
  offset += 1;
  
  proto_tree_add_text(tree, tvb, offset, 2,
		      "Reserved: %u", tvb_get_ntohs(tvb, offset));
}

static void
dissect_echo_req(tvbuff_t *tvb, int offset, packet_info *pinfo,
		 proto_tree *tree)
{
  proto_tree_add_text(tree, tvb, offset, 4,
		      "Identifier: %u", tvb_get_ntohl(tvb, offset));
}

static void
dissect_echo_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
		   proto_tree *tree)
{
  guint8		result;
  guint8		error;

  proto_tree_add_text(tree, tvb, offset, 4,
		      "Identifier: %u", tvb_get_ntohl(tvb, offset));
  offset += 4;
  
  result = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Result: %s (%u)", echoresulttype2str(result), result);
  offset += 1;
  
  error = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, sizeof(error),
		      "Error: %s (%u)", errortype2str(error), error);
  offset += 1;
  
  proto_tree_add_text(tree, tvb, offset, 2,
		      "Reserved: %u", tvb_get_ntohs(tvb, offset));
}

static void
dissect_out_req(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree)
{
  guint32		bearer;
  guint32		frame;
  guint8		phone[PHONELEN+1];
  guint8		subaddr[SUBADDRLEN+1];

  proto_tree_add_text(tree, tvb, offset, 2,
		      "Call ID: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;
  
  proto_tree_add_text(tree, tvb, offset, 2,
		      "Call Serial Number: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;
  
  proto_tree_add_text(tree, tvb, offset, 4,
		      "Minimum BPS: %u", tvb_get_ntohl(tvb, offset));
  offset += 4;
  
  proto_tree_add_text(tree, tvb, offset, 4,
		      "Maximum BPS: %u", tvb_get_ntohl(tvb, offset));
  offset += 4;
  
  bearer = tvb_get_ntohl(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 4,
		      "Bearer capabilities: %s (%u)", bearertype2str(bearer), bearer);
  offset += 4;

  frame = tvb_get_ntohl(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 4,
		      "Framing capabilities: %s (%u)", frametype2str(frame), frame);
  offset += 4;

  proto_tree_add_text(tree, tvb, offset, 2,
		      "Receive window size: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;

  proto_tree_add_text(tree, tvb, offset, 2,
		      "Processing delay: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;
  
  proto_tree_add_text(tree, tvb, offset, 2,
		      "Phone number length: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;
  
  proto_tree_add_text(tree, tvb, offset, 2,
		      "Reserved: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;
  
  tvb_get_nstringz0(tvb, offset, PHONELEN, phone);
  proto_tree_add_text(tree, tvb, offset, PHONELEN,
		      "Phone number: %s", phone);
  offset += PHONELEN;

  tvb_get_nstringz0(tvb, offset, SUBADDRLEN, subaddr);
  proto_tree_add_text(tree, tvb, offset, SUBADDRLEN,
		      "Subaddress: %s", subaddr);
}

static void
dissect_out_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
		  proto_tree *tree)
{
  guint8		result;
  guint8		error;

  proto_tree_add_text(tree, tvb, offset, 2,
		      "Call ID: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;
  
  proto_tree_add_text(tree, tvb, offset, 2,
		      "Peer's call ID: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;

  result = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Result: %s (%u)", outresulttype2str(result), result);
  offset += 1;
  
  error = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Error: %s (%u)", errortype2str(error), error);
  offset += 1;

  proto_tree_add_text(tree, tvb, offset, 2,
		      "Cause code: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;
  
  proto_tree_add_text(tree, tvb, offset, 4,
		      "Connect speed: %u", tvb_get_ntohl(tvb, offset));
  offset += 4;

  proto_tree_add_text(tree, tvb, offset, 2,
		      "Receive window size: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;

  proto_tree_add_text(tree, tvb, offset, 2,
		      "Processing delay: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;
  
  proto_tree_add_text(tree, tvb, offset, 4,
		      "Physical channel ID: %u", tvb_get_ntohl(tvb, offset));
}

static void
dissect_in_req(tvbuff_t *tvb, int offset, packet_info *pinfo,
	       proto_tree *tree)
{
  guint32		bearer;
  guint8		dialed[PHONELEN+1];
  guint8		dialing[PHONELEN+1];
  guint8		subaddr[SUBADDRLEN+1];

  proto_tree_add_text(tree, tvb, offset, 2,
		      "Call ID: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;
  
  proto_tree_add_text(tree, tvb, offset, 2,
		      "Call serial number: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;
  
  bearer = tvb_get_ntohl(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 4,
		      "Bearer capabilities: %s (%u)", bearertype2str(bearer), bearer);
  offset += 4;

  proto_tree_add_text(tree, tvb, offset, 4,
		      "Physical channel ID: %u", tvb_get_ntohl(tvb, offset));
  offset += 4;

  proto_tree_add_text(tree, tvb, offset, 2,
		      "Dialed number length: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;
  
  proto_tree_add_text(tree, tvb, offset, 2,
		      "Dialing number length: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;
  
  tvb_get_nstringz0(tvb, offset, PHONELEN, dialed);
  proto_tree_add_text(tree, tvb, offset, PHONELEN,
		      "Dialed number: %s", dialed);
  offset += PHONELEN;
  
  tvb_get_nstringz0(tvb, offset, PHONELEN, dialing);
  proto_tree_add_text(tree, tvb, offset, PHONELEN,
		      "Dialing number: %s", dialing);
  offset += PHONELEN;
  
  tvb_get_nstringz0(tvb, offset, SUBADDRLEN, subaddr);
  proto_tree_add_text(tree, tvb, offset, SUBADDRLEN,
		      "Subaddress: %s", subaddr);
}

static void
dissect_in_reply(tvbuff_t *tvb, int offset, packet_info *pinfo,
		 proto_tree *tree)
{
  guint8		result;
  guint8		error;

  proto_tree_add_text(tree, tvb, offset, 2,
		      "Call ID: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;
  
  proto_tree_add_text(tree, tvb, offset, 2,
		      "Peer's call ID: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;

  result = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Result: %s (%u)", inresulttype2str(result), result);
  offset += 1;
  
  error = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Error: %s (%u)", errortype2str(error), error);
  offset += 1;

  proto_tree_add_text(tree, tvb, offset, 2,
		      "Receive window size: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;

  proto_tree_add_text(tree, tvb, offset, 2,
		      "Processing delay: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;
  
  proto_tree_add_text(tree, tvb, offset, 2,
		      "Reserved: %u", tvb_get_ntohs(tvb, offset));
}

static void
dissect_in_connected(tvbuff_t *tvb, int offset, packet_info *pinfo,
		     proto_tree *tree)
{
  guint32		frame;
  
  proto_tree_add_text(tree, tvb, offset, 2,
		      "Peer's call ID: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;

  proto_tree_add_text(tree, tvb, offset, 2,
		      "Reserved: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;

  proto_tree_add_text(tree, tvb, offset, 4,
		      "Connect speed: %u", tvb_get_ntohl(tvb, offset));
  offset += 4;
  
  proto_tree_add_text(tree, tvb, offset, 2,
		      "Receive window size: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;

  proto_tree_add_text(tree, tvb, offset, 2,
		      "Processing delay: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;
  
  frame = tvb_get_ntohl(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 4,
		      "Framing capabilities: %s (%u)", frametype2str(frame), frame);
}

static void
dissect_clear_req(tvbuff_t *tvb, int offset, packet_info *pinfo,
		  proto_tree *tree)
{
  proto_tree_add_text(tree, tvb, offset, 2,
		      "Call ID: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;

  proto_tree_add_text(tree, tvb, offset, 2,
		      "Reserved: %u", tvb_get_ntohs(tvb, offset));
}

static void
dissect_disc_notify(tvbuff_t *tvb, int offset, packet_info *pinfo,
		    proto_tree *tree)
{
  guint8		result;
  guint8		error;
  guint8		stats[STATSLEN+1];

  proto_tree_add_text(tree, tvb, offset, 2,
		      "Call ID: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;

  result = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Result: %s (%u)", discresulttype2str(result), result);
  offset += 1;
  
  error = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Error: %s (%u)", errortype2str(error), error);
  offset += 1;

  proto_tree_add_text(tree, tvb, offset, 2,
		      "Cause code: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;
  
  proto_tree_add_text(tree, tvb, offset, 2,
		      "Reserved: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;

  tvb_get_nstringz0(tvb, offset, STATSLEN, stats);
  proto_tree_add_text(tree, tvb, offset, STATSLEN,
		      "Call statistics: %s", stats);
}

static void
dissect_error_notify(tvbuff_t *tvb, int offset, packet_info *pinfo,
		     proto_tree *tree)
{
  proto_tree_add_text(tree, tvb, offset, 2,
		      "Peer's call ID: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;

  proto_tree_add_text(tree, tvb, offset, 2,
		      "Reserved: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;

  proto_tree_add_text(tree, tvb, offset, 4,
		      "CRC errors: %u", tvb_get_ntohl(tvb, offset));
  offset += 4;
  
  proto_tree_add_text(tree, tvb, offset, 4,
		      "Framing errors: %u", tvb_get_ntohl(tvb, offset));
  offset += 4;
  
  proto_tree_add_text(tree, tvb, offset, 4,
		      "Hardware overruns: %u", tvb_get_ntohl(tvb, offset));
  offset += 4;
  
  proto_tree_add_text(tree, tvb, offset, 4,
		      "Buffer overruns: %u", tvb_get_ntohl(tvb, offset));
  offset += 4;
  
  proto_tree_add_text(tree, tvb, offset, 4,
		      "Time-out errors: %u", tvb_get_ntohl(tvb, offset));
  offset += 4;
  
  proto_tree_add_text(tree, tvb, offset, 4,
		      "Alignment errors: %u", tvb_get_ntohl(tvb, offset));
}

static void
dissect_set_link(tvbuff_t *tvb, int offset, packet_info *pinfo,
		 proto_tree *tree)
{
  proto_tree_add_text(tree, tvb, offset, 2,
		      "Peer's call ID: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;

  proto_tree_add_text(tree, tvb, offset, 2,
		      "Reserved: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;

  proto_tree_add_text(tree, tvb, offset, 4,
		      "Send ACCM: %#08x", tvb_get_ntohl(tvb, offset));
  offset += 4;
  
  proto_tree_add_text(tree, tvb, offset, 4,
		      "Recv ACCM: %#08x", tvb_get_ntohl(tvb, offset));
}

void
proto_register_pptp(void)
{
  static gint *ett[] = {
    &ett_pptp,
  };

  static hf_register_info hf[] = {
    { &hf_pptp_message_type,
      { "Message type",			"pptp.type",
	FT_UINT16,	BASE_DEC,	VALS(msgtype_vals),	0x0,
      	"PPTP message type", HFILL }}
  };

  proto_pptp = proto_register_protocol("Point-to-Point Tunnelling Protocol",
				       "PPTP", "pptp");
  proto_register_field_array(proto_pptp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_pptp(void)
{
  dissector_add("tcp.port", TCP_PORT_PPTP, dissect_pptp, proto_pptp);
}
