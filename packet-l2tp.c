/* packet-l2tp.c
 * Routines for Layer Two Tunnelling Protocol (L2TP) (RFC 2661) packet
 * disassembly
 * John Thomes <john@ensemblecom.com>
 *
 * Minor changes by: (2000-01-10)
 * Laurent Cazalet <laurent.cazalet@mailclub.net>
 * Thomas Parvais <thomas.parvais@advalvas.be>
 *
 * $Id: packet-l2tp.c,v 1.27 2001/10/29 21:13:07 guy Exp $
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


static int proto_l2tp = -1;
static int hf_l2tp_type = -1;
static int hf_l2tp_length_bit = -1;
static int hf_l2tp_seq_bit = -1;
static int hf_l2tp_offset_bit = -1;
static int hf_l2tp_priority = -1; 
static int hf_l2tp_version = -1;
static int hf_l2tp_length = -1;
static int hf_l2tp_tunnel = -1;
static int hf_l2tp_session = -1;
static int hf_l2tp_Ns = -1;
static int hf_l2tp_Nr = -1;
static int hf_l2tp_offset = -1;
static int hf_l2tp_avp_mandatory = -1;
static int hf_l2tp_avp_hidden = -1;
static int hf_l2tp_avp_length = -1;
static int hf_l2tp_avp_vendor_id = -1;
static int hf_l2tp_avp_type = -1;
static int hf_l2tp_tie_breaker = -1;

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <glib.h>
#include "packet.h"
#include "resolv.h"

#define UDP_PORT_L2TP   1701

#define CONTROL_BIT(msg_info) (msg_info & 0x8000)   /* Type bit control = 1 data = 0 */
#define LENGTH_BIT(msg_info) (msg_info & 0x4000)    /* Length bit = 1  */ 
#define RESERVE_BITS(msg_info) (msg_info &0x37F8)   /* Reserved bit - usused */
#define SEQUENCE_BIT(msg_info) (msg_info & 0x0800)  /* SEQUENCE bit = 1 Ns and Nr fields */
#define OFFSET_BIT(msg_info) (msg_info & 0x0200)    /* Offset */
#define PRIORITY_BIT(msg_info) (msg_info & 0x0100)  /* Priority */
#define L2TP_VERSION(msg_info) (msg_info & 0x000f)  /* Version of l2tp */
#define MANDATORY_BIT(msg_info) (msg_info & 0x8000) /* Mandatory = 1 */
#define HIDDEN_BIT(msg_info) (msg_info & 0x4000)    /* Hidden = 1 */
#define AVP_LENGTH(msg_info) (msg_info & 0x03ff)    /* AVP Length */
#define FRAMING_SYNC(msg_info)  (msg_info & 0x0001) /* SYNC Framing Type */
#define FRAMING_ASYNC(msg_info) (msg_info & 0x0002) /* ASYNC Framing Type */
#define BEARER_DIGITAL(msg_info) (msg_info & 0x0001) /* Digital Bearer Type */
#define BEARER_ANALOG(msg_info) (msg_info & 0x0002) /* Analog Bearer Type */

static gint ett_l2tp = -1;
static gint ett_l2tp_ctrl = -1;
static gint ett_l2tp_avp = -1;

#define AVP_SCCRQ      1
#define AVP_SCCRP      2
#define AVP_SCCCN      3
#define AVP_StopCCN    4
#define AVP_Reserved   5
#define AVP_HELLO      6 
#define AVP_OCRQ       7 
#define AVP_OCRP       8 
#define AVP_ORCRP      9 
#define AVP_ICRQ      10 
#define AVP_ICRP      11 
#define AVP_ICCN      12 
#define AVP_Reserved1 13 
#define AVP_CDN       14 


#define NUM_CONTROL_CALL_TYPES  16
static const char *calltypestr[NUM_CONTROL_CALL_TYPES+1] = {
  "Unknown Call Type           ",
  "Start_Control_Request       ",
  "Start_Control_Reply         ",
  "Start_Control_Connected     ",
  "Stop_Control_Notification   ",
  "Reserved                    ",
  "Hello                       ",
  "Outgoing_Call_Request       ",
  "Outgoing_Call_Reply         ",
  "Outgoing_Call_Connected     ",
  "Incoming_Call_Request       ",
  "Incoming_Call_Reply         ",
  "Incoming_Call_Connected     ",
  "Reserved                    ",
  "Call_Disconnect_Notification",
  "WAN_Error_Notify            ",
  "Set_Link_Info               ",
};

static const char *calltype_short_str[NUM_CONTROL_CALL_TYPES+1] = {
  "Unknown ",
  "SCCRQ   ",
  "SCCRP   ",
  "SCCCN   ",
  "StopCCN ",
  "Reserved",
  "Hello   ",
  "OCRQ    ",
  "OCRP    ",
  "OCCN    ",
  "ICRQ    ",
  "ICRP    ",
  "ICCN    ",
  "Reserved",
  "CDN     ",
  "WEN     ",
  "SLI     ",
};


static const char *control_msg	= "Control Message";
static const char *data_msg	= "Data    Message";
static const value_string l2tp_type_vals[] = {
	{ 0, "Data Message" },
	{ 1, "Control Message" },
	{ 0, NULL },
};

static const value_string cause_code_direction_vals[] = {
	{ 0, "global error" },
	{ 1, "at peer" },
	{ 2, "at local" },
	{ 0, NULL },
};

static const true_false_string l2tp_length_bit_truth =
	{ "Length field is present", "Length field is not present" };

static const true_false_string l2tp_seq_bit_truth =
	{ "Ns and Nr fields are present", "Ns and Nr fields are not present" };

static const true_false_string l2tp_offset_bit_truth =
	{ "Offset Size field is present", "Offset size field is not present" };

static const true_false_string l2tp_priority_truth =
	{ "This data message has priority", "No priority" };

static const value_string authen_type_vals[] = {
  { 0, "Reserved" },
  { 1, "Textual username and password" },
  { 2, "PPP CHAP" },
  { 3, "PPP PAP" },
  { 4, "No Authentication" },
  { 5, "Microsoft CHAP Version 1" },
  { 0, NULL }
};

#define  CONTROL_MESSAGE  0
#define  RESULT_ERROR_CODE 1
#define  PROTOCOL_VERSION  2
#define  FRAMING_CAPABILITIES 3
#define  BEARER_CAPABILITIES 4
#define  TIE_BREAKER 5
#define  FIRMWARE_REVISION 6
#define  HOST_NAME 7
#define  VENDOR_NAME 8
#define  ASSIGNED_TUNNEL_ID 9
#define  RECEIVE_WINDOW_SIZE 10
#define  CHALLENGE 11
#define  CAUSE_CODE 12 
#define  CHALLENGE_RESPONSE 13
#define  ASSIGNED_SESSION 14
#define  CALL_SERIAL_NUMBER 15
#define  MINIMUM_BPS 16
#define  MAXIMUM_BPS 17
#define  BEARER_TYPE 18
#define  FRAMING_TYPE 19
#define  CALLED_NUMBER 21
#define  CALLING_NUMBER 22
#define  SUB_ADDRESS 23
#define  TX_CONNECT_SPEED 24
#define  PHYSICAL_CHANNEL 25
#define  INITIAL_RECEIVED_LCP 26
#define  LAST_SEND_LCP_CONFREQ 27
#define  LAST_RECEIVED_LCP_CONFREQ 28
#define  PROXY_AUTHEN_TYPE 29
#define  PROXY_AUTHEN_NAME 30
#define  PROXY_AUTHEN_CHALLENGE 31
#define  PROXY_AUTHEN_ID 32
#define  PROXY_AUTHEN_RESPONSE 33
#define  CALL_STATUS_AVPS 34
#define  ACCM 35
#define  RANDOM_VECTOR 36
#define  PRIVATE_GROUP_ID 37
#define  RX_CONNECT_SPEED 38
#define  SEQUENCING_REQUIRED 39
#define  PPP_DISCONNECT_CAUSE_CODE 46	/* RFC 3145 */

#define NUM_AVP_TYPES  40
static const value_string avp_type_vals[] = {
  { CONTROL_MESSAGE,           "Control Message" },
  { RESULT_ERROR_CODE,         "Result-Error Code" },
  { PROTOCOL_VERSION,          "Protocol Version" },
  { FRAMING_CAPABILITIES,      "Framing Capabilities" },
  { BEARER_CAPABILITIES,       "Bearer Capabilities" },
  { TIE_BREAKER,               "Tie Breaker" },
  { FIRMWARE_REVISION,         "Firmware Revision" },
  { HOST_NAME,                 "Host Name" },
  { VENDOR_NAME,               "Vendor Name" },
  { ASSIGNED_TUNNEL_ID,        "Assigned Tunnel ID" },
  { RECEIVE_WINDOW_SIZE,       "Receive Window Size" },
  { CHALLENGE,                 "Challenge" },
  { CAUSE_CODE,                "Cause Code" },
  { CHALLENGE_RESPONSE,        "Challenge Response" },
  { ASSIGNED_SESSION,          "Assigned Session" },
  { CALL_SERIAL_NUMBER,        "Call Serial Number" },
  { MINIMUM_BPS,               "Minimum BPS" },
  { MAXIMUM_BPS,               "Maximum BPS" },
  { BEARER_TYPE,               "Bearer Type" },
  { FRAMING_TYPE,              "Framing Type" },
  { CALLED_NUMBER,             "Called Number" },
  { CALLING_NUMBER,            "Calling Number" },
  { SUB_ADDRESS,               "Sub-Address" },
  { TX_CONNECT_SPEED,          "Connect Speed" },
  { PHYSICAL_CHANNEL,          "Physical Channel" },
  { INITIAL_RECEIVED_LCP,      "Initial Received LCP" },
  { LAST_SEND_LCP_CONFREQ,     "Last Send LCP CONFREQ" },
  { LAST_RECEIVED_LCP_CONFREQ, "Last Received LCP CONFREQ" },
  { PROXY_AUTHEN_TYPE,         "Proxy Authen Type" },
  { PROXY_AUTHEN_NAME,         "Proxy Authen Name" },
  { PROXY_AUTHEN_CHALLENGE,    "Proxy Authen Challenge" },
  { PROXY_AUTHEN_ID,           "Proxy Authen ID" },
  { PROXY_AUTHEN_RESPONSE,     "Proxy Authen Response" },
  { CALL_STATUS_AVPS,          "Call status AVPs" },
  { ACCM,                      "ACCM" },
  { RANDOM_VECTOR,             "Random Vector" },
  { PRIVATE_GROUP_ID,          "Private group ID" },
  { RX_CONNECT_SPEED,          "RxConnect Speed" },
  { SEQUENCING_REQUIRED,       "Sequencing Required" },
  { PPP_DISCONNECT_CAUSE_CODE, "PPP Disconnect Cause Code" },
  { 0,                         NULL }
};

/*
 * These are SMI Network Management Private Enterprise Codes for
 * organizations; see
 *
 *      http://www.isi.edu/in-notes/iana/assignments/enterprise-numbers
 *
 * for a list.
 */
#define VENDOR_IETF 0
#define VENDOR_ACC 5
#define VENDOR_CISCO 9
#define VENDOR_SHIVA 166
#define VENDOR_LIVINGSTON 307
#define VENDOR_3COM 429
#define VENDOR_ASCEND 529
#define VENDOR_BAY 1584
#define VENDOR_JUNIPER 2636
#define VENDOR_COSINE 3085
#define VENDOR_UNISPHERE 4874

static const value_string avp_vendor_id_vals[] = 
{{VENDOR_IETF,"IETF"},
{VENDOR_ACC,"ACC"},
{VENDOR_CISCO,"Cisco"},
{VENDOR_SHIVA,"Shiva"},
{VENDOR_LIVINGSTON,"Livingston"},
{VENDOR_3COM,"3Com"},
{VENDOR_ASCEND,"Ascend"},
{VENDOR_BAY,"Bay Networks"},
{VENDOR_JUNIPER,"Juniper Networks"},
{VENDOR_COSINE,"CoSine Communications"},
{VENDOR_UNISPHERE,"Unisphere Networks"},
{0,NULL}};

static gchar textbuffer[200];

static dissector_handle_t ppp_hdlc_handle;

static void
dissect_l2tp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *l2tp_tree=NULL, *l2tp_avp_tree, *ctrl_tree;
  proto_item *ti, *tf;
  int rhcode;
  int index = 0;
  int tmp_index;
  int proto_length = 0;
  guint16 length = 0;		/* Length field */
  guint16 tid;			/* Tunnel ID */
  guint16 cid;			/* Call ID */
  guint16 offset_size;		/* Offset size */
  guint16 ver_len_hidden;
  guint16 avp_vendor_id;
  guint16 avp_type;
  guint16 msg_type;
  guint16 avp_len;
  guint16 result_code;
  guint16 error_code;
  guint32 bits;
  guint16 firmware_rev;
  guint16	control;
  tvbuff_t	*next_tvb;

  if (check_col(pinfo->fd, COL_PROTOCOL))	/* build output for closed L2tp frame displayed  */
        col_set_str(pinfo->fd, COL_PROTOCOL, "L2TP"); 
  if (check_col(pinfo->fd, COL_INFO))
        col_clear(pinfo->fd, COL_INFO);

  control = tvb_get_ntohs(tvb, 0);

  if (L2TP_VERSION(control) != 2) {
	  if (check_col(pinfo->fd, COL_INFO)) {
		col_add_fstr(pinfo->fd, COL_INFO, "L2TP Version %u", L2TP_VERSION(control) );
	  }
	  return;
  }

  rhcode= 10;

  if (LENGTH_BIT(control)) { 		/* length field included ? */
      index += 2; 			/* skip ahead */
      length = tvb_get_ntohs(tvb, index);
  }

  /* collect the tunnel id & call id */
  index += 2;
  tid = tvb_get_ntohs(tvb, index);
  index += 2;
  cid = tvb_get_ntohs(tvb, index);

  if (check_col(pinfo->fd, COL_INFO)) {
        if (CONTROL_BIT(control)) {
            /* CONTROL MESSAGE */
            tmp_index = index;

              if ((LENGTH_BIT(control))&&(length==12))  		/* ZLB Message */
                  sprintf(textbuffer,"%s - ZLB      (tunnel id=%d, session id=%d)",
                          control_msg , tid ,cid);
              else
              {
                if (SEQUENCE_BIT(control)) {
                    tmp_index += 4;
                }
    
                tmp_index+=4;
    
                avp_type = tvb_get_ntohs(tvb, (tmp_index+=2));
    
                if (avp_type == CONTROL_MESSAGE)
                {
                    /* We print message type */
                    msg_type = tvb_get_ntohs(tvb, (tmp_index+=2));
                    sprintf(textbuffer,"%s - %s (tunnel id=%d, session id=%d)",
                            control_msg ,
                            ((NUM_CONTROL_CALL_TYPES + 1 ) > msg_type) ?
                            calltype_short_str[msg_type] : "Unknown",
                            tid ,cid);
                }
                else
                {
                    /*
		     * This is not a control message.
                     * We never pass here except in case of bad l2tp packet!
		     */
                    sprintf(textbuffer,"%s (tunnel id=%d, session id=%d)",
                            control_msg ,  tid ,cid);
    
                }
              }
        }
        else {
            /* DATA Message */
               sprintf(textbuffer,"%s            (tunnel id=%d, session id=%d)",
                       data_msg, tid ,cid);
        }
        col_add_fstr(pinfo->fd,COL_INFO,textbuffer);
  }

  if (LENGTH_BIT(control)) {
	proto_length = length;
  }
  else {
	proto_length = tvb_length(tvb);
  }

  if (tree) {
        ti = proto_tree_add_item(tree,proto_l2tp, tvb, 0, proto_length, FALSE);
	l2tp_tree = proto_item_add_subtree(ti, ett_l2tp);

	ti = proto_tree_add_text(l2tp_tree, tvb, 0, 2,
			"Packet Type: %s Tunnel Id=%d Session Id=%d",
			(CONTROL_BIT(control) ? control_msg : data_msg), tid, cid);

	ctrl_tree = proto_item_add_subtree(ti, ett_l2tp_ctrl);
	proto_tree_add_uint(ctrl_tree, hf_l2tp_type, tvb, 0, 2, control);
	proto_tree_add_boolean(ctrl_tree, hf_l2tp_length_bit, tvb, 0, 2, control);
	proto_tree_add_boolean(ctrl_tree, hf_l2tp_seq_bit, tvb, 0, 2, control);
	proto_tree_add_boolean(ctrl_tree, hf_l2tp_offset_bit, tvb, 0, 2, control);
	proto_tree_add_boolean(ctrl_tree, hf_l2tp_priority, tvb, 0, 2, control);
	proto_tree_add_uint(ctrl_tree, hf_l2tp_version, tvb, 0, 2, control);
  }
  index = 2;
  if (LENGTH_BIT(control)) {
	  if (tree) {
		proto_tree_add_item(l2tp_tree, hf_l2tp_length, tvb, index, 2, FALSE);
	  }
	index += 2;
  }

  if (tree) {
	proto_tree_add_item(l2tp_tree, hf_l2tp_tunnel, tvb, index, 2, FALSE);
  }
  index += 2;
  if (tree) {
	proto_tree_add_item(l2tp_tree, hf_l2tp_session, tvb, index, 2, FALSE);
  }
  index += 2;

  if (SEQUENCE_BIT(control)) {
	  if (tree) {
		proto_tree_add_item(l2tp_tree, hf_l2tp_Ns, tvb, index, 2, FALSE);
	  }
	  index += 2;
	  if (tree) {
	  	proto_tree_add_item(l2tp_tree, hf_l2tp_Nr, tvb, index, 2, FALSE);
	  }
	  index += 2;
  }
  if (OFFSET_BIT(control)) {
	offset_size = tvb_get_ntohs(tvb, index);
	if (tree) {
		proto_tree_add_uint(l2tp_tree, hf_l2tp_offset, tvb, index, 2, FALSE);
	}
	index += 2;
	if (tree) {
		proto_tree_add_text(l2tp_tree, tvb, index, offset_size, "Offset Padding");
	}
	index += offset_size;
  }
  if (tree && (LENGTH_BIT(control))&&(length==12)) {
            proto_tree_add_text(l2tp_tree, tvb, 0, 0, "Zero Length Bit message");
  }

  if (!CONTROL_BIT(control)) {  /* Data Messages so we are done */
	/* If we have data, signified by having a length bit, dissect it */
	if (tvb_offset_exists(tvb, index)) {
		next_tvb = tvb_new_subset(tvb, index, -1, proto_length - index);
		call_dissector(ppp_hdlc_handle, next_tvb, pinfo, tree);
	}
	return;
  }

  if (tree) {
	if (!LENGTH_BIT(control)) {
		return;
 	}
	while (index < length ) {    /* Process AVP's */
   		ver_len_hidden	= tvb_get_ntohs(tvb, index);
   		avp_len		= AVP_LENGTH(ver_len_hidden);
		avp_vendor_id	= tvb_get_ntohs(tvb, index + 2);
   		avp_type	= tvb_get_ntohs(tvb, index + 4);

		if (avp_vendor_id == VENDOR_IETF) {
			tf =  proto_tree_add_text(l2tp_tree, tvb, index, 
			avp_len, "%s AVP",
		        val_to_str(avp_type, avp_type_vals, "Unknown (%u)"));
		} else {	 /* Vendor-Specific AVP */
			tf =  proto_tree_add_text(l2tp_tree, tvb, index, 
			avp_len, "Vendor %s AVP",
		        val_to_str(avp_vendor_id, avp_vendor_id_vals, "Unknown (%u)"));
		}

                l2tp_avp_tree = proto_item_add_subtree(tf,  ett_l2tp_avp);

                proto_tree_add_boolean_format(l2tp_avp_tree,hf_l2tp_avp_mandatory, tvb, index, 1,
                                           rhcode, "Mandatory: %s",
					   (MANDATORY_BIT(ver_len_hidden)) ? "True" : "False" );
                proto_tree_add_boolean_format(l2tp_avp_tree,hf_l2tp_avp_hidden, tvb, index, 1,
                                           rhcode, "Hidden: %s",
					   (HIDDEN_BIT(ver_len_hidden)) ? "True" : "False" );
		proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_avp_length, tvb, index, 2,
					   rhcode, "Length: %u", avp_len);
		if (HIDDEN_BIT(ver_len_hidden)) { /* don't try do display hidden */
			index += avp_len;
			continue;
		}

		if (avp_len == 0) {
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 0,
			  "AVP length must not be zero");
			return;
		}
		index += 2;
		avp_len -= 2;

		proto_tree_add_item(l2tp_avp_tree, hf_l2tp_avp_vendor_id,
		    tvb, index, 2, FALSE);
		index += 2;
		avp_len -= 2;

		if (avp_vendor_id != VENDOR_IETF) {
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
					    "Type: %u", avp_type);
			index += 2;
			avp_len -= 2;

			/* For the time being, we don't decode any Vendor-
			   specific AVP. */
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 
					    avp_len, "Vendor-Specific AVP");

			index += avp_len;
			continue;
		}

		proto_tree_add_uint(l2tp_avp_tree, hf_l2tp_avp_type,
		    tvb, index, 2, avp_type);
		index += 2;
		avp_len -= 2;

		switch (avp_type) {

		case CONTROL_MESSAGE:
			msg_type = tvb_get_ntohs(tvb, index);
			proto_tree_add_text(l2tp_avp_tree,tvb, index, 2,
			  "Control Message Type: (%u) %s", msg_type,
			  ((NUM_CONTROL_CALL_TYPES + 1 ) > msg_type) ?
			  calltypestr[msg_type] : "Unknown");
			break;

		case RESULT_ERROR_CODE:
			if (avp_len < 2)
				break;
			result_code = tvb_get_ntohs(tvb, index);
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
			  "Result code: %u",  result_code);
			index += 2;
			avp_len -= 2;

			if (avp_len < 2)
				break;
			error_code = tvb_get_ntohs(tvb, index);
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
			  "Error code: %u", error_code);
			index += 2;
			avp_len -= 2;

			if (avp_len == 0)
				break;
			proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
			  "Error Message: %.*s", avp_len,
			  tvb_get_ptr(tvb, index, avp_len));
			break;

		case PROTOCOL_VERSION:
			if (avp_len < 1)
				break;
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 1,
			  "Version: %u", tvb_get_guint8(tvb, index));
			index += 1;
			avp_len -= 1;

			proto_tree_add_text(l2tp_avp_tree, tvb, index, 1,
			  "Revision: %u", tvb_get_guint8(tvb, index));
			break;

		case FRAMING_CAPABILITIES:
			bits = tvb_get_ntohl(tvb, index);
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
			  "Async Framing Supported: %s",
			  (FRAMING_ASYNC(bits)) ? "True" : "False");
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
			  "Sync Framing Supported: %s",
			  (FRAMING_SYNC(bits)) ? "True" : "False");
			break;

		case BEARER_CAPABILITIES:
			bits = tvb_get_ntohl(tvb, index);
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
			  "Analog Access Supported: %s",
			  (BEARER_ANALOG(bits)) ? "True" : "False");
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
			  "Digital Access Supported: %s",
			  (BEARER_DIGITAL(bits)) ? "True" : "False");
			break;

		case TIE_BREAKER:
			proto_tree_add_item(l2tp_avp_tree, hf_l2tp_tie_breaker, tvb, index, 8, FALSE);
			break;

		case FIRMWARE_REVISION:
			firmware_rev = tvb_get_ntohs(tvb, index);
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
			  "Firmware Revision: %d 0x%x", firmware_rev,firmware_rev );
			break;

		case HOST_NAME:
			proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
			  "Host Name: %.*s", avp_len,
			  tvb_get_ptr(tvb, index, avp_len));
			break;

		case VENDOR_NAME:
			proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
			  "Vendor Name: %.*s", avp_len,
			  tvb_get_ptr(tvb, index, avp_len));
			break;

		case ASSIGNED_TUNNEL_ID:
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
			  "Tunnel ID: %u", tvb_get_ntohs(tvb, index));
			break;

		case RECEIVE_WINDOW_SIZE:
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
			  "Receive Window Size: %u",
			  tvb_get_ntohs(tvb, index));
			break;

		case CHALLENGE:
			proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
			  "CHAP Challenge: %s",
			  tvb_bytes_to_str(tvb, index, avp_len));
			break;

		case CAUSE_CODE:
			/*
			 * XXX - export stuff from the Q.931 dissector
			 * to dissect the cause code and cause message,
			 * and use it.
			 */
			if (avp_len < 2)
				break;
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
			  "Cause Code: %u",
			  tvb_get_ntohs(tvb, index));
			index += 2;
			avp_len -= 2;

			if (avp_len < 1)
				break;
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 1,
			  "Cause Msg: %u",
			  tvb_get_guint8(tvb, index));
			index += 1;
			avp_len -= 1;

			if (avp_len == 0)
				break;
			proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
			  "Advisory Msg: %.*s", avp_len,
			  tvb_get_ptr(tvb, index, avp_len));
			break;

		case CHALLENGE_RESPONSE:
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 16,
			  "CHAP Challenge Response: %s",
			  tvb_bytes_to_str(tvb, index, 16));
			break;

		case ASSIGNED_SESSION:
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
			  "Assigned Session: %u",
			  tvb_get_ntohs(tvb, index));
			break;

		case CALL_SERIAL_NUMBER:
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
			  "Call Serial Number: %u",
			  tvb_get_ntohl(tvb, index));
			break;

		case MINIMUM_BPS:
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
			  "Minimum BPS: %u",
			  tvb_get_ntohl(tvb, index));
			break;

		case MAXIMUM_BPS:
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
			  "Maximum BPS: %u",
			  tvb_get_ntohl(tvb, index));
			break;

		case BEARER_TYPE:
			bits = tvb_get_ntohl(tvb, index);
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
			  "Analog Bearer Type: %s",
			  (BEARER_ANALOG(bits)) ? "True" : "False");
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
			  "Digital Bearer Type: %s",
			  (BEARER_DIGITAL(bits)) ? "True" : "False");
			break;

		case FRAMING_TYPE:
			bits = tvb_get_ntohl(tvb, index);
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
			  "Async Framing Type: %s",
			  (FRAMING_ASYNC(bits)) ? "True" : "False");
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
			  "Sync Framing Type: %s",
			  (FRAMING_SYNC(bits)) ? "True" : "False");
			break;

		case CALLED_NUMBER:
			if (avp_len == 0)
				break;
			proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
			  "Called Number: %.*s", avp_len,
			  tvb_get_ptr(tvb, index, avp_len));
			break;

		case CALLING_NUMBER:
			if (avp_len == 0)
				break;
			proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
			  "Calling Number: %.*s", avp_len,
			  tvb_get_ptr(tvb, index, avp_len));
			break;

		case SUB_ADDRESS:
			if (avp_len == 0)
				break;
			proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
			  "Sub-Address: %.*s", avp_len,
			  tvb_get_ptr(tvb, index, avp_len));
			break;

		case TX_CONNECT_SPEED:
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
			  "Connect Speed: %u",
			  tvb_get_ntohl(tvb, index));
			break;

		case PHYSICAL_CHANNEL:
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
			  "Physical Channel: %u",
			  tvb_get_ntohl(tvb, index));
			break;

		case INITIAL_RECEIVED_LCP:
			/*
			 * XXX - can this be dissected by stuff in the
			 * LCP dissector?
			 */
			proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
			  "Initial LCP CONFREQ: %s",
			  tvb_bytes_to_str(tvb, index, avp_len));
			break;

		case LAST_SEND_LCP_CONFREQ:
			/*
			 * XXX - can this be dissected by stuff in the
			 * LCP dissector?
			 */
			proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
			  "Last Sent LCP CONFREQ: %s",
			  tvb_bytes_to_str(tvb, index, avp_len));
			break;

		case LAST_RECEIVED_LCP_CONFREQ:
			/*
			 * XXX - can this be dissected by stuff in the
			 * LCP dissector?
			 */
			proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
			  "Last Received LCP CONFREQ: %s",
			  tvb_bytes_to_str(tvb, index, avp_len));
			break;

		case PROXY_AUTHEN_TYPE:
			msg_type = tvb_get_ntohs(tvb, index);
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
			  "Proxy Authen Type: %s",
			  val_to_str(msg_type, authen_type_vals, "Unknown (%u)"));
			break;

		case PROXY_AUTHEN_NAME:
			if (avp_len == 0)
				break;
			proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
			  "Proxy Authen Name: %.*s", avp_len,
			  tvb_get_ptr(tvb, index, avp_len));
			break;

		case PROXY_AUTHEN_CHALLENGE:
			proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
			  "Proxy Authen Challenge: %s",
			  tvb_bytes_to_str(tvb, index, avp_len));
			break;

		case PROXY_AUTHEN_ID:
			proto_tree_add_text(l2tp_avp_tree, tvb, index + 1, 1,
			  "Proxy Authen ID: %u",
			  tvb_get_guint8(tvb, index + 1));
			break;

		case PROXY_AUTHEN_RESPONSE:
			proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
			  "Proxy Authen Response: %s",
			  tvb_bytes_to_str(tvb, index, avp_len));
			break;

		case CALL_STATUS_AVPS:
			if (avp_len < 2)
				break;
			index += 2;
			avp_len -= 2;

			if (avp_len < 4)
				break;
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
			  "CRC Errors: %u", tvb_get_ntohl(tvb, index));
			index += 4;
			avp_len -= 4;

			if (avp_len < 4)
				break;
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
			  "Framing Errors: %u", tvb_get_ntohl(tvb, index));
			index += 4;
			avp_len -= 4;

			if (avp_len < 4)
				break;
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
			  "Hardware Overruns: %u", tvb_get_ntohl(tvb, index));
			index += 4;
			avp_len -= 4;

			if (avp_len < 4)
				break;
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
			  "Buffer Overruns: %u", tvb_get_ntohl(tvb, index));
			index += 4;
			avp_len -= 4;

			if (avp_len < 4)
				break;
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
			  "Time-out Errors: %u", tvb_get_ntohl(tvb, index));
			index += 4;
			avp_len -= 4;

			if (avp_len < 4)
				break;
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
			  "Alignment Errors: %u", tvb_get_ntohl(tvb, index));
			index += 4;
			avp_len -= 4;
			break;

		case ACCM:
			if (avp_len < 2)
				break;
			index += 2;
			avp_len -= 2;

			if (avp_len < 4)
				break;
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
			  "Send ACCM: %u", tvb_get_ntohl(tvb, index));
			index += 4;
			avp_len -= 4;

			if (avp_len < 4)
				break;
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
			  "Receive ACCM: %u", tvb_get_ntohl(tvb, index));
			index += 4;
			avp_len -= 4;
			break;

		case RANDOM_VECTOR:
			proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
			  "Random Vector: %s",
			  tvb_bytes_to_str(tvb, index, avp_len));
			break;

		case PRIVATE_GROUP_ID:
			proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
			  "Private Group ID: %s",
			  tvb_bytes_to_str(tvb, index, avp_len));
			break;

		case RX_CONNECT_SPEED:
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 4,
			  "Rx Connect Speed: %u",
			  tvb_get_ntohl(tvb, index));
			break;

		case PPP_DISCONNECT_CAUSE_CODE:
			if (avp_len < 2)
				break;
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
			  "Disconnect Code: %u",
			  tvb_get_ntohs(tvb, index));
			index += 2;
			avp_len -= 2;

			if (avp_len < 2)
				break;
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 2,
			  "Control Protocol Number: %u",
			  tvb_get_ntohs(tvb, index));
			index += 2;
			avp_len -= 2;

			if (avp_len < 1)
				break;
			proto_tree_add_text(l2tp_avp_tree, tvb, index, 1,
			  "Direction: %s",
			  val_to_str(tvb_get_guint8(tvb, index), 
				     cause_code_direction_vals, 
				     "Reserved (%u)"));
			index += 1;
			avp_len -= 1;

			if (avp_len == 0)
				break;
			proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
			  "Message: %.*s", avp_len,
			  tvb_get_ptr(tvb, index, avp_len));
			break;

		default:
			proto_tree_add_text(l2tp_avp_tree, tvb, index, avp_len,
			  "Unknown AVP");
			break;
		}

		/* printf("Avp Decode avp_len= %d index= %d length= %d %x\n ",avp_len,
		   index,length,length); */

		index += avp_len;
	}

  }
}

/* registration with the filtering engine */
void
proto_register_l2tp(void)
{
	static hf_register_info hf[] = {
		{ &hf_l2tp_type,
		{ "Type", "lt2p.type", FT_UINT16, BASE_DEC, VALS(l2tp_type_vals), 0x8000,
			"Type bit", HFILL }},

		{ &hf_l2tp_length_bit,
		{ "Length Bit", "lt2p.length_bit", FT_BOOLEAN, 16, TFS(&l2tp_length_bit_truth), 0x4000,
			"Length bit", HFILL }},

		{ &hf_l2tp_seq_bit,
		{ "Sequence Bit", "lt2p.seq_bit", FT_BOOLEAN, 16, TFS(&l2tp_seq_bit_truth), 0x0800,
			"Sequence bit", HFILL }},

		{ &hf_l2tp_offset_bit,
		{ "Offset bit", "lt2p.offset_bit", FT_BOOLEAN, 16, TFS(&l2tp_offset_bit_truth), 0x0200,
			"Offset bit", HFILL }},

		{ &hf_l2tp_priority,
		{ "Priority", "lt2p.priority", FT_BOOLEAN, 16, TFS(&l2tp_priority_truth), 0x0100,
			"Priority bit", HFILL }},

		{ &hf_l2tp_version,
		{ "Version", "lt2p.version", FT_UINT16, BASE_DEC, NULL, 0x000f,
			"Version", HFILL }},

		{ &hf_l2tp_length,
		{ "Length","l2tp.length", FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_l2tp_tunnel,
		{ "Tunnel ID","l2tp.tunnel", FT_UINT16, BASE_DEC, NULL, 0x0, /* Probably should be FT_BYTES */
			"Tunnel ID", HFILL }},

		{ &hf_l2tp_session,
		{ "Session ID","l2tp.session", FT_UINT16, BASE_DEC, NULL, 0x0, /* Probably should be FT_BYTES */
			"Session ID", HFILL }},

		{ &hf_l2tp_Ns,
		{ "Ns","l2tp.Ns", FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_l2tp_Nr,
		{ "Nr","l2tp.Nr", FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_l2tp_offset,
		{ "Offset","l2tp.offset", FT_UINT16, BASE_DEC, NULL, 0x0,
			"Number of octest past the L2TP header at which the"
				"payload data starts.", HFILL }},

		{ &hf_l2tp_avp_mandatory,
		{ "Mandatory", "lt2p.avp.mandatory", FT_BOOLEAN, BASE_NONE, NULL, 0,
			"Mandatory AVP", HFILL }},

		{ &hf_l2tp_avp_hidden,
		{ "Hidden", "lt2p.avp.hidden", FT_BOOLEAN, BASE_NONE, NULL, 0,
			"Hidden AVP", HFILL }},

		{ &hf_l2tp_avp_length,
		{ "Length", "lt2p.avp.length", FT_UINT16, BASE_DEC, NULL, 0,
			"AVP Length", HFILL }},

		{ &hf_l2tp_avp_vendor_id,
		{ "Vendor ID", "lt2p.avp.vendor_id", FT_UINT16, BASE_DEC, VALS(avp_vendor_id_vals), 0,
			"AVP Vendor ID", HFILL }},

		{ &hf_l2tp_avp_type,
		{ "Type", "lt2p.avp.type", FT_UINT16, BASE_DEC, VALS(avp_type_vals), 0,
			"AVP Type", HFILL }},

		{ &hf_l2tp_tie_breaker,
		{ "Tie Breaker", "lt2p.tie_breaker", FT_UINT64, BASE_HEX, NULL, 0,
			"Tie Breaker", HFILL }},

	};

	static gint *ett[] = {
		&ett_l2tp,
		&ett_l2tp_ctrl,
		&ett_l2tp_avp,
	};

	proto_l2tp = proto_register_protocol(
		"Layer 2 Tunneling Protocol", "L2TP", "l2tp");
	proto_register_field_array(proto_l2tp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_l2tp(void)
{
	dissector_add("udp.port", UDP_PORT_L2TP, dissect_l2tp,
	    proto_l2tp);

	/*
	 * Get a handle for the PPP-in-HDLC-like-framing dissector.
	 */
	ppp_hdlc_handle = find_dissector("ppp_hdlc");
}
