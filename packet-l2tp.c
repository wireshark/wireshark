/* packet-l2tp.c
 * Routines for Layer Two Tunnelling Protocol (L2TP) (RFC 2661) packet
 * disassembly
 * John Thomes <john@ensemblecom.com>
 *
 * Minor changes by: (2000-01-10)
 * Laurent Cazalet <laurent.cazalet@mailclub.net>
 * Thomas Parvais <thomas.parvais@advalvas.be>
 *
 * $Id: packet-l2tp.c,v 1.18 2001/01/03 06:55:29 guy Exp $
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


static int proto_l2tp = -1;
static int hf_l2tp_code = -1; /* XXX - to be removed */
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
#define FRAMING_ASYNC(msg_info) (msg_info & 0x0001) /* ASYNCFraming Type */
#define FRAMING_SYNC(msg_info)  (msg_info & 0x0002) /* SYNC Type */


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
};

static const true_false_string l2tp_length_bit_truth =
	{ "Length field is present", "Length field is not present" };

static const true_false_string l2tp_seq_bit_truth =
	{ "Ns and Nr fields are present", "Ns and Nr fields are not present" };

static const true_false_string l2tp_offset_bit_truth =
	{ "Offset Size field is present", "Offset size field is not present" };

static const true_false_string l2tp_priority_truth =
	{ "This data message has priority", "No priority" };

#define NUM_AUTH_TYPES  6
static const char *authen_types[NUM_AUTH_TYPES] = {
  "Reserved",
  "Textual username and password",
  "PPP CHAP",
  "PPP PAP",
  "No Authentication",
  "Microsoft CHAP Version 1",
};

#define  CONTROL_MESSAGE  0
#define  RESULT_ERROR_CODE 1
#define  PROTOCOL_VERSION  2
#define  FRAMING_CAPABIlITIES 3
#define  BEARER_CAPABIlITIES 4
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
#define  UNKNOWN_MESSAGE 20
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
#define  UNKOWN_MESSAGE_36
#define  PRIVATE_GROUP_ID 37
#define  RX_CONNECT_SPEED 38
#define  SEQUENCING_REQUIRED 39

#define NUM_AVP_TYPES  40
static const char *avptypestr[NUM_AVP_TYPES] = {
  "Control Message ",
  "Result-Error Code ",
  "Protocol Version ",
  "Framing Capabilities ",
  "Bearer Capabilities  ",
  "Tie Breaker ",
  "Firmware Revision ",
  "Host Name ",
  "Vendor Name ",
  "Assigned Tunnel ID ",
  "Receive Window Size ",
  "Challenge ",
  "Cause Code ",
  "Challenge Response ",
  "Assigned Session ",
  "Call Serial Number ",
  "Minimun BPS ",
  "Maximum bps ",
  "Bearer Type ",
  "Framing Type ",
  "Unknown Message ",
  "Called Number ",
  "Calling Number ",
  "Sub-Address ",
  "Connect Speed ",
  "Physical Channel ",
  "Initial Received lcP ",
  "Last Send LCP CONFREQ ",
  "Last Received LCP CONFREQ ",
  "Proxy Authen Type ",
  "Proxy Authen Name ",
  "Proxy Authen Challenge ",
  "Proxy Authen ID ",
  "Proxy Authen Response ",
  "Call status AVPs ",
  "ACCM ",
  "Unknown Message ",
  "Private group ID ",
  "RxConnect Speed ",
  "Sequencing Required ",
};


static gchar textbuffer[200];

static dissector_handle_t ppp_handle;

static void
dissect_l2tp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *l2tp_tree=NULL, *l2tp_avp_tree, *ctrl_tree;
  proto_item *ti, *tf;
  int rhcode;
  int index = 0;
  int tmp_index;
  int proto_length = 0;
  unsigned short  length = 0;		/* Length field */
  unsigned short  tid;			/* Tunnel ID */
  unsigned short  cid;			/* Call ID */
  unsigned short  offset_size;		/* Offset size */
  unsigned short ver_len_hidden;
  unsigned short vendor;
  unsigned short avp_type;
  unsigned short msg_type;
  unsigned short avp_len;
  unsigned short result_code;
  unsigned short error_code;
  unsigned short avp_ver;
  unsigned short avp_rev;
  unsigned short framing;
  unsigned short firmware_rev;
  unsigned short gen_type;
  unsigned long long_type;
  char  error_string[100];
  char  message_string[200];

  guint16	control;
  tvbuff_t	*next_tvb;

  CHECK_DISPLAY_AS_DATA(proto_l2tp, tvb, pinfo, tree);

  pinfo->current_proto = "L2TP";
  if (check_col(pinfo->fd, COL_PROTOCOL))	/* build output for closed L2tp frame displayed  */
        col_set_str(pinfo->fd, COL_PROTOCOL, "L2TP"); 

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
		call_dissector(ppp_handle, next_tvb, pinfo, tree);
	}
	return;
  }

  if (tree) {
	if (!LENGTH_BIT(control)) {
		return;
 	}
	while (index < length ) {    /* Process AVP's */
                tmp_index	= index;
   		ver_len_hidden	= tvb_get_ntohs(tvb, tmp_index);
   		avp_len		= AVP_LENGTH(ver_len_hidden);
   		vendor		= tvb_get_ntohs(tvb, (tmp_index+=2));
   		avp_type	= tvb_get_ntohs(tvb, (tmp_index+=2));

		tf =  proto_tree_add_uint_format(l2tp_tree,hf_l2tp_code, tvb, index , avp_len,
                                                 rhcode, "AVP Type  %s  ",  (NUM_AVP_TYPES > avp_type)
                                                 ? avptypestr[avp_type] : "Unknown");
                l2tp_avp_tree = proto_item_add_subtree(tf,  ett_l2tp_avp);

                proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb, index , 1,
                                           rhcode, " Mandatory:%s" ,
					   (MANDATORY_BIT(ver_len_hidden)) ? "True" : "False" );
                proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb, index , 1,
                                           rhcode, " Hidden:%s" ,
					   (HIDDEN_BIT(ver_len_hidden)) ? "True" : "False" );
		proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb, (index + 1), 1,
					   rhcode, " Length:%d" , avp_len );

		if (avp_len == 0) {
			proto_tree_add_text(l2tp_avp_tree, tvb, (index + 1), 1, "Length should not be zero");
			return;
		}

		if (HIDDEN_BIT(ver_len_hidden)) { /* don't try do display hidden */
			index += avp_len;
			continue;
		}

		switch (avp_type) {

		case CONTROL_MESSAGE:
		    msg_type = tvb_get_ntohs(tvb, (tmp_index+=2));
		    proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb, index + 6, 2 ,
					       rhcode, " Control Message Type: (%d)  %s", msg_type,
					       ((NUM_CONTROL_CALL_TYPES + 1 ) > msg_type) ?
					       calltypestr[msg_type] : "Unknown" );
		    break;

		case RESULT_ERROR_CODE:
			if ( avp_len >= 8 ) {
				result_code = tvb_get_ntohs(tvb, (tmp_index+=2));
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 6,
				  2, rhcode,
				  " Result code: %d",  result_code  );
		
			}
			if ( avp_len >= 10 ) {
				error_code = tvb_get_ntohs(tvb, (tmp_index+=2));
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 8,
				  2, rhcode,
				  " Error code: %d", error_code);
			}
			if ( avp_len > 10 ) {
				memset(error_string,'\0' ,sizeof(error_string));
				strncpy(error_string, tvb_get_ptr(tvb, tmp_index,(avp_len - 10)),
						avp_len - 10);
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb, index + 10, (avp_len - 10),
				  rhcode, " Error Message: %s",  error_string  );
			}
			break;

		case PROTOCOL_VERSION:
			avp_ver = tvb_get_ntohs(tvb, (tmp_index+=2));
			avp_rev = tvb_get_ntohs(tvb, (tmp_index+=2));
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb, index + 6, 1,
			  rhcode, " Version: %d",  ((avp_ver&0xff00)>>8)  );
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb, index + 7, 1,
			  rhcode, " Revision: %d",  (avp_ver&0x00ff));
			break;

		case FRAMING_CAPABIlITIES:
			tmp_index+=2;
			framing = tvb_get_ntohs(tvb, (tmp_index+=2));
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb, index + 6, 4,
			  rhcode, " ASYNC FRAMING: %s" , (FRAMING_ASYNC(framing)) ? "True" : "False" );  
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb, index + 6, 4,
			  rhcode, " SYNC FRAMING: %s" , (FRAMING_SYNC(framing)) ? "True" : "False" );  
			break;

		case BEARER_CAPABIlITIES:
			tmp_index+=2;
			framing = tvb_get_ntohs(tvb, (tmp_index+=2));
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb, index + 6, 4 ,
			  rhcode, " Analog Access: %s" , (FRAMING_ASYNC(framing)) ? "True" : "False" );  
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb, index + 6, 4,
			  rhcode, " Digital Access: %s" , (FRAMING_SYNC(framing)) ? "True" : "False" );  
			break;

		case TIE_BREAKER:
			long_type = tvb_get_ntohl(tvb, (tmp_index+=8));
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb, index + 6, 1,
			  rhcode, " TIE_BREAKER %lu 0x%lx", long_type,long_type );
			break;

		case FIRMWARE_REVISION:
			firmware_rev = tvb_get_ntohs(tvb, (tmp_index+=2));
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb, index + 6, 2,
			  rhcode, " Firmware Revision: %d 0x%x", firmware_rev,firmware_rev );
			break;

		case HOST_NAME:
			memset(error_string,'\0',sizeof(error_string));
			strncpy(error_string, tvb_get_ptr(tvb, (tmp_index+=2), (avp_len - 6)),
					avp_len - 6);
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb, index + 6, 
			  (avp_len - 6), rhcode, " Host Name: %s",  error_string  );
			break;

		case VENDOR_NAME:
			memset(message_string,'\0' ,sizeof(message_string));
			strncpy(message_string, tvb_get_ptr(tvb, (tmp_index+=2),(avp_len - 6)),
					avp_len - 6);
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb, index + 6, 
			  (avp_len - 6), rhcode, " Vendor Name: %s",  message_string  );
			break;

		case ASSIGNED_TUNNEL_ID:
			gen_type = tvb_get_ntohs(tvb, (tmp_index+=2));
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 6,
			  2, rhcode, " Tunnel ID: %d",  gen_type  );
			break;

		case RECEIVE_WINDOW_SIZE:
			gen_type = tvb_get_ntohs(tvb, (tmp_index+=2));
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 6,
			  2, rhcode, " Receive Window Size: %d",  gen_type  );
			break;

		case CHALLENGE:
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 6,
			  (avp_len - 6 ), rhcode, "  CHAP Challenge: ");
			break;

		case CHALLENGE_RESPONSE:
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 6,
			  (avp_len - 6 ), rhcode, "  CHAP Challenge Response: ");
			break;

		case CAUSE_CODE:
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 6,
			  1, rhcode, " Cause Code: ");
			break;

		case ASSIGNED_SESSION:
			gen_type = tvb_get_ntohs(tvb, (tmp_index+=2));
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 6,
			  2, rhcode, " Assigned Session: %d",  gen_type  );
			break;

		case CALL_SERIAL_NUMBER:
			gen_type = tvb_get_ntohs(tvb, (tmp_index+=2));
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 6,
			  4, rhcode, " Call Serial Number: %d",  gen_type  );
			break;

		case MINIMUM_BPS:
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 6,
			  4, rhcode, " Minimum BPS: ");
			break;

		case MAXIMUM_BPS:
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 6,
			  4, rhcode, " Maximum BPS ");
			break;

		case BEARER_TYPE:
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 6,
			  4, rhcode, " Bearer Type: ");
			break;

		case FRAMING_TYPE:
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 6,
			  4, rhcode, " Framing Type: ");
			break;

		case UNKNOWN_MESSAGE:
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 6,
			  1, rhcode, " Unknown Message: ");
			break;

		case CALLED_NUMBER:
			memset(message_string,'\0' ,sizeof(message_string));
			strncpy(message_string, tvb_get_ptr(tvb, (tmp_index+=2),(avp_len - 6)),
					avp_len - 6);
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb, index + 6, 
			  (avp_len - 6), rhcode, " Called Number: %s",  message_string  );
			break;

		case CALLING_NUMBER:
			memset(message_string,'\0' ,sizeof(message_string));
			strncpy(message_string, tvb_get_ptr(tvb, (tmp_index+=2),(avp_len - 6)),
					avp_len - 6);
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb, index + 6, 
			  (avp_len - 6), rhcode, " Calling Number: %s",  message_string  );
			break;

		case SUB_ADDRESS:
			memset(message_string,'\0' ,sizeof(message_string));
			strncpy(message_string, tvb_get_ptr(tvb, (tmp_index+=2),(avp_len - 6)),
					avp_len - 6);
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb, index + 6, 
			  (avp_len - 6), rhcode, " Sub-Address: %s",  message_string  );
			break;

		case TX_CONNECT_SPEED:
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 6,
			  4, rhcode, " Connect Speed: ");
			break;

		case PHYSICAL_CHANNEL:
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 6,
			  4, rhcode, " Physical Channel: ");
			break;

		case INITIAL_RECEIVED_LCP:
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 6,
			  (avp_len - 6 ), rhcode, " Initial LCP Conf REQ: ");
			break;

		case LAST_SEND_LCP_CONFREQ:
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 6,
			  (avp_len - 6 ), rhcode, " Last Sent LCP Conf REQ: ");
			break;

		case LAST_RECEIVED_LCP_CONFREQ:
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 6,
			  (avp_len - 6 ), rhcode, " Last Received LCP Conf REQ: ");
			break;

		case PROXY_AUTHEN_TYPE:
			msg_type = tvb_get_ntohs(tvb, (tmp_index+=2));
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 6,
			  1, rhcode, " Proxy Authen Type: %s ", authen_types[msg_type] );
			break;

		case PROXY_AUTHEN_NAME:
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 6,
			  (avp_len - 6 ), rhcode, " Proxy Authen Name: ");
			break;

		case PROXY_AUTHEN_CHALLENGE:
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 6,
			  (avp_len - 6 ), rhcode, " Proxy Authen Challenge: ");
			break;

		case PROXY_AUTHEN_ID:
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 6,
			  2, rhcode, " Paorx Authen ID: ");
			break;

		case PROXY_AUTHEN_RESPONSE:
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 6,
			  (avp_len - 6 ), rhcode, " Proxy Authen Response: ");
			break;

		case CALL_STATUS_AVPS:
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 6,
			  4, rhcode, "  CRC Errors: ");
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 10,
			  4, rhcode, "  Framing Errors: ");
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 14,
			  4, rhcode, "  Hardware Overruns: ");
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 18,
			  4, rhcode, "  Buffer Overruns: ");
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 23,
			  4, rhcode, "  Time-out Errors: ");
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 26,
			  4, rhcode, "  Alignment Errors: ");
			break;

		case ACCM:
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 6,
			  2, rhcode, " Reserve Quantity: ");
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 8,
			  4, rhcode, " Send ACCM: ");
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 12,
			  4, rhcode, " Recv ACCM: ");
			break;

		case PRIVATE_GROUP_ID:
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 6,
			  1, rhcode, " Private Group ID: ");
			break;

		case RX_CONNECT_SPEED:
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index + 6,
			  4, rhcode, " RX Connect Speed: ");
			break;

		case SEQUENCING_REQUIRED:
			proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, tvb,index ,
			  1, rhcode, " Sequencing Required: ");
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
		{ &hf_l2tp_code,
		{ "code", "lt2p.code", FT_UINT16, BASE_DEC, NULL, 0, /* XXX - to be removed */
			"Type bit" }},

		{ &hf_l2tp_type,
		{ "Type", "lt2p.type", FT_UINT16, BASE_DEC, VALS(l2tp_type_vals), 0x8000,
			"Type bit" }},

		{ &hf_l2tp_length_bit,
		{ "Length Bit", "lt2p.length_bit", FT_BOOLEAN, 16, TFS(&l2tp_length_bit_truth), 0x4000,
			"Length bit" }},

		{ &hf_l2tp_seq_bit,
		{ "Sequence Bit", "lt2p.seq_bit", FT_BOOLEAN, 16, TFS(&l2tp_seq_bit_truth), 0x0800,
			"Sequence bit" }},

		{ &hf_l2tp_offset_bit,
		{ "Offset bit", "lt2p.offset_bit", FT_BOOLEAN, 16, TFS(&l2tp_offset_bit_truth), 0x0200,
			"Offset bit" }},

		{ &hf_l2tp_priority,
		{ "Priority", "lt2p.priority", FT_BOOLEAN, 16, TFS(&l2tp_priority_truth), 0x0100,
			"Priority bit" }},

		{ &hf_l2tp_version,
		{ "Version", "lt2p.version", FT_UINT16, BASE_DEC, NULL, 0x000f,
			"Version" }},

		{ &hf_l2tp_length,
		{ "Length","l2tp.length", FT_UINT16, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_l2tp_tunnel,
		{ "Tunnel ID","l2tp.tunnel", FT_UINT16, BASE_DEC, NULL, 0x0, /* Probably should be FT_BYTES */
			"Tunnel ID" }},

		{ &hf_l2tp_session,
		{ "Session ID","l2tp.session", FT_UINT16, BASE_DEC, NULL, 0x0, /* Probably should be FT_BYTES */
			"Session ID" }},

		{ &hf_l2tp_Ns,
		{ "Ns","l2tp.Ns", FT_UINT16, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_l2tp_Nr,
		{ "Nr","l2tp.Nr", FT_UINT16, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_l2tp_offset,
		{ "Offset","l2tp.offset", FT_UINT16, BASE_DEC, NULL, 0x0,
			"Number of octest past the L2TP header at which the"
				"payload data starts." }},

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
	dissector_add("udp.port", UDP_PORT_L2TP, dissect_l2tp);

	/*
	 * Get a handle for the PPP dissector.
	 */
	ppp_handle = find_dissector("ppp");
}
