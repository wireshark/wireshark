/* packet-l2tp.c
 * Routines for Layer Two Tunnelling Protocol (L2TP) (RFC 2661) packet
 * disassembly
 * John Thomes <john@ensemblecom.com>
 *
 * Minor changes by: (2000-01-10)
 * Laurent Cazalet <laurent.cazalet@mailclub.net>
 * Thomas Parvais <thomas.parvais@advalvas.be>
 *
 * $Id: packet-l2tp.c,v 1.8 2000/04/08 07:07:24 guy Exp $
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
static int hf_l2tp_length = -1;
static int hf_l2tp_code = -1;
static int hf_l2tp_id =-1;

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
#define OFFSET_BIT(msg_info) (msg_info & 0x0300)    /* Offset */
#define PRIORITY_BIT(msg_info) (msg_info & 0x0100)  /* Priority */
#define L2TP_VERSION(msg_info) (msg_info & 0x0007)  /* Version of l2tp */
#define MANDATORY_BIT(msg_info) (msg_info & 0x8000) /* Mandatory = 1 */
#define HIDDEN_BIT(msg_info) (msg_info & 0x4000)    /* Hidden = 1 */
#define AVP_LENGTH(msg_info) (msg_info & 0x03ff)    /* AVP Length */
#define FRAMING_ASYNC(msg_info) (msg_info & 0x0001) /* ASYNCFraming Type */
#define FRAMING_SYNC(msg_info)  (msg_info & 0x0002) /* SYNC Type */



static gint ett_l2tp = -1;
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


 static const char *control_msg="Control Message";
 static const char *data_msg="Data    Message";


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
#define  UNOWN_MESSAGE_36
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

static void
dissect_l2tp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
  proto_tree *l2tp_tree, *l2tp_avp_tree;
  proto_item *ti, *tf;
  int rhcode;
  u_char *tmp_ptr;			/* temp pointer used during AVP decode */
  u_char *ptr;				/* pointer used during l2tp  decode */
  int index = 2;			/* keeps track of depth into the AVP */
  unsigned short  ver;		        /* Version and more */
  unsigned short  length;		/* Length field */
  unsigned short  tid;			/* Tunnel ID */
  unsigned short  cid;			/* Call ID */
  unsigned short  Nr;			/* Next recv */
  unsigned short  Ns;			/* Next sent */
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

  ptr =  (u_char * )pd;			/* point to the frame */
  ptr = ptr + offset;			/* current offset into the decoded frame  */
  memcpy(&ver,ptr,sizeof(unsigned short)); /* collect the version */
  ver = htons(ver);
  rhcode= 10;
  Ns = Nr = 0;

  if (LENGTH_BIT(ver)) { 		/* length field included ? */
      ptr += 2; index += 2; 		/* skip ahead */
      memcpy(&length,ptr,sizeof(unsigned short)); /* collect the length */
      length = (htons(length));
  }

  memcpy(&tid,(ptr+=2),sizeof(unsigned short));  /* collect the tunnel id & call id */ 
  memcpy(&cid,(ptr+=2),sizeof(unsigned short));
  index += 4;
  if (check_col(fd, COL_PROTOCOL))	/* build output for closed L2tp frame displayed  */
        col_add_str(fd, COL_PROTOCOL, "L2TP"); 
  if (check_col(fd, COL_INFO)) {
        tid = htons(tid); cid = htons(cid); 

        if (CONTROL_BIT(ver)) {
            /* CONTROL MESSAGE */
            tmp_ptr = ptr;

              if ((LENGTH_BIT(ver))&&(length==12))  		/* ZLB Message */
                  sprintf(textbuffer,"%s - ZLB      (tunnel id=%d, session id=%d)",
                          control_msg , tid ,cid);
              else
              {
                if (SEQUENCE_BIT(ver)) {
                    tmp_ptr=tmp_ptr+4;
                }
    
                tmp_ptr+=4;
    
                memcpy(&avp_type,(tmp_ptr+=2),sizeof(unsigned short));
                avp_type=htons(avp_type);
    
                if (avp_type == CONTROL_MESSAGE)
                {
                    /* We print message type */
                    memcpy(&msg_type,(tmp_ptr+=2),sizeof(unsigned short));
                    msg_type=ntohs(msg_type);
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
        col_add_fstr(fd,COL_INFO,textbuffer);
  }
  if (tree) {
        ti = proto_tree_add_item(tree,proto_l2tp, offset, length , NULL);
	l2tp_tree = proto_item_add_subtree(ti, ett_l2tp);
	proto_tree_add_uint_format(l2tp_tree,hf_l2tp_code, offset ,1,
 	rhcode, "Packet Type: %s Tunnel Id=%d Session Id=%d",( CONTROL_BIT(ver) ? control_msg : data_msg) ,tid,cid);
        if (LENGTH_BIT(ver)) {
	        proto_tree_add_uint_format(l2tp_tree,hf_l2tp_code, (offset +=  2), 2,
                rhcode, "Length: %d ", length);
        }
        if (SEQUENCE_BIT(ver)) {
  		memcpy(&Ns,(ptr+=2),sizeof(unsigned short));
  		memcpy(&Nr,(ptr+=2),sizeof(unsigned short));
  		index += 4;
	        proto_tree_add_uint_format(l2tp_tree,hf_l2tp_code, (offset +=  6 ), 4,
                rhcode, "Ns: %d Nr: %d ", htons(Ns), htons(Nr));
        }
        if ((LENGTH_BIT(ver))&&(length==12)) {
            proto_tree_add_uint_format(l2tp_tree,hf_l2tp_code,offset,1,rhcode,
                                       "Zero Length Bit message");
        }
        if (!CONTROL_BIT(ver)) {  /* Data Messages so we are done */
	         proto_tree_add_uint_format(l2tp_tree,hf_l2tp_code, (offset +=  4) , (length - 12 )  , rhcode, "Data: ");
                 return;
         }

	offset += 4;
	while (index < length ) {    /* Process AVP's */
                tmp_ptr =  ptr;
                memcpy(&ver_len_hidden,(tmp_ptr+=2),sizeof(unsigned short));
   		avp_len =  AVP_LENGTH(htons(ver_len_hidden));
		index += avp_len; /* track how far into the control msg */ 
		memcpy(&vendor,(tmp_ptr+=2),sizeof(unsigned short));
		memcpy(&avp_type,(tmp_ptr+=2),sizeof(unsigned short));
		avp_type=htons(avp_type);
		tf =  proto_tree_add_uint_format(l2tp_tree,hf_l2tp_code, offset , avp_len,
                                                 rhcode, "AVP Type  %s  ",  (NUM_AVP_TYPES > avp_type)
                                                 ? avptypestr[avp_type] : "Unknown");
                l2tp_avp_tree = proto_item_add_subtree(tf,  ett_l2tp_avp);

                proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, offset , 1,
                                           rhcode, " Mandatory:%s" , (MANDATORY_BIT(htons(ver_len_hidden))) ? "True" : "False" );
                proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, offset , 1,
                                           rhcode, " Hidden:%s" , (HIDDEN_BIT(htons(ver_len_hidden))) ? "True" : "False" );
                        proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, (offset + 1), 1,
                                                   rhcode, " Length:%d" , avp_len );

			if (HIDDEN_BIT(htons(ver_len_hidden))) { /* don't try do display hidden */
				ptr = ptr +  avp_len;
				continue;
			}

			switch (avp_type) {

			case CONTROL_MESSAGE:
                            memcpy(&msg_type,(tmp_ptr+=2),sizeof(unsigned short));
                            msg_type=htons(msg_type);
                            proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, offset + 6, 2 ,
                                                       rhcode, " Control Message Type: (%d)  %s", msg_type,
                                                       ((NUM_CONTROL_CALL_TYPES + 1 ) > msg_type) ?
                                                       calltypestr[msg_type] : "Unknown" );
                            break;

			case RESULT_ERROR_CODE:
				if ( avp_len >= 8 ) {
					memcpy(&result_code,(tmp_ptr+=2),sizeof(unsigned short));
					result_code=htons(result_code);
					proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 6,
					  2, rhcode,
					  " Result code: %d",  result_code  );
			
				}
				if ( avp_len >= 10 ) {
					memcpy(&error_code,(tmp_ptr+=2),sizeof(unsigned short));
					error_code=htons(error_code);
					proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 8,
					  2, rhcode,
					  " Error code: %d", error_code);
				}
				if ( avp_len > 10 ) {
					memset(error_string,'\0' ,sizeof(error_string));
					strncpy(error_string,(tmp_ptr),(avp_len - 10));
					proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, offset + 10, (avp_len - 10),
					  rhcode, " Error Message: %s",  error_string  );
				}
				break;

			case PROTOCOL_VERSION:
				tmp_ptr+=2;
				memcpy(&avp_ver,(tmp_ptr),sizeof(unsigned short));
				memcpy(&avp_rev,(tmp_ptr),sizeof(unsigned short));
				avp_ver=(htons(avp_ver));
				avp_rev=(htons(avp_rev));
				memcpy(&avp_rev,(tmp_ptr+=2),sizeof(unsigned short));
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, offset + 6, 1,
				  rhcode, " Version: %d",  ((avp_ver&0xff00)>>8)  );
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, offset + 7, 1,
				  rhcode, " Revision: %d",  (avp_ver&0x00ff));
				break;

			case FRAMING_CAPABIlITIES:
				tmp_ptr+=2;
				memcpy(&framing,(tmp_ptr+=2),sizeof(unsigned short));
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, offset + 6, 4,
				  rhcode, " ASYNC FRAMING: %s" , (FRAMING_ASYNC(htons(framing))) ? "True" : "False" );  
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, offset + 6, 4,
				  rhcode, " SYNC FRAMING: %s" , (FRAMING_SYNC(htons(framing))) ? "True" : "False" );  
				break;

			case BEARER_CAPABIlITIES:
				tmp_ptr+=2;
				memcpy(&framing,(tmp_ptr+=2),sizeof(unsigned short));
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, offset + 6, 4 ,
				  rhcode, " Analog Access: %s" , (FRAMING_ASYNC(htons(framing))) ? "True" : "False" );  
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, offset + 6, 4,
				  rhcode, " Digital Access: %s" , (FRAMING_SYNC(htons(framing))) ? "True" : "False" );  
				break;

			case TIE_BREAKER:
				memcpy(&long_type,(tmp_ptr+=8),sizeof(unsigned long));
            			long_type = htonl(long_type);
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, offset + 6, 1,
				  rhcode, " TIE_BREAKER %lu 0x%lx", long_type,long_type );
				break;

			case FIRMWARE_REVISION:
				memcpy(&firmware_rev,(tmp_ptr+=2),sizeof(unsigned short));
				firmware_rev=htons(firmware_rev);
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, offset + 6, 2,
				  rhcode, " Firmware Revision: %d 0x%x", firmware_rev,firmware_rev );
				break;

			case HOST_NAME:
				memset(error_string,'\0',sizeof(error_string));
				strncpy(error_string,(tmp_ptr+=2),(avp_len - 6));
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, offset + 6, 
				  (avp_len - 6), rhcode, " Host Name: %s",  error_string  );
				break;

			case VENDOR_NAME:
				memset(message_string,'\0' ,sizeof(message_string));
				strncpy(message_string,(tmp_ptr+=2),(avp_len - 6));
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, offset + 6, 
				  (avp_len - 6), rhcode, " Vendor Name: %s",  message_string  );
				break;

			case ASSIGNED_TUNNEL_ID:
				memcpy(&gen_type,(tmp_ptr+=2),sizeof(unsigned short));
				gen_type=htons(gen_type);
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 6,
				  2, rhcode, " Tunnel ID: %d",  gen_type  );
				break;

			case RECEIVE_WINDOW_SIZE:
				memcpy(&gen_type,(tmp_ptr+=2),sizeof(unsigned short));
				gen_type=htons(gen_type);
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 6,
				  2, rhcode, " Receive Window Size: %d",  gen_type  );
				break;

			case CHALLENGE:
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 6,
				  (avp_len - 6 ), rhcode, "  CHAP Challenge: ");
				break;

			case CHALLENGE_RESPONSE:
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 6,
				  (avp_len - 6 ), rhcode, "  CHAP Challenge Response: ");
				break;

			case CAUSE_CODE:
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 6,
				  1, rhcode, " Cause Code: ");
				break;

			case ASSIGNED_SESSION:
				memcpy(&gen_type,(tmp_ptr+=2),sizeof(unsigned short));
				gen_type=htons(gen_type);
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 6,
				  2, rhcode, " Assigned Session: %d",  gen_type  );
				break;

			case CALL_SERIAL_NUMBER:
				memcpy(&gen_type,(tmp_ptr+=2),sizeof(unsigned short));
				gen_type=htons(gen_type);
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 6,
				  4, rhcode, " Call Serial Number: %d",  gen_type  );
				break;

			case MINIMUM_BPS:
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 6,
				  4, rhcode, " Minimum BPS: ");
				break;

			case MAXIMUM_BPS:
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 6,
				  4, rhcode, " Maximum BPS ");
				break;

			case BEARER_TYPE:
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 6,
				  4, rhcode, " Bearer Type: ");
				break;

			case FRAMING_TYPE:
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 6,
				  4, rhcode, " Framing Type: ");
				break;

			case UNKNOWN_MESSAGE:
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 6,
				  1, rhcode, " Unknown Message: ");
				break;

			case CALLED_NUMBER:
				memset(message_string,'\0' ,sizeof(message_string));
				strncpy(message_string,(tmp_ptr+=2),(avp_len - 6));
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, offset + 6, 
				  (avp_len - 6), rhcode, " Called Number: %s",  message_string  );
				break;

			case CALLING_NUMBER:
				memset(message_string,'\0' ,sizeof(message_string));
				strncpy(message_string,(tmp_ptr+=2),(avp_len - 6));
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, offset + 6, 
				  (avp_len - 6), rhcode, " Calling Number: %s",  message_string  );
				break;

			case SUB_ADDRESS:
				memset(message_string,'\0' ,sizeof(message_string));
				strncpy(message_string,(tmp_ptr+=2),(avp_len - 6));
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code, offset + 6, 
				  (avp_len - 6), rhcode, " Sub-Address: %s",  message_string  );
				break;

			case TX_CONNECT_SPEED:
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 6,
				  4, rhcode, " Connect Speed: ");
				break;

			case PHYSICAL_CHANNEL:
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 6,
				  4, rhcode, " Physical Channel: ");
				break;

			case INITIAL_RECEIVED_LCP:
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 6,
				  (avp_len - 6 ), rhcode, " Initial LCP Conf REQ: ");
				break;

			case LAST_SEND_LCP_CONFREQ:
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 6,
				  (avp_len - 6 ), rhcode, " Last Sent LCP Conf REQ: ");
				break;

			case LAST_RECEIVED_LCP_CONFREQ:
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 6,
				  (avp_len - 6 ), rhcode, " Last Received LCP Conf REQ: ");
				break;

			case PROXY_AUTHEN_TYPE:
				memcpy(&msg_type,(tmp_ptr+=2),sizeof(unsigned short));
				msg_type=htons(msg_type);
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 6,
				  1, rhcode, " Proxy Authen Type: %s ", authen_types[msg_type] );
				break;

			case PROXY_AUTHEN_NAME:
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 6,
				  (avp_len - 6 ), rhcode, " Proxy Authen Name: ");
				break;

			case PROXY_AUTHEN_CHALLENGE:
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 6,
				  (avp_len - 6 ), rhcode, " Proxy Authen Challenge: ");
				break;

			case PROXY_AUTHEN_ID:
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 6,
				  2, rhcode, " Paorx Authen ID: ");
				break;

			case PROXY_AUTHEN_RESPONSE:
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 6,
				  (avp_len - 6 ), rhcode, " Proxy Authen Response: ");
				break;

			case CALL_STATUS_AVPS:
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 6,
				  4, rhcode, "  CRC Errors: ");
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 10,
				  4, rhcode, "  Framing Errors: ");
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 14,
				  4, rhcode, "  Hardware Overruns: ");
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 18,
				  4, rhcode, "  Buffer Overruns: ");
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 23,
				  4, rhcode, "  Time-out Errors: ");
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 26,
				  4, rhcode, "  Alignment Errors: ");
				break;

			case ACCM:
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 6,
				  2, rhcode, " Reserve Quantity: ");
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 8,
				  4, rhcode, " Send ACCM: ");
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 12,
				  4, rhcode, " Recv ACCM: ");
				break;

			case PRIVATE_GROUP_ID:
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 6,
				  1, rhcode, " Private Group ID: ");
				break;

			case RX_CONNECT_SPEED:
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset + 6,
				  4, rhcode, " RX Connect Speed: ");
				break;

			case SEQUENCING_REQUIRED:
				proto_tree_add_uint_format(l2tp_avp_tree,hf_l2tp_code,offset ,
				  1, rhcode, " Sequencing Required: ");
				break;
			}

			/* printf("Avp Decode avp_len= %d index= %d length= %d %x\n ",avp_len,
			   index,length,length); */

			ptr = ptr +  avp_len;
			offset += avp_len;
		}
	}
}

/* registration with the filtering engine */
void
proto_register_l2tp(void)
{
	static hf_register_info hf[] = {
		{ &hf_l2tp_code,
		{ "Code","l2tp.code", FT_UINT8, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_l2tp_id,
		{ "Identifier",	"l2tp.id", FT_UINT8, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_l2tp_length,
		{ "Length","l2tp.length", FT_UINT16, BASE_DEC, NULL, 0x0,
			"" }}
	};

	static gint *ett[] = {
		&ett_l2tp,
		&ett_l2tp_avp,
	};

	proto_l2tp = proto_register_protocol ("L2TP Protocol", "l2tp");
	proto_register_field_array(proto_l2tp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_l2tp(void)
{
	dissector_add("udp.port", UDP_PORT_L2TP, dissect_l2tp);
}
