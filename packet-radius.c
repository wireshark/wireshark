/* packet-radius.c
 * Routines for RADIUS packet disassembly
 *
 * $Id: packet-radius.c,v 1.6 1999/12/02 23:25:29 gram Exp $
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
#include <ctype.h>
#include <glib.h>
#include "packet.h"
#include "resolv.h"

static int proto_radius = -1;
static int hf_radius_length = -1;
static int hf_radius_code = -1;
static int hf_radius_id =-1;

static gint ett_radius = -1;
static gint ett_radius_avp = -1;

typedef struct _e_radiushdr {
        guint8 rh_code;
        guint8 rh_ident;
        guint16 rh_pktlength;
} e_radiushdr;

typedef struct _e_avphdr {
        guint8 avp_type;
        guint8 avp_length;
} e_avphdr;

typedef struct _value_value_pair {
        guint16 val1;
        guint16 val2;
} value_value_pair;

#define RADIUS_ACCESS_REQUEST 1
#define RADIUS_ACCESS_ACCEPT  2
#define RADIUS_ACCESS_REJECT  3
#define RADIUS_ACCOUNTING_REQUEST 4
#define RADIUS_ACCOUNTING_RESPONSE 5
#define RADIUS_ACCESS_CHALLENGE 11
#define RADIUS_STATUS_SERVER 12
#define RADIUS_STATUS_CLIENT 13
#define RADIUS_RESERVED 255

#define RD_TP_USER_NAME 1
#define RD_TP_USER_PASSWORD 2
#define RD_TP_CHAP_PASSWORD 3
#define RD_TP_NAS_IP_ADDRESS 4
#define RD_TP_NAS_PORT 5
#define RD_TP_SERVICE_TYPE 6
#define RD_TP_FRAMED_PROTOCOL 7
#define RD_TP_FRAMED_IP_ADDRESS 8
#define RD_TP_FRAMED_IP_NETMASK 9
#define RD_TP_FRAMED_ROUTING 10
#define RD_TP_FILTER_ID 11
#define RD_TP_FRAMED_MTU 12
#define RD_TP_FRAMED_COMPRESSION 13
#define RD_TP_LOGIN_IP_HOST 14
#define RD_TP_LOGIN_SERVICE 15
#define RD_TP_LOGIN_TCP_PORT 16
#define RD_TP_UNASSIGNED 17
#define RD_TP_REPLY_MESSAGE 18
#define RD_TP_CALLBACK_NUMBER 19
#define RD_TP_CALLBACK_ID 20
#define RD_TP_UNASSIGNED2 21
#define RD_TP_FRAMED_ROUTE 22
#define RD_TP_FRAMED_IPX_NETWORK 23
#define RD_TP_STATE 24
#define RD_TP_CLASS 25
#define RD_TP_VENDOR_SPECIFIC 26
#define RD_TP_SESSION_TIMEOUT 27
#define RD_TP_IDLE_TIMEOUT 28
#define RD_TP_TERMINATING_ACTION 29
#define RD_TP_CALLED_STATION_ID 30
#define RD_TP_CALLING_STATION_ID 31
#define RD_TP_NAS_IDENTIFIER 32
#define RD_TP_PROXY_STATE 33
#define RD_TP_LOGIN_LAT_SERVICE 34
#define RD_TP_LOGIN_LAT_NODE 35
#define RD_TP_LOGIN_LAT_GROUP 36
#define RD_TP_FRAMED_APPLETALK_LINK 37
#define RD_TP_FRAMED_APPLETALK_NETWORK 38
#define RD_TP_FRAMED_APPLETALK_ZONE 39
#define RD_TP_ACCT_STATUS_TYPE 40
#define RD_TP_ACCT_DELAY_TIME 41
#define RD_TP_ACCT_INPUT_OCTETS 42
#define RD_TP_ACCT_OUTPUT_OCTETS 43
#define RD_TP_ACCT_SESSION_ID 44
#define RD_TP_ACCT_AUTHENTIC 45
#define RD_TP_ACCT_SESSION_TIME 46
#define RD_TP_ACCT_INPUT_PACKETS 47
#define RD_TP_ACCT_OUTPUT_PACKETS 48
#define RD_TP_ACCT_TERMINATE_CAUSE 49
#define RD_TP_ACCT_MULTI_SESSION_ID 50
#define RD_TP_ACCT_LINK_COUNT 51
#define RD_TP_CHAP_CHALLENGE 60
#define RD_TP_NAS_PORT_TYPE 61
#define RD_TP_PORT_LIMIT 62
#define RD_TP_LOGIN_LAT_PORT 63


#define AUTHENTICATOR_LENGTH 16
#define RD_HDR_LENGTH 4


#define RADIUS_STRING 1
#define RADIUS_BINSTRING 2
#define RADIUS_INTEGER4 3
#define RADIUS_IP_ADDRESS 4
#define RADIUS_SERVICE_TYPE 5
#define RADIUS_FRAMED_PROTOCOL 6
#define RADIUS_FRAMED_ROUTING 7
#define RADIUS_FRAMED_COMPRESSION 8
#define RADIUS_LOGIN_SERVICE 9
#define RADIUS_UNKNOWN 10
#define RADIUS_IPX_ADDRESS 11
#define RADIUS_TERMINATING_ACTION 12
#define RADIUS_ACCOUNTING_STATUS_TYPE 13
#define RADIUS_ACCT_AUTHENTIC 14
#define RADIUS_ACCT_TERMINATE_CAUSE 15
#define RADIUS_NAS_PORT_TYPE 16

static value_string radius_vals[] = {
 {RADIUS_ACCESS_REQUEST, "Access Request"},
 {RADIUS_ACCESS_ACCEPT, "Access Accept"},
 {RADIUS_ACCESS_REJECT, "Access Reject"},
 {RADIUS_ACCOUNTING_REQUEST, "Accounting Request"},
 {RADIUS_ACCOUNTING_RESPONSE, "Accounting Response"},
 {RADIUS_ACCESS_CHALLENGE, "Accounting challenge"},
 {RADIUS_STATUS_SERVER, "StatusServer"},
 {RADIUS_STATUS_CLIENT, "StatusClient"},
 {RADIUS_RESERVED, "Reserved"},
{0, NULL}};

static value_string radius_service_type_vals[]=
{{1, "Login"},
{2, "Framed"},
{3, "Callback Login"},
{4, "Callback Framed"},
{5, "Outbound"},
{6, "Administrative"},
{7, "NAS Prompt"},
{8, "Authenticate Only"},
{9, "Callback NAS Prompt"},
{10, "Call Check"},
{0,NULL}};

static value_string radius_framed_protocol_vals[]=
{{1, "PPP"},
{2, "SLIP"},
{3, "Appletalk Remote Access Protocol (ARAP)"},
{4, "Gandalf proprietary Singlelink/Multilink Protocol"},
{5, "Xylogics proprietary IPX/SLIP"},
{6, "X.75 Synchronous"},
{0,NULL}};

static value_string radius_framed_routing_vals[]=
{{1, "Send Routing Packets"},
{2, "Listen for routing packets"},
{3, "Send and Listen"},
{0,"None"},
{0,NULL}};

static value_string radius_framed_compression_vals[]=
{{1, "VJ TCP/IP Header Compression"},
{2, "IPX Header Compression"},
{3, "Stac-LZS compression"},
{0, "None"},
{0,NULL}};

static value_string radius_login_service_vals[]=
{{1, "Rlogin"},
{2, "TCP Clear"},
{3, "Portmaster"},
{4, "LAT"},
{5, "X.25-PAD"},
{6, "X.25T3POS"},
{8, "TCP Clear Quit"},
{0, "Telnet"},
{0,NULL}};

static value_string radius_terminating_action_vals[]=
{{1, "RADIUS-Request"},
{0, "Default"},
{0,NULL}};

static value_string radius_accounting_status_type_vals[]=
{{1, "Start"},
{2, "Stop"},
{7,"Accounting-On"},
{8,"Accounting-Off"},
{0,NULL}};

static value_string radius_accounting_authentication_vals[]=
{{1, "Radius"},
{2, "Local"},
{7,"Remote"},
{0,NULL}};

static value_string radius_acct_terminate_cause_vals[]=
{{1, "User Request"},
{2, "Lost Carrier"},
{3,"Lost Service"},
{4, "Idle Timeout"},
{5,"Session Timeout"},
{6, "Admin Reset"},
{7, "Admin Reboot"},
{8, "Port Error"},
{9, "NAS Error"},
{10, "NAS Request"},
{11,"NAS Reboot"},
{12, "Port Unneeded"},
{13, "Port Preempted"},
{14,"Port Suspended"},
{15,"Service Unavailable"},
{16,"Callback"},
{17, "User Error"},
{18,"Host Request"},
{0,NULL}};

static value_string radius_nas_port_type_vals[]=
{{0, "Async"},
{1, "Sync"},
{2,"ISDN Sync"},
{3, "ISDN Async V.120"},
{4,"ISDN Async V.110"},
{5, "Virtual"},
{6, "PIAFS"},
{7, "HDLC Clear Channel"},
{8, "X.25"},
{9,"X.75"},
{10, "G.3 Fax"},
{11,"SDSL"},
{12, "ADSL-CAP"},
{13, "ADSL-DMT"},
{14,"IDSL - ISDN"},
{0,NULL}};

static value_value_pair radius_printinfo[] = {
{ RD_TP_USER_NAME, RADIUS_STRING },
{ RD_TP_USER_PASSWORD,RADIUS_BINSTRING },
{ RD_TP_CHAP_PASSWORD, RADIUS_BINSTRING },
{ RD_TP_NAS_IP_ADDRESS, RADIUS_IP_ADDRESS },
{ RD_TP_NAS_PORT, RADIUS_INTEGER4},
{ RD_TP_SERVICE_TYPE, RADIUS_SERVICE_TYPE},
{ RD_TP_FRAMED_PROTOCOL, RADIUS_FRAMED_PROTOCOL},
{ RD_TP_FRAMED_IP_ADDRESS, RADIUS_IP_ADDRESS},
{ RD_TP_FRAMED_IP_NETMASK, RADIUS_IP_ADDRESS},
{ RD_TP_FRAMED_ROUTING, RADIUS_FRAMED_ROUTING},
{ RD_TP_FILTER_ID, RADIUS_STRING},
{ RD_TP_FRAMED_MTU, RADIUS_INTEGER4},
{ RD_TP_FRAMED_COMPRESSION, RADIUS_FRAMED_COMPRESSION},
{ RD_TP_LOGIN_IP_HOST, RADIUS_IP_ADDRESS},
{ RD_TP_LOGIN_SERVICE, RADIUS_LOGIN_SERVICE},
{ RD_TP_LOGIN_TCP_PORT, RADIUS_INTEGER4},
{ RD_TP_UNASSIGNED, RADIUS_UNKNOWN},
{ RD_TP_REPLY_MESSAGE, RADIUS_STRING},
{ RD_TP_CALLBACK_NUMBER, RADIUS_BINSTRING},
{ RD_TP_CALLBACK_ID, RADIUS_BINSTRING},
{ RD_TP_UNASSIGNED2, RADIUS_UNKNOWN},
{ RD_TP_FRAMED_ROUTE, RADIUS_STRING},
{ RD_TP_FRAMED_IPX_NETWORK, RADIUS_IPX_ADDRESS},
{ RD_TP_STATE, RADIUS_BINSTRING},
{ RD_TP_CLASS, RADIUS_BINSTRING},
{ RD_TP_VENDOR_SPECIFIC, RADIUS_BINSTRING},
{ RD_TP_SESSION_TIMEOUT, RADIUS_INTEGER4},
{ RD_TP_IDLE_TIMEOUT, RADIUS_INTEGER4},
{ RD_TP_TERMINATING_ACTION, RADIUS_TERMINATING_ACTION},
{ RD_TP_CALLED_STATION_ID, RADIUS_BINSTRING},
{ RD_TP_CALLING_STATION_ID, RADIUS_BINSTRING},
{ RD_TP_NAS_IDENTIFIER, RADIUS_BINSTRING},
{ RD_TP_PROXY_STATE, RADIUS_BINSTRING},
{ RD_TP_LOGIN_LAT_SERVICE, RADIUS_BINSTRING},
{ RD_TP_LOGIN_LAT_NODE, RADIUS_BINSTRING},
{ RD_TP_LOGIN_LAT_GROUP, RADIUS_BINSTRING},
{ RD_TP_FRAMED_APPLETALK_LINK, RADIUS_INTEGER4},
{ RD_TP_FRAMED_APPLETALK_NETWORK, RADIUS_INTEGER4},
{ RD_TP_FRAMED_APPLETALK_ZONE, RADIUS_BINSTRING},
{ RD_TP_ACCT_STATUS_TYPE, RADIUS_ACCOUNTING_STATUS_TYPE},
{ RD_TP_ACCT_DELAY_TIME, RADIUS_INTEGER4},
{ RD_TP_ACCT_INPUT_OCTETS, RADIUS_INTEGER4},
{ RD_TP_ACCT_OUTPUT_OCTETS, RADIUS_INTEGER4},
{ RD_TP_ACCT_SESSION_ID, RADIUS_STRING},
{ RD_TP_ACCT_AUTHENTIC, RADIUS_ACCT_AUTHENTIC},
{ RD_TP_ACCT_SESSION_TIME, RADIUS_INTEGER4},
{ RD_TP_ACCT_INPUT_PACKETS, RADIUS_INTEGER4},
{ RD_TP_ACCT_OUTPUT_PACKETS, RADIUS_INTEGER4},
{ RD_TP_ACCT_TERMINATE_CAUSE, RADIUS_ACCT_TERMINATE_CAUSE},
{ RD_TP_ACCT_MULTI_SESSION_ID, RADIUS_STRING},
{ RD_TP_ACCT_LINK_COUNT, RADIUS_INTEGER4},
{ RD_TP_CHAP_CHALLENGE, RADIUS_BINSTRING},
{ RD_TP_NAS_PORT_TYPE, RADIUS_NAS_PORT_TYPE},
{ RD_TP_PORT_LIMIT, RADIUS_INTEGER4},
{ RD_TP_LOGIN_LAT_PORT, RADIUS_BINSTRING},
{0,0},
};

static value_string radius_attrib_type_vals[] = {
{ RD_TP_USER_NAME, "User Name"},
{ RD_TP_USER_PASSWORD, "User Password"},
{ RD_TP_CHAP_PASSWORD, "Chap Password"},
{ RD_TP_NAS_IP_ADDRESS, "NAS IP Address"},
{ RD_TP_NAS_PORT, "NAS Port"},
{ RD_TP_SERVICE_TYPE, "Service Type"},
{ RD_TP_FRAMED_PROTOCOL, "Framed Protocol"},
{ RD_TP_FRAMED_IP_ADDRESS, "Framed IP Address"},
{ RD_TP_FRAMED_IP_NETMASK, "Framed IP Netmask"},
{ RD_TP_FRAMED_ROUTING, "Framed Routing"},
{ RD_TP_FILTER_ID, "Filter Id"},
{ RD_TP_FRAMED_MTU, "Framed MTU"},
{ RD_TP_FRAMED_COMPRESSION, "Framed Compression"},
{ RD_TP_LOGIN_IP_HOST, "Login IP Host"},
{ RD_TP_LOGIN_SERVICE, "Login Service"},
{ RD_TP_LOGIN_TCP_PORT, "Login TCP Port"},
{ RD_TP_UNASSIGNED, "Unassigned"},
{ RD_TP_REPLY_MESSAGE, "Reply Message"},
{ RD_TP_CALLBACK_NUMBER, "Callback Number"},
{ RD_TP_CALLBACK_ID, "Callback Id"},
{ RD_TP_UNASSIGNED2, "Unassigned"},
{ RD_TP_FRAMED_ROUTE, "Framed Route"},
{ RD_TP_FRAMED_IPX_NETWORK, "Framed IPX network"},
{ RD_TP_STATE, "State"},
{ RD_TP_CLASS, "Class"},
{ RD_TP_VENDOR_SPECIFIC, "Vendor Specific" },
{ RD_TP_SESSION_TIMEOUT, "Session Timeout"},
{ RD_TP_IDLE_TIMEOUT, "Idle Timeout"},
{ RD_TP_TERMINATING_ACTION, "Terminating Action"},
{ RD_TP_CALLED_STATION_ID, "Called Station Id"},
{ RD_TP_CALLING_STATION_ID, "Calling Station Id"},
{ RD_TP_NAS_IDENTIFIER, "NAS identifier"},
{ RD_TP_PROXY_STATE, "Proxy State"},
{ RD_TP_LOGIN_LAT_SERVICE, "Login LAT Service"},
{ RD_TP_LOGIN_LAT_NODE, "Login LAT Node"},
{ RD_TP_LOGIN_LAT_GROUP, "Login LAT Group"},
{ RD_TP_FRAMED_APPLETALK_LINK, "Framed Appletalk Link"},
{ RD_TP_FRAMED_APPLETALK_NETWORK, "Framed Appletalk Network"},
{ RD_TP_FRAMED_APPLETALK_ZONE, "Framed Appletalk Zone"},
{ RD_TP_ACCT_STATUS_TYPE, "Acct Status Type"},
{ RD_TP_ACCT_DELAY_TIME, "Acct Delay Time"},
{ RD_TP_ACCT_INPUT_OCTETS, "Acct Input Octets"},
{ RD_TP_ACCT_OUTPUT_OCTETS, "Acct Output Octets"},
{ RD_TP_ACCT_SESSION_ID, "Acct Session Id"},
{ RD_TP_ACCT_AUTHENTIC, "Acct Authentic"},
{ RD_TP_ACCT_SESSION_TIME, "Acct Session Time"},
{ RD_TP_ACCT_INPUT_PACKETS, "Acct Input Packets"},
{ RD_TP_ACCT_OUTPUT_PACKETS, "Acct Output Packets"},
{ RD_TP_ACCT_TERMINATE_CAUSE, "Acct Terminate Cause"},
{ RD_TP_ACCT_MULTI_SESSION_ID, "Acct Multi Session Id"},
{ RD_TP_ACCT_LINK_COUNT, "Acct Link Count"},
{ RD_TP_CHAP_CHALLENGE, "Chap Challenge"},
{ RD_TP_NAS_PORT_TYPE, "NAS Port Type"},
{ RD_TP_PORT_LIMIT, "Port Limit"},
{ RD_TP_LOGIN_LAT_PORT, "Login LAT Port"},
{0,NULL},
};

guint32 match_numval(guint32 val, const value_value_pair *vs)
{
  guint32 i = 0;

  while (vs[i].val1) {
    if (vs[i].val1 == val)
      return(vs[i].val2);
    i++;
  }

  return(0);
}

static gchar textbuffer[2000];

gchar *rdconvertbufftostr(guint8 length,const guint8 *pd)
{
/*converts the raw buffer into printable text */
guint32 i;
guint32 totlen=0;

        textbuffer[0]='"';
        textbuffer[1]=0;
        totlen=1;
        for (i=0; i < (guint32)length; i++)
        {
                if( isalnum((int)pd[i])||ispunct((int)pd[i])
                                ||((int)pd[i]==' '))            {
                        textbuffer[totlen]=(gchar)pd[i];
                        totlen++;
                }
                else
                {
                        sprintf(&(textbuffer[totlen]), "\\%03u", pd[i]);
                        totlen=totlen+strlen(&(textbuffer[totlen]));
                }
        }
        textbuffer[totlen]='"';
        textbuffer[totlen+1]=0;
        return textbuffer;
}

gchar *rd_value_to_str(e_avphdr *avph,const u_char *pd, int offset)
{
int print_type;
gchar *result;
guint32 intval;
value_string *valstrarr;
/* prints the values of the attribute value pairs into a text buffer */
  print_type=match_numval(avph->avp_type,radius_printinfo);
  intval=pntohl(&(pd[offset+2]));
  switch(print_type)
  {
        case( RADIUS_STRING ):
        case( RADIUS_BINSTRING ):
		result=rdconvertbufftostr(avph->avp_length-2,&(pd[offset+2]));
                break;
        case( RADIUS_INTEGER4 ):
                sprintf(textbuffer,"%u", intval);
                result=textbuffer;
                break;
        case( RADIUS_IP_ADDRESS ):
                sprintf(textbuffer,"%u.%u.%u.%u",(guint8)pd[offset+2],
                        (guint8)pd[offset+3],(guint8)pd[offset+4],
                        (guint8)pd[offset+5]);
                result=textbuffer;
                break;
        case( RADIUS_SERVICE_TYPE ):
                valstrarr=radius_service_type_vals;
                result=match_strval(intval,valstrarr);
                break;
        case( RADIUS_FRAMED_PROTOCOL ):
                valstrarr= radius_framed_protocol_vals;
                result=match_strval(intval,valstrarr);
                break;
        case( RADIUS_FRAMED_ROUTING ):
                valstrarr=radius_framed_routing_vals;
                result=match_strval(intval,valstrarr);
                break;
        case( RADIUS_FRAMED_COMPRESSION ):
                valstrarr=radius_framed_compression_vals;
                result=match_strval(intval,valstrarr);
                break;
        case( RADIUS_LOGIN_SERVICE ):
                valstrarr=radius_login_service_vals;
                result=match_strval(intval,valstrarr);
                break;
        case( RADIUS_IPX_ADDRESS ):
                sprintf(textbuffer,"%u:%u:%u:%u",(guint8)pd[offset+2],
                        (guint8)pd[offset+3],(guint8)pd[offset+4],
                        (guint8)pd[offset+5]);
                result=textbuffer;
        case( RADIUS_TERMINATING_ACTION ):
                valstrarr=radius_terminating_action_vals;
                result=match_strval(intval,valstrarr);
                break;
        case( RADIUS_ACCOUNTING_STATUS_TYPE ):
                valstrarr=radius_accounting_status_type_vals;
                result=match_strval(intval,valstrarr);
                break;
        case( RADIUS_ACCT_AUTHENTIC ):
                valstrarr=radius_accounting_authentication_vals;
                result=match_strval(intval,valstrarr);
                break;
        case( RADIUS_ACCT_TERMINATE_CAUSE ):
                valstrarr=radius_acct_terminate_cause_vals;
                result=match_strval(intval,valstrarr);
                break;
        case( RADIUS_NAS_PORT_TYPE ):
                valstrarr=radius_nas_port_type_vals;
                result=match_strval(intval,valstrarr);
                break;
        case( RADIUS_UNKNOWN ):
        default:
                result="Unknown Value Type";
                break;
  }
  if (result == NULL) result="Unknown Value";
  return result;
}


void dissect_attribute_value_pairs(const u_char *pd, int offset, frame_data
*fd, proto_tree *tree, int avplength)
{
/* adds the attribute value pairs to the tree */
  e_avphdr avph;
  gchar *avptpstrval;
  gchar *valstr;
  if (avplength==0)
  {
        proto_tree_add_text(tree,offset,0,"No Attribute Value Pairs Found");
        return;
  }

  while (avplength > 0 )
  {

     memcpy(&avph,&pd[offset],sizeof(e_avphdr));
     avplength=avplength-avph.avp_length;
     avptpstrval=match_strval(avph.avp_type, radius_attrib_type_vals);
     if (avptpstrval == NULL) avptpstrval="Unknown Type";
     valstr=rd_value_to_str(&avph, pd, offset);
     if (!BYTES_ARE_IN_FRAME(offset, avph.avp_length)) {
	break;
     }
     proto_tree_add_text(tree,offset,avph.avp_length,
        "t:%s(%d) l:%d, value:%s",
        avptpstrval,avph.avp_type,avph.avp_length,valstr);
     offset=offset+avph.avp_length;
     if (avph.avp_length == 0) {
	break;
     }
  }
}

void dissect_radius(const u_char *pd, int offset, frame_data *fd, 
proto_tree
*tree)
{
  proto_tree *radius_tree,*avptree;
  proto_item *ti,*avptf;
  int rhlength;
  int rhcode;
  int rhident;
  int avplength,hdrlength, offsetavp;
  e_radiushdr rh;

  gchar *codestrval;

  memcpy(&rh,&pd[offset],sizeof(e_radiushdr));


  rhcode= (int)rh.rh_code;
  rhident= (int)rh.rh_ident;
  rhlength= (int)ntohs(rh.rh_pktlength);
  codestrval=  match_strval(rhcode,radius_vals);
  if (codestrval==NULL)
  {
	codestrval="Unknown Packet";
  }
  if (check_col(fd, COL_PROTOCOL))
        col_add_str(fd, COL_PROTOCOL, "RADIUS");
  if (check_col(fd, COL_INFO))
  {
	sprintf(textbuffer,"%s(%d) (id=%d, l=%d)",
		codestrval, rhcode, rhident, rhlength);
        col_add_fstr(fd,COL_INFO,textbuffer);
  }

  if (tree)
  {
	
        ti = proto_tree_add_item(tree,proto_radius, offset, rhlength,
			NULL);

        radius_tree = proto_item_add_subtree(ti, ett_radius);

	proto_tree_add_item_format(radius_tree,hf_radius_code, offset,      1,
                rh.rh_code, "Packet code:0x%01x (%s)",rhcode, codestrval);
        proto_tree_add_item_format(radius_tree,hf_radius_id, offset+1, 1,
                rh.rh_ident, "Packet identifier: 0x%01x (%d)",
			rhident,rhident);         

	proto_tree_add_item_format(radius_tree, hf_radius_length,
			offset+2, 2,
                 (guint16)rhlength, 
		"Packet length: 0x%02x(%d)",rhlength,rhlength); 
         proto_tree_add_text(radius_tree, offset+4,
			AUTHENTICATOR_LENGTH,
                         "Authenticator");
   
	hdrlength=RD_HDR_LENGTH+AUTHENTICATOR_LENGTH;
        avplength= rhlength -hdrlength;

        offsetavp=offset+hdrlength;


        /* list the attribute value pairs */

        avptf = proto_tree_add_text(radius_tree
                        ,offset+hdrlength,avplength,
                        "Attribute value pairs");
        avptree = proto_item_add_subtree(avptf, ett_radius_avp);

        if (avptree !=NULL)
        {
                dissect_attribute_value_pairs( pd,
                                offsetavp,fd,avptree,avplength);
        }
  }
}
/* registration with the filtering engine */
void
proto_register_radius(void)
{
	static hf_register_info hf[] = {
		{ &hf_radius_code,
		{ "Code","radius.code", FT_UINT8, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_radius_id,
		{ "Identifier",	"radius.id", FT_UINT8, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_radius_length,
		{ "Length","radius.length", FT_UINT16, BASE_DEC, NULL, 0x0,
			"" }}
	};
	static gint *ett[] = {
		&ett_radius,
		&ett_radius_avp,
	};

	proto_radius = proto_register_protocol ("Radius Protocol", "radius");
	proto_register_field_array(proto_radius, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}
