/* packet-radius.c
 * Routines for RADIUS packet disassembly
 * Copyright 1999 Johan Feyaerts
 *
 * RFC 2865, RFC 2866, RFC 2867, RFC 2868, RFC 2869
 *
 * $Id: packet-radius.c,v 1.52 2002/03/27 02:37:14 guy Exp $
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
#include <time.h>
#include <epan/packet.h>
#include <epan/resolv.h>

static int proto_radius = -1;
static int hf_radius_length = -1;
static int hf_radius_code = -1;
static int hf_radius_id =-1;

static gint ett_radius = -1;
static gint ett_radius_avp = -1;
static gint ett_radius_eap = -1;

static dissector_handle_t eap_fragment_handle;

#define UDP_PORT_RADIUS		1645
#define UDP_PORT_RADIUS_NEW	1812
#define UDP_PORT_RADACCT	1646
#define UDP_PORT_RADACCT_NEW	1813

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
#define RD_TP_ACCT_INPUT_GIGAWORDS 52
#define RD_TP_ACCT_OUTPUT_GIGAWORDS 53
/* 54 Unused */
#define RD_TP_EVENT_TIMESTAMP 55
/* 56-59 Unused */ 
#define RD_TP_CHAP_CHALLENGE 60
#define RD_TP_NAS_PORT_TYPE 61
#define RD_TP_PORT_LIMIT 62
#define RD_TP_LOGIN_LAT_PORT 63
#define RD_TP_TUNNEL_TYPE 64
#define RD_TP_TUNNEL_MEDIUM_TYPE 65
#define RD_TP_TUNNEL_CLIENT_ENDPOINT 66
#define RD_TP_TUNNEL_SERVER_ENDPOINT 67
#define RD_TP_TUNNEL_CONNECTION 68
#define RD_TP_TUNNEL_PASSWORD 69
#define RD_TP_ARAP_PASSWORD 70
#define RD_TP_ARAP_FEATURES 71
#define RD_TP_ARAP_ZONE_ACCESS 72
#define RD_TP_ARAP_SECURITY 73
#define RD_TP_ARAP_SECURITY_DATA 74
#define RD_TP_PASSWORD_RETRY 75
#define RD_TP_PROMPT 76
#define RD_TP_CONNECT_INFO 77
#define RD_TP_CONFIGURATION_TOKEN 78
#define RD_TP_EAP_MESSAGE 79
#define RD_TP_MESSAGE_AUTHENTICATOR 80
#define RD_TP_TUNNEL_PRIVATE_GROUP_ID 81
#define RD_TP_TUNNEL_ASSIGNMENT_ID 82
#define RD_TP_TUNNEL_TUNNEL_PREFERENCE 83
#define RD_TP_TUNNEL_PACKETS_LOST 86
#define RD_TP_NAS_PORT_ID 87
#define RD_TP_TUNNEL_CLIENT_AUTH_ID 90
#define RD_TP_TUNNEL_SERVER_AUTH_ID 91
#define RD_TP_ASCEND_MODEM_PORTNO 120
#define RD_TP_ASCEND_MODEM_SLOTNO 121
#define RD_TP_ASCEND_MULTILINK_ID 187
#define RD_TP_ASCEND_NUM_IN_MULTILINK 188
#define RD_TP_ASCEND_FIRST_DEST 189
#define RD_TP_ASCEND_PRE_INPUT_OCTETS 190
#define RD_TP_ASCEND_PRE_OUTPUT_OCTETS 191
#define RD_TP_ASCEND_PRE_INPUT_PACKETS 192
#define RD_TP_ASCEND_PRE_OUTPUT_PACKETS 193
#define RD_TP_ASCEND_MAXIMUM_TIME 194
#define RD_TP_ASCEND_DISCONNECT_CAUSE 195
#define RD_TP_ASCEND_CONNECT_PROGRESS 196
#define RD_TP_ASCEND_DATA_RATE 197
#define RD_TP_ASCEND_PRESESSION_TIME 198
#define RD_TP_ASCEND_ASSIGN_IP_POOL 218
#define RD_TP_ASCEND_XMIT_RATE 255





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
#define RADIUS_TUNNEL_TYPE 17
#define RADIUS_TUNNEL_MEDIUM_TYPE 18
#define RADIUS_STRING_TAGGED 19
#define RADIUS_VENDOR_SPECIFIC 20
#define RADIUS_TIMESTAMP 21
#define RADIUS_INTEGER4_TAGGED 22

static value_string radius_vals[] = {
 {RADIUS_ACCESS_REQUEST, "Access Request"},
 {RADIUS_ACCESS_ACCEPT, "Access Accept"},
 {RADIUS_ACCESS_REJECT, "Access Reject"},
 {RADIUS_ACCOUNTING_REQUEST, "Accounting Request"},
 {RADIUS_ACCOUNTING_RESPONSE, "Accounting Response"},
 {RADIUS_ACCESS_CHALLENGE, "Access challenge"},
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

/*
 * These are SMI Network Management Private Enterprise Codes for
 * organizations; see
 *
 *	http://www.isi.edu/in-notes/iana/assignments/enterprise-numbers
 *
 * for a list.
 */
#define VENDOR_ACC 5
#define VENDOR_CISCO 9
#define VENDOR_SHIVA 166
#define VENDOR_LIVINGSTON 307
#define VENDOR_MICROSOFT 311
#define VENDOR_3COM 429
#define VENDOR_ASCEND 529
#define VENDOR_BAY 1584
#define VENDOR_JUNIPER 2636
#define VENDOR_COSINE 3085
#define VENDOR_UNISPHERE 4874
#define VENDOR_ISSANNI 5948

static value_string radius_vendor_specific_vendors[]=
{{VENDOR_ACC,"ACC"},
{VENDOR_CISCO,"Cisco"},
{VENDOR_SHIVA,"Shiva"},
{VENDOR_MICROSOFT,"Microsoft"},
{VENDOR_LIVINGSTON,"Livingston"},
{VENDOR_3COM,"3Com"},
{VENDOR_ASCEND,"Ascend"},
{VENDOR_BAY,"Bay Networks"},
{VENDOR_JUNIPER,"Juniper Networks"},
{VENDOR_COSINE,"CoSine Communications"},
{VENDOR_UNISPHERE,"Unisphere Networks"},
{VENDOR_ISSANNI,"Issanni Communications"},
{0,NULL}};

#define VENDOR_CISCO_AVP_CISCO                 1
#define VENDOR_CISCO_NAS_PORT                  2
#define VENDOR_CISCO_FAX_ACCOUNT_ID_ORIGIN     3
#define VENDOR_CISCO_FAX_MSG_ID                4
#define VENDOR_CISCO_FAX_PAGES                 5
#define VENDOR_CISCO_FAX_COVERPAGE_FLAG        6
#define VENDOR_CISCO_FAX_MODEM_TIME            7
#define VENDOR_CISCO_FAX_CONNECT_SPEED         8
#define VENDOR_CISCO_FAX_RECIPENT_COUNT        9
#define VENDOR_CISCO_FAX_PROCESS_ABORT_FLAG    10
#define VENDOR_CISCO_FAX_DSN_ADDRESS           11
#define VENDOR_CISCO_FAX_DSN_FLAG              12
#define VENDOR_CISCO_FAX_MDN_ADDRESS           13
#define VENDOR_CISCO_FAX_MDN_FLAG              14
#define VENDOR_CISCO_FAX_AUTH_STATUS           15
#define VENDOR_CISCO_EMAIL_SERVER_ADDRESS      16
#define VENDOR_CISCO_EMAIL_SERVER_ACK_FLAG     17
#define VENDOR_CISCO_GATEWAY_ID                18
#define VENDOR_CISCO_CALL_TYPE                 19
#define VENDOR_CISCO_PORT_USED                 20
#define VENDOR_CISCO_ABORT_CAUSE               21
#define VENDOR_CISCO_UNKNOWN_21                21 /* UNKNOWN ! */
#define VENDOR_CISCO_UNKNOWN_22                22 /* UNKNOWN ! */
#define VENDOR_CISCO_H323_REMOTE_ADDRESS	23	
#define VENDOR_CISCO_H323_CONF_ID		24	
#define VENDOR_CISCO_H323_SETUP_TIME		25	
#define VENDOR_CISCO_H323_CALL_ORIGIN		26	
#define VENDOR_CISCO_H323_CALL_TYPE		27	
#define VENDOR_CISCO_H323_CONNECT_TIME		28	
#define VENDOR_CISCO_H323_DISCONNECT_TIME	29	
#define VENDOR_CISCO_H323_DISCONNECT_CAUSE	30	
#define VENDOR_CISCO_H323_VOICE_QUALITY	31	
#define VENDOR_CISCO_UNKNOWN_32                32 /* UNKNOWN ! */
#define VENDOR_CISCO_H323_GW_ID		33	
#define VENDOR_CISCO_UNKNOWN_34                34 /* UNKNOWN ! */
#define VENDOR_CISCO_H323_INCOMING_CONF_ID	35	
#define VENDOR_CISCO_H323_CREDIT_AMOUNT	101	
#define VENDOR_CISCO_H323_CREDIT_TIME		102	
#define VENDOR_CISCO_H323_RETURN_CODE		103	
#define VENDOR_CISCO_H323_PROMPT_ID		104	
#define VENDOR_CISCO_H323_TIME_AND_DAY		105	
#define VENDOR_CISCO_H323_REDIRECT_NUMBER	106	
#define VENDOR_CISCO_H323_PREFERRED_LANG	107	
#define VENDOR_CISCO_H323_REDIRECT_IP_ADDRESS	108	
#define VENDOR_CISCO_H323_BILLING_MODEL	109	
#define VENDOR_CISCO_H323_CURRENCY_TYPE	110	
#define VENDOR_CISCO_MULTILINK_ID              187     
#define VENDOR_CISCO_NUM_IN_MULTILINK          188     
#define VENDOR_CISCO_PRE_INPUT_OCTETS          190     
#define VENDOR_CISCO_PRE_OUTPUT_OCTETS         191     
#define VENDOR_CISCO_PRE_INPUT_PACKETS         192     
#define VENDOR_CISCO_PRE_OUTPUT_PACKETS        193     
#define VENDOR_CISCO_MAXIMUM_TIME              194     
#define VENDOR_CISCO_DISCONNECT_CAUSE          195     
#define VENDOR_CISCO_DATA_RATE                 197     
#define VENDOR_CISCO_PRESESSION_TIME           198     
#define VENDOR_CISCO_PW_LIFETIME               208     
#define VENDOR_CISCO_IP_DIRECT                 209     
#define VENDOR_CISCO_PPP_VJ_SLOT_COMP          210     
#define VENDOR_CISCO_PPP_ASYNC_MAP             212     
#define VENDOR_CISCO_IP_POOL_DEFINITION        217     
#define VENDOR_CISCO_ASING_IP_POOL             218     
#define VENDOR_CISCO_ROUTE_IP                  228     
#define VENDOR_CISCO_LINK_COMPRESSION          233     
#define VENDOR_CISCO_TARGET_UTIL               234     
#define VENDOR_CISCO_MAXIMUM_CHANNELS          235     
#define VENDOR_CISCO_DATA_FILTER               242     
#define VENDOR_CISCO_CALL_FILTER               243     
#define VENDOR_CISCO_IDLE_LIMIT                244     
#define VENDOR_CISCO_XMIT_RATE                 255     

static value_string radius_vendor_cisco_types[]=
{{VENDOR_CISCO_AVP_CISCO              ,"Cisco AV Pair" },
{ VENDOR_CISCO_NAS_PORT               ,"Cisco NAS Port" },
{ VENDOR_CISCO_FAX_ACCOUNT_ID_ORIGIN  ,"Fax Account Id Origin" },    
{ VENDOR_CISCO_FAX_MSG_ID             ,"Fax Msg Id" },    
{ VENDOR_CISCO_FAX_PAGES              ,"Fax Pages" },    
{ VENDOR_CISCO_FAX_COVERPAGE_FLAG     ,"Fax Cover Page Flag" },    
{ VENDOR_CISCO_FAX_MODEM_TIME         ,"Fax Modem Time" },    
{ VENDOR_CISCO_FAX_CONNECT_SPEED      ,"Fax Connect Speed" },    
{ VENDOR_CISCO_FAX_RECIPENT_COUNT     ,"Fax Recipent Count" },    
{ VENDOR_CISCO_FAX_PROCESS_ABORT_FLAG ,"Fax Process Abort Flag" },    
{ VENDOR_CISCO_FAX_DSN_ADDRESS        ,"Fax DSN Address" },    
{ VENDOR_CISCO_FAX_DSN_FLAG           ,"Fax DSN Flag" },    
{ VENDOR_CISCO_FAX_MDN_ADDRESS        ,"Fax MDN Address" },    
{ VENDOR_CISCO_FAX_MDN_FLAG           ,"Fax MDN Flag" },    
{ VENDOR_CISCO_FAX_AUTH_STATUS        ,"Fax Auth Status" },    
{ VENDOR_CISCO_EMAIL_SERVER_ADDRESS   ,"Email Server Address" },    
{ VENDOR_CISCO_EMAIL_SERVER_ACK_FLAG  ,"Email Server Ack Flag" },    
{ VENDOR_CISCO_GATEWAY_ID             ,"Gateway Id" },    
{ VENDOR_CISCO_CALL_TYPE              ,"Call Type" },    
{ VENDOR_CISCO_PORT_USED              ,"Port Used" },    
{ VENDOR_CISCO_ABORT_CAUSE            ,"Abort Cause" },    
{ VENDOR_CISCO_UNKNOWN_21             ,"Vendor Cisco **UNKNOWN** 21" },
{ VENDOR_CISCO_UNKNOWN_22             ,"Vendor Cisco **UNKNOWN** 22" },
{ VENDOR_CISCO_H323_REMOTE_ADDRESS    ,"H323 Remote Address" },
{ VENDOR_CISCO_H323_CONF_ID           ,"H323 Conf Id" },
{ VENDOR_CISCO_H323_SETUP_TIME        ,"H323 Setup Time" },
{ VENDOR_CISCO_H323_CALL_ORIGIN       ,"H323 Call Origin" },
{ VENDOR_CISCO_H323_CALL_TYPE         ,"H323 Call Type" },
{ VENDOR_CISCO_H323_CONNECT_TIME      ,"H323 Connect Time" },
{ VENDOR_CISCO_H323_DISCONNECT_TIME   ,"H323 Disconnect Time" },
{ VENDOR_CISCO_H323_DISCONNECT_CAUSE  ,"H323 Disconnect Cause" },
{ VENDOR_CISCO_H323_VOICE_QUALITY     ,"H323 Voice Quality" },
{ VENDOR_CISCO_UNKNOWN_32             ,"Vendor Cisco **UNKNOWN** 32" },
{ VENDOR_CISCO_H323_GW_ID             ,"H323 GW Id" },
{ VENDOR_CISCO_UNKNOWN_34             ,"Vendor Cisco **UNKNOWN** 34" },
{ VENDOR_CISCO_H323_INCOMING_CONF_ID  ,"H323 Incoming Conf Id" },
{ VENDOR_CISCO_H323_CREDIT_AMOUNT     ,"H323 Credit Amount" },
{ VENDOR_CISCO_H323_CREDIT_TIME       ,"H323 Credit Time" },
{ VENDOR_CISCO_H323_RETURN_CODE       ,"H323 Return Code" },
{ VENDOR_CISCO_H323_PROMPT_ID         ,"H323 Prompt Id" },
{ VENDOR_CISCO_H323_TIME_AND_DAY      ,"H323 Time And Day" },
{ VENDOR_CISCO_H323_REDIRECT_NUMBER   ,"H323 Redirect Number" },
{ VENDOR_CISCO_H323_PREFERRED_LANG    ,"H323 Preferred Lang" },
{ VENDOR_CISCO_H323_REDIRECT_IP_ADDRESS ,"H323 Redirect Ip Address" },
{ VENDOR_CISCO_H323_BILLING_MODEL     ,"H323 Billing Model" },
{ VENDOR_CISCO_H323_CURRENCY_TYPE     ,"H323 Currency Type" },
{ VENDOR_CISCO_MULTILINK_ID           ,"Cisco Multilink ID" },
{ VENDOR_CISCO_NUM_IN_MULTILINK       ,"Cisco Num In Multilink" },
{ VENDOR_CISCO_PRE_INPUT_OCTETS       ,"Cisco Pre Input Octets" },
{ VENDOR_CISCO_PRE_OUTPUT_OCTETS      ,"Cisco Pre Output Octets" },
{ VENDOR_CISCO_PRE_INPUT_PACKETS      ,"Cisco Pre Input Packets" },
{ VENDOR_CISCO_PRE_OUTPUT_PACKETS     ,"Cisco Pre Output Packets" },
{ VENDOR_CISCO_MAXIMUM_TIME           ,"Cisco Maximum Time" },
{ VENDOR_CISCO_DISCONNECT_CAUSE       ,"Cisco Disconnect Cause" },
{ VENDOR_CISCO_DATA_RATE              ,"Cisco Data Rate" },
{ VENDOR_CISCO_PRESESSION_TIME        ,"Cisco PreSession Time" },
{ VENDOR_CISCO_PW_LIFETIME            ,"Cisco PW Lifetime" },
{ VENDOR_CISCO_IP_DIRECT              ,"Cisco IP Direct" },
{ VENDOR_CISCO_PPP_VJ_SLOT_COMP       ,"Cisco PPP VJ Slot Comp" },
{ VENDOR_CISCO_PPP_ASYNC_MAP          ,"Cisco PPP Async Map" },
{ VENDOR_CISCO_IP_POOL_DEFINITION     ,"Cisco IP Pool Definition" },
{ VENDOR_CISCO_ASING_IP_POOL          ,"Cisco Asing IP Pool" },
{ VENDOR_CISCO_ROUTE_IP               ,"Cisco Route IP" },
{ VENDOR_CISCO_LINK_COMPRESSION       ,"Cisco Link Compression" },
{ VENDOR_CISCO_TARGET_UTIL            ,"Cisco Target Util" },
{ VENDOR_CISCO_MAXIMUM_CHANNELS       ,"Cisco Maximum Channels" },
{ VENDOR_CISCO_DATA_FILTER            ,"Cisco Data Filter" },
{ VENDOR_CISCO_CALL_FILTER            ,"Cisco Call Filter" },
{ VENDOR_CISCO_IDLE_LIMIT             ,"Cisco Idle Limit" },
{ VENDOR_CISCO_XMIT_RATE              ,"Cisco Xmit Rate" },
{0,NULL}};

#define VENDOR_COSINE_VSA_CONNECTION_PROFILE_NAME 1
#define VENDOR_COSINE_VSA_ENTERPRISE_ID 2
#define VENDOR_COSINE_VSA_ADDRESS_POOL_NAME 3
#define VENDOR_COSINE_VSA_DS_BYTE 4
#define VENDOR_COSINE_VSA_VPI_VCI 5
#define VENDOR_COSINE_VSA_DLCI 6
#define VENDOR_COSINE_VSA_LNS_IP_ADDRESS 7
#define VENDOR_COSINE_VSA_CLI_USER_PERMISSION_ID 8

static value_string radius_vendor_cosine_types[]=
{{VENDOR_COSINE_VSA_CONNECTION_PROFILE_NAME,"Connection Profile Name"},
{VENDOR_COSINE_VSA_ENTERPRISE_ID,"Enterprise ID"},
{VENDOR_COSINE_VSA_ADDRESS_POOL_NAME,"Address Pool Name"},
{VENDOR_COSINE_VSA_DS_BYTE,"DS Byte"},
{VENDOR_COSINE_VSA_VPI_VCI,"VPI/VCI"},
{VENDOR_COSINE_VSA_DLCI,"DLCI"},
{VENDOR_COSINE_VSA_LNS_IP_ADDRESS,"LNS IP Address"},
{VENDOR_COSINE_VSA_CLI_USER_PERMISSION_ID,"CLI User Permission ID"},
{0,NULL}};

#define VENDOR_ISSANNI_VSA_SOFTFLOW_TEMPLATE   1
#define VENDOR_ISSANNI_VSA_NAT_POOL_NAME       2
#define VENDOR_ISSANNI_VSA_VRD                 3
#define VENDOR_ISSANNI_VSA_TUNNEL_NAME         4
#define VENDOR_ISSANNI_VSA_IP_POOL_NAME        5
#define VENDOR_ISSANNI_VSA_PPPOE_URL           6
#define VENDOR_ISSANNI_VSA_PPPOE_MOTM          7
#define VENDOR_ISSANNI_VSA_SERVICE             8
#define VENDOR_ISSANNI_VSA_PRI_DNS             9
#define VENDOR_ISSANNI_VSA_SEC_DNS             10
#define VENDOR_ISSANNI_VSA_PRI_NBNS            11
#define VENDOR_ISSANNI_VSA_SEC_NBNS            12
#define VENDOR_ISSANNI_VSA_TRAFFIC_CLASS       13
#define VENDOR_ISSANNI_VSA_TUNNEL_TYPE         14
#define VENDOR_ISSANNI_VSA_NAT_TYPE            15
#define VENDOR_ISSANNI_VSA_QOS_CLASS           16
#define VENDOR_ISSANNI_VSA_IFACE_NAME          17

static value_string radius_vendor_issanni_types[]=
{{VENDOR_ISSANNI_VSA_SOFTFLOW_TEMPLATE,"Softflow Template"},
{VENDOR_ISSANNI_VSA_NAT_POOL_NAME,"NAT Pool"},
{VENDOR_ISSANNI_VSA_VRD,"Virtual Routing Domain"},
{VENDOR_ISSANNI_VSA_TUNNEL_NAME,"Tunnel Name"},
{VENDOR_ISSANNI_VSA_IP_POOL_NAME,"IP Pool Name"},
{VENDOR_ISSANNI_VSA_PPPOE_URL,"PPPoE URL"},
{VENDOR_ISSANNI_VSA_PPPOE_MOTM,"PPPoE MOTM"},
{VENDOR_ISSANNI_VSA_SERVICE,"PPPoE Service"},
{VENDOR_ISSANNI_VSA_PRI_DNS,"Primary DNS"},
{VENDOR_ISSANNI_VSA_SEC_DNS,"Secondary DNS"},
{VENDOR_ISSANNI_VSA_PRI_NBNS,"Primary NBNS"},
{VENDOR_ISSANNI_VSA_SEC_NBNS,"Secondary NBNS"},
{VENDOR_ISSANNI_VSA_TRAFFIC_CLASS,"Policing Traffic Class"},
{VENDOR_ISSANNI_VSA_TUNNEL_TYPE,"Tunnel Type"},
{VENDOR_ISSANNI_VSA_NAT_TYPE,"NAT Type"},
{VENDOR_ISSANNI_VSA_QOS_CLASS,"QoS Traffic Class"},
{VENDOR_ISSANNI_VSA_IFACE_NAME,"Interface Name"},
{0,NULL}};

static value_string radius_framed_protocol_vals[]=
{{1, "PPP"},
{2, "SLIP"},
{3, "Appletalk Remote Access Protocol (ARAP)"},
{4, "Gandalf proprietary Singlelink/Multilink Protocol"},
{5, "Xylogics proprietary IPX/SLIP"},
{6, "X.75 Synchronous"},
{256, "Ascend MPP"},
{262, "Ascend MP"},
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
{3, "Interim-Update"},
{7,"Accounting-On"},
{8,"Accounting-Off"},
{9, "Tunnel-Start"}, /* Tunnel accounting */
{10, "Tunnel-Stop"}, /* Tunnel accounting */
{11, "Tunnel-Reject"}, /* Tunnel accounting */
{12, "Tunnel-Link-Start"}, /* Tunnel accounting */
{13, "Tunnel-Link-Stop"}, /* Tunnel accounting */
{14, "Tunnel-Link-Reject"}, /* Tunnel accounting */
{0,NULL}};

static value_string radius_accounting_authentication_vals[]=
{{1, "Radius"},
{2, "Local"},
{3,"Remote"},
/* RFC 2866 says 3 is Remote. Is 7 a mistake? */
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

static value_string radius_tunnel_type_vals[]=
{{1,"PPTP"},
{2,"L2F"},
{3,"L2TP"},
{4,"ATMP"},
{5,"VTP"},
{6,"AH"},
{7,"IP-IP-Encap"},
{8,"MIN-IP-IP"},
{9,"ESP"},
{10,"GRE"},
{11,"DVS"},
{12,"IP-IP"},
{0,NULL}};

static value_string radius_tunnel_medium_type_vals[]=
{{1,"IPv4"}, 
{2,"IPv6"},
{3,"NSAP"},
{4,"HDLC"},
{5,"BBN"},
{6,"IEEE-802"},
{7,"E-163"},
{8,"E-164"},
{9,"F-69"},
{10,"X-121"},
{11,"IPX"},
{12,"Appletalk"},
{13,"Decnet4"},
{14,"Vines"},
{15,"E-164-NSAP"},
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
{15,"Ethernet"},
{16,"xDSL"},
{17,"Cable"},
{18,"Wireless Other"},
{19,"Wireless IEEE 802.11"},
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
{ RD_TP_VENDOR_SPECIFIC, RADIUS_VENDOR_SPECIFIC},
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
{ RD_TP_ACCT_INPUT_GIGAWORDS, RADIUS_INTEGER4},
{ RD_TP_ACCT_OUTPUT_GIGAWORDS, RADIUS_INTEGER4},
{ RD_TP_EVENT_TIMESTAMP, RADIUS_TIMESTAMP},
{ RD_TP_CHAP_CHALLENGE, RADIUS_BINSTRING},
{ RD_TP_NAS_PORT_TYPE, RADIUS_NAS_PORT_TYPE},
{ RD_TP_PORT_LIMIT, RADIUS_INTEGER4},
{ RD_TP_LOGIN_LAT_PORT, RADIUS_BINSTRING},
{ RD_TP_TUNNEL_TYPE, RADIUS_TUNNEL_TYPE},
{ RD_TP_TUNNEL_MEDIUM_TYPE, RADIUS_TUNNEL_MEDIUM_TYPE},
{ RD_TP_TUNNEL_CLIENT_ENDPOINT, RADIUS_STRING_TAGGED},
{ RD_TP_TUNNEL_SERVER_ENDPOINT, RADIUS_STRING_TAGGED},
{ RD_TP_TUNNEL_CONNECTION, RADIUS_BINSTRING},
{ RD_TP_TUNNEL_PASSWORD, RADIUS_STRING_TAGGED},
{ RD_TP_ARAP_PASSWORD, RADIUS_BINSTRING},
{ RD_TP_ARAP_FEATURES, RADIUS_BINSTRING},
{ RD_TP_ARAP_ZONE_ACCESS, RADIUS_BINSTRING},
{ RD_TP_ARAP_SECURITY, RADIUS_BINSTRING},
{ RD_TP_ARAP_SECURITY_DATA, RADIUS_BINSTRING},
{ RD_TP_PASSWORD_RETRY, RADIUS_BINSTRING},
{ RD_TP_PROMPT, RADIUS_BINSTRING},
{ RD_TP_CONNECT_INFO, RADIUS_STRING},
{ RD_TP_CONFIGURATION_TOKEN, RADIUS_BINSTRING},
{ RD_TP_EAP_MESSAGE, RADIUS_BINSTRING},
{ RD_TP_MESSAGE_AUTHENTICATOR, RADIUS_BINSTRING},
{ RD_TP_TUNNEL_PRIVATE_GROUP_ID, RADIUS_STRING_TAGGED},
{ RD_TP_TUNNEL_ASSIGNMENT_ID, RADIUS_STRING_TAGGED},
{ RD_TP_TUNNEL_TUNNEL_PREFERENCE, RADIUS_INTEGER4_TAGGED},
{ RD_TP_TUNNEL_PACKETS_LOST, RADIUS_INTEGER4},
{ RD_TP_NAS_PORT_ID, RADIUS_STRING},
{ RD_TP_TUNNEL_CLIENT_AUTH_ID, RADIUS_STRING_TAGGED},
{ RD_TP_TUNNEL_SERVER_AUTH_ID, RADIUS_STRING_TAGGED},
{ RD_TP_ASCEND_MODEM_PORTNO, RADIUS_INTEGER4},
{ RD_TP_ASCEND_MODEM_SLOTNO, RADIUS_INTEGER4},
{ RD_TP_ASCEND_MULTILINK_ID, RADIUS_INTEGER4},
{ RD_TP_ASCEND_NUM_IN_MULTILINK, RADIUS_INTEGER4},
{ RD_TP_ASCEND_FIRST_DEST, RADIUS_IP_ADDRESS},
{ RD_TP_ASCEND_PRE_INPUT_OCTETS, RADIUS_INTEGER4},
{ RD_TP_ASCEND_PRE_OUTPUT_OCTETS, RADIUS_INTEGER4},
{ RD_TP_ASCEND_PRE_INPUT_PACKETS, RADIUS_INTEGER4},
{ RD_TP_ASCEND_PRE_OUTPUT_PACKETS, RADIUS_INTEGER4},
{ RD_TP_ASCEND_MAXIMUM_TIME, RADIUS_INTEGER4},
{ RD_TP_ASCEND_DISCONNECT_CAUSE, RADIUS_INTEGER4},
{ RD_TP_ASCEND_CONNECT_PROGRESS, RADIUS_INTEGER4},
{ RD_TP_ASCEND_DATA_RATE, RADIUS_INTEGER4},
{ RD_TP_ASCEND_PRESESSION_TIME, RADIUS_INTEGER4},
{ RD_TP_ASCEND_ASSIGN_IP_POOL, RADIUS_INTEGER4},
{ RD_TP_ASCEND_XMIT_RATE, RADIUS_INTEGER4},
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
{ RD_TP_ACCT_INPUT_GIGAWORDS, "Acct Input Gigawords"},
{ RD_TP_ACCT_OUTPUT_GIGAWORDS, "Acct Output Gigawords"},
{ RD_TP_EVENT_TIMESTAMP, "Event Timestamp"},
{ RD_TP_CHAP_CHALLENGE, "Chap Challenge"},
{ RD_TP_NAS_PORT_TYPE, "NAS Port Type"},
{ RD_TP_PORT_LIMIT, "Port Limit"},
{ RD_TP_LOGIN_LAT_PORT, "Login LAT Port"},
{ RD_TP_TUNNEL_TYPE, "Tunnel Type"},
{ RD_TP_TUNNEL_MEDIUM_TYPE, "Tunnel Medium Type"},
{ RD_TP_TUNNEL_CLIENT_ENDPOINT, "Tunnel Client Endpoint"},
{ RD_TP_TUNNEL_SERVER_ENDPOINT, "Tunnel Server Endpoint"},
{ RD_TP_TUNNEL_CONNECTION, "Tunnel Connection"},
{ RD_TP_TUNNEL_PASSWORD, "Tunnel Password"},
{ RD_TP_ARAP_PASSWORD, "ARAP-Password"},
{ RD_TP_ARAP_FEATURES, "ARAP-Features"},
{ RD_TP_ARAP_ZONE_ACCESS, "ARAP-Zone-Access"},
{ RD_TP_ARAP_SECURITY, "ARAP-Security"},
{ RD_TP_ARAP_SECURITY_DATA, "ARAP-Security-Data"},
{ RD_TP_PASSWORD_RETRY, "Password-Retry"},
{ RD_TP_PROMPT, "Prompt"},
{ RD_TP_CONNECT_INFO, "Connect-Info"},
{ RD_TP_CONFIGURATION_TOKEN, "Configuration-Token"},
{ RD_TP_EAP_MESSAGE, "EAP-Message"},
{ RD_TP_MESSAGE_AUTHENTICATOR, "Message Authenticator"},
{ RD_TP_TUNNEL_PRIVATE_GROUP_ID, "Tunnel Private Group ID"},
{ RD_TP_TUNNEL_ASSIGNMENT_ID, "Tunnel Assignment ID"},
{ RD_TP_TUNNEL_TUNNEL_PREFERENCE, "Tunnel Preference"},
{ RD_TP_TUNNEL_PACKETS_LOST, "Tunnel Packets Lost"},
{ RD_TP_NAS_PORT_ID, "NAS Port ID"},
{ RD_TP_TUNNEL_CLIENT_AUTH_ID, "Tunnel Client Auth ID"},
{ RD_TP_TUNNEL_SERVER_AUTH_ID, "Tunnel Server Auth ID"},
{ RD_TP_ASCEND_MODEM_PORTNO, "Ascend Modem Port No"},
{ RD_TP_ASCEND_MODEM_SLOTNO, "Ascend Modem Slot No"},
{ RD_TP_ASCEND_MULTILINK_ID, "Ascend Multilink ID"},
{ RD_TP_ASCEND_NUM_IN_MULTILINK, "Ascend Num In Multilink"},
{ RD_TP_ASCEND_FIRST_DEST, "Ascend First Dest"},
{ RD_TP_ASCEND_PRE_INPUT_OCTETS, "Ascend Pre Input Octets"},
{ RD_TP_ASCEND_PRE_OUTPUT_OCTETS, "Ascend Pre Output Octets"},
{ RD_TP_ASCEND_PRE_INPUT_PACKETS, "Ascend Pre Input Packets"},
{ RD_TP_ASCEND_PRE_OUTPUT_PACKETS, "Ascend Pre Output Packets"},
{ RD_TP_ASCEND_MAXIMUM_TIME, "Ascend Maximum Time"},
{ RD_TP_ASCEND_DISCONNECT_CAUSE, "Ascend Disconnect Cause"},
{ RD_TP_ASCEND_CONNECT_PROGRESS, "Ascend Connect Progress"},
{ RD_TP_ASCEND_DATA_RATE, "Ascend Data Rate"},
{ RD_TP_ASCEND_PRESESSION_TIME, "Ascend PreSession Time"},
{ RD_TP_ASCEND_ASSIGN_IP_POOL, "Ascend Assign IP Pool"},
{ RD_TP_ASCEND_XMIT_RATE, "Ascend Xmit Rate"},
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

gchar *rdconvertbufftostr(gchar *dest, tvbuff_t *tvb, int offset, int length)
{
/*converts the raw buffer into printable text */
	guint32 i;
	guint32 totlen=0;
	const guint8 *pd = tvb_get_ptr(tvb, offset, length);

        dest[0]='"';
        dest[1]=0;
        totlen=1;
        for (i=0; i < (guint32)length; i++)
        {
                if( isalnum((int)pd[i])||ispunct((int)pd[i])
                                ||((int)pd[i]==' '))            {
                        dest[totlen]=(gchar)pd[i];
                        totlen++;
                }
                else
                {
                        sprintf(&(dest[totlen]), "\\%03u", pd[i]);
                        totlen=totlen+strlen(&(dest[totlen]));
                }
        }
        dest[totlen]='"';
        dest[totlen+1]=0;
        return dest;
}

gchar *rd_match_strval(guint32 val, const value_string *vs) {
	return val_to_str(val, vs, "Undefined (%u)");
}

gchar *rd_value_to_str(e_avphdr *avph, tvbuff_t *tvb, int offset)
{
  int print_type;
  gchar *cont;
  value_string *valstrarr;
  guint32 intval;
  const guint8 *pd;
  guint8 tag;
  guint8 vtype;
  char *rtimestamp;
  extern char *tzname[2];

/* prints the values of the attribute value pairs into a text buffer */
  print_type=match_numval(avph->avp_type,radius_printinfo);

  /* Default begin */
  strcpy(textbuffer,"Value:");
  cont=&textbuffer[strlen(textbuffer)];
  switch(print_type)
  {
        case( RADIUS_STRING ):
        case( RADIUS_BINSTRING ):
		rdconvertbufftostr(cont,tvb,offset+2,avph->avp_length-2);
                break;
        case( RADIUS_INTEGER4 ):
                sprintf(cont,"%u", tvb_get_ntohl(tvb,offset+2));
                break;
        case( RADIUS_IP_ADDRESS ):
                ip_to_str_buf(tvb_get_ptr(tvb,offset+2,4),cont);
                break;
        case( RADIUS_SERVICE_TYPE ):
                valstrarr=radius_service_type_vals;
                strcpy(cont,rd_match_strval(tvb_get_ntohl(tvb,offset+2),valstrarr));
                break;
        case( RADIUS_FRAMED_PROTOCOL ):
                valstrarr= radius_framed_protocol_vals;
                strcpy(cont,rd_match_strval(tvb_get_ntohl(tvb,offset+2),valstrarr));
                break;
        case( RADIUS_FRAMED_ROUTING ):
                valstrarr=radius_framed_routing_vals;
                strcpy(cont,rd_match_strval(tvb_get_ntohl(tvb,offset+2),valstrarr));
                break;
        case( RADIUS_FRAMED_COMPRESSION ):
                valstrarr=radius_framed_compression_vals;
                strcpy(cont,rd_match_strval(tvb_get_ntohl(tvb,offset+2),valstrarr));
                break;
        case( RADIUS_LOGIN_SERVICE ):
                valstrarr=radius_login_service_vals;
                strcpy(cont,rd_match_strval(tvb_get_ntohl(tvb,offset+2),valstrarr));
                break;
        case( RADIUS_IPX_ADDRESS ):
                pd = tvb_get_ptr(tvb,offset+2,4);
                sprintf(cont,"%u:%u:%u:%u",(guint8)pd[offset+2],
                        (guint8)pd[offset+3],(guint8)pd[offset+4],
                        (guint8)pd[offset+5]);
        case( RADIUS_TERMINATING_ACTION ):
                valstrarr=radius_terminating_action_vals;
                strcpy(cont,rd_match_strval(tvb_get_ntohl(tvb,offset+2),valstrarr));
                break;
        case( RADIUS_ACCOUNTING_STATUS_TYPE ):
                valstrarr=radius_accounting_status_type_vals;
                strcpy(cont,rd_match_strval(tvb_get_ntohl(tvb,offset+2),valstrarr));
                break;
        case( RADIUS_ACCT_AUTHENTIC ):
                valstrarr=radius_accounting_authentication_vals;
                strcpy(cont,rd_match_strval(tvb_get_ntohl(tvb,offset+2),valstrarr));
                break;
        case( RADIUS_ACCT_TERMINATE_CAUSE ):
                valstrarr=radius_acct_terminate_cause_vals;
                strcpy(cont,rd_match_strval(tvb_get_ntohl(tvb,offset+2),valstrarr));
                break;
        case( RADIUS_NAS_PORT_TYPE ):
                valstrarr=radius_nas_port_type_vals;
                strcpy(cont,rd_match_strval(tvb_get_ntohl(tvb,offset+2),valstrarr));
                break;
	case( RADIUS_TUNNEL_TYPE ):
		valstrarr=radius_tunnel_type_vals;
		/* Tagged ? */
		intval = tvb_get_ntohl(tvb,offset+2);
		if (intval >> 24) {
			sprintf(textbuffer, "Tag:%u, Value:%s",
				intval >> 24,
				rd_match_strval(intval & 0xffffff,valstrarr));
			break;
		}
		strcpy(cont,rd_match_strval(intval,valstrarr));
		break;
	case( RADIUS_TUNNEL_MEDIUM_TYPE ):
		valstrarr=radius_tunnel_medium_type_vals;
		intval = tvb_get_ntohl(tvb,offset+2);
		/* Tagged ? */
		if (intval >> 24) {
			sprintf(textbuffer, "Tag:%u, Value:%s",
				intval >> 24,
				rd_match_strval(intval & 0xffffff,valstrarr));
			break;
		}
		strcpy(cont,rd_match_strval(intval,valstrarr));
		break;
        case( RADIUS_STRING_TAGGED ):
		/* Tagged ? */
		tag = tvb_get_guint8(tvb,offset+2);
		if (tag <= 0x1f) {
			sprintf(textbuffer, "Tag:%u, Value:",
					tag);
			cont=&textbuffer[strlen(textbuffer)];	
			rdconvertbufftostr(cont,tvb,offset+3,avph->avp_length-3);
			break;
		}
		rdconvertbufftostr(cont,tvb,offset+2,avph->avp_length-2);
                break;
	case ( RADIUS_VENDOR_SPECIFIC ):
		valstrarr=radius_vendor_specific_vendors;
		sprintf(textbuffer,"Vendor:%s,",
			rd_match_strval(tvb_get_ntohl(tvb,offset+2),valstrarr));
		cont=&textbuffer[strlen(textbuffer)];
		switch (tvb_get_ntohl(tvb,offset+2)) {
		case ( VENDOR_CISCO ):
		  vtype = tvb_get_guint8(tvb,offset+6);
		  switch (vtype) {
		  case ( VENDOR_CISCO_AVP_CISCO ):
		    sprintf(cont," Type:%s, Len:%i Value:",
			    rd_match_strval(vtype,radius_vendor_cisco_types),
			    avph->avp_length-8);
		    cont=&textbuffer[strlen(textbuffer)];
		    rdconvertbufftostr(cont,tvb,offset+8,
				       avph->avp_length-8);
		    break;
		  default:
		    sprintf(cont," Type:%s, Len:%i Value:",
			    rd_match_strval(vtype,radius_vendor_cisco_types),
			    avph->avp_length-8);
		    cont=&textbuffer[strlen(textbuffer)];
		    rdconvertbufftostr(cont,tvb,offset+8,
				       avph->avp_length-8);
		    break;
		  }
		  break;
		case ( VENDOR_COSINE ):
			vtype = tvb_get_guint8(tvb,offset+6);
			switch (vtype) {
			case ( VENDOR_COSINE_VSA_CONNECTION_PROFILE_NAME ):
			case ( VENDOR_COSINE_VSA_ENTERPRISE_ID ):
			case ( VENDOR_COSINE_VSA_ADDRESS_POOL_NAME ):
			case ( VENDOR_COSINE_VSA_CLI_USER_PERMISSION_ID ):
				sprintf(cont," Type:%s, Value:",
					rd_match_strval(vtype, radius_vendor_cosine_types));
				cont=&textbuffer[strlen(textbuffer)];
				rdconvertbufftostr(cont,tvb,offset+8,avph->avp_length-8);
				break;
			case ( VENDOR_COSINE_VSA_VPI_VCI ):
				sprintf(cont," Type:%s, Value:%u/%u",
					rd_match_strval(vtype, radius_vendor_cosine_types),
					tvb_get_ntohs(tvb,offset+8),
					tvb_get_ntohs(tvb,offset+10));
				break;
			case ( VENDOR_COSINE_VSA_DS_BYTE ):
			case ( VENDOR_COSINE_VSA_DLCI ):
				sprintf(cont," Type:%s, Value:%u",
					rd_match_strval(vtype, radius_vendor_cosine_types),
					tvb_get_ntohl(tvb,offset+8));
				break;
			case ( VENDOR_COSINE_VSA_LNS_IP_ADDRESS ):
				sprintf(cont," Type:%s, Value:",
					rd_match_strval(vtype, radius_vendor_cosine_types));
				cont=&textbuffer[strlen(textbuffer)];
				ip_to_str_buf(tvb_get_ptr(tvb,offset+8,4),cont);
				break;
			default:
				sprintf(cont," Unknown Value Type");
				break;
			}
			break;
		case ( VENDOR_ISSANNI ):
			vtype = tvb_get_guint8(tvb,offset+6);
			switch (vtype) {
			case ( VENDOR_ISSANNI_VSA_SOFTFLOW_TEMPLATE ):
			case ( VENDOR_ISSANNI_VSA_NAT_POOL_NAME ):
			case ( VENDOR_ISSANNI_VSA_VRD ):
			case ( VENDOR_ISSANNI_VSA_TUNNEL_NAME ):
			case ( VENDOR_ISSANNI_VSA_IP_POOL_NAME ):
			case ( VENDOR_ISSANNI_VSA_PPPOE_URL ):
			case ( VENDOR_ISSANNI_VSA_PPPOE_MOTM ):
			case ( VENDOR_ISSANNI_VSA_SERVICE ):
			case ( VENDOR_ISSANNI_VSA_TRAFFIC_CLASS ):
			case ( VENDOR_ISSANNI_VSA_QOS_CLASS ):
			case ( VENDOR_ISSANNI_VSA_IFACE_NAME ):
				sprintf(cont," Type:%s, Value:",
					rd_match_strval(vtype, radius_vendor_issanni_types));
				cont=&textbuffer[strlen(textbuffer)];
				rdconvertbufftostr(cont,tvb,offset+8,avph->avp_length-8);
				break;
			case ( VENDOR_ISSANNI_VSA_NAT_TYPE ):
			case ( VENDOR_ISSANNI_VSA_TUNNEL_TYPE ):
				sprintf(cont," Type:%s, Value:%u",
					rd_match_strval(vtype, radius_vendor_issanni_types),
					tvb_get_ntohl(tvb,offset+8));
				break;
			case ( VENDOR_ISSANNI_VSA_PRI_DNS ):
			case ( VENDOR_ISSANNI_VSA_SEC_DNS ):
			case ( VENDOR_ISSANNI_VSA_PRI_NBNS ):
			case ( VENDOR_ISSANNI_VSA_SEC_NBNS ):
				sprintf(cont," Type:%s, Value:",
					rd_match_strval(vtype, radius_vendor_issanni_types));
				cont=&textbuffer[strlen(textbuffer)];
				ip_to_str_buf(tvb_get_ptr(tvb,offset+8,4),cont);
				break;
			default:
				sprintf(cont," Unknown Value Type");
				break;
			}
			break;
		default: 
			sprintf(cont, " Value:");
			rdconvertbufftostr(cont,tvb,offset+6,avph->avp_length-6);
			break;
		}
		break;
        case( RADIUS_TIMESTAMP ):
		intval=tvb_get_ntohl(tvb,offset+2);
		rtimestamp=ctime((time_t*)&intval);
		rtimestamp[strlen(rtimestamp)-1]=0;
		sprintf(cont,"%d (%s %s)", tvb_get_ntohl(tvb,offset+2), rtimestamp, *tzname);
		break;
        case( RADIUS_INTEGER4_TAGGED ):
		intval = tvb_get_ntohl(tvb,offset+2);
		/* Tagged ? */
		if (intval >> 24) {
			sprintf(textbuffer, "Tag:%u, Value:%u",
				intval >> 24,
				intval & 0xffffff);
			break;
		}
		sprintf(cont,"%u", intval);
		break;
        case( RADIUS_UNKNOWN ):
        default:
                strcpy(textbuffer,"Unknown Value Type");
                break;
  }
  if (cont == textbuffer) {
  	strcpy(cont,"Unknown Value");
  }
  return textbuffer;
}


void dissect_attribute_value_pairs(tvbuff_t *tvb, int offset,proto_tree *tree,
				   int avplength,packet_info *pinfo)
{
/* adds the attribute value pairs to the tree */
  e_avphdr avph;
  gchar *avptpstrval;
  gchar *valstr;
  guint8 *reassembled_data = NULL;
  int reassembled_data_len = 0;
  int data_needed = 0;

  if (avplength==0)
  {
    if (tree)
      proto_tree_add_text(tree, tvb,offset,0,"No Attribute Value Pairs Found");
    return;
  }

  /*
   * In case we throw an exception, clean up whatever stuff we've
   * allocated (if any).
   */
  CLEANUP_PUSH(g_free, reassembled_data);

  while (avplength > 0)
  {
    tvb_memcpy(tvb,(guint8 *)&avph,offset,sizeof(e_avphdr));
    avptpstrval = match_strval(avph.avp_type, radius_attrib_type_vals);
    if (avptpstrval == NULL)
      avptpstrval = "Unknown Type";
    if (avph.avp_length < 2) {
      /*
       * This AVP is bogus - the length includes the type and length
       * fields, so it must be >= 2.
       */
      if (tree) {
        proto_tree_add_text(tree, tvb, offset, avph.avp_length,
			    "t:%s(%u) l:%u (length not >= 2)",
			    avptpstrval, avph.avp_type, avph.avp_length);
      }
      break;
    }

    if (avph.avp_type == RD_TP_EAP_MESSAGE) {
      proto_item *ti;
      proto_tree *eap_tree = NULL;
      gint tvb_len;
      tvbuff_t *next_tvb;
      int data_len;
      int result;

      if (tree) {
        ti = proto_tree_add_text(tree, tvb, offset, avph.avp_length,
				 "t:%s(%u) l:%u",
			 	 avptpstrval, avph.avp_type, avph.avp_length);
        eap_tree = proto_item_add_subtree(ti, ett_radius_eap);
      }
      tvb_len = tvb_length_remaining(tvb, offset+2);
      data_len = avph.avp_length-2;
      if (data_len < tvb_len)
        tvb_len = data_len;
      next_tvb = tvb_new_subset(tvb, offset+2, tvb_len, data_len);

      /*
       * Set the columns non-writable, so that the packet list
       * shows this as an RADIUS packet, not as an EAP packet.
       */
      col_set_writable(pinfo->cinfo, FALSE);

      /*
       * RFC 2869 says, in section 5.13, describing the EAP-Message
       * attribute:
       *
       *    The String field contains EAP packets, as defined in [3].  If
       *    multiple EAP-Message attributes are present in a packet their
       *    values should be concatenated; this allows EAP packets longer than
       *    253 octets to be passed by RADIUS.
       *
       * Do reassembly of EAP-Message attributes.
       */

      /* Are we in the process of reassembling? */
      if (reassembled_data != NULL) {
        /* Yes - show this as an EAP fragment. */
        if (tree)
          proto_tree_add_text(eap_tree, next_tvb, 0, -1, "EAP fragment");

        /*
         * Do we have all of the data in this fragment?
         */
        if (tvb_len >= data_len) {
          /*
           * Yes - add it to the reassembled data.
           */
          tvb_memcpy(next_tvb, reassembled_data + reassembled_data_len,
		     0, data_len);
          reassembled_data_len += data_len;
          data_needed -= data_len;
          if (data_needed <= 0) {
            /*
             * We got at least as much data as we needed; we're done
             * reassembling.
             * XXX - what if we got more?
             */

            /*
             * Allocate a new tvbuff, referring to the reassembled payload.
             */
            next_tvb = tvb_new_real_data(reassembled_data, reassembled_data_len,
					 reassembled_data_len);

            /*
             * We have a tvbuff that refers to this data, so we shouldn't
             * free this data if we throw an exception; clear
             * "reassembled_data", so the cleanup handler won't free it.
             */
            reassembled_data = NULL;
            reassembled_data_len = 0;
            data_needed = 0;

            /*
             * Arrange that the allocated packet data copy be freed when the
             * tvbuff is freed.
             */
            tvb_set_free_cb(next_tvb, g_free);

            /*
             * Add the tvbuff to the list of tvbuffs to which the tvbuff we
             * were handed refers, so it'll get cleaned up when that tvbuff
             * is cleaned up.
             */
            tvb_set_child_real_data_tvbuff(tvb, next_tvb);

            /* Add the defragmented data to the data source list. */
            add_new_data_source(pinfo->fd, next_tvb, "Reassembled EAP");

            /* Now dissect it. */
	    call_dissector(eap_fragment_handle, next_tvb, pinfo, eap_tree);
	  }
	}
      } else {
        /*
         * No - hand it to the dissector.
         */
        result = call_dissector(eap_fragment_handle, next_tvb, pinfo, eap_tree);
        if (result < 0) {
          /* This is only part of the full EAP packet; start reassembly. */
          proto_tree_add_text(eap_tree, next_tvb, 0, -1, "EAP fragment");
          reassembled_data_len = data_len;
          data_needed = -result;
          reassembled_data = g_malloc(reassembled_data_len + data_needed);
          tvb_memcpy(next_tvb, reassembled_data, 0, reassembled_data_len);
        }
      }
    } else {
      if (tree) {
        valstr = rd_value_to_str(&avph, tvb, offset);
        proto_tree_add_text(tree, tvb, offset, avph.avp_length,
			    "t:%s(%u) l:%u, %s",
			    avptpstrval, avph.avp_type, avph.avp_length,
			    valstr);
      }
    }

    offset = offset+avph.avp_length;
    avplength = avplength-avph.avp_length;
  }

  /*
   * Call the cleanup handler to free any reassembled data we haven't
   * attached to a tvbuff, and pop the handler.
   */
  CLEANUP_CALL_AND_POP;
}

static void dissect_radius(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *radius_tree = NULL, *avptree = NULL;
  proto_item *ti,*avptf;
  int rhlength;
  int rhcode;
  int rhident;
  int avplength,hdrlength;
  e_radiushdr rh;

  gchar *codestrval;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "RADIUS");
  if (check_col(pinfo->cinfo, COL_INFO))
        col_clear(pinfo->cinfo, COL_INFO);

  tvb_memcpy(tvb,(guint8 *)&rh,0,sizeof(e_radiushdr));

  rhcode= (int)rh.rh_code;
  rhident= (int)rh.rh_ident;
  rhlength= (int)ntohs(rh.rh_pktlength);
  codestrval=  match_strval(rhcode,radius_vals);
  if (codestrval==NULL)
  {
	codestrval="Unknown Packet";
  }
  if (check_col(pinfo->cinfo, COL_INFO))
  {
        col_add_fstr(pinfo->cinfo,COL_INFO,"%s(%d) (id=%d, l=%d)",
		codestrval, rhcode, rhident, rhlength);
  }

  if (tree)
  {
        ti = proto_tree_add_item(tree,proto_radius, tvb, 0, rhlength, FALSE);

        radius_tree = proto_item_add_subtree(ti, ett_radius);

	proto_tree_add_uint(radius_tree,hf_radius_code, tvb, 0, 1,
                rh.rh_code);
        proto_tree_add_uint_format(radius_tree,hf_radius_id, tvb, 1, 1,
                rh.rh_ident, "Packet identifier: 0x%01x (%d)",
			rhident,rhident);         

	proto_tree_add_uint(radius_tree, hf_radius_length, tvb,
			2, 2, rhlength);
	proto_tree_add_text(radius_tree, tvb, 4,
			AUTHENTICATOR_LENGTH,
                         "Authenticator");
  }
   
  hdrlength=RD_HDR_LENGTH+AUTHENTICATOR_LENGTH;
  avplength= rhlength -hdrlength;

  if (avplength > 0) {
    /* list the attribute value pairs */

    if (tree)
    {
      avptf = proto_tree_add_text(radius_tree,
                                  tvb,hdrlength,avplength,
                                  "Attribute value pairs");
      avptree = proto_item_add_subtree(avptf, ett_radius_avp);
    }

    dissect_attribute_value_pairs(tvb, hdrlength, avptree, avplength, pinfo);
  }
}
/* registration with the filtering engine */
void
proto_register_radius(void)
{
	static hf_register_info hf[] = {
		{ &hf_radius_code,
		{ "Code","radius.code", FT_UINT8, BASE_DEC, VALS(radius_vals), 0x0,
			"", HFILL }},

		{ &hf_radius_id,
		{ "Identifier",	"radius.id", FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_radius_length,
		{ "Length","radius.length", FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }}
	};
	static gint *ett[] = {
		&ett_radius,
		&ett_radius_avp,
		&ett_radius_eap,
	};

	proto_radius = proto_register_protocol("Radius Protocol", "RADIUS",
	    "radius");
	proto_register_field_array(proto_radius, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_radius(void)
{
	dissector_handle_t radius_handle;

	/*
	 * Get a handle for the EAP fragment dissector.
	 */
	eap_fragment_handle = find_dissector("eap_fragment");

	radius_handle = create_dissector_handle(dissect_radius, proto_radius);
	dissector_add("udp.port", UDP_PORT_RADIUS, radius_handle);
	dissector_add("udp.port", UDP_PORT_RADIUS_NEW, radius_handle);
	dissector_add("udp.port", UDP_PORT_RADACCT, radius_handle);
	dissector_add("udp.port", UDP_PORT_RADACCT_NEW, radius_handle);
}
