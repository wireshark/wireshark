/* packet-radius.c
 * Routines for RADIUS packet disassembly
 * Copyright 1999 Johan Feyaerts
 *
 * RFC 2865, RFC 2866, RFC 2867, RFC 2868, RFC 2869
 *
 * $Id: packet-radius.c,v 1.59 2002/05/13 08:57:43 guy Exp $
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
static gint ett_radius_vsa = -1;

static dissector_handle_t eap_fragment_handle;

#define UDP_PORT_RADIUS		1645
#define UDP_PORT_RADIUS_NEW	1812
#define UDP_PORT_RADACCT	1646
#define UDP_PORT_RADACCT_NEW	1813

#define TEXTBUFFER		2000
#define VSABUFFER		10

typedef struct _e_radiushdr {
        guint8 rh_code;
        guint8 rh_ident;
        guint16 rh_pktlength;
} e_radiushdr;

typedef struct _e_avphdr {
        guint8 avp_type;
        guint8 avp_length;
} e_avphdr;

typedef struct _value_value_string {
        guint16 val1;
        guint16 val2;
	gchar *str;
} value_value_string;

typedef struct _rd_vsa_table {
	guint32 vendor;
	value_value_string *attrib;
} rd_vsa_table;

typedef struct _rd_valstr_table {
	int print_type;
	value_string *valstr;
} rd_valstr_table;

typedef struct _rd_vsa_buffer {
	gchar *str;
	int offset;
	guint8 length;
} rd_vsa_buffer;

#define AUTHENTICATOR_LENGTH 16
#define RD_HDR_LENGTH 4

#define RADIUS_ACCESS_REQUEST 1
#define RADIUS_ACCESS_ACCEPT  2
#define RADIUS_ACCESS_REJECT  3
#define RADIUS_ACCOUNTING_REQUEST 4
#define RADIUS_ACCOUNTING_RESPONSE 5
#define RADIUS_ACCESS_PASSWORD_REQUEST 7
#define RADIUS_ACCESS_PASSWORD_ACK 8
#define RADIUS_ACCESS_PASSWORD_REJECT 9
#define RADIUS_ACCESS_CHALLENGE 11
#define RADIUS_STATUS_SERVER 12
#define RADIUS_STATUS_CLIENT 13
#define RADIUS_VENDOR_SPECIFIC_CODE 26
#define RADIUS_ASCEND_ACCESS_NEXT_CODE 29
#define RADIUS_ASCEND_ACCESS_NEW_PIN 30
#define RADIUS_ASCEND_PASSWORD_EXPIRED 32
#define RADIUS_ASCEND_ACCESS_EVENT_REQUEST 33
#define RADIUS_ASCEND_ACCESS_EVENT_RESPONSE 34
#define RADIUS_DISCONNECT_REQUEST 40
#define RADIUS_DISCONNECT_REQUEST_ACK 41
#define RADIUS_DISCONNECT_REQUEST_NAK 42
#define RADIUS_CHANGE_FILTER_REQUEST 43
#define RADIUS_CHANGE_FILTER_REQUEST_ACK 44
#define RADIUS_CHANGE_FILTER_REQUEST_NAK 45
#define RADIUS_RESERVED 255

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
#define CISCO_DISCONNECT_CAUSE			23
#define MICROSOFT_BAP_USAGE			24
#define MICROSOFT_ARAP_PW_CHANGE_REASON		25
#define MICROSOFT_ACCT_AUTH_TYPE		26
#define MICROSOFT_ACCT_EAP_TYPE			27
#define ASCEND_CALLING_ID_TYPE_OF_NUMBER	28
#define ASCEND_CALLING_ID_NUMBERING_PLAN	29
#define ASCEND_CALLING_ID_PRESENTATION		30
#define ASCEND_CALLING_ID_SCREENING		31
#define COSINE_VPI_VCI				32

static value_string radius_vals[] =
{
 {RADIUS_ACCESS_REQUEST, "Access Request"},
 {RADIUS_ACCESS_ACCEPT, "Access Accept"},
 {RADIUS_ACCESS_REJECT, "Access Reject"},
 {RADIUS_ACCOUNTING_REQUEST, "Accounting Request"},
 {RADIUS_ACCOUNTING_RESPONSE, "Accounting Response"},
 {RADIUS_ACCESS_PASSWORD_REQUEST, "Access Password Request"},
 {RADIUS_ACCESS_PASSWORD_ACK, "Access Password Ack"},
 {RADIUS_ACCESS_PASSWORD_REJECT, "Access Password Reject"},
 {RADIUS_ACCESS_CHALLENGE, "Access challenge"},
 {RADIUS_STATUS_SERVER, "StatusServer"},
 {RADIUS_STATUS_CLIENT, "StatusClient"},
 {RADIUS_VENDOR_SPECIFIC_CODE, "Vendor Specific"},
 {RADIUS_ASCEND_ACCESS_NEXT_CODE, "Ascend Access Next Code"},
 {RADIUS_ASCEND_ACCESS_NEW_PIN, "Ascend Access New Pin"},
 {RADIUS_ASCEND_PASSWORD_EXPIRED, "Ascend Password Expired"},
 {RADIUS_ASCEND_ACCESS_EVENT_REQUEST, "Ascend Access Event Request"},
 {RADIUS_ASCEND_ACCESS_EVENT_RESPONSE, "Ascend Access Event Response"},
 {RADIUS_DISCONNECT_REQUEST, "Disconnect Request"},
 {RADIUS_DISCONNECT_REQUEST_ACK, "Disconnect Request ACK"},
 {RADIUS_DISCONNECT_REQUEST_NAK, "Disconnect Request NAK"},
 {RADIUS_CHANGE_FILTER_REQUEST, "Change Filter Request"},
 {RADIUS_CHANGE_FILTER_REQUEST_ACK, "Change Filter Request ACK"},
 {RADIUS_CHANGE_FILTER_REQUEST_NAK, "Change Filter Request NAK"},
 {RADIUS_RESERVED, "Reserved"},
  {0, NULL}
};

/*
 * These are SMI Network Management Private Enterprise Codes for
 * organizations; see
 *
 *	http://www.isi.edu/in-notes/iana/assignments/enterprise-numbers
 *
 * for a list.
 *
 * XXX - these also appear in FreeRadius dictionary files, with items such
 * as
 *
 *	VENDOR          Cisco           9
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

static value_string radius_vendor_specific_vendors[] =
{
  {VENDOR_ACC,		"ACC"},
  {VENDOR_CISCO,	"Cisco"},
  {VENDOR_SHIVA,	"Shiva"},
  {VENDOR_MICROSOFT,	"Microsoft"},
  {VENDOR_LIVINGSTON,	"Livingston"},
  {VENDOR_3COM,		"3Com"},
  {VENDOR_ASCEND,	"Ascend"},
  {VENDOR_BAY,		"Bay Networks"},
  {VENDOR_JUNIPER,	"Juniper Networks"},
  {VENDOR_COSINE,	"CoSine Communications"},
  {VENDOR_UNISPHERE,	"Unisphere Networks"},
  {VENDOR_ISSANNI,	"Issanni Communications"},
  {0, NULL}
};

static value_value_string null_attrib[] =
{
    {0, 0, NULL}
};

static value_string null_vals[] =
{
    {0, NULL}
};

/*
 * XXX - should these be read from files, such as FreeRadius dictionary
 * files?  For example, its "dictionary" file has
 *
 *	ATTRIBUTE       User-Name               1       string
 *
 * for the attribute that's
 *
 *	{1,	RADIUS_STRING,			"User Name"},
 *
 * in our tables:
 *
 *	"string" -> RADIUS_STRING
 *	"octets" -> RADIUS_BINSTRING
 *	"integer" -> RADIUS_INTEGER4
 *	"ipaddr" -> RADIUS_IP_ADDRESS
 */
static value_value_string radius_attrib[] =
{
  {1,	RADIUS_STRING,			"User Name"},
  {2,	RADIUS_STRING,			"User Password"},
  {3,	RADIUS_BINSTRING,		"Chap Password"},
  {4,	RADIUS_IP_ADDRESS,		"NAS IP Address"},
  {5,	RADIUS_INTEGER4,		"NAS Port"},
  {6,	RADIUS_SERVICE_TYPE,		"Service Type"},
  {7,	RADIUS_FRAMED_PROTOCOL,		"Framed Protocol"},
  {8,	RADIUS_IP_ADDRESS,		"Framed IP Address"},
  {9,	RADIUS_IP_ADDRESS,		"Framed IP Netmask"},
  {10,	RADIUS_FRAMED_ROUTING,		"Framed Routing"},
  {11,	RADIUS_STRING,			"Filter Id"},
  {12,	RADIUS_INTEGER4,		"Framed MTU"},
  {13,	RADIUS_FRAMED_COMPRESSION,	"Framed Compression"},
  {14,	RADIUS_IP_ADDRESS,		"Login IP Host"},
  {15,	RADIUS_LOGIN_SERVICE,		"Login Service"},
  {16,	RADIUS_INTEGER4,		"Login TCP Port"},
  {17,	RADIUS_UNKNOWN,			"Unassigned"},
  {18,	RADIUS_STRING,			"Reply Message"},
  {19,	RADIUS_STRING,			"Callback Number"},
  {20,	RADIUS_STRING,			"Callback Id"},
  {21,	RADIUS_UNKNOWN,			"Unassigned"},
  {22,	RADIUS_STRING,			"Framed Route"},
  {23,	RADIUS_IPX_ADDRESS,		"Framed IPX network"},
  {24,	RADIUS_BINSTRING,		"State"},
  {25,	RADIUS_BINSTRING,		"Class"},
  {26,	RADIUS_VENDOR_SPECIFIC,		"Vendor Specific"},
  {27,	RADIUS_INTEGER4,		"Session Timeout"},
  {28,	RADIUS_INTEGER4,		"Idle Timeout"},
  {29,	RADIUS_TERMINATING_ACTION,	"Terminating Action"},
  {30,	RADIUS_STRING,			"Called Station Id"},
  {31,	RADIUS_STRING,			"Calling Station Id"},
  {32,	RADIUS_STRING,			"NAS identifier"},
  {33,	RADIUS_BINSTRING,		"Proxy State"},
  {34,	RADIUS_STRING,			"Login LAT Service"},
  {35,	RADIUS_STRING,			"Login LAT Node"},
  {36,	RADIUS_BINSTRING,		"Login LAT Group"},
  {37,	RADIUS_INTEGER4,		"Framed Appletalk Link"},
  {38,	RADIUS_INTEGER4,		"Framed Appletalk Network"},
  {39,	RADIUS_STRING,			"Framed Appletalk Zone"},
  {40,	RADIUS_ACCOUNTING_STATUS_TYPE,	"Acct Status Type"},
  {41,	RADIUS_INTEGER4,		"Acct Delay Time"},
  {42,	RADIUS_INTEGER4,		"Acct Input Octets"},
  {43,	RADIUS_INTEGER4,		"Acct Output Octets"},
  {44,	RADIUS_STRING,			"Acct Session Id"},
  {45,	RADIUS_ACCT_AUTHENTIC,		"Acct Authentic"},
  {46,	RADIUS_INTEGER4,		"Acct Session Time"},
  {47,	RADIUS_INTEGER4,		"Acct Input Packets"},
  {48,	RADIUS_INTEGER4,		"Acct Output Packets"},
  {49,	RADIUS_ACCT_TERMINATE_CAUSE,	"Acct Terminate Cause"},
  {50,	RADIUS_STRING,			"Acct Multi Session Id"},
  {51,	RADIUS_INTEGER4,		"Acct Link Count"},
  {52,	RADIUS_INTEGER4,		"Acct Input Gigawords"},
  {53,	RADIUS_INTEGER4,		"Acct Output Gigawords"},
  /* 54 Unused */
  {55,	RADIUS_TIMESTAMP,		"Event Timestamp"},
  /* 56-59 Unused */ 
  {60,	RADIUS_STRING,			"Chap Challenge"},
  {61,	RADIUS_NAS_PORT_TYPE,		"NAS Port Type"},
  {62,	RADIUS_INTEGER4,		"Port Limit"},
  {63,	RADIUS_BINSTRING,		"Login LAT Port"},
  {64,	RADIUS_TUNNEL_TYPE,		"Tunnel Type"},
  {65,	RADIUS_TUNNEL_MEDIUM_TYPE,	"Tunnel Medium Type"},
  {66,	RADIUS_STRING_TAGGED,		"Tunnel Client Endpoint"},
  {67,	RADIUS_STRING_TAGGED,		"Tunnel Server Endpoint"},
  {68,	RADIUS_STRING,			"Tunnel Connection"},
  {69,	RADIUS_STRING_TAGGED,		"Tunnel Password"},
  {70,	RADIUS_STRING,			"ARAP-Password"},
  {71,	RADIUS_STRING,			"ARAP-Features"},
  {72,	RADIUS_INTEGER4,		"ARAP-Zone-Access"},
  {73,	RADIUS_INTEGER4,		"ARAP-Security"},
  {74,	RADIUS_STRING,			"ARAP-Security-Data"},
  {75,	RADIUS_INTEGER4,		"Password-Retry"},
  {76,	RADIUS_INTEGER4,		"Prompt"},
  {77,	RADIUS_STRING,			"Connect-Info"},
  {78,	RADIUS_STRING,			"Configuration-Token"},
  {79,	RADIUS_STRING,			"EAP-Message"},
  {80,	RADIUS_BINSTRING,		"Message Authenticator"},
  {81,	RADIUS_STRING_TAGGED,		"Tunnel Private Group ID"},
  {82,	RADIUS_STRING_TAGGED,		"Tunnel Assignment ID"},
  {83,	RADIUS_INTEGER4_TAGGED,		"Tunnel Preference"},
  {84,	RADIUS_STRING,			"ARAP Challenge Response"},
  {85,	RADIUS_INTEGER4,		"Acct Interim Interval"},
  {86,	RADIUS_INTEGER4,		"Tunnel Packets Lost"},
  {87,	RADIUS_STRING,			"NAS Port ID"},
  {88,	RADIUS_STRING,			"Framed Pool"},
  {90,	RADIUS_STRING_TAGGED,		"Tunnel Client Auth ID"},
  {91,	RADIUS_STRING_TAGGED,		"Tunnel Server Auth ID"},
  {120,	RADIUS_INTEGER4,		"Ascend Modem Port No"},
  {121,	RADIUS_INTEGER4,		"Ascend Modem Slot No"},
  {187,	RADIUS_INTEGER4,		"Ascend Multilink ID"},
  {188,	RADIUS_INTEGER4,		"Ascend Num In Multilink"},
  {189,	RADIUS_IP_ADDRESS,		"Ascend First Dest"},
  {190,	RADIUS_INTEGER4,		"Ascend Pre Input Octets"},
  {191,	RADIUS_INTEGER4,		"Ascend Pre Output Octets"},
  {192,	RADIUS_INTEGER4,		"Ascend Pre Input Packets"},
  {193,	RADIUS_INTEGER4,		"Ascend Pre Output Packets"},
  {194,	RADIUS_INTEGER4,		"Ascend Maximum Time"},
  {195,	RADIUS_INTEGER4,		"Ascend Disconnect Cause"},
  {196,	RADIUS_INTEGER4,		"Ascend Connect Progress"},
  {197,	RADIUS_INTEGER4,		"Ascend Data Rate"},
  {198,	RADIUS_INTEGER4,		"Ascend PreSession Time"},
  {218,	RADIUS_INTEGER4,		"Ascend Assign IP Pool"},
  {255,	RADIUS_INTEGER4,		"Ascend Xmit Rate"},
  {0, 0, NULL}
};

static value_string radius_service_type_vals[] =
{
  {1,	"Login"},
  {2,	"Framed"},
  {3,	"Callback Login"},
  {4,	"Callback Framed"},
  {5,	"Outbound"},
  {6,	"Administrative"},
  {7,	"NAS Prompt"},
  {8,	"Authenticate Only"},
  {9,	"Callback NAS Prompt"},
  {10,	"Call Check"},
  {0, NULL}
};

static value_string radius_framed_protocol_vals[] =
{
  {1,	"PPP"},
  {2,	"SLIP"},
  {3,	"Appletalk Remote Access Protocol (ARAP)"},
  {4,	"Gandalf proprietary Singlelink/Multilink Protocol"},
  {5,	"Xylogics proprietary IPX/SLIP"},
  {6,	"X.75 Synchronous"},
  {255,	"Ascend ARA"},
  {256,	"Ascend MPP"},
  {257,	"Ascend EURAW"},
  {258,	"Ascend EUUI"},
  {259,	"Ascend X25"},
  {260,	"Ascend COMB"},
  {261,	"Ascend FR"},
  {262,	"Ascend MP"},
  {263,	"Ascend FR-CIR"},
  {264,	"Ascend ATM-1483"},
  {265,	"Ascend ATM-FR-CIR"},
  {0, NULL}
};

static value_string radius_framed_routing_vals[] =
{
  {1,	"Send Routing Packets"},
  {2,	"Listen for routing packets"},
  {3,	"Send and Listen"},
  {0,	"None"},
  {0, NULL}
};

static value_string radius_framed_compression_vals[] =
{
  {1,	"VJ TCP/IP Header Compression"},
  {2,	"IPX Header Compression"},
  {3,	"Stac-LZS compression"},
  {0,	"None"},
  {0, NULL}
};

static value_string radius_login_service_vals[] =
{
  {1,	"Rlogin"},
  {2,	"TCP Clear"},
  {3,	"Portmaster"},
  {4,	"LAT"},
  {5,	"X.25-PAD"},
  {6,	"X.25T3POS"},
  {8,	"TCP Clear Quit"},
  {0,	"Telnet"},
  {0, NULL}
};

static value_string radius_terminating_action_vals[] =
{
  {1,	"RADIUS-Request"},
  {0,	"Default"},
  {0, NULL}
};

static value_string radius_accounting_status_type_vals[] =
{
  {1,	"Start"},
  {2,	"Stop"},
  {3,	"Interim-Update"},
  {7,	"Accounting-On"},
  {8,	"Accounting-Off"},
  {9,	"Tunnel-Start"},	/* Tunnel accounting */
  {10,	"Tunnel-Stop"},		/* Tunnel accounting */
  {11,	"Tunnel-Reject"},	/* Tunnel accounting */
  {12,	"Tunnel-Link-Start"},	/* Tunnel accounting */
  {13,	"Tunnel-Link-Stop"},	/* Tunnel accounting */
  {14,	"Tunnel-Link-Reject"},	/* Tunnel accounting */
  {0, NULL}
};

static value_string radius_accounting_authentication_vals[] =
{
  {1,	"Radius"},
  {2,	"Local"},
  {3,	"Remote"},
  /* RFC 2866 says 3 is Remote. Is 7 a mistake? */
  {7,	"Remote"},
  {0, NULL}
};

static value_string radius_acct_terminate_cause_vals[] =
{
  {1,	"User Request"},
  {2,	"Lost Carrier"},
  {3,	"Lost Service"},
  {4,	"Idle Timeout"},
  {5,	"Session Timeout"},
  {6,	"Admin Reset"},
  {7,	"Admin Reboot"},
  {8,	"Port Error"},
  {9,	"NAS Error"},
  {10,	"NAS Request"},
  {11,	"NAS Reboot"},
  {12,	"Port Unneeded"},
  {13,	"Port Preempted"},
  {14,	"Port Suspended"},
  {15,	"Service Unavailable"},
  {16,	"Callback"},
  {17,	"User Error"},
  {18,	"Host Request"},
  {0, NULL}
};

static value_string radius_tunnel_type_vals[] =
{
  {1,	"PPTP"},
  {2,	"L2F"},
  {3,	"L2TP"},
  {4,	"ATMP"},
  {5,	"VTP"},
  {6,	"AH"},
  {7,	"IP-IP-Encap"},
  {8,	"MIN-IP-IP"},
  {9,	"ESP"},
  {10,	"GRE"},
  {11,	"DVS"},
  {12,	"IP-IP"},
  {0, NULL}
};

static value_string radius_tunnel_medium_type_vals[] =
{
  {1,	"IPv4"}, 
  {2,	"IPv6"},
  {3,	"NSAP"},
  {4,	"HDLC"},
  {5,	"BBN"},
  {6,	"IEEE-802"},
  {7,	"E-163"},
  {8,	"E-164"},
  {9,	"F-69"},
  {10,	"X-121"},
  {11,	"IPX"},
  {12,	"Appletalk"},
  {13,	"Decnet4"},
  {14,	"Vines"},
  {15,	"E-164-NSAP"},
  {0, NULL}
};

static value_string radius_nas_port_type_vals[] =
{
  {0,	"Async"},
  {1,	"Sync"},
  {2,	"ISDN Sync"},
  {3,	"ISDN Async V.120"},
  {4,	"ISDN Async V.110"},
  {5,	"Virtual"},
  {6,	"PIAFS"},
  {7,	"HDLC Clear Channel"},
  {8,	"X.25"},
  {9,	"X.75"},
  {10,	"G.3 Fax"},
  {11,	"SDSL"},
  {12,	"ADSL-CAP"},
  {13,	"ADSL-DMT"},
  {14,	"IDSL - ISDN"},
  {15,	"Ethernet"},
  {16,	"xDSL"},
  {17,	"Cable"},
  {18,	"Wireless Other"},
  {19,	"Wireless IEEE 802.11"},
  {0, NULL}
};

/*
references:
	'dictionary.cisco' file from FreeRADIUS 
		http://www.freeradius.org
		radiusd/raddb/dictionary.cisco

	http://www.cisco.com/univercd/cc/td/doc/product/access/acs_serv/vapp_dev/vsaig3.htm

	http://www.cisco.com/univercd/cc/td/doc/product/software/ios122/122cgcr/fsecur_c/fappendx/fradattr/scfrdat3.pdf
	http://www.missl.cs.umd.edu/wireless/ethereal/cisco-vsa.pdf

*/

static value_value_string radius_vendor_cisco_attrib[] =
{
	/* stanard sttributes */
  {1,	RADIUS_STRING,		"Cisco AV Pair"},
  {2,	RADIUS_STRING,		"Cisco NAS Port"},
	/* fax */
  {3,	RADIUS_STRING,		"Fax Account Id Origin"},
  {4,	RADIUS_STRING,		"Fax Msg Id"},
  {5,	RADIUS_STRING,		"Fax Pages"},
  {6,	RADIUS_STRING,		"Fax Cover Page Flag"},
  {7,	RADIUS_STRING,		"Fax Modem Time"},
  {8,	RADIUS_STRING,		"Fax Connect Speed"},
  {9,	RADIUS_STRING,		"Fax Recipent Count"},
  {10,	RADIUS_STRING,		"Fax Process Abort Flag"},
  {11,	RADIUS_STRING,		"Fax DSN Address"},
  {12,	RADIUS_STRING,		"Fax DSN Flag"},
  {13,	RADIUS_STRING,		"Fax MDN Address"},
  {14,	RADIUS_STRING,		"Fax MDN Flag"},
  {15,	RADIUS_STRING,		"Fax Auth Status"},
  {16,	RADIUS_STRING,		"Email Server Address"},
  {17,	RADIUS_STRING,		"Email Server Ack Flag"},
  {18,	RADIUS_STRING,		"Gateway Id"},
  {19,	RADIUS_STRING,		"Call Type"},
  {20,	RADIUS_STRING,		"Port Used"},
  {21,	RADIUS_STRING,		"Abort Cause"},
	/* #22 */
	/* H323 - Voice over IP attributes. */
  {23,	RADIUS_STRING,		"H323 Remote Address"},
  {24,	RADIUS_STRING,		"H323 Conf Id"},
  {25,	RADIUS_STRING,		"H323 Setup Time"},
  {26,	RADIUS_STRING,		"H323 Call Origin"},
  {27,	RADIUS_STRING,		"H323 Call Type"},
  {28,	RADIUS_STRING,		"H323 Connect Time"},
  {29,	RADIUS_STRING,		"H323 Disconnect Time"},
  {30,	RADIUS_STRING,		"H323 Disconnect Cause"},
  {31,	RADIUS_STRING,		"H323 Voice Quality"},
	/* #32 */
  {33,	RADIUS_STRING,		"H323 GW Id"},
	/* #34 */
  {35,	RADIUS_STRING,		"H323 Incoming Conf Id"},
	/* #36-#100 */
  {101,	RADIUS_STRING,		"H323 Credit Amount"},
  {102,	RADIUS_STRING,		"H323 Credit Time"},
  {103,	RADIUS_STRING,		"H323 Return Code"},
  {104,	RADIUS_STRING,		"H323 Prompt Id"},
  {105,	RADIUS_STRING,		"H323 Time And Day"},
  {106,	RADIUS_STRING,		"H323 Redirect Number"},
  {107,	RADIUS_STRING,		"H323 Preferred Lang"},
  {108,	RADIUS_STRING,		"H323 Redirect Ip Address"},
  {109,	RADIUS_STRING,		"H323 Billing Model"},
  {110,	RADIUS_STRING,		"H323 Currency Type"},
	/* #111-#186 */
/*
       Extra attributes sent by the Cisco, if you configure
       "radius-server vsa accounting" (requires IOS11.2+).
*/
  {187,	RADIUS_INTEGER4,	"Cisco Multilink ID"},
  {188,	RADIUS_INTEGER4,	"Cisco Num In Multilink"},
	/* #189 */ 
  {190,	RADIUS_INTEGER4,	"Cisco Pre Input Octets"},
  {191,	RADIUS_INTEGER4,	"Cisco Pre Output Octets"},
  {192,	RADIUS_INTEGER4,	"Cisco Pre Input Packets"},
  {193,	RADIUS_INTEGER4,	"Cisco Pre Output Packets"},
  {194,	RADIUS_INTEGER4,	"Cisco Maximum Time"},
  {195,	CISCO_DISCONNECT_CAUSE,	"Cisco Disconnect Cause"},
	/* #196 */ 
  {197,	RADIUS_INTEGER4,	"Cisco Data Rate"},
  {198,	RADIUS_INTEGER4,	"Cisco PreSession Time"},
	/* #199-#207 */ 
  {208,	RADIUS_INTEGER4,	"Cisco PW Lifetime"},
  {209,	RADIUS_INTEGER4,	"Cisco IP Direct"},
  {210,	RADIUS_INTEGER4,	"Cisco PPP VJ Slot Comp"},
	/* #211 */ 
  {212,	RADIUS_INTEGER4,	"Cisco PPP Async Map"},
	/* #213-#216 */ 
  {217,	RADIUS_INTEGER4,	"Cisco IP Pool Definition"},
  {218,	RADIUS_INTEGER4,	"Cisco Asing IP Pool"},
	/* #219-#227 */ 
  {228,	RADIUS_INTEGER4,	"Cisco Route IP"},
	/* #229-#232 */ 
  {233,	RADIUS_INTEGER4,	"Cisco Link Compression"},
  {234,	RADIUS_INTEGER4,	"Cisco Target Util"},
  {235,	RADIUS_INTEGER4,	"Cisco Maximum Channels"},
	/* #236-#241 */ 
  {242,	RADIUS_INTEGER4,	"Cisco Data Filter"},
  {243,	RADIUS_INTEGER4,	"Cisco Call Filter"},
  {244,	RADIUS_INTEGER4,	"Cisco Idle Limit"},
  {255,	RADIUS_INTEGER4,	"Cisco Xmit Rate"},
  {0, 0, NULL}
};

static value_string radius_vendor_cisco_disconnect_cause_vals[] =
{
  {2,	"Unknown"},
  {4,	"CLID-Authentication-Failure"},
  {10,	"No-Carrier"},
  {11,	"Lost-Carrier"},
  {12,	"No-Detected-Result-Codes"},
  {20,	"User-Ends-Session"},
  {21,	"Idle-Timeout"},
  {22,	"Exit-Telnet-Session"},
  {23,	"No-Remote-IP-Addr"},
  {24,	"Exit-Raw-TCP"},
  {25,	"Password-Fail"},
  {26,	"Raw-TCP-Disabled"},
  {27,	"Control-C-Detected"},
  {28,	"EXEC-Program-Destroyed"},
  {40,	"Timeout-PPP-LCP"},
  {41,	"Failed-PPP-LCP-Negotiation"},
  {42,	"Failed-PPP-PAP-Auth-Fail"},
  {43,	"Failed-PPP-CHAP-Auth"},
  {44,	"Failed-PPP-Remote-Auth"},
  {45,	"PPP-Remote-Terminate"},
  {46,	"PPP-Closed-Event"},
  {100,	"Session-Timeout"},
  {101,	"Session-Failed-Security"},
  {102,	"Session-End-Callback"},
  {120,	"Invalid-Protocol"},
  {0, NULL}
};

static value_value_string radius_vendor_microsoft_attrib[] =
{
  {1,	RADIUS_BINSTRING,		"MS CHAP Response"},
  {2,	RADIUS_STRING,			"MS CHAP Error"},
  {3,	RADIUS_BINSTRING,		"MS CHAP CPW 1"},
  {4,	RADIUS_BINSTRING,		"MS CHAP CPW 2"},
  {5,	RADIUS_BINSTRING,		"MS CHAP LM Enc PW"},
  {6,	RADIUS_BINSTRING,		"MS CHAP NT Enc PW"},
  {7,	RADIUS_BINSTRING,		"MS MPPE Encryption Policy"},
  {8,	RADIUS_BINSTRING,		"MS MPPE Encryption Type"},
  {9,	RADIUS_INTEGER4,		"MS RAS Vendor"},
  {10,	RADIUS_STRING,			"MS CHAP Domain"},
  {11,	RADIUS_BINSTRING,		"MS CHAP Challenge"},
  {12,	RADIUS_BINSTRING,		"MS CHAP MPPE Keys"},
  {13,	MICROSOFT_BAP_USAGE,		"MS BAP Usage"},
  {14,	RADIUS_INTEGER4,		"MS Link Utilization Threshold"},
  {15,	RADIUS_INTEGER4,		"MS Link Drop Time Limit"},
  {16,	RADIUS_BINSTRING,		"MS MPPE Send Key"},
  {17,	RADIUS_BINSTRING,		"MS MPPE Recv Key"},
  {18,	RADIUS_STRING,			"MS RAS Version"},
  {19,	RADIUS_BINSTRING,		"MS Old ARAP Password"},
  {20,	RADIUS_BINSTRING,		"MS New ARAP Password"},
  {21,	MICROSOFT_ARAP_PW_CHANGE_REASON,"MS ARAP PW Change Reason"},
  {22,	RADIUS_BINSTRING,		"MS Filter"},
  {23,	MICROSOFT_ACCT_AUTH_TYPE,	"MS Acct Auth Type"},
  {24,	MICROSOFT_ACCT_EAP_TYPE,	"MS Acct EAP Type"},
  {25,	RADIUS_BINSTRING,		"MS CHAP2 Response"},
  {26,	RADIUS_BINSTRING,		"MS CHAP2 Success"},
  {27,	RADIUS_BINSTRING,		"MS CHAP2 CPW"},
  {28,	RADIUS_IP_ADDRESS,		"MS Primary DNS Server"},
  {29,	RADIUS_IP_ADDRESS,		"MS Secondary DNS Server"},
  {30,	RADIUS_IP_ADDRESS,		"MS Primary NBNS Server"},
  {31,	RADIUS_IP_ADDRESS,		"MS Secondary NBNS Server"},
  {0, 0, NULL}
};

static value_string radius_vendor_microsoft_bap_usage_vals[] =
{
  {0,	"Not-Allowed"},
  {1,	"Allowed"},
  {2,	"Required"},
  {0, NULL}
};

static value_string radius_vendor_microsoft_arap_pw_change_reason_vals[] =
{
  {1,	"Just-Change-Password"},
  {2,	"Expired-Password"},
  {3,	"Admin-Required-Password-Change"},
  {4,	"Password-Too-Short"},
  {0, NULL}
};

static value_string radius_vendor_microsoft_acct_auth_type_vals[] =
{
  {1,	"PAP"},
  {2,	"CHAP"},
  {3,	"MS-CHAP-1"},
  {4,	"MS-CHAP-2"},
  {5,	"EAP"},
  {0, NULL}
};

static value_string radius_vendor_microsoft_acct_eap_type_vals[] =
{
  {4,	"MD5"},
  {5,	"OTP"},
  {6,	"Generic-Token-Card"},
  {13,	"TLS"},
  {0, NULL}
};

static value_value_string radius_vendor_ascend_attrib[] =
{
  {7,	RADIUS_STRING,		"Ascend UU Info"},
  {9,	RADIUS_INTEGER4,	"Ascend CIR Timer"},
  {10,	RADIUS_INTEGER4,	"Ascend FR 08 Mode"},
  {11,	RADIUS_INTEGER4,	"Ascend Destination Nas Port"},
  {12,	RADIUS_STRING,		"Ascend FR SVC Addr"},
  {13,	RADIUS_INTEGER4,	"Ascend NAS Port Format"},
  {14,	RADIUS_INTEGER4,	"Ascend ATM Fault Management"},
  {15,	RADIUS_INTEGER4,	"Ascend ATM Loopback Cell Loss"},
  {16,	RADIUS_INTEGER4,	"Ascend Ckt Type"},
  {17,	RADIUS_INTEGER4,	"Ascend SVC Enabled"},
  {18,	RADIUS_INTEGER4,	"Ascend Session Type"},
  {19,	RADIUS_IP_ADDRESS,	"Ascend H323 Gatekeeper"},
  {20,	RADIUS_STRING,		"Ascend Global Call Id"},
  {21,	RADIUS_INTEGER4,	"Ascend H323 Conference Id"},
  {22,	RADIUS_IP_ADDRESS,	"Ascend H323 Fegw Address"},
  {23,	RADIUS_INTEGER4,	"Ascend H323 Dialed Time"},
  {24,	RADIUS_STRING,		"Ascend Dialed Number"},
  {25,	RADIUS_INTEGER4,	"Ascend Inter Arrival Jitter"},
  {26,	RADIUS_INTEGER4,	"Ascend Dropped Octets"},
  {27,	RADIUS_INTEGER4,	"Ascend Dropped Packets"},
  {29,	RADIUS_INTEGER4,	"Ascend X25 Pad X3 Profile"},
  {30,	RADIUS_STRING,		"Ascend X25 Pad X3 Parameters"},
  {31,	RADIUS_STRING,		"Ascend Tunnel VRouter Name"},
  {32,	RADIUS_INTEGER4,	"Ascend X25 Reverse Charging"},
  {33,	RADIUS_STRING,		"Ascend X25 Nui Prompt"},
  {34,	RADIUS_STRING,		"Ascend X25 Nui Password Prompt"},
  {35,	RADIUS_STRING,		"Ascend X25 Cug"},
  {36,	RADIUS_STRING,		"Ascend X25 Pad Alias 1"},
  {37,	RADIUS_STRING,		"Ascend X25 Pad Alias 2"},
  {38,	RADIUS_STRING,		"Ascend X25 Pad Alias 3"},
  {39,	RADIUS_STRING,		"Ascend X25 X121 Address"},
  {40,	RADIUS_STRING,		"Ascend X25 Nui"},
  {41,	RADIUS_STRING,		"Ascend X25 Rpoa"},
  {42,	RADIUS_STRING,		"Ascend X25 Pad Prompt"},
  {43,	RADIUS_STRING,		"Ascend X25 Pad Banner"},
  {44,	RADIUS_STRING,		"Ascend X25 Profile Name"},
  {45,	RADIUS_STRING,		"Ascend Recv Name"},
  {46,	RADIUS_INTEGER4,	"Ascend Bi Directional Auth"},
  {47,	RADIUS_INTEGER4,	"Ascend MTU"},
  {48,	RADIUS_INTEGER4,	"Ascend Call Direction"},
  {49,	RADIUS_INTEGER4,	"Ascend Service Type"},
  {50,	RADIUS_INTEGER4,	"Ascend Filter Required"},
  {51,	RADIUS_INTEGER4,	"Ascend Traffic Shaper"},
  {52,	RADIUS_STRING,		"Ascend Access Intercept LEA"},
  {53,	RADIUS_STRING,		"Ascend Access Intercept Log"},
  {54,	RADIUS_STRING,		"Ascend Private Route Table ID"},
  {55,	RADIUS_INTEGER4,	"Ascend Private Route Required"},
  {56,	RADIUS_INTEGER4,	"Ascend Cache Refresh"},
  {57,	RADIUS_INTEGER4,	"Ascend Cache Time"},
  {58,	RADIUS_INTEGER4,	"Ascend Egress Enabled"},
  {59,	RADIUS_STRING,		"Ascend QOS Upstream"},
  {60,	RADIUS_STRING,		"Ascend QOS Downstream"},
  {61,	RADIUS_INTEGER4,	"Ascend ATM Connect Vpi"},
  {62,	RADIUS_INTEGER4,	"Ascend ATM Connect Vci"},
  {63,	RADIUS_INTEGER4,	"Ascend ATM Connect Group"},
  {64,	RADIUS_INTEGER4,	"Ascend ATM Group"},
  {65,	RADIUS_INTEGER4,	"Ascend IPX Header Compression"},
  {66,	ASCEND_CALLING_ID_TYPE_OF_NUMBER,	"Ascend Calling Id Type Of Number"},
  {67,	ASCEND_CALLING_ID_NUMBERING_PLAN,	"Ascend Calling Id Numbering Plan"},
  {68,	ASCEND_CALLING_ID_PRESENTATION,		"Ascend Calling Id Presentation"},
  {69,	ASCEND_CALLING_ID_SCREENING,		"Ascend Calling Id Screening"},
  {70,	RADIUS_INTEGER4,	"Ascend BIR Enable"},
  {71,	RADIUS_INTEGER4,	"Ascend BIR Proxy"},
  {72,	RADIUS_INTEGER4,	"Ascend BIR Bridge Group"},
  {73,	RADIUS_STRING,		"Ascend IPSEC Profile"},
  {74,	RADIUS_INTEGER4,	"Ascend PPPoE Enable"},
  {75,	RADIUS_INTEGER4,	"Ascend Bridge Non PPPoE"},
  {76,	RADIUS_INTEGER4,	"Ascend ATM Direct"},
  {77,	RADIUS_STRING,		"Ascend ATM Direct Profile"},
  {78,	RADIUS_IP_ADDRESS,	"Ascend Client Primary WINS"},
  {79,	RADIUS_IP_ADDRESS,	"Ascend Client Secondary WINS"},
  {80,	RADIUS_INTEGER4,	"Ascend Client Assign WINS"},
  {81,	RADIUS_INTEGER4,	"Ascend Auth Type"},
  {82,	RADIUS_INTEGER4,	"Ascend Port Redir Protocol"},
  {83,	RADIUS_INTEGER4,	"Ascend Port Redir Portnum"},
  {84,	RADIUS_IP_ADDRESS,	"Ascend Port Redir Server"},
  {85,	RADIUS_INTEGER4,	"Ascend IP Pool Chaining"},
  {86,	RADIUS_IP_ADDRESS,	"Ascend Owner IP Addr"},
  {87,	RADIUS_INTEGER4,	"Ascend IP TOS"},
  {88,	RADIUS_INTEGER4,	"Ascend IP TOS Precedence"},
  {89,	RADIUS_INTEGER4,	"Ascend IP TOS Apply To"},
  {90,	RADIUS_STRING,		"Ascend Filter"},
  {91,	RADIUS_STRING,		"Ascend Telnet Profile"},
  {92,	RADIUS_INTEGER4,	"Ascend Dsl Rate Type"},
  {93,	RADIUS_STRING,		"Ascend Redirect Number"},
  {94,	RADIUS_INTEGER4,	"Ascend ATM Vpi"},
  {95,	RADIUS_INTEGER4,	"Ascend ATM Vci"},
  {96,	RADIUS_INTEGER4,	"Ascend Source IP Check"},
  {97,	RADIUS_INTEGER4,	"Ascend Dsl Rate Mode"},
  {98,	RADIUS_INTEGER4,	"Ascend Dsl Upstream Limit"},
  {99,	RADIUS_INTEGER4,	"Ascend Dsl Downstream Limit"},
  {100,	RADIUS_INTEGER4,	"Ascend Dsl CIR Recv Limit"},
  {101,	RADIUS_INTEGER4,	"Ascend Dsl CIR Xmit Limit"},
  {102,	RADIUS_STRING,		"Ascend VRouter Name"},
  {103,	RADIUS_STRING,		"Ascend Source Auth"},
  {104,	RADIUS_STRING,		"Ascend Private Route"},
  {105,	RADIUS_INTEGER4,	"Ascend Numbering Plan ID"},
  {106,	RADIUS_INTEGER4,	"Ascend FR Link Status DLCI"},
  {107,	RADIUS_STRING,		"Ascend Calling Subaddress"},
  {108,	RADIUS_INTEGER4,	"Ascend Callback Delay"},
  {109,	RADIUS_STRING,		"Ascend Endpoint Disc"},
  {110,	RADIUS_STRING,		"Ascend Remote FW"},
  {111,	RADIUS_INTEGER4,	"Ascend Multicast GLeave Delay"},
  {112,	RADIUS_INTEGER4,	"Ascend CBCP Enable"},
  {113,	RADIUS_INTEGER4,	"Ascend CBCP Mode"},
  {114,	RADIUS_INTEGER4,	"Ascend CBCP Delay"},
  {115,	RADIUS_INTEGER4,	"Ascend CBCP Trunk Group"},
  {116,	RADIUS_STRING,		"Ascend Appletalk Route"},
  {117,	RADIUS_INTEGER4,	"Ascend Appletalk Peer Mode"},
  {118,	RADIUS_INTEGER4,	"Ascend Route Appletalk"},
  {119,	RADIUS_STRING,		"Ascend FCP Parameter"},
  {120,	RADIUS_INTEGER4,	"Ascend Modem Port No"},
  {121,	RADIUS_INTEGER4,	"Ascend Modem Slot No"},
  {122,	RADIUS_INTEGER4,	"Ascend Modem Shelf No"},
  {123,	RADIUS_INTEGER4,	"Ascend Call Attempt Limit"},
  {124,	RADIUS_INTEGER4,	"Ascend Call Block Duration"},
  {125,	RADIUS_INTEGER4,	"Ascend Maximum Call Duration"},
  {126,	RADIUS_INTEGER4,	"Ascend Temporary Rtes"},
  {127,	RADIUS_INTEGER4,	"Ascend Tunneling Protocol"},
  {128,	RADIUS_INTEGER4,	"Ascend Shared Profile Enable"},
  {129,	RADIUS_STRING,		"Ascend Primary Home Agent"},
  {130,	RADIUS_STRING,		"Ascend Secondary Home Agent"},
  {131,	RADIUS_INTEGER4,	"Ascend Dialout Allowed"},
  {132,	RADIUS_IP_ADDRESS,	"Ascend Client Gateway"},
  {133,	RADIUS_INTEGER4,	"Ascend BACP Enable"},
  {134,	RADIUS_INTEGER4,	"Ascend DHCP Maximum Leases"},
  {135,	RADIUS_IP_ADDRESS,	"Ascend Client Primary DNS"},
  {136,	RADIUS_IP_ADDRESS,	"Ascend Client Secondary DNS"},
  {137,	RADIUS_INTEGER4,	"Ascend Client Assign DNS"},
  {138,	RADIUS_INTEGER4,	"Ascend User Acct Type"},
  {139,	RADIUS_IP_ADDRESS,	"Ascend User Acct Host"},
  {140,	RADIUS_INTEGER4,	"Ascend User Acct Port"},
  {141,	RADIUS_STRING,		"Ascend User Acct Key"},
  {142,	RADIUS_INTEGER4,	"Ascend User Acct Base"},
  {143,	RADIUS_INTEGER4,	"Ascend User Acct Time"},
  {144,	RADIUS_IP_ADDRESS,	"Ascend Assign IP Client"},
  {145,	RADIUS_IP_ADDRESS,	"Ascend Assign IP Server"},
  {146,	RADIUS_STRING,		"Ascend Assign IP Global Pool"},
  {147,	RADIUS_INTEGER4,	"Ascend DHCP Reply"},
  {148,	RADIUS_INTEGER4,	"Ascend DHCP Pool Number"},
  {149,	RADIUS_INTEGER4,	"Ascend Expect Callback"},
  {150,	RADIUS_INTEGER4,	"Ascend Event Type"},
  {151,	RADIUS_STRING,		"Ascend Session Svr Key"},
  {152,	RADIUS_INTEGER4,	"Ascend Multicast Rate Limit"},
  {153,	RADIUS_IP_ADDRESS,	"Ascend IF Netmask"},
  {154,	RADIUS_IP_ADDRESS,	"Ascend Remote Addr"},
  {155,	RADIUS_INTEGER4,	"Ascend Multicast Client"},
  {156,	RADIUS_STRING,		"Ascend FR Circuit Name"},
  {157,	RADIUS_INTEGER4,	"Ascend FR LinkUp"},
  {158,	RADIUS_INTEGER4,	"Ascend FR Nailed Grp"},
  {159,	RADIUS_INTEGER4,	"Ascend FR Type"},
  {160,	RADIUS_INTEGER4,	"Ascend FR Link Mgt"},
  {161,	RADIUS_INTEGER4,	"Ascend FR N391"},
  {162,	RADIUS_INTEGER4,	"Ascend FR DCE N392"},
  {163,	RADIUS_INTEGER4,	"Ascend FR DTE N392"},
  {164,	RADIUS_INTEGER4,	"Ascend FR DCE N393"},
  {165,	RADIUS_INTEGER4,	"Ascend FR DTE N393"},
  {166,	RADIUS_INTEGER4,	"Ascend FR T391"},
  {167,	RADIUS_INTEGER4,	"Ascend FR T392"},
  {168,	RADIUS_STRING,		"Ascend Bridge Address"},
  {169,	RADIUS_INTEGER4,	"Ascend TS Idle Limit"},
  {170,	RADIUS_INTEGER4,	"Ascend TS Idle Mode"},
  {171,	RADIUS_INTEGER4,	"Ascend DBA Monitor"},
  {172,	RADIUS_INTEGER4,	"Ascend Base Channel Count"},
  {173,	RADIUS_INTEGER4,	"Ascend Minimum Channels"},
  {174,	RADIUS_STRING,		"Ascend IPX Route"},
  {175,	RADIUS_INTEGER4,	"Ascend FT1 Caller"},
  {176,	RADIUS_STRING,		"Ascend Backup"},
  {177,	RADIUS_INTEGER4,	"Ascend Call Type"},
  {178,	RADIUS_STRING,		"Ascend Group"},
  {179,	RADIUS_INTEGER4,	"Ascend FR DLCI"},
  {180,	RADIUS_STRING,		"Ascend FR Profile Name"},
  {181,	RADIUS_STRING,		"Ascend Ara PW"},
  {182,	RADIUS_STRING,		"Ascend IPX Node Addr"},
  {183,	RADIUS_IP_ADDRESS,	"Ascend Home Agent IP Addr"},
  {184,	RADIUS_STRING,		"Ascend Home Agent Password"},
  {185,	RADIUS_STRING,		"Ascend Home Network Name"},
  {186,	RADIUS_INTEGER4,	"Ascend Home Agent UDP Port"},
  {187,	RADIUS_INTEGER4,	"Ascend Multilink ID"},
  {188,	RADIUS_INTEGER4,	"Ascend Num In Multilink"},
  {189,	RADIUS_IP_ADDRESS,	"Ascend First Dest"},
  {190,	RADIUS_INTEGER4,	"Ascend Pre Input Octets"},
  {191,	RADIUS_INTEGER4,	"Ascend Pre Output Octets"},
  {192,	RADIUS_INTEGER4,	"Ascend Pre Input Packets"},
  {193,	RADIUS_INTEGER4,	"Ascend Pre Output Packets"},
  {194,	RADIUS_INTEGER4,	"Ascend Maximum Time"},
  {195,	RADIUS_INTEGER4,	"Ascend Disconnect Cause"},
  {196,	RADIUS_INTEGER4,	"Ascend Connect Progress"},
  {197,	RADIUS_INTEGER4,	"Ascend Data Rate"},
  {198,	RADIUS_INTEGER4,	"Ascend PreSession Time"},
  {199,	RADIUS_INTEGER4,	"Ascend Token Idle"},
  {200,	RADIUS_INTEGER4,	"Ascend Token Immediate"},
  {201,	RADIUS_INTEGER4,	"Ascend Require Auth"},
  {202,	RADIUS_STRING,		"Ascend Number Sessions"},
  {203,	RADIUS_STRING,		"Ascend Authen Alias"},
  {204,	RADIUS_INTEGER4,	"Ascend Token Expiry"},
  {205,	RADIUS_STRING,		"Ascend Menu Selector"},
  {206,	RADIUS_STRING,		"Ascend Menu Item"},
  {207,	RADIUS_INTEGER4,	"Ascend PW Warntime"},
  {208,	RADIUS_INTEGER4,	"Ascend PW Lifetime"},
  {209,	RADIUS_IP_ADDRESS,	"Ascend IP Direct"},
  {210,	RADIUS_INTEGER4,	"Ascend PPP VJ Slot Comp"},
  {211,	RADIUS_INTEGER4,	"Ascend PPP VJ 1172"},
  {212,	RADIUS_INTEGER4,	"Ascend PPP Async Map"},
  {213,	RADIUS_STRING,		"Ascend Third Prompt"},
  {214,	RADIUS_STRING,		"Ascend Send Secret"},
  {215,	RADIUS_STRING,		"Ascend Receive Secret"},
  {216,	RADIUS_INTEGER4,	"Ascend IPX Peer Mode"},
  {217,	RADIUS_STRING,		"Ascend IP Pool Definition"},
  {218,	RADIUS_INTEGER4,	"Ascend Assign IP Pool"},
  {219,	RADIUS_INTEGER4,	"Ascend FR Direct"},
  {220,	RADIUS_STRING,		"Ascend FR Direct Profile"},
  {221,	RADIUS_INTEGER4,	"Ascend FR Direct DLCI"},
  {222,	RADIUS_INTEGER4,	"Ascend Handle IPX"},
  {223,	RADIUS_INTEGER4,	"Ascend Netware timeout"},
  {224,	RADIUS_INTEGER4,	"Ascend IPX Alias"},
  {225,	RADIUS_INTEGER4,	"Ascend Metric"},
  {226,	RADIUS_INTEGER4,	"Ascend PRI Number Type"},
  {227,	RADIUS_STRING,		"Ascend Dial Number"},
  {228,	RADIUS_INTEGER4,	"Ascend Route IP"},
  {229,	RADIUS_INTEGER4,	"Ascend Route IPX"},
  {230,	RADIUS_INTEGER4,	"Ascend Bridge"},
  {231,	RADIUS_INTEGER4,	"Ascend Send Auth"},
  {232,	RADIUS_STRING,		"Ascend Send Passwd"},
  {233,	RADIUS_INTEGER4,	"Ascend Link Compression"},
  {234,	RADIUS_INTEGER4,	"Ascend Target Util"},
  {235,	RADIUS_INTEGER4,	"Ascend Maximum Channels"},
  {236,	RADIUS_INTEGER4,	"Ascend Inc Channel Count"},
  {237,	RADIUS_INTEGER4,	"Ascend Dec Channel Count"},
  {238,	RADIUS_INTEGER4,	"Ascend Seconds Of History"},
  {239,	RADIUS_INTEGER4,	"Ascend History Weigh Type"},
  {240,	RADIUS_INTEGER4,	"Ascend Add Seconds"},
  {241,	RADIUS_INTEGER4,	"Ascend Remove Seconds"},
  {242,	RADIUS_BINSTRING,	"Ascend Data Filter"},
  {243,	RADIUS_BINSTRING,	"Ascend Call Filter"},
  {244,	RADIUS_INTEGER4,	"Ascend Idle Limit"},
  {245,	RADIUS_INTEGER4,	"Ascend Preempt Limit"},
  {246,	RADIUS_INTEGER4,	"Ascend Callback"},
  {247,	RADIUS_INTEGER4,	"Ascend Data Svc"},
  {248,	RADIUS_INTEGER4,	"Ascend Force 56"},
  {249,	RADIUS_STRING,		"Ascend Billing Number"},
  {250,	RADIUS_INTEGER4,	"Ascend Call By Call"},
  {251,	RADIUS_STRING,		"Ascend Transit Number"},
  {252,	RADIUS_STRING,		"Ascend Host Info"},
  {253,	RADIUS_IP_ADDRESS,	"Ascend PPP Address"},
  {254,	RADIUS_INTEGER4,	"Ascend MPP Idle Percent"},
  {255,	RADIUS_INTEGER4,	"Ascend Xmit Rate"},
  {0, 0, NULL}
};

static value_string radius_vendor_ascend_calling_id_type_of_number_vals[] =
{
  {0,	"Unknown"},
  {1,	"International Number"},
  {2,	"National Number"},
  {3,	"Network Specific"},
  {4,	"Subscriber Number"},
  {6,	"Abbreviated Number"},
  {0, NULL}
};

static value_string radius_vendor_ascend_calling_id_numbering_plan_vals[] =
{
  {0,	"Unknown"},
  {1,	"ISDN Telephony"},
  {3,	"Data"},
  {4,	"Telex"},
  {8,	"National"},
  {9,	"Private"},
  {0, NULL}
};

static value_string radius_vendor_ascend_calling_id_presentation_vals[] =
{
  {0,	"Allowed"},
  {1,	"Restricted"},
  {2,	"Number Not Available"},
  {0, NULL}
};

static value_string radius_vendor_ascend_calling_id_screening_vals[] =
{
  {0,	"User Not Screened"},
  {1,	"User Provided Passed"},
  {2,	"User Provided Failed"},
  {3,	"Network Provided"},
  {0, NULL}
};

static value_value_string radius_vendor_cosine_attrib[] =
{
  {1,	RADIUS_STRING,		"Connection Profile Name"},
  {2,	RADIUS_STRING,		"Enterprise ID"},
  {3,	RADIUS_STRING,		"Address Pool Name"},
  {4,	RADIUS_INTEGER4,	"DS Byte"},
  {5,	COSINE_VPI_VCI,		"VPI/VCI"},
  {6,	RADIUS_INTEGER4,	"DLCI"},
  {7,	RADIUS_IP_ADDRESS,	"LNS IP Address"},
  {8,	RADIUS_STRING,		"CLI User Permission ID"},
  {0, 0, NULL}
};

static value_value_string radius_vendor_issanni_attrib[] =
{
  {1,	RADIUS_STRING,		"Softflow Template"},
  {2,	RADIUS_STRING,		"NAT Pool"},
  {3,	RADIUS_STRING,		"Virtual Routing Domain"},
  {4,	RADIUS_STRING,		"Tunnel Name"},
  {5,	RADIUS_STRING,		"IP Pool Name"},
  {6,	RADIUS_STRING,		"PPPoE URL"},
  {7,	RADIUS_STRING,		"PPPoE MOTM"},
  {8,	RADIUS_STRING,		"PPPoE Service"},
  {9,	RADIUS_IP_ADDRESS,	"Primary DNS"},
  {10,	RADIUS_IP_ADDRESS,	"Secondary DNS"},
  {11,	RADIUS_IP_ADDRESS,	"Primary NBNS"},
  {12,	RADIUS_IP_ADDRESS,	"Secondary NBNS"},
  {13,	RADIUS_STRING,		"Policing Traffic Class"},
  {14,	RADIUS_INTEGER4,	"Tunnel Type"},
  {15,	RADIUS_INTEGER4,	"NAT Type"},
  {16,	RADIUS_STRING,		"QoS Traffic Class"},
  {17,	RADIUS_STRING,		"Interface Name"},
  {0, 0, NULL}
};

static rd_vsa_table radius_vsa_table[] =
{
  {VENDOR_CISCO,	radius_vendor_cisco_attrib},
  {VENDOR_MICROSOFT,	radius_vendor_microsoft_attrib},
  {VENDOR_ASCEND,	radius_vendor_ascend_attrib},
  {VENDOR_COSINE,	radius_vendor_cosine_attrib},
  {VENDOR_ISSANNI,	radius_vendor_issanni_attrib},
  {0, NULL},
};

/*
 * XXX - should these be read from files, such as FreeRadius dictionary
 * files?  For example, its "dictionary" file has entries such as
 *
 *	VALUE           Service-Type            Login-User              1
 *
 * to handle translation of integral values to strings.
 */
static rd_valstr_table valstr_table[] =
{
  {RADIUS_SERVICE_TYPE,			radius_service_type_vals},
  {RADIUS_FRAMED_PROTOCOL,		radius_framed_protocol_vals},
  {RADIUS_FRAMED_ROUTING,		radius_framed_routing_vals},
  {RADIUS_FRAMED_COMPRESSION,		radius_framed_compression_vals},
  {RADIUS_LOGIN_SERVICE,		radius_login_service_vals},
  {RADIUS_TERMINATING_ACTION,		radius_terminating_action_vals},
  {RADIUS_ACCOUNTING_STATUS_TYPE,	radius_accounting_status_type_vals},
  {RADIUS_ACCT_AUTHENTIC,		radius_accounting_authentication_vals},
  {RADIUS_ACCT_TERMINATE_CAUSE,		radius_acct_terminate_cause_vals},
  {RADIUS_NAS_PORT_TYPE,		radius_nas_port_type_vals},
  {CISCO_DISCONNECT_CAUSE,		radius_vendor_cisco_disconnect_cause_vals},
  {MICROSOFT_BAP_USAGE,			radius_vendor_microsoft_bap_usage_vals},
  {MICROSOFT_ARAP_PW_CHANGE_REASON,	radius_vendor_microsoft_arap_pw_change_reason_vals},
  {MICROSOFT_ACCT_AUTH_TYPE,		radius_vendor_microsoft_acct_auth_type_vals},
  {MICROSOFT_ACCT_EAP_TYPE,		radius_vendor_microsoft_acct_eap_type_vals},
  {ASCEND_CALLING_ID_TYPE_OF_NUMBER,	radius_vendor_ascend_calling_id_type_of_number_vals},
  {ASCEND_CALLING_ID_NUMBERING_PLAN,	radius_vendor_ascend_calling_id_numbering_plan_vals},
  {ASCEND_CALLING_ID_PRESENTATION,	radius_vendor_ascend_calling_id_presentation_vals},
  {ASCEND_CALLING_ID_SCREENING,		radius_vendor_ascend_calling_id_screening_vals},
  {0, NULL}
};

static rd_vsa_table *get_vsa_table(guint32 vendor)
{
    guint32 i;

    for (i = 0; radius_vsa_table[i].vendor; i++)
	if (radius_vsa_table[i].vendor == vendor)
	    return(&radius_vsa_table[i]);

    return(NULL);
}

static guint32 match_numval(guint32 val, const value_value_string *vvs)
{
  guint32 i = 0;

  while (vvs[i].val1) {
    if (vvs[i].val1 == val)
      return(vvs[i].val2);
    i++;
  }

  return(0);
}

static gchar textbuffer[TEXTBUFFER];
static rd_vsa_buffer vsabuffer[VSABUFFER];

static void
rdconvertbufftostr(gchar *dest, tvbuff_t *tvb, int offset, int length)
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
                        sprintf(&(dest[totlen]), "\\%03o", pd[i]);
                        totlen=totlen+strlen(&(dest[totlen]));
                }
        }
        dest[totlen]='"';
        dest[totlen+1]=0;
}

static void
rdconvertbufftobinstr(gchar *dest, tvbuff_t *tvb, int offset, int length)
{
/*converts the raw buffer into printable text */
	guint32 i;
	guint32 totlen=0;
	const guint8 *pd = tvb_get_ptr(tvb, offset, length);
	static const char hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
				      '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };


        for (i=0; i < (guint32)length; i++)
        {
		dest[totlen] = hex[pd[i] >> 4];
		totlen++;
		dest[totlen] = hex[pd[i] & 0xF];
		totlen++;
        }
        dest[totlen]='\0';
}

static gchar *rd_match_strval(guint32 val, const value_string *vs) {
	return val_to_str(val, vs, "Undefined(%u)");
}

static gchar *rd_match_strval_attrib(guint32 val, const value_value_string *vvs)
{
    guint32 i;

    for (i = 0; vvs[i].val1; i++)
	if (vvs[i].val1 == val)
	    return(vvs[i].str);

    return("Unknown Type");
}
    
static gchar *rdconvertinttostr(gchar *dest, int print_type, guint32 val)
{
    guint32 i;
    value_string *vs = null_vals;

    for (i = 0; valstr_table[i].print_type; i++)
    {
	if (valstr_table[i].print_type == print_type)
	{
	    vs = valstr_table[i].valstr;
	    break;
	}
    }
    sprintf(dest, "%s(%u)", val_to_str(val, vs, "Undefined"), val);

    return dest;

}

static gchar *rd_value_to_str_2(gchar *dest, e_avphdr *avph, tvbuff_t *tvb,
				int offset, const value_value_string *vvs)
{
  int print_type;
  gchar *cont;
  value_string *valstrarr;
  guint32 intval;
  const guint8 *pd;
  guint8 tag;
  char *rtimestamp;
  extern char *tzname[2];

  int vsa_attrlen;
  int vsa_len;
  int vsa_index;
  rd_vsa_table *vsa_rvt;
  e_avphdr *vsa_avph;

/* prints the values of the attribute value pairs into a text buffer */
  print_type = match_numval(avph->avp_type, vvs);

  /* Default begin */
  strcpy(dest, "Value:");
  cont=&dest[strlen(dest)];
  switch(print_type)
  {
        case( RADIUS_STRING ):
		rdconvertbufftostr(cont,tvb,offset+2,avph->avp_length-2);
                break;
        case( RADIUS_BINSTRING ):
		rdconvertbufftobinstr(cont,tvb,offset+2,avph->avp_length-2);
                break;
        case( RADIUS_INTEGER4 ):
                sprintf(cont,"%u", tvb_get_ntohl(tvb,offset+2));
                break;
        case( RADIUS_IP_ADDRESS ):
                ip_to_str_buf(tvb_get_ptr(tvb,offset+2,4),cont);
                break;
        case( RADIUS_IPX_ADDRESS ):
                pd = tvb_get_ptr(tvb,offset+2,4);
                sprintf(cont,"%u:%u:%u:%u",(guint8)pd[offset+2],
                        (guint8)pd[offset+3],(guint8)pd[offset+4],
                        (guint8)pd[offset+5]);
	case( RADIUS_TUNNEL_TYPE ):
		valstrarr=radius_tunnel_type_vals;
		/* Tagged ? */
		intval = tvb_get_ntohl(tvb,offset+2);
		if (intval >> 24) {
			sprintf(dest, "Tag:%u, Value:%s",
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
			sprintf(dest, "Tag:%u, Value:%s",
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
			sprintf(dest, "Tag:%u, Value:",
					tag);
			cont=&cont[strlen(cont)];	
			rdconvertbufftostr(cont,tvb,offset+3,avph->avp_length-3);
			break;
		}
		rdconvertbufftostr(cont,tvb,offset+2,avph->avp_length-2);
                break;
	case ( RADIUS_VENDOR_SPECIFIC ):
		vsa_index = 1;
		valstrarr = radius_vendor_specific_vendors;
		sprintf(dest,"Vendor:%s",
			rd_match_strval(tvb_get_ntohl(tvb,offset+2),valstrarr));
		cont = &dest[strlen(dest)];
		vsa_rvt = get_vsa_table(tvb_get_ntohl(tvb,offset+2));
		    vsa_attrlen = avph->avp_length;
		    vsa_len = 6;
		do
		{
		    vsa_avph = (e_avphdr*)tvb_get_ptr(tvb, offset+vsa_len, avph->avp_length-vsa_len);
		    cont = &cont[strlen(cont)+1];
		    vsabuffer[vsa_index].str = cont;
			vsabuffer[vsa_index].offset = offset+vsa_len;
			vsabuffer[vsa_index].length = vsa_avph->avp_length;
		    sprintf(cont, "t:%s(%u) l:%u, ",
			    rd_match_strval_attrib(vsa_avph->avp_type,
						   (vsa_rvt ? vsa_rvt->attrib : null_attrib)),
			    vsa_avph->avp_type, vsa_avph->avp_length);
		    cont = &cont[strlen(cont)];
		    rd_value_to_str_2(cont,vsa_avph, tvb, offset+vsa_len,
				      (vsa_rvt ? vsa_rvt->attrib : null_attrib));
		    vsa_len += vsa_avph->avp_length;
			vsa_index++;
		    } while (vsa_attrlen > vsa_len && vsa_index < VSABUFFER);
		break;
        case( RADIUS_SERVICE_TYPE ):
        case( RADIUS_FRAMED_PROTOCOL ):
        case( RADIUS_FRAMED_ROUTING ):
        case( RADIUS_FRAMED_COMPRESSION ):
        case( RADIUS_LOGIN_SERVICE ):
        case( RADIUS_TERMINATING_ACTION ):
        case( RADIUS_ACCOUNTING_STATUS_TYPE ):
        case( RADIUS_ACCT_AUTHENTIC ):
        case( RADIUS_ACCT_TERMINATE_CAUSE ):
        case( RADIUS_NAS_PORT_TYPE ):
	case( ASCEND_CALLING_ID_TYPE_OF_NUMBER ):
	case( ASCEND_CALLING_ID_NUMBERING_PLAN ):
	case( ASCEND_CALLING_ID_PRESENTATION ):
	case( ASCEND_CALLING_ID_SCREENING ):
		rdconvertinttostr(cont, print_type,tvb_get_ntohl(tvb,offset+2));
		break;
	case( COSINE_VPI_VCI ):
		sprintf(cont,"%u/%u",
			tvb_get_ntohs(tvb,offset+2),
			tvb_get_ntohs(tvb,offset+4));
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
			sprintf(cont, "Tag:%u, Value:%u",
				intval >> 24,
				intval & 0xffffff);
			break;
		}
		sprintf(cont,"%u", intval);
		break;
        case( RADIUS_UNKNOWN ):
        default:
                strcpy(cont,"Unknown Value Type");
                break;
  }
  cont=&cont[strlen(cont)];
  if (cont == dest) {
  	strcpy(cont,"Unknown Value");
  }
  return dest;
}

static gchar *rd_value_to_str(e_avphdr *avph, tvbuff_t *tvb, int offset)
{
    int i;
    for (i = 0; i < VSABUFFER; i++)
	vsabuffer[i].str = 0;
    vsabuffer[0].str = textbuffer;
    rd_value_to_str_2(textbuffer, avph, tvb, offset, radius_attrib);
    return textbuffer;
}

static void
dissect_attribute_value_pairs(tvbuff_t *tvb, int offset,proto_tree *tree,
				   int avplength,packet_info *pinfo)
{
/* adds the attribute value pairs to the tree */
  e_avphdr avph;
  gchar *avptpstrval;
  gchar *valstr;
  guint8 *reassembled_data = NULL;
  int reassembled_data_len = 0;
  int data_needed = 0;
  int i;

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
    avptpstrval = rd_match_strval_attrib(avph.avp_type, radius_attrib);
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

    if (avph.avp_type == 79) {	/* RD_TP_EAP_MESSAGE */
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
        proto_item *ti;
        proto_tree *vsa_tree = NULL;
        valstr = rd_value_to_str(&avph, tvb, offset);
        ti = proto_tree_add_text(tree, tvb, offset, avph.avp_length,
			    "t:%s(%u) l:%u, %s",
			    avptpstrval, avph.avp_type, avph.avp_length,
			    valstr);
        vsa_tree = proto_item_add_subtree(ti, ett_radius_vsa);
	for (i = 1; vsabuffer[i].str && i < VSABUFFER; i++)
	    proto_tree_add_text(vsa_tree, tvb, vsabuffer[i].offset, vsabuffer[i].length,
				"%s", vsabuffer[i].str);
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
		&ett_radius_vsa,
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
