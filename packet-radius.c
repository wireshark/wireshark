/* packet-radius.c
 *
 * Routines for RADIUS packet disassembly
 * Copyright 1999 Johan Feyaerts
 *
 * RFC 2865, RFC 2866, RFC 2867, RFC 2868, RFC 2869
 *
 * $Id: packet-radius.c,v 1.71 2002/12/17 22:14:54 oabad Exp $
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <glib.h>
#include <time.h>
#include <epan/packet.h>
#include <epan/resolv.h>

#include "packet-q931.h"
#include "packet-gtp.h"
#include "prefs.h"
#include "crypt-md5.h"

static int proto_radius = -1;
static int hf_radius_length = -1;
static int hf_radius_code = -1;
static int hf_radius_id =-1;
static char *shared_secret = NULL;
static gpointer authenticator = NULL;

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
	const value_string *valstr;
} rd_valstr_table;

typedef struct _rd_vsa_buffer {
	gchar *str;
	int offset;
	guint8 length;
} rd_vsa_buffer;

#define AUTHENTICATOR_LENGTH	16
#define RD_HDR_LENGTH		4

#define RADIUS_ACCESS_REQUEST			1
#define RADIUS_ACCESS_ACCEPT			2
#define RADIUS_ACCESS_REJECT			3
#define RADIUS_ACCOUNTING_REQUEST		4
#define RADIUS_ACCOUNTING_RESPONSE		5
#define RADIUS_ACCESS_PASSWORD_REQUEST		7
#define RADIUS_ACCESS_PASSWORD_ACK		8
#define RADIUS_ACCESS_PASSWORD_REJECT		9
#define RADIUS_ACCESS_CHALLENGE			11
#define RADIUS_STATUS_SERVER			12
#define RADIUS_STATUS_CLIENT			13
#define RADIUS_VENDOR_SPECIFIC_CODE		26
#define RADIUS_ASCEND_ACCESS_NEXT_CODE		29
#define RADIUS_ASCEND_ACCESS_NEW_PIN		30
#define RADIUS_ASCEND_PASSWORD_EXPIRED		32
#define RADIUS_ASCEND_ACCESS_EVENT_REQUEST	33
#define RADIUS_ASCEND_ACCESS_EVENT_RESPONSE	34
#define RADIUS_DISCONNECT_REQUEST		40
#define RADIUS_DISCONNECT_REQUEST_ACK		41
#define RADIUS_DISCONNECT_REQUEST_NAK		42
#define RADIUS_CHANGE_FILTER_REQUEST		43
#define RADIUS_CHANGE_FILTER_REQUEST_ACK	44
#define RADIUS_CHANGE_FILTER_REQUEST_NAK	45
#define RADIUS_RESERVED				255

enum {
    RADIUS_STRING = 1,
    RADIUS_BINSTRING,
    RADIUS_INTEGER4,
    RADIUS_IP_ADDRESS,
    RADIUS_SERVICE_TYPE,
    RADIUS_FRAMED_PROTOCOL,
    RADIUS_FRAMED_ROUTING,
    RADIUS_FRAMED_COMPRESSION,
    RADIUS_LOGIN_SERVICE,
    RADIUS_UNKNOWN,
    RADIUS_IPX_ADDRESS,
    RADIUS_TERMINATING_ACTION,
    RADIUS_ACCOUNTING_STATUS_TYPE,
    RADIUS_ACCT_AUTHENTIC,
    RADIUS_ACCT_TERMINATE_CAUSE,
    RADIUS_NAS_PORT_TYPE,
    RADIUS_TUNNEL_TYPE,
    RADIUS_TUNNEL_MEDIUM_TYPE,
    RADIUS_STRING_TAGGED,
    RADIUS_VENDOR_SPECIFIC,
    RADIUS_TIMESTAMP,
    RADIUS_INTEGER4_TAGGED,

    ACC_REASON_CODE,
    ACC_CCP_OPTION,
    ACC_ROUTE_POLICY,
    ACC_ML_MLX_ADMIN_STATE,
    ACC_CLEARING_CAUSE,
    ACC_CLEARING_LOCATION,
    ACC_REQUEST_TYPE,
    ACC_BRIDGING_SUPPORT,
    ACC_APSM_OVERSUBSCRIBED,
    ACC_ACCT_ON_OFF_REASON,
    ACC_IP_COMPRESSION,
    ACC_IPX_COMPRESSION,
    ACC_CALLBACK_MODE,
    ACC_CALLBACK_CBCP_TYPE,
    ACC_DIALOUT_AUTH_MODE,
    ACC_ACCESS_COMMUNITY,

    CISCO_DISCONNECT_CAUSE,

    SHIVA_TYPE_OF_SERVICE,
    SHIVA_LINK_PROTOCOL,
    SHIVA_DISCONNECT_REASON,
    SHIVA_FUNCTION,
    SHIVA_CONNECT_REASON,

    LIVINGSTON_IPSEC_LOG_OPTIONS,
    LIVINGSTON_IPSEC_DENY_ACTION,
    LIVINGSTON_NAT_LOG_OPTIONS,
    LIVINGSTON_NAT_SESS_DIR_FAIL_ACTION,
    LIVINGSTON_MULTICAST_CLIENT,

    MICROSOFT_BAP_USAGE,
    MICROSOFT_ARAP_PW_CHANGE_REASON,
    MICROSOFT_ACCT_AUTH_TYPE,
    MICROSOFT_ACCT_EAP_TYPE,

    ASCEND_CALLING_ID_TYPE_OF_NUMBER,
    ASCEND_CALLING_ID_NUMBERING_PLAN,
    ASCEND_CALLING_ID_PRESENTATION,
    ASCEND_CALLING_ID_SCREENING,

    BAY_TUNNEL_AUTHEN_TYPE,
    BAY_TUNNEL_AUTHEN_MODE,
    BAY_USER_SERVER_LOCATION,
    BAY_SYSTEM_DISC_REASON,
    BAY_MODEM_DISC_REASON,
    BAY_ADDR_RESOLUTION_PROTOCOL,
    BAY_USER_LEVEL,
    BAY_AUDIT_LEVEL,

    VERSANET_TERMINATION_CAUSE,

    REDBACK_TUNNEL_FUNCTION,
    REDBACK_MCAST_SEND,
    REDBACK_MCAST_RECEIVE,
    REDBACK_TUNNEL_DNIS,
    REDBACK_PVC_ENCAPSULATION_TYPE,
    REDBACK_PVC_CIRCUIT_PADDING,
    REDBACK_BIND_TYPE,
    REDBACK_BIND_AUTH_PROTOCOL,
    REDBACK_LAC_PORT_TYPE,
    REDBACK_LAC_REAL_PORT_TYPE,

    COSINE_VPI_VCI,

    SHASTA_USER_PRIVILEGE,

    COLUMBIA_UNIVERSITY_SIP_METHOD,

    THE3GPP_QOS
};

static value_string radius_vals[] =
{
  {RADIUS_ACCESS_REQUEST,		"Access Request"},
  {RADIUS_ACCESS_ACCEPT,		"Access Accept"},
  {RADIUS_ACCESS_REJECT,		"Access Reject"},
  {RADIUS_ACCOUNTING_REQUEST,		"Accounting Request"},
  {RADIUS_ACCOUNTING_RESPONSE,		"Accounting Response"},
  {RADIUS_ACCESS_PASSWORD_REQUEST,	"Access Password Request"},
  {RADIUS_ACCESS_PASSWORD_ACK,		"Access Password Ack"},
  {RADIUS_ACCESS_PASSWORD_REJECT,	"Access Password Reject"},
  {RADIUS_ACCESS_CHALLENGE,		"Access challenge"},
  {RADIUS_STATUS_SERVER,		"StatusServer"},
  {RADIUS_STATUS_CLIENT,		"StatusClient"},
  {RADIUS_VENDOR_SPECIFIC_CODE,		"Vendor Specific"},
  {RADIUS_ASCEND_ACCESS_NEXT_CODE,	"Ascend Access Next Code"},
  {RADIUS_ASCEND_ACCESS_NEW_PIN,	"Ascend Access New Pin"},
  {RADIUS_ASCEND_PASSWORD_EXPIRED,	"Ascend Password Expired"},
  {RADIUS_ASCEND_ACCESS_EVENT_REQUEST,	"Ascend Access Event Request"},
  {RADIUS_ASCEND_ACCESS_EVENT_RESPONSE,	"Ascend Access Event Response"},
  {RADIUS_DISCONNECT_REQUEST,		"Disconnect Request"},
  {RADIUS_DISCONNECT_REQUEST_ACK,	"Disconnect Request ACK"},
  {RADIUS_DISCONNECT_REQUEST_NAK,	"Disconnect Request NAK"},
  {RADIUS_CHANGE_FILTER_REQUEST,	"Change Filter Request"},
  {RADIUS_CHANGE_FILTER_REQUEST_ACK,	"Change Filter Request ACK"},
  {RADIUS_CHANGE_FILTER_REQUEST_NAK,	"Change Filter Request NAK"},
  {RADIUS_RESERVED,			"Reserved"},
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
#define VENDOR_ACC			5
#define VENDOR_CISCO			9
#define VENDOR_SHIVA			166
#define VENDOR_LIVINGSTON		307
#define VENDOR_MICROSOFT		311
#define VENDOR_3COM			429
#define VENDOR_ASCEND			529
#define VENDOR_BAY			1584
#define VENDOR_FOUNDRY			1991
#define VENDOR_VERSANET			2180
#define VENDOR_REDBACK			2352
#define VENDOR_JUNIPER			2636
#define VENDOR_APTIS			2637
#define VENDOR_COSINE			3085
#define VENDOR_SHASTA			3199
#define VENDOR_NOMADIX			3309
#define VENDOR_UNISPHERE		4874
#define VENDOR_ISSANNI			5948
#define VENDOR_QUINTUM			6618
#define VENDOR_COLUBRIS			8744
#define VENDOR_COLUMBIA_UNIVERSITY	11862
#define VENDOR_THE3GPP			10415

static value_string radius_vendor_specific_vendors[] =
{
  {VENDOR_ACC,			"ACC"},
  {VENDOR_CISCO,		"Cisco"},
  {VENDOR_SHIVA,		"Shiva"},
  {VENDOR_MICROSOFT,		"Microsoft"},
  {VENDOR_LIVINGSTON,		"Livingston"},
  {VENDOR_3COM,			"3Com"},
  {VENDOR_ASCEND,		"Ascend"},
  {VENDOR_BAY,			"Bay Networks"},
  {VENDOR_FOUNDRY,		"Foundry"},
  {VENDOR_VERSANET,		"Versanet"},
  {VENDOR_REDBACK,		"Redback"},
  {VENDOR_JUNIPER,		"Juniper Networks"},
  {VENDOR_APTIS,		"Aptis"},
  {VENDOR_COSINE,		"CoSine Communications"},
  {VENDOR_SHASTA,		"Shasta"},
  {VENDOR_NOMADIX,		"Nomadix"},
  {VENDOR_UNISPHERE,		"Unisphere Networks"},
  {VENDOR_ISSANNI,		"Issanni Communications"},
  {VENDOR_QUINTUM,		"Quintum"},
  {VENDOR_COLUBRIS,		"Colubris"},
  {VENDOR_COLUMBIA_UNIVERSITY,	"Columbia University"},
  {VENDOR_THE3GPP,		"3GPP"},
  {0, NULL}
};

/*
 * XXX - should we construct this table in Ethereal at start-up time by
 * reading files such as FreeRadius dictionary files?  For example,
 * the FreeRadius "dictionary" file has
 *
 *	ATTRIBUTE       User-Name               1       string
 *
 * for the attribute that's
 *
 *	{1,	RADIUS_STRING,			"User Name"},
 *
 * In our tables:
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
  {3,	RADIUS_BINSTRING,		"CHAP Password"},
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
  {37,	RADIUS_INTEGER4,		"Framed AppleTalk Link"},
  {38,	RADIUS_INTEGER4,		"Framed AppleTalk Network"},
  {39,	RADIUS_STRING,			"Framed AppleTalk Zone"},
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
  {60,	RADIUS_BINSTRING,		"CHAP Challenge"},
  {61,	RADIUS_NAS_PORT_TYPE,		"NAS Port Type"},
  {62,	RADIUS_INTEGER4,		"Port Limit"},
  {63,	RADIUS_BINSTRING,		"Login LAT Port"},
  {64,	RADIUS_TUNNEL_TYPE,		"Tunnel Type"},
  {65,	RADIUS_TUNNEL_MEDIUM_TYPE,	"Tunnel Medium Type"},
  {66,	RADIUS_STRING_TAGGED,		"Tunnel Client Endpoint"},
  {67,	RADIUS_STRING_TAGGED,		"Tunnel Server Endpoint"},
  {68,	RADIUS_STRING,			"Tunnel Connection"},
  {69,	RADIUS_STRING_TAGGED,		"Tunnel Password"},
  {70,	RADIUS_STRING,			"ARAP Password"},
  {71,	RADIUS_STRING,			"ARAP Features"},
  {72,	RADIUS_INTEGER4,		"ARAP Zone-Access"},
  {73,	RADIUS_INTEGER4,		"ARAP Security"},
  {74,	RADIUS_STRING,			"ARAP Security Data"},
  {75,	RADIUS_INTEGER4,		"Password Retry"},
  {76,	RADIUS_INTEGER4,		"Prompt"},
  {77,	RADIUS_STRING,			"Connect Info"},
  {78,	RADIUS_STRING,			"Configuration Token"},
  {79,	RADIUS_STRING,			"EAP Message"},
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
  {5,	"X.25 PAD"},
  {6,	"X.25 T3POS"},
  {8,	"TCP Clear Quit"},
  {0,	"Telnet"},
  {0, NULL}
};

static value_string radius_terminating_action_vals[] =
{
  {1,	"RADIUS Request"},
  {0,	"Default"},
  {0, NULL}
};

static value_string radius_accounting_status_type_vals[] =
{
  {1,	"Start"},
  {2,	"Stop"},
  {3,	"Interim Update"},
  {7,	"Accounting On"},
  {8,	"Accounting Off"},
  {9,	"Tunnel Start"},	/* Tunnel accounting */
  {10,	"Tunnel Stop"},		/* Tunnel accounting */
  {11,	"Tunnel Reject"},	/* Tunnel accounting */
  {12,	"Tunnel Link Start"},	/* Tunnel accounting */
  {13,	"Tunnel Link Stop"},	/* Tunnel accounting */
  {14,	"Tunnel Link Reject"},	/* Tunnel accounting */
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
  {6,	"IEEE 802"},
  {7,	"E.163"},
  {8,	"E.164"},
  {9,	"F.69"},
  {10,	"X.121"},
  {11,	"IPX"},
  {12,	"Appletalk"},
  {13,	"Decnet4"},
  {14,	"Vines"},
  {15,	"E.164 NSAP"},
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
  {12,	"ADSL CAP"},
  {13,	"ADSL DMT"},
  {14,	"IDSL ISDN"},
  {15,	"Ethernet"},
  {16,	"xDSL"},
  {17,	"Cable"},
  {18,	"Wireless Other"},
  {19,	"Wireless IEEE 802.11"},
  {0, NULL}
};

/*
reference:
	'dictionary.acc' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.acc
*/
static value_value_string radius_vendor_acc_attrib[] =
{
  {1,	ACC_REASON_CODE,	"Acc Reason Code"},
  {2,	ACC_CCP_OPTION,		"Acc Ccp Option"},
  {3,	RADIUS_INTEGER4,	"Acc Input Errors"},
  {4,	RADIUS_INTEGER4,	"Acc Output Errors"},
  {5,	RADIUS_STRING,		"Acc Access Partition"},
  {6,	RADIUS_STRING,		"Acc Customer Id"},
  {7,	RADIUS_IP_ADDRESS,	"Acc Ip Gateway Pri"},
  {8,	RADIUS_IP_ADDRESS,	"Acc Ip Gateway Sec"},
  {9,	ACC_ROUTE_POLICY,	"Acc Route Policy"},
  {10,	ACC_ML_MLX_ADMIN_STATE,	"Acc ML MLX Admin State"},
  {11,	RADIUS_INTEGER4,	"Acc ML Call Threshold"},
  {12,	RADIUS_INTEGER4,	"Acc ML Clear Threshold"},
  {13,	RADIUS_INTEGER4,	"Acc ML Damping Factor"},
  {14,	RADIUS_STRING,		"Acc Tunnel Secret"},
  {15,	ACC_CLEARING_CAUSE,	"Acc Clearing Cause"},
  {16,	ACC_CLEARING_LOCATION,	"Acc Clearing Location"},
  {17,	RADIUS_STRING,		"Acc Service Profile"},
  {18,	ACC_REQUEST_TYPE,	"Acc Request Type"},
  {19,	ACC_BRIDGING_SUPPORT,	"Acc Bridging Support"},
  {20,	ACC_APSM_OVERSUBSCRIBED,"Acc Apsm Oversubscribed"},
  {21,	ACC_ACCT_ON_OFF_REASON,	"Acc Acct On Off Reason"},
  {22,	RADIUS_INTEGER4,	"Acc Tunnel Port"},
  {23,	RADIUS_IP_ADDRESS,	"Acc Dns Server Pri"},
  {24,	RADIUS_IP_ADDRESS,	"Acc Dns Server Sec"},
  {25,	RADIUS_IP_ADDRESS,	"Acc Nbns Server Pri"},
  {26,	RADIUS_IP_ADDRESS,	"Acc Nbns Server Sec"},
  {27,	RADIUS_INTEGER4,	"Acc Dial Port Index"},
  {28,	ACC_IP_COMPRESSION,	"Acc Ip Compression"},
  {29,	ACC_IPX_COMPRESSION,	"Acc Ipx Compression"},
  {30,	RADIUS_INTEGER4,	"Acc Connect Tx Speed"},
  {31,	RADIUS_INTEGER4,	"Acc Connect Rx Speed"},
  {32,	RADIUS_STRING,		"Acc Modem Modulation Type"},
  {33,	RADIUS_STRING,		"Acc Modem Error Protocol"},
  {34,	RADIUS_INTEGER4,	"Acc Callback Delay"},
  {35,	RADIUS_STRING,		"Acc Callback Num Valid"},
  {36,	ACC_CALLBACK_MODE,	"Acc Callback Mode"},
  {37,	ACC_CALLBACK_CBCP_TYPE,	"Acc Callback CBCP Type"},
  {38,	ACC_DIALOUT_AUTH_MODE,	"Acc Dialout Auth Mode"},
  {39,	RADIUS_STRING,		"Acc Dialout Auth Password"},
  {40,	RADIUS_STRING,		"Acc Dialout Auth Username"},
  {42,	ACC_ACCESS_COMMUNITY,	"Acc Access Community"},
  {0, 0, NULL},
};

static value_string radius_vendor_acc_reason_code_vals[] =
{
  {0,	"No reason No Failure"},
  {1,	"Resource shortage"},
  {2,	"Session already open"},
  {3,	"Too many RADIUS users"},
  {4,	"No authentification server"},
  {5,	"No authentification response"},
  {6,	"No accounting server"},
  {7,	"No accounting response"},
  {8,	"Access Denied"},
  {9,	"Temporary buffer shortage"},
  {10,	"Protocol error"},
  {11,	"Invalid attribute"},
  {12,	"Invalid service type"},
  {13,	"Invalid framed protocol"},
  {14,	"Invalid attribute value"},
  {15,	"Invalid user information"},
  {16,	"Invalid IP address"},
  {17,	"Invalid integer syntax"},
  {18,	"Invalid NAS port"},
  {19,	"Requested by user"},
  {20,	"Network disconnect"},
  {21,	"Service interruption"},
  {22,	"Physical port error"},
  {23,	"Idle timeout"},
  {24,	"Session timeout"},
  {25,	"Administrative reset"},
  {26,	"NAS reload or reset"},
  {27,	"NAS error"},
  {28,	"NAS request"},
  {29,	"Undefined reason given"},
  {30,	"Conflicting attributes"},
  {31,	"Port limit exceeded"},
  {32,	"Facility not available"},
  {33,	"Internal config error"},
  {34,	"Bad route specification"},
  {35,	"Access Partition bind failure"},
  {36,	"Security violation"},
  {37,	"Request type conflict"},
  {38,	"Configuration disallowed"},
  {39,	"Missing attribute"},
  {40,	"Invalid request"},
  {41,	"Missing parameter"},
  {42,	"Invalid parameter"},
  {43,	"Call cleared with cause"},
  {44,	"Inopportune config request"},
  {45,	"Invalid config parameter"},
  {46,	"Missing config parameter"},
  {47,	"Incompatible service profile"},
  {48,	"Administrative reset"},
  {49,	"Administrative reload"},
  {50,	"Port unneeded"},
  {51,	"Port preempted"},
  {52,	"Port suspended"},
  {53,	"Service unavailable"},
  {54,	"Callback"},
  {55,	"User error"},
  {56,	"Host request"},
  {0, NULL}
};

static value_string radius_vendor_acc_ccp_option_vals[] =
{
  {1,	"Disabled"},
  {2,	"Enabled"},
  {0, NULL}
};

static value_string radius_vendor_acc_route_policy_vals[] =
{
  {1,	"Funnel"},
  {2,	"Direct"},
  {0, NULL}
};

static value_string radius_vendor_acc_ml_mlx_admin_state_vals[] =
{
  {1,	"Enabled"},
  {2,	"Disabled"},
  {0, NULL}
};

static value_string radius_vendor_acc_request_type_vals[] =
{
  {1,	"Ring Indication"},
  {2,	"Dial Request"},
  {3,	"User Authentification"},
  {4,	"Tunnel Authentification"},
  {0, NULL}
};

static value_string radius_vendor_acc_bridging_support_vals[] =
{
  {1,	"Disabled"},
  {2,	"Enabled"},
  {0, NULL}
};

static value_string radius_vendor_acc_apsm_oversubscribed_vals[] =
{
  {1,	"False"},
  {2,	"True"},
  {0, NULL}
};

static value_string radius_vendor_acc_acct_on_off_reason_vals[] =
{
  {0,	"NAS Reset"},
  {1,	"NAS Reload"},
  {2,	"Configuration Reset"},
  {3,	"Configuration Reload"},
  {4,	"Enabled"},
  {5,	"Disabled"},
  {0, NULL}
};

static value_string radius_vendor_acc_ip_compression_vals[] =
{
  {1,	"Disabled"},
  {2,	"Enabled"},
  {0, NULL}
};

static value_string radius_vendor_acc_ipx_compression_vals[] =
{
  {1,	"Disabled"},
  {2,	"Enabled"},
  {0, NULL}
};

static value_string radius_vendor_acc_callback_mode_vals[] =
{
  {0,	"User Auth"},
  {3,	"User Specified E.164"},
  {6,	"CBCP Callback"},
  {7,	"CLI Callback"},
  {0, NULL}
};

static value_string radius_vendor_acc_callback_cbcp_type_vals[] =
{
  {1,	"CBCP None"},
  {2,	"CBCP User Specified"},
  {3,	"CBCP Pre Specified"},
  {0, NULL}
};

static value_string radius_vendor_acc_dialout_auth_mode_vals[] =
{
  {1,	"PAP"},
  {2,	"CHAP"},
  {3,	"CHAP PAP"},
  {4,	"NONE"},
  {0, NULL}
};

static value_string radius_vendor_acc_access_community_vals[] =
{
  {1,	"PUBLIC"},
  {2,	"NETMAN"},
  {0, NULL}
};

/*
references:
	'dictionary.cisco' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.cisco

	http://www.cisco.com/univercd/cc/td/doc/product/access/acs_serv/vapp_dev/vsaig3.htm

	http://www.cisco.com/univercd/cc/td/doc/product/software/ios122/122cgcr/fsecur_c/fappendx/fradattr/scfrdat3.pdf
	http://www.missl.cs.umd.edu/wireless/ethereal/cisco-vsa.pdf

*/
static value_value_string radius_vendor_cisco_attrib[] =
{
  /* stanard attributes */
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
  {4,	"CLID Authentication Failure"},
  {10,	"No Carrier"},
  {11,	"Lost Carrier"},
  {12,	"No Detected Result Codes"},
  {20,	"User Ends Session"},
  {21,	"Idle Timeout"},
  {22,	"Exit Telnet Session"},
  {23,	"No Remote IP Addr"},
  {24,	"Exit Raw TCP"},
  {25,	"Password Fail"},
  {26,	"Raw TCP Disabled"},
  {27,	"Control C Detected"},
  {28,	"EXEC Program Destroyed"},
  {40,	"Timeout PPP LCP"},
  {41,	"Failed PPP LCP Negotiation"},
  {42,	"Failed PPP PAP Auth Fail"},
  {43,	"Failed PPP CHAP Auth"},
  {44,	"Failed PPP Remote Auth"},
  {45,	"PPP Remote Terminate"},
  {46,	"PPP Closed Event"},
  {100,	"Session Timeout"},
  {101,	"Session Failed Security"},
  {102,	"Session End Callback"},
  {120,	"Invalid Protocol"},
  {0, NULL}
};

/*
reference:
	'dictionary.shiva' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.shiva
*/
static value_value_string radius_vendor_shiva_attrib[] =
{
  {1,	RADIUS_STRING,		"Shiva User Attributes"},
  {90,	RADIUS_STRING,		"Shiva Called Number"},
  {91,	RADIUS_STRING,		"Shiva Calling Number"},
  {92,	RADIUS_STRING,		"Shiva Customer Id"},
  {93,	SHIVA_TYPE_OF_SERVICE,	"Shiva Type Of Service"},
  {94,	RADIUS_INTEGER4,	"Shiva Link Speed"},
  {95,	RADIUS_INTEGER4,	"Shiva Links In Bundle"},
  {96,	RADIUS_INTEGER4,	"Shiva Compression Type"},
  {97,	SHIVA_LINK_PROTOCOL,	"Shiva Link Protocol"},
  {98,	RADIUS_INTEGER4,	"Shiva Network Protocols"},
  {99,	RADIUS_INTEGER4,	"Shiva Session Id"},
  {100,	SHIVA_DISCONNECT_REASON,"Shiva Disconnect Reason"},
  {101,	RADIUS_IP_ADDRESS,	"Shiva Acct Serv Switch"},
  {102,	RADIUS_INTEGER4,	"Shiva Event Flags"},
  {103,	SHIVA_FUNCTION,		"Shiva Function"},
  {104,	SHIVA_CONNECT_REASON,	"Shiva Connect Reason"},
  {0, 0, NULL},
};

static value_string radius_vendor_shiva_type_of_service_vals[] =
{
  {1,	"Analog"},
  {2,	"Digitized Analog"},
  {3,	"Digital"},
  {4,	"Digital V.110"},
  {5,	"Digital V.120"},
  {6,	"Digital Leased Line"},
  {0, NULL}
};

static value_string radius_vendor_shiva_link_protocol_vals[] =
{
  {1,	"HDLC"},
  {2,	"ARAV1"},
  {3,	"ARAV2"},
  {4,	"SHELL"},
  {5,	"AALAP"},
  {6,	"SLIP"},
  {0, NULL}
};

static value_string radius_vendor_shiva_disconnect_reason_vals[] =
{
  {1,	"Remote"},
  {2,	"Error"},
  {3,	"Idle Timeout"},
  {4,	"Session Timeout"},
  {5,	"Admin Disconnect"},
  {6,	"Dialback"},
  {7,	"Virtual Connection"},
  {8,	"Bandwidth On Demand"},
  {9,	"Failed Authentication"},
  {10,	"Preempted"},
  {11,	"Blocked"},
  {12,	"Tariff Management"},
  {13,	"Backup"},
  {0, NULL}
};

static value_string radius_vendor_shiva_function_vals[] =
{
  {0,	"Unknown"},
  {1,	"Dialin"},
  {2,	"Dialout"},
  {3,	"Lan To Lan"},
  {0, NULL}
};

static value_string radius_vendor_shiva_connect_reason_vals[] =
{
  {1,	"Remote"},
  {2,	"Dialback"},
  {3,	"Virtual Connection"},
  {4,	"Bandwidth On Demand"},
  {0, NULL}
};

/*
reference:
	'dictionary.livingston' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.livingston
*/
static value_value_string radius_vendor_livingston_attrib[] =
{
  {2,	RADIUS_STRING,			"LE Terminate Detail"},
  {3,	RADIUS_STRING,			"LE Advice of Charge"},
  {4,	RADIUS_STRING,			"LE Connect Detail"},
  {6,	RADIUS_STRING,			"LE IP Pool"},
  {7,	RADIUS_IP_ADDRESS,		"LE IP Gateway"},
  {8,	RADIUS_STRING,			"LE Modem Info"},
  {9,	LIVINGSTON_IPSEC_LOG_OPTIONS,	"LE IPSec Log Options"},
  {10,	LIVINGSTON_IPSEC_DENY_ACTION,	"LE IPSec Deny Action"},
  {11,	RADIUS_STRING,			"LE IPSec Active Profile"},
  {12,	RADIUS_STRING,			"LE IPSec Outsource Profile"},
  {13,	RADIUS_STRING,			"LE IPSec Passive Profile"},
  {14,	RADIUS_INTEGER4,		"LE NAT TCP Session Timeout"},
  {15,	RADIUS_INTEGER4,		"LE NAT Other Session Timeout"},
  {16,	LIVINGSTON_NAT_LOG_OPTIONS,	"LE NAT Log Options"},
  {17,	LIVINGSTON_NAT_SESS_DIR_FAIL_ACTION,	"LE NAT Sess Dir Fail Action"},
  {18,	RADIUS_STRING,			"LE NAT Inmap"},
  {19,	RADIUS_STRING,			"LE NAT Outmap"},
  {20,	RADIUS_STRING,			"LE NAT Outsource Inmap"},
  {21,	RADIUS_STRING,			"LE NAT Outsource Outmap"},
  {22,	RADIUS_STRING,			"LE Admin Group"},
  {23,	LIVINGSTON_MULTICAST_CLIENT,	"LE Multicast Client"},
  {0, 0, NULL},
};

static value_string radius_vendor_livingston_ipsec_log_options_vals[] =
{
  {1,	"SA Success On"},
  {2,	"SA Failure On"},
  {3,	"Console On"},
  {4,	"Syslog On"},
  {5,	"SA Success Off"},
  {6,	"SA Failure Off"},
  {7,	"Console Off"},
  {8,	"Syslog Off"},
  {0, NULL}
};

static value_string radius_vendor_livingston_ipsec_deny_action_vals[] =
{
  {1,	"Drop"},
  {2,	"ICMP Reject"},
  {3,	"Pass Through"},
  {0, NULL}
};

static value_string radius_vendor_livingston_nat_log_options_vals[] =
{
  {1,	"Session Success On"},
  {2,	"Session Failure On"},
  {3,	"Console On"},
  {4,	"Syslog On"},
  {5,	"Success Off"},
  {6,	"Failure Off"},
  {7,	"Console Off"},
  {8,	"Syslog Off"},
  {0, NULL}
};

static value_string radius_vendor_livingston_nat_sess_dir_fail_action_vals[] =
{
  {1,	"Drop"},
  {2,	"ICMP Reject"},
  {3,	"Pass Through"},
  {0, NULL}
};

static value_string radius_vendor_livingston_multicast_client_vals[] =
{
  {1,	"On"},
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
  {0,	"Not Allowed"},
  {1,	"Allowed"},
  {2,	"Required"},
  {0, NULL}
};

static value_string radius_vendor_microsoft_arap_pw_change_reason_vals[] =
{
  {1,	"Just Change Password"},
  {2,	"Expired Password"},
  {3,	"Admin Required Password Change"},
  {4,	"Password Too Short"},
  {0, NULL}
};

static value_string radius_vendor_microsoft_acct_auth_type_vals[] =
{
  {1,	"PAP"},
  {2,	"CHAP"},
  {3,	"MS CHAP 1"},
  {4,	"MS CHAP 2"},
  {5,	"EAP"},
  {0, NULL}
};

static value_string radius_vendor_microsoft_acct_eap_type_vals[] =
{
  {4,	"MD5"},
  {5,	"OTP"},
  {6,	"Generic Token Card"},
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

/*
reference:
	'dictionary.bay' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.bay
*/
static value_value_string radius_vendor_bay_attrib[] =
{
  {28,	RADIUS_STRING,			"Annex Filter"},
  {29,	RADIUS_STRING,			"Annex CLI Command"},
  {30,	RADIUS_STRING,			"Annex CLI Filter"},
  {31,	RADIUS_STRING,			"Annex Host Restrict"},
  {32,	RADIUS_STRING,			"Annex Host Allow"},
  {33,	RADIUS_STRING,			"Annex Product Name"},
  {34,	RADIUS_STRING,			"Annex SW Version"},
  {35,	RADIUS_IP_ADDRESS,		"Annex Local IP Address"},
  {36,	RADIUS_INTEGER4,		"Annex Callback Portlist"},
  {37,	RADIUS_INTEGER4,		"Annex Sec Profile Index"},
  {38,	BAY_TUNNEL_AUTHEN_TYPE,		"Annex Tunnel Authen Type"},
  {39,	BAY_TUNNEL_AUTHEN_MODE,		"Annex Tunnel Authen Mode"},
  {40,	RADIUS_STRING,			"Annex Authen Servers"},
  {41,	RADIUS_STRING,			"Annex Acct Servers"},
  {42,	BAY_USER_SERVER_LOCATION,	"Annex User Server Location"},
  {43,	RADIUS_STRING,			"Annex Local Username"},
  {44,	BAY_SYSTEM_DISC_REASON,		"Annex System Disc Reason"},
  {45,	BAY_MODEM_DISC_REASON,		"Annex Modem Disc Reason"},
  {46,	RADIUS_INTEGER4,		"Annex Disconnect Reason"},
  {47,	BAY_ADDR_RESOLUTION_PROTOCOL,	"Annex Addr Resolution Protocol"},
  {48,	RADIUS_STRING,			"Annex Addr Resolution Servers"},
  {49,	RADIUS_STRING,			"Annex Domain Name"},
  {50,	RADIUS_INTEGER4,		"Annex Transmit Speed"},
  {51,	RADIUS_INTEGER4,		"Annex Receive Speed"},
  {52,	RADIUS_STRING,			"Annex Input Filter"},
  {53,	RADIUS_STRING,			"Annex Output Filter"},
  {54,	RADIUS_IP_ADDRESS,		"Annex Primary DNS Server"},
  {55,	RADIUS_IP_ADDRESS,		"Annex Secondary DNS Server"},
  {56,	RADIUS_IP_ADDRESS,		"Annex Primary NBNS Server"},
  {57,	RADIUS_IP_ADDRESS,		"Annex Secondary NBNS Server"},
  {58,	RADIUS_INTEGER4,		"Annex Syslog Tap"},
  {59,	RADIUS_INTEGER4,		"Annex Keypress Timeout"},
  {60,	RADIUS_INTEGER4,		"Annex Unauthenticated Time"},
  {61,	RADIUS_INTEGER4,		"Annex Re CHAP Timeout"},
  {62,	RADIUS_INTEGER4,		"Annex MRRU"},
  {63,	RADIUS_STRING,			"Annex EDO"},
  {64,	RADIUS_INTEGER4,		"Annex PPP Trace Level"},
  {65,	RADIUS_INTEGER4,		"Annex Pre Input Octets"},
  {66,	RADIUS_INTEGER4,		"Annex Pre Output Octets"},
  {67,	RADIUS_INTEGER4,		"Annex Pre Input Packets"},
  {68,	RADIUS_INTEGER4,		"Annex Pre Output Packets"},
  {69,	RADIUS_INTEGER4,		"Annex Connect Progress"},
  {73,	RADIUS_INTEGER4,		"Annex Multicast Rate Limit"},
  {74,	RADIUS_INTEGER4,		"Annex Maximum Call Duration"},
  {75,	RADIUS_INTEGER4,		"Annex Multilink Id"},
  {76,	RADIUS_INTEGER4,		"Annex Num In Multilink"},
  {81,	RADIUS_INTEGER4,		"Annex Logical Channel Number"},
  {82,	RADIUS_INTEGER4,		"Annex Wan Number"},
  {83,	RADIUS_INTEGER4,		"Annex Port"},
  {85,	RADIUS_INTEGER4,		"Annex Pool Id"},
  {86,	RADIUS_STRING,			"Annex Compression Protocol"},
  {87,	RADIUS_INTEGER4,		"Annex Transmitted Packets"},
  {88,	RADIUS_INTEGER4,		"Annex Retransmitted Packets"},
  {89,	RADIUS_INTEGER4,		"Annex Signal to Noise Ratio"},
  {90,	RADIUS_INTEGER4,		"Annex Retrain Requests Sent"},
  {91,	RADIUS_INTEGER4,		"Annex Retrain Requests Rcvd"},
  {92,	RADIUS_INTEGER4,		"Annex Rate Reneg Req Sent"},
  {93,	RADIUS_INTEGER4,		"Annex Rate Reneg Req Rcvd"},
  {94,	RADIUS_INTEGER4,		"Annex Begin Receive Line Level"},
  {95,	RADIUS_INTEGER4,		"Annex End Receive Line Level"},
  {96,	RADIUS_STRING,			"Annex Begin Modulation"},
  {97,	RADIUS_STRING,			"Annex Error Correction Prot"},
  {98,	RADIUS_STRING,			"Annex End Modulation"},
  {100,	BAY_USER_LEVEL,			"Annex User Level"},
  {101,	BAY_AUDIT_LEVEL,		"Annex Audit Level"},
  {0, 0, NULL},
};

static value_string radius_vendor_bay_tunnel_authen_type_vals[] =
{
  {0,	"none"},
  {1,	"kmd5 128"},
  {0, NULL}
};

static value_string radius_vendor_bay_tunnel_authen_mode_vals[] =
{
  {0,	"none"},
  {1,	"prefix suffix"},
  {0, NULL}
};

static value_string radius_vendor_bay_user_server_location_vals[] =
{
  {1,	"local"},
  {2,	"remote"},
  {0, NULL}
};

static value_string radius_vendor_bay_system_disc_reason_vals[] =
{
  {0,	"Unknown"},
  {1,	"Line disconnected"},
  {2,	"Dial failed"},
  {3,	"WAN manager error"},
  {4,	"Disconnect reset"},
  {5,	"Error from adm_notify"},
  {6,	"Modem down adm_notify"},
  {7,	"PPP protocol disconnect"},
  {8,	"Inactivity timer"},
  {9,	"CLI Hangup command"},
  {10,	"CLI last job"},
  {11,	"Session timeout"},
  {12,	"Slave termination"},
  {13,	"Abnormal termination"},
  {14,	"DCD wait failed"},
  {15,	"CLI inactivity"},
  {16,	"Admin port reset"},
  {17,	"CLI auth failed"},
  {18,	"Slave auth failed"},
  {19,	"PAP auth failed"},
  {20,	"CHAP auth failed"},
  {21,	"Local modem reset"},
  {22,	"Modem dead"},
  {23,	"PPP LCP failure"},
  {24,	"PPP IPCP failure"},
  {25,	"PPP IPXCP failure"},
  {26,	"PPP ATCP failure"},
  {27,	"PPP CCP failure"},
  {28,	"PPP MP failure"},
  {29,	"PPP IPCP timeout"},
  {30,	"PPP IPXCP timeout"},
  {31,	"PPP ATCP timeout"},
  {32,	"PPP CCP timeout"},
  {33,	"PPP MP timeout"},
  {34,	"PPP init failure"},
  {35,	"PPP Unknown"},
  {36,	"PPP Dialback failed"},
  {37,	"PPP Address In Use"},
  {38,	"PPP No device"},
  {39,	"PPP Modem hangup rcvd"},
  {40,	"PPP Hangup rcvd"},
  {41,	"PPP Termination rcvd"},
  {42,	"PPP Kill rcvd"},
  {43,	"PPP Time rcvd"},
  {44,	"PPP No memory"},
  {45,	"PPP Connection Abort"},
  {46,	"PPP VPN LCP failure"},
  {47,	"PPP VPN Auth failure"},
  {48,	"PPP MP invalid port"},
  {49,	"PPP Invalid device"},
  {50,	"PPP MMP bundle failure"},
  {51,	"DVS Registration failure"},
  {52,	"DVS Home agent dereg"},
  {53,	"DVS Tunnel no renew"},
  {54,	"DVS Tunnel expired"},
  {0, NULL}
};

static value_string radius_vendor_bay_modem_disc_reason_vals[] =
{
  {0,	"Unknown"},
  {1,	"Local disconnect"},
  {2,	"CD Timer Expired"},
  {4,	"Remote protocol disc"},
  {5,	"Clear down"},
  {6,	"Long Space disconnect"},
  {7,	"Carrier Lost"},
  {8,	"Modem Retrain Timeout"},
  {0, NULL}
};

static value_string radius_vendor_bay_addr_resolution_protocol_vals[] =
{
  {0,	"none"},
  {1,	"DHCP"},
  {0, NULL}
};

static value_string radius_vendor_bay_user_level_vals[] =
{
  {2,	"Manager"},
  {4,	"User"},
  {8,	"Operator"},
  {0, NULL}
};

static value_string radius_vendor_bay_audit_level_vals[] =
{
  {2,	"Manager"},
  {4,	"User"},
  {8,	"Operator"},
  {0, NULL}
};

/*
reference:
	'dictionary.foundry' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.foundry
*/
static value_value_string radius_vendor_foundry_attrib[] =
{
  {1,	RADIUS_INTEGER4,	"Foundry Privilege Level"},
  {2,	RADIUS_STRING,		"Foundry Command String"},
  {3,	RADIUS_INTEGER4,	"Foundry Command Exception Flag"},
  {0, 0, NULL},
};

/*
reference:
	'dictionary.versanet' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.versanet
*/
static value_value_string radius_vendor_versanet_attrib[] =
{
  {1,	VERSANET_TERMINATION_CAUSE,	"Versanet Termination Cause"},
  {0, 0, NULL},
};

static value_string radius_vendor_versanet_termination_cause_vals[] =
{
  {0,	"Normal Hangup No Error Occurred"},
  {3,	"Call Waiting Caused Disconnect"},
  {4,	"Physical Carrier Loss"},
  {5,	"No err correction at other end"},
  {6,	"No resp to feature negotiation"},
  {7,	"1st modem async only 2nd sync"},
  {8,	"No framing technique in common"},
  {9,	"No protocol in common"},
  {10,	"Bad resp to feature negotiation"},
  {11,	"No sync info from remote modem"},
  {12,	"Normal Hangup by Remote modem"},
  {13,	"Retransmission limit reached"},
  {14,	"Protocol violation occurred"},
  {15,	"Lost DTR"},
  {16,	"Received GSTN cleardown"},
  {17,	"Inactivity timeout"},
  {18,	"Speed not supported"},
  {19,	"Long space disconnect"},
  {20,	"Key abort disconnect"},
  {21,	"Clears previous disc reason"},
  {22,	"No connection established"},
  {23,	"Disconnect after three retrains"},
  {0, NULL}
};

/*
reference:
	'dictionary.redback' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.redback
*/
static value_value_string radius_vendor_redback_attrib[] =
{
  {1,	RADIUS_IP_ADDRESS,		"Client DNS Pri"},
  {2,	RADIUS_IP_ADDRESS,		"Client DNS Sec"},
  {3,	RADIUS_INTEGER4,		"DHCP Max Leases"},
  {4,	RADIUS_STRING,			"Context Name"},
  {5,	RADIUS_STRING,			"Bridge Group"},
  {6,	RADIUS_STRING,			"BG Aging Time"},
  {7,	RADIUS_STRING,			"BG Path Cost"},
  {8,	RADIUS_STRING,			"BG Span Dis"},
  {9,	RADIUS_STRING,			"BG Trans BPDU"},
  {10,	RADIUS_INTEGER4,		"Rate Limit Rate"},
  {11,	RADIUS_INTEGER4,		"Rate Limit Burst"},
  {12,	RADIUS_INTEGER4,		"Police Rate"},
  {13,	RADIUS_INTEGER4,		"Police Burst"},
  {14,	RADIUS_INTEGER4,		"Source Validation"},
  {15,	RADIUS_INTEGER4,		"Tunnel Domain"},
  {16,	RADIUS_STRING,			"Tunnel Local Name"},
  {17,	RADIUS_STRING,			"Tunnel Remote Name"},
  {18,	REDBACK_TUNNEL_FUNCTION,	"Tunnel Function"},
  {21,	RADIUS_INTEGER4,		"Tunnel Max Sessions"},
  {22,	RADIUS_INTEGER4,		"Tunnel Max Tunnels"},
  {23,	RADIUS_INTEGER4,		"Tunnel Session Auth"},
  {24,	RADIUS_INTEGER4,		"Tunnel Window"},
  {25,	RADIUS_INTEGER4,		"Tunnel Retransmit"},
  {26,	RADIUS_INTEGER4,		"Tunnel Cmd Timeout"},
  {27,	RADIUS_STRING,			"PPPOE URL"},
  {28,	RADIUS_STRING,			"PPPOE MOTM"},
  {29,	RADIUS_INTEGER4,		"Tunnel Group"},
  {30,	RADIUS_STRING,			"Tunnel Context"},
  {31,	RADIUS_INTEGER4,		"Tunnel Algorithm"},
  {32,	RADIUS_INTEGER4,		"Tunnel Deadtime"},
  {33,	REDBACK_MCAST_SEND,		"Mcast Send"},
  {34,	REDBACK_MCAST_RECEIVE,		"Mcast Receive"},
  {35,	RADIUS_INTEGER4,		"Mcast MaxGroups"},
  {36,	RADIUS_STRING,			"Ip Address Pool Name"},
  {37,	REDBACK_TUNNEL_DNIS,		"Tunnel DNIS"},
  {38,	RADIUS_INTEGER4,		"Medium Type"},
  {39,	REDBACK_PVC_ENCAPSULATION_TYPE,	"PVC Encapsulation Type"},
  {40,	RADIUS_STRING,			"PVC Profile Name"},
  {41,	REDBACK_PVC_CIRCUIT_PADDING,	"PVC Circuit Padding"},
  {42,	REDBACK_BIND_TYPE,		"Bind Type"},
  {43,	REDBACK_BIND_AUTH_PROTOCOL,	"Bind Auth Protocol"},
  {44,	RADIUS_INTEGER4,		"Bind Auth Max Sessions"},
  {45,	RADIUS_STRING,			"Bind Bypass Bypass"},
  {46,	RADIUS_STRING,			"Bind Auth Context"},
  {47,	RADIUS_STRING,			"Bind Auth Service Grp"},
  {48,	RADIUS_STRING,			"Bind Bypass Context"},
  {49,	RADIUS_STRING,			"Bind Int Context"},
  {50,	RADIUS_STRING,			"Bind Tun Context"},
  {51,	RADIUS_STRING,			"Bind Ses Context"},
  {52,	RADIUS_INTEGER4,		"Bind Dot1q Slot"},
  {53,	RADIUS_INTEGER4,		"Bind Dot1q Port"},
  {54,	RADIUS_INTEGER4,		"Bind Dot1q Vlan Tag Id"},
  {55,	RADIUS_STRING,			"Bind Int Interface Name"},
  {56,	RADIUS_STRING,			"Bind L2TP Tunnel Name"},
  {57,	RADIUS_INTEGER4,		"Bind L2TP Flow Control"},
  {58,	RADIUS_STRING,			"Bind Sub User At Context"},
  {59,	RADIUS_STRING,			"Bind Sub Password"},
  {60,	RADIUS_STRING,			"Ip Host Addr"},
  {61,	RADIUS_INTEGER4,		"IP TOS Field"},
  {62,	RADIUS_INTEGER4,		"NAS Real Port"},
  {63,	RADIUS_STRING,			"Tunnel Session Auth Ctx"},
  {64,	RADIUS_STRING,			"Tunnel Session Auth Service Grp"},
  {65,	RADIUS_INTEGER4,		"Tunnel Rate Limit Rate"},
  {66,	RADIUS_INTEGER4,		"Tunnel Rate Limit Burst"},
  {67,	RADIUS_INTEGER4,		"Tunnel Police Rate"},
  {68,	RADIUS_INTEGER4,		"Tunnel Police Burst"},
  {69,	RADIUS_STRING,			"Tunnel L2F Second Password"},
  {128,	RADIUS_INTEGER4,		"Acct Input Octets 64"},
  {129,	RADIUS_INTEGER4,		"Acct Output Octets 64"},
  {130,	RADIUS_INTEGER4,		"Acct Input Packets 64"},
  {131,	RADIUS_INTEGER4,		"Acct Output Packets 64"},
  {132,	RADIUS_IP_ADDRESS,		"Assigned IP Address"},
  {133,	RADIUS_INTEGER4,		"Acct Mcast In Octets"},
  {134,	RADIUS_INTEGER4,		"Acct Mcast Out Octets"},
  {135,	RADIUS_INTEGER4,		"Acct Mcast In Packets"},
  {136,	RADIUS_INTEGER4,		"Acct Mcast Out Packets"},
  {137,	RADIUS_INTEGER4,		"LAC Port"},
  {138,	RADIUS_INTEGER4,		"LAC Real Port"},
  {139,	REDBACK_LAC_PORT_TYPE,		"LAC Port Type"},
  {140,	REDBACK_LAC_REAL_PORT_TYPE,	"LAC Real Port Type"},
  {141, RADIUS_STRING,			"Acct Dyn Ac Ent"},
  {142, RADIUS_INTEGER4,		"Session Error Code"},
  {143, RADIUS_STRING,			"Session Error Msg"},
  {0, 0, NULL},
};

static value_string radius_vendor_redback_tunnel_function_vals[] =
{
  {1,	"LAC Only"},
  {2,	"LNS Only"},
  {3,	"LAC LNS"},
  {0, NULL}
};

static value_string radius_vendor_redback_mcast_send_vals[] =
{
  {1,	"NO SEND"},
  {2,	"SEND"},
  {3,	"UNSOLICITED SEND"},
  {0, NULL}
};

static value_string radius_vendor_redback_mcast_receive_vals[] =
{
  {1,	"NO RECEIVE"},
  {2,	"RECEIVE"},
  {0, NULL}
};

static value_string radius_vendor_redback_tunnel_dnis_vals[] =
{
  {1,	"DNIS"},
  {2,	"DNIS Only"},
  {0, NULL}
};

static value_string radius_vendor_redback_pvc_encapsulation_type_vals[] =
{
  {1,	"AAA ENCAPS ATM RAW"},
  {2,	"AAA ENCAPS ATM ROUTE1483"},
  {3,	"AAA ENCAPS ATM AUTO1483"},
  {4,	"AAA ENCAPS ATM MULTI"},
  {5,	"AAA ENCAPS ATM BRIDGE1483"},
  {6,	"AAA ENCAPS ATM PPP"},
  {7,	"AAA ENCAPS ATM PPP SERIAL"},
  {8,	"AAA ENCAPS ATM PPP NLPID"},
  {9,	"AAA ENCAPS ATM PPP AUTO"},
  {10,	"AAA ENCAPS ATM PPPOE"},
  {11,	"AAA ENCAPS ATM L2TP"},
  {12,	"AAA ENCAPS ATM PPP LLC"},
  {13,	"AAA ENCAPS FRAME AUTO1490"},
  {14,	"AAA ENCAPS FRAME MULTI"},
  {15,	"AAA ENCAPS FRAME BRIDGE1490"},
  {16,	"AAA ENCAPS FRAME PPP"},
  {17,	"AAA ENCAPS FRAME PPP AUTO"},
  {18,	"AAA ENCAPS FRAME PPPOE"},
  {19,	"AAA ENCAPS FRAME ROUTE1490"},
  {20,	"AAA ENCAPS FRAME L2TP"},
  {21,	"AAA ENCAPS L2TP VC MUXED"},
  {22,	"AAA ENCAPS ETH"},
  {23,	"AAA ENCAPS ETH PPPOE"},
  {24,	"AAA ENCAPS ETH MULTI"},
  {0, NULL}
};

static value_string radius_vendor_redback_pvc_circuit_padding_vals[] =
{
  {1,	"AAA CIRCUIT PADDING"},
  {2,	"AAA CIRCUIT NO PADDING"},
  {0, NULL}
};

static value_string radius_vendor_redback_bind_type_vals[] =
{
  {1,	"AAA AUTH BIND"},
  {2,	"AAA BYPASS BIND"},
  {3,	"AAA INTERFACE BIND"},
  {4,	"AAA SUBSCRIBE BIND"},
  {5,	"AAA TUNNEL BIND"},
  {6,	"AAA SESSION BIND"},
  {7,	"AAA Q8021 BIND"},
  {8,	"AAA MULTI BIND"},
  {0, NULL}
};

static value_string radius_vendor_redback_bind_auth_protocol_vals[] =
{
  {1,	"AAA PPP PAP"},
  {2,	"AAA PPP CHAP"},
  {3,	"AAA PPP CHAP WAIT"},
  {4,	"AAA PPP CHAP PAP"},
  {5,	"AAA PPP CHAP WAIT PAP"},
  {0, NULL}
};

static value_string radius_vendor_redback_lac_port_type_vals[] =
{
  {40,	"NAS PORT TYPE 10BT"},
  {41,	"NAS PORT TYPE 100BT"},
  {42,	"NAS PORT TYPE DS3 FR"},
  {43,	"NAS PORT TYPE DS3 ATM"},
  {44,	"NAS PORT TYPE OC3"},
  {45,	"NAS PORT TYPE HSSI"},
  {46,	"NAS PORT TYPE EIA530"},
  {47,	"NAS PORT TYPE T1"},
  {48,	"NAS PORT TYPE CHAN T3"},
  {49,	"NAS PORT TYPE DS1 FR"},
  {50,	"NAS PORT TYPE E3 ATM"},
  {51,	"NAS PORT TYPE IMA ATM"},
  {52,	"NAS PORT TYPE DS3 ATM 2"},
  {53,	"NAS PORT TYPE OC3 ATM 2"},
  {54,	"NAS PORT TYPE 1000BSX"},
  {55,	"NAS PORT TYPE E1 FR"},
  {56,	"NAS PORT TYPE E1 ATM"},
  {57,	"NAS PORT TYPE E3 FR"},
  {58,	"NAS PORT TYPE OC3 POS"},
  {59,	"NAS PORT TYPE OC12 POS"},
  {60,	"NAS PORT TYPE PPPOE"},
  {0, NULL}
};

static value_string radius_vendor_redback_lac_real_port_type_vals[] =
{
  {40,	"NAS PORT TYPE 10BT"},
  {41,	"NAS PORT TYPE 100BT"},
  {42,	"NAS PORT TYPE DS3 FR"},
  {43,	"NAS PORT TYPE DS3 ATM"},
  {44,	"NAS PORT TYPE OC3"},
  {45,	"NAS PORT TYPE HSSI"},
  {46,	"NAS PORT TYPE EIA530"},
  {47,	"NAS PORT TYPE T1"},
  {48,	"NAS PORT TYPE CHAN T3"},
  {49,	"NAS PORT TYPE DS1 FR"},
  {50,	"NAS PORT TYPE E3 ATM"},
  {51,	"NAS PORT TYPE IMA ATM"},
  {52,	"NAS PORT TYPE DS3 ATM 2"},
  {53,	"NAS PORT TYPE OC3 ATM 2"},
  {54,	"NAS PORT TYPE 1000BSX"},
  {55,	"NAS PORT TYPE E1 FR"},
  {56,	"NAS PORT TYPE E1 ATM"},
  {57,	"NAS PORT TYPE E3 FR"},
  {58,	"NAS PORT TYPE OC3 POS"},
  {59,	"NAS PORT TYPE OC12 POS"},
  {60,	"NAS PORT TYPE PPPOE"},
  {0, NULL}
};

/*
reference:
	http://www.juniper.net/techpubs/software/junos53/swconfig53-getting-started/html/sys-mgmt-authentication2.html
*/
static value_value_string radius_vendor_juniper_attrib[] =
{
  {1,	RADIUS_STRING,		"Juniper Local User Name"},
  {2,	RADIUS_STRING,		"Juniper Allow Commands"},
  {3,	RADIUS_STRING,		"Juniper Deny Commands"},
  {0, 0, NULL}
};

/*
reference:
	'dictionary.aptis' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.aptis
*/
static value_value_string radius_vendor_aptis_attrib[] =
{
  {1,	RADIUS_STRING,		"CVX Identification"},
  {2,	RADIUS_INTEGER4,	"CVX VPOP ID"},
  {3,	RADIUS_INTEGER4,	"CVX SS7 Session ID Type"},
  {4,	RADIUS_INTEGER4,	"CVX Radius Redirect"},
  {5,	RADIUS_INTEGER4,	"CVX IPSVC AZNLVL"},
  {6,	RADIUS_INTEGER4,	"CVX IPSVC Mask"},
  {7,	RADIUS_INTEGER4,	"CVX Multilink Match Info"},
  {8,	RADIUS_INTEGER4,	"CVX Multilink Group Number"},
  {9,	RADIUS_INTEGER4,	"CVX PPP Log Mask"},
  {10,	RADIUS_STRING,		"CVX Modem Begin Modulation"},
  {11,	RADIUS_STRING,		"CVX Modem End Modulation"},
  {12,	RADIUS_STRING,		"CVX Modem Error Correction"},
  {13,	RADIUS_STRING,		"CVX Modem Data Compression"},
  {14,	RADIUS_INTEGER4,	"CVX Modem Tx Packets"},
  {15,	RADIUS_INTEGER4,	"CVX Modem ReTx Packets"},
  {16,	RADIUS_INTEGER4,	"CVX Modem SNR"},
  {17,	RADIUS_INTEGER4,	"CVX Modem Local Retrains"},
  {18,	RADIUS_INTEGER4,	"CVX Modem Remote Retrains"},
  {19,	RADIUS_INTEGER4,	"CVX Modem Local Rate Negs"},
  {20,	RADIUS_INTEGER4,	"CVX Modem Remote Rate Negs"},
  {21,	RADIUS_INTEGER4,	"CVX Modem Begin Recv Line Lvl"},
  {22,	RADIUS_INTEGER4,	"CVX Modem End Recv Line Lvl"},
  {0, 0, NULL},
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

/*
reference:
	'dictionary.shasta' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.shasta
*/
static value_value_string radius_vendor_shasta_attrib[] =
{
  {1,	SHASTA_USER_PRIVILEGE,	"Shasta User Privilege"},
  {2,	RADIUS_STRING,		"Shasta Service Profile"},
  {3,	RADIUS_STRING,		"Shasta VPN Name"},
  {0, 0, NULL},
};

static value_string radius_vendor_shasta_user_privilege_vals[] =
{
  {1,	"User"},
  {2,	"Super User"},
  {3,	"SSuper User"},
  {0, NULL}
};

/*
reference:
	'dictionary.nomadix' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.nomadix
*/
static value_value_string radius_vendor_nomadix_attrib[] =
{
  {1,	RADIUS_INTEGER4,	"Nomadix Bw Up"},
  {2,	RADIUS_INTEGER4,	"Nomadix Bw Down"},
  {0, 0, NULL},
};

/*
reference:
	'dictionary.erx' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.erx
*/
static value_value_string radius_vendor_unisphere_attrib[] =
{
  {1,	RADIUS_STRING,		"ERX Virtual Router Name"},
  {2,	RADIUS_STRING,		"ERX Address Pool Name"},
  {3,	RADIUS_STRING,		"ERX Local Loopback Interface"},
  {4,	RADIUS_IP_ADDRESS,	"ERX Primary Dns"},
  {5,	RADIUS_IP_ADDRESS,	"ERX Primary Wins"},
  {6,	RADIUS_IP_ADDRESS,	"ERX Secondary Dns"},
  {7,	RADIUS_IP_ADDRESS,	"ERX Secondary Wins"},
  {8,	RADIUS_STRING,		"ERX Tunnel Virtual Router"},
  {9,	RADIUS_STRING,		"ERX Tunnel Password"},
  {10,	RADIUS_STRING,		"ERX Ingress Policy Name"},
  {11,	RADIUS_STRING,		"ERX Egress Policy Name"},
  {12,	RADIUS_STRING,		"ERX Ingress Statistics"},
  {13,	RADIUS_STRING,		"ERX Egress Statistics"},
  {14,	RADIUS_STRING,		"ERX Atm Service Category"},
  {15,	RADIUS_STRING,		"ERX Atm PCR"},
  {16,	RADIUS_STRING,		"ERX Atm SCR"},
  {17,	RADIUS_STRING,		"ERX Atm MBS"},
  {18,	RADIUS_STRING,		"ERX Cli Initial Access Level"},
  {19,	RADIUS_INTEGER4,	"ERX Cli Allow All VR Access"},
  {20,	RADIUS_STRING,		"ERX Alternate Cli Access Level"},
  {21,	RADIUS_STRING,		"ERX Alternate Cli Vrouter Name"},
  {22,	RADIUS_INTEGER4,	"ERX Sa Validate"},
  {23,	RADIUS_INTEGER4,	"ERX Igmp Enable"},
  {0, 0, NULL},
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

/*
reference:
	'dictionary.quintum' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.quintum
*/
static value_value_string radius_vendor_quintum_attrib[] =
{
  {1,	RADIUS_STRING,		"Quintum AVPair"},
  {2,	RADIUS_STRING,		"Quintum NAS Port"},
  {23,	RADIUS_STRING,		"Quintum h323 remote address"},
  {24,	RADIUS_STRING,		"Quintum h323 conf id"},
  {25,	RADIUS_STRING,		"Quintum h323 setup time"},
  {26,	RADIUS_STRING,		"Quintum h323 call origin"},
  {27,	RADIUS_STRING,		"Quintum h323 call type"},
  {28,	RADIUS_STRING,		"Quintum h323 connect time"},
  {29,	RADIUS_STRING,		"Quintum h323 disconnect time"},
  {30,	RADIUS_STRING,		"Quintum h323 disconnect cause"},
  {31,	RADIUS_STRING,		"Quintum h323 voice quality"},
  {33,	RADIUS_STRING,		"Quintum h323 gw id"},
  {35,	RADIUS_STRING,		"Quintum h323 incoming conf id"},
  {101,	RADIUS_STRING,		"Quintum h323 credit amount"},
  {102,	RADIUS_STRING,		"Quintum h323 credit time"},
  {103,	RADIUS_STRING,		"Quintum h323 return code"},
  {104,	RADIUS_STRING,		"Quintum h323 prompt id"},
  {105,	RADIUS_STRING,		"Quintum h323 time and day"},
  {106,	RADIUS_STRING,		"Quintum h323 redirect number"},
  {107,	RADIUS_STRING,		"Quintum h323 preferred lang"},
  {108,	RADIUS_STRING,		"Quintum h323 redirect ip address"},
  {109,	RADIUS_STRING,		"Quintum h323 billing model"},
  {110,	RADIUS_STRING,		"Quintum h323 currency type"},
  {0, 0, NULL},
};

/*
reference:
	http://download.colubris.com/library/product_doc/CN3500_AdminGuide.pdf
*/
static value_value_string radius_vendor_colubris_attrib[] =
{
  {0,	RADIUS_STRING,		"Colubris AV Pair"},
  {0, 0, NULL},
};

/*
reference:
	'dictionary.columbia_university' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.columbia_university
*/
static value_value_string radius_vendor_columbia_university_attrib[] =
{
  {0,	COLUMBIA_UNIVERSITY_SIP_METHOD,	"SIP Method"},
  {1,	RADIUS_STRING,			"SIP From"},
  {2,	RADIUS_STRING,			"SIP To"},
  {4,	RADIUS_STRING,			"SIP Translated Request URI"},
  {0, 0, NULL},
};

static value_string radius_vendor_columbia_university_sip_method_vals[] =
{
  {0,	"INVITE"},
  {1,	"BYE"},
  {2,	"REGISTER"},
  {3,	"OTHER"},
  {0, NULL}
};

static value_value_string radius_vendor_3gpp_attrib[] =
{
   {5,	THE3GPP_QOS,	"QoS Profile"},
   {0, 0, NULL},
};

static rd_vsa_table radius_vsa_table[] =
{
  {VENDOR_ACC,			radius_vendor_acc_attrib},
  {VENDOR_CISCO,		radius_vendor_cisco_attrib},
  {VENDOR_SHIVA,		radius_vendor_shiva_attrib},
  {VENDOR_LIVINGSTON,		radius_vendor_livingston_attrib},
  {VENDOR_MICROSOFT,		radius_vendor_microsoft_attrib},
  {VENDOR_ASCEND,		radius_vendor_ascend_attrib},
  {VENDOR_BAY,			radius_vendor_bay_attrib},
  {VENDOR_FOUNDRY,		radius_vendor_foundry_attrib},
  {VENDOR_VERSANET,		radius_vendor_versanet_attrib},
  {VENDOR_REDBACK,		radius_vendor_redback_attrib},
  {VENDOR_JUNIPER,		radius_vendor_juniper_attrib},
  {VENDOR_APTIS,		radius_vendor_aptis_attrib},
  {VENDOR_COSINE,		radius_vendor_cosine_attrib},
  {VENDOR_SHASTA,		radius_vendor_shasta_attrib},
  {VENDOR_NOMADIX,		radius_vendor_nomadix_attrib},
  {VENDOR_UNISPHERE,		radius_vendor_unisphere_attrib},
  {VENDOR_ISSANNI,		radius_vendor_issanni_attrib},
  {VENDOR_QUINTUM,		radius_vendor_quintum_attrib},
  {VENDOR_COLUBRIS,		radius_vendor_colubris_attrib},
  {VENDOR_COLUMBIA_UNIVERSITY,	radius_vendor_columbia_university_attrib},
  {VENDOR_THE3GPP,		radius_vendor_3gpp_attrib},
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

  {ACC_REASON_CODE,			radius_vendor_acc_reason_code_vals},
  {ACC_CCP_OPTION,			radius_vendor_acc_ccp_option_vals},
  {ACC_ROUTE_POLICY,			radius_vendor_acc_route_policy_vals},
  {ACC_ML_MLX_ADMIN_STATE,		radius_vendor_acc_ml_mlx_admin_state_vals},
  {ACC_CLEARING_CAUSE,			q931_cause_code_vals},
  {ACC_CLEARING_LOCATION,		q931_cause_location_vals},
  {ACC_REQUEST_TYPE,			radius_vendor_acc_request_type_vals},
  {ACC_BRIDGING_SUPPORT,		radius_vendor_acc_bridging_support_vals},
  {ACC_APSM_OVERSUBSCRIBED,		radius_vendor_acc_apsm_oversubscribed_vals},
  {ACC_ACCT_ON_OFF_REASON,		radius_vendor_acc_acct_on_off_reason_vals},
  {ACC_IP_COMPRESSION,			radius_vendor_acc_ip_compression_vals},
  {ACC_IPX_COMPRESSION,			radius_vendor_acc_ipx_compression_vals},
  {ACC_CALLBACK_MODE,			radius_vendor_acc_callback_mode_vals},
  {ACC_CALLBACK_CBCP_TYPE,		radius_vendor_acc_callback_cbcp_type_vals},
  {ACC_DIALOUT_AUTH_MODE,		radius_vendor_acc_dialout_auth_mode_vals},
  {ACC_ACCESS_COMMUNITY,		radius_vendor_acc_access_community_vals},

  {SHIVA_TYPE_OF_SERVICE,		radius_vendor_shiva_type_of_service_vals},
  {SHIVA_LINK_PROTOCOL,			radius_vendor_shiva_link_protocol_vals},
  {SHIVA_DISCONNECT_REASON,		radius_vendor_shiva_disconnect_reason_vals},
  {SHIVA_FUNCTION,			radius_vendor_shiva_function_vals},
  {SHIVA_CONNECT_REASON,		radius_vendor_shiva_connect_reason_vals},

  {LIVINGSTON_IPSEC_LOG_OPTIONS,	radius_vendor_livingston_ipsec_log_options_vals},
  {LIVINGSTON_IPSEC_DENY_ACTION,	radius_vendor_livingston_ipsec_deny_action_vals},
  {LIVINGSTON_NAT_LOG_OPTIONS,		radius_vendor_livingston_nat_log_options_vals},
  {LIVINGSTON_NAT_SESS_DIR_FAIL_ACTION,	radius_vendor_livingston_nat_sess_dir_fail_action_vals},
  {LIVINGSTON_MULTICAST_CLIENT,		radius_vendor_livingston_multicast_client_vals},

  {CISCO_DISCONNECT_CAUSE,		radius_vendor_cisco_disconnect_cause_vals},

  {MICROSOFT_BAP_USAGE,			radius_vendor_microsoft_bap_usage_vals},
  {MICROSOFT_ARAP_PW_CHANGE_REASON,	radius_vendor_microsoft_arap_pw_change_reason_vals},
  {MICROSOFT_ACCT_AUTH_TYPE,		radius_vendor_microsoft_acct_auth_type_vals},
  {MICROSOFT_ACCT_EAP_TYPE,		radius_vendor_microsoft_acct_eap_type_vals},

  {ASCEND_CALLING_ID_TYPE_OF_NUMBER,	radius_vendor_ascend_calling_id_type_of_number_vals},
  {ASCEND_CALLING_ID_NUMBERING_PLAN,	radius_vendor_ascend_calling_id_numbering_plan_vals},
  {ASCEND_CALLING_ID_PRESENTATION,	radius_vendor_ascend_calling_id_presentation_vals},
  {ASCEND_CALLING_ID_SCREENING,		radius_vendor_ascend_calling_id_screening_vals},

  {BAY_TUNNEL_AUTHEN_TYPE,		radius_vendor_bay_tunnel_authen_type_vals},
  {BAY_TUNNEL_AUTHEN_MODE,		radius_vendor_bay_tunnel_authen_mode_vals},
  {BAY_USER_SERVER_LOCATION,		radius_vendor_bay_user_server_location_vals},
  {BAY_SYSTEM_DISC_REASON,		radius_vendor_bay_system_disc_reason_vals},
  {BAY_MODEM_DISC_REASON,		radius_vendor_bay_modem_disc_reason_vals},
  {BAY_ADDR_RESOLUTION_PROTOCOL,	radius_vendor_bay_addr_resolution_protocol_vals},
  {BAY_USER_LEVEL,			radius_vendor_bay_user_level_vals},
  {BAY_AUDIT_LEVEL,			radius_vendor_bay_audit_level_vals},

  {VERSANET_TERMINATION_CAUSE,		radius_vendor_versanet_termination_cause_vals},

  {REDBACK_TUNNEL_FUNCTION,		radius_vendor_redback_tunnel_function_vals},
  {REDBACK_MCAST_SEND,			radius_vendor_redback_mcast_send_vals},
  {REDBACK_MCAST_RECEIVE,		radius_vendor_redback_mcast_receive_vals},
  {REDBACK_TUNNEL_DNIS,			radius_vendor_redback_tunnel_dnis_vals},
  {REDBACK_PVC_ENCAPSULATION_TYPE,	radius_vendor_redback_pvc_encapsulation_type_vals},
  {REDBACK_PVC_CIRCUIT_PADDING,		radius_vendor_redback_pvc_circuit_padding_vals},
  {REDBACK_BIND_TYPE,			radius_vendor_redback_bind_type_vals},
  {REDBACK_BIND_AUTH_PROTOCOL,		radius_vendor_redback_bind_auth_protocol_vals},
  {REDBACK_LAC_PORT_TYPE,		radius_vendor_redback_lac_port_type_vals},
  {REDBACK_LAC_REAL_PORT_TYPE,		radius_vendor_redback_lac_real_port_type_vals},

  {SHASTA_USER_PRIVILEGE,		radius_vendor_shasta_user_privilege_vals},

  {COLUMBIA_UNIVERSITY_SIP_METHOD,	radius_vendor_columbia_university_sip_method_vals},

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
    guint32 i;

    for (i = 0; vvs && vvs[i].str; i++)
	if (vvs[i].val1 == val)
	    return(vvs[i].val2);

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
rddecryptpass(gchar *dest,tvbuff_t *tvb,int offset,int length)
{
    md5_state_t md_ctx;
    md5_byte_t digest[16];
    guint32 i;
    guint32 totlen = 0;
    const guint8 *pd = tvb_get_ptr(tvb,offset,length);

    if (!shared_secret || !authenticator ) {
	rdconvertbufftostr(dest,tvb,offset,length);
	return;
    }

    dest[0] = '"';
    dest[1] = 0;
    totlen = 1;

    md5_init(&md_ctx);
    md5_append(&md_ctx,shared_secret,strlen(shared_secret));
    md5_append(&md_ctx,authenticator,16);
    md5_finish(&md_ctx,digest);

    for( i = 0 ; i < 16 && i < (guint32)length ; i++ ) {
	dest[totlen] = pd[i] ^ digest[i];
	if ( !isprint(dest[totlen])) {
	    sprintf(&(dest[totlen]),"\\%03o",pd[i] ^ digest[i]);
	    totlen += strlen(&(dest[totlen]));
	} else {
	    totlen++;
	}
    }
    while(i<(guint32)length) {
	if ( isprint((int)pd[i]) ) {
	    dest[totlen] = (gchar)pd[i];
	    totlen++;
	} else {
		sprintf(&(dest[totlen]), "\\%03o", pd[i]);
		totlen=totlen+strlen(&(dest[totlen]));
	}
	i++;
    }
    dest[totlen]='"';
    dest[totlen+1] = 0;

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
	return val_to_str(val, vs, "Undefined");
}

static gchar *rd_match_strval_attrib(guint32 val, const value_value_string *vvs)
{
    guint32 i;

    for (i = 0; vvs[i].str; i++)
	if (vvs[i].val1 == val)
	    return(vvs[i].str);

    return("Unknown Type");
}

static gchar *rdconvertinttostr(gchar *dest, int print_type, guint32 val)
{
    guint32 i;
    const value_string *vs = NULL;

    for (i = 0; valstr_table[i].print_type; i++)
    {
	if (valstr_table[i].print_type == print_type)
	{
	    vs = valstr_table[i].valstr;
	    break;
	}
    }
    sprintf(dest, "%s(%u)", (vs ? rd_match_strval(val, vs) : "Undefined"), val);

    return dest;
}

/* NOTE: This function's signature has been changed with the addition of the
 * tree parameter at the end.
 *
 * The function behaves EXACTLY AS BEFORE for parameters which do not
 * imply THE3GPP_QOS; I had to change the signature because the function
 * decode_qos_umts() wants to write on the protocol tree :)
 *
 * If you think it is better to DUPLICATE the code copying decode_qos_umts
 * here, and adapting it, feel free; only keep in mind that changes will have
 * to be doubled if any bug is found.
 *
 * At last, forgive me if I've messed up some indentation...
 * */
static gchar *rd_value_to_str_2(gchar *dest, const e_avphdr *avph, tvbuff_t *tvb,
				int offset, const value_value_string *vvs, proto_tree *tree)
{
  int print_type;

  /* Variable to peek which will be the next print_type for VENDOR-SPECIFIC
   * RADIUS attributes
   * */
  int next_print_type;

  /* Temporary variable to perform some trick on the cont variable; again, this
   * is needed only when THE3GPP_QOS in involved.
   * */
  gchar *tmp_punt;

  gchar *cont;
  value_string *valstrarr;
  guint32 intval;
  const guint8 *pd;
  guint8 tag;
  char *rtimestamp;
  extern char *tzname[2];

  int vsa_length;
  int vsa_len;
  int vsa_index;
  rd_vsa_table *vsa_rvt;
  const e_avphdr *vsa_avph;

/* prints the values of the attribute value pairs into a text buffer */
  print_type = match_numval(avph->avp_type, vvs);

  /* Default begin */
  strcpy(dest, "Value:");
  cont=&dest[strlen(dest)];
  switch(print_type)
  {
        case( RADIUS_STRING ):
		if ( avph->avp_type == 2 )  { /* User Password */
		    rddecryptpass(cont,tvb,offset+2,avph->avp_length-2);
		} else {
		    rdconvertbufftostr(cont,tvb,offset+2,avph->avp_length-2);
		}
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
			sprintf(dest, "Tag:%u, Value:%s(%u)",
				intval >> 24,
				rd_match_strval(intval & 0xffffff,valstrarr),
				intval & 0xffffff);
			break;
		}
		sprintf(cont, "%s(%u)", rd_match_strval(intval,valstrarr), intval);
		break;
	case( RADIUS_TUNNEL_MEDIUM_TYPE ):
		valstrarr=radius_tunnel_medium_type_vals;
		intval = tvb_get_ntohl(tvb,offset+2);
		/* Tagged ? */
		if (intval >> 24) {
			sprintf(dest, "Tag:%u, Value:%s(%u)",
				intval >> 24,
				rd_match_strval(intval & 0xffffff,valstrarr),
				intval & 0xffffff);
			break;
		}
		sprintf(cont, "%s(%u)", rd_match_strval(intval,valstrarr), intval);
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
		valstrarr = radius_vendor_specific_vendors;
		intval = tvb_get_ntohl(tvb,offset+2);
		sprintf(dest, "Vendor:%s(%u)", rd_match_strval(intval,valstrarr), intval);
		cont = &dest[strlen(dest)];
		vsa_length = avph->avp_length;
		vsa_len = 6;
		vsa_index = 0;
		vsa_rvt = get_vsa_table(intval);
		do
		{
			vsa_avph = (const e_avphdr*)tvb_get_ptr(tvb, offset+vsa_len,
				avph->avp_length-vsa_len);
			if (vsa_rvt)
				next_print_type = match_numval(vsa_avph->avp_type,
					vsa_rvt->attrib);
			else
				next_print_type = 0;
			cont = &cont[strlen(cont)+1];
			tmp_punt = cont;
			vsabuffer[vsa_index].str = cont;
			vsabuffer[vsa_index].offset = offset+vsa_len;
			vsabuffer[vsa_index].length = vsa_avph->avp_length;
			sprintf(cont, "t:%s(%u) l:%u, ",
				(vsa_rvt
					? rd_match_strval_attrib(vsa_avph->avp_type,vsa_rvt->attrib)
					: "Unknown Type"),
				vsa_avph->avp_type, vsa_avph->avp_length);
			cont = &cont[strlen(cont)];
			rd_value_to_str_2(cont, vsa_avph, tvb, offset+vsa_len,
				(vsa_rvt ? vsa_rvt->attrib : NULL), tree);
			vsa_index++;
			vsa_len += vsa_avph->avp_length;
			if (next_print_type == THE3GPP_QOS )
			{
				cont = tmp_punt;
				vsa_index--;
				vsabuffer[vsa_index].str = 0;
			}
		} while (vsa_length > vsa_len && vsa_index < VSABUFFER);
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
	case( ACC_REASON_CODE ):
	case( ACC_CCP_OPTION ):
	case( ACC_ROUTE_POLICY ):
	case( ACC_ML_MLX_ADMIN_STATE ):
	case( ACC_CLEARING_CAUSE ):
	case( ACC_CLEARING_LOCATION ):
	case( ACC_REQUEST_TYPE ):
	case( ACC_BRIDGING_SUPPORT ):
	case( ACC_APSM_OVERSUBSCRIBED ):
	case( ACC_ACCT_ON_OFF_REASON ):
	case( ACC_IP_COMPRESSION ):
	case( ACC_IPX_COMPRESSION ):
	case( ACC_CALLBACK_MODE ):
	case( ACC_CALLBACK_CBCP_TYPE ):
	case( ACC_DIALOUT_AUTH_MODE ):
	case( ACC_ACCESS_COMMUNITY ):
	case( CISCO_DISCONNECT_CAUSE ):
	case( SHIVA_TYPE_OF_SERVICE ):
	case( SHIVA_LINK_PROTOCOL ):
	case( SHIVA_DISCONNECT_REASON ):
	case( SHIVA_FUNCTION ):
	case( SHIVA_CONNECT_REASON ):
	case( LIVINGSTON_IPSEC_LOG_OPTIONS ):
	case( LIVINGSTON_IPSEC_DENY_ACTION ):
	case( LIVINGSTON_NAT_LOG_OPTIONS ):
	case( LIVINGSTON_NAT_SESS_DIR_FAIL_ACTION ):
	case( LIVINGSTON_MULTICAST_CLIENT ):
	case( MICROSOFT_BAP_USAGE ):
	case( MICROSOFT_ARAP_PW_CHANGE_REASON ):
	case( MICROSOFT_ACCT_AUTH_TYPE ):
	case( MICROSOFT_ACCT_EAP_TYPE ):
	case( ASCEND_CALLING_ID_TYPE_OF_NUMBER ):
	case( ASCEND_CALLING_ID_NUMBERING_PLAN ):
	case( ASCEND_CALLING_ID_PRESENTATION ):
	case( ASCEND_CALLING_ID_SCREENING ):
	case( BAY_TUNNEL_AUTHEN_TYPE ):
	case( BAY_TUNNEL_AUTHEN_MODE ):
	case( BAY_USER_SERVER_LOCATION ):
	case( BAY_SYSTEM_DISC_REASON ):
	case( BAY_MODEM_DISC_REASON ):
	case( BAY_ADDR_RESOLUTION_PROTOCOL ):
	case( BAY_USER_LEVEL ):
	case( BAY_AUDIT_LEVEL ):
	case( VERSANET_TERMINATION_CAUSE ):
	case( REDBACK_TUNNEL_FUNCTION ):
	case( REDBACK_MCAST_SEND ):
	case( REDBACK_MCAST_RECEIVE ):
	case( REDBACK_TUNNEL_DNIS ):
	case( REDBACK_PVC_ENCAPSULATION_TYPE ):
	case( REDBACK_PVC_CIRCUIT_PADDING ):
	case( REDBACK_BIND_TYPE ):
	case( REDBACK_BIND_AUTH_PROTOCOL ):
	case( REDBACK_LAC_PORT_TYPE ):
	case( REDBACK_LAC_REAL_PORT_TYPE ):
	case( SHASTA_USER_PRIVILEGE ):
	case( COLUMBIA_UNIVERSITY_SIP_METHOD ):
		rdconvertinttostr(cont, print_type,tvb_get_ntohl(tvb,offset+2));
		break;
	case( COSINE_VPI_VCI ):
		sprintf(cont,"%u/%u",
			tvb_get_ntohs(tvb,offset+2),
			tvb_get_ntohs(tvb,offset+4));
 		break;

	case( THE3GPP_QOS ):
		/* Find the ponter to the already-built label
		 * */
		tmp_punt = dest - 2;
		while (*tmp_punt)
			tmp_punt--;
		tmp_punt++;

		/* Call decode_qos_umts from packet-gtp package
		 * */
		decode_qos_umts(tvb, offset + 1, tree, tmp_punt, 3);
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

/* NOTE: This function's signature has been changed with the addition of the
 * tree parameter at the end. This is needed for 3GPP QoS handling; previous
 * behaviour has not been changed.
 * */
static gchar *rd_value_to_str(
   e_avphdr *avph, tvbuff_t *tvb, int offset, proto_tree *tree)
{
    int i;

    for (i = 0; i < VSABUFFER; i++)
	vsabuffer[i].str = NULL;
    rd_value_to_str_2(textbuffer, avph, tvb, offset, radius_attrib, tree);
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

    if (avph.avp_type == 79) {	/* EAP Message */
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
            add_new_data_source(pinfo, next_tvb, "Reassembled EAP");

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
        int i;
        /* We pre-add a text and a subtree to allow 3GPP QoS decoding
         * to access the protocol tree.
         * */
        ti = proto_tree_add_text(tree, tvb, offset, avph.avp_length,
			    "t:%s(%u) l:%u",
			    avptpstrval, avph.avp_type, avph.avp_length);
        vsa_tree = proto_item_add_subtree(ti, ett_radius_vsa);
        valstr = rd_value_to_str(&avph, tvb, offset, vsa_tree);
        proto_item_append_text(ti, ", %s", valstr);
	for (i = 0; vsabuffer[i].str && i < VSABUFFER; i++)
	    proto_tree_add_text(vsa_tree, tvb, vsabuffer[i].offset,
				vsabuffer[i].length, "%s", vsabuffer[i].str);
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
  rhlength= (int)g_ntohs(rh.rh_pktlength);
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
	if ( authenticator ) {
	    g_free(authenticator);
	}
	authenticator = g_malloc(AUTHENTICATOR_LENGTH);
	if ( authenticator ) {
	    memcpy(authenticator,tvb_get_ptr(tvb,4,AUTHENTICATOR_LENGTH),AUTHENTICATOR_LENGTH);
	}
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

	module_t *radius_module;

	proto_radius = proto_register_protocol("Radius Protocol", "RADIUS",
	    "radius");
	proto_register_field_array(proto_radius, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	
	radius_module = prefs_register_protocol(proto_radius,NULL);
	prefs_register_string_preference(radius_module,"shared_secret","Shared Secret",
					"Shared secret used to decode User Passwords",
					&shared_secret);
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
