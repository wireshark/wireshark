/* packet-radius.c
 *
 * Routines for RADIUS packet disassembly
 * Copyright 1999 Johan Feyaerts
 * Changed 03/12/2003 Rui Carmo (http://the.taoofmac.com - added all 3GPP VSAs, some parsing)
 *
 * RFC 2865, RFC 2866, RFC 2867, RFC 2868, RFC 2869
 *
 * $Id: packet-radius.c,v 1.86 2003/12/17 02:24:53 guy Exp $
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

typedef struct _radius_attr_info {
        guint16 attr_type;
        guint16 value_type;
	gchar *str;
	const value_string *vs;
} radius_attr_info;

typedef struct _rd_vsa_table {
	guint32 vendor;
	const radius_attr_info *attrib;
} rd_vsa_table;

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
#define RADIUS_ACCOUNTING_STATUS		6
#define RADIUS_ACCESS_PASSWORD_REQUEST		7
#define RADIUS_ACCESS_PASSWORD_ACK		8
#define RADIUS_ACCESS_PASSWORD_REJECT		9
#define RADIUS_ACCOUNTING_MESSAGE		10
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

/*
 * List of types for RADIUS attributes.  "Type" refers to how it's
 * formatted for display in Ethereal.
 *
 * Not every RADIUS attribute gets its own type.  If an attribute is
 * an integer or a tagged integer, but happens to have particular strings
 * associated with particular values, it doesn't get its own type -
 * you just put a pointer to the appropriate value_string table in
 * the entry for that attribute in the appropriate radius_attr_info
 * table.  Only if it has to get formatted in some non-standard fashion
 * (as is the case for the CoSine VPI/VCI attribute) does it get a type
 * of its own.
 */
enum {
    RADIUS_STRING = 1,
    RADIUS_BINSTRING,
    RADIUS_INTEGER4,
    RADIUS_IP_ADDRESS,
    RADIUS_IP6_ADDRESS,
    RADIUS_UNKNOWN,
    RADIUS_IPX_ADDRESS,
    RADIUS_STRING_TAGGED,
    RADIUS_VENDOR_SPECIFIC,
    RADIUS_TIMESTAMP,
    RADIUS_INTEGER4_TAGGED,
    RADIUS_EAP_MESSAGE,

    COSINE_VPI_VCI,

    THE3GPP_IMSI,
    THE3GPP_QOS,
    THE3GPP_IMSI_MCC_MNC,
    THE3GPP_GGSN_MCC_MNC,
    THE3GPP_NSAPI,
    THE3GPP_SESSION_STOP_INDICATOR,
    THE3GPP_SELECTION_MODE,
    THE3GPP_CHARGING_CHARACTERISTICS,
    THE3GPP_IPV6_DNS_SERVERS,
    THE3GPP_SGSN_MCC_MNC
};

static const value_string radius_vals[] =
{
  {RADIUS_ACCESS_REQUEST,		"Access Request"},
  {RADIUS_ACCESS_ACCEPT,		"Access Accept"},
  {RADIUS_ACCESS_REJECT,		"Access Reject"},
  {RADIUS_ACCOUNTING_REQUEST,		"Accounting Request"},
  {RADIUS_ACCOUNTING_RESPONSE,		"Accounting Response"},
  {RADIUS_ACCOUNTING_STATUS,		"Accounting Status"},
  {RADIUS_ACCESS_PASSWORD_REQUEST,	"Access Password Request"},
  {RADIUS_ACCESS_PASSWORD_ACK,		"Access Password Ack"},
  {RADIUS_ACCESS_PASSWORD_REJECT,	"Access Password Reject"},
  {RADIUS_ACCOUNTING_MESSAGE,		"Accounting Message"},
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

static const value_string radius_vendor_specific_vendors[] =
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
 * XXX - should we construct these tables in Ethereal at start-up time by
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
 *
 * In addition, it has entries such as
 *
 *	VALUE           Service-Type            Login-User              1
 *
 * to handle translation of integral values to strings, which we'd use to
 * construct value_string tables.
 */
static const value_string radius_service_type_vals[] =
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

static const value_string radius_framed_protocol_vals[] =
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

static const value_string radius_framed_routing_vals[] =
{
  {1,	"Send Routing Packets"},
  {2,	"Listen for routing packets"},
  {3,	"Send and Listen"},
  {0,	"None"},
  {0, NULL}
};

static const value_string radius_framed_compression_vals[] =
{
  {1,	"VJ TCP/IP Header Compression"},
  {2,	"IPX Header Compression"},
  {3,	"Stac-LZS compression"},
  {0,	"None"},
  {0, NULL}
};

static const value_string radius_login_service_vals[] =
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

static const value_string radius_terminating_action_vals[] =
{
  {1,	"RADIUS Request"},
  {0,	"Default"},
  {0, NULL}
};

static const value_string radius_accounting_status_type_vals[] =
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

static const value_string radius_accounting_authentication_vals[] =
{
  {1,	"Radius"},
  {2,	"Local"},
  {3,	"Remote"},
  /* RFC 2866 says 3 is Remote. Is 7 a mistake? */
  {7,	"Remote"},
  {0, NULL}
};

static const value_string radius_acct_terminate_cause_vals[] =
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

static const value_string radius_tunnel_type_vals[] =
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

static const value_string radius_tunnel_medium_type_vals[] =
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

static const value_string radius_nas_port_type_vals[] =
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

static const radius_attr_info radius_attrib[] =
{
  {1,	RADIUS_STRING,		"User Name", NULL},
  {2,	RADIUS_STRING,		"User Password", NULL},
  {3,	RADIUS_BINSTRING,	"CHAP Password", NULL},
  {4,	RADIUS_IP_ADDRESS,	"NAS IP Address", NULL},
  {5,	RADIUS_INTEGER4,	"NAS Port", NULL},
  {6,	RADIUS_INTEGER4,	"Service Type", radius_service_type_vals},
  {7,	RADIUS_INTEGER4,	"Framed Protocol", radius_framed_protocol_vals},
  {8,	RADIUS_IP_ADDRESS,	"Framed IP Address", NULL},
  {9,	RADIUS_IP_ADDRESS,	"Framed IP Netmask", NULL},
  {10,	RADIUS_INTEGER4,	"Framed Routing", radius_framed_routing_vals},
  {11,	RADIUS_STRING,		"Filter Id", NULL},
  {12,	RADIUS_INTEGER4,	"Framed MTU", NULL},
  {13,	RADIUS_INTEGER4,	"Framed Compression", radius_framed_compression_vals},
  {14,	RADIUS_IP_ADDRESS,	"Login IP Host", NULL},
  {15,	RADIUS_INTEGER4,	"Login Service", radius_login_service_vals},
  {16,	RADIUS_INTEGER4,	"Login TCP Port", NULL},
  {17,	RADIUS_UNKNOWN,		"Unassigned", NULL},
  {18,	RADIUS_STRING,		"Reply Message", NULL},
  {19,	RADIUS_STRING,		"Callback Number", NULL},
  {20,	RADIUS_STRING,		"Callback Id", NULL},
  {21,	RADIUS_UNKNOWN,		"Unassigned", NULL},
  {22,	RADIUS_STRING,		"Framed Route", NULL},
  {23,	RADIUS_IPX_ADDRESS,	"Framed IPX network", NULL},
  {24,	RADIUS_BINSTRING,	"State", NULL},
  {25,	RADIUS_BINSTRING,	"Class", NULL},
  {26,	RADIUS_VENDOR_SPECIFIC,	"Vendor Specific", NULL},
  {27,	RADIUS_INTEGER4,	"Session Timeout", NULL},
  {28,	RADIUS_INTEGER4,	"Idle Timeout", NULL},
  {29,	RADIUS_INTEGER4,	"Terminating Action", radius_terminating_action_vals},
  {30,	RADIUS_STRING,		"Called Station Id", NULL},
  {31,	RADIUS_STRING,		"Calling Station Id", NULL},
  {32,	RADIUS_STRING,		"NAS identifier", NULL},
  {33,	RADIUS_BINSTRING,	"Proxy State", NULL},
  {34,	RADIUS_STRING,		"Login LAT Service", NULL},
  {35,	RADIUS_STRING,		"Login LAT Node", NULL},
  {36,	RADIUS_BINSTRING,	"Login LAT Group", NULL},
  {37,	RADIUS_INTEGER4,	"Framed AppleTalk Link", NULL},
  {38,	RADIUS_INTEGER4,	"Framed AppleTalk Network", NULL},
  {39,	RADIUS_STRING,		"Framed AppleTalk Zone", NULL},
  {40,	RADIUS_INTEGER4,	"Acct Status Type", radius_accounting_status_type_vals},
  {41,	RADIUS_INTEGER4,	"Acct Delay Time", NULL},
  {42,	RADIUS_INTEGER4,	"Acct Input Octets", NULL},
  {43,	RADIUS_INTEGER4,	"Acct Output Octets", NULL},
  {44,	RADIUS_STRING,		"Acct Session Id", NULL},
  {45,	RADIUS_INTEGER4,	"Acct Authentic", radius_accounting_authentication_vals},
  {46,	RADIUS_INTEGER4,	"Acct Session Time", NULL},
  {47,	RADIUS_INTEGER4,	"Acct Input Packets", NULL},
  {48,	RADIUS_INTEGER4,	"Acct Output Packets", NULL},
  {49,	RADIUS_INTEGER4,	"Acct Terminate Cause", radius_acct_terminate_cause_vals},
  {50,	RADIUS_STRING,		"Acct Multi Session Id", NULL},
  {51,	RADIUS_INTEGER4,	"Acct Link Count", NULL},
  {52,	RADIUS_INTEGER4,	"Acct Input Gigawords", NULL},
  {53,	RADIUS_INTEGER4,	"Acct Output Gigawords", NULL},
  /* 54 Unused */
  {55,	RADIUS_TIMESTAMP,	"Event Timestamp", NULL},
  /* 56-59 Unused */
  {60,	RADIUS_BINSTRING,	"CHAP Challenge", NULL},
  {61,	RADIUS_INTEGER4,	"NAS Port Type", radius_nas_port_type_vals},
  {62,	RADIUS_INTEGER4,	"Port Limit", NULL},
  {63,	RADIUS_BINSTRING,	"Login LAT Port", NULL},
  {64,	RADIUS_INTEGER4_TAGGED,	"Tunnel Type", radius_tunnel_type_vals},
  {65,	RADIUS_INTEGER4_TAGGED,	"Tunnel Medium Type", radius_tunnel_medium_type_vals},
  {66,	RADIUS_STRING_TAGGED,	"Tunnel Client Endpoint", NULL},
  {67,	RADIUS_STRING_TAGGED,	"Tunnel Server Endpoint", NULL},
  {68,	RADIUS_STRING,		"Tunnel Connection", NULL},
  {69,	RADIUS_STRING_TAGGED,	"Tunnel Password", NULL},
  {70,	RADIUS_STRING,		"ARAP Password", NULL},
  {71,	RADIUS_STRING,		"ARAP Features", NULL},
  {72,	RADIUS_INTEGER4,	"ARAP Zone-Access", NULL},
  {73,	RADIUS_INTEGER4,	"ARAP Security", NULL},
  {74,	RADIUS_STRING,		"ARAP Security Data", NULL},
  {75,	RADIUS_INTEGER4,	"Password Retry", NULL},
  {76,	RADIUS_INTEGER4,	"Prompt", NULL},
  {77,	RADIUS_STRING,		"Connect Info", NULL},
  {78,	RADIUS_STRING,		"Configuration Token", NULL},
  {79,	RADIUS_EAP_MESSAGE,	"EAP Message", NULL},
  {80,	RADIUS_BINSTRING,	"Message Authenticator", NULL},
  {81,	RADIUS_STRING_TAGGED,	"Tunnel Private Group ID", NULL},
  {82,	RADIUS_STRING_TAGGED,	"Tunnel Assignment ID", NULL},
  {83,	RADIUS_INTEGER4_TAGGED,	"Tunnel Preference", NULL},
  {84,	RADIUS_STRING,		"ARAP Challenge Response", NULL},
  {85,	RADIUS_INTEGER4,	"Acct Interim Interval", NULL},
  {86,	RADIUS_INTEGER4,	"Tunnel Packets Lost", NULL},
  {87,	RADIUS_STRING,		"NAS Port ID", NULL},
  {88,	RADIUS_STRING,		"Framed Pool", NULL},
  {90,	RADIUS_STRING_TAGGED,	"Tunnel Client Auth ID", NULL},
  {91,	RADIUS_STRING_TAGGED,	"Tunnel Server Auth ID", NULL},
  {120,	RADIUS_INTEGER4,	"Ascend Modem Port No", NULL},
  {121,	RADIUS_INTEGER4,	"Ascend Modem Slot No", NULL},
  {187,	RADIUS_INTEGER4,	"Ascend Multilink ID", NULL},
  {188,	RADIUS_INTEGER4,	"Ascend Num In Multilink", NULL},
  {189,	RADIUS_IP_ADDRESS,	"Ascend First Dest", NULL},
  {190,	RADIUS_INTEGER4,	"Ascend Pre Input Octets", NULL},
  {191,	RADIUS_INTEGER4,	"Ascend Pre Output Octets", NULL},
  {192,	RADIUS_INTEGER4,	"Ascend Pre Input Packets", NULL},
  {193,	RADIUS_INTEGER4,	"Ascend Pre Output Packets", NULL},
  {194,	RADIUS_INTEGER4,	"Ascend Maximum Time", NULL},
  {195,	RADIUS_INTEGER4,	"Ascend Disconnect Cause", NULL},
  {196,	RADIUS_INTEGER4,	"Ascend Connect Progress", NULL},
  {197,	RADIUS_INTEGER4,	"Ascend Data Rate", NULL},
  {198,	RADIUS_INTEGER4,	"Ascend PreSession Time", NULL},
  {218,	RADIUS_INTEGER4,	"Ascend Assign IP Pool", NULL},
  {255,	RADIUS_INTEGER4,	"Ascend Xmit Rate", NULL},
  {0, 0, NULL, NULL}
};

/*
reference:
	'dictionary.acc' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.acc
*/
static const value_string radius_vendor_acc_reason_code_vals[] =
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

static const value_string radius_vendor_acc_ccp_option_vals[] =
{
  {1,	"Disabled"},
  {2,	"Enabled"},
  {0, NULL}
};

static const value_string radius_vendor_acc_route_policy_vals[] =
{
  {1,	"Funnel"},
  {2,	"Direct"},
  {0, NULL}
};

static const value_string radius_vendor_acc_ml_mlx_admin_state_vals[] =
{
  {1,	"Enabled"},
  {2,	"Disabled"},
  {0, NULL}
};

static const value_string radius_vendor_acc_request_type_vals[] =
{
  {1,	"Ring Indication"},
  {2,	"Dial Request"},
  {3,	"User Authentification"},
  {4,	"Tunnel Authentification"},
  {0, NULL}
};

static const value_string radius_vendor_acc_bridging_support_vals[] =
{
  {1,	"Disabled"},
  {2,	"Enabled"},
  {0, NULL}
};

static const value_string radius_vendor_acc_apsm_oversubscribed_vals[] =
{
  {1,	"False"},
  {2,	"True"},
  {0, NULL}
};

static const value_string radius_vendor_acc_acct_on_off_reason_vals[] =
{
  {0,	"NAS Reset"},
  {1,	"NAS Reload"},
  {2,	"Configuration Reset"},
  {3,	"Configuration Reload"},
  {4,	"Enabled"},
  {5,	"Disabled"},
  {0, NULL}
};

static const value_string radius_vendor_acc_ip_compression_vals[] =
{
  {1,	"Disabled"},
  {2,	"Enabled"},
  {0, NULL}
};

static const value_string radius_vendor_acc_ipx_compression_vals[] =
{
  {1,	"Disabled"},
  {2,	"Enabled"},
  {0, NULL}
};

static const value_string radius_vendor_acc_callback_mode_vals[] =
{
  {0,	"User Auth"},
  {3,	"User Specified E.164"},
  {6,	"CBCP Callback"},
  {7,	"CLI Callback"},
  {0, NULL}
};

static const value_string radius_vendor_acc_callback_cbcp_type_vals[] =
{
  {1,	"CBCP None"},
  {2,	"CBCP User Specified"},
  {3,	"CBCP Pre Specified"},
  {0, NULL}
};

static const value_string radius_vendor_acc_dialout_auth_mode_vals[] =
{
  {1,	"PAP"},
  {2,	"CHAP"},
  {3,	"CHAP PAP"},
  {4,	"NONE"},
  {0, NULL}
};

static const value_string radius_vendor_acc_access_community_vals[] =
{
  {1,	"PUBLIC"},
  {2,	"NETMAN"},
  {0, NULL}
};

static const radius_attr_info radius_vendor_acc_attrib[] =
{
  {1,	RADIUS_INTEGER4,	"Acc Reason Code", radius_vendor_acc_reason_code_vals},
  {2,	RADIUS_INTEGER4,	"Acc Ccp Option", radius_vendor_acc_ccp_option_vals},
  {3,	RADIUS_INTEGER4,	"Acc Input Errors", NULL},
  {4,	RADIUS_INTEGER4,	"Acc Output Errors", NULL},
  {5,	RADIUS_STRING,		"Acc Access Partition", NULL},
  {6,	RADIUS_STRING,		"Acc Customer Id", NULL},
  {7,	RADIUS_IP_ADDRESS,	"Acc Ip Gateway Pri", NULL},
  {8,	RADIUS_IP_ADDRESS,	"Acc Ip Gateway Sec", NULL},
  {9,	RADIUS_INTEGER4,	"Acc Route Policy", radius_vendor_acc_route_policy_vals},
  {10,	RADIUS_INTEGER4,	"Acc ML MLX Admin State", radius_vendor_acc_ml_mlx_admin_state_vals},
  {11,	RADIUS_INTEGER4,	"Acc ML Call Threshold", NULL},
  {12,	RADIUS_INTEGER4,	"Acc ML Clear Threshold", NULL},
  {13,	RADIUS_INTEGER4,	"Acc ML Damping Factor", NULL},
  {14,	RADIUS_STRING,		"Acc Tunnel Secret", NULL},
  {15,	RADIUS_INTEGER4,	"Acc Clearing Cause", q931_cause_code_vals},
  {16,	RADIUS_INTEGER4,	"Acc Clearing Location", q931_cause_location_vals},
  {17,	RADIUS_STRING,		"Acc Service Profile", NULL},
  {18,	RADIUS_INTEGER4,	"Acc Request Type", radius_vendor_acc_request_type_vals},
  {19,	RADIUS_INTEGER4,	"Acc Bridging Support", radius_vendor_acc_bridging_support_vals},
  {20,	RADIUS_INTEGER4,	"Acc Apsm Oversubscribed", radius_vendor_acc_apsm_oversubscribed_vals},
  {21,	RADIUS_INTEGER4,	"Acc Acct On Off Reason", radius_vendor_acc_acct_on_off_reason_vals},
  {22,	RADIUS_INTEGER4,	"Acc Tunnel Port", NULL},
  {23,	RADIUS_IP_ADDRESS,	"Acc Dns Server Pri", NULL},
  {24,	RADIUS_IP_ADDRESS,	"Acc Dns Server Sec", NULL},
  {25,	RADIUS_IP_ADDRESS,	"Acc Nbns Server Pri", NULL},
  {26,	RADIUS_IP_ADDRESS,	"Acc Nbns Server Sec", NULL},
  {27,	RADIUS_INTEGER4,	"Acc Dial Port Index", NULL},
  {28,	RADIUS_INTEGER4,	"Acc Ip Compression", radius_vendor_acc_ip_compression_vals},
  {29,	RADIUS_INTEGER4,	"Acc Ipx Compression", radius_vendor_acc_ipx_compression_vals},
  {30,	RADIUS_INTEGER4,	"Acc Connect Tx Speed", NULL},
  {31,	RADIUS_INTEGER4,	"Acc Connect Rx Speed", NULL},
  {32,	RADIUS_STRING,		"Acc Modem Modulation Type", NULL},
  {33,	RADIUS_STRING,		"Acc Modem Error Protocol", NULL},
  {34,	RADIUS_INTEGER4,	"Acc Callback Delay", NULL},
  {35,	RADIUS_STRING,		"Acc Callback Num Valid", NULL},
  {36,	RADIUS_INTEGER4,	"Acc Callback Mode", radius_vendor_acc_callback_mode_vals},
  {37,	RADIUS_INTEGER4,	"Acc Callback CBCP Type", radius_vendor_acc_callback_cbcp_type_vals},
  {38,	RADIUS_INTEGER4,	"Acc Dialout Auth Mode", radius_vendor_acc_dialout_auth_mode_vals},
  {39,	RADIUS_STRING,		"Acc Dialout Auth Password", NULL},
  {40,	RADIUS_STRING,		"Acc Dialout Auth Username", NULL},
  {42,	RADIUS_INTEGER4,	"Acc Access Community", radius_vendor_acc_access_community_vals},
  {0, 0, NULL, NULL},
};

/*
references:
	'dictionary.cisco' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.cisco

	http://www.cisco.com/univercd/cc/td/doc/product/access/acs_serv/vapp_dev/vsaig3.htm

	http://www.cisco.com/univercd/cc/td/doc/product/software/ios122/122cgcr/fsecur_c/fappendx/fradattr/scfrdat3.pdf
	http://www.missl.cs.umd.edu/wireless/ethereal/cisco-vsa.pdf

*/
static const value_string radius_vendor_cisco_disconnect_cause_vals[] =
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

static const radius_attr_info radius_vendor_cisco_attrib[] =
{
  /* stanard attributes */
  {1,	RADIUS_STRING,		"Cisco AV Pair", NULL},
  {2,	RADIUS_STRING,		"Cisco NAS Port", NULL},
  /* fax */
  {3,	RADIUS_STRING,		"Fax Account Id Origin", NULL},
  {4,	RADIUS_STRING,		"Fax Msg Id", NULL},
  {5,	RADIUS_STRING,		"Fax Pages", NULL},
  {6,	RADIUS_STRING,		"Fax Cover Page Flag", NULL},
  {7,	RADIUS_STRING,		"Fax Modem Time", NULL},
  {8,	RADIUS_STRING,		"Fax Connect Speed", NULL},
  {9,	RADIUS_STRING,		"Fax Recipent Count", NULL},
  {10,	RADIUS_STRING,		"Fax Process Abort Flag", NULL},
  {11,	RADIUS_STRING,		"Fax DSN Address", NULL},
  {12,	RADIUS_STRING,		"Fax DSN Flag", NULL},
  {13,	RADIUS_STRING,		"Fax MDN Address", NULL},
  {14,	RADIUS_STRING,		"Fax MDN Flag", NULL},
  {15,	RADIUS_STRING,		"Fax Auth Status", NULL},
  {16,	RADIUS_STRING,		"Email Server Address", NULL},
  {17,	RADIUS_STRING,		"Email Server Ack Flag", NULL},
  {18,	RADIUS_STRING,		"Gateway Id", NULL},
  {19,	RADIUS_STRING,		"Call Type", NULL},
  {20,	RADIUS_STRING,		"Port Used", NULL},
  {21,	RADIUS_STRING,		"Abort Cause", NULL},
  /* #22 */
  /* H323 - Voice over IP attributes. */
  {23,	RADIUS_STRING,		"H323 Remote Address", NULL},
  {24,	RADIUS_STRING,		"H323 Conf Id", NULL},
  {25,	RADIUS_STRING,		"H323 Setup Time", NULL},
  {26,	RADIUS_STRING,		"H323 Call Origin", NULL},
  {27,	RADIUS_STRING,		"H323 Call Type", NULL},
  {28,	RADIUS_STRING,		"H323 Connect Time", NULL},
  {29,	RADIUS_STRING,		"H323 Disconnect Time", NULL},
  {30,	RADIUS_STRING,		"H323 Disconnect Cause", NULL},
  {31,	RADIUS_STRING,		"H323 Voice Quality", NULL},
  /* #32 */
  {33,	RADIUS_STRING,		"H323 GW Id", NULL},
  /* #34 */
  {35,	RADIUS_STRING,		"H323 Incoming Conf Id", NULL},
  /* #36-#100 */
  {101,	RADIUS_STRING,		"H323 Credit Amount", NULL},
  {102,	RADIUS_STRING,		"H323 Credit Time", NULL},
  {103,	RADIUS_STRING,		"H323 Return Code", NULL},
  {104,	RADIUS_STRING,		"H323 Prompt Id", NULL},
  {105,	RADIUS_STRING,		"H323 Time And Day", NULL},
  {106,	RADIUS_STRING,		"H323 Redirect Number", NULL},
  {107,	RADIUS_STRING,		"H323 Preferred Lang", NULL},
  {108,	RADIUS_STRING,		"H323 Redirect Ip Address", NULL},
  {109,	RADIUS_STRING,		"H323 Billing Model", NULL},
  {110,	RADIUS_STRING,		"H323 Currency Type", NULL},
  /* #111-#186 */
/*
       Extra attributes sent by the Cisco, if you configure
       "radius-server vsa accounting" (requires IOS11.2+).
*/
  {187,	RADIUS_INTEGER4,	"Cisco Multilink ID", NULL},
  {188,	RADIUS_INTEGER4,	"Cisco Num In Multilink", NULL},
  /* #189 */
  {190,	RADIUS_INTEGER4,	"Cisco Pre Input Octets", NULL},
  {191,	RADIUS_INTEGER4,	"Cisco Pre Output Octets", NULL},
  {192,	RADIUS_INTEGER4,	"Cisco Pre Input Packets", NULL},
  {193,	RADIUS_INTEGER4,	"Cisco Pre Output Packets", NULL},
  {194,	RADIUS_INTEGER4,	"Cisco Maximum Time", NULL},
  {195,	RADIUS_INTEGER4,	"Cisco Disconnect Cause", radius_vendor_cisco_disconnect_cause_vals},
  /* #196 */
  {197,	RADIUS_INTEGER4,	"Cisco Data Rate", NULL},
  {198,	RADIUS_INTEGER4,	"Cisco PreSession Time", NULL},
  /* #199-#207 */
  {208,	RADIUS_INTEGER4,	"Cisco PW Lifetime", NULL},
  {209,	RADIUS_INTEGER4,	"Cisco IP Direct", NULL},
  {210,	RADIUS_INTEGER4,	"Cisco PPP VJ Slot Comp", NULL},
  /* #211 */
  {212,	RADIUS_INTEGER4,	"Cisco PPP Async Map", NULL},
  /* #213-#216 */
  {217,	RADIUS_INTEGER4,	"Cisco IP Pool Definition", NULL},
  {218,	RADIUS_INTEGER4,	"Cisco Asing IP Pool", NULL},
  /* #219-#227 */
  {228,	RADIUS_INTEGER4,	"Cisco Route IP", NULL},
  /* #229-#232 */
  {233,	RADIUS_INTEGER4,	"Cisco Link Compression", NULL},
  {234,	RADIUS_INTEGER4,	"Cisco Target Util", NULL},
  {235,	RADIUS_INTEGER4,	"Cisco Maximum Channels", NULL},
  /* #236-#241 */
  {242,	RADIUS_INTEGER4,	"Cisco Data Filter", NULL},
  {243,	RADIUS_INTEGER4,	"Cisco Call Filter", NULL},
  {244,	RADIUS_INTEGER4,	"Cisco Idle Limit", NULL},
  /* Cisco SSG Service Selection Gateway Attributes */
  {250, RADIUS_STRING,		"Cisco Account Info", NULL},
  {251, RADIUS_STRING,		"Cisco Service Info", NULL},
  {252, RADIUS_BINSTRING,	"Cisco Command Info", NULL},
  {253, RADIUS_STRING,		"Cisco Control Info", NULL},
  {255,	RADIUS_INTEGER4,	"Cisco Xmit Rate", NULL},
  {0, 0, NULL, NULL}
};

/*
reference:
	'dictionary.shiva' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.shiva
*/
static const value_string radius_vendor_shiva_type_of_service_vals[] =
{
  {1,	"Analog"},
  {2,	"Digitized Analog"},
  {3,	"Digital"},
  {4,	"Digital V.110"},
  {5,	"Digital V.120"},
  {6,	"Digital Leased Line"},
  {0, NULL}
};

static const value_string radius_vendor_shiva_link_protocol_vals[] =
{
  {1,	"HDLC"},
  {2,	"ARAV1"},
  {3,	"ARAV2"},
  {4,	"SHELL"},
  {5,	"AALAP"},
  {6,	"SLIP"},
  {0, NULL}
};

static const value_string radius_vendor_shiva_disconnect_reason_vals[] =
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

static const value_string radius_vendor_shiva_function_vals[] =
{
  {0,	"Unknown"},
  {1,	"Dialin"},
  {2,	"Dialout"},
  {3,	"Lan To Lan"},
  {0, NULL}
};

static const value_string radius_vendor_shiva_connect_reason_vals[] =
{
  {1,	"Remote"},
  {2,	"Dialback"},
  {3,	"Virtual Connection"},
  {4,	"Bandwidth On Demand"},
  {0, NULL}
};

static const radius_attr_info radius_vendor_shiva_attrib[] =
{
  {1,	RADIUS_STRING,		"Shiva User Attributes", NULL},
  {90,	RADIUS_STRING,		"Shiva Called Number", NULL},
  {91,	RADIUS_STRING,		"Shiva Calling Number", NULL},
  {92,	RADIUS_STRING,		"Shiva Customer Id", NULL},
  {93,	RADIUS_INTEGER4,	"Shiva Type Of Service", radius_vendor_shiva_type_of_service_vals},
  {94,	RADIUS_INTEGER4,	"Shiva Link Speed", NULL},
  {95,	RADIUS_INTEGER4,	"Shiva Links In Bundle", NULL},
  {96,	RADIUS_INTEGER4,	"Shiva Compression Type", NULL},
  {97,	RADIUS_INTEGER4,	"Shiva Link Protocol", radius_vendor_shiva_link_protocol_vals},
  {98,	RADIUS_INTEGER4,	"Shiva Network Protocols", NULL},
  {99,	RADIUS_INTEGER4,	"Shiva Session Id", NULL},
  {100,	RADIUS_INTEGER4,	"Shiva Disconnect Reason", radius_vendor_shiva_disconnect_reason_vals},
  {101,	RADIUS_IP_ADDRESS,	"Shiva Acct Serv Switch", NULL},
  {102,	RADIUS_INTEGER4,	"Shiva Event Flags", NULL},
  {103,	RADIUS_INTEGER4,	"Shiva Function", radius_vendor_shiva_function_vals},
  {104,	RADIUS_INTEGER4,	"Shiva Connect Reason", radius_vendor_shiva_connect_reason_vals},
  {0, 0, NULL, NULL},
};

/*
reference:
	'dictionary.livingston' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.livingston
*/
static const value_string radius_vendor_livingston_ipsec_log_options_vals[] =
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

static const value_string radius_vendor_livingston_ipsec_deny_action_vals[] =
{
  {1,	"Drop"},
  {2,	"ICMP Reject"},
  {3,	"Pass Through"},
  {0, NULL}
};

static const value_string radius_vendor_livingston_nat_log_options_vals[] =
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

static const value_string radius_vendor_livingston_nat_sess_dir_fail_action_vals[] =
{
  {1,	"Drop"},
  {2,	"ICMP Reject"},
  {3,	"Pass Through"},
  {0, NULL}
};

static const value_string radius_vendor_livingston_multicast_client_vals[] =
{
  {1,	"On"},
  {0, NULL}
};

static const radius_attr_info radius_vendor_livingston_attrib[] =
{
  {2,	RADIUS_STRING,		"LE Terminate Detail", NULL},
  {3,	RADIUS_STRING,		"LE Advice of Charge", NULL},
  {4,	RADIUS_STRING,		"LE Connect Detail", NULL},
  {6,	RADIUS_STRING,		"LE IP Pool", NULL},
  {7,	RADIUS_IP_ADDRESS,	"LE IP Gateway", NULL},
  {8,	RADIUS_STRING,		"LE Modem Info", NULL},
  {9,	RADIUS_INTEGER4,	"LE IPSec Log Options", radius_vendor_livingston_ipsec_log_options_vals},
  {10,	RADIUS_INTEGER4,	"LE IPSec Deny Action", radius_vendor_livingston_ipsec_deny_action_vals},
  {11,	RADIUS_STRING,		"LE IPSec Active Profile", NULL},
  {12,	RADIUS_STRING,		"LE IPSec Outsource Profile", NULL},
  {13,	RADIUS_STRING,		"LE IPSec Passive Profile", NULL},
  {14,	RADIUS_INTEGER4,	"LE NAT TCP Session Timeout", NULL},
  {15,	RADIUS_INTEGER4,	"LE NAT Other Session Timeout", NULL},
  {16,	RADIUS_INTEGER4,	"LE NAT Log Options", radius_vendor_livingston_nat_log_options_vals},
  {17,	RADIUS_INTEGER4,	"LE NAT Sess Dir Fail Action", radius_vendor_livingston_nat_sess_dir_fail_action_vals},
  {18,	RADIUS_STRING,		"LE NAT Inmap", NULL},
  {19,	RADIUS_STRING,		"LE NAT Outmap", NULL},
  {20,	RADIUS_STRING,		"LE NAT Outsource Inmap", NULL},
  {21,	RADIUS_STRING,		"LE NAT Outsource Outmap", NULL},
  {22,	RADIUS_STRING,		"LE Admin Group", NULL},
  {23,	RADIUS_INTEGER4,	"LE Multicast Client", radius_vendor_livingston_multicast_client_vals},
  {0, 0, NULL, NULL},
};

static const value_string radius_vendor_microsoft_bap_usage_vals[] =
{
  {0,	"Not Allowed"},
  {1,	"Allowed"},
  {2,	"Required"},
  {0, NULL}
};

static const value_string radius_vendor_microsoft_arap_pw_change_reason_vals[] =
{
  {1,	"Just Change Password"},
  {2,	"Expired Password"},
  {3,	"Admin Required Password Change"},
  {4,	"Password Too Short"},
  {0, NULL}
};

static const value_string radius_vendor_microsoft_acct_auth_type_vals[] =
{
  {1,	"PAP"},
  {2,	"CHAP"},
  {3,	"MS CHAP 1"},
  {4,	"MS CHAP 2"},
  {5,	"EAP"},
  {0, NULL}
};

static const value_string radius_vendor_microsoft_acct_eap_type_vals[] =
{
  {4,	"MD5"},
  {5,	"OTP"},
  {6,	"Generic Token Card"},
  {13,	"TLS"},
  {0, NULL}
};

static const radius_attr_info radius_vendor_microsoft_attrib[] =
{
  {1,	RADIUS_BINSTRING,	"MS CHAP Response", NULL},
  {2,	RADIUS_STRING,		"MS CHAP Error", NULL},
  {3,	RADIUS_BINSTRING,	"MS CHAP CPW 1", NULL},
  {4,	RADIUS_BINSTRING,	"MS CHAP CPW 2", NULL},
  {5,	RADIUS_BINSTRING,	"MS CHAP LM Enc PW", NULL},
  {6,	RADIUS_BINSTRING,	"MS CHAP NT Enc PW", NULL},
  {7,	RADIUS_BINSTRING,	"MS MPPE Encryption Policy", NULL},
  {8,	RADIUS_BINSTRING,	"MS MPPE Encryption Type", NULL},
  {9,	RADIUS_INTEGER4,	"MS RAS Vendor", NULL},
  {10,	RADIUS_STRING,		"MS CHAP Domain", NULL},
  {11,	RADIUS_BINSTRING,	"MS CHAP Challenge", NULL},
  {12,	RADIUS_BINSTRING,	"MS CHAP MPPE Keys", NULL},
  {13,	RADIUS_INTEGER4,	"MS BAP Usage", radius_vendor_microsoft_bap_usage_vals},
  {14,	RADIUS_INTEGER4,	"MS Link Utilization Threshold", NULL},
  {15,	RADIUS_INTEGER4,	"MS Link Drop Time Limit", NULL},
  {16,	RADIUS_BINSTRING,	"MS MPPE Send Key", NULL},
  {17,	RADIUS_BINSTRING,	"MS MPPE Recv Key", NULL},
  {18,	RADIUS_STRING,		"MS RAS Version", NULL},
  {19,	RADIUS_BINSTRING,	"MS Old ARAP Password", NULL},
  {20,	RADIUS_BINSTRING,	"MS New ARAP Password", NULL},
  {21,	RADIUS_INTEGER4,	"MS ARAP PW Change Reason", radius_vendor_microsoft_arap_pw_change_reason_vals},
  {22,	RADIUS_BINSTRING,	"MS Filter", NULL},
  {23,	RADIUS_INTEGER4,	"MS Acct Auth Type", radius_vendor_microsoft_acct_auth_type_vals},
  {24,	RADIUS_INTEGER4,	"MS Acct EAP Type", radius_vendor_microsoft_acct_eap_type_vals},
  {25,	RADIUS_BINSTRING,	"MS CHAP2 Response", NULL},
  {26,	RADIUS_BINSTRING,	"MS CHAP2 Success", NULL},
  {27,	RADIUS_BINSTRING,	"MS CHAP2 CPW", NULL},
  {28,	RADIUS_IP_ADDRESS,	"MS Primary DNS Server", NULL},
  {29,	RADIUS_IP_ADDRESS,	"MS Secondary DNS Server", NULL},
  {30,	RADIUS_IP_ADDRESS,	"MS Primary NBNS Server", NULL},
  {31,	RADIUS_IP_ADDRESS,	"MS Secondary NBNS Server", NULL},
  {0, 0, NULL, NULL}
};

static const value_string radius_vendor_ascend_calling_id_type_of_number_vals[] =
{
  {0,	"Unknown"},
  {1,	"International Number"},
  {2,	"National Number"},
  {3,	"Network Specific"},
  {4,	"Subscriber Number"},
  {6,	"Abbreviated Number"},
  {0, NULL}
};

static const value_string radius_vendor_ascend_calling_id_numbering_plan_vals[] =
{
  {0,	"Unknown"},
  {1,	"ISDN Telephony"},
  {3,	"Data"},
  {4,	"Telex"},
  {8,	"National"},
  {9,	"Private"},
  {0, NULL}
};

static const value_string radius_vendor_ascend_calling_id_presentation_vals[] =
{
  {0,	"Allowed"},
  {1,	"Restricted"},
  {2,	"Number Not Available"},
  {0, NULL}
};

static const value_string radius_vendor_ascend_calling_id_screening_vals[] =
{
  {0,	"User Not Screened"},
  {1,	"User Provided Passed"},
  {2,	"User Provided Failed"},
  {3,	"Network Provided"},
  {0, NULL}
};

static const radius_attr_info radius_vendor_ascend_attrib[] =
{
  {7,	RADIUS_STRING,		"Ascend UU Info", NULL},
  {9,	RADIUS_INTEGER4,	"Ascend CIR Timer", NULL},
  {10,	RADIUS_INTEGER4,	"Ascend FR 08 Mode", NULL},
  {11,	RADIUS_INTEGER4,	"Ascend Destination Nas Port", NULL},
  {12,	RADIUS_STRING,		"Ascend FR SVC Addr", NULL},
  {13,	RADIUS_INTEGER4,	"Ascend NAS Port Format", NULL},
  {14,	RADIUS_INTEGER4,	"Ascend ATM Fault Management", NULL},
  {15,	RADIUS_INTEGER4,	"Ascend ATM Loopback Cell Loss", NULL},
  {16,	RADIUS_INTEGER4,	"Ascend Ckt Type", NULL},
  {17,	RADIUS_INTEGER4,	"Ascend SVC Enabled", NULL},
  {18,	RADIUS_INTEGER4,	"Ascend Session Type", NULL},
  {19,	RADIUS_IP_ADDRESS,	"Ascend H323 Gatekeeper", NULL},
  {20,	RADIUS_STRING,		"Ascend Global Call Id", NULL},
  {21,	RADIUS_INTEGER4,	"Ascend H323 Conference Id", NULL},
  {22,	RADIUS_IP_ADDRESS,	"Ascend H323 Fegw Address", NULL},
  {23,	RADIUS_INTEGER4,	"Ascend H323 Dialed Time", NULL},
  {24,	RADIUS_STRING,		"Ascend Dialed Number", NULL},
  {25,	RADIUS_INTEGER4,	"Ascend Inter Arrival Jitter", NULL},
  {26,	RADIUS_INTEGER4,	"Ascend Dropped Octets", NULL},
  {27,	RADIUS_INTEGER4,	"Ascend Dropped Packets", NULL},
  {29,	RADIUS_INTEGER4,	"Ascend X25 Pad X3 Profile", NULL},
  {30,	RADIUS_STRING,		"Ascend X25 Pad X3 Parameters", NULL},
  {31,	RADIUS_STRING,		"Ascend Tunnel VRouter Name", NULL},
  {32,	RADIUS_INTEGER4,	"Ascend X25 Reverse Charging", NULL},
  {33,	RADIUS_STRING,		"Ascend X25 Nui Prompt", NULL},
  {34,	RADIUS_STRING,		"Ascend X25 Nui Password Prompt", NULL},
  {35,	RADIUS_STRING,		"Ascend X25 Cug", NULL},
  {36,	RADIUS_STRING,		"Ascend X25 Pad Alias 1", NULL},
  {37,	RADIUS_STRING,		"Ascend X25 Pad Alias 2", NULL},
  {38,	RADIUS_STRING,		"Ascend X25 Pad Alias 3", NULL},
  {39,	RADIUS_STRING,		"Ascend X25 X121 Address", NULL},
  {40,	RADIUS_STRING,		"Ascend X25 Nui", NULL},
  {41,	RADIUS_STRING,		"Ascend X25 Rpoa", NULL},
  {42,	RADIUS_STRING,		"Ascend X25 Pad Prompt", NULL},
  {43,	RADIUS_STRING,		"Ascend X25 Pad Banner", NULL},
  {44,	RADIUS_STRING,		"Ascend X25 Profile Name", NULL},
  {45,	RADIUS_STRING,		"Ascend Recv Name", NULL},
  {46,	RADIUS_INTEGER4,	"Ascend Bi Directional Auth", NULL},
  {47,	RADIUS_INTEGER4,	"Ascend MTU", NULL},
  {48,	RADIUS_INTEGER4,	"Ascend Call Direction", NULL},
  {49,	RADIUS_INTEGER4,	"Ascend Service Type", NULL},
  {50,	RADIUS_INTEGER4,	"Ascend Filter Required", NULL},
  {51,	RADIUS_INTEGER4,	"Ascend Traffic Shaper", NULL},
  {52,	RADIUS_STRING,		"Ascend Access Intercept LEA", NULL},
  {53,	RADIUS_STRING,		"Ascend Access Intercept Log", NULL},
  {54,	RADIUS_STRING,		"Ascend Private Route Table ID", NULL},
  {55,	RADIUS_INTEGER4,	"Ascend Private Route Required", NULL},
  {56,	RADIUS_INTEGER4,	"Ascend Cache Refresh", NULL},
  {57,	RADIUS_INTEGER4,	"Ascend Cache Time", NULL},
  {58,	RADIUS_INTEGER4,	"Ascend Egress Enabled", NULL},
  {59,	RADIUS_STRING,		"Ascend QOS Upstream", NULL},
  {60,	RADIUS_STRING,		"Ascend QOS Downstream", NULL},
  {61,	RADIUS_INTEGER4,	"Ascend ATM Connect Vpi", NULL},
  {62,	RADIUS_INTEGER4,	"Ascend ATM Connect Vci", NULL},
  {63,	RADIUS_INTEGER4,	"Ascend ATM Connect Group", NULL},
  {64,	RADIUS_INTEGER4,	"Ascend ATM Group", NULL},
  {65,	RADIUS_INTEGER4,	"Ascend IPX Header Compression", NULL},
  {66,	RADIUS_INTEGER4,	"Ascend Calling Id Type Of Number", radius_vendor_ascend_calling_id_type_of_number_vals},
  {67,	RADIUS_INTEGER4,	"Ascend Calling Id Numbering Plan", radius_vendor_ascend_calling_id_numbering_plan_vals},
  {68,	RADIUS_INTEGER4,	"Ascend Calling Id Presentation", radius_vendor_ascend_calling_id_presentation_vals},
  {69,	RADIUS_INTEGER4,	"Ascend Calling Id Screening", radius_vendor_ascend_calling_id_screening_vals},
  {70,	RADIUS_INTEGER4,	"Ascend BIR Enable", NULL},
  {71,	RADIUS_INTEGER4,	"Ascend BIR Proxy", NULL},
  {72,	RADIUS_INTEGER4,	"Ascend BIR Bridge Group", NULL},
  {73,	RADIUS_STRING,		"Ascend IPSEC Profile", NULL},
  {74,	RADIUS_INTEGER4,	"Ascend PPPoE Enable", NULL},
  {75,	RADIUS_INTEGER4,	"Ascend Bridge Non PPPoE", NULL},
  {76,	RADIUS_INTEGER4,	"Ascend ATM Direct", NULL},
  {77,	RADIUS_STRING,		"Ascend ATM Direct Profile", NULL},
  {78,	RADIUS_IP_ADDRESS,	"Ascend Client Primary WINS", NULL},
  {79,	RADIUS_IP_ADDRESS,	"Ascend Client Secondary WINS", NULL},
  {80,	RADIUS_INTEGER4,	"Ascend Client Assign WINS", NULL},
  {81,	RADIUS_INTEGER4,	"Ascend Auth Type", NULL},
  {82,	RADIUS_INTEGER4,	"Ascend Port Redir Protocol", NULL},
  {83,	RADIUS_INTEGER4,	"Ascend Port Redir Portnum", NULL},
  {84,	RADIUS_IP_ADDRESS,	"Ascend Port Redir Server", NULL},
  {85,	RADIUS_INTEGER4,	"Ascend IP Pool Chaining", NULL},
  {86,	RADIUS_IP_ADDRESS,	"Ascend Owner IP Addr", NULL},
  {87,	RADIUS_INTEGER4,	"Ascend IP TOS", NULL},
  {88,	RADIUS_INTEGER4,	"Ascend IP TOS Precedence", NULL},
  {89,	RADIUS_INTEGER4,	"Ascend IP TOS Apply To", NULL},
  {90,	RADIUS_STRING,		"Ascend Filter", NULL},
  {91,	RADIUS_STRING,		"Ascend Telnet Profile", NULL},
  {92,	RADIUS_INTEGER4,	"Ascend Dsl Rate Type", NULL},
  {93,	RADIUS_STRING,		"Ascend Redirect Number", NULL},
  {94,	RADIUS_INTEGER4,	"Ascend ATM Vpi", NULL},
  {95,	RADIUS_INTEGER4,	"Ascend ATM Vci", NULL},
  {96,	RADIUS_INTEGER4,	"Ascend Source IP Check", NULL},
  {97,	RADIUS_INTEGER4,	"Ascend Dsl Rate Mode", NULL},
  {98,	RADIUS_INTEGER4,	"Ascend Dsl Upstream Limit", NULL},
  {99,	RADIUS_INTEGER4,	"Ascend Dsl Downstream Limit", NULL},
  {100,	RADIUS_INTEGER4,	"Ascend Dsl CIR Recv Limit", NULL},
  {101,	RADIUS_INTEGER4,	"Ascend Dsl CIR Xmit Limit", NULL},
  {102,	RADIUS_STRING,		"Ascend VRouter Name", NULL},
  {103,	RADIUS_STRING,		"Ascend Source Auth", NULL},
  {104,	RADIUS_STRING,		"Ascend Private Route", NULL},
  {105,	RADIUS_INTEGER4,	"Ascend Numbering Plan ID", NULL},
  {106,	RADIUS_INTEGER4,	"Ascend FR Link Status DLCI", NULL},
  {107,	RADIUS_STRING,		"Ascend Calling Subaddress", NULL},
  {108,	RADIUS_INTEGER4,	"Ascend Callback Delay", NULL},
  {109,	RADIUS_STRING,		"Ascend Endpoint Disc", NULL},
  {110,	RADIUS_STRING,		"Ascend Remote FW", NULL},
  {111,	RADIUS_INTEGER4,	"Ascend Multicast GLeave Delay", NULL},
  {112,	RADIUS_INTEGER4,	"Ascend CBCP Enable", NULL},
  {113,	RADIUS_INTEGER4,	"Ascend CBCP Mode", NULL},
  {114,	RADIUS_INTEGER4,	"Ascend CBCP Delay", NULL},
  {115,	RADIUS_INTEGER4,	"Ascend CBCP Trunk Group", NULL},
  {116,	RADIUS_STRING,		"Ascend Appletalk Route", NULL},
  {117,	RADIUS_INTEGER4,	"Ascend Appletalk Peer Mode", NULL},
  {118,	RADIUS_INTEGER4,	"Ascend Route Appletalk", NULL},
  {119,	RADIUS_STRING,		"Ascend FCP Parameter", NULL},
  {120,	RADIUS_INTEGER4,	"Ascend Modem Port No", NULL},
  {121,	RADIUS_INTEGER4,	"Ascend Modem Slot No", NULL},
  {122,	RADIUS_INTEGER4,	"Ascend Modem Shelf No", NULL},
  {123,	RADIUS_INTEGER4,	"Ascend Call Attempt Limit", NULL},
  {124,	RADIUS_INTEGER4,	"Ascend Call Block Duration", NULL},
  {125,	RADIUS_INTEGER4,	"Ascend Maximum Call Duration", NULL},
  {126,	RADIUS_INTEGER4,	"Ascend Temporary Rtes", NULL},
  {127,	RADIUS_INTEGER4,	"Ascend Tunneling Protocol", NULL},
  {128,	RADIUS_INTEGER4,	"Ascend Shared Profile Enable", NULL},
  {129,	RADIUS_STRING,		"Ascend Primary Home Agent", NULL},
  {130,	RADIUS_STRING,		"Ascend Secondary Home Agent", NULL},
  {131,	RADIUS_INTEGER4,	"Ascend Dialout Allowed", NULL},
  {132,	RADIUS_IP_ADDRESS,	"Ascend Client Gateway", NULL},
  {133,	RADIUS_INTEGER4,	"Ascend BACP Enable", NULL},
  {134,	RADIUS_INTEGER4,	"Ascend DHCP Maximum Leases", NULL},
  {135,	RADIUS_IP_ADDRESS,	"Ascend Client Primary DNS", NULL},
  {136,	RADIUS_IP_ADDRESS,	"Ascend Client Secondary DNS", NULL},
  {137,	RADIUS_INTEGER4,	"Ascend Client Assign DNS", NULL},
  {138,	RADIUS_INTEGER4,	"Ascend User Acct Type", NULL},
  {139,	RADIUS_IP_ADDRESS,	"Ascend User Acct Host", NULL},
  {140,	RADIUS_INTEGER4,	"Ascend User Acct Port", NULL},
  {141,	RADIUS_STRING,		"Ascend User Acct Key", NULL},
  {142,	RADIUS_INTEGER4,	"Ascend User Acct Base", NULL},
  {143,	RADIUS_INTEGER4,	"Ascend User Acct Time", NULL},
  {144,	RADIUS_IP_ADDRESS,	"Ascend Assign IP Client", NULL},
  {145,	RADIUS_IP_ADDRESS,	"Ascend Assign IP Server", NULL},
  {146,	RADIUS_STRING,		"Ascend Assign IP Global Pool", NULL},
  {147,	RADIUS_INTEGER4,	"Ascend DHCP Reply", NULL},
  {148,	RADIUS_INTEGER4,	"Ascend DHCP Pool Number", NULL},
  {149,	RADIUS_INTEGER4,	"Ascend Expect Callback", NULL},
  {150,	RADIUS_INTEGER4,	"Ascend Event Type", NULL},
  {151,	RADIUS_STRING,		"Ascend Session Svr Key", NULL},
  {152,	RADIUS_INTEGER4,	"Ascend Multicast Rate Limit", NULL},
  {153,	RADIUS_IP_ADDRESS,	"Ascend IF Netmask", NULL},
  {154,	RADIUS_IP_ADDRESS,	"Ascend Remote Addr", NULL},
  {155,	RADIUS_INTEGER4,	"Ascend Multicast Client", NULL},
  {156,	RADIUS_STRING,		"Ascend FR Circuit Name", NULL},
  {157,	RADIUS_INTEGER4,	"Ascend FR LinkUp", NULL},
  {158,	RADIUS_INTEGER4,	"Ascend FR Nailed Grp", NULL},
  {159,	RADIUS_INTEGER4,	"Ascend FR Type", NULL},
  {160,	RADIUS_INTEGER4,	"Ascend FR Link Mgt", NULL},
  {161,	RADIUS_INTEGER4,	"Ascend FR N391", NULL},
  {162,	RADIUS_INTEGER4,	"Ascend FR DCE N392", NULL},
  {163,	RADIUS_INTEGER4,	"Ascend FR DTE N392", NULL},
  {164,	RADIUS_INTEGER4,	"Ascend FR DCE N393", NULL},
  {165,	RADIUS_INTEGER4,	"Ascend FR DTE N393", NULL},
  {166,	RADIUS_INTEGER4,	"Ascend FR T391", NULL},
  {167,	RADIUS_INTEGER4,	"Ascend FR T392", NULL},
  {168,	RADIUS_STRING,		"Ascend Bridge Address", NULL},
  {169,	RADIUS_INTEGER4,	"Ascend TS Idle Limit", NULL},
  {170,	RADIUS_INTEGER4,	"Ascend TS Idle Mode", NULL},
  {171,	RADIUS_INTEGER4,	"Ascend DBA Monitor", NULL},
  {172,	RADIUS_INTEGER4,	"Ascend Base Channel Count", NULL},
  {173,	RADIUS_INTEGER4,	"Ascend Minimum Channels", NULL},
  {174,	RADIUS_STRING,		"Ascend IPX Route", NULL},
  {175,	RADIUS_INTEGER4,	"Ascend FT1 Caller", NULL},
  {176,	RADIUS_STRING,		"Ascend Backup", NULL},
  {177,	RADIUS_INTEGER4,	"Ascend Call Type", NULL},
  {178,	RADIUS_STRING,		"Ascend Group", NULL},
  {179,	RADIUS_INTEGER4,	"Ascend FR DLCI", NULL},
  {180,	RADIUS_STRING,		"Ascend FR Profile Name", NULL},
  {181,	RADIUS_STRING,		"Ascend Ara PW", NULL},
  {182,	RADIUS_STRING,		"Ascend IPX Node Addr", NULL},
  {183,	RADIUS_IP_ADDRESS,	"Ascend Home Agent IP Addr", NULL},
  {184,	RADIUS_STRING,		"Ascend Home Agent Password", NULL},
  {185,	RADIUS_STRING,		"Ascend Home Network Name", NULL},
  {186,	RADIUS_INTEGER4,	"Ascend Home Agent UDP Port", NULL},
  {187,	RADIUS_INTEGER4,	"Ascend Multilink ID", NULL},
  {188,	RADIUS_INTEGER4,	"Ascend Num In Multilink", NULL},
  {189,	RADIUS_IP_ADDRESS,	"Ascend First Dest", NULL},
  {190,	RADIUS_INTEGER4,	"Ascend Pre Input Octets", NULL},
  {191,	RADIUS_INTEGER4,	"Ascend Pre Output Octets", NULL},
  {192,	RADIUS_INTEGER4,	"Ascend Pre Input Packets", NULL},
  {193,	RADIUS_INTEGER4,	"Ascend Pre Output Packets", NULL},
  {194,	RADIUS_INTEGER4,	"Ascend Maximum Time", NULL},
  {195,	RADIUS_INTEGER4,	"Ascend Disconnect Cause", NULL},
  {196,	RADIUS_INTEGER4,	"Ascend Connect Progress", NULL},
  {197,	RADIUS_INTEGER4,	"Ascend Data Rate", NULL},
  {198,	RADIUS_INTEGER4,	"Ascend PreSession Time", NULL},
  {199,	RADIUS_INTEGER4,	"Ascend Token Idle", NULL},
  {200,	RADIUS_INTEGER4,	"Ascend Token Immediate", NULL},
  {201,	RADIUS_INTEGER4,	"Ascend Require Auth", NULL},
  {202,	RADIUS_STRING,		"Ascend Number Sessions", NULL},
  {203,	RADIUS_STRING,		"Ascend Authen Alias", NULL},
  {204,	RADIUS_INTEGER4,	"Ascend Token Expiry", NULL},
  {205,	RADIUS_STRING,		"Ascend Menu Selector", NULL},
  {206,	RADIUS_STRING,		"Ascend Menu Item", NULL},
  {207,	RADIUS_INTEGER4,	"Ascend PW Warntime", NULL},
  {208,	RADIUS_INTEGER4,	"Ascend PW Lifetime", NULL},
  {209,	RADIUS_IP_ADDRESS,	"Ascend IP Direct", NULL},
  {210,	RADIUS_INTEGER4,	"Ascend PPP VJ Slot Comp", NULL},
  {211,	RADIUS_INTEGER4,	"Ascend PPP VJ 1172", NULL},
  {212,	RADIUS_INTEGER4,	"Ascend PPP Async Map", NULL},
  {213,	RADIUS_STRING,		"Ascend Third Prompt", NULL},
  {214,	RADIUS_STRING,		"Ascend Send Secret", NULL},
  {215,	RADIUS_STRING,		"Ascend Receive Secret", NULL},
  {216,	RADIUS_INTEGER4,	"Ascend IPX Peer Mode", NULL},
  {217,	RADIUS_STRING,		"Ascend IP Pool Definition", NULL},
  {218,	RADIUS_INTEGER4,	"Ascend Assign IP Pool", NULL},
  {219,	RADIUS_INTEGER4,	"Ascend FR Direct", NULL},
  {220,	RADIUS_STRING,		"Ascend FR Direct Profile", NULL},
  {221,	RADIUS_INTEGER4,	"Ascend FR Direct DLCI", NULL},
  {222,	RADIUS_INTEGER4,	"Ascend Handle IPX", NULL},
  {223,	RADIUS_INTEGER4,	"Ascend Netware timeout", NULL},
  {224,	RADIUS_INTEGER4,	"Ascend IPX Alias", NULL},
  {225,	RADIUS_INTEGER4,	"Ascend Metric", NULL},
  {226,	RADIUS_INTEGER4,	"Ascend PRI Number Type", NULL},
  {227,	RADIUS_STRING,		"Ascend Dial Number", NULL},
  {228,	RADIUS_INTEGER4,	"Ascend Route IP", NULL},
  {229,	RADIUS_INTEGER4,	"Ascend Route IPX", NULL},
  {230,	RADIUS_INTEGER4,	"Ascend Bridge", NULL},
  {231,	RADIUS_INTEGER4,	"Ascend Send Auth", NULL},
  {232,	RADIUS_STRING,		"Ascend Send Passwd", NULL},
  {233,	RADIUS_INTEGER4,	"Ascend Link Compression", NULL},
  {234,	RADIUS_INTEGER4,	"Ascend Target Util", NULL},
  {235,	RADIUS_INTEGER4,	"Ascend Maximum Channels", NULL},
  {236,	RADIUS_INTEGER4,	"Ascend Inc Channel Count", NULL},
  {237,	RADIUS_INTEGER4,	"Ascend Dec Channel Count", NULL},
  {238,	RADIUS_INTEGER4,	"Ascend Seconds Of History", NULL},
  {239,	RADIUS_INTEGER4,	"Ascend History Weigh Type", NULL},
  {240,	RADIUS_INTEGER4,	"Ascend Add Seconds", NULL},
  {241,	RADIUS_INTEGER4,	"Ascend Remove Seconds", NULL},
  {242,	RADIUS_BINSTRING,	"Ascend Data Filter", NULL},
  {243,	RADIUS_BINSTRING,	"Ascend Call Filter", NULL},
  {244,	RADIUS_INTEGER4,	"Ascend Idle Limit", NULL},
  {245,	RADIUS_INTEGER4,	"Ascend Preempt Limit", NULL},
  {246,	RADIUS_INTEGER4,	"Ascend Callback", NULL},
  {247,	RADIUS_INTEGER4,	"Ascend Data Svc", NULL},
  {248,	RADIUS_INTEGER4,	"Ascend Force 56", NULL},
  {249,	RADIUS_STRING,		"Ascend Billing Number", NULL},
  {250,	RADIUS_INTEGER4,	"Ascend Call By Call", NULL},
  {251,	RADIUS_STRING,		"Ascend Transit Number", NULL},
  {252,	RADIUS_STRING,		"Ascend Host Info", NULL},
  {253,	RADIUS_IP_ADDRESS,	"Ascend PPP Address", NULL},
  {254,	RADIUS_INTEGER4,	"Ascend MPP Idle Percent", NULL},
  {255,	RADIUS_INTEGER4,	"Ascend Xmit Rate", NULL},
  {0, 0, NULL, NULL}
};

/*
reference:
	'dictionary.bay' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.bay
*/
static const value_string radius_vendor_bay_tunnel_authen_type_vals[] =
{
  {0,	"none"},
  {1,	"kmd5 128"},
  {0, NULL}
};

static const value_string radius_vendor_bay_tunnel_authen_mode_vals[] =
{
  {0,	"none"},
  {1,	"prefix suffix"},
  {0, NULL}
};

static const value_string radius_vendor_bay_user_server_location_vals[] =
{
  {1,	"local"},
  {2,	"remote"},
  {0, NULL}
};

static const value_string radius_vendor_bay_system_disc_reason_vals[] =
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

static const value_string radius_vendor_bay_modem_disc_reason_vals[] =
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

static const value_string radius_vendor_bay_addr_resolution_protocol_vals[] =
{
  {0,	"none"},
  {1,	"DHCP"},
  {0, NULL}
};

static const value_string radius_vendor_bay_user_level_vals[] =
{
  {2,	"Manager"},
  {4,	"User"},
  {8,	"Operator"},
  {0, NULL}
};

static const value_string radius_vendor_bay_audit_level_vals[] =
{
  {2,	"Manager"},
  {4,	"User"},
  {8,	"Operator"},
  {0, NULL}
};

static const radius_attr_info radius_vendor_bay_attrib[] =
{
  {28,	RADIUS_STRING,		"Annex Filter", NULL},
  {29,	RADIUS_STRING,		"Annex CLI Command", NULL},
  {30,	RADIUS_STRING,		"Annex CLI Filter", NULL},
  {31,	RADIUS_STRING,		"Annex Host Restrict", NULL},
  {32,	RADIUS_STRING,		"Annex Host Allow", NULL},
  {33,	RADIUS_STRING,		"Annex Product Name", NULL},
  {34,	RADIUS_STRING,		"Annex SW Version", NULL},
  {35,	RADIUS_IP_ADDRESS,	"Annex Local IP Address", NULL},
  {36,	RADIUS_INTEGER4,	"Annex Callback Portlist", NULL},
  {37,	RADIUS_INTEGER4,	"Annex Sec Profile Index", NULL},
  {38,	RADIUS_INTEGER4,	"Annex Tunnel Authen Type", radius_vendor_bay_tunnel_authen_type_vals},
  {39,	RADIUS_INTEGER4,	"Annex Tunnel Authen Mode", radius_vendor_bay_tunnel_authen_mode_vals},
  {40,	RADIUS_STRING,		"Annex Authen Servers", NULL},
  {41,	RADIUS_STRING,		"Annex Acct Servers", NULL},
  {42,	RADIUS_INTEGER4,	"Annex User Server Location", radius_vendor_bay_user_server_location_vals},
  {43,	RADIUS_STRING,		"Annex Local Username", NULL},
  {44,	RADIUS_INTEGER4,	"Annex System Disc Reason", radius_vendor_bay_system_disc_reason_vals},
  {45,	RADIUS_INTEGER4,	"Annex Modem Disc Reason", radius_vendor_bay_modem_disc_reason_vals},
  {46,	RADIUS_INTEGER4,	"Annex Disconnect Reason", NULL},
  {47,	RADIUS_INTEGER4,	"Annex Addr Resolution Protocol", radius_vendor_bay_addr_resolution_protocol_vals},
  {48,	RADIUS_STRING,		"Annex Addr Resolution Servers", NULL},
  {49,	RADIUS_STRING,		"Annex Domain Name", NULL},
  {50,	RADIUS_INTEGER4,	"Annex Transmit Speed", NULL},
  {51,	RADIUS_INTEGER4,	"Annex Receive Speed", NULL},
  {52,	RADIUS_STRING,		"Annex Input Filter", NULL},
  {53,	RADIUS_STRING,		"Annex Output Filter", NULL},
  {54,	RADIUS_IP_ADDRESS,	"Annex Primary DNS Server", NULL},
  {55,	RADIUS_IP_ADDRESS,	"Annex Secondary DNS Server", NULL},
  {56,	RADIUS_IP_ADDRESS,	"Annex Primary NBNS Server", NULL},
  {57,	RADIUS_IP_ADDRESS,	"Annex Secondary NBNS Server", NULL},
  {58,	RADIUS_INTEGER4,	"Annex Syslog Tap", NULL},
  {59,	RADIUS_INTEGER4,	"Annex Keypress Timeout", NULL},
  {60,	RADIUS_INTEGER4,	"Annex Unauthenticated Time", NULL},
  {61,	RADIUS_INTEGER4,	"Annex Re CHAP Timeout", NULL},
  {62,	RADIUS_INTEGER4,	"Annex MRRU", NULL},
  {63,	RADIUS_STRING,		"Annex EDO", NULL},
  {64,	RADIUS_INTEGER4,	"Annex PPP Trace Level", NULL},
  {65,	RADIUS_INTEGER4,	"Annex Pre Input Octets", NULL},
  {66,	RADIUS_INTEGER4,	"Annex Pre Output Octets", NULL},
  {67,	RADIUS_INTEGER4,	"Annex Pre Input Packets", NULL},
  {68,	RADIUS_INTEGER4,	"Annex Pre Output Packets", NULL},
  {69,	RADIUS_INTEGER4,	"Annex Connect Progress", NULL},
  {73,	RADIUS_INTEGER4,	"Annex Multicast Rate Limit", NULL},
  {74,	RADIUS_INTEGER4,	"Annex Maximum Call Duration", NULL},
  {75,	RADIUS_INTEGER4,	"Annex Multilink Id", NULL},
  {76,	RADIUS_INTEGER4,	"Annex Num In Multilink", NULL},
  {81,	RADIUS_INTEGER4,	"Annex Logical Channel Number", NULL},
  {82,	RADIUS_INTEGER4,	"Annex Wan Number", NULL},
  {83,	RADIUS_INTEGER4,	"Annex Port", NULL},
  {85,	RADIUS_INTEGER4,	"Annex Pool Id", NULL},
  {86,	RADIUS_STRING,		"Annex Compression Protocol", NULL},
  {87,	RADIUS_INTEGER4,	"Annex Transmitted Packets", NULL},
  {88,	RADIUS_INTEGER4,	"Annex Retransmitted Packets", NULL},
  {89,	RADIUS_INTEGER4,	"Annex Signal to Noise Ratio", NULL},
  {90,	RADIUS_INTEGER4,	"Annex Retrain Requests Sent", NULL},
  {91,	RADIUS_INTEGER4,	"Annex Retrain Requests Rcvd", NULL},
  {92,	RADIUS_INTEGER4,	"Annex Rate Reneg Req Sent", NULL},
  {93,	RADIUS_INTEGER4,	"Annex Rate Reneg Req Rcvd", NULL},
  {94,	RADIUS_INTEGER4,	"Annex Begin Receive Line Level", NULL},
  {95,	RADIUS_INTEGER4,	"Annex End Receive Line Level", NULL},
  {96,	RADIUS_STRING,		"Annex Begin Modulation", NULL},
  {97,	RADIUS_STRING,		"Annex Error Correction Prot", NULL},
  {98,	RADIUS_STRING,		"Annex End Modulation", NULL},
  {100,	RADIUS_INTEGER4,	"Annex User Level", radius_vendor_bay_user_level_vals},
  {101,	RADIUS_INTEGER4,	"Annex Audit Level", radius_vendor_bay_audit_level_vals},
  {0, 0, NULL, NULL},
};

/*
reference:
	'dictionary.foundry' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.foundry
*/
static const radius_attr_info radius_vendor_foundry_attrib[] =
{
  {1,	RADIUS_INTEGER4,	"Foundry Privilege Level", NULL},
  {2,	RADIUS_STRING,		"Foundry Command String", NULL},
  {3,	RADIUS_INTEGER4,	"Foundry Command Exception Flag", NULL},
  {0, 0, NULL, NULL},
};

/*
reference:
	'dictionary.versanet' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.versanet
*/
static const value_string radius_vendor_versanet_termination_cause_vals[] =
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

static const radius_attr_info radius_vendor_versanet_attrib[] =
{
  {1,	RADIUS_INTEGER4,	"Versanet Termination Cause", radius_vendor_versanet_termination_cause_vals},
  {0, 0, NULL, NULL},
};

/*
reference:
	'dictionary.redback' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.redback
*/
static const value_string radius_vendor_redback_tunnel_function_vals[] =
{
  {1,	"LAC Only"},
  {2,	"LNS Only"},
  {3,	"LAC LNS"},
  {0, NULL}
};

static const value_string radius_vendor_redback_mcast_send_vals[] =
{
  {1,	"NO SEND"},
  {2,	"SEND"},
  {3,	"UNSOLICITED SEND"},
  {0, NULL}
};

static const value_string radius_vendor_redback_mcast_receive_vals[] =
{
  {1,	"NO RECEIVE"},
  {2,	"RECEIVE"},
  {0, NULL}
};

static const value_string radius_vendor_redback_tunnel_dnis_vals[] =
{
  {1,	"DNIS"},
  {2,	"DNIS Only"},
  {0, NULL}
};

static const value_string radius_vendor_redback_pvc_encapsulation_type_vals[] =
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

static const value_string radius_vendor_redback_pvc_circuit_padding_vals[] =
{
  {1,	"AAA CIRCUIT PADDING"},
  {2,	"AAA CIRCUIT NO PADDING"},
  {0, NULL}
};

static const value_string radius_vendor_redback_bind_type_vals[] =
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

static const value_string radius_vendor_redback_bind_auth_protocol_vals[] =
{
  {1,	"AAA PPP PAP"},
  {2,	"AAA PPP CHAP"},
  {3,	"AAA PPP CHAP WAIT"},
  {4,	"AAA PPP CHAP PAP"},
  {5,	"AAA PPP CHAP WAIT PAP"},
  {0, NULL}
};

static const value_string radius_vendor_redback_lac_port_type_vals[] =
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

static const value_string radius_vendor_redback_lac_real_port_type_vals[] =
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

static const radius_attr_info radius_vendor_redback_attrib[] =
{
  {1,	RADIUS_IP_ADDRESS,	"Client DNS Pri", NULL},
  {2,	RADIUS_IP_ADDRESS,	"Client DNS Sec", NULL},
  {3,	RADIUS_INTEGER4,	"DHCP Max Leases", NULL},
  {4,	RADIUS_STRING,		"Context Name", NULL},
  {5,	RADIUS_STRING,		"Bridge Group", NULL},
  {6,	RADIUS_STRING,		"BG Aging Time", NULL},
  {7,	RADIUS_STRING,		"BG Path Cost", NULL},
  {8,	RADIUS_STRING,		"BG Span Dis", NULL},
  {9,	RADIUS_STRING,		"BG Trans BPDU", NULL},
  {10,	RADIUS_INTEGER4,	"Rate Limit Rate", NULL},
  {11,	RADIUS_INTEGER4,	"Rate Limit Burst", NULL},
  {12,	RADIUS_INTEGER4,	"Police Rate", NULL},
  {13,	RADIUS_INTEGER4,	"Police Burst", NULL},
  {14,	RADIUS_INTEGER4,	"Source Validation", NULL},
  {15,	RADIUS_INTEGER4,	"Tunnel Domain", NULL},
  {16,	RADIUS_STRING,		"Tunnel Local Name", NULL},
  {17,	RADIUS_STRING,		"Tunnel Remote Name", NULL},
  {18,	RADIUS_INTEGER4,	"Tunnel Function", radius_vendor_redback_tunnel_function_vals},
  {21,	RADIUS_INTEGER4,	"Tunnel Max Sessions", NULL},
  {22,	RADIUS_INTEGER4,	"Tunnel Max Tunnels", NULL},
  {23,	RADIUS_INTEGER4,	"Tunnel Session Auth", NULL},
  {24,	RADIUS_INTEGER4,	"Tunnel Window", NULL},
  {25,	RADIUS_INTEGER4,	"Tunnel Retransmit", NULL},
  {26,	RADIUS_INTEGER4,	"Tunnel Cmd Timeout", NULL},
  {27,	RADIUS_STRING,		"PPPOE URL", NULL},
  {28,	RADIUS_STRING,		"PPPOE MOTM", NULL},
  {29,	RADIUS_INTEGER4,	"Tunnel Group", NULL},
  {30,	RADIUS_STRING,		"Tunnel Context", NULL},
  {31,	RADIUS_INTEGER4,	"Tunnel Algorithm", NULL},
  {32,	RADIUS_INTEGER4,	"Tunnel Deadtime", NULL},
  {33,	RADIUS_INTEGER4,	"Mcast Send", radius_vendor_redback_mcast_send_vals},
  {34,	RADIUS_INTEGER4,	"Mcast Receive", radius_vendor_redback_mcast_receive_vals},
  {35,	RADIUS_INTEGER4,	"Mcast MaxGroups", NULL},
  {36,	RADIUS_STRING,		"Ip Address Pool Name", NULL},
  {37,	RADIUS_INTEGER4,	"Tunnel DNIS", radius_vendor_redback_tunnel_dnis_vals},
  {38,	RADIUS_INTEGER4,	"Medium Type", NULL},
  {39,	RADIUS_INTEGER4,	"PVC Encapsulation Type", radius_vendor_redback_pvc_encapsulation_type_vals},
  {40,	RADIUS_STRING,		"PVC Profile Name", NULL},
  {41,	RADIUS_INTEGER4,	"PVC Circuit Padding", radius_vendor_redback_pvc_circuit_padding_vals},
  {42,	RADIUS_INTEGER4,	"Bind Type", radius_vendor_redback_bind_type_vals},
  {43,	RADIUS_INTEGER4,	"Bind Auth Protocol", radius_vendor_redback_bind_auth_protocol_vals},
  {44,	RADIUS_INTEGER4,	"Bind Auth Max Sessions", NULL},
  {45,	RADIUS_STRING,		"Bind Bypass Bypass", NULL},
  {46,	RADIUS_STRING,		"Bind Auth Context", NULL},
  {47,	RADIUS_STRING,		"Bind Auth Service Grp", NULL},
  {48,	RADIUS_STRING,		"Bind Bypass Context", NULL},
  {49,	RADIUS_STRING,		"Bind Int Context", NULL},
  {50,	RADIUS_STRING,		"Bind Tun Context", NULL},
  {51,	RADIUS_STRING,		"Bind Ses Context", NULL},
  {52,	RADIUS_INTEGER4,	"Bind Dot1q Slot", NULL},
  {53,	RADIUS_INTEGER4,	"Bind Dot1q Port", NULL},
  {54,	RADIUS_INTEGER4,	"Bind Dot1q Vlan Tag Id", NULL},
  {55,	RADIUS_STRING,		"Bind Int Interface Name", NULL},
  {56,	RADIUS_STRING,		"Bind L2TP Tunnel Name", NULL},
  {57,	RADIUS_INTEGER4,	"Bind L2TP Flow Control", NULL},
  {58,	RADIUS_STRING,		"Bind Sub User At Context", NULL},
  {59,	RADIUS_STRING,		"Bind Sub Password", NULL},
  {60,	RADIUS_STRING,		"Ip Host Addr", NULL},
  {61,	RADIUS_INTEGER4,	"IP TOS Field", NULL},
  {62,	RADIUS_INTEGER4,	"NAS Real Port", NULL},
  {63,	RADIUS_STRING,		"Tunnel Session Auth Ctx", NULL},
  {64,	RADIUS_STRING,		"Tunnel Session Auth Service Grp", NULL},
  {65,	RADIUS_INTEGER4,	"Tunnel Rate Limit Rate", NULL},
  {66,	RADIUS_INTEGER4,	"Tunnel Rate Limit Burst", NULL},
  {67,	RADIUS_INTEGER4,	"Tunnel Police Rate", NULL},
  {68,	RADIUS_INTEGER4,	"Tunnel Police Burst", NULL},
  {69,	RADIUS_STRING,		"Tunnel L2F Second Password", NULL},
  {128,	RADIUS_INTEGER4,	"Acct Input Octets 64", NULL},
  {129,	RADIUS_INTEGER4,	"Acct Output Octets 64", NULL},
  {130,	RADIUS_INTEGER4,	"Acct Input Packets 64", NULL},
  {131,	RADIUS_INTEGER4,	"Acct Output Packets 64", NULL},
  {132,	RADIUS_IP_ADDRESS,	"Assigned IP Address", NULL},
  {133,	RADIUS_INTEGER4,	"Acct Mcast In Octets", NULL},
  {134,	RADIUS_INTEGER4,	"Acct Mcast Out Octets", NULL},
  {135,	RADIUS_INTEGER4,	"Acct Mcast In Packets", NULL},
  {136,	RADIUS_INTEGER4,	"Acct Mcast Out Packets", NULL},
  {137,	RADIUS_INTEGER4,	"LAC Port", NULL},
  {138,	RADIUS_INTEGER4,	"LAC Real Port", NULL},
  {139,	RADIUS_INTEGER4,	"LAC Port Type", radius_vendor_redback_lac_port_type_vals},
  {140,	RADIUS_INTEGER4,	"LAC Real Port Type", radius_vendor_redback_lac_real_port_type_vals},
  {141, RADIUS_STRING,		"Acct Dyn Ac Ent", NULL},
  {142, RADIUS_INTEGER4,	"Session Error Code", NULL},
  {143, RADIUS_STRING,		"Session Error Msg", NULL},
  {0, 0, NULL, NULL},
};

/*
reference:
	http://www.juniper.net/techpubs/software/junos53/swconfig53-getting-started/html/sys-mgmt-authentication2.html
*/
static const radius_attr_info radius_vendor_juniper_attrib[] =
{
  {1,	RADIUS_STRING,		"Juniper Local User Name", NULL},
  {2,	RADIUS_STRING,		"Juniper Allow Commands", NULL},
  {3,	RADIUS_STRING,		"Juniper Deny Commands", NULL},
  {0, 0, NULL, NULL}
};

/*
reference:
	'dictionary.aptis' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.aptis
*/
static const radius_attr_info radius_vendor_aptis_attrib[] =
{
  {1,	RADIUS_STRING,		"CVX Identification", NULL},
  {2,	RADIUS_INTEGER4,	"CVX VPOP ID", NULL},
  {3,	RADIUS_INTEGER4,	"CVX SS7 Session ID Type", NULL},
  {4,	RADIUS_INTEGER4,	"CVX Radius Redirect", NULL},
  {5,	RADIUS_INTEGER4,	"CVX IPSVC AZNLVL", NULL},
  {6,	RADIUS_INTEGER4,	"CVX IPSVC Mask", NULL},
  {7,	RADIUS_INTEGER4,	"CVX Multilink Match Info", NULL},
  {8,	RADIUS_INTEGER4,	"CVX Multilink Group Number", NULL},
  {9,	RADIUS_INTEGER4,	"CVX PPP Log Mask", NULL},
  {10,	RADIUS_STRING,		"CVX Modem Begin Modulation", NULL},
  {11,	RADIUS_STRING,		"CVX Modem End Modulation", NULL},
  {12,	RADIUS_STRING,		"CVX Modem Error Correction", NULL},
  {13,	RADIUS_STRING,		"CVX Modem Data Compression", NULL},
  {14,	RADIUS_INTEGER4,	"CVX Modem Tx Packets", NULL},
  {15,	RADIUS_INTEGER4,	"CVX Modem ReTx Packets", NULL},
  {16,	RADIUS_INTEGER4,	"CVX Modem SNR", NULL},
  {17,	RADIUS_INTEGER4,	"CVX Modem Local Retrains", NULL},
  {18,	RADIUS_INTEGER4,	"CVX Modem Remote Retrains", NULL},
  {19,	RADIUS_INTEGER4,	"CVX Modem Local Rate Negs", NULL},
  {20,	RADIUS_INTEGER4,	"CVX Modem Remote Rate Negs", NULL},
  {21,	RADIUS_INTEGER4,	"CVX Modem Begin Recv Line Lvl", NULL},
  {22,	RADIUS_INTEGER4,	"CVX Modem End Recv Line Lvl", NULL},
  {0, 0, NULL, NULL},
};

static const radius_attr_info radius_vendor_cosine_attrib[] =
{
  {1,	RADIUS_STRING,		"Connection Profile Name", NULL},
  {2,	RADIUS_STRING,		"Enterprise ID", NULL},
  {3,	RADIUS_STRING,		"Address Pool Name", NULL},
  {4,	RADIUS_INTEGER4,	"DS Byte", NULL},
  {5,	COSINE_VPI_VCI,		"VPI/VCI", NULL},
  {6,	RADIUS_INTEGER4,	"DLCI", NULL},
  {7,	RADIUS_IP_ADDRESS,	"LNS IP Address", NULL},
  {8,	RADIUS_STRING,		"CLI User Permission ID", NULL},
  {0, 0, NULL, NULL}
};

/*
reference:
	'dictionary.shasta' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.shasta
*/
static const value_string radius_vendor_shasta_user_privilege_vals[] =
{
  {1,	"User"},
  {2,	"Super User"},
  {3,	"SSuper User"},
  {0, NULL}
};

static const radius_attr_info radius_vendor_shasta_attrib[] =
{
  {1,	RADIUS_INTEGER4,	"Shasta User Privilege", radius_vendor_shasta_user_privilege_vals},
  {2,	RADIUS_STRING,		"Shasta Service Profile", NULL},
  {3,	RADIUS_STRING,		"Shasta VPN Name", NULL},
  {0, 0, NULL, NULL},
};

/*
reference:
	'dictionary.nomadix' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.nomadix
*/
static const radius_attr_info radius_vendor_nomadix_attrib[] =
{
  {1,	RADIUS_INTEGER4,	"Nomadix Bw Up", NULL},
  {2,	RADIUS_INTEGER4,	"Nomadix Bw Down", NULL},
  {0, 0, NULL, NULL},
};

/*
reference:
	'dictionary.erx' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.erx
*/
static const radius_attr_info radius_vendor_unisphere_attrib[] =
{
  {1,	RADIUS_STRING,		"ERX Virtual Router Name", NULL},
  {2,	RADIUS_STRING,		"ERX Address Pool Name", NULL},
  {3,	RADIUS_STRING,		"ERX Local Loopback Interface", NULL},
  {4,	RADIUS_IP_ADDRESS,	"ERX Primary Dns", NULL},
  {5,	RADIUS_IP_ADDRESS,	"ERX Primary Wins", NULL},
  {6,	RADIUS_IP_ADDRESS,	"ERX Secondary Dns", NULL},
  {7,	RADIUS_IP_ADDRESS,	"ERX Secondary Wins", NULL},
  {8,	RADIUS_STRING,		"ERX Tunnel Virtual Router", NULL},
  {9,	RADIUS_STRING,		"ERX Tunnel Password", NULL},
  {10,	RADIUS_STRING,		"ERX Ingress Policy Name", NULL},
  {11,	RADIUS_STRING,		"ERX Egress Policy Name", NULL},
  {12,	RADIUS_STRING,		"ERX Ingress Statistics", NULL},
  {13,	RADIUS_STRING,		"ERX Egress Statistics", NULL},
  {14,	RADIUS_STRING,		"ERX Atm Service Category", NULL},
  {15,	RADIUS_STRING,		"ERX Atm PCR", NULL},
  {16,	RADIUS_STRING,		"ERX Atm SCR", NULL},
  {17,	RADIUS_STRING,		"ERX Atm MBS", NULL},
  {18,	RADIUS_STRING,		"ERX Cli Initial Access Level", NULL},
  {19,	RADIUS_INTEGER4,	"ERX Cli Allow All VR Access", NULL},
  {20,	RADIUS_STRING,		"ERX Alternate Cli Access Level", NULL},
  {21,	RADIUS_STRING,		"ERX Alternate Cli Vrouter Name", NULL},
  {22,	RADIUS_INTEGER4,	"ERX Sa Validate", NULL},
  {23,	RADIUS_INTEGER4,	"ERX Igmp Enable", NULL},
  {0, 0, NULL, NULL},
};

static const radius_attr_info radius_vendor_issanni_attrib[] =
{
  {1,	RADIUS_STRING,		"Softflow Template", NULL},
  {2,	RADIUS_STRING,		"NAT Pool", NULL},
  {3,	RADIUS_STRING,		"Virtual Routing Domain", NULL},
  {4,	RADIUS_STRING,		"Tunnel Name", NULL},
  {5,	RADIUS_STRING,		"IP Pool Name", NULL},
  {6,	RADIUS_STRING,		"PPPoE URL", NULL},
  {7,	RADIUS_STRING,		"PPPoE MOTM", NULL},
  {8,	RADIUS_STRING,		"PPPoE Service", NULL},
  {9,	RADIUS_IP_ADDRESS,	"Primary DNS", NULL},
  {10,	RADIUS_IP_ADDRESS,	"Secondary DNS", NULL},
  {11,	RADIUS_IP_ADDRESS,	"Primary NBNS", NULL},
  {12,	RADIUS_IP_ADDRESS,	"Secondary NBNS", NULL},
  {13,	RADIUS_STRING,		"Policing Traffic Class", NULL},
  {14,	RADIUS_INTEGER4,	"Tunnel Type", NULL},
  {15,	RADIUS_INTEGER4,	"NAT Type", NULL},
  {16,	RADIUS_STRING,		"QoS Traffic Class", NULL},
  {17,	RADIUS_STRING,		"Interface Name", NULL},
  {0, 0, NULL, NULL}
};

/*
reference:
	'dictionary.quintum' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.quintum
*/
static const radius_attr_info radius_vendor_quintum_attrib[] =
{
  {1,	RADIUS_STRING,		"Quintum AVPair", NULL},
  {2,	RADIUS_STRING,		"Quintum NAS Port", NULL},
  {23,	RADIUS_STRING,		"Quintum h323 remote address", NULL},
  {24,	RADIUS_STRING,		"Quintum h323 conf id", NULL},
  {25,	RADIUS_STRING,		"Quintum h323 setup time", NULL},
  {26,	RADIUS_STRING,		"Quintum h323 call origin", NULL},
  {27,	RADIUS_STRING,		"Quintum h323 call type", NULL},
  {28,	RADIUS_STRING,		"Quintum h323 connect time", NULL},
  {29,	RADIUS_STRING,		"Quintum h323 disconnect time", NULL},
  {30,	RADIUS_STRING,		"Quintum h323 disconnect cause", NULL},
  {31,	RADIUS_STRING,		"Quintum h323 voice quality", NULL},
  {33,	RADIUS_STRING,		"Quintum h323 gw id", NULL},
  {35,	RADIUS_STRING,		"Quintum h323 incoming conf id", NULL},
  {101,	RADIUS_STRING,		"Quintum h323 credit amount", NULL},
  {102,	RADIUS_STRING,		"Quintum h323 credit time", NULL},
  {103,	RADIUS_STRING,		"Quintum h323 return code", NULL},
  {104,	RADIUS_STRING,		"Quintum h323 prompt id", NULL},
  {105,	RADIUS_STRING,		"Quintum h323 time and day", NULL},
  {106,	RADIUS_STRING,		"Quintum h323 redirect number", NULL},
  {107,	RADIUS_STRING,		"Quintum h323 preferred lang", NULL},
  {108,	RADIUS_STRING,		"Quintum h323 redirect ip address", NULL},
  {109,	RADIUS_STRING,		"Quintum h323 billing model", NULL},
  {110,	RADIUS_STRING,		"Quintum h323 currency type", NULL},
  {0, 0, NULL, NULL},
};

/*
reference:
	http://download.colubris.com/library/product_doc/CN3500_AdminGuide.pdf
*/
static const radius_attr_info radius_vendor_colubris_attrib[] =
{
  {0,	RADIUS_STRING,		"Colubris AV Pair", NULL},
  {0, 0, NULL, NULL},
};

/*
reference:
	'dictionary.columbia_university' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.columbia_university
*/
static const value_string radius_vendor_columbia_university_sip_method_vals[] =
{
  {0,	"INVITE"},
  {1,	"BYE"},
  {2,	"REGISTER"},
  {3,	"OTHER"},
  {0, NULL}
};

static const radius_attr_info radius_vendor_columbia_university_attrib[] =
{
  {0,	RADIUS_INTEGER4,	"SIP Method", radius_vendor_columbia_university_sip_method_vals},
  {1,	RADIUS_STRING,		"SIP From", NULL},
  {2,	RADIUS_STRING,		"SIP To", NULL},
  {4,	RADIUS_STRING,		"SIP Translated Request URI", NULL},
  {0, 0, NULL, NULL},
};

static const value_string the3gpp_pdp_type_vals[] = {
  {0,	"IP"},
  {1,	"PPP"},
  {2,	"IPv6"},
  {0, NULL}
};

static const radius_attr_info radius_vendor_3gpp_attrib[] =
{
   /* According to 3GPP TS 29.061 V4.8.0 (2003-06) */
   {1,  THE3GPP_IMSI,		"IMSI", NULL},
   {2,  RADIUS_INTEGER4,	"Charging ID", NULL},
   {3,  RADIUS_INTEGER4,	"PDP Type", the3gpp_pdp_type_vals},
   {4,  RADIUS_IP_ADDRESS,	"Charging Gateway Address", NULL},
   {5,  THE3GPP_QOS,		"QoS Profile", NULL},
   {6,  RADIUS_IP_ADDRESS,	"SGSN Address", NULL},
   {7,  RADIUS_IP_ADDRESS,	"GGSN Address", NULL},
   {8,  THE3GPP_IMSI_MCC_MNC,	"IMSI MCC-MNC", NULL},
   {9,  THE3GPP_GGSN_MCC_MNC,	"GGSN MCC-MNC", NULL},
   {10, THE3GPP_NSAPI,		"NSAPI", NULL},
   {11, THE3GPP_SESSION_STOP_INDICATOR, "Session Stop Indicator", NULL},
   {12, THE3GPP_SELECTION_MODE,	"Selection Mode", NULL},
   {13, THE3GPP_CHARGING_CHARACTERISTICS, "Charging Characteristics", NULL},
   {14, RADIUS_IP6_ADDRESS,	"Charging Gateway IPv6 Address", NULL},
   {15, RADIUS_IP6_ADDRESS,	"SGSN IPv6 Address", NULL},
   {16, RADIUS_IP6_ADDRESS,	"GGSN IPv6 Address", NULL},
   {17, THE3GPP_IPV6_DNS_SERVERS, "IPv6 DNS Servers", NULL},
   {18, THE3GPP_SGSN_MCC_MNC,	"SGSN MCC-MNC", NULL},
   {0, 0, NULL, NULL},
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

static const radius_attr_info *get_attr_info_table(guint32 vendor)
{
    guint32 i;

    for (i = 0; radius_vsa_table[i].vendor; i++)
	if (radius_vsa_table[i].vendor == vendor)
	    return(radius_vsa_table[i].attrib);

    return(NULL);
}

static const radius_attr_info *
find_radius_attr_info(guint32 attr_type, const radius_attr_info *table)
{
    guint32 i;

    for (i = 0; table[i].str; i++)
	if (table[i].attr_type == attr_type)
	    return(&table[i]);

    return(NULL);
}

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
    guint32 totlen;
    const guint8 *pd;
    guchar c;

    if (shared_secret[0] == '\0' || !authenticator ) {
	rdconvertbufftostr(dest,tvb,offset,length);
	return;
    }

    dest[0] = '"';
    dest[1] = '\0';
    totlen = 1;

    md5_init(&md_ctx);
    md5_append(&md_ctx,shared_secret,strlen(shared_secret));
    md5_append(&md_ctx,authenticator,16);
    md5_finish(&md_ctx,digest);

    pd = tvb_get_ptr(tvb,offset,length);
    for( i = 0 ; i < 16 && i < (guint32)length ; i++ ) {
	c = pd[i] ^ digest[i];
#ifdef _WIN32
	/*
	 * XXX - "isprint()" can return "true" for non-ASCII characters, but
	 * those don't work with GTK+ on Windows, as GTK+ on Windows assumes
	 * UTF-8 strings.  Until we fix up Ethereal to properly handle
	 * non-ASCII characters in all output (both GUI displays and text
	 * printouts) on all platforms including Windows, we work around
	 * the problem by escaping all characters that aren't printable ASCII.
	 */
	if ( c >= 0x20 && c <= 0x7f) {
#else
	if ( isprint(c)) {
#endif
	    dest[totlen] = c;
	    totlen++;
	} else {
	    sprintf(&(dest[totlen]),"\\%03o",c);
	    totlen += strlen(&(dest[totlen]));
	}
    }
    while(i<(guint32)length) {
#ifdef _WIN32
	/*
	 * XXX - "isprint()" can return "true" for non-ASCII characters, but
	 * those don't work with GTK+ on Windows, as GTK+ on Windows assumes
	 * UTF-8 strings.  Until we fix up Ethereal to properly handle
	 * non-ASCII characters in all output (both GUI displays and text
	 * printouts) on all platforms including Windows, we work around
	 * the problem by escaping all characters that aren't printable ASCII.
	 */
	if ( pd[i] >= 0x20 && pd[i] <= 0x7f) {
#else
	if ( isprint(pd[i]) ) {
#endif
	    dest[totlen] = (gchar)pd[i];
	    totlen++;
	} else {
	    sprintf(&(dest[totlen]), "\\%03o", pd[i]);
	    totlen=totlen+strlen(&(dest[totlen]));
	}
	i++;
    }
    dest[totlen]='"';
    dest[totlen+1] = '\0';
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
static void rd_value_to_str(gchar *dest, rd_vsa_buffer (*vsabuffer)[VSABUFFER],
			    const e_avphdr *avph, tvbuff_t *tvb,
			    int offset, const radius_attr_info *vvs,
			    proto_tree *tree)
{
  const radius_attr_info *attr_info;

  /* Variable to peek which will be the next print_type for VENDOR-SPECIFIC
   * RADIUS attributes
   * */
  const radius_attr_info *next_attr_info;

  /* Temporary variable to perform some trick on the cont variable; again, this
   * is needed only when THE3GPP_QOS in involved.
   * */
  gchar *tmp_punt;

  gchar *cont;
  guint32 intval;
  gint32 timeval;
  const guint8 *pd;
  guint8 tag;

  int vsa_length;
  int vsa_len;
  int vsa_index;
  const radius_attr_info *vsa_attr_info_table;
  const e_avphdr *vsa_avph;

/* prints the values of the attribute value pairs into a text buffer */
  attr_info = find_radius_attr_info(avph->avp_type, vvs);

  /* Default begin */
  strcpy(dest, "Value:");
  cont=&dest[strlen(dest)];
  switch(attr_info->value_type)
  {
        case( RADIUS_STRING ):
		/* User Password, but only, if not inside vsa */
		if ( avph->avp_type == 2 && (*vsabuffer)[0].str == 0 )  {
		    rddecryptpass(cont,tvb,offset+2,avph->avp_length-2);
		} else {
		    rdconvertbufftostr(cont,tvb,offset+2,avph->avp_length-2);
		}
                break;

        case( RADIUS_BINSTRING ):
		rdconvertbufftobinstr(cont,tvb,offset+2,avph->avp_length-2);
                break;

        case( RADIUS_INTEGER4 ):
        	intval = tvb_get_ntohl(tvb,offset+2);
        	if (attr_info->vs != NULL)
			sprintf(cont, "%s(%u)", rd_match_strval(intval, attr_info->vs), intval);
		else
	                sprintf(cont,"%u", intval);
                break;

        case( RADIUS_IP_ADDRESS ):
                ip_to_str_buf(tvb_get_ptr(tvb,offset+2,4),cont);
                break;

        case( RADIUS_IP6_ADDRESS ):
                ip6_to_str_buf((const struct e_in6_addr *)tvb_get_ptr(tvb,offset+2,16),cont);
                break;

        case( RADIUS_IPX_ADDRESS ):
                pd = tvb_get_ptr(tvb,offset+2,4);
                sprintf(cont,"%u:%u:%u:%u",pd[0],pd[1],pd[2],pd[3]);
		break;

        case( RADIUS_STRING_TAGGED ):
		/* Tagged ? */
		tag = tvb_get_guint8(tvb,offset+2);
		if (tag > 0 && tag <= 0x1f) {
			sprintf(dest, "Tag:%u, Value:",
					tag);
			cont=&cont[strlen(cont)];
			rdconvertbufftostr(cont,tvb,offset+3,avph->avp_length-3);
			break;
		}
		rdconvertbufftostr(cont,tvb,offset+2,avph->avp_length-2);
                break;

	case ( RADIUS_VENDOR_SPECIFIC ):
		intval = tvb_get_ntohl(tvb,offset+2);
		sprintf(dest, "Vendor:%s(%u)", rd_match_strval(intval,radius_vendor_specific_vendors), intval);
		cont = &dest[strlen(dest)];
		vsa_length = avph->avp_length;
		vsa_len = 6;
		vsa_index = 0;
		vsa_attr_info_table = get_attr_info_table(intval);
		do
		{
			vsa_avph = (const e_avphdr*)tvb_get_ptr(tvb, offset+vsa_len,
				avph->avp_length-vsa_len);
			if (vsa_attr_info_table)
				next_attr_info = find_radius_attr_info(vsa_avph->avp_type,
					vsa_attr_info_table);
			else
				next_attr_info = NULL;
			cont = &cont[strlen(cont)+1];
			tmp_punt = cont;
			(*vsabuffer)[vsa_index].str = cont;
			(*vsabuffer)[vsa_index].offset = offset+vsa_len;
			(*vsabuffer)[vsa_index].length = vsa_avph->avp_length;
			sprintf(cont, "t:%s(%u) l:%u, ",
				(next_attr_info
					? next_attr_info->str
					: "Unknown Type"),
				vsa_avph->avp_type, vsa_avph->avp_length);
			cont = &cont[strlen(cont)];
			rd_value_to_str(cont, vsabuffer, vsa_avph, tvb,
					offset+vsa_len, vsa_attr_info_table,
					tree);
			vsa_index++;
			vsa_len += vsa_avph->avp_length;
			if (next_attr_info != NULL &&
			    next_attr_info->value_type == THE3GPP_QOS )
			{
				cont = tmp_punt;
				vsa_index--;
				(*vsabuffer)[vsa_index].str = 0;
			}
		} while (vsa_length > vsa_len && vsa_index < VSABUFFER);
		break;

	case( COSINE_VPI_VCI ):
		sprintf(cont,"%u/%u",
			tvb_get_ntohs(tvb,offset+2),
			tvb_get_ntohs(tvb,offset+4));
 		break;

	case( THE3GPP_IMSI ):
	case( THE3GPP_IMSI_MCC_MNC ):
	case( THE3GPP_GGSN_MCC_MNC ):
	case( THE3GPP_SGSN_MCC_MNC ):
	case( THE3GPP_SELECTION_MODE ):
	case( THE3GPP_CHARGING_CHARACTERISTICS ):
		sprintf(cont,"(encoded in UTF-8 format)");
		break;

	case( THE3GPP_NSAPI ):
	case( THE3GPP_SESSION_STOP_INDICATOR ):
	case( THE3GPP_IPV6_DNS_SERVERS ):
		sprintf(cont,"(not parsed)");
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
		timeval=tvb_get_ntohl(tvb,offset+2);
		sprintf(cont,"%d (%s)", timeval, abs_time_secs_to_str(timeval));
		break;

        case( RADIUS_INTEGER4_TAGGED ):
		tag = tvb_get_guint8(tvb,offset+2);
		intval = tvb_get_ntoh24(tvb,offset+3);
		/* Tagged ? */
		if (tag) {
			if (attr_info->vs != NULL) {
				sprintf(dest, "Tag:%u, Value:%s(%u)",
					tag,
					rd_match_strval(intval, attr_info->vs),
					intval);
			} else {
				sprintf(dest, "Tag:%u, Value:%u",
					tag, intval);
			}
		} else {
	        	if (attr_info->vs != NULL)
				sprintf(cont, "%s(%u)",
					rd_match_strval(intval, attr_info->vs),
					intval);
			else
				sprintf(cont,"%u", intval);
		}
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
}

static void
dissect_attribute_value_pairs(tvbuff_t *tvb, int offset,proto_tree *tree,
				   int avplength,packet_info *pinfo)
{
/* adds the attribute value pairs to the tree */
  e_avphdr avph;
  const radius_attr_info *attr_info;
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
    attr_info = find_radius_attr_info(avph.avp_type, radius_attrib);
    if (avph.avp_length < 2) {
      /*
       * This AVP is bogus - the length includes the type and length
       * fields, so it must be >= 2.
       */
      if (tree) {
        proto_tree_add_text(tree, tvb, offset, avph.avp_length,
			    "t:%s(%u) l:%u (length not >= 2)",
			    attr_info->str, avph.avp_type, avph.avp_length);
      }
      break;
    }

    if (attr_info->value_type == RADIUS_EAP_MESSAGE) {	/* EAP Message */
      proto_item *ti;
      proto_tree *eap_tree = NULL;
      gint tvb_len;
      tvbuff_t *next_tvb;
      int data_len;
      int result;

      if (tree) {
        ti = proto_tree_add_text(tree, tvb, offset, avph.avp_length,
				 "t:%s(%u) l:%u",
			 	 attr_info->str, avph.avp_type, avph.avp_length);
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
        gchar textbuffer[TEXTBUFFER];
        rd_vsa_buffer vsabuffer[VSABUFFER];

        /* We pre-add a text and a subtree to allow 3GPP QoS decoding
         * to access the protocol tree.
         * */
        ti = proto_tree_add_text(tree, tvb, offset, avph.avp_length,
			    "t:%s(%u) l:%u",
			    attr_info->str, avph.avp_type, avph.avp_length);
        vsa_tree = proto_item_add_subtree(ti, ett_radius_vsa);
        for (i = 0; i < VSABUFFER; i++)
	    vsabuffer[i].str = NULL;
        rd_value_to_str(textbuffer, &vsabuffer, &avph, tvb, offset,
			radius_attrib, vsa_tree);
        proto_item_append_text(ti, ", %s", textbuffer);
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
  guint rhlength;
  guint rhcode;
  guint rhident;
  guint avplength,hdrlength;
  e_radiushdr rh;

  gchar *codestrval;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "RADIUS");
  if (check_col(pinfo->cinfo, COL_INFO))
        col_clear(pinfo->cinfo, COL_INFO);

  tvb_memcpy(tvb,(guint8 *)&rh,0,sizeof(e_radiushdr));

  rhcode= rh.rh_code;
  rhident= rh.rh_ident;
  rhlength= g_ntohs(rh.rh_pktlength);
  codestrval=  match_strval(rhcode,radius_vals);
  if (codestrval==NULL)
  {
	codestrval="Unknown Packet";
  }
  /* XXX Check for valid length value:
   * Length
   *
   *  The Length field is two octets.  It indicates the length of the
   *  packet including the Code, Identifier, Length, Authenticator and
   *  Attribute fields.  Octets outside the range of the Length field
   *  MUST be treated as padding and ignored on reception.  If the
   *  packet is shorter than the Length field indicates, it MUST be
   *  silently discarded.  The minimum length is 20 and maximum length
   *  is 4096.
   */

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
