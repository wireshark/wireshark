/* packet-radius.c
 *
 * Routines for RADIUS packet disassembly
 * Copyright 1999 Johan Feyaerts
 * Changed 03/12/2003 Rui Carmo (http://the.taoofmac.com - added all 3GPP VSAs, some parsing)
 *
 * $Id$
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
 *
 * References:
 *
 * RFC 2865 - Remote Authentication Dial In User Service (RADIUS)
 * RFC 2866 - RADIUS Accounting
 * RFC 2867 - RADIUS Accounting Modifications for Tunnel Protocol Support
 * RFC 2868 - RADIUS Attributes for Tunnel Protocol Support
 * RFC 2869 - RADIUS Extensions
 *
 * See also
 *
 *	http://www.iana.org/assignments/radius-types
 */

/*
 * Some of the development of the RADIUS protocol decoder was sponsored by
 * Cable Television Laboratories, Inc. ("CableLabs") based upon proprietary
 * CableLabs' specifications. Your license and use of this protocol decoder
 * does not mean that you are licensed to use the CableLabs'
 * specifications.  If you have questions about this protocol, contact
 * jf.mule [AT] cablelabs.com or c.stuart [AT] cablelabs.com for additional
 * information.
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

#include "isprint.h"

#include <epan/packet.h>
#include <epan/addr_resolv.h>

#include "packet-q931.h"
#include "packet-gtp.h"
#include <epan/prefs.h>
#include <epan/crypt-md5.h>
#include <epan/sminmpec.h>

static int proto_radius = -1;
static int hf_radius_length = -1;
static int hf_radius_code = -1;
static int hf_radius_id =-1;
static int hf_radius_userName = -1;
static int hf_radius_framedProtocol = -1;
static int hf_radius_serviceType = -1;
static int hf_radius_callingStationId = -1;
static int hf_radius_calledStationId = -1;
static int hf_radius_framedAddress = -1;
static int hf_radius_class = -1;
static int hf_radius_nasIp = -1;
static int hf_radius_acctStatusType = -1;
static int hf_radius_acctSessionId = -1;
static int hf_radius_3gpp_SgsnIpAddr = -1;
static int hf_radius_3gpp_GgsnIpAddr = -1;
static int hf_radius_cisco_cai = -1;
static int hf_packetcable_em_header_version_id = -1;
static int hf_packetcable_bcid_timestamp = -1;
static int hf_packetcable_bcid_event_counter = -1;
static int hf_packetcable_em_header_event_message_type = -1;
static int hf_packetcable_em_header_element_type = -1;
static int hf_packetcable_em_header_sequence_number = -1;
static int hf_packetcable_em_header_status = -1;
static int hf_packetcable_em_header_status_error_indicator = -1;
static int hf_packetcable_em_header_status_event_origin = -1;
static int hf_packetcable_em_header_status_event_message_proxied = -1;
static int hf_packetcable_em_header_priority = -1;
static int hf_packetcable_em_header_attribute_count = -1;
static int hf_packetcable_em_header_event_object = -1;
static int hf_packetcable_call_termination_cause_source_document = -1;
static int hf_packetcable_call_termination_cause_code = -1;
static int hf_packetcable_trunk_group_id_trunk_type = -1;
static int hf_packetcable_trunk_group_id_trunk_number = -1;
static int hf_packetcable_qos_status = -1;
static int hf_packetcable_qos_status_indication = -1;
static int hf_packetcable_time_adjustment = -1;
static int hf_packetcable_redirected_from_info_number_of_redirections = -1;
static int hf_packetcable_electronic_surveillance_indication_df_cdc_address = -1;
static int hf_packetcable_electronic_surveillance_indication_df_ccc_address = -1;
static int hf_packetcable_electronic_surveillance_indication_cdc_port = -1;
static int hf_packetcable_electronic_surveillance_indication_ccc_port = -1;
static int hf_packetcable_terminal_display_info_terminal_display_status_bitmask = -1;
static int hf_packetcable_terminal_display_info_sbm_general_display = -1;
static int hf_packetcable_terminal_display_info_sbm_calling_number = -1;
static int hf_packetcable_terminal_display_info_sbm_calling_name = -1;
static int hf_packetcable_terminal_display_info_sbm_message_waiting = -1;
static int hf_packetcable_terminal_display_info_general_display = -1;
static int hf_packetcable_terminal_display_info_calling_number = -1;
static int hf_packetcable_terminal_display_info_calling_name = -1;
static int hf_packetcable_terminal_display_info_message_waiting = -1;
/* This is slightly ugly.  */
static int hf_packetcable_qos_desc_flags[] =
{
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};
static int hf_packetcable_qos_desc_fields[] =
{
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};


static char *shared_secret = NULL;
static gpointer authenticator = NULL;

static gint ett_radius = -1;
static gint ett_radius_avp = -1;
static gint ett_radius_eap = -1;
static gint ett_radius_vsa = -1;
static gint ett_radius_vendor_packetcable_bcid = -1;
static gint ett_radius_vendor_packetcable_status = -1;
static gint ett_radius_vendor_packetcable_qos_status = -1;

static void decode_packetcable_bcid (tvbuff_t *tvb, proto_tree *tree, int offset);

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
	int *hf;
} radius_attr_info;

typedef struct _rd_vsa_table {
	guint32 vendor;
	const radius_attr_info *attrib;
} rd_vsa_table;

typedef struct _rd_vsa_buffer {
	gchar *str;
	int offset;
	guint8 length;
	gchar *val_str;
	int val_offset;
	guint val_len;
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
    RADIUS_STRING,
    RADIUS_BINSTRING,
    RADIUS_USERPASSWORD,
    RADIUS_INTEGER2,
    RADIUS_INTEGER4,
    RADIUS_INTEGER8,
    RADIUS_IP_ADDRESS,
    RADIUS_IP6_ADDRESS,
    RADIUS_IP6_PREFIX,
    RADIUS_IP6_INTF_ID,
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
    THE3GPP_SGSN_MCC_MNC,

    PACKETCABLE_EM_HEADER,
    PACKETCABLE_CALL_TERMINATION_CAUSE,
    PACKETCABLE_RELATED_CALL_BILLING_CORRELATION_ID,
    PACKETCABLE_TRUNK_GROUP_ID,
    PACKETCABLE_QOS_DESCRIPTOR,
    PACKETCABLE_TIME_ADJUSTMENT,
    PACKETCABLE_REDIRECTED_FROM_INFO,
    PACKETCABLE_ELECTRONIC_SURVEILLANCE_INDICATION,
    PACKETCABLE_ELECTRONIC_SURVEILLANCE_DF_SECURITY,
    PACKETCABLE_TERMINAL_DISPLAY_INFO
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
  {11,	"Callback Administrative"},
  {12,	"Voice"},								/*[Chiba]				*/
  {13,	"Fax"},									/*[Chiba]				*/
  {14,	"Modem Relay"},							/*[Chiba]				*/
  {15,	"IAPP-Register"},						/*[IEEE 802.11f][Kerry]	*/
  {16,	"IAPP-AP-Check"},						/*[IEEE 802.11f][Kerry]	*/
  {17,	"Authorize Only"},						/*[RFC3576]				*/
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
  {7,	"GPRS PDP Context"},
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
/* Values for RADIUS Attribute 29, Termination-Action: */
static const value_string radius_terminating_action_vals[] =
{
  {1,	"RADIUS Request"},
  {0,	"Default"},
  {0, NULL}
};
/* Values for RADIUS Attribute 40, Acct-Status-Type [RFC 2866]:*/
static const value_string radius_accounting_status_type_vals[] =
{
  {1,	"Start"},				/*  [RFC 2866]*/
  {2,	"Stop"},				/*  [RFC 2866]*/
  {3,	"Interim Update"},		/*  [RFC 2866]*/
  {7,	"Accounting On"},		/*  [RFC 2866]*/
  {8,	"Accounting Off"},		/*  [RFC 2866]*/
  {9,	"Tunnel Start"},		/* Tunnel accounting [RFC 2867]	*/
  {10,	"Tunnel Stop"},			/* Tunnel accounting [RFC 2867]	*/
  {11,	"Tunnel Reject"},		/* Tunnel accounting [RFC 2867]	*/
  {12,	"Tunnel Link Start"},	/* Tunnel accounting [RFC 2867]	*/
  {13,	"Tunnel Link Stop"},	/* Tunnel accounting [RFC 2867]	*/
  {14,	"Tunnel Link Reject"},	/* Tunnel accounting [RFC 2867]	*/
  {15,	"Failed"},				/* [RFC 2866]					*/

  {0, NULL}
};
/* Values for RADIUS Attribute 45, Acct-Authentic [RFC 2866]: */
static const value_string radius_accounting_authentication_vals[] =
{
  {1,	"Radius"},
  {2,	"Local"},
  {3,	"Remote"},
  {4,	"Diameter"},
  /* RFC 2866 says 3 is Remote. Is 7 a mistake? */
  {7,	"Remote"},
  {0, NULL}
};
/*Values for RADIUS Attribute 49, Acct-Terminate-Cause [RFC 2866]: */
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
  {19,	"Supplicant Restart"},					/*[RFC3580]*/
  {20,	"Reauthentication Failure"},			/*[RFC3580]*/
  {21,	"Port Reinitialized"},					/*[RFC3580]*/
  {22,	"Port Administratively Disabled"},		/*[RFC3580]*/

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
  {12,	"VLAN"},								/*[RFC3580]*/
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
/*Values for RADIUS Attribute 61, NAS-Port-Type [RFC 2865]: */
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
  {20,	"Token-Ring"},									/*[RFC3580]*/
  {21,	"FDDI"},										/*[RFC3580]*/
  {22,	"Wireless - CDMA2000"},							/*[McCann] */
  {23,	"Wireless - UMTS"},								/*[McCann] */
  {24,	"Wireless - 1X-EV"},							/*[McCann] */
  {25,	"IAPP"},									/*[IEEE 802.11f][Kerry]*/
  {26,	"FTTP - Fiber to the Premises"},				/*[Nyce]*/

  {0, NULL}
};
/*
 *Values for RADIUS Attribute 101, Error-Cause Attribute [RFC3576]:
 */
static const value_string radius_error_cause_attribute_vals[]= {
	{201,"Residual Session Context Removed"},
	{202,"Invalid EAP Packet (Ignored)"},
	{401,"Unsupported Attribute"},
	{402,"Missing Attribute"},
	{403,"NAS Identification Mismatch"},
	{404,"Invalid Request"},
	{405,"Unsupported Service"},
	{406,"Unsupported Extension"},
	{501,"Administratively Prohibited"},
	{502,"Request Not Routable (Proxy)"},
	{503,"Session Context Not Found"},
	{504,"Session Context Not Removable"},
	{505,"Other Proxy Processing Error"},
	{506,"Resources Unavailable"},
	{507,"Request Initiated"},
		{0,NULL}
};

static const radius_attr_info radius_attrib[] =
{
  {1,	RADIUS_STRING,		"User Name", NULL, &hf_radius_userName},
  {2,	RADIUS_USERPASSWORD,	"User Password", NULL, NULL},
  {3,	RADIUS_BINSTRING,	"CHAP Password", NULL, NULL},
  {4,	RADIUS_IP_ADDRESS,	"NAS IP Address", NULL, &hf_radius_nasIp},
  {5,	RADIUS_INTEGER4,	"NAS Port", NULL, NULL},
  {6,	RADIUS_INTEGER4,	"Service Type", radius_service_type_vals, &hf_radius_serviceType},
  {7,	RADIUS_INTEGER4,	"Framed Protocol", radius_framed_protocol_vals, &hf_radius_framedProtocol},
  {8,	RADIUS_IP_ADDRESS,	"Framed IP Address", NULL, &hf_radius_framedAddress},
  {9,	RADIUS_IP_ADDRESS,	"Framed IP Netmask", NULL, NULL},
  {10,	RADIUS_INTEGER4,	"Framed Routing", radius_framed_routing_vals, NULL},
  {11,	RADIUS_STRING,		"Filter Id", NULL, NULL},
  {12,	RADIUS_INTEGER4,	"Framed MTU", NULL, NULL},
  {13,	RADIUS_INTEGER4,	"Framed Compression", radius_framed_compression_vals, NULL},
  {14,	RADIUS_IP_ADDRESS,	"Login IP Host", NULL, NULL},
  {15,	RADIUS_INTEGER4,	"Login Service", radius_login_service_vals, NULL},
  {16,	RADIUS_INTEGER4,	"Login TCP Port", NULL, NULL},
  {17,	RADIUS_UNKNOWN,		"Unassigned", NULL, NULL},
  {18,	RADIUS_STRING,		"Reply Message", NULL, NULL},
  {19,	RADIUS_STRING,		"Callback Number", NULL, NULL},
  {20,	RADIUS_STRING,		"Callback Id", NULL, NULL},
  {21,	RADIUS_UNKNOWN,		"Unassigned", NULL, NULL},
  {22,	RADIUS_STRING,		"Framed Route", NULL, NULL},
  {23,	RADIUS_IPX_ADDRESS,	"Framed IPX network", NULL, NULL},
  {24,	RADIUS_BINSTRING,	"State", NULL, NULL},
  {25,	RADIUS_BINSTRING,	"Class", NULL, &hf_radius_class},
  {26,	RADIUS_VENDOR_SPECIFIC,	"Vendor Specific", NULL, NULL},
  {27,	RADIUS_INTEGER4,	"Session Timeout", NULL, NULL},
  {28,	RADIUS_INTEGER4,	"Idle Timeout", NULL, NULL},
  {29,	RADIUS_INTEGER4,	"Terminating Action", radius_terminating_action_vals, NULL},
  {30,	RADIUS_STRING,		"Called Station Id", NULL, &hf_radius_calledStationId},
  {31,	RADIUS_STRING,		"Calling Station Id", NULL, &hf_radius_callingStationId},
  {32,	RADIUS_STRING,		"NAS identifier", NULL, NULL},
  {33,	RADIUS_BINSTRING,	"Proxy State", NULL, NULL},
  {34,	RADIUS_STRING,		"Login LAT Service", NULL, NULL},
  {35,	RADIUS_STRING,		"Login LAT Node", NULL, NULL},
  {36,	RADIUS_BINSTRING,	"Login LAT Group", NULL, NULL},
  {37,	RADIUS_INTEGER4,	"Framed AppleTalk Link", NULL, NULL},
  {38,	RADIUS_INTEGER4,	"Framed AppleTalk Network", NULL, NULL},
  {39,	RADIUS_STRING,		"Framed AppleTalk Zone", NULL, NULL},
  {40,	RADIUS_INTEGER4,	"Acct Status Type", radius_accounting_status_type_vals, &hf_radius_acctStatusType},
  {41,	RADIUS_INTEGER4,	"Acct Delay Time", NULL, NULL},
  {42,	RADIUS_INTEGER4,	"Acct Input Octets", NULL, NULL},
  {43,	RADIUS_INTEGER4,	"Acct Output Octets", NULL, NULL},
  {44,	RADIUS_STRING,		"Acct Session Id", NULL, &hf_radius_acctSessionId},
  {45,	RADIUS_INTEGER4,	"Acct Authentic", radius_accounting_authentication_vals, NULL},
  {46,	RADIUS_INTEGER4,	"Acct Session Time", NULL, NULL},
  {47,	RADIUS_INTEGER4,	"Acct Input Packets", NULL, NULL},
  {48,	RADIUS_INTEGER4,	"Acct Output Packets", NULL, NULL},
  {49,	RADIUS_INTEGER4,	"Acct Terminate Cause", radius_acct_terminate_cause_vals, NULL},
  {50,	RADIUS_STRING,		"Acct Multi Session Id", NULL, NULL},
  {51,	RADIUS_INTEGER4,	"Acct Link Count", NULL, NULL},
  {52,	RADIUS_INTEGER4,	"Acct Input Gigawords", NULL, NULL},
  {53,	RADIUS_INTEGER4,	"Acct Output Gigawords", NULL, NULL},
  /* 54 Unused */
  {55,	RADIUS_TIMESTAMP,	"Event Timestamp", NULL, NULL},
  /* 56-59 Unused */
  {60,	RADIUS_BINSTRING,	"CHAP Challenge", NULL, NULL},
  {61,	RADIUS_INTEGER4,	"NAS Port Type", radius_nas_port_type_vals, NULL},
  {62,	RADIUS_INTEGER4,	"Port Limit", NULL, NULL},
  {63,	RADIUS_BINSTRING,	"Login LAT Port", NULL, NULL},
  {64,	RADIUS_INTEGER4_TAGGED,	"Tunnel Type", radius_tunnel_type_vals, NULL},
  {65,	RADIUS_INTEGER4_TAGGED,	"Tunnel Medium Type", radius_tunnel_medium_type_vals, NULL},
  {66,	RADIUS_STRING_TAGGED,	"Tunnel Client Endpoint", NULL, NULL},
  {67,	RADIUS_STRING_TAGGED,	"Tunnel Server Endpoint", NULL, NULL},
  {68,	RADIUS_STRING,		"Tunnel Connection", NULL, NULL},
  {69,	RADIUS_STRING_TAGGED,	"Tunnel Password", NULL, NULL},
  {70,	RADIUS_STRING,		"ARAP Password", NULL, NULL},
  {71,	RADIUS_STRING,		"ARAP Features", NULL, NULL},
  {72,	RADIUS_INTEGER4,	"ARAP Zone-Access", NULL, NULL},
  {73,	RADIUS_INTEGER4,	"ARAP Security", NULL, NULL},
  {74,	RADIUS_STRING,		"ARAP Security Data", NULL, NULL},
  {75,	RADIUS_INTEGER4,	"Password Retry", NULL, NULL},
  {76,	RADIUS_INTEGER4,	"Prompt", NULL, NULL},
  {77,	RADIUS_STRING,		"Connect Info", NULL, NULL},
  {78,	RADIUS_STRING,		"Configuration Token", NULL, NULL},
  {79,	RADIUS_EAP_MESSAGE,	"EAP Message", NULL, NULL},
  {80,	RADIUS_BINSTRING,	"Message Authenticator", NULL, NULL},
  {81,	RADIUS_STRING_TAGGED,	"Tunnel Private Group ID", NULL, NULL},
  {82,	RADIUS_STRING_TAGGED,	"Tunnel Assignment ID", NULL, NULL},
  {83,	RADIUS_INTEGER4_TAGGED,	"Tunnel Preference", NULL, NULL},
  {84,	RADIUS_STRING,		"ARAP Challenge Response", NULL, NULL},
  {85,	RADIUS_INTEGER4,	"Acct Interim Interval", NULL, NULL},
  {86,	RADIUS_INTEGER4,	"Tunnel Packets Lost", NULL, NULL},
  {87,	RADIUS_STRING,		"NAS Port ID", NULL, NULL},
  {88,	RADIUS_STRING,		"Framed Pool", NULL, NULL},
  {90,	RADIUS_STRING_TAGGED,	"Tunnel Client Auth ID", NULL, NULL},
  {91,	RADIUS_STRING_TAGGED,	"Tunnel Server Auth ID", NULL, NULL},
  {95,	RADIUS_IP6_ADDRESS,	"NAS IPv6 Address", NULL, NULL},
  {96,	RADIUS_IP6_INTF_ID,	"Framed Interface Id", NULL, NULL},
  {97,	RADIUS_IP6_PREFIX,	"Framed IPv6 Prefix", NULL, NULL},
  {98,	RADIUS_IP6_ADDRESS,	"Login IPv6 Host", NULL, NULL},
  {99,	RADIUS_STRING,		"Framed IPV6 Route", NULL, NULL},
  {100,	RADIUS_STRING,		"Framed IPV6 Pool", NULL, NULL},
  {101,	RADIUS_INTEGER4,	"Error-Cause Attribute",radius_error_cause_attribute_vals, NULL},/*[RFC3576]*/
  {120,	RADIUS_INTEGER4,	"Ascend Modem Port No", NULL, NULL},
  {121,	RADIUS_INTEGER4,	"Ascend Modem Slot No", NULL, NULL},
  {187,	RADIUS_INTEGER4,	"Ascend Multilink ID", NULL, NULL},
  {188,	RADIUS_INTEGER4,	"Ascend Num In Multilink", NULL, NULL},
  {189,	RADIUS_IP_ADDRESS,	"Ascend First Dest", NULL, NULL},
  {190,	RADIUS_INTEGER4,	"Ascend Pre Input Octets", NULL, NULL},
  {191,	RADIUS_INTEGER4,	"Ascend Pre Output Octets", NULL, NULL},
  {192,	RADIUS_INTEGER4,	"Ascend Pre Input Packets", NULL, NULL},
  {193,	RADIUS_INTEGER4,	"Ascend Pre Output Packets", NULL, NULL},
  {194,	RADIUS_INTEGER4,	"Ascend Maximum Time", NULL, NULL},
  {195,	RADIUS_INTEGER4,	"Ascend Disconnect Cause", NULL, NULL},
  {196,	RADIUS_INTEGER4,	"Ascend Connect Progress", NULL, NULL},
  {197,	RADIUS_INTEGER4,	"Ascend Data Rate", NULL, NULL},
  {198,	RADIUS_INTEGER4,	"Ascend PreSession Time", NULL, NULL},
  {211,	RADIUS_STRING,		"Merit Proxy-Action", NULL, NULL},
  {218,	RADIUS_INTEGER4,	"Ascend Assign IP Pool", NULL, NULL},
  {222,	RADIUS_STRING,		"Merit User-Id", NULL, NULL},
  {223,	RADIUS_STRING,		"Merit User-Realm", NULL, NULL},
  {255,	RADIUS_INTEGER4,	"Ascend Xmit Rate", NULL, NULL},
  {0, 0, NULL, NULL, NULL}
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
static const value_string radius_vendor_acct_terminate_cause[] =
{
  {1,	"User Request"},
  {4,	"Idle Timeout"},
  {5,	"Session Timeout"},
  {15,	"Service Unavailable"},
  {0, NULL}
};

static const value_string radius_vendor_acc_role_vals[] =
{
  {1,	"Originating"},
  {2,	"Terminating"},
  {0, NULL}
};
static const radius_attr_info radius_vendor_acc_attrib[] =
{
  {1,	RADIUS_INTEGER4,	"Acc Reason Code", radius_vendor_acc_reason_code_vals, NULL},
  {2,	RADIUS_INTEGER4,	"Acc Ccp Option", radius_vendor_acc_ccp_option_vals, NULL},
  {3,	RADIUS_INTEGER4,	"Acc Input Errors", NULL, NULL},
  {4,	RADIUS_INTEGER4,	"Acc Output Errors", NULL, NULL},
  {5,	RADIUS_STRING,		"Acc Access Partition", NULL, NULL},
  {6,	RADIUS_STRING,		"Acc Customer Id", NULL, NULL},
  {7,	RADIUS_IP_ADDRESS,	"Acc Ip Gateway Pri", NULL, NULL},
  {8,	RADIUS_IP_ADDRESS,	"Acc Ip Gateway Sec", NULL, NULL},
  {9,	RADIUS_INTEGER4,	"Acc Route Policy", radius_vendor_acc_route_policy_vals, NULL},
  {10,	RADIUS_INTEGER4,	"Acc ML MLX Admin State", radius_vendor_acc_ml_mlx_admin_state_vals, NULL},
  {11,	RADIUS_INTEGER4,	"Acc ML Call Threshold", NULL, NULL},
  {12,	RADIUS_INTEGER4,	"Acc ML Clear Threshold", NULL, NULL},
  {13,	RADIUS_INTEGER4,	"Acc ML Damping Factor", NULL, NULL},
  {14,	RADIUS_STRING,		"Acc Tunnel Secret", NULL, NULL},
  {15,	RADIUS_INTEGER4,	"Acc Clearing Cause", q931_cause_code_vals, NULL},
  {16,	RADIUS_INTEGER4,	"Acc Clearing Location", q931_cause_location_vals, NULL},
  {17,	RADIUS_STRING,		"Acc Service Profile", NULL, NULL},
  {18,	RADIUS_INTEGER4,	"Acc Request Type", radius_vendor_acc_request_type_vals, NULL},
  {19,	RADIUS_INTEGER4,	"Acc Bridging Support", radius_vendor_acc_bridging_support_vals, NULL},
  {20,	RADIUS_INTEGER4,	"Acc Apsm Oversubscribed", radius_vendor_acc_apsm_oversubscribed_vals, NULL},
  {21,	RADIUS_INTEGER4,	"Acc Acct On Off Reason", radius_vendor_acc_acct_on_off_reason_vals, NULL},
  {22,	RADIUS_INTEGER4,	"Acc Tunnel Port", NULL, NULL},
  {23,	RADIUS_IP_ADDRESS,	"Acc Dns Server Pri", NULL, NULL},
  {24,	RADIUS_IP_ADDRESS,	"Acc Dns Server Sec", NULL, NULL},
  {25,	RADIUS_IP_ADDRESS,	"Acc Nbns Server Pri", NULL, NULL},
  {26,	RADIUS_IP_ADDRESS,	"Acc Nbns Server Sec", NULL, NULL},
  {27,	RADIUS_INTEGER4,	"Acc Dial Port Index", NULL, NULL},
  {28,	RADIUS_INTEGER4,	"Acc Ip Compression", radius_vendor_acc_ip_compression_vals, NULL},
  {29,	RADIUS_INTEGER4,	"Acc Ipx Compression", radius_vendor_acc_ipx_compression_vals, NULL},
  {30,	RADIUS_INTEGER4,	"Acc Connect Tx Speed", NULL, NULL},
  {31,	RADIUS_INTEGER4,	"Acc Connect Rx Speed", NULL, NULL},
  {32,	RADIUS_STRING,		"Acc Modem Modulation Type", NULL, NULL},
  {33,	RADIUS_STRING,		"Acc Modem Error Protocol", NULL, NULL},
  {34,	RADIUS_INTEGER4,	"Acc Callback Delay", NULL, NULL},
  {35,	RADIUS_STRING,		"Acc Callback Num Valid", NULL, NULL},
  {36,	RADIUS_INTEGER4,	"Acc Callback Mode", radius_vendor_acc_callback_mode_vals, NULL},
  {37,	RADIUS_INTEGER4,	"Acc Callback CBCP Type", radius_vendor_acc_callback_cbcp_type_vals, NULL},
  {38,	RADIUS_INTEGER4,	"Acc Dialout Auth Mode", radius_vendor_acc_dialout_auth_mode_vals, NULL},
  {39,	RADIUS_STRING,		"Acc Dialout Auth Password", NULL, NULL},
  {40,	RADIUS_STRING,		"Acc Dialout Auth Username", NULL, NULL},
  {42,	RADIUS_INTEGER4,	"Acc Access Community", radius_vendor_acc_access_community_vals, NULL},
  {43,	RADIUS_INTEGER4,	"Acc Vpsm Reject Cause", NULL, NULL},
  {44,	RADIUS_STRING,		"Acc Ace Token", NULL, NULL},
  {45,	RADIUS_INTEGER4,	"Acc Ace Token-Ttl", NULL, NULL},
  {46,	RADIUS_STRING,		"Acc Ip Pool Name", NULL, NULL},
  {47,	RADIUS_INTEGER4,	"Acc Igmp Admin State", NULL, NULL},
  {48,	RADIUS_INTEGER4,	"Acc Igmp Version", NULL, NULL},
  {49,	RADIUS_INTEGER4,	"Acct-Terminate-Cause", radius_vendor_acct_terminate_cause, NULL},
  {72,	RADIUS_INTEGER4,	"Acc-Time-For-Start-Of-Charging", NULL, NULL},
  {133, RADIUS_INTEGER4,	"Acc-Role",radius_vendor_acc_role_vals, NULL},


  {0, 0, NULL, NULL, NULL},
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
  {1,	RADIUS_STRING,		"Cisco AV Pair", NULL, NULL},
  {2,	RADIUS_STRING,		"Cisco NAS Port", NULL, NULL},
  /* fax */
  {3,	RADIUS_STRING,		"Fax Account Id Origin", NULL, NULL},
  {4,	RADIUS_STRING,		"Fax Msg Id", NULL, NULL},
  {5,	RADIUS_STRING,		"Fax Pages", NULL, NULL},
  {6,	RADIUS_STRING,		"Fax Cover Page Flag", NULL, NULL},
  {7,	RADIUS_STRING,		"Fax Modem Time", NULL, NULL},
  {8,	RADIUS_STRING,		"Fax Connect Speed", NULL, NULL},
  {9,	RADIUS_STRING,		"Fax Recipent Count", NULL, NULL},
  {10,	RADIUS_STRING,		"Fax Process Abort Flag", NULL, NULL},
  {11,	RADIUS_STRING,		"Fax DSN Address", NULL, NULL},
  {12,	RADIUS_STRING,		"Fax DSN Flag", NULL, NULL},
  {13,	RADIUS_STRING,		"Fax MDN Address", NULL, NULL},
  {14,	RADIUS_STRING,		"Fax MDN Flag", NULL, NULL},
  {15,	RADIUS_STRING,		"Fax Auth Status", NULL, NULL},
  {16,	RADIUS_STRING,		"Email Server Address", NULL, NULL},
  {17,	RADIUS_STRING,		"Email Server Ack Flag", NULL, NULL},
  {18,	RADIUS_STRING,		"Gateway Id", NULL, NULL},
  {19,	RADIUS_STRING,		"Call Type", NULL, NULL},
  {20,	RADIUS_STRING,		"Port Used", NULL, NULL},
  {21,	RADIUS_STRING,		"Abort Cause", NULL, NULL},
  /* #22 */
  /* H323 - Voice over IP attributes. */
  {23,	RADIUS_STRING,		"H323 Remote Address", NULL, NULL},
  {24,	RADIUS_STRING,		"H323 Conf Id", NULL, NULL},
  {25,	RADIUS_STRING,		"H323 Setup Time", NULL, NULL},
  {26,	RADIUS_STRING,		"H323 Call Origin", NULL, NULL},
  {27,	RADIUS_STRING,		"H323 Call Type", NULL, NULL},
  {28,	RADIUS_STRING,		"H323 Connect Time", NULL, NULL},
  {29,	RADIUS_STRING,		"H323 Disconnect Time", NULL, NULL},
  {30,	RADIUS_STRING,		"H323 Disconnect Cause", NULL, NULL},
  {31,	RADIUS_STRING,		"H323 Voice Quality", NULL, NULL},
  /* #32 */
  {33,	RADIUS_STRING,		"H323 GW Id", NULL, NULL},
  /* #34 */
  {35,	RADIUS_STRING,		"H323 Incoming Conf Id", NULL, NULL},
  /* #36-#100 */
  {101,	RADIUS_STRING,		"H323 Credit Amount", NULL, NULL},
  {102,	RADIUS_STRING,		"H323 Credit Time", NULL, NULL},
  {103,	RADIUS_STRING,		"H323 Return Code", NULL, NULL},
  {104,	RADIUS_STRING,		"H323 Prompt Id", NULL, NULL},
  {105,	RADIUS_STRING,		"H323 Time And Day", NULL, NULL},
  {106,	RADIUS_STRING,		"H323 Redirect Number", NULL, NULL},
  {107,	RADIUS_STRING,		"H323 Preferred Lang", NULL, NULL},
  {108,	RADIUS_STRING,		"H323 Redirect Ip Address", NULL, NULL},
  {109,	RADIUS_STRING,		"H323 Billing Model", NULL, NULL},
  {110,	RADIUS_STRING,		"H323 Currency Type", NULL, NULL},
  /* #111-#186 */
/*
       Extra attributes sent by the Cisco, if you configure
       "radius-server vsa accounting" (requires IOS11.2+).
*/
  {187,	RADIUS_INTEGER4,	"Cisco Multilink ID", NULL, NULL},
  {188,	RADIUS_INTEGER4,	"Cisco Num In Multilink", NULL, NULL},
  /* #189 */
  {190,	RADIUS_INTEGER4,	"Cisco Pre Input Octets", NULL, NULL},
  {191,	RADIUS_INTEGER4,	"Cisco Pre Output Octets", NULL, NULL},
  {192,	RADIUS_INTEGER4,	"Cisco Pre Input Packets", NULL, NULL},
  {193,	RADIUS_INTEGER4,	"Cisco Pre Output Packets", NULL, NULL},
  {194,	RADIUS_INTEGER4,	"Cisco Maximum Time", NULL, NULL},
  {195,	RADIUS_INTEGER4,	"Cisco Disconnect Cause", radius_vendor_cisco_disconnect_cause_vals, NULL},
  /* #196 */
  {197,	RADIUS_INTEGER4,	"Cisco Data Rate", NULL, NULL},
  {198,	RADIUS_INTEGER4,	"Cisco PreSession Time", NULL, NULL},
  /* #199-#207 */
  {208,	RADIUS_INTEGER4,	"Cisco PW Lifetime", NULL, NULL},
  {209,	RADIUS_INTEGER4,	"Cisco IP Direct", NULL, NULL},
  {210,	RADIUS_INTEGER4,	"Cisco PPP VJ Slot Comp", NULL, NULL},
  /* #211 */
  {212,	RADIUS_INTEGER4,	"Cisco PPP Async Map", NULL, NULL},
  /* #213-#216 */
  {217,	RADIUS_INTEGER4,	"Cisco IP Pool Definition", NULL, NULL},
  {218,	RADIUS_INTEGER4,	"Cisco Asing IP Pool", NULL, NULL},
  /* #219-#227 */
  {228,	RADIUS_INTEGER4,	"Cisco Route IP", NULL, NULL},
  /* #229-#232 */
  {233,	RADIUS_INTEGER4,	"Cisco Link Compression", NULL, NULL},
  {234,	RADIUS_INTEGER4,	"Cisco Target Util", NULL, NULL},
  {235,	RADIUS_INTEGER4,	"Cisco Maximum Channels", NULL, NULL},
  /* #236-#241 */
  {242,	RADIUS_INTEGER4,	"Cisco Data Filter", NULL, NULL},
  {243,	RADIUS_INTEGER4,	"Cisco Call Filter", NULL, NULL},
  {244,	RADIUS_INTEGER4,	"Cisco Idle Limit", NULL, NULL},
  /* Cisco SSG Service Selection Gateway Attributes */
  {250, RADIUS_STRING,		"Cisco Account Info", NULL, &hf_radius_cisco_cai},
  {251, RADIUS_STRING,		"Cisco Service Info", NULL, NULL},
  {252, RADIUS_BINSTRING,	"Cisco Command Info", NULL, NULL},
  {253, RADIUS_STRING,		"Cisco Control Info", NULL, NULL},
  {255,	RADIUS_INTEGER4,	"Cisco Xmit Rate", NULL, NULL},
  {0, 0, NULL, NULL, NULL}
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
  {1,	RADIUS_STRING,		"Shiva User Attributes", NULL, NULL},
  {90,	RADIUS_STRING,		"Shiva Called Number", NULL, NULL},
  {91,	RADIUS_STRING,		"Shiva Calling Number", NULL, NULL},
  {92,	RADIUS_STRING,		"Shiva Customer Id", NULL, NULL},
  {93,	RADIUS_INTEGER4,	"Shiva Type Of Service", radius_vendor_shiva_type_of_service_vals, NULL},
  {94,	RADIUS_INTEGER4,	"Shiva Link Speed", NULL, NULL},
  {95,	RADIUS_INTEGER4,	"Shiva Links In Bundle", NULL, NULL},
  {96,	RADIUS_INTEGER4,	"Shiva Compression Type", NULL, NULL},
  {97,	RADIUS_INTEGER4,	"Shiva Link Protocol", radius_vendor_shiva_link_protocol_vals, NULL},
  {98,	RADIUS_INTEGER4,	"Shiva Network Protocols", NULL, NULL},
  {99,	RADIUS_INTEGER4,	"Shiva Session Id", NULL, NULL},
  {100,	RADIUS_INTEGER4,	"Shiva Disconnect Reason", radius_vendor_shiva_disconnect_reason_vals, NULL},
  {101,	RADIUS_IP_ADDRESS,	"Shiva Acct Serv Switch", NULL, NULL},
  {102,	RADIUS_INTEGER4,	"Shiva Event Flags", NULL, NULL},
  {103,	RADIUS_INTEGER4,	"Shiva Function", radius_vendor_shiva_function_vals, NULL},
  {104,	RADIUS_INTEGER4,	"Shiva Connect Reason", radius_vendor_shiva_connect_reason_vals, NULL},
  {0, 0, NULL, NULL, NULL},
};

/*
reference:
	Cisco ACS 3.2 User Guide - Appendix D
	http://www.cisco.com/univercd/cc/td/doc/product/access/acs_soft/csacs4nt/acs32/user02/ad.htm#wp473517
*/


static const radius_attr_info radius_vendor_cisco_vpn5000_attrib[] =
{
  {1,	RADIUS_INTEGER4,		"CVPN5000-Tunnel-Throughput", NULL, NULL},
  {2,	RADIUS_IP_ADDRESS,	"CVPN5000-Client-Assigned-IP", NULL, NULL},
  {3,	RADIUS_IP_ADDRESS,	"CVPN5000-Client-Real-IP", NULL, NULL},
  {4,	RADIUS_STRING,		"CVPN5000-VPN-GroupInfo", NULL, NULL},
  {5,	RADIUS_STRING,		"CVPN5000-VPN-Password", NULL, NULL},
  {6,	RADIUS_INTEGER4,		"CVPN5000-Echo", NULL, NULL},
  {7,	RADIUS_INTEGER4,		"CVPN5000-Client-Assigned-IPX", NULL, NULL},
  {0, 0, NULL, NULL, NULL},
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
  {2,	RADIUS_STRING,		"LE Terminate Detail", NULL, NULL},
  {3,	RADIUS_STRING,		"LE Advice of Charge", NULL, NULL},
  {4,	RADIUS_STRING,		"LE Connect Detail", NULL, NULL},
  {6,	RADIUS_STRING,		"LE IP Pool", NULL, NULL},
  {7,	RADIUS_IP_ADDRESS,	"LE IP Gateway", NULL, NULL},
  {8,	RADIUS_STRING,		"LE Modem Info", NULL, NULL},
  {9,	RADIUS_INTEGER4,	"LE IPSec Log Options", radius_vendor_livingston_ipsec_log_options_vals, NULL},
  {10,	RADIUS_INTEGER4,	"LE IPSec Deny Action", radius_vendor_livingston_ipsec_deny_action_vals, NULL},
  {11,	RADIUS_STRING,		"LE IPSec Active Profile", NULL, NULL},
  {12,	RADIUS_STRING,		"LE IPSec Outsource Profile", NULL, NULL},
  {13,	RADIUS_STRING,		"LE IPSec Passive Profile", NULL, NULL},
  {14,	RADIUS_INTEGER4,	"LE NAT TCP Session Timeout", NULL, NULL},
  {15,	RADIUS_INTEGER4,	"LE NAT Other Session Timeout", NULL, NULL},
  {16,	RADIUS_INTEGER4,	"LE NAT Log Options", radius_vendor_livingston_nat_log_options_vals, NULL},
  {17,	RADIUS_INTEGER4,	"LE NAT Sess Dir Fail Action", radius_vendor_livingston_nat_sess_dir_fail_action_vals, NULL},
  {18,	RADIUS_STRING,		"LE NAT Inmap", NULL, NULL},
  {19,	RADIUS_STRING,		"LE NAT Outmap", NULL, NULL},
  {20,	RADIUS_STRING,		"LE NAT Outsource Inmap", NULL, NULL},
  {21,	RADIUS_STRING,		"LE NAT Outsource Outmap", NULL, NULL},
  {22,	RADIUS_STRING,		"LE Admin Group", NULL, NULL},
  {23,	RADIUS_INTEGER4,	"LE Multicast Client", radius_vendor_livingston_multicast_client_vals, NULL},
  {0, 0, NULL, NULL, NULL},
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
  {1,	RADIUS_BINSTRING,	"MS CHAP Response", NULL, NULL},
  {2,	RADIUS_STRING,		"MS CHAP Error", NULL, NULL},
  {3,	RADIUS_BINSTRING,	"MS CHAP CPW 1", NULL, NULL},
  {4,	RADIUS_BINSTRING,	"MS CHAP CPW 2", NULL, NULL},
  {5,	RADIUS_BINSTRING,	"MS CHAP LM Enc PW", NULL, NULL},
  {6,	RADIUS_BINSTRING,	"MS CHAP NT Enc PW", NULL, NULL},
  {7,	RADIUS_BINSTRING,	"MS MPPE Encryption Policy", NULL, NULL},
  {8,	RADIUS_BINSTRING,	"MS MPPE Encryption Type", NULL, NULL},
  {9,	RADIUS_INTEGER4,	"MS RAS Vendor", NULL, NULL},
  {10,	RADIUS_STRING,		"MS CHAP Domain", NULL, NULL},
  {11,	RADIUS_BINSTRING,	"MS CHAP Challenge", NULL, NULL},
  {12,	RADIUS_BINSTRING,	"MS CHAP MPPE Keys", NULL, NULL},
  {13,	RADIUS_INTEGER4,	"MS BAP Usage", radius_vendor_microsoft_bap_usage_vals, NULL},
  {14,	RADIUS_INTEGER4,	"MS Link Utilization Threshold", NULL, NULL},
  {15,	RADIUS_INTEGER4,	"MS Link Drop Time Limit", NULL, NULL},
  {16,	RADIUS_BINSTRING,	"MS MPPE Send Key", NULL, NULL},
  {17,	RADIUS_BINSTRING,	"MS MPPE Recv Key", NULL, NULL},
  {18,	RADIUS_STRING,		"MS RAS Version", NULL, NULL},
  {19,	RADIUS_BINSTRING,	"MS Old ARAP Password", NULL, NULL},
  {20,	RADIUS_BINSTRING,	"MS New ARAP Password", NULL, NULL},
  {21,	RADIUS_INTEGER4,	"MS ARAP PW Change Reason", radius_vendor_microsoft_arap_pw_change_reason_vals, NULL},
  {22,	RADIUS_BINSTRING,	"MS Filter", NULL, NULL},
  {23,	RADIUS_INTEGER4,	"MS Acct Auth Type", radius_vendor_microsoft_acct_auth_type_vals, NULL},
  {24,	RADIUS_INTEGER4,	"MS Acct EAP Type", radius_vendor_microsoft_acct_eap_type_vals, NULL},
  {25,	RADIUS_BINSTRING,	"MS CHAP2 Response", NULL, NULL},
  {26,	RADIUS_BINSTRING,	"MS CHAP2 Success", NULL, NULL},
  {27,	RADIUS_BINSTRING,	"MS CHAP2 CPW", NULL, NULL},
  {28,	RADIUS_IP_ADDRESS,	"MS Primary DNS Server", NULL, NULL},
  {29,	RADIUS_IP_ADDRESS,	"MS Secondary DNS Server", NULL, NULL},
  {30,	RADIUS_IP_ADDRESS,	"MS Primary NBNS Server", NULL, NULL},
  {31,	RADIUS_IP_ADDRESS,	"MS Secondary NBNS Server", NULL, NULL},
  {0, 0, NULL, NULL, NULL}
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
  {7,	RADIUS_STRING,		"Ascend UU Info", NULL, NULL},
  {9,	RADIUS_INTEGER4,	"Ascend CIR Timer", NULL, NULL},
  {10,	RADIUS_INTEGER4,	"Ascend FR 08 Mode", NULL, NULL},
  {11,	RADIUS_INTEGER4,	"Ascend Destination Nas Port", NULL, NULL},
  {12,	RADIUS_STRING,		"Ascend FR SVC Addr", NULL, NULL},
  {13,	RADIUS_INTEGER4,	"Ascend NAS Port Format", NULL, NULL},
  {14,	RADIUS_INTEGER4,	"Ascend ATM Fault Management", NULL, NULL},
  {15,	RADIUS_INTEGER4,	"Ascend ATM Loopback Cell Loss", NULL, NULL},
  {16,	RADIUS_INTEGER4,	"Ascend Ckt Type", NULL, NULL},
  {17,	RADIUS_INTEGER4,	"Ascend SVC Enabled", NULL, NULL},
  {18,	RADIUS_INTEGER4,	"Ascend Session Type", NULL, NULL},
  {19,	RADIUS_IP_ADDRESS,	"Ascend H323 Gatekeeper", NULL, NULL},
  {20,	RADIUS_STRING,		"Ascend Global Call Id", NULL, NULL},
  {21,	RADIUS_INTEGER4,	"Ascend H323 Conference Id", NULL, NULL},
  {22,	RADIUS_IP_ADDRESS,	"Ascend H323 Fegw Address", NULL, NULL},
  {23,	RADIUS_INTEGER4,	"Ascend H323 Dialed Time", NULL, NULL},
  {24,	RADIUS_STRING,		"Ascend Dialed Number", NULL, NULL},
  {25,	RADIUS_INTEGER4,	"Ascend Inter Arrival Jitter", NULL, NULL},
  {26,	RADIUS_INTEGER4,	"Ascend Dropped Octets", NULL, NULL},
  {27,	RADIUS_INTEGER4,	"Ascend Dropped Packets", NULL, NULL},
  {29,	RADIUS_INTEGER4,	"Ascend X25 Pad X3 Profile", NULL, NULL},
  {30,	RADIUS_STRING,		"Ascend X25 Pad X3 Parameters", NULL, NULL},
  {31,	RADIUS_STRING,		"Ascend Tunnel VRouter Name", NULL, NULL},
  {32,	RADIUS_INTEGER4,	"Ascend X25 Reverse Charging", NULL, NULL},
  {33,	RADIUS_STRING,		"Ascend X25 Nui Prompt", NULL, NULL},
  {34,	RADIUS_STRING,		"Ascend X25 Nui Password Prompt", NULL, NULL},
  {35,	RADIUS_STRING,		"Ascend X25 Cug", NULL, NULL},
  {36,	RADIUS_STRING,		"Ascend X25 Pad Alias 1", NULL, NULL},
  {37,	RADIUS_STRING,		"Ascend X25 Pad Alias 2", NULL, NULL},
  {38,	RADIUS_STRING,		"Ascend X25 Pad Alias 3", NULL, NULL},
  {39,	RADIUS_STRING,		"Ascend X25 X121 Address", NULL, NULL},
  {40,	RADIUS_STRING,		"Ascend X25 Nui", NULL, NULL},
  {41,	RADIUS_STRING,		"Ascend X25 Rpoa", NULL, NULL},
  {42,	RADIUS_STRING,		"Ascend X25 Pad Prompt", NULL, NULL},
  {43,	RADIUS_STRING,		"Ascend X25 Pad Banner", NULL, NULL},
  {44,	RADIUS_STRING,		"Ascend X25 Profile Name", NULL, NULL},
  {45,	RADIUS_STRING,		"Ascend Recv Name", NULL, NULL},
  {46,	RADIUS_INTEGER4,	"Ascend Bi Directional Auth", NULL, NULL},
  {47,	RADIUS_INTEGER4,	"Ascend MTU", NULL, NULL},
  {48,	RADIUS_INTEGER4,	"Ascend Call Direction", NULL, NULL},
  {49,	RADIUS_INTEGER4,	"Ascend Service Type", NULL, NULL},
  {50,	RADIUS_INTEGER4,	"Ascend Filter Required", NULL, NULL},
  {51,	RADIUS_INTEGER4,	"Ascend Traffic Shaper", NULL, NULL},
  {52,	RADIUS_STRING,		"Ascend Access Intercept LEA", NULL, NULL},
  {53,	RADIUS_STRING,		"Ascend Access Intercept Log", NULL, NULL},
  {54,	RADIUS_STRING,		"Ascend Private Route Table ID", NULL, NULL},
  {55,	RADIUS_INTEGER4,	"Ascend Private Route Required", NULL, NULL},
  {56,	RADIUS_INTEGER4,	"Ascend Cache Refresh", NULL, NULL},
  {57,	RADIUS_INTEGER4,	"Ascend Cache Time", NULL, NULL},
  {58,	RADIUS_INTEGER4,	"Ascend Egress Enabled", NULL, NULL},
  {59,	RADIUS_STRING,		"Ascend QOS Upstream", NULL, NULL},
  {60,	RADIUS_STRING,		"Ascend QOS Downstream", NULL, NULL},
  {61,	RADIUS_INTEGER4,	"Ascend ATM Connect Vpi", NULL, NULL},
  {62,	RADIUS_INTEGER4,	"Ascend ATM Connect Vci", NULL, NULL},
  {63,	RADIUS_INTEGER4,	"Ascend ATM Connect Group", NULL, NULL},
  {64,	RADIUS_INTEGER4,	"Ascend ATM Group", NULL, NULL},
  {65,	RADIUS_INTEGER4,	"Ascend IPX Header Compression", NULL, NULL},
  {66,	RADIUS_INTEGER4,	"Ascend Calling Id Type Of Number", radius_vendor_ascend_calling_id_type_of_number_vals, NULL},
  {67,	RADIUS_INTEGER4,	"Ascend Calling Id Numbering Plan", radius_vendor_ascend_calling_id_numbering_plan_vals, NULL},
  {68,	RADIUS_INTEGER4,	"Ascend Calling Id Presentation", radius_vendor_ascend_calling_id_presentation_vals, NULL},
  {69,	RADIUS_INTEGER4,	"Ascend Calling Id Screening", radius_vendor_ascend_calling_id_screening_vals, NULL},
  {70,	RADIUS_INTEGER4,	"Ascend BIR Enable", NULL, NULL},
  {71,	RADIUS_INTEGER4,	"Ascend BIR Proxy", NULL, NULL},
  {72,	RADIUS_INTEGER4,	"Ascend BIR Bridge Group", NULL, NULL},
  {73,	RADIUS_STRING,		"Ascend IPSEC Profile", NULL, NULL},
  {74,	RADIUS_INTEGER4,	"Ascend PPPoE Enable", NULL, NULL},
  {75,	RADIUS_INTEGER4,	"Ascend Bridge Non PPPoE", NULL, NULL},
  {76,	RADIUS_INTEGER4,	"Ascend ATM Direct", NULL, NULL},
  {77,	RADIUS_STRING,		"Ascend ATM Direct Profile", NULL, NULL},
  {78,	RADIUS_IP_ADDRESS,	"Ascend Client Primary WINS", NULL, NULL},
  {79,	RADIUS_IP_ADDRESS,	"Ascend Client Secondary WINS", NULL, NULL},
  {80,	RADIUS_INTEGER4,	"Ascend Client Assign WINS", NULL, NULL},
  {81,	RADIUS_INTEGER4,	"Ascend Auth Type", NULL, NULL},
  {82,	RADIUS_INTEGER4,	"Ascend Port Redir Protocol", NULL, NULL},
  {83,	RADIUS_INTEGER4,	"Ascend Port Redir Portnum", NULL, NULL},
  {84,	RADIUS_IP_ADDRESS,	"Ascend Port Redir Server", NULL, NULL},
  {85,	RADIUS_INTEGER4,	"Ascend IP Pool Chaining", NULL, NULL},
  {86,	RADIUS_IP_ADDRESS,	"Ascend Owner IP Addr", NULL, NULL},
  {87,	RADIUS_INTEGER4,	"Ascend IP TOS", NULL, NULL},
  {88,	RADIUS_INTEGER4,	"Ascend IP TOS Precedence", NULL, NULL},
  {89,	RADIUS_INTEGER4,	"Ascend IP TOS Apply To", NULL, NULL},
  {90,	RADIUS_STRING,		"Ascend Filter", NULL, NULL},
  {91,	RADIUS_STRING,		"Ascend Telnet Profile", NULL, NULL},
  {92,	RADIUS_INTEGER4,	"Ascend Dsl Rate Type", NULL, NULL},
  {93,	RADIUS_STRING,		"Ascend Redirect Number", NULL, NULL},
  {94,	RADIUS_INTEGER4,	"Ascend ATM Vpi", NULL, NULL},
  {95,	RADIUS_INTEGER4,	"Ascend ATM Vci", NULL, NULL},
  {96,	RADIUS_INTEGER4,	"Ascend Source IP Check", NULL, NULL},
  {97,	RADIUS_INTEGER4,	"Ascend Dsl Rate Mode", NULL, NULL},
  {98,	RADIUS_INTEGER4,	"Ascend Dsl Upstream Limit", NULL, NULL},
  {99,	RADIUS_INTEGER4,	"Ascend Dsl Downstream Limit", NULL, NULL},
  {100,	RADIUS_INTEGER4,	"Ascend Dsl CIR Recv Limit", NULL, NULL},
  {101,	RADIUS_INTEGER4,	"Ascend Dsl CIR Xmit Limit", NULL, NULL},
  {102,	RADIUS_STRING,		"Ascend VRouter Name", NULL, NULL},
  {103,	RADIUS_STRING,		"Ascend Source Auth", NULL, NULL},
  {104,	RADIUS_STRING,		"Ascend Private Route", NULL, NULL},
  {105,	RADIUS_INTEGER4,	"Ascend Numbering Plan ID", NULL, NULL},
  {106,	RADIUS_INTEGER4,	"Ascend FR Link Status DLCI", NULL, NULL},
  {107,	RADIUS_STRING,		"Ascend Calling Subaddress", NULL, NULL},
  {108,	RADIUS_INTEGER4,	"Ascend Callback Delay", NULL, NULL},
  {109,	RADIUS_STRING,		"Ascend Endpoint Disc", NULL, NULL},
  {110,	RADIUS_STRING,		"Ascend Remote FW", NULL, NULL},
  {111,	RADIUS_INTEGER4,	"Ascend Multicast GLeave Delay", NULL, NULL},
  {112,	RADIUS_INTEGER4,	"Ascend CBCP Enable", NULL, NULL},
  {113,	RADIUS_INTEGER4,	"Ascend CBCP Mode", NULL, NULL},
  {114,	RADIUS_INTEGER4,	"Ascend CBCP Delay", NULL, NULL},
  {115,	RADIUS_INTEGER4,	"Ascend CBCP Trunk Group", NULL, NULL},
  {116,	RADIUS_STRING,		"Ascend Appletalk Route", NULL, NULL},
  {117,	RADIUS_INTEGER4,	"Ascend Appletalk Peer Mode", NULL, NULL},
  {118,	RADIUS_INTEGER4,	"Ascend Route Appletalk", NULL, NULL},
  {119,	RADIUS_STRING,		"Ascend FCP Parameter", NULL, NULL},
  {120,	RADIUS_INTEGER4,	"Ascend Modem Port No", NULL, NULL},
  {121,	RADIUS_INTEGER4,	"Ascend Modem Slot No", NULL, NULL},
  {122,	RADIUS_INTEGER4,	"Ascend Modem Shelf No", NULL, NULL},
  {123,	RADIUS_INTEGER4,	"Ascend Call Attempt Limit", NULL, NULL},
  {124,	RADIUS_INTEGER4,	"Ascend Call Block Duration", NULL, NULL},
  {125,	RADIUS_INTEGER4,	"Ascend Maximum Call Duration", NULL, NULL},
  {126,	RADIUS_INTEGER4,	"Ascend Temporary Rtes", NULL, NULL},
  {127,	RADIUS_INTEGER4,	"Ascend Tunneling Protocol", NULL, NULL},
  {128,	RADIUS_INTEGER4,	"Ascend Shared Profile Enable", NULL, NULL},
  {129,	RADIUS_STRING,		"Ascend Primary Home Agent", NULL, NULL},
  {130,	RADIUS_STRING,		"Ascend Secondary Home Agent", NULL, NULL},
  {131,	RADIUS_INTEGER4,	"Ascend Dialout Allowed", NULL, NULL},
  {132,	RADIUS_IP_ADDRESS,	"Ascend Client Gateway", NULL, NULL},
  {133,	RADIUS_INTEGER4,	"Ascend BACP Enable", NULL, NULL},
  {134,	RADIUS_INTEGER4,	"Ascend DHCP Maximum Leases", NULL, NULL},
  {135,	RADIUS_IP_ADDRESS,	"Ascend Client Primary DNS", NULL, NULL},
  {136,	RADIUS_IP_ADDRESS,	"Ascend Client Secondary DNS", NULL, NULL},
  {137,	RADIUS_INTEGER4,	"Ascend Client Assign DNS", NULL, NULL},
  {138,	RADIUS_INTEGER4,	"Ascend User Acct Type", NULL, NULL},
  {139,	RADIUS_IP_ADDRESS,	"Ascend User Acct Host", NULL, NULL},
  {140,	RADIUS_INTEGER4,	"Ascend User Acct Port", NULL, NULL},
  {141,	RADIUS_STRING,		"Ascend User Acct Key", NULL, NULL},
  {142,	RADIUS_INTEGER4,	"Ascend User Acct Base", NULL, NULL},
  {143,	RADIUS_INTEGER4,	"Ascend User Acct Time", NULL, NULL},
  {144,	RADIUS_IP_ADDRESS,	"Ascend Assign IP Client", NULL, NULL},
  {145,	RADIUS_IP_ADDRESS,	"Ascend Assign IP Server", NULL, NULL},
  {146,	RADIUS_STRING,		"Ascend Assign IP Global Pool", NULL, NULL},
  {147,	RADIUS_INTEGER4,	"Ascend DHCP Reply", NULL, NULL},
  {148,	RADIUS_INTEGER4,	"Ascend DHCP Pool Number", NULL, NULL},
  {149,	RADIUS_INTEGER4,	"Ascend Expect Callback", NULL, NULL},
  {150,	RADIUS_INTEGER4,	"Ascend Event Type", NULL, NULL},
  {151,	RADIUS_STRING,		"Ascend Session Svr Key", NULL, NULL},
  {152,	RADIUS_INTEGER4,	"Ascend Multicast Rate Limit", NULL, NULL},
  {153,	RADIUS_IP_ADDRESS,	"Ascend IF Netmask", NULL, NULL},
  {154,	RADIUS_IP_ADDRESS,	"Ascend Remote Addr", NULL, NULL},
  {155,	RADIUS_INTEGER4,	"Ascend Multicast Client", NULL, NULL},
  {156,	RADIUS_STRING,		"Ascend FR Circuit Name", NULL, NULL},
  {157,	RADIUS_INTEGER4,	"Ascend FR LinkUp", NULL, NULL},
  {158,	RADIUS_INTEGER4,	"Ascend FR Nailed Grp", NULL, NULL},
  {159,	RADIUS_INTEGER4,	"Ascend FR Type", NULL, NULL},
  {160,	RADIUS_INTEGER4,	"Ascend FR Link Mgt", NULL, NULL},
  {161,	RADIUS_INTEGER4,	"Ascend FR N391", NULL, NULL},
  {162,	RADIUS_INTEGER4,	"Ascend FR DCE N392", NULL, NULL},
  {163,	RADIUS_INTEGER4,	"Ascend FR DTE N392", NULL, NULL},
  {164,	RADIUS_INTEGER4,	"Ascend FR DCE N393", NULL, NULL},
  {165,	RADIUS_INTEGER4,	"Ascend FR DTE N393", NULL, NULL},
  {166,	RADIUS_INTEGER4,	"Ascend FR T391", NULL, NULL},
  {167,	RADIUS_INTEGER4,	"Ascend FR T392", NULL, NULL},
  {168,	RADIUS_STRING,		"Ascend Bridge Address", NULL, NULL},
  {169,	RADIUS_INTEGER4,	"Ascend TS Idle Limit", NULL, NULL},
  {170,	RADIUS_INTEGER4,	"Ascend TS Idle Mode", NULL, NULL},
  {171,	RADIUS_INTEGER4,	"Ascend DBA Monitor", NULL, NULL},
  {172,	RADIUS_INTEGER4,	"Ascend Base Channel Count", NULL, NULL},
  {173,	RADIUS_INTEGER4,	"Ascend Minimum Channels", NULL, NULL},
  {174,	RADIUS_STRING,		"Ascend IPX Route", NULL, NULL},
  {175,	RADIUS_INTEGER4,	"Ascend FT1 Caller", NULL, NULL},
  {176,	RADIUS_STRING,		"Ascend Backup", NULL, NULL},
  {177,	RADIUS_INTEGER4,	"Ascend Call Type", NULL, NULL},
  {178,	RADIUS_STRING,		"Ascend Group", NULL, NULL},
  {179,	RADIUS_INTEGER4,	"Ascend FR DLCI", NULL, NULL},
  {180,	RADIUS_STRING,		"Ascend FR Profile Name", NULL, NULL},
  {181,	RADIUS_STRING,		"Ascend Ara PW", NULL, NULL},
  {182,	RADIUS_STRING,		"Ascend IPX Node Addr", NULL, NULL},
  {183,	RADIUS_IP_ADDRESS,	"Ascend Home Agent IP Addr", NULL, NULL},
  {184,	RADIUS_STRING,		"Ascend Home Agent Password", NULL, NULL},
  {185,	RADIUS_STRING,		"Ascend Home Network Name", NULL, NULL},
  {186,	RADIUS_INTEGER4,	"Ascend Home Agent UDP Port", NULL, NULL},
  {187,	RADIUS_INTEGER4,	"Ascend Multilink ID", NULL, NULL},
  {188,	RADIUS_INTEGER4,	"Ascend Num In Multilink", NULL, NULL},
  {189,	RADIUS_IP_ADDRESS,	"Ascend First Dest", NULL, NULL},
  {190,	RADIUS_INTEGER4,	"Ascend Pre Input Octets", NULL, NULL},
  {191,	RADIUS_INTEGER4,	"Ascend Pre Output Octets", NULL, NULL},
  {192,	RADIUS_INTEGER4,	"Ascend Pre Input Packets", NULL, NULL},
  {193,	RADIUS_INTEGER4,	"Ascend Pre Output Packets", NULL, NULL},
  {194,	RADIUS_INTEGER4,	"Ascend Maximum Time", NULL, NULL},
  {195,	RADIUS_INTEGER4,	"Ascend Disconnect Cause", NULL, NULL},
  {196,	RADIUS_INTEGER4,	"Ascend Connect Progress", NULL, NULL},
  {197,	RADIUS_INTEGER4,	"Ascend Data Rate", NULL, NULL},
  {198,	RADIUS_INTEGER4,	"Ascend PreSession Time", NULL, NULL},
  {199,	RADIUS_INTEGER4,	"Ascend Token Idle", NULL, NULL},
  {200,	RADIUS_INTEGER4,	"Ascend Token Immediate", NULL, NULL},
  {201,	RADIUS_INTEGER4,	"Ascend Require Auth", NULL, NULL},
  {202,	RADIUS_STRING,		"Ascend Number Sessions", NULL, NULL},
  {203,	RADIUS_STRING,		"Ascend Authen Alias", NULL, NULL},
  {204,	RADIUS_INTEGER4,	"Ascend Token Expiry", NULL, NULL},
  {205,	RADIUS_STRING,		"Ascend Menu Selector", NULL, NULL},
  {206,	RADIUS_STRING,		"Ascend Menu Item", NULL, NULL},
  {207,	RADIUS_INTEGER4,	"Ascend PW Warntime", NULL, NULL},
  {208,	RADIUS_INTEGER4,	"Ascend PW Lifetime", NULL, NULL},
  {209,	RADIUS_IP_ADDRESS,	"Ascend IP Direct", NULL, NULL},
  {210,	RADIUS_INTEGER4,	"Ascend PPP VJ Slot Comp", NULL, NULL},
  {211,	RADIUS_INTEGER4,	"Ascend PPP VJ 1172", NULL, NULL},
  {212,	RADIUS_INTEGER4,	"Ascend PPP Async Map", NULL, NULL},
  {213,	RADIUS_STRING,		"Ascend Third Prompt", NULL, NULL},
  {214,	RADIUS_STRING,		"Ascend Send Secret", NULL, NULL},
  {215,	RADIUS_STRING,		"Ascend Receive Secret", NULL, NULL},
  {216,	RADIUS_INTEGER4,	"Ascend IPX Peer Mode", NULL, NULL},
  {217,	RADIUS_STRING,		"Ascend IP Pool Definition", NULL, NULL},
  {218,	RADIUS_INTEGER4,	"Ascend Assign IP Pool", NULL, NULL},
  {219,	RADIUS_INTEGER4,	"Ascend FR Direct", NULL, NULL},
  {220,	RADIUS_STRING,		"Ascend FR Direct Profile", NULL, NULL},
  {221,	RADIUS_INTEGER4,	"Ascend FR Direct DLCI", NULL, NULL},
  {222,	RADIUS_INTEGER4,	"Ascend Handle IPX", NULL, NULL},
  {223,	RADIUS_INTEGER4,	"Ascend Netware timeout", NULL, NULL},
  {224,	RADIUS_INTEGER4,	"Ascend IPX Alias", NULL, NULL},
  {225,	RADIUS_INTEGER4,	"Ascend Metric", NULL, NULL},
  {226,	RADIUS_INTEGER4,	"Ascend PRI Number Type", NULL, NULL},
  {227,	RADIUS_STRING,		"Ascend Dial Number", NULL, NULL},
  {228,	RADIUS_INTEGER4,	"Ascend Route IP", NULL, NULL},
  {229,	RADIUS_INTEGER4,	"Ascend Route IPX", NULL, NULL},
  {230,	RADIUS_INTEGER4,	"Ascend Bridge", NULL, NULL},
  {231,	RADIUS_INTEGER4,	"Ascend Send Auth", NULL, NULL},
  {232,	RADIUS_STRING,		"Ascend Send Passwd", NULL, NULL},
  {233,	RADIUS_INTEGER4,	"Ascend Link Compression", NULL, NULL},
  {234,	RADIUS_INTEGER4,	"Ascend Target Util", NULL, NULL},
  {235,	RADIUS_INTEGER4,	"Ascend Maximum Channels", NULL, NULL},
  {236,	RADIUS_INTEGER4,	"Ascend Inc Channel Count", NULL, NULL},
  {237,	RADIUS_INTEGER4,	"Ascend Dec Channel Count", NULL, NULL},
  {238,	RADIUS_INTEGER4,	"Ascend Seconds Of History", NULL, NULL},
  {239,	RADIUS_INTEGER4,	"Ascend History Weigh Type", NULL, NULL},
  {240,	RADIUS_INTEGER4,	"Ascend Add Seconds", NULL, NULL},
  {241,	RADIUS_INTEGER4,	"Ascend Remove Seconds", NULL, NULL},
  {242,	RADIUS_BINSTRING,	"Ascend Data Filter", NULL, NULL},
  {243,	RADIUS_BINSTRING,	"Ascend Call Filter", NULL, NULL},
  {244,	RADIUS_INTEGER4,	"Ascend Idle Limit", NULL, NULL},
  {245,	RADIUS_INTEGER4,	"Ascend Preempt Limit", NULL, NULL},
  {246,	RADIUS_INTEGER4,	"Ascend Callback", NULL, NULL},
  {247,	RADIUS_INTEGER4,	"Ascend Data Svc", NULL, NULL},
  {248,	RADIUS_INTEGER4,	"Ascend Force 56", NULL, NULL},
  {249,	RADIUS_STRING,		"Ascend Billing Number", NULL, NULL},
  {250,	RADIUS_INTEGER4,	"Ascend Call By Call", NULL, NULL},
  {251,	RADIUS_STRING,		"Ascend Transit Number", NULL, NULL},
  {252,	RADIUS_STRING,		"Ascend Host Info", NULL, NULL},
  {253,	RADIUS_IP_ADDRESS,	"Ascend PPP Address", NULL, NULL},
  {254,	RADIUS_INTEGER4,	"Ascend MPP Idle Percent", NULL, NULL},
  {255,	RADIUS_INTEGER4,	"Ascend Xmit Rate", NULL, NULL},
  {0, 0, NULL, NULL, NULL}
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
  {28,	RADIUS_STRING,		"Annex Filter", NULL, NULL},
  {29,	RADIUS_STRING,		"Annex CLI Command", NULL, NULL},
  {30,	RADIUS_STRING,		"Annex CLI Filter", NULL, NULL},
  {31,	RADIUS_STRING,		"Annex Host Restrict", NULL, NULL},
  {32,	RADIUS_STRING,		"Annex Host Allow", NULL, NULL},
  {33,	RADIUS_STRING,		"Annex Product Name", NULL, NULL},
  {34,	RADIUS_STRING,		"Annex SW Version", NULL, NULL},
  {35,	RADIUS_IP_ADDRESS,	"Annex Local IP Address", NULL, NULL},
  {36,	RADIUS_INTEGER4,	"Annex Callback Portlist", NULL, NULL},
  {37,	RADIUS_INTEGER4,	"Annex Sec Profile Index", NULL, NULL},
  {38,	RADIUS_INTEGER4,	"Annex Tunnel Authen Type", radius_vendor_bay_tunnel_authen_type_vals, NULL},
  {39,	RADIUS_INTEGER4,	"Annex Tunnel Authen Mode", radius_vendor_bay_tunnel_authen_mode_vals, NULL},
  {40,	RADIUS_STRING,		"Annex Authen Servers", NULL, NULL},
  {41,	RADIUS_STRING,		"Annex Acct Servers", NULL, NULL},
  {42,	RADIUS_INTEGER4,	"Annex User Server Location", radius_vendor_bay_user_server_location_vals, NULL},
  {43,	RADIUS_STRING,		"Annex Local Username", NULL, NULL},
  {44,	RADIUS_INTEGER4,	"Annex System Disc Reason", radius_vendor_bay_system_disc_reason_vals, NULL},
  {45,	RADIUS_INTEGER4,	"Annex Modem Disc Reason", radius_vendor_bay_modem_disc_reason_vals, NULL},
  {46,	RADIUS_INTEGER4,	"Annex Disconnect Reason", NULL, NULL},
  {47,	RADIUS_INTEGER4,	"Annex Addr Resolution Protocol", radius_vendor_bay_addr_resolution_protocol_vals, NULL},
  {48,	RADIUS_STRING,		"Annex Addr Resolution Servers", NULL, NULL},
  {49,	RADIUS_STRING,		"Annex Domain Name", NULL, NULL},
  {50,	RADIUS_INTEGER4,	"Annex Transmit Speed", NULL, NULL},
  {51,	RADIUS_INTEGER4,	"Annex Receive Speed", NULL, NULL},
  {52,	RADIUS_STRING,		"Annex Input Filter", NULL, NULL},
  {53,	RADIUS_STRING,		"Annex Output Filter", NULL, NULL},
  {54,	RADIUS_IP_ADDRESS,	"Annex Primary DNS Server", NULL, NULL},
  {55,	RADIUS_IP_ADDRESS,	"Annex Secondary DNS Server", NULL, NULL},
  {56,	RADIUS_IP_ADDRESS,	"Annex Primary NBNS Server", NULL, NULL},
  {57,	RADIUS_IP_ADDRESS,	"Annex Secondary NBNS Server", NULL, NULL},
  {58,	RADIUS_INTEGER4,	"Annex Syslog Tap", NULL, NULL},
  {59,	RADIUS_INTEGER4,	"Annex Keypress Timeout", NULL, NULL},
  {60,	RADIUS_INTEGER4,	"Annex Unauthenticated Time", NULL, NULL},
  {61,	RADIUS_INTEGER4,	"Annex Re CHAP Timeout", NULL, NULL},
  {62,	RADIUS_INTEGER4,	"Annex MRRU", NULL, NULL},
  {63,	RADIUS_STRING,		"Annex EDO", NULL, NULL},
  {64,	RADIUS_INTEGER4,	"Annex PPP Trace Level", NULL, NULL},
  {65,	RADIUS_INTEGER4,	"Annex Pre Input Octets", NULL, NULL},
  {66,	RADIUS_INTEGER4,	"Annex Pre Output Octets", NULL, NULL},
  {67,	RADIUS_INTEGER4,	"Annex Pre Input Packets", NULL, NULL},
  {68,	RADIUS_INTEGER4,	"Annex Pre Output Packets", NULL, NULL},
  {69,	RADIUS_INTEGER4,	"Annex Connect Progress", NULL, NULL},
  {73,	RADIUS_INTEGER4,	"Annex Multicast Rate Limit", NULL, NULL},
  {74,	RADIUS_INTEGER4,	"Annex Maximum Call Duration", NULL, NULL},
  {75,	RADIUS_INTEGER4,	"Annex Multilink Id", NULL, NULL},
  {76,	RADIUS_INTEGER4,	"Annex Num In Multilink", NULL, NULL},
  {81,	RADIUS_INTEGER4,	"Annex Logical Channel Number", NULL, NULL},
  {82,	RADIUS_INTEGER4,	"Annex Wan Number", NULL, NULL},
  {83,	RADIUS_INTEGER4,	"Annex Port", NULL, NULL},
  {85,	RADIUS_INTEGER4,	"Annex Pool Id", NULL, NULL},
  {86,	RADIUS_STRING,		"Annex Compression Protocol", NULL, NULL},
  {87,	RADIUS_INTEGER4,	"Annex Transmitted Packets", NULL, NULL},
  {88,	RADIUS_INTEGER4,	"Annex Retransmitted Packets", NULL, NULL},
  {89,	RADIUS_INTEGER4,	"Annex Signal to Noise Ratio", NULL, NULL},
  {90,	RADIUS_INTEGER4,	"Annex Retrain Requests Sent", NULL, NULL},
  {91,	RADIUS_INTEGER4,	"Annex Retrain Requests Rcvd", NULL, NULL},
  {92,	RADIUS_INTEGER4,	"Annex Rate Reneg Req Sent", NULL, NULL},
  {93,	RADIUS_INTEGER4,	"Annex Rate Reneg Req Rcvd", NULL, NULL},
  {94,	RADIUS_INTEGER4,	"Annex Begin Receive Line Level", NULL, NULL},
  {95,	RADIUS_INTEGER4,	"Annex End Receive Line Level", NULL, NULL},
  {96,	RADIUS_STRING,		"Annex Begin Modulation", NULL, NULL},
  {97,	RADIUS_STRING,		"Annex Error Correction Prot", NULL, NULL},
  {98,	RADIUS_STRING,		"Annex End Modulation", NULL, NULL},
  {100,	RADIUS_INTEGER4,	"Annex User Level", radius_vendor_bay_user_level_vals, NULL},
  {101,	RADIUS_INTEGER4,	"Annex Audit Level", radius_vendor_bay_audit_level_vals, NULL},
  {0, 0, NULL, NULL, NULL},
};

/*
reference:
	'dictionary.foundry' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.foundry
*/
static const radius_attr_info radius_vendor_foundry_attrib[] =
{
  {1,	RADIUS_INTEGER4,	"Foundry Privilege Level", NULL, NULL},
  {2,	RADIUS_STRING,		"Foundry Command String", NULL, NULL},
  {3,	RADIUS_INTEGER4,	"Foundry Command Exception Flag", NULL, NULL},
  {0, 0, NULL, NULL, NULL},
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
  {1,	RADIUS_INTEGER4,	"Versanet Termination Cause", radius_vendor_versanet_termination_cause_vals, NULL},
  {0, 0, NULL, NULL, NULL},
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
  {1,	RADIUS_IP_ADDRESS,	"Client DNS Pri", NULL, NULL},
  {2,	RADIUS_IP_ADDRESS,	"Client DNS Sec", NULL, NULL},
  {3,	RADIUS_INTEGER4,	"DHCP Max Leases", NULL, NULL},
  {4,	RADIUS_STRING,		"Context Name", NULL, NULL},
  {5,	RADIUS_STRING,		"Bridge Group", NULL, NULL},
  {6,	RADIUS_STRING,		"BG Aging Time", NULL, NULL},
  {7,	RADIUS_STRING,		"BG Path Cost", NULL, NULL},
  {8,	RADIUS_STRING,		"BG Span Dis", NULL, NULL},
  {9,	RADIUS_STRING,		"BG Trans BPDU", NULL, NULL},
  {10,	RADIUS_INTEGER4,	"Rate Limit Rate", NULL, NULL},
  {11,	RADIUS_INTEGER4,	"Rate Limit Burst", NULL, NULL},
  {12,	RADIUS_INTEGER4,	"Police Rate", NULL, NULL},
  {13,	RADIUS_INTEGER4,	"Police Burst", NULL, NULL},
  {14,	RADIUS_INTEGER4,	"Source Validation", NULL, NULL},
  {15,	RADIUS_INTEGER4,	"Tunnel Domain", NULL, NULL},
  {16,	RADIUS_STRING,		"Tunnel Local Name", NULL, NULL},
  {17,	RADIUS_STRING,		"Tunnel Remote Name", NULL, NULL},
  {18,	RADIUS_INTEGER4,	"Tunnel Function", radius_vendor_redback_tunnel_function_vals, NULL},
  {21,	RADIUS_INTEGER4,	"Tunnel Max Sessions", NULL, NULL},
  {22,	RADIUS_INTEGER4,	"Tunnel Max Tunnels", NULL, NULL},
  {23,	RADIUS_INTEGER4,	"Tunnel Session Auth", NULL, NULL},
  {24,	RADIUS_INTEGER4,	"Tunnel Window", NULL, NULL},
  {25,	RADIUS_INTEGER4,	"Tunnel Retransmit", NULL, NULL},
  {26,	RADIUS_INTEGER4,	"Tunnel Cmd Timeout", NULL, NULL},
  {27,	RADIUS_STRING,		"PPPOE URL", NULL, NULL},
  {28,	RADIUS_STRING,		"PPPOE MOTM", NULL, NULL},
  {29,	RADIUS_INTEGER4,	"Tunnel Group", NULL, NULL},
  {30,	RADIUS_STRING,		"Tunnel Context", NULL, NULL},
  {31,	RADIUS_INTEGER4,	"Tunnel Algorithm", NULL, NULL},
  {32,	RADIUS_INTEGER4,	"Tunnel Deadtime", NULL, NULL},
  {33,	RADIUS_INTEGER4,	"Mcast Send", radius_vendor_redback_mcast_send_vals, NULL},
  {34,	RADIUS_INTEGER4,	"Mcast Receive", radius_vendor_redback_mcast_receive_vals, NULL},
  {35,	RADIUS_INTEGER4,	"Mcast MaxGroups", NULL, NULL},
  {36,	RADIUS_STRING,		"Ip Address Pool Name", NULL, NULL},
  {37,	RADIUS_INTEGER4,	"Tunnel DNIS", radius_vendor_redback_tunnel_dnis_vals, NULL},
  {38,	RADIUS_INTEGER4,	"Medium Type", NULL, NULL},
  {39,	RADIUS_INTEGER4,	"PVC Encapsulation Type", radius_vendor_redback_pvc_encapsulation_type_vals, NULL},
  {40,	RADIUS_STRING,		"PVC Profile Name", NULL, NULL},
  {41,	RADIUS_INTEGER4,	"PVC Circuit Padding", radius_vendor_redback_pvc_circuit_padding_vals, NULL},
  {42,	RADIUS_INTEGER4,	"Bind Type", radius_vendor_redback_bind_type_vals, NULL},
  {43,	RADIUS_INTEGER4,	"Bind Auth Protocol", radius_vendor_redback_bind_auth_protocol_vals, NULL},
  {44,	RADIUS_INTEGER4,	"Bind Auth Max Sessions", NULL, NULL},
  {45,	RADIUS_STRING,		"Bind Bypass Bypass", NULL, NULL},
  {46,	RADIUS_STRING,		"Bind Auth Context", NULL, NULL},
  {47,	RADIUS_STRING,		"Bind Auth Service Grp", NULL, NULL},
  {48,	RADIUS_STRING,		"Bind Bypass Context", NULL, NULL},
  {49,	RADIUS_STRING,		"Bind Int Context", NULL, NULL},
  {50,	RADIUS_STRING,		"Bind Tun Context", NULL, NULL},
  {51,	RADIUS_STRING,		"Bind Ses Context", NULL, NULL},
  {52,	RADIUS_INTEGER4,	"Bind Dot1q Slot", NULL, NULL},
  {53,	RADIUS_INTEGER4,	"Bind Dot1q Port", NULL, NULL},
  {54,	RADIUS_INTEGER4,	"Bind Dot1q Vlan Tag Id", NULL, NULL},
  {55,	RADIUS_STRING,		"Bind Int Interface Name", NULL, NULL},
  {56,	RADIUS_STRING,		"Bind L2TP Tunnel Name", NULL, NULL},
  {57,	RADIUS_INTEGER4,	"Bind L2TP Flow Control", NULL, NULL},
  {58,	RADIUS_STRING,		"Bind Sub User At Context", NULL, NULL},
  {59,	RADIUS_STRING,		"Bind Sub Password", NULL, NULL},
  {60,	RADIUS_STRING,		"Ip Host Addr", NULL, NULL},
  {61,	RADIUS_INTEGER4,	"IP TOS Field", NULL, NULL},
  {62,	RADIUS_INTEGER4,	"NAS Real Port", NULL, NULL},
  {63,	RADIUS_STRING,		"Tunnel Session Auth Ctx", NULL, NULL},
  {64,	RADIUS_STRING,		"Tunnel Session Auth Service Grp", NULL, NULL},
  {65,	RADIUS_INTEGER4,	"Tunnel Rate Limit Rate", NULL, NULL},
  {66,	RADIUS_INTEGER4,	"Tunnel Rate Limit Burst", NULL, NULL},
  {67,	RADIUS_INTEGER4,	"Tunnel Police Rate", NULL, NULL},
  {68,	RADIUS_INTEGER4,	"Tunnel Police Burst", NULL, NULL},
  {69,	RADIUS_STRING,		"Tunnel L2F Second Password", NULL, NULL},
  {128,	RADIUS_INTEGER4,	"Acct Input Octets 64", NULL, NULL},
  {129,	RADIUS_INTEGER4,	"Acct Output Octets 64", NULL, NULL},
  {130,	RADIUS_INTEGER4,	"Acct Input Packets 64", NULL, NULL},
  {131,	RADIUS_INTEGER4,	"Acct Output Packets 64", NULL, NULL},
  {132,	RADIUS_IP_ADDRESS,	"Assigned IP Address", NULL, NULL},
  {133,	RADIUS_INTEGER4,	"Acct Mcast In Octets", NULL, NULL},
  {134,	RADIUS_INTEGER4,	"Acct Mcast Out Octets", NULL, NULL},
  {135,	RADIUS_INTEGER4,	"Acct Mcast In Packets", NULL, NULL},
  {136,	RADIUS_INTEGER4,	"Acct Mcast Out Packets", NULL, NULL},
  {137,	RADIUS_INTEGER4,	"LAC Port", NULL, NULL},
  {138,	RADIUS_INTEGER4,	"LAC Real Port", NULL, NULL},
  {139,	RADIUS_INTEGER4,	"LAC Port Type", radius_vendor_redback_lac_port_type_vals, NULL},
  {140,	RADIUS_INTEGER4,	"LAC Real Port Type", radius_vendor_redback_lac_real_port_type_vals, NULL},
  {141, RADIUS_STRING,		"Acct Dyn Ac Ent", NULL, NULL},
  {142, RADIUS_INTEGER4,	"Session Error Code", NULL, NULL},
  {143, RADIUS_STRING,		"Session Error Msg", NULL, NULL},
  {0, 0, NULL, NULL, NULL},
};

/*
reference:
    http://www.juniper.net/techpubs/software/junos/junos62/swconfig62-system-basics/frameset.htm
*/
static const radius_attr_info radius_vendor_juniper_attrib[] =
{
  {1,	RADIUS_STRING,		"Juniper Local User Name", NULL, NULL},
  {2,	RADIUS_STRING,		"Juniper Allow Commands", NULL, NULL},
  {3,	RADIUS_STRING,		"Juniper Deny Commands", NULL, NULL},
  {4,	RADIUS_STRING,		"Juniper Allow Configuration", NULL, NULL},
  {5,	RADIUS_STRING,		"Juniper Deny Configuration", NULL, NULL},
  {0, 0, NULL, NULL, NULL}
};

/*
reference:
	'dictionary.aptis' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.aptis
*/
static const radius_attr_info radius_vendor_aptis_attrib[] =
{
  {1,	RADIUS_STRING,		"CVX Identification", NULL, NULL},
  {2,	RADIUS_INTEGER4,	"CVX VPOP ID", NULL, NULL},
  {3,	RADIUS_INTEGER4,	"CVX SS7 Session ID Type", NULL, NULL},
  {4,	RADIUS_INTEGER4,	"CVX Radius Redirect", NULL, NULL},
  {5,	RADIUS_INTEGER4,	"CVX IPSVC AZNLVL", NULL, NULL},
  {6,	RADIUS_INTEGER4,	"CVX IPSVC Mask", NULL, NULL},
  {7,	RADIUS_INTEGER4,	"CVX Multilink Match Info", NULL, NULL},
  {8,	RADIUS_INTEGER4,	"CVX Multilink Group Number", NULL, NULL},
  {9,	RADIUS_INTEGER4,	"CVX PPP Log Mask", NULL, NULL},
  {10,	RADIUS_STRING,		"CVX Modem Begin Modulation", NULL, NULL},
  {11,	RADIUS_STRING,		"CVX Modem End Modulation", NULL, NULL},
  {12,	RADIUS_STRING,		"CVX Modem Error Correction", NULL, NULL},
  {13,	RADIUS_STRING,		"CVX Modem Data Compression", NULL, NULL},
  {14,	RADIUS_INTEGER4,	"CVX Modem Tx Packets", NULL, NULL},
  {15,	RADIUS_INTEGER4,	"CVX Modem ReTx Packets", NULL, NULL},
  {16,	RADIUS_INTEGER4,	"CVX Modem SNR", NULL, NULL},
  {17,	RADIUS_INTEGER4,	"CVX Modem Local Retrains", NULL, NULL},
  {18,	RADIUS_INTEGER4,	"CVX Modem Remote Retrains", NULL, NULL},
  {19,	RADIUS_INTEGER4,	"CVX Modem Local Rate Negs", NULL, NULL},
  {20,	RADIUS_INTEGER4,	"CVX Modem Remote Rate Negs", NULL, NULL},
  {21,	RADIUS_INTEGER4,	"CVX Modem Begin Recv Line Lvl", NULL, NULL},
  {22,	RADIUS_INTEGER4,	"CVX Modem End Recv Line Lvl", NULL, NULL},
  {0, 0, NULL, NULL, NULL},
};

/*
reference:
	Dictonary of Cisco ACS 3.1
	http://www.cisco.com/en/US/products/sw/secursw/ps2086/products_user_guide_chapter09186a0080102172.html#984410
*/


static const value_string radius_vendor_cisco_vpn3000_sep_card_assignment_vals[] =
{
  {1,	"SEP 1"},
  {2,	"SEP 2"},
  {3,	"SEP 1 + SEP 2"},
  {4,	"SEP 3"},
  {5,   	"SEP 1 + SEP 3"},
  {6,   	"SEP 2 + SEP 3"},
  {7,   	"SEP 1 + SEP 2 + SEP 3"},
  {8,   	"SEP 4"},
  {9,	"SEP 1 + SEP 4"},
  {10,  	"SEP 2 + SEP 4"},
  {11,  	"SEP 1 + SEP 2 + SEP 4"},
  {12,  	"SEP 3 + SEP 4"},
  {13,  	"SEP 1 + SEP 3 + SEP 4"},
  {14,  	"SEP 2 + SEP 3 + SEP 4"},
  {15,	"Any SEP"},
  {0, NULL}
};

static const value_string radius_vendor_cisco_vpn3000_tunneling_protocols_vals[] =
{
  {1,	"PPTP"},
  {2,	"L2TP"},
  {3,	"PPTP and L2TP"},
  {4,	"IPSec"},
  {5,	"PPTP and IPSec"},
  {6,	"L2TP and IPSec"},
  {7,	"PPTP - L2TP - IPSec"},
  {8,	"L2TP/IPSec"},
  {9,	"PPTP and L2TP/IPSec"},
  {10,	"L2TP and L2TP/IPSec"},
  {11,	"PPTP - L2TP - L2TP/IPSec"},
  {0, NULL}
};

static const value_string radius_vendor_cisco_vpn3000_ipsec_authentication_vals[] =
{
  {0,	"None"},
  {1,	"RADIUS"},
  {3,	"NT Domain"},
  {4,	"SDI"},
  {5,	"Internal"},
  {6,	"Radius with Expiry"},
  {7,	"KERBEROS / Active Directory"},
  {0, NULL}
};

static const value_string radius_vendor_cisco_vpn3000_allow_pw_store_vals[] =
{
  {0,	"False"},
  {1,	"True"},
  {0, NULL}
};

static const value_string radius_vendor_cisco_vpn3000_use_client_address_vals[] =
{
  {0,	"False"},
  {1,	"True"},
  {0, NULL}
};

static const value_string radius_vendor_cisco_vpn3000_pptp_encryption_vals[] =
{
  {1,   "Encryption required"},
  {2,   "40 Bits"},
  {3,   "40 Bits - Encryption required"},
  {4,   "128 Bits"},
  {5,   "128 Bits - Encryption required"},
  {6,   "40 or 128 Bits"},
  {7,   "40 or 128 Bits - Encryption required"},
  {8,   "Stateless Required"},
  {9,   "Encryption / Stateless required"},
  {10,  "40 Bits - Stateless required"},
  {11,  "40 Bits Encryption / Stateless required"},
  {12,  "128 Bits - Stateless required"},
  {13,  "128 Bits - Encryption / Stateless required"},
  {14,  "40/128 Bits - Stateless required"},
  {15,  "40/128 Bits - Encryption / Stateless required"},
  {0, NULL}
};


static const value_string radius_vendor_cisco_vpn3000_l2tp_encryption_vals[] =
{
  {1,	"Encryption required"},
  {2,	"40 Bits"},
  {3,	"40 Bits - Encryption required"},
  {4,	"128 Bits"},
  {5,	"128 Bits - Encryption required"},
  {6,	"40 or 128 Bits"},
  {7,	"40 or 128 Bits - Encryption required"},
  {8,	"Stateless Required"},
  {9,	"Encryption / Stateless required"},
  {10,	"40 Bits - Stateless required"},
  {11,	"40 Bits Encryption / Stateless required"},
  {12,	"128 Bits - Stateless required"},
  {13,	"128 Bits - Encryption / Stateless required"},
  {14,	"40/128 Bits - Stateless required"},
  {15,	"40/128 Bits - Encryption / Stateless required"},
 {0, NULL}
};

static const value_string radius_vendor_cisco_vpn3000_tunnel_type_vals[] =
{
  {1,	"LAN-to-LAN"},
  {2,	"Remote Access"},
 {0, NULL}
};

static const value_string radius_vendor_cisco_vpn3000_mode_config_vals[] =
{
  {0,	"OFF"},
  {1,	"ON"},
 {0, NULL}
};

static const value_string radius_vendor_cisco_vpn3000_user_group_lock_vals[] =
{
  {0,	"OFF"},
  {1,	"ON"},
 {0, NULL}
};

static const value_string radius_vendor_cisco_vpn3000_ipsec_over_udp_vals[] =
{
  {0,	"OFF"},
  {1,	"ON"},
 {0, NULL}
};

static const value_string radius_vendor_cisco_vpn3000_pptp_mppc_compression_vals[] =
{
  {1,	"ON"},
  {2,	"OFF"},
 {0, NULL}
};

static const value_string radius_vendor_cisco_vpn3000_l2tp_mppc_compression_vals[] =
{
  {0,	"ON"},
  {1,	"OFF"},
 {0, NULL}
};

static const value_string radius_vendor_cisco_vpn3000_ipsec_ip_compression_vals[] =
{
  {0,	"None"},
  {1,	"LZS"},
 {0, NULL}
};

static const value_string radius_vendor_cisco_vpn3000_ipsec_ike_peer_idcheck_vals[] =
{
  {1,	"Required"},
  {2,	"If supported by certifiate"},
  {3,	"Do not check"},
  {0, NULL}
};

static const value_string radius_vendor_cisco_vpn3000_ike_keep_alives_vals[] =
{
  {0,	"OFF"},
  {1,	"ON"},
 {0, NULL}
};


static const value_string radius_vendor_cisco_vpn3000_auth_on_rekey_vals[] =
{
  {0,	"OFF"},
  {1,	"ON"},
 {0, NULL}
};

static const value_string radius_vendor_cisco_vpn3000_required_client_fw_vendor_code_vals[] =
{
  {1,	"Cisco Systems (with CIC) "},
  {2,	"Zone Labs"},
  {3,	"Network ICE"},
  {4,	"Sygate"},
  {5,	"Cisco Systems (with CSA) "},
 {0, NULL}
};

static const value_string radius_vendor_cisco_vpn3000_hw_client_auth_vals[] =
{
  {0,	"OFF"},
  {1,	"ON"},
 {0, NULL}
};

static const value_string radius_vendor_cisco_vpn_req_user_auth_vals[] =
{
  {0,	"No"},
  {1,	"Yes"},
  {0, NULL}
};

static const value_string radius_vendor_cisco_vpn3000_ip_phone_bypass_vals[] =
{
  {0,	"No"},
  {1,	"Yes"},
 {0, NULL}
};

static const value_string radius_vendor_cisco_vpn3000_ipsec_split_tunneling_policy_vals[] =
{
  {0,	"Tunnel everything"},
  {1,	"Only tunnel networks in list"},
 {0, NULL}
};

static const value_string radius_vendor_cisco_vpn3000_ipsec_required_client_fw_capability_vals[] =
{
  {0,	"None"},
  {1,	"Policy defined by remote FW AYT"},
  {2,	"Policy pushed CPP"},
  {4,	"Policy from Server"},
 {0, NULL}
};

static const value_string radius_vendor_cisco_vpn3000_ipsec_client_fw_filter_optional_vals[] =
{
  {0,	"Required"},
  {1,	"Optional"},
 {0, NULL}
};

static const value_string radius_vendor_cisco_vpn3000_ipsec_backup_servers_vals[] =
{
  {1,	"User Client-configured list"},
  {2,	"Disable and clear client list"},
  {3,	"Use Backup server list"},
 {0, NULL}
};

static const value_string radius_vendor_cisco_vpn3000_ms_client_intercept_dhcp_configure_message_vals[] =
{
  {0,	"No"},
  {1,	"Yes"},
 {0, NULL}
};

static const value_string radius_vendor_cisco_vpn3000_allow_network_extension_mode_vals[] =
{
  {0,	"No"},
  {1,	"Yes"},
 {0, NULL}
};

static const value_string radius_vendor_cisco_vpn3000_webvpn_content_filter_parameters_vals[] =
{
  {1,	"Java & ActiveX"},
  {2,	"JavaScript"},
  {3,	"Java & ActiveX - JavaScript"},
  {4,	"Images"},
  {5,	"Java & ActiveX - Images"},
  {6,	"JavaScript - Images"},
  {7,	"Java & ActiveX - JavaScript - Images"},
  {8,	"Cookies"},
  {9,	"Cookies - Java & ActiveX"},
  {10,	"Cookies - Javascript"},
  {11,  	"Cookies - Java & ActiveX - JavaScript"},
  {12,	"Cookies - Images"},
  {13,	"Cookies - Images - Java &ActiveX"},
  {14,	"Cookies - Images - JavaScript"},
  {15,	"Cookies - Images - Java &ActiveX - JavaScript"},
 {0, NULL}
};

static const value_string radius_vendor_cisco_vpn3000_strip_realm_vals[] =
{
  {0,	"No"},
  {1,	"Yes"},
 {0, NULL}
};

static const radius_attr_info radius_vendor_cisco_vpn3000_attrib[] =
{
  {1,	RADIUS_STRING,		"CVPN3000-Access-Hours", NULL, NULL},
  {2,	RADIUS_INTEGER4,		"CVPN3000-Simultaneous-Logins", NULL, NULL},
  {5,	RADIUS_IP_ADDRESS,	"CVPN3000-Primary-DNS", NULL, NULL},
  {6,	RADIUS_IP_ADDRESS,	"CVPN3000-Secondary-DNS", NULL, NULL},
  {7,	RADIUS_IP_ADDRESS,	"CVPN3000-Primary-WINS", NULL, NULL},
  {8,	RADIUS_IP_ADDRESS,	"CVPN3000-Secondary-WINS", NULL, NULL},
  {9,   	RADIUS_INTEGER4,		"CVPN3000-SEP-Card-Assignment", radius_vendor_cisco_vpn3000_sep_card_assignment_vals, NULL},
  {11,  	RADIUS_INTEGER4,		"CVPN3000-Tunneling-Protocols", radius_vendor_cisco_vpn3000_tunneling_protocols_vals, NULL},
  {12,	RADIUS_STRING,		"CVPN3000-IPSec-Sec-Association", NULL, NULL},
  {13,	RADIUS_INTEGER4,		"CVPN3000-IPSec-Authentication", radius_vendor_cisco_vpn3000_ipsec_authentication_vals, NULL},
  {15,	RADIUS_STRING,		"CVPN3000-IPSec-Banner1", NULL, NULL},
  {16,	RADIUS_INTEGER4,		"CVPN3000-IPSec-Allow-Passwd-Store", radius_vendor_cisco_vpn3000_allow_pw_store_vals, NULL},
  {17,	RADIUS_INTEGER4,		"CVPN3000-Use-Client-Address", radius_vendor_cisco_vpn3000_use_client_address_vals, NULL},
  {20,	RADIUS_INTEGER4,		"CVPN3000-PPTP-Encryption", radius_vendor_cisco_vpn3000_pptp_encryption_vals, NULL},
  {21,	RADIUS_INTEGER4,		"CVPN3000-L2TP-Encryption", radius_vendor_cisco_vpn3000_l2tp_encryption_vals, NULL},
  {27,	RADIUS_STRING,		"CVPN3000-IPSec-Split-Tunnel-List", NULL, NULL},
  {28,	RADIUS_STRING,		"CVPN3000-IPSec-Default-Domain", NULL, NULL},
  {29,	RADIUS_STRING,		"CVPN3000-IPSec-Split-DNS-Names", NULL, NULL},
  {30,	RADIUS_INTEGER4,		"CVPN3000-IPSec-Tunnel-Type", radius_vendor_cisco_vpn3000_tunnel_type_vals, NULL},
  {31,	RADIUS_INTEGER4,		"CVPN3000-IPSec-Mode-Config", radius_vendor_cisco_vpn3000_mode_config_vals, NULL},
  {33,	RADIUS_INTEGER4,		"CVPN3000-IPSec-User-Group-Lock", radius_vendor_cisco_vpn3000_user_group_lock_vals, NULL},
  {34,  	RADIUS_INTEGER4,		"CVPN3000-IPSec-Over-UDP", radius_vendor_cisco_vpn3000_ipsec_over_udp_vals, NULL},
  {35,	RADIUS_INTEGER4,		"CVPN3000-IPSec-Over-UDP-Port", NULL, NULL},
  {36,	RADIUS_STRING,		"CVPN3000-IPSec-Banner2", NULL, NULL},
  {37,	RADIUS_INTEGER4,		"CVPN3000-PPTP-MPPC-Compression", radius_vendor_cisco_vpn3000_pptp_mppc_compression_vals, NULL},
  {38,	RADIUS_INTEGER4,		"CVPN3000-L2TP-MPPC-Compression", radius_vendor_cisco_vpn3000_l2tp_mppc_compression_vals, NULL},
  {39,	RADIUS_INTEGER4,		"CVPN3000-IPSec-IP-Compression", radius_vendor_cisco_vpn3000_ipsec_ip_compression_vals, NULL},
  {40,	RADIUS_INTEGER4,		"CVPN3000-IPSec-IKE-Peer-IDCheck", radius_vendor_cisco_vpn3000_ipsec_ike_peer_idcheck_vals, NULL},
  {41,	RADIUS_INTEGER4,		"CVPN3000-IKE-Keep-Alives", radius_vendor_cisco_vpn3000_ike_keep_alives_vals, NULL},
  {42,	RADIUS_INTEGER4,		"CVPN3000-IPSec-Auth-On-Rekey", radius_vendor_cisco_vpn3000_auth_on_rekey_vals, NULL},
  {45,	RADIUS_INTEGER4,		"CVPN3000-Required-Client-Firewall-Vendor-Code", radius_vendor_cisco_vpn3000_required_client_fw_vendor_code_vals, NULL},
  {46,	RADIUS_INTEGER4,		"CVPN3000-Required-Client-Firewall-Product-Code", NULL, NULL},
  {47,	RADIUS_STRING,		"CVPN3000-Required-Client-Firewall-Description", NULL, NULL},
  {48,	RADIUS_INTEGER4,		"CVPN3000-Require-HW-Client-Auth", radius_vendor_cisco_vpn3000_hw_client_auth_vals, NULL},
  {49,	RADIUS_INTEGER4,		"CVPN3000-Required-Individual-User-Auth", radius_vendor_cisco_vpn_req_user_auth_vals, NULL},
  {50,	RADIUS_INTEGER4,		"CVPN3000-Authenticated-User-Idle-Timeout", NULL, NULL},
  {51,	RADIUS_INTEGER4,		"CVPN3000-Cisco-IP-Phone-Bypass", radius_vendor_cisco_vpn3000_ip_phone_bypass_vals, NULL},
  {52,	RADIUS_STRING,		"CVPN3000-User-Auth-Server-Name", NULL, NULL},
  {53,	RADIUS_INTEGER4,		"CVPN3000-User-Auth-Server-Port", NULL, NULL},
  {54,  	RADIUS_STRING,		"CVPN3000-User-Auth-Server-Secret", NULL, NULL},
  {55,	RADIUS_INTEGER4,		"CVPN3000-IPSec-Split-Tunneling-Policy", radius_vendor_cisco_vpn3000_ipsec_split_tunneling_policy_vals, NULL},
  {56,	RADIUS_INTEGER4,		"CVPN3000-IPSec-Required-Client-Firewall-Capability", radius_vendor_cisco_vpn3000_ipsec_required_client_fw_capability_vals, NULL},
  {57,	RADIUS_STRING,		"CVPN3000-IPSec-Client-Firewall-Filter-Name", NULL, NULL},
  {58,	RADIUS_INTEGER4,		"CVPN3000-IPSec-Client-Firewall-Filter-Optional", radius_vendor_cisco_vpn3000_ipsec_client_fw_filter_optional_vals, NULL},
  {59,	RADIUS_INTEGER4,		"CVPN3000-IPSec-Backup-Servers", radius_vendor_cisco_vpn3000_ipsec_backup_servers_vals, NULL},
  {60,	RADIUS_STRING,		"CVPN3000-IPSec-Backup-Server-List", NULL, NULL},
  {62,	RADIUS_INTEGER4,		"CVPN3000-MS-Client-Intercept-DHCP-Configure-Message", radius_vendor_cisco_vpn3000_ms_client_intercept_dhcp_configure_message_vals, NULL},
  {63,	RADIUS_IP_ADDRESS,	"CVPN3000-MS-Client-Subnet-Mask", NULL, NULL},
  {64,	RADIUS_INTEGER4,		"CVPN3000-Allow-Network-Extension-Mode", radius_vendor_cisco_vpn3000_allow_network_extension_mode_vals, NULL},
  {68,	RADIUS_INTEGER4,		"CVPN3000-Confidence-Interval", NULL, NULL},
  {69,	RADIUS_INTEGER4,		"CVPN3000-WebVPN-Content-Filter-Parameters", radius_vendor_cisco_vpn3000_webvpn_content_filter_parameters_vals, NULL},
  {70,	RADIUS_INTEGER4,		"CVPN3000-WebVPN-Enable-functions", NULL, NULL},
  {74,	RADIUS_STRING,		"CVPN3000-WebVPN-Exchange-Server-Address", NULL, NULL},
  {75,	RADIUS_INTEGER4,		"CVPN3000-Cisco-LEAP-Bypass", NULL, NULL},
  {77,	RADIUS_STRING,		"CVPN3000-Client-Type-Version-Limiting", NULL, NULL},
  {78,	RADIUS_STRING,		"CVPN3000-WebVPN-ExchangeServer-NETBIOS-Name", NULL, NULL},
  {79,	RADIUS_STRING,		"CVPN3000-Port-Forwarding-Name", NULL, NULL},
  {135,	RADIUS_INTEGER4,		"CVPN3000-Strip-Realm", radius_vendor_cisco_vpn3000_strip_realm_vals, NULL},
  {0,	0, NULL, NULL, NULL}
};

static const radius_attr_info radius_vendor_cosine_attrib[] =
{
  {1,	RADIUS_STRING,		"Connection Profile Name", NULL, NULL},
  {2,	RADIUS_STRING,		"Enterprise ID", NULL, NULL},
  {3,	RADIUS_STRING,		"Address Pool Name", NULL, NULL},
  {4,	RADIUS_INTEGER4,	"DS Byte", NULL, NULL},
  {5,	COSINE_VPI_VCI,		"VPI/VCI", NULL, NULL},
  {6,	RADIUS_INTEGER4,	"DLCI", NULL, NULL},
  {7,	RADIUS_IP_ADDRESS,	"LNS IP Address", NULL, NULL},
  {8,	RADIUS_STRING,		"CLI User Permission ID", NULL, NULL},
  {0, 0, NULL, NULL, NULL}
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
  {1,	RADIUS_INTEGER4,	"Shasta User Privilege", radius_vendor_shasta_user_privilege_vals, NULL},
  {2,	RADIUS_STRING,		"Shasta Service Profile", NULL, NULL},
  {3,	RADIUS_STRING,		"Shasta VPN Name", NULL, NULL},
  {0, 0, NULL, NULL, NULL},
};

/*
reference:
	'dictionary.nomadix' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.nomadix
*/
static const radius_attr_info radius_vendor_nomadix_attrib[] =
{
  {1,	RADIUS_INTEGER4,	"Nomadix Bw Up", NULL, NULL},
  {2,	RADIUS_INTEGER4,	"Nomadix Bw Down", NULL, NULL},
  {0, 0, NULL, NULL, NULL},
};

/*
reference:
	PKT-SP-EM-I09-040402 - PacketCable(tm) Event Message Specification
	http://www.packetcable.com/specifications/
*/

/* XXX - Do we need to strip off the spaces for RJ strings? */
#define PACKETCABLE_RJ_STRING RADIUS_STRING
#define PACKETCABLE_EM_HEADER_CODE 1

static value_string radius_vendor_packetcable_event_message_vals[] =
{
  {0,  "Reserved"},
  {1,  "Signaling_Start"},
  {2,  "Signaling_Stop"},
  {3,  "Database_Query"},
  {4,  "Intelligent_Peripheral_Usage_Start"},
  {5,  "Intelligent_Peripheral_Usage_Stop"},
  {6,  "Service_Instance"},
  {7,  "QoS_Reserve"},
  {8,  "QoS_Release"},
  {9,  "Service_Activation"},
  {10, "Service_Deactivation"},
  {11,  "Media_Report"},
  {12,  "Signal_Instance"},
  {13, "Interconnect_(Signaling)_Start"},
  {14, "Interconnect_(Signaling)_Stop"},
  {15, "Call_Answer"},
  {16, "Call_Disconnect"},
  {17, "Time_Change"},
  {19, "QoS_Commit"},
  {20, "Media_Alive"},
  {31,  "Policy_Request"},
  {32,  "Policy_Delete"},
  {33,  "Policy_Update"},
  {0, NULL}
};

static value_string radius_vendor_packetcable_query_type_vals[] =
{
  {0,  "Reserved"},
  {1,  "Toll Free Number Looukp"},
  {2,  "LNPNumberLookup"},
  {3,  "Calling Name Delivery Lookup"},
  {0, NULL}
};

static value_string radius_vendor_packetcable_channel_state_vals[] =
{
  {0,  "Not Used/Reserved"},
  {1,  "Open"},
  {2,  "Change"},
  {2,  "Close"},
  {0, NULL}
};

static value_string radius_vendor_packetcable_direction_indicator_vals[] =
{
  {0,  "Undefined"},
  {1,  "Originating"},
  {2,  "Terminating"},
  {0, NULL}
};

static value_string radius_vendor_packetcable_flow_direction_vals[] =
{
  {0,  "Reserved"},
  {1,  "Upstream"},
  {2,  "Downstream"},
  {0, NULL}
};

static value_string radius_vendor_packetcable_signal_type_vals[] =
{
  {0,  "Reserved"},
  {1,  "Network_Signal"},
  {2,  "Subject_Signal"},
  {0, NULL}
};

static value_string radius_vendor_packetcable_alerting_signal_vals[] =
{
  {0,  "Reserved"},
  {1,  "Ringing (rg)"},
  {2,  "Distinctive ringing 2 (r2)"},
  {3,  "Distinctive ringing 3 (r3)"},
  {4,  "Distinctive ringing 4 (r4)"},
  {5,  "Ringsplash (rs)"},
  {6,  "Call waiting tone 1 (wt1)"},
  {7,  "Call waiting tone 2 (wt2)"},
  {8,  "Call waiting tone 3 (wt3)"},
  {9,  "Call waiting tone 4 (wt4)"},
  {10,  "Reserved"},
  {11,  "Distinctive ringing 0 (r0)"},
  {12,  "Distinctive ringing 1 (r1)"},
  {13,  "Distinctive ringing 5 (r5)"},
  {14,  "Distinctive ringing 6 (r6)"},
  {15,  "Distinctive ringing 7 (r7)"},
  {0, NULL}
};

static value_string radius_vendor_packetcable_subject_audible_signal_vals[] =
{
  {0,  "Reserved"},
  {1,  "Dial tone (dl)"},
  {2,  "Stutter dial tone (sl)"},
  {3,  "Ring back tone (rt)"},
  {4,  "Reorder tone (ro)"},
  {5,  "Busy tone (bz)"},
  {6,  "Confirmation tone (cf)"},
  {7,  "Reserved"},
  {8,  "Message waiting indicator (mwi)"},
  {9,  "Off-hook warning tone (ot)"},
  {10, "Reserved"},
  {11, "Reserved"},
  {12, "Reserved"},
  {13, "Reserved"},
  {14, "Reserved"},
  {15, "Reserved"},
  {16, "Reserved"},
  {17, "Reserved"},
  {18, "Reserved"},
  {19, "Reserved"},
  {20, "Reserved"},
  {21, "Reserved"},
  {0, NULL}
};

static value_string radius_vendor_packetcable_element_requesting_qos_vals[] =
{
  {0, "Client"},
  {1, "Policy Server"},
  {2, "Embedded Client"},
  {0, NULL}
};

static value_string radius_vendor_packetcable_qos_release_reason_vals[] =
{
  {1,   "Gate Closed by PS"},
  {2,   "Inactivity resource recovery (T4) timer expiration"},
  {3,   "CM Failure"},
  {4,   "Pre-Empted"},
  {5,   "RSVP PathTear request"},
  {6,   "CM Request"},
  {7,   "Admitted (T2) timer expiration"},
  {127, "Other"},
  {0, NULL}
};

static value_string radius_vendor_packetcable_policy_denied_reason_vals[] =
{
  {1,   "Policy Server admission control failure"},
  {2,   "Insufficient resources"},
  {3,   "Unknown subscriber"},
  {4,   "Unauthorized AMID"},
  {5,   "Undefined Service Class Name"},
  {6,   "Incompatible Envelope"},
  {127, "Other"},
  {0, NULL}
};

static value_string radius_vendor_packetcable_policy_deleted_reason_vals[] =
{
  {1,   "Application Manager request"},
  {2,   "CMTS decistion"},
  {127, "Other"},
  {0, NULL}
};

static value_string radius_vendor_packetcable_policy_update_reason_vals[] =
{
  {1,   "Traffic Profile"},
  {2,   "Classifier"},
  {3,   "Volume Limit"},
  {4,   "Time Limit"},
  {5,   "Opaque data"},
  {6,   "Multiple Updates"},
  {127, "Other"},
  {0, NULL}
};

static value_string radius_vendor_packetcable_policy_decision_status_vals[] =
{
  {1, "Policy Approved"},
  {2, "Policy Denied"},
  {0, NULL}
};


static value_string packetcable_em_header_element_type_vals[] =
{
  {0,  "Reserved"},
  {1,  "CMS"},
  {2,  "CMTS"},
  {3,  "Media Gateway Controller"},
  {0, NULL}
};

#define PACKETCABLE_EMHS_EI_MASK 0X0003
#define PACKETCABLE_EMHS_EO_MASK 0X0004
#define PACKETCABLE_EMHS_EMP_MASK 0X0008
#define PACKETCABLE_EMHS_RESERVED_MASK 0Xfff0

static value_string packetcable_em_header_status_error_indicator_vals[] =
{
  {0,  "No Error"},
  {1,  "Possible Error"},
  {2,  "Known Error"},
  {3,  "Reserved"},
  {0, NULL},
};

static value_string packetcable_em_header_status_event_origin_vals[] =
{
  {0,  "Trusted Element"},
  {1,  "Untrusted Element"},
  {0, NULL},
};

static value_string packetcable_em_header_status_event_message_proxied_vals[] =
{
  {0,  "Not proxied"},
  {1,  "Proxied"},
  {0, NULL},
};

static value_string packetcable_call_termination_cause_vals[] =
{
  {0,  "Reserved"},
  {1,  "BAF"},
  {2,  "Reserved"},
  {0, NULL},
};

static value_string packetcable_trunk_type_vals[] =
{
  {1,  "Not Used"},
  {2,  "Not Used"},
  {3,  "SS7 direct trunk group member"},
  {4,  "SS7 from IC to AT and SS7 from AT to EO"},
  {5,  "Not Used"},
  {6,  "SS7 from IC to AT and non-SS7 from AT to EO (terminating only)"},
  {9,  "Signaling type not specified"},
  {0, NULL},
};

#define PACKETCABLE_QOS_STATE_INDICATION_MASK 0X0003
static value_string packetcable_state_indication_vals[] =
{
  {0,  "Illegal Value"},
  {1,  "Resource Reserved but not Activated"},
  {2,  "Resource Activated"},
  {3,  "Resource Reserved & Activated"},
};

#define PACKETCABLE_SERVICE_FLOW_SCHEDULING_TYPE_MASK  (1 << 2)
#define PACKETCABLE_NOMINAL_GRANT_INTERVAL_MASK        (1 << 3)
#define PACKETCABLE_TOLERATED_GRANT_JITTER_MASK        (1 << 4)
#define PACKETCABLE_GRANTS_PER_INTERVAL_MASK   (1 << 5)
#define PACKETCABLE_UNSOLICITED_GRANT_SIZE_MASK        (1 << 6)
#define PACKETCABLE_TRAFFIC_PRIORITY_MASK      (1 << 7)
#define PACKETCABLE_MAXIMUM_SUSTAINED_RATE_MASK        (1 << 8)
#define PACKETCABLE_MAXIMUM_TRAFFIC_BURST_MASK (1 << 9)
#define PACKETCABLE_MINIMUM_RESERVED_TRAFFIC_RATE_MASK (1 << 10)
#define PACKETCABLE_MINIMUM_PACKET_SIZE_MASK   (1 << 11)
#define PACKETCABLE_MAXIMUM_CONCATENATED_BURST_MASK    (1 << 12)
#define PACKETCABLE_REQUEST_TRANSMISSION_POLICY_MASK   (1 << 13)
#define PACKETCABLE_NOMINAL_POLLING_INTERVAL_MASK      (1 << 14)
#define PACKETCABLE_TOLERATED_POLL_JITTER_MASK (1 << 15)
#define PACKETCABLE_IP_TYPE_OF_SERVICE_OVERRIDE_MASK   (1 << 16)
#define PACKETCABLE_MAXIMUM_DOWNSTREAM_LATENCY_MASK    (1 << 17)

static guint32 packetcable_qos_desc_mask[] =
{
  PACKETCABLE_SERVICE_FLOW_SCHEDULING_TYPE_MASK,
  PACKETCABLE_NOMINAL_GRANT_INTERVAL_MASK,
  PACKETCABLE_TOLERATED_GRANT_JITTER_MASK,
  PACKETCABLE_GRANTS_PER_INTERVAL_MASK,
  PACKETCABLE_UNSOLICITED_GRANT_SIZE_MASK,
  PACKETCABLE_TRAFFIC_PRIORITY_MASK,
  PACKETCABLE_MAXIMUM_SUSTAINED_RATE_MASK,
  PACKETCABLE_MAXIMUM_TRAFFIC_BURST_MASK,
  PACKETCABLE_MINIMUM_RESERVED_TRAFFIC_RATE_MASK,
  PACKETCABLE_MINIMUM_PACKET_SIZE_MASK,
  PACKETCABLE_MAXIMUM_CONCATENATED_BURST_MASK,
  PACKETCABLE_REQUEST_TRANSMISSION_POLICY_MASK,
  PACKETCABLE_NOMINAL_POLLING_INTERVAL_MASK,
  PACKETCABLE_TOLERATED_POLL_JITTER_MASK,
  PACKETCABLE_IP_TYPE_OF_SERVICE_OVERRIDE_MASK,
  PACKETCABLE_MAXIMUM_DOWNSTREAM_LATENCY_MASK,
};

#define PACKETCABLE_QOS_DESC_BITFIELDS 16


static const radius_attr_info radius_vendor_cablelabs_attrib[] =
{
  {0,  RADIUS_RESERVED,                        "Reserved", NULL, NULL},
  {1,  PACKETCABLE_EM_HEADER,                  "EM_Header Data structure", NULL, NULL},
  /* 2 Undefined */
  {3,  RADIUS_STRING,                          "MTA_Endpoint_Name", NULL, NULL},
  {4,  PACKETCABLE_RJ_STRING,                  "Calling_Party_Number", NULL, NULL},
  {5,  PACKETCABLE_RJ_STRING,                  "Called_Party_Number", NULL, NULL},
  {6,  PACKETCABLE_RJ_STRING,                  "Database_ID", NULL, NULL},
  {7,  RADIUS_INTEGER2,                        "Query_Type", radius_vendor_packetcable_query_type_vals, NULL},
  /* 8 Undefined */
  {9,  PACKETCABLE_RJ_STRING,                  "Returned_Number", NULL, NULL},
  /* 10 Undefined */
  {11, PACKETCABLE_CALL_TERMINATION_CAUSE,     "Call_Termination_Cause", NULL, NULL},
  /* 12 Undefined */
  {13, PACKETCABLE_RELATED_CALL_BILLING_CORRELATION_ID,        "Related_Call_Billing_Correlation_ID", NULL, NULL},
  {14, PACKETCABLE_RJ_STRING,                  "First_Call_Calling_Party_Number", NULL, NULL},
  {15, PACKETCABLE_RJ_STRING,                  "Second_Call_Calling_Party_Number", NULL, NULL},
  {16, PACKETCABLE_RJ_STRING,                  "Charge_Number", NULL, NULL},
  {17, PACKETCABLE_RJ_STRING,                  "Forwarded_Number", NULL, NULL},
  {18, PACKETCABLE_RJ_STRING,                  "Service_Name", NULL, NULL},
  /* 19 Undefined */
  {20, PACKETCABLE_RJ_STRING,                  "Intl_Code", NULL, NULL},
  {21, PACKETCABLE_RJ_STRING,                  "Dial_Around_Code", NULL, NULL},
  {22, PACKETCABLE_RJ_STRING,                  "Location_Routing_Number", NULL, NULL},
  {23, PACKETCABLE_RJ_STRING,                  "Carrier_Identification_Code", NULL, NULL},
  {24, PACKETCABLE_TRUNK_GROUP_ID,             "Trunk_Group_ID", NULL, NULL},
  {25, PACKETCABLE_RJ_STRING,                  "Routing_Number", NULL, NULL},
  {26, RADIUS_INTEGER4,                        "MTA_UDP_Portnum", NULL, NULL},
  /* 27 Undefined */
  /* 28 Undefined */
  {29, RADIUS_INTEGER2,                        "Channel_State", radius_vendor_packetcable_channel_state_vals, NULL},
  {30, RADIUS_INTEGER4,                        "SF_ID", NULL, NULL},
  {31, PACKETCABLE_RJ_STRING,                  "Error_Description", NULL, NULL},
  {32, PACKETCABLE_QOS_DESCRIPTOR,             "QoS_Descriptor", NULL, NULL},
  {37, RADIUS_INTEGER2,                        "Direction_indicator", radius_vendor_packetcable_direction_indicator_vals, NULL},
  {38, PACKETCABLE_TIME_ADJUSTMENT,            "Time_Adjustment", NULL, NULL},
  {39, RADIUS_STRING,                          "SDP_Upstream", NULL, NULL},
  {40, RADIUS_STRING,                          "SDP_Downstream", NULL, NULL},
  {41, RADIUS_STRING,                          "User_Input", NULL, NULL},
  {42, PACKETCABLE_RJ_STRING,                  "Translation_Input", NULL, NULL},
  {43, PACKETCABLE_REDIRECTED_FROM_INFO,       "Redirected_From_Info", NULL, NULL},
  {44, PACKETCABLE_ELECTRONIC_SURVEILLANCE_INDICATION, "Electronic_Surveillance_Indication", NULL, NULL},
  {45, PACKETCABLE_RJ_STRING,                  "Redirected_From_Party_Number", NULL, NULL},
  {46, PACKETCABLE_RJ_STRING,                  "Redirected_To_Party_Number", NULL, NULL},
  {47, PACKETCABLE_ELECTRONIC_SURVEILLANCE_DF_SECURITY,        "Electronic_Surveillance_DF_Security", NULL, NULL},
  {48, RADIUS_INTEGER4,                        "CCC_ID", NULL, NULL},
  {49, RADIUS_STRING,                          "Financial Entity ID", NULL, NULL},
  {50, RADIUS_INTEGER2,                        "Flow Direction", radius_vendor_packetcable_flow_direction_vals, NULL},
  {51, RADIUS_INTEGER2,                        "Signal_Type", radius_vendor_packetcable_signal_type_vals, NULL},
  {52, RADIUS_INTEGER4,                        "Alerting_Signal", radius_vendor_packetcable_alerting_signal_vals, NULL},
  {53, RADIUS_INTEGER4,                        "Subject_Audible_Signal", radius_vendor_packetcable_subject_audible_signal_vals, NULL},
  {54, PACKETCABLE_TERMINAL_DISPLAY_INFO,      "Terminal_Display_Info", NULL, NULL},
  {55, RADIUS_STRING,                          "Switch_Hook_Flash", NULL, NULL},
  {56, RADIUS_STRING,                          "Dialed_Digits", NULL, NULL},
  {57, RADIUS_STRING,                          "Misc_Signaling_Information", NULL, NULL},

/* PacketCable MM */
  {61, RADIUS_INTEGER8,                        "AM_Opaque_Data", NULL, NULL },
  {62, RADIUS_IP_ADDRESS,                      "Subscriber_ID", NULL, NULL },
  {63, RADIUS_INTEGER8,                        "Volume_Usage_Limit", NULL, NULL },
  {64, RADIUS_INTEGER8,                        "Gate_Usage_Info", NULL, NULL },
  {65, RADIUS_INTEGER2,                        "Element_Requesting_QoS", radius_vendor_packetcable_element_requesting_qos_vals, NULL },
  {66, RADIUS_INTEGER2,                        "QoS_Release_Reason", radius_vendor_packetcable_qos_release_reason_vals, NULL },
  {67, RADIUS_INTEGER2,                        "Policy_Denied_Reason", radius_vendor_packetcable_policy_denied_reason_vals, NULL },
  {68, RADIUS_INTEGER2,                        "Policy_Deleted_Reason", radius_vendor_packetcable_policy_deleted_reason_vals, NULL },
  {69, RADIUS_INTEGER2,                        "Policy_Update_Reason", radius_vendor_packetcable_policy_update_reason_vals, NULL },
  {70, RADIUS_INTEGER2,                        "Policy_Decision_Status", radius_vendor_packetcable_policy_decision_status_vals, NULL },
  {71, RADIUS_INTEGER4,                        "Application_Manager_ID", NULL, NULL },
  {72, RADIUS_INTEGER4,                        "Time_Usage_Limit", NULL, NULL },
  {73, RADIUS_INTEGER4,                        "Gate_Time_Info", NULL, NULL },

  {80, PACKETCABLE_RJ_STRING,                  "Account_Code", NULL, NULL},
  {81, PACKETCABLE_RJ_STRING,                  "Authorization_Code", NULL, NULL},
  {0, 0, NULL, NULL, NULL},
};



/*
reference:
	'unisphere5-3.dct' file from Juniper Networks
          http://www.juniper.net/techpubs/software/erx/junose53/unisphere5-3.dct
*/

static const value_string radius_vendor_unisphere_ingress_statistics_vals[] =
{
  {0,	"Disable"},
  {1,	"Enable"}
};

static const value_string radius_vendor_unisphere_egress_statistics_vals[] =
{
  {0,	"Disable"},
  {1,	"Enable"}
};

static const value_string radius_vendor_unisphere_atm_service_category_vals[] =
{
  {1,	"UBR"},
  {2,	"UBRPCR"},
  {3,	"nrtVBR"},
  {4,	"CBR"},
  {0,	"NULL"}
};

static const value_string radius_vendor_unisphere_cli_allow_all_vr_access_vals[] =
{
  {0,	"Disable"},
  {1,	"Enable"},
};

static const value_string radius_vendor_unisphere_sa_validate_vals[] =
{
  {0,	"Disable"},
  {1,	"Enable"},
};

static const value_string radius_vendor_unisphere_igmp_enable_vals[] =
{
  {0,	"Disable"},
  {1,	"Enable"},
};

static const value_string radius_vendor_unisphere_ppp_protocol_vals[] =
{
  {0,	"none"},
  {1,	"pap"},
  {2,	"chap"},
  {3,	"pap-chap"},
  {4,	"chap-pap"}
};

static const value_string radius_vendor_unisphere_tunnel_bearer_type_vals[] =
{
  {0,	"none"},
  {1,	"analog"},
  {2,	"digital"},
};


static const radius_attr_info radius_vendor_unisphere_attrib[] =
{
  {1,	RADIUS_STRING,		"ERX Virtual Router Name", NULL, NULL},
  {2,	RADIUS_STRING,		"ERX Address Pool Name", NULL, NULL},
  {3,	RADIUS_STRING,		"ERX Local Loopback Interface", NULL, NULL},
  {4,	RADIUS_IP_ADDRESS,	"ERX Primary Dns", NULL, NULL},
  {5,	RADIUS_IP_ADDRESS,	"ERX Primary Wins", NULL, NULL},
  {6,	RADIUS_IP_ADDRESS,	"ERX Secondary Dns", NULL, NULL},
  {7,	RADIUS_IP_ADDRESS,	"ERX Secondary Wins", NULL, NULL},
  {8,	RADIUS_STRING,		"ERX Tunnel Virtual Router", NULL, NULL},
  {9,	RADIUS_STRING,		"ERX Tunnel Password", NULL, NULL},
  {10,	RADIUS_STRING,		"ERX Ingress Policy Name", NULL, NULL},
  {11,	RADIUS_STRING,		"ERX Egress Policy Name", NULL, NULL},
  {12,	RADIUS_STRING,		"ERX Ingress Statistics", radius_vendor_unisphere_ingress_statistics_vals, NULL},
  {13,	RADIUS_STRING,		"ERX Egress Statistics", radius_vendor_unisphere_egress_statistics_vals, NULL},
  {14,	RADIUS_STRING,		"ERX Atm Service Category", radius_vendor_unisphere_atm_service_category_vals, NULL},
  {15,	RADIUS_STRING,		"ERX Atm PCR", NULL, NULL},
  {16,	RADIUS_STRING,		"ERX Atm SCR", NULL, NULL},
  {17,	RADIUS_STRING,		"ERX Atm MBS", NULL, NULL},
  {18,	RADIUS_STRING,		"ERX Cli Initial Access Level", NULL, NULL},
  {19,	RADIUS_INTEGER4,	"ERX Cli Allow All VR Access", radius_vendor_unisphere_cli_allow_all_vr_access_vals, NULL},
  {20,	RADIUS_STRING,		"ERX Alternate Cli Access Level", NULL, NULL},
  {21,	RADIUS_STRING,		"ERX Alternate Cli Vrouter Name", NULL, NULL},
  {22,	RADIUS_INTEGER4,	"ERX Sa Validate", radius_vendor_unisphere_sa_validate_vals, NULL},
  {23,	RADIUS_INTEGER4,	"ERX Igmp Enable", radius_vendor_unisphere_igmp_enable_vals, NULL},
  {24,	RADIUS_STRING,		"ERX PPPoE Description", NULL, NULL},
  {25,	RADIUS_STRING,		"ERX Redirect Virtual Router Name", NULL, NULL},
  {26,	RADIUS_STRING,		"ERX Qos Profile Name", NULL, NULL},
  /* 27 Unused */
  {28,	RADIUS_STRING,		"ERX PPPoE URL", NULL, NULL},
  /* 29,30 Unused */
  {31,	RADIUS_STRING,		"ERX Service Bundle", NULL, NULL},
  /* 32 Unused */
  {33,	RADIUS_INTEGER4,	"ERX Tunnel Max Sessions", NULL, NULL},
  {34,	RADIUS_INTEGER4,	"ERX Framed IP Route Tag", NULL, NULL},
  {35,	RADIUS_STRING,		"ERX Tunnel Dialout Number", NULL, NULL},
  {36,	RADIUS_STRING,		"ERX PPP Username", NULL, NULL},
  {37,	RADIUS_STRING,		"ERX PPP Password", NULL, NULL},
  {38,	RADIUS_INTEGER4,	"ERX PPP Protocol", radius_vendor_unisphere_ppp_protocol_vals, NULL},
  {39,	RADIUS_INTEGER4,	"ERX Tunnel Min Bps", NULL, NULL},
  {40,	RADIUS_INTEGER4,	"ERX Tunnel Max Bps", NULL, NULL},
  {41,	RADIUS_INTEGER4,	"ERX Tunnel Bearer Type", radius_vendor_unisphere_tunnel_bearer_type_vals, NULL},
  {42,	RADIUS_INTEGER4,	"ERX Input Gigapackets", NULL, NULL},
  {43,	RADIUS_INTEGER4,	"ERX Output Gigapackets", NULL, NULL},
  {44,	RADIUS_STRING,		"ERX Tunnel Interface Id", NULL, NULL},
  {45,	RADIUS_STRING,		"ERX IPV6 Virtual Router", NULL, NULL},
  {46,	RADIUS_STRING,		"ERX IPV6 Local Interface", NULL, NULL},
  {47,	RADIUS_IP6_ADDRESS,	"ERX IPV6 Primary Dns", NULL, NULL},
  {48,	RADIUS_IP6_ADDRESS,	"ERX IPV6 Secondary Dns", NULL, NULL},
  /* 49, 50 Unused */
  {51,	RADIUS_BINSTRING,	"ERX Disconnect Cause", NULL, NULL},
  /* 52 Unused */
  {53,	RADIUS_BINSTRING,	"ERX Service Description", NULL, NULL},
  /* 54 Unused */
  {55,	RADIUS_BINSTRING,	"ERX DHCP Options", NULL, NULL},
  {56,	RADIUS_STRING,		"ERX DHCP Mac Address", NULL, NULL},
  {57,	RADIUS_IP_ADDRESS,	"ERX DHCP Gi Address", NULL, NULL},
  {0, 0, NULL, NULL, NULL},
};

/*
reference:
	Cisco ACS 3.2 User Guide - Appendix D
	http://www.cisco.com/univercd/cc/td/doc/product/access/acs_soft/csacs4nt/acs32/user02/ad.htm#wp473531
*/

static const radius_attr_info radius_vendor_cisco_bbsm_attrib[] =
{
  {1,	RADIUS_INTEGER4,	"CBBSM-Bandwidth", NULL, NULL},
  {0, 0, NULL, NULL, NULL},
};

static const radius_attr_info radius_vendor_issanni_attrib[] =
{
  {1,	RADIUS_STRING,		"Softflow Template", NULL, NULL},
  {2,	RADIUS_STRING,		"NAT Pool", NULL, NULL},
  {3,	RADIUS_STRING,		"Virtual Routing Domain", NULL, NULL},
  {4,	RADIUS_STRING,		"Tunnel Name", NULL, NULL},
  {5,	RADIUS_STRING,		"IP Pool Name", NULL, NULL},
  {6,	RADIUS_STRING,		"PPPoE URL", NULL, NULL},
  {7,	RADIUS_STRING,		"PPPoE MOTM", NULL, NULL},
  {8,	RADIUS_STRING,		"PPPoE Service", NULL, NULL},
  {9,	RADIUS_IP_ADDRESS,	"Primary DNS", NULL, NULL},
  {10,	RADIUS_IP_ADDRESS,	"Secondary DNS", NULL, NULL},
  {11,	RADIUS_IP_ADDRESS,	"Primary NBNS", NULL, NULL},
  {12,	RADIUS_IP_ADDRESS,	"Secondary NBNS", NULL, NULL},
  {13,	RADIUS_STRING,		"Policing Traffic Class", NULL, NULL},
  {14,	RADIUS_INTEGER4,	"Tunnel Type", NULL, NULL},
  {15,	RADIUS_INTEGER4,	"NAT Type", NULL, NULL},
  {16,	RADIUS_STRING,		"QoS Traffic Class", NULL, NULL},
  {17,	RADIUS_STRING,		"Interface Name", NULL, NULL},
  {0, 0, NULL, NULL, NULL}
};

/*
reference:
	'dictionary.quintum' file from FreeRADIUS
		http://www.freeradius.org/radiusd/raddb/dictionary.quintum
*/
static const radius_attr_info radius_vendor_quintum_attrib[] =
{
  {1,	RADIUS_STRING,		"Quintum AVPair", NULL, NULL},
  {2,	RADIUS_STRING,		"Quintum NAS Port", NULL, NULL},
  {23,	RADIUS_STRING,		"Quintum h323 remote address", NULL, NULL},
  {24,	RADIUS_STRING,		"Quintum h323 conf id", NULL, NULL},
  {25,	RADIUS_STRING,		"Quintum h323 setup time", NULL, NULL},
  {26,	RADIUS_STRING,		"Quintum h323 call origin", NULL, NULL},
  {27,	RADIUS_STRING,		"Quintum h323 call type", NULL, NULL},
  {28,	RADIUS_STRING,		"Quintum h323 connect time", NULL, NULL},
  {29,	RADIUS_STRING,		"Quintum h323 disconnect time", NULL, NULL},
  {30,	RADIUS_STRING,		"Quintum h323 disconnect cause", NULL, NULL},
  {31,	RADIUS_STRING,		"Quintum h323 voice quality", NULL, NULL},
  {33,	RADIUS_STRING,		"Quintum h323 gw id", NULL, NULL},
  {35,	RADIUS_STRING,		"Quintum h323 incoming conf id", NULL, NULL},
  {101,	RADIUS_STRING,		"Quintum h323 credit amount", NULL, NULL},
  {102,	RADIUS_STRING,		"Quintum h323 credit time", NULL, NULL},
  {103,	RADIUS_STRING,		"Quintum h323 return code", NULL, NULL},
  {104,	RADIUS_STRING,		"Quintum h323 prompt id", NULL, NULL},
  {105,	RADIUS_STRING,		"Quintum h323 time and day", NULL, NULL},
  {106,	RADIUS_STRING,		"Quintum h323 redirect number", NULL, NULL},
  {107,	RADIUS_STRING,		"Quintum h323 preferred lang", NULL, NULL},
  {108,	RADIUS_STRING,		"Quintum h323 redirect ip address", NULL, NULL},
  {109,	RADIUS_STRING,		"Quintum h323 billing model", NULL, NULL},
  {110,	RADIUS_STRING,		"Quintum h323 currency type", NULL, NULL},
  {0, 0, NULL, NULL, NULL},
};

/*
reference:
	http://download.colubris.com/library/product_doc/CN3500_AdminGuide.pdf
*/
static const radius_attr_info radius_vendor_colubris_attrib[] =
{
  {0,	RADIUS_STRING,		"Colubris AV Pair", NULL, NULL},
  {0, 0, NULL, NULL, NULL},
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
  {0,	RADIUS_INTEGER4,	"SIP Method", radius_vendor_columbia_university_sip_method_vals, NULL},
  {1,	RADIUS_STRING,		"SIP From", NULL, NULL},
  {2,	RADIUS_STRING,		"SIP To", NULL, NULL},
  {4,	RADIUS_STRING,		"SIP Translated Request URI", NULL, NULL},
  {0, 0, NULL, NULL, NULL},
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
   {1,  THE3GPP_IMSI,		"IMSI", NULL, NULL},
   {2,  RADIUS_INTEGER4,	"Charging ID", NULL, NULL},
   {3,  RADIUS_INTEGER4,	"PDP Type", the3gpp_pdp_type_vals, NULL},
   {4,  RADIUS_IP_ADDRESS,	"Charging Gateway Address", NULL, NULL},
   {5,  THE3GPP_QOS,		"QoS Profile", NULL, NULL},
   {6,  RADIUS_IP_ADDRESS,	"SGSN Address", NULL, &hf_radius_3gpp_SgsnIpAddr},
   {7,  RADIUS_IP_ADDRESS,	"GGSN Address", NULL, &hf_radius_3gpp_GgsnIpAddr},
   {8,  THE3GPP_IMSI_MCC_MNC,	"IMSI MCC-MNC", NULL, NULL},
   {9,  THE3GPP_GGSN_MCC_MNC,	"GGSN MCC-MNC", NULL, NULL},
   {10, THE3GPP_NSAPI,		"NSAPI", NULL, NULL},
   {11, THE3GPP_SESSION_STOP_INDICATOR, "Session Stop Indicator", NULL, NULL},
   {12, THE3GPP_SELECTION_MODE,	"Selection Mode", NULL, NULL},
   {13, THE3GPP_CHARGING_CHARACTERISTICS, "Charging Characteristics", NULL, NULL},
   {14, RADIUS_IP6_ADDRESS,	"Charging Gateway IPv6 Address", NULL, NULL},
   {15, RADIUS_IP6_ADDRESS,	"SGSN IPv6 Address", NULL, NULL},
   {16, RADIUS_IP6_ADDRESS,	"GGSN IPv6 Address", NULL, NULL},
   {17, THE3GPP_IPV6_DNS_SERVERS, "IPv6 DNS Servers", NULL, NULL},
   {18, THE3GPP_SGSN_MCC_MNC,	"SGSN MCC-MNC", NULL, NULL},
   {0, 0, NULL, NULL, NULL},
};

static const radius_attr_info radius_vendor_gemtek_systems_attrib[] =
{
   {21, RADIUS_INTEGER4,	"Acct-Session-Input-Octets", NULL, NULL},
   {22, RADIUS_INTEGER4,	"Acct-Session-Input-Gigawords", NULL, NULL},
   {23, RADIUS_INTEGER4,	"Acct-Session-Output-Octets", NULL, NULL},
   {24, RADIUS_INTEGER4,	"Acct-Session-Output-Gigawords", NULL, NULL},
   {25, RADIUS_INTEGER4,	"Acct-Session-Octets", NULL, NULL},
   {26, RADIUS_INTEGER4,	"Acct-Session-Gigawords", NULL, NULL},
   {0, 0, NULL, NULL, NULL},
};

static const radius_attr_info radius_vendor_wifi_alliance_attrib[] =
{
   {1,  RADIUS_STRING,		"Location-ID", NULL, NULL},
   {2,  RADIUS_STRING,		"Location-Name", NULL, NULL},
   {3,  RADIUS_STRING,		"Logoff-URL", NULL, NULL},
   {4,  RADIUS_STRING,		"Redirection-URL", NULL, NULL},
   {5,  RADIUS_INTEGER4,	"Bandwidth-Min-Up", NULL, NULL},
   {6,  RADIUS_INTEGER4,	"Bandwidth-Min-Down", NULL, NULL},
   {7,  RADIUS_INTEGER4,	"Bandwidth-Max-Up", NULL, NULL},
   {8,  RADIUS_INTEGER4,	"Bandwidth-Max-Down", NULL, NULL},
   {9,  RADIUS_STRING,		"Session-Terminate-Time", NULL, NULL},
   {10, RADIUS_INTEGER4,	"Session-Terminate-End-Of-Day", NULL, NULL},
   {11, RADIUS_STRING,		"Billing-Class-Of-Service", NULL, NULL},
   {0, 0, NULL, NULL, NULL},
};

static rd_vsa_table radius_vsa_table[] =
{
  {VENDOR_ACC,			radius_vendor_acc_attrib},
  {VENDOR_CISCO,		radius_vendor_cisco_attrib},
  {VENDOR_SHIVA,		radius_vendor_shiva_attrib},
  {VENDOR_CISCO_VPN5000,	radius_vendor_cisco_vpn5000_attrib},
  {VENDOR_LIVINGSTON,		radius_vendor_livingston_attrib},
  {VENDOR_MICROSOFT,		radius_vendor_microsoft_attrib},
  {VENDOR_ASCEND,		radius_vendor_ascend_attrib},
  {VENDOR_BAY,			radius_vendor_bay_attrib},
  {VENDOR_FOUNDRY,		radius_vendor_foundry_attrib},
  {VENDOR_VERSANET,		radius_vendor_versanet_attrib},
  {VENDOR_REDBACK,		radius_vendor_redback_attrib},
  {VENDOR_JUNIPER,		radius_vendor_juniper_attrib},
  {VENDOR_CISCO_VPN3000,	radius_vendor_cisco_vpn3000_attrib},
  {VENDOR_APTIS,		radius_vendor_aptis_attrib},
  {VENDOR_COSINE,		radius_vendor_cosine_attrib},
  {VENDOR_SHASTA,		radius_vendor_shasta_attrib},
  {VENDOR_NOMADIX,		radius_vendor_nomadix_attrib},
  {VENDOR_CABLELABS,		radius_vendor_cablelabs_attrib},
  {VENDOR_UNISPHERE,		radius_vendor_unisphere_attrib},
  {VENDOR_CISCO_BBSM,		radius_vendor_cisco_bbsm_attrib},
  {VENDOR_ISSANNI,		radius_vendor_issanni_attrib},
  {VENDOR_QUINTUM,		radius_vendor_quintum_attrib},
  {VENDOR_COLUBRIS,		radius_vendor_colubris_attrib},
  {VENDOR_COLUMBIA_UNIVERSITY,	radius_vendor_columbia_university_attrib},
  {VENDOR_THE3GPP,		radius_vendor_3gpp_attrib},
  {VENDOR_GEMTEK_SYSTEMS,	radius_vendor_gemtek_systems_attrib},
  {VENDOR_WIFI_ALLIANCE,	radius_vendor_wifi_alliance_attrib},
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
                if( isprint((int)pd[i])) {
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
/*converts the raw buffer into printable hex display */
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
	rdconvertbufftobinstr(dest,tvb,offset,length);
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
	if ( isprint(c)) {
	    dest[totlen] = c;
	    totlen++;
	} else {
	    sprintf(&(dest[totlen]),"\\%03o",c);
	    totlen += strlen(&(dest[totlen]));
	}
    }
    while(i<(guint32)length) {
	if ( isprint(pd[i]) ) {
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

static gchar *rd_match_strval(guint32 val, const value_string *vs) {
	return val_to_str(val, vs, "Undefined");
}

static void rd_add_field_to_tree(proto_tree *tree, tvbuff_t *tvb, int offset,
                                 guint length,
                                 const radius_attr_info *attr_info)
{
  if (attr_info->hf) {
    switch(attr_info->value_type)
    {
        case( RADIUS_STRING ):
        case( RADIUS_BINSTRING ):
                proto_tree_add_item(tree, *attr_info->hf, tvb, offset, length, FALSE);
                break;

        case( RADIUS_INTEGER4 ):
                if (length != 4) {
                        proto_tree_add_text(tree, tvb, offset, length,
                            "%s: Length is %u, should be 4",
                            proto_registrar_get_name(*attr_info->hf),
                            length);
                        break;
                }
                proto_tree_add_item(tree, *attr_info->hf, tvb, offset, 4, FALSE);
                break;

        case( RADIUS_INTEGER8 ):
                if (length != 8) {
                        proto_tree_add_text(tree, tvb, offset, length,
                            "%s: Length is %u, should be 8",
                            proto_registrar_get_name(*attr_info->hf),
                            length);
                        break;
                }
                proto_tree_add_item(tree, *attr_info->hf, tvb, offset, 8, FALSE);
                break;

        case( RADIUS_IP_ADDRESS ):
                if (length != 4) {
                        proto_tree_add_text(tree, tvb, offset, length,
                            "%s: Length is %u, should be 4",
                            proto_registrar_get_name(*attr_info->hf),
                            length);
                        break;
                }
                proto_tree_add_item(tree, *attr_info->hf, tvb, offset, 4, FALSE);
                break;
    }
  }
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
			    int offset, const radius_attr_info *attr_info,
			    proto_tree *tree)
{
  /* Variable to peek which will be the next print_type for VENDOR-SPECIFIC
   * RADIUS attributes
   * */
  const radius_attr_info *next_attr_info;

  /* Temporary variable to perform some trick on the cont variable; again, this
   * is needed only when THE3GPP_QOS in involved.
   * */
  gchar *tmp_punt;

  gchar *cont;
  guint32 intval, packetcable_qos_flags;
  gint32 timeval;
  const guint8 *pd;
  guint8 tag, packetcable_buf[64], bitmask;
  guint8 ipv6_prefix_length;
  guint8 ipv6_addr_temp[16];

  int vsa_length;
  int vsa_len;
  int vsa_index;
  const radius_attr_info *vsa_attr_info_table;
  const e_avphdr *vsa_avph;
  proto_item *ti;
  proto_tree *obj_tree;
  guint packetcable_qos_off = offset + 22;

  /* Default begin */
  strcpy(dest, "Value:");
  cont=&dest[strlen(dest)];
  if(attr_info == NULL) {
    strcpy(cont,"Unknown Value Type");
    return;
  }
  switch(attr_info->value_type)
  {
        case( RADIUS_STRING ):
		rdconvertbufftostr(cont,tvb,offset+2,avph->avp_length-2);
		rd_add_field_to_tree(tree, tvb, offset+2, avph->avp_length-2,
		    attr_info);
                break;

        case( RADIUS_BINSTRING ):
		rdconvertbufftobinstr(cont,tvb,offset+2,avph->avp_length-2);
		rd_add_field_to_tree(tree, tvb, offset+2, avph->avp_length-2,
		    attr_info);
                break;

        case( RADIUS_USERPASSWORD ):
		rddecryptpass(cont,tvb,offset+2,avph->avp_length-2);
                break;

        case( RADIUS_INTEGER2 ):
        	intval = tvb_get_ntohs(tvb,offset+2);
        	if (attr_info->vs != NULL)
			sprintf(cont, "%s(%u)", rd_match_strval(intval, attr_info->vs), intval);
		else
	                sprintf(cont,"%u", intval);
		rd_add_field_to_tree(tree, tvb, offset+2, 2, attr_info);
                break;

        case( RADIUS_INTEGER4 ):
        	intval = tvb_get_ntohl(tvb,offset+2);
        	if (attr_info->vs != NULL)
			sprintf(cont, "%s(%u)", rd_match_strval(intval, attr_info->vs), intval);
		else
	                sprintf(cont,"%u", intval);
		rd_add_field_to_tree(tree, tvb, offset+2, 4, attr_info);
                break;

	case( RADIUS_INTEGER8 ):
		sprintf(cont, "%" PRIx64, tvb_get_ntoh64(tvb, offset+2));
		rd_add_field_to_tree(tree, tvb, offset+2, 8, attr_info);
		break;

        case( RADIUS_IP_ADDRESS ):
                ip_to_str_buf(tvb_get_ptr(tvb,offset+2,4),cont);
		rd_add_field_to_tree(tree, tvb, offset+2, 4, attr_info);
		break;

        case( RADIUS_IP6_ADDRESS ):
                ip6_to_str_buf((const struct e_in6_addr *)tvb_get_ptr(tvb,offset+2,16),cont);
                break;

        case( RADIUS_IP6_PREFIX ):
                ipv6_prefix_length = tvb_get_guint8(tvb,offset+3);
                memset(ipv6_addr_temp, 0, 16);
                if (ipv6_prefix_length > 16) ipv6_prefix_length = 16;
                tvb_memcpy(tvb, ipv6_addr_temp, offset+4, ipv6_prefix_length);
                ip6_to_str_buf((const struct e_in6_addr *)ipv6_addr_temp, cont);
                break;

        case( RADIUS_IP6_INTF_ID ):
                ipv6_prefix_length = tvb_get_guint8(tvb,offset+1);
                memset(ipv6_addr_temp, 0, 16);
                if (ipv6_prefix_length > 16) ipv6_prefix_length = 16;
                tvb_memcpy(tvb, ipv6_addr_temp, offset+2, ipv6_prefix_length);
                ip6_to_str_buf((const struct e_in6_addr *)ipv6_addr_temp, cont);
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
		sprintf(dest, "Vendor:%s(%u)", rd_match_strval(intval,sminmpec_values), intval);
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
					offset+vsa_len, next_attr_info,
					tree);
			vsa_index++;
			vsa_len += vsa_avph->avp_length;

			if ( next_attr_info )
			{
				rd_add_field_to_tree(tree, tvb, offset+8,
				                     avph->avp_length-8,
				                     next_attr_info);
				if ( next_attr_info->value_type == THE3GPP_QOS )
				{
			    		cont = tmp_punt;
					vsa_index--;
					(*vsabuffer)[vsa_index].str = 0;
				}
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
		sprintf(cont,"(not parsed)");
		break;

	case( THE3GPP_IPV6_DNS_SERVERS ):
		/* XXX - this is described as a list of IPv6 addresses of
		   DNS servers, so we probably need to process more than
		   one IPv6 address. */
		ip6_to_str_buf((const struct e_in6_addr *)tvb_get_ptr(tvb,offset+2,16),cont);
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


	case ( PACKETCABLE_EM_HEADER ):
		proto_tree_add_text(tree, tvb, offset, avph->avp_length, "%s", vsabuffer[0]->str);
		vsabuffer[0]->str = NULL;
		proto_tree_add_item(tree, hf_packetcable_em_header_version_id,
				tvb, offset + 2, 2, FALSE);
		ti = proto_tree_add_text(tree, tvb, offset + 4, 24, "BCID");
		obj_tree = proto_item_add_subtree(ti, ett_radius_vendor_packetcable_bcid);
		decode_packetcable_bcid(tvb, obj_tree, offset + 4);

		proto_tree_add_item(tree, hf_packetcable_em_header_event_message_type,
				tvb, offset + 28, 2, FALSE);
		proto_tree_add_item(tree, hf_packetcable_em_header_element_type,
				tvb, offset + 30, 2, FALSE);
		tvb_memcpy(tvb, packetcable_buf, offset + 32, 8); packetcable_buf[8] = '\0';
		proto_tree_add_text(tree, tvb, offset + 32, 8,
				"Element ID: %s", packetcable_buf );
		tvb_memcpy(tvb, packetcable_buf, offset + 41, 7); packetcable_buf[7] = '\0';
		proto_tree_add_text(tree, tvb, offset + 40, 8,
				"Time Zone: DST: %c, Offset: %s", tvb_get_guint8(tvb, offset + 40),
				packetcable_buf);
		proto_tree_add_item(tree, hf_packetcable_em_header_sequence_number,
				tvb, offset + 48, 4, FALSE);
		tvb_memcpy(tvb, packetcable_buf, offset + 52, 18); packetcable_buf[18] = '\0';
		proto_tree_add_text(tree, tvb, offset + 52, 18,
				"Event Time: %s", packetcable_buf);

		ti = proto_tree_add_item(tree, hf_packetcable_em_header_status,
				tvb, offset + 70, 4, FALSE);
		obj_tree = proto_item_add_subtree(ti, ett_radius_vendor_packetcable_status);
		proto_tree_add_item(obj_tree, hf_packetcable_em_header_status_error_indicator,
				tvb, offset + 70, 4, FALSE);
		proto_tree_add_item(obj_tree, hf_packetcable_em_header_status_event_origin,
				tvb, offset + 70, 4, FALSE);
		proto_tree_add_item(obj_tree, hf_packetcable_em_header_status_event_message_proxied,
				tvb, offset + 70, 4, FALSE);

		proto_tree_add_item(tree, hf_packetcable_em_header_priority,
				tvb, offset + 74, 1, FALSE);
		proto_tree_add_item(tree, hf_packetcable_em_header_attribute_count,
				tvb, offset + 75, 2, FALSE);
		proto_tree_add_item(tree, hf_packetcable_em_header_event_object,
				tvb, offset + 77, 1, FALSE);
		break;
	case ( PACKETCABLE_CALL_TERMINATION_CAUSE ):
		proto_tree_add_text(tree, tvb, offset, avph->avp_length, "%s", vsabuffer[0]->str);
		vsabuffer[0]->str = NULL;
		proto_tree_add_item(tree, hf_packetcable_call_termination_cause_source_document,
				tvb, offset + 2, 2, FALSE);
		proto_tree_add_item(tree, hf_packetcable_call_termination_cause_code,
				tvb, offset + 4, 4, FALSE);
		break;
	case ( PACKETCABLE_RELATED_CALL_BILLING_CORRELATION_ID ):
		proto_tree_add_text(tree, tvb, offset, avph->avp_length, "%s", vsabuffer[0]->str);
		vsabuffer[0]->str = NULL;
		decode_packetcable_bcid(tvb, tree, offset + 2);
		break;
	case ( PACKETCABLE_TRUNK_GROUP_ID ):
		proto_tree_add_text(tree, tvb, offset, avph->avp_length, "%s", vsabuffer[0]->str);
		vsabuffer[0]->str = NULL;
		proto_tree_add_item(tree, hf_packetcable_trunk_group_id_trunk_type,
				tvb, offset + 2, 2, FALSE);
		proto_tree_add_item(tree, hf_packetcable_trunk_group_id_trunk_number,
				tvb, offset + 4, 4, FALSE);
		break;
	case ( PACKETCABLE_QOS_DESCRIPTOR ):
		proto_tree_add_text(tree, tvb, offset, avph->avp_length, "%s", vsabuffer[0]->str);
		vsabuffer[0]->str = NULL;
		packetcable_qos_flags = tvb_get_letohl(tvb, offset + 2);
		ti = proto_tree_add_item(tree, hf_packetcable_qos_status,
				tvb, offset + 2, 4, FALSE);
		obj_tree = proto_item_add_subtree(ti, ett_radius_vendor_packetcable_qos_status);
		proto_tree_add_item(obj_tree, hf_packetcable_qos_status_indication,
				tvb, offset + 2, 4, FALSE);
		for (intval = 0; intval < PACKETCABLE_QOS_DESC_BITFIELDS; intval++) {
			proto_tree_add_item(obj_tree, hf_packetcable_qos_desc_flags[intval],
					tvb, offset + 2, 4, FALSE);
		}
		tvb_memcpy(tvb, packetcable_buf, offset + 6, 16); packetcable_buf[16] = '\0';
		proto_tree_add_text(tree, tvb, offset + 6, 16,
				"Service Class Name: %s", packetcable_buf);
		packetcable_qos_flags = ntohl(packetcable_qos_flags);
		for (intval = 0; intval < PACKETCABLE_QOS_DESC_BITFIELDS; intval++) {
			if (packetcable_qos_flags & packetcable_qos_desc_mask[intval]) {
				proto_tree_add_item(tree, hf_packetcable_qos_desc_fields[intval],
						tvb, packetcable_qos_off, 4, FALSE);
				packetcable_qos_off += 4;
			}
		}
		break;
	case ( PACKETCABLE_TIME_ADJUSTMENT ):
		proto_tree_add_text(tree, tvb, offset, avph->avp_length, "%s", vsabuffer[0]->str);
		vsabuffer[0]->str = NULL;
		proto_tree_add_item(tree, hf_packetcable_time_adjustment,
				tvb, offset + 2, 8, FALSE);
		break;
	case ( PACKETCABLE_REDIRECTED_FROM_INFO ):
		proto_tree_add_text(tree, tvb, offset, avph->avp_length, "%s", vsabuffer[0]->str);
		vsabuffer[0]->str = NULL;
		tvb_memcpy(tvb, packetcable_buf, offset + 2, 20); packetcable_buf[20] = '\0';
		proto_tree_add_text(tree, tvb, offset + 2, 20,
				"Last-Redirecting-Party: %s", packetcable_buf);
		tvb_memcpy(tvb, packetcable_buf, offset + 22, 20); packetcable_buf[20] = '\0';
		proto_tree_add_text(tree, tvb, offset + 22, 20,
				"Original-Called-Party: %s", packetcable_buf);
		proto_tree_add_item(tree, hf_packetcable_redirected_from_info_number_of_redirections,
				tvb, offset + 42, 2, FALSE);
		break;
	case ( PACKETCABLE_ELECTRONIC_SURVEILLANCE_INDICATION ):
		if (avph->avp_length == 2) {
		    proto_tree_add_text(tree, tvb, offset, avph->avp_length, "%s [None]", vsabuffer[0]->str);
		    vsabuffer[0]->str = NULL;
		    break;
		}
		proto_tree_add_text(tree, tvb, offset, avph->avp_length, "%s", vsabuffer[0]->str);
		vsabuffer[0]->str = NULL;
		proto_tree_add_item(tree, hf_packetcable_electronic_surveillance_indication_df_cdc_address,
				tvb, offset + 2, 4, FALSE);
		proto_tree_add_item(tree, hf_packetcable_electronic_surveillance_indication_df_ccc_address,
				tvb, offset + 6, 4, FALSE);
		proto_tree_add_item(tree, hf_packetcable_electronic_surveillance_indication_cdc_port,
				tvb, offset + 10, 2, FALSE);
		proto_tree_add_item(tree, hf_packetcable_electronic_surveillance_indication_ccc_port,
				tvb, offset + 12, 2, FALSE);
		proto_tree_add_text(tree, tvb, offset + 14, avph->avp_length,
				"DF-DF-Key");
		break;
	case ( PACKETCABLE_ELECTRONIC_SURVEILLANCE_DF_SECURITY ):
		break;
#define PACKETCABLE_GENERAL_DISPLAY (1 << 0)
#define PACKETCABLE_CALLING_NUMBER  (1 << 1)
#define PACKETCABLE_CALLING_NAME    (1 << 2)
#define PACKETCABLE_MESSAGE_WAITING (1 << 3)
	case ( PACKETCABLE_TERMINAL_DISPLAY_INFO ):
		proto_tree_add_text(tree, tvb, offset, avph->avp_length, "%s", vsabuffer[0]->str);
		vsabuffer[0]->str = NULL;
		bitmask = tvb_get_guint8(tvb, 2);
		intval = offset + 3;
		ti = proto_tree_add_item(tree, hf_packetcable_terminal_display_info_terminal_display_status_bitmask,
				tvb, offset + 2, 1, FALSE);
		obj_tree = proto_item_add_subtree(ti, ett_radius_vsa);
		proto_tree_add_item(obj_tree, hf_packetcable_terminal_display_info_sbm_general_display,
				tvb, offset + 2, 1, bitmask);
		proto_tree_add_item(obj_tree, hf_packetcable_terminal_display_info_sbm_calling_number,
				tvb, offset + 2, 1, bitmask);
		proto_tree_add_item(obj_tree, hf_packetcable_terminal_display_info_sbm_calling_name,
				tvb, offset + 2, 1, bitmask);
		proto_tree_add_item(obj_tree, hf_packetcable_terminal_display_info_sbm_message_waiting,
				tvb, offset + 2, 1, bitmask);
		if (bitmask & PACKETCABLE_GENERAL_DISPLAY) {
			proto_tree_add_item(obj_tree, hf_packetcable_terminal_display_info_general_display,
				tvb, intval, 80, FALSE);
			intval += 80;
		}
		if (bitmask & PACKETCABLE_CALLING_NUMBER) {
			proto_tree_add_item(obj_tree, hf_packetcable_terminal_display_info_calling_number,
				tvb, intval, 40, FALSE);
			intval += 40;
		}
		if (bitmask & PACKETCABLE_CALLING_NAME) {
			proto_tree_add_item(obj_tree, hf_packetcable_terminal_display_info_calling_name,
				tvb, intval, 40, FALSE);
			intval += 40;
		}
		if (bitmask & PACKETCABLE_MESSAGE_WAITING) {
			proto_tree_add_item(obj_tree, hf_packetcable_terminal_display_info_message_waiting,
				tvb, intval, 40, FALSE);
			intval += 40;
		}

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
                strcpy(cont,"Unknown Value Type");
                break;
        default:
        	g_assert_not_reached();
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
  proto_item *ti = NULL;
  guint8 *reassembled_data = NULL;
  int reassembled_data_len = 0;
  int data_needed = 0;
  char *attr_info_str = "(Invalid)";

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
        if (attr_info) {
	  attr_info_str = attr_info->str;
	}
        proto_tree_add_text(tree, tvb, offset, avph.avp_length,
			    "t:%s(%u) l:%u (length not >= 2)",
			    attr_info_str, avph.avp_type, avph.avp_length);
      }
      break;
    }

    if (tree) {
      ti = proto_tree_add_text(tree, tvb, offset, avph.avp_length,
			       "t:%s(%u) l:%u",
			       attr_info ? attr_info->str : "Unknown Type",
			       avph.avp_type, avph.avp_length);
    }
    if (attr_info != NULL && attr_info->value_type == RADIUS_EAP_MESSAGE) {
      /* EAP Message */
      proto_tree *eap_tree = NULL;
      gint tvb_len;
      tvbuff_t *next_tvb;
      int data_len;
      int result;

      if (tree)
        eap_tree = proto_item_add_subtree(ti, ett_radius_eap);
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
        proto_tree *vsa_tree = NULL;
        int i;
        gchar textbuffer[TEXTBUFFER];
        rd_vsa_buffer vsabuffer[VSABUFFER];

        /* We pre-add a text and a subtree to allow 3GPP QoS decoding
         * to access the protocol tree.
         * */
        vsa_tree = proto_item_add_subtree(ti, ett_radius_vsa);
        for (i = 0; i < VSABUFFER; i++)
	    vsabuffer[i].str = NULL;
        rd_value_to_str(textbuffer, &vsabuffer, &avph, tvb, offset,
			attr_info, vsa_tree);
        proto_item_append_text(ti, ", %s", textbuffer);
	for (i = 0; vsabuffer[i].str && i < VSABUFFER; i++) {
	    proto_tree_add_text(vsa_tree, tvb, vsabuffer[i].offset,
				vsabuffer[i].length, "%s", vsabuffer[i].str);
	}
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

/* Decode a PacketCable BCID. */
/* XXX - This should probably be combinde with the equivalent COPS code */
static void decode_packetcable_bcid (tvbuff_t *tvb, proto_tree *tree, int offset)
{
	guint8 packetcable_buf[16];

	proto_tree_add_item(tree, hf_packetcable_bcid_timestamp,
			tvb, offset, 4, FALSE);
	tvb_memcpy(tvb, packetcable_buf, offset + 4, 8); packetcable_buf[8] = '\0';
	proto_tree_add_text(tree, tvb, offset + 4, 8,
			"Element ID: %s", packetcable_buf);
	tvb_memcpy(tvb, packetcable_buf, offset + 13, 7); packetcable_buf[7] = '\0';
	proto_tree_add_text(tree, tvb, offset + 12, 8,
			"Time Zone: DST: %c, Offset: %s", tvb_get_guint8(tvb, offset + 12),
			packetcable_buf);
	proto_tree_add_item(tree, hf_packetcable_bcid_event_counter,
			tvb, offset + 20, 4, FALSE);
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
  gchar *hex_authenticator;

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
	hex_authenticator = g_malloc(AUTHENTICATOR_LENGTH * 2 + 1);
	rdconvertbufftobinstr(hex_authenticator, tvb, 4, AUTHENTICATOR_LENGTH);
	proto_tree_add_text(radius_tree, tvb, 4,
			AUTHENTICATOR_LENGTH,
                         "Authenticator: 0x%s", hex_authenticator);
	g_free(hex_authenticator);
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
			"", HFILL }},

		{ &hf_radius_userName,
		{ "User-Name",	"radius.username", FT_STRING, BASE_NONE, NULL, 0x0,
			"", HFILL }},

		{ &hf_radius_serviceType,
		{ "Service-Type",	"radius.service_type", FT_UINT32, BASE_DEC, VALS(radius_service_type_vals), 0x0,
			"", HFILL }},

		{ &hf_radius_framedProtocol,
		{ "Framed-Protocol",	"radius.framed_protocol", FT_UINT32, BASE_DEC, VALS(radius_framed_protocol_vals), 0x0,
			"", HFILL }},

		{ &hf_radius_callingStationId,
		{ "Calling-Station-Id",	"radius.calling", FT_STRING, BASE_NONE, NULL, 0x0,
			"", HFILL }},

		{ &hf_radius_calledStationId,
		{ "Called-Station-Id",	"radius.called", FT_STRING, BASE_NONE, NULL, 0x0,
			"", HFILL }},

		{ &hf_radius_class,
		{ "Class",	"radius.class", FT_BYTES, BASE_NONE, NULL, 0x0,
			"", HFILL }},

		{ &hf_radius_acctSessionId,
		{ "Accounting Session Id",	"radius.acct.sessionid", FT_STRING, BASE_NONE, NULL, 0x0,
			"", HFILL }},

		{ &hf_radius_framedAddress,
		{ "Framed Address",	"radius.framed_addr", FT_IPv4, BASE_NONE, NULL, 0x0,
			"", HFILL }},

		{ &hf_radius_acctStatusType,
		{ "Accounting Status Type",	"radius.acct.status_type", FT_UINT32, BASE_DEC, VALS(radius_accounting_status_type_vals), 0x0,
			"", HFILL }},

		{ &hf_radius_nasIp,
		{ "Nas IP Address",	"radius.nas_ip", FT_IPv4, BASE_NONE, NULL, 0x0,
			"", HFILL }},

		{ &hf_radius_3gpp_SgsnIpAddr,
		{ "SGSN IP Address",	"radius.3gpp.sgsn_ip", FT_IPv4, BASE_NONE, NULL, 0x0,
			"", HFILL }},

		{ &hf_radius_3gpp_GgsnIpAddr,
		{ "GGSN IP Address",	"radius.3gpp.ggsn_ip", FT_IPv4, BASE_NONE, NULL, 0x0,
			"", HFILL }},

		{ &hf_radius_cisco_cai,
		{ "Cisco-Account-Info",	"radius.cisco.cai", FT_STRING, BASE_NONE, NULL, 0x0,
			"", HFILL }},

		{ &hf_packetcable_em_header_version_id,
			{ "Event Message Version ID","radius.vendor.pkt.emh.vid",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  "PacketCable Event Message header version ID", HFILL }
		},
		{ &hf_packetcable_bcid_timestamp,
			{ "Timestamp","radius.vendor.pkt.bcid.ts",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "PacketCable Event Message BCID Timestamp", HFILL }
		},
		{ &hf_packetcable_bcid_event_counter,
			{ "Event Counter","radius.vendor.pkt.bcid.ec",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "PacketCable Event Message BCID Event Counter", HFILL }
		},
		{ &hf_packetcable_em_header_event_message_type,
			{ "Event Message Type","radius.vendor.pkt.emh.emt",
			  FT_UINT16, BASE_DEC, radius_vendor_packetcable_event_message_vals, 0x0,
			  "PacketCable Event Message Type", HFILL }
		},
		{ &hf_packetcable_em_header_element_type,
			{ "Element Type","radius.vendor.pkt.emh.et",
			  FT_UINT16, BASE_DEC, packetcable_em_header_element_type_vals, 0x0,
			  "PacketCable Event Message Element Type", HFILL }
		},
		{ &hf_packetcable_em_header_sequence_number,
			{ "Sequence Number","radius.vendor.pkt.emh.sn",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "PacketCable Event Message Sequence Number", HFILL }
		},
		{ &hf_packetcable_em_header_status,
			{ "Status","radius.vendor.pkt.emh.st",
			  FT_UINT32, BASE_HEX, NULL, 0x0,
			  "PacketCable Event Message Status", HFILL }
		},
		{ &hf_packetcable_em_header_status_error_indicator,
			{ "Status","radius.vendor.pkt.emh.st.ei",
			  FT_UINT32, BASE_HEX, packetcable_em_header_status_error_indicator_vals,
			  PACKETCABLE_EMHS_EI_MASK,
			  "PacketCable Event Message Status Error Indicator", HFILL }
		},
		{ &hf_packetcable_em_header_status_event_origin,
			{ "Event Origin","radius.vendor.pkt.emh.st.eo",
			  FT_UINT32, BASE_HEX, packetcable_em_header_status_event_origin_vals,
			  PACKETCABLE_EMHS_EO_MASK,
			  "PacketCable Event Message Status Event Origin", HFILL }
		},
		{ &hf_packetcable_em_header_status_event_message_proxied,
			{ "Event Message Proxied","radius.vendor.pkt.emh.st.emp",
			  FT_UINT32, BASE_HEX, packetcable_em_header_status_event_message_proxied_vals,
			  PACKETCABLE_EMHS_EMP_MASK,
			  "PacketCable Event Message Status Event Message Proxied", HFILL }
		},
		{ &hf_packetcable_em_header_priority,
			{ "Priority","radius.vendor.pkt.emh.priority",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  "PacketCable Event Message Priority", HFILL }
		},
		{ &hf_packetcable_em_header_attribute_count,
			{ "Attribute Count","radius.vendor.pkt.emh.ac",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  "PacketCable Event Message Attribute Count", HFILL }
		},
		{ &hf_packetcable_em_header_event_object,
			{ "Event Object","radius.vendor.pkt.emh.eo",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  "PacketCable Event Message Event Object", HFILL }
		},
		{ &hf_packetcable_call_termination_cause_source_document,
			{ "Source Document","radius.vendor.pkt.ctc.sd",
			  FT_UINT16, BASE_HEX, packetcable_call_termination_cause_vals, 0x0,
			  "PacketCable Call Termination Cause Source Document", HFILL }
		},
		{ &hf_packetcable_call_termination_cause_code,
			{ "Event Object","radius.vendor.pkt.ctc.cc",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "PacketCable Call Termination Cause Code", HFILL }
		},
		{ &hf_packetcable_trunk_group_id_trunk_type,
			{ "Trunk Type","radius.vendor.pkt.tgid.tt",
			  FT_UINT16, BASE_HEX, packetcable_trunk_type_vals, 0x0,
			  "PacketCable Trunk Group ID Trunk Type", HFILL }
		},
		{ &hf_packetcable_trunk_group_id_trunk_number,
			{ "Event Object","radius.vendor.pkt.tgid.tn",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "PacketCable Trunk Group ID Trunk Number", HFILL }
		},
		{ &hf_packetcable_qos_status,
			{ "QoS Status","radius.vendor.pkt.qs",
			  FT_UINT32, BASE_HEX, NULL, 0x0,
			  "PacketCable QoS Descriptor Attribute QoS Status", HFILL }
		},
		{ &hf_packetcable_qos_status_indication,
			{ "Status Indication","radius.vendor.pkt.qs.si",
			  FT_UINT32, BASE_DEC, packetcable_state_indication_vals, PACKETCABLE_QOS_STATE_INDICATION_MASK,
			  "PacketCable QoS Descriptor Attribute QoS State Indication", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[0],
			{ "Service Flow Scheduling Type","radius.vendor.pkt.qs.flags.sfst",
			  FT_UINT32, BASE_DEC, NULL, PACKETCABLE_SERVICE_FLOW_SCHEDULING_TYPE_MASK,
			  "PacketCable QoS Descriptor Attribute Bitmask: Service Flow Scheduling Type", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[1],
			{ "Grant Interval","radius.vendor.pkt.qs.flags.gi",
			  FT_UINT32, BASE_DEC, NULL, PACKETCABLE_NOMINAL_GRANT_INTERVAL_MASK,
			  "PacketCable QoS Descriptor Attribute Bitmask: Grant Interval", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[2],
			{ "Tolerated Grant Jitter","radius.vendor.pkt.qs.flags.tgj",
			  FT_UINT32, BASE_DEC, NULL, PACKETCABLE_TOLERATED_GRANT_JITTER_MASK,
			  "PacketCable QoS Descriptor Attribute Bitmask: Tolerated Grant Jitter", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[3],
			{ "Grants Per Interval","radius.vendor.pkt.qs.flags.gpi",
			  FT_UINT32, BASE_DEC, NULL, PACKETCABLE_GRANTS_PER_INTERVAL_MASK,
			  "PacketCable QoS Descriptor Attribute Bitmask: Grants Per Interval", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[4],
			{ "Unsolicited Grant Size","radius.vendor.pkt.qs.flags.ugs",
			  FT_UINT32, BASE_DEC, NULL, PACKETCABLE_UNSOLICITED_GRANT_SIZE_MASK,
			  "PacketCable QoS Descriptor Attribute Bitmask: Unsolicited Grant Size", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[5],
			{ "Traffic Priority","radius.vendor.pkt.qs.flags.tp",
			  FT_UINT32, BASE_DEC, NULL, PACKETCABLE_TRAFFIC_PRIORITY_MASK,
			  "PacketCable QoS Descriptor Attribute Bitmask: Traffic Priority", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[6],
			{ "Maximum Sustained Rate","radius.vendor.pkt.qs.flags.msr",
			  FT_UINT32, BASE_DEC, NULL, PACKETCABLE_MAXIMUM_SUSTAINED_RATE_MASK,
			  "PacketCable QoS Descriptor Attribute Bitmask: Maximum Sustained Rate", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[7],
			{ "Maximum Traffic Burst","radius.vendor.pkt.qs.flags.mtb",
			  FT_UINT32, BASE_DEC, NULL, PACKETCABLE_MAXIMUM_TRAFFIC_BURST_MASK,
			  "PacketCable QoS Descriptor Attribute Bitmask: Maximum Traffic Burst", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[8],
			{ "Minimum Reserved Traffic Rate","radius.vendor.pkt.qs.flags.mrtr",
			  FT_UINT32, BASE_DEC, NULL, PACKETCABLE_MINIMUM_RESERVED_TRAFFIC_RATE_MASK,
			  "PacketCable QoS Descriptor Attribute Bitmask: Minimum Reserved Traffic Rate", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[9],
			{ "Minium Packet Size","radius.vendor.pkt.qs.flags.mps",
			  FT_UINT32, BASE_DEC, NULL, PACKETCABLE_MINIMUM_PACKET_SIZE_MASK,
			  "PacketCable QoS Descriptor Attribute Bitmask: Minimum Packet Size", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[10],
			{ "Maximum Concatenated Burst","radius.vendor.pkt.qs.flags.mcb",
			  FT_UINT32, BASE_DEC, NULL, PACKETCABLE_MAXIMUM_CONCATENATED_BURST_MASK,
			  "PacketCable QoS Descriptor Attribute Bitmask: Maximum Concatenated Burst", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[11],
			{ "Status Request/Transmission Policy","radius.vendor.pkt.qs.flags.srtp",
			  FT_UINT32, BASE_DEC, NULL, PACKETCABLE_REQUEST_TRANSMISSION_POLICY_MASK,
			  "PacketCable QoS Descriptor Attribute Bitmask: Status Request/Transmission Policy", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[12],
			{ "Nominal Polling Interval","radius.vendor.pkt.qs.flags.npi",
			  FT_UINT32, BASE_DEC, NULL, PACKETCABLE_NOMINAL_POLLING_INTERVAL_MASK,
			  "PacketCable QoS Descriptor Attribute Bitmask: Nominal Polling Interval", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[13],
			{ "Tolerated Poll Jitter","radius.vendor.pkt.qs.flags.tpj",
			  FT_UINT32, BASE_DEC, NULL, PACKETCABLE_TOLERATED_POLL_JITTER_MASK,
			  "PacketCable QoS Descriptor Attribute Bitmask: Tolerated Poll Jitter", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[14],
			{ "Type of Service Override","radius.vendor.pkt.qs.flags.toso",
			  FT_UINT32, BASE_DEC, NULL, PACKETCABLE_IP_TYPE_OF_SERVICE_OVERRIDE_MASK,
			  "PacketCable QoS Descriptor Attribute Bitmask: Type of Service Override", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[15],
			{ "Maximum Downstream Latency","radius.vendor.pkt.qs.flags.mdl",
			  FT_UINT32, BASE_DEC, NULL, PACKETCABLE_MAXIMUM_DOWNSTREAM_LATENCY_MASK,
			  "PacketCable QoS Descriptor Attribute Bitmask: Maximum Downstream Latency", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[0],
			{ "Service Flow Scheduling Type","radius.vendor.pkt.qs.sfst",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "PacketCable QoS Descriptor Attribute Service Flow Scheduling Type", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[1],
			{ "Grant Interval","radius.vendor.pkt.qs.gi",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "PacketCable QoS Descriptor Attribute Grant Interval", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[2],
			{ "Tolerated Grant Jitter","radius.vendor.pkt.qs.tgj",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "PacketCable QoS Descriptor Attribute Tolerated Grant Jitter", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[3],
			{ "Grants Per Interval","radius.vendor.pkt.qs.gpi",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "PacketCable QoS Descriptor Attribute Grants Per Interval", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[4],
			{ "Unsolicited Grant Size","radius.vendor.pkt.qs.ugs",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "PacketCable QoS Descriptor Attribute Unsolicited Grant Size", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[5],
			{ "Traffic Priority","radius.vendor.pkt.qs.tp",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "PacketCable QoS Descriptor Attribute Traffic Priority", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[6],
			{ "Maximum Sustained Rate","radius.vendor.pkt.qs.msr",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "PacketCable QoS Descriptor Attribute Maximum Sustained Rate", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[7],
			{ "Maximum Traffic Burst","radius.vendor.pkt.qs.mtb",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "PacketCable QoS Descriptor Attribute Maximum Traffic Burst", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[8],
			{ "Minimum Reserved Traffic Rate","radius.vendor.pkt.qs.mrtr",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "PacketCable QoS Descriptor Attribute Minimum Reserved Traffic Rate", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[9],
			{ "Minium Packet Size","radius.vendor.pkt.qs.mps",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "PacketCable QoS Descriptor Attribute Minimum Packet Size", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[10],
			{ "Maximum Concatenated Burst","radius.vendor.pkt.qs.mcb",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "PacketCable QoS Descriptor Attribute Maximum Concatenated Burst", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[11],
			{ "Status Request/Transmission Policy","radius.vendor.pkt.qs.srtp",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "PacketCable QoS Descriptor Attribute Status Request/Transmission Policy", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[12],
			{ "Nominal Polling Interval","radius.vendor.pkt.qs.npi",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "PacketCable QoS Descriptor Attribute Nominal Polling Interval", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[13],
			{ "Tolerated Poll Jitter","radius.vendor.pkt.qs.tpj",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "PacketCable QoS Descriptor Attribute Tolerated Poll Jitter", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[14],
			{ "Type of Service Override","radius.vendor.pkt.qs.toso",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "PacketCable QoS Descriptor Attribute Type of Service Override", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[15],
			{ "Maximum Downstream Latency","radius.vendor.pkt.qs.mdl",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  "PacketCable QoS Descriptor Attribute Maximum Downstream Latency", HFILL }
		},
		{ &hf_packetcable_time_adjustment,
			{ "Time Adjustment","radius.vendor.pkt.ti",
			  FT_UINT64, BASE_DEC, NULL, 0x0,
			  "PacketCable Time Adjustment", HFILL }
		},
		{ &hf_packetcable_redirected_from_info_number_of_redirections,
			{ "Number-of-Redirections","radius.vendor.pkt.rfi.nr",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  "PacketCable Redirected-From-Info Number-of-Redirections", HFILL }
		},
		{ &hf_packetcable_electronic_surveillance_indication_df_cdc_address,
			{ "DF_CDC_Address","radius.vendor.pkt.esi.dfcdca",
			  FT_IPv4, BASE_DEC, NULL, 0x0,
			  "PacketCable Electronic-Surveillance-Indication DF_CDC_Address", HFILL }
		},
		{ &hf_packetcable_electronic_surveillance_indication_df_ccc_address,
			{ "DF_CDC_Address","radius.vendor.pkt.esi.dfccca",
			  FT_IPv4, BASE_DEC, NULL, 0x0,
			  "PacketCable Electronic-Surveillance-Indication DF_CCC_Address", HFILL }
		},
		{ &hf_packetcable_electronic_surveillance_indication_cdc_port,
			{ "CDC-Port","radius.vendor.pkt.esi.cdcp",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  "PacketCable Electronic-Surveillance-Indication CDC-Port", HFILL }
		},
		{ &hf_packetcable_electronic_surveillance_indication_ccc_port,
			{ "CCC-Port","radius.vendor.pkt.esi.cccp",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  "PacketCable Electronic-Surveillance-Indication CCC-Port", HFILL }
		},

		{ &hf_packetcable_terminal_display_info_terminal_display_status_bitmask,
			{ "Terminal_Display_Status_Bitmask","radius.vendor.pkt.tdi.sbm",
			  FT_UINT8, BASE_HEX, NULL, 0xff,
			  "PacketCable Terminal_Display_Info Terminal_Display_Status_Bitmask", HFILL }
		},
		{ &hf_packetcable_terminal_display_info_sbm_general_display,
			{ "General_Display","radius.vendor.pkt.tdi.sbm.gd",
			  FT_BOOLEAN, 8, NULL, 0x01,
			  "PacketCable Terminal_Display_Info Terminal_Display_Status_Bitmask General_Display", HFILL }
		},
		{ &hf_packetcable_terminal_display_info_sbm_calling_number,
			{ "Calling_Number","radius.vendor.pkt.tdi.sbm.cnum",
			  FT_BOOLEAN, 8, NULL, 0x02,
			  "PacketCable Terminal_Display_Info Terminal_Display_Status_Bitmask Calling_Number", HFILL }
		},
		{ &hf_packetcable_terminal_display_info_sbm_calling_name,
			{ "Calling_Name","radius.vendor.pkt.tdi.sbm.cname",
			  FT_BOOLEAN, 8, NULL, 0x04,
			  "PacketCable Terminal_Display_Info Terminal_Display_Status_Bitmask Calling_Name", HFILL }
		},
		{ &hf_packetcable_terminal_display_info_sbm_message_waiting,
			{ "Message_Waiting","radius.vendor.pkt.tdi.sbm.mw",
			  FT_BOOLEAN, 8, NULL, 0x08,
			  "PacketCable Terminal_Display_Info Terminal_Display_Status_Bitmask Message_Waiting", HFILL }
		},
		{ &hf_packetcable_terminal_display_info_general_display,
			{ "General_Display","radius.vendor.pkt.tdi.gd",
			  FT_STRING, BASE_NONE, NULL, 0,
			  "PacketCable Terminal_Display_Info General_Display", HFILL }
		},
		{ &hf_packetcable_terminal_display_info_calling_number,
			{ "Calling_Number","radius.vendor.pkt.tdi.cnum",
			  FT_STRING, BASE_NONE, NULL, 0,
			  "PacketCable Terminal_Display_Info Calling_Number", HFILL }
		},
		{ &hf_packetcable_terminal_display_info_calling_name,
			{ "Calling_Name","radius.vendor.pkt.tdi.cname",
			  FT_STRING, BASE_NONE, NULL, 0,
			  "PacketCable Terminal_Display_Info Calling_Name", HFILL }
		},
		{ &hf_packetcable_terminal_display_info_message_waiting,
			{ "Message_Waiting","radius.vendor.pkt.tdi.mw",
			  FT_STRING, BASE_NONE, NULL, 0,
			  "PacketCable Terminal_Display_Info Message_Waiting", HFILL }
		},

	};
	static gint *ett[] = {
		&ett_radius,
		&ett_radius_avp,
		&ett_radius_eap,
		&ett_radius_vsa,
		&ett_radius_vendor_packetcable_bcid,
		&ett_radius_vendor_packetcable_status,
		&ett_radius_vendor_packetcable_qos_status,
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
