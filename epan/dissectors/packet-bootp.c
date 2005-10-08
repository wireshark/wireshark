/* packet-bootp.c
 * Routines for BOOTP/DHCP packet disassembly
 * Copyright 1998, Gilbert Ramirez <gram@alumni.rice.edu>
 * Copyright 2004, Thomas Anders <thomas.anders [AT] blue-cable.de>
 *
 * $Id$
 *
 * The information used comes from:
 * RFC  951: Bootstrap Protocol
 * RFC 1497: BOOTP extensions
 * RFC 1542: Clarifications and Extensions for the Bootstrap Protocol
 * RFC 2131: Dynamic Host Configuration Protocol
 * RFC 2132: DHCP Options and BOOTP Vendor Extensions
 * RFC 2241: DHCP Options for Novell Directory Services
 * RFC 2242: NetWare/IP Domain Name and Information
 * RFC 2489: Procedure for Defining New DHCP Options
 * RFC 2610: DHCP Options for Service Location Protocol
 * RFC 3046: DHCP Relay Agent Information Option
 * RFC 3118: Authentication for DHCP Messages
 * RFC 3203: DHCP reconfigure extension
 * RFC 3495: DHCP Option (122) for CableLabs Client Configuration
 * RFC 3594: PacketCable Security Ticket Control Sub-Option (122.9)
 * draft-ietf-dhc-fqdn-option-07.txt
 * BOOTP and DHCP Parameters
 *     http://www.iana.org/assignments/bootp-dhcp-parameters
 * DOCSIS(TM) 2.0 Radio Frequency Interface Specification
 *     http://www.cablemodem.com/downloads/specs/CM-SP-RFIv2.0-I08-050408.pdf
 * PacketCable(TM) 1.0 MTA Device Provisioning Specification
 *     http://www.packetcable.com/downloads/specs/PKT-SP-PROV-I10-040730.pdf
 *     http://www.cablelabs.com/specifications/archives/PKT-SP-PROV-I05-021127.pdf (superseded by above)
 * PacketCable(TM) 1.5 MTA Device Provisioning Specification
 *     http://www.packetcable.com/downloads/specs/PKT-SP-PROV1.5-I01-050128.pdf
 * CableHome(TM) 1.1 Specification
 *     http://www.cablelabs.com/projects/cablehome/downloads/specs/CH-SP-CH1.1-I08-050408.pdf
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

/*
 * Some of the development of the BOOTP/DHCP protocol decoder was sponsored by
 * Cable Television Laboratories, Inc. ("CableLabs") based upon proprietary
 * CableLabs' specifications. Your license and use of this protocol decoder
 * does not mean that you are licensed to use the CableLabs'
 * specifications.  If you have questions about this protocol, contact
 * jf.mule [AT] cablelabs.com or c.stuart [AT] cablelabs.com for additional
 * information.
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include "packet-arp.h"
#include "packet-dns.h"				/* for get_dns_name() */
#include <epan/addr_resolv.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/strutil.h>
#include <epan/arptypes.h>
#include <epan/emem.h>

static int bootp_dhcp_tap = -1;
static int proto_bootp = -1;
static int hf_bootp_type = -1;
static int hf_bootp_hw_type = -1;
static int hf_bootp_hw_len = -1;
static int hf_bootp_hops = -1;
static int hf_bootp_id = -1;
static int hf_bootp_secs = -1;
static int hf_bootp_flags = -1;
static int hf_bootp_flags_broadcast = -1;
static int hf_bootp_flags_reserved = -1;
static int hf_bootp_ip_client = -1;
static int hf_bootp_ip_your = -1;
static int hf_bootp_ip_server = -1;
static int hf_bootp_ip_relay = -1;
static int hf_bootp_hw_addr = -1;
static int hf_bootp_server = -1;
static int hf_bootp_file = -1;
static int hf_bootp_cookie = -1;
static int hf_bootp_vendor = -1;
static int hf_bootp_dhcp = -1;
static int hf_bootp_fqdn_s = -1;
static int hf_bootp_fqdn_o = -1;
static int hf_bootp_fqdn_e = -1;
static int hf_bootp_fqdn_n = -1;
static int hf_bootp_fqdn_mbz = -1;
static int hf_bootp_fqdn_rcode1 = -1;
static int hf_bootp_fqdn_rcode2 = -1;
static int hf_bootp_fqdn_name = -1;
static int hf_bootp_fqdn_asciiname = -1;
static int hf_bootp_pkt_mtacap_len = -1;
static int hf_bootp_docsis_cmcap_len = -1;
static int hf_bootp_hw_ether_addr = -1;

static gint ett_bootp = -1;
static gint ett_bootp_flags = -1;
static gint ett_bootp_option = -1;
static gint ett_bootp_fqdn = -1;

gboolean novell_string = FALSE;

#define UDP_PORT_BOOTPS  67
#define UDP_PORT_BOOTPC  68

#define BOOTP_BC	0x8000
#define BOOTP_MBZ	0x7FFF

/* FQDN stuff */
#define F_FQDN_S	0x01
#define F_FQDN_O	0x02
#define F_FQDN_E	0x04
#define F_FQDN_N	0x08
#define F_FQDN_MBZ	0xf0

static const true_false_string tfs_fqdn_s = {
  "Server",
  "Client"
};

static const true_false_string tfs_fqdn_o = {
  "Override",
  "No override"
};

static const true_false_string tfs_fqdn_e = {
  "Binary encoding",
  "ASCII encoding"
};

static const true_false_string tfs_fqdn_n = {
  "No server updates",
  "Some server updates"
};

enum field_type {
	special,
	none,
	presence,
	ipv4,			/* single IPv4 address */
	ipv4_list,		/* list of IPv4 addresses */
	string,
	bytes,
	opaque,
	val_boolean,
	val_u_byte,
	val_u_short,
	val_u_short_list,
	val_u_le_short,
	val_u_long,
	time_in_secs,
	fqdn,
	ipv4_or_fqdn
};

struct opt_info {
	const char	*text;
	enum field_type ftype;
	const void	*data;
};

static const true_false_string flag_set_broadcast = {
  "Broadcast",
  "Unicast"
};


/* PacketCable/DOCSIS definitions */
#define PACKETCABLE_MTA_CAP10 "pktc1.0:"
#define PACKETCABLE_MTA_CAP15 "pktc1.5:"
#define PACKETCABLE_CM_CAP11  "docsis1.1:"
#define PACKETCABLE_CM_CAP20  "docsis2.0:"

#define PACKETCABLE_CCC_I05      1
#define PACKETCABLE_CCC_DRAFT5   2
#define PACKETCABLE_CCC_RFC_3495 3

static enum_val_t pkt_ccc_protocol_versions[] = {
	{ "ccc_i05",     "PKT-SP-PROV-I05-021127", PACKETCABLE_CCC_I05 },
	{ "ccc_draft_5", "IETF Draft 5",           PACKETCABLE_CCC_DRAFT5 },
	{ "rfc_3495",    "RFC 3495",               PACKETCABLE_CCC_RFC_3495 },
	{ NULL, NULL, 0 }
};

static gint pkt_ccc_protocol_version = PACKETCABLE_CCC_RFC_3495;
static gint pkt_ccc_option = 122;


static int dissect_vendor_pxeclient_suboption(proto_tree *v_tree, tvbuff_t *tvb,
    int optoff, int optend);
static int dissect_vendor_cablelabs_suboption(proto_tree *v_tree, tvbuff_t *tvb,
    int optoff, int optend);
static int dissect_netware_ip_suboption(proto_tree *v_tree, tvbuff_t *tvb,
    int optoff, int optend);
static int bootp_dhcp_decode_agent_info(proto_tree *v_tree, tvbuff_t *tvb,
    int optoff, int optend);
static void dissect_packetcable_mta_cap(proto_tree *v_tree, tvbuff_t *tvb,
       int voff, int len);
static void dissect_docsis_cm_cap(proto_tree *v_tree, tvbuff_t *tvb,
       int voff, int len);
static int dissect_packetcable_i05_ccc(proto_tree *v_tree, tvbuff_t *tvb,
    int optoff, int optend);
static int dissect_packetcable_ietf_ccc(proto_tree *v_tree, tvbuff_t *tvb,
    int optoff, int optend, int revision);


static const char *
get_dhcp_type(guint8 byte)
{
	static const char	*opt53_text[] = {
		"Unknown Message Type",
		"Discover",
		"Offer",
		"Request",
		"Decline",
		"ACK",
		"NAK",
		"Release",
		"Inform",
		"Force Renew"
	};
	int i;

	if (byte > 0 && byte < (sizeof opt53_text / sizeof opt53_text[0]))
		i = byte;
	else
		i = 0;
	return opt53_text[i];
}

/* DHCP Authentication protocols */
#define AUTHEN_PROTO_CONFIG_TOKEN	0
#define AUTHEN_PROTO_DELAYED_AUTHEN	1

/* DHCP Authentication algorithms for delayed authentication */
#define AUTHEN_DELAYED_ALGO_HMAC_MD5	1

/* DHCP Authentication Replay Detection Methods */
#define AUTHEN_RDM_MONOTONIC_COUNTER	0x00

/* DHCP Option Overload (option code 52) */
#define OPT_OVERLOAD_FILE		1
#define OPT_OVERLOAD_SNAME		2
#define OPT_OVERLOAD_BOTH		3

/* Server name and boot file offsets and lengths */
#define SERVER_NAME_OFFSET		44
#define SERVER_NAME_LEN 		64
#define FILE_NAME_OFFSET		108
#define FILE_NAME_LEN			128
#define VENDOR_INFO_OFFSET		236

static const true_false_string toggle_tfs = {
	"Enabled",
	"Disabled"
};

static const true_false_string yes_no_tfs = {
	"Yes",
	"No"
};

/* Returns the number of bytes consumed by this option. */
static int
bootp_option(tvbuff_t *tvb, proto_tree *bp_tree, int voff, int eoff,
    gboolean first_pass, gboolean *at_end, const char **dhcp_type_p,
    const guint8 **vendor_class_id_p)
{
	const char		*text;
	enum field_type		ftype;
	guchar			code = tvb_get_guint8(tvb, voff);
	int			optlen;
	const struct true_false_string *tfs;
	const value_string	*vs;
	guchar			byte;
	int			i, consumed;
	int			optoff, optleft, optend;
	gulong			time_secs;
	proto_tree		*v_tree, *o52tree, *flags_tree, *ft;
	proto_item		*vti;
	guint8			protocol;
	guint8			algorithm;
	guint8			rdm;
	guint8			fqdn_flags;
	int			o52voff, o52eoff;
	gboolean		o52at_end;
	gboolean		skip_opaque = FALSE;

	static const value_string nbnt_vals[] = {
	    {0x1,   "B-node" },
	    {0x2,   "P-node" },
	    {0x4,   "M-node" },
	    {0x8,   "H-node" },
	    {0,     NULL     } };

	static const value_string slpda_vals[] = {
	    {0x00,   "Dynamic Discovery" },
	    {0x01,   "Static Discovery" },
	    {0x80,   "Backwards compatibility" },
	    {0,     NULL     } };

	static const value_string slp_scope_vals[] = {
	    {0x00,   "Preferred Scope" },
	    {0x01,   "Mandatory Scope" },
	    {0,     NULL     } };

	static const value_string authen_protocol_vals[] = {
	    {AUTHEN_PROTO_CONFIG_TOKEN,   "configuration token" },
	    {AUTHEN_PROTO_DELAYED_AUTHEN, "delayed authentication" },
	    {0,                           NULL     } };

	static const value_string authen_da_algo_vals[] = {
	    {AUTHEN_DELAYED_ALGO_HMAC_MD5, "HMAC_MD5" },
	    {0,                            NULL     } };

	static const value_string authen_rdm_vals[] = {
	    {AUTHEN_RDM_MONOTONIC_COUNTER, "Monotonically-increasing counter" },
	    {0,                            NULL     } };

	static const value_string opt_overload_vals[] = {
	    { OPT_OVERLOAD_FILE,  "Boot file name holds options",                },
	    { OPT_OVERLOAD_SNAME, "Server host name holds options",              },
	    { OPT_OVERLOAD_BOTH,  "Boot file and server host names hold options" },
	    { 0,                  NULL                                           } };

	static struct opt_info opt[] = {
		/*   0 */ { "Padding",					none, NULL },
		/*   1 */ { "Subnet Mask",				ipv4, NULL },
		/*   2 */ { "Time Offset",				time_in_secs, NULL },
		/*   3 */ { "Router",					ipv4_list, NULL },
		/*   4 */ { "Time Server",				ipv4_list, NULL },
		/*   5 */ { "Name Server",				ipv4_list, NULL },
		/*   6 */ { "Domain Name Server",			ipv4_list, NULL },
		/*   7 */ { "Log Server",				ipv4_list, NULL },
		/*   8 */ { "Cookie Server",				ipv4_list, NULL },
		/*   9 */ { "LPR Server",				ipv4_list, NULL },
		/*  10 */ { "Impress Server",				ipv4_list, NULL },
		/*  11 */ { "Resource Location Server",			ipv4_list, NULL },
		/*  12 */ { "Host Name",				string, NULL },
		/*  13 */ { "Boot File Size",				val_u_short, NULL },
		/*  14 */ { "Merit Dump File",				string, NULL },
		/*  15 */ { "Domain Name",				string, NULL },
		/*  16 */ { "Swap Server",				ipv4, NULL },
		/*  17 */ { "Root Path",				string, NULL },
		/*  18 */ { "Extensions Path",				string, NULL },
		/*  19 */ { "IP Forwarding",				val_boolean, TFS(&toggle_tfs) },
		/*  20 */ { "Non-Local Source Routing",			val_boolean, TFS(&toggle_tfs) },
		/*  21 */ { "Policy Filter",				special, NULL },
		/*  22 */ { "Maximum Datagram Reassembly Size",		val_u_short, NULL },
		/*  23 */ { "Default IP Time-to-Live",			val_u_byte, NULL },
		/*  24 */ { "Path MTU Aging Timeout",			time_in_secs, NULL },
		/*  25 */ { "Path MTU Plateau Table",			val_u_short_list, NULL },
		/*  26 */ { "Interface MTU",				val_u_short, NULL },
		/*  27 */ { "All Subnets are Local",			val_boolean, TFS(&yes_no_tfs) },
		/*  28 */ { "Broadcast Address",			ipv4, NULL },
		/*  29 */ { "Perform Mask Discovery",			val_boolean, TFS(&toggle_tfs) },
		/*  30 */ { "Mask Supplier",				val_boolean, TFS(&yes_no_tfs) },
		/*  31 */ { "Perform Router Discover",			val_boolean, TFS(&toggle_tfs) },
		/*  32 */ { "Router Solicitation Address",		ipv4, NULL },
		/*  33 */ { "Static Route",				special, NULL },
		/*  34 */ { "Trailer Encapsulation",			val_boolean, TFS(&toggle_tfs) },
		/*  35 */ { "ARP Cache Timeout",			time_in_secs, NULL },
		/*  36 */ { "Ethernet Encapsulation",			val_boolean, TFS(&toggle_tfs) },
		/*  37 */ { "TCP Default TTL", 				val_u_byte, NULL },
		/*  38 */ { "TCP Keepalive Interval",			time_in_secs, NULL },
		/*  39 */ { "TCP Keepalive Garbage",			val_boolean, TFS(&toggle_tfs) },
		/*  40 */ { "Network Information Service Domain",	string, NULL },
		/*  41 */ { "Network Information Service Servers",	ipv4_list, NULL },
		/*  42 */ { "Network Time Protocol Servers",		ipv4_list, NULL },
		/*  43 */ { "Vendor-Specific Information",		special, NULL },
		/*  44 */ { "NetBIOS over TCP/IP Name Server",		ipv4_list, NULL },
		/*  45 */ { "NetBIOS over TCP/IP Datagram Distribution Name Server", ipv4_list, NULL },
		/*  46 */ { "NetBIOS over TCP/IP Node Type",		val_u_byte, VALS(nbnt_vals) },
		/*  47 */ { "NetBIOS over TCP/IP Scope",		string, NULL },
		/*  48 */ { "X Window System Font Server",		ipv4_list, NULL },
		/*  49 */ { "X Window System Display Manager",		ipv4_list, NULL },
		/*  50 */ { "Requested IP Address",			ipv4, NULL },
		/*  51 */ { "IP Address Lease Time",			time_in_secs, NULL },
		/*  52 */ { "Option Overload",				special, NULL },
		/*  53 */ { "DHCP Message Type",			special, NULL },
		/*  54 */ { "Server Identifier",			ipv4, NULL },
		/*  55 */ { "Parameter Request List",			special, NULL },
		/*  56 */ { "Message",					string, NULL },
		/*  57 */ { "Maximum DHCP Message Size",		val_u_short, NULL },
		/*  58 */ { "Renewal Time Value",			time_in_secs, NULL },
		/*  59 */ { "Rebinding Time Value",			time_in_secs, NULL },
		/*  60 */ { "Vendor class identifier",			special, NULL },
		/*  61 */ { "Client identifier",			special, NULL },
		/*  62 */ { "Novell/Netware IP domain",			string, NULL },
		/*  63 */ { "Novell Options",				special, NULL },
		/*  64 */ { "Network Information Service+ Domain",	string, NULL },
		/*  65 */ { "Network Information Service+ Servers",	ipv4_list, NULL },
		/*  66 */ { "TFTP Server Name",				string, NULL },
		/*  67 */ { "Bootfile name",				string, NULL },
		/*  68 */ { "Mobile IP Home Agent",			ipv4_list, NULL },
		/*  69 */ { "SMTP Server",				ipv4_list, NULL },
		/*  70 */ { "POP3 Server",				ipv4_list, NULL },
		/*  71 */ { "NNTP Server",				ipv4_list, NULL },
		/*  72 */ { "Default WWW Server",			ipv4_list, NULL },
		/*  73 */ { "Default Finger Server",			ipv4_list, NULL },
		/*  74 */ { "Default IRC Server",			ipv4_list, NULL },
		/*  75 */ { "StreetTalk Server",			ipv4_list, NULL },
		/*  76 */ { "StreetTalk Directory Assistance Server",	ipv4_list, NULL },
		/*  77 */ { "User Class Information",			opaque, NULL },
		/*  78 */ { "Directory Agent Information",		special, NULL },
		/*  79 */ { "Service Location Agent Scope",		special, NULL },
		/*  80 */ { "Naming Authority",				opaque, NULL },
		/*  81 */ { "Client Fully Qualified Domain Name",	special, NULL },
		/*  82 */ { "Agent Information Option",                 special, NULL },
		/*  83 */ { "Unassigned",				opaque, NULL },
		/*  84 */ { "Unassigned",				opaque, NULL },
		/*  85 */ { "Novell Directory Services Servers",	special, NULL },
		/*  86 */ { "Novell Directory Services Tree Name",	string, NULL },
		/*  87 */ { "Novell Directory Services Context",	string, NULL },
		/*  88 */ { "IEEE 1003.1 POSIX Timezone",		opaque, NULL },
		/*  89 */ { "Fully Qualified Domain Name",		opaque, NULL },
		/*  90 */ { "Authentication",				special, NULL },
		/*  91 */ { "Vines TCP/IP Server Option",		opaque, NULL },
		/*  92 */ { "Server Selection Option",			opaque, NULL },
		/*  93 */ { "Client System Architecture",		opaque, NULL },
		/*  94 */ { "Client Network Device Interface",		opaque, NULL },
		/*  95 */ { "Lightweight Directory Access Protocol",	opaque, NULL },
		/*  96 */ { "IPv6 Transitions",				opaque, NULL },
		/*  97 */ { "UUID/GUID-based Client Identifier",	opaque, NULL },
		/*  98 */ { "Open Group's User Authentication",		opaque, NULL },
		/*  99 */ { "Unassigned",				opaque, NULL },
		/* 100 */ { "Printer Name",				opaque, NULL },
		/* 101 */ { "MDHCP multicast address",			opaque, NULL },
		/* 102 */ { "Removed/unassigned",			opaque, NULL },
		/* 103 */ { "Removed/unassigned",			opaque, NULL },
		/* 104 */ { "Removed/unassigned",			opaque, NULL },
		/* 105 */ { "Removed/unassigned",			opaque, NULL },
		/* 106 */ { "Removed/unassigned",			opaque, NULL },
		/* 107 */ { "Removed/unassigned",			opaque, NULL },
		/* 108 */ { "Swap Path Option",				opaque, NULL },
		/* 109 */ { "Unassigned",				opaque, NULL },
		/* 110 */ { "IPX Compability",				opaque, NULL },
		/* 111 */ { "Unassigned",				opaque, NULL },
		/* 112 */ { "NetInfo Parent Server Address",		ipv4_list, NULL },
		/* 113 */ { "NetInfo Parent Server Tag",		string, NULL },
		/* 114 */ { "URL",					opaque, NULL },
		/* 115 */ { "DHCP Failover Protocol",			opaque, NULL },
		/* 116 */ { "DHCP Auto-Configuration",			opaque, NULL },
		/* 117 */ { "Name Service Search",		       	opaque, NULL },
		/* 118 */ { "Subnet Selection Option",		       	opaque, NULL },
		/* 119 */ { "Domain Search",				opaque, NULL },
		/* 120 */ { "SIP Servers",				opaque, NULL },
		/* 121 */ { "Classless Static Route",		       	opaque, NULL },
		/* 122 */ { "CableLabs Client Configuration",		opaque, NULL },
		/* 123 */ { "Unassigned",				opaque, NULL },
		/* 124 */ { "Unassigned",				opaque, NULL },
		/* 125 */ { "Unassigned",				opaque, NULL },
		/* 126 */ { "Extension",				opaque, NULL },
		/* 127 */ { "Extension",				opaque, NULL },
		/* 128 */ { "Private",					opaque, NULL },
		/* 129 */ { "Private",					opaque, NULL },
		/* 130 */ { "Private",					opaque, NULL },
		/* 131 */ { "Private",					opaque, NULL },
		/* 132 */ { "Private",					opaque, NULL },
		/* 133 */ { "Private",					opaque, NULL },
		/* 134 */ { "Private",					opaque, NULL },
		/* 135 */ { "Private",					opaque, NULL },
		/* 136 */ { "Private",					opaque, NULL },
		/* 137 */ { "Private",					opaque, NULL },
		/* 138 */ { "Private",					opaque, NULL },
		/* 139 */ { "Private",					opaque, NULL },
		/* 140 */ { "Private",					opaque, NULL },
		/* 141 */ { "Private",					opaque, NULL },
		/* 142 */ { "Private",					opaque, NULL },
		/* 143 */ { "Private",					opaque, NULL },
		/* 144 */ { "Private",					opaque, NULL },
		/* 145 */ { "Private",					opaque, NULL },
		/* 146 */ { "Private",					opaque, NULL },
		/* 147 */ { "Private",					opaque, NULL },
		/* 148 */ { "Private",					opaque, NULL },
		/* 149 */ { "Private",					opaque, NULL },
		/* 150 */ { "Private",					opaque, NULL },
		/* 151 */ { "Private",					opaque, NULL },
		/* 152 */ { "Private",					opaque, NULL },
		/* 153 */ { "Private",					opaque, NULL },
		/* 154 */ { "Private",					opaque, NULL },
		/* 155 */ { "Private",					opaque, NULL },
		/* 156 */ { "Private",					opaque, NULL },
		/* 157 */ { "Private",					opaque, NULL },
		/* 158 */ { "Private",					opaque, NULL },
		/* 159 */ { "Private",					opaque, NULL },
		/* 160 */ { "Private",					opaque, NULL },
		/* 161 */ { "Private",					opaque, NULL },
		/* 162 */ { "Private",					opaque, NULL },
		/* 163 */ { "Private",					opaque, NULL },
		/* 164 */ { "Private",					opaque, NULL },
		/* 165 */ { "Private",					opaque, NULL },
		/* 166 */ { "Private",					opaque, NULL },
		/* 167 */ { "Private",					opaque, NULL },
		/* 168 */ { "Private",					opaque, NULL },
		/* 169 */ { "Private",					opaque, NULL },
		/* 170 */ { "Private",					opaque, NULL },
		/* 171 */ { "Private",					opaque, NULL },
		/* 172 */ { "Private",					opaque, NULL },
		/* 173 */ { "Private",					opaque, NULL },
		/* 174 */ { "Private",					opaque, NULL },
		/* 175 */ { "Private",					opaque, NULL },
		/* 176 */ { "Private",					opaque, NULL },
		/* 177 */ { "Private",					opaque, NULL },
		/* 178 */ { "Private",					opaque, NULL },
		/* 179 */ { "Private",					opaque, NULL },
		/* 180 */ { "Private",					opaque, NULL },
		/* 181 */ { "Private",					opaque, NULL },
		/* 182 */ { "Private",					opaque, NULL },
		/* 183 */ { "Private",					opaque, NULL },
		/* 184 */ { "Private",					opaque, NULL },
		/* 185 */ { "Private",					opaque, NULL },
		/* 186 */ { "Private",					opaque, NULL },
		/* 187 */ { "Private",					opaque, NULL },
		/* 188 */ { "Private",					opaque, NULL },
		/* 189 */ { "Private",					opaque, NULL },
		/* 190 */ { "Private",					opaque, NULL },
		/* 191 */ { "Private",					opaque, NULL },
		/* 192 */ { "Private",					opaque, NULL },
		/* 193 */ { "Private",					opaque, NULL },
		/* 194 */ { "Private",					opaque, NULL },
		/* 195 */ { "Private",					opaque, NULL },
		/* 196 */ { "Private",					opaque, NULL },
		/* 197 */ { "Private",					opaque, NULL },
		/* 198 */ { "Private",					opaque, NULL },
		/* 199 */ { "Private",					opaque, NULL },
		/* 200 */ { "Private",					opaque, NULL },
		/* 201 */ { "Private",					opaque, NULL },
		/* 202 */ { "Private",					opaque, NULL },
		/* 203 */ { "Private",					opaque, NULL },
		/* 204 */ { "Private",					opaque, NULL },
		/* 205 */ { "Private",					opaque, NULL },
		/* 206 */ { "Private",					opaque, NULL },
		/* 207 */ { "Private",					opaque, NULL },
		/* 208 */ { "Private",					opaque, NULL },
		/* 209 */ { "Private",					opaque, NULL },
		/* 210 */ { "Authentication",				special, NULL }
	};

	/* Options whose length isn't "optlen + 2". */
	switch (code) {

	case 0:		/* Padding */
		/* check how much padding we have */
		for (i = voff + 1; i < eoff; i++ ) {
			if (tvb_get_guint8(tvb, i) != 0) {
				break;
			}
		}
		i = i - voff;
		if (!first_pass) {
			if (bp_tree != NULL) {
				proto_tree_add_text(bp_tree, tvb, voff, i,
				    "Padding");
			}
		}
		consumed = i;
		return consumed;
		break;

	case 255:	/* End Option */
		if (!first_pass) {
			if (bp_tree != NULL) {
				proto_tree_add_text(bp_tree, tvb, voff, 1,
				    "End Option");
			}
		}
		*at_end = TRUE;
		consumed = 1;
		return consumed;
	}

	/*
	 * Get the length of the option, and the number of bytes it
	 * consumes (the length doesn't include the option code or
	 * length bytes).
	 *
	 * On the first pass, check first whether we have the length
	 * byte, so that we don't throw an exception; if we throw an
	 * exception in the first pass, which is only checking for options
	 * whose values we need in order to properly dissect the packet
	 * on the second pass, we won't actually dissect the options, so
	 * you won't be able to see which option had the problem.
	 */
	if (first_pass) {
		if (!tvb_bytes_exist(tvb, voff+1, 1)) {
			/*
			 * We don't have the length byte; just return 1
			 * as the number of bytes we consumed, to count
			 * the code byte.
			 */
			return 1;
		}
	}
	optlen = tvb_get_guint8(tvb, voff+1);
	consumed = optlen + 2;

	/*
	 * In the first pass, we don't put anything into the protocol
	 * tree; we just check for some options we have to look at
	 * in order to properly process the packet:
	 *
	 *	53 (DHCP message type) - if this is present, this is DHCP
	 *
	 *	60 (Vendor class identifier) - we need this in order to
	 *	   interpret the vendor-specific info
	 *
	 * We also check, before fetching anything, to make sure we
	 * have the entire item we're fetching, so that we don't throw
	 * an exception.
	 */
	if (first_pass) {
		if (tvb_bytes_exist(tvb, voff+2, consumed-2)) {
			switch (code) {

			case 53:
				*dhcp_type_p =
				    get_dhcp_type(tvb_get_guint8(tvb, voff+2));
				break;

			case 60:
				*vendor_class_id_p =
				    tvb_get_ptr(tvb, voff+2, consumed-2);
				break;
			}
		}

		/*
		 * We don't do anything else here.
		 */
		return consumed;
	}

	/*
	 * This is the second pass - if there's a protocol tree to be
	 * built, we put stuff into it, otherwise we just return.
	 */
	if (bp_tree == NULL) {
		/* Don't put anything in the protocol tree. */
		return consumed;
	}

	optoff = voff+2;

	text = opt[code].text;
	/* Special cases */
	switch (code) {

	case 21:	/* Policy Filter */
		if (optlen == 8) {
			/* one IP address pair */
			proto_tree_add_text(bp_tree, tvb, voff, consumed,
				"Option %d: %s = %s/%s", code, text,
				ip_to_str(tvb_get_ptr(tvb, optoff, 4)),
				ip_to_str(tvb_get_ptr(tvb, optoff+4, 4)));
		} else {
			/* > 1 IP address pair. Let's make a sub-tree */
			vti = proto_tree_add_text(bp_tree, tvb, voff,
				consumed, "Option %d: %s", code, text);
			v_tree = proto_item_add_subtree(vti, ett_bootp_option);
			for (i = optoff, optleft = optlen;
			    optleft > 0; i += 8, optleft -= 8) {
				if (optleft < 8) {
					proto_tree_add_text(v_tree, tvb, i, optleft,
					    "Option length isn't a multiple of 8");
					break;
				}
				proto_tree_add_text(v_tree, tvb, i, 8, "IP Address/Mask: %s/%s",
					ip_to_str(tvb_get_ptr(tvb, i, 4)),
					ip_to_str(tvb_get_ptr(tvb, i+4, 4)));
			}
		}
		break;

	case 33:	/* Static Route */
		if (optlen == 8) {
			/* one IP address pair */
			proto_tree_add_text(bp_tree, tvb, voff, consumed,
				"Option %d: %s = %s/%s", code, text,
				ip_to_str(tvb_get_ptr(tvb, optoff, 4)),
				ip_to_str(tvb_get_ptr(tvb, optoff+4, 4)));
		} else {
			/* > 1 IP address pair. Let's make a sub-tree */
			vti = proto_tree_add_text(bp_tree, tvb, voff,
				consumed, "Option %d: %s", code, text);
			v_tree = proto_item_add_subtree(vti, ett_bootp_option);
			for (i = optoff, optleft = optlen; optleft > 0;
			    i += 8, optleft -= 8) {
				if (optleft < 8) {
					proto_tree_add_text(v_tree, tvb, i, optleft,
					    "Option length isn't a multiple of 8");
					break;
				}
				proto_tree_add_text(v_tree, tvb, i, 8,
					"Destination IP Address/Router: %s/%s",
					ip_to_str(tvb_get_ptr(tvb, i, 4)),
					ip_to_str(tvb_get_ptr(tvb, i+4, 4)));
			}
		}
		break;

	case 43:	/* Vendor-Specific Info */
		/* PXE protocol 2.1 as described in the intel specs */
		if (*vendor_class_id_p != NULL &&
		    strncmp(*vendor_class_id_p, "PXEClient", strlen("PXEClient")) == 0) {
			vti = proto_tree_add_text(bp_tree, tvb, voff,
				consumed, "Option %d: %s (PXEClient)", code, text);
			v_tree = proto_item_add_subtree(vti, ett_bootp_option);

			optend = optoff + optlen;
			while (optoff < optend) {
				optoff = dissect_vendor_pxeclient_suboption(v_tree,
					tvb, optoff, optend);
			}
		} else if (*vendor_class_id_p != NULL &&
			   ((strncmp(*vendor_class_id_p, "pktc", strlen("pktc")) == 0) ||
                            (strncmp(*vendor_class_id_p, "docsis", strlen("docsis")) == 0) ||
                            (strncmp(*vendor_class_id_p, "CableHome", strlen("CableHome")) == 0))) {
		        /* CableLabs standard - see www.cablelabs.com/projects */
		        vti = proto_tree_add_text(bp_tree, tvb, voff,
				consumed, "Option %d: %s (CableLabs)", code, text);
			v_tree = proto_item_add_subtree(vti, ett_bootp_option);

			optend = optoff + optlen;
			while (optoff < optend) {
			        optoff = dissect_vendor_cablelabs_suboption(v_tree,
					tvb, optoff, optend);
			}
		} else {
			proto_tree_add_text(bp_tree, tvb, voff, consumed,
				"Option %d: %s (%d bytes)", code, text, optlen);
		}
		break;

	case 52:	/* Option Overload */
		if (optlen < 1) {
			proto_tree_add_text(bp_tree, tvb, voff, consumed,
				"Option %d: length isn't >= 1", code);
			break;
		}
		byte = tvb_get_guint8(tvb, optoff);
		vti = proto_tree_add_text(bp_tree, tvb, voff, consumed,
			"Option %d: %s = %s", code, text,
			val_to_str(byte, opt_overload_vals,
			    "Unknown (0x%02x)"));

		/* Just in case we find an option 52 in sname or file */
		if (voff > VENDOR_INFO_OFFSET && byte >= 1 && byte <= 3) {
			o52tree = proto_item_add_subtree(vti, ett_bootp_option);
			if (byte == 1 || byte == 3) {	/* 'file' */
				vti = proto_tree_add_text (o52tree, tvb,
					FILE_NAME_OFFSET, FILE_NAME_LEN,
					"Boot file name option overload");
				v_tree = proto_item_add_subtree(vti, ett_bootp_option);
				o52voff = FILE_NAME_OFFSET;
				o52eoff = FILE_NAME_OFFSET + FILE_NAME_LEN;
				o52at_end = FALSE;
				while (o52voff < o52eoff && !o52at_end) {
					o52voff += bootp_option(tvb, v_tree, o52voff,
						o52eoff, FALSE, &o52at_end,
						dhcp_type_p, vendor_class_id_p);
				}
			}
			if (byte == 2 || byte == 3) {	/* 'sname' */
				vti = proto_tree_add_text (o52tree, tvb,
					SERVER_NAME_OFFSET, SERVER_NAME_LEN,
					"Server host name option overload");
				v_tree = proto_item_add_subtree(vti, ett_bootp_option);
				o52voff = SERVER_NAME_OFFSET;
				o52eoff = SERVER_NAME_OFFSET + SERVER_NAME_LEN;
				o52at_end = FALSE;
				while (o52voff < o52eoff && !o52at_end) {
					o52voff += bootp_option(tvb, v_tree, o52voff,
						o52eoff, FALSE, &o52at_end,
						dhcp_type_p, vendor_class_id_p);
				}
			}
		}

/*		protocol = tvb_get_guint8(tvb, optoff);
		proto_tree_add_text(v_tree, tvb, optoff, 1, "Protocol: %s (%u)",
				    val_to_str(protocol, authen_protocol_vals, "Unknown"),
				    protocol); */
		break;

	case 53:	/* DHCP Message Type */
		if (optlen != 1) {
			proto_tree_add_text(bp_tree, tvb, voff, consumed,
				"Option %d: length isn't 1", code);
			break;
		}
		proto_tree_add_text(bp_tree, tvb, voff, 3, "Option %d: %s = DHCP %s",
			code, text, get_dhcp_type(tvb_get_guint8(tvb, optoff)));
		break;

	case 55:	/* Parameter Request List */
		vti = proto_tree_add_text(bp_tree, tvb, voff,
			consumed, "Option %d: %s", code, text);
		v_tree = proto_item_add_subtree(vti, ett_bootp_option);
		for (i = 0; i < optlen; i++) {
			byte = tvb_get_guint8(tvb, optoff+i);
			if (byte < array_length(opt)) {
				proto_tree_add_text(v_tree, tvb, optoff+i, 1, "%d = %s",
						byte, opt[byte].text);
			} else {
				proto_tree_add_text(vti, tvb, optoff+i, 1,
					"Unknown Option Code: %d", byte);
			}
		}
		break;

	case 60:	/* Vendor class identifier */
		/*
		 * XXX - RFC 2132 says this is a string of octets;
		 * should we check for non-printables?
		 */
		vti = proto_tree_add_text(bp_tree, tvb, voff, consumed,
			"Option %d: %s = \"%s\"", code, text,
			tvb_format_stringzpad(tvb, optoff, consumed-2));
		if ((tvb_memeql(tvb, optoff, PACKETCABLE_MTA_CAP10, strlen(PACKETCABLE_MTA_CAP10)) == 0) ||
			(tvb_memeql(tvb, optoff, PACKETCABLE_MTA_CAP15, strlen(PACKETCABLE_MTA_CAP10)) == 0)) {
			v_tree = proto_item_add_subtree(vti, ett_bootp_option);
			dissect_packetcable_mta_cap(v_tree, tvb, optoff, optlen);
		} else if (tvb_memeql(tvb, optoff, PACKETCABLE_CM_CAP11, strlen(PACKETCABLE_CM_CAP11)) == 0 ||
				tvb_memeql(tvb, optoff, PACKETCABLE_CM_CAP20, strlen(PACKETCABLE_CM_CAP20)) == 0 ) {
			v_tree = proto_item_add_subtree(vti, ett_bootp_option);
			dissect_docsis_cm_cap(v_tree, tvb, optoff, optlen);
		}
		break;

	case 61:	/* Client Identifier */
		if (optlen > 0)
			byte = tvb_get_guint8(tvb, optoff);
		else
			byte = 0;

		/* We *MAY* use hwtype/hwaddr. If we have 7 bytes, I'll
		   guess that the first is the hwtype, and the last 6
		   are the hw addr */
		/* See http://www.iana.org/assignments/arp-parameters */
		/* RFC2132 9.14 Client-identifier has the following to say:
		   A hardware type of 0 (zero) should be used when the value
		   field contains an identifier other than a hardware address
		   (e.g. a fully qualified domain name). */

		if (optlen == 7 && byte > 0 && byte < 48) {
			vti = proto_tree_add_text(bp_tree, tvb, voff,
				consumed, "Option %d: %s", code, text);
			v_tree = proto_item_add_subtree(vti, ett_bootp_option);
			proto_tree_add_text(v_tree, tvb, optoff, 1,
				"Hardware type: %s",
				arphrdtype_to_str(byte,
					"Unknown (0x%02x)"));
			if (byte == ARPHRD_ETHER || byte == ARPHRD_IEEE802)
				proto_tree_add_item(v_tree,
				    hf_bootp_hw_ether_addr, tvb, optoff+1, 6,
				    FALSE);
			else
				proto_tree_add_text(v_tree, tvb, optoff+1, 6,
					"Client hardware address: %s",
					arphrdaddr_to_str(tvb_get_ptr(tvb, optoff+1, 6),
					6, byte));
		} else {
			/* otherwise, it's opaque data */
			proto_tree_add_text(bp_tree, tvb, voff, consumed,
				"Option %d: %s (%d bytes)", code, text, optlen);
		}
		break;

	case 63:	/* NetWare/IP options (RFC 2242) */
		vti = proto_tree_add_text(bp_tree, tvb, voff,
		    consumed, "Option %d: %s", code, text);
		v_tree = proto_item_add_subtree(vti, ett_bootp_option);

		optend = optoff + optlen;
		while (optoff < optend)
			optoff = dissect_netware_ip_suboption(v_tree, tvb, optoff, optend);
		break;

	case 78:	/* SLP Directory Agent Option RFC2610 Added by Greg Morris (gmorris@novell.com)*/
		if (optlen < 1) {
			proto_tree_add_text(bp_tree, tvb, voff, consumed,
				"Option %d: length isn't >= 1", code);
			break;
		}
		optleft = optlen;
		byte = tvb_get_guint8(tvb, optoff);
		vti = proto_tree_add_text(bp_tree, tvb, voff, consumed,
				"Option %d: %s = %s", code, text,
				val_to_str(byte, slpda_vals,
				    "Unknown (0x%02x)"));
		optoff++;
		optleft--;
		if (byte == 0x80) {
			if (optleft == 0)
				break;
			optoff++;
			optleft--;
		}
		v_tree = proto_item_add_subtree(vti, ett_bootp_option);
		for (i = optoff; optleft > 0; i += 4, optleft -= 4) {
			if (optleft < 4) {
				proto_tree_add_text(v_tree, tvb, i, optleft,
				    "Option length isn't a multiple of 4");
				break;
			}
			proto_tree_add_text(v_tree, tvb, i, 4, "SLPDA Address: %s",
			    ip_to_str(tvb_get_ptr(tvb, i, 4)));
		}
		break;

	case 79:	/* SLP Service Scope Option RFC2610 Added by Greg Morris (gmorris@novell.com)*/
		byte = tvb_get_guint8(tvb, optoff);
		vti = proto_tree_add_text(bp_tree, tvb, voff, consumed,
				"Option %d: %s = %s", code, text,
				val_to_str(byte, slp_scope_vals,
				    "Unknown (0x%02x)"));
		v_tree = proto_item_add_subtree(vti, ett_bootp_option);
		optoff++;
		optleft = optlen - 1;
		proto_tree_add_text(v_tree, tvb, optoff, optleft,
		    "%s = \"%s\"", text,
		    tvb_format_stringzpad(tvb, optoff, optleft));
		break;

	case 81:	/* Client Fully Qualified Domain Name */
		if (optlen < 3) {
			proto_tree_add_text(bp_tree, tvb, voff, consumed,
				"Option %d: length isn't >= 3", code);
			break;
		}
		vti = proto_tree_add_text(bp_tree, tvb, voff, consumed,
				"Option %d: FQDN", code);
		v_tree = proto_item_add_subtree(vti, ett_bootp_option);
		fqdn_flags = tvb_get_guint8(tvb, optoff);
		ft = proto_tree_add_text(v_tree, tvb, optoff, 1, "Flags: 0x%02x", fqdn_flags);
		flags_tree = proto_item_add_subtree(ft, ett_bootp_fqdn);
		proto_tree_add_item(flags_tree, hf_bootp_fqdn_mbz, tvb, optoff, 1, FALSE);
		proto_tree_add_item(flags_tree, hf_bootp_fqdn_n, tvb, optoff, 1, FALSE);
		proto_tree_add_item(flags_tree, hf_bootp_fqdn_e, tvb, optoff, 1, FALSE);
		proto_tree_add_item(flags_tree, hf_bootp_fqdn_o, tvb, optoff, 1, FALSE);
		proto_tree_add_item(flags_tree, hf_bootp_fqdn_s, tvb, optoff, 1, FALSE);
		/* XXX: use code from packet-dns for return code decoding */
		proto_tree_add_item(v_tree, hf_bootp_fqdn_rcode1, tvb, optoff+1, 1, FALSE);
		/* XXX: use code from packet-dns for return code decoding */
		proto_tree_add_item(v_tree, hf_bootp_fqdn_rcode2, tvb, optoff+2, 1, FALSE);
		if (optlen > 3) {
			if (fqdn_flags & F_FQDN_E) {
				/* XXX: use code from packet-dns for binary encoded name */
				proto_tree_add_item(v_tree, hf_bootp_fqdn_name,
				    tvb, optoff+3, optlen-3, FALSE);

			} else {
				proto_tree_add_item(v_tree, hf_bootp_fqdn_asciiname,
				    tvb, optoff+3, optlen-3, FALSE);
			}
		}
		break;

	case 82:        /* Relay Agent Information Option */
		vti = proto_tree_add_text(bp_tree, tvb, voff, consumed,
					  "Option %d: %s (%d bytes)",
					  code, text, optlen);
		v_tree = proto_item_add_subtree(vti, ett_bootp_option);
		optend = optoff + optlen;
		while (optoff < optend)
			optoff = bootp_dhcp_decode_agent_info(v_tree, tvb, optoff, optend);
		break;

	case 85:        /* Novell Servers (RFC 2241) */
		/* Option 85 can be sent as a string */
		/* Added by Greg Morris (gmorris[AT]novell.com) */
		if (novell_string) {
			proto_tree_add_text(bp_tree, tvb, voff, consumed,
			    "Option %d: %s = \"%s\"", code, text,
			    tvb_format_stringzpad(tvb, optoff, optlen));
		} else {
			if (optlen == 4) {
				/* one IP address */
				proto_tree_add_text(bp_tree, tvb, voff, consumed,
					"Option %d: %s = %s", code, text,
					ip_to_str(tvb_get_ptr(tvb, optoff, 4)));
			} else {
				/* > 1 IP addresses. Let's make a sub-tree */
				vti = proto_tree_add_text(bp_tree, tvb, voff,
					consumed, "Option %d: %s", code, text);
				v_tree = proto_item_add_subtree(vti, ett_bootp_option);
				for (i = optoff, optleft = optlen; optleft > 0;
				    i += 4, optleft -= 4) {
					if (optleft < 4) {
						proto_tree_add_text(v_tree, tvb, i, optleft,
						    "Option length isn't a multiple of 4");
						break;
					}
					proto_tree_add_text(v_tree, tvb, i, 4, "IP Address: %s",
						ip_to_str(tvb_get_ptr(tvb, i, 4)));
				}
			}
        	}
	        break;

	case 90:	/* DHCP Authentication */
	case 210:	/* Was this used for authentication at one time? */
		if (optlen < 11) {
			proto_tree_add_text(bp_tree, tvb, voff, consumed,
				"Option %d: length isn't >= 11", code);
			break;
		}
		vti = proto_tree_add_text(bp_tree, tvb, voff,
			consumed, "Option %d: %s", code, text);
		v_tree = proto_item_add_subtree(vti, ett_bootp_option);

		optleft = optlen;
		protocol = tvb_get_guint8(tvb, optoff);
		proto_tree_add_text(v_tree, tvb, optoff, 1, "Protocol: %s (%u)",
				    val_to_str(protocol, authen_protocol_vals, "Unknown"),
				    protocol);
		optoff++;
		optleft--;

		algorithm = tvb_get_guint8(tvb, optoff);
		switch (protocol) {

		case AUTHEN_PROTO_DELAYED_AUTHEN:
			proto_tree_add_text(v_tree, tvb, optoff, 1,
				    "Algorithm: %s (%u)",
				    val_to_str(algorithm, authen_da_algo_vals, "Unknown"),
				    algorithm);
			break;

		default:
			proto_tree_add_text(v_tree, tvb, optoff, 1,
				    "Algorithm: %u", algorithm);
			break;
		}
		optoff++;
		optleft--;

		rdm = tvb_get_guint8(tvb, optoff);
		proto_tree_add_text(v_tree, tvb, optoff, 1,
				    "Replay Detection Method: %s (%u)",
				    val_to_str(rdm, authen_rdm_vals, "Unknown"),
				    rdm);
		optoff++;
		optleft--;

		switch (rdm) {

		case AUTHEN_RDM_MONOTONIC_COUNTER:
			proto_tree_add_text(v_tree, tvb, optoff, 8,
				    "Replay Detection Value: %" PRIx64,
				    tvb_get_ntoh64(tvb, optoff));
			break;

		default:
			proto_tree_add_text(v_tree, tvb, optoff, 8,
				    "Replay Detection Value: %s",
				    tvb_bytes_to_str(tvb, optoff, 8));
			break;
		}
		optoff += 8;
		optleft -= 8;

		switch (protocol) {

		case AUTHEN_PROTO_DELAYED_AUTHEN:
			switch (algorithm) {

			case AUTHEN_DELAYED_ALGO_HMAC_MD5:
				if (optlen < 31) {
					proto_tree_add_text(bp_tree, tvb, 0, 0,
						"Option %d: length isn't >= 31", code);
					break;
				}
				proto_tree_add_text(v_tree, tvb, optoff, 4,
					"Secret ID: 0x%08x",
					tvb_get_ntohl(tvb, optoff));
				optoff += 4;
				optleft -= 4;
				proto_tree_add_text(v_tree, tvb, optoff, 16,
					"HMAC MD5 Hash: %s",
					tvb_bytes_to_str(tvb, optoff, 16));
				break;

			default:
				if (optleft == 0)
					break;
				proto_tree_add_text(v_tree, tvb, optoff, optleft,
					"Authentication Information: %s",
					tvb_bytes_to_str(tvb, optoff, optleft));
				break;
			}
			break;

		default:
			if (optleft == 0)
				break;
			proto_tree_add_text(v_tree, tvb, optoff, optleft,
				"Authentication Information: %s",
				tvb_bytes_to_str(tvb, optoff, optleft));
			break;
		}
		break;

	default:	/* not special */
		/* The PacketCable CCC option number can vary.  If this is a CCC option,
		   handle it and skip the "opaque" case below.
		 */
		if (code == pkt_ccc_option) {
			skip_opaque = TRUE;
			vti = proto_tree_add_text(bp_tree, tvb, voff, consumed,
						  "Option %d: CableLabs Client Configuration (%d bytes)",
						  code, optlen);
			v_tree = proto_item_add_subtree(vti, ett_bootp_option);
			optend = optoff + optlen;
			while (optoff < optend) {
				switch (pkt_ccc_protocol_version) {
					case PACKETCABLE_CCC_I05:
						optoff = dissect_packetcable_i05_ccc(v_tree, tvb, optoff, optend);
						break;
					case PACKETCABLE_CCC_DRAFT5:
					case PACKETCABLE_CCC_RFC_3495:
						optoff = dissect_packetcable_ietf_ccc(v_tree, tvb, optoff, optend, pkt_ccc_protocol_version);
						break;
					default: /* XXX Should we do something here? */
						break;
				}
			}
		}

		break;
	}

	/* Normal cases */
	if (code < array_length(opt)) {
		text = opt[code].text;
		ftype = opt[code].ftype;

		if (ftype == special)
			return consumed;
		if (ftype == opaque) {
			if (skip_opaque) /* Currently used by PacketCable CCC */
				return consumed;
		}

		vti = proto_tree_add_text(bp_tree, tvb, voff, consumed,
		    "Option %d: %s", code, text);
		switch (ftype) {

		case ipv4:
			if (optlen != 4) {
				proto_item_append_text(vti,
				    " - length isn't 4");
				break;
			}
			proto_item_append_text(vti, " = %s",
				ip_to_str(tvb_get_ptr(tvb, optoff, 4)));
			break;

		case ipv4_list:
			if (optlen == 4) {
				/* one IP address */
				proto_item_append_text(vti, " = %s",
					ip_to_str(tvb_get_ptr(tvb, optoff, 4)));
			} else {
				/* > 1 IP addresses. Let's make a sub-tree */
				v_tree = proto_item_add_subtree(vti, ett_bootp_option);
				for (i = optoff, optleft = optlen; optleft > 0;
				    i += 4, optleft -= 4) {
					if (optleft < 4) {
						proto_tree_add_text(v_tree, tvb, i, voff + consumed - i,
						    "Option length isn't a multiple of 4");
						break;
					}
					proto_tree_add_text(v_tree, tvb, i, 4, "IP Address: %s",
						ip_to_str(tvb_get_ptr(tvb, i, 4)));
				}
			}
			break;

		case string:
			/* Fix for non null-terminated string supplied by
			 * John Lines <John.Lines[AT]aeat.co.uk>
			 */
			proto_item_append_text(vti, " = \"%s\"",
					tvb_format_stringzpad(tvb, optoff, consumed-2));
			break;

		case opaque:
			proto_item_append_text(vti, " (%d bytes)", optlen);
			break;

		case val_boolean:
			if (optlen != 1) {
				proto_item_append_text(vti,
				    " - length isn't 1");
				break;
			}
			tfs = (const struct true_false_string *) opt[code].data;
			i = tvb_get_guint8(tvb, optoff);
			if (i != 0 && i != 1) {
				proto_item_append_text(vti,
				    " = Invalid Value %d", i);
			} else {
				proto_item_append_text(vti, " = %s",
				    i == 0 ? tfs->false_string : tfs->true_string);
			}
			break;

		case val_u_byte:
			if (optlen != 1) {
				proto_item_append_text(vti,
				    " - length isn't 1");
				break;
			}
			vs = (const value_string *) opt[code].data;
			byte = tvb_get_guint8(tvb, optoff);
			if (vs != NULL) {
				proto_item_append_text(vti, " = %s",
				    val_to_str(byte, vs, "Unknown (%u)"));
			} else
				proto_item_append_text(vti, " = %u", byte);
			break;

		case val_u_short:
			if (optlen != 2) {
				proto_item_append_text(vti,
				    " - length isn't 2");
				break;
			}
			proto_item_append_text(vti, " = %u",
			    tvb_get_ntohs(tvb, optoff));
			break;

		case val_u_short_list:
			if (optlen == 2) {
				/* one gushort */
				proto_item_append_text(vti, " = %u",
				    tvb_get_ntohs(tvb, optoff));
			} else {
				/* > 1 gushort */
				v_tree = proto_item_add_subtree(vti, ett_bootp_option);
				for (i = optoff, optleft = optlen; optleft > 0;
				    i += 2, optleft -= 2) {
					if (optleft < 2) {
						proto_tree_add_text(v_tree, tvb, i, voff + consumed - i,
						    "Option length isn't a multiple of 2");
						break;
					}
					proto_tree_add_text(v_tree, tvb, i, 4, "Value: %u",
						tvb_get_ntohs(tvb, i));
				}
			}
			break;

		case val_u_long:
			if (optlen != 4) {
				proto_item_append_text(vti,
				    " - length isn't 4");
				break;
			}
			proto_item_append_text(vti, " = %u",
			    tvb_get_ntohl(tvb, optoff));
			break;

		case time_in_secs:
			if (optlen != 4) {
				proto_item_append_text(vti,
				    " - length isn't 4");
				break;
			}
			time_secs = tvb_get_ntohl(tvb, optoff);
			proto_item_append_text(vti, " = %s",
			    ((time_secs == 0xffffffff) ?
			      "infinity" :
			      time_secs_to_str(time_secs)));
			break;

		default:
			proto_item_append_text(vti, " (%d bytes)", optlen);
			break;
		}
	} else {
		proto_tree_add_text(bp_tree, tvb, voff, consumed,
				"Unknown Option Code: %d (%d bytes)", code, optlen);
	}

	return consumed;
}

static int
bootp_dhcp_decode_agent_info(proto_tree *v_tree, tvbuff_t *tvb, int optoff,
    int optend)
{
	int suboptoff = optoff;
	guint8 subopt;
	guint8 subopt_len;

	subopt = tvb_get_guint8(tvb, optoff);
	suboptoff++;

	if (suboptoff >= optend) {
		proto_tree_add_text(v_tree, tvb, optoff, 1,
			"Suboption %d: no room left in option for suboption length",
	 		subopt);
	 	return (optend);
	}
	subopt_len = tvb_get_guint8(tvb, suboptoff);
	suboptoff++;

	if (suboptoff+subopt_len > optend) {
		proto_tree_add_text(v_tree, tvb, optoff, optend-optoff,
			"Suboption %d: no room left in option for suboption value",
	 		subopt);
	 	return (optend);
	}
	switch (subopt) {
	case 1:
		proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,
				    "Agent Circuit ID: %s",
				    tvb_bytes_to_str(tvb, suboptoff, subopt_len));
		break;
	case 2:
		proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,
				    "Agent Remote ID: %s",
				    tvb_bytes_to_str(tvb, suboptoff, subopt_len));
		break;
	default:
		proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,
				    "Invalid agent suboption %d (%d bytes)",
				    subopt, subopt_len);
		break;
	}
	optoff += (subopt_len + 2);
	return optoff;
}

static int
dissect_vendor_pxeclient_suboption(proto_tree *v_tree, tvbuff_t *tvb,
    int optoff, int optend)
{
	int suboptoff = optoff;
	guint8 subopt;
	guint8 subopt_len;
	int suboptleft;
	proto_tree *o43pxeclient_v_tree;
	proto_item *vti;

	static struct opt_info o43pxeclient_opt[]= {
		/* 0 */ {"nop", special, NULL},	/* dummy */
		/* 1 */ {"PXE mtftp IP", ipv4_list, NULL},
		/* 2 */ {"PXE mtftp client port", val_u_le_short, NULL},
		/* 3 */ {"PXE mtftp server port",val_u_le_short, NULL},
		/* 4 */ {"PXE mtftp timeout", val_u_byte, NULL},
		/* 5 */ {"PXE mtftp delay", val_u_byte, NULL},
		/* 6 */ {"PXE discovery control", val_u_byte, NULL},
			/*
			 * Correct: b0 (lsb): disable broadcast discovery
			 *	b1: disable multicast discovery
			 *	b2: only use/accept servers in boot servers
			 *	b3: download bootfile without prompt/menu/disc
			 */
		/* 7 */ {"PXE multicast address", ipv4_list, NULL},
		/* 8 */ {"PXE boot servers", special, NULL},
		/* 9 */ {"PXE boot menu", special, NULL},
		/* 10 */ {"PXE menu prompt", special, NULL},
		/* 11 */ {"PXE multicast address alloc", special, NULL},
		/* 12 */ {"PXE credential types", special, NULL},
		/* 71 {"PXE boot item", special, NULL}, */
		/* 255 {"PXE end options", special, NULL} */
	};

	subopt = tvb_get_guint8(tvb, suboptoff);
	suboptoff++;

	if (subopt == 0) {
		proto_tree_add_text(v_tree, tvb, optoff, 1, "Padding");
                return (suboptoff);
	} else if (subopt == 255) {	/* End Option */
		proto_tree_add_text(v_tree, tvb, optoff, 1, "End PXEClient option");
		/* Make sure we skip any junk left this option */
		return (optend);
	}

	if (suboptoff >= optend) {
		proto_tree_add_text(v_tree, tvb, optoff, 1,
			"Suboption %d: no room left in option for suboption length",
	 		subopt);
	 	return (optend);
	}
	subopt_len = tvb_get_guint8(tvb, suboptoff);
	suboptoff++;

	if (suboptoff+subopt_len > optend) {
		proto_tree_add_text(v_tree, tvb, optoff, optend-optoff,
			"Suboption %d: no room left in option for suboption value",
	 		subopt);
	 	return (optend);
	}
	if ( subopt == 71 ) {	/* 71 {"PXE boot item", special} */
		/* case special */
		/* I may need to decode that properly one day */
		proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
			"Suboption %d: %s (%d byte%s)" ,
	 		subopt, "PXE boot item",
			subopt_len, plurality(subopt_len, "", "s"));
	} else if ((subopt < 1) || (subopt >= array_length(o43pxeclient_opt))) {
		proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
			"Unknown suboption %d (%d byte%s)", subopt, subopt_len,
			plurality(subopt_len, "", "s"));
	} else {
		switch (o43pxeclient_opt[subopt].ftype) {

		case special:
			/* I may need to decode that properly one day */
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
				"Suboption %d: %s (%d byte%s)",
		 		subopt, o43pxeclient_opt[subopt].text,
				subopt_len, plurality(subopt_len, "", "s"));
			break;

		case ipv4_list:
			if (subopt_len == 4) {
				/* one IP address */
				proto_tree_add_text(v_tree, tvb, optoff, 6,
				    "Suboption %d : %s = %s",
				    subopt, o43pxeclient_opt[subopt].text,
				    ip_to_str(tvb_get_ptr(tvb, suboptoff, 4)));
			} else {
				/* > 1 IP addresses. Let's make a sub-tree */
				vti = proto_tree_add_text(v_tree, tvb, optoff,
				    subopt_len+2, "Suboption %d: %s",
				    subopt, o43pxeclient_opt[subopt].text);
				o43pxeclient_v_tree = proto_item_add_subtree(vti, ett_bootp_option);
				for (suboptleft = subopt_len; suboptleft > 0;
				    suboptoff += 4, suboptleft -= 4) {
					if (suboptleft < 4) {
						proto_tree_add_text(o43pxeclient_v_tree,
						    tvb, suboptoff, suboptleft,
						    "Suboption length isn't a multiple of 4");
						break;
					}
					proto_tree_add_text(o43pxeclient_v_tree,
					    tvb, suboptoff, 4, "IP Address: %s",
					    ip_to_str(tvb_get_ptr(tvb, suboptoff, 4)));
				}
			}
			break;

/* XXX		case string:
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
				"Suboption %d: %s", subopt, o43pxeclient_opt[subopt].text);
			break;
   XXX */

		case val_u_byte:
			if (subopt_len != 1) {
				proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
					"Suboption %d: suboption length isn't 1", subopt);
				break;
			}
			proto_tree_add_text(v_tree, tvb, optoff, 3, "Suboption %d: %s = %u",
			    subopt, o43pxeclient_opt[subopt].text,
			    tvb_get_guint8(tvb, suboptoff));
			break;

		case val_u_le_short:
			if (subopt_len != 2) {
				proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
					"Suboption %d: suboption length isn't 2", subopt);
				break;
			}
			proto_tree_add_text(v_tree, tvb, optoff, 4, "Suboption %d: %s = %u",
			    subopt, o43pxeclient_opt[subopt].text,
			    tvb_get_letohs(tvb, suboptoff));
			break;

		default:
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,"ERROR, please report: Unknown subopt type handler %d", subopt);
			break;
		}
	}
	optoff += (subopt_len + 2);
	return optoff;
}


static int
dissect_vendor_cablelabs_suboption(proto_tree *v_tree, tvbuff_t *tvb,
    int optoff, int optend)
{
	int suboptoff = optoff;
	guint8 subopt, byte_val;
	guint8 subopt_len;

	static struct opt_info o43cablelabs_opt[]= {
		/* 0 */ {"nop", special, NULL},	/* dummy */
		/* 1 */ {"Suboption Request List", string, NULL},
		/* 2 */ {"Device Type", string, NULL},
		/* 3 */ {"eSAFE Types", string, NULL},
		/* 4 */ {"Serial Number", string, NULL},
		/* 5 */ {"Hardware Version", string, NULL},
		/* 6 */ {"Software Version", string, NULL},
		/* 7 */ {"Boot ROM version", string, NULL},
		/* 8 */ {"Organizationally Unique Identifier", special, NULL},
		/* 9 */ {"Model Number", string, NULL},
		/* 10 */ {"Vendor Name", string, NULL},
		/* *** 11-30: CableHome *** */
		/* 11 */ {"Address Realm", special, NULL},
		/* 12 */ {"CM/PS System Description", string, NULL},
		/* 13 */ {"CM/PS Firmware Revision", string, NULL},
		/* 14 */ {"Firewall Policy File Version", string, NULL},
		/* 15 */ {"Unassigned (CableHome)", special, NULL},
		/* 16 */ {"Unassigned (CableHome)", special, NULL},
		/* 17 */ {"Unassigned (CableHome)", special, NULL},
		/* 18 */ {"Unassigned (CableHome)", special, NULL},
		/* 19 */ {"Unassigned (CableHome)", special, NULL},
		/* 20 */ {"Unassigned (CableHome)", special, NULL},
		/* 21 */ {"Unassigned (CableHome)", special, NULL},
		/* 22 */ {"Unassigned (CableHome)", special, NULL},
		/* 23 */ {"Unassigned (CableHome)", special, NULL},
		/* 24 */ {"Unassigned (CableHome)", special, NULL},
		/* 25 */ {"Unassigned (CableHome)", special, NULL},
		/* 26 */ {"Unassigned (CableHome)", special, NULL},
		/* 27 */ {"Unassigned (CableHome)", special, NULL},
		/* 28 */ {"Unassigned (CableHome)", special, NULL},
		/* 29 */ {"Unassigned (CableHome)", special, NULL},
		/* 30 */ {"Unassigned (CableHome)", special, NULL},
		/* *** 31-50: PacketCable *** */
		/* 31 */ {"MTA MAC Address", special, NULL},
		/* 32 */ {"Correlation ID", val_u_long, NULL},
		/* 33-50 {"Unassigned (PacketCable)", special, NULL}, */
		/* *** 51-127: CableLabs *** */
		/* 51-127 {"Unassigned (CableLabs)", special, NULL}, */
		/* *** 128-254: Vendors *** */
		/* 128-254 {"Unassigned (Vendors)", special, NULL}, */
		/* 255 {"end options", special, NULL} */
	};

	static const value_string cablehome_subopt11_vals[] = {
		{ 1, "PS WAN-Man" },
		{ 2, "PS WAN-Data" },
		{ 0, NULL }
	};

	subopt = tvb_get_guint8(tvb, suboptoff);
	suboptoff++;

	if (subopt == 0) {
		proto_tree_add_text(v_tree, tvb, optoff, 1, "Padding");
                return (suboptoff);
	} else if (subopt == 255) {	/* End Option */
		proto_tree_add_text(v_tree, tvb, optoff, 1, "End CableLabs option");
		/* Make sure we skip any junk left this option */
		return (optend);
	}

	if (suboptoff >= optend) {
		proto_tree_add_text(v_tree, tvb, optoff, 1,
			"Suboption %d: no room left in option for suboption length",
	 		subopt);
	 	return (optend);
	}
	subopt_len = tvb_get_guint8(tvb, suboptoff);
	suboptoff++;

	if (suboptoff+subopt_len > optend) {
		proto_tree_add_text(v_tree, tvb, optoff, optend-optoff,
			"Suboption %d: no room left in option for suboption value",
	 		subopt);
	 	return (optend);
	}
	if ( (subopt < 1 ) || (subopt >= array_length(o43cablelabs_opt)) ) {
		proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
			"Suboption %d: Unassigned (%d byte%s)", subopt, subopt_len,
			plurality(subopt_len, "", "s"));
	} else {
		switch (o43cablelabs_opt[subopt].ftype) {

		case special:
			if ( subopt == 8 ) {	/* OUI */
				if (subopt_len != 3) {
					proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
						"Suboption %d: suboption length isn't 3", subopt);
					break;
				}
				proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
					"Suboption %d: OUI = %s",
					subopt, bytes_to_str_punct(tvb_get_ptr(tvb, suboptoff, 3), 3, ':'));
			} else if ( subopt == 11 ) { /* Address Realm */
				if (subopt_len != 1) {
					proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
						"Suboption %d: suboption length isn't 1", subopt);
					break;
				}
				byte_val = tvb_get_guint8(tvb, suboptoff);
				proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
					"Suboption %d: %s = %s (0x%02x)",
					subopt, o43cablelabs_opt[subopt].text,
					val_to_str(byte_val, cablehome_subopt11_vals, "Unknown"), byte_val);
			} else if ( subopt == 31 ) { /* MTA MAC address */
				if (subopt_len != 6) {
					proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
						"Suboption %d: suboption length isn't 6", subopt);
					break;
				}
				proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
					"Suboption %d: %s = %s",
					subopt,  o43cablelabs_opt[subopt].text,
					bytes_to_str_punct(tvb_get_ptr(tvb, suboptoff, 6), 6, ':'));
			} else {
				proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
					"Suboption %d: %s (%d byte%s)" ,
					subopt, o43cablelabs_opt[subopt].text,
					subopt_len, plurality(subopt_len, "", "s"));
			}
			break;

		case string:
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
				"Suboption %d: %s = \"%s\"", subopt,
				o43cablelabs_opt[subopt].text,
				tvb_format_stringzpad(tvb, suboptoff, subopt_len));
			break;

		case bytes:
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
				"Suboption %d: %s = 0x%s", subopt,
				o43cablelabs_opt[subopt].text,
				tvb_bytes_to_str(tvb, suboptoff, subopt_len));
			break;

		case val_u_long:
			if (subopt_len != 4) {
				proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
					"Suboption %d: suboption length isn't 4", subopt);
				break;
			}
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
				"Suboption %d: %s = %u", subopt,
				o43cablelabs_opt[subopt].text,
				tvb_get_ntohl(tvb, suboptoff));
			break;

		default:
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,"ERROR, please report: Unknown subopt type handler %d", subopt);
			break;
		}
	}
	optoff += (subopt_len + 2);
	return optoff;
}



static int
dissect_netware_ip_suboption(proto_tree *v_tree, tvbuff_t *tvb,
    int optoff, int optend)
{
	int suboptoff = optoff;
	guint8 subopt;
	guint8 subopt_len;
	int suboptleft;
	const struct true_false_string *tfs;
	int i;
	proto_tree *o63_v_tree;
	proto_item *vti;

	static struct opt_info o63_opt[]= {
		/* 0 */ {"",none,NULL},
		/* 1 */ {"NWIP does not exist on subnet",presence,NULL},
		/* 2 */ {"NWIP exist in options area",presence,NULL},
		/* 3 */ {"NWIP exists in sname/file",presence,NULL},
		/* 4 */ {"NWIP exists,but too big",presence,NULL},
		/* 5 */ {"Broadcast for nearest Netware server",val_boolean,TFS(&yes_no_tfs)},
		/* 6 */ {"Preferred DSS server",ipv4_list,NULL},
		/* 7 */ {"Nearest NWIP server",ipv4_list,NULL},
		/* 8 */ {"Autoretries",val_u_byte,NULL},
		/* 9 */ {"Autoretry delay,secs",val_u_byte,NULL},
		/* 10*/ {"Support NetWare/IP v1.1",val_boolean,TFS(&yes_no_tfs)},
		/* 11*/ {"Primary DSS",ipv4,NULL}
	};

	subopt = tvb_get_guint8(tvb, optoff);
	suboptoff++;

	if (suboptoff >= optend) {
		proto_tree_add_text(v_tree, tvb, optoff, 1,
			"Suboption %d: no room left in option for suboption length",
	 		subopt);
	 	return (optend);
	}
	subopt_len = tvb_get_guint8(tvb, suboptoff);
	suboptoff++;

	if (subopt >= array_length(o63_opt)) {
		proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2, "Unknown suboption %d", subopt);
	} else {
		switch (o63_opt[subopt].ftype) {

		case presence:
			if (subopt_len != 0) {
				proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,
					"Suboption %d: length isn't 0", subopt);
				suboptoff += subopt_len;
				break;
			}
			proto_tree_add_text(v_tree, tvb, optoff, 2, "Suboption %d: %s", subopt, o63_opt[subopt].text);
			break;

		case ipv4:
			if (subopt_len != 4) {
				proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,
					"Suboption %d: length isn't 4", subopt);
				suboptoff += subopt_len;
				break;
			}
			if (suboptoff+4 > optend) {
				proto_tree_add_text(v_tree, tvb, optoff, optend-optoff,
				    "Suboption %d: no room left in option for suboption value",
				    subopt);
			 	return (optend);
			}
			proto_tree_add_text(v_tree, tvb, optoff, 6,
			    "Suboption %d: %s = %s" ,
			    subopt, o63_opt[subopt].text,
			    ip_to_str(tvb_get_ptr(tvb, suboptoff, 4)));
			suboptoff += 6;
			break;

		case ipv4_list:
			if (subopt_len == 4) {
				/* one IP address */
				proto_tree_add_text(v_tree, tvb, optoff, 6,
				    "Suboption %d : %s = %s",
				    subopt, o63_opt[subopt].text,
				    ip_to_str(tvb_get_ptr(tvb, suboptoff, 4)));
				suboptoff += 4;
			} else {
				/* > 1 IP addresses. Let's make a sub-tree */
				vti = proto_tree_add_text(v_tree, tvb, optoff,
				    subopt_len+2, "Suboption %d: %s",
				    subopt, o63_opt[subopt].text);
				o63_v_tree = proto_item_add_subtree(vti, ett_bootp_option);
				for (suboptleft = subopt_len; suboptleft > 0;
				    suboptoff += 4, suboptleft -= 4) {
					if (suboptleft < 4) {
						proto_tree_add_text(o63_v_tree,
						    tvb, suboptoff, suboptleft,
						    "Suboption length isn't a multiple of 4");
						suboptoff += suboptleft;
						break;
					}
					proto_tree_add_text(o63_v_tree, tvb, suboptoff, 4, "IP Address: %s",
					    ip_to_str(tvb_get_ptr(tvb, suboptoff, 4)));
				}
			}
			break;

		case val_boolean:
			if (subopt_len != 1) {
				proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,
					"Suboption %d: length isn't 1", subopt);
				suboptoff += subopt_len;
				break;
			}
			if (suboptoff+1 > optend) {
				proto_tree_add_text(v_tree, tvb, optoff, optend-optoff,
				    "Suboption %d: no room left in option for suboption value",
				    subopt);
			 	return (optend);
			}
			tfs = (const struct true_false_string *) o63_opt[subopt].data;
			i = tvb_get_guint8(tvb, suboptoff);
			if (i != 0 && i != 1) {
				proto_tree_add_text(v_tree, tvb, optoff, 3,
				    "Subption %d: %s = Invalid Value %d",
				    subopt, o63_opt[subopt].text, i);
			} else {
				proto_tree_add_text(v_tree, tvb, optoff, 3,
				    "Subption %d: %s = %s", subopt,
				    o63_opt[subopt].text,
				    i == 0 ? tfs->false_string : tfs->true_string);
			}
			suboptoff += 3;
			break;

		case val_u_byte:
			if (subopt_len != 1) {
				proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,
					"Suboption %d: length isn't 1", subopt);
				suboptoff += subopt_len;
				break;
			}
			if (suboptoff+1 > optend) {
				proto_tree_add_text(v_tree, tvb, optoff, optend-optoff,
				    "Suboption %d: no room left in option for suboption value",
				    subopt);
			 	return (optend);
			}
			proto_tree_add_text(v_tree, tvb, optoff, 3, "Suboption %d: %s = %u",
			    subopt, o63_opt[subopt].text,
			    tvb_get_guint8(tvb, suboptoff));
			suboptoff += 1;
			break;

		default:
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,"Unknown suboption %d", subopt);
			suboptoff += subopt_len;
			break;
		}
	}
	return suboptoff;
}


/* PacketCable Multimedia Terminal Adapter device capabilities (option 60).
   Ref: PKT-SP-I05-021127 sections 8.2 and 10 */

#define PKT_MDC_TLV_OFF 10


/* These are ASCII-encoded hexadecimal digits.  We use the raw hex equivalent for
   convenience. */
#define PKT_MDC_VERSION			0x3031  /* "01" */
#define PKT_MDC_TEL_END			0x3032  /* "02" */
#define PKT_MDC_TGT			0x3033  /* "03" */
#define PKT_MDC_HTTP_ACC		0x3034  /* "04" */
#define PKT_MDC_SYSLOG			0x3035  /* "05" */
#define PKT_MDC_NCS			0x3036  /* "06" */
#define PKT_MDC_PRI_LINE		0x3037  /* "07" */
#define PKT_MDC_VENDOR_TLV		0x3038  /* "08" */
#define PKT_MDC_NVRAM_STOR		0x3039  /* "09" */
#define PKT_MDC_PROV_REP		0x3041  /* "0A" */
#define PKT_MDC_PROV_REP_LC		0x3061  /* "0A" */
#define PKT_MDC_SUPP_CODECS		0x3042  /* "0B" */
#define PKT_MDC_SUPP_CODECS_LC		0x3062  /* "0b" */
#define PKT_MDC_SILENCE			0x3043  /* "0C" */
#define PKT_MDC_SILENCE_LC		0x3063  /* "0c" */
#define PKT_MDC_ECHO_CANCEL		0x3044  /* "0D" */
#define PKT_MDC_ECHO_CANCEL_LC		0x3064  /* "0d" */
#define PKT_MDC_RSVP			0x3045  /* "0E" */
#define PKT_MDC_RSVP_LC			0x3065  /* "0e" */
#define PKT_MDC_UGS_AD			0x3046  /* "0F" */
#define PKT_MDC_UGS_AD_LC		0x3066  /* "0f" */
#define PKT_MDC_IF_INDEX		0x3130  /* "10" */
#define PKT_MDC_FLOW_LOG		0x3131  /* "11" */
#define PKT_MDC_PROV_FLOWS		0x3132	/* "12" */
/* PacketCable 1.5: */
#define PKT_MDC_T38_VERSION		0x3133	/* "13" */
#define	PKT_MDC_T38_EC			0x3134	/* "14" */
#define	PKT_MDC_RFC2833_DTMF		0x3135	/* "15" */
#define PKT_MDC_VOICE_METRICS		0x3136	/* "16" */
#define	PKT_MDC_MIBS			0x3137	/* "17" */
#define	PKT_MDC_MGPI			0x3138	/* "18" */

static const value_string pkt_mdc_type_vals[] = {
	{ PKT_MDC_VERSION,		"PacketCable Version" },
	{ PKT_MDC_TEL_END,		"Number Of Telephony Endpoints" },
	{ PKT_MDC_TGT,			"TGT Support" },
	{ PKT_MDC_HTTP_ACC,		"HTTP Download File Access Method Support" },
	{ PKT_MDC_SYSLOG,		"MTA-24 Event SYSLOG Notification Support" },
	{ PKT_MDC_NCS,			"NCS Service Flow Support" },
	{ PKT_MDC_PRI_LINE,		"Primary Line Support" },
	{ PKT_MDC_VENDOR_TLV,		"Vendor Specific TLV Type(s)" },
	{ PKT_MDC_NVRAM_STOR,		"NVRAM Ticket/Session Keys Storage Support" },
	{ PKT_MDC_PROV_REP,		"Provisioning Event Reporting Support" },
	{ PKT_MDC_PROV_REP_LC,		"Provisioning Event Reporting Support" },
	{ PKT_MDC_SUPP_CODECS,		"Supported CODEC(s)" },
	{ PKT_MDC_SUPP_CODECS_LC,	"Supported CODEC(s)" },
	{ PKT_MDC_SILENCE,		"Silence Suppression Support" },
	{ PKT_MDC_SILENCE_LC,		"Silence Suppression Support" },
	{ PKT_MDC_ECHO_CANCEL,		"Echo Cancellation Support" },
	{ PKT_MDC_ECHO_CANCEL_LC,	"Echo Cancellation Support" },
	{ PKT_MDC_RSVP,			"RSVP Support/ Reserved" },
	{ PKT_MDC_RSVP_LC,		"RSVP Support/ Reserved" },
	{ PKT_MDC_UGS_AD,		"UGS-AD Support" },
	{ PKT_MDC_UGS_AD_LC,		"UGS-AD Support" },
	{ PKT_MDC_IF_INDEX,		"MTA's \"ifIndex\" starting number in \"ifTable\"" },
	{ PKT_MDC_FLOW_LOG,		"Provisioning Flow Logging Support" },
	{ PKT_MDC_PROV_FLOWS,		"Supported Provisioning Flows" },
	/* PacketCable 1.5: */
	{ PKT_MDC_T38_VERSION,		"T38 Version Support" },
	{ PKT_MDC_T38_EC,		"T38 Error Correction Support" },
	{ PKT_MDC_RFC2833_DTMF,		"RFC 2833 DTMF Support" },
	{ PKT_MDC_VOICE_METRICS,	"Voice Metrics Support" },
	{ PKT_MDC_MIBS,			"MIB Support" },
	{ PKT_MDC_MGPI,			"Multiple Grants Per Interval Support" },
	{ 0,					NULL }
};

static const value_string pkt_mdc_version_vals[] = {
	{ 0x3030,	"PacketCable 1.0" },
	{ 0x3031,	"PacketCable 1.1/1.5" }, /* 1.5 replaces 1.1-1.3 */
	{ 0x3032,	"PacketCable 1.2" },
	{ 0x3033,	"PacketCable 1.3" },
	{ 0,		NULL }
};

static const value_string pkt_mdc_boolean_vals[] = {
	{ 0x3030,	"No" },
	{ 0x3031,	"Yes" },
	{ 0,		NULL }
};

static const value_string pkt_mdc_codec_vals[] = {
	{ 0x3031,	"other" },           /* "01" */
	{ 0x3032,	"unknown" },
	{ 0x3033,	"G.729" },
	{ 0x3034,	"reserved" },
	{ 0x3035,	"G.729E" },
	{ 0x3036,	"PCMU" },
	{ 0x3037,	"G.726-32" },
	{ 0x3038,	"G.728" },
	{ 0x3039,	"PCMA" },            /* "09" */
	{ 0x3041,	"G.726-16" },        /* "0A" */
	{ 0x3042,	"G.726-24" },
	{ 0x3043,	"G.726-40" },
	{ 0x3044,	"iLBC" },
	{ 0x3045,	"BV16" },
	{ 0x3046,	"telephone-event" }, /* "0F" */
	{ 0,		NULL }
};

static const value_string pkt_mdc_t38_version_vals[] = {
	{ 0x3030,	"Unsupported" },
	{ 0x3031,	"T.38 Version Zero" }, /* default */
	{ 0x3032,	"T.38 Version One" },
	{ 0x3033,	"T.38 Version Two" },
	{ 0x3035,	"T.38 Version Three" },
	{ 0,		NULL }
};

static const value_string pkt_mdc_t38_ec_vals[] = {
	{ 0x3030,	"None" },
	{ 0x3031,	"Redundancy" }, /* default */
	{ 0x3032,	"FEC" },
	{ 0,		NULL }
};

static const value_string pkt_mdc_mibs_vals[] = {
	{ 0x3030,	"PacketCable 1.0" },
	{ 0x3031,	"PacketCable 1.5" },
	{ 0x3032,	"Reserved" },
	{ 0x3033,	"Reserved" },
	{ 0x3034,	"Reserved" },
	{ 0x3035,	"IETF" },
	{ 0,		NULL }
};

/* DOCSIS Cable Modem device capabilities (option 60). */
/* XXX we should rename all PKT_CM_* variables to DOCSIS_CM_* */
#define PKT_CM_TLV_OFF 12

#define PKT_CM_CONCAT_SUP	0x3031  /* "01" */
#define PKT_CM_DOCSIS_VER	0x3032  /* "02" */
#define PKT_CM_FRAG_SUP		0x3033  /* "03" */
#define PKT_CM_PHS_SUP		0x3034  /* "04" */
#define PKT_CM_IGMP_SUP		0x3035  /* "05" */
#define PKT_CM_PRIV_SUP		0x3036  /* "06" */
#define PKT_CM_DSAID_SUP	0x3037  /* "07" */
#define PKT_CM_USID_SUP		0x3038  /* "08" */
#define PKT_CM_FILT_SUP		0x3039  /* "09" */
#define PKT_CM_TET_MI		0x3041  /* "0A" */
#define PKT_CM_TET_MI_LC	0x3061  /* "0a" */
#define PKT_CM_TET		0x3042  /* "0B" */
#define PKT_CM_TET_LC		0x3062  /* "0b" */
#define PKT_CM_DCC_SUP		0x3043  /* "0C" */
#define PKT_CM_DCC_SUP_LC	0x3063  /* "0c" */

static const value_string pkt_cm_type_vals[] = {
	{ PKT_CM_CONCAT_SUP,	"Concatenation Support" },
	{ PKT_CM_DOCSIS_VER,	"DOCSIS Version" },
	{ PKT_CM_FRAG_SUP,	"Fragmentation Support" },
	{ PKT_CM_PHS_SUP,	"PHS Support" },
	{ PKT_CM_IGMP_SUP,	"IGMP Support" },
	{ PKT_CM_PRIV_SUP,	"Privacy Support" },
	{ PKT_CM_DSAID_SUP,	"Downstream SAID Support" },
	{ PKT_CM_USID_SUP,	"Upstream SID Support" },
	{ PKT_CM_FILT_SUP,	"Optional Filtering Support" },
	{ PKT_CM_TET_MI,	"Transmit Equalizer Taps per Modulation Interval" },
	{ PKT_CM_TET_MI_LC,	"Transmit Equalizer Taps per Modulation Interval" },
	{ PKT_CM_TET,		"Number of Transmit Equalizer Taps" },
	{ PKT_CM_TET_LC,	"Number of Transmit Equalizer Taps" },
	{ PKT_CM_DCC_SUP,	"DCC Support" },
	{ PKT_CM_DCC_SUP_LC,	"DCC Support" },
	{ 0, NULL }
};

static const value_string pkt_cm_version_vals[] = {
	{ 0x3030,	"DOCSIS 1.0" },
	{ 0x3031,	"DOCSIS 1.1" },
	{ 0x3032,	"DOCSIS 2.0" },
	{ 0,		NULL }
};

static const value_string pkt_cm_privacy_vals[] = {
	{ 0x3030,	"BPI Support" },
	{ 0x3031,	"BPI Plus Support" },
	{ 0,		NULL }
};


static const value_string pkt_mdc_supp_flow_vals[] = {
	{ 1 << 0, "Secure Flow (Full Secure Provisioning Flow)" },
	{ 1 << 1, "Hybrid Flow" },
	{ 1 << 2, "Basic Flow" },
	{ 0, NULL }
};


static void
dissect_packetcable_mta_cap(proto_tree *v_tree, tvbuff_t *tvb, int voff, int len)
{
	guint16 raw_val;
	unsigned long flow_val = 0;
	int off = PKT_MDC_TLV_OFF + voff;
	guint tlv_len;
	guint i;
	guint8 asc_val[3] = "  ", flow_val_str[5];
	char bit_fld[64];
	proto_item *ti;
	proto_tree *subtree;

	tvb_memcpy (tvb, asc_val, off, 2);
	if (sscanf(asc_val, "%x", &tlv_len) != 1 || tlv_len < 1) {
		proto_tree_add_text(v_tree, tvb, off, len - off,
			"Bogus length: %s", asc_val);
		return;
	} else {
		proto_tree_add_uint_format(v_tree, hf_bootp_pkt_mtacap_len, tvb, off, 2,
				tlv_len, "MTA DC Length: %d", tlv_len);
		off += 2;

		while (off - voff < len) {
			/* Type */
			raw_val = tvb_get_ntohs (tvb, off);

			/* Length */
			tvb_memcpy(tvb, asc_val, off + 2, 2);
			if (sscanf(asc_val, "%x", &tlv_len) != 1 || tlv_len < 1) {
				proto_tree_add_text(v_tree, tvb, off, len - off,
							"[Bogus length: %s]", asc_val);
				return;
			} else {
				/* Value(s) */

				ti = proto_tree_add_text(v_tree,
				    tvb, off, (tlv_len * 2) + 4,
				    "0x%s: %s = ",
				    tvb_format_text(tvb, off, 2),
				    val_to_str(raw_val, pkt_mdc_type_vals, "unknown"));
				switch (raw_val) {
					case PKT_MDC_VERSION:
						raw_val = tvb_get_ntohs(tvb, off + 4);
						proto_item_append_text(ti,
						    "%s (%s)",
						    val_to_str(raw_val, pkt_mdc_version_vals, "Reserved"),
						    tvb_format_stringzpad(tvb, off + 4, 2) );
						break;
					case PKT_MDC_TEL_END:
					case PKT_MDC_IF_INDEX:
						proto_item_append_text(ti,
						    "%s",
						    tvb_format_stringzpad(tvb, off + 4, 2) );
						break;
					case PKT_MDC_TGT:
					case PKT_MDC_HTTP_ACC:
					case PKT_MDC_SYSLOG:
					case PKT_MDC_NCS:
					case PKT_MDC_PRI_LINE:
					case PKT_MDC_NVRAM_STOR:
					case PKT_MDC_PROV_REP:
					case PKT_MDC_PROV_REP_LC:
					case PKT_MDC_SILENCE:
					case PKT_MDC_SILENCE_LC:
					case PKT_MDC_ECHO_CANCEL:
					case PKT_MDC_ECHO_CANCEL_LC:
					case PKT_MDC_RSVP:
					case PKT_MDC_RSVP_LC:
					case PKT_MDC_UGS_AD:
					case PKT_MDC_UGS_AD_LC:
					case PKT_MDC_FLOW_LOG:
					case PKT_MDC_RFC2833_DTMF:
					case PKT_MDC_VOICE_METRICS:
						raw_val = tvb_get_ntohs(tvb, off + 4);
						proto_item_append_text(ti,
						    "%s (%s)",
						    val_to_str(raw_val, pkt_mdc_boolean_vals, "unknown"),
						    tvb_format_stringzpad(tvb, off + 4, 2) );
						break;
					case PKT_MDC_SUPP_CODECS:
					case PKT_MDC_SUPP_CODECS_LC:
						for (i = 0; i < tlv_len; i++) {
							raw_val = tvb_get_ntohs(tvb, off + 4 + (i * 2) );
							proto_item_append_text(ti,
							    "%s%s (%s)",
							    plurality(i + 1, "", ", "),
							    val_to_str(raw_val, pkt_mdc_codec_vals, "unknown"),
							    tvb_format_stringzpad(tvb, off + 4 + (i * 2), 2) );
						}
						break;
					case PKT_MDC_PROV_FLOWS:
						tvb_memcpy(tvb, flow_val_str, off + 4, 4);
						flow_val_str[4] = '\0';
						flow_val = strtoul(flow_val_str, NULL, 16);
						proto_item_append_text(ti,
						    "0x%04lx", flow_val);
						break;
					case PKT_MDC_T38_VERSION:
						raw_val = tvb_get_ntohs(tvb, off + 4);
						proto_item_append_text(ti,
						    "%s (%s)",
						    val_to_str(raw_val, pkt_mdc_t38_version_vals, "unknown"),
						    tvb_format_stringzpad(tvb, off + 4, 2) );
						break;
					case PKT_MDC_T38_EC:
						raw_val = tvb_get_ntohs(tvb, off + 4);
						proto_item_append_text(ti,
						    "%s (%s)",
						    val_to_str(raw_val, pkt_mdc_t38_ec_vals, "unknown"),
						    tvb_format_stringzpad(tvb, off + 4, 2) );
						break;
					case PKT_MDC_MIBS:
						raw_val = tvb_get_ntohs(tvb, off + 4);
						proto_item_append_text(ti,
						    "%s (%s)",
						    val_to_str(raw_val, pkt_mdc_mibs_vals, "unknown"),
						    tvb_format_stringzpad(tvb, off + 4, 2) );
						break;
					case PKT_MDC_VENDOR_TLV:
					default:
						proto_item_append_text(ti,
						    "%s",
						    tvb_format_stringzpad(tvb, off + 4, tlv_len * 2) );
						break;
				}
			}
			subtree = proto_item_add_subtree(ti, ett_bootp_option);
			if (raw_val == PKT_MDC_PROV_FLOWS) {
				for (i = 0 ; i < 3; i++) {
					if (flow_val & pkt_mdc_supp_flow_vals[i].value) {
						decode_bitfield_value(bit_fld, flow_val, pkt_mdc_supp_flow_vals[i].value, 16);
						proto_tree_add_text(ti, tvb, off + 4, 4, "%s%s",
							bit_fld, pkt_mdc_supp_flow_vals[i].strptr);
					}
				}
			}
			off += (tlv_len * 2) + 4;
		}
	}
}

static void
dissect_docsis_cm_cap(proto_tree *v_tree, tvbuff_t *tvb, int voff, int len)
{
	unsigned long raw_val;
	int off = PKT_CM_TLV_OFF + voff;
	int tlv_len, i;
	guint8 asc_val[3] = "  ";
	proto_item *ti;

	tvb_memcpy (tvb, asc_val, off, 2);
	if (sscanf(asc_val, "%x", &tlv_len) != 1 || tlv_len < 1) {
		proto_tree_add_text(v_tree, tvb, off, len - off,
				    "Bogus length: %s", asc_val);
		return;
	} else {
		proto_tree_add_uint_format(v_tree, hf_bootp_docsis_cmcap_len, tvb, off, 2,
				tlv_len, "CM DC Length: %d", tlv_len);
		off += 2;

		while (off - voff < len) {
			/* Type */
			raw_val = tvb_get_ntohs (tvb, off);

			/* Length */
			tvb_memcpy(tvb, asc_val, off + 2, 2);
			if (sscanf(asc_val, "%x", &tlv_len) != 1 || tlv_len < 1) {
				proto_tree_add_text(v_tree, tvb, off, len - off,
							"[Bogus length: %s]", asc_val);
				return;
			} else {
				/* Value(s) */
				/*strptr+=g_snprintf(strptr, TLV_STR_LEN-(strptr-tlv_str), "Length: %d, Value%s: ", tlv_len,
						plurality(tlv_len, "", "s") );*/

				ti = proto_tree_add_text(v_tree, tvb, off,
				    (tlv_len * 2) + 4,
				    "0x%s: %s = ",
				    tvb_format_text(tvb, off, 2),
				    val_to_str(raw_val, pkt_cm_type_vals, "unknown"));
				switch (raw_val) {
					case PKT_CM_CONCAT_SUP:
					case PKT_CM_FRAG_SUP:
					case PKT_CM_PHS_SUP:
					case PKT_CM_IGMP_SUP:
					case PKT_CM_DCC_SUP:
					case PKT_CM_DCC_SUP_LC:
						for (i = 0; i < tlv_len; i++) {
							raw_val = tvb_get_ntohs(tvb, off + 4 + (i * 2) );
							proto_item_append_text(ti,
							    "%s%s (%s)",
							    plurality(i + 1, "", ", "),
							    val_to_str(raw_val, pkt_mdc_boolean_vals, "unknown"),
							    tvb_format_text(tvb, off + 4 + (i * 2), 2) );
						}
						break;
					case PKT_CM_DOCSIS_VER:
						raw_val = tvb_get_ntohs(tvb, off + 4);
						proto_item_append_text(ti,
						    "%s (%s)",
						    val_to_str(raw_val, pkt_cm_version_vals, "Reserved"),
						    tvb_format_text(tvb, off + 4, 2) );
						break;
					case PKT_CM_PRIV_SUP:
						raw_val = tvb_get_ntohs(tvb, off + 4);
						proto_item_append_text(ti,
						    "%s (%s)",
						    val_to_str(raw_val, pkt_cm_privacy_vals, "Reserved"),
						    tvb_format_text(tvb, off + 4, 2) );
						break;
					case PKT_CM_DSAID_SUP:
					case PKT_CM_USID_SUP:
					case PKT_CM_TET_MI:
					case PKT_CM_TET_MI_LC:
					case PKT_CM_TET:
					case PKT_CM_TET_LC:
						tvb_memcpy (tvb, asc_val, off + 4, 2);
						raw_val = strtoul(asc_val, NULL, 16);
						proto_item_append_text(ti,
						    "%lu", raw_val);
						break;
					case PKT_CM_FILT_SUP:
						tvb_memcpy (tvb, asc_val, off + 4, 2);
						raw_val = strtoul(asc_val, NULL, 16);
						if (raw_val & 0x01)
							proto_item_append_text(ti,
							    "802.1p filtering");
						if (raw_val & 0x02) {
							if (raw_val & 0x01)
								proto_item_append_text(ti, ", ");
							proto_item_append_text(ti,
							    "802.1Q filtering");
						}
						if (! raw_val & 0x03)
							proto_item_append_text(ti,
							    "None");
						proto_item_append_text(ti,
						    " (0x%02lx)", raw_val);
						break;
				}
			}
			off += (tlv_len * 2) + 4;
		}
	}
}


/* Definitions specific to PKT-SP-PROV-I05-021127 begin with "PKT_CCC_I05".
   Definitions specific to IETF draft 5 and RFC 3495 begin with "PKT_CCC_IETF".
   Shared definitions begin with "PKT_CCC".
 */
#define PKT_CCC_PRI_DHCP       1
#define PKT_CCC_SEC_DHCP       2
#define PKT_CCC_I05_SNMP       3
#define PKT_CCC_IETF_PROV_SRV  3
#define PKT_CCC_I05_PRI_DNS    4
#define PKT_CCC_IETF_AS_KRB    4
#define PKT_CCC_I05_SEC_DNS    5
#define PKT_CCC_IETF_AP_KRB    5
#define PKT_CCC_KRB_REALM      6
#define PKT_CCC_TGT_FLAG       7
#define PKT_CCC_PROV_TIMER     8
#define PKT_CCC_CMS_FQDN       9
#define PKT_CCC_IETF_SEC_TKT   9
#define PKT_CCC_AS_KRB        10
#define PKT_CCC_AP_KRB        11
#define PKT_CCC_MTA_KRB_CLEAR 12

static const value_string pkt_i05_ccc_opt_vals[] = {
	{ PKT_CCC_PRI_DHCP,		"Primary DHCP Server" },
	{ PKT_CCC_SEC_DHCP,		"Secondary DHCP Server" },
	{ PKT_CCC_I05_SNMP,		"SNMP Entity" },
	{ PKT_CCC_I05_PRI_DNS,		"Primary DNS Server" },
	{ PKT_CCC_I05_SEC_DNS,		"Secondary DNS Server" },
	{ PKT_CCC_KRB_REALM,		"Kerberos Realm" },
	{ PKT_CCC_TGT_FLAG,		"MTA should fetch TGT?" },
	{ PKT_CCC_PROV_TIMER,		"Provisioning Timer" },
	{ PKT_CCC_CMS_FQDN,		"CMS FQDN" },
	{ PKT_CCC_AS_KRB,		"AS-REQ/AS-REP Backoff and Retry" },
	{ PKT_CCC_AP_KRB,		"AP-REQ/AP-REP Backoff and Retry" },
	{ PKT_CCC_MTA_KRB_CLEAR,	"MTA should clear Kerberos tickets?" },
	{ 0, NULL },
};

static const value_string pkt_draft5_ccc_opt_vals[] = {
	{ PKT_CCC_PRI_DHCP,		"TSP's Primary DHCP Server" },
	{ PKT_CCC_SEC_DHCP,		"TSP's Secondary DHCP Server" },
	{ PKT_CCC_IETF_PROV_SRV,	"TSP's Provisioning Server" },
	{ PKT_CCC_IETF_AS_KRB,		"TSP's AS-REQ/AS-REP Backoff and Retry" },
	{ PKT_CCC_IETF_AP_KRB,		"TSP's AP-REQ/AP-REP Backoff and Retry" },
	{ PKT_CCC_KRB_REALM,		"TSP's Kerberos Realm Name" },
	{ PKT_CCC_TGT_FLAG,		"TSP's Ticket Granting Server Utilization" },
	{ PKT_CCC_PROV_TIMER,		"TSP's Provisioning Timer Value" },
	{ PKT_CCC_IETF_SEC_TKT,		"PacketCable Security Ticket Control" },
	{ 0, NULL },
};

static const value_string pkt_i05_ccc_ticket_ctl_vals[] = {
	{ 1, "Invalidate Provisioning Application Server's ticket" },
	{ 2, "Invalidate all CMS Application Server tickets" },
	{ 3, "Invalidate all Application Server tickets" },
	{ 0, NULL },
};

static int
dissect_packetcable_i05_ccc(proto_tree *v_tree, tvbuff_t *tvb, int optoff,
    int optend)
{
	int suboptoff = optoff;
	guint8 subopt, subopt_len, fetch_tgt, timer_val, ticket_ctl;
	proto_tree *pkt_s_tree;
	proto_item *vti;

	subopt = tvb_get_guint8(tvb, optoff);
	suboptoff++;

	if (suboptoff >= optend) {
		proto_tree_add_text(v_tree, tvb, optoff, 1,
			"Suboption %d: no room left in option for suboption length",
	 		subopt);
	 	return (optend);
	}
	subopt_len = tvb_get_guint8(tvb, optoff);
	suboptoff++;

	vti = proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,
	    "Suboption %u: %s: ", subopt,
	    val_to_str(subopt, pkt_i05_ccc_opt_vals, "unknown/reserved") );

	switch (subopt) {
		case PKT_CCC_PRI_DHCP:	/* String values */
		case PKT_CCC_SEC_DHCP:
		case PKT_CCC_I05_SNMP:
		case PKT_CCC_I05_PRI_DNS:
		case PKT_CCC_I05_SEC_DNS:
		case PKT_CCC_KRB_REALM:
		case PKT_CCC_CMS_FQDN:
			proto_item_append_text(vti, "%s (%u byte%s)",
					tvb_format_stringzpad(tvb, suboptoff, subopt_len),
					subopt_len,
					plurality(subopt_len, "", "s") );
			suboptoff += subopt_len;
			break;

		case PKT_CCC_TGT_FLAG:
			if (suboptoff+1 > optend) {
				proto_item_append_text(vti,
				    "no room left in option for suboption value");
			 	return (optend);
			}
			fetch_tgt = tvb_get_guint8(tvb, suboptoff);
			proto_item_append_text(vti, "%s (%u byte%s%s)",
					fetch_tgt ? "Yes" : "No",
					subopt_len,
					plurality(subopt_len, "", "s"),
					subopt_len != 1 ? " [Invalid]" : "");
			suboptoff += subopt_len;
			break;

		case PKT_CCC_PROV_TIMER:
			if (suboptoff+1 > optend) {
				proto_item_append_text(vti,
				    "no room left in option for suboption value");
			 	return (optend);
			}
			timer_val = tvb_get_guint8(tvb, suboptoff);
			proto_item_append_text(vti, "%u%s (%u byte%s%s)", timer_val,
					timer_val > 30 ? " [Invalid]" : "",
					subopt_len,
					plurality(subopt_len, "", "s"),
					subopt_len != 1 ? " [Invalid]" : "");
			suboptoff += subopt_len;
			break;

		case PKT_CCC_AS_KRB:
			if (suboptoff+12 > optend) {
				proto_item_append_text(vti,
				    "no room left in option for suboption value");
			 	return (optend);
			}
			proto_item_append_text(vti, "(%u byte%s%s)", subopt_len,
					plurality(subopt_len, "", "s"),
					subopt_len != 12 ? " [Invalid]" : "");
			if (subopt_len == 12) {
				pkt_s_tree = proto_item_add_subtree(vti, ett_bootp_option);
				proto_tree_add_text(pkt_s_tree, tvb, suboptoff, 4,
						"pktcMtaDevRealmUnsolicitedKeyNomTimeout: %u",
						tvb_get_ntohl(tvb, suboptoff));
				proto_tree_add_text(pkt_s_tree, tvb, suboptoff + 4, 4,
						"pktcMtaDevRealmUnsolicitedKeyMaxTimeout: %u",
						tvb_get_ntohl(tvb, suboptoff + 4));
				proto_tree_add_text(pkt_s_tree, tvb, suboptoff + 8, 4,
						"pktcMtaDevRealmUnsolicitedKeyMaxRetries: %u",
						tvb_get_ntohl(tvb, suboptoff + 8));
			}
			suboptoff += subopt_len;
			break;

		case PKT_CCC_AP_KRB:
			if (suboptoff+12 > optend) {
				proto_item_append_text(vti,
				    "no room left in option for suboption value");
			 	return (optend);
			}
			proto_item_append_text(vti, "(%u byte%s%s)", subopt_len,
					plurality(subopt_len, "", "s"),
					subopt_len != 12 ? " [Invalid]" : "");
			if (subopt_len == 12) {
				pkt_s_tree = proto_item_add_subtree(vti, ett_bootp_option);
				proto_tree_add_text(pkt_s_tree, tvb, suboptoff, 4,
						"pktcMtaDevProvUnsolicitedKeyNomTimeout: %u",
						tvb_get_ntohl(tvb, suboptoff));
				proto_tree_add_text(pkt_s_tree, tvb, suboptoff + 4, 4,
						"pktcMtaDevProvUnsolicitedKeyMaxTimeout: %u",
						tvb_get_ntohl(tvb, suboptoff + 4));
				proto_tree_add_text(pkt_s_tree, tvb, suboptoff + 8, 4,
						"pktcMtaDevProvUnsolicitedKeyMaxRetries: %u",
						tvb_get_ntohl(tvb, suboptoff + 8));
			}
			suboptoff += subopt_len;
			break;

		case PKT_CCC_MTA_KRB_CLEAR:
			if (suboptoff+1 > optend) {
				proto_item_append_text(vti,
				    "no room left in option for suboption value");
			 	return (optend);
			}
			ticket_ctl = tvb_get_guint8(tvb, suboptoff);
			proto_item_append_text(vti, "%s (%u) (%u byte%s%s)",
					val_to_str (ticket_ctl, pkt_i05_ccc_ticket_ctl_vals, "unknown/invalid"),
					ticket_ctl,
					subopt_len,
					plurality(subopt_len, "", "s"),
					subopt_len != 1 ? " [Invalid]" : "");
			suboptoff += subopt_len;
			break;

		default:
			suboptoff += subopt_len;
			break;

	}
	return suboptoff;
}


static const value_string sec_tcm_vals[] = {
	{ 1 << 0, "PacketCable Provisioning Server" },
	{ 1 << 1, "All PacketCable Call Management Servers" },
	{ 0, NULL }
};

static int
dissect_packetcable_ietf_ccc(proto_tree *v_tree, tvbuff_t *tvb, int optoff,
    int optend, int revision)
{
	int suboptoff = optoff;
	guint8 subopt, subopt_len;
	guint32 ipv4_addr;
	guint8 prov_type, fetch_tgt, timer_val;
	guint16 sec_tcm;
	proto_tree *pkt_s_tree;
	proto_item *vti;
	int max_timer_val = 255, i;
	char *dns_name, bit_fld[24];

	subopt = tvb_get_guint8(tvb, suboptoff);
	suboptoff++;

	if (suboptoff >= optend) {
		proto_tree_add_text(v_tree, tvb, optoff, 1,
			"Suboption %d: no room left in option for suboption length",
	 		subopt);
	 	return (optend);
	}
	subopt_len = tvb_get_guint8(tvb, suboptoff);
	suboptoff++;

	vti = proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,
	    "Suboption %u: %s: ", subopt,
	    val_to_str(subopt, pkt_draft5_ccc_opt_vals, "unknown/reserved") );

	switch (subopt) {
		case PKT_CCC_PRI_DHCP:	/* IPv4 values */
		case PKT_CCC_SEC_DHCP:
			if (suboptoff+4 > optend) {
				proto_item_append_text(vti,
				    "no room left in option for suboption value");
			 	return (optend);
			}
			ipv4_addr = tvb_get_ipv4(tvb, suboptoff);
			proto_item_append_text(vti, "%s (%u byte%s%s)",
					ip_to_str((guint8 *)&ipv4_addr),
					subopt_len,
					plurality(subopt_len, "", "s"),
					subopt_len != 4 ? " [Invalid]" : "");
			suboptoff += subopt_len;
			break;

		case PKT_CCC_IETF_PROV_SRV:
			if (suboptoff+1 > optend) {
				proto_item_append_text(vti,
				    "no room left in option for suboption value");
			 	return (optend);
			}
			prov_type = tvb_get_guint8(tvb, suboptoff);
			suboptoff += 1;
			switch (prov_type) {
				case 0:
					/* XXX - check suboption length */
					get_dns_name(tvb, suboptoff, suboptoff, &dns_name);
					proto_item_append_text(vti, "%s (%u byte%s)", dns_name,
							subopt_len - 1, plurality(subopt_len, "", "s") );
					break;
				case 1:
					if (suboptoff+4 > optend) {
						proto_item_append_text(vti,
						    "no room left in option for suboption value");
					 	return (optend);
					}
					ipv4_addr = tvb_get_ipv4(tvb, suboptoff);
					proto_item_append_text(vti, "%s (%u byte%s%s)",
							ip_to_str((guint8 *)&ipv4_addr),
							subopt_len,
							plurality(subopt_len, "", "s"),
							subopt_len != 5 ? " [Invalid]" : "");
					break;
				default:
					proto_item_append_text(vti, "Invalid type: %u (%u byte%s)",
							prov_type,
							subopt_len,
							plurality(subopt_len, "", "s") );
					break;
			}
			suboptoff += subopt_len - 1;
			break;

		case PKT_CCC_IETF_AS_KRB:
			if (suboptoff+12 > optend) {
				proto_item_append_text(vti,
				    "no room left in option for suboption value");
			 	return (optend);
			}
			proto_item_append_text(vti, "(%u byte%s%s)", subopt_len,
					plurality(subopt_len, "", "s"),
					subopt_len != 12 ? " [Invalid]" : "");
			if (subopt_len == 12) {
				pkt_s_tree = proto_item_add_subtree(vti, ett_bootp_option);
				proto_tree_add_text(pkt_s_tree, tvb, suboptoff, 4,
						"pktcMtaDevRealmUnsolicitedKeyNomTimeout: %u",
						tvb_get_ntohl(tvb, suboptoff));
				proto_tree_add_text(pkt_s_tree, tvb, suboptoff + 4, 4,
						"pktcMtaDevRealmUnsolicitedKeyMaxTimeout: %u",
						tvb_get_ntohl(tvb, suboptoff + 4));
				proto_tree_add_text(pkt_s_tree, tvb, suboptoff + 8, 4,
						"pktcMtaDevRealmUnsolicitedKeyMaxRetries: %u",
						tvb_get_ntohl(tvb, suboptoff + 8));
			}
			suboptoff += subopt_len;
			break;

		case PKT_CCC_IETF_AP_KRB:
			proto_item_append_text(vti, "(%u byte%s%s)", subopt_len,
					plurality(subopt_len, "", "s"),
					subopt_len != 12 ? " [Invalid]" : "");
			if (subopt_len == 12) {
				pkt_s_tree = proto_item_add_subtree(vti, ett_bootp_option);
				proto_tree_add_text(pkt_s_tree, tvb, suboptoff, 4,
					"pktcMtaDevProvUnsolicitedKeyNomTimeout: %u",
					tvb_get_ntohl(tvb, suboptoff));
				proto_tree_add_text(pkt_s_tree, tvb, suboptoff + 4, 4,
						"pktcMtaDevProvUnsolicitedKeyMaxTimeout: %u",
						tvb_get_ntohl(tvb, suboptoff + 4));
				proto_tree_add_text(pkt_s_tree, tvb, suboptoff + 8, 4,
					"pktcMtaDevProvUnsolicitedKeyMaxRetries: %u",
					tvb_get_ntohl(tvb, suboptoff + 8));
			}
			suboptoff += subopt_len;
			break;

		case PKT_CCC_KRB_REALM: /* String values */
			/* XXX - check suboption length */
			get_dns_name(tvb, suboptoff, suboptoff, &dns_name);
			proto_item_append_text(vti, "%s (%u byte%s)", dns_name,
					subopt_len, plurality(subopt_len, "", "s") );
			suboptoff += subopt_len;
			break;

		case PKT_CCC_TGT_FLAG:
			if (suboptoff+1 > optend) {
				proto_item_append_text(vti,
				    "no room left in option for suboption value");
			 	return (optend);
			}
			fetch_tgt = tvb_get_guint8(tvb, suboptoff);
			proto_item_append_text(vti, "%s (%u byte%s%s)",
					fetch_tgt ? "Yes" : "No",
					subopt_len,
					plurality(subopt_len, "", "s"),
					subopt_len != 1 ? " [Invalid]" : "");
			suboptoff += 1;
			break;

		case PKT_CCC_PROV_TIMER:
			if (suboptoff+1 > optend) {
				proto_item_append_text(vti,
				    "no room left in option for suboption value");
			 	return (optend);
			}
			if (revision == PACKETCABLE_CCC_DRAFT5)
				max_timer_val = 30;
			timer_val = tvb_get_guint8(tvb, suboptoff);
			proto_item_append_text(vti, "%u%s (%u byte%s%s)", timer_val,
					timer_val > max_timer_val ? " [Invalid]" : "",
					subopt_len,
					plurality(subopt_len, "", "s"),
					subopt_len != 1 ? " [Invalid]" : "");
			suboptoff += 1;
			break;

		case PKT_CCC_IETF_SEC_TKT:
			if (suboptoff+2 > optend) {
				proto_item_append_text(vti,
				    "no room left in option for suboption value");
			 	return (optend);
			}
			sec_tcm = tvb_get_ntohs(tvb, suboptoff);
			proto_item_append_text(vti, "0x%04x (%u byte%s%s)", sec_tcm, subopt_len,
					plurality(subopt_len, "", "s"),
					subopt_len != 2 ? " [Invalid]" : "");
			if (subopt_len == 2) {
				pkt_s_tree = proto_item_add_subtree(vti, ett_bootp_option);
				for (i = 0; i < 2; i++) {
					if (sec_tcm & sec_tcm_vals[i].value) {
						decode_bitfield_value(bit_fld, sec_tcm, sec_tcm_vals[i].value, 16);
						proto_tree_add_text(pkt_s_tree, tvb, suboptoff, 2, "%sInvalidate %s",
							bit_fld, sec_tcm_vals[i].strptr);
					}
				}
			}
			suboptoff += subopt_len;
			break;

		default:
			suboptoff += subopt_len;
			break;
	}
	return suboptoff;
}

#define BOOTREQUEST	1
#define BOOTREPLY	2

static const value_string op_vals[] = {
	{ BOOTREQUEST,	"Boot Request" },
	{ BOOTREPLY,	"Boot Reply" },
	{ 0,		NULL }
};

static void
dissect_bootp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*bp_tree = NULL;
	proto_item	*ti;
	proto_tree	*flag_tree = NULL;
	proto_item	*fi;
	guint8		op;
	guint8		htype, hlen;
	const guint8	*haddr;
	int		voff, eoff, tmpvoff; /* vendor offset, end offset */
	guint32		ip_addr;
	gboolean	at_end;
	const char	*dhcp_type = NULL;
	const guint8	*vendor_class_id = NULL;
	guint16		flags;
	int		offset_delta;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "BOOTP");
	if (check_col(pinfo->cinfo, COL_INFO)) {
		/*
		 * In case we throw an exception fetching the opcode, etc.
		 */
		col_clear(pinfo->cinfo, COL_INFO);
	}

	op = tvb_get_guint8(tvb, 0);
	htype = tvb_get_guint8(tvb, 1);
	hlen = tvb_get_guint8(tvb, 2);
	if (check_col(pinfo->cinfo, COL_INFO)) {
		switch (op) {

		case BOOTREQUEST:
			if ((htype == ARPHRD_ETHER || htype == ARPHRD_IEEE802)
			    && hlen == 6)
				col_add_fstr(pinfo->cinfo, COL_INFO, "Boot Request from %s (%s)",
				    arphrdaddr_to_str(tvb_get_ptr(tvb, 28, hlen),
				        hlen, htype),
				    get_ether_name(tvb_get_ptr(tvb, 28, hlen)));
			else
				col_add_fstr(pinfo->cinfo, COL_INFO, "Boot Request from %s",
				    arphrdaddr_to_str(tvb_get_ptr(tvb, 28, hlen),
					hlen, htype));
			break;

		case BOOTREPLY:
			col_set_str(pinfo->cinfo, COL_INFO, "Boot Reply");
			break;

		default:
			col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown BOOTP message type (%u)",
			    op);
			break;
		}
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_bootp, tvb, 0, -1, FALSE);
		bp_tree = proto_item_add_subtree(ti, ett_bootp);

		proto_tree_add_uint(bp_tree, hf_bootp_type, tvb,
					   0, 1,
					   op);
		proto_tree_add_uint_format(bp_tree, hf_bootp_hw_type, tvb,
					   1, 1,
					   htype,
					   "Hardware type: %s",
					   arphrdtype_to_str(htype,
							     "Unknown (0x%02x)"));
		proto_tree_add_uint(bp_tree, hf_bootp_hw_len, tvb,
				    2, 1, hlen);
		proto_tree_add_item(bp_tree, hf_bootp_hops, tvb,
				    3, 1, FALSE);
		proto_tree_add_item(bp_tree, hf_bootp_id, tvb,
				    4, 4, FALSE);
		proto_tree_add_item(bp_tree, hf_bootp_secs, tvb,
				    8, 2, FALSE);
		flags = tvb_get_ntohs(tvb, 10);
		fi = proto_tree_add_uint(bp_tree, hf_bootp_flags, tvb,
				    10, 2, flags);
		proto_item_append_text(fi, " (%s)",
		    (flags & BOOTP_BC) ? "Broadcast" : "Unicast");
    		flag_tree = proto_item_add_subtree(fi, ett_bootp_flags);
		proto_tree_add_boolean(flag_tree, hf_bootp_flags_broadcast, tvb,
				    10, 2, flags);
		proto_tree_add_uint(flag_tree, hf_bootp_flags_reserved, tvb,
				    10, 2, flags);
		proto_tree_add_item(bp_tree, hf_bootp_ip_client, tvb,
				    12, 4, FALSE);
		proto_tree_add_item(bp_tree, hf_bootp_ip_your, tvb,
				    16, 4, FALSE);
		proto_tree_add_item(bp_tree, hf_bootp_ip_server, tvb,
				    20, 4, FALSE);
		proto_tree_add_item(bp_tree, hf_bootp_ip_relay, tvb,
				    24, 4, FALSE);

		if (hlen > 0 && hlen <= 16) {
			haddr = tvb_get_ptr(tvb, 28, hlen);
			if ((htype == ARPHRD_ETHER || htype == ARPHRD_IEEE802)
			    && hlen == 6)
				proto_tree_add_ether(bp_tree, hf_bootp_hw_ether_addr, tvb, 28, 6, haddr);
			else
				/* The chaddr element is 16 bytes in length,
				   although only the first hlen bytes are used */
				proto_tree_add_bytes_format(bp_tree, hf_bootp_hw_addr, tvb,
						   28, 16,
						   haddr,
						   "Client hardware address: %s",
						   arphrdaddr_to_str(haddr,
								     hlen,
								     htype));
		}
		else {
			proto_tree_add_text(bp_tree,  tvb,
						   28, 16, "Client address not given");
		}

		/* The server host name is optional */
		if (tvb_get_guint8(tvb, 44) != '\0') {
			proto_tree_add_item(bp_tree, hf_bootp_server, tvb,
						   SERVER_NAME_OFFSET,
						   SERVER_NAME_LEN, FALSE);
		}
		else {
			proto_tree_add_string_format(bp_tree, hf_bootp_server, tvb,
						   SERVER_NAME_OFFSET,
						   SERVER_NAME_LEN,
						   tvb_get_ptr(tvb, SERVER_NAME_OFFSET, 1),
						   "Server host name not given");
		}

		/* Boot file */
		if (tvb_get_guint8(tvb, 108) != '\0') {
			proto_tree_add_item(bp_tree, hf_bootp_file, tvb,
						   FILE_NAME_OFFSET,
						   FILE_NAME_LEN, FALSE);
		}
		else {
			proto_tree_add_string_format(bp_tree, hf_bootp_file, tvb,
						   FILE_NAME_OFFSET,
						   FILE_NAME_LEN,
						   tvb_get_ptr(tvb, FILE_NAME_OFFSET, 1),
						   "Boot file name not given");
		}
	}

	voff = VENDOR_INFO_OFFSET;

	/* rfc2132 says it SHOULD exist, not that it MUST exist */
	if (tvb_bytes_exist(tvb, voff, 4)) {
		if (tvb_get_ntohl(tvb, voff) == 0x63825363) {
			if (tree) {
				ip_addr = tvb_get_ipv4(tvb, voff);
				proto_tree_add_ipv4_format(bp_tree, hf_bootp_cookie, tvb,
				    voff, 4, ip_addr,
				    "Magic cookie: (OK)");
			}
			voff += 4;
		}
		else {
			if (tree) {
				proto_tree_add_text(bp_tree,  tvb,
					voff, 64, "Bootp vendor specific options");
			}
			voff += 64;
		}
	}

	eoff = tvb_reported_length(tvb);

	/*
	 * In the first pass, we just look for the DHCP message type
	 * and Vendor class identifier options.
	 */
	tmpvoff = voff;
	at_end = FALSE;
	while (tmpvoff < eoff && !at_end) {
		offset_delta = bootp_option(tvb, 0, tmpvoff, eoff, TRUE, &at_end,
		    &dhcp_type, &vendor_class_id);
		if (offset_delta <= 0) {
			THROW(ReportedBoundsError);
		}
		tmpvoff += offset_delta;
	}

	/*
	 * If there was a DHCP message type option, flag this packet
	 * as DHCP.
	 */
	if (dhcp_type != NULL) {
		/*
		 * Yes, this is a DHCP packet, and "dhcp_type" is the
		 * packet type.
		 */
		if (check_col(pinfo->cinfo, COL_PROTOCOL))
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "DHCP");
		if (check_col(pinfo->cinfo, COL_INFO))
			col_add_fstr(pinfo->cinfo, COL_INFO, "DHCP %-8s - Transaction ID 0x%x",
			    dhcp_type, tvb_get_ntohl(tvb, 4));
		if (tree)
			proto_tree_add_boolean_hidden(bp_tree, hf_bootp_dhcp,
			    tvb, 0, 0, 1);
		tap_queue_packet( bootp_dhcp_tap, pinfo, dhcp_type);
	}

	/*
	 * If we're not building the protocol tree, we don't need to
	 * make a second pass.
	 */
	if (tree == NULL)
		return;

	/*
	 * OK, now build the protocol tree.
	 */
	at_end = FALSE;
	while (voff < eoff && !at_end) {
		offset_delta = bootp_option(tvb, bp_tree, voff, eoff, FALSE, &at_end,
		    &dhcp_type, &vendor_class_id);
		if (offset_delta <= 0) {
			THROW(ReportedBoundsError);
		}
		voff += offset_delta;
	}
	if (voff < eoff) {
		/*
		 * Padding after the end option.
		 */
		proto_tree_add_text(bp_tree, tvb, voff, eoff - voff, "Padding");
	}
}

void
proto_register_bootp(void)
{
  static hf_register_info hf[] = {
    { &hf_bootp_dhcp,
      { "Frame is DHCP",                "bootp.dhcp",    FT_BOOLEAN,
        BASE_NONE,			NULL,		 0x0,
        "", HFILL }},

    { &hf_bootp_type,
      { "Message type",			"bootp.type",	 FT_UINT8,
         BASE_DEC, 			VALS(op_vals),   0x0,
      	"", HFILL }},

    { &hf_bootp_hw_type,
      { "Hardware type",	       	"bootp.hw.type", FT_UINT8,
        BASE_HEX,			NULL,		 0x0,
      	"", HFILL }},

    { &hf_bootp_hw_len,
      { "Hardware address length",	"bootp.hw.len",  FT_UINT8,
        BASE_DEC,			NULL,		 0x0,
      	"", HFILL }},

    { &hf_bootp_hops,
      { "Hops",			       	"bootp.hops",	 FT_UINT8,
        BASE_DEC,			NULL,		 0x0,
      	"", HFILL }},

    { &hf_bootp_id,
      { "Transaction ID",	       	"bootp.id",	 FT_UINT32,
        BASE_HEX,			 NULL,		 0x0,
      	"", HFILL }},

    { &hf_bootp_secs,
      { "Seconds elapsed",	       	"bootp.secs",	 FT_UINT16,
        BASE_DEC,			 NULL,		 0x0,
      	"", HFILL }},

    { &hf_bootp_flags,
      { "Bootp flags",		       	"bootp.flags",   FT_UINT16,
        BASE_HEX,			NULL,		 0x0,
      	"", HFILL }},

    { &hf_bootp_flags_broadcast,
      { "Broadcast flag",	       	"bootp.flags.bc", FT_BOOLEAN,
        16,			TFS(&flag_set_broadcast), BOOTP_BC,
      	"", HFILL }},

    { &hf_bootp_flags_reserved,
      { "Reserved flags",	       	"bootp.flags.reserved", FT_UINT16,
        BASE_HEX,			NULL,		BOOTP_MBZ,
      	"", HFILL }},

    { &hf_bootp_ip_client,
      { "Client IP address",	       	"bootp.ip.client",FT_IPv4,
        BASE_NONE,			NULL,		  0x0,
      	"", HFILL }},

    { &hf_bootp_ip_your,
      { "Your (client) IP address",	"bootp.ip.your",  FT_IPv4,
        BASE_NONE,			NULL,		  0x0,
      	"", HFILL }},

    { &hf_bootp_ip_server,
      { "Next server IP address",	"bootp.ip.server",FT_IPv4,
        BASE_NONE,			NULL,		  0x0,
      	"", HFILL }},

    { &hf_bootp_ip_relay,
      { "Relay agent IP address",	"bootp.ip.relay", FT_IPv4,
        BASE_NONE,			NULL,		  0x0,
      	"", HFILL }},

    { &hf_bootp_hw_addr,
      { "Client hardware address",	"bootp.hw.addr", FT_BYTES,
        BASE_NONE,			NULL,		 0x0,
      	"", HFILL }},

    { &hf_bootp_hw_ether_addr,
      { "Client MAC address",		"bootp.hw.mac_addr", FT_ETHER,
        BASE_NONE,			NULL,		 0x0,
      	"", HFILL }},

    { &hf_bootp_server,
      { "Server host name",		"bootp.server",  FT_STRING,
        BASE_NONE,			NULL,		 0x0,
      	"", HFILL }},

    { &hf_bootp_file,
      { "Boot file name",		"bootp.file",	 FT_STRING,
        BASE_NONE,			NULL,		 0x0,
      	"", HFILL }},

    { &hf_bootp_cookie,
      { "Magic cookie",			"bootp.cookie",	 FT_IPv4,
         BASE_NONE,			NULL,		 0x0,
      	"", HFILL }},

    { &hf_bootp_vendor,
      { "Bootp Vendor Options",		"bootp.vendor", FT_BYTES,
        BASE_NONE,			NULL,		 0x0,
      	"", HFILL }},

    { &hf_bootp_fqdn_s,
      { "Server",		"bootp.fqdn.s",		FT_BOOLEAN,
        8,			TFS(&tfs_fqdn_s),	F_FQDN_S,
      	"If true, server should do DDNS update", HFILL }},

    { &hf_bootp_fqdn_o,
      { "Server overrides",	"bootp.fqdn.o",		FT_BOOLEAN,
        8,			TFS(&tfs_fqdn_o),	F_FQDN_O,
      	"If true, server insists on doing DDNS update", HFILL }},

    { &hf_bootp_fqdn_e,
      { "Encoding",	"bootp.fqdn.e",		FT_BOOLEAN,
        8,			TFS(&tfs_fqdn_e),	F_FQDN_E,
      	"If true, name is binary encoded", HFILL }},

    { &hf_bootp_fqdn_n,
      { "Server DDNS",	"bootp.fqdn.n",		FT_BOOLEAN,
        8,			TFS(&tfs_fqdn_n),	F_FQDN_N,
      	"If true, server should not do any DDNS updates", HFILL }},

    { &hf_bootp_fqdn_mbz,
      { "Reserved flags",	"bootp.fqdn.mbz",	FT_UINT8,
        BASE_HEX,		NULL,			F_FQDN_MBZ,
      	"", HFILL }},

    { &hf_bootp_fqdn_rcode1,
      { "A-RR result",	       	"bootp.fqdn.rcode1",	 FT_UINT8,
        BASE_DEC,		NULL,			 0x0,
      	"Result code of A-RR update", HFILL }},

    { &hf_bootp_fqdn_rcode2,
      { "PTR-RR result",       	"bootp.fqdn.rcode2",	 FT_UINT8,
        BASE_DEC,		NULL,			 0x0,
      	"Result code of PTR-RR update", HFILL }},

    { &hf_bootp_fqdn_name,
      { "Client name",		"bootp.fqdn.name",	FT_BYTES,
        BASE_NONE,		NULL,			0x0,
      	"Name to register via DDNS", HFILL }},

    { &hf_bootp_fqdn_asciiname,
      { "Client name",		"bootp.fqdn.name",	FT_STRING,
        BASE_NONE,		NULL,			0x0,
      	"Name to register via DDNS", HFILL }},

    { &hf_bootp_pkt_mtacap_len,
      { "PacketCable MTA Device Capabilities Length",	"bootp.vendor.pktc.mtacap_len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "PacketCable MTA Device Capabilities Length", HFILL }},
    { &hf_bootp_docsis_cmcap_len,
      { "DOCSIS CM Device Capabilities Length",	"bootp.vendor.docsis.cmcap_len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "DOCSIS Cable Modem Device Capabilities Length", HFILL }},
  };

  static gint *ett[] = {
    &ett_bootp,
    &ett_bootp_flags,
    &ett_bootp_option,
    &ett_bootp_fqdn,
  };

  module_t *bootp_module;

  proto_bootp = proto_register_protocol("Bootstrap Protocol", "BOOTP/DHCP",
					"bootp");
  proto_register_field_array(proto_bootp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  bootp_dhcp_tap = register_tap("bootp");

  bootp_module = prefs_register_protocol(proto_bootp, NULL);

  prefs_register_bool_preference(bootp_module, "novellserverstring",
    "Decode Option 85 as String",
    "Novell Servers option 85 can be configured as a string instead of address",
    &novell_string);

  prefs_register_enum_preference(bootp_module, "pkt.ccc.protocol_version",
    "PacketCable CCC protocol version",
    "The PacketCable CCC protocol version",
    &pkt_ccc_protocol_version,
    pkt_ccc_protocol_versions,
    FALSE);

  prefs_register_uint_preference(bootp_module, "pkt.ccc.option",
    "PacketCable CCC option",
    "Option Number for PacketCable CableLabs Client Configuration",
    10,
    &pkt_ccc_option);


}

void
proto_reg_handoff_bootp(void)
{
  dissector_handle_t bootp_handle;

  bootp_handle = create_dissector_handle(dissect_bootp, proto_bootp);
  dissector_add("udp.port", UDP_PORT_BOOTPS, bootp_handle);
  dissector_add("udp.port", UDP_PORT_BOOTPC, bootp_handle);
}
