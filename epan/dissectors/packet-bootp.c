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
 *     http://www.cablemodem.com/downloads/specs/CM-SP-RFIv2.0-I06-040804.pdf
 * PacketCable(TM) MTA Device Provisioning Specification
 *     http://www.packetcable.com/downloads/specs/PKT-SP-PROV-I10-040730.pdf
 *     http://www.cablelabs.com/specifications/archives/PKT-SP-PROV-I05-021127.pdf (superseded by above)
 * CableHome(TM) 1.1 Specification
 *     http://www.cablelabs.com/projects/cablehome/downloads/specs/CH-SP-CH1.1-I05-040806.pdf
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

#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/strutil.h>

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

#define	PLURALIZE(n)	(((n) > 1) ? "s" : "")

enum field_type { none, ipv4, string, toggle, yes_no, special, opaque,
	time_in_secs,
	val_u_byte, val_u_short, val_u_le_short, val_u_long,
	val_s_long, fqdn, ipv4_or_fqdn, bytes };

struct opt_info {
	char	*text;
	enum field_type ftype;
};

static const true_false_string flag_set_broadcast = {
  "Broadcast",
  "Unicast"
};


/* PacketCable definitions */
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
    int optp);
static int dissect_vendor_cablelabs_suboption(proto_tree *v_tree, tvbuff_t *tvb,
    int optp);
static int dissect_netware_ip_suboption(proto_tree *v_tree, tvbuff_t *tvb,
    int optp);
static int bootp_dhcp_decode_agent_info(proto_tree *v_tree, tvbuff_t *tvb,
    int optp);
static void dissect_packetcable_mta_cap(proto_tree *v_tree, tvbuff_t *tvb,
       int voff, int len);
static void dissect_docsis_cm_cap(proto_tree *v_tree, tvbuff_t *tvb,
       int voff, int len);
static int dissect_packetcable_i05_ccc(proto_tree *v_tree, tvbuff_t *tvb, int optp);
static int dissect_packetcable_ietf_ccc(proto_tree *v_tree, tvbuff_t *tvb, int optp, int revision);


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

/* Returns the number of bytes consumed by this option. */
static int
bootp_option(tvbuff_t *tvb, proto_tree *bp_tree, int voff, int eoff,
    gboolean first_pass, gboolean *at_end, const char **dhcp_type_p,
    const guint8 **vendor_class_id_p)
{
	char			*text;
	enum field_type		ftype;
	guchar			code = tvb_get_guint8(tvb, voff);
	int			vlen;
	guchar			byte;
	int			i,optp, consumed;
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
		/*   0 */ { "Padding",					none },
		/*   1 */ { "Subnet Mask",				ipv4 },
		/*   2 */ { "Time Offset",				time_in_secs },
		/*   3 */ { "Router",					ipv4 },
		/*   4 */ { "Time Server",				ipv4 },
		/*   5 */ { "Name Server",				ipv4 },
		/*   6 */ { "Domain Name Server",			ipv4 },
		/*   7 */ { "Log Server",				ipv4 },
		/*   8 */ { "Cookie Server",				ipv4 },
		/*   9 */ { "LPR Server",				ipv4 },
		/*  10 */ { "Impress Server",				ipv4 },
		/*  11 */ { "Resource Location Server",			ipv4 },
		/*  12 */ { "Host Name",				string },
		/*  13 */ { "Boot File Size",				val_u_short },
		/*  14 */ { "Merit Dump File",				string },
		/*  15 */ { "Domain Name",				string },
		/*  16 */ { "Swap Server",				ipv4 },
		/*  17 */ { "Root Path",				string },
		/*  18 */ { "Extensions Path",				string },
		/*  19 */ { "IP Forwarding",				toggle },
		/*  20 */ { "Non-Local Source Routing",			toggle },
		/*  21 */ { "Policy Filter",				special },
		/*  22 */ { "Maximum Datagram Reassembly Size",		val_u_short },
		/*  23 */ { "Default IP Time-to-Live",			val_u_byte },
		/*  24 */ { "Path MTU Aging Timeout",			time_in_secs },
		/*  25 */ { "Path MTU Plateau Table",			val_u_short },
		/*  26 */ { "Interface MTU",				val_u_short },
		/*  27 */ { "All Subnets are Local",			yes_no },
		/*  28 */ { "Broadcast Address",			ipv4 },
		/*  29 */ { "Perform Mask Discovery",			toggle },
		/*  30 */ { "Mask Supplier",				yes_no },
		/*  31 */ { "Perform Router Discover",			toggle },
		/*  32 */ { "Router Solicitation Address",		ipv4 },
		/*  33 */ { "Static Route",				special },
		/*  34 */ { "Trailer Encapsulation",			toggle },
		/*  35 */ { "ARP Cache Timeout",			time_in_secs },
		/*  36 */ { "Ethernet Encapsulation",			toggle },
		/*  37 */ { "TCP Default TTL", 				val_u_byte },
		/*  38 */ { "TCP Keepalive Interval",			time_in_secs },
		/*  39 */ { "TCP Keepalive Garbage",			toggle },
		/*  40 */ { "Network Information Service Domain",	string },
		/*  41 */ { "Network Information Service Servers",	ipv4 },
		/*  42 */ { "Network Time Protocol Servers",		ipv4 },
		/*  43 */ { "Vendor-Specific Information",		special },
		/*  44 */ { "NetBIOS over TCP/IP Name Server",		ipv4 },
		/*  45 */ { "NetBIOS over TCP/IP Datagram Distribution Name Server", ipv4 },
		/*  46 */ { "NetBIOS over TCP/IP Node Type",		special },
		/*  47 */ { "NetBIOS over TCP/IP Scope",		string },
		/*  48 */ { "X Window System Font Server",		ipv4 },
		/*  49 */ { "X Window System Display Manager",		ipv4 },
		/*  50 */ { "Requested IP Address",			ipv4 },
		/*  51 */ { "IP Address Lease Time",			time_in_secs },
		/*  52 */ { "Option Overload",				special },
		/*  53 */ { "DHCP Message Type",			special },
		/*  54 */ { "Server Identifier",			ipv4 },
		/*  55 */ { "Parameter Request List",			special },
		/*  56 */ { "Message",					string },
		/*  57 */ { "Maximum DHCP Message Size",		val_u_short },
		/*  58 */ { "Renewal Time Value",			time_in_secs },
		/*  59 */ { "Rebinding Time Value",			time_in_secs },
		/*  60 */ { "Vendor class identifier",			special },
		/*  61 */ { "Client identifier",			special },
		/*  62 */ { "Novell/Netware IP domain",			string },
		/*  63 */ { "Novell Options",				special },
		/*  64 */ { "Network Information Service+ Domain",	string },
		/*  65 */ { "Network Information Service+ Servers",	ipv4 },
		/*  66 */ { "TFTP Server Name",				string },
		/*  67 */ { "Bootfile name",				string },
		/*  68 */ { "Mobile IP Home Agent",			ipv4 },
		/*  69 */ { "SMTP Server",				ipv4 },
		/*  70 */ { "POP3 Server",				ipv4 },
		/*  71 */ { "NNTP Server",				ipv4 },
		/*  72 */ { "Default WWW Server",			ipv4 },
		/*  73 */ { "Default Finger Server",			ipv4 },
		/*  74 */ { "Default IRC Server",			ipv4 },
		/*  75 */ { "StreetTalk Server",			ipv4 },
		/*  76 */ { "StreetTalk Directory Assistance Server",	ipv4 },
		/*  77 */ { "User Class Information",			opaque },
		/*  78 */ { "Directory Agent Information",		special },
		/*  79 */ { "Service Location Agent Scope",		special },
		/*  80 */ { "Naming Authority",				opaque },
		/*  81 */ { "Client Fully Qualified Domain Name",	special },
		/*  82 */ { "Agent Information Option",                 special },
		/*  83 */ { "Unassigned",				opaque },
		/*  84 */ { "Unassigned",				opaque },
		/*  85 */ { "Novell Directory Services Servers",	special },
		/*  86 */ { "Novell Directory Services Tree Name",	string },
		/*  87 */ { "Novell Directory Services Context",	string },
		/*  88 */ { "IEEE 1003.1 POSIX Timezone",		opaque },
		/*  89 */ { "Fully Qualified Domain Name",		opaque },
		/*  90 */ { "Authentication",				special },
		/*  91 */ { "Vines TCP/IP Server Option",		opaque },
		/*  92 */ { "Server Selection Option",			opaque },
		/*  93 */ { "Client System Architecture",		opaque },
		/*  94 */ { "Client Network Device Interface",		opaque },
		/*  95 */ { "Lightweight Directory Access Protocol",	opaque },
		/*  96 */ { "IPv6 Transitions",				opaque },
		/*  97 */ { "UUID/GUID-based Client Identifier",	opaque },
		/*  98 */ { "Open Group's User Authentication",		opaque },
		/*  99 */ { "Unassigned",				opaque },
		/* 100 */ { "Printer Name",				opaque },
		/* 101 */ { "MDHCP multicast address",			opaque },
		/* 102 */ { "Removed/unassigned",			opaque },
		/* 103 */ { "Removed/unassigned",			opaque },
		/* 104 */ { "Removed/unassigned",			opaque },
		/* 105 */ { "Removed/unassigned",			opaque },
		/* 106 */ { "Removed/unassigned",			opaque },
		/* 107 */ { "Removed/unassigned",			opaque },
		/* 108 */ { "Swap Path Option",				opaque },
		/* 109 */ { "Unassigned",				opaque },
		/* 110 */ { "IPX Compability",				opaque },
		/* 111 */ { "Unassigned",				opaque },
		/* 112 */ { "NetInfo Parent Server Address",		ipv4 },
		/* 113 */ { "NetInfo Parent Server Tag",		string },
		/* 114 */ { "URL",					opaque },
		/* 115 */ { "DHCP Failover Protocol",			opaque },
		/* 116 */ { "DHCP Auto-Configuration",			opaque },
		/* 117 */ { "Name Service Search",		       	opaque },
		/* 118 */ { "Subnet Selection Option",		       	opaque },
		/* 119 */ { "Domain Search",				opaque },
		/* 120 */ { "SIP Servers",				opaque },
		/* 121 */ { "Classless Static Route",		       	opaque },
		/* 122 */ { "CableLabs Client Configuration",		opaque },
		/* 123 */ { "Unassigned",				opaque },
		/* 124 */ { "Unassigned",				opaque },
		/* 125 */ { "Unassigned",				opaque },
		/* 126 */ { "Extension",				opaque },
		/* 127 */ { "Extension",				opaque },
		/* 128 */ { "Private",					opaque },
		/* 129 */ { "Private",					opaque },
		/* 130 */ { "Private",					opaque },
		/* 131 */ { "Private",					opaque },
		/* 132 */ { "Private",					opaque },
		/* 133 */ { "Private",					opaque },
		/* 134 */ { "Private",					opaque },
		/* 135 */ { "Private",					opaque },
		/* 136 */ { "Private",					opaque },
		/* 137 */ { "Private",					opaque },
		/* 138 */ { "Private",					opaque },
		/* 139 */ { "Private",					opaque },
		/* 140 */ { "Private",					opaque },
		/* 141 */ { "Private",					opaque },
		/* 142 */ { "Private",					opaque },
		/* 143 */ { "Private",					opaque },
		/* 144 */ { "Private",					opaque },
		/* 145 */ { "Private",					opaque },
		/* 146 */ { "Private",					opaque },
		/* 147 */ { "Private",					opaque },
		/* 148 */ { "Private",					opaque },
		/* 149 */ { "Private",					opaque },
		/* 150 */ { "Private",					opaque },
		/* 151 */ { "Private",					opaque },
		/* 152 */ { "Private",					opaque },
		/* 153 */ { "Private",					opaque },
		/* 154 */ { "Private",					opaque },
		/* 155 */ { "Private",					opaque },
		/* 156 */ { "Private",					opaque },
		/* 157 */ { "Private",					opaque },
		/* 158 */ { "Private",					opaque },
		/* 159 */ { "Private",					opaque },
		/* 160 */ { "Private",					opaque },
		/* 161 */ { "Private",					opaque },
		/* 162 */ { "Private",					opaque },
		/* 163 */ { "Private",					opaque },
		/* 164 */ { "Private",					opaque },
		/* 165 */ { "Private",					opaque },
		/* 166 */ { "Private",					opaque },
		/* 167 */ { "Private",					opaque },
		/* 168 */ { "Private",					opaque },
		/* 169 */ { "Private",					opaque },
		/* 170 */ { "Private",					opaque },
		/* 171 */ { "Private",					opaque },
		/* 172 */ { "Private",					opaque },
		/* 173 */ { "Private",					opaque },
		/* 174 */ { "Private",					opaque },
		/* 175 */ { "Private",					opaque },
		/* 176 */ { "Private",					opaque },
		/* 177 */ { "Private",					opaque },
		/* 178 */ { "Private",					opaque },
		/* 179 */ { "Private",					opaque },
		/* 180 */ { "Private",					opaque },
		/* 181 */ { "Private",					opaque },
		/* 182 */ { "Private",					opaque },
		/* 183 */ { "Private",					opaque },
		/* 184 */ { "Private",					opaque },
		/* 185 */ { "Private",					opaque },
		/* 186 */ { "Private",					opaque },
		/* 187 */ { "Private",					opaque },
		/* 188 */ { "Private",					opaque },
		/* 189 */ { "Private",					opaque },
		/* 190 */ { "Private",					opaque },
		/* 191 */ { "Private",					opaque },
		/* 192 */ { "Private",					opaque },
		/* 193 */ { "Private",					opaque },
		/* 194 */ { "Private",					opaque },
		/* 195 */ { "Private",					opaque },
		/* 196 */ { "Private",					opaque },
		/* 197 */ { "Private",					opaque },
		/* 198 */ { "Private",					opaque },
		/* 199 */ { "Private",					opaque },
		/* 200 */ { "Private",					opaque },
		/* 201 */ { "Private",					opaque },
		/* 202 */ { "Private",					opaque },
		/* 203 */ { "Private",					opaque },
		/* 204 */ { "Private",					opaque },
		/* 205 */ { "Private",					opaque },
		/* 206 */ { "Private",					opaque },
		/* 207 */ { "Private",					opaque },
		/* 208 */ { "Private",					opaque },
		/* 209 */ { "Private",					opaque },
		/* 210 */ { "Authentication",				special }
	};

	/* Options whose length isn't "vlen + 2". */
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
	vlen = tvb_get_guint8(tvb, voff+1);
	consumed = vlen + 2;

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

	text = opt[code].text;
	/* Special cases */
	switch (code) {

	case 21:	/* Policy Filter */
		if (vlen == 8) {
			/* one IP address pair */
			proto_tree_add_text(bp_tree, tvb, voff, consumed,
				"Option %d: %s = %s/%s", code, text,
				ip_to_str(tvb_get_ptr(tvb, voff+2, 4)),
				ip_to_str(tvb_get_ptr(tvb, voff+6, 4)));
		} else {
			/* > 1 IP address pair. Let's make a sub-tree */
			vti = proto_tree_add_text(bp_tree, tvb, voff,
				consumed, "Option %d: %s", code, text);
			v_tree = proto_item_add_subtree(vti, ett_bootp_option);
			for (i = voff + 2; i < voff + consumed; i += 8) {
				proto_tree_add_text(v_tree, tvb, i, 8, "IP Address/Mask: %s/%s",
					ip_to_str(tvb_get_ptr(tvb, i, 4)),
					ip_to_str(tvb_get_ptr(tvb, i+4, 4)));
			}
		}
		break;

	case 33:	/* Static Route */
		if (vlen == 8) {
			/* one IP address pair */
			proto_tree_add_text(bp_tree, tvb, voff, consumed,
				"Option %d: %s = %s/%s", code, text,
				ip_to_str(tvb_get_ptr(tvb, voff+2, 4)),
				ip_to_str(tvb_get_ptr(tvb, voff+6, 4)));
		} else {
			/* > 1 IP address pair. Let's make a sub-tree */
			vti = proto_tree_add_text(bp_tree, tvb, voff,
				consumed, "Option %d: %s", code, text);
			v_tree = proto_item_add_subtree(vti, ett_bootp_option);
			for (i = voff + 2; i < voff + consumed; i += 8) {
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

			optp = voff+2;
			while (optp < voff+consumed) {
				optp = dissect_vendor_pxeclient_suboption(v_tree,
					tvb, optp);
			}
		} else if (*vendor_class_id_p != NULL &&
			   ((strncmp(*vendor_class_id_p, "pktc", strlen("pktc")) == 0) ||
                            (strncmp(*vendor_class_id_p, "docsis", strlen("docsis")) == 0) ||
                            (strncmp(*vendor_class_id_p, "CableHome", strlen("CableHome")) == 0))) {
		        /* CableLabs standard - see www.cablelabs.com/projects */
		        vti = proto_tree_add_text(bp_tree, tvb, voff,
				consumed, "Option %d: %s (CableLabs)", code, text);
			v_tree = proto_item_add_subtree(vti, ett_bootp_option);

			optp = voff+2;
			while (optp < voff+consumed) {
			        optp = dissect_vendor_cablelabs_suboption(v_tree,
					tvb, optp);
			}
		} else {
			proto_tree_add_text(bp_tree, tvb, voff, consumed,
				"Option %d: %s (%d bytes)", code, text, vlen);
		}
		break;

	case 46:	/* NetBIOS-over-TCP/IP Node Type */
		byte = tvb_get_guint8(tvb, voff+2);
		proto_tree_add_text(bp_tree, tvb, voff, consumed,
				"Option %d: %s = %s", code, text,
				val_to_str(byte, nbnt_vals,
				    "Unknown (0x%02x)"));
		break;

	case 52:	/* Option Overload */
		byte = tvb_get_guint8(tvb, voff+2);
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

/*		protocol = tvb_get_guint8(tvb, voff+2);
		proto_tree_add_text(v_tree, tvb, voff+2, 1, "Protocol: %s (%u)",
				    val_to_str(protocol, authen_protocol_vals, "Unknown"),
				    protocol); */
		break;
	case 53:	/* DHCP Message Type */
		proto_tree_add_text(bp_tree, tvb, voff, 3, "Option %d: %s = DHCP %s",
			code, text, get_dhcp_type(tvb_get_guint8(tvb, voff+2)));
		break;

	case 55:	/* Parameter Request List */
		vti = proto_tree_add_text(bp_tree, tvb, voff,
			vlen + 2, "Option %d: %s", code, text);
		v_tree = proto_item_add_subtree(vti, ett_bootp_option);
		for (i = 0; i < vlen; i++) {
			byte = tvb_get_guint8(tvb, voff+2+i);
			if (byte < array_length(opt)) {
				proto_tree_add_text(v_tree, tvb, voff+2+i, 1, "%d = %s",
						byte, opt[byte].text);
			} else {
				proto_tree_add_text(vti, tvb, voff+2+i, 1,
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
			tvb_format_stringzpad(tvb, voff+2, consumed-2));
		if ((tvb_memeql(tvb, voff+2, PACKETCABLE_MTA_CAP10, strlen(PACKETCABLE_MTA_CAP10)) == 0) ||
			(tvb_memeql(tvb, voff+2, PACKETCABLE_MTA_CAP15, strlen(PACKETCABLE_MTA_CAP10)) == 0)) {
			v_tree = proto_item_add_subtree(vti, ett_bootp_option);
			dissect_packetcable_mta_cap(v_tree, tvb, voff+2, vlen);
		} else if (tvb_memeql(tvb, voff+2, PACKETCABLE_CM_CAP11, strlen(PACKETCABLE_CM_CAP11)) == 0 ||
				tvb_memeql(tvb, voff+2, PACKETCABLE_CM_CAP20, strlen(PACKETCABLE_CM_CAP20)) == 0 ) {
			v_tree = proto_item_add_subtree(vti, ett_bootp_option);
			dissect_docsis_cm_cap(v_tree, tvb, voff+2, vlen);
		}
		break;

	case 61:	/* Client Identifier */
		if (vlen > 0)
			byte = tvb_get_guint8(tvb, voff+2);
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

		if (vlen == 7 && byte > 0 && byte < 48) {

			vti = proto_tree_add_text(bp_tree, tvb, voff,
				consumed, "Option %d: %s", code, text);
			v_tree = proto_item_add_subtree(vti, ett_bootp_option);
			proto_tree_add_text(v_tree, tvb, voff+2, 1,
				"Hardware type: %s",
				arphrdtype_to_str(byte,
					"Unknown (0x%02x)"));
			proto_tree_add_text(v_tree, tvb, voff+3, 6,
				"Client hardware address: %s",
				arphrdaddr_to_str(tvb_get_ptr(tvb, voff+3, 6),
					6, byte));
		} else {
			/* otherwise, it's opaque data */
			proto_tree_add_text(bp_tree, tvb, voff, consumed,
				"Option %d: %s (%d bytes)", code, text, vlen);
		}
		break;

	case 63:	/* NetWare/IP options */
		vti = proto_tree_add_text(bp_tree, tvb, voff,
		    consumed, "Option %d: %s", code, text);
		v_tree = proto_item_add_subtree(vti, ett_bootp_option);

		optp = voff+2;
		while (optp < voff+consumed)
			optp = dissect_netware_ip_suboption(v_tree, tvb, optp);
		break;

	case 78:	/* SLP Directory Agent Option RFC2610 Added by Greg Morris (gmorris@novell.com)*/
		byte = tvb_get_guint8(tvb, voff+2);
		vti = proto_tree_add_text(bp_tree, tvb, voff, consumed,
				"Option %d: %s = %s", code, text,
				val_to_str(byte, slpda_vals,
				    "Unknown (0x%02x)"));
		if (byte == 0x80) {
			voff++;
			consumed--;
		}
		v_tree = proto_item_add_subtree(vti, ett_bootp_option);
		for (i = voff + 3; i < voff + consumed; i += 4) {
			proto_tree_add_text(v_tree, tvb, i, 4, "SLPDA Address: %s",
			    ip_to_str(tvb_get_ptr(tvb, i, 4)));
		}
		if (byte == 0x80) {
			consumed++;
		}
		break;

	case 79:	/* SLP Service Scope Option RFC2610 Added by Greg Morris (gmorris@novell.com)*/
		byte = tvb_get_guint8(tvb, voff+2);
		vti = proto_tree_add_text(bp_tree, tvb, voff, consumed,
				"Option %d: %s = %s", code, text,
				val_to_str(byte, slp_scope_vals,
				    "Unknown (0x%02x)"));
		v_tree = proto_item_add_subtree(vti, ett_bootp_option);
		proto_tree_add_text(v_tree, tvb, voff+3, consumed-3,
		    "%s = \"%s\"", text,
		    tvb_format_stringzpad(tvb, voff+3, vlen-1));
		break;

	case 81:	/* Client Fully Qualified Domain Name */
		vti = proto_tree_add_text(bp_tree, tvb, voff, consumed,
				"Option %d: FQDN", code);
		v_tree = proto_item_add_subtree(vti, ett_bootp_option);
		fqdn_flags = tvb_get_guint8(tvb, voff+2);
		ft = proto_tree_add_text(v_tree, tvb, voff+2, 1, "Flags: 0x%02x", fqdn_flags);
		flags_tree = proto_item_add_subtree(ft, ett_bootp_fqdn);
		proto_tree_add_item(flags_tree, hf_bootp_fqdn_mbz, tvb, voff+2, 1, FALSE);
		proto_tree_add_item(flags_tree, hf_bootp_fqdn_n, tvb, voff+2, 1, FALSE);
		proto_tree_add_item(flags_tree, hf_bootp_fqdn_e, tvb, voff+2, 1, FALSE);
		proto_tree_add_item(flags_tree, hf_bootp_fqdn_o, tvb, voff+2, 1, FALSE);
		proto_tree_add_item(flags_tree, hf_bootp_fqdn_s, tvb, voff+2, 1, FALSE);
		/* XXX: use code from packet-dns for return code decoding */
		proto_tree_add_item(v_tree, hf_bootp_fqdn_rcode1, tvb, voff+3, 1, FALSE);
		/* XXX: use code from packet-dns for return code decoding */
		proto_tree_add_item(v_tree, hf_bootp_fqdn_rcode2, tvb, voff+4, 1, FALSE);
		if (fqdn_flags & F_FQDN_E) {
			/* XXX: use code from packet-dns for binary encoded name */
			proto_tree_add_item(v_tree, hf_bootp_fqdn_name, tvb, voff+5,
				vlen-5, FALSE);

		} else {
			proto_tree_add_item(v_tree, hf_bootp_fqdn_asciiname, tvb, voff+5,
				vlen-5, FALSE);
		}
		break;

	case 82:        /* Relay Agent Information Option */
		vti = proto_tree_add_text(bp_tree, tvb, voff, consumed,
					  "Option %d: %s (%d bytes)",
					  code, text, vlen);
		v_tree = proto_item_add_subtree(vti, ett_bootp_option);
		optp = voff+2;
		while (optp < voff+consumed) {
			optp = bootp_dhcp_decode_agent_info(v_tree, tvb, optp);
		}
		break;

	case 85:        /* Novell Servers */
		/* Option 85 can be sent as a string */
		/* Added by Greg Morris (gmorris[AT]novell.com) */
		if (novell_string) {
			proto_tree_add_text(bp_tree, tvb, voff, consumed,
			    "Option %d: %s = \"%s\"", code, text,
			    tvb_format_stringzpad(tvb, voff+2, consumed-2));
		} else {
			if (vlen == 4) {
				/* one IP address */
				proto_tree_add_text(bp_tree, tvb, voff, consumed,
					"Option %d: %s = %s", code, text,
					ip_to_str(tvb_get_ptr(tvb, voff+2, 4)));
			} else {
				/* > 1 IP addresses. Let's make a sub-tree */
				vti = proto_tree_add_text(bp_tree, tvb, voff,
					consumed, "Option %d: %s", code, text);
				v_tree = proto_item_add_subtree(vti, ett_bootp_option);
				for (i = voff + 2; i < voff + consumed; i += 4) {
					proto_tree_add_text(v_tree, tvb, i, 4, "IP Address: %s",
						ip_to_str(tvb_get_ptr(tvb, i, 4)));
				}
			}
        }
        break;

	case 90:	/* DHCP Authentication */
	case 210:	/* Was this used for authentication at one time? */
		vti = proto_tree_add_text(bp_tree, tvb, voff,
			vlen + 2, "Option %d: %s", code, text);
		v_tree = proto_item_add_subtree(vti, ett_bootp_option);

		protocol = tvb_get_guint8(tvb, voff+2);
		proto_tree_add_text(v_tree, tvb, voff+2, 1, "Protocol: %s (%u)",
				    val_to_str(protocol, authen_protocol_vals, "Unknown"),
				    protocol);

		algorithm = tvb_get_guint8(tvb, voff+3);
		switch (protocol) {

		case AUTHEN_PROTO_DELAYED_AUTHEN:
			proto_tree_add_text(v_tree, tvb, voff+3, 1,
				    "Algorithm: %s (%u)",
				    val_to_str(algorithm, authen_da_algo_vals, "Unknown"),
				    algorithm);
			break;

		default:
			proto_tree_add_text(v_tree, tvb, voff+3, 1,
				    "Algorithm: %u", algorithm);
			break;
		}

		rdm = tvb_get_guint8(tvb, voff+4);
		proto_tree_add_text(v_tree, tvb, voff+4, 1,
				    "Replay Detection Method: %s (%u)",
				    val_to_str(rdm, authen_rdm_vals, "Unknown"),
				    rdm);

		switch (rdm) {

		case AUTHEN_RDM_MONOTONIC_COUNTER:
			proto_tree_add_text(v_tree, tvb, voff+5, 8,
				    "Replay Detection Value: %" PRIx64,
				    tvb_get_ntoh64(tvb, voff+5));
			break;

		default:
			proto_tree_add_text(v_tree, tvb, voff+5, 8,
				    "Replay Detection Value: %s",
				    tvb_bytes_to_str(tvb, voff+5, 8));
			break;
		}

		switch (protocol) {

		case AUTHEN_PROTO_DELAYED_AUTHEN:
			switch (algorithm) {

			case AUTHEN_DELAYED_ALGO_HMAC_MD5:
				proto_tree_add_text(v_tree, tvb, voff+13, 4,
					"Secret ID: 0x%08x",
					tvb_get_ntohl(tvb, voff+13));
				proto_tree_add_text(v_tree, tvb, voff+17, 16,
					"HMAC MD5 Hash: %s",
					tvb_bytes_to_str(tvb, voff+17, 16));
				break;

			default:
				proto_tree_add_text(v_tree, tvb, voff+13, vlen-11,
					"Authentication Information: %s",
					tvb_bytes_to_str(tvb, voff+17, vlen-11));
				break;
			}
			break;

		default:
			proto_tree_add_text(v_tree, tvb, voff+13, vlen-11,
				"Authentication Information: %s",
				tvb_bytes_to_str(tvb, voff+17, vlen-11));
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
						  code, vlen);
			v_tree = proto_item_add_subtree(vti, ett_bootp_option);
			optp = voff+2;
			while (optp < voff+consumed) {
				switch (pkt_ccc_protocol_version) {
					case PACKETCABLE_CCC_I05:
						optp = dissect_packetcable_i05_ccc(v_tree, tvb, optp);
						break;
					case PACKETCABLE_CCC_DRAFT5:
					case PACKETCABLE_CCC_RFC_3495:
						optp = dissect_packetcable_ietf_ccc(v_tree, tvb, optp, pkt_ccc_protocol_version);
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

		switch (ftype) {

		case special:
			return consumed;

		case ipv4:
			if (vlen == 4) {
				/* one IP address */
				proto_tree_add_text(bp_tree, tvb, voff, consumed,
					"Option %d: %s = %s", code, text,
					ip_to_str(tvb_get_ptr(tvb, voff+2, 4)));
			} else {
				/* > 1 IP addresses. Let's make a sub-tree */
				vti = proto_tree_add_text(bp_tree, tvb, voff,
					consumed, "Option %d: %s", code, text);
				v_tree = proto_item_add_subtree(vti, ett_bootp_option);
				for (i = voff + 2; i < voff + consumed; i += 4) {
					proto_tree_add_text(v_tree, tvb, i, 4, "IP Address: %s",
						ip_to_str(tvb_get_ptr(tvb, i, 4)));
				}
			}
			break;

		case string:
			/* Fix for non null-terminated string supplied by
			 * John Lines <John.Lines[AT]aeat.co.uk>
			 */
			proto_tree_add_text(bp_tree, tvb, voff, consumed,
					"Option %d: %s = \"%s\"", code, text,
					tvb_format_stringzpad(tvb, voff+2, consumed-2));
			break;

		case opaque:
			if (! skip_opaque) { /* Currently used by PacketCable CCC */
				proto_tree_add_text(bp_tree, tvb, voff, consumed,
						"Option %d: %s (%d bytes)",
						code, text, vlen);
			}
			break;

		case val_u_short:
			if (vlen == 2) {
				/* one gushort */
				proto_tree_add_text(bp_tree, tvb, voff, consumed,
						"Option %d: %s = %d", code, text,
						tvb_get_ntohs(tvb, voff+2));
			} else {
				/* > 1 gushort */
				vti = proto_tree_add_text(bp_tree, tvb, voff,
					consumed, "Option %d: %s", code, text);
				v_tree = proto_item_add_subtree(vti, ett_bootp_option);
				for (i = voff + 2; i < voff + consumed; i += 2) {
					proto_tree_add_text(v_tree, tvb, i, 4, "Value: %d",
						tvb_get_ntohs(tvb, i));
				}
			}
			break;

		case val_u_long:
			proto_tree_add_text(bp_tree, tvb, voff, consumed,
					"Option %d: %s = %d", code, text,
					tvb_get_ntohl(tvb, voff+2));
			break;

		case val_u_byte:
			proto_tree_add_text(bp_tree, tvb, voff, consumed,
					"Option %d: %s = %d", code, text,
					tvb_get_guint8(tvb, voff+2));
			break;

		case toggle:
			i = tvb_get_guint8(tvb, voff+2);
			if (i != 0 && i != 1) {
				proto_tree_add_text(bp_tree, tvb, voff, consumed,
						"Option %d: %s = Invalid Value %d", code, text,
						i);
			} else {
				proto_tree_add_text(bp_tree, tvb, voff, consumed,
						"Option %d: %s = %s", code, text,
						i == 0 ? "Disabled" : "Enabled");
			}
			break;

		case yes_no:
			i = tvb_get_guint8(tvb, voff+2);
			if (i != 0 && i != 1) {
				proto_tree_add_text(bp_tree, tvb, voff, consumed,
						"Option %d: %s = Invalid Value %d", code, text,
						i);
			} else {
				proto_tree_add_text(bp_tree, tvb, voff, consumed,
						"Option %d: %s = %s", code, text,
						i == 0 ? "No" : "Yes");
			}
			break;

		case time_in_secs:
			time_secs = tvb_get_ntohl(tvb, voff+2);
			proto_tree_add_text(bp_tree, tvb, voff, consumed,
				"Option %d: %s = %s", code, text,
				((time_secs == 0xffffffff) ?
				    "infinity" :
				    time_secs_to_str(time_secs)));
			break;

		default:
			proto_tree_add_text(bp_tree, tvb, voff, consumed,
					"Option %d: %s (%d bytes)", code, text, vlen);
		}
	} else {
		proto_tree_add_text(bp_tree, tvb, voff, consumed,
				"Unknown Option Code: %d (%d bytes)", code, vlen);
	}

	return consumed;
}

static int
bootp_dhcp_decode_agent_info(proto_tree *v_tree, tvbuff_t *tvb, int optp)
{
	guint8 subopt;
	guint8 subopt_len;

	subopt = tvb_get_guint8(tvb, optp);
	subopt_len = tvb_get_guint8(tvb, optp+1);
	switch (subopt) {
	case 1:
		proto_tree_add_text(v_tree, tvb, optp, subopt_len + 2,
				    "Agent Circuit ID: %s",
				    tvb_bytes_to_str(tvb, optp+2, subopt_len));
		break;
	case 2:
		proto_tree_add_text(v_tree, tvb, optp, subopt_len + 2,
				    "Agent Remote ID: %s",
				    tvb_bytes_to_str(tvb, optp+2, subopt_len));
		break;
	default:
		proto_tree_add_text(v_tree, tvb, optp, subopt_len + 2,
				    "Invalid agent suboption %d (%d bytes)",
				    subopt, subopt_len);
		break;
	}
	optp += (subopt_len + 2);
	return optp;
}

static int
dissect_vendor_pxeclient_suboption(proto_tree *v_tree, tvbuff_t *tvb, int optp)
{
	guint8 subopt;
	guint8 subopt_len;
	int slask;
	proto_tree *o43pxeclient_v_tree;
	proto_item *vti;

	struct o43pxeclient_opt_info {
		char	*text;
		enum field_type	ft;
	};

	static struct o43pxeclient_opt_info o43pxeclient_opt[]= {
		/* 0 */ {"nop", special},	/* dummy */
		/* 1 */ {"PXE mtftp IP", ipv4},
		/* 2 */ {"PXE mtftp client port", val_u_le_short},
		/* 3 */ {"PXE mtftp server port",val_u_le_short},
		/* 4 */ {"PXE mtftp timeout", val_u_byte},
		/* 5 */ {"PXE mtftp delay", val_u_byte},
		/* 6 */ {"PXE discovery control", val_u_byte},
			/*
			 * Correct: b0 (lsb): disable broadcast discovery
			 *	b1: disable multicast discovery
			 *	b2: only use/accept servers in boot servers
			 *	b3: download bootfile without prompt/menu/disc
			 */
		/* 7 */ {"PXE multicast address", ipv4},
		/* 8 */ {"PXE boot servers", special},
		/* 9 */ {"PXE boot menu", special},
		/* 10 */ {"PXE menu prompt", special},
		/* 11 */ {"PXE multicast address alloc", special},
		/* 12 */ {"PXE credential types", special},
		/* 71 {"PXE boot item", special} */
		/* 255 {"PXE end options", special} */
	};

	subopt = tvb_get_guint8(tvb, optp);

	if (subopt == 0 ) {
		proto_tree_add_text(v_tree, tvb, optp, 1, "Padding");
                return (optp+1);
	} else if (subopt == 255) {	/* End Option */
		proto_tree_add_text(v_tree, tvb, optp, 1, "End PXEClient option");
		/* Make sure we skip any junk left this option */
		return (optp+255);
	}

	subopt_len = tvb_get_guint8(tvb, optp+1);

	if ( subopt == 71 ) {	/* 71 {"PXE boot item", special} */
		/* case special */
		/* I may need to decode that properly one day */
		proto_tree_add_text(v_tree, tvb, optp, subopt_len+2,
			"Suboption %d: %s (%d byte%s)" ,
	 		subopt, "PXE boot item",
			subopt_len, plurality(subopt_len, "", "s"));
	} else if ((subopt < 1 ) || (subopt > array_length(o43pxeclient_opt))) {
		proto_tree_add_text(v_tree, tvb, optp, subopt_len+2,
			"Unknown suboption %d (%d byte%s)", subopt, subopt_len,
			plurality(subopt_len, "", "s"));
	} else {
		switch (o43pxeclient_opt[subopt].ft) {

/* XXX		case string:
			proto_tree_add_text(v_tree, tvb, optp, subopt_len+2,
				"Suboption %d: %s", subopt, o43pxeclient_opt[subopt].text);
			break;
   XXX */
		case special:
			/* I may need to decode that properly one day */
			proto_tree_add_text(v_tree, tvb, optp, subopt_len+2,
				"Suboption %d: %s (%d byte%s)" ,
		 		subopt, o43pxeclient_opt[subopt].text,
				subopt_len, plurality(subopt_len, "", "s"));
			break;

		case val_u_le_short:
			proto_tree_add_text(v_tree, tvb, optp, 4, "Suboption %d: %s = %u",
			    subopt, o43pxeclient_opt[subopt].text,
			    tvb_get_letohs(tvb, optp+2));
			break;

		case val_u_byte:
			proto_tree_add_text(v_tree, tvb, optp, 3, "Suboption %d: %s = %u",
			    subopt, o43pxeclient_opt[subopt].text,
			    tvb_get_guint8(tvb, optp+2));
			break;

		case ipv4:
			if (subopt_len == 4) {
				/* one IP address */
				proto_tree_add_text(v_tree, tvb, optp, 6,
				    "Suboption %d : %s = %s",
				    subopt, o43pxeclient_opt[subopt].text,
				    ip_to_str(tvb_get_ptr(tvb, optp+2, 4)));
			} else {
				/* > 1 IP addresses. Let's make a sub-tree */
				vti = proto_tree_add_text(v_tree, tvb, optp,
				    subopt_len+2, "Suboption %d: %s",
				    subopt, o43pxeclient_opt[subopt].text);
				o43pxeclient_v_tree = proto_item_add_subtree(vti, ett_bootp_option);
				for (slask = optp + 2 ; slask < optp+subopt_len; slask += 4) {
					proto_tree_add_text(o43pxeclient_v_tree, tvb, slask, 4, "IP Address: %s",
					    ip_to_str(tvb_get_ptr(tvb, slask, 4)));
				}
			}
			break;
		default:
			proto_tree_add_text(v_tree, tvb, optp, subopt_len+2,"ERROR, please report: Unknown subopt type handler %d", subopt);
			break;
		}
	}
	optp += (subopt_len + 2);
	return optp;
}


static int
dissect_vendor_cablelabs_suboption(proto_tree *v_tree, tvbuff_t *tvb, int optp)
{
	guint8 subopt, byte_val;
	guint8 subopt_len;

	struct o43cablelabs_opt_info {
		char	*text;
		enum field_type	ft;
	};

	static struct o43cablelabs_opt_info o43cablelabs_opt[]= {
		/* 0 */ {"nop", special},	/* dummy */
		/* 1 */ {"Suboption Request List", string},
		/* 2 */ {"Device Type", string},
		/* 3 */ {"eSAFE Types", string},
		/* 4 */ {"Serial Number", string},
		/* 5 */ {"Hardware Version", string},
		/* 6 */ {"Software Version", string},
		/* 7 */ {"Boot ROM version", string},
		/* 8 */ {"Organizationally Unique Identifier", special},
		/* 9 */ {"Model Number", string},
		/* 10 */ {"Vendor Name", string},
		/* *** 11-30: CableHome *** */
		/* 11 */ {"Address Realm", special},
		/* 12 */ {"CM/PS System Description", string},
		/* 13 */ {"CM/PS Firmware Revision", string},
		/* 14 */ {"Firewall Policy File Version", string},
		/* 15 */ {"Unassigned (CableHome)", special},
		/* 16 */ {"Unassigned (CableHome)", special},
		/* 17 */ {"Unassigned (CableHome)", special},
		/* 18 */ {"Unassigned (CableHome)", special},
		/* 19 */ {"Unassigned (CableHome)", special},
		/* 20 */ {"Unassigned (CableHome)", special},
		/* 21 */ {"Unassigned (CableHome)", special},
		/* 22 */ {"Unassigned (CableHome)", special},
		/* 23 */ {"Unassigned (CableHome)", special},
		/* 24 */ {"Unassigned (CableHome)", special},
		/* 25 */ {"Unassigned (CableHome)", special},
		/* 26 */ {"Unassigned (CableHome)", special},
		/* 27 */ {"Unassigned (CableHome)", special},
		/* 28 */ {"Unassigned (CableHome)", special},
		/* 29 */ {"Unassigned (CableHome)", special},
		/* 30 */ {"Unassigned (CableHome)", special},
		/* *** 31-50: PacketCable *** */
		/* 31 */ {"MTA MAC Address", special},
		/* 32 */ {"Correlation ID", string},
		/* 33-50 {"Unassigned (PacketCable)", special}, */
		/* *** 51-127: CableLabs *** */
		/* 51-127 {"Unassigned (CableLabs)", special}, */
		/* *** 128-254: Vendors *** */
		/* 128-254 {"Unassigned (Vendors)", special}, */
		/* 255 {"end options", special} */
	};

	static const value_string cablehome_subopt11_vals[] = {
		{ 1, "PS WAN-Man" },
		{ 2, "PS WAN-Data" },
		{ 0, NULL }
	};

	subopt = tvb_get_guint8(tvb, optp);

	if (subopt == 0 ) {
		proto_tree_add_text(v_tree, tvb, optp, 1, "Padding");
                return (optp+1);
	} else if (subopt == 255) {	/* End Option */
		proto_tree_add_text(v_tree, tvb, optp, 1, "End CableLabs option");
		/* Make sure we skip any junk left this option */
		return (optp+255);
	}

	subopt_len = tvb_get_guint8(tvb, optp+1);

	if ( (subopt < 1 ) || (subopt > array_length(o43cablelabs_opt)) ) {
		proto_tree_add_text(v_tree, tvb, optp, subopt_len+2,
			"Suboption %d: Unassigned (%d byte%s)", subopt, subopt_len,
			plurality(subopt_len, "", "s"));
	} else {
		switch (o43cablelabs_opt[subopt].ft) {

		case string:
			proto_tree_add_text(v_tree, tvb, optp, subopt_len+2,
				"Suboption %d: %s = \"%s\"", subopt,
				o43cablelabs_opt[subopt].text,
				tvb_format_stringzpad(tvb, optp+2, subopt_len));
			break;

		case bytes:
			proto_tree_add_text(v_tree, tvb, optp, subopt_len+2,
				"Suboption %d: %s = 0x%s", subopt,
				o43cablelabs_opt[subopt].text,
				tvb_bytes_to_str(tvb, optp+2, subopt_len));
			break;

		case special:
			if ( subopt == 8 ) {	/* OUI */
				proto_tree_add_text(v_tree, tvb, optp, subopt_len+2,
					"Suboption %d: OUI = %s" ,
					subopt, bytes_to_str_punct(tvb_get_ptr(tvb, optp+2, 3), 3, ':'));
			} else if ( subopt == 11 ) { /* Address Realm */
				byte_val = tvb_get_guint8(tvb, optp + 2);
				proto_tree_add_text(v_tree, tvb, optp, subopt_len+2,
					"Suboption %d: %s = %s (0x%02x)",
					subopt, o43cablelabs_opt[subopt].text,
					val_to_str(byte_val, cablehome_subopt11_vals, "Unknown"), byte_val);
			} else if ( subopt == 31 ) { /* MTA MAC address */
				proto_tree_add_text(v_tree, tvb, optp, subopt_len+2,
					"Suboption %d: %s = %s",
					subopt,  o43cablelabs_opt[subopt].text,
					bytes_to_str_punct(tvb_get_ptr(tvb, optp+2, 6), 6, ':'));
			} else {
				proto_tree_add_text(v_tree, tvb, optp, subopt_len+2,
					"Suboption %d: %s (%d byte%s)" ,
					subopt, o43cablelabs_opt[subopt].text,
					subopt_len, plurality(subopt_len, "", "s"));
			}
			break;

		default:
			proto_tree_add_text(v_tree, tvb, optp, subopt_len+2,"ERROR, please report: Unknown subopt type handler %d", subopt);
			break;
		}
	}
	optp += (subopt_len + 2);
	return optp;
}



static int
dissect_netware_ip_suboption(proto_tree *v_tree, tvbuff_t *tvb, int optp)
{
	guint8 subopt;
	guint8 subopt_len;
	int slask;
	proto_tree *o63_v_tree;
	proto_item *vti;

	struct o63_opt_info {
		char	*truet;
		char 	*falset;
		enum field_type	ft;
	};

	static struct o63_opt_info o63_opt[]= {
		/* 0 */ {"","",none},
		/* 1 */ {"NWIP does not exist on subnet","",string},
		/* 2 */ {"NWIP exist in options area","",string},
		/* 3 */ {"NWIP exists in sname/file","",string},
		/* 4 */ {"NWIP exists, but too big","",string},
		/* 5 */ {"Broadcast for nearest Netware server","Do NOT Broadcast for nearest Netware server",yes_no},
		/* 6 */ {"Preferred DSS server","",ipv4},
		/* 7 */ {"Nearest NWIP server","",ipv4},
		/* 8 */ {"Autoretries","",val_u_short},
		/* 9 */ {"Autoretry delay, secs ","",val_u_short},
		/* 10*/ {"Support NetWare/IP v1.1","Do NOT support NetWare/IP v1.1",yes_no},
		/* 11*/ {"Primary DSS ", "" , special}
	};

	subopt = tvb_get_guint8(tvb, optp);
	if (subopt > array_length(o63_opt)) {
		proto_tree_add_text(v_tree, tvb,optp,1,"Unknown suboption %d", subopt);
		optp++;
	} else {
		switch (o63_opt[subopt].ft) {

		case string:
			proto_tree_add_text(v_tree, tvb, optp, 2, "Suboption %d: %s", subopt, o63_opt[subopt].truet);
			optp+=2;
			break;

		case yes_no:
			if (tvb_get_guint8(tvb, optp+2)==1) {
				proto_tree_add_text(v_tree, tvb, optp, 3, "Suboption %d: %s", subopt, o63_opt[subopt].truet);
			} else {
				proto_tree_add_text(v_tree, tvb, optp, 3, "Suboption %d: %s" , subopt, o63_opt[subopt].falset);
			}
			optp+=3;
			break;

		case special:
			proto_tree_add_text(v_tree, tvb, optp, 6,
			    "Suboption %d: %s = %s" ,
			    subopt, o63_opt[subopt].truet,
			    ip_to_str(tvb_get_ptr(tvb, optp+2, 4)));
			optp=optp+6;
			break;

		case val_u_short:
			proto_tree_add_text(v_tree, tvb, optp, 3, "Suboption %d: %s = %u",
			    subopt, o63_opt[subopt].truet,
			    tvb_get_guint8(tvb, optp+2));	/* XXX - 1 byte? */
			optp+=3;
			break;

		case ipv4:
			subopt_len = tvb_get_guint8(tvb, optp+1);
			if (subopt_len == 4) {
				/* one IP address */
				proto_tree_add_text(v_tree, tvb, optp, 6,
				    "Suboption %d : %s = %s",
				    subopt, o63_opt[subopt].truet,
				    ip_to_str(tvb_get_ptr(tvb, optp+2, 4)));
				optp=optp+6;
			} else {
				/* > 1 IP addresses. Let's make a sub-tree */
				vti = proto_tree_add_text(v_tree, tvb, optp,
				    subopt_len+2, "Suboption %d: %s",
				    subopt, o63_opt[subopt].truet);
				o63_v_tree = proto_item_add_subtree(vti, ett_bootp_option);
				for (slask = optp + 2 ; slask < optp+subopt_len; slask += 4) {
					proto_tree_add_text(o63_v_tree, tvb, slask, 4, "IP Address: %s",
					    ip_to_str(tvb_get_ptr(tvb, slask, 4)));
				}
				optp=slask;
			}
			break;
		default:
			proto_tree_add_text(v_tree, tvb,optp,1,"Unknown suboption %d", subopt);
			optp++;
			break;
		}
	}
	return optp;
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
	{ PKT_CM_DCC_SUP_LC,	"DCC Support" }
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
	guint off = PKT_MDC_TLV_OFF + voff;
	guint tlv_len, i;
	guint8 asc_val[3] = "  ", flow_val_str[5];
	static GString *tlv_str = NULL;
	char bit_fld[64];
	proto_item *ti;
	proto_tree *subtree;

	if (! tlv_str)
		tlv_str = g_string_new("");

	tvb_memcpy (tvb, asc_val, off, 2);
	if (sscanf(asc_val, "%x", &tlv_len) != 1) {
		proto_tree_add_text(v_tree, tvb, off, len - off,
			"Bogus length: %s", asc_val);
		return;
	} else {
		proto_tree_add_uint_format(v_tree, hf_bootp_pkt_mtacap_len, tvb, off, 2,
				tlv_len, "MTA DC Length: %d", tlv_len);
		off += 2;

		while ((int) off - voff < len) {
			/* Type */
			raw_val = tvb_get_ntohs (tvb, off);
			g_string_sprintf(tlv_str, "0x%.2s: %s = ",
					tvb_get_ptr(tvb, off, 2),
					val_to_str(raw_val, pkt_mdc_type_vals, "unknown"));

			/* Length */
			tvb_memcpy(tvb, asc_val, off + 2, 2);
			if (sscanf(asc_val, "%x", &tlv_len) != 1) {
				proto_tree_add_text(v_tree, tvb, off, len - off,
							"[Bogus length: %s]", asc_val);
				return;
			} else {
				/* Value(s) */
				/*g_string_sprintfa(tlv_str, "Length: %d, Value: ", tlv_len);*/

				switch (raw_val) {
					case PKT_MDC_VERSION:
						raw_val = tvb_get_ntohs(tvb, off + 4);
						g_string_sprintfa(tlv_str, "%s (%.2s)",
								val_to_str(raw_val, pkt_mdc_version_vals, "Reserved"),
								tvb_get_ptr(tvb, off + 4, 2) );
						break;
					case PKT_MDC_TEL_END:
					case PKT_MDC_IF_INDEX:
						g_string_sprintfa(tlv_str, "%.2s",
								tvb_get_ptr(tvb, off + 4, 2) );
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
						g_string_sprintfa(tlv_str, "%s (%.2s)",
								val_to_str(raw_val, pkt_mdc_boolean_vals, "unknown"),
								tvb_get_ptr(tvb, off + 4, 2) );
						break;
					case PKT_MDC_SUPP_CODECS:
					case PKT_MDC_SUPP_CODECS_LC:
						for (i = 0; i < tlv_len; i++) {
							raw_val = tvb_get_ntohs(tvb, off + 4 + (i * 2) );
							g_string_sprintfa(tlv_str, "%s%s (%.2s)",
									plurality(i + 1, "", ", "),
									val_to_str(raw_val, pkt_mdc_codec_vals, "unknown"),
									tvb_get_ptr(tvb, off + 4 + (i * 2), 2) );
						}
						break;
					case PKT_MDC_PROV_FLOWS:
						tvb_memcpy(tvb, flow_val_str, off + 4, 4);
						flow_val_str[4] = '\0';
						flow_val = strtoul(flow_val_str, NULL, 16);
						g_string_sprintfa(tlv_str, "0x%04lx", flow_val);
						break;
					case PKT_MDC_T38_VERSION:
						raw_val = tvb_get_ntohs(tvb, off + 4);
						g_string_sprintfa(tlv_str, "%s (%.2s)",
								val_to_str(raw_val, pkt_mdc_t38_version_vals, "unknown"),
								tvb_get_ptr(tvb, off + 4, 2) );
						break;
					case PKT_MDC_T38_EC:
						raw_val = tvb_get_ntohs(tvb, off + 4);
						g_string_sprintfa(tlv_str, "%s (%.2s)",
								val_to_str(raw_val, pkt_mdc_t38_ec_vals, "unknown"),
								tvb_get_ptr(tvb, off + 4, 2) );
						break;
					case PKT_MDC_MIBS:
						raw_val = tvb_get_ntohs(tvb, off + 4);
						g_string_sprintfa(tlv_str, "%s (%.2s)",
								val_to_str(raw_val, pkt_mdc_mibs_vals, "unknown"),
								tvb_get_ptr(tvb, off + 4, 2) );
						break;
					case PKT_MDC_VENDOR_TLV:
					default:
						g_string_sprintfa(tlv_str, "%s",
								tvb_format_stringzpad(tvb, off + 4, tlv_len * 2) );
						break;
				}
			}
			ti = proto_tree_add_text(v_tree, tvb, off, (tlv_len * 2) + 4, tlv_str->str);
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
	guint off = PKT_CM_TLV_OFF + voff;
	guint tlv_len, i;
	guint8 asc_val[3] = "  ";
	static GString *tlv_str = NULL;

	if (! tlv_str)
		tlv_str = g_string_new("");

	tvb_memcpy (tvb, asc_val, off, 2);
	if (sscanf(asc_val, "%x", &tlv_len) != 1) {
		proto_tree_add_text(v_tree, tvb, off, len - off,
				    "Bogus length: %s", asc_val);
		return;
	} else {
		proto_tree_add_uint_format(v_tree, hf_bootp_docsis_cmcap_len, tvb, off, 2,
				tlv_len, "CM DC Length: %d", tlv_len);
		off += 2;

		while ((int) off - voff < len) {
			/* Type */
			raw_val = tvb_get_ntohs (tvb, off);
			g_string_sprintf(tlv_str, "0x%.2s: %s = ",
					tvb_get_ptr(tvb, off, 2),
					val_to_str(raw_val, pkt_cm_type_vals, "unknown"));

			/* Length */
			tvb_memcpy(tvb, asc_val, off + 2, 2);
			if (sscanf(asc_val, "%x", &tlv_len) != 1) {
				proto_tree_add_text(v_tree, tvb, off, len - off,
							"[Bogus length: %s]", asc_val);
				return;
			} else {
				/* Value(s) */
				/*g_string_sprintfa(tlv_str, "Length: %d, Value%s: ", tlv_len,
						plurality(tlv_len, "", "s") );*/

				switch (raw_val) {
					case PKT_CM_CONCAT_SUP:
					case PKT_CM_FRAG_SUP:
					case PKT_CM_PHS_SUP:
					case PKT_CM_IGMP_SUP:
					case PKT_CM_DCC_SUP:
					case PKT_CM_DCC_SUP_LC:
						for (i = 0; i < tlv_len; i++) {
							raw_val = tvb_get_ntohs(tvb, off + 4 + (i * 2) );
							g_string_sprintfa(tlv_str, "%s%s (%.2s)",
									plurality(i + 1, "", ", "),
									val_to_str(raw_val, pkt_mdc_boolean_vals, "unknown"),
									tvb_get_ptr(tvb, off + 4 + (i * 2), 2) );
						}
						break;
					case PKT_CM_DOCSIS_VER:
						raw_val = tvb_get_ntohs(tvb, off + 4);
						g_string_sprintfa(tlv_str, "%s (%.2s)",
								val_to_str(raw_val, pkt_cm_version_vals, "Reserved"),
								tvb_get_ptr(tvb, off + 4, 2) );
						break;
					case PKT_CM_PRIV_SUP:
						raw_val = tvb_get_ntohs(tvb, off + 4);
						g_string_sprintfa(tlv_str, "%s (%.2s)",
								val_to_str(raw_val, pkt_cm_privacy_vals, "Reserved"),
								tvb_get_ptr(tvb, off + 4, 2) );
						break;
					case PKT_CM_DSAID_SUP:
					case PKT_CM_USID_SUP:
					case PKT_CM_TET_MI:
					case PKT_CM_TET_MI_LC:
					case PKT_CM_TET:
					case PKT_CM_TET_LC:
						tvb_memcpy (tvb, asc_val, off + 4, 2);
						raw_val = strtoul(asc_val, NULL, 16);
						g_string_sprintfa(tlv_str, "%lu", raw_val);
						break;
					case PKT_CM_FILT_SUP:
						tvb_memcpy (tvb, asc_val, off + 4, 2);
						raw_val = strtoul(asc_val, NULL, 16);
						if (raw_val & 0x01)
							g_string_append(tlv_str, "802.1P filtering");
						if (raw_val & 0x02) {
							if (raw_val & 0x01)
								g_string_append(tlv_str, ", ");
							g_string_append(tlv_str, "802.1Q filtering");
						}
						if (! raw_val & 0x03)
							g_string_append(tlv_str, "None");
						g_string_sprintfa(tlv_str, " (0x%02lx)", raw_val);
						break;
				}
			}
			proto_tree_add_text(v_tree, tvb, off, (tlv_len * 2) + 4, tlv_str->str);
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
dissect_packetcable_i05_ccc(proto_tree *v_tree, tvbuff_t *tvb, int optp)
{
	guint8 subopt, subopt_len, fetch_tgt, timer_val, ticket_ctl;
	guint32 nom_to, max_to, max_ret;
	proto_tree *pkt_s_tree;
	proto_item *vti;
	static GString *opt_str = NULL;

	if (! opt_str)
		opt_str = g_string_new("");

	subopt = tvb_get_guint8(tvb, optp);
	subopt_len = tvb_get_guint8(tvb, optp + 1);
	optp += 2;

	g_string_sprintf(opt_str, "Suboption %u: %s: ", subopt,
			val_to_str(subopt, pkt_i05_ccc_opt_vals, "unknown/reserved") );

	switch (subopt) {
		case PKT_CCC_PRI_DHCP:	/* String values */
		case PKT_CCC_SEC_DHCP:
		case PKT_CCC_I05_SNMP:
		case PKT_CCC_I05_PRI_DNS:
		case PKT_CCC_I05_SEC_DNS:
		case PKT_CCC_KRB_REALM:
		case PKT_CCC_CMS_FQDN:
			g_string_sprintfa(opt_str, "%s (%u byte%s)",
					tvb_format_stringzpad(tvb, optp, subopt_len),
					subopt_len,
					plurality(subopt_len, "", "s") );
			proto_tree_add_text(v_tree, tvb, optp - 2, subopt_len + 2, opt_str->str);
			optp += subopt_len;
			break;

		case PKT_CCC_TGT_FLAG:
			fetch_tgt = tvb_get_guint8(tvb, optp);
			g_string_sprintfa(opt_str, "%s (%u byte%s%s)",
					fetch_tgt ? "Yes" : "No",
					subopt_len,
					plurality(subopt_len, "", "s"),
					subopt_len != 1 ? " [Invalid]" : "");
			proto_tree_add_text(v_tree, tvb, optp - 2, subopt_len + 2, opt_str->str);
			optp += 1;
			break;

		case PKT_CCC_PROV_TIMER:
			timer_val = tvb_get_guint8(tvb, optp);
			g_string_sprintfa(opt_str, "%u%s (%u byte%s%s)", timer_val,
					timer_val > 30 ? " [Invalid]" : "",
					subopt_len,
					plurality(subopt_len, "", "s"),
					subopt_len != 1 ? " [Invalid]" : "");
			proto_tree_add_text(v_tree, tvb, optp - 2, subopt_len + 2, opt_str->str);
			optp += 1;
			break;

		case PKT_CCC_AS_KRB:
			nom_to = tvb_get_ntohl(tvb, optp);
			max_to = tvb_get_ntohl(tvb, optp + 4);
			max_ret = tvb_get_ntohl(tvb, optp + 8);
			g_string_sprintfa(opt_str, "(%u byte%s%s)", subopt_len,
					plurality(subopt_len, "", "s"),
					subopt_len != 12 ? " [Invalid]" : "");
			vti = proto_tree_add_text(v_tree, tvb, optp - 2, subopt_len + 2, opt_str->str);
			pkt_s_tree = proto_item_add_subtree(vti, ett_bootp_option);
			proto_tree_add_text(pkt_s_tree, tvb, optp, 4,
					"pktcMtaDevRealmUnsolicitedKeyNomTimeout: %u", nom_to);
			proto_tree_add_text(pkt_s_tree, tvb, optp + 4, 4,
					"pktcMtaDevRealmUnsolicitedKeyMaxTimeout: %u", max_to);
			proto_tree_add_text(pkt_s_tree, tvb, optp + 8, 4,
					"pktcMtaDevRealmUnsolicitedKeyMaxRetries: %u", max_ret);
			optp += 12;
			break;

		case PKT_CCC_AP_KRB:
			nom_to = tvb_get_ntohl(tvb, optp);
			max_to = tvb_get_ntohl(tvb, optp + 4);
			max_ret = tvb_get_ntohl(tvb, optp + 8);
			g_string_sprintfa(opt_str, "(%u byte%s%s)", subopt_len,
					plurality(subopt_len, "", "s"),
					subopt_len != 12 ? " [Invalid]" : "");
			vti = proto_tree_add_text(v_tree, tvb, optp - 2, subopt_len + 2, opt_str->str);
			pkt_s_tree = proto_item_add_subtree(vti, ett_bootp_option);
			proto_tree_add_text(pkt_s_tree, tvb, optp, 4,
					"pktcMtaDevProvUnsolicitedKeyNomTimeout: %u", nom_to);
			proto_tree_add_text(pkt_s_tree, tvb, optp + 4, 4,
					"pktcMtaDevProvUnsolicitedKeyMaxTimeout: %u", max_to);
			proto_tree_add_text(pkt_s_tree, tvb, optp + 8, 4,
					"pktcMtaDevProvUnsolicitedKeyMaxRetries: %u", max_ret);
			optp += 12;
			break;

		case PKT_CCC_MTA_KRB_CLEAR:
			ticket_ctl = tvb_get_guint8(tvb, optp);
			g_string_sprintfa(opt_str, "%s (%u) (%u byte%s%s)",
					val_to_str (ticket_ctl, pkt_i05_ccc_ticket_ctl_vals, "unknown/invalid"),
					ticket_ctl,
					subopt_len,
					plurality(subopt_len, "", "s"),
					subopt_len != 1 ? " [Invalid]" : "");
			proto_tree_add_text(v_tree, tvb, optp - 2, subopt_len + 2, opt_str->str);
			optp += 1;
			break;

		default:
			proto_tree_add_text(v_tree, tvb, optp - 2, subopt_len + 2, opt_str->str);
			break;

	}
	return optp;
}


static const value_string sec_tcm_vals[] = {
	{ 1 << 0, "PacketCable Provisioning Server" },
	{ 1 << 1, "All PacketCable Call Management Servers" },
	{ 0, NULL }
};

static int
dissect_packetcable_ietf_ccc(proto_tree *v_tree, tvbuff_t *tvb, int optp,
	int revision)
{
	guint8 subopt, subopt_len, ipv4_addr[4];
	guint8 prov_type, fetch_tgt, timer_val;
	guint16 sec_tcm;
	guint32 nom_to, max_to, max_ret;
	proto_tree *pkt_s_tree;
	proto_item *vti;
	static GString *opt_str = NULL;
	int max_timer_val = 255, i;
	char dns_name[255], bit_fld[24];

	if (! opt_str)
		opt_str = g_string_new("");

	subopt = tvb_get_guint8(tvb, optp);
	subopt_len = tvb_get_guint8(tvb, optp + 1);
	optp += 2;

	g_string_sprintf(opt_str, "Suboption %u: %s: ", subopt,
			val_to_str(subopt, pkt_draft5_ccc_opt_vals, "unknown/reserved") );

	switch (subopt) {
		case PKT_CCC_PRI_DHCP:	/* IPv4 values */
		case PKT_CCC_SEC_DHCP:
			tvb_memcpy(tvb, ipv4_addr, optp, 4);
			g_string_sprintfa(opt_str, "%u.%u.%u.%u (%u byte%s%s)",
					ipv4_addr[0], ipv4_addr[1], ipv4_addr[2], ipv4_addr[3],
					subopt_len,
					plurality(subopt_len, "", "s"),
					subopt_len != 4 ? " [Invalid]" : "");
			proto_tree_add_text(v_tree, tvb, optp - 2, subopt_len + 2, opt_str->str);
			optp += subopt_len;
			break;

		case PKT_CCC_IETF_PROV_SRV:
			prov_type = tvb_get_guint8(tvb, optp);
			optp += 1;
			switch (prov_type) {
				case 0:
					get_dns_name(tvb, optp, optp + 1, dns_name,
						sizeof(dns_name));
					g_string_sprintfa(opt_str, "%s (%u byte%s)", dns_name,
							subopt_len - 1, plurality(subopt_len, "", "s") );
					proto_tree_add_text(v_tree, tvb, optp - 3, subopt_len + 2, opt_str->str);
					optp += subopt_len - 1;
					break;
				case 1:
					tvb_memcpy(tvb, ipv4_addr, optp, 4);
					g_string_sprintfa(opt_str, "%u.%u.%u.%u (%u byte%s%s)",
							ipv4_addr[0], ipv4_addr[1], ipv4_addr[2], ipv4_addr[3],
							subopt_len,
							plurality(subopt_len, "", "s"),
							subopt_len != 5 ? " [Invalid]" : "");
					proto_tree_add_text(v_tree, tvb, optp - 3, subopt_len + 2, opt_str->str);
					optp += subopt_len - 1;
					break;
				default:
					g_string_sprintfa(opt_str, "Invalid type: %u (%u byte%s)",
							tvb_get_guint8(tvb, optp),
							subopt_len,
							plurality(subopt_len, "", "s") );
					proto_tree_add_text(v_tree, tvb, optp - 3, subopt_len + 2, opt_str->str);
					optp += subopt_len - 1;
					break;
			}
			break;

		case PKT_CCC_IETF_AS_KRB:
			nom_to = tvb_get_ntohl(tvb, optp);
			max_to = tvb_get_ntohl(tvb, optp + 4);
			max_ret = tvb_get_ntohl(tvb, optp + 8);
			g_string_sprintfa(opt_str, "(%u byte%s%s)", subopt_len,
					plurality(subopt_len, "", "s"),
					subopt_len != 12 ? " [Invalid]" : "");
			vti = proto_tree_add_text(v_tree, tvb, optp - 2, subopt_len + 2, opt_str->str);
			pkt_s_tree = proto_item_add_subtree(vti, ett_bootp_option);
			proto_tree_add_text(pkt_s_tree, tvb, optp, 4,
					"pktcMtaDevRealmUnsolicitedKeyNomTimeout: %u", nom_to);
			proto_tree_add_text(pkt_s_tree, tvb, optp + 4, 4,
					"pktcMtaDevRealmUnsolicitedKeyMaxTimeout: %u", max_to);
			proto_tree_add_text(pkt_s_tree, tvb, optp + 8, 4,
					"pktcMtaDevRealmUnsolicitedKeyMaxRetries: %u", max_ret);
			optp += 12;
			break;

		case PKT_CCC_IETF_AP_KRB:
			nom_to = tvb_get_ntohl(tvb, optp);
			max_to = tvb_get_ntohl(tvb, optp + 4);
			max_ret = tvb_get_ntohl(tvb, optp + 8);
			g_string_sprintfa(opt_str, "(%u byte%s%s)", subopt_len,
					plurality(subopt_len, "", "s"),
					subopt_len != 12 ? " [Invalid]" : "");
			vti = proto_tree_add_text(v_tree, tvb, optp - 2, subopt_len + 2, opt_str->str);
			pkt_s_tree = proto_item_add_subtree(vti, ett_bootp_option);
			proto_tree_add_text(pkt_s_tree, tvb, optp, 4,
					"pktcMtaDevProvUnsolicitedKeyNomTimeout: %u", nom_to);
			proto_tree_add_text(pkt_s_tree, tvb, optp + 4, 4,
					"pktcMtaDevProvUnsolicitedKeyMaxTimeout: %u", max_to);
			proto_tree_add_text(pkt_s_tree, tvb, optp + 8, 4,
					"pktcMtaDevProvUnsolicitedKeyMaxRetries: %u", max_ret);
			optp += 12;
			break;

		case PKT_CCC_KRB_REALM: /* String values */
			get_dns_name(tvb, optp, optp + 1, dns_name, sizeof(dns_name));
			g_string_sprintfa(opt_str, "%s (%u byte%s)", dns_name,
					subopt_len, plurality(subopt_len, "", "s") );
			proto_tree_add_text(v_tree, tvb, optp - 2, subopt_len + 2, opt_str->str);
			optp += subopt_len;
			break;

		case PKT_CCC_TGT_FLAG:
			fetch_tgt = tvb_get_guint8(tvb, optp);
			g_string_sprintfa(opt_str, "%s (%u byte%s%s)",
					fetch_tgt ? "Yes" : "No",
					subopt_len,
					plurality(subopt_len, "", "s"),
					subopt_len != 1 ? " [Invalid]" : "");
			proto_tree_add_text(v_tree, tvb, optp - 2, subopt_len + 2, opt_str->str);
			optp += 1;
			break;

		case PKT_CCC_PROV_TIMER:
			if (revision == PACKETCABLE_CCC_DRAFT5)
				max_timer_val = 30;
			timer_val = tvb_get_guint8(tvb, optp);
			g_string_sprintfa(opt_str, "%u%s (%u byte%s%s)", timer_val,
					timer_val > max_timer_val ? " [Invalid]" : "",
					subopt_len,
					plurality(subopt_len, "", "s"),
					subopt_len != 1 ? " [Invalid]" : "");
			proto_tree_add_text(v_tree, tvb, optp - 2, subopt_len + 2, opt_str->str);
			optp += 1;
			break;

		case PKT_CCC_IETF_SEC_TKT:
			sec_tcm = tvb_get_ntohs(tvb, optp);
			g_string_sprintfa(opt_str, "0x%04x (%u byte%s%s)", sec_tcm, subopt_len,
					plurality(subopt_len, "", "s"),
					subopt_len != 2 ? " [Invalid]" : "");
			vti = proto_tree_add_text(v_tree, tvb, optp - 2, subopt_len + 2, opt_str->str);
			pkt_s_tree = proto_item_add_subtree(vti, ett_bootp_option);
			for (i = 0 ; i < 2; i++) {
				if (sec_tcm & sec_tcm_vals[i].value) {
					decode_bitfield_value(bit_fld, sec_tcm, sec_tcm_vals[i].value, 16);
					proto_tree_add_text(pkt_s_tree, tvb, optp, 2, "%sInvalidate %s",
						bit_fld, sec_tcm_vals[i].strptr);
				}
			}
			optp += 2;
			break;

		default:
			proto_tree_add_text(v_tree, tvb, optp - 2, subopt_len + 2, opt_str->str);
			break;

	}
	return optp;
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

		if (hlen > 0) {
			haddr = tvb_get_ptr(tvb, 28, hlen);
			proto_tree_add_bytes_format(bp_tree, hf_bootp_hw_addr, tvb,
				/* The chaddr element is 16 bytes in length, although
				   only the first hlen bytes are used */
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
				tvb_memcpy(tvb, (void *)&ip_addr, voff, sizeof(ip_addr));
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
		tmpvoff += bootp_option(tvb, 0, tmpvoff, eoff, TRUE, &at_end,
		    &dhcp_type, &vendor_class_id);
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
		tap_queue_packet( bootp_dhcp_tap, pinfo, (gpointer) dhcp_type);
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
		voff += bootp_option(tvb, bp_tree, voff, eoff, FALSE, &at_end,
		    &dhcp_type, &vendor_class_id);
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
      	"Server should do ddns update", HFILL }},

    { &hf_bootp_fqdn_o,
      { "Server overrides",	"bootp.fqdn.o",		FT_BOOLEAN,
        8,			TFS(&tfs_fqdn_o),	F_FQDN_O,
      	"Server insists on doing DDNS update", HFILL }},

    { &hf_bootp_fqdn_e,
      { "Binary encoding",	"bootp.fqdn.e",		FT_BOOLEAN,
        8,			TFS(&tfs_fqdn_e),	F_FQDN_E,
      	"Name is binary encoded", HFILL }},

    { &hf_bootp_fqdn_n,
      { "No server ddns",	"bootp.fqdn.n",		FT_BOOLEAN,
        8,			TFS(&tfs_fqdn_n),	F_FQDN_N,
      	"Server should not do any DDNS updates", HFILL }},

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
      	"Name to register via ddns", HFILL }},

    { &hf_bootp_fqdn_asciiname,
      { "Client name",		"bootp.fqdn.name",	FT_STRING,
        BASE_NONE,		NULL,			0x0,
      	"Name to register via ddns", HFILL }},

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
