/* packet-bootp.c
 * Routines for BOOTP/DHCP packet disassembly
 * Gilbert Ramirez <gram@xiexie.org>
 *
 * $Id: packet-bootp.c,v 1.45 2001/01/09 06:31:34 guy Exp $
 *
 * The information used comes from:
 * RFC  951: Bootstrap Protocol
 * RFC 1542: Clarifications and Extensions for the Bootstrap Protocol
 * RFC 2131: Dynamic Host Configuration Protocol
 * RFC 2132: DHCP Options and BOOTP Vendor Extensions
 * RFC 2489: Procedure for Defining New DHCP Options
 * BOOTP and DHCP Parameters
 *     http://www.isi.edu/in-notes/iana/assignments/bootp-dhcp-parameters
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <string.h>
#include <glib.h>
#include "packet.h"
#include "packet-arp.h"

static int proto_bootp = -1;
static int hf_bootp_type = -1;
static int hf_bootp_hw_type = -1;
static int hf_bootp_hw_len = -1;
static int hf_bootp_hops = -1;
static int hf_bootp_id = -1;
static int hf_bootp_secs = -1;
static int hf_bootp_flag = -1;
static int hf_bootp_ip_client = -1;
static int hf_bootp_ip_your = -1;
static int hf_bootp_ip_server = -1;
static int hf_bootp_ip_relay = -1;
static int hf_bootp_hw_addr = -1;
static int hf_bootp_server = -1;
static int hf_bootp_file = -1;
static int hf_bootp_cookie = -1;
static int hf_bootp_dhcp = -1;

static guint ett_bootp = -1;
static guint ett_bootp_option = -1;

#define UDP_PORT_BOOTPS  67

enum field_type { none, ipv4, string, toggle, yes_no, special, opaque,
	time_in_secs,
	val_u_byte, val_u_short, val_u_long,
	val_s_long };

struct opt_info {
	char	*text;
	enum field_type ftype;
};

#define NUM_OPT_INFOS 128
#define NUM_O63_SUBOPTS 11

static int dissect_netware_ip_suboption(proto_tree *v_tree, tvbuff_t *tvb,
    int optp);

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
		"Inform"
	};
	int i;

	if (byte > 0 && byte < (sizeof opt53_text / sizeof opt53_text[0]))
		i = byte;
	else
		i = 0;
	return opt53_text[i];
}

/* Returns the number of bytes consumed by this option. */
static int
bootp_option(tvbuff_t *tvb, proto_tree *bp_tree, int voff, int eoff)
{
	char			*text;
	enum field_type		ftype;
	u_char			code = tvb_get_guint8(tvb, voff);
	int			vlen;
	u_char			byte;
	int			i,optp, consumed;
	u_long			time_secs;
	proto_tree		*v_tree;
	proto_item		*vti;

	static const value_string nbnt_vals[] = {
	    {0x1,   "B-node" },
	    {0x2,   "P-node" },
	    {0x4,   "M-node" },
	    {0x8,   "H-node" },
	    {0,     NULL     } };

	static struct opt_info opt[] = {
		/*   0 */ { "Padding",								none },
		/*   1 */ { "Subnet Mask",							ipv4 },
		/*   2 */ { "Time Offset",							val_s_long },
		/*   3 */ { "Router",								ipv4 },
		/*   4 */ { "Time Server",							ipv4 },
		/*   5 */ { "Name Server",							ipv4 },
		/*   6 */ { "Domain Name Server",					ipv4 },
		/*   7 */ { "Log Server",							ipv4 },
		/*   8 */ { "Cookie Server",						ipv4 },
		/*   9 */ { "LPR Server",							ipv4 },
		/*  10 */ { "Impress Server",						ipv4 },
		/*  11 */ { "Resource Location Server",				ipv4 },
		/*  12 */ { "Host Name",							string },
		/*  13 */ { "Boot File Size",						val_u_short },
		/*  14 */ { "Merit Dump File",						string },
		/*  15 */ { "Domain Name",							string },
		/*  16 */ { "Swap Server",							ipv4 },
		/*  17 */ { "Root Path",							string },
		/*  18 */ { "Extensions Path",						string },
		/*  19 */ { "IP Forwarding",						toggle },
		/*  20 */ { "Non-Local Source Routing",				toggle },
		/*  21 */ { "Policy Filter",						special },
		/*  22 */ { "Maximum Datagram Reassembly Size",		val_u_short },
		/*  23 */ { "Default IP Time-to-Live",				val_u_byte },
		/*  24 */ { "Path MTU Aging Timeout",				time_in_secs },
		/*  25 */ { "Path MTU Plateau Table",				val_u_short },
		/*  26 */ { "Interface MTU",						val_u_short },
		/*  27 */ { "All Subnets are Local",				yes_no },
		/*  28 */ { "Broadcast Address",					ipv4 },
		/*  29 */ { "Perform Mask Discovery",				toggle },
		/*  30 */ { "Mask Supplier",						yes_no },
		/*  31 */ { "Perform Router Discover",				toggle },
		/*  32 */ { "Router Solicitation Address",			ipv4 },
		/*  33 */ { "Static Route",							special },
		/*  34 */ { "Trailer Encapsulation",				toggle },
		/*  35 */ { "ARP Cache Timeout",					time_in_secs },
		/*  36 */ { "Ethernet Encapsulation",				toggle },
		/*  37 */ { "TCP Default TTL", 						val_u_byte },
		/*  38 */ { "TCP Keepalive Interval",				time_in_secs },
		/*  39 */ { "TCP Keepalive Garbage",				toggle },
		/*  40 */ { "Network Information Service Domain",	string },
		/*  41 */ { "Network Information Service Servers",	ipv4 },
		/*  42 */ { "Network Time Protocol Servers",		ipv4 },
		/*  43 */ { "Vendor-Specific Information",			special },
		/*  44 */ { "NetBIOS over TCP/IP Name Server",		ipv4 },
		/*  45 */ { "NetBIOS over TCP/IP Datagram Distribution Name Server", ipv4 },
		/*  46 */ { "NetBIOS over TCP/IP Node Type",		special },
		/*  47 */ { "NetBIOS over TCP/IP Scope",			string },
		/*  48 */ { "X Window System Font Server",			ipv4 },
		/*  49 */ { "X Window System Display Manager",		ipv4 },
		/*  50 */ { "Requested IP Address",					ipv4 },
		/*  51 */ { "IP Address Lease Time",				time_in_secs },
		/*  52 */ { "Option Overload",						special },
		/*  53 */ { "DHCP Message Type",					special },
		/*  54 */ { "Server Identifier",					ipv4 },
		/*  55 */ { "Parameter Request List",				special },
		/*  56 */ { "Message",								string },
		/*  57 */ { "Maximum DHCP Message Size",			val_u_short },
		/*  58 */ { "Renewal Time Value",					time_in_secs },
		/*  59 */ { "Rebinding Time Value",					time_in_secs },
		/*  60 */ { "Vendor class identifier",				opaque },
		/*  61 */ { "Client identifier",					special },
		/*  62 */ { "Novell/Netware IP domain",					string },
		/*  63 */ { "Novell Options",	special },
		/*  64 */ { "Network Information Service+ Domain",	string },
		/*  65 */ { "Network Information Service+ Servers",	ipv4 },
		/*  66 */ { "TFTP Server Name",						string },
		/*  67 */ { "Bootfile name",						string },
		/*  68 */ { "Mobile IP Home Agent",					ipv4 },
		/*  69 */ { "SMTP Server",							ipv4 },
		/*  70 */ { "POP3 Server",							ipv4 },
		/*  71 */ { "NNTP Server",							ipv4 },
		/*  72 */ { "Default WWW Server",					ipv4 },
		/*  73 */ { "Default Finger Server",				ipv4 },
		/*  74 */ { "Default IRC Server",					ipv4 },
		/*  75 */ { "StreetTalk Server",					ipv4 },
		/*  76 */ { "StreetTalk Directory Assistance Server", ipv4 },
		/*  77 */ { "User Class Information",				opaque },
		/*  78 */ { "Directory Agent Information",			opaque },
		/*  79 */ { "Service Location Agent Scope",			opaque },
		/*  80 */ { "Naming Authority",						opaque },
		/*  81 */ { "Client Fully Qualified Domain Name",	opaque },
		/*  82 */ { "Agent Circuit ID",						opaque },
		/*  83 */ { "Agent Remote ID",						opaque },
		/*  84 */ { "Agent Subnet Mask",					opaque },
		/*  85 */ { "Novell Directory Services Servers",	opaque },
		/*  86 */ { "Novell Directory Services Tree Name",	opaque },
		/*  87 */ { "Novell Directory Services Context",	opaque },
		/*  88 */ { "IEEE 1003.1 POSIX Timezone",			opaque },
		/*  89 */ { "Fully Qualified Domain Name",			opaque },
		/*  90 */ { "Authentication",						opaque },
		/*  91 */ { "Vines TCP/IP Server Option",			opaque },
		/*  92 */ { "Server Selection Option",				opaque },
		/*  93 */ { "Client System Architecture",			opaque },
		/*  94 */ { "Client Network Device Interface",		opaque },
		/*  95 */ { "Lightweight Directory Access Protocol",	opaque },
		/*  96 */ { "IPv6 Transitions",						opaque },
		/*  97 */ { "UUID/GUID-based Client Identifier",	opaque },
		/*  98 */ { "Open Group's User Authentication",		opaque },
		/*  99 */ { "Unassigned",							opaque },
		/* 100 */ { "Printer Name",							opaque },
		/* 101 */ { "MDHCP multicast address",				opaque },
		/* 102 */ { "Removed/unassigned",					opaque },
		/* 103 */ { "Removed/unassigned",					opaque },
		/* 104 */ { "Removed/unassigned",					opaque },
		/* 105 */ { "Removed/unassigned",					opaque },
		/* 106 */ { "Removed/unassigned",					opaque },
		/* 107 */ { "Removed/unassigned",					opaque },
		/* 108 */ { "Swap Path Option",						opaque },
		/* 109 */ { "Unassigned",							opaque },
		/* 110 */ { "IPX Compability",						opaque },
		/* 111 */ { "Unassigned",							opaque },
		/* 112 */ { "Netinfo Parent Server Address",		opaque },
		/* 113 */ { "Netinfo Parent Server Tag",			opaque },
		/* 114 */ { "URL",									opaque },
		/* 115 */ { "DHCP Failover Protocol",				opaque },
		/* 116 */ { "DHCP Auto-Configuration",				opaque },
		/* 117 */ { "Unassigned",							opaque },
		/* 118 */ { "Unassigned",							opaque },
		/* 119 */ { "Unassigned",							opaque },
		/* 120 */ { "Unassigned",							opaque },
		/* 121 */ { "Unassigned",							opaque },
		/* 122 */ { "Unassigned",							opaque },
		/* 123 */ { "Unassigned",							opaque },
		/* 124 */ { "Unassigned",							opaque },
		/* 125 */ { "Unassigned",							opaque },
		/* 126 */ { "Extension",							opaque },
		/* 127 */ { "Extension",							opaque }
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
		if (bp_tree != NULL)
			proto_tree_add_text(bp_tree, tvb, voff, i, "Padding");
		consumed = i;
		return consumed;
		break;

	case 255:	/* End Option */
		if (bp_tree != NULL)
			proto_tree_add_text(bp_tree, tvb, voff, 1, "End Option");
		consumed = 1;
		return consumed;
	}

	/*
	 * Get the length of the option, and the number of bytes it
	 * consumes (the length doesn't include the option code or
	 * length bytes).
	 */
	vlen = tvb_get_guint8(tvb, voff+1);
	consumed = vlen + 2;
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
		proto_tree_add_text(bp_tree, tvb, voff, consumed,
				"Option %d: %s", code, text);
		break;

	case 46:	/* NetBIOS-over-TCP/IP Node Type */
		byte = tvb_get_guint8(tvb, voff+2);
		proto_tree_add_text(bp_tree, tvb, voff, consumed,
				"Option %d: %s = %s", code, text,
				val_to_str(byte, nbnt_vals,
				    "Unknown (0x%02x)"));
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
			if (byte < NUM_OPT_INFOS) {
				proto_tree_add_text(v_tree, tvb, voff+2+i, 1, "%d = %s",
						byte, opt[byte].text);
			} else {
				proto_tree_add_text(vti, tvb, voff+2+i, 1,
					"Unknown Option Code: %d", byte);
			}
		}
		break;

	case 61:	/* Client Identifier */
		/* We *MAY* use hwtype/hwaddr. If we have 7 bytes, I'll
		   guess that the first is the hwtype, and the last 6
		   are the hw addr */
		if (vlen == 7) {
			guint8 htype;

			vti = proto_tree_add_text(bp_tree, tvb, voff,
				consumed, "Option %d: %s", code, text);
			v_tree = proto_item_add_subtree(vti, ett_bootp_option);
			htype = tvb_get_guint8(tvb, voff+2);
			proto_tree_add_text(v_tree, tvb, voff+2, 1,
				"Hardware type: %s",
				arphrdtype_to_str(htype,
					"Unknown (0x%02x)"));
			proto_tree_add_text(v_tree, tvb, voff+3, 6,
				"Client hardware address: %s",
				arphrdaddr_to_str(tvb_get_ptr(tvb, voff+3, 6),
					6, htype));
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

	default:	/* not special */
		break;
	}

	/* Normal cases */
	if (code < NUM_OPT_INFOS) {
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
			 * John Lines <John.Lines@aeat.co.uk>
			 */
			proto_tree_add_text(bp_tree, tvb, voff, consumed,
					"Option %d: %s = %.*s", code, text, vlen,
					tvb_get_ptr(tvb, voff+2, consumed-2));
			break;

		case opaque:
			proto_tree_add_text(bp_tree, tvb, voff, consumed,
					"Option %d: %s (%d bytes)",
					code, text, vlen);
			break;

		case val_u_short:
			if (vlen == 2) {
				/* one u_short */
				proto_tree_add_text(bp_tree, tvb, voff, consumed,
						"Option %d: %s = %d", code, text,
						tvb_get_ntohs(tvb, voff+2));
			} else {
				/* > 1 u_short */
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
	if (subopt > NUM_O63_SUBOPTS) {
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
	guint8		op;
	guint8		htype, hlen;
	guint8		*haddr;
	int		voff, eoff; /* vender offset, end offset */
	guint32		ip_addr;
	gboolean	is_dhcp = FALSE;
	const char	*dhcp_type;

	CHECK_DISPLAY_AS_DATA(proto_bootp, tvb, pinfo, tree);

	pinfo->current_proto = "BOOTP/DHCP";

	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "BOOTP");
	if (check_col(pinfo->fd, COL_INFO)) {
		/*
		 * In case we throw an exception fetching the opcode, etc.
		 */
		col_clear(pinfo->fd, COL_INFO);
	}

	op = tvb_get_guint8(tvb, 0);
	htype = tvb_get_guint8(tvb, 1);
	hlen = tvb_get_guint8(tvb, 2);
	if (check_col(pinfo->fd, COL_INFO)) {
		switch (op) {

		case BOOTREQUEST:
			col_add_fstr(pinfo->fd, COL_INFO, "Boot Request from %s",
				arphrdaddr_to_str(tvb_get_ptr(tvb, 28, hlen),
					hlen, htype));
			break;

		case BOOTREPLY:
			col_set_str(pinfo->fd, COL_INFO, "Boot Reply");
			break;

		default:
			col_add_fstr(pinfo->fd, COL_INFO, "Unknown BOOTP message type (%u)",
			    op);
			break;
		}
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_bootp, tvb, 0,
		    tvb_length(tvb), FALSE);
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
		proto_tree_add_uint(bp_tree, hf_bootp_flag, tvb,
				    10, 2, tvb_get_ntohs(tvb, 10) & 0x8000);

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
						   28, hlen,
						   haddr,
						   "Client hardware address: %s",
						   arphrdaddr_to_str(haddr,
								     hlen,
								     htype));
		}
		else {
			proto_tree_add_text(bp_tree,  tvb,
						   28, 0, "Client address not given");
		}

		/* The server host name is optional */
		if (tvb_get_guint8(tvb, 44) != '\0') {
			proto_tree_add_item(bp_tree, hf_bootp_server, tvb,
						   44, 64, FALSE);
		}
		else {
			proto_tree_add_string_format(bp_tree, hf_bootp_server, tvb,
						   44, 64,
						   tvb_get_ptr(tvb, 44, 1),
						   "Server host name not given");
		}

		/* Boot file */
		if (tvb_get_guint8(tvb, 108) != '\0') {
			proto_tree_add_item(bp_tree, hf_bootp_file, tvb,
						   108, 128, FALSE);
		}
		else {
			proto_tree_add_string_format(bp_tree, hf_bootp_file, tvb,
						   108, 128,
						   tvb_get_ptr(tvb, 108, 1),
						   "Boot file name not given");
		}

		tvb_memcpy(tvb, (void *)&ip_addr, 236, sizeof(ip_addr));
		if (tvb_get_ntohl(tvb, 236) == 0x63825363) {
			proto_tree_add_ipv4_format(bp_tree, hf_bootp_cookie, tvb,
					    236, 4, ip_addr,
					    "Magic cookie: (OK)");
		}
		else {
			proto_tree_add_ipv4(bp_tree, hf_bootp_cookie, tvb,
					    236, 4, ip_addr);
		}
	}

	voff = 240;
	eoff = tvb_reported_length(tvb);
	while (voff < eoff) {
		/* Handle the DHCP option specially here, so that we
		   can flag DHCP packets as such. */
		if (!is_dhcp && tvb_get_guint8(tvb, voff) == 53) {
			/*
			 * We haven't already seen a DHCP Type option, and
			 * this is a DHCP Type option, so flag this packet
			 * as DHCP.
			 */
			dhcp_type = get_dhcp_type(tvb_get_guint8(tvb, voff+2));
			if (check_col(pinfo->fd, COL_PROTOCOL))
				col_set_str(pinfo->fd, COL_PROTOCOL, "DHCP");
			if (check_col(pinfo->fd, COL_INFO))
				col_add_fstr(pinfo->fd, COL_INFO, "DHCP %-8s - Transaction ID 0x%x",
				    dhcp_type, tvb_get_ntohl(tvb, 4));
			if (tree)
				proto_tree_add_boolean_hidden(bp_tree, hf_bootp_dhcp,
				    tvb, 0, 0, 1);
			is_dhcp = TRUE;
		}
		voff += bootp_option(tvb, bp_tree, voff, eoff);
	}
}

void
proto_register_bootp(void)
{
  static hf_register_info hf[] = {
    { &hf_bootp_dhcp,
      { "Frame is DHCP",                "bootp.dhcp",    FT_BOOLEAN,
        BASE_NONE,			NULL,		 0x0,
        "" }},                            
                      
    { &hf_bootp_type,
      { "Message type",			"bootp.type",	 FT_UINT8,
         BASE_DEC, 			VALS(op_vals),   0x0,
      	"" }},

    { &hf_bootp_hw_type,
      { "Hardware type",	       	"bootp.hw.type", FT_UINT8,
        BASE_HEX,			NULL,		 0x0,
      	"" }},

    { &hf_bootp_hw_len,
      { "Hardware address length",	"bootp.hw.len",  FT_UINT8,
        BASE_DEC,			NULL,		 0x0,
      	"" }},

    { &hf_bootp_hops,
      { "Hops",			       	"bootp.hops",	 FT_UINT8,
        BASE_DEC,			NULL,		 0x0,
      	"" }},

    { &hf_bootp_id,
      { "Transaction ID",	       	"bootp.id",	 FT_UINT32,
        BASE_HEX,			 NULL,		 0x0,
      	"" }},

    { &hf_bootp_secs,
      { "Seconds elapsed",	       	"bootp.secs",	 FT_UINT16,
        BASE_DEC,			 NULL,		 0x0,
      	"" }},

    { &hf_bootp_flag,
      { "Broadcast flag",	       	"bootp.flag",    FT_UINT16,
        BASE_HEX,			NULL,		 0x0,
      	"" }},

    { &hf_bootp_ip_client,
      { "Client IP address",	       	"bootp.ip.client",FT_IPv4,
        BASE_NONE,			NULL,		  0x0,
      	"" }},

    { &hf_bootp_ip_your,
      { "Your (client) IP address",	"bootp.ip.your",  FT_IPv4,
        BASE_NONE,			NULL,		  0x0,
      	"" }},

    { &hf_bootp_ip_server,
      { "Next server IP address",	"bootp.ip.server",FT_IPv4,
        BASE_NONE,			NULL,		  0x0,
      	"" }},

    { &hf_bootp_ip_relay,
      { "Relay agent IP address",	"bootp.ip.relay", FT_IPv4,
        BASE_NONE,			NULL,		  0x0,
      	"" }},

    { &hf_bootp_hw_addr,
      { "Client hardware address",	"bootp.hw.addr", FT_BYTES,
        BASE_NONE,			NULL,		 0x0,
      	"" }},

    { &hf_bootp_server,
      { "Server host name",		"bootp.server",  FT_STRING,
        BASE_NONE,			NULL,		 0x0,
      	"" }},

    { &hf_bootp_file,
      { "Boot file name",		"bootp.file",	 FT_STRING,
        BASE_NONE,			NULL,		 0x0,
      	"" }},

    { &hf_bootp_cookie,
      { "Magic cookie",			"bootp.cookie",	 FT_IPv4,
         BASE_NONE,			NULL,		 0x0,
      	"" }},
  };
  static gint *ett[] = {
    &ett_bootp,
    &ett_bootp_option,
  };
  
  proto_bootp = proto_register_protocol("Bootstrap Protocol", "BOOTP/DHCP",
					"bootp");
  proto_register_field_array(proto_bootp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_bootp(void)
{
  dissector_add("udp.port", UDP_PORT_BOOTPS, dissect_bootp, proto_bootp);
}
