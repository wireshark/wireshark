/* packet-bootp.c
 * Routines for BOOTP/DHCP packet disassembly
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
 *
 * $Id: packet-bootp.c,v 1.24 2000/01/07 22:05:30 guy Exp $
 *
 * The information used comes from:
 * RFC 2132: DHCP Options and BOOTP Vendor Extensions
 * RFC 1542: Clarifications and Extensions for the Bootstrap Protocol
 * RFC 2131: Dynamic Host Configuration Protocol
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

static guint ett_bootp = -1;
static guint ett_bootp_option = -1;

enum field_type { none, ipv4, string, toggle, yes_no, special, opaque,
	time_in_secs,
	val_u_byte, val_u_short, val_u_long,
	val_s_long };

struct opt_info {
	char	*text;
	enum field_type ftype;
};

#define NUM_OPT_INFOS 77

/* returns the number of bytes consumed by this option */
static int
bootp_option(const u_char *pd, proto_tree *bp_tree, int voff, int eoff)
{
	char			*text;
	enum field_type	ftype;
	u_char			code = pd[voff];
	int				vlen = pd[voff+1];
	u_char			byte;
	int				i, consumed = vlen + 2;
	u_long			time_secs;
	proto_tree		*v_tree;
	proto_item		*vti;

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
		/*  76 */ { "StreetTalk Directory Assistance Server", ipv4 }
	};

	text = opt[code].text;
	/* Special cases */
	switch (code) {
		/* Padding */
		case 0:
			/* check how much padding we have */
			for (i = voff + 1; i < eoff; i++ ) {
				if (pd[i] != 0) {
					break;
				}
			}
			i = i - voff;
			proto_tree_add_text(bp_tree, voff, i, "Padding");
			consumed = i;
			return consumed;

		/* Policy Filter */
		case 21:
			/* one IP address pair */
			if (vlen == 8) {
				proto_tree_add_text(bp_tree, voff, consumed,
					"Option %d: %s = %s/%s", code, text,
					ip_to_str((guint8*)&pd[voff+2]),
					ip_to_str((guint8*)&pd[voff+6]));
			}
			/* > 1 IP address pair. Let's make a sub-tree */
			else {

				vti = proto_tree_add_text(bp_tree, voff,
					consumed, "Option %d: %s", code, text);
				v_tree = proto_item_add_subtree(vti, ett_bootp_option);
				for (i = voff + 2; i < voff + consumed; i += 8) {
					proto_tree_add_text(v_tree, i, 8, "IP Address/Mask: %s/%s",
						ip_to_str((guint8*)&pd[i]),
						ip_to_str((guint8*)&pd[i+4]));
				}
			}
			break;

		/* Static Route */
		case 33:
			/* one IP address pair */
			if (vlen == 8) {
				proto_tree_add_text(bp_tree, voff, consumed,
					"Option %d: %s = %s/%s", code, text,
					ip_to_str((guint8*)&pd[voff+2]),
					ip_to_str((guint8*)&pd[voff+6]));
			}
			/* > 1 IP address pair. Let's make a sub-tree */
			else {

				vti = proto_tree_add_text(bp_tree, voff,
					consumed, "Option %d: %s", code, text);
				v_tree = proto_item_add_subtree(vti, ett_bootp_option);
				for (i = voff + 2; i < voff + consumed; i += 8) {
					proto_tree_add_text(v_tree, i, 8,
						"Destination IP Address/Router: %s/%s",
						ip_to_str((guint8*)&pd[i]),
						ip_to_str((guint8*)&pd[i+4]));
				}
			}
			break;

		/* Vendor-Specific Info */
		case 43:
			proto_tree_add_text(bp_tree, voff, consumed,
					"Option %d: %s", code, text);
			break;

		/* NetBIOS-over-TCP/IP Node Type */
		case 46:
			byte = pd[voff+2];
			proto_tree_add_text(bp_tree, voff, consumed,
					"Option %d: %s = %s", code, text,
					val_to_str(byte, nbnt_vals,
					    "Unknown (0x%02x)"));
			break;
				
		/* DHCP Message Type */
		case 53:
			byte = pd[voff+2];
			if (byte > 0 && byte < 9) {
				i = byte;
			}
			else {
				i = 0;
			}
			proto_tree_add_text(bp_tree, voff, 3, "Option %d: %s = DHCP %s",
				code, text, opt53_text[i]);
			break;

		/* Parameter Request List */
		case 55:
			vti = proto_tree_add_text(bp_tree, voff,
				vlen + 2, "Option %d: %s", code, text);
			v_tree = proto_item_add_subtree(vti, ett_bootp_option);
			for (i = 0; i < vlen; i++) {
				byte = pd[voff+2+i];
				if (byte < NUM_OPT_INFOS) {
					proto_tree_add_text(v_tree, voff+2+i, 1, "%d = %s",
							byte, opt[byte].text);
				}
				else {
					proto_tree_add_text(vti, voff+2+i, 1,
						"Unknown Option Code: %d", byte);
				}
			}
			break;

		/* Client Identifier */
		case 61:
			/* We *MAY* use hwtype/hwaddr. If we have 7 bytes, I'll
				guess that the first is the hwtype, and the last 6 are
				the hw addr */
			if (vlen == 7) {
				vti = proto_tree_add_text(bp_tree, voff,
					consumed, "Option %d: %s", code, text);
				v_tree = proto_item_add_subtree(vti, ett_bootp_option);
				proto_tree_add_text(v_tree, voff+2, 1,
					"Hardware type: %s",
					arphrdtype_to_str(pd[voff+2],
						"Unknown (0x%02x)"));
				proto_tree_add_text(v_tree, voff+3, 6,
					"Client hardware address: %s",
					arphrdaddr_to_str((guint8*)&pd[voff+3],
						6, pd[voff+2]));
			}
			/* otherwise, it's opaque data */
			else {
				proto_tree_add_text(bp_tree, voff, consumed,
					"Option %d: %s (%d bytes)", code, text, vlen);
			}
			break;

		/* End Option */
		case 255:
			proto_tree_add_text(bp_tree, voff, 1, "End Option");
			consumed = 1;
			return consumed;

		default:
			/* nothing */
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
				/* one IP address */
				if (vlen == 4) {
					proto_tree_add_text(bp_tree, voff, consumed,
						"Option %d: %s = %s", code, text,
						ip_to_str((guint8*)&pd[voff+2]));
				}
				/* > 1 IP addresses. Let's make a sub-tree */
				else {

					vti = proto_tree_add_text(bp_tree, voff,
						consumed, "Option %d: %s", code, text);
					v_tree = proto_item_add_subtree(vti, ett_bootp_option);
					for (i = voff + 2; i < voff + consumed; i += 4) {
						proto_tree_add_text(v_tree, i, 4, "IP Address: %s",
							ip_to_str((guint8*)&pd[i]));
					}
				}
				break;

			case string:
				/* Fix for non null-terminated string supplied by
				 * John Lines <John.Lines@aeat.co.uk>
				 */
				proto_tree_add_text(bp_tree, voff, consumed,
						"Option %d: %s = %.*s", code, text, vlen, &pd[voff+2]);
				break;

			case opaque:
				proto_tree_add_text(bp_tree, voff, consumed,
						"Option %d: %s (%d bytes)",
						code, text, vlen);
				break;

			case val_u_short:
				/* one IP address */
				if (vlen == 2) {
					proto_tree_add_text(bp_tree, voff, consumed,
							"Option %d: %s = %d", code, text,
							pntohs(&pd[voff+2]));
				}
				/* > 1 u_short */
				else {
					vti = proto_tree_add_text(bp_tree, voff,
						consumed, "Option %d: %s", code, text);
					v_tree = proto_item_add_subtree(vti, ett_bootp_option);
					for (i = voff + 2; i < voff + consumed; i += 2) {
						proto_tree_add_text(v_tree, i, 4, "Value: %d",
							pntohs(&pd[i]));
					}
				}
				break;

			case val_u_long:
				proto_tree_add_text(bp_tree, voff, consumed,
						"Option %d: %s = %d", code, text,
						pntohl(&pd[voff+2]));
				break;

			case val_u_byte:
				proto_tree_add_text(bp_tree, voff, consumed,
						"Option %d: %s = %d", code, text, pd[voff+2]);
				break;

			case toggle:
				i = pd[voff+2];
				if (i != 0 && i != 1) {
					proto_tree_add_text(bp_tree, voff, consumed,
							"Option %d: %s = Invalid Value %d", code, text,
							pd[voff+2]);
				}
				else {
					proto_tree_add_text(bp_tree, voff, consumed,
							"Option %d: %s = %s", code, text,
							pd[voff+2] == 0 ? "Disabled" : "Enabled");
				}
				break;

			case yes_no:
				i = pd[voff+2];
				if (i != 0 && i != 1) {
					proto_tree_add_text(bp_tree, voff, consumed,
							"Option %d: %s = Invalid Value %d", code, text,
							pd[voff+2]);
				}
				else {
					proto_tree_add_text(bp_tree, voff, consumed,
							"Option %d: %s = %s", code, text,
							pd[voff+2] == 0 ? "No" : "Yes");
				}
				break;

			case time_in_secs:
				time_secs = pntohl(&pd[voff+2]);
				proto_tree_add_text(bp_tree, voff, consumed,
					"Option %d: %s = %s", code, text,
					((time_secs == 0xffffffff) ?
					    "infinity" :
					    time_secs_to_str(time_secs)));
				break;

			default:
				proto_tree_add_text(bp_tree, voff, consumed,
						"Option %d: %s (%d bytes)", code, text, vlen);
		}
	}
	else {
		proto_tree_add_text(bp_tree, voff, consumed,
				"Unknown Option Code: %d (%d bytes)", code, vlen);
	}

	return consumed;
}

void
dissect_bootp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_tree	*bp_tree;
	proto_item	*ti;
	int			voff, eoff; /* vender offset, end offset */
	guint32		ip_addr;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "BOOTP");

	if (check_col(fd, COL_INFO)) {
		if (pd[offset] == 1) {
			col_add_fstr(fd, COL_INFO, "Boot Request from %s",
				arphrdaddr_to_str((guint8*)&pd[offset+28],
					pd[offset+2], pd[offset+1]));
		}
		else {
			col_add_str(fd, COL_INFO, "Boot Reply");
		}
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_bootp, offset, END_OF_FRAME, NULL);
		bp_tree = proto_item_add_subtree(ti, ett_bootp);

		proto_tree_add_item_format(bp_tree, hf_bootp_type, 
					   offset, 1,
					   pd[offset], 
					   pd[offset] == 1 ?
					   "Boot Request" : "Boot Reply");
		proto_tree_add_item_format(bp_tree, hf_bootp_hw_type,
					   offset + 1, 1,
					   pd[offset+1],
					   "Hardware type: %s",
					   arphrdtype_to_str(pd[offset+1],
							     "Unknown (0x%02x)"));
		proto_tree_add_item(bp_tree, hf_bootp_hw_len,
				    offset + 2, 1, pd[offset+2]);
		proto_tree_add_item(bp_tree, hf_bootp_hops,
				    offset + 3, 1, pd[offset+3]);
		proto_tree_add_item(bp_tree, hf_bootp_id,
				   offset + 4, 4, pntohl(&pd[offset+4]));
		proto_tree_add_item(bp_tree, hf_bootp_secs,
				    offset + 8, 2, pntohs(&pd[offset+8]));
		proto_tree_add_item(bp_tree, hf_bootp_flag,
				    offset + 10, 2, pd[offset+10] & 1);

		memcpy(&ip_addr, &pd[offset+12], sizeof(ip_addr));
		proto_tree_add_item(bp_tree, hf_bootp_ip_client, 
				    offset + 12, 4, ip_addr);
		memcpy(&ip_addr, &pd[offset+16], sizeof(ip_addr));
		proto_tree_add_item(bp_tree, hf_bootp_ip_your, 
				    offset + 16, 4, ip_addr);
		memcpy(&ip_addr, &pd[offset+20], sizeof(ip_addr));
		proto_tree_add_item(bp_tree, hf_bootp_ip_server,
				    offset + 20, 4, ip_addr);
		memcpy(&ip_addr, &pd[offset+24], sizeof(ip_addr));
		proto_tree_add_item(bp_tree, hf_bootp_ip_relay,
				    offset + 24, 4, ip_addr);

		proto_tree_add_item_format(bp_tree, hf_bootp_hw_addr, 
					   offset + 28, pd[offset+2],
					   &pd[offset+28],
					   "Client hardware address: %s",
					   arphrdaddr_to_str((guint8*)&pd[offset+28],
							     pd[offset+2], pd[offset+1]));

		/* The server host name is optional */
		if (pd[offset+44]) {
			proto_tree_add_item_format(bp_tree, hf_bootp_server,
						   offset + 44, 64,
						   &pd[offset+44],
						   "Server host name: %s",
						   &pd[offset+44]);
		}
		else {
			proto_tree_add_item_format(bp_tree, hf_bootp_server,
						   offset + 44, 64,
						   &pd[offset+44],
						   "Server host name not given");
		}

		/* Boot file */
		if (pd[offset+108]) {
			proto_tree_add_item_format(bp_tree, hf_bootp_file,
						   offset + 108, 128,
						   &pd[offset+108],
						   "Boot file name: %s",
						   &pd[offset+108]);
		}
		else {
			proto_tree_add_item_format(bp_tree, hf_bootp_file,
						   offset + 108, 128,
						   &pd[offset+108],
						   "Boot file name not given");
		}

		if (pntohl(&pd[offset+236]) == 0x63825363) {
			proto_tree_add_item_format(bp_tree, hf_bootp_cookie,
						   offset + 236, 4,
						   pd[offset+236],
						   "Magic cookie: (OK)");
		}
		else {
			memcpy(&ip_addr, &pd[offset + 236], sizeof(ip_addr));
			proto_tree_add_item(bp_tree, hf_bootp_cookie,
					    offset + 236, 4, ip_addr);
		}

		voff = offset+240;
		eoff = pi.captured_len;

		while (voff < eoff) {
			voff += bootp_option(pd, bp_tree, voff, eoff);
		}
	}
}

void
proto_register_bootp(void)
{
  static hf_register_info hf[] = {
    { &hf_bootp_type,
      { "Message type",			"bootp.type",	 FT_UINT8,  BASE_NONE, NULL, 0x0,
      	"" }},

    { &hf_bootp_hw_type,
      { "Hardware type",	       	"bootp.hw.type", FT_UINT8,  BASE_HEX, NULL, 0x0,
      	"" }},

    { &hf_bootp_hw_len,
      { "Hardware address length",	"bootp.hw.len",  FT_UINT8,  BASE_DEC, NULL, 0x0,
      	"" }},

    { &hf_bootp_hops,
      { "Hops",			       	"bootp.hops",	 FT_UINT8,  BASE_DEC, NULL, 0x0,
      	"" }},

    { &hf_bootp_id,
      { "Transaction ID",	       	"bootp.id",	 FT_UINT32, BASE_HEX, NULL, 0x0,
      	"" }},

    { &hf_bootp_secs,
      { "Seconds elapsed",	       	"bootp.secs",	 FT_UINT16, BASE_DEC, NULL, 0x0,
      	"" }},

    { &hf_bootp_flag,
      { "Broadcast flag",	       	"bootp.flag",    FT_UINT16, BASE_DEC, NULL, 0x0,
      	"" }},

    { &hf_bootp_ip_client,
      { "Client IP address",	       	"bootp.ip.client",FT_IPv4,  BASE_NONE, NULL, 0x0,
      	"" }},

    { &hf_bootp_ip_your,
      { "Your (client) IP address",	"bootp.ip.your",  FT_IPv4,  BASE_NONE, NULL, 0x0,
      	"" }},

    { &hf_bootp_ip_server,
      { "Next server IP address",	"bootp.ip.server",FT_IPv4,  BASE_NONE, NULL, 0x0,
      	"" }},

    { &hf_bootp_ip_relay,
      { "Relay agent IP address",	"bootp.ip.relay", FT_IPv4,  BASE_NONE, NULL, 0x0,
      	"" }},

    { &hf_bootp_hw_addr,
      { "Client hardware address",	"bootp.hw.addr", FT_BYTES,  BASE_NONE, NULL, 0x0,
      	"" }},

    { &hf_bootp_server,
      { "Server host name",		"bootp.server",  FT_STRING, BASE_NONE, NULL, 0x0,
      	"" }},

    { &hf_bootp_file,
      { "Boot file name",		"bootp.file",	 FT_STRING, BASE_NONE, NULL, 0x0,
      	"" }},

    { &hf_bootp_cookie,
      { "Magic cookie",			"bootp.cookie",	 FT_IPv4,   BASE_NONE, NULL, 0x0,
      	"" }},
  };
  static gint *ett[] = {
    &ett_bootp,
    &ett_bootp_option,
  };
  
  proto_bootp = proto_register_protocol("Bootstrap Protocol", "bootp");
  proto_register_field_array(proto_bootp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}
