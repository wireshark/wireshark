/* packet-dhpcv6.c
 * Routines for DHCPv6 packet disassembly
 * Jun-ichiro itojun Hagino <itojun@iijlab.net>
 * IItom Tsutomu MIENO <iitom@utouto.com>
 * SHIRASAKI Yasuhiro <yasuhiro@gnome.gr.jp>
 *
 * $Id: packet-dhcpv6.c,v 1.5 2002/06/26 01:24:42 guy Exp $
 *
 * The information used comes from:
 * draft-ietf-dhc-dhcpv6-26.txt
 * draft-troan-dhcpv6-opt-prefix-delegation-01.txt
 * draft-ietf-dhc-dhcpv6-opt-dnsconfig-02.txt
 *
 * Note that protocol constants are still subject to change, based on IANA
 * assignment decisions.
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
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <string.h>
#include <glib.h>
#include <epan/int-64bit.h>
#include <epan/packet.h>
#include <epan/ipv6-utils.h>

static int proto_dhcpv6 = -1;
static int hf_dhcpv6_msgtype = -1;

static guint ett_dhcpv6 = -1;
static guint ett_dhcpv6_option = -1;

#define UDP_PORT_DHCPV6_DOWNSTREAM	546
#define UDP_PORT_DHCPV6_UPSTREAM	547

#define DHCPV6_LEASEDURATION_INFINITY	0xffffffff

#define	SOLICIT			1
#define	ADVERTISE		2
#define	REQUEST			3
#define	CONFIRM			4
#define	RENEW			5
#define	REBIND			6
#define	REPLY			7
#define	RELEASE			8
#define	DECLINE			9
#define	RECONFIGURE		10
#define	INFORMATION_REQUEST	11
#define	RELAY_FORW		12
#define	RELAY_REPL		13

#define	OPTION_CLIENTID		1
#define	OPTION_SERVERID		2
#define	OPTION_IA		3
#define	OPTION_IA_TA		4
#define	OPTION_IAADDR		5
#define	OPTION_ORO		6
#define	OPTION_PREFERENCE	7
#define	OPTION_ELAPSED_TIME	8
#define	OPTION_RELAY_MSG	9
/* #define	OPTION_SERVER_MSG	10 */
#define	OPTION_AUTH		11
#define	OPTION_UNICAST		12
#define	OPTION_STATUS_CODE	13
#define	OPTION_RAPID_COMMIT	14
#define	OPTION_USER_CLASS	15
#define	OPTION_VENDOR_CLASS	16
#define	OPTION_VENDOR_OPTS	17
#define	OPTION_INTERFACE_ID	18
#define	OPTION_RECONF_MSG	19
#define	OPTION_RECONF_NONCE	20

#define	OPTION_DNS_SERVERS	25
#define	OPTION_DOMAIN_LIST	26
#define	OPTION_PREFIXDEL	30
#define	OPTION_PREFIX_INFO	31
#define	OPTION_PREFIXREQ	32

#define	DUID_LLT		1
#define	DUID_EN			2
#define	DUID_LL			3
#define	DUID_LL_OLD		4

static const value_string msgtype_vals[] = {
	{ SOLICIT,	"Solicit" },
	{ ADVERTISE,	"Advertise" },
	{ REQUEST,	"Request" }, 
	{ CONFIRM,	"Confirm" },
	{ RENEW,	"Renew" },
	{ REBIND,	"Rebind" },
	{ REPLY,	"Reply" },
	{ RELEASE,	"Release" },
	{ DECLINE,	"Decline" },
	{ RECONFIGURE,	"Reconfigure" },
	{ INFORMATION_REQUEST,	"Information-request" },
	{ RELAY_FORW,	"Relay-forw" },
	{ RELAY_REPL,	"Relay-repl" },
	{ 0, NULL }
};

static const value_string opttype_vals[] = {
	{ OPTION_CLIENTID,	"Client Identifier" },
	{ OPTION_SERVERID,	"Server Identifier" },
	{ OPTION_IA,		"Identify Association" },
	{ OPTION_IA_TA,		"Identify Association for Temporary Address" },
	{ OPTION_IAADDR,	"IA Address" },
	{ OPTION_ORO,		"Option Request" },
	{ OPTION_PREFERENCE,	"Preference" },
	{ OPTION_ELAPSED_TIME,	"Elapsed time" },
	{ OPTION_RELAY_MSG,	"Relay Message" },
/*	{ OPTION_SERVER_MSG,	"Server message" }, */
	{ OPTION_AUTH,		"Authentication" },
	{ OPTION_UNICAST,	"Server unicast" },
	{ OPTION_STATUS_CODE,	"Status code" },
	{ OPTION_RAPID_COMMIT,	"Rapid Commit" },
	{ OPTION_USER_CLASS,	"User Class" },
	{ OPTION_VENDOR_CLASS,	"Vendor Class" },
	{ OPTION_VENDOR_OPTS,	"Vendor-specific Information" },
	{ OPTION_INTERFACE_ID,	"Interface-Id" },
	{ OPTION_RECONF_MSG,	"Reconfigure Message" },
	{ OPTION_RECONF_NONCE,	"Reconfigure Nonce" },
	{ OPTION_DNS_SERVERS,	"Domain Name Server" },
	{ OPTION_DOMAIN_LIST,	"Domain Search List" },
	{ OPTION_PREFIXDEL,	"Prefix Delegation" },
	{ OPTION_PREFIX_INFO,	"Prefix Information" },
	{ OPTION_PREFIXREQ,	"Prefix Request" },
	{ 0,	NULL }
};

static const value_string statuscode_vals[] =
{
	{0, "Success" },
	{1, "UnspecFail" },
	{2, "AuthFailed" },
	{3, "AddrUnvail" },
	{4, "NoAddrAvail" },
	{5, "NoBinding" },
	{6, "ConfNoMatch" },
	{7, "NotOnLink" },
	{8, "UseMulticast" },
	{0, NULL }
};

static const value_string duidtype_vals[] =
{
	{ DUID_LLT,	"link-layer address plus time" },
	{ DUID_EN,	"assigned by vendor based on Enterprise number" },
	{ DUID_LL,	"link-layer address" },
	{ DUID_LL_OLD,	"link-layer address (old)" },
	{ 0, NULL }
};

/* Returns the number of bytes consumed by this option. */
static int
dhcpv6_option(tvbuff_t *tvb, proto_tree *bp_tree, int off, int eoff,
    gboolean *at_end)
{
	guint16	opttype;
	guint16	optlen;
	proto_item *ti;
	proto_tree *subtree;
	int i;
	struct e_in6_addr in6;
	guint16 duidtype;

	/* option type and length must be present */
	if (eoff - off < 4) {
		*at_end = TRUE;
		return 0;
	}

	opttype = tvb_get_ntohs(tvb, off);
	optlen = tvb_get_ntohs(tvb, off + 2);

	/* truncated case */
	if (eoff - off < 4 + optlen) {
		*at_end = TRUE;
		return 0;
	}

	ti = proto_tree_add_text(bp_tree, tvb, off, 4 + optlen,
		"%s", val_to_str(opttype, opttype_vals, "DHCP option %u"));

	subtree = proto_item_add_subtree(ti, ett_dhcpv6_option);
	proto_tree_add_text(subtree, tvb, off, 2, "option type: %d", opttype);
	proto_tree_add_text(subtree, tvb, off + 2, 2, "option length: %d",
		optlen);

	off += 4;
	switch (opttype) {
	case OPTION_CLIENTID:
	case OPTION_SERVERID:
		if (optlen < 2) {
			proto_tree_add_text(subtree, tvb, off, optlen,
				"DUID: malformed option");
			break;
		}
		duidtype = tvb_get_ntohs(tvb, off);
		proto_tree_add_text(subtree, tvb, off, 2,
			"DUID type: %s (%u)", 
				    val_to_str(duidtype, 
					       duidtype_vals, "Unknown"),
				    duidtype);
		switch (duidtype) {
		case DUID_LLT:
			if (optlen < 8) {
				proto_tree_add_text(subtree, tvb, off,
					optlen, "DUID: malformed option");
				break;
			}
			/* XXX seconds since Jan 1 2000 */
			proto_tree_add_text(subtree, tvb, off + 2, 2,
				"Hardware type: %u",
				tvb_get_ntohs(tvb, off + 2));
			proto_tree_add_text(subtree, tvb, off + 4, 4,
				"Time: %u", tvb_get_ntohl(tvb, off + 4));
			if (optlen > 8) {
				proto_tree_add_text(subtree, tvb, off + 8,
					optlen - 8, "Link-layer address");
			}
			break;
		case DUID_EN:
			if (optlen < 6) {
				proto_tree_add_text(subtree, tvb, off,
					optlen, "DUID: malformed option");
				break;
			}
			proto_tree_add_text(subtree, tvb, off + 2, 4,
					    "enterprise-number");
			if (optlen > 6) {
				proto_tree_add_text(subtree, tvb, off + 6,
					optlen - 6, "identifier");
			}
			break;
		case DUID_LL:
		case DUID_LL_OLD:
			if (optlen < 4) {
				proto_tree_add_text(subtree, tvb, off,
					optlen, "DUID: malformed option");
				break;
			}
			proto_tree_add_text(subtree, tvb, off + 2, 2,
				"Hardware type: %u",
				tvb_get_ntohs(tvb, off + 2));
			if (optlen > 4) {
				proto_tree_add_text(subtree, tvb, off + 4,
					optlen - 4, "Link-layer address");
			}
			break;
		}
		break;
	case OPTION_IA:
	  if (optlen < 12) {
	    proto_tree_add_text(subtree, tvb, off,
				optlen, "IA: malformed option");
	    break;
	  }
	  proto_tree_add_text(subtree, tvb, off, 4,
			      "IAID: %u",
			      tvb_get_ntohl(tvb, off));
	  proto_tree_add_text(subtree, tvb, off+4, 4,
			      "T1: %u", tvb_get_ntohl(tvb, off+4));
	  proto_tree_add_text(subtree, tvb, off+8, 4,
			      "T2: %u", tvb_get_ntohl(tvb, off+8));
	  if (optlen > 12) {
	    gboolean at_end_;
	    dhcpv6_option(tvb, subtree, off+12, off + optlen - 12, &at_end_);
	  }
	  break;
	case OPTION_IA_TA:
	  if (optlen < 4) {
	    proto_tree_add_text(subtree, tvb, off,
				optlen, "IA_TA: malformed option");
	    break;
	  }
	  proto_tree_add_text(subtree, tvb, off, 4,
			      "IAID: %u",
			      tvb_get_ntohl(tvb, off));
	  if (optlen > 4) {
	    gboolean at_end_;
	    dhcpv6_option(tvb, subtree, off+4, off + optlen - 4, &at_end_);
	  }
	  break;
	case OPTION_IAADDR:
	  if (optlen < 24) {
	    proto_tree_add_text(subtree, tvb, off,
				optlen, "IAADDR: malformed option");
	    break;
	  }
	  tvb_memcpy(tvb, (guint8 *)&in6, off, sizeof(in6));
	  proto_tree_add_text(subtree, tvb, off,
			      sizeof(in6), "IPv6 address: %s",
				ip6_to_str(&in6));
	  proto_tree_add_text(subtree, tvb, off+16, 4,
			      "preferred-lifetime: %u",
			      tvb_get_ntohl(tvb, off+16));
	  proto_tree_add_text(subtree, tvb, off+20, 4,
			      "valid-lifetime: %u",
			      tvb_get_ntohl(tvb, off+20));
	  if (optlen > 24) {
	    gboolean at_end_;
	    dhcpv6_option(tvb, subtree, off+24, off + optlen - 24, &at_end_);
	  }
	  break;
	case OPTION_ORO:
		for (i = 0; i < optlen; i += 2) {
		    guint16 requested_opt_code;
		    requested_opt_code = tvb_get_ntohs(tvb, off + i);
		    proto_tree_add_text(subtree, tvb, off + i,
			    2, "Requested Option code: %s (%d)", 
					    val_to_str(requested_opt_code,
						       opttype_vals,
						       "Unknown"),
					    requested_opt_code);
		}
		break;
	case OPTION_PREFERENCE:
	  if (optlen != 1) {
	    proto_tree_add_text(subtree, tvb, off,
				optlen, "PREFERENCE: malformed option");
	    break;
	  }
	  proto_tree_add_text(subtree, tvb, off, 1,
			      "pref-value: %d",
			      (guint32)tvb_get_guint8(tvb, off));
	  break;
	case OPTION_ELAPSED_TIME:
	  if (optlen != 2) {
	    proto_tree_add_text(subtree, tvb, off,
				optlen, "ELAPSED-TIME: malformed option");
	    break;
	  }
	  proto_tree_add_text(subtree, tvb, off, 2,
			      "elapsed-time: %d sec",
			      (guint32)tvb_get_ntohs(tvb, off));
	  break;
	case OPTION_RELAY_MSG:
	  if (optlen == 0) {
	    proto_tree_add_text(subtree, tvb, off,
				optlen, "RELAY-MSG: malformed option");
	    break;
	  } else {
	    gboolean at_end_;
	    dhcpv6_option(tvb, subtree, off, off + optlen, &at_end_);
	  }
	  break;
	case OPTION_AUTH:
	  if (optlen < 15) {
	    proto_tree_add_text(subtree, tvb, off,
				optlen, "AUTH: malformed option");
	    break;
	  }
	  proto_tree_add_text(subtree, tvb, off, 1,
			      "Protocol: %d",
			      (guint32)tvb_get_guint8(tvb, off));
	  proto_tree_add_text(subtree, tvb, off+1, 1,
			      "Algorithm: %d",
			      (guint32)tvb_get_guint8(tvb, off+1));
	  proto_tree_add_text(subtree, tvb, off+2, 1,
			      "RDM: %d",
			      (guint32)tvb_get_guint8(tvb, off+2));
	  proto_tree_add_text(subtree, tvb, off+3, 8,
			      "Reply Detection");
	  proto_tree_add_text(subtree, tvb, off+11, optlen-11,
			      "Authentication Information");
	  break;
	case OPTION_UNICAST:
	  if (optlen != 16) {
	    proto_tree_add_text(subtree, tvb, off,
				optlen, "UNICAST: malformed option");
	    break;
	  }
	  tvb_memcpy(tvb, (guint8 *)&in6, off, sizeof(in6));
	  proto_tree_add_text(subtree, tvb, off,
			      sizeof(in6), "IPv6 address: %s",
				ip6_to_str(&in6));
	  break;
	case OPTION_STATUS_CODE:
	    {
		guint16 status_code;
		char *status_message = 0;
		status_code = tvb_get_ntohs(tvb, off);
		proto_tree_add_text(subtree, tvb, off, 2, 
				    "Status Code: %s (%d)",
				    val_to_str(status_code, statuscode_vals, 
					       "Unknown"),
				    status_code);

		if (optlen - 2 > 0)
		    status_message = g_malloc(optlen - 2 + 1);
		if (status_message != 0){
		    memset(status_message, 0, optlen - 2 + 1);
		    status_message = tvb_memcpy(tvb, status_message, off + 2, 
						optlen - 2);
		    proto_tree_add_text(subtree, tvb, off + 2, optlen - 2,
					"Status Message: %s",
					status_message);
		    g_free(status_message);
		}
	    }
	    break;
	case OPTION_VENDOR_CLASS:
	  if (optlen < 4) {
	    proto_tree_add_text(subtree, tvb, off,
				optlen, "VENDOR_CLASS: malformed option");
	    break;
	  }
	  proto_tree_add_text(subtree, tvb, off, 4,
			      "enterprise-number: %u",
			      tvb_get_ntohl(tvb, off));
	  if (optlen > 4) {
	    proto_tree_add_text(subtree, tvb, off+4, optlen-4,
				"vendor-class-data");
	  }
	  break;
	case OPTION_VENDOR_OPTS:
	  if (optlen < 4) {
	    proto_tree_add_text(subtree, tvb, off,
				optlen, "VENDOR_OPTS: malformed option");
	    break;
	  }
	  proto_tree_add_text(subtree, tvb, off, 4,
			      "enterprise-number: %u",
			      tvb_get_ntohl(tvb, off));
	  if (optlen > 4) {
	    proto_tree_add_text(subtree, tvb, off+4, optlen-4,
				"option-data");
	  }
	  break;
	case OPTION_INTERFACE_ID:
	  if (optlen == 0) {
	    proto_tree_add_text(subtree, tvb, off,
				optlen, "INTERFACE_ID: malformed option");
	    break;
	  }
	  proto_tree_add_text(subtree, tvb, off, optlen, "Interface-ID");
	  break;
	case OPTION_RECONF_MSG:
	  if (optlen != 1) {
	    proto_tree_add_text(subtree, tvb, off,
				optlen, "RECONF_MSG: malformed option");
	    break;
	  }
	  proto_tree_add_text(subtree, tvb, off, optlen,
			      "Reconfigure-type: %s",
			      val_to_str(tvb_get_guint8(tvb, off),
					 msgtype_vals,
					 "Message Type %u"));
	  break;
	case OPTION_RECONF_NONCE:
	  if (optlen != 8) {
	    proto_tree_add_text(subtree, tvb, off,
				optlen, "RECONF_NONCE: malformed option");
	    break;
	  }
	  proto_tree_add_text(subtree, tvb, off, optlen,
			      "Reconfigure-nonce");
	  break;
	case OPTION_DNS_SERVERS:
		if (optlen % 16) {
			proto_tree_add_text(subtree, tvb, off, optlen,
				"DNS servers address: malformed option");
			break;
		}
		for (i = 0; i < optlen; i += 16) {
			tvb_memcpy(tvb, (guint8 *)&in6, off + i, sizeof(in6));
			proto_tree_add_text(subtree, tvb, off + i,
				sizeof(in6), "DNS servers address: %s",
				ip6_to_str(&in6));
		}
		break;
	case OPTION_DOMAIN_LIST:
	  if (optlen > 0) {
	    proto_tree_add_text(subtree, tvb, off, optlen, "Search String");
	  }
	  break;
	case OPTION_PREFIXDEL:
	    {
		gboolean at_end_;
		dhcpv6_option(tvb, subtree, off, off + optlen, &at_end_);
	    }
	    break;
	case OPTION_PREFIX_INFO:
	    {
		guint32 lease_duration;
		guint8  prefix_length;
		struct e_in6_addr in6;
		
		lease_duration = tvb_get_ntohl(tvb, off);
		prefix_length  = tvb_get_guint8(tvb, off + 4);
		if ( lease_duration == DHCPV6_LEASEDURATION_INFINITY) {
			proto_tree_add_text(subtree, tvb, off, 4,	
				    "Lease duration: infinity");
		} else {
			proto_tree_add_text(subtree, tvb, off, 4,
				    "Lease duration: %u", lease_duration);
		}
		proto_tree_add_text(subtree, tvb, off + 4, 1,
				    "Prefix length: %d", prefix_length);
		tvb_memcpy(tvb, (guint8 *)&in6, off + 5 , sizeof(in6));
		proto_tree_add_text(subtree, tvb, off + 5,
				    16, "Prefix address: %s",
				    ip6_to_str(&in6));
	    }
	    break;
	case OPTION_PREFIXREQ:
	    {
		guint8  prefix_length;
		prefix_length  = tvb_get_guint8(tvb, off);
		proto_tree_add_text(subtree, tvb, off, 1,
				    "Prefix length: %d", prefix_length);
	    }
	    break;
	}


	return 4 + optlen;
}


static void
dissect_dhcpv6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    gboolean downstream)
{
	proto_tree *bp_tree = NULL;
	proto_item *ti;
	guint8 msgtype;
	guint32 xid;
	int off, eoff;
	gboolean at_end;

	downstream = 0; /* feature reserved */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "DHCPv6");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	msgtype = tvb_get_guint8(tvb, 0);

	/* XXX relay agent messages have to be decoded differently */

	xid = tvb_get_ntohl(tvb, 0) & 0x00ffffff;

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_set_str(pinfo->cinfo, COL_INFO,
			    val_to_str(msgtype,
				       msgtype_vals,
				       "Message Type %u"));
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_dhcpv6, tvb, 0, -1, FALSE);
		bp_tree = proto_item_add_subtree(ti, ett_dhcpv6);

		proto_tree_add_uint(bp_tree, hf_dhcpv6_msgtype, tvb, 0, 1,
			msgtype);
		proto_tree_add_text(bp_tree, tvb, 1, 3, "Transaction-ID: 0x%08x", xid);
#if 0
		tvb_memcpy(tvb, (guint8 *)&in6, 4, sizeof(in6));
		proto_tree_add_text(bp_tree, tvb, 4, sizeof(in6),
			"Server address: %s", ip6_to_str(&in6));
#endif
	}

	off = 4;
	eoff = tvb_reported_length(tvb);

	at_end = FALSE;
	while (off < eoff && !at_end)
		off += dhcpv6_option(tvb, bp_tree, off, eoff, &at_end);
}

static void
dissect_dhcpv6_downstream(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_dhcpv6(tvb, pinfo, tree, TRUE);
}

static void
dissect_dhcpv6_upstream(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_dhcpv6(tvb, pinfo, tree, FALSE);
}


void
proto_register_dhcpv6(void)
{
  static hf_register_info hf[] = {
    { &hf_dhcpv6_msgtype,
      { "Message type",			"dhcpv6.msgtype",	 FT_UINT8,
         BASE_DEC, 			VALS(msgtype_vals),   0x0,
      	"", HFILL }},
  };
  static gint *ett[] = {
    &ett_dhcpv6,
    &ett_dhcpv6_option,
  };
  
  proto_dhcpv6 = proto_register_protocol("DHCPv6", "DHCPv6", "dhcpv6");
  proto_register_field_array(proto_dhcpv6, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dhcpv6(void)
{
  dissector_handle_t dhcpv6_handle;

  dhcpv6_handle = create_dissector_handle(dissect_dhcpv6_downstream,
	proto_dhcpv6);
  dissector_add("udp.port", UDP_PORT_DHCPV6_DOWNSTREAM, dhcpv6_handle);
  dhcpv6_handle = create_dissector_handle(dissect_dhcpv6_upstream,
	proto_dhcpv6);
  dissector_add("udp.port", UDP_PORT_DHCPV6_UPSTREAM, dhcpv6_handle);
}
