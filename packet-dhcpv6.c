/* packet-dhpcv6.c
 * Routines for DHCPv6 packet disassembly
 * Jun-ichiro itojun Hagino <itojun@iijlab.net>
 *
 * $Id: packet-dhcpv6.c,v 1.2 2002/01/11 11:07:21 guy Exp $
 *
 * The information used comes from:
 * draft-ietf-dhc-dhcpv6-22.txt
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
#include "int-64bit.h"
#include "packet.h"
#include "ipv6-utils.h"

static int proto_dhcpv6 = -1;
static int hf_dhcpv6_msgtype = -1;

static guint ett_dhcpv6 = -1;
static guint ett_dhcpv6_option = -1;

#define UDP_PORT_DHCPV6_DOWNSTREAM	546
#define UDP_PORT_DHCPV6_UPSTREAM	547

static const value_string msgtype_vals[] = {
	{ 7,	"Reply" },
	{ 11,	"Information request" },
	{ 0,	NULL }
};

static const value_string opttype_vals[] = {
	{ 1,	"DUID" },
	{ 11,	"DNS servers address" },
	{ 0,	NULL }
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
	case 1:	/* DUID */
		if (optlen < 2) {
			proto_tree_add_text(subtree, tvb, off, optlen,
				"DUID: malformed option");
			break;
		}
		duidtype = tvb_get_ntohs(tvb, off);
		proto_tree_add_text(subtree, tvb, off, 2,
			"DUID type: %u", duidtype);
		switch (duidtype) {
		case 1:
			if (optlen < 8) {
				proto_tree_add_text(subtree, tvb, off,
					optlen, "DUID: malformed option");
				break;
			}
			/* XXX seconds since Jan 1 2000 */
			proto_tree_add_text(subtree, tvb, off + 2, 4,
				"Time: %u", tvb_get_ntohl(tvb, off + 6));
			proto_tree_add_text(subtree, tvb, off + 6, 2,
				"Hardware type: %u",
				tvb_get_ntohs(tvb, off + 6));
			if (optlen > 8) {
				proto_tree_add_text(subtree, tvb, off + 8,
					optlen - 8, "Link-layer address");
			}
			break;
		case 2:
			if (optlen < 10) {
				proto_tree_add_text(subtree, tvb, off,
					optlen, "DUID: malformed option");
				break;
			}
			proto_tree_add_text(subtree, tvb, off + 2, 8, "VUID");
			if (optlen > 10) {
				proto_tree_add_text(subtree, tvb, off + 10,
					optlen - 10, "Domain name");
			}
			break;
		case 3:
			if (optlen < 4) {
				proto_tree_add_text(subtree, tvb, off,
					optlen, "DUID: malformed option");
				break;
			}
			proto_tree_add_text(subtree, tvb, off + 2, 2,
				"Hardware type: %u",
				tvb_get_ntohs(tvb, off + 10));
			if (optlen > 4) {
				proto_tree_add_text(subtree, tvb, off + 4,
					optlen - 4, "Link-layer address");
			}
			break;
		}
		break;
	case 11:	/* DNS servers address */
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
	struct e_in6_addr in6;
	int off, eoff;
	gboolean at_end;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "DHCPv6");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	msgtype = tvb_get_guint8(tvb, 0);

	/* XXX relay agent messages have to be decoded differently */

	xid = tvb_get_ntohl(tvb, 0) & 0x00ffffff;

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_set_str(pinfo->cinfo, COL_INFO,
			downstream ? "DHCPv6 reply" : "DHCPv6 request");
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_dhcpv6, tvb, 0,
		    tvb_length(tvb), FALSE);
		bp_tree = proto_item_add_subtree(ti, ett_dhcpv6);

		proto_tree_add_uint(bp_tree, hf_dhcpv6_msgtype, tvb, 0, 1,
			msgtype);
		proto_tree_add_text(bp_tree, tvb, 1, 3, "XID: 0x%08x", xid);
		tvb_memcpy(tvb, (guint8 *)&in6, 4, sizeof(in6));
		proto_tree_add_text(bp_tree, tvb, 4, sizeof(in6),
			"Server address: %s", ip6_to_str(&in6));
	}

	off = 20;
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
