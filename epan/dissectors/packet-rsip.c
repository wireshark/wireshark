/* packet-rsip.c
 * Routines for Realm Specific IP (RSIP) Protocol dissection
 * Brian Ginsbach <ginsbach@cray.com>
 *
 * Copyright (c) 2006, 2010 Cray Inc. All Rights Reserved.
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/ipproto.h>

/* Forward declaration we need below */
void proto_reg_handoff_rsip(void);

/* Initialize the protocol and registered fields */
static int proto_rsip = -1;
static int hf_rsip_version = -1;
static int hf_rsip_message_type = -1;
static int hf_rsip_message_length = -1;
static int hf_rsip_parameter_type = -1;
static int hf_rsip_parameter_length = -1;
static int hf_rsip_parameter_value = -1;
static int hf_rsip_parameter_address_type = -1;
static int hf_rsip_parameter_address_ipv4 = -1;
static int hf_rsip_parameter_address_ipv4_netmask = -1;
static int hf_rsip_parameter_address_ipv6 = -1;
static int hf_rsip_parameter_address_fqdn = -1;
static int hf_rsip_parameter_ports_number = -1;
static int hf_rsip_parameter_ports_port_number = -1;
static int hf_rsip_parameter_lease_time = -1;
static int hf_rsip_parameter_client_id = -1;
static int hf_rsip_parameter_bind_id = -1;
static int hf_rsip_parameter_tunnel_type = -1;
static int hf_rsip_parameter_method = -1;
static int hf_rsip_parameter_error = -1;
static int hf_rsip_parameter_flow_policy_local = -1;
static int hf_rsip_parameter_flow_policy_remote = -1;
static int hf_rsip_parameter_indicator = -1;
static int hf_rsip_parameter_message_counter = -1;
static int hf_rsip_parameter_vendor_specific_vendor_id = -1;
static int hf_rsip_parameter_vendor_specific_subtype = -1;
static int hf_rsip_parameter_vendor_specific_value = -1;
static int hf_rsip_parameter_spi_number = -1;
static int hf_rsip_parameter_spi = -1;

/* Initialize the subtree pointers */
static gint ett_rsip = -1;
static gint ett_rsip_param = -1;
static gint ett_rsip_param_val = -1;

#define UDP_PORT_RSIP	4555
#define TCP_PORT_RSIP	4555

/* Message Types in RFC 3103 Appendix B / RFC 3104 Appendix C style */
static const value_string msg_type_appendix_vals[] = {
	{ 1,	"ERROR_RESPONSE" },
	{ 2,	"REGISTER_REQUEST" },
	{ 3,	"REGISTER_RESPONSE" },
	{ 4,	"DE-REGISTER_REQUEST" },
	{ 5,	"DE-REGISTER_RESPONSE" },
	{ 6,	"ASSIGN_REQUEST_RSA-IP" },
	{ 7,	"ASSIGN_RESPONSE_RSA-IP" },
	{ 8,	"ASSIGN_REQUEST_RSAP-IP" },
	{ 9,	"ASSIGN_RESPONSE_RSAP-IP" },
	{ 10,	"EXTEND_REQUEST" },
	{ 11,	"EXTEND_RESPONSE" },
	{ 12,	"FREE_REQUEST" },
	{ 13,	"FREE_RESPONSE" },
	{ 14,	"QUERY_REQUEST" },
	{ 15,	"QUERY_RESPONSE" },
	{ 16,	"LISTEN_REQUEST" },
	{ 17,	"LISTEN_RESPONSE" },
	{ 22,	"ASSIGN_REQUEST_RSIPSEC" },
	{ 23,	"ASSIGN_RESPONSE_RSIPEC" },
	{ 0,	NULL }
};

static const value_string msg_type_vals[] = {
	{ 1,	"Error Response" },
	{ 2,	"Register Request" },
	{ 3,	"Register Response" },
	{ 4,	"Deregister Request" },
	{ 5,	"Deregister Response" },
	{ 6,	"Assign Request RSA-IP" },
	{ 7,	"Assign Response RSA-IP" },
	{ 8,	"Assign Request RSAP-IP" },
	{ 9,	"Assign Response RSAP-IP" },
	{ 10,	"Extend Request" },
	{ 11,	"Extend Response" },
	{ 12,	"Free Request" },
	{ 13,	"Free Response" },
	{ 14,	"Query Request" },
	{ 15,	"Query Response" },
	{ 16,	"Listen Request" },
	{ 17,	"Listen Response" },
	{ 22,	"Assign Request RSIPsec" },
	{ 23,	"Assign Response RSIPsec" },
	{ 0,	NULL }
};

static const value_string param_type_vals[] = {
	{ 1,	"Address" },
	{ 2,	"Port" },
	{ 3,	"Lease Time" },
	{ 4,	"Client ID" },
	{ 5,	"Bind ID" },
	{ 6,	"Tunnel Type" },
	{ 7,	"RSIP Method" },
	{ 8,	"Error" },
	{ 9,	"Flow Policy" },
	{ 10,	"Indicator" },
	{ 11,	"Message Counter" },
	{ 12,	"Vendor Specific" },
	{ 22,	"SPI" },
	{ 0,	NULL }
};

static const value_string addr_type_vals[] = {
	{ 0,	"Reserved" },
	{ 1,	"IPv4" },
	{ 2,	"IPv4 Netmask" },
	{ 3,	"IPv6" },
	{ 4,	"Fully Qualified Doman Name" },
	{ 0,	NULL }
};

static const value_string tunnel_type_vals[] = {
	{ 1,	"IP-IP Tunnel" },
	{ 2,	"GRE Tunnel" },
	{ 3,	"L2TP" },
	{ 0,	NULL }
};

static const value_string method_vals[] = {
	{ 1,	"RSA-IP" },
	{ 2,	"RSAP-IP" },
	{ 0,	NULL }
};

#if 0
/* Error Numbers in RFC 3103 Appendix A / RFC 3104 Appendix B style */
static const value_string error_number_appendix_vals[] = {
	{ 101,	"UNKNOWN_ERROR" },
	{ 102,	"USE_TCP" },
	{ 103,	"FLOW_POLICY_VIOLATION" },
	{ 104,	"INTERNAL_SERVER_ERROR" },
	{ 105,	"MESSAGE_COUNTER_REQUIRED" },
	{ 106,	"UNSUPPORTED_RSIP_VERSION" },
	{ 201,	"MISSING_PARAM" },
	{ 202,	"DUPLICATE_PARAM" },
	{ 203,	"EXTRA_PARAM" },
	{ 204,	"ILLEGAL_PARAM" },
	{ 205,	"BAD_PARAM" },
	{ 206,	"ILLEGAL_MESSAGE" },
	{ 207,	"BAD_MESSAGE" },
	{ 208,	"UNSUPPORTED_MESSAGE" },
	{ 301,	"REGISTER_FIRST" },
	{ 302,	"ALREADY_REGISTERED" },
	{ 303,	"ALREADY_UNREGISTERED" },
	{ 304,	"REGISTRATION_DENIED" },
	{ 305,	"BAD_CLIENT_ID" },
	{ 306,	"BAD_BIND_ID" },
	{ 307,	"BAD_TUNNEL_TYPE" },
	{ 308,	"LOCAL_ADDR_UNAVAILABLE" },
	{ 309,	"LOCAL_ADDRPORT_UNAVAILABLE" },
	{ 310,	"LOCAL_ADDR_INUSE" },
	{ 311,	"LOCAL_ADDRPORT_INUSE" },
	{ 312,	"LOCAL_ADDR_UNALlOWED" },
	{ 313,	"LOCAL_ADDRPORT_UNALLOWED" },
	{ 314,	"REMOTE_ADDR_UNALLOWED" },
	{ 315,	"REMOTE_ADDRPORT_UNALLOWED" },
	{ 400,	"IPSEC_UNALLOWED" },
	{ 401,	"IPSEC_SPI_UNAVAILABLE" },
	{ 402,	"IPSEC_SPI_INUSE" },
	{ 0,	NULL }
};
#endif

static const value_string error_number_vals[] = {
	{ 101,	"Unknown Error" },
	{ 102,	"Use TCP" },
	{ 103,	"Flow Policy Violation" },
	{ 104,	"Internal Server Error" },
	{ 105,	"Message Counter Required" },
	{ 106,	"Unsupported RSIP Version" },
	{ 201,	"Missing Parameter" },
	{ 202,	"Duplicate Parameter" },
	{ 203,	"Extra Paramter" },
	{ 204,	"Illegal Parameter" },
	{ 205,	"Bad Parameter" },
	{ 206,	"Illegal Message" },
	{ 207,	"Bad Message" },
	{ 208,	"Unsupported Message" },
	{ 301,	"Register First" },
	{ 302,	"Already Registered" },
	{ 303,	"Already Unregistered" },
	{ 304,	"Registration Denied" },
	{ 305,	"Bad Client ID" },
	{ 306,	"Bad Bind ID" },
	{ 307,	"Bad Tunnel Type" },
	{ 308,	"Local Address Unavailable" },
	{ 309,	"Local Address Port Unavailable" },
	{ 310,	"Local Address Inuse" },
	{ 311,	"Local Address Port Inuse" },
	{ 312,	"Local Address Unallowed" },
	{ 313,	"Local Address Port Unallowed" },
	{ 314,	"Remote Address Unallowed" },
	{ 315,	"Remote Address Port Unallowed" },
	{ 400,	"IPsec Unallowed" },
	{ 401,	"IPsec SPI Unavailable" },
	{ 402,	"IPsec SPI Inuse" },
	{ 0,	NULL }
};

static const value_string lcl_flow_policy_vals[] = {
	{ 1,	"Macro Flows" },
	{ 2,	"Micro Flows " },
	{ 0,	NULL }
};

static const value_string rmt_flow_policy_vals[] = {
	{ 1,	"Macro Flows" },
	{ 2,	"Micro Flows" },
	{ 3,	"No Policy" },
	{ 0,	NULL }
};

/* Code to actually dissect the packets */
static int
rsip_parameter(tvbuff_t *tvb, proto_tree *rsip_tree, int off, int eoff)
{
	int		consumed, i, paramleft;
	guint8		addrtype, flowpolicy, method, number, paramtype, tuntype;
	guint16		error, ind, paramlen, portnum;
	guint32		bid, cid, leasetm, msgc;
	proto_tree	*p_tree, *v_tree;
	proto_item	*pti, *vti;
	struct e_in6_addr in6;

	/* XXX */
	if (off >= eoff)
		return 0;

	paramtype = tvb_get_guint8(tvb, off);
	paramlen = tvb_get_ntohs(tvb, off + 1);

	pti = proto_tree_add_text(rsip_tree, tvb, off, 3 + paramlen,
	    "%s",
	    val_to_str(paramtype, param_type_vals, "Unknown (%d)"));
	p_tree = proto_item_add_subtree(pti, ett_rsip_param);

	proto_tree_add_item(p_tree, hf_rsip_parameter_type, tvb,
	    off, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(p_tree, hf_rsip_parameter_length, tvb,
	    off + 1, 2, ENC_BIG_ENDIAN);
	consumed = 3;

	if (paramlen == 0)
	    return consumed;

	vti = proto_tree_add_item(p_tree, hf_rsip_parameter_value,
	    tvb, off + 3, paramlen, ENC_NA);
	v_tree = proto_item_add_subtree(vti, ett_rsip_param_val);

	switch (paramtype) {
	case 1:		/* Address */
		proto_tree_add_item(v_tree, hf_rsip_parameter_address_type,
		    tvb, off + 3, 1, ENC_BIG_ENDIAN);

		addrtype = tvb_get_guint8(tvb, off + 3);

		switch (addrtype) {
		case 0:		/* Reserved */
			break;
		case 1:		/* IPv4 */
			if (paramlen - 1 > 0) {
				proto_tree_add_item(v_tree,
				    hf_rsip_parameter_address_ipv4, tvb,
				    off + 4, paramlen - 1, FALSE);
				proto_item_append_text(pti, ": %s",
				    tvb_ip_to_str(tvb, off + 4));
			} else
				proto_item_append_text(pti,
				    ": Any IPv4 Address");
			break;
		case 2:		/* IPv4 netmask */
			if (paramlen - 1 > 0) {
				proto_tree_add_item(v_tree,
				    hf_rsip_parameter_address_ipv4_netmask,
				    tvb, off + 4, paramlen - 1, FALSE);
				proto_item_append_text(pti, "(netmask): %s",
				    tvb_ip_to_str(tvb, off + 4));
			} else
				proto_item_append_text(pti,
				    ": Any IPv4 Netmask");
			break;
		case 3:		/* IPv6 */
			if (paramlen - 1 > 0) {
				tvb_get_ipv6(tvb, off + 4, &in6);
				proto_tree_add_item(v_tree,
				    hf_rsip_parameter_address_ipv6, tvb,
				    off + 4, paramlen - 1, FALSE);
				proto_item_append_text(pti, ": %s",
				    ip6_to_str(&in6));
			} else
				proto_item_append_text(pti,
				    ": Any IPv6 Address");
			break;
		case 4:		/* FQDN */
			if (paramlen - 1 > 0) {
				proto_tree_add_item(v_tree,
				    hf_rsip_parameter_address_fqdn, tvb,
				    off + 4, paramlen - 1, FALSE);
				proto_item_append_text(pti, ": %s",
				    tvb_format_text(tvb, off + 4, paramlen - 1));
			} else
				proto_item_append_text(pti,
				    ": Any Fully Qualified Domain Name");
			break;
		default:
			proto_tree_add_text(p_tree, tvb, off + 4,
			    paramlen - 1, ": Unknown Address Type");
			break;
		}
		break;
	case 2:		/* Ports */
		proto_tree_add_item(v_tree, hf_rsip_parameter_ports_number,
		    tvb, off + 3, 1, ENC_BIG_ENDIAN);
		number = tvb_get_guint8(tvb, off + 3);
		if (paramlen == 1) {
			switch (number) {
			case 0:
				proto_item_append_text(pti, ": Unspecified");
				break;
			case 1:
				proto_item_append_text(pti, ": Any port");
				break;
			default:
				proto_item_append_text(pti, ": Any %d ports",
				    number);
				break;
			}
		} else {
			portnum = tvb_get_ntohs(tvb, off + 4);
			if (number == 1) {
				proto_tree_add_item(v_tree,
				    hf_rsip_parameter_ports_port_number,
				    tvb, off + 4, 2, ENC_BIG_ENDIAN);
			} else {
				paramleft = paramlen - 1;
				if (paramleft == 2) {
					proto_tree_add_uint_format_value(v_tree,
					    hf_rsip_parameter_ports_port_number,
					    tvb, off + 4, 2, portnum, "%d - %d",
					    portnum, portnum + number);
					proto_item_append_text(pti,
					    ": %d - %d", portnum,
					    portnum + number);
				} else {
					for (i = off + 4;
					    paramleft > 0;
					    i += 2, paramleft -= 2)
						proto_tree_add_item(v_tree,
						    hf_rsip_parameter_ports_port_number,
						    tvb, i, 2, ENC_BIG_ENDIAN);
					proto_item_append_text(pti,
					    ": List of %d Ports", number);
				}
			}
		}
		break;
	case 3:		/* Lease Time */
		/* XXX if paramlen != 4 we've got a protocol violation */
		proto_tree_add_item(v_tree, hf_rsip_parameter_lease_time,
		    tvb, off + 3, paramlen, ENC_BIG_ENDIAN);
		leasetm = tvb_get_ntohl(tvb, off + 3);
		proto_item_append_text(pti, ": %d seconds", leasetm);
		break;
	case 4:		/* Client ID */
		/* XXX if paramlen != 4 we've got a protocol violation */
		proto_tree_add_item(v_tree, hf_rsip_parameter_client_id,
		    tvb, off + 3, paramlen, ENC_BIG_ENDIAN);
		cid = tvb_get_ntohl(tvb, off + 3);
		proto_item_append_text(pti, ": %d", cid);
		break;
	case 5:		/* Bind ID */
		/* XXX if paramlen != 4 we've got a protocol violation */
		proto_tree_add_item(v_tree, hf_rsip_parameter_bind_id,
		    tvb, off + 3, paramlen, ENC_BIG_ENDIAN);
		bid = tvb_get_ntohl(tvb, off + 3);
		proto_item_append_text(pti, ": %d", bid);
		break;
	case 6:		/* Tunnel Type */
		/* XXX if paramlen != 1 we've got a protocol violation */
		proto_tree_add_item(v_tree, hf_rsip_parameter_tunnel_type,
		    tvb, off + 3, paramlen, ENC_BIG_ENDIAN);
		tuntype = tvb_get_guint8(tvb, off + 3);
		proto_item_append_text(pti, ": %s",
		    val_to_str(tuntype, tunnel_type_vals,
		        "Unknown Tunnel Type (%d)"));
		break;
	case 7:		/* RSIP Method */
		/* XXX if paramlen != 1 we've got a protocol violation */
		proto_tree_add_item(v_tree, hf_rsip_parameter_method,
		    tvb, off + 3, paramlen, ENC_BIG_ENDIAN);
		method = tvb_get_guint8(tvb, off + 3);
		proto_item_append_text(pti, ": %s",
		    val_to_str(method, method_vals,
		    "Unknown RSIP Method (%d)"));
		break;
	case 8:		/* Error */
		/* XXX if paramlen != 2 we've got a protocol violation */
		proto_tree_add_item(v_tree, hf_rsip_parameter_error,
		    tvb, off + 3, paramlen, ENC_BIG_ENDIAN);
		error = tvb_get_ntohs(tvb, off + 3);
		proto_item_append_text(pti, ": %s",
		    val_to_str(error, error_number_vals, "Undefined Error (%d)"));
		break;
	case 9:		/* Flow Policy */
		/* XXX if paramlen != 2 we've got a protocol violation */
		proto_tree_add_item(v_tree,
		    hf_rsip_parameter_flow_policy_local, tvb, off + 3, 1, ENC_BIG_ENDIAN);
		flowpolicy = tvb_get_guint8(tvb, off + 3);
		proto_item_append_text(pti, ": %s",
		    val_to_str(flowpolicy, lcl_flow_policy_vals,
		    "Undefined Local Flow Policy (%d)"));
		proto_tree_add_item(v_tree,
		    hf_rsip_parameter_flow_policy_remote, tvb, off + 4, 1,
		    ENC_BIG_ENDIAN);
		flowpolicy = tvb_get_guint8(tvb, off + 4);
		proto_item_append_text(pti, "/%s",
		    val_to_str(flowpolicy, rmt_flow_policy_vals,
		    "Undefined Remote Flow Policy (%d)"));
		break;
	case 10:	/* Indicator */
		/* XXX if paramlen != 2 we've got a protocol violation */
		proto_tree_add_item(v_tree, hf_rsip_parameter_indicator, tvb,
		    off + 3, 2, ENC_BIG_ENDIAN);
		ind = tvb_get_ntohs(tvb, off + 3);
		proto_item_append_text(pti, ": %d", ind);
		break;
	case 11:	/* Message Counter */
		/* XXX if paramlen != 4 we've got a protocol violation */
		proto_tree_add_item(v_tree, hf_rsip_parameter_message_counter,
		    tvb, off + 3, 4, ENC_BIG_ENDIAN);
		msgc = tvb_get_ntohl(tvb, off + 3);
		proto_item_append_text(pti, ": %d", msgc);
		break;
	case 12:	/* Vendor Specific */
		proto_tree_add_item(v_tree,
		    hf_rsip_parameter_vendor_specific_vendor_id, tvb, off + 3,
		    2, ENC_BIG_ENDIAN);
		proto_tree_add_item(v_tree,
		    hf_rsip_parameter_vendor_specific_subtype, tvb, off + 5,
		    2, ENC_BIG_ENDIAN);
		proto_tree_add_item(v_tree,
		    hf_rsip_parameter_vendor_specific_value, tvb, off + 9,
		    paramlen - 4, ENC_NA);
		break;
	case 22:	/* SPI */
		proto_tree_add_item(v_tree, hf_rsip_parameter_spi_number, tvb,
		    off + 3, 2, ENC_BIG_ENDIAN);
		/* XXX need loop? */
		proto_tree_add_item(v_tree, hf_rsip_parameter_spi, tvb,
		    off + 5, 4, ENC_BIG_ENDIAN);
		break;
	default:
		break;
	}

	consumed += paramlen;

	return consumed;
}

static int
rsip_message_error_response(tvbuff_t *tvb, proto_tree *rsip_tree,
    int offset, int eoffset)
{
	int		consumed, offset_delta;
	/*
	   <Error>
	   [Message Counter]	UDP required
	   [Client ID]
	   [Bind ID]
	 */

	consumed = 0;
	do {
		offset_delta =
		    rsip_parameter(tvb, rsip_tree, offset, eoffset);
		offset += offset_delta;
		consumed += offset_delta;
	} while ((offset_delta > 0) && (offset < eoffset));

	return consumed;
}

static int
rsip_message_register_request(tvbuff_t *tvb, proto_tree *rsip_tree,
    int offset, int eoffset)
{
	int		consumed, offset_delta;
	/*
	   [Message Counter]	UDP required
	 */

	consumed = 0;
	do {
		offset_delta =
		    rsip_parameter(tvb, rsip_tree, offset, eoffset);
		offset += offset_delta;
		consumed += offset_delta;
	} while ((offset_delta > 0) && (offset < eoffset));

	return consumed;
}

static int
rsip_message_register_response(tvbuff_t *tvb, proto_tree *rsip_tree,
    int offset, int eoffset)
{
	int		consumed, offset_delta;
	/*
	   <Client ID>
	   <Lease Time>
	   <Flow Policy>
	   [Message Counter]	UDP required
	   [RSIP Method]...
	   [Tunnel Type]...
	 */

	consumed = 0;
	do {
		offset_delta =
		    rsip_parameter(tvb, rsip_tree, offset, eoffset);
		offset += offset_delta;
		consumed += offset_delta;
	} while ((offset_delta > 0) && (offset < eoffset));

	return consumed;
}

static int
rsip_message_deregister_request(tvbuff_t *tvb, proto_tree *rsip_tree,
    int offset, int eoffset)
{
	int		consumed, offset_delta;
	/*
	   <Client ID>
	   [Message Counter]	UDP required
	 */

	consumed = 0;
	do {
		offset_delta =
		    rsip_parameter(tvb, rsip_tree, offset, eoffset);
		offset += offset_delta;
		consumed += offset_delta;
	} while ((offset_delta > 0) && (offset < eoffset));

	return consumed;
}

static int
rsip_message_deregister_response(tvbuff_t *tvb, proto_tree *rsip_tree,
    int offset, int eoffset)
{
	return rsip_message_deregister_request(tvb, rsip_tree, offset, eoffset);
}

static int
rsip_message_assign_request_rsaip(tvbuff_t *tvb, proto_tree *rsip_tree,
    int offset, int eoffset)
{
	int		consumed, offset_delta;
	/*
	   <Client ID>
	   <Address (local)>
	   <Address (remote)>
	   <Ports (remote)>
	   [Message Counter]	UDP required
	   [Lease Time]
	   [Tunnel Type]
	 */

	consumed = 0;
	do {
		offset_delta =
		    rsip_parameter(tvb, rsip_tree, offset, eoffset);
		offset += offset_delta;
		consumed += offset_delta;
	} while ((offset_delta > 0) && (offset < eoffset));

	return consumed;
}

static int
rsip_message_assign_response_rsaip(tvbuff_t *tvb, proto_tree *rsip_tree,
    int offset, int eoffset)
{
	int		consumed, offset_delta;
	/*
	   <Client ID>
	   <Bind ID>
	   <Address (local)>
	   <Address (remote)>
	   <Ports (remote)>
	   <Lease Time>
	   <Tunnel Type>
	   [Message Counter]	UDP required
	   [Address (tunnel endpoint)]
	 */

	consumed = 0;
	do {
		offset_delta =
		    rsip_parameter(tvb, rsip_tree, offset, eoffset);
		offset += offset_delta;
		consumed += offset_delta;
	} while ((offset_delta > 0) && (offset < eoffset));

	return consumed;
}

static int
rsip_message_assign_request_rsapip(tvbuff_t *tvb, proto_tree *rsip_tree,
    int offset, int eoffset)
{
	int		consumed, offset_delta;
	/*
	   <Client ID>
	   <Address (local)>
	   <Ports (local)>
	   <Address (remote)>
	   <Ports (remote)>
	   [Message Counter]	UDP required
	   [Lease Time]
	   [Tunnel Type]
	 */

	consumed = 0;
	do {
		offset_delta =
		    rsip_parameter(tvb, rsip_tree, offset, eoffset);
		offset += offset_delta;
		consumed += offset_delta;
	} while ((offset_delta > 0) && (offset < eoffset));

	return consumed;
}

static int
rsip_message_assign_response_rsapip(tvbuff_t *tvb, proto_tree *rsip_tree,
    int offset, int eoffset)
{
	int		consumed, offset_delta;
	/*
	   <Client ID>
	   <Bind ID>
	   <Address (local)>
	   <Ports (local)>
	   <Address (remote)>
	   <Ports (remote)>
	   <Lease Time>
	   <Tunnel Type>
	   [Address (tunnel endpoint)]
	   [Message Counter]	UDP required
	 */

	consumed = 0;
	do {
		offset_delta =
		    rsip_parameter(tvb, rsip_tree, offset, eoffset);
		offset += offset_delta;
		consumed += offset_delta;
	} while ((offset_delta > 0) && (offset < eoffset));

	return consumed;
}

static int
rsip_message_extend_request(tvbuff_t *tvb, proto_tree *rsip_tree,
    int offset, int eoffset)
{
	int		consumed, offset_delta;
	/*
	   <Client ID>
	   <Bind ID>
	   [Lease Time]
	   [Message Counter]	UDP required
	*/

	consumed = 0;
	do {
		offset_delta =
		    rsip_parameter(tvb, rsip_tree, offset, eoffset);
		offset += offset_delta;
		consumed += offset_delta;
	} while ((offset_delta > 0) && (offset < eoffset));

	return consumed;
}

static int
rsip_message_extend_response(tvbuff_t *tvb, proto_tree *rsip_tree,
    int offset, int eoffset)
{
	int		consumed, offset_delta;
	/*
	   <Client ID>
	   <Bind ID>
	   <Lease Time>
	   [Message Counter]	UDP required
	*/

	consumed = 0;
	do {
		offset_delta =
		    rsip_parameter(tvb, rsip_tree, offset, eoffset);
		offset += offset_delta;
		consumed += offset_delta;
	} while ((offset_delta > 0) && (offset < eoffset));

	return consumed;
}

static int
rsip_message_free_request(tvbuff_t *tvb, proto_tree *rsip_tree,
    int offset, int eoffset)
{
	int		consumed, offset_delta;
	/*
	   <Client ID>
	   <Bind ID>
	   [Message Counter]	UDP required
	*/

	consumed = 0;
	do {
		offset_delta =
		    rsip_parameter(tvb, rsip_tree, offset, eoffset);
		offset += offset_delta;
		consumed += offset_delta;
	} while ((offset_delta > 0) && (offset < eoffset));

	return consumed;
}

static int
rsip_message_free_response(tvbuff_t *tvb, proto_tree *rsip_tree,
    int offset, int eoffset)
{
	int		consumed, offset_delta;
	/*
	   <Client ID>
	   <Bind ID>
	   [Message Counter]	UDP required
	*/

	consumed = 0;
	do {
		offset_delta =
		    rsip_parameter(tvb, rsip_tree, offset, eoffset);
		offset += offset_delta;
		consumed += offset_delta;
	} while ((offset_delta > 0) && (offset < eoffset));

	return consumed;
}

static int
rsip_message_query_request(tvbuff_t *tvb, proto_tree *rsip_tree,
    int offset, int eoffset)
{
	int		consumed, offset_delta;
	/*
	   <Client ID>
	   [Message Counter]	UDP required
	   [Address Tuple]...
	   [Network Tuple]...

	   <Address Tuple> ::= <Indicator (address)>
	                       <Address>

	   <Netwrok Tuple> ::= <Indicator (network)>
	                       <Address (network)>
	                       <Address (netmask)>
	*/

	consumed = 0;
	do {
		offset_delta =
		    rsip_parameter(tvb, rsip_tree, offset, eoffset);
		offset += offset_delta;
		consumed += offset_delta;
	} while ((offset_delta > 0) && (offset < eoffset));

	return consumed;
}

static int
rsip_message_query_response(tvbuff_t *tvb, proto_tree *rsip_tree,
    int offset, int eoffset)
{
	int		consumed, offset_delta;
	/*
	   <Client ID>
	   [Message Counter]	UDP required
	   [Local Address Tuple]...
	   [Local Network Tuple]...
	   [Remote Address Tuple]...
	   [Remote Network Tuple]...

	   <Local Address Tuple> ::= <Indicator (local address)>
	                             <Address>

	   <Local Network Tuple> ::= <Indicator (local network)>
	                             <Address (network)>
				     <Address (netmask)>

	   <Remote Address Tuple> ::= <Indicator (remote address)>
	                              <Address>

	   <Remote Network Tuple> ::= <Indicator (remote network)>
	                              <Address (network)>
				      <Address (netmask)>
	*/

	consumed = 0;
	do {
		offset_delta =
		    rsip_parameter(tvb, rsip_tree, offset, eoffset);
		offset += offset_delta;
		consumed += offset_delta;
	} while ((offset_delta > 0) && (offset < eoffset));

	return consumed;
}

static int
rsip_message_listen_request(tvbuff_t *tvb, proto_tree *rsip_tree,
    int offset, int eoffset)
{
	int		consumed, offset_delta;
	/*
	   <Client ID>
	   <Address (local)>
	   <Ports (local)>
	   <Address (remote)>
	   <Ports (remote)>
	   [Message Counter]	UDP required
	   [Lease Time]
	   [Tunnel Type]...
	 */

	consumed = 0;
	do {
		offset_delta =
		    rsip_parameter(tvb, rsip_tree, offset, eoffset);
		offset += offset_delta;
		consumed += offset_delta;
	} while ((offset_delta > 0) && (offset < eoffset));

	return consumed;
}

static int
rsip_message_listen_response(tvbuff_t *tvb, proto_tree *rsip_tree,
    int offset, int eoffset)
{
	int		consumed, offset_delta;
	/*
	   <Client ID>
	   <Bind ID>
	   <Address (local)>
	   <Ports (local)>
	   <Address (remote)>
	   <Ports (remote)>
	   <Tunnel Type>
	   <Lease Time>
	   [Address (tunnel endpoint)]
	   [Message Counter]	UDP required
	 */

	consumed = 0;
	do {
		offset_delta =
		    rsip_parameter(tvb, rsip_tree, offset, eoffset);
		offset += offset_delta;
		consumed += offset_delta;
	} while ((offset_delta > 0) && (offset < eoffset));

	return consumed;
}

static int
rsip_message_assign_request_rsipsec(tvbuff_t *tvb, proto_tree *rsip_tree,
    int offset, int eoffset)
{
	int		consumed, offset_delta;
	/*
	   <Client ID>
	   <Address (local)>
	   <Ports (local)>
	   <Address (remote)>
	   <Ports (remote)>
	   [Message Counter]	UDP required
	   [Lease Time]
	   [Tunnel Type]...
	 */

	consumed = 0;
	do {
		offset_delta =
		    rsip_parameter(tvb, rsip_tree, offset, eoffset);
		offset += offset_delta;
		consumed += offset_delta;
	} while ((offset_delta > 0) && (offset < eoffset));

	return consumed;
}

static int
rsip_message_assign_response_rsipsec(tvbuff_t *tvb, proto_tree *rsip_tree,
    int offset, int eoffset)
{
	int		consumed, offset_delta;
	/*
	   <Client ID>
	   <Bind ID>
	   <Address (local)>
	   <Ports (local)>
	   <Address (remote)>
	   <Ports (remote)>
	   <Tunnel Type>
	   <Lease Time>
	   [Address (tunnel endpoint)]
	   [Message Counter]	UDP required
	 */

	consumed = 0;
	do {
		offset_delta =
		    rsip_parameter(tvb, rsip_tree, offset, eoffset);
		offset += offset_delta;
		consumed += offset_delta;
	} while ((offset_delta > 0) && (offset < eoffset));

	return consumed;
}

static void
dissect_rsip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item	*ti;
	proto_tree	*rsip_tree;
	guint8		msgtype;
	/*gboolean	msgcnt_required;*/
	int		eoff;

	msgtype = tvb_get_guint8(tvb, 1);

	/*msgcnt_required = (pinfo->ipproto == IP_PROTO_UDP)? TRUE : FALSE;*/

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RSIP");

	col_clear(pinfo->cinfo, COL_INFO);

	col_add_str(pinfo->cinfo, COL_INFO,
	    val_to_str(msgtype, msg_type_vals,
	        "Unknown Message Type (0x%0x)"));

	if (tree) {
		ti = proto_tree_add_item(tree, proto_rsip, tvb, 0, -1, FALSE);

		rsip_tree = proto_item_add_subtree(ti, ett_rsip);

		proto_tree_add_item(rsip_tree,
		    hf_rsip_version, tvb, 0, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(rsip_tree,
		    hf_rsip_message_type, tvb, 1, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(rsip_tree,
		    hf_rsip_message_length, tvb, 2, 2, ENC_BIG_ENDIAN);

		eoff = tvb_reported_length(tvb);

		switch (msgtype) {
		case 1:		/* Error Response */
			rsip_message_error_response(tvb, rsip_tree, 4, eoff);
			break;
		case 2:		/* Register Request */
			rsip_message_register_request(tvb, rsip_tree, 4, eoff);
			break;
		case 3:		/* Register Response */
			rsip_message_register_response(tvb, rsip_tree, 4, eoff);
			break;
		case 4:		/* De-register Request */
			rsip_message_deregister_request(tvb, rsip_tree, 4, eoff);
			break;
		case 5:		/* De-register Response */
			rsip_message_deregister_response(tvb, rsip_tree, 4, eoff);
			break;
		case 6:		/* Assign Request RSA-IP */
			rsip_message_assign_request_rsaip(tvb, rsip_tree, 4, eoff);
			break;
		case 7:		/* Assign Response RSA-IP */
			rsip_message_assign_response_rsaip(tvb, rsip_tree, 4, eoff);
			break;
		case 8:		/* Assign Request RSAP-IP */
			rsip_message_assign_request_rsapip(tvb, rsip_tree, 4, eoff);
			break;
		case 9:		/* Assign Response RSAP-IP */
			rsip_message_assign_response_rsapip(tvb, rsip_tree, 4, eoff);
			break;
		case 10:	/* Extend Request */
			rsip_message_extend_request(tvb, rsip_tree, 4, eoff);
			break;
		case 11:	/* Extend Response */
			rsip_message_extend_response(tvb, rsip_tree, 4, eoff);
			break;
		case 12:	/* Free Request */
			rsip_message_free_request(tvb, rsip_tree, 4, eoff);
			break;
		case 13:	/* Free Response */
			rsip_message_free_response(tvb, rsip_tree, 4, eoff);
			break;
		case 14:	/* Query Request */
			rsip_message_query_request(tvb, rsip_tree, 4, eoff);
			break;
		case 15:	/* Query Response */
			rsip_message_query_response(tvb, rsip_tree, 4, eoff);
			break;
		case 16:	/* Listen Request */
			rsip_message_listen_request(tvb, rsip_tree, 4, eoff);
			break;
		case 17:	/* Listen Response */
			rsip_message_listen_response(tvb, rsip_tree, 4, eoff);
			break;
		case 22:	/* Assign Request RSIPsec */
			rsip_message_assign_request_rsipsec(tvb, rsip_tree, 4, eoff);
			break;
		case 23:	/* Assign Response RSIPsec */
			rsip_message_assign_response_rsipsec(tvb, rsip_tree, 4, eoff);
			break;
		}
	}
}


/* Register the protocol with Wireshark */
void
proto_register_rsip(void)
{

	static hf_register_info hf[] = {
		{ &hf_rsip_version,
			{ "Protocol version",	"rsip.version",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_rsip_message_type,
			{ "Message type",	"rsip.message_type",
			  FT_UINT8, BASE_DEC, VALS(msg_type_appendix_vals), 0x0,
			  NULL, HFILL }
		},
		{ &hf_rsip_message_length,
			{ "Message length",	"rsip.message_length",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},

		{ &hf_rsip_parameter_type,
			{ "Type",		"rsip.parameter.type",
			  FT_UINT8, BASE_DEC, VALS(param_type_vals), 0x0,
			  NULL, HFILL }
		},
		{ &hf_rsip_parameter_length,
			{ "Length",		"rsip.parameter.length",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_rsip_parameter_value,
			{ "Value",		"rsip.parameter.value",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }},

		{ &hf_rsip_parameter_address_type,
			{ "Address type",	"rsip.parameter.address_type",
			  FT_UINT8, BASE_DEC, VALS(addr_type_vals), 0x0,
			  NULL, HFILL }
		},
		{ &hf_rsip_parameter_address_ipv4,
			{ "IPv4 Address",	"rsip.parameter.address",
			  FT_IPv4, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_rsip_parameter_address_ipv4_netmask,
			{ "IPv4 Netmask",	"rsip.parameter.netmask",
			  FT_IPv4, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_rsip_parameter_address_ipv6,
			{ "IPv6 Address",	"rsip.parameter.address",
			  FT_IPv6, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_rsip_parameter_address_fqdn,
			{ "Fully Qualified Domain Name", "rsip.parameter.fqdn",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},

		{ &hf_rsip_parameter_ports_number,
			{ "Number",		"rsip.parameter.ports.number",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_rsip_parameter_ports_port_number,
			{ "Port",	"rsip.parameter.ports.port_number",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},

		{ &hf_rsip_parameter_lease_time,
			{ "Lease time",		"rsip.parameter.lease_time",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},

		{ &hf_rsip_parameter_client_id,
			{ "Client ID",		"rsip.parameter.client_id",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},

		{ &hf_rsip_parameter_bind_id,
			{ "Bind ID",		"rsip.parameter.bind_id",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},

		{ &hf_rsip_parameter_tunnel_type,
			{ "Tunnel type",		"rsip.parameter.tunnel_type",
			  FT_UINT8, BASE_DEC, VALS(tunnel_type_vals), 0x0,
			  NULL, HFILL }
		},

		{ &hf_rsip_parameter_method,
			{ "Method",		"rsip.method_param.method",
			  FT_UINT8, BASE_DEC, VALS(method_vals), 0x0,
			  NULL, HFILL }
		},

		{ &hf_rsip_parameter_error,
			{ "Error",		"rsip.parameter.error",
			  FT_UINT16, BASE_DEC, VALS(error_number_vals), 0x0,
			  NULL, HFILL }
		},

		{ &hf_rsip_parameter_flow_policy_local,
			{ "Local Flow Policy",	"rsip.parameter.local_flow_policy",
			  FT_UINT8, BASE_DEC, VALS(lcl_flow_policy_vals), 0x0,
			  NULL, HFILL }
		},
		{ &hf_rsip_parameter_flow_policy_remote,
			{ "Remote Flow Policy",	"rsip.parameter.remote_flow_policy",
			  FT_UINT8, BASE_DEC, VALS(rmt_flow_policy_vals), 0x0,
			  NULL, HFILL }
		},

		{ &hf_rsip_parameter_indicator,
			{ "Value",	"rsip.parameter.indicator",
			  FT_UINT16, BASE_HEX, NULL, 0x0,
			  NULL, HFILL }
		},

		{ &hf_rsip_parameter_message_counter,
			{ "Counter",	"rsip.parameter.message_counter",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},

		{ &hf_rsip_parameter_vendor_specific_vendor_id,
			{ "Vendor ID",	"rsip.parameter.vendor_specific.vendor_id",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_rsip_parameter_vendor_specific_subtype,
			{ "Subtype",	"rsip.parameter.vendor_specific.subtype",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_rsip_parameter_vendor_specific_value,
			{ "Value",	"rsip.parameter.vendor_specific.value",
			  FT_NONE, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},

		{ &hf_rsip_parameter_spi_number,
			{ "Number",	"rsip.parameter.spi_number",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_rsip_parameter_spi,
			{ "SPI",	"rsip.parameter.spi",
			  FT_UINT32, BASE_HEX, NULL, 0x0,
			  NULL, HFILL }
		}
	};

	static gint *ett[] = {
		&ett_rsip,
		&ett_rsip_param,
		&ett_rsip_param_val
	};

	proto_rsip = proto_register_protocol("Realm Specific IP Protocol",
	    "RSIP", "rsip");

	proto_register_field_array(proto_rsip, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_rsip(void)
{
	static gboolean initialized = FALSE;
	dissector_handle_t rsip_handle;

	if (!initialized) {

		rsip_handle = create_dissector_handle(dissect_rsip,
		    proto_rsip);
		dissector_add_uint("udp.port", UDP_PORT_RSIP, rsip_handle);
		dissector_add_uint("tcp.port", TCP_PORT_RSIP, rsip_handle);

		initialized = TRUE;
	}
}
