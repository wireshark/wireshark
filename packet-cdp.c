/* packet-cdp.c
 * Routines for the disassembly of the "Cisco Discovery Protocol"
 * (c) Copyright Hannes R. Boehm <hannes@boehm.org>
 *
 * $Id: packet-cdp.c,v 1.28 2000/12/28 09:49:09 guy Exp $
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
 
#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include "packet.h"
#include "strutil.h"
#include "nlpid.h"

/*
 * See
 *
 *	http://www.cisco.com/univercd/cc/td/doc/product/lan/trsrb/frames.htm
 *
 * for some information on CDP.
 */

/* Offsets in TLV structure. */
#define	TLV_TYPE	0
#define	TLV_LENGTH	2

static int proto_cdp = -1;
static int hf_cdp_version = -1;
static int hf_cdp_checksum = -1;
static int hf_cdp_ttl = -1;
static int hf_cdp_tlvtype = -1;
static int hf_cdp_tlvlength = -1;

static gint ett_cdp = -1;
static gint ett_cdp_tlv = -1;
static gint ett_cdp_address = -1;
static gint ett_cdp_capabilities = -1;

static int
dissect_address_tlv(tvbuff_t *tvb, int offset, int length, proto_tree *tree);
static void
dissect_capabilities(tvbuff_t *tvb, int offset, int length, proto_tree *tree);
static void
add_multi_line_string_to_tree(proto_tree *tree, tvbuff_t *tvb, gint start,
  gint len, const gchar *prefix);

#define TYPE_DEVICE_ID		0x0001
#define TYPE_ADDRESS		0x0002
#define TYPE_PORT_ID		0x0003
#define TYPE_CAPABILITIES	0x0004
#define TYPE_IOS_VERSION	0x0005
#define TYPE_PLATFORM		0x0006

static const value_string type_vals[] = {
	{ TYPE_DEVICE_ID,    "Device ID" },
	{ TYPE_ADDRESS,      "Addresses" },
	{ TYPE_PORT_ID,      "Port ID" },
	{ TYPE_CAPABILITIES, "Capabilities" },
	{ TYPE_IOS_VERSION,  "Software version" },
	{ TYPE_PLATFORM,     "Platform" },
	{ 0,                 NULL },
};
	
static void 
dissect_cdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti; 
    proto_tree *cdp_tree = NULL;
    int offset = 0;
    guint16 type;
    guint16 length;
    proto_item *tlvi;
    proto_tree *tlv_tree;
    int real_length;
    guint32 naddresses;
    int addr_length;

    CHECK_DISPLAY_AS_DATA(proto_cdp, tvb, pinfo, tree);

    pinfo->current_proto = "CDP";

    if (check_col(pinfo->fd, COL_PROTOCOL))
        col_set_str(pinfo->fd, COL_PROTOCOL, "CDP");
    if (check_col(pinfo->fd, COL_INFO))
        col_set_str(pinfo->fd, COL_INFO, "Cisco Discovery Protocol"); 

    if (tree){
        ti = proto_tree_add_item(tree, proto_cdp, tvb, offset,
        			 tvb_length_remaining(tvb, offset), FALSE);
	cdp_tree = proto_item_add_subtree(ti, ett_cdp);
	
	/* CDP header */
	proto_tree_add_item(cdp_tree, hf_cdp_version, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_uint_format(cdp_tree, hf_cdp_ttl, tvb, offset, 1,
				   tvb_get_guint8(tvb, offset),
				   "TTL: %u seconds",
				   tvb_get_guint8(tvb, offset));
	offset += 1;
	proto_tree_add_item(cdp_tree, hf_cdp_checksum, tvb, offset, 2, FALSE);
	offset += 2;

	while (tvb_reported_length_remaining(tvb, offset) != 0) {
	    type = tvb_get_ntohs(tvb, offset + TLV_TYPE);
	    length = tvb_get_ntohs(tvb, offset + TLV_LENGTH);

	    switch (type) {

	    case TYPE_DEVICE_ID:
		/* Device ID */
		tlvi = proto_tree_add_text(cdp_tree, tvb, offset,
			    length, "Device ID: %.*s",
			    length - 4,
			    tvb_get_ptr(tvb, offset + 4, length - 4));
		tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
		proto_tree_add_uint(tlv_tree, hf_cdp_tlvtype, tvb,
			    offset + TLV_TYPE, 2, type);
		proto_tree_add_uint(tlv_tree, hf_cdp_tlvlength, tvb,
			    offset + TLV_LENGTH, 2, length);
		proto_tree_add_text(tlv_tree, tvb, offset + 4,
			    length - 4, "Device ID: %.*s",
			    length - 4,
			    tvb_get_ptr(tvb, offset + 4, length - 4));
		offset += length;
		break;

	    case TYPE_ADDRESS:
		/* Addresses */
		tlvi = proto_tree_add_text(cdp_tree, tvb, offset,
			    length, "Addresses");
		tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
		proto_tree_add_uint(tlv_tree, hf_cdp_tlvtype, tvb,
			    offset + TLV_TYPE, 2, type);
		proto_tree_add_uint(tlv_tree, hf_cdp_tlvlength, tvb,
			    offset + TLV_LENGTH, 2, length);
		offset += 4;
		length -= 4;
		naddresses = tvb_get_ntohl(tvb, offset);
		proto_tree_add_text(tlv_tree, tvb, offset, 4,
			    "Number of addresses: %u", naddresses);
		offset += 4;
		length -= 4;
		while (naddresses != 0) {
		    addr_length = dissect_address_tlv(tvb, offset, length,
		    		tlv_tree);
		    if (addr_length < 0)
			break;
		    offset += addr_length;
		    length -= addr_length;

		    naddresses--;
		}
		offset += length;
		break;

	    case TYPE_PORT_ID:
		real_length = length;
		if (tvb_get_guint8(tvb, offset + real_length) != 0x00) {
		    /* The length in the TLV doesn't appear to be the
		       length of the TLV, as the byte just past it
		       isn't the first byte of a 2-byte big-endian
		       small integer; make the length of the TLV the length
		       in the TLV, plus 4 bytes for the TLV type and length,
		       minus 1 because that's what makes one capture work. */
		    real_length = length + 3;
		}
		tlvi = proto_tree_add_text(cdp_tree, tvb, offset,
			    real_length, "Port ID: %.*s",
			    real_length - 4,
			    tvb_get_ptr(tvb, offset + 4, real_length - 4));
		tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
		proto_tree_add_uint(tlv_tree, hf_cdp_tlvtype, tvb,
			    offset + TLV_TYPE, 2, type);
		proto_tree_add_uint(tlv_tree, hf_cdp_tlvlength, tvb,
			    offset + TLV_LENGTH, 2, length);
		proto_tree_add_text(tlv_tree, tvb, offset + 4,
			    real_length - 4,
			    "Sent through Interface: %.*s",
			    real_length - 4,
			    tvb_get_ptr(tvb, offset + 4, real_length - 4));
		offset += real_length;
		break;

	    case TYPE_CAPABILITIES:
		tlvi = proto_tree_add_text(cdp_tree, tvb, offset,
			    length, "Capabilities");
		tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
		proto_tree_add_uint(tlv_tree, hf_cdp_tlvtype, tvb,
			    offset + TLV_TYPE, 2, type);
		proto_tree_add_uint(tlv_tree, hf_cdp_tlvlength, tvb,
			    offset + TLV_LENGTH, 2, length);
		offset += 4;
		length -= 4;
		dissect_capabilities(tvb, offset, length, tlv_tree);
		offset += length;
		break;

	    case TYPE_IOS_VERSION:
		tlvi = proto_tree_add_text(cdp_tree, tvb, offset,
			    length, "Software Version");
		tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
		proto_tree_add_uint(tlv_tree, hf_cdp_tlvtype, tvb,
			    offset + TLV_TYPE, 2, type);
		proto_tree_add_uint(tlv_tree, hf_cdp_tlvlength, tvb,
			    offset + TLV_LENGTH, 2, length);
		add_multi_line_string_to_tree(tlv_tree, tvb, offset + 4,
				length - 4, "Software Version: ");
		offset += length;
		break;

	    case TYPE_PLATFORM:
		/* ??? platform */
		tlvi = proto_tree_add_text(cdp_tree, tvb,
			    offset, length, "Platform: %.*s",
			    length - 4,
			    tvb_get_ptr(tvb, offset + 4, length - 4));
		tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
		proto_tree_add_uint(tlv_tree, hf_cdp_tlvtype, tvb,
			    offset + TLV_TYPE, 2, type);
		proto_tree_add_uint(tlv_tree, hf_cdp_tlvlength, tvb,
			    offset + TLV_LENGTH, 2, length);
		proto_tree_add_text(tlv_tree, tvb, offset + 4,
			    length - 4, "Platform: %.*s",
			    length - 4,
			    tvb_get_ptr(tvb, offset + 4, length - 4));
		offset += length;
		break;

	    default:
		tlvi = proto_tree_add_text(cdp_tree, tvb, offset,
			    length, "Type: %s, length: %u",
			    val_to_str(type, type_vals, "Unknown (0x%04x)"),
			    length);
		tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
		proto_tree_add_uint(tlv_tree, hf_cdp_tlvtype, tvb,
			    offset + TLV_TYPE, 2, type);
		proto_tree_add_uint(tlv_tree, hf_cdp_tlvlength, tvb,
			    offset + TLV_LENGTH, 2, length);
		if (length > 4) {
			proto_tree_add_text(tlv_tree, tvb, offset + 4,
					length - 4, "Data");
		} else
			return;
		offset += length;
	    }
	}
    	dissect_data(tvb, offset, pinfo, cdp_tree);
    }
}

#define	PROTO_TYPE_NLPID	1
#define	PROTO_TYPE_IEEE_802_2	2

static const value_string proto_type_vals[] = {
	{ PROTO_TYPE_NLPID,      "NLPID" },
	{ PROTO_TYPE_IEEE_802_2, "802.2" },
	{ 0,                     NULL },
};

static int
dissect_address_tlv(tvbuff_t *tvb, int offset, int length, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *address_tree;
    guint8 protocol_type;
    guint8 protocol_length;
    int nlpid;
    char *protocol_str;
    guint16 address_length;
    char *address_type_str;
    char *address_str;

    if (length < 1)
        return -1;
    ti = proto_tree_add_notext(tree, tvb, offset, length);
    address_tree = proto_item_add_subtree(ti, ett_cdp_address);
    protocol_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(address_tree, tvb, offset, 1, "Protocol type: %s",
	val_to_str(protocol_type, proto_type_vals, "Unknown (0x%02x)"));
    offset += 1;
    length -= 1;

    if (length < 1) {
        proto_item_set_text(ti, "Truncated address");
	return -1;
    }
    protocol_length = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(address_tree, tvb, offset, 1, "Protocol length: %u",
			protocol_length);
    offset += 1;
    length -= 1;

    if (length < protocol_length) {
        proto_item_set_text(ti, "Truncated address");
        if (length != 0) {
            proto_tree_add_text(address_tree, tvb, offset, length,
              "Protocol: %s (truncated)",
              tvb_bytes_to_str(tvb, offset, length));
        }
	return -1;
    }
    protocol_str = NULL;
    if (protocol_type == PROTO_TYPE_NLPID && protocol_length == 1) {
    	nlpid = tvb_get_guint8(tvb, offset);
    	protocol_str = val_to_str(nlpid, nlpid_vals, "Unknown (0x%02x)");
    } else
        nlpid = -1;
    if (protocol_str == NULL)
        protocol_str = tvb_bytes_to_str(tvb, offset, protocol_length);
    proto_tree_add_text(address_tree, tvb, offset, protocol_length,
			"Protocol: %s", protocol_str);
    offset += protocol_length;
    length -= protocol_length;

    if (length < 2) {
        proto_item_set_text(ti, "Truncated address");
	return -1;
    }
    address_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(address_tree, tvb, offset, 2, "Address length: %u",
			address_length);
    offset += 2;
    length -= 2;

    if (length < address_length) {
        proto_item_set_text(ti, "Truncated address");
        if (length != 0) {
            proto_tree_add_text(address_tree, tvb, offset, length,
              "Address: %s (truncated)",
              tvb_bytes_to_str(tvb, offset, length));
        }
	return -1;
    }
    /* XXX - the Cisco document seems to be saying that, for 802.2-format
       protocol types, 0xAAAA03 0x000000 0x0800 is IPv6, but 0x0800 is
       the Ethernet protocol type for IPv4. */
    length = 2 + protocol_length + 2 + address_length;
    address_type_str = NULL;
    address_str = NULL;
    if (protocol_type == PROTO_TYPE_NLPID && protocol_length == 1) {
        switch (nlpid) {

        /* XXX - dissect NLPID_ISO8473_CLNP as OSI CLNP address? */

        case NLPID_IP:
            if (address_length == 4) {
                /* The address is an IP address. */
                address_type_str = "IP address";
                address_str = ip_to_str(tvb_get_ptr(tvb, offset, 4));
            }
            break;
        }
    }
    if (address_type_str == NULL)
        address_type_str = "Address";
    if (address_str == NULL) {
        address_str = tvb_bytes_to_str(tvb, offset, address_length);
    }
    proto_item_set_text(ti, "%s: %s", address_type_str, address_str);
    proto_tree_add_text(address_tree, tvb, offset, address_length, "%s: %s",
      address_type_str, address_str);
    return 2 + protocol_length + 2 + address_length;
}

static void
dissect_capabilities(tvbuff_t *tvb, int offset, int length, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *capabilities_tree;
    guint32 capabilities;

    if (length < 4)
        return;
    capabilities = tvb_get_ntohl(tvb, offset);
    ti = proto_tree_add_text(tree, tvb, offset, length, "Capabilities: 0x%08x",
        capabilities);
    capabilities_tree = proto_item_add_subtree(ti, ett_cdp_capabilities);
    proto_tree_add_text(capabilities_tree, tvb, offset, 4,
	decode_boolean_bitfield(capabilities, 0x01, 4*8,
	    "Performs level 3 routing",
	    "Doesn't perform level 3 routing"));
    proto_tree_add_text(capabilities_tree, tvb, offset, 4,
	decode_boolean_bitfield(capabilities, 0x02, 4*8,
	    "Performs level 2 transparent bridging",
	    "Doesn't perform level 2 transparent bridging"));
    proto_tree_add_text(capabilities_tree, tvb, offset, 4,
	decode_boolean_bitfield(capabilities, 0x04, 4*8,
	    "Performs level 2 source-route bridging",
	    "Doesn't perform level 2 source-route bridging"));
    proto_tree_add_text(capabilities_tree, tvb, offset, 4,
	decode_boolean_bitfield(capabilities, 0x08, 4*8,
	    "Performs level 2 switching",
	    "Doesn't perform level 2 switching"));
    proto_tree_add_text(capabilities_tree, tvb, offset, 4,
	decode_boolean_bitfield(capabilities, 0x10, 4*8,
	    "Sends and receives packets for network-layer protocols",
	    "Doesn't send or receive packets for network-layer protocols"));
    proto_tree_add_text(capabilities_tree, tvb, offset, 4,
	decode_boolean_bitfield(capabilities, 0x20, 4*8,
	    "Doesn't forward IGMP Report packets on nonrouter ports",
	    "Forwards IGMP Report packets on nonrouter ports"));
    proto_tree_add_text(capabilities_tree, tvb, offset, 4,
	decode_boolean_bitfield(capabilities, 0x40, 4*8,
	    "Provides level 1 functionality",
	    "Doesn't provide level 1 functionality"));
}

static void
add_multi_line_string_to_tree(proto_tree *tree, tvbuff_t *tvb, gint start,
  gint len, const gchar *prefix)
{
    int prefix_len;
    int i;
    char blanks[64+1];
    gint next;
    int line_len;
    int data_len;

    prefix_len = strlen(prefix);
    if (prefix_len > 64)
	prefix_len = 64;
    for (i = 0; i < prefix_len; i++)
	blanks[i] = ' ';
    blanks[i] = '\0';
    while (len > 0) {
	line_len = tvb_find_line_end(tvb, start, len, &next);
	data_len = next - start;
	proto_tree_add_text(tree, tvb, start, data_len, "%s%.*s", prefix,
	   line_len, tvb_get_ptr(tvb, start, line_len));
	start += data_len;
	len -= data_len;
	prefix = blanks;
    }
}

void
proto_register_cdp(void)
{
    static hf_register_info hf[] = {
	{ &hf_cdp_version,
	{ "Version",		"cdp.version",  FT_UINT8, BASE_DEC, NULL, 0x0,
	  "" }},

	{ &hf_cdp_ttl,
	{ "TTL",		"cdp.ttl", FT_UINT16, BASE_DEC, NULL, 0x0,
	  "" }},

	{ &hf_cdp_checksum,
	{ "Checksum",		"cdp.checksum", FT_UINT16, BASE_HEX, NULL, 0x0,
	  "" }},

	{ &hf_cdp_tlvtype,
	{ "Type",		"cdp.tlv.type", FT_UINT16, BASE_HEX, VALS(type_vals), 0x0,
	  "" }},

	{ &hf_cdp_tlvlength,
	{ "Length",		"cdp.tlv.len", FT_UINT16, BASE_DEC, NULL, 0x0,
	  "" }},
    };
    static gint *ett[] = {
	&ett_cdp,
	&ett_cdp_tlv,
	&ett_cdp_address,
	&ett_cdp_capabilities,
    };

    proto_cdp = proto_register_protocol("Cisco Discovery Protocol", "cdp");
    proto_register_field_array(proto_cdp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_cdp(void)
{
    dissector_add("llc.cisco_pid", 0x2000, dissect_cdp);
}
