/* packet-cdp.c
 * Routines for the disassembly of the "Cisco Discovery Protocol"
 * (c) Copyright Hannes R. Boehm <hannes@boehm.org>
 *
 * $Id: packet-cdp.c,v 1.26 2000/11/13 07:18:44 guy Exp $
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
static int hf_cdp_flags = -1;
static int hf_cdp_ttl = -1;
static int hf_cdp_tlvtype = -1;
static int hf_cdp_tlvlength = -1;

static gint ett_cdp = -1;
static gint ett_cdp_tlv = -1;
static gint ett_cdp_address = -1;
static gint ett_cdp_capabilities = -1;

static int
dissect_address_tlv(const u_char *pd, int offset, int length, proto_tree *tree);
static void
dissect_capabilities(const u_char *pd, int offset, int length, proto_tree *tree);
static void
add_multi_line_string_to_tree(proto_tree *tree, gint start, gint len,
  const gchar *prefix, const gchar *string);

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
	
void 
dissect_cdp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
    proto_item *ti; 
    proto_tree *cdp_tree = NULL;
    guint16 type;
    guint16 length;
    char *type_str;
    char *stringmem;
    proto_item *tlvi;
    proto_tree *tlv_tree;
    int real_length;
    guint32 naddresses;
    int addr_length;

    OLD_CHECK_DISPLAY_AS_DATA(proto_cdp, pd, offset, fd, tree);

    if (check_col(fd, COL_PROTOCOL))
        col_add_str(fd, COL_PROTOCOL, "CDP");
    if (check_col(fd, COL_INFO))
        col_add_str(fd, COL_INFO, "Cisco Discovery Protocol"); 

    if(tree){
        ti = proto_tree_add_item(tree, proto_cdp, NullTVB, offset, END_OF_FRAME, FALSE);
	cdp_tree = proto_item_add_subtree(ti, ett_cdp);
	
	/* CDP header */
	proto_tree_add_uint(cdp_tree, hf_cdp_version, NullTVB, offset, 1, pd[offset]);
	offset += 1;
	proto_tree_add_uint_format(cdp_tree, hf_cdp_ttl, NullTVB, offset, 1,
				   pntohs(&pd[offset]),
				   "TTL: %u seconds", pd[offset]);
	offset += 1;
	proto_tree_add_uint_format(cdp_tree, hf_cdp_flags, NullTVB, offset, 2,
				   pd[offset], 
				   "Checksum: 0x%04x", pntohs(&pd[offset]));
	offset += 2;

	while( IS_DATA_IN_FRAME(offset) ){
		type = pntohs(&pd[offset + TLV_TYPE]);
		length = pntohs(&pd[offset + TLV_LENGTH]);
		type_str = val_to_str(type, type_vals,
		    "Unknown (0x%04x)");

		switch( type ){
			case TYPE_DEVICE_ID:
				/* Device ID */
				tlvi = proto_tree_add_text(cdp_tree, NullTVB, offset,
				    length, "Device ID: %s",
				    &pd[offset+4]);
				tlv_tree = proto_item_add_subtree(tlvi,
				    ett_cdp_tlv);
				proto_tree_add_uint(tlv_tree, hf_cdp_tlvtype, NullTVB,
				    offset + TLV_TYPE, 2, type);
				proto_tree_add_uint(tlv_tree, hf_cdp_tlvlength, NullTVB,
				    offset + TLV_LENGTH, 2, length);
				proto_tree_add_text(tlv_tree, NullTVB, offset + 4,
				    length - 4, "Device ID: %s",
				    &pd[offset+4]);
				offset+=length;
				break;
			case TYPE_ADDRESS:
				/* Addresses */
				tlvi = proto_tree_add_text(cdp_tree, NullTVB, offset,
				    length, "Addresses");
				tlv_tree = proto_item_add_subtree(tlvi,
				    ett_cdp_tlv);
				proto_tree_add_uint(tlv_tree, hf_cdp_tlvtype, NullTVB,
				    offset + TLV_TYPE, 2, type);
				proto_tree_add_uint(tlv_tree, hf_cdp_tlvlength, NullTVB,
				    offset + TLV_LENGTH, 2, length);
				offset += 4;
				length -= 4;
				naddresses = pntohl(&pd[offset]);
				proto_tree_add_text(tlv_tree, NullTVB, offset, 4,
				    "Number of addresses: %u", naddresses);
				offset += 4;
				length -= 4;
				while (naddresses != 0) {
				    addr_length = dissect_address_tlv(pd,
				        offset, length, tlv_tree);
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
				if (pd[offset + real_length] != 0x00) {
				    /* The length in the TLV doesn't
				       appear to be the length of the
				       TLV, as the byte just past it
				       isn't the first byte of a 2-byte
				       big-endian small integer; make
				       the length of the TLV the length
				       in the TLV, plus 4 bytes for the
				       TLV type and length, minus 1
				       because that's what makes one
				       capture work. */
				    real_length = length + 3;
				}
				tlvi = proto_tree_add_text(cdp_tree, NullTVB, offset,
				    real_length, "Port ID: %s",
				    &pd[offset+4]);
				tlv_tree = proto_item_add_subtree(tlvi,
				    ett_cdp_tlv);
				proto_tree_add_uint(tlv_tree, hf_cdp_tlvtype, NullTVB,
				    offset + TLV_TYPE, 2, type);
				proto_tree_add_uint(tlv_tree, hf_cdp_tlvlength, NullTVB,
				    offset + TLV_LENGTH, 2, length);
				proto_tree_add_text(tlv_tree, NullTVB, offset + 4,
				    real_length - 4,
				    "Sent through Interface: %s",
				    &pd[offset+4]);
				offset += real_length;
				break;
			case TYPE_CAPABILITIES:
				tlvi = proto_tree_add_text(cdp_tree, NullTVB, offset,
				    length, "Capabilities");
				tlv_tree = proto_item_add_subtree(tlvi,
				    ett_cdp_tlv);
				proto_tree_add_uint(tlv_tree, hf_cdp_tlvtype, NullTVB,
				    offset + TLV_TYPE, 2, type);
				proto_tree_add_uint(tlv_tree, hf_cdp_tlvlength, NullTVB,
				    offset + TLV_LENGTH, 2, length);
				offset += 4;
				length -= 4;
				dissect_capabilities(pd, offset, length,
				    tlv_tree);
				offset += length;
				break;
			case TYPE_IOS_VERSION:
				tlvi = proto_tree_add_text(cdp_tree, NullTVB, offset,
				    length, "Software Version");
				tlv_tree = proto_item_add_subtree(tlvi,
				    ett_cdp_tlv);
				proto_tree_add_uint(tlv_tree, hf_cdp_tlvtype, NullTVB,
				    offset + TLV_TYPE, 2, type);
				proto_tree_add_uint(tlv_tree, hf_cdp_tlvlength, NullTVB,
				    offset + TLV_LENGTH, 2, length);
				add_multi_line_string_to_tree(tlv_tree,
				    offset + 4, length - 4, "Software Version: ",
				    &pd[offset+4] );
				offset += length;
				break;
			case TYPE_PLATFORM:
				/* ??? platform */
				stringmem = malloc(length);
				memset(stringmem, '\0', length);
				memcpy(stringmem, &pd[offset+4], length - 4 );
				tlvi = proto_tree_add_text(cdp_tree, NullTVB,
				    offset, length, "Platform: %s",
				    stringmem);
				tlv_tree = proto_item_add_subtree(tlvi,
				    ett_cdp_tlv);
				proto_tree_add_uint(tlv_tree, hf_cdp_tlvtype, NullTVB,
				    offset + TLV_TYPE, 2, type);
				proto_tree_add_uint(tlv_tree, hf_cdp_tlvlength, NullTVB,
				    offset + TLV_LENGTH, 2, length);
				proto_tree_add_text(tlv_tree, NullTVB, offset + 4,
				    length - 4, "Platform: %s", stringmem);
				free(stringmem);
				offset+=length;
				break;
			default:
				tlvi = proto_tree_add_text(cdp_tree, NullTVB, offset,
				    length, "Type: %s, length: %u",
				    type_str, length);
				tlv_tree = proto_item_add_subtree(tlvi,
				    ett_cdp_tlv);
				proto_tree_add_uint(tlv_tree, hf_cdp_tlvtype, NullTVB,
				    offset + TLV_TYPE, 2, type);
				proto_tree_add_uint(tlv_tree, hf_cdp_tlvlength, NullTVB,
				    offset + TLV_LENGTH, 2, length);
				if (length > 4) {
					proto_tree_add_text(tlv_tree, NullTVB,
					    offset + 4, length - 4, "Data");
				} else
					return;
				offset+=length;
		}
	}
    	old_dissect_data(pd, offset, fd, cdp_tree);
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
dissect_address_tlv(const u_char *pd, int offset, int length, proto_tree *tree)
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
    ti = proto_tree_add_notext(tree, NullTVB, offset, length);
    address_tree = proto_item_add_subtree(ti, ett_cdp_address);
    protocol_type = pd[offset];
    proto_tree_add_text(address_tree, NullTVB, offset, 1, "Protocol type: %s",
	val_to_str(protocol_type, proto_type_vals, "Unknown (0x%02x)"));
    offset += 1;
    length -= 1;

    if (length < 1) {
        proto_item_set_text(ti, "Truncated address");
	return -1;
    }
    protocol_length = pd[offset];
    proto_tree_add_text(address_tree, NullTVB, offset, 1, "Protocol length: %u",
			protocol_length);
    offset += 1;
    length -= 1;

    if (length < protocol_length) {
        proto_item_set_text(ti, "Truncated address");
        if (length != 0) {
            proto_tree_add_text(address_tree, NullTVB, offset, length,
              "Protocol: %s (truncated)", bytes_to_str(&pd[offset], length));
        }
	return -1;
    }
    protocol_str = NULL;
    if (protocol_type == PROTO_TYPE_NLPID && protocol_length == 1) {
    	nlpid = pd[offset];
    	protocol_str = val_to_str(nlpid, nlpid_vals, "Unknown (0x%02x)");
    } else
        nlpid = -1;
    if (protocol_str == NULL)
        protocol_str = bytes_to_str(&pd[offset], protocol_length);
    proto_tree_add_text(address_tree, NullTVB, offset, protocol_length,
			"Protocol: %s", protocol_str);
    offset += protocol_length;
    length -= protocol_length;

    if (length < 2) {
        proto_item_set_text(ti, "Truncated address");
	return -1;
    }
    address_length = pntohs(&pd[offset]);
    proto_tree_add_text(address_tree, NullTVB, offset, 2, "Address length: %u",
			address_length);
    offset += 2;
    length -= 2;

    if (length < address_length) {
        proto_item_set_text(ti, "Truncated address");
        if (length != 0) {
            proto_tree_add_text(address_tree, NullTVB, offset, length,
              "Address: %s (truncated)", bytes_to_str(&pd[offset], length));
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
                address_str = ip_to_str(&pd[offset]);
            }
            break;
        }
    }
    if (address_type_str == NULL)
        address_type_str = "Address";
    if (address_str == NULL) {
        address_str = bytes_to_str(&pd[offset], address_length);
    }
    proto_item_set_text(ti, "%s: %s", address_type_str, address_str);
    proto_tree_add_text(address_tree, NullTVB, offset, address_length, "%s: %s",
      address_type_str, address_str);
    return 2 + protocol_length + 2 + address_length;
}

static void
dissect_capabilities(const u_char *pd, int offset, int length, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *capabilities_tree;
    guint32 capabilities;

    if (length < 4)
        return;
    capabilities = pntohl(&pd[offset]);
    ti = proto_tree_add_text(tree, NullTVB, offset, length, "Capabilities: 0x%08x",
        capabilities);
    capabilities_tree = proto_item_add_subtree(ti, ett_cdp_capabilities);
    proto_tree_add_text(capabilities_tree, NullTVB, offset, 4,
	decode_boolean_bitfield(capabilities, 0x01, 4*8,
	    "Performs level 3 routing",
	    "Doesn't perform level 3 routing"));
    proto_tree_add_text(capabilities_tree, NullTVB, offset, 4,
	decode_boolean_bitfield(capabilities, 0x02, 4*8,
	    "Performs level 2 transparent bridging",
	    "Doesn't perform level 2 transparent bridging"));
    proto_tree_add_text(capabilities_tree, NullTVB, offset, 4,
	decode_boolean_bitfield(capabilities, 0x04, 4*8,
	    "Performs level 2 source-route bridging",
	    "Doesn't perform level 2 source-route bridging"));
    proto_tree_add_text(capabilities_tree, NullTVB, offset, 4,
	decode_boolean_bitfield(capabilities, 0x08, 4*8,
	    "Performs level 2 switching",
	    "Doesn't perform level 2 switching"));
    proto_tree_add_text(capabilities_tree, NullTVB, offset, 4,
	decode_boolean_bitfield(capabilities, 0x10, 4*8,
	    "Sends and receives packets for network-layer protocols",
	    "Doesn't send or receive packets for network-layer protocols"));
    proto_tree_add_text(capabilities_tree, NullTVB, offset, 4,
	decode_boolean_bitfield(capabilities, 0x20, 4*8,
	    "Doesn't forward IGMP Report packets on nonrouter ports",
	    "Forwards IGMP Report packets on nonrouter ports"));
    proto_tree_add_text(capabilities_tree, NullTVB, offset, 4,
	decode_boolean_bitfield(capabilities, 0x40, 4*8,
	    "Provides level 1 functionality",
	    "Doesn't provide level 1 functionality"));
}

static void
add_multi_line_string_to_tree(proto_tree *tree, gint start, gint len,
  const gchar *prefix, const gchar *string)
{
    int prefix_len;
    int i;
    char blanks[64+1];
    const gchar *p, *q;
    int line_len;
    int data_len;

    prefix_len = strlen(prefix);
    if (prefix_len > 64)
	prefix_len = 64;
    for (i = 0; i < prefix_len; i++)
	blanks[i] = ' ';
    blanks[i] = '\0';
    p = string;
    for (;;) {
	q = strchr(p, '\n');
	if (q != NULL) {
	    line_len = q - p;
	    data_len = line_len + 1;
	} else {
	    line_len = strlen(p);
	    data_len = line_len;
	}
	proto_tree_add_text(tree, NullTVB, start, data_len, "%s%.*s", prefix,
	   line_len, p);
	if (q == NULL)
	    break;
	p += data_len;
	start += data_len;
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

                { &hf_cdp_flags,
                { "Flags",		"cdp.flags", FT_UINT8, BASE_HEX, NULL, 0x0,
			"" }},

                { &hf_cdp_ttl,
                { "TTL",		"cdp.ttl", FT_UINT16, BASE_DEC, NULL, 0x0,
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
