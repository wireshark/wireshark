/* packet-cdp.c
 * Routines for the disassembly of the "Cisco Discovery Protocol"
 * (c) Copyright Hannes R. Boehm <hannes@boehm.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/in_cksum.h>

#include <epan/oui.h>
#include <epan/nlpid.h>


/*
 * See
 *
 *	http://www.cisco.com/univercd/cc/td/doc/product/lan/trsrb/frames.htm#xtocid12
 *
 * for some information on CDP.
 *
 * See
 *
 *	http://www.cisco.com/en/US/products/hw/switches/ps663/products_tech_note09186a0080094713.shtml#cdp
 *
 * for some more information on CDP version 2.
 */

/* Offsets in TLV structure. */
#define	TLV_TYPE	0
#define	TLV_LENGTH	2

static int proto_cdp = -1;
static int hf_cdp_version = -1;
static int hf_cdp_checksum = -1;
static int hf_cdp_checksum_good = -1;
static int hf_cdp_checksum_bad = -1;
static int hf_cdp_ttl = -1;
static int hf_cdp_tlvtype = -1;
static int hf_cdp_tlvlength = -1;
static int hf_cdp_deviceid = -1;
static int hf_cdp_platform = -1;
static int hf_cdp_portid = -1;

static gint ett_cdp = -1;
static gint ett_cdp_tlv = -1;
static gint ett_cdp_nrgyz_tlv = -1;
static gint ett_cdp_address = -1;
static gint ett_cdp_capabilities = -1;
static gint ett_cdp_spare_poe_tlv = -1;
static gint ett_cdp_checksum = -1;

static dissector_handle_t data_handle;

static int
dissect_address_tlv(tvbuff_t *tvb, int offset, int length, proto_tree *tree);
static void
dissect_capabilities(tvbuff_t *tvb, int offset, int length, proto_tree *tree);
static void
dissect_nrgyz_tlv(tvbuff_t *tvb, int offset, guint16 length, guint16 num,
  proto_tree *tree);
static void
dissect_spare_poe_tlv(tvbuff_t *tvb, int offset, int length, proto_tree *tree);
static void
add_multi_line_string_to_tree(proto_tree *tree, tvbuff_t *tvb, gint start,
  gint len, const gchar *prefix);

#define TYPE_DEVICE_ID		0x0001
#define TYPE_ADDRESS		0x0002
#define TYPE_PORT_ID		0x0003
#define TYPE_CAPABILITIES	0x0004
#define TYPE_IOS_VERSION	0x0005
#define TYPE_PLATFORM		0x0006
#define TYPE_IP_PREFIX		0x0007
#define TYPE_PROTOCOL_HELLO     0x0008 /* Protocol Hello */
#define TYPE_VTP_MGMT_DOMAIN    0x0009 /* VTP Domain, CTPv2 - see second URL */
#define TYPE_NATIVE_VLAN        0x000a /* Native VLAN, CTPv2 - see second URL */
#define TYPE_DUPLEX             0x000b /* Full/Half Duplex - see second URL */
/*                              0x000c */
/*                              0x000d */
#define TYPE_VOIP_VLAN_REPLY    0x000e /* VoIP VLAN reply */
#define TYPE_VOIP_VLAN_QUERY    0x000f /* VoIP VLAN query */
#define TYPE_POWER              0x0010 /* Power consumption */
#define TYPE_MTU                0x0011 /* MTU */
#define TYPE_TRUST_BITMAP       0x0012 /* Trust bitmap */
#define TYPE_UNTRUSTED_COS      0x0013 /* Untrusted port CoS */
#define TYPE_SYSTEM_NAME        0x0014 /* System Name */
#define TYPE_SYSTEM_OID         0x0015 /* System OID */
#define TYPE_MANAGEMENT_ADDR    0x0016 /* Management Address(es) */
#define TYPE_LOCATION           0x0017 /* Location */
#define TYPE_EXT_PORT_ID        0x0018 /* External Port-ID */
#define TYPE_POWER_REQUESTED    0x0019 /* Power Requested */
#define TYPE_POWER_AVAILABLE    0x001a /* Power Available */
#define TYPE_PORT_UNIDIR        0x001b /* Port Unidirectional */
#define TYPE_NRGYZ              0x001d /* EnergyWise over CDP */
#define TYPE_SPARE_POE          0x001f /* Spare Pair PoE */

static const value_string type_vals[] = {
	{ TYPE_DEVICE_ID,    	"Device ID" },
	{ TYPE_ADDRESS,      	"Addresses" },
	{ TYPE_PORT_ID,      	"Port ID" },
	{ TYPE_CAPABILITIES, 	"Capabilities" },
	{ TYPE_IOS_VERSION,  	"Software version" },
	{ TYPE_PLATFORM,        "Platform" },
	{ TYPE_IP_PREFIX,       "IP Prefix/Gateway (used for ODR)" },
	{ TYPE_PROTOCOL_HELLO,  "Protocol Hello" },
	{ TYPE_VTP_MGMT_DOMAIN, "VTP Management Domain" },
	{ TYPE_NATIVE_VLAN,     "Native VLAN" },
	{ TYPE_DUPLEX,          "Duplex" },
	{ TYPE_VOIP_VLAN_REPLY, "VoIP VLAN Reply" },
	{ TYPE_VOIP_VLAN_QUERY, "VoIP VLAN Query" },
	{ TYPE_POWER,           "Power consumption" },
	{ TYPE_MTU,             "MTU"},
	{ TYPE_TRUST_BITMAP,    "Trust Bitmap" },
	{ TYPE_UNTRUSTED_COS,   "Untrusted Port CoS" },
	{ TYPE_SYSTEM_NAME,     "System Name" },
	{ TYPE_SYSTEM_OID,      "System Object ID" },
	{ TYPE_MANAGEMENT_ADDR, "Management Address" },
	{ TYPE_LOCATION,        "Location" },
	{ TYPE_EXT_PORT_ID,     "External Port-ID" },
	{ TYPE_POWER_REQUESTED, "Power Requested" },
	{ TYPE_POWER_AVAILABLE, "Power Available" },
	{ TYPE_PORT_UNIDIR,     "Port Unidirectional" },
	{ TYPE_NRGYZ,           "EnergyWise" },
	{ TYPE_SPARE_POE,       "Spare PoE" },
	{ 0,                    NULL }
};

#define TYPE_HELLO_CLUSTER_MGMT    0x0112

static const value_string type_hello_vals[] = {
        { TYPE_HELLO_CLUSTER_MGMT,   "Cluster Management" },
	{ 0,                    NULL }
};

#define TYPE_NRGYZ_ROLE		   0x00000007
#define TYPE_NRGYZ_DOMAIN	   0x00000008
#define TYPE_NRGYZ_NAME		   0x00000009
#define TYPE_NRGYZ_REPLYTO	   0x00000017

static const value_string type_nrgyz_vals[] = {
	{ TYPE_NRGYZ_ROLE,	     "Role" },
	{ TYPE_NRGYZ_DOMAIN,	     "Domain" },
	{ TYPE_NRGYZ_NAME,	     "Name" },
	{ TYPE_NRGYZ_REPLYTO,	     "Reply To" },
	{ 0,			     NULL }
};

static void
dissect_cdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti, *checksum_item;
    proto_tree *cdp_tree = NULL, *checksum_tree;
    int offset = 0;
    guint16 type;
    guint16 length, packet_checksum, computed_checksum, data_length;
    gboolean checksum_good, checksum_bad;
    proto_item *tlvi = NULL;
    proto_tree *tlv_tree = NULL;
    int real_length;
    guint32 naddresses;
    guint32 power_avail_len, power_avail;
    guint32 power_req_len, power_req;
    int addr_length;
    guint32 ip_addr;
    vec_t cksum_vec[1];

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CDP");
    col_clear(pinfo->cinfo, COL_INFO);

    if (tree) {
        ti = proto_tree_add_item(tree, proto_cdp, tvb, offset, -1, FALSE);
	cdp_tree = proto_item_add_subtree(ti, ett_cdp);

	/* CDP header */
	proto_tree_add_item(cdp_tree, hf_cdp_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_uint_format_value(cdp_tree, hf_cdp_ttl, tvb, offset, 1,
					 tvb_get_guint8(tvb, offset),
					 "%u seconds",
					 tvb_get_guint8(tvb, offset));
	offset += 1;
    } else {
	offset += 2; /* The version/ttl fields from above */
    }

    /* Checksum display & verification code */
    packet_checksum = tvb_get_ntohs(tvb, offset);

    data_length = tvb_reported_length(tvb);

    /* CDP doesn't adhere to RFC 1071 section 2. (B). It incorrectly assumes
     * checksums are calculated on a big endian platform, therefore i.s.o.
     * padding odd sized data with a zero byte _at the end_ it sets the last
     * big endian _word_ to contain the last network _octet_. This byteswap
     * has to be done on the last octet of network data before feeding it to
     * the Internet checksum routine.
     * CDP checksumming code has a bug in the addition of this last _word_
     * as a signed number into the long word intermediate checksum. When
     * reducing this long to word size checksum an off-by-one error can be
     * made. This off-by-one error is compensated for in the last _word_ of
     * the network data.
     */
    if (data_length & 1) {
        guint8 *padded_buffer;
        /* Allocate new buffer */
        padded_buffer = ep_alloc(data_length+1);
        tvb_memcpy(tvb, padded_buffer, 0, data_length);
        /* Swap bytes in last word */
        padded_buffer[data_length] = padded_buffer[data_length-1];
        padded_buffer[data_length-1] = 0;
        /* Compensate off-by-one error */
        if (padded_buffer[data_length] & 0x80) {
          padded_buffer[data_length]--;
          padded_buffer[data_length-1]--;
        }
        /* Setup checksum routine data buffer */
        cksum_vec[0].ptr = padded_buffer;
        cksum_vec[0].len = data_length+1;
    } else {
        /* Setup checksum routine data buffer */
        cksum_vec[0].ptr = tvb_get_ptr(tvb, 0, data_length);
        cksum_vec[0].len = data_length;
    }

    computed_checksum = in_cksum(cksum_vec, 1);
    checksum_good = (computed_checksum == 0);
    checksum_bad = !checksum_good;
    if (checksum_good) {
        checksum_item = proto_tree_add_uint_format(cdp_tree,
	hf_cdp_checksum, tvb, offset, 2, packet_checksum,
	"Checksum: 0x%04x [correct]", packet_checksum);
    } else {
	checksum_item = proto_tree_add_uint_format(cdp_tree,
	 hf_cdp_checksum, tvb, offset, 2, packet_checksum,
	 "Checksum: 0x%04x [incorrect, should be 0x%04x]",
	 packet_checksum,
	 in_cksum_shouldbe(packet_checksum, computed_checksum));
    }

    checksum_tree = proto_item_add_subtree(checksum_item, ett_cdp_checksum);
    checksum_item = proto_tree_add_boolean(checksum_tree, hf_cdp_checksum_good,
					   tvb, offset, 2, checksum_good);
    PROTO_ITEM_SET_GENERATED(checksum_item);
    checksum_item = proto_tree_add_boolean(checksum_tree, hf_cdp_checksum_bad,
					   tvb, offset, 2, checksum_bad);
    PROTO_ITEM_SET_GENERATED(checksum_item);

    offset += 2;

    while (tvb_reported_length_remaining(tvb, offset) != 0) {
      type = tvb_get_ntohs(tvb, offset + TLV_TYPE);
      length = tvb_get_ntohs(tvb, offset + TLV_LENGTH);
      if (length < 4) {
	if (tree) {
	  tlvi = proto_tree_add_text(cdp_tree, tvb, offset, 4,
				     "TLV with invalid length %u (< 4)",
				     length);
	  tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
	}
	offset += 4;
	break;
      }

      switch (type) {

      case TYPE_DEVICE_ID:
		  /* Device ID */

		  col_append_fstr(pinfo->cinfo, COL_INFO,
			  "Device ID: %s  ",
			  tvb_format_stringzpad(tvb, offset + 4, length - 4));

	if (tree) {
	  tlvi = proto_tree_add_text(cdp_tree, tvb, offset,
				     length, "Device ID: %s",
				     tvb_format_stringzpad(tvb, offset + 4, length - 4));
	  tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_deviceid, tvb, offset + 4, length - 4, ENC_ASCII|ENC_NA);
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

    col_append_fstr(pinfo->cinfo, COL_INFO,
		  "Port ID: %s  ",
		  tvb_format_stringzpad(tvb, offset + 4,
					length - 4));

	if (tree) {
	  tlvi = proto_tree_add_text(cdp_tree, tvb, offset,
				     real_length, "Port ID: %s",
				     tvb_format_text(tvb, offset + 4, real_length - 4));
	  tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_portid, tvb, offset + 4, real_length - 4, ENC_ASCII|ENC_NA);
	}
	offset += real_length;
	break;

      case TYPE_ADDRESS:
	/* Addresses */
	if (tree) {
	  tlvi = proto_tree_add_text(cdp_tree, tvb, offset,
				     length, "Addresses");
	  tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
	}
	offset += 4;
	length -= 4;
	naddresses = tvb_get_ntohl(tvb, offset);
	if (tree) {
	  proto_tree_add_text(tlv_tree, tvb, offset, 4,
			      "Number of addresses: %u", naddresses);
	}
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

      case TYPE_CAPABILITIES:
	if (tree) {
	  tlvi = proto_tree_add_text(cdp_tree, tvb, offset,
				     length, "Capabilities");
	  tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
	}
	offset += 4;
	length -= 4;
	dissect_capabilities(tvb, offset, length, tlv_tree);
	offset += length;
	break;

      case TYPE_IOS_VERSION:
	if (tree) {
	  tlvi = proto_tree_add_text(cdp_tree, tvb, offset,
				     length, "Software Version");
	  tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
	  add_multi_line_string_to_tree(tlv_tree, tvb, offset + 4,
					length - 4, "Software Version: ");
	}
	offset += length;
	break;

      case TYPE_PLATFORM:
	/* ??? platform */
	if (tree) {
	  tlvi = proto_tree_add_text(cdp_tree, tvb,
				     offset, length, "Platform: %s",
				     tvb_format_text(tvb, offset + 4, length - 4));
	  tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_platform, tvb, offset + 4, length - 4, ENC_ASCII|ENC_NA);
	}
	offset += length;
	break;

      case TYPE_IP_PREFIX:
	if (length == 8) {
	  /* if length is 8 then this is default gw not prefix */
	  if (tree) {
	    tlvi = proto_tree_add_text(cdp_tree, tvb, offset,
				       length, "ODR Default gateway: %s",
				       tvb_ip_to_str(tvb, offset+4));
	    tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
		proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
	    proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
	    proto_tree_add_text(tlv_tree, tvb, offset+4, 4,
				"ODR Default gateway = %s",
				tvb_ip_to_str(tvb, offset+4));
	  }
	  offset += 8;
	} else {
	  if (tree) {
	    tlvi = proto_tree_add_text(cdp_tree, tvb, offset,
				       length, "IP Prefixes: %d",length/5);

	    /* the actual number of prefixes is (length-4)/5
	       but if the variable is not a "float" but "integer"
	       then length/5=(length-4)/5  :)  */

	    tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
		proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
	    proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
	  }
	  offset += 4;
	  length -= 4;
	  while (length > 0) {
	    if (tree) {
	      proto_tree_add_text(tlv_tree, tvb, offset, 5,
				  "IP Prefix = %s/%u",
				  tvb_ip_to_str(tvb, offset),
				  tvb_get_guint8(tvb,offset+4));
	    }
	    offset += 5;
	    length -= 5;
	  }
	}
	break;

      case TYPE_PROTOCOL_HELLO:
	if (tree) {
	  tlvi = proto_tree_add_text(cdp_tree, tvb,
				     offset,length, "Protocol Hello: %s",
				     val_to_str(tvb_get_ntohs(tvb, offset+7), type_hello_vals, "Unknown (0x%04x)"));
	  tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_text(tlv_tree, tvb, offset+4, 3,
			      "OUI: 0x%06X (%s)",
			      tvb_get_ntoh24(tvb,offset+4),
			      val_to_str(tvb_get_ntoh24(tvb,offset+4), oui_vals, "Unknown"));
	  proto_tree_add_text(tlv_tree, tvb, offset+7, 2,
			      "Protocol ID: 0x%04X (%s)",
			      tvb_get_ntohs(tvb, offset+7),
			      val_to_str(tvb_get_ntohs(tvb, offset+7), type_hello_vals, "Unknown"));

	  switch(tvb_get_ntohs(tvb, offset+7)) {

	  case TYPE_HELLO_CLUSTER_MGMT:
	    /*		proto_tree_add_text(tlv_tree, tvb, offset+9,
			length - 9, "Cluster Management");
	    */
	    ip_addr = tvb_get_ipv4(tvb, offset+9);
	    proto_tree_add_text(tlv_tree, tvb, offset+9, 4,
				"Cluster Master IP: %s",ip_to_str((guint8 *)&ip_addr));
	    ip_addr = tvb_get_ipv4(tvb, offset+13);
	    proto_tree_add_text(tlv_tree, tvb, offset+13, 4,
				"UNKNOWN (IP?): 0x%08X (%s)",
				ip_addr, ip_to_str((guint8 *)&ip_addr));
	    proto_tree_add_text(tlv_tree, tvb, offset+17, 1,
				"Version?: 0x%02X",
				tvb_get_guint8(tvb, offset+17));
	    proto_tree_add_text(tlv_tree, tvb, offset+18, 1,
				"Sub Version?: 0x%02X",
				tvb_get_guint8(tvb, offset+18));
	    proto_tree_add_text(tlv_tree, tvb, offset+19, 1,
				"Status?: 0x%02X",
				tvb_get_guint8(tvb, offset+19));
	    proto_tree_add_text(tlv_tree, tvb, offset+20, 1,
				"UNKNOWN: 0x%02X",
				tvb_get_guint8(tvb, offset+20));
	    proto_tree_add_text(tlv_tree, tvb, offset+21, 6,
				"Cluster Commander MAC: %s",
				tvb_ether_to_str(tvb, offset+21));
	    proto_tree_add_text(tlv_tree, tvb, offset+27, 6,
				"Switch's MAC: %s",
				tvb_ether_to_str(tvb, offset+27));
	    proto_tree_add_text(tlv_tree, tvb, offset+33, 1,
				"UNKNOWN: 0x%02X",
				tvb_get_guint8(tvb, offset+33));
	    proto_tree_add_text(tlv_tree, tvb, offset+34, 2,
				"Management VLAN: %d",
				tvb_get_ntohs(tvb, offset+34));
	    break;
	  default:
	    proto_tree_add_text(tlv_tree, tvb, offset + 9,
				length - 9, "Unknown");
	    break;
	  }
	}
	offset += length;
	break;

      case TYPE_VTP_MGMT_DOMAIN:
	if (tree) {
	  tlvi = proto_tree_add_text(cdp_tree, tvb,
				     offset, length, "VTP Management Domain: %s",
				     tvb_format_text(tvb, offset + 4, length - 4));
	  tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_text(tlv_tree, tvb, offset + 4,
			      length - 4, "VTP Management Domain: %s",
			      tvb_format_text(tvb, offset + 4, length - 4));
	}
	offset += length;
	break;

      case TYPE_NATIVE_VLAN:
	if (tree) {
	  tlvi = proto_tree_add_text(cdp_tree, tvb,
				     offset, length, "Native VLAN: %u",
				     tvb_get_ntohs(tvb, offset + 4));
	  tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_text(tlv_tree, tvb, offset + 4,
			      length - 4, "Native VLAN: %u",
			      tvb_get_ntohs(tvb, offset + 4));
	}
	offset += length;
	break;

      case TYPE_DUPLEX:
	if (tree) {
	  tlvi = proto_tree_add_text(cdp_tree, tvb,
				     offset, length, "Duplex: %s",
				     tvb_get_guint8(tvb, offset + 4) ?
				     "Full" : "Half" );
	  tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_text(tlv_tree, tvb, offset + 4,
			      length - 4, "Duplex: %s",
			      tvb_get_guint8(tvb, offset + 4) ?
			      "Full" : "Half" );
	}
	offset += length;
	break;

      case TYPE_VOIP_VLAN_REPLY:
	if (tree) {
	  if (length >= 7) {
	    tlvi = proto_tree_add_text(cdp_tree, tvb, offset, length,
				       "VoIP VLAN Reply: %u", tvb_get_ntohs(tvb, offset + 5));
	  } else {
	    /*
	     * XXX - what are these?  I've seen them in some captures;
	     * they have a length of 6, and run up to the end of
	     * the packet, so if we try to dissect it the same way
	     * we dissect the 7-byte ones, we report a malformed
	     * frame.
	     */
	    tlvi = proto_tree_add_text(cdp_tree, tvb,
				       offset, length, "VoIP VLAN Reply");
	  }
	  tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_text(tlv_tree, tvb, offset + 4,
			      1, "Data");
	  if (length >= 7) {
	    proto_tree_add_text(tlv_tree, tvb, offset + 5,
				2, "Voice VLAN: %u",
				tvb_get_ntohs(tvb, offset + 5));
	  }
	}
	offset += length;
	break;

      case TYPE_VOIP_VLAN_QUERY:
	if (tree) {
	  if (length >= 7) {
	    tlvi = proto_tree_add_text(cdp_tree, tvb,
				       offset, length, "VoIP VLAN Query: %u", tvb_get_ntohs(tvb, offset + 5));
	  } else {
	    /*
	     * XXX - what are these?  I've seen them in some captures;
	     * they have a length of 6, and run up to the end of
	     * the packet, so if we try to dissect it the same way
	     * we dissect the 7-byte ones, we report a malformed
	     * frame.
	     */
	    tlvi = proto_tree_add_text(cdp_tree, tvb,
				       offset, length, "VoIP VLAN Query");
	  }
	  tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_text(tlv_tree, tvb, offset + 4,
			      1, "Data");
	  if (length >= 7) {
	    proto_tree_add_text(tlv_tree, tvb, offset + 5,
				2, "Voice VLAN: %u",
				tvb_get_ntohs(tvb, offset + 5));
	  }
	}
	offset += length;
	break;

      case TYPE_POWER:
	if (tree) {
	  tlvi = proto_tree_add_text(cdp_tree, tvb,
				     offset, length, "Power Consumption: %u mW",
				     tvb_get_ntohs(tvb, offset + 4));
	  tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_text(tlv_tree, tvb, offset + 4,
			      length - 4, "Power Consumption: %u mW",
			      tvb_get_ntohs(tvb, offset + 4));
	}
	offset += length;
	break;

      case TYPE_MTU:
	if (tree) {
	  tlvi = proto_tree_add_text(cdp_tree, tvb,
				     offset, length, "MTU: %u",
				     tvb_get_ntohl(tvb,offset + 4));
	  tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_text(tlv_tree, tvb, offset + 4,
			      length - 4, "MTU: %u",
			      tvb_get_ntohl(tvb,offset + 4));
	}
	offset += length;
	break;

      case TYPE_TRUST_BITMAP:
	if (tree) {
	  tlvi = proto_tree_add_text(cdp_tree, tvb,
				     offset, length, "Trust Bitmap: 0x%02X",
				     tvb_get_guint8(tvb, offset + 4));
	  tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_text(tlv_tree, tvb, offset + 4,
			      length - 4, "Trust Bitmap: %02x",
			      tvb_get_guint8(tvb, offset + 4));
	}
	offset += length;
	break;

      case TYPE_UNTRUSTED_COS:
	if (tree) {
	  tlvi = proto_tree_add_text(cdp_tree, tvb,
				     offset, length, "Untrusted port CoS: 0x%02X",
				     tvb_get_guint8(tvb, offset + 4));
	  tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_text(tlv_tree, tvb, offset + 4,
			      length - 4, "Untrusted port CoS: %02x",
			      tvb_get_guint8(tvb, offset + 4));
	}
	offset += length;
	break;

      case TYPE_SYSTEM_NAME:
	if (tree) {
	  tlvi = proto_tree_add_text(cdp_tree, tvb,
				     offset, length, "System Name: %s",
				     tvb_format_text(tvb, offset + 4, length - 4));
	  tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_text(tlv_tree, tvb, offset + 4,
			      length - 4, "System Name: %s",
			      tvb_format_text(tvb, offset + 4, length - 4));
	}
	offset += length;
	break;

      case TYPE_SYSTEM_OID:
	if (tree) {
	  tlvi = proto_tree_add_text(cdp_tree, tvb,
				     offset, length, "System Object Identifier");
	  tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_text(tlv_tree, tvb, offset + 4,
			      length - 4, "System Object Identifier: %s",
			      tvb_bytes_to_str(tvb, offset + 4, length - 4));
	}
	offset += length;
	break;

      case TYPE_MANAGEMENT_ADDR:
	if (tree) {
	  tlvi = proto_tree_add_text(cdp_tree, tvb,
				     offset, length, "Management Addresses");
	  tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
	}
	offset += 4;
	length -= 4;
	naddresses = tvb_get_ntohl(tvb, offset);
	if (tree) {
	  proto_tree_add_text(tlv_tree, tvb, offset, 4,
			      "Number of addresses: %u", naddresses);
	}
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

      case TYPE_LOCATION:
	if (tree) {
	  tlvi = proto_tree_add_text(cdp_tree, tvb,
				     offset, length, "Location: %s",
				     tvb_format_text(tvb, offset + 5, length - 5));
	  tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_text(tlv_tree, tvb, offset + 4,
			      1 , "UNKNOWN: 0x%02X",
			      tvb_get_guint8(tvb, offset + 4));
	  proto_tree_add_text(tlv_tree, tvb, offset + 5,
			      length - 5, "Location: %s",
			      tvb_format_text(tvb, offset + 5, length - 5));
	}
	offset += length;
	break;

      case TYPE_POWER_REQUESTED:
	if (tree) {
	  tlvi = proto_tree_add_text(cdp_tree, tvb,
				     offset, length, "Power Request: ");
	  tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_text(tlv_tree, tvb, offset + 4,
			      2, "Request-ID: %u",
			      tvb_get_ntohs(tvb, offset + 4));
	  proto_tree_add_text(tlv_tree, tvb, offset + 6,
			      2, "Management-ID: %u",
			      tvb_get_ntohs(tvb, offset + 6));
	}
	power_req_len = (tvb_get_ntohs(tvb, offset + TLV_LENGTH)) - 8;
	/* Move offset to where the list of Power Request Values Exist */
	offset += 8;
	while(power_req_len) {
	  if (power_req_len > 4) {
	    power_req = tvb_get_ntohl(tvb, offset);
	    if (tree) {
	      proto_tree_add_text(tlv_tree, tvb, offset,
				  4, "Power Requested: %u mW", power_req);
	      proto_item_append_text(tlvi, "%u mW, ", power_req);
	    }
	    power_req_len -= 4;
	    offset += 4;
	  } else {
	    if (power_req_len == 4) {
	      power_req = tvb_get_ntohl(tvb, offset);
	      if (tree) {
		proto_tree_add_text(tlv_tree, tvb, offset,
				    4, "Power Requested: %u mW", power_req);
		proto_item_append_text(tlvi, "%u mW", power_req);
	      }
	    }
	    offset += power_req_len;
	    break;
	  }
	}
	break;

      case TYPE_POWER_AVAILABLE:
	if (tree) {
	  tlvi = proto_tree_add_text(cdp_tree, tvb,
				     offset, length, "Power Available: ");
	  tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_text(tlv_tree, tvb, offset + 4,
			      2, "Request-ID: %u",
			      tvb_get_ntohs(tvb, offset + 4));
	  proto_tree_add_text(tlv_tree, tvb, offset + 6,
			      2, "Management-ID: %u",
			      tvb_get_ntohs(tvb, offset + 6));
	}
	power_avail_len = (tvb_get_ntohs(tvb, offset + TLV_LENGTH)) - 8;
	/* Move offset to where the list of Power Available Values Exist */
	offset += 8;
	while(power_avail_len) {
	  if (power_avail_len >= 4) {
	    power_avail = tvb_get_ntohl(tvb, offset);
	    if (tree) {
	      proto_tree_add_text(tlv_tree, tvb, offset,
				  4, "Power Available: %u mW", power_avail);
	      proto_item_append_text(tlvi, "%u mW, ", power_avail);
	    }
	    power_avail_len -= 4;
	    offset += 4;
	  } else {
	    offset += power_avail_len;
	    break;
	  }
	}
	break;

      case TYPE_NRGYZ:
	if (tree) {
	  tlvi = proto_tree_add_text(cdp_tree, tvb,
				     offset, length, "EnergyWise");
	  tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_text(tlv_tree, tvb, offset + 4,
			      20, "Encrypted Data");
	  proto_tree_add_text(tlv_tree, tvb, offset + 24,
			      4, "Unknown (Seen Sequence?): %u",
			      tvb_get_ntohl(tvb, offset + 24));
	  proto_tree_add_text(tlv_tree, tvb, offset + 28,
			      4, "Sequence Number: %u",
			      tvb_get_ntohl(tvb, offset + 28));
	  proto_tree_add_text(tlv_tree, tvb, offset + 32,
			      16, "Model Number: %s",
			      tvb_format_stringzpad(tvb, offset + 32, 16));
	  proto_tree_add_text(tlv_tree, tvb, offset + 48,
			      2, "Unknown Pad: %x",
			      tvb_get_ntohs(tvb, offset + 48));
	  proto_tree_add_text(tlv_tree, tvb, offset + 50,
			      3, "Hardware Version ID: %s",
			      tvb_format_stringzpad(tvb, offset + 50, 3));
	  proto_tree_add_text(tlv_tree, tvb, offset + 53,
			      11, "System Serial Number: %s",
			      tvb_format_stringzpad(tvb, offset + 53, 11));
	  proto_tree_add_text(tlv_tree, tvb, offset + 64,
			      8, "Unknown Values");
	  proto_tree_add_text(tlv_tree, tvb, offset + 72,
			      2, "Length of TLV table: %u",
			      tvb_get_ntohs(tvb, offset + 72));
	  proto_tree_add_text(tlv_tree, tvb, offset + 74,
			      2, "Number of TLVs in table: %u",
			      tvb_get_ntohs(tvb, offset + 74));
/*
	  proto_tree_add_text(tlv_tree, tvb,
			      offset + 76, length - 76,
			      "EnergyWise TLV Table");
*/
	  dissect_nrgyz_tlv(tvb, offset + 76,
			    tvb_get_ntohs(tvb, offset + 72),
			    tvb_get_ntohs(tvb, offset + 74),
			    tlv_tree);


	}
	offset += length;
	break;

      case TYPE_SPARE_POE:
	if (tree) {
	  tlvi = proto_tree_add_text(cdp_tree, tvb, offset, length,
				     "Spare Pair PoE");
	  tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);

	  proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
	}
        offset += 4;
        length -= 4;
        dissect_spare_poe_tlv(tvb, offset, length, tlv_tree);
	offset += length;
	break;

      default:
	if (tree) {
	  tlvi = proto_tree_add_text(cdp_tree, tvb, offset,
				     length, "Type: %s, length: %u",
				     val_to_str(type, type_vals, "Unknown (0x%04x)"),
				     length);
	  tlv_tree = proto_item_add_subtree(tlvi, ett_cdp_tlv);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
	  proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
	  if (length > 4) {
	    proto_tree_add_text(tlv_tree, tvb, offset + 4,
				length - 4, "Data");
	  } else {
	    return;
	  }
	}
	offset += length;
      }
    }
    call_dissector(data_handle, tvb_new_subset_remaining(tvb, offset), pinfo,
		   cdp_tree);
}

#define	PROTO_TYPE_NLPID	1
#define	PROTO_TYPE_IEEE_802_2	2

static const value_string proto_type_vals[] = {
	{ PROTO_TYPE_NLPID,      "NLPID" },
	{ PROTO_TYPE_IEEE_802_2, "802.2" },
	{ 0,                     NULL }
};

static int
dissect_address_tlv(tvbuff_t *tvb, int offset, int length, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *address_tree;
    guint8 protocol_type;
    guint8 protocol_length;
    int nlpid;
    const char *protocol_str;
    guint16 address_length;
    const char *address_type_str;
    const char *address_str;

    if (length < 1)
        return -1;
    ti = proto_tree_add_text(tree, tvb, offset, length, "Truncated address");
    address_tree = proto_item_add_subtree(ti, ett_cdp_address);
    protocol_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(address_tree, tvb, offset, 1, "Protocol type: %s",
	val_to_str(protocol_type, proto_type_vals, "Unknown (0x%02x)"));
    offset += 1;
    length -= 1;

    if (length < 1)
	return -1;
    protocol_length = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(address_tree, tvb, offset, 1, "Protocol length: %u",
			protocol_length);
    offset += 1;
    length -= 1;

    if (length < protocol_length) {
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

    if (length < 2)
	return -1;
    address_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(address_tree, tvb, offset, 2, "Address length: %u",
			address_length);
    offset += 2;
    length -= 2;

    if (length < address_length) {
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
                address_str = tvb_ip_to_str(tvb, offset);
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
    proto_tree_add_text(capabilities_tree, tvb, offset, 4, "%s",
	decode_boolean_bitfield(capabilities, 0x01, 4*8,
	    "Is  a Router",
	    "Not a Router"));
    proto_tree_add_text(capabilities_tree, tvb, offset, 4, "%s",
	decode_boolean_bitfield(capabilities, 0x02, 4*8,
	    "Is  a Transparent Bridge",
	    "Not a Transparent Bridge"));
    proto_tree_add_text(capabilities_tree, tvb, offset, 4, "%s",
	decode_boolean_bitfield(capabilities, 0x04, 4*8,
	    "Is  a Source Route Bridge",
	    "Not a Source Route Bridge"));
    proto_tree_add_text(capabilities_tree, tvb, offset, 4, "%s",
	decode_boolean_bitfield(capabilities, 0x08, 4*8,
	    "Is  a Switch",
	    "Not a Switch"));
    proto_tree_add_text(capabilities_tree, tvb, offset, 4, "%s",
	decode_boolean_bitfield(capabilities, 0x10, 4*8,
	    "Is  a Host",
	    "Not a Host"));
    proto_tree_add_text(capabilities_tree, tvb, offset, 4, "%s",
	decode_boolean_bitfield(capabilities, 0x20, 4*8,
	    "Is  IGMP capable",
	    "Not IGMP capable"));
    proto_tree_add_text(capabilities_tree, tvb, offset, 4, "%s",
	decode_boolean_bitfield(capabilities, 0x40, 4*8,
	    "Is  a Repeater",
	    "Not a Repeater"));
}

static void
dissect_nrgyz_tlv(tvbuff_t *tvb, int offset, guint16 length, guint16 num,
		  proto_tree *tree)
{
    guint32 tlvt, tlvl, ip_addr;
    proto_item *it = NULL;
    proto_tree *etree = NULL;
    char const *ttext = NULL;

    while (num-- && length >= 8) {
	tlvt = tvb_get_ntohl(tvb, offset);
	tlvl = tvb_get_ntohl(tvb, offset + 4);

	if (length < tlvl) break;
	length -= tlvl;

	if (tlvl < 8) {
		proto_tree_add_text(tree, tvb, offset, 8,
				    "TLV with invalid length %u (< 8)",
				    tlvl);
		offset += 8;
		break;
	}
	else {
	    ttext = val_to_str(tlvt, type_nrgyz_vals, "Unknown (0x%04x)");
	    switch (tlvt) {
	    case TYPE_NRGYZ_ROLE:
	    case TYPE_NRGYZ_DOMAIN:
	    case TYPE_NRGYZ_NAME:
		it = proto_tree_add_text(tree, tvb, offset,
					 tlvl, "EnergyWise %s: %s", ttext,
					 tvb_format_stringzpad(tvb,
							 offset + 8, tlvl - 8)
					 );
		break;
	    case TYPE_NRGYZ_REPLYTO:
		ip_addr = tvb_get_ipv4(tvb, offset + 12);
		it = proto_tree_add_text(tree, tvb, offset,
					 tlvl, "EnergyWise %s: %s port %u",
					 ttext,
					 ip_to_str((guint8 *)&ip_addr),
					 tvb_get_ntohs(tvb, offset + 10)
					 );
		break;
	    default:
		it = proto_tree_add_text(tree, tvb, offset,
					 tlvl, "EnergyWise %s TLV", ttext);
	    }
	    etree = proto_item_add_subtree(it, ett_cdp_nrgyz_tlv);
	    proto_tree_add_text(etree, tvb, offset, 4,
				"TLV Type: %x (%s)", tlvt, ttext);
	    proto_tree_add_text(etree, tvb, offset + 4, 4,
				"TLV Length: %u", tlvl);
	    switch (tlvt) {
	    case TYPE_NRGYZ_ROLE:
	    case TYPE_NRGYZ_DOMAIN:
	    case TYPE_NRGYZ_NAME:
		proto_tree_add_text(etree, tvb, offset + 8,
				    tlvl - 8, "%s %s", ttext,
				    tvb_format_stringzpad(tvb,
							  offset + 8, tlvl - 8)
				    );
		break;
	    case TYPE_NRGYZ_REPLYTO:
		ip_addr = tvb_get_ipv4(tvb, offset + 12);
		proto_tree_add_text(etree, tvb, offset + 8, 2,
				    "Unknown Field");
		proto_tree_add_text(etree, tvb, offset + 10, 2,
				    "Port %d",
				    tvb_get_ntohs(tvb, offset + 10)
				    );
		proto_tree_add_text(etree, tvb, offset + 12, 4,
				    "IP Address %s",
				    ip_to_str((guint8 *)&ip_addr)
				    );
		proto_tree_add_text(etree, tvb, offset + 16, 2,
				    "Unknown Field (Backup server Port?)");
		proto_tree_add_text(etree, tvb, offset + 18, 4,
				    "Unknown Field (Backup Server IP?)");
		break;
	    default:
		if (tlvl > 8) {
		    proto_tree_add_text(etree, tvb, offset + 8,
					tlvl - 8, "Data");
		}
	    }
	    offset += tlvl;
	}
    }
    if (length) {
	proto_tree_add_text(tree, tvb, offset, length,
			    "Invalid garbage at end");
    }
}

static void
dissect_spare_poe_tlv(tvbuff_t *tvb, int offset, int length,
		      proto_tree *tree)
{
    proto_item *ti;
    proto_tree *tlv_tree;
    guint8 tlv_data;

    if (length == 0) {
        return;
    }

    tlv_data = tvb_get_guint8(tvb, offset);
    ti = proto_tree_add_text(tree, tvb, offset, length,
			     "Spare Pair PoE: 0x%02x", tlv_data);
    tlv_tree = proto_item_add_subtree(ti, ett_cdp_spare_poe_tlv);

    proto_tree_add_text(tlv_tree, tvb, offset, 1, "%s",
        decode_boolean_bitfield(tlv_data, 0x01, 8,
	    "PSE Four-Wire PoE Supported",
	    "PSE Four-Wire PoE Not Supported"));
    proto_tree_add_text(tlv_tree, tvb, offset, 1, "%s",
        decode_boolean_bitfield(tlv_data, 0x02, 8,
	    "PD  Spare Pair Architecture Shared",
	    "PD  Spare Pair Architecture Independent"));
    proto_tree_add_text(tlv_tree, tvb, offset, 1, "%s",
        decode_boolean_bitfield(tlv_data, 0x04, 8,
	    "PD  Request Spare Pair PoE On",
	    "PD  Request Spare Pair PoE Off"));
    proto_tree_add_text(tlv_tree, tvb, offset, 1, "%s",
        decode_boolean_bitfield(tlv_data, 0x08, 8,
	    "PSE Spare Pair PoE On",
	    "PSE Spare Pair PoE Off"));
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

    prefix_len = (int)strlen(prefix);
    if (prefix_len > 64)
	prefix_len = 64;
    for (i = 0; i < prefix_len; i++)
	blanks[i] = ' ';
    blanks[i] = '\0';
    while (len > 0) {
	line_len = tvb_find_line_end(tvb, start, len, &next, FALSE);
	data_len = next - start;
	proto_tree_add_text(tree, tvb, start, data_len, "%s%s", prefix,
	   tvb_format_stringzpad(tvb, start, line_len));
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
	  NULL, HFILL }},

	{ &hf_cdp_ttl,
	{ "TTL",		"cdp.ttl", FT_UINT16, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }},

	{ &hf_cdp_checksum,
	{ "Checksum",		"cdp.checksum", FT_UINT16, BASE_HEX, NULL, 0x0,
	  NULL, HFILL }},

	{ &hf_cdp_checksum_good,
	  { "Good",       "cdp.checksum_good", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	    "True: checksum matches packet content; False: doesn't match content or not checked", HFILL }},

	{ &hf_cdp_checksum_bad,
	  { "Bad",       "cdp.checksum_bad", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	    "True: checksum doesn't match packet content; False: matches content or not checked", HFILL }},

	{ &hf_cdp_tlvtype,
	{ "Type",		"cdp.tlv.type", FT_UINT16, BASE_HEX, VALS(type_vals), 0x0,
	  NULL, HFILL }},

	{ &hf_cdp_tlvlength,
	{ "Length",		"cdp.tlv.len", FT_UINT16, BASE_DEC, NULL, 0x0,
	  NULL, HFILL }},

	{ &hf_cdp_deviceid,
	{"Device ID", "cdp.deviceid", FT_STRING, BASE_NONE,
	 NULL, 0, NULL, HFILL }},

	{ &hf_cdp_platform,
	{"Platform", "cdp.platform", FT_STRING, BASE_NONE,
	 NULL, 0, NULL, HFILL }},

	{ &hf_cdp_portid,
	{"Sent through Interface", "cdp.portid", FT_STRING, BASE_NONE,
		NULL, 0, NULL, HFILL }}
    };
    static gint *ett[] = {
	&ett_cdp,
	&ett_cdp_tlv,
	&ett_cdp_nrgyz_tlv,
	&ett_cdp_address,
	&ett_cdp_capabilities,
	&ett_cdp_checksum,
	&ett_cdp_spare_poe_tlv
    };

    proto_cdp = proto_register_protocol("Cisco Discovery Protocol",
					"CDP", "cdp");
    proto_register_field_array(proto_cdp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_cdp(void)
{
    dissector_handle_t cdp_handle;

    data_handle = find_dissector("data");
    cdp_handle = create_dissector_handle(dissect_cdp, proto_cdp);
    dissector_add_uint("llc.cisco_pid", 0x2000, cdp_handle);
    dissector_add_uint("chdlctype", 0x2000, cdp_handle);
    dissector_add_uint("ppp.protocol", 0x0207, cdp_handle);
}
