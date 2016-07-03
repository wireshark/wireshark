/* packet-packetbb.c
 * Routines for parsing packetbb rfc 5444
 * Parser created by Henning Rogge <henning.rogge@fkie.fraunhofer.de> of Fraunhover
 *
 * http://tools.ietf.org/html/rfc5444
 * http://tools.ietf.org/html/rfc5498
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "config.h"


#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

void proto_reg_handoff_packetbb(void);
void proto_register_packetbb(void);

#define PACKET_HEADER_HASSEQNR     0x08
#define PACKET_HEADER_HASTLV       0x04

#define MSG_HEADER_HASORIG         0x80
#define MSG_HEADER_HASHOPLIMIT     0x40
#define MSG_HEADER_HASHOPCOUNT     0x20
#define MSG_HEADER_HASSEQNR        0x10

#define ADDR_HASHEAD               0x80
#define ADDR_HASFULLTAIL           0x40
#define ADDR_HASZEROTAIL           0x20
#define ADDR_HASSINGLEPRELEN       0x10
#define ADDR_HASMULTIPRELEN        0x08

#define TLV_HAS_TYPEEXT            0x80
#define TLV_HAS_SINGLEINDEX        0x40
#define TLV_HAS_MULTIINDEX         0x20
#define TLV_HAS_VALUE              0x10
#define TLV_HAS_EXTLEN             0x08
#define TLV_HAS_MULTIVALUE         0x04

#define MAX_ADDR_SIZE                16

#define PACKETBB_MSG_TLV_LENGTH        (G_MAXUINT8 + 1)

#define TLV_CAT_PACKET             0
#define TLV_CAT_MESSAGE            1
#define TLV_CAT_ADDRESS            2

/* Message types defined by IANA in RFC5444 */
const value_string msgheader_type_vals[] = {
  { 0, "HELLO (NHDP)"                   },
  { 1, "TC (OLSRv2 Topology Control)"   },
  { 0, NULL                             }};

/* Packet TLV types defined by IANA in RFC7182 */
const value_string pkttlv_type_vals[] = {
  { 5, "ICV (Integrity Check Value)"    },
  { 6, "Timestamp"                      },
  { 0, NULL                             }};

/* Message TLV types defined by IANA in RFC5497,7181,7182 */
const value_string msgtlv_type_vals[] = {
  {  0, "Interval time"                 },
  {  1, "Validity time"                 },
  {  5, "ICV (Integrity Check Value)"   },
  {  6, "Timestamp"                     },
  {  7, "MPR willingness"               },
  {  8, "Continuous sequence number"    },
  {  0, NULL                            }};

/* Address TLV types defined by IANA in RFC5497,6130,7181,7182 */
const value_string addrtlv_type_vals[] = {
  {  0, "Interval time"                 },
  {  1, "Validity time"                 },
  {  2, "Local interface status"        },
  {  3, "Link status"                   },
  {  4, "Other neighbor status"         },
  {  5, "ICV (Integrity Check Value)"   },
  {  6, "Timestamp"                     },
  {  7, "Link metric"                   },
  {  8, "MPR (Multipoint Relay)"        },
  {  9, "Neighbor address type"         },
  { 10, "Gateway"                       },
  {  0, NULL                            }};

static int proto_packetbb = -1;
static guint global_packetbb_port = 269;

static int hf_packetbb_header = -1;
static int hf_packetbb_version = -1;
static int hf_packetbb_header_flags = -1;
static int hf_packetbb_header_flags_phasseqnum = -1;
static int hf_packetbb_header_flags_phastlv = -1;
static int hf_packetbb_seqnr = -1;
static int hf_packetbb_msg = -1;
static int hf_packetbb_msgheader = -1;
static int hf_packetbb_msgheader_type = -1;
static int hf_packetbb_msgheader_flags = -1;
static int hf_packetbb_msgheader_flags_mhasorig = -1;
static int hf_packetbb_msgheader_flags_mhashoplimit = -1;
static int hf_packetbb_msgheader_flags_mhashopcount = -1;
static int hf_packetbb_msgheader_flags_mhasseqnr = -1;
static int hf_packetbb_msgheader_addresssize = -1;
static int hf_packetbb_msgheader_size = -1;
static int hf_packetbb_msgheader_origaddripv4 = -1;
static int hf_packetbb_msgheader_origaddripv6 = -1;
static int hf_packetbb_msgheader_origaddrmac = -1;
static int hf_packetbb_msgheader_origaddrcustom = -1;
static int hf_packetbb_msgheader_hoplimit = -1;
static int hf_packetbb_msgheader_hopcount = -1;
static int hf_packetbb_msgheader_seqnr = -1;
static int hf_packetbb_addr = -1;
static int hf_packetbb_addr_num = -1;
static int hf_packetbb_addr_flags = -1;
static int hf_packetbb_addr_flags_hashead = -1;
static int hf_packetbb_addr_flags_hasfulltail = -1;
static int hf_packetbb_addr_flags_haszerotail = -1;
static int hf_packetbb_addr_flags_hassingleprelen = -1;
static int hf_packetbb_addr_flags_hasmultiprelen = -1;
static int hf_packetbb_addr_head = -1;
static int hf_packetbb_addr_tail = -1;
static int hf_packetbb_addr_value[4] = { -1, -1, -1, -1 };
static int hf_packetbb_addr_value_mid = -1;
static int hf_packetbb_addr_value_prefix = -1;
static int hf_packetbb_tlvblock = -1;
static int hf_packetbb_tlvblock_length = -1;
static int hf_packetbb_tlv = -1;
static int hf_packetbb_pkttlv_type = -1;
static int hf_packetbb_msgtlv_type = -1;
static int hf_packetbb_addrtlv_type = -1;
static int hf_packetbb_tlv_flags = -1;
static int hf_packetbb_tlv_flags_hastypext = -1;
static int hf_packetbb_tlv_flags_hassingleindex = -1;
static int hf_packetbb_tlv_flags_hasmultiindex = -1;
static int hf_packetbb_tlv_flags_hasvalue = -1;
static int hf_packetbb_tlv_flags_hasextlen = -1;
static int hf_packetbb_tlv_flags_hasmultivalue = -1;
static int hf_packetbb_tlv_typeext = -1;
static int hf_packetbb_tlv_indexstart = -1;
static int hf_packetbb_tlv_indexend = -1;
static int hf_packetbb_tlv_length = -1;
static int hf_packetbb_tlv_value = -1;
static int hf_packetbb_tlv_multivalue = -1;

static gint ett_packetbb = -1;
static gint ett_packetbb_header = -1;
static gint ett_packetbb_header_flags = -1;
static gint ett_packetbb_msg[PACKETBB_MSG_TLV_LENGTH];
static gint ett_packetbb_msgheader = -1;
static gint ett_packetbb_msgheader_flags = -1;
static gint ett_packetbb_addr = -1;
static gint ett_packetbb_addr_flags = -1;
static gint ett_packetbb_addr_value = -1;
static gint ett_packetbb_tlvblock = -1;
static gint ett_packetbb_tlv[PACKETBB_MSG_TLV_LENGTH];
static gint ett_packetbb_tlv_flags = -1;
static gint ett_packetbb_tlv_value = -1;

static expert_field ei_packetbb_error = EI_INIT;


static int dissect_pbb_tlvblock(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset,
    guint maxoffset, gint8 addrCount, guint tlvCat) {
  guint16 tlvblockLength;
  guint tlvblockEnd;

  proto_tree *tlvblock_tree, *tlv_tree, *tlvValue_tree;
  proto_item *tlvBlock_item, *tlv_item, *tlvValue_item;

  int tlvCount = 0;

  int hf_packetbb_tlv_type = 0;
  const value_string* tlv_type_vals = NULL;

  static const int *flags[] = {
    &hf_packetbb_tlv_flags_hastypext,
    &hf_packetbb_tlv_flags_hassingleindex,
    &hf_packetbb_tlv_flags_hasmultiindex,
    &hf_packetbb_tlv_flags_hasvalue,
    &hf_packetbb_tlv_flags_hasextlen,
    &hf_packetbb_tlv_flags_hasmultivalue,
    NULL
  };

  if (maxoffset < offset + 2) {
    proto_tree_add_expert_format(tree, pinfo, &ei_packetbb_error, tvb, offset, maxoffset - offset,
        "Not enough octets for minimal tlvblock");
    return maxoffset;
  }

  tlvblockLength = tvb_get_ntohs(tvb, offset);

  tlvblockEnd = offset + 2 + tlvblockLength;
  if (maxoffset < tlvblockEnd) {
    proto_tree_add_expert_format(tree, pinfo, &ei_packetbb_error, tvb, offset, maxoffset - offset,
        "Not enough octets for tlvblock");
    return maxoffset;
  }

  tlvBlock_item = proto_tree_add_item(tree, hf_packetbb_tlvblock, tvb, offset, tlvblockEnd - offset, ENC_NA);
  tlvblock_tree = proto_item_add_subtree(tlvBlock_item, ett_packetbb_tlvblock);

  proto_tree_add_item(tlvblock_tree, hf_packetbb_tlvblock_length, tvb, offset, 2, ENC_BIG_ENDIAN);

  offset += 2;
  while (offset < tlvblockEnd) {
    guint tlvStart, tlvLength;
    guint8 tlvType, tlvFlags, tlvExtType, indexStart, indexEnd;
    guint16 length = 0;

    tlvStart = offset;
    tlvType = tvb_get_guint8(tvb, offset++);
    tlvFlags = tvb_get_guint8(tvb, offset++);

    indexStart = 0;
    indexEnd = addrCount ? (addrCount - 1) : 0;
    tlvExtType = 0;

    if ((tlvFlags & TLV_HAS_TYPEEXT) != 0) {
      tlvExtType = tvb_get_guint8(tvb, offset++);
    }

    if ((tlvFlags & TLV_HAS_SINGLEINDEX) != 0) {
      indexStart = indexEnd = tvb_get_guint8(tvb, offset++);
    }
    else if ((tlvFlags & TLV_HAS_MULTIINDEX) != 0) {
      indexStart = tvb_get_guint8(tvb, offset++);
      indexEnd = tvb_get_guint8(tvb, offset++);
    }

    if ((tlvFlags & TLV_HAS_VALUE) != 0) {
      if ((tlvFlags & TLV_HAS_EXTLEN) != 0) {
        length = tvb_get_ntohs(tvb, offset++);
      }
      else {
        length = tvb_get_guint8(tvb, offset++);
      }
    }

    tlvLength = offset - tlvStart + length;
    offset = tlvStart;

    tlv_item = proto_tree_add_item(tlvBlock_item, hf_packetbb_tlv, tvb, tlvStart, tlvLength, ENC_NA);
    tlv_tree = proto_item_add_subtree(tlv_item, ett_packetbb_tlv[tlvType]);

    /* select possible strings for tlvType */
    if (tlvCat == TLV_CAT_PACKET) {
      hf_packetbb_tlv_type = hf_packetbb_pkttlv_type;
      tlv_type_vals = pkttlv_type_vals;
    }
    else if (tlvCat == TLV_CAT_MESSAGE) {
      hf_packetbb_tlv_type = hf_packetbb_msgtlv_type;
      tlv_type_vals = msgtlv_type_vals;
    }
    else {
      /* assume TLV_CAT_ADDRESS */
      hf_packetbb_tlv_type = hf_packetbb_addrtlv_type;
      tlv_type_vals = addrtlv_type_vals;
    }

    if ((tlvFlags & TLV_HAS_TYPEEXT) == 0) {
      proto_item_append_text(tlv_item, " (%s)",
        val_to_str_const(tlvType, tlv_type_vals, "Unknown type"));
    }
    else {
      proto_item_append_text(tlv_item, " (%s / %d)",
        val_to_str_const(tlvType, tlv_type_vals, "Unknown type"), tlvExtType);
    }

    /* add type */
    proto_tree_add_item(tlv_tree, hf_packetbb_tlv_type, tvb, offset++, 1, ENC_BIG_ENDIAN);

    /* add flags */
    proto_tree_add_bitmask(tlv_tree, tvb, offset, hf_packetbb_tlv_flags, ett_packetbb_tlv_flags, flags, ENC_BIG_ENDIAN);
    offset++;

    if ((tlvFlags & TLV_HAS_TYPEEXT) != 0) {
      /* add ext-type */
      proto_tree_add_item(tlv_tree, hf_packetbb_tlv_typeext, tvb, offset++, 1, ENC_BIG_ENDIAN);
    }

    if (addrCount > 0) {
      /* add index values */
      if ((tlvFlags & TLV_HAS_SINGLEINDEX) != 0) {
        proto_tree_add_uint(tlv_tree, hf_packetbb_tlv_indexstart, tvb, offset++, 1, indexStart);

        proto_tree_add_uint_format_value(tlv_tree, hf_packetbb_tlv_indexend, tvb, offset, 0, indexEnd, "%d (implicit)", indexEnd);
      }
      else if ((tlvFlags & TLV_HAS_MULTIINDEX) != 0) {
        proto_tree_add_uint(tlv_tree, hf_packetbb_tlv_indexstart, tvb, offset++, 1, indexStart);
        proto_tree_add_uint(tlv_tree, hf_packetbb_tlv_indexend, tvb, offset++, 1, indexEnd);
      }
      else {
        proto_tree_add_uint_format_value(tlv_tree, hf_packetbb_tlv_indexstart, tvb, offset, 0, indexStart, "%d (implicit)", indexStart);
        proto_tree_add_uint_format_value(tlv_tree, hf_packetbb_tlv_indexend, tvb, offset, 0, indexEnd, "%d (implicit)", indexEnd);
      }
    }

    /* add length */
    if ((tlvFlags & TLV_HAS_VALUE) != 0) {
      if ((tlvFlags & TLV_HAS_EXTLEN) != 0) {
        proto_tree_add_uint(tlv_tree, hf_packetbb_tlv_length, tvb, offset, 2, length);
        offset += 2;
      }
      else {
        proto_tree_add_uint(tlv_tree, hf_packetbb_tlv_length, tvb, offset++, 1, length);
      }
    }
    else {
      proto_tree_add_uint_format_value(tlv_tree, hf_packetbb_tlv_length, tvb, offset, 0, 0, "0 (implicit)");
    }

    if (length > 0) {
      /* add value */
      tlvValue_item = proto_tree_add_item(tlv_tree, hf_packetbb_tlv_value, tvb, offset, length, ENC_NA);

      if ((tlvFlags & TLV_HAS_MULTIVALUE) == 0) {
        offset += length;
      }
      else {
        int i;
        guint c = indexEnd - indexStart + 1;
        if (c > 0) {
          tlvValue_tree = proto_item_add_subtree(tlvValue_item, ett_packetbb_tlv_value);

          for (i=indexStart; i<=indexEnd; i++) {
            proto_tree_add_item(tlvValue_tree, hf_packetbb_tlv_multivalue, tvb, offset, length/c, ENC_NA);
            offset += (length/c);
          }
        }
      }
    }
    tlvCount++;
  }

  proto_item_append_text(tlvBlock_item, " (%d TLVs)", tlvCount);

  return offset;
}

static int dissect_pbb_addressblock(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint maxoffset,
    guint8 addressType, guint8 addressSize) {
  guint8 addr[MAX_ADDR_SIZE];

  guint8 numAddr;
  guint8 address_flags;
  guint8 head_length = 0, tail_length = 0;
  guint block_length = 0, midSize = 0;
  guint block_index = 0, head_index = 0, tail_index = 0, mid_index = 0, prefix_index = 0;

  proto_tree *addr_tree = NULL;
  proto_tree *addrValue_tree = NULL;

  proto_item *addr_item = NULL;
  proto_item *addrValue_item = NULL;

  int i = 0;

  static const int *flags[] = {
    &hf_packetbb_addr_flags_hashead,
    &hf_packetbb_addr_flags_hasfulltail,
    &hf_packetbb_addr_flags_haszerotail,
    &hf_packetbb_addr_flags_hassingleprelen,
    &hf_packetbb_addr_flags_hasmultiprelen,
    NULL
  };

  if (maxoffset - offset < 2) {
    proto_tree_add_expert_format(tree, pinfo, &ei_packetbb_error, tvb, offset, maxoffset - offset,
        "Not enough octets for minimal addressblock header");
    return tvb_reported_length(tvb);
  }

  DISSECTOR_ASSERT(addressSize <= MAX_ADDR_SIZE);

  memset(addr, 0, addressSize);

  block_length = 2;
  block_index = offset;
  midSize = addressSize;

  numAddr = tvb_get_guint8(tvb, offset++);
  address_flags = tvb_get_guint8(tvb, offset++);

  if ((address_flags & ADDR_HASHEAD) != 0) {
    head_index = offset;

    if (maxoffset - offset <= 0) {
      proto_tree_add_expert_format(tree, pinfo, &ei_packetbb_error, tvb, offset, maxoffset - offset,
         "Not enough octets for addressblock head");
      return tvb_reported_length(tvb);
    }
    head_length = tvb_get_guint8(tvb, offset++);

    if (head_length > addressSize-1) {
      proto_tree_add_expert_format(tree, pinfo, &ei_packetbb_error, tvb, offset, maxoffset - offset,
          "address head length is too long");
      return tvb_reported_length(tvb);
    }
    if (maxoffset - offset < head_length) {
      proto_tree_add_expert_format(tree, pinfo, &ei_packetbb_error, tvb, offset, maxoffset - offset,
          "Not enough octets for addressblock head");
      return tvb_reported_length(tvb);
    }
    tvb_memcpy(tvb, addr, offset, head_length);

    midSize -= head_length;
    block_length += (head_length+1);
    offset += head_length;
  }
  if ((address_flags & ADDR_HASZEROTAIL) != 0) {
    tail_index = offset;

    if (maxoffset - offset <= 0) {
      proto_tree_add_expert_format(tree, pinfo, &ei_packetbb_error, tvb, offset, maxoffset - offset,
          "Not enough octets for addressblock tail");
      return tvb_reported_length(tvb);
    }
    tail_length = tvb_get_guint8(tvb, offset++);
    if (tail_length > addressSize-1-head_length) {
      proto_tree_add_expert_format(tree, pinfo, &ei_packetbb_error, tvb, offset, maxoffset - offset,
          "address tail length is too long");
      return tvb_reported_length(tvb);
    }
    midSize -= tail_length;
    block_length++;
  }
  else if ((address_flags & ADDR_HASFULLTAIL) != 0) {
    tail_index = offset;

    if (maxoffset - offset <= 0) {
      proto_tree_add_expert_format(tree, pinfo, &ei_packetbb_error, tvb, offset, maxoffset - offset,
          "Not enough octets for addressblock tail");
      return tvb_reported_length(tvb);
    }
    tail_length = tvb_get_guint8(tvb, offset++);
    if (tail_length > addressSize-1-head_length) {
      proto_tree_add_expert_format(tree, pinfo, &ei_packetbb_error, tvb, offset, maxoffset - offset,
          "address tail length is too long");
      return tvb_reported_length(tvb);
    }

    if (maxoffset - offset < tail_length) {
      proto_tree_add_expert_format(tree, pinfo, &ei_packetbb_error, tvb, offset, maxoffset - offset,
          "Not enough octets for addressblock tail");
      return tvb_reported_length(tvb);
    }
    tvb_memcpy(tvb, &addr[addressSize - tail_length], offset, tail_length);

    midSize -= tail_length;
    block_length += (tail_length+1);
    offset += tail_length;
  }

  mid_index = offset;
  block_length += numAddr * midSize;
  offset += numAddr * midSize;

  if ((address_flags & ADDR_HASSINGLEPRELEN) != 0) {
    prefix_index = offset;
    block_length++;
  }
  else if ((address_flags & ADDR_HASMULTIPRELEN) != 0) {
    prefix_index = offset;
    block_length += numAddr;
  }

  if (maxoffset < block_index + block_length) {
    proto_tree_add_expert_format(tree, pinfo, &ei_packetbb_error, tvb, offset, maxoffset - offset,
        "Not enough octets for address block");
    return maxoffset;
  }

  /* add address tree */
  addr_item = proto_tree_add_item(tree, hf_packetbb_addr, tvb, block_index, block_length, ENC_NA);
  addr_tree = proto_item_add_subtree(addr_item, ett_packetbb_addr);
  proto_item_append_text(addr_item, " (%d addresses)", numAddr);

  /* add num-addr */
  proto_tree_add_item(addr_tree, hf_packetbb_addr_num, tvb, block_index, 1, ENC_BIG_ENDIAN);

  /* add flags */
  proto_tree_add_bitmask(addr_tree, tvb, block_index+1, hf_packetbb_addr_flags, ett_packetbb_addr_flags, flags, ENC_BIG_ENDIAN);

  if ((address_flags & ADDR_HASHEAD) != 0) {
    /* add head */
    proto_tree_add_item(addr_tree, hf_packetbb_addr_head, tvb, head_index, head_length+1, ENC_NA);
  }

  if ((address_flags & ADDR_HASFULLTAIL) != 0) {
    /* add full tail */
    proto_tree_add_item(addr_tree, hf_packetbb_addr_tail, tvb, tail_index, tail_length+1, ENC_NA);
  }
  else if ((address_flags & ADDR_HASZEROTAIL) != 0) {
    /* add zero tail */
    proto_tree_add_item(addr_tree, hf_packetbb_addr_tail, tvb, tail_index, 1, ENC_NA);
  }
  for (i=0; i<numAddr; i++) {
    guint32 ipv4 = 0;
    guint8 prefix = addressSize * 8;

    tvb_memcpy(tvb, &addr[head_length], mid_index + midSize*i, midSize);
    ipv4 = (addr[3] << 24) + (addr[2] << 16) + (addr[1] << 8) + addr[0];

    switch (addressType) {
      case 0:
        addrValue_item = proto_tree_add_ipv4(addr_tree, hf_packetbb_addr_value[addressType],
            tvb, mid_index, block_index + block_length - mid_index, ipv4);
        break;
      case 1:
        addrValue_item = proto_tree_add_ipv6(addr_tree, hf_packetbb_addr_value[addressType],
            tvb, mid_index, block_index + block_length - mid_index, (struct e_in6_addr *)addr);
        break;
      case 2:
        addrValue_item = proto_tree_add_ether(addr_tree, hf_packetbb_addr_value[addressType],
            tvb, mid_index, block_index + block_length - mid_index, addr);
        break;
      case 3:
        addrValue_item = proto_tree_add_bytes(addr_tree, hf_packetbb_addr_value[addressType],
            tvb, mid_index, block_index + block_length - mid_index, addr);
        break;
      default:
        break;
    }
    addrValue_tree = proto_item_add_subtree(addrValue_item, ett_packetbb_addr_value);

    proto_tree_add_item(addrValue_tree, hf_packetbb_addr_value_mid, tvb,
        mid_index + midSize*i, midSize, ENC_NA);

    if ((address_flags & ADDR_HASSINGLEPRELEN) != 0) {
      prefix = tvb_get_guint8(tvb, prefix_index);
      proto_tree_add_item(addrValue_tree, hf_packetbb_addr_value_prefix, tvb, prefix_index, 1, ENC_BIG_ENDIAN);
    }
    else if ((address_flags & ADDR_HASMULTIPRELEN) != 0) {
      prefix = tvb_get_guint8(tvb, prefix_index + i);
      proto_tree_add_item(addrValue_tree, hf_packetbb_addr_value_prefix, tvb, prefix_index + i, 1, ENC_BIG_ENDIAN);
    }
    proto_item_append_text(addrValue_item, "/%d", prefix);
  }

  offset = dissect_pbb_tlvblock(tvb, pinfo, addr_tree, block_index + block_length, maxoffset, numAddr, TLV_CAT_ADDRESS);
  return offset;
}

static int dissect_pbb_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset) {
  proto_tree *message_tree;
  proto_tree *header_tree = NULL;
  proto_tree *headerFlags_tree = NULL;

  proto_item *message_item;
  proto_item *header_item = NULL;
  proto_item *headerFlags_item = NULL;

  guint8 messageType;
  guint8 messageFlags;
  guint16 messageLength, headerLength, messageEnd;
  guint8 addressSize, addressType;

  if (tvb_reported_length(tvb) - offset < 6) {
    proto_tree_add_expert_format(tree, pinfo, &ei_packetbb_error, tvb, offset, -1,
        "Not enough octets for minimal message header");
    return tvb_reported_length(tvb);
  }

  messageType = tvb_get_guint8(tvb, offset);
  messageFlags = tvb_get_guint8(tvb, offset+1);
  messageLength = tvb_get_ntohs(tvb, offset+2);
  addressSize = (messageFlags & 0x0f) + 1;

  switch (addressSize) {
    case 4:
      addressType = 0;
      break;
    case 16:
      addressType = 1;
      break;
    case 6:
      addressType = 2;
      break;
    default:
      addressType = 3;
      break;
  }

  messageEnd = offset + messageLength;

  headerLength = 4;

  /* calculate header size */
  if ((messageFlags & MSG_HEADER_HASORIG) != 0) {
    headerLength += addressSize;
  }
  if ((messageFlags & MSG_HEADER_HASHOPLIMIT) != 0) {
    headerLength ++;
  }
  if ((messageFlags & MSG_HEADER_HASHOPCOUNT) != 0) {
    headerLength ++;
  }
  if ((messageFlags & MSG_HEADER_HASSEQNR) != 0) {
    headerLength += 2;
  }

  /* test length for message size */
  if (tvb_reported_length(tvb) - offset < messageLength) {
    proto_tree_add_expert_format(tree, pinfo, &ei_packetbb_error, tvb, offset, -1,
        "Not enough octets for message");
    return tvb_reported_length(tvb);
  }

  message_item = proto_tree_add_item(tree, hf_packetbb_msg, tvb, offset, messageLength, ENC_NA);
  message_tree = proto_item_add_subtree(message_item, ett_packetbb_msg[messageType]);
  proto_item_append_text(message_item, " (%s)",
    val_to_str_const(messageType, msgheader_type_vals, "Unknown type"));

  header_item = proto_tree_add_item(message_tree, hf_packetbb_msgheader, tvb, offset, headerLength, ENC_NA);
  header_tree = proto_item_add_subtree(header_item, ett_packetbb_msgheader);

  /* type */
  proto_tree_add_item(header_tree, hf_packetbb_msgheader_type, tvb, offset, 1, ENC_BIG_ENDIAN);

  /* flags */
  headerFlags_item = proto_tree_add_uint(header_tree, hf_packetbb_msgheader_flags,
      tvb, offset+1, 1, messageFlags & 0xf8);

  headerFlags_tree = proto_item_add_subtree(headerFlags_item, ett_packetbb_msgheader_flags);
  proto_tree_add_boolean(headerFlags_tree, hf_packetbb_msgheader_flags_mhasorig,
      tvb, offset+1, 1, messageFlags);
  proto_tree_add_boolean(headerFlags_tree, hf_packetbb_msgheader_flags_mhashoplimit,
      tvb, offset+1, 1, messageFlags);
  proto_tree_add_boolean(headerFlags_tree, hf_packetbb_msgheader_flags_mhashopcount,
      tvb, offset+1, 1, messageFlags);
  proto_tree_add_boolean(headerFlags_tree, hf_packetbb_msgheader_flags_mhasseqnr,
      tvb, offset+1, 1, messageFlags);

  proto_tree_add_uint(header_tree, hf_packetbb_msgheader_addresssize,
      tvb, offset + 1, 1, (messageFlags & 0x0f) + 1);

  /* size */
  proto_tree_add_item(header_tree, hf_packetbb_msgheader_size, tvb, offset+2, 2, ENC_BIG_ENDIAN);

  offset += 4;

  /* originator address */
  if ((messageFlags & MSG_HEADER_HASORIG) != 0) {
    switch (addressSize) {
    case 4:
      /* IPv4 */
      proto_tree_add_item(header_tree, hf_packetbb_msgheader_origaddripv4,
          tvb, offset, addressSize, ENC_BIG_ENDIAN);
      break;
    case 16:
      /* IPv6 */
      proto_tree_add_item(header_tree, hf_packetbb_msgheader_origaddripv6,
          tvb, offset, addressSize, ENC_NA);
      break;
    case 6:
      /* MAC */
      proto_tree_add_item(header_tree, hf_packetbb_msgheader_origaddrmac,
          tvb, offset, addressSize, ENC_NA);
      break;
    default:
      /* Unknown */
      proto_tree_add_item(header_tree, hf_packetbb_msgheader_origaddrcustom,
          tvb, offset, addressSize, ENC_NA);
      break;
    }
    offset += addressSize;
  }

  /* hop limit */
  if ((messageFlags & MSG_HEADER_HASHOPLIMIT) != 0) {
    proto_tree_add_item(header_tree, hf_packetbb_msgheader_hoplimit, tvb, offset++, 1, ENC_BIG_ENDIAN);
  }

  /* hop count */
  if ((messageFlags & MSG_HEADER_HASHOPCOUNT) != 0) {
    proto_tree_add_item(header_tree, hf_packetbb_msgheader_hopcount, tvb, offset++, 1, ENC_BIG_ENDIAN);
  }

  /* sequence number */
  if ((messageFlags & MSG_HEADER_HASSEQNR) != 0) {
    proto_tree_add_item(header_tree, hf_packetbb_msgheader_seqnr, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
  }

  if (offset >= messageEnd) {
    /* this is an error, tlv block is mandatory */
    return tvb_reported_length(tvb);
  }
  offset = dissect_pbb_tlvblock(tvb, pinfo, message_tree, offset, messageEnd, 0, TLV_CAT_MESSAGE);
  while (offset < messageEnd) {
    offset = dissect_pbb_addressblock(tvb, pinfo, message_tree, offset, messageEnd, addressType, addressSize);
  }
  return offset;
}

static int dissect_pbb_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint headerLength, guint tlvIndex) {
  proto_tree *header_tree;
  proto_item *header_item;

  guint8 packet_flags = tvb_get_guint8(tvb, 0);

  static const int *flags[] = {
    &hf_packetbb_header_flags_phasseqnum,
    &hf_packetbb_header_flags_phastlv,
    NULL
  };

  header_item = proto_tree_add_item(tree, hf_packetbb_header, tvb, 0, headerLength, ENC_NA);
  header_tree = proto_item_add_subtree(header_item, ett_packetbb_header);

  /* version */
  proto_tree_add_item(header_tree, hf_packetbb_version, tvb, 0, 1, ENC_BIG_ENDIAN);

  /* flags */
  proto_tree_add_bitmask(header_tree, tvb, 0, hf_packetbb_header_flags, ett_packetbb_header_flags, flags, ENC_BIG_ENDIAN);

  /* sequence number */
  if ((packet_flags & PACKET_HEADER_HASSEQNR) != 0) {
    proto_tree_add_item(header_tree, hf_packetbb_seqnr, tvb, 1, 2, ENC_BIG_ENDIAN);
  }

  if ((packet_flags & PACKET_HEADER_HASTLV) != 0) {
    return dissect_pbb_tlvblock(tvb, pinfo, tree, tlvIndex, tvb_reported_length(tvb), 0, TLV_CAT_PACKET);
  }
  return headerLength;
}

static int dissect_packetbb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_) {

  proto_item *ti;
  proto_tree *packetbb_tree;
  guint offset;
  guint8 packet_flags;
  guint headerLength = 1;
  guint tlvIndex = 0;

  /* Make sure it's a PacketBB packet */

  /* calculate header length */
  packet_flags = tvb_get_guint8(tvb, 0);
  if ((packet_flags & PACKET_HEADER_HASSEQNR) != 0) {
    headerLength += 2;
  }
  if ((packet_flags & PACKET_HEADER_HASTLV) != 0) {
    tlvIndex = headerLength;
    headerLength += 2;
  }

  if (tvb_reported_length(tvb) < headerLength) {
    return 0;
  }
  if ((packet_flags & PACKET_HEADER_HASTLV) != 0) {
    headerLength += tvb_get_ntohs(tvb, tlvIndex);
  }
  if (tvb_reported_length(tvb) < headerLength) {
    return 0;
  }

  /* Reasonably certain it's a PacketBB packet */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "packetbb");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_packetbb, tvb, 0, -1, ENC_NA);
  packetbb_tree = proto_item_add_subtree(ti, ett_packetbb);

  offset = dissect_pbb_header(tvb, pinfo, packetbb_tree, headerLength, tlvIndex);
  while (offset < tvb_reported_length(tvb)) {
    offset = dissect_pbb_message(tvb, pinfo, packetbb_tree, offset);
  }

  return tvb_captured_length(tvb);
}

void proto_reg_handoff_packetbb(void) {
  static gboolean packetbb_prefs_initialized = FALSE;
  static dissector_handle_t packetbb_handle;
  static guint packetbb_udp_port;

  if (!packetbb_prefs_initialized) {
    packetbb_handle = create_dissector_handle(dissect_packetbb, proto_packetbb);
    packetbb_prefs_initialized = TRUE;
  }
  else {
    dissector_delete_uint("udp.port", global_packetbb_port, packetbb_handle);
  }

  packetbb_udp_port = global_packetbb_port;
  dissector_add_uint("udp.port", packetbb_udp_port, packetbb_handle);
}

void proto_register_packetbb(void) {
  /* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    { &hf_packetbb_header,
      { "Packet header", "packetbb.header",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_version,
      { "Version", "packetbb.version",
        FT_UINT8, BASE_DEC, NULL, 0xF0,
        NULL, HFILL }
    },
    { &hf_packetbb_header_flags,
      { "Flags", "packetbb.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0F,
        NULL, HFILL }
    },
    { &hf_packetbb_header_flags_phasseqnum,
      { "Has sequence number", "packetbb.flags.phasseqnum",
        FT_BOOLEAN, 8, TFS(&tfs_true_false), PACKET_HEADER_HASSEQNR,
        NULL, HFILL }
    },
    { &hf_packetbb_header_flags_phastlv,
      { "Has tlv block", "packetbb.flags.phastlv",
        FT_BOOLEAN, 8, TFS(&tfs_true_false), PACKET_HEADER_HASTLV,
        NULL, HFILL }
    },
    { &hf_packetbb_seqnr,
      { "Sequence number", "packetbb.seqnr",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_packetbb_msg,
      { "Message", "packetbb.msg",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_msgheader,
      { "Message header", "packetbb.msg.header",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_msgheader_type,
      { "Type", "packetbb.msg.type",
        FT_UINT8, BASE_DEC, VALS(msgheader_type_vals), 0,
        NULL, HFILL }
    },
    { &hf_packetbb_msgheader_flags,
      { "Flags", "packetbb.msg.flags",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_msgheader_flags_mhasorig,
      { "Has originator address", "packetbb.msg.flags.mhasorig",
        FT_BOOLEAN, 8, TFS(&tfs_true_false), MSG_HEADER_HASORIG,
        NULL, HFILL }
    },
    { &hf_packetbb_msgheader_flags_mhashoplimit,
      { "Has hoplimit", "packetbb.msg.flags.mhashoplimit",
        FT_BOOLEAN, 8, TFS(&tfs_true_false), MSG_HEADER_HASHOPLIMIT,
        NULL, HFILL }
    },
    { &hf_packetbb_msgheader_flags_mhashopcount,
      { "Has hopcount", "packetbb.msg.flags.mhashopcount",
        FT_BOOLEAN, 8, TFS(&tfs_true_false), MSG_HEADER_HASHOPCOUNT,
        NULL, HFILL }
    },
    { &hf_packetbb_msgheader_flags_mhasseqnr,
      { "Has sequence number", "packetbb.msg.flags.mhasseqnum",
        FT_BOOLEAN, 8, TFS(&tfs_true_false), MSG_HEADER_HASSEQNR,
        NULL, HFILL }
    },
    { &hf_packetbb_msgheader_addresssize,
      { "AddressSize", "packetbb.msg.addrsize",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_msgheader_size,
      { "Size", "packetbb.msg.size",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_msgheader_origaddripv4,
      { "Originator address", "packetbb.msg.origaddr4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_msgheader_origaddripv6,
      { "Originator address", "packetbb.msg.origaddr6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_msgheader_origaddrmac,
      { "Originator address", "packetbb.msg.origaddrmac",
        FT_ETHER, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_msgheader_origaddrcustom,
      { "Originator address", "packetbb.msg.origaddrcustom",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_msgheader_hoplimit,
      { "Hop limit", "packetbb.msg.hoplimit",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_msgheader_hopcount,
      { "Hop count", "packetbb.msg.hopcount",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_msgheader_seqnr,
      { "Sequence number", "packetbb.msg.seqnum",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },

    { &hf_packetbb_addr,
      { "Address block", "packetbb.msg.addr",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_addr_num,
      { "Count", "packetbb.msg.addr.num",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_addr_flags,
      { "Flags", "packetbb.msg.addr.flags",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_addr_flags_hashead,
      { "Has head", "packetbb.msg.addr.hashead",
        FT_BOOLEAN, 8, TFS(&tfs_true_false), ADDR_HASHEAD,
        NULL, HFILL }
    },
    { &hf_packetbb_addr_flags_hasfulltail,
      { "Has full tail", "packetbb.msg.addr.hasfulltail",
        FT_BOOLEAN, 8, TFS(&tfs_true_false), ADDR_HASFULLTAIL,
        NULL, HFILL }
    },
    { &hf_packetbb_addr_flags_haszerotail,
      { "Has zero tail", "packetbb.msg.addr.haszerotail",
        FT_BOOLEAN, 8, TFS(&tfs_true_false), ADDR_HASZEROTAIL,
        NULL, HFILL }
    },
    { &hf_packetbb_addr_flags_hassingleprelen,
      { "Has single prelen", "packetbb.msg.addr.hassingleprelen",
        FT_BOOLEAN, 8, TFS(&tfs_true_false), ADDR_HASSINGLEPRELEN,
        NULL, HFILL }
    },
    { &hf_packetbb_addr_flags_hasmultiprelen,
      { "Has multiple prelen", "packetbb.msg.addr.hasmultiprelen",
        FT_BOOLEAN, 8, TFS(&tfs_true_false), ADDR_HASMULTIPRELEN,
        NULL, HFILL }
    },
    { &hf_packetbb_addr_head,
      { "Head", "packetbb.msg.addr.head",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_addr_tail,
      { "Tail", "packetbb.msg.addr.tail",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_addr_value[0],
      { "Address", "packetbb.msg.addr.value4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_addr_value[1],
      { "Address", "packetbb.msg.addr.value6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_addr_value[2],
      { "Address", "packetbb.msg.addr.valuemac",
        FT_ETHER, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_addr_value[3],
      { "Address", "packetbb.msg.addr.valuecustom",
        FT_UINT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_addr_value_mid,
      { "Mid", "packetbb.msg.addr.value.mid",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_addr_value_prefix,
      { "Prefix", "packetbb.msg.addr.value.prefix",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_tlvblock,
      { "TLV block", "packetbb.tlvblock",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_tlvblock_length,
      { "Length", "packetbb.tlvblock.length",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_tlv,
      { "TLV", "packetbb.tlv",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_pkttlv_type,
      { "Type", "packetbb.pkttlv.type",
        FT_UINT8, BASE_DEC, VALS(pkttlv_type_vals), 0,
        NULL, HFILL }
    },
    { &hf_packetbb_msgtlv_type,
      { "Type", "packetbb.msgtlv.type",
        FT_UINT8, BASE_DEC, VALS(msgtlv_type_vals), 0,
        NULL, HFILL }
    },
    { &hf_packetbb_addrtlv_type,
      { "Type", "packetbb.addrtlv.type",
        FT_UINT8, BASE_DEC, VALS(addrtlv_type_vals), 0,
        NULL, HFILL }
    },
    { &hf_packetbb_tlv_flags,
      { "Flags", "packetbb.tlv.flags",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_tlv_typeext,
      { "Extended Type", "packetbb.tlv.typeext",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_tlv_flags_hastypext,
      { "Has type-ext", "packetbb.tlv.hastypeext",
        FT_BOOLEAN, 8, TFS(&tfs_true_false), TLV_HAS_TYPEEXT,
        NULL, HFILL }
    },
    { &hf_packetbb_tlv_flags_hassingleindex,
      { "Has single index", "packetbb.tlv.hassingleindex",
        FT_BOOLEAN, 8, TFS(&tfs_true_false), TLV_HAS_SINGLEINDEX,
        NULL, HFILL }
    },
    { &hf_packetbb_tlv_flags_hasmultiindex,
      { "Has multiple indices", "packetbb.tlv.hasmultiindex",
        FT_BOOLEAN, 8, TFS(&tfs_true_false), TLV_HAS_MULTIINDEX,
        NULL, HFILL }
    },
    { &hf_packetbb_tlv_flags_hasvalue,
      { "Has value", "packetbb.tlv.hasvalue",
        FT_BOOLEAN, 8, TFS(&tfs_true_false), TLV_HAS_VALUE,
        NULL, HFILL }
    },
    { &hf_packetbb_tlv_flags_hasextlen,
      { "Has extended length", "packetbb.tlv.hasextlen",
        FT_BOOLEAN, 8, TFS(&tfs_true_false), TLV_HAS_EXTLEN,
        NULL, HFILL }
    },
    { &hf_packetbb_tlv_flags_hasmultivalue,
      { "Has multiple values", "packetbb.tlv.hasmultivalue",
        FT_BOOLEAN, 8, TFS(&tfs_true_false), TLV_HAS_MULTIVALUE,
        NULL, HFILL }
    },
    { &hf_packetbb_tlv_indexstart,
      { "Index start", "packetbb.tlv.indexstart",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_tlv_indexend,
      { "Index end", "packetbb.tlv.indexend",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_tlv_length,
      { "Length", "packetbb.tlv.length",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_tlv_value,
      { "Value", "packetbb.tlv.value",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_packetbb_tlv_multivalue,
      { "Multivalue", "packetbb.tlv.multivalue",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    }
  };

  /* Setup protocol subtree array */
  gint *ett_base[] = {
    &ett_packetbb,
    &ett_packetbb_header,
    &ett_packetbb_header_flags,
    &ett_packetbb_msgheader,
    &ett_packetbb_msgheader_flags,
    &ett_packetbb_addr,
    &ett_packetbb_addr_flags,
    &ett_packetbb_addr_value,
    &ett_packetbb_tlvblock,
    &ett_packetbb_tlv_flags,
    &ett_packetbb_tlv_value
  };

  static ei_register_info ei[] = {
    { &ei_packetbb_error, { "packetbb.error", PI_PROTOCOL, PI_WARN, "ERROR!", EXPFILL }},
  };

  static gint *ett[array_length(ett_base) + 2*PACKETBB_MSG_TLV_LENGTH];
  module_t *packetbb_module;
  expert_module_t* expert_packetbb;
  int i,j;

  memcpy(ett, ett_base, sizeof(ett_base));
  j = array_length(ett_base);
  for (i=0; i<PACKETBB_MSG_TLV_LENGTH; i++) {
    ett_packetbb_msg[i] = -1;
    ett_packetbb_tlv[i] = -1;

    ett[j++] = &ett_packetbb_msg[i];
    ett[j++] = &ett_packetbb_tlv[i];
  }

  /* name, short name, abbrev */
  proto_packetbb = proto_register_protocol("PacketBB Protocol", "PacketBB",
      "packetbb");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_packetbb, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_packetbb = expert_register_protocol(proto_packetbb);
  expert_register_field_array(expert_packetbb, ei, array_length(ei));

  /* configurable packetbb port */
  packetbb_module = prefs_register_protocol(proto_packetbb, proto_reg_handoff_packetbb);
  prefs_register_uint_preference(packetbb_module, "communication_port",
      "UDP port for packetbb", "UDP communication port for packetbb PDUs",
      10, &global_packetbb_port);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
