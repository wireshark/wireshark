/* packet-nsip.c
 * Routines for Network Service Over IP dissection
 * Copyright 2000, Susanne Edlund <susanne.edlund@ericsson.com>
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

/* 3GPP TS 48.016 V 5.3.0 (2004-07) Release 6 + CR013 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>

#include <prefs.h>

#define NSIP_DEBUG 0
#define NSIP_SEP ", " /* Separator string */

static range_t *global_nsip_udp_port_range;
#define DEFAULT_NSIP_PORT_RANGE "2157,19999"

void proto_reg_handoff_nsip(void);

/* Initialize the protocol and registered fields */
static int proto_nsip = -1;

static int hf_nsip_cause = -1;
static int hf_nsip_ns_vci = -1;
static int hf_nsip_pdu_type = -1;
static int hf_nsip_bvci = -1;
static int hf_nsip_nsei = -1;
static int hf_nsip_ip4_elements = -1;
static int hf_nsip_ip6_elements = -1;
static int hf_nsip_max_num_ns_vc = -1;
static int hf_nsip_num_ip4_endpoints = -1;
static int hf_nsip_num_ip6_endpoints = -1;
static int hf_nsip_reset_flag = -1;
static int hf_nsip_reset_flag_spare = -1;
static int hf_nsip_ip_address_type = -1;
static int hf_nsip_ip_address_ipv4 = -1;
static int hf_nsip_ip_address_ipv6 = -1;
static int hf_nsip_end_flag = -1;
static int hf_nsip_end_flag_spare = -1;
static int hf_nsip_control_bits_r = -1;
static int hf_nsip_control_bits_c = -1;
static int hf_nsip_control_bits_spare = -1;
static int hf_nsip_transaction_id = -1;
static int hf_nsip_ip_element_ip_address_ipv4 = -1;
static int hf_nsip_ip_element_ip_address_ipv6 = -1;
static int hf_nsip_ip_element_udp_port = -1;
static int hf_nsip_ip_element_signalling_weight = -1;
static int hf_nsip_ip_element_data_weight = -1;


/* Initialize the subtree pointers */
static gint ett_nsip = -1;
static gint ett_nsip_control_bits = -1;
static gint ett_nsip_reset_flag = -1;
static gint ett_nsip_end_flag = -1;
static gint ett_nsip_ip_element = -1;
static gint ett_nsip_ip_element_list = -1;

/* PDU type coding, v5.3.0, table 10.3.7.1, p 51 */
#define NSIP_PDU_NS_UNITDATA        0x00
#define NSIP_PDU_NS_RESET           0x02
#define NSIP_PDU_NS_RESET_ACK       0x03
#define NSIP_PDU_NS_BLOCK           0x04
#define NSIP_PDU_NS_BLOCK_ACK       0x05
#define NSIP_PDU_NS_UNBLOCK         0x06
#define NSIP_PDU_NS_UNBLOCK_ACK     0x07
#define NSIP_PDU_NS_STATUS          0x08
#define NSIP_PDU_NS_ALIVE           0x0a
#define NSIP_PDU_NS_ALIVE_ACK       0x0b
#define NSIP_PDU_SNS_ACK            0x0c
#define NSIP_PDU_SNS_ADD            0x0d
#define NSIP_PDU_SNS_CHANGEWEIGHT   0x0e
#define NSIP_PDU_SNS_CONFIG         0x0f
#define NSIP_PDU_SNS_CONFIG_ACK     0x10
#define NSIP_PDU_SNS_DELETE         0x11
#define NSIP_PDU_SNS_SIZE           0x12
#define NSIP_PDU_SNS_SIZE_ACK       0x13

static const value_string tab_nsip_pdu_types[] = {
  { NSIP_PDU_NS_UNITDATA,        "NS_UNITDATA" },
  { NSIP_PDU_NS_RESET,           "NS_RESET" },
  { NSIP_PDU_NS_RESET_ACK,       "NS_RESET_ACK" },
  { NSIP_PDU_NS_BLOCK,           "NS_BLOCK" },
  { NSIP_PDU_NS_BLOCK_ACK,       "NS_BLOCK_ACK" },
  { NSIP_PDU_NS_UNBLOCK,         "NS_UNBLOCK" },
  { NSIP_PDU_NS_UNBLOCK_ACK,     "NS_UNBLOCK_ACK" },
  { NSIP_PDU_NS_STATUS,          "NS_STATUS" },
  { NSIP_PDU_NS_ALIVE,           "NS_ALIVE" },
  { NSIP_PDU_NS_ALIVE_ACK,       "NS_ALIVE_ACK" },
  { NSIP_PDU_SNS_ACK,            "SNS_ACK" },
  { NSIP_PDU_SNS_ADD,            "SNS_ADD" },
  { NSIP_PDU_SNS_CHANGEWEIGHT,   "SNS_CHANGEWEIGHT" },
  { NSIP_PDU_SNS_CONFIG,         "SNS_CONFIG" },
  { NSIP_PDU_SNS_CONFIG_ACK,     "SNS_CONFIG_ACK" },
  { NSIP_PDU_SNS_DELETE,         "SNS_DELETE" },
  { NSIP_PDU_SNS_SIZE,           "SNS_SIZE" },
  { NSIP_PDU_SNS_SIZE_ACK,       "SNS_SIZE_ACK" },
  { 0,                            NULL },
};

/* Information element coding, v 5.3.0, table 10.3.1, p 46 */
#define NSIP_IE_CAUSE              0x00
#define NSIP_IE_NS_VCI             0x01
#define NSIP_IE_NS_PDU             0x02
#define NSIP_IE_BVCI               0x03
#define NSIP_IE_NSEI               0x04
#define NSIP_IE_IP4_ELEMENTS       0x05
#define NSIP_IE_IP6_ELEMENTS       0x06
#define NSIP_IE_MAX_NUM_NS_VC      0x07
#define NSIP_IE_NUM_IP4_ENDPOINTS  0x08
#define NSIP_IE_NUM_IP6_ENDPOINTS  0x09
#define NSIP_IE_RESET_FLAG         0x0a
#define NSIP_IE_IP_ADDRESS         0x0b

static const value_string tab_nsip_ieis[] = {
  { NSIP_IE_CAUSE,               "Cause" },
  { NSIP_IE_NS_VCI,              "NS-VCI" },
  { NSIP_IE_NS_PDU,              "NS PDU" },
  { NSIP_IE_BVCI,                "BVCI" },
  { NSIP_IE_NSEI,                "NSEI" },
  { NSIP_IE_IP4_ELEMENTS,        "List of IP4 Elements" },
  { NSIP_IE_IP6_ELEMENTS,        "List of IP6 Elements" },
  { NSIP_IE_MAX_NUM_NS_VC,       "Maximum Number of NC-VCs" },
  { NSIP_IE_NUM_IP4_ENDPOINTS,   "Number of IP4 Endpoints" },
  { NSIP_IE_NUM_IP6_ENDPOINTS,   "Number of IP6 Endpoints"},
  { NSIP_IE_RESET_FLAG,          "Reset Flag" },
  { NSIP_IE_IP_ADDRESS,          "IP Address" },
  { 0,                            NULL },
};

/* Cause values, v 5.3.0, table 10.3.2.1, p 47 */
#define NSIP_CAUSE_TRANSIT_NETWORK_FAILURE      0x00
#define NSIP_CAUSE_OM_INTERVENTION              0x01
#define NSIP_CAUSE_EQUIPMENT_FAILURE            0x02
#define NSIP_CAUSE_NS_VC_BLOCKED                0x03
#define NSIP_CAUSE_NS_VC_UNKNOWN                0x04
#define NSIP_CAUSE_BVCI_UNKNOWN                 0x05
#define NSIP_CAUSE_SEMANTICALLY_INCORRECT_PDU   0x08
#define NSIP_CAUSE_NSIP_PDU_NOT_COMPATIBLE      0x0a
#define NSIP_CAUSE_PROTOCOL_ERROR               0x0b
#define NSIP_CAUSE_INVALID_ESSENTIAL_IE         0x0c
#define NSIP_CAUSE_MISSING_ESSENTIAL_IE         0x0d
#define NSIP_CAUSE_INVALID_NUM_IP4_ENDPOINTS    0x0e
#define NSIP_CAUSE_INVALID_NUM_IP6_ENDPOINTS    0x0f
#define NSIP_CAUSE_INVALID_NUM_NS_VC            0x10
#define NSIP_CAUSE_INVALID_WEIGHTS              0x11
#define NSIP_CAUSE_UNKNOWN_IP_ENDPOINT          0x12
#define NSIP_CAUSE_UNKNOWN_IP_ADDRESS           0x13
#define NSIP_CAUSE_IP_TEST_FAILED               0x14

static const value_string tab_nsip_cause_values[] = {
  { NSIP_CAUSE_TRANSIT_NETWORK_FAILURE,   "Transit network failure" },
  { NSIP_CAUSE_OM_INTERVENTION,           "O&M intervention" },
  { NSIP_CAUSE_EQUIPMENT_FAILURE,         "Equipment failure" },
  { NSIP_CAUSE_NS_VC_BLOCKED,             "NS-VC blocked" },
  { NSIP_CAUSE_NS_VC_UNKNOWN,             "NS-VC unknown" },
  { NSIP_CAUSE_BVCI_UNKNOWN,              "BVCI unknown on that NSE" },
  { NSIP_CAUSE_SEMANTICALLY_INCORRECT_PDU, "Semantically incorrect PDU" },
  { NSIP_CAUSE_NSIP_PDU_NOT_COMPATIBLE,   "PDU not compatible with the protocol state" },
  { NSIP_CAUSE_PROTOCOL_ERROR,            "Protocol error - unspecified" },
  { NSIP_CAUSE_INVALID_ESSENTIAL_IE,      "Invalid essential IE" },
  { NSIP_CAUSE_MISSING_ESSENTIAL_IE,      "Missing essential IE" },
  { NSIP_CAUSE_INVALID_NUM_IP4_ENDPOINTS, "Invalid number of IP4 endpoints" },
  { NSIP_CAUSE_INVALID_NUM_IP6_ENDPOINTS, "Invalid number of IP6 endpoints" },
  { NSIP_CAUSE_INVALID_NUM_NS_VC,         "Invalid number of NS-VCs" },
  { NSIP_CAUSE_INVALID_WEIGHTS,           "Invalid weights" },
  { NSIP_CAUSE_UNKNOWN_IP_ENDPOINT,       "Unknown IP endpoint" },
  { NSIP_CAUSE_UNKNOWN_IP_ADDRESS,        "Unknown IP address" },
  { NSIP_CAUSE_IP_TEST_FAILED,            "IP test failed" },
  { 0,                                     NULL },
};

/* Presence requirements of Information Elements
   v 5.3.0, chapter 8.1.1, p. 35 */
#define NSIP_IE_PRESENCE_M 1   /* Mandatory */
#define NSIP_IE_PRESENCE_O 2   /* Conditional */
#define NSIP_IE_PRESENCE_C 3   /* Optional */

/* Format options */
#define NSIP_IE_FORMAT_V 1
#define NSIP_IE_FORMAT_TV 2
#define NSIP_IE_FORMAT_TLV 3

/* IP address types, v 5.3.0, chapter 10.3.2b, p. 48 */
#define NSIP_IP_ADDRESS_TYPE_IPV4 1
#define NSIP_IP_ADDRESS_TYPE_IPV6 2
#define NSIP_IP_VERSION_4 4
#define NSIP_IP_VERSION_6 6

static const value_string ip_address_type_vals[] = {
  { 0,                         "Reserved" },
  { NSIP_IP_ADDRESS_TYPE_IPV4, "IPv4 Address" },
  { NSIP_IP_ADDRESS_TYPE_IPV6, "IPv6 Address" },
  { 0,                            NULL },
};


#define NSIP_MASK_CONTROL_BITS_R 0x01
#define NSIP_MASK_CONTROL_BITS_C 0x02
#define NSIP_MASK_CONTROL_BITS_SPARE 0xFC
#define NSIP_MASK_END_FLAG 0x01
#define NSIP_MASK_END_FLAG_SPARE 0xFE
#define NSIP_MASK_RESET_FLAG 0x01
#define NSIP_MASK_RESET_FLAG_SPARE 0xFE

static dissector_handle_t bssgp_handle;
static dissector_handle_t nsip_handle;

typedef struct {
  guint8        iei;
  guint8        presence_req;
  int           format;
  guint16       value_length; /* in bytes */
  guint16       total_length; /* as specified, or 0 if unspecified */
} nsip_ie_t;

typedef struct {
  tvbuff_t     *tvb;
  int           offset;
  packet_info  *pinfo;
  proto_tree   *nsip_tree;
  proto_tree   *parent_tree;
  proto_item   *ti;
} build_info_t;

typedef struct {
  int version;
  int address_length;
  int total_length;
} nsip_ip_element_info_t;

static nsip_ip_element_info_t ipv4_element = { NSIP_IP_VERSION_4, 4, 8 };
static nsip_ip_element_info_t ipv6_element = { NSIP_IP_VERSION_6, 16, 20 };

static void
get_value_length(nsip_ie_t *ie, build_info_t *bi) {
  /* length indicator in bit 8, 0 => two bytes, 1 => one byte */
  const guint8 MASK_LENGTH_INDICATOR = 0x80;
  const guint8 MASK_ONE_BYTE_LENGTH = 0x7f;
  guint8 length_len;
  guint16 length;

  length = tvb_get_guint8(bi->tvb, bi->offset);
  length_len = 1;

  if (length & MASK_LENGTH_INDICATOR) {
    length &= MASK_ONE_BYTE_LENGTH;
  }
  else {
    length_len++;
    length <<= 8;
    length |= tvb_get_guint8(bi->tvb, bi->offset+1);
  }
  ie->value_length = length;
  ie->total_length += length_len + length;
  bi->offset += length_len;
}

static int
check_correct_iei(nsip_ie_t *ie, build_info_t *bi) {
  guint8 fetched_iei = tvb_get_guint8(bi->tvb, bi->offset);

#if NSIP_DEBUG
  if (fetched_iei != ie->iei) {
    proto_tree_add_text(bi->nsip_tree, bi->tvb, bi->offset, 1,
                        "Tried IEI %s (%#02x), found IEI %s (%#02x)",
                        val_to_str(ie->iei, tab_nsip_ieis, "Unknown"),
                        ie->iei,
                        val_to_str(fetched_iei, tab_nsip_ieis, "Unknown"),
                        fetched_iei);
  }
#endif
  return (fetched_iei == ie->iei);
}

static void
decode_iei_cause(nsip_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  guint8 cause;

  if (bi->nsip_tree) {
    cause = tvb_get_guint8(bi->tvb, bi->offset);
    proto_tree_add_uint_format(bi->nsip_tree, hf_nsip_cause,
                               bi->tvb, ie_start_offset, ie->total_length,
                               cause,
                               "Cause: %s (%#02x)",
                               val_to_str(cause, tab_nsip_cause_values,
                                          "Unknown"), cause);
    if (check_col(bi->pinfo->cinfo, COL_INFO)) {
        col_append_sep_fstr(bi->pinfo->cinfo, COL_INFO, NSIP_SEP,
            "Cause: %s",
            val_to_str(cause, tab_nsip_cause_values, "Unknown (0x%02x)"));
    }
    proto_item_append_text(bi->ti, ", Cause: %s",
            val_to_str(cause, tab_nsip_cause_values, "Unknown (0x%02x)"));
  }
  bi->offset += ie->value_length;
}

static void
decode_iei_ns_vci(nsip_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  guint16 ns_vci;

  if (bi->nsip_tree) {
    ns_vci = tvb_get_ntohs(bi->tvb, bi->offset);

    proto_tree_add_uint_format(bi->nsip_tree, hf_nsip_ns_vci,
                               bi->tvb, ie_start_offset, ie->total_length,
                               ns_vci,
                               "NS VCI: %#04x", ns_vci);
    if (check_col(bi->pinfo->cinfo, COL_INFO)) {
        col_append_sep_fstr(bi->pinfo->cinfo, COL_INFO, NSIP_SEP,
            "NS VCI: %#04x", ns_vci);
    }
    proto_item_append_text(bi->ti, ", NS VCI: %#04x", ns_vci);
  }
  bi->offset += ie->value_length;
}

static void
decode_iei_ns_pdu(nsip_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  tvbuff_t * next_tvb;

  if (bi->nsip_tree) {
    proto_tree_add_text(bi->nsip_tree, bi->tvb, ie_start_offset,
                        ie->total_length,
                        "NS PDU (%u bytes)", ie->value_length);
  }
  next_tvb = tvb_new_subset(bi->tvb, bi->offset, ie->value_length, -1);
  if (nsip_handle) {
    call_dissector(nsip_handle, next_tvb, bi->pinfo, bi->nsip_tree);
  }
  else {
    bi->offset += ie->value_length;
  }
}

static void
decode_iei_nsei(nsip_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  guint16 nsei = tvb_get_ntohs(bi->tvb, bi->offset);

  if (bi->nsip_tree) {
    proto_tree_add_uint(bi->nsip_tree, hf_nsip_nsei, bi->tvb,
                        ie_start_offset, ie->total_length, nsei);
  }
  bi->offset += ie->value_length;

  if (check_col(bi->pinfo->cinfo, COL_INFO)) {
    col_append_sep_fstr(bi->pinfo->cinfo, COL_INFO, NSIP_SEP,
                        "NSEI %u", nsei);
  }
  proto_item_append_text(bi->ti, ", NSEI %u", nsei);
}

static void
decode_iei_bvci(nsip_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  guint16 bvci = tvb_get_ntohs(bi->tvb, bi->offset);

  if (bi->nsip_tree) {
    proto_tree_add_uint(bi->nsip_tree, hf_nsip_bvci, bi->tvb,
                        ie_start_offset, ie->total_length, bvci);
  }
  bi->offset += ie->value_length;

  if (check_col(bi->pinfo->cinfo, COL_INFO)) {
    col_append_sep_fstr(bi->pinfo->cinfo, COL_INFO, NSIP_SEP,
                        "BVCI %u", bvci);
  }
  proto_item_append_text(bi->ti, ", BVCI %u", bvci);
}

static proto_item *
decode_ip_element(nsip_ip_element_info_t *element, build_info_t *bi, proto_tree * element_tree) {
  guint16 udp_port;
  guint32 ip4_addr;
  struct e_in6_addr ip6_addr;
  proto_item *tf = NULL;
  proto_tree *field_tree = NULL;

  if (bi->nsip_tree) {
    tf = proto_tree_add_text(element_tree, bi->tvb, bi->offset,
                             element->total_length, "IP Element");
    field_tree = proto_item_add_subtree(tf, ett_nsip_ip_element);

    /* IP address */
    switch (element->version) {
    case NSIP_IP_VERSION_4:
      ip4_addr = tvb_get_ipv4(bi->tvb, bi->offset);
      proto_tree_add_item(field_tree, hf_nsip_ip_address_ipv4,
                          bi->tvb, bi->offset, element->address_length,
                          ENC_BIG_ENDIAN);
      proto_item_append_text(tf, ": IP address: %s",
                             ip_to_str((guint8 *)&ip4_addr));

      break;
    case NSIP_IP_VERSION_6:
      tvb_get_ipv6(bi->tvb, bi->offset, &ip6_addr);
      proto_tree_add_item(field_tree, hf_nsip_ip_address_ipv6, bi->tvb,
                          bi->offset, element->address_length,
                          ENC_NA);
      proto_item_append_text(tf, ": IP address: %s",
                             ip6_to_str((struct e_in6_addr *)&ip6_addr));
      break;
    default:
      ;
    }
  }
  bi->offset += element->address_length;

  if (bi->nsip_tree) {
    /* UDP port value */
    udp_port = tvb_get_ntohs(bi->tvb, bi->offset);
    proto_tree_add_uint_format(field_tree, hf_nsip_ip_element_udp_port,
                               bi->tvb, bi->offset, 2, udp_port,
                               "UDP Port: %u", udp_port);
    proto_item_append_text(tf, ", UDP Port: %u", udp_port);
  }
  bi->offset += 2;

  if (bi->nsip_tree) {
    /* Signalling weight */
    proto_tree_add_item(field_tree, hf_nsip_ip_element_signalling_weight,
                        bi->tvb, bi->offset, 1, ENC_BIG_ENDIAN);
  }
  bi->offset++;

  if (bi->nsip_tree) {
    /* Data weight */
    proto_tree_add_item(field_tree, hf_nsip_ip_element_data_weight,
                        bi->tvb, bi->offset, 1, ENC_BIG_ENDIAN);
  }
  bi->offset++;
  return tf;
}

static proto_item *
decode_ip_elements(nsip_ip_element_info_t *element, nsip_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  int i;
  int num_elements = ie->value_length / element->total_length;
  proto_item *tf;
  proto_tree *field_tree;

  tf = proto_tree_add_text(bi->nsip_tree, bi->tvb, ie_start_offset,
                           ie->total_length,
                           "List of IP%u Elements (%u Elements)",
                           element->version, num_elements);
  field_tree = proto_item_add_subtree(tf, ett_nsip_ip_element_list);

  for (i = 0; i < num_elements; i++) {
    decode_ip_element(element, bi, field_tree);
  }
  return tf;
}

static void
decode_iei_max_num_ns_vc(nsip_ie_t *ie, build_info_t *bi, int ie_start_offset) {
 guint16 num_ns_vc;

 if (bi->nsip_tree) {
   num_ns_vc = tvb_get_ntohs(bi->tvb, bi->offset);

   proto_tree_add_uint_format(bi->nsip_tree, hf_nsip_max_num_ns_vc,
                              bi->tvb, ie_start_offset, ie->total_length,
                              num_ns_vc,
                              "Maximum Number of NS-VCs: %u", num_ns_vc);
 }
 bi->offset += 2;
}

static void
decode_iei_num_ip4_endpoints(nsip_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  guint16 num_endpoints;

  if (bi->nsip_tree) {
    num_endpoints = tvb_get_ntohs(bi->tvb, bi->offset);

    proto_tree_add_uint_format(bi->nsip_tree, hf_nsip_num_ip4_endpoints,
                               bi->tvb, ie_start_offset, ie->total_length,
                               num_endpoints,
                               "Number of IP4 Endpoints: %u", num_endpoints);
  }
  bi->offset += 2;
}

static void
decode_iei_num_ip6_endpoints(nsip_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  guint16 num_endpoints;

  if (bi->nsip_tree) {
    num_endpoints = tvb_get_ntohs(bi->tvb, bi->offset);

    proto_tree_add_uint_format(bi->nsip_tree, hf_nsip_num_ip6_endpoints,
                               bi->tvb, ie_start_offset, ie->total_length,
                               num_endpoints,
                               "Number of IP6 Endpoints: %u", num_endpoints);
  }
  bi->offset += 2;
}

static void
decode_iei_reset_flag(nsip_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  guint8 flag;
  proto_item *tf;
  proto_tree *field_tree;

  flag = tvb_get_guint8(bi->tvb, bi->offset);
  if (bi->nsip_tree) {

     tf = proto_tree_add_text(bi->nsip_tree, bi->tvb, ie_start_offset,
                 ie->total_length,
                 "Reset Flag: %#02x", flag);

     field_tree = proto_item_add_subtree(tf, ett_nsip_reset_flag);
     proto_tree_add_boolean(field_tree, hf_nsip_reset_flag, bi->tvb,
                           bi->offset, 1,
                           flag & NSIP_MASK_RESET_FLAG);
     if (flag & NSIP_MASK_RESET_FLAG) {
         if (check_col(bi->pinfo->cinfo, COL_INFO)) {
           col_append_sep_fstr(bi->pinfo->cinfo, COL_INFO, NSIP_SEP,
                   "Reset");
         }
         proto_item_append_text(bi->ti, ", Reset");
     }
     proto_tree_add_uint(field_tree, hf_nsip_reset_flag_spare,
                           bi->tvb, bi->offset, 1,
                           flag & NSIP_MASK_RESET_FLAG_SPARE);
  }
  bi->offset += 1;
}

static void
decode_iei_ip_address(nsip_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  guint8 addr_type;
  guint32 ip4_addr;
  struct e_in6_addr ip6_addr;

  addr_type = tvb_get_guint8(bi->tvb, bi->offset);
  proto_tree_add_item(bi->nsip_tree, hf_nsip_ip_address_type,
                          bi->tvb, bi->offset, 1, ENC_BIG_ENDIAN);
  switch (addr_type) {
  case NSIP_IP_ADDRESS_TYPE_IPV4:
    ie->total_length = 2 + ipv4_element.address_length;
    ip4_addr = tvb_get_ipv4(bi->tvb, bi->offset+1);
    if (bi->nsip_tree) {
      proto_tree_add_ipv4(bi->nsip_tree, hf_nsip_ip_address_ipv4,
                          bi->tvb, ie_start_offset, ie->total_length,
                          ip4_addr);
    }
    break;
  case NSIP_IP_ADDRESS_TYPE_IPV6:
    ie->total_length = 2 + ipv6_element.address_length;
    tvb_get_ipv6(bi->tvb, bi->offset+1, &ip6_addr);
    if (bi->nsip_tree) {
      proto_tree_add_ipv6(bi->nsip_tree, hf_nsip_ip_address_ipv4,
                          bi->tvb, ie_start_offset, ie->total_length,
                          (guint8 *)&ip6_addr);
    }
    break;
  default:
    return; /* error */
  }
  bi->offset += ie->value_length;
}

static void
decode_iei_transaction_id(nsip_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  guint8 id;
  if (bi->nsip_tree) {
    id = tvb_get_guint8(bi->tvb, bi->offset);
    proto_tree_add_uint(bi->nsip_tree, hf_nsip_transaction_id,
                        bi->tvb, ie_start_offset, ie->total_length, id);
    if (check_col(bi->pinfo->cinfo, COL_INFO)) {
      col_append_sep_fstr(bi->pinfo->cinfo, COL_INFO, NSIP_SEP,
              "Transaction Id: %d", id);
    }
  }
 bi->offset += 1;
}

static void
decode_iei_end_flag(nsip_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  guint8 flag;
  proto_item *tf;
  proto_tree *field_tree;

  if (bi->nsip_tree) {
      flag = tvb_get_guint8(bi->tvb, bi->offset);

      tf = proto_tree_add_text(bi->nsip_tree, bi->tvb, ie_start_offset,
                     ie->total_length,
                     "End Flag: %#02x", flag);

      field_tree = proto_item_add_subtree(tf, ett_nsip_end_flag);
      proto_tree_add_boolean(field_tree, hf_nsip_end_flag, bi->tvb,
                           bi->offset, 1,
                           flag & NSIP_MASK_END_FLAG);
      if (flag & NSIP_MASK_END_FLAG) {
          proto_item_append_text(bi->ti, ", End");
      }
      proto_tree_add_uint(field_tree, hf_nsip_end_flag_spare,
                           bi->tvb, bi->offset, 1,
                           flag & NSIP_MASK_END_FLAG_SPARE);
  }
  bi->offset += 1;
}

static void
decode_iei_control_bits(nsip_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  guint8 control_bits;
  proto_item *tf;
  proto_tree *field_tree;

  control_bits = tvb_get_guint8(bi->tvb, bi->offset);

  if (bi->nsip_tree) {
    tf = proto_tree_add_text(bi->nsip_tree, bi->tvb, ie_start_offset,
                             ie->total_length,
                             "NS SDU Control bits: %#02x", control_bits);

    field_tree = proto_item_add_subtree(tf, ett_nsip_control_bits);
    proto_tree_add_boolean(field_tree, hf_nsip_control_bits_r, bi->tvb,
                           bi->offset, 1,
                           control_bits & NSIP_MASK_CONTROL_BITS_R);
    proto_tree_add_boolean(field_tree, hf_nsip_control_bits_c, bi->tvb,
                           bi->offset, 1,
                           control_bits & NSIP_MASK_CONTROL_BITS_C);
    proto_tree_add_uint(field_tree, hf_nsip_control_bits_spare,
                           bi->tvb, bi->offset, 1,
                           control_bits & NSIP_MASK_CONTROL_BITS_SPARE);
  }
  bi->offset++;

  if (check_col(bi->pinfo->cinfo, COL_INFO)) {
    if (control_bits & NSIP_MASK_CONTROL_BITS_R) {
      col_append_sep_str(bi->pinfo->cinfo, COL_INFO, NSIP_SEP, "Req CF");
      proto_item_append_text(bi->ti, ", Request Change Flow");
    }

    if (control_bits & NSIP_MASK_CONTROL_BITS_C) {
      col_append_sep_str(bi->pinfo->cinfo, COL_INFO, NSIP_SEP, "Conf CF");
      proto_item_append_text(bi->ti, ", Confirm Change Flow");
    }
  }
}


static void
decode_ie(nsip_ie_t *ie, build_info_t *bi) {

  int org_offset = bi->offset;

  if (tvb_length_remaining(bi->tvb, bi->offset) < 1) {
    return;
  }
  switch (ie->format) {
  case NSIP_IE_FORMAT_TLV:
    if (!check_correct_iei(ie, bi)) {
      return;
    }
    bi->offset++; /* Account for type */
    ie->total_length = 1;
    get_value_length(ie, bi);
    break;
  case NSIP_IE_FORMAT_TV:
    if (!check_correct_iei(ie, bi)) {
      return;
    }
    bi->offset++; /* Account for type */
    ie->value_length = ie->total_length - 1;
    break;
  case NSIP_IE_FORMAT_V:
    ie->value_length = ie->total_length;
  default:
    ;
  }
  switch (ie->iei) {
  case NSIP_IE_CAUSE:
    decode_iei_cause(ie, bi, org_offset);
    break;
  case NSIP_IE_NS_VCI:
    decode_iei_ns_vci(ie, bi, org_offset);
    break;
  case NSIP_IE_NS_PDU:
    decode_iei_ns_pdu(ie, bi, org_offset);
    break;
  case NSIP_IE_NSEI:
    decode_iei_nsei(ie, bi, org_offset);
    break;
  case NSIP_IE_BVCI:
    decode_iei_bvci(ie, bi, org_offset);
    break;
  case NSIP_IE_IP4_ELEMENTS:
    decode_ip_elements(&ipv4_element, ie, bi, org_offset);
    break;
  case NSIP_IE_IP6_ELEMENTS:
    decode_ip_elements(&ipv6_element, ie, bi, org_offset);
    break;
  case NSIP_IE_MAX_NUM_NS_VC:
    decode_iei_max_num_ns_vc(ie, bi, org_offset);
    break;
  case NSIP_IE_NUM_IP4_ENDPOINTS:
    decode_iei_num_ip4_endpoints(ie, bi, org_offset);
    break;
  case NSIP_IE_NUM_IP6_ENDPOINTS:
    decode_iei_num_ip6_endpoints(ie, bi, org_offset);
    break;
  case NSIP_IE_RESET_FLAG:
    decode_iei_reset_flag(ie, bi, org_offset);
    break;
  case NSIP_IE_IP_ADDRESS:
    decode_iei_ip_address(ie, bi, org_offset);
    break;
  default:
    ;
  }
}

static void
decode_pdu_general(nsip_ie_t *ies, int num_ies, build_info_t *bi) {
  int i;
  for (i = 0; i < num_ies; i++) {
    decode_ie(&ies[i], bi);
  }
}

static void
decode_pdu_ns_unitdata(build_info_t *bi) {
  tvbuff_t *next_tvb;

  nsip_ie_t ies[] = {
    { 0, NSIP_IE_PRESENCE_M, NSIP_IE_FORMAT_V, 0, 1 }, /* Control bits */
    { NSIP_IE_BVCI, NSIP_IE_PRESENCE_M, NSIP_IE_FORMAT_V, 0, 2 },
    { 0, NSIP_IE_PRESENCE_M, NSIP_IE_FORMAT_V, 0, 0 },
    /* NS SDU, length unknown */
  };
  gint sdu_length;

  decode_iei_control_bits(ies, bi, bi->offset);
  decode_pdu_general(&ies[1], 1, bi);

  next_tvb = tvb_new_subset_remaining(bi->tvb, bi->offset);
  if (bssgp_handle) {
    call_dissector(bssgp_handle, next_tvb, bi->pinfo, bi->parent_tree);
  }
  else {
    sdu_length = tvb_length_remaining(bi->tvb, bi->offset);
    proto_tree_add_text(bi->nsip_tree, bi->tvb, bi->offset, sdu_length,
                        "NS SDU (%u bytes)", sdu_length);
  }
}

static void
decode_pdu_ns_reset(build_info_t *bi) {
  nsip_ie_t ies[] = {
    { NSIP_IE_CAUSE, NSIP_IE_PRESENCE_M, NSIP_IE_FORMAT_TLV, 0, 3 },
    { NSIP_IE_NS_VCI, NSIP_IE_PRESENCE_M, NSIP_IE_FORMAT_TLV, 0, 4 },
    { NSIP_IE_NSEI, NSIP_IE_PRESENCE_M, NSIP_IE_FORMAT_TLV, 0, 4 },
  };
  decode_pdu_general(ies, 3, bi);
}

static void
decode_pdu_ns_reset_ack(build_info_t *bi) {
  nsip_ie_t ies[] = {
    { NSIP_IE_NS_VCI, NSIP_IE_PRESENCE_M, NSIP_IE_FORMAT_TLV, 0, 4 },
    { NSIP_IE_NSEI, NSIP_IE_PRESENCE_M, NSIP_IE_FORMAT_TLV, 0, 4 },
  };
  decode_pdu_general(ies, 2, bi);
}

static void
decode_pdu_ns_block(build_info_t *bi) {
  nsip_ie_t ies[] = {
    { NSIP_IE_CAUSE, NSIP_IE_PRESENCE_M, NSIP_IE_FORMAT_TLV, 0, 3 },
    { NSIP_IE_NS_VCI, NSIP_IE_PRESENCE_M, NSIP_IE_FORMAT_TLV, 0, 4 },
  };
  decode_pdu_general(ies, 2, bi);
}

static void
decode_pdu_ns_block_ack(build_info_t *bi) {
  nsip_ie_t ies[] = { { NSIP_IE_NS_VCI, NSIP_IE_PRESENCE_M, NSIP_IE_FORMAT_TLV,
                        0, 1 }, };
  decode_pdu_general(ies, 1, bi);
}

static void
decode_pdu_ns_status(build_info_t *bi) {
  nsip_ie_t ies[] = {
    { NSIP_IE_CAUSE, NSIP_IE_PRESENCE_M, NSIP_IE_FORMAT_TLV, 0, 3 },
    { NSIP_IE_NS_VCI, NSIP_IE_PRESENCE_M, NSIP_IE_FORMAT_TLV, 0, 4 },
    { NSIP_IE_NS_PDU, NSIP_IE_PRESENCE_C, NSIP_IE_FORMAT_TLV, 0, 0 },
    /* Unknown length */
    { NSIP_IE_BVCI, NSIP_IE_PRESENCE_C, NSIP_IE_FORMAT_TLV, 0, 4 },
    { NSIP_IE_IP4_ELEMENTS, NSIP_IE_PRESENCE_C, NSIP_IE_FORMAT_TLV, 0, 0 },
    /* Unknown length */
    { NSIP_IE_IP6_ELEMENTS, NSIP_IE_PRESENCE_C, NSIP_IE_FORMAT_TLV, 0, 0 },
    /* Unknown length */
  };
  decode_pdu_general(ies, 6, bi);
}

static void
decode_pdu_sns_ack(build_info_t *bi) {
  nsip_ie_t ies[] = {
    { NSIP_IE_NSEI, NSIP_IE_PRESENCE_M, NSIP_IE_FORMAT_TLV, 0, 4 },
    { 0, NSIP_IE_PRESENCE_M, NSIP_IE_FORMAT_V, 0, 1 }, /* Transaction id */
    { NSIP_IE_CAUSE, NSIP_IE_PRESENCE_C, NSIP_IE_FORMAT_TLV, 0, 3 },
    { NSIP_IE_IP_ADDRESS, NSIP_IE_PRESENCE_C, NSIP_IE_FORMAT_TV, 0, 0 },
    /* Unknown length */
    { NSIP_IE_IP4_ELEMENTS, NSIP_IE_PRESENCE_C, NSIP_IE_FORMAT_TLV, 0, 0 },
    { NSIP_IE_IP6_ELEMENTS, NSIP_IE_PRESENCE_C, NSIP_IE_FORMAT_TLV, 0, 0 },
  };
  decode_pdu_general(ies, 1, bi);
  decode_iei_transaction_id(&ies[1], bi, bi->offset);
  decode_pdu_general(&ies[2], 4, bi);
}

static void
decode_pdu_sns_add(build_info_t *bi) {
  nsip_ie_t ies[] = {
    { NSIP_IE_NSEI, NSIP_IE_PRESENCE_M, NSIP_IE_FORMAT_TLV, 0, 4 },
    { 0, NSIP_IE_PRESENCE_M, NSIP_IE_FORMAT_V, 0, 1 }, /* Transaction id */
    { NSIP_IE_IP4_ELEMENTS, NSIP_IE_PRESENCE_C, NSIP_IE_FORMAT_TLV, 0, 0 },
    /* Unknown length */
    { NSIP_IE_IP6_ELEMENTS, NSIP_IE_PRESENCE_C, NSIP_IE_FORMAT_TLV, 0, 0 },
    /* Unknown length */
  };
  decode_pdu_general(ies, 1, bi);
  decode_iei_transaction_id(&ies[1], bi, bi->offset);
  decode_pdu_general(&ies[2], 2, bi);
}

static void
decode_pdu_sns_changeweight(build_info_t *bi) {
  nsip_ie_t ies[] = {
    { NSIP_IE_NSEI, NSIP_IE_PRESENCE_M, NSIP_IE_FORMAT_TLV, 0, 4 },
    { 0, NSIP_IE_PRESENCE_M, NSIP_IE_FORMAT_V, 0, 1 }, /* Transaction id */
    { NSIP_IE_IP4_ELEMENTS, NSIP_IE_PRESENCE_C, NSIP_IE_FORMAT_TLV, 0, 0 },
    /* Unknown length */
    { NSIP_IE_IP6_ELEMENTS, NSIP_IE_PRESENCE_C, NSIP_IE_FORMAT_TLV, 0, 0 },
    /* Unknown length */
  };
  decode_pdu_general(ies, 1, bi);
  decode_iei_transaction_id(&ies[1], bi, bi->offset);
  decode_pdu_general(&ies[2], 2, bi);
}

static void
decode_pdu_sns_config(build_info_t *bi) {

    nsip_ie_t ies[] = {
      { 0, NSIP_IE_PRESENCE_M, NSIP_IE_FORMAT_V, 0, 1 }, /* End flag */
      { NSIP_IE_NSEI, NSIP_IE_PRESENCE_M, NSIP_IE_FORMAT_TLV, 0, 4 },
      { NSIP_IE_IP4_ELEMENTS, NSIP_IE_PRESENCE_C, NSIP_IE_FORMAT_TLV, 0, 0 },
      /* Unknown length */
      { NSIP_IE_IP6_ELEMENTS, NSIP_IE_PRESENCE_C, NSIP_IE_FORMAT_TLV, 0, 0 },
      /* Unknown length */
    };
    decode_iei_end_flag(ies, bi, bi->offset);
    decode_pdu_general(&ies[1], 3, bi);
}

static void
decode_pdu_sns_config_ack(build_info_t *bi) {
  nsip_ie_t ies[] = {
    { NSIP_IE_NSEI, NSIP_IE_PRESENCE_M, NSIP_IE_FORMAT_TLV, 0, 4 },
    { NSIP_IE_CAUSE, NSIP_IE_PRESENCE_C, NSIP_IE_FORMAT_TLV, 0, 3 },
  };
  decode_pdu_general(ies, 2, bi);
}

static void
decode_pdu_sns_delete(build_info_t *bi) {
  nsip_ie_t ies[] = {
    { NSIP_IE_NSEI, NSIP_IE_PRESENCE_M, NSIP_IE_FORMAT_TLV, 0, 4}, /* CR013 */
    { 0, NSIP_IE_PRESENCE_M, NSIP_IE_FORMAT_V, 0, 1 }, /* Transaction id */
    { NSIP_IE_IP_ADDRESS, NSIP_IE_PRESENCE_C, NSIP_IE_FORMAT_TV, 0, 0 },
    /* Unknown length */
    { NSIP_IE_IP4_ELEMENTS, NSIP_IE_PRESENCE_C, NSIP_IE_FORMAT_TLV, 0, 0 },
    { NSIP_IE_IP6_ELEMENTS, NSIP_IE_PRESENCE_C, NSIP_IE_FORMAT_TLV, 0, 0 },
  };
  decode_pdu_general(ies, 1, bi);
  decode_iei_transaction_id(&ies[1], bi, bi->offset);
  decode_pdu_general(&ies[2], 3, bi);
}

static void
decode_pdu_sns_size(build_info_t *bi) {
  nsip_ie_t ies[] = {
    { NSIP_IE_NSEI, NSIP_IE_PRESENCE_M, NSIP_IE_FORMAT_TLV, 0, 4 },
    { NSIP_IE_RESET_FLAG, NSIP_IE_PRESENCE_M, NSIP_IE_FORMAT_TV, 0, 2 },
    { NSIP_IE_MAX_NUM_NS_VC, NSIP_IE_PRESENCE_M, NSIP_IE_FORMAT_TV, 0, 3 },
    { NSIP_IE_NUM_IP4_ENDPOINTS, NSIP_IE_PRESENCE_C, NSIP_IE_FORMAT_TV,
      0, 3 },
    { NSIP_IE_NUM_IP6_ENDPOINTS, NSIP_IE_PRESENCE_C, NSIP_IE_FORMAT_TV,
      0, 3 },
  };
  decode_pdu_general(ies, 5, bi);
}

static void
decode_pdu_sns_size_ack(build_info_t *bi) {
  nsip_ie_t ies[] = {
    { NSIP_IE_NSEI, NSIP_IE_PRESENCE_M, NSIP_IE_FORMAT_TLV, 0, 4 },
    { NSIP_IE_CAUSE, NSIP_IE_PRESENCE_C, NSIP_IE_FORMAT_TLV, 0, 3 },
  };
  decode_pdu_general(ies, 2, bi);
}

static void
decode_pdu(guint8 pdu_type, build_info_t *bi) {
  switch (pdu_type) {
  case NSIP_PDU_NS_UNITDATA:
    decode_pdu_ns_unitdata(bi);
    break;
  case NSIP_PDU_NS_RESET:
    decode_pdu_ns_reset(bi);
    break;
  case NSIP_PDU_NS_RESET_ACK:
    decode_pdu_ns_reset_ack(bi);
    break;
  case NSIP_PDU_NS_BLOCK:
    decode_pdu_ns_block(bi);
    break;
  case NSIP_PDU_NS_BLOCK_ACK:
    decode_pdu_ns_block_ack(bi);
    break;
  case NSIP_PDU_NS_STATUS:
    decode_pdu_ns_status(bi);
    break;
  case NSIP_PDU_SNS_ACK:
    decode_pdu_sns_ack(bi);
    break;
  case NSIP_PDU_SNS_ADD:
    decode_pdu_sns_add(bi);
    break;
  case NSIP_PDU_SNS_CHANGEWEIGHT:
    decode_pdu_sns_changeweight(bi);
    break;
  case NSIP_PDU_SNS_CONFIG:
    decode_pdu_sns_config(bi);
    break;
  case NSIP_PDU_SNS_CONFIG_ACK:
    decode_pdu_sns_config_ack(bi);
    break;
  case NSIP_PDU_SNS_DELETE:
    decode_pdu_sns_delete(bi);
    break;
  case NSIP_PDU_SNS_SIZE:
    decode_pdu_sns_size(bi);
    break;
  case NSIP_PDU_SNS_SIZE_ACK:
    decode_pdu_sns_size_ack(bi);
    break;
  case NSIP_PDU_NS_ALIVE:
  case NSIP_PDU_NS_ALIVE_ACK:
  case NSIP_PDU_NS_UNBLOCK:
  case NSIP_PDU_NS_UNBLOCK_ACK:
    /* Only contains PDU type, which has already been decoded */
  default: ;
  }
}

static void
dissect_nsip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  guint8 pdu_type;
  build_info_t bi = { NULL, 0, NULL, NULL, NULL, NULL };
  proto_tree *nsip_tree;

  bi.tvb = tvb;
  bi.pinfo = pinfo;
  bi.parent_tree = tree;

  pinfo->current_proto = "GPRS-NS";

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "GPRS-NS");

  col_clear(pinfo->cinfo, COL_INFO);

  pdu_type = tvb_get_guint8(tvb, 0);
  bi.offset++;

  if (tree) {
    bi.ti = proto_tree_add_item(tree, proto_nsip, tvb, 0, -1,
                             FALSE);
    nsip_tree = proto_item_add_subtree(bi.ti, ett_nsip);
    proto_tree_add_uint_format(nsip_tree, hf_nsip_pdu_type, tvb, 0, 1,
                               pdu_type,
                               "PDU type: %s (%#02x)",
                               val_to_str(pdu_type, tab_nsip_pdu_types,
                                          "Unknown"), pdu_type);
    proto_item_append_text(bi.ti, ", PDU type: %s",
                               val_to_str(pdu_type, tab_nsip_pdu_types, "Unknown"));
    bi.nsip_tree = nsip_tree;
  }

  col_add_str(pinfo->cinfo, COL_INFO,
              val_to_str(pdu_type, tab_nsip_pdu_types, "Unknown PDU type"));
  decode_pdu(pdu_type, &bi);
}

void
proto_register_nsip(void)
{
  static hf_register_info hf[] = {
    { &hf_nsip_cause,
      { "Cause", "nsip.cause",
        FT_UINT8, BASE_OCT, VALS(tab_nsip_cause_values), 0x0,
        NULL, HFILL }
    },
    { &hf_nsip_ns_vci,
      { "NS-VCI", "nsip.ns_vci",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Network Service Virtual Link Identifier", HFILL }
    },
    { &hf_nsip_pdu_type,
      { "PDU type", "nsip.pdu_type",
        FT_UINT8, BASE_OCT, VALS(tab_nsip_pdu_types), 0x0,
        "PDU type information element", HFILL }
    },
    { &hf_nsip_bvci,
      { "BVCI", "nsip.bvci",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "BSSGP Virtual Connection Identifier", HFILL }
    },
    { &hf_nsip_nsei,
      { "NSEI", "nsip.nsei",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Network Service Entity Identifier", HFILL }
    },
    { &hf_nsip_ip4_elements,
      { "IP4 elements", "nsip.ip4_elements",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "List of IP4 elements", HFILL }
    },
    { &hf_nsip_ip6_elements,
      { "IP6 elements", "nsip.ip6_elements",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "List of IP6 elements", HFILL }
    },
    { &hf_nsip_max_num_ns_vc,
      { "Maximum number of NS-VCs", "nsip.max_num_ns_vc",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nsip_num_ip4_endpoints,
      { "Number of IP4 endpoints", "nsip.num_ip4_endpoints",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nsip_num_ip6_endpoints,
      { "Number of IP6 endpoints", "nsip.num_ip6_endpoints",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nsip_reset_flag,
      { "Reset flag", "nsip.reset_flag.flag",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), NSIP_MASK_RESET_FLAG,
        NULL, HFILL }
    },
    { &hf_nsip_reset_flag_spare,
      { "Reset flag spare bits", "nsip.reset_flag.spare",
        FT_UINT8, BASE_HEX, NULL, NSIP_MASK_RESET_FLAG_SPARE,
        NULL, HFILL }
    },
    { &hf_nsip_ip_address_type,
      { "IP Address Type", "nsip.ip_address_type",
        FT_UINT8, BASE_DEC, VALS(ip_address_type_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_nsip_ip_address_ipv4,
      { "IP Address", "nsip.ipv4_address",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nsip_ip_address_ipv6,
      { "IP Address", "nsip.ipv6_address",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nsip_end_flag,
      { "End flag", "nsip.end_flag.flag",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), NSIP_MASK_END_FLAG,
        NULL, HFILL }
    },
    { &hf_nsip_end_flag_spare,
      { "End flag spare bits", "nsip.end_flag.spare",
        FT_UINT8, BASE_HEX, NULL, NSIP_MASK_END_FLAG_SPARE,
        NULL, HFILL }
    },
    { &hf_nsip_control_bits_r,
      { "Request change flow", "nsip.control_bits.r",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), NSIP_MASK_CONTROL_BITS_R,
        NULL, HFILL }
    },
    { &hf_nsip_control_bits_c,
      { "Confirm change flow", "nsip.control_bits.c",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), NSIP_MASK_CONTROL_BITS_C,
        NULL, HFILL }
    },
    { &hf_nsip_control_bits_spare,
      { "Spare bits", "nsip.control_bits.spare",
        FT_UINT8, BASE_HEX, NULL, NSIP_MASK_CONTROL_BITS_SPARE,
        NULL, HFILL }
    },
    { &hf_nsip_transaction_id,
      { "Transaction ID", "nsip.transaction_id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_nsip_ip_element_ip_address_ipv4,
      { "IP Address", "nsip.ip_element.ipv4_address",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nsip_ip_element_ip_address_ipv6,
      { "IP Address", "nsip.ip_element.ipv6_address",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nsip_ip_element_udp_port,
      { "UDP Port", "nsip.ip_element.udp_port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nsip_ip_element_signalling_weight,
      { "Signalling Weight", "nsip.ip_element.signalling_weight",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_nsip_ip_element_data_weight,
      { "Data Weight", "nsip.ip_element.data_weight",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_nsip,
    &ett_nsip_control_bits,
    &ett_nsip_reset_flag,
    &ett_nsip_end_flag,
    &ett_nsip_ip_element,
    &ett_nsip_ip_element_list,
  };

  module_t *nsip_module;

  /* Register the protocol name and description */
  proto_nsip = proto_register_protocol("GPRS Network Service",
                                       "GPRS-NS", "gprs-ns");

  /* Required function calls to register the header fields and
     subtrees used */
  proto_register_field_array(proto_nsip, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector("gprs_ns", dissect_nsip, proto_nsip);

  /* Set default UDP ports */
  range_convert_str(&global_nsip_udp_port_range, DEFAULT_NSIP_PORT_RANGE, MAX_UDP_PORT);

  /* Register configuration options */
  nsip_module = prefs_register_protocol(proto_nsip, proto_reg_handoff_nsip);
  prefs_register_obsolete_preference(nsip_module, "udp.port1");
  prefs_register_obsolete_preference(nsip_module, "udp.port2");
  prefs_register_range_preference(nsip_module, "udp.ports", "GPRS-NS UDP ports",
                                  "UDP ports to be decoded as GPRS-NS (default: "
                                  DEFAULT_NSIP_PORT_RANGE ")",
                                  &global_nsip_udp_port_range, MAX_UDP_PORT);
}

static void
range_delete_callback(guint32 port)
{
    dissector_delete_uint("udp.port", port, nsip_handle);
}

static void
range_add_callback(guint32 port)
{
    dissector_add_uint("udp.port", port, nsip_handle);
}

void
proto_reg_handoff_nsip(void) {
  static gboolean nsip_prefs_initialized = FALSE;
  static range_t *nsip_udp_port_range;

  if (!nsip_prefs_initialized) {
    nsip_handle = find_dissector("gprs_ns");
    bssgp_handle = find_dissector("bssgp");
    nsip_prefs_initialized = TRUE;
  } else {
    range_foreach(nsip_udp_port_range, range_delete_callback);
    g_free(nsip_udp_port_range);
  }

  nsip_udp_port_range = range_copy(global_nsip_udp_port_range);

  range_foreach(nsip_udp_port_range, range_add_callback);

}
