/* packet-acn.c
 * Routines for ACN packet disassembly
 *
 * Copyright (c) 2003 by Erwin Rol <erwin@erwinrol.com>
 * Copyright (c) 2006 by Electronic Theatre Controls, Inc.
 *                    Bill Florac <bflorac@etcconnect.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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

 /*
    Todo:
      Add reading of DDL files so we can futher explode DMP packets
      For some of the Set/Get properties where we have a range of data
      it would be better to show the block of data rather and
      address-data pair on each line...

      Build CID to "Name" table from file so we can display real names
      rather than CIDs
 */

/* Include files */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/to_str.h>

/* Forward declarations */
void proto_register_acn(void);
void proto_reg_handoff_acn(void);

/* pdu flags */
#define ACN_PDU_FLAG_L     0x80
#define ACN_PDU_FLAG_V     0x40
#define ACN_PDU_FLAG_H     0x20
#define ACN_PDU_FLAG_D     0x10

#define ACN_DMX_OPTION_P   0x80
#define ACN_DMX_OPTION_S   0x40

#define ACN_DMP_ADT_FLAG_V 0x80 /* V = Specifies whether address is a virtual address or not. */
#define ACN_DMP_ADT_FLAG_R 0x40 /* R = Specifies whether address is relative to last valid address in packet or not. */
#define ACN_DMP_ADT_FLAG_D 0x30 /* D1, D0 = Specify non-range or range address, single data, equal size
                                   or mixed size data array */
#define ACN_DMP_ADT_EXTRACT_D(f)        (((f) & ACN_DMP_ADT_FLAG_D) >> 4)

#define ACN_DMP_ADT_FLAG_X 0x0c /* X1, X0 = These bits are reserved and their values shall be set to 0
                                   when encoded. Their values shall be ignored when decoding. */

#define ACN_DMP_ADT_FLAG_A 0x03 /* A1, A0 = Size of Address elements */
#define ACN_DMP_ADT_EXTRACT_A(f)        ((f) & ACN_DMP_ADT_FLAG_A)

#define ACN_DMP_ADT_V_VIRTUAL   0
#define ACN_DMP_ADT_V_ACTUAL    1

#define ACN_DMP_ADT_R_ABSOLUTE  0
#define ACN_DMP_ADT_R_RELATIVE  1

#define ACN_DMP_ADT_D_NS        0
#define ACN_DMP_ADT_D_RS        1
#define ACN_DMP_ADT_D_RE        2
#define ACN_DMP_ADT_D_RM        3

#define ACN_DMP_ADT_A_1         0
#define ACN_DMP_ADT_A_2         1
#define ACN_DMP_ADT_A_4         2
#define ACN_DMP_ADT_A_R         3

#define ACN_PROTOCOL_ID_SDT           1
#define ACN_PROTOCOL_ID_DMP           2
#define ACN_PROTOCOL_ID_DMX           3
#define ACN_PROTOCOL_ID_DMX_2         4

#define ACN_ADDR_NULL                 0
#define ACN_ADDR_IPV4                 1
#define ACN_ADDR_IPV6                 2
#define ACN_ADDR_IPPORT               3

/* STD Messages */
#define ACN_SDT_VECTOR_UNKNOWN          0
#define ACN_SDT_VECTOR_REL_WRAP         1
#define ACN_SDT_VECTOR_UNREL_WRAP       2
#define ACN_SDT_VECTOR_CHANNEL_PARAMS   3
#define ACN_SDT_VECTOR_JOIN             4
#define ACN_SDT_VECTOR_JOIN_REFUSE      5
#define ACN_SDT_VECTOR_JOIN_ACCEPT      6
#define ACN_SDT_VECTOR_LEAVE            7
#define ACN_SDT_VECTOR_LEAVING          8
#define ACN_SDT_VECTOR_CONNECT          9
#define ACN_SDT_VECTOR_CONNECT_ACCEPT  10
#define ACN_SDT_VECTOR_CONNECT_REFUSE  11
#define ACN_SDT_VECTOR_DISCONNECT      12
#define ACN_SDT_VECTOR_DISCONNECTING   13
#define ACN_SDT_VECTOR_ACK             14
#define ACN_SDT_VECTOR_NAK             15
#define ACN_SDT_VECTOR_GET_SESSION     16
#define ACN_SDT_VECTOR_SESSIONS        17

#define ACN_REFUSE_CODE_NONSPECIFIC     1
#define ACN_REFUSE_CODE_ILLEGAL_PARAMS  2
#define ACN_REFUSE_CODE_LOW_RESOURCES   3
#define ACN_REFUSE_CODE_ALREADY_MEMBER  4
#define ACN_REFUSE_CODE_BAD_ADDR_TYPE   5
#define ACN_REFUSE_CODE_NO_RECIP_CHAN   6

#define ACN_REASON_CODE_NONSPECIFIC          1
/*#define ACN_REASON_CODE_                   2 */
/*#define ACN_REASON_CODE_                   3 */
/*#define ACN_REASON_CODE_                   4 */
/*#define ACN_REASON_CODE_                   5 */
#define ACN_REASON_CODE_NO_RECIP_CHAN        6
#define ACN_REASON_CODE_CHANNEL_EXPIRED      7
#define ACN_REASON_CODE_LOST_SEQUENCE        8
#define ACN_REASON_CODE_SATURATED            9
#define ACN_REASON_CODE_TRANS_ADDR_CHANGING 10
#define ACN_REASON_CODE_ASKED_TO_LEAVE      11
#define ACN_REASON_CODE_NO_RECIPIENT        12

#define ACN_DMP_VECTOR_UNKNOWN               0
#define ACN_DMP_VECTOR_GET_PROPERTY          1
#define ACN_DMP_VECTOR_SET_PROPERTY          2
#define ACN_DMP_VECTOR_GET_PROPERTY_REPLY    3
#define ACN_DMP_VECTOR_EVENT                 4
#define ACN_DMP_VECTOR_MAP_PROPERTY          5
#define ACN_DMP_VECTOR_UNMAP_PROPERTY        6
#define ACN_DMP_VECTOR_SUBSCRIBE             7
#define ACN_DMP_VECTOR_UNSUBSCRIBE           8
#define ACN_DMP_VECTOR_GET_PROPERTY_FAIL     9
#define ACN_DMP_VECTOR_SET_PROPERTY_FAIL    10
#define ACN_DMP_VECTOR_MAP_PROPERTY_FAIL    11
#define ACN_DMP_VECTOR_SUBSCRIBE_ACCEPT     12
#define ACN_DMP_VECTOR_SUBSCRIBE_REJECT     13
#define ACN_DMP_VECTOR_ALLOCATE_MAP         14
#define ACN_DMP_VECTOR_ALLOCATE_MAP_REPLY   15
#define ACN_DMP_VECTOR_DEALLOCATE_MAP       16

#define ACN_DMP_REASON_CODE_NONSPECIFIC                  1
#define ACN_DMP_REASON_CODE_NOT_A_PROPERTY               2
#define ACN_DMP_REASON_CODE_WRITE_ONLY                   3
#define ACN_DMP_REASON_CODE_NOT_WRITABLE                 4
#define ACN_DMP_REASON_CODE_DATA_ERROR                   5
#define ACN_DMP_REASON_CODE_MAPS_NOT_SUPPORTED           6
#define ACN_DMP_REASON_CODE_SPACE_NOT_AVAILABLE          7
#define ACN_DMP_REASON_CODE_PROP_NOT_MAPPABLE            8
#define ACN_DMP_REASON_CODE_MAP_NOT_ALLOCATED            9
#define ACN_DMP_REASON_CODE_SUBSCRIPTION_NOT_SUPPORTED  10
#define ACN_DMP_REASON_CODE_NO_SUBSCRIPTIONS_SUPPORTED  11

#define ACN_DMX_VECTOR      2

#define ACN_PREF_DMX_DISPLAY_HEX  0
#define ACN_PREF_DMX_DISPLAY_DEC  1
#define ACN_PREF_DMX_DISPLAY_PER  2

#define ACN_PREF_DMX_DISPLAY_20PL 0
#define ACN_PREF_DMX_DISPLAY_16PL 1

typedef struct
{
  guint32 start;
  guint32 vector;
  guint32 header;
  guint32 data;
  guint32 data_length;
} acn_pdu_offsets;

typedef struct
{
  guint8  flags;
  guint32 address;  /* or first address */
  guint32 increment;
  guint32 count;
  guint32 size;
  guint32 data_length;
} acn_dmp_adt_type;

/*
 * See
 * ANSI BSR E1.17 Architecture for Control Networks
 * ANSI BSR E1.31
 */

#define ACTUAL_ADDRESS  0
/* forward reference */
static guint32 acn_add_address(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, const char *label);
static int     dissect_acn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Global variables */
static int proto_acn = -1;
static gint ett_acn = -1;
static gint ett_acn_channel_owner_info_block = -1;
static gint ett_acn_channel_member_info_block = -1;
static gint ett_acn_channel_parameter = -1;
static gint ett_acn_address = -1;
static gint ett_acn_address_type = -1;
static gint ett_acn_pdu_flags = -1;
static gint ett_acn_dmp_pdu = -1;
static gint ett_acn_sdt_pdu = -1;
static gint ett_acn_sdt_client_pdu = -1;
static gint ett_acn_sdt_base_pdu = -1;
static gint ett_acn_root_pdu = -1;
static gint ett_acn_dmx_address = -1;
static gint ett_acn_dmx_2_options = -1;
static gint ett_acn_dmx_data_pdu = -1;
static gint ett_acn_dmx_pdu = -1;

/*  Register fields */
/* In alphabetical order */
static int hf_acn_association = -1;
static int hf_acn_channel_number = -1;
static int hf_acn_cid = -1;
/* static int hf_acn_client_protocol_id = -1; */
static int hf_acn_data = -1;
static int hf_acn_data8 = -1;
static int hf_acn_data16 = -1;
static int hf_acn_data24 = -1;
static int hf_acn_data32 = -1;
/* static int hf_acn_dmp_adt = -1; */ /* address and data type*/
static int hf_acn_dmp_adt_a = -1;
static int hf_acn_dmp_adt_v = -1;
static int hf_acn_dmp_adt_r = -1;
static int hf_acn_dmp_adt_d = -1;
static int hf_acn_dmp_adt_x = -1;
static int hf_acn_dmp_reason_code = -1;
static int hf_acn_dmp_vector = -1;
static int hf_acn_dmp_actual_address = -1;
static int hf_acn_dmp_virtual_address = -1;
static int hf_acn_dmp_actual_address_first = -1;
static int hf_acn_dmp_virtual_address_first = -1;
static int hf_acn_expiry = -1;
static int hf_acn_first_memeber_to_ack = -1;
static int hf_acn_first_missed_sequence = -1;
static int hf_acn_ip_address_type = -1;
static int hf_acn_ipv4 = -1;
static int hf_acn_ipv6 = -1;
static int hf_acn_last_memeber_to_ack = -1;
static int hf_acn_last_missed_sequence = -1;
static int hf_acn_mak_threshold = -1;
static int hf_acn_member_id = -1;
static int hf_acn_nak_holdoff = -1;
static int hf_acn_nak_max_wait = -1;
static int hf_acn_nak_modulus = -1;
static int hf_acn_nak_outbound_flag = -1;
static int hf_acn_oldest_available_wrapper = -1;
static int hf_acn_packet_identifier = -1;
static int hf_acn_pdu = -1;
static int hf_acn_pdu_flag_d = -1;
static int hf_acn_pdu_flag_h = -1;
static int hf_acn_pdu_flag_l = -1;
static int hf_acn_pdu_flag_v = -1;
static int hf_acn_pdu_flags = -1;
static int hf_acn_pdu_length = -1;
static int hf_acn_port = -1;
static int hf_acn_postamble_size = -1;
static int hf_acn_preamble_size = -1;
static int hf_acn_protocol_id = -1;
static int hf_acn_reason_code = -1;
static int hf_acn_reciprocal_channel = -1;
static int hf_acn_refuse_code = -1;
static int hf_acn_reliable_sequence_number = -1;
static int hf_acn_adhoc_expiry = -1;
/* static int hf_acn_sdt_pdu = -1; */
static int hf_acn_sdt_vector = -1;
static int hf_acn_dmx_vector = -1;
/* static int hf_acn_session_count = -1; */
static int hf_acn_total_sequence_number = -1;
static int hf_acn_dmx_source_name = -1;
static int hf_acn_dmx_priority = -1;
static int hf_acn_dmx_2_reserved = -1;
static int hf_acn_dmx_sequence_number = -1;
static int hf_acn_dmx_2_options = -1;
static int hf_acn_dmx_2_option_p = -1;
static int hf_acn_dmx_2_option_s = -1;
static int hf_acn_dmx_universe = -1;

static int hf_acn_dmx_start_code = -1;
static int hf_acn_dmx_2_first_property_address = -1;
static int hf_acn_dmx_increment = -1;
static int hf_acn_dmx_count = -1;
static int hf_acn_dmx_2_start_code = -1;
static int hf_acn_dmx_data = -1;

/* static int hf_acn_dmx_dmp_vector = -1; */

/* Try heuristic ACN decode */
static gboolean global_acn_dmx_enable = FALSE;
static gint     global_acn_dmx_display_view = 0;
static gint     global_acn_dmx_display_line_format = 0;
static gboolean global_acn_dmx_display_zeros = FALSE;
static gboolean global_acn_dmx_display_leading_zeros = FALSE;


static const value_string acn_protocol_id_vals[] = {
  { ACN_PROTOCOL_ID_SDT, "SDT Protocol" },
  { ACN_PROTOCOL_ID_DMP, "DMP Protocol" },
  { ACN_PROTOCOL_ID_DMX, "DMX Protocol" },
  { ACN_PROTOCOL_ID_DMX_2, "Ratified DMX Protocol" },
  { 0,       NULL },
};

static const value_string acn_dmp_adt_r_vals[] = {
  { 0, "Relative" },
  { 1, "Absolute" },
  { 0,       NULL },
};

static const value_string acn_dmp_adt_v_vals[] = {
  { 0, "Actual" },
  { 1, "Virtual" },
  { 0,       NULL },
};

static const value_string acn_dmp_adt_d_vals[] = {
  { ACN_DMP_ADT_D_NS, "Non-range, single data item" },
  { ACN_DMP_ADT_D_RS, "Range, single data item" },
  { ACN_DMP_ADT_D_RE, "Range, array of equal size data items" },
  { ACN_DMP_ADT_D_RM, "Range, series of mixed size data items" },
  { 0,       NULL },
};

static const value_string acn_dmp_adt_a_vals[] = {
  { ACN_DMP_ADT_A_1, "1 octet" },
  { ACN_DMP_ADT_A_2, "2 octets" },
  { ACN_DMP_ADT_A_4, "4 octets" },
  { ACN_DMP_ADT_A_R, "reserved" },
  { 0,       NULL },
};


static const value_string acn_sdt_vector_vals[] = {
  {ACN_SDT_VECTOR_UNKNOWN,        "Unknown"},
  {ACN_SDT_VECTOR_REL_WRAP,       "Reliable Wrapper"},
  {ACN_SDT_VECTOR_UNREL_WRAP,     "Unreliable Wrapper"},
  {ACN_SDT_VECTOR_CHANNEL_PARAMS, "Channel Parameters"},
  {ACN_SDT_VECTOR_JOIN,           "Join"},
  {ACN_SDT_VECTOR_JOIN_REFUSE,    "Join Refuse"},
  {ACN_SDT_VECTOR_JOIN_ACCEPT,    "Join Accept"},
  {ACN_SDT_VECTOR_LEAVE,          "Leave"},
  {ACN_SDT_VECTOR_LEAVING,        "Leaving"},
  {ACN_SDT_VECTOR_CONNECT,        "Connect"},
  {ACN_SDT_VECTOR_CONNECT_ACCEPT, "Connect Accept"},
  {ACN_SDT_VECTOR_CONNECT_REFUSE, "Connect Refuse"},
  {ACN_SDT_VECTOR_DISCONNECT,     "Disconnect"},
  {ACN_SDT_VECTOR_DISCONNECTING,  "Disconnecting"},
  {ACN_SDT_VECTOR_ACK,            "Ack"},
  {ACN_SDT_VECTOR_NAK,            "Nak"},
  {ACN_SDT_VECTOR_GET_SESSION,    "Get Session"},
  {ACN_SDT_VECTOR_SESSIONS,       "Sessions"},
  { 0,       NULL },
};

static const value_string acn_dmx_vector_vals[] = {
  {ACN_DMX_VECTOR,  "Streaming DMX"},
  { 0,       NULL },
};

static const value_string acn_dmp_vector_vals[] = {
  {ACN_DMP_VECTOR_UNKNOWN,            "Unknown"},
  {ACN_DMP_VECTOR_GET_PROPERTY,       "Get Property"},
  {ACN_DMP_VECTOR_SET_PROPERTY,       "Set Property"},
  {ACN_DMP_VECTOR_GET_PROPERTY_REPLY, "Get property reply"},
  {ACN_DMP_VECTOR_EVENT,              "Event"},
  {ACN_DMP_VECTOR_MAP_PROPERTY,       "Map Property"},
  {ACN_DMP_VECTOR_UNMAP_PROPERTY,     "Unmap Property"},
  {ACN_DMP_VECTOR_SUBSCRIBE,          "Subscribe"},
  {ACN_DMP_VECTOR_UNSUBSCRIBE,        "Unsubscribe"},
  {ACN_DMP_VECTOR_GET_PROPERTY_FAIL,  "Get Property Fail"},
  {ACN_DMP_VECTOR_SET_PROPERTY_FAIL,  "Set Property Fail"},
  {ACN_DMP_VECTOR_MAP_PROPERTY_FAIL,  "Map Property Fail"},
  {ACN_DMP_VECTOR_SUBSCRIBE_ACCEPT,   "Subscribe Accept"},
  {ACN_DMP_VECTOR_SUBSCRIBE_REJECT,   "Subscribe Reject"},
  {ACN_DMP_VECTOR_ALLOCATE_MAP,       "Allocate Map"},
  {ACN_DMP_VECTOR_ALLOCATE_MAP_REPLY, "Allocate Map Reply"},
  {ACN_DMP_VECTOR_DEALLOCATE_MAP,     "Deallocate Map"},
  { 0,       NULL },
};

static const value_string acn_ip_address_type_vals[] = {
  { ACN_ADDR_NULL,   "Null"},
  { ACN_ADDR_IPV4,   "IPv4"},
  { ACN_ADDR_IPV6,   "IPv6"},
  { ACN_ADDR_IPPORT, "Port"},
  { 0,       NULL },
};

static const value_string acn_refuse_code_vals[] = {
  { ACN_REFUSE_CODE_NONSPECIFIC,    "Nonspecific" },
  { ACN_REFUSE_CODE_ILLEGAL_PARAMS, "Illegal Parameters" },
  { ACN_REFUSE_CODE_LOW_RESOURCES,  "Low Resources" },
  { ACN_REFUSE_CODE_ALREADY_MEMBER, "Already Member" },
  { ACN_REFUSE_CODE_BAD_ADDR_TYPE,  "Bad Address Type" },
  { ACN_REFUSE_CODE_NO_RECIP_CHAN,  "No Reciprocal Channel" },
  { 0,       NULL },
};

static const value_string acn_reason_code_vals[] = {
  { ACN_REASON_CODE_NONSPECIFIC,         "Nonspecific" },
  { ACN_REASON_CODE_NO_RECIP_CHAN,       "No Reciprocal Channel" },
  { ACN_REASON_CODE_CHANNEL_EXPIRED,     "Channel Expired" },
  { ACN_REASON_CODE_LOST_SEQUENCE,       "Lost Sequence" },
  { ACN_REASON_CODE_SATURATED,           "Saturated" },
  { ACN_REASON_CODE_TRANS_ADDR_CHANGING, "Transport Address Changing" },
  { ACN_REASON_CODE_ASKED_TO_LEAVE,      "Asked to Leave" },
  { ACN_REASON_CODE_NO_RECIPIENT,        "No Recipient"},
  { 0,       NULL },
};

static const value_string acn_dmp_reason_code_vals[] = {
  { ACN_DMP_REASON_CODE_NONSPECIFIC,                "Nonspecific" },
  { ACN_DMP_REASON_CODE_NOT_A_PROPERTY,             "Not a Property" },
  { ACN_DMP_REASON_CODE_WRITE_ONLY,                 "Write Only" },
  { ACN_DMP_REASON_CODE_NOT_WRITABLE,               "Not Writable" },
  { ACN_DMP_REASON_CODE_DATA_ERROR,                 "Data Error" },
  { ACN_DMP_REASON_CODE_MAPS_NOT_SUPPORTED,         "Maps not Supported" },
  { ACN_DMP_REASON_CODE_SPACE_NOT_AVAILABLE,        "Space not Available" },
  { ACN_DMP_REASON_CODE_PROP_NOT_MAPPABLE,          "Property not Mappable"},
  { ACN_DMP_REASON_CODE_MAP_NOT_ALLOCATED,          "Map not Allocated"},
  { ACN_DMP_REASON_CODE_SUBSCRIPTION_NOT_SUPPORTED, "Subscription not Supported"},
  { ACN_DMP_REASON_CODE_NO_SUBSCRIPTIONS_SUPPORTED, "No Subscriptions Supported"},
  { 0,       NULL },
};

static const enum_val_t dmx_display_view[] = {
  { "hex"    , "Hex    ",     ACN_PREF_DMX_DISPLAY_HEX  },
  { "decimal", "Decimal",     ACN_PREF_DMX_DISPLAY_DEC  },
  { "percent", "Percent",     ACN_PREF_DMX_DISPLAY_PER  },
  { NULL, NULL, 0 }
};

static const enum_val_t dmx_display_line_format[] = {
  { "20 per line", "20 per line",     ACN_PREF_DMX_DISPLAY_20PL  },
  { "16 per line", "16 per line",     ACN_PREF_DMX_DISPLAY_16PL  },
  { NULL, NULL, 0 }
};

/******************************************************************************/
/* Test to see if it is an ACN Packet                                         */
static gboolean
is_acn(tvbuff_t *tvb)
{
  static const char acn_packet_id[] = "ASC-E1.17\0\0\0";  /* must be 12 bytes */

  if (tvb_captured_length(tvb) < (4+sizeof(acn_packet_id)))
    return FALSE;

  /* Check the bytes in octets 4 - 16 */
  if (tvb_memeql(tvb, 4, acn_packet_id, sizeof(acn_packet_id)-1) != 0)
    return FALSE;

  return TRUE;
}


/******************************************************************************/
/* Heuristic dissector                                                        */
static gboolean
dissect_acn_heur( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_ )
{
  /* This is a heuristic dissector, which means we get all the UDP
   * traffic not sent to a known dissector and not claimed by
   * a heuristic dissector called before us!
   */

  /* abort if it is NOT an ACN packet */
  if (!is_acn(tvb)) return FALSE;

  /* else, dissect it */
  dissect_acn(tvb, pinfo, tree);
  return TRUE;
}

/******************************************************************************/
/*  Adds tree branch for channel owner info block                             */
static guint32
acn_add_channel_owner_info_block(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  proto_item *pi;
  proto_tree *this_tree;
  guint32     session_count;
  guint32     x;

  this_tree = proto_tree_add_subtree(tree, tvb, offset, 8, ett_acn_channel_owner_info_block, NULL,
                                    "Channel Owner Info Block");

  proto_tree_add_item(this_tree, hf_acn_member_id, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(this_tree, hf_acn_channel_number, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  offset += acn_add_address(tvb, pinfo, this_tree, offset, "Destination Address:");
  offset += acn_add_address(tvb, pinfo, this_tree, offset, "Source Address:");

  session_count = tvb_get_ntohs(tvb, offset);
  for (x=0; x<session_count; x++) {
    pi = proto_tree_add_item(this_tree, hf_acn_protocol_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_item_append_text(pi, " #%d",  x+1);
    offset += 4;
  }
  return offset;
}

/******************************************************************************/
/*  Adds tree branch for channel member info block                            */
static guint32
acn_add_channel_member_info_block(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  proto_item *pi;
  proto_tree *this_tree;
  guint32     session_count;
  guint32     x;

  this_tree = proto_tree_add_subtree(tree, tvb, offset, 8, ett_acn_channel_member_info_block,
                                NULL, "Channel Member Info Block");

  proto_tree_add_item(this_tree, hf_acn_member_id, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(this_tree, hf_acn_cid, tvb, offset, 16, ENC_BIG_ENDIAN);
  offset += 16;
  proto_tree_add_item(this_tree, hf_acn_channel_number, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  offset += acn_add_address(tvb, pinfo, this_tree, offset, "Destination Address:");
  offset += acn_add_address(tvb, pinfo, this_tree, offset, "Source Address:");
  proto_tree_add_item(this_tree, hf_acn_reciprocal_channel, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  session_count = tvb_get_ntohs(tvb, offset);
  for (x=0; x<session_count; x++) {
    pi = proto_tree_add_item(this_tree, hf_acn_protocol_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_item_append_text(pi, " #%d",  x+1);
    offset += 4;
  }
  return offset;
}


/******************************************************************************/
/* Add labeled expiry                                                         */
static guint32
acn_add_expiry(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, int hf)
{
  proto_tree_add_item(tree, hf, tvb, offset, 2, ENC_NA);
  offset += 1;
  return offset;
}


/******************************************************************************/
/*  Adds tree branch for channel parameters                                   */
static guint32
acn_add_channel_parameter(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
  proto_tree *param_tree;

  param_tree = proto_tree_add_subtree(tree, tvb, offset, 8, ett_acn_channel_parameter,
                            NULL, "Channel Parameter Block");

  proto_tree_add_item(param_tree, hf_acn_expiry, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  proto_tree_add_item(param_tree, hf_acn_nak_outbound_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  proto_tree_add_item(param_tree, hf_acn_nak_holdoff, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(param_tree, hf_acn_nak_modulus, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(param_tree, hf_acn_nak_max_wait, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  return offset; /* bytes used */
}


/******************************************************************************/
/* Add an address tree                                                        */
static guint32
acn_add_address(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, const char *label)
{
  proto_item *pi;
  proto_tree *addr_tree = NULL;
  guint8      ip_address_type;
  guint32     port;

  /* Get type */
  ip_address_type = tvb_get_guint8(tvb, offset);

  switch (ip_address_type) {
    case ACN_ADDR_NULL:
      proto_tree_add_item(tree, hf_acn_ip_address_type, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset    += 1;
      break;
    case ACN_ADDR_IPV4:
      /* Build tree and add type*/
      addr_tree = proto_tree_add_subtree(tree, tvb, offset, 7, ett_acn_address, &pi, label);
      proto_tree_add_item(addr_tree, hf_acn_ip_address_type, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset    += 1;
      /* Add port */
      port       = tvb_get_ntohs(tvb, offset);
      proto_tree_add_item(addr_tree, hf_acn_port, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset    += 2;
      /* Add Address */
      proto_tree_add_item(addr_tree, hf_acn_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
      /* Append port and address to tree item */
      proto_item_append_text(pi, " %s, Port %d", tvb_address_to_str(wmem_packet_scope(), tvb, AT_IPv4, offset), port);
      offset    += 4;
      break;
    case ACN_ADDR_IPV6:
      /* Build tree and add type*/
      addr_tree = proto_tree_add_subtree(tree, tvb, offset, 19, ett_acn_address, &pi, label);
      proto_tree_add_item(addr_tree, hf_acn_ip_address_type, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset    += 1;
      /* Add port */
      port       = tvb_get_ntohs(tvb, offset);
      proto_tree_add_item(addr_tree, hf_acn_port, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset    += 2;
      /* Add Address */
      proto_tree_add_item(addr_tree, hf_acn_ipv6, tvb, offset, 16, ENC_NA);
      /* Append port and address to tree item */
      proto_item_append_text(pi, " %s, Port %d", tvb_address_to_str(wmem_packet_scope(), tvb, AT_IPv6, offset), port);
      offset    += 16;
      break;
    case ACN_ADDR_IPPORT:
      /* Build tree and add type*/
      addr_tree = proto_tree_add_subtree(tree, tvb, offset, 3, ett_acn_address, &pi, label);
      proto_tree_add_item(addr_tree, hf_acn_ip_address_type, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset    += 1;
      /* Add port */
      port       = tvb_get_ntohs(tvb, offset);
      proto_tree_add_item(addr_tree, hf_acn_port, tvb, offset, 2, ENC_BIG_ENDIAN);
      /* Append port to tree item */
      proto_item_append_text(pi, " Port %d", port);
      offset    += 2;
      break;
  }
  return offset;
}

/******************************************************************************/
/*  Adds tree branch for address type                             */
static guint32
acn_add_dmp_address_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, acn_dmp_adt_type *adt)
{
  proto_tree  *this_tree;
  guint8       D;
  const gchar *name;

    /* header contains address and data type */
  adt->flags = tvb_get_guint8(tvb, offset);

  D = ACN_DMP_ADT_EXTRACT_D(adt->flags);
  name = val_to_str(D, acn_dmp_adt_d_vals, "not valid (%d)");
  this_tree = proto_tree_add_subtree_format(tree, tvb, offset, 1, ett_acn_address_type,
                                NULL, "Address and Data Type: %s", name);

  proto_tree_add_uint(this_tree, hf_acn_dmp_adt_v, tvb, offset, 1, adt->flags);
  proto_tree_add_uint(this_tree, hf_acn_dmp_adt_r, tvb, offset, 1, adt->flags);
  proto_tree_add_uint(this_tree, hf_acn_dmp_adt_d, tvb, offset, 1, adt->flags);
  proto_tree_add_uint(this_tree, hf_acn_dmp_adt_x, tvb, offset, 1, adt->flags);
  proto_tree_add_uint(this_tree, hf_acn_dmp_adt_a, tvb, offset, 1, adt->flags);
  offset += 1;

  return offset; /* bytes used */
}

/******************************************************************************/
/* Add an dmp address                                                         */
static guint32
acn_add_dmp_address(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, acn_dmp_adt_type *adt)
{
  guint32 start_offset;
  guint32 bytes_used;
  guint8  D, A;

  start_offset = offset;

  D = ACN_DMP_ADT_EXTRACT_D(adt->flags);
  A = ACN_DMP_ADT_EXTRACT_A(adt->flags);

  switch (D) {
    case ACN_DMP_ADT_D_NS:      /* Non-range address, Single data item */
      adt->increment    = 1;
      adt->count        = 1;
      switch (A) {              /* address */
        case ACN_DMP_ADT_A_1:   /* One octet address, (range: one octet address, increment, and count). */
          adt->address  = tvb_get_guint8(tvb, offset);
          offset       += 1;
          bytes_used    = 1;
          break;
        case ACN_DMP_ADT_A_2:   /* Two octet address, (range: two octet address, increment, and count). */
          adt->address  = tvb_get_ntohs(tvb, offset);
          offset       += 2;
          bytes_used    = 2;
          break;
        case ACN_DMP_ADT_A_4:   /* Four octet address, (range: one octet address, increment, and count). */
          adt->address  = tvb_get_ntohl(tvb, offset);
          offset       += 4;
          bytes_used    = 4;
          break;
        default:                /* and ACN_DMP_ADT_A_R (Four octet address, (range: four octet address, increment, and count)*/
          return offset;
      }                         /* of switch (A)  */

      if (adt->flags & ACN_DMP_ADT_FLAG_V) {
        proto_tree_add_uint(tree, hf_acn_dmp_virtual_address, tvb, start_offset, bytes_used, adt->address);
      } else {
        proto_tree_add_uint(tree, hf_acn_dmp_actual_address, tvb, start_offset, bytes_used, adt->address);
      }
      break;

    case ACN_DMP_ADT_D_RS:      /* Range address, Single data item */
      switch (A) {
        case ACN_DMP_ADT_A_1:   /* One octet address, (range: one octet address, increment, and count). */
          adt->address    = tvb_get_guint8(tvb, offset);
          offset         += 1;
          adt->increment  = tvb_get_guint8(tvb, offset);
          offset         += 1;
          adt->count      = tvb_get_guint8(tvb, offset);
          offset         += 1;
          bytes_used      = 3;
          break;
        case ACN_DMP_ADT_A_2:   /* Two octet address, (range: two octet address, increment, and count). */
          adt->address    = tvb_get_ntohs(tvb, offset);
          offset         += 2;
          adt->increment  = tvb_get_ntohs(tvb, offset);
          offset         += 2;
          adt->count      = tvb_get_ntohs(tvb, offset);
          offset         += 2;
          bytes_used      = 6;
          break;
        case ACN_DMP_ADT_A_4:   /* Four octet address, (range: four octet address, increment, and count). */
          adt->address    = tvb_get_ntohl(tvb, offset);
          offset         += 4;
          adt->increment  = tvb_get_ntohl(tvb, offset);
          offset         += 4;
          adt->count      = tvb_get_ntohl(tvb, offset);
          offset         += 4;
          bytes_used      = 12;
          break;
        default:                /* and ACN_DMP_ADT_A_R, this reserved....so it has no meaning yet */
          return offset;
      }                         /* of switch (A)  */

      if (adt->flags & ACN_DMP_ADT_FLAG_V) {
        proto_tree_add_uint_format_value(tree, hf_acn_dmp_virtual_address_first, tvb, start_offset, bytes_used,
                            adt->address, "0x%X, inc: %d, count: %d",
                            adt->address, adt->increment, adt->count);
      } else {
        proto_tree_add_uint_format_value(tree, hf_acn_dmp_actual_address_first, tvb, start_offset, bytes_used,
                            adt->address, "0x%X, inc: %d, count: %d",
                            adt->address, adt->increment, adt->count);
      }
      break;

    case ACN_DMP_ADT_D_RE:      /* Range address, Array of equal size data items */
      switch (A) {
        case ACN_DMP_ADT_A_1:   /* One octet address, (range: one octet address, increment, and count). */
          adt->address    = tvb_get_guint8(tvb, offset);
          offset         += 1;
          adt->increment  = tvb_get_guint8(tvb, offset);
          offset         += 1;
          adt->count      = tvb_get_guint8(tvb, offset);
          offset         += 1;
          bytes_used      = 3;
          break;
        case ACN_DMP_ADT_A_2:   /* Two octet address, (range: two octet address, increment, and count). */
          adt->address    = tvb_get_ntohs(tvb, offset);
          offset         += 2;
          adt->increment  = tvb_get_ntohs(tvb, offset);
          offset         += 2;
          adt->count      = tvb_get_ntohs(tvb, offset);
          offset         += 2;
          bytes_used      = 6;
          break;
        case ACN_DMP_ADT_A_4:   /* Four octet address, (range: four octet address, increment, and count). */
          adt->address    = tvb_get_ntohl(tvb, offset);
          offset         += 4;
          adt->increment  = tvb_get_ntohl(tvb, offset);
          offset         += 4;
          adt->count      = tvb_get_ntohl(tvb, offset);
          offset         += 4;
          bytes_used      = 12;
          break;
        default:                /* and ACN_DMP_ADT_A_R, this reserved....so it has no meaning yet */
          return offset;
      }                         /* of switch (A)  */

      if (adt->flags & ACN_DMP_ADT_FLAG_V) {
        proto_tree_add_uint_format_value(tree, hf_acn_dmp_virtual_address_first, tvb, start_offset, bytes_used,
                            adt->address, "0x%X, inc: %d, count: %d",
                            adt->address, adt->increment, adt->count);
      } else {
        proto_tree_add_uint_format_value(tree, hf_acn_dmp_actual_address_first, tvb, start_offset, bytes_used,
                            adt->address, "0x%X, inc: %d, count: %d",
                            adt->address, adt->increment, adt->count);
      }
      break;

    case ACN_DMP_ADT_D_RM: /* Range address, Series of mixed size data items */
      switch (A) {
        case ACN_DMP_ADT_A_1: /* One octet address, (range: one octet address, increment, and count). */
          adt->address =   tvb_get_guint8(tvb, offset);
          offset += 1;
          adt->increment =   tvb_get_guint8(tvb, offset);
          offset += 1;
          adt->count =   tvb_get_guint8(tvb, offset);
          offset += 1;
          bytes_used = 3;
          break;
        case ACN_DMP_ADT_A_2: /* Two octet address, (range: two octet address, increment, and count). */
          adt->address =   tvb_get_ntohs(tvb, offset);
          offset += 2;
          adt->increment =   tvb_get_ntohs(tvb, offset);
          offset += 2;
          adt->count =   tvb_get_ntohs(tvb, offset);
          offset += 2;
          bytes_used = 6;
          break;
        case ACN_DMP_ADT_A_4: /* Four octet address, (range: four octet address, increment, and count). */
          adt->address =   tvb_get_ntohl(tvb, offset);
          offset += 4;
          adt->increment =   tvb_get_ntohl(tvb, offset);
          offset += 4;
          adt->count =   tvb_get_ntohl(tvb, offset);
          offset += 4;
          bytes_used = 12;
          break;
        default: /* and ACN_DMP_ADT_A_R, this reserved....so it has no meaning yet */
          return offset;
      } /* of switch (A)  */

      if (adt->flags & ACN_DMP_ADT_FLAG_V) {
        proto_tree_add_uint_format_value(tree, hf_acn_dmp_virtual_address_first, tvb, start_offset, bytes_used,
                            adt->address, "0x%X, inc: %d, count: %d",
                            adt->address, adt->increment, adt->count);
      } else {
        proto_tree_add_uint_format_value(tree, hf_acn_dmp_actual_address_first, tvb, start_offset, bytes_used,
                            adt->address, "0x%X, inc: %d, count: %d",
                            adt->address, adt->increment, adt->count);
      }
      break;
  } /* of switch (D) */

  return offset;
}


/*******************************************************************************/
/* Display DMP Data                                                            */
#define BUFFER_SIZE 128
static guint32
acn_add_dmp_data(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, acn_dmp_adt_type *adt)
{
  guint8      D, A;
  guint32     data_size;
  guint32     data_value;
  guint32     data_address;
  guint32     x,y;
  gchar       buffer[BUFFER_SIZE];
  proto_item *ti;
  guint32     ok_to_process = FALSE;

  buffer[0] = 0;

  /* We would like to rip through Property Address-Data pairs                 */
  /* but since we don't now how many there are nor how big the data size is,  */
  /* it not possible. So, we just show the whole thing as a block of date!    */
  /*                                                                          */
  /* There are a few exceptions however                                       */
  /* 1) if the address type is ACN_DMP_ADT_D_NS or ACN_DMP_ADT_D_RS and       */
  /*    or ACN_DMP_ADT_D_RE                                                   */
  /*    then number of bytes is <= count + 4. Each value is at least one byte */
  /*    and another address/data pair is at least 4 bytes so if the remaining */
  /*    bytes is less than the count plus 4 then the remaining data           */
  /*    must be all data                                                      */
  /*                                                                          */
  /* 2) if the address type is ACN_DMP_ADT_D_RE and the number of bytes       */
  /*    equals the number of bytes in remaining in the pdu then there is      */
  /*    a 1 to one match                                                      */

  D = ACN_DMP_ADT_EXTRACT_D(adt->flags);
  switch (D) {
    case ACN_DMP_ADT_D_NS:
    case ACN_DMP_ADT_D_RS:
      if (adt->data_length <= adt->count + 4) {
        ok_to_process = TRUE;
      }
      break;
    case ACN_DMP_ADT_D_RE:
      if (adt->count == 0) {
        break;
      }
      if (adt->data_length <= adt->count + 4) {
        ok_to_process = TRUE;
      }
      break;
  }

  if (!ok_to_process) {
    data_size  = adt->data_length;
    ti         = proto_tree_add_item(tree, hf_acn_data, tvb, offset, data_size, ENC_NA);
    offset    += data_size;
    proto_item_set_text(ti, "Data and more Address-Data Pairs (further dissection not possible)");
    return offset;
  }

  A = ACN_DMP_ADT_EXTRACT_A(adt->flags);

  switch (D) {
    case ACN_DMP_ADT_D_NS:      /* Non-range address, Single data item */
      /* calculate data size */
      data_size    = adt->data_length;
      data_address = adt->address;

      switch (A) {
        case ACN_DMP_ADT_A_1: /* One octet address, (range: one octet address, increment, and count). */
          g_snprintf(buffer, BUFFER_SIZE, "Addr 0x%2.2X ->", data_address);
          break;
        case ACN_DMP_ADT_A_2: /* Two octet address, (range: two octet address, increment, and count). */
          g_snprintf(buffer, BUFFER_SIZE, "Addr 0x%4.4X ->", data_address);
          break;
        case ACN_DMP_ADT_A_4: /* Four octet address, (range: four octet address, increment, and count). */
          g_snprintf(buffer, BUFFER_SIZE, "Addr 0x%8.8X ->", data_address);
          break;
        default: /* and ACN_DMP_ADT_A_R, this reserved....so it has no meaning yet */
          offset += data_size;
          return offset;
      }

      switch (data_size) {
        case 1:
          data_value = tvb_get_guint8(tvb, offset);
          proto_tree_add_uint_format(tree, hf_acn_data8, tvb, offset, 1, data_value, "%s %2.2X", buffer, data_value);
          break;
        case 2:
          data_value = tvb_get_ntohs(tvb, offset);
          proto_tree_add_uint_format(tree, hf_acn_data16, tvb, offset, 2, data_value, "%s %4.4X", buffer, data_value);
          break;
        case 3:
          data_value = tvb_get_ntoh24(tvb, offset);
          proto_tree_add_uint_format(tree, hf_acn_data24, tvb, offset, 3, data_value, "%s %6.6X", buffer, data_value);
          break;
        case 4:
          data_value = tvb_get_ntohl(tvb, offset);
          proto_tree_add_uint_format(tree, hf_acn_data32, tvb, offset, 4, data_value, "%s %8.8X", buffer, data_value);
          break;
        default:
          /* build string of values */
          for (y=0; y<20 && y<data_size; y++) {
            data_value = tvb_get_guint8(tvb, offset+y);
            g_snprintf(buffer, BUFFER_SIZE, "%s %2.2X", buffer, data_value);
          }
          /* add the item */
          ti = proto_tree_add_item(tree, hf_acn_data, tvb, offset, data_size, ENC_NA);
          offset += data_size;
          /* change the text */
          proto_item_set_text(ti, "%s", buffer);
          break;
      } /* of switch (data_size) */
      offset += data_size;
      break;

    case ACN_DMP_ADT_D_RS: /* Range address, Single data item */
      /* calculate data size */
      data_size = adt->data_length;
      data_address = adt->address;

      for (x=0; x<adt->count; x++) {
        switch (A) {
          case ACN_DMP_ADT_A_1: /* One octet address, (range: one octet address, increment, and count). */
            g_snprintf(buffer, BUFFER_SIZE, "Addr 0x%2.2X ->", data_address);
            break;
          case ACN_DMP_ADT_A_2: /* Two octet address, (range: two octet address, increment, and count). */
            g_snprintf(buffer, BUFFER_SIZE, "Addr 0x%4.4X ->", data_address);
            break;
          case ACN_DMP_ADT_A_4: /* Four octet address, (range: four octet address, increment, and count). */
            g_snprintf(buffer, BUFFER_SIZE, "Addr 0x%8.8X ->", data_address);
            break;
          default: /* and ACN_DMP_ADT_A_R, this reserved....so it has no meaning yet */
            return offset;
        }

        switch (data_size) {
          case 1:
            data_value = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format(tree, hf_acn_data8, tvb, offset, 1, data_value, "%s %2.2X", buffer, data_value);
            break;
          case 2:
            data_value = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint_format(tree, hf_acn_data8, tvb, offset, 2, data_value, "%s %4.4X", buffer, data_value);
            break;
          case 3:
            data_value = tvb_get_ntoh24(tvb, offset);
            proto_tree_add_uint_format(tree, hf_acn_data8, tvb, offset, 3, data_value, "%s %6.6X", buffer, data_value);
            break;
          case 4:
            data_value = tvb_get_ntohl(tvb, offset);
            proto_tree_add_uint_format(tree, hf_acn_data8, tvb, offset, 4, data_value, "%s %8.8X", buffer, data_value);
            break;
          default:
            /* build string of values */
            for (y=0; y<20 && y<data_size; y++) {
              data_value = tvb_get_guint8(tvb, offset+y);
              g_snprintf(buffer, BUFFER_SIZE, "%s %2.2X", buffer, data_value);
            }
            /* add the item */
            ti = proto_tree_add_item(tree, hf_acn_data, tvb, offset, data_size, ENC_NA);
            /* change the text */
            proto_item_set_text(ti, "%s", buffer);
            break;
        } /* of switch (data_size) */
        data_address += adt->increment;
      } /* of (x=0;x<adt->count;x++) */
      offset += data_size;
      break;

    case ACN_DMP_ADT_D_RE: /* Range address, Array of equal size data items */
      /* calculate data size */
      data_size = adt->data_length / adt->count;
      data_address = adt->address;

      for (x=0; x<adt->count; x++) {
        switch (A) {
          case ACN_DMP_ADT_A_1: /* One octet address, (range: one octet address, increment, and count). */
            g_snprintf(buffer, BUFFER_SIZE, "Addr 0x%2.2X ->", data_address);
            break;
          case ACN_DMP_ADT_A_2: /* Two octet address, (range: two octet address, increment, and count). */
            g_snprintf(buffer, BUFFER_SIZE, "Addr 0x%4.4X ->", data_address);
            break;
          case ACN_DMP_ADT_A_4: /* Four octet address, (range: four octet address, increment, and count). */
            g_snprintf(buffer, BUFFER_SIZE, "Addr 0x%8.8X ->", data_address);
            break;
          default: /* and ACN_DMP_ADT_A_R, this reserved....so it has no meaning yet */
            return offset;
        }

        switch (data_size) {
          case 1:
            data_value = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format(tree, hf_acn_data8, tvb, offset, 1, data_value, "%s %2.2X", buffer, data_value);
            break;
          case 2:
            data_value = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint_format(tree, hf_acn_data8, tvb, offset, 2, data_value, "%s %4.4X", buffer, data_value);
            break;
          case 3:
            data_value = tvb_get_ntoh24(tvb, offset);
            proto_tree_add_uint_format(tree, hf_acn_data8, tvb, offset, 3, data_value, "%s %6.6X", buffer, data_value);
            break;
          case 4:
            data_value = tvb_get_ntohl(tvb, offset);
            proto_tree_add_uint_format(tree, hf_acn_data8, tvb, offset, 4, data_value, "%s %8.8X", buffer, data_value);
            break;
          default:
            /* build string of values */
            for (y=0; y<20 && y<data_size; y++) {
              data_value = tvb_get_guint8(tvb, offset+y);
              g_snprintf(buffer, BUFFER_SIZE, "%s %2.2X", buffer, data_value);
            }
            /* add the item */
            ti = proto_tree_add_item(tree, hf_acn_data, tvb, offset, data_size, ENC_NA);
            /* change the text */
            proto_item_set_text(ti, "%s", buffer);
            break;
        } /* of switch (data_size) */

        offset += data_size;
        data_address += adt->increment;
      } /* of (x=0;x<adt->count;x++) */
      break;

    case ACN_DMP_ADT_D_RM: /* Range address, Series of mixed size data items */
      data_size = adt->data_length;
      ti = proto_tree_add_item(tree, hf_acn_data, tvb, offset, data_size, ENC_NA);
      offset += data_size;
      /* change the text */
      proto_item_set_text(ti, "Mixed size data items");
      break;
  } /* of switch (D) */

  return offset;
}

/*******************************************************************************/
/* Display DMP Reason codes                                                    */
  #define BUFFER_SIZE 128
static guint32
acn_add_dmp_reason_codes(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, acn_dmp_adt_type *adt)
{
  guint8       D, A;
  guint32      data_value;
  guint32      data_address;
  guint32      x;

  gchar        buffer[BUFFER_SIZE];
  const gchar *name;

  buffer[0] = 0;

  D = ACN_DMP_ADT_EXTRACT_D(adt->flags);
  A = ACN_DMP_ADT_EXTRACT_A(adt->flags);
  switch (D) {
    case ACN_DMP_ADT_D_NS: /* Non-range address, Single data item */
      data_address = adt->address;
      switch (A) {
        case ACN_DMP_ADT_A_1: /* One octet address, (range: one octet address, increment, and count). */
          g_snprintf(buffer, BUFFER_SIZE, "Addr 0x%2.2X ->", data_address);
          break;
        case ACN_DMP_ADT_A_2: /* Two octet address, (range: two octet address, increment, and count). */
          g_snprintf(buffer, BUFFER_SIZE, "Addr 0x%4.4X ->", data_address);
          break;
        case ACN_DMP_ADT_A_4: /* Four octet address, (range: four octet address, increment, and count). */
          g_snprintf(buffer, BUFFER_SIZE, "Addr 0x%8.8X ->", data_address);
          break;
        default: /* and ACN_DMP_ADT_A_R, this reserved....so it has no meaning yet */
          return offset;
      }

      /* Get reason */
      data_value  = tvb_get_guint8(tvb, offset);
      name        = val_to_str(data_value, acn_dmp_reason_code_vals, "reason not valid (%d)");
      proto_tree_add_uint_format(tree, hf_acn_data8, tvb, offset, 1, data_value, "%s %s", buffer, name);
      offset     += 1;
      break;

    case ACN_DMP_ADT_D_RS: /* Range address, Single data item */
      data_address = adt->address;
      for (x=0; x<adt->count; x++) {
        switch (A) {
          case ACN_DMP_ADT_A_1: /* One octet address, (range: one octet address, increment, and count). */
            g_snprintf(buffer, BUFFER_SIZE, "Addr 0x%2.2X ->", data_address);
            break;
          case ACN_DMP_ADT_A_2: /* Two octet address, (range: two octet address, increment, and count). */
            g_snprintf(buffer, BUFFER_SIZE, "Addr 0x%4.4X ->", data_address);
            break;
          case ACN_DMP_ADT_A_4: /* Four octet address, (range: four octet address, increment, and count). */
            g_snprintf(buffer, BUFFER_SIZE, "Addr 0x%8.8X ->", data_address);
            break;
          default: /* and ACN_DMP_ADT_A_R, this reserved....so it has no meaning yet */
            return offset;
        }

        /* Get reason */
        data_value = tvb_get_guint8(tvb, offset);
        name       = val_to_str(data_value, acn_dmp_reason_code_vals, "reason not valid (%d)");
        proto_tree_add_uint_format(tree, hf_acn_data8, tvb, offset, 1, data_value, "%s %s", buffer, name);

        data_address += adt->increment;
      } /* of (x=0;x<adt->count;x++) */
      offset += 1;
      break;

    case ACN_DMP_ADT_D_RE: /* Range address, Array of equal size data items */
    case ACN_DMP_ADT_D_RM: /* Range address, Series of mixed size data items */
      data_address = adt->address;
      for (x=0; x<adt->count; x++) {
        switch (A) {
          case ACN_DMP_ADT_A_1: /* One octet address, (range: one octet address, increment, and count). */
            g_snprintf(buffer, BUFFER_SIZE, "Addr 0x%2.2X ->", data_address);
            break;
          case ACN_DMP_ADT_A_2: /* Two octet address, (range: two octet address, increment, and count). */
            g_snprintf(buffer, BUFFER_SIZE, "Addr 0x%4.4X ->", data_address);
            break;
          case ACN_DMP_ADT_A_4: /* Four octet address, (range: four octet address, increment, and count). */
            g_snprintf(buffer, BUFFER_SIZE, "Addr 0x%8.8X ->", data_address);
            break;
          default: /* and ACN_DMP_ADT_A_R, this reserved....so it has no meaning yet */
            return offset;
        }
        /* Get reason */
        data_value    = tvb_get_guint8(tvb, offset);
        name          = val_to_str(data_value, acn_dmp_reason_code_vals, "reason not valid (%d)");
        proto_tree_add_uint_format(tree, hf_acn_data8, tvb, offset, 1, data_value, "%s %s", buffer, name);
        data_address += adt->increment;
        offset       += 1;
      } /* of (x=0;x<adt->count;x++) */
      break;
  } /* of switch (D) */

  return offset;
}

/******************************************************************************/
/* Dissect wrapped SDT PDU                                                    */
static guint32
dissect_acn_dmp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets)
{
  /* common to all pdu */
  guint8            pdu_flags;
  guint32           pdu_start;
  guint32           pdu_length;
  guint32           pdu_flvh_length; /* flags, length, vector, header */
  guint8            D;
  guint8            octet;
  guint32           length1;
  guint32           length2;
  guint32           length3;
  guint32           vector_offset;
  guint32           header_offset;
  guint32           data_offset;
  guint32           old_offset;
  guint32           end_offset;
  guint32           data_length;
  guint32           address_count;

  proto_item       *ti, *pi;
  proto_tree       *pdu_tree  = NULL;
  proto_tree       *flag_tree = NULL;

  /* this pdu */
  const gchar      *name;
  acn_dmp_adt_type  adt       = {0,0,0,0,0,0};
  acn_dmp_adt_type  adt2      = {0,0,0,0,0,0};
  guint32           vector;

  /* save start of pdu block */
  pdu_start = offset;

  /* get PDU flags and length flag first */
  octet     = tvb_get_guint8(tvb, offset++);
  pdu_flags = octet & 0xf0;
  length1   = octet & 0x0f;     /* bottom 4 bits only */
  length2   = tvb_get_guint8(tvb, offset++);

  /* if length flag is set, then we have a 20 bit length else we have a 12 bit */
  /* flvh = flags, length, vector, header */
  if (pdu_flags & ACN_PDU_FLAG_L) {
    length3 = tvb_get_guint8(tvb, offset);
    offset += 1;
    pdu_length = length3 | (length2 << 8) | (length1 << 16);
    pdu_flvh_length = 3;
  } else {
    pdu_length = length2 | (length1 << 8);
    pdu_flvh_length = 2;
  }
  /* offset should now be pointing to vector (if one exists) */

  /* Add pdu item and tree */
  ti       = proto_tree_add_item(tree, hf_acn_pdu, tvb, pdu_start, pdu_length, ENC_NA);
  pdu_tree = proto_item_add_subtree(ti, ett_acn_dmp_pdu);

  /* Add flag item and tree */
  pi        = proto_tree_add_uint(pdu_tree, hf_acn_pdu_flags, tvb, pdu_start, 1, pdu_flags);
  flag_tree = proto_item_add_subtree(pi, ett_acn_pdu_flags);
  proto_tree_add_item(flag_tree, hf_acn_pdu_flag_l, tvb, pdu_start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flag_tree, hf_acn_pdu_flag_v, tvb, pdu_start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flag_tree, hf_acn_pdu_flag_h, tvb, pdu_start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flag_tree, hf_acn_pdu_flag_d, tvb, pdu_start, 1, ENC_BIG_ENDIAN);

  /* Add PDU Length item */
  proto_tree_add_uint(pdu_tree, hf_acn_pdu_length, tvb, pdu_start, pdu_flvh_length, pdu_length);

  /* Set vector offset */
  if (pdu_flags & ACN_PDU_FLAG_V) {
    /* use new values */
    vector_offset             = offset;
    last_pdu_offsets->vector  = offset;
    offset                   += 1;
    pdu_flvh_length++;
  } else {
    /* use last values */
    vector_offset             = last_pdu_offsets->vector;
  }
  /* offset should now be pointing to header (if one exists) */

  /* Add Vector item */
  vector = tvb_get_guint8(tvb, vector_offset);
  proto_tree_add_uint(pdu_tree, hf_acn_dmp_vector, tvb, vector_offset, 1, vector);

  /* Add Vector item to tree*/
  name = val_to_str(vector, acn_dmp_vector_vals, "not valid (%d)");
  proto_item_append_text(ti, ": ");
  proto_item_append_text(ti, "%s", name);

  /* Set header offset */
  if (pdu_flags & ACN_PDU_FLAG_H) {
    /* use new values */
    header_offset             = offset;
    last_pdu_offsets->header  = offset;
    offset                   += 1;
    pdu_flvh_length++;
  } else {
    /* use last values */
    header_offset             = last_pdu_offsets->header;
  }
  /* offset should now be pointing to data (if one exists) */

  /* header contains address and data type */
  acn_add_dmp_address_type(tvb, pinfo, pdu_tree, header_offset, &adt);

  /* Adjust data */
  if (pdu_flags & ACN_PDU_FLAG_D) {
    /* use new values */
    data_offset                   = offset;
    data_length                   = pdu_length - pdu_flvh_length;
    last_pdu_offsets->data        = offset;
    last_pdu_offsets->data_length = data_length;
  } else {
    /* use last values */
    data_offset                   = last_pdu_offsets->data;
    data_length                   = last_pdu_offsets->data_length;
  }
  end_offset = data_offset + data_length;

  switch (vector) {
    case ACN_DMP_VECTOR_UNKNOWN:
      break;
    case ACN_DMP_VECTOR_GET_PROPERTY:
      /* Rip through property address */
      while (data_offset < end_offset) {
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_address(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;
      }
      break;
    case ACN_DMP_VECTOR_SET_PROPERTY:
      /* Rip through Property Address-Data pairs                                 */
      /* But, in reality, this generally won't work as we have know way of       */
      /* calculating the next Address-Data pair                                  */
      while (data_offset < end_offset) {
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_address(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;

        adt.data_length = data_length - (data_offset - old_offset);
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_data(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;
      }
      break;
    case ACN_DMP_VECTOR_GET_PROPERTY_REPLY:
      /* Rip through Property Address-Data pairs */
      /* But, in reality, this generally won't work as we have know way of       */
      /* calculating the next Address-Data pair                                  */
      while (data_offset < end_offset) {
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_address(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;

        adt.data_length = data_length - (data_offset - old_offset);
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_data(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;
      }
      break;
    case ACN_DMP_VECTOR_EVENT:
      /* Rip through Property Address-Data pairs */
      /* But, in reality, this generally won't work as we have know way of       */
      /* calculating the next Address-Data pair                                  */
      while (data_offset < end_offset) {
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_address(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;

        adt.data_length = data_length - (data_offset - old_offset);
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_data(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;
      }
      break;
    case ACN_DMP_VECTOR_MAP_PROPERTY:
      /* Virtual Address type */
      data_offset = acn_add_dmp_address_type(tvb, pinfo, pdu_tree, data_offset, &adt2);
      /* Rip through Actual-Virtual Address Pairs */
      while (data_offset < end_offset) {
        /* actual */
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_address(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;
        D = ACN_DMP_ADT_EXTRACT_D(adt.flags);
        switch (D) {
          case ACN_DMP_ADT_D_NS:
            address_count = 1;
            break;
          case ACN_DMP_ADT_D_RS:
            address_count = 1;
            break;
          case ACN_DMP_ADT_D_RE:
            address_count = adt.count;
            break;
            /*case ACN_DMP_ADT_D_RM: */
          default:
            /* OUCH */
            return pdu_start + pdu_length;
            break;
        }

        /* virtual */
        while (address_count > 0) {
          data_offset = acn_add_dmp_address(tvb, pinfo, pdu_tree, data_offset, &adt2);
          address_count--;
        }
      }
      break;
    case ACN_DMP_VECTOR_UNMAP_PROPERTY:
      /* Rip through Actual Property Address */
      while (data_offset < end_offset) {
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_address(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;
      }
      break;
    case ACN_DMP_VECTOR_SUBSCRIBE:
      /* Rip through Property Address */
      while (data_offset < end_offset) {
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_address(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;
      }
      break;
    case ACN_DMP_VECTOR_UNSUBSCRIBE:
      /* Rip through Property Address */
      while (data_offset < end_offset) {
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_address(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;
      }
      break;
    case ACN_DMP_VECTOR_GET_PROPERTY_FAIL:
      /* Rip through Address-Reason Code Pairs */
      while (data_offset < end_offset) {
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_address(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;

        adt.data_length = data_length - (data_offset - old_offset);
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_reason_codes(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;
      }
      break;
    case ACN_DMP_VECTOR_SET_PROPERTY_FAIL:
      /* Rip through Address-Reason Code Pairs */
      while (data_offset < end_offset) {
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_address(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;

        adt.data_length = data_length - (data_offset - old_offset);
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_reason_codes(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;
      }
      break;
    case ACN_DMP_VECTOR_MAP_PROPERTY_FAIL:
      /* Rip through Address-Reason Code Pairs */
      while (data_offset < end_offset) {
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_address(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;

        adt.data_length = data_length - (data_offset - old_offset);
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_reason_codes(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;
      }
      break;
    case ACN_DMP_VECTOR_SUBSCRIBE_ACCEPT:
      /* Rip through Property Addresses */
      while (data_offset < end_offset) {
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_address(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;
      }
      break;
    case ACN_DMP_VECTOR_SUBSCRIBE_REJECT:
      /* Rip through Address-Reason Code Pairs */
      while (data_offset < end_offset) {
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_address(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;

        adt.data_length = data_length - (data_offset - old_offset);
        old_offset      = data_offset;
        data_offset     = acn_add_dmp_reason_codes(tvb, pinfo, pdu_tree, data_offset, &adt);
        if (old_offset == data_offset) break;
      }
      break;
    case ACN_DMP_VECTOR_ALLOCATE_MAP:
      /* No data for this */
      break;
    case ACN_DMP_VECTOR_ALLOCATE_MAP_REPLY:
      /* Single reason code  */
      proto_tree_add_item(pdu_tree, hf_acn_dmp_reason_code, tvb, data_offset, 1, ENC_BIG_ENDIAN);
      /* data_offset += 1; */
    case ACN_DMP_VECTOR_DEALLOCATE_MAP:
      /* No data for this */
      break;
  }

  return pdu_start + pdu_length;
}


/******************************************************************************/
/* Dissect wrapped SDT PDU                                                    */
static guint32
dissect_acn_sdt_wrapped_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets)
{
  /* common to all pdu */
  guint8       pdu_flags;
  guint32      pdu_start;
  guint32      pdu_length;
  guint32      pdu_flvh_length; /* flags, length, vector, header */
  guint8       octet;
  guint32      length1;
  guint32      length2;
  guint32      length3;
  guint32      vector_offset;
  guint32      data_offset;
  guint32      data_length;

  proto_item  *ti, *pi;
  proto_tree  *pdu_tree  = NULL;
  proto_tree  *flag_tree = NULL;

  /* this pdu */
  const gchar *name;
  guint32      vector;

  /* save start of pdu block */
  pdu_start = offset;

  /* get PDU flags and length flag first */
  octet     = tvb_get_guint8(tvb, offset++);
  pdu_flags = octet & 0xf0;
  length1   = octet & 0x0f;     /* bottom 4 bits only */
  length2   = tvb_get_guint8(tvb, offset++);

  /* if length flag is set, then we have a 20 bit length else we have a 12 bit */
  /* flvh = flags, length, vector, header */
  if (pdu_flags & ACN_PDU_FLAG_L) {
    length3 = tvb_get_guint8(tvb, offset);
    offset += 1;
    pdu_length = length3 | (length2 << 8) | (length1 << 16);
    pdu_flvh_length = 3;
  } else {
    pdu_length = length2 | (length1 << 8);
    pdu_flvh_length = 2;
  }
  /* offset should now be pointing to vector (if one exists) */

  /* Add pdu item and tree */
  ti = proto_tree_add_item(tree, hf_acn_pdu, tvb, pdu_start, pdu_length, ENC_NA);
  pdu_tree = proto_item_add_subtree(ti, ett_acn_sdt_pdu);

  /* Add flag item and tree */
  pi = proto_tree_add_uint(pdu_tree, hf_acn_pdu_flags, tvb, pdu_start, 1, pdu_flags);
  flag_tree = proto_item_add_subtree(pi, ett_acn_pdu_flags);
  proto_tree_add_item(flag_tree, hf_acn_pdu_flag_l, tvb, pdu_start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flag_tree, hf_acn_pdu_flag_v, tvb, pdu_start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flag_tree, hf_acn_pdu_flag_h, tvb, pdu_start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flag_tree, hf_acn_pdu_flag_d, tvb, pdu_start, 1, ENC_BIG_ENDIAN);

  /* Add PDU Length item */
  proto_tree_add_uint(pdu_tree, hf_acn_pdu_length, tvb, pdu_start, pdu_flvh_length, pdu_length);

  /* Set vector offset */
  if (pdu_flags & ACN_PDU_FLAG_V) {
    /* use new values */
    vector_offset = offset;
    last_pdu_offsets->vector = offset;
    offset += 1;
    pdu_flvh_length++;
  } else {
    /* use last values */
    vector_offset = last_pdu_offsets->vector;
  }
  /* offset should now be pointing to header (if one exists) */

  /* Add Vector item */
  vector = tvb_get_guint8(tvb, vector_offset);
  proto_tree_add_uint(pdu_tree, hf_acn_sdt_vector, tvb, vector_offset, 1, vector);

  /* Add Vector item to tree*/
  name = val_to_str(vector, acn_sdt_vector_vals, "not valid (%d)");
  proto_item_append_text(ti, ": ");
  proto_item_append_text(ti, "%s", name);

  /* NO HEADER DATA ON THESE* (at least so far) */

  /* Adjust data */
  if (pdu_flags & ACN_PDU_FLAG_D) {
    /* use new values */
    data_offset = offset;
    data_length = pdu_length - pdu_flvh_length;
    last_pdu_offsets->data = offset;
    last_pdu_offsets->data_length = data_length;
  } else {
    /* use last values */
    data_offset = last_pdu_offsets->data;
    /*data_length = last_pdu_offsets->data_length;*/
  }

  switch (vector) {
    case ACN_SDT_VECTOR_ACK:
      proto_tree_add_item(pdu_tree, hf_acn_reliable_sequence_number, tvb, data_offset, 4, ENC_BIG_ENDIAN);
      /*data_offset += 4;*/
      break;
    case ACN_SDT_VECTOR_CHANNEL_PARAMS:
      data_offset = acn_add_channel_parameter(tvb, pinfo, pdu_tree, data_offset);
      data_offset = acn_add_address(tvb, pinfo, pdu_tree, data_offset, "Ad-hoc Address:");
      /*data_offset =*/ acn_add_expiry(tvb, pinfo, pdu_tree, data_offset, hf_acn_adhoc_expiry);
      break;
    case ACN_SDT_VECTOR_LEAVE:
      /* nothing more */
      break;
    case ACN_SDT_VECTOR_CONNECT:
      /* Protocol ID item */
      proto_tree_add_item(pdu_tree, hf_acn_protocol_id, tvb, data_offset, 4, ENC_BIG_ENDIAN);
      /*data_offset += 4;*/
      break;
    case ACN_SDT_VECTOR_CONNECT_ACCEPT:
      /* Protocol ID item */
      proto_tree_add_item(pdu_tree, hf_acn_protocol_id, tvb, data_offset, 4, ENC_BIG_ENDIAN);
      /*data_offset += 4;*/
      break;
    case ACN_SDT_VECTOR_CONNECT_REFUSE:
      /* Protocol ID item */
      proto_tree_add_item(pdu_tree, hf_acn_protocol_id, tvb, data_offset, 4, ENC_BIG_ENDIAN);
      data_offset += 4;
      proto_tree_add_item(pdu_tree, hf_acn_refuse_code, tvb, data_offset, 1, ENC_BIG_ENDIAN);
      /*data_offset += 1;*/
      break;
    case ACN_SDT_VECTOR_DISCONNECT:
      /* Protocol ID item */
      proto_tree_add_item(pdu_tree, hf_acn_protocol_id, tvb, data_offset, 4, ENC_BIG_ENDIAN);
      /*data_offset += 4;*/
      break;
    case ACN_SDT_VECTOR_DISCONNECTING:
      /* Protocol ID item */
      proto_tree_add_item(pdu_tree, hf_acn_protocol_id, tvb, data_offset, 4, ENC_BIG_ENDIAN);
      data_offset += 4;
      proto_tree_add_item(pdu_tree, hf_acn_reason_code, tvb, data_offset, 1, ENC_BIG_ENDIAN);
      /*data_offset += 1;*/
      break;

  }

  return pdu_start + pdu_length;
}


/******************************************************************************/
/* Dissect SDT Client PDU                                                     */
static guint32
dissect_acn_sdt_client_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets)
{
  /* common to all pdu */
  guint8           pdu_flags;
  guint32          pdu_start;
  guint32          pdu_length;
  guint32          pdu_flvh_length; /* flags, length, vector, header */
  acn_pdu_offsets  pdu_offsets = {0,0,0,0,0};
  guint8           octet;
  guint32          length1;
  guint32          length2;
  guint32          length3;
  guint32          vector_offset;
  guint32          header_offset;
  guint32          data_offset;
  guint32          data_length;
  guint32          old_offset;
  guint32          end_offset;

  proto_item      *ti, *pi;
  proto_tree      *pdu_tree    = NULL;
  proto_tree      *flag_tree   = NULL;

  /* this pdu */
  const gchar     *name;
  guint32          member_id;
  guint32          protocol_id;
  guint16          association;

  /* save start of pdu block */
  pdu_start         = offset;
  pdu_offsets.start = pdu_start;

  /* get PDU flags and length flag first */
  octet     = tvb_get_guint8(tvb, offset++);
  pdu_flags = octet & 0xf0;
  length1   = octet & 0x0f;     /* bottom 4 bits only */
  length2   = tvb_get_guint8(tvb, offset++);

  /* if length flag is set, then we have a 20 bit length else we have a 12 bit */
  /* flvh = flags, length, vector, header */
  if (pdu_flags & ACN_PDU_FLAG_L) {
    length3 = tvb_get_guint8(tvb, offset);
    offset += 1;
    pdu_length = length3 | (length2 << 8) | (length1 << 16);
    pdu_flvh_length = 3;
  } else {
    pdu_length = length2 | (length1 << 8);
    pdu_flvh_length = 2;
  }
  /* offset should now be pointing to vector (if one exists) */

  /* Add pdu item and tree */
  ti       = proto_tree_add_item(tree, hf_acn_pdu, tvb, pdu_start, pdu_length, ENC_NA);
  pdu_tree = proto_item_add_subtree(ti, ett_acn_sdt_client_pdu);

  /* Add flag item and tree */
  pi = proto_tree_add_uint(pdu_tree, hf_acn_pdu_flags, tvb, pdu_start, 1, pdu_flags);
  flag_tree = proto_item_add_subtree(pi, ett_acn_pdu_flags);
  proto_tree_add_item(flag_tree, hf_acn_pdu_flag_l, tvb, pdu_start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flag_tree, hf_acn_pdu_flag_v, tvb, pdu_start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flag_tree, hf_acn_pdu_flag_h, tvb, pdu_start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flag_tree, hf_acn_pdu_flag_d, tvb, pdu_start, 1, ENC_BIG_ENDIAN);

  /* Add PDU Length item */
  proto_tree_add_uint(pdu_tree, hf_acn_pdu_length, tvb, pdu_start, pdu_flvh_length, pdu_length);

  /* Set vector offset */
  if (pdu_flags & ACN_PDU_FLAG_V) {
    /* use new values */
    vector_offset = offset;
    last_pdu_offsets->vector = offset;
    offset += 2;
    pdu_flvh_length += 2;
  } else {
    /* use last values */
    vector_offset = last_pdu_offsets->vector;
  }
  /* offset should now be pointing to header (if one exists) */

  /* add Member ID item  */
  member_id = tvb_get_ntohs(tvb, vector_offset);
  proto_tree_add_uint(pdu_tree, hf_acn_member_id, tvb, vector_offset, 2, member_id);

  /* Set header offset */
  if (pdu_flags & ACN_PDU_FLAG_H) {
    /* use new values */
    header_offset             = offset;
    last_pdu_offsets->header  = offset;
    offset                   += 6;
    pdu_flvh_length          += 6;
  } else {
    /* use last values */
    header_offset             = last_pdu_offsets->header;
  }
  /* offset should now be pointing to data (if one exists) */

  /* add Protocol ID item (Header)*/
  protocol_id = tvb_get_ntohl(tvb, header_offset);
  proto_tree_add_uint(pdu_tree, hf_acn_protocol_id, tvb, header_offset, 4, protocol_id);
  header_offset += 4;

  /* Add protocol to tree*/
  name = val_to_str(protocol_id, acn_protocol_id_vals, "id not valid (%d)");
  proto_item_append_text(ti, ": ");
  proto_item_append_text(ti, "%s", name);

  /* add association item */
  association = tvb_get_ntohs(tvb, header_offset);
  proto_tree_add_uint(pdu_tree, hf_acn_association, tvb, header_offset, 2, association);
  /*header_offset += 2;*/

  /* Adjust data */
  if (pdu_flags & ACN_PDU_FLAG_D) {
    /* use new values */
    data_offset = offset;
    data_length = pdu_length - pdu_flvh_length;
    last_pdu_offsets->data = offset;
    last_pdu_offsets->data_length = data_length;
  } else {
    /* use last values */
    data_offset = last_pdu_offsets->data;
    data_length = last_pdu_offsets->data_length;
  }
  end_offset = data_offset + data_length;

  switch (protocol_id) {
    case ACN_PROTOCOL_ID_SDT:
      while (data_offset < end_offset) {
        old_offset  = data_offset;
        data_offset = dissect_acn_sdt_wrapped_pdu(tvb, pinfo, pdu_tree, data_offset, &pdu_offsets);
        if (old_offset == data_offset) break;
      }
      break;
    case ACN_PROTOCOL_ID_DMP:
      while (data_offset < end_offset) {
        old_offset  = data_offset;
        data_offset = dissect_acn_dmp_pdu(tvb, pinfo, pdu_tree, data_offset, &pdu_offsets);
        if (data_offset == old_offset) break;
      }
      break;
  }
  return pdu_start + pdu_length;
}


/******************************************************************************/
/* level to string (ascii)                                                    */
/*  level    : 8 bit value                                                    */
/*  string   : pointer to buffer to fill                                      */
/*  leading_char: character to buffer left of digits                             */
/*  min_char : minimum number of characters (for filling, not including space)*/
/*  show_zero: show zeros or dots                                             */
/* also adds a space to right end                                             */
/*                                                                            */
/*  returns end of string                                                     */
/*  faster than printf()                                                      */
static char *
ltos(guint8 level, gchar *string, guint8 base, gchar leading_char, guint8 min_chars, gboolean show_zero)
{
  guint8 i;
  /* verify base */
  if (base < 2 || base > 16) {
    *string = '\0';
    return(string);
  }
  /* deal with zeros */
  if ((level == 0) && (!show_zero)) {
    for (i=0; i<min_chars; i++) {
      string[i] = '.';
    }
    string[i++] = ' ';
    string[i] = '\0';
    return(string + i);
  }

  i = 0;
  /* do our convert, comes out backwards! */
  do {
    string[i++] = "0123456789ABCDEF"[level % base];
  } while ((level /= base) > 0);

  /* expand to needed character */
  for (; i<min_chars; i++) {
    string[i] = leading_char;
  }
  /* terminate */
  string[i] = '\0';

  /* now reverse (and correct) the order */
  g_strreverse(string);

  /* add a space at the end (ok it's at the start but it will be at the end)*/
  string[i++] = ' ';
  string[i] = '\0';
  return(string + i);
}


/******************************************************************************/
/* Dissect DMX data PDU                                                       */
#define BUFFER_SIZE 128
static guint32
dissect_acn_dmx_data_pdu(guint32 protocol_id, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets)
{
  /* common to all pdu */
  guint8            pdu_flags;
  guint32           pdu_start;
  guint32           pdu_length;
  guint32           pdu_flvh_length; /* flags, length, vector, header */
  guint8            octet;
  guint32           length1;
  guint32           length2;
  guint32           length3;
  guint32           vector_offset;
  guint32           data_offset;
  guint32           end_offset;
  guint32           data_length;
  guint32           header_offset;
  guint32           total_cnt;
  guint32           item_cnt;

  proto_item       *ti, *pi;
  proto_tree       *pdu_tree;
  proto_tree       *flag_tree;

/* this pdu */
  acn_dmp_adt_type  adt       = {0,0,0,0,0,0};
  const gchar      *name;
  guint32           vector;
  gchar             buffer[BUFFER_SIZE];
  char             *buf_ptr;
  guint             x;
  guint8            level;
  guint8            min_char;
  guint8            base;
  gchar             leading_char;
  guint             perline;
  guint             halfline;
  guint16           dmx_count;
  guint16           dmx_start_code;

  buffer[0] = 0;

  /* save start of pdu block */
  pdu_start = offset;

  /* get PDU flags and length flag first */
  octet     = tvb_get_guint8(tvb, offset++);
  pdu_flags = octet & 0xf0;
  length1   = octet & 0x0f;     /* bottom 4 bits only */
  length2   = tvb_get_guint8(tvb, offset++);

  /* if length flag is set, then we have a 20 bit length else we have a 12 bit */
  /* flvh = flags, length, vector, header */
  if (pdu_flags & ACN_PDU_FLAG_L) {
    length3 = tvb_get_guint8(tvb, offset);
    offset += 1;
    pdu_length = length3 | (length2 << 8) | (length1 << 16);
    pdu_flvh_length = 3;
  } else {
    pdu_length = length2 | (length1 << 8);
    pdu_flvh_length = 2;
  }
  /* offset should now be pointing to vector (if one exists) */

  /* Add pdu item and tree */
  ti       = proto_tree_add_item(tree, hf_acn_pdu, tvb, pdu_start, pdu_length, ENC_NA);
  pdu_tree = proto_item_add_subtree(ti, ett_acn_dmx_data_pdu);

  /* Add flag item and tree */
  pi = proto_tree_add_uint(pdu_tree, hf_acn_pdu_flags, tvb, pdu_start, 1, pdu_flags);
  flag_tree = proto_item_add_subtree(pi, ett_acn_pdu_flags);
  proto_tree_add_item(flag_tree, hf_acn_pdu_flag_l, tvb, pdu_start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flag_tree, hf_acn_pdu_flag_v, tvb, pdu_start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flag_tree, hf_acn_pdu_flag_h, tvb, pdu_start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flag_tree, hf_acn_pdu_flag_d, tvb, pdu_start, 1, ENC_BIG_ENDIAN);

  /* Add PDU Length item */
  proto_tree_add_uint(pdu_tree, hf_acn_pdu_length, tvb, pdu_start, pdu_flvh_length, pdu_length);

  /* Set vector offset */
  if (pdu_flags & ACN_PDU_FLAG_V) {
    /* use new values */
    vector_offset = offset;
    last_pdu_offsets->vector = offset;
    offset += 1;
    pdu_flvh_length += 1;
  } else {
    /* use last values */
    vector_offset = last_pdu_offsets->vector;
  }
  /* offset should now be pointing to header (if one exists) */

  /* Add Vector item */
  vector = tvb_get_guint8(tvb, vector_offset);
  proto_tree_add_uint(pdu_tree, hf_acn_dmp_vector, tvb, vector_offset, 1, vector);

  /* Add Vector item to tree*/
  name = val_to_str(vector, acn_dmp_vector_vals, "not valid (%d)");
  proto_item_append_text(ti, ": ");
  proto_item_append_text(ti, "%s", name);

  /* Set header offset */
  if (pdu_flags & ACN_PDU_FLAG_H) {
    /* use new values */
    header_offset = offset;
    last_pdu_offsets->header = offset;
    offset += 1;
    pdu_flvh_length++;
  } else {
    /* use last values */
    header_offset = last_pdu_offsets->header;
  }
  /* offset should now be pointing to data (if one exists) */

  /* process based on vector */
  acn_add_dmp_address_type(tvb, pinfo, pdu_tree, header_offset, &adt);

  /* Adjust data */
  if (pdu_flags & ACN_PDU_FLAG_D) {
    /* use new values */
    data_offset = offset;
    data_length = pdu_length - pdu_flvh_length;
    last_pdu_offsets->data = offset;
    last_pdu_offsets->data_length = data_length;
  } else {
    /* use last values */
    data_offset = last_pdu_offsets->data;
    data_length = last_pdu_offsets->data_length;
  }
  end_offset = data_offset + data_length;

  switch (vector) {
    case ACN_DMP_VECTOR_SET_PROPERTY:
      dmx_start_code = tvb_get_ntohs(tvb, data_offset);
      if (protocol_id==ACN_PROTOCOL_ID_DMX_2) {
        proto_tree_add_item(pdu_tree, hf_acn_dmx_2_first_property_address, tvb, data_offset, 2, ENC_BIG_ENDIAN);
      } else{
        proto_tree_add_item(pdu_tree, hf_acn_dmx_start_code, tvb, data_offset, 2, ENC_BIG_ENDIAN);
      }
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_dmx_increment, tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      dmx_count    = tvb_get_ntohs(tvb, data_offset);
      proto_tree_add_item(pdu_tree, hf_acn_dmx_count, tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;

      if (protocol_id==ACN_PROTOCOL_ID_DMX_2) {
        proto_tree_add_item(pdu_tree, hf_acn_dmx_2_start_code, tvb, data_offset, 1, ENC_BIG_ENDIAN);
        data_offset += 1;
        dmx_count   -= 1;
      }

      buf_ptr = buffer;

      switch (global_acn_dmx_display_line_format) {
        case ACN_PREF_DMX_DISPLAY_16PL:
          perline  = 16;
          halfline = 8;
          break;
        default:
          perline  = 20;
          halfline = 10;
      }

      /* values base on display mode */
      switch ((guint)global_acn_dmx_display_view) {
        case ACN_PREF_DMX_DISPLAY_HEX:
          min_char = 2;
          base     = 16;
          break;
/*        case ACN_PREF_DMX_DISPLAY_PER: */
        default:
          min_char = 3;
          base     = 10;
      }

      /* do we display leading zeros */
      if (global_acn_dmx_display_leading_zeros) {
        leading_char = '0';
      } else {
        leading_char = ' ';
      }

      /* add a snippet to info (this may be slow) */
      col_append_fstr(pinfo->cinfo,COL_INFO, ", Sc %02x, [%02x %02x %02x %02x %02x %02x...]",
        dmx_start_code,
        tvb_get_guint8(tvb, data_offset),
        tvb_get_guint8(tvb, data_offset+1),
        tvb_get_guint8(tvb, data_offset+2),
        tvb_get_guint8(tvb, data_offset+3),
        tvb_get_guint8(tvb, data_offset+4),
        tvb_get_guint8(tvb, data_offset+5));

      /* add a header line */
      for (x=0; x<perline; x++) {
        buf_ptr = ltos((guint8)(x+1), buf_ptr, 10, ' ', min_char, FALSE);
        if ((x+1)==halfline) {
          *buf_ptr++ =  '|';
          *buf_ptr++ =  ' ';
        }
      }
      *buf_ptr = '\0';
      proto_tree_add_string(pdu_tree, hf_acn_dmx_data, tvb, data_offset, dmx_count, buffer);

      /* start our line */
      g_snprintf(buffer, BUFFER_SIZE, "001-%03d: ", perline);
      buf_ptr = buffer + 9;

      total_cnt = 0;
      item_cnt = 0;
      for (x=data_offset; x<end_offset; x++) {
        level = tvb_get_guint8(tvb, x);
        if (global_acn_dmx_display_view==ACN_PREF_DMX_DISPLAY_PER) {
          if ((level > 0) && (level < 3)) {
            level = 1;
          } else {
            level = level * 100 / 255;
          }
        }
        buf_ptr = ltos(level, buf_ptr, base, leading_char, min_char, global_acn_dmx_display_zeros);
        total_cnt++;
        item_cnt++;

        if (item_cnt == perline || x == (end_offset-1)) {
          /* add leader... */
          proto_tree_add_string_format(pdu_tree, hf_acn_dmx_data, tvb, data_offset, item_cnt, buffer, "%s", buffer);
          data_offset += perline;
          g_snprintf(buffer, BUFFER_SIZE, "%03d-%03d: ",total_cnt, total_cnt+perline);
          buf_ptr = buffer + 9;
          item_cnt = 0;
        } else {
          /* add separator character */
          if (item_cnt == halfline) {
            *buf_ptr++ = '|';
            *buf_ptr++ = ' ';
            *buf_ptr   = '\0';
          }
        }
      }
    /* NOTE:
     address data type                   (fixed at 0xA2)
     start code - 1 byte, reserved       (should be 0)
                - 1 byte, start code     (0x255)
                - 2 bytes, packet offset (should be 0000)
     address increment - 4 bytes         (ignore)
     number of dmx values - 4 bytes      (0-512)
     dmx values 0-512 bytes              (data)
     */

    break;
  }
  return pdu_start + pdu_length;
}



/******************************************************************************/
/* Dissect DMX Base PDU                                                       */
static guint32
dissect_acn_dmx_pdu(guint32 protocol_id, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets)
{
  /* common to all pdu */
  guint8           pdu_flags;
  guint32          pdu_start;
  guint32          pdu_length;
  guint32          pdu_flvh_length; /* flags, length, vector, header */
  acn_pdu_offsets  pdu_offsets = {0,0,0,0,0};
  guint8           octet;
  guint8           option_flags;
  guint32          length1;
  guint32          length2;
  guint32          length3;
  guint32          vector_offset;
  guint32          data_offset;
  guint32          data_length;

  proto_item      *ti, *pi;
  proto_tree      *pdu_tree;
  proto_tree      *flag_tree;

  const char      *name;

/* this pdu */
  guint32          vector;

  guint32          universe;
  guint32          priority;
  guint32          sequence;

  /* save start of pdu block */
  pdu_start = offset;
  pdu_offsets.start = pdu_start;

  /* get PDU flags and length flag first */
  octet     = tvb_get_guint8(tvb, offset++);
  pdu_flags = octet & 0xf0;
  length1   = octet & 0x0f;     /* bottom 4 bits only */
  length2   = tvb_get_guint8(tvb, offset++);

  /* if length flag is set, then we have a 20 bit length else we have a 12 bit */
  /* flvh = flags, length, vector, header */
  if (pdu_flags & ACN_PDU_FLAG_L) {
    length3 = tvb_get_guint8(tvb, offset);
    offset += 1;
    pdu_length = length3 | (length2 << 8) | (length1 << 16);
    pdu_flvh_length = 3;
  } else {
    pdu_length = length2 | (length1 << 8);
    pdu_flvh_length = 2;
  }

  /* offset should now be pointing to vector (if one exists) */

  /* Add pdu item and tree */
  ti = proto_tree_add_item(tree, hf_acn_pdu, tvb, pdu_start, pdu_length, ENC_NA);
  pdu_tree = proto_item_add_subtree(ti, ett_acn_dmx_pdu);

  /* Add flag item and tree */
  pi = proto_tree_add_uint(pdu_tree, hf_acn_pdu_flags, tvb, pdu_start, 1, pdu_flags);
  flag_tree = proto_item_add_subtree(pi, ett_acn_pdu_flags);
  proto_tree_add_item(flag_tree, hf_acn_pdu_flag_l, tvb, pdu_start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flag_tree, hf_acn_pdu_flag_v, tvb, pdu_start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flag_tree, hf_acn_pdu_flag_h, tvb, pdu_start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flag_tree, hf_acn_pdu_flag_d, tvb, pdu_start, 1, ENC_BIG_ENDIAN);

  /* Add PDU Length item */
  proto_tree_add_uint(pdu_tree, hf_acn_pdu_length, tvb, pdu_start, pdu_flvh_length, pdu_length);

  /* Set vector offset */
  if (pdu_flags & ACN_PDU_FLAG_V) {
    /* use new values */
    vector_offset = offset;
    last_pdu_offsets->vector = offset;
    offset          += 4;
    pdu_flvh_length += 4;
  } else {
    /* use last values */
    vector_offset = last_pdu_offsets->vector;
  }
  /* offset should now be pointing to header (if one exists) */

  /* Add Vector item */
  vector = tvb_get_ntohl(tvb, vector_offset);
  proto_tree_add_item(pdu_tree, hf_acn_dmx_vector, tvb, vector_offset, 4, ENC_BIG_ENDIAN);
  /* vector_offset +=4; */

  /* Add Vector item to tree*/
  name = val_to_str(vector, acn_dmx_vector_vals, "not valid (%d)");
  proto_item_append_text(ti, ": %s", name);

  /* NO HEADER DATA ON THESE* (at least so far) */

  /* Adjust data */
  if (pdu_flags & ACN_PDU_FLAG_D) {
    /* use new values */
    data_offset = offset;
    data_length = pdu_length - pdu_flvh_length;
    last_pdu_offsets->data = offset;
    last_pdu_offsets->data_length = data_length;
  } else {
    /* use last values */
    data_offset = last_pdu_offsets->data;
    /*data_length = last_pdu_offsets->data_length;*/
  }

  /* process based on vector */
  switch (vector) {
    case 0x02:
      if (protocol_id==ACN_PROTOCOL_ID_DMX_2) {
        proto_tree_add_item(pdu_tree, hf_acn_dmx_source_name, tvb, data_offset, 64, ENC_UTF_8|ENC_NA);
        data_offset += 64;
      } else{
        proto_tree_add_item(pdu_tree, hf_acn_dmx_source_name, tvb, data_offset, 32, ENC_UTF_8|ENC_NA);
        data_offset += 32;
      }

      priority = tvb_get_guint8(tvb, data_offset);
      proto_tree_add_item(pdu_tree, hf_acn_dmx_priority, tvb, data_offset, 1, ENC_BIG_ENDIAN);
      data_offset += 1;

      if (protocol_id==ACN_PROTOCOL_ID_DMX_2) {
        proto_tree_add_item(pdu_tree, hf_acn_dmx_2_reserved, tvb, data_offset, 2, ENC_BIG_ENDIAN);
        data_offset += 2;
      }

      sequence = tvb_get_guint8(tvb, data_offset);
      proto_tree_add_item(pdu_tree, hf_acn_dmx_sequence_number, tvb, data_offset, 1, ENC_BIG_ENDIAN);
      data_offset += 1;

      if (protocol_id == ACN_PROTOCOL_ID_DMX_2) {
        option_flags = tvb_get_guint8(tvb, data_offset);
        pi = proto_tree_add_uint(pdu_tree, hf_acn_dmx_2_options, tvb, data_offset, 1, option_flags);
        flag_tree = proto_item_add_subtree(pi, ett_acn_dmx_2_options);
        proto_tree_add_item(flag_tree, hf_acn_dmx_2_option_p, tvb, data_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(flag_tree, hf_acn_dmx_2_option_s, tvb, data_offset, 1, ENC_BIG_ENDIAN);
        data_offset += 1;
      }

      universe = tvb_get_ntohs(tvb, data_offset);
      proto_tree_add_item(pdu_tree, hf_acn_dmx_universe       , tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;

      /* add universe to info */
      col_append_fstr(pinfo->cinfo,COL_INFO, ", Universe %d, Seq %3d", universe, sequence );
      proto_item_append_text(ti, ", Universe: %d, Priority: %d", universe, priority);

      /*data_offset =*/ dissect_acn_dmx_data_pdu(protocol_id, tvb, pinfo, pdu_tree, data_offset, &pdu_offsets);

      break;
  }
  return pdu_start + pdu_length;
}

/******************************************************************************/
/* Dissect SDT Base PDU                                                       */
static guint32
dissect_acn_sdt_base_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets)
{
  /* common to all pdu */
  guint8           pdu_flags;
  guint32          pdu_start;
  guint32          pdu_length;
  guint32          pdu_flvh_length; /* flags, length, vector, header */
  acn_pdu_offsets  pdu_offsets = {0,0,0,0,0};
  guint8           octet;
  guint32          length1;
  guint32          length2;
  guint32          length3;
  guint32          vector_offset;
  guint32          data_offset;
  guint32          end_offset;
  guint32          old_offset;
  guint32          data_length;

  proto_item      *ti, *pi;
  proto_tree      *pdu_tree;
  proto_tree      *flag_tree;

  /* this pdu */
  const gchar     *name;
  guint32          vector;
  guint32          member_id;

  /* save start of pdu block */
  pdu_start         = offset;
  pdu_offsets.start = pdu_start;

  /* get PDU flags and length flag first */
  octet     = tvb_get_guint8(tvb, offset++);
  pdu_flags = octet & 0xf0;
  length1   = octet & 0x0f;     /* bottom 4 bits only */
  length2   = tvb_get_guint8(tvb, offset++);

  /* if length flag is set, then we have a 20 bit length else we have a 12 bit */
  /* flvh = flags, length, vector, header */
  if (pdu_flags & ACN_PDU_FLAG_L) {
    length3 = tvb_get_guint8(tvb, offset);
    offset += 1;
    pdu_length      = length3 | (length2 << 8) | (length1 << 16);
    pdu_flvh_length = 3;
  } else {
    pdu_length = length2 | (length1 << 8);
    pdu_flvh_length = 2;
  }
  /* offset should now be pointing to vector (if one exists) */

  /* Add pdu item and tree */
  ti = proto_tree_add_item(tree, hf_acn_pdu, tvb, pdu_start, pdu_length, ENC_NA);
  pdu_tree = proto_item_add_subtree(ti, ett_acn_sdt_base_pdu);

  /* Add flag item and tree */
  pi = proto_tree_add_uint(pdu_tree, hf_acn_pdu_flags, tvb, pdu_start, 1, pdu_flags);
  flag_tree = proto_item_add_subtree(pi, ett_acn_pdu_flags);
  proto_tree_add_item(flag_tree, hf_acn_pdu_flag_l, tvb, pdu_start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flag_tree, hf_acn_pdu_flag_v, tvb, pdu_start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flag_tree, hf_acn_pdu_flag_h, tvb, pdu_start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flag_tree, hf_acn_pdu_flag_d, tvb, pdu_start, 1, ENC_BIG_ENDIAN);

  /* Add PDU Length item */
  proto_tree_add_uint(pdu_tree, hf_acn_pdu_length, tvb, pdu_start, pdu_flvh_length, pdu_length);

  /* Set vector offset */
  if (pdu_flags & ACN_PDU_FLAG_V) {
    /* use new values */
    vector_offset = offset;
    last_pdu_offsets->vector = offset;
    offset += 1;
    pdu_flvh_length++;
  } else {
    /* use last values */
    vector_offset = last_pdu_offsets->vector;
  }
  /* offset should now be pointing to header (if one exists) */

  /* Add Vector item */
  vector = tvb_get_guint8(tvb, vector_offset);
  proto_tree_add_uint(pdu_tree, hf_acn_sdt_vector, tvb, vector_offset, 1, vector);

  /* Add Vector item to tree*/
  name = val_to_str(vector, acn_sdt_vector_vals, "not valid (%d)");
  proto_item_append_text(ti, ": ");
  proto_item_append_text(ti, "%s", name);

  /* NO HEADER DATA ON THESE* (at least so far) */

  /* Adjust data */
  if (pdu_flags & ACN_PDU_FLAG_D) {
    /* use new values */
    data_offset = offset;
    data_length = pdu_length - pdu_flvh_length;
    last_pdu_offsets->data = offset;
    last_pdu_offsets->data_length = data_length;
  } else {
    /* use last values */
    data_offset = last_pdu_offsets->data;
    data_length = last_pdu_offsets->data_length;
  }
  end_offset = data_offset + data_length;

  /* process based on vector */
  switch (vector) {
    case ACN_SDT_VECTOR_UNKNOWN:
      break;
    case ACN_SDT_VECTOR_REL_WRAP:
    case ACN_SDT_VECTOR_UNREL_WRAP:
      proto_tree_add_item(pdu_tree, hf_acn_channel_number,           tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_total_sequence_number,    tvb, data_offset, 4, ENC_BIG_ENDIAN);
      data_offset += 4;
      proto_tree_add_item(pdu_tree, hf_acn_reliable_sequence_number, tvb, data_offset, 4, ENC_BIG_ENDIAN);
      data_offset += 4;
      proto_tree_add_item(pdu_tree, hf_acn_oldest_available_wrapper, tvb, data_offset, 4, ENC_BIG_ENDIAN);
      data_offset += 4;
      proto_tree_add_item(pdu_tree, hf_acn_first_memeber_to_ack,     tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_last_memeber_to_ack,      tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_mak_threshold,            tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;

      while (data_offset < end_offset) {
        old_offset = data_offset;
        data_offset = dissect_acn_sdt_client_pdu(tvb, pinfo, pdu_tree, data_offset, &pdu_offsets);
        if (data_offset == old_offset) break;
      }
      break;
    case ACN_SDT_VECTOR_CHANNEL_PARAMS:
      break;
    case ACN_SDT_VECTOR_JOIN:
      proto_tree_add_item(pdu_tree, hf_acn_cid,                      tvb, data_offset, 16, ENC_BIG_ENDIAN);
      data_offset += 16;
      proto_tree_add_item(pdu_tree, hf_acn_member_id,                tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_channel_number,           tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_reciprocal_channel,       tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_total_sequence_number,    tvb, data_offset, 4, ENC_BIG_ENDIAN);
      data_offset += 4;
      proto_tree_add_item(pdu_tree, hf_acn_reliable_sequence_number, tvb, data_offset, 4, ENC_BIG_ENDIAN);
      data_offset += 4;
      data_offset = acn_add_address(tvb, pinfo, pdu_tree, data_offset, "Destination Address:");
      data_offset = acn_add_channel_parameter(tvb, pinfo, pdu_tree, data_offset);
      /*data_offset =*/ acn_add_expiry(tvb, pinfo, pdu_tree, data_offset, hf_acn_adhoc_expiry);
      break;
    case ACN_SDT_VECTOR_JOIN_REFUSE:
      pi = proto_tree_add_item(pdu_tree, hf_acn_cid,                  tvb, data_offset, 16, ENC_BIG_ENDIAN);
      data_offset += 16;
      proto_item_append_text(pi, "(Leader)");
      proto_tree_add_item(pdu_tree, hf_acn_channel_number,            tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_member_id,                 tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_reliable_sequence_number,  tvb, data_offset, 4, ENC_BIG_ENDIAN);
      data_offset += 4;
      proto_tree_add_item(pdu_tree, hf_acn_refuse_code,               tvb, data_offset, 1, ENC_BIG_ENDIAN);
      /*data_offset ++;*/
      break;
    case ACN_SDT_VECTOR_JOIN_ACCEPT:
      pi = proto_tree_add_item(pdu_tree, hf_acn_cid, tvb, data_offset, 16, ENC_BIG_ENDIAN);
      data_offset += 16;
      proto_item_append_text(pi, "(Leader)");
      proto_tree_add_item(pdu_tree, hf_acn_channel_number, tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_member_id, tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_reliable_sequence_number, tvb, data_offset, 4, ENC_BIG_ENDIAN);
      data_offset += 4;
      proto_tree_add_item(pdu_tree, hf_acn_reciprocal_channel, tvb, data_offset, 2, ENC_BIG_ENDIAN);
      /*data_offset += 2;*/
      break;
    case ACN_SDT_VECTOR_LEAVE:
      break;
    case ACN_SDT_VECTOR_LEAVING:
      pi = proto_tree_add_item(pdu_tree, hf_acn_cid,                 tvb, data_offset, 16, ENC_BIG_ENDIAN);
      data_offset += 16;
      proto_item_append_text(pi, "(Leader)");
      proto_tree_add_item(pdu_tree, hf_acn_channel_number,           tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_member_id,                tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_reliable_sequence_number, tvb, data_offset, 4, ENC_BIG_ENDIAN);
      data_offset += 4;
      proto_tree_add_item(pdu_tree, hf_acn_reason_code,              tvb, data_offset, 1, ENC_BIG_ENDIAN);
      /* offset += 1; */
      break;
    case ACN_SDT_VECTOR_CONNECT:
      break;
    case ACN_SDT_VECTOR_CONNECT_ACCEPT:
      break;
    case ACN_SDT_VECTOR_CONNECT_REFUSE:
      break;
    case ACN_SDT_VECTOR_DISCONNECT:
      break;
    case ACN_SDT_VECTOR_DISCONNECTING:
      break;
    case ACN_SDT_VECTOR_ACK:
      break;
    case ACN_SDT_VECTOR_NAK:
      pi = proto_tree_add_item(pdu_tree, hf_acn_cid,                 tvb, data_offset, 16, ENC_BIG_ENDIAN);
      data_offset += 16;
      proto_item_append_text(pi, "(Leader)");
      proto_tree_add_item(pdu_tree, hf_acn_channel_number,           tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_member_id,                tvb, data_offset, 2, ENC_BIG_ENDIAN);
      data_offset += 2;
      proto_tree_add_item(pdu_tree, hf_acn_reliable_sequence_number, tvb, data_offset, 4, ENC_BIG_ENDIAN);
      data_offset += 4;
      proto_tree_add_item(pdu_tree, hf_acn_first_missed_sequence,    tvb, data_offset, 4, ENC_BIG_ENDIAN);
      data_offset += 4;
      proto_tree_add_item(pdu_tree, hf_acn_last_missed_sequence,     tvb, data_offset, 4, ENC_BIG_ENDIAN);
      /*data_offset += 4;*/
      break;
    case ACN_SDT_VECTOR_GET_SESSION:
      proto_tree_add_item(pdu_tree, hf_acn_cid, tvb, data_offset, 16, ENC_BIG_ENDIAN);
      /*data_offset += 16;*/
      break;
    case ACN_SDT_VECTOR_SESSIONS:
      member_id = tvb_get_ntohs(tvb, data_offset);
      switch (member_id) {
        case 0:
          /*data_offset =*/ acn_add_channel_owner_info_block(tvb, pinfo, pdu_tree, data_offset);
          break;
        case 1:
          /*data_offset =*/ acn_add_channel_member_info_block(tvb, pinfo, pdu_tree, data_offset);
          break;
      }
      break;
  }

  return pdu_start + pdu_length;
}

/******************************************************************************/
/* Dissect Root PDU                                                           */
static guint32
dissect_acn_root_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, acn_pdu_offsets *last_pdu_offsets)
{
  /* common to all pdu */
  guint8           pdu_flags;
  guint32          pdu_start;
  guint32          pdu_length;
  guint32          pdu_flvh_length; /* flags, length, vector, header */
  acn_pdu_offsets  pdu_offsets = {0,0,0,0,0};
  guint8           octet;
  guint32          length1;
  guint32          length2;
  guint32          length3;
  guint32          vector_offset;
  guint32          header_offset;
  guint32          data_offset;
  guint32          end_offset;
  guint32          old_offset;
  guint32          data_length;

  proto_item      *ti, *pi;
  proto_tree      *pdu_tree;
  proto_tree      *flag_tree;

  /* this pdu */
  guint32          protocol_id;
  e_guid_t         guid;

  /* save start of pdu block */
  pdu_start         = offset;
  pdu_offsets.start = pdu_start;

  /* get PDU flags and length flag first */
  octet     = tvb_get_guint8(tvb, offset++);
  pdu_flags = octet & 0xf0;
  length1   = octet & 0x0f;     /* bottom 4 bits only */
  length2   = tvb_get_guint8(tvb, offset++);

  /* if length flag is set, then we have a 20 bit length else we have a 12 bit */
  /* flvh = flags, length, vector, header */
  if (pdu_flags & ACN_PDU_FLAG_L) {
    length3 = tvb_get_guint8(tvb, offset);
    offset += 1;
    pdu_length = length3 | (length2 << 8) | (length1 << 16);
    pdu_flvh_length = 3;
  } else {
    pdu_length = length2 | (length1 << 8);
    pdu_flvh_length = 2;
  }
  /* offset should now be pointing to vector (if one exists) */

  /* Add pdu item and tree */
  ti = proto_tree_add_item(tree, hf_acn_pdu, tvb, pdu_start, pdu_length, ENC_NA);
  pdu_tree = proto_item_add_subtree(ti, ett_acn_root_pdu);

  /* Add flag item and tree */
  pi = proto_tree_add_uint(pdu_tree, hf_acn_pdu_flags, tvb, pdu_start, 1, pdu_flags);
  flag_tree = proto_item_add_subtree(pi, ett_acn_pdu_flags);
  proto_tree_add_item(flag_tree, hf_acn_pdu_flag_l, tvb, pdu_start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flag_tree, hf_acn_pdu_flag_v, tvb, pdu_start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flag_tree, hf_acn_pdu_flag_h, tvb, pdu_start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(flag_tree, hf_acn_pdu_flag_d, tvb, pdu_start, 1, ENC_BIG_ENDIAN);

  /* Add PDU Length item */
  proto_tree_add_uint(pdu_tree, hf_acn_pdu_length, tvb, pdu_start, pdu_flvh_length, pdu_length);

  /* Set vector offset */
  if (pdu_flags & ACN_PDU_FLAG_V) {
    /* use new values */
    vector_offset = offset;
    last_pdu_offsets->vector = offset;
    offset += 4;
    pdu_flvh_length += 4;
  } else {
    /* use last values */
    vector_offset = last_pdu_offsets->vector;
  }
  /* offset should now be pointing to header (if one exists) */

  /* Get Protocol ID (vector) */
  protocol_id = tvb_get_ntohl(tvb, vector_offset);
  proto_tree_add_uint(pdu_tree, hf_acn_protocol_id, tvb, vector_offset, 4, protocol_id);

  /* process based on protocol_id */
  switch (protocol_id) {
    case ACN_PROTOCOL_ID_DMX:
    case ACN_PROTOCOL_ID_DMX_2:
      if (global_acn_dmx_enable) {
        proto_item_append_text(ti,": Root DMX");

        /* Set header offset */
        if (pdu_flags & ACN_PDU_FLAG_H) {
          /* use new values */
          header_offset = offset;
          last_pdu_offsets->header = offset;
          offset += 16;
          pdu_flvh_length += 16;
        } else {
          /* use last values */
          header_offset = last_pdu_offsets->header;
        }
        /* offset should now be pointing to data (if one exists) */

        /* get Header (CID) 16 bytes */
        tvb_get_guid(tvb, header_offset, &guid, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, ", Src: %s", guid_to_str(wmem_packet_scope(), &guid));

        /* add cid to info */
        col_add_fstr(pinfo->cinfo,COL_INFO, "CID %s", guid_to_str(wmem_packet_scope(), &guid));

        proto_tree_add_item(pdu_tree, hf_acn_cid, tvb, header_offset, 16, ENC_BIG_ENDIAN);
        /*header_offset += 16;*/

        /* Adjust data */
        if (pdu_flags & ACN_PDU_FLAG_D) {
          /* use new values */
          data_offset = offset;
          data_length = pdu_length - pdu_flvh_length;
          last_pdu_offsets->data = offset;
          last_pdu_offsets->data_length = data_length;
        } else {
          /* use last values */
          data_offset = last_pdu_offsets->data;
          data_length = last_pdu_offsets->data_length;
        }
        end_offset = data_offset + data_length;

        /* adjust for what we used */
        while (data_offset < end_offset) {
          old_offset = data_offset;
          data_offset = dissect_acn_dmx_pdu(protocol_id, tvb, pinfo, pdu_tree, data_offset, &pdu_offsets);
          if (data_offset == old_offset) break;
        }
      }
      break;
    case ACN_PROTOCOL_ID_SDT:
      /* Adjust header */
      proto_item_append_text(ti,": Root SDT");

      /* Set header offset */
      if (pdu_flags & ACN_PDU_FLAG_H) {
        /* use new values */
        header_offset = offset;
        last_pdu_offsets->header = offset;
        offset += 16;
        pdu_flvh_length += 16;
      } else {
        /* use last values */
        header_offset = last_pdu_offsets->header;
      }
      /* offset should now be pointing to data (if one exists) */

      /* get Header (CID) 16 bytes */
      tvb_get_guid(tvb, header_offset, &guid, ENC_BIG_ENDIAN);
      proto_item_append_text(ti, ", Src: %s", guid_to_str(wmem_packet_scope(), &guid));

      proto_tree_add_item(pdu_tree, hf_acn_cid, tvb, header_offset, 16, ENC_BIG_ENDIAN);
      /*header_offset += 16;*/

      /* Adjust data */
      if (pdu_flags & ACN_PDU_FLAG_D) {
        /* use new values */
        data_offset = offset;
        data_length = pdu_length - pdu_flvh_length;
        last_pdu_offsets->data = offset;
        last_pdu_offsets->data_length = data_length;
      } else {
        /* use last values */
        data_offset = last_pdu_offsets->data;
        data_length = last_pdu_offsets->data_length;
      }
      end_offset = data_offset + data_length;

      /* adjust for what we used */
      while (data_offset < end_offset) {
        old_offset = data_offset;
        data_offset = dissect_acn_sdt_base_pdu(tvb, pinfo, pdu_tree, data_offset, &pdu_offsets);
        if (data_offset == old_offset) break;
      }
      break;
  }

  return pdu_start + pdu_length;
}

/******************************************************************************/
/* Dissect ACN                                                                */
static int
dissect_acn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item      *ti;
  proto_tree      *acn_tree;
  guint32          data_offset = 0;
  guint32          old_offset;
  guint32          end_offset;
  acn_pdu_offsets  pdu_offsets = {0,0,0,0,0};

/*   if (!is_acn(tvb)) { */
/*     return 0;         */
/*   }                   */

  /* Set the protocol column */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ACN");

  col_add_fstr(pinfo->cinfo,COL_INFO, "ACN [Src Port: %d, Dst Port: %d]", pinfo->srcport, pinfo->destport );

  ti = proto_tree_add_item(tree, proto_acn, tvb, 0, -1, ENC_NA);
  acn_tree = proto_item_add_subtree(ti, ett_acn);

  /* add preamble, postamble and ACN Packet ID */
  proto_tree_add_item(acn_tree, hf_acn_preamble_size, tvb, data_offset, 2, ENC_BIG_ENDIAN);
  data_offset += 2;
  proto_tree_add_item(acn_tree, hf_acn_postamble_size, tvb, data_offset, 2, ENC_BIG_ENDIAN);
  data_offset += 2;
  proto_tree_add_item(acn_tree, hf_acn_packet_identifier, tvb, data_offset, 12, ENC_UTF_8|ENC_NA);
  data_offset += 12;

  /* one past the last byte */
  end_offset = data_offset + tvb_reported_length_remaining(tvb, data_offset);
  while (data_offset < end_offset) {
    old_offset = data_offset;
    data_offset = dissect_acn_root_pdu(tvb, pinfo, acn_tree, data_offset, &pdu_offsets);
    if (data_offset == old_offset) break;
  }
  return tvb_reported_length(tvb);
}

/******************************************************************************/
/* Register protocol                                                          */
void
proto_register_acn(void)
{
  static hf_register_info hf[] = {
    /**************************************************************************/
    /* In alphabetical order */
    /* Address Type */
    /* PDU flags*/
    { &hf_acn_ip_address_type,
      { "Addr Type", "acn.ip_address_type",
        FT_UINT8, BASE_DEC, VALS(acn_ip_address_type_vals), 0x0,
        NULL, HFILL }
    },
    /* Association */
    { &hf_acn_association,
      { "Association", "acn.association",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* Channel Number */
    { &hf_acn_channel_number,
      { "Channel Number", "acn.channel_number",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* CID */
    { &hf_acn_cid,
      { "CID", "acn.cid",
        FT_GUID, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* Client Protocol ID */
#if 0
    { &hf_acn_client_protocol_id,
      { "Client Protocol ID", "acn.client_protocol_id",
        FT_UINT32, BASE_DEC, VALS(acn_protocol_id_vals), 0x0,
        NULL, HFILL }
    },
#endif
    /* DMP data */
    { &hf_acn_data,
      { "Data", "acn.dmp_data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_acn_data8,
      { "Addr", "acn.dmp_data8",
        FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
        "Data8", HFILL }
    },
    { &hf_acn_data16,
      { "Addr", "acn.dmp_data16",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        "Data16", HFILL }
    },
    { &hf_acn_data24,
      { "Addr", "acn.dmp_data24",
        FT_UINT24, BASE_DEC_HEX, NULL, 0x0,
        "Data24", HFILL }
    },
    { &hf_acn_data32,
      { "Addr", "acn.dmp_data32",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
        "Data32", HFILL }
    },

    /* DMP Address type*/
#if 0
    { &hf_acn_dmp_adt,
      { "Address and Data Type", "acn.dmp_adt",
        FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
#endif
    { &hf_acn_dmp_adt_a,
      { "Size", "acn.dmp_adt_a",
        FT_UINT8, BASE_DEC, VALS(acn_dmp_adt_a_vals), 0x03,
        NULL, HFILL }
    },
    { &hf_acn_dmp_adt_d,
      { "Data Type", "acn.dmp_adt_d",
        FT_UINT8, BASE_DEC, VALS(acn_dmp_adt_d_vals), 0x30,
        NULL, HFILL }
    },
    { &hf_acn_dmp_adt_r,
      { "Relative", "acn.dmp_adt_r",
        FT_UINT8, BASE_DEC, VALS(acn_dmp_adt_r_vals), 0x40,
        NULL, HFILL }
    },
    { &hf_acn_dmp_adt_v,
      { "Virtual", "acn.dmp_adt_v",
        FT_UINT8, BASE_DEC, VALS(acn_dmp_adt_v_vals), 0x80,
        NULL, HFILL }
    },
    { &hf_acn_dmp_adt_x,
      { "Reserved", "acn.dmp_adt_x",
        FT_UINT8, BASE_DEC, NULL, 0x0c,
        NULL, HFILL }
    },

    /* DMP Reason Code */
    { &hf_acn_dmp_reason_code,
      { "Reason Code", "acn.dmp_reason_code",
        FT_UINT8, BASE_DEC, VALS(acn_dmp_reason_code_vals), 0x0,
        NULL, HFILL }
    },

    /* DMP Vector */
    { &hf_acn_dmp_vector,
      { "DMP Vector", "acn.dmp_vector",
        FT_UINT8, BASE_DEC, VALS(acn_dmp_vector_vals), 0x0,
        NULL, HFILL }
    },

    { &hf_acn_dmp_actual_address,
      { "Actual Address", "acn.dmp_actual_address",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_acn_dmp_virtual_address,
      { "Virtual Address", "acn.dmp_virtual_address",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_acn_dmp_actual_address_first,
      { "Actual Address First", "acn.dmp_actual_address_first",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_acn_dmp_virtual_address_first,
      { "Virtual Address First", "acn.dmp_virtual_address_first",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },

    /* Expiry */
    { &hf_acn_expiry,
      { "Expiry", "acn.expiry",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* First Member to ACK */
    { &hf_acn_first_memeber_to_ack,
      { "First Member to ACK", "acn.first_member_to_ack",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* First Missed Sequence */
    { &hf_acn_first_missed_sequence,
      { "First Missed Sequence", "acn.first_missed_sequence",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* IPV4 */
    { &hf_acn_ipv4,
      { "IPV4", "acn.ipv4",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* IPV6 */
    { &hf_acn_ipv6,
      { "IPV6", "acn.ipv6",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* Last Member to ACK */
    { &hf_acn_last_memeber_to_ack,
      { "Last Member to ACK", "acn.last_member_to_ack",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* Last Missed Sequence */
    { &hf_acn_last_missed_sequence,
      { "Last Missed Sequence", "acn.last_missed_sequence",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* MAK threshold */
    { &hf_acn_mak_threshold,
      { "MAK Threshold", "acn.mak_threshold",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* MemberID */
    { &hf_acn_member_id,
      { "Member ID", "acn.member_id",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* NAK Holdoff */
    { &hf_acn_nak_holdoff,
      { "NAK holdoff (ms)", "acn.nak_holdoff",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* NAK Max Wait */
    { &hf_acn_nak_max_wait,
      { "NAK Max Wait (ms)", "acn.nak_max_wait",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* NAK Modulus */
    { &hf_acn_nak_modulus,
      { "NAK Modulus", "acn.nak_modulus",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* NAK Outbound Flag */
    { &hf_acn_nak_outbound_flag,
      { "NAK Outbound Flag", "acn.nak_outbound_flag",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }
    },
    /* Oldest Available Wrapper */
    { &hf_acn_oldest_available_wrapper,
      { "Oldest Available Wrapper", "acn.oldest_available_wrapper",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* Preamble Sizet */
    { &hf_acn_preamble_size,
      { "Size of preamble", "acn.preamble_size",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Preamble size in bytes", HFILL }
    },
    /* Packet Identifier */
    { &hf_acn_packet_identifier,
      { "Packet Identifier", "acn.packet_identifier",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* PDU */
    { &hf_acn_pdu,
      { "PDU", "acn.pdu",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    /* PDU flags*/
    { &hf_acn_pdu_flags,
      { "Flags", "acn.pdu.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "PDU Flags", HFILL }
    },
    { &hf_acn_pdu_flag_d,
      { "Data", "acn.pdu.flag_d",
        FT_BOOLEAN, 8, NULL, ACN_PDU_FLAG_D,
        "Data flag", HFILL }
    },
    { &hf_acn_pdu_flag_h,
      { "Header", "acn.pdu.flag_h",
        FT_BOOLEAN, 8, NULL, ACN_PDU_FLAG_H,
        "Header flag", HFILL }
    },
    { &hf_acn_pdu_flag_l,
      { "Length", "acn.pdu.flag_l",
        FT_BOOLEAN, 8, NULL, ACN_PDU_FLAG_L,
        "Length flag", HFILL }
    },
    { &hf_acn_pdu_flag_v,
      { "Vector", "acn.pdu.flag_v",
        FT_BOOLEAN, 8, NULL, ACN_PDU_FLAG_V,
        "Vector flag", HFILL }
    },
    /* PDU Length */
    { &hf_acn_pdu_length,
      { "Length", "acn.pdu.length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "PDU Length", HFILL }
    },
    /* Port */
    { &hf_acn_port,
      { "Port", "acn.port",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* Postamble Size */
    { &hf_acn_postamble_size,
      { "Size of postamble", "acn.postamble_size",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Postamble size in bytes", HFILL }
    },
    /* Protocol ID */
    { &hf_acn_protocol_id,
      { "Protocol ID", "acn.protocol_id",
        FT_UINT32, BASE_DEC, VALS(acn_protocol_id_vals), 0x0,
        NULL, HFILL }
    },
    /* Reason Code */
    { &hf_acn_reason_code,
      { "Reason Code", "acn.reason_code",
        FT_UINT8, BASE_DEC, VALS(acn_reason_code_vals), 0x0,
        NULL, HFILL }
    },
    /* Reciprocal Channel */
    { &hf_acn_reciprocal_channel,
      { "Reciprocal Channel Number", "acn.reciprocal_channel",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        "Reciprocal Channel", HFILL }
    },
    /* Refuse Code */
    { &hf_acn_refuse_code,
      { "Refuse Code", "acn.refuse_code",
        FT_UINT8, BASE_DEC, VALS(acn_refuse_code_vals), 0x0,
        NULL, HFILL }
    },
    /* Reliable Sequence Number */
    { &hf_acn_reliable_sequence_number,
      { "Reliable Sequence Number", "acn.reliable_sequence_number",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    /* Ad-hoc Expiry */
    { &hf_acn_adhoc_expiry,
      { "Ad-hoc Expiry", "acn.adhoc_expiry",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    /* SDT Vector */
    { &hf_acn_sdt_vector,
      { "STD Vector", "acn.sdt_vector",
        FT_UINT8, BASE_DEC, VALS(acn_sdt_vector_vals), 0x0,
        NULL, HFILL }
    },

    /* DMX Vector */
    { &hf_acn_dmx_vector,
      { "Vector", "acn.dmx_vector",
        FT_UINT32, BASE_DEC, VALS(acn_dmx_vector_vals), 0x0,
        "DMX Vector", HFILL }
    },
    /* DMX Source Name */
    { &hf_acn_dmx_source_name,
      { "Source", "acn.dmx.source_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "DMX Source Name", HFILL }
    },

    /* DMX priority */
    { &hf_acn_dmx_priority,
      { "Priority", "acn.dmx.priority",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "DMX Priority", HFILL }
    },

    /* DMX 2 reserved */
    { &hf_acn_dmx_2_reserved,
      { "Reserved", "acn.dmx.reserved",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "DMX Reserved", HFILL }
    },

    /* DMX Sequence number */
    { &hf_acn_dmx_sequence_number,
      { "Seq No", "acn.dmx.seq_number",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "DMX Sequence Number", HFILL }
    },

    /* DMX 2 options */
    { &hf_acn_dmx_2_options,
      { "Options", "acn.dmx.options",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "DMX Options", HFILL }
    },

    { &hf_acn_dmx_2_option_p,
      { "Preview Data", "acn.dmx.option_p",
        FT_BOOLEAN, 8, NULL, ACN_DMX_OPTION_P,
        "Preview Data flag", HFILL }
    },

    { &hf_acn_dmx_2_option_s,
      { "Stream Terminated", "acn.dmx.option_s",
        FT_BOOLEAN, 8, NULL, ACN_DMX_OPTION_S,
        "Stream Terminated flag", HFILL }
    },

    /* DMX Universe */
    { &hf_acn_dmx_universe,
      { "Universe", "acn.dmx.universe",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "DMX Universe", HFILL }
    },

    /* DMX Start Code */
    { &hf_acn_dmx_start_code,
      { "Start Code", "acn.dmx.start_code",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        "DMX Start Code", HFILL }
    },

    /* DMX 2 First Property Address */
    { &hf_acn_dmx_2_first_property_address,
      { "First Property Address", "acn.dmx.start_code",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        "DMX First Property Address", HFILL }
    },

    /* DMX Address Increment */
    { &hf_acn_dmx_increment,
      { "Increment", "acn.dmx.increment",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "DMX Increment", HFILL }
    },

    /* DMX Packet Count */
    { &hf_acn_dmx_count,
      { "Count", "acn.dmx.count",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "DMX Count", HFILL }
    },

    /* DMX 2 Start Code */
    { &hf_acn_dmx_2_start_code,
      { "Start Code", "acn.dmx.start_code2",
        FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
        "DMX Start Code", HFILL }
    },

    /*
     * If you want the pretty-printed data in the field, for filtering
     * purposes, you have to make it an FT_STRING.
     *
     * If you want the raw data in the field, for filtering purposes,
     * you have to make it an FT_BYTES *AND* use "proto_tree_add_bytes_format()"
     * to put the pretty-printed data into the display but not the field.
     */
    { &hf_acn_dmx_data,
      { "Data", "acn.dmx.data",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },

    /* Session Count */
#if 0
    { &hf_acn_session_count,
      { "Session Count", "acn.session_count",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    },
#endif
    /* Total Sequence Number */
    { &hf_acn_total_sequence_number,
      { "Total Sequence Number", "acn.total_sequence_number",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }
    }
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_acn,
    &ett_acn_channel_owner_info_block,
    &ett_acn_channel_member_info_block,
    &ett_acn_channel_parameter,
    &ett_acn_address,
    &ett_acn_address_type,
    &ett_acn_pdu_flags,
    &ett_acn_dmp_pdu,
    &ett_acn_sdt_pdu,
    &ett_acn_sdt_client_pdu,
    &ett_acn_sdt_base_pdu,
    &ett_acn_root_pdu,
    &ett_acn_dmx_address,
    &ett_acn_dmx_2_options,
    &ett_acn_dmx_data_pdu,
    &ett_acn_dmx_pdu
  };

  module_t *acn_module;
  proto_acn = proto_register_protocol (
    "Architecture for Control Networks", /* name */
    "ACN",                               /* short name */
    "acn"                                /* abbrev */
    );

  proto_register_field_array(proto_acn, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  acn_module = prefs_register_protocol(proto_acn, NULL);
  prefs_register_obsolete_preference(acn_module, "heuristic_acn");

  prefs_register_bool_preference(acn_module, "dmx_enable",
                                 "Streaming DMX",
                                 "Enable Streaming DMX extension dissector (ANSI BSR E1.31)",
                                 &global_acn_dmx_enable);

  prefs_register_enum_preference(acn_module, "dmx_display_view",
                                 "DMX, display format",
                                 "Display format",
                                 &global_acn_dmx_display_view,
                                 dmx_display_view,
                                 TRUE);

  prefs_register_bool_preference(acn_module, "dmx_display_zeros",
                                 "DMX, display zeros",
                                 "Display zeros instead of dots",
                                 &global_acn_dmx_display_zeros);

  prefs_register_bool_preference(acn_module, "dmx_display_leading_zeros",
                                 "DMX, display leading zeros",
                                 "Display leading zeros on levels",
                                 &global_acn_dmx_display_leading_zeros);

  prefs_register_enum_preference(acn_module, "dmx_display_line_format",
                                 "DMX, display line format",
                                 "Display line format",
                                 &global_acn_dmx_display_line_format,
                                 dmx_display_line_format,
                                 TRUE);
}


/******************************************************************************/
/* Register handoff                                                           */
void
proto_reg_handoff_acn(void)
{
  /* dissector_handle_t acn_handle; */
  /* acn_handle = create_dissector_handle(dissect_acn, proto_acn); */
  /* dissector_add_for_decode_as("udp.port", acn_handle);                         */
  heur_dissector_add("udp", dissect_acn_heur, "ACN over UDP", "acn_udp", proto_acn, HEURISTIC_DISABLE);
}

/*
 * Editor modelines
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
