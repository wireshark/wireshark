/* packet-vuze-dht.c
 * Routines for Vuze-DHT dissection
 * Copyright 2011, Xiao Xiangquan <xiaoxiangquan@gmail.com>
 *
 * $Id$
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

#include "config.h"
#include <epan/packet.h>
#include <epan/prefs.h>

#define DEFAULT_UDP_PORT 11273

/* --- protocol specification:
 * http://wiki.vuze.com/w/Distributed_hash_table
 */

/* protocol versions */
enum {
  PV_DIV_AND_CONT           =  6,
  PV_ANTI_SPOOF             =  7,
  PV_ANTI_SPOOF2            =  8,
  PV_FIX_ORIGINATOR         =  9,
  PV_NETWORKS               =  9,
  PV_VIVALDI                = 10,
  PV_REMOVE_DIST_ADD_VER    = 11,
  PV_XFER_STATUS            = 12,
  PV_SIZE_ESTIMATE          = 13,
  PV_VENDOR_ID              = 14,
  PV_BLOCK_KEYS             = 14,
  PV_GENERIC_NETPOS         = 15,
  PV_VIVALDI_FINDVALUE      = 16,
  PV_ANON_VALUES            = 17,
  PV_CVS_FIX_OVERLOAD_V1    = 18,
  PV_CVS_FIX_OVERLOAD_V2    = 19,
  PV_MORE_STATS             = 20,
  PV_CVS_FIX_OVERLOAD_V3    = 21,
  PV_MORE_NODE_STATUS       = 22,
  PV_LONGER_LIFE            = 23,
  PV_REPLICATION_CONTROL    = 24,
  PV_RESTRICT_ID_PORTS      = 32,
  PV_RESTRICT_ID_PORTS2     = 33,
  PV_RESTRICT_ID_PORTS2X    = 34,
  PV_RESTRICT_ID_PORTS2Y    = 35,
  PV_RESTRICT_ID_PORTS2Z    = 36,
  PV_RESTRICT_ID3           = 50
};

/* Type Length */
enum {
  TL_BYTE  =  1,
  TL_BOOL  =  1,
  TL_SHORT =  2,
  TL_INT   =  4,
  TL_IPv4  =  4,
  TL_LONG  =  8,
  TL_IPv6  = 16
};

/* Bool type */
enum {
  BT_FALSE = 0x0,
  BT_TRUE = 0x1
};
static const value_string vuze_dht_bool_type_vals[] = {
  { BT_FALSE, "False" },
  { BT_TRUE, "True" },
  { 0, NULL }
};

/* action type */
enum {
  AT_PING_REQUEST       = 1024,
  AT_PING_REPLY         = 1025,
  AT_STORE_REQUEST      = 1026,
  AT_STORE_REPLY        = 1027,
  AT_FIND_NODE_REQUEST  = 1028,
  AT_FIND_NODE_REPLY    = 1029,
  AT_FIND_VALUE_REQUEST = 1030,
  AT_FIND_VALUE_REPLY   = 1031,
  AT_ERROR_REPLY        = 1032,
  AT_KEY_BLOCK_REQUEST  = 1036,
  AT_KEY_BLOCK_REPLY    = 1037
};
static const value_string vuze_dht_action_type_vals[] = {
  { AT_PING_REQUEST,        "PING request" },
  { AT_PING_REPLY,          "PING reply" },
  { AT_STORE_REQUEST,       "STORE request" },
  { AT_STORE_REPLY,         "STORE reply" },
  { AT_FIND_NODE_REQUEST,   "FIND_NODE request" },
  { AT_FIND_NODE_REPLY,     "FIND_NODE reply" },
  { AT_FIND_VALUE_REQUEST,  "FIND_VALUE request" },
  { AT_FIND_VALUE_REPLY,    "FIND_VALUE reply" },
  { AT_ERROR_REPLY,         "ERROR reply" },
  { AT_KEY_BLOCK_REQUEST,   "kEY_BLOCK request" },
  { AT_KEY_BLOCK_REPLY,     "KEY_BLOCK reply" },
  { 0, NULL }
};

/* Contact type, must be 1(UDP) */
enum {
  CONTACT_UDP = 1
};
static const value_string vuze_dht_contact_type_vals[] = {
  { CONTACT_UDP, "UDP" },
  { 0, NULL }
};

/* Node type */
enum {
  NT_BOOTSTRAP_NODE = 0x0,
  NT_ORDINARY_NODE  = 0x1,
  NT_UNKNOWN_NODE   = 0xffffffff
};
static const value_string vuze_dht_node_type_vals[] = {
  { NT_BOOTSTRAP_NODE, "Bootstrap node" },
  { NT_ORDINARY_NODE,  "Ordinary node" },
  { NT_UNKNOWN_NODE,   "Unknown node" },
  { 0, NULL }
};

/* flag type */
enum {
    FT_SINGLE_VALUE = 0x00,
    FT_DOWNLOADING  = 0x01,
    FT_SEEDING      = 0x02,
    FT_MULTI_VALUE  = 0x04,
    FT_STATS        = 0x08
};
static const value_string vuze_dht_flag_type_vals[] = {
  { FT_SINGLE_VALUE, "Single value" },
  { FT_DOWNLOADING,  "Downloading" },
  { FT_SEEDING,      "Seeding" },
  { FT_MULTI_VALUE,  "Multi value" },
  { FT_STATS,        "Stats" },
  { 0, NULL }
};

/* error type */
enum {
  ET_WRONG_ADDRESS  = 1,
  ET_KEY_BLOCKED    = 2
};
static const value_string vuze_dht_error_type_vals[] = {
  { ET_WRONG_ADDRESS, "Originator's address stored in the request is incorrect" },
  { ET_KEY_BLOCKED,   "The requested key has been blocked" },
  { 0, NULL }
};

static int proto_vuze_dht = -1;

/* --- fields ---*/

/* address appears in contacts, request header, reply error */
static int hf_vuze_dht_address = -1;
static int hf_vuze_dht_address_len = -1;
static int hf_vuze_dht_address_v4 = -1;
static int hf_vuze_dht_address_v6 = -1;
static int hf_vuze_dht_address_port = -1;

/* contact appears in values, reply find_node, reply find_value */
static int hf_vuze_dht_contact = -1;
static int hf_vuze_dht_contact_type = -1;
static int hf_vuze_dht_proto_ver = -1;

/* value appears in reply find_value */
static int hf_vuze_dht_value = -1;
static int hf_vuze_dht_value_ver = -1;
static int hf_vuze_dht_value_created = -1;
static int hf_vuze_dht_value_bytes_count = -1;
static int hf_vuze_dht_value_bytes = -1;
static int hf_vuze_dht_value_flags = -1;
static int hf_vuze_dht_value_life_hours = -1;
static int hf_vuze_dht_value_replication_factor = -1;

/* firstly appear in request header */
static int hf_vuze_dht_connection_id = -1;
static int hf_vuze_dht_action = -1;
static int hf_vuze_dht_transaction_id = -1;
static int hf_vuze_dht_vendor_id = -1;
static int hf_vuze_dht_network_id = -1;
static int hf_vuze_dht_local_proto_ver = -1;
static int hf_vuze_dht_instance_id = -1;
static int hf_vuze_dht_time = -1;

/* firstly appear in reply ping */
static int hf_vuze_dht_network_coordinates_count = -1;
static int hf_vuze_dht_network_coordinates = -1;
static int hf_vuze_dht_network_coordinate = -1;
static int hf_vuze_dht_network_coordinate_type = -1;
static int hf_vuze_dht_network_coordinate_size = -1;
static int hf_vuze_dht_network_coordinate_data = -1;

/* firstly appear in request store */
static int hf_vuze_dht_spoof_id = -1;
static int hf_vuze_dht_keys_count = -1;
static int hf_vuze_dht_keys = -1;
static int hf_vuze_dht_key = -1;
static int hf_vuze_dht_key_len = -1;
static int hf_vuze_dht_key_data = -1;
static int hf_vuze_dht_value_group = -1;
static int hf_vuze_dht_value_groups = -1;
static int hf_vuze_dht_value_groups_count = -1;
static int hf_vuze_dht_values_count = -1;

/* firstly appear in reply store */
static int hf_vuze_dht_diversifications_len = -1;
static int hf_vuze_dht_diversifications = -1;

/* firstly appear in request find_node */
static int hf_vuze_dht_id_len = -1;
static int hf_vuze_dht_id = -1;
static int hf_vuze_dht_node_status = -1;
static int hf_vuze_dht_size = -1;

/* firstly appear in reply find_node */
static int hf_vuze_dht_node_type = -1;
static int hf_vuze_dht_contacts_count = -1;
static int hf_vuze_dht_contacts = -1;

/* firstly appear in request find_value */
static int hf_vuze_dht_flags = -1;
static int hf_vuze_dht_values_num = -1;
static int hf_vuze_dht_values_total = -1;
static int hf_vuze_dht_reads_per_min = -1;
static int hf_vuze_dht_diversification_type = -1;
static int hf_vuze_dht_max_values = -1;

/* firstly appear in reply find_value */
static int hf_vuze_dht_has_continuation = -1;
static int hf_vuze_dht_has_values = -1;

/* firstly appear in reply error */
static int hf_vuze_dht_error_type = -1;
static int hf_vuze_dht_key_block_request_len = -1;
static int hf_vuze_dht_key_block_request = -1;
static int hf_vuze_dht_signature_len = -1;
static int hf_vuze_dht_signature = -1;

/* trees */
static gint ett_vuze_dht = -1;
static gint ett_vuze_dht_address = -1;
static gint ett_vuze_dht_contacts = -1;
static gint ett_vuze_dht_contact = -1;
static gint ett_vuze_dht_keys = -1;
static gint ett_vuze_dht_key = -1;
static gint ett_vuze_dht_value_groups = -1;
static gint ett_vuze_dht_value_group = -1;
static gint ett_vuze_dht_value = -1;
static gint ett_vuze_dht_network_coordinates = -1;
static gint ett_vuze_dht_network_coordinate = -1;

/* port use */
static guint global_vuze_dht_udp_port = DEFAULT_UDP_PORT;

void proto_reg_handoff_vuze_dht(void);

/* --- Address format --------------

byte:          indicates length of the IP address (4 for IPv4, 16 for IPv6)
4 or 16 bytes: the address in network byte order
short:         port number

*/
static int
dissect_vuze_dht_address(tvbuff_t *tvb, packet_info _U_*pinfo, proto_tree *tree, int offset, const char* addr_name)
{
  guint8 ip_length;
  proto_tree *sub_tree;
  proto_item *ti;
  address addr;

  ip_length = tvb_get_guint8(tvb,offset);
  /* the decoded length is ip length+3, see the format above */
  ti = proto_tree_add_none_format(tree, hf_vuze_dht_address, tvb, offset, ip_length+3, "%s: ", addr_name );
  sub_tree = proto_item_add_subtree(ti, ett_vuze_dht_address);

  proto_tree_add_item(sub_tree, hf_vuze_dht_address_len, tvb, offset, TL_BYTE, ENC_BIG_ENDIAN);
  offset += TL_BYTE;

  switch(ip_length)
  {
  case TL_IPv4:
    proto_tree_add_item(sub_tree, hf_vuze_dht_address_v4, tvb, offset, ip_length, ENC_BIG_ENDIAN);
    TVB_SET_ADDRESS( &addr, AT_IPv4, tvb, offset, ip_length);
    break;
  case TL_IPv6:
    proto_tree_add_item(sub_tree, hf_vuze_dht_address_v6, tvb, offset, ip_length, ENC_NA);
    TVB_SET_ADDRESS( &addr, AT_IPv6, tvb, offset, ip_length);
    break;
  default:
    addr.type = AT_NONE;
    break;
  }
  offset += ip_length;

  proto_tree_add_item(sub_tree, hf_vuze_dht_address_port, tvb, offset, TL_SHORT, ENC_BIG_ENDIAN);
  proto_item_append_text( ti, "%s:%d", ep_address_to_str( &addr ), tvb_get_ntohs(tvb,offset) );
  offset += TL_SHORT;

  return offset;
}

/* --- Contact format --------------

byte:        indicates contact type, which must be UDP(1)
byte:        the contact's protocol version
7 or 19 bytes: Address

*/
static int
dissect_vuze_dht_contact(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  proto_item *ti;
  proto_tree *sub_tree;

  /* the decoded length is ip length+5, see the format above */
  ti = proto_tree_add_none_format( tree, hf_vuze_dht_contact, tvb, offset, tvb_get_guint8(tvb,offset+2)+5,
      "%s contact, version %d",
      val_to_str_const( tvb_get_guint8(tvb, offset), vuze_dht_contact_type_vals, "Unknown"),
      tvb_get_guint8(tvb, offset+1) );
  sub_tree = proto_item_add_subtree(ti, ett_vuze_dht_contact);

  proto_tree_add_item(sub_tree, hf_vuze_dht_contact_type, tvb, offset, TL_BYTE, ENC_BIG_ENDIAN);
  offset += TL_BYTE;
  proto_tree_add_item(sub_tree, hf_vuze_dht_proto_ver, tvb, offset, TL_BYTE, ENC_BIG_ENDIAN);
  offset += TL_BYTE;
  offset = dissect_vuze_dht_address( tvb, pinfo, sub_tree, offset, "Contact Address" );

  return offset;
}

/* --- Contact List --- */
static int
dissect_vuze_dht_contacts(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int contacts_count)
{
  proto_item *ti;
  proto_tree *sub_tree;
  int i;

  ti = proto_tree_add_none_format( tree, hf_vuze_dht_contacts, tvb, offset, 0, "%d contacts", contacts_count );
  sub_tree = proto_item_add_subtree(ti, ett_vuze_dht_contacts);
  for( i=0; i<contacts_count; i++ )
    offset = dissect_vuze_dht_contact( tvb, pinfo, sub_tree, offset );

  return offset;
}

/* --- Key format
 Name               | Type
 LENGTH               byte
 KEY                  byte[LENGTH]
 --- */
static int
dissect_vuze_dht_key(tvbuff_t *tvb, packet_info _U_*pinfo, proto_tree *tree, int offset)
{
  proto_item *ti;
  proto_tree *sub_tree;
  guint key_len;

  key_len = tvb_get_guint8( tvb, offset );
  ti = proto_tree_add_item( tree, hf_vuze_dht_key, tvb, offset, key_len+1, ENC_NA );
  sub_tree = proto_item_add_subtree(ti, ett_vuze_dht_key);

  proto_tree_add_item( sub_tree, hf_vuze_dht_key_len, tvb, offset, TL_BYTE, ENC_BIG_ENDIAN );
  offset += TL_BYTE;

  proto_tree_add_item( sub_tree, hf_vuze_dht_key_data, tvb, offset, key_len, ENC_NA );
  proto_item_append_text( ti, ": %d bytes ( %s )", key_len, tvb_bytes_to_str(tvb, offset, key_len ) );
  offset += key_len;

  return offset;
}

/* --- Keys List --- */
static int
dissect_vuze_dht_keys(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int keys_count)
{
  proto_item *ti;
  proto_tree *sub_tree;
  int i;

  ti = proto_tree_add_none_format( tree, hf_vuze_dht_keys, tvb, offset, 0, "%d keys", keys_count );
  sub_tree = proto_item_add_subtree(ti, ett_vuze_dht_keys);
  for( i=0; i<keys_count; i++ )
    offset = dissect_vuze_dht_key( tvb, pinfo, sub_tree, offset );

  return offset;
}

/* --- Value format --------------

Name             | Type  | Protocol version    | Note
VERSION            byte    >=REMOVE_DIST_ADD_VER  Version of the value. (details later)
CREATED            long    always                Creation time. Units unknown; probably milliseconds since the epoch.
VALUE_BYTES_COUNT  short   always                Number of bytes in the value.
VALUE_BYTES        bytes   always                The bytes of the value.
ORIGINATOR         contact always                presumably the node that created the value.
FLAGS              byte    always
LIFE_HOURS         byte    >=LONGER_LIFE          Hours for the value to live. (Details of how it's handled)
REPLICATION_FACTOR byte    >=REPLICATION_CONTROL  Per-value # of replicas to maintain.

If STATS are used in request, then some stats for the value are returned instead of value itself.
They are serialised as follows:
  0 (byte) - version,
  number of stored values for the key (int),
  total size of stored values (int),
  reads per minute (int),
  diversification type (byte).
*/
static int
dissect_vuze_dht_value(tvbuff_t *tvb, packet_info _U_*pinfo, proto_tree *tree, int offset, int ver )
{
  proto_item *ti;
  proto_tree *sub_tree;
  int value_ver = -1;

  ti = proto_tree_add_item( tree, hf_vuze_dht_value, tvb, offset, 0, ENC_NA );
  sub_tree = proto_item_add_subtree(ti, ett_vuze_dht_value);
  if( ver >= PV_REMOVE_DIST_ADD_VER )
  {
    proto_tree_add_item(sub_tree, hf_vuze_dht_value_ver, tvb, offset, TL_INT, ENC_BIG_ENDIAN);
    value_ver = tvb_get_ntohl( tvb, offset );
    offset += TL_INT;
  }
  /* It's a return for STATS */
  if( value_ver==0 )
  {
    proto_item_append_text( ti,
                            " (reply to STATS): %d values for the key, out of %d in total...",
                            tvb_get_ntohl(tvb, offset), tvb_get_ntohl(tvb, offset+TL_INT) );

    proto_tree_add_item(tree, hf_vuze_dht_values_num, tvb, offset, TL_INT, ENC_BIG_ENDIAN);
    offset += TL_INT;
    proto_tree_add_item(tree, hf_vuze_dht_values_total, tvb, offset, TL_INT, ENC_BIG_ENDIAN);
    offset += TL_INT;
    proto_tree_add_item(tree, hf_vuze_dht_reads_per_min, tvb, offset, TL_INT, ENC_BIG_ENDIAN);
    offset += TL_INT;
    proto_tree_add_item(tree, hf_vuze_dht_diversification_type, tvb, offset, TL_BYTE, ENC_BIG_ENDIAN);
    offset += TL_BYTE;
  }
  /* regular value */
  else
  {
    int value_bytes_count;

    proto_tree_add_item(sub_tree, hf_vuze_dht_value_created, tvb, offset, TL_LONG, ENC_BIG_ENDIAN);
    offset += TL_LONG;

    proto_tree_add_item(sub_tree, hf_vuze_dht_value_bytes_count, tvb, offset, TL_SHORT, ENC_BIG_ENDIAN);
    value_bytes_count = tvb_get_ntohs(tvb, offset);
    offset += TL_SHORT;

    proto_tree_add_item(sub_tree, hf_vuze_dht_value_bytes, tvb, offset, value_bytes_count, ENC_NA);
    proto_item_append_text( ti, ": %d bytes ( %s )", value_bytes_count, tvb_bytes_to_str(tvb, offset, value_bytes_count ) );
    offset += value_bytes_count;

    offset = dissect_vuze_dht_contact( tvb, pinfo, sub_tree, offset );

    proto_tree_add_item(sub_tree, hf_vuze_dht_value_flags, tvb, offset, TL_BYTE, ENC_BIG_ENDIAN);
    offset += TL_BYTE;
    proto_tree_add_item(sub_tree, hf_vuze_dht_value_life_hours, tvb, offset, TL_BYTE, ENC_BIG_ENDIAN);
    offset += TL_BYTE;
    proto_tree_add_item(sub_tree, hf_vuze_dht_value_replication_factor, tvb, offset, TL_BYTE, ENC_BIG_ENDIAN);
    offset += TL_BYTE;
  }

  return offset;
}

/* --- Values format
values_count        short
values              value[values_count]
 --- */
static int
dissect_vuze_dht_value_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int ver)
{
  proto_item *ti;
  proto_tree *sub_tree;
  int values_count;
  int i;

  values_count = tvb_get_ntohs( tvb, offset );

  ti = proto_tree_add_none_format( tree, hf_vuze_dht_value_group, tvb, offset, 0, "%d values", values_count );
  sub_tree = proto_item_add_subtree(ti, ett_vuze_dht_value_group);

  proto_tree_add_item( sub_tree, hf_vuze_dht_values_count, tvb, offset, TL_SHORT, ENC_BIG_ENDIAN );
  offset += TL_SHORT;

  for( i=0; i<values_count; i++ )
    offset = dissect_vuze_dht_value( tvb, pinfo, sub_tree, offset, ver );

  return offset;
}

/* --- Values Groups format
value_group[value_groups_count]
 --- */
static int
dissect_vuze_dht_value_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int value_groups_count, int ver)
{
  proto_item *ti;
  proto_tree *sub_tree;
  int i;

  ti = proto_tree_add_none_format( tree, hf_vuze_dht_value_groups, tvb, offset, 0, "%d value groups", value_groups_count );
  sub_tree = proto_item_add_subtree(ti, ett_vuze_dht_value_groups);
  for( i=0; i<value_groups_count; i++ )
    offset = dissect_vuze_dht_value_group( tvb, pinfo, sub_tree, offset, ver );

  return offset;
}

/* --- Network Coordinates format ------
Name               | Type
TYPE                 byte
SIZE                 byte
Network Coordinates  byte[SIZE]
 */
static int
dissect_vuze_dht_network_coordinate(tvbuff_t *tvb, packet_info _U_*pinfo, proto_tree *tree, int offset)
{
  proto_item *ti;
  proto_tree *sub_tree;
  guint coordinate_size;

  coordinate_size = tvb_get_guint8( tvb, offset+1 );

  ti = proto_tree_add_item( tree, hf_vuze_dht_network_coordinate, tvb, offset, coordinate_size+2, ENC_NA );
  sub_tree = proto_item_add_subtree(ti, ett_vuze_dht_network_coordinate);

  proto_item_append_text( ti, ": type %d, length %d ( %s )",
    tvb_get_guint8(tvb,offset), tvb_get_guint8(tvb,offset+TL_BYTE), tvb_bytes_to_str(tvb, offset+TL_BYTE+TL_BYTE, coordinate_size ) );

  proto_tree_add_item( sub_tree, hf_vuze_dht_network_coordinate_type, tvb, offset, TL_BYTE, ENC_BIG_ENDIAN );
  offset += TL_BYTE;
  proto_tree_add_item( sub_tree, hf_vuze_dht_network_coordinate_size, tvb, offset, TL_BYTE, ENC_BIG_ENDIAN );
  offset += TL_BYTE;
  proto_tree_add_item( sub_tree, hf_vuze_dht_network_coordinate_data, tvb, offset, coordinate_size, ENC_NA );
  offset += coordinate_size;

  return offset;
}

/* --- Network Coordinates List ---
Name                     | Type              | Protocol version
Network Coordinates Count  byte                >=PV_GENERIC_NETPOS
Network Coordinates        Network Coordinate  >=PV_GENERIC_NETPOS
 */
static int
dissect_vuze_dht_network_coordinates(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int ver)
{
  proto_item *ti;
  proto_tree *sub_tree;
  guint i;
  guint network_coordinates_count;

  if( ver >= PV_GENERIC_NETPOS )
  {
    proto_tree_add_item(tree, hf_vuze_dht_network_coordinates_count, tvb, offset, TL_BYTE, ENC_BIG_ENDIAN);
    network_coordinates_count = tvb_get_guint8( tvb, offset );
    offset += TL_BYTE;

    ti = proto_tree_add_none_format( tree, hf_vuze_dht_network_coordinates, tvb, offset, 0, "%d network coordinates", network_coordinates_count );
    sub_tree = proto_item_add_subtree(ti, ett_vuze_dht_network_coordinates);
    for( i=0; i<network_coordinates_count; i++ )
      offset = dissect_vuze_dht_network_coordinate( tvb, pinfo, sub_tree, offset );
  }
  return offset;
}

/* ---  Request Header format --------------

Name                  | Type  | Protocol version | Note
CONNECTION_ID           long    always             random number with most significant bit set to 1
ACTION                  int     always             type of the packet
TRANSACTION_ID          int     always             unique number used through the communication; it is randomly generated
                                                   at the start of the application and increased by 1 with each sent packet
PROTOCOL_VERSION        byte    always             version of protocol used in this packet
VENDOR_ID               byte    >=VENDOR_ID         ID of the DHT implementator; 0 = Azureus, 1 = ShareNet, 255 = unknown
NETWORK_ID              int     >=NETWORKS          ID of the network; 0 = stable version; 1 = CVS version
LOCAL_PROTOCOL_VERSION  byte    >=FIX_ORIGINATOR    maximum protocol version this node supports; if this packet's protocol
                                                   version is <FIX_ORIGINATOR then the value is stored at the end of the packet
NODE_ADDRESS            address always             address of the local node
INSTANCE_ID             int     always             application's helper number; randomly generated at the start
TIME                    long    always             time of the local node; stored as number of milliseconds since Epoch

*/
static int
dissect_vuze_dht_request_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int *action, int *ver )
{
  proto_tree_add_item(tree, hf_vuze_dht_connection_id, tvb, offset, TL_LONG, ENC_BIG_ENDIAN);
  offset += TL_LONG;

  proto_tree_add_item(tree, hf_vuze_dht_action, tvb, offset, TL_INT, ENC_BIG_ENDIAN);
  *action = tvb_get_ntohl(tvb, offset);
  col_append_fstr(pinfo->cinfo, COL_INFO, " Action: %s", val_to_str_const( *action, vuze_dht_action_type_vals, "Unknown") );
  offset += TL_INT;

  proto_tree_add_item(tree, hf_vuze_dht_transaction_id, tvb, offset, TL_INT, ENC_BIG_ENDIAN);
  offset += TL_INT;

  proto_tree_add_item(tree, hf_vuze_dht_proto_ver, tvb, offset, TL_BYTE, ENC_BIG_ENDIAN);
  *ver = tvb_get_guint8( tvb, offset );
  offset += TL_BYTE;

  if( *ver >= PV_VENDOR_ID )
  {
    proto_tree_add_item(tree, hf_vuze_dht_vendor_id, tvb, offset, TL_BYTE, ENC_BIG_ENDIAN);
    offset += TL_BYTE;
  }

  if( *ver > PV_NETWORKS )
  {
    proto_tree_add_item(tree, hf_vuze_dht_network_id, tvb, offset, TL_INT, ENC_BIG_ENDIAN);
    offset += TL_INT;
  }
  if( *ver > PV_FIX_ORIGINATOR )
  {
    proto_tree_add_item(tree, hf_vuze_dht_local_proto_ver, tvb, offset, TL_BYTE, ENC_BIG_ENDIAN);
    offset += TL_BYTE;
  }

  offset = dissect_vuze_dht_address(tvb, pinfo, tree, offset, "Local Address");
  proto_tree_add_item(tree, hf_vuze_dht_instance_id, tvb, offset, TL_INT, ENC_BIG_ENDIAN);
  offset += TL_INT;
  proto_tree_add_item(tree, hf_vuze_dht_time, tvb, offset, TL_LONG, ENC_BIG_ENDIAN);
  offset += TL_LONG;

  return offset;
}

/* ---  Reply Header format --------------

Name           | Type | Protocol version | Note
ACTION           int    always             type of the packet
TRANSACTION_ID   int    always             must be equal to TRANSACTION_ID from the request
CONNECTION_ID    long   always             must be equal to CONNECTION_ID from the request
PROTOCOL_VERSION byte   always             version of protocol used in this packet
VENDOR_ID        byte   >=VENDOR_ID         same meaning as in the request
NETWORK_ID       int    >=NETWORKS          same meaning as in the request
INSTANCE_ID      int    always             instance id of the node that replies to the request

*/
static int
dissect_vuze_dht_reply_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int *action, int *ver )
{
  proto_tree_add_item(tree, hf_vuze_dht_action, tvb, offset, TL_INT, ENC_BIG_ENDIAN);
  *action = tvb_get_ntohl(tvb, offset);
  col_append_fstr(pinfo->cinfo, COL_INFO, " Action: %s", val_to_str_const( *action, vuze_dht_action_type_vals, "Unknown") );
  offset += TL_INT;

  proto_tree_add_item(tree, hf_vuze_dht_transaction_id, tvb, offset, TL_INT, ENC_BIG_ENDIAN);
  offset += TL_INT;

  proto_tree_add_item(tree, hf_vuze_dht_connection_id, tvb, offset, TL_LONG, ENC_BIG_ENDIAN);
  offset += TL_LONG;

  proto_tree_add_item(tree, hf_vuze_dht_proto_ver, tvb, offset, TL_BYTE, ENC_BIG_ENDIAN);
  *ver = tvb_get_guint8( tvb, offset );
  offset += TL_BYTE;

  if( *ver >= PV_VENDOR_ID )
  {
    proto_tree_add_item(tree, hf_vuze_dht_vendor_id, tvb, offset, TL_BYTE, ENC_BIG_ENDIAN);
    offset += TL_BYTE;
  }

  if( *ver > PV_NETWORKS )
  {
    proto_tree_add_item(tree, hf_vuze_dht_network_id, tvb, offset, TL_INT, ENC_BIG_ENDIAN);
    offset += TL_INT;
  }

  proto_tree_add_item(tree, hf_vuze_dht_instance_id, tvb, offset, TL_INT, ENC_BIG_ENDIAN);
  offset += TL_INT;

  return offset;
}

/* --- Reply Ping -----------------

ACTION equal to 1025
If protocol version is >=VIVALDI then packet's body carries network coordinates.

*/
static int
dissect_vuze_dht_reply_ping(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int ver )
{
  if( ver >= PV_VIVALDI )
  {
    offset = dissect_vuze_dht_network_coordinates( tvb, pinfo, tree, offset, ver );
  }
  return offset;
}

/* --- Request Store -----------------

Name             | Type       | Protocol version | Note
SPOOF_ID           int          >=ANTI_SPOOF        Spoof ID of the target node; it must be the same number as previously retrived through FIND_NODE reply.
KEYS_COUNT         byte         always             Number of keys that follow.
KEYS               keys         always             Keys that the target node should store.
VALUE_GROUPS_COUNT byte         always             Number of groups of values this packet contains.
VALUES             value groups always             Groups of values, one for each key; values are stored in the same order as keys.

*/
static int
dissect_vuze_dht_request_store(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int ver )
{
  guint8 keys_count, value_groups_count;
  if( ver >= PV_ANTI_SPOOF )
  {
    proto_tree_add_item(tree, hf_vuze_dht_spoof_id, tvb, offset, TL_INT, ENC_BIG_ENDIAN);
    offset += TL_INT;
  }
  proto_tree_add_item(tree, hf_vuze_dht_keys_count, tvb, offset, TL_BYTE, ENC_BIG_ENDIAN);
  keys_count = tvb_get_guint8( tvb, offset );
  offset += TL_BYTE;

  offset = dissect_vuze_dht_keys( tvb, pinfo, tree, offset, keys_count );

  proto_tree_add_item(tree, hf_vuze_dht_value_groups_count, tvb, offset, TL_BYTE, ENC_BIG_ENDIAN);
  value_groups_count = tvb_get_guint8( tvb, offset );
  offset += TL_BYTE;

  offset = dissect_vuze_dht_value_groups( tvb, pinfo, tree, offset, value_groups_count, ver );

  return offset;
}

/* --- Reply Store -----------------

Name                  | Type | Protocol version | Note
DIVERSIFICATIONS_LENGTH byte   >=DIV_AND_CONT      Number of diversifications this packet contains.
DIVERSIFICATIONS        byte[] >=DIV_AND_CONT      Array with diversifications;
                                                  they are stored in the same order as keys and values from the request.
*/
static int
dissect_vuze_dht_reply_store(tvbuff_t *tvb, packet_info _U_*pinfo, proto_tree *tree, int offset, int ver )
{
  if( ver >= PV_DIV_AND_CONT )
  {
    guint diversifications_len;
    proto_tree_add_item(tree, hf_vuze_dht_diversifications_len, tvb, offset, TL_BYTE, ENC_BIG_ENDIAN);
    diversifications_len = tvb_get_guint8( tvb, offset );
    offset += TL_BYTE;

    proto_tree_add_item(tree, hf_vuze_dht_diversifications, tvb, offset, diversifications_len, ENC_NA);
    offset += diversifications_len;
  }

  return offset;
}

/* --- Request Find node -----------------

Name      | Type | Protocol version | Note
ID_LENGTH   byte   always             Length of the following ID.
ID          byte[] always             ID to search
NODE_STATUS int    >=MORE_NODE_STATUS  Node status
DHT_SIZE    int    >=MORE_NODE_STATUS  Estimated size of the DHT; Unknown value can be indicated as zero.

*/
static int
dissect_vuze_dht_request_find_node(tvbuff_t *tvb, packet_info _U_*pinfo, proto_tree *tree, int offset, int ver )
{
  guint id_len;

  proto_tree_add_item(tree, hf_vuze_dht_id_len, tvb, offset, TL_BYTE, ENC_BIG_ENDIAN);
  id_len = tvb_get_guint8( tvb, offset );
  offset += TL_BYTE;

  proto_tree_add_item(tree, hf_vuze_dht_id, tvb, offset, id_len, ENC_NA);
  offset += id_len;

  if( ver >= PV_MORE_NODE_STATUS )
  {
    proto_tree_add_item(tree, hf_vuze_dht_node_status, tvb, offset, TL_INT, ENC_BIG_ENDIAN);
    offset += TL_INT;
    proto_tree_add_item(tree, hf_vuze_dht_size, tvb, offset, TL_INT, ENC_BIG_ENDIAN);
    offset += TL_INT;
  }

  return offset;
}

/* --- Reply Find node -----------------

Name              | Type              | Protocol version | Note
SPOOF_ID            int                 >=ANTI_SPOOF        Spoof ID of the requesting node;
                                                           it should be constructed from information known about
                                                           requesting contact and not easily guessed by others.
NODE_TYPE           int                 >=XFER_STATUS       Type of the replying node;
                                                           Possible values are 0 for bootstrap node,
                                                           1 for ordinary node and ffffffffh for unknown type.
DHT_SIZE            int                 >=SIZE_ESTIMATE     Estimated size of the DHT; Unknown value can be indicated as zero.
NETWORK_COORDINATES network coordinates >=VIVALDI           Network coordinates of replying node.
CONTACTS_COUNT      short               always             Number of carried contacts.
CONTACTS            contacts            always             List with contacts.

*/
static int
dissect_vuze_dht_reply_find_node(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int ver )
{
  guint contacts_count;

  if( ver >= PV_ANTI_SPOOF )
  {
    proto_tree_add_item(tree, hf_vuze_dht_spoof_id, tvb, offset, TL_INT, ENC_BIG_ENDIAN);
    offset += TL_INT;
  }
  if( ver >= PV_XFER_STATUS )
  {
    proto_tree_add_item(tree, hf_vuze_dht_node_type, tvb, offset, TL_INT, ENC_BIG_ENDIAN);
    offset += TL_INT;
  }
  if( ver >= PV_SIZE_ESTIMATE )
  {
    proto_tree_add_item(tree, hf_vuze_dht_size, tvb, offset, TL_INT, ENC_BIG_ENDIAN);
    offset += TL_INT;
  }
  if( ver >= PV_VIVALDI )
  {
    offset = dissect_vuze_dht_network_coordinates( tvb, pinfo, tree, offset, ver );
  }

  proto_tree_add_item(tree, hf_vuze_dht_contacts_count, tvb, offset, TL_SHORT, ENC_BIG_ENDIAN);
  contacts_count = tvb_get_ntohs( tvb, offset );
  offset += TL_SHORT;

  offset = dissect_vuze_dht_contacts( tvb, pinfo, tree, offset, contacts_count );

  return offset;
}

/* --- Request Find value -----------------

Name     | Type | Note
KEY        key    Key for which the values are requested.
FLAGS      byte   Flags for the operation, possible values are:
                      SINGLE_VALUE = 00h
                      DOWNLOADING = 01h
                      SEEDING = 02h
                      MULTI_VALUE = 04h
                      STATS = 08h
MAX_VALUES byte   Maximum number of returned values.
*/
static int
dissect_vuze_dht_request_find_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int ver _U_ )
{
  offset = dissect_vuze_dht_key( tvb, pinfo, tree, offset );
  proto_tree_add_item(tree, hf_vuze_dht_flags, tvb, offset, TL_BYTE, ENC_BIG_ENDIAN);
  offset += TL_BYTE;
  proto_tree_add_item(tree, hf_vuze_dht_max_values, tvb, offset, TL_BYTE, ENC_BIG_ENDIAN);
  offset += TL_BYTE;

  return offset;
}

/* --- Reply Find value -----------------

Name               | Type              | Condition                     | Note
HAS_CONTINUATION     boolean             protocol version >=DIV_AND_CONT  Indicates whether there is at least one other packet with values.
HAS_VALUES           boolean             always                          Indicates whether this packet carries values or contacts.
CONTACTS_COUNT       short               HAS_VALUES == false             Number of stored contacts.
CONTACTS             contacts            HAS_VALUES == false             Stored contacts that are close to the searched key.
NETWORK_COORDINATES  network coordinates HAS_VALUES == false             Network coordinates of the replying node.
                                         && protocol version >=VIVALDI_FINDVALUE
DIVERSIFICATION_TYPE byte                HAS_VALUES == true              Type of key's diversification.
                                         && protocol version >=DIV_AND_CONT
VALUES               value group         HAS_VALUES == true              Values that match searched key.

*/
static int
dissect_vuze_dht_reply_find_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int ver )
{
  guint8 has_values;
  guint contacts_count;
  if( ver >= PV_DIV_AND_CONT )
  {
    proto_tree_add_item(tree, hf_vuze_dht_has_continuation, tvb, offset, TL_BOOL, ENC_BIG_ENDIAN);
    offset += TL_BOOL;
  }
  proto_tree_add_item(tree, hf_vuze_dht_has_values, tvb, offset, TL_BOOL, ENC_BIG_ENDIAN);
  has_values = tvb_get_guint8( tvb, offset );
  offset += TL_BOOL;

  if( has_values )
  {
    proto_tree_add_item(tree, hf_vuze_dht_contacts_count, tvb, offset, TL_SHORT, ENC_BIG_ENDIAN);
    contacts_count = tvb_get_ntohs( tvb, offset );
    offset += TL_SHORT;
    offset = dissect_vuze_dht_contacts( tvb, pinfo, tree, offset, contacts_count  );

    if( ver >= PV_VIVALDI_FINDVALUE )
    {
      offset = dissect_vuze_dht_network_coordinates( tvb, pinfo, tree, offset, ver );
    }
    if( ver >= PV_DIV_AND_CONT )
    {
      proto_tree_add_item(tree, hf_vuze_dht_diversification_type, tvb, offset, TL_BYTE, ENC_BIG_ENDIAN);
      offset += TL_BYTE;
    }
    offset = dissect_vuze_dht_value_group( tvb, pinfo, tree, offset, ver );
  }

  return offset;
}

/* --- Reply Error -----------------

Name                   | Type   | Condition                 | Note
ERROR_TYPE               int      always                      Type of the error. Possible values are:
                                                                WRONG_ADDRESS = 1 - originator's address stored in the request is incorrect
                                                                KEY_BLOCKED = 2 - the requested key has been blocked
SENDER_ADDRESS           address  ERROR_TYPE == WRONG_ADDRESS Real originator's address.
KEY_BLOCK_REQUEST_LENGTH byte     ERROR_TYPE == KEY_BLOCKED   Length of the following request.
KEY_BLOCK_REQUEST        byte[]   ERROR_TYPE == KEY_BLOCKED   Request that blocks/unlocks the key.
SIGNATURE_LENGTH         short    ERROR_TYPE == KEY_BLOCKED   Length of the following signature.
SIGNATURE                byte[]   ERROR_TYPE == KEY_BLOCKED   Signature of the request.

*/
static int
dissect_vuze_dht_reply_error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int ver _U_ )
{
  guint error_type;
  guint8 key_block_request_len;
  guint signature_len;

  proto_tree_add_item(tree, hf_vuze_dht_error_type, tvb, offset, TL_INT, ENC_BIG_ENDIAN);
  error_type = tvb_get_ntohl( tvb, offset );
  col_append_fstr(pinfo->cinfo, COL_INFO, " Error: %s", val_to_str_const( error_type, vuze_dht_error_type_vals, "Unknown") );
  offset += TL_INT;

  switch(error_type)
  {
  case ET_WRONG_ADDRESS:
    offset = dissect_vuze_dht_address( tvb, pinfo, tree, offset, "Sender Address" );
    break;
  case ET_KEY_BLOCKED:
    proto_tree_add_item(tree, hf_vuze_dht_key_block_request_len, tvb, offset, TL_BYTE, ENC_BIG_ENDIAN);
    key_block_request_len = tvb_get_guint8( tvb, offset );
    offset += TL_BYTE;

    proto_tree_add_item(tree, hf_vuze_dht_key_block_request, tvb, offset, key_block_request_len, ENC_NA);
    offset += key_block_request_len;

    proto_tree_add_item(tree, hf_vuze_dht_signature_len, tvb, offset, TL_SHORT, ENC_BIG_ENDIAN);
    signature_len = tvb_get_ntohs( tvb, offset );
    offset += TL_SHORT;

    proto_tree_add_item(tree, hf_vuze_dht_signature, tvb, offset, signature_len, ENC_NA);
    offset += signature_len;
    break;
  default:
    break;
  }

  return offset;
}

/* --- Request Key block -----------------

Name                    | Type  | Note
SPOOF_ID                  int     Spoof ID obtained through FIND_NODE request.
KEY_BLOCK_REQUEST_LENGTH  byte    Length of the following request.
KEY_BLOCK_REQUEST         byte[]  Request that blocks/unlocks the key.
SIGNATURE_LENGTH          short   Length of the following signature.
SIGNATURE                 byte[]  Signature of the request.

*/
static int
dissect_vuze_dht_request_key_block(tvbuff_t *tvb, packet_info _U_*pinfo, proto_tree *tree, int offset, int ver _U_ )
{
  guint8 key_block_request_len;
  guint signature_len;

  proto_tree_add_item(tree, hf_vuze_dht_spoof_id, tvb, offset, TL_INT, ENC_BIG_ENDIAN);
  offset += TL_INT;

  proto_tree_add_item(tree, hf_vuze_dht_key_block_request_len, tvb, offset, TL_BYTE, ENC_BIG_ENDIAN);
  key_block_request_len = tvb_get_guint8( tvb, offset );
  offset += TL_BYTE;

  proto_tree_add_item(tree, hf_vuze_dht_key_block_request, tvb, offset, key_block_request_len, ENC_NA);
  offset += key_block_request_len;

  proto_tree_add_item(tree, hf_vuze_dht_signature_len, tvb, offset, TL_SHORT, ENC_BIG_ENDIAN);
  signature_len = tvb_get_ntohs( tvb, offset );
  offset += TL_SHORT;

  proto_tree_add_item(tree, hf_vuze_dht_signature, tvb, offset, signature_len, ENC_NA);
  offset += signature_len;

  return offset;
}

static int
dissect_vuze_dht(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  proto_tree *sub_tree;
  int action, proto_ver;
  int decoded_length = 0;

  /* set the protocol column */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Vuze-DHT");
  /* clear the info column */
  col_clear( pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_vuze_dht, tvb, 0, -1, ENC_NA);
  sub_tree = proto_item_add_subtree(ti, ett_vuze_dht);

  /*
    Requests always start with Connection IDs, which guaranteed to have their MSB set to 1
    Replies always start with the action, which always has the MSB clear
    Therefore, the MSB of an incoming packet should be used to distinguish requests from replies.
  */
  if( tvb_get_guint8(tvb,0) & 0x80 )
  {
    decoded_length = dissect_vuze_dht_request_header(tvb, pinfo, sub_tree, decoded_length, &action, &proto_ver );
  }
  else
  {
    decoded_length = dissect_vuze_dht_reply_header(tvb, pinfo, sub_tree, decoded_length, &action, &proto_ver );
  }

  switch( action )
  {
  case AT_PING_REQUEST:
    break;
  case AT_PING_REPLY:
    decoded_length = dissect_vuze_dht_reply_ping(tvb, pinfo, sub_tree, decoded_length, proto_ver );
    break;
  case AT_STORE_REQUEST:
    decoded_length = dissect_vuze_dht_request_store(tvb, pinfo, sub_tree, decoded_length, proto_ver );
    break;
  case AT_STORE_REPLY:
    decoded_length = dissect_vuze_dht_reply_store(tvb, pinfo, sub_tree, decoded_length, proto_ver );
    break;
  case AT_FIND_NODE_REQUEST:
    decoded_length = dissect_vuze_dht_request_find_node(tvb, pinfo, sub_tree, decoded_length, proto_ver );
    break;
  case AT_FIND_NODE_REPLY:
    decoded_length = dissect_vuze_dht_reply_find_node(tvb, pinfo, sub_tree, decoded_length, proto_ver );
    break;
  case AT_FIND_VALUE_REQUEST:
    decoded_length = dissect_vuze_dht_request_find_value(tvb, pinfo, sub_tree, decoded_length, proto_ver );
    break;
  case AT_FIND_VALUE_REPLY:
    decoded_length = dissect_vuze_dht_reply_find_value(tvb, pinfo, sub_tree, decoded_length, proto_ver );
    break;
  case AT_ERROR_REPLY:
    decoded_length = dissect_vuze_dht_reply_error(tvb, pinfo, sub_tree, decoded_length, proto_ver );
    break;
  case AT_KEY_BLOCK_REQUEST:
    decoded_length = dissect_vuze_dht_request_key_block(tvb, pinfo, sub_tree, decoded_length, proto_ver );
    break;
  default:
    break;
  }

  return decoded_length;
}

void
proto_register_vuze_dht(void)
{
  static hf_register_info hf[] = {
    { &hf_vuze_dht_address,
      { "Address", "vuze-dht.address",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_address_len,
      { "Address Length", "vuze-dht.address.length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_address_v4,
      { "IPv4 Address", "vuze-dht.address.ipv4",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_address_v6,
      { "IPv6 Address", "vuze-dht.address.ipv6",
      FT_IPv6, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_address_port,
      { "Port", "vuze-dht.address.port",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_contact,
      { "Contact", "vuze-dht.contact",
      FT_NONE, BASE_NONE,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_contact_type,
      { "Contact Type", "vuze-dht.contact.type",
      FT_UINT8, BASE_DEC,  VALS(vuze_dht_contact_type_vals), 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_proto_ver,
      { "Protocol Version", "vuze-dht.proto_ver",
      FT_UINT8, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_value,
      { "Value", "vuze-dht.value",
      FT_NONE, BASE_NONE,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_value_ver,
      { "Value Version", "vuze-dht.value.ver",
      FT_UINT32, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_value_created,
      { "Value Creation Time", "vuze-dht.value.creation_time",
      FT_UINT64, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_value_bytes_count,
      { "Value Bytes Count", "vuze-dht.value.bytes_count",
      FT_UINT16, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_value_bytes,
      { "Value Bytes", "vuze-dht.value.bytes",
      FT_BYTES, BASE_NONE,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_value_flags,
      { "Value Flags", "vuze-dht.value.flags",
      FT_UINT8, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_value_life_hours,
      { "Value Life Hours", "vuze-dht.value.life_hours",
      FT_UINT8, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_value_replication_factor,
      { "Value Replication Factor", "vuze-dht.value.replication_factor",
      FT_UINT8, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_connection_id,
      { "Connection ID", "vuze-dht.connection_id",
      FT_UINT64, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_action,
      { "Action", "vuze-dht.action",
      FT_UINT32, BASE_DEC,  VALS(vuze_dht_action_type_vals), 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_transaction_id,
      { "Transaction ID", "vuze-dht.transaction_id",
      FT_UINT32, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_vendor_id,
      { "Vendor ID", "vuze-dht.vendor_id",
      FT_UINT8, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_network_id,
      { "Network ID", "vuze-dht.network_id",
      FT_UINT32, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_local_proto_ver,
      { "Local Protocol Version", "vuze-dht.local_proto_ver",
      FT_UINT8, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_instance_id,
      { "Instance ID", "vuze-dht.instance_id",
      FT_UINT32, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_time,
      { "Time", "vuze-dht.time",
      FT_UINT64, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_network_coordinates_count,
      { "Network Coordinates Count", "vuze-dht.network_coordinates_count",
      FT_UINT8, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_network_coordinates,
      { "Network Coordinates", "vuze-dht.network_coordinates",
      FT_NONE, BASE_NONE,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_network_coordinate,
      { "Network Coordinate", "vuze-dht.network_coordinate",
      FT_NONE, BASE_NONE,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_network_coordinate_type,
      { "Network Coordinate Type", "vuze-dht.network_coordinate.type",
      FT_UINT8, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_network_coordinate_size,
      { "Network Coordinate Size", "vuze-dht.network_coordinate.size",
      FT_UINT8, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_network_coordinate_data,
      { "Network Coordinate Data", "vuze-dht.network_coordinate.data",
      FT_BYTES, BASE_NONE,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_spoof_id,
      { "Spoof ID", "vuze-dht.spoof_id",
      FT_UINT32, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_keys_count,
      { "Keys Count", "vuze-dht.keys_count",
      FT_UINT8, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_keys,
      { "Keys", "vuze-dht.keys",
      FT_NONE, BASE_NONE,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_key,
      { "Key", "vuze-dht.key",
      FT_NONE, BASE_NONE,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_key_len,
      { "Key Length", "vuze-dht.key.len",
      FT_UINT8, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_key_data,
      { "Key Data", "vuze-dht.key.data",
      FT_BYTES, BASE_NONE,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_values_count,
      { "Values Count", "vuze-dht.values_count",
      FT_UINT16, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_value_groups_count,
      { "Value Groups Count", "vuze-dht.value_groups_count",
      FT_UINT8, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_value_group,
      { "Values", "vuze-dht.values",
      FT_NONE, BASE_NONE,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_value_groups,
      { "Value Groups", "vuze-dht.value_groups",
      FT_NONE, BASE_NONE,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_diversifications_len,
      { "Diversifications Length", "vuze-dht.diversifications_len",
      FT_UINT8, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_diversifications,
      { "Diversifications", "vuze-dht.diversifications",
      FT_BYTES, BASE_NONE,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_id_len,
      { "ID Length", "vuze-dht.id_len",
      FT_UINT8, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_id,
      { "ID", "vuze-dht.id",
      FT_BYTES, BASE_NONE,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_node_status,
      { "Node Status", "vuze-dht.node_status",
      FT_UINT32, BASE_HEX,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_size,
      { "DHT Size", "vuze-dht.dht_size",
      FT_UINT32, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_node_type,
      { "Node Type", "vuze-dht.node_type",
      FT_UINT32, BASE_DEC,  VALS(vuze_dht_node_type_vals), 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_contacts_count,
      { "Contacts Count", "vuze-dht.contacts_count",
      FT_UINT16, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_contacts,
      { "Contacts", "vuze-dht.contacts",
      FT_NONE, BASE_NONE,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_flags,
      { "Flags", "vuze-dht.flags",
      FT_UINT8, BASE_DEC,  VALS(vuze_dht_flag_type_vals), 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_values_num,
      { "Values Num", "vuze-dht.stats.values_num",
      FT_UINT32, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_values_total,
      { "Values Total", "vuze-dht.stats.values_total",
      FT_UINT32, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_reads_per_min,
      { "Reads Per Minute", "vuze-dht.stats.reads_per_min",
      FT_UINT32, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_diversification_type,
      { "Diversification Type", "vuze-dht.stats.diversification_type",
      FT_UINT8, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_max_values,
      { "Max values", "vuze-dht.max_values",
      FT_UINT8, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_has_continuation,
      { "Has Continuation", "vuze-dht.has_continuation",
      FT_UINT8, BASE_DEC,  VALS(vuze_dht_bool_type_vals), 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_has_values,
      { "Has Values", "vuze-dht.has_values",
      FT_UINT8, BASE_DEC,  VALS(vuze_dht_bool_type_vals), 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_error_type,
      { "Error Type", "vuze-dht.error_type",
      FT_UINT32, BASE_DEC,  VALS(vuze_dht_error_type_vals), 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_key_block_request_len,
      { "Key Block Request Length", "vuze-dht.key_block_request_len",
      FT_UINT8, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_key_block_request,
      { "Key Block Request", "vuze-dht.key_block_request",
      FT_BYTES, BASE_NONE,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_signature_len,
      { "Signature Length", "vuze-dht.signature_len",
      FT_UINT16, BASE_DEC,  NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_vuze_dht_signature,
      { "Signature", "vuze-dht.signature",
      FT_BYTES, BASE_NONE,  NULL, 0x0,
      NULL, HFILL }
    }
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
      &ett_vuze_dht,
      &ett_vuze_dht_address,
      &ett_vuze_dht_contacts,
      &ett_vuze_dht_contact,
      &ett_vuze_dht_keys,
      &ett_vuze_dht_key,
      &ett_vuze_dht_value_groups,
      &ett_vuze_dht_value_group,
      &ett_vuze_dht_value,
      &ett_vuze_dht_network_coordinates,
      &ett_vuze_dht_network_coordinate
  };

  module_t *vuze_dht_module;

  /* Register protocol */
  proto_vuze_dht = proto_register_protocol (
                        "Vuze DHT Protocol",  /* name */
                        "Vuze-DHT",               /* short name */
                        "vuze-dht"                /* abbrev */
                        );

  proto_register_field_array(proto_vuze_dht, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  new_register_dissector("vuze-dht", dissect_vuze_dht, proto_vuze_dht);

  /* Register our configuration options */
  vuze_dht_module = prefs_register_protocol(proto_vuze_dht, proto_reg_handoff_vuze_dht);

  prefs_register_uint_preference(vuze_dht_module, "udp_port",
                                           "Vuze DHT Protocol UDP port",
                                           "Set the UDP port for Vuze DHT Protocol.",
                                           10, &global_vuze_dht_udp_port);
}

void
proto_reg_handoff_vuze_dht(void)
{
  static gboolean vuze_dht_prefs_initialized = FALSE;
  static dissector_handle_t vuze_dht_handle;
  static guint vuze_dht_udp_port;

  if (!vuze_dht_prefs_initialized)
  {
    vuze_dht_handle = new_create_dissector_handle(dissect_vuze_dht, proto_vuze_dht);
    vuze_dht_prefs_initialized = TRUE;
  }
  else
  {
    dissector_delete_uint("udp.port", vuze_dht_udp_port, vuze_dht_handle);
  }

  /* Set our port number for future use */
  vuze_dht_udp_port = global_vuze_dht_udp_port;
  dissector_add_uint("udp.port", global_vuze_dht_udp_port, vuze_dht_handle);
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

