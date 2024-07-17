/******************************************************************************************************/
/* packet-bt-dht.c
 * Routines for BT-DHT dissection
 * Copyright 2011, Xiao Xiangquan <xiaoxiangquan@gmail.com>
 *
 * A plugin for BT-DHT packet:
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/to_str.h>
#include <epan/expert.h>

#include <wsutil/strtoi.h>

#define DHT_MIN_LEN 5

void proto_register_bt_dht(void);
void proto_reg_handoff_bt_dht(void);

/* Specifications:
 * https://www.bittorrent.org/beps/bep_0005.html BEP 5 DHT Protocol
 * https://www.bittorrent.org/beps/bep_0042.html BEP 42 DHT Security extension
 */

static int proto_bt_dht;
static dissector_handle_t bt_dht_handle;

/* fields */
static int hf_bencoded_int;
static int hf_bencoded_string;
static int hf_bencoded_list;
static int hf_bencoded_dict;
static int hf_bencoded_dict_entry;
static int hf_bencoded_list_terminator;

static int hf_bt_dht_error;
static int hf_bt_dht_peers;
static int hf_bt_dht_peer;
static int hf_bt_dht_nodes;
static int hf_bt_dht_node;
static int hf_bt_dht_id;

static int hf_ip;
static int hf_ip6;
static int hf_port;
static int hf_truncated_data;

static expert_field ei_int_string;
static expert_field ei_invalid_len;

/* tree types */
static int ett_bt_dht;
static int ett_bencoded_list;
static int ett_bencoded_dict;
static int ett_bencoded_dict_entry;
static int ett_bt_dht_error;
static int ett_bt_dht_peers;
static int ett_bt_dht_nodes;

/* some keys use short name in packet */
static const value_string short_key_name_value_string[] = {
  { 'a', "Request arguments" },
  { 'e', "Error" },
  { 'q', "Request type" },
  { 'r', "Response values" },
  { 't', "Transaction ID" },
  { 'v', "Version" },
  { 'y', "Message type" },
  { 0, NULL }
};

/* some values use short name in packet */
static const value_string short_val_name_value_string[] = {
  { 'e', "Error" },
  { 'q', "Request" },
  { 'r', "Response" },
  { 0, NULL }
};

static const char dict_str[] = "Dictionary...";
static const char list_str[] = "List...";


static inline bool
bencoded_string_length(packet_info *pinfo, tvbuff_t *tvb, unsigned *offset_ptr, unsigned *length)
{
  unsigned offset, start;
  unsigned remaining = tvb_captured_length_remaining(tvb, *offset_ptr);
  if (remaining == 0)
    return false;

  offset = *offset_ptr;
  start = offset;

  while(tvb_get_uint8(tvb, offset) != ':' && --remaining)
    ++offset;

  if (remaining && ws_strtou32(tvb_get_string_enc(pinfo->pool, tvb, start, offset-start, ENC_ASCII),
      NULL, length)) {
    ++offset; /* skip the ':' */
    *offset_ptr = offset;
    return true;
  }
  return false;
}


/*
 * dissect a bencoded string from tvb, start at offset. it's like "5:abcde"
 * *result will be the decoded value
 */

static int
dissect_bencoded_string(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const char **result, bool tohex, const char *label )
{
  unsigned string_len;
  if (!bencoded_string_length(pinfo, tvb, &offset, &string_len))
    return 0;

  const unsigned remaining = tvb_captured_length_remaining(tvb, offset);
  if (remaining < string_len)
    return 0;

  /* fill the return data */
  if (string_len == 0)
    *result = "";
  else if (tohex)
    *result = tvb_bytes_to_str(pinfo->pool, tvb, offset, string_len );
  else
    *result = tvb_get_string_enc( pinfo->pool, tvb, offset, string_len , ENC_ASCII);

  proto_tree_add_string_format( tree, hf_bencoded_string, tvb, offset, string_len, *result, "%s: %s", label, *result );
  offset += string_len;
  return offset;
}

/*
 * dissect a bencoded integer from tvb, start at offset. it's like "i5673e"
 * *result will be the decoded value
 */
static int
dissect_bencoded_int(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const char **result, const char *label )
{
  unsigned start_offset;
  unsigned remaining = tvb_captured_length_remaining(tvb, offset);

  /* the shortest valid integer is i0e, so we need at least 3 bytes */
  if (remaining < 3)
    return 0;

  if (tvb_get_uint8(tvb, offset) != 'i')
    return 0;

  offset += 1;
  remaining -= 1;
  start_offset = offset;
  while (tvb_get_uint8(tvb, offset) != 'e' && --remaining)
    offset += 1;

  if (remaining == 0)
    return 0;

  proto_tree_add_item(tree, hf_bencoded_list_terminator, tvb, offset, 1, ENC_ASCII);

  *result = tvb_get_string_enc( pinfo->pool, tvb, start_offset, offset-start_offset, ENC_ASCII);
  proto_tree_add_string_format( tree, hf_bencoded_int, tvb, start_offset, offset-start_offset, *result,
    "%s: %s", label, *result );

  offset += 1;
  return offset;
}

/* pre definition of dissect_bencoded_dict(), which is needed by dissect_bencoded_list() */
static int dissect_bencoded_dict(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const char *label );

/* dissect a bencoded list from tvb, start at offset. it's like "lXXXe", "X" is any bencoded thing */
static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_bencoded_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const char *label  )
{
  proto_item *ti;
  proto_tree *sub_tree;
  unsigned    one_byte;
  const char *result;

  /* the shortest valid list is "le", so we need at least 2 bytes */
  if (tvb_captured_length_remaining(tvb, offset) < 2)
    return 0;

  ti = proto_tree_add_none_format( tree, hf_bencoded_list, tvb, offset, 0, "%s: list...", label );
  sub_tree = proto_item_add_subtree( ti, ett_bencoded_list);

  if (tvb_get_uint8(tvb, offset) != 'l')
    return 0;
  offset += 1;

  while (tvb_captured_length_remaining(tvb, offset) > 0)
  {
    one_byte = tvb_get_uint8(tvb, offset);
    if (one_byte == 'e')
      break;

    unsigned start_offset = offset;
    switch( one_byte )
    {
    /* a integer */
    case 'i':
      offset = dissect_bencoded_int( tvb, pinfo, sub_tree, offset, &result, "Integer" );
      break;
    /* a sub-list */
    case 'l':
      offset = dissect_bencoded_list( tvb, pinfo, sub_tree, offset, "Sub-list" );
      break;
    /* a dictionary */
    case 'd':
      offset = dissect_bencoded_dict( tvb, pinfo, sub_tree, offset, "Sub-dict" );
      break;
    /* a string */
    default:
      offset = dissect_bencoded_string( tvb, pinfo, sub_tree, offset, &result, false, "String" );
      break;
    }
    if (offset <= start_offset)
    {
      proto_tree_add_expert(sub_tree, pinfo, &ei_int_string, tvb, offset, -1);
      /* if offset is not going on, there is no chance to exit the loop, then return*/
      return 0;
    }
  }

  if (tvb_captured_length_remaining(tvb, offset) == 0)
    return 0;

  proto_tree_add_item(sub_tree, hf_bencoded_list_terminator, tvb, offset, 1, ENC_ASCII);
  offset += 1;
  return offset;
}

/* dissect a bt dht error from tvb, start at offset. it's like "li201e9:error msge" */
static int
dissect_bt_dht_error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const char **result, const char *label )
{
  proto_item *ti;
  proto_tree *sub_tree;
  const char *error_no, *error_msg;

  error_no  = NULL;
  error_msg = NULL;

  ti       = proto_tree_add_item( tree, hf_bt_dht_error, tvb, offset, 0, ENC_NA );
  sub_tree = proto_item_add_subtree( ti, ett_bt_dht_error);

  /* we have confirmed that the first byte is 'l' */
  offset += 1;

  /* dissect bt-dht error number and message */
  offset = dissect_bencoded_int( tvb, pinfo, sub_tree, offset, &error_no, "Error ID" );
  if (offset == 0) {
    return 0;
  }
  offset = dissect_bencoded_string( tvb, pinfo, sub_tree, offset, &error_msg, false, "Error Message" );
  if (offset == 0) {
    return 0;
  }

  proto_item_set_text( ti, "%s: error %s, %s", label, error_no, error_msg );
  col_append_fstr( pinfo->cinfo, COL_INFO, " No=%s Msg=%s", error_no, error_msg );
  *result = wmem_strdup_printf(pinfo->pool, "error %s, %s", error_no, error_msg );

  return offset + 1;
}

/* dissect a bt dht values list from tvb, start at offset. it's like "l6:....6:....e" */
static int
dissect_bt_dht_values(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const char **result, const char *label )
{
  proto_item *ti;
  proto_tree *sub_tree;
  proto_item *value_ti;
  proto_tree *value_tree;

  unsigned    peer_index;
  unsigned    string_len;

  ti = proto_tree_add_item( tree, hf_bt_dht_peers, tvb, offset, 0, ENC_NA );
  sub_tree = proto_item_add_subtree( ti, ett_bt_dht_peers);

  peer_index = 0;
  /* we has confirmed that the first byte is 'l' */
  offset += 1;

  /* dissect bt-dht values */
  while( tvb_get_uint8(tvb,offset)!='e' )
  {
    if (!bencoded_string_length(pinfo, tvb, &offset, &string_len))
    {
      expert_add_info(pinfo, ti, &ei_invalid_len);
      // Fail hard here rather than potentially looping excessively.
      return 0;
    }
    else if (string_len == 6)
    {
      /* 4 bytes ip, 2 bytes port */
      peer_index += 1;

      value_ti = proto_tree_add_item( sub_tree, hf_bt_dht_peer, tvb, offset, 6, ENC_NA );
      proto_item_append_text(value_ti, " %d", peer_index);
      value_tree = proto_item_add_subtree( value_ti, ett_bt_dht_peers);

      proto_tree_add_item( value_tree, hf_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
      proto_item_append_text(value_ti, " (IP/Port: %s", tvb_ip_to_str(pinfo->pool, tvb, offset));
      proto_tree_add_item( value_tree, hf_port, tvb, offset+4, 2, ENC_BIG_ENDIAN);
      proto_item_append_text(value_ti, ":%u)", tvb_get_ntohs( tvb, offset+4 ));
    }
    else if (string_len == 18)
    {
      /* 16 bytes ip, 2 bytes port */
      peer_index += 1;

      value_ti = proto_tree_add_item( sub_tree, hf_bt_dht_peer, tvb, offset, 18, ENC_NA );
      proto_item_append_text(value_ti, " %d", peer_index);
      value_tree = proto_item_add_subtree( value_ti, ett_bt_dht_peers);

      proto_tree_add_item( value_tree, hf_ip6, tvb, offset, 16, ENC_NA);
      proto_item_append_text(value_ti, " (IPv6/Port: [%s]", tvb_ip6_to_str(pinfo->pool, tvb, offset));
      proto_tree_add_item( value_tree, hf_port, tvb, offset+16, 2, ENC_BIG_ENDIAN);
      proto_item_append_text(value_ti, ":%u)", tvb_get_ntohs( tvb, offset+16 ));
    }
    else
    {
      /* truncated data */
      proto_tree_add_item( tree, hf_truncated_data, tvb, offset, string_len, ENC_NA );
    }

    offset += string_len;
  }

  if (tvb_get_uint8(tvb,offset)=='e') { /* list ending delimiter */
    proto_tree_add_item(sub_tree, hf_bencoded_list_terminator, tvb, offset, 1, ENC_ASCII);
    offset++;
  }

  proto_item_set_text( ti, "%s: %d peers", label, peer_index );
  col_append_fstr( pinfo->cinfo, COL_INFO, " Peers=%d", peer_index );
  *result = wmem_strdup_printf(pinfo->pool, "%d peers", peer_index);

  return offset;
}

static int
dissect_bt_dht_nodes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const char **result, const char *label, bool is_ipv6 )
{
  proto_item *ti;
  proto_tree *sub_tree;
  proto_item *node_ti;
  proto_tree *node_tree;

  unsigned    node_index;
  unsigned    string_len;
  unsigned    node_byte_length;

  if (!bencoded_string_length(pinfo, tvb, &offset, &string_len))
    return 0;

  ti = proto_tree_add_item( tree, hf_bt_dht_nodes, tvb, offset, string_len, ENC_NA );
  sub_tree = proto_item_add_subtree( ti, ett_bt_dht_nodes);
  node_index = 0;

  /* 26 bytes = 20 bytes id + 4 bytes ipv4 address + 2 bytes port */
  node_byte_length = 26;

  if ( is_ipv6 )
  {
    /* 38 bytes = 20 bytes id + 16 bytes ipv6 address + 2 bytes port */
    node_byte_length = 38;
  }

  for( ; string_len>=node_byte_length; string_len-=node_byte_length, offset+=node_byte_length )
  {
    node_index += 1;

    node_ti = proto_tree_add_item( sub_tree, hf_bt_dht_node, tvb, offset, node_byte_length, ENC_NA);
    proto_item_append_text(node_ti, " %d", node_index);
    node_tree = proto_item_add_subtree( node_ti, ett_bt_dht_peers);

    proto_tree_add_item( node_tree, hf_bt_dht_id, tvb, offset, 20, ENC_NA);
    proto_item_append_text(node_ti, " (id: %s", tvb_bytes_to_str(pinfo->pool, tvb, offset, 20));

    if ( is_ipv6 )
    {
      proto_tree_add_item( node_tree, hf_ip6, tvb, offset+20, 16, ENC_NA);
      proto_item_append_text(node_ti, ", IPv6/Port: [%s]", tvb_ip6_to_str(pinfo->pool, tvb, offset+20));

      proto_tree_add_item( node_tree, hf_port, tvb, offset+36, 2, ENC_BIG_ENDIAN);
      proto_item_append_text(node_ti, ":%u)", tvb_get_ntohs( tvb, offset+36 ));
    }
    else
    {
      proto_tree_add_item( node_tree, hf_ip, tvb, offset+20, 4, ENC_BIG_ENDIAN);
      proto_item_append_text(node_ti, ", IPv4/Port: %s", tvb_ip_to_str(pinfo->pool, tvb, offset+20));

      proto_tree_add_item( node_tree, hf_port, tvb, offset+24, 2, ENC_BIG_ENDIAN);
      proto_item_append_text(node_ti, ":%u)", tvb_get_ntohs( tvb, offset+24 ));
    }
  }

  if( string_len>0 )
  {
    proto_tree_add_item( tree, hf_truncated_data, tvb, offset, string_len, ENC_NA );
    offset += string_len;
  }
  proto_item_set_text( ti, "%s: %d nodes", label, node_index );
  col_append_fstr( pinfo->cinfo, COL_INFO, " Nodes=%d", node_index );
  *result = wmem_strdup_printf(pinfo->pool, "%d", node_index);

  return offset;
}

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_bencoded_dict_entry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset )
{
  proto_item *ti;
  proto_tree *sub_tree;
  bool        tohex;
  const char *key;
  const char *val;
  unsigned    orig_offset = offset;

  key = NULL;
  val = NULL;

  ti       = proto_tree_add_item( tree, hf_bencoded_dict_entry, tvb, offset, 0, ENC_NA );
  sub_tree = proto_item_add_subtree( ti, ett_bencoded_dict_entry);

  /* dissect the key, it must be a string */
  offset   = dissect_bencoded_string( tvb, pinfo, sub_tree, offset, &key, false, "Key" );
  if (offset == 0)
  {
    proto_tree_add_expert_format(sub_tree, pinfo, &ei_int_string, tvb, offset, -1, "Invalid string for Key");
    return 0;
  }

  if (tvb_captured_length_remaining(tvb, offset) == 0)
    return 0;

  /* If it is a dict, then just do recursion */
  switch( tvb_get_uint8(tvb,offset) )
  {
  case 'd':
    offset = dissect_bencoded_dict( tvb, pinfo, sub_tree, offset, "Value" );
    val    = dict_str;
    break;
  case 'l':
    if( strcmp(key,"e")==0 )
      offset = dissect_bt_dht_error( tvb, pinfo, sub_tree, offset, &val, "Value" );
    else if( strcmp(key,"values")==0 )
      offset = dissect_bt_dht_values( tvb, pinfo, sub_tree, offset, &val, "Value" );
    /* other unfamiliar lists */
    else
    {
      offset = dissect_bencoded_list( tvb, pinfo, sub_tree, offset, "Value" );
      val = list_str;
    }
    break;
  case 'i':
    offset = dissect_bencoded_int( tvb, pinfo, sub_tree, offset, &val, "Value" );
    break;
  /* it's a string */
  default:
    /* special process */
    if( strcmp(key,"nodes")==0 )
    {
      offset = dissect_bt_dht_nodes( tvb, pinfo, sub_tree, offset, &val, "Value", 0 );
    }
    else if( strcmp(key,"nodes6")==0 )
    {
      offset = dissect_bt_dht_nodes( tvb, pinfo, sub_tree, offset, &val, "Value", 1 );
    }
    else if( strcmp(key,"ip")==0 )
    {
      /*
       * BEP 42 DHT Security extension
       * https://www.bittorrent.org/beps/bep_0042.html
       * https://www.rasterbar.com/products/libtorrent/dht_sec.html
       */

      unsigned len;
      int old_offset = offset;
      if (!bencoded_string_length(pinfo, tvb, &offset, &len)) {
        proto_tree_add_expert_format(sub_tree, pinfo, &ei_int_string, tvb, offset, -1, "Invalid string for value");
        return 0;
      }

      if(len == 6) {
        proto_tree_add_item(sub_tree, hf_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
        val = tvb_ip_to_str(pinfo->pool, tvb, offset);
        offset += 4;
        proto_tree_add_item(sub_tree, hf_port, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
      }
      else {
        /* XXX: BEP 42 doesn't mention IPv6 and predates the IPv6 DHT;
         * it doesn't make sense for IPv6 because the purpose is to tell
         * the requestor its own publicly routable IP address and port
         * (working around NAT). So any other length than 6 is unexpected.
         */
        offset = dissect_bencoded_string( tvb, pinfo, sub_tree, old_offset, &val, true, "Value" );
      }
    }
    else
    {
      /* some need to return hex string */
      tohex = strcmp(key,"id")==0 || strcmp(key,"target")==0
           || strcmp(key,"info_hash")==0 || strcmp(key,"t")==0
           || strcmp(key,"v")==0 || strcmp(key,"token")==0;
      offset = dissect_bencoded_string( tvb, pinfo, sub_tree, offset, &val, tohex, "Value" );
    }
  }

  if (offset == 0)
  {
    proto_tree_add_expert_format(sub_tree, pinfo, &ei_int_string, tvb, offset, -1, "Invalid string for value");
    return 0;
  }

  if(key && strcmp(key,"q")==0 && strlen(val)>1 )
    col_prepend_fstr(pinfo->cinfo, COL_INFO, "%c%s", g_ascii_toupper(val[0]), val + 1);
  if(key && strcmp(key,"r")==0 )
    col_prepend_fstr(pinfo->cinfo, COL_INFO, "Response");
  if(key && strcmp(key,"e")==0 )
    col_prepend_fstr(pinfo->cinfo, COL_INFO, "Error");
  if(key && (strcmp(key,"info_hash")==0 || strcmp(key,"target")==0) )
    col_append_fstr(pinfo->cinfo, COL_INFO, " %c%s=%s", g_ascii_toupper(key[0]), key + 1, val);

  if(key && strlen(key)==1 )
    key = val_to_str_const( key[0], short_key_name_value_string, key );
  if(val && strlen(val)==1 )
    val = val_to_str_const( val[0], short_val_name_value_string, val );

  proto_item_set_text( ti, "%s: %s", key, val );
  proto_item_set_len( ti, offset-orig_offset );

  return offset;
}

/* dict = d...e */
static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_bencoded_dict(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const char *label )
{
  proto_item *ti;
  proto_tree *sub_tree;
  unsigned    orig_offset = offset;

  /* the shortest valid dictionary is "de", so we need at least 2 bytes */
  if (tvb_captured_length_remaining(tvb, offset) < 2)
    return 0;

  if(offset == 0)
  {
    ti = proto_tree_add_item(tree, proto_bt_dht, tvb, 0, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_bt_dht);
  }
  else
  {
    ti = proto_tree_add_none_format( tree, hf_bencoded_dict, tvb, offset, -1, "%s: Dictionary...", label );
    sub_tree = proto_item_add_subtree( ti, ett_bencoded_dict);
  }

  if (tvb_get_uint8(tvb, offset) != 'd')
    return 0;
  offset += 1;

  while (tvb_captured_length_remaining(tvb, offset) > 0) {
    if (tvb_get_uint8(tvb, offset) == 'e')
      break;

    offset = dissect_bencoded_dict_entry( tvb, pinfo, sub_tree, offset );
    if (offset == 0)
    {
      proto_tree_add_expert(sub_tree, pinfo, &ei_int_string, tvb, offset, -1);
      return 0;
    }
  }

  if (tvb_captured_length_remaining(tvb, offset) == 0)
    return 0;

  proto_tree_add_item(sub_tree, hf_bencoded_list_terminator, tvb, offset, 1, ENC_ASCII);
  offset += 1;
  proto_item_set_len( ti, offset-orig_offset );

  return offset;
}

static bool
test_bt_dht(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{

  /* The DHT KRPC protocol sends packets that are bencoded dictionaries.
   * Bencoded dictionaries always have the keys in sorted (raw string)
   * order. There are three possible message types, query, which has "a" and
   * "q" keys that map to dictionaries, response, which has an "r" key
   * that maps to a dictionary, and error, which has an "e" key that maps
   * to a list.
   *
   * Conveniently, those keys appear in sort order before all other possible
   * top level keys, with the exception of the "ip" key added in BEP-0042.
   *
   * Thus, there are only four possible initial sets of bytes, corresponding
   * to beginning with an "a" dictionary, "r" dictionary, "ip" string, or an
   * "e" list.
   */

  if (tvb_captured_length_remaining(tvb, offset) < DHT_MIN_LEN)
    return false;

  if (tvb_memeql(tvb, offset, (const uint8_t*)"d1:ad", 5) == 0) {
    return true;
  } else if (tvb_memeql(tvb, offset, (const uint8_t*)"d1:rd", 5) == 0) {
    return true;
  } else if (tvb_memeql(tvb, offset, (const uint8_t*)"d2:ip", 5) == 0) {
    return true;
  } else if (tvb_memeql(tvb, offset, (const uint8_t*)"d1:el", 5) == 0) {
    return true;
  }

  return false;
}

static int
dissect_bt_dht(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  /* BitTorrent clients use the same UDP connection for DHT as for uTP.
   * So even if this has been set as the dissector for this conversation
   * or port, test it and reject it if not BT-DHT in order to give other
   * dissectors, especially BT-uTP, a chance.
   */
  if (!test_bt_dht(pinfo, tvb, 0, data)) {
    return 0;
  }

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "BT-DHT");
  col_clear(pinfo->cinfo, COL_INFO);

  /* XXX: There is a separate "bencode" dissector. Would it be possible
   * to use it, at least to move some functions into a shared header?
   * DHT has some keys with special meanings, and some values that
   * are supposed to be interpreted specially (e.g., IP/port combinations),
   * so maybe it's more trouble than it's worth.
   */
  return dissect_bencoded_dict(tvb, pinfo, tree, 0, "BitTorrent DHT Protocol");
}

static
bool dissect_bt_dht_heur (tvbuff_t *tvb, packet_info *pinfo,
                                        proto_tree *tree, void *data)
{
  conversation_t *conversation;

  if (!test_bt_dht(pinfo, tvb, 0, data)) {
    return false;
  }

  conversation = find_or_create_conversation(pinfo);
  conversation_set_dissector_from_frame_number(conversation, pinfo->num, bt_dht_handle);

  dissect_bt_dht(tvb, pinfo, tree, NULL);
  return true;
}

void
proto_register_bt_dht(void)
{
  expert_module_t* expert_bt_dht;

  static hf_register_info hf[] = {
    { &hf_bencoded_string,
      { "String", "bt-dht.bencoded.string",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_bencoded_list,
      { "List", "bt-dht.bencoded.list",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_bencoded_int,
      { "Int", "bt-dht.bencoded.int",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_bencoded_dict,
      { "Dictionary", "bt-dht.bencoded.dict",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_bencoded_dict_entry,
      { "Dictionary Entry", "bt-dht.bencoded.dict_entry",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_bencoded_list_terminator,
      { "Terminator", "bt-dht.bencoded.list.terminator",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_bt_dht_error,
      { "Error", "bt-dht.error",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_bt_dht_peer,
      { "Peer", "bt-dht.peer",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_bt_dht_peers,
      { "Peers", "bt-dht.peers",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_bt_dht_node,
      { "Node", "bt-dht.node",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_bt_dht_nodes,
      { "Nodes", "bt-dht.nodes",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_bt_dht_id,
      { "ID", "bt-dht.id",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ip,
      { "IP", "bt-dht.ip",
        FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ip6,
      { "IP", "bt-dht.ip6",
        FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_port,
      { "Port", "bt-dht.port",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_truncated_data,
      { "Truncated data", "bt-dht.truncated_data",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }
  };

  static ei_register_info ei[] = {
    { &ei_int_string, { "bt-dht.invalid_string", PI_MALFORMED, PI_ERROR,
    "String must contain an integer", EXPFILL }},
    { &ei_invalid_len, { "bt-dht.invalid_length", PI_MALFORMED, PI_ERROR,
    "Invalid length", EXPFILL }},
  };

  /* Setup protocol subtree array */
  static int *ett[] = {
    &ett_bt_dht,
    &ett_bencoded_list,
    &ett_bencoded_dict,
    &ett_bt_dht_error,
    &ett_bt_dht_peers,
    &ett_bt_dht_nodes,
    &ett_bencoded_dict_entry
  };

  module_t *bt_dht_module;

  proto_bt_dht = proto_register_protocol ("BitTorrent DHT Protocol", "BT-DHT", "bt-dht");

  bt_dht_module = prefs_register_protocol(proto_bt_dht, NULL);
  prefs_register_obsolete_preference(bt_dht_module, "enable");

  proto_register_field_array(proto_bt_dht, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  expert_bt_dht = expert_register_protocol(proto_bt_dht);
  expert_register_field_array(expert_bt_dht, ei, array_length(ei));

  bt_dht_handle = register_dissector("bt-dht", dissect_bt_dht, proto_bt_dht);
}

void
proto_reg_handoff_bt_dht(void)
{
  heur_dissector_add("udp", dissect_bt_dht_heur, "BitTorrent DHT over UDP", "bittorrent_dht_udp", proto_bt_dht, HEURISTIC_ENABLE);

  // If this is ever streamed (transported over TCP) we need to add recursion checks.
  dissector_add_for_decode_as_with_preference("udp.port", bt_dht_handle);
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
