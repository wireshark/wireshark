/******************************************************************************************************/
/* packet-bt-dht.c
 * Routines for BT-DHT dissection
 * Copyright 2011, Xiao Xiangquan <xiaoxiangquan@gmail.com>
 *
 * $Id$
 *
 * A plugin for BT-DHT packet:
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <epan/packet.h>
#include <epan/conversation.h>

/* Specifications: BEP-0005
 * http://www.bittorrent.org/beps/bep_0005.html
 */

static int proto_bt_dht = -1;
static dissector_handle_t bt_dht_handle;

/* fields */
static int hf_bencoded_int = -1;
static int hf_bencoded_string = -1;
static int hf_bencoded_list = -1;
static int hf_bencoded_dict = -1;
static int hf_bencoded_dict_entry = -1;

static int hf_bt_dht_error = -1;
static int hf_bt_dht_peers = -1;
static int hf_bt_dht_peer = -1;
static int hf_bt_dht_nodes = -1;
static int hf_bt_dht_node = -1;
static int hf_bt_dht_id = -1;

static int hf_ip = -1;
static int hf_port = -1;
static int hf_truncated_data = -1;

/* tree types */
static gint ett_bt_dht = -1;
static gint ett_bencoded_list = -1;
static gint ett_bencoded_dict = -1;
static gint ett_bencoded_dict_entry = -1;
static gint ett_bt_dht_error = -1;
static gint ett_bt_dht_peers = -1;
static gint ett_bt_dht_nodes = -1;

/* some keys use short name in packet */
static const value_string short_key_name_value_string[] = {
  { 'y', "message_type" },
  { 'q', "request_type" },
  { 'e', "error" },
  { 't', "transaction ID" },
  { 'v', "version" },
  { 'a', "request arguments" },
  { 'r', "response values" },
  { 0, NULL }
};

/* some values use short name in packet */
static const value_string short_val_name_value_string[] = {
  { 'q', "request" },
  { 'r', "response" },
  { 'e', "error" },
  { 0, NULL }
};

static const char dict_str[] = "dictionary...";
static const char list_str[] = "list...";
/*
 * dissect a bencoded string from tvb, start at offset. it's like "5:abcde"
 * *result will be the decoded value
 */
static int dissect_bencoded_string(tvbuff_t *tvb, packet_info _U_*pinfo, proto_tree *tree, guint offset, char **result, gboolean tohex, char *label )
{
  guint string_len_start;
  guint string_len;

  string_len_start = offset;

  while( tvb_get_guint8(tvb,offset) != ':' )
    offset ++;

  string_len = atoi( tvb_get_ephemeral_string(tvb,string_len_start,offset-string_len_start) );
  /* skip the ':' */
  offset++;

  /* fill the return data */
  if( tohex )
    *result = tvb_bytes_to_str(tvb, offset, string_len );
  else
    *result = tvb_get_ephemeral_string( tvb, offset, string_len );

  proto_tree_add_string_format( tree, hf_bencoded_string, tvb, offset, string_len, *result, "%s: %s", label, *result );
  offset += string_len;
  return offset;
}

/*
 * dissect a bencoded integer from tvb, start at offset. it's like "i5673e"
 * *result will be the decoded value
 */
static int dissect_bencoded_int(tvbuff_t *tvb, packet_info _U_*pinfo, proto_tree *tree, guint offset, char **result, char *label )
{
  guint start_offset;

  start_offset = offset;

  /* we has confirmed that the first byte is 'i' */
  offset ++;

  while( tvb_get_guint8(tvb,offset)!='e' )
    offset ++;

  *result = tvb_get_ephemeral_string( tvb, offset, offset-start_offset-1 );
  proto_tree_add_string_format( tree, hf_bencoded_int, tvb, offset, offset-start_offset-1, *result,
    "%s: %s", label, *result );

  offset ++;
  return offset;
}

/* pre definition of dissect_bencoded_dict(), which is needed by dissect_bencoded_list() */
static int dissect_bencoded_dict(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, char *label );

/* dissect a bencoded list from tvb, start at offset. it's like "lXXXe", "X" is any bencoded thing */
static int dissect_bencoded_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, char *label  )
{
  proto_item *ti;
  proto_tree *sub_tree;
  guint one_byte;
  char *result;

  ti = proto_tree_add_none_format( tree, hf_bencoded_list, tvb, offset, 0, "%s: list...", label );
  sub_tree = proto_item_add_subtree( ti, ett_bencoded_list);

  /* skip the 'l' */
  offset++;

  while( (one_byte=tvb_get_guint8(tvb,offset)) != 'e' )
  {
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
      offset = dissect_bencoded_string( tvb, pinfo, sub_tree, offset, &result, FALSE, "String" );
      break;
    }
  }
  offset++;
  return offset;
}

/* dissect a bt dht error from tvb, start at offset. it's like "li201e9:error msge" */
static int dissect_bt_dht_error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, char **result, char *label )
{
  proto_item *ti;
  proto_tree *sub_tree;
  char *error_no, *error_msg;

  error_no = NULL;
  error_msg = NULL;

  ti = proto_tree_add_item( tree, hf_bt_dht_error, tvb, offset, 0, ENC_NA );
  sub_tree = proto_item_add_subtree( ti, ett_bt_dht_error);

  /* we have confirmed that the first byte is 'l' */
  offset ++;

  /* dissect bt-dht error number and message */
  offset = dissect_bencoded_int( tvb, pinfo, sub_tree, offset, &error_no, "Error ID" );
  offset = dissect_bencoded_string( tvb, pinfo, sub_tree, offset, &error_msg, FALSE, "Error Message" );

  proto_item_set_text( ti, "%s: error %s, %s", label, error_no, error_msg );
  col_append_fstr( pinfo->cinfo, COL_INFO, "error_no=%s  error_msg=%s  ", error_no, error_msg );
  *result = ep_strdup_printf("error %s, %s", error_no, error_msg );

  return offset;
}

/* dissect a bt dht values list from tvb, start at offset. it's like "l6:....6:....e" */
static int dissect_bt_dht_values(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, char **result, char *label )
{
  proto_item *ti;
  proto_tree *sub_tree;
  proto_item *value_ti;
  proto_tree *value_tree;
  address addr;

  guint peer_index;
  guint string_len_start;
  guint string_len;
  guint16 port;

  ti = proto_tree_add_item( tree, hf_bt_dht_peers, tvb, offset, 0, ENC_NA );
  sub_tree = proto_item_add_subtree( ti, ett_bt_dht_peers);

  peer_index = 0;
  /* we has confirmed that the first byte is 'l' */
  offset ++;

  /* dissect bt-dht values */
  while( tvb_get_guint8(tvb,offset)!='e' )
  {
    string_len_start = offset;
    while( tvb_get_guint8(tvb,offset) != ':' )
      offset ++;

    string_len = atoi( tvb_get_ephemeral_string(tvb,string_len_start,offset-string_len_start) );
    /* skip the ':' */
    offset++;
    /* 4 bytes ip, 2 bytes port */
    for( ; string_len>=6; string_len-=6, offset+=6 )
    {
      peer_index ++;
      SET_ADDRESS( &addr, AT_IPv4, 4, tvb_get_ptr( tvb, offset, 4) );
      port = tvb_get_letohl( tvb, offset+4 );

      value_ti = proto_tree_add_none_format( sub_tree, hf_bt_dht_peer, tvb, offset, 6,
          "%d\t%s:%u", peer_index, ep_address_to_str( &addr ), port );
      value_tree = proto_item_add_subtree( value_ti, ett_bt_dht_peers);

      proto_tree_add_item( value_tree, hf_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
      proto_tree_add_item( value_tree, hf_port, tvb, offset+4, 2, ENC_BIG_ENDIAN);
    }
    /* truncated data */
    if( string_len>0 )
    {
      proto_tree_add_item( tree, hf_truncated_data, tvb, offset, string_len, ENC_NA );
      offset += string_len;
    }
  }
  proto_item_set_text( ti, "%s: %d peers", label, peer_index );
  col_append_fstr( pinfo->cinfo, COL_INFO, "reply=%d peers  ", peer_index );
  *result = ep_strdup_printf("%d peers", peer_index);

  return offset;
}

static int dissect_bt_dht_nodes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, char **result, char *label )
{
  proto_item *ti;
  proto_tree *sub_tree;
  proto_item *node_ti;
  proto_tree *node_tree;

  guint node_index;
  guint string_len_start;
  guint string_len;
  address addr;
  guint16 port;
  guint8 *id;

  ti = proto_tree_add_item( tree, hf_bt_dht_nodes, tvb, offset, 0, ENC_NA );
  sub_tree = proto_item_add_subtree( ti, ett_bt_dht_nodes);
  node_index = 0;

  string_len_start = offset;
  while( tvb_get_guint8(tvb,offset) != ':' )
    offset ++;

  string_len = atoi( tvb_get_ephemeral_string(tvb,string_len_start,offset-string_len_start) );
  /* skip the ':' */
  offset++;

  /* 20 bytes id, 4 bytes ip, 2 bytes port */
  for( ; string_len>=26; string_len-=26, offset+=26 )
  {
    node_index++;

    id = tvb_bytes_to_str(tvb, offset, 20 );
    SET_ADDRESS( &addr, AT_IPv4, 4, tvb_get_ptr( tvb, offset, 4) );
    port = tvb_get_letohl( tvb, offset+24 );

    node_ti = proto_tree_add_none_format( sub_tree, hf_bt_dht_node, tvb, offset, 26,
        "%d\t%s %s:%u", node_index, id, ep_address_to_str( &addr ), port );
    node_tree = proto_item_add_subtree( node_ti, ett_bt_dht_peers);

    proto_tree_add_item( node_tree, hf_bt_dht_id, tvb, offset, 20, ENC_NA);
    proto_tree_add_item( node_tree, hf_ip, tvb, offset+20, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item( node_tree, hf_port, tvb, offset+24, 2, ENC_BIG_ENDIAN);
  }
  if( string_len>0 )
  {
    proto_tree_add_item( tree, hf_truncated_data, tvb, offset, string_len, ENC_NA );
    offset += string_len;
  }
  proto_item_set_text( ti, "%s: %d nodes", label, node_index );
  col_append_fstr( pinfo->cinfo, COL_INFO, "reply=%d nodes  ", node_index );
  *result = ep_strdup_printf("%d", node_index);

  return offset;
}

static int dissect_bencoded_dict_entry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset )
{
  proto_item *ti;
  proto_tree *sub_tree;
  gboolean tohex;
  char *key, *val;

  key = NULL;
  val = NULL;

  ti = proto_tree_add_item( tree, hf_bencoded_dict_entry, tvb, offset, 0, ENC_NA );
  sub_tree = proto_item_add_subtree( ti, ett_bencoded_dict_entry);

  /* dissect the key, it must be a string */
  offset = dissect_bencoded_string( tvb, pinfo, sub_tree, offset, &key, FALSE, "Key" );

  /* it is a dict, just recursion */
  switch( tvb_get_guint8(tvb,offset) )
  {
  case 'd':
    offset = dissect_bencoded_dict( tvb, pinfo, sub_tree, offset, "Value" );
    val = (char*)dict_str;
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
      val = (char*)list_str;
    }
    break;
  case 'i':
    offset = dissect_bencoded_int( tvb, pinfo, sub_tree, offset, &val, "Value" );
    break;
  /* it's a string */
  default:
    /* special process */
  if( strcmp(key,"nodes")==0 )
      offset = dissect_bt_dht_nodes( tvb, pinfo, sub_tree, offset, &val, "Value" );
  /* some need to return hex string */
    else
    {
      tohex = strcmp(key,"id")==0 || strcmp(key,"target")==0
           || strcmp(key,"info_hash")==0 || strcmp(key,"t")==0
           || strcmp(key,"v")==0;
      offset = dissect_bencoded_string( tvb, pinfo, sub_tree, offset, &val, tohex, "Value" );
    }
  }

  if( strlen(key)==1 )
    key = (char*)val_to_str( key[0], short_key_name_value_string, key );
  if( strlen(val)==1 )
    val = (char*)val_to_str( val[0], short_val_name_value_string, val );

  proto_item_set_text( ti, "%s: %s", key, val );

  if( strcmp(key,"message_type")==0 || strcmp(key,"request_type")==0 )
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s=%s  ", key, val);

  return offset;
}

/* dict = d...e */
static int dissect_bencoded_dict(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, char *label )
{
  proto_item *ti;
  proto_tree *sub_tree;

  ti = proto_tree_add_none_format( tree, hf_bencoded_dict, tvb, offset, 0, "%s: dictionary...", label );
  sub_tree = proto_item_add_subtree( ti, ett_bencoded_dict);

  /* skip the first char('d') */
  offset ++;

  while( tvb_get_guint8(tvb,offset)!='e' )
    offset = dissect_bencoded_dict_entry( tvb, pinfo, sub_tree, offset );

  offset++;
  return offset;
}

static void dissect_bt_dht(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "BT-DHT");
  col_clear(pinfo->cinfo, COL_INFO);
  if( tree )
    dissect_bencoded_dict(tvb, pinfo, tree, 0, "BT-DHT Protocol" );
}

static gboolean test_bt_dht_packet (tvbuff_t *tvb, packet_info *pinfo,
                                        proto_tree *tree)
{
   conversation_t *conversation;

  /* try dissecting */
  if( tvb_get_guint8(tvb,0)=='d' )
  {
      conversation = find_or_create_conversation(pinfo);
      conversation_set_dissector(conversation, bt_dht_handle);

      dissect_bt_dht(tvb, pinfo, tree);
      return TRUE;
   }
   return FALSE;
}

void proto_register_bt_dht(void)
{
  static hf_register_info hf[] = {
    { &hf_bencoded_string,
      { "string", "bt-dht.bencoded.string",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_bencoded_list,
      { "list", "bt-dht.bencoded.list",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_bencoded_int,
      { "int", "bt-dht.bencoded.int",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_bencoded_dict,
      { "dictionary", "bt-dht.bencoded.dict",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_bencoded_dict_entry,
      { "dictionary entry", "bt-dht.bencoded.dict_entry",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_bt_dht_error,
      { "Error", "bt-dht.error",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_bt_dht_peer,
      { "peer", "bt-dht.peer",
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
      { "id", "bt-dht.id",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_ip,
      { "ip", "bt-dht.ip",
        FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_port,
      { "port", "bt-dht.port",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_truncated_data,
      { "truncated data", "bt-dht.truncated_data",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    }
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_bt_dht,
    &ett_bencoded_list,
    &ett_bencoded_dict,
    &ett_bt_dht_error,
    &ett_bt_dht_peers,
    &ett_bt_dht_nodes,
    &ett_bencoded_dict_entry
  };

  proto_bt_dht = proto_register_protocol (
    "Bittorrent DHT Protocol",  /* name */
    "BT-DHT",                   /* short name */
    "bt-dht"                    /* abbrev */
  );

  proto_register_field_array(proto_bt_dht, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_bt_dht(void)
{
  heur_dissector_add("udp", test_bt_dht_packet, proto_bt_dht);
}

