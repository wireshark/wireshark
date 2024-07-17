/* packet-bt-tracker.c
 * Routines for BitTorrent Tracker over UDP dissection
 * Copyright 2023, Ivan Nardi <nardi.ivan@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/to_str.h>
#include <epan/prefs.h>

void proto_register_bt_tracker(void);
void proto_reg_handoff_bt_tracker(void);

/* Specifications:
 * https://www.bittorrent.org/beps/bep_0015.html BEP 15 UDP Tracker Protocol for BitTorrent
 * https://www.bittorrent.org/beps/bep_0041.html BEP 41 UDP Tracker Protocol Extensions
 */

enum {
  ACTION_CONNECT = 0,
  ACTION_ANNOUNCE = 1,
  ACTION_SCRAPE = 2,
  ACTION_ERROR = 3,
};

enum {
  MSG_TYPE_CONNECT_REQUEST,
  MSG_TYPE_CONNECT_RESPONSE,
  MSG_TYPE_ANNOUNCE_REQUEST,
  MSG_TYPE_ANNOUNCE_RESPONSE,
  MSG_TYPE_SCRAPE_REQUEST,
  MSG_TYPE_SCRAPE_RESPONSE,
  MSG_TYPE_ERROR_RESPONSE,

  MSG_TYPE_UNKNOWN,
};

static const value_string bt_tracker_msg_type_vals[] = {
  { MSG_TYPE_CONNECT_REQUEST,   "Connection Request"  },
  { MSG_TYPE_CONNECT_RESPONSE,  "Connection Response"  },
  { MSG_TYPE_ANNOUNCE_REQUEST,  "Announce Request"  },
  { MSG_TYPE_ANNOUNCE_RESPONSE, "Announce Response"  },
  { MSG_TYPE_SCRAPE_REQUEST,    "Scrape Request"  },
  { MSG_TYPE_SCRAPE_RESPONSE,   "Scrape Response"  },
  { MSG_TYPE_ERROR_RESPONSE,    "Error Response"  },
  { 0, NULL }
};

static const value_string bt_tracker_event_vals[] = {
  { 0, "None"  },
  { 1, "Completed"  },
  { 2, "Started"  },
  { 3, "Stopped"  },
  { 0, NULL }
};

static const value_string bt_tracker_action_vals[] = {
  { ACTION_CONNECT,  "Connect"  },
  { ACTION_ANNOUNCE, "Announce"   },
  { ACTION_SCRAPE,   "Scrape" },
  { ACTION_ERROR,    "Error" },
  { 0, NULL }
};

enum {
  EXT_END_OF_OPTIONS  = 0,
  EXT_NOP             = 1,
  EXT_URLDATA         = 2,
  EXT_MAX
};

static const value_string bt_tracker_extension_type_vals[] = {
  { EXT_END_OF_OPTIONS, "End of Options" },
  { EXT_NOP,            "NOP" },
  { EXT_URLDATA,        "URL Data" },
  { 0, NULL }
};

static int proto_bt_tracker;
static dissector_handle_t bt_tracker_handle;

static int hf_bt_tracker_msg_type;
static int hf_bt_tracker_protocol_id;
static int hf_bt_tracker_action;
static int hf_bt_tracker_transaction_id;
static int hf_bt_tracker_connection_id;
static int hf_bt_tracker_info_hash;
static int hf_bt_tracker_peer_id;
static int hf_bt_tracker_downloaded;
static int hf_bt_tracker_left;
static int hf_bt_tracker_uploaded;
static int hf_bt_tracker_event;
static int hf_bt_tracker_ip_address;
static int hf_bt_tracker_key;
static int hf_bt_tracker_num_want;
static int hf_bt_tracker_port;
static int hf_bt_tracker_interval;
static int hf_bt_tracker_leechers;
static int hf_bt_tracker_seeders;
static int hf_bt_tracker_trackers;
static int hf_bt_tracker_tracker;
static int hf_bt_tracker_tr_ip;
static int hf_bt_tracker_tr_ip6;
static int hf_bt_tracker_tr_port;
static int hf_bt_tracker_completed;
static int hf_bt_tracker_error_msg;
static int hf_bt_tracker_extension;
static int hf_bt_tracker_extension_type;
static int hf_bt_tracker_extension_len;
static int hf_bt_tracker_extension_unknown;
static int hf_bt_tracker_extension_urldata;

static int ett_bt_tracker;
static int ett_bt_tracker_trackers;
static int ett_bt_tracker_extension;

#define MAGIC_CONSTANT 0x41727101980

static unsigned
get_message_type(tvbuff_t *tvb)
{
  if (tvb_get_ntoh64(tvb, 0) == MAGIC_CONSTANT &&
      tvb_get_ntohl(tvb, 8) == ACTION_CONNECT)
    return MSG_TYPE_CONNECT_REQUEST;
  if (tvb_get_ntohl(tvb, 0) == ACTION_CONNECT)
    return MSG_TYPE_CONNECT_RESPONSE;
  if (tvb_get_ntohl(tvb, 8) == ACTION_ANNOUNCE)
    return MSG_TYPE_ANNOUNCE_REQUEST;
  if (tvb_get_ntohl(tvb, 0) == ACTION_ANNOUNCE)
    return MSG_TYPE_ANNOUNCE_RESPONSE;
  if (tvb_get_ntohl(tvb, 8) == ACTION_SCRAPE)
    return MSG_TYPE_SCRAPE_REQUEST;
  if (tvb_get_ntohl(tvb, 0) == ACTION_SCRAPE)
    return MSG_TYPE_SCRAPE_RESPONSE;
  if (tvb_get_ntohl(tvb, 0) == ACTION_ERROR)
    return MSG_TYPE_ERROR_RESPONSE;

  return MSG_TYPE_UNKNOWN;
}

static bool
is_ipv4_format(packet_info *pinfo)
{
  wmem_list_frame_t *cur;
  int cur_proto;
  const char *cur_name;

  /* Format of Announce Response message depends on IPv4 vs IPv6
     "Which format is used is determined by the address family of the underlying UDP packet.
      I.e. packets from a v4 address use the v4 format, those from a v6 address use the v6 format."
     Check the innermost IP layer, to take into account tunnels
  */

  cur = wmem_list_frame_prev(wmem_list_tail(pinfo->layers));
  while (cur != NULL) {
    cur_proto = (int)GPOINTER_TO_UINT(wmem_list_frame_data(cur));
    cur_name = proto_get_protocol_filter_name(cur_proto);
    if (!strcmp(cur_name, "ip"))
      return true;
    if (!strcmp(cur_name, "ipv6"))
      return false;
    cur = wmem_list_frame_prev(cur);
  }
  return true;
}
static int
dissect_bt_tracker_extension(tvbuff_t *tvb, packet_info _U_*pinfo, proto_tree *tree, int offset)
{
  proto_item *ti;
  proto_tree *ext_tree;
  uint8_t extension_type;
  uint32_t extension_length;
  int32_t tot_length;

  while (offset < (int)tvb_reported_length(tvb)) {
    extension_type = tvb_get_uint8(tvb, offset);

    tot_length = 1;
    if (extension_type == EXT_URLDATA) {
      tot_length += 1 + tvb_get_uint8(tvb, offset + 1);
    } else if (extension_type >= EXT_MAX) {
      tot_length = -1;
    }

    ti = proto_tree_add_none_format(tree, hf_bt_tracker_extension, tvb, offset, tot_length, "Extension: %s", val_to_str_const(extension_type, bt_tracker_extension_type_vals, "Unknown"));
    ext_tree = proto_item_add_subtree(ti, ett_bt_tracker_extension);
    proto_tree_add_item(ext_tree, hf_bt_tracker_extension_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    switch (extension_type) {
      case EXT_END_OF_OPTIONS:
        /* Option parsing continues until either the end of the packet is reached, or an EndOfOptions option is encountered, whichever happens first */
        return offset;
      case EXT_NOP:
        /* A special case option that has a fixed-length of one byte. It is not followed by a length field, or associated data.
           A NOP has no affect on option parsing. It is used only if optional padding is necessary in the future. */
        break;
      case EXT_URLDATA:
        proto_tree_add_item_ret_uint(ext_tree, hf_bt_tracker_extension_len, tvb, offset, 1, ENC_BIG_ENDIAN, &extension_length);
        offset += 1;
        proto_tree_add_item(ext_tree, hf_bt_tracker_extension_urldata, tvb, offset, extension_length, ENC_ASCII);
        offset += extension_length;
        break;
      default:
        proto_tree_add_item(ext_tree, hf_bt_tracker_extension_unknown, tvb, offset, -1, ENC_NA);
        return offset;
    }
  }
  return offset;
}

static int
dissect_bt_tracker_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, unsigned msg_type)
{
  unsigned node_index = 0;
  int stride_length;
  proto_item *ti;
  proto_tree *sub_tree;
  bool is_ipv6;

  ti = proto_tree_add_uint(tree, hf_bt_tracker_msg_type, tvb, 0, 0, msg_type);
  proto_item_set_generated(ti);

  switch (msg_type) {
  case MSG_TYPE_CONNECT_REQUEST:
    proto_tree_add_item(tree, hf_bt_tracker_protocol_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_bt_tracker_action, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_tracker_transaction_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;

  case MSG_TYPE_CONNECT_RESPONSE:
    proto_tree_add_item(tree, hf_bt_tracker_action, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_tracker_transaction_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_tracker_connection_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    break;

  case MSG_TYPE_ANNOUNCE_REQUEST:
    proto_tree_add_item(tree, hf_bt_tracker_connection_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_bt_tracker_action, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_tracker_transaction_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_tracker_info_hash, tvb, offset, 20, ENC_NA);
    offset += 20;
    proto_tree_add_item(tree, hf_bt_tracker_peer_id, tvb, offset, 20, ENC_NA);
    offset += 20;
    proto_tree_add_item(tree, hf_bt_tracker_downloaded, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_bt_tracker_left, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_bt_tracker_uploaded, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_bt_tracker_event, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_tracker_ip_address, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_tracker_key, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_tracker_num_want, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_tracker_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    offset = dissect_bt_tracker_extension(tvb, pinfo, tree, offset);
    break;

  case MSG_TYPE_ANNOUNCE_RESPONSE:
    proto_tree_add_item(tree, hf_bt_tracker_action, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_tracker_transaction_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_tracker_interval, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_tracker_leechers, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_tracker_seeders, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (tvb_captured_length_remaining(tvb, offset) > 0)
    {
      stride_length = 6;
      is_ipv6 = !is_ipv4_format(pinfo);
      if (is_ipv6)
        stride_length = 18;
      ti = proto_tree_add_item(tree, hf_bt_tracker_trackers, tvb, offset, -1, ENC_NA);
      sub_tree = proto_item_add_subtree(ti, ett_bt_tracker_trackers);

      while (tvb_captured_length_remaining(tvb, offset) >= stride_length)
      {
        proto_item *node_ti;
        proto_tree *node_tree;

        node_index += 1;

        node_ti = proto_tree_add_item(sub_tree, hf_bt_tracker_tracker, tvb, offset, stride_length, ENC_NA);
        proto_item_append_text(node_ti, " %d", node_index);
        node_tree = proto_item_add_subtree(node_ti, ett_bt_tracker_trackers);

        if (is_ipv6)
        {
          proto_tree_add_item( node_tree, hf_bt_tracker_tr_ip6, tvb, offset, 16, ENC_NA);
          proto_item_append_text(node_ti, ", IPv6/Port: [%s]", tvb_ip6_to_str(pinfo->pool, tvb, offset));

          proto_tree_add_item( node_tree, hf_bt_tracker_tr_port, tvb, offset + 16, 2, ENC_BIG_ENDIAN);
          proto_item_append_text(node_ti, ":%u", tvb_get_ntohs( tvb, offset + 16 ));
        }
        else
        {
          proto_tree_add_item( node_tree, hf_bt_tracker_tr_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
          proto_item_append_text(node_ti, ", IPv4/Port: %s", tvb_ip_to_str(pinfo->pool, tvb, offset));

          proto_tree_add_item( node_tree, hf_bt_tracker_tr_port, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
          proto_item_append_text(node_ti, ":%u", tvb_get_ntohs( tvb, offset + 4 ));
        }

        offset += stride_length;
      }
      proto_item_set_text(ti, "Trackers: %d trackers", node_index);
      col_append_fstr(pinfo->cinfo, COL_INFO, ": %d trackers", node_index);
    }

    break;

  case MSG_TYPE_SCRAPE_REQUEST:
    proto_tree_add_item(tree, hf_bt_tracker_connection_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, hf_bt_tracker_action, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_tracker_transaction_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    while (tvb_captured_length_remaining(tvb, offset) >= 20)
    {
      proto_tree_add_item(tree, hf_bt_tracker_info_hash, tvb, offset, 20, ENC_NA);
      offset += 20;
    }
    break;

  case MSG_TYPE_SCRAPE_RESPONSE:
    proto_tree_add_item(tree, hf_bt_tracker_action, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_tracker_transaction_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    while (tvb_captured_length_remaining(tvb, offset) >= 12)
    {
      proto_tree_add_item(tree, hf_bt_tracker_seeders, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(tree, hf_bt_tracker_completed, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(tree, hf_bt_tracker_leechers, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
    }

    break;

  case MSG_TYPE_ERROR_RESPONSE:
    proto_tree_add_item(tree, hf_bt_tracker_action, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_tracker_transaction_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_bt_tracker_error_msg, tvb, offset, -1, ENC_ASCII);
    offset = tvb_captured_length(tvb);
    break;

  }

  return offset;

}
static int
dissect_bt_tracker(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  unsigned msg_type;
  proto_item *ti;
  proto_tree *sub_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "BT-Tracker");
  col_clear(pinfo->cinfo, COL_INFO);

  msg_type = get_message_type(tvb);

  col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(msg_type, bt_tracker_msg_type_vals, " Unknown Msg Type"));

  ti = proto_tree_add_item(tree, proto_bt_tracker, tvb, 0, -1, ENC_NA);
  sub_tree = proto_item_add_subtree(ti, ett_bt_tracker);

  return dissect_bt_tracker_msg(tvb, pinfo, sub_tree, 0, msg_type);
}


static bool
dissect_bt_tracker_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  conversation_t *conversation;

  /* Look for a Connect Request */
  if (tvb_captured_length_remaining(tvb, 0) < 16)
    return false;
  if (tvb_get_ntoh64(tvb, 0) != MAGIC_CONSTANT)
    return false;
  if (tvb_get_ntohl(tvb, 8) != ACTION_CONNECT)
    return false;

  conversation = find_or_create_conversation(pinfo);
  conversation_set_dissector_from_frame_number(conversation, pinfo->num, bt_tracker_handle);

  dissect_bt_tracker(tvb, pinfo, tree, data);
  return true;
}

void
proto_register_bt_tracker(void)
{
  static hf_register_info hf[] = {
    { &hf_bt_tracker_protocol_id,
      { "Protocol", "bt-tracker.proto_id",
      FT_UINT64, BASE_HEX, NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_bt_tracker_action,
      { "Action", "bt-tracker.action",
      FT_UINT32, BASE_DEC, VALS(bt_tracker_action_vals), 0x0,
      NULL, HFILL }
    },
    { &hf_bt_tracker_transaction_id,
      { "Transaction Id", "bt-tracker.transaction_id",
      FT_UINT32, BASE_DEC, NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_bt_tracker_connection_id,
      { "Connection Id", "bt-tracker.connection_id",
      FT_UINT64, BASE_DEC, NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_bt_tracker_msg_type,
      { "Message Type", "bt-tracker.msg_type",
      FT_UINT8, BASE_DEC, VALS(bt_tracker_msg_type_vals), 0x0,
      NULL, HFILL }
    },
    { &hf_bt_tracker_info_hash,
      { "Info Hash", "bt-tracker.info_hash",
      FT_BYTES, BASE_NONE, NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_bt_tracker_peer_id,
      { "Peer Id", "bt-tracker.peer_id",
      FT_BYTES, BASE_NONE, NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_bt_tracker_downloaded,
      { "Downloaded", "bt-tracker.downloaded",
      FT_UINT64, BASE_DEC, NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_bt_tracker_left,
      { "Left", "bt-tracker.left",
      FT_UINT64, BASE_DEC, NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_bt_tracker_uploaded,
      { "Uploaded", "bt-tracker.uploaded",
      FT_UINT64, BASE_DEC, NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_bt_tracker_event,
      { "Event", "bt-tracker.event",
      FT_UINT32, BASE_DEC, VALS(bt_tracker_event_vals), 0x00,
      NULL, HFILL }
    },
    { &hf_bt_tracker_ip_address,
      { "IP Address", "bt-tracker.ip_address",
      FT_IPv4, BASE_NONE, NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_bt_tracker_key,
      { "Key", "bt-tracker.key",
      FT_UINT32, BASE_DEC, NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_bt_tracker_num_want,
      { "Num Want", "bt-tracker.num_want",
      FT_INT32, BASE_DEC, NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_bt_tracker_port,
      { "Port", "bt-tracker.port",
      FT_UINT16, BASE_DEC, NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_bt_tracker_interval,
      { "Interval", "bt-tracker.interval",
      FT_INT32, BASE_DEC, NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_bt_tracker_leechers,
      { "Leechers", "bt-tracker.leechers",
      FT_INT32, BASE_DEC, NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_bt_tracker_seeders,
      { "Seeders", "bt-tracker.seeders",
      FT_INT32, BASE_DEC, NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_bt_tracker_trackers,
      { "Trackers", "bt-tracker.trackers",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_tracker_tracker,
      { "Tracker", "bt-tracker.tracker",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_tracker_tr_ip,
      { "IP", "bt-tracker.tracker.ip",
      FT_IPv4, BASE_NONE, NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_bt_tracker_tr_ip6,
      { "IPv6", "bt-tracker.tracker.ip6",
      FT_IPv6, BASE_NONE, NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_bt_tracker_tr_port,
      { "(TCP) Port", "bt-tracker.tracker.port",
      FT_UINT16, BASE_DEC, NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_bt_tracker_completed,
      { "Completed", "bt-tracker.completed",
      FT_INT32, BASE_DEC, NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_bt_tracker_error_msg,
      { "Error message", "bt-tracker.error_msg",
      FT_STRING, BASE_NONE, NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_bt_tracker_extension,
      { "Extension", "bt-tracker.extension",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_tracker_extension_type,
      { "Extension Type", "bt-tracker.extension_type",
      FT_UINT8, BASE_HEX, VALS(bt_tracker_extension_type_vals), 0x0,
      NULL, HFILL }
    },
    { &hf_bt_tracker_extension_len,
      { "Extension Length", "bt-tracker.extension_len",
      FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_tracker_extension_unknown,
      { "Extension Unknown", "bt-tracker.extension_unknown",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_bt_tracker_extension_urldata,
      { "URL Data", "bt-tracker.extension.urldata",
      FT_STRING, BASE_NONE, NULL, 0x00,
      NULL, HFILL }
    },
  };

  /* Setup protocol subtree array */
  static int *ett[] = { &ett_bt_tracker, &ett_bt_tracker_trackers, &ett_bt_tracker_extension};
  module_t *bt_tracker_module;

  /* Register protocol */
  proto_bt_tracker = proto_register_protocol ("BitTorrent Tracker", "BT-Tracker", "bt-tracker");

  bt_tracker_module = prefs_register_protocol(proto_bt_tracker, NULL);
  prefs_register_obsolete_preference(bt_tracker_module, "enable");

  proto_register_field_array(proto_bt_tracker, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_bt_tracker(void)
{
  heur_dissector_add("udp", dissect_bt_tracker_heur, "BitTorrent Tracker over UDP", "bt_tracker_udp", proto_bt_tracker, HEURISTIC_ENABLE);

  bt_tracker_handle = create_dissector_handle(dissect_bt_tracker, proto_bt_tracker);
  dissector_add_for_decode_as_with_preference("udp.port", bt_tracker_handle);
}
