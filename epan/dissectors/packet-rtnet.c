/* packet-rtnet.c
 * Routines for RTnet packet disassembly
 *
 * $Id$
 *
 * Copyright (c) 2003 by Erwin Rol <erwin@erwinrol.com>
 * Copyright (c) 2004 by Jan Kiszka <jan.kiszka@web.de>
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

/* Include files */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <ctype.h>
#include <time.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/etypes.h>
#include <epan/strutil.h>

/*
 * See
 *
 *	http://www.rtnet.org/
 *
 *	http://www.rts.uni-hannover.de/rtnet/lxr/source/Documentation/RTmac.spec
 */

#define RTMAC_TYPE_TDMA     0x0001 /* since version 2    */
#define RTMAC_TYPE_TDMA_V1  0x9031 /* first TDMA version */

static const value_string rtmac_type_vals[] = {
  { RTMAC_TYPE_TDMA,    "TDMA" },
  { RTMAC_TYPE_TDMA_V1, "TDMA-V1" },
  { 0, NULL }
};

#define RTMAC_FLAG_TUNNEL   0x01
#define RTMAC_FLAGS_RES     0xFE

#define RTCFG_MSG_S1_CONFIG    0x0
#define RTCFG_MSG_ANN_NEW      0x1
#define RTCFG_MSG_ANN_REPLY    0x2
#define RTCFG_MSG_S2_CONFIG    0x3
#define RTCFG_MSG_S2_FRAG      0x4
#define RTCFG_MSG_ACK          0x5
#define RTCFG_MSG_READY        0x6
#define RTCFG_MSG_HBEAT        0x7
#define RTCFG_MSG_DEAD_STN     0x8

static const value_string rtcfg_msg_vals[] = {
  { RTCFG_MSG_S1_CONFIG, "Stage 1 Config" },
  { RTCFG_MSG_ANN_NEW,   "New Announce" },
  { RTCFG_MSG_ANN_REPLY, "Reply Announce" },
  { RTCFG_MSG_S2_CONFIG, "Stage 2 Config" },
  { RTCFG_MSG_S2_FRAG,   "Stage 2 Fragment" },
  { RTCFG_MSG_ACK,       "Acknowledge" },
  { RTCFG_MSG_READY,     "Ready" },
  { RTCFG_MSG_HBEAT,     "Heartbeat" },
  { RTCFG_MSG_DEAD_STN,  "Dead Station" },
  { 0, NULL }
};

#define RTCFG_ADDRESS_TYPE_MAC  0x00
#define RTCFG_ADDRESS_TYPE_IP   0x01

static const value_string rtcfg_address_type_vals[] = {
  { RTCFG_ADDRESS_TYPE_MAC,    "MAC" },
  { RTCFG_ADDRESS_TYPE_IP,     "IP" },
  { 0, NULL }
};

#define TDMA_V1_MSG_NOTIFY_MASTER          0x10
#define TDMA_V1_MSG_REQUEST_TEST           0x11
#define TDMA_V1_MSG_ACK_TEST               0x12
#define TDMA_V1_MSG_REQUEST_CONF           0x13
#define TDMA_V1_MSG_ACK_CONF               0x14
#define TDMA_V1_MSG_ACK_ACK_CONF           0x15
#define TDMA_V1_MSG_STATION_LIST           0x16
#define TDMA_V1_MSG_REQUEST_CHANGE_OFFSET  0x17
#define TDMA_V1_MSG_START_OF_FRAME         0x18

static const value_string tdma_v1_msg_vals[] = {
  { TDMA_V1_MSG_NOTIFY_MASTER,         "Notify Master" },
  { TDMA_V1_MSG_REQUEST_TEST,          "Request Test" },
  { TDMA_V1_MSG_ACK_TEST,              "Acknowledge Test" },
  { TDMA_V1_MSG_REQUEST_CONF,          "Request Config" },
  { TDMA_V1_MSG_ACK_CONF,              "Acknowledge Config" },
  { TDMA_V1_MSG_ACK_ACK_CONF,          "Ack Ack Config" },
  { TDMA_V1_MSG_STATION_LIST,          "Station List" },
  { TDMA_V1_MSG_REQUEST_CHANGE_OFFSET, "Request Change Offset" },
  { TDMA_V1_MSG_START_OF_FRAME,        "Start of Frame" },
  { 0, NULL }
};

#define TDMA_MSG_SYNC           0x0000
#define TDMA_MSG_CAL_REQUEST    0x0010
#define TDMA_MSG_CAL_REPLY      0x0011

static const value_string tdma_msg_vals[] = {
  { TDMA_MSG_SYNC,              "Synchronisation" },
  { TDMA_MSG_CAL_REQUEST,       "Request Calibration" },
  { TDMA_MSG_CAL_REPLY,         "Reply Calibration" },
  { 0, NULL }
};

static dissector_table_t ethertype_table;
static dissector_handle_t data_handle;

/* Define the rtnet proto */
static int proto_rtmac = -1;
static int proto_tdma = -1;
static int proto_rtcfg = -1;

/* RTmac Header */
static int hf_rtmac_header_type = -1;
static int hf_rtmac_header_ver = -1;
static int hf_rtmac_header_flags = -1;
static int hf_rtmac_header_flags_tunnel = -1;
static int hf_rtmac_header_flags_res = -1;
static int hf_rtmac_header_res_v1 = -1;


/* RTcfg */
static int hf_rtcfg_vers_id = -1;
static int hf_rtcfg_vers = -1;
static int hf_rtcfg_id = -1;
static int hf_rtcfg_address_type = -1;
static int hf_rtcfg_client_ip_address = -1;
static int hf_rtcfg_server_ip_address = -1;
static int hf_rtcfg_burst_rate = -1;
static int hf_rtcfg_padding = -1;
static int hf_rtcfg_s1_config_length = -1;
static int hf_rtcfg_config_data = -1;
static int hf_rtcfg_client_flags = -1;
static int hf_rtcfg_client_flags_available = -1;
static int hf_rtcfg_client_flags_ready = -1;
static int hf_rtcfg_client_flags_res = -1;
static int hf_rtcfg_server_flags = -1;
static int hf_rtcfg_server_flags_res0 = -1;
static int hf_rtcfg_server_flags_ready = -1;
static int hf_rtcfg_server_flags_res2 = -1;
static int hf_rtcfg_active_stations = -1;
static int hf_rtcfg_heartbeat_period = -1;
static int hf_rtcfg_s2_config_length = -1;
static int hf_rtcfg_config_offset = -1;
static int hf_rtcfg_ack_length = -1;
static int hf_rtcfg_client_hw_address = -1;


/* TDMA-V1 */
static int hf_tdma_v1_msg = -1;

/* TDMA REQUEST_CONF */
static int hf_tdma_v1_msg_request_conf_station = -1;
static int hf_tdma_v1_msg_request_conf_padding = -1;
static int hf_tdma_v1_msg_request_conf_mtu = -1;
static int hf_tdma_v1_msg_request_conf_cycle = -1;

/* TDMA ACK_CONF */
static int hf_tdma_v1_msg_ack_conf_station = -1;
static int hf_tdma_v1_msg_ack_conf_padding = -1;
static int hf_tdma_v1_msg_ack_conf_mtu = -1;
static int hf_tdma_v1_msg_ack_conf_cycle = -1;

/* TDMA ACK_ACK_CONF */
static int hf_tdma_v1_msg_ack_ack_conf_station = -1;
static int hf_tdma_v1_msg_ack_ack_conf_padding = -1;

/* TDMA REQUEST_TEST */
static int hf_tdma_v1_msg_request_test_counter = -1;
static int hf_tdma_v1_msg_request_test_tx = -1;

/* TDMA ACK_TEST */
static int hf_tdma_v1_msg_ack_test_counter = -1;
static int hf_tdma_v1_msg_ack_test_tx = -1;

/* TDMA STATION_LIST */
static int hf_tdma_v1_msg_station_list_nr_stations = -1;
static int hf_tdma_v1_msg_station_list_padding = -1;

static int hf_tdma_v1_msg_station_list_ip = -1;
static int hf_tdma_v1_msg_station_list_nr = -1;

/* TDMA CHANGE_OFFSET */
static int hf_tdma_v1_msg_request_change_offset_offset = -1;

/* TDMA START_OF_FRAME */
static int hf_tdma_v1_msg_start_of_frame_timestamp = -1;


/* TDMA since version 2 */
static int hf_tdma_ver = -1;
static int hf_tdma_id = -1;

/* TDMA Sync */
static int hf_tdma_sync_cycle = -1;
static int hf_tdma_sync_xmit_stamp = -1;
static int hf_tdma_sync_sched_xmit = -1;

/* TDMA Request Calibration */
static int hf_tdma_req_cal_xmit_stamp = -1;
static int hf_tdma_req_cal_rpl_cycle = -1;
static int hf_tdma_req_cal_rpl_slot = -1;

/* TDMA Reply Calibration */
static int hf_tdma_rpl_cal_req_stamp = -1;
static int hf_tdma_rpl_cal_rcv_stamp = -1;
static int hf_tdma_rpl_cal_xmit_stamp = -1;


/* Define the tree for rtnet */
static int ett_rtmac = -1;
static int ett_rtmac_flags = -1;
static int ett_tdma = -1;
static int ett_rtcfg = -1;

static guint
dissect_rtnet_tdma_notify_master(tvbuff_t *tvb _U_, guint offset, proto_tree *tree _U_)
{
  return offset;
}

static guint
dissect_rtnet_tdma_request_test(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_tdma_v1_msg_request_test_counter, tvb,
                       offset, 4, ENC_LITTLE_ENDIAN );
  offset += 4;

  proto_tree_add_item(tree, hf_tdma_v1_msg_request_test_tx, tvb,
                       offset, 8, ENC_LITTLE_ENDIAN );
  offset += 8;

  return offset;
}

static guint
dissect_rtnet_tdma_ack_test(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_tdma_v1_msg_ack_test_counter, tvb,
                       offset, 4, ENC_LITTLE_ENDIAN );
  offset += 4;

  proto_tree_add_item(tree, hf_tdma_v1_msg_ack_test_tx, tvb,
                       offset, 8, ENC_LITTLE_ENDIAN );
  offset += 8;

  return offset;
}

static guint
dissect_rtnet_tdma_request_conf(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_tdma_v1_msg_request_conf_station, tvb,
                       offset, 1, ENC_BIG_ENDIAN );
  offset += 1;

  proto_tree_add_item(tree, hf_tdma_v1_msg_request_conf_padding, tvb,
                       offset, 1, ENC_BIG_ENDIAN );
  offset += 1;

  proto_tree_add_item(tree, hf_tdma_v1_msg_request_conf_mtu, tvb,
                       offset, 2, ENC_BIG_ENDIAN );
  offset += 2;

  proto_tree_add_item(tree, hf_tdma_v1_msg_request_conf_cycle, tvb,
                       offset, 4, ENC_BIG_ENDIAN );
  offset += 4;

  return offset;
}


static guint
dissect_rtnet_tdma_ack_conf(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_tdma_v1_msg_ack_conf_station, tvb,
                       offset, 1, ENC_BIG_ENDIAN );
  offset += 1;

  proto_tree_add_item(tree, hf_tdma_v1_msg_ack_conf_padding, tvb,
                       offset, 1, ENC_BIG_ENDIAN );
  offset += 1;

  proto_tree_add_item(tree, hf_tdma_v1_msg_ack_conf_mtu, tvb,
                       offset, 2, ENC_BIG_ENDIAN );
  offset += 2;

  proto_tree_add_item(tree, hf_tdma_v1_msg_ack_conf_cycle, tvb,
                       offset, 4, ENC_BIG_ENDIAN );
  offset += 4;

  return offset;
}

static guint
dissect_rtnet_tdma_ack_ack_conf(tvbuff_t *tvb, guint offset, proto_tree *tree) {

  proto_tree_add_item(tree, hf_tdma_v1_msg_ack_ack_conf_station, tvb,
                       offset, 1, ENC_BIG_ENDIAN );

  offset += 1;

  proto_tree_add_item(tree, hf_tdma_v1_msg_ack_ack_conf_padding, tvb,
                       offset, 3, ENC_NA );
  offset += 3;

  return offset;
}

static guint
dissect_rtnet_tdma_station_list(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  guint8 nr_stations;
  guint8 i;

  nr_stations = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(tree, hf_tdma_v1_msg_station_list_nr_stations, tvb,
                      offset, 1, nr_stations);

  offset += 1;

  proto_tree_add_item(tree, hf_tdma_v1_msg_station_list_padding, tvb,
                       offset, 3, ENC_NA );
  offset += 3;


  for( i = 0; i < nr_stations; i++ )
  {
    proto_tree_add_item(tree, hf_tdma_v1_msg_station_list_ip, tvb,
                        offset, 4, ENC_BIG_ENDIAN );

    offset += 4;

    proto_tree_add_item(tree, hf_tdma_v1_msg_station_list_nr, tvb,
                        offset, 1, ENC_BIG_ENDIAN );

    offset += 1;

    proto_tree_add_item(tree, hf_tdma_v1_msg_station_list_padding, tvb,
                        offset, 3, ENC_NA );
    offset += 3;
  }

  return offset;
}

static guint
dissect_rtnet_tdma_request_change_offset(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_tdma_v1_msg_request_change_offset_offset, tvb,
                       offset, 4, ENC_BIG_ENDIAN );

  offset += 4;

  return offset;
}

static guint
dissect_rtnet_tdma_start_of_frame(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_tdma_v1_msg_start_of_frame_timestamp, tvb,
                       offset, 8, ENC_BIG_ENDIAN );
  offset += 8;

  return offset;
}

static void
dissect_rtnet_tdma_v1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *root) {
  guint offset = 0;
  guint32 msg;
  proto_tree *tree;
  proto_item *ti;

  msg = tvb_get_ntohl(tvb, offset);

  /* Set the protocol column */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "TDMA-V1");

  /* set the info column */
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
      val_to_str(msg, tdma_v1_msg_vals, "Unknown (0x%04x)"));
  }

  if (root) {
    ti = proto_tree_add_item(root, proto_tdma, tvb, 0, -1, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_tdma);

    proto_item_append_text(ti, ", Version 1, %s",
      val_to_str(msg, tdma_v1_msg_vals, "Unknown (0x%04x)"));

    proto_tree_add_item(tree, hf_tdma_v1_msg, tvb,
                        offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    switch( msg ) {
      case TDMA_V1_MSG_NOTIFY_MASTER:
        dissect_rtnet_tdma_notify_master(tvb, offset, tree);
        break;

      case TDMA_V1_MSG_REQUEST_TEST:
        dissect_rtnet_tdma_request_test(tvb, offset, tree);
        break;

      case TDMA_V1_MSG_ACK_TEST:
        dissect_rtnet_tdma_ack_test(tvb, offset, tree);
        break;

      case TDMA_V1_MSG_REQUEST_CONF:
        dissect_rtnet_tdma_request_conf(tvb, offset, tree);
        break;

      case TDMA_V1_MSG_ACK_CONF:
        dissect_rtnet_tdma_ack_conf(tvb, offset, tree);
        break;

      case TDMA_V1_MSG_ACK_ACK_CONF:
        dissect_rtnet_tdma_ack_ack_conf(tvb, offset, tree);
        break;

      case TDMA_V1_MSG_STATION_LIST:
        dissect_rtnet_tdma_station_list (tvb, offset, tree);
        break;

      case TDMA_V1_MSG_REQUEST_CHANGE_OFFSET:
        dissect_rtnet_tdma_request_change_offset(tvb, offset, tree);
        break;

      case TDMA_V1_MSG_START_OF_FRAME:
        dissect_rtnet_tdma_start_of_frame(tvb, offset, tree);
        break;

      default:
        break;
    }
  }
}

static void
dissect_tdma_sync(tvbuff_t *tvb, guint offset, proto_tree *tree) {
  gint64 timestamp;
  proto_item *ti;

  proto_tree_add_item(tree, hf_tdma_sync_cycle, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  ti = proto_tree_add_item(tree, hf_tdma_sync_xmit_stamp, tvb, offset, 8, ENC_BIG_ENDIAN);
  timestamp = tvb_get_ntoh64(tvb, offset) - tvb_get_ntoh64(tvb, offset+8);
  proto_item_append_text(ti, " (%s%" G_GINT64_MODIFIER "d)", (timestamp > 0) ? "+" : "", timestamp);
  offset += 8;

  proto_tree_add_item(tree, hf_tdma_sync_sched_xmit, tvb, offset, 8, ENC_BIG_ENDIAN);
}

static void
dissect_tdma_request_cal(tvbuff_t *tvb, guint offset, proto_tree *tree) {

  proto_tree_add_item(tree, hf_tdma_req_cal_xmit_stamp, tvb, offset, 8, ENC_BIG_ENDIAN);
  offset += 8;

  proto_tree_add_item(tree, hf_tdma_req_cal_rpl_cycle, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_tdma_req_cal_rpl_slot, tvb, offset, 8, ENC_BIG_ENDIAN);
}

static void
dissect_tdma_reply_cal(tvbuff_t *tvb, guint offset, proto_tree *tree) {
  gint64 timestamp;
  proto_item *ti;

  proto_tree_add_item(tree, hf_tdma_rpl_cal_req_stamp, tvb, offset, 8, ENC_BIG_ENDIAN);
  offset += 8;

  proto_tree_add_item(tree, hf_tdma_rpl_cal_rcv_stamp, tvb, offset, 8, ENC_BIG_ENDIAN);

  timestamp = tvb_get_ntoh64(tvb, offset+8) - tvb_get_ntoh64(tvb, offset);
  offset += 8;

  ti = proto_tree_add_item(tree, hf_tdma_rpl_cal_xmit_stamp, tvb, offset, 8, ENC_BIG_ENDIAN);
  proto_item_append_text(ti, " (%s%" G_GINT64_MODIFIER "d)", (timestamp > 0) ? "+" : "", timestamp);
}

static void
dissect_rtnet_tdma(tvbuff_t *tvb, packet_info *pinfo, proto_tree *root) {
  guint offset = 0;
  guint16 msg;
  proto_item *ti;
  proto_tree *tree;

  msg = tvb_get_ntohs(tvb, 2);

  /* Set the protocol column */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "TDMA");

  /* Set the info column */
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
                 val_to_str(msg, tdma_msg_vals, "Unknown (0x%04x)"));
  }

  if (root) {
    ti = proto_tree_add_item(root, proto_tdma, tvb, 0, -1, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_tdma);

    proto_item_append_text(ti, ", %s", val_to_str(msg, tdma_msg_vals, "Unknown (0x%04x)"));

    proto_tree_add_item(tree, hf_tdma_ver, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_tdma_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    switch (msg) {
      case TDMA_MSG_SYNC:
        dissect_tdma_sync(tvb, offset, tree);
        break;

      case TDMA_MSG_CAL_REQUEST:
        dissect_tdma_request_cal(tvb, offset, tree);
        break;

      case TDMA_MSG_CAL_REPLY:
        dissect_tdma_reply_cal(tvb, offset, tree);
        break;

      default:
        break;
    }
  }
}

static void
dissect_rtmac(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  gint offset = 0;
  guint8 ver,flags;
  guint16 type;
  tvbuff_t *next_tvb;
  proto_tree *ti=NULL, *rtmac_tree=NULL;
  proto_item *item;
  dissector_handle_t dissector=NULL;
  const gchar *type_str=NULL;

  /* Read the header */
  type = tvb_get_ntohs(tvb, offset);
  ver = tvb_get_guint8(tvb, offset+2);
  flags = tvb_get_guint8(tvb, offset+3);

  if (ver == 1) {
    type_str = match_strval(type, rtmac_type_vals);
    if (!type_str) {
      dissector = dissector_get_uint_handle(ethertype_table, type);
    }
  } else {
    if (flags & RTMAC_FLAG_TUNNEL) {
      dissector = dissector_get_uint_handle(ethertype_table, type);
    }
  }
  if (!dissector)
    dissector = data_handle;

  if (tree) {
    ti = proto_tree_add_item(tree, proto_rtmac, tvb, offset, 4, ENC_NA);
    rtmac_tree = proto_item_add_subtree(ti, ett_rtmac);
    proto_item_append_text(ti, ", Version %d", ver);
  }

  /* Set the protocol column */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTmac");

  /* set the info column */
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_clear(pinfo->cinfo,COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown (0x%04x)",type);
  }

  if (rtmac_tree) {
    if (ver == 1) {
      if (!type_str) {
        if (dissector != data_handle)
          type_str = dissector_handle_get_short_name(dissector);
        else
          type_str = "Unknown";
      }
    } else {
      if (!(flags & RTMAC_FLAG_TUNNEL))
        type_str = val_to_str(type, rtmac_type_vals, "Unknown");
      else {
        if (dissector != data_handle)
          type_str = dissector_handle_get_short_name(dissector);
        else
          type_str = "Unknown";
      }
    }
    proto_tree_add_string_format(rtmac_tree, hf_rtmac_header_type, tvb, offset, 2,
                                 type_str, "Type: %s (0x%04x)", type_str, type);
    offset += 2;

    proto_tree_add_item(rtmac_tree, hf_rtmac_header_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (ver == 1)
      proto_tree_add_item(rtmac_tree, hf_rtmac_header_res_v1, tvb, offset, 1, ENC_BIG_ENDIAN);
    else {
      item = proto_tree_add_item(rtmac_tree, hf_rtmac_header_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
      ti = proto_item_add_subtree(item, ett_rtmac_flags);
      proto_tree_add_item(ti, hf_rtmac_header_flags_res, tvb, offset, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(ti, hf_rtmac_header_flags_tunnel, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    offset += 1;
  }
  else
    offset += 4;

  next_tvb = tvb_new_subset_remaining(tvb, offset);

  if (ver == 1)
    switch (type) {
      case RTMAC_TYPE_TDMA_V1:
        dissect_rtnet_tdma_v1(next_tvb, pinfo, tree);
        break;

      default:
        call_dissector(dissector, next_tvb, pinfo, tree);
        break;
    }
  else
    if (flags & RTMAC_FLAG_TUNNEL)
      call_dissector(dissector, next_tvb, pinfo, tree);
    else
      switch (type) {
        case RTMAC_TYPE_TDMA:
          dissect_rtnet_tdma(next_tvb, pinfo, tree);
          break;

        default:
          call_dissector(data_handle, next_tvb, pinfo, tree);
          break;
      }
}

static void
dissect_rtcfg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  gint offset = 0;
  proto_tree *vers_id_tree, *vers_id_item, *flags_tree, *flags_item;
  guint8 vers_id;
  guint8 addr_type;
  guint32 config_length,len;
  proto_tree *ti=NULL,*rtcfg_tree=NULL;

  /* Set the protocol column */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTcfg");

  /* Clear out stuff in the info column */
  col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_rtcfg, tvb, offset, -1, ENC_NA);
    rtcfg_tree = proto_item_add_subtree(ti, ett_rtcfg);
  }

  vers_id = tvb_get_guint8(tvb, offset);

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
           val_to_str(vers_id, rtcfg_msg_vals, "Unknown (0x%04x)"));
  }

  if( rtcfg_tree )
  {
    vers_id_item = proto_tree_add_uint(rtcfg_tree, hf_rtcfg_vers_id, tvb,
                                       offset, 1, vers_id);

    vers_id_tree=proto_item_add_subtree(vers_id_item, ett_rtcfg);
    proto_tree_add_item(vers_id_tree, hf_rtcfg_vers, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(vers_id_tree, hf_rtcfg_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_item_append_text(ti, ", Version %d, %s",
             (vers_id >> 5),
             val_to_str(vers_id, rtcfg_msg_vals, "Unknown (0x%04x)"));

    switch( vers_id & 0x1f )
    {
       case RTCFG_MSG_S1_CONFIG:
         addr_type = tvb_get_guint8(tvb, offset);
         proto_tree_add_item( rtcfg_tree, hf_rtcfg_address_type, tvb, offset, 1, ENC_BIG_ENDIAN );
         offset += 1;

         switch( addr_type )
         {
           case RTCFG_ADDRESS_TYPE_MAC:
             /* nothing */
             break;

           case RTCFG_ADDRESS_TYPE_IP:
             proto_tree_add_item( rtcfg_tree, hf_rtcfg_client_ip_address, tvb, offset, 4, ENC_BIG_ENDIAN );
             offset += 4;

             proto_tree_add_item( rtcfg_tree, hf_rtcfg_server_ip_address, tvb, offset, 4, ENC_BIG_ENDIAN );
             offset += 4;

             break;
         }

         proto_tree_add_item( rtcfg_tree, hf_rtcfg_burst_rate, tvb, offset, 1, ENC_BIG_ENDIAN );
         offset += 1;

         config_length = tvb_get_ntohs( tvb, offset );
         proto_tree_add_item( rtcfg_tree, hf_rtcfg_s1_config_length, tvb, offset, 2, ENC_BIG_ENDIAN );
         offset += 2;

         if( config_length > 0 ) {
           proto_tree_add_item( rtcfg_tree, hf_rtcfg_config_data, tvb, offset, config_length, ENC_NA );
           offset += config_length;
         }

         break;

       case RTCFG_MSG_ANN_NEW:
         addr_type = tvb_get_guint8(tvb, offset);
         proto_tree_add_item( rtcfg_tree, hf_rtcfg_address_type, tvb, offset, 1, ENC_BIG_ENDIAN );
         offset += 1;

         switch( addr_type )
         {
           case RTCFG_ADDRESS_TYPE_MAC:
             /* nothing */
             break;

           case RTCFG_ADDRESS_TYPE_IP:
             proto_tree_add_item( rtcfg_tree, hf_rtcfg_client_ip_address, tvb, offset, 4, ENC_BIG_ENDIAN );
             offset += 4;
             break;
         }

         flags_item = proto_tree_add_item(rtcfg_tree, hf_rtcfg_client_flags, tvb,
                                          offset, 1, ENC_BIG_ENDIAN);

         flags_tree=proto_item_add_subtree(flags_item, ett_rtcfg);
         proto_tree_add_item(flags_tree, hf_rtcfg_client_flags_available, tvb, offset, 1, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_rtcfg_client_flags_ready, tvb, offset, 1, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_rtcfg_client_flags_res, tvb, offset, 1, ENC_BIG_ENDIAN);
         offset += 1;

         proto_tree_add_item( rtcfg_tree, hf_rtcfg_burst_rate, tvb, offset, 1, ENC_BIG_ENDIAN );
         offset += 1;

         break;

       case RTCFG_MSG_ANN_REPLY:
         addr_type = tvb_get_guint8(tvb, offset);
         proto_tree_add_item( rtcfg_tree, hf_rtcfg_address_type, tvb, offset, 1, ENC_BIG_ENDIAN );
         offset += 1;

         switch( addr_type )
         {
           case RTCFG_ADDRESS_TYPE_MAC:
             /* nothing */
             break;

           case RTCFG_ADDRESS_TYPE_IP:
             proto_tree_add_item( rtcfg_tree, hf_rtcfg_client_ip_address, tvb, offset, 4, ENC_BIG_ENDIAN );
             offset += 4;
             break;
         }

         flags_item = proto_tree_add_item(rtcfg_tree, hf_rtcfg_client_flags, tvb,
                                          offset, 1, ENC_BIG_ENDIAN);

         flags_tree=proto_item_add_subtree(flags_item, ett_rtcfg);
         proto_tree_add_item(flags_tree, hf_rtcfg_client_flags_available, tvb, offset, 1, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_rtcfg_client_flags_ready, tvb, offset, 1, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_rtcfg_client_flags_res, tvb, offset, 1, ENC_BIG_ENDIAN);
         offset += 1;

         proto_tree_add_item( rtcfg_tree, hf_rtcfg_padding, tvb, offset, 1, ENC_BIG_ENDIAN );
         offset += 1;

         break;

       case RTCFG_MSG_S2_CONFIG:
         flags_item = proto_tree_add_item(rtcfg_tree, hf_rtcfg_server_flags, tvb,
                                          offset, 1, ENC_BIG_ENDIAN);

         flags_tree=proto_item_add_subtree(flags_item, ett_rtcfg);
         proto_tree_add_item(flags_tree, hf_rtcfg_server_flags_res0, tvb, offset, 1, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_rtcfg_server_flags_ready, tvb, offset, 1, ENC_BIG_ENDIAN);
         proto_tree_add_item(flags_tree, hf_rtcfg_server_flags_res2, tvb, offset, 1, ENC_BIG_ENDIAN);
         offset += 1;

         proto_tree_add_item( rtcfg_tree, hf_rtcfg_active_stations, tvb, offset, 4, ENC_BIG_ENDIAN );
         offset += 4;

         proto_tree_add_item( rtcfg_tree, hf_rtcfg_heartbeat_period, tvb, offset, 2, ENC_BIG_ENDIAN );
         offset += 2;

         config_length = tvb_get_ntohl( tvb, offset );
         proto_tree_add_item( rtcfg_tree, hf_rtcfg_s2_config_length, tvb, offset, 4, ENC_BIG_ENDIAN );
         offset += 4;

         if( config_length > 0 ) {
           len = tvb_reported_length_remaining(tvb, offset);
           proto_tree_add_item( rtcfg_tree, hf_rtcfg_config_data, tvb, offset, len, ENC_NA );
           offset += len;
         }

         break;

       case RTCFG_MSG_S2_FRAG:
         proto_tree_add_item( rtcfg_tree, hf_rtcfg_config_offset, tvb, offset, 4, ENC_BIG_ENDIAN );
         offset += 4;

         len = tvb_reported_length_remaining(tvb, offset);
         proto_tree_add_item( rtcfg_tree, hf_rtcfg_config_data, tvb, offset, len, ENC_NA );
         offset += len;
         break;

       case RTCFG_MSG_ACK:
         proto_tree_add_item( rtcfg_tree, hf_rtcfg_ack_length, tvb, offset, 4, ENC_BIG_ENDIAN );
         offset += 4;

         break;

       case RTCFG_MSG_READY:
         break;

       case RTCFG_MSG_HBEAT:
         break;

       case RTCFG_MSG_DEAD_STN:
         addr_type = tvb_get_guint8(tvb, offset);
         proto_tree_add_item( rtcfg_tree, hf_rtcfg_address_type, tvb, offset, 1, ENC_BIG_ENDIAN );
         offset += 1;

         switch( addr_type )
         {
           case RTCFG_ADDRESS_TYPE_MAC:
             /* nothing */
             break;

           case RTCFG_ADDRESS_TYPE_IP:
             proto_tree_add_item( rtcfg_tree, hf_rtcfg_client_ip_address, tvb, offset, 4, ENC_BIG_ENDIAN );
             offset += 4;
             break;
         }

         switch (pinfo->fd->lnk_t) {
           case WTAP_ENCAP_ETHERNET:
             proto_tree_add_bytes_format( rtcfg_tree, hf_rtcfg_client_hw_address, tvb, offset, 32,
                                          NULL, "Client Hardware Address: %s",
					  tvb_ether_to_str(tvb, offset));
             break;

           default:
             proto_tree_add_item( rtcfg_tree, hf_rtcfg_client_hw_address, tvb, offset, 32, ENC_NA );
             break;
         }
         offset += 32;

         break;

    }
  }
}

void
proto_register_rtmac(void) {
  static hf_register_info hf_array_rtmac[] = {

    /* RTmac header */
    { &hf_rtmac_header_type,
      { "Type",
        "rtmac.header.type",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "RTmac Type", HFILL }},

    { &hf_rtmac_header_ver,
      { "Version",
        "rtmac.header.ver",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "RTmac Version", HFILL }},

    { &hf_rtmac_header_flags,
      { "Flags",
        "rtmac.header.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "RTmac Flags", HFILL }},

    { &hf_rtmac_header_flags_tunnel,
      { "Tunnelling Flag",
        "rtmac.header.flags.tunnel",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), RTMAC_FLAG_TUNNEL,
        "RTmac Tunnelling Flag", HFILL }},

    { &hf_rtmac_header_flags_res,
      { "Reserved Flags",
        "rtmac.header.flags.res",
        FT_UINT8, BASE_HEX, NULL, RTMAC_FLAGS_RES,
        "RTmac Reserved Flags", HFILL }},

    { &hf_rtmac_header_res_v1,
      { "Reserved",
        "rtmac.header.res",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "RTmac Reserved", HFILL }},
  };

  static hf_register_info hf_array_tdma[] = {

    /* TDMA msg */
    { &hf_tdma_v1_msg,
      { "Message",
        "tdma-v1.msg",
        FT_UINT32, BASE_HEX, VALS(tdma_v1_msg_vals), 0x0,
        "TDMA-V1 Message", HFILL }},

    /* TDMA request conf */

    { &hf_tdma_v1_msg_request_conf_station,
      { "Station",
        "tdma-v1.msg.request_conf.station",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "TDMA Station", HFILL }},

    { &hf_tdma_v1_msg_request_conf_padding,
      { "Padding",
        "tdma-v1.msg.request_conf.padding",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "TDMA Padding", HFILL }},

    { &hf_tdma_v1_msg_request_conf_mtu,
      { "MTU",
        "tdma-v1.msg.request_conf.mtu",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "TDMA MTU", HFILL }},

    { &hf_tdma_v1_msg_request_conf_cycle,
      { "Cycle",
        "tdma-v1.msg.request_conf.cycle",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "TDMA Cycle", HFILL }},

    /* TDMA ack conf */

    { &hf_tdma_v1_msg_ack_conf_station,
      { "Station",
        "tdma-v1.msg.ack_conf.station",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "TDMA Station", HFILL }},

    { &hf_tdma_v1_msg_ack_conf_padding,
      { "Padding",
        "tdma-v1.msg.ack_conf.padding",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "TDMA Padding", HFILL }},

    { &hf_tdma_v1_msg_ack_conf_mtu,
      { "MTU",
        "tdma-v1.msg.ack_conf.mtu",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "TDMA MTU", HFILL }},

    { &hf_tdma_v1_msg_ack_conf_cycle,
      { "Cycle",
        "tdma-v1.msg.ack_conf.cycle",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "TDMA Cycle", HFILL }},

    /* TDMA ack ack conf */

    { &hf_tdma_v1_msg_ack_ack_conf_station,
      { "Station",
        "tdma-v1.msg.ack_ack_conf.station",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "TDMA Station", HFILL }},

    { &hf_tdma_v1_msg_ack_ack_conf_padding,
      { "Padding",
        "tdma-v1.msg.ack_ack_conf.padding",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "TDMA Padding", HFILL }},

    /* TDMA request test */

    { &hf_tdma_v1_msg_request_test_counter,
      { "Counter",
        "tdma-v1.msg.request_test.counter",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "TDMA Counter", HFILL }},

    { &hf_tdma_v1_msg_request_test_tx,
      { "TX",
        "tdma-v1.msg.request_test.tx",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        "TDMA TX", HFILL }},

    /* TDMA ack test */

    { &hf_tdma_v1_msg_ack_test_counter,
      { "Counter",
        "tdma-v1.msg.ack_test.counter",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "TDMA Counter", HFILL }},

    { &hf_tdma_v1_msg_ack_test_tx,
      { "TX",
        "tdma-v1.msg.ack_test.tx",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        "TDMA TX", HFILL }},

    /* TDMA ack test */

    { &hf_tdma_v1_msg_request_change_offset_offset,
      { "Offset",
        "tdma-v1.msg.request_change_offset.offset",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "TDMA Offset", HFILL }},

    /* TDMA start of frame */


    { &hf_tdma_v1_msg_start_of_frame_timestamp,
      { "Timestamp",
        "tdma-v1.msg.start_of_frame.timestamp",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        "TDMA Timestamp", HFILL }},

    /* TDMA station list */

    { &hf_tdma_v1_msg_station_list_nr_stations,
      { "Nr. Stations",
        "tdma-v1.msg.station_list.nr_stations",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "TDMA Nr. Stations", HFILL }},

    { &hf_tdma_v1_msg_station_list_nr,
      { "Nr.",
        "tdma-v1.msg.station_list.nr",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "TDMA Station Number", HFILL }},

    { &hf_tdma_v1_msg_station_list_ip,
      { "IP",
        "tdma-v1.msg.station_list.ip",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        "TDMA Station IP", HFILL }},

    { &hf_tdma_v1_msg_station_list_padding,
      { "Padding",
        "tdma-v1.msg.station_list.padding",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "TDMA Padding", HFILL }},


    /* TDMA since version 2 */

    { &hf_tdma_ver,
      { "Version",
        "tdma.ver",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "TDMA Version", HFILL }},

    { &hf_tdma_id,
      { "Message ID",
        "tdma.id",
        FT_UINT16, BASE_HEX, VALS(tdma_msg_vals), 0x0,
        "TDMA Message ID", HFILL }},

    /* TDMA sync */

    { &hf_tdma_sync_cycle,
      { "Cycle Number",
        "tdma.sync.cycle",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "TDMA Sync Cycle Number", HFILL }},

    { &hf_tdma_sync_xmit_stamp,
      { "Transmission Time Stamp",
        "tdma.sync.xmit_stamp",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        "TDMA Sync Transmission Time Stamp", HFILL }},

    { &hf_tdma_sync_sched_xmit,
      { "Scheduled Transmission Time",
        "tdma.sync.sched_xmit",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        "TDMA Sync Scheduled Transmission Time", HFILL }},

    /* TDMA request calibration */

    { &hf_tdma_req_cal_xmit_stamp,
      { "Transmission Time Stamp",
        "tdma.req_cal.xmit_stamp",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        "TDMA Request Calibration Transmission Time Stamp", HFILL }},

    { &hf_tdma_req_cal_rpl_cycle,
      { "Reply Cycle Number",
        "tdma.req_cal.rpl_cycle",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "TDMA Request Calibration Reply Cycle Number", HFILL }},

    { &hf_tdma_req_cal_rpl_slot,
      { "Reply Slot Offset",
        "tdma.req_cal.rpl_slot",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        "TDMA Request Calibration Reply Slot Offset", HFILL }},

    /* TDMA reply calibration */

    { &hf_tdma_rpl_cal_req_stamp,
      { "Request Transmission Time",
        "tdma.rpl_cal.req_stamp",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        "TDMA Reply Calibration Request Transmission Time", HFILL }},

    { &hf_tdma_rpl_cal_rcv_stamp,
      { "Reception Time Stamp",
        "tdma.rpl_cal.rcv_stamp",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        "TDMA Reply Calibration Reception Time Stamp", HFILL }},

    { &hf_tdma_rpl_cal_xmit_stamp,
      { "Transmission Time Stamp",
        "tdma.rpl_cal.xmit_stamp",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        "TDMA Reply Calibration Transmission Time Stamp", HFILL }},
  };

  static gint *ett_array_rtmac[] = {
    &ett_rtmac,
    &ett_rtmac_flags,
  };

  static gint *ett_array_tdma[] = {
    &ett_tdma,
  };

  proto_rtmac = proto_register_protocol("Real-Time Media Access Control", "RTmac", "rtmac");
  proto_register_field_array(proto_rtmac, hf_array_rtmac, array_length(hf_array_rtmac));
  proto_register_subtree_array(ett_array_rtmac, array_length(ett_array_rtmac));

  proto_tdma = proto_register_protocol("TDMA RTmac Discipline", "TDMA", "tdma");
  proto_register_field_array(proto_rtmac, hf_array_tdma, array_length(hf_array_tdma));
  proto_register_subtree_array(ett_array_tdma, array_length(ett_array_tdma));
}


void
proto_register_rtcfg(void) {
  static hf_register_info hf[] = {
    { &hf_rtcfg_vers_id,
      { "Version and ID",
        "rtcfg.vers_id",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "RTcfg Version and ID", HFILL }},

    { &hf_rtcfg_vers,
      { "Version",
        "rtcfg.vers",
        FT_UINT8, BASE_DEC, NULL, 0xe0,
        "RTcfg Version", HFILL }},

    { &hf_rtcfg_id,
      { "ID",
        "rtcfg.id",
        FT_UINT8, BASE_HEX, VALS(rtcfg_msg_vals), 0x1f,
        "RTcfg ID", HFILL }},

    { &hf_rtcfg_address_type,
      { "Address Type",
        "rtcfg.address_type",
        FT_UINT8, BASE_DEC, VALS(rtcfg_address_type_vals), 0x00,
        "RTcfg Address Type", HFILL }},

    { &hf_rtcfg_client_ip_address,
      { "Client IP Address",
        "rtcfg.client_ip_address",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        "RTcfg Client IP Address", HFILL }},

    { &hf_rtcfg_server_ip_address,
      { "Server IP Address",
        "rtcfg.server_ip_address",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        "RTcfg Server IP Address", HFILL }},

    { &hf_rtcfg_burst_rate,
      { "Stage 2 Burst Rate",
        "rtcfg.burst_rate",
        FT_UINT8, BASE_DEC, NULL, 0x00,
        "RTcfg Stage 2 Burst Rate", HFILL }},

    { &hf_rtcfg_s1_config_length,
      { "Stage 1 Config Length",
        "rtcfg.s1_config_length",
        FT_UINT16, BASE_DEC, NULL, 0x00,
        "RTcfg Stage 1 Config Length", HFILL }},

    { &hf_rtcfg_config_data,
      { "Config Data",
        "rtcfg.config_data",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        "RTcfg Config Data", HFILL }},

    { &hf_rtcfg_padding,
      { "Padding",
        "rtcfg.padding",
        FT_UINT8, BASE_DEC, NULL, 0x00,
        "RTcfg Padding", HFILL }},

    { &hf_rtcfg_client_flags,
      { "Flags",
        "rtcfg.client_flags",
        FT_UINT8, BASE_HEX, NULL, 0x00,
        "RTcfg Client Flags", HFILL }},

    { &hf_rtcfg_client_flags_available,
      { "Req. Available",
        "rtcfg.client_flags.available",
        FT_UINT8, BASE_DEC, NULL, 0x01,
        "Request Available", HFILL }},

    { &hf_rtcfg_client_flags_ready,
      { "Client Ready",
        "rtcfg.client_flags.ready",
        FT_UINT8, BASE_DEC, NULL, 0x02,
        NULL, HFILL }},

    { &hf_rtcfg_client_flags_res,
      { "Reserved",
        "rtcfg.client_flags.res",
        FT_UINT8, BASE_HEX, NULL, 0xfc,
        NULL, HFILL }},

    { &hf_rtcfg_server_flags,
      { "Flags",
        "rtcfg.server_flags",
        FT_UINT8, BASE_HEX, NULL, 0x00,
        "RTcfg Server Flags", HFILL }},

    { &hf_rtcfg_server_flags_res0,
      { "Reserved",
        "rtcfg.server_flags.res0",
        FT_UINT8, BASE_HEX, NULL, 0x01,
        NULL, HFILL }},

    { &hf_rtcfg_server_flags_ready,
      { "Server Ready",
        "rtcfg.server_flags.ready",
        FT_UINT8, BASE_DEC, NULL, 0x02,
        NULL, HFILL }},

    { &hf_rtcfg_server_flags_res2,
      { "Reserved",
        "rtcfg.server_flags.res2",
        FT_UINT8, BASE_HEX, NULL, 0xfc,
        NULL, HFILL }},

    { &hf_rtcfg_active_stations,
      { "Active Stations",
        "rtcfg.active_stations",
        FT_UINT32, BASE_DEC, NULL, 0x00,
        "RTcfg Active Stations", HFILL }},

    { &hf_rtcfg_heartbeat_period,
      { "Heartbeat Period",
        "rtcfg.hearbeat_period",
        FT_UINT16, BASE_DEC, NULL, 0x00,
        "RTcfg Heartbeat Period", HFILL }},

    { &hf_rtcfg_s2_config_length,
      { "Stage 2 Config Length",
        "rtcfg.s2_config_length",
        FT_UINT32, BASE_DEC, NULL, 0x00,
        "RTcfg Stage 2 Config Length", HFILL }},

    { &hf_rtcfg_config_offset,
      { "Config Offset",
        "rtcfg.config_offset",
        FT_UINT32, BASE_DEC, NULL, 0x00,
        "RTcfg Config Offset", HFILL }},

    { &hf_rtcfg_ack_length,
      { "Ack Length",
        "rtcfg.ack_length",
        FT_UINT32, BASE_DEC, NULL, 0x00,
        "RTcfg Ack Length", HFILL }},

    { &hf_rtcfg_client_hw_address,
      { "Client Hardware Address",
        "rtcfg.client_ip_address",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        "RTcfg Client Hardware Address", HFILL }}
  };

  static gint *ett[] = {
    &ett_rtcfg,
  };

  proto_rtcfg = proto_register_protocol("RTcfg","RTcfg","rtcfg");
  proto_register_field_array(proto_rtcfg,hf,array_length(hf));
  proto_register_subtree_array(ett,array_length(ett));
}

/* The registration hand-off routing */

void
proto_reg_handoff_rtmac(void) {
  dissector_handle_t rtmac_handle;

  rtmac_handle = create_dissector_handle(dissect_rtmac, proto_rtmac);
  dissector_add_uint("ethertype", ETHERTYPE_RTMAC, rtmac_handle);
  ethertype_table = find_dissector_table("ethertype");
}

void
proto_reg_handoff_rtcfg(void) {
  dissector_handle_t rtcfg_handle;

  data_handle = find_dissector("data");
  rtcfg_handle = create_dissector_handle(dissect_rtcfg, proto_rtcfg);
  dissector_add_uint("ethertype", ETHERTYPE_RTCFG, rtcfg_handle);
}
