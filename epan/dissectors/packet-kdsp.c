/* packet-kdsp.c
 * Routines for Kismet Drone/Server Protocol packet disassembly
 * By Kyle Feuz <kyle.feuz@aggiemail.usu.edu>
 * Copyright 2011 Kyle Feuz
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/dissectors/packet-tcp.h>

#define KDSP_PORT 2502
#define FRAME_HEADER_LEN 12

#define HELLO 1
#define STRING 2
#define CAPPACKET 3
#define CHANNELSET 4
#define SOURCE 5
#define REPORT 6

#define CPT_FLAG 0x80000000
#define GPS_FLAG 0x00000002
#define RADIO_FLAG 0x00000001

#define RADIO_ACCURACY_FLAG 0x000000
#define RADIO_FREQ_MHZ_FLAG 0x000000
#define RADIO_SIGNAL_DBM_FLAG 0x000000
#define RADIO_NOISE_DBM_FLAG 0x000000
#define RADIO_CARRIER_FLAG 0x000000
#define RADIO_ENCODING_FLAG 0x000000
#define RADIO_DATARATE_FLAG 0x000000
#define RADIO_SIGNAL_RSSI_FLAG 0x000000
#define RADIO_NOISE_RSSI_FLAG 0x000000

#define GPS_FIX_FLAG 0x000000
#define GPS_LAT_FLAG 0x000000
#define GPS_LON_FLAG 0x000000
#define GPS_ALT_FLAG 0x000000
#define GPS_SPD_FLAG 0x000000
#define GPS_HEADING_FLAG 0x000000

#define DATA_UUID_FLAG 0x000000
#define DATA_PACKLEN_FLAG 0x000000
#define DATA_TVSEC_FLAG 0x000000
#define DATA_TVUSEC_FLAG 0x000000
#define DATA_DLT_FLAG 0x000000

#define CH_UUID_FLAG 0x00000001
#define CH_CMD_FLAG 0x00000002
#define CH_CURCH_FLAG 0x00000004
#define CH_HOP_FLAG 0x00000008
#define CH_NUMCH_FLAG 0x00000010
#define CH_CHANNELS_FLAG 0x00000020
#define CH_DWELL_FLAG 0x00000040
#define CH_RATE_FLAG 0x00000080
#define CH_HOPDWELL_FLAG 0x00000100

#define SRC_UUID_FLAG 0x00000001
#define SRC_INVALID_FLAG 0x00000002
#define SRC_NAMESTR_FLAG 0x00000004
#define SRC_INTSTR_FLAG 0x00000008
#define SRC_TYPESTR_FLAG 0x00000010
#define SRC_HOP_FLAG 0x00000020
#define SRC_DWELL_FLAG 0x00000040
#define SRC_RATE_FLAG 0x00000080

#define REPORT_UUID_FLAG 0x000000
#define REPORT_FLAGS_FLAG 0x000000
#define REPORT_HOP_TM_SEC_FLAG 0x000000
#define REPORT_HOP_TM_USEC_FLAG 0x000000

void proto_reg_handoff_kdsp(void);

static int proto_kdsp = -1;

static guint global_kdsp_tcp_port = KDSP_PORT;


static dissector_handle_t kdsp_handle;
static dissector_handle_t ieee80211_handle;

static const value_string packettypenames[] = {
  {0, "NULL"},
  {1, "HELLO"},
  {2, "STRING"},
  {3, "CAPPACKET"},
  {4, "CHANNELSET"},
  {5, "SOURCE"},
  {6, "REPORT"},
  {0, NULL}
};

static const value_string channelcmds[] = {
  {0, "NONE"},
  {1, "SET HOP"},
  {2, "SET VECTOR"},
  {3, "SET CURRENT"},
  {4, "SET HOP/DWELL"},
  {0, NULL}
};


static gint hf_kdsp_sentinel = -1;
static gint hf_kdsp_cmdnum = -1;
static gint hf_kdsp_length = -1;

static gint hf_kdsp_version = -1;
static gint hf_kdsp_server_version = -1;
static gint hf_kdsp_hostname = -1;

static gint hf_kdsp_str_flags = -1;
static gint hf_kdsp_str_len = -1;
static gint hf_kdsp_str_msg = -1;

static gint hf_kdsp_cpt_bitmap = -1;
static gint hf_kdsp_cpt_flag_cpt = -1;
static gint hf_kdsp_cpt_flag_gps = -1;
static gint hf_kdsp_cpt_flag_radio = -1;
static gint hf_kdsp_cpt_offset = -1;

static gint hf_kdsp_radio_hdr_len = -1;
static gint hf_kdsp_radio_content_bitmap = -1;
static gint hf_kdsp_radio_accuracy = -1;
static gint hf_kdsp_radio_freq_mhz = -1;
static gint hf_kdsp_radio_signal_dbm = -1;
static gint hf_kdsp_radio_noise_dbm = -1;
static gint hf_kdsp_radio_carrier = -1;
static gint hf_kdsp_radio_encoding = -1;
static gint hf_kdsp_radio_datarate = -1;
static gint hf_kdsp_radio_signal_rssi = -1;
static gint hf_kdsp_radio_noise_rssi = -1;

static gint hf_kdsp_gps_hdr_len = -1;
static gint hf_kdsp_gps_content_bitmap = -1;
static gint hf_kdsp_gps_fix = -1;
static gint hf_kdsp_gps_lat = -1;
static gint hf_kdsp_gps_lon = -1;
static gint hf_kdsp_gps_alt = -1;
static gint hf_kdsp_gps_spd = -1;
static gint hf_kdsp_gps_heading = -1;

static gint hf_kdsp_cpt_data_hdr_len = -1;
static gint hf_kdsp_cpt_data_content_bitmap = -1;
static gint hf_kdsp_cpt_uuid = -1;
static gint hf_kdsp_cpt_packet_len = -1;
static gint hf_kdsp_cpt_tv_sec = -1;
static gint hf_kdsp_cpt_tv_usec = -1;
static gint hf_kdsp_cpt_dlt = -1;

static gint hf_kdsp_ch_length = -1;
static gint hf_kdsp_ch_bitmap = -1;
static gint hf_kdsp_ch_flag_uuid = -1;
static gint hf_kdsp_ch_flag_cmd = -1;
static gint hf_kdsp_ch_flag_curch = -1;
static gint hf_kdsp_ch_flag_hop = -1;
static gint hf_kdsp_ch_flag_numch = -1;
static gint hf_kdsp_ch_flag_channels = -1;
static gint hf_kdsp_ch_flag_dwell = -1;
static gint hf_kdsp_ch_flag_rate = -1;
static gint hf_kdsp_ch_flag_hopdwell = -1;
static gint hf_kdsp_ch_uuid = -1;
static gint hf_kdsp_ch_cmd = -1;
static gint hf_kdsp_ch_cur_ch = -1;
static gint hf_kdsp_ch_hop = -1;
static gint hf_kdsp_ch_num_ch = -1;
static gint hf_kdsp_ch_data = -1;
static gint hf_kdsp_ch_ch = -1;
static gint hf_kdsp_ch_dwell = -1;
static gint hf_kdsp_ch_start = -1;
static gint hf_kdsp_ch_end = -1;
static gint hf_kdsp_ch_width = -1;
static gint hf_kdsp_ch_iter = -1;
static gint hf_kdsp_ch_rate = -1;
static gint hf_kdsp_ch_ch_dwell = -1;

static gint hf_kdsp_source_length = -1;
static gint hf_kdsp_source_bitmap = -1;
static gint hf_kdsp_source_uuid = -1;
static gint hf_kdsp_source_invalidate = -1;
static gint hf_kdsp_source_name = -1;
static gint hf_kdsp_source_interface = -1;
static gint hf_kdsp_source_type = -1;
static gint hf_kdsp_source_hop = -1;
static gint hf_kdsp_source_dwell = -1;
static gint hf_kdsp_source_rate = -1;

static gint hf_kdsp_report_hdr_len = -1;
static gint hf_kdsp_report_content_bitmap = -1;
static gint hf_kdsp_report_uuid = -1;
static gint hf_kdsp_report_flags = -1;
static gint hf_kdsp_report_hop_tm_sec = -1;
static gint hf_kdsp_report_hop_tm_usec = -1;

static gint ett_kdsp_pdu = -1;
static gint ett_cpt_bitmap = -1;
static gint ett_ch_bitmap = -1;
static gint ett_ch_data = -1;

/* determine PDU length of protocol */
static guint
get_kdsp_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
  return (guint)tvb_get_ntohl(tvb, offset+8) + FRAME_HEADER_LEN; /* length is at offset 8 */
}

/* This method dissects fully reassembled messages */
static void
dissect_kdsp_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint32 command = 0;
  guint32 offset = 0;
  guint32 length = 0;
  guint32 numChan = 0;
  guint32 bitmap = 0;
  guint16 type = 0;
  guint32 i;

  tvbuff_t *ieee80211_tvb = NULL;
  proto_item *kdsp_item = NULL;
  proto_tree *kdsp_tree = NULL;
  proto_item *sub_item = NULL;
  proto_tree *sub_tree = NULL;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "KDSP");
  col_clear(pinfo->cinfo, COL_INFO);

  command = (guint32)tvb_get_ntohl(tvb, 4);
  col_add_fstr(pinfo->cinfo, COL_INFO, "Command %s; ",
               val_to_str(command, packettypenames, "Unknown (0x%02x)"));
  col_set_fence(pinfo->cinfo, COL_INFO);

  kdsp_item = proto_tree_add_item(tree, proto_kdsp, tvb, 0, -1, ENC_NA);
  kdsp_tree = proto_item_add_subtree(kdsp_item, ett_kdsp_pdu);
  proto_tree_add_item(kdsp_tree, hf_kdsp_sentinel, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(kdsp_tree, hf_kdsp_cmdnum, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_item_append_text(kdsp_item, ", Command %s",
                         val_to_str(command, packettypenames, "Unknown (0x%02x)"));

  proto_tree_add_item(kdsp_tree, hf_kdsp_length, tvb, offset, 4, ENC_BIG_ENDIAN);
  length = (guint32)tvb_get_ntohl(tvb, offset);
  offset += 4;

  if(command == HELLO){
    proto_tree_add_item(kdsp_tree, hf_kdsp_version, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset +=4;
    proto_tree_add_item(kdsp_tree, hf_kdsp_server_version,
                        tvb, offset, 32, ENC_ASCII|ENC_NA);
    offset +=32;
    proto_tree_add_item(kdsp_tree, hf_kdsp_hostname, tvb, offset, 32, ENC_ASCII|ENC_NA);
    /*offset +=32;*/
  }
  else if(command == STRING){
    proto_tree_add_item(kdsp_tree, hf_kdsp_str_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset +=4;
    proto_tree_add_item(kdsp_tree, hf_kdsp_str_len, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset +=4;
    proto_tree_add_item(kdsp_tree, hf_kdsp_str_msg, tvb, offset, -1, ENC_ASCII|ENC_NA);
  }
  else if(command == CAPPACKET){
    sub_item = proto_tree_add_item(kdsp_tree, hf_kdsp_cpt_bitmap, tvb, offset, 4, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(sub_item, ett_cpt_bitmap);
    proto_tree_add_item(sub_tree, hf_kdsp_cpt_flag_cpt, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_kdsp_cpt_flag_gps, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_kdsp_cpt_flag_radio, tvb, offset, 4, ENC_BIG_ENDIAN);
    bitmap = tvb_get_ntohl(tvb, offset);
    offset +=4;
    proto_tree_add_item(kdsp_tree, hf_kdsp_cpt_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset +=4;
    if(bitmap & RADIO_FLAG){
      proto_tree_add_item(kdsp_tree, hf_kdsp_radio_hdr_len, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(kdsp_tree, hf_kdsp_radio_content_bitmap, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(kdsp_tree, hf_kdsp_radio_accuracy, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(kdsp_tree, hf_kdsp_radio_freq_mhz, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(kdsp_tree, hf_kdsp_radio_signal_dbm, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(kdsp_tree, hf_kdsp_radio_noise_dbm, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(kdsp_tree, hf_kdsp_radio_carrier, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(kdsp_tree, hf_kdsp_radio_encoding, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(kdsp_tree, hf_kdsp_radio_datarate, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(kdsp_tree, hf_kdsp_radio_signal_rssi, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(kdsp_tree, hf_kdsp_radio_noise_rssi, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
    }
    if(bitmap & GPS_FLAG){
      proto_tree_add_item(kdsp_tree, hf_kdsp_gps_hdr_len, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(kdsp_tree, hf_kdsp_gps_content_bitmap, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(kdsp_tree, hf_kdsp_gps_fix, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(kdsp_tree, hf_kdsp_gps_lat, tvb, offset, 12, ENC_NA);
      offset += 12;
      proto_tree_add_item(kdsp_tree, hf_kdsp_gps_lon, tvb, offset, 12, ENC_NA);
      offset += 12;
      proto_tree_add_item(kdsp_tree, hf_kdsp_gps_alt, tvb, offset, 12, ENC_NA);
      offset += 12;
      proto_tree_add_item(kdsp_tree, hf_kdsp_gps_spd, tvb, offset, 12, ENC_NA);
      offset += 12;
      proto_tree_add_item(kdsp_tree, hf_kdsp_gps_heading, tvb, offset, 12, ENC_NA);
      offset += 12;
    }
    if(bitmap & CPT_FLAG){
      proto_tree_add_item(kdsp_tree, hf_kdsp_cpt_data_hdr_len, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(kdsp_tree, hf_kdsp_cpt_data_content_bitmap, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
      proto_tree_add_item(kdsp_tree, hf_kdsp_cpt_uuid, tvb, offset, 16, ENC_NA);
      offset += 16;
      proto_tree_add_item(kdsp_tree, hf_kdsp_cpt_packet_len, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(kdsp_tree, hf_kdsp_cpt_tv_sec, tvb, offset, 8, ENC_BIG_ENDIAN);
      offset += 8;
      proto_tree_add_item(kdsp_tree, hf_kdsp_cpt_tv_usec, tvb, offset, 8, ENC_BIG_ENDIAN);
      offset += 8;
      proto_tree_add_item(kdsp_tree, hf_kdsp_cpt_dlt, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
    }
    ieee80211_tvb = tvb_new_subset_remaining(tvb, offset);
    call_dissector(ieee80211_handle, ieee80211_tvb, pinfo, tree);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "KDSP");
  }
  else if(command == CHANNELSET){
    proto_tree_add_item(kdsp_tree, hf_kdsp_ch_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    sub_item = proto_tree_add_item(kdsp_tree, hf_kdsp_ch_bitmap, tvb, offset, 4, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(sub_item, ett_ch_bitmap);
    proto_tree_add_item(sub_tree, hf_kdsp_ch_flag_uuid, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_kdsp_ch_flag_cmd, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_kdsp_ch_flag_curch, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_kdsp_ch_flag_hop, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_kdsp_ch_flag_numch, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_kdsp_ch_flag_channels, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_kdsp_ch_flag_dwell, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_kdsp_ch_flag_rate, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_kdsp_ch_flag_hopdwell, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(kdsp_tree, hf_kdsp_ch_uuid, tvb, offset, 16, ENC_NA);
    offset += 16;
    proto_tree_add_item(kdsp_tree, hf_kdsp_ch_cmd, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(kdsp_tree, hf_kdsp_ch_cur_ch, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(kdsp_tree, hf_kdsp_ch_hop, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(kdsp_tree, hf_kdsp_ch_num_ch, tvb, offset, 2, ENC_BIG_ENDIAN);
    numChan = (guint16)tvb_get_ntohs(tvb, offset);
    offset += 2;
    sub_item = proto_tree_add_item(kdsp_tree, hf_kdsp_ch_data, tvb, offset, 2046, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_ch_data);

    for(i = 0; i<numChan; i++){
      type = (guint16)tvb_get_ntohs(tvb, offset);
      type = type >> 15;
      if(!type){/* Highest bit (1 << 15) == 0 if channel */
        proto_tree_add_item(sub_tree, hf_kdsp_ch_ch, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(sub_tree, hf_kdsp_ch_dwell, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 6;
      }
      else{/* Highest bit (1 << 15) == 1 if range */
        proto_tree_add_item(sub_tree, hf_kdsp_ch_start, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(sub_tree, hf_kdsp_ch_end, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(sub_tree, hf_kdsp_ch_width, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(sub_tree, hf_kdsp_ch_iter, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
      }
    }
    offset = length+FRAME_HEADER_LEN-4;
    proto_tree_add_item(kdsp_tree, hf_kdsp_ch_rate, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(kdsp_tree, hf_kdsp_ch_ch_dwell, tvb, offset, 2, ENC_BIG_ENDIAN);
    /*offset += 2;*/
   }
  else if(command == SOURCE){
    proto_tree_add_item(kdsp_tree, hf_kdsp_source_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset +=2;
    sub_item = proto_tree_add_item(kdsp_tree, hf_kdsp_ch_bitmap, tvb, offset, 4, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(sub_item, ett_ch_bitmap);
    proto_tree_add_item(sub_tree, hf_kdsp_ch_flag_uuid, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(kdsp_tree, hf_kdsp_source_bitmap, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset +=4;
    proto_tree_add_item(kdsp_tree, hf_kdsp_source_uuid, tvb, offset, 16, ENC_NA);
    offset += 16;
    proto_tree_add_item(kdsp_tree, hf_kdsp_source_invalidate,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset +=2;
    proto_tree_add_item(kdsp_tree, hf_kdsp_source_name, tvb, offset, 16, ENC_ASCII|ENC_NA);
    offset +=16;
    proto_tree_add_item(kdsp_tree, hf_kdsp_source_interface,
                        tvb, offset, 16, ENC_ASCII|ENC_NA);
    offset += 16;
    proto_tree_add_item(kdsp_tree, hf_kdsp_source_type, tvb, offset, 16, ENC_ASCII|ENC_NA);
    offset +=16;
    proto_tree_add_item(kdsp_tree, hf_kdsp_source_hop, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset +=1;
    proto_tree_add_item(kdsp_tree, hf_kdsp_source_dwell, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(kdsp_tree, hf_kdsp_source_rate, tvb, offset, 2, ENC_BIG_ENDIAN);
    /*offset += 2;*/
  }
  else if(command == REPORT){
    proto_tree_add_item(kdsp_tree, hf_kdsp_report_hdr_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(kdsp_tree, hf_kdsp_report_content_bitmap, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(kdsp_tree, hf_kdsp_report_uuid, tvb, offset, 16, ENC_NA);
    offset += 16;
    proto_tree_add_item(kdsp_tree, hf_kdsp_report_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(kdsp_tree, hf_kdsp_report_hop_tm_sec, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(kdsp_tree, hf_kdsp_report_hop_tm_usec, tvb, offset, 4, ENC_BIG_ENDIAN);
    /*offset += 4;*/

  }

}

static void
dissect_kdsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN,
                   get_kdsp_message_len, dissect_kdsp_message);
}

void
proto_register_kdsp(void)
{
  module_t *kdsp_module;

  static hf_register_info hf[] = {
    { &hf_kdsp_sentinel,
      { "Sentinel", "kdsp.sentinel",
        FT_UINT32, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_cmdnum,
      { "Command", "kdsp.command",
        FT_UINT32, BASE_DEC,
        VALS(packettypenames), 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_length,
      { "Length", "kdsp.length",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_version,
      { "KDSP Version", "kdsp.version",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_server_version,
      { "Server Version", "kdsp.server.version",
        FT_STRING, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_hostname,
      { "Hostname", "kdsp.hostname",
        FT_STRING, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_str_flags,
      { "String Flags", "kdsp.str.flags",
        FT_UINT32, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_str_len,
      { "String Length", "kdsp.str.length",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_str_msg,
      { "Message", "kdsp.str.message",
        FT_STRING, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_cpt_bitmap,
      { "Bitmap", "kdsp.cpt.bitmap",
        FT_UINT32, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_cpt_flag_cpt,
      { "Capture Packet Flag", "kdsp.cpt.flag.cpt",
        FT_BOOLEAN, 32,
        NULL, CPT_FLAG,
        NULL, HFILL }
    },
    { &hf_kdsp_cpt_flag_gps,
      { "Capture GPS Flag", "kdsp.cpt.flag.gps",
        FT_BOOLEAN, 32,
        NULL, GPS_FLAG,
        NULL, HFILL }
    },
    { &hf_kdsp_cpt_flag_radio,
      { "Capture Radio Flag", "kdsp.cpt.flag.radio",
        FT_BOOLEAN, 32,
        NULL, RADIO_FLAG,
        NULL, HFILL }
    },
    { &hf_kdsp_cpt_offset,
      { "Offset", "kdsp.cpt.offset",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_radio_hdr_len,
      { "Length", "kdsp.radio.length",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_radio_content_bitmap,
      { "Bitmap", "kdsp.radio.bitmap",
        FT_UINT32, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_radio_accuracy,
      { "Accuracy", "kdsp.radio.accuracy",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_radio_freq_mhz,
      { "Frequency", "kdsp.radio.freq",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_radio_signal_dbm,
      { "Signal dbm", "kdsp.radio.signal_dbm",
        FT_INT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_radio_noise_dbm,
      { "Noise dbm", "kdsp.radio.noise_dbm",
        FT_INT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_radio_carrier,
      { "Carrier", "kdsp.radio.car",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_radio_encoding,
      { "Encoding", "kdsp.radio.enc",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_radio_datarate,
      { "Data Rate", "kdsp.radio.datarate",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_radio_signal_rssi,
      { "Signal rssi", "kdsp.radio.signal_rssi",
        FT_INT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_radio_noise_rssi,
      { "Noise rssi", "kdsp.radio.noise_rssi",
        FT_INT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_gps_hdr_len,
      { "GPS Length", "kdsp.gps.length",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_gps_content_bitmap,
      { "Bitmap", "kdsp.gps.bitmap",
        FT_UINT32, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_gps_fix,
      { "GPS fix", "kdsp.gps.fix",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_gps_lat,
      { "Latitude", "kdsp.gps.lat",
        FT_NONE, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_gps_lon,
      { "Longitude", "kdsp.gps.lon",
        FT_NONE, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_gps_alt,
      { "Alt", "kdsp.gps.alt",
        FT_NONE, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_gps_spd,
      { "Spd", "kdsp.gps.spd",
        FT_NONE, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_gps_heading,
      { "Heading", "kdsp.gps.heading",
        FT_NONE, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_cpt_data_hdr_len,
      { "Length", "kdsp.cpt.length",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_cpt_data_content_bitmap,
      { "Bitmap", "kdsp.cpt.bitmap",
        FT_UINT32, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_cpt_uuid,
      { "UUID", "kdsp.cpt.uuid",
        FT_BYTES, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_cpt_packet_len,
      { "Packet Length", "kdsp.cpt.pkt_len",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_cpt_tv_sec,
      { "TV sec", "kdsp.cpt.tv_sec",
        FT_UINT64, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_cpt_tv_usec,
      { "TV usec", "kdsp.cpt.tv_usec",
        FT_UINT64, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_cpt_dlt,
      { "dlt", "kdsp.cpt.dlt",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_ch_length,
      { "Length", "kdsp.chset.length",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_ch_bitmap,
      { "Bitmap", "kdsp.chset.bitmap",
        FT_UINT32, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_ch_flag_uuid,
      { "UUID Flag", "kdsp.ch.flag.uuid",
        FT_BOOLEAN, 32,
        NULL, CH_UUID_FLAG,
        NULL, HFILL }
    },
    { &hf_kdsp_ch_flag_cmd,
      { "Command Flag", "kdsp.ch.flag.cmd",
        FT_BOOLEAN, 32,
        NULL, CH_CMD_FLAG,
        NULL, HFILL }
    },
    { &hf_kdsp_ch_flag_curch,
      { "Current Channel Flag", "kdsp.ch.flag.curch",
        FT_BOOLEAN, 32,
        NULL, CH_CURCH_FLAG,
        NULL, HFILL }
    },
    { &hf_kdsp_ch_flag_hop,
      { "Hop Flag", "kdsp.ch.flag.hop",
        FT_BOOLEAN, 32,
        NULL, CH_HOP_FLAG,
        NULL, HFILL }
    },
    { &hf_kdsp_ch_flag_numch,
      { "Num Channels Flag", "kdsp.ch.flag.numch",
        FT_BOOLEAN, 32,
        NULL, CH_NUMCH_FLAG,
        NULL, HFILL }
    },
    { &hf_kdsp_ch_flag_channels,
      { "Channels Flag", "kdsp.ch.flag.channels",
        FT_BOOLEAN, 32,
        NULL, CH_CHANNELS_FLAG,
        NULL, HFILL }
    },
    { &hf_kdsp_ch_flag_dwell,
      { "Dwell Flag", "kdsp.ch.flag.dwell",
        FT_BOOLEAN, 32,
        NULL, CH_DWELL_FLAG,
        NULL, HFILL }
    },
    { &hf_kdsp_ch_flag_rate,
      { "Rate Flag", "kdsp.ch.flag.rate",
        FT_BOOLEAN, 32,
        NULL, CH_RATE_FLAG,
        NULL, HFILL }
    },
    { &hf_kdsp_ch_flag_hopdwell,
      { "Hop-Dwell Flag", "kdsp.ch.flag.hopdwell",
        FT_BOOLEAN, 32,
        NULL, CH_HOPDWELL_FLAG,
        NULL, HFILL }
    },
    { &hf_kdsp_ch_uuid,
      { "UUID", "kdsp.chset.uuid",
        FT_NONE, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_ch_cmd,
      { "Command", "kdsp.chset.cmd",
        FT_UINT16, BASE_DEC,
        VALS(channelcmds), 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_ch_cur_ch,
      { "Current Channel", "kdsp.chset.cur_ch",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_ch_hop,
      { "Channel Hop", "kdsp.chset.hop",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_ch_num_ch,
      { "Number of Channels", "kdsp.chset.num_ch",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_ch_data,
      { "Channel Data", "kdsp.chset.data",
        FT_NONE, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_ch_ch,
      { "Channel", "kdsp.chset.ch",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_ch_dwell,
      { "Dwell", "kdsp.chset.dwell",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_ch_start,
      { "Start", "kdsp.chset.start",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_ch_end,
      { "End", "kdsp.chset.end",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_ch_width,
      { "Width", "kdsp.chset.width",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_ch_iter,
      { "Iter", "kdsp.chset.iter",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_ch_rate,
      { "Rate", "kdsp.chset.rate",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_ch_ch_dwell,
      { "Dwell", "kdsp.chset.dwell",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_source_length,
      { "Length", "kdsp.source.length",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_source_bitmap,
      { "Source Bitmap", "kdsp.source.bitmap",
        FT_UINT32, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_source_uuid,
      { "UUID", "kdsp.source.uuid",
        FT_NONE, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_source_invalidate,
      { "Source Invalidate", "kdsp.source.invalidate",
        FT_UINT16, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_source_name,
      { "Source Name", "kdsp.server.version",
        FT_STRING, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_source_interface,
      { "Interface", "kdsp.source.interface",
        FT_STRING, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_source_type,
      { "Type", "kdsp.source.type",
        FT_STRING, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_source_hop,
      { "Source Hop", "kdsp.source.hop",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_source_dwell,
      { "Source Dwell", "kdsp.source.dwell",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_source_rate,
      { "Source Rate", "kdsp.source.rate",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_report_hdr_len,
      { "Length", "kdsp.report.length",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_report_content_bitmap,
      { "Bitmap", "kdsp.report.bitmap",
        FT_UINT32, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_report_uuid,
      { "UUID", "kdsp.report.uuid",
        FT_NONE, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_report_flags,
      { "flags", "kdsp.report.flags",
        FT_UINT8, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_report_hop_tm_sec,
      { "Hop Time (sec)", "kdsp.report.sec",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_kdsp_report_hop_tm_usec,
      { "Hop Time (usec)", "kdsp.report.usec",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    }
  };


  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_kdsp_pdu,
    &ett_cpt_bitmap,
    &ett_ch_bitmap,
    &ett_ch_data
  };

  proto_kdsp = proto_register_protocol(
                                       "Kismet Drone/Server Protocol",
                                       "KDSP",
                                       "kdsp"
                                       );

  proto_register_field_array(proto_kdsp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));



  kdsp_module = prefs_register_protocol(proto_kdsp, proto_reg_handoff_kdsp);

  prefs_register_uint_preference(kdsp_module, "tcp.port",
                                 "Kismet Drone TCP Port",
                                 "Set the port for Kismet Drone/Server messages (if other"
                                 " than the default of 2502)", 10,
                                 &global_kdsp_tcp_port);

}


void
proto_reg_handoff_kdsp(void)
{
  static gboolean initialized = FALSE;
  static guint tcp_port;

  if(!initialized) {
    kdsp_handle = create_dissector_handle(dissect_kdsp, proto_kdsp);
    ieee80211_handle = find_dissector("wlan");
  }else{
    dissector_delete_uint("tcp.port", tcp_port, kdsp_handle);
  }

  tcp_port = global_kdsp_tcp_port;

  dissector_add_uint("tcp.port", global_kdsp_tcp_port, kdsp_handle);

}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
