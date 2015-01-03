/* packet-wifi-display.c
 *
 * Wi-Fi Display
 *
 * Copyright 2011-2013 Qualcomm Atheros, Inc.
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

# include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/expert.h>

#include "packet-ieee80211.h"

void proto_register_wifi_display(void);

static int proto_wifi_display = -1;

static int hf_wfd_subelem_id = -1;
static int hf_wfd_subelem_len = -1;

static int hf_wfd_subelem_dev_info_type = -1;
static int hf_wfd_subelem_dev_info_coupled_sink_source = -1;
static int hf_wfd_subelem_dev_info_coupled_sink_sink = -1;
static int hf_wfd_subelem_dev_info_available = -1;
static int hf_wfd_subelem_dev_info_wsd = -1;
static int hf_wfd_subelem_dev_info_pc = -1;
static int hf_wfd_subelem_dev_info_content_protection = -1;
static int hf_wfd_subelem_dev_info_time_sync = -1;
static int hf_wfd_subelem_dev_info_control_port = -1;
static int hf_wfd_subelem_dev_info_max_throughput = -1;
static int hf_wfd_subelem_dev_info_audio_unsupp_pri_sink = -1;
static int hf_wfd_subelem_dev_info_audio_only_supp_source = -1;
static int hf_wfd_subelem_dev_info_tdls_persistent_group = -1;
static int hf_wfd_subelem_dev_info_tdls_persistent_group_reinvoke = -1;
static int hf_wfd_subelem_dev_info_reserved = -1;

static int hf_wfd_subelem_assoc_bssid = -1;

static int hf_wfd_subelem_coupled_sink_status_bitmap = -1;
static int hf_wfd_subelem_coupled_sink_reserved = -1;
static int hf_wfd_subelem_coupled_sink_mac_addr = -1;

static int hf_wfd_subelem_session_descr_len = -1;
static int hf_wfd_subelem_session_dev_addr = -1;
static int hf_wfd_subelem_session_assoc_bssid = -1;
static int hf_wfd_subelem_session_dev_info_type = -1;
static int hf_wfd_subelem_session_dev_info_coupled_sink_source = -1;
static int hf_wfd_subelem_session_dev_info_coupled_sink_sink = -1;
static int hf_wfd_subelem_session_dev_info_available = -1;
static int hf_wfd_subelem_session_dev_info_wsd = -1;
static int hf_wfd_subelem_session_dev_info_pc = -1;
static int hf_wfd_subelem_session_dev_info_content_protection = -1;
static int hf_wfd_subelem_session_dev_info_time_sync = -1;
static int hf_wfd_subelem_session_dev_info_audio_unsupp_pri_sink = -1;
static int hf_wfd_subelem_session_dev_info_audio_only_supp_source = -1;
static int hf_wfd_subelem_session_dev_info_tdls_persistent_group = -1;
static int hf_wfd_subelem_session_dev_info_tdls_persistent_group_reinvoke = -1;
static int hf_wfd_subelem_session_dev_info_reserved = -1;
static int hf_wfd_subelem_session_dev_info_max_throughput = -1;
static int hf_wfd_subelem_session_coupled_sink_status_bitmap = -1;
static int hf_wfd_subelem_session_coupled_sink_reserved = -1;
static int hf_wfd_subelem_session_coupled_sink_addr = -1;
static int hf_wfd_subelem_session_extra_info = -1;

static int hf_wfd_subelem_ext_capab = -1;
static int hf_wfd_subelem_ext_capab_uibc = -1;
static int hf_wfd_subelem_ext_capab_i2c_read_write = -1;
static int hf_wfd_subelem_ext_capab_preferred_display_mode = -1;
static int hf_wfd_subelem_ext_capab_standby_resume_control = -1;
static int hf_wfd_subelem_ext_capab_tdls_persistent = -1;
static int hf_wfd_subelem_ext_capab_tdls_persistent_bssid = -1;
static int hf_wfd_subelem_ext_capab_reserved = -1;

static int hf_wfd_subelem_alt_mac_addr = -1;

static gint ett_wfd_subelem = -1;
static gint ett_wfd_dev_info_descr = -1;

static expert_field ei_wfd_subelem_len_invalid = EI_INIT;
static expert_field ei_wfd_subelem_session_descr_invalid = EI_INIT;
static expert_field ei_wfd_subelem_id = EI_INIT;

enum wifi_display_subelem {
  WFD_SUBELEM_DEVICE_INFO = 0,
  WFD_SUBELEM_ASSOCIATED_BSSID = 1,
  WFD_SUBELEM_AUDIO_FORMATS = 2,
  WFD_SUBELEM_VIDEO_FORMATS = 3,
  WFD_SUBELEM_3D_VIDEO_FORMATS = 4,
  WFD_SUBELEM_CONTENT_PROTECTION = 5,
  WFD_SUBELEM_COUPLED_SINK = 6,
  WFD_SUBELEM_EXT_CAPAB = 7,
  WFD_SUBELEM_LOCAL_IP_ADDRESS = 8,
  WFD_SUBELEM_SESSION_INFO = 9,
  WFD_SUBELEM_ALT_MAC_ADDR = 10
};

static const value_string wfd_subelem_ids[] = {
  { WFD_SUBELEM_DEVICE_INFO, "WFD Device Information" },
  { WFD_SUBELEM_ASSOCIATED_BSSID, "Associated BSSID" },
  { WFD_SUBELEM_AUDIO_FORMATS, "WFD Audio Formats" },
  { WFD_SUBELEM_VIDEO_FORMATS, "WFD Video Formats" },
  { WFD_SUBELEM_3D_VIDEO_FORMATS, "WFD 3D Video Formats" },
  { WFD_SUBELEM_CONTENT_PROTECTION, "WFD Content Protection" },
  { WFD_SUBELEM_COUPLED_SINK, "Coupled Sink Information" },
  { WFD_SUBELEM_EXT_CAPAB, "WFD Extended Capability" },
  { WFD_SUBELEM_LOCAL_IP_ADDRESS, "Local IP Address" },
  { WFD_SUBELEM_SESSION_INFO, "WFD Session Information" },
  { WFD_SUBELEM_ALT_MAC_ADDR, "Alternative MAC Address" },
  { 0, NULL }
};


static const value_string wfd_dev_info_types[] = {
  { 0, "WFD source" },
  { 1, "WFD primary sink" },
  { 2, "WFD secondary sink" },
  { 3, "WFD source/primary sink" },
  { 0, NULL }
};

static const value_string wfd_dev_info_avail[] = {
  { 0, "Not available for WFD Session" },
  { 1, "Available for WFD Session" },
  { 0, NULL }
};

static const value_string wfd_dev_info_pc[] = {
  { 0, "P2P" },
  { 1, "TDLS" },
  { 0, NULL }
};

static const value_string wfd_coupled_sink_status_bitmap[] = {
  { 0, "Not coupled/Available for Coupling" },
  { 1, "Coupled" },
  { 2, "Teardown Coupling" },
  { 3, "Reserved" },
  { 0, NULL }
};

static void
dissect_wfd_subelem_device_info(proto_tree *tree, tvbuff_t *tvb, int offset)
{
  proto_tree_add_item(tree, hf_wfd_subelem_dev_info_type,
                      tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_wfd_subelem_dev_info_coupled_sink_source,
                      tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_wfd_subelem_dev_info_coupled_sink_sink,
                      tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_wfd_subelem_dev_info_available,
                      tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_wfd_subelem_dev_info_wsd,
                      tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_wfd_subelem_dev_info_pc,
                      tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_wfd_subelem_dev_info_content_protection,
                      tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_wfd_subelem_dev_info_time_sync,
                      tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_wfd_subelem_dev_info_audio_unsupp_pri_sink,
                      tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_wfd_subelem_dev_info_audio_only_supp_source,
                      tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_wfd_subelem_dev_info_tdls_persistent_group,
                      tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree,
                      hf_wfd_subelem_dev_info_tdls_persistent_group_reinvoke,
                      tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_wfd_subelem_dev_info_reserved,
                      tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_wfd_subelem_dev_info_control_port,
                      tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_wfd_subelem_dev_info_max_throughput,
                      tvb, offset, 2, ENC_BIG_ENDIAN);
}

static void
dissect_wfd_subelem_associated_bssid(packet_info *pinfo, proto_tree *tree,
                                     tvbuff_t *tvb, int offset, int len)
{
  if (len < 6) {
    expert_add_info_format(pinfo, tree, &ei_wfd_subelem_len_invalid, "Too short Wi-Fi Display Associated BSSID");
    return;
  }
  proto_tree_add_item(tree, hf_wfd_subelem_assoc_bssid, tvb, offset, 6, ENC_NA);
}

static void
dissect_wfd_subelem_coupled_sink(packet_info *pinfo, proto_tree *tree,
                                 tvbuff_t *tvb, int offset, int len)
{
  if (len < 1) {
    expert_add_info_format(pinfo, tree, &ei_wfd_subelem_len_invalid, "Too short Wi-Fi Display Coupled Sink");
    return;
  }
  proto_tree_add_item(tree, hf_wfd_subelem_coupled_sink_status_bitmap,
                      tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_wfd_subelem_coupled_sink_reserved,
                      tvb, offset, 1, ENC_BIG_ENDIAN);
  if (len < 1 + 6) {
    expert_add_info_format(pinfo, tree, &ei_wfd_subelem_len_invalid, "Too short Wi-Fi Display Coupled Sink");
    return;
  }
  proto_tree_add_item(tree, hf_wfd_subelem_coupled_sink_mac_addr, tvb,
                      offset + 1, 6, ENC_NA);
}

static void
dissect_wfd_subelem_session_info(packet_info *pinfo, proto_tree *tree,
                                 tvbuff_t *tvb, int offset, guint16 len)
{
  int end = offset + len, next;
  proto_item *item;
  proto_tree *descr;

  while (offset < end) {
    guint8 dlen = tvb_get_guint8(tvb, offset);
    next = offset + 1 + dlen;

    descr = proto_tree_add_subtree(tree, tvb, offset, 1 + dlen,
                               ett_wfd_dev_info_descr, &item, "WFD Device Info Descriptor");
    if (offset + 1 + dlen > end || dlen < 23) {
      expert_add_info(pinfo, item, &ei_wfd_subelem_session_descr_invalid);
      break;
    }

    proto_tree_add_item(descr, hf_wfd_subelem_session_descr_len,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(descr, hf_wfd_subelem_session_dev_addr, tvb, offset, 6,
                        ENC_NA);
    proto_item_append_text(descr, ": %s", tvb_ether_to_str(tvb, offset));
    offset += 6;

    proto_tree_add_item(descr, hf_wfd_subelem_session_assoc_bssid,
                        tvb, offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(descr, hf_wfd_subelem_session_dev_info_type,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(descr,
                        hf_wfd_subelem_session_dev_info_coupled_sink_source,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(descr,
                        hf_wfd_subelem_session_dev_info_coupled_sink_sink,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(descr, hf_wfd_subelem_session_dev_info_available,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(descr, hf_wfd_subelem_session_dev_info_wsd,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(descr, hf_wfd_subelem_session_dev_info_pc,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(descr,
                        hf_wfd_subelem_session_dev_info_content_protection,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(descr, hf_wfd_subelem_session_dev_info_time_sync,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree,
                        hf_wfd_subelem_session_dev_info_audio_unsupp_pri_sink,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree,
                        hf_wfd_subelem_session_dev_info_audio_only_supp_source,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree,
                        hf_wfd_subelem_session_dev_info_tdls_persistent_group,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree,
                        hf_wfd_subelem_session_dev_info_tdls_persistent_group_reinvoke,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree,
                        hf_wfd_subelem_session_dev_info_reserved,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(descr, hf_wfd_subelem_session_dev_info_max_throughput,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(descr,
                        hf_wfd_subelem_session_coupled_sink_status_bitmap,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(descr,
                        hf_wfd_subelem_session_coupled_sink_reserved,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(descr, hf_wfd_subelem_session_coupled_sink_addr,
                        tvb, offset, 6, ENC_NA);
    offset += 6;

    if (offset < next) {
      proto_tree_add_item(descr, hf_wfd_subelem_session_extra_info, tvb, offset, next - offset, ENC_NA);
    }

    offset = next;
  }
}

static void
dissect_wfd_subelem_ext_capab(packet_info *pinfo, proto_tree *tree,
                                 tvbuff_t *tvb, int offset, int len)
{
  if (len<2) {
    expert_add_info_format(pinfo, tree, &ei_wfd_subelem_len_invalid,
                           "Too short Wi-Fi Display Extended Capability");
    return;
  }
  proto_tree_add_item(tree, hf_wfd_subelem_ext_capab,
                      tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_wfd_subelem_ext_capab_uibc,
                      tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_wfd_subelem_ext_capab_i2c_read_write,
                      tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_wfd_subelem_ext_capab_preferred_display_mode,
                      tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_wfd_subelem_ext_capab_standby_resume_control,
                      tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_wfd_subelem_ext_capab_tdls_persistent,
                      tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_wfd_subelem_ext_capab_tdls_persistent_bssid,
                      tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_wfd_subelem_ext_capab_reserved,
                      tvb, offset, 2, ENC_BIG_ENDIAN);
}

static void
dissect_wfd_subelem_alt_mac_addr(packet_info *pinfo, proto_tree *tree,
                                 tvbuff_t *tvb, int offset, int len)
{
  if (len<6) {
    expert_add_info_format(pinfo, tree, &ei_wfd_subelem_len_invalid,
                           "Too short Wi-Fi Display Alternative MAC Address");
    return;
  }
  proto_tree_add_item(tree, hf_wfd_subelem_alt_mac_addr,
                      tvb, offset, 6, ENC_NA);
}

void dissect_wifi_display_ie(packet_info *pinfo, proto_tree *tree,
                             tvbuff_t *tvb, int offset, gint size)
{
  int end = offset + size;
  guint8 id;
  guint16 len;
  proto_tree *wfd_tree;
  proto_item *subelem;

  while (offset < end) {
    if (end - offset < 2) {
      expert_add_info_format(pinfo, tree, &ei_wfd_subelem_len_invalid, "Packet too short for Wi-Fi Display subelement");
      break;
    }

    id = tvb_get_guint8(tvb, offset);
    len = tvb_get_ntohs(tvb, offset + 1);
    wfd_tree = proto_tree_add_subtree(tree, tvb, offset, 3 + len,
                                  ett_wfd_subelem, &subelem,
                                  val_to_str(id, wfd_subelem_ids,
                                             "Unknown subelement ID (%u)"));
    if (offset + 3 + len > end) {
      expert_add_info_format(pinfo, subelem, &ei_wfd_subelem_len_invalid, "Packet too short for Wi-Fi Display subelement payload");
    }

    proto_tree_add_item(wfd_tree, hf_wfd_subelem_id, tvb, offset, 1,
                        ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(wfd_tree, hf_wfd_subelem_len, tvb, offset, 2,
                        ENC_BIG_ENDIAN);
    offset += 2;

    switch (id) {
    case WFD_SUBELEM_DEVICE_INFO:
      dissect_wfd_subelem_device_info(wfd_tree, tvb, offset);
      break;
    case WFD_SUBELEM_ASSOCIATED_BSSID:
      dissect_wfd_subelem_associated_bssid(pinfo, wfd_tree, tvb, offset, len);
      break;
    case WFD_SUBELEM_COUPLED_SINK:
      dissect_wfd_subelem_coupled_sink(pinfo, wfd_tree, tvb, offset, len);
      break;
    case WFD_SUBELEM_SESSION_INFO:
      dissect_wfd_subelem_session_info(pinfo, wfd_tree, tvb, offset, len);
      break;
    case WFD_SUBELEM_EXT_CAPAB:
      dissect_wfd_subelem_ext_capab(pinfo, wfd_tree, tvb, offset, len);
      break;
    case WFD_SUBELEM_ALT_MAC_ADDR:
      dissect_wfd_subelem_alt_mac_addr(pinfo, wfd_tree, tvb, offset, len);
      break;
    default:
      expert_add_info(pinfo, subelem, &ei_wfd_subelem_id);
      break;
    }

    offset += len;
  }
}

void
proto_register_wifi_display(void)
{
  static hf_register_info hf[] = {
    { &hf_wfd_subelem_id,
      { "Subelement ID", "wifi_display.subelem.id",
        FT_UINT8, BASE_DEC, VALS(wfd_subelem_ids), 0, NULL, HFILL }},
    { &hf_wfd_subelem_len,
      { "Length", "wifi_display.subelem.length",
        FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
    { &hf_wfd_subelem_dev_info_type,
      { "Device type", "wifi_display.subelem.dev_info.type",
        FT_UINT16, BASE_DEC, VALS(wfd_dev_info_types), 0x0003, NULL, HFILL }},
    { &hf_wfd_subelem_dev_info_coupled_sink_source,
      { "Coupled sink operation supported by WFD source",
        "wifi_display.subelem.dev_info.coupled_sink_by_source",
        FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL }},
    { &hf_wfd_subelem_dev_info_coupled_sink_sink,
      { "Coupled sink operation supported by WFD sink",
        "wifi_display.subelem.dev_info.coupled_sink_by_sink",
        FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL }},
    { &hf_wfd_subelem_dev_info_available,
      { "Available for WFD Session", "wifi_display.subelem.dev_info.available",
        FT_UINT16, BASE_DEC, VALS(wfd_dev_info_avail), 0x0030, NULL, HFILL }},
    { &hf_wfd_subelem_dev_info_wsd,
      { "WFD Service Discovery", "wifi_display.subelem.dev_info.wsd",
        FT_BOOLEAN, 16, NULL, 0x0040, NULL, HFILL }},
    { &hf_wfd_subelem_dev_info_pc,
      { "Preferred Connectivity", "wifi_display.subelem.dev_info.pc",
        FT_UINT16, BASE_DEC, VALS(wfd_dev_info_pc), 0x0080, NULL, HFILL }},
    { &hf_wfd_subelem_dev_info_content_protection,
      { "Content Protection using HDCP2.0",
        "wifi_display.subelem.dev_info.content_protection",
        FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL }},
    { &hf_wfd_subelem_dev_info_time_sync,
      { "Time Synchronization using 802.1AS",
        "wifi_display.subelem.dev_info.time_sync",
        FT_BOOLEAN, 16, NULL, 0x0200, NULL, HFILL }},
    { &hf_wfd_subelem_dev_info_audio_unsupp_pri_sink,
      { "Audio un-supported at Primary sink",
        "wifi_display.subelem.session.audio_unsupp_pri_sink",
        FT_BOOLEAN, 16, NULL, 0x0400, NULL, HFILL }},
    { &hf_wfd_subelem_dev_info_audio_only_supp_source,
      { "Audio only support af WFD source",
        "wifi_display.subelem.session.audio_only_supp_source",
        FT_BOOLEAN, 16, NULL, 0x0800, NULL, HFILL }},
    { &hf_wfd_subelem_dev_info_tdls_persistent_group,
      { "TDLS Persistent Group",
        "wifi_display.subelem.session.tdls_persistent_group",
        FT_BOOLEAN, 16, NULL, 0x1000, NULL, HFILL }},
    { &hf_wfd_subelem_dev_info_tdls_persistent_group_reinvoke,
      { "TDLS Persistent Group Re-invoke",
        "wifi_display.subelem.session.tdls_persistent_group_reinvoke",
        FT_BOOLEAN, 16, NULL, 0x2000, NULL, HFILL }},
    { &hf_wfd_subelem_dev_info_reserved,
      { "Reserved", "wifi_display.subelem.session.reserved",
        FT_UINT16, BASE_DEC, NULL, 0xc000, NULL, HFILL }},
    { &hf_wfd_subelem_dev_info_control_port,
      { "Session Management Control Port",
        "wifi_display.subelem.dev_info.control_port",
        FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
    { &hf_wfd_subelem_dev_info_max_throughput,
      { "WFD Device Maximum Throughput (Mbps)",
        "wifi_display.subelem.dev_info.max_throughput",
        FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
    { &hf_wfd_subelem_assoc_bssid,
      { "Associated BSSID", "wifi_display.subelem.assoc_bssid.bssid",
        FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},
    { &hf_wfd_subelem_coupled_sink_status_bitmap,
      { "Coupled Sink Status bitmap",
        "wifi_display.subelem.coupled_sink.status",
        FT_UINT8, BASE_DEC, VALS(wfd_coupled_sink_status_bitmap), 0x03,
        NULL, HFILL }},
    { &hf_wfd_subelem_coupled_sink_reserved,
      { "Reserved", "wifi_display.subelem.coupled_sink.reserved",
        FT_UINT8, BASE_DEC, NULL, 0xfc, NULL, HFILL }},
    { &hf_wfd_subelem_coupled_sink_mac_addr,
      { "Coupled Sink MAC Address",
        "wifi_display.subelem.coupled_sink.mac_addr",
        FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},
    { &hf_wfd_subelem_session_descr_len,
      { "Descriptor length",
        "wifi_display.subelem.session.descr_len",
        FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
    { &hf_wfd_subelem_session_dev_addr,
      { "Device address",
        "wifi_display.subelem.session.device_address",
        FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},
    { &hf_wfd_subelem_session_assoc_bssid,
      { "Associated BSSID",
        "wifi_display.subelem.session.associated_bssid",
        FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},
    { &hf_wfd_subelem_session_dev_info_type,
      { "Device type", "wifi_display.subelem.session.type",
        FT_UINT16, BASE_DEC, VALS(wfd_dev_info_types), 0x0003, NULL, HFILL }},
    { &hf_wfd_subelem_session_dev_info_coupled_sink_source,
      { "Coupled sink operation supported by WFD source",
        "wifi_display.subelem.session.coupled_sink_by_source",
        FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL }},
    { &hf_wfd_subelem_session_dev_info_coupled_sink_sink,
      { "Coupled sink operation supported by WFD sink",
        "wifi_display.subelem.session.coupled_sink_by_sink",
        FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL }},
    { &hf_wfd_subelem_session_dev_info_available,
      { "Available for WFD Session", "wifi_display.subelem.session.available",
        FT_UINT16, BASE_DEC, VALS(wfd_dev_info_avail), 0x0030, NULL, HFILL }},
    { &hf_wfd_subelem_session_dev_info_wsd,
      { "WFD Service Discovery", "wifi_display.subelem.session.wsd",
        FT_BOOLEAN, 16, NULL, 0x0040, NULL, HFILL }},
    { &hf_wfd_subelem_session_dev_info_pc,
      { "Preferred Connectivity", "wifi_display.subelem.session.pc",
        FT_UINT16, BASE_DEC, VALS(wfd_dev_info_pc), 0x0080, NULL, HFILL }},
    { &hf_wfd_subelem_session_dev_info_content_protection,
      { "Content Protection using HDCP2.0",
        "wifi_display.subelem.session.content_protection",
        FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL }},
    { &hf_wfd_subelem_session_dev_info_time_sync,
      { "Time Synchronization using 802.1AS",
        "wifi_display.subelem.session.time_sync",
        FT_BOOLEAN, 16, NULL, 0x0200, NULL, HFILL }},
    { &hf_wfd_subelem_session_dev_info_audio_unsupp_pri_sink,
      { "Audio un-supported at Primary sink",
        "wifi_display.subelem.session.audio_unsupp_pri_sink",
        FT_BOOLEAN, 16, NULL, 0x0400, NULL, HFILL }},
    { &hf_wfd_subelem_session_dev_info_audio_only_supp_source,
      { "Audio only support af WFD source",
        "wifi_display.subelem.session.audio_only_supp_source",
        FT_BOOLEAN, 16, NULL, 0x0800, NULL, HFILL }},
    { &hf_wfd_subelem_session_dev_info_tdls_persistent_group,
      { "TDLS Persistent Group",
        "wifi_display.subelem.session.tdls_persistent_group",
        FT_BOOLEAN, 16, NULL, 0x1000, NULL, HFILL }},
    { &hf_wfd_subelem_session_dev_info_tdls_persistent_group_reinvoke,
      { "TDLS Persistent Group Re-invoke",
        "wifi_display.subelem.session.tdls_persistent_group_reinvoke",
        FT_BOOLEAN, 16, NULL, 0x2000, NULL, HFILL }},
    { &hf_wfd_subelem_session_dev_info_reserved,
      { "Reserved", "wifi_display.subelem.session.reserved",
        FT_UINT16, BASE_DEC, NULL, 0xc000, NULL, HFILL }},
    { &hf_wfd_subelem_session_dev_info_max_throughput,
      { "WFD Device Maximum Throughput (Mbps)",
        "wifi_display.subelem.session.max_throughput",
        FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
    { &hf_wfd_subelem_session_coupled_sink_status_bitmap,
      { "Coupled Sink Status bitmap",
        "wifi_display.subelem.session.coupled_sink_status",
        FT_UINT8, BASE_DEC, VALS(wfd_coupled_sink_status_bitmap), 0x03,
        NULL, HFILL }},
    { &hf_wfd_subelem_session_coupled_sink_reserved,
      { "Reserved", "wifi_display.subelem.session.coupled_sink.reserved",
        FT_UINT8, BASE_DEC, NULL, 0xfc, NULL, HFILL }},
    { &hf_wfd_subelem_session_coupled_sink_addr,
      { "Coupled peer sink address",
        "wifi_display.subelem.session.coupled_peer_sink_addr",
        FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},
    { &hf_wfd_subelem_session_extra_info,
      { "Extra info in the end of descriptor",
        "wifi_display.subelem.session.extra_info",
        FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
    { &hf_wfd_subelem_ext_capab,
      { "WFD Extended Capability Bitmap",
        "wifi_display.subelem.ext_capab",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_wfd_subelem_ext_capab_uibc,
      { "User Input Back Channel(UIBC)",
        "wifi_display.subelem.ext_capab.uibc",
        FT_BOOLEAN, 16, TFS (&tfs_supported_not_supported), 0x0001, NULL, HFILL }},
    { &hf_wfd_subelem_ext_capab_i2c_read_write,
      { "I2C Read/Write",
        "wifi_display.subelem.ext_capab.i2c_read_write",
        FT_BOOLEAN, 16, TFS (&tfs_supported_not_supported), 0x0002, NULL, HFILL }},
    { &hf_wfd_subelem_ext_capab_preferred_display_mode,
      { "Preferred Display Mode",
        "wifi_display.subelem.ext_capab.preferred_display_mode",
        FT_BOOLEAN, 16, TFS (&tfs_supported_not_supported), 0x0004, NULL, HFILL }},
    { &hf_wfd_subelem_ext_capab_standby_resume_control,
      { "Standby and Resume Control",
        "wifi_display.subelem.ext_capab.standby_resume_control",
        FT_BOOLEAN, 16, TFS (&tfs_supported_not_supported), 0x008, NULL, HFILL }},
    { &hf_wfd_subelem_ext_capab_tdls_persistent,
      { "TDLS Persistent",
        "wifi_display.subelem.ext_capab.tdls_persistent",
        FT_BOOLEAN, 16, TFS (&tfs_supported_not_supported), 0x0010, NULL, HFILL }},
    { &hf_wfd_subelem_ext_capab_tdls_persistent_bssid,
      { "TDLS Persistent BSSID",
        "wifi_display.subelem.ext_capab.tdls_persistent_bssid",
        FT_BOOLEAN, 16, TFS (&tfs_supported_not_supported), 0x0020, NULL, HFILL }},
    { &hf_wfd_subelem_ext_capab_reserved,
      { "Reserved", "wifi_display.subelem.ext_capab.reserved",
        FT_UINT16, BASE_HEX, NULL, 0xffc0, NULL, HFILL }},
    { &hf_wfd_subelem_alt_mac_addr,
      { "Alternative MAC Address", "wifi_display.subelem.alt_mac_addr",
        FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL }},
  };
  static gint *ett[] = {
    &ett_wfd_subelem,
    &ett_wfd_dev_info_descr
  };

  static ei_register_info ei[] = {
      { &ei_wfd_subelem_len_invalid, { "wifi_display.subelem.length.invalid", PI_MALFORMED, PI_ERROR, "Subelement length invalid", EXPFILL }},
      { &ei_wfd_subelem_session_descr_invalid, { "wifi_display.subelem.session.descr_invalid", PI_MALFORMED, PI_ERROR, "Invalid WFD Device Info Descriptor", EXPFILL }},
      { &ei_wfd_subelem_id, { "wifi_display.subelem.id.unknown", PI_PROTOCOL, PI_WARN, "Unknown subelement payload", EXPFILL }},
  };

  expert_module_t* expert_wifi_display;

  proto_wifi_display = proto_register_protocol("Wi-Fi Display", "WFD", "wifi_display");
  proto_register_field_array(proto_wifi_display, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  expert_wifi_display = expert_register_protocol(proto_wifi_display);
  expert_register_field_array(expert_wifi_display, ei, array_length(ei));
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
