/* packet-wassp.c
 * Routines for the disassembly of the Chantry/HiPath AP-Controller
 * tunneling protocol.
 *
 * $Id$
 *
 * Copyright 2009 Joerg Mayer (see AUTHORS file)
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

/*
  http://ietfreport.isoc.org/all-ids/draft-singh-capwap-ctp-02.txt
  looks very similar (but not always identical).

  AC: Access Controller
  BM (old):
  BP (old):
  MU: Mobile Unit (Wireless client)
  RU: Radio Unit (Access point)

  TODO:
  - Improve heuristics!!!
  - Verify TLV descriptions/types
  - Add TLV descriptions
  - Fix 802.11 frame dissection
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/expert.h>

/* protocol handles */
static int proto_wassp = -1;

static dissector_handle_t snmp_handle;
static dissector_handle_t ieee80211_handle;

/* ett handles */
static int ett_wassp = -1;
static int ett_wassp_tlv_header = -1;

/* hf elements */
/* tlv generic */
static int hf_wassp_tlv_type = -1;
static int hf_wassp_tlv_length = -1;
static int hf_wassp_tlv_data = -1;
/* tunnel header */
static int hf_wassp_version = -1;
static int hf_wassp_type = -1;
static int hf_wassp_seqno = -1;
static int hf_wassp_flags = -1;
static int hf_wassp_sessionid = -1;
static int hf_wassp_length = -1;
/* tunnel data */
static int hf_data = -1;
/* tunnel tlvs */
static int hf_status = -1;
static int hf_ru_soft_version = -1;
static int hf_ru_serial_number = -1;
static int hf_ru_challenge = -1;
static int hf_ru_response = -1;
static int hf_ac_ipaddr = -1;
static int hf_ru_vns_id = -1;
static int hf_tftp_server = -1;
static int hf_image_path = -1;
static int hf_ru_config = -1;
static int hf_ru_state = -1;
static int hf_ru_session_key = -1;
static int hf_message_type = -1;
static int hf_random_number = -1;
static int hf_standby_timeout = -1;
static int hf_ru_challenge_id = -1;
static int hf_ru_model = -1;
static int hf_ru_scan_mode = -1;
static int hf_ru_scan_type = -1;
static int hf_ru_scan_interval = -1;
static int hf_ru_radio_type = -1;
static int hf_ru_channel_dwell_time = -1;
static int hf_ru_channel_list = -1;
static int hf_ru_trap = -1;
static int hf_ru_scan_times = -1;
static int hf_ru_scan_delay = -1;
static int hf_ru_scan_req_id = -1;
static int hf_static_config = -1;
static int hf_local_bridging = -1;
static int hf_static_bp_ipaddr = -1;
static int hf_static_bp_netmask = -1;
static int hf_static_bp_gateway = -1;
static int hf_static_bm_ipaddr = -1;
static int hf_ru_alarm = -1;
static int hf_bp_request_id = -1;
static int hf_snmp_error_status = -1;
static int hf_snmp_error_index = -1;
static int hf_ap_img_to_ram = -1;
static int hf_ap_img_role = -1;
static int hf_ap_stats_block = -1;
static int hf_ap_stats_block_ether = -1;
static int hf_ap_stats_block_radio_a = -1;
static int hf_ap_stats_block_radio_b_g = -1;
static int hf_mu_stats_block = -1;
static int hf_mu_stats_block_65 = -1;
static int hf_dot1x_stats_block = -1;
static int hf_block_config = -1;
static int hf_config_radio = -1;
static int hf_config_vns = -1;
static int hf_wassp_vlan_tag = -1;
static int hf_wassp_tunnel_type = -1;
static int hf_ap_dhcp_mode = -1;
static int hf_ap_ipaddr = -1;
static int hf_ap_netmask = -1;
static int hf_ap_gateway = -1;
static int hf_preauth_resp = -1;
static int hf_bp_pmk = -1;
static int hf_ac_reg_challenge = -1;
static int hf_ac_reg_response = -1;
static int hf_stats = -1;
static int hf_certificate = -1;
static int hf_radio_id = -1;
static int hf_network_id = -1;
static int hf_mu_mac = -1;
static int hf_time = -1;
static int hf_num_radios = -1;
static int hf_radio_info = -1;
static int hf_network_info = -1;
static int hf_vendor_id = -1;
static int hf_product_id = -1;
static int hf_radio_info_ack = -1;
static int hf_mu_rf_stats_block = -1;
static int hf_stats_request_type = -1;
static int hf_stats_last = -1;
static int hf_mu_pmkid_list = -1;
static int hf_mu_pmk_bp = -1;
static int hf_mu_pmkid_bp = -1;
static int hf_countdown_time = -1;
/* discover header */
static int hf_wassp_discover1 = -1;
/* static int hf_wassp_length = -1; */
static int hf_wassp_discover2 = -1;
static int hf_wassp_subtype = -1;
static int hf_wassp_ether = -1;
static int hf_wassp_discover3 = -1;
/* discover tlvs */
/* peer header */
/* peer tlvs */
/* stats */
static int hf_stats_dot11_ackfailurecount = -1;
static int hf_stats_dot11_fcserrorcount = -1;
static int hf_stats_dot11_failedcount = -1;
static int hf_stats_dot11_frameduplicatecount = -1;
static int hf_stats_dot11_multicastreceivedframecount = -1;
static int hf_stats_dot11_multicasttransmittedframecount = -1;
static int hf_stats_dot11_multipleretrycount = -1;
static int hf_stats_dot11_rtsfailurecount = -1;
static int hf_stats_dot11_rtssuccesscount = -1;
static int hf_stats_dot11_receivedfragementcount = -1;
static int hf_stats_dot11_retrycount = -1;
static int hf_stats_dot11_transmittedfragmentcount = -1;
static int hf_stats_dot11_transmittedframecount = -1;
static int hf_stats_dot11_webundecryptablecount = -1;
static int hf_stats_dot11_wepexcludedcount = -1;
static int hf_stats_dot11_wepicverrorcount = -1;
static int hf_stats_drm_allocfailures = -1;
static int hf_stats_drm_currentchannel = -1;
static int hf_stats_drm_currentpower = -1;
static int hf_stats_drm_datatxfailures = -1;
static int hf_stats_drm_devicetype = -1;
static int hf_stats_drm_indatapackets = -1;
static int hf_stats_drm_inmgmtpackets = -1;
static int hf_stats_drm_loadfactor = -1;
static int hf_stats_drm_mgmttxfailures = -1;
static int hf_stats_drm_msgqfailures = -1;
static int hf_stats_drm_nodrmcurrentchannel = -1;
static int hf_stats_drm_outdatapackets = -1;
static int hf_stats_drm_outmgmtpackets = -1;
static int hf_stats_if_inbcastpackets = -1;
static int hf_stats_if_indiscards = -1;
static int hf_stats_if_inerrors = -1;
static int hf_stats_if_inmcastpackets = -1;
static int hf_stats_if_inoctets = -1;
static int hf_stats_if_inucastpackets = -1;
static int hf_stats_if_mtu = -1;
static int hf_stats_if_outbcastpackets = -1;
static int hf_stats_if_outdiscards = -1;
static int hf_stats_if_outerrors = -1;
static int hf_stats_if_outoctets = -1;
static int hf_stats_if_outucastpackets = -1;
static int hf_stats_if_outmcastpackets = -1;
static int hf_stats_mu_address = -1;
static int hf_stats_mu_associationcount = -1;
static int hf_stats_mu_authenticationcount = -1;
static int hf_stats_mu_deassociationcount = -1;
static int hf_stats_mu_deauthenticationcount = -1;
static int hf_stats_mu_ifindex = -1;
static int hf_stats_mu_reassociationcount = -1;
static int hf_stats_mu_receivedbytes = -1;
static int hf_stats_mu_receivederrors = -1;
static int hf_stats_mu_receivedframecount = -1;
static int hf_stats_mu_receivedrssi = -1;
static int hf_stats_mu_receivedrate = -1;
static int hf_stats_mu_transmittedbytes = -1;
static int hf_stats_mu_transmittederrors = -1;
static int hf_stats_mu_transmittedframecount = -1;
static int hf_stats_mu_transmittedrssi = -1;
static int hf_stats_mu_transmittedrate = -1;
static int hf_stats_mu_rf_stats_end = -1;
static int hf_stats_rfc_1213_sysuptime = -1;
static int hf_dot1x_stats_credent = -1;
static int hf_dot1x_stats_end_date = -1;
static int hf_stats_tlv_max = -1;
/* config */
static int hf_config_trace_status_debug = -1;
static int hf_config_trace_status_config = -1;
static int hf_config_use_bcast_for_disassc = -1;
static int hf_config_bandwidth_voice_assc = -1;
static int hf_config_bandwidth_voice_reassc = -1;
static int hf_config_bandwidth_video_assc = -1;
static int hf_config_bandwidth_video_reassc = -1;
static int hf_config_bandwidth_video_reserve = -1;
static int hf_config_bandwidth_adm_ctrl_reserve = -1;
static int hf_config_vlan_tag = -1;
static int hf_config_country_code = -1;
static int hf_config_poll_duration = -1;
static int hf_config_poll_interval = -1;
static int hf_config_poll_maintain_client_session = -1;
static int hf_config_telnet_enable = -1;
static int hf_config_telnet_password = -1;
static int hf_config_telnet_password_entry_mode = -1;
static int hf_config_outdoor_enable_environment = -1;
static int hf_config_slp_retry_count = -1;
static int hf_config_slp_retry_delay = -1;
static int hf_config_dns_retry_count = -1;
static int hf_config_dns_retry_delay = -1;
static int hf_config_mcast_slp_retry_count = -1;
static int hf_config_mcast_slp_retry_delay = -1;
static int hf_config_disc_retry_count = -1;
static int hf_config_disc_retry_delay = -1;
static int hf_config_logging_alarm_sev = -1;
static int hf_config_blacklist_blacklist_add = -1;
static int hf_config_failover_ac_ip_addr = -1;
static int hf_config_static_ac_ip_addr = -1;
static int hf_config_dhcp_assignment = -1;
static int hf_config_static_ap_ip_addr = -1;
static int hf_config_static_ap_ip_netmask = -1;
static int hf_config_static_ap_default_gw = -1;
static int hf_config_blacklist_del = -1;
static int hf_config_macaddr_req = -1;
static int hf_config_availability_mode = -1;
/* config vns */
static int hf_config_vns_radio_id = -1;
static int hf_config_vns_vns_id = -1;
static int hf_config_vns_turbo_voice = -1;
static int hf_config_vns_prop_ie = -1;
static int hf_config_vns_enable_802_11_h = -1;
static int hf_config_vns_power_backoff = -1;
static int hf_config_vns_bridge_mode = -1;
static int hf_config_vns_vlan_tag = -1;
static int hf_config_vns_process_ie_req = -1;
static int hf_config_vns_enable_u_apsd = -1;
static int hf_config_vns_adm_ctrl_voice = -1;
static int hf_config_vns_adm_ctrl_video = -1;
static int hf_config_vns_qos_up_value = -1;
static int hf_config_vns_priority_override = -1;
static int hf_config_vns_dscp_override_value = -1;
static int hf_config_vns_enable_802_11_e = -1;
static int hf_config_vns_enable_wmm = -1;
static int hf_config_vns_legacy_client_priority = -1;
static int hf_config_vns_ssid_id = -1;
static int hf_config_vns_ssid_bcast_string = -1;
static int hf_config_vns_ssid_suppress = -1;
static int hf_config_vns_802_1_x_enable = -1;
static int hf_config_vns_802_1_x_dyn_rekey = -1;
static int hf_config_vns_wpa_enable = -1;
static int hf_config_vns_wpa_v2_enable = -1;
static int hf_config_vns_wpa_passphrase = -1;
static int hf_config_vns_wpa_cipher_type = -1;
static int hf_config_vns_wpa_v2_cipher_type = -1;
static int hf_config_vns_wep_key_index = -1;
static int hf_config_vns_wep_default_key_value = -1;
static int hf_config_vns_channel_report = -1;
static int hf_config_vns_wds_service = -1;
static int hf_config_vns_wds_pref_parent = -1;
static int hf_config_vns_wds_bridge = -1;
static int hf_config_vns_okc_enabled = -1;
static int hf_config_vns_mu_assoc_retries = -1;
static int hf_config_vns_mu_assoc_timeout = -1;
static int hf_config_vns_wds_parent = -1;
static int hf_config_vns_wds_back_parent = -1;
static int hf_config_vns_wds_name = -1;
/* config radio */
static int hf_config_radio_radio_id = -1;
static int hf_config_radio_enable_radio = -1;
static int hf_config_radio_channel = -1;
static int hf_config_radio_op_rate_set = -1;
static int hf_config_radio_op_rate_max = -1;
static int hf_config_radio_beacon_period = -1;
static int hf_config_radio_dtim_period = -1;
static int hf_config_radio_rts_threshold = -1;
static int hf_config_radio_fragment_threshold = -1;
static int hf_config_radio_power_level = -1;
static int hf_config_radio_diversity_rx = -1;
static int hf_config_radio_diversity_tx = -1;
static int hf_config_radio_short_preamble = -1;
static int hf_config_radio_basic_rate_max = -1;
static int hf_config_radio_basic_rate_min = -1;
static int hf_config_radio_hw_retries = -1;
static int hf_config_radio_tx_power_min = -1;
static int hf_config_radio_tx_power_max = -1;
static int hf_config_radio_domain_id = -1;
static int hf_config_radio_b_enable = -1;
static int hf_config_radio_b_basic_rates = -1;
static int hf_config_radio_g_enable = -1;
static int hf_config_radio_g_protect_mode = -1;
static int hf_config_radio_g_protect_type = -1;
static int hf_config_radio_g_protect_rate = -1;
static int hf_config_radio_g_basic_rate = -1;
static int hf_config_radio_a_support_802_11_j = -1;
static int hf_config_radio_atpc_en_interval = -1;
static int hf_config_radio_acs_ch_list = -1;
static int hf_config_radio_tx_power_adj = -1;

#define PROTO_SHORT_NAME "WASSP"
#define PROTO_LONG_NAME "Wireless Access Station Session Protocol"

#define PORT_WASSP_DISCOVER	13907
#define PORT_WASSP_TUNNEL	13910
/* #define PORT_WASSP_PEER		13913?? */

/* ============= copy/paste/modify from value_string.[hc] ============== */
typedef struct _ext_value_string {
  guint32  value;
  const gchar   *strptr;
  int* hf_element;
  int (*specialfunction)(tvbuff_t *, packet_info *, proto_tree *, guint32,
	guint32, const struct _ext_value_string *);
  const struct _ext_value_string *evs;
} ext_value_string;


static const gchar*
match_strextval_idx(guint32 val, const ext_value_string *vs, gint *idx) {
  gint i = 0;

  if(vs) {
    while (vs[i].strptr) {
      if (vs[i].value == val) {
	if (idx)
	  *idx = i;
	return(vs[i].strptr);
      }
      i++;
    }
  }

  if (idx)
    *idx = -1;
  return NULL;
}

static const gchar*
extval_to_str_idx(guint32 val, const ext_value_string *vs, gint *idx, const char *fmt) {
  const gchar *ret;

  if (!fmt)
    fmt="Unknown";

  ret = match_strextval_idx(val, vs, idx);
  if (ret != NULL)
    return ret;

  return ep_strdup_printf(fmt, val);
}
/* ============= end copy/paste/modify  ============== */

/* Forward decls needed by wassp_tunnel_tlv_vals et al */
static int dissect_snmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *wassp_tree,
	volatile guint32 offset, guint32 length, const ext_value_string *value_array);
static int dissect_ieee80211(tvbuff_t *tvb, packet_info *pinfo, proto_tree *wassp_tree,
	volatile guint32 offset, guint32 length, const ext_value_string *value_array);
static int dissect_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *wassp_tree,
	guint32 offset, guint32 length, const ext_value_string *value_array);

static const ext_value_string wassp_tunnel_tlv_config_vns_tlv_vals[] = {
	{ 1, "V_RADIO_ID", &hf_config_vns_radio_id, NULL, NULL },
	{ 2, "V_VNS_ID", &hf_config_vns_vns_id, NULL, NULL },
	{ 3, "V_TURBO_VOICE", &hf_config_vns_turbo_voice, NULL, NULL },
	{ 4, "V_PROP_IE", &hf_config_vns_prop_ie, NULL, NULL },
	{ 5, "V_ENABLE_802_11_H", &hf_config_vns_enable_802_11_h, NULL, NULL },
	{ 6, "V_POWER_BACKOFF", &hf_config_vns_power_backoff, NULL, NULL },
	{ 7, "V_BRIDGE_MODE", &hf_config_vns_bridge_mode, NULL, NULL },
	{ 8, "V_VLAN_TAG", &hf_config_vns_vlan_tag, NULL, NULL },
	{ 9, "V_PROCESS_IE_REQ", &hf_config_vns_process_ie_req, NULL, NULL },
	{ 10, "V_ENABLE_U_APSD", &hf_config_vns_enable_u_apsd, NULL, NULL },
	{ 11, "V_ADM_CTRL_VOICE", &hf_config_vns_adm_ctrl_voice, NULL, NULL },
	{ 12, "V_ADM_CTRL_VIDEO", &hf_config_vns_adm_ctrl_video, NULL, NULL },
	{ 13, "V_QOS_UP_VALUE", &hf_config_vns_qos_up_value, NULL, NULL },
	{ 14, "V_PRIORITY_OVERRIDE", &hf_config_vns_priority_override, NULL, NULL },
	{ 15, "V_DSCP_OVERRIDE_VALUE", &hf_config_vns_dscp_override_value, NULL, NULL },
	{ 16, "V_ENABLE_802_11_E", &hf_config_vns_enable_802_11_e, NULL, NULL },
	{ 17, "V_ENABLE_WMM", &hf_config_vns_enable_wmm, NULL, NULL },
	{ 18, "V_LEGACY_CLIENT_PRIORITY", &hf_config_vns_legacy_client_priority, NULL, NULL },
	{ 19, "V_SSID_ID", &hf_config_vns_ssid_id, NULL, NULL },
	{ 20, "V_SSID_BCAST_STRING", &hf_config_vns_ssid_bcast_string, NULL, NULL },
	{ 21, "V_SSID_SUPPRESS", &hf_config_vns_ssid_suppress, NULL, NULL },
	{ 22, "V_802_1_X_ENABLE", &hf_config_vns_802_1_x_enable, NULL, NULL },
	{ 23, "V_802_1_X_DYN_REKEY", &hf_config_vns_802_1_x_dyn_rekey, NULL, NULL },
	{ 24, "V_WPA_ENABLE", &hf_config_vns_wpa_enable, NULL, NULL },
	{ 25, "V_WPA_V2_ENABLE", &hf_config_vns_wpa_v2_enable, NULL, NULL },
	{ 26, "V_WPA_PASSPHRASE", &hf_config_vns_wpa_passphrase, NULL, NULL },
	{ 27, "V_WPA_CIPHER_TYPE", &hf_config_vns_wpa_cipher_type, NULL, NULL },
	{ 28, "V_WPA_V2_CIPHER_TYPE", &hf_config_vns_wpa_v2_cipher_type, NULL, NULL },
	{ 29, "V_WEP_KEY_INDEX", &hf_config_vns_wep_key_index, NULL, NULL },
	{ 30, "V_WEP_DEFAULT_KEY_VALUE", &hf_config_vns_wep_default_key_value, NULL, NULL },
	{ 31, "V_CHANNEL_REPORT", &hf_config_vns_channel_report, NULL, NULL },
	{ 32, "V_WDS_SERVICE", &hf_config_vns_wds_service, NULL, NULL },
	{ 33, "V_WDS_PREF_PARENT", &hf_config_vns_wds_pref_parent, NULL, NULL },
	{ 34, "V_WDS_BRIDGE", &hf_config_vns_wds_bridge, NULL, NULL },
	{ 35, "V_OKC_ENABLED", &hf_config_vns_okc_enabled, NULL, NULL },
	{ 36, "V_MU_ASSOC_RETRIES", &hf_config_vns_mu_assoc_retries, NULL, NULL },
	{ 37, "V_MU_ASSOC_TIMEOUT", &hf_config_vns_mu_assoc_timeout, NULL, NULL },
	{ 38, "V_WDS_PARENT", &hf_config_vns_wds_parent, NULL, NULL },
	{ 39, "V_WDS_BACK_PARENT", &hf_config_vns_wds_back_parent, NULL, NULL },
	{ 40, "V_WDS_NAME", &hf_config_vns_wds_name, NULL, NULL },

	{ 0,	NULL, NULL, NULL, NULL }
};

static const ext_value_string wassp_tunnel_tlv_config_radio_tlv_vals[] = {
	{ 1, "R_RADIO_ID", &hf_config_radio_radio_id, NULL, NULL },
	{ 2, "R_ENABLE_RADIO", &hf_config_radio_enable_radio, NULL, NULL },
	{ 3, "R_CHANNEL", &hf_config_radio_channel, NULL, NULL },
	{ 4, "R_OP_RATE_SET", &hf_config_radio_op_rate_set, NULL, NULL },
	{ 5, "R_OP_RATE_MAX", &hf_config_radio_op_rate_max, NULL, NULL },
	{ 6, "R_BEACON_PERIOD", &hf_config_radio_beacon_period, NULL, NULL },
	{ 7, "R_DTIM_PERIOD", &hf_config_radio_dtim_period, NULL, NULL },
	{ 8, "R_RTS_THRESHOLD", &hf_config_radio_rts_threshold, NULL, NULL },
	{ 9, "R_RETRY_LIMIT_SHORT", /* hf_, */ NULL, NULL, NULL },
	{ 10, "R_RETRY_LIMIT_LONG", /* hf_, */ NULL, NULL, NULL },
	{ 11, "R_FRAGMENT_THRESHOLD", &hf_config_radio_fragment_threshold, NULL, NULL },
	{ 12, "R_POWER_LEVEL", &hf_config_radio_power_level, NULL, NULL },
	{ 13, "R_DIVERSITY_LEFT", /* hf_, */ NULL, NULL, NULL },
	{ 14, "R_DIVERSITY_RIGHT", /* hf_, */ NULL, NULL, NULL },
	{ 15, "R_DIVERSITY_RX", &hf_config_radio_diversity_rx, NULL, NULL },
	{ 16, "R_DIVERSITY_TX", &hf_config_radio_diversity_tx, NULL, NULL },
	{ 17, "R_SHORT_PREAMBLE", &hf_config_radio_short_preamble, NULL, NULL },
	{ 18, "R_BASIC_RATE_MAX", &hf_config_radio_basic_rate_max, NULL, NULL },
	{ 19, "R_BASIC_RATE_MIN", &hf_config_radio_basic_rate_min, NULL, NULL },
	{ 20, "R_HW_RETRIES", &hf_config_radio_hw_retries, NULL, NULL },
	{ 21, "R_DRM_TX_POWER_MIN", &hf_config_radio_tx_power_min, NULL, NULL },
	{ 22, "R_DRM_TX_POWER_MAX", &hf_config_radio_tx_power_max, NULL, NULL },
	{ 23, "R_DRM_AVOID_WLAN", /* hf_, */ NULL, NULL, NULL },
	{ 24, "R_DRM_DOMAIN_ID", &hf_config_radio_domain_id, NULL, NULL },
	{ 25, "R_B_ENABLE", &hf_config_radio_b_enable, NULL, NULL },
	{ 26, "R_B_BASIC_RATES", &hf_config_radio_b_basic_rates, NULL, NULL },
	{ 27, "R_G_ENABLE", &hf_config_radio_g_enable, NULL, NULL },
	{ 28, "R_G_PROTECT_MODE", &hf_config_radio_g_protect_mode, NULL, NULL },
	{ 29, "R_G_PROTECT_TYPE", &hf_config_radio_g_protect_type, NULL, NULL },
	{ 30, "R_G_PROTECT_RATE", &hf_config_radio_g_protect_rate, NULL, NULL },
	{ 31, "R_G_BASIC_RATE", &hf_config_radio_g_basic_rate, NULL, NULL },
	{ 32, "R_A_SUPPORT_802_11_J", &hf_config_radio_a_support_802_11_j, NULL, NULL },
	{ 33, "R_ATPC_EN_INTERVAL", &hf_config_radio_atpc_en_interval, NULL, NULL },
	{ 34, "R_ACS_CH_LIST", &hf_config_radio_acs_ch_list, NULL, NULL },
	{ 35, "R_TX_POWER_ADJ", &hf_config_radio_tx_power_adj, NULL, NULL },

	{ 0,	NULL, NULL, NULL, NULL }
};

static const ext_value_string wassp_tunnel_tlv_config_tlv_vals[] = {
	{ 1, "RADIO_CONFIG_BLOCK", &hf_config_radio, dissect_tlv, wassp_tunnel_tlv_config_radio_tlv_vals },
	{ 2, "VNS_CONFIG_BLOCK", &hf_config_vns, dissect_tlv, wassp_tunnel_tlv_config_vns_tlv_vals },
	{ 3, "DIVERSITY_LEFT", /* hf_, */ NULL, NULL, NULL },
	{ 4, "DIVERSITY_RIGHT", /* hf_, */ NULL, NULL, NULL },
	{ 5, "TRACE_STATUS_DEBUG", &hf_config_trace_status_debug, NULL, NULL },
	{ 6, "TRACE_STATUS_CONFIG", &hf_config_trace_status_config, NULL, NULL },
	{ 7, "BRIDGE_AT_AP", /* hf_, */ NULL, NULL, NULL },
	{ 8, "USE_BCAST_FOR_DISASSC", &hf_config_use_bcast_for_disassc, NULL, NULL },
	{ 9, "BANDWIDTH_VOICE_ASSC", &hf_config_bandwidth_voice_assc, NULL, NULL },
	{ 10, "BANDWIDTH_VOICE_REASSC", &hf_config_bandwidth_voice_reassc, NULL, NULL },
	{ 11, "BANDWIDTH_VIDEO_ASSC", &hf_config_bandwidth_video_assc, NULL, NULL },
	{ 12, "BANDWIDTH_VIDEO_REASSC", &hf_config_bandwidth_video_reassc, NULL, NULL },
	{ 13, "BANDWIDTH_VIDEO_RESERVE", &hf_config_bandwidth_video_reserve, NULL, NULL },
	{ 14, "BANDWIDTH_ADM_CTRL_RESERVE", &hf_config_bandwidth_adm_ctrl_reserve, NULL, NULL },
	{ 15, "VLAN_TAG", &hf_config_vlan_tag, NULL, NULL },
	{ 16, "COUNTRY_CODE", &hf_config_country_code, NULL, NULL },
	{ 17, "POLL_DURATION", &hf_config_poll_duration, NULL, NULL },
	{ 18, "POLL_INTERVAL", &hf_config_poll_interval, NULL, NULL },
	{ 19, "POLL_REBOOT_ON_FAIL", /* hf_, */ NULL, NULL, NULL },
	{ 20, "POLL_MAINTAIN_CLIENT_SESSION", &hf_config_poll_maintain_client_session, NULL, NULL },
	{ 21, "TELNET_ENABLE", &hf_config_telnet_enable, NULL, NULL },
	{ 22, "TELNET_PASSWORD", &hf_config_telnet_password, NULL, NULL },
	{ 23, "TELNET_PASSWORD_ENTRY_MODE", &hf_config_telnet_password_entry_mode, NULL, NULL },
	{ 24, "OUTDOOR_ENABLE-ENVIRONMENT", &hf_config_outdoor_enable_environment, NULL, NULL },
	{ 25, "BSS_COUNT", /* hf_, */ NULL, NULL, NULL },
	{ 26, "DRM_ENABLE", /* hf_, */ NULL, NULL, NULL },
	{ 27, "DRM_ENABLE_SHAPE_COV", /* hf_, */ NULL, NULL, NULL },
	{ 28, "SLP_RETRY_COUNT", &hf_config_slp_retry_count, NULL, NULL },
	{ 29, "SLP_RETRY_DELAY", &hf_config_slp_retry_delay, NULL, NULL },
	{ 30, "DNS_RETRY_COUNT", &hf_config_dns_retry_count, NULL, NULL },
	{ 31, "DNS_RETRY_DELAY", &hf_config_dns_retry_delay, NULL, NULL },
	{ 32, "MCAST_SLP_RETRY_COUNT", &hf_config_mcast_slp_retry_count, NULL, NULL },
	{ 33, "MCAST_SLP_RETRY_DELAY", &hf_config_mcast_slp_retry_delay, NULL, NULL },
	{ 34, "DISC_RETRY_COUNT", &hf_config_disc_retry_count, NULL, NULL },
	{ 35, "DISC_RETRY_DELAY", &hf_config_disc_retry_delay, NULL, NULL },
	{ 36, "LOGGING_ALARM_SEV", &hf_config_logging_alarm_sev, NULL, NULL },
	{ 37, "BLACKLIST-BLACKLIST_ADD", &hf_config_blacklist_blacklist_add, NULL, NULL },
	{ 38, "FAILOVER_AC_IP_ADDR", &hf_config_failover_ac_ip_addr, NULL, NULL },
	{ 39, "STATIC_AC_IP_ADDR", &hf_config_static_ac_ip_addr, NULL, NULL },
	{ 40, "DHCP_ASSIGNMENT", &hf_config_dhcp_assignment, NULL, NULL },
	{ 41, "STATIC_AP_IP_ADDR", &hf_config_static_ap_ip_addr, NULL, NULL },
	{ 42, "STATIC_AP_IP_NETMASK", &hf_config_static_ap_ip_netmask, NULL, NULL },
	{ 43, "STATIC_AP_DEFAULT_GW", &hf_config_static_ap_default_gw, NULL, NULL },
	{ 44, "BLACKLIST_DEL", &hf_config_blacklist_del, NULL, NULL },
	{ 45, "MACADDR_REQ", &hf_config_macaddr_req, NULL, NULL },
	{ 46, "AVAILABILITY_MODE", &hf_config_availability_mode, NULL, NULL },
	{ 47, "AP_PERSISTENCE", /* hf_, */ NULL, NULL, NULL },
	{ 48, "FOREIGN_AP", /* hf_, */ NULL, NULL, NULL },
	{ 49, "SUPP1X_CREDENTIAL_REMOVE", /* hf_, */ NULL, NULL, NULL },
	{ 50, "SUPP1X_CERT_TFTP_IP", /* hf_, */ NULL, NULL, NULL },
	{ 51, "SUPP1X_CERT_TFTP_PATH", /* hf_, */ NULL, NULL, NULL },
	{ 52, "SUPP1X_PRIVATE", /* hf_, */ NULL, NULL, NULL },
	{ 53, "SUPP1X_DOMAIN", /* hf_, */ NULL, NULL, NULL },
	{ 54, "SUPP1X_USERID", /* hf_, */ NULL, NULL, NULL },
	{ 55, "SUPP1X_PASSWORD", /* hf_, */ NULL, NULL, NULL },
	{ 56, "SUPP1X_CREDENT", /* hf_, */ NULL, NULL, NULL },
	{ 57, "SUPP1X_SERIAL", /* hf_, */ NULL, NULL, NULL },
	{ 58, "SUPP1X_START_DATE", /* hf_, */ NULL, NULL, NULL },
	{ 59, "SUPP1X_END_DATE", /* hf_, */ NULL, NULL, NULL },
	{ 60, "SUPP1X_ISSUED_BY", /* hf_, */ NULL, NULL, NULL },
	{ 61, "SUPP1X_ISSUED_TO", /* hf_, */ NULL, NULL, NULL },

	{ 0,	NULL, NULL, NULL, NULL }
};

static const ext_value_string wassp_tunnel_mu_stats_block_65_tlv_vals[] = {

	{ 0,	NULL, NULL, NULL, NULL }
};

static const ext_value_string wassp_tunnel_mu_stats_block_tlv_vals[] = {
	{ 65, "MU_STATS_BLOCK_65", &hf_mu_stats_block_65, dissect_tlv, wassp_tunnel_mu_stats_block_65_tlv_vals },

	{ 0,	NULL, NULL, NULL, NULL }
};

static const ext_value_string wassp_tunnel_ap_stats_block_tlv_vals[] = {
	{ 1, "DOT11_ACKFailureCount", &hf_stats_dot11_ackfailurecount, NULL, NULL },
	{ 2, "DOT11_FCSErrorCount", &hf_stats_dot11_fcserrorcount, NULL, NULL },
	{ 3, "DOT11_FailedCount", &hf_stats_dot11_failedcount, NULL, NULL },
	{ 4, "DOT11_FrameDuplicateCount", &hf_stats_dot11_frameduplicatecount, NULL, NULL },
	{ 5, "DOT11_MulticastReceivedFrameCount", &hf_stats_dot11_multicastreceivedframecount, NULL, NULL },
	{ 6, "DOT11_MulticastTransmittedFrameCount", &hf_stats_dot11_multicasttransmittedframecount, NULL, NULL },
	{ 7, "DOT11_MultipleRetryCount", &hf_stats_dot11_multipleretrycount, NULL, NULL },
	{ 8, "DOT11_RTSFailureCount", &hf_stats_dot11_rtsfailurecount, NULL, NULL },
	{ 9, "DOT11_RTSSuccessCount", &hf_stats_dot11_rtssuccesscount, NULL, NULL },
	{ 10, "DOT11_ReceivedFragementCount", &hf_stats_dot11_receivedfragementcount, NULL, NULL },
	{ 11, "DOT11_RetryCount", &hf_stats_dot11_retrycount, NULL, NULL },
	{ 12, "DOT11_TransmittedFragmentCount", &hf_stats_dot11_transmittedfragmentcount, NULL, NULL },
	{ 13, "DOT11_TransmittedFrameCount", &hf_stats_dot11_transmittedframecount, NULL, NULL },
	{ 14, "DOT11_WEBUndecryptableCount", &hf_stats_dot11_webundecryptablecount, NULL, NULL },
	{ 15, "DOT11_WEPExcludedCount", &hf_stats_dot11_wepexcludedcount, NULL, NULL },
	{ 16, "DOT11_WEPICVErrorCount", &hf_stats_dot11_wepicverrorcount, NULL, NULL },
	{ 17, "DRM_AllocFailures", &hf_stats_drm_allocfailures, NULL, NULL },
	{ 18, "DRM_CurrentChannel", &hf_stats_drm_currentchannel, NULL, NULL },
	{ 19, "DRM_CurrentPower", &hf_stats_drm_currentpower, NULL, NULL },
	{ 20, "DRM_DataTxFailures", &hf_stats_drm_datatxfailures, NULL, NULL },
	{ 21, "DRM_DeviceType", &hf_stats_drm_devicetype, NULL, NULL },
	{ 22, "DRM_InDataPackets", &hf_stats_drm_indatapackets, NULL, NULL },
	{ 23, "DRM_InMgmtPackets", &hf_stats_drm_inmgmtpackets, NULL, NULL },
	{ 24, "DRM_LoadFactor", &hf_stats_drm_loadfactor, NULL, NULL },
	{ 25, "DRM_MgmtTxFailures", &hf_stats_drm_mgmttxfailures, NULL, NULL },
	{ 26, "DRM_MsgQFailures", &hf_stats_drm_msgqfailures, NULL, NULL },
	{ 27, "DRM_NoDRMCurrentChannel", &hf_stats_drm_nodrmcurrentchannel, NULL, NULL },
	{ 28, "DRM_OutDataPackets", &hf_stats_drm_outdatapackets, NULL, NULL },
	{ 29, "DRM_OutMgmtPackets", &hf_stats_drm_outmgmtpackets, NULL, NULL },
	{ 30, "IF_InBcastPackets", &hf_stats_if_inbcastpackets, NULL, NULL },
	{ 31, "IF_InDiscards", &hf_stats_if_indiscards, NULL, NULL },
	{ 32, "IF_InErrors", &hf_stats_if_inerrors, NULL, NULL },
	{ 33, "IF_InMcastPackets", &hf_stats_if_inmcastpackets, NULL, NULL },
	{ 34, "IF_InOctets", &hf_stats_if_inoctets, NULL, NULL },
	{ 35, "IF_InUcastPackets", &hf_stats_if_inucastpackets, NULL, NULL },
	{ 36, "IF_MTU", &hf_stats_if_mtu, NULL, NULL },
	{ 37, "IF_OutBcastPackets", &hf_stats_if_outbcastpackets, NULL, NULL },
	{ 38, "IF_OutDiscards", &hf_stats_if_outdiscards, NULL, NULL },
	{ 39, "IF_OutErrors", &hf_stats_if_outerrors, NULL, NULL },
	{ 40, "IF_OutOctets", &hf_stats_if_outoctets, NULL, NULL },
	{ 41, "IF_OutUcastPackets", &hf_stats_if_outucastpackets, NULL, NULL },
	{ 42, "IF_OutMCastPackets", &hf_stats_if_outmcastpackets, NULL, NULL },
	{ 43, "MU_Address", &hf_stats_mu_address, NULL, NULL },
	{ 44, "MU_AssociationCount", &hf_stats_mu_associationcount, NULL, NULL },
	{ 45, "MU_AuthenticationCount", &hf_stats_mu_authenticationcount, NULL, NULL },
	{ 46, "MU_DeAssociationCount", &hf_stats_mu_deassociationcount, NULL, NULL },
	{ 47, "MU_DeAuthenticationCount", &hf_stats_mu_deauthenticationcount, NULL, NULL },
	{ 48, "MU_IfIndex", &hf_stats_mu_ifindex, NULL, NULL },
	{ 49, "MU_ReAssociationCount", &hf_stats_mu_reassociationcount, NULL, NULL },
	{ 50, "MU_ReceivedBytes", &hf_stats_mu_receivedbytes, NULL, NULL },
	{ 51, "MU_ReceivedErrors", &hf_stats_mu_receivederrors, NULL, NULL },
	{ 52, "MU_ReceivedFrameCount", &hf_stats_mu_receivedframecount, NULL, NULL },
	{ 53, "MU_ReceivedRSSI", &hf_stats_mu_receivedrssi, NULL, NULL },
	{ 54, "MU_ReceivedRate", &hf_stats_mu_receivedrate, NULL, NULL },
	{ 55, "MU_TransmittedBytes", &hf_stats_mu_transmittedbytes, NULL, NULL },
	{ 56, "MU_TransmittedErrors", &hf_stats_mu_transmittederrors, NULL, NULL },
	{ 57, "MU_TransmittedFrameCount", &hf_stats_mu_transmittedframecount, NULL, NULL },
	{ 58, "MU_TransmittedRSSI", &hf_stats_mu_transmittedrssi, NULL, NULL },
	{ 59, "MU_TransmittedRate", &hf_stats_mu_transmittedrate, NULL, NULL },
	{ 60, "MU_RF_STATS_END", &hf_stats_mu_rf_stats_end, NULL, NULL },
	{ 61, "RFC_1213_SYSUPTIME", &hf_stats_rfc_1213_sysuptime, NULL, NULL },
	{ 62, "STATS_ETHER_BLOCK", &hf_ap_stats_block_ether, dissect_tlv, wassp_tunnel_ap_stats_block_tlv_vals },
	{ 63, "STATS_RADIO_A_BLOCK", &hf_ap_stats_block_radio_a, dissect_tlv, wassp_tunnel_ap_stats_block_tlv_vals },
	{ 64, "STATS_RADIO_B_G_BLOCK", &hf_ap_stats_block_radio_b_g, dissect_tlv, wassp_tunnel_ap_stats_block_tlv_vals },
	{ 65, "MU_STATS_BLOCK", &hf_mu_stats_block, dissect_tlv, wassp_tunnel_ap_stats_block_tlv_vals },
	{ 66, "WDS_BLOCK", /* hf_, */ NULL, NULL, NULL },
	{ 67, "WDS_Role", /* hf_, */ NULL, NULL, NULL },
	{ 68, "WDS_PARENT_MAC", /* hf_, */ NULL, NULL, NULL },
	{ 69, "WDS_BSSID", /* hf_, */ NULL, NULL, NULL },
	{ 70, "DOT1x_STATS_BLOCK", &hf_dot1x_stats_block, dissect_tlv, wassp_tunnel_ap_stats_block_tlv_vals },
	{ 71, "DOT1x_CREDENT", &hf_dot1x_stats_credent, NULL, NULL },
	{ 72, "DOT1x_END_DATE", &hf_dot1x_stats_end_date, NULL, NULL },
	{ 73, "TLV_MAX", &hf_stats_tlv_max, NULL, NULL },

	{ 0,	NULL, NULL, NULL, NULL }
};

static const ext_value_string wassp_tunnel_tlv_vals[] = {
	{ 1, "STATUS", &hf_status, NULL, NULL },
	{ 2, "RU-SOFT-VERSION", &hf_ru_soft_version, NULL, NULL },
	{ 3, "RU-SERIAL-NUMBER", &hf_ru_serial_number, NULL, NULL },
	{ 4, "RU-REG-CHALLENGE", &hf_ru_challenge, NULL, NULL },
	{ 5, "RU-REG-RESPONSE", &hf_ru_response, NULL, NULL },
	{ 6, "AC-IPADDR", &hf_ac_ipaddr, NULL, NULL },
	{ 7, "RU-VNS-ID", &hf_ru_vns_id, NULL, NULL },
	{ 8, "TFTP-SERVER", &hf_tftp_server, NULL, NULL },
	{ 9, "IMAGE-PATH", &hf_image_path, NULL, NULL },
	{ 10, "RU-CONFIG", &hf_ru_config, dissect_snmp, NULL },
	{ 11, "RU-STATE", &hf_ru_state, NULL, NULL },
	{ 12, "RU-SESSION-KEY", &hf_ru_session_key, NULL, NULL },
	{ 13, "MESSAGE-TYPE", &hf_message_type, NULL, NULL },
	{ 14, "RANDOM-NUMBER", &hf_random_number, NULL, NULL },
	{ 15, "STANDBY-TIMEOUT", &hf_standby_timeout, NULL, NULL },
	{ 16, "RU-CHALLENGE-ID", &hf_ru_challenge_id, NULL, NULL },
	{ 17, "RU-MODEL", &hf_ru_model, NULL, NULL },
	{ 18, "RU-SCAN-MODE", &hf_ru_scan_mode, NULL, NULL },
	{ 19, "RU-SCAN-TYPE", &hf_ru_scan_type, NULL, NULL },
	{ 20, "RU-SCAN-INTERVAL", &hf_ru_scan_interval, NULL, NULL },
	{ 21, "RU-RADIO-TYPE", &hf_ru_radio_type, NULL, NULL },
	{ 22, "RU-CHANNEL-DWELL-TIME", &hf_ru_channel_dwell_time, NULL, NULL },
	{ 23, "RU-CHANNEL-LIST", &hf_ru_channel_list, NULL, NULL },
	{ 24, "RU-TRAP", &hf_ru_trap, NULL, NULL },
	{ 25, "RU-SCAN-TIMES", &hf_ru_scan_times, NULL, NULL },
	{ 26, "RU-SCAN-DELAY", &hf_ru_scan_delay, NULL, NULL },
	{ 27, "RU-SCAN-REQ-ID", &hf_ru_scan_req_id, NULL, NULL },
	{ 28, "STATIC-CONFIG", &hf_static_config, NULL, NULL },
	{ 29, "LOCAL-BRIDGING", &hf_local_bridging, NULL, NULL },
	{ 30, "STATIC-BP-IPADDR", &hf_static_bp_ipaddr, NULL, NULL },
	{ 31, "STATIC-BP-NETMASK", &hf_static_bp_netmask, NULL, NULL },
	{ 32, "STATIC-BP-GATEWAY", &hf_static_bp_gateway, NULL, NULL },
	{ 33, "STATIC-BM-IPADDR", &hf_static_bm_ipaddr, NULL, NULL },
	{ 34, "TUNNEL_PROTOCOL/BSSID", /* &hf_, */ NULL, NULL, NULL },
	{ 35, "BP_WIRED_MACADDR", /* &hf_, */ NULL, NULL, NULL },
	{ 36, "RU_CAPABILITY", /* &hf_, */ NULL, NULL, NULL },
	{ 37, "RU_SSID_NAME", /* hf_, */ NULL, NULL, NULL },
	{ 38, "RU_ALARM", &hf_ru_alarm, dissect_snmp, NULL },
	{ 39, "PREAUTH_RESP", &hf_preauth_resp, NULL, NULL },
	{ 40, "BP_PMK", &hf_bp_pmk, NULL, NULL },
	{ 41, "AC_REG_CHALLENGE", &hf_ac_reg_challenge, NULL, NULL },
	{ 42, "AC_REG_RESPONSE", &hf_ac_reg_response, NULL, NULL },
	{ 43, "STATS", &hf_stats, NULL, NULL },
	{ 44, "CERTIFICATE", &hf_certificate, NULL, NULL },
	{ 45, "RADIO_ID", &hf_radio_id, NULL, NULL },
	{ 46, "BP-REQUEST-ID", &hf_bp_request_id, NULL, NULL },
	{ 47, "NETWORK_ID", &hf_network_id, NULL, NULL },
	{ 48, "MU_MAC", &hf_mu_mac, NULL, NULL },
	{ 49, "TIME", &hf_time, NULL, NULL },
	{ 50, "NUM_RADIOS", &hf_num_radios, NULL, NULL },
	{ 51, "RADIO_INFO", &hf_radio_info, NULL, NULL },
	{ 52, "NETWORK_INFO", &hf_network_info, NULL, NULL },
	{ 53, "VENDOR_ID", &hf_vendor_id, NULL, NULL },
	{ 54, "PRODUCT_ID", &hf_product_id, NULL, NULL },
	{ 55, "RADIO_INFO_ACK", &hf_radio_info_ack, NULL, NULL },
	{ 60, "SNMP-ERROR-STATUS", &hf_snmp_error_status, NULL, NULL },
	{ 61, "SNMP-ERROR-INDEX", &hf_snmp_error_index, NULL, NULL },
	{ 62, "ALTERNATE_AC_IPADDR", /* &hf_, */ NULL, NULL, NULL },
	{ 63, "AP-IMG-TO-RAM", &hf_ap_img_to_ram, NULL, NULL },
	{ 64, "AP-IMG-ROLE", &hf_ap_img_role, NULL, NULL },
	{ 65, "AP_STATS_BLOCK", &hf_ap_stats_block, dissect_tlv, wassp_tunnel_ap_stats_block_tlv_vals },
	{ 66, "MU_RF_STATS_BLOCK", &hf_mu_rf_stats_block, dissect_tlv, wassp_tunnel_mu_stats_block_tlv_vals },
	{ 67, "STATS_REQUEST_TYPE", &hf_stats_request_type, NULL, NULL },
	{ 68, "STATS_LAST", &hf_stats_last, NULL, NULL },
	{ 69, "TLV_CONFIG", &hf_block_config, dissect_tlv, wassp_tunnel_tlv_config_tlv_vals },
	{ 70, "CONFIG_ERROR_BLOCK", /* &hf_, */ NULL, NULL, NULL },
	{ 71, "CONFIG_MODIFIED_BLOCK", /* &hf_, */ NULL, NULL, NULL },
	{ 72, "MU_PMKID_LIST", &hf_mu_pmkid_list, NULL, NULL },
	{ 73, "MU_PMK_BP", &hf_mu_pmk_bp, NULL, NULL },
	{ 74, "MU_PMKID_BP", &hf_mu_pmkid_bp, NULL, NULL },
	{ 75, "COUNTDOWN_TIME", &hf_countdown_time, NULL, NULL },
	{ 76, "WASSP-VLAN-TAG", &hf_wassp_vlan_tag, NULL, NULL },
	{ 81, "WASSP-TUNNEL-TYPE", &hf_wassp_tunnel_type, NULL, NULL },
	{ 88, "AP-DHCP-MODE", &hf_ap_dhcp_mode, NULL, NULL },
	{ 89, "AP-IPADDR", &hf_ap_ipaddr, NULL, NULL },
	{ 90, "AP-NETMASK", &hf_ap_netmask, NULL, NULL },
	{ 91, "AP-GATEWAY", &hf_ap_gateway, NULL, NULL },

	{ 0,	NULL, NULL, NULL, NULL }
};

static const value_string wassp_tunnel_pdu_type[] = {
	{ 1, "?Discover?" },
	{ 2, "RU Registration Request" },
	{ 3, "RU Registration Response" },
	{ 4, "RU Authentication Request" },
	{ 5, "RU Authentication Response" },
	{ 6, "RU Software Version Validate Request" },
	{ 7, "RU Software Version Validate Response" },
	{ 8, "RU Configuration Request" },
	{ 9, "RU Configuration Response" },
	{ 10, "RU Acknowledge" },
	{ 11, "RU Configuration Status Notify" },
	{ 12, "RU Set State Request" },
	{ 13, "RU Set State Response" },
	{ 14, "RU Statistics Notify" },
	{ 15, "Data" },
	{ 16, "Poll" },
	{ 17, "SNMP Request" },
	{ 18, "SNMP Response" },
	{ 19, "BP Trap Notify" },
	{ 20, "BP Scan Request" },
	{ 21, "RFM Notify" },
	{ 22, "RU SNMP Alarm Notify" },
	{ 23, "RU SNMP Set Alarm" },
	{ 24, "RU SNMP Set Log Status" },
	{ 25, "RU SNMP Get Log Request" },
	{ 26, "RU SNMP Get Log Response" },
	{ 27, "SEC Update Notify" },
	{ 28, "RU Stats Req" },
	{ 29, "RU Stats Resp" },
	{ 30, "MU Stats Req" },
	{ 31, "MU Stats Response" },

	{ 0,	NULL }
};

#if 0
static const value_string wassp_setresult_vals[] = {
	{ 0,	"Success" },
	{ 1,	"Failauth" },

	{ 0,	NULL }
};
#endif

static int
dissect_snmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *wassp_tree,
	volatile guint32 offset, guint32 length, const ext_value_string *value_array _U_)
{
	tvbuff_t *snmp_tvb;

	/* Don't add SNMP stuff to the info column */
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_writable(pinfo->cinfo, FALSE);

	snmp_tvb = tvb_new_subset(tvb, offset, length, length);

	/* Continue after SNMP dissection errors */
	TRY {
		call_dissector(snmp_handle, snmp_tvb, pinfo, wassp_tree);
	} CATCH2(BoundsError, ReportedBoundsError) {
		expert_add_info_format(pinfo, NULL,
			PI_MALFORMED, PI_ERROR,
			"Malformed or short SNMP subpacket");

		col_append_str(pinfo->cinfo, COL_INFO,
				" [Malformed or short SNMP subpacket] " );
	} ENDTRY;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_writable(pinfo->cinfo, TRUE);

	offset += length;

	return offset;
}

static int
dissect_ieee80211(tvbuff_t *tvb, packet_info *pinfo, proto_tree *wassp_tree,
	volatile guint32 offset, guint32 length, const ext_value_string *value_array _U_)
{
	tvbuff_t *ieee80211_tvb;

	/* Don't add IEEE 802.11 stuff to the info column */
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_writable(pinfo->cinfo, FALSE);

	ieee80211_tvb = tvb_new_subset(tvb, offset, length, length);

	/* Continue after IEEE 802.11 dissection errors */
	TRY {
		call_dissector(ieee80211_handle, ieee80211_tvb, pinfo, wassp_tree);
	} CATCH2(BoundsError, ReportedBoundsError) {
		expert_add_info_format(pinfo, NULL,
			PI_MALFORMED, PI_ERROR,
			"Malformed or short IEEE 802.11 subpacket");

		col_append_str(pinfo->cinfo, COL_INFO,
				" [Malformed or short IEEE 802.11 subpacket] " );
	} ENDTRY;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_writable(pinfo->cinfo, TRUE);

	offset += length;

	return offset;
}

static int
dissect_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *wassp_tree,
	guint32 offset, guint32 length _U_, const ext_value_string *value_array)
{
	guint32 tlv_type;
	guint32 tlv_length;
	proto_item *tlv_item;
	proto_item *tlv_tree;
	proto_item *type_item;
	int type_index;
	guint32 tlv_end;

	tlv_type = tvb_get_ntohs(tvb, offset);
	tlv_length = tvb_get_ntohs(tvb, offset + 2);
	DISSECTOR_ASSERT(tlv_length >= 4);
	tlv_item = proto_tree_add_text(wassp_tree, tvb,
		offset, tlv_length,
		"T %d, L %d: %s",
		tlv_type,
		tlv_length,
		extval_to_str_idx(tlv_type, value_array, NULL, "Unknown"));
	tlv_tree = proto_item_add_subtree(tlv_item,
		ett_wassp_tlv_header);
	type_item = proto_tree_add_item(tlv_tree, hf_wassp_tlv_type,
		tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_item_append_text(type_item, " = %s",
		extval_to_str_idx(tlv_type, value_array,
			&type_index, "Unknown"));
	offset += 2;
	proto_tree_add_item(tlv_tree, hf_wassp_tlv_length,
		tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	tlv_length -= 4;

	if (tlv_length == 0)
		return offset;

	tlv_end = offset + tlv_length;

	/* Make hf_ handling independent of specialfuncion */
	if ( type_index != -1 && value_array[type_index].hf_element) {
		proto_tree_add_item(tlv_tree,
			*(value_array[type_index].hf_element),
			tvb, offset, tlv_length, ENC_BIG_ENDIAN);
	} else {
		proto_tree_add_item(tlv_tree, hf_wassp_tlv_data,
			tvb, offset, tlv_length, ENC_BIG_ENDIAN);
	}
	if ( type_index != -1 && value_array[type_index].specialfunction ) {
		guint32 newoffset;

		while (offset < tlv_end) {
			newoffset = value_array[type_index].specialfunction (
				tvb, pinfo, tlv_tree, offset, tlv_length,
				value_array[type_index].evs);
			DISSECTOR_ASSERT(newoffset > offset);
			offset = newoffset;
		}
	}
	return tlv_end;
}

static int
dissect_wassp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *wassp_tree = NULL;
	guint32 offset = 0;
	guint32 packet_length;
	guint8 packet_type;
	guint32 subtype;

	packet_type = tvb_get_guint8(tvb, 1);
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_SHORT_NAME);
	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_str(pinfo->cinfo, COL_INFO, val_to_str(packet_type,
			wassp_tunnel_pdu_type, "Type 0x%02x"));

	if (tree) {
		/* Header dissection */
		ti = proto_tree_add_item(tree, proto_wassp, tvb, offset, -1,
		    ENC_BIG_ENDIAN);
		wassp_tree = proto_item_add_subtree(ti, ett_wassp);

		proto_tree_add_item(wassp_tree, hf_wassp_version, tvb, offset, 1,
			ENC_BIG_ENDIAN);
		offset += 1;

		proto_tree_add_item(wassp_tree, hf_wassp_type, tvb, offset, 1,
			ENC_BIG_ENDIAN);
		offset += 1;

		switch (packet_type) {
		case 1: /* Discover ??? */
			proto_tree_add_item(wassp_tree, hf_wassp_discover1, tvb, offset, 2,
				ENC_BIG_ENDIAN);
			offset += 2;
			packet_length = tvb_get_ntohs(tvb, offset);
			proto_tree_add_item(wassp_tree, hf_wassp_length, tvb, offset, 2,
				ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(wassp_tree, hf_wassp_discover2, tvb, offset, 2,
				ENC_BIG_ENDIAN);
			offset += 2;
			subtype = tvb_get_ntohs(tvb, offset);
			proto_tree_add_item(wassp_tree, hf_wassp_subtype, tvb, offset, 2,
				ENC_BIG_ENDIAN);
			offset += 2;
			switch (subtype) {
			case 1:
				proto_tree_add_item(wassp_tree, hf_wassp_ether, tvb, offset, 6,
					ENC_BIG_ENDIAN);
				offset += 6;
				break;
			case 2:
				proto_tree_add_item(wassp_tree, hf_wassp_discover3, tvb, offset, 2,
					ENC_BIG_ENDIAN);
				offset += 2;
				break;
			}
			break;
		default:
			proto_tree_add_item(wassp_tree, hf_wassp_seqno, tvb, offset, 1,
				ENC_BIG_ENDIAN);
			offset += 1;
	
			proto_tree_add_item(wassp_tree, hf_wassp_flags, tvb, offset, 1,
				ENC_BIG_ENDIAN);
			offset += 1;
	
			proto_tree_add_item(wassp_tree, hf_wassp_sessionid, tvb, offset, 2,
				ENC_BIG_ENDIAN);
			offset += 2;

			packet_length = tvb_get_ntohs(tvb, offset);
			proto_tree_add_item(wassp_tree, hf_wassp_length, tvb, offset, 2,
				ENC_BIG_ENDIAN);
			offset += 2;

			break;
		}
		/* Body dissection */
		switch (packet_type) {
		case 15: /* Data: 802.11 packet with FCS */
				offset = dissect_ieee80211(tvb, pinfo, wassp_tree,
					offset, packet_length - offset, NULL);
			break;
		default:
			while (offset < packet_length)
				offset = dissect_tlv(tvb, pinfo, wassp_tree,
					offset, 0, wassp_tunnel_tlv_vals);
			break;
		}
	}
	return offset;
}

static gboolean
test_wassp(tvbuff_t *tvb)
{
	/* Minimum of 8 bytes, first byte (version) has value of 3 */
	if ( tvb_length(tvb) < 8
		    || tvb_get_guint8(tvb, 0) != 3
		    /* || tvb_get_guint8(tvb, 2) != 0
		    || tvb_get_ntohs(tvb, 6) > tvb_reported_length(tvb) */
	) {
		return FALSE;
	}
	return TRUE;
}

#if 0
static gboolean
dissect_wassp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if ( !test_wassp(tvb) ) {
		return FALSE;
	}
	dissect_wassp(tvb, pinfo, tree);
	return TRUE;
}
#endif

static int
dissect_wassp_static(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if ( !test_wassp(tvb) ) {
		return 0;
	}
	return dissect_wassp(tvb, pinfo, tree);
}

void
proto_register_wassp(void)
{
	static hf_register_info hf[] = {

	/* TLV fields */
		{ &hf_wassp_tlv_type,
		{ "TlvType",	"wassp.tlv.type", FT_UINT8, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_wassp_tlv_length,
		{ "TlvLength",	"wassp.tlv.length", FT_UINT8, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_wassp_tlv_data,
		{ "TlvData",   "wassp.tlv.data", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

	/* WASSP tunnel header */
		{ &hf_wassp_version,
		{ "Protocol Version",	"wassp.version", FT_UINT8, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_wassp_type,
		{ "PDU Type",	"wassp.type", FT_UINT8, BASE_DEC, VALS(wassp_tunnel_pdu_type),
			0x0, NULL, HFILL }},

		{ &hf_wassp_seqno,
		{ "Sequence No",	"wassp.seqno", FT_UINT8, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_wassp_flags,
		{ "Flags",	"wassp.flags", FT_UINT8, BASE_HEX, NULL,
			0x0, NULL, HFILL }},

		{ &hf_wassp_sessionid,
		{ "Session ID",	"wassp.sessionid", FT_UINT8, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_wassp_length,
		{ "PDU Length",	"wassp.length", FT_UINT8, BASE_HEX, NULL,
			0x0, NULL, HFILL }},

	/* Data: Embedded IEEE 802.11 Frame */
		{ &hf_data,
		{ "DATA", "wassp.data", FT_NONE, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

	/* WASSP tunnel data */
		{ &hf_status,
		{ "STATUS", "wassp.status", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ru_soft_version,
		{ "RU-SOFT-VERSION", "wassp.ru.soft.version", FT_STRING, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ru_serial_number,
		{ "RU-SERIAL-NUMBER", "wassp.ru.serial.number", FT_STRING, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ru_challenge,
		{ "RU-CHALLENGE", "wassp.ru.challenge", FT_BYTES, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ru_response,
		{ "RU-RESPONSE", "wassp.ru.response", FT_BYTES, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ac_ipaddr,
		{ "AC-IPADDR", "wassp.ac.ipaddr", FT_IPv4, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ru_vns_id,
		{ "RU-VNS-ID", "wassp.ru.vns.id", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL }},

		{ &hf_tftp_server,
		{ "TFTP-SERVER", "wassp.tftp.server", FT_IPv4, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

		{ &hf_image_path,
		{ "IMAGE-PATH", "wassp.image.path", FT_STRING, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ru_config,
		{ "RU-CONFIG", "wassp.ru.config", FT_NONE, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ru_state,
		{ "RU-STATE", "wassp.ru.state", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ru_session_key,
		{ "RU-SESSION-KEY", "wassp.ru.session.key", FT_STRING, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

		{ &hf_message_type,
		{ "MESSAGE-TYPE", "wassp.message.type", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL }},

		{ &hf_random_number,
		{ "RANDOM-NUMBER", "wassp.random.number", FT_BYTES, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

		{ &hf_standby_timeout,
		{ "STANDBY-TIMEOUT", "wassp.standby.timeout", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ru_challenge_id,
		{ "RU-CHALLENGE-ID", "wassp.ru.challenge.id", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ru_model,
		{ "RU-MODEL", "wassp.ru.model", FT_STRING, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ru_scan_mode,
		{ "RU-SCAN-MODE", "wassp.ru.scan.mode", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ru_scan_type,
		{ "RU-SCAN-TYPE", "wassp.ru.scan.type", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ru_scan_interval,
		{ "RU-SCAN-INTERVAL", "wassp.ru.scan.interval", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ru_radio_type,
		{ "RU-RADIO-TYPE", "wassp.ru.radio.type", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ru_channel_dwell_time,
		{ "RU-CHANNEL-DWELL-TIME", "wassp.ru.channel.dwell.time", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ru_channel_list,
		{ "RU-CHANNEL-LIST", "wassp.ru.channel.list", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ru_trap,
		{ "RU-TRAP", "wassp.ru.trap", FT_STRING, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ru_scan_times,
		{ "RU-SCAN-TIMES", "wassp.ru.scan.times", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ru_scan_delay,
		{ "RU-SCAN-DELAY", "wassp.ru.scan.delay", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ru_scan_req_id,
		{ "RU-SCAN-REQ-ID", "wassp.ru.scan.req.id", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL }},

		{ &hf_static_config,
		{ "STATIC-CONFIG", "wassp.static.config", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL }},

		{ &hf_local_bridging,
		{ "LOCAL-BRIDGING", "wassp.local.bridging", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL }},

		{ &hf_static_bp_ipaddr,
		{ "STATIC-BP-IPADDR", "wassp.static.bp.ipaddr", FT_IPv4, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

		{ &hf_static_bp_netmask,
		{ "STATIC-BP-NETMASK", "wassp.static.bp.netmask", FT_IPv4, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

		{ &hf_static_bp_gateway,
		{ "STATIC-BP-GATEWAY", "wassp.static.bp.gateway", FT_IPv4, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

		{ &hf_static_bm_ipaddr,
		{ "STATIC-BM-IPADDR", "wassp.static.bm.ipaddr", FT_IPv4, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ru_alarm,
		{ "RU-ALARM", "wassp.ru.alarm", FT_NONE, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

		{ &hf_bp_request_id,
		{ "BP-REQUEST-ID", "wassp.bp.request.id", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL }},

		{ &hf_snmp_error_status,
		{ "SNMP-ERROR-STATUS", "wassp.snmp.error.status", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL }},

		{ &hf_snmp_error_index,
		{ "SNMP-ERROR-INDEX", "wassp.snmp.error.index", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ap_img_to_ram,
		{ "AP-IMG-TO-RAM", "wassp.ap.img.to.ram", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ap_img_role,
		{ "AP-IMG-ROLE", "wassp.ap.img.role", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ap_stats_block,
		{ "AP Stats Block", "wassp.ap_stats_block", FT_NONE, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

		{ &hf_block_config,
		{ "Config", "wassp.tlv_config", FT_NONE, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

		{ &hf_wassp_vlan_tag,
		{ "WASSP-VLAN-TAG", "wassp.vlan.tag", FT_INT32, BASE_DEC, NULL,
				0x0, NULL, HFILL }},

		{ &hf_wassp_tunnel_type,
		{ "WASSP-TUNNEL-TYPE", "wassp.tunnel.type", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ap_dhcp_mode,
		{ "AP-DHCP-MODE", "wassp.ap.dhcp.mode", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ap_ipaddr,
		{ "AP-IPADDR", "wassp.ap.ipaddr", FT_IPv4, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ap_netmask,
		{ "AP-NETMASK", "wassp.ap.netmask", FT_IPv4, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ap_gateway,
		{ "AP-GATEWAY", "wassp.ap.gateway", FT_IPv4, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

		{ &hf_preauth_resp,
		{ "PREAUTH_RESP",	"wassp.preauth.resp", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_bp_pmk,
		{ "BP_PMK",	"wassp.bp.pmk", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_ac_reg_challenge,
		{ "AC_REG_CHALLENGE",	"wassp.ac.reg.challenge", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_ac_reg_response,
		{ "AC_REG_RESPONSE",	"wassp.ac.reg.response", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats,
		{ "STATS",	"wassp.stats", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_certificate,
		{ "CERTIFICATE",	"wassp.certificate", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_radio_id,
		{ "RADIO_ID",	"wassp.radio.id", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_network_id,
		{ "NETWORK_ID",	"wassp.network.id", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_mu_mac,
		{ "MU_MAC",	"wassp.mu.mac", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_time,
		{ "TIME",	"wassp.time", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_num_radios,
		{ "NUM_RADIOS",	"wassp.num.radios", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_radio_info,
		{ "RADIO_INFO",	"wassp.radio.info", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_network_info,
		{ "NETWORK_INFO",	"wassp.network.info", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_vendor_id,
		{ "VENDOR_ID",	"wassp.vendor.id", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_product_id,
		{ "PRODUCT_ID",	"wassp.product.id", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_radio_info_ack,
		{ "RADIO_INFO_ACK",	"wassp.radio.info.ack", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_mu_rf_stats_block,
		{ "MU_RF_STATS_BLOCK",	"wassp.mu.rf.stats.block", FT_NONE, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_request_type,
		{ "STATS_REQUEST_TYPE",	"wassp.stats.request.type", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_last,
		{ "STATS_LAST",	"wassp.stats.last", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_mu_pmkid_list,
		{ "MU_PMKID_LIST",	"wassp.mu.pmkid.list", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_mu_pmk_bp,
		{ "MU_PMK_BP",	"wassp.mu.pmk.bp", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_mu_pmkid_bp,
		{ "MU_PMKID_BP",	"wassp.mu.pmkid.bp", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_countdown_time,
		{ "COUNTDOWN_TIME",	"wassp.countdown.time", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

	/* WASSP tunnel subtypes AP stats block */
		{ &hf_ap_stats_block_ether,
		{ "Ether Stats", "wassp.ap_stats_block.ether", FT_NONE, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ap_stats_block_radio_a,
		{ "Radio-A Stats", "wassp.ap_stats_block.radioa", FT_NONE, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

		{ &hf_ap_stats_block_radio_b_g,
		{ "Radio-B/G Stats", "wassp.ap_stats_block.radiobg", FT_NONE, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

		{ &hf_mu_stats_block,
		{ "Mobile User Stats", "wassp.mustats", FT_NONE, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

		{ &hf_mu_stats_block_65,
		{ "MU Stats Unknown 65", "wassp.mustats.65", FT_NONE, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

		{ &hf_dot1x_stats_block,
		{ "DOT1x_STATS_BLOCK", "wassp.ap_stats_block.dot1x", FT_NONE, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

	/* WASSP stats */
		{ &hf_stats_dot11_ackfailurecount,
		{ "DOT11_ACKFailureCount",	"wassp.stats.dot11.ackfailurecount", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_dot11_fcserrorcount,
		{ "DOT11_FCSErrorCount",	"wassp.stats.dot11.fcserrorcount", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_dot11_failedcount,
		{ "DOT11_FailedCount",	"wassp.stats.dot11.failedcount", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_dot11_frameduplicatecount,
		{ "DOT11_FrameDuplicateCount",	"wassp.stats.dot11.frameduplicatecount", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_dot11_multicastreceivedframecount,
		{ "DOT11_MulticastReceivedFrameCount",	"wassp.stats.dot11.multicastreceivedframecount", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_dot11_multicasttransmittedframecount,
		{ "DOT11_MulticastTransmittedFrameCount",	"wassp.stats.dot11.multicasttransmittedframecount", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_dot11_multipleretrycount,
		{ "DOT11_MultipleRetryCount",	"wassp.stats.dot11.multipleretrycount", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_dot11_rtsfailurecount,
		{ "DOT11_RTSFailureCount",	"wassp.stats.dot11.rtsfailurecount", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_dot11_rtssuccesscount,
		{ "DOT11_RTSSuccessCount",	"wassp.stats.dot11.rtssuccesscount", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_dot11_receivedfragementcount,
		{ "DOT11_ReceivedFragementCount",	"wassp.stats.dot11.receivedfragementcount", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_dot11_retrycount,
		{ "DOT11_RetryCount",	"wassp.stats.dot11.retrycount", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_dot11_transmittedfragmentcount,
		{ "DOT11_TransmittedFragmentCount",	"wassp.stats.dot11.transmittedfragmentcount", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_dot11_transmittedframecount,
		{ "DOT11_TransmittedFrameCount",	"wassp.stats.dot11.transmittedframecount", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_dot11_webundecryptablecount,
		{ "DOT11_WEBUndecryptableCount",	"wassp.stats.dot11.webundecryptablecount", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_dot11_wepexcludedcount,
		{ "DOT11_WEPExcludedCount",	"wassp.stats.dot11.wepexcludedcount", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_dot11_wepicverrorcount,
		{ "DOT11_WEPICVErrorCount",	"wassp.stats.dot11.wepicverrorcount", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_drm_allocfailures,
		{ "DRM_AllocFailures",	"wassp.stats.drm.allocfailures", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_drm_currentchannel,
		{ "DRM_CurrentChannel",	"wassp.stats.drm.currentchannel", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_drm_currentpower,
		{ "DRM_CurrentPower",	"wassp.stats.drm.currentpower", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_drm_datatxfailures,
		{ "DRM_DataTxFailures",	"wassp.stats.drm.datatxfailures", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_drm_devicetype,
		{ "DRM_DeviceType",	"wassp.stats.drm.devicetype", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_drm_indatapackets,
		{ "DRM_InDataPackets",	"wassp.stats.drm.indatapackets", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_drm_inmgmtpackets,
		{ "DRM_InMgmtPackets",	"wassp.stats.drm.inmgmtpackets", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_drm_loadfactor,
		{ "DRM_LoadFactor",	"wassp.stats.drm.loadfactor", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_drm_mgmttxfailures,
		{ "DRM_MgmtTxFailures",	"wassp.stats.drm.mgmttxfailures", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_drm_msgqfailures,
		{ "DRM_MsgQFailures",	"wassp.stats.drm.msgqfailures", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_drm_nodrmcurrentchannel,
		{ "DRM_NoDRMCurrentChannel",	"wassp.stats.drm.nodrmcurrentchannel", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_drm_outdatapackets,
		{ "DRM_OutDataPackets",	"wassp.stats.drm.outdatapackets", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_drm_outmgmtpackets,
		{ "DRM_OutMgmtPackets",	"wassp.stats.drm.outmgmtpackets", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_if_inbcastpackets,
		{ "IF_InBcastPackets",	"wassp.stats.if.inbcastpackets", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_if_indiscards,
		{ "IF_InDiscards",	"wassp.stats.if.indiscards", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_if_inerrors,
		{ "IF_InErrors",	"wassp.stats.if.inerrors", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_if_inmcastpackets,
		{ "IF_InMcastPackets",	"wassp.stats.if.inmcastpackets", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_if_inoctets,
		{ "IF_InOctets",	"wassp.stats.if.inoctets", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_if_inucastpackets,
		{ "IF_InUcastPackets",	"wassp.stats.if.inucastpackets", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_if_mtu,
		{ "IF_MTU",	"wassp.stats.if.mtu", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_if_outbcastpackets,
		{ "IF_OutBcastPackets",	"wassp.stats.if.outbcastpackets", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_if_outdiscards,
		{ "IF_OutDiscards",	"wassp.stats.if.outdiscards", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_if_outerrors,
		{ "IF_OutErrors",	"wassp.stats.if.outerrors", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_if_outoctets,
		{ "IF_OutOctets",	"wassp.stats.if.outoctets", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_if_outucastpackets,
		{ "IF_OutUcastPackets",	"wassp.stats.if.outucastpackets", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_if_outmcastpackets,
		{ "IF_OutMCastPackets",	"wassp.stats.if.outmcastpackets", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_mu_address,
		{ "MU_Address",	"wassp.stats.mu.address", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_mu_associationcount,
		{ "MU_AssociationCount",	"wassp.stats.mu.associationcount", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_mu_authenticationcount,
		{ "MU_AuthenticationCount",	"wassp.stats.mu.authenticationcount", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_mu_deassociationcount,
		{ "MU_DeAssociationCount",	"wassp.stats.mu.deassociationcount", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_mu_deauthenticationcount,
		{ "MU_DeAuthenticationCount",	"wassp.stats.mu.deauthenticationcount", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_mu_ifindex,
		{ "MU_IfIndex",	"wassp.stats.mu.ifindex", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_mu_reassociationcount,
		{ "MU_ReAssociationCount",	"wassp.stats.mu.reassociationcount", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_mu_receivedbytes,
		{ "MU_ReceivedBytes",	"wassp.stats.mu.receivedbytes", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_mu_receivederrors,
		{ "MU_ReceivedErrors",	"wassp.stats.mu.receivederrors", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_mu_receivedframecount,
		{ "MU_ReceivedFrameCount",	"wassp.stats.mu.receivedframecount", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_mu_receivedrssi,
		{ "MU_ReceivedRSSI",	"wassp.stats.mu.receivedrssi", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_mu_receivedrate,
		{ "MU_ReceivedRate",	"wassp.stats.mu.receivedrate", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_mu_transmittedbytes,
		{ "MU_TransmittedBytes",	"wassp.stats.mu.transmittedbytes", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_mu_transmittederrors,
		{ "MU_TransmittedErrors",	"wassp.stats.mu.transmittederrors", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_mu_transmittedframecount,
		{ "MU_TransmittedFrameCount",	"wassp.stats.mu.transmittedframecount", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_mu_transmittedrssi,
		{ "MU_TransmittedRSSI",	"wassp.stats.mu.transmittedrssi", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_mu_transmittedrate,
		{ "MU_TransmittedRate",	"wassp.stats.mu.transmittedrate", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_mu_rf_stats_end,
		{ "MU_RF_STATS_END",	"wassp.stats.mu.rf.stats.end", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_rfc_1213_sysuptime,
		{ "RFC_1213_SYSUPTIME",	"wassp.stats.rfc.1213.sysuptime", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_dot1x_stats_credent,
		{ "DOT1x_CREDENT",	"wassp.stats.dot1x.credent", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_dot1x_stats_end_date,
		{ "DOT1x_END_DATE",	"wassp.stats.dot1x.enddate", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_stats_tlv_max,
		{ "TLV_MAX",	"wassp.stats.tlvmax", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

	/* WASSP tunnel subtypes TLV config */
		{ &hf_config_radio,
		{ "Config Radio", "wassp.tlv_config.radio", FT_NONE, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

		{ &hf_config_vns,
		{ "Config VNS", "wassp.tlv_config.vns", FT_NONE, BASE_NONE, NULL,
				0x0, NULL, HFILL }},

	/* WASSP config */
		{ &hf_config_trace_status_debug,
		{ "TRACE_STATUS_DEBUG",	"wassp.config.trace.status.debug", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_trace_status_config,
		{ "TRACE_STATUS_CONFIG",	"wassp.config.trace.status.config", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_use_bcast_for_disassc,
		{ "USE_BCAST_FOR_DISASSC",	"wassp.config.use.bcast.for.disassc", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_bandwidth_voice_assc,
		{ "BANDWIDTH_VOICE_ASSC",	"wassp.config.bandwidth.voice.assc", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_bandwidth_voice_reassc,
		{ "BANDWIDTH_VOICE_REASSC",	"wassp.config.bandwidth.voice.reassc", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_bandwidth_video_assc,
		{ "BANDWIDTH_VIDEO_ASSC",	"wassp.config.bandwidth.video.assc", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_bandwidth_video_reassc,
		{ "BANDWIDTH_VIDEO_REASSC",	"wassp.config.bandwidth.video.reassc", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_bandwidth_video_reserve,
		{ "BANDWIDTH_VIDEO_RESERVE",	"wassp.config.bandwidth.video.reserve", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_bandwidth_adm_ctrl_reserve,
		{ "BANDWIDTH_ADM_CTRL_RESERVE",	"wassp.config.bandwidth.adm.ctrl.reserve", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vlan_tag,
		{ "VLAN_TAG",	"wassp.config.vlan.tag", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_country_code,
		{ "COUNTRY_CODE",	"wassp.config.country.code", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_poll_duration,
		{ "POLL_DURATION",	"wassp.config.poll.duration", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_poll_interval,
		{ "POLL_INTERVAL",	"wassp.config.poll.interval", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_poll_maintain_client_session,
		{ "POLL_MAINTAIN_CLIENT_SESSION",	"wassp.config.poll.maintain.client.session", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_telnet_enable,
		{ "TELNET_ENABLE",	"wassp.config.telnet.enable", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_telnet_password,
		{ "TELNET_PASSWORD",	"wassp.config.telnet.password", FT_STRING, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_telnet_password_entry_mode,
		{ "TELNET_PASSWORD_ENTRY_MODE",	"wassp.config.telnet.password.entry.mode", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_outdoor_enable_environment,
		{ "OUTDOOR_ENABLE_ENVIRONMENT",	"wassp.config.outdoor.enable.environment", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_slp_retry_count,
		{ "SLP_RETRY_COUNT",	"wassp.config.slp.retry.count", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_slp_retry_delay,
		{ "SLP_RETRY_DELAY",	"wassp.config.slp.retry.delay", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_dns_retry_count,
		{ "DNS_RETRY_COUNT",	"wassp.config.dns.retry.count", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_dns_retry_delay,
		{ "DNS_RETRY_DELAY",	"wassp.config.dns.retry.delay", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_mcast_slp_retry_count,
		{ "MCAST_SLP_RETRY_COUNT",	"wassp.config.mcast.slp.retry.count", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_mcast_slp_retry_delay,
		{ "MCAST_SLP_RETRY_DELAY",	"wassp.config.mcast.slp.retry.delay", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_disc_retry_count,
		{ "DISC_RETRY_COUNT",	"wassp.config.disc.retry.count", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_disc_retry_delay,
		{ "DISC_RETRY_DELAY",	"wassp.config.disc.retry.delay", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_logging_alarm_sev,
		{ "LOGGING_ALARM_SEV",	"wassp.config.logging.alarm.sev", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_blacklist_blacklist_add,
		{ "BLACKLIST_BLACKLIST_ADD",	"wassp.config.blacklist.blacklist.add", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_failover_ac_ip_addr,
		{ "FAILOVER_AC_IP_ADDR",	"wassp.config.failover.ac.ip.addr", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_static_ac_ip_addr,
		{ "STATIC_AC_IP_ADDR",	"wassp.config.static.ac.ip.addr", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_dhcp_assignment,
		{ "DHCP_ASSIGNMENT",	"wassp.config.dhcp.assignment", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_static_ap_ip_addr,
		{ "STATIC_AP_IP_ADDR",	"wassp.config.static.ap.ip.addr", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_static_ap_ip_netmask,
		{ "STATIC_AP_IP_NETMASK",	"wassp.config.static.ap.ip.netmask", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_static_ap_default_gw,
		{ "STATIC_AP_DEFAULT_GW",	"wassp.config.static.ap.default.gw", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_blacklist_del,
		{ "BLACKLIST_DEL",	"wassp.config.blacklist.del", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_macaddr_req,
		{ "MACADDR_REQ",	"wassp.config.macaddr.req", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_availability_mode,
		{ "AVAILABILITY_MODE",	"wassp.config.availability.mode", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

	/* WASSP config vns */
		{ &hf_config_vns_radio_id,
		{ "V_RADIO_ID",	"wassp.config.vns.radio.id", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_vns_id,
		{ "V_VNS_ID",	"wassp.config.vns.vns.id", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_turbo_voice,
		{ "V_TURBO_VOICE",	"wassp.config.vns.turbo.voice", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_prop_ie,
		{ "V_PROP_IE",	"wassp.config.vns.prop.ie", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_enable_802_11_h,
		{ "V_ENABLE_802_11_H",	"wassp.config.vns.enable.802.11.h", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_power_backoff,
		{ "V_POWER_BACKOFF",	"wassp.config.vns.power.backoff", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_bridge_mode,
		{ "V_BRIDGE_MODE",	"wassp.config.vns.bridge.mode", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_vlan_tag,
		{ "V_VLAN_TAG",	"wassp.config.vns.vlan.tag", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_process_ie_req,
		{ "V_PROCESS_IE_REQ",	"wassp.config.vns.process.ie.req", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_enable_u_apsd,
		{ "V_ENABLE_U_APSD",	"wassp.config.vns.enable.u.apsd", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_adm_ctrl_voice,
		{ "V_ADM_CTRL_VOICE",	"wassp.config.vns.adm.ctrl.voice", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_adm_ctrl_video,
		{ "V_ADM_CTRL_VIDEO",	"wassp.config.vns.adm.ctrl.video", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_qos_up_value,
		{ "V_QOS_UP_VALUE",	"wassp.config.vns.qos.up.value", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_priority_override,
		{ "V_PRIORITY_OVERRIDE",	"wassp.config.vns.priority.override", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_dscp_override_value,
		{ "V_DSCP_OVERRIDE_VALUE",	"wassp.config.vns.dscp.override.value", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_enable_802_11_e,
		{ "V_ENABLE_802_11_E",	"wassp.config.vns.enable.802.11.e", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_enable_wmm,
		{ "V_ENABLE_WMM",	"wassp.config.vns.enable.wmm", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_legacy_client_priority,
		{ "V_LEGACY_CLIENT_PRIORITY",	"wassp.config.vns.legacy.client.priority", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_ssid_id,
		{ "V_SSID_ID",	"wassp.config.vns.ssid.id", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_ssid_bcast_string,
		{ "V_SSID_BCAST_STRING",	"wassp.config.vns.ssid.bcast.string", FT_STRING, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_ssid_suppress,
		{ "V_SSID_SUPPRESS",	"wassp.config.vns.ssid.suppress", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_802_1_x_enable,
		{ "V_802_1_X_ENABLE",	"wassp.config.vns.802.1.x.enable", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_802_1_x_dyn_rekey,
		{ "V_802_1_X_DYN_REKEY",	"wassp.config.vns.802.1.x.dyn.rekey", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_wpa_enable,
		{ "V_WPA_ENABLE",	"wassp.config.vns.wpa.enable", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_wpa_v2_enable,
		{ "V_WPA_V2_ENABLE",	"wassp.config.vns.wpa.v2.enable", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_wpa_passphrase,
		{ "V_WPA_PASSPHRASE",	"wassp.config.vns.wpa.passphrase", FT_STRING, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_wpa_cipher_type,
		{ "V_WPA_CIPHER_TYPE",	"wassp.config.vns.wpa.cipher.type", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_wpa_v2_cipher_type,
		{ "V_WPA_V2_CIPHER_TYPE",	"wassp.config.vns.wpa.v2.cipher.type", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_wep_key_index,
		{ "V_WEP_KEY_INDEX",	"wassp.config.vns.wep.key.index", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_wep_default_key_value,
		{ "V_WEP_DEFAULT_KEY_VALUE",	"wassp.config.vns.wep.default.key.value", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_channel_report,
		{ "V_CHANNEL_REPORT",	"wassp.config.vns.channel.report", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_wds_service,
		{ "V_WDS_SERVICE",	"wassp.config.vns.wds.service", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_wds_pref_parent,
		{ "V_WDS_PREF_PARENT",	"wassp.config.vns.wds.pref.parent", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_wds_bridge,
		{ "V_WDS_BRIDGE",	"wassp.config.vns.wds.bridge", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_okc_enabled,
		{ "V_OKC_ENABLED",	"wassp.config.vns.okc.enabled", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_mu_assoc_retries,
		{ "V_MU_ASSOC_RETRIES",	"wassp.config.vns.mu.assoc.retries", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_mu_assoc_timeout,
		{ "V_MU_ASSOC_TIMEOUT",	"wassp.config.vns.mu.assoc.timeout", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_wds_parent,
		{ "V_WDS_PARENT",	"wassp.config.vns.wds.parent", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_wds_back_parent,
		{ "V_WDS_BACK_PARENT",	"wassp.config.vns.wds.back.parent", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_vns_wds_name,
		{ "V_WDS_NAME",	"wassp.config.vns.wds.name", FT_STRING, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

	/* WASSP config radio */
		{ &hf_config_radio_radio_id,
		{ "R_RADIO_ID",	"wassp.config.radio.radio.id", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_enable_radio,
		{ "R_ENABLE_RADIO",	"wassp.config.radio.enable.radio", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_channel,
		{ "R_CHANNEL",	"wassp.config.radio.channel", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_op_rate_set,
		{ "R_OP_RATE_SET",	"wassp.config.radio.op.rate.set", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_op_rate_max,
		{ "R_OP_RATE_MAX",	"wassp.config.radio.op.rate.max", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_beacon_period,
		{ "R_BEACON_PERIOD",	"wassp.config.radio.beacon.period", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_dtim_period,
		{ "R_DTIM_PERIOD",	"wassp.config.radio.dtim.period", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_rts_threshold,
		{ "R_RTS_THRESHOLD",	"wassp.config.radio.rts.threshold", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_fragment_threshold,
		{ "R_FRAGMENT_THRESHOLD",	"wassp.config.radio.fragment.threshold", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_power_level,
		{ "R_POWER_LEVEL",	"wassp.config.radio.power.level", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_diversity_rx,
		{ "R_DIVERSITY_RX",	"wassp.config.radio.diversity.rx", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_diversity_tx,
		{ "R_DIVERSITY_TX",	"wassp.config.radio.diversity.tx", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_short_preamble,
		{ "R_SHORT_PREAMBLE",	"wassp.config.radio.short.preamble", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_basic_rate_max,
		{ "R_BASIC_RATE_MAX",	"wassp.config.radio.basic.rate.max", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_basic_rate_min,
		{ "R_BASIC_RATE_MIN",	"wassp.config.radio.basic.rate.min", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_hw_retries,
		{ "R_HW_RETRIES",	"wassp.config.radio.hw.retries", FT_STRING, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_tx_power_min,
		{ "R_TX_POWER_MIN",	"wassp.config.radio.tx.power.min", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_tx_power_max,
		{ "R_TX_POWER_MAX",	"wassp.config.radio.tx.power.max", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_domain_id,
		{ "R_DOMAIN_ID",	"wassp.config.radio.domain.id", FT_STRING, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_b_enable,
		{ "R_B_ENABLE",	"wassp.config.radio.b.enable", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_b_basic_rates,
		{ "R_B_BASIC_RATES",	"wassp.config.radio.b.basic.rates", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_g_enable,
		{ "R_G_ENABLE",	"wassp.config.radio.g.enable", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_g_protect_mode,
		{ "R_G_PROTECT_MODE",	"wassp.config.radio.g.protect.mode", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_g_protect_type,
		{ "R_G_PROTECT_TYPE",	"wassp.config.radio.g.protect.type", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_g_protect_rate,
		{ "R_G_PROTECT_RATE",	"wassp.config.radio.g.protect.rate", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_g_basic_rate,
		{ "R_G_BASIC_RATE",	"wassp.config.radio.g.basic.rate", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_a_support_802_11_j,
		{ "R_A_SUPPORT_802_11_J",	"wassp.config.radio.a.support.802.11.j", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_atpc_en_interval,
		{ "R_ATPC_EN_INTERVAL",	"wassp.config.radio.atpc.en.interval", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_acs_ch_list,
		{ "R_ACS_CH_LIST",	"wassp.config.radio.acs.ch.list", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_config_radio_tx_power_adj,
		{ "R_TX_POWER_ADJ",	"wassp.config.radio.tx.power.adj", FT_INT32, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

	/* WASSP discover header */
		{ &hf_wassp_discover1,
		{ "Discover Header1",	"wassp.discover1", FT_UINT8, BASE_HEX, NULL,
			0x0, NULL, HFILL }},

		/* { &hf_wassp_length, */ /* see tunnel header */

		{ &hf_wassp_discover2,
		{ "Discover Header2",	"wassp.discover2", FT_UINT8, BASE_HEX, NULL,
			0x0, NULL, HFILL }},

		{ &hf_wassp_subtype,
		{ "Discover Subtype",	"wassp.subtype", FT_UINT8, BASE_DEC, NULL,
			0x0, NULL, HFILL }},

		{ &hf_wassp_ether,
		{ "Discover Ether",	"wassp.ether", FT_ETHER, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_wassp_discover3,
		{ "Discover Header3",	"wassp.discover3", FT_UINT8, BASE_HEX, NULL,
			0x0, NULL, HFILL }},

	};
	static gint *ett[] = {
		&ett_wassp,
		&ett_wassp_tlv_header,
	};

	proto_wassp = proto_register_protocol(PROTO_LONG_NAME, PROTO_SHORT_NAME, "wassp");
	proto_register_field_array(proto_wassp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_wassp(void)
{
	dissector_handle_t wassp_handle;


	wassp_handle = new_create_dissector_handle(dissect_wassp_static, proto_wassp);
	dissector_add_uint("udp.port", PORT_WASSP_DISCOVER, wassp_handle);
	dissector_add_uint("udp.port", PORT_WASSP_TUNNEL, wassp_handle);
	/* dissector_add_uint("udp.port", PORT_WASSP_PEER, wassp_handle); */
#if 0
	heur_dissector_add("udp", dissect_wassp_heur, proto_wassp);
#endif

	snmp_handle = find_dissector("snmp");
	ieee80211_handle = find_dissector("wlan");
}

