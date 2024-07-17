/* packet-dect-mitel-rfp.c
 * Routines for DECT-Mitel-RFP dissection
 * Copyright 2022, Bernhard Dick <bernhard@bdick.de>
 *
 * Parts are based on the EVENTPHONE rfpproxy project that is MIT licensed
 * and Copyright (c) 2019 Bianco Veigel <devel at zivillian.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * This is a proprietary protocol deveolped by Mitel for communication
 * between the DECT system management Software (OMM) and the DECT
 * base station (RFPs)
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/column-utils.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/tfs.h>
#include <epan/tvbuff.h>
#include <epan/unit_strings.h>
#include <epan/value_string.h>
#include <ftypes/ftypes.h>

/* Prototypes */
void proto_reg_handoff_dect_mitel_rfp(void);
void proto_register_dect_mitel_rfp(void);

/* Initialize the protocol and registered fields */
static int proto_dect_mitel_rfp;

static int hf_dect_mitel_rfp_message_type;
static int hf_dect_mitel_rfp_message_length;

/* CONTROL-ACK */
static int hf_dect_mitel_rfp_control_ack_message;
static int hf_dect_mitel_rfp_control_ack_call_id;

/* CONTROL-NACK */
static int hf_dect_mitel_rfp_control_nack_message;
static int hf_dect_mitel_rfp_control_nack_call_id;
static int hf_dect_mitel_rfp_control_nack_reason;

/* CONTROL-HEARTBEAT */
static int hf_dect_mitel_rfp_control_heartbeat_milliseconds;
static int hf_dect_mitel_rfp_control_heartbeat_nanoseconds;

/* SYS-IP-OPTIONS */
static int hf_dect_mitel_rfp_sys_ip_options_voice_tos;
static int hf_dect_mitel_rfp_sys_ip_options_signalling_tos;
static int hf_dect_mitel_rfp_sys_ip_options_ttl;
static int hf_dect_mitel_rfp_sys_ip_options_signal_vlan_priority;
static int hf_dect_mitel_rfp_sys_ip_options_voice_vlan_priority;

/* SYS-LED */
static int hf_dect_mitel_rfp_sys_led_id;
static int hf_dect_mitel_rfp_sys_led_color;

/* SYS-HEARTBEAT-INTERVAL */
static int hf_dect_mitel_rfp_sys_heartbeat_interval_value;

/* SYS-SYSLOG */
static int hf_dect_mitel_rfp_sys_syslog_ip_address;
static int hf_dect_mitel_rfp_sys_syslog_port;

/* SYS-MAX-CHANNELS */
static int hf_dect_mitel_rfp_sys_max_channels_dsp;
static int hf_dect_mitel_rfp_sys_max_channels_sessions;

/* SYS-HTTP-SET */
static int hf_dect_mitel_rfp_sys_http_set_ip_address;
static int hf_dect_mitel_rfp_sys_http_set_port;

/* SYS-PASSWD */
static int hf_dect_mitel_rfp_sys_passwd_remote_access_enabled;
static int hf_dect_mitel_rfp_sys_passwd_root_username;
static int hf_dect_mitel_rfp_sys_passwd_root_password;
static int hf_dect_mitel_rfp_sys_passwd_admin_username;
static int hf_dect_mitel_rfp_sys_passwd_admin_password;

/* SYS-RPING */
static int hf_dect_mitel_rfp_sys_rping_ip_address;
static int hf_dect_mitel_rfp_sys_rping_rtt;

/* SYS-CORE-DUMP */
static int hf_dect_mitel_rfp_sys_core_dump_url;

/* SYS-VSNTP-TIME */
static int hf_dect_mitel_rfp_sys_vsntp_time_t1_seconds;
static int hf_dect_mitel_rfp_sys_vsntp_time_t1_nanoseconds;
static int hf_dect_mitel_rfp_sys_vsntp_time_t2_seconds;
static int hf_dect_mitel_rfp_sys_vsntp_time_t2_nanoseconds;

/* SYS-INIT */
static int hf_dect_mitel_rfp_sys_init_rfp_model;
static int hf_dect_mitel_rfp_sys_init_rfp_mac;
static int hf_dect_mitel_rfp_sys_init_crypted;
static int hf_dect_mitel_rfp_sys_init_protocol;
static int hf_dect_mitel_rfp_sys_init_rfp_capabilities;
static int hf_dect_mitel_rfp_sys_init_rfp_capability_normal_tx;
static int hf_dect_mitel_rfp_sys_init_rfp_capability_indoor;
static int hf_dect_mitel_rfp_sys_init_rfp_capability_wlan;
static int hf_dect_mitel_rfp_sys_init_rfp_capability_encryption;
static int hf_dect_mitel_rfp_sys_init_rfp_capability_frequency_shift;
static int hf_dect_mitel_rfp_sys_init_rfp_capability_low_tx;
static int hf_dect_mitel_rfp_sys_init_rfp_capability_advanced_feature;
static int hf_dect_mitel_rfp_sys_init_rfp_software_version;
static int hf_dect_mitel_rfp_sys_init_signature;

/* SYS-AUTHENTICATE */
static int hf_dect_mitel_rfp_sys_authenticate_omm_iv;
static int hf_dect_mitel_rfp_sys_authenticate_rfp_iv;

/* SYS-LICENSE-TIMER */
static int hf_dect_mitel_rfp_sys_license_timer_query;
static int hf_dect_mitel_rfp_sys_license_timer_grace_period;
static int hf_dect_mitel_rfp_sys_license_timer_checksum;

/* MEDIA */
static int hf_dect_mitel_rfp_media_handle;
static int hf_dect_mitel_rfp_media_mcei;
static int hf_dect_mitel_rfp_media_direction;

/* MEDIA-OPEN */
static int hf_dect_mitel_rfp_media_open_codec;
static int hf_dect_mitel_rfp_media_open_slot_count;
static int hf_dect_mitel_rfp_media_open_flags;

/* MEDIA-CONF */
static int hf_dect_mitel_rfp_media_conf_vif;
static int hf_dect_mitel_rfp_media_conf_vad;
static int hf_dect_mitel_rfp_media_conf_codec_count;
static int hf_dect_mitel_rfp_media_conf_codec_type;
static int hf_dect_mitel_rfp_media_conf_codec_pt;
static int hf_dect_mitel_rfp_media_conf_codec_rate;
static int hf_dect_mitel_rfp_media_conf_ppn;
static int hf_dect_mitel_rfp_media_conf_local_port_1;
static int hf_dect_mitel_rfp_media_conf_local_port_2;
static int hf_dect_mitel_rfp_media_conf_rx_ip_address;
static int hf_dect_mitel_rfp_media_conf_rx_port_1;
static int hf_dect_mitel_rfp_media_conf_rx_port_2;
static int hf_dect_mitel_rfp_media_conf_tx_ip_address;
static int hf_dect_mitel_rfp_media_conf_tx_port_1;
static int hf_dect_mitel_rfp_media_conf_tx_port_2;

/* MEDIA-START */
static int hf_dect_mitel_rfp_media_start_time;
static int hf_dect_mitel_rfp_media_start_met_keep_alive;

/* MEDIA-STATISTICS */
static int hf_dect_mitel_rfp_media_statistics_duration;
static int hf_dect_mitel_rfp_media_statistics_tx_packets;
static int hf_dect_mitel_rfp_media_statistics_tx_bytes;
static int hf_dect_mitel_rfp_media_statistics_rx_packets;
static int hf_dect_mitel_rfp_media_statistics_rx_bytes;
static int hf_dect_mitel_rfp_media_statistics_lost_packets;
static int hf_dect_mitel_rfp_media_statistics_max_jitter;
static int hf_dect_mitel_rfp_media_statistics_rtp_ip_address;

/* MEDIA-REDIRECT-START */
static int hf_dect_mitel_rfp_media_redirect_start_local_port_1;
static int hf_dect_mitel_rfp_media_redirect_start_local_port_2;
static int hf_dect_mitel_rfp_media_redirect_start_remote_ip_address;
static int hf_dect_mitel_rfp_media_redirect_start_remote_port_1;
static int hf_dect_mitel_rfp_media_redirect_start_remote_port_2;
static int hf_dect_mitel_rfp_media_redirect_start_time;

/* MEDIA-REDIRECT-STOP */
static int hf_dect_mitel_rfp_media_redirect_stop_fallback;

/* MEDIA-DTMF */
static int hf_dect_mitel_rfp_media_dtmf_duration;
static int hf_dect_mitel_rfp_media_dtmf_key;

/* MEDIA-TONE */
static int hf_dect_mitel_rfp_media_tone_count;
static int hf_dect_mitel_rfp_media_tone_frequency_1;
static int hf_dect_mitel_rfp_media_tone_frequency_2;
static int hf_dect_mitel_rfp_media_tone_frequency_3;
static int hf_dect_mitel_rfp_media_tone_frequency_4;
static int hf_dect_mitel_rfp_media_tone_cb_1;
static int hf_dect_mitel_rfp_media_tone_cb_2;
static int hf_dect_mitel_rfp_media_tone_cb_3;
static int hf_dect_mitel_rfp_media_tone_cb_4;
static int hf_dect_mitel_rfp_media_tone_duration;
static int hf_dect_mitel_rfp_media_tone_cycle_count;
static int hf_dect_mitel_rfp_media_tone_cycle_to;
static int hf_dect_mitel_rfp_media_tone_next;

/* SYNC */
static int hf_dect_mitel_rfp_sync_payload_type;
static int hf_dect_mitel_rfp_sync_payload_length;

/* SYNC FREQ_CTRL_MODE_IND */
static int hf_dect_mitel_rfp_sync_freq_ctrl_mode_ind_mode;

/* SYNC FREQ_CTRL_MODE_CFM */
static int hf_dect_mitel_rfp_sync_freq_ctrl_mode_cfm_mode;
static int hf_dect_mitel_rfp_sync_freq_ctrl_mode_cfm_ppm;
static int hf_dect_mitel_rfp_sync_freq_ctrl_mode_cfm_avg;

/* SYNC SET_FREQUENCY */
static int hf_dect_mitel_rfp_sync_set_frequency_value;

/* SYNC START_MAC_SLAVE_MODE_IND */
static int hf_dect_mitel_rfp_sync_start_mac_slave_mode_ind_rfp;

/* SYNC SYSTEM_SEARCH_IND */
static int hf_dect_mitel_rfp_sync_system_search_ind_mode;

/* SYNC SYSTEM_SEARCH_CFM */
static int hf_dect_mitel_rfp_sync_system_search_cfm_count;
static int hf_dect_mitel_rfp_sync_system_search_cfm_item_rpn;
static int hf_dect_mitel_rfp_sync_system_search_cfm_item_rssi;

/* SYNC PHASE_OFS_WITH_RSSI_IND */
static int hf_dect_mitel_rfp_sync_phase_ofs_with_rssi_ind_count;
static int hf_dect_mitel_rfp_sync_phase_ofs_with_rssi_ind_item_rpn;
static int hf_dect_mitel_rfp_sync_phase_ofs_with_rssi_ind_item_offset;
static int hf_dect_mitel_rfp_sync_phase_ofs_with_rssi_ind_item_rssi;
static int hf_dect_mitel_rfp_sync_phase_ofs_with_rssi_ind_item_qt_sync_check;

/* Message Type */
enum dect_mitel_rfp_message_type_coding {
	DECT_MITEL_RFP_MESSAGE_TYPE_CONTROL_ACK                  = 0x0001,
	DECT_MITEL_RFP_MESSAGE_TYPE_CONTROL_NACK                 = 0x0002,
	DECT_MITEL_RFP_MESSAGE_TYPE_CONTROL_HEARTBEAT            = 0x0003,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_IP_OPTIONS               = 0x0101,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_LED                      = 0x0102,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_SPY                      = 0x0104,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_HEARTBEAT_INTERVAL       = 0x0105,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_RSX                      = 0x0106,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_SYSLOG                   = 0x0107,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_MAX_CHANNELS             = 0x0108,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_HTTP_SET                 = 0x0109,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_PASSWD                   = 0x010a,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_CRYPTED_PACKET           = 0x010b,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_OMM_CONTROL              = 0x010c,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_STATE_DUMP               = 0x010d,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_RPING                    = 0x010e,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_STATE_DUMP_REQ           = 0x010f,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_STATE_DUMP_RES           = 0x0110,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_NEW_SW                   = 0x0111,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_AUDIO_LOG                = 0x0112,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_USB_OVERLOAD             = 0x0113,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_SW_CONTAINER             = 0x0115,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_CORE_DUMP                = 0x0116,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_VSNTP_TIME               = 0x0117,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_UPDATE_802_1X_SUPPLICANT = 0x0119,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_INIT                     = 0x0120,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_RESET                    = 0x0121,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_SUPPLICANT_MD5           = 0x0122,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_STREAM_INFO              = 0x0123,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_RFP_AUTH_KEY             = 0x0124,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_RFP_RE_ENROLEMENT        = 0x0125,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_ENCRYPTION_CONF          = 0x0126,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_AUTHENTICATE             = 0x012d,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYS_LICENSE_TIMER            = 0x0134,
	DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_OPEN                   = 0x0200,
	DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_CONF                   = 0x0201,
	DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_CLOSE                  = 0x0202,
	DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_START                  = 0x0203,
	DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_STOP                   = 0x0204,
	DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_STATISTICS             = 0x0205,
	DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_REDIRECT_START         = 0x0206,
	DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_REDIRECT_STOP          = 0x0207,
	DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_RESTART                = 0x0208,
	DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_DTMF                   = 0x0209,
	DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_DSP_CLOSE              = 0x020a,
	DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_TONE                   = 0x020b,
	DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_BANDWIDTH_SWO          = 0x020c,
	DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_MUTE                   = 0x020d,
	DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_G729_USED              = 0x020e,
	DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_TRACE_PPN              = 0x020f,
	DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_EOS_DETECT             = 0x0210,
	DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_AUDIO_STATISTICS       = 0x0211,
	DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_VIDEO_STATE            = 0x0212,
	DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_CHANNEL_MOD_INFO       = 0x0213,
	DECT_MITEL_RFP_MESSAGE_TYPE_ETH                          = 0x0301,
	DECT_MITEL_RFP_MESSAGE_TYPE_SYNC                         = 0x0302,
	DECT_MITEL_RFP_MESSAGE_TYPE_WLAN_RFP_CONFIG              = 0x0401,
	DECT_MITEL_RFP_MESSAGE_TYPE_WLAN_RFP_UP                  = 0x0402,
	DECT_MITEL_RFP_MESSAGE_TYPE_WLAN_RFP_DOWN                = 0x0403,
	DECT_MITEL_RFP_MESSAGE_TYPE_WLAN_RFP_CLIENT_REQ          = 0x0404,
	DECT_MITEL_RFP_MESSAGE_TYPE_WLAN_RFP_CLIENT_REP          = 0x0405,
	DECT_MITEL_RFP_MESSAGE_TYPE_WLAN_RFP_SET_ACL             = 0x0406,
	DECT_MITEL_RFP_MESSAGE_TYPE_WLAN_RFP_CLIENT_INFO         = 0x0407,
	DECT_MITEL_RFP_MESSAGE_TYPE_WLAN_RFP_ACK                 = 0x0408,
	DECT_MITEL_RFP_MESSAGE_TYPE_WLAN_RFP_LINK_NOK_NACK       = 0x0409,
	DECT_MITEL_RFP_MESSAGE_TYPE_WLAN_RFP_IFACE_REP           = 0x040e,
	DECT_MITEL_RFP_MESSAGE_TYPE_SNMP_RFP_UPDATE              = 0x0501,
	DECT_MITEL_RFP_MESSAGE_TYPE_CONF_OPEN                    = 0x0600,
	DECT_MITEL_RFP_MESSAGE_TYPE_CONF_ADD_SUBSCR              = 0x0601,
	DECT_MITEL_RFP_MESSAGE_TYPE_CONF_CHG_SUBSCR              = 0x0602,
	DECT_MITEL_RFP_MESSAGE_TYPE_CONF_DEL_SUBSCR              = 0x0603,
	DECT_MITEL_RFP_MESSAGE_TYPE_CONF_CLOSE                   = 0x0604,
	DECT_MITEL_RFP_MESSAGE_TYPE_CONF_RTP                     = 0x0605,
	DECT_MITEL_RFP_MESSAGE_TYPE_BLUETOOTH_DEVICE             = 0x0700,
	DECT_MITEL_RFP_MESSAGE_TYPE_BLUETOOTH_CONFIG             = 0x0701,
	DECT_MITEL_RFP_MESSAGE_TYPE_BLUETOOTH_DATA               = 0x0702,
	DECT_MITEL_RFP_MESSAGE_TYPE_VIDEO_DEVICE                 = 0x0800,
	DECT_MITEL_RFP_MESSAGE_TYPE_VIDEO_CONFIG                 = 0x0801,
};

/* CONTROL-NACK */
enum dect_mitel_rfp_control_nack_reason_coding {
	DECT_MITEL_RFP_CONTROL_NACK_REASON_OK                  = 0x04000000,
	DECT_MITEL_RFP_CONTROL_NACK_REASON_INVALID_ELEMENT     = 0x04000001,
	DECT_MITEL_RFP_CONTROL_NACK_REASON_NO_RESOURCE         = 0x04000002,
	DECT_MITEL_RFP_CONTROL_NACK_REASON_WRONG_STATE         = 0x04000003,
	DECT_MITEL_RFP_CONTROL_NACK_REASON_INVALID_PARAMETERS  = 0x04000004,
	DECT_MITEL_RFP_CONTROL_NACK_REASON_PORT_IN_USE         = 0x04000005,
	DECT_MITEL_RFP_CONTROL_NACK_REASON_CODEC_NOT_SUPPORTED = 0x04000006,
	DECT_MITEL_RFP_CONTROL_NACK_REASON_VIDEO_NOT_SUPPORTED = 0x04000007,
};

/* SYS-LED */
enum dect_mitel_rfp_sys_led_color_coding {
	DECT_MITEL_RFP_SYS_LED_COLOR_OFF                = 0x00,
	DECT_MITEL_RFP_SYS_LED_COLOR_STEADY_GREEN       = 0x01,
	DECT_MITEL_RFP_SYS_LED_COLOR_FLASH_GREEN        = 0x02,
	DECT_MITEL_RFP_SYS_LED_COLOR_FLASH_GREEN_ORANGE = 0x03,
	DECT_MITEL_RFP_SYS_LED_COLOR_FLASH_GREEN_RED    = 0x04,
	DECT_MITEL_RFP_SYS_LED_COLOR_STEADY_RED         = 0x05,
	DECT_MITEL_RFP_SYS_LED_COLOR_STEADY_ORANGE      = 0x06,
	DECT_MITEL_RFP_SYS_LED_COLOR_CYCLE_GREEN_RED    = 0x07,
};

/* SYS-INIT */
enum dect_mitel_rfp_sys_init_rfp_model_coding {
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP31    = 0x0001,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP33    = 0x0002,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP41    = 0x0003,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP32    = 0x0004,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP32US  = 0x0005,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP34    = 0x0006,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP34US  = 0x0007,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP42    = 0x0008,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP42US  = 0x0009,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP35    = 0x000b,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP36    = 0x000c,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP43    = 0x000d,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP37    = 0x000e,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP44    = 0x0010,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP45    = 0x0011,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP47    = 0x0012,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP48    = 0x0013,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_PC_ECM   = 0x0014,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_PC       = 0x0015,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPL31   = 0x1001,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPL33   = 0x1002,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPL41   = 0x1003,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPL32US = 0x1005,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPL34   = 0x1006,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPL34US = 0x1007,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPL42   = 0x1008,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPL42US = 0x1009,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPL35   = 0x100B,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPL36   = 0x100C,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPL43   = 0x100D,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPL37   = 0x100E,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPSL35  = 0x200B,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPSL36  = 0x200C,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPSL43  = 0x200D,
	DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPSL37  = 0x200E,
};

enum dect_mitel_rfp_sys_init_rfp_capability_coding {
	DECT_MITEL_RFP_SYS_INIT_RFP_CAPABILITY_NORMAL_TX        = 0x00000008,
	DECT_MITEL_RFP_SYS_INIT_RFP_CAPABILITY_INDOOR           = 0x00000010,
	DECT_MITEL_RFP_SYS_INIT_RFP_CAPABILITY_WLAN             = 0x00000020,
	DECT_MITEL_RFP_SYS_INIT_RFP_CAPABILITY_ENCRYPTION       = 0x00000100,
	DECT_MITEL_RFP_SYS_INIT_RFP_CAPABILITY_FREQUENCY_SHIFT  = 0x00000200,
	DECT_MITEL_RFP_SYS_INIT_RFP_CAPABILITY_LOW_TX           = 0x00000400,
	DECT_MITEL_RFP_SYS_INIT_RFP_CAPABILITY_ADVANCED_FEATURE = 0x00008000,
};

/* MEDIA */
enum dect_mitel_rfp_media_direction_coding {
	DECT_MITEL_RFP_MEDIA_DIRECTION_NONE = 0x0,
	DECT_MITEL_RFP_MEDIA_DIRECTION_RX   = 0x1,
	DECT_MITEL_RFP_MEDIA_DIRECTION_TX   = 0x2,
	DECT_MITEL_RFP_MEDIA_DIRECTION_RXTX = 0x3,
};

/* MEDIA-CONF */
enum dect_mitel_rfp_media_conf_codec_type_coding {
	DECT_MITEL_RFP_MEDIA_CONF_CODEC_TYPE_G711_A    = 0x0,
	DECT_MITEL_RFP_MEDIA_CONF_CODEC_TYPE_G723_1_53 = 0x1,
	DECT_MITEL_RFP_MEDIA_CONF_CODEC_TYPE_G723_1_63 = 0x2,
	DECT_MITEL_RFP_MEDIA_CONF_CODEC_TYPE_G729      = 0x3,
	DECT_MITEL_RFP_MEDIA_CONF_CODEC_TYPE_G711_U    = 0x4,
};

/* SYNC */
enum dect_mitel_rfp_sync_payload_type_coding {
	DECT_MITEL_RFP_SYNC_TYPE_GET_REQ_RSSI_COMP_IND    = 0x7d0e,
	DECT_MITEL_RFP_SYNC_TYPE_GET_REQ_RSSI_COMP_CFM    = 0x7d0f,
	DECT_MITEL_RFP_SYNC_TYPE_FREQ_CTRL_MODE_IND       = 0x7d15,
	DECT_MITEL_RFP_SYNC_TYPE_FREQ_CTRL_MODE_CFM       = 0x7d16,
	DECT_MITEL_RFP_SYNC_TYPE_PHASE_OFFSET_IND         = 0x7d17,
	DECT_MITEL_RFP_SYNC_TYPE_SET_FREQUENCY            = 0x7d18,
	DECT_MITEL_RFP_SYNC_TYPE_SET_REPORT_LIMIT         = 0x7d1a,
	DECT_MITEL_RFP_SYNC_TYPE_RESET_MAC_IND            = 0x7d1b,
	DECT_MITEL_RFP_SYNC_TYPE_START_MAC_MASTER_IND     = 0x7d1c,
	DECT_MITEL_RFP_SYNC_TYPE_START_MAC_SLAVE_MODE_IND = 0x7d1d,
	DECT_MITEL_RFP_SYNC_TYPE_SYSTEM_SEARCH_IND        = 0x7d1e,
	DECT_MITEL_RFP_SYNC_TYPE_SYSTEM_SEARCH_CFM        = 0x7d1f,
	DECT_MITEL_RFP_SYNC_TYPE_MAC_STARTED_IND          = 0x7d20,
	DECT_MITEL_RFP_SYNC_TYPE_RESET_MAC_CFM            = 0x7d21,
	DECT_MITEL_RFP_SYNC_TYPE_START_MAC_MASTER_CFM     = 0x7d22,
	DECT_MITEL_RFP_SYNC_TYPE_START_MAC_MASTER_REJ     = 0x7d23,
	DECT_MITEL_RFP_SYNC_TYPE_START_MAC_SLAVE_MODE_CFM = 0x7d24,
	DECT_MITEL_RFP_SYNC_TYPE_START_MAC_SLAVE_REJ      = 0x7d25,
	DECT_MITEL_RFP_SYNC_TYPE_SYSTEM_SEARCH_REJ        = 0x7d26,
	DECT_MITEL_RFP_SYNC_TYPE_READY_FOR_SYNC_IND       = 0x7d27,
	DECT_MITEL_RFP_SYNC_TYPE_GET_ACTIVE_CHANNEL_CFM   = 0x7d29,
	DECT_MITEL_RFP_SYNC_TYPE_PHASE_OFS_WITH_RSSI_IND  = 0x7d2c,
	DECT_MITEL_RFP_SYNC_TYPE_RESET_MAC_IF_IDLE_CFM    = 0x7d2f,
	DECT_MITEL_RFP_SYNC_TYPE_UNKNOWN_READY_FOR_SYNC   = 0x7d32,
	DECT_MITEL_RFP_SYNC_TYPE_UNKNOWN_STANDBY          = 0x7d33,
};

/* Message Type */
static const value_string dect_mitel_rfp_message_type_val[] = {
	{ DECT_MITEL_RFP_MESSAGE_TYPE_CONTROL_ACK,                  "CONTROL-ACK" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_CONTROL_NACK,                 "CONTROL-NACK" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_CONTROL_HEARTBEAT,            "CONTROL-HEARTBEAT" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_IP_OPTIONS,               "SYS-IP-OPTIONS" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_LED,                      "SYS-LED" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_SPY,                      "SYS-SPY" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_HEARTBEAT_INTERVAL,       "SYS-HEARTBEAT-INTERVAL" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_RSX,                      "SYS-RSX" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_SYSLOG,                   "SYS-SYSLOG" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_MAX_CHANNELS,             "SYS-MAX-CHANNELS" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_HTTP_SET,                 "SYS-HTTP-SET" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_PASSWD,                   "SYS-PASSWD" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_CRYPTED_PACKET,           "SYS-CRYPTED-PACKET" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_OMM_CONTROL,              "SYS-OMM-CONTROL" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_STATE_DUMP,               "SYS-STATE-DUMP" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_RPING,                    "SYS-RPING" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_STATE_DUMP_REQ,           "SYS-STATE-DUMP-REQ" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_STATE_DUMP_RES,           "SYS-STATE-DUMP-RES" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_NEW_SW,                   "SYS-NEW-SW" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_AUDIO_LOG,                "SYS-AUDIO-LOG" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_USB_OVERLOAD,             "SYS-USB-OVERLOAD" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_SW_CONTAINER,             "SYS-SW-CONTAINER" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_CORE_DUMP,                "SYS-CORE-DUMP" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_VSNTP_TIME,               "SYS-VSNTP-TIME" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_UPDATE_802_1X_SUPPLICANT, "SYS-UPDATE-802-1X-SUPPLICANT" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_INIT,                     "SYS-INIT" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_RESET,                    "SYS-RESET" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_SUPPLICANT_MD5,           "SYS-SUPPLICANT-MD5" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_STREAM_INFO,              "SYS-STREAM-INFO" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_RFP_AUTH_KEY,             "SYS-RFP-AUTH-KEY" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_RFP_RE_ENROLEMENT,        "SYS-RFP-RE-ENROLEMENT" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_ENCRYPTION_CONF,          "SYS-ENCRYPTION-CONF" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_AUTHENTICATE,             "SYS-AUTHENTICATE" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYS_LICENSE_TIMER,            "SYS-LICENSE-TIMER" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_OPEN,                   "MEDIA-OPEN" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_CONF,                   "MEDIA-CONF" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_CLOSE,                  "MEDIA-CLOSE" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_START,                  "MEDIA-START" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_STOP,                   "MEDIA-STOP" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_STATISTICS,             "MEDIA-STATISTICS" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_REDIRECT_START,         "MEDIA-REDIRECT-START" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_REDIRECT_STOP,          "MEDIA-REDIRECT-STOP" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_RESTART,                "MEDIA-RESTART" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_DTMF,                   "MEDIA-DTMF" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_DSP_CLOSE,              "MEDIA-DSP-CLOSE" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_TONE,                   "MEDIA-TONE" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_BANDWIDTH_SWO,          "MEDIA-BANDWIDTH-SWO" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_MUTE,                   "MEDIA-MUTE" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_G729_USED,              "MEDIA-G729-USED" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_TRACE_PPN,              "MEDIA-TRACE-PPN" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_EOS_DETECT,             "MEDIA-EOS-DETECT" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_AUDIO_STATISTICS,       "MEDIA-AUDIO-STATISTICS" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_VIDEO_STATE,            "MEDIA-VIDEO-STATE" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_CHANNEL_MOD_INFO,       "MEDIA-CHANNEL-MOD-INFO" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_ETH,                          "DECToE" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SYNC,                         "SYNC" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_WLAN_RFP_CONFIG,              "WLAN-RFP-CONFIG" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_WLAN_RFP_UP,                  "WLAN-RFP-UP" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_WLAN_RFP_DOWN,                "WLAN-RFP-DOWN" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_WLAN_RFP_CLIENT_REQ,          "WLAN-RFP-CLIENT-REQ" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_WLAN_RFP_CLIENT_REP,          "WLAN-RFP-CLIENT-REP" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_WLAN_RFP_SET_ACL,             "WLAN-RFP-SET-ACL" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_WLAN_RFP_CLIENT_INFO,         "WLAN-RFP-CLIENT-INFO" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_WLAN_RFP_ACK,                 "WLAN-RFP-ACK" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_WLAN_RFP_LINK_NOK_NACK,       "WLAN-RFP-LINK-NON-NACK" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_WLAN_RFP_IFACE_REP,           "WLAN-RFP-IFACE-REP" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_SNMP_RFP_UPDATE,              "SNMP-RFP-UPDATE" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_CONF_OPEN,                    "CONF-OPEN" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_CONF_ADD_SUBSCR,              "CONF-ADD-SUBSCR" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_CONF_CHG_SUBSCR,              "CONF-CHG-SUBSCR" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_CONF_DEL_SUBSCR,              "CONF-DEL-SUBSCR" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_CONF_CLOSE,                   "CONF-CLOSE" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_CONF_RTP,                     "CONF-RTP" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_BLUETOOTH_DEVICE,             "BLUETOOTH-DEVICE" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_BLUETOOTH_CONFIG,             "BLUETOOTH-CONFIG" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_BLUETOOTH_DATA,               "BLUETOOTH-DATA" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_VIDEO_DEVICE,                 "VIDEO-DEVICE" },
	{ DECT_MITEL_RFP_MESSAGE_TYPE_VIDEO_CONFIG,                 "VIDEO-CONFIG" },
	{ 0, NULL }
};

/* CONTROL-NACK */
static const value_string dect_mitel_rfp_control_nack_reason_val[] = {
	{ DECT_MITEL_RFP_CONTROL_NACK_REASON_OK,                  "OK" },
	{ DECT_MITEL_RFP_CONTROL_NACK_REASON_INVALID_ELEMENT,     "Invalid element" },
	{ DECT_MITEL_RFP_CONTROL_NACK_REASON_NO_RESOURCE,         "No resource" },
	{ DECT_MITEL_RFP_CONTROL_NACK_REASON_WRONG_STATE,         "Wrong state" },
	{ DECT_MITEL_RFP_CONTROL_NACK_REASON_INVALID_PARAMETERS,  "Invalid parameters" },
	{ DECT_MITEL_RFP_CONTROL_NACK_REASON_PORT_IN_USE,         "Port in use" },
	{ DECT_MITEL_RFP_CONTROL_NACK_REASON_CODEC_NOT_SUPPORTED, "Codec not supported" },
	{ DECT_MITEL_RFP_CONTROL_NACK_REASON_VIDEO_NOT_SUPPORTED, "Video not supported" },
	{ 0, NULL }
};

/* SYS-LED */
static const value_string dect_mitel_rfp_sys_led_color_val[] = {
	{ DECT_MITEL_RFP_SYS_LED_COLOR_OFF,                "Off" },
	{ DECT_MITEL_RFP_SYS_LED_COLOR_STEADY_GREEN,       "Steady green" },
	{ DECT_MITEL_RFP_SYS_LED_COLOR_FLASH_GREEN,        "Flash green" },
	{ DECT_MITEL_RFP_SYS_LED_COLOR_FLASH_GREEN_ORANGE, "Flash green-orange" },
	{ DECT_MITEL_RFP_SYS_LED_COLOR_FLASH_GREEN_RED,    "Flash green-red" },
	{ DECT_MITEL_RFP_SYS_LED_COLOR_STEADY_RED,         "Steady red" },
	{ DECT_MITEL_RFP_SYS_LED_COLOR_STEADY_ORANGE,      "Steady orange" },
	{ DECT_MITEL_RFP_SYS_LED_COLOR_CYCLE_GREEN_RED,    "Cycle green-red" },
	{ 0, NULL }
};

/* SYS-INIT */
static const value_string dect_mitel_rfp_sys_init_rfp_model_val[] = {
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP31,    "RFP 31" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP33,    "RFP 33" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP41,    "RFP 41" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP32,    "RFP 32" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP32US,  "RFP 32 (US Version)" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP34,    "RFP 34" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP34US,  "RFP 34 (US Version)" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP42,    "RFP 42" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP42US,  "RFP 42 (US Version)" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP35,    "RFP 35" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP36,    "RFP 36" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP43,    "RFP 43" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP37,    "RFP 37" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP44,    "RFP 44" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP45,    "RFP 45" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP47,    "RFP 47" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFP48,    "RFP 48" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_PC_ECM,   "PC-ECM" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_PC,       "PC" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPL31,   "RFP L31" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPL33,   "RFP L33" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPL41,   "RFP L41" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPL32US, "RFP L32 (US Version)" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPL34,   "RFP L34" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPL34US, "RFP L34 (US Version)" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPL42,   "RFP L42" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPL42US, "RFP L42 (US Version)" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPL35,   "RFP L35" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPL36,   "RFP L36" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPL43,   "RFP L43" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPL37,   "RFP L37" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPSL35,  "RFP SL35" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPSL36,  "RFP SL36" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPSL43,  "RFP SL43" },
	{ DECT_MITEL_RFP_SYS_INIT_RFP_MODEL_RFPSL37,  "RFP SL37" },
	{ 0, NULL }
};

/* MEDIA */
static const value_string dect_mitel_rfp_media_direction_val[] = {
	{ DECT_MITEL_RFP_MEDIA_DIRECTION_NONE, "None" },
	{ DECT_MITEL_RFP_MEDIA_DIRECTION_RX,   "RX" },
	{ DECT_MITEL_RFP_MEDIA_DIRECTION_TX,   "TX" },
	{ DECT_MITEL_RFP_MEDIA_DIRECTION_RXTX, "RX+TX" },
	{ 0, NULL }
};

/* MEDIA-CONF */
static const value_string dect_mitel_rfp_media_conf_codec_type_val[] = {
	{ DECT_MITEL_RFP_MEDIA_CONF_CODEC_TYPE_G711_A,    "G.711 alaw" },
	{ DECT_MITEL_RFP_MEDIA_CONF_CODEC_TYPE_G723_1_53, "G.723 5.3kbit/s" },
	{ DECT_MITEL_RFP_MEDIA_CONF_CODEC_TYPE_G723_1_63, "G.723 6.3kbit/s" },
	{ DECT_MITEL_RFP_MEDIA_CONF_CODEC_TYPE_G729,      "G.729" },
	{ DECT_MITEL_RFP_MEDIA_CONF_CODEC_TYPE_G711_U,    "G.711 ulaw" },
	{ 0, NULL }
};

/* SYNC */
static const value_string dect_mitel_rfp_sync_payload_type_val[] = {
	{ DECT_MITEL_RFP_SYNC_TYPE_GET_REQ_RSSI_COMP_IND,    "GET_REQ_RSSI_COMP_IND" },
	{ DECT_MITEL_RFP_SYNC_TYPE_GET_REQ_RSSI_COMP_CFM,    "GET_REQ_RSSI_COMP_CFM" },
	{ DECT_MITEL_RFP_SYNC_TYPE_FREQ_CTRL_MODE_IND,       "FREQ_CTRL_MODE_IND" },
	{ DECT_MITEL_RFP_SYNC_TYPE_FREQ_CTRL_MODE_CFM,       "FREQ_CTRL_MODE_CFM" },
	{ DECT_MITEL_RFP_SYNC_TYPE_PHASE_OFFSET_IND,         "PHASE_OFFSET_IND" },
	{ DECT_MITEL_RFP_SYNC_TYPE_SET_FREQUENCY,            "SET_FREQUENCY" },
	{ DECT_MITEL_RFP_SYNC_TYPE_SET_REPORT_LIMIT,         "SET_REPORT_LIMIT" },
	{ DECT_MITEL_RFP_SYNC_TYPE_RESET_MAC_IND,            "RESET_MAC_IND" },
	{ DECT_MITEL_RFP_SYNC_TYPE_START_MAC_MASTER_IND,     "START_MAC_MASTER_IND" },
	{ DECT_MITEL_RFP_SYNC_TYPE_START_MAC_SLAVE_MODE_IND, "START_MAC_SLAVE_MODE_IND" },
	{ DECT_MITEL_RFP_SYNC_TYPE_SYSTEM_SEARCH_IND,        "SYSTEM_SEARCH_IND" },
	{ DECT_MITEL_RFP_SYNC_TYPE_SYSTEM_SEARCH_CFM,        "SYSTEM_SEARCH_CFM" },
	{ DECT_MITEL_RFP_SYNC_TYPE_MAC_STARTED_IND,          "MAC_STARTED_IND" },
	{ DECT_MITEL_RFP_SYNC_TYPE_RESET_MAC_CFM,            "RESET_MAC_CFM" },
	{ DECT_MITEL_RFP_SYNC_TYPE_START_MAC_MASTER_CFM,     "START_MAC_MASTER_CFM" },
	{ DECT_MITEL_RFP_SYNC_TYPE_START_MAC_MASTER_REJ,     "START_MAC_MASTER_REJ" },
	{ DECT_MITEL_RFP_SYNC_TYPE_START_MAC_SLAVE_MODE_CFM, "START_MAC_SLAVE_MODE_CFM" },
	{ DECT_MITEL_RFP_SYNC_TYPE_START_MAC_SLAVE_REJ,      "START_MAC_SLAVE_REJ" },
	{ DECT_MITEL_RFP_SYNC_TYPE_SYSTEM_SEARCH_REJ,        "SYSTEM_SEARCH_REJ" },
	{ DECT_MITEL_RFP_SYNC_TYPE_READY_FOR_SYNC_IND,       "READY_FOR_SYNC_IND" },
	{ DECT_MITEL_RFP_SYNC_TYPE_GET_ACTIVE_CHANNEL_CFM,   "GET_ACTIVE_CHANNEL_CFM" },
	{ DECT_MITEL_RFP_SYNC_TYPE_PHASE_OFS_WITH_RSSI_IND,  "PHASE_OFS_WITH_RSSI_IND" },
	{ DECT_MITEL_RFP_SYNC_TYPE_RESET_MAC_IF_IDLE_CFM,    "RESET_MAC_IF_IDLE_CFM" },
	{ DECT_MITEL_RFP_SYNC_TYPE_UNKNOWN_READY_FOR_SYNC,   "UNKNOWN_READY_FOR_SYNC" },
	{ DECT_MITEL_RFP_SYNC_TYPE_UNKNOWN_STANDBY,          "UNKNOWN_STANDBY" },
	{ 0, NULL }
};

static dissector_handle_t dect_mitel_rfp_handle;
static dissector_handle_t dect_mitel_eth_handle;

/* Preferences */
#define DECT_MITEL_RFP_TCP_PORT 16321
static unsigned tcp_port_pref = DECT_MITEL_RFP_TCP_PORT;

/* Initialize the subtree pointers */
static int ett_dect_mitel_rfp;
static int ett_dect_mitel_rfp_sys_init_rfp_capabilities;
static int ett_dect_mitel_rfp_media_tone_entry;
static int ett_dect_mitel_rfp_sync_system_search_cfm_item;
static int ett_dect_mitel_rfp_sync_phase_ofs_with_rssi_ind_item;

/*
CONTROL-ACK Message
| Offset | Len | Content |
| ------ | --- | ------- |
|      0 |   2 | Message |
|      2 |   2 | Call ID |
 */
static unsigned dissect_dect_mitel_rfp_control_ack(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_rfp_control_ack_message, tvb, offset, 2, ENC_NA);
	offset += 2;
	proto_tree_add_item(tree, hf_dect_mitel_rfp_control_ack_call_id, tvb, offset, 2, ENC_NA);
	offset += 2;
	return offset;
}

/*
CONTROL-NACK Message
| Offset | Len | Content       |
| ------ | --- | ------------- |
|      0 |   2 | Message       |
|      2 |   2 | Call ID       |
|      4 |   4 | Reject resaon |
 */
static unsigned dissect_dect_mitel_rfp_control_nack(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_rfp_control_nack_message, tvb, offset, 2, ENC_NA);
	offset += 2;
	proto_tree_add_item(tree, hf_dect_mitel_rfp_control_nack_call_id, tvb, offset, 2, ENC_NA);
	offset += 2;
	proto_tree_add_item(tree, hf_dect_mitel_rfp_control_nack_reason, tvb, offset, 4, ENC_NA);
	offset += 4;
	return offset;
}

/*
CONTROL-HEARTBEAT Message
| Offset | Len | Content             |
| ------ | --- | ------------------- |
|      0 |   4 | Uptime milliseconds |
|      4 |   4 | Uptime nanoseconds  |
 */
static unsigned dissect_dect_mitel_rfp_control_heartbeat(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_rfp_control_heartbeat_milliseconds, tvb, offset, 4, ENC_NA);
	offset += 4;
	proto_tree_add_item(tree, hf_dect_mitel_rfp_control_heartbeat_nanoseconds, tvb, offset, 4, ENC_NA);
	offset += 4;
	return offset;
}

/*
SYS-IP-OPTIONS Message
| Offset | Len | Content                     |
| ------ | --- | --------------------------- |
|      0 |   1 | Voice Type of Service (ToS) |
|      1 |   1 | Signalling ToS              |
|      2 |   1 | TTL                         |
|      3 |   1 | Signal VLAN priority        |
|      4 |   1 | Voice VLAN priority         |
 */
static unsigned dissect_dect_mitel_rfp_sys_ip_options(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_ip_options_voice_tos, tvb, offset, 1, ENC_NA);
	offset++;
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_ip_options_signalling_tos, tvb, offset, 1, ENC_NA);
	offset++;
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_ip_options_ttl, tvb, offset, 1, ENC_NA);
	offset++;
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_ip_options_signal_vlan_priority, tvb, offset, 1, ENC_NA);
	offset++;
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_ip_options_voice_vlan_priority, tvb, offset, 1, ENC_NA);
	offset++;
	return offset;
}

/*
SYS-LED Message
| Offset | Len | Content     |
| ------ | --- | ----------- |
|      0 |   1 | LED ID      |
|      1 |   1 | LED Colour  |
*/
static unsigned dissect_dect_mitel_rfp_sys_led(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	uint8_t led_id, led_color;
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_led_id, tvb, offset, 1, ENC_NA);
	led_id = tvb_get_uint8(tvb, offset);
	offset++;
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_led_color, tvb, offset, 1, ENC_NA);
	led_color = tvb_get_uint8(tvb, offset);
	offset++;
	col_append_fstr(pinfo->cinfo, COL_INFO, "LED %d:%s", led_id,
		val_to_str(led_color, dect_mitel_rfp_sys_led_color_val, "Unknown: %02x"));
	return offset;
}

/*
SYS-HEARTBEAT-INTERVAL Message
| Offset | Len | Content            |
| ------ | --- | ------------------ |
|      0 |   1 | Interval value (s) |
*/
static unsigned dissect_dect_mitel_rfp_sys_heartbeat_interval(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	uint8_t interval;
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_heartbeat_interval_value, tvb, offset, 1, ENC_BIG_ENDIAN);
	interval = tvb_get_uint8(tvb, offset);
	col_append_fstr(pinfo->cinfo, COL_INFO, "Interval: %ds", interval);
	offset++;

	return offset;
}

/*
SYS-SYSLOG Message
| Offset | Len | Content            |
| ------ | --- | ------------------ |
|      0 |  16 | IP Address         |
|     16 |   2 | Port               |
*/
static unsigned dissect_dect_mitel_rfp_sys_syslog(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_syslog_ip_address, tvb, offset, 16, ENC_NA);
	offset += 16;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_syslog_port, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	return offset;
}

/*
SYS-MAX-CHANNELS Message
| Offset | Len | Content   |
| ------ | --- | --------- |
|      0 |   1 | DSP       |
|      1 |   1 | Sesseions |
*/
static unsigned dissect_dect_mitel_rfp_sys_max_channels(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_max_channels_dsp, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_max_channels_sessions, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	return offset;
}

/*
SYS-HTTP-SET Message
| Offset | Len | Content            |
| ------ | --- | ------------------ |
|      0 |  16 | IP Address         |
|     16 |   2 | Port               |
*/
static unsigned dissect_dect_mitel_rfp_sys_http_set(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_http_set_ip_address, tvb, offset, 16, ENC_NA);
	offset += 16;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_http_set_port, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	return offset;
}

/*
SYS-PASSWD Message
| Offset | Len | Content                     |
| ------ | --- | --------------------------- |
|      0 |   1 | Remote Access Enabled (0x1) |
|      2 |  65 | Root username               |
|     67 |  65 | Root password               |
|    132 |  65 | Admin username              |
|    197 |  65 | Admin password              |
*/
static unsigned dissect_dect_mitel_rfp_sys_passwd(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_passwd_remote_access_enabled, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_passwd_root_username, tvb, offset, 65, ENC_ASCII);
	offset += 65;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_passwd_root_password, tvb, offset, 65, ENC_ASCII);
	offset += 65;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_passwd_admin_username, tvb, offset, 65, ENC_ASCII);
	offset += 65;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_passwd_admin_password, tvb, offset, 65, ENC_ASCII);
	offset += 65;

	return offset;
}

/*
SYS-RPING Message
| Offset | Len | Content    |
| ------ | --- | ---------- |
|      0 |  16 | IP Address |
|     16 |   4 | RTT (ms)   |
*/
static unsigned dissect_dect_mitel_rfp_sys_rping(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_rping_ip_address, tvb, offset, 16, ENC_NA);
	offset += 16;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_rping_rtt, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	return offset;
}

/*
SYS-CORE-DUMP Message
| Offset | Len | Content |
| ------ | --- | ------- |
|      0 | len | URL     |
*/
static unsigned dissect_dect_mitel_rfp_sys_core_dump(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset, uint16_t message_length)
{
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_core_dump_url, tvb, offset, message_length, ENC_ASCII);
	offset += message_length;

	return offset;
}

/*
SYS-VSNTP-TIME Message
| Offset | Len | Content        |
| ------ | --- | -------------- |
|      0 |   4 | T1 seconds     |
|      4 |   4 | T1 nanoseconds |
|      8 |   4 | T2 seconds     |
|     12 |   4 | T2 nanoseconds |
*/
static unsigned dissect_dect_mitel_rfp_sys_vsntp_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_vsntp_time_t1_seconds, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_vsntp_time_t1_nanoseconds, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_vsntp_time_t2_seconds, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_vsntp_time_t2_nanoseconds, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	return offset;
}

/*
SYS-INIT Message
| Offset | Len | Content           |
| ------ | --- | ----------------- |
|      0 |   4 | Model Type        |
|      8 |   6 | MAC Address       |
|     20 |   4 | Capabilities      |
|     24 |  64 | AES enrypted Data |
|     88 |   4 | Protocol          |
|    112 |  32 | Software Version  |
|    256 |  16 | Signature         |
 */
static unsigned dissect_dect_mitel_rfp_sys_init(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	static int *const capabilities_flags [] = {
		&hf_dect_mitel_rfp_sys_init_rfp_capability_normal_tx,
		&hf_dect_mitel_rfp_sys_init_rfp_capability_indoor,
		&hf_dect_mitel_rfp_sys_init_rfp_capability_wlan,
		&hf_dect_mitel_rfp_sys_init_rfp_capability_encryption,
		&hf_dect_mitel_rfp_sys_init_rfp_capability_frequency_shift,
		&hf_dect_mitel_rfp_sys_init_rfp_capability_low_tx,
		&hf_dect_mitel_rfp_sys_init_rfp_capability_advanced_feature,
		NULL
	};

	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_init_rfp_model, tvb, offset, 4, ENC_NA);
	offset += 8;
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_init_rfp_mac, tvb, offset, 6, ENC_NA);
	offset += 12;
	proto_tree_add_bitmask(tree, tvb, offset, hf_dect_mitel_rfp_sys_init_rfp_capabilities, ett_dect_mitel_rfp_sys_init_rfp_capabilities, capabilities_flags, ENC_NA);
	offset += 4;
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_init_crypted, tvb, offset, 64, ENC_NA);
	offset += 64;
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_init_protocol, tvb, offset, 4, ENC_NA);
	offset += 24;
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_init_rfp_software_version, tvb, offset, 32, ENC_ASCII);
	offset += 144;
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_init_signature, tvb, offset, 16, ENC_NA);
	offset += 16;
	return offset;
}

/*
SYS-AUTHENTICATE Message
| Offset | Len | Content         |
| ------ | --- | --------------- |
|      7 |   8 | RFP Blowfish IV |
|     21 |   8 | OMM Blowfish IV |
*/
static unsigned dissect_dect_mitel_rfp_sys_authenticate(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	offset += 7;
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_authenticate_rfp_iv, tvb, offset, 8, ENC_NA);
	offset += 16;
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_authenticate_omm_iv, tvb, offset, 8, ENC_NA);
	offset += 8;
	return offset;
}

/*
SYS-LICENSE-TIMER Message
| Offset | Len | Content          | Comment                              |
| ------ | --- | ---------------- | ------------------------------------ |
|      0 |   4 | Grace period (m) | Most significant bit indicates QUERY |
|      4 |  16 | Checksum         |                                      |
*/
static unsigned dissect_dect_mitel_rfp_sys_license_timer(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_license_timer_query, tvb, offset, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_license_timer_grace_period, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_license_timer_checksum, tvb, offset, 16, ENC_NA);
	offset += 16;

	return offset;
}

/*
MEDIA-OPEN Message
| Offset | Len | Content    |
| ------ | --- | ---------- |
|      0 |   1 | Codec      |
|      1 |   1 | Slot count |
|      2 |   4 | Flags      |
*/
static unsigned dissect_dect_mitel_rfp_media_open(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_open_codec, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_open_slot_count, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_open_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset+=4;

	return offset;
}

/*
MEDIA-CONF Message
| Offset | Len | Content       |
| ------ | --- | ------------- |
|      2 |   1 | Vif           |
|      3 |   1 | VAD           |
|      4 |   1 | Codec count   |
|      5 |   1 | Codec 1 Type  |
|      6 |   1 | Codec 1 Pt    |
|      7 |   1 | Codec 1 Rate  |
|     .. | ..  | ...           |
|     56 |   1 | MCEI          |
|     58 |   2 | PPN           |
|     64 |   2 | Local port 1  |
|     66 |   2 | Local port 2  |
|     70 |   4 | RX IP address |
|     74 |   2 | RX port 1     |
|     76 |   2 | RX port 2     |
|     78 |   4 | TX IP address |
|     82 |   2 | TX port 1     |
|     84 |   2 | TX port 2     |
*/
static unsigned dissect_dect_mitel_rfp_media_conf(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	uint32_t codec_count;
	unsigned mcei_offset;
	mcei_offset = offset + 56;
	offset += 2;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_conf_vif, tvb, offset, 1,ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_conf_vad, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item_ret_uint(tree, hf_dect_mitel_rfp_media_conf_codec_count, tvb, offset, 1, ENC_BIG_ENDIAN, &codec_count);
	offset++;

	for (uint32_t i = 0; i < codec_count && offset < mcei_offset; i++) {
		proto_tree_add_item(tree, hf_dect_mitel_rfp_media_conf_codec_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		proto_tree_add_item(tree, hf_dect_mitel_rfp_media_conf_codec_pt, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		proto_tree_add_item(tree, hf_dect_mitel_rfp_media_conf_codec_rate, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	offset = mcei_offset;
	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_mcei, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_conf_ppn, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 6;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_conf_local_port_1, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_conf_local_port_2, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_conf_rx_ip_address, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_conf_rx_port_1, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_conf_rx_port_2, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_conf_tx_ip_address, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_conf_tx_port_1, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_conf_tx_port_2, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	return offset;
}

/*
MEDIA-START Message
| Offset | Len | Content       |
| ------ | --- | ------------- |
|      0 |   1 | Direction     |
|      2 |   4 | Time          |
|      6 |   1 | Met keepalive |
*/
static unsigned dissect_dect_mitel_rfp_media_start(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_direction, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_start_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_start_met_keep_alive, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	return offset;
}

/*
MEDIA-STOP Message
| Offset | Len | Content       |
| ------ | --- | ------------- |
|      0 |   1 | Direction     |
*/
static unsigned dissect_dect_mitel_rfp_media_stop(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_direction, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	return offset;
}

/*
MEDIA-STATISTICS Message
| Offset | Len | Content        |
| ------ | --- | -------------- |
|      2 |   4 | Duration       |
|      6 |   4 | TX packets     |
|     10 |   4 | TX bytes       |
|     14 |   4 | RX packets     |
|     18 |   4 | RX bytes       |
|     22 |   4 | Lost packets   |
|     26 |   4 | Max jitter     |
|     30 |   4 | RTP IP address |
*/
static unsigned dissect_dect_mitel_rfp_media_statistics(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_statistics_duration, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_statistics_tx_packets, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_statistics_tx_bytes, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_statistics_rx_packets, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_statistics_rx_bytes, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_statistics_lost_packets, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_statistics_max_jitter, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_statistics_rtp_ip_address, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	return offset;
}

/*
MEDIA-REDIRECT-START Message
| Offset | Len | Content            |
| ------ | --- | ------------------ |
|      2 |   2 | Local port 1       |
|      4 |   2 | Local port 2       |
|      6 |   4 | Remote IP address  |
|     10 |   2 | Remote port 1      |
|     12 |   2 | Remote port 2      |
|     14 |   4 | Time               |
*/
static unsigned dissect_dect_mitel_rfp_media_redirect_start(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	offset += 2;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_redirect_start_local_port_1, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_redirect_start_local_port_2, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_redirect_start_remote_ip_address, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_redirect_start_remote_port_1, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_redirect_start_remote_port_2, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_redirect_start_time, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	return offset;
}

/*
MEDIA-REDIRECT-STOP Message
| Offset | Len | Content       |
| ------ | --- | ------------- |
|      0 |   1 | Fallback      |
*/
static unsigned dissect_dect_mitel_rfp_media_redirect_stop(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_redirect_stop_fallback, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	return offset;
}

/*
MEDIA-RESTART Message
| Offset | Len | Content |
| ------ | --- | ------- |
|      0 |   1 | MCEI    |
*/
static unsigned dissect_dect_mitel_rfp_media_restart(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_mcei, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	return offset;
}

/*
MEDIA-DTMF Message
| Offset | Len | Content   |
| ------ | --- | --------- |
|      0 |   2 | Duration  |
|      2 |   1 | Key       |
|      3 |   1 | Direction |
*/
static unsigned dissect_dect_mitel_rfp_media_dtmf(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_dtmf_duration, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_dtmf_key, tvb, offset, 1, ENC_ASCII_7BITS);
	offset++;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_direction, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	return offset;
}

/*
MEDIA-TONE Message
| Offset | Len | Content   |
| ------ | --- | --------- |
|      0 |   1 | Direction |
|      1 |   1 | Count     |
|      6 |  24 | Tone 0    |
| ...    | ... | ...       |
| 6+24*n |  24 | Tone n    |

Tone:
| Offset | Len | Content     |
| ------ | --- | ----------- |
|      0 |   2 | Frequency 1 |
|      2 |   2 | Frequency 2 |
|      4 |   2 | Frequency 3 |
|      6 |   2 | Frequency 4 |
|      8 |   2 | cB 1        |
|     10 |   2 | cB 2        |
|     12 |   2 | cB 3        |
|     14 |   2 | cB 4        |
|     16 |   2 | Duration    |
|     18 |   2 | Cycle count |
|     20 |   2 | Cycle to    |
|     22 |   2 | Next        |
*/
static unsigned dissect_dect_mitel_rfp_media_tone(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	uint8_t tone_count;
	proto_tree *tone_tree;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_direction, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_tone_count, tvb, offset, 1, ENC_BIG_ENDIAN);
	tone_count = tvb_get_uint8(tvb, offset);
	offset += 5;

	for (uint8_t i = 0; i < tone_count; i++) {
		tone_tree = proto_tree_add_subtree(tree, tvb, offset, 24, ett_dect_mitel_rfp_media_tone_entry, NULL, "Tone entry");

		proto_tree_add_item(tone_tree, hf_dect_mitel_rfp_media_tone_frequency_1, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(tone_tree, hf_dect_mitel_rfp_media_tone_frequency_2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(tone_tree, hf_dect_mitel_rfp_media_tone_frequency_3, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(tone_tree, hf_dect_mitel_rfp_media_tone_frequency_4, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(tone_tree, hf_dect_mitel_rfp_media_tone_cb_1, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(tone_tree, hf_dect_mitel_rfp_media_tone_cb_2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(tone_tree, hf_dect_mitel_rfp_media_tone_cb_3, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(tone_tree, hf_dect_mitel_rfp_media_tone_cb_4, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(tone_tree, hf_dect_mitel_rfp_media_tone_duration, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(tone_tree, hf_dect_mitel_rfp_media_tone_cycle_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(tone_tree, hf_dect_mitel_rfp_media_tone_cycle_to, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(tone_tree, hf_dect_mitel_rfp_media_tone_next, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
	}

	return offset;
}

/*
MEDIA Message
| Offset | Len | Content         |
| ------ | --- | --------------- |
|      0 |   2 | Handle          |
|      2 |     | Message content |
*/
static unsigned dissect_dect_mitel_rfp_media(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, unsigned offset, uint16_t message_type)
{
	proto_tree_add_item(tree, hf_dect_mitel_rfp_media_handle, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	switch(message_type) {
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_OPEN:
			offset = dissect_dect_mitel_rfp_media_open(tvb, pinfo, tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_CONF:
			offset = dissect_dect_mitel_rfp_media_conf(tvb, pinfo, tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_CLOSE:
			offset += 2;
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_START:
			offset = dissect_dect_mitel_rfp_media_start(tvb, pinfo, tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_STOP:
			offset = dissect_dect_mitel_rfp_media_stop(tvb, pinfo, tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_STATISTICS:
			offset = dissect_dect_mitel_rfp_media_statistics(tvb, pinfo, tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_REDIRECT_START:
			offset = dissect_dect_mitel_rfp_media_redirect_start(tvb, pinfo, tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_REDIRECT_STOP:
			offset = dissect_dect_mitel_rfp_media_redirect_stop(tvb, pinfo, tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_RESTART:
			offset = dissect_dect_mitel_rfp_media_restart(tvb, pinfo, tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_DTMF:
			offset = dissect_dect_mitel_rfp_media_dtmf(tvb, pinfo, tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_TONE:
			offset = dissect_dect_mitel_rfp_media_tone(tvb, pinfo, tree, data, offset);
			break;
	}
	return offset;
}

/*
SYNC FREQ_CTRL_MODE_IND Message
| Offset | Len | Content |
| ------ | --- | ------- |
|      0 |   1 | Mode    |
*/
static unsigned dissect_dect_mitel_rfp_sync_freq_ctrl_mode_ind(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sync_freq_ctrl_mode_ind_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	return offset;
}

/*
SYNC FREQ_CTRL_MODE_CFM Message
| Offset | Len | Content |
| ------ | --- | ------- |
|      0 |   1 | Mode    |
|      1 |   2 | Ppm     |
|      3 |   2 | Avg     |
*/
static unsigned dissect_dect_mitel_rfp_sync_freq_ctrl_mode_cfm(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sync_freq_ctrl_mode_cfm_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_sync_freq_ctrl_mode_cfm_ppm, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_sync_freq_ctrl_mode_cfm_avg, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	return offset;
}

/*
SYNC SET_FREQUENCY Message
| Offset | Len | Content   |
| ------ | --- | --------- |
|      0 |   2 | Frequency |
*/
static unsigned dissect_dect_mitel_rfp_sync_set_frequency(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sync_set_frequency_value, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	return offset;
}

/*
SYNC START_MAC_SLAVE_MODE Message
| Offset | Len | Content   |
| ------ | --- | --------- |
|      0 |   2 | RFP       |
*/
static unsigned dissect_dect_mitel_rfp_start_mac_slave_mode(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sync_start_mac_slave_mode_ind_rfp, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	return offset;
}

/*
SYNC SYSTEM_SEARCH_IND Message
| Offset | Len | Content |
| ------ | --- | ------- |
|      0 |   1 | Mode    |
*/
static unsigned dissect_dect_mitel_rfp_sync_system_search_ind(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sync_system_search_ind_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	return offset;
}

/*
SYNC SYSTEM_SEARCH_CFM Message
| Offset | Len | Content |
| ------ | --- | ------- |
|      0 |   1 | Count   |
|      1 |   4 | Item 1  |
| ...    | ... | ...     |
|  1+4*n |   4 | Item n  |

Item:

| Offset | Len | Content       |
| ------ | --- | ------------- |
|      0 |   2 | RPN           |
|      4 |   2 | RSSI          |
*/
static unsigned dissect_dect_mitel_rfp_sync_system_search_cfm(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	uint8_t item_count;
	proto_tree *item_tree;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_sync_system_search_cfm_count, tvb, offset, 1, ENC_BIG_ENDIAN);
	item_count = tvb_get_uint8(tvb, offset);
	offset++;

	for (uint8_t i = 0; i < item_count; i++) {
		item_tree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_dect_mitel_rfp_sync_phase_ofs_with_rssi_ind_item, NULL, "Item");

		proto_tree_add_item(item_tree, hf_dect_mitel_rfp_sync_system_search_cfm_item_rpn, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(item_tree, hf_dect_mitel_rfp_sync_system_search_cfm_item_rssi, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}

	return offset;
}


/*
SYNC PHASE_OFS_WITH_RSSI_IND Message
| Offset | Len | Content |
| ------ | --- | ------- |
|      0 |   1 | Count   |
|      1 |   6 | Item 1  |
| ...    | ... | ...     |
|  1+6*n |   6 | Item n  |

Item:

| Offset | Len | Content       |
| ------ | --- | ------------- |
|      0 |   2 | RPN           |
|      2 |   2 | Offset        |
|      4 |   1 | RSSI          |
|      5 |   1 | Qt Sync Check |
*/
static unsigned dissect_dect_mitel_rfp_sync_phase_ofs_with_rssi_ind(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, unsigned offset)
{
	uint8_t item_count;
	proto_tree *item_tree;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_sync_phase_ofs_with_rssi_ind_count, tvb, offset, 1, ENC_BIG_ENDIAN);
	item_count = tvb_get_uint8(tvb, offset);
	offset++;

	for (uint8_t i = 0; i < item_count; i++) {
		item_tree = proto_tree_add_subtree(tree, tvb, offset, 6, ett_dect_mitel_rfp_sync_phase_ofs_with_rssi_ind_item, NULL, "Item");

		proto_tree_add_item(item_tree, hf_dect_mitel_rfp_sync_phase_ofs_with_rssi_ind_item_rpn, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(item_tree, hf_dect_mitel_rfp_sync_phase_ofs_with_rssi_ind_item_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(item_tree, hf_dect_mitel_rfp_sync_phase_ofs_with_rssi_ind_item_rssi, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(item_tree, hf_dect_mitel_rfp_sync_phase_ofs_with_rssi_ind_item_qt_sync_check, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}

	return offset;
}

/*
SYNC Message
| Offset | Len | Content |
| ------ | --- | ------- |
|      0 |   2 | Type    |
|      2 |   1 | Length  |
|      3 | len | Content |
*/
static unsigned dissect_dect_mitel_rfp_sync(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, unsigned offset)
{
	uint16_t message_type;
	uint8_t payload_length;
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sync_payload_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	message_type = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(message_type, dect_mitel_rfp_sync_payload_type_val, " Unknown 0x%04x"));
	offset += 2;

	proto_tree_add_item(tree, hf_dect_mitel_rfp_sync_payload_length, tvb, offset, 1, ENC_BIG_ENDIAN);
	payload_length = tvb_get_uint8(tvb, offset);
	offset++;

	if (payload_length > 0) {
		switch(message_type) {
			case DECT_MITEL_RFP_SYNC_TYPE_FREQ_CTRL_MODE_IND:
				offset = dissect_dect_mitel_rfp_sync_freq_ctrl_mode_ind(tvb, pinfo, tree, data, offset);
				break;
			case DECT_MITEL_RFP_SYNC_TYPE_FREQ_CTRL_MODE_CFM:
				offset = dissect_dect_mitel_rfp_sync_freq_ctrl_mode_cfm(tvb, pinfo, tree, data, offset);
				break;
			case DECT_MITEL_RFP_SYNC_TYPE_SET_FREQUENCY:
				offset = dissect_dect_mitel_rfp_sync_set_frequency(tvb, pinfo, tree, data, offset);
				break;
			case DECT_MITEL_RFP_SYNC_TYPE_START_MAC_SLAVE_MODE_IND:
				offset = dissect_dect_mitel_rfp_start_mac_slave_mode(tvb, pinfo, tree, data, offset);
				break;
			case DECT_MITEL_RFP_SYNC_TYPE_SYSTEM_SEARCH_IND:
				offset = dissect_dect_mitel_rfp_sync_system_search_ind(tvb, pinfo, tree, data, offset);
				break;
			case DECT_MITEL_RFP_SYNC_TYPE_SYSTEM_SEARCH_CFM:
				offset = dissect_dect_mitel_rfp_sync_system_search_cfm(tvb, pinfo, tree, data, offset);
				break;
			case DECT_MITEL_RFP_SYNC_TYPE_PHASE_OFS_WITH_RSSI_IND:
				offset = dissect_dect_mitel_rfp_sync_phase_ofs_with_rssi_ind(tvb, pinfo, tree, data, offset);
				break;
		}
	}

	return offset;
}

static int dissect_dect_mitel_rfp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *ti;
	proto_tree *dect_mitel_rfp_tree;

	unsigned offset = 0;
	uint16_t message_type, message_length;
	tvbuff_t *next_tvb;
	bool ip_encapsulated = true;

	/*** COLUMN DATA ***/
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MITEL-RFP");
	col_clear(pinfo->cinfo, COL_INFO);

	/*** PROTOCOL TREE ***/
	ti = proto_tree_add_item(tree, proto_dect_mitel_rfp, tvb, 0, -1, ENC_NA);

	dect_mitel_rfp_tree = proto_item_add_subtree(ti, ett_dect_mitel_rfp);

	proto_tree_add_item(dect_mitel_rfp_tree, hf_dect_mitel_rfp_message_type, tvb,
			offset, 2, ENC_NA);
	message_type = tvb_get_uint16(tvb, offset, ENC_NA);
	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(message_type, dect_mitel_rfp_message_type_val, "Unknown 0x%04x"));
	offset += 2;

	proto_tree_add_item(dect_mitel_rfp_tree, hf_dect_mitel_rfp_message_length, tvb,
		offset, 2, ENC_NA);
	message_length = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
	offset += 2;

	switch ( message_type ) {
		case DECT_MITEL_RFP_MESSAGE_TYPE_CONTROL_ACK:
			dissect_dect_mitel_rfp_control_ack(tvb, pinfo, dect_mitel_rfp_tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_CONTROL_NACK:
			dissect_dect_mitel_rfp_control_nack(tvb, pinfo, dect_mitel_rfp_tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_CONTROL_HEARTBEAT:
			dissect_dect_mitel_rfp_control_heartbeat(tvb, pinfo, dect_mitel_rfp_tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_SYS_IP_OPTIONS:
			dissect_dect_mitel_rfp_sys_ip_options(tvb, pinfo, dect_mitel_rfp_tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_SYS_LED:
			dissect_dect_mitel_rfp_sys_led(tvb, pinfo, dect_mitel_rfp_tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_SYS_HEARTBEAT_INTERVAL:
			dissect_dect_mitel_rfp_sys_heartbeat_interval(tvb, pinfo, dect_mitel_rfp_tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_SYS_SYSLOG:
			dissect_dect_mitel_rfp_sys_syslog(tvb, pinfo, dect_mitel_rfp_tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_SYS_MAX_CHANNELS:
			dissect_dect_mitel_rfp_sys_max_channels(tvb, pinfo, dect_mitel_rfp_tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_SYS_HTTP_SET:
			dissect_dect_mitel_rfp_sys_http_set(tvb, pinfo, dect_mitel_rfp_tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_SYS_PASSWD:
			dissect_dect_mitel_rfp_sys_passwd(tvb, pinfo, dect_mitel_rfp_tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_SYS_RPING:
			dissect_dect_mitel_rfp_sys_rping(tvb, pinfo, dect_mitel_rfp_tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_SYS_CORE_DUMP:
			dissect_dect_mitel_rfp_sys_core_dump(tvb, pinfo, dect_mitel_rfp_tree, data, offset, message_length);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_SYS_VSNTP_TIME:
			dissect_dect_mitel_rfp_sys_vsntp_time(tvb, pinfo, dect_mitel_rfp_tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_SYS_INIT:
			dissect_dect_mitel_rfp_sys_init(tvb, pinfo, dect_mitel_rfp_tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_SYS_AUTHENTICATE:
			dissect_dect_mitel_rfp_sys_authenticate(tvb, pinfo, dect_mitel_rfp_tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_SYS_LICENSE_TIMER:
			dissect_dect_mitel_rfp_sys_license_timer(tvb, pinfo, dect_mitel_rfp_tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_OPEN:
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_CONF:
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_CLOSE:
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_START:
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_STOP:
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_STATISTICS:
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_REDIRECT_START:
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_REDIRECT_STOP:
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_RESTART:
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_DTMF:
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_DSP_CLOSE:
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_TONE:
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_BANDWIDTH_SWO:
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_MUTE:
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_G729_USED:
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_TRACE_PPN:
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_EOS_DETECT:
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_AUDIO_STATISTICS:
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_VIDEO_STATE:
		case DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_CHANNEL_MOD_INFO:
			dissect_dect_mitel_rfp_media(tvb, pinfo, dect_mitel_rfp_tree, data, offset, message_type);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_ETH:
			/* Handover to DECT-MITEL-ETH*/
			proto_item_set_len(ti, 4);
			next_tvb = tvb_new_subset_remaining(tvb, offset);
			call_dissector_with_data(dect_mitel_eth_handle, next_tvb, pinfo, tree, &ip_encapsulated);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_SYNC:
			dissect_dect_mitel_rfp_sync(tvb, pinfo, dect_mitel_rfp_tree, data, offset);
			break;
		default:
			break;
	}

	return tvb_captured_length(tvb);
}

static void fmt_dect_mitel_rfp_media_conf_codec_rate(char *rate_string, uint32_t rate)
{
	snprintf(rate_string, 9, "%d000Hz", rate);
}

static void fmt_dect_mitel_rfp_media_statistics_max_jitter(char *max_jitter_string, uint32_t max_jitter)
{
	snprintf(max_jitter_string, 14, "%.3fms", max_jitter / 1000.0);
}

static void fmt_dect_mitel_rfp_sync_phase_ofs_with_rssi_ind_item_offset(char *item_offset_string, uint32_t item_offset)
{
	snprintf(item_offset_string, 10, "%dns", item_offset * 48);
}

void proto_register_dect_mitel_rfp(void)
{
	static hf_register_info hf[] = {
		{ &hf_dect_mitel_rfp_message_type,
			{ "Message Type", "dect_mitel_rfp.message.type", FT_UINT16, BASE_HEX,
				VALS(dect_mitel_rfp_message_type_val), 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_message_length,
			{ "Length", "dect_mitel_rfp.message.length", FT_UINT16, BASE_DEC,
				NULL, 0x0, NULL, HFILL
			}
		},
		/* CONTROL-ACK */
		{ &hf_dect_mitel_rfp_control_ack_message,
			{ "Message Type", "dect_mitel_rfp.control.ack.message", FT_UINT16, BASE_HEX,
				VALS(dect_mitel_rfp_message_type_val), 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_control_ack_call_id,
			{ "Call ID", "dect_mitel_rfp.control.ack.call_id", FT_UINT16, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		/* CONTROL-NACK */
		{ &hf_dect_mitel_rfp_control_nack_message,
			{ "Message Type", "dect_mitel_rfp.control.nack.message", FT_UINT16, BASE_HEX,
				VALS(dect_mitel_rfp_message_type_val), 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_control_nack_call_id,
			{ "Call ID", "dect_mitel_rfp.control.nack.call_id", FT_UINT16, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_control_nack_reason,
			{ "Reject reason", "dect_mitel_rfp.control.nack.reason", FT_UINT32, BASE_HEX,
				VALS(dect_mitel_rfp_control_nack_reason_val), 0x0, NULL, HFILL
			}
		},
		/* CONTROL-HEARTBEAT */
		{ &hf_dect_mitel_rfp_control_heartbeat_milliseconds,
			{ "Milliseconds", "dect_mitel_rfp.control.heartbeat.milliseconds", FT_UINT32, BASE_DEC|BASE_UNIT_STRING,
				&units_milliseconds, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_control_heartbeat_nanoseconds,
			{ "Nanoseconds", "dect_mitel_rfp.control.heartbeat.nanoseconds", FT_UINT32, BASE_DEC|BASE_UNIT_STRING,
				&units_nanoseconds, 0x0, NULL, HFILL
			}
		},
		/* SYS-IP-OPTIONS */
		{ &hf_dect_mitel_rfp_sys_ip_options_voice_tos,
			{ "Voice ToS", "dect_mitel_rfp.sys.ip_options.voice_tos", FT_UINT8, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_ip_options_signalling_tos,
			{ "Signalling ToS", "dect_mitel_rfp.sys.ip_options.signalling_tos", FT_UINT8, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_ip_options_ttl,
			{ "TTL", "dect_mitel_rfp.sys.ip_options.ttl", FT_UINT8, BASE_DEC,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_ip_options_signal_vlan_priority,
			{ "Signal VLAN priority", "dect_mitel_rfp.sys.ip_options.signal_vlan_priority", FT_UINT8, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_ip_options_voice_vlan_priority,
			{ "Voice VLAN priority", "dect_mitel_rfp.sys.ip_options.voice_vlan_priority", FT_UINT8, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		/* SYS-LED */
		{ &hf_dect_mitel_rfp_sys_led_id,
			{ "ID", "dect_mitel_rfp.sys.led.id", FT_UINT8, BASE_DEC,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_led_color,
			{ "Color", "dect_mitel_rfp.sys.led.color", FT_UINT8, BASE_HEX,
				VALS(dect_mitel_rfp_sys_led_color_val), 0x0, NULL, HFILL
			}
		},
		/* SYS-HEARTBEAT-INTERVAL */
		{ &hf_dect_mitel_rfp_sys_heartbeat_interval_value,
			{ "Interval", "dect_mitel_rfp.sys.heartbeat_interval.value", FT_UINT8, BASE_DEC|BASE_UNIT_STRING,
				&units_seconds, 0, NULL, HFILL
			}
		},
		/* SYS-SYSLOG */
		{ &hf_dect_mitel_rfp_sys_syslog_ip_address,
			{ "IP address", "dect_mitel_rfp.sys.syslog.ip_address", FT_IPv6, BASE_NONE,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_syslog_port,
			{ "Port", "dect_mitel_rfp.sys.syslog.port", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		/* SYS-MAX-CHANNELS */
		{ &hf_dect_mitel_rfp_sys_max_channels_dsp,
			{ "DSP", "dect_mitel_rfp.sys.max_channels.dsp", FT_UINT8, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_max_channels_sessions,
			{ "Sessions", "dect_mitel_rfp.sys.max_channels.sessions", FT_UINT8, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		/* SYS-HTTP-SET */
		{ &hf_dect_mitel_rfp_sys_http_set_ip_address,
			{ "IP address", "dect_mitel_rfp.sys.http_set.ip_address", FT_IPv6, BASE_NONE,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_http_set_port,
			{ "Port", "dect_mitel_rfp.sys.http_set.port", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		/* SYS-PASSWD */
		{ &hf_dect_mitel_rfp_sys_passwd_remote_access_enabled,
			{ "Remote access enabled", "dect_mitel_rfp.sys.passwd.remote_access_enabled", FT_BOOLEAN, 8,
				NULL, 0x1, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_passwd_root_username,
			{ "Root username", "dect_mitel_rfp.sys.passwd.root_username", FT_STRINGZ, BASE_NONE,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_passwd_root_password,
			{ "Root password", "dect_mitel_rfp.sys.passwd.root_password", FT_STRINGZ, BASE_NONE,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_passwd_admin_username,
			{ "Admin username", "dect_mitel_rfp.sys.passwd.admin_username", FT_STRINGZ, BASE_NONE,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_passwd_admin_password,
			{ "Admin password", "dect_mitel_rfp.sys.passwd.admin_password", FT_STRINGZ, BASE_NONE,
				NULL, 0, NULL, HFILL
			}
		},
		/* SYS-RPING */
		{ &hf_dect_mitel_rfp_sys_rping_ip_address,
			{ "IP address", "dect_mitel_rfp.sys.rping.ip_address", FT_IPv6, BASE_NONE,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_rping_rtt,
			{ "RTT", "dect_mitel_rfp.sys.rping.rtt", FT_UINT32, BASE_DEC|BASE_UNIT_STRING,
				&units_milliseconds, 0, NULL, HFILL
			}
		},
		/* SYS-CORE-DUMP */
		{ &hf_dect_mitel_rfp_sys_core_dump_url,
			{ "URL", "dect_mitel_rfp.sys.core_dump.url", FT_STRINGZ, BASE_NONE,
				NULL, 0, NULL, HFILL
			}
		},
		/* SYS-VSNTP-TIME */
		{ &hf_dect_mitel_rfp_sys_vsntp_time_t1_seconds,
			{ "T1 seconds", "dect_mitel_rfp.sys.vsntp_time.t1_seconds", FT_UINT32, BASE_DEC|BASE_UNIT_STRING,
				&units_seconds, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_vsntp_time_t1_nanoseconds,
			{ "T1 nanoseconds", "dect_mitel_rfp.sys.vsntp_time.t1_nanoseconds", FT_UINT32, BASE_DEC|BASE_UNIT_STRING,
				&units_nanoseconds, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_vsntp_time_t2_seconds,
			{ "T2 seconds", "dect_mitel_rfp.sys.vsntp_time.t2_seconds", FT_UINT32, BASE_DEC|BASE_UNIT_STRING,
				&units_seconds, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_vsntp_time_t2_nanoseconds,
			{ "T2 nanoseconds", "dect_mitel_rfp.sys.vsntp_time.t2_nanoseconds", FT_UINT32, BASE_DEC|BASE_UNIT_STRING,
				&units_nanoseconds, 0, NULL, HFILL
			}
		},
		/* SYS-INIT */
		{ &hf_dect_mitel_rfp_sys_init_rfp_model,
			{ "RFP Model", "dect_mitel_rfp.sys.init.rfp_model", FT_UINT32, BASE_HEX,
				VALS(dect_mitel_rfp_sys_init_rfp_model_val), 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_init_rfp_mac,
			{ "RFP MAC Address", "dect_mitel_rfp.sys.init.rfp_mac", FT_ETHER, BASE_NONE,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_init_crypted,
			{ "Crypted", "dect_mitel_rfp.sys.init.crypted", FT_BYTES, BASE_NONE,
				NULL, 0x0, "AES Crypted fields", HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_init_protocol,
			{ "Protocol", "dect_mitel_rfp.sys.init.protocol", FT_UINT32, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_init_rfp_capabilities,
			{ "RPF Capabilities", "dect_mitel_rfp.sys.init.capabilities", FT_UINT32, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_init_rfp_capability_normal_tx,
			{ "Normal TX power", "dect_mitel_rfp.sys.init.capabilities.normal_tx", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_RFP_SYS_INIT_RFP_CAPABILITY_NORMAL_TX, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_init_rfp_capability_indoor,
			{ "Indoor", "dect_mitel_rfp.sys.init.capabilities.indoor", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_RFP_SYS_INIT_RFP_CAPABILITY_INDOOR, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_init_rfp_capability_wlan,
			{ "WLAN", "dect_mitel_rfp.sys.init.capabilities.wlan", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_RFP_SYS_INIT_RFP_CAPABILITY_WLAN, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_init_rfp_capability_encryption,
			{ "Encryption", "dect_mitel_rfp.sys.init.capabilities.encryption", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_RFP_SYS_INIT_RFP_CAPABILITY_ENCRYPTION, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_init_rfp_capability_frequency_shift,
			{ "Frequency shift", "dect_mitel_rfp.sys.init.capabilities.frequency_shift", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_RFP_SYS_INIT_RFP_CAPABILITY_FREQUENCY_SHIFT, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_init_rfp_capability_low_tx,
			{ "Low TX power", "dect_mitel_rfp.sys.init.capabilities.low_tx", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_RFP_SYS_INIT_RFP_CAPABILITY_LOW_TX, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_init_rfp_capability_advanced_feature,
			{ "Advanced Feature", "dect_mitel_rfp.sys.init.capabilities.advanced_feature", FT_BOOLEAN, 32,
				TFS(&tfs_yes_no), DECT_MITEL_RFP_SYS_INIT_RFP_CAPABILITY_ADVANCED_FEATURE, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_init_rfp_software_version,
			{ "RFP Software Version", "dect_mitel_rfp.sys.init.rfp_software_version", FT_STRING, BASE_NONE,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_init_signature,
			{ "Signature", "dect_mitel_rfp.sys.init.signature", FT_BYTES, BASE_NONE,
				NULL, 0x0, NULL, HFILL
			}
		},
		/* SYS-AUTHENTICATE */
		{ &hf_dect_mitel_rfp_sys_authenticate_rfp_iv,
			{ "RFP IV", "dect_mitel_rfp.sys.authenticate.rfp_iv", FT_UINT64, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_authenticate_omm_iv,
			{ "OMM IV", "dect_mitel_rfp.sys.authenticate.omm_iv", FT_UINT64, BASE_HEX,
				NULL, 0x0, NULL, HFILL
			}
		},
		/* SYS-LICENSE-TIMER */
		{ &hf_dect_mitel_rfp_sys_license_timer_query,
			{ "Query", "dect_mitel_rfp.sys.license_timer.query", FT_BOOLEAN, 32,
				NULL, 0x80000000, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_license_timer_grace_period,
			{ "Grace period", "dect_mitel_rfp.sys.license_timer.grace_period", FT_UINT32, BASE_DEC|BASE_UNIT_STRING,
				&units_minutes, 0x7FFFFFFF, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sys_license_timer_checksum,
			{ "Checksum", "dect_mitel_rfp.sys.license_timer.checksum", FT_BYTES, BASE_NONE,
				NULL, 0, NULL, HFILL
			}
		},
		/* MEDIA */
		{ &hf_dect_mitel_rfp_media_handle,
			{ "Handle", "dect_mitel_rfp.media.handle", FT_UINT16, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_mcei,
			{ "MCEI", "dect_mitel_rfp.media.mcei", FT_UINT8, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_direction,
			{ "Direction", "dect_mitel_rfp.media.start.direction", FT_UINT8, BASE_HEX,
				VALS(dect_mitel_rfp_media_direction_val), 0, NULL, HFILL
			}
		},
		/* MEDIA-OPEN */
		{ &hf_dect_mitel_rfp_media_open_codec,
			{ "Codec", "dect_mitel_rfp.media.open.codec", FT_UINT8, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_open_slot_count,
			{ "Slot count", "dect_mitel_rfp.media.open.slot_count", FT_UINT8, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_open_flags,
			{ "Flags", "dect_mitel_rfp.media.open.flags", FT_UINT32, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		/* MEDIA-CONF */
		{ &hf_dect_mitel_rfp_media_conf_vif,
			{ "VIF", "dect_mitel_rfp.media.conf.vif", FT_UINT8, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_conf_vad,
			{ "VAD", "dect_mitel_rfp.media.conf.vad", FT_BOOLEAN, 8,
				NULL, 0x01, "Voice Activity Detection (VAD)", HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_conf_codec_count,
			{ "Codec count", "dect_mitel_rfp.media.conf.codec_count", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_conf_codec_type,
			{ "Type", "dect_mitel_rfp.media.conf.codec.type", FT_UINT8, BASE_HEX,
				VALS(dect_mitel_rfp_media_conf_codec_type_val), 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_conf_codec_pt,
			{ "Priority", "dect_mitel_rfp.media.conf.codec.priority", FT_UINT8, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_conf_codec_rate,
			{ "Rate", "dect_mitel_rfp.media.conf.codec.rate", FT_UINT8, BASE_CUSTOM,
				CF_FUNC(&fmt_dect_mitel_rfp_media_conf_codec_rate), 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_conf_ppn,
			{ "PPN", "dect_mitel_rfp.media.conf.ppn", FT_UINT16, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_conf_local_port_1,
			{ "Local port 1", "dect_mitel_rfp.media.conf.local_port_1", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_conf_local_port_2,
			{ "Local port 2", "dect_mitel_rfp.media.conf.local_port_2", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_conf_rx_ip_address,
			{ "RX IP Address", "dect_mitel_rfp.media.conf.rx_ip_address", FT_IPv4, BASE_NONE,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_conf_rx_port_1,
			{ "RX port 1", "dect_mitel_rfp.media.conf.rx_port_1", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_conf_rx_port_2,
			{ "RX port 2", "dect_mitel_rfp.media.conf.rx_port_2", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_conf_tx_ip_address,
			{ "TX IP Address", "dect_mitel_rfp.media.conf.tx_ip_address", FT_IPv4, BASE_NONE,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_conf_tx_port_1,
			{ "TX port 1", "dect_mitel_rfp.media.conf.tx_port_1", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_conf_tx_port_2,
			{ "TX port 2", "dect_mitel_rfp.media.conf.tx_port_2", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		/* MEDIA-START */
		{ &hf_dect_mitel_rfp_media_start_time,
			{ "Time", "dect_mitel_rfp.media.start.time", FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_start_met_keep_alive,
			{ "Met keep alive", "dect_mitel_rfp.media.start.met_keep_alive", FT_UINT8, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		/* MEDIA-STATISTICS */
		{ &hf_dect_mitel_rfp_media_statistics_duration,
			{ "Duration", "dect_mitel_rfp.media.statistics.duration", FT_UINT32, BASE_DEC|BASE_UNIT_STRING,
				&units_seconds, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_statistics_tx_packets,
			{ "TX packets", "dect_mitel_rfp.media.statistics.tx_packets", FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_statistics_tx_bytes,
			{ "TX bytes", "dect_mitel_rfp.media.statistics.tx_bytes", FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_statistics_rx_packets,
			{ "RX packets", "dect_mitel_rfp.media.statistics.rx_packets", FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_statistics_rx_bytes,
			{ "RX bytes", "dect_mitel_rfp.media.statistics.rx_bytes", FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_statistics_lost_packets,
			{ "Lost packets", "dect_mitel_rfp.media.statistics.lost_packets", FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_statistics_max_jitter,
			{ "Max jitter", "dect_mitel_rfp.media.statistics.max_jitter", FT_UINT32, BASE_CUSTOM,
				CF_FUNC(&fmt_dect_mitel_rfp_media_statistics_max_jitter), 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_statistics_rtp_ip_address,
			{ "RTP IP address", "dect_mitel_rfp.media.statistics.rtp_ip_address", FT_IPv4, BASE_NONE,
				NULL, 0, NULL, HFILL
			}
		},
		/* MEDIA-REDIRECT-START */
		{ &hf_dect_mitel_rfp_media_redirect_start_local_port_1,
			{ "Local port 1", "dect_mitel_rfp.media.redirect_start.local_port_1", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_redirect_start_local_port_2,
			{ "Local port 2", "dect_mitel_rfp.media.redirect_start.local_port_2", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_redirect_start_remote_ip_address,
			{ "Remote IP address", "dect_mitel_rfp.media.redirect_start.remote_ip_address", FT_IPv4, BASE_NONE,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_redirect_start_remote_port_1,
			{ "Remote port 1", "dect_mitel_rfp.media.redirect_start.remote_port_1", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_redirect_start_remote_port_2,
			{ "Remote port 2", "dect_mitel_rfp.media.redirect_start.remote_port_2", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_redirect_start_time,
			{ "Time", "dect_mitel_rfp.media.redirect_start.time", FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		/* MEDIA-REDIRECT-STOP */
		{ &hf_dect_mitel_rfp_media_redirect_stop_fallback,
			{ "Fallback", "dect_mitel_rfp.media.redirect_stop.fallback", FT_UINT8, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		/* MEDIA-DTMF */
		{ &hf_dect_mitel_rfp_media_dtmf_duration,
			{ "Duration", "dect_mitel_rfp.media.dtmf.duration", FT_UINT16, BASE_DEC|BASE_UNIT_STRING,
				&units_milliseconds, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_dtmf_key,
			{ "Key", "dect_mitel_rfp.media.dtmf.key", FT_CHAR, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		/* MEDIA-TONE */
		{ &hf_dect_mitel_rfp_media_tone_count,
			{ "Count", "dect_mitel_rfp.media.tone.count", FT_UINT8, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_tone_frequency_1,
			{ "Frequency 1", "dect_mitel_rfp.media.tone.frequency_1", FT_UINT16, BASE_DEC|BASE_UNIT_STRING,
				&units_hz, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_tone_frequency_2,
			{ "Frequency 2", "dect_mitel_rfp.media.tone.frequency_2", FT_UINT16, BASE_DEC|BASE_UNIT_STRING,
				&units_hz, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_tone_frequency_3,
			{ "Frequency 3", "dect_mitel_rfp.media.tone.frequency_3", FT_UINT16, BASE_DEC|BASE_UNIT_STRING,
				&units_hz, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_tone_frequency_4,
			{ "Frequency 4", "dect_mitel_rfp.media.tone.frequency_4", FT_UINT16, BASE_DEC|BASE_UNIT_STRING,
				&units_hz, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_tone_cb_1,
			{ "cB 1", "dect_mitel_rfp.media.tone.cb_1", FT_INT16, BASE_DEC|BASE_UNIT_STRING,
				&units_centibels, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_tone_cb_2,
			{ "cB 2", "dect_mitel_rfp.media.tone.cb_2", FT_INT16, BASE_DEC|BASE_UNIT_STRING,
				&units_centibels, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_tone_cb_3,
			{ "cB 3", "dect_mitel_rfp.media.tone.cb_3", FT_INT16, BASE_DEC|BASE_UNIT_STRING,
				&units_centibels, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_tone_cb_4,
			{ "cB 4", "dect_mitel_rfp.media.tone.cb_4", FT_INT16, BASE_DEC|BASE_UNIT_STRING,
				&units_centibels, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_tone_duration,
			{ "Duration", "dect_mitel_rfp.media.tone.duration", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_tone_cycle_count,
			{ "Cycle count", "dect_mitel_rfp.media.tone.cycle_count", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_tone_cycle_to,
			{ "Cycle to", "dect_mitel_rfp.media.tone.cycle_to", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_media_tone_next,
			{ "Next", "dect_mitel_rfp.media.tone.next", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		/* SYNC */
		{ &hf_dect_mitel_rfp_sync_payload_type,
			{ "Type", "dect_mitel_rfp.sync.payload_type", FT_UINT16, BASE_HEX,
				VALS(dect_mitel_rfp_sync_payload_type_val), 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sync_payload_length,
			{ "Length", "dect_mitel_rfp.sync.payload_length", FT_UINT8, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		/* SYNC FREQ_CTRL_MODE_IND */
		{ &hf_dect_mitel_rfp_sync_freq_ctrl_mode_ind_mode,
			{ "Mode", "dect_mitel_rfp.sync.freq_ctrl_mode_ind.mode", FT_UINT8, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		/* SYNC FREQ_CTRL_MODE_CFM */
		{ &hf_dect_mitel_rfp_sync_freq_ctrl_mode_cfm_mode,
			{ "Mode", "dect_mitel_rfp.sync.freq_ctrl_mode_cfm.mode", FT_UINT8, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sync_freq_ctrl_mode_cfm_ppm,
			{ "ppm", "dect_mitel_rfp.sync.freq_ctrl_mode_cfm.ppm", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sync_freq_ctrl_mode_cfm_avg,
			{ "avg", "dect_mitel_rfp.sync.freq_ctrl_mode_cfm.avg", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		/* SYNC SET_FREQUENCY */
		{ &hf_dect_mitel_rfp_sync_set_frequency_value,
			{ "Frequency", "dect_mitel_rfp.sync.set_frequency.value", FT_UINT16, BASE_DEC|BASE_UNIT_STRING,
				&units_hz, 0, NULL, HFILL
			}
		},
		/* SYNC START_MAC_SLAVE_MODE_IND */
		{ &hf_dect_mitel_rfp_sync_start_mac_slave_mode_ind_rfp,
			{ "RFP", "dect_mitel_rfp.sync.start_mac_slave_mode_ind.rfp", FT_UINT16, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		/* SYNC SYSTEM_SEARCH_IND */
		{ &hf_dect_mitel_rfp_sync_system_search_ind_mode,
			{ "Mode", "dect_mitel_rfp.sync.system_search_ind.mode", FT_UINT8, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		/* SYNC SYSTEM_SEARCH_CFM */
		{ &hf_dect_mitel_rfp_sync_system_search_cfm_count,
			{ "Count", "dect_mitel_rfp.sync.system_search_cfm.count", FT_UINT8, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sync_system_search_cfm_item_rpn,
			{ "RPN", "dect_mitel_rfp.sync.system_search_cfm.item.rpn", FT_UINT16, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sync_system_search_cfm_item_rssi,
			{ "RSSI", "dect_mitel_rfp.sync.system_search_cfm.item.rssi", FT_UINT16, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		/* SYNC PHASE_OFS_WITH_RSSI_IND */
		{ &hf_dect_mitel_rfp_sync_phase_ofs_with_rssi_ind_count,
			{ "Count", "dect_mitel_rfp.sync.phase_ofs_with_rssi_ind.count", FT_UINT8, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sync_phase_ofs_with_rssi_ind_item_rpn,
			{ "RPN", "dect_mitel_rfp.sync.phase_ofs_with_rssi_ind.item.rpn", FT_UINT16, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sync_phase_ofs_with_rssi_ind_item_offset,
			{ "Offset", "dect_mitel_rfp.sync.phase_ofs_with_rssi_ind.item.offset", FT_UINT16, BASE_CUSTOM,
				CF_FUNC(&fmt_dect_mitel_rfp_sync_phase_ofs_with_rssi_ind_item_offset), 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sync_phase_ofs_with_rssi_ind_item_rssi,
			{ "RSSI", "dect_mitel_rfp.sync.phase_ofs_with_rssi_ind.item.rssi", FT_UINT8, BASE_DEC,
				NULL, 0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_sync_phase_ofs_with_rssi_ind_item_qt_sync_check,
			{ "QT-Sync-Check", "dect_mitel_rfp.sync.phase_ofs_with_rssi_ind.item.qt_sync_check", FT_UINT8, BASE_HEX,
				NULL, 0, NULL, HFILL
			}
		},
	};

	static int *ett[] = {
		&ett_dect_mitel_rfp,
		&ett_dect_mitel_rfp_sys_init_rfp_capabilities,
		&ett_dect_mitel_rfp_media_tone_entry,
		&ett_dect_mitel_rfp_sync_phase_ofs_with_rssi_ind_item,
		&ett_dect_mitel_rfp_sync_system_search_cfm_item,
	};

	proto_dect_mitel_rfp = proto_register_protocol("Mitel RFP/OMM TCP communication protocol",
			"DECT-MITEL-RFP", "dect_mitel_rfp");

	proto_register_field_array(proto_dect_mitel_rfp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	dect_mitel_rfp_handle = register_dissector("dect_mitel_rfp", dissect_dect_mitel_rfp,
			proto_dect_mitel_rfp);
}

void proto_reg_handoff_dect_mitel_rfp(void)
{
	dissector_add_uint_with_preference("tcp.port", tcp_port_pref, dect_mitel_rfp_handle);

	dect_mitel_eth_handle = find_dissector("dect_mitel_eth");
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
