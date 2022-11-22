/* packet-dect-mitel-rfp.c
 * Routines for DECT-Mitel-RFP dissection
 * Copyright 2022, Bernhard Dick <bernhard@bdick.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * This is a proprietary protocol deveolped by Mitel for communication
 * inbetween the DECT system management Software (OMM) and the DECT
 * base station (RFPs)
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <ftypes/ftypes.h>
#include <proto.h>
#include <tfs.h>
#include <tvbuff.h>
#include <value_string.h>

/* Prototypes */
void proto_reg_handoff_dect_mitel_rfp(void);
void proto_register_dect_mitel_rfp(void);

/* Initialize the protocol and registered fields */
static int proto_dect_mitel_rfp = -1;

static int hf_dect_mitel_rfp_message_type = -1;
static int hf_dect_mitel_rfp_message_length = -1;

/* CONTROL-ACK */
static int hf_dect_mitel_rfp_control_ack_message = -1;
static int hf_dect_mitel_rfp_control_ack_call_id = -1;

/* CONTROL-NACK */
static int hf_dect_mitel_rfp_control_nack_message = -1;
static int hf_dect_mitel_rfp_control_nack_call_id = -1;
static int hf_dect_mitel_rfp_control_nack_reason = -1;

/* CONTROL-HEARTBEAT */
static int hf_dect_mitel_rfp_control_heartbeat_milliseconds = -1;
static int hf_dect_mitel_rfp_control_heartbeat_nanoseconds = -1;

/* SYS-IP-OPTIONS */
static int hf_dect_mitel_rfp_sys_ip_options_voice_tos = -1;
static int hf_dect_mitel_rfp_sys_ip_options_signalling_tos = -1;
static int hf_dect_mitel_rfp_sys_ip_options_ttl = -1;
static int hf_dect_mitel_rfp_sys_ip_options_signal_vlan_priority = -1;
static int hf_dect_mitel_rfp_sys_ip_options_voice_vlan_priority = -1;

/* SYS-LED */
static int hf_dect_mitel_rfp_sys_led_id    = -1;
static int hf_dect_mitel_rfp_sys_led_color = -1;

/* SYS-AUTHENTICATE */
static int hf_dect_mitel_rfp_sys_authenticate_omm_iv = -1;
static int hf_dect_mitel_rfp_sys_authenticate_rfp_iv = -1;

/* SYS-INIT */
static int hf_dect_mitel_rfp_sys_init_rfp_model = -1;
static int hf_dect_mitel_rfp_sys_init_rfp_mac = -1;
static int hf_dect_mitel_rfp_sys_init_crypted = -1;
static int hf_dect_mitel_rfp_sys_init_protocol = -1;
static int hf_dect_mitel_rfp_sys_init_rfp_capabilities = -1;
static int hf_dect_mitel_rfp_sys_init_rfp_capability_normal_tx = -1;
static int hf_dect_mitel_rfp_sys_init_rfp_capability_indoor = -1;
static int hf_dect_mitel_rfp_sys_init_rfp_capability_wlan = -1;
static int hf_dect_mitel_rfp_sys_init_rfp_capability_encryption = -1;
static int hf_dect_mitel_rfp_sys_init_rfp_capability_frequency_shift = -1;
static int hf_dect_mitel_rfp_sys_init_rfp_capability_low_tx = -1;
static int hf_dect_mitel_rfp_sys_init_rfp_capability_advanced_feature = -1;
static int hf_dect_mitel_rfp_sys_init_rfp_brand = -1;
static int hf_dect_mitel_rfp_sys_init_rfp_software_version = -1;
static int hf_dect_mitel_rfp_sys_init_signature = -1;

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
	DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_TONE2                  = 0x020b,
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

enum dect_mitel_rfp_sys_init_rfp_brand_coding {
	DECT_MITEL_RFP_SYS_INIT_RFP_BRAND_AVAYA  = 0x001,
	DECT_MITEL_RFP_SYS_INIT_RFP_BRAND_FFSIP  = 0x002,
	DECT_MITEL_RFP_SYS_INIT_RFP_BRAND_A5000  = 0x004,
	DECT_MITEL_RFP_SYS_INIT_RFP_BRAND_Mitel  = 0x008,
	DECT_MITEL_RFP_SYS_INIT_RFP_BRAND_OC01XX = 0x010,
	DECT_MITEL_RFP_SYS_INIT_RFP_BRAND_OCX    = 0x020,
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
	{ DECT_MITEL_RFP_MESSAGE_TYPE_MEDIA_TONE2,                  "MEDIA-TONE2" },
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
	{ DECT_MITEL_RFP_MESSAGE_TYPE_BLUETOOTH_DATA,               "BLUETOOOTH-DATA" },
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

static const value_string dect_mitel_rfp_sys_init_rfp_brand_val[] = {
	{DECT_MITEL_RFP_SYS_INIT_RFP_BRAND_AVAYA,  "Avaya" },
	{DECT_MITEL_RFP_SYS_INIT_RFP_BRAND_FFSIP,  "FF-SIP" },
	{DECT_MITEL_RFP_SYS_INIT_RFP_BRAND_A5000,  "A5000" },
	{DECT_MITEL_RFP_SYS_INIT_RFP_BRAND_Mitel,  "Mitel" },
	{DECT_MITEL_RFP_SYS_INIT_RFP_BRAND_OC01XX, "OC01XX" },
	{DECT_MITEL_RFP_SYS_INIT_RFP_BRAND_OCX,    "OCX" },
	{ 0, NULL }
};

static dissector_handle_t dect_mitel_rfp_handle;
static dissector_handle_t dect_mitel_eth_handle;

/* Preferences */
#define DECT_MITEL_RFP_TCP_PORT 16321
static guint tcp_port_pref = DECT_MITEL_RFP_TCP_PORT;

/* Initialize the subtree pointers */
static gint ett_dect_mitel_rfp = -1;

/*
CONTROL-ACK Message
| Offset | Len | Content |
| ------ | --- | ------- |
|      0 |   2 | Message |
|      2 |   2 | Call ID |
 */
static guint dissect_dect_mitel_rfp_control_ack(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, guint offset)
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
static guint dissect_dect_mitel_rfp_control_nack(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, guint offset)
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
static guint dissect_dect_mitel_rfp_control_heartbeat(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, guint offset)
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
static guint dissect_dect_mitel_rfp_sys_ip_options(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, guint offset)
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
static guint dissect_dect_mitel_rfp_sys_led(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, guint offset)
{
	guint8 led_id, led_color;
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_led_id, tvb, offset, 1, ENC_NA);
	led_id = tvb_get_guint8(tvb, offset);
	offset++;
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_led_color, tvb, offset, 1, ENC_NA);
	led_color = tvb_get_guint8(tvb, offset);
	offset++;
	col_append_fstr(pinfo->cinfo, COL_INFO, "LED %d:%s", led_id,
		val_to_str(led_color, dect_mitel_rfp_sys_led_color_val, "Unknown: %02x"));
	return offset;
}

/*
SYS-AUTHENTICATE Message
| Offset | Len | Content         |
| ------ | --- | --------------- |
|      7 |   8 | RFP Blowfish IV |
|     21 |   8 | OMM Blowfish IV |
*/
static guint dissect_dect_mitel_rfp_sys_authenticate(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, guint offset)
{
	offset += 7;
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_authenticate_rfp_iv, tvb, offset, 8, ENC_NA);
	offset += 16;
	proto_tree_add_item(tree, hf_dect_mitel_rfp_sys_authenticate_omm_iv, tvb, offset, 8, ENC_NA);
	offset += 8;
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
static guint dissect_dect_mitel_rfp_sys_init(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_, guint offset)
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
	proto_tree_add_bitmask(tree, tvb, offset, hf_dect_mitel_rfp_sys_init_rfp_capabilities, ett_dect_mitel_rfp, capabilities_flags, ENC_NA);
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

static int dissect_dect_mitel_rfp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *ti;
	proto_tree *dect_mitel_rfp_tree;

	guint offset = 0;
	guint16 message_type;
	tvbuff_t *next_tvb;
	gboolean ip_encapsulated = true;

	/*** COLUMN DATA ***/
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MITEL-RFP");
	col_clear(pinfo->cinfo, COL_INFO);

	/*** PROTOCOL TREE ***/
	ti = proto_tree_add_item(tree, proto_dect_mitel_rfp, tvb, 0, -1, ENC_NA);

	dect_mitel_rfp_tree = proto_item_add_subtree(ti, ett_dect_mitel_rfp);

	proto_tree_add_item(dect_mitel_rfp_tree, hf_dect_mitel_rfp_message_type, tvb,
			offset, 2, ENC_NA);
	message_type = tvb_get_guint16(tvb, offset, ENC_NA);
	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(message_type, dect_mitel_rfp_message_type_val, "Unknown 0x%04x"));
	offset += 2;

	proto_tree_add_item(dect_mitel_rfp_tree, hf_dect_mitel_rfp_message_length, tvb,
		offset, 2, ENC_NA);
	offset += 2;

	switch ( message_type ) {
		case DECT_MITEL_RFP_MESSAGE_TYPE_CONTROL_ACK:
			offset = dissect_dect_mitel_rfp_control_ack(tvb, pinfo, tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_CONTROL_NACK:
			offset = dissect_dect_mitel_rfp_control_nack(tvb, pinfo, tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_CONTROL_HEARTBEAT:
			offset = dissect_dect_mitel_rfp_control_heartbeat(tvb, pinfo, tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_SYS_IP_OPTIONS:
			offset = dissect_dect_mitel_rfp_sys_ip_options(tvb, pinfo, tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_SYS_LED:
			offset = dissect_dect_mitel_rfp_sys_led(tvb, pinfo, tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_SYS_AUTHENTICATE:
			offset = dissect_dect_mitel_rfp_sys_authenticate(tvb, pinfo, tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_SYS_INIT:
			offset = dissect_dect_mitel_rfp_sys_init(tvb, pinfo, tree, data, offset);
			break;
		case DECT_MITEL_RFP_MESSAGE_TYPE_ETH:
			/* Handover to DECT-MITEL-ETH*/
			next_tvb = tvb_new_subset_remaining(tvb, offset);
			call_dissector_with_data(dect_mitel_eth_handle, next_tvb, pinfo, tree, &ip_encapsulated);
			break;
		default:
			break;
	}

	return tvb_captured_length(tvb);
}

void proto_register_dect_mitel_rfp(void)
{
	module_t        *dect_mitel_rfp_module;

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
			{ "Reject reason", "dect_mitel_rfp.control.nack.message", FT_UINT32, BASE_HEX,
				VALS(dect_mitel_rfp_control_nack_reason_val), 0x0, NULL, HFILL
			}
		},
		/* CONTROL-HEARTBEAT */
		{ &hf_dect_mitel_rfp_control_heartbeat_milliseconds,
			{ "Milliseconds", "dect_mitel_rfp.control.heartbeat.milliseconds", FT_UINT32, BASE_DEC,
				NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_dect_mitel_rfp_control_heartbeat_nanoseconds,
			{ "Nanoseconds", "dect_mitel_rfp.control.heartbeat.nanoseconds", FT_UINT32, BASE_DEC,
				NULL, 0x0, NULL, HFILL
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
		{ &hf_dect_mitel_rfp_sys_init_rfp_brand,
			{ "RFP Brand", "dect_mitel_rfp.sys.init.rfp_brand", FT_UINT16, BASE_HEX,
				VALS(dect_mitel_rfp_sys_init_rfp_brand_val), 0x03FF, NULL, HFILL
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
	};

	static gint *ett[] = {
		&ett_dect_mitel_rfp
	};

	proto_dect_mitel_rfp = proto_register_protocol("Mitel RFP/OMM TCP communication protocol",
			"DECT-MITEL-RFP", "dect_mitel_rfp");

	proto_register_field_array(proto_dect_mitel_rfp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	dect_mitel_rfp_handle = register_dissector("dect_mitel_rfp", dissect_dect_mitel_rfp,
			proto_dect_mitel_rfp);

	dect_mitel_rfp_module = prefs_register_protocol(proto_dect_mitel_rfp,
			proto_reg_handoff_dect_mitel_rfp);

	prefs_register_uint_preference(dect_mitel_rfp_module, "tcp.port", "dect_mitel_rfp TCP Port",
			" dect_mitel_rfp TCP port if other than the default",
			10, &tcp_port_pref);

}

void proto_reg_handoff_dect_mitel_rfp(void)
{
	static gboolean initialized = FALSE;
	static int current_tcp_port;

	if (!initialized) {
		dissector_add_uint_with_preference("tcp.port", tcp_port_pref, dect_mitel_rfp_handle);

		initialized = TRUE;
	} else {
		dissector_delete_uint("tcp.port", current_tcp_port, dect_mitel_rfp_handle);
	}
	current_tcp_port = tcp_port_pref;
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
