/* packet-lorawan.c
 * Dissector routines for the LoRaWAN protocol
 * By Erik de Jong <erikdejong@gmail.com>
 * Copyright 2017 Erik de Jong
 * Copyright 2022 Ales Povalac <alpov@alpov.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <math.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include <epan/strutil.h>
#include <epan/crc16-tvb.h> /* For CRC verification */
#include <wsutil/wsgcrypt.h>

void proto_reg_handoff_lorawan(void);
void proto_register_lorawan(void);

static dissector_handle_t lorawan_handle;

static int proto_lorawan;
static int hf_lorawan_msgtype_type;
static int hf_lorawan_mac_header_type;
static int hf_lorawan_mac_header_ftype_type;
static int hf_lorawan_mac_header_rfu_type;
static int hf_lorawan_mac_header_major_type;
static int hf_lorawan_mac_commands_type;
static int hf_lorawan_mac_command_uplink_type;
static int hf_lorawan_mac_command_downlink_type;
static int hf_lorawan_mac_command_down_link_check_ans_type;
static int hf_lorawan_mac_command_down_link_check_ans_margin_type;
static int hf_lorawan_mac_command_down_link_check_ans_gwcnt_type;
static int hf_lorawan_mac_command_down_link_adr_req_datarate_type;
static int hf_lorawan_mac_command_down_link_adr_req_txpower_type;
static int hf_lorawan_mac_command_down_link_adr_req_channel_type;
static int hf_lorawan_mac_command_down_link_adr_req_channel1_type;
static int hf_lorawan_mac_command_down_link_adr_req_channel2_type;
static int hf_lorawan_mac_command_down_link_adr_req_channel3_type;
static int hf_lorawan_mac_command_down_link_adr_req_channel4_type;
static int hf_lorawan_mac_command_down_link_adr_req_channel5_type;
static int hf_lorawan_mac_command_down_link_adr_req_channel6_type;
static int hf_lorawan_mac_command_down_link_adr_req_channel7_type;
static int hf_lorawan_mac_command_down_link_adr_req_channel8_type;
static int hf_lorawan_mac_command_down_link_adr_req_channel9_type;
static int hf_lorawan_mac_command_down_link_adr_req_channel10_type;
static int hf_lorawan_mac_command_down_link_adr_req_channel11_type;
static int hf_lorawan_mac_command_down_link_adr_req_channel12_type;
static int hf_lorawan_mac_command_down_link_adr_req_channel13_type;
static int hf_lorawan_mac_command_down_link_adr_req_channel14_type;
static int hf_lorawan_mac_command_down_link_adr_req_channel15_type;
static int hf_lorawan_mac_command_down_link_adr_req_channel16_type;
static int hf_lorawan_mac_command_down_link_adr_req_channel_mask_control_type;
static int hf_lorawan_mac_command_down_link_adr_req_repetitions_type;
static int hf_lorawan_mac_command_up_link_adr_ans_txpower_type;
static int hf_lorawan_mac_command_up_link_adr_ans_datarate_type;
static int hf_lorawan_mac_command_up_link_adr_ans_channel_mask_type;
static int hf_lorawan_mac_command_down_dutycycle_type;
static int hf_lorawan_mac_command_down_rx_setup_req_rx1droffset_type;
static int hf_lorawan_mac_command_down_rx_setup_req_rx2datarate_type;
static int hf_lorawan_mac_command_down_rx_setup_req_frequency_type;
static int hf_lorawan_mac_command_up_rx_setup_ans_type;
static int hf_lorawan_mac_command_up_rx_setup_ans_rx1droffset_type;
static int hf_lorawan_mac_command_up_rx_setup_ans_rx2datarate_type;
static int hf_lorawan_mac_command_up_rx_setup_ans_frequency_type;
static int hf_lorawan_mac_command_up_device_status_ans_battery_type;
static int hf_lorawan_mac_command_up_device_status_ans_margin_type;
static int hf_lorawan_mac_command_down_new_channel_req_index_type;
static int hf_lorawan_mac_command_down_new_channel_req_frequency_type;
static int hf_lorawan_mac_command_down_new_channel_req_drrange_max_type;
static int hf_lorawan_mac_command_down_new_channel_req_drrange_min_type;
static int hf_lorawan_mac_command_up_new_channel_ans_type;
static int hf_lorawan_mac_command_up_new_channel_ans_datarate_type;
static int hf_lorawan_mac_command_up_new_channel_ans_frequency_type;
static int hf_lorawan_mac_command_down_rx_timing_req_delay_type;
static int hf_lorawan_mac_command_up_di_channel_ans_type;
static int hf_lorawan_mac_command_up_ping_slot_info_req_type;
static int hf_lorawan_mac_command_up_ping_slot_channel_ans_type;
static int hf_lorawan_mac_command_up_beacon_freq_ans_type;
static int hf_lorawan_mac_command_down_tx_param_setup_req_type;
static int hf_lorawan_mac_command_down_di_channel_req_type;
static int hf_lorawan_mac_command_down_device_time_ans_type;
static int hf_lorawan_mac_command_down_ping_slot_channel_req_type;
static int hf_lorawan_mac_command_down_beacon_freq_req_type;
static int hf_lorawan_join_request_type;
static int hf_lorawan_join_request_joineui_type;
static int hf_lorawan_join_request_deveui_type;
static int hf_lorawan_join_request_devnonce_type;
static int hf_lorawan_join_accept_type;
static int hf_lorawan_join_accept_joinnonce_type;
static int hf_lorawan_join_accept_netid_type;
static int hf_lorawan_join_accept_devaddr_type;
static int hf_lorawan_join_accept_dlsettings_type;
static int hf_lorawan_join_accept_dlsettings_rx1droffset_type;
static int hf_lorawan_join_accept_dlsettings_rx2dr_type;
static int hf_lorawan_join_accept_rxdelay_type;
static int hf_lorawan_join_accept_cflist_type;
static int hf_lorawan_frame_header_type;
static int hf_lorawan_frame_header_address_type;
static int hf_lorawan_frame_header_frame_control_adr_type;
static int hf_lorawan_frame_header_frame_control_adrackreq_type;
static int hf_lorawan_frame_header_frame_control_ack_type;
static int hf_lorawan_frame_header_frame_control_fpending_type;
static int hf_lorawan_frame_header_frame_control_foptslen_type;
static int hf_lorawan_frame_header_frame_control_type;
static int hf_lorawan_frame_header_frame_counter_type;
static int hf_lorawan_frame_fport_type;
static int hf_lorawan_frame_payload_type;
static int hf_lorawan_frame_payload_decrypted_type;
static int hf_lorawan_mic_type;
static int hf_lorawan_mic_status_type;
static int hf_lorawan_beacon_rfu1_type;
static int hf_lorawan_beacon_time_type;
static int hf_lorawan_beacon_crc1_type;
static int hf_lorawan_beacon_crc1_status_type;
static int hf_lorawan_beacon_gwspecific_type;
static int hf_lorawan_beacon_gwspecific_infodesc_type;
static int hf_lorawan_beacon_gwspecific_lat_type;
static int hf_lorawan_beacon_gwspecific_lng_type;
static int hf_lorawan_beacon_rfu2_type;
static int hf_lorawan_beacon_crc2_type;
static int hf_lorawan_beacon_crc2_status_type;

static int * const hfx_lorawan_mac_command_link_check_ans[] = {
	&hf_lorawan_mac_command_up_link_adr_ans_txpower_type,
	&hf_lorawan_mac_command_up_link_adr_ans_datarate_type,
	&hf_lorawan_mac_command_up_link_adr_ans_channel_mask_type,
	NULL
};
static int * const hfx_lorawan_mac_command_link_adr_req_channel[] = {
	&hf_lorawan_mac_command_down_link_adr_req_channel1_type,
	&hf_lorawan_mac_command_down_link_adr_req_channel2_type,
	&hf_lorawan_mac_command_down_link_adr_req_channel3_type,
	&hf_lorawan_mac_command_down_link_adr_req_channel4_type,
	&hf_lorawan_mac_command_down_link_adr_req_channel5_type,
	&hf_lorawan_mac_command_down_link_adr_req_channel6_type,
	&hf_lorawan_mac_command_down_link_adr_req_channel7_type,
	&hf_lorawan_mac_command_down_link_adr_req_channel8_type,
	&hf_lorawan_mac_command_down_link_adr_req_channel9_type,
	&hf_lorawan_mac_command_down_link_adr_req_channel10_type,
	&hf_lorawan_mac_command_down_link_adr_req_channel11_type,
	&hf_lorawan_mac_command_down_link_adr_req_channel12_type,
	&hf_lorawan_mac_command_down_link_adr_req_channel13_type,
	&hf_lorawan_mac_command_down_link_adr_req_channel14_type,
	&hf_lorawan_mac_command_down_link_adr_req_channel15_type,
	&hf_lorawan_mac_command_down_link_adr_req_channel16_type,
	NULL
};
static int * const hfx_lorawan_mac_command_rx_setup_ans[] = {
	&hf_lorawan_mac_command_up_rx_setup_ans_rx1droffset_type,
	&hf_lorawan_mac_command_up_rx_setup_ans_rx2datarate_type,
	&hf_lorawan_mac_command_up_rx_setup_ans_frequency_type,
	NULL
};
static int * const hfx_lorawan_mac_command_new_channel_ans[] = {
	&hf_lorawan_mac_command_up_new_channel_ans_datarate_type,
	&hf_lorawan_mac_command_up_new_channel_ans_frequency_type,
	NULL
};

static int * const hfx_lorawan_frame_header_frame_control[] = {
	&hf_lorawan_frame_header_frame_control_adr_type,
	&hf_lorawan_frame_header_frame_control_adrackreq_type,
	&hf_lorawan_frame_header_frame_control_ack_type,
	&hf_lorawan_frame_header_frame_control_fpending_type,
	&hf_lorawan_frame_header_frame_control_foptslen_type,
	NULL
};

static int * const hfx_lorawan_join_accept_dlsettings[] = {
	&hf_lorawan_join_accept_dlsettings_rx1droffset_type,
	&hf_lorawan_join_accept_dlsettings_rx2dr_type,
	NULL
};

static int ett_lorawan;
static int ett_lorawan_mac_header;
static int ett_lorawan_mac_commands;
static int ett_lorawan_mac_command;
static int ett_lorawan_mac_command_link_check_ans;
static int ett_lorawan_mac_command_link_adr_req_channel;
static int ett_lorawan_mac_command_rx_setup_ans;
static int ett_lorawan_mac_command_new_channel_ans;
static int ett_lorawan_join_request;
static int ett_lorawan_join_accept;
static int ett_lorawan_join_accept_dlsettings;
static int ett_lorawan_frame_header;
static int ett_lorawan_frame_header_control;
static int ett_lorawan_frame_payload_decrypted;
static int ett_lorawan_beacon;
static int ett_lorawan_beacon_gwspecific;

#define LORAWAN_MAC_FTYPE_MASK						0xE0
#define LORAWAN_MAC_FTYPE(ftype)					(((ftype) & LORAWAN_MAC_FTYPE_MASK) >> 5)

#define LORAWAN_MAC_FTYPE_JOINREQUEST					0
#define LORAWAN_MAC_FTYPE_JOINACCEPT					1
#define LORAWAN_MAC_FTYPE_UNCONFIRMEDDATAUP				2
#define LORAWAN_MAC_FTYPE_UNCONFIRMEDDATADOWN				3
#define LORAWAN_MAC_FTYPE_CONFIRMEDDATAUP				4
#define LORAWAN_MAC_FTYPE_CONFIRMEDDATADOWN				5
#define LORAWAN_MAC_FTYPE_RFU						6
#define LORAWAN_MAC_FTYPE_PROPRIETARY					7
#define LORAWAN_MAC_BEACON						0xFFF0

#define LORAWAN_MAC_RFU_MASK						0x1C

#define LORAWAN_MAC_MAJOR_MASK						0x03
#define LORAWAN_MAC_MAJOR(major)					((major) & LORAWAN_MAC_MAJOR_MASK)

#define LORAWAN_MAC_MAJOR_R1						0

#define LORAWAN_MAC_COMMAND_UP_LINK_CHECK_REQ				0x02
#define LORAWAN_MAC_COMMAND_UP_LINK_ADR_ANS				0x03
#define LORAWAN_MAC_COMMAND_UP_DUTY_ANS					0x04
#define LORAWAN_MAC_COMMAND_UP_RX_SETUP_ANS				0x05
#define LORAWAN_MAC_COMMAND_UP_DEV_STATUS_ANS				0x06
#define LORAWAN_MAC_COMMAND_UP_NEW_CHANNEL_ANS				0x07
#define LORAWAN_MAC_COMMAND_UP_RX_TIMING_ANS				0x08
#define LORAWAN_MAC_COMMAND_UP_TX_PARAM_SETUP_ANS			0x09
#define LORAWAN_MAC_COMMAND_UP_DI_CHANNEL_ANS				0x0A
#define LORAWAN_MAC_COMMAND_UP_DEVICE_TIME_REQ				0x0D
#define LORAWAN_MAC_COMMAND_UP_PING_SLOT_INFO_REQ			0x10
#define LORAWAN_MAC_COMMAND_UP_PING_SLOT_CHANNEL_ANS			0x11
#define LORAWAN_MAC_COMMAND_UP_BEACON_TIMING_REQ			0x12
#define LORAWAN_MAC_COMMAND_UP_BEACON_FREQ_ANS				0x13

#define LORAWAN_MAC_COMMAND_DOWN_LINK_CHECK_ANS				0x02
#define LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ				0x03
#define LORAWAN_MAC_COMMAND_DOWN_DUTY_REQ				0x04
#define LORAWAN_MAC_COMMAND_DOWN_RX_SETUP_REQ				0x05
#define LORAWAN_MAC_COMMAND_DOWN_DEV_STATUS_REQ				0x06
#define LORAWAN_MAC_COMMAND_DOWN_NEW_CHANNEL_REQ			0x07
#define LORAWAN_MAC_COMMAND_DOWN_RX_TIMING_REQ				0x08
#define LORAWAN_MAC_COMMAND_DOWN_TX_PARAM_SETUP_REQ			0x09
#define LORAWAN_MAC_COMMAND_DOWN_DI_CHANNEL_REQ				0x0A
#define LORAWAN_MAC_COMMAND_DOWN_DEVICE_TIME_ANS			0x0D
#define LORAWAN_MAC_COMMAND_DOWN_PING_SLOT_INFO_ANS			0x10
#define LORAWAN_MAC_COMMAND_DOWN_PING_SLOT_CHANNEL_REQ			0x11
#define LORAWAN_MAC_COMMAND_DOWN_BEACON_TIMING_ANS			0x12
#define LORAWAN_MAC_COMMAND_DOWN_BEACON_FREQ_REQ			0x13

#define LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_DATARATE_MASK		0xF0
#define LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_TXPOWER_MASK		0x0F
#define LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_1_MASK		0x0001
#define LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_2_MASK		0x0002
#define LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_3_MASK		0x0004
#define LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_4_MASK		0x0008
#define LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_5_MASK		0x0010
#define LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_6_MASK		0x0020
#define LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_7_MASK		0x0040
#define LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_8_MASK		0x0080
#define LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_9_MASK		0x0100
#define LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_10_MASK		0x0200
#define LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_11_MASK		0x0400
#define LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_12_MASK		0x0800
#define LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_13_MASK		0x1000
#define LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_14_MASK		0x2000
#define LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_15_MASK		0x4000
#define LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_16_MASK		0x8000
#define LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHMASKCNTL_MASK		0x70
#define LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_NBREP_MASK		0x0F
#define LORAWAN_MAC_COMMAND_UP_LINK_ADR_ANS_TXPOWER_MASK		0x04
#define LORAWAN_MAC_COMMAND_UP_LINK_ADR_ANS_DATARATE_MASK		0x02
#define LORAWAN_MAC_COMMAND_UP_LINK_ADR_ANS_CHANNEL_MASK		0x01
#define LORAWAN_MAC_COMMAND_DOWN_RX_SETUP_RX1DROFFSET_MASK		0x70
#define LORAWAN_MAC_COMMAND_DOWN_RX_SETUP_RX2DATARATE_MASK		0x0F
#define LORAWAN_MAC_COMMAND_UP_RX_SETUP_ANS_TXPOWER_MASK		0x04
#define LORAWAN_MAC_COMMAND_UP_RX_SETUP_ANS_DATARATE_MASK		0x02
#define LORAWAN_MAC_COMMAND_UP_RX_SETUP_ANS_CHANNEL_MASK		0x01
#define LORAWAN_MAC_COMMAND_UP_DEVICE_STATUS_ANS_MARGIN_MASK		0x3F
#define LORAWAN_MAC_COMMAND_DOWN_NEW_CHANNEL_REQ_DRRANGE_MAX_MASK	0xF0
#define LORAWAN_MAC_COMMAND_DOWN_NEW_CHANNEL_REQ_DRRANGE_MIN_MASK	0x0F
#define LORAWAN_MAC_COMMAND_UP_NEW_CHANNEL_ANS_DATARATE_MASK		0x02
#define LORAWAN_MAC_COMMAND_UP_NEW_CHANNEL_ANS_FREQUENCY_MASK		0x01
#define LORAWAN_MAC_COMMAND_DOWN_RX_TIMING_REQ_DELAY_MASK		0x0F

#define LORAWAN_JOIN_ACCEPT_RX1DROFFSET_MASK				0x70
#define LORAWAN_JOIN_ACCEPT_RX2DR_MASK					0x0F

#define LORAWAN_FRAME_FOPTSLEN_MASK					0x0F

#define LORAWAN_AES_BLOCK_LENGTH					16
#define LORAWAN_AES_PADDEDSIZE(length)					(LORAWAN_AES_BLOCK_LENGTH * ((length + LORAWAN_AES_BLOCK_LENGTH - 1) / LORAWAN_AES_BLOCK_LENGTH))

static expert_field ei_lorawan_missing_keys;
static expert_field ei_lorawan_decrypting_error;
static expert_field ei_lorawan_mic;
static expert_field ei_lorawan_length_error;
static expert_field ei_lorawan_mhdr_error;

static const value_string lorawan_ftypenames[] = {
	{ LORAWAN_MAC_FTYPE_JOINREQUEST,		"Join Request" },
	{ LORAWAN_MAC_FTYPE_JOINACCEPT,			"Join Accept" },
	{ LORAWAN_MAC_FTYPE_UNCONFIRMEDDATAUP,		"Unconfirmed Data Up" },
	{ LORAWAN_MAC_FTYPE_UNCONFIRMEDDATADOWN,	"Unconfirmed Data Down" },
	{ LORAWAN_MAC_FTYPE_CONFIRMEDDATAUP,		"Confirmed Data Up" },
	{ LORAWAN_MAC_FTYPE_CONFIRMEDDATADOWN,		"Confirmed Data Down" },
	{ LORAWAN_MAC_FTYPE_RFU,			"RFU" },
	{ LORAWAN_MAC_FTYPE_PROPRIETARY,		"Proprietary" },
	// TODO: having this here makes no sense.
	//  It's value doesn't fit into 3 bits, and is only ever looked up with a hardcoded key...
	{ LORAWAN_MAC_BEACON, 				"Class-B Beacon" },
	{ 0, NULL }
};

static const value_string lorawan_majornames[] = {
	{ LORAWAN_MAC_MAJOR_R1,				"LoRaWAN R1" },
	{ 0, NULL }
};

static const value_string lorawan_mac_uplink_commandnames[] = {
	{ LORAWAN_MAC_COMMAND_UP_LINK_CHECK_REQ,	"Network validation request" },
	{ LORAWAN_MAC_COMMAND_UP_LINK_ADR_ANS,		"Data rate adjustment response" },
	{ LORAWAN_MAC_COMMAND_UP_DUTY_ANS,		"Duty-cycle rate set response" },
	{ LORAWAN_MAC_COMMAND_UP_RX_SETUP_ANS,		"Reception slots set response" },
	{ LORAWAN_MAC_COMMAND_UP_DEV_STATUS_ANS,	"Status response" },
	{ LORAWAN_MAC_COMMAND_UP_NEW_CHANNEL_ANS,	"Channel creation/modification response" },
	{ LORAWAN_MAC_COMMAND_UP_RX_TIMING_ANS,		"Reception slots timing set response" },
	{ LORAWAN_MAC_COMMAND_UP_TX_PARAM_SETUP_ANS,	"End-device transmit parameters response" },
	{ LORAWAN_MAC_COMMAND_UP_DI_CHANNEL_ANS,	"Channel DI response" },
	{ LORAWAN_MAC_COMMAND_UP_DEVICE_TIME_REQ,	"End-device time request" },
	{ LORAWAN_MAC_COMMAND_UP_PING_SLOT_INFO_REQ,	"Class-B ping-slot periodicity request" },
	{ LORAWAN_MAC_COMMAND_UP_PING_SLOT_CHANNEL_ANS,	"Class-B ping-slot frequency response" },
	{ LORAWAN_MAC_COMMAND_UP_BEACON_TIMING_REQ,	"Class-B beacon timing request" },
	{ LORAWAN_MAC_COMMAND_UP_BEACON_FREQ_ANS,	"Class-B beacon frequency response" },
	{ 0, NULL }
};

static const value_string lorawan_mac_downlink_commandnames[] = {
	{ LORAWAN_MAC_COMMAND_DOWN_LINK_CHECK_ANS,	"Network validation response" },
	{ LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ,	"Data rate adjustment request" },
	{ LORAWAN_MAC_COMMAND_DOWN_DUTY_REQ,		"Duty-cycle rate set request" },
	{ LORAWAN_MAC_COMMAND_DOWN_RX_SETUP_REQ,	"Reception slots set request" },
	{ LORAWAN_MAC_COMMAND_DOWN_DEV_STATUS_REQ,	"Status request" },
	{ LORAWAN_MAC_COMMAND_DOWN_NEW_CHANNEL_REQ,	"Channel creation/modification request" },
	{ LORAWAN_MAC_COMMAND_DOWN_RX_TIMING_REQ,	"Reception slots timing set request" },
	{ LORAWAN_MAC_COMMAND_DOWN_TX_PARAM_SETUP_REQ,	"End-device transmit parameters request" },
	{ LORAWAN_MAC_COMMAND_DOWN_DI_CHANNEL_REQ,	"Channel DI request" },
	{ LORAWAN_MAC_COMMAND_DOWN_DEVICE_TIME_ANS,	"End-device time response" },
	{ LORAWAN_MAC_COMMAND_DOWN_PING_SLOT_INFO_ANS,	"Class-B ping-slot periodicity response" },
	{ LORAWAN_MAC_COMMAND_DOWN_PING_SLOT_CHANNEL_REQ,	"Class-B ping-slot frequency request" },
	{ LORAWAN_MAC_COMMAND_DOWN_BEACON_TIMING_ANS,	"Class-B beacon timing response" },
	{ LORAWAN_MAC_COMMAND_DOWN_BEACON_FREQ_REQ,	"Class-B beacon frequency request" },
	{ 0, NULL }
};


typedef struct _root_keys_t {
	char		*deveui_string;
	char		*appkey_string;
	GByteArray	*deveui;
	GByteArray	*appkey;
} root_key_t;

typedef struct _session_keys_t {
	char		*dev_addr_string;
	char		*nwkskey_string;
	char		*appskey_string;
	uint32_t		dev_addr;
	GByteArray	*nwkskey;
	GByteArray	*appskey;
} session_key_t;

static root_key_t *root_keys;
static session_key_t *session_keys;
static unsigned root_num_keys;
static unsigned session_num_keys;

static void
byte_array_reverse(GByteArray *arr)
{
	for (unsigned i = 0; i < arr->len / 2; i++) {
		int8_t b = arr->data[i];
		arr->data[i] = arr->data[(arr->len - 1) - i];
		arr->data[(arr->len - 1) - i] = b;
	}
}

static bool
root_keys_update_cb(void *r, char **err)
{
	root_key_t *rec = (root_key_t *)r;

	if (rec->deveui_string == NULL) {
		*err = g_strdup("End-device identifier can't be empty");
		return false;
	}
	if (!rec->deveui) {
		rec->deveui = g_byte_array_new();
	}
	if (!hex_str_to_bytes(rec->deveui_string, rec->deveui, false)) {
		*err = g_strdup("End-device identifier must be hexadecimal");
		return false;
	}
	if (rec->deveui->len != 8) {
		*err = g_strdup("End-device identifier must be 8 bytes hexadecimal");
		return false;
	}
	byte_array_reverse(rec->deveui);

	if (rec->appkey_string == NULL) {
		*err = g_strdup("Application key can't be empty");
		return false;
	}
	if (!rec->appkey) {
		rec->appkey = g_byte_array_new();
	}
	if (!hex_str_to_bytes(rec->appkey_string, rec->appkey, false)) {
		*err = g_strdup("Application key must be hexadecimal");
		return false;
	}
	if (rec->appkey->len != 16) {
		*err = g_strdup("Application key must be 16 bytes hexadecimal");
		return false;
	}

	*err = NULL;
	return true;
}

static void *
root_keys_copy_cb(void *n, const void *o, size_t siz _U_)
{
	root_key_t *new_rec = (root_key_t*)n;
	const root_key_t *old_rec = (const root_key_t*)o;

	if (old_rec->deveui_string) {
		new_rec->deveui_string = g_strdup(old_rec->deveui_string);
		new_rec->deveui = g_byte_array_new();
		hex_str_to_bytes(new_rec->deveui_string, new_rec->deveui, false);
		byte_array_reverse(new_rec->deveui);
	} else {
		new_rec->deveui_string = NULL;
		new_rec->deveui = NULL;
	}

	if (old_rec->appkey_string) {
		new_rec->appkey_string = g_strdup(old_rec->appkey_string);
		new_rec->appkey = g_byte_array_new();
		hex_str_to_bytes(new_rec->appkey_string, new_rec->appkey, false);
	}
	else {
		new_rec->appkey_string = NULL;
		new_rec->appkey = NULL;
	}

	return new_rec;
}

static void
root_keys_free_cb(void *r)
{
	root_key_t *rec = (root_key_t*)r;

	g_free(rec->deveui_string);
	g_byte_array_free(rec->deveui, true);
	g_free(rec->appkey_string);
	g_byte_array_free(rec->appkey, true);
}

static bool
session_keys_update_cb(void *r, char **err)
{
	session_key_t *rec = (session_key_t*)r;

	if (rec->dev_addr_string == NULL) {
		*err = g_strdup("Device address can't be empty");
		return false;
	}
	GByteArray *addr = g_byte_array_new();
	if (!hex_str_to_bytes(rec->dev_addr_string, addr, false)) {
		g_byte_array_free(addr, true);
		*err = g_strdup("Device address must be hexadecimal");
		return false;
	}
	if (addr->len != 4) {
		g_byte_array_free(addr, true);
		*err = g_strdup("Device address must be 4 bytes hexadecimal");
		return false;
	}
	byte_array_reverse(addr);
	memcpy(&rec->dev_addr, addr->data, sizeof(rec->dev_addr));
	g_byte_array_free(addr, true);

	if (rec->nwkskey_string == NULL) {
		*err = g_strdup("Network session key can't be empty");
		return false;
	}
	if (!rec->nwkskey) {
		rec->nwkskey = g_byte_array_new();
	}
	if (!hex_str_to_bytes(rec->nwkskey_string, rec->nwkskey, false)) {
		*err = g_strdup("Network session key must be hexadecimal");
		return false;
	}
	if (rec->nwkskey->len != 16) {
		*err = g_strdup("Network session key must be 16 bytes hexadecimal");
		return false;
	}

	if (rec->appskey_string == NULL) {
		*err = g_strdup("Application session key can't be empty");
		return false;
	}
	if (!rec->appskey) {
		rec->appskey = g_byte_array_new();
	}
	if (!hex_str_to_bytes(rec->appskey_string, rec->appskey, false)) {
		*err = g_strdup("Application session key must be hexadecimal");
		return false;
	}
	if (rec->appskey->len != 16) {
		*err = g_strdup("Application session key must be 16 bytes hexadecimal");
		return false;
	}

	*err = NULL;
	return true;
}

static void *
session_keys_copy_cb(void *n, const void *o, size_t siz _U_)
{
	session_key_t *new_rec = (session_key_t*)n;
	const session_key_t *old_rec = (const session_key_t*)o;

	if (old_rec->dev_addr_string) {
		new_rec->dev_addr_string = g_strdup(old_rec->dev_addr_string);
		GByteArray *addr = g_byte_array_new();
		if (hex_str_to_bytes(new_rec->dev_addr_string, addr, false)) {
			if (addr->len == 4) {
				byte_array_reverse(addr);
				memcpy(&new_rec->dev_addr, addr->data, sizeof(new_rec->dev_addr));
			} else {
				new_rec->dev_addr = 0;
			}
		}
		g_byte_array_free(addr, true);
	} else {
		new_rec->dev_addr_string = NULL;
		new_rec->dev_addr = 0;
	}

	if (old_rec->nwkskey_string) {
		new_rec->nwkskey_string = g_strdup(old_rec->nwkskey_string);
		new_rec->nwkskey = g_byte_array_new();
		hex_str_to_bytes(new_rec->nwkskey_string, new_rec->nwkskey, false);
	} else {
		new_rec->nwkskey_string = NULL;
		new_rec->nwkskey = NULL;
	}

	if (old_rec->appskey_string) {
		new_rec->appskey_string = g_strdup(old_rec->appskey_string);
		new_rec->appskey = g_byte_array_new();
		hex_str_to_bytes(new_rec->appskey_string, new_rec->appskey, false);
	} else {
		new_rec->appskey_string = NULL;
		new_rec->appskey = NULL;
	}

	return new_rec;
}

static void
session_keys_free_cb(void *r)
{
	session_key_t *rec = (session_key_t*)r;

	g_free(rec->dev_addr_string);
	g_free(rec->nwkskey_string);
	g_byte_array_free(rec->nwkskey, true);
	g_free(rec->appskey_string);
	g_byte_array_free(rec->appskey, true);
}

UAT_CSTRING_CB_DEF(root_keys, deveui_string, root_key_t)
UAT_CSTRING_CB_DEF(root_keys, appkey_string, root_key_t)
UAT_CSTRING_CB_DEF(session_keys, dev_addr_string, session_key_t)
UAT_CSTRING_CB_DEF(session_keys, nwkskey_string, session_key_t)
UAT_CSTRING_CB_DEF(session_keys, appskey_string, session_key_t)

static session_key_t *
get_session_key(uint32_t dev_addr)
{
	unsigned i;
	for (i = 0; i < session_num_keys; i++) {
		if (session_keys[i].dev_addr == dev_addr) {
			return &session_keys[i];
		}
	}
	return NULL;
}

static root_key_t *
get_root_key(const uint8_t *deveui)
{
	unsigned i;
	for (i = 0; i < root_num_keys; i++) {
		if (root_keys[i].deveui != NULL && memcmp(root_keys[i].deveui->data, deveui, 8) == 0) {
			return &root_keys[i];
		}
	}
	return NULL;
}

static uint32_t
calculate_mic(const uint8_t *in, uint8_t length, const uint8_t *key)
{
	/*
	 * cmac = aes128_cmac(key, in)
	 * MIC = cmac[0..3]
	 */
	gcry_mac_hd_t mac_hd;
	uint32_t mac;
	size_t read_digest_length = 4;

	if (gcry_mac_open(&mac_hd, GCRY_MAC_CMAC_AES, 0, NULL)) {
		return 0;
	}
	if (gcry_mac_setkey(mac_hd, key, 16)) {
		gcry_mac_close(mac_hd);
		return 0;
	}
	/* Pass in the message */
	if (gcry_mac_write(mac_hd, in, length)) {
		gcry_mac_close(mac_hd);
		return 0;
	}
	/* Read out the digest */
	if (gcry_mac_read(mac_hd, &mac, &read_digest_length)) {
		gcry_mac_close(mac_hd);
		return 0;
	}
	/* Now close the mac handle */
	gcry_mac_close(mac_hd);
	return mac;
}

static nstime_t
gps_to_utctime(const uint32_t gpstime)
{
	nstime_t utctime;
	utctime.secs = (uint64_t)gpstime;
	utctime.secs += 315964800; /* difference between Unix epoch and GPS epoch */
	utctime.secs -= 18; /* leap seconds valid after 2017-01-01 */
	utctime.nsecs = 0;
	return utctime;
}

static void
cf_coords_lat_custom(char *buffer, uint32_t value)
{
	int32_t coord_int = (value < 0x00800000) ? ((int32_t)value) : ((int32_t)value - 0x01000000);
	double coord_double = coord_int * 90. / 0x00800000;

	snprintf(buffer, ITEM_LABEL_LENGTH, "%.5f%c", fabs(coord_double), (coord_double >= 0) ? 'N' : 'S');
}

static void
cf_coords_lng_custom(char *buffer, uint32_t value)
{
	int32_t coord_int = (value < 0x00800000) ? ((int32_t)value) : ((int32_t)value - 0x01000000);
	double coord_double = coord_int * 180. / 0x00800000;

	snprintf(buffer, ITEM_LABEL_LENGTH, "%.5f%c", fabs(coord_double), (coord_double >= 0) ? 'E' : 'W');
}

static bool
aes128_lorawan_encrypt(const uint8_t *key, const uint8_t *data_in, uint8_t *data_out, int length)
{
	gcry_cipher_hd_t cipher;
	if (gcry_cipher_open(&cipher, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, 0)) {
		return false;
	}
	if (gcry_cipher_setkey(cipher, key, LORAWAN_AES_BLOCK_LENGTH)) {
		gcry_cipher_close(cipher);
		return false;
	}
	if (gcry_cipher_encrypt(cipher, data_out, length, data_in, length)) {
		gcry_cipher_close(cipher);
		return false;
	}
	gcry_cipher_close(cipher);
	return true;
}

/* length should be a multiple of 16, in should be padded to get to a multiple of 16 */
static bool
decrypt_lorawan_frame_payload(const uint8_t *in, int length, uint8_t *out, const uint8_t * key, uint8_t dir, uint32_t dev_addr, uint32_t fcnt)
{
	gcry_cipher_hd_t cipher;
	uint8_t iv[LORAWAN_AES_BLOCK_LENGTH] = {0x01, 0x00, 0x00, 0x00, 0x00, dir, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
	memcpy(iv + 6, &dev_addr, 4);
	memcpy(iv + 10, &fcnt, 4);
	if (gcry_cipher_open(&cipher, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR, 0)) {
		return false;
	}
	if (gcry_cipher_setkey(cipher, key, LORAWAN_AES_BLOCK_LENGTH)) {
		gcry_cipher_close(cipher);
		return false;
	}
	if (gcry_cipher_setctr(cipher, iv, 16)) {
		gcry_cipher_close(cipher);
		return false;
	}
	if (gcry_cipher_encrypt(cipher, out, length, in, length)) {
		gcry_cipher_close(cipher);
		return false;
	}
	gcry_cipher_close(cipher);
	return true;
}

static int
dissect_lorawan_mac_commands(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, bool uplink)
{
	proto_item *ti, *tf;
	proto_tree *mac_command_tree, *field_tree;
	uint8_t command;
	int32_t current_offset = 0;

	ti = proto_tree_add_item(tree, hf_lorawan_mac_commands_type, tvb, 0, -1, ENC_NA);
	mac_command_tree = proto_item_add_subtree(ti, ett_lorawan_mac_commands);

	do {
		command = tvb_get_uint8(tvb, current_offset);
		if (uplink) {
			tf = proto_tree_add_item(mac_command_tree, hf_lorawan_mac_command_uplink_type, tvb, current_offset, 1, ENC_NA);
			current_offset++;
			proto_item_append_text(tf, " (%s)", val_to_str_const(command, lorawan_mac_uplink_commandnames, "RFU"));
			switch (command) {
				case LORAWAN_MAC_COMMAND_UP_LINK_CHECK_REQ:
				case LORAWAN_MAC_COMMAND_UP_DUTY_ANS:
				case LORAWAN_MAC_COMMAND_UP_RX_TIMING_ANS:
				case LORAWAN_MAC_COMMAND_UP_TX_PARAM_SETUP_ANS:
				case LORAWAN_MAC_COMMAND_UP_DEVICE_TIME_REQ:
				case LORAWAN_MAC_COMMAND_UP_BEACON_TIMING_REQ:
					/* No payload */
				break;
				case LORAWAN_MAC_COMMAND_UP_LINK_ADR_ANS:
					field_tree = proto_item_add_subtree(tf, ett_lorawan_mac_command);
					proto_tree_add_bitmask(field_tree, tvb, current_offset, hf_lorawan_mac_command_down_link_check_ans_type, ett_lorawan_mac_command_link_check_ans, hfx_lorawan_mac_command_link_check_ans, ENC_NA);
					current_offset++;
				break;
				case LORAWAN_MAC_COMMAND_UP_RX_SETUP_ANS:
					field_tree = proto_item_add_subtree(tf, ett_lorawan_mac_command);
					proto_tree_add_bitmask(field_tree, tvb, current_offset, hf_lorawan_mac_command_up_rx_setup_ans_type, ett_lorawan_mac_command_rx_setup_ans, hfx_lorawan_mac_command_rx_setup_ans, ENC_NA);
					current_offset++;
				break;
				case LORAWAN_MAC_COMMAND_UP_DEV_STATUS_ANS:
					field_tree = proto_item_add_subtree(tf, ett_lorawan_mac_command);
					proto_tree_add_item(field_tree, hf_lorawan_mac_command_up_device_status_ans_battery_type, tvb, current_offset, 1, ENC_NA);
					current_offset++;
					proto_tree_add_item(field_tree, hf_lorawan_mac_command_up_device_status_ans_margin_type, tvb, current_offset, 1, ENC_NA);
					current_offset++;
				break;
				case LORAWAN_MAC_COMMAND_UP_DI_CHANNEL_ANS:
					field_tree = proto_item_add_subtree(tf, ett_lorawan_mac_command);
					proto_tree_add_item(field_tree, hf_lorawan_mac_command_up_di_channel_ans_type, tvb, current_offset, 1, ENC_NA);
					current_offset++;
				break;
				case LORAWAN_MAC_COMMAND_UP_NEW_CHANNEL_ANS:
					field_tree = proto_item_add_subtree(tf, ett_lorawan_mac_command);
					proto_tree_add_bitmask(field_tree, tvb, current_offset, hf_lorawan_mac_command_up_new_channel_ans_type, ett_lorawan_mac_command_new_channel_ans, hfx_lorawan_mac_command_new_channel_ans, ENC_NA);
					current_offset++;
				break;
				case LORAWAN_MAC_COMMAND_UP_PING_SLOT_INFO_REQ:
					field_tree = proto_item_add_subtree(tf, ett_lorawan_mac_command);
					proto_tree_add_item(field_tree, hf_lorawan_mac_command_up_ping_slot_info_req_type, tvb, current_offset, 1, ENC_NA);
					current_offset++;
				break;
				case LORAWAN_MAC_COMMAND_UP_PING_SLOT_CHANNEL_ANS:
					field_tree = proto_item_add_subtree(tf, ett_lorawan_mac_command);
					proto_tree_add_item(field_tree, hf_lorawan_mac_command_up_ping_slot_channel_ans_type, tvb, current_offset, 1, ENC_NA);
					current_offset++;
				break;
				case LORAWAN_MAC_COMMAND_UP_BEACON_FREQ_ANS:
					field_tree = proto_item_add_subtree(tf, ett_lorawan_mac_command);
					proto_tree_add_item(field_tree, hf_lorawan_mac_command_up_beacon_freq_ans_type, tvb, current_offset, 1, ENC_NA);
					current_offset++;
				break;
				default:
					/* End on unknown mac command because command lengths are not explicitly given */
					return tvb_captured_length(tvb);
				break;
			}
		} else {
			tf = proto_tree_add_item(mac_command_tree, hf_lorawan_mac_command_downlink_type, tvb, current_offset, 1, ENC_NA);
			current_offset++;
			proto_item_append_text(tf, " (%s)", val_to_str_const(command, lorawan_mac_downlink_commandnames, "RFU"));
			switch (command) {
				case LORAWAN_MAC_COMMAND_DOWN_LINK_CHECK_ANS:
					field_tree = proto_item_add_subtree(tf, ett_lorawan_mac_command);
					proto_tree_add_item(field_tree, hf_lorawan_mac_command_down_link_check_ans_margin_type, tvb, current_offset, 1, ENC_NA);
					current_offset++;
					proto_tree_add_item(field_tree, hf_lorawan_mac_command_down_link_check_ans_gwcnt_type, tvb, current_offset, 1, ENC_NA);
					current_offset++;
				break;
				case LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ:
					field_tree = proto_item_add_subtree(tf, ett_lorawan_mac_command);
					/* Region specific */
					proto_tree_add_item(field_tree, hf_lorawan_mac_command_down_link_adr_req_datarate_type, tvb, current_offset, 1, ENC_NA);
					proto_tree_add_item(field_tree, hf_lorawan_mac_command_down_link_adr_req_txpower_type, tvb, current_offset, 1, ENC_NA);
					current_offset++;
					proto_tree_add_bitmask(field_tree, tvb, current_offset, hf_lorawan_mac_command_down_link_adr_req_channel_type, ett_lorawan_mac_command_link_adr_req_channel, hfx_lorawan_mac_command_link_adr_req_channel, ENC_LITTLE_ENDIAN);
					current_offset += 2;
					proto_tree_add_item(field_tree, hf_lorawan_mac_command_down_link_adr_req_channel_mask_control_type, tvb, current_offset, 1, ENC_NA);
					proto_tree_add_item(field_tree, hf_lorawan_mac_command_down_link_adr_req_repetitions_type, tvb, current_offset, 1, ENC_NA);
					current_offset++;
				break;
				case LORAWAN_MAC_COMMAND_DOWN_DUTY_REQ:
					field_tree = proto_item_add_subtree(tf, ett_lorawan_mac_command);
					proto_tree_add_item(field_tree, hf_lorawan_mac_command_down_dutycycle_type, tvb, current_offset, 1, ENC_NA);
					current_offset++;
				break;
				case LORAWAN_MAC_COMMAND_DOWN_RX_SETUP_REQ:
					field_tree = proto_item_add_subtree(tf, ett_lorawan_mac_command);
					proto_tree_add_item(field_tree, hf_lorawan_mac_command_down_rx_setup_req_rx1droffset_type, tvb, current_offset, 1, ENC_NA);
					/* Region specific */
					proto_tree_add_item(field_tree, hf_lorawan_mac_command_down_rx_setup_req_rx2datarate_type, tvb, current_offset, 1, ENC_NA);
					current_offset++;
					proto_tree_add_item(field_tree, hf_lorawan_mac_command_down_rx_setup_req_frequency_type, tvb, current_offset, 3, ENC_LITTLE_ENDIAN);
					current_offset += 3;
				break;
				case LORAWAN_MAC_COMMAND_DOWN_DEV_STATUS_REQ:
				case LORAWAN_MAC_COMMAND_DOWN_PING_SLOT_INFO_ANS:
					/* No payload */
				break;
				case LORAWAN_MAC_COMMAND_DOWN_NEW_CHANNEL_REQ:
					field_tree = proto_item_add_subtree(tf, ett_lorawan_mac_command);
					proto_tree_add_item(field_tree, hf_lorawan_mac_command_down_new_channel_req_index_type, tvb, current_offset, 1, ENC_NA);
					current_offset++;
					proto_tree_add_item(field_tree, hf_lorawan_mac_command_down_new_channel_req_frequency_type, tvb, current_offset, 3, ENC_LITTLE_ENDIAN);
					current_offset += 3;
					/* Region specific */
					proto_tree_add_item(field_tree, hf_lorawan_mac_command_down_new_channel_req_drrange_max_type, tvb, current_offset, 1, ENC_NA);
					/* Region specific */
					proto_tree_add_item(field_tree, hf_lorawan_mac_command_down_new_channel_req_drrange_min_type, tvb, current_offset, 1, ENC_NA);
					current_offset++;
				break;
				case LORAWAN_MAC_COMMAND_DOWN_RX_TIMING_REQ:
					field_tree = proto_item_add_subtree(tf, ett_lorawan_mac_command);
					proto_tree_add_item(field_tree, hf_lorawan_mac_command_down_rx_timing_req_delay_type, tvb, current_offset, 1, ENC_NA);
					current_offset++;
				break;
				case LORAWAN_MAC_COMMAND_DOWN_TX_PARAM_SETUP_REQ:
					field_tree = proto_item_add_subtree(tf, ett_lorawan_mac_command);
					proto_tree_add_item(field_tree, hf_lorawan_mac_command_down_tx_param_setup_req_type, tvb, current_offset, 1, ENC_NA);
					current_offset++;
				break;
				case LORAWAN_MAC_COMMAND_DOWN_DI_CHANNEL_REQ:
					field_tree = proto_item_add_subtree(tf, ett_lorawan_mac_command);
					proto_tree_add_item(field_tree, hf_lorawan_mac_command_down_di_channel_req_type, tvb, current_offset, 4, ENC_NA);
					current_offset += 4;
				break;
				case LORAWAN_MAC_COMMAND_DOWN_DEVICE_TIME_ANS:
				case LORAWAN_MAC_COMMAND_DOWN_BEACON_TIMING_ANS:
					/* The time provided is the GPS time at the end of the uplink transmission. The
					 * command has a 5-octet payload defined as follows:
					 *   32-bit unsigned integer: seconds since epoch
					 *   8-bit unsigned integer: fractional-second in 1/256s increments
					 */
					field_tree = proto_item_add_subtree(tf, ett_lorawan_mac_command);
					proto_tree_add_item(field_tree, hf_lorawan_mac_command_down_device_time_ans_type, tvb, current_offset, 5, ENC_NA);
					current_offset += 5;
				break;
				case LORAWAN_MAC_COMMAND_DOWN_PING_SLOT_CHANNEL_REQ:
					field_tree = proto_item_add_subtree(tf, ett_lorawan_mac_command);
					proto_tree_add_item(field_tree, hf_lorawan_mac_command_down_ping_slot_channel_req_type, tvb, current_offset, 4, ENC_NA);
					current_offset += 4;
				break;
				case LORAWAN_MAC_COMMAND_DOWN_BEACON_FREQ_REQ:
					field_tree = proto_item_add_subtree(tf, ett_lorawan_mac_command);
					proto_tree_add_item(field_tree, hf_lorawan_mac_command_down_beacon_freq_req_type, tvb, current_offset, 3, ENC_NA);
					current_offset += 3;
				break;
				default:
					/* End on unknown mac command because command lengths are not explicitly given */
					return tvb_captured_length(tvb);
				break;
			}
		}
	} while (tvb_captured_length_remaining(tvb, current_offset));
	return tvb_captured_length(tvb);
}

static int
dissect_lorawan_beacon(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_)
{
	proto_item *ti;
	proto_tree *gwspecific_tree;
	int32_t current_offset = 0;
	unsigned length = tvb_reported_length(tvb);
	uint16_t calc_crc1, calc_crc2;
	nstime_t utctime;

	proto_tree_add_string(tree, hf_lorawan_msgtype_type, tvb, current_offset, 0, val_to_str_const(LORAWAN_MAC_BEACON, lorawan_ftypenames, "RFU"));

	if (length == 17) {
		calc_crc1 = crc16_r3_ccitt_tvb(tvb, 0, 6);
		calc_crc2 = crc16_r3_ccitt_tvb(tvb, 8, 7);
		proto_tree_add_item(tree, hf_lorawan_beacon_rfu1_type, tvb, current_offset, 2, ENC_NA);
		current_offset += 2;
	} else {
		calc_crc1 = crc16_r3_ccitt_tvb(tvb, 0, 7);
		calc_crc2 = crc16_r3_ccitt_tvb(tvb, 9, 8);
		proto_tree_add_item(tree, hf_lorawan_beacon_rfu1_type, tvb, current_offset, 3, ENC_NA);
		current_offset += 3;
	}
	utctime = gps_to_utctime(tvb_get_uint32(tvb, current_offset, ENC_LITTLE_ENDIAN));
	proto_tree_add_time(tree, hf_lorawan_beacon_time_type, tvb, current_offset, 4, &utctime);
	current_offset += 4;
	proto_tree_add_checksum(tree, tvb, current_offset, hf_lorawan_beacon_crc1_type, hf_lorawan_beacon_crc1_status_type, NULL, pinfo, calc_crc1, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
	current_offset += 2;

	ti = proto_tree_add_item(tree, hf_lorawan_beacon_gwspecific_type, tvb, current_offset, 7, ENC_NA);
	gwspecific_tree = proto_item_add_subtree(ti, ett_lorawan_beacon_gwspecific);
	proto_tree_add_item(gwspecific_tree, hf_lorawan_beacon_gwspecific_infodesc_type, tvb, current_offset, 1, ENC_NA);
	current_offset++;
	proto_tree_add_item(gwspecific_tree, hf_lorawan_beacon_gwspecific_lat_type, tvb, current_offset, 3, ENC_LITTLE_ENDIAN);
	current_offset += 3;
	proto_tree_add_item(gwspecific_tree, hf_lorawan_beacon_gwspecific_lng_type, tvb, current_offset, 3, ENC_LITTLE_ENDIAN);
	current_offset += 3;

	if (length == 19) {
		proto_tree_add_item(tree, hf_lorawan_beacon_rfu2_type, tvb, current_offset, 1, ENC_NA);
		current_offset++;
	}
	proto_tree_add_checksum(tree, tvb, current_offset, hf_lorawan_beacon_crc2_type, hf_lorawan_beacon_crc2_status_type, NULL, pinfo, calc_crc2, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);

	return tvb_captured_length(tvb);
}

static int
dissect_lorawan_join_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_)
{
	proto_item *tf;
	proto_tree *field_tree;
	int32_t current_offset = 1;

	tf = proto_tree_add_item(tree, hf_lorawan_join_request_type, tvb, current_offset, 18, ENC_NA);
	field_tree = proto_item_add_subtree(tf, ett_lorawan_join_request);
	proto_tree_add_item(field_tree, hf_lorawan_join_request_joineui_type, tvb, current_offset, 8, ENC_LITTLE_ENDIAN);
	current_offset += 8;
	proto_tree_add_item(field_tree, hf_lorawan_join_request_deveui_type, tvb, current_offset, 8, ENC_LITTLE_ENDIAN);
	current_offset += 8;
	proto_tree_add_item(field_tree, hf_lorawan_join_request_devnonce_type, tvb, current_offset, 2, ENC_LITTLE_ENDIAN);
	current_offset += 2;

	/* MIC
	 * cmac = aes128_cmac(AppKey, msg)
	 * MIC = cmac[0..3]
	 */
	root_key_t *root_key = get_root_key(tvb_get_ptr(tvb, current_offset - 10, 8));
	if (root_key) {
		proto_tree_add_checksum(tree, tvb, current_offset, hf_lorawan_mic_type, hf_lorawan_mic_status_type, &ei_lorawan_mic, pinfo,
			calculate_mic(tvb_get_ptr(tvb, 0, current_offset), current_offset, root_key->appkey->data), ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
	} else {
		proto_item *checksum_item = proto_tree_add_checksum(tree, tvb, current_offset, hf_lorawan_mic_type, hf_lorawan_mic_status_type, NULL, pinfo,
			0, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
		expert_add_info(pinfo, checksum_item, &ei_lorawan_missing_keys);
	}

	return tvb_captured_length(tvb);
}

static int
dissect_lorawan_join_accept(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_)
{
	proto_item *tf;
	proto_tree *field_tree;
	int32_t current_offset = 1;
	root_key_t *root_key = NULL;

	int length = tvb_captured_length_remaining(tvb, current_offset);
	tf = proto_tree_add_item(tree, hf_lorawan_join_accept_type, tvb, current_offset, 12, ENC_NA);
	field_tree = proto_item_add_subtree(tf, ett_lorawan_join_accept);

	/* Join-Accept may be either 16B or 32B long (including MIC) */
	if (length != 16 && length != 32) {
		expert_add_info(pinfo, field_tree, &ei_lorawan_length_error);
		proto_tree_add_item(tree, hf_lorawan_frame_payload_type, tvb, current_offset, tvb_captured_length_remaining(tvb, current_offset), ENC_NA);
		return tvb_captured_length(tvb);
	}

	/* Iterate through all available root keys for Join-Accept */
	uint8_t *decrypted_buffer = (uint8_t *)wmem_alloc0(pinfo->pool, length);
	uint8_t *mic_buffer = (uint8_t *)wmem_alloc0(pinfo->pool, length - 4 + 1);
	uint32_t mic_check;
	for (unsigned key_idx = 0; key_idx < root_num_keys; key_idx++) {
		if (aes128_lorawan_encrypt(root_keys[key_idx].appkey->data, tvb_get_ptr(tvb, current_offset, length), decrypted_buffer, length)) {
			mic_buffer[0] = tvb_get_uint8(tvb, current_offset - 1); // unencrypted MHDR
			memcpy(&mic_buffer[1], decrypted_buffer, length - 4); // decrypted Join-Accept
			memcpy(&mic_check, &decrypted_buffer[length - 4], 4); // decrypted MIC

			// check for valid MIC of payload decrypted using current AppKey
			if (calculate_mic(mic_buffer, length - 4 + 1, root_keys[key_idx].appkey->data) == mic_check) {
				root_key = &root_keys[key_idx];
				break;
			}
		}
	}

	if (root_key) {
		tvbuff_t *next_tvb = tvb_new_child_real_data(tvb, decrypted_buffer, length, length);
		add_new_data_source(pinfo, next_tvb, "Decrypted payload");
		current_offset = 0;

		proto_tree_add_item(field_tree, hf_lorawan_join_accept_joinnonce_type, next_tvb, current_offset, 3, ENC_LITTLE_ENDIAN);
		current_offset += 3;
		proto_tree_add_item(field_tree, hf_lorawan_join_accept_netid_type, next_tvb, current_offset, 3, ENC_LITTLE_ENDIAN);
		current_offset += 3;
		proto_tree_add_item(field_tree, hf_lorawan_join_accept_devaddr_type, next_tvb, current_offset, 4, ENC_LITTLE_ENDIAN);
		current_offset += 4;
		proto_tree_add_bitmask(field_tree, next_tvb, current_offset, hf_lorawan_join_accept_dlsettings_type, ett_lorawan_join_accept_dlsettings, hfx_lorawan_join_accept_dlsettings, ENC_NA);
		current_offset++;
		proto_tree_add_item(field_tree, hf_lorawan_join_accept_rxdelay_type, next_tvb, current_offset, 1, ENC_NA);
		current_offset++;
		if (tvb_captured_length(next_tvb) - current_offset > 4) {
			proto_tree_add_item(field_tree, hf_lorawan_join_accept_cflist_type, next_tvb, current_offset, 16, ENC_NA);
			current_offset += 16;
			proto_item_set_len(tf, proto_item_get_len(tf) + 16);
		}

		proto_tree_add_checksum(tree, next_tvb, current_offset, hf_lorawan_mic_type, hf_lorawan_mic_status_type, &ei_lorawan_mic, pinfo, 0, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY | PROTO_CHECKSUM_ZERO);
	} else {
		expert_add_info(pinfo, field_tree, &ei_lorawan_missing_keys);
		proto_tree_add_item(tree, hf_lorawan_frame_payload_type, tvb, current_offset, tvb_captured_length_remaining(tvb, current_offset), ENC_NA);
	}

	return tvb_captured_length(tvb);
}

static int
dissect_lorawan_data(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, bool uplink)
{
	proto_item *ti = NULL, *tf;
	proto_tree *field_tree;
	int32_t current_offset = 1;
	uint8_t fopts_length = (tvb_get_uint8(tvb, current_offset + 4) & LORAWAN_FRAME_FOPTSLEN_MASK);
	uint8_t fport = 0;

	/* Frame header */
	tf = proto_tree_add_item(tree, hf_lorawan_frame_header_type, tvb, current_offset, 7 + fopts_length, ENC_NA);
	field_tree = proto_item_add_subtree(tf, ett_lorawan_frame_header);
	proto_tree_add_item(field_tree, hf_lorawan_frame_header_address_type, tvb, current_offset, 4, ENC_LITTLE_ENDIAN);
	uint32_t dev_address = tvb_get_uint32(tvb, current_offset, ENC_LITTLE_ENDIAN);
	current_offset += 4;
	proto_tree_add_bitmask(field_tree, tvb, current_offset, hf_lorawan_frame_header_frame_control_type, ett_lorawan_frame_header_control, hfx_lorawan_frame_header_frame_control, ENC_NA);
	current_offset++;
	proto_tree_add_item(field_tree, hf_lorawan_frame_header_frame_counter_type, tvb, current_offset, 2, ENC_LITTLE_ENDIAN);
	uint32_t fcnt = tvb_get_uint16(tvb, current_offset, ENC_LITTLE_ENDIAN);
	current_offset += 2;

	/*
	 * If fopts_length > 0 then MAC commands are present in fopts field and port cannot be 0
	 * If fopts_length == 0 then port can be any value
	 * If port == 0 then MAC commands are in frame payload
	 */

	if (fopts_length > 0) {
		tvbuff_t *next_tvb = tvb_new_subset_length(tvb, current_offset, fopts_length);
		current_offset += dissect_lorawan_mac_commands(next_tvb, pinfo, tree, uplink);
	}

	if (tvb_captured_length_remaining(tvb, current_offset) > 4) {
		/* FPort present */
		proto_tree_add_item(tree, hf_lorawan_frame_fport_type, tvb, current_offset, 1, ENC_NA);
		fport = tvb_get_uint8(tvb, current_offset);
		current_offset++;
	}

	if ((fopts_length > 0) && (fport == 0)) {
		/* TODO?: error, not allowed */
	}

	uint8_t frmpayload_length = tvb_captured_length_remaining(tvb, current_offset) - 4;
	if (frmpayload_length > 0) {
		ti = proto_tree_add_item(tree, hf_lorawan_frame_payload_type, tvb, current_offset, frmpayload_length, ENC_NA);
	}

	session_key_t *session_key = get_session_key(dev_address);
	if (session_key && frmpayload_length > 0) {
		uint8_t padded_length = LORAWAN_AES_PADDEDSIZE(frmpayload_length);
		uint8_t *decrypted_buffer = (uint8_t *)wmem_alloc0(pinfo->pool, padded_length);
		uint8_t *encrypted_buffer = (uint8_t *)wmem_alloc0(pinfo->pool, padded_length);
		tvb_memcpy(tvb, encrypted_buffer, current_offset, frmpayload_length);
		if (decrypt_lorawan_frame_payload(encrypted_buffer, padded_length, decrypted_buffer, (fport == 0) ? session_key->nwkskey->data : session_key->appskey->data, !uplink, dev_address, fcnt)) {
			tvbuff_t *next_tvb = tvb_new_child_real_data(tvb, decrypted_buffer, frmpayload_length, frmpayload_length);
			add_new_data_source(pinfo, next_tvb, "Decrypted payload");
			proto_tree *frame_payload_decrypted_tree = proto_item_add_subtree(ti, ett_lorawan_frame_payload_decrypted);
			if (fport == 0) {
				current_offset += dissect_lorawan_mac_commands(next_tvb, pinfo, tree, uplink);
			} else {
				/*
				 * fport values 0x01 - 0xDF are application specific
				 * fport values 0xE0 - 0xFF are reserved for future extensions
				 */
				proto_tree_add_bytes(frame_payload_decrypted_tree, hf_lorawan_frame_payload_decrypted_type, next_tvb, 0, frmpayload_length, decrypted_buffer);
				current_offset += frmpayload_length;
			}
		} else {
			proto_tree_add_expert_format(tree, pinfo, &ei_lorawan_decrypting_error, tvb, current_offset, 4, "Decrypting error");
			current_offset += frmpayload_length;
		}
	} else {
		current_offset += frmpayload_length;
	}

	/*
	 * MIC
	 * cmac = aes128_cmac(NwkSKey, B0 | msg)
	 * MIC = cmac[0..3]
	 * B0 = 0x49 | 0x00 | 0x00 | 0x00 | 0x00 | dir | devAddr | fcntup/fcntdown | len(msg)
	 */
	if (session_key) {
		int frame_length = current_offset;
		uint8_t *msg = (uint8_t *)wmem_alloc0(pinfo->pool, frame_length + 16);
		msg[0] = 0x49;
		msg[5] = uplink ? 0 : 1;
		memcpy(msg + 6, &dev_address, 4);
		memcpy(msg + 10, &fcnt, 4);
		msg[15] = frame_length;
		tvb_memcpy(tvb, msg + 16, 0, frame_length);
		proto_tree_add_checksum(tree, tvb, current_offset, hf_lorawan_mic_type, hf_lorawan_mic_status_type, &ei_lorawan_mic, pinfo, calculate_mic(msg, frame_length + 16, session_key->nwkskey->data), ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
	} else {
		proto_item *checksum_item = proto_tree_add_checksum(tree, tvb, current_offset, hf_lorawan_mic_type, hf_lorawan_mic_status_type, NULL, pinfo,
			0, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
		expert_add_info(pinfo, checksum_item, &ei_lorawan_missing_keys);
	}

	return tvb_captured_length(tvb);
}

static int
dissect_lorawan(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	proto_item *ti, *tf;
	proto_tree *lorawan_tree, *field_tree;
	int32_t current_offset = 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "LoRaWAN");
	col_clear(pinfo->cinfo,COL_INFO);
	ti = proto_tree_add_item(tree, proto_lorawan, tvb, 0, -1, ENC_NA);
	lorawan_tree = proto_item_add_subtree(ti, ett_lorawan);

	/* Detect and dissect Class-B beacon frames
	 * common mark: beacon is 17B or 19B long and begins with 2 bytes of zeroed RFU
	 */
	uint16_t classb_rfu = tvb_get_uint16(tvb, current_offset, ENC_LITTLE_ENDIAN);
	unsigned classb_length = tvb_reported_length(tvb);
	if (classb_rfu == 0x0000 && (classb_length == 17 || classb_length == 19)) {
		return dissect_lorawan_beacon(tvb, pinfo, lorawan_tree);
	}

	/* MAC header */
	uint8_t mac_ftype = LORAWAN_MAC_FTYPE(tvb_get_uint8(tvb, current_offset));
	proto_tree_add_string(lorawan_tree, hf_lorawan_msgtype_type, tvb, current_offset, 0, val_to_str_const(mac_ftype, lorawan_ftypenames, "RFU"));
	tf = proto_tree_add_item(lorawan_tree, hf_lorawan_mac_header_type, tvb, current_offset, 1, ENC_NA);
	proto_item_append_text(tf, " (Message Type: %s, Major Version: %s)",
						   val_to_str_const(mac_ftype, lorawan_ftypenames, "RFU"),
						   val_to_str_const(LORAWAN_MAC_MAJOR(tvb_get_uint8(tvb, current_offset)), lorawan_majornames, "RFU"));

	/* Validate MHDR fields for LoRaWAN packet, do not dissect malformed packets */
	if ((tvb_get_uint8(tvb, current_offset) & (LORAWAN_MAC_MAJOR_MASK | LORAWAN_MAC_RFU_MASK)) != LORAWAN_MAC_MAJOR_R1) {
		expert_add_info(pinfo, lorawan_tree, &ei_lorawan_mhdr_error);
		mac_ftype = LORAWAN_MAC_FTYPE_RFU;
	}

	field_tree = proto_item_add_subtree(tf, ett_lorawan_mac_header);
	proto_tree_add_item(field_tree, hf_lorawan_mac_header_ftype_type, tvb, current_offset, 1, ENC_NA);
	proto_tree_add_item(field_tree, hf_lorawan_mac_header_rfu_type, tvb, current_offset, 1, ENC_NA);
	proto_tree_add_item(field_tree, hf_lorawan_mac_header_major_type, tvb, current_offset, 1, ENC_NA);
	current_offset++;

	switch (mac_ftype) {
		case LORAWAN_MAC_FTYPE_JOINREQUEST:
			return dissect_lorawan_join_request(tvb, pinfo, lorawan_tree);

		case LORAWAN_MAC_FTYPE_JOINACCEPT:
			return dissect_lorawan_join_accept(tvb, pinfo, lorawan_tree);

		case LORAWAN_MAC_FTYPE_UNCONFIRMEDDATAUP:
		case LORAWAN_MAC_FTYPE_CONFIRMEDDATAUP:
			return dissect_lorawan_data(tvb, pinfo, lorawan_tree, true /*uplink*/);

		case LORAWAN_MAC_FTYPE_UNCONFIRMEDDATADOWN:
		case LORAWAN_MAC_FTYPE_CONFIRMEDDATADOWN:
			return dissect_lorawan_data(tvb, pinfo, lorawan_tree, false /*downlink*/);

		default: /* LORAWAN_MAC_FTYPE_RFU or LORAWAN_MAC_FTYPE_PROPRIETARY */
			proto_tree_add_item(lorawan_tree, hf_lorawan_frame_payload_type, tvb, current_offset, tvb_captured_length_remaining(tvb, current_offset), ENC_NA);
			return tvb_captured_length(tvb);
	}
}

void
proto_register_lorawan(void)
{
	static hf_register_info hf[] = {
	{ &hf_lorawan_msgtype_type,
		{ "Message type", "lorawan.msgtype",
		FT_STRING, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_header_type,
		{ "MAC Header", "lorawan.mhdr",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		"[MHDR] MAC Header", HFILL }
	},
	{ &hf_lorawan_mac_header_ftype_type,
		{ "Message Type", "lorawan.mhdr.ftype",
		FT_UINT8, BASE_DEC,
		VALS(lorawan_ftypenames), LORAWAN_MAC_FTYPE_MASK,
		"[FType] Message Type", HFILL }
	},
	{ &hf_lorawan_mac_header_rfu_type,
		{ "RFU", "lorawan.mhdr.rfu",
		FT_UINT8, BASE_DEC,
		NULL, LORAWAN_MAC_RFU_MASK,
		"[RFU]", HFILL }
	},
	{ &hf_lorawan_mac_header_major_type,
		{ "Major Version", "lorawan.mhdr.major",
		FT_UINT8, BASE_DEC,
		VALS(lorawan_majornames), LORAWAN_MAC_MAJOR_MASK,
		"[Major] Major Version", HFILL }
	},
	{ &hf_lorawan_mac_commands_type,
		{ "MAC Commands", "lorawan.mac_commands",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_uplink_type,
		{ "Uplink Command", "lorawan.mac_command_uplink",
		FT_UINT8, BASE_DEC,
		VALS(lorawan_mac_uplink_commandnames), 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_downlink_type,
		{ "Downlink Command", "lorawan.mac_command_downlink",
		FT_UINT8, BASE_DEC,
		VALS(lorawan_mac_downlink_commandnames), 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_link_check_ans_type,
		{ "Link Check Answer", "lorawan.link_check_answer",
		FT_UINT8, BASE_HEX,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_link_check_ans_margin_type,
		{ "Demodulation Margin", "lorawan.link_check_answer.margin",
		FT_UINT8, BASE_DEC|BASE_UNIT_STRING,
		&units_decibels, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_link_check_ans_gwcnt_type,
		{ "Gateway Count", "lorawan.link_check_answer.gwcnt",
		FT_UINT8, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_link_adr_req_datarate_type,
		{ "Data Rate", "lorawan.link_adr_request.datarate",
		FT_UINT8, BASE_DEC,
		NULL, LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_DATARATE_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_link_adr_req_txpower_type,
		{ "Transmit Power", "lorawan.link_adr_request.txpower",
		FT_UINT8, BASE_DEC,
		NULL, LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_TXPOWER_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_link_adr_req_channel_type,
		{ "Channel 1", "lorawan.link_adr_request.channel",
		FT_UINT16, BASE_HEX,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_link_adr_req_channel1_type,
		{ "Channel 1", "lorawan.link_adr_request.channel.1",
		FT_BOOLEAN, 16,
		NULL, LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_1_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_link_adr_req_channel2_type,
		{ "Channel 2", "lorawan.link_adr_request.channel.2",
		FT_BOOLEAN, 16,
		NULL, LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_2_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_link_adr_req_channel3_type,
		{ "Channel 3", "lorawan.link_adr_request.channel.3",
		FT_BOOLEAN, 16,
		NULL, LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_3_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_link_adr_req_channel4_type,
		{ "Channel 4", "lorawan.link_adr_request.channel.4",
		FT_BOOLEAN, 16,
		NULL, LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_4_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_link_adr_req_channel5_type,
		{ "Channel 5", "lorawan.link_adr_request.channel.5",
		FT_BOOLEAN, 16,
		NULL, LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_5_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_link_adr_req_channel6_type,
		{ "Channel 6", "lorawan.link_adr_request.channel.6",
		FT_BOOLEAN, 16,
		NULL, LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_6_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_link_adr_req_channel7_type,
		{ "Channel 7", "lorawan.link_adr_request.channel.7",
		FT_BOOLEAN, 16,
		NULL, LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_7_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_link_adr_req_channel8_type,
		{ "Channel 8", "lorawan.link_adr_request.channel.8",
		FT_BOOLEAN, 16,
		NULL, LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_8_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_link_adr_req_channel9_type,
		{ "Channel 9", "lorawan.link_adr_request.channel.9",
		FT_BOOLEAN, 16,
		NULL, LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_9_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_link_adr_req_channel10_type,
		{ "Channel 10", "lorawan.link_adr_request.channel.10",
		FT_BOOLEAN, 16,
		NULL, LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_10_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_link_adr_req_channel11_type,
		{ "Channel 11", "lorawan.link_adr_request.channel.11",
		FT_BOOLEAN, 16,
		NULL, LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_11_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_link_adr_req_channel12_type,
		{ "Channel 12", "lorawan.link_adr_request.channel.12",
		FT_BOOLEAN, 16,
		NULL, LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_12_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_link_adr_req_channel13_type,
		{ "Channel 13", "lorawan.link_adr_request.channel.13",
		FT_BOOLEAN, 16,
		NULL, LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_13_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_link_adr_req_channel14_type,
		{ "Channel 14", "lorawan.link_adr_request.channel.14",
		FT_BOOLEAN, 16,
		NULL, LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_14_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_link_adr_req_channel15_type,
		{ "Channel 15", "lorawan.link_adr_request.channel.15",
		FT_BOOLEAN, 16,
		NULL, LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_15_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_link_adr_req_channel16_type,
		{ "Channel 16", "lorawan.link_adr_request.channel.16",
		FT_BOOLEAN, 16,
		NULL, LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHANNEL_16_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_link_adr_req_channel_mask_control_type,
		{ "Channel Mask Control", "lorawan.link_adr_request.chmaskctl",
		FT_UINT8, BASE_DEC,
		NULL, LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_CHMASKCNTL_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_link_adr_req_repetitions_type,
		{ "Number Of Repetitions", "lorawan.link_adr_request.nbrep",
		FT_UINT8, BASE_DEC,
		NULL, LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ_NBREP_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_up_link_adr_ans_txpower_type,
		{ "Transmit Power Ack", "lorawan.link_adr_response.txpower",
		FT_BOOLEAN, 8,
		NULL, LORAWAN_MAC_COMMAND_UP_LINK_ADR_ANS_TXPOWER_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_up_link_adr_ans_datarate_type,
		{ "Data Rate Ack", "lorawan.link_adr_response.datarate",
		FT_BOOLEAN, 8,
		NULL, LORAWAN_MAC_COMMAND_UP_LINK_ADR_ANS_DATARATE_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_up_link_adr_ans_channel_mask_type,
		{ "Channel Mask Ack", "lorawan.link_adr_response.channelmask",
		FT_BOOLEAN, 8,
		NULL, LORAWAN_MAC_COMMAND_UP_LINK_ADR_ANS_CHANNEL_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_dutycycle_type,
		{ "Duty Cycle", "lorawan.dutycycle_request.dutycycle",
		FT_UINT8, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_rx_setup_req_rx1droffset_type,
		{ "RX1 Datarate Offset", "lorawan.rx_setup_request.rx1droffset",
		FT_UINT8, BASE_DEC,
		NULL, LORAWAN_MAC_COMMAND_DOWN_RX_SETUP_RX1DROFFSET_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_rx_setup_req_rx2datarate_type,
		{ "RX2 Datarate", "lorawan.rx_setup_request.rx2datarate",
		FT_UINT8, BASE_DEC,
		NULL, LORAWAN_MAC_COMMAND_DOWN_RX_SETUP_RX2DATARATE_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_rx_setup_req_frequency_type,
		{ "Frequency", "lorawan.rx_setup_request.frequency",
		FT_UINT24, BASE_DEC|BASE_UNIT_STRING,
		&units_hz, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_up_rx_setup_ans_type,
		{ "RX Setup Response", "lorawan.rx_setup_response",
		FT_UINT8, BASE_HEX,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_up_rx_setup_ans_rx1droffset_type,
		{ "RX1 Datarate Offset Ack", "lorawan.rx_setup_response.rx1droffset",
		FT_BOOLEAN, 8,
		NULL, LORAWAN_MAC_COMMAND_UP_RX_SETUP_ANS_TXPOWER_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_up_rx_setup_ans_rx2datarate_type,
		{ "RX2 Datarate Ack", "lorawan.rx_setup_response.rx2datarate",
		FT_BOOLEAN, 8,
		NULL, LORAWAN_MAC_COMMAND_UP_RX_SETUP_ANS_DATARATE_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_up_rx_setup_ans_frequency_type,
		{ "Frequency Ack", "lorawan.rx_setup_response.frequency",
		FT_BOOLEAN, 8,
		NULL, LORAWAN_MAC_COMMAND_UP_RX_SETUP_ANS_CHANNEL_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_up_device_status_ans_battery_type,
		{ "Battery Level", "lorawan.device_status_response.battery",
		FT_UINT8, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_up_device_status_ans_margin_type,
		{ "Margin", "lorawan.device_status_response.margin",
		FT_UINT8, BASE_DEC,
		NULL, LORAWAN_MAC_COMMAND_UP_DEVICE_STATUS_ANS_MARGIN_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_new_channel_req_index_type,
		{ "Index", "lorawan.new_channel_request.index",
		FT_UINT8, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_new_channel_req_frequency_type,
		{ "Frequency", "lorawan.new_channel_request.frequency",
		FT_UINT24, BASE_DEC|BASE_UNIT_STRING,
		&units_hz, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_new_channel_req_drrange_max_type,
		{ "Maximum Data Rate", "lorawan.new_channel_request.drrange_max",
		FT_UINT8, BASE_DEC,
		NULL, LORAWAN_MAC_COMMAND_DOWN_NEW_CHANNEL_REQ_DRRANGE_MAX_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_new_channel_req_drrange_min_type,
		{ "Minimum Data Rate", "lorawan.new_channel_request.drrange_min",
		FT_UINT8, BASE_DEC,
		NULL, LORAWAN_MAC_COMMAND_DOWN_NEW_CHANNEL_REQ_DRRANGE_MIN_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_up_new_channel_ans_type,
		{ "New Channel Response", "lorawan.new_channel_response",
		FT_UINT8, BASE_HEX,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_up_new_channel_ans_datarate_type,
		{ "Datarate Ack", "lorawan.new_channel_response.datarate",
		FT_BOOLEAN, 8,
		NULL, LORAWAN_MAC_COMMAND_UP_NEW_CHANNEL_ANS_DATARATE_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_up_new_channel_ans_frequency_type,
		{ "Frequency Ack", "lorawan.new_channel_response.frequency",
		FT_BOOLEAN, 8,
		NULL, LORAWAN_MAC_COMMAND_UP_NEW_CHANNEL_ANS_FREQUENCY_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_rx_timing_req_delay_type,
		{ "Delay", "lorawan.rx_timing_request.delay",
		FT_UINT8, BASE_DEC|BASE_UNIT_STRING,
		&units_seconds, LORAWAN_MAC_COMMAND_DOWN_RX_TIMING_REQ_DELAY_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_up_di_channel_ans_type,
		{ "Status", "lorawan.di_channel_response",
		FT_BYTES, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_up_ping_slot_info_req_type,
		{ "PingSlotParam", "lorawan.ping_slot_info_request",
		FT_BYTES, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_up_ping_slot_channel_ans_type,
		{ "Status", "lorawan.ping_slot_channel_response",
		FT_BYTES, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_up_beacon_freq_ans_type,
		{ "Status", "lorawan.beacon_freq_response",
		FT_BYTES, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_tx_param_setup_req_type,
		{ "DwellTime, EIRP", "lorawan.tx_param_setup_request",
		FT_BYTES, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_di_channel_req_type,
		{ "ChIndex, Frequency", "lorawan.di_channel_request",
		FT_BYTES, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_device_time_ans_type,
		{ "DeviceTimeAns", "lorawan.device_time_response",
		FT_BYTES, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_ping_slot_channel_req_type,
		{ "Frequency, DR", "lorawan.ping_slot_channel_request",
		FT_BYTES, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_command_down_beacon_freq_req_type,
		{ "Frequency", "lorawan.beacon_freq_request",
		FT_BYTES, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_join_request_type,
		{ "Join Request", "lorawan.join_request",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_join_request_joineui_type,
		{ "Join-Server identifier", "lorawan.join_request.joineui",
		FT_EUI64, BASE_NONE,
		NULL, 0x0,
		"[JoinEUI] Join-Server identifier", HFILL }
	},
	{ &hf_lorawan_join_request_deveui_type,
		{ "End-device identifier", "lorawan.join_request.deveui",
		FT_EUI64, BASE_NONE,
		NULL, 0x0,
		"[DevEUI] End-device identifier", HFILL }
	},
	{ &hf_lorawan_join_request_devnonce_type,
		{ "Device Nonce", "lorawan.join_request.devnonce",
		FT_UINT16, BASE_DEC,
		NULL, 0x0,
		"[DevNonce] Device Nonce", HFILL }
	},
	{ &hf_lorawan_join_accept_type,
		{ "Join Accept", "lorawan.join_accept",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_join_accept_joinnonce_type,
		{ "Join-Server nonce", "lorawan.join_accept.joinnonce",
		FT_UINT24, BASE_HEX,
		NULL, 0x0,
		"[JoinNonce] Join-Server nonce", HFILL }
	},
	{ &hf_lorawan_join_accept_netid_type,
		{ "Network identifier", "lorawan.join_accept.netid",
		FT_UINT24, BASE_HEX,
		NULL, 0x0,
		"[NetID] Network identifier", HFILL }
	},
	{ &hf_lorawan_join_accept_devaddr_type,
		{ "Device Address", "lorawan.join_accept.devaddr",
		FT_UINT32, BASE_HEX,
		NULL, 0x0,
		"[DevAddr] Device Address", HFILL }
	},
	{ &hf_lorawan_join_accept_dlsettings_type,
		{ "Downlink configuration", "lorawan.join_accept.dlsettings",
		FT_UINT8, BASE_HEX,
		NULL, 0x0,
		"[DLSettings] Downlink configuration", HFILL }
	},
	{ &hf_lorawan_join_accept_dlsettings_rx1droffset_type,
		{ "RX1 Data rate offset", "lorawan.join_accept.dlsettings.rx1droffset",
		FT_UINT8, BASE_DEC,
		NULL, LORAWAN_JOIN_ACCEPT_RX1DROFFSET_MASK,
		"[RX1DROffset] RX1 Data rate offset", HFILL }
	},
	{ &hf_lorawan_join_accept_dlsettings_rx2dr_type,
		{ "RX2 Data rate", "lorawan.join_accept.dlsettings.rx2datarate",
		FT_UINT8, BASE_DEC,
		NULL, LORAWAN_JOIN_ACCEPT_RX2DR_MASK,
		"[RX2DataRate] RX2 Data rate", HFILL }
	},
	{ &hf_lorawan_join_accept_rxdelay_type,
		{ "Delay between TX and RX", "lorawan.join_accept.rxdelay",
		FT_UINT8, BASE_DEC|BASE_UNIT_STRING,
		&units_seconds, 0x0,
		"[RXDelay] Delay between TX and RX", HFILL }
	},
	{ &hf_lorawan_join_accept_cflist_type,
		{ "List of network parameters", "lorawan.join_accept.cflist",
		FT_BYTES, BASE_NONE,
		NULL, 0x0,
		"[CFList] List of network parameters", HFILL }
	},
	{ &hf_lorawan_frame_header_type,
		{ "Frame Header", "lorawan.fhdr",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		"[FHDR] Frame Header", HFILL }
	},
	{ &hf_lorawan_frame_header_address_type,
		{ "Device Address", "lorawan.fhdr.devaddr",
		FT_UINT32, BASE_HEX,
		NULL, 0x0,
		"[DevAddr] Device Address", HFILL }
	},
	{ &hf_lorawan_frame_header_frame_control_type,
		{ "Frame Control", "lorawan.fhdr.fctrl",
		FT_UINT8, BASE_HEX,
		NULL, 0x0,
		"[FCtrl] Frame Control", HFILL }
	},
	{ &hf_lorawan_frame_header_frame_control_adr_type,
		{ "Adaptive Data Rate", "lorawan.fhdr.fctrl.adr",
		FT_BOOLEAN, 8,
		NULL, 0x80,
		"[ADR] Adaptive Data Rate", HFILL }
	},
	{ &hf_lorawan_frame_header_frame_control_adrackreq_type,
		{ "ADR Acknowledgement Request", "lorawan.fhdr.fctrl.adrackreq",
		FT_BOOLEAN, 8,
		NULL, 0x40,
		"[ADRACKReq] ADR Acknowledgement Request(up) / RFU(down)", HFILL}
	},
	{ &hf_lorawan_frame_header_frame_control_ack_type,
		{ "Acknowledgement", "lorawan.fhdr.fctrl.ack",
		FT_BOOLEAN, 8,
		NULL, 0x20,
		"[ACK] Acknowledgement", HFILL }
	},
	{ &hf_lorawan_frame_header_frame_control_fpending_type,
		{ "ClassB Enabled / Frame Pending", "lorawan.fhdr.fctrl.fpending",
		FT_BOOLEAN, 8,
		NULL, 0x10,
		"[FPending/ClassB] ClassB Enabled (up) / Frame Pending (down)", HFILL }
	},
	{ &hf_lorawan_frame_header_frame_control_foptslen_type,
		{ "Frame Options Length", "lorawan.fhdr.fctrl.foptslen",
		FT_UINT8, BASE_DEC,
		NULL, LORAWAN_FRAME_FOPTSLEN_MASK,
		"[FOptsLen] Frame Options Length", HFILL }
	},
	{ &hf_lorawan_frame_header_frame_counter_type,
		{ "Frame Counter", "lorawan.fhdr.fcnt",
		FT_UINT16, BASE_DEC,
		NULL, 0x0,
		"[FCnt] Frame Counter", HFILL }
	},
	{ &hf_lorawan_frame_fport_type,
		{ "Port", "lorawan.fport",
		FT_UINT8, BASE_HEX,
		NULL, 0x0,
		"[FPort] Port", HFILL }
	},
	{ &hf_lorawan_frame_payload_type,
		{ "Frame Payload", "lorawan.frmpayload",
		FT_BYTES, BASE_NONE,
		NULL, 0x0,
		"[FRMPayload] Frame Payload", HFILL }
	},
	{ &hf_lorawan_frame_payload_decrypted_type,
		{ "Decrypted Frame Payload", "lorawan.frmpayload_decrypted",
		FT_BYTES, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_mic_type,
		{ "Message Integrity Code", "lorawan.mic",
		FT_UINT32, BASE_HEX,
		NULL, 0x0,
		"[MIC] Message Integrity Code", HFILL }
	},
	{ &hf_lorawan_mic_status_type,
		{ "Message Integrity Code Status", "lorawan.mic.status",
		FT_UINT8, BASE_NONE,
		VALS(proto_checksum_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_beacon_rfu1_type,
		{ "RFU", "lorawan.beacon.rfu1",
		FT_BYTES, BASE_NONE,
		NULL, 0x0,
		"[RFU]", HFILL}
	},
	{ &hf_lorawan_beacon_time_type,
		{ "Timestamp", "lorawan.beacon.time",
		FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
		NULL, 0x0,
		"[Time] Timestamp", HFILL}
	},
	{ &hf_lorawan_beacon_crc1_type,
		{ "CRC of Timestamp", "lorawan.beacon.crc1",
		FT_UINT16, BASE_HEX,
		NULL, 0x0,
		"[CRC] CRC of Timestamp", HFILL }
	},
	{ &hf_lorawan_beacon_crc1_status_type,
		{ "Beacon Timestamp CRC Status", "lorawan.beacon.crc1.status",
		FT_UINT8, BASE_NONE,
		VALS(proto_checksum_vals), 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_beacon_gwspecific_type,
		{ "Gateway specific part", "lorawan.beacon.gwspecific",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		"[GwSpecific] Gateway specific part", HFILL }
	},
	{ &hf_lorawan_beacon_gwspecific_infodesc_type,
		{ "Information descriptor", "lorawan.beacon.gwspecific.infodesc",
		FT_UINT8, BASE_DEC,
		NULL, 0x0,
		"[InfoDesc] Information descriptor", HFILL }
	},
	{ &hf_lorawan_beacon_gwspecific_lat_type,
		{ "GPS latitude", "lorawan.beacon.gwspecific.lat",
		FT_UINT24, BASE_CUSTOM,
		CF_FUNC(cf_coords_lat_custom), 0x0,
		"[Lat] GPS latitude", HFILL }
	},
	{ &hf_lorawan_beacon_gwspecific_lng_type,
		{ "GPS longitude", "lorawan.beacon.gwspecific.lng",
		FT_UINT24, BASE_CUSTOM,
		CF_FUNC(cf_coords_lng_custom), 0x0,
		"[Lng] GPS longitude", HFILL }
	},
	{ &hf_lorawan_beacon_rfu2_type,
		{ "RFU", "lorawan.beacon.rfu2",
		FT_BYTES, BASE_NONE,
		NULL, 0x0,
		"[RFU]", HFILL }
	},
	{ &hf_lorawan_beacon_crc2_type,
		{ "CRC of GwSpecific", "lorawan.beacon.crc2",
		FT_UINT16, BASE_HEX,
		NULL, 0x0,
		"[CRC] CRC of GwSpecific", HFILL }
	},
	{ &hf_lorawan_beacon_crc2_status_type,
		{ "Beacon GwSpecific CRC Status", "lorawan.beacon.crc2.status",
		FT_UINT8, BASE_NONE,
		VALS(proto_checksum_vals), 0x0,
		NULL, HFILL }
	},
	};

	/* Setup protocol subtree array */
	static int *ett[] = {
		&ett_lorawan,
		&ett_lorawan_mac_header,
		&ett_lorawan_mac_commands,
		&ett_lorawan_mac_command,
		&ett_lorawan_mac_command_link_check_ans,
		&ett_lorawan_mac_command_link_adr_req_channel,
		&ett_lorawan_mac_command_rx_setup_ans,
		&ett_lorawan_mac_command_new_channel_ans,
		&ett_lorawan_join_request,
		&ett_lorawan_join_accept,
		&ett_lorawan_join_accept_dlsettings,
		&ett_lorawan_frame_header,
		&ett_lorawan_frame_header_control,
		&ett_lorawan_frame_payload_decrypted,
		&ett_lorawan_beacon,
		&ett_lorawan_beacon_gwspecific,
	};

	static ei_register_info ei[] = {
		{ &ei_lorawan_missing_keys, { "lorawan.missing_keys", PI_PROTOCOL, PI_NOTE, "Missing encryption keys", EXPFILL }},
		{ &ei_lorawan_decrypting_error, { "lorawan.decrypting_error", PI_DECRYPTION, PI_ERROR, "Error decrypting payload", EXPFILL }},
		{ &ei_lorawan_mic, { "lorawan.mic_bad.expert", PI_CHECKSUM, PI_WARN, "Bad MIC", EXPFILL }},
		{ &ei_lorawan_length_error, { "lorawan.length_error", PI_MALFORMED, PI_ERROR, "Field length is not according to LoRaWAN standard", EXPFILL }},
		{ &ei_lorawan_mhdr_error, { "lorawan.mhdr_error", PI_MALFORMED, PI_ERROR, "LoRaWAN MAC Header malformed", EXPFILL }},
	};

	expert_module_t* expert_lorawan;

	proto_lorawan = proto_register_protocol (
		"LoRaWAN Protocol",	/* name */
		"LoRaWAN",		/* short name */
		"lorawan"		/* abbrev */
	);

	lorawan_handle = register_dissector("lorawan", dissect_lorawan, proto_lorawan);

	proto_register_field_array(proto_lorawan, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_lorawan = expert_register_protocol(proto_lorawan);
	expert_register_field_array(expert_lorawan, ei, array_length(ei));

	static uat_field_t root_keys_uat_fields[] = {
		UAT_FLD_CSTRING(root_keys, deveui_string, "DevEUI", "LoRaWAN End-device Identifier"),
		UAT_FLD_CSTRING(root_keys, appkey_string, "AppKey", "LoRaWAN Application Key"),
		UAT_END_FIELDS
	};
	static uat_field_t session_keys_uat_fields[] = {
		UAT_FLD_CSTRING(session_keys, dev_addr_string, "DevAddr", "LoRaWAN Device Address"),
		UAT_FLD_CSTRING(session_keys, nwkskey_string, "NwkSKey", "LoRaWAN Network Session Key"),
		UAT_FLD_CSTRING(session_keys, appskey_string, "AppSKey", "LoRaWAN Application Session Key"),
		UAT_END_FIELDS
	};

	uat_t *root_keys_uat = uat_new("LoRaWAN Root Keys",
		sizeof(root_key_t),
		"root_keys_lorawan",
		true,
		&root_keys,
		&root_num_keys,
		UAT_AFFECTS_DISSECTION | UAT_AFFECTS_FIELDS,
		NULL,
		root_keys_copy_cb,
		root_keys_update_cb,
		root_keys_free_cb,
		NULL,
		NULL,
		root_keys_uat_fields
	);
	uat_t *session_keys_uat = uat_new("LoRaWAN Session Keys",
		sizeof(session_key_t),
		"session_keys_lorawan",
		true,
		&session_keys,
		&session_num_keys,
		UAT_AFFECTS_DISSECTION | UAT_AFFECTS_FIELDS,
		NULL,
		session_keys_copy_cb,
		session_keys_update_cb,
		session_keys_free_cb,
		NULL,
		NULL,
		session_keys_uat_fields
	);

	module_t *lorawan_module;
	lorawan_module = prefs_register_protocol(proto_lorawan, NULL);
	prefs_register_uat_preference(lorawan_module, "root_keys_lorawan", "LoRaWAN Root Keys",
		"A table to define root encryption keys for LoRaWAN devices, used for Join Request/Accept",
		root_keys_uat);
	prefs_register_uat_preference(lorawan_module, "session_keys_lorawan", "LoRaWAN Session Keys",
		"A table to define session encryption keys for LoRaWAN devices, used for Data Up/Down",
		session_keys_uat);
}

void
proto_reg_handoff_lorawan(void)
{
	dissector_add_uint("loratap.syncword", 0x34, lorawan_handle);
	dissector_add_for_decode_as("udp.port", lorawan_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
