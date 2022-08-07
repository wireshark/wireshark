/* packet-lorawan.c
 * Dissector routines for the LoRaWAN protocol
 * By Erik de Jong <erikdejong@gmail.com>
 * Copyright 2017 Erik de Jong
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include <epan/strutil.h>
#include <wsutil/wsgcrypt.h>

void proto_reg_handoff_lorawan(void);
void proto_register_lorawan(void);

static int proto_lorawan = -1;
static int hf_lorawan_mac_header_type = -1;
static int hf_lorawan_mac_header_mtype_type = -1;
static int hf_lorawan_mac_header_rfu_type = -1;
static int hf_lorawan_mac_header_major_type = -1;
static int hf_lorawan_mac_commands_type = -1;
static int hf_lorawan_mac_command_uplink_type = -1;
static int hf_lorawan_mac_command_downlink_type = -1;
static int hf_lorawan_mac_command_down_link_check_ans_type = -1;
static int hf_lorawan_mac_command_down_link_check_ans_margin_type = -1;
static int hf_lorawan_mac_command_down_link_check_ans_gwcnt_type = -1;
static int hf_lorawan_mac_command_down_link_adr_req_datarate_type = -1;
static int hf_lorawan_mac_command_down_link_adr_req_txpower_type = -1;
static int hf_lorawan_mac_command_down_link_adr_req_channel_type = -1;
static int hf_lorawan_mac_command_down_link_adr_req_channel1_type = -1;
static int hf_lorawan_mac_command_down_link_adr_req_channel2_type = -1;
static int hf_lorawan_mac_command_down_link_adr_req_channel3_type = -1;
static int hf_lorawan_mac_command_down_link_adr_req_channel4_type = -1;
static int hf_lorawan_mac_command_down_link_adr_req_channel5_type = -1;
static int hf_lorawan_mac_command_down_link_adr_req_channel6_type = -1;
static int hf_lorawan_mac_command_down_link_adr_req_channel7_type = -1;
static int hf_lorawan_mac_command_down_link_adr_req_channel8_type = -1;
static int hf_lorawan_mac_command_down_link_adr_req_channel9_type = -1;
static int hf_lorawan_mac_command_down_link_adr_req_channel10_type = -1;
static int hf_lorawan_mac_command_down_link_adr_req_channel11_type = -1;
static int hf_lorawan_mac_command_down_link_adr_req_channel12_type = -1;
static int hf_lorawan_mac_command_down_link_adr_req_channel13_type = -1;
static int hf_lorawan_mac_command_down_link_adr_req_channel14_type = -1;
static int hf_lorawan_mac_command_down_link_adr_req_channel15_type = -1;
static int hf_lorawan_mac_command_down_link_adr_req_channel16_type = -1;
static int hf_lorawan_mac_command_down_link_adr_req_channel_mask_control_type = -1;
static int hf_lorawan_mac_command_down_link_adr_req_repetitions_type = -1;
static int hf_lorawan_mac_command_up_link_adr_ans_txpower_type = -1;
static int hf_lorawan_mac_command_up_link_adr_ans_datarate_type = -1;
static int hf_lorawan_mac_command_up_link_adr_ans_channel_mask_type = -1;
static int hf_lorawan_mac_command_down_dutycycle_type = -1;
static int hf_lorawan_mac_command_down_rx_setup_req_rx1droffset_type = -1;
static int hf_lorawan_mac_command_down_rx_setup_req_rx2datarate_type = -1;
static int hf_lorawan_mac_command_down_rx_setup_req_frequency_type = -1;
static int hf_lorawan_mac_command_up_rx_setup_ans_type = -1;
static int hf_lorawan_mac_command_up_rx_setup_ans_rx1droffset_type = -1;
static int hf_lorawan_mac_command_up_rx_setup_ans_rx2datarate_type = -1;
static int hf_lorawan_mac_command_up_rx_setup_ans_frequency_type = -1;
static int hf_lorawan_mac_command_up_device_status_ans_battery_type = -1;
static int hf_lorawan_mac_command_up_device_status_ans_margin_type = -1;
static int hf_lorawan_mac_command_down_new_channel_req_index_type = -1;
static int hf_lorawan_mac_command_down_new_channel_req_frequency_type = -1;
static int hf_lorawan_mac_command_down_new_channel_req_drrange_max_type = -1;
static int hf_lorawan_mac_command_down_new_channel_req_drrange_min_type = -1;
static int hf_lorawan_mac_command_up_new_channel_ans_type = -1;
static int hf_lorawan_mac_command_up_new_channel_ans_datarate_type = -1;
static int hf_lorawan_mac_command_up_new_channel_ans_frequency_type = -1;
static int hf_lorawan_mac_command_down_rx_timing_req_delay_type = -1;
static int hf_lorawan_join_request_type = -1;
static int hf_lorawan_join_request_appeui_type = -1;
static int hf_lorawan_join_request_deveui_type = -1;
static int hf_lorawan_join_request_devnonce_type = -1;
static int hf_lorawan_join_accept_type = -1;
static int hf_lorawan_join_accept_appnonce_type = -1;
static int hf_lorawan_join_accept_netid_type = -1;
static int hf_lorawan_join_accept_devaddr_type = -1;
static int hf_lorawan_join_accept_dlsettings_rx1droffset_type = -1;
static int hf_lorawan_join_accept_dlsettings_rx2dr_type = -1;
static int hf_lorawan_join_accept_rxdelay_type = -1;
static int hf_lorawan_join_accept_cflist_type = -1;
static int hf_lorawan_frame_header_type = -1;
static int hf_lorawan_frame_header_address_type = -1;
static int hf_lorawan_frame_header_frame_control_adr_type = -1;
static int hf_lorawan_frame_header_frame_control_adrackreq_type = -1;
static int hf_lorawan_frame_header_frame_control_ack_type = -1;
static int hf_lorawan_frame_header_frame_control_fpending_type = -1;
static int hf_lorawan_frame_header_frame_control_foptslen_type = -1;
static int hf_lorawan_frame_header_frame_control_type = -1;
static int hf_lorawan_frame_header_frame_counter_type = -1;
static int hf_lorawan_frame_fport_type = -1;
static int hf_lorawan_frame_payload_type = -1;
static int hf_lorawan_frame_payload_decrypted_type = -1;
static int hf_lorawan_mic_type = -1;
static int hf_lorawan_mic_status_type = -1;

static gint ett_lorawan = -1;
static gint ett_lorawan_mac_header = -1;
static gint ett_lorawan_mac_commands = -1;
static gint ett_lorawan_mac_command = -1;
static gint ett_lorawan_mac_command_link_check_ans = -1;
static gint ett_lorawan_mac_command_link_adr_req_channel = -1;
static gint ett_lorawan_mac_command_rx_setup_ans = -1;
static gint ett_lorawan_mac_command_new_channel_ans = -1;
static gint ett_lorawan_join_request = -1;
static gint ett_lorawan_join_accept = -1;
static gint ett_lorawan_frame_header = -1;
static gint ett_lorawan_frame_header_control = -1;
static gint ett_lorawan_frame_payload_decrypted = -1;

#define LORAWAN_MAC_MTYPE_MASK						0xE0
#define LORAWAN_MAC_MTYPE(mtype)					(((mtype) & LORAWAN_MAC_MTYPE_MASK) >> 5)

#define LORAWAN_MAC_MTYPE_JOINREQUEST					0
#define LORAWAN_MAC_MTYPE_JOINACCEPT					1
#define LORAWAN_MAC_MTYPE_UNCONFIRMEDDATAUP				2
#define LORAWAN_MAC_MTYPE_UNCONFIRMEDDATADOWN				3
#define LORAWAN_MAC_MTYPE_CONFIRMEDDATAUP				4
#define LORAWAN_MAC_MTYPE_CONFIRMEDDATADOWN				5
#define LORAWAN_MAC_MTYPE_PROPRIETARY					7

#define LORAWAN_MAC_RFU_MASK						0x1C

#define LORAWAN_MAC_MAJOR_MASK						0x03
#define LORAWAN_MAC_MAJOR(major)					((major) & LORAWAN_MAC_MAJOR_MASK)

#define LORAWAN_MAC_MAJOR_R1						0

#define LORAWAN_MAC_COMMAND_UP_LINK_CHECK_REQ				2
#define LORAWAN_MAC_COMMAND_UP_LINK_ADR_ANS				3
#define LORAWAN_MAC_COMMAND_UP_DUTY_ANS					4
#define LORAWAN_MAC_COMMAND_UP_RX_SETUP_ANS				5
#define LORAWAN_MAC_COMMAND_UP_DEV_STATUS_ANS				6
#define LORAWAN_MAC_COMMAND_UP_NEW_CHANNEL_ANS				7
#define LORAWAN_MAC_COMMAND_UP_RX_TIMING_ANS				8

#define LORAWAN_MAC_COMMAND_DOWN_LINK_CHECK_ANS				2
#define LORAWAN_MAC_COMMAND_DOWN_LINK_ADR_REQ				3
#define LORAWAN_MAC_COMMAND_DOWN_DUTY_REQ				4
#define LORAWAN_MAC_COMMAND_DOWN_RX_SETUP_REQ				5
#define LORAWAN_MAC_COMMAND_DOWN_DEV_STATUS_REQ				6
#define LORAWAN_MAC_COMMAND_DOWN_NEW_CHANNEL_REQ			7
#define LORAWAN_MAC_COMMAND_DOWN_RX_TIMING_REQ				8

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
#define LORAWAN_AES_PADDEDSIZE(length)					(length + (16 - (length % 16)))

static expert_field ei_lorawan_unverified_mic = EI_INIT;
static expert_field ei_lorawan_decrypting_error = EI_INIT;
static expert_field ei_lorawan_mic = EI_INIT;

static const value_string lorawan_mtypenames[] = {
	{ LORAWAN_MAC_MTYPE_JOINREQUEST,		"Join Request" },
	{ LORAWAN_MAC_MTYPE_JOINACCEPT,			"Join Accept" },
	{ LORAWAN_MAC_MTYPE_UNCONFIRMEDDATAUP,		"Unconfirmed Data Up" },
	{ LORAWAN_MAC_MTYPE_UNCONFIRMEDDATADOWN,	"Unconfirmed Data Down" },
	{ LORAWAN_MAC_MTYPE_CONFIRMEDDATAUP,		"Confirmed Data Up" },
	{ LORAWAN_MAC_MTYPE_CONFIRMEDDATADOWN,		"Confirmed Data Down" },
	{ LORAWAN_MAC_MTYPE_PROPRIETARY,		"Proprietary" },
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
	{ 0, NULL }
};


typedef struct _device_encryption_keys_t {
	gchar		*dev_addr_string;
	gchar		*nwkskey_string;
	gchar		*appskey_string;
	gchar		*appeui_string;
	guint32		dev_addr;
	GByteArray	*nwkskey;
	GByteArray	*appskey;
	GByteArray	*appeui;
} device_encryption_keys_t;

static device_encryption_keys_t *device_encryption_keys = NULL;
static guint device_encryption_num_keys = 0;

static gboolean
device_encryption_keys_update_cb(void *r, char **err)
{
	device_encryption_keys_t *rec = (device_encryption_keys_t *)r;

	if (rec->dev_addr_string == NULL) {
		*err = g_strdup("Device address can't be empty");
		return FALSE;
	}
	GByteArray *addr = g_byte_array_new();
	if (!hex_str_to_bytes(rec->dev_addr_string, addr, FALSE)) {
		g_byte_array_free(addr, TRUE);
		*err = g_strdup("Device address must be hexadecimal");
		return FALSE;
	}
	if (addr->len != 4) {
		g_byte_array_free(addr, TRUE);
		*err = g_strdup("Device address must be 4 bytes hexadecimal");
		return FALSE;
	}
	rec->dev_addr = *(guint32*)addr->data;
	g_byte_array_free(addr, TRUE);

	if (rec->nwkskey_string == NULL) {
		*err = g_strdup("Network key can't be empty");
		return FALSE;
	}
	if (!rec->nwkskey) {
		rec->nwkskey = g_byte_array_new();
	}
	if (!hex_str_to_bytes(rec->nwkskey_string, rec->nwkskey, FALSE)) {
		*err = g_strdup("Network encryption key must be hexadecimal");
		return FALSE;
	}
	if (rec->nwkskey->len != 16) {
		*err = g_strdup("Network encryption key must be 16 bytes hexadecimal");
		return FALSE;
	}

	if (rec->appskey_string == NULL) {
		*err = g_strdup("Application key can't be empty");
		return FALSE;
	}
	if (!rec->appskey) {
		rec->appskey = g_byte_array_new();
	}
	if (!hex_str_to_bytes(rec->appskey_string, rec->appskey, FALSE)) {
		*err = g_strdup("Application encryption key must be hexadecimal");
		return FALSE;
	}
	if (rec->appskey->len != 16) {
		*err = g_strdup("Application encryption key must be 16 bytes hexadecimal");
		return FALSE;
	}

	if (rec->appeui_string == NULL) {
		*err = g_strdup("Application eui can't be empty");
		return FALSE;
	}
	if (!rec->appeui) {
		rec->appeui = g_byte_array_new();
	}
	if (!hex_str_to_bytes(rec->appeui_string, rec->appeui, FALSE)) {
		*err = g_strdup("Application eui must be hexadecimal");
		return FALSE;
	}
	if (rec->appeui->len != 8) {
		*err = g_strdup("Application eui must be 8 bytes hexadecimal");
		return FALSE;
	}

	*err = NULL;
	return TRUE;
}

static void *
device_encryption_keys_copy_cb(void *n, const void *o, size_t siz _U_)
{
	device_encryption_keys_t* new_rec = (device_encryption_keys_t*)n;
	const device_encryption_keys_t* old_rec = (const device_encryption_keys_t*)o;

	if (old_rec->dev_addr_string) {
		new_rec->dev_addr_string = g_strdup(old_rec->dev_addr_string);
		GByteArray *addr = g_byte_array_new();
		if (hex_str_to_bytes(new_rec->dev_addr_string, addr, FALSE)) {
			if (addr->len == 4) {
				new_rec->dev_addr = *(guint32*)addr->data;
			} else {
				new_rec->dev_addr = 0;
			}
		}
		g_byte_array_free(addr, TRUE);
	} else {
		new_rec->dev_addr_string = NULL;
		new_rec->dev_addr = 0;
	}

	if (old_rec->nwkskey_string) {
		new_rec->nwkskey_string = g_strdup(old_rec->nwkskey_string);
		new_rec->nwkskey = g_byte_array_new();
		hex_str_to_bytes(new_rec->nwkskey_string, new_rec->nwkskey, FALSE);
	} else {
		new_rec->nwkskey_string = NULL;
		new_rec->nwkskey = NULL;
	}

	if (old_rec->appskey_string) {
		new_rec->appskey_string = g_strdup(old_rec->appskey_string);
		new_rec->appskey = g_byte_array_new();
		hex_str_to_bytes(new_rec->appskey_string, new_rec->appskey, FALSE);
	} else {
		new_rec->appskey_string = NULL;
		new_rec->appskey = NULL;
	}

	if (old_rec->appeui_string) {
		new_rec->appeui_string = g_strdup(old_rec->appeui_string);
		new_rec->appeui = g_byte_array_new();
		hex_str_to_bytes(new_rec->appeui_string, new_rec->appeui, FALSE);
	} else {
		new_rec->appeui_string = NULL;
		new_rec->appeui = NULL;
	}

	return new_rec;
}

static void
device_encryption_keys_free_cb(void *r)
{
	device_encryption_keys_t *rec = (device_encryption_keys_t*)r;

	g_free(rec->dev_addr_string);
	g_free(rec->nwkskey_string);
	g_byte_array_free(rec->nwkskey, TRUE);
	g_free(rec->appskey_string);
	g_byte_array_free(rec->appskey, TRUE);
	g_free(rec->appeui_string);
	g_byte_array_free(rec->appeui, TRUE);
}

UAT_CSTRING_CB_DEF(device_encryption_keys, dev_addr_string, device_encryption_keys_t)
UAT_CSTRING_CB_DEF(device_encryption_keys, nwkskey_string, device_encryption_keys_t)
UAT_CSTRING_CB_DEF(device_encryption_keys, appskey_string, device_encryption_keys_t)
UAT_CSTRING_CB_DEF(device_encryption_keys, appeui_string, device_encryption_keys_t)

static device_encryption_keys_t *get_encryption_keys_dev_address(guint32 dev_addr)
{
	guint i;
	for (i = 0; i < device_encryption_num_keys; i++) {
		if (device_encryption_keys[i].dev_addr == dev_addr) {
			return &device_encryption_keys[i];
		}
	}
	return NULL;
}

static device_encryption_keys_t *get_encryption_keys_app_eui(const guint8 *appeui)
{
	guint i;
	for (i = 0; i < device_encryption_num_keys; i++) {
		if (device_encryption_keys[i].appeui) {
			if (!memcmp(device_encryption_keys[i].appeui->data, appeui, 8)) {
				return &device_encryption_keys[i];
			}
		}
	}
	return NULL;
}

static guint32
calculate_mic(const guint8 *in, guint8 length, const guint8 *key)
{
	/*
	 * cmac = aes128_cmac(key, in)
	 * MIC = cmac[0..3]
	 */
	gcry_mac_hd_t mac_hd;
	guint32 mac;
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

/* length should be a multiple of 16, in should be padded to get to a multiple of 16 */
static gboolean
decrypt_lorawan_frame_payload(const guint8 *in, gint length, guint8 *out, const guint8 * key, guint8 dir, guint32 dev_addr, guint32 fcnt)
{
	gcry_cipher_hd_t cipher;
	guint8 iv[LORAWAN_AES_BLOCK_LENGTH] = {0x01, 0x00, 0x00, 0x00, 0x00, dir, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
	memcpy(iv + 6, &dev_addr, 4);
	memcpy(iv + 10, &fcnt, 4);
	if (gcry_cipher_open(&cipher, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR, 0)) {
		return FALSE;
	}
	if (gcry_cipher_setkey(cipher, key, LORAWAN_AES_BLOCK_LENGTH)) {
		gcry_cipher_close(cipher);
		return FALSE;
	}
	if (gcry_cipher_setctr(cipher, iv, 16)) {
		gcry_cipher_close(cipher);
		return FALSE;
	}
	if (gcry_cipher_encrypt(cipher, out, length, in, length)) {
		gcry_cipher_close(cipher);
		return FALSE;
	}
	gcry_cipher_close(cipher);
	return TRUE;
}

static int
dissect_lorawan_mac_commands(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gboolean uplink)
{
	proto_item *ti, *tf;
	proto_tree *mac_command_tree, *field_tree;
	guint8 command;
	gint32 current_offset = 0;

	static int * const link_adr_ans_flags[] = {
		&hf_lorawan_mac_command_up_link_adr_ans_txpower_type,
		&hf_lorawan_mac_command_up_link_adr_ans_datarate_type,
		&hf_lorawan_mac_command_up_link_adr_ans_channel_mask_type,
		NULL
	};
	static int * const link_adr_req_channel_flags[] = {
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
	static int * const rx_setup_ans_flags[] = {
		&hf_lorawan_mac_command_up_rx_setup_ans_rx1droffset_type,
		&hf_lorawan_mac_command_up_rx_setup_ans_rx2datarate_type,
		&hf_lorawan_mac_command_up_rx_setup_ans_frequency_type,
		NULL
	};
	static int * const new_channel_ans_flags[] = {
		&hf_lorawan_mac_command_up_new_channel_ans_datarate_type,
		&hf_lorawan_mac_command_up_new_channel_ans_frequency_type,
		NULL
	};

	ti = proto_tree_add_item(tree, hf_lorawan_mac_commands_type, tvb, 0, -1, ENC_NA);
	mac_command_tree = proto_item_add_subtree(ti, ett_lorawan_mac_commands);

	do {
		command = tvb_get_guint8(tvb, current_offset);
		if (uplink) {
			tf = proto_tree_add_item(mac_command_tree, hf_lorawan_mac_command_uplink_type, tvb, current_offset, 1, ENC_NA);
			current_offset++;
			proto_item_append_text(tf, " (%s)", val_to_str(command, lorawan_mac_uplink_commandnames, "RFU"));
			switch (command) {
				case LORAWAN_MAC_COMMAND_UP_LINK_CHECK_REQ:
				case LORAWAN_MAC_COMMAND_UP_DUTY_ANS:
				case LORAWAN_MAC_COMMAND_UP_RX_TIMING_ANS:
					/* No payload */
				break;
				case LORAWAN_MAC_COMMAND_UP_LINK_ADR_ANS:
					field_tree = proto_item_add_subtree(tf, ett_lorawan_mac_command);
					proto_tree_add_bitmask(field_tree, tvb, current_offset, hf_lorawan_mac_command_down_link_check_ans_type, ett_lorawan_mac_command_link_check_ans, link_adr_ans_flags, ENC_NA);
					current_offset++;
				break;
				case LORAWAN_MAC_COMMAND_UP_RX_SETUP_ANS:
					field_tree = proto_item_add_subtree(tf, ett_lorawan_mac_command);
					proto_tree_add_bitmask(field_tree, tvb, current_offset, hf_lorawan_mac_command_up_rx_setup_ans_type, ett_lorawan_mac_command_rx_setup_ans, rx_setup_ans_flags, ENC_NA);
					current_offset++;
				break;
				case LORAWAN_MAC_COMMAND_UP_DEV_STATUS_ANS:
					field_tree = proto_item_add_subtree(tf, ett_lorawan_mac_command);
					proto_tree_add_item(field_tree, hf_lorawan_mac_command_up_device_status_ans_battery_type, tvb, current_offset, 1, ENC_NA);
					current_offset++;
					proto_tree_add_item(field_tree, hf_lorawan_mac_command_up_device_status_ans_margin_type, tvb, current_offset, 1, ENC_NA);
					current_offset++;
				break;
				case LORAWAN_MAC_COMMAND_UP_NEW_CHANNEL_ANS:
					field_tree = proto_item_add_subtree(tf, ett_lorawan_mac_command);
					proto_tree_add_bitmask(field_tree, tvb, current_offset, hf_lorawan_mac_command_up_new_channel_ans_type, ett_lorawan_mac_command_new_channel_ans, new_channel_ans_flags, ENC_NA);
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
			proto_item_append_text(tf, " (%s)", val_to_str(command, lorawan_mac_downlink_commandnames, "RFU"));
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
					proto_tree_add_bitmask(field_tree, tvb, current_offset, hf_lorawan_mac_command_down_link_adr_req_channel_type, ett_lorawan_mac_command_link_adr_req_channel, link_adr_req_channel_flags, ENC_LITTLE_ENDIAN);
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
dissect_lorawan(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	proto_item *ti, *tf;
	proto_tree *lorawan_tree, *field_tree, *frame_payload_decrypted_tree;
	gint32 current_offset = 0;
	guint8 mac_mtype;
	guint8 fopts_length = 0;
	guint8 frmpayload_length = 0;
	guint8 fport;
	guint32 dev_address;
	guint32 fcnt;
	proto_item *checksum_item;
	gboolean uplink = TRUE;
	device_encryption_keys_t *encryption_keys = NULL;

	static int * const flags[] = {
		&hf_lorawan_frame_header_frame_control_adr_type,
		&hf_lorawan_frame_header_frame_control_adrackreq_type,
		&hf_lorawan_frame_header_frame_control_ack_type,
		&hf_lorawan_frame_header_frame_control_fpending_type,
		&hf_lorawan_frame_header_frame_control_foptslen_type,
		NULL
	};

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "LoRaWAN");
	col_clear(pinfo->cinfo,COL_INFO);
	ti = proto_tree_add_item(tree, proto_lorawan, tvb, 0, -1, ENC_NA);
	lorawan_tree = proto_item_add_subtree(ti, ett_lorawan);

	/* MAC header */
	tf = proto_tree_add_item(lorawan_tree, hf_lorawan_mac_header_type, tvb, current_offset, 1, ENC_NA);
	mac_mtype = LORAWAN_MAC_MTYPE(tvb_get_guint8(tvb, current_offset));
	proto_item_append_text(tf, " (Message Type: %s, Major Version: %s)", val_to_str(mac_mtype, lorawan_mtypenames, "RFU"), val_to_str(LORAWAN_MAC_MAJOR(tvb_get_guint8(tvb, current_offset)), lorawan_majornames, "RFU"));

	field_tree = proto_item_add_subtree(tf, ett_lorawan_mac_header);
	proto_tree_add_item(field_tree, hf_lorawan_mac_header_mtype_type, tvb, current_offset, 1, ENC_NA);
	proto_tree_add_item(field_tree, hf_lorawan_mac_header_rfu_type, tvb, current_offset, 1, ENC_NA);
	proto_tree_add_item(field_tree, hf_lorawan_mac_header_major_type, tvb, current_offset, 1, ENC_NA);
	current_offset++;

	if (mac_mtype == LORAWAN_MAC_MTYPE_JOINREQUEST) {
		tf = proto_tree_add_item(lorawan_tree, hf_lorawan_join_request_type, tvb, current_offset, 18, ENC_NA);
		field_tree = proto_item_add_subtree(tf, ett_lorawan_join_request);
		proto_tree_add_item(field_tree, hf_lorawan_join_request_appeui_type, tvb, current_offset, 8, ENC_LITTLE_ENDIAN);
		current_offset += 8;
		proto_tree_add_item(field_tree, hf_lorawan_join_request_deveui_type, tvb, current_offset, 8, ENC_LITTLE_ENDIAN);
		current_offset += 8;
		proto_tree_add_item(field_tree, hf_lorawan_join_request_devnonce_type, tvb, current_offset, 2, ENC_NA);
		current_offset += 2;

		/* MIC
		 * cmac = aes128_cmac(AppKey, msg)
		 * MIC = cmac[0..3]
		 */
		encryption_keys = get_encryption_keys_app_eui(tvb_get_ptr(tvb, current_offset - 18, 8));
		if (encryption_keys) {
			proto_tree_add_checksum(lorawan_tree, tvb, current_offset, hf_lorawan_mic_type, hf_lorawan_mic_status_type, &ei_lorawan_mic, pinfo,
								calculate_mic(tvb_get_ptr(tvb, 0, current_offset), current_offset, encryption_keys->appskey->data), ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
		} else {
			checksum_item = proto_tree_add_checksum(lorawan_tree, tvb, current_offset, hf_lorawan_mic_type, hf_lorawan_mic_status_type, NULL, pinfo,
								0, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
			expert_add_info(pinfo, checksum_item, &ei_lorawan_unverified_mic);
		}
		return tvb_captured_length(tvb);
	} else if (mac_mtype == LORAWAN_MAC_MTYPE_JOINACCEPT) {
		tf = proto_tree_add_item(lorawan_tree, hf_lorawan_join_accept_type, tvb, current_offset, 12, ENC_NA);
		field_tree = proto_item_add_subtree(tf, ett_lorawan_join_accept);
		proto_tree_add_item(field_tree, hf_lorawan_join_accept_appnonce_type, tvb, current_offset, 3, ENC_NA);
		current_offset += 3;
		proto_tree_add_item(field_tree, hf_lorawan_join_accept_netid_type, tvb, current_offset, 3, ENC_NA);
		current_offset += 3;
		proto_tree_add_item(field_tree, hf_lorawan_join_accept_devaddr_type, tvb, current_offset, 4, ENC_LITTLE_ENDIAN);
		dev_address = tvb_get_guint32(tvb, current_offset, ENC_LITTLE_ENDIAN);
		current_offset += 4;
		proto_tree_add_item(field_tree, hf_lorawan_join_accept_dlsettings_rx1droffset_type, tvb, current_offset, 1, ENC_NA);
		proto_tree_add_item(field_tree, hf_lorawan_join_accept_dlsettings_rx2dr_type, tvb, current_offset, 1, ENC_NA);
		current_offset++;
		proto_tree_add_item(field_tree, hf_lorawan_join_accept_rxdelay_type, tvb, current_offset, 1, ENC_NA);
		current_offset++;
		if (tvb_captured_length(tvb) - current_offset > 4) {
			proto_tree_add_item(field_tree, hf_lorawan_join_accept_cflist_type, tvb, current_offset, 16, ENC_NA);
			current_offset += 16;
			proto_item_set_len(tf, proto_item_get_len(tf) + 16);
		}

		/* MIC
		 * cmac = aes128_cmac(AppKey, msg)
		 * MIC = cmac[0..3]
		 */
		encryption_keys = get_encryption_keys_dev_address(dev_address);
		if (encryption_keys) {
			proto_tree_add_checksum(lorawan_tree, tvb, current_offset, hf_lorawan_mic_type, hf_lorawan_mic_status_type, &ei_lorawan_mic, pinfo, calculate_mic(tvb_get_ptr(tvb, 0, current_offset), current_offset, encryption_keys->appskey->data), ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
		} else {
			checksum_item = proto_tree_add_checksum(lorawan_tree, tvb, current_offset, hf_lorawan_mic_type, hf_lorawan_mic_status_type, NULL, pinfo,
								0, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
			expert_add_info(pinfo, checksum_item, &ei_lorawan_unverified_mic);
		}
		return tvb_captured_length(tvb);
	} else if ((mac_mtype >= LORAWAN_MAC_MTYPE_UNCONFIRMEDDATAUP) && (mac_mtype <= LORAWAN_MAC_MTYPE_CONFIRMEDDATADOWN)) {
		if (mac_mtype & 1) {
			uplink = FALSE;
		}
		fopts_length = (tvb_get_guint8(tvb, current_offset + 4) & LORAWAN_FRAME_FOPTSLEN_MASK);
		/* Frame header */
		tf = proto_tree_add_item(lorawan_tree, hf_lorawan_frame_header_type, tvb, current_offset, 7 + fopts_length, ENC_NA);
		field_tree = proto_item_add_subtree(tf, ett_lorawan_frame_header);
		proto_tree_add_item(field_tree, hf_lorawan_frame_header_address_type, tvb, current_offset, 4, ENC_LITTLE_ENDIAN);
		dev_address = tvb_get_guint32(tvb, current_offset, ENC_LITTLE_ENDIAN);
		current_offset += 4;
		proto_tree_add_bitmask(field_tree, tvb, current_offset, hf_lorawan_frame_header_frame_control_type, ett_lorawan_frame_header_control, flags, ENC_NA);
		current_offset++;
		proto_tree_add_item(field_tree, hf_lorawan_frame_header_frame_counter_type, tvb, current_offset, 2, ENC_LITTLE_ENDIAN);
		fcnt = tvb_get_guint16(tvb, current_offset, ENC_LITTLE_ENDIAN);
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

		proto_tree_add_item(lorawan_tree, hf_lorawan_frame_fport_type, tvb, current_offset, 1, ENC_NA);
		fport = tvb_get_guint8(tvb, current_offset);
		current_offset++;

		if ((fopts_length > 0) && (fport == 0)) {
			/* TODO?: error, not allowed */
		}

		frmpayload_length = tvb_captured_length_remaining(tvb, current_offset) - 4;
		ti = proto_tree_add_item(lorawan_tree, hf_lorawan_frame_payload_type, tvb, current_offset, frmpayload_length, ENC_NA);
		encryption_keys = get_encryption_keys_dev_address(dev_address);
		if (encryption_keys) {
			guint8 padded_length = LORAWAN_AES_PADDEDSIZE(frmpayload_length);
			guint8 *decrypted_buffer = (guint8*)wmem_alloc0(pinfo->pool, padded_length);
			guint8 *encrypted_buffer = (guint8*)wmem_alloc0(pinfo->pool, padded_length);
			memcpy(encrypted_buffer, tvb_get_ptr(tvb, current_offset, frmpayload_length), frmpayload_length);
			if (decrypt_lorawan_frame_payload(encrypted_buffer, padded_length, decrypted_buffer, encryption_keys->appskey->data, !uplink, dev_address, fcnt)) {
				tvbuff_t *next_tvb = tvb_new_child_real_data(tvb, decrypted_buffer,frmpayload_length, frmpayload_length);
				add_new_data_source(pinfo, next_tvb, "Decrypted payload");
				frame_payload_decrypted_tree = proto_item_add_subtree(ti, ett_lorawan_frame_payload_decrypted);
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
				proto_tree_add_expert_format(lorawan_tree, pinfo, &ei_lorawan_decrypting_error, tvb, current_offset, 4, "Decrypting error");
				current_offset += frmpayload_length;
			}
		} else {
			current_offset += frmpayload_length;
		}
	} else {
		/* RFU */
		current_offset = tvb_captured_length(tvb) - 4;
	}

	/*
	 * MIC
	 * cmac = aes128_cmac(NwkSKey, B0 | msg)
	 * MIC = cmac[0..3]
	 * B0 = 0x49 | 0x00 | 0x00 | 0x00 | 0x00 | dir | devAddr | fcntup/fcntdown | len(msg)
	 */
	if (encryption_keys) {
		gint frame_length = current_offset;
		guint8 *msg = (guint8 *)wmem_alloc0(pinfo->pool, frame_length + 16);
		msg[0] = 0x49;
		msg[5] = uplink ? 0 : 1;
		memcpy(msg + 6, &dev_address, 4);
		memcpy(msg + 10, &fcnt, 4);
		msg[15] = frame_length;
		memcpy(msg + 16, tvb_get_ptr(tvb, 0, frame_length), frame_length);
		proto_tree_add_checksum(lorawan_tree, tvb, current_offset, hf_lorawan_mic_type, hf_lorawan_mic_status_type, &ei_lorawan_mic, pinfo, calculate_mic(msg, frame_length + 16, encryption_keys->nwkskey->data), ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
	} else {
		checksum_item = proto_tree_add_checksum(lorawan_tree, tvb, current_offset, hf_lorawan_mic_type, hf_lorawan_mic_status_type, NULL, pinfo,
							0, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
		expert_add_info(pinfo, checksum_item, &ei_lorawan_unverified_mic);
	}
	return tvb_captured_length(tvb);
}

void
proto_register_lorawan(void)
{
	static hf_register_info hf[] = {
	{ &hf_lorawan_mac_header_type,
		{ "MAC Header", "lorawan.mhdr",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_header_mtype_type,
		{ "Message Type", "lorawan.mhdr.mtype",
		FT_UINT8, BASE_DEC,
		VALS(lorawan_mtypenames), LORAWAN_MAC_MTYPE_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_mac_header_rfu_type,
		{ "RFU", "lorawan.mhdr.rfu",
		FT_UINT8, BASE_DEC,
		NULL, LORAWAN_MAC_RFU_MASK,
		"Reserved for Future Use", HFILL }
	},
	{ &hf_lorawan_mac_header_major_type,
		{ "Major Version", "lorawan.mhdr.major",
		FT_UINT8, BASE_DEC,
		VALS(lorawan_majornames), LORAWAN_MAC_MAJOR_MASK,
		NULL, HFILL }
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
	{ &hf_lorawan_join_request_type,
		{ "Join Request", "lorawan.join_request",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_join_request_appeui_type,
		{ "AppEUI", "lorawan.join_request.appeui",
		FT_EUI64, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_join_request_deveui_type,
		{ "DevEUI", "lorawan.join_request.deveui",
		FT_EUI64, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_join_request_devnonce_type,
		{ "Device Nonce", "lorawan.join_request.devnonce",
		FT_BYTES, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_join_accept_type,
		{ "Join Accept", "lorawan.join_accept",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_join_accept_appnonce_type,
		{ "Application Nonce", "lorawan.join_accept.appnonce",
		FT_BYTES, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_join_accept_netid_type,
		{ "Net ID", "lorawan.join_accept.netid",
		FT_BYTES, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_join_accept_devaddr_type,
		{ "Device Address", "lorawan.join_accept.devaddr",
		FT_UINT32, BASE_HEX,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_join_accept_dlsettings_rx1droffset_type,
		{ "RX1 Datarate Offset", "lorawan.join_accept.rx1droffset",
		FT_UINT8, BASE_DEC,
		NULL, LORAWAN_JOIN_ACCEPT_RX1DROFFSET_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_join_accept_dlsettings_rx2dr_type,
		{ "RX2 Datarate", "lorawan.join_accept.rx2datarate",
		FT_UINT8, BASE_DEC,
		NULL, LORAWAN_JOIN_ACCEPT_RX2DR_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_join_accept_rxdelay_type,
		{ "RX Delay", "lorawan.join_accept.rxdelay",
		FT_UINT8, BASE_DEC|BASE_UNIT_STRING,
		&units_seconds, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_join_accept_cflist_type,
		{ "Channel Frequency List", "lorawan.join_accept.cflist",
		FT_BYTES, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_frame_header_type,
		{ "Frame Header", "lorawan.fhdr",
		FT_NONE, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_frame_header_address_type,
		{ "Device Address", "lorawan.fhdr.devaddr",
		FT_UINT32, BASE_HEX,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_frame_header_frame_control_type,
		{ "Frame Control", "lorawan.fhdr.fctrl",
		FT_UINT8, BASE_HEX,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_frame_header_frame_control_adr_type,
		{ "Adaptive Data Rate", "lorawan.fhdr.fctrl.adr",
		FT_BOOLEAN, 8,
		NULL, 0x80,
		NULL, HFILL }
	},
	{ &hf_lorawan_frame_header_frame_control_adrackreq_type,
		{ "ADR Acknowledgement Request", "lorawan.fhdr.fctrl.adrackreq",
		FT_BOOLEAN, 8,
		NULL, 0x40,
		NULL, HFILL }
	},
	{ &hf_lorawan_frame_header_frame_control_ack_type,
		{ "ACK", "lorawan.fhdr.fctrl.ack",
		FT_BOOLEAN, 8,
		NULL, 0x20,
		NULL, HFILL }
	},
	{ &hf_lorawan_frame_header_frame_control_fpending_type,
		{ "Frame Pending", "lorawan.fhdr.fctrl.fpending",
		FT_BOOLEAN, 8,
		NULL, 0x10,
		NULL, HFILL }
	},
	{ &hf_lorawan_frame_header_frame_control_foptslen_type,
		{ "Frame Options Length", "lorawan.fhdr.fctrl.foptslen",
		FT_UINT8, BASE_DEC,
		NULL, LORAWAN_FRAME_FOPTSLEN_MASK,
		NULL, HFILL }
	},
	{ &hf_lorawan_frame_header_frame_counter_type,
		{ "Frame Counter", "lorawan.fhdr.fcnt",
		FT_UINT16, BASE_DEC,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_frame_fport_type,
		{ "FPort", "lorawan.fport",
		FT_UINT8, BASE_HEX,
		NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_lorawan_frame_payload_type,
		{ "Frame Payload", "lorawan.frmpayload",
		FT_BYTES, BASE_NONE,
		NULL, 0x0,
		NULL, HFILL }
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
		NULL, HFILL }
	},
	{ &hf_lorawan_mic_status_type,
		{ "Message Integrity Code Status", "lorawan.mic.status",
		FT_UINT8, BASE_NONE,
		VALS(proto_checksum_vals), 0x0,
		NULL, HFILL }
	}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
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
		&ett_lorawan_frame_header,
		&ett_lorawan_frame_header_control,
		&ett_lorawan_frame_payload_decrypted
	};

	static ei_register_info ei[] = {
		{ &ei_lorawan_unverified_mic, { "lorawan.mic_unverified", PI_PROTOCOL, PI_NOTE, "MIC could not be verified because of missing encryption keys", EXPFILL }},
		{ &ei_lorawan_decrypting_error, { "lorawan.decrypting_error", PI_DECRYPTION, PI_ERROR, "Error decrypting payload", EXPFILL }},
		{ &ei_lorawan_mic, { "lorawan.mic_bad.expert", PI_CHECKSUM, PI_WARN, "Bad MIC", EXPFILL }}
	};

	expert_module_t* expert_lorawan;

	proto_lorawan = proto_register_protocol (
		"LoRaWAN Protocol",	/* name */
		"LoRaWAN",		/* short name */
		"lorawan"		/* abbrev */
	);

	register_dissector("lorawan", dissect_lorawan, proto_lorawan);

	proto_register_field_array(proto_lorawan, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_lorawan = expert_register_protocol(proto_lorawan);
	expert_register_field_array(expert_lorawan, ei, array_length(ei));

	static uat_field_t device_encryption_keys_uat_fields[] = {
		UAT_FLD_CSTRING(device_encryption_keys, dev_addr_string, "Device Address", "LoRaWAN Device Address"),
		UAT_FLD_CSTRING(device_encryption_keys, nwkskey_string, "Network Key", "LoRaWAN Network Key"),
		UAT_FLD_CSTRING(device_encryption_keys, appskey_string, "Application Key", "LoRaWAN Application Key"),
		UAT_FLD_CSTRING(device_encryption_keys, appeui_string, "Application EUI", "LoRaWAN Application EUI"),
		UAT_END_FIELDS
	};

	uat_t *device_encryption_keys_uat = uat_new("LoRaWAN Encryption Keys",
		sizeof(device_encryption_keys_t),
		"encryption_keys_lorawan",
		TRUE,
		&device_encryption_keys,
		&device_encryption_num_keys,
		UAT_AFFECTS_DISSECTION|UAT_AFFECTS_FIELDS,
		NULL,
		device_encryption_keys_copy_cb,
		device_encryption_keys_update_cb,
		device_encryption_keys_free_cb,
		NULL,
		NULL,
		device_encryption_keys_uat_fields
	);

	module_t *lorawan_module;
	lorawan_module = prefs_register_protocol(proto_lorawan, NULL);
	prefs_register_uat_preference(lorawan_module, "encryption_keys_lorawan", "LoRaWAN Encryption Keys",
		"A table to define encryption keys for LoRaWAN devices",
		device_encryption_keys_uat);
}

void
proto_reg_handoff_lorawan(void)
{
	dissector_handle_t lorawan_handle;
	lorawan_handle = create_dissector_handle(dissect_lorawan, proto_lorawan);
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
