/* packet-bt-mijia.c
 * Routines for Bluetooth Mijia Protocol
 *
 * Copyright 2021, Lingao Meng <menglingao@xiaomi.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref: Mijia Bluetooth Protocol
 * https://wiki.n.miui.com/pages/viewpage.action?pageId=15478509
 */

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <glib.h>
#include <wsutil/wsgcrypt.h>
#include <epan/expert.h>
#include <stdio.h>
#include <epan/uat.h>
#include <epan/reassemble.h>

/* UAT Network, Beacon key entry structure. */
typedef struct
{
	gchar *beacon_key_string;
	guint8 *beacon_key;
	gint beacon_key_length;

	guint8 valid; /* Valid */
} uat_mijia_record_t;

static uat_mijia_record_t *uat_mijia_records = NULL;

static uat_t *mijia_uat = NULL;
static guint num_mijia_uat = 0;

UAT_CSTRING_CB_DEF(uat_mijia_records, beacon_key_string, uat_mijia_record_t)

void proto_register_bt_mijia_beacon(void);

static int proto_bt_mijia_beacon = -1;

static int hf_bt_mijia_sd_frame_control = -1;
static int hf_bt_mijia_sd_frame_control_rfu = -1;
static int hf_bt_mijia_sd_frame_control_locate = -1;
static int hf_bt_mijia_sd_frame_control_encrypted = -1;
static int hf_bt_mijia_sd_frame_control_mac_include = -1;
static int hf_bt_mijia_sd_frame_control_capability_include = -1;
static int hf_bt_mijia_sd_frame_control_object_include = -1;
static int hf_bt_mijia_sd_frame_control_mesh_include = -1;
static int hf_bt_mijia_sd_frame_control_registered = -1;
static int hf_bt_mijia_sd_frame_control_solicited = -1;
static int hf_bt_mijia_sd_frame_control_auth_mode = -1;
static int hf_bt_mijia_sd_frame_control_version = -1;

static int hf_bt_mijia_sd_product_id = -1;

static int hf_bt_mijia_sd_frame_counter = -1;

static int hf_bt_mijia_sd_ble_mac = -1;
static int hf_bt_mijia_sd_capability = -1;
static int hf_bt_mijia_sd_capability_connectable = -1;
static int hf_bt_mijia_sd_capability_centralable = -1;
static int hf_bt_mijia_sd_capability_encryptable = -1;
static int hf_bt_mijia_sd_capability_bondtability = -1;
static int hf_bt_mijia_sd_capability_io_include = -1;
static int hf_bt_mijia_sd_capability_rfu = -1;

static int hf_bt_mijia_sd_wifi_mac_address = -1;
static int hf_bt_mijia_sd_io_capability = -1;
static int hf_bt_mijia_sd_io_capability_input_6_number = -1;
static int hf_bt_mijia_sd_io_capability_input_6_char = -1;
static int hf_bt_mijia_sd_io_capability_read_nfc_tag = -1;
static int hf_bt_mijia_sd_io_capability_scan_qr_code = -1;
static int hf_bt_mijia_sd_io_capability_output_6_number = -1;
static int hf_bt_mijia_sd_io_capability_output_6_char = -1;
static int hf_bt_mijia_sd_io_capability_gene_nfc_tag = -1;
static int hf_bt_mijia_sd_io_capability_gene_qr_code = -1;
static int hf_bt_mijia_sd_io_capability_rfu = -1;

static int hf_bt_mijia_sd_object = -1;
static int hf_bt_mijia_sd_object_id = -1;
static int hf_bt_mijia_sd_object_len = -1;
static int hf_bt_mijia_sd_object_raw = -1;

static int hf_bt_mijia_sd_extended_frame_counter = -1;
static int hf_bt_mijia_sd_message_integrity_check = -1;

static int hf_bt_mijia_sd_mesh = -1;
static int hf_bt_mijia_sd_mesh_pb_adv_support = -1;
static int hf_bt_mijia_sd_mesh_pb_gatt_support = -1;

static int hf_bt_mijia_sd_mesh_state = -1;
static int hf_bt_mijia_sd_mesh_version = -1;
static int hf_bt_mijia_sd_mesh_rfu = -1;

static int ett_mijia_beacon = -1;
static int ett_mijia_beacon_frame_control = -1;
static int ett_mijia_beacon_oob = -1;
static int ett_mijia_beacon_obj = -1;
static int ett_mijia_beacon_capa = -1;
static int ett_mijia_beacon_mesh = -1;

static expert_field ei_mijia_beacon_unknown_payload = EI_INIT;

static int * const hfx_bt_mijia_sd_frame_control[] = {
    &hf_bt_mijia_sd_frame_control_rfu,
    &hf_bt_mijia_sd_frame_control_locate,
    &hf_bt_mijia_sd_frame_control_encrypted,
    &hf_bt_mijia_sd_frame_control_mac_include,
    &hf_bt_mijia_sd_frame_control_capability_include,
    &hf_bt_mijia_sd_frame_control_object_include,
    &hf_bt_mijia_sd_frame_control_mesh_include,
    &hf_bt_mijia_sd_frame_control_registered,
    &hf_bt_mijia_sd_frame_control_solicited,
    &hf_bt_mijia_sd_frame_control_auth_mode,
    &hf_bt_mijia_sd_frame_control_version,
    NULL
};

static int * const hfx_bt_mijia_sd_capability[] = {
    &hf_bt_mijia_sd_capability_connectable,
    &hf_bt_mijia_sd_capability_centralable,
    &hf_bt_mijia_sd_capability_encryptable,
    &hf_bt_mijia_sd_capability_bondtability,
    &hf_bt_mijia_sd_capability_io_include,
    &hf_bt_mijia_sd_capability_rfu,
    NULL
};

static int * const hfx_bt_mijia_sd_io_capability[] = {
    &hf_bt_mijia_sd_io_capability_input_6_number,
    &hf_bt_mijia_sd_io_capability_input_6_char,
    &hf_bt_mijia_sd_io_capability_read_nfc_tag,
    &hf_bt_mijia_sd_io_capability_scan_qr_code,
    &hf_bt_mijia_sd_io_capability_output_6_number,
    &hf_bt_mijia_sd_io_capability_output_6_char,
    &hf_bt_mijia_sd_io_capability_gene_nfc_tag,
    &hf_bt_mijia_sd_io_capability_gene_qr_code,
    &hf_bt_mijia_sd_io_capability_rfu,
    NULL
};

static gint
dissect_mijia_beacon_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

	proto_item *item, *obj_item, *mesh_item;
	proto_tree *sub_tree, *obj_tree, *mesh_tree;
	guint offset = 0;
	guint8 nonce[12];

	guint16 frame_control = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Mijia Beacon");
	item = proto_tree_add_item(tree, proto_bt_mijia_beacon, tvb, offset, -1, ENC_NA);
	sub_tree = proto_item_add_subtree(item, ett_mijia_beacon);

	proto_tree_add_bitmask(sub_tree, tvb, offset, hf_bt_mijia_sd_frame_control, ett_mijia_beacon,  hfx_bt_mijia_sd_frame_control, ENC_BIG_ENDIAN);
	offset += 2;

	memcpy(nonce + 6, tvb_get_ptr(tvb, offset, 2), 2);
	proto_tree_add_item(sub_tree, hf_bt_mijia_sd_product_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	memcpy(nonce + 6 + 2, tvb_get_ptr(tvb, offset, 1), 1);
	proto_tree_add_item(sub_tree, hf_bt_mijia_sd_frame_counter, tvb, offset, 1, ENC_NA);
	offset += 1;

	if (frame_control & 0x0010)
	{
		memcpy(nonce, tvb_get_ptr(tvb, offset, 6), 6);
		proto_tree_add_item(sub_tree, hf_bt_mijia_sd_ble_mac, tvb, offset, 6, ENC_NA);
		offset += 6;
	}

	if (frame_control & 0x0020)
	{
		guint8 capa = tvb_get_guint8(tvb, offset);

		proto_tree_add_bitmask(sub_tree, tvb, offset, hf_bt_mijia_sd_capability, ett_mijia_beacon, hfx_bt_mijia_sd_capability, ENC_NA);
		offset += 1;

		if ((capa & 0x18) == 0x18)
		{
			proto_tree_add_item(sub_tree, hf_bt_mijia_sd_wifi_mac_address, tvb, offset, 2, ENC_NA);
			offset += 2;
		}

		if (capa & 0x20)
		{
			proto_tree_add_bitmask(sub_tree, tvb, offset, hf_bt_mijia_sd_io_capability, ett_mijia_beacon,  hfx_bt_mijia_sd_io_capability, ENC_BIG_ENDIAN);
			offset += 2;
		}
	}

	if ((frame_control & 0x0040) && (frame_control & 0x0008))
	{
		guint obj_len = tvb_reported_length_remaining(tvb, offset) - 7 - 3 + 1;
		guint8 *decrypted_data;
		gcry_error_t gcrypt_err;
		gcry_cipher_hd_t cipher_hd;
		guint64 ccm_lengths[3];
		guint i = 0;
		gint8 aad = 0x11, tag[4];
		tvbuff_t *de_cry_tvb;

		memcpy(nonce + 6 + 2 + 1, tvb_get_ptr(tvb, offset + obj_len, 3), 3);

		obj_item = proto_tree_add_item(sub_tree, hf_bt_mijia_sd_object, tvb, offset, obj_len, ENC_NA);
		obj_tree = proto_item_add_subtree(obj_item, hf_bt_mijia_sd_object);

		for (i = 0; i < num_mijia_uat; i++)
		{
			if (uat_mijia_records[i].valid == 0)
			{
				continue;
			}

			if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CCM, 0))
			{
				continue;
			}

			gcrypt_err = gcry_cipher_setkey(cipher_hd, uat_mijia_records[i].beacon_key, 16);
			if (gcrypt_err != 0)
			{
				gcry_cipher_close(cipher_hd);
				continue;
			}

			/* Load nonce */
			gcrypt_err = gcry_cipher_setiv(cipher_hd, &nonce, 12);
			if (gcrypt_err != 0)
			{
				gcry_cipher_close(cipher_hd);
				continue;
			}
			/* */
			ccm_lengths[0] = obj_len;
			ccm_lengths[1] = 1; /* aad */
			ccm_lengths[2] = 4; /* icv */

			gcrypt_err = gcry_cipher_ctl(cipher_hd, GCRYCTL_SET_CCM_LENGTHS, ccm_lengths, sizeof(ccm_lengths));
			if (gcrypt_err != 0)
			{
				gcry_cipher_close(cipher_hd);
				continue;
			}

			gcrypt_err = gcry_cipher_authenticate(cipher_hd, &aad, 1);
			if (gcrypt_err != 0)
			{
				gcry_cipher_close(cipher_hd);
				continue;
			}

			decrypted_data = (guint8 *)wmem_alloc(pinfo->pool, obj_len);

			/* Decrypt */
			gcrypt_err = gcry_cipher_decrypt(cipher_hd, decrypted_data, obj_len, tvb_get_ptr(tvb, offset, obj_len), obj_len);
			if (gcrypt_err != 0)
			{
				gcry_cipher_close(cipher_hd);
				continue;
			}

			gcrypt_err = gcry_cipher_gettag(cipher_hd, tag, 4);
			if (gcrypt_err != 0)
			{
				gcry_cipher_close(cipher_hd);
				continue;
			}

			gcry_cipher_close(cipher_hd);

			if (memcmp(tag, tvb_get_ptr(tvb, offset + obj_len + 3, 4), 4))
			{
				continue;
			}

			de_cry_tvb = tvb_new_child_real_data(tvb, decrypted_data, obj_len, obj_len);
			add_new_data_source(pinfo, de_cry_tvb, "Decrypted beacon data");

			proto_tree_add_item(obj_tree, hf_bt_mijia_sd_object_id, de_cry_tvb, 0, 2, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(obj_tree, hf_bt_mijia_sd_object_len, de_cry_tvb, 2, 1, ENC_NA);
			proto_tree_add_item(obj_tree, hf_bt_mijia_sd_object_raw, de_cry_tvb, 3, obj_len - 3, ENC_NA);
			break;
		}

		offset += obj_len;

		proto_tree_add_item(sub_tree, hf_bt_mijia_sd_extended_frame_counter, tvb, offset, 3, ENC_LITTLE_ENDIAN);
		offset += 3;

		proto_tree_add_item(sub_tree, hf_bt_mijia_sd_message_integrity_check, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
	}

	if (frame_control & 0x0080)
	{
		mesh_item = proto_tree_add_item(sub_tree, hf_bt_mijia_sd_mesh, tvb, offset, 2, ENC_NA);
		mesh_tree = proto_item_add_subtree(mesh_item, hf_bt_mijia_sd_mesh);
		proto_tree_add_item(mesh_tree, hf_bt_mijia_sd_mesh_pb_adv_support, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(mesh_tree, hf_bt_mijia_sd_mesh_pb_gatt_support, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(mesh_tree, hf_bt_mijia_sd_mesh_state, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(mesh_tree, hf_bt_mijia_sd_mesh_version, tvb, offset, 1, ENC_NA);
		offset += 1;

		proto_tree_add_item(mesh_tree, hf_bt_mijia_sd_mesh_rfu, tvb, offset, 1, ENC_NA);
		offset += 2;
	}

	//There is still some data but all data should be already disssected
	if (tvb_captured_length_remaining(tvb, offset) != 0)
	{
		proto_tree_add_expert(sub_tree, pinfo, &ei_mijia_beacon_unknown_payload, tvb, offset, -1);
	}

	return tvb_reported_length(tvb);
}

static const value_string bt_mijia_sd_frame_control_auth_mode_format[] = {
    {0, "RC4 (Deprecated)"},
    {1, "Standard"},
    {2, "Security"},
    {0, NULL}};

static const value_string bt_mijia_sd_capability_bondtability_format[] = {
    {0, "Not Used"},
    {1, "Before Bind"},
    {2, "After Bind"},
    {3, "Combo Bind"},
    {0, NULL}};

static const value_string bt_mijia_sd_mesh_state_format[] = {
    {0, "Un-Authentication"},
    {1, "Un-Provision"},
    {2, "Un-Configuration"},
    {3, "Usable"},
    {0, NULL}};

static const value_string bt_mijia_sd_object_id_format[] = {
    {0x0001, "Connected"},
    {0x0002, "Paired"},
    {0x0003, "Near"},
    {0x0004, "Away"},
    {0x0005, "Lock(Deprecated)"},
    {0x0006, "Fingerprint"},
    {0x0007, "Door"},
    {0x0008, "Armed"},
    {0x0009, "Gesture"},
    {0x000a, "Body Temperature"},
    {0x000b, "Lock Event"},
    {0x000c, "Flooding"},
    {0x000d, "Smoke"},
    {0x000e, "Gas"},
    {0x000f, "Moving"},
    {0x0010, "Toothbrush"},
    {0x0011, "Cat's eye"},
    {0x0012, "Weighing"},
    {0x1001, "Button"},
    {0x1002, "Sleep"},
    {0x1003, "RSSI"},
    {0x1004, "Temperature"},
    {0x1006, "Humidity"},
    {0x1007, "Illumination"},
    {0x1008, "Soil moisture"},
    {0x1009, "Soil EC"},
    {0x100a, "Power"},
    {0x100e, "Lock state"},
    {0x100f, "Door status"},
    {0, NULL},
};

static gint
compute_ascii_key(guchar **ascii_key, const gchar *key)
{
	guint key_len = 0, raw_key_len;
	gint hex_digit;
	guchar key_byte;
	guint i, j;

	if (key != NULL)
	{
		raw_key_len = (guint)strlen(key);
		if ((raw_key_len > 2) && (key[0] == '0') && ((key[1] == 'x') || (key[1] == 'X')))
		{
			/*
			* Key begins with "0x" or "0X"; skip that and treat the rest
			* as a sequence of hex digits.
			*/
			i = 2; /* first character after "0[Xx]" */
			j = 0;
			if (raw_key_len % 2 == 1)
			{
				/*
				* Key has an odd number of characters; we act as if the
				* first character had a 0 in front of it, making the
				* number of characters even.
				*/
				key_len = (raw_key_len - 2) / 2 + 1;
				*ascii_key = (guchar *)g_malloc((key_len + 1) * sizeof(gchar));
				hex_digit = g_ascii_xdigit_value(key[i]);
				i++;
				if (hex_digit == -1)
				{
					g_free(*ascii_key);
					*ascii_key = NULL;
					return -1; /* not a valid hex digit */
				}
				(*ascii_key)[j] = (guchar)hex_digit;
				j++;
			}
			else
			{
				/*
				* Key has an even number of characters, so we treat each
				* pair of hex digits as a single byte value.
				*/
				key_len = (raw_key_len - 2) / 2;
				*ascii_key = (guchar *)g_malloc((key_len + 1) * sizeof(gchar));
			}

			while (i < (raw_key_len - 1))
			{
				hex_digit = g_ascii_xdigit_value(key[i]);
				i++;
				if (hex_digit == -1)
				{
					g_free(*ascii_key);
					*ascii_key = NULL;
					return -1; /* not a valid hex digit */
				}
				key_byte = ((guchar)hex_digit) << 4;
				hex_digit = g_ascii_xdigit_value(key[i]);
				i++;
				if (hex_digit == -1)
				{
					g_free(*ascii_key);
					*ascii_key = NULL;
					return -1; /* not a valid hex digit */
				}
				key_byte |= (guchar)hex_digit;
				(*ascii_key)[j] = key_byte;
				j++;
			}
			(*ascii_key)[j] = '\0';
		}

		else if ((raw_key_len == 2) && (key[0] == '0') && ((key[1] == 'x') || (key[1] == 'X')))
		{
			return 0;
		}
		else
		{
			key_len = raw_key_len;
			*ascii_key = (guchar *)g_strdup(key);
		}
	}
	return key_len;
}

static gboolean
uat_mijia_record_update_cb(void *r, char **err _U_)
{
	uat_mijia_record_t *rec = (uat_mijia_record_t *)r;

	rec->valid = 0;

	/* Compute keys & lengths once and for all */
	if (rec->beacon_key_string)
	{
		g_free(rec->beacon_key);
		rec->beacon_key_length = compute_ascii_key(&rec->beacon_key, rec->beacon_key_string);
		rec->valid = 1;
	}
	else
	{
		rec->beacon_key_length = 0;
		rec->beacon_key = NULL;
	}

	return TRUE;
}

static void *
uat_mijia_record_copy_cb(void *n, const void *o, size_t siz _U_)
{
	uat_mijia_record_t *new_rec = (uat_mijia_record_t *)n;
	const uat_mijia_record_t *old_rec = (const uat_mijia_record_t *)o;

	memset(new_rec, 0x00, sizeof(uat_mijia_record_t));

	/* Copy UAT fields */
	new_rec->beacon_key_string = g_strdup(old_rec->beacon_key_string);

	/* Parse keys as in an update */
	uat_mijia_record_update_cb(new_rec, NULL);

	return new_rec;
}

static void
uat_mijia_record_free_cb(void *r)
{
	uat_mijia_record_t *rec = (uat_mijia_record_t *)r;

	g_free(rec->beacon_key_string);
	g_free(rec->beacon_key);
}

void proto_register_bt_mijia_beacon(void)
{

	static hf_register_info hf[] = {
	    {&hf_bt_mijia_sd_frame_control,
	     {"Frame Control", "mibeacon.frame",
	      FT_UINT16, BASE_HEX, NULL, 0x0,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_frame_control_rfu,
	     {"Reserved", "mibeacon.frame.rfu",
	      FT_UINT16, BASE_HEX, NULL, 0x0300,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_frame_control_locate,
	     {"Locate", "mibeacon.frame.locate",
	      FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x0400,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_frame_control_encrypted,
	     {"Encrypted", "mibeacon.frame.encrypted",
	      FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x0800,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_frame_control_mac_include,
	     {"BT MAC Include", "mibeacon.frame.mac",
	      FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x1000,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_frame_control_capability_include,
	     {"Capability Include", "mibeacon.frame.capability",
	      FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x2000,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_frame_control_object_include,
	     {"Object Include", "mibeacon.frame.object",
	      FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x4000,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_frame_control_mesh_include,
	     {"Mesh Include", "mibeacon.frame.mesh",
	      FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x8000,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_frame_control_registered,
	     {"Registered", "mibeacon.frame.register",
	      FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x0001,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_frame_control_solicited,
	     {"Solicited", "mibeacon.frame.solicited",
	      FT_BOOLEAN, 16, TFS(&tfs_available_not_available), 0x0002,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_frame_control_auth_mode,
	     {"Auth Mode", "mibeacon.frame.auth",
	      FT_UINT16, BASE_DEC, VALS(bt_mijia_sd_frame_control_auth_mode_format), 0x000c,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_frame_control_version,
	     {"Version", "mibeacon.frame.version",
	      FT_UINT8, BASE_DEC, NULL, 0x00f0,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_product_id,
	     {"Product ID", "mibeacon.product",
	      FT_UINT16, BASE_DEC, NULL, 0x00,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_frame_counter,
	     {"Frame Counter", "mibeacon.frame_counter",
	      FT_UINT8, BASE_HEX, NULL, 0x00,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_ble_mac,
	     {"BT MAC Address", "mibeacon.ble_mac_address",
	      FT_ETHER, BASE_NONE, NULL, 0x00,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_capability,
	     {"Capability", "mibeacon.capability",
	      FT_UINT8, BASE_DEC, NULL, 0x00,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_capability_connectable,
	     {"Connectable", "mibeacon.capability.connectable",
	      FT_BOOLEAN, 8, NULL, 0x01,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_capability_centralable,
	     {"Centralable", "mibeacon.capability.centralable",
	      FT_BOOLEAN, 8, NULL, 0x02,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_capability_encryptable,
	     {"Encryptable", "mibeacon.capability.encryptable",
	      FT_BOOLEAN, 8, NULL, 0x04,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_capability_bondtability,
	     {"Bondability", "mibeacon.capability.bondtability",
	      FT_UINT8, BASE_DEC, VALS(bt_mijia_sd_capability_bondtability_format), 0x18,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_capability_io_include,
	     {"I/O Capability", "mibeacon.capability.io",
	      FT_BOOLEAN, 8, NULL, 0x20,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_capability_rfu,
	     {"Reserved", "mibeacon.capability.rfu",
	      FT_UINT8, BASE_HEX, NULL, 0xc0,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_wifi_mac_address,
	     {"WIFI MAC Address", "mibeacon.wifi_mac_address",
	      FT_UINT16, BASE_HEX, NULL, 0x00,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_io_capability,
	     {"I/O Capability", "mibeacon.io",
	      FT_UINT16, BASE_HEX, NULL, 0x00,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_io_capability_input_6_number,
	     {"Input 6 Number", "mibeacon.io.input_6_number",
	      FT_BOOLEAN, 8, NULL, 0x01,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_io_capability_input_6_char,
	     {"Input 6 Char", "mibeacon.io.input_6_char",
	      FT_BOOLEAN, 8, NULL, 0x02,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_io_capability_read_nfc_tag,
	     {"Read NFC Tag", "mibeacon.io.read_nfc",
	      FT_BOOLEAN, 8, NULL, 0x04,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_io_capability_scan_qr_code,
	     {"Scan QR Code", "mibeacon.io.scan_qr",
	      FT_BOOLEAN, 8, NULL, 0x08,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_io_capability_output_6_number,
	     {"Output 6 Number", "mibeacon.io.output_6_char",
	      FT_BOOLEAN, 8, NULL, 0x10,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_io_capability_output_6_char,
	     {"Output 6 Char", "mibeacon.io.input_6_char",
	      FT_BOOLEAN, 8, NULL, 0x20,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_io_capability_gene_nfc_tag,
	     {"Generate NFC Tag", "mibeacon.io.gene_nfc",
	      FT_BOOLEAN, 8, NULL, 0x40,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_io_capability_gene_qr_code,
	     {"Generate QR Code", "mibeacon.io.gene_qr",
	      FT_BOOLEAN, 8, NULL, 0x80,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_io_capability_rfu,
	     {"Reserved", "mibeacon.io.rfu",
	      FT_UINT8, BASE_HEX, NULL, 0xff,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_object,
	     {"Object", "mibeacon.object",
	      FT_BYTES, BASE_NONE, NULL, 0x00,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_object_id,
	     {"ID", "mibeacon.object.id",
	      FT_UINT16, BASE_HEX, VALS(bt_mijia_sd_object_id_format), 0x00,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_object_len,
	     {"Len", "mibeacon.object.len",
	      FT_UINT8, BASE_HEX, NULL, 0x00,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_object_raw,
	     {"Decrypt", "mibeacon.object.raw",
	      FT_BYTES, BASE_NONE, NULL, 0x00,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_extended_frame_counter,
	     {"Extended Frame Counter", "mibeacon.extended",
	      FT_UINT24, BASE_HEX, NULL, 0x00,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_message_integrity_check,
	     {"Message Integrity Check", "mibeacon.integrity",
	      FT_UINT32, BASE_HEX, NULL, 0x00,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_mesh,
	     {"Mesh", "mibeacon.mesh",
	      FT_UINT16, BASE_HEX, NULL, 0x00,
	      NULL, HFILL}},

	    {&hf_bt_mijia_sd_mesh_pb_adv_support,
	     {"PB-ADV Support", "mibeacon.mesh.pbadv",
	      FT_BOOLEAN, 8, TFS(&tfs_available_not_available), 0x01,
	      NULL, HFILL}},

	    {&hf_bt_mijia_sd_mesh_pb_gatt_support,
	     {"PB-GATT Support", "mibeacon.mesh.pbgatt",
	      FT_BOOLEAN, 8, TFS(&tfs_available_not_available), 0x02,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_mesh_state,
	     {"State", "mibeacon.mesh.state",
	      FT_UINT8, BASE_DEC, VALS(bt_mijia_sd_mesh_state_format), 0x0C,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_mesh_version,
	     {"Version", "mibeacon.mesh.version",
	      FT_UINT8, BASE_DEC, NULL, 0xf0,
	      NULL, HFILL}},
	    {&hf_bt_mijia_sd_mesh_rfu,
	     {"Reserved", "mibeacon.mesh.rfu",
	      FT_UINT8, BASE_HEX, NULL, 0x00,
	      NULL, HFILL}},
	};

	static gint *ett[] = {
	    &ett_mijia_beacon,
	    &ett_mijia_beacon_frame_control,
	    &ett_mijia_beacon_oob,
	    &ett_mijia_beacon_obj,
	    &ett_mijia_beacon_capa,
	    &ett_mijia_beacon_mesh,
	};

	static ei_register_info ei[] = {
	    {&ei_mijia_beacon_unknown_payload, {"mibeacon.unknown_payload", PI_PROTOCOL, PI_ERROR, "Unknown Payload", EXPFILL}},
	};

	/* UAT Beacon Key definitions */
	static uat_field_t mijia_uat_flds[] = {
	    UAT_FLD_CSTRING(uat_mijia_records, beacon_key_string, "Beacon Key", "Beacon Key"),
	    UAT_END_FIELDS};

	mijia_uat = uat_new("Bluetooth Mijia Keys",
			    sizeof(uat_mijia_record_t), /* record size */
			    "mijia_keys",		/* filename */
			    TRUE,			/* from_profile */
			    &uat_mijia_records,		/* data_ptr */
			    &num_mijia_uat,		/* numitems_ptr */
			    UAT_AFFECTS_DISSECTION,	/* affects dissection of packets, but not set of named fields */
			    NULL,			/* help */
			    uat_mijia_record_copy_cb,	/* copy callback */
			    uat_mijia_record_update_cb, /* update callback */
			    uat_mijia_record_free_cb,	/* free callback */
			    NULL,			/* post update callback */
			    NULL,			/* reset callback */
			    mijia_uat_flds);		/* UAT field definitions */

	expert_module_t *expert_mijia_beacon;

	proto_bt_mijia_beacon = proto_register_protocol("Bluetooth Mijia Beacon", "Mijia Beacon", "mibeacon");

	proto_register_field_array(proto_bt_mijia_beacon, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_mijia_beacon = expert_register_protocol(proto_bt_mijia_beacon);
	expert_register_field_array(expert_mijia_beacon, ei, array_length(ei));

	module_t *mijia_module;
	mijia_module = prefs_register_protocol_subtree("Bluetooth", proto_bt_mijia_beacon, NULL);
	prefs_register_static_text_preference(mijia_module, "version",
					      "Mijia Beacon",
					      "Version of protocol supported by this dissector.");

	prefs_register_uat_preference(mijia_module,
				      "mijia_key_table",
				      "Mijia Keys",
				      "Configured Mijia Keys",
				      mijia_uat);

	register_dissector("mijia.beacon", dissect_mijia_beacon_msg, proto_bt_mijia_beacon);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
