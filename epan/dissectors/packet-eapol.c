/* packet-eapol.c
 * Routines for EAPOL 802.1X authentication header disassembly
 * (From IEEE Draft P802.1X/D11; is there a later draft, or a
 * final standard?  If so, check it.)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/crypt/wep-wpadefs.h>
#include "packet-ieee80211.h"
#include <epan/etypes.h>

static int proto_eapol = -1;
static int hf_eapol_version = -1;
static int hf_eapol_type = -1;
static int hf_eapol_len = -1;
static int hf_eapol_keydes_type = -1;
static int hf_eapol_keydes_key_len = -1;
static int hf_eapol_keydes_replay_counter = -1;
static int hf_eapol_keydes_key_iv = -1;
static int hf_eapol_keydes_key_index = -1;
static int hf_eapol_keydes_key_index_type = -1;
static int hf_eapol_keydes_key_index_number = -1;
static int hf_eapol_keydes_key_signature = -1;
static int hf_eapol_keydes_key = -1;
static int hf_eapol_keydes_key_generated_locally = -1;

static int hf_eapol_wpa_keydes_keyinfo = -1;
static int hf_eapol_wpa_keydes_keyinfo_keydes_version = -1;
static int hf_eapol_wpa_keydes_keyinfo_key_type = -1;
static int hf_eapol_wpa_keydes_keyinfo_key_index = -1;
static int hf_eapol_wpa_keydes_keyinfo_install = -1;
static int hf_eapol_wpa_keydes_keyinfo_key_ack = -1;
static int hf_eapol_wpa_keydes_keyinfo_key_mic = -1;
static int hf_eapol_wpa_keydes_keyinfo_secure = -1;
static int hf_eapol_wpa_keydes_keyinfo_error = -1;
static int hf_eapol_wpa_keydes_keyinfo_request = -1;
static int hf_eapol_wpa_keydes_keyinfo_encrypted_key_data = -1;
static int hf_eapol_wpa_keydes_nonce = -1;
static int hf_eapol_wpa_keydes_rsc = -1;
static int hf_eapol_wpa_keydes_id = -1;
static int hf_eapol_wpa_keydes_mic = -1;
static int hf_eapol_wpa_keydes_data_len = -1;
static int hf_eapol_wpa_keydes_data = -1;

static gint ett_eapol = -1;
static gint ett_eapol_keydes_data = -1;
static gint ett_eapol_key_index = -1;
static gint ett_keyinfo = -1;

static dissector_handle_t eap_handle;
static dissector_handle_t data_handle;

#define EAPOL_HDR_LEN   4

#define EAPOL_2001      1
#define EAPOL_2004      2
#define EAPOL_2010      3

#define EAP_PACKET              0
#define EAPOL_START             1
#define EAPOL_LOGOFF            2
#define EAPOL_KEY               3
#define EAPOL_ENCAP_ASF_ALERT   4

#define EAPOL_RSN_KEY           2 /* TBD, may change in final IEEE 802.1X-REV
                                   */
#define EAPOL_WPA_KEY           254

static const value_string eapol_version_vals[] = {
  { EAPOL_2001,   "802.1X-2001" },
  { EAPOL_2004,   "802.1X-2004" },
  { EAPOL_2010,   "802.1X-2010" },
  { 0, NULL }
};

static const value_string eapol_type_vals[] = {
  { EAP_PACKET,            "EAP Packet" },
  { EAPOL_START,           "Start" },
  { EAPOL_LOGOFF,          "Logoff" },
  { EAPOL_KEY,             "Key" },
  { EAPOL_ENCAP_ASF_ALERT, "Encapsulated ASF Alert" },
  { 0, NULL }
};

static const value_string eapol_keydes_type_vals[] = {
  { 1, "RC4 Descriptor" },
  { EAPOL_RSN_KEY, "EAPOL RSN Key" },
  { EAPOL_WPA_KEY, "EAPOL WPA Key" },
  { 0, NULL }
};

#define KEY_INFO_KEYDES_VERSION_MASK        0x0007
#define KEY_INFO_KEY_TYPE_MASK              0x0008
#define KEY_INFO_KEY_INDEX_MASK             0x0030
#define KEY_INFO_INSTALL_MASK               0x0040
#define KEY_INFO_KEY_ACK_MASK               0x0080
#define KEY_INFO_KEY_MIC_MASK               0x0100
#define KEY_INFO_SECURE_MASK                0x0200
#define KEY_INFO_ERROR_MASK                 0x0400
#define KEY_INFO_REQUEST_MASK               0x0800
#define KEY_INFO_ENCRYPTED_KEY_DATA_MASK    0x1000

static const true_false_string keytype_tfs = { "Unicast", "Broadcast" };

static const true_false_string keyinfo_key_type_tfs = { "Pairwise Key", "Group Key" };

#define KEYDES_KEY_INDEX_TYPE_MASK      0x80
#define KEYDES_KEY_INDEX_NUMBER_MASK    0x7F

#define KEYDES_VER_TYPE1        0x01
#define KEYDES_VER_TYPE2        0x02
#define KEYDES_VER_TYPE3        0x03

static const value_string keydes_version_vals[] = {
  { KEYDES_VER_TYPE1,     "RC4 Cipher, HMAC-MD5 MIC" },
  { KEYDES_VER_TYPE2,     "AES Cipher, HMAC-SHA1 MIC" },
  { KEYDES_VER_TYPE3,     "AES Cipher, AES-128-CMAC MIC" },
  { 0, NULL }
};

static void
dissect_eapol(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  int         offset = 0;
  guint8      eapol_type;
  guint8      keydesc_type;
  guint16     eapol_len;
  guint       len;
  guint16     eapol_key_len, eapol_data_len;
  guint16     keyinfo;
  gboolean    generated_locally;
  proto_tree *ti = NULL;
  proto_tree *eapol_tree = NULL;
  proto_tree *keyinfo_item = NULL;
  proto_tree *keyinfo_tree = NULL;
  proto_tree *key_index_tree, *keydes_tree;
  tvbuff_t   *next_tvb;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "EAPOL");
  col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_eapol, tvb, 0, -1, ENC_NA);
    eapol_tree = proto_item_add_subtree(ti, ett_eapol);

    proto_tree_add_item(eapol_tree, hf_eapol_version, tvb, offset, 1, ENC_BIG_ENDIAN);
  }
  offset++;

  eapol_type = tvb_get_guint8(tvb, offset);
  if (tree)
    proto_tree_add_item(eapol_tree, hf_eapol_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_str(pinfo->cinfo, COL_INFO,
                val_to_str(eapol_type, eapol_type_vals, "Unknown Type (0x%02X)"));
  offset++;

  eapol_len = tvb_get_ntohs(tvb, offset);
  len = EAPOL_HDR_LEN + eapol_len;
  set_actual_length(tvb, len);
  if (tree) {
    proto_item_set_len(ti, len);
    proto_tree_add_item(eapol_tree, hf_eapol_len, tvb, offset, 2, ENC_BIG_ENDIAN);
  }
  offset += 2;

  switch (eapol_type) {

  case EAP_PACKET:
    next_tvb = tvb_new_subset_remaining(tvb, offset);
    call_dissector(eap_handle, next_tvb, pinfo, eapol_tree);
    break;

  case EAPOL_KEY:
    if (tree) {
      keydesc_type = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(eapol_tree, hf_eapol_keydes_type, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
      if (keydesc_type == EAPOL_WPA_KEY || keydesc_type == EAPOL_RSN_KEY) {
        keyinfo = tvb_get_ntohs(tvb, offset);
        if (check_col(pinfo->cinfo, COL_INFO)) {
          if (keyinfo & KEY_INFO_REQUEST_MASK) {
            col_set_str(pinfo->cinfo, COL_INFO, "Key (Request)");
            if (keyinfo & KEY_INFO_ERROR_MASK)
              col_set_str(pinfo->cinfo, COL_INFO, "Key (Request, Error)");
          } else if (keyinfo & KEY_INFO_KEY_TYPE_MASK) {
            guint16 masked;
            masked = keyinfo &
              (KEY_INFO_INSTALL_MASK | KEY_INFO_KEY_ACK_MASK |
               KEY_INFO_KEY_MIC_MASK | KEY_INFO_SECURE_MASK);
            switch (masked) {
            case KEY_INFO_KEY_ACK_MASK:
              col_set_str(pinfo->cinfo, COL_INFO, "Key (Message 1 of 4)");
              break;
            case KEY_INFO_KEY_MIC_MASK:
              col_set_str(pinfo->cinfo, COL_INFO, "Key (Message 2 of 4)");
              break;
            case (KEY_INFO_INSTALL_MASK | KEY_INFO_KEY_ACK_MASK |
                  KEY_INFO_KEY_MIC_MASK | KEY_INFO_SECURE_MASK):
              col_set_str(pinfo->cinfo, COL_INFO, "Key (Message 3 of 4)");
              break;
            case (KEY_INFO_KEY_MIC_MASK | KEY_INFO_SECURE_MASK):
              col_set_str(pinfo->cinfo, COL_INFO, "Key (Message 4 of 4)");
              break;
            }
          } else {
            if (keyinfo & KEY_INFO_KEY_ACK_MASK)
              col_set_str(pinfo->cinfo, COL_INFO, "Key (Group Message 1 of 2)");
            else
              col_set_str(pinfo->cinfo, COL_INFO, "Key (Group Message 2 of 2)");
          }
        }
        keyinfo_item =
          proto_tree_add_item(eapol_tree, hf_eapol_wpa_keydes_keyinfo, tvb,
                              offset, 2, ENC_BIG_ENDIAN);

        keyinfo_tree = proto_item_add_subtree(keyinfo_item, ett_keyinfo);
        proto_tree_add_item(keyinfo_tree, hf_eapol_wpa_keydes_keyinfo_keydes_version, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(keyinfo_tree, hf_eapol_wpa_keydes_keyinfo_key_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(keyinfo_tree, hf_eapol_wpa_keydes_keyinfo_key_index, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(keyinfo_tree, hf_eapol_wpa_keydes_keyinfo_install, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(keyinfo_tree, hf_eapol_wpa_keydes_keyinfo_key_ack, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(keyinfo_tree, hf_eapol_wpa_keydes_keyinfo_key_mic, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(keyinfo_tree, hf_eapol_wpa_keydes_keyinfo_secure, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(keyinfo_tree, hf_eapol_wpa_keydes_keyinfo_error, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(keyinfo_tree, hf_eapol_wpa_keydes_keyinfo_request, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(keyinfo_tree, hf_eapol_wpa_keydes_keyinfo_encrypted_key_data, tvb, offset, 2, ENC_BIG_ENDIAN);

        offset += 2;
        proto_tree_add_item(eapol_tree, hf_eapol_keydes_key_len, tvb, offset,
                            2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(eapol_tree, hf_eapol_keydes_replay_counter, tvb,
                            offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_item(eapol_tree, hf_eapol_wpa_keydes_nonce, tvb, offset,
                            32, ENC_BIG_ENDIAN);
        offset += 32;
        proto_tree_add_item(eapol_tree, hf_eapol_keydes_key_iv, tvb,
                            offset, 16, ENC_BIG_ENDIAN);
        offset += 16;
        proto_tree_add_item(eapol_tree, hf_eapol_wpa_keydes_rsc, tvb, offset,
                            8, ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_item(eapol_tree, hf_eapol_wpa_keydes_id, tvb, offset, 8,
                            ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_item(eapol_tree, hf_eapol_wpa_keydes_mic, tvb, offset,
                            16, ENC_BIG_ENDIAN);
        offset += 16;
        eapol_data_len = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(eapol_tree, hf_eapol_wpa_keydes_data_len, tvb,
                            offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        if (eapol_data_len != 0) {
          ti = proto_tree_add_item(eapol_tree, hf_eapol_wpa_keydes_data,
                tvb, offset, eapol_data_len, ENC_BIG_ENDIAN);
          if ((keyinfo & KEY_INFO_ENCRYPTED_KEY_DATA_MASK) ||
              !(keyinfo & KEY_INFO_KEY_TYPE_MASK)) {
            /* RSN: EAPOL-Key Key Data is encrypted.
             * WPA: Group Keys use encrypted Key Data.
             * Cannot parse this without knowing the key.
             * IEEE 802.11i-2004 8.5.2.
             */
          } else {
            keydes_tree = proto_item_add_subtree(ti, ett_eapol_keydes_data);
            ieee_80211_add_tagged_parameters(tvb, offset, pinfo, keydes_tree,
                                             eapol_data_len, -1);
          }
        }
      } else {
        eapol_key_len = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(eapol_tree, hf_eapol_keydes_key_len, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(eapol_tree, hf_eapol_keydes_replay_counter, tvb,
                            offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_item(eapol_tree, hf_eapol_keydes_key_iv, tvb,
                            offset, 16, ENC_NA);
        offset += 16;
        ti = proto_tree_add_item(eapol_tree, hf_eapol_keydes_key_index, tvb, offset, 1, ENC_BIG_ENDIAN);
        key_index_tree = proto_item_add_subtree(ti, ett_eapol_key_index);
        proto_tree_add_item(key_index_tree, hf_eapol_keydes_key_index_type,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(key_index_tree, hf_eapol_keydes_key_index_number,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(eapol_tree, hf_eapol_keydes_key_signature, tvb,
                            offset, 16, ENC_NA);
        offset += 16;
        if (eapol_key_len != 0) {
          /* IEEE 802.1X-2004 7.6.3.6: If no bytes remain, then */
          generated_locally = eapol_len <= 44; /* Size of rc4 key with no key content */
          if (!generated_locally) {
              proto_tree_add_item(eapol_tree, hf_eapol_keydes_key, tvb, offset,
                                  eapol_key_len, ENC_BIG_ENDIAN);
          }

          proto_tree_add_boolean(eapol_tree, hf_eapol_keydes_key_generated_locally, tvb, offset,
                                 0, generated_locally);
        }
      }
    }
    break;

  case EAPOL_ENCAP_ASF_ALERT:   /* XXX - is this an SNMP trap? */
  default:
    next_tvb = tvb_new_subset_remaining(tvb, offset);
    call_dissector(data_handle, next_tvb, pinfo, eapol_tree);
    break;
  }
}

void
proto_register_eapol(void)
{
  static hf_register_info hf[] = {
    { &hf_eapol_version, {
        "Version", "eapol.version",
        FT_UINT8, BASE_DEC, VALS(eapol_version_vals), 0x0,
        NULL, HFILL }},

    { &hf_eapol_type, {
        "Type", "eapol.type",
        FT_UINT8, BASE_DEC, VALS(eapol_type_vals), 0x0,
        NULL, HFILL }},

    { &hf_eapol_len, {
        "Length", "eapol.len",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_eapol_keydes_type, {
        "Key Descriptor Type", "eapol.keydes.type",
        FT_UINT8, BASE_DEC, VALS(eapol_keydes_type_vals), 0x0,
        NULL, HFILL }},

    { &hf_eapol_keydes_key_len, {
        "Key Length", "eapol.keydes.key_len",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_eapol_keydes_replay_counter, {
        "Replay Counter", "eapol.keydes.replay_counter",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_eapol_keydes_key_iv, {
        "Key IV", "eapol.keydes.key_iv",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_eapol_keydes_key_index, {
        "Key Index", "eapol.keydes.key_index",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_eapol_keydes_key_index_type, {
        "Type", "eapol.keydes.key_index.type",
        FT_BOOLEAN, 8, TFS(&keytype_tfs), KEYDES_KEY_INDEX_TYPE_MASK ,
        NULL, HFILL }},

    { &hf_eapol_keydes_key_index_number, {
        "Number", "eapol.keydes.key_index.number",
        FT_UINT8, BASE_DEC, NULL, KEYDES_KEY_INDEX_NUMBER_MASK,
        NULL, HFILL }},

    { &hf_eapol_keydes_key_signature, {
        "Key Signature", "eapol.keydes.key_signature",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_eapol_keydes_key, {
        "Key", "eapol.keydes.key",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_eapol_keydes_key_generated_locally, {
        "Key Generated Locally", "eapol.keydes.key.generated_locally",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_eapol_wpa_keydes_keyinfo, {
        "Key Information", "eapol.keydes.key_info",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_eapol_wpa_keydes_keyinfo_keydes_version, {
        "Key Descriptor Version", "eapol.keydes.key_info.keydes_version",
        FT_UINT16, BASE_DEC, VALS(keydes_version_vals), KEY_INFO_KEYDES_VERSION_MASK,
        NULL, HFILL }},

    { &hf_eapol_wpa_keydes_keyinfo_key_type, {
        "Key Type", "eapol.keydes.key_info.key_type",
        FT_BOOLEAN, 16, TFS(&keyinfo_key_type_tfs), KEY_INFO_KEY_TYPE_MASK,
        NULL, HFILL }},

    { &hf_eapol_wpa_keydes_keyinfo_key_index, {
        "Key Index", "eapol.keydes.key_info.key_index",
        FT_UINT16, BASE_DEC, NULL, KEY_INFO_KEY_INDEX_MASK,
        NULL, HFILL }},

    { &hf_eapol_wpa_keydes_keyinfo_install, {
        "Install", "eapol.keydes.key_info.install",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), KEY_INFO_INSTALL_MASK,
        NULL, HFILL }},

    { &hf_eapol_wpa_keydes_keyinfo_key_ack, {
        "Key ACK", "eapol.keydes.key_info.key_ack",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), KEY_INFO_KEY_ACK_MASK,
        NULL, HFILL }},

    { &hf_eapol_wpa_keydes_keyinfo_key_mic, {
        "Key MIC", "eapol.keydes.key_info.key_mic",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), KEY_INFO_KEY_MIC_MASK,
        NULL, HFILL }},

    { &hf_eapol_wpa_keydes_keyinfo_secure, {
        "Secure", "eapol.keydes.key_info.secure",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), KEY_INFO_SECURE_MASK,
        NULL, HFILL }},

    { &hf_eapol_wpa_keydes_keyinfo_error, {
        "Error", "eapol.keydes.key_info.error",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), KEY_INFO_ERROR_MASK,
        NULL, HFILL }},

    { &hf_eapol_wpa_keydes_keyinfo_request, {
        "Request", "eapol.keydes.key_info.request",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), KEY_INFO_REQUEST_MASK,
        NULL, HFILL }},

    { &hf_eapol_wpa_keydes_keyinfo_encrypted_key_data, {
        "Encrypted Key Data", "eapol.keydes.key_info.encrypted_key_data",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), KEY_INFO_ENCRYPTED_KEY_DATA_MASK,
        NULL, HFILL }},

    { &hf_eapol_wpa_keydes_nonce, {
        "WPA Key Nonce", "eapol.keydes.nonce",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_eapol_wpa_keydes_rsc, {
        "WPA Key RSC", "eapol.keydes.rsc",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_eapol_wpa_keydes_id, {
        "WPA Key ID", "eapol.keydes.id",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_eapol_wpa_keydes_mic, {
        "WPA Key MIC", "eapol.keydes.mic",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_eapol_wpa_keydes_data_len, {
        "WPA Key Data Length", "eapol.keydes.data_len",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_eapol_wpa_keydes_data, {
        "WPA Key Data", "eapol.keydes.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
  };

  static gint *ett[] = {
    &ett_eapol,
    &ett_eapol_keydes_data,
    &ett_keyinfo,
    &ett_eapol_key_index
  };

  proto_eapol = proto_register_protocol("802.1X Authentication", "EAPOL", "eapol");
  register_dissector("eapol", dissect_eapol, proto_eapol);

  proto_register_field_array(proto_eapol, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_eapol(void)
{
  dissector_handle_t eapol_handle;

  /*
   * Get handles for the EAP and raw data dissectors.
   */
  eap_handle  = find_dissector("eap");
  data_handle = find_dissector("data");

  eapol_handle = create_dissector_handle(dissect_eapol, proto_eapol);
  dissector_add_uint("ethertype", ETHERTYPE_EAPOL, eapol_handle);
  dissector_add_uint("ethertype", ETHERTYPE_RSN_PREAUTH, eapol_handle);
}
