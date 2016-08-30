/* packet-eapol.c
 * Routines for EAPOL 802.1X authentication header disassembly
 * (From IEEE Draft P802.1X/D11; is there a later draft, or a
 * final standard?  If so, check it.)
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

#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/eapol_keydes_types.h>

void proto_register_eapol(void);
void proto_reg_handoff_eapol(void);

static int proto_eapol = -1;
static int hf_eapol_version = -1;
static int hf_eapol_type = -1;
static int hf_eapol_len = -1;
static int hf_eapol_keydes_type = -1;
static int hf_eapol_keydes_body = -1;
static int hf_eapol_keydes_key_len = -1;
static int hf_eapol_keydes_replay_counter = -1;
static int hf_eapol_keydes_key_iv = -1;
static int hf_eapol_keydes_key_index = -1;
static int hf_eapol_keydes_key_index_type = -1;
static int hf_eapol_keydes_key_index_number = -1;
static int hf_eapol_keydes_key_signature = -1;
static int hf_eapol_keydes_key = -1;
static int hf_eapol_keydes_key_generated_locally = -1;

static gint ett_eapol = -1;
static gint ett_eapol_key_index = -1;
static gint ett_keyinfo = -1;

static dissector_table_t eapol_keydes_type_dissector_table;

static dissector_handle_t eapol_handle;

static dissector_handle_t eap_handle;
static dissector_handle_t mka_handle;

#define EAPOL_HDR_LEN   4

#define EAPOL_2001      1
#define EAPOL_2004      2
#define EAPOL_2010      3

#define EAP_PACKET              0
#define EAPOL_START             1
#define EAPOL_LOGOFF            2
#define EAPOL_KEY               3
#define EAPOL_ENCAP_ASF_ALERT   4
#define EAPOL_MKA               5

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
  { EAPOL_MKA,             "MKA" },
  { 0, NULL }
};

static const value_string eapol_keydes_type_vals[] = {
  { EAPOL_RC4_KEY, "RC4 Descriptor" },
  { EAPOL_RSN_KEY, "EAPOL RSN Key" },
  { EAPOL_WPA_KEY, "EAPOL WPA Key" },
  { 0, NULL }
};

static const true_false_string keytype_tfs = { "Unicast", "Broadcast" };

#define KEYDES_KEY_INDEX_TYPE_MASK      0x80
#define KEYDES_KEY_INDEX_NUMBER_MASK    0x7F

static int
dissect_eapol(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  int         offset = 0;
  guint8      eapol_type;
  guint16     eapol_len;
  guint8      keydesc_type;
  guint       len;
  proto_tree *ti;
  proto_tree *eapol_tree;
  tvbuff_t   *next_tvb;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "EAPOL");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_eapol, tvb, 0, -1, ENC_NA);
  eapol_tree = proto_item_add_subtree(ti, ett_eapol);

  proto_tree_add_item(eapol_tree, hf_eapol_version, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;

  eapol_type = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(eapol_tree, hf_eapol_type, tvb, offset, 1, ENC_BIG_ENDIAN);
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
    keydesc_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(eapol_tree, hf_eapol_keydes_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    next_tvb = tvb_new_subset_remaining(tvb, offset);
    if (!dissector_try_uint_new(eapol_keydes_type_dissector_table,
                                keydesc_type, next_tvb, pinfo, eapol_tree,
                                FALSE, NULL))
      proto_tree_add_item(eapol_tree, hf_eapol_keydes_body, tvb, offset, -1, ENC_NA);
    break;

  case EAPOL_MKA:
    next_tvb = tvb_new_subset_remaining(tvb, offset);
    call_dissector(mka_handle, next_tvb, pinfo, eapol_tree);
    break;

  case EAPOL_ENCAP_ASF_ALERT:   /* XXX - is this an SNMP trap? */
  default:
    next_tvb = tvb_new_subset_remaining(tvb, offset);
    call_data_dissector(next_tvb, pinfo, eapol_tree);
    break;
  }
  return tvb_captured_length(tvb);
}

static int
dissect_eapol_rc4_key(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  int         offset = 0;
  guint16     eapol_key_len;
  gboolean    generated_locally;
  proto_tree *ti;
  proto_tree *key_index_tree;
  gint        eapol_len;

  eapol_key_len = tvb_get_ntohs(tvb, offset);
  proto_tree_add_item(tree, hf_eapol_keydes_key_len, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(tree, hf_eapol_keydes_replay_counter, tvb,
                      offset, 8, ENC_BIG_ENDIAN);
  offset += 8;
  proto_tree_add_item(tree, hf_eapol_keydes_key_iv, tvb,
                      offset, 16, ENC_NA);
  offset += 16;
  ti = proto_tree_add_item(tree, hf_eapol_keydes_key_index, tvb, offset, 1, ENC_BIG_ENDIAN);
  key_index_tree = proto_item_add_subtree(ti, ett_eapol_key_index);
  proto_tree_add_item(key_index_tree, hf_eapol_keydes_key_index_type,
                      tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(key_index_tree, hf_eapol_keydes_key_index_number,
                      tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  proto_tree_add_item(tree, hf_eapol_keydes_key_signature, tvb,
                      offset, 16, ENC_NA);
  offset += 16;
  if (eapol_key_len != 0) {
    /*
     * Body length of EAPOL-Key message in which we're contained is 1 byte
     * larger than the reported length of the key descriptor we were handed,
     * that 1 byte being the Key Descriptor Type.
     */
    eapol_len = 1 + tvb_reported_length(tvb);

    /* IEEE 802.1X-2004 7.6.3.6: If no bytes remain, then */
    generated_locally = eapol_len <= 44; /* Size of rc4 key with no key content */
    if (!generated_locally) {
      proto_tree_add_item(tree, hf_eapol_keydes_key, tvb, offset,
                          eapol_key_len, ENC_NA);
    }

    proto_tree_add_boolean(tree, hf_eapol_keydes_key_generated_locally, tvb, offset,
                           0, generated_locally);
  }
  return tvb_captured_length(tvb);
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

    { &hf_eapol_keydes_body, {
        "Key Descriptor Body", "eapol.keydes.body",
        FT_BYTES, BASE_NONE, NULL, 0x0,
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
  };

  static gint *ett[] = {
    &ett_eapol,
    &ett_keyinfo,
    &ett_eapol_key_index
  };

  proto_eapol = proto_register_protocol("802.1X Authentication", "EAPOL", "eapol");
  eapol_handle = register_dissector("eapol", dissect_eapol, proto_eapol);

  proto_register_field_array(proto_eapol, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  eapol_keydes_type_dissector_table = register_dissector_table("eapol.keydes.type",
                                                               "EAPOL Key Descriptor Type",
                                                               proto_eapol, FT_UINT8,
                                                               BASE_DEC);
}

void
proto_reg_handoff_eapol(void)
{
  dissector_handle_t eapol_rc4_key_handle;

  /*
   * Get handles for the EAP and raw data dissectors.
   */
  eap_handle  = find_dissector_add_dependency("eap", proto_eapol);
  mka_handle  = find_dissector_add_dependency("mka", proto_eapol);

  dissector_add_uint("ethertype", ETHERTYPE_EAPOL, eapol_handle);
  dissector_add_uint("ethertype", ETHERTYPE_RSN_PREAUTH, eapol_handle);

  /*
   * EAPOL key descriptor types.
   */
  eapol_rc4_key_handle = create_dissector_handle(dissect_eapol_rc4_key,
                                                     proto_eapol);
  dissector_add_uint("eapol.keydes.type", EAPOL_RC4_KEY, eapol_rc4_key_handle);
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
