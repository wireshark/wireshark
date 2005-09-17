/* packet-eapol.c
 * Routines for EAPOL 802.1X authentication header disassembly
 * (From IEEE Draft P802.1X/D11; is there a later draft, or a
 * final standard?  If so, check it.)
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include "packet-ieee80211.h"
#include <epan/etypes.h>

static int proto_eapol = -1;
static int hf_eapol_version = -1;
static int hf_eapol_type = -1;
static int hf_eapol_len = -1;
static int hf_eapol_keydes_type = -1;
static int hf_eapol_keydes_keylen = -1;
static int hf_eapol_keydes_replay_counter = -1;
static int hf_eapol_keydes_key_iv = -1;
static int hf_eapol_keydes_key_index_keytype = -1;
static int hf_eapol_keydes_key_index_indexnum = -1;
static int hf_eapol_keydes_key_signature = -1;
static int hf_eapol_keydes_key = -1;

static int hf_eapol_wpa_keydes_keyinfo = -1;
static int hf_eapol_wpa_keydes_keyinfo_keydes_ver = -1;
static int hf_eapol_wpa_keydes_keyinfo_key_type = -1;
static int hf_eapol_wpa_keydes_keyinfo_key_index = -1;
static int hf_eapol_wpa_keydes_keyinfo_install = -1;
static int hf_eapol_wpa_keydes_keyinfo_key_ack = -1;
static int hf_eapol_wpa_keydes_keyinfo_key_mic = -1;
static int hf_eapol_wpa_keydes_keyinfo_secure = -1;
static int hf_eapol_wpa_keydes_keyinfo_error = -1;
static int hf_eapol_wpa_keydes_keyinfo_request = -1;
static int hf_eapol_wpa_keydes_keyinfo_encr_key_data = -1;
static int hf_eapol_wpa_keydes_nonce = -1;
static int hf_eapol_wpa_keydes_rsc = -1;
static int hf_eapol_wpa_keydes_id = -1;
static int hf_eapol_wpa_keydes_mic = -1;
static int hf_eapol_wpa_keydes_datalen = -1;
static int hf_eapol_wpa_keydes_data = -1;

static gint ett_eapol = -1;
static gint ett_eapol_keydes_data = -1;
static gint ett_eapol_key_index = -1;
static gint ett_keyinfo = -1;

static dissector_handle_t eap_handle;
static dissector_handle_t data_handle;

#define EAPOL_HDR_LEN	4

#define EAP_PACKET		0
#define EAPOL_START		1
#define EAPOL_LOGOFF		2
#define EAPOL_KEY		3
#define EAPOL_ENCAP_ASF_ALERT	4

#define EAPOL_RSN_KEY		2 /* TBD, may change in final IEEE 802.1X-REV
				   */
#define EAPOL_WPA_KEY		254

static const value_string eapol_type_vals[] = {
    { EAP_PACKET,            "EAP Packet" },
    { EAPOL_START,           "Start" },
    { EAPOL_LOGOFF,          "Logoff" },
    { EAPOL_KEY,             "Key" },
    { EAPOL_ENCAP_ASF_ALERT, "Encapsulated ASF Alert" },
    { 0,                     NULL }
};

static const value_string eapol_keydes_type_vals[] = {
	{ 1, "RC4 Descriptor" },
	{ EAPOL_RSN_KEY, "EAPOL RSN key" },
	{ EAPOL_WPA_KEY, "EAPOL WPA key" },
	{ 0, NULL }
};

#define KEY_INFO_KEYDES_VER_MASK	0x0007
#define KEY_INFO_KEY_TYPE_MASK		0x0008
#define KEY_INFO_KEY_INDEX_MASK		0x0030
#define KEY_INFO_INSTALL_MASK		0x0040
#define KEY_INFO_KEY_ACK_MASK		0x0080
#define KEY_INFO_KEY_MIC_MASK		0x0100
#define KEY_INFO_SECURE_MASK		0x0200
#define KEY_INFO_ERROR_MASK		0x0400
#define KEY_INFO_REQUEST_MASK		0x0800
#define KEY_INFO_ENCR_KEY_DATA_MASK	0x1000

static const true_false_string keytype_tfs =
	{ "Unicast", "Broadcast" };
static const true_false_string tfs_keyinfo_key_type =
	{ "Pairwise key", "Group key" };
#define KEYDES_VER_TYPE1	0x01
#define KEYDES_VER_TYPE2	0x02
static const value_string keydes_ver[] = {
	{ KEYDES_VER_TYPE1,	"HMAC-MD5 for MIC and RC4 for encryption" },
	{ KEYDES_VER_TYPE2,	"AES-CBC-MAC for MIC and HMAC-SHA1 for encryption" },
	{ 0, 		NULL }
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
  guint8      key_index;
  guint16     keyinfo;
  proto_tree *ti = NULL;
  proto_tree *eapol_tree = NULL;
  proto_tree *keyinfo_item = NULL;
  proto_tree *keyinfo_tree = NULL;
  proto_tree *key_index_tree, *keydes_tree;
  tvbuff_t   *next_tvb;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "EAPOL");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_eapol, tvb, 0, -1, FALSE);
    eapol_tree = proto_item_add_subtree(ti, ett_eapol);

    proto_tree_add_item(eapol_tree, hf_eapol_version, tvb, offset, 1, FALSE);
  }
  offset++;

  eapol_type = tvb_get_guint8(tvb, offset);
  if (tree)
    proto_tree_add_uint(eapol_tree, hf_eapol_type, tvb, offset, 1, eapol_type);
  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_str(pinfo->cinfo, COL_INFO,
		val_to_str(eapol_type, eapol_type_vals, "Unknown type (0x%02X)"));
  offset++;

  eapol_len = tvb_get_ntohs(tvb, offset);
  len = EAPOL_HDR_LEN + eapol_len;
  set_actual_length(tvb, len);
  if (tree) {
    proto_item_set_len(ti, len);
    proto_tree_add_uint(eapol_tree, hf_eapol_len, tvb, offset, 2, eapol_len);
  }
  offset += 2;

  switch (eapol_type) {

  case EAP_PACKET:
    next_tvb = tvb_new_subset(tvb, offset, -1, -1);
    call_dissector(eap_handle, next_tvb, pinfo, eapol_tree);
    break;

  case EAPOL_KEY:
    if (tree) {
      keydesc_type = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(eapol_tree, hf_eapol_keydes_type, tvb, offset, 1, FALSE);
      offset += 1;
      if (keydesc_type == EAPOL_WPA_KEY || keydesc_type == EAPOL_RSN_KEY) {
	keyinfo = tvb_get_ntohs(tvb, offset);
	keyinfo_item = 
	  proto_tree_add_uint(eapol_tree, hf_eapol_wpa_keydes_keyinfo, tvb,
			      offset, 2, keyinfo);

	keyinfo_tree = proto_item_add_subtree(keyinfo_item, ett_keyinfo);
	proto_tree_add_uint(keyinfo_tree, hf_eapol_wpa_keydes_keyinfo_keydes_ver, tvb, offset, 2, keyinfo);
	proto_tree_add_boolean(keyinfo_tree, hf_eapol_wpa_keydes_keyinfo_key_type, tvb, offset, 2, keyinfo);
	proto_tree_add_uint(keyinfo_tree, hf_eapol_wpa_keydes_keyinfo_key_index, tvb, offset, 2, keyinfo);
	proto_tree_add_boolean(keyinfo_tree, hf_eapol_wpa_keydes_keyinfo_install, tvb, offset, 2, keyinfo);
	proto_tree_add_boolean(keyinfo_tree, hf_eapol_wpa_keydes_keyinfo_key_ack, tvb, offset, 2, keyinfo);
	proto_tree_add_boolean(keyinfo_tree, hf_eapol_wpa_keydes_keyinfo_key_mic, tvb, offset, 2, keyinfo);
	proto_tree_add_boolean(keyinfo_tree, hf_eapol_wpa_keydes_keyinfo_secure, tvb, offset, 2, keyinfo);
	proto_tree_add_boolean(keyinfo_tree, hf_eapol_wpa_keydes_keyinfo_error, tvb, offset, 2, keyinfo);
	proto_tree_add_boolean(keyinfo_tree, hf_eapol_wpa_keydes_keyinfo_request, tvb, offset, 2, keyinfo);
	proto_tree_add_boolean(keyinfo_tree, hf_eapol_wpa_keydes_keyinfo_encr_key_data, tvb, offset, 2, keyinfo);

        offset += 2;
        proto_tree_add_uint(eapol_tree, hf_eapol_keydes_keylen, tvb, offset,
        		    2, tvb_get_ntohs(tvb, offset));
        offset += 2;
        proto_tree_add_item(eapol_tree, hf_eapol_keydes_replay_counter, tvb,
        		    offset, 8, FALSE);
        offset += 8;
        proto_tree_add_item(eapol_tree, hf_eapol_wpa_keydes_nonce, tvb, offset,
        		    32, FALSE);
        offset += 32;
        proto_tree_add_item(eapol_tree, hf_eapol_keydes_key_iv, tvb,
        		    offset, 16, FALSE);
        offset += 16;
        proto_tree_add_item(eapol_tree, hf_eapol_wpa_keydes_rsc, tvb, offset,
        		    8, FALSE);
        offset += 8;
        proto_tree_add_item(eapol_tree, hf_eapol_wpa_keydes_id, tvb, offset, 8,
        		    FALSE);
        offset += 8;
        proto_tree_add_item(eapol_tree, hf_eapol_wpa_keydes_mic, tvb, offset,
        		    16, FALSE);
        offset += 16;
        eapol_data_len = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint(eapol_tree, hf_eapol_wpa_keydes_datalen, tvb,
        		    offset, 2, eapol_data_len);
        offset += 2;
        if (eapol_data_len != 0) {
          ti = proto_tree_add_item(eapol_tree, hf_eapol_wpa_keydes_data,
          	tvb, offset, eapol_data_len, FALSE);
	  if ((keyinfo & KEY_INFO_ENCR_KEY_DATA_MASK) ||
	      !(keyinfo & KEY_INFO_KEY_TYPE_MASK)) {
	    /* RSN: EAPOL-Key Key Data is encrypted.
	     * WPA: Group Keys use encrypted Key Data.
	     * Cannot parse this without knowing the key. */
	  } else {
	    keydes_tree = proto_item_add_subtree(ti, ett_eapol_keydes_data);
	    ieee_80211_add_tagged_parameters(tvb, offset, pinfo, keydes_tree,
					     eapol_data_len);
	  }
        }
      }
      else {
        eapol_key_len = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint(eapol_tree, hf_eapol_keydes_keylen, tvb, offset, 2, eapol_key_len);
        offset += 2;
        proto_tree_add_item(eapol_tree, hf_eapol_keydes_replay_counter, tvb,
  			  offset, 8, FALSE);
        offset += 8;
        proto_tree_add_item(eapol_tree, hf_eapol_keydes_key_iv, tvb,
  			  offset, 16, FALSE);
        offset += 16;
        key_index = tvb_get_guint8(tvb, offset);
        ti = proto_tree_add_text(eapol_tree, tvb, offset, 1,
  			       "Key Index: %s, index %u",
  			       (key_index & 0x80) ? "unicast" : "broadcast",
  			       key_index & 0x7F);
        key_index_tree = proto_item_add_subtree(ti, ett_eapol_key_index);
        proto_tree_add_boolean(eapol_tree, hf_eapol_keydes_key_index_keytype,
  			     tvb, offset, 1, key_index);
        proto_tree_add_uint(eapol_tree, hf_eapol_keydes_key_index_indexnum,
  			     tvb, offset, 1, key_index);
        offset += 1;
        proto_tree_add_item(eapol_tree, hf_eapol_keydes_key_signature, tvb,
  			  offset, 16, FALSE);
        offset += 16;
        if (eapol_key_len != 0)
          proto_tree_add_item(eapol_tree, hf_eapol_keydes_key, tvb, offset,
  			    eapol_key_len, FALSE);
      }
    }
    break;

  case EAPOL_ENCAP_ASF_ALERT:	/* XXX - is this an SNMP trap? */
  default:
    next_tvb = tvb_new_subset(tvb, offset, -1, -1);
    call_dissector(data_handle, next_tvb, pinfo, eapol_tree);
    break;
  }
}

void
proto_register_eapol(void)
{
  static hf_register_info hf[] = {
	{ &hf_eapol_version, {
		"Version", "eapol.version", FT_UINT8, BASE_DEC,
		NULL, 0x0, "", HFILL }},
	{ &hf_eapol_type, {
		"Type", "eapol.type", FT_UINT8, BASE_DEC,
		VALS(eapol_type_vals), 0x0, "", HFILL }},
	{ &hf_eapol_len, {
		"Length", "eapol.len", FT_UINT16, BASE_DEC,
		NULL, 0x0, "Length", HFILL }},
	{ &hf_eapol_keydes_type, {
		"Descriptor Type", "eapol.keydes.type", FT_UINT8, BASE_DEC,
		VALS(eapol_keydes_type_vals), 0x0, "Key Descriptor Type", HFILL }},
	{ &hf_eapol_keydes_keylen, {
		"Key Length", "eapol.keydes.keylen", FT_UINT16, BASE_DEC,
		NULL, 0x0, "Key Length", HFILL }},
	{ &hf_eapol_keydes_replay_counter, {
		"Replay Counter", "eapol.keydes.replay_counter", FT_UINT64, BASE_DEC,
		NULL, 0x0, "Replay Counter", HFILL }},
	{ &hf_eapol_keydes_key_iv, {
		"Key IV", "eapol.keydes.key_iv", FT_BYTES, BASE_NONE,
		NULL, 0x0, "Key Initialization Vector", HFILL }},
	{ &hf_eapol_keydes_key_index_keytype, {
		"Key Type", "eapol.keydes.index.keytype", FT_BOOLEAN, 8,
		TFS(&keytype_tfs), 0x80, "Key Type (unicast/broadcast)", HFILL }},
	{ &hf_eapol_keydes_key_index_indexnum, {
		"Index Number", "eapol.keydes.index.indexnum", FT_UINT8, BASE_DEC,
		NULL, 0x7F, "Key Index number", HFILL }},
	{ &hf_eapol_keydes_key_signature, {
		"Key Signature", "eapol.keydes.key_signature", FT_BYTES, BASE_NONE,
		NULL, 0x0, "Key Signature", HFILL }},
	{ &hf_eapol_keydes_key, {
		"Key", "eapol.keydes.key", FT_BYTES, BASE_NONE,
		NULL, 0x0, "Key", HFILL }},

	{ &hf_eapol_wpa_keydes_keyinfo, {
		"Key Information", "eapol.keydes.key_info", FT_UINT16,
		BASE_HEX, NULL, 0x0, "WPA key info", HFILL }},

	{ &hf_eapol_wpa_keydes_keyinfo_keydes_ver, {
		"Key Descriptor Version", 
		"eapol.keydes.key_info.keydes_ver", 
		FT_UINT16, BASE_DEC, VALS(&keydes_ver),
		KEY_INFO_KEYDES_VER_MASK, 
		"Key Descriptor Version Type", HFILL }},
	{ &hf_eapol_wpa_keydes_keyinfo_key_type, {
		"Key Type", 
		"eapol.keydes.key_info.key_type", 
		FT_BOOLEAN, 16, TFS(&tfs_keyinfo_key_type), 
		KEY_INFO_KEY_TYPE_MASK, 
		"Key Type (Pairwise or Group)", HFILL }},
	{ &hf_eapol_wpa_keydes_keyinfo_key_index, {
		"Key Index", 
		"eapol.keydes.key_info.key_index", 
		FT_UINT16, BASE_DEC, NULL, 
		KEY_INFO_KEY_INDEX_MASK, 
		"Key Index (0-3) (RSN: Reserved)", HFILL }},
	{ &hf_eapol_wpa_keydes_keyinfo_install, {
		"Install flag", 
		"eapol.keydes.key_info.install", 
		FT_BOOLEAN, 16, TFS(&flags_set_truth), 
		KEY_INFO_INSTALL_MASK, 
		"Install flag", HFILL }},
	{ &hf_eapol_wpa_keydes_keyinfo_key_ack, {
		"Key Ack flag", 
		"eapol.keydes.key_info.key_ack", 
		FT_BOOLEAN, 16, TFS(&flags_set_truth), 
		KEY_INFO_KEY_ACK_MASK, 
		"Key Ack flag", HFILL }},
	{ &hf_eapol_wpa_keydes_keyinfo_key_mic, {
		"Key MIC flag", 
		"eapol.keydes.key_info.key_mic", 
		FT_BOOLEAN, 16, TFS(&flags_set_truth), 
		KEY_INFO_KEY_MIC_MASK, 
		"Key MIC flag", HFILL }},
	{ &hf_eapol_wpa_keydes_keyinfo_secure, {
		"Secure flag", 
		"eapol.keydes.key_info.secure", 
		FT_BOOLEAN, 16, TFS(&flags_set_truth), 
		KEY_INFO_SECURE_MASK, 
		"Secure flag", HFILL }},
	{ &hf_eapol_wpa_keydes_keyinfo_error, {
		"Error flag", 
		"eapol.keydes.key_info.error", 
		FT_BOOLEAN, 16, TFS(&flags_set_truth), 
		KEY_INFO_ERROR_MASK, 
		"Error flag", HFILL }},
	{ &hf_eapol_wpa_keydes_keyinfo_request, {
		"Request flag", 
		"eapol.keydes.key_info.request", 
		FT_BOOLEAN, 16, TFS(&flags_set_truth), 
		KEY_INFO_REQUEST_MASK, 
		"Request flag", HFILL }},
	{ &hf_eapol_wpa_keydes_keyinfo_encr_key_data, {
		"Encrypted Key Data flag", 
		"eapol.keydes.key_info.encr_key_data", 
		FT_BOOLEAN, 16, TFS(&flags_set_truth), 
		KEY_INFO_ENCR_KEY_DATA_MASK, 
		"Encrypted Key Data flag", HFILL }},
	{ &hf_eapol_wpa_keydes_nonce, {
		"Nonce", "eapol.keydes.nonce", FT_BYTES, BASE_NONE,
		NULL, 0x0, "WPA Key Nonce", HFILL }},
	{ &hf_eapol_wpa_keydes_rsc, {
		"WPA Key RSC", "eapol.keydes.rsc", FT_BYTES, BASE_NONE, NULL,
		0x0, "WPA Key Receive Sequence Counter", HFILL }},
	{ &hf_eapol_wpa_keydes_id, {
		"WPA Key ID", "eapol.keydes.id", FT_BYTES, BASE_NONE, NULL,
		0x0, "WPA Key ID(RSN Reserved)", HFILL }},
	{ &hf_eapol_wpa_keydes_mic, {
		"WPA Key MIC", "eapol.keydes.mic", FT_BYTES, BASE_NONE, NULL,
		0x0, "WPA Key Message Integrity Check", HFILL }},
	{ &hf_eapol_wpa_keydes_datalen, {
		"WPA Key Length", "eapol.keydes.datalen", FT_UINT16, BASE_DEC,
		NULL, 0x0, "WPA Key Data Length", HFILL }},
	{ &hf_eapol_wpa_keydes_data, {
		"WPA Key", "eapol.keydes.data", FT_BYTES, BASE_NONE,
		NULL, 0x0, "WPA Key Data", HFILL }},
  };
  static gint *ett[] = {
	&ett_eapol,
	&ett_eapol_keydes_data,
	&ett_keyinfo,
	&ett_eapol_key_index
  };

  proto_eapol = proto_register_protocol("802.1X Authentication", "EAPOL", "eapol");
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
  eap_handle = find_dissector("eap");
  data_handle = find_dissector("data");

  eapol_handle = create_dissector_handle(dissect_eapol, proto_eapol);
  dissector_add("ethertype", ETHERTYPE_EAPOL, eapol_handle);
  dissector_add("ethertype", ETHERTYPE_RSN_PREAUTH, eapol_handle);
}
