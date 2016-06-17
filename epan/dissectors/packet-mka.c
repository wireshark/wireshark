/* packet-mka.c
 * Routines for EAPOL-MKA 802.1X authentication header disassembly
 * Copyright 2014, Hitesh K Maisheri <maisheri.hitesh@gmail.com>
 *
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
#include <epan/expert.h>

#define BASIC_PARAM_SET_TYPE         1
#define LIVE_PEER_LIST_TYPE          1
#define POTENTIAL_PEER_LIST_TYPE     2
#define MACSEC_SAK_USE_TYPE          3
#define DISTRIBUTED_SAK_TYPE         4
#define DISTRIBUTED_CAK_TYPE         5
#define KMD_TYPE                     6
#define ICV_TYPE                     255

void proto_register_mka(void);

static int proto_mka = -1;

static int hf_mka_version_id = -1;
static int hf_mka_basic_param_set = -1;
static int hf_mka_live_peer_list_set = -1;
static int hf_mka_potential_peer_list_set = -1;
static int hf_mka_macsec_sak_use_set = -1;
static int hf_mka_distributed_sak_set = -1;
static int hf_mka_distributed_cak_set = -1;
static int hf_mka_kmd_set = -1;
static int hf_mka_icv_set = -1;
static int hf_mka_param_set_type = -1;

static int hf_mka_keyserver_priority = -1;
static int hf_mka_key_server = -1;
static int hf_mka_macsec_desired = -1;
static int hf_mka_macsec_capability = -1;
static int hf_mka_param_body_length = -1;
static int hf_mka_sci = -1;
static int hf_mka_actor_mi = -1;
static int hf_mka_actor_mn = -1;
static int hf_mka_algo_agility = -1;
static int hf_mka_cak_name = -1;

static int hf_mka_latest_key_an = -1;
static int hf_mka_latest_key_tx = -1;
static int hf_mka_latest_key_rx = -1;
static int hf_mka_old_key_an = -1;
static int hf_mka_old_key_tx = -1;
static int hf_mka_old_key_rx = -1;
static int hf_mka_plain_tx = -1;
static int hf_mka_plain_rx = -1;
static int hf_mka_delay_protect = -1;
static int hf_mka_latest_key_server_mi = -1;
static int hf_mka_latest_key_number = -1;
static int hf_mka_latest_lowest_acceptable_pn = -1;
static int hf_mka_old_key_server_mi = -1;
static int hf_mka_old_key_number = -1;
static int hf_mka_old_lowest_acceptable_pn = -1;

static int hf_mka_distributed_an = -1;
static int hf_mka_confidentiality_offset = -1;
static int hf_mka_key_number = -1;
static int hf_mka_aes_key_wrap_sak = -1;
static int hf_mka_macsec_cipher_suite = -1;
static int hf_mka_aes_key_wrap_cak = -1;

static int hf_mka_kmd = -1;

static int hf_mka_icv = -1;

static expert_field ei_mka_undecoded = EI_INIT;
static expert_field ei_unexpected_data = EI_INIT;

static gint ett_mka = -1;
static gint ett_mka_basic_param_set = -1;
static gint ett_mka_peer_list_set = -1;
static gint ett_mka_sak_use_set = -1;
static gint ett_mka_distributed_sak_set = -1;
static gint ett_mka_distributed_cak_set = -1;
static gint ett_mka_kmd_set = -1;
static gint ett_mka_icv_set = -1;

static const value_string param_set_type_vals[] = {
  { 1,                     "Live Peer List" },
  { 2,                     "Potential Peer List" },
  { 3,                     "MACsec SAK Use" },
  { 4,                     "Distributed SAK" },
  { 5,                     "Distributed CAK" },
  { 6,                     "KMD" },
  { 7,                     "Announcement" },
  { 255,                   "ICV" },
  { 0, NULL }
};

static const value_string macsec_capability_type_vals[] = {
  { 0,                     "MACsec not implemented" },
  { 1,                     "MACsec Integrity without confidentiality" },
  { 2,                     "MACsec Integrity with no confidentiality offset" },
  { 3,                     "MACsec Integrity with confidentiality offset" },
  { 0, NULL }
};

static const val64_string  macsec_cipher_suite_vals[] = {
  { G_GINT64_CONSTANT(0x0080C20001000001),           "GCM-AES-128" },
  { G_GINT64_CONSTANT(0x0080C20001000002),           "GCM-AES-256" },
  { G_GINT64_CONSTANT(0x0080C20001000003),           "GCM-AES-XPN-128" },
  { G_GINT64_CONSTANT(0x0080C20001000004),           "GCM-AES-XPN-256" },
  { 0, NULL }
};

static void
dissect_basic_paramset(proto_tree *mka_tree, tvbuff_t *tvb, int *offset_ptr)
{
  int offset = *offset_ptr;
  proto_tree *basic_param_set_tree;
  proto_tree *ti;
  guint16 basic_param_set_len;
  guint16 cak_len;

  basic_param_set_len = (tvb_get_ntohs(tvb, offset + 2)) & 0x0fff;
  ti = proto_tree_add_item(mka_tree, hf_mka_basic_param_set, tvb, offset, basic_param_set_len + 4, ENC_NA);
  basic_param_set_tree = proto_item_add_subtree(ti, ett_mka_basic_param_set);

  proto_tree_add_item(basic_param_set_tree, hf_mka_version_id,
                      tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(basic_param_set_tree, hf_mka_keyserver_priority,
                      tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(basic_param_set_tree, hf_mka_key_server,
                      tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(basic_param_set_tree, hf_mka_macsec_desired,
                      tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(basic_param_set_tree, hf_mka_macsec_capability,
                      tvb, offset, 1, ENC_BIG_ENDIAN);

  proto_tree_add_uint(basic_param_set_tree, hf_mka_param_body_length,
                      tvb, offset, 2, basic_param_set_len);
  offset += 2;

  proto_tree_add_item(basic_param_set_tree, hf_mka_sci,
                      tvb, offset, 8, ENC_NA);
  offset += 8;

  proto_tree_add_item(basic_param_set_tree, hf_mka_actor_mi,
                      tvb, offset, 12, ENC_NA);
  offset += 12;

  proto_tree_add_item(basic_param_set_tree, hf_mka_actor_mn,
                      tvb, offset, 4, ENC_NA);
  offset += 4;

  proto_tree_add_item(basic_param_set_tree, hf_mka_algo_agility,
                      tvb, offset, 4, ENC_NA);
  offset += 4;

  cak_len = basic_param_set_len - 28;
  proto_tree_add_item(basic_param_set_tree, hf_mka_cak_name,
                      tvb, offset, cak_len, ENC_NA);
  offset += cak_len;

  *offset_ptr = offset;
}

static void
dissect_peer_list(proto_tree *mka_tree, tvbuff_t *tvb, int *offset_ptr)
{
  int offset = *offset_ptr;
  proto_tree *peer_list_set_tree;
  proto_tree *ti;
  int hf_peer = -1;
  gint16 peer_list_len;

  if (tvb_get_guint8(tvb, offset) == LIVE_PEER_LIST_TYPE) {
    hf_peer = hf_mka_live_peer_list_set;
  } else {
    hf_peer = hf_mka_potential_peer_list_set;
  }

  peer_list_len = (tvb_get_ntohs(tvb, offset + 2)) & 0x0fff;
  ti = proto_tree_add_item(mka_tree, hf_peer, tvb, offset, peer_list_len + 4, ENC_NA);
  peer_list_set_tree = proto_item_add_subtree(ti, ett_mka_peer_list_set);

  proto_tree_add_item(peer_list_set_tree, hf_mka_param_set_type,
                      tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_uint(peer_list_set_tree, hf_mka_param_body_length,
                      tvb, offset, 2, peer_list_len);
  offset += 2;

  while (peer_list_len > 0) {
    proto_tree_add_item(peer_list_set_tree, hf_mka_actor_mi,
                        tvb, offset, 12, ENC_NA);
    offset += 12;

    proto_tree_add_item(peer_list_set_tree, hf_mka_actor_mn,
                        tvb, offset, 4, ENC_NA);
    offset += 4;

    peer_list_len -= 16;
  }

  *offset_ptr = offset;
}

static void
dissect_sak_use(proto_tree *mka_tree, tvbuff_t *tvb, int *offset_ptr)
{
  int offset = *offset_ptr;
  proto_tree *sak_use_set_tree;
  proto_tree *ti;
  guint16 sak_use_len;

  sak_use_len = (tvb_get_ntohs(tvb, offset + 2)) & 0x0fff;
  ti = proto_tree_add_item(mka_tree, hf_mka_macsec_sak_use_set, tvb, offset, sak_use_len + 4, ENC_NA);
  sak_use_set_tree = proto_item_add_subtree(ti, ett_mka_sak_use_set);

  proto_tree_add_item(sak_use_set_tree, hf_mka_param_set_type,
                      tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(sak_use_set_tree, hf_mka_latest_key_an,
                      tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(sak_use_set_tree, hf_mka_latest_key_tx,
                      tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(sak_use_set_tree, hf_mka_latest_key_rx,
                      tvb, offset, 1, ENC_BIG_ENDIAN);


  proto_tree_add_item(sak_use_set_tree, hf_mka_old_key_an,
                      tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(sak_use_set_tree, hf_mka_old_key_tx,
                      tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(sak_use_set_tree, hf_mka_old_key_rx,
                      tvb, offset, 1, ENC_BIG_ENDIAN);

  offset += 1;

  proto_tree_add_item(sak_use_set_tree, hf_mka_plain_tx,
                      tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(sak_use_set_tree, hf_mka_plain_rx,
                      tvb, offset, 1, ENC_BIG_ENDIAN);

  proto_tree_add_item(sak_use_set_tree, hf_mka_delay_protect,
                      tvb, offset, 1, ENC_BIG_ENDIAN);

  proto_tree_add_uint(sak_use_set_tree, hf_mka_param_body_length,
                      tvb, offset, 2, sak_use_len);

  offset += 2;

  proto_tree_add_item(sak_use_set_tree, hf_mka_latest_key_server_mi,
                      tvb, offset, 12, ENC_NA);
  offset += 12;

  proto_tree_add_item(sak_use_set_tree, hf_mka_latest_key_number,
                      tvb, offset, 4, ENC_NA);
  offset += 4;

  proto_tree_add_item(sak_use_set_tree, hf_mka_latest_lowest_acceptable_pn,
                      tvb, offset, 4, ENC_NA);
  offset += 4;

  proto_tree_add_item(sak_use_set_tree, hf_mka_old_key_server_mi,
                      tvb, offset, 12, ENC_NA);
  offset += 12;

  proto_tree_add_item(sak_use_set_tree, hf_mka_old_key_number,
                      tvb, offset, 4, ENC_NA);
  offset += 4;

  proto_tree_add_item(sak_use_set_tree, hf_mka_old_lowest_acceptable_pn,
                      tvb, offset, 4, sak_use_len);
  offset += 4;

  *offset_ptr = offset;

}

static void
dissect_distributed_sak(proto_tree *mka_tree, packet_info *pinfo, tvbuff_t *tvb, int *offset_ptr)
{
  int offset = *offset_ptr;
  guint16 distributed_sak_len;
  proto_tree *distributed_sak_tree;
  proto_tree *ti;

  distributed_sak_len = (tvb_get_ntohs(tvb, offset + 2)) & 0x0fff;
  ti = proto_tree_add_item(mka_tree, hf_mka_distributed_sak_set, tvb, offset, distributed_sak_len + 4, ENC_NA);
  distributed_sak_tree = proto_item_add_subtree(ti, ett_mka_distributed_sak_set);

  proto_tree_add_item(distributed_sak_tree, hf_mka_param_set_type,
                      tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(distributed_sak_tree, hf_mka_distributed_an,
                      tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(distributed_sak_tree, hf_mka_confidentiality_offset,
                      tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_uint(distributed_sak_tree, hf_mka_param_body_length,
                      tvb, offset, 2, distributed_sak_len);
  offset += 2;

  switch (distributed_sak_len) {
  case 28:
    proto_tree_add_item(distributed_sak_tree, hf_mka_key_number,
                        tvb, offset, 4, ENC_NA);
    offset += 4;

    proto_tree_add_item(distributed_sak_tree, hf_mka_aes_key_wrap_sak,
                        tvb, offset, 24, ENC_NA);
    offset += 24;
    break;

  case 36:
    proto_tree_add_item(distributed_sak_tree, hf_mka_key_number,
                        tvb, offset, 4, ENC_NA);
    offset += 4;

    proto_tree_add_item(distributed_sak_tree, hf_mka_macsec_cipher_suite,
                        tvb, offset, 8, ENC_NA);
    offset += 8;

    proto_tree_add_item(distributed_sak_tree, hf_mka_aes_key_wrap_sak,
                        tvb, offset, 24, ENC_NA);
    offset += 24;
    break;

  case 52:
    proto_tree_add_item(distributed_sak_tree, hf_mka_key_number,
                        tvb, offset, 4, ENC_NA);
    offset += 4;

    proto_tree_add_item(distributed_sak_tree, hf_mka_macsec_cipher_suite,
                        tvb, offset, 8, ENC_NA);
    offset += 8;

    proto_tree_add_item(distributed_sak_tree, hf_mka_aes_key_wrap_sak,
                        tvb, offset, 40, ENC_NA);
    offset += 40;
    break;

  default:
    proto_tree_add_expert(distributed_sak_tree, pinfo, &ei_mka_undecoded, tvb, offset, distributed_sak_len);
    offset += distributed_sak_len;
  }

  *offset_ptr = offset;
}

static void
dissect_distributed_cak(proto_tree *mka_tree, tvbuff_t *tvb, int *offset_ptr)
{
  int offset = *offset_ptr;
  guint16 distributed_cak_len;
  proto_tree *distributed_cak_tree;
  proto_tree *ti;
  guint16 cak_len;

  distributed_cak_len = (tvb_get_ntohs(tvb, offset + 2)) & 0x0fff;
  ti = proto_tree_add_item(mka_tree, hf_mka_distributed_cak_set, tvb, offset, distributed_cak_len + 4, ENC_NA);
  distributed_cak_tree = proto_item_add_subtree(ti, ett_mka_distributed_cak_set);

  proto_tree_add_item(distributed_cak_tree, hf_mka_param_set_type,
                      tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_uint(distributed_cak_tree, hf_mka_param_body_length,
                      tvb, offset, 2, distributed_cak_len);
  offset += 2;

  proto_tree_add_item(distributed_cak_tree, hf_mka_aes_key_wrap_cak,
                      tvb, offset, 24, ENC_NA);
  offset += 24;

  cak_len = distributed_cak_len - 24;
  proto_tree_add_item(distributed_cak_tree, hf_mka_cak_name,
                      tvb, offset, cak_len, ENC_NA);
  offset += cak_len;

  *offset_ptr = offset;
}

static void
dissect_kmd(proto_tree *mka_tree, tvbuff_t *tvb, int *offset_ptr)
{
  int offset = *offset_ptr;
  guint16 kmd_len;
  proto_tree *kmd_set_tree;
  proto_tree *ti;

  kmd_len = (tvb_get_ntohs(tvb, offset + 2)) & 0x0fff;
  ti = proto_tree_add_item(mka_tree, hf_mka_kmd_set, tvb, offset, kmd_len + 4, ENC_NA);
  kmd_set_tree = proto_item_add_subtree(ti, ett_mka_kmd_set);

  proto_tree_add_item(kmd_set_tree, hf_mka_param_set_type,
                      tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_uint(kmd_set_tree, hf_mka_param_body_length,
                      tvb, offset, 2, kmd_len);
  offset += 2;

  proto_tree_add_item(kmd_set_tree, hf_mka_kmd,
                      tvb, offset, kmd_len, ENC_NA);
  offset += kmd_len;

  *offset_ptr = offset;
}

static void
dissect_icv(proto_tree *mka_tree, tvbuff_t *tvb, int *offset_ptr)
{
  int offset = *offset_ptr;
  guint16 icv_len;
  proto_tree *icv_set_tree;
  proto_tree *ti;

  icv_len = (tvb_get_ntohs(tvb, offset + 2)) & 0x0fff;
  ti = proto_tree_add_item(mka_tree, hf_mka_icv_set, tvb, offset, icv_len + 4, ENC_NA);
  icv_set_tree = proto_item_add_subtree(ti, ett_mka_icv_set);

  proto_tree_add_item(icv_set_tree, hf_mka_param_set_type,
                      tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_uint(icv_set_tree, hf_mka_param_body_length,
                      tvb, offset, 2, icv_len);
  offset += 2;

  proto_tree_add_item(icv_set_tree, hf_mka_icv,
                      tvb, offset, icv_len, ENC_NA);
  offset += icv_len;

  *offset_ptr = offset;
}

static int
dissect_mka(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  int         offset = 0;
  guint8      mka_version_type = 0;
  proto_tree *ti;
  proto_tree *mka_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "EAPOL-MKA");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_mka, tvb, 0, -1, ENC_NA);
  mka_tree = proto_item_add_subtree(ti, ett_mka);

  /*
   * The 802.1X-2010 spec specifies support for MKA version 1 only
   */
  mka_version_type = tvb_get_guint8(tvb, offset);
  if (mka_version_type != 1) {
    expert_add_info(pinfo, ti, &ei_unexpected_data);
  }

  /*
   * Basic Parameter set is always the first parameter set, dissect it first !
   */
  dissect_basic_paramset(mka_tree, tvb, &offset);

  while(tvb_reported_length_remaining(tvb, offset) > 0) {
    switch (tvb_get_guint8(tvb, offset)) {
    case LIVE_PEER_LIST_TYPE:
    case POTENTIAL_PEER_LIST_TYPE:
      dissect_peer_list(mka_tree, tvb, &offset);
      break;

    case MACSEC_SAK_USE_TYPE:
      dissect_sak_use(mka_tree, tvb, &offset);
      break;

    case DISTRIBUTED_SAK_TYPE:
      dissect_distributed_sak(mka_tree, pinfo, tvb, &offset);
      break;

    case DISTRIBUTED_CAK_TYPE:
      dissect_distributed_cak(mka_tree, tvb, &offset);
      break;

    case KMD_TYPE:
      dissect_kmd(mka_tree, tvb, &offset);
      break;

    case ICV_TYPE:
      dissect_icv(mka_tree, tvb, &offset);
      break;

    default:
        proto_tree_add_expert(mka_tree, pinfo, &ei_mka_undecoded, tvb, offset, -1);
        offset += tvb_reported_length_remaining(tvb, offset);
    }
  }
  return tvb_captured_length(tvb);
}

void
proto_register_mka(void)
{
  expert_module_t  *expert_mka = NULL;

  static ei_register_info ei[] = {
    { &ei_mka_undecoded, {
        "mka.expert.undecoded_data", PI_UNDECODED, PI_WARN, "Undecoded data", EXPFILL }},
    { &ei_unexpected_data, {
        "mka.expert.unexpected_data", PI_PROTOCOL, PI_WARN, "Unexpected data", EXPFILL }},
  };

  static hf_register_info hf[] = {
    { &hf_mka_version_id, {
        "MKA Version Identifier", "mka.version_id",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_basic_param_set, {
        "Basic Parameter set", "mka.basic_param_set",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_live_peer_list_set, {
        "Live Peer List Parameter set", "mka.live_peer_list_set",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_potential_peer_list_set, {
        "Potential Peer List Parameter set", "mka.live_peer_list_set",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_macsec_sak_use_set, {
        "MACsec SAK Use parameter set", "mka.macsec_sak_use_set",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_distributed_sak_set, {
        "Distributed SAK parameter set", "mka.distributed_sak_set",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_distributed_cak_set, {
        "Distributed CAK parameter set", "mka.distributed_cak_set",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_kmd_set, {
        "Key Management Domain set", "mka.basic_kmd_set",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_icv_set, {
        "Integrity Check Value Set", "mka.basic_icv_set",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_param_set_type, {
        "Parameter set type", "mka.param_set_type",
        FT_UINT8, BASE_DEC, VALS(param_set_type_vals), 0x0,
        NULL, HFILL }},

    { &hf_mka_keyserver_priority, {
        "Key Server Priority", "mka.ks_prio",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_key_server, {
        "Key Server", "mka.key_server",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},

    { &hf_mka_macsec_desired, {
        "MACsec Desired", "mka.macsec_desired",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},

    { &hf_mka_macsec_capability, {
        "MACsec Capability", "mka.macsec_capability",
        FT_UINT8, BASE_DEC, VALS(macsec_capability_type_vals), 0x30,
        NULL, HFILL }},

    { &hf_mka_param_body_length, {
        "Parameter set body length", "mka.param_body_length",
        FT_UINT16, BASE_DEC, NULL, 0x0fff,
        NULL, HFILL }},

    { &hf_mka_sci, {
        "SCI", "mka.sci",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_actor_mi, {
        "Actor Member Identifier", "mka.actor_mi",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_actor_mn, {
        "Actor Message Number", "mka.actor_mn",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_algo_agility, {
        "Algorithm Agility", "mka.algo_agility",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_cak_name, {
        "CAK Name", "mka.cak_name",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_latest_key_an, {
        "Latest Key AN", "mka.latest_key_an",
        FT_UINT8, BASE_DEC, NULL, 0xc0,
        NULL, HFILL }},

    { &hf_mka_latest_key_tx, {
        "Latest Key tx", "mka.latest_key_tx",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},

    { &hf_mka_latest_key_rx, {
        "Latest Key rx", "mka.latest_key_rx",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},

    { &hf_mka_old_key_an, {
        "Old Key AN", "mka.old_key_an",
        FT_UINT8, BASE_DEC, NULL, 0x0c,
        NULL, HFILL }},

    { &hf_mka_old_key_tx, {
        "Old Key tx", "mka.old_key_tx",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},

    { &hf_mka_old_key_rx, {
        "Old Key rx", "mka.old_key_rx",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},

    { &hf_mka_plain_tx, {
        "Plain tx", "mka.plain_tx",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},

    { &hf_mka_plain_rx, {
        "Plain rx", "mka.plain_rx",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},

    { &hf_mka_delay_protect, {
        "Delay protect", "mka.delay_protect",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},

    { &hf_mka_latest_key_server_mi, {
        "Latest Key: Key Sever Member Identifier", "mka.latest_key_server_mi",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_latest_key_number, {
        "Latest Key: Key Number", "mka.latest_key_number",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_latest_lowest_acceptable_pn, {
        "Latest Key: Lowest Acceptable PN", "mka.latest_lowest_acceptable_pn",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_old_key_server_mi, {
        "Old Key: Key Sever Member Identifier", "mka.old_key_server_mi",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_old_key_number, {
        "Old Key: Key Number", "mka.old_key_number",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_old_lowest_acceptable_pn, {
        "Old Key: Lowest Acceptable PN", "mka.old_lowest_acceptable_pn",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_distributed_an, {
        "Distributed AN", "mka.distributed_an",
        FT_UINT8, BASE_DEC, NULL, 0xc0,
        NULL, HFILL }},

    { &hf_mka_confidentiality_offset, {
        "Confidentiality Offset", "mka.confidentiality_offset",
        FT_UINT8, BASE_DEC, NULL, 0x30,
        NULL, HFILL }},

    { &hf_mka_key_number, {
        "Key Number", "mka.key_number",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_aes_key_wrap_sak, {
        "AES Key Wrap of SAK", "mka.aes_key_wrap_sak",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_aes_key_wrap_cak, {
        "AES Key Wrap of CAK", "mka.aes_key_wrap_cak",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_macsec_cipher_suite, {
        "MACsec Cipher Suite", "mka.macsec_cipher_suite",
        FT_UINT64, BASE_HEX|BASE_VAL64_STRING, VALS64(macsec_cipher_suite_vals), 0x0,
        NULL, HFILL }},

    { &hf_mka_kmd, {
        "Key Management Domain", "mka.kmd",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_icv, {
        "Integrity Check Value", "mka.icv",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

  };

  static gint *ett[] = {
    &ett_mka,
    &ett_mka_basic_param_set,
    &ett_mka_peer_list_set,
    &ett_mka_sak_use_set,
    &ett_mka_distributed_sak_set,
    &ett_mka_distributed_cak_set,
    &ett_mka_kmd_set,
    &ett_mka_icv_set
  };

  proto_mka = proto_register_protocol("MACsec Key Agreement", "EAPOL-MKA", "mka");
  register_dissector("mka", dissect_mka, proto_mka);

  proto_register_field_array(proto_mka, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  expert_mka = expert_register_protocol(proto_mka);
  expert_register_field_array(expert_mka, ei, array_length(ei));

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
