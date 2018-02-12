/* packet-mka.c
 * Routines for EAPOL-MKA IEEE 802.1X-2010 / IEEE 802.1bx-2014 MKPDU dissection
 * Copyright 2014, Hitesh K Maisheri <maisheri.hitesh@gmail.com>
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

#include "packet-eapol.h"

#define LIVE_PEER_LIST_TYPE          1
#define POTENTIAL_PEER_LIST_TYPE     2
#define MACSEC_SAK_USE_TYPE          3
#define DISTRIBUTED_SAK_TYPE         4
#define DISTRIBUTED_CAK_TYPE         5
#define KMD_TYPE                     6
#define ANNOUNCEMENT_TYPE            7
#define XPN_TYPE                     8
#define ICV_TYPE                     255

void proto_register_mka(void);
void proto_reg_handoff_mka(void);

static int proto_mka = -1;

static int hf_mka_version_id = -1;
static int hf_mka_basic_param_set = -1;
static int hf_mka_live_peer_list_set = -1;
static int hf_mka_potential_peer_list_set = -1;
static int hf_mka_macsec_sak_use_set = -1;
static int hf_mka_distributed_sak_set = -1;
static int hf_mka_distributed_cak_set = -1;
static int hf_mka_kmd_set = -1;
static int hf_mka_announcement_set = -1;
static int hf_mka_xpn_set = -1;
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

static int hf_mka_padding = -1;

static int hf_mka_peer_mi = -1;
static int hf_mka_peer_mn = -1;

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

static int hf_mka_suspension_time = -1;

static int hf_mka_unknown_set = -1;
static int hf_mka_unknown_param_set = -1;

static int hf_mka_icv = -1;

static expert_field ei_mka_undecoded = EI_INIT;
static expert_field ei_unexpected_data = EI_INIT;
static expert_field ei_mka_unimplemented = EI_INIT;

static gint ett_mka = -1;
static gint ett_mka_basic_param_set = -1;
static gint ett_mka_peer_list_set = -1;
static gint ett_mka_sak_use_set = -1;
static gint ett_mka_distributed_sak_set = -1;
static gint ett_mka_distributed_cak_set = -1;
static gint ett_mka_kmd_set = -1;
static gint ett_mka_announcement_set = -1;
static gint ett_mka_xpn_set = -1;
static gint ett_mka_unknown_set = -1;
static gint ett_mka_icv_set = -1;

static const value_string param_set_type_vals[] = {
  { LIVE_PEER_LIST_TYPE,       "Live Peer List" },
  { POTENTIAL_PEER_LIST_TYPE,  "Potential Peer List" },
  { MACSEC_SAK_USE_TYPE,       "MACsec SAK Use" },
  { DISTRIBUTED_SAK_TYPE,      "Distributed SAK" },
  { DISTRIBUTED_CAK_TYPE,      "Distributed CAK" },
  { KMD_TYPE,                  "KMD" },
  { ANNOUNCEMENT_TYPE,         "Announcement" },
  { XPN_TYPE,                  "XPN" },
  { ICV_TYPE,                  "ICV Indicator" },
  { 0, NULL }
};

static const value_string macsec_capability_type_vals[] = {
  { 0,                     "MACsec not implemented" },
  { 1,                     "MACsec Integrity without confidentiality" },
  { 2,                     "MACsec Integrity with no confidentiality offset" },
  { 3,                     "MACsec Integrity with confidentiality offset" },
  { 0, NULL }
};

static const value_string algo_agility_vals[] = {
  { 0x0080C201, "IEEE Std 802.1X-2010" },
  { 0, NULL }
};

static const value_string confidentiality_offset_vals[] = {
  { 0, "No confidentiality" },
  { 1, "No confidentiality offset" },
  { 2, "Confidentiality offset 30 octets" },
  { 3, "Confidentiality offset 50 octets" },
  { 0, NULL }
};

static const val64_string macsec_cipher_suite_vals[] = {
  { G_GINT64_CONSTANT(0x0080020001000001),           "GCM-AES-128" }, // Original, incorrect value in IEEE 802.1AE-2006 and IEEE 802.1X-2010
  { G_GINT64_CONSTANT(0x0080C20001000001),           "GCM-AES-128" },
  { G_GINT64_CONSTANT(0x0080C20001000002),           "GCM-AES-256" },
  { G_GINT64_CONSTANT(0x0080C20001000003),           "GCM-AES-XPN-128" },
  { G_GINT64_CONSTANT(0x0080C20001000004),           "GCM-AES-XPN-256" },
  { 0, NULL }
};

static void
dissect_basic_paramset(proto_tree *mka_tree, packet_info *pinfo, tvbuff_t *tvb, int *offset_ptr)
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

  if (tvb_get_guint8(tvb, offset) & 0x80)
  {
    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Key Server");
  }

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

  if (basic_param_set_len%4) {
    int padding_len = (4 - (basic_param_set_len % 4));

    proto_tree_add_item(basic_param_set_tree, hf_mka_padding,
                        tvb, offset, padding_len, ENC_NA);

    offset += padding_len;
  }

  *offset_ptr = offset;
}

static void
dissect_peer_list(proto_tree *mka_tree, packet_info *pinfo, tvbuff_t *tvb, int *offset_ptr)
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

  while (peer_list_len >= 16) {
    proto_tree_add_item(peer_list_set_tree, hf_mka_peer_mi,
                        tvb, offset, 12, ENC_NA);
    offset += 12;

    proto_tree_add_item(peer_list_set_tree, hf_mka_peer_mn,
                        tvb, offset, 4, ENC_NA);
    offset += 4;

    peer_list_len -= 16;
  }

  if (peer_list_len != 0) {
    proto_tree_add_expert(peer_list_set_tree, pinfo, &ei_mka_undecoded, tvb, offset, peer_list_len);
    offset += peer_list_len;
  }

  *offset_ptr = offset;
}

static void
dissect_sak_use(proto_tree *mka_tree, packet_info *pinfo _U_, tvbuff_t *tvb, int *offset_ptr)
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
                      tvb, offset, 4, ENC_NA);
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

  if (distributed_sak_len == 0) // Plain text
  {
      // Nothing
  }
  else if (distributed_sak_len == 28) // GCM-AES-128
  {
    proto_tree_add_item(distributed_sak_tree, hf_mka_key_number,
                        tvb, offset, 4, ENC_NA);
    offset += 4;

    proto_tree_add_item(distributed_sak_tree, hf_mka_aes_key_wrap_sak,
                        tvb, offset, 24, ENC_NA);
    offset += 24;
  }
  else if (distributed_sak_len >= 36) // Other than default cipher
  {
    proto_tree_add_item(distributed_sak_tree, hf_mka_key_number,
                        tvb, offset, 4, ENC_NA);
    offset += 4;

    proto_tree_add_item(distributed_sak_tree, hf_mka_macsec_cipher_suite,
                        tvb, offset, 8, ENC_NA);
    offset += 8;

    proto_tree_add_item(distributed_sak_tree, hf_mka_aes_key_wrap_sak,
                        tvb, offset, distributed_sak_len - 12, ENC_NA);
    offset += (distributed_sak_len - 12);
  }
  else
  {
    proto_tree_add_expert(distributed_sak_tree, pinfo, &ei_mka_undecoded, tvb, offset, distributed_sak_len);
    offset += distributed_sak_len;
  }

  if (distributed_sak_len%4) {
    int padding_len = (4 - (distributed_sak_len % 4));

    proto_tree_add_item(distributed_sak_tree, hf_mka_padding,
                        tvb, offset, padding_len, ENC_NA);

    offset += padding_len;
  }

  *offset_ptr = offset;
}

static void
dissect_distributed_cak(proto_tree *mka_tree, packet_info *pinfo _U_, tvbuff_t *tvb, int *offset_ptr)
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

  if (distributed_cak_len%4) {
    int padding_len = (4 - (distributed_cak_len % 4));

    proto_tree_add_item(distributed_cak_tree, hf_mka_padding,
                        tvb, offset, padding_len, ENC_NA);

    offset += padding_len;
  }

  *offset_ptr = offset;
}

static void
dissect_kmd(proto_tree *mka_tree, packet_info *pinfo _U_, tvbuff_t *tvb, int *offset_ptr)
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
dissect_announcement(proto_tree *mka_tree, packet_info *pinfo, tvbuff_t *tvb, int *offset_ptr)
{
  int offset = *offset_ptr;
  guint16 announcement_len;
  proto_tree *announcement_set_tree;
  proto_tree *ti;

  announcement_len = (tvb_get_ntohs(tvb, offset + 2)) & 0x0fff;
  ti = proto_tree_add_item(mka_tree, hf_mka_announcement_set, tvb, offset, announcement_len + 4, ENC_NA);
  announcement_set_tree = proto_item_add_subtree(ti, ett_mka_announcement_set);

  proto_tree_add_item(announcement_set_tree, hf_mka_param_set_type,
                      tvb, offset, 1, ENC_BIG_ENDIAN);

  offset += 2;

  proto_tree_add_uint(announcement_set_tree, hf_mka_param_body_length,
                      tvb, offset, 2, announcement_len);
  offset += 2;

  // See IEEE 802.1X-2010, Section 11.11.1, Figure 11-15 and Section 11.12
  proto_tree_add_expert(announcement_set_tree, pinfo, &ei_mka_unimplemented, tvb, offset, announcement_len);

  offset += announcement_len;

  *offset_ptr = offset;
}

static void
dissect_xpn(proto_tree *mka_tree, packet_info *pinfo _U_, tvbuff_t *tvb, int *offset_ptr)
{
  int offset = *offset_ptr;
  guint16 xpn_len;
  proto_tree *xpn_set_tree;
  proto_tree *ti;

  xpn_len = (tvb_get_ntohs(tvb, offset + 2)) & 0x0fff;
  ti = proto_tree_add_item(mka_tree, hf_mka_xpn_set, tvb, offset, xpn_len + 4, ENC_NA);
  xpn_set_tree = proto_item_add_subtree(ti, ett_mka_xpn_set);

  proto_tree_add_item(xpn_set_tree, hf_mka_param_set_type,
                      tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(xpn_set_tree, hf_mka_suspension_time,
                      tvb, offset, 1, ENC_NA);
  offset += 1;

  proto_tree_add_uint(xpn_set_tree, hf_mka_param_body_length,
                      tvb, offset, 2, xpn_len);
  offset += 2;

  proto_tree_add_item(xpn_set_tree, hf_mka_latest_lowest_acceptable_pn,
                      tvb, offset, 4, ENC_NA);
  offset += 4;

  proto_tree_add_item(xpn_set_tree, hf_mka_old_lowest_acceptable_pn,
                      tvb, offset, 4, ENC_NA);
  offset += 4;

  *offset_ptr = offset;
}

static void
dissect_icv(proto_tree *mka_tree, packet_info *pinfo _U_, tvbuff_t *tvb, int *offset_ptr, guint16 *icv_len)
{
  int offset = *offset_ptr;
  proto_tree *icv_set_tree;
  proto_tree *ti;

  *icv_len = (tvb_get_ntohs(tvb, offset + 2)) & 0x0fff;
  ti = proto_tree_add_item(mka_tree, hf_mka_icv_set, tvb, offset, 4, ENC_NA);
  icv_set_tree = proto_item_add_subtree(ti, ett_mka_icv_set);

  proto_tree_add_item(icv_set_tree, hf_mka_param_set_type,
                      tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_uint(icv_set_tree, hf_mka_param_body_length,
                      tvb, offset, 2, *icv_len);
  offset += 2;

  *offset_ptr = offset;
}

static void
dissect_unknown_param_set(proto_tree *mka_tree, packet_info *pinfo _U_, tvbuff_t *tvb, int *offset_ptr)
{
  int offset = *offset_ptr;
  guint16 param_set_len;
  proto_tree *param_set_tree;
  proto_tree *ti;

  param_set_len = (tvb_get_ntohs(tvb, offset + 2)) & 0x0fff;
  ti = proto_tree_add_item(mka_tree, hf_mka_unknown_set, tvb, offset, param_set_len + 4, ENC_NA);
  param_set_tree = proto_item_add_subtree(ti, ett_mka_unknown_set);

  proto_tree_add_item(param_set_tree, hf_mka_param_set_type,
                      tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_uint(param_set_tree, hf_mka_param_body_length,
                      tvb, offset, 2, param_set_len);
  offset += 2;

  proto_tree_add_item(param_set_tree, hf_mka_unknown_param_set,
                      tvb, offset, param_set_len, ENC_NA);

  offset += param_set_len;

  if (param_set_len%4) {
    int padding_len = (4 - (param_set_len % 4));

    proto_tree_add_item(param_set_tree, hf_mka_padding,
                        tvb, offset, padding_len, ENC_NA);

    offset += padding_len;
  }

  *offset_ptr = offset;
}

static int
dissect_mka(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  int         offset = 0;
  guint8      mka_version_type;
  guint16     icv_len = 16; // Default ICV length, see IEEE 802.1X-2010, Section 11.11
  proto_tree *ti;
  proto_tree *mka_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "EAPOL-MKA");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_mka, tvb, 0, -1, ENC_NA);
  mka_tree = proto_item_add_subtree(ti, ett_mka);

  /*
   * The 802.1X-2010 spec specifies support for MKA version 1 only.
   * The 802.1Xbx-2014 spec specifies support for MKA version 2.
   */
  mka_version_type = tvb_get_guint8(tvb, offset);
  if ((mka_version_type != 1) && (mka_version_type != 2)) {
    expert_add_info(pinfo, ti, &ei_unexpected_data);
  }

  /*
   * Basic Parameter set is always the first parameter set, dissect it first !
   */
  dissect_basic_paramset(mka_tree, pinfo, tvb, &offset);

  while(tvb_reported_length_remaining(tvb, offset) > icv_len) {
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s",
                        val_to_str_const(tvb_get_guint8(tvb, offset), param_set_type_vals, "Unknown"));
    switch (tvb_get_guint8(tvb, offset)) {
    case LIVE_PEER_LIST_TYPE:
    case POTENTIAL_PEER_LIST_TYPE:
      dissect_peer_list(mka_tree, pinfo, tvb, &offset);
      break;

    case MACSEC_SAK_USE_TYPE:
      dissect_sak_use(mka_tree, pinfo, tvb, &offset);
      break;

    case DISTRIBUTED_SAK_TYPE:
      dissect_distributed_sak(mka_tree, pinfo, tvb, &offset);
      break;

    case DISTRIBUTED_CAK_TYPE:
      dissect_distributed_cak(mka_tree, pinfo, tvb, &offset);
      break;

    case KMD_TYPE:
      dissect_kmd(mka_tree, pinfo, tvb, &offset);
      break;

    case ANNOUNCEMENT_TYPE:
      dissect_announcement(mka_tree, pinfo, tvb, &offset);
      break;

    case XPN_TYPE:
      dissect_xpn(mka_tree, pinfo, tvb, &offset);
      break;

    case ICV_TYPE:
      // This ICV indicator does not include the ICV itself, see IEEE 802.1X-2010, Section 11.11.1
      dissect_icv(mka_tree, pinfo, tvb, &offset, &icv_len);
      break;

    default:
      dissect_unknown_param_set(mka_tree, pinfo, tvb, &offset);
      break;
    }
  }

  proto_tree_add_item(mka_tree, hf_mka_icv, tvb, offset, icv_len, ENC_NA);

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
    { &ei_mka_unimplemented, {
        "mka.expert.unimplemented", PI_UNDECODED, PI_WARN, "Announcement TLVs not handled, if you want this implemented please contact the wireshark developers", EXPFILL }}
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
        "Key Management Domain set", "mka.kmd_set",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_announcement_set, {
        "Announcement parameter set", "mka.announcement_set",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_xpn_set, {
        "Extended Packet Numbering set", "mka.xpn_set",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_unknown_set, {
        "Unknown parameter set", "mka.unknown_set",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_unknown_param_set, {
        "Unknown parameter set", "mka.unknown_param_set",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_icv_set, {
        "Integrity Check Value Indicator", "mka.icv_indicator",
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
        FT_UINT32, BASE_HEX, VALS(algo_agility_vals), 0x0,
        NULL, HFILL }},

    { &hf_mka_cak_name, {
        "CAK Name", "mka.cak_name",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_padding, {
        "Padding", "mka.padding",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_peer_mi, {
        "Peer Member Identifier", "mka.peer_mi",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_peer_mn, {
        "Peer Message Number", "mka.peer_mn",
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
        "Latest Key: Key Server Member Identifier", "mka.latest_key_server_mi",
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
        "Old Key: Key Server Member Identifier", "mka.old_key_server_mi",
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
        FT_UINT8, BASE_DEC, VALS(confidentiality_offset_vals), 0x30,
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

    { &hf_mka_suspension_time, {
        "Suspension time", "mka.suspension_time",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_mka_icv, {
        "Integrity Check Value", "mka.icv",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }}
  };

  static gint *ett[] = {
    &ett_mka,
    &ett_mka_basic_param_set,
    &ett_mka_peer_list_set,
    &ett_mka_sak_use_set,
    &ett_mka_distributed_sak_set,
    &ett_mka_distributed_cak_set,
    &ett_mka_kmd_set,
    &ett_mka_announcement_set,
    &ett_mka_xpn_set,
    &ett_mka_unknown_set,
    &ett_mka_icv_set
  };

  proto_mka = proto_register_protocol("MACsec Key Agreement", "EAPOL-MKA", "mka");
  register_dissector("mka", dissect_mka, proto_mka);

  proto_register_field_array(proto_mka, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  expert_mka = expert_register_protocol(proto_mka);
  expert_register_field_array(expert_mka, ei, array_length(ei));

}

void
proto_reg_handoff_mka(void)
{
  static dissector_handle_t mka_handle;

  mka_handle = create_dissector_handle(dissect_mka, proto_mka);
  dissector_add_uint("eapol.type", EAPOL_MKA, mka_handle);
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
