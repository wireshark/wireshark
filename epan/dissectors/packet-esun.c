/* packet-esun.c
 * Routines for ESUN (Custom Protocol) dissection
 * Copyright 2025, Girish Kalele <gkalele@upscaleai.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/etypes.h>
#include <epan/packet.h>

void proto_register_esun(void);
void proto_reg_handoff_esun(void);

/* Protocol handle */
static int proto_esun;

/* Header fields */
static int hf_esun_rev;
static int hf_esun_fbit;
static int hf_esun_cos;
static int hf_esun_ecn;
static int hf_esun_flow_label;
static int hf_esun_ttl;
static int hf_esun_ud;
static int hf_esun_rsvd;

/* Subtree handle */
static int ett_esun;

/* Bit masks for Byte 0 */
#define ESUN_REV_MASK 0xC0
#define ESUN_FBIT_MASK 0x20
#define ESUN_COS_MASK 0x1C
#define ESUN_ECN_MASK 0x03

/* Bit masks for Byte 3 */
#define ESUN_TTL_MASK 0xF0
#define ESUN_UD_MASK 0x0C
#define ESUN_RSVD_MASK 0x03

/* Dissector function */
static int dissect_esun(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        void *data _U_) {
  proto_item *ti;
  proto_tree *esun_tree;
  guint8 byte0;
  bool f_bit_set;
  int offset = 0;

  /* Check that there's enough data */
  if (tvb_reported_length(tvb) < 4)
    return 0;

  /* Update Protocol column */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ESUN");
  col_clear(pinfo->cinfo, COL_INFO);

  /* Create Protocol Tree */
  ti = proto_tree_add_item(tree, proto_esun, tvb, 0, 4, ENC_NA);
  esun_tree = proto_item_add_subtree(ti, ett_esun);

  /* --- Byte 0 --- */
  byte0 = tvb_get_uint8(tvb, offset);
  proto_tree_add_item(esun_tree, hf_esun_rev, tvb, offset, 1, ENC_NA);
  proto_tree_add_item(esun_tree, hf_esun_fbit, tvb, offset, 1, ENC_NA);
  proto_tree_add_item(esun_tree, hf_esun_cos, tvb, offset, 1, ENC_NA);
  proto_tree_add_item(esun_tree, hf_esun_ecn, tvb, offset, 1, ENC_NA);

  /* Logic check for F-bit */
  f_bit_set = (byte0 & ESUN_FBIT_MASK) ? true : false;
  offset += 1;

  /* --- Byte 1-2: Flow Label --- */
  if (f_bit_set) {
    proto_tree_add_item(esun_tree, hf_esun_flow_label, tvb, offset, 2,
                        ENC_BIG_ENDIAN);
    col_append_fstr(pinfo->cinfo, COL_INFO, "Flow: 0x%04x ",
                    tvb_get_ntohs(tvb, offset));
  } else {
    proto_item *fl_item;
    fl_item = proto_tree_add_item(esun_tree, hf_esun_flow_label, tvb, offset, 2,
                                  ENC_BIG_ENDIAN);
    proto_item_append_text(fl_item, " <Ignored (F=0)>");
  }
  offset += 2;

  /* --- Byte 3 --- */
  /* byte3 was unused, just adding items to tree */
  proto_tree_add_item(esun_tree, hf_esun_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(esun_tree, hf_esun_ud, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(esun_tree, hf_esun_rsvd, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  /* Call data dissector for the rest */
  if (tvb_reported_length_remaining(tvb, offset) > 0) {
    call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, tree);
  }

  return tvb_captured_length(tvb);
}

/* Protocol Registration */
void proto_register_esun(void) {
  static hf_register_info hf[] = {
      /* Byte 0 */
      {&hf_esun_rev,
       {"Rev", "esun.rev", FT_UINT8, BASE_DEC, NULL, ESUN_REV_MASK, NULL,
        HFILL}},
      {&hf_esun_fbit,
       {"F-bit", "esun.f", FT_BOOLEAN, 8, NULL, ESUN_FBIT_MASK, NULL, HFILL}},
      {&hf_esun_cos,
       {"EH-CoS", "esun.cos", FT_UINT8, BASE_DEC, NULL, ESUN_COS_MASK, NULL,
        HFILL}},
      {&hf_esun_ecn,
       {"EH-ECN", "esun.ecn", FT_UINT8, BASE_DEC, NULL, ESUN_ECN_MASK, NULL,
        HFILL}},
      /* Byte 1-2 */
      {&hf_esun_flow_label,
       {"Flow Label", "esun.flow_label", FT_UINT16, BASE_DEC, NULL, 0x0, NULL,
        HFILL}},
      /* Byte 3 */
      {&hf_esun_ttl,
       {"Time to Live", "esun.ttl", FT_UINT8, BASE_DEC, NULL, ESUN_TTL_MASK,
        "Packet Time to Live (TTL)", HFILL}},
      {&hf_esun_ud,
       {"User Defined Bits", "esun.ud", FT_UINT8, BASE_DEC, NULL, ESUN_UD_MASK,
        "Bits available for user definition", HFILL}},
      {&hf_esun_rsvd,
       {"Reserved Bits", "esun.rsvd", FT_UINT8, BASE_DEC, NULL, ESUN_RSVD_MASK,
        "Reserved for future use", HFILL}}};

  static int *ett[] = {&ett_esun};

  proto_esun = proto_register_protocol("ESUN Protocol", "ESUN", "esun");
  proto_register_field_array(proto_esun, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

/* Handoff Registration */
void proto_reg_handoff_esun(void) {
  static dissector_handle_t esun_handle;

  esun_handle = create_dissector_handle(dissect_esun, proto_esun);
  dissector_add_for_decode_as("ethertype", esun_handle);
}
