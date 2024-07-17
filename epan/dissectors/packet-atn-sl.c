/* packet-atn-sl.c
 * Routines for ISO/OSI network protocol packet disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_atn_sl(void);
void proto_reg_handoff_atn_sl(void);

/* protocols and fields */

static int  proto_atn_sl;
static int ett_atn_sl;

static int hf_atn_sl_tt;
static int hf_atn_sl_sc;

/* ATN traffic types (ICAO doc 9705 Edition3 SV5 5.6.2.2.6.7.3) */
#define ATN_TT_ATSC_NO_PREFERENCE       0x01
#define ATN_TT_ATSC_CLASS_A             0x10
#define ATN_TT_ATSC_CLASS_B             0x11
#define ATN_TT_ATSC_CLASS_C             0x12
#define ATN_TT_ATSC_CLASS_D             0x13
#define ATN_TT_ATSC_CLASS_E             0x14
#define ATN_TT_ATSC_CLASS_F             0x15
#define ATN_TT_ATSC_CLASS_G             0x16
#define ATN_TT_ATSC_CLASS_H             0x17
#define ATN_TT_AOC_NO_PREFERENCE        0x21
#define ATN_TT_AOC_G                    0x22
#define ATN_TT_AOC_V                    0x23
#define ATN_TT_AOC_S                    0x24
#define ATN_TT_AOC_H                    0x25
#define ATN_TT_AOC_M                    0x26
#define ATN_TT_AOC_G_V                  0x27
#define ATN_TT_AOC_G_V_S                0x28
#define ATN_TT_AOC_G_V_H_S              0x29
#define ATN_TT_ADM_NO_PREFERENCE        0x30
#define ATN_TT_SYS_MGMT_NO_PREFERENCE   0x60

/* ATN security classification (ICAO doc 9705 Edition3 SV5 5.6.2.2.6.8.3) */
#define ATN_SC_UNCLASSIFIED             0x01
#define ATN_SC_RESTRICTED               0x02
#define ATN_SC_CONFIDENTIAL             0x03
#define ATN_SC_SECRET                   0x04
#define ATN_SC_TOP_SECRET               0x05

/* ATN security label records */
#define OSI_OPT_SECURITY_ATN_SR         0xc0
#define OSI_OPT_SECURITY_ATN_TT         0x0f
#define OSI_OPT_SECURITY_ATN_SC         0x03
#define OSI_OPT_SECURITY_ATN_SR_LEN     6
#define OSI_OPT_SECURITY_ATN_TT_LEN     1
#define OSI_OPT_SECURITY_ATN_SC_LEN     1
#define OSI_OPT_SECURITY_ATN_SI_MAX_LEN 8


static const unsigned char atn_security_registration_val[] = {
  0x06, 0x04, 0x2b, 0x1b, 0x00, 0x00
}; /* =iso(1).org(3).ICAO(27).ATN(0).TrafficType(0)*/

#if 0
static const value_string osi_opt_sec_atn_sr_vals[] = {
  {OSI_OPT_SECURITY_ATN_SR, "ATN Security Label"},
  {0,                       NULL}
};
#endif

static const value_string osi_opt_sec_atn_si_vals[] = {
  {OSI_OPT_SECURITY_ATN_TT, "Traffic Type and Routing"},
  {OSI_OPT_SECURITY_ATN_SC, "Security classification"},
  {0,                       NULL}
};

static const value_string osi_opt_sec_atn_tt_vals[] = {
  {ATN_TT_ATSC_NO_PREFERENCE,     "ATSC No preference"},
  {ATN_TT_ATSC_CLASS_A,           "ATSC Class A"},
  {ATN_TT_ATSC_CLASS_B,           "ATSC Class B"},
  {ATN_TT_ATSC_CLASS_C,           "ATSC Class C"},
  {ATN_TT_ATSC_CLASS_D,           "ATSC Class D"},
  {ATN_TT_ATSC_CLASS_E,           "ATSC Class E"},
  {ATN_TT_ATSC_CLASS_F,           "ATSC Class F"},
  {ATN_TT_ATSC_CLASS_G,           "ATSC Class G"},
  {ATN_TT_ATSC_CLASS_H,           "ATSC Class H"},
  {ATN_TT_AOC_NO_PREFERENCE,      "AOC No preference"},
  {ATN_TT_AOC_G,                  "AOC Gatelink only"},
  {ATN_TT_AOC_V,                  "AOC VHF only"},
  {ATN_TT_AOC_S,                  "AOC Satellite only"},
  {ATN_TT_AOC_H,                  "AOC HF only"},
  {ATN_TT_AOC_M,                  "AOC Mode S only"},
  {ATN_TT_AOC_G_V,                "AOC Gatelink first, then VHF"},
  {ATN_TT_AOC_G_V_S,              "AOC Gatelink first, then VHF, then Satellite"},
  {ATN_TT_AOC_G_V_H_S,            "AOC Gatelink first, then VHF, then HF, then Satellite"},
  {ATN_TT_ADM_NO_PREFERENCE,      "ATN Administrative No preference"},
  {ATN_TT_SYS_MGMT_NO_PREFERENCE, "ATN Systems Management No preference"},
  {0,                             NULL}
};

static const value_string osi_opt_sec_atn_sc_vals[] = {
  {ATN_SC_UNCLASSIFIED, "unclassified"},
  {ATN_SC_RESTRICTED,   "restricted"},
  {ATN_SC_CONFIDENTIAL, "confidential"},
  {ATN_SC_SECRET,       "secret"},
  {ATN_SC_TOP_SECRET,   "top secret"},
  {0,                   NULL}
};

/* dissect ATN security label used for policy based interdomain routing.*/
/* For details see ICAO doc 9705 Edition 3 SV5 5.6.2.2.2.2 */
static int
dissect_atn_sl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
               void* data _U_)
{
  proto_item *ti;
  proto_tree *atn_sl_tree;
  unsigned offset = 0;
  unsigned char len = 0;
  uint8_t tag_name = 0;
  unsigned  security_info_end = 0;

  ti = proto_tree_add_item(tree, proto_atn_sl, tvb, offset, -1, ENC_NA);
  atn_sl_tree = proto_item_add_subtree(ti, ett_atn_sl);

  /* check Security Registration Length */
  len =  tvb_get_uint8(tvb, offset);
  if ( OSI_OPT_SECURITY_ATN_SR_LEN != len )
    return tvb_captured_length(tvb);
  offset++;

  /* check Security Registration ID */
  if ( tvb_memeql(tvb, offset, atn_security_registration_val, OSI_OPT_SECURITY_ATN_SR_LEN) )
    return tvb_captured_length(tvb);

  offset += OSI_OPT_SECURITY_ATN_SR_LEN;

  /* Security Information length */
  len = tvb_get_uint8(tvb, offset);

  if ( OSI_OPT_SECURITY_ATN_SI_MAX_LEN < len )
    return tvb_captured_length(tvb);

  offset++;

  security_info_end = offset + len;
  while ( offset < security_info_end ) {
    /* check tag name length*/
    len = tvb_get_uint8(tvb, offset); /* check tag name length*/
    if ( len != 1 )
      return tvb_captured_length(tvb);

    offset++;

    tag_name = tvb_get_uint8(tvb, offset);
    offset++;

    switch(tag_name) {
      case OSI_OPT_SECURITY_ATN_TT:
        /* check tag set length*/
        len = tvb_get_uint8(tvb, offset);
        if ( len != OSI_OPT_SECURITY_ATN_TT_LEN )
          return tvb_captured_length(tvb);

        offset++;
        proto_tree_add_uint_format(atn_sl_tree, hf_atn_sl_tt, tvb, offset, 1,
                                   tvb_get_uint8(tvb, offset), "%s: %s",
                                   val_to_str(OSI_OPT_SECURITY_ATN_TT, osi_opt_sec_atn_si_vals, "Unknown (0x%x)"),
                                   val_to_str(tvb_get_uint8(tvb, offset ), osi_opt_sec_atn_tt_vals, "Unknown (0x%x)"));
        offset += len;
        break;

      case OSI_OPT_SECURITY_ATN_SC:
        /* check tag set length*/
        len = tvb_get_uint8(tvb, offset);
        if ( len != OSI_OPT_SECURITY_ATN_SC_LEN )
          return tvb_captured_length(tvb);

        offset++;
        proto_tree_add_uint_format(atn_sl_tree, hf_atn_sl_sc, tvb, offset, 1,
                                   tvb_get_uint8(tvb, offset), "%s: %s",
                                   val_to_str(OSI_OPT_SECURITY_ATN_SC, osi_opt_sec_atn_si_vals, "Unknown (0x%x)"),
                                   val_to_str(tvb_get_uint8(tvb, offset ), osi_opt_sec_atn_sc_vals, "Unknown (0x%x)"));
        offset += len;
        break;

      default:
        return tvb_captured_length(tvb);
    }
  }
  return tvb_captured_length(tvb);
}

void
proto_register_atn_sl(void)
{
  static hf_register_info hf[] = {
    { &hf_atn_sl_tt,
      { "ATN traffic type", "atn_sl.tt", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_atn_sl_sc,
      { "ATN security classification", "atn_sl.sc", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
  };
  static int *ett[] = {
    &ett_atn_sl,
  };

  proto_atn_sl = proto_register_protocol("ATN Security Label", "ATN SL", "atn_sl");
  proto_register_field_array(proto_atn_sl, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_atn_sl(void)
{
  dissector_handle_t atn_sl_handle;

  atn_sl_handle = create_dissector_handle(dissect_atn_sl, proto_atn_sl);
  dissector_add_for_decode_as("osi.opt_security", atn_sl_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
