/* packet-sdh.c
 * Routines for SDH/SONET encapsulation dissection
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 - 2012 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>


#define COLUMNS 270

static int proto_sdh = -1;

static gint ett_sdh = -1;

static int hf_sdh_a1 = -1;
static int hf_sdh_a2 = -1;
static int hf_sdh_j0 = -1;
static int hf_sdh_b1 = -1;
static int hf_sdh_e1 = -1;
static int hf_sdh_f1 = -1;
static int hf_sdh_d1 = -1;
static int hf_sdh_d2 = -1;
static int hf_sdh_d3 = -1;
static int hf_sdh_au = -1;
static int hf_sdh_b2 = -1;
static int hf_sdh_k1 = -1;
static int hf_sdh_k2 = -1;
static int hf_sdh_d4 = -1;
static int hf_sdh_d5 = -1;
static int hf_sdh_d6 = -1;
static int hf_sdh_d7 = -1;
static int hf_sdh_d8 = -1;
static int hf_sdh_d9 = -1;
static int hf_sdh_d10 = -1;
static int hf_sdh_d11 = -1;
static int hf_sdh_d12 = -1;
static int hf_sdh_s1 = -1;
static int hf_sdh_m1 = -1;
static int hf_sdh_e2 = -1;

static int hf_sdh_j1 = -1;

static dissector_handle_t data_handle;

static gint sdh_data_rate = 1;

static enum_val_t data_rates[] = {
  {"Attempt to guess", "Attempt to guess", -1},
  {"OC-3",  "OC-3",   1},
  {"OC-12", "OC-12",  4},
  {"OC-24", "OC-24",  8},
  {"OC-48", "OC-48", 16},
  {NULL, NULL, -1}
};

static int 
get_sdh_level(tvbuff_t *tvb, packet_info *pinfo)
{
  /*data rate has been set in the SDH options*/
  if(sdh_data_rate != -1) return sdh_data_rate;
  /*ERF specifies data rate*/
  switch((pinfo->pseudo_header->erf.ehdr_list[0].ehdr & 0xff00) >> 8){ 
    case 1: /*OC-3*/
      return 1;
    case 2: /*OC-12*/
      return 4;
    case 3: /*OC-48*/
      return 16; 
    default:  /*drop through and try the next method*/
      ;   
  }
  /*returns the multiplier for each data level*/
  switch(tvb_reported_length(tvb)){
    case 2430:  /*OC-3*/
      return 1;
    case 9720:  /*OC-12*/
      return 4;
    case 19440: /*OC-24*/
      return 8;
    case 38880: /*OC-48*/
      return 16; 
  }

  return 1;
}


static void
dissect_sdh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SDH");
  col_clear(pinfo->cinfo,COL_INFO);

  if (tree) {
    proto_tree *sdh_tree;
    proto_item *sdh_item;

    int     level = get_sdh_level(tvb, pinfo);

    guint32 a1;
    guint32 a2;
    guint8  j0;
    guint8  b1;
    guint8  e1;
    guint8  f1;
    guint8  d1;
    guint8  d2;
    guint8  d3;
    guint8  h1;
    guint8  h2;
    guint16 au;
    guint32 b2;
    guint8  k1;
    guint8  k2;
    guint8  d4;
    guint8  d5;
    guint8  d6;
    guint8  d7;
    guint8  d8;
    guint8  d9;
    guint8  d10;
    guint8  d11;
    guint8  d12;
    guint8  s1;
    guint8  m1;
    guint8  e2;
    guint8  j1;

    sdh_item = proto_tree_add_protocol_format(tree, proto_sdh, tvb, 0, -1, "SDH");
    sdh_tree = proto_item_add_subtree(sdh_item, ett_sdh);

    a1  = tvb_get_ntoh24(tvb, 0+(0*level*COLUMNS));
    a2  = tvb_get_ntoh24(tvb, 3+(0*level*COLUMNS));
    j0  = tvb_get_guint8(tvb, 6+(0*level*COLUMNS));
    b1  = tvb_get_guint8(tvb, 0+(1*level*COLUMNS));
    e1  = tvb_get_guint8(tvb, 3+(1*level*COLUMNS));
    f1  = tvb_get_guint8(tvb, 6+(1*level*COLUMNS));
    d1  = tvb_get_guint8(tvb, 0+(2*level*COLUMNS));
    d2  = tvb_get_guint8(tvb, 3+(2*level*COLUMNS));
    d3  = tvb_get_guint8(tvb, 6+(2*level*COLUMNS));
    h1  = tvb_get_guint8(tvb, 0+(3*level*COLUMNS));
    h2  = tvb_get_guint8(tvb, 3+(3*level*COLUMNS));
    au  = (h2 | ((0x03 & h1) << 8));
    b2  = 0;
    b2  = tvb_get_guint8(tvb, 0+(4*level*COLUMNS)) << 16;
    b2  = tvb_get_guint8(tvb, (1*level)+(4*level*COLUMNS)) << 8;
    b2  = tvb_get_guint8(tvb, (2*level)+(4*level*COLUMNS));
    k1  = tvb_get_guint8(tvb, 3+(4*level*COLUMNS));
    k2  = tvb_get_guint8(tvb, 6+(4*level*COLUMNS));
    d4  = tvb_get_guint8(tvb, 0+(5*level*COLUMNS));
    d5  = tvb_get_guint8(tvb, 3+(5*level*COLUMNS));
    d6  = tvb_get_guint8(tvb, 6+(5*level*COLUMNS));
    d7  = tvb_get_guint8(tvb, 0+(6*level*COLUMNS));
    d8  = tvb_get_guint8(tvb, 3+(6*level*COLUMNS));
    d9  = tvb_get_guint8(tvb, 6+(6*level*COLUMNS));
    d10 = tvb_get_guint8(tvb, 0+(7*level*COLUMNS));
    d11 = tvb_get_guint8(tvb, 3+(7*level*COLUMNS));
    d12 = tvb_get_guint8(tvb, 6+(7*level*COLUMNS));
    s1  = tvb_get_guint8(tvb, 0+(8*level*COLUMNS));
    m1  = tvb_get_guint8(tvb, 5+(8*level*COLUMNS));
    e2  = tvb_get_guint8(tvb, 6+(8*level*COLUMNS));

    j1 = tvb_get_guint8(tvb, au);

    proto_tree_add_uint_format(sdh_tree, hf_sdh_a1,  tvb, 0, 3, a1, "A1 %x", a1);
    proto_tree_add_uint_format(sdh_tree, hf_sdh_a2,  tvb, 3, 3, a2, "A2 %x", a2);
    proto_tree_add_uint_format(sdh_tree, hf_sdh_j0,  tvb, 6, 1, j0, "J0 %d", j0);
    proto_tree_add_uint_format(sdh_tree, hf_sdh_b1,  tvb, 0+(1*level*COLUMNS), 1,  b1, "B1 %d",  b1);
    proto_tree_add_uint_format(sdh_tree, hf_sdh_e1,  tvb, 3+(1*level*COLUMNS), 1,  e1, "E1 %d",  e1);
    proto_tree_add_uint_format(sdh_tree, hf_sdh_f1,  tvb, 6+(1*level*COLUMNS), 1,  f1, "F1 %d",  f1);
    proto_tree_add_uint_format(sdh_tree, hf_sdh_d1,  tvb, 0+(2*level*COLUMNS), 1,  d1, "D1 %d",  d1);
    proto_tree_add_uint_format(sdh_tree, hf_sdh_d2,  tvb, 3+(2*level*COLUMNS), 1,  d2, "D2 %d",  d2);
    proto_tree_add_uint_format(sdh_tree, hf_sdh_d3,  tvb, 6+(2*level*COLUMNS), 1,  d3, "D3 %d",  d3);
    proto_tree_add_uint_format(sdh_tree, hf_sdh_au,  tvb, 0+(3*level*COLUMNS), 9,  au, "AU pointer %d h1 %d, h2 %d", au, h1, h2);
    proto_tree_add_uint_format(sdh_tree, hf_sdh_b2,  tvb, 0+(4*level*COLUMNS), 1,  b2, "B2 %d",  b2);
    proto_tree_add_uint_format(sdh_tree, hf_sdh_k1,  tvb, 3+(4*level*COLUMNS), 1,  k1, "K1 %d",  k1);
    proto_tree_add_uint_format(sdh_tree, hf_sdh_k2,  tvb, 6+(4*level*COLUMNS), 1,  k2, "K2 %d",  k2);
    proto_tree_add_uint_format(sdh_tree, hf_sdh_d4,  tvb, 0+(5*level*COLUMNS), 1,  d4, "D4 %d",  d4);
    proto_tree_add_uint_format(sdh_tree, hf_sdh_d5,  tvb, 3+(5*level*COLUMNS), 1,  d5, "D5 %d",  d5);
    proto_tree_add_uint_format(sdh_tree, hf_sdh_d6,  tvb, 6+(5*level*COLUMNS), 1,  d6, "D6 %d",  d6);
    proto_tree_add_uint_format(sdh_tree, hf_sdh_d7,  tvb, 0+(6*level*COLUMNS), 1,  d7, "D7 %d",  d7);
    proto_tree_add_uint_format(sdh_tree, hf_sdh_d8,  tvb, 3+(6*level*COLUMNS), 1,  d8, "D8 %d",  d8);
    proto_tree_add_uint_format(sdh_tree, hf_sdh_d9,  tvb, 6+(6*level*COLUMNS), 1,  d9, "D9 %d",  d9);
    proto_tree_add_uint_format(sdh_tree, hf_sdh_d10, tvb, 0+(7*level*COLUMNS), 1, d10, "D10 %d", d10);
    proto_tree_add_uint_format(sdh_tree, hf_sdh_d11, tvb, 3+(7*level*COLUMNS), 1, d11, "D11 %d", d11);
    proto_tree_add_uint_format(sdh_tree, hf_sdh_d12, tvb, 6+(7*level*COLUMNS), 1, d12, "D12 %d", d12);
    proto_tree_add_uint_format(sdh_tree, hf_sdh_s1,  tvb, 0+(8*level*COLUMNS), 1,  s1, "S1 %d",  s1);
    proto_tree_add_uint_format(sdh_tree, hf_sdh_m1,  tvb, 5+(8*level*COLUMNS), 1,  m1, "M1 %d",  m1);
    proto_tree_add_uint_format(sdh_tree, hf_sdh_e2,  tvb, 6+(7*level*COLUMNS), 1,  e2, "E2 %d",  e2);

    proto_tree_add_uint_format(sdh_tree, hf_sdh_j1,  tvb, au, 1, j1, "J1 %d", j1);
  }

}

void
proto_register_sdh(void)
{
  static hf_register_info hf[] = {
    { &hf_sdh_a1,
    { "A1", "sdh.a1", FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_sdh_a2,
    { "A2", "sdh.a2", FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_sdh_j0,
    { "J0", "sdh.j0", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_sdh_b1,
    { "B1", "sdh.b1", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_sdh_e1,
    { "E1", "sdh.e1", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_sdh_f1,
    { "F1", "sdh.f1", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_sdh_d1,
    { "D1", "sdh.d1", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_sdh_d2,
    { "D2", "sdh.d2", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_sdh_d3,
    { "D3", "sdh.d3", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_sdh_au,
    { "AU", "sdh.au", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_sdh_b2,
    { "B2", "sdh.b2", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_sdh_k1,
    { "K1", "sdh.k1", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_sdh_k2,
    { "K2", "sdh.k2", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_sdh_d4,
    { "D4", "sdh.d4", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_sdh_d5,
    { "D5", "sdh.d5", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_sdh_d6,
    { "D6", "sdh.d6", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_sdh_d7,
    { "D7", "sdh.d7", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_sdh_d8,
    { "D8", "sdh.d8", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_sdh_d9,
    { "D9", "sdh.d9", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_sdh_d10,
    { "D10", "sdh.d10", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_sdh_d11,
    { "D11", "sdh.d11", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_sdh_d12,
    { "D12", "sdh.d12", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_sdh_s1,
    { "S1", "sdh.s1", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_sdh_m1,
    { "M1", "sdh.m1", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_sdh_e2,
    { "E2", "sdh.e2", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_sdh_j1,
    { "J1", "sdh.j1", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }}
  };
  static gint *ett[] = {
    &ett_sdh
  };

  module_t *sdh_module;


  proto_sdh = proto_register_protocol("SDH/SONET Protocol", "SDH", "sdh");
  proto_register_field_array(proto_sdh, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  sdh_module = prefs_register_protocol(proto_sdh, NULL);
  prefs_register_enum_preference(sdh_module, "data.rate",
    "Data rate",
    "Data rate",
    &sdh_data_rate, data_rates, ENC_BIG_ENDIAN);

  register_dissector("sdh", dissect_sdh, proto_sdh);
}

void
proto_reg_handoff_sdh(void)
{
  dissector_handle_t sdh_handle;

  sdh_handle = find_dissector("sdh");
  dissector_add_uint("wtap_encap", WTAP_ENCAP_SDH, sdh_handle);

  data_handle = find_dissector("data");

}

