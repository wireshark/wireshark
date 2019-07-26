/* packet-eero.c
 * Routines for EERO packet disassembly
 *
 * By Charlie Lenahan <clenahan@sonicbison.com>
 * Copyright 2019 Charlie Lenahan
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <epan/etypes.h>


void proto_register_eero(void);
void proto_reg_handoff_eero(void);

static int proto_eero = -1;

static int hf_eero_type = -1;
static int hf_eero_src_mac = -1;
static int hf_eero_data = -1;

static gint ett_eero = -1;

static dissector_handle_t eero_handle;

static capture_dissector_handle_t eero_cap_handle;



static gboolean
capture_eero(const guchar *pd _U_, int offset _U_, int len _U_, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header _U_)
{
  capture_dissector_increment_count(cpinfo, proto_eero);
  return TRUE;
}

static int
dissect_eero(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  int           tot_len;
  proto_tree   *eero_tree           = NULL;
  proto_item   *ti;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "EERO");
  col_clear(pinfo->cinfo, COL_INFO);

  tot_len = tvb_reported_length_remaining(tvb,0);


  if (tree)
  {
      int offset=0;
      int type = tvb_get_guint8(tvb, 0);

      ti = proto_tree_add_protocol_format(tree, proto_eero, tvb, offset, tot_len, "EERO,  Type 0x%04x", type);

      eero_tree = proto_item_add_subtree(ti, ett_eero);

      proto_tree_add_uint(eero_tree, hf_eero_type, tvb, offset, 1, type);
      offset+=1;

      proto_tree_add_item(eero_tree, hf_eero_src_mac, tvb, offset, 6, ENC_NA);
      offset += 6;

      proto_tree_add_item(eero_tree,
                          hf_eero_data,
                          tvb, offset, tvb_reported_length_remaining(tvb,offset), ENC_NA);
  }

   return tvb_captured_length(tvb);
}

void
proto_register_eero(void)
{
  static hf_register_info hf[] = {
      { &hf_eero_src_mac,
          { "Sender MAC address", "eero.hw_mac",
              FT_ETHER, BASE_NONE, NULL, 0x0,
              NULL, HFILL }},
      { &hf_eero_type,
          { "Type", "eero.type",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
      },
      { &hf_eero_data,
          { "Data", "eero.data",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }},
  };

  static gint *ett[] = {
    &ett_eero
  };


  proto_eero = proto_register_protocol("EERO Protocol","EERO", "eero");

  proto_register_field_array(proto_eero, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  eero_handle = register_dissector( "eero" , dissect_eero, proto_eero );

  eero_cap_handle = register_capture_dissector("eero", capture_eero, proto_eero);
}

void
proto_reg_handoff_eero(void)
{
  dissector_add_uint("ethertype", ETHERTYPE_EERO, eero_handle);

  capture_dissector_add_uint("ethertype", ETHERTYPE_EERO, eero_cap_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
