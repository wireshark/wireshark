/* packet-aruba-adp.c
 * Routines for Aruba ADP header disassembly
 *
 * $Id$
 *
 * Giles Scott < gscott <at> arubanetworks dot com>
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
#include <epan/addr_resolv.h>

#define UDP_PORT_ADP 8200
#define ADP_REQUEST 1
#define ADP_RESPONSE 2

static int proto_aruba_adp = -1;
static gint ett_aruba_adp  = -1;

static int hf_adp_version  = -1;
static int hf_adp_type     = -1;
static int hf_adp_id       = -1;
static int hf_adp_mac      = -1;
static int hf_adp_switchip = -1;

static const value_string adp_type_val[] =
{
  {1, "Request"},
  {2, "Response"},
  {0, NULL},
};

static void
dissect_aruba_adp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *ti = NULL;
  proto_tree *aruba_adp_tree = NULL;
  guint16 type;
  const gchar *mac_str;
  const gchar *switchip;


  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ADP");
  col_clear(pinfo->cinfo, COL_INFO);


  if (tree) {
    ti = proto_tree_add_item(tree, proto_aruba_adp, tvb, 0, 0, ENC_NA);
    aruba_adp_tree = proto_item_add_subtree(ti, ett_aruba_adp);

    proto_tree_add_item(aruba_adp_tree, hf_adp_version, tvb, 0, 2, ENC_BIG_ENDIAN);
  }
  type = tvb_get_ntohs(tvb, 2);

  if (tree) {
    proto_tree_add_item(aruba_adp_tree, hf_adp_type, tvb, 2, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(aruba_adp_tree, hf_adp_id, tvb, 4, 2, ENC_BIG_ENDIAN);
  }

  switch(type){
    case ADP_REQUEST:

      proto_tree_add_item(aruba_adp_tree, hf_adp_mac, tvb, 6, 6, ENC_NA);
      mac_str = tvb_ether_to_str(tvb, 6);

      col_add_fstr(pinfo->cinfo, COL_INFO, "ADP Request Src MAC: %s", mac_str);

      proto_item_append_text(ti, ", Request Src MAC: %s", mac_str);
      break;

    case ADP_RESPONSE:

      proto_tree_add_item(aruba_adp_tree, hf_adp_switchip, tvb, 6, 4, ENC_BIG_ENDIAN);
      switchip = tvb_ip_to_str(tvb, 6);

        col_add_fstr(pinfo->cinfo, COL_INFO, "ADP Response Switch IP: %s", switchip);

      proto_item_append_text(ti, ", Response Switch IP: %s", switchip);
      break;

    default:
        break;

  }
}

void
proto_register_aruba_adp(void)
{
  static hf_register_info hf[] = {
    { &hf_adp_version,
    { "Version", "adp.version", FT_UINT16, BASE_DEC, NULL,0x0,
    "ADP version", HFILL}},

    { &hf_adp_type,
    { "Type", "adp.type", FT_UINT16, BASE_DEC, VALS(adp_type_val), 0x0,
    "ADP type", HFILL}},

    { &hf_adp_id,
    { "Transaction ID", "adp.id", FT_UINT16, BASE_DEC, NULL, 0x0,
    "ADP transaction ID", HFILL}},

    { &hf_adp_mac,
    { "MAC address", "adp.mac", FT_ETHER, BASE_NONE, NULL, 0x0,
    NULL, HFILL}},

    { &hf_adp_switchip,
    { "Switch IP", "adp.switch", FT_IPv4, BASE_NONE, NULL, 0x0,
    "Switch IP address", HFILL}},

    };

  static gint *ett[] = {
    &ett_aruba_adp,
  };

  proto_aruba_adp = proto_register_protocol("Aruba Discovery Protocol",
                    "ADP", "adp");
  proto_register_field_array(proto_aruba_adp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_aruba_adp(void)
{
  dissector_handle_t adp_handle;

  adp_handle = create_dissector_handle(dissect_aruba_adp, proto_aruba_adp);
  dissector_add_uint("udp.port", UDP_PORT_ADP, adp_handle);
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

