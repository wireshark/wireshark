/* packet-daytime.c
 * Routines for Daytime Protocol (RFC 867) packet dissection
 * Copyright 2006, Stephen Fisher (see AUTHORS file)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-time.c
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

#define NEW_PROTO_TREE_API

#include "config.h"

#include <epan/packet.h>

void proto_register_daytime(void);
void proto_reg_handoff_daytime(void);

static dissector_handle_t daytime_handle;

static header_field_info *hfi_daytime = NULL;

#define DAYTIME_HFI_INIT HFI_INIT(proto_daytime)

static header_field_info hfi_daytime_string DAYTIME_HFI_INIT =
{ "Daytime", "daytime.string",
  FT_STRING, BASE_NONE, NULL, 0x0,
  "String containing time and date", HFILL };

static header_field_info hfi_response_request DAYTIME_HFI_INIT =
{ "Type", "daytime.response_request",
  FT_BOOLEAN, 8, TFS(&tfs_response_request), 0x0,
  NULL, HFILL };

static gint ett_daytime = -1;

/* This dissector works for TCP and UDP daytime packets */
#define DAYTIME_PORT 13

static int
dissect_daytime(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_tree    *daytime_tree;
  proto_item    *ti;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "DAYTIME");

  col_add_fstr(pinfo->cinfo, COL_INFO, "DAYTIME %s",
    pinfo->srcport == pinfo->match_uint ? "Response":"Request");

  if (tree) {

    ti = proto_tree_add_item(tree, hfi_daytime, tvb, 0, -1, ENC_NA);
    daytime_tree = proto_item_add_subtree(ti, ett_daytime);

    proto_tree_add_boolean(daytime_tree, &hfi_response_request, tvb, 0, 0, pinfo->srcport==DAYTIME_PORT);
    if (pinfo->srcport == DAYTIME_PORT) {
      proto_tree_add_item(daytime_tree, &hfi_daytime_string, tvb, 0, -1, ENC_ASCII|ENC_NA);
    }
  }
  return tvb_captured_length(tvb);
}

void
proto_register_daytime(void)
{
#ifndef HAVE_HFI_SECTION_INIT
  static header_field_info *hfi[] = {
    &hfi_daytime_string,
    &hfi_response_request,
  };
#endif

  static gint *ett[] = {
    &ett_daytime,
  };

  int proto_daytime;

  proto_daytime = proto_register_protocol("Daytime Protocol", "DAYTIME", "daytime");
  hfi_daytime = proto_registrar_get_nth(proto_daytime);

  proto_register_fields(proto_daytime, hfi, array_length(hfi));
  proto_register_subtree_array(ett, array_length(ett));

  daytime_handle = create_dissector_handle(dissect_daytime, proto_daytime);
}

void
proto_reg_handoff_daytime(void)
{
  dissector_add_uint("udp.port", DAYTIME_PORT, daytime_handle);
  dissector_add_uint("tcp.port", DAYTIME_PORT, daytime_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
