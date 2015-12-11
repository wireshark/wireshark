/* packet-dscrsp.c
 * Routines for Dynamic Service Change Response dissection
 * Copyright 2002, Anand V. Narwani <anand[AT]narwani.org>
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

void proto_register_docsis_dscrsp(void);
void proto_reg_handoff_docsis_dscrsp(void);

/* Initialize the protocol and registered fields */
static int proto_docsis_dscrsp = -1;
static int hf_docsis_dscrsp_tranid = -1;
static int hf_docsis_dscrsp_response = -1;
static dissector_handle_t docsis_tlv_handle;

/* Initialize the subtree pointers */
static gint ett_docsis_dscrsp = -1;

extern value_string docsis_conf_code[];

/* Dissection */
static int
dissect_dscrsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *dscrsp_tree = NULL;
  guint16 transid;
  guint8 response;
  tvbuff_t *next_tvb;

  transid = tvb_get_ntohs (tvb, 0);
  response = tvb_get_guint8 (tvb, 2);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Dynamic Service Change Response ID = %u (%s)", transid,
                val_to_str (response, docsis_conf_code, "%d"));

  if (tree)
    {
      it =
        proto_tree_add_protocol_format (tree, proto_docsis_dscrsp, tvb, 0, -1,
                                        "DSC Response");
      dscrsp_tree = proto_item_add_subtree (it, ett_docsis_dscrsp);
      proto_tree_add_item (dscrsp_tree, hf_docsis_dscrsp_tranid, tvb, 0, 2,
                           ENC_BIG_ENDIAN);
      proto_tree_add_item (dscrsp_tree, hf_docsis_dscrsp_response, tvb, 2, 1,
                           ENC_BIG_ENDIAN);

    }
    /* Call Dissector for Appendix C TLV's */
    next_tvb = tvb_new_subset_remaining (tvb, 3);
    call_dissector (docsis_tlv_handle, next_tvb, pinfo, dscrsp_tree);
    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */
void
proto_register_docsis_dscrsp (void)
{
  static hf_register_info hf[] = {
    {&hf_docsis_dscrsp_tranid,
     {"Transaction Id", "docsis_dscrsp.tranid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Service Identifier", HFILL}
    },
    {&hf_docsis_dscrsp_response,
     {"Confirmation Code", "docsis_dscrsp.confcode",
      FT_UINT8, BASE_DEC, VALS (docsis_conf_code), 0x0,
      NULL, HFILL}
    },
  };

  static gint *ett[] = {
    &ett_docsis_dscrsp,
  };

  proto_docsis_dscrsp =
    proto_register_protocol ("DOCSIS Dynamic Service Change Response",
                             "DOCSIS DSC-RSP", "docsis_dscrsp");

  proto_register_field_array (proto_docsis_dscrsp, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("docsis_dscrsp", dissect_dscrsp, proto_docsis_dscrsp);
}

void
proto_reg_handoff_docsis_dscrsp (void)
{
  dissector_handle_t docsis_dscrsp_handle;

  docsis_dscrsp_handle = find_dissector ("docsis_dscrsp");
  docsis_tlv_handle = find_dissector ("docsis_tlv");
  dissector_add_uint ("docsis_mgmt", 0x13, docsis_dscrsp_handle);

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
