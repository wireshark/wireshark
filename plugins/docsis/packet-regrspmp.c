/* packet-regrspmp.c
 * Routines for REG-RSP-MP Message dissection
 * Copyright 2007, Bruno Verstuyft  <bruno.verstuyft@excentis.com>
 *
 * Based on packet-regrsp.c (by Anand V. Narwani <anand[AT]narwani.org>)
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

void proto_register_docsis_regrspmp(void);
void proto_reg_handoff_docsis_regrspmp(void);

/* Initialize the protocol and registered fields */
static int proto_docsis_regrspmp = -1;

static int hf_docsis_regrspmp_sid = -1;

static int hf_docsis_regrspmp_response = -1;

static int hf_docsis_regrspmp_number_of_fragments = -1;
static int hf_docsis_regrspmp_fragment_sequence_number = -1;

static dissector_handle_t docsis_tlv_handle;

/* Initialize the subtree pointers */
static gint ett_docsis_regrspmp = -1;

/* Dissection */
static int
dissect_regrspmp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *regrspmp_tree = NULL;
  tvbuff_t *next_tvb;

  col_set_str(pinfo->cinfo, COL_INFO, "REG-RSP-MP Message:");

  if (tree)
    {
      it = proto_tree_add_protocol_format (tree, proto_docsis_regrspmp, tvb, 0, -1,"REG-RSP-MP Message");
      regrspmp_tree = proto_item_add_subtree (it, ett_docsis_regrspmp);

      proto_tree_add_item (regrspmp_tree, hf_docsis_regrspmp_sid, tvb, 0, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item (regrspmp_tree, hf_docsis_regrspmp_response, tvb, 2, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item (regrspmp_tree, hf_docsis_regrspmp_number_of_fragments, tvb, 3, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item (regrspmp_tree, hf_docsis_regrspmp_fragment_sequence_number, tvb, 4, 1, ENC_BIG_ENDIAN);

    }
  /* Call Dissector for Appendix C TLV's */
  next_tvb = tvb_new_subset_remaining (tvb, 5);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, regrspmp_tree);
  return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */
void
proto_register_docsis_regrspmp (void)
{
  static hf_register_info hf[] = {
    {&hf_docsis_regrspmp_sid,
     {"Sid", "docsis_regrspmp.sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Reg-Rsp-Mp Sid", HFILL}
    },
    {&hf_docsis_regrspmp_response,
     {"Response", "docsis_regrspmp.response",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Reg-Rsp-Mp Response", HFILL}
    },
    {&hf_docsis_regrspmp_number_of_fragments,
     {"Number of Fragments", "docsis_regrspmp.number_of_fragments",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Reg-Rsp-Mp Number of Fragments", HFILL}
    },
    {&hf_docsis_regrspmp_fragment_sequence_number,
     {"Fragment Sequence Number", "docsis_regrspmp.fragment_sequence_number",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Reg-Rsp-Mp Fragment Sequence Number", HFILL}
    },
  };

  static gint *ett[] = {
    &ett_docsis_regrspmp,
  };

  proto_docsis_regrspmp =
    proto_register_protocol ("DOCSIS Registration Response Multipart",
                             "DOCSIS Reg-Rsp-Mp", "docsis_regrspmp");

  proto_register_field_array (proto_docsis_regrspmp, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("docsis_regrspmp", dissect_regrspmp, proto_docsis_regrspmp);
}

void
proto_reg_handoff_docsis_regrspmp (void)
{
  dissector_handle_t docsis_regrspmp_handle;

  docsis_tlv_handle = find_dissector ("docsis_tlv");
  docsis_regrspmp_handle = find_dissector ("docsis_regrspmp");
  dissector_add_uint ("docsis_mgmt", 45, docsis_regrspmp_handle);
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
