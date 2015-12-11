/* packet-regreqmp.c
 * Routines for REG-REQ-MP Message dissection
 * Copyright 2007, Bruno Verstuyft  <bruno.verstuyft@excentis.com>
 *
 * Based on packet-regreq.c (by Anand V. Narwani <anand[AT]narwani.org>)
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

void proto_register_docsis_regreqmp(void);
void proto_reg_handoff_docsis_regreqmp(void);

/* Initialize the protocol and registered fields */
static int proto_docsis_regreqmp = -1;

static int hf_docsis_regreqmp_sid = -1;

static int hf_docsis_regreqmp_number_of_fragments = -1;
static int hf_docsis_regreqmp_fragment_sequence_number = -1;

static dissector_handle_t docsis_tlv_handle;

/* Initialize the subtree pointers */
static gint ett_docsis_regreqmp = -1;

/* Dissection */
static int
dissect_regreqmp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *regreqmp_tree = NULL;
  tvbuff_t *next_tvb;

  col_set_str(pinfo->cinfo, COL_INFO, "REG-REQ-MP Message:");

  if (tree)
    {
      it = proto_tree_add_protocol_format (tree, proto_docsis_regreqmp, tvb, 0, -1,"REG-REQ-MP Message");
      regreqmp_tree = proto_item_add_subtree (it, ett_docsis_regreqmp);

      proto_tree_add_item (regreqmp_tree, hf_docsis_regreqmp_sid, tvb, 0, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item (regreqmp_tree, hf_docsis_regreqmp_number_of_fragments, tvb, 2, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item (regreqmp_tree, hf_docsis_regreqmp_fragment_sequence_number, tvb, 3, 1, ENC_BIG_ENDIAN);

    }
  /* Call Dissector for Appendix C TLV's */
  next_tvb = tvb_new_subset_remaining (tvb, 4);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, regreqmp_tree);
  return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */
void
proto_register_docsis_regreqmp (void)
{
  static hf_register_info hf[] = {
    {&hf_docsis_regreqmp_sid,
     {"Sid", "docsis_regreqmp.sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Reg-Req-Mp Sid", HFILL}
    },
    {&hf_docsis_regreqmp_number_of_fragments,
     {"Number of Fragments", "docsis_regreqmp.number_of_fragments",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Reg-Req-Mp Number of Fragments", HFILL}
    },
    {&hf_docsis_regreqmp_fragment_sequence_number,
     {"Fragment Sequence Number", "docsis_regreqmp.fragment_sequence_number",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Reg-Req-Mp Fragment Sequence Number", HFILL}
    },
  };

  static gint *ett[] = {
    &ett_docsis_regreqmp,
  };

  proto_docsis_regreqmp =
    proto_register_protocol ("DOCSIS Registration Request Multipart",
                             "DOCSIS Reg-Req-Mp", "docsis_regreqmp");

  proto_register_field_array (proto_docsis_regreqmp, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("docsis_regreqmp", dissect_regreqmp, proto_docsis_regreqmp);
}

void
proto_reg_handoff_docsis_regreqmp (void)
{
  dissector_handle_t docsis_regreqmp_handle;

  docsis_tlv_handle = find_dissector ("docsis_tlv");
  docsis_regreqmp_handle = find_dissector ("docsis_regreqmp");
  dissector_add_uint ("docsis_mgmt", 44, docsis_regreqmp_handle);
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
