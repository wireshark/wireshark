/* packet-intrngreq.c
 * Routines for Intial Ranging Request Message dissection
 * Copyright 2003, Brian Wheeler <brian.wheeler[AT]arrisi.com>
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

/* Initialize the protocol and registered fields */
static int proto_docsis_intrngreq = -1;
static int hf_docsis_intrngreq_down_chid = -1;
static int hf_docsis_intrngreq_sid = -1;
static int hf_docsis_intrngreq_up_chid = -1;

void proto_register_docsis_intrngreq(void);
void proto_reg_handoff_docsis_intrngreq(void);

/* Initialize the subtree pointers */
static gint ett_docsis_intrngreq = -1;

/* Dissection */
static int
dissect_intrngreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *intrngreq_item;
  proto_tree *intrngreq_tree;
  guint16 sid;

  sid = tvb_get_ntohs (tvb, 0);

  col_add_fstr (pinfo->cinfo, COL_INFO, "Initial Ranging Request: SID = %u",sid);

  if (tree)
    {
      intrngreq_item =
        proto_tree_add_protocol_format (tree, proto_docsis_intrngreq, tvb, 0,
                                        tvb_captured_length(tvb),
                                        "Initial Ranging Request");
      intrngreq_tree = proto_item_add_subtree (intrngreq_item, ett_docsis_intrngreq);
      proto_tree_add_item (intrngreq_tree, hf_docsis_intrngreq_sid, tvb, 0, 2,
                           ENC_BIG_ENDIAN);
      proto_tree_add_item (intrngreq_tree, hf_docsis_intrngreq_down_chid, tvb, 2, 1,
                           ENC_BIG_ENDIAN);
      proto_tree_add_item (intrngreq_tree, hf_docsis_intrngreq_up_chid, tvb, 3,
                           1, ENC_BIG_ENDIAN);
    }
    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */
void
proto_register_docsis_intrngreq (void)
{
  static hf_register_info hf[] = {
    {&hf_docsis_intrngreq_sid,
     {"Service Identifier", "docsis_intrngreq.sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_intrngreq_down_chid,
     {"Downstream Channel ID", "docsis_intrngreq.downchid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_intrngreq_up_chid,
     {"Upstream Channel ID", "docsis_intrngreq.upchid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },

  };

  static gint *ett[] = {
    &ett_docsis_intrngreq,
  };

  proto_docsis_intrngreq = proto_register_protocol ("DOCSIS Initial Ranging Message",
                                                    "DOCSIS INT-RNG-REQ",
                                                    "docsis_intrngreq");

  proto_register_field_array (proto_docsis_intrngreq, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("docsis_intrngreq", dissect_intrngreq, proto_docsis_intrngreq);
}

void
proto_reg_handoff_docsis_intrngreq (void)
{
  dissector_handle_t docsis_intrngreq_handle;

  docsis_intrngreq_handle = find_dissector ("docsis_intrngreq");
  dissector_add_uint ("docsis_mgmt", 0x1E, docsis_intrngreq_handle);
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
