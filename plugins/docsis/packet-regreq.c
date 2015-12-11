/* packet-regreq.c
 * Routines for Registration Request dissection
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

void proto_register_docsis_regreq(void);
void proto_reg_handoff_docsis_regreq(void);

/* Initialize the protocol and registered fields */
static int proto_docsis_regreq = -1;
static int hf_docsis_regreq_sid = -1;


/* Initialize the subtree pointers */
static gint ett_docsis_regreq = -1;

static dissector_handle_t docsis_tlv_handle;

/* Code to actually dissect the packets */
static int
dissect_regreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *regreq_tree = NULL;
  guint16 sid;
  tvbuff_t *next_tvb;

  sid = tvb_get_ntohs (tvb, 0);

  col_add_fstr (pinfo->cinfo, COL_INFO, "Registration Request SID = %u",
                sid);

  if (tree)
    {
      it =
        proto_tree_add_protocol_format (tree, proto_docsis_regreq, tvb, 0, -1,
                                        "Registration Request");
      regreq_tree = proto_item_add_subtree (it, ett_docsis_regreq);
      proto_tree_add_item (regreq_tree, hf_docsis_regreq_sid, tvb, 0, 2,
                           ENC_BIG_ENDIAN);
    }
    /* Call Dissector for Appendix C TlV's */
    next_tvb = tvb_new_subset_remaining (tvb, 2);
    call_dissector (docsis_tlv_handle, next_tvb, pinfo, regreq_tree);
    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */
void
proto_register_docsis_regreq (void)
{
  static hf_register_info hf[] = {
    {&hf_docsis_regreq_sid,
     {"Service Identifier", "docsis_regreq.sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
  };

  static gint *ett[] = {
    &ett_docsis_regreq,
  };

  proto_docsis_regreq =
    proto_register_protocol ("DOCSIS Registration Requests", "DOCSIS REG-REQ",
                             "docsis_regreq");

  proto_register_field_array (proto_docsis_regreq, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("docsis_regreq", dissect_regreq, proto_docsis_regreq);
}

void
proto_reg_handoff_docsis_regreq (void)
{
  dissector_handle_t docsis_regreq_handle;

  docsis_regreq_handle = find_dissector ("docsis_regreq");
  docsis_tlv_handle = find_dissector ("docsis_tlv");

  dissector_add_uint ("docsis_mgmt", 0x06, docsis_regreq_handle);
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
