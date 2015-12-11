/* packet-dsdreq.c
 * Routines for Dynamic Service Delete Request dissection
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

void proto_register_docsis_dsdreq(void);
void proto_reg_handoff_docsis_dsdreq(void);

/* Initialize the protocol and registered fields */
static int proto_docsis_dsdreq = -1;
static int hf_docsis_dsdreq_tranid = -1;
static int hf_docsis_dsdreq_rsvd = -1;
static int hf_docsis_dsdreq_sfid = -1;

static dissector_handle_t docsis_tlv_handle;

/* Initialize the subtree pointers */
static gint ett_docsis_dsdreq = -1;

/* Dissection */
static int
dissect_dsdreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *dsdreq_tree = NULL;
  guint16 transid;
  tvbuff_t *next_tvb;

  transid = tvb_get_ntohs (tvb, 0);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Dynamic Service Delete Request Tran-id = %u", transid);
  if (tree)
    {
      it =
        proto_tree_add_protocol_format (tree, proto_docsis_dsdreq, tvb, 0, -1,
                                        "DSD Request");
      dsdreq_tree = proto_item_add_subtree (it, ett_docsis_dsdreq);
      proto_tree_add_item (dsdreq_tree, hf_docsis_dsdreq_tranid, tvb, 0, 2,
                           ENC_BIG_ENDIAN);
      proto_tree_add_item (dsdreq_tree, hf_docsis_dsdreq_rsvd, tvb, 2, 2,
                           ENC_BIG_ENDIAN);
      proto_tree_add_item (dsdreq_tree, hf_docsis_dsdreq_sfid, tvb, 4, 4,
                           ENC_BIG_ENDIAN);
    }

    /* Call Dissector for Appendix C TLV's */
    next_tvb = tvb_new_subset_remaining (tvb, 8);
    call_dissector (docsis_tlv_handle, next_tvb, pinfo, dsdreq_tree);
    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */
void
proto_register_docsis_dsdreq (void)
{
  static hf_register_info hf[] = {
    {&hf_docsis_dsdreq_tranid,
     {"Transaction Id", "docsis_dsdreq.tranid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dsdreq_rsvd,
     {"Reserved", "docsis_dsdreq.rsvd",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dsdreq_sfid,
     {"Service Flow ID", "docsis_dsdreq.sfid",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
  };

  static gint *ett[] = {
    &ett_docsis_dsdreq,
  };

  proto_docsis_dsdreq =
    proto_register_protocol ("DOCSIS Dynamic Service Delete Request",
                             "DOCSIS DSD-REQ", "docsis_dsdreq");

  proto_register_field_array (proto_docsis_dsdreq, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("docsis_dsdreq", dissect_dsdreq, proto_docsis_dsdreq);
}

void
proto_reg_handoff_docsis_dsdreq (void)
{
  dissector_handle_t docsis_dsdreq_handle;

  docsis_dsdreq_handle = find_dissector ("docsis_dsdreq");
  docsis_tlv_handle = find_dissector ("docsis_tlv");
  dissector_add_uint ("docsis_mgmt", 0x15, docsis_dsdreq_handle);
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
