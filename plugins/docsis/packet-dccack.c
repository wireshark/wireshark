/* packet-dccack.c
 * Routines for DCC Acknowledge Message  dissection
 * Copyright 2004, Darryl Hymel <darryl.hymel[AT]arrisi.com>
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
#include <epan/expert.h>

void proto_register_docsis_dccack(void);
void proto_reg_handoff_docsis_dccack(void);

#define DCCACK_KEY_SEQ_NUM 31
#define DCCACK_HMAC_DIGEST 27

/* Initialize the protocol and registered fields */
static int proto_docsis_dccack = -1;

static int hf_docsis_dcc_type = -1;
static int hf_docsis_dcc_length = -1;
static int hf_docsis_dccack_tran_id = -1;
static int hf_docsis_dccack_key_seq_num = -1;
static int hf_docsis_dccack_hmac_digest = -1;

/* Initialize the subtree pointers */
static gint ett_docsis_dccack = -1;
static gint ett_docsis_dccack_tlv = -1;

static const value_string dccack_tlv_vals[] = {
  {DCCACK_HMAC_DIGEST, "HMAC-DigestNumber"},
  {DCCACK_KEY_SEQ_NUM, "Auth Key Sequence Number"},
  {0, NULL}
};

static expert_field ei_docsis_dccack_tlvlen_bad = EI_INIT;

static dissector_handle_t docsis_dccack_handle;

/* Dissection */
static int
dissect_dccack (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  guint16 pos;
  guint8 type;
  guint32 length;
  proto_tree *dcc_tree, *tlv_tree;
  proto_item *dcc_item, *tlv_item, *tlv_len_item;

  col_set_str(pinfo->cinfo, COL_INFO, "DCC-ACK Message");

  dcc_item = proto_tree_add_item(tree, proto_docsis_dccack, tvb, 0, -1, ENC_NA);
  dcc_tree = proto_item_add_subtree (dcc_item, ett_docsis_dccack);
  proto_tree_add_item (dcc_tree, hf_docsis_dccack_tran_id, tvb, 0, 2, ENC_BIG_ENDIAN);

  pos = 2;
  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    type = tvb_get_guint8 (tvb, pos);
    tlv_tree = proto_tree_add_subtree(dcc_tree, tvb, pos, -1,
                                            ett_docsis_dccack_tlv, &tlv_item,
                                            val_to_str(type, dccack_tlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (tlv_tree, hf_docsis_dcc_type, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (tlv_tree, hf_docsis_dcc_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(tlv_item, length + 2);

    switch (type)
    {
    case DCCACK_KEY_SEQ_NUM:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_dccack_key_seq_num, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_dccack_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCACK_HMAC_DIGEST:
      if (length == 20)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_dccack_hmac_digest, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_dccack_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    }      /* switch(type) */

    pos += length;
  }        /*   while (tvb_reported_length_remaining(tvb, pos) > 0) */

  return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */
void
proto_register_docsis_dccack (void)
{
  static hf_register_info hf[] = {
    {&hf_docsis_dcc_type,
     {
      "Type",
      "docsis_dccack.tlvtype",
      FT_UINT8, BASE_DEC, VALS(dccack_tlv_vals), 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcc_length,
     {
      "Length",
      "docsis_dccack.tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dccack_tran_id ,
     {
       "Transaction ID",
       "docsis_dccack.tran_id",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccack_key_seq_num ,
     {
       "Auth Key Sequence Number",
       "docsis_dccack.key_seq_num",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccack_hmac_digest ,
     {
       "HMAC-DigestNumber",
       "docsis_dccack.hmac_digest",
       FT_BYTES, BASE_NONE, NULL, 0x0,
       NULL,
       HFILL
     }
    },

  };

  static gint *ett[] = {
    &ett_docsis_dccack,
    &ett_docsis_dccack_tlv,
  };

  static ei_register_info ei[] = {
    {&ei_docsis_dccack_tlvlen_bad, { "docsis_dccack.tlvlenbad", PI_MALFORMED, PI_ERROR, "Bad TLV length", EXPFILL}},
  };

  expert_module_t* expert_docsis_dccack;

  proto_docsis_dccack =
    proto_register_protocol ("DOCSIS Downstream Channel Change Acknowledge",
                             "DOCSIS DCC-ACK", "docsis_dccack");

  proto_register_field_array (proto_docsis_dccack, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
  expert_docsis_dccack = expert_register_protocol(proto_docsis_dccack);
  expert_register_field_array(expert_docsis_dccack, ei, array_length(ei));

  docsis_dccack_handle = register_dissector ("docsis_dccack", dissect_dccack, proto_docsis_dccack);
}

void
proto_reg_handoff_docsis_dccack (void)
{
  dissector_add_uint ("docsis_mgmt", 0x19, docsis_dccack_handle);

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
