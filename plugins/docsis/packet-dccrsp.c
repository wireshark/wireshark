/* packet-dccrsp.c
 * Routines for DCC Response Message  dissection
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

void proto_register_docsis_dccrsp(void);
void proto_reg_handoff_docsis_dccrsp(void);

#define DCCRSP_CM_JUMP_TIME 1
#define DCCRSP_KEY_SEQ_NUM 31
#define DCCRSP_HMAC_DIGEST 27

/* Define DCC-RSP CM Jump Time subtypes
 * These are subtype of DCCRSP_CM_JUMP_TIME (1)
 */
#define DCCRSP_CM_JUMP_TIME_LENGTH 1
#define DCCRSP_CM_JUMP_TIME_START 2

/* Initialize the protocol and registered fields */
static int proto_docsis_dccrsp = -1;

static int hf_docsis_dccrsp_tran_id = -1;
static int hf_docsis_dccrsp_conf_code = -1;
static int hf_docsis_dcc_type = -1;
static int hf_docsis_dcc_length = -1;
static int hf_docsis_dcc_cm_jump_subtype = -1;
static int hf_docsis_dcc_cm_jump_length = -1;
static int hf_docsis_dccrsp_cm_jump_time_length = -1;
static int hf_docsis_dccrsp_cm_jump_time_start = -1;
static int hf_docsis_dccrsp_key_seq_num = -1;
static int hf_docsis_dccrsp_hmac_digest = -1;

/* Initialize the subtree pointers */
static gint ett_docsis_dccrsp = -1;
static gint ett_docsis_dccrsp_cm_jump_time = -1;
static gint ett_docsis_dccrsp_tlv = -1;

static expert_field ei_docsis_dccrsp_tlvlen_bad = EI_INIT;

static dissector_handle_t docsis_dccrsp_handle;

/* Defined in packet-tlv.c */
extern value_string docsis_conf_code[];

static const value_string dccrsp_tlv_vals[] = {
  {DCCRSP_CM_JUMP_TIME, "CM Jump Time Encodings"},
  {DCCRSP_KEY_SEQ_NUM, "Auth Key Sequence Number"},
  {DCCRSP_HMAC_DIGEST, "HMAC-Digest Number"},
  {0, NULL}
};

static const value_string cm_jump_subtlv_vals[] = {
  {DCCRSP_CM_JUMP_TIME_LENGTH, "Length of Jump"},
  {DCCRSP_CM_JUMP_TIME_START, "Start Time of Jump"},
  {0, NULL}
};

/* Dissection */
static void
dissect_dccrsp_cm_jump_time (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int start, guint16 len)
{
  guint8 type;
  guint32 length;
  proto_tree *dcc_tree;
  proto_item *dcc_item, *tlv_len_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_guint8 (tvb, pos);
    dcc_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_dccrsp_cm_jump_time, &dcc_item,
                                            val_to_str(type, cm_jump_subtlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (dcc_tree, hf_docsis_dcc_cm_jump_subtype, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (dcc_tree, hf_docsis_dcc_cm_jump_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(dcc_item, length + 2);

    switch (type)
    {
    case DCCRSP_CM_JUMP_TIME_LENGTH:
      if (length == 4)
      {
        proto_tree_add_item (dcc_tree, hf_docsis_dccrsp_cm_jump_time_length, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_dccrsp_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCRSP_CM_JUMP_TIME_START:
      if (length == 8)
      {
        proto_tree_add_item (dcc_tree, hf_docsis_dccrsp_cm_jump_time_start, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_dccrsp_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    }

    pos += length;
  }
}

static int
dissect_dccrsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  guint16 pos;
  guint8 type;
  guint32 length;
  proto_tree *dcc_tree, *tlv_tree;
  proto_item *dcc_item, *tlv_item, *tlv_len_item;

  col_set_str(pinfo->cinfo, COL_INFO, "DCC-RSP Message");

  dcc_item = proto_tree_add_item (tree, proto_docsis_dccrsp, tvb, 0, -1, ENC_NA);
  dcc_tree = proto_item_add_subtree (dcc_item, ett_docsis_dccrsp);
  proto_tree_add_item (dcc_tree, hf_docsis_dccrsp_tran_id, tvb, 0, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item (dcc_tree, hf_docsis_dccrsp_conf_code, tvb, 2, 1, ENC_BIG_ENDIAN);

  pos = 3;
  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    type = tvb_get_guint8 (tvb, pos);
    tlv_tree = proto_tree_add_subtree(dcc_tree, tvb, pos, -1,
                                            ett_docsis_dccrsp_tlv, &tlv_item,
                                            val_to_str(type, dccrsp_tlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (tlv_tree, hf_docsis_dcc_type, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (tlv_tree, hf_docsis_dcc_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(tlv_item, length + 2);

    switch (type)
    {
    case DCCRSP_CM_JUMP_TIME:
      dissect_dccrsp_cm_jump_time (tvb, pinfo, tlv_tree, pos, length );
      break;
    case DCCRSP_KEY_SEQ_NUM:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_dccrsp_key_seq_num, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_dccrsp_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCRSP_HMAC_DIGEST:
      if (length == 20)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_dccrsp_hmac_digest, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_dccrsp_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    }      /* switch(type) */

    pos += length;
  }       /* while (tvb_reported_length_remaining(tvb, pos) > 0) */

  return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */
void
proto_register_docsis_dccrsp (void)
{
  static hf_register_info hf[] = {
    {&hf_docsis_dccrsp_tran_id ,
     {
       "Transaction ID",
       "docsis_dccrsp.tran_id",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccrsp_conf_code ,
     {
       "Confirmation Code",
       "docsis_dccrsp.conf_code",
       FT_UINT8, BASE_DEC, VALS (docsis_conf_code), 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcc_type,
     {
      "Type",
      "docsis_dccrsp.tlvtype",
      FT_UINT8, BASE_DEC, VALS(dccrsp_tlv_vals), 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcc_length,
     {
      "Length",
      "docsis_dccrsp.tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcc_cm_jump_subtype,
     {
      "Type",
      "docsis_dccrsp.cm_jump_tlvtype",
      FT_UINT8, BASE_DEC, VALS(cm_jump_subtlv_vals), 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcc_cm_jump_length,
     {
      "Length",
      "docsis_dccrsp.cm_jump_tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dccrsp_cm_jump_time_length ,
     {
       "Length of Jump",
       "docsis_dccrsp.cm_jump_time_length",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccrsp_cm_jump_time_start ,
     {
       "Start Time of Jump",
       "docsis_dccrsp.cm_jump_time_start",
       FT_UINT64, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccrsp_key_seq_num ,
     {
       "Auth Key Sequence Number",
       "docsis_dccrsp.key_seq_num",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccrsp_hmac_digest ,
     {
       "HMAC-Digest Number",
       "docsis_dccrsp.hmac_digest",
       FT_BYTES, BASE_NONE, NULL, 0x0,
       NULL,
       HFILL
     }
    },

  };

  static gint *ett[] = {
    &ett_docsis_dccrsp,
    &ett_docsis_dccrsp_cm_jump_time,
    &ett_docsis_dccrsp_tlv,
  };

  static ei_register_info ei[] = {
    {&ei_docsis_dccrsp_tlvlen_bad, { "docsis_dccrsp.tlvlenbad", PI_MALFORMED, PI_ERROR, "Bad TLV length", EXPFILL}},
  };

  expert_module_t* expert_docsis_dccrsp;

  proto_docsis_dccrsp =
    proto_register_protocol ("DOCSIS Downstream Channel Change Response",
                             "DOCSIS DCC-RSP", "docsis_dccrsp");

  proto_register_field_array (proto_docsis_dccrsp, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
  expert_docsis_dccrsp = expert_register_protocol(proto_docsis_dccrsp);
  expert_register_field_array(expert_docsis_dccrsp, ei, array_length(ei));

  docsis_dccrsp_handle = register_dissector ("docsis_dccrsp", dissect_dccrsp, proto_docsis_dccrsp);
}

void
proto_reg_handoff_docsis_dccrsp (void)
{
  dissector_add_uint ("docsis_mgmt", 0x18, docsis_dccrsp_handle);

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
