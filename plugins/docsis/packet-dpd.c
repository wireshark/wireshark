/* packet-dpd.c
 * Routines for DOCSIS 3.1 Downstream Profile Descriptor dissection.
 * Copyright 2016, Bruno Verstuyft <bruno.verstuyft@excentis.com>
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


#define SUBCARRIER_ASSIGNMENT_RANGE_LIST 5
#define SUBCARRIER_ASSIGNMENT_VECTOR 6

#define SUBCARRIER_ASSIGNMENT_RANGE_CONT 0
#define SUBCARRIER_ASSIGNMENT_RANGE_SKIPBY1 1
#define SUBCARRIER_ASSIGNMENT_LIST 2


void proto_register_docsis_dpd(void);
void proto_reg_handoff_docsis_dpd(void);

/* Initialize the protocol and registered fields */
static int proto_docsis_dpd = -1;
static int hf_docsis_dpd_tlv_unknown = -1;
static int hf_docsis_dpd_dschid = -1;
static int hf_docsis_dpd_prof_id = -1;
static int hf_docsis_dpd_ccc = -1;

static int hf_docsis_dpd_tlv_subc_assign_type = -1;
static int hf_docsis_dpd_tlv_subc_assign_value = -1;
static int hf_docsis_dpd_subc_assign_range = -1;
static int hf_docsis_dpd_tlv_subc_assign_reserved = -1;
static int hf_docsis_dpd_tlv_subc_assign_modulation = -1;
static int hf_docsis_dpd_subc_assign_index = -1;

static int hf_docsis_dpd_tlv_subc_assign_vector_oddness = -1;
static int hf_docsis_dpd_tlv_subc_assign_vector_reserved = -1;
static int hf_docsis_dpd_tlv_subc_assign_vector_subc_start = -1;
static int hf_docsis_dpd_tlv_subc_assign_vector_modulation_odd = -1;
static int hf_docsis_dpd_tlv_subc_assign_vector_modulation_even = -1;


static expert_field ei_docsis_dpd_tlvlen_bad = EI_INIT;
static expert_field ei_docsis_dpd_value_unknown = EI_INIT;


/* Initialize the subtree pointers */
static gint ett_docsis_dpd = -1;
static gint ett_docsis_dpd_tlv = -1;
static gint ett_docsis_dpd_tlv_subcarrier_assignment = -1;
static gint ett_docsis_dpd_tlv_subcarrier_assignment_vector = -1;

/*BASE_CUSTOM function for subcarrier range*/
static void
subc_assign_range(
    char *buf,
    guint32 value)
{
    g_snprintf(buf, ITEM_LABEL_LENGTH,
               "%u - %u",
               value >> 16, value &0xFFFF);
}

static const value_string docsis_dpd_subc_assign_type_str[] = {
  {0, "range, continuous"},
  {1, "range, skip by 1"},
  {2, "list"},
  {3, "reserved"},
  {0, NULL}
};

static const value_string docsis_dpd_subc_assign_value_str[] = {
  {0, "specific value"},
  {1, "default value"},
  {0, NULL}
};

static const value_string docsis_dpd_subc_assign_modulation_str[] = {
  {0, "zero-bit loaded"},
  {1, "reserved"},
  {2, "QPSK (for NPC profile only)"},
  {3, "reserved"},
  {4, "16-QAM"},
  {5, "reserved"},
  {6, "64-QAM"},
  {7, "128-QAM"},
  {8, "256-QAM"},
  {9, "512-QAM"},
  {10, "1024-QAM"},
  {11, "2048-QAM"},
  {12, "4096-QAM"},
  {13, "8192-QAM"},
  {14, "16384-QAM"},
  {15, "reserved"},
  {0, NULL}
};

static const value_string docsis_dpd_tlv_subc_assign_vector_oddness_str[] = {
  {0, "N is even"},
  {1, "N is odd"},
  {0, NULL}
};

static const value_string docsis_dpd_tlv_subc_assign_vector_modulation_str[] = {
  {0, "zero-bit loaded"},
  {1, "continuous pilot"},
  {2, "QPSK (for NPC profile only)"},
  {3, "reserved"},
  {4, "16-QAM"},
  {5, "reserved"},
  {6, "64-QAM"},
  {7, "128-QAM"},
  {8, "256-QAM"},
  {9, "512-QAM"},
  {10, "1024-QAM"},
  {11, "2048-QAM"},
  {12, "4096-QAM"},
  {13, "8192-QAM"},
  {14, "16384-QAM"},
  {15, "reserved"},
  {0, NULL}
};


/* Dissection */
static void
dissect_dpd_subcarrier_assignment_range_list(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, guint start, guint len)
{
  proto_item *it;
  proto_tree *subcarrier_assignment_tree;
  guint8 subcarrier_assignment_type;
  guint16 subcarrier_assignment_index;

  it = proto_tree_add_protocol_format (tree, proto_docsis_dpd, tvb, start-2, len+2, ".5 Subcarrier Assignment Range/List");
  subcarrier_assignment_tree = proto_item_add_subtree (it, ett_docsis_dpd_tlv_subcarrier_assignment);

  proto_tree_add_item (subcarrier_assignment_tree, hf_docsis_dpd_tlv_subc_assign_type, tvb, start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (subcarrier_assignment_tree, hf_docsis_dpd_tlv_subc_assign_value, tvb, start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (subcarrier_assignment_tree, hf_docsis_dpd_tlv_subc_assign_reserved, tvb, start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (subcarrier_assignment_tree, hf_docsis_dpd_tlv_subc_assign_modulation, tvb, start, 1, ENC_BIG_ENDIAN);


  subcarrier_assignment_type = (tvb_get_guint8 (tvb, start) >> 6);

  switch (subcarrier_assignment_type)
  {
    case SUBCARRIER_ASSIGNMENT_RANGE_CONT:
    case SUBCARRIER_ASSIGNMENT_RANGE_SKIPBY1:
      proto_tree_add_item (subcarrier_assignment_tree, hf_docsis_dpd_subc_assign_range, tvb, start + 1, 4, ENC_BIG_ENDIAN);
      break;
    case SUBCARRIER_ASSIGNMENT_LIST:
      for (subcarrier_assignment_index = 0; subcarrier_assignment_index < len/2; ++subcarrier_assignment_index) {
        proto_tree_add_item (subcarrier_assignment_tree, hf_docsis_dpd_subc_assign_index, tvb, start + 1 + 2*subcarrier_assignment_index, 2, ENC_BIG_ENDIAN);
      }
      break;
    default:
      expert_add_info_format(pinfo, subcarrier_assignment_tree, &ei_docsis_dpd_value_unknown, "Unknown subcarrier assignment type: %u", subcarrier_assignment_type);
      break;
  }
}

static void
dissect_dpd_subcarrier_assignment_vector(tvbuff_t * tvb, proto_tree * tree, guint start, guint len)
{
  proto_item *it;
  proto_tree *subcarrier_assignment_vector_tree;
  guint8 subcarrier_assignment_vector_oddness;
  guint vector_index;

  it = proto_tree_add_protocol_format (tree, proto_docsis_dpd, tvb, start-3, len+3, ".6 Subcarrier Assignment Vector");
  subcarrier_assignment_vector_tree = proto_item_add_subtree (it, ett_docsis_dpd_tlv_subcarrier_assignment_vector);

  proto_tree_add_item (subcarrier_assignment_vector_tree, hf_docsis_dpd_tlv_subc_assign_vector_oddness, tvb, start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (subcarrier_assignment_vector_tree, hf_docsis_dpd_tlv_subc_assign_vector_reserved, tvb, start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (subcarrier_assignment_vector_tree, hf_docsis_dpd_tlv_subc_assign_vector_subc_start, tvb, start, 2, ENC_BIG_ENDIAN);


  subcarrier_assignment_vector_oddness = (tvb_get_guint8(tvb, start) >> 7);

  for(vector_index = 0; vector_index < len; ++vector_index)
  {
    proto_tree_add_item (subcarrier_assignment_vector_tree, hf_docsis_dpd_tlv_subc_assign_vector_modulation_odd, tvb, start + 2 + vector_index, 1, ENC_BIG_ENDIAN);
    if (!((vector_index == len -1) && subcarrier_assignment_vector_oddness))
    {
      proto_tree_add_item (subcarrier_assignment_vector_tree, hf_docsis_dpd_tlv_subc_assign_vector_modulation_even, tvb, start + 2 + vector_index, 1, ENC_BIG_ENDIAN);
    }
  }
}


static void
dissect_dpd_tlv (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, guint start, guint len)
{
  proto_item *it;
  proto_tree *tlv_tree;
  guint pos = start;
  guint length;
  guint8 type;

  it = proto_tree_add_protocol_format (tree, proto_docsis_dpd, tvb, 0, len, "TLV Data");
  tlv_tree = proto_item_add_subtree (it, ett_docsis_dpd_tlv);

  while (pos < (len + start))
  {
    type = tvb_get_guint8 (tvb, pos++);
    length = tvb_get_guint8 (tvb, pos++);
    if(pos + length > start + len)
    {
      expert_add_info_format(pinfo, tlv_tree, &ei_docsis_dpd_tlvlen_bad, "Wrong TLV length: %u", length);
    }

    switch (type)
    {
      case SUBCARRIER_ASSIGNMENT_RANGE_LIST:
        if (length >= 5)
        {
          dissect_dpd_subcarrier_assignment_range_list(tvb, pinfo, tlv_tree, pos, length);
        }
        else
        {
          expert_add_info_format(pinfo, tlv_tree, &ei_docsis_dpd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case SUBCARRIER_ASSIGNMENT_VECTOR:
        /*FOR THIS TYPE, LENGTH IS 2 BYTES INSTEAD OF 1 */
        length = tvb_get_ntohs (tvb, pos-1);
        ++pos;
        if (length >=2)
        {
          dissect_dpd_subcarrier_assignment_vector(tvb, tlv_tree, pos, length);
        }
        else
        {
          expert_add_info_format(pinfo, tlv_tree, &ei_docsis_dpd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      default: proto_tree_add_item (tlv_tree, hf_docsis_dpd_tlv_unknown, tvb, pos - 2, length+2, ENC_NA);
               expert_add_info_format(pinfo, tlv_tree, &ei_docsis_dpd_value_unknown, "Unknown TLV: %u", type);
               break;
    } /* switch */
    pos = pos + length;
  } /* while */
}

static int
dissect_dpd (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data  _U_)
{
  proto_item *it;
  proto_tree *dpd_tree = NULL;

  guint8 downstream_channel_id;
  guint8 profile_identifier;
  guint8 configuration_change_count;
  guint len;
  downstream_channel_id = tvb_get_guint8 (tvb, 0);
  profile_identifier = tvb_get_guint8 (tvb, 1);
  configuration_change_count = tvb_get_guint8 (tvb, 2);
  len = tvb_captured_length_remaining (tvb, 3);

  col_add_fstr (pinfo->cinfo, COL_INFO, "DPD: DS CH ID: %u, Profile ID: %u, CCC: %u", downstream_channel_id, profile_identifier, configuration_change_count);

  if (tree)
  {
    it = proto_tree_add_protocol_format (tree, proto_docsis_dpd, tvb, 0, -1, "Downstream Profile Descriptor");
    dpd_tree = proto_item_add_subtree (it, ett_docsis_dpd);
    proto_tree_add_item (dpd_tree, hf_docsis_dpd_dschid, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item (dpd_tree, hf_docsis_dpd_prof_id, tvb, 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item (dpd_tree, hf_docsis_dpd_ccc, tvb, 2, 1, ENC_BIG_ENDIAN);
  }
  /* Call Dissector TLV's */
  dissect_dpd_tlv(tvb, pinfo, dpd_tree, 3, len);

  return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */
void
proto_register_docsis_dpd(void)
{
  static hf_register_info hf[] = {
    {&hf_docsis_dpd_tlv_unknown,
     {"Unknown TLV", "docsis_dpd.unknown_tlv",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dpd_dschid,
     {"Downstream Channel ID", "docsis_dpd.dschid", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_dpd_prof_id,
     {"Profile Identifier", "docsis_dpd.prof_id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_dpd_ccc,
     {"Configuration Change Count", "docsis_dpd.ccc", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_subc_assign_type,
      {"Subcarrier Assignment Type", "docsis_dpd.tlv.subc_assign.type", FT_UINT8, BASE_DEC, VALS(docsis_dpd_subc_assign_type_str), 0xC0, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_subc_assign_value,
      {"Subcarrier Assignment Value", "docsis_dpd.tlv.subc_assign.value", FT_UINT8, BASE_DEC, VALS(docsis_dpd_subc_assign_value_str), 0x20, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_subc_assign_reserved,
      {"reserved", "docsis_dpd.tlv.subc_assign.reserved", FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_subc_assign_modulation,
     {"Subcarrier Assignment Modulation", "docsis_dpd.tlv.subc_assign.modulation", FT_UINT8, BASE_DEC, VALS(docsis_dpd_subc_assign_modulation_str), 0x0F, NULL, HFILL}
    },
    {&hf_docsis_dpd_subc_assign_range,
     {"Subcarrier index range", "docsis_dpd.tlv.subc_assign.range", FT_UINT32, BASE_CUSTOM, CF_FUNC(subc_assign_range), 0x00, NULL, HFILL}
    },
    {&hf_docsis_dpd_subc_assign_index,
     {"Subcarrier index", "docsis_dpd.tlv.subc_assign.index", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_subc_assign_vector_oddness,
     {"Odd or even", "docsis_dpd.tlv.subc_assign_vect.oddness", FT_UINT8, BASE_DEC, VALS(docsis_dpd_tlv_subc_assign_vector_oddness_str), 0x80, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_subc_assign_vector_reserved,
     {"Reserved", "docsis_dpd.tlv.subc_assign_vect.reserved", FT_UINT8, BASE_DEC, NULL, 0x60, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_subc_assign_vector_subc_start,
     {"Subcarrier start", "docsis_dpd.tlv.subc_assign_vect.subc_start", FT_UINT16, BASE_DEC, NULL, 0x1FFF, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_subc_assign_vector_modulation_odd,
     {"Modulation", "docsis_dpd.tlv.subc_assign_vect.modulation", FT_UINT8, BASE_DEC, VALS(docsis_dpd_tlv_subc_assign_vector_modulation_str), 0xF0, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_subc_assign_vector_modulation_even,
     {"Modulation", "docsis_dpd.tlv.subc_assign_vect.modulation", FT_UINT8, BASE_DEC, VALS(docsis_dpd_tlv_subc_assign_vector_modulation_str), 0x0F, NULL, HFILL}
    },
  };

  static ei_register_info ei[] = {
    {&ei_docsis_dpd_tlvlen_bad, { "docsis_dpd.tlvlenbad", PI_MALFORMED, PI_ERROR, "Bad TLV length", EXPFILL}},
    {&ei_docsis_dpd_value_unknown, { "docsis_dpd.valueunknown", PI_PROTOCOL, PI_WARN, "Unknown value", EXPFILL}}
  };

  static gint *ett[] = {
    &ett_docsis_dpd,
    &ett_docsis_dpd_tlv,
    &ett_docsis_dpd_tlv_subcarrier_assignment,
    &ett_docsis_dpd_tlv_subcarrier_assignment_vector
  };

  expert_module_t* expert_docsis_dpd;

  proto_docsis_dpd = proto_register_protocol ("DOCSIS Downstream Profile Descriptor", "DOCSIS DPD", "docsis_dpd");

  proto_register_field_array (proto_docsis_dpd, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
  expert_docsis_dpd = expert_register_protocol(proto_docsis_dpd);
  expert_register_field_array(expert_docsis_dpd, ei, array_length(ei));
  register_dissector ("docsis_dpd", dissect_dpd, proto_docsis_dpd);
}

void
proto_reg_handoff_docsis_dpd (void)
{
  dissector_handle_t docsis_dpd_handle;
  docsis_dpd_handle = find_dissector ("docsis_dpd");
  dissector_add_uint ("docsis_mgmt", 0x32, docsis_dpd_handle);
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
