/* packet-ocd.c
 * Routines for DOCSIS 3.1 OFDM Channel Descriptor dissection.
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

#include <wsutil/utf8_entities.h>

#define DISCRETE_FOURIER_TRANSFORM_SIZE 0
#define CYCLIC_PREFIX 1
#define ROLL_OFF 2
#define OFDM_SPECTRUM_LOCATION 3
#define TIME_INTERLEAVING_DEPTH 4
#define SUBCARRIER_ASSIGNMENT_RANGE_LIST 5
#define PRIMARY_CAPABILITY_INDICATOR 6

#define SUBCARRIER_ASSIGNMENT_RANGE_CONT 0
#define SUBCARRIER_ASSIGNMENT_RANGE_SKIPBY1 1
#define SUBCARRIER_ASSIGNMENT_LIST 2


void proto_register_docsis_ocd(void);
void proto_reg_handoff_docsis_ocd(void);

/* Initialize the protocol and registered fields */
static int proto_docsis_ocd = -1;
static int hf_docsis_ocd_tlv_unknown = -1;
static int hf_docsis_ocd_dschid = -1;
static int hf_docsis_ocd_ccc = -1;

static int hf_docsis_ocd_tlv_four_trans_size = -1;
static int hf_docsis_ocd_tlv_cycl_pref = -1;
static int hf_docsis_ocd_tlv_roll_off = -1;
static int hf_docsis_ocd_tlv_ofdm_spec_loc = -1;
static int hf_docsis_ocd_tlv_time_int_depth = -1;
static int hf_docsis_ocd_tlv_prim_cap_ind = -1;

static int hf_docsis_ocd_tlv_sub_assign_length = -1;
static int hf_docsis_ocd_tlv_subc_assign_type = -1;
static int hf_docsis_ocd_tlv_subc_assign_value = -1;
static int docsis_ocd_subc_assign_subc_type = -1;
static int docsis_ocd_subc_assign_range = -1;
static int docsis_ocd_subc_assign_index = -1;

/* Initialize the subtree pointers */
static gint ett_docsis_ocd = -1;
static gint ett_docsis_ocd_tlv = -1;
static gint ett_docsis_ocd_tlv_subcarrier_assignment = -1;

static expert_field ei_docsis_ocd_tlvlen_bad = EI_INIT;
static expert_field ei_docsis_ocd_value_unknown = EI_INIT;

static const value_string docsis_ocd_four_trans_size[] = {
  {0, "4096 subcarriers at 50 kHz spacing"},
  {1, "8192 subcarriers at 25 kHz spacing"},
  {0, NULL}
};

static const value_string docsis_ocd_cyc_prefix[] = {
  {0, "0.9375 "UTF8_MICRO_SIGN"s with 192 samples"},
  {1, "1.25 "UTF8_MICRO_SIGN"s with 256 samples"},
  {2, "2.5 "UTF8_MICRO_SIGN"s with 512 samples"},
  {3, "3.75 "UTF8_MICRO_SIGN"s with 768 samples"},
  {4, "5.0 "UTF8_MICRO_SIGN"s with 1024 samples"},
  {0, NULL}
};

static const value_string docsis_ocd_roll_off[] = {
  {0, "0 "UTF8_MICRO_SIGN"s with 0 samples"},
  {1, "0.3125 "UTF8_MICRO_SIGN"s with 64 samples"},
  {2, "0.625 "UTF8_MICRO_SIGN"s with 128 samples"},
  {3, "0.9375 "UTF8_MICRO_SIGN"s with 192 samples"},
  {4, "1.25 "UTF8_MICRO_SIGN"s with 256 samples"},
  {0, NULL}
};

static const value_string docsis_ocd_prim_cap_ind_str[] = {
  {0, "channel is not primary capable"},
  {1, "channel is primary capable"},
  {0, NULL}
};

/** BASE_CUSTOM formatter for the OFDM spectrum location
 */
static void
ofdm_spec_loc(
    char *buf,
    guint32 value)
{
    g_snprintf(buf, ITEM_LABEL_LENGTH,
        "%u Hz",
        value);
}

static void
subc_assign_range(
    char *buf,
    guint32 value)
{
    g_snprintf(buf, ITEM_LABEL_LENGTH,
        "%u - %u",
        value >> 16, value &0xFFFF);
}

static const value_string docsis_ocd_subc_assign_type_str[] = {
  {0, "range, continuous"},
  {1, "range, skip by 1"},
  {2, "list"},
  {3, "reserved"},
  {0, NULL}
};

static const value_string docsis_ocd_subc_assign_value_str[] = {
  {0, "specific value"},
  {1, "default value"},
  {0, NULL}
};

static const value_string docsis_ocd_subc_assign_subc_type_str[] = {
  {1, "continuous pilot"},
  {16, "excluded subcarriers"},
  {20, "PLC, 16-QAM"},
  {0, NULL}
};


/* Dissection */
static void
dissect_subcarrier_assignment_range_list(tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, guint16 start, guint16 len)
{
  proto_item *it;
  proto_tree *subcarrier_assignment_tree;
  guint8 subcarrier_assignment_type;
  guint16 subcarrier_assignment_index;

  it = proto_tree_add_protocol_format (tree, proto_docsis_ocd, tvb, start-2, len+2, ".5 Subcarrier Assignment Range/List");
  subcarrier_assignment_tree = proto_item_add_subtree (it, ett_docsis_ocd_tlv_subcarrier_assignment);

  proto_tree_add_item (subcarrier_assignment_tree, hf_docsis_ocd_tlv_sub_assign_length, tvb, start-1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (subcarrier_assignment_tree, hf_docsis_ocd_tlv_subc_assign_type, tvb, start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (subcarrier_assignment_tree, hf_docsis_ocd_tlv_subc_assign_value, tvb, start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (subcarrier_assignment_tree, docsis_ocd_subc_assign_subc_type, tvb, start, 1, ENC_BIG_ENDIAN);


  subcarrier_assignment_type = (tvb_get_guint8 (tvb, start) >> 6);

  switch (subcarrier_assignment_type) {
    case SUBCARRIER_ASSIGNMENT_RANGE_CONT:
    case SUBCARRIER_ASSIGNMENT_RANGE_SKIPBY1:
      proto_tree_add_item (subcarrier_assignment_tree, docsis_ocd_subc_assign_range, tvb, start + 1, 4, ENC_BIG_ENDIAN);
      break;
    case SUBCARRIER_ASSIGNMENT_LIST:
      for (subcarrier_assignment_index = 0; subcarrier_assignment_index < len/2; ++subcarrier_assignment_index) {
        proto_tree_add_item (subcarrier_assignment_tree, docsis_ocd_subc_assign_index, tvb, start + 1 + 2*subcarrier_assignment_index, 2, ENC_BIG_ENDIAN);
      }
      break;
    default:
      expert_add_info_format(pinfo, tree, &ei_docsis_ocd_value_unknown, "Unknown subcarrier assignment type %d", subcarrier_assignment_type);
      break;
  }
}


static void
dissect_ocd_tlv (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, guint8 start, guint16 len)
{
  proto_item *it;
  proto_tree *tlv_tree;
  guint16 pos = start;
  guint8 type, length;

  it = proto_tree_add_protocol_format (tree, proto_docsis_ocd, tvb, start, len, "TLV Data");
  tlv_tree = proto_item_add_subtree (it, ett_docsis_ocd_tlv);

  while (pos < (len + start))
  {
    type = tvb_get_guint8 (tvb, pos++);
    length = tvb_get_guint8 (tvb, pos++);
    if(pos + length > start + len) {
      expert_add_info_format(pinfo, tlv_tree, &ei_docsis_ocd_tlvlen_bad, "Wrong TLV length: %u", length);
    }
    switch (type)
    {
      case DISCRETE_FOURIER_TRANSFORM_SIZE:
        if (length == 1)
        {
          proto_tree_add_item (tlv_tree, hf_docsis_ocd_tlv_four_trans_size, tvb, pos, 1, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info_format(pinfo, tlv_tree, &ei_docsis_ocd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case CYCLIC_PREFIX:
        if (length == 1)
        {
          proto_tree_add_item (tlv_tree, hf_docsis_ocd_tlv_cycl_pref, tvb, pos, 1, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info_format(pinfo, tlv_tree, &ei_docsis_ocd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case ROLL_OFF:
        if (length == 1)
        {
          proto_tree_add_item (tlv_tree, hf_docsis_ocd_tlv_roll_off, tvb, pos, 1, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info_format(pinfo, tlv_tree, &ei_docsis_ocd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case OFDM_SPECTRUM_LOCATION:
        if (length == 4)
        {
          proto_tree_add_item (tlv_tree, hf_docsis_ocd_tlv_ofdm_spec_loc, tvb, pos, 4, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info_format(pinfo, tlv_tree, &ei_docsis_ocd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case TIME_INTERLEAVING_DEPTH:
        if (length == 1)
        {
          proto_tree_add_item (tlv_tree, hf_docsis_ocd_tlv_time_int_depth, tvb, pos, 1, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info_format(pinfo, tlv_tree, &ei_docsis_ocd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case SUBCARRIER_ASSIGNMENT_RANGE_LIST:
        if (length >= 5)
        {
          dissect_subcarrier_assignment_range_list(tvb, pinfo, tlv_tree, pos, length);
        }
        else
        {
          expert_add_info_format(pinfo, tlv_tree, &ei_docsis_ocd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case PRIMARY_CAPABILITY_INDICATOR:
        if (length == 1)
        {
          proto_tree_add_item (tlv_tree, hf_docsis_ocd_tlv_prim_cap_ind, tvb, pos, 1, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info_format(pinfo, tlv_tree, &ei_docsis_ocd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      default:
        proto_tree_add_item (tlv_tree, hf_docsis_ocd_tlv_unknown, tvb, pos - 2, length+2, ENC_NA);
        break;
    } /* switch */
    pos = pos + length;
  } /* while */
}

static int
dissect_ocd (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *ocd_tree = NULL;

  guint8 downstream_channel_id;
  guint8 configuration_change_count;
  guint16 len;

  downstream_channel_id = tvb_get_guint8 (tvb, 0);
  configuration_change_count = tvb_get_guint8 (tvb, 1);
  len = tvb_captured_length_remaining (tvb, 2);

  col_add_fstr (pinfo->cinfo, COL_INFO, "OCD: DS CH ID: %u, CCC: %u", downstream_channel_id, configuration_change_count);

  if (tree)
  {
    it = proto_tree_add_protocol_format (tree, proto_docsis_ocd, tvb, 0, -1, "OFDM Channel Descriptor");
    ocd_tree = proto_item_add_subtree (it, ett_docsis_ocd);
    proto_tree_add_item (ocd_tree, hf_docsis_ocd_dschid, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item (ocd_tree, hf_docsis_ocd_ccc, tvb, 1, 1, ENC_BIG_ENDIAN);
  }
  /* Call Dissector TLV's */
  dissect_ocd_tlv(tvb, pinfo, ocd_tree, 2, len);

  return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */
void
proto_register_docsis_ocd(void)
{
  static hf_register_info hf[] = {
    {&hf_docsis_ocd_tlv_unknown,
      {"Unknown TLV", "docsis_ocd.unknown_tlv", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_dschid,
      {"Downstream Channel ID", "docsis_ocd.dschid", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_ccc,
      {"Configuration Change Count", "docsis_ocd.ccc", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_tlv_four_trans_size,
      {".0 Discrete Fourier Transform Size", "docsis_ocd.tlv.four_trans_size", FT_UINT8, BASE_DEC, VALS (docsis_ocd_four_trans_size), 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_tlv_cycl_pref,
      {".1 Cylic Prefix", "docsis_ocd.tlv.cyc_pref", FT_UINT8, BASE_DEC, VALS (docsis_ocd_cyc_prefix), 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_tlv_roll_off,
      {".2 Roll Off", "docsis_ocd.tlv.roll_off", FT_UINT8, BASE_DEC, VALS (docsis_ocd_roll_off), 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_tlv_ofdm_spec_loc,
      {".3 OFDM Spectrum Location", "docsis_ocd.tlv.ofdm_spec_loc", FT_UINT32, BASE_CUSTOM, CF_FUNC(ofdm_spec_loc) , 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_tlv_time_int_depth,
      {".4 Time Interleaving Depth", "docsis_ocd.tlv.time_int_depth", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_tlv_prim_cap_ind,
      {".6 Primary Capable Indicator", "docsis_ocd.tlv.prim_cap_ind", FT_UINT8, BASE_DEC, VALS(docsis_ocd_prim_cap_ind_str), 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_tlv_sub_assign_length,
      {"Subcarrier Assignment Length", "docsis_ocd.tlv.subc_assign.length", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    {&hf_docsis_ocd_tlv_subc_assign_type,
      {"Assignment type", "docsis_ocd.tlv.subc_assign.type", FT_UINT8, BASE_DEC, VALS(docsis_ocd_subc_assign_type_str), 0xC0, NULL, HFILL}
    },
    {&hf_docsis_ocd_tlv_subc_assign_value,
      {"Assignment value", "docsis_ocd.tlv.subc_assign.value", FT_UINT8, BASE_DEC, VALS(docsis_ocd_subc_assign_value_str), 0x20, NULL, HFILL}
    },
    {&docsis_ocd_subc_assign_subc_type,
      {"Subcarrier Type", "docsis_ocd.tlv.subc_assign.subc_type", FT_UINT8, BASE_DEC, VALS(docsis_ocd_subc_assign_subc_type_str), 0x1F, NULL, HFILL}
    },
    {&docsis_ocd_subc_assign_range,
      {"Subcarrier index range", "docsis_ocd.tlv.subc_assign.range", FT_UINT32, BASE_CUSTOM, CF_FUNC(subc_assign_range), 0x00, NULL, HFILL}
    },
    {&docsis_ocd_subc_assign_index,
      {"Subcarrier index", "docsis_ocd.tlv.subc_assign.index", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
  };

  static ei_register_info ei[] = {
    {&ei_docsis_ocd_tlvlen_bad, { "docsis_ocd.tlvlenbad", PI_MALFORMED, PI_ERROR, "Bad TLV length", EXPFILL}},
    {&ei_docsis_ocd_value_unknown, { "docsis_ocd.valueunknown", PI_PROTOCOL, PI_WARN, "Unknown value", EXPFILL}}
  };

  static gint *ett[] = {
    &ett_docsis_ocd,
    &ett_docsis_ocd_tlv,
    &ett_docsis_ocd_tlv_subcarrier_assignment
  };

  expert_module_t* expert_docsis_ocd;

  proto_docsis_ocd = proto_register_protocol ("DOCSIS OFDM Channel Descriptor", "DOCSIS OCD", "docsis_ocd");

  proto_register_field_array (proto_docsis_ocd, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
  expert_docsis_ocd = expert_register_protocol(proto_docsis_ocd);
  expert_register_field_array(expert_docsis_ocd, ei, array_length(ei));
  register_dissector ("docsis_ocd", dissect_ocd, proto_docsis_ocd);
}

void
proto_reg_handoff_docsis_ocd (void)
{
  dissector_handle_t docsis_ocd_handle;
  docsis_ocd_handle = find_dissector ("docsis_ocd");
  dissector_add_uint ("docsis_mgmt", 0x31, docsis_ocd_handle);
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
