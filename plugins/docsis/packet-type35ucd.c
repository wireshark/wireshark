/* packet-type35ucd.c
 *
 * Routines for Type 35 UCD - DOCSIS 3.0 only - Message dissection
 * Copyright 2015, Adrian Simionov <daniel.simionov@gmail.com>
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

#define type35ucd_SYMBOL_RATE 1
#define type35ucd_FREQUENCY 2
#define type35ucd_PREAMBLE 3
#define type35ucd_BURST_DESCR5 5
#define type35ucd_EXT_PREAMBLE 6
#define type35ucd_SCDMA_MODE_ENABLE 7
#define type35ucd_SCDMA_SPREADING_INTERVAL 8
#define type35ucd_SCDMA_CODES_PER_MINI_SLOT 9
#define type35ucd_SCDMA_ACTIVE_CODES 10
#define type35ucd_SCDMA_CODE_HOPPING_SEED 11
#define type35ucd_SCDMA_US_RATIO_NUM 12
#define type35ucd_SCDMA_US_RATIO_DENOM 13
#define type35ucd_SCDMA_TIMESTAMP_SNAPSHOT 14
#define type35ucd_MAINTAIN_POWER_SPECTRAL_DENSITY 15
#define type35ucd_RANGING_REQUIRED 16
#define type35ucd_MAX_SCHEDULED_CODES 17
#define type35ucd_RANGING_HOLD_OFF_PRIORITY_FIELD 18
#define type35ucd_RANGING_CHANNEL_CLASS_ID 19
#define type35ucd_SCDMA_SELECTION_ACTIVE_CODES_AND_CODE_HOPPING 20
#define type35ucd_SCDMA_SELECTION_STRING_FOR_ACTIVE_CODES 21
#define type35ucd_HIGHER_UCD_FOR_SAME_UCID 22

#define type35ucd_MODULATION 1
#define type35ucd_DIFF_ENCODING 2
#define type35ucd_PREAMBLE_LEN 3
#define type35ucd_PREAMBLE_VAL_OFF 4
#define type35ucd_FEC 5
#define type35ucd_FEC_CODEWORD 6
#define type35ucd_SCRAMBLER_SEED 7
#define type35ucd_MAX_BURST 8
#define type35ucd_GUARD_TIME 9
#define type35ucd_LAST_CW_LEN 10
#define type35ucd_SCRAMBLER_ONOFF 11
#define type35ucd_RS_INT_DEPTH 12
#define type35ucd_RS_INT_BLOCK 13
#define type35ucd_PREAMBLE_TYPE 14
#define type35ucd_SCMDA_SCRAMBLER_ONOFF 15
#define type35ucd_SCDMA_CODES_PER_SUBFRAME 16
#define type35ucd_SCDMA_FRAMER_INT_STEP_SIZE 17
#define type35ucd_TCM_ENABLED 18

#define IUC_REQUEST 1
#define IUC_REQ_DATA 2
#define IUC_INIT_MAINT 3
#define IUC_STATION_MAINT 4
#define IUC_SHORT_DATA_GRANT 5
#define IUC_LONG_DATA_GRANT 6
#define IUC_NULL_IE 7
#define IUC_DATA_ACK 8
#define IUC_ADV_PHY_SHORT_DATA_GRANT 9
#define IUC_ADV_PHY_LONG_DATA_GRANT 10
#define IUC_ADV_PHY_UGS 11
#define IUC_RESERVED12 12
#define IUC_RESERVED13 13
#define IUC_RESERVED14 14
#define IUC_EXPANSION 15

void proto_register_docsis_type35ucd(void);
void proto_reg_handoff_docsis_type35ucd(void);

/* Initialize the protocol and registered fields */
static int proto_docsis_type35ucd = -1;

static int hf_docsis_type35ucd_upstream_chid = -1;
static int hf_docsis_type35ucd_config_ch_cnt = -1;
static int hf_docsis_type35ucd_mini_slot_size = -1;
static int hf_docsis_type35ucd_down_chid = -1;
static int hf_docsis_type35ucd_type = -1;
static int hf_docsis_type35ucd_length = -1;
static int hf_docsis_type35ucd_burst_type = -1;
static int hf_docsis_type35ucd_burst_length = -1;
static int hf_docsis_type35ucd_symbol_rate = -1;
static int hf_docsis_type35ucd_frequency = -1;
static int hf_docsis_type35ucd_preamble_pat = -1;
static int hf_docsis_type35ucd_iuc = -1;
static int hf_docsis_type35ucd_ext_preamble = -1;
static int hf_docsis_type35ucd_scdma_mode_enable = -1;
static int hf_docsis_type35ucd_scdma_spreading_interval = -1;
static int hf_docsis_type35ucd_scdma_codes_per_mini_slot = -1;
static int hf_docsis_type35ucd_scdma_active_codes = -1;
static int hf_docsis_type35ucd_scdma_code_hopping_seed = -1;
static int hf_docsis_type35ucd_scdma_us_ratio_num = -1;
static int hf_docsis_type35ucd_scdma_us_ratio_denom = -1;
static int hf_docsis_type35ucd_scdma_timestamp_snapshot = -1;
static int hf_docsis_type35ucd_maintain_power_spectral_density = -1;
static int hf_docsis_type35ucd_ranging_required = -1;
static int hf_docsis_type35ucd_rnghoff_cm = -1;
static int hf_docsis_type35ucd_rnghoff_erouter = -1;
static int hf_docsis_type35ucd_rnghoff_emta = -1;
static int hf_docsis_type35ucd_rnghoff_estb = -1;
static int hf_docsis_type35ucd_rnghoff_rsvd = -1;
static int hf_docsis_type35ucd_rnghoff_id_ext = -1;
static int hf_docsis_type35ucd_chan_class_id_cm = -1;
static int hf_docsis_type35ucd_chan_class_id_erouter = -1;
static int hf_docsis_type35ucd_chan_class_id_emta = -1;
static int hf_docsis_type35ucd_chan_class_id_estb = -1;
static int hf_docsis_type35ucd_chan_class_id_rsvd = -1;
static int hf_docsis_type35ucd_chan_class_id_id_ext = -1;
static int hf_docsis_type35ucd_max_scheduled_codes = -1;
static int hf_docsis_type35ucd_active_code_hopping = -1;
static int hf_docsis_type35ucd_higher_ucd_for_same_ucid = -1;
static int hf_docsis_type35ucd_higher_ucd_for_same_ucid_resv = -1;
static int hf_docsis_type35ucd_scdma_selection_active_codes = -1;

static int hf_docsis_burst_mod_type = -1;
static int hf_docsis_burst_diff_encoding = -1;
static int hf_docsis_burst_preamble_len = -1;
static int hf_docsis_burst_preamble_val_off = -1;
static int hf_docsis_burst_fec = -1;
static int hf_docsis_burst_fec_codeword = -1;
static int hf_docsis_burst_scrambler_seed = -1;
static int hf_docsis_burst_max_burst = -1;
static int hf_docsis_burst_guard_time = -1;
static int hf_docsis_burst_last_cw_len = -1;
static int hf_docsis_burst_scrambler_onoff = -1;
static int hf_docsis_rs_int_depth = -1;
static int hf_docsis_rs_int_block = -1;
static int hf_docsis_preamble_type = -1;
static int hf_docsis_scdma_scrambler_onoff = -1;
static int hf_docsis_scdma_codes_per_subframe = -1;
static int hf_docsis_scdma_framer_int_step_size = -1;
static int hf_docsis_tcm_enabled = -1;

static expert_field ei_docsis_type35ucd_tlvlen_bad = EI_INIT;
static expert_field ei_docsis_type35ucd_tlvtype_bad = EI_INIT;

/* Initialize the subtree pointers */
static gint ett_docsis_type35ucd = -1;
static gint ett_docsis_type35tlv = -1;
static gint ett_docsis_type35_burst_tlv = -1;

static const value_string channel_tlv_vals[] _U_ = {
  {type35ucd_SYMBOL_RATE,                     "Symbol Rate"},
  {type35ucd_FREQUENCY,                       "Frequency"},
  {type35ucd_PREAMBLE,                        "Preamble Pattern"},
  {type35ucd_BURST_DESCR5,                    "Burst Descriptor Type 5"},
  {type35ucd_EXT_PREAMBLE,                    "Extended Preamble Pattern"},
  {type35ucd_SCDMA_MODE_ENABLE,               "SCDMA Mode Enabled"},
  {type35ucd_SCDMA_SPREADING_INTERVAL,        "SCDMA Spreading Intervals per Frame"},
  {type35ucd_SCDMA_CODES_PER_MINI_SLOT,       "SCDMA Codes per Mini-slot"},
  {type35ucd_SCDMA_ACTIVE_CODES,              "SCDMA Number of Active Codes"},
  {type35ucd_SCDMA_CODE_HOPPING_SEED,         "SCDMA Code Hopping Seed"},
  {type35ucd_SCDMA_US_RATIO_NUM,              "SCDMA US ratio numerator M"},
  {type35ucd_SCDMA_US_RATIO_DENOM,            "SCDMA US ratio denominator N"},
  {type35ucd_SCDMA_TIMESTAMP_SNAPSHOT,        "SCDMA Timestamp Snapshot"},
  {type35ucd_MAINTAIN_POWER_SPECTRAL_DENSITY, "Maintain Power Spectral Density"},
  {type35ucd_RANGING_REQUIRED,                "Ranging Required"},
  {type35ucd_MAX_SCHEDULED_CODES,             "S-CDMA Maximum Scheduled Codes"},
  {type35ucd_RANGING_HOLD_OFF_PRIORITY_FIELD, "Ranging Hold-Off Priority Field"},
  {type35ucd_RANGING_CHANNEL_CLASS_ID,        "Ranging Channel Class ID"},
  {type35ucd_SCDMA_SELECTION_ACTIVE_CODES_AND_CODE_HOPPING, "S-CDMA Selection Mode for Active Codes and Code Hopping"},
  {type35ucd_SCDMA_SELECTION_STRING_FOR_ACTIVE_CODES, "S-CDMA Selection String for Active Codes"},
  {type35ucd_HIGHER_UCD_FOR_SAME_UCID,        "Higher UCD for the same UCID present bitmap"},
  {0, NULL}
};

static const value_string burst_tlv_vals[] = {
  {type35ucd_MODULATION,                      "Modulation Type"},
  {type35ucd_DIFF_ENCODING,                   "Differential Encoding"},
  {type35ucd_PREAMBLE_LEN,                    "Preamble Length"},
  {type35ucd_PREAMBLE_VAL_OFF,                "Preamble Value Offset"},
  {type35ucd_FEC,                             "FEC Error Correction (T)"},
  {type35ucd_FEC_CODEWORD,                    "FEC Codeword Information Bytes (k)"},
  {type35ucd_SCRAMBLER_SEED,                  "Scrambler Seed"},
  {type35ucd_MAX_BURST,                       "Maximum Burst Size"},
  {type35ucd_GUARD_TIME,                      "Guard Time Size"},
  {type35ucd_LAST_CW_LEN,                     "Last Codeword Length"},
  {type35ucd_SCRAMBLER_ONOFF,                 "Scrambler On/Off"},
  {type35ucd_RS_INT_DEPTH,                    "R-S Interleaver Depth (Ir)"},
  {type35ucd_RS_INT_BLOCK,                    "R-S Interleaver Block Size (Br)"},
  {type35ucd_PREAMBLE_TYPE,                   "Preamble Type"},
  {type35ucd_SCMDA_SCRAMBLER_ONOFF,           "S-CDMA Spreader On/Off"},
  {type35ucd_SCDMA_CODES_PER_SUBFRAME,        "S-CDMA Codes per Subframe"},
  {type35ucd_SCDMA_FRAMER_INT_STEP_SIZE,      "S-CDMA Framer Interleaving Step Size"},
  {type35ucd_TCM_ENABLED,                     "TCM Encoding"},
  {0, NULL}
};

static const value_string on_off_vals[] = {
  {1, "On"},
  {2, "Off"},
  {0, NULL}
};

static const value_string preamble_type[] = {
  {1, "QPSK0"},
  {2, "QPSK1"},
  {0, NULL}
};

const true_false_string type35ucd_tfs_allow_inhibit = { "Inhibit Initial Ranging",
                                                        "Ranging Allowed" };

const true_false_string type35ucd_tfs_inhibit_allow = { "Ranging Allowed",
                                                        "Inhibit Initial Ranging" };

static const value_string mod_vals2[] = {
  {1, "QPSK"},
  {2, "16-QAM"},
  {3, "8-QAM"},
  {4, "32-QAM"},
  {5, "64-QAM"},
  {6, "128-QAM (SCDMA-only)"},
  {7, "Reserved for C-DOCSIS"},
  {0, NULL}
};

static const value_string tlv20_vals[] = {
  {0, "Selectable active codes mode 1 enabled and code hopping disabled"},
  {1, "Selectable active codes mode 1 enabled and code hopping mode 1 enabled"},
  {2, "Selectable active codes mode 2 enabled and code hopping mode 2 enabled"},
  {3, "Selectable active codes mode 2 enabled and code hopping disabled"},
  {0, NULL}
};

const true_false_string type35ucd_tfs_present_not_present = { "UCD35 is present for this UCID",
                                                              "UCD35 is not present for this UCID" };

static const value_string iuc_vals3[] = {
  {IUC_REQUEST,                  "Request"},
  {IUC_REQ_DATA,                 "REQ/Data"},
  {IUC_INIT_MAINT,               "Initial Maintenance"},
  {IUC_STATION_MAINT,            "Station Maintenance"},
  {IUC_SHORT_DATA_GRANT,         "Short Data Grant"},
  {IUC_LONG_DATA_GRANT,          "Long Data Grant"},
  {IUC_NULL_IE,                  "NULL IE"},
  {IUC_DATA_ACK,                 "Data Ack"},
  {IUC_ADV_PHY_SHORT_DATA_GRANT, "Advanced Phy Short Data Grant"},
  {IUC_ADV_PHY_LONG_DATA_GRANT,  "Advanced Phy Long Data Grant"},
  {IUC_ADV_PHY_UGS,              "Advanced Phy UGS"},
  {IUC_RESERVED12,               "Reserved 12"},
  {IUC_RESERVED13,               "Reserved 13"},
  {IUC_RESERVED14,               "Reserved 14"},
  {IUC_EXPANSION,                "IUC Expansion"},
  {0, NULL}
};

static const value_string last_cw_len_vals[] = {
  {1, "Fixed"},
  {2, "Shortened"},
  {0, NULL}
};

static const value_string max_scheduled_codes_vals[] = {
  {1, "Enabled."},
  {2, "Disabled."},
  {0, NULL}
};

static const value_string ranging_required[] = {
  {0, "No ranging required."},
  {1, "Unicast initial ranging required."},
  {2, "Broadcast initial ranging required."},
  {0, NULL}
};

/* Dissection */
static int
dissect_type35ucd (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  guint16 pos, endtlvpos;
  guint8 type, length;
  guint8 tlvlen, tlvtype;
  proto_tree *type35ucd_burst_tree;
  proto_item *type35ucd_burst_item;
  proto_tree *type35ucd_tree;
  proto_item *type35ucd_item;
  proto_tree *type35tlv_tree;
  proto_item *type35tlv_item;
  guint16 len;
  guint8 upchid, symrate;

  len = tvb_reported_length(tvb);
  upchid = tvb_get_guint8 (tvb, 0);

  /* if the upstream Channel ID is 0 then this is for Telephony Return) */
  if (upchid > 0)
    col_add_fstr (pinfo->cinfo, COL_INFO,
                  "Type 35 UCD Message: Channel ID = %u (U%u)", upchid,
                  upchid - 1);
  else
    col_add_fstr (pinfo->cinfo, COL_INFO,
                  "Type 35 UCD Message: Channel ID = %u (Telephony Return)",
                  upchid);

  type35ucd_item =
    proto_tree_add_protocol_format (tree, proto_docsis_type35ucd, tvb, 0,
                                    tvb_captured_length(tvb),
                                    "UCD Message (Type 35)");
  type35ucd_tree = proto_item_add_subtree (type35ucd_item, ett_docsis_type35ucd);
  proto_tree_add_item (type35ucd_tree, hf_docsis_type35ucd_upstream_chid, tvb, 0, 1,
                       ENC_BIG_ENDIAN);
  proto_tree_add_item (type35ucd_tree, hf_docsis_type35ucd_config_ch_cnt, tvb, 1, 1,
                       ENC_BIG_ENDIAN);
  proto_tree_add_item (type35ucd_tree, hf_docsis_type35ucd_mini_slot_size, tvb, 2, 1,
                       ENC_BIG_ENDIAN);
  proto_tree_add_item (type35ucd_tree, hf_docsis_type35ucd_down_chid, tvb, 3, 1,
                       ENC_BIG_ENDIAN);

  pos = 4;
  while (pos < len)
    {
      type = tvb_get_guint8 (tvb, pos);
      type35tlv_tree = proto_tree_add_subtree(type35ucd_tree, tvb, pos, -1,
                                        ett_docsis_type35tlv, &type35tlv_item,
                                        val_to_str(type, channel_tlv_vals,
                                                   "Unknown TLV (%u)"));
      proto_tree_add_uint (type35tlv_tree, hf_docsis_type35ucd_type,
                           tvb, pos, 1, type);
      pos++;
      length = tvb_get_guint8 (tvb, pos);
      proto_tree_add_uint (type35tlv_tree, hf_docsis_type35ucd_length,
                           tvb, pos, 1, length);
      pos++;
      proto_item_set_len(type35tlv_item, length + 2);
      switch (type)
        {
          case type35ucd_SYMBOL_RATE:
            if (length == 1)
              {
                symrate = tvb_get_guint8 (tvb, pos);
                proto_tree_add_uint (type35tlv_tree, hf_docsis_type35ucd_symbol_rate,
                                     tvb, pos, length, symrate * 160);
              }
            else
              {
                expert_add_info_format(pinfo, type35tlv_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            pos = pos + length;
            break;
          case type35ucd_FREQUENCY:
            if (length == 4)
              {
                proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_frequency, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
                pos = pos + length;
              }
            else
              {
                expert_add_info_format(pinfo, type35tlv_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case type35ucd_PREAMBLE:
            proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_preamble_pat, tvb,
                                 pos, length, ENC_NA);
            pos = pos + length;
            break;
          case type35ucd_EXT_PREAMBLE:
            proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_ext_preamble, tvb,
                                 pos, length, ENC_NA);
            pos = pos + length;
            break;
          case type35ucd_SCDMA_MODE_ENABLE:
            if (length == 1)
              {
                proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_scdma_mode_enable,
                                     tvb, pos, length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, type35tlv_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            pos = pos + length;
            break;
          case type35ucd_SCDMA_SPREADING_INTERVAL:
            if (length == 1)
              {
                proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_scdma_spreading_interval,
                                     tvb, pos, length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, type35tlv_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            pos = pos + length;
            break;
          case type35ucd_SCDMA_CODES_PER_MINI_SLOT:
            if (length == 1)
              {
                proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_scdma_codes_per_mini_slot,
                                     tvb, pos, length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, type35tlv_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            pos = pos + length;
            break;
          case type35ucd_SCDMA_ACTIVE_CODES:
            if (length == 1)
              {
                proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_scdma_active_codes,
                                     tvb, pos, length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, type35tlv_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            pos = pos + length;
            break;
          case type35ucd_SCDMA_CODE_HOPPING_SEED:
            if (length == 2)
              {
                proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_scdma_code_hopping_seed,
                                     tvb, pos, length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, type35tlv_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            pos = pos + length;
            break;
          case type35ucd_SCDMA_US_RATIO_NUM:
            if (length == 2)
              {
                proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_scdma_us_ratio_num,
                                     tvb, pos, length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, type35tlv_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            pos = pos + length;
            break;
          case type35ucd_SCDMA_US_RATIO_DENOM:
            if (length == 2)
              {
                proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_scdma_us_ratio_denom,
                                     tvb, pos, length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, type35tlv_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            pos = pos + length;
            break;
          case type35ucd_SCDMA_TIMESTAMP_SNAPSHOT:
            if (length == 9)
              {
                proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_scdma_timestamp_snapshot,
                                     tvb, pos, length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, type35tlv_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            pos = pos + length;
            break;
          case type35ucd_MAINTAIN_POWER_SPECTRAL_DENSITY:
            if (length == 1)
              {
                proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_maintain_power_spectral_density,
                                     tvb, pos, length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, type35tlv_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            pos = pos + length;
            break;
          case type35ucd_RANGING_REQUIRED:
            if (length == 1)
              {
                proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_ranging_required,
                                     tvb, pos, length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, type35tlv_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            pos = pos + length;
            break;
          case type35ucd_MAX_SCHEDULED_CODES:
            if (length == 1)
              {
                proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_max_scheduled_codes,
                                     tvb, pos, length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, type35tlv_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            pos = pos + length;
            break;
          case type35ucd_RANGING_HOLD_OFF_PRIORITY_FIELD:
            if (length == 4)
              {
                proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_rnghoff_cm, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
                proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_rnghoff_erouter, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
                proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_rnghoff_emta, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
                proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_rnghoff_estb, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
                proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_rnghoff_rsvd, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
                proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_rnghoff_id_ext, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, type35tlv_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            pos = pos + length;
            break;
          case type35ucd_RANGING_CHANNEL_CLASS_ID:
            if (length == 4)
              {
                proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_chan_class_id_cm, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
                proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_chan_class_id_erouter, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
                proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_chan_class_id_emta, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
                proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_chan_class_id_estb, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
                proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_chan_class_id_rsvd, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
                proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_chan_class_id_id_ext, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, type35tlv_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            pos = pos + length;
            break;
          case type35ucd_SCDMA_SELECTION_ACTIVE_CODES_AND_CODE_HOPPING:
            if (length == 1)
              {
                proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_active_code_hopping,
                                     tvb, pos, length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, type35tlv_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            pos = pos + length;
            break;
          case type35ucd_SCDMA_SELECTION_STRING_FOR_ACTIVE_CODES:
            if (length == 16)
              {
                proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_scdma_selection_active_codes,
                                     tvb, pos, length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, type35tlv_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            pos = pos + length;
            break;
          case type35ucd_HIGHER_UCD_FOR_SAME_UCID:
            if (length == 1)
              {
                proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_higher_ucd_for_same_ucid,
                                     tvb, pos, length, ENC_NA);
                proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_higher_ucd_for_same_ucid_resv, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, type35tlv_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            pos = pos + length;
            break;
          case type35ucd_BURST_DESCR5:
            proto_tree_add_item (type35tlv_tree, hf_docsis_type35ucd_iuc, tvb,
                                 pos++, 1, ENC_BIG_ENDIAN);
            endtlvpos = pos + length - 1;
            while (pos < endtlvpos)
              {
                tlvtype = tvb_get_guint8 (tvb, pos);
                type35ucd_burst_tree = proto_tree_add_subtree (type35tlv_tree, tvb, pos, -1,
                                                               ett_docsis_type35_burst_tlv, &type35ucd_burst_item,
                                                               val_to_str(tlvtype, burst_tlv_vals,
                                                               "Unknown TLV (%u)"));
                proto_tree_add_uint (type35ucd_burst_tree, hf_docsis_type35ucd_burst_type, tvb, pos, 1, tlvtype);
                pos++;
                tlvlen = tvb_get_guint8 (tvb, pos);
                proto_tree_add_uint (type35ucd_burst_tree, hf_docsis_type35ucd_burst_length, tvb, pos, 1, tlvlen);
                pos++;
                proto_item_set_len(type35ucd_burst_item, tlvlen + 2);
                switch (tlvtype)
                  {
                    case type35ucd_MODULATION:
                      if (tlvlen == 1)
                        {
                          proto_tree_add_item (type35ucd_burst_tree,
                                               hf_docsis_burst_mod_type, tvb,
                                               pos, tlvlen, ENC_BIG_ENDIAN);
                        }
                      else
                        {
                          expert_add_info_format(pinfo, type35ucd_burst_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
                        }
                      break;
                    case type35ucd_DIFF_ENCODING:
                      if (tlvlen == 1)
                        {
                          proto_tree_add_item (type35ucd_burst_tree,
                                               hf_docsis_burst_diff_encoding,
                                               tvb, pos, tlvlen, ENC_BIG_ENDIAN);
                        }
                      else
                        {
                          expert_add_info_format(pinfo, type35ucd_burst_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
                        }
                      break;
                    case type35ucd_PREAMBLE_LEN:
                      if (tlvlen == 2)
                        {
                          proto_tree_add_item (type35ucd_burst_tree,
                                               hf_docsis_burst_preamble_len,
                                               tvb, pos, tlvlen, ENC_BIG_ENDIAN);
                        }
                      else
                        {
                          expert_add_info_format(pinfo, type35ucd_burst_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
                        }
                      break;
                    case type35ucd_PREAMBLE_VAL_OFF:
                      if (tlvlen == 2)
                        {
                          proto_tree_add_item (type35ucd_burst_tree,
                                               hf_docsis_burst_preamble_val_off,
                                               tvb, pos, tlvlen, ENC_BIG_ENDIAN);
                        }
                      else
                        {
                          expert_add_info_format(pinfo, type35ucd_burst_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
                        }
                      break;
                    case type35ucd_FEC:
                      if (tlvlen == 1)
                        {
                          proto_tree_add_item (type35ucd_burst_tree,
                                               hf_docsis_burst_fec, tvb, pos,
                                               tlvlen, ENC_BIG_ENDIAN);
                        }
                      else
                        {
                          expert_add_info_format(pinfo, type35ucd_burst_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
                        }
                      break;
                    case type35ucd_FEC_CODEWORD:
                      if (tlvlen == 1)
                        {
                          proto_tree_add_item (type35ucd_burst_tree,
                                               hf_docsis_burst_fec_codeword,
                                               tvb, pos, tlvlen, ENC_BIG_ENDIAN);
                        }
                      else
                        {
                          expert_add_info_format(pinfo, type35ucd_burst_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
                        }
                      break;
                    case type35ucd_SCRAMBLER_SEED:
                      if (tlvlen == 2)
                        {
                          proto_tree_add_item (type35ucd_burst_tree,
                                               hf_docsis_burst_scrambler_seed,
                                               tvb, pos, tlvlen, ENC_BIG_ENDIAN);
                        }
                      else
                        {
                          expert_add_info_format(pinfo, type35ucd_burst_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
                        }
                      break;
                    case type35ucd_MAX_BURST:
                      if (tlvlen == 1)
                        {
                          proto_tree_add_item (type35ucd_burst_tree,
                                               hf_docsis_burst_max_burst, tvb,
                                               pos, tlvlen, ENC_BIG_ENDIAN);
                        }
                      else
                        {
                          expert_add_info_format(pinfo, type35ucd_burst_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
                        }
                      break;
                    case type35ucd_GUARD_TIME:
                      if (tlvlen == 1)
                        {
                          proto_tree_add_item (type35ucd_burst_tree,
                                               hf_docsis_burst_guard_time,
                                               tvb, pos, tlvlen, ENC_BIG_ENDIAN);
                        }
                      else
                        {
                          expert_add_info_format(pinfo, type35ucd_burst_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
                        }
                      break;
                    case type35ucd_LAST_CW_LEN:
                      if (tlvlen == 1)
                        {
                          proto_tree_add_item (type35ucd_burst_tree,
                                               hf_docsis_burst_last_cw_len,
                                               tvb, pos, tlvlen, ENC_BIG_ENDIAN);
                        }
                      else
                        {
                          expert_add_info_format(pinfo, type35ucd_burst_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
                        }
                      break;
                    case type35ucd_SCRAMBLER_ONOFF:
                      if (tlvlen == 1)
                        {
                          proto_tree_add_item (type35ucd_burst_tree,
                                               hf_docsis_burst_scrambler_onoff,
                                               tvb, pos, tlvlen, ENC_BIG_ENDIAN);
                        }
                      else
                        {
                          expert_add_info_format(pinfo, type35ucd_burst_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
                        }
                      break;
                    case type35ucd_RS_INT_DEPTH:
                      if (tlvlen == 1)
                        {
                          proto_tree_add_item (type35ucd_burst_tree,
                                               hf_docsis_rs_int_depth,
                                               tvb, pos, tlvlen, ENC_BIG_ENDIAN);
                        }
                      else
                        {
                          expert_add_info_format(pinfo, type35ucd_burst_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
                        }
                      break;
                    case type35ucd_RS_INT_BLOCK:
                      if (tlvlen == 2)
                        {
                          proto_tree_add_item (type35ucd_burst_tree,
                                               hf_docsis_rs_int_block,
                                               tvb, pos, tlvlen, ENC_BIG_ENDIAN);
                        }
                      else
                        {
                          expert_add_info_format(pinfo, type35ucd_burst_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
                        }
                      break;
                    case type35ucd_PREAMBLE_TYPE:
                      if (tlvlen == 1)
                        {
                          proto_tree_add_item (type35ucd_burst_tree,
                                               hf_docsis_preamble_type,
                                               tvb, pos, tlvlen, ENC_BIG_ENDIAN);
                        }
                      else
                        {
                          expert_add_info_format(pinfo, type35ucd_burst_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
                        }
                      break;
                    case type35ucd_SCMDA_SCRAMBLER_ONOFF:
                      if (tlvlen == 1)
                        {
                          proto_tree_add_item (type35ucd_burst_tree,
                                               hf_docsis_scdma_scrambler_onoff,
                                               tvb, pos, tlvlen, ENC_BIG_ENDIAN);
                        }
                      else
                        {
                          expert_add_info_format(pinfo, type35ucd_burst_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
                        }
                      break;
                    case type35ucd_SCDMA_CODES_PER_SUBFRAME:
                      if (tlvlen == 1)
                        {
                          proto_tree_add_item (type35ucd_burst_tree,
                                               hf_docsis_scdma_codes_per_subframe,
                                               tvb, pos, tlvlen, ENC_BIG_ENDIAN);
                        }
                      else
                        {
                          expert_add_info_format(pinfo, type35ucd_burst_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
                        }
                      break;
                    case type35ucd_SCDMA_FRAMER_INT_STEP_SIZE:
                      if (tlvlen == 1)
                        {
                          proto_tree_add_item (type35ucd_burst_tree,
                                               hf_docsis_scdma_framer_int_step_size,
                                               tvb, pos, tlvlen, ENC_BIG_ENDIAN);
                        }
                      else
                        {
                          expert_add_info_format(pinfo, type35ucd_burst_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
                        }
                      break;
                    case type35ucd_TCM_ENABLED:
                      if (tlvlen == 1)
                        {
                          proto_tree_add_item (type35ucd_burst_tree,
                                               hf_docsis_tcm_enabled,
                                               tvb, pos, tlvlen, ENC_BIG_ENDIAN);
                        }
                      else
                        {
                          expert_add_info_format(pinfo, type35ucd_burst_item, &ei_docsis_type35ucd_tlvlen_bad, "Wrong TLV length: %u", length);
                        }
                      break;
                    default:
                      expert_add_info_format(pinfo, type35ucd_burst_item, &ei_docsis_type35ucd_tlvtype_bad, "Unknown TLV type: %u", tlvtype);
                  }         /* switch(tlvtype) */
                pos = pos + tlvlen;
              }             /* while (pos < endtlvpos) */
            break;
          default:
            expert_add_info_format(pinfo, type35tlv_item, &ei_docsis_type35ucd_tlvtype_bad, "Unknown TLV type: %u", type);
            pos = pos + length;
        }                   /* switch(type) */
    }                       /* while (pos < len) */
  return len;
}

/* Register the protocol with Wireshark */
void
proto_register_docsis_type35ucd (void)
{
  static hf_register_info hf[] = {
    {&hf_docsis_type35ucd_upstream_chid,
     {"Upstream Channel ID", "docsis_type35ucd.upchid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type35ucd_config_ch_cnt,
     {"Config Change Count", "docsis_type35ucd.confcngcnt",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Configuration Change Count", HFILL}
    },
    {&hf_docsis_type35ucd_mini_slot_size,
     {"Mini Slot Size (6.25us TimeTicks)", "docsis_type35ucd.mslotsize",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type35ucd_down_chid,
     {"Downstream Channel ID", "docsis_type35ucd.downchid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Management Message", HFILL}
    },
    {&hf_docsis_type35ucd_type,
     {"Type", "docsis_type35ucd.type",
      FT_UINT8, BASE_DEC, VALS(channel_tlv_vals), 0x0,
      "Channel TLV type", HFILL}
    },
    {&hf_docsis_type35ucd_length,
     {"Length", "docsis_type35ucd.length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Channel TLV length", HFILL}
    },
    {&hf_docsis_type35ucd_burst_type,
     {"Type", "docsis_type35ucd.burst.tlvtype",
      FT_UINT8, BASE_DEC, VALS(burst_tlv_vals), 0x0,
      "Burst TLV type", HFILL}
    },
    {&hf_docsis_type35ucd_burst_length,
     {"Length", "docsis_type35ucd.burst.tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Burst TLV length", HFILL}
    },
    {&hf_docsis_type35ucd_symbol_rate,
     {"Symbol Rate (ksym/sec)", "docsis_type35ucd.symrate",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Symbol Rate", HFILL}
    },
    {&hf_docsis_type35ucd_frequency,
     {"Frequency (Hz)", "docsis_type35ucd.freq",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Upstream Center Frequency", HFILL}
    },
    {&hf_docsis_type35ucd_preamble_pat,
     {"Preamble Pattern", "docsis_type35ucd.preamble",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Preamble Superstring", HFILL}
    },
    {&hf_docsis_type35ucd_iuc,
     {"Interval Usage Code", "docsis_type35ucd.iuc",
      FT_UINT8, BASE_DEC, VALS (iuc_vals3), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_mod_type,
     {"Modulation Type", "docsis_type35ucd.burst.modtype",
      FT_UINT8, BASE_DEC, VALS (mod_vals2), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_diff_encoding,
     {"Differential Encoding", "docsis_type35ucd.burst.diffenc",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_preamble_len,
     {"Preamble Length (Bits)", "docsis_type35ucd.burst.preamble_len",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_preamble_val_off,
     {"Preamble Offset (Bits)", "docsis_type35ucd.burst.preamble_off",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_fec,
     {"FEC (T)", "docsis_type35ucd.burst.fec",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "FEC (T) Codeword Parity Bits = 2^T", HFILL}
    },
    {&hf_docsis_burst_fec_codeword,
     {"FEC Codeword Info bytes (k)", "docsis_type35ucd.burst.fec_codeword",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_scrambler_seed,
     {"Scrambler Seed", "docsis_type35ucd.burst.scrambler_seed",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "Burst Descriptor", HFILL}
    },
    {&hf_docsis_burst_max_burst,
     {"Max Burst Size (Minislots)", "docsis_type35ucd.burst.maxburst",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_guard_time,
     {"Guard Time Size (Symbol Times)", "docsis_type35ucd.burst.guardtime",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Guard Time Size", HFILL}
    },
    {&hf_docsis_burst_last_cw_len,
     {"Last Codeword Length", "docsis_type35ucd.burst.last_cw_len",
      FT_UINT8, BASE_DEC, VALS (last_cw_len_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_scrambler_onoff,
     {"Scrambler On/Off", "docsis_type35ucd.burst.scrambleronoff",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type35ucd_ext_preamble,
     {"Extended Preamble Pattern", "docsis_type35ucd.extpreamble",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type35ucd_scdma_mode_enable,
     {"SCDMA Mode Enable", "docsis_type35ucd.scdmaenable",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type35ucd_scdma_spreading_interval,
     {"SCDMA Spreading Interval", "docsis_type35ucd.scdmaspreadinginterval",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type35ucd_scdma_codes_per_mini_slot,
     {"SCDMA Codes per mini slot", "docsis_type35ucd.scdmacodesperminislot",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type35ucd_scdma_active_codes,
     {"SCDMA Active Codes", "docsis_type35ucd.scdmaactivecodes",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type35ucd_scdma_code_hopping_seed,
     {"SCDMA Code Hopping Seed", "docsis_type35ucd.scdmacodehoppingseed",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type35ucd_scdma_us_ratio_num,
     {"SCDMA US Ratio Numerator", "docsis_type35ucd.scdmausrationum",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type35ucd_scdma_us_ratio_denom,
     {"SCDMA US Ratio Denominator", "docsis_type35ucd.scdmausratiodenom",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type35ucd_scdma_timestamp_snapshot,
     {"SCDMA Timestamp Snapshot", "docsis_type35ucd.scdmatimestamp",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type35ucd_maintain_power_spectral_density,
     {"Maintain power spectral density", "docsis_type35ucd.maintainpowerspectraldensity",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type35ucd_ranging_required,
     {"Ranging Required", "docsis_type35ucd.rangingrequired",
      FT_UINT8, BASE_DEC, VALS (ranging_required), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type35ucd_rnghoff_cm,
     {"Ranging Hold-Off (CM)","docsis_type35ucd.rnghoffcm",
      FT_BOOLEAN, 32, TFS(&type35ucd_tfs_allow_inhibit), 0x1,
      NULL, HFILL}
    },
    {&hf_docsis_type35ucd_rnghoff_erouter,
     {"Ranging Hold-Off (eRouter)",
      "docsis_type35ucd.rnghofferouter",
      FT_BOOLEAN, 32, TFS(&type35ucd_tfs_allow_inhibit), 0x2,
      NULL, HFILL}
    },
    {&hf_docsis_type35ucd_rnghoff_emta,
     {"Ranging Hold-Off (eMTA or EDVA)",
      "docsis_type35ucd.rnghoffemta",
      FT_BOOLEAN, 32, TFS(&type35ucd_tfs_allow_inhibit), 0x4,
      NULL, HFILL}
    },
    {&hf_docsis_type35ucd_rnghoff_estb,
     {"Ranging Hold-Off (DSG/eSTB)",
      "docsis_type35ucd.rnghoffestb",
      FT_BOOLEAN, 32, TFS(&type35ucd_tfs_allow_inhibit), 0x8,
      NULL, HFILL}
    },
    {&hf_docsis_type35ucd_rnghoff_rsvd,
     {"Reserved [0x000000]",
      "docsis_type35ucd.rnghoffrsvd",
      FT_UINT32, BASE_HEX, NULL, 0xFFF0,
      NULL, HFILL}
    },
    {&hf_docsis_type35ucd_rnghoff_id_ext,
     {"CM Ranging Class ID Extension",
      "docsis_type35ucd.rngidext",
      FT_UINT32, BASE_HEX, NULL, 0xFFFF0000,
      NULL, HFILL}
    },
    {&hf_docsis_type35ucd_chan_class_id_cm,
     {"Channel Class ID (CM)","docsis_type35ucd.classidcm",
      FT_BOOLEAN, 32, TFS(&type35ucd_tfs_inhibit_allow), 0x1,
      NULL, HFILL}
    },
    {&hf_docsis_type35ucd_chan_class_id_erouter,
     {"Channel Class ID (eRouter)",
      "docsis_type35ucd.classiderouter",
      FT_BOOLEAN, 32, TFS(&type35ucd_tfs_inhibit_allow), 0x2,
      NULL, HFILL}
    },
    {&hf_docsis_type35ucd_chan_class_id_emta,
     {"Channel Class ID (eMTA or EDVA)",
      "docsis_type35ucd.classidemta",
      FT_BOOLEAN, 32, TFS(&type35ucd_tfs_inhibit_allow), 0x4,
      NULL, HFILL}
    },
    {&hf_docsis_type35ucd_chan_class_id_estb,
     {"Channel Class ID (DSG/eSTB)",
      "docsis_type35ucd.classidestb",
      FT_BOOLEAN, 32, TFS(&type35ucd_tfs_inhibit_allow), 0x8,
      NULL, HFILL}
    },
    {&hf_docsis_type35ucd_chan_class_id_rsvd,
     {"Reserved [0x000000]",
      "docsis_type35ucd.classidrsvd",
      FT_UINT32, BASE_HEX, NULL, 0xFFF0,
      NULL, HFILL}
    },
    {&hf_docsis_type35ucd_chan_class_id_id_ext,
     {"CM Ranging Class ID Extension",
      "docsis_type35ucd.classidext",
      FT_UINT32, BASE_HEX, NULL, 0xFFFF0000,
      NULL, HFILL}
    },
    {&hf_docsis_type35ucd_active_code_hopping,
     {"S-CDMA Selection Mode for Active Codes and Code Hopping", "docsis_type35ucd.selectcodehop",
      FT_UINT8, BASE_DEC, VALS (tlv20_vals), 0x0,
      "SCDMA Selection Mode for Active Codes and Code Hopping", HFILL}
    },
    {&hf_docsis_type35ucd_scdma_selection_active_codes,
     {"S-CDMA Selection String for Active Codes", "docsis_type35ucd.selectcode",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "SCDMA Selection String for Active Codes", HFILL}
    },
    {&hf_docsis_type35ucd_higher_ucd_for_same_ucid,
     {"Higher UCD for the same UCID", "docsis_type35ucd.highucdpresent",
      FT_BOOLEAN, 8, TFS(&type35ucd_tfs_present_not_present), 0x1,
      "Higher UCD for the same UCID present bitmap", HFILL}
    },
    {&hf_docsis_type35ucd_higher_ucd_for_same_ucid_resv,
     {"Reserved", "docsis_type35ucd.highucdresv",
      FT_UINT8, BASE_HEX, NULL, 0xFE,
      NULL, HFILL}
    },
    {&hf_docsis_type35ucd_max_scheduled_codes,
     {"S-CDMA Max Scheduled Codes", "docsis_type35ucd.scdmamaxcodes",
      FT_UINT8, BASE_DEC, VALS (max_scheduled_codes_vals), 0x0,
      "S-CDMA Maximum Scheduled Codes", HFILL}
    },
    {&hf_docsis_rs_int_depth,
     {"R-S Interleaver Depth (Ir)", "docsis_type35ucd.burst.rsintdepth",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_rs_int_block,
     {"R-S Interleaver Block Size (Br)", "docsis_type35ucd.burst.rsintblock",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_preamble_type,
     {"Preamble Type", "docsis_type35ucd.burst.preambletype",
      FT_UINT8, BASE_DEC, VALS (preamble_type), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_scdma_scrambler_onoff,
     {"S-CDMA Spreader On/Off", "docsis_type35ucd.burst.scdmascrambleronoff",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_scdma_codes_per_subframe,
     {"S-CDMA Codes per Subframe", "docsis_type35ucd.burst.scdmacodespersubframe",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_scdma_framer_int_step_size,
     {"S-CDMA Framer Interleaving Step Size", "docsis_type35ucd.burst.scdmaframerintstepsize",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tcm_enabled,
     {"TCM Encoding", "docsis_type35ucd.burst.tcmenabled",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      NULL, HFILL}
    },
  };

  static ei_register_info ei[] = {
    {&ei_docsis_type35ucd_tlvlen_bad, { "docsis_type35ucd.tlvlenbad", PI_MALFORMED, PI_ERROR, "Bad TLV length", EXPFILL}},
    {&ei_docsis_type35ucd_tlvtype_bad, { "docsis_type35ucd.tlvtypebad", PI_PROTOCOL, PI_WARN, "Bad TLV type", EXPFILL}},
  };

  static gint *ett[] = {
    &ett_docsis_type35ucd,
    &ett_docsis_type35tlv,
    &ett_docsis_type35_burst_tlv,
  };

  expert_module_t* expert_docsis_type35ucd;

  proto_docsis_type35ucd =
    proto_register_protocol ("DOCSIS Upstream Channel Descriptor Type 35",
                             "DOCSIS type35ucd", "docsis_type35ucd");

  proto_register_field_array (proto_docsis_type35ucd, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
  expert_docsis_type35ucd = expert_register_protocol(proto_docsis_type35ucd);
  expert_register_field_array(expert_docsis_type35ucd, ei, array_length(ei));

  register_dissector ("docsis_type35ucd", dissect_type35ucd, proto_docsis_type35ucd);
}

void
proto_reg_handoff_docsis_type35ucd (void)
{
  dissector_handle_t docsis_type35ucd_handle;

  docsis_type35ucd_handle = find_dissector ("docsis_type35ucd");
  dissector_add_uint ("docsis_mgmt", 0x23, docsis_type35ucd_handle);
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
