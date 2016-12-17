/* packet-type51ucd.c
 *
 * Routines for Type 51 UCD - DOCSIS 3.1 only - Message dissection
 * Copyright 2016, Bruno Verstuyft <bruno.verstuyft@excentis.com>
 * Based on packet-type35ucd.c (Copyright 2015, Adrian Simionov <daniel.simionov@gmail.com>)
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

#define type51ucd_SYMBOL_RATE 1
#define type51ucd_FREQUENCY 2
#define type51ucd_PREAMBLE 3
#define type51ucd_EXT_PREAMBLE 6
#define type51ucd_SCDMA_MODE_ENABLE 7
#define type51ucd_SCDMA_SPREADING_INTERVAL 8
#define type51ucd_SCDMA_CODES_PER_MINI_SLOT 9
#define type51ucd_SCDMA_ACTIVE_CODES 10
#define type51ucd_SCDMA_CODE_HOPPING_SEED 11
#define type51ucd_SCDMA_US_RATIO_NUM 12
#define type51ucd_SCDMA_US_RATIO_DENOM 13
#define type51ucd_SCDMA_TIMESTAMP_SNAPSHOT 14
#define type51ucd_MAINTAIN_POWER_SPECTRAL_DENSITY 15
#define type51ucd_RANGING_REQUIRED 16
#define type51ucd_MAX_SCHEDULED_CODES 17
#define type51ucd_RANGING_HOLD_OFF_PRIORITY_FIELD 18
#define type51ucd_RANGING_CHANNEL_CLASS_ID 19
#define type51ucd_SCDMA_SELECTION_ACTIVE_CODES_AND_CODE_HOPPING 20
#define type51ucd_SCDMA_SELECTION_STRING_FOR_ACTIVE_CODES 21
#define type51ucd_HIGHER_UCD_FOR_SAME_UCID 22
#define type51ucd_BURST_DESCR23 23
#define type51ucd_UCD_CHANGE_IND_BITMASK 24
#define type51ucd_OFDMA_TIMESTAMP_SNAPSHOT 25
#define type51ucd_OFDMA_CYCLIC_PREFIX_SIZE 26
#define type51ucd_OFDMA_ROLLOFF_PERIOD_SIZE 27
#define type51ucd_SUBCARRIER_SPACING 28
#define type51ucd_CENTER_FREQ_SUBC_0 29
#define type51ucd_SUBC_EXCL_BAND 30
#define type51ucd_UNUSED_SUBC_SPEC 31
#define type51ucd_SYMB_IN_OFDMA_FRAME 32
#define type51ucd_RAND_SEED 33


#define type51ucd_MODULATION 1
#define type51ucd_DIFF_ENCODING 2
#define type51ucd_PREAMBLE_LEN 3
#define type51ucd_PREAMBLE_VAL_OFF 4
#define type51ucd_FEC 5
#define type51ucd_FEC_CODEWORD 6
#define type51ucd_SCRAMBLER_SEED 7
#define type51ucd_MAX_BURST 8
#define type51ucd_GUARD_TIME 9
#define type51ucd_LAST_CW_LEN 10
#define type51ucd_SCRAMBLER_ONOFF 11
#define type51ucd_RS_INT_DEPTH 12
#define type51ucd_RS_INT_BLOCK 13
#define type51ucd_PREAMBLE_TYPE 14
#define type51ucd_SCMDA_SCRAMBLER_ONOFF 15
#define type51ucd_SCDMA_CODES_PER_SUBFRAME 16
#define type51ucd_SCDMA_FRAMER_INT_STEP_SIZE 17
#define type51ucd_TCM_ENABLED 18
#define type51ucd_SUBC_INIT_RANG 19
#define type51ucd_SUBC_FINE_RANG 20
#define type51ucd_OFDMA_PROFILE 21
#define type51ucd_OFDMA_IR_POWER_CONTROL 22

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

void proto_register_docsis_type51ucd(void);
void proto_reg_handoff_docsis_type51ucd(void);

/* Initialize the protocol and registered fields */
static int proto_docsis_type51ucd = -1;

static int hf_docsis_type51ucd_upstream_chid = -1;
static int hf_docsis_type51ucd_config_ch_cnt = -1;
static int hf_docsis_type51ucd_mini_slot_size = -1;
static int hf_docsis_type51ucd_down_chid = -1;
static int hf_docsis_type51ucd_type = -1;
static int hf_docsis_type51ucd_length = -1;
static int hf_docsis_type51ucd_burst_type = -1;
static int hf_docsis_type51ucd_burst_length = -1;
static int hf_docsis_type51ucd_symbol_rate = -1;
static int hf_docsis_type51ucd_frequency = -1;
static int hf_docsis_type51ucd_preamble_pat = -1;
static int hf_docsis_type51ucd_iuc = -1;
static int hf_docsis_type51ucd_ext_preamble = -1;
static int hf_docsis_type51ucd_scdma_mode_enable = -1;
static int hf_docsis_type51ucd_scdma_spreading_interval = -1;
static int hf_docsis_type51ucd_scdma_codes_per_mini_slot = -1;
static int hf_docsis_type51ucd_scdma_active_codes = -1;
static int hf_docsis_type51ucd_scdma_code_hopping_seed = -1;
static int hf_docsis_type51ucd_scdma_us_ratio_num = -1;
static int hf_docsis_type51ucd_scdma_us_ratio_denom = -1;
static int hf_docsis_type51ucd_scdma_timestamp_snapshot = -1;
static int hf_docsis_type51ucd_maintain_power_spectral_density = -1;
static int hf_docsis_type51ucd_ranging_required = -1;
static int hf_docsis_type51ucd_rnghoff_cm = -1;
static int hf_docsis_type51ucd_rnghoff_erouter = -1;
static int hf_docsis_type51ucd_rnghoff_emta = -1;
static int hf_docsis_type51ucd_rnghoff_estb = -1;
static int hf_docsis_type51ucd_rnghoff_rsvd = -1;
static int hf_docsis_type51ucd_rnghoff_id_ext = -1;
static int hf_docsis_type51ucd_chan_class_id_cm = -1;
static int hf_docsis_type51ucd_chan_class_id_erouter = -1;
static int hf_docsis_type51ucd_chan_class_id_emta = -1;
static int hf_docsis_type51ucd_chan_class_id_estb = -1;
static int hf_docsis_type51ucd_chan_class_id_rsvd = -1;
static int hf_docsis_type51ucd_chan_class_id_id_ext = -1;
static int hf_docsis_type51ucd_max_scheduled_codes = -1;
static int hf_docsis_type51ucd_active_code_hopping = -1;
static int hf_docsis_type51ucd_higher_ucd_for_same_ucid = -1;
static int hf_docsis_type51ucd_higher_ucd_for_same_ucid_resv = -1;
static int hf_docsis_type51ucd_scdma_selection_active_codes = -1;
static int hf_docsis_type51ucd_ucd_change_ind_bitmask_subc_excl_band = -1;
static int hf_docsis_type51ucd_ucd_change_ind_bitmask_unused_subc = -1;
static int hf_docsis_type51ucd_ucd_change_ind_bitmask_other_subc = -1;
static int hf_docsis_type51ucd_ucd_change_ind_bitmask_burst_attr_iuc5 = -1;
static int hf_docsis_type51ucd_ucd_change_ind_bitmask_burst_attr_iuc6 = -1;
static int hf_docsis_type51ucd_ucd_change_ind_bitmask_burst_attr_iuc9 = -1;
static int hf_docsis_type51ucd_ucd_change_ind_bitmask_burst_attr_iuc10 = -1;
static int hf_docsis_type51ucd_ucd_change_ind_bitmask_burst_attr_iuc11 = -1;
static int hf_docsis_type51ucd_ucd_change_ind_bitmask_burst_attr_iuc12 = -1;
static int hf_docsis_type51ucd_ucd_change_ind_bitmask_burst_attr_iuc13 = -1;
static int hf_docsis_type51ucd_ucd_change_ind_bitmask_burst_attr_iuc3_or_4 = -1;
static int hf_docsis_type51ucd_ucd_change_ind_bitmask_reserved = -1;
static int hf_docsis_type51ucd_ofdma_timestamp_snapshot = -1;
static int hf_docsis_type51ucd_ofdma_cyclic_prefix_size = -1;
static int hf_docsis_type51ucd_ofdma_rolloff_period_size = -1;
static int hf_docsis_type51ucd_subc_spacing = -1;
static int hf_docsis_type51ucd_cent_freq_subc0 = -1;
static int hf_docsis_type51ucd_subcarrier_range = -1;
static int hf_docsis_type51ucd_symb_ofdma_frame = -1;
static int hf_docsis_type51ucd_rand_seed = -1;
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
static int hf_docsis_subc_init_rang = -1;
static int hf_docsis_subc_fine_rang = -1;
static int hf_docsis_type51ucd_ofdma_prof_mod_order = -1;
static int hf_docsis_type51ucd_ofdma_prof_pilot_pattern = -1;
static int hf_docsis_type51ucd_ofdma_prof_num_add_minislots = -1;
static int hf_docsis_ofdma_ir_pow_ctrl_start_pow = -1;
static int hf_docsis_ofdma_ir_pow_ctrl_step_size = -1;

static expert_field ei_docsis_type51ucd_tlvlen_bad = EI_INIT;
static expert_field ei_docsis_type51ucd_tlvtype_bad = EI_INIT;

/* Initialize the subtree pointers */
static gint ett_docsis_type51ucd = -1;
static gint ett_docsis_type51tlv = -1;
static gint ett_docsis_type51_burst_tlv = -1;

static dissector_handle_t docsis_type51ucd_handle;

static const value_string channel_tlv_vals[] _U_ = {
  {type51ucd_SYMBOL_RATE,                     "Symbol Rate"},
  {type51ucd_FREQUENCY,                       "Frequency"},
  {type51ucd_PREAMBLE,                        "Preamble Pattern"},
  {type51ucd_EXT_PREAMBLE,                    "Extended Preamble Pattern"},
  {type51ucd_SCDMA_MODE_ENABLE,               "SCDMA Mode Enabled"},
  {type51ucd_SCDMA_SPREADING_INTERVAL,        "SCDMA Spreading Intervals per Frame"},
  {type51ucd_SCDMA_CODES_PER_MINI_SLOT,       "SCDMA Codes per Mini-slot"},
  {type51ucd_SCDMA_ACTIVE_CODES,              "SCDMA Number of Active Codes"},
  {type51ucd_SCDMA_CODE_HOPPING_SEED,         "SCDMA Code Hopping Seed"},
  {type51ucd_SCDMA_US_RATIO_NUM,              "SCDMA US ratio numera7tor M"},
  {type51ucd_SCDMA_US_RATIO_DENOM,            "SCDMA US ratio denominator N"},
  {type51ucd_SCDMA_TIMESTAMP_SNAPSHOT,        "SCDMA Timestamp Snapshot"},
  {type51ucd_MAINTAIN_POWER_SPECTRAL_DENSITY, "Maintain Power Spectral Density"},
  {type51ucd_RANGING_REQUIRED,                "Ranging Required"},
  {type51ucd_MAX_SCHEDULED_CODES,             "S-CDMA Maximum Scheduled Codes"},
  {type51ucd_RANGING_HOLD_OFF_PRIORITY_FIELD, "Ranging Hold-Off Priority Field"},
  {type51ucd_RANGING_CHANNEL_CLASS_ID,        "Ranging Channel Class ID"},
  {type51ucd_SCDMA_SELECTION_ACTIVE_CODES_AND_CODE_HOPPING, "S-CDMA Selection Mode for Active Codes and Code Hopping"},
  {type51ucd_SCDMA_SELECTION_STRING_FOR_ACTIVE_CODES, "S-CDMA Selection String for Active Codes"},
  {type51ucd_HIGHER_UCD_FOR_SAME_UCID,        "Higher UCD for the same UCID present bitmap"},
  {type51ucd_BURST_DESCR23,                   "Burst Descriptor Type 23"},
  {type51ucd_UCD_CHANGE_IND_BITMASK,          "UCD Change Indicator Bitmask"},
  {type51ucd_OFDMA_TIMESTAMP_SNAPSHOT,        "OFDMA Timestamp Snapshot"},
  {type51ucd_OFDMA_CYCLIC_PREFIX_SIZE,        "OFDMA Cyclic Prefix Size"},
  {type51ucd_OFDMA_ROLLOFF_PERIOD_SIZE,       "OFDMA Rolloff Period Size"},
  {type51ucd_SUBCARRIER_SPACING,              "Subcarrier Spacing"},
  {type51ucd_CENTER_FREQ_SUBC_0,              "Center Frequency of Subcarrier 0"},
  {type51ucd_SUBC_EXCL_BAND,                  "Subcarrier Exclusion Band"},
  {type51ucd_UNUSED_SUBC_SPEC,                "Unused Subcarrier Specification"},
  {type51ucd_SYMB_IN_OFDMA_FRAME,             "Symbols in OFDMA frame"},
  {type51ucd_RAND_SEED,                       "Randomization Seed"},
  {0, NULL}
};

static const value_string burst_tlv_vals[] = {
  {type51ucd_MODULATION,                      "Modulation Type"},
  {type51ucd_DIFF_ENCODING,                   "Differential Encoding"},
  {type51ucd_PREAMBLE_LEN,                    "Preamble Length"},
  {type51ucd_PREAMBLE_VAL_OFF,                "Preamble Value Offset"},
  {type51ucd_FEC,                             "FEC Error Correction (T)"},
  {type51ucd_FEC_CODEWORD,                    "FEC Codeword Information Bytes (k)"},
  {type51ucd_SCRAMBLER_SEED,                  "Scrambler Seed"},
  {type51ucd_MAX_BURST,                       "Maximum Burst Size"},
  {type51ucd_GUARD_TIME,                      "Guard Time Size"},
  {type51ucd_LAST_CW_LEN,                     "Last Codeword Length"},
  {type51ucd_SCRAMBLER_ONOFF,                 "Scrambler on/off"},
  {type51ucd_RS_INT_DEPTH,                    "R-S Interleaver Depth (Ir)"},
  {type51ucd_RS_INT_BLOCK,                    "R-S Interleaver Block Size (Br)"},
  {type51ucd_PREAMBLE_TYPE,                   "Preamble Type"},
  {type51ucd_SCMDA_SCRAMBLER_ONOFF,           "S-CDMA Spreader on/off"},
  {type51ucd_SCDMA_CODES_PER_SUBFRAME,        "S-CDMA Codes per Subframe"},
  {type51ucd_SCDMA_FRAMER_INT_STEP_SIZE,      "S-CDMA Framer Interleaving Step Size"},
  {type51ucd_TCM_ENABLED,                     "TCM Encoding"},
  {type51ucd_SUBC_INIT_RANG,                  "Subcarriers (Nir) Initial Ranging"},
  {type51ucd_SUBC_FINE_RANG,                  "Subcarriers (Nfr) Initial Ranging"},
  {type51ucd_OFDMA_PROFILE,                   "OFDMA Profile"},
  {0, NULL}
};

static const value_string on_off_vals[] = {
  {1, "On"},
  {2, "Off"},
  {0, NULL}
};

const true_false_string type51ucd_tfs_allow_inhibit = { "Inhibit Initial Ranging",
                                                        "Ranging Allowed" };

const true_false_string type51ucd_tfs_inhibit_allow = { "Ranging Allowed",
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

const true_false_string type51ucd_tfs_present_not_present = { "Higher UCD is present for this UCID",
                                                              "Higher UCD is not present for this UCID" };

static const value_string ofdma_prof_mod_order[] = {
  {1, "BPSK"},
  {2, "QPSK"},
  {3, "8-QAM"},
  {4, "16-QAM"},
  {5, "32-QAM"},
  {6, "64-QAM"},
  {7, "128-QAM"},
  {8, "256-QAM"},
  {9, "512-QAM"},
  {10, "1024-QAM"},
  {11, "2048-QAM"},
  {12, "4096-QAM"},
  {0, NULL}
};


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
  {3, "Probing required."},
  {0, NULL}
};


static void
ofdma_ir_pow_ctrl_start_pow(
    char *buf,
    guint32 value)
{
    g_snprintf(buf, ITEM_LABEL_LENGTH,
               "%f dBmV/1.6MHz",
               value/4.0);
}

static void
ofdma_ir_pow_ctrl_step_size(
    char *buf,
    guint32 value)
{
    g_snprintf(buf, ITEM_LABEL_LENGTH,
               "%f dB",
               value/4.0);
}

static const value_string ucd_change_ind_vals[] = {
  {0, "No changes"},
  {1, "Changes"},
  {0, NULL}
};

static const value_string ofdma_cyclic_prefix_size_vals[] = {
  {1, "96 samples"},
  {2, "128 samples"},
  {3, "160 samples"},
  {4, "192 samples"},
  {5, "224 samples"},
  {6, "256 samples"},
  {7, "288 samples"},
  {8, "320 samples"},
  {9, "384 samples"},
  {10, "512 samples"},
  {11, "640 samples"},
  {0, NULL}
};

static const value_string ofdma_rolloff_period_size_vals[] = {
  {1, "0 samples"},
  {2, "32 samples"},
  {3, "64 samples"},
  {4, "96 samples"},
  {5, "128 samples"},
  {6, "160 samples"},
  {7, "192 samples"},
  {8, "224 samples"},
  {0, NULL}
};

static const value_string subc_spacing_vals[] = {
  {1, "25 kHz (corresponds to 4096 subcarriers and 16 subcarriers per minislot)"},
  {2, "50 kHz (corresponds to 2048 subcarriers and 8 subcarriers per minislot)"},
  {0, NULL}
};

static void
subcarrier_range (
    char *buf,
    guint32 value)
{
    g_snprintf(buf, ITEM_LABEL_LENGTH,
         "%u - %u",
         value >> 16, value &0xFFFF);
}

/* Dissection */
static void
dissect_type51ucd_burstdescriptor(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, guint16 start, guint16 length)
{
  guint16 endtlvpos, pos;
  guint16 i;
  proto_tree *type51ucd_burst_tree;
  proto_item *type51ucd_burst_item;
  guint8 tlvlen, tlvtype;

  pos = start;
  proto_tree_add_item (tree, hf_docsis_type51ucd_iuc, tvb, pos++, 1, ENC_BIG_ENDIAN);

  endtlvpos = pos + length - 1;
  while (pos < endtlvpos)
  {
    tlvtype = tvb_get_guint8 (tvb, pos);
    type51ucd_burst_tree = proto_tree_add_subtree (tree, tvb, pos, -1,
                                                   ett_docsis_type51_burst_tlv, &type51ucd_burst_item,
                                                   val_to_str(tlvtype, burst_tlv_vals,
                                                   "Unknown TLV (%u)"));
    proto_tree_add_uint (type51ucd_burst_tree, hf_docsis_type51ucd_burst_type, tvb, pos++, 1, tlvtype);
    tlvlen = tvb_get_guint8 (tvb, pos);
    proto_tree_add_uint (type51ucd_burst_tree, hf_docsis_type51ucd_burst_length, tvb, pos++, 1, tlvlen);
    proto_item_set_len(type51ucd_burst_item, tlvlen + 2);
    switch (tlvtype)
    {
      case type51ucd_MODULATION:
        if (tlvlen == 1)
        {
          proto_tree_add_item (type51ucd_burst_tree,
                                 hf_docsis_burst_mod_type, tvb,
                                 pos, tlvlen, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info_format(pinfo, type51ucd_burst_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_DIFF_ENCODING:
        if (tlvlen == 1)
        {
          proto_tree_add_item (type51ucd_burst_tree,
                                 hf_docsis_burst_diff_encoding,
                                 tvb, pos, tlvlen, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info_format(pinfo, type51ucd_burst_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_PREAMBLE_LEN:
        if (tlvlen == 2)
        {
          proto_tree_add_item (type51ucd_burst_tree,
                                hf_docsis_burst_preamble_len,
                               tvb, pos, tlvlen, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info_format(pinfo, type51ucd_burst_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_PREAMBLE_VAL_OFF:
        if (tlvlen == 2)
        {
          proto_tree_add_item (type51ucd_burst_tree,
                                hf_docsis_burst_preamble_val_off,
                                tvb, pos, tlvlen, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info_format(pinfo, type51ucd_burst_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_FEC:
        if (tlvlen == 1)
        {
          proto_tree_add_item (type51ucd_burst_tree,
                                hf_docsis_burst_fec, tvb, pos,
                                tlvlen, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info_format(pinfo, type51ucd_burst_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_FEC_CODEWORD:
        if (tlvlen == 1)
        {
          proto_tree_add_item (type51ucd_burst_tree,
                                 hf_docsis_burst_fec_codeword,
                                 tvb, pos, tlvlen, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info_format(pinfo, type51ucd_burst_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_SCRAMBLER_SEED:
        if (tlvlen == 2)
        {
          proto_tree_add_item (type51ucd_burst_tree,
                                 hf_docsis_burst_scrambler_seed,
                                 tvb, pos, tlvlen, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info_format(pinfo, type51ucd_burst_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_MAX_BURST:
        if (tlvlen == 1)
        {
          proto_tree_add_item (type51ucd_burst_tree,
                                 hf_docsis_burst_max_burst, tvb,
                                 pos, tlvlen, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info_format(pinfo, type51ucd_burst_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_GUARD_TIME:
        if (tlvlen == 1)
        {
          proto_tree_add_item (type51ucd_burst_tree,
                                 hf_docsis_burst_guard_time,
                                 tvb, pos, tlvlen, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info_format(pinfo, type51ucd_burst_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_LAST_CW_LEN:
        if (tlvlen == 1)
        {
          proto_tree_add_item (type51ucd_burst_tree,
                                 hf_docsis_burst_last_cw_len,
                                 tvb, pos, tlvlen, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info_format(pinfo, type51ucd_burst_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_SCRAMBLER_ONOFF:
        if (tlvlen == 1)
        {
          proto_tree_add_item (type51ucd_burst_tree,
                                 hf_docsis_burst_scrambler_onoff,
                                 tvb, pos, tlvlen, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info_format(pinfo, type51ucd_burst_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_RS_INT_DEPTH:
        if (tlvlen == 1)
        {
          proto_tree_add_item (type51ucd_burst_tree,
                                 hf_docsis_rs_int_depth,
                                 tvb, pos, tlvlen, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info_format(pinfo, type51ucd_burst_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_RS_INT_BLOCK:
        if (tlvlen == 2)
        {
          proto_tree_add_item (type51ucd_burst_tree,
                                hf_docsis_rs_int_block,
                                tvb, pos, tlvlen, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info_format(pinfo, type51ucd_burst_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_PREAMBLE_TYPE:
        if (tlvlen == 1)
        {
          proto_tree_add_item (type51ucd_burst_tree,
                                 hf_docsis_preamble_type,
                                 tvb, pos, tlvlen, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info_format(pinfo, type51ucd_burst_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_SCMDA_SCRAMBLER_ONOFF:
        if (tlvlen == 1)
        {
          proto_tree_add_item (type51ucd_burst_tree,
                                 hf_docsis_scdma_scrambler_onoff,
                                 tvb, pos, tlvlen, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info_format(pinfo, type51ucd_burst_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_SCDMA_CODES_PER_SUBFRAME:
        if (tlvlen == 1)
        {
          proto_tree_add_item (type51ucd_burst_tree,
                                 hf_docsis_scdma_codes_per_subframe,
                                 tvb, pos, tlvlen, ENC_BIG_ENDIAN);

        }
        else
        {
          expert_add_info_format(pinfo, type51ucd_burst_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_SCDMA_FRAMER_INT_STEP_SIZE:
        if (tlvlen == 1)
        {
          proto_tree_add_item (type51ucd_burst_tree,
                                 hf_docsis_scdma_framer_int_step_size,
                                 tvb, pos, tlvlen, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info_format(pinfo, type51ucd_burst_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_TCM_ENABLED:
        if (tlvlen == 1)
        {
          proto_tree_add_item (type51ucd_burst_tree,
                                 hf_docsis_tcm_enabled,
                                 tvb, pos, tlvlen, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info_format(pinfo, type51ucd_burst_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_SUBC_INIT_RANG:
        if (tlvlen == 2)
        {
          proto_tree_add_item (type51ucd_burst_tree,
                                 hf_docsis_subc_init_rang,
                                 tvb, pos, tlvlen, ENC_BIG_ENDIAN);
        }
        else
        {
            expert_add_info_format(pinfo, type51ucd_burst_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_SUBC_FINE_RANG:
        if (tlvlen == 2)
        {
          proto_tree_add_item (type51ucd_burst_tree,
                                hf_docsis_subc_fine_rang,
                                tvb, pos, tlvlen, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info_format(pinfo, type51ucd_burst_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_OFDMA_PROFILE:
        if ((tlvlen % 2) == 0)
        {
          for(i =0; i < tlvlen; i+=2) {
            proto_tree_add_item (type51ucd_burst_tree, hf_docsis_type51ucd_ofdma_prof_mod_order, tvb, pos + i, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (type51ucd_burst_tree, hf_docsis_type51ucd_ofdma_prof_pilot_pattern, tvb, pos + i, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (type51ucd_burst_tree, hf_docsis_type51ucd_ofdma_prof_num_add_minislots, tvb, pos + i + 1, 1, ENC_BIG_ENDIAN);
          }
        }
        else
        {
          expert_add_info_format(pinfo, type51ucd_burst_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u (even length expected)", length);
        }
        break;
      case type51ucd_OFDMA_IR_POWER_CONTROL:
        if (tlvlen == 2)
        {
          proto_tree_add_item (type51ucd_burst_tree, hf_docsis_ofdma_ir_pow_ctrl_start_pow, tvb, pos, tlvlen, ENC_BIG_ENDIAN);
          proto_tree_add_item (type51ucd_burst_tree, hf_docsis_ofdma_ir_pow_ctrl_step_size, tvb, pos + 1, tlvlen, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info_format(pinfo, type51ucd_burst_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u (even length expected)", length);
        }
        break;
      default:
        expert_add_info_format(pinfo, type51ucd_burst_item, &ei_docsis_type51ucd_tlvtype_bad, "Unknown TLV type: %u", tlvtype);

    }
    pos = pos + tlvlen;
  } /*while*/
}


static int
dissect_type51ucd (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  guint16 pos;
  guint8 type, length;
  guint16 i;

  proto_tree *type51ucd_tree;
  proto_item *type51ucd_item;
  proto_tree *type51tlv_tree;
  proto_item *type51tlv_item;
  guint16 len;
  guint8 upchid, symrate;

  len = tvb_reported_length(tvb);
  upchid = tvb_get_guint8 (tvb, 0);

  /* if the upstream Channel ID is 0 then this is for Telephony Return) */
  if (upchid > 0)
    col_add_fstr (pinfo->cinfo, COL_INFO,
                  "Type 51 UCD Message: Channel ID = %u (U%u)", upchid,
                  upchid - 1);
  else
    col_add_fstr (pinfo->cinfo, COL_INFO,
                  "Type 51 UCD Message: Channel ID = %u (Telephony Return)",
                  upchid);

  type51ucd_item =
    proto_tree_add_protocol_format (tree, proto_docsis_type51ucd, tvb, 0,
                                    tvb_captured_length(tvb),
                                    "UCD Message (Type 51)");
  type51ucd_tree = proto_item_add_subtree (type51ucd_item, ett_docsis_type51ucd);
  proto_tree_add_item (type51ucd_tree, hf_docsis_type51ucd_upstream_chid, tvb, 0, 1,
                       ENC_BIG_ENDIAN);
  proto_tree_add_item (type51ucd_tree, hf_docsis_type51ucd_config_ch_cnt, tvb, 1, 1,
                       ENC_BIG_ENDIAN);
  proto_tree_add_item (type51ucd_tree, hf_docsis_type51ucd_mini_slot_size, tvb, 2, 1,
                       ENC_BIG_ENDIAN);
  proto_tree_add_item (type51ucd_tree, hf_docsis_type51ucd_down_chid, tvb, 3, 1,
                       ENC_BIG_ENDIAN);

  pos = 4;
  while (pos < len)
  {
    type = tvb_get_guint8 (tvb, pos);
    type51tlv_tree = proto_tree_add_subtree(type51ucd_tree, tvb, pos, -1,
                                        ett_docsis_type51tlv, &type51tlv_item,
                                        val_to_str(type, channel_tlv_vals,
                                                   "Unknown TLV (%u)"));
    proto_tree_add_uint (type51tlv_tree, hf_docsis_type51ucd_type,
                           tvb, pos, 1, type);
    pos++;
    length = tvb_get_guint8 (tvb, pos);
    proto_tree_add_uint (type51tlv_tree, hf_docsis_type51ucd_length,
                           tvb, pos, 1, length);
    pos++;
    proto_item_set_len(type51tlv_item, length + 2);
    switch (type)
    {
      case type51ucd_SYMBOL_RATE:
        if (length == 1)
        {
          symrate = tvb_get_guint8 (tvb, pos);
          proto_tree_add_uint (type51tlv_tree, hf_docsis_type51ucd_symbol_rate,
                                     tvb, pos, length, symrate * 160);
        }
        else
        {
          expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_FREQUENCY:
        if (length == 4)
        {
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_frequency, tvb,
                                   pos, length, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_PREAMBLE:
        proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_preamble_pat, tvb,
                             pos, length, ENC_NA);
        break;
      case type51ucd_EXT_PREAMBLE:
        proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_ext_preamble, tvb,
                             pos, length, ENC_NA);
        break;
      case type51ucd_SCDMA_MODE_ENABLE:
        if (length == 1)
        {
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_scdma_mode_enable,
                                 tvb, pos, length, ENC_NA);
        }
        else
        {
          expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_SCDMA_SPREADING_INTERVAL:
        if (length == 1)
        {
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_scdma_spreading_interval,
                                 tvb, pos, length, ENC_NA);
        }
        else
        {
            expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_SCDMA_CODES_PER_MINI_SLOT:
        if (length == 1)
        {
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_scdma_codes_per_mini_slot,
                                 tvb, pos, length, ENC_NA);
        }
        else
        {
          expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_SCDMA_ACTIVE_CODES:
        if (length == 1)
        {
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_scdma_active_codes,
                                 tvb, pos, length, ENC_NA);
        }
        else
        {
          expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_SCDMA_CODE_HOPPING_SEED:
        if (length == 2)
        {
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_scdma_code_hopping_seed,
                               tvb, pos, length, ENC_NA);
        }
        else
        {
          expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_SCDMA_US_RATIO_NUM:
        if (length == 2)
        {
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_scdma_us_ratio_num,
                                 tvb, pos, length, ENC_NA);
        }
        else
        {
          expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_SCDMA_US_RATIO_DENOM:
        if (length == 2)
        {
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_scdma_us_ratio_denom,
                               tvb, pos, length, ENC_NA);
        }
        else
        {
          expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_SCDMA_TIMESTAMP_SNAPSHOT:
        if (length == 9)
        {
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_scdma_timestamp_snapshot,
                               tvb, pos, length, ENC_NA);
        }
        else
        {
          expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_MAINTAIN_POWER_SPECTRAL_DENSITY:
        if (length == 1)
        {
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_maintain_power_spectral_density,
                               tvb, pos, length, ENC_NA);
        }
        else
        {
          expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_RANGING_REQUIRED:
        if (length == 1)
        {
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_ranging_required,
                                 tvb, pos, length, ENC_NA);
        }
        else
        {
          expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_MAX_SCHEDULED_CODES:
        if (length == 1)
        {
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_max_scheduled_codes,
                               tvb, pos, length, ENC_NA);
        }
        else
        {
          expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_RANGING_HOLD_OFF_PRIORITY_FIELD:
        if (length == 4)
        {
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_rnghoff_cm, tvb,
                                 pos, length, ENC_BIG_ENDIAN);
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_rnghoff_erouter, tvb,
                                 pos, length, ENC_BIG_ENDIAN);
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_rnghoff_emta, tvb,
                                 pos, length, ENC_BIG_ENDIAN);
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_rnghoff_estb, tvb,
                                 pos, length, ENC_BIG_ENDIAN);
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_rnghoff_rsvd, tvb,
                                 pos, length, ENC_BIG_ENDIAN);
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_rnghoff_id_ext, tvb,
                               pos, length, ENC_BIG_ENDIAN);
        }
        else
        {
            expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_RANGING_CHANNEL_CLASS_ID:
        if (length == 4)
        {
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_chan_class_id_cm, tvb,
                                 pos, length, ENC_BIG_ENDIAN);
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_chan_class_id_erouter, tvb,
                                 pos, length, ENC_BIG_ENDIAN);
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_chan_class_id_emta, tvb,
                                 pos, length, ENC_BIG_ENDIAN);
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_chan_class_id_estb, tvb,
                                 pos, length, ENC_BIG_ENDIAN);
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_chan_class_id_rsvd, tvb,
                                 pos, length, ENC_BIG_ENDIAN);
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_chan_class_id_id_ext, tvb,
                                 pos, length, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_SCDMA_SELECTION_ACTIVE_CODES_AND_CODE_HOPPING:
        if (length == 1)
        {
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_active_code_hopping,
                                 tvb, pos, length, ENC_NA);
        }
        else
        {
          expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_SCDMA_SELECTION_STRING_FOR_ACTIVE_CODES:
        if (length == 16)
        {
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_scdma_selection_active_codes,
                                 tvb, pos, length, ENC_NA);
        }
        else
        {
          expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_HIGHER_UCD_FOR_SAME_UCID:
        if (length == 1)
        {
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_higher_ucd_for_same_ucid,
                                tvb, pos, length, ENC_NA);
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_higher_ucd_for_same_ucid_resv, tvb,
                                pos, length, ENC_BIG_ENDIAN);
        }
        else
        {
          expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_UCD_CHANGE_IND_BITMASK:
        if (length == 2)
        {
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_ucd_change_ind_bitmask_subc_excl_band,
                                    tvb, pos + 1, 1, ENC_NA);
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_ucd_change_ind_bitmask_unused_subc,
                                    tvb, pos + 1, 1, ENC_NA);
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_ucd_change_ind_bitmask_other_subc,
                                    tvb, pos + 1, 1, ENC_NA);
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_ucd_change_ind_bitmask_burst_attr_iuc5,
                                    tvb, pos + 1, 1, ENC_NA);
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_ucd_change_ind_bitmask_burst_attr_iuc6,
                                    tvb, pos + 1, 1, ENC_NA);
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_ucd_change_ind_bitmask_burst_attr_iuc9,
                                    tvb, pos + 1, 1, ENC_NA);
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_ucd_change_ind_bitmask_burst_attr_iuc10,
                                    tvb, pos + 1, 1, ENC_NA);
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_ucd_change_ind_bitmask_burst_attr_iuc11,
                                    tvb, pos + 1, 1, ENC_NA);
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_ucd_change_ind_bitmask_burst_attr_iuc12,
                                    tvb, pos, 1, ENC_NA);
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_ucd_change_ind_bitmask_burst_attr_iuc13,
                                    tvb, pos, 1, ENC_NA);
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_ucd_change_ind_bitmask_burst_attr_iuc3_or_4,
                                    tvb, pos, 1, ENC_NA);
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_ucd_change_ind_bitmask_reserved,
                                    tvb, pos, 1, ENC_NA);
        }
        else
        {
          expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_OFDMA_TIMESTAMP_SNAPSHOT:
        if (length == 9)
        {
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_ofdma_timestamp_snapshot,
                                tvb, pos, length, ENC_NA);
        }
        else
        {
          expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_OFDMA_CYCLIC_PREFIX_SIZE:
        if (length == 1)
        {
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_ofdma_cyclic_prefix_size,
                                tvb, pos, length, ENC_NA);
        }
        else
        {
          expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_OFDMA_ROLLOFF_PERIOD_SIZE:
        if (length == 1)
        {
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_ofdma_rolloff_period_size,
                                tvb, pos, length, ENC_NA);
        }
        else
        {
          expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_SUBCARRIER_SPACING:
        if (length == 1)
        {
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_subc_spacing,
                                tvb, pos, length, ENC_NA);
        }
        else
        {
          expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_CENTER_FREQ_SUBC_0:
        if (length == 4)
        {
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_cent_freq_subc0,
                                   tvb, pos, length, ENC_NA);
        }
        else
        {
          expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_SUBC_EXCL_BAND:
        if ((length % 4) == 0)
        {
          for(i = 0; i < length; i+=4) {
            proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_subcarrier_range, tvb, pos+i, 4, ENC_NA);
          }
        }
        else
        {
          expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_UNUSED_SUBC_SPEC:
        if ((length % 4) == 0)
        {
          for(i = 0; i < length; i+=4) {
            proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_subcarrier_range, tvb, pos+i, 4, ENC_NA);
          }
        }
        else
        {
          expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_SYMB_IN_OFDMA_FRAME:
        if (length == 1)
        {
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_symb_ofdma_frame,
                                 tvb, pos, length, ENC_NA);
        }
        else
        {
          expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_RAND_SEED:
        if (length == 3)
        {
          proto_tree_add_item (type51tlv_tree, hf_docsis_type51ucd_rand_seed,
                                tvb, pos, length, ENC_NA);
        }
        else
        {
          expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvlen_bad, "Wrong TLV length: %u", length);
        }
        break;
      case type51ucd_BURST_DESCR23:
        dissect_type51ucd_burstdescriptor(tvb, pinfo, type51tlv_tree, pos, length);
        break;
    default:
      expert_add_info_format(pinfo, type51tlv_item, &ei_docsis_type51ucd_tlvtype_bad, "Unknown TLV type: %u", type);
    }                   /* switch(type) */
    pos = pos + length;
  }                       /* while (pos < len) */
  return len;
}

/* Register the protocol with Wireshark */
void
proto_register_docsis_type51ucd (void)
{
  static hf_register_info hf[] = {
    {&hf_docsis_type51ucd_upstream_chid,
     {"Upstream Channel ID", "docsis_type51ucd.upchid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_config_ch_cnt,
     {"Config Change Count", "docsis_type51ucd.confcngcnt",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Configuration Change Count", HFILL}
    },
    {&hf_docsis_type51ucd_mini_slot_size,
     {"Mini Slot Size (6.25us TimeTicks)", "docsis_type51ucd.mslotsize",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_down_chid,
     {"Downstream Channel ID", "docsis_type51ucd.downchid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Management Message", HFILL}
    },
    {&hf_docsis_type51ucd_type,
     {"Type", "docsis_type51ucd.type",
      FT_UINT8, BASE_DEC, VALS(channel_tlv_vals), 0x0,
      "Channel TLV type", HFILL}
    },
    {&hf_docsis_type51ucd_length,
     {"Length", "docsis_type51ucd.length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Channel TLV length", HFILL}
    },
    {&hf_docsis_type51ucd_burst_type,
     {"Type", "docsis_type51ucd.burst.tlvtype",
      FT_UINT8, BASE_DEC, VALS(burst_tlv_vals), 0x0,
      "Burst TLV type", HFILL}
    },
    {&hf_docsis_type51ucd_burst_length,
     {"Length", "docsis_type51ucd.burst.tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Burst TLV length", HFILL}
    },
    {&hf_docsis_type51ucd_symbol_rate,
     {"Symbol Rate (ksym/sec)", "docsis_type51ucd.symrate",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Symbol Rate", HFILL}
    },
    {&hf_docsis_type51ucd_frequency,
     {"Frequency (Hz)", "docsis_type51ucd.freq",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Upstream Center Frequency", HFILL}
    },
    {&hf_docsis_type51ucd_preamble_pat,
     {"Preamble Pattern", "docsis_type51ucd.preamble",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Preamble Superstring", HFILL}
    },
    {&hf_docsis_type51ucd_iuc,
     {"Interval Usage Code", "docsis_type51ucd.iuc",
      FT_UINT8, BASE_DEC, VALS (iuc_vals3), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_mod_type,
     {"Modulation Type", "docsis_type51ucd.burst.modtype",
      FT_UINT8, BASE_DEC, VALS (mod_vals2), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_diff_encoding,
     {"Differential Encoding", "docsis_type51ucd.burst.diffenc",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_preamble_len,
     {"Preamble Length (Bits)", "docsis_type51ucd.burst.preamble_len",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_preamble_val_off,
     {"Preamble Offset (Bits)", "docsis_type51ucd.burst.preamble_off",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_fec,
     {"FEC (T)", "docsis_type51ucd.burst.fec",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "FEC (T) Codeword Parity Bits = 2^T", HFILL}
    },
    {&hf_docsis_burst_fec_codeword,
     {"FEC Codeword Info bytes (k)", "docsis_type51ucd.burst.fec_codeword",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_scrambler_seed,
     {"Scrambler Seed", "docsis_type51ucd.burst.scrambler_seed",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "Burst Descriptor", HFILL}
    },
    {&hf_docsis_burst_max_burst,
     {"Max Burst Size (Minislots)", "docsis_type51ucd.burst.maxburst",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_guard_time,
     {"Guard Time Size (Symbol Times)", "docsis_type51ucd.burst.guardtime",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Guard Time Size", HFILL}
    },
    {&hf_docsis_burst_last_cw_len,
     {"Last Codeword Length", "docsis_type51ucd.burst.last_cw_len",
      FT_UINT8, BASE_DEC, VALS (last_cw_len_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_scrambler_onoff,
     {"Scrambler On/Off", "docsis_type51ucd.burst.scrambleronoff",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_ext_preamble,
     {"Extended Preamble Pattern", "docsis_type51ucd.extpreamble",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_scdma_mode_enable,
     {"SCDMA Mode Enable", "docsis_type51ucd.scdmaenable",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_scdma_spreading_interval,
     {"SCDMA Spreading Interval", "docsis_type51ucd.scdmaspreadinginterval",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_scdma_codes_per_mini_slot,
     {"SCDMA Codes per mini slot", "docsis_type51ucd.scdmacodesperminislot",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_scdma_active_codes,
     {"SCDMA Active Codes", "docsis_type51ucd.scdmaactivecodes",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_scdma_code_hopping_seed,
     {"SCDMA Code Hopping Seed", "docsis_type51ucd.scdmacodehoppingseed",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_scdma_us_ratio_num,
     {"SCDMA US Ratio Numerator", "docsis_type51ucd.scdmausrationum",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_scdma_us_ratio_denom,
     {"SCDMA US Ratio Denominator", "docsis_type51ucd.scdmausratiodenom",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_scdma_timestamp_snapshot,
     {"SCDMA Timestamp Snapshot", "docsis_type51ucd.scdmatimestamp",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_maintain_power_spectral_density,
     {"Maintain power spectral density", "docsis_type51ucd.maintainpowerspectraldensity",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_ranging_required,
     {"Ranging Required", "docsis_type51ucd.rangingrequired",
      FT_UINT8, BASE_DEC, VALS (ranging_required), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_rnghoff_cm,
     {"Ranging Hold-Off (CM)","docsis_type51ucd.rnghoffcm",
      FT_BOOLEAN, 32, TFS(&type51ucd_tfs_allow_inhibit), 0x1,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_rnghoff_erouter,
     {"Ranging Hold-Off (eRouter)",
      "docsis_type51ucd.rnghofferouter",
      FT_BOOLEAN, 32, TFS(&type51ucd_tfs_allow_inhibit), 0x2,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_rnghoff_emta,
     {"Ranging Hold-Off (eMTA or EDVA)",
      "docsis_type51ucd.rnghoffemta",
      FT_BOOLEAN, 32, TFS(&type51ucd_tfs_allow_inhibit), 0x4,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_rnghoff_estb,
     {"Ranging Hold-Off (DSG/eSTB)",
      "docsis_type51ucd.rnghoffestb",
      FT_BOOLEAN, 32, TFS(&type51ucd_tfs_allow_inhibit), 0x8,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_rnghoff_rsvd,
     {"Reserved [0x000000]",
      "docsis_type51ucd.rnghoffrsvd",
      FT_UINT32, BASE_HEX, NULL, 0xFFF0,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_rnghoff_id_ext,
     {"CM Ranging Class ID Extension",
      "docsis_type51ucd.rngidext",
      FT_UINT32, BASE_HEX, NULL, 0xFFFF0000,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_chan_class_id_cm,
     {"Channel Class ID (CM)","docsis_type51ucd.classidcm",
      FT_BOOLEAN, 32, TFS(&type51ucd_tfs_inhibit_allow), 0x1,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_chan_class_id_erouter,
     {"Channel Class ID (eRouter)",
      "docsis_type51ucd.classiderouter",
      FT_BOOLEAN, 32, TFS(&type51ucd_tfs_inhibit_allow), 0x2,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_chan_class_id_emta,
     {"Channel Class ID (eMTA or EDVA)",
      "docsis_type51ucd.classidemta",
      FT_BOOLEAN, 32, TFS(&type51ucd_tfs_inhibit_allow), 0x4,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_chan_class_id_estb,
     {"Channel Class ID (DSG/eSTB)",
      "docsis_type51ucd.classidestb",
      FT_BOOLEAN, 32, TFS(&type51ucd_tfs_inhibit_allow), 0x8,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_chan_class_id_rsvd,
     {"Reserved [0x000000]",
      "docsis_type51ucd.classidrsvd",
      FT_UINT32, BASE_HEX, NULL, 0xFFF0,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_chan_class_id_id_ext,
     {"CM Ranging Class ID Extension",
      "docsis_type51ucd.classidext",
      FT_UINT32, BASE_HEX, NULL, 0xFFFF0000,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_active_code_hopping,
     {"S-CDMA Selection Mode for Active Codes and Code Hopping", "docsis_type51ucd.selectcodehop",
      FT_UINT8, BASE_DEC, VALS (tlv20_vals), 0x0,
      "SCDMA Selection Mode for Active Codes and Code Hopping", HFILL}
    },
    {&hf_docsis_type51ucd_scdma_selection_active_codes,
     {"S-CDMA Selection String for Active Codes", "docsis_type51ucd.selectcode",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "SCDMA Selection String for Active Codes", HFILL}
    },
    {&hf_docsis_type51ucd_higher_ucd_for_same_ucid,
     {"Higher UCD for the same UCID", "docsis_type51ucd.highucdpresent",
      FT_BOOLEAN, 8, TFS(&type51ucd_tfs_present_not_present), 0x1,
      "Higher UCD for the same UCID present bitmap", HFILL}
    },
    {&hf_docsis_type51ucd_higher_ucd_for_same_ucid_resv,
     {"Reserved", "docsis_type51ucd.highucdresv",
      FT_UINT8, BASE_HEX, NULL, 0xFE,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_max_scheduled_codes,
     {"S-CDMA Max Scheduled Codes", "docsis_type51ucd.scdmamaxcodes",
      FT_UINT8, BASE_DEC, VALS (max_scheduled_codes_vals), 0x0,
      "S-CDMA Maximum Scheduled Codes", HFILL}
    },
    {&hf_docsis_rs_int_depth,
     {"Scrambler On/Off", "docsis_type51ucd.burst.rsintdepth",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "R-S Interleaver Depth", HFILL}
    },
    {&hf_docsis_rs_int_block,
     {"Scrambler On/Off", "docsis_type51ucd.burst.rsintblock",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "R-S Interleaver Block", HFILL}
    },
    {&hf_docsis_preamble_type,
     {"Scrambler On/Off", "docsis_type51ucd.burst.preambletype",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Preamble Type", HFILL}
    },
    {&hf_docsis_scdma_scrambler_onoff,
     {"Scrambler On/Off", "docsis_type51ucd.burst.scdmascrambleronoff",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      "SCDMA Scrambler On/Off", HFILL}
    },
    {&hf_docsis_scdma_codes_per_subframe,
     {"SCDMA Codes per Subframe", "docsis_type51ucd.burst.scdmacodespersubframe",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_scdma_framer_int_step_size,
     {"SCDMA Framer Interleaving Step Size", "docsis_type51ucd.burst.scdmaframerintstepsize",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tcm_enabled,
     {"TCM Enabled", "docsis_type51ucd.burst.tcmenabled",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_subc_init_rang,
     {"Subcarriers (Nir) Initial Ranging", "docsis_type51ucd.burst.subc_init_rang",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_subc_fine_rang,
     {"Subcarriers (Nfr) Fine Ranging", "docsis_type51ucd.burst.subc_fine_rang",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_ofdma_prof_mod_order,
     {"OFDMA Profile: modulation", "docsis_type51ucd.burst.ofma_prof_mod_order",
      FT_UINT8, BASE_DEC, VALS(ofdma_prof_mod_order), 0xF0,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_ofdma_prof_pilot_pattern,
     {"OFDMA Profile: pilot pattern", "docsis_type51ucd.burst.ofma_prof_pilot_pattern",
      FT_UINT8, BASE_DEC, NULL, 0x0F,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_ofdma_prof_num_add_minislots,
     {"OFDMA Profile: Additional Minislots that have identical bit-loading and pilot pattern index", "docsis_type51ucd.burst.ofma_prof_add_minislots",
      FT_UINT8, BASE_DEC, NULL, 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_ofdma_ir_pow_ctrl_start_pow,
     {"OFDMA IR Power Control Starting Power Level", "docsis_type51ucd.burst.ofma_ir_pow_ctrl_start_pow",
      FT_UINT8, BASE_CUSTOM, CF_FUNC(ofdma_ir_pow_ctrl_start_pow), 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_ofdma_ir_pow_ctrl_step_size,
     {"OFDMA IR Power Control Step Size", "docsis_type51ucd.burst.ofma_ir_pow_ctrl_step_size",
      FT_UINT8, BASE_CUSTOM, CF_FUNC(ofdma_ir_pow_ctrl_step_size), 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_ucd_change_ind_bitmask_subc_excl_band,
     {"UCD Change Indicator Bitmask: Subcarrier Exclusion Band TLV", "docsis_type51ucd.burst.ucd_change_ind_bitmask_subc_excl_band",
      FT_UINT8, BASE_DEC, VALS(ucd_change_ind_vals), 0x01,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_ucd_change_ind_bitmask_unused_subc,
     {"UCD Change Indicator Bitmask: Unused Subcarrier Specification TLV", "docsis_type51ucd.burst.ucd_change_ind_bitmask_unused_subc",
      FT_UINT8, BASE_DEC, VALS(ucd_change_ind_vals), 0x02,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_ucd_change_ind_bitmask_other_subc,
     {"UCD Change Indicator Bitmask: Other than Subcarrier Exclusion Band and Unused Subcarrier Specification TLV", "docsis_type51ucd.burst.ucd_change_ind_bitmask_other_subc",
      FT_UINT8, BASE_DEC, VALS(ucd_change_ind_vals), 0x04,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_ucd_change_ind_bitmask_burst_attr_iuc5,
     {"UCD Change Indicator Bitmask: Burst Attributes associated with IUC5", "docsis_type51ucd.burst.ucd_change_ind_bitmask_burst_attr_iuc5",
      FT_UINT8, BASE_DEC, VALS(ucd_change_ind_vals), 0x08,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_ucd_change_ind_bitmask_burst_attr_iuc6,
     {"UCD Change Indicator Bitmask: Burst Attributes associated with IUC6", "docsis_type51ucd.burst.ucd_change_ind_bitmask_burst_attr_iuc6",
      FT_UINT8, BASE_DEC, VALS(ucd_change_ind_vals), 0x10,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_ucd_change_ind_bitmask_burst_attr_iuc9,
     {"UCD Change Indicator Bitmask: Burst Attributes associated with IUC9", "docsis_type51ucd.burst.ucd_change_ind_bitmask_burst_attr_iuc9",
      FT_UINT8, BASE_DEC, VALS(ucd_change_ind_vals), 0x20,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_ucd_change_ind_bitmask_burst_attr_iuc10,
     {"UCD Change Indicator Bitmask: Burst Attributes associated with IUC10", "docsis_type51ucd.burst.ucd_change_ind_bitmask_burst_attr_iuc10",
      FT_UINT8, BASE_DEC, VALS(ucd_change_ind_vals), 0x40,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_ucd_change_ind_bitmask_burst_attr_iuc11,
     {"UCD Change Indicator Bitmask: Burst Attributes associated with IUC11", "docsis_type51ucd.burst.ucd_change_ind_bitmask_burst_attr_iuc11",
      FT_UINT8, BASE_DEC, VALS(ucd_change_ind_vals), 0x80,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_ucd_change_ind_bitmask_burst_attr_iuc12,
     {"UCD Change Indicator Bitmask: Burst Attributes associated with IUC12", "docsis_type51ucd.burst.ucd_change_ind_bitmask_burst_attr_iuc12",
      FT_UINT8, BASE_DEC, VALS(ucd_change_ind_vals), 0x01,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_ucd_change_ind_bitmask_burst_attr_iuc13,
     {"UCD Change Indicator Bitmask: Burst Attributes associated with IUC13", "docsis_type51ucd.burst.ucd_change_ind_bitmask_burst_attr_iuc13",
      FT_UINT8, BASE_DEC, VALS(ucd_change_ind_vals), 0x02,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_ucd_change_ind_bitmask_burst_attr_iuc3_or_4,
     {"UCD Change Indicator Bitmask: Burst Attributes associated with IUC3 or IUC4", "docsis_type51ucd.burst.ucd_change_ind_bitmask_burst_attr_iuc3_or_4",
      FT_UINT8, BASE_DEC, VALS(ucd_change_ind_vals), 0x04,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_ucd_change_ind_bitmask_reserved,
     {"UCD Change Indicator Bitmask: Reserved", "docsis_type51ucd.burst.ucd_change_ind_bitmask_reserved",
      FT_UINT8, BASE_HEX, NULL, 0xF8,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_ofdma_timestamp_snapshot,
     {"OFDMA Timestamp Snapshot", "docsis_type51ucd.ofdma_timestamp_snapshot",
      FT_BYTES, BASE_NONE, NULL, 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_ofdma_cyclic_prefix_size,
     {"OFDMA Cyclic Prefix Size", "docsis_type51ucd.ofdma_cyclic_prefix_size",
      FT_UINT8, BASE_DEC, VALS(ofdma_cyclic_prefix_size_vals), 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_ofdma_rolloff_period_size,
     {"OFDMA Rolloff Period Size", "docsis_type51ucd.ofdma_rolloff_period_size",
      FT_UINT8, BASE_DEC, VALS(ofdma_rolloff_period_size_vals), 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_subc_spacing,
     {"Subcarrier Spacing", "docsis_type51ucd.subc_spacing",
      FT_UINT8, BASE_DEC, VALS(subc_spacing_vals), 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_cent_freq_subc0,
     {"Center Frequency of Subcarrier 0", "docsis_type51ucd.cent_freq_subc0",
      FT_UINT8, BASE_DEC, NULL, 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_subcarrier_range,
     {"Subcarrier range", "docsis_type51ucd.subc_range",
      FT_UINT32, BASE_CUSTOM, CF_FUNC(subcarrier_range), 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_symb_ofdma_frame,
     {"Symbols in OFDMA frame", "docsis_type51ucd.symb_ofdma_frame",
      FT_UINT8, BASE_DEC, NULL, 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_type51ucd_rand_seed,
     {"Randomization Seed", "docsis_type51ucd.rand_seed",
      FT_BYTES, BASE_NONE, NULL, 0x00,
      NULL, HFILL}
    },
  };



  static ei_register_info ei[] = {
    {&ei_docsis_type51ucd_tlvlen_bad, {"docsis_type51ucd.tlvlenbad", PI_MALFORMED, PI_ERROR, "Bad TLV length", EXPFILL}},
    {&ei_docsis_type51ucd_tlvtype_bad, {"docsis_type51ucd.tlvtypebad", PI_PROTOCOL, PI_WARN, "Bad TLV type", EXPFILL}},
  };

  static gint *ett[] = {
    &ett_docsis_type51ucd,
    &ett_docsis_type51tlv,
    &ett_docsis_type51_burst_tlv,
  };

  expert_module_t* expert_docsis_type51ucd;

  proto_docsis_type51ucd =
    proto_register_protocol ("DOCSIS Upstream Channel Descriptor Type 51",
                             "DOCSIS type51ucd", "docsis_type51ucd");

  proto_register_field_array (proto_docsis_type51ucd, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
  expert_docsis_type51ucd = expert_register_protocol(proto_docsis_type51ucd);
  expert_register_field_array(expert_docsis_type51ucd, ei, array_length(ei));

  docsis_type51ucd_handle = register_dissector ("docsis_type51ucd", dissect_type51ucd, proto_docsis_type51ucd);
}

void
proto_reg_handoff_docsis_type51ucd (void)
{
  dissector_add_uint ("docsis_mgmt", 0x33, docsis_type51ucd_handle);
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
