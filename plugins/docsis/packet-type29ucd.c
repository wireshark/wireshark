/* packet-type29ucd.c
 * Routines for Type 29 UCD - DOCSIS 2.0 only - Message dissection
 * Copyright 2003, Brian Wheeler <brian.wheeler[AT]arrisi.com>
 *
 * $Id$
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

#define type29ucd_SYMBOL_RATE 1
#define type29ucd_FREQUENCY 2
#define type29ucd_PREAMBLE 3
#define type29ucd_BURST_DESCR 4
#define type29ucd_BURST_DESCR5 5
#define type29ucd_EXT_PREAMBLE 6
#define type29ucd_SCDMA_MODE_ENABLE 7
#define type29ucd_SCDMA_SPREADING_INTERVAL 8
#define type29ucd_SCDMA_CODES_PER_MINI_SLOT 9
#define type29ucd_SCDMA_ACTIVE_CODES 10
#define type29ucd_SCDMA_CODE_HOPPING_SEED 11
#define type29ucd_SCDMA_US_RATIO_NUM 12
#define type29ucd_SCDMA_US_RATIO_DENOM 13
#define type29ucd_SCDMA_TIMESTAMP_SNAPSHOT 14
#define type29ucd_MAINTAIN_POWER_SPECTRAL_DENSITY 15
#define type29ucd_RANGING_REQUIRED 16

#define type29ucd_MODULATION 1
#define type29ucd_DIFF_ENCODING 2
#define type29ucd_PREAMBLE_LEN 3
#define type29ucd_PREAMBLE_VAL_OFF 4
#define type29ucd_FEC 5
#define type29ucd_FEC_CODEWORD 6
#define type29ucd_SCRAMBLER_SEED 7
#define type29ucd_MAX_BURST 8
#define type29ucd_GUARD_TIME 9
#define type29ucd_LAST_CW_LEN 10
#define type29ucd_SCRAMBLER_ONOFF 11
#define type29ucd_RS_INT_DEPTH 12
#define type29ucd_RS_INT_BLOCK 13
#define type29ucd_PREAMBLE_TYPE 14
#define type29ucd_SCMDA_SCRAMBLER_ONOFF 15
#define type29ucd_SCDMA_CODES_PER_SUBFRAME 16
#define type29ucd_SCDMA_FRAMER_INT_STEP_SIZE 17
#define type29ucd_TCM_ENABLED 18

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

/* Initialize the protocol and registered fields */
static int proto_docsis_type29ucd = -1;

static int hf_docsis_type29ucd_upstream_chid = -1;
static int hf_docsis_type29ucd_config_ch_cnt = -1;
static int hf_docsis_type29ucd_mini_slot_size = -1;
static int hf_docsis_type29ucd_down_chid = -1;
static int hf_docsis_type29ucd_symbol_rate = -1;
static int hf_docsis_type29ucd_frequency = -1;
static int hf_docsis_type29ucd_preamble_pat = -1;
static int hf_docsis_type29ucd_iuc = -1;
static int hf_docsis_type29ucd_ext_preamble = -1;
static int hf_docsis_type29ucd_scdma_mode_enable = -1;
static int hf_docsis_type29ucd_scdma_spreading_interval = -1;
static int hf_docsis_type29ucd_scdma_codes_per_mini_slot = -1;
static int hf_docsis_type29ucd_scdma_active_codes = -1;
static int hf_docsis_type29ucd_scdma_code_hopping_seed = -1;
static int hf_docsis_type29ucd_scdma_us_ratio_num = -1;
static int hf_docsis_type29ucd_scdma_us_ratio_denom = -1;
static int hf_docsis_type29ucd_scdma_timestamp_snapshot = -1;
static int hf_docsis_type29ucd_maintain_power_spectral_density = -1;
static int hf_docsis_type29ucd_ranging_required = -1;

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


/* Initialize the subtree pointers */
static gint ett_docsis_type29ucd = -1;
static gint ett_burst_descr = -1;

static const value_string channel_tlv_vals[] _U_ = {
     {type29ucd_SYMBOL_RATE, "Symbol Rate"},
     {type29ucd_FREQUENCY, "Frequency"},
     {type29ucd_PREAMBLE, "Preamble Pattern"},
     {type29ucd_BURST_DESCR, "Burst Descriptor"},
     {type29ucd_BURST_DESCR5, "Burst Descriptor DOCSIS 2.0"},
     {type29ucd_EXT_PREAMBLE, "Extended Preamble Pattern"},
     {type29ucd_SCDMA_MODE_ENABLE, "SCDMA Mode Enabled"},
     {type29ucd_SCDMA_SPREADING_INTERVAL, "SCDMA Spreading Intervals per Frame"},
     {type29ucd_SCDMA_CODES_PER_MINI_SLOT, "SCDMA Codes per Mini-slot"},
     {type29ucd_SCDMA_ACTIVE_CODES, "SCDMA Number of Active Codes"},
     {type29ucd_SCDMA_CODE_HOPPING_SEED, "SCDMA Code Hopping Seed"},
     {type29ucd_SCDMA_US_RATIO_NUM, "SCDMA US ratio numerator M"},
     {type29ucd_SCDMA_US_RATIO_DENOM, "SCDMA US ratio denominator N"},
     {type29ucd_SCDMA_TIMESTAMP_SNAPSHOT, "SCDMA Timestamp Snapshot"},
     {type29ucd_MAINTAIN_POWER_SPECTRAL_DENSITY, "Maintain Power Spectral Density"},
     {type29ucd_RANGING_REQUIRED, "Ranging Required"},
     {0, NULL}
};

static const value_string on_off_vals[] = {
  {1, "On"},
  {2, "Off"},
  {0, NULL}
};

static const value_string mod_vals2[] = {
     {1, "QPSK"},
     {2, "QAM16"},
     {3, "QAM8"},
     {4, "QAM32"},
     {5, "QAM64"},
     {6, "QAM128 (S-CDMA)"},
     {0, NULL}
};

value_string iuc_vals2[] = {
     {IUC_REQUEST, "Request"},
     {IUC_REQ_DATA, "REQ/Data"},
     {IUC_INIT_MAINT, "Initial Maintenance"},
     {IUC_STATION_MAINT, "Station Maintenance"},
     {IUC_SHORT_DATA_GRANT, "Short Data Grant"},
     {IUC_LONG_DATA_GRANT, "Long Data Grant"},
     {IUC_NULL_IE, "NULL IE"},
     {IUC_DATA_ACK, "Data Ack"},
     {IUC_ADV_PHY_SHORT_DATA_GRANT, "Advanced Phy Short Data Grant"},
     {IUC_ADV_PHY_LONG_DATA_GRANT, "Advanced Phy Long Data Grant"},
     {IUC_ADV_PHY_UGS, "Advanced Phy UGS"},
     {IUC_RESERVED12, "Reserved 12"},
     {IUC_RESERVED13, "Reserved 13"},
     {IUC_RESERVED14, "Reserved 14"},
     {IUC_EXPANSION, "IUC Expansion"},
     {0, NULL}
};

static const value_string last_cw_len_vals[] = {
  {1, "Fixed"},
  {2, "Shortened"},
  {0, NULL}
};
/* Code to actually dissect the packets */
static void
dissect_type29ucd (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  guint16 pos, endtlvpos;
  guint8 type, length;
  guint8 tlvlen, tlvtype;
  proto_tree *burst_descr_tree;
  proto_item *it;
  proto_tree *type29ucd_tree;
  proto_item *type29ucd_item;
  guint16 len;
  guint8 upchid, symrate;

  len = tvb_length_remaining (tvb, 0);
  upchid = tvb_get_guint8 (tvb, 0);

  /* if the upstream Channel ID is 0 then this is for Telephony Return) */
  col_clear (pinfo->cinfo, COL_INFO);
  if (upchid > 0)
	col_add_fstr (pinfo->cinfo, COL_INFO,
		      "type29ucd Message:  Channel ID = %u (U%u)", upchid,
		      upchid - 1);
  else
	col_add_fstr (pinfo->cinfo, COL_INFO,
		      "type29ucd Message:  Channel ID = %u (Telephony Return)",
		      upchid);

  if (tree)
    {
      type29ucd_item =
	proto_tree_add_protocol_format (tree, proto_docsis_type29ucd, tvb, 0,
					tvb_length_remaining (tvb, 0),
					"type29ucd Message");
      type29ucd_tree = proto_item_add_subtree (type29ucd_item, ett_docsis_type29ucd);
      proto_tree_add_item (type29ucd_tree, hf_docsis_type29ucd_upstream_chid, tvb, 0, 1,
			   ENC_BIG_ENDIAN);
      proto_tree_add_item (type29ucd_tree, hf_docsis_type29ucd_config_ch_cnt, tvb, 1, 1,
			   ENC_BIG_ENDIAN);
      proto_tree_add_item (type29ucd_tree, hf_docsis_type29ucd_mini_slot_size, tvb, 2, 1,
			   ENC_BIG_ENDIAN);
      proto_tree_add_item (type29ucd_tree, hf_docsis_type29ucd_down_chid, tvb, 3, 1,
			   ENC_BIG_ENDIAN);

      pos = 4;
      while (pos < len)
	{
	  type = tvb_get_guint8 (tvb, pos++);
	  length = tvb_get_guint8 (tvb, pos++);
	  switch (type)
	    {
	    case type29ucd_SYMBOL_RATE:
	      if (length == 1)
		{
		  symrate = tvb_get_guint8 (tvb, pos);
		  proto_tree_add_uint (type29ucd_tree, hf_docsis_type29ucd_symbol_rate,
				       tvb, pos, length, symrate * 160);
		}
	      else
		{
		  THROW (ReportedBoundsError);
		}
	      pos = pos + length;
	      break;
	    case type29ucd_FREQUENCY:
	      if (length == 4)
		{
		  proto_tree_add_item (type29ucd_tree, hf_docsis_type29ucd_frequency, tvb,
				       pos, length, ENC_BIG_ENDIAN);
		  pos = pos + length;
		}
	      else
		{
		  THROW (ReportedBoundsError);
		}
	      break;
	    case type29ucd_PREAMBLE:
	      proto_tree_add_item (type29ucd_tree, hf_docsis_type29ucd_preamble_pat, tvb,
				   pos, length, ENC_NA);
	      pos = pos + length;
	      break;
/* DOCSIS 2.0 UCD TLV definitions 
 * #define type29ucd_EXT_PREAMBLE 6
 * #define type29ucd_SCDMA_MODE_ENABLE 7
 * #define type29ucd_SCDMA_SPREADING_INTERVAL 8
 * #define type29ucd_SCDMA_CODES_PER_MINI_SLOT 9
 * #define type29ucd_SCDMA_ACTIVE_CODES 10
 * #define type29ucd_SCDMA_CODE_HOPPING_SEED 11
 * #define type29ucd_SCDMA_US_RATIO_NUM 12
 * #define type29ucd_SCDMA_US_RATIO_DENOM 13
 * #define type29ucd_SCDMA_TIMESTAMP_SNAPSHOT 14
 * #define type29ucd_MAINTAIN_POWER_SPECTRAL_DENSITY 15
 * #define type29ucd_RANGING_REQUIRED 16
 */
	    case type29ucd_EXT_PREAMBLE:
	      proto_tree_add_item (type29ucd_tree, hf_docsis_type29ucd_ext_preamble, tvb,
				   pos, length, ENC_NA);
	      pos = pos + length;
	      break;
	    case type29ucd_SCDMA_MODE_ENABLE:
	      if (length == 1)
		{
		  proto_tree_add_item (type29ucd_tree, hf_docsis_type29ucd_scdma_mode_enable,
				       tvb, pos, length, ENC_NA);
		}
	      else
		{
		  THROW (ReportedBoundsError);
		}
	      pos = pos + length;
	      break;
	    case type29ucd_SCDMA_SPREADING_INTERVAL:
	      if (length == 1)
		{
		  proto_tree_add_item (type29ucd_tree, hf_docsis_type29ucd_scdma_spreading_interval,
				       tvb, pos, length, ENC_NA);
		}
	      else
		{
		  THROW (ReportedBoundsError);
		}
	      pos = pos + length;
	      break;
	    case type29ucd_SCDMA_CODES_PER_MINI_SLOT:
	      if (length == 1)
		{
		  proto_tree_add_item (type29ucd_tree, hf_docsis_type29ucd_scdma_codes_per_mini_slot,
				       tvb, pos, length, ENC_NA);
		}
	      else
		{
		  THROW (ReportedBoundsError);
		}
	      pos = pos + length;
	      break;
	    case type29ucd_SCDMA_ACTIVE_CODES:
	      if (length == 1)
		{
		  proto_tree_add_item (type29ucd_tree, hf_docsis_type29ucd_scdma_active_codes,
				       tvb, pos, length, ENC_NA);
		}
	      else
		{
		  THROW (ReportedBoundsError);
		}
	      pos = pos + length;
	      break;
	    case type29ucd_SCDMA_CODE_HOPPING_SEED:
	      if (length == 2)
		{
		  proto_tree_add_item (type29ucd_tree, hf_docsis_type29ucd_scdma_code_hopping_seed,
				       tvb, pos, length, ENC_NA);
		}
	      else
		{
		  THROW (ReportedBoundsError);
		}
	      pos = pos + length;
	      break;
	    case type29ucd_SCDMA_US_RATIO_NUM:
	      if (length == 2)
		{
		  proto_tree_add_item (type29ucd_tree, hf_docsis_type29ucd_scdma_us_ratio_num,
				       tvb, pos, length, ENC_NA);
		}
	      else
		{
		  THROW (ReportedBoundsError);
		}
	      pos = pos + length;
	      break;
	    case type29ucd_SCDMA_US_RATIO_DENOM:
	      if (length == 2)
		{
 		  proto_tree_add_item (type29ucd_tree, hf_docsis_type29ucd_scdma_us_ratio_denom,
				       tvb, pos, length, ENC_NA);
		}
	      else
		{
		  THROW (ReportedBoundsError);
		}
	      pos = pos + length;
	      break;
	    case type29ucd_SCDMA_TIMESTAMP_SNAPSHOT:
	      if (length == 9)
		{
		  proto_tree_add_item (type29ucd_tree, hf_docsis_type29ucd_scdma_timestamp_snapshot,
				       tvb, pos, length, ENC_NA);
		}
	      else
		{
		  THROW (ReportedBoundsError);
		}
	      pos = pos + length;
	      break;
	    case type29ucd_MAINTAIN_POWER_SPECTRAL_DENSITY:
	      if (length == 1)
		{
		  proto_tree_add_item (type29ucd_tree, hf_docsis_type29ucd_maintain_power_spectral_density,
				       tvb, pos, length, ENC_NA);
		}
	      else
		{
		  THROW (ReportedBoundsError);
		}
	      pos = pos + length;
	      break;
	    case type29ucd_RANGING_REQUIRED:
	      if (length == 1)
		{
		  proto_tree_add_item (type29ucd_tree, hf_docsis_type29ucd_ranging_required,
				       tvb, pos, length, ENC_NA);
		}
	      else
		{
		  THROW (ReportedBoundsError);
		}
	      pos = pos + length;
	      break;	       
/* DOCSIS 1.1 BURST DESCRIPTOR */
	     case type29ucd_BURST_DESCR:
	      it =
		proto_tree_add_text (type29ucd_tree, tvb, pos, length,
				     "4 Burst Descriptor (Length = %u)",
				     length);
	      burst_descr_tree = proto_item_add_subtree (it, ett_burst_descr);
	      proto_tree_add_item (burst_descr_tree, hf_docsis_type29ucd_iuc, tvb,
				   pos++, 1, ENC_BIG_ENDIAN);
	      endtlvpos = pos + length - 1;
	      while (pos < endtlvpos)
		{
		  tlvtype = tvb_get_guint8 (tvb, pos++);
		  tlvlen = tvb_get_guint8 (tvb, pos++);
		  switch (tlvtype)
		    {
		    case type29ucd_MODULATION:
		      if (tlvlen == 1)
			{
			  proto_tree_add_item (burst_descr_tree,
					       hf_docsis_burst_mod_type, tvb,
					       pos, tlvlen, ENC_BIG_ENDIAN);
			}
		      else
			{
			  THROW (ReportedBoundsError);
			}
		      break;
		    case type29ucd_DIFF_ENCODING:
		      if (tlvlen == 1)
			{
			  proto_tree_add_item (burst_descr_tree,
					       hf_docsis_burst_diff_encoding,
					       tvb, pos, tlvlen, ENC_BIG_ENDIAN);
			}
		      else
			{
			  THROW (ReportedBoundsError);
			}
		      break;
		    case type29ucd_PREAMBLE_LEN:
		      if (tlvlen == 2)
			{
			  proto_tree_add_item (burst_descr_tree,
					       hf_docsis_burst_preamble_len,
					       tvb, pos, tlvlen, ENC_BIG_ENDIAN);
			}
		      else
			{
			  THROW (ReportedBoundsError);
			}
		      break;
		    case type29ucd_PREAMBLE_VAL_OFF:
		      if (tlvlen == 2)
			{
			  proto_tree_add_item (burst_descr_tree,
					       hf_docsis_burst_preamble_val_off,
					       tvb, pos, tlvlen, ENC_BIG_ENDIAN);
			}
		      else
			{
			  THROW (ReportedBoundsError);
			}
		      break;
		    case type29ucd_FEC:
		      if (tlvlen == 1)
			{
			  proto_tree_add_item (burst_descr_tree,
					       hf_docsis_burst_fec, tvb, pos,
					       tlvlen, ENC_BIG_ENDIAN);
			}
		      else
			{
			  THROW (ReportedBoundsError);
			}
		      break;
		    case type29ucd_FEC_CODEWORD:
		      if (tlvlen == 1)
			{
			  proto_tree_add_item (burst_descr_tree,
					       hf_docsis_burst_fec_codeword,
					       tvb, pos, tlvlen, ENC_BIG_ENDIAN);
			}
		      else
			{
			  THROW (ReportedBoundsError);
			}
		      break;
		    case type29ucd_SCRAMBLER_SEED:
		      if (tlvlen == 2)
			{
			  proto_tree_add_item (burst_descr_tree,
					       hf_docsis_burst_scrambler_seed,
					       tvb, pos, tlvlen, ENC_BIG_ENDIAN);
			}
		      else
			{
			  THROW (ReportedBoundsError);
			}
		      break;
		    case type29ucd_MAX_BURST:
		      if (tlvlen == 1)
			{
			  proto_tree_add_item (burst_descr_tree,
					       hf_docsis_burst_max_burst, tvb,
					       pos, tlvlen, ENC_BIG_ENDIAN);
			}
		      else
			{
			  THROW (ReportedBoundsError);
			}
		      break;
		    case type29ucd_GUARD_TIME:
		      if (tlvlen == 1)
			{
			  proto_tree_add_item (burst_descr_tree,
					       hf_docsis_burst_guard_time,
					       tvb, pos, tlvlen, ENC_BIG_ENDIAN);
			}
		      else
			{
			  THROW (ReportedBoundsError);
			}
		      break;
		    case type29ucd_LAST_CW_LEN:
		      if (tlvlen == 1)
			{
			  proto_tree_add_item (burst_descr_tree,
					       hf_docsis_burst_last_cw_len,
					       tvb, pos, tlvlen, ENC_BIG_ENDIAN);
			}
		      else
			{
			  THROW (ReportedBoundsError);
			}
		      break;
		     case type29ucd_SCRAMBLER_ONOFF:
		       if (tlvlen == 1)
			 {
			    proto_tree_add_item (burst_descr_tree,
						 hf_docsis_burst_scrambler_onoff,
						 tvb, pos, tlvlen, ENC_BIG_ENDIAN);
			 }
		       else
			 {
			    THROW (ReportedBoundsError);
			 }
		       break;
		    }		/* switch(tlvtype) */
		   pos = pos + tlvlen;
		}		/* while (pos < endtlvpos) */
	       break;
/* DOCSIS 2.0 Upstream Channel Descriptor */
	     case type29ucd_BURST_DESCR5:
	      it =
		proto_tree_add_text (type29ucd_tree, tvb, pos, length,
				     "5 Burst Descriptor (Length = %u)",
				     length);
	      burst_descr_tree = proto_item_add_subtree (it, ett_burst_descr);
	      proto_tree_add_item (burst_descr_tree, hf_docsis_type29ucd_iuc, tvb,
				   pos++, 1, ENC_BIG_ENDIAN);
	      endtlvpos = pos + length - 1;
	      while (pos < endtlvpos)
		{
		  tlvtype = tvb_get_guint8 (tvb, pos++);
		  tlvlen = tvb_get_guint8 (tvb, pos++);
		  switch (tlvtype)
		    {
		    case type29ucd_MODULATION:
		      if (tlvlen == 1)
			{
			  proto_tree_add_item (burst_descr_tree,
					       hf_docsis_burst_mod_type, tvb,
					       pos, tlvlen, ENC_BIG_ENDIAN);
			}
		      else
			{
			  THROW (ReportedBoundsError);
			}
		      break;
		    case type29ucd_DIFF_ENCODING:
		      if (tlvlen == 1)
			{
			  proto_tree_add_item (burst_descr_tree,
					       hf_docsis_burst_diff_encoding,
					       tvb, pos, tlvlen, ENC_BIG_ENDIAN);
			}
		      else
			{
			  THROW (ReportedBoundsError);
			}
		      break;
		    case type29ucd_PREAMBLE_LEN:
		      if (tlvlen == 2)
			{
			  proto_tree_add_item (burst_descr_tree,
					       hf_docsis_burst_preamble_len,
					       tvb, pos, tlvlen, ENC_BIG_ENDIAN);
			}
		      else
			{
			  THROW (ReportedBoundsError);
			}
		      break;
		    case type29ucd_PREAMBLE_VAL_OFF:
		      if (tlvlen == 2)
			{
			  proto_tree_add_item (burst_descr_tree,
					       hf_docsis_burst_preamble_val_off,
					       tvb, pos, tlvlen, ENC_BIG_ENDIAN);
			}
		      else
			{
			  THROW (ReportedBoundsError);
			}
		      break;
		    case type29ucd_FEC:
		      if (tlvlen == 1)
			{
			  proto_tree_add_item (burst_descr_tree,
					       hf_docsis_burst_fec, tvb, pos,
					       tlvlen, ENC_BIG_ENDIAN);
			}
		      else
			{
			  THROW (ReportedBoundsError);
			}
		      break;
		    case type29ucd_FEC_CODEWORD:
		      if (tlvlen == 1)
			{
			  proto_tree_add_item (burst_descr_tree,
					       hf_docsis_burst_fec_codeword,
					       tvb, pos, tlvlen, ENC_BIG_ENDIAN);
			}
		      else
			{
			  THROW (ReportedBoundsError);
			}
		      break;
		    case type29ucd_SCRAMBLER_SEED:
		      if (tlvlen == 2)
			{
			  proto_tree_add_item (burst_descr_tree,
					       hf_docsis_burst_scrambler_seed,
					       tvb, pos, tlvlen, ENC_BIG_ENDIAN);
			}
		      else
			{
			  THROW (ReportedBoundsError);
			}
		      break;
		    case type29ucd_MAX_BURST:
		      if (tlvlen == 1)
			{
			  proto_tree_add_item (burst_descr_tree,
					       hf_docsis_burst_max_burst, tvb,
					       pos, tlvlen, ENC_BIG_ENDIAN);
			}
		      else
			{
			  THROW (ReportedBoundsError);
			}
		      break;
		    case type29ucd_GUARD_TIME:
		      if (tlvlen == 1)
			{
			  proto_tree_add_item (burst_descr_tree,
					       hf_docsis_burst_guard_time,
					       tvb, pos, tlvlen, ENC_BIG_ENDIAN);
			}
		      else
			{
			  THROW (ReportedBoundsError);
			}
		      break;
		    case type29ucd_LAST_CW_LEN:
		      if (tlvlen == 1)
			{
			  proto_tree_add_item (burst_descr_tree,
					       hf_docsis_burst_last_cw_len,
					       tvb, pos, tlvlen, ENC_BIG_ENDIAN);
			}
		      else
			{
			  THROW (ReportedBoundsError);
			}
		      break;
		    case type29ucd_SCRAMBLER_ONOFF:
		      if (tlvlen == 1)
			{
			  proto_tree_add_item (burst_descr_tree,
					       hf_docsis_burst_scrambler_onoff,
					       tvb, pos, tlvlen, ENC_BIG_ENDIAN);
			}
		      else
			{
			  THROW (ReportedBoundsError);
			}
		      break;
/* New cases added for DOCSIS 2.0 US Physical Burst Descriptor TLV */
/* #define type29ucd_RS_INT_DEPTH 12
 * #define type29ucd_RS_INT_BLOCK 13
 * #define type29ucd_PREAMBLE_TYPE 14
 * #define type29ucd_SCMDA_SCRAMBLER_ONOFF 15
 * #define type29ucd_SCDMA_CODES_PER_SUBFRAME 16
 * #define type29ucd_SCDMA_FRAMER_INT_STEP_SIZE 17
 * #define type29ucd_TCM_ENABLED 18
 */
		     case type29ucd_RS_INT_DEPTH:
		      if (tlvlen == 1)
			{
			  proto_tree_add_item (burst_descr_tree,
					       hf_docsis_rs_int_depth,
					       tvb, pos, tlvlen, ENC_BIG_ENDIAN);
			}
		      else
			{
			  THROW (ReportedBoundsError);
			}
		      break;
		     case type29ucd_RS_INT_BLOCK:
		      if (tlvlen == 2)
			{
			  proto_tree_add_item (burst_descr_tree,
					       hf_docsis_rs_int_block,
					       tvb, pos, tlvlen, ENC_BIG_ENDIAN);
			}
		      else
			{
			  THROW (ReportedBoundsError);
			}
		      break;
		     case type29ucd_PREAMBLE_TYPE:
		      if (tlvlen == 1)
			{
			  proto_tree_add_item (burst_descr_tree,
					       hf_docsis_preamble_type,
					       tvb, pos, tlvlen, ENC_BIG_ENDIAN);
			}
		      else
			{
			  THROW (ReportedBoundsError);
			}
		      break;
		     case type29ucd_SCMDA_SCRAMBLER_ONOFF:
		      if (tlvlen == 1)
			{
			  proto_tree_add_item (burst_descr_tree,
					       hf_docsis_scdma_scrambler_onoff,
					       tvb, pos, tlvlen, ENC_BIG_ENDIAN);
			}
		      else
			{
			  THROW (ReportedBoundsError);
			}
		      break;
		     case type29ucd_SCDMA_CODES_PER_SUBFRAME:
		      if (tlvlen == 1)
			{
			  proto_tree_add_item (burst_descr_tree,
					       hf_docsis_scdma_codes_per_subframe,
					       tvb, pos, tlvlen, ENC_BIG_ENDIAN);
			}
		      else
			{
			  THROW (ReportedBoundsError);
			}
		      break;
		     case type29ucd_SCDMA_FRAMER_INT_STEP_SIZE:
		      if (tlvlen == 1)
			{
			  proto_tree_add_item (burst_descr_tree,
					       hf_docsis_scdma_framer_int_step_size,
					       tvb, pos, tlvlen, ENC_BIG_ENDIAN);
			}
		      else
			{
			  THROW (ReportedBoundsError);
			}
		      break;
		     case type29ucd_TCM_ENABLED:
		      if (tlvlen == 1)
			{
			  proto_tree_add_item (burst_descr_tree,
					       hf_docsis_tcm_enabled,
					       tvb, pos, tlvlen, ENC_BIG_ENDIAN);
			}
		      else
			{
			  THROW (ReportedBoundsError);
			}
		      break;
/* End of DOCSIS 2.0 US burst Descriptor Changes */
		    }		/* switch(tlvtype) */
		  pos = pos + tlvlen;
		}		/* while (pos < endtlvpos) */
	      break;
	    }			/* switch(type) */
	}			/* while (pos < len) */
    }				/* if (tree) */

}

/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/


void
proto_register_docsis_type29ucd (void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    {&hf_docsis_type29ucd_upstream_chid,
     {"Upstream Channel ID", "docsis_type29ucd.upchid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_type29ucd_config_ch_cnt,
     {"Config Change Count", "docsis_type29ucd.confcngcnt",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Configuration Change Count", HFILL}
     },
    {&hf_docsis_type29ucd_mini_slot_size,
     {"Mini Slot Size (6.25us TimeTicks)", "docsis_type29ucd.mslotsize",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_type29ucd_down_chid,
     {"Downstream Channel ID", "docsis_type29ucd.downchid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Management Message", HFILL}
     },
    {&hf_docsis_type29ucd_symbol_rate,
     {"1 Symbol Rate (ksym/sec)", "docsis_type29ucd.symrate",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Symbol Rate", HFILL}
     },
    {&hf_docsis_type29ucd_frequency,
     {"2 Frequency (Hz)", "docsis_type29ucd.freq",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Upstream Center Frequency", HFILL}
     },
    {&hf_docsis_type29ucd_preamble_pat,
     {"3 Preamble Pattern", "docsis_type29ucd.preamble",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Preamble Superstring", HFILL}
     },
    {&hf_docsis_type29ucd_iuc,
     {"Interval Usage Code", "docsis_type29ucd.iuc",
      FT_UINT8, BASE_DEC, VALS (iuc_vals2), 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_burst_mod_type,
     {"1 Modulation Type", "docsis_type29ucd.burst.modtype",
      FT_UINT8, BASE_DEC, VALS (mod_vals2), 0x0,
      "Modulation Type", HFILL}
     },
    {&hf_docsis_burst_diff_encoding,
     {"2 Differential Encoding", "docsis_type29ucd.burst.diffenc",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      "Differential Encoding", HFILL}
     },
    {&hf_docsis_burst_preamble_len,
     {"3 Preamble Length (Bits)", "docsis_type29ucd.burst.preamble_len",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Preamble Length (Bits)", HFILL}
     },
    {&hf_docsis_burst_preamble_val_off,
     {"4 Preamble Offset (Bits)", "docsis_type29ucd.burst.preamble_off",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Preamble Offset (Bits)", HFILL}
     },
    {&hf_docsis_burst_fec,
     {"5 FEC (T)", "docsis_type29ucd.burst.fec",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "FEC (T) Codeword Parity Bits = 2^T", HFILL}
     },
    {&hf_docsis_burst_fec_codeword,
     {"6 FEC Codeword Info bytes (k)", "docsis_type29ucd.burst.fec_codeword",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "FEC Codeword Info Bytes (k)", HFILL}
     },
    {&hf_docsis_burst_scrambler_seed,
     {"7 Scrambler Seed", "docsis_type29ucd.burst.scrambler_seed",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "Burst Descriptor", HFILL}
     },
    {&hf_docsis_burst_max_burst,
     {"8 Max Burst Size (Minislots)", "docsis_type29ucd.burst.maxburst",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Max Burst Size (Minislots)", HFILL}
     },
    {&hf_docsis_burst_guard_time,
     {"9 Guard Time Size (Symbol Times)", "docsis_type29ucd.burst.guardtime",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Guard Time Size", HFILL}
     },
    {&hf_docsis_burst_last_cw_len,
     {"10 Last Codeword Length", "docsis_type29ucd.burst.last_cw_len",
      FT_UINT8, BASE_DEC, VALS (last_cw_len_vals), 0x0,
      "Last Codeword Length", HFILL}
     },
    {&hf_docsis_burst_scrambler_onoff,
     {"11 Scrambler On/Off", "docsis_type29ucd.burst.scrambleronoff",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      "Scrambler On/Off", HFILL}
     },
/* DOCSIS 2.0 UCD TLV definitions
 *  * #define type29ucd_EXT_PREAMBLE 6
 *  * #define type29ucd_SCDMA_MODE_ENABLE 7
 *  * #define type29ucd_SCDMA_SPREADING_INTERVAL 8
 *  * #define type29ucd_SCDMA_CODES_PER_MINI_SLOT 9
 *  * #define type29ucd_SCDMA_ACTIVE_CODES 10
 *  * #define type29ucd_SCDMA_CODE_HOPPING_SEED 11
 *  * #define type29ucd_SCDMA_US_RATIO_NUM 12
 *  * #define type29ucd_SCDMA_US_RATIO_DENOM 13
 *  * #define type29ucd_SCDMA_TIMESTAMP_SNAPSHOT 14
 *  * #define type29ucd_MAINTAIN_POWER_SPECTRAL_DENSITY 15
 *  * #define type29ucd_RANGING_REQUIRED 16
 *  */
    {&hf_docsis_type29ucd_ext_preamble,
     {"6 Extended Preamble Pattern", "docsis_type29ucd.extpreamble",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Extended Preamble Pattern", HFILL}
     },
    {&hf_docsis_type29ucd_scdma_mode_enable,
     {"7 SCDMA Mode Enable", "docsis_type29ucd.scdmaenable",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "SCDMA Mode Enable", HFILL}
     },
    {&hf_docsis_type29ucd_scdma_spreading_interval,
     {"8 SCDMA Spreading Interval", "docsis_type29ucd.scdmaspreadinginterval",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "SCDMA Spreading Interval", HFILL}
     },
    {&hf_docsis_type29ucd_scdma_codes_per_mini_slot,
     {"9 SCDMA Codes per mini slot", "docsis_type29ucd.scdmacodesperminislot",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "SCDMA Codes per mini slot", HFILL}
     },
    {&hf_docsis_type29ucd_scdma_active_codes,
     {"10 SCDMA Active Codes", "docsis_type29ucd.scdmaactivecodes",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "SCDMA Active Codes", HFILL}
     },
    {&hf_docsis_type29ucd_scdma_code_hopping_seed,
     {"11 SCDMA Code Hopping Seed", "docsis_type29ucd.scdmacodehoppingseed",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "SCDMA Code Hopping Seed", HFILL}
     },
    {&hf_docsis_type29ucd_scdma_us_ratio_num,
     {"12 SCDMA US Ratio Numerator", "docsis_type29ucd.scdmausrationum",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "SCDMA US Ratio Numerator", HFILL}
     },
    {&hf_docsis_type29ucd_scdma_us_ratio_denom,
     {"13 SCDMA US Ratio Denominator", "docsis_type29ucd.scdmausratiodenom",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "SCDMA US Ratio Denominator", HFILL}
     },
    {&hf_docsis_type29ucd_scdma_timestamp_snapshot,
     {"14 SCDMA Timestamp Snapshot", "docsis_type29ucd.scdmatimestamp",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "SCDMA Timestamp Snapshot", HFILL}
     },
    {&hf_docsis_type29ucd_maintain_power_spectral_density,
     {"15 Maintain power spectral density", "docsis_type29ucd.maintainpowerspectraldensity",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Maintain power spectral density", HFILL}
     },
    {&hf_docsis_type29ucd_ranging_required,
     {"16 Ranging Required", "docsis_type29ucd.rangingrequired",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Ranging Required", HFILL}
     },
/* #define type29ucd_RS_INT_DEPTH 12
 * #define type29ucd_RS_INT_BLOCK 13
 * #define type29ucd_PREAMBLE_TYPE 14
 * #define type29ucd_SCMDA_SCRAMBLER_ONOFF 15
 * #define type29ucd_SCDMA_CODES_PER_SUBFRAME 16
 * #define type29ucd_SCDMA_FRAMER_INT_STEP_SIZE 17
 * #define type29ucd_TCM_ENABLED 18
 */
    {&hf_docsis_rs_int_depth,
     {"12 Scrambler On/Off", "docsis_type29ucd.burst.rsintdepth",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "R-S Interleaver Depth", HFILL}
     },
    {&hf_docsis_rs_int_block,
     {"13 Scrambler On/Off", "docsis_type29ucd.burst.rsintblock",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "R-S Interleaver Block", HFILL}
     },
    {&hf_docsis_preamble_type,
     {"14 Scrambler On/Off", "docsis_type29ucd.burst.preambletype",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Preamble Type", HFILL}
     },
    {&hf_docsis_scdma_scrambler_onoff,
     {"15 Scrambler On/Off", "docsis_type29ucd.burst.scdmascrambleronoff",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      "SCDMA Scrambler On/Off", HFILL}
     },
    {&hf_docsis_scdma_codes_per_subframe,
     {"16 Scrambler On/Off", "docsis_type29ucd.burst.scdmacodespersubframe",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "SCDMA Codes per Subframe", HFILL}
     },
    {&hf_docsis_scdma_framer_int_step_size,
     {"17 Scrambler On/Off", "docsis_type29ucd.burst.scdmaframerintstepsize",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "SCDMA Framer Interleaving Step Size", HFILL}
     },
    {&hf_docsis_tcm_enabled,
     {"18 Scrambler On/Off", "docsis_type29ucd.burst.tcmenabled",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      "TCM Enabled", HFILL}
     },
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_docsis_type29ucd,
    &ett_burst_descr,
  };

/* Register the protocol name and description */
  proto_docsis_type29ucd =
    proto_register_protocol ("DOCSIS Upstream Channel Descriptor Type 29",
			     "DOCSIS type29ucd", "docsis_type29ucd");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array (proto_docsis_type29ucd, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("docsis_type29ucd", dissect_type29ucd, proto_docsis_type29ucd);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_docsis_type29ucd (void)
{
  dissector_handle_t docsis_type29ucd_handle;

  docsis_type29ucd_handle = find_dissector ("docsis_type29ucd");
  dissector_add_uint ("docsis_mgmt", 0x1D, docsis_type29ucd_handle);

}
