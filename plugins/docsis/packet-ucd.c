/* packet-ucd.c
 * Routines for UCD Message dissection
 * Copyright 2002, Anand V. Narwani <anand[AT]narwani.org>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "moduleinfo.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gmodule.h>

#include <epan/packet.h>

#define UCD_SYMBOL_RATE 1
#define UCD_FREQUENCY 2
#define UCD_PREAMBLE 3
#define UCD_BURST_DESCR 4
#define UCD_BURST_DESCR5 5

#define UCD_MODULATION 1
#define UCD_DIFF_ENCODING 2
#define UCD_PREAMBLE_LEN 3
#define UCD_PREAMBLE_VAL_OFF 4
#define UCD_FEC 5
#define UCD_FEC_CODEWORD 6
#define UCD_SCRAMBLER_SEED 7
#define UCD_MAX_BURST 8
#define UCD_GUARD_TIME 9
#define UCD_LAST_CW_LEN 10
#define UCD_SCRAMBLER_ONOFF 11
#define UCD_RS_INT_DEPTH 12
#define UCD_RS_INT_BLOCK 13
#define UCD_PREAMBLE_TYPE 14
#define UCD_SCMDA_SCRAMBLER_ONOFF 15
#define UCD_SCDMA_CODES_PER_SUBFRAME 16
#define UCD_SCDMA_FRAMER_INT_STEP_SIZE 17
#define UCD_TCM_ENABLED 18

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
static int proto_docsis_ucd = -1;

static int hf_docsis_ucd_upstream_chid = -1;
static int hf_docsis_ucd_config_ch_cnt = -1;
static int hf_docsis_ucd_mini_slot_size = -1;
static int hf_docsis_ucd_down_chid = -1;
static int hf_docsis_ucd_type = -1;
static int hf_docsis_ucd_length = -1;
static int hf_docsis_ucd_symbol_rate = -1;
static int hf_docsis_ucd_frequency = -1;
static int hf_docsis_ucd_preamble_pat = -1;
static int hf_docsis_ucd_iuc = -1;

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
static gint ett_docsis_ucd = -1;
static gint ett_tlv = -1;

static const value_string channel_tlv_vals[] = {
     {UCD_SYMBOL_RATE, "Symbol Rate"},
     {UCD_FREQUENCY, "Frequency"},
     {UCD_PREAMBLE, "Preamble Pattern"},
     {UCD_BURST_DESCR, "Burst Descriptor"},
     {UCD_BURST_DESCR5, "Burst Descriptor DOCSIS 2.0"},
     {0, NULL}
};

static const value_string on_off_vals[] = {
     {1, "On"},
     {2, "Off"},
     {0, NULL}
};

static const value_string mod_vals[] = {
     {1, "QPSK"},
     {2, "QAM16"},
     {0, NULL}
};

value_string iuc_vals[] = {
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
     {IUC_RESERVED12, "Reserved"},
     {IUC_RESERVED13, "Reserved"},
     {IUC_RESERVED14, "Reserved"},
     {IUC_EXPANSION, "Expanded IUC"},
     {0, NULL}
   
};

static const value_string last_cw_len_vals[] = {
     {1, "Fixed"},
     {2, "Shortened"},
     {0, NULL}
};
/* Code to actually dissect the packets */
static void
  dissect_ucd (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  int pos, endtlvpos;
  guint8 type, length;
  guint8 tlvlen, tlvtype;
  proto_tree *ucd_tree;
  proto_item *ucd_item;
  proto_tree *tlv_tree;
  proto_item *tlv_item;
  gint len;
  guint8 upchid, symrate;
   
  len = tvb_reported_length_remaining (tvb, 0);
   upchid = tvb_get_guint8 (tvb, 0);
   
   /* if the upstream Channel ID is 0 then this is for Telephony Return) */
   if (check_col (pinfo->cinfo, COL_INFO))
     {
	col_clear (pinfo->cinfo, COL_INFO);
	if (upchid > 0)
	  col_add_fstr (pinfo->cinfo, COL_INFO,
			"UCD Message:  Channel ID = %u (U%u)", upchid,
			upchid - 1);
	else
	  col_add_fstr (pinfo->cinfo, COL_INFO,
			"UCD Message:  Channel ID = %u (Telephony Return)",
			upchid);
     }
   
   if (tree)
     {
	ucd_item =
	proto_tree_add_protocol_format (tree, proto_docsis_ucd, tvb, 0, -1,
					"UCD Message");
	ucd_tree = proto_item_add_subtree (ucd_item, ett_docsis_ucd);
	proto_tree_add_item (ucd_tree, hf_docsis_ucd_upstream_chid, tvb, 0, 1,
			     FALSE);
	proto_tree_add_item (ucd_tree, hf_docsis_ucd_config_ch_cnt, tvb, 1, 1,
			     FALSE);
	proto_tree_add_item (ucd_tree, hf_docsis_ucd_mini_slot_size, tvb, 2, 1,
			     FALSE);
	proto_tree_add_item (ucd_tree, hf_docsis_ucd_down_chid, tvb, 3, 1,
			     FALSE);
	
	pos = 4;
	while (pos < len)
	  {
	  type = tvb_get_guint8 (tvb, pos);
	  tlv_item = proto_tree_add_text (ucd_tree, tvb, pos, -1,
					  "%s",
					  val_to_str(type, channel_tlv_vals,
						     "Unknown TLV (%u)"));  
	  tlv_tree = proto_item_add_subtree (tlv_item, ett_tlv);
	  proto_tree_add_uint (tlv_tree, hf_docsis_ucd_type,
			       tvb, pos, 1, type);
	  pos++;
	  length = tvb_get_guint8 (tvb, pos);
	  proto_tree_add_uint (tlv_tree, hf_docsis_ucd_length,
			       tvb, pos, 1, length);
	  pos++;
	  proto_item_set_len(tlv_item, length + 2);
	     switch (type)
	       {
		case UCD_SYMBOL_RATE:
		  if (length == 1)
		    {
		       symrate = tvb_get_guint8 (tvb, pos);
		       proto_tree_add_uint (tlv_tree, hf_docsis_ucd_symbol_rate,
					    tvb, pos, length, symrate * 160);
		    }
		  else
		    {
		       THROW (ReportedBoundsError);
		    }
		  pos = pos + length;
		  break;
		case UCD_FREQUENCY:
		  if (length == 4)
		    {
		       proto_tree_add_item (tlv_tree, hf_docsis_ucd_frequency, tvb,
					    pos, length, FALSE);
		       pos = pos + length;
		    }
		  else
		    {
		       THROW (ReportedBoundsError);
		    }
		  break;
		case UCD_PREAMBLE:
		  proto_tree_add_item (tlv_tree, hf_docsis_ucd_preamble_pat, tvb,
				       pos, length, FALSE);
		  pos = pos + length;
		  break;
		case UCD_BURST_DESCR:
		  proto_tree_add_item (tlv_tree, hf_docsis_ucd_iuc, tvb,
				       pos++, 1, FALSE);
		  endtlvpos = pos + length - 1;
		  while (pos < endtlvpos)
		    {
		       tlvtype = tvb_get_guint8 (tvb, pos++);
		       tlvlen = tvb_get_guint8 (tvb, pos++);
		       switch (tlvtype)
			 {
			  case UCD_MODULATION:
			    if (tlvlen == 1)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_burst_mod_type, tvb,
						      pos, tlvlen, FALSE);
			      }
			    else
			      {
				 THROW (ReportedBoundsError);
			      }
			    break;
			  case UCD_DIFF_ENCODING:
			    if (tlvlen == 1)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_burst_diff_encoding,
						      tvb, pos, tlvlen, FALSE);
			      }
			    else
			      {
				 THROW (ReportedBoundsError);
			      }
			    break;
			  case UCD_PREAMBLE_LEN:
			    if (tlvlen == 2)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_burst_preamble_len,
						      tvb, pos, tlvlen, FALSE);
			      }
			    else
			      {
				 THROW (ReportedBoundsError);
			      }
			    break;
			  case UCD_PREAMBLE_VAL_OFF:
			    if (tlvlen == 2)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_burst_preamble_val_off,
						      tvb, pos, tlvlen, FALSE);
			      }
			    else
			      {
				 THROW (ReportedBoundsError);
			      }
			    break;
			  case UCD_FEC:
			    if (tlvlen == 1)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_burst_fec, tvb, pos,
						      tlvlen, FALSE);
			      }
			    else
			      {
				 THROW (ReportedBoundsError);
			      }
			    break;
			  case UCD_FEC_CODEWORD:
			    if (tlvlen == 1)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_burst_fec_codeword,
						      tvb, pos, tlvlen, FALSE);
			      }
			    else
			      {
				 THROW (ReportedBoundsError);
			      }
			    break;
			  case UCD_SCRAMBLER_SEED:
			    if (tlvlen == 2)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_burst_scrambler_seed,
						      tvb, pos, tlvlen, FALSE);
			      }
			    else
			      {
				 THROW (ReportedBoundsError);
			      }
			    break;
			  case UCD_MAX_BURST:
			    if (tlvlen == 1)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_burst_max_burst, tvb,
						      pos, tlvlen, FALSE);
			      }
			    else
			      {
				 THROW (ReportedBoundsError);
			      }
			    break;
			  case UCD_GUARD_TIME:
			    if (tlvlen == 1)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_burst_guard_time,
						      tvb, pos, tlvlen, FALSE);
			      }
			    else
			      {
				 THROW (ReportedBoundsError);
			      }
			    break;
			  case UCD_LAST_CW_LEN:
			    if (tlvlen == 1)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_burst_last_cw_len,
						      tvb, pos, tlvlen, FALSE);
			      }
			    else
			      {
				 THROW (ReportedBoundsError);
			      }
			    break;
			  case UCD_SCRAMBLER_ONOFF:
			    if (tlvlen == 1)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_burst_scrambler_onoff,
						      tvb, pos, tlvlen, FALSE);
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
		case UCD_BURST_DESCR5:
		  /* DOCSIS 2.0 Upstream Channel Descriptor */
		  proto_tree_add_item (tlv_tree, hf_docsis_ucd_iuc, tvb,
				       pos++, 1, FALSE);
		  endtlvpos = pos + length - 1;
		  while (pos < endtlvpos)
		    {
		       tlvtype = tvb_get_guint8 (tvb, pos++);
		       tlvlen = tvb_get_guint8 (tvb, pos++);
		       switch (tlvtype)
			 {
			  case UCD_MODULATION:
			    if (tlvlen == 1)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_burst_mod_type, tvb,
						      pos, tlvlen, FALSE);
			      }
			    else
			      {
				 THROW (ReportedBoundsError);
			      }
			    break;
			  case UCD_DIFF_ENCODING:
			    if (tlvlen == 1)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_burst_diff_encoding,
						      tvb, pos, tlvlen, FALSE);
			      }
			    else
			      {
				 THROW (ReportedBoundsError);
			      }
			    break;
			  case UCD_PREAMBLE_LEN:
			    if (tlvlen == 2)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_burst_preamble_len,
						      tvb, pos, tlvlen, FALSE);
			      }
			    else
			      {
				 THROW (ReportedBoundsError);
			      }
			    break;
			  case UCD_PREAMBLE_VAL_OFF:
			    if (tlvlen == 2)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_burst_preamble_val_off,
						      tvb, pos, tlvlen, FALSE);
			      }
			    else
			      {
				 THROW (ReportedBoundsError);
			      }
			    break;
			  case UCD_FEC:
			    if (tlvlen == 1)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_burst_fec, tvb, pos,
						      tlvlen, FALSE);
			      }
			    else
			      {
				 THROW (ReportedBoundsError);
			      }
			    break;
			  case UCD_FEC_CODEWORD:
			    if (tlvlen == 1)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_burst_fec_codeword,
						      tvb, pos, tlvlen, FALSE);
			      }
			    else
			      {
				 THROW (ReportedBoundsError);
			      }
			    break;
			  case UCD_SCRAMBLER_SEED:
			    if (tlvlen == 2)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_burst_scrambler_seed,
						      tvb, pos, tlvlen, FALSE);
			      }
			    else
			      {
				 THROW (ReportedBoundsError);
			      }
			    break;
			  case UCD_MAX_BURST:
			    if (tlvlen == 1)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_burst_max_burst, tvb,
						      pos, tlvlen, FALSE);
			      }
			    else
			      {
				 THROW (ReportedBoundsError);
			      }
			    break;
			  case UCD_GUARD_TIME:
			    if (tlvlen == 1)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_burst_guard_time,
						      tvb, pos, tlvlen, FALSE);
			      }
			    else
			      {
				 THROW (ReportedBoundsError);
			      }
			    break;
			  case UCD_LAST_CW_LEN:
			    if (tlvlen == 1)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_burst_last_cw_len,
						      tvb, pos, tlvlen, FALSE);
			      }
			    else
			      {
				 THROW (ReportedBoundsError);
			      }
			    break;
			  case UCD_SCRAMBLER_ONOFF:
			    if (tlvlen == 1)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_burst_scrambler_onoff,
						      tvb, pos, tlvlen, FALSE);
			      }
			    else
			      {
				 THROW (ReportedBoundsError);
			      }
			    break;
			    /* New cases added for DOCSIS 2.0 US Physical Burst Descriptor TLV */
			    /* #define UCD_RS_INT_DEPTH 12
			     *  * #define UCD_RS_INT_BLOCK 13
			     *  * #define UCD_PREAMBLE_TYPE 14
			     *  * #define UCD_SCMDA_SCRAMBLER_ONOFF 15
			     *  * #define UCD_SCDMA_CODES_PER_SUBFRAME 16
			     *  * #define UCD_SCDMA_FRAMER_INT_STEP_SIZE 17
			     *  * #define UCD_TCM_ENABLED 18
			     *  */
			  case UCD_RS_INT_DEPTH:
			    if (tlvlen == 1)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_rs_int_depth,
						      tvb, pos, tlvlen, FALSE);
			      }
			    else
			      {
				 THROW (ReportedBoundsError);
			      }
			    break;
			  case UCD_RS_INT_BLOCK:
			    if (tlvlen == 2)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_rs_int_block,
						      tvb, pos, tlvlen, FALSE);
			      }
			    else
			      {
				 THROW (ReportedBoundsError);
			      }
			    break;
			  case UCD_PREAMBLE_TYPE:
			    if (tlvlen == 1)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_preamble_type,
						      tvb, pos, tlvlen, FALSE);
			      }
			    else
			      {
				 THROW (ReportedBoundsError);
			      }
			    break;
			  case UCD_SCMDA_SCRAMBLER_ONOFF:
			    if (tlvlen == 1)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_scdma_scrambler_onoff,
						      tvb, pos, tlvlen, FALSE);
			      }
			    else
			      {
				 THROW (ReportedBoundsError);
			      }
			    break;
			  case UCD_SCDMA_CODES_PER_SUBFRAME:
			    if (tlvlen == 1)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_scdma_codes_per_subframe,
						      tvb, pos, tlvlen, FALSE);
			      }
			    else
			      {
				 THROW (ReportedBoundsError);
			      }
			    break;
			  case UCD_SCDMA_FRAMER_INT_STEP_SIZE:
			    if (tlvlen == 1)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_scdma_framer_int_step_size,
						      tvb, pos, tlvlen, FALSE);
			      }
			    else
			      {
				 THROW (ReportedBoundsError);
			      }
			    break;
			  case UCD_TCM_ENABLED:
			    if (tlvlen == 1)
			      {
				 proto_tree_add_item (tlv_tree,
						      hf_docsis_tcm_enabled,
						      tvb, pos, tlvlen, FALSE);
			      }
			    else
			      {
				 THROW (ReportedBoundsError);
			      }
			    break;
			 }           /* switch(tlvtype) */
		       pos = pos + tlvlen;
		    }               /* while (pos < endtlvpos) */
		  break;
	       }                   /* switch(type) */
	  }                       /* while (pos < len) */
     }                           /* if (tree) */
   
}

/* Register the protocol with Ethereal */

/* this format is require because a script is used to build the C function
 that calls all the protocol registration.
 */


void
proto_register_docsis_ucd (void)
{
   
   /* Setup list of header fields  See Section 1.6.1 for details*/
   static hf_register_info hf[] = {
    {&hf_docsis_ucd_upstream_chid,
     {"Upstream Channel ID", "docsis.ucd.upchid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Upstream Channel ID", HFILL}
     },
    {&hf_docsis_ucd_config_ch_cnt,
     {"Config Change Count", "docsis.ucd.confcngcnt",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Configuration Change Count", HFILL}
     },
    {&hf_docsis_ucd_mini_slot_size,
     {"Mini Slot Size (6.25us TimeTicks)", "docsis.ucd.mslotsize",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Mini Slot Size (6.25us TimeTicks)", HFILL}
     },
    {&hf_docsis_ucd_down_chid,
     {"Downstream Channel ID", "docsis.ucd.downchid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Management Message", HFILL}
     },
    {&hf_docsis_ucd_type,
     {"TLV Type", "docsis.ucd.type",
      FT_UINT8, BASE_DEC, VALS(channel_tlv_vals), 0x0,
      "Channel TLV type", HFILL}
     },
    {&hf_docsis_ucd_length,
     {"TLV Length", "docsis.ucd.length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Channel TLV length", HFILL}
     },
    {&hf_docsis_ucd_symbol_rate,
     {"Symbol Rate (ksym/sec)", "docsis.ucd.symrate",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Symbol Rate", HFILL}
     },
    {&hf_docsis_ucd_frequency,
     {"Frequency (Hz)", "docsis.ucd.freq",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Upstream Center Frequency", HFILL}
     },
    {&hf_docsis_ucd_preamble_pat,
     {"Preamble Pattern", "docsis.ucd.preamble",
      FT_BYTES, BASE_HEX, NULL, 0x0,
      "Preamble Superstring", HFILL}
     },
    {&hf_docsis_ucd_iuc,
     {"Interval Usage Code", "docsis.ucd.iuc",
      FT_UINT8, BASE_DEC, VALS (iuc_vals), 0x0,
      "Interval Usage Code", HFILL}
     },
    {&hf_docsis_burst_mod_type,
     {"1 Modulation Type", "docsis.ucd.burst.modtype",
      FT_UINT8, BASE_DEC, VALS (mod_vals), 0x0,
      "Modulation Type", HFILL}
     },
    {&hf_docsis_burst_diff_encoding,
     {"2 Differential Encoding", "docsis.ucd.burst.diffenc",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      "Differential Encoding", HFILL}
     },
    {&hf_docsis_burst_preamble_len,
     {"3 Preamble Length (Bits)", "docsis.ucd.burst.preamble_len",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Preamble Length (Bits)", HFILL}
     },
    {&hf_docsis_burst_preamble_val_off,
     {"4 Preamble Offset (Bits)", "docsis.ucd.burst.preamble_off",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Preamble Offset (Bits)", HFILL}
     },
    {&hf_docsis_burst_fec,
     {"5 FEC (T)", "docsis.ucd.burst.fec",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "FEC (T) Codeword Parity Bits = 2^T", HFILL}
     },
    {&hf_docsis_burst_fec_codeword,
     {"6 FEC Codeword Info bytes (k)", "docsis.ucd.burst.fec_codeword",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "FEC Codeword Info Bytes (k)", HFILL}
     },
    {&hf_docsis_burst_scrambler_seed,
     {"7 Scrambler Seed", "docsis.ucd.burst.scrambler_seed",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "Burst Descriptor", HFILL}
     },
    {&hf_docsis_burst_max_burst,
     {"8 Max Burst Size (Minislots)", "docsis.ucd.burst.maxburst",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Max Burst Size (Minislots)", HFILL}
     },
    {&hf_docsis_burst_guard_time,
     {"9 Guard Time Size (Symbol Times)", "docsis.ucd.burst.guardtime",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Guard Time Size", HFILL}
     },
    {&hf_docsis_burst_last_cw_len,
     {"10 Last Codeword Length", "docsis.ucd.burst.last_cw_len",
      FT_UINT8, BASE_DEC, VALS (last_cw_len_vals), 0x0,
      "Last Codeword Length", HFILL}
     },
    {&hf_docsis_burst_scrambler_onoff,
     {"11 Scrambler On/Off", "docsis.ucd.burst.scrambleronoff",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      "Scrambler On/Off", HFILL}
     },
    {&hf_docsis_rs_int_depth,
     {"12 RS Interleaver Depth", "docsis.ucd.burst.rsintdepth",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "R-S Interleaver Depth", HFILL}
    },
    {&hf_docsis_rs_int_block,
     {"13 RS Interleaver Block Size", "docsis.ucd.burst.rsintblock",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "R-S Interleaver Block", HFILL}
    },
    {&hf_docsis_preamble_type,
     {"14 Preamble Type", "docsis.ucd.burst.preambletype",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Preamble Type", HFILL}
    },
    {&hf_docsis_scdma_scrambler_onoff,
     {"15 SCDMA Scrambler On/Off", "docsis.ucd.burst.scdmascrambleronoff",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      "SCDMA Scrambler On/Off", HFILL}
    },
    {&hf_docsis_scdma_codes_per_subframe,
     {"16 SCDMA Codes per Subframe", "docsis.ucd.burst.scdmacodespersubframe",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "SCDMA Codes per Subframe", HFILL}
    },
    {&hf_docsis_scdma_framer_int_step_size,
     {"17 SDMA Framer Int Step Size", "docsis.ucd.burst.scdmaframerintstepsize",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "SCDMA Framer Interleaving Step Size", HFILL}
    },
    {&hf_docsis_tcm_enabled,
     {"18 TCM Enable", "docsis.ucd.burst.tcmenabled",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      "TCM Enabled", HFILL}
    },
   };
   
   /* Setup protocol subtree array */
   static gint *ett[] = {
      &ett_docsis_ucd,
	&ett_tlv,
   };
   
   /* Register the protocol name and description */
   proto_docsis_ucd =
     proto_register_protocol ("DOCSIS Upstream Channel Descriptor",
			      "DOCSIS UCD", "docsis_ucd");
   
   /* Required function calls to register the header fields and subtrees used */
   proto_register_field_array (proto_docsis_ucd, hf, array_length (hf));
   proto_register_subtree_array (ett, array_length (ett));
   
   register_dissector ("docsis_ucd", dissect_ucd, proto_docsis_ucd);
}


/* If this dissector uses sub-dissector registration add a registration routine.
 This format is required because a script is used to find these routines and
 create the code that calls these routines.
 */
void
proto_reg_handoff_docsis_ucd (void)
{
   dissector_handle_t docsis_ucd_handle;
   
   docsis_ucd_handle = find_dissector ("docsis_ucd");
   dissector_add ("docsis_mgmt", 0x02, docsis_ucd_handle);
   
}
