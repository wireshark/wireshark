/* packet-rngrsp.c
 * Routines for Ranging Response Message dissection
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
#include <epan/exceptions.h>

#define RNGRSP_TIMING 1
#define RNGRSP_PWR_LEVEL_ADJ 2
#define RNGRSP_OFFSET_FREQ_ADJ 3
#define RNGRSP_TRANSMIT_EQ_ADJ 4
#define RNGRSP_RANGING_STATUS 5
#define RNGRSP_DOWN_FREQ_OVER 6
#define RNGRSP_UP_CHID_OVER 7

void proto_register_docsis_rngrsp(void);
void proto_reg_handoff_docsis_rngrsp(void);

/* Initialize the protocol and registered fields */
static int proto_docsis_rngrsp = -1;
static int hf_docsis_rngrsp_upstream_chid = -1;
static int hf_docsis_rngrsp_sid = -1;
static int hf_docsis_rngrsp_timing_adj = -1;
static int hf_docsis_rngrsp_power_adj = -1;
static int hf_docsis_rngrsp_freq_adj = -1;
static int hf_docsis_rngrsp_xmit_eq_adj = -1;
static int hf_docsis_rngrsp_ranging_status = -1;
static int hf_docsis_rngrsp_down_freq_over = -1;
static int hf_docsis_rngrsp_upstream_ch_over = -1;

static const value_string rng_stat_vals[] = {
  {1, "Continue"},
  {2, "Abort"},
  {3, "Success"},
  {0, NULL}
};

/* Initialize the subtree pointers */
static gint ett_docsis_rngrsp = -1;

/* Code to actually dissect the packets */
static void
dissect_rngrsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  proto_item *it;
  proto_tree *rngrsp_tree;
  guint8 tlvtype, tlvlen;
  int pos;
  gint length;
  guint8 upchid;
  guint16 sid;
  gint8 pwr;
  gint32 tim;

  sid = tvb_get_ntohs (tvb, 0);
  upchid = tvb_get_guint8 (tvb, 2);

  if (upchid > 0)
	col_add_fstr (pinfo->cinfo, COL_INFO,
		      "Ranging Response: SID = %u, Upstream Channel = %u (U%u)",
		      sid, upchid, upchid - 1);
  else
	col_add_fstr (pinfo->cinfo, COL_INFO,
		      "Ranging Response: SID = %u, Telephony Return", sid);


  if (tree)
    {
      it =
	proto_tree_add_protocol_format (tree, proto_docsis_rngrsp, tvb, 0, -1,
					"Ranging Response");
      rngrsp_tree = proto_item_add_subtree (it, ett_docsis_rngrsp);
      proto_tree_add_item (rngrsp_tree, hf_docsis_rngrsp_sid, tvb, 0, 2,
			   ENC_BIG_ENDIAN);
      proto_tree_add_item (rngrsp_tree, hf_docsis_rngrsp_upstream_chid, tvb,
			   2, 1, ENC_BIG_ENDIAN);

      length = tvb_reported_length_remaining (tvb, 0);
      pos = 3;
      while (pos < length)
	{
	  tlvtype = tvb_get_guint8 (tvb, pos++);
	  tlvlen = tvb_get_guint8 (tvb, pos++);
	  switch (tlvtype)
	    {
	    case RNGRSP_TIMING:
	      if (tlvlen == 4)
		{
		  tim = tvb_get_ntohl (tvb, pos);
		  proto_tree_add_int (rngrsp_tree,
				      hf_docsis_rngrsp_timing_adj, tvb, pos,
				      tlvlen, tim);
		}
	      else
		{
		  THROW (ReportedBoundsError);
		}
	      break;
	    case RNGRSP_PWR_LEVEL_ADJ:
	      if (tlvlen == 1)
		{
		  pwr = tvb_get_guint8 (tvb, pos);
		  proto_tree_add_int (rngrsp_tree, hf_docsis_rngrsp_power_adj,
				      tvb, pos, tlvlen, pwr);
		}
	      else
		{
		  THROW (ReportedBoundsError);
		}
	      break;
	    case RNGRSP_OFFSET_FREQ_ADJ:
	      if (tlvlen == 2)
		{
		  proto_tree_add_item (rngrsp_tree, hf_docsis_rngrsp_freq_adj,
				       tvb, pos, tlvlen, ENC_BIG_ENDIAN);
		}
	      else
		{
		  THROW (ReportedBoundsError);
		}
	      break;
	    case RNGRSP_TRANSMIT_EQ_ADJ:
	      proto_tree_add_item (rngrsp_tree, hf_docsis_rngrsp_xmit_eq_adj,
				   tvb, pos, tlvlen, ENC_NA);
	      break;
	    case RNGRSP_RANGING_STATUS:
	      if (tlvlen == 1)
		proto_tree_add_item (rngrsp_tree,
				     hf_docsis_rngrsp_ranging_status, tvb,
				     pos, tlvlen, ENC_BIG_ENDIAN);
	      else
		{
		  THROW (ReportedBoundsError);
		}
	      break;
	    case RNGRSP_DOWN_FREQ_OVER:
	      if (tlvlen == 4)
		proto_tree_add_item (rngrsp_tree,
				     hf_docsis_rngrsp_down_freq_over, tvb,
				     pos, tlvlen, ENC_BIG_ENDIAN);
	      else
		{
		  THROW (ReportedBoundsError);
		}
	      break;
	    case RNGRSP_UP_CHID_OVER:
	      if (tlvlen == 1)
		proto_tree_add_item (rngrsp_tree,
				     hf_docsis_rngrsp_upstream_ch_over, tvb,
				     pos, tlvlen, ENC_BIG_ENDIAN);
	      else
		{
		  THROW (ReportedBoundsError);
		}
	      break;

	    }			/* switch(tlvtype) */
	  pos = pos + tlvlen;
	}			/* while (pos < length) */
    }				/* if (tree) */
}




/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/


void
proto_register_docsis_rngrsp (void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    {&hf_docsis_rngrsp_sid,
     {"Service Identifier", "docsis_rngrsp.sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_rngrsp_upstream_chid,
     {"Upstream Channel ID", "docsis_rngrsp.upchid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_rngrsp_timing_adj,
     {"Timing Adjust (6.25us/64)", "docsis_rngrsp.timingadj",
      FT_INT32, BASE_DEC, NULL, 0x0,
      "Timing Adjust", HFILL}
     },
    {&hf_docsis_rngrsp_power_adj,
     {"Power Level Adjust (0.25dB units)", "docsis_rngrsp.poweradj",
      FT_INT8, BASE_DEC, NULL, 0x0,
      "Power Level Adjust", HFILL}
     },
    {&hf_docsis_rngrsp_freq_adj,
     {"Offset Freq Adjust (Hz)", "docsis_rngrsp.freqadj",
      FT_INT16, BASE_DEC, NULL, 0x0,
      "Frequency Adjust", HFILL}
     },
    {&hf_docsis_rngrsp_xmit_eq_adj,
     {"Transmit Equalisation Adjust", "docsis_rngrsp.xmit_eq_adj",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Timing Equalisation Adjust", HFILL}
     },
    {&hf_docsis_rngrsp_ranging_status,
     {"Ranging Status", "docsis_rngrsp.rng_stat",
      FT_UINT8, BASE_DEC, VALS (rng_stat_vals), 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_rngrsp_down_freq_over,
     {"Downstream Frequency Override (Hz)", "docsis_rngrsp.freq_over",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Downstream Frequency Override", HFILL}
     },
    {&hf_docsis_rngrsp_upstream_ch_over,
     {"Upstream Channel ID Override", "docsis_rngrsp.chid_override",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },

  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_docsis_rngrsp,
  };

/* Register the protocol name and description */
  proto_docsis_rngrsp = proto_register_protocol ("DOCSIS Ranging Response",
						 "DOCSIS RNG-RSP",
						 "docsis_rngrsp");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array (proto_docsis_rngrsp, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("docsis_rngrsp", dissect_rngrsp, proto_docsis_rngrsp);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_docsis_rngrsp (void)
{
  dissector_handle_t docsis_rngrsp_handle;

  docsis_rngrsp_handle = find_dissector ("docsis_rngrsp");
  dissector_add_uint ("docsis_mgmt", 0x05, docsis_rngrsp_handle);

}
