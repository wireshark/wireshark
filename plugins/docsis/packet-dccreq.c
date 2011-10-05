/* packet-dccreq.c
 * Routines for DCC Request Message  dissection
 * Copyright 2004, Darryl Hymel <darryl.hymel[AT]arrisi.com>
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
#include "config.h"
#endif

#include <epan/packet.h>

#define DCCREQ_UP_CHAN_ID 1
#define DCCREQ_DS_PARAMS 2
#define DCCREQ_INIT_TECH 3
#define DCCREQ_UCD_SUB 4
#define DCCREQ_SAID_SUB 6
#define DCCREQ_SF_SUB 7
#define DCCREQ_CMTS_MAC_ADDR 8
#define DCCREQ_KEY_SEQ_NUM 31
#define DCCREQ_HMAC_DIGEST 27

/* Define Downstrean Parameters subtypes
 * These are subtype of DCCREQ_DS_PARAMS (2)
 */

#define DCCREQ_DS_FREQ 1
#define DCCREQ_DS_MOD_TYPE 2
#define DCCREQ_DS_SYM_RATE 3
#define DCCREQ_DS_INTLV_DEPTH 4
#define DCCREQ_DS_CHAN_ID 5
#define DCCREQ_DS_SYNC_SUB 6

/* Define Service Flow Substitution subtypes
 * These are subtypes of DCCREQ_SF_SUB (7)
 */
#define DCCREQ_SF_SFID 1
#define DCCREQ_SF_SID 2
#define DCCREQ_SF_UNSOL_GRANT_TREF 5

/* Initialize the protocol and registered fields */
static int proto_docsis_dccreq = -1;

static int hf_docsis_dccreq_tran_id = -1;
static int hf_docsis_dccreq_up_chan_id = -1;
static int hf_docsis_dccreq_ds_freq = -1;
static int hf_docsis_dccreq_ds_mod_type = -1;
static int hf_docsis_dccreq_ds_sym_rate = -1;
static int hf_docsis_dccreq_ds_intlv_depth_i = -1;
static int hf_docsis_dccreq_ds_intlv_depth_j = -1;
static int hf_docsis_dccreq_ds_chan_id = -1;
static int hf_docsis_dccreq_ds_sync_sub = -1;
static int hf_docsis_dccreq_init_tech = -1;
static int hf_docsis_dccreq_ucd_sub = -1;
static int hf_docsis_dccreq_said_sub_cur = -1;
static int hf_docsis_dccreq_said_sub_new = -1;
static int hf_docsis_dccreq_sf_sfid_cur = -1;
static int hf_docsis_dccreq_sf_sfid_new = -1;
static int hf_docsis_dccreq_sf_sid_cur = -1;
static int hf_docsis_dccreq_sf_sid_new = -1;
static int hf_docsis_dccreq_sf_unsol_grant_tref = -1;
static int hf_docsis_dccreq_cmts_mac_addr = -1;
static int hf_docsis_dccreq_key_seq_num = -1;
static int hf_docsis_dccreq_hmac_digest = -1;

/* Initialize the subtree pointers */
static gint ett_docsis_dccreq = -1;
static gint ett_docsis_dccreq_ds_params = -1;
static gint ett_docsis_dccreq_sf_sub = -1;


value_string ds_mod_type_vals[] = {
     {0 , "64 QAM"},
     {1 , "256 QAM"},
     {0, NULL}
};

value_string ds_sym_rate_vals[] = {
     {0 , "5.056941 Msym/sec"},
     {1 , "5.360537 Msym/sec"},
     {2 , "6.952 Msym/sec"},
     {0, NULL}
};
value_string init_tech_vals[] = {
     {0 , "Reinitialize MAC"},
     {1 , "Broadcast Init RNG on new chanbefore normal op"},
     {2 , "Unicast RNG on new chan before normal op"},
     {3 , "Either Unicast or broadcast RNG on new chan before normal op"},
     {4 , "Use new chan directly without re-init or RNG"},
     {0, NULL}
};
/* Code to actually dissect the packets */
static void
dissect_dccreq_ds_params (tvbuff_t * tvb, proto_tree * tree, int start, guint16 len)
{
  guint8 type, length;
  proto_item *dcc_item;
  proto_tree *dcc_tree;
  int pos;

  pos = start;
  dcc_item = proto_tree_add_text ( tree, tvb, start, len, "2 DCC-REQ Downstream Params Encodings (Length = %u)", len);
  dcc_tree = proto_item_add_subtree ( dcc_item , ett_docsis_dccreq_ds_params);
  
  while ( pos < ( start + len) ) 
    {
	type = tvb_get_guint8 (tvb, pos++);
	length = tvb_get_guint8 (tvb, pos++);
	
	switch (type)
	  {
	    case DCCREQ_DS_FREQ:
	      if (length == 4)
		{
		  proto_tree_add_item (dcc_tree, hf_docsis_dccreq_ds_freq, tvb,
				       pos, length, FALSE);
		}
	      else
		{
		  THROW (ReportedBoundsError);
		}
	      break;
	    case DCCREQ_DS_MOD_TYPE:
	      if (length == 1)
		{
	          proto_tree_add_item (dcc_tree, hf_docsis_dccreq_ds_mod_type, tvb,
				   pos, length, FALSE);
		}
              else 
		{
		  THROW (ReportedBoundsError);
		}
	      break;
	    case DCCREQ_DS_SYM_RATE:
	      if (length == 1)
		{
	          proto_tree_add_item (dcc_tree, hf_docsis_dccreq_ds_sym_rate, tvb,
				   pos, length, FALSE);
		}
              else 
		{
		  THROW (ReportedBoundsError);
		}
	      break;
	    case DCCREQ_DS_INTLV_DEPTH:
	      if (length == 2)
		{
	          proto_tree_add_item (dcc_tree, hf_docsis_dccreq_ds_intlv_depth_i, tvb,
				   pos, 1, FALSE);
	          proto_tree_add_item (dcc_tree, hf_docsis_dccreq_ds_intlv_depth_j, tvb,
				   pos + 1, 1, FALSE);
		}
              else 
		{
		  THROW (ReportedBoundsError);
		}
	      break;
	    case DCCREQ_DS_CHAN_ID:
	      if (length == 1)
		{
	          proto_tree_add_item (dcc_tree, hf_docsis_dccreq_ds_chan_id, tvb,
				   pos, length, FALSE);
		}
              else 
		{
		  THROW (ReportedBoundsError);
		}
	      break;
	    case DCCREQ_DS_SYNC_SUB:
	          proto_tree_add_item (dcc_tree, hf_docsis_dccreq_ds_sync_sub, tvb,
				   pos, length, FALSE);
	      break;

	    }
	  pos = pos + length;
      }
}
static void
dissect_dccreq_sf_sub (tvbuff_t * tvb, proto_tree * tree, int start, guint16 len)
{
  guint8 type, length;
  proto_item *dcc_item;
  proto_tree *dcc_tree;
  int pos;
   
  pos = start;
  dcc_item = proto_tree_add_text ( tree, tvb, start, len, "7 DCC-REQ Service Flow Substitution Encodings (Length = %u)", len);
  dcc_tree = proto_item_add_subtree ( dcc_item , ett_docsis_dccreq_sf_sub);
  
  while ( pos < ( start + len) ) 
    {
	type = tvb_get_guint8 (tvb, pos++);
	length = tvb_get_guint8 (tvb, pos++);
	
	switch (type)
	  {
	    case DCCREQ_SF_SFID:
	      if (length == 8)
		{
		  proto_tree_add_item (dcc_tree, hf_docsis_dccreq_sf_sfid_cur, tvb,
				       pos, 4, FALSE);
		  proto_tree_add_item (dcc_tree, hf_docsis_dccreq_sf_sfid_new, tvb,
				       pos + 4, 4, FALSE);
		}
	      else
		{
		  THROW (ReportedBoundsError);
		}
	      break;
	    case DCCREQ_SF_SID:
	      if (length == 4)
		{
		  proto_tree_add_item (dcc_tree, hf_docsis_dccreq_sf_sid_cur, tvb,
				       pos, 2, FALSE);
		  proto_tree_add_item (dcc_tree, hf_docsis_dccreq_sf_sid_new, tvb,
				       pos + 2, 2, FALSE);
		}
	      else
		{
		  THROW (ReportedBoundsError);
		}
	      break;
	    case DCCREQ_SF_UNSOL_GRANT_TREF:
	      if (length == 4)
		{
		  proto_tree_add_item (dcc_tree, hf_docsis_dccreq_sf_unsol_grant_tref, tvb,
				       pos, length, FALSE);
		}
	      else
		{
		  THROW (ReportedBoundsError);
		}
		break;
	    }
	  pos = pos + length;
      }
}
static void
dissect_dccreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  guint16 pos;
  guint8 type, length;
  proto_tree *dcc_tree;
  proto_item *dcc_item;
  guint16 len;

  len = tvb_length_remaining (tvb, 0);

  col_set_str(pinfo->cinfo, COL_INFO, "DCC-REQ Message: ");

  if (tree)
    {
      dcc_item =
	proto_tree_add_protocol_format (tree, proto_docsis_dccreq, tvb, 0,
					tvb_length_remaining (tvb, 0),
					"DCC-REQ Message");
      dcc_tree = proto_item_add_subtree (dcc_item, ett_docsis_dccreq);
      proto_tree_add_item (dcc_tree, hf_docsis_dccreq_tran_id, tvb, 0, 2, FALSE);

      pos = 2;
      while (pos < len)
	{
	  type = tvb_get_guint8 (tvb, pos++);
	  length = tvb_get_guint8 (tvb, pos++);

	  switch (type)
	    {
	    case DCCREQ_UP_CHAN_ID:
	      if (length == 1)
		{
		  proto_tree_add_item (dcc_tree, hf_docsis_dccreq_up_chan_id, tvb,
				       pos, length, FALSE);
		}
	      else
		{
		  THROW (ReportedBoundsError);
		}
	      break;
	    case DCCREQ_DS_PARAMS:
	      dissect_dccreq_ds_params (tvb , dcc_tree , pos , length );
	      break;
	    case DCCREQ_INIT_TECH:
	      if (length == 1)
		{
		  proto_tree_add_item (dcc_tree, hf_docsis_dccreq_init_tech, tvb,
				       pos, length, FALSE);
		}
	      else
		{
		  THROW (ReportedBoundsError);
		}
	      break;
	    case DCCREQ_UCD_SUB:
		  proto_tree_add_item (dcc_tree, hf_docsis_dccreq_ucd_sub, tvb,
				       pos, length, ENC_NA);
	      break;
	    case DCCREQ_SAID_SUB:
	      if (length == 4)
		{
		  proto_tree_add_item (dcc_tree, hf_docsis_dccreq_said_sub_cur, tvb,
				       pos, 2, FALSE);
		  proto_tree_add_item (dcc_tree, hf_docsis_dccreq_said_sub_new, tvb,
				       pos + 2, 2, FALSE);
		}
	      else
		{
		  THROW (ReportedBoundsError);
		}
	      break;
	    case DCCREQ_SF_SUB:
	      dissect_dccreq_sf_sub (tvb , dcc_tree , pos , length );
	      break;
	    case DCCREQ_CMTS_MAC_ADDR:
	      if (length == 6)
		{
		  proto_tree_add_item (dcc_tree, hf_docsis_dccreq_cmts_mac_addr, tvb,
				       pos, length, FALSE);
		}
	      else
		{
		  THROW (ReportedBoundsError);
		}
	      break;
	    case DCCREQ_KEY_SEQ_NUM:
	      if (length == 1)
		{
		  proto_tree_add_item (dcc_tree, hf_docsis_dccreq_key_seq_num, tvb,
				       pos, length, FALSE);
		}
	      else
		{
		  THROW (ReportedBoundsError);
		}
	      break;
	    case DCCREQ_HMAC_DIGEST:
	      if (length == 20)
		{
		  proto_tree_add_item (dcc_tree, hf_docsis_dccreq_hmac_digest, tvb,
				       pos, length, ENC_NA);
		}
	      else
		{
		  THROW (ReportedBoundsError);
		}
	      break;
	    }			/* switch(type) */
	  pos = pos + length;
	}			/* while (pos < len) */
    }				/* if (tree) */

}
/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/


void
proto_register_docsis_dccreq (void)
{
/* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    {&hf_docsis_dccreq_tran_id ,
      {
      "Transaction ID", 
      "docsis_dccreq.tran_id",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, 
      HFILL
      }
    },
    {&hf_docsis_dccreq_up_chan_id ,
      {
      "Up Channel ID", 
      "docsis_dccreq.up_chan_id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, 
      HFILL
      }
    },
    {&hf_docsis_dccreq_ds_freq ,
      {
      "Frequency", 
      "docsis_dccreq.ds_freq",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, 
      HFILL
      }
    },
    {&hf_docsis_dccreq_ds_mod_type ,
      {
      "Modulation Type", 
      "docsis_dccreq.ds_mod_type",
      FT_UINT8, BASE_DEC, VALS (ds_mod_type_vals), 0x0,
      NULL, 
      HFILL
      }
    },
    {&hf_docsis_dccreq_ds_sym_rate ,
      {
      "Symbol Rate", 
      "docsis_dccreq.ds_sym_rate",
      FT_UINT8, BASE_DEC, VALS (ds_sym_rate_vals), 0x0,
      NULL, 
      HFILL
      }
    },
    {&hf_docsis_dccreq_ds_intlv_depth_i ,
      {
      "Interleaver Depth I Value", 
      "docsis_dccreq.ds_intlv_depth_i",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, 
      HFILL
      }
    },
    {&hf_docsis_dccreq_ds_intlv_depth_j ,
      {
      "Interleaver Depth J Value", 
      "docsis_dccreq.ds_intlv_depth_j",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, 
      HFILL
      }
    },
    {&hf_docsis_dccreq_ds_chan_id ,
      {
      "Downstream Channel ID",
      "docsis_dccreq.ds_chan_id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
      }
    },
    {&hf_docsis_dccreq_ds_sync_sub ,
      {
      "SYNC Substitution",
      "docsis_dccreq.ds_sync_sub",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
      }
    },
    {&hf_docsis_dccreq_init_tech ,
      {
      "Initialization Technique", 
      "docsis_dccreq.init_tech",
      FT_UINT8, BASE_DEC, VALS (init_tech_vals), 0x0,
      NULL, 
      HFILL
      }
    },
    {&hf_docsis_dccreq_ucd_sub ,
      {
      "UCD Substitution", 
      "docsis_dccreq.ucd_sub",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, 
      HFILL
      }
    },
    {&hf_docsis_dccreq_said_sub_cur ,
      {
      "SAID Sub - Current Value",
      "docsis_dccreq.said_sub_cur",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
      }
    },
    {&hf_docsis_dccreq_said_sub_new ,
      {
      "SAID Sub - New Value",
      "docsis_dccreq.said_sub_new",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
      }
    },
    {&hf_docsis_dccreq_sf_sfid_cur ,
      {
      "SF Sub - SFID Current Value",
      "docsis_dccreq.sf_sfid_cur",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
      }
    },
    {&hf_docsis_dccreq_sf_sfid_new ,
      {
      "SF Sub - SFID New Value",
      "docsis_dccreq.sf_sfid_new",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
      }
    },
    {&hf_docsis_dccreq_sf_sid_cur ,
      {
      "SF Sub - SID Current Value",
      "docsis_dccreq.sf_sid_cur",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
      }
    },
    {&hf_docsis_dccreq_sf_sid_new ,
      {
      "SF Sub - SID New Value",
      "docsis_dccreq.sf_sid_new",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
      }
    },
    {&hf_docsis_dccreq_sf_unsol_grant_tref ,
      {
      "SF Sub - Unsolicited Grant Time Reference",
      "docsis_dccreq.sf_unsol_grant_tref",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
      }
    },
    {&hf_docsis_dccreq_cmts_mac_addr ,
      {
      "CMTS Mac Address",
      "docsis_dccreq.cmts_mac_addr",
      FT_ETHER, BASE_NONE, NULL, 0x0,
      NULL,
      HFILL
      }
    },
    {&hf_docsis_dccreq_key_seq_num ,
      {
      "Auth Key Sequence Number",
      "docsis_dccreq.key_seq_num",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
      }
    },
    {&hf_docsis_dccreq_hmac_digest ,
      {
      "HMAC-DigestNumber",
      "docsis_dccreq.hmac_digest",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL,
      HFILL
      }
    },

  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_docsis_dccreq,
    &ett_docsis_dccreq_sf_sub,
    &ett_docsis_dccreq_ds_params,
  };

/* Register the protocol name and description */
  proto_docsis_dccreq =
    proto_register_protocol ("DOCSIS Downstream Channel Change Request",
			     "DOCSIS DCC-REQ", "docsis_dccreq");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array (proto_docsis_dccreq, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("docsis_dccreq", dissect_dccreq, proto_docsis_dccreq);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_docsis_dccreq (void)
{
  dissector_handle_t docsis_dccreq_handle;

  docsis_dccreq_handle = find_dissector ("docsis_dccreq");
  dissector_add_uint ("docsis_mgmt", 0x17, docsis_dccreq_handle);

}
