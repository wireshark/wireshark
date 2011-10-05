/* packet-dccack.c
 * Routines for DCC Acknowledge Message  dissection
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

#define DCCACK_KEY_SEQ_NUM 31
#define DCCACK_HMAC_DIGEST 27

/* Initialize the protocol and registered fields */
static int proto_docsis_dccack = -1;

static int hf_docsis_dccack_tran_id = -1;
static int hf_docsis_dccack_key_seq_num = -1;
static int hf_docsis_dccack_hmac_digest = -1;

/* Initialize the subtree pointers */
static gint ett_docsis_dccack = -1;


/* Code to actually dissect the packets */
static void
dissect_dccack (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  guint16 pos;
  guint8 type, length;
  proto_tree *dcc_tree;
  proto_item *dcc_item;
  guint16 len;

  len = tvb_length_remaining (tvb, 0);

  col_set_str(pinfo->cinfo, COL_INFO, "DCC-ACK Message: ");

  if (tree)
    {
      dcc_item =
	proto_tree_add_protocol_format (tree, proto_docsis_dccack, tvb, 0,
					tvb_length_remaining (tvb, 0),
					"DCC-ACK Message");
      dcc_tree = proto_item_add_subtree (dcc_item, ett_docsis_dccack);
      proto_tree_add_item (dcc_tree, hf_docsis_dccack_tran_id, tvb, 0, 2, FALSE);

      pos = 2;
      while (pos < len)
	{
	  type = tvb_get_guint8 (tvb, pos++);
	  length = tvb_get_guint8 (tvb, pos++);
	  switch (type)
	    {
	    case DCCACK_KEY_SEQ_NUM:
	      if (length == 1)
		{
		  proto_tree_add_item (dcc_tree, hf_docsis_dccack_key_seq_num, tvb,
				       pos, length, FALSE);
		}
	      else
		{
		  THROW (ReportedBoundsError);
		}
	      break;
	    case DCCACK_HMAC_DIGEST:
	      if (length == 20)
		{
		  proto_tree_add_item (dcc_tree, hf_docsis_dccack_hmac_digest, tvb,
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
proto_register_docsis_dccack (void)
{
/* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
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

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_docsis_dccack,
  };

/* Register the protocol name and description */
  proto_docsis_dccack =
    proto_register_protocol ("DOCSIS Downstream Channel Change Acknowledge",
			     "DOCSIS DCC-ACK", "docsis_dccack");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array (proto_docsis_dccack, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("docsis_dccack", dissect_dccack, proto_docsis_dccack);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_docsis_dccack (void)
{
  dissector_handle_t docsis_dccack_handle;

  docsis_dccack_handle = find_dissector ("docsis_dccack");
  dissector_add_uint ("docsis_mgmt", 0x19, docsis_dccack_handle);

}
