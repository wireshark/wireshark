/* packet-tuxedo.c
 * Routines for BEA Tuxedo ATMI protocol
 *
 * metatech <metatech@flashmail.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

static int proto_tuxedo = -1;
static int hf_tuxedo_magic = -1;
static int hf_tuxedo_opcode = -1;

static gint ett_tuxedo = -1;

static dissector_handle_t tuxedo_handle;

#define TUXEDO_MAGIC           0x91039858
#define TUXEDO_SMAGIC          0x73903842

#define TUXEDO_ATMI_CALL                 1
#define TUXEDO_ATMI_REPLY                2
#define TUXEDO_ATMI_FAILURE              3
#define TUXEDO_ATMI_CONNECT              4
#define TUXEDO_ATMI_DATA                 5
#define TUXEDO_ATMI_DISCON               6
#define TUXEDO_ATMI_PREPARE              7
#define TUXEDO_ATMI_READY                8
#define TUXEDO_ATMI_COMMIT               9
#define TUXEDO_ATMI_DONE                10
#define TUXEDO_ATMI_COMPLETE            11
#define TUXEDO_ATMI_ROLLBACK            12
#define TUXEDO_ATMI_HEURISTIC           13
#define TUXEDO_ATMI_PRE_NW_ACALL1       14
#define TUXEDO_ATMI_PRE_NW_ACALL1_RPLY  15
#define TUXEDO_ATMI_PRE_NW_ACALL2       16
#define TUXEDO_ATMI_PRE_NW_ACALL2_RPLY  17
#define TUXEDO_ATMI_PRE_NW_ACALL3       18
#define TUXEDO_ATMI_PRE_NW_ACALL3_RPLY  19
#define TUXEDO_ATMI_PRE_NW_LLE          20
#define TUXEDO_ATMI_PRE_NW_LLE_RPLY     21
#define TUXEDO_ATMI_SEC_EXCHG_RQST      22
#define TUXEDO_ATMI_SEC_EXCHG_RPLY      23
#define TUXEDO_ATMI_SEC_NW_ACALL3       24
#define TUXEDO_ATMI_SEC_NW_ACALL3_RPLY  25


static const value_string tuxedo_opcode_vals[] = {
  { TUXEDO_ATMI_CALL,                 "CALL" },
  { TUXEDO_ATMI_REPLY,                "REPLY" },
  { TUXEDO_ATMI_FAILURE,              "FAILURE" },
  { TUXEDO_ATMI_CONNECT,              "CONNECT" },
  { TUXEDO_ATMI_DATA,                 "DATA" },
  { TUXEDO_ATMI_DISCON,               "DISCON" },
  { TUXEDO_ATMI_PREPARE,              "PREPARE" },
  { TUXEDO_ATMI_READY,                "READY" },
  { TUXEDO_ATMI_COMMIT,               "COMMIT" },
  { TUXEDO_ATMI_DONE,                 "DONE" },
  { TUXEDO_ATMI_COMPLETE,             "COMPLETE" },
  { TUXEDO_ATMI_ROLLBACK,             "ROLLBACK" },
  { TUXEDO_ATMI_HEURISTIC,            "HEURISTIC" },
  { TUXEDO_ATMI_PRE_NW_ACALL1,        "ACALL1" },
  { TUXEDO_ATMI_PRE_NW_ACALL1_RPLY,   "ACALL1_REPLY" },
  { TUXEDO_ATMI_PRE_NW_ACALL2,        "ACALL2" },
  { TUXEDO_ATMI_PRE_NW_ACALL2_RPLY,   "ACALL2_REPLY" },
  { TUXEDO_ATMI_PRE_NW_ACALL3,        "ACALL3" },
  { TUXEDO_ATMI_PRE_NW_ACALL3_RPLY,   "ACALL3_REPLY" },
  { TUXEDO_ATMI_PRE_NW_LLE,           "LLE" },
  { TUXEDO_ATMI_PRE_NW_LLE_RPLY,      "LLE_REPLY" },
  { TUXEDO_ATMI_SEC_EXCHG_RQST,       "SEC_EXCHANGE" },
  { TUXEDO_ATMI_SEC_EXCHG_RPLY,       "SEC_EXCHANGE_REPLY" },
  { TUXEDO_ATMI_SEC_NW_ACALL3,        "SEC_ACALL3" },
  { TUXEDO_ATMI_SEC_NW_ACALL3_RPLY,   "SEC_ACALL3_REPLY" },
  { 0,          NULL }
};


static void
dissect_tuxedo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*tuxedoroot_tree = NULL;
	proto_item	*ti;
	guint32 magic;
	guint32 opcode;
	
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) col_set_str(pinfo->cinfo, COL_PROTOCOL, "TUXEDO");	  	
	
	if (tvb_length(tvb) >= 8)
	{
		magic = tvb_get_ntohl(tvb, 0);
		if (magic == TUXEDO_MAGIC || magic == TUXEDO_SMAGIC)
		{
			opcode = tvb_get_ntohl(tvb, 4);

			if (check_col(pinfo->cinfo, COL_INFO)) 
			{					
				col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(opcode, tuxedo_opcode_vals, "Unknown (0x%02x)"));		
			}

			if (tree)
			{
				ti = proto_tree_add_item(tree, proto_tuxedo, tvb, 0, -1, FALSE);
				tuxedoroot_tree = proto_item_add_subtree(ti, ett_tuxedo);

				proto_tree_add_item(tuxedoroot_tree, hf_tuxedo_magic, tvb, 0, 4, FALSE);		
				proto_tree_add_item(tuxedoroot_tree, hf_tuxedo_opcode, tvb, 4, 4, FALSE);
			}
		}
		else
		{
			/* This packet is a continuation */
			if (check_col(pinfo->cinfo, COL_INFO)) col_set_str(pinfo->cinfo, COL_INFO, "Continuation");		
			if (tree)
			{
				ti = proto_tree_add_item(tree, proto_tuxedo, tvb, 0, -1, FALSE);
			}
		}
	}
}

static gboolean
dissect_tuxedo_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if (tvb_length(tvb) >= 8)
	{
		guint32 magic;
		magic = tvb_get_ntohl(tvb, 0);
		if (magic == TUXEDO_MAGIC || magic == TUXEDO_SMAGIC) 
		{
			/* Register this dissector for this conversation */
			conversation_t  *conversation = NULL;
			conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
			if (conversation == NULL) 
			{
				conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
			}
			conversation_set_dissector(conversation, tuxedo_handle);

			dissect_tuxedo(tvb, pinfo, tree);
			return TRUE;
		}
	}
	return FALSE;
}

void
proto_register_tuxedo(void)
{
  static hf_register_info hf[] = {
   { &hf_tuxedo_magic,
      { "Magic", "tuxedo.magic", FT_UINT32, BASE_HEX, NULL, 0x0, "TUXEDO magic", HFILL }},

   { &hf_tuxedo_opcode,
      { "Opcode", "tuxedo.opcode", FT_UINT32, BASE_HEX, VALS(tuxedo_opcode_vals), 0x0, "TUXEDO opcode", HFILL }}

  };
  static gint *ett[] = {
    &ett_tuxedo,
  };

  proto_tuxedo = proto_register_protocol("BEA Tuxedo", "TUXEDO", "tuxedo");
  proto_register_field_array(proto_tuxedo, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  tuxedo_handle = create_dissector_handle(dissect_tuxedo, proto_tuxedo);

}

void
proto_reg_handoff_tuxedo(void)
{
	heur_dissector_add("tcp", dissect_tuxedo_heur, proto_tuxedo);
	dissector_add_handle("tcp.port", tuxedo_handle);
}
