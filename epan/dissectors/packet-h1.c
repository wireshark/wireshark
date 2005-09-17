/* packet-h1.c
 * Routines for Sinec H1 packet disassembly
 * Gerrit Gehnen <G.Gehnen@atrie.de>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include <string.h>

#include <glib.h>
#include <epan/packet.h>

static int proto_h1 = -1;
static int hf_h1_header = -1;
static int hf_h1_len = -1;
static int hf_h1_opfield = -1;
static int hf_h1_oplen = -1;
static int hf_h1_opcode = -1;
static int hf_h1_requestblock = -1;
static int hf_h1_requestlen = -1;
static int hf_h1_dbnr = -1;
static int hf_h1_dwnr = -1;
static int hf_h1_dlen = -1;
static int hf_h1_org = -1;
static int hf_h1_response = -1;
static int hf_h1_response_len = -1;
static int hf_h1_response_value = -1;
static int hf_h1_empty_len = -1;
static int hf_h1_empty = -1;

static dissector_handle_t data_handle;

#define EMPTY_BLOCK 	0xFF
#define OPCODE_BLOCK	0x01
#define REQUEST_BLOCK	0x03
#define RESPONSE_BLOCK	0x0F

static const value_string opcode_vals[] = {
  {3, "Write Request"},
  {4, "Write Response"},
  {5, "Read Request"},
  {6, "Read Response"},
  {0, NULL}
};

static const value_string org_vals[] = {
  {0x01, "DB"},
  {0x02, "MB"},
  {0x03, "EB"},
  {0x04, "AB"},
  {0x05, "PB"},
  {0x06, "ZB"},
  {0x07, "TB"},
  {0x08, "BS"},
  {0x09, "AS"},
  {0x0a, "DX"},
  {0x10, "DE"},
  {0x11, "QB"},
  {0, NULL}
};

static const value_string returncode_vals[] = {
  {0x00, "No error"},
  {0x02, "Requested block does not exist"},
  {0x03, "Requested block too small"},
  {0xFF, "Error, reason unknown"},
  {0, NULL}
};

static gint ett_h1 = -1;
static gint ett_opcode = -1;
static gint ett_org = -1;
static gint ett_response = -1;
static gint ett_empty = -1;

static gboolean dissect_h1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tvbuff_t *next_tvb;

  proto_tree *h1_tree = NULL;

  proto_item *ti;
  proto_tree *opcode_tree = NULL;
  proto_tree *org_tree = NULL;
  proto_tree *response_tree = NULL;
  proto_tree *empty_tree = NULL;

  unsigned int position = 3;
  unsigned int offset=0;

  if (tvb_length_remaining(tvb, 0) < 2)
    {
      /* Not enough data captured to hold the "S5" header; don't try
         to interpret it as H1. */
      return FALSE;
    }

  if (!(tvb_get_guint8(tvb,offset) == 'S' && tvb_get_guint8(tvb,offset+1) == '5'))
    {
      return FALSE;
    }

  if (check_col (pinfo->cinfo, COL_PROTOCOL))
    col_set_str (pinfo->cinfo, COL_PROTOCOL, "H1");
  if (check_col (pinfo->cinfo, COL_INFO))
    col_add_str (pinfo->cinfo, COL_INFO, "S5: ");
  if (tree)
    {
      ti = proto_tree_add_item (tree, proto_h1, tvb, offset, 16, FALSE);
      h1_tree = proto_item_add_subtree (ti, ett_h1);
      proto_tree_add_uint (h1_tree, hf_h1_header, tvb, offset, 2,
			   tvb_get_ntohs(tvb,offset));
      proto_tree_add_uint (h1_tree, hf_h1_len, tvb, offset + 2, 1,
			   tvb_get_guint8(tvb,offset+2));
    }

  while (position < tvb_get_guint8(tvb,offset+2))
    {
      switch (tvb_get_guint8(tvb,offset + position))
	{
	  case OPCODE_BLOCK:
	    if (h1_tree)
	      {
		ti = proto_tree_add_uint (h1_tree, hf_h1_opfield, tvb,
					  offset + position,
					  tvb_get_guint8(tvb,offset+position+1),
					  tvb_get_guint8(tvb,offset+position));
		opcode_tree = proto_item_add_subtree (ti, ett_opcode);
		proto_tree_add_uint (opcode_tree, hf_h1_oplen, tvb,
				     offset + position + 1, 1,
				     tvb_get_guint8(tvb,offset + position + 1));
		proto_tree_add_uint (opcode_tree, hf_h1_opcode, tvb,
				     offset + position + 2, 1,
				     tvb_get_guint8(tvb,offset + position + 2));
	      }
	    if (check_col (pinfo->cinfo, COL_INFO))
	      {
		col_append_str (pinfo->cinfo, COL_INFO,
				val_to_str (tvb_get_guint8(tvb,offset + position + 2),
					    opcode_vals,"Unknown Opcode (0x%2.2x)"));
	      }
	    break;
	  case REQUEST_BLOCK:
	    if (h1_tree)
	      {
		ti = proto_tree_add_uint (h1_tree, hf_h1_requestblock, tvb,
					  offset + position,
					  tvb_get_guint8(tvb,offset + position + 1),
					  tvb_get_guint8(tvb,offset + position));
		org_tree = proto_item_add_subtree (ti, ett_org);
		proto_tree_add_uint (org_tree, hf_h1_requestlen, tvb,
				     offset + position + 1, 1,
				     tvb_get_guint8(tvb,offset + position+1));
		proto_tree_add_uint (org_tree, hf_h1_org, tvb,
				     offset + position + 2, 1,
				     tvb_get_guint8(tvb,offset + position+2));
		proto_tree_add_uint (org_tree, hf_h1_dbnr, tvb,
				     offset + position + 3, 1,
				     tvb_get_guint8(tvb,offset + position+3));
		proto_tree_add_uint (org_tree, hf_h1_dwnr, tvb,
				     offset + position + 4, 2,
				     tvb_get_ntohs(tvb,offset+position+4));
		proto_tree_add_int (org_tree, hf_h1_dlen, tvb,
				    offset + position + 6, 2,
				    tvb_get_ntohs(tvb,offset+position+6));
	      }
	    if (check_col (pinfo->cinfo, COL_INFO))
	      {
		col_append_fstr (pinfo->cinfo, COL_INFO, " %s %d",
				 val_to_str (tvb_get_guint8(tvb,offset + position + 2),
					     org_vals,"Unknown Type (0x%2.2x)"),
				 tvb_get_guint8(tvb,offset + position + 3));
		col_append_fstr (pinfo->cinfo, COL_INFO, " DW %d",
				 tvb_get_ntohs(tvb,offset+position+4));
		col_append_fstr (pinfo->cinfo, COL_INFO, " Count %d",
				 tvb_get_ntohs(tvb,offset+position+6));
	      }
	    break;
	  case RESPONSE_BLOCK:
	    if (h1_tree)
	      {
		ti = proto_tree_add_uint (h1_tree, hf_h1_response, tvb,
					  offset + position,
					  tvb_get_guint8(tvb,offset + position + 1),
					  tvb_get_guint8(tvb,offset + position));
		response_tree = proto_item_add_subtree (ti, ett_response);
		proto_tree_add_uint (response_tree, hf_h1_response_len, tvb,
				     offset + position + 1, 1,
				     tvb_get_guint8(tvb,offset + position+1));
		proto_tree_add_uint (response_tree, hf_h1_response_value, tvb,
				     offset + position + 2, 1,
				     tvb_get_guint8(tvb,offset + position+2));
	      }
	    if (check_col (pinfo->cinfo, COL_INFO))
	      {
		col_append_fstr (pinfo->cinfo, COL_INFO, " %s",
				 val_to_str (tvb_get_guint8(tvb,offset + position + 2),
					     returncode_vals,"Unknown Returcode (0x%2.2x"));
	      }
	    break;
	  case EMPTY_BLOCK:
	    if (h1_tree)
	      {
		ti = proto_tree_add_uint (h1_tree, hf_h1_empty, tvb,
					  offset + position,
					  tvb_get_guint8(tvb,offset + position + 1),
					  tvb_get_guint8(tvb,offset + position));
		empty_tree = proto_item_add_subtree (ti, ett_empty);

		proto_tree_add_uint (empty_tree, hf_h1_empty_len, tvb,
				     offset + position + 1, 1,
				     tvb_get_guint8(tvb,offset + position+1));
	      }
	    break;
	  default:
	    /* This is not a valid telegram. So cancel dissection
               and try the next dissector */
            return FALSE;
	    break;
	}
	if (tvb_get_guint8(tvb,offset + position + 1) < 1)
	    THROW(ReportedBoundsError);
	position += tvb_get_guint8(tvb,offset + position + 1);	/* Goto next section */
    }			/* ..while */
  next_tvb = tvb_new_subset(tvb, offset+tvb_get_guint8(tvb,offset+2), -1, -1);
  call_dissector(data_handle,next_tvb, pinfo, tree);

  return TRUE;
}


void
proto_register_h1 (void)
{
  static hf_register_info hf[] = {
    {&hf_h1_header,
     {"H1-Header", "h1.header", FT_UINT16, BASE_HEX, NULL, 0x0,
      "", HFILL }},
    {&hf_h1_len,
     {"Length indicator", "h1.len", FT_UINT16, BASE_DEC, NULL, 0x0,
      "", HFILL }},
    {&hf_h1_opfield,
     {"Operation identifier", "h1.opfield", FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }},
    {&hf_h1_oplen,
     {"Operation length", "h1.oplen", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
    {&hf_h1_opcode,
     {"Opcode", "h1.opcode", FT_UINT8, BASE_HEX, VALS (opcode_vals), 0x0,
      "", HFILL }},
    {&hf_h1_requestblock,
     {"Request identifier", "h1.request", FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }},
    {&hf_h1_requestlen,
     {"Request length", "h1.reqlen", FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }},
    {&hf_h1_org,
     {"Memory type", "h1.org", FT_UINT8, BASE_HEX, VALS (org_vals), 0x0,
      "", HFILL }},
    {&hf_h1_dbnr,
     {"Memory block number", "h1.dbnr", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
    {&hf_h1_dwnr,
     {"Address within memory block", "h1.dwnr", FT_UINT16, BASE_DEC, NULL, 0x0,
      "", HFILL }},
    {&hf_h1_dlen,
     {"Length in words", "h1.dlen", FT_INT16, BASE_DEC, NULL, 0x0, "", HFILL }},
    {&hf_h1_response,
     {"Response identifier", "h1.response", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
    {&hf_h1_response_len,
     {"Response length", "h1.reslen", FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }},
    {&hf_h1_response_value,
     {"Response value", "h1.resvalue", FT_UINT8, BASE_DEC,
      VALS (returncode_vals), 0x0, "", HFILL }},
    {&hf_h1_empty,
     {"Empty field", "h1.empty", FT_UINT8, BASE_HEX, NULL, 0x0,
      "", HFILL }},
    {&hf_h1_empty_len,
     {"Empty field length", "h1.empty_len", FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }}
  };

  static gint *ett[] = {
    &ett_h1,
    &ett_opcode,
    &ett_response,
    &ett_org,
    &ett_empty
  };

  proto_h1 = proto_register_protocol ("Sinec H1 Protocol", "H1", "h1");
  proto_register_field_array (proto_h1, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_h1(void)
{
  heur_dissector_add("cotp", dissect_h1, proto_h1);
  heur_dissector_add("cotp_is", dissect_h1, proto_h1);
  data_handle = find_dissector("data");
}
