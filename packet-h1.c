/* packet-h1.c
 * Routines for Sinec H1 packet disassembly
 * Gerrit Gehnen <G.Gehnen@atrie.de>
 *
 * $Id: packet-h1.c,v 1.2 2000/03/02 07:38:02 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <string.h>

#include <glib.h>
#include "packet.h"
#include "globals.h"
#include "packet-h1.h"

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
  {0xFF, "Error, reason unkown"},
  {0, NULL}
};

static gint ett_h1 = -1;
static gint ett_opcode = -1;
static gint ett_org = -1;
static gint ett_response = -1;
static gint ett_empty = -1;


void
dissect_h1 (const u_char * pd, int offset, frame_data * fd, proto_tree * tree)
{
  proto_tree *h1_tree = NULL;
  proto_item *ti;
  proto_tree *opcode_tree = NULL;
  proto_tree *org_tree = NULL;
  proto_tree *response_tree = NULL;
  proto_tree *empty_tree = NULL;

  unsigned int position = 2;

  if (pd[offset] == 'S' && pd[offset + 1] == '5')
    {
      if (check_col (fd, COL_PROTOCOL))
	col_add_str (fd, COL_PROTOCOL, "H1");
      if (check_col (fd, COL_INFO))
	col_add_str (fd, COL_INFO, "S5: ");
      if (tree)
	{
	  ti = proto_tree_add_item (tree, proto_h1, offset, 16, NULL);
	  h1_tree = proto_item_add_subtree (ti, ett_h1);
	  proto_tree_add_item (h1_tree, hf_h1_header, offset, 2,
			       pd[offset] * 0x100 + pd[offset + 1]);
	  proto_tree_add_item (h1_tree, hf_h1_len, offset + 2, 1,
			       pd[offset + 2]);
	}

      while (position < pd[offset + 2])
	{
	  switch (pd[offset + position])
	    {
	    case OPCODE_BLOCK:
	      if (h1_tree)
		{
		  ti = proto_tree_add_item (h1_tree, hf_h1_opfield,
					    offset + position,
					    pd[offset + position + 1],
					    pd[offset + position]);
		  opcode_tree = proto_item_add_subtree (ti, ett_opcode);
		  proto_tree_add_item (opcode_tree, hf_h1_oplen,
				       offset + position + 1, 1,
				       pd[offset + position + 1]);
		  proto_tree_add_item (opcode_tree, hf_h1_opcode,
				       offset + position + 2, 1,
				       pd[offset + position + 2]);
		}
	      if (check_col (fd, COL_INFO))
		{
		  col_append_str (fd, COL_INFO,
				  match_strval (pd[offset + position + 2],
						opcode_vals));
		}
	      break;
	    case REQUEST_BLOCK:
	      if (h1_tree)
		{
		  ti = proto_tree_add_item (h1_tree, hf_h1_requestblock,
					    offset + position,
					    pd[offset + position + 1],
					    pd[offset + position]);
		  org_tree = proto_item_add_subtree (ti, ett_org);
		  proto_tree_add_item (org_tree, hf_h1_requestlen,
				       offset + position + 1, 1,
				       pd[offset + position + 1]);
		  proto_tree_add_item (org_tree, hf_h1_org,
				       offset + position + 2, 1,
				       pd[offset + position + 2]);
		  proto_tree_add_item (org_tree, hf_h1_dbnr,
				       offset + position + 3, 1,
				       pd[offset + position + 3]);
		  proto_tree_add_item (org_tree, hf_h1_dwnr,
				       offset + position + 4, 2,
				       pd[offset + position + 4] * 0x100 +
				       pd[offset + position + 5]);
		  proto_tree_add_item (org_tree, hf_h1_dlen,
				       offset + position + 6, 2,
				       pd[offset + position + 6] * 0x100 +
				       pd[offset + position + 7]);
		}
	      if (check_col (fd, COL_INFO))
		{
		  col_append_fstr (fd, COL_INFO, " %s %d",
				   match_strval (pd[offset + position + 2],
						 org_vals),
				   pd[offset + position + 3]);
		  col_append_fstr (fd, COL_INFO, " DW %d",
				   pd[offset + position + 4] * 0x100 +
				   pd[offset + position + 5]);
		  col_append_fstr (fd, COL_INFO, " Count %d",
				   pd[offset + position + 6] * 0x100 +
				   pd[offset + position + 7]);
		}
	      break;
	    case RESPONSE_BLOCK:
	      if (h1_tree)
		{
		  ti = proto_tree_add_item (h1_tree, hf_h1_response,
					    offset + position,
					    pd[offset + position + 1],
					    pd[offset + position]);
		  response_tree = proto_item_add_subtree (ti, ett_response);
		  proto_tree_add_item (response_tree, hf_h1_response_len,
				       offset + position + 1, 1,
				       pd[offset + position + 1]);
		  proto_tree_add_item (response_tree, hf_h1_response_value,
				       offset + position + 2, 1,
				       pd[offset + position + 2]);
		}
	      if (check_col (fd, COL_INFO))
		{
		  col_append_fstr (fd, COL_INFO, " %s",
				   match_strval (pd[offset + position + 2],
						 returncode_vals));
		}
	      break;
	    case EMPTY_BLOCK:
	      if (h1_tree)
		{
		  ti = proto_tree_add_item (h1_tree, hf_h1_empty,
					    offset + position,
					    pd[offset + position + 1],
					    pd[offset + position]);
		  empty_tree = proto_item_add_subtree (ti, ett_empty);

		  proto_tree_add_item (empty_tree, hf_h1_empty_len,
				       offset + position + 1, 1,
				       pd[offset + position + 1]);
		}
	      break;
	    default:
	      /* TODO: Add Default Handler. */
	    }
	  position += pd[offset + position + 1];	/* Goto next section */
	}			/* ..while */

      dissect_data (pd, offset + pd[offset + 2], fd, tree);
    }
  else
    {
      dissect_data (pd, offset, fd, tree);
    }
}


void
proto_register_h1 (void)
{
  static hf_register_info hf[] = {
    {&hf_h1_header,
     {"H1-Header", "h1.header", FT_UINT16, BASE_HEX, NULL, 0x0,
      ""}},
    {&hf_h1_len,
     {"Length indicator", "h1.len", FT_UINT16, BASE_DEC, NULL, 0x0,
      ""}},
    {&hf_h1_opfield,
     {"Operation identifier", "h1.opfield", FT_UINT8, BASE_HEX, NULL, 0x0,
      ""}},
    {&hf_h1_oplen,
     {"Operation length", "h1.oplen", FT_UINT8, BASE_HEX, NULL, 0x0, ""}},
    {&hf_h1_opcode,
     {"Opcode", "h1.opcode", FT_UINT8, BASE_HEX, VALS (opcode_vals), 0x0,
      ""}},
    {&hf_h1_requestblock,
     {"Request identifier", "h1.request", FT_UINT8, BASE_HEX, NULL, 0x0,
      ""}},
    {&hf_h1_requestlen,
     {"Request length", "h1.reqlen", FT_UINT8, BASE_HEX, NULL, 0x0,
      ""}},
    {&hf_h1_org,
     {"Memory type", "h1.org", FT_UINT8, BASE_HEX, VALS (org_vals), 0x0,
      ""}},
    {&hf_h1_dbnr,
     {"Memory block number", "h1.dbnr", FT_UINT8, BASE_DEC, NULL, 0x0, ""}},
    {&hf_h1_dwnr,
     {"Address within memory block", "h1.dwnr", FT_UINT16, BASE_DEC, NULL, 0x0,
      ""}},
    {&hf_h1_dlen,
     {"Length in words", "h1.dlen", FT_INT16, BASE_DEC, NULL, 0x0, ""}},
    {&hf_h1_response,
     {"Response identifier", "h1.response", FT_UINT8, BASE_DEC, NULL, 0x0, ""}},
    {&hf_h1_response_len,
     {"Response length", "h1.reslen", FT_UINT8, BASE_DEC, NULL, 0x0,
      ""}},
    {&hf_h1_response_value,
     {"Response value", "h1.resvalue", FT_UINT8, BASE_DEC,
      VALS (returncode_vals), 0x0, ""}},
    {&hf_h1_empty,
     {"Emtpy field", "h1.empty", FT_UINT8, BASE_HEX, NULL, 0x0,
      ""}},
    {&hf_h1_empty_len,
     {"Empty field length", "h1.empty_len", FT_UINT8, BASE_DEC, NULL, 0x0,
      ""}}
  };

  static gint *ett[] = {
    &ett_h1,
    &ett_opcode,
    &ett_response,
    &ett_org,
    &ett_empty
  };

  proto_h1 = proto_register_protocol ("Sinec H1 Protocol", "h1");
  proto_register_field_array (proto_h1, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
}
