/* packet-sercosiii_1v1_mst.c
 * Routines for SERCOS III dissection
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>

#include "packet-sercosiii.h"

static gint hf_siii_mst_channel = -1;
static gint hf_siii_mst_type = -1;
static gint hf_siii_mst_cyclecntvalid = -1;
static gint hf_siii_mst_telno = -1;
static gint hf_siii_mst_phase = -1;
static gint hf_siii_mst_cyclecnt = -1;
static gint hf_siii_mst_crc32 = -1;

static gint ett_siii_mst = -1;
static gint ett_siii_mst_teltype = -1;
static gint ett_siii_mst_phase = -1;

static const value_string siii_mst_phase_text[]=
{
  {0x00, "CP0"},
  {0x01, "CP1"},
  {0x02, "CP2"},
  {0x03, "CP3"},
  {0x04, "CP4"},
  {0x80, "CP0 (Phase Change)"},
  {0x81, "CP1 (Phase Change)"},
  {0x82, "CP2 (Phase Change)"},
  {0x83, "CP3 (Phase Change)"},
  {0x84, "CP4 (Phase Change)"},
  {0, NULL}
};

static const value_string siii_mst_teltype_text[]=
{
  {0x00, "CP0"},
  {0x01, "CP1"},
  {0x02, "CP2"},
  {0x03, "CP3"},
  {0x04, "CP4"},
  {0x80, "CP0 (Phase Change)"},
  {0x81, "CP1 (Phase Change)"},
  {0x82, "CP2 (Phase Change)"},
  {0x83, "CP3 (Phase Change)"},
  {0x84, "CP4 (Phase Change)"},
  {0, NULL}
};

static const value_string siii_mst_channel_text[]=
{
  {0x00, "P-Telegram"},
  {0x01, "S-Telegram"},
  {0, NULL}
};

static const value_string siii_mst_type_text[]=
{
  {0x00, "MDT"},
  {0x01, "AT"},
  {0, NULL}
};

static const value_string siii_mst_cyclecntvalid_text[]=
{
  {0x00, "Invalid"},
  {0x01, "Valid"},
  {0, NULL}
};


void dissect_siii_mst(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item*  ti;
  proto_tree* subtree;
  proto_tree* subtree2;

  ti = proto_tree_add_text(tree, tvb, 0, 6, "MST");
  subtree = proto_item_add_subtree(ti, ett_siii_mst);

  ti = proto_tree_add_text(subtree, tvb, 0, 1, "Telegram Type");
  subtree2 = proto_item_add_subtree(ti, ett_siii_mst_teltype);

  proto_tree_add_item(subtree2, hf_siii_mst_channel, tvb, 0, 1, TRUE);
  proto_tree_add_item(subtree2, hf_siii_mst_type, tvb, 0, 1, TRUE);
  proto_tree_add_item(subtree2, hf_siii_mst_cyclecntvalid, tvb, 0, 1, TRUE);
  proto_tree_add_item(subtree2, hf_siii_mst_telno, tvb, 0, 1, TRUE);

  ti = proto_tree_add_text(subtree, tvb, 1, 1, "Phase Field");
  subtree2 = proto_item_add_subtree(ti, ett_siii_mst_phase);

  proto_tree_add_item(subtree2, hf_siii_mst_phase, tvb, 1, 1, TRUE);
  proto_tree_add_item(subtree2, hf_siii_mst_cyclecnt, tvb, 1, 1, TRUE);
  proto_tree_add_item(subtree, hf_siii_mst_crc32, tvb, 2, 4, TRUE);

}

void dissect_siii_mst_init(gint proto_siii)
{
  /* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf_siii_header[] = {
    { &hf_siii_mst_channel,
      { "Channel", "siii.channel",
        FT_UINT8, BASE_DEC, VALS(siii_mst_channel_text), 0x80,
        NULL, HFILL }
    },
    { &hf_siii_mst_type,
      { "Telegram Type" , "siii.type",
        FT_UINT8, BASE_DEC, VALS(siii_mst_type_text), 0x40,
        NULL, HFILL }
    },
    { &hf_siii_mst_cyclecntvalid,
      { "Cycle Count Valid", "siii.cyclecntvalid",
        FT_UINT8, BASE_DEC, VALS(siii_mst_cyclecntvalid_text), 0x20,
        NULL, HFILL }
    },
    { &hf_siii_mst_telno,
      { "Telegram Number", "siii.telno",
        FT_UINT8, BASE_DEC, NULL, 0x0F,
        NULL, HFILL }
    },
    { &hf_siii_mst_phase,
      { "Phase", "siii.mst.phase",
        FT_UINT8, BASE_HEX, VALS(siii_mst_phase_text), 0x8F,    /* CHANGED: SB: new value is 0x8F for masking out phase */
        NULL, HFILL }
    },
    { &hf_siii_mst_cyclecnt,
      { "Cycle Cnt", "siii.mst.cyclecnt",
        FT_UINT8, BASE_DEC, NULL, 0x70,    /* CHANGED: SB: new value is 0x70 for masking out cycle cnt */
        NULL, HFILL }
    },
    { &hf_siii_mst_crc32,
      { "CRC32", "siii.mst.crc32",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL }
    }
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_siii_mst,
    &ett_siii_mst_teltype,
    &ett_siii_mst_phase
  };

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_siii, hf_siii_header, array_length(hf_siii_header));
  proto_register_subtree_array(ett, array_length(ett));
}
