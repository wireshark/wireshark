/* packet-mtp2.c
 * Routines for MTP2 dissection
 * It is hopefully (needs testing) compliant to
 * ITU-T Q. 703
 *
 * Copyright 2001, Michael Tuexen <michael.tuexen[AT]icn.siemens.de>
 *
 * $Id: packet-mtp2.c,v 1.1 2001/12/11 03:04:26 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-m2pa.c
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

#include <glib.h>

#include "packet.h"

/* Initialize the protocol and registered fields */
static int proto_mtp2      = -1;
static int hf_mtp2_bsn     = -1;
static int hf_mtp2_bib     = -1;
static int hf_mtp2_fsn     = -1;
static int hf_mtp2_fib     = -1;
static int hf_mtp2_li      = -1;
static int hf_mtp2_spare   = -1;
static int hf_mtp2_sf      = -1;
static int hf_mtp2_long_sf = -1;

/* Initialize the subtree pointers */
static gint ett_mtp2       = -1;

static dissector_handle_t mtp3_handle;
static int mtp3_proto_id;

#define BSN_BIB_LENGTH 1
#define FSN_FIB_LENGTH 1
#define LI_LENGTH      1
#define HEADER_LENGTH  (BSN_BIB_LENGTH + FSN_FIB_LENGTH + LI_LENGTH)
#define SF_LENGTH      1
#define LONG_SF_LENGTH 2

#define BSN_BIB_OFFSET 0
#define FSN_FIB_OFFSET (BSN_BIB_OFFSET + BSN_BIB_LENGTH)
#define LI_OFFSET      (FSN_FIB_OFFSET + FSN_FIB_LENGTH)
#define SIO_OFFSET     (LI_OFFSET + LI_LENGTH)
#define SF_OFFSET      (LI_OFFSET + LI_LENGTH)

#define BSN_MASK       0x7f
#define BIB_MASK       0x80
#define FSN_MASK       0x7f
#define FIB_MASK       0x80
#define LI_MASK        0x3f
#define SPARE_MASK     0xc0

#define STATUS_O       0x0
#define STATUS_N       0x1
#define STATUS_E       0x2
#define STATUS_OS      0x3
#define STATUS_PO      0x4
#define STATUS_B       0x5

static const value_string status_field_vals[] = {
	{ STATUS_O,	 "Status Indication O" },
  { STATUS_N,  "Status Indication N" },
	{ STATUS_E,	 "Status Indication E" },
	{ STATUS_OS, "Status Indication OS" },
	{ STATUS_PO, "Status Indication PO" },
	{ STATUS_B,  "Status Indication BO" },
  { 0,         NULL} 
};

static void
dissect_mtp2_header(tvbuff_t *su_tvb, proto_item *mtp2_tree)
{  
  guint8 bsn_bib, fsn_fib, li;
  
  bsn_bib = tvb_get_guint8(su_tvb, BSN_BIB_OFFSET);
  fsn_fib = tvb_get_guint8(su_tvb, FSN_FIB_OFFSET);
  li      = tvb_get_guint8(su_tvb, LI_OFFSET);
  
  if (mtp2_tree) {
    proto_tree_add_uint(mtp2_tree, hf_mtp2_bsn, su_tvb, BSN_BIB_OFFSET, BSN_BIB_LENGTH, bsn_bib);
    proto_tree_add_uint(mtp2_tree, hf_mtp2_bib, su_tvb, BSN_BIB_OFFSET, BSN_BIB_LENGTH, bsn_bib);
    proto_tree_add_uint(mtp2_tree, hf_mtp2_fsn, su_tvb, FSN_FIB_OFFSET, FSN_FIB_LENGTH, fsn_fib);
    proto_tree_add_uint(mtp2_tree, hf_mtp2_fib, su_tvb, FSN_FIB_OFFSET, FSN_FIB_LENGTH, fsn_fib);
    proto_tree_add_uint(mtp2_tree, hf_mtp2_li, su_tvb, LI_OFFSET, LI_LENGTH, li);
    proto_tree_add_uint(mtp2_tree, hf_mtp2_spare, su_tvb, LI_OFFSET, LI_LENGTH, li);
  }
}

static void
dissect_mtp2_fisu(packet_info *pinfo)
{  
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_str(pinfo->cinfo, COL_INFO, "FISU");
}

static void
dissect_mtp2_lssu(tvbuff_t *su_tvb, packet_info *pinfo, proto_item *mtp2_tree)
{  
  guint8  li, sf;
  guint16 long_sf;

  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_str(pinfo->cinfo, COL_INFO, "LSSU");

  if (mtp2_tree) {
    li = tvb_get_guint8(su_tvb, LI_OFFSET);
    if ((li & LI_MASK) == 1) {
      sf = tvb_get_guint8(su_tvb, SF_OFFSET);
      proto_tree_add_uint(mtp2_tree, hf_mtp2_sf, su_tvb, SF_OFFSET, SF_LENGTH, sf);
    } else {
      long_sf = tvb_get_letohs(su_tvb, SF_OFFSET);
      proto_tree_add_uint(mtp2_tree, hf_mtp2_long_sf, su_tvb, SF_OFFSET, LONG_SF_LENGTH, long_sf);
    }
  }
}

static void
dissect_mtp2_msu(tvbuff_t *su_tvb, packet_info *pinfo, proto_item *mtp2_item, proto_item *tree)
{  
  gint sif_sio_length;
  tvbuff_t *sif_sio_tvb;

  if ((check_col(pinfo->cinfo, COL_INFO)) && (!proto_is_protocol_enabled(mtp3_proto_id)))
    col_append_str(pinfo->cinfo, COL_INFO, "MSU");
    
  sif_sio_length = tvb_length(su_tvb) - HEADER_LENGTH;
  sif_sio_tvb = tvb_new_subset(su_tvb, SIO_OFFSET, sif_sio_length, sif_sio_length);
  call_dissector(mtp3_handle, sif_sio_tvb, pinfo, tree);
  
  if (tree)
    proto_item_set_len(mtp2_item, HEADER_LENGTH);

}

static void
dissect_mtp2_su(tvbuff_t *su_tvb, packet_info *pinfo, proto_item *mtp2_item, proto_item *mtp2_tree, proto_tree *tree)
{
  guint8 li;
  
  dissect_mtp2_header(su_tvb, mtp2_tree);
  li = tvb_get_guint8(su_tvb, LI_OFFSET);
  switch(li & LI_MASK) {
  case 0:
    dissect_mtp2_fisu(pinfo);
    break;
  case 1:
  case 2:
    dissect_mtp2_lssu(su_tvb, pinfo, mtp2_tree);
    break;
  default:
    dissect_mtp2_msu(su_tvb, pinfo, mtp2_item, tree);
    break;
  }
}

static void
dissect_mtp2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *mtp2_item = NULL;
  proto_tree *mtp2_tree = NULL;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MTP2");

  if (tree) {
    mtp2_item = proto_tree_add_item(tree, proto_mtp2, tvb, 0, tvb_length(tvb), FALSE);
    mtp2_tree = proto_item_add_subtree(mtp2_item, ett_mtp2);
  };

  dissect_mtp2_su(tvb, pinfo, mtp2_item, mtp2_tree, tree);
}

void
proto_register_mtp2(void)
{

  static hf_register_info hf[] = {
    { &hf_mtp2_bsn,
      { "Backward sequence number", "mtp2.bsn",
	      FT_UINT8, BASE_DEC, NULL, BSN_MASK,          
	      "", HFILL }
    },
    { &hf_mtp2_bib,
      { "Backward indicator bit", "mtp2.bib",
	      FT_UINT8, BASE_DEC, NULL, BIB_MASK,          
	      "", HFILL }
    },
    { &hf_mtp2_fsn,
      { "Forward sequence number", "mtp2.fsn",
	      FT_UINT8, BASE_DEC, NULL, FSN_MASK,          
	      "", HFILL }
    },
    { &hf_mtp2_fib,
      { "Forward indicator bit", "mtp2.fib",
	      FT_UINT8, BASE_DEC, NULL, FIB_MASK,          
	      "", HFILL }
    },
    { &hf_mtp2_li,
      { "Length Indicator", "mtp2.li",
	      FT_UINT8, BASE_DEC, NULL, LI_MASK,          
	      "", HFILL }
    },
    { &hf_mtp2_spare,
      { "Spare", "mtp2.spare",
	      FT_UINT8, BASE_DEC, NULL, SPARE_MASK,          
	      "", HFILL }
    },
    { &hf_mtp2_sf,
      { "Status field", "mtp2.sf",
	      FT_UINT8, BASE_DEC, VALS(status_field_vals), 0x0,          
	      "", HFILL }
    },
    { &hf_mtp2_long_sf,
      { "Status field", "mtp2.long_sf",
	      FT_UINT16, BASE_HEX, NULL, 0x0,          
	      "", HFILL }
    }
  };

  static gint *ett[] = {
    &ett_mtp2
  };

  proto_mtp2 = proto_register_protocol("Message Transfer Part Level 2", "MTP2", "mtp2");
  register_dissector("mtp2", dissect_mtp2, proto_mtp2);

  proto_register_field_array(proto_mtp2, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

};

void
proto_reg_handoff_mtp2(void)
{
  mtp3_handle   = find_dissector("mtp3");
  mtp3_proto_id = proto_get_id_by_filter_name("mtp3");
}
