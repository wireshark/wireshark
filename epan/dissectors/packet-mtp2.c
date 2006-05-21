/* packet-mtp2.c
 * Routines for MTP2 dissection
 * It is hopefully (needs testing) compliant to
 * ITU-T Q.703 and Q.703 Annex A.
 *
 * Copyright 2001, 2004 Michael Tuexen <tuexen [AT] fh-muenster.de>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
#include <epan/packet.h>
#include "epan/prefs.h"

#define LITTLE_ENDIAN_BYTE_ORDER TRUE

/* Initialize the protocol and registered fields */
static int proto_mtp2        = -1;
static int hf_mtp2_bsn       = -1;
static int hf_mtp2_ext_bsn   = -1;
static int hf_mtp2_ext_res   = -1;
static int hf_mtp2_bib       = -1;
static int hf_mtp2_ext_bib   = -1;
static int hf_mtp2_fsn       = -1;
static int hf_mtp2_ext_fsn   = -1;
static int hf_mtp2_fib       = -1;
static int hf_mtp2_ext_fib   = -1;
static int hf_mtp2_li        = -1;
static int hf_mtp2_ext_li    = -1;
static int hf_mtp2_spare     = -1;
static int hf_mtp2_ext_spare = -1;
static int hf_mtp2_sf        = -1;
static int hf_mtp2_long_sf   = -1;

/* Initialize the subtree pointers */
static gint ett_mtp2       = -1;

static dissector_handle_t mtp3_handle;
static int mtp3_proto_id;
static gboolean use_extended_sequence_numbers_default = FALSE;
static gboolean use_extended_sequence_numbers         = FALSE;

#define BSN_BIB_LENGTH          1
#define FSN_FIB_LENGTH          1
#define LI_LENGTH               1
#define HEADER_LENGTH           (BSN_BIB_LENGTH + FSN_FIB_LENGTH + LI_LENGTH)

#define EXTENDED_BSN_BIB_LENGTH 2
#define EXTENDED_FSN_FIB_LENGTH 2
#define EXTENDED_LI_LENGTH      2
#define EXTENDED_HEADER_LENGTH  (EXTENDED_BSN_BIB_LENGTH + EXTENDED_FSN_FIB_LENGTH + EXTENDED_LI_LENGTH)

#define BSN_BIB_OFFSET          0
#define FSN_FIB_OFFSET          (BSN_BIB_OFFSET + BSN_BIB_LENGTH)
#define LI_OFFSET               (FSN_FIB_OFFSET + FSN_FIB_LENGTH)
#define SIO_OFFSET              (LI_OFFSET + LI_LENGTH)

#define EXTENDED_BSN_BIB_OFFSET 0
#define EXTENDED_FSN_FIB_OFFSET (EXTENDED_BSN_BIB_OFFSET + EXTENDED_BSN_BIB_LENGTH)
#define EXTENDED_LI_OFFSET      (EXTENDED_FSN_FIB_OFFSET + EXTENDED_FSN_FIB_LENGTH)
#define EXTENDED_SIO_OFFSET     (EXTENDED_LI_OFFSET + EXTENDED_LI_LENGTH)

#define BSN_MASK                0x7f
#define BIB_MASK                0x80
#define FSN_MASK                0x7f
#define FIB_MASK                0x80
#define LI_MASK                 0x3f
#define SPARE_MASK              0xc0

#define EXTENDED_BSN_MASK       0x0fff
#define EXTENDED_RES_MASK       0x7000
#define EXTENDED_BIB_MASK       0x8000
#define EXTENDED_FSN_MASK       0x0fff
#define EXTENDED_FIB_MASK       0x8000
#define EXTENDED_LI_MASK        0x01ff
#define EXTENDED_SPARE_MASK     0xfe00

static void
dissect_mtp2_header(tvbuff_t *su_tvb, proto_item *mtp2_tree)
{
  if (mtp2_tree) {
    if (use_extended_sequence_numbers) {
      proto_tree_add_item(mtp2_tree, hf_mtp2_ext_bsn,   su_tvb, EXTENDED_BSN_BIB_OFFSET, EXTENDED_BSN_BIB_LENGTH, LITTLE_ENDIAN_BYTE_ORDER);
      proto_tree_add_item(mtp2_tree, hf_mtp2_ext_res,   su_tvb, EXTENDED_BSN_BIB_OFFSET, EXTENDED_BSN_BIB_LENGTH, LITTLE_ENDIAN_BYTE_ORDER);
      proto_tree_add_item(mtp2_tree, hf_mtp2_ext_bib,   su_tvb, EXTENDED_BSN_BIB_OFFSET, EXTENDED_BSN_BIB_LENGTH, LITTLE_ENDIAN_BYTE_ORDER);
      proto_tree_add_item(mtp2_tree, hf_mtp2_ext_fsn,   su_tvb, EXTENDED_FSN_FIB_OFFSET, EXTENDED_FSN_FIB_LENGTH, LITTLE_ENDIAN_BYTE_ORDER);
      proto_tree_add_item(mtp2_tree, hf_mtp2_ext_res,   su_tvb, EXTENDED_BSN_BIB_OFFSET, EXTENDED_BSN_BIB_LENGTH, LITTLE_ENDIAN_BYTE_ORDER);
      proto_tree_add_item(mtp2_tree, hf_mtp2_ext_fib,   su_tvb, EXTENDED_FSN_FIB_OFFSET, EXTENDED_FSN_FIB_LENGTH, LITTLE_ENDIAN_BYTE_ORDER);
      proto_tree_add_item(mtp2_tree, hf_mtp2_ext_li,    su_tvb, EXTENDED_LI_OFFSET,      EXTENDED_LI_LENGTH,      LITTLE_ENDIAN_BYTE_ORDER);
      proto_tree_add_item(mtp2_tree, hf_mtp2_ext_spare, su_tvb, EXTENDED_LI_OFFSET,      EXTENDED_LI_LENGTH,      LITTLE_ENDIAN_BYTE_ORDER);
    } else {
      proto_tree_add_item(mtp2_tree, hf_mtp2_bsn,   su_tvb, BSN_BIB_OFFSET, BSN_BIB_LENGTH, LITTLE_ENDIAN_BYTE_ORDER);
      proto_tree_add_item(mtp2_tree, hf_mtp2_bib,   su_tvb, BSN_BIB_OFFSET, BSN_BIB_LENGTH, LITTLE_ENDIAN_BYTE_ORDER);
      proto_tree_add_item(mtp2_tree, hf_mtp2_fsn,   su_tvb, FSN_FIB_OFFSET, FSN_FIB_LENGTH, LITTLE_ENDIAN_BYTE_ORDER);
      proto_tree_add_item(mtp2_tree, hf_mtp2_fib,   su_tvb, FSN_FIB_OFFSET, FSN_FIB_LENGTH, LITTLE_ENDIAN_BYTE_ORDER);
      proto_tree_add_item(mtp2_tree, hf_mtp2_li,    su_tvb, LI_OFFSET,      LI_LENGTH,      LITTLE_ENDIAN_BYTE_ORDER);
      proto_tree_add_item(mtp2_tree, hf_mtp2_spare, su_tvb, LI_OFFSET,      LI_LENGTH,      LITTLE_ENDIAN_BYTE_ORDER);
    }
  }
}

static void
dissect_mtp2_fisu(packet_info *pinfo)
{
  if (check_col(pinfo->cinfo, COL_INFO))
    col_set_str(pinfo->cinfo, COL_INFO, "FISU ");
}

static const value_string status_field_vals[] = {
  { 0x0, "Status Indication O" },
  { 0x1, "Status Indication N" },
  { 0x2, "Status Indication E" },
  { 0x3, "Status Indication OS" },
  { 0x4, "Status Indication PO" },
  { 0x5, "Status Indication BO" },
  { 0,   NULL}
};

#define SF_OFFSET          (LI_OFFSET + LI_LENGTH)
#define EXTENDED_SF_OFFSET (EXTENDED_LI_OFFSET + EXTENDED_LI_LENGTH)

#define SF_LENGTH          1
#define LONG_SF_LENGTH     2

static void
dissect_mtp2_lssu(tvbuff_t *su_tvb, packet_info *pinfo, proto_item *mtp2_tree)
{
  if (check_col(pinfo->cinfo, COL_INFO))
    col_set_str(pinfo->cinfo, COL_INFO, "LSSU ");
  
  if (mtp2_tree) {
    if (use_extended_sequence_numbers) {
      if ((tvb_get_letohs(su_tvb, EXTENDED_LI_OFFSET) & EXTENDED_LI_MASK) == 1)
        proto_tree_add_item(mtp2_tree, hf_mtp2_sf,      su_tvb, EXTENDED_SF_OFFSET, SF_LENGTH,      LITTLE_ENDIAN_BYTE_ORDER);
      else
        proto_tree_add_item(mtp2_tree, hf_mtp2_long_sf, su_tvb, EXTENDED_SF_OFFSET, LONG_SF_LENGTH, LITTLE_ENDIAN_BYTE_ORDER);
    } else {
      if ((tvb_get_guint8(su_tvb, LI_OFFSET) & LI_MASK) == 1)
        proto_tree_add_item(mtp2_tree, hf_mtp2_sf,      su_tvb, SF_OFFSET,          SF_LENGTH,      LITTLE_ENDIAN_BYTE_ORDER);
      else
        proto_tree_add_item(mtp2_tree, hf_mtp2_long_sf, su_tvb, SF_OFFSET,          LONG_SF_LENGTH, LITTLE_ENDIAN_BYTE_ORDER);
    }
  }
}

static void
dissect_mtp2_msu(tvbuff_t *su_tvb, packet_info *pinfo, proto_item *mtp2_item, proto_item *tree)
{
  gint sif_sio_length;
  tvbuff_t *sif_sio_tvb;

  if (check_col(pinfo->cinfo, COL_INFO))
    col_set_str(pinfo->cinfo, COL_INFO, "MSU ");

  if (use_extended_sequence_numbers) {
    sif_sio_length = tvb_length(su_tvb) - EXTENDED_HEADER_LENGTH;
    sif_sio_tvb = tvb_new_subset(su_tvb, EXTENDED_SIO_OFFSET, sif_sio_length, sif_sio_length);
  } else {
    sif_sio_length = tvb_length(su_tvb) - HEADER_LENGTH;
    sif_sio_tvb = tvb_new_subset(su_tvb, SIO_OFFSET, sif_sio_length, sif_sio_length);
  }
  call_dissector(mtp3_handle, sif_sio_tvb, pinfo, tree);

  if (tree) {
    if (use_extended_sequence_numbers)
      proto_item_set_len(mtp2_item, EXTENDED_HEADER_LENGTH);
    else
      proto_item_set_len(mtp2_item, HEADER_LENGTH);
  }
}

static void
dissect_mtp2_su(tvbuff_t *su_tvb, packet_info *pinfo, proto_item *mtp2_item, proto_item *mtp2_tree, proto_tree *tree)
{
  guint16 li;

  dissect_mtp2_header(su_tvb, mtp2_tree);
  if (use_extended_sequence_numbers)
    li = tvb_get_letohs(su_tvb, EXTENDED_LI_OFFSET) & EXTENDED_LI_MASK;
  else
    li = tvb_get_guint8(su_tvb, LI_OFFSET) & LI_MASK;
  switch(li) {
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

  if (pinfo->annex_a_used == MTP2_ANNEX_A_USED_UNKNOWN)
    use_extended_sequence_numbers = use_extended_sequence_numbers_default;
  else
    use_extended_sequence_numbers = (pinfo->annex_a_used == MTP2_ANNEX_A_USED);
    
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MTP2");
  
  if (tree) {
    mtp2_item = proto_tree_add_item(tree, proto_mtp2, tvb, 0, -1, FALSE);
    mtp2_tree = proto_item_add_subtree(mtp2_item, ett_mtp2);
  };

  dissect_mtp2_su(tvb, pinfo, mtp2_item, mtp2_tree, tree);
}

void
proto_register_mtp2(void)
{

  static hf_register_info hf[] = {
    { &hf_mtp2_bsn,       { "Backward sequence number", "mtp2.bsn",   FT_UINT8,  BASE_DEC, NULL,                    BSN_MASK,            "", HFILL } },
    { &hf_mtp2_ext_bsn,   { "Backward sequence number", "mtp2.bsn",   FT_UINT16, BASE_DEC, NULL,                    EXTENDED_BSN_MASK,   "", HFILL } },
    { &hf_mtp2_ext_res,   { "Reserved",                 "mtp2.res",   FT_UINT16, BASE_DEC, NULL,                    EXTENDED_RES_MASK,   "", HFILL } },
    { &hf_mtp2_bib,       { "Backward indicator bit",   "mtp2.bib",   FT_UINT8,  BASE_DEC, NULL,                    BIB_MASK,            "", HFILL } },
    { &hf_mtp2_ext_bib,   { "Backward indicator bit",   "mtp2.bib",   FT_UINT16, BASE_DEC, NULL,                    EXTENDED_BIB_MASK,   "", HFILL } },
    { &hf_mtp2_fsn,       { "Forward sequence number",  "mtp2.fsn",   FT_UINT8,  BASE_DEC, NULL,                    FSN_MASK,            "", HFILL } },
    { &hf_mtp2_ext_fsn,   { "Forward sequence number",  "mtp2.fsn",   FT_UINT16, BASE_DEC, NULL,                    EXTENDED_FSN_MASK,   "", HFILL } },
    { &hf_mtp2_fib,       { "Forward indicator bit",    "mtp2.fib",   FT_UINT8,  BASE_DEC, NULL,                    FIB_MASK,            "", HFILL } },
    { &hf_mtp2_ext_fib,   { "Forward indicator bit",    "mtp2.fib",   FT_UINT16, BASE_DEC, NULL,                    EXTENDED_FIB_MASK,   "", HFILL } },
    { &hf_mtp2_li,        { "Length Indicator",         "mtp2.li",    FT_UINT8,  BASE_DEC, NULL,                    LI_MASK,             "", HFILL } },
    { &hf_mtp2_ext_li,    { "Length Indicator",         "mtp2.li",    FT_UINT16, BASE_DEC, NULL,                    EXTENDED_LI_MASK,    "", HFILL } },
    { &hf_mtp2_spare,     { "Spare",                    "mtp2.spare", FT_UINT8,  BASE_DEC, NULL,                    SPARE_MASK,          "", HFILL } },
    { &hf_mtp2_ext_spare, { "Spare",                    "mtp2.spare", FT_UINT16, BASE_DEC, NULL,                    EXTENDED_SPARE_MASK, "", HFILL } },
    { &hf_mtp2_sf,        { "Status field",             "mtp2.sf",    FT_UINT8,  BASE_DEC, VALS(status_field_vals), 0x0,                 "", HFILL } },
    { &hf_mtp2_long_sf,   { "Status field",             "mtp2.sf",    FT_UINT16, BASE_HEX, NULL,                    0x0,                 "", HFILL } }
  };

  static gint *ett[] = {
    &ett_mtp2
  };

  module_t *mtp2_module;

  proto_mtp2 = proto_register_protocol("Message Transfer Part Level 2", "MTP2", "mtp2");
  register_dissector("mtp2", dissect_mtp2, proto_mtp2);

  proto_register_field_array(proto_mtp2, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  
  mtp2_module = prefs_register_protocol(proto_mtp2, NULL);
  prefs_register_bool_preference(mtp2_module, 
                                 "use_extended_sequence_numbers",
                                 "Use extended sequence numbers",
                                 "Whether the MTP2 dissector should use extended sequence numbers as described in Q.703, Annex A as a default.",
                                 &use_extended_sequence_numbers_default);


}

void
proto_reg_handoff_mtp2(void)
{
  dissector_handle_t mtp2_handle;

  mtp2_handle = create_dissector_handle(dissect_mtp2, proto_mtp2);

  dissector_add("wtap_encap", WTAP_ENCAP_MTP2, mtp2_handle);
  dissector_add("wtap_encap", WTAP_ENCAP_MTP2_WITH_PHDR, mtp2_handle);

  mtp3_handle   = find_dissector("mtp3");
  mtp3_proto_id = proto_get_id_by_filter_name("mtp3");
}
