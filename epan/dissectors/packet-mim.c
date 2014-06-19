/* packet-mim.c
 * Routines for analyzing Cisco FabricPath MiM packets
 * Copyright 2011, Leonard Tracy <letracy@cisco.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335 USA.
 */

/*
 *
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/addr_resolv.h>
#include <epan/prefs.h>

void proto_register_mim(void);
void proto_reg_handoff_fabricpath(void);

static int proto_fp = -1 ;
static gint ett_mim = -1 ;
static gint ett_hmac = -1 ;

/* Main protocol items */
static int hf_s_hmac = -1;
static int hf_d_hmac = -1;
static int hf_d_hmac_mc = -1;
static int hf_ftag = -1;
static int hf_ttl = -1;



/* HMAC subtrees */
static int hf_swid = -1 ;
static int hf_sswid = -1;
static int hf_eid = -1;
static int hf_lid = -1;
static int hf_ul = -1;
static int hf_ig = -1;
static int hf_ooodl = -1;

/*  Ethernet heuristic dissectors (such as this one) get called for
 *  every Ethernet frame Wireshark handles.  In order to not impose that
 *  performance penalty on everyone this dissector disables itself by
 *  default.
 *
 *  This is done separately from the disabled protocols list mainly so
 *  we can disable it by default.  XXX Maybe there's a better way.
 */
static gboolean  mim_enable_dissector = FALSE;

static const true_false_string ig_tfs = {
  "Group address (multicast/broadcast)",
  "Individual address (unicast)"
};
static const true_false_string ul_tfs = {
  "Locally administered address (this is NOT the factory default)",
  "Globally unique address (factory default)"
};
static const true_false_string ooodl_tfs = {
  "Out of order delivery (If DA) or Do not learn (If SA)",
  "Deliver in order (If DA) or Learn (If SA)"
};

static dissector_handle_t eth_dissector ;


#define FP_PROTO_COL_NAME "FabricPath"
#define FP_PROTO_COL_INFO "Cisco FabricPath MiM Encapsulated Frame"

#define FP_FIELD_LEN 3

#define FP_EID_MASK    0x00FCC0
#define FP_3B_EID_MASK 0xFCC000

#define FP_UL_MASK     0x020000
#define FP_IG_MASK     0x010000
#define FP_EID2_MASK   0x00C000
#define FP_RES_MASK    0x002000
#define FP_OOO_MASK    0x001000
#define FP_SWID_MASK   0x000FFF

#define FP_BF_LEN    3
#define FP_LID_LEN   2
#define FP_SSWID_LEN 1
#define FP_FTAG_LEN  2

#define FP_FTAG_MASK     0xFFC0
#define FP_TTL_MASK      0x003F

#define FP_HMAC_IG_MASK    G_GINT64_CONSTANT(0x010000000000)
#define FP_HMAC_SWID_MASK  G_GINT64_CONSTANT(0x000FFF000000)
#define FP_HMAC_SSWID_MASK G_GINT64_CONSTANT(0x000000FF0000)
#define FP_HMAC_LID_MASK   G_GINT64_CONSTANT(0x00000000FFFF)


#define FP_HMAC_LEN 6
#define FP_HEADER_SIZE (16)


static int dissect_fp( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_ );


static gboolean
dissect_fp_heur (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

  guint16 type = 0;

  /*
   * Is ethertype ETHERTYPE_DCE
   */

  type = tvb_get_ntohs (tvb, 12);

  if (type == ETHERTYPE_DCE) {
    dissect_fp (tvb, pinfo, tree, NULL);
    return TRUE;
  } else {
    return FALSE;
  }
}

static gboolean
fp_is_ig_set (guint64 hmac)
{
  if (hmac & FP_HMAC_IG_MASK) {
    return TRUE;
  } else {
    return FALSE;
  }
}

static void
fp_get_hmac_addr (guint64 hmac, guint16 *swid, guint16 *sswid, guint16 *lid) {

  if (!swid || !sswid || !lid) {
    return;
  }

  *swid  = (guint16) ((hmac & FP_HMAC_SWID_MASK) >> 24);
  *sswid = (guint16) ((hmac & FP_HMAC_SSWID_MASK) >> 16);
  *lid   = (guint16)  (hmac & FP_HMAC_LID_MASK);
}

static void
fp_add_hmac (tvbuff_t *tvb, proto_tree *tree, int offset) {

  guint16 eid;

  if (!tree) {
    return;
  }

  eid = tvb_get_ntohs(tvb, offset);

  eid &= FP_EID_MASK;
  eid = ((eid & 0x00C0) >> 6) + ((eid & 0xFC00) >> 8);
  proto_tree_add_uint(tree, hf_eid, tvb, offset, FP_BF_LEN, eid);

  proto_tree_add_item (tree, hf_ul, tvb, offset, FP_BF_LEN, ENC_NA);
  proto_tree_add_item (tree, hf_ig, tvb, offset, FP_BF_LEN, ENC_NA);
  proto_tree_add_item (tree, hf_ooodl, tvb, offset, FP_BF_LEN, ENC_NA);
  proto_tree_add_item (tree, hf_swid, tvb, offset, FP_BF_LEN, ENC_BIG_ENDIAN);
  offset += FP_BF_LEN;

  proto_tree_add_item (tree, hf_sswid, tvb, offset, FP_SSWID_LEN, ENC_BIG_ENDIAN);
  offset += FP_SSWID_LEN;

  proto_tree_add_item (tree, hf_lid, tvb, offset, FP_LID_LEN, ENC_BIG_ENDIAN);
  /*offset += FP_LID_LEN;*/

}
/* FabricPath MiM Dissector */
static int
dissect_fp( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_ )
{
  proto_item   *ti ;
  proto_tree   *fp_tree ;
  proto_tree   *fp_addr_tree ;
  tvbuff_t     *next_tvb ;
  int           offset   = 0 ;
  guint64       hmac_src;
  guint64       hmac_dst;
  guint16       sswid    = 0;
  guint16       ssswid   = 0;
  guint16       slid     = 0;
  guint16       dswid    = 0;
  guint16       dsswid   = 0;
  guint16       dlid     = 0;
  const guint8 *dst_addr = NULL;
  gboolean      dest_ig  = FALSE;

  col_set_str( pinfo->cinfo, COL_PROTOCOL, FP_PROTO_COL_NAME ) ;
  col_set_str( pinfo->cinfo, COL_INFO, FP_PROTO_COL_INFO ) ;

  if (tree) {

    hmac_dst = tvb_get_ntoh48 (tvb, 0);
    hmac_src = tvb_get_ntoh48 (tvb, 6);

    dest_ig = fp_is_ig_set(hmac_dst);
    if (!dest_ig) {
      fp_get_hmac_addr (hmac_dst, &dswid, &dsswid, &dlid);
    } else {
      hmac_dst = GUINT64_TO_BE (hmac_dst);
      /* Get pointer to most sig byte of destination address
         in network order
      */
      dst_addr = ((const guint8 *) &hmac_dst) + 2;
    }



    fp_get_hmac_addr (hmac_src, &sswid, &ssswid, &slid);

    if (PTREE_DATA(tree)->visible) {
      if (dest_ig) {

        ti = proto_tree_add_protocol_format(tree, proto_fp, tvb, 0, FP_HEADER_SIZE,
                                            "Cisco FabricPath, Src: %03x.%02x.%04x, Dst: %s (%s)",
                                            sswid, ssswid, slid,
                                            get_ether_name(dst_addr), ether_to_str(dst_addr));
      } else {
        ti = proto_tree_add_protocol_format(tree, proto_fp, tvb, 0, FP_HEADER_SIZE,
                                            "Cisco FabricPath, Src: %03x.%02x.%04x, Dst: %03x.%02x.%04x",
                                            sswid, ssswid, slid,
                                            dswid, dsswid, dlid);
      }
    } else {
      ti = proto_tree_add_item( tree, proto_fp, tvb, 0, -1, ENC_NA ) ;
    }
    fp_tree = proto_item_add_subtree( ti, ett_mim ) ;

    offset = 0;
    /* Add dest and source heir. mac */
    if (dest_ig) {
      /* MCAST address */
      proto_tree_add_ether( fp_tree,  hf_d_hmac_mc, tvb, offset, 6,
                            dst_addr);
    } else {
      /* Unicast */
      ti = proto_tree_add_none_format (fp_tree, hf_d_hmac, tvb, offset, 6, "Destination: %03x.%02x.%04x", dswid, dsswid, dlid);
      fp_addr_tree = proto_item_add_subtree (ti, ett_hmac);
      fp_add_hmac (tvb, fp_addr_tree, offset);
    }

    offset += FP_HMAC_LEN;
    ti = proto_tree_add_none_format (fp_tree, hf_s_hmac, tvb, offset, 6,
                                     "Source: %03x.%02x.%04x", sswid, ssswid, slid);
    fp_addr_tree = proto_item_add_subtree (ti, ett_hmac);
    fp_add_hmac (tvb, fp_addr_tree, offset);

    offset += FP_HMAC_LEN;
    /* Skip ethertype */
    offset += 2;

    proto_tree_add_item (fp_tree, hf_ftag, tvb, offset, FP_FTAG_LEN, ENC_BIG_ENDIAN);

    proto_tree_add_item (fp_tree, hf_ttl, tvb, offset, FP_FTAG_LEN, ENC_BIG_ENDIAN);

  }
  /* call the eth dissector */
  next_tvb = tvb_new_subset_remaining( tvb, FP_HEADER_SIZE) ;
  call_dissector( eth_dissector, next_tvb, pinfo, tree ) ;

  return tvb_length( tvb ) ;
}

/* Register the protocol with Wireshark */
void
proto_register_mim(void)
{
  static hf_register_info hf[] = {
    { &hf_s_hmac,
      { "Source HMAC", "cfp.s_hmac",
        FT_NONE, BASE_NONE, NULL,
        0, "Source Hierarchical MAC", HFILL }},

    { &hf_d_hmac,
      { "Destination HMAC", "cfp.d_hmac",
        FT_NONE, BASE_NONE, NULL,
        0, "Destination Hierarchical MAC", HFILL }},

    { &hf_d_hmac_mc,
      { "MC Destination", "cfp.d_hmac",
        FT_ETHER, BASE_NONE, NULL,
        0, "Multicast Destination Address", HFILL }},

    { &hf_ftag,
      { "FTAG", "cfp.ftag",
        FT_UINT16, BASE_DEC, NULL, FP_FTAG_MASK,
        "FTAG field identifying forwarding distribution tree.", HFILL }},

    { &hf_ttl,
      { "TTL", "cfp.ttl",
        FT_UINT16, BASE_DEC, NULL, FP_TTL_MASK,
        "The remaining hop count for this frame", HFILL }},
    {
      &hf_swid,
      { "switch-id", "cfp.swid",
        FT_UINT24, BASE_DEC_HEX, NULL, FP_SWID_MASK,
        "Switch-id/nickname of switch in FabricPath network", HFILL }},
    {
      &hf_sswid,
      { "sub-switch-id", "cfp.sswid",
        FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
        "Sub-switch-id of switch in FabricPath network", HFILL }},
    {
      &hf_eid,
      { "End Node ID", "cfp.eid",
        FT_UINT24, BASE_DEC_HEX, NULL, FP_3B_EID_MASK,
        "Cisco FabricPath End node ID", HFILL }},
    {
      &hf_lid,
      { "Source LID", "cfp.lid",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
        "Source or Destination Port index on switch in FabricPath network", HFILL }},
    {
      &hf_ul,
      { "U/L bit", "cfp.ul",
        FT_BOOLEAN, 24, TFS(&ul_tfs), FP_UL_MASK,
        "Specifies if this is a locally administered or globally unique (IEEE assigned) address", HFILL }},
    {
      &hf_ig,
      { "I/G bit", "cfp.ig",
        FT_BOOLEAN, 24 /* FP_BF_LEN */, TFS(&ig_tfs), FP_IG_MASK,
        "Specifies if this is an individual (unicast) or group (broadcast/multicast) address", HFILL }},
    {
      &hf_ooodl,
      { "OOO/DL Bit", "cfp.ooodl",
        FT_BOOLEAN, 24 /* FP_BF_LEN */, TFS(&ooodl_tfs), FP_OOO_MASK,
        "Specifies Out of Order Delivery OK in destination address and Do Not Learn when set in source address", HFILL }}

  };

  static gint *ett[] = {
    &ett_mim,
    &ett_hmac
  };

  module_t *mim_module;

  proto_fp = proto_register_protocol("Cisco FabricPath", "CFP", "cfp");

  mim_module = prefs_register_protocol (proto_fp, proto_reg_handoff_fabricpath);

  prefs_register_bool_preference (mim_module, "enable", "Enable dissector",
                                  "Enable this dissector (default is false)",
                                  &mim_enable_dissector);

  proto_register_field_array(proto_fp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_fabricpath(void)
{
  /*
    dissector_handle_t fp_handle;
    fp_handle = new_create_dissector_handle(dissect_fp, proto_fp);
    dissector_add_uint("ethertype", ETHERTYPE_DCE, fp_handle);
  */
  static gboolean prefs_initialized = FALSE;

  if (!prefs_initialized) {
    /*
     * Using Heuristic dissector (As opposed to
     * registering the ethertype) in order to
     * get outer source and destination MAC
     * before the standard ethernet dissector
     */
    heur_dissector_add ("eth", dissect_fp_heur, proto_fp);
    eth_dissector = find_dissector( "eth" );
    prefs_initialized = TRUE;
  }

  proto_set_decoding(proto_fp, mim_enable_dissector);
}
