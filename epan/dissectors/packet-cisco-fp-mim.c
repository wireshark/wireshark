/* packet-cisco-fp-mim.c
 * Routines for analyzing Cisco FabricPath MiM (MAC-in-MAA) packets
 * Copyright 2011, Leonard Tracy <letracy@cisco.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 *  https://clnv.s3.amazonaws.com/2016/usa/pdf/BRKDCT-3313.pdf
 *  https://clnv.s3.amazonaws.com/2014/eur/pdf/BRKDCT-2081.pdf
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/addr_resolv.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/crc32-tvb.h>

void proto_register_mim(void);
void proto_reg_handoff_fabricpath(void);

static gboolean fp_check_fcs = FALSE;

static int proto_fp = -1;
static gint ett_mim = -1;
static gint ett_hmac = -1;

/* Main protocol items */
static int hf_s_hmac = -1;
static int hf_d_hmac = -1;
static int hf_d_hmac_mc = -1;
static int hf_ftag = -1;
static int hf_ttl = -1;

static int hf_fp_etype = -1;
static int hf_fp_1ad_etype = -1;
static int hf_fp_1ad_priority = -1;
static int hf_fp_1ad_cfi = -1;
static int hf_fp_1ad_svid = -1;
static int hf_fp_fcs = -1;
static int hf_fp_fcs_status = -1;

/* HMAC subtrees */
static int hf_swid = -1;
static int hf_sswid = -1;
static int hf_eid = -1;
static int hf_lid = -1;
static int hf_ul = -1;
static int hf_ig = -1;
static int hf_ooodl = -1;

static expert_field ei_fp_fcs_bad = EI_INIT;

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

static dissector_handle_t eth_withoutfcs_dissector;

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
#define FP_HEADER_WITH_1AD_SIZE (20)

/* 0100.0000.0000 */
#define MAC_MC_BC          G_GINT64_CONSTANT(0x010000000000)

/* proto */
static int dissect_fp_common( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int header_size );

/*
 * These packets are a bit strange.
 *
 * They run over Ethernet, but, instead of a normal 14-octet Ethernet
 * header, they have a 16-octet or 20-octet header, which happens to
 * have, in the position occupied by the Type/Length field in an
 * Ethernet header, the Ethertype value reserved for FabricPath.
 *
 * The fields in the positions occupied by the destination and source
 * MAC addresses in an Ethernet header are occupied by addresses that
 * are parsed specially, so we want to dissect them differently from
 * normal MAC addresses.
 *
 * The Ethertype field is part of a 4-octet FP tag, which includes
 * the Ethertype and some additional information.
 *
 * So we register as a heuristic dissector, which gets called before
 * the regular code that checks Ethertypes.
 */
static gboolean
dissect_fp_heur (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  guint16 etype = 0;
  int header_size = 0;

  if ( ! tvb_bytes_exist( tvb, 12, 2 ) )
     return FALSE;

  etype = tvb_get_ntohs( tvb, 12 );

  switch ( etype ) {
    case ETHERTYPE_DCE:
      header_size = FP_HEADER_SIZE;
      break;
    case ETHERTYPE_IEEE_802_1AD:
    case ETHERTYPE_VLAN:
      if ( tvb_bytes_exist( tvb, 16, 2 ) && tvb_get_ntohs( tvb, 16 ) == ETHERTYPE_DCE ) {
        header_size = FP_HEADER_WITH_1AD_SIZE;
        break;
      }
      /* fall through */
    default:
      return FALSE;
  }

  if ( dissect_fp_common( tvb, pinfo, tree, header_size ) > 0 ) {
    return TRUE;
  }

  return FALSE;
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
dissect_fp_common ( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int header_size)
{
  proto_item   *ti;
  proto_tree   *fp_tree;
  proto_tree   *fp_addr_tree;
  tvbuff_t     *next_tvb;
  int           offset   = 0;
  int           next_tvb_len = 0;
  int           fcs_offset = 0;
  guint64       hmac_src;
  guint64       hmac_dst;
  guint16       sswid    = 0;
  guint16       ssswid   = 0;
  guint16       slid     = 0;
  guint16       dswid    = 0;
  guint16       dsswid   = 0;
  guint16       dlid     = 0;
  guint16       etype    = 0;
  const guint8 *dst_addr = NULL;
  gboolean      dest_as_mac  = FALSE;


  col_set_str( pinfo->cinfo, COL_PROTOCOL, FP_PROTO_COL_NAME );
  col_set_str( pinfo->cinfo, COL_INFO, FP_PROTO_COL_INFO );

  /*
   * Outer SA:
   * - SwitchID ingress FP switch system ID
   * - SubswitchID is used in some cases of VPC+
   * - LID (Local ID)  is specific to the implementation
   *   + N7K the LID is generally the port index of the ingress interface
   *   + N5K/N6K LID most of the time will be 0
   *   + EndnodeID is not currently used
   *
   * Outer DA:
   * - For known SA/DA is taken from MAC table for DMAC
   * - For broadcast and multicast is the same as DMAC
   * - For unknown unicast DA is 010f.ffc1.01c0 (flood to vlan)
   * - For known unicast DA, but unknown SA is 010f.ffc1.02c0 (flood to fabric)
   */

  hmac_dst = tvb_get_ntoh48 (tvb, 0);
  hmac_src = tvb_get_ntoh48 (tvb, 6);

  if (hmac_dst & MAC_MC_BC) {
    dest_as_mac = TRUE;
  }
  if (!dest_as_mac) {
    fp_get_hmac_addr (hmac_dst, &dswid, &dsswid, &dlid);
  } else {
    hmac_dst = GUINT64_TO_BE (hmac_dst);
    /* Get pointer to most sig byte of destination address
       in network order
    */
    dst_addr = ((const guint8 *) &hmac_dst) + 2;
  }
  fp_get_hmac_addr (hmac_src, &sswid, &ssswid, &slid);

  /* FIXME: Does this make sense??? */
  if (tree && PTREE_DATA(tree)->visible) {
    if (dest_as_mac) {
      address      ether_addr;

      set_address(&ether_addr, AT_ETHER, 6, dst_addr);

      ti = proto_tree_add_protocol_format(tree, proto_fp, tvb, 0, header_size,
                                          "Cisco FabricPath, Src: %03x.%02x.%04x, Dst: %s",
                                          sswid, ssswid, slid,
                                          address_with_resolution_to_str(pinfo->pool, &ether_addr));
    } else {
      ti = proto_tree_add_protocol_format(tree, proto_fp, tvb, 0, header_size,
                                          "Cisco FabricPath, Src: %03x.%02x.%04x, Dst: %03x.%02x.%04x",
                                          sswid, ssswid, slid,
                                          dswid, dsswid, dlid);
    }
  } else {
    ti = proto_tree_add_item( tree, proto_fp, tvb, 0, header_size, ENC_NA );
  }
  fp_tree = proto_item_add_subtree( ti, ett_mim );

  /* Add dest and source heir. mac */
  if (dest_as_mac) {
    /* MCAST address */
    proto_tree_add_ether( fp_tree,  hf_d_hmac_mc, tvb, offset, 6, dst_addr);
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

  etype = tvb_get_ntohs(tvb, offset);
  switch (etype) {
  case ETHERTYPE_DCE:
      proto_tree_add_item(fp_tree, hf_fp_etype, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      break;
  case ETHERTYPE_IEEE_802_1AD:
  case ETHERTYPE_VLAN:
      proto_tree_add_item(fp_tree, hf_fp_1ad_etype, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(fp_tree, hf_fp_1ad_priority, tvb, offset, 2, ENC_NA);
      proto_tree_add_item(fp_tree, hf_fp_1ad_cfi, tvb, offset, 2, ENC_NA);
      proto_tree_add_item(fp_tree, hf_fp_1ad_svid, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(fp_tree, hf_fp_etype, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      break;
  default:
      /* The heuristics should prevent us from getting here */
      DISSECTOR_ASSERT(0);
  }

  proto_tree_add_item (fp_tree, hf_ftag, tvb, offset, FP_FTAG_LEN, ENC_BIG_ENDIAN);
  proto_tree_add_item (fp_tree, hf_ttl, tvb, offset, FP_FTAG_LEN, ENC_BIG_ENDIAN);

  /* eval FCS */
  fcs_offset = tvb_reported_length(tvb) - 4;

  if ( tvb_bytes_exist(tvb, fcs_offset, 4 ) ) {
    if ( fp_check_fcs ) {
      guint32 fcs = crc32_802_tvb(tvb, fcs_offset);
      proto_tree_add_checksum(fp_tree, tvb, fcs_offset, hf_fp_fcs, hf_fp_fcs_status, &ei_fp_fcs_bad, pinfo, fcs, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
    } else {
      proto_tree_add_checksum(fp_tree, tvb, fcs_offset, hf_fp_fcs, hf_fp_fcs_status, &ei_fp_fcs_bad, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
    }
    proto_tree_set_appendix(fp_tree, tvb, fcs_offset, 4);
  }

  /* call the eth dissector w/o the FCS */
  next_tvb_len = tvb_reported_length_remaining( tvb, header_size ) - 4;
  next_tvb = tvb_new_subset_length( tvb, header_size, next_tvb_len );

  /*
   * We've already verified the replaced CFP checksum
   * Therefore we call the Ethernet dissector without expecting a FCS
   */
  call_dissector( eth_withoutfcs_dissector, next_tvb, pinfo, tree );

  return tvb_captured_length( tvb );
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
      { "MC Destination", "cfp.d_hmac_mc",
        FT_ETHER, BASE_NONE, NULL,
        0, "Multicast Destination Address", HFILL }},

    { &hf_fp_etype,
      { "FP Ethertype", "cfp.etype", FT_UINT16, BASE_HEX,
        VALS(etype_vals), 0x0, NULL, HFILL }},

    { &hf_fp_1ad_etype,
      { "IEEE 802.1ad Ethertype", "cfp.1ad.etype", FT_UINT16, BASE_HEX,
        VALS(etype_vals), 0x0, NULL, HFILL }},

    { &hf_fp_1ad_priority,
      { "Priority", "cfp.1ad.priority", FT_UINT16, BASE_DEC,
        0, 0xE000, NULL, HFILL }},

    { &hf_fp_1ad_cfi,
      { "DEI", "cfp.1ad.dei", FT_UINT16, BASE_DEC,
        0, 0x1000, "Drop Eligibility", HFILL }},

    { &hf_fp_1ad_svid,
      { "ID", "cfp.1ad.id", FT_UINT16, BASE_DEC,
        0, 0x0FFF, "Vlan ID", HFILL }},

    { &hf_fp_fcs,
      { "Frame check sequence", "cfp.fcs", FT_UINT32, BASE_HEX,
        NULL, 0x0, "FabricPath checksum", HFILL }},

    { &hf_fp_fcs_status,
      { "FCS status", "cfp.fcs.status", FT_UINT8, BASE_NONE,
        VALS(proto_checksum_vals), 0x0, NULL, HFILL }},

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

  static ei_register_info ei[] = {
    { &ei_fp_fcs_bad, { "cfp.fcs_bad", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }}
  };

  module_t *mim_module;
  expert_module_t *expert_mim;

  proto_fp = proto_register_protocol("Cisco FabricPath", "CFP", "cfp");

  mim_module = prefs_register_protocol (proto_fp, NULL);

  prefs_register_obsolete_preference (mim_module, "enable");

  prefs_register_bool_preference(mim_module, "check_fcs",
                                 "Validate the FabricPath checksum if possible",
                                 "Whether to validate the Frame Check Sequence",
                                 &fp_check_fcs);

  proto_register_field_array(proto_fp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  expert_mim = expert_register_protocol(proto_fp);
  expert_register_field_array(expert_mim, ei, array_length(ei));
}

void
proto_reg_handoff_fabricpath(void)
{
  /*
   * Using Heuristic dissector (As opposed to
   * registering the ethertype) in order to
   * get outer source and destination MAC
   * before the standard ethernet dissector
   */
  heur_dissector_add ("eth", dissect_fp_heur, "Cisco FabricPath over Ethernet", "fp_eth", proto_fp, HEURISTIC_ENABLE);

  /*
   * The FCS in FabricPath frames covers the entire FabricPath frame,
   * not the encapsulated Ethernet frame, so we don't want to treat
   * the encapsulated frame as if it had an FCS.
   */
  eth_withoutfcs_dissector = find_dissector_add_dependency( "eth_withoutfcs", proto_fp );
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
