/* packet-erf.c
 * Routines for ERF encapsulation dissection
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
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/expert.h>

/*
#include "wiretap/atm.h"
*/
#include "wiretap/erf.h"
#include <epan/prefs.h>
#include "packet-erf.h"

/* Initialize the protocol and registered fields */
static int proto_erf        = -1;

static int hf_erf_ts   = -1;
static int hf_erf_type      = -1;
static int hf_erf_ehdr      = -1;
static int hf_erf_ehdr_t      = -1;
static int hf_erf_flags     = -1;
static int hf_erf_flags_cap     = -1;
static int hf_erf_flags_vlen     = -1;
static int hf_erf_flags_trunc    = -1;
static int hf_erf_flags_rxe     = -1;
static int hf_erf_flags_dse     = -1;
static int hf_erf_flags_res     = -1;

static int hf_erf_rlen      = -1;
static int hf_erf_lctr      = -1;
static int hf_erf_wlen      = -1;

/* Classification extension header */

/* InterceptID extension header */
static int hf_erf_ehdr_int_res1 = -1;
static int hf_erf_ehdr_int_id = -1;
static int hf_erf_ehdr_int_res2 = -1;

/* Raw Link extension header */
static int hf_erf_ehdr_raw_link_res = -1;
static int hf_erf_ehdr_raw_link_seqnum = -1;
static int hf_erf_ehdr_raw_link_rate = -1;
static int hf_erf_ehdr_raw_link_type = -1;

/* Classification extension header */
static int hf_erf_ehdr_class_flags = -1;
static int hf_erf_ehdr_class_flags_sh = -1;
static int hf_erf_ehdr_class_flags_shm = -1;
static int hf_erf_ehdr_class_flags_res1 = -1;
static int hf_erf_ehdr_class_flags_user = -1;
static int hf_erf_ehdr_class_flags_res2 = -1;
static int hf_erf_ehdr_class_flags_drop = -1;
static int hf_erf_ehdr_class_flags_str = -1;
static int hf_erf_ehdr_class_seqnum = -1;

/* BFS extension header */
static int hf_erf_ehdr_bfs_hash = -1;
static int hf_erf_ehdr_bfs_color = -1;
static int hf_erf_ehdr_bfs_raw_hash = -1;

/* Channelised extension header */
static int hf_erf_ehdr_chan_morebits = -1;
static int hf_erf_ehdr_chan_morefrag = -1;
static int hf_erf_ehdr_chan_seqnum = -1;
static int hf_erf_ehdr_chan_res = -1;
static int hf_erf_ehdr_chan_virt_container_id = -1;
static int hf_erf_ehdr_chan_assoc_virt_container_size = -1;
static int hf_erf_ehdr_chan_speed = -1;
static int hf_erf_ehdr_chan_type = -1;

/* New BFS extension header */
static int hf_erf_ehdr_new_bfs_payload_hash = -1;
static int hf_erf_ehdr_new_bfs_color = -1;
static int hf_erf_ehdr_new_bfs_flow_hash = -1;

/* Unknown extension header */
static int hf_erf_ehdr_unk = -1;

/* MC HDLC Header */
static int hf_erf_mc_hdlc_cn     = -1;
static int hf_erf_mc_hdlc_res1   = -1;
static int hf_erf_mc_hdlc_res2   = -1;
static int hf_erf_mc_hdlc_fcse   = -1;
static int hf_erf_mc_hdlc_sre    = -1;
static int hf_erf_mc_hdlc_lre    = -1;
static int hf_erf_mc_hdlc_afe    = -1;
static int hf_erf_mc_hdlc_oe     = -1;
static int hf_erf_mc_hdlc_lbe    = -1;
static int hf_erf_mc_hdlc_first  = -1;
static int hf_erf_mc_hdlc_res3   = -1;

/* MC RAW Header */
static int hf_erf_mc_raw_int   = -1;
static int hf_erf_mc_raw_res1  = -1;
static int hf_erf_mc_raw_res2  = -1;
static int hf_erf_mc_raw_res3  = -1;
static int hf_erf_mc_raw_sre   = -1;
static int hf_erf_mc_raw_lre   = -1;
static int hf_erf_mc_raw_res4  = -1;
static int hf_erf_mc_raw_lbe   = -1;
static int hf_erf_mc_raw_first = -1;
static int hf_erf_mc_raw_res5  = -1;

/* MC ATM Header */
static int hf_erf_mc_atm_cn   = -1;
static int hf_erf_mc_atm_res1 = -1;
static int hf_erf_mc_atm_mul  = -1;
static int hf_erf_mc_atm_port = -1;
static int hf_erf_mc_atm_res2 = -1;
static int hf_erf_mc_atm_lbe  = -1;
static int hf_erf_mc_atm_hec  = -1;
static int hf_erf_mc_atm_crc10   = -1;
static int hf_erf_mc_atm_oamcell = -1;
static int hf_erf_mc_atm_first   = -1;
static int hf_erf_mc_atm_res3    = -1;

/* MC Raw link Header */
static int hf_erf_mc_rawl_cn   = -1;
static int hf_erf_mc_rawl_res2 = -1;
static int hf_erf_mc_rawl_lbe  = -1;
static int hf_erf_mc_rawl_first = -1;
static int hf_erf_mc_rawl_res3 = -1;

/* MC AAL5 Header */
static int hf_erf_mc_aal5_cn = -1;
static int hf_erf_mc_aal5_res1 = -1;
static int hf_erf_mc_aal5_port = -1;
static int hf_erf_mc_aal5_crcck = -1;
static int hf_erf_mc_aal5_crce = -1;
static int hf_erf_mc_aal5_lenck = -1;
static int hf_erf_mc_aal5_lene = -1;
static int hf_erf_mc_aal5_res2 = -1;
static int hf_erf_mc_aal5_first = -1;
static int hf_erf_mc_aal5_res3 = -1;

/* MC AAL2 Header */
static int hf_erf_mc_aal2_cn = -1;
static int hf_erf_mc_aal2_res1 = -1;
static int hf_erf_mc_aal2_res2 = -1;
static int hf_erf_mc_aal2_port = -1;
static int hf_erf_mc_aal2_res3 = -1;
static int hf_erf_mc_aal2_first = -1;
static int hf_erf_mc_aal2_maale = -1;
static int hf_erf_mc_aal2_lene = -1;
static int hf_erf_mc_aal2_cid = -1;

/* AAL2 Header */
static int hf_erf_aal2_cid = -1;
static int hf_erf_aal2_maale = -1;
static int hf_erf_aal2_maalei = -1;
static int hf_erf_aal2_first = -1;
static int hf_erf_aal2_res1 = -1;

/* ERF Ethernet header/pad */
static int hf_erf_eth_off = -1;
static int hf_erf_eth_res1 = -1;

/* Initialize the subtree pointers */
static gint ett_erf = -1;
static gint ett_erf_pseudo_hdr = -1;
static gint ett_erf_types = -1;
static gint ett_erf_flags = -1;
static gint ett_erf_mc_hdlc = -1;
static gint ett_erf_mc_raw = -1;
static gint ett_erf_mc_atm = -1;
static gint ett_erf_mc_rawlink = -1;
static gint ett_erf_mc_aal5 = -1;
static gint ett_erf_mc_aal2 = -1;
static gint ett_erf_aal2 = -1;
static gint ett_erf_eth = -1;

/* Default subdissector, display raw hex data */
static dissector_handle_t data_handle;

/* IPv4 and IPv6 subdissectors */
static dissector_handle_t ipv4_handle;
static dissector_handle_t ipv6_handle;

static dissector_handle_t infiniband_handle;
static dissector_handle_t infiniband_link_handle;

typedef enum {
  ERF_HDLC_CHDLC = 0,
  ERF_HDLC_PPP = 1,
  ERF_HDLC_FRELAY = 2,
  ERF_HDLC_MTP2 = 3,
  ERF_HDLC_GUESS = 4,
  ERF_HDLC_MAX = 5
} erf_hdlc_type_vals;
static gint erf_hdlc_type = ERF_HDLC_GUESS;
static dissector_handle_t chdlc_handle, ppp_handle, frelay_handle, mtp2_handle;

static gboolean erf_rawcell_first = FALSE;

typedef enum {
  ERF_AAL5_GUESS = 0,
  ERF_AAL5_LLC = 1,
  ERF_AAL5_UNSPEC = 2
} erf_aal5_type_val;
static gint erf_aal5_type = ERF_AAL5_GUESS;
static dissector_handle_t atm_untruncated_handle;

static gboolean erf_ethfcs = TRUE;
static dissector_handle_t ethwithfcs_handle, ethwithoutfcs_handle;

/* ERF Header */
#define ERF_HDR_TYPES_MASK 0xff
#define ERF_HDR_TYPE_MASK 0x7f
#define ERF_HDR_EHDR_MASK 0x80
#define ERF_HDR_FLAGS_MASK 0xff
#define ERF_HDR_CAP_MASK 0x03
#define ERF_HDR_VLEN_MASK 0x04
#define ERF_HDR_TRUNC_MASK 0x08
#define ERF_HDR_RXE_MASK 0x10
#define ERF_HDR_DSE_MASK 0x20
#define ERF_HDR_RES_MASK 0xC0

/* Classification */
#define EHDR_CLASS_SH_MASK  0x800000
#define EHDR_CLASS_SHM_MASK 0x400000
#define EHDR_CLASS_RES1_MASK 0x300000
#define EHDR_CLASS_USER_MASK 0x0FFFF0
#define EHDR_CLASS_RES2_MASK 0x08
#define EHDR_CLASS_DROP_MASK 0x04
#define EHDR_CLASS_STER_MASK 0x03

/* Header for ATM traffic identification */
#define ATM_HDR_LENGTH 4

/* Multi Channel HDLC */
#define MC_HDLC_CN_MASK 0x03ff
#define MC_HDLC_RES1_MASK 0xfc00
#define MC_HDLC_RES2_MASK 0xff
#define MC_HDLC_FCSE_MASK 0x01
#define MC_HDLC_SRE_MASK 0x02
#define MC_HDLC_LRE_MASK 0x04
#define MC_HDLC_AFE_MASK 0x08
#define MC_HDLC_OE_MASK 0x10
#define MC_HDLC_LBE_MASK 0x20
#define MC_HDLC_FIRST_MASK 0x40
#define MC_HDLC_RES3_MASK 0x80

/* Multi Channel RAW */
#define MC_RAW_INT_MASK 0x0f
#define MC_RAW_RES1_MASK 0xf0
#define MC_RAW_RES2_MASK 0xffff
#define MC_RAW_RES3_MASK 0x01
#define MC_RAW_SRE_MASK 0x02
#define MC_RAW_LRE_MASK 0x04
#define MC_RAW_RES4_MASK 0x18
#define MC_RAW_LBE_MASK 0x20
#define MC_RAW_FIRST_MASK 0x40
#define MC_RAW_RES5_MASK 0x80

/* Multi Channel ATM */
#define MC_ATM_CN_MASK 0x03ff
#define MC_ATM_RES1_MASK 0x7c00
#define MC_ATM_MUL_MASK 0x8000
#define MC_ATM_PORT_MASK 0x0f
#define MC_ATM_RES2_MASK 0xf0
#define MC_ATM_LBE_MASK 0x01
#define MC_ATM_HEC_MASK 0x02
#define MC_ATM_CRC10_MASK 0x04
#define MC_ATM_OAMCELL_MASK 0x08
#define MC_ATM_FIRST_MASK 0x10
#define MC_ATM_RES3_MASK 0xe0

/* Multi Channel RAW Link */
#define MC_RAWL_CN_MASK 0x03ff
#define MC_RAWL_RES1_MASK 0xfffc
#define MC_RAWL_RES2_MASK 0x1f
#define MC_RAWL_LBE_MASK 0x20
#define MC_RAWL_FIRST_MASK 0x40
#define MC_RAWL_RES3_MASK 0x80

/* Multi Channel AAL5 */
#define MC_AAL5_CN_MASK 0x03ff
#define MC_AAL5_RES1_MASK 0xfc00
#define MC_AAL5_PORT_MASK 0x0f
#define MC_AAL5_CRCCK_MASK 0x10
#define MC_AAL5_CRCE_MASK 0x20
#define MC_AAL5_LENCK_MASK 0x40
#define MC_AAL5_LENE_MASK 0x80
#define MC_AAL5_RES2_MASK 0x0f
#define MC_AAL5_FIRST_MASK 0x10
#define MC_AAL5_RES3_MASK 0xe0

/* Multi Channel AAL2 */
#define MC_AAL2_CN_MASK 0x03ff
#define MC_AAL2_RES1_MASK 0x1c00
#define MC_AAL2_RES2_MASK 0xe000
#define MC_AAL2_PORT_MASK 0x0f
#define MC_AAL2_RES3_MASK 0x10
#define MC_AAL2_FIRST_MASK 0x20
#define MC_AAL2_MAALE_MASK 0x40
#define MC_AAL2_LENE_MASK 0x80
#define MC_AAL2_CID_MASK 0xff

/* AAL2 */
#define AAL2_CID_MASK 0xff
#define AAL2_MAALE_MASK 0xff
#define AAL2_MAALEI_MASK 0x0001
#define AAL2_FIRST_MASK 0x0002
#define AAL2_RES1_MASK 0xfffc

/* ETH */
#define ETH_OFF_MASK 0xff
#define ETH_RES1_MASK 0xff

/* Record type defines */
static const value_string erf_type_vals[] = {
  { ERF_TYPE_LEGACY,"LEGACY"},
  { ERF_TYPE_HDLC_POS,"HDLC_POS"},
  { ERF_TYPE_ETH,"ETH"},
  { ERF_TYPE_ATM,"ATM"},
  { ERF_TYPE_AAL5,"AAL5"},
  { ERF_TYPE_MC_HDLC,"MC_HDLC"},
  { ERF_TYPE_MC_RAW,"MC_RAW"},
  { ERF_TYPE_MC_ATM,"MC_ATM"},
  { ERF_TYPE_MC_RAW_CHANNEL,"MC_RAW_CHANNEL"},
  { ERF_TYPE_MC_AAL5,"MC_AAL5"},
  { ERF_TYPE_COLOR_HDLC_POS,"COLOR_HDLC_POS"},
  { ERF_TYPE_COLOR_ETH,"COLOR_ETH"},
  { ERF_TYPE_MC_AAL2,"MC_AAL2 "},
  { ERF_TYPE_IP_COUNTER,"IP_COUNTER"},
  { ERF_TYPE_TCP_FLOW_COUNTER,"TCP_FLOW_COUNTER"},
  { ERF_TYPE_DSM_COLOR_HDLC_POS,"DSM_COLOR_HDLC_POS"},
  { ERF_TYPE_DSM_COLOR_ETH,"DSM_COLOR_ETH "},
  { ERF_TYPE_COLOR_MC_HDLC_POS,"COLOR_MC_HDLC_POS"},
  { ERF_TYPE_AAL2,"AAL2"},
  { ERF_TYPE_PAD,"PAD"},
  { ERF_TYPE_INFINIBAND, "INFINIBAND"},
  { ERF_TYPE_IPV4, "IPV4"},
  { ERF_TYPE_IPV6, "IPV6"},
  { ERF_TYPE_RAW_LINK, "RAW_LINK"},
  { ERF_TYPE_INFINIBAND_LINK, "INFINIBAND_LINK"},
  {0, NULL}
};

/* Extended headers type defines */
static const value_string ehdr_type_vals[] = {
  { EXT_HDR_TYPE_CLASSIFICATION, "Classification"},
  { EXT_HDR_TYPE_INTERCEPTID, "InterceptID"},
  { EXT_HDR_TYPE_RAW_LINK, "Raw Link"},
  { EXT_HDR_TYPE_BFS, "BFS Filter/Hash"},
  { EXT_HDR_TYPE_CHANNELISED, "Channelised"},
  { EXT_HDR_TYPE_NEW_BFS, "New BFS Filter/Hash"},
  { 0, NULL }
};


static const value_string raw_link_types[] = {
  { 0x00, "raw SONET"},
  { 0x01, "raw SDH"},
  { 0x02, "SONET spe"},
  { 0x03, "SDH spe"},
  { 0x04, "ds3"},
  { 0x05, "SONET spe w/o POH"},
  { 0x06, "SDH spe w/o POH"},
  { 0x07, "SONET line mode 2"},
  { 0x08, "SHD line mode 2"},
  { 0x09, "raw bit-level"},
  { 0x0A, "raw 10Gbe 66b"},
  { 0, NULL },
};

static const value_string raw_link_rates[] = {
  { 0x00, "reserved"},
  { 0x01, "oc3/stm1"},
  { 0x02, "oc12/stm4"},
  { 0x03, "oc48/stm16"},
  { 0x04, "oc192/stm64"},
  { 0, NULL },
};

static const value_string channelised_assoc_virt_container_size[] = {
  { 0x00, "unused field"},
  { 0x01, "VC-3 / STS-1"},
  { 0x02, "VC-4 / STS-3"},
  { 0x03, "VC-4-4c / STS-12"},
  { 0x04, "VC-4-16c / STS-48"},
  { 0x05, "VC-4-64c / STS-192"},
  { 0, NULL }
};

static const value_string channelised_speed[] = {
  { 0x00, "Reserved"},
  { 0x01, "STM-0 / STS-1"},
  { 0x02, "STM-1 / STS-3"},
  { 0x03, "STM-4 / STS-12"},
  { 0x04, "STM-16 / STS-48"},
  { 0x05, "STM-64 / STS-192"},
  { 0, NULL}
};

static const value_string channelised_type[] = {
  { 0x00, "SOH / TOH"},
  { 0x01, "POH"},
  { 0x02, "Container"},
  { 0x03, "POS Packet"},
  { 0x04, "ATM Cell"},
  { 0x05, "Positive justification bytes"},
  { 0x06, "Raw demultiplexed channel"},
  { 0, NULL}
};



/* Copy of atm_guess_traffic_type from atm.c in /wiretap */
static void
erf_atm_guess_lane_type(const guint8 *pd, guint len,
    union wtap_pseudo_header *pseudo_header)
{
  if (len >= 2) {
    if (pd[0] == 0xff && pd[1] == 0x00) {
      /*
       * Looks like LE Control traffic.
       */
      pseudo_header->atm.subtype = TRAF_ST_LANE_LE_CTRL;
    } else {
      /*
       * XXX - Ethernet, or Token Ring?
       * Assume Ethernet for now; if we see earlier
       * LANE traffic, we may be able to figure out
       * the traffic type from that, but there may
       * still be situations where the user has to
       * tell us.
       */
      pseudo_header->atm.subtype = TRAF_ST_LANE_802_3;
    }
  }
}

static void
erf_atm_guess_traffic_type(const guint8 *pd, guint len,
    union wtap_pseudo_header *pseudo_header)
{
  /*
   * Start out assuming nothing other than that it's AAL5.
   */
  pseudo_header->atm.aal = AAL_5;
  pseudo_header->atm.type = TRAF_UNKNOWN;
  pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;

  if (pseudo_header->atm.vpi == 0) {
    /*
     * Traffic on some PVCs with a VPI of 0 and certain
     * VCIs is of particular types.
     */
    switch (pseudo_header->atm.vci) {

    case 5:
      /*
       * Signalling AAL.
       */
      pseudo_header->atm.aal = AAL_SIGNALLING;
      return;

    case 16:
      /*
       * ILMI.
       */
      pseudo_header->atm.type = TRAF_ILMI;
      return;
    }
  }

  /*
   * OK, we can't tell what it is based on the VPI/VCI; try
   * guessing based on the contents, if we have enough data
   * to guess.
   */

  if (len >= 3) {
    if (pd[0] == 0xaa && pd[1] == 0xaa && pd[2] == 0x03) {
      /*
       * Looks like a SNAP header; assume it's LLC
       * multiplexed RFC 1483 traffic.
       */
      pseudo_header->atm.type = TRAF_LLCMX;
    } else if ((pseudo_header->atm.aal5t_len &&
                pseudo_header->atm.aal5t_len < 16) || len<16) {
      /*
       * As this cannot be a LANE Ethernet frame (less
       * than 2 bytes of LANE header + 14 bytes of
       * Ethernet header) we can try it as a SSCOP frame.
       */
      pseudo_header->atm.aal = AAL_SIGNALLING;
    } else if (pd[0] == 0x83 || pd[0] == 0x81) {
      /*
       * MTP3b headers often encapsulate
       * a SCCP or MTN in the 3G network.
       * This should cause 0x83 or 0x81
       * in the first byte.
       */
      pseudo_header->atm.aal = AAL_SIGNALLING;
    } else {
      /*
       * Assume it's LANE.
       */
      pseudo_header->atm.type = TRAF_LANE;
      erf_atm_guess_lane_type(pd, len, pseudo_header);
    }
  } else {
    /*
     * Not only VCI 5 is used for signaling. It might be
     * one of these VCIs.
     */
    pseudo_header->atm.aal = AAL_SIGNALLING;
  }
}

static void
dissect_classification_ex_header(tvbuff_t *tvb,  packet_info *pinfo, proto_tree *pseudo_hdr_tree, int idx)
{
  proto_item *int_item= NULL, *flags_item = NULL;
  proto_tree *int_tree = NULL, *flags_tree = NULL;
  guint64 hdr = pinfo->pseudo_header->erf.ehdr_list[idx].ehdr;
  guint32 value = (guint32)(hdr >> 32);

  if (pseudo_hdr_tree){
    int_item = proto_tree_add_text(pseudo_hdr_tree, tvb, 0, 0, "Classification");
    int_tree = proto_item_add_subtree(int_item, ett_erf_pseudo_hdr);
    PROTO_ITEM_SET_GENERATED(int_item);

    proto_tree_add_uint(int_tree, hf_erf_ehdr_t , tvb, 0, 0, (guint8)((hdr >> 56) & 0x7F));
    flags_item=proto_tree_add_uint(int_tree, hf_erf_ehdr_class_flags, tvb, 0, 0, value & 0xFFFFFF);
    flags_tree = proto_item_add_subtree(flags_item, ett_erf_flags);


    proto_tree_add_uint(flags_tree, hf_erf_ehdr_class_flags_sh, tvb, 0, 0, value);
    proto_tree_add_uint(flags_tree, hf_erf_ehdr_class_flags_shm, tvb, 0, 0,  value);
    proto_tree_add_uint(flags_tree, hf_erf_ehdr_class_flags_res1, tvb, 0, 0, value);
    proto_tree_add_uint(flags_tree, hf_erf_ehdr_class_flags_user, tvb, 0, 0, value);
    proto_tree_add_uint(flags_tree, hf_erf_ehdr_class_flags_res2, tvb, 0, 0, value);
    proto_tree_add_uint(flags_tree, hf_erf_ehdr_class_flags_drop, tvb, 0, 0, value);
    proto_tree_add_uint(flags_tree, hf_erf_ehdr_class_flags_str, tvb, 0, 0, value);
    proto_tree_add_uint(int_tree, hf_erf_ehdr_class_seqnum, tvb, 0, 0, (guint32)hdr);
  }
}

static void
dissect_intercept_ex_header(tvbuff_t *tvb,  packet_info *pinfo, proto_tree *pseudo_hdr_tree, int idx)
{
  proto_item *int_item= NULL;
  proto_tree *int_tree = NULL;
  guint64 hdr = pinfo->pseudo_header->erf.ehdr_list[idx].ehdr;
  if (pseudo_hdr_tree){
    int_item = proto_tree_add_text(pseudo_hdr_tree, tvb, 0, 0, "InterceptID");
    int_tree = proto_item_add_subtree(int_item, ett_erf_pseudo_hdr);
    PROTO_ITEM_SET_GENERATED(int_item);

    proto_tree_add_uint(int_tree, hf_erf_ehdr_t , tvb, 0, 0, (guint8)((hdr >> 56) & 0x7F));
    proto_tree_add_uint(int_tree, hf_erf_ehdr_int_res1, tvb, 0, 0, (guint8)((hdr >> 48) & 0xFF));
    proto_tree_add_uint(int_tree, hf_erf_ehdr_int_id, tvb, 0, 0, (guint16)((hdr >> 32 ) & 0xFFFF));
    proto_tree_add_uint(int_tree, hf_erf_ehdr_int_res2, tvb, 0, 0, (guint32)hdr);
  }
}

static void
dissect_raw_link_ex_header(tvbuff_t *tvb,  packet_info *pinfo, proto_tree *pseudo_hdr_tree, int idx)
{
  proto_item *int_item= NULL;
  proto_tree *int_tree = NULL;
  guint64 hdr = pinfo->pseudo_header->erf.ehdr_list[idx].ehdr;

  if (pseudo_hdr_tree){
    int_item = proto_tree_add_text(pseudo_hdr_tree, tvb, 0, 0, "Raw Link");
    int_tree = proto_item_add_subtree(int_item, ett_erf_pseudo_hdr);
    PROTO_ITEM_SET_GENERATED(int_item);

    proto_tree_add_uint(int_tree, hf_erf_ehdr_t , tvb, 0, 0, (guint8)((hdr >> 56) & 0x7F));
    proto_tree_add_uint(int_tree, hf_erf_ehdr_raw_link_res , tvb, 0, 0,  (guint32)((hdr >> 32) & 0xFFFFFF));
    proto_tree_add_uint(int_tree, hf_erf_ehdr_raw_link_seqnum , tvb, 0, 0, (guint32)((hdr >> 16) & 0xffff));
    proto_tree_add_uint(int_tree, hf_erf_ehdr_raw_link_rate, tvb, 0, 0, (guint32)((hdr >> 8) & 0x00ff));
    proto_tree_add_uint(int_tree, hf_erf_ehdr_raw_link_type, tvb, 0, 0, (guint32)(hdr & 0x00ff));
  }
}

static void
dissect_bfs_ex_header(tvbuff_t *tvb,  packet_info *pinfo, proto_tree *pseudo_hdr_tree, int idx)
{
  proto_item *int_item= NULL;
  proto_tree *int_tree = NULL;
  guint64 hdr = pinfo->pseudo_header->erf.ehdr_list[idx].ehdr;

  if (pseudo_hdr_tree){
    int_item = proto_tree_add_text(pseudo_hdr_tree, tvb, 0, 0, "BFS Filter/Hash");
    int_tree = proto_item_add_subtree(int_item, ett_erf_pseudo_hdr);
    PROTO_ITEM_SET_GENERATED(int_item);

    proto_tree_add_uint(int_tree, hf_erf_ehdr_t , tvb, 0, 0, (guint8)((hdr >> 56) & 0x7F));
    proto_tree_add_uint(int_tree, hf_erf_ehdr_bfs_hash, tvb, 0, 0, (guint32)((hdr >> 48) & 0xFF));
    proto_tree_add_uint(int_tree, hf_erf_ehdr_bfs_color, tvb, 0, 0, (guint32)((hdr >> 32) & 0xFFFF));
    proto_tree_add_uint(int_tree, hf_erf_ehdr_bfs_raw_hash, tvb, 0, 0, (guint32)(hdr & 0xFFFFFFFF));
  }
}

static int
channelised_fill_sdh_g707_format(sdh_g707_format_t* in_fmt, guint16 bit_flds, guint8 vc_size, guint8 speed)
{
  int i = 0; /* i = 4 --> ITU-T letter #E - index of AUG-64
        * i = 3 --> ITU-T letter #D - index of AUG-16
        * i = 2 --> ITU-T letter #C - index of AUG-4,
        * i = 1 --> ITU-T letter #B  -index of AUG-1
        * i = 0 --> ITU-T letter #A  - index of AU3*/

  if (0 == vc_size)
  {
    /* unknown / unsed container size*/
    return -1;
  }
  in_fmt->m_vc_size = vc_size;
  in_fmt->m_sdh_line_rate = speed;
  memset(&(in_fmt->m_vc_index_array[0]), 0xff, DECHAN_MAX_AUG_INDEX);

  /* for STM64 traffic, start from #E index shoud be 0 */
  in_fmt->m_vc_index_array[ speed - 1] = 0;
  /* for STM64 traffic,from #D and so on .. */
    for (i = (speed - 2); i >= 0; i--)
  {
    guint8 aug_n_index = 0;

    /*if AUG-n is bigger than vc-size*/
    if ( i >= (vc_size - 1))
    {
      /* check the value in bit flds */
      aug_n_index = ((bit_flds >> (2 *i))& 0x3) +1;
    }
    else
    {
      aug_n_index = 0;
    }
    in_fmt->m_vc_index_array[i] = aug_n_index;
  }
  return 0;
}

static void
channelised_fill_vc_id_string(char* out_string, int maxstrlen, sdh_g707_format_t* in_fmt)
{
  int i = 0;
  int cur_len = 0, print_index = 0;
  guint8 is_printed = 0;
  static char* g_vc_size_strings[] =  {
                  "unknown", /* 0x0 */
                  "VC3", /*0x1*/
                  "VC4", /*0x2*/
                  "VC4-4c", /*0x3*/
                  "VC4-16c", /*0x4*/
                  "VC4-64c", /*0x5*/
                  "VC4-256c", /*0x6*/};

  print_index = g_snprintf(out_string, maxstrlen,"%s(",g_vc_size_strings[in_fmt->m_vc_size]);

  if (in_fmt->m_sdh_line_rate <= 0 )
  {
    /* line rate is not given */
    for (i = (DECHAN_MAX_AUG_INDEX -1); i >= 0; i--)
    {
      if ( (in_fmt->m_vc_index_array[i] > 0) || (is_printed) )
      {
        cur_len = g_snprintf(out_string+print_index, maxstrlen,"%s%d",((is_printed)?", ":""),     in_fmt->m_vc_index_array[i]);
        print_index += cur_len;
        is_printed = 1;
      }
    }

  }
  else
  {
    for (i = in_fmt->m_sdh_line_rate - 2; i >= 0; i--)
    {
      cur_len = g_snprintf(out_string+print_index, maxstrlen,"%s%d",((is_printed)?", ":""),     in_fmt->m_vc_index_array[i]);
      print_index += cur_len;
      is_printed = 1;
    }
  }
  if ( ! is_printed )
  {
    /* Not printed . possibly its a ocXc packet with (0,0,0...) */
    for ( i =0; i < in_fmt->m_vc_size - 2; i++)
    {
      cur_len = g_snprintf(out_string+print_index, maxstrlen,"%s0",((is_printed)?", ":""));
      print_index += cur_len;
      is_printed = 1;
    }
  }
  g_snprintf(out_string+print_index, maxstrlen, ")");
  return;
}

static void
dissect_channelised_ex_header(tvbuff_t *tvb,  packet_info *pinfo, proto_tree *pseudo_hdr_tree, int idx)
{
  proto_item *int_item = NULL;
  proto_item *int_tree = NULL;
  guint64 hdr = pinfo->pseudo_header->erf.ehdr_list[idx].ehdr;
  sdh_g707_format_t g707_format;
  char vc_id_string[64] = {0};
  guint8 vc_id = (guint8)((hdr >> 24) & 0xFF);
  guint8 vc_size = (guint8)((hdr >> 16) & 0xFF);
  guint8 line_speed = (guint8)((hdr >> 8) & 0xFF);

  channelised_fill_sdh_g707_format(&g707_format, vc_id, vc_size, line_speed);
  channelised_fill_vc_id_string(vc_id_string, 64, &g707_format);

  if (pseudo_hdr_tree){
    int_item = proto_tree_add_text(pseudo_hdr_tree, tvb, 0, 0, "Channelised");
    int_tree = proto_item_add_subtree(int_item, ett_erf_pseudo_hdr);
    PROTO_ITEM_SET_GENERATED(int_item);

    proto_tree_add_uint(int_tree, hf_erf_ehdr_t, tvb, 0, 0, (guint8)((hdr >> 56) & 0x7F));
    proto_tree_add_boolean(int_tree, hf_erf_ehdr_chan_morebits, tvb, 0, 0, (guint8)((hdr >> 63) & 0x1));
    proto_tree_add_boolean(int_tree, hf_erf_ehdr_chan_morefrag, tvb, 0, 0, (guint8)((hdr >> 55) & 0x1));
    proto_tree_add_uint(int_tree, hf_erf_ehdr_chan_seqnum, tvb, 0, 0, (guint16)((hdr >> 40) & 0x7FFF));
    proto_tree_add_uint(int_tree, hf_erf_ehdr_chan_res, tvb, 0, 0, (guint8)((hdr >> 32) & 0xFF));
    proto_tree_add_uint(int_tree, hf_erf_ehdr_chan_virt_container_id, tvb, 0, 0, vc_id);
    proto_tree_add_text(int_tree, tvb, 0, 0, "Virtual Container ID (g.707): %s", vc_id_string);
    proto_tree_add_uint(int_tree, hf_erf_ehdr_chan_assoc_virt_container_size, tvb, 0, 0, vc_size);
    proto_tree_add_uint(int_tree, hf_erf_ehdr_chan_speed, tvb, 0, 0, line_speed);
    proto_tree_add_uint(int_tree, hf_erf_ehdr_chan_type, tvb, 0, 0, (guint8)((hdr >> 0) & 0xFF));
  }
}

static void
dissect_new_bfs_ex_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pseudo_hdr_tree, int idx)
{
  proto_item *int_item = NULL;
  proto_item *int_tree = NULL;
  guint64 hdr = pinfo->pseudo_header->erf.ehdr_list[idx].ehdr;

  if(pseudo_hdr_tree){
    int_item = proto_tree_add_text(pseudo_hdr_tree, tvb, 0, 0, "New BFS Filter/Hash");
    int_tree = proto_item_add_subtree(int_item, ett_erf_pseudo_hdr);
    PROTO_ITEM_SET_GENERATED(int_item);

    proto_tree_add_uint(int_tree, hf_erf_ehdr_t, tvb, 0, 0, (guint8)((hdr >> 56) & 0x7F));
    proto_tree_add_uint(int_tree, hf_erf_ehdr_new_bfs_payload_hash, tvb, 0, 0, (guint32)((hdr >> 32) & 0xFFFFFF));
    proto_tree_add_uint(int_tree, hf_erf_ehdr_new_bfs_color, tvb, 0, 0, (guint8)((hdr >> 24) & 0xFF));
    proto_tree_add_uint(int_tree, hf_erf_ehdr_new_bfs_flow_hash, tvb, 0, 0, (guint32)(hdr & 0xFFFFFF));
  }
}


static void
dissect_unknown_ex_header(tvbuff_t *tvb,  packet_info *pinfo, proto_tree *pseudo_hdr_tree, int idx)
{
  proto_item *unk_item= NULL;
  proto_tree *unk_tree = NULL;
  guint64 hdr = pinfo->pseudo_header->erf.ehdr_list[idx].ehdr;

  if (pseudo_hdr_tree){
    unk_item = proto_tree_add_text(pseudo_hdr_tree, tvb, 0, 0, "Unknown");
    unk_tree = proto_item_add_subtree(unk_item, ett_erf_pseudo_hdr);
    PROTO_ITEM_SET_GENERATED(unk_item);

    proto_tree_add_uint(unk_tree, hf_erf_ehdr_t , tvb, 0, 0, (guint8)((hdr >> 56) & 0x7F));
    proto_tree_add_uint64(unk_tree, hf_erf_ehdr_unk, tvb, 0, 0, hdr);
  }
}

static void
dissect_mc_hdlc_header(tvbuff_t *tvb,  packet_info *pinfo, proto_tree *tree)
{
  proto_item *mc_hdlc_item = NULL;
  proto_tree *mc_hdlc_tree = NULL;
  struct erf_mc_hdlc_hdrx * mc_hdlc;
  proto_item *pi;

  if (tree) {
    mc_hdlc_item = proto_tree_add_text(tree, tvb, 0, 0, "Multi Channel HDLC Header");
    mc_hdlc_tree = proto_item_add_subtree(mc_hdlc_item, ett_erf_mc_hdlc);
    PROTO_ITEM_SET_GENERATED(mc_hdlc_item);
    mc_hdlc = (struct erf_mc_hdlc_hdrx *) (&pinfo->pseudo_header->erf.subhdr.mc_hdr);

    proto_tree_add_uint(mc_hdlc_tree, hf_erf_mc_hdlc_cn, tvb, 0, 0,  mc_hdlc->byte01);
    proto_tree_add_uint(mc_hdlc_tree, hf_erf_mc_hdlc_res1, tvb, 0, 0,  mc_hdlc->byte01);
    proto_tree_add_uint(mc_hdlc_tree, hf_erf_mc_hdlc_res2, tvb, 0, 0,  mc_hdlc->byte2);
    pi=proto_tree_add_uint(mc_hdlc_tree, hf_erf_mc_hdlc_fcse, tvb, 0, 0,  mc_hdlc->byte3);
    if (mc_hdlc->byte3 & MC_HDLC_FCSE_MASK)
      expert_add_info_format(pinfo, pi, PI_CHECKSUM, PI_ERROR, "ERF MC FCS Error");

    pi=proto_tree_add_uint(mc_hdlc_tree, hf_erf_mc_hdlc_sre,  tvb, 0, 0,  mc_hdlc->byte3);
    if (mc_hdlc->byte3 & MC_HDLC_SRE_MASK)
      expert_add_info_format(pinfo, pi, PI_CHECKSUM, PI_ERROR, "ERF MC Short Record Error, <5 bytes");

    pi=proto_tree_add_uint(mc_hdlc_tree, hf_erf_mc_hdlc_lre,  tvb, 0, 0,  mc_hdlc->byte3);
    if (mc_hdlc->byte3 & MC_HDLC_LRE_MASK)
      expert_add_info_format(pinfo, pi, PI_CHECKSUM, PI_ERROR, "ERF MC Long Record Error, >2047 bytes");

    pi=proto_tree_add_uint(mc_hdlc_tree, hf_erf_mc_hdlc_afe,  tvb, 0, 0,  mc_hdlc->byte3);
    if (mc_hdlc->byte3 & MC_HDLC_AFE_MASK)
      expert_add_info_format(pinfo, pi, PI_CHECKSUM, PI_ERROR, "ERF MC Aborted Frame Error");

    pi=proto_tree_add_uint(mc_hdlc_tree, hf_erf_mc_hdlc_oe,   tvb, 0, 0,  mc_hdlc->byte3);
    if (mc_hdlc->byte3 & MC_HDLC_OE_MASK)
      expert_add_info_format(pinfo, pi, PI_CHECKSUM, PI_ERROR, "ERF MC Octet Error, the closing flag was not octet aligned after bit unstuffing");

    pi=proto_tree_add_uint(mc_hdlc_tree, hf_erf_mc_hdlc_lbe,  tvb, 0, 0,  mc_hdlc->byte3);
    if (mc_hdlc->byte3 & MC_HDLC_LBE_MASK)
      expert_add_info_format(pinfo, pi, PI_CHECKSUM, PI_ERROR, "ERF MC Lost Byte Error");

    proto_tree_add_uint(mc_hdlc_tree, hf_erf_mc_hdlc_first, tvb, 0, 0,  mc_hdlc->byte3);
    proto_tree_add_uint(mc_hdlc_tree, hf_erf_mc_hdlc_res3,  tvb, 0, 0,  mc_hdlc->byte3);

  }
}

static void
dissect_mc_raw_header(tvbuff_t *tvb,  packet_info *pinfo, proto_tree *tree)
{
  proto_item *mc_raw_item = NULL;
  proto_tree *mc_raw_tree = NULL;
  struct erf_mc_raw_hdrx * mc_raw;

  if (tree) {
    mc_raw_item = proto_tree_add_text(tree, tvb, 0, 0, "Multi Channel RAW Header");
    mc_raw_tree = proto_item_add_subtree(mc_raw_item, ett_erf_mc_raw);
    PROTO_ITEM_SET_GENERATED(mc_raw_item);
    mc_raw = (struct erf_mc_raw_hdrx *) (&pinfo->pseudo_header->erf.subhdr.mc_hdr);

    proto_tree_add_uint(mc_raw_tree, hf_erf_mc_raw_int,  tvb, 0, 0, mc_raw->byte0);
    proto_tree_add_uint(mc_raw_tree, hf_erf_mc_raw_res1, tvb, 0, 0, mc_raw->byte0);
    proto_tree_add_uint(mc_raw_tree, hf_erf_mc_raw_res2, tvb, 0, 0, mc_raw->byte12);
    proto_tree_add_uint(mc_raw_tree, hf_erf_mc_raw_res3, tvb, 0, 0, mc_raw->byte3);
    proto_tree_add_uint(mc_raw_tree, hf_erf_mc_raw_sre, tvb, 0, 0, mc_raw->byte3);
    proto_tree_add_uint(mc_raw_tree, hf_erf_mc_raw_lre,  tvb, 0, 0, mc_raw->byte3);
    proto_tree_add_uint(mc_raw_tree, hf_erf_mc_raw_res4, tvb, 0, 0, mc_raw->byte3);
    proto_tree_add_uint(mc_raw_tree, hf_erf_mc_raw_lbe, tvb, 0, 0, mc_raw->byte3);
    proto_tree_add_uint(mc_raw_tree, hf_erf_mc_raw_first, tvb, 0, 0, mc_raw->byte3);
    proto_tree_add_uint(mc_raw_tree, hf_erf_mc_raw_res5, tvb, 0, 0, mc_raw->byte3);
  }
}

static void
dissect_mc_atm_header(tvbuff_t *tvb,  packet_info *pinfo, proto_tree *tree)
{
  proto_item *mc_atm_item = NULL;
  proto_tree *mc_atm_tree = NULL;
  struct erf_mc_atm_hdrx * mc_atm;

  if (tree) {
    mc_atm_item = proto_tree_add_text(tree, tvb, 0, 0, "Multi Channel ATM Header");
    mc_atm_tree = proto_item_add_subtree(mc_atm_item, ett_erf_mc_atm);
    PROTO_ITEM_SET_GENERATED(mc_atm_item);
    mc_atm = (struct erf_mc_atm_hdrx *) (&pinfo->pseudo_header->erf.subhdr.mc_hdr);

    proto_tree_add_uint(mc_atm_tree, hf_erf_mc_atm_cn,   tvb, 0, 0, mc_atm->byte01);
    proto_tree_add_uint(mc_atm_tree, hf_erf_mc_atm_res1, tvb, 0, 0, mc_atm->byte01);
    proto_tree_add_uint(mc_atm_tree, hf_erf_mc_atm_mul,  tvb, 0, 0, mc_atm->byte01);

    proto_tree_add_uint(mc_atm_tree, hf_erf_mc_atm_port, tvb, 0, 0, mc_atm->byte2);
    proto_tree_add_uint(mc_atm_tree, hf_erf_mc_atm_res2, tvb, 0, 0, mc_atm->byte2);

    proto_tree_add_uint(mc_atm_tree, hf_erf_mc_atm_lbe,     tvb, 0, 0, mc_atm->byte3);
    proto_tree_add_uint(mc_atm_tree, hf_erf_mc_atm_hec,     tvb, 0, 0, mc_atm->byte3);
    proto_tree_add_uint(mc_atm_tree, hf_erf_mc_atm_crc10,   tvb, 0, 0, mc_atm->byte3);
    proto_tree_add_uint(mc_atm_tree, hf_erf_mc_atm_oamcell, tvb, 0, 0, mc_atm->byte3);
    proto_tree_add_uint(mc_atm_tree, hf_erf_mc_atm_first,   tvb, 0, 0, mc_atm->byte3);
    proto_tree_add_uint(mc_atm_tree, hf_erf_mc_atm_res3,    tvb, 0, 0, mc_atm->byte3);
  }
}

static void
dissect_mc_rawlink_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *mc_rawl_item = NULL;
  proto_tree *mc_rawl_tree = NULL;
  struct erf_mc_rawl_hdrx * mc_rawl;

  if (tree) {
    mc_rawl_item = proto_tree_add_text(tree, tvb, 0, 0, "Multi Channel RAW Link Header");
    mc_rawl_tree = proto_item_add_subtree(mc_rawl_item, ett_erf_mc_rawlink);
    PROTO_ITEM_SET_GENERATED(mc_rawl_item);
    mc_rawl = (struct erf_mc_rawl_hdrx *) (&pinfo->pseudo_header->erf.subhdr.mc_hdr);

    proto_tree_add_uint(mc_rawl_tree, hf_erf_mc_rawl_cn, tvb, 0, 0, mc_rawl->byte01);
    proto_tree_add_uint(mc_rawl_tree, hf_erf_mc_rawl_res2,  tvb, 0, 0, mc_rawl->byte3);
    proto_tree_add_uint(mc_rawl_tree, hf_erf_mc_rawl_lbe,   tvb, 0, 0, mc_rawl->byte3);
    proto_tree_add_uint(mc_rawl_tree, hf_erf_mc_rawl_first, tvb, 0, 0, mc_rawl->byte3);
    proto_tree_add_uint(mc_rawl_tree, hf_erf_mc_rawl_res3,  tvb, 0, 0, mc_rawl->byte3);
  }
}

static void
dissect_mc_aal5_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *mc_aal5_item = NULL;
  proto_tree *mc_aal5_tree = NULL;
  struct erf_mc_aal5_hdrx * mc_aal5;

  if (tree) {
    mc_aal5_item = proto_tree_add_text(tree, tvb, 0, 0, "Multi Channel AAL5 Header");
    mc_aal5_tree = proto_item_add_subtree(mc_aal5_item, ett_erf_mc_aal5);
    PROTO_ITEM_SET_GENERATED(mc_aal5_item);
    mc_aal5 = (struct erf_mc_aal5_hdrx *) (&pinfo->pseudo_header->erf.subhdr.mc_hdr);

    proto_tree_add_uint(mc_aal5_tree, hf_erf_mc_aal5_cn,   tvb, 0, 0, mc_aal5->byte01);
    proto_tree_add_uint(mc_aal5_tree, hf_erf_mc_aal5_res1, tvb, 0, 0, mc_aal5->byte01);

    proto_tree_add_uint(mc_aal5_tree, hf_erf_mc_aal5_port,  tvb, 0, 0, mc_aal5->byte2);
    proto_tree_add_uint(mc_aal5_tree, hf_erf_mc_aal5_crcck, tvb, 0, 0, mc_aal5->byte2);
    proto_tree_add_uint(mc_aal5_tree, hf_erf_mc_aal5_crce,  tvb, 0, 0, mc_aal5->byte2);
    proto_tree_add_uint(mc_aal5_tree, hf_erf_mc_aal5_lenck, tvb, 0, 0, mc_aal5->byte2);
    proto_tree_add_uint(mc_aal5_tree, hf_erf_mc_aal5_lene,  tvb, 0, 0, mc_aal5->byte2);

    proto_tree_add_uint(mc_aal5_tree, hf_erf_mc_aal5_res2,  tvb, 0, 0, mc_aal5->byte3);
    proto_tree_add_uint(mc_aal5_tree, hf_erf_mc_aal5_first, tvb, 0, 0, mc_aal5->byte3);
    proto_tree_add_uint(mc_aal5_tree, hf_erf_mc_aal5_res3,  tvb, 0, 0, mc_aal5->byte3);
  }
}

static void
dissect_mc_aal2_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *mc_aal2_item = NULL;
  proto_tree *mc_aal2_tree = NULL;
  struct erf_mc_aal2_hdrx * mc_aal2;

  if (tree) {
    mc_aal2_item = proto_tree_add_text(tree, tvb, 0, 0, "Multi Channel AAL2 Header");
    mc_aal2_tree = proto_item_add_subtree(mc_aal2_item, ett_erf_mc_aal2);
    PROTO_ITEM_SET_GENERATED(mc_aal2_item);
    mc_aal2 = (struct erf_mc_aal2_hdrx *) (&pinfo->pseudo_header->erf.subhdr.mc_hdr);

    proto_tree_add_uint(mc_aal2_tree, hf_erf_mc_aal2_cn,   tvb, 0, 0, mc_aal2->byte01);
    proto_tree_add_uint(mc_aal2_tree, hf_erf_mc_aal2_res1, tvb, 0, 0, mc_aal2->byte01);
    proto_tree_add_uint(mc_aal2_tree, hf_erf_mc_aal2_res2, tvb, 0, 0, mc_aal2->byte01);

    proto_tree_add_uint(mc_aal2_tree, hf_erf_mc_aal2_port, tvb, 0, 0, mc_aal2->byte2);
    proto_tree_add_uint(mc_aal2_tree, hf_erf_mc_aal2_res3, tvb, 0, 0, mc_aal2->byte2);
    proto_tree_add_uint(mc_aal2_tree, hf_erf_mc_aal2_first, tvb, 0, 0, mc_aal2->byte2);
    proto_tree_add_uint(mc_aal2_tree, hf_erf_mc_aal2_maale, tvb, 0, 0, mc_aal2->byte2);
    proto_tree_add_uint(mc_aal2_tree, hf_erf_mc_aal2_lene,  tvb, 0, 0, mc_aal2->byte2);

    proto_tree_add_uint(mc_aal2_tree, hf_erf_mc_aal2_cid,    tvb, 0, 0, mc_aal2->byte3);
  }
}

static void
dissect_aal2_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *aal2_item = NULL;
  proto_tree *aal2_tree = NULL;
  struct erf_aal2_hdrx * aal2;

  if (tree) {
    aal2_item = proto_tree_add_text(tree, tvb, 0, 0, "AAL2 Header");
    aal2_tree = proto_item_add_subtree(aal2_item, ett_erf_aal2);
    PROTO_ITEM_SET_GENERATED(aal2_item);
    aal2 = (struct erf_aal2_hdrx*) (&pinfo->pseudo_header->erf.subhdr.mc_hdr);

    proto_tree_add_uint(aal2_tree, hf_erf_aal2_cid,   tvb, 0, 0, aal2->byte0);

    proto_tree_add_uint(aal2_tree, hf_erf_aal2_maale, tvb, 0, 0, aal2->byte1);

    proto_tree_add_uint(aal2_tree, hf_erf_aal2_maalei, tvb, 0, 0, aal2->byte23);
    proto_tree_add_uint(aal2_tree, hf_erf_aal2_first, tvb, 0, 0, aal2->byte23);
    proto_tree_add_uint(aal2_tree, hf_erf_aal2_res1, tvb, 0, 0, aal2->byte23);

  }
}

static void
dissect_eth_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *eth_item = NULL;
  proto_tree *eth_tree = NULL;
  struct erf_eth_hdrx * eth_hdr;

  if (tree) {
    eth_item = proto_tree_add_text(tree, tvb, 0, 0, "Ethernet Header");
    eth_tree = proto_item_add_subtree(eth_item, ett_erf_eth);
    PROTO_ITEM_SET_GENERATED(eth_item);
    eth_hdr = (struct erf_eth_hdrx *) (&pinfo->pseudo_header->erf.subhdr.eth_hdr);

    proto_tree_add_uint(eth_tree, hf_erf_eth_off, tvb, 0, 0, eth_hdr->byte0);
    proto_tree_add_uint(eth_tree, hf_erf_eth_res1, tvb, 0, 0, eth_hdr->byte1);
  }
}

static void
dissect_erf_pseudo_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *pi;
  proto_item *pseudo_hdr_item = NULL, *flags_item = NULL, *types_item = NULL;
  proto_tree *pseudo_hdr_tree = NULL, *flags_tree = NULL, *types_tree = NULL;

  pseudo_hdr_item = proto_tree_add_text(tree, tvb, 0, 0, "ERF Header");
  pseudo_hdr_tree = proto_item_add_subtree(pseudo_hdr_item, ett_erf_pseudo_hdr);
  PROTO_ITEM_SET_GENERATED( pseudo_hdr_item);

  proto_tree_add_uint64(pseudo_hdr_tree, hf_erf_ts, tvb, 0, 0, pinfo->pseudo_header->erf.phdr.ts);

  types_item = proto_tree_add_text(pseudo_hdr_tree, tvb, 0, 0, "Header type");
  PROTO_ITEM_SET_GENERATED(types_item);

  types_tree = proto_item_add_subtree(types_item, ett_erf_types);
  proto_tree_add_uint(types_tree, hf_erf_type, tvb, 0, 0, pinfo->pseudo_header->erf.phdr.type);
  proto_tree_add_uint(types_tree, hf_erf_ehdr, tvb, 0, 0, pinfo->pseudo_header->erf.phdr.type);

  flags_item=proto_tree_add_uint(pseudo_hdr_tree, hf_erf_flags, tvb, 0, 0, pinfo->pseudo_header->erf.phdr.flags);
  flags_tree = proto_item_add_subtree(flags_item, ett_erf_flags);

  proto_tree_add_uint(flags_tree, hf_erf_flags_cap, tvb, 0, 0, pinfo->pseudo_header->erf.phdr.flags);
  proto_tree_add_uint(flags_tree, hf_erf_flags_vlen, tvb, 0, 0, pinfo->pseudo_header->erf.phdr.flags);
  pi=proto_tree_add_uint(flags_tree, hf_erf_flags_trunc, tvb, 0, 0, pinfo->pseudo_header->erf.phdr.flags);
  if (pinfo->pseudo_header->erf.phdr.flags & ERF_HDR_TRUNC_MASK)
    expert_add_info_format(pinfo, pi, PI_CHECKSUM, PI_ERROR, "ERF Truncation Error");

  pi=proto_tree_add_uint(flags_tree, hf_erf_flags_rxe, tvb, 0, 0, pinfo->pseudo_header->erf.phdr.flags);
  if (pinfo->pseudo_header->erf.phdr.flags & ERF_HDR_RXE_MASK)
    expert_add_info_format(pinfo, pi, PI_CHECKSUM, PI_ERROR, "ERF Rx Error");

  pi=proto_tree_add_uint(flags_tree, hf_erf_flags_dse, tvb, 0, 0, pinfo->pseudo_header->erf.phdr.flags);
  if (pinfo->pseudo_header->erf.phdr.flags & ERF_HDR_DSE_MASK)
    expert_add_info_format(pinfo, pi, PI_CHECKSUM, PI_ERROR, "ERF DS Error");

  proto_tree_add_uint(flags_tree, hf_erf_flags_res, tvb, 0, 0, pinfo->pseudo_header->erf.phdr.flags);

  proto_tree_add_uint(pseudo_hdr_tree, hf_erf_rlen, tvb, 0, 0, pinfo->pseudo_header->erf.phdr.rlen);
  pi=proto_tree_add_uint(pseudo_hdr_tree, hf_erf_lctr, tvb, 0, 0, pinfo->pseudo_header->erf.phdr.lctr);
  if (pinfo->pseudo_header->erf.phdr.lctr > 0)
    expert_add_info_format(pinfo, pi, PI_SEQUENCE, PI_WARN, "Packet loss occurred between previous and current packet");

  proto_tree_add_uint(pseudo_hdr_tree, hf_erf_wlen, tvb, 0, 0, pinfo->pseudo_header->erf.phdr.wlen);
}

static void
dissect_erf_pseudo_extension_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *pi;
  proto_item *pseudo_hdr_item = NULL;
  proto_tree *pseudo_hdr_tree = NULL;
  guint8 type;
  guint8 has_more = pinfo->pseudo_header->erf.phdr.type & 0x80;
  int i = 0;
  int max = sizeof(pinfo->pseudo_header->erf.ehdr_list)/sizeof(struct erf_ehdr);

  pseudo_hdr_item = proto_tree_add_text(tree, tvb, 0, 0, "ERF Extension Headers");
  pseudo_hdr_tree = proto_item_add_subtree(pseudo_hdr_item, ett_erf_pseudo_hdr);
  PROTO_ITEM_SET_GENERATED(pseudo_hdr_item);

  while(has_more && i < max){
    type = (guint8) (pinfo->pseudo_header->erf.ehdr_list[i].ehdr >> 56);

    switch(type & 0x7f){
    case EXT_HDR_TYPE_CLASSIFICATION:
      dissect_classification_ex_header(tvb, pinfo, pseudo_hdr_tree, i);
      break;
    case EXT_HDR_TYPE_INTERCEPTID:
      dissect_intercept_ex_header(tvb, pinfo, pseudo_hdr_tree, i);
      break;
    case EXT_HDR_TYPE_RAW_LINK:
      dissect_raw_link_ex_header(tvb, pinfo, pseudo_hdr_tree, i);
      break;
    case EXT_HDR_TYPE_BFS:
      dissect_bfs_ex_header(tvb, pinfo, pseudo_hdr_tree, i);
      break;
	  case EXT_HDR_TYPE_CHANNELISED:
      dissect_channelised_ex_header(tvb, pinfo, pseudo_hdr_tree, i);
	    break;
    case EXT_HDR_TYPE_NEW_BFS:
      dissect_new_bfs_ex_header(tvb, pinfo, pseudo_hdr_tree, i);
      break;
    default:
      dissect_unknown_ex_header(tvb, pinfo, pseudo_hdr_tree, i);
      break;
    }
    has_more = type & 0x80;
    i++;
  }
  if (has_more){
    pi = proto_tree_add_text(pseudo_hdr_tree, tvb, 0, 0, "More extension header present");
    expert_add_info_format(pinfo, pi, PI_SEQUENCE, PI_WARN, "Some of the extension headers are not shown");
  }

}

static void
dissect_erf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint8 flags;
  guint8 erf_type;
  guint32 atm_hdr=0;
  proto_item *erf_item = NULL;
  proto_tree *erf_tree = NULL;
  guint atm_pdu_caplen;
  const guint8 *atm_pdu;
  erf_hdlc_type_vals hdlc_type;
  guint8 first_byte;
  tvbuff_t *new_tvb;
  guint8 aal2_cid;

  erf_type=pinfo->pseudo_header->erf.phdr.type & 0x7F;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ERF");

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
       val_to_str(erf_type, erf_type_vals, "Unknown type %u"));
  }

  if (tree) {
    erf_item = proto_tree_add_item(tree, proto_erf, tvb, 0, -1, ENC_NA);
    erf_tree = proto_item_add_subtree(erf_item, ett_erf);

    dissect_erf_pseudo_header(tvb, pinfo, erf_tree);
    if (pinfo->pseudo_header->erf.phdr.type & 0x80){
      dissect_erf_pseudo_extension_header(tvb, pinfo, erf_tree);
    }
  }

  flags = pinfo->pseudo_header->erf.phdr.flags;
  /*
   * Set if frame is Received or Sent.
   * XXX - this is really testing the low-order bit of the capture
   * interface number, so interface 0 is assumed to be capturing
   * in one direction on a bi-directional link, interface 1 is
   * assumed to be capturing in the other direction on that link,
   * and interfaces 2 and 3 are assumed to be capturing in two
   * different directions on another link.  We don't distinguish
   * between the two links.
   */
  pinfo->p2p_dir = ( (flags & 0x01) ? P2P_DIR_RECV : P2P_DIR_SENT);

  switch(erf_type) {

  case ERF_TYPE_RAW_LINK:
    call_dissector(data_handle, tvb, pinfo, erf_tree);
    break;

  case ERF_TYPE_IPV4:
    if (ipv4_handle)
      call_dissector(ipv4_handle, tvb, pinfo, erf_tree);
    else
      call_dissector(data_handle, tvb, pinfo, erf_tree);
    break;

  case ERF_TYPE_IPV6:
    if (ipv6_handle)
      call_dissector(ipv6_handle, tvb, pinfo, erf_tree);
    else
      call_dissector(data_handle, tvb, pinfo, erf_tree);
    break;

  case ERF_TYPE_INFINIBAND:
    if (infiniband_handle)
      call_dissector(infiniband_handle, tvb, pinfo, erf_tree);
    else
      call_dissector(data_handle, tvb, pinfo, erf_tree);
    break;

  case ERF_TYPE_INFINIBAND_LINK:
    if (infiniband_link_handle)
      call_dissector(infiniband_link_handle, tvb, pinfo, erf_tree);
    else
      call_dissector(data_handle, tvb, pinfo, erf_tree);
    break;

  case ERF_TYPE_LEGACY:
  case ERF_TYPE_IP_COUNTER:
  case ERF_TYPE_TCP_FLOW_COUNTER:
    /* undefined */
    break;

  case ERF_TYPE_PAD:
    /* Nothing to do */
    break;

  case ERF_TYPE_MC_RAW:
    dissect_mc_raw_header(tvb, pinfo, erf_tree);
    if (data_handle)
      call_dissector(data_handle, tvb, pinfo, tree);
    break;

  case ERF_TYPE_MC_RAW_CHANNEL:
    dissect_mc_rawlink_header(tvb, pinfo, erf_tree);
    if (data_handle)
      call_dissector(data_handle, tvb, pinfo, tree);
    break;

  case ERF_TYPE_MC_ATM:
    dissect_mc_atm_header(tvb, pinfo, erf_tree);
    /* continue with type ATM */

  case ERF_TYPE_ATM:
    memset(&pinfo->pseudo_header->atm, 0, sizeof(pinfo->pseudo_header->atm));
    atm_hdr = tvb_get_ntohl(tvb, 0);
    pinfo->pseudo_header->atm.vpi = ((atm_hdr & 0x0ff00000) >> 20);
    pinfo->pseudo_header->atm.vci = ((atm_hdr & 0x000ffff0) >>  4);
    pinfo->pseudo_header->atm.channel = (flags & 0x03);

    /* Work around to have decoding working */
    if (erf_rawcell_first) {
      new_tvb = tvb_new_subset_remaining(tvb, ATM_HDR_LENGTH);
      /* Treat this as a (short) ATM AAL5 PDU */
      pinfo->pseudo_header->atm.aal = AAL_5;
      switch (erf_aal5_type) {

      case ERF_AAL5_GUESS:
        pinfo->pseudo_header->atm.type = TRAF_UNKNOWN;
        pinfo->pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
        /* Try to guess the type according to the first bytes */
        atm_pdu_caplen = tvb_length(new_tvb);
        atm_pdu = tvb_get_ptr(new_tvb, 0, atm_pdu_caplen);
        erf_atm_guess_traffic_type(atm_pdu, atm_pdu_caplen, pinfo->pseudo_header);
        break;

      case ERF_AAL5_LLC:
        pinfo->pseudo_header->atm.type = TRAF_LLCMX;
        pinfo->pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
        break;

      case ERF_AAL5_UNSPEC:
        pinfo->pseudo_header->atm.aal = AAL_5;
        pinfo->pseudo_header->atm.type = TRAF_UNKNOWN;
        pinfo->pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
        break;
      }

      call_dissector(atm_untruncated_handle, new_tvb, pinfo, tree);
    } else {
      /* Treat this as a raw cell */
      pinfo->pseudo_header->atm.flags |= ATM_RAW_CELL;
      pinfo->pseudo_header->atm.flags |= ATM_NO_HEC;
      pinfo->pseudo_header->atm.aal = AAL_UNKNOWN;
      /* can call atm_untruncated because we set ATM_RAW_CELL flag */
      call_dissector(atm_untruncated_handle, tvb, pinfo, tree);
    }
    break;

  case ERF_TYPE_MC_AAL5:
    dissect_mc_aal5_header(tvb, pinfo, erf_tree);
    /* continue with type AAL5 */

  case ERF_TYPE_AAL5:
    atm_hdr = tvb_get_ntohl(tvb, 0);
    memset(&pinfo->pseudo_header->atm, 0, sizeof(pinfo->pseudo_header->atm));
    pinfo->pseudo_header->atm.vpi = ((atm_hdr & 0x0ff00000) >> 20);
    pinfo->pseudo_header->atm.vci = ((atm_hdr & 0x000ffff0) >>  4);
    pinfo->pseudo_header->atm.channel = (flags & 0x03);

    new_tvb = tvb_new_subset_remaining(tvb, ATM_HDR_LENGTH);
    /* Work around to have decoding working */
    pinfo->pseudo_header->atm.aal = AAL_5;
    switch (erf_aal5_type) {

    case ERF_AAL5_GUESS:
      pinfo->pseudo_header->atm.type = TRAF_UNKNOWN;
      pinfo->pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
      /* Try to guess the type according to the first bytes */
      atm_pdu_caplen = tvb_length(new_tvb);
      atm_pdu = tvb_get_ptr(new_tvb, 0, atm_pdu_caplen);
      erf_atm_guess_traffic_type(atm_pdu, atm_pdu_caplen, pinfo->pseudo_header);
      break;

    case ERF_AAL5_LLC:
      pinfo->pseudo_header->atm.type = TRAF_LLCMX;
      pinfo->pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
      break;

    case ERF_AAL5_UNSPEC:
      pinfo->pseudo_header->atm.aal = AAL_5;
      pinfo->pseudo_header->atm.type = TRAF_UNKNOWN;
      pinfo->pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;
      break;
    }

    call_dissector(atm_untruncated_handle, new_tvb, pinfo, tree);
    break;

  case ERF_TYPE_MC_AAL2:
    dissect_mc_aal2_header(tvb, pinfo, erf_tree);

    /*
     * ERF_TYPE_MC_AAL2 MC pseudoheader is not included in tvb,
     * and we do not supply 'dct2000' pseudoheader.
     */

    atm_hdr = tvb_get_ntohl(tvb, 0);
    aal2_cid = ((struct erf_mc_aal2_hdrx *)(&pinfo->pseudo_header->erf.subhdr.mc_hdr))->byte3;

    /* Change wtap pseudo_header from erf to atm for atm dissector */
    memset(&pinfo->pseudo_header->atm, 0, sizeof(pinfo->pseudo_header->atm));

    /* fill in atm pseudo header */
    pinfo->pseudo_header->atm.aal = AAL_2;
    pinfo->pseudo_header->atm.flags |= ATM_AAL2_NOPHDR;
    pinfo->pseudo_header->atm.vpi = ((atm_hdr & 0x0ff00000) >> 20);
    pinfo->pseudo_header->atm.vci = ((atm_hdr & 0x000ffff0) >>  4);
    pinfo->pseudo_header->atm.channel = (flags & 0x03);
    pinfo->pseudo_header->atm.aal2_cid = aal2_cid;
    pinfo->pseudo_header->atm.type = TRAF_UNKNOWN;
    pinfo->pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;

    /* remove ATM cell header from tvb */
    new_tvb = tvb_new_subset_remaining(tvb, ATM_HDR_LENGTH);
    call_dissector(atm_untruncated_handle, new_tvb, pinfo, tree);
    break;

  case ERF_TYPE_AAL2:
    dissect_aal2_header(tvb, pinfo, erf_tree);

    /*
     * We removed the ERF_TYPE_AAL2 'ext' pseudoheader in wtap,
     * and do not supply the 'dct2000' pseudoheader.
     */

    atm_hdr = tvb_get_ntohl(tvb, 0);
    aal2_cid = ((struct erf_aal2_hdrx *)(&pinfo->pseudo_header->erf.subhdr.mc_hdr))->byte0;

    /* Change wtap pseudo_header from erf to atm for atm dissector */
    memset(&pinfo->pseudo_header->atm, 0, sizeof(pinfo->pseudo_header->atm));

    /* fill in atm pseudo header */
    pinfo->pseudo_header->atm.aal = AAL_2;
    pinfo->pseudo_header->atm.flags |= ATM_AAL2_NOPHDR;
    pinfo->pseudo_header->atm.vpi = ((atm_hdr & 0x0ff00000) >> 20);
    pinfo->pseudo_header->atm.vci = ((atm_hdr & 0x000ffff0) >>  4);
    pinfo->pseudo_header->atm.channel = (flags & 0x03);
    pinfo->pseudo_header->atm.type = TRAF_UNKNOWN;
    pinfo->pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;

    /* remove ATM cell header from tvb */
    new_tvb = tvb_new_subset_remaining(tvb, ATM_HDR_LENGTH);
    call_dissector(atm_untruncated_handle, new_tvb, pinfo, tree);
    break;

  case ERF_TYPE_ETH:
  case ERF_TYPE_COLOR_ETH:
  case ERF_TYPE_DSM_COLOR_ETH:
    dissect_eth_header(tvb, pinfo, erf_tree);
    if (erf_ethfcs)
      call_dissector(ethwithfcs_handle, tvb, pinfo, tree);
    else
      call_dissector(ethwithoutfcs_handle, tvb, pinfo, tree);
    break;

  case ERF_TYPE_MC_HDLC:
    dissect_mc_hdlc_header(tvb, pinfo, erf_tree);
    /* continue with type HDLC */

  case ERF_TYPE_HDLC_POS:
  case ERF_TYPE_COLOR_HDLC_POS:
  case ERF_TYPE_DSM_COLOR_HDLC_POS:
  case ERF_TYPE_COLOR_MC_HDLC_POS:
    hdlc_type = erf_hdlc_type;

    if (hdlc_type == ERF_HDLC_GUESS) {
      /* Try to guess the type. */
      first_byte = tvb_get_guint8(tvb, 0);
      if (first_byte == 0x0f || first_byte == 0x8f)
        hdlc_type = ERF_HDLC_CHDLC;
      else {
        /* Anything to check for to recognize Frame Relay or MTP2?
           Should we require PPP packets to beging with FF 03? */
        hdlc_type = ERF_HDLC_PPP;
      }
    }
    /* Clean the pseudo header (if used in subdissector) and call the
       appropriate subdissector. */
    switch (hdlc_type) {
    case ERF_HDLC_CHDLC:
      call_dissector(chdlc_handle, tvb, pinfo, tree);
      break;
    case ERF_HDLC_PPP:
      call_dissector(ppp_handle, tvb, pinfo, tree);
      break;
    case ERF_HDLC_FRELAY:
      memset(&pinfo->pseudo_header->x25, 0, sizeof(pinfo->pseudo_header->x25));
      call_dissector(frelay_handle, tvb, pinfo, tree);
      break;
    case ERF_HDLC_MTP2:
      /* not used, but .. */
      memset(&pinfo->pseudo_header->mtp2, 0, sizeof(pinfo->pseudo_header->mtp2));
      call_dissector(mtp2_handle, tvb, pinfo, tree);
      break;
    default:
      break;
    }
    break;

  default:
    break;
  } /* erf type */
}

void
proto_register_erf(void)
{

  static hf_register_info hf[] = {
    /* ERF Header */
    { &hf_erf_ts, { "Timestamp", "erf.ts", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_erf_type, { "type", "erf.types.type", FT_UINT8, BASE_DEC,  VALS(erf_type_vals), ERF_HDR_TYPE_MASK, NULL, HFILL } },
    { &hf_erf_ehdr, { "Extension header present", "erf.types.ext_header", FT_UINT8, BASE_DEC,  NULL, ERF_HDR_EHDR_MASK, NULL, HFILL } },
    { &hf_erf_flags,{ "flags", "erf.flags", FT_UINT8, BASE_DEC, NULL, ERF_HDR_FLAGS_MASK, NULL, HFILL } },
    { &hf_erf_flags_cap,{ "capture interface", "erf.flags.cap", FT_UINT8, BASE_DEC, NULL, ERF_HDR_CAP_MASK, NULL, HFILL } },
    { &hf_erf_flags_vlen,{ "varying record length", "erf.flags.vlen", FT_UINT8, BASE_DEC, NULL, ERF_HDR_VLEN_MASK, NULL, HFILL } },
    { &hf_erf_flags_trunc,{ "truncated", "erf.flags.trunc", FT_UINT8, BASE_DEC, NULL, ERF_HDR_TRUNC_MASK, NULL, HFILL } },
    { &hf_erf_flags_rxe,{ "rx error", "erf.flags.rxe", FT_UINT8, BASE_DEC, NULL, ERF_HDR_RXE_MASK, NULL, HFILL } },
    { &hf_erf_flags_dse,{ "ds error", "erf.flags.dse", FT_UINT8, BASE_DEC, NULL, ERF_HDR_DSE_MASK, NULL, HFILL } },
    { &hf_erf_flags_res,{ "reserved", "erf.flags.res", FT_UINT8, BASE_DEC, NULL, ERF_HDR_RES_MASK, NULL, HFILL } },
    { &hf_erf_rlen, { "record length", "erf.rlen", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_erf_lctr, { "loss counter", "erf.lctr", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_erf_wlen, { "wire length", "erf.wlen", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    { &hf_erf_ehdr_t, { "Extension Type", "erf.ehdr.types", FT_UINT8, BASE_DEC,  VALS(ehdr_type_vals), 0x0, NULL, HFILL } },

    /* Intercept ID Extension Header */
    { &hf_erf_ehdr_int_res1, { "Reserved", "erf.ehdr.int.res1", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_erf_ehdr_int_id, { "Intercept ID", "erf.ehdr.int.intid", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_erf_ehdr_int_res2, { "Reserved", "erf.ehdr.int.res2", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    /* Raw Link Extension Header */
    { &hf_erf_ehdr_raw_link_res, { "Reserved", "erf.ehdr.raw.res", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_erf_ehdr_raw_link_seqnum, { "Sequence number", "erf.ehdr.raw.seqnum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_erf_ehdr_raw_link_rate, { "Rate", "erf.ehdr.raw.rate", FT_UINT8, BASE_DEC, VALS(raw_link_rates), 0x0, NULL, HFILL } },
    { &hf_erf_ehdr_raw_link_type, { "Link Type", "erf.ehdr.raw.link_type", FT_UINT8, BASE_DEC, VALS(raw_link_types), 0x0, NULL, HFILL } },

    /* Classification Extension Header */
    { &hf_erf_ehdr_class_flags, { "Flags", "erf.ehdr.class.flags", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_erf_ehdr_class_flags_sh, { "Search hit", "erf.ehdr.class.flags.sh", FT_UINT32, BASE_DEC, NULL, EHDR_CLASS_SH_MASK, NULL, HFILL } },
    { &hf_erf_ehdr_class_flags_shm, { "Multiple search hits", "erf.ehdr.class.flags.shm", FT_UINT32, BASE_DEC, NULL, EHDR_CLASS_SHM_MASK, NULL, HFILL } },
    { &hf_erf_ehdr_class_flags_res1, { "Reserved", "erf.ehdr.class.flags.res1", FT_UINT32, BASE_DEC, NULL, EHDR_CLASS_RES1_MASK, NULL, HFILL } },
    { &hf_erf_ehdr_class_flags_user, { "User classification", "erf.ehdr.class.flags.user", FT_UINT32, BASE_DEC, NULL, EHDR_CLASS_USER_MASK, NULL, HFILL } },
    { &hf_erf_ehdr_class_flags_res2, { "Reserved", "erf.ehdr.class.flags.res2", FT_UINT32, BASE_DEC, NULL, EHDR_CLASS_RES2_MASK, NULL, HFILL } },
    { &hf_erf_ehdr_class_flags_drop, { "Drop Steering Bit", "erf.ehdr.class.flags.drop", FT_UINT32, BASE_DEC, NULL, EHDR_CLASS_DROP_MASK, NULL, HFILL } },
    { &hf_erf_ehdr_class_flags_str, { "Stream Steering Bits", "erf.ehdr.class.flags.str", FT_UINT32, BASE_DEC, NULL, EHDR_CLASS_STER_MASK, NULL, HFILL } },
    { &hf_erf_ehdr_class_seqnum, { "Sequence number", "erf.ehdr.class.seqnum", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    /* BFS Extension Header */
    { &hf_erf_ehdr_bfs_hash, { "Hash", "erf.ehdr.bfs.hash", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_erf_ehdr_bfs_color, { "Filter Color", "erf.ehdr.bfs.color", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_erf_ehdr_bfs_raw_hash, { "Raw Hash", "erf.ehdr.bfs.rawhash", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },

    /* Channelised Extension Header */
    { &hf_erf_ehdr_chan_morebits, { "More Bits", "erf.ehdr.chan.morebits", FT_BOOLEAN, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_erf_ehdr_chan_morefrag, { "More Fragments", "erf.ehdr.chan.morefrag", FT_BOOLEAN, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_erf_ehdr_chan_seqnum, { "Sequence Number", "erf.ehdr.chan.seqnum", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_erf_ehdr_chan_res, { "Reserved", "erf.ehdr.chan.res", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_erf_ehdr_chan_virt_container_id, { "Virtual Container ID", "erf.ehdr.chan.vcid", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_erf_ehdr_chan_assoc_virt_container_size, { "Associated Virtual Container Size", "erf.ehdr.chan.vcsize", FT_UINT8, BASE_HEX, VALS(channelised_assoc_virt_container_size), 0, NULL, HFILL } },
    { &hf_erf_ehdr_chan_speed, { "Origin Line Type/Rate", "erf.ehdr.chan.rate", FT_UINT8, BASE_HEX, VALS(channelised_speed), 0, NULL, HFILL } },
    { &hf_erf_ehdr_chan_type, { "Frame Part Type", "erf.ehdr.chan.type", FT_UINT8, BASE_HEX, VALS(channelised_type), 0, NULL, HFILL } },

    /* New BFS Extension Header */
    { &hf_erf_ehdr_new_bfs_payload_hash, { "Payload Hash", "erf.hdr.newbfs.payloadhash", FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_erf_ehdr_new_bfs_color, { "Filter Color", "erf.hdr.newbfs.color", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_erf_ehdr_new_bfs_flow_hash, { "Flow Hash", "erf.hdr.newbfs.flowhash", FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL } },

    /* Unknown Extension Header */
    { &hf_erf_ehdr_unk, { "Data", "erf.ehdr.unknown.data", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    /* MC HDLC Header */
    { &hf_erf_mc_hdlc_cn,   { "connection number", "erf.mchdlc.cn", FT_UINT16, BASE_DEC, NULL, MC_HDLC_CN_MASK, NULL, HFILL } },
    { &hf_erf_mc_hdlc_res1, { "reserved", "erf.mchdlc.res1", FT_UINT16, BASE_DEC, NULL, MC_HDLC_RES1_MASK, NULL, HFILL } },
    { &hf_erf_mc_hdlc_res2, { "reserved", "erf.mchdlc.res2", FT_UINT8, BASE_DEC, NULL, MC_HDLC_RES2_MASK, NULL, HFILL } },
    { &hf_erf_mc_hdlc_fcse, { "FCS error", "erf.mchdlc.fcse", FT_UINT8, BASE_DEC, NULL, MC_HDLC_FCSE_MASK, NULL, HFILL } },
    { &hf_erf_mc_hdlc_sre,  { "Short record error", "erf.mchdlc.sre", FT_UINT8, BASE_DEC, NULL, MC_HDLC_SRE_MASK, NULL, HFILL } },
    { &hf_erf_mc_hdlc_lre,  { "Long record error", "erf.mchdlc.lre", FT_UINT8, BASE_DEC, NULL, MC_HDLC_LRE_MASK, NULL, HFILL } },
    { &hf_erf_mc_hdlc_afe,  { "Aborted frame error", "erf.mchdlc.afe", FT_UINT8, BASE_DEC, NULL, MC_HDLC_AFE_MASK, NULL, HFILL } },
    { &hf_erf_mc_hdlc_oe,   { "Octet error", "erf.mchdlc.oe", FT_UINT8, BASE_DEC, NULL, MC_HDLC_OE_MASK, NULL, HFILL } },
    { &hf_erf_mc_hdlc_lbe,  { "Lost byte error", "erf.mchdlc.lbe", FT_UINT8, BASE_DEC, NULL, MC_HDLC_LBE_MASK, NULL, HFILL } },
    { &hf_erf_mc_hdlc_first, { "First record", "erf.mchdlc.first", FT_UINT8, BASE_DEC, NULL, MC_HDLC_FIRST_MASK, NULL, HFILL } },
    { &hf_erf_mc_hdlc_res3, { "reserved", "erf.mchdlc.res3", FT_UINT8, BASE_DEC, NULL, MC_HDLC_RES3_MASK, NULL, HFILL } },

    /* MC RAW Header */
    { &hf_erf_mc_raw_int,   { "physical interface", "erf.mcraw.int", FT_UINT8, BASE_DEC, NULL, MC_RAW_INT_MASK, NULL, HFILL } },
    { &hf_erf_mc_raw_res1, { "reserved", "erf.mcraw.res1", FT_UINT8, BASE_DEC, NULL, MC_RAW_RES1_MASK, NULL, HFILL } },
    { &hf_erf_mc_raw_res2, { "reserved", "erf.mcraw.res2", FT_UINT16, BASE_DEC, NULL, MC_RAW_RES2_MASK, NULL, HFILL } },
    { &hf_erf_mc_raw_res3, { "reserved", "erf.mcraw.res3", FT_UINT8, BASE_DEC, NULL, MC_RAW_RES3_MASK, NULL, HFILL } },
    { &hf_erf_mc_raw_sre,  { "Short record error", "erf.mcraw.sre", FT_UINT8, BASE_DEC, NULL, MC_RAW_SRE_MASK, NULL, HFILL } },
    { &hf_erf_mc_raw_lre,  { "Long record error", "erf.mcraw.lre", FT_UINT8, BASE_DEC, NULL, MC_RAW_LRE_MASK, NULL, HFILL } },
    { &hf_erf_mc_raw_res4,  { "reserved", "erf.mcraw.res4", FT_UINT8, BASE_DEC, NULL, MC_RAW_RES4_MASK, NULL, HFILL } },
    { &hf_erf_mc_raw_lbe,  { "Lost byte error", "erf.mcraw.lbe", FT_UINT8, BASE_DEC, NULL, MC_RAW_LBE_MASK, NULL, HFILL } },
    { &hf_erf_mc_raw_first, { "First record", "erf.mcraw.first", FT_UINT8, BASE_DEC, NULL, MC_RAW_FIRST_MASK, NULL, HFILL } },
    { &hf_erf_mc_raw_res5, { "reserved", "erf.mcraw.res5", FT_UINT8, BASE_DEC, NULL, MC_RAW_RES5_MASK, NULL, HFILL } },

    /* MC ATM Header */
    { &hf_erf_mc_atm_cn,   { "connection number", "erf.mcatm.cn", FT_UINT16, BASE_DEC, NULL, MC_ATM_CN_MASK, NULL, HFILL } },
    { &hf_erf_mc_atm_res1, { "reserved", "erf.mcatm.res1", FT_UINT16, BASE_DEC, NULL, MC_ATM_RES1_MASK, NULL, HFILL } },
    { &hf_erf_mc_atm_mul,  { "multiplexed", "erf.mcatm.mul", FT_UINT16, BASE_DEC, NULL, MC_ATM_MUL_MASK, NULL, HFILL } },
    { &hf_erf_mc_atm_port, { "physical port", "erf.mcatm.port", FT_UINT8, BASE_DEC, NULL, MC_ATM_PORT_MASK, NULL, HFILL } },
    { &hf_erf_mc_atm_res2, { "reserved", "erf.mcatm.res2", FT_UINT8, BASE_DEC, NULL, MC_ATM_RES2_MASK, NULL, HFILL } },
    { &hf_erf_mc_atm_lbe,  { "Lost Byte Error", "erf.mcatm.lbe", FT_UINT8, BASE_DEC, NULL, MC_ATM_LBE_MASK, NULL, HFILL } },
    { &hf_erf_mc_atm_hec,  { "HEC corrected", "erf.mcatm.hec", FT_UINT8, BASE_DEC, NULL, MC_ATM_HEC_MASK, NULL, HFILL } },
    { &hf_erf_mc_atm_crc10, { "OAM Cell CRC10 Error (not implemented)", "erf.mcatm.crc10", FT_UINT8, BASE_DEC, NULL, MC_ATM_CRC10_MASK, NULL, HFILL } },
    { &hf_erf_mc_atm_oamcell,  { "OAM Cell", "erf.mcatm.oamcell", FT_UINT8, BASE_DEC, NULL, MC_ATM_OAMCELL_MASK, NULL, HFILL } },
    { &hf_erf_mc_atm_first, { "First record", "erf.mcatm.first", FT_UINT8, BASE_DEC, NULL, MC_ATM_FIRST_MASK, NULL, HFILL } },
    { &hf_erf_mc_atm_res3, { "reserved", "erf.mcatm.res3", FT_UINT8, BASE_DEC, NULL, MC_ATM_RES3_MASK, NULL, HFILL } },

    /* MC RAW Link Header */
    { &hf_erf_mc_rawl_cn,   { "connection number", "erf.mcrawl.cn", FT_UINT8, BASE_DEC, NULL, MC_RAWL_CN_MASK, NULL, HFILL } },
    { &hf_erf_mc_rawl_res2,  { "reserved", "erf.mcrawl.res2", FT_UINT8, BASE_DEC, NULL, MC_RAWL_RES2_MASK, NULL, HFILL } },
    { &hf_erf_mc_rawl_lbe,  { "Lost byte error", "erf.mcrawl.lbe", FT_UINT8, BASE_DEC, NULL, MC_RAWL_LBE_MASK, NULL, HFILL } },
    { &hf_erf_mc_rawl_first, { "First record", "erf.mcrawl.first", FT_UINT8, BASE_DEC, NULL, MC_RAWL_FIRST_MASK, NULL, HFILL } },
    { &hf_erf_mc_rawl_res3, { "reserved", "erf.mcrawl.res5", FT_UINT8, BASE_DEC, NULL, MC_RAWL_RES3_MASK, NULL, HFILL } },

    /* MC AAL5 Header */
    { &hf_erf_mc_aal5_cn,   { "connection number", "erf.mcaal5.cn", FT_UINT16, BASE_DEC, NULL, MC_AAL5_CN_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal5_res1, { "reserved", "erf.mcaal5.res1", FT_UINT16, BASE_DEC, NULL, MC_AAL5_RES1_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal5_port, { "physical port", "erf.mcaal5.port", FT_UINT8, BASE_DEC, NULL, MC_AAL5_PORT_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal5_crcck, { "CRC checked", "erf.mcaal5.crcck", FT_UINT8, BASE_DEC, NULL, MC_AAL5_CRCCK_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal5_crce,  { "CRC error", "erf.mcaal5.crce", FT_UINT8, BASE_DEC, NULL, MC_AAL5_CRCE_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal5_lenck,  { "Length checked", "erf.mcaal5.lenck", FT_UINT8, BASE_DEC, NULL, MC_AAL5_LENCK_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal5_lene, { "Length error", "erf.mcaal5.lene", FT_UINT8, BASE_DEC, NULL, MC_AAL5_LENE_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal5_res2,  { "reserved", "erf.mcaal5.res2", FT_UINT8, BASE_DEC, NULL, MC_AAL5_RES2_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal5_first, { "First record", "erf.mcaal5.first", FT_UINT8, BASE_DEC, NULL, MC_AAL5_FIRST_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal5_res3, { "reserved", "erf.mcaal5.res3", FT_UINT8, BASE_DEC, NULL, MC_AAL5_RES3_MASK, NULL, HFILL } },

    /* MC AAL2 Header */
    { &hf_erf_mc_aal2_cn,   { "connection number", "erf.mcaal2.cn", FT_UINT16, BASE_DEC, NULL, MC_AAL2_CN_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal2_res1, { "reserved for extra connection", "erf.mcaal2.res1", FT_UINT16, BASE_DEC, NULL, MC_AAL2_RES1_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal2_res2,  { "reserved for type", "erf.mcaal2.mul", FT_UINT16, BASE_DEC, NULL, MC_AAL2_RES2_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal2_port, { "physical port", "erf.mcaal2.port", FT_UINT8, BASE_DEC, NULL, MC_AAL2_PORT_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal2_res3, { "reserved", "erf.mcaal2.res2", FT_UINT8, BASE_DEC, NULL, MC_AAL2_RES3_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal2_first,  { "first cell received", "erf.mcaal2.lbe", FT_UINT8, BASE_DEC, NULL, MC_AAL2_FIRST_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal2_maale,  { "MAAL error", "erf.mcaal2.hec", FT_UINT8, BASE_DEC, NULL, MC_AAL2_MAALE_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal2_lene, { "Length error", "erf.mcaal2.crc10", FT_UINT8, BASE_DEC, NULL, MC_AAL2_LENE_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal2_cid, { "Channel Identification Number", "erf.mcaal2.cid", FT_UINT8, BASE_DEC, NULL, MC_AAL2_CID_MASK, NULL, HFILL } },

    /* AAL2 Header */
    { &hf_erf_aal2_cid, { "Channel Identification Number", "erf.aal2.cid", FT_UINT8, BASE_DEC, NULL, AAL2_CID_MASK, NULL, HFILL } },
    { &hf_erf_aal2_maale,  { "MAAL error number", "erf.aal2.maale", FT_UINT8, BASE_DEC, NULL, AAL2_MAALE_MASK, NULL, HFILL } },
    { &hf_erf_aal2_maalei,  { "MAAL error", "erf.aal2.hec", FT_UINT16, BASE_DEC, NULL, AAL2_MAALEI_MASK, NULL, HFILL } },
    { &hf_erf_aal2_first,  { "first cell received", "erf.aal2.lbe", FT_UINT16, BASE_DEC, NULL, AAL2_FIRST_MASK, NULL, HFILL } },
    { &hf_erf_aal2_res1, { "reserved", "erf.aal2.res1", FT_UINT16, BASE_DEC, NULL, AAL2_RES1_MASK, NULL, HFILL } },

    /* ETH Header */
    { &hf_erf_eth_off,   { "offset", "erf.eth.off", FT_UINT8, BASE_DEC, NULL, ETH_OFF_MASK, NULL, HFILL } },
    { &hf_erf_eth_res1,   { "reserved", "erf.eth.res1", FT_UINT8, BASE_DEC, NULL, ETH_RES1_MASK, NULL, HFILL } },

  };

  static gint *ett[] = {
    &ett_erf,
    &ett_erf_pseudo_hdr,
    &ett_erf_types,
    &ett_erf_flags,
    &ett_erf_mc_hdlc,
    &ett_erf_mc_raw,
    &ett_erf_mc_atm,
    &ett_erf_mc_rawlink,
    &ett_erf_mc_aal5,
    &ett_erf_mc_aal2,
    &ett_erf_aal2,
    &ett_erf_eth
  };

  static enum_val_t erf_hdlc_options[] = {
    { "chdlc",  "Cisco HDLC",       ERF_HDLC_CHDLC },
    { "ppp",    "PPP serial",       ERF_HDLC_PPP },
    { "frelay", "Frame Relay",      ERF_HDLC_FRELAY },
    { "mtp2",   "SS7 MTP2",         ERF_HDLC_MTP2 },
    { "guess",  "Attempt to guess", ERF_HDLC_GUESS },
    { NULL, NULL, 0 }
  };

  static enum_val_t erf_aal5_options[] = {
    { "guess", "Attempt to guess", ERF_AAL5_GUESS },
    { "llc",   "LLC multiplexed",  ERF_AAL5_LLC },
    { "unspec", "Unspecified", ERF_AAL5_UNSPEC },
    { NULL, NULL, 0 }
  };

  module_t *erf_module;

  proto_erf = proto_register_protocol("Extensible Record Format", "ERF", "erf");
  register_dissector("erf", dissect_erf, proto_erf);

  proto_register_field_array(proto_erf, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  erf_module = prefs_register_protocol(proto_erf, NULL);

  prefs_register_enum_preference(erf_module, "hdlc_type", "ERF_HDLC Layer 2",
                                 "Protocol encapsulated in HDLC records",
                                 &erf_hdlc_type, erf_hdlc_options, FALSE);

  prefs_register_bool_preference(erf_module, "rawcell_first",
                                 "Raw ATM cells are first cell of AAL5 PDU",
                                 "Whether raw ATM cells should be treated as "
                                 "the first cell of an AAL5 PDU",
                                 &erf_rawcell_first);

  prefs_register_enum_preference(erf_module, "aal5_type",
                                 "ATM AAL5 packet type",
                                 "Protocol encapsulated in ATM AAL5 packets",
                                 &erf_aal5_type, erf_aal5_options, FALSE);

  prefs_register_bool_preference(erf_module, "ethfcs",
                                 "Ethernet packets have FCS",
                                 "Whether the FCS is present in Ethernet packets",
                                 &erf_ethfcs);
}

void
proto_reg_handoff_erf(void)
{
  dissector_handle_t erf_handle;

  erf_handle = find_dissector("erf");
  dissector_add_uint("wtap_encap", WTAP_ENCAP_ERF, erf_handle);

  /* Dissector called to dump raw data, or unknown protocol */
  data_handle = find_dissector("data");

  /* Get handle for IP dissectors) */
  ipv4_handle = find_dissector("ip");
  ipv6_handle = find_dissector("ipv6");

  /* Get handle for Infiniband dissector */
  infiniband_handle = find_dissector("infiniband");
  infiniband_link_handle = find_dissector("infiniband_link");

  /* Get handles for serial line protocols */
  chdlc_handle = find_dissector("chdlc");
  ppp_handle = find_dissector("ppp_hdlc");
  frelay_handle = find_dissector("fr");
  mtp2_handle = find_dissector("mtp2");

  /* Get handle for ATM dissector */
  atm_untruncated_handle = find_dissector("atm_untruncated");

  /* Get handles for Ethernet dissectors */
  ethwithfcs_handle = find_dissector("eth_withfcs");
  ethwithoutfcs_handle = find_dissector("eth_withoutfcs");
}
