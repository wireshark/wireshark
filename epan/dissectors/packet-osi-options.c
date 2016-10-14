/* packet-osi-options.c
 * Routines for the decode of ISO/OSI option part
 * Covers:
 * ISO  8473 CLNP (ConnectionLess Mode Network Service Protocol)
 * ISO 10589 ISIS (Intradomain Routing Information Exchange Protocol)
 * ISO  9542 ESIS (End System To Intermediate System Routing Exchange Protocol)
 *
 * Ralf Schneider <Ralf.Schneider@t-online.de>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include "packet-osi.h"
#include "packet-osi-options.h"


/* ATN traffic types (ICAO doc 9705 Edition3 SV5 5.6.2.2.6.7.3) */
#define ATN_TT_ATSC_NO_PREFERENCE       0x01
#define ATN_TT_ATSC_CLASS_A             0x10
#define ATN_TT_ATSC_CLASS_B             0x11
#define ATN_TT_ATSC_CLASS_C             0x12
#define ATN_TT_ATSC_CLASS_D             0x13
#define ATN_TT_ATSC_CLASS_E             0x14
#define ATN_TT_ATSC_CLASS_F             0x15
#define ATN_TT_ATSC_CLASS_G             0x16
#define ATN_TT_ATSC_CLASS_H             0x17
#define ATN_TT_AOC_NO_PREFERENCE        0x21
#define ATN_TT_AOC_G                    0x22
#define ATN_TT_AOC_V                    0x23
#define ATN_TT_AOC_S                    0x24
#define ATN_TT_AOC_H                    0x25
#define ATN_TT_AOC_M                    0x26
#define ATN_TT_AOC_G_V                  0x27
#define ATN_TT_AOC_G_V_S                0x28
#define ATN_TT_AOC_G_V_H_S              0x29
#define ATN_TT_ADM_NO_PREFERENCE        0x30
#define ATN_TT_SYS_MGMT_NO_PREFERENCE   0x60

/* ATN security classification (ICAO doc 9705 Edition3 SV5 5.6.2.2.6.8.3) */
#define ATN_SC_UNCLASSIFIED             0x01
#define ATN_SC_RESTRICTED               0x02
#define ATN_SC_CONFIDENTIAL             0x03
#define ATN_SC_SECRET                   0x04
#define ATN_SC_TOP_SECRET               0x05

/* ATN security label records */
#define OSI_OPT_SECURITY_ATN_SR         0xc0
#define OSI_OPT_SECURITY_ATN_TT         0x0f
#define OSI_OPT_SECURITY_ATN_SC         0x03
#define OSI_OPT_SECURITY_ATN_SR_LEN     6
#define OSI_OPT_SECURITY_ATN_TT_LEN     1
#define OSI_OPT_SECURITY_ATN_SC_LEN     1
#define OSI_OPT_SECURITY_ATN_SI_MAX_LEN 8


#define OSI_OPT_SECURITY                0xc5
#define OSI_OPT_QOS_MAINTANANCE         0xc3
#define OSI_OPT_PRIORITY                0xcd
#define OSI_OPT_ADDRESS_MASK            0xe1
#define OSI_OPT_SNPA_MASK               0xe2
#define OSI_OPT_ES_CONFIG_TIMER         0xc6

#define OSI_OPT_MAX_PRIORITY            0x0e

#define OSI_OPT_PADDING                 0xcc
#define OSI_OPT_SOURCE_ROUTING          0xc8
#define OSI_OPT_RECORD_OF_ROUTE         0xcb
#define OSI_OPT_REASON_OF_DISCARD       0xc1

#define OSI_OPT_SEC_MASK                0xc0
#define OSI_OPT_SEC_RESERVED            0x00
#define OSI_OPT_SEC_SRC_ADR_SPEC        0x01
#define OSI_OPT_SEC_DST_ADR_SPEC        0x02
#define OSI_OPT_SEC_GLOBAL_UNIQUE       0x03

#define OSI_OPT_QOS_MASK                0xc0
#define OSI_OPT_QOS_RESERVED            0x00
#define OSI_OPT_QOS_SRC_ADR_SPEC        0x01
#define OSI_OPT_QOS_DST_ADR_SPEC        0x02
#define OSI_OPT_QOS_GLOBAL_UNIQUE       0x03

#define OSI_OPT_QOS_SUB_MASK            0x3f
#define OSI_OPT_QOS_SUB_RSVD            0x20
#define OSI_OPT_QOS_SUB_SEQ_VS_TRS      0x10
#define OSI_OPT_QOS_SUB_CONG_EXPED      0x08
#define OSI_OPT_QOS_SUB_TSD_VS_COST     0x04
#define OSI_OPT_QOS_SUB_RESERR_TRS      0x02
#define OSI_OPT_QOS_SUB_RESERR_COST     0x01

#define OSI_OPT_RFD_GENERAL             0x00
#define OSI_OPT_RFD_ADDRESS             0x08
#define OSI_OPT_RFD_SOURCE_ROUTING      0x09
#define OSI_OPT_RFD_LIFETIME            0x0a
#define OSI_OPT_RFD_PDU_DISCARDED       0x0b
#define OSI_OPT_RFD_REASSEMBLY          0x0c

#define OSI_OPT_RFD_MASK                0xf0
#define OSI_OPT_RFD_SUB_MASK            0x0f

extern gboolean clnp_decode_atn_options; /* as defined in packet-clnp.c */
extern int hf_clnp_atntt; /* as defined in packet-clnp.c */
extern int hf_clnp_atnsc; /* as defined in packet-clnp.c */

/* Generated from convert_proto_tree_add_text.pl */
static int hf_osi_options_address_mask = -1;
static int hf_osi_options_transit_delay_vs_cost = -1;
static int hf_osi_options_rtd_general = -1;
static int hf_osi_options_residual_error_prob_vs_transit_delay = -1;
static int hf_osi_options_qos_sequencing_vs_transit_delay = -1;
static int hf_osi_options_rtd_address = -1;
static int hf_osi_options_congestion_experienced = -1;
static int hf_osi_options_esct = -1;
static int hf_osi_options_rtd_reassembly = -1;
static int hf_osi_options_qos_maintenance = -1;
static int hf_osi_options_security_type = -1;
static int hf_osi_options_route_recording = -1;
static int hf_osi_options_last_hop = -1;
static int hf_osi_options_route = -1;
static int hf_osi_options_rtd_lifetime = -1;
static int hf_osi_options_rtd_source_routing = -1;
static int hf_osi_options_padding = -1;
static int hf_osi_options_rfd_error_class = -1;
static int hf_osi_options_snpa_mask = -1;
static int hf_osi_options_source_routing = -1;
static int hf_osi_options_priority = -1;
static int hf_osi_options_qos_reserved = -1;
static int hf_osi_options_residual_error_prob_vs_cost = -1;
static int hf_osi_options_rtd_pdu_discarded = -1;
static int hf_osi_options_rfd_field = -1;

static gint ott_osi_options       = -1;
static gint ott_osi_qos           = -1;
static gint ott_osi_route         = -1;
static gint ott_osi_redirect      = -1;

static expert_field ei_osi_options_none = EI_INIT;
static expert_field ei_osi_options_rfd_error_class = EI_INIT;

static const guchar atn_security_registration_val[] = {
  0x06, 0x04, 0x2b, 0x1b, 0x00, 0x00
}; /* =iso(1).org(3).ICAO(27).ATN(0).TrafficType(0)*/

static const value_string osi_opt_sec_atn_sr_vals[] = {
  {OSI_OPT_SECURITY_ATN_SR, "ATN Security Label"},
  {0,                       NULL}
};

static const value_string osi_opt_sec_atn_si_vals[] = {
  {OSI_OPT_SECURITY_ATN_TT, "Traffic Type and Routing"},
  {OSI_OPT_SECURITY_ATN_SC, "Security classification"},
  {0,                       NULL}
};

static const value_string osi_opt_sec_atn_tt_vals[] = {
  {ATN_TT_ATSC_NO_PREFERENCE,     "ATSC No preference"},
  {ATN_TT_ATSC_CLASS_A,           "ATSC Class A"},
  {ATN_TT_ATSC_CLASS_B,           "ATSC Class B"},
  {ATN_TT_ATSC_CLASS_C,           "ATSC Class C"},
  {ATN_TT_ATSC_CLASS_D,           "ATSC Class D"},
  {ATN_TT_ATSC_CLASS_E,           "ATSC Class E"},
  {ATN_TT_ATSC_CLASS_F,           "ATSC Class F"},
  {ATN_TT_ATSC_CLASS_G,           "ATSC Class G"},
  {ATN_TT_ATSC_CLASS_H,           "ATSC Class H"},
  {ATN_TT_AOC_NO_PREFERENCE,      "AOC No preference"},
  {ATN_TT_AOC_G,                  "AOC Gatelink only"},
  {ATN_TT_AOC_V,                  "AOC VHF only"},
  {ATN_TT_AOC_S,                  "AOC Satellite only"},
  {ATN_TT_AOC_H,                  "AOC HF only"},
  {ATN_TT_AOC_M,                  "AOC Mode S only"},
  {ATN_TT_AOC_G_V,                "AOC Gatelink first, then VHF"},
  {ATN_TT_AOC_G_V_S,              "AOC Gatelink first, then VHF, then Satellite"},
  {ATN_TT_AOC_G_V_H_S,            "AOC Gatelink first, then VHF, then HF, then Satellite"},
  {ATN_TT_ADM_NO_PREFERENCE,      "ATN Administrative No preference"},
  {ATN_TT_SYS_MGMT_NO_PREFERENCE, "ATN Systems Management No preference"},
  {0,                             NULL}
};

static const value_string osi_opt_sec_atn_sc_vals[] = {
  {ATN_SC_UNCLASSIFIED, "unclassified"},
  {ATN_SC_RESTRICTED,   "restricted"},
  {ATN_SC_CONFIDENTIAL, "confidential"},
  {ATN_SC_SECRET,       "secret"},
  {ATN_SC_TOP_SECRET,   "top secret"},
  {0,                   NULL}
};

static const value_string osi_opt_sec_vals[] = {
  {OSI_OPT_SEC_RESERVED,      "Reserved"},
  {OSI_OPT_SEC_SRC_ADR_SPEC,  "Source Address Specific"},
  {OSI_OPT_SEC_DST_ADR_SPEC,  "Destination Address Specific"},
  {OSI_OPT_SEC_GLOBAL_UNIQUE, "Globally Unique"},
  {0,                         NULL}
};

static const value_string osi_opt_qos_vals[] = {
  {OSI_OPT_QOS_RESERVED,      "Reserved"},
  {OSI_OPT_QOS_SRC_ADR_SPEC,  "Source Address Specific"},
  {OSI_OPT_QOS_DST_ADR_SPEC,  "Destination Address Specific"},
  {OSI_OPT_QOS_GLOBAL_UNIQUE, "Globally Unique"},
  {0,                         NULL}
};

static const value_string osi_opt_rfd_error_class[] = {
  {OSI_OPT_RFD_GENERAL, "General"},
  {OSI_OPT_RFD_ADDRESS, "Address"},
  {OSI_OPT_RFD_SOURCE_ROUTING, "Source Routing"},
  {OSI_OPT_RFD_LIFETIME, "Lifetime"},
  {OSI_OPT_RFD_PDU_DISCARDED, "PDU discarded"},
  {OSI_OPT_RFD_REASSEMBLY, "Reassembly"},
  {0,    NULL}
};

static const value_string osi_opt_rfd_general[] = {
  {0x00, "Reason not specified"},
  {0x01, "Protocol procedure error"},
  {0x02, "Incorrect checksum"},
  {0x03, "PDU discarded due to congestion"},
  {0x04, "Header syntax error ( cannot be parsed )"},
  {0x05, "Segmentation needed but not permitted"},
  {0x06, "Incomplete PDU received"},
  {0x07, "Duplicate option"},
  {0,    NULL}
};

static const value_string osi_opt_rfd_address[] = {
  {0x00, "Destination Address unreachable"},
  {0x01, "Destination Address unknown"},
  {0,    NULL}
};

static const value_string osi_opt_rfd_src_route[] = {
  {0x00, "Unspecified source routing error"},
  {0x01, "Syntax error in source routing field"},
  {0x02, "Unknown address in source routing field"},
  {0x03, "Path not acceptable"},
  {0,    NULL}
};

static const value_string osi_opt_rfd_lifetime[] = {
  {0x00, "Lifetime expired while data unit in transit"},
  {0x01, "Lifetime expired during reassembly"},
  {0,    NULL}
};

static const value_string osi_opt_rfd_discarded[] = {
  {0x00, "Unsupported option not specified"},
  {0x01, "Unsupported protocol version"},
  {0x02, "Unsupported security option"},
  {0x03, "Unsupported source routing option"},
  {0x04, "Unsupported recording of route option"},
  {0,    NULL}
};

static const value_string osi_opt_rfd_reassembly[] = {
  {0x00, "Reassembly interference"},
  {0,    NULL} };


static void
dissect_option_qos(const guint8 qos, proto_tree *tree, tvbuff_t *tvb, int offset)
{
  proto_item *ti;
  proto_tree *osi_qos_tree;

  ti = proto_tree_add_item(tree, hf_osi_options_qos_maintenance, tvb, offset, 1, ENC_BIG_ENDIAN);
  osi_qos_tree = proto_item_add_subtree(ti, ott_osi_qos);

  if ( ((qos & OSI_OPT_QOS_MASK) >> 6) == OSI_OPT_QOS_GLOBAL_UNIQUE) { /* Analye BIT field to get all Values */
    proto_tree_add_item(osi_qos_tree, hf_osi_options_qos_reserved, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(osi_qos_tree, hf_osi_options_qos_sequencing_vs_transit_delay, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(osi_qos_tree, hf_osi_options_congestion_experienced, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(osi_qos_tree, hf_osi_options_transit_delay_vs_cost, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(osi_qos_tree, hf_osi_options_residual_error_prob_vs_transit_delay, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(osi_qos_tree, hf_osi_options_residual_error_prob_vs_cost, tvb, offset, 1, ENC_NA);
  }
}

static void
dissect_option_route(guchar parm_type, int offset, guchar parm_len,
                     tvbuff_t *tvb, proto_tree *tree )
{
  guchar      next_hop = 0;
  guint16     this_hop = 0;
  guchar      netl     = 0;
  guchar      last_hop = 0;
  guchar      cnt_hops = 0;
  guchar      crr      = 0;
  gchar*      str;

  proto_tree *osi_route_tree = NULL;

  if ( parm_type == OSI_OPT_SOURCE_ROUTING ) {
    next_hop = tvb_get_guint8(tvb, offset + 1);
    netl     = tvb_get_guint8(tvb, next_hop + 2);
    this_hop = offset + 2;  /* points to first netl */

    proto_tree_add_uint_format_value(tree, hf_osi_options_source_routing, tvb, offset + next_hop, netl,
                        tvb_get_guint8(tvb, offset), "%s   ( Next Hop Highlighted In Data Buffer )",
                        (tvb_get_guint8(tvb, offset) == 0) ? "Partial Source Routing" :
                                                             "Complete Source Routing");
  }
  else if ( parm_type == OSI_OPT_RECORD_OF_ROUTE ) {
    crr = tvb_get_guint8(tvb, offset);
    last_hop = tvb_get_guint8(tvb, offset + 1);
    osi_route_tree = proto_tree_add_subtree(tree, tvb, offset, parm_len, ott_osi_route, NULL,
                             (crr == 0) ? "Partial Route Recording" : "Complete Route Recording");

    /* Complete Route Recording or Partial Route Recording */
    proto_tree_add_uint_format_value(tree, hf_osi_options_route_recording, tvb, offset, 1, crr, "%s ",
                             (crr == 0) ? "Partial Route Recording" :
                                          "Complete Route Recording");

    /* "last_hop" is either :
     *  0x03 : special value for no NET recorded yet.
     *  0xFF : special value telling there is no more place
               in the Route Recording Allocated Length and
               therefore next NETs won't be recorded.
    *  Other value : Total length of recorded NETs so far.
    */
    if ( last_hop == 0x03 )
      proto_tree_add_uint_format(osi_route_tree, hf_osi_options_last_hop, tvb, offset + 1, 1, last_hop,
                          "No Network Entity Titles Recorded Yet");
    if ( last_hop == 0xFF )
      proto_tree_add_uint_format(osi_route_tree, hf_osi_options_last_hop, tvb, offset + 1, 1, last_hop,
                          "Recording Terminated : No more space !");

    if ( last_hop == 255 || last_hop == 0x03 )
      this_hop = parm_len + 1;   /* recording terminated,
                                  * or not begun, nothing to show */
    else
      this_hop = offset + 2;         /* points to first netl */
  }

  while ( this_hop < offset + last_hop -2 ) { /* -2 for crr and last_hop */
    netl = tvb_get_guint8(tvb, this_hop);
    str = print_nsap_net(tvb, this_hop + 1, netl);
    proto_tree_add_string_format(osi_route_tree, hf_osi_options_route, tvb, this_hop, netl + 1, str,
                        "Hop #%3u NETL: %2u, NET: %s", cnt_hops++, netl, str);
    this_hop += 1 + netl;
  }
}


static void
dissect_option_rfd(const guchar error, const guchar field, int offset,
                   guchar len _U_, tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo )
{
  proto_item *ti;

  ti = proto_tree_add_item(tree, hf_osi_options_rfd_error_class, tvb, offset, 1, ENC_BIG_ENDIAN);

  switch ((error & OSI_OPT_RFD_MASK) >> 4)
  {
  case OSI_OPT_RFD_GENERAL:
    proto_tree_add_item(tree, hf_osi_options_rtd_general, tvb, offset, 1, ENC_BIG_ENDIAN);
  break;
  case OSI_OPT_RFD_ADDRESS:
    proto_tree_add_item(tree, hf_osi_options_rtd_address, tvb, offset, 1, ENC_BIG_ENDIAN);
  break;
  case OSI_OPT_RFD_SOURCE_ROUTING:
    proto_tree_add_item(tree, hf_osi_options_rtd_source_routing, tvb, offset, 1, ENC_BIG_ENDIAN);
  break;
  case OSI_OPT_RFD_LIFETIME:
    proto_tree_add_item(tree, hf_osi_options_rtd_lifetime, tvb, offset, 1, ENC_BIG_ENDIAN);
  break;
  case OSI_OPT_RFD_PDU_DISCARDED:
    proto_tree_add_item(tree, hf_osi_options_rtd_pdu_discarded, tvb, offset, 1, ENC_BIG_ENDIAN);
  break;
  case OSI_OPT_RFD_REASSEMBLY:
    proto_tree_add_item(tree, hf_osi_options_rtd_reassembly, tvb, offset, 1, ENC_BIG_ENDIAN);
  break;
  default:
    expert_add_info(pinfo, ti, &ei_osi_options_rfd_error_class);
  }

  proto_tree_add_uint(tree, hf_osi_options_rfd_field, tvb, offset + field, 1, field);
}

/* dissect ATN security label used for policy based interdomain routing.*/
/* For details see ICAO doc 9705 Edition 3 SV5 5.6.2.2.2.2 */
static void
dissect_option_atn_security_label(const guchar sub_type, guchar length,
                                  tvbuff_t *tvb, guint offset,
                                  proto_tree *tree)
{
  proto_tree *atn_sl_tree;
  guchar len = 0;
  guint8 tag_name = 0;
  guint  security_info_end = 0;

  /* check for ATN security label */
  if ( OSI_OPT_SECURITY_ATN_SR != sub_type )
    return;

  /* check Security Registration Length */
  len =  tvb_get_guint8(tvb, ++offset);
  if ( OSI_OPT_SECURITY_ATN_SR_LEN != len )
    return;

  /* check Security Registration ID */
  if ( tvb_memeql(tvb, ++offset , atn_security_registration_val, OSI_OPT_SECURITY_ATN_SR_LEN) )
    return;

  atn_sl_tree = proto_tree_add_subtree(tree, tvb, offset, length, ott_osi_qos, NULL,
                           val_to_str(sub_type, osi_opt_sec_atn_sr_vals, "Unknown (0x%x)"));

  offset += OSI_OPT_SECURITY_ATN_SR_LEN;

  /* Security Information length */
  len = tvb_get_guint8(tvb, offset);

  if ( OSI_OPT_SECURITY_ATN_SI_MAX_LEN < len )
    return;

  offset++;

  security_info_end = offset + len;
  while ( offset < security_info_end ) {
    /* check tag name length*/
    len = tvb_get_guint8(tvb, offset); /* check tag name length*/
    if ( len != 1 )
      return;

    offset++;

    tag_name = tvb_get_guint8(tvb, offset);
    offset++;

    switch(tag_name) {
      case OSI_OPT_SECURITY_ATN_TT:
        /* check tag set length*/
        len = tvb_get_guint8(tvb, offset);
        if ( len != OSI_OPT_SECURITY_ATN_TT_LEN )
          return;

        offset++;
        proto_tree_add_uint_format(atn_sl_tree, hf_clnp_atntt, tvb, offset, 1,
                                   tvb_get_guint8(tvb, offset), "%s: %s",
                                   val_to_str(OSI_OPT_SECURITY_ATN_TT, osi_opt_sec_atn_si_vals, "Unknown (0x%x)"),
                                   val_to_str(tvb_get_guint8(tvb, offset ), osi_opt_sec_atn_tt_vals, "Unknown (0x%x)"));
        offset += len;
        break;

      case OSI_OPT_SECURITY_ATN_SC:
        /* check tag set length*/
        len = tvb_get_guint8(tvb, offset);
        if ( len != OSI_OPT_SECURITY_ATN_SC_LEN )
          return;

        offset++;
        proto_tree_add_uint_format(atn_sl_tree, hf_clnp_atnsc, tvb, offset, 1,
                                   tvb_get_guint8(tvb, offset), "%s: %s",
                                   val_to_str(OSI_OPT_SECURITY_ATN_SC, osi_opt_sec_atn_si_vals, "Unknown (0x%x)"),
                                   val_to_str(tvb_get_guint8(tvb, offset ), osi_opt_sec_atn_sc_vals, "Unknown (0x%x)"));
        offset += len;
        break;

      default:
        return;
    }
  }
}

/* ############################## Dissection Functions ###################### */

/*
 * Name: dissect_osi_options()
 *
 * Description:
 *   Main entry area for esis de-mangling.  This will build the
 *   main esis tree data and call the sub-protocols as needed.
 *
 * Input:
 *   guchar       : length of option section
 *   tvbuff_t *   : tvbuff containing packet data
 *   int          : offset into packet where we are (packet_data[offset]== start
 *                  of what we care about)
 *   proto_tree * : tree of display data.  May be NULL.
 *
 * Output:
 *   void, but we will add to the proto_tree if it is not NULL.
 */
void
dissect_osi_options(guchar opt_len, tvbuff_t *tvb, int offset, proto_tree *tree, packet_info *pinfo)
{
  proto_item *ti;
  proto_tree *osi_option_tree = NULL;
  guchar      parm_len        = 0;
  guchar      parm_type       = 0;
  guint8      octet;

    osi_option_tree = proto_tree_add_subtree(tree, tvb, offset, opt_len,
                             ott_osi_options, &ti, "### Option Section ###");
    if ( 0 == opt_len ) {
       expert_add_info(pinfo, ti, &ei_osi_options_none);
       return;
    }

    while ( 0 < opt_len ) {
      parm_type = tvb_get_guint8(tvb, offset++);
      parm_len = tvb_get_guint8(tvb, offset++);

      switch ( parm_type ) {
        case OSI_OPT_QOS_MAINTANANCE:
          octet = tvb_get_guint8(tvb, offset);
          dissect_option_qos(octet, osi_option_tree, tvb, offset);
          break;

        case OSI_OPT_SECURITY:
          octet = tvb_get_guint8(tvb, offset);
          if ( clnp_decode_atn_options ) {
            dissect_option_atn_security_label(octet,parm_len,tvb, offset,
                                              osi_option_tree);
          } else {
            ti = proto_tree_add_item(osi_option_tree, hf_osi_options_security_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_item_set_len(ti, parm_len);
          }
          break;

        case OSI_OPT_PRIORITY:
          octet = tvb_get_guint8(tvb, offset);
          if ( OSI_OPT_MAX_PRIORITY >= octet ) {
            ti = proto_tree_add_item(osi_option_tree, hf_osi_options_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
          } else {
            ti = proto_tree_add_uint_format_value(osi_option_tree, hf_osi_options_priority, tvb, offset, 1,
                                octet, "%u ( Invalid )", octet);
          }
          proto_item_set_len(ti, parm_len);
          break;

        case OSI_OPT_ADDRESS_MASK:
          proto_tree_add_bytes_format_value(osi_option_tree, hf_osi_options_address_mask, tvb, offset, parm_len,
                              NULL, "%s",
                              print_area(tvb, offset, parm_len));
          break;

        case OSI_OPT_SNPA_MASK:
          proto_tree_add_item(osi_option_tree, hf_osi_options_snpa_mask, tvb, offset, parm_len, ENC_NA);
          break;

        case OSI_OPT_ES_CONFIG_TIMER:
          ti = proto_tree_add_item(osi_option_tree, hf_osi_options_esct, tvb, offset, 2, ENC_BIG_ENDIAN);
          proto_item_set_len(ti, parm_len);          break;

        case OSI_OPT_PADDING:
          proto_tree_add_item(osi_option_tree, hf_osi_options_padding, tvb, offset, parm_len, ENC_NA);
          break;

        case OSI_OPT_SOURCE_ROUTING:
        case OSI_OPT_RECORD_OF_ROUTE:
          dissect_option_route(parm_type, offset, parm_len, tvb,
                               osi_option_tree);
          break;

        case OSI_OPT_REASON_OF_DISCARD:
          dissect_option_rfd(tvb_get_guint8(tvb, offset),
                             tvb_get_guint8(tvb, offset + 1), offset, parm_len,
                             tvb, osi_option_tree, pinfo);
          break;
      }
      opt_len -= parm_len + 2;
      offset  += parm_len;
    }
} /* dissect-osi-options */


/*
 * Name: proto_register_osi_options()
 *
 * Description:
 *      main register for esis protocol set.  We register some display
 *      formats and the protocol module variables.
 *
 *      NOTE: this procedure to autolinked by the makefile process that
 *      builds register.c
 *
 * Input:
 *      void
 *
 * Output:
 *      void
 */

void
proto_register_osi_options(void) {

  static hf_register_info hf[] =
  {
      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_osi_options_qos_maintenance, { "Quality of service maintenance", "osi.options.qos.maintenance", FT_UINT8, BASE_DEC, VALS(osi_opt_qos_vals), OSI_OPT_QOS_MASK, NULL, HFILL }},
      { &hf_osi_options_qos_reserved, { "Reserved", "osi.options.qos.reserved", FT_BOOLEAN, 8, NULL, OSI_OPT_QOS_SUB_RSVD, NULL, HFILL }},
      { &hf_osi_options_qos_sequencing_vs_transit_delay, { "Sequencing versus transit delay", "osi.options.qos.seq_vs_trs", FT_BOOLEAN, 8, NULL, OSI_OPT_QOS_SUB_SEQ_VS_TRS, NULL, HFILL }},
      { &hf_osi_options_congestion_experienced, { "Congestion experienced", "osi.options.qos.cong_exped", FT_BOOLEAN, 8, NULL, OSI_OPT_QOS_SUB_CONG_EXPED, NULL, HFILL }},
      { &hf_osi_options_transit_delay_vs_cost, { "Transit delay versus cost", "osi.options.qos.tsd_vs_cost", FT_BOOLEAN, 8, NULL, OSI_OPT_QOS_SUB_TSD_VS_COST, NULL, HFILL }},
      { &hf_osi_options_residual_error_prob_vs_transit_delay, { "Residual error probability versus transit delay", "osi.options.qos.reserror_trs", FT_BOOLEAN, 8, NULL, OSI_OPT_QOS_SUB_RESERR_TRS, NULL, HFILL }},
      { &hf_osi_options_residual_error_prob_vs_cost, { "Residual error probability versus cost", "osi.options.qos.reserror_cost", FT_BOOLEAN, 8, NULL, OSI_OPT_QOS_SUB_RESERR_COST, NULL, HFILL }},
      { &hf_osi_options_source_routing, { "Source Routing", "osi.options.source_routing", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_osi_options_route_recording, { "Route Recording", "osi.options.route_recording", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_osi_options_last_hop, { "Last Hop", "osi.options.last_hop", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_osi_options_route, { "Route", "osi.options.route", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_osi_options_rfd_error_class, { "Error Class", "osi.options.rfd.error_class", FT_UINT8, BASE_DEC, VALS(osi_opt_rfd_error_class), OSI_OPT_RFD_MASK, NULL, HFILL }},
      { &hf_osi_options_rtd_general, { "Reason for discard {General}", "osi.options.rtd_general", FT_UINT8, BASE_DEC, VALS(osi_opt_rfd_general), OSI_OPT_RFD_SUB_MASK, NULL, HFILL }},
      { &hf_osi_options_rtd_address, { "Reason for discard {Address}", "osi.options.rtd_address", FT_UINT8, BASE_DEC, VALS(osi_opt_rfd_address), OSI_OPT_RFD_SUB_MASK, NULL, HFILL }},
      { &hf_osi_options_rtd_source_routing, { "Reason for discard {Source Routing}", "osi.options.rtd_source_routing", FT_UINT8, BASE_DEC, VALS(osi_opt_rfd_src_route), OSI_OPT_RFD_SUB_MASK, NULL, HFILL }},
      { &hf_osi_options_rtd_lifetime, { "Reason for discard {Lifetime}", "osi.options.rtd_lifetime", FT_UINT8, BASE_DEC, VALS(osi_opt_rfd_lifetime), OSI_OPT_RFD_SUB_MASK, NULL, HFILL }},
      { &hf_osi_options_rtd_pdu_discarded, { "Reason for discard {PDU discarded}", "osi.options.rtd_pdu_discarded", FT_UINT8, BASE_DEC, VALS(osi_opt_rfd_discarded), OSI_OPT_RFD_SUB_MASK, NULL, HFILL }},
      { &hf_osi_options_rtd_reassembly, { "Reason for discard {Reassembly}", "osi.options.rtd_reassembly", FT_UINT8, BASE_DEC, VALS(osi_opt_rfd_reassembly), OSI_OPT_RFD_SUB_MASK, NULL, HFILL }},
      { &hf_osi_options_rfd_field, { "Field", "osi.options.rfd.field", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_osi_options_security_type, { "Security type", "osi.options.security_type", FT_UINT8, BASE_DEC, VALS(osi_opt_sec_vals), OSI_OPT_SEC_MASK, NULL, HFILL }},
      { &hf_osi_options_priority, { "Priority", "osi.options.priority", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_osi_options_address_mask, { "Address Mask", "osi.options.address_mask", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_osi_options_snpa_mask, { "SNPA Mask", "osi.options.snpa_mask", FT_SYSTEM_ID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_osi_options_esct, { "ESCT (seconds)", "osi.options.esct", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_osi_options_padding, { "Padding", "osi.options.padding", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
  };

  static gint *ott[] = {
    &ott_osi_options,
    &ott_osi_qos,
    &ott_osi_route,
    &ott_osi_redirect
  };

  static ei_register_info ei[] = {
      { &ei_osi_options_none, { "osi.options.none", PI_PROTOCOL, PI_NOTE, "No Options for this PDU", EXPFILL }},
      { &ei_osi_options_rfd_error_class, { "osi.options.rfd.error_class.unknown", PI_PROTOCOL, PI_WARN, "UNKNOWN Error Class", EXPFILL }},
  };

  expert_module_t *expert_osi_options;

  proto_register_field_array(proto_osi, hf, array_length(hf));
  proto_register_subtree_array(ott, array_length(ott));
  expert_osi_options = expert_register_protocol(proto_osi);
  expert_register_field_array(expert_osi_options, ei, array_length(ei));
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */

