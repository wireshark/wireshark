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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/decode_as.h>
#include "packet-osi.h"
#include "packet-osi-options.h"

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

/* Generated from convert_proto_tree_add_text.pl */
static int hf_osi_options_address_mask;
static int hf_osi_options_transit_delay_vs_cost;
static int hf_osi_options_rtd_general;
static int hf_osi_options_residual_error_prob_vs_transit_delay;
static int hf_osi_options_qos_sequencing_vs_transit_delay;
static int hf_osi_options_rtd_address;
static int hf_osi_options_congestion_experienced;
static int hf_osi_options_esct;
static int hf_osi_options_rtd_reassembly;
static int hf_osi_options_qos_maintenance;
static int hf_osi_options_security_type;
static int hf_osi_options_route_recording;
static int hf_osi_options_last_hop;
static int hf_osi_options_route;
static int hf_osi_options_rtd_lifetime;
static int hf_osi_options_rtd_source_routing;
static int hf_osi_options_padding;
static int hf_osi_options_rfd_error_class;
static int hf_osi_options_snpa_mask;
static int hf_osi_options_source_routing;
static int hf_osi_options_priority;
static int hf_osi_options_qos_reserved;
static int hf_osi_options_residual_error_prob_vs_cost;
static int hf_osi_options_rtd_pdu_discarded;
static int hf_osi_options_rfd_field;

static int ett_osi_options;
static int ett_osi_qos;
static int ett_osi_route;
static int ett_osi_redirect;

static expert_field ei_osi_options_none;
static expert_field ei_osi_options_rfd_error_class;

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

static dissector_table_t subdissector_decode_as_opt_security_table;

static void
dissect_option_qos(const uint8_t qos, proto_tree *tree, tvbuff_t *tvb, int offset)
{
  proto_item *ti;
  proto_tree *osi_qos_tree;

  ti = proto_tree_add_item(tree, hf_osi_options_qos_maintenance, tvb, offset, 1, ENC_BIG_ENDIAN);
  osi_qos_tree = proto_item_add_subtree(ti, ett_osi_qos);

  if ( ((qos & OSI_OPT_QOS_MASK) >> 6) == OSI_OPT_QOS_GLOBAL_UNIQUE) { /* Analyze BIT field to get all Values */
    proto_tree_add_item(osi_qos_tree, hf_osi_options_qos_reserved, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(osi_qos_tree, hf_osi_options_qos_sequencing_vs_transit_delay, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(osi_qos_tree, hf_osi_options_congestion_experienced, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(osi_qos_tree, hf_osi_options_transit_delay_vs_cost, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(osi_qos_tree, hf_osi_options_residual_error_prob_vs_transit_delay, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(osi_qos_tree, hf_osi_options_residual_error_prob_vs_cost, tvb, offset, 1, ENC_NA);
  }
}

static void
dissect_option_route(unsigned char parm_type, int offset, unsigned char parm_len,
                     tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo )
{
  unsigned char      next_hop = 0;
  uint16_t    this_hop = 0;
  unsigned char      netl     = 0;
  unsigned char      last_hop = 0;
  unsigned char      cnt_hops = 0;
  unsigned char      crr      = 0;
  char*      str;

  proto_tree *osi_route_tree = NULL;

  if ( parm_type == OSI_OPT_SOURCE_ROUTING ) {
    next_hop = tvb_get_uint8(tvb, offset + 1);
    netl     = tvb_get_uint8(tvb, next_hop + 2);
    this_hop = offset + 2;  /* points to first netl */

    proto_tree_add_uint_format_value(tree, hf_osi_options_source_routing, tvb, offset + next_hop, netl,
                        tvb_get_uint8(tvb, offset), "%s   ( Next Hop Highlighted In Data Buffer )",
                        (tvb_get_uint8(tvb, offset) == 0) ? "Partial Source Routing" :
                                                             "Complete Source Routing");
  }
  else if ( parm_type == OSI_OPT_RECORD_OF_ROUTE ) {
    crr = tvb_get_uint8(tvb, offset);
    last_hop = tvb_get_uint8(tvb, offset + 1);
    osi_route_tree = proto_tree_add_subtree(tree, tvb, offset, parm_len, ett_osi_route, NULL,
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
    netl = tvb_get_uint8(tvb, this_hop);
    str = print_nsap_net(pinfo->pool, tvb, this_hop + 1, netl);
    proto_tree_add_string_format(osi_route_tree, hf_osi_options_route, tvb, this_hop, netl + 1, str,
                        "Hop #%3u NETL: %2u, NET: %s", cnt_hops++, netl, str);
    this_hop += 1 + netl;
  }
}


static void
dissect_option_rfd(const unsigned char error, const unsigned char field, int offset,
                   unsigned char len _U_, tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo )
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

/* ############################## Dissection Functions ###################### */

/*
 * Name: dissect_osi_options()
 *
 * Description:
 *   Main entry area for esis de-mangling.  This will build the
 *   main esis tree data and call the sub-protocols as needed.
 *
 * Input:
 *   unsigned char       : length of option section
 *   tvbuff_t *   : tvbuff containing packet data
 *   int          : offset into packet where we are (packet_data[offset]== start
 *                  of what we care about)
 *   proto_tree * : tree of display data.  May be NULL.
 *
 * Output:
 *   void, but we will add to the proto_tree if it is not NULL.
 */
void
dissect_osi_options(unsigned char opt_len, tvbuff_t *tvb, int offset, proto_tree *tree, packet_info *pinfo)
{
  proto_item *ti;
  proto_tree *osi_option_tree = NULL;
  unsigned char      parm_len        = 0;
  unsigned char      parm_type       = 0;
  uint8_t     octet;
  uint32_t    sec_type;
  tvbuff_t   *next_tvb;

    osi_option_tree = proto_tree_add_subtree(tree, tvb, offset, opt_len,
                             ett_osi_options, &ti, "### Option Section ###");
    if ( 0 == opt_len ) {
       expert_add_info(pinfo, ti, &ei_osi_options_none);
       return;
    }

    while ( 0 < opt_len ) {
      parm_type = tvb_get_uint8(tvb, offset++);
      parm_len = tvb_get_uint8(tvb, offset++);

      switch ( parm_type ) {
        case OSI_OPT_QOS_MAINTANANCE:
          octet = tvb_get_uint8(tvb, offset);
          dissect_option_qos(octet, osi_option_tree, tvb, offset);
          break;

        case OSI_OPT_SECURITY:
          /*
           * This is unspecified by ISO 8473, and the interpretation
           * of the value of the security option appears to be
           * specified by various profiles, such as GOSIP, TUBA, and
           * ATN.
           *
           * Thus, we use a payload dissector, so the user can
           * specify which dissector to use.
           */
          proto_tree_add_item_ret_uint(osi_option_tree, hf_osi_options_security_type, tvb, offset, 1, ENC_BIG_ENDIAN, &sec_type);
          /* XXX */
          switch ( sec_type ) {

          case OSI_OPT_SEC_RESERVED:
          case OSI_OPT_SEC_SRC_ADR_SPEC:
          case OSI_OPT_SEC_DST_ADR_SPEC:
          default:
            break;

          case OSI_OPT_SEC_GLOBAL_UNIQUE:
              next_tvb = tvb_new_subset_length(tvb, offset + 1, parm_len - 1);
              dissector_try_payload(subdissector_decode_as_opt_security_table,
                                     next_tvb, pinfo, osi_option_tree);
              break;
          }
          break;

        case OSI_OPT_PRIORITY:
          octet = tvb_get_uint8(tvb, offset);
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
                              print_area(pinfo->pool, tvb, offset, parm_len));
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
                               osi_option_tree, pinfo);
          break;

        case OSI_OPT_REASON_OF_DISCARD:
          dissect_option_rfd(tvb_get_uint8(tvb, offset),
                             tvb_get_uint8(tvb, offset + 1), offset, parm_len,
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

  static int *ett[] = {
    &ett_osi_options,
    &ett_osi_qos,
    &ett_osi_route,
    &ett_osi_redirect
  };

  static ei_register_info ei[] = {
      { &ei_osi_options_none, { "osi.options.none", PI_PROTOCOL, PI_NOTE, "No Options for this PDU", EXPFILL }},
      { &ei_osi_options_rfd_error_class, { "osi.options.rfd.error_class.unknown", PI_PROTOCOL, PI_WARN, "UNKNOWN Error Class", EXPFILL }},
  };

  expert_module_t *expert_osi_options;

  proto_register_field_array(proto_osi, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_osi_options = expert_register_protocol(proto_osi);
  expert_register_field_array(expert_osi_options, ei, array_length(ei));

  subdissector_decode_as_opt_security_table = register_decode_as_next_proto(proto_osi,
        "osi.opt_security", "OSI Security Option", NULL);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
