/* packet-osi-options.c
 * Routines for the decode of ISO/OSI option part
 * Covers:
 * ISO  8473 CLNP (ConnectionLess Mode Network Service Protocol)
 * ISO 10589 ISIS (Intradomain Routing Information Exchange Protocol)
 * ISO  9542 ESIS (End System To Intermediate System Routing Exchange Protocol)
 *
 * $Id$
 * Ralf Schneider <Ralf.Schneider@t-online.de>
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

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/nlpid.h>
#include "packet-osi.h"
#include "packet-isis.h"
#include "packet-isis-clv.h"
#include "packet-isis-hello.h"
#include "packet-isis-lsp.h"
#include "packet-isis-snp.h"
#include "packet-esis.h"
#include "packet-osi-options.h"

#define OSI_OPT_SECURITY           0xc5
#define OSI_OPT_QOS_MAINTANANCE    0xc3
#define OSI_OPT_PRIORITY           0xcd
#define OSI_OPT_ADDRESS_MASK       0xe1
#define OSI_OPT_SNPA_MASK          0xe2
#define OSI_OPT_ES_CONFIG_TIMER    0xc6

#define OSI_OPT_MAX_PRIORITY       0x0e

#define OSI_OPT_PADDING            0xcc
#define OSI_OPT_SOURCE_ROUTING     0xc8
#define OSI_OPT_RECORD_OF_ROUTE    0xcb
#define OSI_OPT_REASON_OF_DISCARD  0xc1

#define OSI_OPT_SEC_MASK           0xc0
#define OSI_OPT_SEC_RESERVED       0x00
#define OSI_OPT_SEC_SRC_ADR_SPEC   0x40
#define OSI_OPT_SEC_DST_ADR_SPEC   0x80
#define OSI_OPT_SEC_GLOBAL_UNIQUE  0xc0

#define OSI_OPT_QOS_MASK           0xc0
#define OSI_OPT_QOS_RESERVED       0x00
#define OSI_OPT_QOS_SRC_ADR_SPEC   0x40
#define OSI_OPT_QOS_DST_ADR_SPEC   0x80
#define OSI_OPT_QOS_GLOBAL_UNIQUE  0xc0

#define OSI_OPT_QOS_SUB_MASK        0x3f
#define OSI_OPT_QOS_SUB_RSVD        0x20
#define OSI_OPT_QOS_SUB_SEQ_VS_TRS  0x10
#define OSI_OPT_QOS_SUB_CONG_EXPED  0x08
#define OSI_OPT_QOS_SUB_TSD_VS_COST 0x04
#define OSI_OPT_QOS_SUB_RESERR_TRS  0x02
#define OSI_OPT_QOS_SUB_RESERR_COST 0x01

#define OSI_OPT_RFD_GENERAL         0x00
#define OSI_OPT_RFD_ADDRESS         0x80
#define OSI_OPT_RFD_SOURCE_ROUTING  0x90
#define OSI_OPT_RFD_LIFETIME        0xa0
#define OSI_OPT_RFD_PDU_DISCARDED   0xb0
#define OSI_OPT_RFD_REASSEMBLY      0xc0

#define OSI_OPT_RFD_MASK            0xf0
#define OSI_OPT_RFD_SUB_MASK        0x0f




static gint ott_osi_options       = -1;
static gint ott_osi_qos           = -1;
static gint ott_osi_route         = -1;
static gint ott_osi_redirect      = -1;

static const value_string osi_opt_sec_vals[] = {
        { OSI_OPT_SEC_RESERVED,      "Reserved"},
        { OSI_OPT_SEC_SRC_ADR_SPEC,  "Source Address Specific"},
        { OSI_OPT_SEC_DST_ADR_SPEC,  "Destination Address Specific"},
        { OSI_OPT_SEC_GLOBAL_UNIQUE, "Globally Unique"},
        { 0,            NULL} };

static const value_string osi_opt_qos_vals[] = {
        { OSI_OPT_QOS_RESERVED,      "Reserved"},
        { OSI_OPT_QOS_SRC_ADR_SPEC,  "Source Address Specific"},
        { OSI_OPT_QOS_DST_ADR_SPEC,  "Destination Address Specific"},
        { OSI_OPT_QOS_GLOBAL_UNIQUE, "Globally Unique"},
        { 0,            NULL} };

static const value_string osi_opt_qos_sub_vals[] = {
        { 0x20,  " xx10 0000 Reserved"},
        { 0x10,  " xx01 0000 Sequencing versus transit delay"},
        { 0x08,  " xx00 1000 Congestion experienced"},
        { 0x04,  " xx00 0100 Transit delay versus cost"},
        { 0x02,  " xx00 0010 Residual error probability versus transit delay"},
        { 0x01,  " xx00 0001 Residual error probability versus cost"},
        { 0,            NULL} };

static const value_string osi_opt_rfd_general[] = {
        { 0x00, "Reason not specified"},
        { 0x01, "Protocol procedure error"},
        { 0x02, "Incorrect checksum"},
        { 0x03, "PDU discarded due to congestion"},
        { 0x04, "Header syntax error ( cannot be parsed )"},
        { 0x05, "Segmentation needed but not permitted"},
        { 0x06, "Incomplete PDU received"},
        { 0x07, "Duplicate option"},
        { 0,    NULL} };

static const value_string osi_opt_rfd_address[] = {
        { 0x00, "Destination Address unreachable"},
        { 0x01, "Destination Address unknown"},
        { 0,    NULL} };

static const value_string osi_opt_rfd_src_route[] = {
        { 0x00, "Unspecified source routing error"},
        { 0x01, "Syntax error in source routing field"},
        { 0x02, "Unknown address in source routing field"},
        { 0x03, "Path not acceptable"},
        { 0,    NULL} };

static const value_string osi_opt_rfd_lifetime[] = {
        { 0x00, "Lifetime expired while data unit in transit"},
        { 0x01, "Lifetime expired during reassembly"},
        { 0,    NULL} };

static const value_string osi_opt_rfd_discarded[] = {
        { 0x00, "Unsupported option not specified"},
        { 0x01, "Unsupported protocol version"},
        { 0x02, "Unsupported security option"},
        { 0x03, "Unsupported source routing option"},
        { 0x04, "Unsupported recording of route option"},
        { 0,    NULL} };

static const value_string osi_opt_rfd_reassembly[] = {
        { 0x00, "Reassembly interference"},
        { 0,    NULL} };


static void
dissect_option_qos( const guchar type, const guchar sub_type, int offset,
                    guchar len, tvbuff_t *tvb, proto_tree *tree ) {

  guchar      tmp_type = 0;
  proto_item *ti;
  proto_tree *osi_qos_tree = NULL;


  ti = proto_tree_add_text( tree, tvb, offset, len,
                            "Quality of service maintenance: %s",
                       val_to_str( type, osi_opt_qos_vals, "Unknown (0x%x)") );

  osi_qos_tree = proto_item_add_subtree( ti, ott_osi_qos );

  if ( OSI_OPT_SEC_MASK == type ) {     /* Analye BIT field to get all Values */

    tmp_type = sub_type & OSI_OPT_QOS_SUB_RSVD;
    if ( tmp_type ) {
         proto_tree_add_text( osi_qos_tree, tvb, offset, len,
         val_to_str( tmp_type, osi_opt_qos_sub_vals, "Unknown (0x%x)") );
    }
    tmp_type = sub_type & OSI_OPT_QOS_SUB_SEQ_VS_TRS;
    if ( tmp_type ) {
         proto_tree_add_text( osi_qos_tree, tvb, offset, len,
         val_to_str( tmp_type, osi_opt_qos_sub_vals, "Unknown (0x%x)") );
    }
    tmp_type = sub_type &OSI_OPT_QOS_SUB_CONG_EXPED;
    if ( tmp_type ) {
         proto_tree_add_text( osi_qos_tree, tvb, offset, len,
         val_to_str( tmp_type, osi_opt_qos_sub_vals, "Unknown (0x%x)") );
    }
    tmp_type = sub_type & OSI_OPT_QOS_SUB_TSD_VS_COST;

    if ( tmp_type ) {
         proto_tree_add_text( osi_qos_tree, tvb, offset, len,
         val_to_str( tmp_type, osi_opt_qos_sub_vals, "Unknown (0x%x)") );
    }
    tmp_type = sub_type & OSI_OPT_QOS_SUB_RESERR_TRS;
    if ( tmp_type ) {
         proto_tree_add_text( osi_qos_tree, tvb, offset, len,
         val_to_str( tmp_type, osi_opt_qos_sub_vals, "Unknown (0x%x)") );
    }
    tmp_type = sub_type & OSI_OPT_QOS_SUB_RESERR_COST;
    if ( tmp_type ) {
         proto_tree_add_text( osi_qos_tree, tvb, offset, len,
         val_to_str( tmp_type, osi_opt_qos_sub_vals, "Unknown (0x%x)") );
    }
  }
}

static void
dissect_option_route( guchar parm_type, int offset, guchar parm_len,
                      tvbuff_t *tvb, proto_tree *tree ) {

  guchar      next_hop = 0;
  guint16     this_hop = 0;
  guchar      netl     = 0;
  guchar      last_hop = 0;
  guchar      cnt_hops = 0;

  proto_item *ti;
  proto_tree *osi_route_tree = NULL;

  static const value_string osi_opt_route[] = {
        { 0x03, "No Network Entity Titles Recorded Yet"},
        { 0xff, "Recording Terminated !"},
        { 0,    NULL} };

  if ( parm_type == OSI_OPT_SOURCE_ROUTING ) {
    next_hop = tvb_get_guint8(tvb, offset + 1 );
    netl     = tvb_get_guint8(tvb, next_hop + 2 );
    this_hop = offset + 3;         /* points to first netl */

    ti = proto_tree_add_text( tree, tvb, offset + next_hop, netl,
            "Source Routing: %s   ( Next Hop Highlighted In Data Buffer )",
            (tvb_get_guint8(tvb, offset) == 0) ? "Partial Source Routing" :
                                                 "Complete Source Routing"  );
  }
  else {
    last_hop = tvb_get_guint8(tvb, offset + 1 );
        /* points to the end of the list */
    netl     = tvb_get_guint8(tvb, last_hop );
        /* mis-used to highlight buffer */

    ti = proto_tree_add_text( tree, tvb, offset + next_hop, netl,
            "Record of Route: %s : %s",
            (tvb_get_guint8(tvb, offset) == 0) ? "Partial Source Routing" :
                                                 "Complete Source Routing" ,
            val_to_str( last_hop, osi_opt_route, "Unknown (0x%x" ) );
    if ( 255 == last_hop )
      this_hop = parm_len + 1;   /* recording terminated, nothing to show */
    else
      this_hop = offset + 3;
  }
  osi_route_tree = proto_item_add_subtree( ti, ott_osi_route );

  while ( this_hop < parm_len ) {
    netl = tvb_get_guint8(tvb, this_hop + 1);
    proto_tree_add_text( osi_route_tree, tvb, offset + this_hop, netl,
                  "Hop #%3u NETL: %2u, NET: %s",
                  cnt_hops++,
                  netl,
                  print_nsap_net( tvb_get_ptr(tvb, this_hop + 1, netl), netl ) );
    this_hop += 1 + netl;
  }
}





static void
dissect_option_rfd( const guchar error, const guchar field, int offset,
                          guchar len, tvbuff_t *tvb, proto_tree *tree ) {
  guchar error_class = 0;
  const char   *format_string[] =
             { "Reason for discard {General}        : %s, in field %u",
               "Reason for discard {Address}        : %s, in field %u",
               "Reason for discard {Source Routing}: %s, in field %u",
               "Reason for discard {Lifetime}       : %s, in field %u",
               "Reason for discard {PDU discarded}  : %s, in field %u",
               "Reason for discard {Reassembly}     : %s, in field %u"
             };

  error_class = error & OSI_OPT_RFD_MASK;
  tvb_ensure_bytes_exist(tvb, offset + field, 1);

  if ( OSI_OPT_RFD_GENERAL == error_class ) {
    proto_tree_add_text( tree, tvb, offset + field, 1, format_string[0],
                         val_to_str( error & OSI_OPT_RFD_SUB_MASK,
                               osi_opt_rfd_general, "Unknown (0x%x)"), field );
  }
  else if ( OSI_OPT_RFD_ADDRESS == error_class ) {
    proto_tree_add_text( tree, tvb, offset + field, 1, format_string[1],
                         val_to_str( error & OSI_OPT_RFD_SUB_MASK,
                               osi_opt_rfd_address, "Unknown (0x%x)"), field );
  }
  else if ( OSI_OPT_RFD_SOURCE_ROUTING == error_class ) {
    proto_tree_add_text( tree, tvb, offset + field, 1, format_string[2],
                         val_to_str( error & OSI_OPT_RFD_SUB_MASK,
                             osi_opt_rfd_src_route, "Unknown (0x%x)"), field );
  }
  else if ( OSI_OPT_RFD_LIFETIME == error_class ) {
    proto_tree_add_text( tree, tvb, offset + field, 1, format_string[3],
                         val_to_str( error & OSI_OPT_RFD_SUB_MASK,
                              osi_opt_rfd_lifetime, "Unknown (0x%x)"), field );
  }
  else if ( OSI_OPT_RFD_PDU_DISCARDED == error_class ) {
    proto_tree_add_text( tree, tvb, offset + field, 1, format_string[4],
                         val_to_str( error & OSI_OPT_RFD_SUB_MASK,
                             osi_opt_rfd_discarded, "Unknown (0x%x)"), field );
  }
  else if ( OSI_OPT_RFD_REASSEMBLY == error_class ) {
    proto_tree_add_text( tree, tvb, offset + field, 1, format_string[5],
                         val_to_str( error & OSI_OPT_RFD_SUB_MASK,
                            osi_opt_rfd_reassembly, "Unknown (0x%x)"), field );
  }
  else {
    proto_tree_add_text( tree, tvb, offset, len,
                         "Reason for discard: UNKNOWN Error Class" );
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
dissect_osi_options( guchar opt_len, tvbuff_t *tvb,
                     int offset, proto_tree *tree) {
   proto_item *ti;
   proto_tree *osi_option_tree = NULL;
   guchar      parm_len        = 0;
   guchar      parm_type       = 0;
   guint8      octet;

   if (tree) {
     if ( 0 == opt_len ) {
       proto_tree_add_text( tree, tvb, offset, 0,
                            "### No Options for this PDU ###" );
       return;
     }

     ti = proto_tree_add_text( tree, tvb, offset, opt_len,
                               "### Option Section ###" );
     osi_option_tree = proto_item_add_subtree( ti, ott_osi_options );

     while ( 0 < opt_len ) {
        parm_type   = (int) tvb_get_guint8(tvb, offset);
        offset++;
        parm_len    = (int) tvb_get_guint8(tvb, offset);
        offset++;

        switch ( parm_type ) {
          case   OSI_OPT_QOS_MAINTANANCE:
                 octet = tvb_get_guint8(tvb, offset);
                 dissect_option_qos( (guchar) (octet&OSI_OPT_QOS_MASK),
                                     (guchar) (octet&OSI_OPT_QOS_SUB_MASK),
                                     offset, parm_len, tvb, osi_option_tree );
          break;
          case   OSI_OPT_SECURITY:
                 octet = tvb_get_guint8(tvb, offset);
                 proto_tree_add_text( osi_option_tree, tvb, offset, parm_len,
                  "Security type: %s",
                  val_to_str( octet&OSI_OPT_SEC_MASK,
                              osi_opt_sec_vals, "Unknown (0x%x)")  );
          break;
          case   OSI_OPT_PRIORITY:
                 octet = tvb_get_guint8(tvb, offset);
                 if ( OSI_OPT_MAX_PRIORITY >= octet ) {
                   proto_tree_add_text( osi_option_tree, tvb, offset, parm_len,
                                        "Priority    : %u", octet );
                 }
                 else {
                   proto_tree_add_text( osi_option_tree, tvb, offset, parm_len,
                                        "Priority    : %u ( Invalid )",
                                        octet );
                 }
          break;
          case   OSI_OPT_ADDRESS_MASK:
                 proto_tree_add_text( osi_option_tree, tvb, offset, parm_len,
                  "Address Mask: %s",
		  print_area( tvb_get_ptr(tvb, offset, parm_len), parm_len ) );
          break;
          case   OSI_OPT_SNPA_MASK:
                 proto_tree_add_text( osi_option_tree, tvb, offset, parm_len,
                  "SNPA Mask   : %s",
		  print_system_id( tvb_get_ptr(tvb, offset, parm_len), parm_len ));
          break;
          case   OSI_OPT_ES_CONFIG_TIMER:
                 proto_tree_add_text( osi_option_tree, tvb, offset, parm_len,
                  "ESCT     : %u seconds", tvb_get_ntohs( tvb, offset ) );
          break;
          case   OSI_OPT_PADDING:
                 proto_tree_add_text( osi_option_tree, tvb, offset, parm_len,
                  "Padding  : %u Octets", parm_len ) ;
          break;
          case   OSI_OPT_SOURCE_ROUTING:
          case   OSI_OPT_RECORD_OF_ROUTE:
                 dissect_option_route( parm_type,
                                       offset, parm_len, tvb, osi_option_tree );
          break;
          case   OSI_OPT_REASON_OF_DISCARD:
                 dissect_option_rfd( tvb_get_guint8(tvb, offset),
                                     tvb_get_guint8(tvb, offset + 1),
                                     offset, parm_len, tvb, osi_option_tree );
          break;
        }
        opt_len -= parm_len + 2;
        offset  += parm_len;
      }
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
  static gint *ott[] = {
    &ott_osi_options,
    &ott_osi_qos,
    &ott_osi_route,
    &ott_osi_redirect,
  };
  proto_register_subtree_array( ott, array_length(ott));
}
