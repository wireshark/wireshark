/* packet-osi-options.c
 * Routines for the decode of ISO/OSI option part 
 * Covers:
 * ISO  8473 CLNP (ConnectionLess Mode Network Service Protocol)
 * ISO 10589 ISIS (Intradomain Routeing Information Exchange Protocol)
 * ISO  9542 ESIS (End System To Intermediate System Routeing Exchange Protocol)
 *
 * $Id: packet-osi-options.c,v 1.1 2000/04/15 22:11:11 guy Exp $
 * Ralf Schneider <Ralf.Schneider@t-online.de>
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
 *
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include "packet.h"
#include "nlpid.h"
#include "packet-osi.h"
#include "packet-isis.h"
#include "packet-isis-clv.h"
#include "packet-isis-hello.h"
#include "packet-isis-lsp.h"
#include "packet-isis-snp.h"
#include "packet-esis.h"
#include "packet-clnp.h"
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
#define OSI_OPT_RFD_SOURCE_ROUTEING 0x90
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
        { 0x00, "Unspecified source routeing error"},
        { 0x01, "Syntax error in source routeing field"},
        { 0x02, "Unknown address in source routeing field"},
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
        { 0x03, "Unsupported source routeing option"},
        { 0x04, "Unsupported recording of route option"},
        { 0,    NULL} };
     
static const value_string osi_opt_rfd_reassembly[] = {
        { 0x00, "Reassembly interference"},
        { 0,    NULL} };
     

void
dissect_option_qos( const u_char type, const u_char sub_type, u_char offset,
                    u_char len, const u_char *pd, proto_tree *tree ) {

  u_char      tmp_type = 0;
  proto_item *ti;
  proto_tree *osi_qos_tree = NULL;
  
  
  ti = proto_tree_add_text( tree, offset, len,
                            "Quality of service maintenance: %s",
                       val_to_str( type, osi_opt_qos_vals, "Unknown (0x%x)") );
  
  osi_qos_tree = proto_item_add_subtree( ti, ott_osi_qos );
                           
  if ( OSI_OPT_SEC_MASK == type ) {     /* Analye BIT field to get all Values */

    tmp_type = sub_type & OSI_OPT_QOS_SUB_RSVD;
    if ( tmp_type ) {
         proto_tree_add_text( osi_qos_tree, offset, len,
         val_to_str( tmp_type, osi_opt_qos_sub_vals, "Unknown (0x%x)") );
    }
    tmp_type = sub_type & OSI_OPT_QOS_SUB_SEQ_VS_TRS;
    if ( tmp_type ) {
         proto_tree_add_text( osi_qos_tree, offset, len,
         val_to_str( tmp_type, osi_opt_qos_sub_vals, "Unknown (0x%x)") );
    }
    tmp_type = sub_type &OSI_OPT_QOS_SUB_CONG_EXPED;
    if ( tmp_type ) {
         proto_tree_add_text( osi_qos_tree, offset, len,
         val_to_str( tmp_type, osi_opt_qos_sub_vals, "Unknown (0x%x)") );
    }
    tmp_type = sub_type & OSI_OPT_QOS_SUB_TSD_VS_COST;
    
    if ( tmp_type ) {
         proto_tree_add_text( osi_qos_tree, offset, len,
         val_to_str( tmp_type, osi_opt_qos_sub_vals, "Unknown (0x%x)") );
    }
    tmp_type = sub_type & OSI_OPT_QOS_SUB_RESERR_TRS;
    if ( tmp_type ) {
         proto_tree_add_text( osi_qos_tree, offset, len,
         val_to_str( tmp_type, osi_opt_qos_sub_vals, "Unknown (0x%x)") );
    }
    tmp_type = sub_type & OSI_OPT_QOS_SUB_RESERR_COST;
    if ( tmp_type ) {
         proto_tree_add_text( osi_qos_tree, offset, len,
         val_to_str( tmp_type, osi_opt_qos_sub_vals, "Unknown (0x%x)") );
    }
  }
};
void
dissect_option_route( u_char parm_type, u_char offset, u_char parm_len, 
                      const u_char *pd, proto_tree *tree ) {

  u_char      next_hop = 0;
  u_char      this_hop = 0;
  u_char      netl     = 0;
  u_char      last_hop = 0;
  u_char      cnt_hops = 0;
  
  proto_item *ti;
  proto_tree *osi_route_tree = NULL;

  static const value_string osi_opt_route[] = {
        { 0x03, "No Network Entity Titles Recorded Yet"},
        { 0xff, "Recording Terminated !"},
        { 0,    NULL} };

  if ( parm_type == OSI_OPT_SOURCE_ROUTING ) {
    next_hop = pd[offset + 1 ];
    netl     = pd[next_hop + 2 ];
    this_hop = offset + 3;         /* points to first netl */

    ti = proto_tree_add_text( tree, offset + next_hop, netl, 
            "Source Routing: %s   ( Next Hop Highlighted In Data Buffer )",
            (pd[offset] == 0) ? "Partial Source Routeing" :
                                "Complete Source Routeing"  ); 
  }
  else {
    last_hop = pd[offset + 1 ];  /* points to the end of the list */
    netl     = pd[ last_hop ];   /* mis-used to highlight buffer */

    ti = proto_tree_add_text( tree, offset + next_hop, netl,
            "Record of Route: %s : %s",
            (pd[offset] == 0) ? "Partial Source Routeing" :
                                "Complete Source Routeing" ,
            val_to_str( last_hop, osi_opt_route, "Unknown (0x%x" ) );
    if ( 255 == last_hop ) 
      this_hop = parm_len + 1;   /* recording terminated, nothing to show */
    else
      this_hop = offset + 3;
  }
  osi_route_tree = proto_item_add_subtree( ti, ott_osi_route );
  
  while ( this_hop < parm_len ) {
    netl = pd[this_hop + 1];
    proto_tree_add_text( osi_route_tree, offset + this_hop, netl,
                  "Hop #%3u NETL: %2u, NET: %s",
                  cnt_hops++,
                  netl,
                  print_nsap_net( &pd[this_hop + 1], netl ) );
    this_hop += 1 + netl;
  }
};





void
dissect_option_rfd( const u_char error, const u_char field, u_char offset,
                          u_char len, const u_char *pd, proto_tree *tree ) {
  u_char error_class = 0;
  char   *format_string[] = 
             { "Reason for discard {General}        : %s, in field %u",
               "Reason for discard {Address}        : %s, in field %u",
               "Reason for discard {Source Routeing}: %s, in field %u",
               "Reason for discard {Lifetime}       : %s, in field %u",
               "Reason for discard {PDU discarded}  : %s, in field %u",
               "Reason for discard {Reassembly}     : %s, in field %u"
             };
  
  error_class = error & OSI_OPT_RFD_MASK;

  if ( OSI_OPT_RFD_GENERAL == error_class ) {
    proto_tree_add_text( tree, offset + field, 1, format_string[0],
                         val_to_str( error & OSI_OPT_RFD_SUB_MASK,
                               osi_opt_rfd_general, "Unknown (0x%x)"), field );
  }
  else if ( OSI_OPT_RFD_ADDRESS == error_class ) {
    proto_tree_add_text( tree, offset + field, 1, format_string[1],
                         val_to_str( error & OSI_OPT_RFD_SUB_MASK,
                               osi_opt_rfd_address, "Unknown (0x%x)"), field );
  }
  else if ( OSI_OPT_RFD_SOURCE_ROUTEING == error_class ) {
    proto_tree_add_text( tree, offset + field, 1, format_string[2],
                         val_to_str( error & OSI_OPT_RFD_SUB_MASK,
                             osi_opt_rfd_src_route, "Unknown (0x%x)"), field );
  }
  else if ( OSI_OPT_RFD_LIFETIME == error_class ) {
    proto_tree_add_text( tree, offset + field, 1, format_string[3],
                         val_to_str( error & OSI_OPT_RFD_SUB_MASK,
                              osi_opt_rfd_lifetime, "Unknown (0x%x)"), field );
  }
  else if ( OSI_OPT_RFD_PDU_DISCARDED == error_class ) {
    proto_tree_add_text( tree, offset + field, 1, format_string[4],
                         val_to_str( error & OSI_OPT_RFD_SUB_MASK,
                             osi_opt_rfd_discarded, "Unknown (0x%x)"), field );
  }
  else if ( OSI_OPT_RFD_REASSEMBLY == error_class ) {
    proto_tree_add_text( tree, offset + field, 1, format_string[5],
                         val_to_str( error & OSI_OPT_RFD_SUB_MASK,
                            osi_opt_rfd_reassembly, "Unknown (0x%x)"), field );
  }
  else {
    proto_tree_add_text( tree, offset, len,
                         "Reason for discard: UNKNOWN Error Class" );
  } 
};

/* ############################## Dissection Functions ###################### */

/*
 * Name: dissect_osi_options()
 * 
 * Description:
 *   Main entry area for esis de-mangling.  This will build the
 *   main esis tree data and call the sub-protocols as needed.
 *
 * Input:
 *   u_char       : PDU type to check if option is allowed or not
 *   u_char       : length of option section 
 *   u_char *     : packet data
 *   int          : offset into packet where we are (packet_data[offset]== start
 *                  of what we care about)
 *   frame_data * : frame data (whole packet with extra info)
 *   proto_tree * : tree of display data.  May be NULL.
 *
 * Output:
 *   void, but we will add to the proto_tree if it is not NULL.
 */
void
dissect_osi_options( u_char pdu_type, u_char opt_len, const u_char *pd, 
                     int offset, frame_data *fd, proto_tree *tree) {
   proto_item *ti;
   proto_tree *osi_option_tree = NULL;
   u_char      parm_len        = 0;
   u_char      parm_type       = 0;

   if (tree) {
     if ( 0 == opt_len ) {
       proto_tree_add_text( tree, offset, 0, 
                            "### No Options for this PDU ###" );
       return;
     }
     
     if ( opt_len > END_OF_FRAME ) {
       proto_tree_add_text( tree, offset, END_OF_FRAME, 
           "### Options go past the end of the captured data in this PDU ###" );
       return;
     }

     ti = proto_tree_add_text( tree, offset, opt_len,
                               "### Option Section ###" );
     osi_option_tree = proto_item_add_subtree( ti, ott_osi_options );

     while ( 0 < opt_len ) {
        parm_type   = (int) pd[offset++];
        parm_len    = (int) pd[offset++];
         
        switch ( parm_type ) {
          case   OSI_OPT_QOS_MAINTANANCE:
                 dissect_option_qos( pd[offset]&OSI_OPT_QOS_MASK,
                                     pd[offset]&OSI_OPT_QOS_SUB_MASK,
                                     offset, parm_len, pd, osi_option_tree );
          break;
          case   OSI_OPT_SECURITY:
                 proto_tree_add_text( osi_option_tree, offset, parm_len,
                  "Security type: %s",
                  val_to_str( pd[offset]&OSI_OPT_SEC_MASK,
                              osi_opt_sec_vals, "Unknown (0x%x)")  );
          break;
          case   OSI_OPT_PRIORITY:
                 if ( OSI_OPT_MAX_PRIORITY >= pd[offset] ) { 
                   proto_tree_add_text( osi_option_tree, offset, parm_len,
                                        "Priority    : %u", pd[offset] );
                 }
                 else {
                   proto_tree_add_text( osi_option_tree, offset, parm_len,
                                        "Priority    : %u ( Invalid )", 
                                        pd[offset] );
                 } 
          break;
          case   OSI_OPT_ADDRESS_MASK:
                 proto_tree_add_text( osi_option_tree, offset, parm_len,
                  "Address Mask: %s", print_area( &pd[offset], parm_len ) );
          break;
          case   OSI_OPT_SNPA_MASK:
                 proto_tree_add_text( osi_option_tree, offset, parm_len,
                  "SNPA Mask   : %s", print_system_id( &pd[offset], parm_len ));
          break;
          case   OSI_OPT_ES_CONFIG_TIMER:
                 proto_tree_add_text( osi_option_tree, offset, parm_len,
                  "ESCT     : %u seconds", pntohs( &pd[offset] ) ); 
          break;
          case   OSI_OPT_PADDING:
                 proto_tree_add_text( osi_option_tree, offset, parm_len,
                  "Padding  : %u Octets", parm_len ) ;
          break;
          case   OSI_OPT_SOURCE_ROUTING:
          case   OSI_OPT_RECORD_OF_ROUTE:
                 dissect_option_route( parm_type,
                                       offset, parm_len, pd, osi_option_tree );
          break;
          case   OSI_OPT_REASON_OF_DISCARD:
                 dissect_option_rfd( pd[offset],
                                     pd[offset + 1],
                                     offset, parm_len, pd, osi_option_tree );
          break;
        }
        opt_len -= parm_len + 2;
        offset  += parm_len;
      }
   } 
}; /* dissect-osi-options */


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
};
                                                       
