/* packet-esis.c
 * Routines for ISO/OSI End System to Intermediate System  
 * Routeing Exchange Protocol ISO 9542.
 *
 * $Id: packet-esis.c,v 1.6 2000/08/10 16:04:33 deniel Exp $
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
#include "packet-osi-options.h"
#include "packet-esis.h"


/* esis base header */
static int  proto_esis        = -1;

static int  hf_esis_nlpi      = -1;
static int  hf_esis_length    = -1;
static int  hf_esis_version   = -1;
static int  hf_esis_reserved  = -1;
static int  hf_esis_type      = -1;
static int  hf_esis_holdtime  = -1;
static int  hf_esis_checksum  = -1;

static gint ett_esis              = -1;
static gint ett_esis_area_addr    = -1;

static const value_string esis_vals[] = {
  { ESIS_ESH_PDU, "ES HELLO"},
  { ESIS_ISH_PDU, "IS HELLO"},
  { ESIS_RD_PDU,  "RD REQUEST"},
  { 0,             NULL} };

/* internal prototypes */

void esis_dissect_esh_pdu( u_char len, const u_char *pd, int offset,
                           frame_data *fd, proto_tree *treepd);
void esis_dissect_ish_pdu( u_char len, const u_char *pd, int offset,
                           frame_data *fd, proto_tree *tree);
void esis_dissect_redirect_pdu( u_char len, const u_char *pd, int offset,
                                frame_data *fd, proto_tree *tree);

/* ################## Descriptions ###########################################*/
/* Parameters for the ESH PDU
 * Source Address Parameter:
 *
 * Octet:    Length:   Parameter Type:
 *     10          1   Number of Source Adresses ( NSAPs served by this Network
 *     11          1   Source Address Length Indicator ( SAL )     #    Entity )
 * 12-m-1   variable   Source Address ( NSAP )
 *      m              Options, dissected in osi.c
 *
 *
 * Parameter for the ISH PDU:
 * Network Entity Title Parameter:
 *
 * Octet:    Length:   Parameter Type:
 *     10          1   Network Entity Title Length Indicator ( NETL )
 * 11-m-1   variable   Network Entity Title ( NET )
 *      m              Options, dissected in osi.c
 *
 *
 * Parameter for the RD PDU:
 * When re-directed to an IS:
 *
 *  Octet:   Length:   Parameter Type:
 *      10         1   Destination Address Length Indicator ( DAL )
 *  11>m-1  variable   Destination Address ( DA )
 *       m         1   Subnetwork Address Length Indicator ( BSNPAL )
 * m+1>n-1  variable   Subnetwork Address ( BSNPA )
 *       n         1   Network Entity Title Length Indicator ( NETL )
 * n+1>p-1  variable   Network Entity Title ( NET )
 *       p             Options, dissected in osi.c
 *
 *
 * Parameter for the RD PDU:
 * When re-directed to an ES:
 *
 *  Octet:   Length:   Parameter Type:
 *      10         1   Destination Address Length Indicator ( DAL )
 *  11>m-1  variable   Destination Address ( DA )
 *       m         1   Subnetwork Address Length Indicator ( BSNPAL )
 * m+1>n-1  variable   Subnetwork Address ( BSNPA )
 *       n         1   Network Entity Title Length Indicator ( NETL ) == 0
 *     n+1             Options, dissected in osi.c
 *
 */

/* ############################ Tool Functions ############################## */


/* ############################## Dissection Functions ###################### */
/*
 * Name: dissect_esis_unknown()
 *
 * Description:
 *   There was some error in the protocol and we are in unknown space
 *   here.  Add a tree item to cover the error and go on.  Note
 *   that we make sure we don't go off the end of the bleedin packet here!
 *
 *   This is just a copy of isis.c and isis.h, so I keep the stuff also
 *   and adapt the names to cover possible protocol errors! Ive really no
 *   idea wether I need this or not.
 *  
 * Input
 *   int offset      : Current offset into packet data.
 *   int len         : length of to dump.
 *   proto_tree *    : tree of display data.  May be NULL.
 *   frame_data * fd : frame data
 *   char *          : format text
 *
 * Output:
 *   void (may modify proto tree)
 */
void
esis_dissect_unknown(int offset,guint length,proto_tree *tree,frame_data *fd,
                     char *fmat, ...){
  va_list ap;

  if ( !IS_DATA_IN_FRAME(offset) ) {
    /* 
     * big oops   They were off the end of the packet already.
     * Just ignore this one.
    */
    return;
  }
  if ( !BYTES_ARE_IN_FRAME(offset, length) ) {
    /* 
     * length will take us past eop.  Truncate length.
    */
    length = END_OF_FRAME;
  }

  va_start(ap, fmat);
  proto_tree_add_text_valist(tree, NullTVB, offset, length, fmat, ap);
  va_end(ap);
}


void
esis_dissect_esh_pdu( u_char len, const u_char *pd, int offset, 
                      frame_data *fd, proto_tree *tree) {
  proto_tree *esis_area_tree;
  int         no_sa   = 0;
  int         sal     = 0;
  
  proto_item  *ti;
  
  if (tree) {
    offset += ESIS_HDR_FIXED_LENGTH;

    no_sa  = pd[offset];
    len   -= 1;

    ti = proto_tree_add_text( tree, NullTVB, offset++, END_OF_FRAME, 
            "Number of Source Addresses (SA, Format: NSAP) : %u", no_sa );
    
    esis_area_tree = proto_item_add_subtree( ti, ett_esis_area_addr );
    while ( no_sa-- > 0 ) {
       sal = (int) pd[offset++];
       proto_tree_add_text(esis_area_tree, NullTVB, offset, 1, "SAL: %2u Octets", sal);
       proto_tree_add_text(esis_area_tree, NullTVB, offset + 1, sal,
                           " SA: %s", print_nsap_net( &pd[offset], sal ) );
       offset += sal;
       len    -= ( sal + 1 );
    }
    dissect_osi_options( PDU_TYPE_ESIS_ESH, len, pd, offset, fd, tree );
  }  
} /* esis_dissect_esh_pdu */ ;

void
esis_dissect_ish_pdu( u_char len, const u_char *pd, int offset,
                      frame_data *fd, proto_tree *tree) {
  
  int   netl    = 0;

  if (tree) {
    offset += ESIS_HDR_FIXED_LENGTH;

    netl = (int) pd[ offset ];
    proto_tree_add_text( tree, NullTVB, offset, netl + 1, 
                         "### Network Entity Titel Section ###");
    proto_tree_add_text( tree, NullTVB, offset++, 1, "NETL: %2u Octets", netl);
    proto_tree_add_text( tree, NullTVB, offset, netl,
                           " NET: %s", print_nsap_net( &pd[offset], netl ) );
    offset += netl;
    len    -= ( netl + 1 );

    dissect_osi_options( PDU_TYPE_ESIS_ISH, len, pd, offset, fd, tree );
  }
};

void
esis_dissect_redirect_pdu( u_char len, const u_char *pd, int offset,
                           frame_data *fd, proto_tree *tree) {

  int   tmpl    = 0;

  if (tree) {
    offset += ESIS_HDR_FIXED_LENGTH;

    tmpl = (int) pd[ offset ];
    proto_tree_add_text( tree, NullTVB, offset, tmpl + 1, 
                         "### Destination Address Section ###" );
    proto_tree_add_text( tree, NullTVB, offset++, 1, "DAL: %2u Octets", tmpl);
    proto_tree_add_text( tree, NullTVB, offset, tmpl,
                         " DA : %s", print_nsap_net( &pd[offset], tmpl ) );
    offset += tmpl;
    len    -= ( tmpl + 1 );
    tmpl    = (int) pd[ offset ];

    proto_tree_add_text( tree, NullTVB, offset, tmpl + 1, 
                         "###  Subnetwork Address Section ###");
    proto_tree_add_text( tree, NullTVB, offset++, 1, "BSNPAL: %2u Octets", tmpl);
    proto_tree_add_text( tree, NullTVB, offset, tmpl,
                           " BSNPA: %s", print_system_id( &pd[offset], tmpl ) );
    offset += tmpl;
    len    -= ( tmpl + 1 );
    tmpl    = (int) pd[ offset ];

    if ( 0 == tmpl ) {
      proto_tree_add_text( tree, NullTVB, offset, 1, 
                           "### No Network Entity Title Section ###" );
      offset++;
      len--;
    }
    else {
      proto_tree_add_text( tree, NullTVB, offset, 1,
                           "### Network Entity Title Section ###" );
      proto_tree_add_text( tree, NullTVB, offset++, 1, "NETL: %2u Octets", tmpl );
      proto_tree_add_text( tree, NullTVB, offset, tmpl,
                           " NET: %s", print_nsap_net( &pd[offset], tmpl ) );
      offset += tmpl;
      len    -= ( tmpl + 1 );
    }
    dissect_osi_options( PDU_TYPE_ESIS_RD, len, pd, offset, fd, tree );
  }
}


/*
 * Name: dissect_esis()
 * 
 * Description:
 *   Main entry area for esis de-mangling.  This will build the
 *   main esis tree data and call the sub-protocols as needed.
 *
 * Input:
 *   u_char *     : packet data
 *   int          : offset into packet where we are (packet_data[offset]== start
 *                  of what we care about)
 *   frame_data * : frame data (whole packet with extra info)
 *   proto_tree * : tree of display data.  May be NULL.
 *
 * Output:
 *   void, but we will add to the proto_tree if it is not NULL.
 */
static void
dissect_esis(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
   char       *pdu_type_string        = NULL;
   char       *pdu_type_format_string = "PDU Type      : %s (R:%s%s%s)";   
   esis_hdr_t *ehdr;
   proto_item *ti;
   proto_tree *esis_tree    = NULL;
   int         variable_len = 0;
   u_int       tmp_uint     = 0;

   if (check_col(fd, COL_PROTOCOL))
     col_add_str(fd, COL_PROTOCOL, "ESIS");

   if (!BYTES_ARE_IN_FRAME(offset, sizeof(*ehdr))) {
     esis_dissect_unknown(offset, sizeof(*ehdr), tree, fd,
                          "Not enough capture data for header (%d vs %d)",
			  sizeof(*ehdr), END_OF_FRAME);
     return;
   }

   ehdr = (esis_hdr_t *) &pd[offset];
   
   if (ehdr->esis_version != ESIS_REQUIRED_VERSION){
     esis_dissect_unknown(offset, END_OF_FRAME, tree, fd,
                          "Unknown ESIS version (%d vs %d)",
                           ehdr->esis_version, ESIS_REQUIRED_VERSION );
     return;
   }

   if (tree) {
     ti = proto_tree_add_item(tree, proto_esis, NullTVB, offset, END_OF_FRAME, FALSE);
     esis_tree = proto_item_add_subtree(ti, ett_esis);

     proto_tree_add_uint( esis_tree, hf_esis_nlpi, NullTVB, offset, 1, ehdr->esis_nlpi );
     proto_tree_add_uint( esis_tree, hf_esis_length, NullTVB,
                          offset + 1, 1, ehdr->esis_length );
     proto_tree_add_uint( esis_tree, hf_esis_version, NullTVB, offset + 2, 1, 
                          ehdr->esis_version );
     proto_tree_add_uint( esis_tree, hf_esis_reserved, NullTVB, offset + 3, 1, 
                          ehdr->esis_reserved );

     pdu_type_string = val_to_str(ehdr->esis_type&OSI_PDU_TYPE_MASK,
                                  esis_vals, "Unknown (0x%x)");

     proto_tree_add_uint_format( esis_tree, hf_esis_type, NullTVB, offset + 4, 1, 
                                 ehdr->esis_type, 
                                 pdu_type_format_string,
                                 pdu_type_string,
                                 (ehdr->esis_type&BIT_8) ? "1" : "0",
                                 (ehdr->esis_type&BIT_7) ? "1" : "0",
                                 (ehdr->esis_type&BIT_6) ? "1" : "0");

     tmp_uint = pntohs( ehdr->esis_holdtime );
     proto_tree_add_uint_format(esis_tree, hf_esis_holdtime, NullTVB, offset + 5, 2, 
                                tmp_uint, "Holding Time  : %u seconds",
                                tmp_uint );

     tmp_uint = pntohs( ehdr->esis_checksum );
     
     proto_tree_add_uint_format( esis_tree, hf_esis_checksum, NullTVB, offset + 7, 2,
                                 tmp_uint, "Checksum      : 0x%x ( %s )", 
                                 tmp_uint, calc_checksum( &pd[offset], 
                                                          ehdr->esis_length ,
                                                          tmp_uint ) );
   }


   /*
    * Let us make sure we use the same names for all our decodes
    * here.  First, dump the name into info column, and THEN
    * dispatch the sub-type.
    */
   if (check_col(fd, COL_INFO)) {
     col_add_str(fd, COL_INFO, 
                 val_to_str( ehdr->esis_type&OSI_PDU_TYPE_MASK, esis_vals,
                             "Unknown (0x%x)" ) );
   } 

   variable_len = ehdr->esis_length - ESIS_HDR_FIXED_LENGTH;

   switch (ehdr->esis_type) {
     case ESIS_ESH_PDU:
          esis_dissect_esh_pdu( variable_len, pd, offset, fd, esis_tree);
     break;
     case ESIS_ISH_PDU:
          esis_dissect_ish_pdu( variable_len, pd, offset, fd, esis_tree);
     break;
     case ESIS_RD_PDU:
          esis_dissect_redirect_pdu( variable_len, pd, offset, fd, 
                                     esis_tree);
     break;
     default:
         esis_dissect_unknown(offset, END_OF_FRAME, tree, fd,
                               "unknown esis packet type" );
   }
} /* dissect_esis */


/*
 * Name: proto_register_esisesis()
 *
 * Description:
 *	main register for esis protocol set.  We register some display
 *	formats and the protocol module variables.
 *
 * 	NOTE: this procedure to autolinked by the makefile process that
 *	builds register.c
 *
 * Input: 
 *	void
 *
 * Output:
 *	void
 */
void 
proto_register_esis(void) {
  static hf_register_info hf[] = {
    { &hf_esis_nlpi,
      { "Network Layer Protocol Identifier", "esis.nlpi",	
        FT_UINT8, BASE_HEX, VALS(nlpid_vals), 0x0, ""                       }},
    { &hf_esis_length,
      { "PDU Length    ", "esis.length", FT_UINT8, BASE_DEC, NULL, 0x0, "" }},
    { &hf_esis_version,
      { "Version (==1) ", "esis.ver",    FT_UINT8, BASE_DEC, NULL, 0x0, "" }},
    { &hf_esis_reserved,
      { "Reserved(==0) ", "esis.res",    FT_UINT8, BASE_DEC, NULL, 0x0, "" }},
    { &hf_esis_type,
      { "PDU Type      ", "esis.type",   FT_UINT8, BASE_DEC, VALS(esis_vals),
         0xff, "" }},
    { &hf_esis_holdtime,
      { "Holding Time  ", "esis.htime",  FT_UINT16, BASE_DEC, NULL, 0x0, " s"}},
    { &hf_esis_checksum,
      { "Checksum      ", "esis.chksum", FT_UINT16, BASE_HEX, NULL, 0x0, "" }}
  };
  /*
   * 
   * 
   */
  static gint *ett[] = {
    &ett_esis,
    &ett_esis_area_addr,
  };

  proto_esis = proto_register_protocol( PROTO_STRING_ESIS, "esis");
  proto_register_field_array(proto_esis, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
};

void
proto_reg_handoff_esis(void)
{
  old_dissector_add("osinl", NLPID_ISO9542_ESIS, dissect_esis);
}
