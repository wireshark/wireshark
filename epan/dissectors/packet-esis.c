/* packet-esis.c
 * Routines for ISO/OSI End System to Intermediate System
 * Routing Exchange Protocol ISO 9542.
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

#include <glib.h>
#include <epan/packet.h>
#include <wsutil/pint.h>
#include <epan/nlpid.h>
#include "packet-osi.h"
#include "packet-osi-options.h"
#include "packet-esis.h"

void proto_register_esis(void);
void proto_reg_handoff_esis(void);

/* esis base header */
static int  proto_esis        = -1;

static int  hf_esis_nlpi      = -1;
static int  hf_esis_length    = -1;
static int  hf_esis_version   = -1;
static int  hf_esis_reserved  = -1;
static int  hf_esis_type      = -1;
static int  hf_esis_holdtime  = -1;
static int  hf_esis_checksum  = -1;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_esis_dal = -1;
static int hf_esis_number_of_source_addresses = -1;
static int hf_esis_netl = -1;
static int hf_esis_sal = -1;
static int hf_esis_bsnpal = -1;
static int hf_esis_net = -1;
static int hf_esis_da = -1;
static int hf_esis_bsnpa = -1;

static gint ett_esis              = -1;
static gint ett_esis_area_addr    = -1;

static const value_string esis_vals[] = {
  { ESIS_ESH_PDU, "ES HELLO"},
  { ESIS_ISH_PDU, "IS HELLO"},
  { ESIS_RD_PDU,  "RD REQUEST"},
  { 0,             NULL} };

/* internal prototypes */

static void esis_dissect_esh_pdu( guint8 len, tvbuff_t *tvb,
                           proto_tree *treepd);
static void esis_dissect_ish_pdu( guint8 len, tvbuff_t *tvb,
                           proto_tree *tree);
static void esis_dissect_redirect_pdu( guint8 len, tvbuff_t *tvb,
                           proto_tree *tree);

/* ################## Descriptions ###########################################*/
/* Parameters for the ESH PDU
 * Source Address Parameter:
 *
 * Octet:    Length:   Parameter Type:
 *     10          1   Number of Source Addresses ( NSAPs served by this Network
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
 *   idea whether I need this or not.
 *
 * Input
 *   tvbuff_t *      : tvbuff with packet data.
 *   proto_tree *    : tree of display data.  May be NULL.
 *   char *          : format text
 *   subsequent args : arguments to format
 *
 * Output:
 *   void (may modify proto tree)
 */
static void
esis_dissect_unknown( tvbuff_t *tvb, proto_tree *tree, const char *fmat, ...){
  va_list ap;

  va_start(ap, fmat);
  proto_tree_add_text_valist(tree, tvb, 0, -1, fmat, ap);
  va_end(ap);
}


static void
esis_dissect_esh_pdu( guint8 len, tvbuff_t *tvb, proto_tree *tree) {
  proto_tree *esis_area_tree;
  int         offset  = 0;
  int         no_sa   = 0;
  int         sal     = 0;

  proto_item  *ti;

  if (tree) {
    offset += ESIS_HDR_FIXED_LENGTH;

    no_sa  = tvb_get_guint8(tvb, offset);
    len   -= 1;

    ti = proto_tree_add_uint( tree, hf_esis_number_of_source_addresses, tvb, offset, 1, no_sa);
    offset++;

    esis_area_tree = proto_item_add_subtree( ti, ett_esis_area_addr );
    while ( no_sa-- > 0 ) {
      sal = (int) tvb_get_guint8(tvb, offset);
      proto_tree_add_uint_format_value(esis_area_tree, hf_esis_sal, tvb, offset, 1, sal, "%2u Octets", sal);
      offset++;
      proto_tree_add_text(esis_area_tree, tvb, offset, sal,
                          " SA: %s",
                          print_nsap_net( tvb_get_ptr(tvb, offset, sal), sal ) );
      offset += sal;
      len    -= ( sal + 1 );
    }
    dissect_osi_options( len, tvb, offset, tree );
  }
} /* esis_dissect_esh_pdu */

static void
esis_dissect_ish_pdu( guint8 len, tvbuff_t *tvb, proto_tree *tree) {

  int   offset  = 0;
  int   netl    = 0;

  if (tree) {
    offset += ESIS_HDR_FIXED_LENGTH;

    netl = (int) tvb_get_guint8(tvb, offset);
    proto_tree_add_text( tree, tvb, offset, netl + 1,
                         "### Network Entity Title Section ###");
    proto_tree_add_uint_format_value(tree, hf_esis_netl, tvb, offset++, 1, netl, "%2u Octets", netl);
    proto_tree_add_string( tree, hf_esis_net, tvb, offset, netl, print_nsap_net( tvb_get_ptr(tvb, offset, netl), netl ) );
    offset += netl;
    len    -= ( netl + 1 );

    dissect_osi_options( len, tvb, offset, tree );
  }
}

static void
esis_dissect_redirect_pdu( guint8 len, tvbuff_t *tvb, proto_tree *tree) {

  int   offset  = 0;
  int   tmpl    = 0;

  if (tree) {
    offset += ESIS_HDR_FIXED_LENGTH;

    tmpl = (int) tvb_get_guint8(tvb, offset);
    proto_tree_add_text( tree, tvb, offset, tmpl + 1,
                         "### Destination Address Section ###" );
    proto_tree_add_uint_format_value(tree, hf_esis_dal, tvb, offset++, 1, tmpl, "%2u Octets", tmpl);
    proto_tree_add_string( tree, hf_esis_da, tvb, offset, tmpl,
                         print_nsap_net( tvb_get_ptr(tvb, offset, tmpl), tmpl ) );
    offset += tmpl;
    len    -= ( tmpl + 1 );
    tmpl    = (int) tvb_get_guint8(tvb, offset);

    proto_tree_add_text( tree, tvb, offset, tmpl + 1,
                         "###  Subnetwork Address Section ###");
    proto_tree_add_uint_format_value(tree, hf_esis_bsnpal, tvb, offset++, 1, tmpl, "%2u Octets", tmpl);
    proto_tree_add_item( tree, hf_esis_bsnpa, tvb, offset, tmpl, ENC_NA);
    offset += tmpl;
    len    -= ( tmpl + 1 );
    tmpl    = (int) tvb_get_guint8(tvb, offset);

    if ( 0 == tmpl ) {
      proto_tree_add_text( tree, tvb, offset, 1,
                           "### No Network Entity Title Section ###" );
      offset++;
      len--;
    }
    else {
      proto_tree_add_text( tree, tvb, offset, 1,
                           "### Network Entity Title Section ###" );
      proto_tree_add_uint_format_value(tree, hf_esis_netl, tvb, offset++, 1, tmpl, "%2u Octets", tmpl );
      proto_tree_add_string( tree, hf_esis_net, tvb, offset, tmpl,
                           print_nsap_net( tvb_get_ptr(tvb, offset, tmpl), tmpl ) );
      offset += tmpl;
      len    -= ( tmpl + 1 );
    }
    dissect_osi_options( len, tvb, offset, tree );
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
 *   tvbuff *      : tvbuff referring to packet data
 *   packet_info * : info for current packet
 *   proto_tree *  : tree of display data.  May be NULL.
 *
 * Output:
 *   void, but we will add to the proto_tree if it is not NULL.
 */
static void
dissect_esis(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  const char *pdu_type_string        = NULL;
  const char *pdu_type_format_string = "PDU Type      : %s (R:%s%s%s)";
  esis_hdr_t  ehdr;
  proto_item *ti;
  proto_tree *esis_tree    = NULL;
  guint8      variable_len;
  guint       tmp_uint     = 0;
  const char *cksum_status;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ESIS");
  col_clear(pinfo->cinfo, COL_INFO);

  tvb_memcpy(tvb, (guint8 *)&ehdr, 0, sizeof ehdr);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_esis, tvb, 0, -1, ENC_NA);
    esis_tree = proto_item_add_subtree(ti, ett_esis);

    if (ehdr.esis_version != ESIS_REQUIRED_VERSION){
      esis_dissect_unknown(tvb, esis_tree,
                           "Unknown ESIS version (%u vs %u)",
                           ehdr.esis_version, ESIS_REQUIRED_VERSION );
      return;
    }

    if (ehdr.esis_length < ESIS_HDR_FIXED_LENGTH) {
      esis_dissect_unknown(tvb, esis_tree,
                           "Bogus ESIS length (%u, must be >= %u)",
                           ehdr.esis_length, ESIS_HDR_FIXED_LENGTH );
      return;
    }
    proto_tree_add_uint( esis_tree, hf_esis_nlpi, tvb, 0, 1, ehdr.esis_nlpi );
    proto_tree_add_uint( esis_tree, hf_esis_length, tvb,
                         1, 1, ehdr.esis_length );
    proto_tree_add_uint( esis_tree, hf_esis_version, tvb, 2, 1,
                         ehdr.esis_version );
    proto_tree_add_uint( esis_tree, hf_esis_reserved, tvb, 3, 1,
                         ehdr.esis_reserved );

    pdu_type_string = val_to_str(ehdr.esis_type&OSI_PDU_TYPE_MASK,
                                 esis_vals, "Unknown (0x%x)");

    proto_tree_add_uint_format( esis_tree, hf_esis_type, tvb, 4, 1,
                                ehdr.esis_type,
                                pdu_type_format_string,
                                pdu_type_string,
                                (ehdr.esis_type&0x80) ? "1" : "0",
                                (ehdr.esis_type&0x40) ? "1" : "0",
                                (ehdr.esis_type&0x20) ? "1" : "0");

    tmp_uint = pntoh16( ehdr.esis_holdtime );
    proto_tree_add_uint_format_value(esis_tree, hf_esis_holdtime, tvb, 5, 2,
                               tmp_uint, "%u seconds",
                               tmp_uint );

    tmp_uint = pntoh16( ehdr.esis_checksum );

    switch (calc_checksum( tvb, 0, ehdr.esis_length, tmp_uint )) {

    case NO_CKSUM:
      cksum_status = "Not Used";
      break;

    case DATA_MISSING:
      cksum_status = "Not checkable - not all of packet was captured";
      break;

    case CKSUM_OK:
      cksum_status = "Is good";
      break;

    case CKSUM_NOT_OK:
      cksum_status = "Is wrong";
      break;

    default:
      cksum_status = NULL;
      DISSECTOR_ASSERT_NOT_REACHED();
    }
    proto_tree_add_uint_format_value( esis_tree, hf_esis_checksum, tvb, 7, 2,
                                tmp_uint, "0x%x ( %s )",
                                tmp_uint, cksum_status );
  }


  /*
   * Let us make sure we use the same names for all our decodes
   * here.  First, dump the name into info column, and THEN
   * dispatch the sub-type.
   */
  col_add_str(pinfo->cinfo, COL_INFO,
                val_to_str( ehdr.esis_type&OSI_PDU_TYPE_MASK, esis_vals,
                            "Unknown (0x%x)" ) );

  variable_len = ehdr.esis_length - ESIS_HDR_FIXED_LENGTH;

  switch (ehdr.esis_type & OSI_PDU_TYPE_MASK) {
  case ESIS_ESH_PDU:
    esis_dissect_esh_pdu( variable_len, tvb, esis_tree);
    break;
  case ESIS_ISH_PDU:
    esis_dissect_ish_pdu( variable_len, tvb, esis_tree);
    break;
  case ESIS_RD_PDU:
    esis_dissect_redirect_pdu( variable_len, tvb, esis_tree);
    break;
  default:
    esis_dissect_unknown(tvb, esis_tree,
                         "Unknown ESIS packet type 0x%x",
                         ehdr.esis_type & OSI_PDU_TYPE_MASK );
  }
} /* dissect_esis */


/*
 * Name: proto_register_esis()
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
proto_register_esis(void) {
  static hf_register_info hf[] = {
    { &hf_esis_nlpi,
      { "Network Layer Protocol Identifier", "esis.nlpi",
        FT_UINT8, BASE_HEX, VALS(nlpid_vals), 0x0, NULL, HFILL }},

    { &hf_esis_length,
      { "PDU Length", "esis.length",  FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_esis_version,
      { "Version (==1)", "esis.ver",  FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_esis_reserved,
      { "Reserved(==0)", "esis.res",  FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_esis_type,
      { "PDU Type", "esis.type",      FT_UINT8, BASE_DEC, VALS(esis_vals), 0xff, NULL, HFILL }},

    { &hf_esis_holdtime,
      { "Holding Time", "esis.htime", FT_UINT16, BASE_DEC, NULL, 0x0, "s", HFILL }},

    { &hf_esis_checksum,
      { "Checksum", "esis.chksum",    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_esis_number_of_source_addresses, { "Number of Source Addresses (SA, Format: NSAP)", "esis.number_of_source_addresses", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_esis_sal, { "SAL", "esis.sal", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_esis_netl, { "NETL", "esis.netl", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_esis_dal, { "DAL", "esis.dal", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_esis_bsnpal, { "BSNPAL", "esis.bsnpal", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_esis_net, { "NET", "esis.net", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_esis_da, { "DA", "esis.da", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_esis_bsnpa, { "BSNPA", "esis.bsnpa", FT_SYSTEM_ID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
  };
  /*
   *
   *
   */
  static gint *ett[] = {
    &ett_esis,
    &ett_esis_area_addr,
  };

  proto_esis = proto_register_protocol( PROTO_STRING_ESIS, "ESIS", "esis");
  proto_register_field_array(proto_esis, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_dissector("esis", dissect_esis, proto_esis);
}

void
proto_reg_handoff_esis(void)
{
  dissector_handle_t esis_handle;

  esis_handle = find_dissector("esis");
  dissector_add_uint("osinl.incl", NLPID_ISO9542_ESIS, esis_handle);
}
