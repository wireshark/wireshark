/* packet-trill.c
 * Routines for TRILL (TRansparent Interconnection of Lots of Links) dissection
 * Copyright 2010, David Bond <mokon@mokon.net>
 *
 * $Id$
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
 * See: http://tools.ietf.org/html/draft-ietf-trill-rbridge-protocol-16
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/etypes.h>

static int proto_trill = -1 ;
static gint ett_trill = -1 ;

static int hf_trill_version = -1 ;
static int hf_trill_reserved = -1 ;
static int hf_trill_multi_dst = -1 ;
static int hf_trill_op_len = -1 ;
static int hf_trill_hop_cnt = -1 ;
static int hf_trill_egress_nick = -1 ;
static int hf_trill_ingress_nick = -1 ;
/* TODO For now we will just add all the options into a byte field.
   Later this should be parsed out into a sub-tree with all the option
   details. */
static int hf_trill_options= -1 ;

static dissector_handle_t eth_dissector ;

#define TRILL_VERSION_MASK   0xC000
#define TRILL_RESERVED_MASK  0x3000
#define TRILL_MULTI_DST_MASK 0x0800
#define TRILL_OP_LEN_MASK    0x07C0
#define TRILL_HOP_CNT_MASK   0x003F

#define TRILL_PROTO_COL_NAME "TRILL"
#define TRILL_PROTO_COL_INFO "TRILL Encapsulated Frame"

#define TRILL_MIN_FRAME_LENGTH     6
#define TRILL_BIT_FIELDS_LEN       2
#define TRILL_NICKNAME_LEN         2
#define TRILL_OP_LENGTH_BYTE_UNITS 0x4

static const true_false_string multi_dst_strings = {
  "Multi-Destination TRILL Frame",
  "Known Unicast TRILL Frame"
} ;

static const range_string version_strings[] = {
  { 0, 0, "draft-ietf-trill-rbridge-protocol-16 Version" },
  { 1, 3, "Unallocated Version" },
  { 0, 0, NULL }
} ;

static const range_string reserved_strings[] = {
  { 0, 0, "Legal Value" },
  { 1, 3, "Illegal Value" },
  { 0, 0, NULL }
} ;

static const range_string nickname_strings[] = {
  { 0x0000, 0x0000, "Nickname Not Specified" },
  { 0x0001, 0xFFBF, "Valid Nickname" },
  { 0xFFC0, 0xFFFE, "Reserved for Future Specification" },
  { 0xFFFF, 0xFFFF, "Permanently Reserved" },
  { 0, 0, NULL }
} ;

/* Trill Dissector */
static int
dissect_trill( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_ )
{
  proto_item *ti ;
  proto_tree *trill_tree ;
  guint32     op_len ;
  tvbuff_t   *next_tvb ;
  int         offset = 0 ;

  col_set_str( pinfo->cinfo, COL_PROTOCOL, TRILL_PROTO_COL_NAME ) ;
  col_set_str( pinfo->cinfo, COL_INFO, TRILL_PROTO_COL_INFO ) ;

  op_len = tvb_get_bits( tvb, 5, 5, ENC_BIG_ENDIAN ) * TRILL_OP_LENGTH_BYTE_UNITS ;
  if (tree) {
    ti = proto_tree_add_item( tree, proto_trill, tvb, 0, -1, ENC_NA ) ;
    trill_tree = proto_item_add_subtree( ti, ett_trill ) ;

    /* Parse the bit fields, i.e. V, R, M, Op-Length, Hop Count. */
    proto_tree_add_item( trill_tree, hf_trill_version, tvb, offset,
      TRILL_BIT_FIELDS_LEN, ENC_BIG_ENDIAN ) ;
    proto_tree_add_item( trill_tree, hf_trill_reserved, tvb, offset,
      TRILL_BIT_FIELDS_LEN, ENC_BIG_ENDIAN ) ;
    proto_tree_add_item( trill_tree, hf_trill_multi_dst, tvb, offset,
      TRILL_BIT_FIELDS_LEN, ENC_BIG_ENDIAN ) ;
    proto_tree_add_item( trill_tree, hf_trill_op_len, tvb, offset,
      TRILL_BIT_FIELDS_LEN, ENC_BIG_ENDIAN ) ;
    proto_tree_add_item( trill_tree, hf_trill_hop_cnt, tvb, offset,
      TRILL_BIT_FIELDS_LEN, ENC_BIG_ENDIAN ) ;

    /* Parse the egress nickname. */
    offset += TRILL_BIT_FIELDS_LEN ;
    proto_tree_add_item( trill_tree, hf_trill_egress_nick, tvb, offset,
      TRILL_NICKNAME_LEN, ENC_BIG_ENDIAN ) ;

    /* Parse the ingress nickname. */
    offset += TRILL_NICKNAME_LEN  ;
    proto_tree_add_item( trill_tree, hf_trill_ingress_nick, tvb, offset,
      TRILL_NICKNAME_LEN , ENC_BIG_ENDIAN ) ;

    /* Parse the options field. */
    offset += TRILL_NICKNAME_LEN  ;
    if( op_len != 0 ) {
      proto_tree_add_item( trill_tree, hf_trill_options, tvb,
        offset, op_len, ENC_NA ) ;
    }
  }

  /* call the eth dissector */
  next_tvb = tvb_new_subset_remaining( tvb, TRILL_MIN_FRAME_LENGTH + op_len ) ;
  call_dissector( eth_dissector, next_tvb, pinfo, tree ) ;

  return tvb_length( tvb ) ;
}

/* Register the protocol with Wireshark */
void
proto_register_trill(void)
{
  static hf_register_info hf[] = {
    { &hf_trill_version,
      { "Version", "trill.version",
        FT_UINT16, BASE_DEC_HEX|BASE_RANGE_STRING, RVALS(version_strings),
        TRILL_VERSION_MASK, "The TRILL version number.", HFILL }},
    { &hf_trill_reserved,
      { "Reserved", "trill.reserved",
        FT_UINT16, BASE_DEC_HEX|BASE_RANGE_STRING, RVALS(reserved_strings),
        TRILL_RESERVED_MASK, "Bits reserved for future specification.", HFILL }},
    { &hf_trill_multi_dst,
      { "Multi Destination", "trill.multi_dst",
        FT_BOOLEAN, 16, TFS(&multi_dst_strings), TRILL_MULTI_DST_MASK,
        "A boolean specifying if this is a multi-destination frame.", HFILL }},
    { &hf_trill_op_len,
      { "Option Length", "trill.op_len",
        FT_UINT16, BASE_DEC_HEX, NULL, TRILL_OP_LEN_MASK,
        "The length of the options field of this frame.", HFILL }},
    { &hf_trill_hop_cnt,
      { "Hop Count", "trill.hop_cnt",
        FT_UINT16, BASE_DEC_HEX, NULL, TRILL_HOP_CNT_MASK,
        "The remaining hop count for this frame.", HFILL }},
    { &hf_trill_egress_nick,
      { "Egress/Root RBridge Nickname", "trill.egress_nick",
        FT_UINT16, BASE_DEC_HEX|BASE_RANGE_STRING, RVALS(nickname_strings), 0x0,
        "The Egress or Distribution Tree Root RBridge Nickname.", HFILL }},
    { &hf_trill_ingress_nick,
      { "Ingress RBridge Nickname", "trill.ingress_nick",
        FT_UINT16, BASE_DEC_HEX|BASE_RANGE_STRING, RVALS(nickname_strings), 0x0,
        "The Ingress RBridge Nickname.", HFILL }},
    { &hf_trill_options,
      { "Options", "trill.options",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "The TRILL Options field.", HFILL }}
  };

  static gint *ett[] = {
    &ett_trill
  };

  proto_trill = proto_register_protocol("TRILL", "TRILL", "trill");
  proto_register_field_array(proto_trill, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_trill(void)
{
  dissector_handle_t trill_handle;

  trill_handle = new_create_dissector_handle(dissect_trill, proto_trill);
  dissector_add_uint("ethertype", ETHERTYPE_TRILL, trill_handle);

  eth_dissector = find_dissector( "eth" ) ;
}

