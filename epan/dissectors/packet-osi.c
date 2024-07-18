/* packet-osi.c
 * Routines for ISO/OSI network and transport protocol packet disassembly
 * Main entrance point and common functions
 *
 * Laurent Deniel <laurent.deniel@free.fr>
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
#include <epan/prefs.h>
#include <epan/llcsaps.h>
#include <epan/aftypes.h>
#include <epan/nlpid.h>
#include <epan/ppptypes.h>
#include <epan/chdlctypes.h>
#include <epan/ipproto.h>
#include "packet-osi.h"
#include "packet-tpkt.h"
#include "packet-juniper.h"

void proto_reg_handoff_osi(void);
void proto_register_osi(void);

int  proto_osi;

static int hf_osi_nlpid;

static dissector_handle_t osi_handle;
static dissector_handle_t osi_tpkt_handle;
static dissector_handle_t osi_juniper_handle;


/* Preferences for OSI over TPKT over TCP */
static bool tpkt_desegment;

bool
osi_calc_checksum( tvbuff_t *tvb, int offset, unsigned len, uint32_t* c0, uint32_t* c1) {
  unsigned      available_len;
  const uint8_t *p;
  unsigned      seglen;
  unsigned      i;

  available_len = tvb_captured_length_remaining( tvb, offset );
  if ( available_len < len )
    return false;

  p = tvb_get_ptr( tvb, offset, len );

  /*
   * The maximum values of c0 and c1 will occur if all bytes have the
   * value 255; if so, then c0 will be len*255 and c1 will be
   * (len*255 + (len-1)*255 + ... + 255), which is
   * (len + (len - 1) + ... + 1)*255, or 255*(len*(len + 1))/2.
   * This means it can overflow if "len" is 5804 or greater.
   *
   * (A+B) mod 255 = ((A mod 255) + (B mod 255) mod 255, so
   * we can solve this by taking c0 and c1 mod 255 every
   * 5803 bytes.
   */
  *c0 = 0;
  *c1 = 0;
  while (len != 0) {
    seglen = len;
    if (seglen > 5803)
      seglen = 5803;
    for (i = 0; i < seglen; i++) {
      (*c0) += *(p++);
      (*c1) += (*c0);
    }

    (*c0) = (*c0) % 255;
    (*c1) = (*c1) % 255;

    len -= seglen;
  }

  return true;
}


bool
osi_check_and_get_checksum( tvbuff_t *tvb, int offset, unsigned len, int offset_check, uint16_t* result) {
  const uint8_t *p;
  uint8_t       discard         = 0;
  uint32_t      c0, c1, factor;
  unsigned      seglen, initlen = len;
  unsigned      i;
  int           block, x, y;

  /* Make sure the checksum is part of the data being checksummed. */
  DISSECTOR_ASSERT(offset_check >= offset);
  DISSECTOR_ASSERT((unsigned)offset_check + 2 <= (unsigned)offset + len);

  /*
   * If we don't have all the data to be checksummed, report that and don't
   * try checksumming.
   */
  if (!tvb_bytes_exist(tvb, offset, len))
    return false;
  offset_check -= offset;

  p = tvb_get_ptr( tvb, offset, len );
  block  = offset_check / 5803;

  /*
   * The maximum values of c0 and c1 will occur if all bytes have the
   * value 255; if so, then c0 will be len*255 and c1 will be
   * (len*255 + (len-1)*255 + ... + 255), which is
   * (len + (len - 1) + ... + 1)*255, or 255*(len*(len + 1))/2.
   * This means it can overflow if "len" is 5804 or greater.
   *
   * (A+B) mod 255 = ((A mod 255) + (B mod 255) mod 255, so
   * we can solve this by taking c0 and c1 mod 255 every
   * 5803 bytes.
   */
  c0 = 0;
  c1 = 0;

  while (len != 0) {
    seglen = len;
    if ( block-- == 0 ) {
      seglen = offset_check % 5803;
      discard = 1;
    } else if ( seglen > 5803 )
      seglen = 5803;
    for (i = 0; i < seglen; i++) {
      c0 = c0 + *(p++);
      c1 += c0;
    }
    if ( discard ) {
      /*
       * This works even if (offset_check % 5803) == 5802
       */
      p += 2;
      c1 += 2*c0;
      len -= 2;
      discard = 0;
    }

    c0 = c0 % 255;
    c1 = c1 % 255;

    len -= seglen;
  }

  factor = ( initlen - offset_check ) * c0;
  x = factor - c0 - c1;
  y = c1 - factor - 1;

  /*
   * This algorithm uses the 8 bits one's complement arithmetic.
   * Therefore, we must correct an effect produced
   * by the "standard" arithmetic (two's complement)
   */

  if (x < 0 ) x--;
  if (y > 0 ) y++;

  x %= 255;
  y %= 255;

  if (x == 0) x = 0xFF;
  if (y == 0) y = 0x01;

  *result = ( x << 8 ) | ( y & 0xFF );
  return true;
}

/* 4 octet ATN extended checksum: ICAO doc 9705 Ed3 Volume V section 5.5.4.6.4 */
/* It is calculated over TP4 userdata (all checksums set to zero ) and a pseudo tailer */
/* of length SRC-NSAP, SRC-NSAP, length DST-NSAP, DST-NSAP and ATN extended checksum. */
/* In case of a CR TPDU, the value of the ISO 8073 16-bit fletcher checksum parameter shall */
/* be set to zero. */
uint32_t check_atn_ec_32(
  tvbuff_t *tvb, unsigned tpdu_len,
  unsigned offset_ec_32_val,   /* offset ATN extended checksum value, calculated at last as part of pseudo trailer */
  unsigned offset_iso8073_val, /* offset ISO 8073 fletcher checksum, CR only*/
  unsigned clnp_dst_len,       /* length of DST-NSAP */
  const uint8_t *clnp_dst,   /* DST-NSAP */
  unsigned clnp_src_len,       /* length of SRC-NSAP */
  const uint8_t *clnp_src)   /* SRC-NSAP */
{
  unsigned  i = 0;
  uint32_t c0 = 0;
  uint32_t c1 = 0;
  uint32_t c2 = 0;
  uint32_t c3 = 0;
  uint32_t sum = 0;

  /* sum across complete TPDU  */
  for ( i =0; i< tpdu_len; i++){
    c0 += tvb_get_uint8(tvb, i) ;

    if( ( i >= offset_ec_32_val ) &&  /* ignore 32 bit ATN extended checksum value */
        ( i < ( offset_ec_32_val + 4 ) ) ) {
      c0 -= tvb_get_uint8(tvb, i);
    }

    if( ( offset_iso8073_val ) && /* ignore 16 bit ISO 8073 checksum, if present*/
        ( i >= offset_iso8073_val ) &&
        ( i < ( offset_iso8073_val + 2 ) ) ) {
      c0 -= tvb_get_uint8(tvb, i);
    }

    if ( c0 >= 0x000000FF )
      c0 -= 0x00000FF;
    c1 += c0;
    if ( c1 >= 0x000000FF )
      c1 -= 0x000000FF;
    c2 += c1;
    if ( c2 >= 0x000000FF )
      c2 -= 0x000000FF;
    c3 += c2;
    if ( c3 >= 0x000000FF )
      c3 -= 0x000000FF;
  }
  /* add NSAP parts of pseudo trailer */
  c0 += clnp_dst_len;
  if ( c0 >= 0x000000FF )
    c0 -= 0x000000FF;
  c1 += c0;
  if ( c1 >= 0x000000FF )
    c1 -= 0x000000FF;
  c2 += c1;
  if ( c2 >= 0x000000FF )
    c2 -= 0x000000FF;
  c3 += c2;
  if ( c3 >= 0x000000FF )
    c3 -= 0x000000FF;
  for ( i =0; i< clnp_dst_len; i++){
    c0 += clnp_dst[i];
    if ( c0 >= 0x000000FF )
      c0 -= 0x000000FF;
    c1 += c0;
    if ( c1 >= 0x000000FF )
      c1 -= 0x000000FF;
    c2 += c1;
    if ( c2 >= 0x000000FF )
      c2 -= 0x000000FF;
    c3 += c2;
    if ( c3 >= 0x000000FF )
      c3 -= 0x000000FF;
  }
  c0 += clnp_src_len;
  if ( c0 >= 0x000000FF )
    c0 -= 0x000000FF;
  c1 += c0;
  if ( c1 >= 0x000000FF )
    c1 -= 0x000000FF;
  c2 += c1;
  if ( c2 >= 0x000000FF )
    c2 -= 0x000000FF;
  c3 += c2;
  if ( c3 >= 0x000000FF )
    c3 -= 0x000000FF;
  for ( i =0; i< clnp_src_len; i++){
    c0 += clnp_src[i];
    if ( c0 >= 0x000000FF )
      c0 -= 0x000000FF;
    c1 += c0;
    if ( c1 >= 0x000000FF )
      c1 -= 0x000000FF;
    c2 += c1;
    if ( c2 >= 0x000000FF )
      c2 -= 0x000000FF;
    c3 += c2;
    if ( c3 >= 0x000000FF )
      c3 -= 0x000000FF;
  }
  /* add extended checksum as last part of the pseudo trailer */
  for ( i = offset_ec_32_val; i< (offset_ec_32_val+4); i++){
    c0 += tvb_get_uint8(tvb, i) ;

    if ( c0 >= 0x000000FF )
      c0 -= 0x00000FF;
    c1 += c0;
    if ( c1 >= 0x000000FF )
      c1 -= 0x000000FF;
    c2 += c1;
    if ( c2 >= 0x000000FF )
      c2 -= 0x000000FF;
    c3 += c2;
    if ( c3 >= 0x000000FF )
      c3 -= 0x000000FF;
  }

  sum = (c3 << 24) + (c2 << 16 ) + (c1 << 8) + c0;
  return sum;
}

/* 2 octet ATN extended checksum: ICAO doc 9705 Ed3 Volume V section 5.5.4.6.4 */
/* It is calculated over TP4 userdata (all checksums set to zero ) and a pseudo tailer */
/* of length SRC-NSAP, SRC-NSAP, length DST-NSAP, DST-NSAP and ATN extended checksum. */
/* In case of a CR TPDU, the value of the ISO 8073 16-bit fletcher checksum parameter shall */
/* be set to zero. */
/* this routine is currently *untested* because of the unavailability of samples.*/
uint16_t check_atn_ec_16(
  tvbuff_t *tvb,
  unsigned tpdu_len,
  unsigned offset_ec_16_val,   /* offset ATN extended checksum value, calculated at last as part of pseudo trailer */
  unsigned offset_iso8073_val, /* offset ISO 8073 fletcher checksum, CR only*/
  unsigned clnp_dst_len,       /* length of DST-NSAP */
  const uint8_t *clnp_dst,   /* DST-NSAP */
  unsigned clnp_src_len,       /* length of SRC-NSAP */
  const uint8_t *clnp_src)   /* SRC-NSAP */
{
  unsigned i = 0;
  uint16_t c0 = 0;
  uint16_t c1 = 0;
  uint16_t sum;

  /* sum across complete TPDU */
  for ( i =0; i< tpdu_len; i++){

    c0 += tvb_get_uint8(tvb, i);

    if( (i >= offset_ec_16_val) && /* ignore 16 bit extended checksum */
        (i < (offset_ec_16_val + 2) ) ) {
      c0 -= tvb_get_uint8(tvb, i) ;
    }

    if( (i >= offset_iso8073_val) && /* ignore 16 bit ISO 8073 checksum, if present*/
        (i < (offset_iso8073_val + 2) ) ) {
      c0 -= tvb_get_uint8(tvb, i) ;
    }

    if ( c0 >= 0x00FF )
       c0 -= 0x00FF;
    c1 += c0;
    if ( c1 >= 0x00FF )
      c1 -= 0x00FF;
  }
  /* add NSAP parts of pseudo trailer */
  c0 += clnp_dst_len;
  if ( c0 >= 0x00FF )
    c0 -= 0x00FF;
  c1 += c0;
  if ( c1 >= 0x00FF )
    c1 -= 0x00FF;
  for ( i =0; i< clnp_dst_len; i++){
    c0 += clnp_dst[i];
    if ( c0 >= 0x00FF )
      c0 -= 0x00FF;
    c1 += c0;
    if ( c1 >= 0x00FF )
      c1 -= 0x00FF;
  }
  c0 += clnp_src_len;
  if ( c0 >= 0x00FF )
    c0 -= 0x00FF;
  c1 += c0;
  if ( c1 >= 0x00FF )
    c1 -= 0x00FF;
  for ( i =0; i< clnp_src_len; i++){
    c0 += clnp_src[i];
    if ( c0 >= 0x00FF )
      c0 -= 0x00FF;
    c1 += c0;
    if ( c1 >= 0x00FF )
      c1 -= 0x00FF;
  }
  /* add extended checksum as last part of the pseudo trailer */
  for ( i = offset_ec_16_val; i< (offset_ec_16_val+2); i++){
    c0 += tvb_get_uint8(tvb, i) ;

    if ( c0 >= 0x00FF )
      c0 -= 0x00FF;
    c1 += c0;
    if ( c1 >= 0x00FF )
      c1 -= 0x00FF;
  }

  sum =  (c1 << 8) + c0 ;
  return sum;
}


/* main entry point */

/*
 * These assume the NLPID is a secondary protocol identifier, not an
 * initial protocol identifier.
 *
 * This is an issue only if, in any packet where an NLPID appears, it's
 * an initial protocol identifier *AND* it can have the value 1, which
 * means T.70 for an IPI and X.29 for an SPI.
 */
const value_string nlpid_vals[] = {
  { NLPID_NULL,            "NULL" },
  { NLPID_SPI_X_29,        "X.29" },
  { NLPID_X_633,           "X.633" },
  { NLPID_Q_931,           "Q.931" },
  { NLPID_Q_2931,          "Q.2931" },
  { NLPID_Q_2119,          "Q.2119" },
  { NLPID_SNAP,            "SNAP" },
  { NLPID_ISO8473_CLNP,    "CLNP" },
  { NLPID_ISO9542_ESIS,    "ESIS" },
  { NLPID_ISO10589_ISIS,   "ISIS" },
  { NLPID_ISO10747_IDRP,   "IDRP" },
  { NLPID_AVAYA_IPVPN,     "Avaya SPBM Fabric IPVPN" },
  { NLPID_ISO9542X25_ESIS, "ESIS (X.25)" },
  { NLPID_ISO10030,        "ISO 10030" },
  { NLPID_ISO11577,        "ISO 11577" },
  { NLPID_COMPRESSED,      "Data compression protocol" },
  { NLPID_IP,              "IP" },
  { NLPID_TRILL,           "TRILL" },
  { NLPID_SNDCF,           "SubNetwork Dependent Convergence Function"},
  { NLPID_IP6,             "IPv6" },
  { NLPID_PPP,             "PPP" },
  { 0,                     NULL },
};

static dissector_table_t osinl_incl_subdissector_table;
static dissector_table_t osinl_excl_subdissector_table;
static dissector_handle_t ppp_handle;

/* Dissect OSI over TCP over TPKT */
static int
dissect_osi_tpkt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  dissect_tpkt_encap(tvb, pinfo, tree, tpkt_desegment, osi_handle);
  return tvb_captured_length(tvb);
}

static int dissect_osi_juniper(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  uint8_t    nlpid;
  tvbuff_t   *next_tvb;

  nlpid = tvb_get_uint8(tvb, 0);
  if(dissector_try_uint(osinl_incl_subdissector_table, nlpid, tvb, pinfo, tree))
    return tvb_captured_length(tvb);

  next_tvb = tvb_new_subset_remaining(tvb, 1);
  dissector_try_uint(osinl_excl_subdissector_table, nlpid, next_tvb, pinfo, tree);
  return tvb_captured_length(tvb);
}

static int dissect_osi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  uint8_t   nlpid;
  tvbuff_t *new_tvb;

  nlpid = tvb_get_uint8(tvb, 0);

  /*
   * Try the subdissector table for protocols in which the NLPID is
   * considered part of the PDU; it should be handed a tvbuff that
   * includes the NLPID, and should put the NLPID into the protocol
   * tree itself.
   */
  if (dissector_try_uint(osinl_incl_subdissector_table, nlpid, tvb, pinfo, tree))
    return tvb_captured_length(tvb);

  /*
   * Try the subdissector table for protocols in which the NLPID is
   * *not* considered part of the PDU; it should be handed a tvbuff
   * that doesn't include the NLPID, and we should put the NLPID into
   * the protocol tree ourselves.
   */
  proto_tree_add_uint(tree, hf_osi_nlpid, tvb, 0, 1, nlpid);
  new_tvb = tvb_new_subset_remaining(tvb, 1);
  if (dissector_try_uint(osinl_excl_subdissector_table, nlpid, new_tvb, pinfo, tree))
    return tvb_captured_length(tvb);

  switch (nlpid) {

    /* ESIS (X.25) is not currently decoded */

    case NLPID_ISO9542X25_ESIS:
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "ESIS (X.25)");
      call_data_dissector(tvb, pinfo, tree);
      break;
    case NLPID_ISO10747_IDRP:
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "IDRP");
      call_data_dissector(tvb, pinfo, tree);
      break;
    default:
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISO");
      col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown ISO protocol (%02x)", nlpid);

      call_data_dissector(tvb, pinfo, tree);
      break;
  }
  return tvb_captured_length(tvb);
} /* dissect_osi */

void
proto_reg_handoff_osi(void)
{
  dissector_add_uint("llc.dsap", SAP_OSINL1, osi_handle);
  dissector_add_uint("llc.dsap", SAP_OSINL2, osi_handle);
  dissector_add_uint("llc.dsap", SAP_OSINL3, osi_handle);
  dissector_add_uint("llc.dsap", SAP_OSINL4, osi_handle);
  dissector_add_uint("llc.dsap", SAP_OSINL5, osi_handle);
  dissector_add_uint("ppp.protocol", PPP_OSI, osi_handle);
  dissector_add_uint("chdlc.protocol", CHDLCTYPE_OSI, osi_handle);
  dissector_add_uint("null.type", BSD_AF_ISO, osi_handle);
  dissector_add_uint("gre.proto", SAP_OSINL5, osi_handle);
  dissector_add_uint("ip.proto", IP_PROTO_ISOIP, osi_handle); /* ISO network layer PDUs [RFC 1070] */

  dissector_add_uint("juniper.proto", JUNIPER_PROTO_ISO, osi_juniper_handle);
  dissector_add_uint("juniper.proto", JUNIPER_PROTO_CLNP, osi_juniper_handle);
  dissector_add_uint("juniper.proto", JUNIPER_PROTO_MPLS_CLNP, osi_juniper_handle);

  ppp_handle  = find_dissector("ppp");

  dissector_add_for_decode_as_with_preference("tcp.port", osi_tpkt_handle);
}

void
proto_register_osi(void)
{
  static hf_register_info hf[] = {
    { &hf_osi_nlpid,
      { "Network Layer Protocol Identifier", "osi.nlpid", FT_UINT8, BASE_HEX,
        VALS(nlpid_vals), 0x0, NULL, HFILL }},
  };
  module_t *osi_module;

  proto_osi = proto_register_protocol("OSI", "OSI", "osi");
  proto_register_field_array(proto_osi, hf, array_length(hf));

  /* There's no "OSI" protocol *per se*, but we do register a
     dissector table so various protocols running at the
     network layer can register themselves.
     all protocols that require inclusion of the NLPID
     should register here
  */
  osinl_incl_subdissector_table = register_dissector_table("osinl.incl",
                                                           "OSI incl NLPID", proto_osi, FT_UINT8, BASE_HEX);

  /* This dissector table is for those protocols whose PDUs
   * aren't* defined to begin with an NLPID.
   * (typically non OSI protocols like IP,IPv6,PPP */
  osinl_excl_subdissector_table = register_dissector_table("osinl.excl",
                                                           "OSI excl NLPID", proto_osi, FT_UINT8, BASE_HEX);

  /* Preferences how OSI protocols should be dissected */
  osi_module = prefs_register_protocol(proto_osi, NULL);

  prefs_register_bool_preference(osi_module, "tpkt_reassemble",
                                 "Reassemble segmented TPKT datagrams",
                                 "Whether segmented TPKT datagrams should be reassembled",
                                 &tpkt_desegment);

  /* Register the dissector handles */
  osi_handle = register_dissector("osi", dissect_osi, proto_osi);
  osi_juniper_handle = register_dissector("osi_juniper", dissect_osi_juniper, proto_osi);
  osi_tpkt_handle = register_dissector("osi_tpkt", dissect_osi_tpkt, proto_osi);
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
