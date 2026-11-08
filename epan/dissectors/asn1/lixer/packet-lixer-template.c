/* packet-lixer.c
 * Routines for 3GPP TS 33.128 LI_XER (IEF to ICF) dissection
 *
 * See 3GPP TS 33.128 V19.8.0 (2026-09), clause 6.2.2A.2 and Annex F
 * (TS33128IdentityAssociation)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <wsutil/array.h>

#include "packet-ber.h"
#include "packet-e164.h"
#include "packet-e212.h"
#include "packet-gsm_a_common.h"
#include "packet-tcp.h"
#include "packet-tls.h"

/* The start of the iEFRecordOID, the first component of an IEFMessage:
 * [1] IMPLICIT RELATIVE-OID with threeGPP(4) tS33128IdentityAssociation(20) */
#define LIXER_RECORD_OID_TAG    0x81
#define LIXER_RECORD_OID_PREFIX 0x0414

void proto_register_lixer(void);
void proto_reg_handoff_lixer(void);

static int proto_lixer;

static dissector_handle_t lixer_handle;

static bool lixer_desegment = true;

#include "packet-lixer-hf.c"
static int hf_lixer_aMFRegionID;
static int hf_lixer_aMFSetID;
static int hf_lixer_aMFPointer;
static int hf_lixer_fiveGTMSI;

static int ett_lixer;
static int ett_lixer_imsi;
static int ett_lixer_msisdn;
static int ett_lixer_plmnid;
static int ett_lixer_tai;
static int ett_lixer_fiveg_guti;
static int ett_lixer_suci;
#include "packet-lixer-ett.c"

/* A 5G-GUTI as in TS 24.501 figure 9.11.3.4.1, without the first four
 * octets: MCC and MNC, AMF Region ID, AMF Set ID, AMF Pointer and 5G-TMSI */
static void
dissect_lixer_5g_guti(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  int offset;

  offset = dissect_e212_mcc_mnc(tvb, pinfo, tree, 0, E212_GUAMI, true);
  proto_tree_add_item(tree, hf_lixer_aMFRegionID, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  proto_tree_add_item(tree, hf_lixer_aMFSetID, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_lixer_aMFPointer, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(tree, hf_lixer_fiveGTMSI, tvb, offset, 4, ENC_BIG_ENDIAN);
}

#include "packet-lixer-fn.c"

/* One IEFMessage */
static int
dissect_lixer_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  proto_item *ti;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LI_XER");

  ti = proto_tree_add_item(tree, proto_lixer, tvb, 0, -1, ENC_NA);
  return dissect_IEFMessage_PDU(tvb, pinfo, proto_item_add_subtree(ti, ett_lixer), data);
}

/* The length of the BER encoded IEFMessage at offset, or 0 if it needs
 * more data */
static unsigned
get_lixer_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
  volatile unsigned len = 0;
  unsigned ber_offset;
  uint32_t ber_len;

  TRY {
    ber_offset = get_ber_identifier(tvb, offset, NULL, NULL, NULL);
    ber_offset = get_ber_length(tvb, ber_offset, &ber_len, NULL);
    /* get_ber_length() clamps ber_len to INT32_MAX */
    len = ber_offset - offset + ber_len;
  }
  CATCH_BOUNDS_ERRORS {
    len = 0;
  }
  ENDTRY;

  return len;
}

/* The IEFMessages of a TCP or TLS stream; the IEF transmits them over TLS
 * (TS 33.128 clause 6.2.2A.2.3) */
static int
dissect_lixer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  col_clear(pinfo->cinfo, COL_INFO);

  /* the shortest identifier and length are 2 octets */
  tcp_dissect_pdus(tvb, pinfo, tree, lixer_desegment, 2,
                   get_lixer_message_len, dissect_lixer_message, data);
  return tvb_captured_length(tvb);
}

static bool
dissect_lixer_heur_tls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct tlsinfo *tlsinfo = (struct tlsinfo *)data;
  unsigned offset = 2;
  uint8_t len_octet;
  uint8_t oid_len;

  /* an IEFMessage is a SEQUENCE */
  if (tvb_captured_length(tvb) < 2 || tvb_get_uint8(tvb, 0) != 0x30)
    return false;
  len_octet = tvb_get_uint8(tvb, 1);
  if (len_octet & 0x80) {
    /* the long form, or 0 octets for the indefinite form */
    if ((len_octet & 0x7f) > 4)
      return false;
    offset += len_octet & 0x7f;
  }

  /* its iEFRecordOID, with at least threeGPP(4) tS33128IdentityAssociation(20) */
  if (!tvb_bytes_exist(tvb, offset, 4))
    return false;
  if (tvb_get_uint8(tvb, offset) != LIXER_RECORD_OID_TAG)
    return false;
  oid_len = tvb_get_uint8(tvb, offset + 1);
  if (oid_len < 2 || (oid_len & 0x80))
    return false;
  if (tvb_get_ntohs(tvb, offset + 2) != LIXER_RECORD_OID_PREFIX)
    return false;

  /* TLS can keep it for this session */
  if (tlsinfo)
    *(tlsinfo->app_handle) = lixer_handle;
  dissect_lixer(tvb, pinfo, tree, data);

  return true;
}

/*--- proto_register_lixer --------------------------------------------------*/
void proto_register_lixer(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-lixer-hfarr.c"
    { &hf_lixer_aMFRegionID,
      { "AMF Region ID", "lixer.aMFRegionID",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lixer_aMFSetID,
      { "AMF Set ID", "lixer.aMFSetID",
        FT_UINT16, BASE_DEC, NULL, 0xffc0,
        NULL, HFILL }},
    { &hf_lixer_aMFPointer,
      { "AMF Pointer", "lixer.aMFPointer",
        FT_UINT8, BASE_DEC, NULL, 0x3f,
        NULL, HFILL }},
    { &hf_lixer_fiveGTMSI,
      { "5G-TMSI", "lixer.fiveGTMSI",
        FT_UINT32, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_lixer,
    &ett_lixer_imsi,
    &ett_lixer_msisdn,
    &ett_lixer_plmnid,
    &ett_lixer_tai,
    &ett_lixer_fiveg_guti,
    &ett_lixer_suci,
#include "packet-lixer-ettarr.c"
  };

  module_t *lixer_module;

  /* Register protocol */
  proto_lixer = proto_register_protocol("3GPP TS 33.128 LI_XER Identity Association", "LI_XER", "lixer");

  /* Register fields and subtrees */
  proto_register_field_array(proto_lixer, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  lixer_handle = register_dissector("lixer", dissect_lixer, proto_lixer);

  lixer_module = prefs_register_protocol(proto_lixer, NULL);
  prefs_register_bool_preference(lixer_module, "desegment",
                                 "Reassemble LI_XER messages spanning multiple TCP segments",
                                 "Whether the LI_XER dissector should reassemble messages spanning multiple TCP segments."
                                 " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                 &lixer_desegment);
}

/*--- proto_reg_handoff_lixer -----------------------------------------------*/
void proto_reg_handoff_lixer(void) {

  /* no port is assigned */
  dissector_add_uint_range_with_preference("tcp.port", "", lixer_handle);
  dissector_add_for_decode_as("tls.port", lixer_handle);
  heur_dissector_add("tls", dissect_lixer_heur_tls, "LI_XER over TLS", "lixer_tls", proto_lixer, HEURISTIC_ENABLE);
}
