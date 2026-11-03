/* packet-li-ps-pdu-template.c
 * Routines for ETSI TS 102 232-1 LI-PS-PDU dissection
 *
 * See ETSI TS 102 232-1 V3.38.1 (2026-08), with ETSI TS 102 232-3 (IP access)
 * and ETSI TS 103 280 (common parameters)
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
#include <epan/asn1.h>
#include <wsutil/array.h>

#include "packet-ber.h"
#include "packet-HI2Operations.h"
#include "packet-li-ps-pdu.h"
#include "packet-lix2.h"

#define PNAME  "ETSI TS 102 232-1 LI-PS-PDU"
#define PSNAME "LI-PS-PDU"
#define PFNAME "li-ps-pdu"

void proto_register_li_ps_pdu(void);
void proto_reg_handoff_li_ps_pdu(void);

static int proto_li_ps_pdu;

static dissector_handle_t ip_handle;

#include "packet-li-ps-pdu-hf.c"
static int hf_li_ps_pdu_IRIPayload_element;
static int hf_li_ps_pdu_CCPayload_element;
static int hf_li_ps_pdu_not_decoded;

static int ett_li_ps_pdu;
static int ett_li_ps_pdu_contents;
#include "packet-li-ps-pdu-ett.c"

static expert_field ei_li_ps_pdu_not_decoded;

/* A type of a module that Wireshark does not have (see the .MODULE of
 * li-ps-pdu.cnf): its element is shown as bytes. ber.c gives the element
 * in a tvb of its own: its contents, or the whole element without a tag of
 * its own. */
static unsigned
dissect_li_ps_pdu_not_decoded(bool implicit_tag _U_, tvbuff_t *tvb, unsigned offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index)
{
  unsigned len = tvb_reported_length_remaining(tvb, offset);
  proto_item *ti;

  if (hf_index > 0 && proto_registrar_get_ftype(hf_index) == FT_NONE) {
    ti = proto_tree_add_item(tree, hf_index, tvb, offset, len, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_li_ps_pdu_contents);
  }
  ti = proto_tree_add_item(tree, hf_li_ps_pdu_not_decoded, tvb, offset, len, ENC_NA);
  expert_add_info(actx->pinfo, ti, &ei_li_ps_pdu_not_decoded);

  return offset + len;
}

#define dissect_li_ps_pdu_not_decoded_CC_PDU dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_CSvoice_CC_PDU dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_CTTRAFFIC dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_Conf_CC_PDU dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_ConfIRIsContent dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_CorrelationValues dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_EmailCC dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_EmailIRI dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_Gcse_CC_PDU dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_GcseIRIsContent dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_HI1_Operation dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_ILHIPayload dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_IPMMCC dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_IPMMIRI dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_IRI_Parameters dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_IRIsContent dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_L2CC dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_L2IRI dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_L2IRIOnly dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_Location dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_MessagingCC dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_MessagingIRI dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_MessagingMMCC dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_Network_Element_Identifier dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_ProSeIRIsContent dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_PstnIsdnCC dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_PstnIsdnIRI dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_TARGETACTIVITYMONITOR dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_TARGETACTIVITYMONITOR_1 dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_TTRAFFIC dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_ThreeGPP_HI1_Operation dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_UmtsCS_IRIsContent dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_UmtsIRIsContent dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_Voip_CC_PDU dissect_li_ps_pdu_not_decoded

#include "packet-li-ps-pdu-fn.c"

/* The PS-PDU and its Payload, under a protocol item */
static int
dissect_li_ps_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  int8_t ber_class;
  bool pc;
  int32_t tag;
  proto_item *ti;

  /* PS-PDU is a SEQUENCE */
  get_ber_identifier(tvb, 0, &ber_class, &pc, &tag);
  if (ber_class != BER_CLASS_UNI || !pc || tag != BER_UNI_TAG_SEQUENCE)
    return 0;

  ti = proto_tree_add_item(tree, proto_li_ps_pdu, tvb, 0, -1, ENC_NA);
  return dissect_PS_PDU_PDU(tvb, pinfo, proto_item_add_subtree(ti, ett_li_ps_pdu), data);
}

static int
dissect_li_ps_pdu_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  int8_t ber_class;
  proto_item *ti;

  /* Payload is a CHOICE of context-specific tags */
  get_ber_identifier(tvb, 0, &ber_class, NULL, NULL);
  if (ber_class != BER_CLASS_CON)
    return 0;

  ti = proto_tree_add_item(tree, proto_li_ps_pdu, tvb, 0, -1, ENC_NA);
  return dissect_Payload_PDU(tvb, pinfo, proto_item_add_subtree(ti, ett_li_ps_pdu), data);
}

/*--- proto_register_li_ps_pdu ----------------------------------------------*/
void proto_register_li_ps_pdu(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-li-ps-pdu-hfarr.c"
    { &hf_li_ps_pdu_IRIPayload_element,
      { "IRIPayload", "li-ps-pdu.IRIPayload_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TS33128Payloads.IRIPayload", HFILL }},
    { &hf_li_ps_pdu_CCPayload_element,
      { "CCPayload", "li-ps-pdu.CCPayload_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TS33128Payloads.CCPayload", HFILL }},
    { &hf_li_ps_pdu_not_decoded,
      { "Not decoded", "li-ps-pdu.not_decoded",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_li_ps_pdu,
    &ett_li_ps_pdu_contents,
#include "packet-li-ps-pdu-ettarr.c"
  };

  static ei_register_info ei[] = {
    { &ei_li_ps_pdu_not_decoded,
      { "li-ps-pdu.not_decoded.expert", PI_UNDECODED, PI_NOTE,
        "Not decoded: Wireshark does not have the ASN.1 module of this type", EXPFILL }},
  };

  expert_module_t *expert_li_ps_pdu;

  /* Register protocol */
  proto_li_ps_pdu = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_li_ps_pdu, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_li_ps_pdu = expert_register_protocol(proto_li_ps_pdu);
  expert_register_field_array(expert_li_ps_pdu, ei, array_length(ei));

  register_dissector("li-ps-pdu", dissect_li_ps_pdu, proto_li_ps_pdu);
  register_dissector("li-ps-pdu.payload", dissect_li_ps_pdu_payload, proto_li_ps_pdu);
}

/*--- proto_reg_handoff_li_ps_pdu -------------------------------------------*/
void proto_reg_handoff_li_ps_pdu(void) {

  ip_handle = find_dissector_add_dependency("ip", proto_li_ps_pdu);
}
