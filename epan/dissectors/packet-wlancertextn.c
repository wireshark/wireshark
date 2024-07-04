/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-wlancertextn.c                                                      */
/* asn2wrs.py -b -q -L -p wlancertextn -c ./wlancertextn.cnf -s ./packet-wlancertextn-template -D . -O ../.. WLANCERTEXTN.asn */

/* packet-wlancertextn.c
 * Routines for Wireless Certificate Extension (RFC3770)
 *  Ronnie Sahlberg 2005
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-wlancertextn.h"
#include "packet-x509af.h"
#include "packet-x509ce.h"
#include "packet-x509sat.h"

#define PNAME  "Wlan Certificate Extension"
#define PSNAME "WLANCERTEXTN"
#define PFNAME "wlancertextn"

void proto_register_wlancertextn(void);
void proto_reg_handoff_wlancertextn(void);

/* Initialize the protocol and registered fields */
static int proto_wlancertextn;
static int hf_wlancertextn_SSIDList_PDU;          /* SSIDList */
static int hf_wlancertextn_SSIDList_item;         /* SSID */

/* Initialize the subtree pointers */
static int ett_wlancertextn_SSIDList;



static int
dissect_wlancertextn_SSID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t SSIDList_sequence_of[1] = {
  { &hf_wlancertextn_SSIDList_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_wlancertextn_SSID },
};

static int
dissect_wlancertextn_SSIDList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SSIDList_sequence_of, hf_index, ett_wlancertextn_SSIDList);

  return offset;
}

/*--- PDUs ---*/

static int dissect_SSIDList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_wlancertextn_SSIDList(false, tvb, offset, &asn1_ctx, tree, hf_wlancertextn_SSIDList_PDU);
  return offset;
}



/*--- proto_register_wlancertextn ----------------------------------------------*/
void proto_register_wlancertextn(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_wlancertextn_SSIDList_PDU,
      { "SSIDList", "wlancertextn.SSIDList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_wlancertextn_SSIDList_item,
      { "SSID", "wlancertextn.SSID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_wlancertextn_SSIDList,
  };

  /* Register protocol */
  proto_wlancertextn = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_wlancertextn, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_wlancertextn -------------------------------------------*/
void proto_reg_handoff_wlancertextn(void) {
  register_ber_oid_dissector("1.3.6.1.5.5.7.1.13", dissect_SSIDList_PDU, proto_wlancertextn, "id-pe-wlanSSID");
  register_ber_oid_dissector("1.3.6.1.5.5.7.10.6", dissect_SSIDList_PDU, proto_wlancertextn, "id-aca-wlanSSID");

  oid_add_from_string("id-kp-eapOverPPP","1.3.6.1.5.5.7.3.13");
  oid_add_from_string("id-kp-eapOverLAN","1.3.6.1.5.5.7.3.14");
}

