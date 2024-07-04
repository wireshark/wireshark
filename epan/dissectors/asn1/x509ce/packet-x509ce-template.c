/* packet-x509ce.c
 * Routines for X.509 Certificate Extensions packet dissection
 *  Ronnie Sahlberg 2004
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
#include <epan/oids.h>

#include "packet-ber.h"
#include "packet-x509ce.h"
#include "packet-x509af.h"
#include "packet-x509if.h"
#include "packet-x509sat.h"
#include "packet-p1.h"

#define PNAME  "X.509 Certificate Extensions"
#define PSNAME "X509CE"
#define PFNAME "x509ce"

void proto_register_x509ce(void);
void proto_reg_handoff_x509ce(void);

/* Initialize the protocol and registered fields */
static int proto_x509ce;
static int hf_x509ce_id_ce_invalidityDate;
static int hf_x509ce_id_ce_baseUpdateTime;
static int hf_x509ce_object_identifier_id;
static int hf_x509ce_IPAddress_ipv4;
static int hf_x509ce_IPAddress_ipv4_mask;
static int hf_x509ce_IPAddress_ipv6;
static int hf_x509ce_IPAddress_ipv6_mask;
static int hf_x509ce_IPAddress_unknown;
#include "packet-x509ce-hf.c"

/* Initialize the subtree pointers */
#include "packet-x509ce-ett.c"
#include "packet-x509ce-fn.c"

static const val64_string ciplus_scr_cap[] = {
    { 0, "DES" },
    { 1, "DES and AES" },
    { 0, NULL }
};

static const val64_string ciplus_security_level[] = {
    { 0, "Standard Security Level" },
    { 1, "ECP Security Level" },
    { 0, NULL }
};

/* CI+ (www.ci-plus.com) defines some X.509 certificate extensions
   that use OIDs which are not officially assigned
   dissection of these extensions can be enabled temporarily using the
   functions below */
void
x509ce_enable_ciplus(void)
{
  dissector_handle_t dh25, dh26, dh27, dh50;

  dh25 = create_dissector_handle(dissect_ScramblerCapabilities_PDU, proto_x509ce);
  dissector_change_string("ber.oid", "1.3.6.1.5.5.7.1.25", dh25);
  dh26 = create_dissector_handle(dissect_CiplusInfo_PDU, proto_x509ce);
  dissector_change_string("ber.oid", "1.3.6.1.5.5.7.1.26", dh26);
  dh27 = create_dissector_handle(dissect_CicamBrandId_PDU, proto_x509ce);
  dissector_change_string("ber.oid", "1.3.6.1.5.5.7.1.27", dh27);
  dh50 = create_dissector_handle(dissect_SecurityLevel_PDU, proto_x509ce);
  dissector_change_string("ber.oid", "1.3.6.1.5.5.7.1.50", dh50);
}

void
x509ce_disable_ciplus(void)
{
  dissector_reset_string("ber.oid", "1.3.6.1.5.5.7.1.25");
  dissector_reset_string("ber.oid", "1.3.6.1.5.5.7.1.26");
  dissector_reset_string("ber.oid", "1.3.6.1.5.5.7.1.27");
  dissector_reset_string("ber.oid", "1.3.6.1.5.5.7.1.50");
}


static int
dissect_x509ce_invalidityDate_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

  return dissect_x509ce_GeneralizedTime(false, tvb, 0, &asn1_ctx, tree, hf_x509ce_id_ce_invalidityDate);
}

static int
dissect_x509ce_baseUpdateTime_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  return dissect_x509ce_GeneralizedTime(false, tvb, 0, &asn1_ctx, tree, hf_x509ce_id_ce_baseUpdateTime);
}

/*--- proto_register_x509ce ----------------------------------------------*/
void proto_register_x509ce(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_x509ce_id_ce_baseUpdateTime,
      { "baseUpdateTime", "x509ce.id_ce_baseUpdateTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_id_ce_invalidityDate,
      { "invalidityDate", "x509ce.id_ce_invalidityDate",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_object_identifier_id,
      { "Id", "x509ce.id", FT_OID, BASE_NONE, NULL, 0,
        "Object identifier Id", HFILL }},
    { &hf_x509ce_IPAddress_ipv4,
      { "iPAddress", "x509ce.IPAddress.ipv4", FT_IPv4, BASE_NONE, NULL, 0,
        "IPv4 address", HFILL }},
    { &hf_x509ce_IPAddress_ipv4_mask,
      { "iPAddress Mask", "x509ce.IPAddress.ipv4_mask", FT_IPv4, BASE_NONE, NULL, 0,
        "IPv4 address Mask", HFILL }},
    { &hf_x509ce_IPAddress_ipv6,
      { "iPAddress", "x509ce.IPAddress.ipv6", FT_IPv6, BASE_NONE, NULL, 0,
        "IPv6 address", HFILL }},
    { &hf_x509ce_IPAddress_ipv6_mask,
      { "iPAddress Mask", "x509ce.IPAddress.ipv6_mask", FT_IPv6, BASE_NONE, NULL, 0,
        "IPv6 address Mask", HFILL }},
    { &hf_x509ce_IPAddress_unknown,
      { "iPAddress", "x509ce.IPAddress.unknown", FT_BYTES, BASE_NONE, NULL, 0,
        "Unknown Address", HFILL }},

#include "packet-x509ce-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
#include "packet-x509ce-ettarr.c"
  };

  /* Register protocol */
  proto_x509ce = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_x509ce, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_x509ce -------------------------------------------*/
void proto_reg_handoff_x509ce(void) {
#include "packet-x509ce-dis-tab.c"
  register_ber_oid_dissector("2.5.29.24", dissect_x509ce_invalidityDate_callback, proto_x509ce, "id-ce-invalidityDate");
  register_ber_oid_dissector("2.5.29.51", dissect_x509ce_baseUpdateTime_callback, proto_x509ce, "id-ce-baseUpdateTime");
  oid_add_from_string("anyPolicy","2.5.29.32.0");
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
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
