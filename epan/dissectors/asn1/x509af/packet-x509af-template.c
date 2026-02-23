/* packet-x509af.c
 * Routines for X.509 Authentication Framework packet dissection
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
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/expert.h>
#include <epan/strutil.h>
#include <epan/export_object.h>
#include <epan/proto_data.h>
#include <wsutil/array.h>

#include "packet-ber.h"
#include "packet-x509af.h"
#include "packet-x509ce.h"
#include "packet-x509if.h"
#include "packet-x509sat.h"
#include "packet-ldap.h"
#include "packet-pkixalgs.h"
#if defined(HAVE_LIBGNUTLS)
#include <gnutls/gnutls.h>
#endif

void proto_register_x509af(void);
void proto_reg_handoff_x509af(void);

static dissector_handle_t pkix_crl_handle;

static int x509af_eo_tap;

/* Initialize the protocol and registered fields */
static int proto_x509af;
static int hf_x509af_algorithm_id;
static int hf_x509af_extension_id;
static int hf_x509af_subjectPublicKey_dh;
static int hf_x509af_subjectPublicKey_dsa;
static int hf_x509af_subjectPublicKey_rsa;
#include "packet-x509af-hf.c"

/* Initialize the subtree pointers */
static int ett_pkix_crl;
static int ett_x509af_SubjectPublicKey;
#include "packet-x509af-ett.c"

static expert_field ei_x509af_certificate_invalid;

static const char *algorithm_id;
static void
x509af_export_publickey(tvbuff_t *tvb, asn1_ctx_t *actx, int offset, int len);

/* proto_data keys */
#define X509AF_EO_INFO_KEY      0
#define X509AF_PRIVATE_DATA_KEY 1

typedef struct _x509af_eo_t {
  const char *subjectname;
  char *serialnum;
  tvbuff_t *payload;
} x509af_eo_t;

typedef struct _x509af_private_data_t {
  nstime_t last_time;
  nstime_t not_before;
  nstime_t not_after;
#if 0
  // TODO: Move static global algorithm_id here.
  // (Why is the algorithm_id string wmem_file_scope()? That makes
  // no sense as a global common to all conversations.)
  const char *algorithm_id;
#endif
} x509af_private_data_t;

static x509af_private_data_t *
x509af_get_private_data(packet_info *pinfo)
{
  x509af_private_data_t *x509af_data = (x509af_private_data_t*)p_get_proto_data(pinfo->pool, pinfo, proto_x509af, X509AF_PRIVATE_DATA_KEY);
  if (!x509af_data) {
    x509af_data = wmem_new0(pinfo->pool, x509af_private_data_t);
    nstime_set_unset(&x509af_data->not_before);
    nstime_set_unset(&x509af_data->not_after);
    p_add_proto_data(pinfo->pool, pinfo, proto_x509af, X509AF_PRIVATE_DATA_KEY, x509af_data);
  }
  return x509af_data;
}

#include "packet-x509af-fn.c"

static tap_packet_status
x509af_eo_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *data, tap_flags_t flags _U_)
{
  export_object_list_t *object_list = (export_object_list_t *)tapdata;
  const x509af_eo_t *eo_info = (const x509af_eo_t *)data;
  export_object_entry_t *entry;

  if (data) {
    entry = g_new0(export_object_entry_t, 1);

    entry->pkt_num = pinfo->num;

    // There should be a commonName
    char *name = strstr(eo_info->subjectname, "id-at-commonName=");
    if (name) {
      name += strlen("id-at-commonName=");
      entry->hostname = g_strndup(name, strcspn(name, ","));
    }
    entry->content_type = g_strdup("application/pkix-cert");

    entry->filename = g_strdup_printf("%s.cer", eo_info->serialnum);

    entry->payload_len = tvb_captured_length(eo_info->payload);
    entry->payload_data = (uint8_t *)tvb_memdup(NULL, eo_info->payload, 0, entry->payload_len);

    object_list->add_entry(object_list->gui_data, entry);

    return TAP_PACKET_REDRAW;
  } else {
    return TAP_PACKET_DONT_REDRAW;
  }
}

/* Exports the SubjectPublicKeyInfo structure as gnutls_datum_t.
 * actx->private_data is assumed to be a gnutls_datum_t pointer which will be
 * filled in if non-NULL. */
static void
x509af_export_publickey(tvbuff_t *tvb _U_, asn1_ctx_t *actx _U_, int offset _U_, int len _U_)
{
#if defined(HAVE_LIBGNUTLS)
  gnutls_datum_t *subjectPublicKeyInfo = (gnutls_datum_t *)actx->private_data;
  if (subjectPublicKeyInfo) {
    /* This is only passed to ssh_find_private_key_by_pubkey, which uses it
     * with gnutls_pubkey_import, which treats the data as const, so this
     * cast is acceptable. */
    subjectPublicKeyInfo->data = (unsigned char *) tvb_get_ptr(tvb, offset, len);
    subjectPublicKeyInfo->size = len;
    actx->private_data = NULL;
  }
#endif
}

const char *x509af_get_last_algorithm_id(void) {
  return algorithm_id;
}


static int
dissect_pkix_crl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	proto_tree *tree;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "PKIX-CRL");

	col_set_str(pinfo->cinfo, COL_INFO, "Certificate Revocation List");


	tree=proto_tree_add_subtree(parent_tree, tvb, 0, -1, ett_pkix_crl, NULL, "Certificate Revocation List");

	return dissect_x509af_CertificateList(false, tvb, 0, &asn1_ctx, tree, -1);
}

static void
x509af_cleanup_protocol(void)
{
  algorithm_id = NULL;
}

/*--- proto_register_x509af ----------------------------------------------*/
void proto_register_x509af(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_x509af_algorithm_id,
      { "Algorithm Id", "x509af.algorithm.id",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_extension_id,
      { "Extension Id", "x509af.extension.id",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_subjectPublicKey_dh,
      { "DH Public Key", "x509af.subjectPublicKey.dh",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_subjectPublicKey_dsa,
      { "DSA Public Key", "x509af.subjectPublicKey.dsa",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_subjectPublicKey_rsa,
      { "RSA Public Key", "x509af.subjectPublicKey.rsa",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
#include "packet-x509af-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_pkix_crl,
    &ett_x509af_SubjectPublicKey,
#include "packet-x509af-ettarr.c"
  };

  static ei_register_info ei[] = {
    { &ei_x509af_certificate_invalid, { "x509af.signedCertificate.invalid", PI_SECURITY, PI_WARN, "Invalid certificate", EXPFILL }},
  };

  expert_module_t *expert_x509af;

  /* Register protocol */
  proto_x509af = proto_register_protocol("X.509 Authentication Framework", "X509AF", "x509af");

  /* Register fields and subtrees */
  proto_register_field_array(proto_x509af, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  expert_x509af = expert_register_protocol(proto_x509af);
  expert_register_field_array(expert_x509af, ei, array_length(ei));

  x509af_eo_tap = register_export_object(proto_x509af, x509af_eo_packet, NULL);

  register_cleanup_routine(&x509af_cleanup_protocol);

  pkix_crl_handle = register_dissector("x509af", dissect_pkix_crl, proto_x509af);

  register_ber_syntax_dissector("Certificate", proto_x509af, dissect_x509af_Certificate_PDU);
  register_ber_syntax_dissector("CertificateList", proto_x509af, dissect_CertificateList_PDU);
  register_ber_syntax_dissector("CrossCertificatePair", proto_x509af, dissect_CertificatePair_PDU);

  register_ber_oid_syntax(".cer", NULL, "Certificate");
  register_ber_oid_syntax(".crt", NULL, "Certificate");
  register_ber_oid_syntax(".crl", NULL, "CertificateList");
}


/*--- proto_reg_handoff_x509af -------------------------------------------*/
void proto_reg_handoff_x509af(void) {

	dissector_add_string("media_type", "application/pkix-crl", pkix_crl_handle);

#include "packet-x509af-dis-tab.c"

	/*XXX these should really go to a better place but since
	  I have not that ITU standard, I'll put it here for the time
	  being.
	  Only implemented those algorithms that take no parameters
	  for the time being,   ronnie
	*/
	/* from http://www.alvestrand.no/objectid/1.3.14.3.2.html */
	register_ber_oid_dissector("1.3.14.3.2.2", dissect_ber_oid_NULL_callback, proto_x509af, "md4WithRSA");
	register_ber_oid_dissector("1.3.14.3.2.3", dissect_ber_oid_NULL_callback, proto_x509af, "md5WithRSA");
	register_ber_oid_dissector("1.3.14.3.2.4", dissect_ber_oid_NULL_callback, proto_x509af, "md4WithRSAEncryption");
	register_ber_oid_dissector("1.3.14.3.2.6", dissect_ber_oid_NULL_callback, proto_x509af, "desECB");
	register_ber_oid_dissector("1.3.14.3.2.11", dissect_ber_oid_NULL_callback, proto_x509af, "rsaSignature");
	register_ber_oid_dissector("1.3.14.3.2.14", dissect_ber_oid_NULL_callback, proto_x509af, "mdc2WithRSASignature");
	register_ber_oid_dissector("1.3.14.3.2.15", dissect_ber_oid_NULL_callback, proto_x509af, "shaWithRSASignature");
	register_ber_oid_dissector("1.3.14.3.2.16", dissect_ber_oid_NULL_callback, proto_x509af, "dhWithCommonModulus");
	register_ber_oid_dissector("1.3.14.3.2.17", dissect_ber_oid_NULL_callback, proto_x509af, "desEDE");
	register_ber_oid_dissector("1.3.14.3.2.18", dissect_ber_oid_NULL_callback, proto_x509af, "sha");
	register_ber_oid_dissector("1.3.14.3.2.19", dissect_ber_oid_NULL_callback, proto_x509af, "mdc-2");
	register_ber_oid_dissector("1.3.14.3.2.20", dissect_ber_oid_NULL_callback, proto_x509af, "dsaCommon");
	register_ber_oid_dissector("1.3.14.3.2.21", dissect_ber_oid_NULL_callback, proto_x509af, "dsaCommonWithSHA");
	register_ber_oid_dissector("1.3.14.3.2.22", dissect_ber_oid_NULL_callback, proto_x509af, "rsaKeyTransport");
	register_ber_oid_dissector("1.3.14.3.2.23", dissect_ber_oid_NULL_callback, proto_x509af, "keyed-hash-seal");
	register_ber_oid_dissector("1.3.14.3.2.24", dissect_ber_oid_NULL_callback, proto_x509af, "md2WithRSASignature");
	register_ber_oid_dissector("1.3.14.3.2.25", dissect_ber_oid_NULL_callback, proto_x509af, "md5WithRSASignature");
	register_ber_oid_dissector("1.3.14.3.2.26", dissect_ber_oid_NULL_callback, proto_x509af, "SHA-1");
	register_ber_oid_dissector("1.3.14.3.2.27", dissect_ber_oid_NULL_callback, proto_x509af, "dsaWithSHA1");
	register_ber_oid_dissector("1.3.14.3.2.28", dissect_ber_oid_NULL_callback, proto_x509af, "dsaWithCommonSHA1");
	register_ber_oid_dissector("1.3.14.3.2.29", dissect_ber_oid_NULL_callback, proto_x509af, "sha-1WithRSAEncryption");

	/* these will generally be encoded as ";binary" in LDAP */

	dissector_add_string("ldap.name", "cACertificate", create_dissector_handle(dissect_x509af_Certificate_PDU, proto_x509af));
	dissector_add_string("ldap.name", "userCertificate", create_dissector_handle(dissect_x509af_Certificate_PDU, proto_x509af));

	dissector_add_string("ldap.name", "certificateRevocationList", create_dissector_handle(dissect_CertificateList_PDU, proto_x509af));
	dissector_add_string("ldap.name", "crl", create_dissector_handle(dissect_CertificateList_PDU, proto_x509af));

	dissector_add_string("ldap.name", "authorityRevocationList", create_dissector_handle(dissect_CertificateList_PDU, proto_x509af));
	dissector_add_string("ldap.name", "arl", create_dissector_handle(dissect_CertificateList_PDU, proto_x509af));

	dissector_add_string("ldap.name", "crossCertificatePair", create_dissector_handle(dissect_CertificatePair_PDU, proto_x509af));

	/* RFC 7468 files */
	dissector_add_string("rfc7468.preeb_label", "CERTIFICATE", create_dissector_handle(dissect_x509af_Certificate_PDU, proto_x509af));
	dissector_add_string("rfc7468.preeb_label", "X509 CRL", create_dissector_handle(dissect_CertificateList_PDU, proto_x509af));
	dissector_add_string("rfc7468.preeb_label", "ATTRIBUTE CERTIFICATE", create_dissector_handle(dissect_AttributeCertificate_PDU, proto_x509af));
	dissector_add_string("rfc7468.preeb_label", "PUBLIC KEY", create_dissector_handle(dissect_SubjectPublicKeyInfo_PDU, proto_x509af));
}
