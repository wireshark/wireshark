/* packet-cms.c
 * Routines for RFC5652 Cryptographic Message Syntax packet dissection
 *   Ronnie Sahlberg 2004
 *   Stig Bjorlykke 2010
 *   Uwe Heuert 2022
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
#include <epan/proto_data.h>
#include <wsutil/wsgcrypt.h>

#include "packet-ber.h"
#include "packet-cms.h"
#include "packet-x509af.h"
#include "packet-x509ce.h"
#include "packet-x509if.h"
#include "packet-x509sat.h"
#include "packet-pkcs12.h"

#define PNAME  "Cryptographic Message Syntax"
#define PSNAME "CMS"
#define PFNAME "cms"

void proto_register_cms(void);
void proto_reg_handoff_cms(void);

/* Initialize the protocol and registered fields */
static int proto_cms;
static int hf_cms_ci_contentType;
#include "packet-cms-hf.c"

/* Initialize the subtree pointers */
static int ett_cms;
#include "packet-cms-ett.c"

static dissector_handle_t cms_handle;

static int dissect_cms_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) ; /* XXX kill a compiler warning until asn2wrs stops generating these silly wrappers */

struct cms_private_data {
  const char *object_identifier_id;
  tvbuff_t *content_tvb;
};

static proto_tree *top_tree;
static proto_tree *cap_tree;

#define HASH_SHA1 "1.3.14.3.2.26"

#define HASH_MD5 "1.2.840.113549.2.5"


/* SHA-2 variants */
#define HASH_SHA224 "2.16.840.1.101.3.4.2.4"
#define SHA224_BUFFER_SIZE  32 /* actually 28 */
#define HASH_SHA256 "2.16.840.1.101.3.4.2.1"
#define SHA256_BUFFER_SIZE  32

unsigned char digest_buf[MAX(HASH_SHA1_LENGTH, HASH_MD5_LENGTH)];

/*
* Dissect CMS PDUs inside a PPDU.
*/
static int
dissect_cms(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
	int offset = 0;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_cms, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_cms);
	}
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CMS");
	col_clear(pinfo->cinfo, COL_INFO);

	while (tvb_reported_length_remaining(tvb, offset) > 0){
		offset=dissect_cms_ContentInfo(false, tvb, offset, &asn1_ctx , tree, -1);
	}
	return tvb_captured_length(tvb);
}

static struct cms_private_data*
cms_get_private_data(packet_info *pinfo)
{
  struct cms_private_data *cms_data = (struct cms_private_data*)p_get_proto_data(pinfo->pool, pinfo, proto_cms, 0);
  if (!cms_data) {
    cms_data = wmem_new0(pinfo->pool, struct cms_private_data);
    p_add_proto_data(pinfo->pool, pinfo, proto_cms, 0, cms_data);
  }
  return cms_data;
}

static void
cms_verify_msg_digest(proto_item *pi, tvbuff_t *content, const char *alg, tvbuff_t *tvb, int offset)
{
  int i= 0, buffer_size = 0;

  /* we only support two algorithms at the moment  - if we do add SHA2
     we should add a registration process to use a registration process */

  if(strcmp(alg, HASH_SHA1) == 0) {
    gcry_md_hash_buffer(GCRY_MD_SHA1, digest_buf, tvb_get_ptr(content, 0, tvb_captured_length(content)), tvb_captured_length(content));
    buffer_size = HASH_SHA1_LENGTH;

  } else if(strcmp(alg, HASH_MD5) == 0) {
    gcry_md_hash_buffer(GCRY_MD_MD5, digest_buf, tvb_get_ptr(content, 0, tvb_captured_length(content)), tvb_captured_length(content));
    buffer_size = HASH_MD5_LENGTH;
  }

  if(buffer_size) {
    /* compare our computed hash with what we have received */

    if(tvb_bytes_exist(tvb, offset, buffer_size) &&
       (tvb_memeql(tvb, offset, digest_buf, buffer_size) != 0)) {
      proto_item_append_text(pi, " [incorrect, should be ");
      for(i = 0; i < buffer_size; i++)
	proto_item_append_text(pi, "%02X", digest_buf[i]);

      proto_item_append_text(pi, "]");
    }
    else
      proto_item_append_text(pi, " [correct]");
  } else {
    proto_item_append_text(pi, " [unable to verify]");
  }

}

#include "packet-cms-fn.c"

/*--- proto_register_cms ----------------------------------------------*/
void proto_register_cms(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_cms_ci_contentType,
      { "contentType", "cms.contentInfo.contentType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
#include "packet-cms-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
	  &ett_cms,
#include "packet-cms-ettarr.c"
  };

  /* Register protocol */
  proto_cms = proto_register_protocol(PNAME, PSNAME, PFNAME);

  cms_handle = register_dissector(PFNAME, dissect_cms, proto_cms);

  /* Register fields and subtrees */
  proto_register_field_array(proto_cms, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_ber_syntax_dissector("ContentInfo", proto_cms, dissect_ContentInfo_PDU);
  register_ber_syntax_dissector("SignedData", proto_cms, dissect_SignedData_PDU);
  register_ber_oid_syntax(".p7s", NULL, "ContentInfo");
  register_ber_oid_syntax(".p7m", NULL, "ContentInfo");
  register_ber_oid_syntax(".p7c", NULL, "ContentInfo");


}


/*--- proto_reg_handoff_cms -------------------------------------------*/
void proto_reg_handoff_cms(void) {
  dissector_handle_t content_info_handle;
#include "packet-cms-dis-tab.c"

  /* RFC 3370 [CMS-ASN} section 4.3.1 */
  register_ber_oid_dissector("1.2.840.113549.1.9.16.3.6", dissect_ber_oid_NULL_callback, proto_cms, "id-alg-CMS3DESwrap");

  oid_add_from_string("id-data","1.2.840.113549.1.7.1");
  oid_add_from_string("id-alg-des-ede3-cbc","1.2.840.113549.3.7");
  oid_add_from_string("id-alg-des-cbc","1.3.14.3.2.7");

  oid_add_from_string("id-ct-authEnvelopedData","1.2.840.113549.1.9.16.1.23");
  oid_add_from_string("id-aes-CBC-CMAC-128","0.4.0.127.0.7.1.3.1.1.2");
  oid_add_from_string("id-aes-CBC-CMAC-192","0.4.0.127.0.7.1.3.1.1.3");
  oid_add_from_string("id-aes-CBC-CMAC-256","0.4.0.127.0.7.1.3.1.1.4");
  oid_add_from_string("ecdsaWithSHA256","1.2.840.10045.4.3.2");
  oid_add_from_string("ecdsaWithSHA384","1.2.840.10045.4.3.3");
  oid_add_from_string("ecdsaWithSHA512","1.2.840.10045.4.3.4");

  content_info_handle = create_dissector_handle (dissect_ContentInfo_PDU, proto_cms);

  dissector_add_string("media_type", "application/pkcs7-mime", content_info_handle);
  dissector_add_string("media_type", "application/pkcs7-signature", content_info_handle);

  dissector_add_string("media_type", "application/vnd.de-dke-k461-ic1+xml", content_info_handle);
  dissector_add_string("media_type", "application/vnd.de-dke-k461-ic1+xml; encap=cms-tr03109", content_info_handle);
  dissector_add_string("media_type", "application/vnd.de-dke-k461-ic1+xml; encap=cms-tr03109-zlib", content_info_handle);
  dissector_add_string("media_type", "application/hgp;encap=cms", content_info_handle);
}
